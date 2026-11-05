// Bounded host Neighbor Discovery for configured addresses (RFC 4861 address
// resolution and Neighbor Unreachability Detection, RFC 4862 section 5.4
// Duplicate Address Detection) on Ethernet ports. No router, prefix or
// autoconfiguration state exists: routes and addresses are configured. All
// storage is allocated fallibly when the Host is created; each neighbor is
// keyed by its link (with generation) and next-hop address and shared by
// every path that uses it.
use alloc::vec::Vec;
use core::net::Ipv6Addr;
use ntcp::Instant;
use ntcp_icmp::{NeighborAdvertisement, NeighborSolicitation};
use ntcp_path::LinkId;

use crate::{Entropy, Error, table};

// RFC 4861 section 10 host constants. The two timer variables below are
// initialized from REACHABLE_TIME and RETRANS_TIMER; the rest are constants
// whose values the RFC fixes.
const REACHABLE_TIME_MS: u64 = 30_000;
const RETRANS_TIMER_MS: u64 = 1_000;
const MAX_MULTICAST_SOLICIT: u8 = 3;
const MAX_UNICAST_SOLICIT: u8 = 3;
const DELAY_FIRST_PROBE_TIME_MS: u64 = 5_000;
// RFC 4862 section 5.4.2 delays the first DAD solicitation by a random time
// up to MAX_RTR_SOLICITATION_DELAY (RFC 4861 section 10).
const MAX_RTR_SOLICITATION_DELAY_MS: u64 = 1_000;

/// Neighbor Discovery storage of one Host, all of it allocated at creation;
/// the default (nothing) supports no ND-capable port.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NeighborLimits {
    /// Neighbor cache entries, shared by every ND-capable port.
    pub entries: usize,
    /// Output attempts held while their next hop is resolved (RFC 4861
    /// section 7.2.2). A held attempt stays with its owner, blocked and
    /// never transmitted; it is retried once resolved, through the
    /// ordinary egress revalidation, and failed otherwise.
    pub pending_packets: usize,
    /// Configured addresses on ND-capable ports (each with its DAD state).
    pub addresses: usize,
    /// Advertisements answering solicitations, queued for control output.
    /// A solicitation arriving while every slot is occupied is not
    /// answered: its sender retransmits it (RFC 4861 section 7.2.2), and a
    /// later copy is answered once a slot frees.
    pub answers: usize,
}

/// The configuration of one ND-capable Ethernet port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NdPort {
    pub mac: [u8; 6],
    /// RFC 4862 DupAddrDetectTransmits; 0 disables Duplicate Address
    /// Detection administratively.
    pub dad_transmits: u8,
    /// The embedding's receive path also delivers this port's own multicast
    /// transmissions, so that many of its own DAD solicitations are expected
    /// back (RFC 4862 section 5.4.3) rather than counted as another node's.
    pub loops_back_multicast: bool,
}
impl NdPort {
    pub const fn new(mac: [u8; 6]) -> Self {
        Self {
            mac,
            dad_transmits: 1,
            loops_back_multicast: false,
        }
    }
}

/// RFC 4861 section 7.3.2 reachability states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NeighborState {
    Incomplete,
    Reachable,
    Stale,
    Delay,
    Probe,
}

/// The Duplicate Address Detection state of a configured address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressState {
    /// Tentative: waiting for its multicast groups, delayed or probing.
    Tentative,
    Assigned,
    /// Another node uses it; it stays unusable.
    Duplicate,
}

// The RFC 4861 section 7.2.5 branch an advertisement took.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NaBranch {
    // No entry: silently discarded.
    NoEntry,
    // INCOMPLETE without a Target Link-Layer Address option: discarded.
    IncompleteNoAddress,
    // INCOMPLETE resolved: REACHABLE when solicited, else STALE.
    IncompleteSolicited,
    IncompleteUnsolicited,
    // Override clear with a different address: REACHABLE becomes STALE,
    // nothing else changes; other states ignore it.
    KeptReachableToStale,
    KeptIgnored,
    // Accepted update: solicited sets REACHABLE, an unsolicited changed
    // address STALE, an unsolicited unchanged one keeps the state.
    UpdatedSolicited,
    UpdatedChanged,
    UpdatedUnchanged,
}

// Where a solicitation is sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Destination {
    // The target's solicited-node group.
    Multicast,
    Unicast([u8; 6]),
}

// One ND control message to originate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Control {
    // Resolution or unreachability probe from an assigned address of the
    // port, or a DAD probe from the unspecified address (`dad`).
    Solicit {
        link: LinkId,
        target: Ipv6Addr,
        destination: Destination,
        dad: bool,
    },
    // Answer from `target` to `to` (all-nodes when None).
    Advertise {
        link: LinkId,
        target: Ipv6Addr,
        to: Option<(Ipv6Addr, [u8; 6])>,
    },
}

// The authority to complete one polled control message; stale when its
// subject changed meanwhile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlToken {
    Entry { slot: usize, id: u64, sent: u8 },
    Dad { slot: usize, id: u64, sent: u8 },
    Answer { slot: usize, id: u64 },
}

// What the backend's outcome for one control message means.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlOutcome {
    // Definitely submitted. A solicitation consumes an attempt and starts
    // its RetransTimer spacing; a DAD probe counts toward
    // DupAddrDetectTransmits and, on a port that loops back multicast, its
    // own copy is expected back. An answer is done.
    Submitted,
    // Possibly submitted: it may be on the wire, so every solicitation
    // starts its RetransTimer spacing (RFC 4861 section 7.3.3, RFC 4862
    // section 5.4.2). A resolution or unreachability solicitation also
    // consumes an attempt, failure following one RetransTimer after the
    // final one. A DAD probe does not count (an address is assigned only
    // after definitely submitted probes), but on a looping port its own
    // copy may come back and is expected. An answer ends: the solicitor
    // retransmits.
    Uncertain,
    // Certainly not submitted and retried later: nothing is consumed and no
    // spacing starts; an answer stays queued.
    Blocked,
    // Certainly not submitted and not retried by the backend: a
    // solicitation stays due as if never polled (nothing consumed, no
    // spacing); an answer ends.
    Failed,
}

// Results of caller-time service and ingress the Host acts on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NdEvent {
    Assigned { link: LinkId, address: Ipv6Addr },
    Duplicate { link: LinkId, address: Ipv6Addr },
    // Neighbor Unreachability Detection or address resolution failed: the
    // entry is gone.
    Unreachable { link: LinkId, address: Ipv6Addr },
    // An advertisement cleared the entry's IsRouter flag (RFC 4861 section
    // 7.2.5: the neighbor stops being used as a router).
    RouterLost { link: LinkId, address: Ipv6Addr },
}

// The next hop's output disposition for one packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Resolution {
    Ready([u8; 6]),
    Held,
}

#[derive(Clone, Copy)]
struct Interface {
    link: LinkId,
    port: NdPort,
    // RFC 4861 section 6.3.2 variables, in caller time units.
    base_reachable: u64,
    retrans: u64,
    reachable: u64,
}

#[derive(Clone, Copy)]
struct Entry {
    id: u64,
    link: LinkId,
    address: Ipv6Addr,
    state: NeighborState,
    mac: Option<[u8; 6]>,
    // When `mac` last took its value: only packets submitted since went
    // to it.
    mapped_at: Instant,
    router: bool,
    // The state's timer: REACHABLE expiry, DELAY end, or for INCOMPLETE and
    // PROBE the time the next solicitation is due (or, once all were
    // submitted, failure). For STALE, which has no timer, when the entry
    // became STALE: the order in which idle entries are reclaimed.
    deadline: Instant,
    // Solicitations possibly or definitely submitted in INCOMPLETE or PROBE.
    sent: u8,
}

#[derive(Clone, Copy)]
enum Dad {
    // Its multicast groups are not yet joined.
    Waiting,
    // `sent` counts definitely submitted probes; `deadline` is when the
    // next is due (or, once all were submitted, assignment).
    Probing { sent: u8, deadline: Instant },
    Done(AddressState),
}

#[derive(Clone, Copy)]
struct Address {
    id: u64,
    link: LinkId,
    address: Ipv6Addr,
    dad: Dad,
    // Own DAD solicitations possibly or definitely submitted on a port that
    // loops back multicast and not yet seen looped back.
    looped: u8,
}

#[derive(Clone, Copy)]
struct Answer {
    id: u64,
    link: LinkId,
    target: Ipv6Addr,
    to: Option<(Ipv6Addr, [u8; 6])>,
    // When the solicitation was accepted: the answer is due from then on.
    queued: Instant,
}

#[derive(Clone, Copy)]
struct Pending<T> {
    entry: u64,
    // Resolution failed: the owner is advised and the attempt dropped.
    failed: bool,
    tag: T,
}

pub(crate) struct Neighbors<T> {
    units_per_second: u64,
    next_id: u64,
    interfaces: Vec<Option<Interface>>,
    entries: Vec<Option<Entry>>,
    addresses: Vec<Option<Address>>,
    answers: Vec<Option<Answer>>,
    pending: Vec<Option<Pending<T>>>,
}

fn random_u32(entropy: Option<&mut Entropy>) -> Result<u32, Error> {
    let mut bytes = [0; 4];
    entropy.ok_or(Error::Entropy)?(&mut bytes).map_err(|_| Error::Entropy)?;
    Ok(u32::from_be_bytes(bytes))
}

// Uniform in [MIN_RANDOM_FACTOR, MAX_RANDOM_FACTOR) = [0.5, 1.5) times
// `base` (RFC 4861 section 6.3.2).
fn reachable_time(base: u64, entropy: Option<&mut Entropy>) -> Result<u64, Error> {
    let r = u128::from(random_u32(entropy)?);
    Ok(base / 2 + ((u128::from(base) * r) >> 32) as u64)
}

impl<T: Copy + PartialEq> Neighbors<T> {
    pub(crate) fn new(
        limits: NeighborLimits,
        links: usize,
        units_per_second: u64,
    ) -> Result<Self, Error> {
        let ports = if limits.entries == 0 { 0 } else { links };
        Ok(Self {
            units_per_second,
            next_id: 0,
            interfaces: table(ports, None)?,
            entries: table(limits.entries, None)?,
            addresses: table(limits.addresses, None)?,
            answers: table(limits.answers, None)?,
            pending: table(limits.pending_packets, None)?,
        })
    }
    fn units(&self, ms: u64) -> u64 {
        ms.saturating_mul(self.units_per_second) / 1000
    }
    fn id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }
    fn interface(&self, link: LinkId) -> Option<&Interface> {
        self.interfaces.iter().flatten().find(|i| i.link == link)
    }
    pub(crate) fn ports_free(&self) -> usize {
        self.interfaces.iter().filter(|i| i.is_none()).count()
    }
    pub(crate) fn port(&self, link: LinkId) -> Option<NdPort> {
        self.interface(link).map(|i| i.port)
    }

    // An ND-capable port, its timer variables initialized from the RFC
    // defaults and ReachableTime drawn from `entropy`.
    pub(crate) fn add_port(
        &mut self,
        link: LinkId,
        port: NdPort,
        entropy: Option<&mut Entropy>,
    ) -> Result<(), Error> {
        let slot = self
            .interfaces
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let base_reachable = self.units(REACHABLE_TIME_MS);
        let reachable = reachable_time(base_reachable, entropy)?;
        self.interfaces[slot] = Some(Interface {
            link,
            port,
            base_reachable,
            retrans: self.units(RETRANS_TIMER_MS),
            reachable,
        });
        Ok(())
    }

    // Forget a removed port's interface, neighbors, addresses and answers;
    // its held packets fail.
    pub(crate) fn remove_port(&mut self, link: LinkId) {
        for interface in &mut self.interfaces {
            if interface.is_some_and(|i| i.link == link) {
                *interface = None;
            }
        }
        for slot in 0..self.entries.len() {
            if self.entries[slot].is_some_and(|e| e.link == link) {
                self.fail(slot);
            }
        }
        for address in &mut self.addresses {
            if address.is_some_and(|a| a.link == link) {
                *address = None;
            }
        }
        for answer in &mut self.answers {
            if answer.is_some_and(|a| a.link == link) {
                *answer = None;
            }
        }
    }

    // Replace BaseReachableTime (RFC 4861 section 6.3.2 recomputes
    // ReachableTime whenever it changes). Nothing changes on failure.
    pub(crate) fn set_base_reachable(
        &mut self,
        link: LinkId,
        base_ms: u64,
        entropy: Option<&mut Entropy>,
    ) -> Result<(), Error> {
        let base = self.units(base_ms);
        let interface = self
            .interfaces
            .iter_mut()
            .flatten()
            .find(|i| i.link == link)
            .ok_or(Error::InvalidContext)?;
        interface.reachable = reachable_time(base, entropy)?;
        interface.base_reachable = base;
        Ok(())
    }

    pub(crate) fn state(
        &self,
        link: LinkId,
        address: Ipv6Addr,
    ) -> Option<(NeighborState, Option<[u8; 6]>, bool)> {
        self.find(link, address)
            .and_then(|slot| self.entries[slot])
            .map(|e| (e.state, e.mac, e.router))
    }
    fn find(&self, link: LinkId, address: Ipv6Addr) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.is_some_and(|e| e.link == link && e.address == address))
    }

    // Configured addresses.

    // A configured address of an ND-capable port, tentative until DAD
    // completes (immediately assigned when DupAddrDetectTransmits is 0).
    pub(crate) fn add_address(
        &mut self,
        link: LinkId,
        address: Ipv6Addr,
    ) -> Result<AddressState, Error> {
        let port = self.port(link).ok_or(Error::InvalidContext)?;
        if self.address(link, address).is_some() {
            return Err(Error::Path(ntcp_path::Error::Duplicate));
        }
        let slot = self
            .addresses
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let dad = if port.dad_transmits == 0 {
            Dad::Done(AddressState::Assigned)
        } else {
            Dad::Waiting
        };
        let id = self.id();
        self.addresses[slot] = Some(Address {
            id,
            link,
            address,
            dad,
            looped: 0,
        });
        Ok(self.address_state(link, address).unwrap())
    }
    pub(crate) fn remove_address(&mut self, link: LinkId, address: Ipv6Addr) {
        if let Some(slot) = self.address(link, address) {
            self.addresses[slot] = None;
        }
    }
    fn address(&self, link: LinkId, address: Ipv6Addr) -> Option<usize> {
        self.addresses
            .iter()
            .position(|a| a.is_some_and(|a| a.link == link && a.address == address))
    }
    // Every configured address of `link`, tentative ones included.
    pub(crate) fn addresses_on(&self, link: LinkId) -> impl Iterator<Item = Ipv6Addr> + '_ {
        self.addresses
            .iter()
            .flatten()
            .filter(move |a| a.link == link)
            .map(|a| a.address)
    }
    pub(crate) fn address_state(&self, link: LinkId, address: Ipv6Addr) -> Option<AddressState> {
        let a = self.addresses[self.address(link, address)?]?;
        Some(match a.dad {
            Dad::Done(state) => state,
            _ => AddressState::Tentative,
        })
    }
    // Any assigned address of the port, the source of its solicitations.
    pub(crate) fn assigned_source(&self, link: LinkId) -> Option<Ipv6Addr> {
        let assigned =
            |a: &&Address| a.link == link && matches!(a.dad, Dad::Done(AddressState::Assigned));
        let addresses = || self.addresses.iter().flatten().filter(assigned);
        // A link-local source when there is one (RFC 4861 section 7.2.2
        // prefers the packet's own source; Host chooses that when known).
        addresses()
            .find(|a| a.address.is_unicast_link_local())
            .or_else(|| addresses().next())
            .map(|a| a.address)
    }

    // The embedding has joined the all-nodes group and `address`'s
    // solicited-node group on its port (RFC 4862 section 5.4.2 requires
    // them before the first probe), which then starts after a random delay.
    pub(crate) fn membership_ready(
        &mut self,
        link: LinkId,
        address: Ipv6Addr,
        now: Instant,
        entropy: Option<&mut Entropy>,
    ) -> Result<(), Error> {
        let slot = self.address(link, address).ok_or(Error::InvalidContext)?;
        let mut a = self.addresses[slot].unwrap();
        if let Dad::Waiting = a.dad {
            // Uniform in [0, MAX_RTR_SOLICITATION_DELAY).
            let r = u128::from(random_u32(entropy)?);
            let delay = ((u128::from(self.units(MAX_RTR_SOLICITATION_DELAY_MS)) * r) >> 32) as u64;
            a.dad = Dad::Probing {
                sent: 0,
                deadline: now.saturating_add(delay),
            };
            self.addresses[slot] = Some(a);
        }
        Ok(())
    }

    fn dad_failed(&mut self, slot: usize, events: &mut impl FnMut(NdEvent)) {
        let mut a = self.addresses[slot].unwrap();
        if matches!(a.dad, Dad::Done(_)) {
            return;
        }
        a.dad = Dad::Done(AddressState::Duplicate);
        self.addresses[slot] = Some(a);
        events(NdEvent::Duplicate {
            link: a.link,
            address: a.address,
        });
    }

    // Ingress (validated messages that arrived on `link`).

    // A Neighbor Solicitation from `source` (RFC 4861 sections 7.2.3 and
    // 7.2.4; RFC 4862 section 5.4.3).
    pub(crate) fn solicitation(
        &mut self,
        link: LinkId,
        source: Ipv6Addr,
        ns: NeighborSolicitation,
        now: Instant,
        events: &mut impl FnMut(NdEvent),
    ) -> Result<(), Error> {
        self.port(link).ok_or(Error::InvalidContext)?;
        let own = self.address(link, ns.target);
        if let Some(slot) = own {
            let a = self.addresses[slot].unwrap();
            if !matches!(a.dad, Dad::Done(_)) {
                // A tentative target: a resolution solicitation is ignored;
                // another node's DAD probe for it fails DAD, unless it is
                // one of this port's own probes looped back.
                if source.is_unspecified() {
                    if a.looped > 0 {
                        let mut a = a;
                        a.looped -= 1;
                        self.addresses[slot] = Some(a);
                    } else {
                        self.dad_failed(slot, events);
                    }
                }
                return Ok(());
            }
        }
        if !source.is_unspecified()
            && let Some(mac) = ns.source_link_layer
        {
            self.learn(link, source, mac, now);
        }
        let Some(slot) = own else {
            return Ok(());
        };
        if !matches!(
            self.addresses[slot].unwrap().dad,
            Dad::Done(AddressState::Assigned)
        ) {
            return Ok(());
        }
        // An unspecified source is answered to all-nodes; a unicast one at
        // its stated or cached link-layer address. Without either there is
        // no mapping to answer at, and nothing is queued.
        let to = if source.is_unspecified() {
            None
        } else {
            let cached = self.state(link, source).and_then(|(_, mac, _)| mac);
            match ns.source_link_layer.or(cached) {
                Some(mac) => Some((source, mac)),
                None => return Ok(()),
            }
        };
        let id = self.id();
        let answer = Answer {
            id,
            link,
            target: ns.target,
            to,
            queued: now,
        };
        // A bounded answer queue: when full, the solicitation's sender
        // retransmits (RFC 4861 section 7.2.2).
        if let Some(free) = self.answers.iter_mut().find(|a| a.is_none()) {
            *free = Some(answer);
        }
        Ok(())
    }

    // RFC 4861 section 7.2.3: a unicast-source solicitation's Source
    // Link-Layer Address creates a STALE entry or updates a different one
    // to STALE; an unchanged one is left as is.
    fn learn(&mut self, link: LinkId, address: Ipv6Addr, mac: [u8; 6], now: Instant) {
        match self.find(link, address) {
            Some(slot) => {
                let mut e = self.entries[slot].unwrap();
                if e.mac != Some(mac) {
                    e.mac = Some(mac);
                    e.mapped_at = now;
                    e.state = NeighborState::Stale;
                    e.deadline = now;
                    e.sent = 0;
                    self.entries[slot] = Some(e);
                }
            }
            None => {
                // Without a free or reclaimable entry, nothing is learned:
                // the mapping is resolved when this node first sends to it.
                if let Some(slot) = self.vacancy() {
                    let id = self.id();
                    self.entries[slot] = Some(Entry {
                        id,
                        link,
                        address,
                        state: NeighborState::Stale,
                        mac: Some(mac),
                        mapped_at: now,
                        router: false,
                        deadline: now,
                        sent: 0,
                    });
                }
            }
        }
    }

    // A valid Redirect's target (RFC 4861 section 8.3). Its Target
    // Link-Layer Address creates a STALE entry or updates a different
    // mapping to STALE; the same mapping keeps its state. A target that is
    // not the destination is a router, with or without a mapping (an entry
    // created later for it is marked by `mark_router`); a new entry for a
    // target that is the destination is not, and an existing one keeps its
    // flag. Without a free or reclaimable entry nothing is learned.
    pub(crate) fn redirect(
        &mut self,
        link: LinkId,
        target: Ipv6Addr,
        mac: Option<[u8; 6]>,
        router: bool,
        now: Instant,
    ) {
        if let Some(mac) = mac {
            self.learn(link, target, mac, now);
        }
        if router {
            self.mark_router(link, target);
        }
    }

    // Record that `address` on `link` is a router.
    pub(crate) fn mark_router(&mut self, link: LinkId, address: Ipv6Addr) {
        if let Some(slot) = self.find(link, address) {
            let mut e = self.entries[slot].unwrap();
            e.router = true;
            self.entries[slot] = Some(e);
        }
    }

    // A Neighbor Advertisement (RFC 4861 section 7.2.5; RFC 4862 section
    // 5.4.4 for a tentative target). Confirmation draws a new ReachableTime;
    // when that fails nothing changes and the error is returned.
    pub(crate) fn advertisement(
        &mut self,
        link: LinkId,
        na: NeighborAdvertisement,
        now: Instant,
        entropy: Option<&mut Entropy>,
        events: &mut impl FnMut(NdEvent),
    ) -> Result<NaBranch, Error> {
        self.port(link).ok_or(Error::InvalidContext)?;
        if let Some(slot) = self.address(link, na.target) {
            // Any valid advertisement of a tentative address is a duplicate,
            // with or without a cache entry; one for an assigned address is
            // another node's error, never a mapping of this node's own.
            self.dad_failed(slot, events);
            return Ok(NaBranch::NoEntry);
        }
        let Some(slot) = self.find(link, na.target) else {
            return Ok(NaBranch::NoEntry);
        };
        let mut e = self.entries[slot].unwrap();
        let reachable = |this: &mut Self, entropy| this.confirmation(link, now, entropy);
        let mut router_lost = false;
        let branch = if e.state == NeighborState::Incomplete {
            // The Override flag is ignored; the address is required.
            let Some(mac) = na.target_link_layer else {
                return Ok(NaBranch::IncompleteNoAddress);
            };
            e.mac = Some(mac);
            e.mapped_at = now;
            router_lost = e.router && !na.router;
            e.router = na.router;
            e.sent = 0;
            if na.solicited {
                e.state = NeighborState::Reachable;
                e.deadline = reachable(self, entropy)?;
                NaBranch::IncompleteSolicited
            } else {
                e.state = NeighborState::Stale;
                e.deadline = now;
                NaBranch::IncompleteUnsolicited
            }
        } else {
            let changed = na.target_link_layer.is_some_and(|mac| e.mac != Some(mac));
            if !na.override_ && changed {
                if e.state != NeighborState::Reachable {
                    return Ok(NaBranch::KeptIgnored);
                }
                e.state = NeighborState::Stale;
                e.deadline = now;
                NaBranch::KeptReachableToStale
            } else {
                if na.solicited {
                    e.deadline = reachable(self, entropy)?;
                }
                if changed {
                    e.mac = na.target_link_layer;
                    e.mapped_at = now;
                }
                router_lost = e.router && !na.router;
                e.router = na.router;
                if na.solicited {
                    e.state = NeighborState::Reachable;
                    e.sent = 0;
                    NaBranch::UpdatedSolicited
                } else if changed {
                    e.state = NeighborState::Stale;
                    e.deadline = now;
                    e.sent = 0;
                    NaBranch::UpdatedChanged
                } else {
                    // The state is kept, and with it the progress of
                    // INCOMPLETE or PROBE: such an advertisement confirms
                    // nothing (RFC 4861 section 7.2.5), so neither its
                    // solicitations nor its failure time restart.
                    NaBranch::UpdatedUnchanged
                }
            }
        };
        self.entries[slot] = Some(e);
        if router_lost {
            events(NdEvent::RouterLost {
                link,
                address: na.target,
            });
        }
        Ok(branch)
    }

    // Reachability is confirmed on `link`: a fresh ReachableTime is drawn
    // (RFC 4861 section 6.3.2 re-randomizes it at least every few hours;
    // every confirmation satisfies that), returning the REACHABLE deadline.
    fn confirmation(
        &mut self,
        link: LinkId,
        now: Instant,
        entropy: Option<&mut Entropy>,
    ) -> Result<Instant, Error> {
        let interface = self
            .interfaces
            .iter_mut()
            .flatten()
            .find(|i| i.link == link)
            .ok_or(Error::InvalidContext)?;
        interface.reachable = reachable_time(interface.base_reachable, entropy)?;
        Ok(now.saturating_add(interface.reachable))
    }

    // An upper-layer reachability hint (RFC 4861 section 7.3.1): forward
    // progress through the neighbor by a packet submitted at `carried_at`.
    // It never resolves INCOMPLETE and confirms nothing when the mapping
    // has changed since: the packet went to another link-layer address.
    pub(crate) fn confirm(
        &mut self,
        link: LinkId,
        address: Ipv6Addr,
        carried_at: Instant,
        now: Instant,
        entropy: Option<&mut Entropy>,
    ) -> Result<bool, Error> {
        let Some(slot) = self.find(link, address) else {
            return Ok(false);
        };
        let mut e = self.entries[slot].unwrap();
        if e.state == NeighborState::Incomplete || e.mapped_at > carried_at {
            return Ok(false);
        }
        e.deadline = self.confirmation(link, now, entropy)?;
        e.state = NeighborState::Reachable;
        e.sent = 0;
        self.entries[slot] = Some(e);
        Ok(true)
    }

    // Egress.

    // The disposition of output `tag` for `address` on `link`. A usable
    // mapping is returned (the first use of a STALE one starts DELAY, RFC
    // 4861 section 7.3.3); otherwise it is held (once, however often it is
    // retried), a pending slot being reserved before an INCOMPLETE entry is
    // created, so exhaustion of either is backpressure (Error::Capacity)
    // that leaves no entry behind.
    pub(crate) fn output(
        &mut self,
        link: LinkId,
        address: Ipv6Addr,
        now: Instant,
        tag: T,
    ) -> Result<Resolution, Error> {
        self.port(link).ok_or(Error::InvalidContext)?;
        let found = self.find(link, address);
        if let Some(slot) = found {
            let mut e = self.entries[slot].unwrap();
            if let Some(mac) = e.mac.filter(|_| e.state != NeighborState::Incomplete) {
                if e.state == NeighborState::Stale {
                    e.state = NeighborState::Delay;
                    e.deadline = now.saturating_add(self.units(DELAY_FIRST_PROBE_TIME_MS));
                    self.entries[slot] = Some(e);
                }
                return Ok(Resolution::Ready(mac));
            }
        }
        if self
            .pending
            .iter()
            .flatten()
            .any(|p| p.tag == tag && !p.failed)
        {
            return Ok(Resolution::Held);
        }
        let held = self
            .pending
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let entry = match found {
            Some(slot) => self.entries[slot].unwrap().id,
            None => {
                let slot = self.vacancy().ok_or(Error::Capacity)?;
                let id = self.id();
                self.entries[slot] = Some(Entry {
                    id,
                    link,
                    address,
                    state: NeighborState::Incomplete,
                    mac: None,
                    mapped_at: now,
                    router: false,
                    deadline: now,
                    sent: 0,
                });
                id
            }
        };
        self.pending[held] = Some(Pending {
            entry,
            failed: false,
            tag,
        });
        Ok(Resolution::Held)
    }

    // The next held output selected by `filter` whose neighbor is now
    // resolved, with the mapping, or whose resolution failed (`None`).
    // Taking it is `release`; held output was never transmitted.
    pub(crate) fn next_pending(
        &self,
        filter: impl Fn(T) -> bool,
    ) -> Option<(usize, T, Option<[u8; 6]>)> {
        (0..self.pending.len()).find_map(|slot| {
            let (tag, ended) = self.pending_at(slot)?;
            Some((slot, tag, ended.filter(|_| filter(tag))?))
        })
    }
    pub(crate) fn pending_slots(&self) -> usize {
        self.pending.len()
    }
    // The output held in `slot` and, once its resolution ended, the
    // mapping (`Some(Some(_))`) or failure (`Some(None)`).
    pub(crate) fn pending_at(&self, slot: usize) -> Option<(T, Option<Option<[u8; 6]>>)> {
        let p = self.pending.get(slot).copied().flatten()?;
        if p.failed {
            return Some((p.tag, Some(None)));
        }
        let mac = self
            .entries
            .iter()
            .flatten()
            .find(|e| e.id == p.entry)
            .and_then(|e| e.mac.filter(|_| e.state != NeighborState::Incomplete));
        Some((p.tag, mac.map(Some)))
    }
    pub(crate) fn release(&mut self, slot: usize) {
        self.pending[slot] = None;
    }

    // A slot for a new entry: a free one, else the entry STALE the longest
    // with no held output. A STALE entry is idle (its first use starts
    // DELAY), so reclaiming it costs at most a new resolution, while active
    // entries (INCOMPLETE, REACHABLE, DELAY, PROBE) and entries owing held
    // output stay pinned and their exhaustion is backpressure.
    fn vacancy(&self) -> Option<usize> {
        if let Some(slot) = self.entries.iter().position(Option::is_none) {
            return Some(slot);
        }
        let held = |id| self.pending.iter().flatten().any(|p| p.entry == id);
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(slot, e)| Some((slot, (*e)?)))
            .filter(|(_, e)| e.state == NeighborState::Stale && !held(e.id))
            .min_by_key(|(_, e)| e.deadline)
            .map(|(slot, _)| slot)
    }

    // Resolution failed: the entry is removed and its held packets fail.
    fn fail(&mut self, slot: usize) {
        let id = self.entries[slot].unwrap().id;
        self.entries[slot] = None;
        for p in self.pending.iter_mut().flatten() {
            if p.entry == id {
                p.failed = true;
            }
        }
    }

    // Control output.

    // The next control message due at `now`: answers first, then DAD and
    // neighbor solicitations. Polling changes nothing; `complete` applies
    // the backend's outcome (see ControlOutcome), so a solicitation never
    // known to be unsent is spaced by RetransTimer and blocked data never
    // holds control output back.
    pub(crate) fn next_control(&self, now: Instant) -> Option<(Control, ControlToken)> {
        for (slot, a) in self.answers.iter().enumerate() {
            if let Some(a) = a {
                let control = Control::Advertise {
                    link: a.link,
                    target: a.target,
                    to: a.to,
                };
                return Some((control, ControlToken::Answer { slot, id: a.id }));
            }
        }
        for (slot, a) in self.addresses.iter().enumerate() {
            let Some(a) = a else { continue };
            let Dad::Probing { sent, deadline } = a.dad else {
                continue;
            };
            let transmits = self.port(a.link).map_or(0, |p| p.dad_transmits);
            if sent < transmits && deadline <= now {
                let control = Control::Solicit {
                    link: a.link,
                    target: a.address,
                    destination: Destination::Multicast,
                    dad: true,
                };
                return Some((
                    control,
                    ControlToken::Dad {
                        slot,
                        id: a.id,
                        sent,
                    },
                ));
            }
        }
        for (slot, e) in self.entries.iter().enumerate() {
            let Some(e) = e else { continue };
            let (limit, destination) = match (e.state, e.mac) {
                (NeighborState::Incomplete, _) => (MAX_MULTICAST_SOLICIT, Destination::Multicast),
                (NeighborState::Probe, Some(mac)) => {
                    (MAX_UNICAST_SOLICIT, Destination::Unicast(mac))
                }
                _ => continue,
            };
            if e.sent < limit && e.deadline <= now && self.assigned_source(e.link).is_some() {
                let control = Control::Solicit {
                    link: e.link,
                    target: e.address,
                    destination,
                    dad: false,
                };
                return Some((
                    control,
                    ControlToken::Entry {
                        slot,
                        id: e.id,
                        sent: e.sent,
                    },
                ));
            }
        }
        None
    }

    pub(crate) fn complete(&mut self, token: ControlToken, outcome: ControlOutcome, now: Instant) {
        match token {
            ControlToken::Answer { slot, id } => {
                if outcome != ControlOutcome::Blocked
                    && self.answers[slot].is_some_and(|a| a.id == id)
                {
                    self.answers[slot] = None;
                }
            }
            _ if matches!(outcome, ControlOutcome::Blocked | ControlOutcome::Failed) => {}
            ControlToken::Dad { slot, id, sent } => {
                let Some(mut a) = self.addresses[slot].filter(|a| a.id == id) else {
                    return;
                };
                let Dad::Probing { sent: now_sent, .. } = a.dad else {
                    return;
                };
                if now_sent != sent {
                    return;
                }
                let retrans = self.interface(a.link).map_or(0, |i| i.retrans);
                let submitted = u8::from(outcome == ControlOutcome::Submitted);
                a.dad = Dad::Probing {
                    sent: sent + submitted,
                    deadline: now.saturating_add(retrans),
                };
                if self.port(a.link).is_some_and(|p| p.loops_back_multicast) {
                    a.looped = a.looped.saturating_add(1);
                }
                self.addresses[slot] = Some(a);
            }
            ControlToken::Entry { slot, id, sent } => {
                let Some(mut e) = self.entries[slot].filter(|e| e.id == id && e.sent == sent)
                else {
                    return;
                };
                if !matches!(e.state, NeighborState::Incomplete | NeighborState::Probe) {
                    return;
                }
                // Submitted or Uncertain alike: one attempt is consumed.
                e.sent = sent + 1;
                e.deadline = now.saturating_add(self.interface(e.link).map_or(0, |i| i.retrans));
                self.entries[slot] = Some(e);
            }
        }
    }

    // Caller-time service.

    // Apply every timer due at `now`: REACHABLE to STALE after
    // ReachableTime, DELAY to PROBE after DELAY_FIRST_PROBE_TIME, failure a
    // full RetransTimer after the final solicitation or probe, and DAD
    // completion one RetransTimer after the final submitted probe.
    pub(crate) fn service(&mut self, now: Instant, events: &mut impl FnMut(NdEvent)) {
        for slot in 0..self.entries.len() {
            let Some(mut e) = self.entries[slot] else {
                continue;
            };
            if e.deadline > now {
                continue;
            }
            match e.state {
                NeighborState::Reachable => e.state = NeighborState::Stale,
                NeighborState::Delay => {
                    e.state = NeighborState::Probe;
                    e.sent = 0;
                    e.deadline = now;
                }
                NeighborState::Incomplete if e.sent >= MAX_MULTICAST_SOLICIT => {
                    self.fail(slot);
                    events(NdEvent::Unreachable {
                        link: e.link,
                        address: e.address,
                    });
                    continue;
                }
                NeighborState::Probe if e.sent >= MAX_UNICAST_SOLICIT => {
                    self.fail(slot);
                    events(NdEvent::Unreachable {
                        link: e.link,
                        address: e.address,
                    });
                    continue;
                }
                _ => continue,
            }
            self.entries[slot] = Some(e);
        }
        for slot in 0..self.addresses.len() {
            let Some(mut a) = self.addresses[slot] else {
                continue;
            };
            let transmits = self.port(a.link).map_or(0, |p| p.dad_transmits);
            if let Dad::Probing { sent, deadline } = a.dad
                && sent >= transmits
                && deadline <= now
            {
                a.dad = Dad::Done(AddressState::Assigned);
                self.addresses[slot] = Some(a);
                events(NdEvent::Assigned {
                    link: a.link,
                    address: a.address,
                });
            }
        }
    }

    // The earliest time `service` or `next_control` has work.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        let entries = self.entries.iter().flatten().filter_map(|e| match e.state {
            NeighborState::Stale => None,
            _ => Some(e.deadline),
        });
        let addresses = self.addresses.iter().flatten().filter_map(|a| match a.dad {
            Dad::Probing { deadline, .. } => Some(deadline),
            _ => None,
        });
        let answers = self.answers.iter().flatten().map(|a| a.queued);
        entries.chain(addresses).chain(answers).min()
    }
}
