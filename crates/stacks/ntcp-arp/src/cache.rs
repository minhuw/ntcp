// A bounded ARP resolution cache with Linux-style neighbour reachability
// states (the RFC 4861 section 7.3.2 machine Linux applies to ARP too). It
// performs no I/O: the embedding feeds it parsed packets and caller time,
// polls control messages to transmit and reports their outcomes. Every table
// is allocated fallibly at construction and never grows. Entries are keyed by
// link and IPv4 address, so one cache can serve several Ethernet ports.
use alloc::vec::Vec;
use core::net::Ipv4Addr;
use ntcp_ethernet::BROADCAST;

use crate::{Arp, Error, Operation};

/// Storage of one cache, all of it allocated by `ArpCache::new`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArpLimits {
    /// Registered Ethernet links.
    pub links: usize,
    /// Cache entries (dynamic and permanent), shared by every link.
    pub entries: usize,
    /// Output attempts held while their next hop is resolved. A held
    /// attempt stays with its owner, never transmitted, and is retried once
    /// resolved or failed otherwise; this table records only its tag.
    pub held: usize,
    /// Replies queued for control output. A request arriving while every
    /// slot is occupied is not answered (counted as a dropped reply); its
    /// sender retransmits.
    pub replies: usize,
    /// Local and published addresses.
    pub addresses: usize,
}

/// Timers and attempt counts, defaulting to Linux's neighbour defaults
/// (net.ipv4.neigh.default.*).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpTimers {
    /// base_reachable_time; each ReachableTime is drawn uniformly from
    /// [0.5, 1.5) times it.
    pub base_reachable_ms: u64,
    /// retrans_time: the spacing of requests to one destination and the
    /// wait after the last one before resolution fails.
    pub retrans_ms: u64,
    /// mcast_solicit: broadcast requests while INCOMPLETE (at least one).
    pub broadcast_requests: u8,
    /// ucast_solicit: unicast probes in PROBE.
    pub unicast_probes: u8,
    /// delay_first_probe_time.
    pub delay_first_probe_ms: u64,
}
impl Default for ArpTimers {
    fn default() -> Self {
        Self {
            base_reachable_ms: 30_000,
            retrans_ms: 1_000,
            broadcast_requests: 3,
            unicast_probes: 3,
            delay_first_probe_ms: 5_000,
        }
    }
}

/// The reachability state of an entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArpState {
    Incomplete,
    Reachable,
    Stale,
    Delay,
    Probe,
    /// Configured: never expires, never replaced by learning or evicted.
    Permanent,
}

/// An address this cache answers requests for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressKind {
    /// One of the node's own addresses, answered with its link's MAC; the
    /// source of the link's requests.
    Local,
    /// Answered with the given MAC on the node's behalf (proxy ARP); never
    /// used as a source.
    Published([u8; 6]),
}

/// The next hop's disposition for one output attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resolution {
    Ready([u8; 6]),
    /// Held while the address is resolved; `ArpCache::next_wake` reports
    /// its end.
    Held,
}

/// A held output attempt whose resolution ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Wake<T> {
    /// Resolved: retry it, which resolves again and finds the mapping.
    Retry(T),
    /// Resolution failed or its entry was removed; it was never sent.
    Unreachable(T),
}

/// A caller-time result the embedding acts on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event<L> {
    /// Resolution or unreachability probing failed: the entry is gone and
    /// its held output fails.
    Unreachable { link: L, address: Ipv4Addr },
}

/// One ARP packet to transmit on `link`, Ethernet `source` to `destination`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Control<L> {
    pub link: L,
    pub source: [u8; 6],
    pub destination: [u8; 6],
    pub arp: Arp,
}
impl<L> Control<L> {
    /// The complete Ethernet frame, padded to the 60-octet minimum.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        crate::encode_frame(out, self.source, self.destination, &self.arp)
    }
}

/// The authority to complete one polled control message; stale (and then
/// ignored) once its subject changed.
#[must_use = "an uncompleted ARP transmission is polled again"]
#[derive(Debug, Eq, PartialEq)]
pub struct ControlToken(Token);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Token {
    Entry { slot: usize, id: u64, sent: u8 },
    Reply { slot: usize, id: u64 },
}

/// What the backend's outcome for one control message means.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlOutcome {
    /// Definitely submitted: a request consumes an attempt and starts its
    /// RetransTimer spacing; a reply is done.
    Submitted,
    /// Possibly submitted: as Submitted, since it may be on the wire.
    Uncertain,
    /// Certainly not submitted, retried later: nothing is consumed, no
    /// spacing starts and a reply stays queued.
    Blocked,
    /// Certainly not submitted and not retried by the backend: a request
    /// stays due as if never polled; a reply ends, counted as dropped.
    Failed,
}

/// Cumulative counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArpCounters {
    /// Requests and probes possibly or definitely submitted.
    pub requests_sent: u64,
    /// Replies possibly or definitely submitted.
    pub replies_sent: u64,
    /// Replies not queued (queue full) or failed by the backend.
    pub replies_dropped: u64,
    /// Packets from another station claiming one of the local addresses.
    pub conflicts: u64,
    /// Entries failed by resolution or unreachability probing.
    pub resolution_failures: u64,
}

#[derive(Clone, Copy)]
struct Interface<L> {
    link: L,
    mac: [u8; 6],
    // The current ReachableTime, in caller units.
    reachable: u64,
}

#[derive(Clone, Copy)]
struct Entry<L> {
    id: u64,
    link: L,
    address: Ipv4Addr,
    state: ArpState,
    mac: Option<[u8; 6]>,
    // When `mac` last took its value: only packets submitted since went
    // to it.
    mapped_at: u64,
    // The last resolution through the entry (or its creation): the order in
    // which idle entries are reclaimed.
    used_at: u64,
    // REACHABLE expiry, DELAY end, or for INCOMPLETE and PROBE when the
    // next request is due (or, once all were sent, failure).
    deadline: u64,
    // Requests possibly or definitely submitted in INCOMPLETE or PROBE.
    sent: u8,
}

#[derive(Clone, Copy)]
struct Address<L> {
    link: L,
    address: Ipv4Addr,
    kind: AddressKind,
}

#[derive(Clone, Copy)]
struct Reply<L> {
    id: u64,
    link: L,
    destination: [u8; 6],
    arp: Arp,
    // When the request was accepted: the reply is due from then on.
    queued: u64,
}

#[derive(Clone, Copy)]
struct Pending<T> {
    entry: u64,
    // Resolution failed: the owner is advised and the attempt dropped.
    failed: bool,
    tag: T,
}

/// A bounded ARP cache for links `L` holding output attempts tagged `T`.
/// Time is caller time, in `units_per_second` units; it may run backwards,
/// which delays timers but never makes one fire early.
pub struct ArpCache<L, T> {
    units_per_second: u64,
    timers: ArpTimers,
    base_reachable: u64,
    retrans: u64,
    delay_first_probe: u64,
    next_id: u64,
    counters: ArpCounters,
    interfaces: Vec<Option<Interface<L>>>,
    entries: Vec<Option<Entry<L>>>,
    addresses: Vec<Option<Address<L>>>,
    replies: Vec<Option<Reply<L>>>,
    pending: Vec<Option<Pending<T>>>,
}

fn table<V: Clone>(count: usize, value: V) -> Result<Vec<V>, Error> {
    count
        .checked_mul(core::mem::size_of::<V>())
        .filter(|n| *n <= isize::MAX as usize)
        .ok_or(Error::Capacity)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    result.resize(count, value);
    Ok(result)
}

// Uniform in [0.5, 1.5) times `base` (Linux neigh_rand_reach_time; RFC 4861
// section 6.3.2), from the caller's entropy.
fn reachable_time(base: u64, random: &mut dyn FnMut() -> Option<u32>) -> Result<u64, Error> {
    let r = u128::from(random().ok_or(Error::Entropy)?);
    Ok(base / 2 + ((u128::from(base) * r) >> 32) as u64)
}

// An address no ARP exchange resolves: Ethernet maps broadcast and
// multicast directly, and the unspecified address is no station's.
fn unresolvable(address: Ipv4Addr) -> bool {
    address.is_unspecified() || address.is_broadcast() || address.is_multicast()
}

// A broadcast or multicast Ethernet address (the group bit) names no
// single station.
fn group_mac(mac: [u8; 6]) -> bool {
    mac[0] & 1 != 0
}

impl<L: Copy + Eq, T: Copy + PartialEq> ArpCache<L, T> {
    pub fn new(limits: ArpLimits, timers: ArpTimers, units_per_second: u64) -> Result<Self, Error> {
        if timers.broadcast_requests == 0 || units_per_second == 0 {
            return Err(Error::Config);
        }
        let units = |ms: u64| ms.saturating_mul(units_per_second) / 1000;
        Ok(Self {
            units_per_second,
            timers,
            base_reachable: units(timers.base_reachable_ms),
            retrans: units(timers.retrans_ms),
            delay_first_probe: units(timers.delay_first_probe_ms),
            next_id: 0,
            counters: ArpCounters::default(),
            interfaces: table(limits.links, None)?,
            entries: table(limits.entries, None)?,
            addresses: table(limits.addresses, None)?,
            replies: table(limits.replies, None)?,
            pending: table(limits.held, None)?,
        })
    }
    pub fn units_per_second(&self) -> u64 {
        self.units_per_second
    }
    pub fn timers(&self) -> ArpTimers {
        self.timers
    }
    pub fn counters(&self) -> ArpCounters {
        self.counters
    }
    fn id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }
    fn interface(&self, link: L) -> Option<&Interface<L>> {
        self.interfaces.iter().flatten().find(|i| i.link == link)
    }

    // Links.

    /// Whether `link` is registered: an embedding serving several kinds of
    /// port asks before it routes a packet or address here.
    pub fn has_link(&self, link: L) -> bool {
        self.interface(link).is_some()
    }

    /// Register an Ethernet link with its MAC; its ReachableTime is drawn
    /// from `random`.
    pub fn add_link(
        &mut self,
        link: L,
        mac: [u8; 6],
        random: &mut dyn FnMut() -> Option<u32>,
    ) -> Result<(), Error> {
        if self.interface(link).is_some() {
            return Err(Error::Duplicate);
        }
        let slot = self
            .interfaces
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let reachable = reachable_time(self.base_reachable, random)?;
        self.interfaces[slot] = Some(Interface {
            link,
            mac,
            reachable,
        });
        Ok(())
    }

    /// Forget a link with its entries, addresses and queued replies; its
    /// held output fails.
    pub fn remove_link(&mut self, link: L) {
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
        for reply in &mut self.replies {
            if reply.is_some_and(|r| r.link == link) {
                *reply = None;
            }
        }
    }

    // Addresses.

    /// Answer requests on `link` for `address`. A local address also
    /// sources the link's requests; a published one is answered only.
    pub fn add_address(
        &mut self,
        link: L,
        address: Ipv4Addr,
        kind: AddressKind,
    ) -> Result<(), Error> {
        self.interface(link).ok_or(Error::UnknownLink)?;
        if unresolvable(address) {
            return Err(Error::Address);
        }
        if self.address(link, address).is_some() {
            return Err(Error::Duplicate);
        }
        let slot = self
            .addresses
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.addresses[slot] = Some(Address {
            link,
            address,
            kind,
        });
        Ok(())
    }

    /// Stop answering for `address` on `link`. When the link keeps no local
    /// address, it can send no request, so its resolutions and probes fail
    /// now rather than stall.
    pub fn remove_address(&mut self, link: L, address: Ipv4Addr) -> bool {
        let Some(slot) = self.address(link, address) else {
            return false;
        };
        self.addresses[slot] = None;
        if self.source(link).is_none() {
            for slot in 0..self.entries.len() {
                if self.entries[slot].is_some_and(|e| {
                    e.link == link && matches!(e.state, ArpState::Incomplete | ArpState::Probe)
                }) {
                    self.fail(slot);
                    self.counters.resolution_failures += 1;
                }
            }
        }
        true
    }

    fn address(&self, link: L, address: Ipv4Addr) -> Option<usize> {
        self.addresses
            .iter()
            .position(|a| a.is_some_and(|a| a.link == link && a.address == address))
    }
    fn answered(&self, address: Ipv4Addr) -> Option<AddressKind> {
        self.addresses
            .iter()
            .flatten()
            .find(|a| a.address == address)
            .map(|a| a.kind)
    }
    // The sender address of the link's requests: its first local address.
    fn source(&self, link: L) -> Option<Ipv4Addr> {
        self.addresses
            .iter()
            .flatten()
            .find(|a| a.link == link && a.kind == AddressKind::Local)
            .map(|a| a.address)
    }

    // Entries.

    /// Configure a permanent mapping, replacing any dynamic entry for the
    /// address (whose held output is then ready).
    pub fn add_permanent(
        &mut self,
        link: L,
        address: Ipv4Addr,
        mac: [u8; 6],
        now: u64,
    ) -> Result<(), Error> {
        self.interface(link).ok_or(Error::UnknownLink)?;
        if unresolvable(address) || self.answered(address).is_some() || group_mac(mac) {
            return Err(Error::Address);
        }
        let (slot, id) = match self.find(link, address) {
            Some(slot) => (slot, self.entries[slot].unwrap().id),
            None => (self.vacancy().ok_or(Error::Capacity)?, self.id()),
        };
        self.entries[slot] = Some(Entry {
            id,
            link,
            address,
            state: ArpState::Permanent,
            mac: Some(mac),
            mapped_at: now,
            used_at: now,
            deadline: now,
            sent: 0,
        });
        Ok(())
    }

    /// Remove the entry for `address`, permanent or dynamic; its held
    /// output fails.
    pub fn remove_entry(&mut self, link: L, address: Ipv4Addr) -> bool {
        match self.find(link, address) {
            Some(slot) => {
                self.fail(slot);
                true
            }
            None => false,
        }
    }

    /// The state and mapping of the entry for `address` on `link`.
    pub fn entry(&self, link: L, address: Ipv4Addr) -> Option<(ArpState, Option<[u8; 6]>)> {
        let e = self.entries[self.find(link, address)?]?;
        Some((e.state, e.mac))
    }

    fn find(&self, link: L, address: Ipv4Addr) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.is_some_and(|e| e.link == link && e.address == address))
    }

    // A slot for a new entry: a free one, else the STALE entry used longest
    // ago with no held output. A STALE entry is idle (its next use starts
    // DELAY), so reclaiming it costs at most a new resolution, while active
    // entries (INCOMPLETE, REACHABLE, DELAY, PROBE), permanent ones and
    // entries owing held output stay pinned; their exhaustion is
    // backpressure.
    fn vacancy(&self) -> Option<usize> {
        if let Some(slot) = self.entries.iter().position(Option::is_none) {
            return Some(slot);
        }
        let held = |id| self.pending.iter().flatten().any(|p| p.entry == id);
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(slot, e)| Some((slot, (*e)?)))
            .filter(|(_, e)| e.state == ArpState::Stale && !held(e.id))
            .min_by_key(|(_, e)| e.used_at)
            .map(|(slot, _)| slot)
    }

    // The entry is removed and its held output fails.
    fn fail(&mut self, slot: usize) {
        let id = self.entries[slot].unwrap().id;
        self.entries[slot] = None;
        for p in self.pending.iter_mut().flatten() {
            if p.entry == id {
                p.failed = true;
            }
        }
    }

    // Reachability is confirmed on `link`: a fresh ReachableTime is drawn
    // (Linux re-randomizes it periodically; every confirmation satisfies
    // that), returning the REACHABLE deadline.
    fn confirmation(
        &mut self,
        link: L,
        now: u64,
        random: &mut dyn FnMut() -> Option<u32>,
    ) -> Result<u64, Error> {
        let base = self.base_reachable;
        let interface = self
            .interfaces
            .iter_mut()
            .flatten()
            .find(|i| i.link == link)
            .ok_or(Error::UnknownLink)?;
        interface.reachable = reachable_time(base, random)?;
        Ok(now.saturating_add(interface.reachable))
    }

    /// An upper-layer reachability confirmation (Linux dst_confirm; RFC
    /// 4861 section 7.3.1): forward progress through the neighbour by a
    /// packet submitted at `carried_at`. It never resolves INCOMPLETE,
    /// leaves permanent entries alone, and confirms nothing when the
    /// mapping has changed since: the packet went to another MAC.
    pub fn confirm(
        &mut self,
        link: L,
        address: Ipv4Addr,
        carried_at: u64,
        now: u64,
        random: &mut dyn FnMut() -> Option<u32>,
    ) -> Result<bool, Error> {
        let Some(slot) = self.find(link, address) else {
            return Ok(false);
        };
        let mut e = self.entries[slot].unwrap();
        if matches!(e.state, ArpState::Incomplete | ArpState::Permanent) || e.mapped_at > carried_at
        {
            return Ok(false);
        }
        e.deadline = self.confirmation(link, now, random)?;
        e.state = ArpState::Reachable;
        e.sent = 0;
        self.entries[slot] = Some(e);
        Ok(true)
    }

    // Egress.

    /// The disposition of output `tag` for `address` on `link`. A usable
    /// mapping is returned (the first use of a STALE one starts DELAY);
    /// otherwise the tag is held (once, however often it is retried), its
    /// slot reserved before an INCOMPLETE entry is created, so exhaustion
    /// of either is backpressure (`Error::Capacity`) that leaves nothing
    /// behind.
    pub fn resolve(
        &mut self,
        link: L,
        address: Ipv4Addr,
        now: u64,
        tag: T,
    ) -> Result<Resolution, Error> {
        self.interface(link).ok_or(Error::UnknownLink)?;
        if unresolvable(address) || self.answered(address).is_some() {
            return Err(Error::Address);
        }
        let found = self.find(link, address);
        if let Some(slot) = found {
            let mut e = self.entries[slot].unwrap();
            if let Some(mac) = e.mac.filter(|_| e.state != ArpState::Incomplete) {
                if e.state == ArpState::Stale {
                    e.state = ArpState::Delay;
                    e.deadline = now.saturating_add(self.delay_first_probe);
                }
                e.used_at = now;
                self.entries[slot] = Some(e);
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
                self.source(link).ok_or(Error::NoSource)?;
                let slot = self.vacancy().ok_or(Error::Capacity)?;
                let id = self.id();
                self.entries[slot] = Some(Entry {
                    id,
                    link,
                    address,
                    state: ArpState::Incomplete,
                    mac: None,
                    mapped_at: now,
                    used_at: now,
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

    /// The next held attempt accepted by `filter` whose resolution ended,
    /// removed from the held set. The embedding keeps the attempt itself
    /// (one transmit slot per owner) and retries it on `Wake::Retry`.
    //= https://www.rfc-editor.org/rfc/rfc1122#section-2.3.2.2
    //# The link layer SHOULD save (rather than discard) at least
    //# one (the latest) packet of each set of packets destined to
    //# the same unresolved IP address, and transmit the saved
    //# packet when the address has been resolved.
    pub fn next_wake(&mut self, filter: impl Fn(&T) -> bool) -> Option<Wake<T>> {
        for slot in 0..self.pending.len() {
            let Some(p) = self.pending[slot].filter(|p| filter(&p.tag)) else {
                continue;
            };
            let entry = self.entries.iter().flatten().find(|e| e.id == p.entry);
            let wake = match entry {
                _ if p.failed => Wake::Unreachable(p.tag),
                None => Wake::Unreachable(p.tag),
                Some(e) if e.state != ArpState::Incomplete => Wake::Retry(p.tag),
                Some(_) => continue,
            };
            self.pending[slot] = None;
            return Some(wake);
        }
        None
    }

    /// Forget every held record of `tag` (its owner gave the attempt up).
    pub fn release(&mut self, tag: T) -> bool {
        let mut found = false;
        for p in &mut self.pending {
            if p.is_some_and(|p| p.tag == tag) {
                *p = None;
                found = true;
            }
        }
        found
    }

    // Ingress.

    /// A parsed ARP packet received on `link` (RFC 826 "Packet Reception").
    /// A reply answering this node's outstanding request draws a new
    /// ReachableTime from `random`; when that fails, nothing changes and
    /// the error is returned.
    pub fn receive(
        &mut self,
        link: L,
        arp: &Arp,
        now: u64,
        random: &mut dyn FnMut() -> Option<u32>,
    ) -> Result<(), Error> {
        let interface = *self.interface(link).ok_or(Error::UnknownLink)?;
        // The link's own transmission looped back, or a sender hardware
        // address naming no single station (a reply to it would not be
        // unicast): nothing to learn or answer.
        if arp.sender_mac == interface.mac || group_mac(arp.sender_mac) {
            return Ok(());
        }
        let target = self.address(link, arp.target_ip).map(|slot| {
            let a = self.addresses[slot].unwrap();
            a.kind
        });
        let sender = arp.sender_ip;
        if sender.is_unspecified() {
            // An RFC 5227 probe: its sender has no address to learn. A
            // probe for a local address is answered (as Linux does), so
            // the prober finds the address in use; published addresses
            // are not defended.
            if arp.operation == Operation::Request && target == Some(AddressKind::Local) {
                self.answer(link, interface.mac, arp, now);
            }
            return Ok(());
        }
        if unresolvable(sender) {
            return Ok(());
        }
        match self.answered(sender) {
            // Another station claims a local address: counted, never
            // learned; no defence.
            Some(AddressKind::Local) => {
                self.counters.conflicts += 1;
                return Ok(());
            }
            Some(AddressKind::Published(_)) => return Ok(()),
            None => {}
        }
        let found = self.find(link, sender);
        // A reply to this node's own request: one addressed from a local
        // address and MAC of this link to an entry still resolving or
        // probing.
        let solicited = arp.operation == Operation::Reply
            && target == Some(AddressKind::Local)
            && arp.target_mac == interface.mac
            && found.is_some_and(|slot| {
                matches!(
                    self.entries[slot].unwrap().state,
                    ArpState::Incomplete | ArpState::Probe
                )
            });
        let reachable = if solicited {
            Some(self.confirmation(link, now, random)?)
        } else {
            None
        };
        //= https://www.rfc-editor.org/rfc/rfc826#name-abstract
        //# Merge_flag := false
        //# If the pair <protocol type, sender protocol address> is
        //# already in my translation table, update the sender
        //# hardware address field of the entry with the new
        //# information in the packet and set Merge_flag to true.
        //
        //= https://www.rfc-editor.org/rfc/rfc826#name-abstract
        //# Notice that the <protocol type, sender protocol address, sender
        //# hardware address> triplet is merged into the table before the
        //# opcode is looked at.
        //
        // Permanent entries are configuration, never merged (Linux
        // NUD_PERMANENT). A changed mapping is unconfirmed (STALE); an
        // unchanged one keeps its state, unless the packet answers this
        // node's request, which confirms it (REACHABLE).
        if let Some(slot) = found {
            let mut e = self.entries[slot].unwrap();
            if e.state != ArpState::Permanent {
                let changed = e.mac != Some(arp.sender_mac);
                if changed {
                    e.mac = Some(arp.sender_mac);
                    e.mapped_at = now;
                }
                if let Some(deadline) = reachable {
                    e.state = ArpState::Reachable;
                    e.deadline = deadline;
                    e.sent = 0;
                } else if changed {
                    e.state = ArpState::Stale;
                    e.deadline = now;
                    e.sent = 0;
                }
                self.entries[slot] = Some(e);
            }
        }
        let Some(kind) = target else {
            return Ok(());
        };
        // Only a request for an answered address adds its sender (STALE, as
        // Linux neigh_event_ns), since this node will likely talk back. A
        // reply or gratuitous announcement from an uncached sender adds
        // nothing (Linux arp_accept=0): it could fill the table with
        // mappings nobody asked for. Without a free or reclaimable entry
        // nothing is learned; the mapping is resolved on first use.
        if arp.operation != Operation::Request {
            return Ok(());
        }
        if found.is_none()
            && let Some(slot) = self.vacancy()
        {
            let id = self.id();
            self.entries[slot] = Some(Entry {
                id,
                link,
                address: sender,
                state: ArpState::Stale,
                mac: Some(arp.sender_mac),
                mapped_at: now,
                used_at: now,
                deadline: now,
                sent: 0,
            });
        }
        let claim = match kind {
            AddressKind::Local => interface.mac,
            AddressKind::Published(mac) => mac,
        };
        self.answer(link, claim, arp, now);
        Ok(())
    }

    // Queue the reply to `request`, claiming its target address for `mac`.
    //= https://www.rfc-editor.org/rfc/rfc826#name-abstract
    //# ?Is the opcode ares_op$REQUEST?  (NOW look at the opcode!!)
    //# Yes:
    //# Swap hardware and protocol fields, putting the local
    //# hardware and protocol addresses in the sender fields.
    //# Set the ar$op field to ares_op$REPLY
    //# Send the packet to the (new) target hardware address on
    //# the same hardware on which the request was received.
    fn answer(&mut self, link: L, mac: [u8; 6], request: &Arp, now: u64) {
        let arp = Arp {
            operation: Operation::Reply,
            sender_mac: mac,
            sender_ip: request.target_ip,
            target_mac: request.sender_mac,
            target_ip: request.sender_ip,
        };
        let destination = request.sender_mac;
        // A retransmitted request whose reply is still queued adds nothing.
        if self
            .replies
            .iter()
            .flatten()
            .any(|r| r.link == link && r.destination == destination && r.arp == arp)
        {
            return;
        }
        let id = self.id();
        match self.replies.iter_mut().find(|r| r.is_none()) {
            Some(free) => {
                *free = Some(Reply {
                    id,
                    link,
                    destination,
                    arp,
                    queued: now,
                })
            }
            None => self.counters.replies_dropped += 1,
        }
    }

    // Control output.

    /// The next control message for `link` due at `now`: queued replies
    /// first, then broadcast requests and unicast probes. Polling changes
    /// nothing; `complete` applies the backend's outcome, so requests to one
    /// destination stay spaced by RetransTimer however often this is
    /// polled.
    pub fn next_control(&self, link: L, now: u64) -> Option<(Control<L>, ControlToken)> {
        let interface = self.interface(link)?;
        for (slot, r) in self.replies.iter().enumerate() {
            if let Some(r) = r.filter(|r| r.link == link) {
                let control = Control {
                    link,
                    source: interface.mac,
                    destination: r.destination,
                    arp: r.arp,
                };
                return Some((control, ControlToken(Token::Reply { slot, id: r.id })));
            }
        }
        let source = self.source(link)?;
        for (slot, e) in self.entries.iter().enumerate() {
            let Some(e) = e.filter(|e| e.link == link) else {
                continue;
            };
            let (limit, destination) = match (e.state, e.mac) {
                //= https://www.rfc-editor.org/rfc/rfc826#name-abstract
                //# It then causes
                //# this packet to be broadcast to all stations on the Ethernet cable
                //# originally determined by the routing mechanism.
                (ArpState::Incomplete, _) => (self.timers.broadcast_requests, BROADCAST),
                (ArpState::Probe, Some(mac)) => (self.timers.unicast_probes, mac),
                _ => continue,
            };
            if e.sent < limit && e.deadline <= now {
                //= https://www.rfc-editor.org/rfc/rfc826#name-abstract
                //# The Address
                //# Resolution module then sets the ar$hrd field to
                //# ares_hrd$Ethernet, ar$pro to the protocol type that is being
                //# resolved, ar$hln to 6 (the number of bytes in a 48.bit Ethernet
                //# address), ar$pln to the length of an address in that protocol,
                //# ar$op to ares_op$REQUEST, ar$sha with the 48.bit ethernet address
                //# of itself, ar$spa with the protocol address of itself, and ar$tpa
                //# with the protocol address of the machine that is trying to be
                //# accessed.
                //
                // ar$tha is zero, as Linux sends it, in broadcast requests and
                // unicast probes alike.
                //= https://www.rfc-editor.org/rfc/rfc826#name-abstract
                //# It does not set ar$tha to anything in particular,
                //# because it is this value that it is trying to determine.
                let arp = Arp {
                    operation: Operation::Request,
                    sender_mac: interface.mac,
                    sender_ip: source,
                    target_mac: [0; 6],
                    target_ip: e.address,
                };
                let control = Control {
                    link,
                    source: interface.mac,
                    destination,
                    arp,
                };
                let token = Token::Entry {
                    slot,
                    id: e.id,
                    sent: e.sent,
                };
                return Some((control, ControlToken(token)));
            }
        }
        None
    }

    /// The backend's outcome for one polled control message.
    //= https://www.rfc-editor.org/rfc/rfc1122#section-2.3.2.1
    //# A mechanism to prevent ARP flooding (repeatedly sending an
    //# ARP Request for the same IP address, at a high rate) MUST be
    //# included.  The recommended maximum rate is 1 per second per
    //# destination.
    //
    // Each possibly submitted request to a destination defers its next one
    // by RetransTimer (1 s by default), and only `next_control` originates
    // requests.
    pub fn complete(&mut self, token: ControlToken, outcome: ControlOutcome, now: u64) {
        match token.0 {
            Token::Reply { slot, id } => {
                if outcome == ControlOutcome::Blocked
                    || !self.replies[slot].is_some_and(|r| r.id == id)
                {
                    return;
                }
                self.replies[slot] = None;
                if outcome == ControlOutcome::Failed {
                    self.counters.replies_dropped += 1;
                } else {
                    self.counters.replies_sent += 1;
                }
            }
            _ if matches!(outcome, ControlOutcome::Blocked | ControlOutcome::Failed) => {}
            Token::Entry { slot, id, sent } => {
                let Some(mut e) = self.entries[slot].filter(|e| e.id == id && e.sent == sent)
                else {
                    return;
                };
                if !matches!(e.state, ArpState::Incomplete | ArpState::Probe) {
                    return;
                }
                // Submitted or Uncertain alike: one attempt is consumed.
                e.sent = sent + 1;
                e.deadline = now.saturating_add(self.retrans);
                self.entries[slot] = Some(e);
                self.counters.requests_sent += 1;
            }
        }
    }

    // Caller-time service.

    /// Apply every timer due at `now`: REACHABLE to STALE after
    /// ReachableTime, DELAY to PROBE after DELAY_FIRST_PROBE, and failure a
    /// full RetransTimer after the final request or probe. On a link without
    /// a local address, which can send no request, a due resolution or
    /// validation fails at once instead.
    //= https://www.rfc-editor.org/rfc/rfc1122#section-2.3.2.1
    //# An implementation of the Address Resolution Protocol (ARP)
    //# [LINK:2] MUST provide a mechanism to flush out-of-date cache
    //# entries.  If this mechanism involves a timeout, it SHOULD be
    //# possible to configure the timeout value.
    pub fn service(&mut self, now: u64, events: &mut impl FnMut(Event<L>)) {
        for slot in 0..self.entries.len() {
            let Some(mut e) = self.entries[slot] else {
                continue;
            };
            if e.deadline > now {
                continue;
            }
            match e.state {
                ArpState::Reachable => e.state = ArpState::Stale,
                // Its request could never be polled: left in place, the
                // entry would keep an unvalidated mapping in use and a
                // deadline that is always due.
                ArpState::Incomplete | ArpState::Delay | ArpState::Probe
                    if self.source(e.link).is_none() =>
                {
                    self.unreachable(slot, events);
                    continue;
                }
                ArpState::Delay => {
                    e.state = ArpState::Probe;
                    e.sent = 0;
                    e.deadline = now;
                }
                ArpState::Incomplete if e.sent >= self.timers.broadcast_requests => {
                    self.unreachable(slot, events);
                    continue;
                }
                ArpState::Probe if e.sent >= self.timers.unicast_probes => {
                    self.unreachable(slot, events);
                    continue;
                }
                _ => continue,
            }
            self.entries[slot] = Some(e);
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc826#name-abstract
    //# After a suitable time, the daemon considers removing an entry.
    //# It first sends (with a small number of retransmissions if needed)
    //# an address resolution packet with opcode REQUEST directly to the
    //# Ethernet address in the table.  If a REPLY is not seen in a short
    //# amount of time, the entry is deleted.  The request is sent
    //# directly so as not to bother every station on the Ethernet.
    fn unreachable(&mut self, slot: usize, events: &mut impl FnMut(Event<L>)) {
        let e = self.entries[slot].unwrap();
        self.fail(slot);
        self.counters.resolution_failures += 1;
        events(Event::Unreachable {
            link: e.link,
            address: e.address,
        });
    }

    /// The earliest time `service` or `next_control` has work.
    pub fn next_deadline(&self) -> Option<u64> {
        let entries = self.entries.iter().flatten().filter_map(|e| match e.state {
            ArpState::Stale | ArpState::Permanent => None,
            _ => Some(e.deadline),
        });
        let replies = self.replies.iter().flatten().map(|r| r.queued);
        entries.chain(replies).min()
    }
}
