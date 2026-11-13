// The Host side of Neighbor Discovery: ND-capable Ethernet port
// registration, configured addresses under Duplicate Address Detection, ND
// ingress ahead of ordinary destination admission, control output and
// caller-time service (`neighbor` holds the state). The same calls resolve
// the IPv4 next hops of a neighbor port by ARP (`arp` holds that state).
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ntcp::{Instant, IpMetadata};
use ntcp_icmp::{
    ND_HOP_LIMIT, NeighborAdvertisement, NeighborMessage, NeighborSolicitation, decode_neighbor,
};
use ntcp_path::{InterfaceKey, LinkId, PathService, ScopedAddress};

use crate::neighbor::{
    AddressState, Control, ControlOutcome, ControlToken, Destination, NdEvent, NdPort, Resolution,
};
use crate::{
    Advice, BackendOutcome, EgressContext, Error, Forwarding, Host, IngressContext,
    Ipv4NeighborTable, Ipv4Receive, Ipv6Receive, NeighborHold, Owner, ReceiveCapabilities,
    Received, ResolvedNextHop,
};
use alloc::boxed::Box;
use ntcp::TransmitAttempt;
#[cfg(any(test, feature = "test-support"))]
use ntcp_arp::ArpState;

const ICMPV6: u8 = 58;
const SOLICITATION: u8 = 135;
const ADVERTISEMENT: u8 = 136;
const REDIRECT: u8 = 137;

/// One neighbor control packet written by `Host::neighbor_output`: `len`
/// octets for `link`, carried in an Ethernet frame of type `ethertype` to
/// `destination`: a complete IPv6 ND packet (to a 33:33 group or a resolved
/// neighbor), or an ARP body (broadcast, or unicast to the station it
/// answers or probes). Its ticket completes it.
#[must_use = "an uncompleted ND transmission is polled again"]
#[derive(Debug, Eq, PartialEq)]
pub struct NeighborTransmit {
    pub link: LinkId,
    pub destination: [u8; 6],
    pub ethertype: u16,
    pub len: usize,
    pub ticket: NeighborTicket,
}

/// Authority to report the outcome of one neighbor control packet.
#[derive(Debug, Eq, PartialEq)]
pub struct NeighborTicket {
    context: crate::ContextId,
    token: Token,
}

// The cache a control packet came from.
#[derive(Debug, Eq, PartialEq)]
enum Token {
    Nd(ControlToken),
    Arp(ntcp_arp::ControlToken),
}

/// One caller-time Neighbor Discovery pass (`Host::service_neighbors`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NeighborReport {
    /// Addresses whose DAD completed, now published as sources.
    pub assigned: usize,
    /// Addresses found duplicate since the previous pass (by received
    /// solicitations or advertisements), which stay unusable.
    pub duplicates: usize,
    pub first_error: Option<Error>,
}

/// The Ethernet next hop of one output attempt on a neighbor port
/// (`Host::resolve_neighbor`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NeighborHop {
    Resolved([u8; 6]),
    /// Address resolution is pending. The attempt is held, not transmitted:
    /// the embedding keeps it blocked (`BackendOutcome::WouldBlock`), so
    /// nothing is committed, charged or trained, until `neighbor_wake`
    /// releases it.
    Held,
}

/// A held output attempt whose neighbor resolution ended
/// (`Host::neighbor_wake`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NeighborWake {
    /// Resolved: retry it through egress, which revalidates its path, link
    /// generation, MTU and the neighbor mapping before submission.
    Retry {
        owner: Owner,
        attempt: TransmitAttempt,
    },
    /// Resolution failed (RFC 4861 section 7.2.2; for an IPv4 next hop,
    /// ARP's requests went unanswered): the owner's advice is
    /// Address Unreachable, which RFC 4443 classes as a soft error; the
    /// attempt was never transmitted.
    Unreachable {
        owner: Owner,
        attempt: TransmitAttempt,
        advice: Advice,
    },
}

// The identity of held output: one pending slot however often retried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeldOutput {
    // A transport attempt, blocked with its owner.
    Transport {
        owner: Owner,
        attempt: TransmitAttempt,
    },
    // A queued Host ICMP message (its queueing order), held in the queue.
    Icmp(u64),
    // The Echo adjunct probe of a path, sent again once resolved.
    Probe(ntcp_path::PathId),
}

fn v6(address: IpAddr) -> Option<Ipv6Addr> {
    match address {
        IpAddr::V6(address) => Some(address),
        IpAddr::V4(_) => None,
    }
}

impl Host {
    /// Register a neighbor Ethernet port: its next hops are resolved by this
    /// Host (`Forwarding::IpNextHop`), its addresses are configured through
    /// `add_neighbor_address`, and its ReachableTime is drawn from the
    /// Host's entropy, which must be set. IPv6 next hops are resolved by
    /// Neighbor Discovery, whose addresses stay tentative until Duplicate
    /// Address Detection completes (`Limits::neighbors` storage). When the
    /// port receives IPv4 and `Limits::ipv4_neighbors` provides storage, its
    /// IPv4 next hops are resolved by ARP; such a port that does not
    /// receive IPv6 takes no Neighbor Discovery storage.
    pub fn register_neighbor_port(
        &mut self,
        interface: InterfaceKey,
        mtu: u32,
        receive: ReceiveCapabilities,
        port: NdPort,
    ) -> Result<IngressContext, Error> {
        let arp = receive.ipv4 != Ipv4Receive::Disabled && self.ipv4_neighbors.enabled();
        let nd = receive.ipv6 != Ipv6Receive::Disabled || !arp;
        if nd && self.neighbors.ports_free() == 0 {
            return Err(Error::Capacity);
        }
        if self.entropy.is_none() {
            return Err(Error::Entropy);
        }
        let context = self.register_link(interface, mtu, receive, Forwarding::IpNextHop)?;
        let mut added = if nd {
            self.neighbors
                .add_port(context.link, port, self.entropy.as_mut())
        } else {
            Ok(())
        };
        if arp && added.is_ok() {
            added = self.ipv4_neighbors.table_mut().add_link(
                context.link,
                port.mac,
                self.entropy.as_mut(),
            );
        }
        if let Err(error) = added {
            self.remove_link(context)?;
            return Err(error);
        }
        Ok(context)
    }

    /// Configure `address` on a neighbor port. An IPv6 address is tentative
    /// (no ordinary traffic leaves from it and none is received for it)
    /// until DAD, which starts once `neighbor_membership_ready` states its
    /// groups are joined, completes in `service_neighbors`; with
    /// DupAddrDetectTransmits 0 it is published at once. An IPv4 address on
    /// a port that resolves IPv4 by ARP is published at once (no conflict
    /// detection): ARP answers requests for it, and the port's first one is
    /// the source of its requests.
    pub fn add_neighbor_address(
        &mut self,
        link: LinkId,
        address: impl Into<IpAddr>,
    ) -> Result<AddressState, Error> {
        self.port(link)?;
        let address = match address.into() {
            IpAddr::V6(address) => address,
            IpAddr::V4(address) => return self.add_ipv4_neighbor_address(link, address),
        };
        let zone = address.is_unicast_link_local().then_some(link);
        // Checked before DAD, which would otherwise publish nothing.
        ScopedAddress::new(IpAddr::V6(address), zone)?;
        let state = self.neighbors.add_address(link, address)?;
        if state == AddressState::Assigned
            && let Err(error) = publish(&mut self.paths, link, address)
        {
            self.neighbors.remove_address(link, address);
            return Err(error);
        }
        Ok(state)
    }

    fn add_ipv4_neighbor_address(
        &mut self,
        link: LinkId,
        address: Ipv4Addr,
    ) -> Result<AddressState, Error> {
        let table = self.ipv4_neighbors.table_mut();
        if !table.has_link(link) {
            return Err(Error::InvalidContext);
        }
        let scoped = ScopedAddress::new(IpAddr::V4(address), None)?;
        table.add_local(link, address)?;
        if let Err(error) = self.paths.register_source(scoped, link) {
            self.ipv4_neighbors.table_mut().remove_local(link, address);
            return Err(error.into());
        }
        Ok(AddressState::Assigned)
    }

    /// Configure a permanent mapping for an IPv4 neighbor on a port that
    /// resolves IPv4 by ARP: it never expires and what ARP learns never
    /// replaces it. Neighbor Discovery keeps no such entries (`Unsupported`
    /// for an IPv6 neighbor).
    pub fn add_static_neighbor(
        &mut self,
        link: LinkId,
        address: IpAddr,
        mac: [u8; 6],
        now: Instant,
    ) -> Result<(), Error> {
        self.port(link)?;
        let IpAddr::V4(address) = address else {
            return Err(Error::Unsupported);
        };
        let table = self.ipv4_neighbors.table_mut();
        if !table.has_link(link) {
            return Err(Error::Unsupported);
        }
        table.add_permanent(link, address, mac, now)
    }

    /// Resolve the IPv4 next hops of neighbor ports through `table` instead
    /// of this Host's own cache (`Limits::ipv4_neighbors`, then unused):
    /// for example one Ethernet port's table, shared by the Hosts of its
    /// queues. Every port registered afterwards that receives IPv4 resolves
    /// it there. Refused (`InvalidContext`) once a link is registered.
    pub fn set_ipv4_neighbor_table(
        &mut self,
        table: Box<dyn Ipv4NeighborTable>,
    ) -> Result<(), Error> {
        if self.ports.iter().any(Option::is_some) {
            return Err(Error::InvalidContext);
        }
        self.ipv4_neighbors.install(table);
        Ok(())
    }

    /// The table `set_ipv4_neighbor_table` installed: its embedding drives
    /// what the Host's calls do not (a shared table's housekeeping).
    pub fn ipv4_neighbor_table_mut(&mut self) -> Option<&mut (dyn Ipv4NeighborTable + 'static)> {
        self.ipv4_neighbors.installed()
    }

    /// The embedding has joined all-nodes and `address`'s solicited-node
    /// group on `link`'s interface; its first DAD probe follows a random
    /// delay (RFC 4862 section 5.4.2).
    pub fn neighbor_membership_ready(
        &mut self,
        link: LinkId,
        address: Ipv6Addr,
        now: Instant,
    ) -> Result<(), Error> {
        self.neighbors
            .membership_ready(link, address, now, self.entropy.as_mut())
    }

    pub fn neighbor_address_state(&self, link: LinkId, address: Ipv6Addr) -> Option<AddressState> {
        self.neighbors.address_state(link, address)
    }

    /// Inspection for tests of embeddings that serve ND ports: the cache
    /// entry for `address` on `link`, its state, link-layer address and
    /// IsRouter flag. Resolution itself is `resolve_neighbor`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn neighbor(
        &self,
        link: LinkId,
        address: Ipv6Addr,
    ) -> Option<(crate::NeighborState, Option<[u8; 6]>, bool)> {
        self.neighbors.state(link, address)
    }

    /// Inspection for tests of embeddings that serve IPv4 neighbor ports:
    /// the ARP entry for `address` on `link`, its state and MAC.
    #[cfg(any(test, feature = "test-support"))]
    pub fn ipv4_neighbor(
        &self,
        link: LinkId,
        address: Ipv4Addr,
    ) -> Option<(ArpState, Option<[u8; 6]>)> {
        self.ipv4_neighbors.table().entry(link, address)
    }

    /// Apply every Neighbor Discovery and ARP timer due at `now`
    /// (reachability, probing, resolution failure and DAD completion).
    pub fn service_neighbors(&mut self, now: Instant) -> NeighborReport {
        let mut report = NeighborReport {
            duplicates: core::mem::take(&mut self.unreported_duplicates),
            ..NeighborReport::default()
        };
        let Self {
            neighbors,
            ipv4_neighbors,
            paths,
            ..
        } = self;
        neighbors.service(now, &mut |event| apply(paths, event, &mut report));
        ipv4_neighbors
            .table_mut()
            .service(now, &mut |link, address| {
                lost(
                    paths,
                    link,
                    IpAddr::V4(address),
                    None,
                    ntcp_path::NeighborLoss::Unreachable,
                    &mut report,
                )
            });
        self.settle_held_icmp(now);
        report
    }

    /// The Ethernet next hop of `context`'s output attempt, held for
    /// `owner` on a neighbor port: its next hop's cached mapping (the first
    /// use of a STALE one starts DELAY; STALE, DELAY and PROBE never block
    /// output), or Held while it is resolved, by Neighbor Discovery for an
    /// IPv6 next hop and by ARP for an IPv4 one (`Unsupported` on a port
    /// that does not resolve the family). Exhausted neighbor or pending
    /// storage is backpressure (`Error::Capacity`) that leaves no entry
    /// behind. A TCP owner keeps the address it found while the entry is
    /// REACHABLE or PERMANENT and uses it until that entry changes, without
    /// resolving again and so without refreshing the entry's use time, as
    /// Linux's neigh_output sends to a NUD_CONNECTED entry; an IPv4 table
    /// installed with `set_ipv4_neighbor_table` takes part when it reports
    /// a generation (`Ipv4NeighborTable::generation`).
    //= https://www.rfc-editor.org/rfc/rfc8201#section-3
    //= reason=No same-link bypass: PathService::select resolves an on-link route's next hop to the destination itself and keys, estimates and correlates that path exactly as a gateway path, so on-link destinations get the same shared estimate, Packet Too Big processing and PLPMTUD; the Host resolves the next hop by bounded host Neighbor Discovery (Host::resolve_neighbor holds output until an NS/NA exchange maps it), which changes no Path MTU state. Host test on_link_route_resolves_by_neighbor_discovery_and_keeps_pmtud: an on-link route is resolved by NS/NA before the SYN leaves and a downstream PTB correlated with a definitely submitted data segment lowers the path estimate to 1280 while the 1500 first-hop fact stays; core wire test ipv6_same_prefix_proxy_wire_path_does_not_bypass_downstream_ptb: 1500-to-1280 feedback, bounded repair and real receiver progress for a same-/64 peer. Namespace evidence (T19, AC-22; integration/rfc_host nd-proxy cases): the native runtime selects a destination inside its /64 through its on-link route, and a Linux router answers its Neighbor Solicitation for that destination, which lies behind it, as an NDP proxy (proxy_ndp with ip -6 neigh add proxy); no native segment precedes the solicited proxy NA and every segment carries the router's MAC with the destination's IPv6 address. After the router's downstream link falls from 1500 to 1280 its kernel-generated PTB (MTU 1280, valid checksum, Icmp6OutPktTooBigs rising by the PTBs captured) quotes a captured native packet larger than 1280, the dropped range is repaired in packets of at most 1280 octets, complete bidirectional hashed streams reach EOF with the native runtime as client and as server, the 1500-octet first-hop MTU stays, and existing and new sockets report 1280 through IPV6_MTU. The black-hole variant (the router's outgoing PTBs dropped by an owned nft rule) still delivers the stream through connection-local PLPMTUD fallback without a shared-estimate change, and the gateway variant shows the same PTB processing through an io.gateway route resolved by NS/NA.
    //# Note that Path MTU Discovery must be performed even in cases where a node "thinks" a destination is attached to the same link as itself, as it might have a PMTU lower than the link MTU. In a situation such as when a neighboring router acts as proxy [ND] for some destination, the destination can appear to be directly connected, but it is in fact more than one hop away.
    pub fn resolve_neighbor(
        &mut self,
        context: EgressContext,
        owner: Owner,
        now: Instant,
    ) -> Result<NeighborHop, Error> {
        let binding = match owner {
            Owner::Tcp(id) => self.binding_index(id),
            _ => None,
        };
        // A connection whose next hop's entry is still connected sends to
        // the address it found.
        if let Some(mac) = self.cached_neighbor(context, binding) {
            return Ok(NeighborHop::Resolved(mac));
        }
        let stamp = context.binding.snapshot.stamp();
        let port = self.port_slot(context.link)?;
        let ResolvedNextHop::Address(next_hop) = context.next_hop else {
            return Err(Error::Unsupported);
        };
        let held = HeldOutput::Transport {
            owner,
            attempt: context.attempt,
        };
        let hop = match next_hop.address() {
            IpAddr::V6(next_hop) => self.neighbor_hop(context.link, next_hop, now, held),
            IpAddr::V4(next_hop) => self.ipv4_hop(context.link, next_hop, now, held),
        }?;
        // Kept only while the entry is connected: a STALE, DELAY or PROBE
        // one is resolved on every use, which advances its state and use
        // time as before.
        if let (Some(index), NeighborHop::Resolved(mac)) = (binding, hop)
            && self.connected_neighbor(context.link, next_hop.address()) == Some(mac)
            && let Some(generation) = self.neighbor_generation(next_hop.address())
        {
            self.bindings[index].as_mut().unwrap().neighbor = Some(crate::NeighborDst {
                stamp,
                port,
                generation,
                mac,
            });
        }
        Ok(hop)
    }

    // The link-layer address binding record `binding` keeps for the next
    // hop of `context` (`NeighborDst`), while it holds.
    fn cached_neighbor(&self, context: EgressContext, binding: Option<usize>) -> Option<[u8; 6]> {
        let n = self.bindings[binding?].as_ref().unwrap().neighbor?;
        let ResolvedNextHop::Address(next_hop) = context.next_hop else {
            return None;
        };
        if n.stamp != context.binding.snapshot.stamp()
            || !self.ports[n.port].is_some_and(|p| p.link == context.link)
            || self.neighbor_generation(next_hop.address()) != Some(n.generation)
        {
            return None;
        }
        debug_assert_eq!(self.port_slot(context.link), Ok(n.port));
        debug_assert_eq!(
            self.connected_neighbor(context.link, next_hop.address()),
            Some(n.mac)
        );
        Some(n.mac)
    }
    // Whether `resolve_neighbor` of `owner`'s `context` takes the kept
    // address, and which.
    #[cfg(test)]
    pub(crate) fn neighbor_cached(&self, context: EgressContext, owner: Owner) -> Option<[u8; 6]> {
        let Owner::Tcp(id) = owner else {
            return None;
        };
        self.cached_neighbor(context, self.binding_index(id))
    }

    // The neighbour-state generation of `next_hop`'s family, None for an
    // IPv4 table that keeps none.
    fn neighbor_generation(&self, next_hop: IpAddr) -> Option<u64> {
        match next_hop {
            IpAddr::V6(_) => Some(self.neighbors.generation()),
            IpAddr::V4(_) => self.ipv4_neighbors.table().generation(),
        }
    }
    // The link-layer address resolution returns for `next_hop` on `link`
    // while its entry is connected, read without changing it.
    fn connected_neighbor(&self, link: LinkId, next_hop: IpAddr) -> Option<[u8; 6]> {
        match next_hop {
            IpAddr::V6(next_hop) => self.neighbors.connected(link, next_hop),
            IpAddr::V4(next_hop) => {
                let table = self.ipv4_neighbors.table();
                table
                    .has_link(link)
                    .then(|| table.connected(link, next_hop))
                    .flatten()
            }
        }
    }

    // The IPv4 next hop's disposition for `held`, resolved by ARP.
    fn ipv4_hop(
        &mut self,
        link: LinkId,
        next_hop: Ipv4Addr,
        now: Instant,
        held: HeldOutput,
    ) -> Result<NeighborHop, Error> {
        let table = self.ipv4_neighbors.table_mut();
        if !table.has_link(link) {
            return Err(Error::Unsupported);
        }
        Ok(
            match table.resolve(link, next_hop, now, NeighborHold(held))? {
                Some(mac) => NeighborHop::Resolved(mac),
                None => NeighborHop::Held,
            },
        )
    }

    // The next hop's disposition for `held`; a Redirect's router target
    // keeps its IsRouter flag on the entry resolution creates for it.
    fn neighbor_hop(
        &mut self,
        link: LinkId,
        next_hop: Ipv6Addr,
        now: Instant,
        held: HeldOutput,
    ) -> Result<NeighborHop, Error> {
        let resolution = self.neighbors.output(link, next_hop, now, held)?;
        let zone = next_hop.is_unicast_link_local().then_some(link);
        if let Ok(address) = ScopedAddress::new(IpAddr::V6(next_hop), zone)
            && self.paths.redirect_router(link, address)
        {
            self.neighbors.mark_router(link, next_hop);
        }
        Ok(match resolution {
            Resolution::Ready(mac) => NeighborHop::Resolved(mac),
            Resolution::Held => NeighborHop::Held,
        })
    }

    /// The next held attempt whose resolution ended, removed from the
    /// pending set.
    pub fn neighbor_wake(&mut self) -> Option<NeighborWake> {
        let transport = |held: &HeldOutput| matches!(held, HeldOutput::Transport { .. });
        let (held, resolved) = match self.neighbors.next_pending(|held| transport(&held)) {
            Some((slot, held, mac)) => {
                self.neighbors.release(slot);
                (held, mac.is_some())
            }
            None => {
                let (held, resolved) = self
                    .ipv4_neighbors
                    .table_mut()
                    .next_wake(&|held| transport(&held.0))?;
                (held.0, resolved)
            }
        };
        let HeldOutput::Transport { owner, attempt } = held else {
            return None;
        };
        Some(match resolved {
            true => NeighborWake::Retry { owner, attempt },
            false => NeighborWake::Unreachable {
                owner,
                attempt,
                advice: Advice::NetworkError(ntcp::NetworkError::SoftUnreachable),
            },
        })
    }

    // The Ethernet destination of Host-originated ICMP output leaving
    // through `key`, resolved as transport output is (RFC 4861 sections
    // 7.2.2 and 7.3.3): None where the embedding resolves the next hop (a
    // port that is not ND-capable), a cached mapping (the first use of a
    // STALE one starts DELAY), or Held while it is resolved for `held`; an
    // IPv4 next hop on a port that resolves IPv4 by ARP is resolved there.
    // Exhausted neighbor or pending storage is `Error::Capacity`.
    pub(crate) fn host_output_neighbor(
        &mut self,
        key: ntcp_path::PathKey,
        now: Instant,
        held: HeldOutput,
    ) -> Result<Option<NeighborHop>, Error> {
        if let ResolvedNextHop::Address(next_hop) = key.next_hop()
            && let IpAddr::V4(next_hop) = next_hop.address()
            && self.ipv4_neighbors.table().has_link(key.link())
        {
            return Ok(Some(self.ipv4_hop(key.link(), next_hop, now, held)?));
        }
        if self.neighbors.port(key.link()).is_none() {
            return Ok(None);
        }
        let ResolvedNextHop::Address(next_hop) = key.next_hop() else {
            return Err(Error::Unsupported);
        };
        let next_hop = v6(next_hop.address()).ok_or(Error::Unsupported)?;
        Ok(Some(self.neighbor_hop(key.link(), next_hop, now, held)?))
    }

    // Held Host ICMP output whose resolution ended: a queued message is
    // sent by the next `icmp_output` pass, or discarded and counted unsent
    // when resolution failed or its entry disappeared (no ICMP error is
    // originated about it); a held Echo adjunct probe is due again, or
    // waits its retry timeout. The slot of a message or probe that is gone
    // (displaced at a full queue, its path changed) is freed.
    pub(crate) fn settle_held_icmp(&mut self, now: Instant) {
        for slot in 0..self.neighbors.pending_slots() {
            let Some((held, ended)) = self.neighbors.pending_at(slot) else {
                continue;
            };
            let resolved = ended.map(|mac| mac.is_some());
            let present = match held {
                HeldOutput::Transport { .. } => continue,
                HeldOutput::Icmp(arrival) => self.icmp_output_settle(arrival, resolved),
                HeldOutput::Probe(path) => self.adjunct_settle(path, resolved, now),
            };
            if !present || resolved.is_some() {
                self.neighbors.release(slot);
            }
        }
        // ARP yields only ended records; one whose message or probe is gone
        // stays until its resolution ends.
        let host_output = |held: &NeighborHold| !matches!(held.0, HeldOutput::Transport { .. });
        while let Some((held, resolved)) = self.ipv4_neighbors.table_mut().next_wake(&host_output) {
            match held.0 {
                HeldOutput::Transport { .. } => {}
                HeldOutput::Icmp(arrival) => {
                    self.icmp_output_settle(arrival, Some(resolved));
                }
                HeldOutput::Probe(path) => {
                    self.adjunct_settle(path, Some(resolved), now);
                }
            }
        }
    }

    /// The earliest caller time at which `service_neighbors` or
    /// `neighbor_output` has work.
    pub fn next_neighbor_deadline(&self) -> Option<Instant> {
        let ipv4 = self.ipv4_neighbors.table().next_deadline();
        match self.neighbors.next_deadline() {
            Some(ipv6) => Some(ipv4.map_or(ipv6, |ipv4| ipv4.min(ipv6))),
            None => ipv4,
        }
    }

    /// ARP input: the body of an ARP frame (EtherType 0x0806; Ethernet
    /// padding may follow it) received on a port that resolves IPv4 by ARP,
    /// which the embedding addressed to this port's MAC or to broadcast.
    /// It learns and confirms mappings, may release held output, and queues
    /// the reply to a request for one of the port's IPv4 addresses for
    /// `neighbor_output`. ARP is not IP, so it does not pass `receive`,
    /// whose input is an IP packet: the embedding, which parses the
    /// Ethernet header, routes it here by its EtherType.
    pub fn receive_arp(
        &mut self,
        context: IngressContext,
        now: Instant,
        body: &[u8],
    ) -> Result<(), Error> {
        self.port(context.link)?;
        if !self.ipv4_neighbors.table().has_link(context.link) {
            return Err(Error::Unsupported);
        }
        let arp = ntcp_arp::parse(body)?;
        let Self {
            ipv4_neighbors,
            entropy,
            ..
        } = self;
        ipv4_neighbors
            .table_mut()
            .receive(context.link, &arp, now, entropy.as_mut())?;
        self.settle_held_icmp(now);
        Ok(())
    }

    /// Cumulative ARP counters of every port (zero without ARP storage).
    pub fn arp_counters(&self) -> crate::ArpCounters {
        self.ipv4_neighbors.table().counters()
    }

    // ND ingress on an ND-capable port, before ordinary destination
    // admission (a solicitation goes to a group, or to a tentative address
    // this context does not yet own): `Received::Neighbor`, or a Redirect's
    // outcome. None for anything that is not a Neighbor Solicitation,
    // Advertisement or Redirect, which then takes the ordinary path. The Hop Limit is the arriving packet's; a message in a packet
    // carrying a Fragment header, an atomic fragment included, is refused
    // (RFC 6980 section 5). A later fragment cannot be recognized here, and
    // its reassembly (to a unicast address this context owns) is refused
    // at dispatch by the Fragment-header provenance it keeps.
    pub(crate) fn neighbor_receive(
        &mut self,
        context: IngressContext,
        now: Instant,
        frame: &[u8],
    ) -> Result<Option<Received<'static>>, Error> {
        if self.neighbors.port(context.link).is_none() {
            return Ok(None);
        }
        let Ok(packet) = ntcp_ip6::parse_fragment(frame) else {
            return Ok(None);
        };
        let first = packet.fragment.is_none_or(|f| f.offset == 0);
        if packet.protocol != ICMPV6
            || !first
            || !matches!(
                packet.payload.first(),
                Some(&(SOLICITATION | ADVERTISEMENT | REDIRECT))
            )
        {
            return Ok(None);
        }
        if packet.fragment.is_some() {
            return Err(ntcp_ip::Error::FragmentationUnsupported.into());
        }
        let (Some(source), Some(destination)) = (v6(packet.ip.source), v6(packet.ip.destination))
        else {
            return Err(Error::Unsupported);
        };
        if source.is_multicast() || !self.neighbor_destination(context.link, destination) {
            return Err(ntcp_path::Error::NoRoute.into());
        }
        if packet.payload.first() == Some(&REDIRECT) {
            let redirect =
                ntcp_icmp::decode_ipv6_redirect(packet.ip, packet.hop_limit, packet.payload)?;
            let outcome = self.redirect_ipv6(context, now, source, redirect)?;
            // Its Target Link-Layer Address may have resolved held output.
            self.settle_held_icmp(now);
            return Ok(Some(Received::Redirect(outcome)));
        }
        let message = decode_neighbor(packet.ip, packet.hop_limit, packet.payload)?;
        let mut report = NeighborReport::default();
        let Self {
            neighbors,
            paths,
            entropy,
            ..
        } = self;
        let mut events = |event| apply(paths, event, &mut report);
        match message {
            NeighborMessage::Solicitation(ns) => {
                neighbors.solicitation(context.link, source, ns, now, &mut events)?
            }
            NeighborMessage::Advertisement(na) => {
                neighbors.advertisement(context.link, na, now, entropy.as_mut(), &mut events)?;
            }
        }
        self.unreported_duplicates = self.unreported_duplicates.saturating_add(report.duplicates);
        self.settle_held_icmp(now);
        report.first_error.map_or(Ok(Some(Received::Neighbor)), Err)
    }

    // A destination ND accepts on `link`: an address configured there
    // (tentative included), all-nodes, or the solicited-node group of one.
    fn neighbor_destination(&self, link: LinkId, destination: Ipv6Addr) -> bool {
        destination == ntcp_ethernet::IPV6_ALL_NODES
            || self.neighbors.addresses_on(link).any(|address| {
                address == destination || ntcp_ethernet::solicited_node(address) == destination
            })
    }

    /// Write `link`'s next due neighbor control packet into `out`: ND
    /// (answers, DAD probes, then resolution and unreachability
    /// solicitations), then ARP (replies, then broadcast requests and
    /// unicast probes). It is independent of data output and of other
    /// ports: neither blocked data nor another port's blocked transmit path
    /// holds it back. A solicitation or request counts, and its
    /// RetransTimer spacing starts, only once `complete_neighbor_output`
    /// reports it possibly or definitely submitted.
    pub fn neighbor_output(
        &mut self,
        link: LinkId,
        now: Instant,
        out: &mut [u8],
    ) -> Result<Option<NeighborTransmit>, Error> {
        let Some((control, token)) = self.neighbors.next_control(link, now) else {
            let Some((destination, len, token)) =
                self.ipv4_neighbors.table_mut().output(link, now, out)?
            else {
                return Ok(None);
            };
            return Ok(Some(NeighborTransmit {
                link,
                destination,
                ethertype: ntcp_ethernet::ETHERTYPE_ARP,
                len,
                ticket: NeighborTicket {
                    context: self.paths.context(),
                    token: Token::Arp(token),
                },
            }));
        };
        let (link, source, destination, mac, message) = match control {
            Control::Solicit {
                link,
                target,
                destination,
                dad,
            } => {
                let port = self.neighbors.port(link).ok_or(Error::InvalidContext)?;
                let source = if dad {
                    Ipv6Addr::UNSPECIFIED
                } else {
                    self.neighbors
                        .assigned_source(link)
                        .ok_or(Error::InvalidContext)?
                };
                let (ip, mac) = match destination {
                    Destination::Multicast => {
                        let group = ntcp_ethernet::solicited_node(target);
                        (group, ntcp_ethernet::ipv6_multicast_mac(group).unwrap())
                    }
                    Destination::Unicast(mac) => (target, mac),
                };
                let ns = NeighborSolicitation {
                    target,
                    source_link_layer: (!dad).then_some(port.mac),
                };
                (link, source, ip, mac, NeighborMessage::Solicitation(ns))
            }
            Control::Advertise { link, target, to } => {
                let port = self.neighbors.port(link).ok_or(Error::InvalidContext)?;
                let all_nodes = ntcp_ethernet::IPV6_ALL_NODES;
                let (ip, mac) = to.unwrap_or((
                    all_nodes,
                    ntcp_ethernet::ipv6_multicast_mac(all_nodes).unwrap(),
                ));
                // A host's answer overrides (RFC 4861 section 7.2.4): it
                // is neither a proxy nor an anycast address.
                let na = NeighborAdvertisement {
                    router: false,
                    solicited: to.is_some(),
                    override_: true,
                    target,
                    target_link_layer: Some(port.mac),
                };
                (link, target, ip, mac, NeighborMessage::Advertisement(na))
            }
        };
        let ip = IpMetadata {
            source: IpAddr::V6(source),
            destination: IpAddr::V6(destination),
        };
        let header = ntcp_ip6::IPV6_HEADER;
        let body = out.get_mut(header..).ok_or(Error::Capacity)?;
        let len = match message {
            NeighborMessage::Solicitation(ns) => ntcp_icmp::encode_solicitation(ip, ns, body),
            NeighborMessage::Advertisement(na) => ntcp_icmp::encode_advertisement(ip, na, body),
        }
        .map_err(|_| Error::Capacity)?;
        let header = ntcp_ip6::Header {
            ip,
            hop_limit: ND_HOP_LIMIT,
            dscp: 0,
            ecn: 0,
        };
        let len = ntcp_ip6::encode_datagram(out, header, ICMPV6, len)?;
        Ok(Some(NeighborTransmit {
            link,
            destination: mac,
            ethertype: ntcp_ethernet::ETHERTYPE_IPV6,
            len,
            ticket: NeighborTicket {
                context: self.paths.context(),
                token: Token::Nd(token),
            },
        }))
    }

    /// The backend's outcome for one ND control packet. `Submitted`
    /// consumes a solicitation attempt and advances DAD. `Unknown` (it may
    /// be on the wire) starts the RetransTimer spacing of every
    /// solicitation and consumes a resolution or unreachability attempt,
    /// but does not advance DAD; on a port that loops back multicast, the
    /// DAD probe's own copy is then expected. `WouldBlock`, `Rejected` and
    /// `NotSubmitted` (certainly unsent) consume nothing and leave the
    /// solicitation due. An answer ends on any outcome except `WouldBlock`
    /// and `Rejected`, which keep it for a retry. An ARP request is
    /// consumed and spaced like a resolution solicitation, and an ARP reply
    /// ends like an answer.
    pub fn complete_neighbor_output(
        &mut self,
        ticket: NeighborTicket,
        outcome: BackendOutcome,
        now: Instant,
    ) -> Result<(), Error> {
        if ticket.context != self.paths.context() {
            return Err(Error::InvalidContext);
        }
        match ticket.token {
            Token::Nd(token) => {
                let outcome = match outcome {
                    BackendOutcome::Submitted => ControlOutcome::Submitted,
                    BackendOutcome::Unknown => ControlOutcome::Uncertain,
                    BackendOutcome::WouldBlock | BackendOutcome::Rejected => {
                        ControlOutcome::Blocked
                    }
                    BackendOutcome::NotSubmitted => ControlOutcome::Failed,
                };
                self.neighbors.complete(token, outcome, now);
            }
            Token::Arp(token) => {
                use ntcp_arp::ControlOutcome as Arp;
                let outcome = match outcome {
                    BackendOutcome::Submitted => Arp::Submitted,
                    BackendOutcome::Unknown => Arp::Uncertain,
                    BackendOutcome::WouldBlock | BackendOutcome::Rejected => Arp::Blocked,
                    BackendOutcome::NotSubmitted => Arp::Failed,
                };
                self.ipv4_neighbors
                    .table_mut()
                    .complete(token, outcome, now);
            }
        }
        Ok(())
    }
}

fn publish(paths: &mut PathService, link: LinkId, address: Ipv6Addr) -> Result<(), Error> {
    let zone = address.is_unicast_link_local().then_some(link);
    paths.register_source(ScopedAddress::new(IpAddr::V6(address), zone)?, link)?;
    Ok(())
}

// An assigned address becomes a source of its link; a duplicate one stays
// unusable and is reported.
fn apply(paths: &mut PathService, event: NdEvent, report: &mut NeighborReport) {
    match event {
        NdEvent::Assigned { link, address } => match publish(paths, link, address) {
            Ok(()) => report.assigned += 1,
            Err(error) => {
                report.first_error.get_or_insert(error);
            }
        },
        NdEvent::Duplicate { .. } => report.duplicates += 1,
        // Redirect overrides through the neighbor end (RFC 4861 sections
        // 7.2.5 and 7.3.3: NUD removes stale forwarding information).
        NdEvent::Unreachable { link, address } | NdEvent::RouterLost { link, address } => {
            let loss = match event {
                NdEvent::Unreachable { .. } => ntcp_path::NeighborLoss::Unreachable,
                _ => ntcp_path::NeighborLoss::NotRouter,
            };
            let zone = address.is_unicast_link_local().then_some(link);
            lost(paths, link, IpAddr::V6(address), zone, loss, report);
        }
    }
}

// A lost neighbor ends the Redirects through it. A failed IPv4 neighbor is
// lost as an unreachable one: ARP reports no other loss.
fn lost(
    paths: &mut PathService,
    link: LinkId,
    address: IpAddr,
    zone: Option<LinkId>,
    loss: ntcp_path::NeighborLoss,
    report: &mut NeighborReport,
) {
    if let Err(error) = ScopedAddress::new(address, zone)
        .and_then(|neighbor| paths.end_redirects(link, neighbor, loss))
    {
        report.first_error.get_or_insert(error.into());
    }
}
