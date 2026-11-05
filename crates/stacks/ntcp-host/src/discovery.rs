// The Host side of Neighbor Discovery: ND-capable Ethernet port
// registration, configured addresses under Duplicate Address Detection, ND
// ingress ahead of ordinary destination admission, control output and
// caller-time service (`neighbor` holds the state).
use core::net::{IpAddr, Ipv6Addr};
use ntcp::{Instant, IpMetadata};
use ntcp_icmp::{
    ND_HOP_LIMIT, NeighborAdvertisement, NeighborMessage, NeighborSolicitation, decode_neighbor,
};
use ntcp_path::{InterfaceKey, LinkId, PathService, ScopedAddress};

use crate::neighbor::{
    AddressState, Control, ControlOutcome, ControlToken, Destination, NdEvent, NdPort, Resolution,
};
use crate::{
    Advice, BackendOutcome, EgressContext, Error, Forwarding, Host, IngressContext, Owner,
    ReceiveCapabilities, Received, ResolvedNextHop,
};
use ntcp::TransmitAttempt;

const ICMPV6: u8 = 58;
const SOLICITATION: u8 = 135;
const ADVERTISEMENT: u8 = 136;
const REDIRECT: u8 = 137;

/// One ND control packet written by `Host::neighbor_output`: a complete
/// IPv6 packet of `len` octets for `link`, to the Ethernet `destination`
/// (a 33:33 group or a resolved neighbor). Its ticket completes it.
#[must_use = "an uncompleted ND transmission is polled again"]
#[derive(Debug, Eq, PartialEq)]
pub struct NeighborTransmit {
    pub link: LinkId,
    pub destination: [u8; 6],
    pub len: usize,
    pub ticket: NeighborTicket,
}

/// Authority to report the outcome of one ND control packet.
#[derive(Debug, Eq, PartialEq)]
pub struct NeighborTicket {
    context: crate::ContextId,
    token: ControlToken,
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

/// The Ethernet next hop of one IPv6 output attempt on an ND-capable port
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
    /// Resolution failed (RFC 4861 section 7.2.2): the owner's advice is
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
    /// Register an ND-capable Ethernet port: its IPv6 next hops are resolved
    /// by this Host's Neighbor Discovery (`Forwarding::IpNextHop`), its IPv6
    /// addresses are configured through `add_neighbor_address` and stay
    /// tentative until Duplicate Address Detection completes, and its
    /// ReachableTime is drawn from the Host's entropy, which must be set.
    /// Needs `Limits::neighbors` storage.
    pub fn register_neighbor_port(
        &mut self,
        interface: InterfaceKey,
        mtu: u32,
        receive: ReceiveCapabilities,
        port: NdPort,
    ) -> Result<IngressContext, Error> {
        if self.neighbors.ports_free() == 0 {
            return Err(Error::Capacity);
        }
        if self.entropy.is_none() {
            return Err(Error::Entropy);
        }
        let context = self.register_link(interface, mtu, receive, Forwarding::IpNextHop)?;
        if let Err(error) = self
            .neighbors
            .add_port(context.link, port, self.entropy.as_mut())
        {
            self.remove_link(context)?;
            return Err(error);
        }
        Ok(context)
    }

    /// Configure `address` on an ND-capable port. It is tentative (no
    /// ordinary traffic leaves from it and none is received for it) until
    /// DAD, which starts once `neighbor_membership_ready` states its groups
    /// are joined, completes in `service_neighbors`; with DupAddrDetectTransmits
    /// 0 it is published at once.
    pub fn add_neighbor_address(
        &mut self,
        link: LinkId,
        address: Ipv6Addr,
    ) -> Result<AddressState, Error> {
        self.port(link)?;
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

    /// Apply every Neighbor Discovery timer due at `now` (reachability,
    /// probing, resolution failure and DAD completion).
    pub fn service_neighbors(&mut self, now: Instant) -> NeighborReport {
        let mut report = NeighborReport {
            duplicates: core::mem::take(&mut self.unreported_duplicates),
            ..NeighborReport::default()
        };
        let Self {
            neighbors, paths, ..
        } = self;
        neighbors.service(now, &mut |event| apply(paths, event, &mut report));
        self.settle_held_icmp(now);
        report
    }

    /// The Ethernet next hop of `context`'s output attempt, held for
    /// `owner` on an ND-capable port: its IPv6 next hop's cached mapping
    /// (the first use of a STALE one starts DELAY; STALE, DELAY and PROBE
    /// never block output), or Held while it is resolved. Exhausted neighbor
    /// or pending storage is backpressure (`Error::Capacity`) that leaves no
    /// entry behind.
    pub fn resolve_neighbor(
        &mut self,
        context: EgressContext,
        owner: Owner,
        now: Instant,
    ) -> Result<NeighborHop, Error> {
        self.port(context.link)?;
        let ResolvedNextHop::Address(next_hop) = context.next_hop else {
            return Err(Error::Unsupported);
        };
        let next_hop = v6(next_hop.address()).ok_or(Error::Unsupported)?;
        let held = HeldOutput::Transport {
            owner,
            attempt: context.attempt,
        };
        self.neighbor_hop(context.link, next_hop, now, held)
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
        let (slot, held, mac) = self
            .neighbors
            .next_pending(|held| matches!(held, HeldOutput::Transport { .. }))?;
        self.neighbors.release(slot);
        let HeldOutput::Transport { owner, attempt } = held else {
            return None;
        };
        Some(match mac {
            Some(_) => NeighborWake::Retry { owner, attempt },
            None => NeighborWake::Unreachable {
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
    // STALE one starts DELAY), or Held while it is resolved for `held`.
    // Exhausted neighbor or pending storage is `Error::Capacity`.
    pub(crate) fn host_output_neighbor(
        &mut self,
        key: ntcp_path::PathKey,
        now: Instant,
        held: HeldOutput,
    ) -> Result<Option<NeighborHop>, Error> {
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
    }

    /// The earliest caller time at which `service_neighbors` or
    /// `neighbor_output` has work.
    pub fn next_neighbor_deadline(&self) -> Option<Instant> {
        self.neighbors.next_deadline()
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

    /// Write `link`'s next due ND control packet (answers, DAD probes, then
    /// resolution and unreachability solicitations) into `out`. It is
    /// independent of data output and of other ports: neither blocked data
    /// nor another port's blocked transmit path holds it back. A
    /// solicitation counts, and its RetransTimer spacing starts, only once
    /// `complete_neighbor_output` reports it possibly or definitely
    /// submitted.
    pub fn neighbor_output(
        &mut self,
        link: LinkId,
        now: Instant,
        out: &mut [u8],
    ) -> Result<Option<NeighborTransmit>, Error> {
        let Some((control, token)) = self.neighbors.next_control(link, now) else {
            return Ok(None);
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
            len,
            ticket: NeighborTicket {
                context: self.paths.context(),
                token,
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
    /// and `Rejected`, which keep it for a retry.
    pub fn complete_neighbor_output(
        &mut self,
        ticket: NeighborTicket,
        outcome: BackendOutcome,
        now: Instant,
    ) -> Result<(), Error> {
        if ticket.context != self.paths.context() {
            return Err(Error::InvalidContext);
        }
        let outcome = match outcome {
            BackendOutcome::Submitted => ControlOutcome::Submitted,
            BackendOutcome::Unknown => ControlOutcome::Uncertain,
            BackendOutcome::WouldBlock | BackendOutcome::Rejected => ControlOutcome::Blocked,
            BackendOutcome::NotSubmitted => ControlOutcome::Failed,
        };
        self.neighbors.complete(ticket.token, outcome, now);
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
            if let Err(error) = ScopedAddress::new(IpAddr::V6(address), zone)
                .and_then(|neighbor| paths.end_redirects(link, neighbor, loss))
            {
                report.first_error.get_or_insert(error.into());
            }
        }
    }
}
