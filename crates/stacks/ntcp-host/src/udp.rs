//! Host UDP (RFC 768) flows on the managed path authority.
//!
//! A flow is a bound local socket address with an optional fixed remote. It
//! is admitted by the Endpoint's own address policy, sends through the same
//! path resolution and physical-submission evidence as TCP, and receives
//! protocol-17 datagrams that pass the UDP checksum. ICMP errors quoting its
//! datagrams are correlated by the single Host dispatcher and become bounded,
//! consumed events. All storage is allocated once by `Host::new`.

use crate::ledger::{Evidence, Owner, Selector};
use crate::{BackendOutcome, Error, Host, IngressPacket};
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use ntcp::{AddressValidation, Endpoint, EndpointError, Instant, IpMetadata, NetworkError};
use ntcp::{InputDisposition, PreparedPath};
use ntcp_path::{Dscp, LinkId, PathStatus, ResolvedNextHop, ScopedAddress};

/// Explicit UDP storage. Zero flows (the `managed_limits` default) disables
/// UDP entirely; `managed_udp_limits` adds the matching path and ledger room.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UdpLimits {
    /// Concurrent flows; each holds one path client and one ledger owner.
    pub flows: usize,
    /// Datagrams queued per flow; later arrivals are dropped until the
    /// application reads (UDP has no transport backpressure of its own).
    pub receive_datagrams: usize,
    /// Largest payload one receive slot holds. Without reassembly nothing
    /// larger than the receiving link allows can arrive, so embeddings size
    /// this from their link; a larger datagram is dropped, never truncated.
    pub max_payload: usize,
    /// Advice events retained per flow. A full queue replaces its oldest
    /// event: each report describes the path as recently observed, so the
    /// newest supersedes the oldest for an application that fell behind.
    pub events: usize,
    /// Datagrams per flow that, once evicted from the ledger's per-owner
    /// history, keep an exact signature for the feedback horizon, so ICMP
    /// quoting any other datagram stays attributable. Size it as the flow's
    /// sustained send rate times the horizon; past it the oldest signatures
    /// fold into a summary of their own four-tuple, which keeps them
    /// ambiguous at the cost of that four-tuple's owner-level advice.
    pub evicted_signatures: usize,
}

/// Add UDP capacity to limits from `managed_limits`: one path client and
/// cache entry per flow (a flow pins the path it currently sends on), one
/// ledger owner per flow, one concurrent attempt, because a datagram's
/// reservation lives only inside a single `udp_send` call, and each flow's
/// evicted-signature budget.
pub fn managed_udp_limits(
    paths: ntcp_path::Limits,
    limits: crate::Limits,
    udp: UdpLimits,
) -> Result<(ntcp_path::Limits, crate::Limits), Error> {
    let add = |a: usize, b: usize| a.checked_add(b).ok_or(Error::Capacity);
    let attempts = usize::from(udp.flows != 0);
    Ok((
        ntcp_path::Limits {
            paths: add(paths.paths, udp.flows)?,
            clients: add(paths.clients, udp.flows)?,
            ..paths
        },
        crate::Limits {
            ledger: crate::LedgerLimits {
                owners: add(limits.ledger.owners, udp.flows)?,
                concurrent_attempts: add(limits.ledger.concurrent_attempts, attempts)?,
                datagram_evidence: add(
                    limits.ledger.datagram_evidence,
                    udp.flows
                        .checked_mul(udp.evicted_signatures)
                        .ok_or(Error::Capacity)?,
                )?,
                ..limits.ledger
            },
            udp,
            ..limits
        },
    ))
}

/// Exact flow generation; a closed flow's handle never names its successor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpFlowId {
    slot: usize,
    generation: u64,
}

/// Per-flow IP send parameters (RFC 1122 section 3.2.1.7 lets the transport
/// set TTL; the DSCP selects the routing class like a TCP connection's).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpOptions {
    pub dscp: u8,
    pub hop_limit: u8,
}

/// Correlated ICMP advice about one of this flow's own datagrams to
/// `remote`. A path-level decrease, if any, has already been published and
/// governs this flow's next `udp_send` to that destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpEvent {
    /// A router dropped a datagram of `dropped_len` IP octets; `mtu` is its
    /// validated next-hop MTU (None from an IPv4 router that reported none).
    PacketTooBig {
        remote: SocketAddr,
        mtu: Option<u32>,
        dropped_len: u32,
    },
    NetworkError {
        remote: SocketAddr,
        error: NetworkError,
    },
}

/// What a flow may send to its pinned destination now: the path's MMS_S
/// (RFC 1191 section 6.1: path MTU less the minimum IP header) and the
/// largest UDP payload one unfragmented datagram may carry, with the path
/// incarnation and shared version they were read from. Datagrams are indivisible, so an application
/// sizes each one against this before building it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpPathLimits {
    pub destination: IpAddr,
    pub path: ntcp_path::PathId,
    pub version: u64,
    pub mms_s: u32,
    pub max_payload: usize,
}

/// Where the one physical call goes; the closure owns no other authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpEgress {
    pub link: LinkId,
    pub next_hop: ResolvedNextHop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpSent {
    /// Sealed evidence of an actual submission of this many IP octets.
    Submitted(usize),
    /// The backend outcome is unknown: sealed as possibly submitted, never
    /// reported as success and never to be retried as unsent.
    PossiblySubmitted(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpSendError {
    /// The datagram exceeds what the current path allows. This Host sends
    /// only unfragmented datagrams (IPv4 always with DF), so it is refused
    /// rather than split; `max_payload` is the largest UDP payload this flow
    /// may send to that destination now.
    TooBig {
        max_payload: usize,
    },
    /// The backend certainly did not submit it; nothing was recorded.
    NotSubmitted(BackendOutcome),
    Host(Error),
}
impl From<Error> for UdpSendError {
    fn from(error: Error) -> Self {
        Self::Host(error)
    }
}

#[derive(Clone, Copy)]
struct Flow {
    local: SocketAddr,
    remote: Option<SocketAddr>,
    options: UdpOptions,
    path: Option<PreparedPath>,
    // Newest unconsumed shared change to the pinned path, replaced (never
    // queued) by later ones, so a slow reader sees the current limits.
    change: Option<UdpPathLimits>,
    received: Ring,
    events: Ring,
}
#[derive(Clone, Copy, Default)]
struct Ring {
    head: usize,
    len: usize,
}
#[derive(Clone, Copy)]
struct Slot {
    generation: u64,
    flow: Option<Flow>,
}

pub(crate) struct Udp {
    pub(crate) limits: UdpLimits,
    slots: Vec<Slot>,
    // Slot i owns entries [i * depth, (i + 1) * depth) of each table, and
    // payload bytes [i * depth * max_payload ..] in max_payload strides.
    received: Vec<(SocketAddr, usize)>,
    payload: Vec<u8>,
    events: Vec<Option<UdpEvent>>,
    generation: u64,
}

const UNSPECIFIED: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

impl Udp {
    pub fn new(limits: UdpLimits) -> Result<Self, Error> {
        if limits.flows != 0
            && (limits.receive_datagrams == 0 || limits.max_payload == 0 || limits.events == 0)
        {
            return Err(Error::Capacity);
        }
        let queued = limits
            .flows
            .checked_mul(limits.receive_datagrams)
            .ok_or(Error::Capacity)?;
        Ok(Self {
            limits,
            slots: crate::table(
                limits.flows,
                Slot {
                    generation: 0,
                    flow: None,
                },
            )?,
            received: crate::table(queued, (UNSPECIFIED, 0))?,
            payload: crate::table(
                queued
                    .checked_mul(limits.max_payload)
                    .ok_or(Error::Capacity)?,
                0u8,
            )?,
            events: crate::table(
                limits
                    .flows
                    .checked_mul(limits.events)
                    .ok_or(Error::Capacity)?,
                None,
            )?,
            generation: 0,
        })
    }
    fn flow(&self, id: UdpFlowId) -> Result<Flow, Error> {
        self.slots
            .get(id.slot)
            .filter(|s| s.generation == id.generation)
            .and_then(|s| s.flow)
            .ok_or(Error::Obsolete)
    }
    fn live(&self, slot: usize, generation: u64) -> bool {
        self.slots
            .get(slot)
            .is_some_and(|s| s.generation == generation && s.flow.is_some())
    }
    fn push_event(&mut self, slot: usize, event: UdpEvent) {
        let depth = self.limits.events;
        let flow = self.slots[slot].flow.as_mut().unwrap();
        let ring = &mut flow.events;
        let index = (ring.head + ring.len) % depth;
        if ring.len == depth {
            ring.head = (ring.head + 1) % depth;
        } else {
            ring.len += 1;
        }
        self.events[slot * depth + index] = Some(event);
    }
}

fn udp_limits(snapshot: ntcp_path::PathSnapshot) -> Result<UdpPathLimits, Error> {
    let destination = snapshot.key().destination().address();
    let header = if destination.is_ipv4() {
        ntcp_ip::IPV4_HEADER
    } else {
        ntcp_ip6::IPV6_HEADER
    };
    let budget = snapshot.ip_packet_budget()? as usize;
    Ok(UdpPathLimits {
        destination,
        path: snapshot.path(),
        version: snapshot.version(),
        mms_s: snapshot.mms_s()?,
        max_payload: budget
            .saturating_sub(header + ntcp_ip::UDP_HEADER)
            .min(usize::from(u16::MAX) - ntcp_ip::UDP_HEADER),
    })
}

fn supported(address: SocketAddr) -> bool {
    !matches!(address, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.flowinfo() != 0)
}

impl Host {
    /// Bind a flow to `local` (a source this Host owns) and optionally one
    /// `remote`. Addresses pass the Endpoint's own policy (Open with a remote,
    /// Bind without). A connected flow acquires its path now, so an
    /// unroutable association fails here; an unconnected one acquires it at
    /// its first send. One flow per exact (local, remote) binding; a duplicate
    /// is AddressInUse, as for a TCP tuple.
    pub fn udp_open(
        &mut self,
        endpoint: &Endpoint,
        local: SocketAddr,
        remote: Option<SocketAddr>,
        options: UdpOptions,
    ) -> Result<UdpFlowId, Error> {
        self.check_endpoint(endpoint)?;
        let dscp = Dscp::new(options.dscp)?;
        if options.hop_limit == 0 {
            return Err(ntcp_ip::Error::Invalid.into());
        }
        let admitted = match remote {
            Some(remote) => {
                remote.port() != 0
                    && supported(remote)
                    && endpoint.admits_datagram(AddressValidation::Open {
                        local: local.ip(),
                        remote: remote.ip(),
                    })
            }
            None => endpoint.admits_datagram(AddressValidation::Bind { local: local.ip() }),
        };
        if !admitted || local.port() == 0 || !supported(local) {
            return Err(EndpointError::InvalidAddress.into());
        }
        self.source(local.ip())?;
        if self
            .udp
            .slots
            .iter()
            .flat_map(|s| s.flow)
            .any(|f| f.local == local && f.remote == remote)
        {
            return Err(EndpointError::AddressInUse.into());
        }
        let slot = self
            .udp
            .slots
            .iter()
            .position(|s| s.flow.is_none())
            .ok_or(Error::Capacity)?;
        let generation = self.udp.generation.checked_add(1).ok_or(Error::Capacity)?;
        let path = match remote {
            Some(remote) => {
                let request = self.request(local.ip(), remote.ip(), dscp)?;
                let via = ScopedAddress::new(remote.ip(), None)?;
                let resolved = self.paths.resolve_via(request, via)?;
                self.forwarding_resolved(resolved.key())?;
                let (client, snapshot) = self.paths.acquire_via(request, via)?;
                // The flow observes its initial path here (and through
                // `udp_path_limits`); only later changes notify it.
                self.paths.acknowledge(client, snapshot.stamp())?;
                Some(PreparedPath { client, snapshot })
            }
            None => None,
        };
        self.udp.generation = generation;
        self.udp.slots[slot] = Slot {
            generation,
            flow: Some(Flow {
                local,
                remote,
                options,
                path,
                change: None,
                received: Ring::default(),
                events: Ring::default(),
            }),
        };
        Ok(UdpFlowId { slot, generation })
    }

    /// Release the flow's path and storage. Its submission history becomes
    /// tombstones, so feedback quoting it can never be attributed to a
    /// later generation sending identical datagrams.
    pub fn udp_close(&mut self, id: UdpFlowId) -> Result<(), Error> {
        let flow = self.udp.flow(id)?;
        if let Some(path) = flow.path {
            self.paths.release(path.client)?;
        }
        if let Some(index) = self.ledger.owner_index(Owner::Datagram {
            flow: id.slot,
            generation: id.generation,
        }) {
            self.ledger.release_owner(index, self.now);
        }
        self.udp.slots[id.slot].flow = None;
        Ok(())
    }

    /// Send one datagram as one physical attempt. Everything fallible happens
    /// first: address policy, current path authority (rebinding when the
    /// destination or routing changed), the unfragmented size policy, exact
    /// RFC 768 encoding with its checksum, and the evidence reservation.
    /// `submit` is the single backend call; afterwards the evidence is sealed
    /// (Submitted, or possibly submitted for an unknown outcome) or cancelled
    /// without allocation or fallible lookup. A certain non-submission
    /// records nothing, and the caller may retry with a new call.
    #[allow(clippy::too_many_arguments)]
    pub fn udp_send(
        &mut self,
        endpoint: &Endpoint,
        now: Instant,
        id: UdpFlowId,
        remote: Option<SocketAddr>,
        payload: &[u8],
        packet: &mut [u8],
        submit: impl FnOnce(UdpEgress, &[u8]) -> BackendOutcome,
    ) -> Result<UdpSent, UdpSendError> {
        self.check_endpoint(endpoint)?;
        let flow = self.udp.flow(id)?;
        let remote = match (flow.remote, remote) {
            (Some(fixed), None) => fixed,
            (Some(fixed), Some(remote)) if fixed == remote => fixed,
            (None, Some(remote)) => remote,
            _ => return Err(Error::InvalidContext.into()),
        };
        if remote.port() == 0
            || !supported(remote)
            || !endpoint.admits_datagram(AddressValidation::Open {
                local: flow.local.ip(),
                remote: remote.ip(),
            })
        {
            return Err(Error::from(EndpointError::InvalidAddress).into());
        }
        let (prepared, limits) = self.udp_path(id.slot, flow, remote.ip())?;
        let snapshot = prepared.snapshot;
        let ipv4 = remote.is_ipv4();
        let header = if ipv4 {
            ntcp_ip::IPV4_HEADER
        } else {
            ntcp_ip6::IPV6_HEADER
        };
        let overhead = header + ntcp_ip::UDP_HEADER;
        let max_payload = limits.max_payload;
        if payload.len() > max_payload {
            return Err(UdpSendError::TooBig { max_payload });
        }
        let len = overhead + payload.len();
        let packet = packet.get_mut(..len).ok_or(Error::Capacity)?;
        packet[overhead..].copy_from_slice(payload);
        let ip = IpMetadata {
            source: flow.local.ip(),
            destination: remote.ip(),
        };
        let (dscp, hop_limit) = (flow.options.dscp, flow.options.hop_limit);
        let encoded = if ipv4 {
            ntcp_ip::encode_udp(
                packet,
                ntcp_ip::Header {
                    ip,
                    hop_limit,
                    dscp,
                    ecn: 0,
                    ipv4_options: Default::default(),
                },
                flow.local.port(),
                remote.port(),
                payload.len(),
                0,
            )
        } else {
            ntcp_ip6::encode_udp(
                packet,
                ntcp_ip6::Header {
                    ip,
                    hop_limit,
                    dscp,
                    ecn: 0,
                },
                flow.local.port(),
                remote.port(),
                payload.len(),
            )
        };
        if encoded.map_err(Error::Codec)? != len {
            return Err(Error::Obsolete.into());
        }
        let udp = &packet[header..];
        let owner = Owner::Datagram {
            flow: id.slot,
            generation: id.generation,
        };
        let evidence = Evidence {
            link: snapshot.key().link(),
            path: snapshot.path(),
            owner,
            source: ip.source,
            destination: ip.destination,
            dscp,
            header_len: header as u16,
            packet_len: len as u32,
            protocol: ntcp_ip::PROTOCOL_UDP,
            transport: Selector::Udp {
                source_port: flow.local.port(),
                destination_port: remote.port(),
                length: u16::from_be_bytes([udp[4], udp[5]]),
                checksum: u16::from_be_bytes([udp[6], udp[7]]),
            },
        };
        let ticket = self.reserve_datagram(endpoint, owner, evidence)?;
        self.now = self.now.max(now);
        let egress = UdpEgress {
            link: snapshot.key().link(),
            next_hop: snapshot.key().next_hop(),
        };
        match submit(egress, packet) {
            BackendOutcome::Submitted => {
                self.ledger.seal(ticket, now, false);
                Ok(UdpSent::Submitted(len))
            }
            BackendOutcome::Unknown => {
                self.ledger.seal(ticket, now, true);
                Ok(UdpSent::PossiblySubmitted(len))
            }
            outcome => {
                self.ledger.cancel(ticket);
                Err(UdpSendError::NotSubmitted(outcome))
            }
        }
    }

    // Owner admission and the single reservation, reclaiming dead TCP
    // generations and unusable reservations once before backpressuring.
    fn reserve_datagram(
        &mut self,
        endpoint: &Endpoint,
        owner: Owner,
        evidence: Evidence,
    ) -> Result<u64, Error> {
        let reserve = |host: &mut Self| {
            let index = host.ledger.admit(owner)?;
            host.ledger.reserve_group(index, &[evidence])
        };
        match reserve(self) {
            Err(Error::Capacity) => {
                self.maintain_ledger(endpoint);
                reserve(self)
            }
            result => result,
        }
    }

    /// Pin `remote` (the fixed remote when None) as the flow's destination,
    /// with the same checked rebind as a send, and report its current limits.
    /// An unconsumed change notification survives this acknowledgement.
    pub fn udp_path_limits(
        &mut self,
        endpoint: &Endpoint,
        id: UdpFlowId,
        remote: Option<IpAddr>,
    ) -> Result<UdpPathLimits, Error> {
        self.check_endpoint(endpoint)?;
        let flow = self.udp.flow(id)?;
        let remote = match (flow.remote.map(|r| r.ip()), remote) {
            (Some(fixed), None) => fixed,
            (Some(fixed), Some(remote)) if fixed == remote => fixed,
            (None, Some(remote)) => remote,
            _ => return Err(Error::InvalidContext),
        };
        Ok(self.udp_path(id.slot, flow, remote)?.1)
    }

    /// The newest shared change to the flow's pinned path since it was last
    /// taken, consumed once. Sends and queries acknowledge the path service
    /// but never consume this, so a change is not lost to a send that raced
    /// with it.
    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.1
    //= reason=PathService stores IPv6 estimates and Host ICMPv6 dispatch processes correlated Packet Too Big messages. TCP learns MMS_S changes through Host::service_changes budget application; a Host UDP flow reads MMS_S and its payload limit with Host::udp_path_limits and receives each shared change through Host::udp_path_change (coalesced to the newest version and not consumed by sends), without a failed send. Dual-family Host tests, tun_echo and the isolated namespace shared-fanout case verify it.
    //# It is therefore suggested that the IP layer store PMTU information and that the ICMPv6 layer process received Packet Too Big messages. The packetization layers may respond to changes in the PMTU by changing the size of the messages they send. To support this layering, packetization layers require a way to learn of changes in the value of MMS_S, the "maximum send transport-message size" [RFC1122].
    pub fn udp_path_change(&mut self, id: UdpFlowId) -> Result<Option<UdpPathLimits>, Error> {
        self.udp.flow(id)?;
        Ok(self.udp.slots[id.slot].flow.as_mut().unwrap().change.take())
    }

    // Change service for one flow: a dirty pinned path is re-read (rebound
    // when invalidated) and its newest limits replace the notification.
    pub(crate) fn udp_service(&mut self, slot: usize) -> Result<bool, Error> {
        let Some(flow) = self.udp.slots[slot].flow else {
            return Ok(false);
        };
        let Some(prepared) = flow.path else {
            return Ok(false);
        };
        if !self.paths.is_dirty(prepared.client)? {
            return Ok(false);
        }
        let remote = prepared.snapshot.key().destination().address();
        self.udp_path(slot, flow, remote)?;
        Ok(true)
    }

    // The flow's current authority for `remote`: the live snapshot when it
    // still selects the same request and forwarding destination, otherwise
    // a checked rebind (or first acquisition). Every send consumes the
    // newest shared estimate, acknowledging what it observed; a shared
    // change it acknowledges is first recorded as the flow's notification,
    // always naming the destination whose path changed.
    fn udp_path(
        &mut self,
        slot: usize,
        flow: Flow,
        remote: IpAddr,
    ) -> Result<(PreparedPath, UdpPathLimits), Error> {
        let changed = match flow.path {
            Some(prepared) if self.paths.is_dirty(prepared.client)? => {
                Some(self.paths.snapshot(prepared.client)?)
            }
            _ => None,
        };
        let request = self.request(flow.local.ip(), remote, Dscp::new(flow.options.dscp)?)?;
        let via = ScopedAddress::new(remote, None)?;
        let current = match flow.path {
            Some(prepared) => {
                let snapshot = self.paths.snapshot(prepared.client)?;
                (snapshot.status() == PathStatus::Valid
                    && snapshot.key().request() == request
                    && snapshot.key().forwarding_destination() == via)
                    .then_some(PreparedPath {
                        client: prepared.client,
                        snapshot,
                    })
            }
            None => None,
        };
        let prepared = match current {
            Some(prepared) => {
                self.forwarding(prepared.snapshot)?;
                prepared
            }
            None => {
                let resolved = self.paths.resolve_via(request, via)?;
                self.forwarding_resolved(resolved.key())?;
                let (client, snapshot) = match flow.path {
                    Some(old) => self.paths.rebind_via(old.client, request, via)?,
                    None => self.paths.acquire_via(request, via)?,
                };
                PreparedPath { client, snapshot }
            }
        };
        let limits = udp_limits(prepared.snapshot)?;
        // Moving the pin to another destination is not a change of that
        // destination's path: a pending change of the old one is reported
        // with its own newest limits, or not at all once it is invalid.
        let change = match changed {
            Some(old) if old.key().destination() == prepared.snapshot.key().destination() => {
                Some(limits)
            }
            Some(old) if old.status() == PathStatus::Valid => Some(udp_limits(old)?),
            _ => None,
        };
        let record = self.udp.slots[slot].flow.as_mut().unwrap();
        record.path = Some(prepared);
        if change.is_some() {
            record.change = change;
        }
        self.paths
            .acknowledge(prepared.client, prepared.snapshot.stamp())?;
        Ok((prepared, limits))
    }

    /// Next queued datagram: its sender and length. A buffer smaller than the
    /// datagram leaves it queued and reports Capacity.
    pub fn udp_receive(
        &mut self,
        id: UdpFlowId,
        buffer: &mut [u8],
    ) -> Result<Option<(SocketAddr, usize)>, Error> {
        let flow = self.udp.flow(id)?;
        if flow.received.len == 0 {
            return Ok(None);
        }
        let depth = self.udp.limits.receive_datagrams;
        let entry = id.slot * depth + flow.received.head;
        let (remote, len) = self.udp.received[entry];
        let stride = self.udp.limits.max_payload;
        buffer
            .get_mut(..len)
            .ok_or(Error::Capacity)?
            .copy_from_slice(&self.udp.payload[entry * stride..][..len]);
        let ring = &mut self.udp.slots[id.slot].flow.as_mut().unwrap().received;
        ring.head = (ring.head + 1) % depth;
        ring.len -= 1;
        Ok(Some((remote, len)))
    }

    /// Next correlated ICMP advice for this flow generation, consumed once.
    pub fn udp_event(&mut self, id: UdpFlowId) -> Result<Option<UdpEvent>, Error> {
        let flow = self.udp.flow(id)?;
        if flow.events.len == 0 {
            return Ok(None);
        }
        let depth = self.udp.limits.events;
        let event = self.udp.events[id.slot * depth + flow.events.head].take();
        let ring = &mut self.udp.slots[id.slot].flow.as_mut().unwrap().events;
        ring.head = (ring.head + 1) % depth;
        ring.len -= 1;
        Ok(event)
    }

    // Deliver a correlated report to the exact live flow generation that
    // submitted the datagram; a closed or reused slot receives nothing.
    pub(crate) fn udp_advise(&mut self, owner: Owner, event: UdpEvent) {
        if let Owner::Datagram { flow, generation } = owner
            && self.udp.live(flow, generation)
        {
            self.udp.push_event(flow, event);
        }
    }

    // Protocol 17 for an address this link owns. The checksum is verified
    // over the pseudo-header (a received IPv4 zero means none was sent; IPv6
    // requires one), the addresses pass the same Incoming policy as TCP, and
    // a connected flow's exact binding takes precedence over an unconnected
    // one. No matching flow, a full queue or an oversized payload drops the
    // datagram; this Host originates no ICMP Port Unreachable.
    pub(crate) fn input_udp(
        &mut self,
        endpoint: &Endpoint,
        packet: &IngressPacket,
    ) -> InputDisposition {
        let (source, destination) = (packet.ip.source, packet.ip.destination);
        let Ok(udp) = ntcp_ip_common::parse_udp(source, destination, packet.payload) else {
            return InputDisposition::Dropped;
        };
        if !endpoint.admits_datagram(AddressValidation::Incoming {
            source,
            destination,
        }) {
            return InputDisposition::Dropped;
        }
        let local = SocketAddr::new(destination, udp.destination_port);
        let remote = SocketAddr::new(source, udp.source_port);
        let slots = &self.udp.slots;
        let Some(slot) = slots
            .iter()
            .position(|s| {
                s.flow
                    .is_some_and(|f| f.local == local && f.remote == Some(remote))
            })
            .or_else(|| {
                slots.iter().position(|s| {
                    s.flow
                        .is_some_and(|f| f.local == local && f.remote.is_none())
                })
            })
        else {
            return InputDisposition::Dropped;
        };
        let (depth, stride) = (
            self.udp.limits.receive_datagrams,
            self.udp.limits.max_payload,
        );
        let ring = self.udp.slots[slot].flow.unwrap().received;
        if ring.len == depth || udp.payload.len() > stride {
            return InputDisposition::Dropped;
        }
        let entry = slot * depth + (ring.head + ring.len) % depth;
        self.udp.received[entry] = (remote, udp.payload.len());
        self.udp.payload[entry * stride..][..udp.payload.len()].copy_from_slice(udp.payload);
        self.udp.slots[slot].flow.as_mut().unwrap().received.len += 1;
        InputDisposition::Processed
    }
}
