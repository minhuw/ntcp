//! Host UDP (RFC 768) flows on the managed path authority.
//!
//! A flow is a bound local socket address with an optional fixed remote. It
//! is admitted by the Endpoint's own address policy, sends through the same
//! path resolution as TCP, records physical-submission evidence of every
//! datagram in the ledger, and receives
//! protocol-17 datagrams that pass the UDP checksum. ICMP errors quoting its
//! datagrams are correlated by the single Host dispatcher and become bounded,
//! consumed events. All storage is allocated once by `Host::new`.

use crate::emitter::{
    DatagramError, DatagramReport, IPV4_PEER_REASSEMBLY, IPV6_PEER_REASSEMBLY, Piece, Plan,
    ProbeRecord, UdpDatagramLimits, UdpSend, UdpSendMode, family_max,
};
use crate::ident::IdentifierBackpressure;
use crate::ledger::{Evidence, FragmentPrefix, Owner, Selector};
use crate::{BackendOutcome, Error, Host, IngressPacket};
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use ntcp::{AddressValidation, Endpoint, EndpointError, Instant, IpMetadata, NetworkError};
use ntcp::{InputDisposition, PreparedPath};
use ntcp_path::{Dscp, LinkId, PathStatus, ResolvedNextHop};

mod receipts;
use receipts::Receipt;
pub use receipts::{
    ProbeReceipt, ProbeReportError, RetrySuppression, SharedOffer, UdpProbeBounds,
    UdpProbeOutcome, UdpProbeReport, UdpSharedWriter,
};

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
    /// Probe-mode receipts one flow may hold unreported (RFC 4821 section 9
    /// outcome reporting). Each definite Probe-mode submission takes one
    /// until its outcome is reported or it becomes unusable (expired after
    /// the feedback horizon, or stale because the flow's path or its
    /// negative or discovery-policy revision changed); a Probe-mode send
    /// with none free is refused before submission. Size it as the probes
    /// the application keeps outstanding at once; at least one per flow.
    /// It is configured once, here, for every flow the Host opens under this
    /// configuration; there is no per-flow override.
    pub probe_receipts: usize,
}

/// Add UDP capacity to limits from `managed_limits`: one path client and
/// cache entry per flow (a flow pins the path it currently sends on), one
/// ledger owner per flow, concurrent attempts for one datagram (a
/// datagram's reservation lives only inside a single send call: one ticket,
/// or one per fragment up to `limits.datagrams.max_fragments`), and each
/// flow's evicted-signature budget.
pub fn managed_udp_limits(
    paths: ntcp_path::Limits,
    limits: crate::Limits,
    udp: UdpLimits,
) -> Result<(ntcp_path::Limits, crate::Limits), Error> {
    let add = |a: usize, b: usize| a.checked_add(b).ok_or(Error::Capacity);
    let attempts = if udp.flows == 0 {
        0
    } else {
        limits.datagrams.max_fragments.max(1)
    };
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
/// incarnation and shared version they were read from. `udp_send` never
/// divides a datagram, so an application using it sizes each one against
/// this before building it; `udp_datagram_limits` reports what the
/// fragmenting and probing modes of `udp_send_datagram` accept.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpPathLimits {
    pub destination: IpAddr,
    pub path: ntcp_path::PathId,
    pub version: u64,
    pub mms_s: u32,
    pub max_payload: usize,
    /// The complete IP header length H of the route the path selected: the
    /// base header, and on an SR route its Segment Routing Header. `mms_s`
    /// and `max_payload` subtract it.
    pub header_len: usize,
}

/// Where the one physical call goes; the closure owns no other authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpEgress {
    pub link: LinkId,
    pub next_hop: ResolvedNextHop,
    /// The Ethernet destination this Host resolved for the packet: Host
    /// ICMP output on an ND-capable port (`register_neighbor_port`). None
    /// where the embedding resolves the next hop itself.
    pub link_layer: Option<[u8; 6]>,
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
    /// The datagram exceeds what the current path allows unfragmented.
    /// `udp_send` never splits a datagram (IPv4 with DF, except on a route
    /// or path whose owner disabled discovery, where it leaves without DF
    /// under that route's sending limit); it is refused, and `max_payload`
    /// is the largest UDP payload this flow may send whole to that
    /// destination now. Fragmentation and probes are selected through
    /// `udp_send_datagram`.
    TooBig {
        max_payload: usize,
    },
    /// A DF-clear IPv4 datagram (a discovery-disabled route) has no
    /// Identification available now (the RFC 6864 ceiling or entropy);
    /// nothing was recorded, and the caller holds the datagram and retries
    /// rather than reuse a value.
    Backpressure(IdentifierBackpressure),
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
    // The link scoping the flow's IPv6 link-local addresses (D1): Some
    // exactly when its local address, or a fixed remote, is link-local.
    // Sources, paths and received datagrams are those of that link only.
    zone: Option<LinkId>,
    options: UdpOptions,
    // Default send mode and stated peer capability (Refuse until set).
    send: UdpSend,
    path: Option<PreparedPath>,
    // Newest unconsumed shared change to the pinned path, replaced (never
    // queued) by later ones, so a slow reader sees the current limits.
    change: Option<UdpPathLimits>,
    received: Ring,
    events: Ring,
    // The application's reported probe outcomes for its pinned path.
    bounds: UdpProbeBounds,
    // Serial of the owner's current shared-writer grant, if any.
    writer: Option<u64>,
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
    // Slot i owns receipts [i * probe_receipts, (i + 1) * probe_receipts).
    receipts: Vec<Option<Receipt>>,
    generation: u64,
    // Issued receipt and shared-writer serials: a handle names exactly one.
    receipt_serial: u64,
    writer_serial: u64,
}

const UNSPECIFIED: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

impl Udp {
    // Each flow holding a path, by slot, with its client.
    pub(crate) fn clients(&self) -> impl Iterator<Item = (usize, ntcp_path::ClientId)> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(slot, s)| Some((slot, s.flow.as_ref()?.path?.client)))
    }
    pub fn new(limits: UdpLimits) -> Result<Self, Error> {
        if limits.flows != 0
            && (limits.receive_datagrams == 0
                || limits.max_payload == 0
                || limits.events == 0
                || limits.probe_receipts == 0)
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
            receipts: crate::table(
                limits
                    .flows
                    .checked_mul(limits.probe_receipts)
                    .ok_or(Error::Capacity)?,
                None,
            )?,
            generation: 0,
            receipt_serial: 0,
            writer_serial: 0,
        })
    }
    fn flow(&self, id: UdpFlowId) -> Result<Flow, Error> {
        self.slots
            .get(id.slot)
            .filter(|s| s.generation == id.generation)
            .and_then(|s| s.flow)
            .ok_or(Error::Obsolete)
    }
    /// Flows currently bound to `path`, with their bound snapshot. A read.
    pub(crate) fn flows_on(
        &self,
        path: ntcp_path::PathId,
    ) -> impl Iterator<Item = (UdpFlowId, PreparedPath)> + '_ {
        self.slots.iter().enumerate().filter_map(move |(slot, s)| {
            let prepared = s.flow?.path?;
            (prepared.snapshot.path() == path).then_some((
                UdpFlowId {
                    slot,
                    generation: s.generation,
                },
                prepared,
            ))
        })
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

// `header` is the complete IP header length of the path's route
// (`Host::header_plan`): the flow's MMS_S is the path budget less it. A
// budget that no longer holds the indivisible header and the UDP header
// (an SR route's Segment Routing Header after a PMTU decrease, a lower
// administrative estimate or link MTU) admits no datagram: Unsupported,
// never a truncated header, another route or an invented payload size.
fn udp_limits(snapshot: ntcp_path::PathSnapshot, header: usize) -> Result<UdpPathLimits, Error> {
    let destination = snapshot.key().destination().address();
    let budget = snapshot.ip_packet_budget().map_err(Error::from)? as usize;
    if budget < header + ntcp_ip::UDP_HEADER {
        return Err(Error::Unsupported);
    }
    Ok(UdpPathLimits {
        destination,
        path: snapshot.path(),
        version: snapshot.version(),
        mms_s: snapshot.payload_budget(
            u32::try_from(header).map_err(|_| Error::Capacity)?,
            0,
            None,
        )?,
        max_payload: budget
            .saturating_sub(header + ntcp_ip::UDP_HEADER)
            .min(usize::from(u16::MAX) - ntcp_ip::UDP_HEADER),
        header_len: header,
    })
}

fn link_local(address: IpAddr) -> bool {
    matches!(address, IpAddr::V6(v) if v.is_unicast_link_local())
}

// The zone of the flow's datagrams to `remote`: its own, which is Some
// exactly when its local address or `remote` is link-local.
fn flow_zone(flow: Flow, remote: IpAddr) -> Option<LinkId> {
    flow.zone.filter(|_| link_local(flow.local.ip()) || link_local(remote))
}

// Send admission of `remote` for the flow, in its zone: a link-local
// remote is reachable only from a scoped flow, on the flow's link.
fn admits_remote(endpoint: &Endpoint, flow: Flow, remote: IpAddr) -> bool {
    endpoint.admits_scoped_datagram(
        AddressValidation::Open {
            local: flow.local.ip(),
            remote,
        },
        flow_zone(flow, remote),
    )
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
        self.udp_open_scoped(endpoint, local, remote, None, options)
    }

    /// `udp_open` for a flow whose IPv6 link-local local address (or fixed
    /// remote) is scoped to the link `zone`, present exactly when one of
    /// them is link-local (as for a `ScopedTuple`). The flow's source, path
    /// and ledger evidence are those of that link, it receives only
    /// datagrams arriving on it, and the identical binding on another link
    /// is a separate flow. A zone whose link was removed or replaced owns
    /// no source: such an open, and every later send of a flow whose link
    /// went away, is refused (`SourceNotOwned`).
    pub fn udp_open_scoped(
        &mut self,
        endpoint: &Endpoint,
        local: SocketAddr,
        remote: Option<SocketAddr>,
        zone: Option<LinkId>,
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
                    && endpoint.admits_scoped_datagram(
                        AddressValidation::Open {
                            local: local.ip(),
                            remote: remote.ip(),
                        },
                        zone,
                    )
            }
            None => endpoint
                .admits_scoped_datagram(AddressValidation::Bind { local: local.ip() }, zone),
        };
        if !admitted || local.port() == 0 || !supported(local) {
            return Err(EndpointError::InvalidAddress.into());
        }
        self.source(local.ip(), zone)?;
        if self
            .udp
            .slots
            .iter()
            .flat_map(|s| s.flow)
            .any(|f| f.local == local && f.remote == remote && f.zone == zone)
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
                let request = self.request(local.ip(), remote.ip(), zone, dscp)?;
                let via = crate::scoped(remote.ip(), zone)?;
                let resolved = self.paths.resolve_via(request, via)?;
                self.forwarding_resolved(resolved.key())?;
                let (client, snapshot) = self.paths.acquire_resolved(request, via, resolved)?;
                self.holders[client.index()] = crate::Holder::Flow(slot);
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
                zone,
                options,
                send: UdpSend::default(),
                path,
                change: None,
                received: Ring::default(),
                events: Ring::default(),
                bounds: UdpProbeBounds::default(),
                writer: None,
            }),
        };
        self.udp.clear_receipts(slot);
        Ok(UdpFlowId { slot, generation })
    }

    /// Release the flow's path and storage. Its submission history becomes
    /// tombstones, so feedback quoting it can never be attributed to a
    /// later generation sending identical datagrams.
    pub fn udp_close(&mut self, id: UdpFlowId) -> Result<(), Error> {
        let flow = self.udp.flow(id)?;
        if let Some(path) = flow.path {
            self.holders[path.client.index()] = crate::Holder::None;
            self.paths.release(path.client)?;
        }
        if let Some(index) = self.ledger.owner_index(Owner::Datagram {
            flow: id.slot,
            generation: id.generation,
        }) {
            self.ledger.release_owner(index, self.now);
        }
        self.udp.slots[id.slot].flow = None;
        self.udp.clear_receipts(id.slot);
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
    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.1
    //= reason=T7 PathService stores shared IP estimates, T8 Host binds actual native/TUN TCP factories and T9 Host ICMP dispatch processes correlated Datagram Too Big messages. T10 lets packetization layers respond: TCP connections receive each shared change by budget application in Host::service_changes, and Host UDP flows read their payload limit (Host::udp_path_limits) and change notifications (Host::udp_path_change) to resize. Host::udp_send sends each UDP datagram unfragmented, with DF except on an owner-flagged route (UdpSendError::TooBig reports the allowable payload); T13's Host::udp_send_datagram adds an explicit per-flow default and per-send mode: Fragment source-fragments a datagram larger than the connectionless effective size within the peer reassembly guarantee or a stated capability (every IPv4 fragment keeps DF and carries an Identification from the Host allocator), Refuse keeps udp_send's contract, and Probe sends one unfragmented datagram above the estimate. The integration/rfc_host fragment and fragment-ptb cases show datagram users that do not resize served by intentional source fragmentation on a real path (tun_echo replies and a driven Host UDP flow, refragmented at 1280 after a real router PTB). IPv4 TCP sets DF by default; native sockets configured with IP_MTU_DISCOVER=IP_PMTUDISC_DONT clear it on ordinary output, each such packet carrying an Identification leased from the same allocator, while their PLPMTUD probes keep DF. T12's owner route or path discovery disable (1191-093, the user's recorded decision B) leaves DF clear on every Host::udp_send and Host::udp_send_datagram UDP datagram and source fragment of the flagged IPv4 route, each with a leased Identification, under the RFC 1122 section 3.3.3 sending limit, so a datagram protocol that relies on fragmentation in the network has that DF-clear choice; the owner sets that flag with the ntcp-pathctl utility through the opt-in local control socket of the native runtime or tun_echo (T12 stage 6). The integration/rfc_host admin cases show it on the wire: after the ntcp-pathctl utility disables discovery on tun_echo's IPv4 path to one destination, every packet to it, source fragments of UDP replies included, leaves with DF clear and its own nonzero leased Identification, at most 576 octets through the Forwarder route or at most the owner's administrative value when one is set, while another destination through the same route keeps DF on its packets and fragments. Host::udp_send, the T9 whole-datagram API that tun_echo's Refuse-mode UDP echo replies use, leaves its IPv4 datagrams on such a route DF clear with a leased Identification as well, holding a datagram on identifier backpressure (UdpSendError::Backpressure) and refusing one above the sending limit with its payload limit (ntcp-host test disabled_ipv4_route_clears_df_on_whole_udp_send_datagrams); the integration/rfc_host admin refuse case captures tun_echo's Refuse-mode replies after ntcp-pathctl disables discovery on its IPv4 path: DF clear, distinct nonzero Identifications and at most 576 octets, a larger reply refused locally with the 548-octet payload limit, while the neighbor destination keeps DF and re-enabling restores it. Route isolation of the IPv4 policy is shown in-process: ntcp-host test disabling_one_ipv4_route_leaves_a_neighbor_route_keeping_df_on_fragments disables one of two routes sharing a link and next hop, whose fragments leave DF clear while the other route keeps DF on its fragments; on the wire, the integration/rfc_host icmp route-isolation case gives the datagram_drive Host a second route (the same link and Forwarder next hop, selected by DSCP): after the owner disables discovery on its default route, that route's source fragments leave DF clear with one nonzero leased Identification per datagram and at most 576 octets, while the neighboring enabled route keeps DF on its fragments and the peer reassembles both.
    //# We therefore believe that the IP layer should store PMTU information and that the ICMP layer should process received Datagram Too Big messages. The packetization layers must still be able to respond to changes in the Path MTU, by changing the size of the datagrams they send, and must also be able to specify that datagrams are sent with the DF bit set. We do not want the IP layer to simply set the DF bit in every packet, since it is possible that a packetization layer, perhaps a UDP application outside the kernel, is unable to change its datagram size. Protocols involving intentional fragmentation, while inelegant, are sometimes successful (NFS being the primary example), and we do not want to break such protocols.
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
            || !admits_remote(endpoint, flow, remote.ip())
        {
            return Err(Error::from(EndpointError::InvalidAddress).into());
        }
        let (prepared, limits) = self.udp_path(id.slot, flow, remote.ip())?;
        let snapshot = prepared.snapshot;
        let ipv4 = remote.is_ipv4();
        let plan = self.header_plan(snapshot.key())?;
        let header = plan.len;
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
            ntcp_ip6::encode_udp_routed(
                packet,
                ntcp_ip6::Header {
                    ip,
                    hop_limit,
                    dscp,
                    ecn: 0,
                },
                plan.segments,
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
            header_len: header as u32,
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
        if snapshot.clears_dont_fragment() {
            // RFC 1191 section 6.6: on a route or path whose owner disabled
            // discovery the datagram leaves without DF whatever the caller
            // requests, a non-atomic datagram with its own leased
            // Identification. No identifier is output backpressure: nothing
            // was recorded and the caller may retry.
            if let Err(backpressure) = self.lease_df_clear(now, packet) {
                self.ledger.cancel(ticket);
                return Err(UdpSendError::Backpressure(backpressure));
            }
        }
        self.now = self.now.max(now);
        let egress = UdpEgress {
            link: snapshot.key().link(),
            next_hop: snapshot.key().next_hop(),
            link_layer: None,
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
        let zone = flow_zone(flow, remote);
        let request =
            self.request(flow.local.ip(), remote, zone, Dscp::new(flow.options.dscp)?)?;
        let via = crate::scoped(remote, zone)?;
        let current = match flow.path {
            Some(prepared) => {
                let snapshot = self.paths.snapshot(prepared.client)?;
                // An SR route derives the forwarding destination S1, which
                // `forwarding` validates by reselecting.
                (snapshot.status() == PathStatus::Valid
                    && snapshot.key().request() == request
                    && (snapshot.key().forwarding_destination() == via
                        || self
                            .header_plan(snapshot.key())
                            .is_ok_and(|plan| !plan.segments.is_empty())))
                    .then_some(PreparedPath {
                        client: prepared.client,
                        snapshot,
                    })
            }
            None => None,
        };
        let prepared = match current {
            Some(prepared) => {
                self.forwarding(&prepared.snapshot)?;
                prepared
            }
            None => {
                let resolved = self.paths.resolve_via(request, via)?;
                self.forwarding_resolved(resolved.key())?;
                let (client, snapshot) = match flow.path {
                    Some(old) => self
                        .paths
                        .rebind_resolved(old.client, request, via, resolved)?,
                    None => self.paths.acquire_resolved(request, via, resolved)?,
                };
                self.holders[client.index()] = crate::Holder::Flow(slot);
                PreparedPath { client, snapshot }
            }
        };
        let limits = udp_limits(
            prepared.snapshot,
            self.header_plan(prepared.snapshot.key())?.len,
        )?;
        // Moving the pin to another destination is not a change of that
        // destination's path: a pending change of the old one is reported
        // with its own newest limits, or not at all once it is invalid.
        let change = match changed {
            Some(old) if old.key().destination() == prepared.snapshot.key().destination() => {
                Some(limits)
            }
            // An old path that no longer admits datagrams has no limits to
            // report.
            Some(old) if old.status() == PathStatus::Valid => {
                match udp_limits(old, self.header_plan(old.key())?.len) {
                    Err(Error::Unsupported) => None,
                    limits => Some(limits?),
                }
            }
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
    // A datagram with an IPv6 link-local address is scoped to its arrival
    // `link` and reaches only a flow of that zone.
    // Record a received UDP datagram's discard.
    #[cold]
    #[inline(never)]
    fn drop_udp(
        &mut self,
        reason: ntcp::DropReason,
        packet: &IngressPacket,
        ports: Option<(u16, u16)>,
    ) -> InputDisposition {
        let ip = packet.ip;
        self.drops.record(reason, self.now, packet.payload.len(), || match ports {
            Some((source, destination)) => ntcp::DropSubject::Transport {
                protocol: 17,
                source: SocketAddr::new(ip.source, source),
                destination: SocketAddr::new(ip.destination, destination),
            },
            None => ntcp::DropSubject::Ip {
                source: ip.source,
                destination: ip.destination,
                protocol: 17,
            },
        });
        InputDisposition::Dropped
    }

    pub(crate) fn input_udp(
        &mut self,
        endpoint: &Endpoint,
        link: LinkId,
        packet: &IngressPacket,
    ) -> InputDisposition {
        let (source, destination) = (packet.ip.source, packet.ip.destination);
        let udp = match ntcp_ip_common::parse_udp(source, destination, packet.payload) {
            Ok(udp) => udp,
            Err(error) => {
                let reason = match error {
                    ntcp_ip_common::Error::Checksum => ntcp::DropReason::UdpCsum,
                    ntcp_ip_common::Error::Truncated => ntcp::DropReason::PktTooSmall,
                    _ => ntcp::DropReason::IpInhdr,
                };
                return self.drop_udp(reason, packet, None);
            }
        };
        let zone = (link_local(source) || link_local(destination)).then_some(link);
        if !endpoint.admits_scoped_datagram(
            AddressValidation::Incoming {
                source,
                destination,
            },
            zone,
        ) {
            let ports = Some((udp.source_port, udp.destination_port));
            return self.drop_udp(ntcp::DropReason::AddressPolicy, packet, ports);
        }
        let local = SocketAddr::new(destination, udp.destination_port);
        let remote = SocketAddr::new(source, udp.source_port);
        let ports = Some((udp.source_port, udp.destination_port));
        let slots = &self.udp.slots;
        // An unconnected flow's zone scopes its link-local local address; a
        // global one receives no link-local source it could not answer.
        let Some(slot) = slots
            .iter()
            .position(|s| {
                s.flow.is_some_and(|f| {
                    f.local == local && f.remote == Some(remote) && f.zone == zone
                })
            })
            .or_else(|| {
                slots.iter().position(|s| {
                    s.flow
                        .is_some_and(|f| f.local == local && f.remote.is_none() && f.zone == zone)
                })
            })
        else {
            return self.drop_udp(ntcp::DropReason::NoSocket, packet, ports);
        };
        let (depth, stride) = (
            self.udp.limits.receive_datagrams,
            self.udp.limits.max_payload,
        );
        let ring = self.udp.slots[slot].flow.unwrap().received;
        if ring.len == depth || udp.payload.len() > stride {
            return self.drop_udp(ntcp::DropReason::SocketRcvbuff, packet, ports);
        }
        let entry = slot * depth + (ring.head + ring.len) % depth;
        self.udp.received[entry] = (remote, udp.payload.len());
        self.udp.payload[entry * stride..][..udp.payload.len()].copy_from_slice(udp.payload);
        self.udp.slots[slot].flow.as_mut().unwrap().received.len += 1;
        InputDisposition::Processed
    }
}

impl Host {
    /// Set the flow's default send mode and the peer reassembly capability
    /// it states (complete reconstructed IP octets, from explicit
    /// application, protocol or deployment knowledge; None keeps the
    /// receiver guarantee). A send may override both.
    pub fn udp_set_send(&mut self, id: UdpFlowId, send: UdpSend) -> Result<(), Error> {
        self.udp.flow(id)?;
        check_capability(send)?;
        self.udp.slots[id.slot].flow.as_mut().unwrap().send = send;
        Ok(())
    }

    /// The limits `udp_send_datagram` applies to `remote` under `send` (the
    /// flow default when None): the unfragmented payload limit, the size
    /// fragments are cut to, the largest logical datagram the mode accepts
    /// and the peer guarantee in force. Pins the destination like
    /// `udp_path_limits`.
    pub fn udp_datagram_limits(
        &mut self,
        endpoint: &Endpoint,
        id: UdpFlowId,
        remote: Option<IpAddr>,
        send: Option<UdpSend>,
    ) -> Result<UdpDatagramLimits, Error> {
        self.check_endpoint(endpoint)?;
        let flow = self.udp.flow(id)?;
        let send = send.unwrap_or(flow.send);
        check_capability(send)?;
        let remote = match (flow.remote.map(|r| r.ip()), remote) {
            (Some(fixed), None) => fixed,
            (Some(fixed), Some(remote)) if fixed == remote => fixed,
            (None, Some(remote)) => remote,
            _ => return Err(Error::InvalidContext),
        };
        let (prepared, limits) = self.udp_path(id.slot, flow, remote)?;
        self.datagram_limits(prepared.snapshot, limits, send, flow.bounds)
    }

    fn datagram_limits(
        &self,
        snapshot: ntcp_path::PathSnapshot,
        path: UdpPathLimits,
        send: UdpSend,
        bounds: UdpProbeBounds,
    ) -> Result<UdpDatagramLimits, Error> {
        let ipv4 = path.destination.is_ipv4();
        let header = path.header_len;
        let overhead = header + ntcp_ip::UDP_HEADER;
        let udp_max = usize::from(u16::MAX) - ntcp_ip::UDP_HEADER;
        let floor = if ipv4 {
            IPV4_PEER_REASSEMBLY
        } else {
            IPV6_PEER_REASSEMBLY
        };
        let guarantee = send.peer_capability.map_or(floor, |c| c.max(floor));
        let probe = bounds.on(snapshot.path());
        let effective_size = self.flow_size(snapshot, probe)?;
        let effective_payload = (effective_size as usize)
            .saturating_sub(overhead)
            .min(udp_max);
        // The fragment budget: every fragment but the last carries a
        // multiple of 8 data octets (RFC 791 section 3.2, RFC 8200 section
        // 4.5); `fragment_count` applies the same cut when sending.
        let fragmentable_payload = if send.mode == UdpSendMode::Fragment {
            let per = header + if ipv4 { 0 } else { ntcp_ip6::FRAGMENT_HEADER };
            let room = (effective_size as usize).saturating_sub(per);
            let fragments = self.datagram_limits.max_fragments;
            let data = if fragments == 0 || room < 8 {
                0
            } else {
                (fragments - 1) * (room & !7) + room
            };
            (header + data)
                .min(guarantee as usize)
                .min(family_max(ipv4))
                .saturating_sub(overhead)
                .min(udp_max)
        } else {
            0
        };
        let max_payload = match send.mode {
            UdpSendMode::Refuse => path.max_payload,
            // No probe leaves a path whose owner disabled discovery.
            UdpSendMode::Probe if snapshot.discovery_disabled() => 0,
            UdpSendMode::Probe => (snapshot.first_hop_mtu() as usize)
                .min(family_max(ipv4))
                .saturating_sub(overhead)
                .min(udp_max),
            UdpSendMode::Fragment => fragmentable_payload.max(path.max_payload),
        };
        Ok(UdpDatagramLimits {
            path,
            send,
            unfragmented_payload: path.max_payload,
            effective_size,
            effective_payload,
            fragmentable_payload,
            max_payload,
            guarantee,
            guarantee_stated: send.peer_capability.is_some(),
            probe,
        })
    }

    /// Send one datagram under `send` (the flow default when None):
    ///
    /// - Refuse: exactly `udp_send`'s contract, reported as one packet.
    /// - Fragment: a datagram within the connectionless effective size goes
    ///   out unfragmented; a larger one within the peer guarantee (or stated
    ///   capability) and `max_fragments` is fragmented to that size even
    ///   below the first-hop MTU (RFC 4821 section 8), each IPv4 fragment
    ///   with DF; one that may not be fragmented still goes whole within the
    ///   shared ordinary budget; beyond both the send is refused with
    ///   `PeerLimit` (RFC 1122 section 3.3.3, RFC 8200 section 5) or
    ///   `TooBig`. `UdpDatagramLimits::fragments` states the same decision.
    /// - Probe: one unfragmented datagram up to the first-hop MTU (RFC 4821
    ///   section 9); only the learned-size admission is bypassed, and the
    ///   returned record proves submission, not delivery. A receipt is
    ///   reserved first (refused with `ReceiptsExhausted`, or with
    ///   `RetrySuppressed` after a reported timeout failure at that size);
    ///   a definite submission's record carries it for
    ///   `Host::udp_report_probe`.
    ///
    /// The UDP checksum is computed once over the complete datagram.
    /// `packet` must hold `UdpDatagramLimits::buffer_len(payload.len())`
    /// octets. `submit` is called once per physical packet, in order; the
    /// transaction stops at the first outcome that is not Submitted.
    //= https://www.rfc-editor.org/rfc/rfc4821#section-8
    //= reason=Host::udp_send_datagram's Fragment mode (crates/stacks/ntcp-host/src/udp.rs) fragments, in the host IP layer, an application datagram larger than the connectionless effective Path MTU E = min(shared ordinary budget, max(connectionless initial eff_pmtu, adjunct-confirmed lower bound)), which the probe outcomes a flow's application reports (4821-160) raise or bound for that flow only, to E even when it is smaller than the first-hop MTU, within the receiver reassembly guarantee (IPv4 576, IPv6 1500) or a capability the application states; a datagram the guarantee forbids fragmenting still goes whole within the shared budget. Every IPv4 fragment carries DF (except on an owner-disabled IPv4 route, the user's recorded decision B under RFC 1191 section 6.6, where every packet leaves DF clear) and a leased Identification, and IPv6 uses the same emitter, so the behavior is the same in both families. Host tests cut a 3000-octet datagram at E = 1280 below a 1500 first hop into 1276-octet IPv4 and 1280-octet IPv6 fragments with DF on each IPv4 fragment and one complete-datagram checksum; the integration/rfc_host fragment case captures tun_echo replies cut to E below the 1500 first hop, and fragment-ptb shows a real router PTB for an oversized DF first fragment lowering the path so the next datagram is refragmented at 1280. Section 9's exception is Probe mode (4821-158).
    //# It is RECOMMENDED that IPv4 implementations use a strategy that mimics IPv6 functionality. When an application sends datagrams that are larger than the effective Path MTU, they SHOULD be fragmented to the Path MTU in the host IP layer even if they are smaller than the MTU of the first link, directly attached to the host. The DF bit SHOULD be set on the fragments, so they will not be fragmented again in the network. This technique will minimize the likelihood that applications will rely on IPv4 fragmentation in a way that cannot be implemented in IPv6. At least one major operating system already uses this strategy. Section 9 describes some exceptions to this rule when the application is sending oversized packets for probing or diagnostic purposes.
    //= https://www.rfc-editor.org/rfc/rfc4821#section-4
    //= reason=Host::udp_send_datagram's Probe mode (UdpSendMode::Probe, crates/stacks/ntcp-host/src/udp.rs), selected per send or as a flow default beside Fragment (fragments a datagram that is too large) and Refuse (rejects it; udp_send's contract), sends one application datagram larger than the current estimate (the shared learned budget, eff_pmtu) and up to the first-hop link MTU unfragmented: IPv4 with DF, IPv6 without a Fragment header. It bypasses only the learned-size admission and keeps first-hop, path-generation and exact-byte validation. Its ProbeRecord states definite or uncertain submission, flow generation, path incarnation, version and negative revision, size, the estimate it exceeded and the submission time; it proves submission, not delivery, and writes no shared state (the application reports the outcome through Host::udp_report_probe, 4821-160). Host tests send a probe above a learned 1280 estimate within the 1500 first hop and assert one unfragmented packet (DF on IPv4), the record, an uncertain record for an unknown backend outcome, refusal beyond the first hop and an unchanged shared limit; the integration/rfc_host probe-mode case sends 1400- and 1500-octet probes above a router-taught 1280 estimate in both families and captures each as one unfragmented packet (DF on IPv4) drawing a real router PTB.
    //# All implementations MUST include mechanisms for applications to selectively transmit packets larger than the current effective Path MTU, but smaller than the first-hop link MTU. This is necessary to implement PLPMTUD using a connectionless protocol within an application and to implement diagnostic tools that do not rely on the operating system's implementation of Path MTU Discovery. See Section 9 for further discussion.
    //= https://www.rfc-editor.org/rfc/rfc4821#section-9
    //= reason=Host::udp_send_datagram's Probe mode (UdpSendMode::Probe, crates/stacks/ntcp-host/src/udp.rs), selected per send or as a flow default beside Fragment (fragments a datagram that is too large) and Refuse (rejects it; udp_send's contract), sends one application datagram larger than the current estimate (the shared learned budget, eff_pmtu) and up to the first-hop link MTU unfragmented: IPv4 with DF, IPv6 without a Fragment header. It bypasses only the learned-size admission and keeps first-hop, path-generation and exact-byte validation. Its ProbeRecord states definite or uncertain submission, flow generation, path incarnation, version and negative revision, size, the estimate it exceeded and the submission time; it proves submission, not delivery, and writes no shared state (the application reports the outcome through Host::udp_report_probe, 4821-160). Host tests send a probe above a learned 1280 estimate within the 1500 first hop and assert one unfragmented packet (DF on IPv4), the record, an uncertain record for an unknown backend outcome, refusal beyond the first hop and an unchanged shared limit; the integration/rfc_host probe-mode case sends 1400- and 1500-octet probes above a router-taught 1280 estimate in both families and captures each as one unfragmented packet (DF on IPv4) drawing a real router PTB.
    //# All implementations MUST include a mechanism where applications using connectionless protocols can send their own probes. This is necessary to implement PLPMTUD in an application protocol as described in Section 10.4 or to implement diagnostic tools for debugging problems with PMTUD. There MUST be a mechanism that permits an application to send datagrams that are larger than eff_pmtu, the operating systems estimate of the Path MTU, without being fragmented. If these are IPv4 packets, they MUST have the DF bit set.
    //= https://www.rfc-editor.org/rfc/rfc4821#section-9
    //= reason=Host::udp_send_datagram's Probe mode (UdpSendMode::Probe, crates/stacks/ntcp-host/src/udp.rs), selected per send or as a flow default beside Fragment (fragments a datagram that is too large) and Refuse (rejects it; udp_send's contract), sends one application datagram larger than the current estimate (the shared learned budget, eff_pmtu) and up to the first-hop link MTU unfragmented: IPv4 with DF, IPv6 without a Fragment header. It bypasses only the learned-size admission and keeps first-hop, path-generation and exact-byte validation. Its ProbeRecord states definite or uncertain submission, flow generation, path incarnation, version and negative revision, size, the estimate it exceeded and the submission time; it proves submission, not delivery, and writes no shared state (the application reports the outcome through Host::udp_report_probe, 4821-160). Host tests send a probe above a learned 1280 estimate within the 1500 first hop and assert one unfragmented packet (DF on IPv4), the record, an uncertain record for an unknown backend outcome, refusal beyond the first hop and an unchanged shared limit; the integration/rfc_host probe-mode case sends 1400- and 1500-octet probes above a router-taught 1280 estimate in both families and captures each as one unfragmented packet (DF on IPv4) drawing a real router PTB.
    //# At this time, most operating systems support two modes for sending datagrams: one that silently fragments packets that are too large, and another that rejects packets that are too large. Neither of these modes is suitable for implementing PLPMTUD in an application or diagnosing problems with Path MTU Discovery. A third mode is REQUIRED where the datagram is sent even if it is larger than the current estimate of the Path MTU.
    //= https://www.rfc-editor.org/rfc/rfc4821#section-10.4
    //= reason=Host::udp_send_datagram's Probe mode (UdpSendMode::Probe, crates/stacks/ntcp-host/src/udp.rs), selected per send or as a flow default beside Fragment (fragments a datagram that is too large) and Refuse (rejects it; udp_send's contract), sends one application datagram larger than the current estimate (the shared learned budget, eff_pmtu) and up to the first-hop link MTU unfragmented: IPv4 with DF, IPv6 without a Fragment header. It bypasses only the learned-size admission and keeps first-hop, path-generation and exact-byte validation. Its ProbeRecord states definite or uncertain submission, flow generation, path incarnation, version and negative revision, size, the estimate it exceeded and the submission time; it proves submission, not delivery, and writes no shared state (the application reports the outcome through Host::udp_report_probe, 4821-160). Host tests send a probe above a learned 1280 estimate within the 1500 first hop and assert one unfragmented packet (DF on IPv4), the record, an uncertain record for an unknown backend outcome, refusal beyond the first hop and an unchanged shared limit; the integration/rfc_host probe-mode case sends 1400- and 1500-octet probes above a router-taught 1280 estimate in both families and captures each as one unfragmented packet (DF on IPv4) drawing a real router PTB.
    //# All application probing techniques require the ability to send messages that are larger than the current eff_pmtu described in Section 9.
    #[allow(clippy::too_many_arguments)]
    pub fn udp_send_datagram(
        &mut self,
        endpoint: &Endpoint,
        now: Instant,
        id: UdpFlowId,
        remote: Option<SocketAddr>,
        send: Option<UdpSend>,
        payload: &[u8],
        packet: &mut [u8],
        submit: impl FnMut(UdpEgress, &[u8]) -> BackendOutcome,
    ) -> Result<DatagramReport, DatagramError> {
        self.check_endpoint(endpoint)?;
        let flow = self.udp.flow(id)?;
        let send = send.unwrap_or(flow.send);
        check_capability(send)?;
        let remote = match (flow.remote, remote) {
            (Some(fixed), None) => fixed,
            (Some(fixed), Some(remote)) if fixed == remote => fixed,
            (None, Some(remote)) => remote,
            _ => return Err(Error::InvalidContext.into()),
        };
        if remote.port() == 0
            || !supported(remote)
            || !admits_remote(endpoint, flow, remote.ip())
        {
            return Err(Error::from(EndpointError::InvalidAddress).into());
        }
        let (prepared, path) = self.udp_path(id.slot, flow, remote.ip())?;
        let snapshot = prepared.snapshot;
        let limits = self.datagram_limits(snapshot, path, send, flow.bounds)?;
        let ipv4 = remote.is_ipv4();
        let header = path.header_len;
        let data_len = ntcp_ip::UDP_HEADER + payload.len();
        let complete = header + data_len;
        let budget = snapshot.ip_packet_budget().map_err(Error::from)? as usize;
        // Whether to cut the datagram, and to what size.
        let ip = IpMetadata {
            source: flow.local.ip(),
            destination: remote.ip(),
        };
        // Receipt capacity is reserved before a Probe-mode submission.
        let mut receipt = None;
        let fragment_size = match send.mode {
            UdpSendMode::Refuse => {
                if payload.len() > path.max_payload {
                    return Err(DatagramError::TooBig {
                        max_payload: path.max_payload,
                    });
                }
                None
            }
            UdpSendMode::Probe => {
                if snapshot.discovery_disabled() {
                    return Err(DatagramError::DiscoveryDisabled);
                }
                if payload.len() > limits.max_payload {
                    return Err(DatagramError::TooBig {
                        max_payload: limits.max_payload,
                    });
                }
                if let Some(s) = limits.probe.suppressed
                    && complete as u32 >= s.size
                    && now < s.until
                {
                    return Err(DatagramError::RetrySuppressed {
                        size: s.size,
                        until: s.until,
                    });
                }
                receipt = Some(self.reserve_receipt(id, now, snapshot)?);
                None
            }
            UdpSendMode::Fragment => {
                // The decision `UdpDatagramLimits` reports: within the
                // effective size whole, then fragments within the peer
                // guarantee and `max_fragments`.
                if limits.fragments(payload.len()) {
                    Some(limits.effective_size as usize)
                } else if payload.len() <= limits.effective_payload
                    || payload.len() <= path.max_payload
                {
                    // Never refused within the path's unfragmented limit.
                    None
                } else if complete > limits.guarantee as usize {
                    return Err(DatagramError::PeerLimit {
                        max_payload: limits.max_payload,
                        guarantee: limits.guarantee,
                    });
                } else {
                    return Err(DatagramError::TooBig {
                        max_payload: limits.max_payload,
                    });
                }
            }
        };
        let (dscp, hop_limit) = (flow.options.dscp, flow.options.hop_limit);
        let (source_port, destination_port) = (flow.local.port(), remote.port());
        match fragment_size {
            None => {
                let packet = packet.get_mut(..complete).ok_or(Error::Capacity)?;
                packet[header + ntcp_ip::UDP_HEADER..].copy_from_slice(payload);
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
                        source_port,
                        destination_port,
                        payload.len(),
                        0,
                    )
                } else {
                    ntcp_ip6::encode_udp_routed(
                        packet,
                        ntcp_ip6::Header {
                            ip,
                            hop_limit,
                            dscp,
                            ecn: 0,
                        },
                        self.header_plan(snapshot.key())?.segments,
                        source_port,
                        destination_port,
                        payload.len(),
                    )
                };
                if encoded.map_err(Error::Codec)? != complete {
                    return Err(Error::Obsolete.into());
                }
            }
            Some(size) => {
                let data = packet
                    .get_mut(size..size + data_len)
                    .ok_or(Error::Capacity)?;
                data[ntcp_ip::UDP_HEADER..].copy_from_slice(payload);
                ntcp_ip_common::encode_udp(
                    ip.source,
                    ip.destination,
                    source_port,
                    destination_port,
                    data,
                    payload.len(),
                )
                .map_err(Error::Codec)?;
            }
        }
        let owner = Owner::Datagram {
            flow: id.slot,
            generation: id.generation,
        };
        // Per-fragment evidence (RFC 4821 section 8 host fragmentation): the
        // ICMP dispatcher correlates a quoted first fragment by its UDP
        // selector and a later one only by its exact physical evidence.
        let evidence = |piece: Piece, data: &[u8]| {
            let transport = if piece.offset == 0 {
                // Fragment zero (or the whole datagram) starts with the UDP
                // header of the complete datagram.
                let (udp, first) = match fragment_size {
                    Some(_) => (data, piece.more),
                    None => (&data[header..], false),
                };
                let (length, checksum) = (
                    u16::from_be_bytes([udp[4], udp[5]]),
                    u16::from_be_bytes([udp[6], udp[7]]),
                );
                if first {
                    Selector::UdpFirstFragment {
                        source_port,
                        destination_port,
                        length,
                        checksum,
                    }
                } else {
                    Selector::Udp {
                        source_port,
                        destination_port,
                        length,
                        checksum,
                    }
                }
            } else {
                Selector::Fragment {
                    offset: piece.offset as u16,
                    more: piece.more,
                    prefix: FragmentPrefix::new(data),
                    logical_ports: (source_port, destination_port),
                }
            };
            Some(Evidence {
                link: snapshot.key().link(),
                path: snapshot.path(),
                owner,
                source: ip.source,
                destination: ip.destination,
                dscp,
                header_len: piece.header_len as u32,
                packet_len: piece.packet_len as u32,
                protocol: ntcp_ip::PROTOCOL_UDP,
                transport,
            })
        };
        let plan = Plan {
            ip,
            protocol: ntcp_ip::PROTOCOL_UDP,
            dscp,
            hop_limit,
            data_len,
            fragment_size,
            snapshot,
            client: Some(prepared.client),
            options: None,
        };
        let mut report = self.transmit(
            now,
            plan,
            packet,
            evidence,
            Some(owner),
            Some(endpoint),
            submit,
        )?;
        if send.mode == UdpSendMode::Probe {
            let definite = report.submitted == 1;
            let receipt = match receipt {
                Some(index) if definite => {
                    Some(self.issue_receipt(id, index, snapshot, complete as u32, now))
                }
                _ => None,
            };
            report.probe = Some(ProbeRecord {
                definite,
                flow_generation: id.generation,
                path: snapshot.path(),
                version: snapshot.version(),
                negative_revision: snapshot.negative_revision(),
                size: complete as u32,
                above: (complete > budget).then_some(budget as u32),
                submitted_at: now,
                receipt,
            });
        }
        Ok(report)
    }
}

fn check_capability(send: UdpSend) -> Result<(), Error> {
    // A stated capability is a complete reconstructed datagram; one below
    // the family's receiver guarantee states nothing more than it.
    if send
        .peer_capability
        .is_some_and(|c| !(IPV4_PEER_REASSEMBLY..=65575).contains(&c))
    {
        return Err(Error::Capacity);
    }
    Ok(())
}
