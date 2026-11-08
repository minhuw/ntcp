//! Explicit serialized factory and network-budget contracts. The provider is
//! borrowed for one transaction; it is never stored inside an Endpoint.
use crate::{
    ActiveOpenOptions, ConnectionId, EndpointError, Instant, IpMetadata, Ipv4RegistrationError,
    Ipv4RegistrationPlan, ListenerId, OutgoingIpv4Options, RegisteredOption, Tuple,
};
use ntcp_path::{ClientId, ContextId, Dscp, PathSnapshot};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactoryRole {
    Active,
    Passive,
    TimeWaitReplacement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathFactoryRequest {
    pub tuple: Tuple,
    /// The link scoping `tuple`, present exactly when one of its addresses
    /// is IPv6 link-local (`ScopedTuple`). The provider selects paths only
    /// on that link.
    pub zone: Option<ntcp_path::LinkId>,
    pub role: FactoryRole,
    pub listener: Option<ListenerId>,
    pub dscp: Dscp,
    pub ipv4_options: OutgoingIpv4Options,
    /// The owner's checked plan for `ipv4_options` of an active open. The
    /// provider binds it to the route authority it selects in `prepare`;
    /// option-bearing output then leaves only under that authority.
    pub registration: Option<Ipv4RegistrationPlan>,
}

/// A provisional client already charged to the provider's bounded storage.
/// Construction validates its context and outbound tuple before using it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedPath {
    pub client: ClientId,
    pub snapshot: PathSnapshot,
}

/// The largest complete IP datagram (header included) that the Host context
/// can receive for one family: its reassembly capacity, its maximum live
/// connected link enabled for the family and the family wire limit, the
/// least of them. A managed connection's receive MSS offer is derived from
/// it, never from the discovered send PMTU or the local send ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveIpCapability {
    context: ContextId,
    ipv6: bool,
    ip_packet: u32,
}
impl ReceiveIpCapability {
    /// `None` unless `ip_packet` carries the fixed IP and TCP base headers
    /// and one payload octet, and fits the family's non-jumbo datagram
    /// (65535 octets for IPv4; a 65535-octet payload after the 40-octet
    /// IPv6 header).
    pub const fn new(context: ContextId, ipv6: bool, ip_packet: u32) -> Option<Self> {
        let (header, wire) = if ipv6 { (40, 65575) } else { (20, 65535) };
        if ip_packet < header + 20 + 1 || ip_packet > wire {
            return None;
        }
        Some(Self {
            context,
            ipv6,
            ip_packet,
        })
    }
    pub const fn context(self) -> ContextId {
        self.context
    }
    pub const fn ipv6(self) -> bool {
        self.ipv6
    }
    pub const fn ip_packet(self) -> u32 {
        self.ip_packet
    }
    /// The TCP payload one such datagram carries after the IP and TCP base
    /// headers; TCP options are not subtracted (RFC 6691 section 2).
    pub const fn mss(self) -> u16 {
        (self.ip_packet - if self.ipv6 { 40 } else { 20 } - 20) as u16
    }
}

/// A prepared path and the receive capability derived for its family in
/// the same serialized factory transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedFactory {
    pub path: PreparedPath,
    pub receive: ReceiveIpCapability,
}

pub trait PathProvider {
    type Error;
    /// Acquire the provisional path and derive, from current facts, the
    /// receive capability of the request's family. A provider that cannot
    /// state one fails without retaining anything.
    fn prepare(&mut self, request: PathFactoryRequest) -> Result<PreparedFactory, Self::Error>;
    /// All capacity must have been reserved by prepare. Commit cannot fail.
    fn commit(&mut self, prepared: PreparedPath, connection: ConnectionId);
    fn cancel(&mut self, prepared: PreparedPath);
    /// The complete IP header length, extension headers included, of the
    /// path a stateless reply with these addresses and DSCP would leave on
    /// now, so that the Endpoint sizes the reply as it will be placed. A
    /// `zone` (the arrival link of the input that caused the reply, present
    /// exactly when one of its addresses is IPv6 link-local) restricts that
    /// path to its link. None when the provider states none: the reply is
    /// sized with the minimal header and the provider's own submission check
    /// decides.
    fn reply_header_len(
        &mut self,
        ip: IpMetadata,
        zone: Option<ntcp_path::LinkId>,
        dscp: u8,
    ) -> Option<u16> {
        let _ = (ip, zone, dscp);
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedError<E> {
    Provider(E),
    Endpoint(EndpointError),
}
impl<E> From<EndpointError> for ManagedError<E> {
    fn from(error: EndpointError) -> Self {
        Self::Endpoint(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedOpenOptions {
    pub transport: ActiveOpenOptions,
    pub dscp: u8,
    pub ipv4_options: OutgoingIpv4Options,
    /// Required when `ipv4_options` requests Record Route or Timestamp: the
    /// checked plan for exactly that request between this open's addresses
    /// (RFC 791 section 3.1), stated for the route authority the open
    /// selects. Its option area keeps the plan's size for the connection.
    pub registration: Option<Ipv4RegistrationPlan>,
    pub receive_authority: Option<ListenerId>,
}

/// Readable even for a released transport generation with final output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedPathInfo {
    pub binding: PreparedPath,
    pub tuple: Tuple,
    /// The link scoping `tuple` (`ScopedTuple::zone`).
    pub zone: Option<ntcp_path::LinkId>,
    /// Current retained outgoing selection, which can change after validated
    /// peer return-route input before the host refreshes the bound path key.
    pub forwarding_destination: core::net::IpAddr,
    pub ip_header_len: u16,
    pub ordinary_ip_budget: u32,
}

/// What a path provider reads of a connection's managed path on every
/// packet (`Endpoint::managed_route`): the parts of `ManagedPathInfo` that
/// select its route, without a copy of the bound path's snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedRoute {
    pub client: ntcp_path::ClientId,
    /// The observation of the bound snapshot (`PreparedPath::snapshot`): a
    /// stamp names one snapshot, so equal stamps mean an equal binding.
    pub stamp: ntcp_path::ChangeStamp,
    /// The traffic class of the connection's packets.
    pub dscp: u8,
    /// See `ManagedPathInfo::zone`.
    pub zone: Option<ntcp_path::LinkId>,
    /// See `ManagedPathInfo::forwarding_destination`.
    pub forwarding_destination: core::net::IpAddr,
    /// See `ManagedPathInfo::ordinary_ip_budget`.
    pub ordinary_ip_budget: u32,
}

/// Transport-local limits of one connection, reported beside (never inside)
/// the shared IP-layer path estimate: none of them is network evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportCeilings {
    /// The peer's MSS option (or the family default without one).
    pub peer_mss: u16,
    /// The user's TCP_MAXSEG-style ceiling.
    pub user_mss: Option<u16>,
    /// The connection's configured send MSS limit.
    pub local_mss: u16,
    /// Segment scratch allocation, in octets.
    pub allocation: usize,
    /// Configured IP payload ceiling of each transmitted packet.
    pub send_ip_payload_limit: u16,
    /// Endpoint destination-policy MTU ceiling, when one applies.
    pub destination_mtu: Option<u32>,
    /// The resulting send MSS, intersected with the path budget.
    pub effective_mss: usize,
}

/// Minted from the actual selected departure, retrieved by exact live attempt.
/// A size or a DF bit cannot construct an authenticated intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveryIntent {
    pub(crate) binding: PreparedPath,
    pub(crate) ip_packet_len: u32,
    pub(crate) selected_at: Instant,
}
impl DiscoveryIntent {
    pub const fn binding(self) -> PreparedPath {
        self.binding
    }
    pub const fn ip_packet_len(self) -> u32 {
        self.ip_packet_len
    }
    pub const fn selected_at(self) -> Instant {
        self.selected_at
    }
}

#[derive(Clone, Copy)]
pub(crate) struct FactoryTransaction {
    pub request: PathFactoryRequest,
    pub prepared: PreparedPath,
    pub receive: ReceiveIpCapability,
    pub inserted: Option<ConnectionId>,
}

// The open's registration plan, checked before any path or connection
// resource is committed: originating Record Route or Timestamp needs the
// owner's plan, and a supplied plan must describe exactly this request.
pub(crate) fn check_registration(
    request: &PathFactoryRequest,
) -> Result<(), Ipv4RegistrationError> {
    let options = &request.ipv4_options;
    let missing = |option| Err(Ipv4RegistrationError::MissingExpectation { option });
    match &request.registration {
        Some(plan) => {
            plan.check_request(request.tuple.local.ip(), request.tuple.remote.ip(), options)
        }
        None if options.record_route_slots.is_some() => missing(RegisteredOption::RecordRoute),
        None if options.timestamp.is_some() => missing(RegisteredOption::Timestamp),
        None => Ok(()),
    }
}

// The receive capability was derived for this Host context and the family
// of the request's tuple.
pub(crate) fn valid_receive(
    context: ContextId,
    request: PathFactoryRequest,
    receive: ReceiveIpCapability,
) -> bool {
    receive.context() == context && receive.ipv6() == request.tuple.local.is_ipv6()
}

pub(crate) fn valid_prepared(
    context: ContextId,
    request: PathFactoryRequest,
    prepared: PreparedPath,
) -> bool {
    let key = prepared.snapshot.key();
    let destination = request
        .ipv4_options
        .source_route
        .and_then(|r| r.hops().first().copied())
        .map(core::net::IpAddr::V4)
        .unwrap_or(request.tuple.remote.ip());
    check_registration(&request).is_ok()
        && prepared.client.context() == context
        && key.context() == context
        && key.source_address().address() == request.tuple.local.ip()
        && key.destination().address() == request.tuple.remote.ip()
        // A scoped tuple's path lies on its own link.
        && request.zone.is_none_or(|zone| key.link() == zone)
        // An SR route, whose path header carries the Segment Routing Header,
        // forwards a final destination to the first segment it derives.
        && (key.forwarding_destination().address() == destination
            || (destination == request.tuple.remote.ip()
                && destination.is_ipv6()
                && prepared.snapshot.ip_header_len() > 40))
        && key.dscp() == request.dscp
        && prepared.snapshot.ip_packet_budget().is_ok_and(|budget| {
            let header =
                if let (core::net::IpAddr::V4(source), core::net::IpAddr::V4(destination)) =
                    (request.tuple.local.ip(), request.tuple.remote.ip())
                {
                    request
                        .ipv4_options
                        .encode(source, destination, 0, &mut [0; 40])
                        .map(|(_, n)| 20 + n)
                        .unwrap_or(usize::MAX)
                } else {
                    // The base header and any Segment Routing Header.
                    prepared.snapshot.ip_header_len() as usize
                };
            header
                .checked_add(20)
                .is_some_and(|headers| headers <= budget as usize)
        })
}
