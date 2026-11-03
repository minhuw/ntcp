//! Explicit serialized factory and network-budget contracts. The provider is
//! borrowed for one transaction; it is never stored inside an Endpoint.
use crate::{
    ActiveOpenOptions, ConnectionId, EndpointError, Instant, Ipv4RegistrationError,
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

pub trait PathProvider {
    type Error;
    fn prepare(&mut self, request: PathFactoryRequest) -> Result<PreparedPath, Self::Error>;
    /// All capacity must have been reserved by prepare. Commit cannot fail.
    fn commit(&mut self, prepared: PreparedPath, connection: ConnectionId);
    fn cancel(&mut self, prepared: PreparedPath);
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
    /// Current retained outgoing selection, which can change after validated
    /// peer return-route input before the host refreshes the bound path key.
    pub forwarding_destination: core::net::IpAddr,
    pub ip_header_len: u16,
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
        && key.forwarding_destination().address() == destination
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
                    40
                };
            header
                .checked_add(20)
                .is_some_and(|headers| headers <= budget as usize)
        })
}
