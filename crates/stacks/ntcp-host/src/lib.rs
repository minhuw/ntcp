#![no_std]

extern crate alloc;
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};
use ntcp::{
    ConnectionId, Endpoint, EndpointConfig, EndpointError, Instant, IpMetadata, Ipv4Options,
    ManagedError, PathFactoryRequest, PathProvider, PreparedPath, RxPacketMetadata, Transmit,
    TransmitAttempt, Tuple,
};
pub use ntcp_path as path;
use path::{
    ContextId, Dscp, ForwarderId, InterfaceKey, LinkId, PathRequest, PathService, PathSnapshot,
    PathStatus, ResolvedNextHop, ScopedAddress,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Path(path::Error),
    Endpoint(EndpointError),
    Codec(ntcp_ip::Error),
    Capacity,
    Allocation,
    InvalidContext,
    Unsupported,
    Obsolete,
}
impl From<path::Error> for Error {
    fn from(error: path::Error) -> Self {
        Self::Path(error)
    }
}
impl From<EndpointError> for Error {
    fn from(error: EndpointError) -> Self {
        Self::Endpoint(error)
    }
}
impl From<ntcp_ip::Error> for Error {
    fn from(error: ntcp_ip::Error) -> Self {
        Self::Codec(error)
    }
}
impl From<ManagedError<Error>> for Error {
    fn from(error: ManagedError<Error>) -> Self {
        match error {
            ManagedError::Provider(error) => error,
            ManagedError::Endpoint(error) => Self::Endpoint(error),
        }
    }
}

/// Actual codec/input-buffer capabilities. Neither profile supplies fragment
/// reassembly, IPv6 extension traversal, derived MMS_R, or a standard clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveCapabilities {
    pub max_ip_packet: usize,
    pub ipv4: Ipv4Receive,
    pub ipv6: Ipv6Receive,
    pub gro: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv4Receive {
    Disabled,
    /// Validate framing and retain unrecognized options while leaving known
    /// option interpretation disabled by the embedding's receive policy.
    Unrecognized,
    /// Current codec decoding and metadata retention; this does not promise
    /// complete IPv4 option processing (the remaining host work is T14).
    Options {
        source_routes: bool,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv6Receive {
    Disabled,
    BaseHeader,
}

/// A backend explicitly assigns its forwarding contract at registration.
/// `IpNextHop` requires the embedding to resolve the returned IP next hop;
/// a fixed MAC or a TUN L3 endpoint instead uses `Forwarder`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Forwarding {
    IpNextHop,
    Forwarder(ForwarderId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub bindings: usize,
    pub output_leases: usize,
}

/// Storage rationale: all occupied transport generations, one provisional
/// factory (including TIME-WAIT replacement), the Endpoint's single independent
/// stateless reservation lane when control output is enabled, and explicitly
/// requested migration headroom. Connection-associated final output uses its
/// retained binding. Every sum is checked; source/link/route capacities are
/// configured authority.
pub fn managed_limits(
    config: &EndpointConfig,
    links: usize,
    sources: usize,
    source_owners: usize,
    routes: usize,
    migration_headroom: usize,
) -> Result<(path::Limits, Limits), Error> {
    let bindings = config
        .max_connections
        .checked_add(1)
        .ok_or(Error::Capacity)?;
    let output_leases = usize::from(config.max_control_packets != 0);
    let clients = bindings
        .checked_add(output_leases)
        .and_then(|n| n.checked_add(migration_headroom))
        .ok_or(Error::Capacity)?;
    Ok((
        path::Limits {
            links,
            sources,
            source_owners,
            routes,
            paths: clients,
            clients,
        },
        Limits {
            bindings,
            output_leases,
        },
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IngressContext {
    link: LinkId,
}
impl IngressContext {
    pub const fn link(self) -> LinkId {
        self.link
    }
    pub const fn context(self) -> ContextId {
        self.link.context()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EgressContext {
    pub link: LinkId,
    pub next_hop: ResolvedNextHop,
    pub binding: PreparedPath,
    pub attempt: TransmitAttempt,
}

#[derive(Clone, Copy, Debug)]
pub struct IngressPacket<'a> {
    pub ip: IpMetadata,
    pub traffic_class: u8,
    pub protocol: u8,
    pub options: Ipv4Options,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy)]
struct Port {
    link: LinkId,
    receive: ReceiveCapabilities,
    forwarding: Forwarding,
}
#[derive(Clone, Copy)]
struct Binding {
    owner: Option<ConnectionId>,
    prepared: PreparedPath,
}
#[derive(Clone, Copy)]
struct Lease {
    attempt: TransmitAttempt,
    prepared: PreparedPath,
}

/// Serialized authority beside an Endpoint, with one canonical PathService.
/// No socket/peer limits or TCP delivery evidence enter the shared service.
/// All tables are allocated fallibly once; packet/factory operations allocate
/// only through the Endpoint's independently bounded transport allocator.
pub struct Host {
    paths: PathService,
    ports: Vec<Option<Port>>,
    bindings: Vec<Option<Binding>>,
    leases: Vec<Option<Lease>>,
    timebase: ntcp::CallerTimebase,
    attached: bool,
}

fn table<T: Clone>(count: usize, value: T) -> Result<Vec<T>, Error> {
    count
        .checked_mul(core::mem::size_of::<T>())
        .filter(|n| *n <= isize::MAX as usize)
        .ok_or(Error::Capacity)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    result.resize(count, value);
    Ok(result)
}

impl Host {
    pub fn new(
        context: ContextId,
        path_limits: path::Limits,
        limits: Limits,
        timebase: ntcp::CallerTimebase,
    ) -> Result<Self, Error> {
        if limits
            .bindings
            .checked_add(limits.output_leases)
            .ok_or(Error::Capacity)?
            > path_limits.clients
            || !matches!(timebase.units_per_second, 1_000_000 | 1_000_000_000)
            || !(1..=255_000_000).contains(&timebase.max_segment_lifetime_us)
        {
            return Err(Error::Capacity);
        }
        Ok(Self {
            paths: PathService::new(context, path_limits)?,
            ports: table(path_limits.links, None)?,
            bindings: table(limits.bindings, None)?,
            leases: table(limits.output_leases, None)?,
            timebase,
            attached: false,
        })
    }
    pub fn paths(&self) -> &PathService {
        &self.paths
    }
    pub fn register_source(
        &mut self,
        address: ScopedAddress,
        link: LinkId,
    ) -> Result<path::SourceId, Error> {
        self.port(link)?;
        Ok(self.paths.register_source(address, link)?)
    }
    pub fn remove_source_owner(
        &mut self,
        source: path::SourceId,
        link: LinkId,
    ) -> Result<(), Error> {
        Ok(self.paths.remove_source_owner(source, link)?)
    }
    pub fn add_route(&mut self, route: path::Route) -> Result<path::RouteId, Error> {
        Ok(self.paths.add_route(route)?)
    }
    pub fn replace_route(
        &mut self,
        old: path::RouteId,
        route: path::Route,
    ) -> Result<path::RouteId, Error> {
        Ok(self.paths.replace_route(old, route)?)
    }
    pub fn remove_route(&mut self, route: path::RouteId) -> Result<(), Error> {
        Ok(self.paths.remove_route(route)?)
    }
    pub fn set_link_mtu(&mut self, link: LinkId, mtu: u32) -> Result<(), Error> {
        Ok(self.paths.set_link_mtu(link, mtu)?)
    }
    pub fn set_ipv4_plateaus(&mut self, plateaus: path::Ipv4Plateaus) -> Result<(), Error> {
        Ok(self.paths.set_ipv4_plateaus(plateaus)?)
    }
    pub fn binding_count(&self) -> usize {
        self.bindings.iter().flatten().count()
    }
    pub fn lease_count(&self) -> usize {
        self.leases.iter().flatten().count()
    }

    pub fn register_link(
        &mut self,
        interface: InterfaceKey,
        mtu: u32,
        receive: ReceiveCapabilities,
        forwarding: Forwarding,
    ) -> Result<IngressContext, Error> {
        if receive.max_ip_packet < 20 || receive.max_ip_packet > 65575 {
            return Err(Error::Unsupported);
        }
        let slot = self
            .ports
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let link = self.paths.register_link(interface, mtu)?;
        self.ports[slot] = Some(Port {
            link,
            receive,
            forwarding,
        });
        Ok(IngressContext { link })
    }
    fn port(&self, link: LinkId) -> Result<Port, Error> {
        self.paths.link(link)?;
        self.ports
            .iter()
            .flatten()
            .find(|port| port.link == link)
            .copied()
            .ok_or(Error::InvalidContext)
    }
    pub fn receive_capabilities(
        &self,
        context: IngressContext,
    ) -> Result<ReceiveCapabilities, Error> {
        Ok(self.port(context.link)?.receive)
    }
    pub fn ingress_context(&self, link: LinkId) -> Result<IngressContext, Error> {
        self.port(link)?;
        Ok(IngressContext { link })
    }
    pub fn remove_link(&mut self, context: IngressContext) -> Result<(), Error> {
        self.port(context.link)?;
        self.paths.remove_link(context.link)?;
        let slot = self
            .ports
            .iter()
            .position(|p| p.is_some_and(|p| p.link == context.link))
            .unwrap();
        self.ports[slot] = None;
        Ok(())
    }
    pub fn attach(&mut self, endpoint: &mut Endpoint) -> Result<(), Error> {
        if self.attached || self.timebase != endpoint.caller_timebase() {
            return Err(Error::InvalidContext);
        }
        endpoint.enable_managed_paths(self.paths.context())?;
        self.attached = true;
        Ok(())
    }
    fn check_endpoint(&self, endpoint: &Endpoint) -> Result<(), Error> {
        if endpoint.managed_context() != Some(self.paths.context()) {
            return Err(Error::InvalidContext);
        }
        Ok(())
    }
    fn forwarding(&self, snapshot: PathSnapshot) -> Result<Port, Error> {
        self.paths.validate_selection(snapshot.key())?;
        if snapshot.key().destination().address().is_ipv6() && snapshot.first_hop_mtu() < 1280 {
            return Err(Error::Unsupported);
        }
        let port = self.port(snapshot.key().link())?;
        match (port.forwarding, snapshot.key().next_hop()) {
            (Forwarding::Forwarder(a), ResolvedNextHop::Forwarder(b)) if a == b => Ok(port),
            (Forwarding::IpNextHop, ResolvedNextHop::Address(_)) => Ok(port),
            _ => Err(Error::Unsupported),
        }
    }
    fn request(
        &self,
        source: IpAddr,
        destination: IpAddr,
        dscp: Dscp,
    ) -> Result<PathRequest, Error> {
        // Endpoint's current tuple contract rejects scoped socket addresses;
        // the canonical service still supports scoped identities independently.
        // An unregistered source is missing local authority, not a missing
        // route: NoRoute is reserved for forwarding selection from a source
        // this host owns.
        let source = self
            .paths
            .sources()
            .find(|(_, address)| address.address() == source && address.zone().is_none())
            .map(|(id, _)| id)
            .ok_or(path::Error::SourceNotOwned)?;
        Ok(PathRequest {
            source,
            destination: ScopedAddress::new(destination, None)?,
            dscp,
        })
    }
    pub fn binding(&self, owner: ConnectionId) -> Result<PreparedPath, Error> {
        self.bindings
            .iter()
            .flatten()
            .find(|b| b.owner == Some(owner))
            .map(|b| b.prepared)
            .ok_or(Error::InvalidContext)
    }

    /// Explicit trusted negative evidence, with RFC hold in the configured
    /// caller timebase. Re-reading/equal reports do not restart the deadline.
    /// Larger TCP probe proof stays connection-local: T10 must add validated
    /// positive publication before this shared ordinary ceiling can rise.
    pub fn trusted_decrease(
        &mut self,
        now: Instant,
        path: path::PathId,
        mtu: u32,
    ) -> Result<path::EstimateChange, Error> {
        let not_before = now
            .checked_add(
                self.timebase
                    .units_per_second
                    .checked_mul(600)
                    .ok_or(Error::Capacity)?,
            )
            .ok_or(Error::Capacity)?;
        Ok(self
            .paths
            .trusted_decrease_with_hold(path, mtu, not_before)?)
    }

    /// Apply one newest snapshot then acknowledge exactly that observation.
    /// Failure (including capacity during rebind) keeps the dirty notification.
    pub fn refresh(
        &mut self,
        endpoint: &mut Endpoint,
        owner: ConnectionId,
    ) -> Result<PreparedPath, Error> {
        self.check_endpoint(endpoint)?;
        let index = self
            .bindings
            .iter()
            .position(|b| b.is_some_and(|b| b.owner == Some(owner)))
            .ok_or(Error::InvalidContext)?;
        let current = endpoint.managed_path(owner)?;
        let mut binding = self.bindings[index].unwrap();
        if current.binding.client != binding.prepared.client {
            return Err(Error::InvalidContext);
        }
        let via = ScopedAddress::new(current.forwarding_destination, None)?;
        let mut snapshot = self.paths.snapshot(binding.prepared.client)?;
        // A validated peer return-route update need not invalidate the old
        // routing entry, so compare the actual outgoing selection as well.
        if snapshot.status() != PathStatus::Valid || snapshot.key().forwarding_destination() != via
        {
            let request = self.request(
                snapshot.key().source_address().address(),
                snapshot.key().destination().address(),
                snapshot.key().dscp(),
            )?;
            let resolved = self.paths.resolve_via(request, via)?;
            self.forwarding_resolved(resolved.key())?;
            let (client, rebound) = self
                .paths
                .rebind_via(binding.prepared.client, request, via)?;
            binding.prepared = PreparedPath {
                client,
                snapshot: rebound,
            };
            self.bindings[index] = Some(binding);
            snapshot = rebound;
        }
        self.forwarding(snapshot)?;
        let prepared = PreparedPath {
            client: binding.prepared.client,
            snapshot,
        };
        endpoint.apply_path_budget(owner, prepared)?;
        self.bindings[index].as_mut().unwrap().prepared = prepared;
        self.paths.acknowledge(prepared.client, snapshot.stamp())?;
        Ok(prepared)
    }

    /// Atomic live routing-class change. Callers serialize socket-policy state
    /// with this operation; failed capacity/route checks leave both authorities
    /// unchanged. Held attempts must first obtain a nonsubmission certificate.
    pub fn rebind_dscp(
        &mut self,
        endpoint: &mut Endpoint,
        owner: ConnectionId,
        dscp: u8,
    ) -> Result<(), Error> {
        self.check_endpoint(endpoint)?;
        if endpoint.is_output_reserved(owner) {
            return Err(EndpointError::OutputReserved.into());
        }
        let old = endpoint.managed_path(owner)?;
        let binding = self.binding(owner)?;
        if binding.client != old.binding.client {
            return Err(Error::InvalidContext);
        }
        let mut request = binding.snapshot.key().request();
        request.dscp = Dscp::new(dscp)?;
        let via = ScopedAddress::new(old.forwarding_destination, None)?;
        let resolved = self.paths.resolve_via(request, via)?;
        self.forwarding_resolved(resolved.key())?;
        let (client, snapshot) = self.paths.rebind_via(binding.client, request, via)?;
        let prepared = PreparedPath { client, snapshot };
        // The same source/destination/context was preflighted above. Core's
        // application does no allocation and permits this exact rebind.
        endpoint
            .apply_path_budget(owner, prepared)
            .expect("preflighted path rebind");
        let record = self
            .bindings
            .iter_mut()
            .flatten()
            .find(|b| b.owner == Some(owner))
            .unwrap();
        record.prepared = prepared;
        self.paths.acknowledge(client, snapshot.stamp())?;
        Ok(())
    }

    /// Bounded sweep also visits detached/released generations. No fd/accept
    /// lifetime participates. Reserved output pins its owner independently.
    pub fn refresh_all(&mut self, endpoint: &mut Endpoint) -> Result<(), Error> {
        self.collect(endpoint)?;
        let mut first = None;
        for index in 0..self.bindings.len() {
            if let Some(owner) = self.bindings[index].and_then(|b| b.owner)
                && let Err(error) = self.refresh(endpoint, owner)
            {
                first.get_or_insert(error);
            }
        }
        first.map_or(Ok(()), Err)
    }
    pub fn collect(&mut self, endpoint: &Endpoint) -> Result<(), Error> {
        self.check_endpoint(endpoint)?;
        for binding in &mut self.bindings {
            if binding.is_some_and(|b| {
                b.owner.is_some_and(|id| {
                    !endpoint.connection_exists(id) && !endpoint.is_output_reserved(id)
                })
            }) {
                self.paths
                    .release(binding.take().unwrap().prepared.client)?;
            }
        }
        for lease in &mut self.leases {
            if lease.is_some_and(|l| endpoint.transmit_attempt_packet(l.attempt).is_none()) {
                self.paths.release(lease.take().unwrap().prepared.client)?;
            }
        }
        Ok(())
    }

    pub fn decode_ingress<'a>(
        &self,
        context: IngressContext,
        frame: &'a [u8],
    ) -> Result<IngressPacket<'a>, Error> {
        let capabilities = self.port(context.link)?.receive;
        if frame.len() > capabilities.max_ip_packet {
            return Err(Error::Unsupported);
        }
        let packet = match frame.first().ok_or(ntcp_ip::Error::Truncated)? >> 4 {
            4 => {
                let source_routes = match capabilities.ipv4 {
                    Ipv4Receive::Disabled => return Err(Error::Unsupported),
                    Ipv4Receive::Unrecognized => false,
                    Ipv4Receive::Options { source_routes } => source_routes,
                };
                let packet = ntcp_ip::parse(frame, source_routes)?;
                IngressPacket {
                    ip: packet.ip,
                    traffic_class: packet.traffic_class,
                    protocol: packet.protocol,
                    options: if capabilities.ipv4 == Ipv4Receive::Unrecognized {
                        packet.ipv4_options.unrecognized()
                    } else {
                        packet.ipv4_options
                    },
                    payload: packet.payload,
                }
            }
            6 if capabilities.ipv6 == Ipv6Receive::BaseHeader => {
                let packet = ntcp_ip6::parse(frame)?;
                IngressPacket {
                    ip: packet.ip,
                    traffic_class: packet.traffic_class,
                    protocol: packet.protocol,
                    options: Ipv4Options::default(),
                    payload: packet.payload,
                }
            }
            _ => return Err(Error::Unsupported),
        };
        let zone = match packet.ip.destination {
            IpAddr::V6(v) if v.is_unicast_link_local() => Some(context.link),
            _ => None,
        };
        self.paths.local_source(
            ScopedAddress::new(packet.ip.destination, zone)?,
            context.link,
        )?;
        Ok(packet)
    }

    /// Complete outer metadata is validated before dispatch. Quoted options
    /// remain historical data inside the ICMP decoder and are never recorded
    /// as present-day destination options. Timestamp recording, when requested,
    /// is the caller's explicit low-level clock contract, not a UTC guarantee.
    #[allow(clippy::too_many_arguments)]
    pub fn input_ip(
        &mut self,
        endpoint: &mut Endpoint,
        context: IngressContext,
        now: Instant,
        frame: &[u8],
        metadata: RxPacketMetadata,
        outgoing_dscp: u8,
        timestamp: Option<u32>,
    ) -> Result<ntcp::InputDisposition, Error> {
        self.check_endpoint(endpoint)?;
        let packet = self.decode_ingress(context, frame)?;
        if metadata.tcp_segment_size.is_some() && !self.port(context.link)?.receive.gro {
            return Err(Error::Unsupported);
        }
        if packet.protocol == 6 {
            // Bindings cover every Endpoint slot plus one provisional factory,
            // so a full table can only hold generations this embedding has not
            // yet collected. Reclaim them before a factory needs one, rather
            // than reporting admissible input as a capacity failure.
            if self.bindings.iter().all(Option::is_some) {
                self.collect(endpoint)?;
            }
            let mut options = packet.options;
            if let (Some(timestamp), IpAddr::V4(local)) = (timestamp, packet.ip.destination) {
                // Failure to record a received option invalidates this packet,
                // not the embedding. In particular a full Timestamp option
                // with overflow 15 cannot be advanced any further.
                let Ok(recorded) = options.record(local, timestamp) else {
                    return Ok(ntcp::InputDisposition::Dropped);
                };
                options = recorded;
            }
            Ok(endpoint.input_with_path_provider(
                now,
                packet.ip,
                packet.traffic_class,
                options,
                packet.payload,
                metadata,
                outgoing_dscp,
                self,
            )?)
        } else if packet.protocol == if packet.ip.source.is_ipv4() { 1 } else { 58 } {
            let feedback = ntcp_icmp::decode_icmp(frame)?;
            // RFC 6633: discard after wire validation, before tuple lookup,
            // clock advancement or any access to a possibly reserved owner.
            if feedback.kind == ntcp_icmp::FeedbackKind::SourceQuench {
                return Ok(ntcp::InputDisposition::Dropped);
            }
            let quote = feedback.quoted;
            let tuple = Tuple {
                local: SocketAddr::new(quote.ip.source, quote.source_port),
                remote: SocketAddr::new(quote.ip.destination, quote.destination_port),
            };
            if feedback.kind == ntcp_icmp::FeedbackKind::PacketTooBig {
                endpoint.pmtu_feedback(
                    now,
                    tuple,
                    quote.sequence,
                    quote.ip_packet_len,
                    quote.ip_header_len,
                    feedback.candidate_mtu.unwrap_or(0),
                )?;
            } else if let Some(error) = feedback
                .ipv4_network_error()
                .or_else(|| feedback.ipv6_network_error())
            {
                endpoint.network_error(now, tuple, quote.sequence, error)?;
            }
            Ok(ntcp::InputDisposition::Processed)
        } else {
            Err(Error::Unsupported)
        }
    }

    /// Obtain authority for a selected reservation. Keep this context with a
    /// blocked frame; validate_egress must run again at EVERY physical retry.
    pub fn egress_context(
        &mut self,
        endpoint: &mut Endpoint,
        attempt: TransmitAttempt,
    ) -> Result<EgressContext, Error> {
        self.check_endpoint(endpoint)?;
        let packet = endpoint
            .transmit_attempt_packet(attempt)
            .ok_or(Error::Obsolete)?;
        let binding = if let Some(owner) = packet.connection {
            self.refresh(endpoint, owner)?
        } else if let Some(index) = self
            .leases
            .iter()
            .position(|l| l.is_some_and(|l| l.attempt == attempt))
        {
            let lease = self.leases[index].unwrap();
            let mut snapshot = self.paths.snapshot(lease.prepared.client)?;
            let request = self.request(
                packet.ip.source,
                packet.ip.destination,
                Dscp::new(packet.dscp)?,
            )?;
            let via = ScopedAddress::new(wire_destination(packet), None)?;
            let prepared = if snapshot.status() != PathStatus::Valid
                || snapshot.key().request() != request
                || snapshot.key().forwarding_destination() != via
            {
                // Resolve and check the actual port before changing pins or
                // client generation. Failure leaves the held lease dirty and
                // retryable when authority/capacity is restored.
                let resolved = self.paths.resolve_via(request, via)?;
                self.forwarding_resolved(resolved.key())?;
                let (client, rebound) = self
                    .paths
                    .rebind_via(lease.prepared.client, request, via)?;
                snapshot = rebound;
                PreparedPath { client, snapshot }
            } else {
                self.forwarding(snapshot)?;
                PreparedPath {
                    client: lease.prepared.client,
                    snapshot,
                }
            };
            self.leases[index].as_mut().unwrap().prepared = prepared;
            self.paths.acknowledge(prepared.client, snapshot.stamp())?;
            prepared
        } else {
            let index = self
                .leases
                .iter()
                .position(Option::is_none)
                .ok_or(Error::Capacity)?;
            let destination = wire_destination(packet);
            let request = self.request(
                packet.ip.source,
                packet.ip.destination,
                Dscp::new(packet.dscp)?,
            )?;
            let via = ScopedAddress::new(destination, None)?;
            let resolved = self.paths.resolve_via(request, via)?;
            self.forwarding_resolved(resolved.key())?;
            let (client, snapshot) = self.paths.acquire_via(request, via)?;
            let prepared = PreparedPath { client, snapshot };
            self.leases[index] = Some(Lease { attempt, prepared });
            prepared
        };
        self.forwarding(binding.snapshot)?;
        if packet.dscp != binding.snapshot.key().dscp().value()
            || packet.ip.source != binding.snapshot.key().source_address().address()
            || packet.ip.destination != binding.snapshot.key().destination().address()
            || wire_destination(packet) != binding.snapshot.key().forwarding_destination().address()
        {
            return Err(Error::Obsolete);
        }
        Ok(EgressContext {
            link: binding.snapshot.key().link(),
            next_hop: binding.snapshot.key().next_hop(),
            binding,
            attempt,
        })
    }
    fn forwarding_resolved(&self, key: path::PathKey) -> Result<(), Error> {
        if key.destination().address().is_ipv6() && self.paths.link(key.link())?.mtu < 1280 {
            return Err(Error::Unsupported);
        }
        let port = self.port(key.link())?;
        match (port.forwarding, key.next_hop()) {
            (Forwarding::Forwarder(a), ResolvedNextHop::Forwarder(b)) if a == b => Ok(()),
            (Forwarding::IpNextHop, ResolvedNextHop::Address(_)) => Ok(()),
            _ => Err(Error::Unsupported),
        }
    }

    /// Hold exclusive authority through the synchronous backend call. The
    /// caller resolves Submitted/Rejected/WouldBlock/unknown using the existing
    /// reservation API; this bridge never invents a submission outcome.
    pub fn with_validated_egress<R>(
        &mut self,
        endpoint: &mut Endpoint,
        context: EgressContext,
        frame: &[u8],
        shared_payload_len: usize,
        submit: impl FnOnce(EgressContext) -> R,
    ) -> Result<R, Error> {
        let live = self.validate_egress(endpoint, context, frame, shared_payload_len)?;
        Ok(submit(live))
    }

    /// The frame starts at IP and contains exactly its resident bytes (no
    /// Ethernet padding). shared_payload_len is added exactly once. Software
    /// GSO calls this separately for each actual physical segment/attempt.
    pub fn validate_egress(
        &mut self,
        endpoint: &mut Endpoint,
        context: EgressContext,
        frame: &[u8],
        shared_payload_len: usize,
    ) -> Result<EgressContext, Error> {
        let live = self.egress_context(endpoint, context.attempt)?;
        let packet = endpoint
            .transmit_attempt_packet(context.attempt)
            .ok_or(Error::Obsolete)?;
        // Stateless bytes carry no local delivery/probe proof to transfer.
        // Revalidate them under the replacement lease rather than stranding
        // the independent control lane after route/source replacement.
        if packet.connection.is_some()
            && (live.binding.client != context.binding.client
                || live.binding.snapshot.path() != context.binding.snapshot.path()
                || live.link != context.link
                || live.next_hop != context.next_hop)
        {
            return Err(Error::Obsolete);
        }
        let (ip, header, total, protocol) = if packet.ip.source.is_ipv4() {
            ntcp_ip::quote_header(frame)?
        } else {
            ntcp_ip6::quote_header(frame)?
        };
        let actual = frame
            .len()
            .checked_add(shared_payload_len)
            .ok_or(Error::Capacity)?;
        let class = if packet.ip.source.is_ipv4() {
            frame[1]
        } else {
            (frame[0] << 4) | (frame[1] >> 4)
        };
        let expected_header = if let (IpAddr::V4(source), IpAddr::V4(destination)) =
            (packet.ip.source, packet.ip.destination)
        {
            20 + packet
                .ipv4_options
                .encode(source, destination, 0, &mut [0; 40])
                .map_err(|e| Error::Endpoint(EndpointError::Ipv4Options(e)))?
                .1
        } else {
            40
        };
        let actual_destination = if packet.ip.source.is_ipv4() {
            IpAddr::V4(core::net::Ipv4Addr::new(
                frame[16], frame[17], frame[18], frame[19],
            ))
        } else {
            ip.destination
        };
        if actual_destination
            != live
                .binding
                .snapshot
                .key()
                .forwarding_destination()
                .address()
            || protocol != 6
            || ip != packet.ip
            || actual != total
            || total != packet.len + expected_header
            || header != expected_header
            || Dscp::from_traffic_class(class).value() != packet.dscp
            || (class & 3) != packet.ecn
            || total as u32 > live.binding.snapshot.first_hop_mtu()
        {
            return Err(Error::Obsolete);
        }
        let ordinary = if let Some(owner) = packet.connection {
            endpoint
                .managed_path(owner)?
                .ordinary_ip_budget
                .min(live.binding.snapshot.ip_packet_budget()?)
        } else {
            live.binding.snapshot.ip_packet_budget()?
        };
        if total as u32 > ordinary {
            let intent = endpoint
                .transmit_discovery_intent(context.attempt)
                .ok_or(Error::Obsolete)?;
            let selected = intent.binding();
            if (packet.ip.source.is_ipv4() && frame[6] & 0x40 == 0)
                || selected.client != live.binding.client
                || selected.snapshot.path() != live.binding.snapshot.path()
                || selected.snapshot.negative_revision()
                    != live.binding.snapshot.negative_revision()
                || intent.selected_at() < live.binding.snapshot.retry_not_before()
                || intent.ip_packet_len() != total as u32
            {
                return Err(Error::Obsolete);
            }
        }
        Ok(live)
    }
}

fn wire_destination(packet: Transmit) -> IpAddr {
    packet
        .ipv4_options
        .source_route
        .and_then(|r| r.hops().first().copied())
        .map(IpAddr::V4)
        .unwrap_or(packet.ip.destination)
}

impl PathProvider for Host {
    type Error = Error;
    //= https://www.rfc-editor.org/rfc/rfc1191#section-3.1
    //= reason=Host acquires canonical IP path authority before TCP construction, and native/TUN factories use that budget before first output. Physical submission validates current path authority and complete IP size; transport MSS, buffers and local discovery remain independent. Dual-family first-SYN/hidden-SYNACK and framed-stream tests exercise the handoff. Generic validated ICMP publication and cross-protocol fanout are separate T9/T10 obligations.
    //# Some TCP implementations send an MSS option only if the destination host is on a non-connected network. However, in general the TCP layer may not have the appropriate information to make this decision, so it is preferable to leave to the IP layer the task of determining a suitable MTU for the Internet path.
    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
    //= reason=Managed factories acquire per-host records from configured network/default routes before TCP construction, initializing unlearned budgets from the physical first hop. Trusted decreases change only per-host learned estimates, preserving forwarding routes and independent first-hop facts. Dual-family two-Endpoint tests exercise both route selections, first SYN/hidden child and later decreases without forwarding-route mutation. Generic ICMP publication remains the separate 1191-057 obligation.
    //# When the first packet is sent to a host for which no per-host route exists, a route is chosen either from the set of per-network routes, or from the set of default routes. The PMTU fields in these route entries should be initialized to be the MTU of the associated first-hop data link, and must never be changed by the PMTU Discovery process. (PMTU Discovery only creates or changes entries for per-host routes). Until a Datagram Too Big message is received, the PMTU associated with the initially-chosen route is presumed to be accurate.
    fn prepare(&mut self, request: PathFactoryRequest) -> Result<PreparedPath, Error> {
        if !self.attached {
            return Err(Error::InvalidContext);
        }
        let index = self
            .bindings
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let destination = request
            .ipv4_options
            .source_route
            .and_then(|r| r.hops().first().copied())
            .map(IpAddr::V4)
            .unwrap_or(request.tuple.remote.ip());
        let request = self.request(
            request.tuple.local.ip(),
            request.tuple.remote.ip(),
            request.dscp,
        )?;
        let via = ScopedAddress::new(destination, None)?;
        let resolved = self.paths.resolve_via(request, via)?;
        self.forwarding_resolved(resolved.key())?;
        let (client, snapshot) = self.paths.acquire_via(request, via)?;
        let prepared = PreparedPath { client, snapshot };
        self.bindings[index] = Some(Binding {
            owner: None,
            prepared,
        });
        Ok(prepared)
    }
    fn commit(&mut self, prepared: PreparedPath, connection: ConnectionId) {
        let binding = self
            .bindings
            .iter_mut()
            .flatten()
            .find(|b| b.owner.is_none() && b.prepared == prepared)
            .expect("prepared binding preflight");
        binding.owner = Some(connection);
    }
    fn cancel(&mut self, prepared: PreparedPath) {
        let index = self
            .bindings
            .iter()
            .position(|b| b.is_some_and(|b| b.owner.is_none() && b.prepared == prepared))
            .expect("prepared binding preflight");
        self.paths
            .release(prepared.client)
            .expect("live provisional client");
        self.bindings[index] = None;
    }
}

#[cfg(test)]
mod tests;
