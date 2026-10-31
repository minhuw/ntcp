#![no_std]

extern crate alloc;
use alloc::vec::Vec;
use core::net::IpAddr;
use ntcp::{
    ConnectionId, CorrelatedPmtu, CorrelatedSegment, Endpoint, EndpointConfig, EndpointError,
    Instant, IpMetadata, Ipv4Options, ManagedError, NetworkError, PathFactoryRequest, PathProvider,
    PmtuFeedback, PreparedPath, RxPacketMetadata, Transmit, TransmitAttempt,
};
use ntcp_icmp::{FeedbackKind, QuotedTransport};
pub use ntcp_path as path;
mod ledger;
use ledger::Ledger;
pub use ledger::{
    Correlation, Evidence, LedgerLimits, Owner, QuoteKey, QuotedSelector, Record, Selector,
    feedback_horizon,
};
mod udp;
use path::{
    ContextId, Dscp, ForwarderId, InterfaceKey, LinkId, PathRequest, PathService, PathSnapshot,
    PathStatus, ResolvedNextHop, ScopedAddress,
};
use udp::Udp;
pub use udp::{
    UdpEgress, UdpEvent, UdpFlowId, UdpLimits, UdpOptions, UdpSendError, UdpSent,
    managed_udp_limits,
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
    pub ledger: LedgerLimits,
    /// Datagram flows; none unless added by `managed_udp_limits`.
    pub udp: UdpLimits,
}

/// Storage rationale: all occupied transport generations, one provisional
/// factory (including TIME-WAIT replacement), the Endpoint's single independent
/// stateless reservation lane when control output is enabled, and explicitly
/// requested migration headroom. Connection-associated final output uses its
/// retained binding. Every sum is checked; source/link/route capacities are
/// configured authority.
///
/// Submission ledger: one owner record per binding and per stateless lane, so
/// every live generation is admitted without waiting. Each owner keeps one
/// entry per full-sized segment its configured send buffer can hold
/// outstanding, plus one for the control segment (SYN/FIN/pure ACK) that may
/// accompany it. A connection configured with a larger send buffer extends
/// its own history the same way before its next physical call (fallibly,
/// freed with its record); smaller segments after a decrease, or a failed
/// extension, overflow into same-owner eviction (which preserves ambiguity
/// in a summary that delivery shrinks, and never blocks output). Concurrent unsealed attempts equal
/// the largest Endpoint output pool (max_connections + 1), each holding one
/// physical attempt. The horizon is twice the configured MSL.
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
    let mss = usize::from(config.connection.mss.max(1));
    let history_per_owner = config
        .connection
        .send_capacity
        .div_ceil(mss)
        .checked_add(1)
        .ok_or(Error::Capacity)?;
    let ledger = LedgerLimits {
        owners: bindings.checked_add(output_leases).ok_or(Error::Capacity)?,
        history_per_owner,
        segment_bytes: mss,
        concurrent_attempts: bindings,
        datagram_evidence: 0,
        feedback_horizon: feedback_horizon(config.connection.timebase).ok_or(Error::Capacity)?,
    };
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
            ledger,
            udp: UdpLimits::default(),
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

/// Opaque authority over the evidence reserved for one physical attempt (or
/// one pre-reserved aggregate). It cannot be cloned, so an outcome is
/// finalized at most once: Submitted and Unknown seal it, a certified
/// non-submission cancels it, WouldBlock and a retained rejection return it.
#[must_use = "an unresolved ticket keeps its evidence reservation"]
#[derive(Debug, Eq, PartialEq)]
pub struct SubmissionTicket {
    ticket: u64,
}

/// The backend's own statement about one synchronous physical call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendOutcome {
    /// Handed to the link.
    Submitted,
    /// Certainly not submitted; retry the same attempt later.
    WouldBlock,
    /// Certainly not submitted and not retried (the caller then certifies the
    /// Endpoint side, e.g. abandon_transmit or reject_local_output).
    NotSubmitted,
    /// Certainly not submitted; the caller retains the reservation through
    /// Endpoint::reject_unsubmitted and the next attempt reuses this ticket.
    Rejected,
    /// The call may have reached the link (timeout, asynchronous error).
    Unknown,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Submission {
    /// Sealed once and accepted by the Endpoint.
    Submitted,
    Blocked(SubmissionTicket),
    Rejected(SubmissionTicket),
    Cancelled,
    /// Sealed as possibly submitted; the Endpoint attempt is left untouched
    /// for the caller's existing quarantine (never retried, never cancelled
    /// as unsent, never accepted as success).
    PossiblySubmitted,
}

/// No backend call happened; the ticket is returned unchanged.
#[derive(Debug, Eq, PartialEq)]
pub struct Refused {
    pub error: Error,
    pub ticket: SubmissionTicket,
}

/// Why a wire-valid ICMP error had no effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IcmpDiscard {
    /// RFC 6633: discarded after wire validation, before correlation.
    SourceQuench,
    /// No live or remembered submission matches the quote.
    Uncorrelated,
    /// Matches more than one owner generation or submission (tombstones
    /// included), or disagree on the path for a path-level report.
    Ambiguous,
    /// A link-scoped quoted source arrived on another link.
    LinkScope,
    /// The owner generation no longer exists (or changed before a replay).
    Stale,
    /// Impossible report: below the family minimum or no smaller than the
    /// packet it claims to have dropped.
    Implausible,
}

/// TCP policy's disposition of a correlated report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpReport {
    PacketTooBig(PmtuFeedback),
    NetworkError { error: NetworkError, accepted: bool },
}

/// Host-validated advice for an owner without TCP policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Advice {
    /// `mtu` is the validated reported next-hop MTU, None from an IPv4
    /// router that reported none; `dropped_len` is the complete length of
    /// the submitted packet. Any shared decrease is reported separately.
    PacketTooBig {
        mtu: Option<u32>,
        dropped_len: u32,
    },
    NetworkError(NetworkError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IcmpOutcome {
    Discarded(IcmpDiscard),
    /// `published` is present only when TCP accepted an immediate decrease
    /// about its current path and the Host then published it.
    Tcp {
        owner: ConnectionId,
        report: TcpReport,
        published: Option<path::EstimateChange>,
    },
    /// Datagram or stateless submissions; `owner` is None for a path-level
    /// report whose matches agree on the path but not on one submission.
    Advice {
        owner: Option<Owner>,
        advice: Advice,
        published: Option<path::EstimateChange>,
    },
}

/// An ICMP error for a TCP owner whose output is reserved. Nothing was
/// applied or published; retain the frame and replay it with
/// `Host::replay_icmp` once the reservation resolves. The replay is
/// revalidated from the frame and acts only for this exact generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeferredIcmp {
    context: IngressContext,
    owner: ConnectionId,
}
impl DeferredIcmp {
    pub const fn context(self) -> IngressContext {
        self.context
    }
    pub const fn owner(self) -> ConnectionId {
        self.owner
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IcmpDispatch {
    Completed(IcmpOutcome),
    Deferred(DeferredIcmp),
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
    ledger: Ledger,
    udp: Udp,
    // Latest caller time seen by a submission or collection; only used to
    // skip burying history that has already expired.
    now: Instant,
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
            .and_then(|n| n.checked_add(limits.udp.flows))
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
            ledger: Ledger::new(limits.ledger)?,
            udp: Udp::new(limits.udp)?,
            now: 0,
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
        Ok(PathRequest {
            source: self.source(source)?,
            destination: ScopedAddress::new(destination, None)?,
            dscp,
        })
    }
    fn source(&self, address: IpAddr) -> Result<path::SourceId, Error> {
        Ok(self
            .paths
            .sources()
            .find(|(_, a)| a.address() == address && a.zone().is_none())
            .map(|(id, _)| id)
            .ok_or(path::Error::SourceNotOwned)?)
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
        self.maintain_ledger(endpoint);
        Ok(())
    }

    // Advance the ledger's view of time and drop expired evidence now.
    // Production expiry needs no call: `collect` sweeps it and correlation
    // ignores expired evidence lazily.
    #[cfg(test)]
    pub(crate) fn expire_submissions(&mut self, now: Instant) {
        self.now = self.now.max(now);
        self.ledger.expire(self.now);
    }

    // Retire delivered TCP data, reclaim reservations no call can use, and
    // release owner records of generations that no longer exist (their
    // history becomes tombstones until the feedback horizon).
    fn maintain_ledger(&mut self, endpoint: &Endpoint) {
        for index in 0..self.ledger.pending_len() {
            let Some(pending) = self.ledger.pending(index) else {
                continue;
            };
            let Some(attempt) = pending.attempt else {
                continue;
            };
            let retained = pending.issued
                && match self.ledger.owner(pending.owner) {
                    Some(Owner::Tcp(id)) => endpoint.is_output_reserved(id),
                    _ => false,
                };
            if endpoint.transmit_attempt_packet(attempt).is_none() && !retained {
                self.ledger.drop_pending(index);
            }
        }
        for index in 0..self.ledger.limits().owners {
            match self.ledger.owner(index) {
                Some(Owner::Tcp(id)) if endpoint.connection_exists(id) => {
                    if let Ok(progress) = endpoint.send_progress(id) {
                        self.ledger.retire_tcp(id, progress.unacknowledged_sequence);
                    }
                }
                Some(Owner::Tcp(id)) if !endpoint.is_output_reserved(id) => {
                    self.ledger.release_owner(index, self.now);
                }
                _ => {}
            }
        }
        self.ledger.expire(self.now);
    }

    // Idempotent: one reservation per physical attempt. Owner admission is
    // the only owner-level backpressure; dead generations are released first.
    fn reserve_attempt(
        &mut self,
        endpoint: &Endpoint,
        owner: Owner,
        attempt: TransmitAttempt,
    ) -> Result<usize, Error> {
        let index = match self.ledger.admit(owner) {
            Ok(index) => index,
            Err(Error::Capacity) => {
                self.maintain_ledger(endpoint);
                self.ledger.admit(owner)?
            }
            Err(error) => return Err(error),
        };
        if let Owner::Tcp(id) = owner
            && let Ok(capacity) = endpoint.send_capacity(id)
        {
            self.ledger.provision(index, capacity);
        }
        let stale = |a| endpoint.transmit_attempt_packet(a).is_none();
        match self.ledger.reserve(index, attempt, stale) {
            Err(Error::Capacity) => {
                self.maintain_ledger(endpoint);
                self.ledger.reserve(index, attempt, stale)
            }
            result => result,
        }
    }

    /// Decode with transport ingress ownership: the destination must be a
    /// source registered on the arrival link itself.
    pub fn decode_ingress<'a>(
        &self,
        context: IngressContext,
        frame: &'a [u8],
    ) -> Result<IngressPacket<'a>, Error> {
        let packet = self.parse_ingress(context, frame)?;
        self.owned_on_link(context, packet.ip.destination)?;
        Ok(packet)
    }
    fn owned_on_link(&self, context: IngressContext, destination: IpAddr) -> Result<(), Error> {
        let zone = match destination {
            IpAddr::V6(v) if v.is_unicast_link_local() => Some(context.link),
            _ => None,
        };
        self.paths
            .local_source(ScopedAddress::new(destination, zone)?, context.link)?;
        Ok(())
    }
    // ICMP errors about our own submissions may return over any registered
    // link of this context (asymmetric routing). That admits the error only;
    // the outgoing link is never inferred from arrival, and correlation still
    // requires the original submission. A link-scoped destination stays bound
    // to its own link.
    fn owned_in_context(&self, context: IngressContext, destination: IpAddr) -> Result<(), Error> {
        if matches!(destination, IpAddr::V6(v) if v.is_unicast_link_local()) {
            return self.owned_on_link(context, destination);
        }
        let address = ScopedAddress::new(destination, None)?;
        if self
            .ports
            .iter()
            .flatten()
            .any(|port| self.paths.local_source(address, port.link).is_ok())
        {
            Ok(())
        } else {
            Err(path::Error::NoRoute.into())
        }
    }
    fn parse_ingress<'a>(
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
        let packet = self.parse_ingress(context, frame)?;
        if is_icmp(&packet) {
            // One dispatcher for every embedding. A reserved owner keeps this
            // entrypoint's established OutputReserved contract, with nothing
            // applied or published; callers that retain frames use input_icmp.
            return match self.input_icmp(endpoint, context, now, frame)? {
                IcmpDispatch::Deferred(_) => Err(EndpointError::OutputReserved.into()),
                IcmpDispatch::Completed(IcmpOutcome::Discarded(IcmpDiscard::SourceQuench)) => {
                    Ok(ntcp::InputDisposition::Dropped)
                }
                IcmpDispatch::Completed(_) => Ok(ntcp::InputDisposition::Processed),
            };
        }
        self.owned_on_link(context, packet.ip.destination)?;
        if metadata.tcp_segment_size.is_some() && !self.port(context.link)?.receive.gro {
            return Err(Error::Unsupported);
        }
        if packet.protocol == ntcp_ip::PROTOCOL_UDP && metadata.tcp_segment_size.is_none() {
            return Ok(self.input_udp(endpoint, &packet));
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
        } else {
            Err(Error::Unsupported)
        }
    }

    /// The single ICMP classification/dispatch path. The error is admitted on
    /// any registered link of this context when its destination is an
    /// unscoped registered source, then correlated with the submission ledger
    /// (context, family, canonical source/final destination, complete header
    /// and packet lengths, protocol and transport selector). Quoted TTL/hop
    /// limit, ECN, DSCP and IPv4 identification are not compared: routers may
    /// rewrite the first three, and an atomic datagram's identification
    /// carries no meaning (RFC 6864 section 4.1). Options were validated
    /// structurally by the codec, not compared with historical bytes.
    ///
    /// Correlation is plausibility against off-path forgery, not
    /// authentication: an attacker holding the exact quote can still act as
    /// the router that sent it. Policy: only exact evidence (a live entry or
    /// exact evicted-datagram signature matching every selector field) is
    /// positive; lossy history only denies. Path-level effects require an
    /// exact match and every match and lossy hit to agree on one path
    /// incarnation; owner-level effects require one owner generation and one
    /// submission (TCP: one span), with no lossy hit. A TCP owner's policy runs first and a shared decrease
    /// is published only for its immediate, current-path decrease (never for
    /// Deferred). A reserved owner is returned as Deferred before anything is
    /// applied. Unmatched quotes are discarded; there is no fallback to the
    /// connection-local sent ring.
    pub fn input_icmp(
        &mut self,
        endpoint: &mut Endpoint,
        context: IngressContext,
        now: Instant,
        frame: &[u8],
    ) -> Result<IcmpDispatch, Error> {
        self.dispatch_icmp(endpoint, context, now, frame, None)
    }

    /// Replay a retained frame for its deferred owner generation. Everything
    /// is revalidated (ingress, wire, correlation); if the quote no longer
    /// identifies that exact generation, the frame is discarded as Stale.
    pub fn replay_icmp(
        &mut self,
        endpoint: &mut Endpoint,
        deferred: DeferredIcmp,
        now: Instant,
        frame: &[u8],
    ) -> Result<IcmpDispatch, Error> {
        self.dispatch_icmp(endpoint, deferred.context, now, frame, Some(deferred.owner))
    }

    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.2
    //= reason=The Host dispatcher notifies the specific correlated sender while processing the report: TCP consumes PmtuFeedback drop advice and a Host UDP flow receives UdpEvent::PacketTooBig, whether or not the estimate changes. Path-level change notification is separate: a shared decrease only marks path clients dirty, and other users adopt it at their next egress refresh or send-budget check. Dual-family TUN tests consume the UDP event immediately and observe the TCP flow adopt the shared decrease at its next egress.
    //# It is important to understand that the notification of the packetization
    //# layer instances using the path about the change in the PMTU is distinct from
    //# the notification of a specific instance that a packet has been dropped. The
    //# latter should be done as soon as practical (i.e., asynchronously from the
    //# point of view of the packetization layer instance), while the former may be
    //# delayed until a packetization layer instance wants to create a packet.
    fn dispatch_icmp(
        &mut self,
        endpoint: &mut Endpoint,
        context: IngressContext,
        now: Instant,
        frame: &[u8],
        expected: Option<ConnectionId>,
    ) -> Result<IcmpDispatch, Error> {
        use IcmpDispatch::Completed;
        use IcmpOutcome::Discarded;
        self.check_endpoint(endpoint)?;
        let packet = self.parse_ingress(context, frame)?;
        if !is_icmp(&packet) {
            return Err(Error::Unsupported);
        }
        self.owned_in_context(context, packet.ip.destination)?;
        let feedback = ntcp_icmp::decode_icmp_quote(frame)?;
        // RFC 6633: after wire validation, before correlation, clock
        // advancement or any access to a possibly reserved owner.
        if feedback.kind == FeedbackKind::SourceQuench {
            return Ok(Completed(Discarded(IcmpDiscard::SourceQuench)));
        }
        self.now = self.now.max(now);
        let quote = feedback.quoted;
        let key = QuoteKey {
            source: quote.ip.source,
            destination: quote.ip.destination,
            header_len: quote.ip_header_len,
            packet_len: quote.ip_packet_len,
            protocol: quote.protocol,
            transport: match quote.transport {
                QuotedTransport::Tcp {
                    source_port,
                    destination_port,
                    sequence,
                } => QuotedSelector::Tcp {
                    source_port,
                    destination_port,
                    sequence,
                },
                QuotedTransport::Udp {
                    source_port,
                    destination_port,
                    length,
                    checksum,
                } => QuotedSelector::Udp {
                    source_port,
                    destination_port,
                    length,
                    checksum,
                },
                QuotedTransport::Other => QuotedSelector::Other,
            },
        };
        let ptb = feedback.kind == FeedbackKind::PacketTooBig;
        let candidate = feedback.candidate_mtu;
        let exact = self.ledger.correlate(now, &key);
        // The dropped packet's complete length under each matching reading.
        let mut dropped = (exact.matches != 0).then_some(key.packet_len);
        let mut correlation = exact;
        //= https://www.rfc-editor.org/rfc/rfc1191#section-5
        //# If the Total Length field returned is
        //# not less than the current PMTU estimate, it must be reduced by
        //# 4 times the value of the returned Header Length field.
        // A legacy router without a next-hop MTU may have returned the Total
        // Length inflated by the header length; both readings correlate, and
        // matches under both are ambiguous.
        if ptb
            && quote.ip.source.is_ipv4()
            && candidate.is_none()
            && let Some(packet_len) = key
                .packet_len
                .checked_sub(u32::from(key.header_len))
                .filter(|len| *len >= u32::from(key.header_len) + 20)
        {
            let corrected = self.ledger.correlate(now, &QuoteKey { packet_len, ..key });
            if corrected.matches != 0 {
                dropped = Some(dropped.map_or(packet_len, |len| len.min(packet_len)));
            }
            correlation = correlation.either(corrected);
        }
        let Some(dropped) = dropped else {
            return Ok(Completed(Discarded(IcmpDiscard::Uncorrelated)));
        };
        let scoped = matches!(quote.ip.source, IpAddr::V6(v) if v.is_unicast_link_local());
        if scoped
            && correlation
                .owner
                .is_none_or(|r| r.evidence.link != context.link)
        {
            return Ok(Completed(Discarded(IcmpDiscard::LinkScope)));
        }
        let error = if ptb {
            None
        } else {
            // Every other decoded kind classifies for its family.
            let Some(error) = feedback
                .ipv4_network_error()
                .or_else(|| feedback.ipv6_network_error())
            else {
                return Ok(Completed(Discarded(IcmpDiscard::Implausible)));
            };
            Some(error)
        };
        let ipv4 = quote.ip.source.is_ipv4();
        let Some(record) = correlation.owner else {
            // Only a non-TCP PTB can act at the path level alone: a TCP quote
            // needs its connection's policy before anything is published.
            if let (true, Some(path), false) = (
                ptb,
                correlation.path,
                key.protocol == ntcp_icmp::PROTOCOL_TCP,
            ) && let Some(mtu) = report_mtu(ipv4, dropped, candidate)
            {
                let published = self.publish(now, path, ipv4, &key, dropped, candidate, None)?;
                return Ok(Completed(IcmpOutcome::Advice {
                    owner: None,
                    advice: Advice::PacketTooBig {
                        mtu,
                        dropped_len: dropped,
                    },
                    published,
                }));
            }
            return Ok(Completed(Discarded(IcmpDiscard::Ambiguous)));
        };
        let evidence = record.evidence;
        let Owner::Tcp(id) = evidence.owner else {
            let advice = match error {
                Some(error) => Advice::NetworkError(error),
                None => {
                    let Some(mtu) = report_mtu(ipv4, evidence.packet_len, candidate) else {
                        return Ok(Completed(Discarded(IcmpDiscard::Implausible)));
                    };
                    Advice::PacketTooBig {
                        mtu,
                        dropped_len: evidence.packet_len,
                    }
                }
            };
            let published = match (error, correlation.path) {
                (None, Some(path)) => self.publish(
                    now,
                    path,
                    ipv4,
                    &key,
                    evidence.packet_len,
                    candidate,
                    None,
                )?,
                _ => None,
            };
            // A datagram flow consumes its advice from a bounded queue, after
            // any shared decrease is in place for its next send.
            if let Selector::Udp {
                destination_port, ..
            } = evidence.transport
            {
                let remote = core::net::SocketAddr::new(evidence.destination, destination_port);
                self.udp_advise(
                    evidence.owner,
                    match advice {
                        Advice::PacketTooBig { mtu, dropped_len } => UdpEvent::PacketTooBig {
                            remote,
                            mtu,
                            dropped_len,
                        },
                        Advice::NetworkError(error) => UdpEvent::NetworkError { remote, error },
                    },
                );
            }
            return Ok(Completed(IcmpOutcome::Advice {
                owner: Some(evidence.owner),
                advice,
                published,
            }));
        };
        if expected.is_some_and(|owner| owner != id) || !endpoint.connection_exists(id) {
            return Ok(Completed(Discarded(IcmpDiscard::Stale)));
        }
        if endpoint.is_output_reserved(id) {
            return Ok(IcmpDispatch::Deferred(DeferredIcmp { context, owner: id }));
        }
        let Selector::Tcp { start, end, .. } = evidence.transport else {
            return Ok(Completed(Discarded(IcmpDiscard::Uncorrelated)));
        };
        let segment = CorrelatedSegment {
            start,
            end,
            ip_packet_len: evidence.packet_len,
            ip_header_len: evidence.header_len,
        };
        if let Some(error) = error {
            let Some(accepted) = live(endpoint.correlated_network_error(now, id, segment, error))?
            else {
                return Ok(Completed(Discarded(IcmpDiscard::Stale)));
            };
            return Ok(Completed(IcmpOutcome::Tcp {
                owner: id,
                report: TcpReport::NetworkError { error, accepted },
                published: None,
            }));
        }
        // Only a path incarnation that is still valid and still this
        // connection's binding may change any estimate. Older submissions
        // remain drop advice for their outstanding data.
        let current = correlation.path.filter(|path| {
            self.binding(id).is_ok_and(|b| b.snapshot.path() == *path)
                && self
                    .paths
                    .path_snapshot(*path)
                    .is_ok_and(|s| s.status() == PathStatus::Valid)
        });
        let report = CorrelatedPmtu {
            segment,
            quoted_packet_len: key.packet_len,
            candidate_mtu: candidate.unwrap_or(0),
            current_path: current.is_some(),
        };
        let Some(outcome) = live(endpoint.correlated_pmtu_feedback(now, id, report))? else {
            return Ok(Completed(Discarded(IcmpDiscard::Stale)));
        };
        // Publication strictly follows TCP's acceptance of an immediate
        // decrease; a Deferred report must not be pre-empted through the
        // shared estimate that the connection itself would then adopt.
        let published = match (outcome, current) {
            (PmtuFeedback::Decreased { mtu }, Some(path)) => self.publish(
                now,
                path,
                ipv4,
                &key,
                evidence.packet_len,
                candidate,
                Some(mtu),
            )?,
            _ => None,
        };
        Ok(Completed(IcmpOutcome::Tcp {
            owner: id,
            report: TcpReport::PacketTooBig(outcome),
            published,
        }))
    }

    // Shared network fact from a correlated PTB: the reported next-hop MTU
    // (IPv4 floor 68; IPv6 reports below 1280 are discarded), or for an IPv4
    // router without one, RFC 1191's plateau below the corrected length using
    // this Host's table. Never applied to an invalidated incarnation, never
    // larger than or equal to the dropped packet, and held for 600 seconds.
    //
    // `applied` is the estimate a correlated TCP owner just decreased to.
    // The larger of it and the Host's own estimate is published: a shared
    // ceiling must not undercut a decrease the accepting owner applied under
    // its configured policy (it would be clamped to it at its next egress),
    // and one connection's plateau override must not lower other clients
    // below the Host's table. Both readings agree for a next-hop report.
    #[allow(clippy::too_many_arguments)]
    fn publish(
        &mut self,
        now: Instant,
        path: path::PathId,
        ipv4: bool,
        key: &QuoteKey,
        dropped: u32,
        candidate: Option<u32>,
        applied: Option<u32>,
    ) -> Result<Option<path::EstimateChange>, Error> {
        let Some(snapshot) = self
            .paths
            .path_snapshot(path)
            .ok()
            .filter(|s| s.status() == PathStatus::Valid)
        else {
            return Ok(None);
        };
        let mtu = match (candidate, ipv4) {
            (None, true) => {
                let Some(table) = snapshot.ipv4_plateaus() else {
                    return Ok(None);
                };
                match table.legacy_fallback(
                    snapshot.ip_packet_budget()?,
                    key.packet_len,
                    u32::from(key.header_len),
                    dropped,
                ) {
                    Ok(mtu) => mtu,
                    Err(_) => return Ok(None),
                }
            }
            _ => match report_mtu(ipv4, dropped, candidate) {
                Some(Some(mtu)) => {
                    debug_assert!(applied.is_none_or(|applied| applied == mtu));
                    mtu
                }
                _ => return Ok(None),
            },
        };
        let mtu = applied.map_or(mtu, |applied| applied.max(mtu));
        if mtu >= dropped {
            return Ok(None);
        }
        Ok(Some(self.trusted_decrease(now, path, mtu)?))
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
                let (client, rebound) =
                    self.paths.rebind_via(lease.prepared.client, request, via)?;
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
        // Evidence storage is reserved with the authority, before any bytes
        // can reach a backend; validate_egress fills it for each retry.
        self.reserve_attempt(
            endpoint,
            packet.connection.map_or(Owner::Stateless, Owner::Tcp),
            attempt,
        )?;
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
        let transport = tcp_selector(&frame[header..], total - header)?;
        let pending = self.reserve_attempt(
            endpoint,
            packet.connection.map_or(Owner::Stateless, Owner::Tcp),
            context.attempt,
        )?;
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
        self.ledger.set_evidence(
            pending,
            Evidence {
                link: live.link,
                path: live.binding.snapshot.path(),
                stamp: live.binding.snapshot.stamp(),
                owner: packet.connection.map_or(Owner::Stateless, Owner::Tcp),
                source: packet.ip.source,
                destination: packet.ip.destination,
                dscp: packet.dscp,
                header_len: header as u16,
                packet_len: total as u32,
                protocol,
                transport,
            },
        );
        Ok(live)
    }

    /// Issue the single ticket for this attempt's (idempotent) reservation.
    /// A retained ticket whose rejected attempt was replaced is not reissued:
    /// its holder keeps using it for the replacement attempt.
    pub fn submission_ticket(
        &mut self,
        endpoint: &mut Endpoint,
        context: EgressContext,
    ) -> Result<SubmissionTicket, Error> {
        self.check_endpoint(endpoint)?;
        let packet = endpoint
            .transmit_attempt_packet(context.attempt)
            .ok_or(Error::Obsolete)?;
        let index = self.reserve_attempt(
            endpoint,
            packet.connection.map_or(Owner::Stateless, Owner::Tcp),
            context.attempt,
        )?;
        Ok(SubmissionTicket {
            ticket: self.ledger.issue(index)?,
        })
    }

    /// Inspection of the ledger for tests of submitting embeddings; the ICMP
    /// dispatcher correlates internally. Expired entries never match.
    #[cfg(any(test, feature = "test-support"))]
    pub fn correlate(&self, now: Instant, quote: &QuoteKey) -> Correlation {
        self.ledger.correlate(now, quote)
    }

    /// Certified non-submission outside `submit` (for example after a
    /// refused revalidation the caller resolves with the Endpoint).
    pub fn cancel_submission(&mut self, ticket: SubmissionTicket) {
        self.ledger.cancel(ticket.ticket);
    }

    /// The physical-attempt transaction. Every fallible step happens before
    /// `submit` runs: exact revalidation of the bytes and path (at EVERY
    /// retry), evidence reservation, TCP delivery retirement, and the
    /// Endpoint's acceptance preflight. Afterwards the outcome is finalized
    /// without allocation or fallible lookup. The closure is the one backend
    /// call, including any timestamp fallback it performs; software GSO
    /// submits each physical segment with its own attempt and ticket.
    #[allow(clippy::too_many_arguments)]
    pub fn submit(
        &mut self,
        endpoint: &mut Endpoint,
        now: Instant,
        ticket: SubmissionTicket,
        context: EgressContext,
        frame: &[u8],
        shared_payload_len: usize,
        submit: impl FnOnce(EgressContext) -> BackendOutcome,
    ) -> Result<Submission, Refused> {
        let pending = self
            .ledger
            .find_ticket(ticket.ticket)
            .and_then(|index| self.ledger.pending(index));
        if pending.is_none_or(|p| p.attempt != Some(context.attempt)) {
            return Err(Refused {
                error: Error::Obsolete,
                ticket,
            });
        }
        let prepared = (|| {
            let live = self.validate_egress(endpoint, context, frame, shared_payload_len)?;
            if !endpoint.preflight_accept_transmit(now, context.attempt)? {
                return Err(Error::Obsolete);
            }
            Ok(live)
        })();
        let live = match prepared {
            Ok(live) => live,
            Err(error) => return Err(Refused { error, ticket }),
        };
        debug_assert!(
            self.ledger
                .find_ticket(ticket.ticket)
                .is_some_and(|index| self.ledger.has_evidence(index))
        );
        self.now = self.now.max(now);
        if let Some(id) = endpoint
            .transmit_attempt_packet(context.attempt)
            .and_then(|p| p.connection)
            && let Ok(progress) = endpoint.send_progress(id)
        {
            self.ledger.retire_tcp(id, progress.unacknowledged_sequence);
        }
        match submit(live) {
            BackendOutcome::Submitted => {
                self.ledger.seal(ticket.ticket, now, false);
                let accepted = endpoint.accept_transmit(now, context.attempt);
                assert!(matches!(accepted, Ok(true)), "preflighted acceptance");
                Ok(Submission::Submitted)
            }
            BackendOutcome::WouldBlock => Ok(Submission::Blocked(ticket)),
            BackendOutcome::Rejected => Ok(Submission::Rejected(ticket)),
            BackendOutcome::NotSubmitted => {
                self.ledger.cancel(ticket.ticket);
                Ok(Submission::Cancelled)
            }
            BackendOutcome::Unknown => {
                self.ledger.seal(ticket.ticket, now, true);
                Ok(Submission::PossiblySubmitted)
            }
        }
    }
}

// Transport selector of an exactly validated outgoing TCP segment. The
// span is the sequence space it consumes: payload plus SYN and FIN.
fn tcp_selector(tcp: &[u8], segment_len: usize) -> Result<Selector, Error> {
    let header = tcp.get(..20).ok_or(Error::Obsolete)?;
    let offset = usize::from(header[12] >> 4) * 4;
    let payload = segment_len.checked_sub(offset).filter(|_| offset >= 20);
    let payload = payload.ok_or(Error::Obsolete)?;
    let start = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    let control = u32::from(header[13] & 0x02 != 0) + u32::from(header[13] & 0x01 != 0);
    Ok(Selector::Tcp {
        source_port: u16::from_be_bytes([header[0], header[1]]),
        destination_port: u16::from_be_bytes([header[2], header[3]]),
        start,
        end: start.wrapping_add(payload as u32).wrapping_add(control),
    })
}

// A generation the Endpoint released after the Host's existence check is
// stale feedback, not a Host failure.
fn live<T>(result: Result<T, EndpointError>) -> Result<Option<T>, Error> {
    match result {
        Err(EndpointError::InvalidHandle) => Ok(None),
        result => Ok(Some(result?)),
    }
}

fn is_icmp(packet: &IngressPacket) -> bool {
    packet.protocol == if packet.ip.source.is_ipv4() { 1 } else { 58 }
}

// Host-level validation of a PTB's next-hop MTU for owners without TCP
// policy: None when impossible (below the IPv6 minimum, or no smaller than
// the packet it claims to have dropped); Some(None) for an IPv4 router that
// reported no next-hop MTU.
fn report_mtu(ipv4: bool, dropped: u32, candidate: Option<u32>) -> Option<Option<u32>> {
    let Some(mtu) = candidate else {
        return ipv4.then_some(None);
    };
    let mtu = if ipv4 { mtu.max(68) } else { mtu };
    (mtu < dropped && (ipv4 || mtu >= 1280)).then_some(Some(mtu))
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
