//! # Egress validation
//!
//! A connection's packet is validated when it is built, against the
//! connection's checked egress decision, as Linux validates a socket's
//! cached route in ip_queue_xmit (__sk_dst_check, which compares the
//! route's genid or fib6 serial number with the socket's cookie), and not
//! again when it leaves. `Host::egress_context` takes that decision
//! (`Host::refresh`: forwarding selection, port and forwarding mode, the
//! connection's complete headers within the path budget), valid while its
//! PathService change stamp holds, and checks the packet's addresses,
//! class and forwarding destination against it.
//!
//! At each physical attempt `Host::submit` and `Host::submit_group` make
//! O(1) checks only: the context's path stamp is still the path's (any
//! change of a path's selection, budget or validity, a rebind or a release
//! refuses the frame as `Error::Obsolete`, and a connection's binding is
//! first brought up to date so that its output is packetized again), the
//! packet fits the path's first-hop MTU (Linux's ip_finish_output check
//! against the device; for an aggregate each segment, as
//! ip_finish_output_gso), and an IPv4 packet on a path that clears DF
//! carries none (the embedding's per-attempt rewrite, RFC 1191 section
//! 6.6). The frame is the embedding's encoding of the attempt's packet for
//! the context's path: debug builds check its addresses, base destination,
//! header plan, lengths, class and ECN codepoint on every attempt; release
//! builds trust it, as Linux's device layer trusts the skb its IP layer
//! built. A stateless reply's frame is still parsed for the ledger evidence
//! that ICMP errors about it are correlated with.
//!
//! As in Linux, where packets already built or queued leave on the route
//! they were built for (ip_finish_output reads the skb's dst, not the
//! socket's current one), a packet authorized before a change its path's
//! stamp does not record may leave stale: bytes built before a path change
//! and authorized again under the new path's context (they are not sized
//! again), or a frame whose next hop's link-layer address changed after
//! the frame was addressed. The next packet built uses the new state.

#![no_std]

extern crate alloc;
use alloc::vec::Vec;
use core::{cell::Cell, net::IpAddr};
use ntcp::{
    ConnectionId, CorrelatedPmtu, CorrelatedSegment, Endpoint, EndpointConfig, EndpointError,
    ExpectedRegistrations, Instant, IpMetadata, Ipv4Options, Ipv4RegistrationPlan, ManagedError,
    ManagedRoute, NetworkError, OutgoingIpv4Options, PathFactoryRequest, PathProvider,
    PmtuFeedback, PreparedFactory, PreparedPath, RxPacketMetadata, Transmit, TransmitAttempt,
    TransmitGroup,
};
use ntcp_icmp::{FeedbackKind, QuotedTransport};
pub use ntcp_path as path;
mod ledger;
mod live;
use ledger::Ledger;
pub use ledger::{LedgerLimits, Owner, feedback_horizon};
use live::Live;
// Ledger inspection for the tests of crates that submit through a Host.
#[cfg(any(test, feature = "test-support"))]
pub use ledger::{
    Correlation, Evidence, FragmentPrefix, QuoteKey, QuotedSelector, Record, Selector,
};
#[cfg(not(any(test, feature = "test-support")))]
use ledger::{Evidence, FragmentPrefix, QuoteKey, QuotedSelector, Selector};
mod icmp_error;
use icmp_error::ErrorLimiter;
pub use icmp_error::IcmpErrorLimits;
mod ingress;
use ingress::IcmpOutput;
pub use ingress::{
    Datagram, EchoDisposition, Envelope, IcmpOutputCounters, IcmpOutputLimits, Processed,
    ProcessedEnvelope, Received, managed_icmp_output_limits,
};
mod reassembly;
use reassembly::Reassembly;
pub use reassembly::{DiscardCounters, ReassemblyCounters, ReassemblyLimits};
mod emitter;
pub use emitter::{
    ConnectionlessSizing, DatagramError, DatagramLimits, DatagramReport, IPV4_PEER_REASSEMBLY,
    IPV6_PEER_REASSEMBLY, ProbeRecord, UdpDatagramLimits, UdpSend, UdpSendMode,
};
mod adjunct;
use adjunct::Adjunct;
pub use adjunct::{
    AdjunctCounters, AdjunctLimits, DEFAULT_RESTART_SECONDS, MIN_RESTART_SECONDS, ProbeOutcome,
};
mod ident;
use ident::IdentifierAllocator as Allocator;
pub use ident::{
    Continuity, DEFAULT_LIFETIME_SECONDS, Entropy, EntropyError, IdentifierAllocator,
    IdentifierBackpressure, IdentifierLimits,
};
mod admin;
pub use admin::{AdminCandidate, AdminClient, Administration, AffectedPath, ClientReport};
mod neighbor;
pub use neighbor::{AddressState, NdPort, NeighborLimits};
use neighbor::{NdTables, Neighbors};
pub use ntcp_arp::{ArpCounters, ArpState};
// Neighbor cache inspection for the tests of embeddings (`Host::neighbor`).
#[cfg(any(test, feature = "test-support"))]
pub use neighbor::NeighborState;
mod redirect;
pub use redirect::{RedirectOutcome, RedirectRejection};
mod arp;
pub use arp::{Ipv4NeighborTable, NeighborHold};
mod discovery;
pub use discovery::{NeighborHop, NeighborReport, NeighborTicket, NeighborTransmit, NeighborWake};
mod udp;
use path::{
    ContextId, Dscp, ForwarderId, InterfaceKey, LinkId, PathRequest, PathService, PathSnapshot,
    PathStatus, ResolvedNextHop, ScopedAddress,
};
use udp::Udp;
pub use udp::{
    ProbeReceipt, ProbeReportError, RetrySuppression, SharedOffer, UdpEgress, UdpEvent, UdpFlowId,
    UdpLimits, UdpOptions, UdpPathLimits, UdpProbeBounds, UdpProbeOutcome, UdpProbeReport,
    UdpSendError, UdpSent, UdpSharedWriter, managed_udp_limits,
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
    /// The administration capability was not issued by this Host.
    Unauthorized,
    /// A planned connection's option-bearing output would leave under
    /// another route authority than the one its registration plan was
    /// stated for, or under none because no route resolves. Nothing is
    /// submitted; the owner revalidates (`registration_candidate`,
    /// `revalidate_registration`) or opens a new connection.
    StaleRoute,
    /// The embedding's entropy supply is absent or failed; what needed it
    /// (an RFC 4861 ReachableTime or RFC 4862 DAD delay) did not change.
    Entropy,
}
/// Why a received frame or datagram that `receive`, `process`,
/// `decode_datagram` or `input_datagram` refused with `error` is
/// discarded, for the caller that swallows the error to record. An
/// `Unsupported` refusal is named by the frame's own fields where the
/// caller can read them.
pub fn drop_reason(error: &Error) -> ntcp::DropReason {
    use ntcp::DropReason as R;
    match error {
        Error::Codec(error) => ip_drop_reason(*error),
        Error::Path(_) => R::IpInaddrerrors,
        Error::Endpoint(_) => R::InvalidMetadata,
        Error::Unsupported => R::UnhandledProto,
        _ => R::NotSpecified,
    }
}

/// Why an ICMP message completed as `outcome` was discarded without being
/// acted on; None for one acted on.
pub fn icmp_outcome_reason(outcome: &IcmpOutcome) -> Option<ntcp::DropReason> {
    use ntcp::DropReason as R;
    Some(match outcome {
        IcmpOutcome::Discarded(IcmpDiscard::SourceQuench) => R::IcmpSourceQuench,
        IcmpOutcome::Discarded(IcmpDiscard::Implausible) => R::IcmpOutOfWindow,
        IcmpOutcome::Discarded(
            IcmpDiscard::Uncorrelated
            | IcmpDiscard::Ambiguous
            | IcmpDiscard::LinkScope
            | IcmpDiscard::Stale,
        ) => R::IcmpNoSocket,
        IcmpOutcome::Echo(EchoDisposition::Dropped) => R::IcmpOutputDropped,
        IcmpOutcome::Echo(EchoDisposition::UnauthorizedRoute) => R::IpSourceRouteRefused,
        IcmpOutcome::Probe(ProbeOutcome::Unmatched) => R::IcmpNoSocket,
        IcmpOutcome::Redirect(RedirectOutcome::Rejected(
            RedirectRejection::NoEvidence
            | RedirectRejection::Uncorrelated
            | RedirectRejection::Stale,
        )) => R::IcmpNoSocket,
        IcmpOutcome::Redirect(RedirectOutcome::Rejected(_)) => R::IcmpInvalid,
        _ => return None,
    })
}

/// `drop_reason` of an IP codec error.
pub fn ip_drop_reason(error: ntcp_ip::Error) -> ntcp::DropReason {
    use ntcp::DropReason as R;
    use ntcp_ip::Error as E;
    match error {
        E::Truncated => R::PktTooSmall,
        E::Length | E::Version | E::Invalid | E::Options => R::IpInhdr,
        E::Checksum => R::IpCsum,
        E::FragmentationUnsupported => R::FragUnsupported,
        E::ExtensionsUnsupported => R::Ipv6BadExthdr,
        E::JumbogramsUnsupported => R::PktTooBig,
        E::VlanUnsupported | E::EtherTypeUnsupported => R::UnhandledProto,
        E::ProtocolUnsupported => R::IpNoproto,
        E::Quote => R::IcmpInvalid,
    }
}

/// `drop_reason` of an ICMP message `input_icmp_datagram` refused.
pub fn icmp_drop_reason(error: &Error) -> ntcp::DropReason {
    use ntcp::DropReason as R;
    match error {
        Error::Codec(ntcp_ip::Error::Checksum) => R::IcmpCsum,
        Error::Codec(ntcp_ip::Error::Truncated) => R::PktTooSmall,
        Error::Codec(ntcp_ip::Error::FragmentationUnsupported) => R::FragUnsupported,
        Error::Codec(_) | Error::Unsupported => R::IcmpInvalid,
        error => drop_reason(error),
    }
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

/// Actual codec/input-buffer capabilities of one link: `max_ip_packet` bounds
/// each physical packet, fragments included. Reassembly is configured per
/// Host (`Limits::reassembly`) and states its own reconstructed capacity
/// (`Host::reassembly_capacity`). IPv6 extension header traversal is the
/// `Ipv6Receive::Extensions` profile; no profile supplies a standard clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveCapabilities {
    pub max_ip_packet: usize,
    pub ipv4: Ipv4Receive,
    pub ipv6: Ipv6Receive,
    pub gro: bool,
}
/// IPv4 receive profile. Every enabled profile validates the options of each
/// datagram and hands every option except NOP and EOL, known or unknown, to
/// TCP and to ICMP processing (RFC 1122 section 3.2.1.8); the two settings
/// change only what the Host interprets or admits, never what it retains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv4Receive {
    Disabled,
    Enabled {
        /// Record Route and Timestamp interpretation, which RFC 1122 section
        /// 3.2.1.8 makes optional: destination processing (`Host::process`)
        /// records this host in them once per complete datagram. Without it
        /// they are delivered exactly as received.
        interpretation: bool,
        /// Admission of datagrams carrying a Loose or Strict Source Route,
        /// checked on every fragment before reassembly. Use of the return
        /// route is authorized separately by its consumer.
        source_routes: bool,
    },
}
impl Ipv4Receive {
    // Source-route admission, or None when IPv4 is disabled.
    pub(crate) fn source_routes(self) -> Option<bool> {
        match self {
            Self::Disabled => None,
            Self::Enabled { source_routes, .. } => Some(source_routes),
        }
    }
    // Record Route and Timestamp interpretation.
    pub(crate) fn interpretation(self) -> bool {
        matches!(
            self,
            Self::Enabled {
                interpretation: true,
                ..
            }
        )
    }
}
/// IPv6 receive profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv6Receive {
    Disabled,
    /// The upper layer directly after the base header, or after a Fragment
    /// header directly after it; any other extension header is refused
    /// without receive processing or errors.
    BaseHeader,
    /// Extension headers in their actual order (RFC 8200 section 4): the
    /// headers before any Fragment header are processed on every arriving
    /// packet and the rest after reassembly, which keeps fragment zero's
    /// complete unfragmentable part. Unrecognized options apply their
    /// action; a Routing header of any type is skipped with Segments Left
    /// zero and refused above zero, since no local address is a segment
    /// endpoint; Hop-by-Hop Options only directly after the base header; an
    /// unrecognized Next Header (anything but TCP, UDP, ICMPv6 and No Next
    /// Header ends the chain) is refused. Refusals draw the RFC 4443
    /// Parameter Problem through the Host's ICMP output and error limiter.
    /// Jumbograms stay unsupported.
    Extensions,
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
    /// Fragment reassembly; disabled by default.
    pub reassembly: ReassemblyLimits,
    /// The rate limit shared by every ICMP error this Host originates.
    pub icmp_errors: IcmpErrorLimits,
    /// Queue for ICMP messages this Host originates; disabled by default.
    pub icmp_output: IcmpOutputLimits,
    /// Source fragmentation and identifier allocation; nothing is
    /// fragmented by default.
    pub datagrams: DatagramLimits,
    /// Neighbor Discovery for ND-capable ports; none by default.
    pub neighbors: NeighborLimits,
    /// ARP for the IPv4 next hops of neighbor ports, the same quantities
    /// for that family (the answers are ARP replies); none by default, and
    /// none needed with a table of the embedding's
    /// (`Host::set_ipv4_neighbor_table`).
    pub ipv4_neighbors: NeighborLimits,
}

/// Fragmented datagrams this Host context can receive, per family: what it
/// reassembles under the worst conforming fragmentation, with every bound
/// backed by storage allocated when the Host was created. The values hold
/// for the lifetime of this Host (`context`); a replacement Host states its
/// own. Receive-MSS policy built on them is not decided here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReassemblyCapacity {
    pub context: ContextId,
    /// RFC 1122 section 3.3.2 EMTU_R: the largest complete IP datagram,
    /// header included, that can be reassembled.
    pub emtu_r: u32,
    /// The largest transport message, transport header included: RFC 1122
    /// MMS_R = EMTU_R - 20 for IPv4, and EMTU_R - 40 (the fixed header) for
    /// IPv6. RFC 1191's MSS paragraph subtracts 40 from the datagram size
    /// for IPv4, that is MMS_R less TCP's 20-octet header.
    pub mms_r: u32,
}

/// Storage rationale: all occupied transport generations, one provisional
/// factory (including TIME-WAIT replacement), the Endpoint's single independent
/// stateless reservation lane when control output is enabled, and explicitly
/// requested migration headroom. Connection-associated final output uses its
/// retained binding. Every sum is checked; source/link/route capacities are
/// configured authority.
///
/// Submission ledger: connections record no evidence (ICMP errors about
/// them are checked against their own sequence space), so the only owner
/// provisioned here is the Endpoint's stateless lane, with one record and one
/// unsealed attempt: the Endpoint holds at most one stateless reservation,
/// and a retained ticket is re-keyed to its replacement attempt rather than
/// duplicated. The record exists even without control output, which needs
/// none, because a ledger has at least one; `managed_udp_limits` adds each
/// flow's record and attempts. Each record keeps one entry per full-sized
/// segment the configured send buffer holds, plus one: the TCP-derived size
/// connections used when they kept evidence, retained for the lane and for
/// datagram flows. Beyond it a record's oldest entry is evicted into its
/// key's summary, which never blocks output. The horizon is twice the
/// configured MSL.
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
        owners: 1,
        history_per_owner,
        concurrent_attempts: 1,
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
            reassembly: ReassemblyLimits::default(),
            icmp_errors: IcmpErrorLimits::default(),
            icmp_output: IcmpOutputLimits::default(),
            datagrams: DatagramLimits::default(),
            neighbors: NeighborLimits::default(),
            ipv4_neighbors: NeighborLimits::default(),
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

/// The authority `egress_context` gives one attempt: the link and next hop
/// its packet leaves through, and the path observation it was granted
/// under (the path client and its stamp), which every physical attempt
/// checks. The path's snapshot stays where it lives
/// (`Host::egress_snapshot`), as Linux's skb holds a reference to its dst.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EgressContext {
    pub link: LinkId,
    pub next_hop: ResolvedNextHop,
    pub attempt: TransmitAttempt,
    client: path::ClientId,
    stamp: path::ChangeStamp,
    // The snapshot granted, for debug builds' check that the live snapshot
    // of an unchanged stamp is still that one.
    #[cfg(debug_assertions)]
    snapshot: PathSnapshot,
}
impl EgressContext {
    /// The path client the attempt's packet leaves through.
    pub const fn client(&self) -> path::ClientId {
        self.client
    }
    /// The observation of that client's path the authority was granted
    /// under.
    pub const fn stamp(&self) -> path::ChangeStamp {
        self.stamp
    }
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
/// A connection's attempt reserves no evidence (its ICMP errors are checked
/// against its sequence space); its Endpoint reservation is finalized once.
#[must_use = "an unresolved ticket keeps its evidence reservation"]
#[derive(Debug, Eq, PartialEq)]
pub struct SubmissionTicket {
    ticket: Option<u64>,
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
    /// `published` is present only when TCP decreased its estimate at once
    /// or left it Unchanged for a report about its current path, and the
    /// Host then published its own estimate (a decrease or a hold restart).
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
    /// An Echo Request addressed to this Host, answered by its Echo service.
    Echo(EchoDisposition),
    /// An Echo Reply, or an ICMP error quoting an Echo Request, considered
    /// by the Echo adjunct.
    Probe(ProbeOutcome),
    /// An IPv4 Redirect. (An ICMPv6 Redirect is Neighbor Discovery,
    /// consumed by `receive` on an ND-capable port: `Received::Redirect`.)
    Redirect(RedirectOutcome),
}

/// An ICMP error for a TCP owner whose output is reserved. Nothing was
/// applied or published. The token itself carries the report, normalized
/// from the validated frame and the quoted segment the connection's send
/// window accepted, with the path the connection used on arrival, bound to
/// this Host context and the owner generation: `Host::replay_icmp` applies
/// it once the reservation resolves, without the frame. The replay
/// revalidates the generation, the quote's overlap with outstanding data and
/// the current authority of that path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeferredIcmp {
    context: IngressContext,
    owner: ConnectionId,
    report: Correlated,
}

// One validated report about one TCP connection: the quoted segment's
// sequence span and lengths, the connection's path incarnation when the
// report arrived, and the family-normalized report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Correlated {
    segment: CorrelatedSegment,
    path: Option<path::PathId>,
    ipv4: bool,
    kind: CorrelatedKind,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CorrelatedKind {
    /// `quoted_packet_len` as returned (RFC 1191 legacy inflation included);
    /// `candidate` None from an IPv4 router that reported no next-hop MTU.
    PacketTooBig {
        quoted_packet_len: u32,
        candidate: Option<u32>,
    },
    NetworkError(NetworkError),
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

/// One `Host::service_changes` pass. Counts and the first failure only, so a
/// pass never allocates however many clients fail.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServiceReport {
    /// Deferred reports, applied at their timeout, that lowered the shared
    /// estimate.
    pub decreased: usize,
    /// Confirmed probes that raised the shared estimate.
    pub raised: usize,
    /// Dirty clients brought to their newest snapshot and acknowledged.
    pub applied: usize,
    /// Clients left dirty (or results left unpublished) by a failure.
    pub failed: usize,
    pub first_error: Option<Error>,
}
impl ServiceReport {
    fn fail(&mut self, error: Error) {
        self.failed += 1;
        self.first_error.get_or_insert(error);
    }
}

#[derive(Clone, Copy)]
struct Port {
    link: LinkId,
    receive: ReceiveCapabilities,
    forwarding: Forwarding,
}
// A destination address `owned_on_link` found to be a source owned on
// `link` at path revision `revision`. Every change of links, sources or
// their owners moves the revision, so while it holds the lookup finds the
// same, as Linux's early demux trusts a socket's cached input route while
// its dst stays valid.
#[derive(Clone, Copy, PartialEq)]
struct LocalDestination {
    link: LinkId,
    address: IpAddr,
    revision: u64,
}
#[derive(Clone, Copy)]
struct Binding {
    owner: Option<ConnectionId>,
    prepared: PreparedPath,
    registration: Option<Registration>,
    // When the binding last moved to another path incarnation: data its
    // owner sent until then left on another path.
    moved: Option<Instant>,
    // The connection's local and remote ports, which with its path's
    // addresses name it in a quote (`redirected_path`).
    ports: (u16, u16),
    // The egress decision `refresh` last checked in full for `prepared`.
    dst: Option<Dst>,
    // The next hop's link-layer address `resolve_neighbor` last found
    // connected.
    neighbor: Option<NeighborDst>,
}
impl Binding {
    fn rebind(&mut self, prepared: PreparedPath, now: Instant) {
        if prepared.snapshot.path() != self.prepared.snapshot.path() {
            self.moved = Some(now);
        }
        self.prepared = prepared;
        self.dst = None;
        self.neighbor = None;
    }
}
// A connection's resolved next hop, as Linux's neigh_output sends to a
// NUD_CONNECTED entry through its cached header (neigh_hh_output) with no
// lookup and no write to the entry: the link-layer address of the next
// hop of the path with `stamp` on the port in slot `port`, which its
// neighbour entry held while REACHABLE or PERMANENT. The neighbour-state
// generation of the next hop's family (ARP or ND) moves whenever such an
// entry leaves that state, changes its address or is removed, the path
// stamp whenever the path's next hop or a Redirect's router target can
// change, and a port slot names its link while the port is registered.
// Debug builds compare it with what resolution returns on every use.
#[derive(Clone, Copy)]
struct NeighborDst {
    stamp: path::ChangeStamp,
    port: usize,
    generation: u64,
    mac: [u8; 6],
}
// A connection's checked egress decision, as Linux keeps a socket's route
// in sk_dst_cache and revalidates it on each transmit only by its cookie
// (__sk_dst_check: ipv4_dst_check compares the route's genid,
// ip6_dst_check the fib6 serial number of the socket's cookie):
// `refresh` found the binding current and its checks passed (forwarding
// selection, port and forwarding mode, the connection's complete headers
// within the path budget, the observation acknowledged) for exactly these
// inputs. The path's stamp is the cookie: every change of a path's
// selection, budget or validity gives a new one (route, source and link
// changes, PMTU decreases and increases, Redirects and their end), and a
// rebind gives the binding a new client. The connection's own route
// inputs (class, scope, forwarding destination after a peer's return
// route, IP header length) are compared, and the port by its slot, since
// ports are immutable while registered. Debug builds repeat the full
// checks on every use (`current_checks`).
#[derive(Clone, Copy)]
struct Dst {
    stamp: path::ChangeStamp,
    client: path::ClientId,
    dscp: u8,
    zone: Option<LinkId>,
    forwarding_destination: IpAddr,
    ip_header_len: u16,
    port: usize,
}
impl Dst {
    fn holds(
        &self,
        prepared: &PreparedPath,
        stamp: path::ChangeStamp,
        current: &ManagedRoute,
    ) -> bool {
        self.stamp == stamp
            && prepared.snapshot.stamp() == stamp
            && current.stamp == stamp
            && self.client == prepared.client
            && self.dscp == current.dscp
            && self.zone == current.zone
            && self.forwarding_destination == current.forwarding_destination
            && self.ip_header_len == current.ip_header_len
    }
}
// A planned open's checked plan, whose options hold the connection's
// complete immutable source route, and the route authority the owner's
// expected registrations were stated for: route identity with its
// generation, source, forwarding destination and DSCP. PMTU revisions are
// not part of a PathKey.
#[derive(Clone, Copy)]
struct Registration {
    plan: Ipv4RegistrationPlan,
    authorized: path::PathKey,
}
// What holds a PathService client (`Host::holders`). Output leases and
// ICMP output are not listed: they read their path when they use it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Holder {
    None,
    Binding(usize),
    Flow(usize),
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
    // Process-unique identity binding issued administration capabilities.
    instance: u64,
    // Owner search aging (RFC 4821 section 7.3, RFC 1191/8201 aging
    // timer) for every TCP connection with PLPMTUD; None until set.
    search_aging: Option<ntcp::SearchAging>,
    paths: PathService,
    ports: Vec<Option<Port>>,
    // The destination last found to be a source owned on a link, and the
    // path revision it was found at (`owned_on_link`).
    local: Cell<Option<LocalDestination>>,
    bindings: Vec<Option<Binding>>,
    // Occupied `bindings` records: what service and collection passes and
    // owner lookups visit.
    live_bindings: Live,
    // The unoccupied `bindings` records, taken from the end, and the
    // occupied ones no connection has committed yet: a factory finds its
    // record, and a commit or cancel its own, without a pass over the
    // bindings.
    free_bindings: Vec<usize>,
    provisional: Live,
    // Per endpoint connection slot (`ConnectionId::index`), the binding its
    // owner generation committed, if any; sized when attached.
    owner_bindings: Vec<Option<usize>>,
    // Committed bindings yet to adopt the owner search aging, and those
    // whose owners hold results to publish.
    unaged: Live,
    unpublished: Live,
    // The endpoint's reclaim count when the last collection completed.
    reclaimed: u64,
    // Reclaimed connections and bindings collection has looked at.
    #[cfg(test)]
    collect_visits: u64,
    // Per PathService client slot (`ClientId::index`), the binding or
    // datagram flow it serves, which a change service pass brings a dirty
    // client taken from the service's queue to.
    holders: Vec<Holder>,
    leases: Vec<Option<Lease>>,
    ledger: Ledger,
    udp: Udp,
    reassembly: Reassembly,
    errors: ErrorLimiter,
    icmp_output: IcmpOutput,
    // Destination of datagrams that `input_ip` reassembles: one datagram of
    // the reassembly capacity, empty while reassembly is disabled.
    completed: Vec<u8>,
    datagram_limits: DatagramLimits,
    identifiers: Allocator,
    adjunct: Adjunct,
    neighbors: NdTables<discovery::HeldOutput>,
    ipv4_neighbors: arp::Ipv4Backend,
    // Addresses ND ingress found duplicate since the last
    // `service_neighbors` report, which carries them to the owner.
    unreported_duplicates: usize,
    entropy: Option<Entropy>,
    // Latest caller time seen by a submission or collection; only used to
    // skip burying history that has already expired.
    now: Instant,
    timebase: ntcp::CallerTimebase,
    attached: bool,
    // `ipv4_header_errors`.
    ipv4_header_errors: u64,
    // What this Host discarded without returning an error, by reason.
    pub(crate) drops: ntcp::DropRecorder,
}

/// The IP header plan of output on one path (`Host::header_plan`).
#[derive(Clone, Copy, Debug)]
pub struct HeaderPlan<'a> {
    pub segments: &'a [core::net::Ipv6Addr],
    pub len: usize,
}

// Every slot of a `count`-slot table, descending, so that taking from the
// end hands out slot 0 first, with room for all of them, so that freeing a
// slot never allocates.
fn free_slots(count: usize) -> Result<Vec<usize>, Error> {
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    slots.extend((0..count).rev());
    Ok(slots)
}

// Whether `free` lists each unoccupied slot of `table` once and nothing
// else: the full scan a free list replaces, for debug assertions.
fn lists_free<T>(free: &[usize], table: &[Option<T>]) -> bool {
    let mut listed = alloc::vec![false; table.len()];
    free.iter()
        .all(|&slot| !core::mem::replace(&mut listed[slot], true))
        && table
            .iter()
            .zip(listed)
            .all(|(record, listed)| listed == record.is_none())
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
    /// The caller must supply a confidential, unpredictable `lookup_key`
    /// from an initialized CSPRNG: it keys the path cache's hash
    /// (`PathService::new`).
    pub fn new(
        context: ContextId,
        path_limits: path::Limits,
        limits: Limits,
        timebase: ntcp::CallerTimebase,
        lookup_key: [u8; 16],
    ) -> Result<Self, Error> {
        if limits
            .bindings
            .checked_add(limits.output_leases)
            .and_then(|n| n.checked_add(limits.udp.flows))
            .and_then(|n| n.checked_add(usize::from(limits.icmp_output.messages != 0)))
            .ok_or(Error::Capacity)?
            > path_limits.clients
            || !matches!(timebase.units_per_second, 1_000_000 | 1_000_000_000)
            || !(1..=255_000_000).contains(&timebase.max_segment_lifetime_us)
        {
            return Err(Error::Capacity);
        }
        limits.datagrams.validate()?;
        // Probes leave through the ICMP output drain and its path client.
        if limits.datagrams.adjunct.paths != 0 && limits.icmp_output.messages == 0 {
            return Err(Error::Capacity);
        }
        let paths = PathService::new(context, path_limits, lookup_key)?;
        Ok(Self {
            instance: admin::next_instance()?,
            search_aging: None,
            paths,
            ports: table(path_limits.links, None)?,
            local: Cell::new(None),
            bindings: table(limits.bindings, None)?,
            live_bindings: Live::new(limits.bindings)?,
            free_bindings: free_slots(limits.bindings)?,
            provisional: Live::new(limits.bindings)?,
            owner_bindings: Vec::new(),
            unaged: Live::new(limits.bindings)?,
            unpublished: Live::new(limits.bindings)?,
            reclaimed: 0,
            #[cfg(test)]
            collect_visits: 0,
            holders: table(path_limits.clients, Holder::None)?,
            leases: table(limits.output_leases, None)?,
            ledger: Ledger::new(limits.ledger)?,
            udp: Udp::new(limits.udp)?,
            reassembly: Reassembly::new(limits.reassembly, timebase.units_per_second)?,
            errors: ErrorLimiter::new(limits.icmp_errors, timebase.units_per_second),
            icmp_output: IcmpOutput::new(limits.icmp_output)?,
            completed: table(
                [false, true]
                    .into_iter()
                    .filter_map(|ipv6| limits.reassembly.datagram_capacity(ipv6))
                    .max()
                    .unwrap_or(0),
                0u8,
            )?,
            datagram_limits: limits.datagrams,
            identifiers: Allocator::new(limits.datagrams.identifiers, timebase.units_per_second)?,
            adjunct: Adjunct::new(limits.datagrams.adjunct, timebase.units_per_second)?,
            neighbors: NdTables::new(Neighbors::new(
                limits.neighbors,
                path_limits.links,
                timebase.units_per_second,
            )?),
            ipv4_neighbors: arp::Ipv4Backend::new(
                limits.ipv4_neighbors,
                path_limits.links,
                timebase.units_per_second,
            )?,
            unreported_duplicates: 0,
            entropy: None,
            now: 0,
            timebase,
            attached: false,
            ipv4_header_errors: 0,
            drops: ntcp::DropRecorder::new(),
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
        // An ND-capable port's IPv6 addresses are published by DAD
        // (`add_neighbor_address`), never at once.
        if address.address().is_ipv6() && self.neighbors.port(link).is_some() {
            return Err(Error::Unsupported);
        }
        // Likewise its IPv4 addresses, which ARP must also answer for.
        if address.address().is_ipv4() && self.ipv4_neighbors.table().has_link(link) {
            return Err(Error::Unsupported);
        }
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
    /// An owner-configured Segment Routing route (`PathService::add_segment_route`).
    pub fn add_segment_route(
        &mut self,
        route: path::Route,
        segments: &[core::net::Ipv6Addr],
    ) -> Result<path::RouteId, Error> {
        Ok(self.paths.add_segment_route(route, segments)?)
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
    /// None while reassembly is disabled.
    pub fn reassembly_capacity(&self, ipv6: bool) -> Option<ReassemblyCapacity> {
        let emtu_r = self.reassembly.limits().datagram_capacity(ipv6)? as u32;
        Some(ReassemblyCapacity {
            context: self.paths.context(),
            emtu_r,
            mms_r: emtu_r - if ipv6 { 40 } else { 20 },
        })
    }
    //= https://www.rfc-editor.org/rfc/rfc1191#section-3.1
    //= reason=Managed connections send the MSS this paragraph describes. T13 supplies the host capacity: Host::reassembly_capacity states, per family and per Host context, EMTU_R (RFC 1122 section 3.3.2: the largest complete IP datagram, header included, that the configured, storage-backed reassembly engine accepts) and MMS_R (EMTU_R - 20 for IPv4, EMTU_R - 40 for IPv6). This paragraph calls the largest reassemblable datagram MMS_R, so its host MMS_R-40 is EMTU_R - 40, that is RFC 1122's MMS_R less TCP's 20-octet header for IPv4; the TCP payload unit (MSS) differs from both EMTU_R and MMS_R. T16 derives the managed receive MSS inside every Host factory transaction (active, Fast Open, passive child and TIME-WAIT replacement): Host::receive_ip_capability takes the least of EMTU_R (no term while reassembly is disabled), the largest live link enabled for the family at the smaller of its current MTU and physical receive capacity (the permitted maximum connected-link choice: a multi-homed Host counts its largest link, not the selected route's) and the family wire limit, less the IP and TCP base headers, so 65495 is offered exactly when an actual 65535-octet IPv4 link and matching reassembly support it; only user and advertised caps reduce it, a discovered send PMTU never does, and the offer is frozen once committed in its SYN or SYN-ACK. Host factory tests (ntcp-host src/tests/receive_capability.rs) cover both families, unequal links with per-link family enablement, link addition, removal and MTU change, new listener children after a topology change, separate contexts and source replacement, reassembly below and above the links and disabled, physical capacity below a link MTU, the 65535-octet IPv4 link and rejection without a capability. The supplied managed embeddings keep no static receive sizing: native SYN and SYN-ACK offers follow the Host's link (ntcp-socket packet_tests.rs) and tun_echo's equal Host::receive_ip_capability (tun_echo_pmtu_tests.rs). On the wire, the integration/rfc_host mss case's production-factory driver (src/bin/two_link.rs) owns two TUNs of unequal MTU with genuine reassembly and routes over the smaller: in both families the captured SYN-ACK and SYN offers over the smaller link equal the larger link's derivation, also for connections opened after real downstream PTBs lowered the send PMTU. Raw Endpoints keep their documented caller-supplied receive limits as an explicit legacy contract, on which this closure does not rest. The optional link-derived choice is not itself a required feature.
    //# in the MSS option. The MSS option should be 40 octets less than the size of the
    //# largest datagram the host is able to reassemble (MMS_R, as defined in [1]); in many
    //# cases, this will be the architectural limit of 65495 (65535 - 40) octets. A host MAY
    //# send an MSS value derived from the MTU of its connected network (the maximum MTU
    //# over its connected networks, for a multi-homed host); this should not cause problems
    //# for PMTU Discovery, and may dissuade a broken peer from sending enormous datagrams.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-3.1
    //= reason=Managed receive offers derive from Host::receive_ip_capability, never above the maximum MTU of the connected links enabled for the family (each counted at the smaller of its current MTU and physical receive capacity), nor above EMTU_R or the family wire limit. User disposition (decision A, 2026-11-04, recorded): 65495 is advertised only when this uncapped derivation supports it, that is with an actual 65535-octet IPv4 link and matching reassembly capacity; this paragraph's warning against unnecessary use of such a large MSS is read as not covering that capability-backed use, so no 65494 or other substitute ceiling applies, and any smaller link, physical receive or reassembly capacity gives a smaller offer. Host factory tests (ntcp-host src/tests/receive_capability.rs) offer 65495 on a 65535-octet IPv4 link with 65535-octet reassembly and 64960, 65494 and 65494 with 65000-octet reassembly, a 65534-octet physical receive capacity and a 65534-octet link; a smaller validated send PMTU leaves the offer unchanged. Raw Endpoint offers keep their configured receive_ip_payload_limit and MSS caps as an explicit legacy contract. No sign-bit bug is alleged.
    //# Note: At the moment, we see no reason to send an MSS greater than the maximum MTU of
    //# the connected networks, and we recommend that hosts do not use 65495. It is quite
    //# possible that some IP implementations have sign-bit bugs that would be tickled by
    //# unnecessary use of such a large MSS.
    /// The receive capability of this Host context for one family, from
    /// current facts: the least of the reassembly capacity (EMTU_R; no term
    /// while reassembly is disabled), the largest live link that enables the
    /// family, each counted at its current MTU or at what its backend can
    /// physically receive when that is smaller, and the family's non-jumbo
    /// datagram limit. Every managed factory derives its connection's
    /// receive MSS offer from it; the discovered send PMTU and the selected
    /// route play no part. `Unsupported` when no link receives the family or
    /// the result cannot carry the IP and TCP base headers and one octet.
    pub fn receive_ip_capability(&self, ipv6: bool) -> Result<ntcp::ReceiveIpCapability, Error> {
        let links = self
            .ports
            .iter()
            .flatten()
            .filter(|port| {
                if ipv6 {
                    port.receive.ipv6 != Ipv6Receive::Disabled
                } else {
                    port.receive.ipv4 != Ipv4Receive::Disabled
                }
            })
            .filter_map(|port| {
                let mtu = self.paths.link(port.link).ok()?.mtu;
                Some(mtu.min(port.receive.max_ip_packet as u32))
            })
            .max()
            .ok_or(Error::Unsupported)?;
        let reassembly = self
            .reassembly_capacity(ipv6)
            .map_or(u32::MAX, |capacity| capacity.emtu_r);
        let wire = if ipv6 { 65575 } else { 65535 };
        ntcp::ReceiveIpCapability::new(
            self.paths.context(),
            ipv6,
            links.min(reassembly).min(wire),
        )
        .ok_or(Error::Unsupported)
    }
    pub fn reassembly_counters(&self) -> ReassemblyCounters {
        self.reassembly.counters()
    }
    /// Arriving IPv4 packets and fragments discarded for an error in their
    /// header (`ntcp_ip::header_error`), a bad checksum included, by
    /// `receive` or by the destination processing of a frame given to
    /// `input_icmp`, as Linux counts the Ip MIB's InHdrErrors. A frame the
    /// embedding's link framing refused before the IP layer saw it is not
    /// counted. For administrative reporting.
    pub fn ipv4_header_errors(&self) -> u64 {
        self.ipv4_header_errors
    }
    /// What this Host discarded itself, by reason: fragments its reassembly
    /// refused, duplicated or abandoned, UDP datagrams no flow took, ICMP
    /// messages it discarded after validation and ICMP output it did not
    /// queue or send. A frame or datagram one of its calls refuses with an
    /// error is the caller's to record (`drop_reason`).
    pub fn drop_counts(&self) -> ntcp::DropCounts {
        self.drops.counts()
    }
    /// This Host's discard counts and feed (`ntcp::DropRecorder`).
    pub fn drops_mut(&mut self) -> &mut ntcp::DropRecorder {
        &mut self.drops
    }
    pub fn drops(&self) -> &ntcp::DropRecorder {
        &self.drops
    }
    /// The earliest reassembly deadline, at which a `service_changes` pass
    /// discards the expired datagram (and may queue its Time Exceeded) even
    /// when nothing else arrives.
    pub fn next_reassembly_deadline(&self) -> Option<Instant> {
        self.reassembly.next_deadline()
    }
    /// Supply the cryptographically secure entropy the Host draws on for
    /// unpredictable identifiers. Without it (or when it fails) whatever
    /// needs it is refused with backpressure; there is no weaker fallback.
    pub fn set_entropy(&mut self, entropy: Entropy) {
        self.entropy = Some(entropy);
    }
    /// Start issuing identifiers for non-atomic datagrams. Nothing is issued
    /// before this. A fresh allocator issues at once: a newly started stack
    /// assumes no earlier incarnation emitted from its sources. A
    /// transferred allocator must come from a started Host
    /// (`take_identifiers`) with the same timebase units; its leases carry
    /// over. Instants are this Host's caller timebase, which the
    /// transferring embedding must share.
    pub fn start_identifiers(&mut self, continuity: Continuity) -> Result<(), Error> {
        if self.identifiers.running() {
            return Err(Error::InvalidContext);
        }
        match continuity {
            Continuity::Fresh => self.identifiers.start(),
            Continuity::Transfer(allocator) => {
                if !allocator.running()
                    || allocator.units_per_second() != self.timebase.units_per_second
                {
                    return Err(Error::InvalidContext);
                }
                self.identifiers = allocator;
                self.datagram_limits.identifiers = self.identifiers.limits();
            }
        }
        Ok(())
    }
    /// Move this Host's allocator out for a successor context, with every
    /// live lease. This Host issues no identifier afterwards.
    pub fn take_identifiers(&mut self) -> Result<IdentifierAllocator, Error> {
        let empty = Allocator::new(
            IdentifierLimits {
                ipv4_tuples: 0,
                ipv6_leases: 0,
                ..self.datagram_limits.identifiers
            },
            self.timebase.units_per_second,
        )?;
        Ok(core::mem::replace(&mut self.identifiers, empty))
    }
    /// Lease an Identification for one non-atomic datagram (a DF-clear IPv4
    /// packet is one, RFC 6864 section 4.1) of `protocol` from `source` to
    /// `destination`, physically submitted no later than `now`. The value is
    /// unique for that tuple within the maximum datagram lifetime; when none
    /// is available the caller must hold the packet and retry, never reuse.
    pub fn lease_identification(
        &mut self,
        now: Instant,
        source: IpAddr,
        destination: IpAddr,
        protocol: u8,
    ) -> Result<u32, IdentifierBackpressure> {
        self.identifiers
            .issue(now, source, destination, protocol, self.entropy.as_mut())
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
        self.port_slot(link).map(|slot| self.ports[slot].unwrap())
    }
    fn port_slot(&self, link: LinkId) -> Result<usize, Error> {
        self.paths.link(link)?;
        self.ports
            .iter()
            .position(|port| port.is_some_and(|port| port.link == link))
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
        self.neighbors.remove_port(context.link);
        self.ipv4_neighbors.table_mut().remove_link(context.link);
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
        let connections = endpoint.max_connections();
        self.owner_bindings
            .try_reserve_exact(connections)
            .map_err(|_| Error::Allocation)?;
        endpoint.enable_managed_paths(self.paths.context())?;
        self.owner_bindings.resize(connections, None);
        self.attached = true;
        Ok(())
    }
    fn check_endpoint(&self, endpoint: &Endpoint) -> Result<(), Error> {
        if endpoint.managed_context() != Some(self.paths.context()) {
            return Err(Error::InvalidContext);
        }
        Ok(())
    }
    fn forwarding(&self, snapshot: &PathSnapshot) -> Result<Port, Error> {
        self.forwarding_slot(snapshot)
            .map(|slot| self.ports[slot].unwrap())
    }
    // `forwarding`, naming the port by its slot.
    fn forwarding_slot(&self, snapshot: &PathSnapshot) -> Result<usize, Error> {
        self.paths.validate_snapshot(snapshot)?;
        if snapshot.key().destination().address().is_ipv6() && snapshot.first_hop_mtu() < 1280 {
            return Err(Error::Unsupported);
        }
        let slot = self.port_slot(snapshot.key().link())?;
        match (
            self.ports[slot].unwrap().forwarding,
            snapshot.key().next_hop(),
        ) {
            (Forwarding::Forwarder(a), ResolvedNextHop::Forwarder(b)) if a == b => Ok(slot),
            (Forwarding::IpNextHop, ResolvedNextHop::Address(_)) => Ok(slot),
            _ => Err(Error::Unsupported),
        }
    }
    // `zone` scopes the link-local addresses of a scoped identity
    // (`ScopedTuple`); unscoped addresses never carry it.
    fn request(
        &self,
        source: IpAddr,
        destination: IpAddr,
        zone: Option<LinkId>,
        dscp: Dscp,
    ) -> Result<PathRequest, Error> {
        // An unregistered source is missing local authority, not a missing
        // route: NoRoute is reserved for forwarding selection from a source
        // this host owns.
        Ok(PathRequest {
            source: self.source(source, zone)?,
            destination: scoped(destination, zone)?,
            dscp,
        })
    }
    fn source(&self, address: IpAddr, zone: Option<LinkId>) -> Result<path::SourceId, Error> {
        let zone = zone.filter(|_| matches!(address, IpAddr::V6(v) if v.is_unicast_link_local()));
        Ok(self
            .paths
            .sources()
            .find(|(_, a)| a.address() == address && a.zone() == zone)
            .map(|(id, _)| id)
            .ok_or(path::Error::SourceNotOwned)?)
    }
    pub fn binding(&self, owner: ConnectionId) -> Result<PreparedPath, Error> {
        self.binding_index(owner)
            .map(|index| self.bindings[index].as_ref().unwrap().prepared)
            .ok_or(Error::InvalidContext)
    }
    // The record of `owner`'s binding.
    fn binding_index(&self, owner: ConnectionId) -> Option<usize> {
        debug_assert!(self.live_bindings.matches(&self.bindings));
        let owned = |index: usize| {
            self.bindings[index]
                .as_ref()
                .is_some_and(|b| b.owner == Some(owner))
        };
        // A slot's binding is its newest committed generation's: committing
        // one frees the binding of the slot's reclaimed predecessor.
        let index = self
            .owner_bindings
            .get(owner.index())
            .copied()
            .flatten()
            .filter(|&index| owned(index));
        debug_assert_eq!(index, self.live_bindings.iter().find(|&index| owned(index)));
        index
    }
    // Whether `holders` names exactly the bindings' and flows' clients:
    // the scans it replaces, for debug assertions.
    fn holders_listed(&self) -> bool {
        let bindings = (0..self.bindings.len()).filter_map(|index| {
            let client = self.bindings[index]?.prepared.client;
            Some((client, Holder::Binding(index)))
        });
        let flows = self
            .udp
            .clients()
            .map(|(slot, client)| (client, Holder::Flow(slot)));
        let mut listed = 0;
        bindings.chain(flows).all(|(client, holder)| {
            listed += 1;
            self.holders[client.index()] == holder
        }) && self.holders.iter().filter(|&&h| h != Holder::None).count() == listed
    }
    // The record of a prepared binding no connection has committed yet.
    fn provisional(&self, prepared: PreparedPath) -> Option<usize> {
        debug_assert!(
            self.provisional
                .iter()
                .eq(self
                    .live_bindings
                    .iter()
                    .filter(|&index| self.bindings[index].unwrap().owner.is_none()))
        );
        self.provisional.iter().find(|&index| {
            self.bindings[index]
                .as_ref()
                .is_some_and(|b| b.owner.is_none() && b.prepared == prepared)
        })
    }

    /// RFC 1191 section 5's current Path MTU estimate (complete IP octets)
    /// of the path `owner` is bound to, as Linux reports a connected
    /// socket's dst_mtu through IP_MTU and IPV6_MTU: the shared estimate,
    /// trusted decreases and administrative restrictions included
    /// (`PathSnapshot::pmtu_estimate`), never the discovery-policy sending
    /// limit or the connection's own search or black-hole state. A pure
    /// read. A binding that `refresh` would move reads the path the same
    /// selection names (`PathService::resolve_via`, then the cached valid
    /// incarnation of that key); when no incarnation exists yet, or no route
    /// resolves, the connection is still bound to its path and that path's
    /// latest estimate is reported (frozen at its invalidation, decreases
    /// learned before it included), as Linux reports a socket's cached route
    /// until output revalidates it.
    pub fn path_mtu_estimate(
        &self,
        endpoint: &Endpoint,
        owner: ConnectionId,
    ) -> Result<u32, Error> {
        self.check_endpoint(endpoint)?;
        let binding = self.binding(owner)?;
        let current = endpoint.managed_path(owner)?;
        if current.binding.client != binding.client {
            return Err(Error::InvalidContext);
        }
        let via = scoped(current.forwarding_destination, current.zone)?;
        let live = self.paths.snapshot(binding.client)?;
        if live.status() == PathStatus::Valid && self.forwards_via(live.key(), via) {
            return Ok(live.pmtu_estimate()?);
        }
        let selected = self
            .request(
                live.key().source_address().address(),
                live.key().destination().address(),
                current.zone,
                live.key().dscp(),
            )
            .ok()
            .and_then(|request| self.paths.resolve_via(request, via).ok())
            .and_then(|resolved| {
                self.paths.path_administrations().find(|path| {
                    path.snapshot.key() == resolved.key()
                        && path.snapshot.status() == PathStatus::Valid
                })
            });
        Ok(match selected {
            Some(path) => path.snapshot.pmtu_estimate()?,
            None => live.last_pmtu_estimate(),
        })
    }

    /// Explicit trusted negative evidence, with RFC hold in the configured
    /// caller timebase. A fresh equal report keeps the estimate but restarts
    /// the deadline. Only `service_changes` publishing a definitely submitted
    /// probe's delivery after the hold can raise this shared ordinary ceiling.
    pub fn trusted_decrease(
        &mut self,
        now: Instant,
        path: path::PathId,
        mtu: u32,
    ) -> Result<path::EstimateChange, Error> {
        let not_before = now
            .checked_add(self.decrease_hold()?)
            .ok_or(Error::Capacity)?;
        Ok(self
            .paths
            .trusted_decrease_with_hold(path, mtu, not_before)?)
    }

    // The RFC 1191/8201 600-second hold after a decrease, in caller units.
    pub(crate) fn decrease_hold(&self) -> Result<u64, Error> {
        self.timebase
            .units_per_second
            .checked_mul(600)
            .ok_or(Error::Capacity)
    }

    /// Apply one newest snapshot then acknowledge exactly that observation.
    /// Failure (including capacity during rebind) keeps the dirty notification.
    pub fn refresh(
        &mut self,
        endpoint: &mut Endpoint,
        owner: ConnectionId,
    ) -> Result<PreparedPath, Error> {
        self.check_endpoint(endpoint)?;
        let index = self.binding_index(owner).ok_or(Error::InvalidContext)?;
        let current = endpoint.managed_route(owner)?;
        self.refresh_route(endpoint, owner, index, current)?;
        Ok(self.bindings[index].as_ref().unwrap().prepared)
    }
    // `refresh` of `owner`'s binding record `index`, the connection's route
    // as the Endpoint reports it now being `current`. The record then holds
    // the refreshed path.
    fn refresh_route(
        &mut self,
        endpoint: &mut Endpoint,
        owner: ConnectionId,
        index: usize,
        current: ManagedRoute,
    ) -> Result<(), Error> {
        let binding = self.bindings[index].as_ref().unwrap();
        let mut client = binding.prepared.client;
        if current.client != client {
            return Err(Error::InvalidContext);
        }
        // The decision checked for these inputs, while its cookie holds.
        if let Some(dst) = self.held_dst(binding, &current) {
            debug_assert_eq!(
                self.current_checks(endpoint, owner, &binding.prepared, &current),
                Ok(Some(dst.port))
            );
            debug_assert_eq!(self.paths.is_dirty(client), Ok(false));
            return Ok(());
        }
        if let Some(port) = self.current_checks(endpoint, owner, &binding.prepared, &current)? {
            let stamp = binding.prepared.snapshot.stamp();
            self.paths.acknowledge(client, stamp)?;
            self.bindings[index].as_mut().unwrap().dst = Some(Dst {
                stamp,
                client,
                dscp: current.dscp,
                zone: current.zone,
                forwarding_destination: current.forwarding_destination,
                ip_header_len: current.ip_header_len,
                port,
            });
            return Ok(());
        }
        let via = scoped(current.forwarding_destination, current.zone)?;
        let mut snapshot = self.paths.snapshot(client)?;
        // A validated peer return-route update need not invalidate the old
        // routing entry, so compare the actual outgoing selection as well.
        if snapshot.status() != PathStatus::Valid || !self.forwards_via(snapshot.key(), via) {
            let request = self.request(
                snapshot.key().source_address().address(),
                snapshot.key().destination().address(),
                current.zone,
                snapshot.key().dscp(),
            )?;
            let resolved = self.paths.resolve_via(request, via)?;
            self.forwarding_resolved(resolved.key())?;
            let (rebound_client, rebound) =
                self.paths.rebind_resolved(client, request, via, resolved)?;
            client = rebound_client;
            let now = self.now;
            self.bindings[index].as_mut().unwrap().rebind(
                PreparedPath {
                    client,
                    snapshot: rebound,
                },
                now,
            );
            snapshot = rebound;
        }
        self.forwarding(&snapshot)?;
        let prepared = PreparedPath { client, snapshot };
        // The connection's complete headers (an SR route's Segment Routing
        // Header included) must still fit the path: a header that no longer
        // does fails admission rather than being cut.
        endpoint.validate_path_budget(owner, &prepared)?;
        endpoint.apply_path_budget(owner, prepared)?;
        let now = self.now;
        self.bindings[index].as_mut().unwrap().rebind(prepared, now);
        self.paths.acknowledge(prepared.client, snapshot.stamp())?;
        Ok(())
    }

    // `binding`'s egress decision, if it still holds for the connection's
    // route `current`.
    fn held_dst(&self, binding: &Binding, current: &ManagedRoute) -> Option<Dst> {
        let dst = binding.dst?;
        let stamp = self.paths.stamp(binding.prepared.client).ok()?;
        (dst.holds(&binding.prepared, stamp, current)
            && self.ports[dst.port]
                .is_some_and(|port| port.link == binding.prepared.snapshot.key().link()))
        .then_some(dst)
    }
    // Whether `refresh` of `owner` would take its held egress decision now.
    #[cfg(test)]
    fn dst_held(&self, endpoint: &Endpoint, owner: ConnectionId) -> bool {
        let binding = self.bindings[self.binding_index(owner).unwrap()]
            .as_ref()
            .unwrap();
        self.held_dst(binding, &endpoint.managed_route(owner).unwrap())
            .is_some()
    }

    // The checks `refresh` makes of a binding `prepared` whose observation
    // is current, the connection's route being `current`: its port's slot
    // when they pass, None when the binding is not current (to be brought
    // up to date). The Host stored, and the Endpoint applied under the
    // path's class, the client's current observation (a stamp names one
    // snapshot) on the outgoing selection the connection still uses:
    // nothing to rebind or apply, only the checks of any use. A pure read.
    fn current_checks(
        &self,
        endpoint: &Endpoint,
        owner: ConnectionId,
        prepared: &PreparedPath,
        current: &ManagedRoute,
    ) -> Result<Option<usize>, Error> {
        let via = scoped(current.forwarding_destination, current.zone)?;
        let stamp = self.paths.stamp(prepared.client)?;
        if prepared.snapshot.stamp() != stamp
            || current.stamp != stamp
            || current.dscp != prepared.snapshot.key().dscp().value()
            || prepared.snapshot.status() != PathStatus::Valid
            || !self.forwards_via(prepared.snapshot.key(), via)
        {
            return Ok(None);
        }
        debug_assert_eq!(self.paths.snapshot(prepared.client), Ok(prepared.snapshot));
        let port = self.forwarding_slot(&prepared.snapshot)?;
        endpoint.validate_path_budget(owner, prepared)?;
        Ok(Some(port))
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
        let via = scoped(old.forwarding_destination, old.zone)?;
        let resolved = self.paths.resolve_via(request, via)?;
        self.forwarding_resolved(resolved.key())?;
        let (client, snapshot) =
            self.paths
                .rebind_resolved(binding.client, request, via, resolved)?;
        let prepared = PreparedPath { client, snapshot };
        // The same source/destination/context was preflighted above. Core's
        // application does no allocation and permits this exact rebind.
        endpoint
            .apply_path_budget(owner, prepared)
            .expect("preflighted path rebind");
        let index = self.binding_index(owner).unwrap();
        let now = self.now;
        self.bindings[index].as_mut().unwrap().rebind(prepared, now);
        self.paths.acknowledge(client, snapshot.stamp())?;
        Ok(())
    }

    /// Bounded sweep also visits detached/released generations. No fd/accept
    /// lifetime participates. Reserved output pins its owner independently.
    pub fn refresh_all(&mut self, endpoint: &mut Endpoint) -> Result<(), Error> {
        self.collect(endpoint)?;
        let mut first = None;
        for index in 0..self.bindings.len() {
            if let Some(owner) = self.bindings[index].as_ref().and_then(|b| b.owner)
                && let Err(error) = self.refresh(endpoint, owner)
            {
                first.get_or_insert(error);
            }
        }
        first.map_or(Ok(()), Err)
    }

    /// The change service: one bounded pass, run by an embedding before it
    /// selects output. First publish each live connection's unpublished
    /// results (an applied deferred decrease, a confirmed probe), then bring
    /// every dirty client to its newest snapshot and acknowledge exactly that
    /// stamp: a TCP binding by budget-only application (no repair; allowed
    /// while its output is reserved, held frames still meet the submit-time
    /// barrier), a UDP flow by updating its coalesced change notification.
    /// Output leases stay lazy: `egress_context` refreshes them before use.
    /// A failing client stays dirty and never stops service of the others.
    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
    //= reason=PathService marks every client of a path dirty on each trusted decrease and on link MTU, route, source, link or plateau changes. Host::service_changes, run on every native service_egress and MTU-refresh pass and every tun_echo transmit pass, brings each dirty TCP binding (reserved owners included, budget only, no repair) and each Host UDP flow (a coalesced per-flow change slot carrying MMS_S and the payload limit) to the newest snapshot and acknowledges exactly that version; a failing client stays dirty without stopping the others, and stateless leases and every physical submission revalidate against the current version. Dual-family Host tests (two TCP flows plus a UDP flow, held scalar, zero-copy and partial software GSO reservations, a randomized multi-client model), native reservation-race tests and the isolated namespace shared-fanout case, in which a real router PTB quotes only TCP flow A, verify it.
    //# The packetization layers must be notified about decreases in the PMTU. Any packetization layer instance (for example, a TCP connection) that is actively using the path must be notified if the PMTU estimate is decreased.
    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.2
    //= reason=PathService marks every client of a path dirty on each trusted decrease and on link MTU, route, source, link or plateau changes. Host::service_changes, run on every native service_egress and MTU-refresh pass and every tun_echo transmit pass, brings each dirty TCP binding (reserved owners included, budget only, no repair) and each Host UDP flow (a coalesced per-flow change slot carrying MMS_S and the payload limit) to the newest snapshot and acknowledges exactly that version; a failing client stays dirty without stopping the others, and stateless leases and every physical submission revalidate against the current version. Dual-family Host tests (two TCP flows plus a UDP flow, held scalar, zero-copy and partial software GSO reservations, a randomized multi-client model), native reservation-race tests and the isolated namespace shared-fanout case, in which a real router PTB quotes only TCP flow A, verify it.
    //# The packetization layers must be notified about decreases in the PMTU. Any packetization layer instance (for example, a TCP connection) that is actively using the path must be notified if the PMTU estimate is decreased.
    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
    //= reason=A correlated router PTB quoting a Host UDP datagram publishes the decrease to the shared path, and Host::service_changes then applies it to every TCP connection bound to that path (budget only, no repair) on the next native or tun_echo service pass, before any TCP output. Dual-family Host tests and the tun_echo and isolated namespace udp-quoted cases verify it. Sentence continuation is preserved in 1191-060.
    //# Note: even if the Datagram Too Big message contains an Original Datagram Header that refers to a UDP packet, the TCP layer must be notified if any of its connections use the given
    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.2
    //= reason=A correlated router PTB quoting a Host UDP datagram publishes the decrease to the shared path, and Host::service_changes then applies it to every TCP connection bound to that path (budget only, no repair) on the next native or tun_echo service pass, before any TCP output. Dual-family Host tests and the tun_echo and isolated namespace udp-quoted cases verify it.
    //# Note: even if the Packet Too Big message contains an Original Packet Header that refers to a UDP packet, the TCP layer must be notified if any of its connections use the given path.
    pub fn service_changes(
        &mut self,
        endpoint: &mut Endpoint,
        now: Instant,
    ) -> Result<ServiceReport, Error> {
        self.collect(endpoint)?;
        // Each pass runs only when its producer left it work: an assembly
        // held, an adjunct path table, a binding listed.
        if self.reassembly.holds() {
            self.expire_reassembly(now);
        }
        if self.adjunct.enabled() {
            self.service_adjunct(now);
        }
        let mut report = ServiceReport::default();
        // Connections created after an owner aging change adopt it here,
        // before their first output selection.
        let mut next = 0;
        while self.unaged.len() != 0
            && let Some(index) = self.unaged.next(next)
        {
            next = index + 1;
            let owner = self.bindings[index].as_ref().and_then(|b| b.owner).unwrap();
            match self.apply_search_aging(endpoint, now, owner) {
                Ok(()) => self.unaged.remove(index),
                Err(error) => report.fail(error),
            }
        }
        self.take_progress(endpoint);
        let mut next = 0;
        while self.unpublished.len() != 0
            && let Some(index) = self.unpublished.next(next)
        {
            next = index + 1;
            let owner = self.bindings[index].as_ref().and_then(|b| b.owner).unwrap();
            match self.publish_results(endpoint, now, owner, &mut report) {
                Ok(()) => self.unpublished.remove(index),
                Err(error) => report.fail(error),
            }
        }
        debug_assert!(self.holders_listed());
        // The path service queues each client it makes dirty. A pass serves
        // those queued when it began: a TCP binding's by budget-only
        // application, a datagram flow's by its change notification. One
        // that fails stays dirty and is queued again for the next pass.
        for _ in 0..self.paths.queued_dirty() {
            let Some(client) = self.paths.take_dirty() else {
                continue;
            };
            let served = match self.holders[client.index()] {
                Holder::Binding(index) => {
                    let binding = self.bindings[index].unwrap();
                    debug_assert_eq!(binding.prepared.client, client);
                    match binding.owner {
                        Some(owner) => self.refresh(endpoint, owner).map(|_| true),
                        // Not yet committed: served once it is.
                        None => Ok(false),
                    }
                }
                Holder::Flow(slot) => self.udp_service(slot),
                Holder::None => continue,
            };
            match served {
                Ok(true) => report.applied += 1,
                Ok(false) => {}
                Err(error) => report.fail(error),
            }
            // A client rebound before its service failed is stale: the
            // rebind queued its successor.
            if !matches!(served, Ok(true))
                && let Err(error) = self.paths.requeue_dirty(client)
                && error != path::Error::StaleHandle
            {
                return Err(error.into());
            }
        }
        Ok(report)
    }

    // Each result is taken exactly once; a stale one publishes nothing.
    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
    //= reason=PathService keeps per-host learned estimates keyed by the path, created on first use with the current route's first hop, and never changes forwarding routes. Host ICMP dispatch derives the estimate from a nonzero Next-Hop MTU or the RFC1191 section 5 plateau below the quoted length, corrected against the Host's shared path estimate, RFC 1191 section 5's current PMTU estimate, never the connection's estimate, requires a correlated quote (for a TCP connection, its four-tuple and an in-window quoted sequence, RFC 5927 section 4.1 as Linux checks it, about the connection's current path; otherwise committed submission evidence of a stateless reply or datagram) and lowers the per-host record only when lower. A correlated TCP report about the connection's current path at or above its proven delivery lowers the record at once (the larger of the Host and TCP estimates) and otherwise restarts its hold. One below proven delivery is deferred whatever the connection's loss-inferred estimate and changes nothing shared (no decrease, hold restart or notification) until the connection applies exactly that report at the quoted data's timeout; Host::service_changes then publishes the larger of the Host estimate and the report's own policy-derived size, so a loss-inferred value never leaks. Cumulative progress past the quoted data refutes it, and released owners, rebound paths and subsumed results publish nothing. Stale or evicted path incarnations are never resurrected or changed. Dual-family Host tests (including legacy IPv4 reports without a Next-Hop MTU, compared with and without prior black-hole loss inference: identical derived size, deferral and publication) and real router PTBs in the isolated namespace gate verify it.
    //# When a Datagram Too Big message is received, the ICMP layer determines a new estimate for the Path MTU (either from a non-zero Next-Hop MTU value in the packet, or using the method described in section 5). If a per-host route for this path does not exist, then one is created (almost as if a per-host ICMP Redirect is being processed; the new route uses the same first-hop router as the current route). If the PMTU estimate associated with the per-host route is higher than the new estimate, then the value in the routing entry is changed.
    fn publish_results(
        &mut self,
        endpoint: &mut Endpoint,
        now: Instant,
        owner: ConnectionId,
        report: &mut ServiceReport,
    ) -> Result<(), Error> {
        if live(endpoint.has_unpublished_results(owner))? != Some(true) {
            return Ok(());
        }
        if let Some(Some(result)) = live(endpoint.take_pending_pmtu_applied(owner))?
            && self.publish_applied(now, owner, result)? == Some(path::EstimateChange::Decreased)
        {
            report.decreased += 1;
        }
        if let Some(Some(probe)) = live(endpoint.take_confirmed_probe(owner))?
            && self.publish_confirmed(now, owner, probe)?
                == Some(path::DeliveryConfirmation::Raised)
        {
            report.raised += 1;
        }
        Ok(())
    }

    // A deferred report the connection applied at the quoted data's timeout
    // becomes a shared fact only for the owner's unchanged binding and valid
    // path incarnation, under the same rule as an immediate decrease: the
    // larger of the Host estimate and the report's own policy-derived size,
    // so a lower loss-inferred connection estimate never leaks. A
    // decrease needs no negative-revision equality: it applies monotonically,
    // and a result the current ceiling already subsumes is discarded rather
    // than restarting the hold as a fresh report would.
    fn publish_applied(
        &mut self,
        now: Instant,
        owner: ConnectionId,
        result: ntcp::PendingPmtuApplied,
    ) -> Result<Option<path::EstimateChange>, Error> {
        let (binding, origin) = (self.binding(owner)?, result.binding());
        let path = origin.snapshot.path();
        let Some(snapshot) = self
            .paths
            .path_snapshot(path)
            .ok()
            .filter(|s| s.status() == PathStatus::Valid)
        else {
            return Ok(None);
        };
        let mtu = result.host_estimate().max(result.applied_mtu());
        if binding.client != origin.client
            || binding.snapshot.path() != path
            || mtu >= result.report().segment.ip_packet_len
            || snapshot.learned_mtu().is_some_and(|learned| mtu >= learned)
        {
            return Ok(None);
        }
        Ok(Some(self.trusted_decrease(now, path, mtu)?))
    }

    // Delivery of a definitely submitted, unfragmented probe of exactly the
    // confirmed length, selected after the hold under the current negative
    // revision on this owner's unchanged binding (RFC 4821 section 5.2: a
    // network fact other packetization layers may share). The path service
    // rechecks revision, hold and first hop at publication time. Other
    // clients receive ordinary permission only, never local delivery proof.
    fn publish_confirmed(
        &mut self,
        now: Instant,
        owner: ConnectionId,
        probe: ntcp::ConfirmedProbe,
    ) -> Result<Option<path::DeliveryConfirmation>, Error> {
        let (binding, intent) = (self.binding(owner)?, probe.intent());
        let selected = intent.binding();
        if binding.client != selected.client
            || binding.snapshot.path() != selected.snapshot.path()
            || probe.receipt().ip_packet_len != intent.ip_packet_len()
        {
            return Ok(None);
        }
        // A size result selected under another discovery policy, or on a
        // path whose owner has since disabled discovery, publishes nothing.
        if self
            .paths
            .path_snapshot(selected.snapshot.path())
            .is_ok_and(|live| {
                live.discovery_disabled()
                    || live.discovery_revision() != selected.snapshot.discovery_revision()
            })
        {
            return Ok(None);
        }
        match self.paths.confirm_delivery(
            selected.snapshot.path(),
            intent.ip_packet_len(),
            selected.snapshot.negative_revision(),
            intent.selected_at(),
            now,
        ) {
            Ok(outcome) => Ok(Some(outcome)),
            // An invalidated or replaced path incarnation is stale evidence.
            Err(
                path::Error::Invalidated
                | path::Error::StaleHandle
                | path::Error::NoRoute
                | path::Error::SelectionChanged,
            ) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn collect(&mut self, endpoint: &Endpoint) -> Result<(), Error> {
        self.check_endpoint(endpoint)?;
        // A committed binding outlives its connection until the endpoint
        // reclaims it (and a reclaimed connection holds no reservation):
        // free those of the connections reclaimed since the last collection,
        // each the one its slot names, or, past what the endpoint keeps of
        // them, of every connection gone.
        let reclaimed = endpoint.reclaimed();
        // Nothing reclaimed since the last collection frees nothing.
        if reclaimed != self.reclaimed {
            if let Some(gone) = endpoint.reclaimed_since(self.reclaimed) {
                for id in gone {
                    #[cfg(test)]
                    {
                        self.collect_visits += 1;
                    }
                    if let Some(index) = self.owner_bindings[id.index()]
                        && self.bindings[index].as_ref().unwrap().owner == Some(id)
                    {
                        self.free_binding(index)?;
                    }
                }
            } else {
                let mut next = 0;
                while let Some(index) = self.live_bindings.next(next) {
                    next = index + 1;
                    #[cfg(test)]
                    {
                        self.collect_visits += 1;
                    }
                    if let Some(id) = self.bindings[index].as_ref().and_then(|b| b.owner)
                        && !endpoint.connection_exists(id)
                    {
                        self.free_binding(index)?;
                    }
                }
            }
        }
        for lease in &mut self.leases {
            if lease
                .as_ref()
                .is_some_and(|l| endpoint.transmit_attempt_packet(l.attempt).is_none())
            {
                self.paths.release(lease.take().unwrap().prepared.client)?;
            }
        }
        debug_assert!(lists_free(&self.free_bindings, &self.bindings));
        self.reclaimed = reclaimed;
        if self.ledger.due(self.now) {
            self.maintain_ledger(endpoint);
        }
        Ok(())
    }

    // Free the committed binding `index`, whose connection the endpoint has
    // reclaimed.
    fn free_binding(&mut self, index: usize) -> Result<(), Error> {
        let binding = self.bindings[index].take().unwrap();
        let owner = binding.owner.unwrap();
        self.live_bindings.remove(index);
        self.free_bindings.push(index);
        for set in [&mut self.unaged, &mut self.unpublished] {
            if set.contains(index) {
                set.remove(index);
            }
        }
        debug_assert_eq!(self.owner_bindings[owner.index()], Some(index));
        self.owner_bindings[owner.index()] = None;
        self.holders[binding.prepared.client.index()] = Holder::None;
        self.paths.release(binding.prepared.client)?;
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

    // Reclaim reservations no call can use, and drop expired evidence.
    fn maintain_ledger(&mut self, endpoint: &Endpoint) {
        let mut next = 0;
        while let Some(index) = self.ledger.next_pending(next) {
            next = index + 1;
            let pending = self.ledger.pending(index).unwrap();
            if pending
                .attempt
                .is_some_and(|attempt| endpoint.transmit_attempt_packet(attempt).is_none())
            {
                self.ledger.drop_pending(index);
            }
        }
        self.ledger.expire(self.now);
    }

    // What the endpoint reports of its connections since last asked: newly
    // acknowledged data confirms its neighbor at once, as Linux confirms a
    // route's neighbor in tcp_ack, and results wait for the next service
    // pass.
    fn take_progress(&mut self, endpoint: &mut Endpoint) {
        while let Some((owner, delivered)) = endpoint.next_progress() {
            let Some(index) = self.binding_index(owner) else {
                continue;
            };
            if let Some(sent) = delivered {
                self.confirm_progress(index, sent);
            }
            if !self.unpublished.contains(index)
                && endpoint.has_unpublished_results(owner) == Ok(true)
            {
                self.unpublished.insert(index);
            }
        }
    }
    // RFC 4861 section 7.3.1 forward progress: the peer acknowledged data
    // its owner last sent at `sent`, through the binding's neighbor if the
    // binding had not moved since. The neighbor table refuses data sent
    // before its current mapping (`confirm`).
    fn confirm_progress(&mut self, index: usize, sent: Instant) {
        let binding = self.bindings[index].as_ref().unwrap();
        let snapshot = binding.prepared.snapshot;
        if binding.moved.is_some_and(|moved| sent <= moved)
            || snapshot.status() != PathStatus::Valid
        {
            return;
        }
        let ResolvedNextHop::Address(next_hop) = snapshot.key().next_hop() else {
            return;
        };
        let link = snapshot.key().link();
        // A confirmation without entropy for its ReachableTime is lost, like
        // an unsent hint; NUD then probes.
        let _ = match next_hop.address() {
            IpAddr::V6(next_hop) => {
                self.neighbors
                    .confirm(link, next_hop, sent, self.now, self.entropy.as_mut())
            }
            IpAddr::V4(next_hop) => self.ipv4_neighbors.table_mut().confirm(
                link,
                next_hop,
                sent,
                self.now,
                self.entropy.as_mut(),
            ),
        };
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
        match self.ledger.reserve(index, attempt) {
            Err(Error::Capacity) => {
                self.maintain_ledger(endpoint);
                self.ledger.reserve(index, attempt)
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
        let local = LocalDestination {
            link: context.link,
            address: destination,
            revision: self.paths.revision(),
        };
        if self.local.get() == Some(local) {
            debug_assert!(self.local_on_link(context.link, destination).is_ok());
            return Ok(());
        }
        self.local_on_link(context.link, destination)?;
        self.local.set(Some(local));
        Ok(())
    }
    fn local_on_link(&self, link: LinkId, destination: IpAddr) -> Result<(), Error> {
        let zone = match destination {
            IpAddr::V6(v) if v.is_unicast_link_local() => Some(link),
            _ => None,
        };
        self.paths
            .local_source(ScopedAddress::new(destination, zone)?, link)?;
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
        // A source owned on any link is owned in the context.
        let revision = self.paths.revision();
        if let Some(local) = self.local.get()
            && local.address == destination
            && local.revision == revision
        {
            debug_assert!(self.local_on_link(local.link, destination).is_ok());
            return Ok(());
        }
        let address = ScopedAddress::new(destination, None)?;
        let Some(port) = self
            .ports
            .iter()
            .flatten()
            .find(|port| self.paths.local_source(address, port.link).is_ok())
        else {
            return Err(path::Error::NoRoute.into());
        };
        self.local.set(Some(LocalDestination {
            link: port.link,
            address: destination,
            revision,
        }));
        Ok(())
    }
    fn parse_ingress<'a>(
        &self,
        context: IngressContext,
        frame: &'a [u8],
    ) -> Result<IngressPacket<'a>, Error> {
        self.parse_ingress_limited(context, frame, None, false)
    }
    // One complete (never fragmented) datagram: an arriving packet within
    // the link's physical limit, or a reassembled one within `reassembled`.
    // `received`: from `receive`, which verified its IPv4 header checksum.
    fn parse_ingress_limited<'a>(
        &self,
        context: IngressContext,
        frame: &'a [u8],
        reassembled: Option<usize>,
        received: bool,
    ) -> Result<IngressPacket<'a>, Error> {
        let capabilities = self.port(context.link)?.receive;
        if frame.len() > reassembled.unwrap_or(capabilities.max_ip_packet) {
            return Err(Error::Unsupported);
        }
        let packet = match frame.first().ok_or(ntcp_ip::Error::Truncated)? >> 4 {
            4 => {
                let source_routes = capabilities
                    .ipv4
                    .source_routes()
                    .ok_or(Error::Unsupported)?;
                let packet = if received {
                    ntcp_ip::parse_received(frame, source_routes)?
                } else {
                    ntcp_ip::parse(frame, source_routes)?
                };
                IngressPacket {
                    ip: packet.ip,
                    traffic_class: packet.traffic_class,
                    protocol: packet.protocol,
                    options: packet.ipv4_options,
                    payload: packet.payload,
                }
            }
            6 if capabilities.ipv6 == Ipv6Receive::BaseHeader => {
                let packet = ntcp_ip6::parse(frame)?;
                // This profile has no extension header receive processing.
                if !packet.base_layout() {
                    return Err(ntcp_ip::Error::ExtensionsUnsupported.into());
                }
                IngressPacket {
                    ip: packet.ip,
                    traffic_class: packet.traffic_class,
                    protocol: packet.protocol,
                    options: Ipv4Options::default(),
                    payload: packet.payload,
                }
            }
            // The chain's receive processing again, without errors: a
            // datagram from `receive` passes it unchanged, and anything else
            // is refused here as it would have been there.
            6 if capabilities.ipv6 == Ipv6Receive::Extensions => {
                let packet = ntcp_ip6::parse(frame)?;
                if !ingress::processed_upper_layer(packet.protocol) {
                    return Err(ntcp_ip::Error::ExtensionsUnsupported.into());
                }
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

    /// One physical packet arriving by link-layer unicast: `receive`
    /// (framing, local authority, reassembly), destination processing
    /// (`process`) and then, for a complete datagram, `input_datagram`; a
    /// fragment held for reassembly is Processed, one it discarded Dropped,
    /// as is a datagram whose Timestamp option cannot be advanced.
    ///
    /// Quoted options remain historical data inside the ICMP decoder and are
    /// never recorded as present-day destination options. `timestamp` is the
    /// caller-asserted wire value written to an eligible Timestamp slot when
    /// interpretation is enabled (`Ipv4Options::record`): the caller's
    /// explicit low-level clock contract, not a UTC guarantee. Without one,
    /// Record Route is still recorded and the Timestamp option kept as it
    /// arrived.
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
        // The completion buffer leaves the Host for the dispatch below, which
        // never reassembles, and is always restored.
        let mut completed = core::mem::take(&mut self.completed);
        let result = match self.receive(context, now, frame, false, &mut completed) {
            Ok(Received::Datagram(datagram)) => {
                match self.process_clock(datagram, ingress::Clock::Asserted(timestamp)) {
                    Ok(Some(processed)) => {
                        self.input_datagram(endpoint, now, processed, metadata, outgoing_dscp)
                    }
                    Ok(None) => {
                        self.drops.record(ntcp::DropReason::IpInhdr, now, frame.len(), || {
                            ntcp::DropSubject::of_ip_packet(frame)
                        });
                        Ok(ntcp::InputDisposition::Dropped)
                    }
                    Err(error) => Err(error),
                }
            }
            Ok(Received::Held | Received::Neighbor | Received::Redirect(_)) => {
                Ok(ntcp::InputDisposition::Processed)
            }
            Ok(Received::Discarded) => Ok(ntcp::InputDisposition::Dropped),
            Err(error) => Err(error),
        };
        self.completed = completed;
        result
    }

    // UDP and TCP input of one processed complete datagram: its options are
    // the result of destination processing, never recorded again here.
    fn input_transport(
        &mut self,
        endpoint: &mut Endpoint,
        now: Instant,
        context: IngressContext,
        packet: &IngressPacket,
        metadata: RxPacketMetadata,
        outgoing_dscp: u8,
    ) -> Result<ntcp::InputDisposition, Error> {
        self.owned_on_link(context, packet.ip.destination)?;
        if metadata.tcp_segment_size.is_some() && !self.port(context.link)?.receive.gro {
            return Err(Error::Unsupported);
        }
        if packet.protocol == ntcp_ip::PROTOCOL_UDP && metadata.tcp_segment_size.is_none() {
            return Ok(self.input_udp(endpoint, context.link, packet));
        }
        if packet.protocol == 6 {
            // Bindings cover every Endpoint slot plus one provisional factory,
            // so a full table can only hold generations this embedding has not
            // yet collected. Reclaim them before a factory needs one, rather
            // than reporting admissible input as a capacity failure.
            if self.live_bindings.len() == self.bindings.len() {
                self.collect(endpoint)?;
            }
            let disposition = endpoint.input_with_path_provider(
                now,
                context.link,
                packet.ip,
                packet.traffic_class,
                packet.options,
                packet.payload,
                metadata,
                outgoing_dscp,
                self,
            )?;
            self.take_progress(endpoint);
            Ok(disposition)
        } else {
            let (ip, protocol) = (packet.ip, packet.protocol);
            self.drops.record_error(
                ntcp::DropReason::IpNoproto,
                now,
                packet.payload.len(),
                || ntcp::DropSubject::Ip {
                    source: ip.source,
                    destination: ip.destination,
                    protocol,
                },
            );
            Err(Error::Unsupported)
        }
    }

    /// The single ICMP classification/dispatch path. The error is admitted on
    /// any registered link of this context when its destination is an
    /// unscoped registered source. A TCP quote is then about the managed
    /// connection of its scoped four-tuple when that connection's sent
    /// sequence space holds the quoted sequence (RFC 5927 section 4.1, as
    /// Linux checks it), on the connection's current path; connections keep
    /// no per-segment evidence. Any other quote, and a TCP quote no
    /// connection accepts, is correlated with the submission ledger, which
    /// holds the stateless replies and Host datagrams (context, family,
    /// canonical source/final destination, complete header and packet
    /// lengths, protocol and transport selector; for a quoted source
    /// fragment, its UDP header at offset zero or else its offset, MF and
    /// every recorded leading data octet, never ports). Quoted TTL/hop limit,
    /// ECN, DSCP and IPv4 identification are not compared: routers may
    /// rewrite the first three, and an atomic datagram's identification
    /// carries no meaning (RFC 6864 section 4.1). Options were validated
    /// structurally by the codec, not compared with historical bytes.
    ///
    /// Either check is plausibility against off-path forgery, not
    /// authentication: an attacker holding a connection's four-tuple and an
    /// in-window sequence, or the exact quote of a datagram, can act as the
    /// router that sent it. Ledger policy: only exact evidence (a live entry
    /// or exact evicted-datagram signature matching every selector field) is
    /// positive; lossy history only denies. Path-level effects require an
    /// exact match and every match and lossy hit to agree on one path
    /// incarnation; owner-level effects require one owner generation and one
    /// submission, with no lossy hit. A TCP owner's policy runs first and a
    /// shared estimate is published only for its current-path Decreased or
    /// Unchanged disposition (never for Deferred). A reserved owner is
    /// returned as Deferred, carrying the normalized report, before anything
    /// is applied. Quotes neither check accepts are discarded. `frame` is one
    /// unfragmented packet, given
    /// destination processing (`process`) with time from `timestamps`, which
    /// is sampled at most once and only for a Timestamp slot this host may
    /// write; an Echo Request is answered by the Echo service
    /// (`input_icmp_datagram`).
    pub fn input_icmp(
        &mut self,
        endpoint: &mut Endpoint,
        context: IngressContext,
        now: Instant,
        frame: &[u8],
        timestamps: Option<&mut dyn ntcp::Ipv4TimestampProvider>,
    ) -> Result<IcmpDispatch, Error> {
        let datagram = Envelope::physical(context, frame.len(), false)
            .datagram(frame)
            .ok_or(Error::Obsolete)?;
        let processed = self.process(datagram, timestamps).inspect_err(|error| {
            if let Error::Codec(error) = *error
                && frame.first().is_some_and(|b| b >> 4 == 4)
            {
                self.count_header_error(frame, error);
            }
        })?;
        self.input_icmp_datagram(endpoint, now, processed)
    }

    /// Apply a deferred report to its owner generation, or defer it again
    /// while that owner's output is still reserved. The report was validated
    /// and correlated on arrival; it needs neither the frame nor any record
    /// of the quoted segment. A generation that no longer exists makes it Stale; TCP rejects
    /// a quote no longer overlapping outstanding data; a path incarnation that
    /// is no longer the owner's valid binding leaves drop advice only, with
    /// nothing published.
    pub fn replay_icmp(
        &mut self,
        endpoint: &mut Endpoint,
        deferred: DeferredIcmp,
        now: Instant,
    ) -> Result<IcmpDispatch, Error> {
        self.check_endpoint(endpoint)?;
        if deferred.context.context() != self.paths.context() {
            return Err(Error::InvalidContext);
        }
        self.now = self.now.max(now);
        let dispatch = self.tcp_report(endpoint, now, deferred)?;
        self.record_icmp_outcome(now, &dispatch, &[]);
        Ok(dispatch)
    }

    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.2
    //= reason=The Host dispatcher notifies the specific correlated sender while processing the report: TCP consumes PmtuFeedback drop advice and a Host UDP flow receives UdpEvent::PacketTooBig, whether or not the estimate changes. Path-level change notification is separate: a shared decrease marks the path's clients dirty, and Host::service_changes then brings every other user to the new budget (TCP budget application, the UDP flow change slot) on the next service pass. Dual-family TUN tests consume the UDP event immediately and observe the TCP flow adopt the shared decrease after the next service pass.
    //# It is important to understand that the notification of the packetization
    //# layer instances using the path about the change in the PMTU is distinct from
    //# the notification of a specific instance that a packet has been dropped. The
    //# latter should be done as soon as practical (i.e., asynchronously from the
    //# point of view of the packetization layer instance), while the former may be
    //# delayed until a packetization layer instance wants to create a packet.
    fn dispatch_icmp(
        &mut self,
        endpoint: &mut Endpoint,
        now: Instant,
        context: IngressContext,
        packet: &IngressPacket,
    ) -> Result<IcmpDispatch, Error> {
        use IcmpDispatch::Completed;
        use IcmpOutcome::Discarded;
        self.owned_in_context(context, packet.ip.destination)?;
        let feedback = icmp_feedback(packet)?;
        // RFC 6633: after wire validation, before correlation, clock
        // advancement or any access to a possibly reserved owner.
        if feedback.kind == FeedbackKind::SourceQuench {
            return Ok(Completed(Discarded(IcmpDiscard::SourceQuench)));
        }
        self.now = self.now.max(now);
        let quote = feedback.quoted;
        let key = quote_key(&quote);
        let ptb = feedback.kind == FeedbackKind::PacketTooBig;
        let candidate = feedback.candidate_mtu;
        // The decoder requires the outer destination to be the quoted
        // source: a link-local one is the address of the arrival link, which
        // constrains the candidates. Unscoped quotes search every link, the
        // outgoing link coming only from the connection or ledger evidence.
        let scoped = matches!(quote.ip.source, IpAddr::V6(v) if v.is_unicast_link_local());
        let zone = scoped.then_some(context.link);
        let ipv4 = quote.ip.source.is_ipv4();
        // RFC 5927 section 4.1, as Linux: a TCP quote is about the connection
        // of its scoped tuple whose sent sequence space holds the quoted
        // sequence, and that connection's policy then judges it. Connections
        // keep no per-segment evidence; a quote none accepts may still name
        // a stateless reply in the ledger.
        if let Some((owner, mut segment, path)) = self.tcp_quote(endpoint, &key, zone) {
            if !self.quote_authorized(path, packet.payload) {
                return Ok(Completed(Discarded(IcmpDiscard::Uncorrelated)));
            }
            //= https://www.rfc-editor.org/rfc/rfc1191#section-5
            //# If the Total Length field returned is
            //# not less than the current PMTU estimate, it must be reduced by
            //# 4 times the value of the returned Header Length field.
            if ptb
                && ipv4
                && candidate.is_none()
                && self
                    .paths
                    .path_snapshot(path)
                    .is_ok_and(|s| s.pmtu_estimate().is_ok_and(|e| key.packet_len >= e))
                && let Some(packet_len) = key
                    .packet_len
                    .checked_sub(key.header_len)
                    .filter(|len| *len >= key.header_len + 20)
            {
                segment.ip_packet_len = packet_len;
            }
            let kind = if ptb {
                CorrelatedKind::PacketTooBig {
                    quoted_packet_len: key.packet_len,
                    candidate,
                }
            } else {
                let Some(error) = feedback
                    .ipv4_network_error()
                    .or_else(|| feedback.ipv6_network_error())
                else {
                    return Ok(Completed(Discarded(IcmpDiscard::Implausible)));
                };
                CorrelatedKind::NetworkError(error)
            };
            let report = Correlated {
                segment,
                path: Some(path),
                ipv4,
                kind,
            };
            return self.tcp_report(
                endpoint,
                now,
                DeferredIcmp {
                    context,
                    owner,
                    report,
                },
            );
        }
        let exact = self.ledger.correlate_in(now, &key, zone);
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
                .checked_sub(key.header_len)
                .filter(|len| *len >= key.header_len + 20)
        {
            let corrected = self.ledger.correlate_in(now, &QuoteKey { packet_len, ..key }, zone);
            if corrected.matches != 0 {
                dropped = Some(dropped.map_or(packet_len, |len| len.min(packet_len)));
            }
            correlation = correlation.either(corrected);
        }
        let Some(dropped) = dropped else {
            // The Host's own Echo probes are not in the ledger: their
            // identifier, sequence and exact length match the adjunct.
            if let Some(outcome) = self.adjunct_error(now, packet.payload, &feedback)? {
                return Ok(Completed(IcmpOutcome::Probe(outcome)));
            }
            return Ok(Completed(Discarded(IcmpDiscard::Uncorrelated)));
        };
        // Before any positive use, the quoted header plan must be the one
        // the route generation of the matched submissions' path encoded
        // (`quote_authorized`); a quote altered beyond legitimate segment
        // advancement matches no submission.
        if [correlation.path, correlation.owner.map(|r| r.evidence.path)]
            .into_iter()
            .flatten()
            .any(|path| !self.quote_authorized(path, packet.payload))
        {
            return Ok(Completed(Discarded(IcmpDiscard::Uncorrelated)));
        }
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
        let Some(record) = correlation.owner else {
            // Only a non-TCP PTB can act at the path level alone: a TCP quote
            // needs its connection's policy before anything is published.
            if let (true, Some(path), false) = (
                ptb,
                correlation.path,
                key.protocol == ntcp_icmp::PROTOCOL_TCP,
            ) && let Some(mtu) = report_mtu(ipv4, dropped, candidate)
            {
                let published =
                    self.publish(now, path, ipv4, quoted(&key), dropped, candidate, None)?;
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
        // Connections record no evidence: the owner is a datagram flow or
        // the stateless lane, which take advice only.
        let evidence = record.evidence;
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
                quoted(&key),
                evidence.packet_len,
                candidate,
                None,
            )?,
            _ => None,
        };
        // A datagram flow consumes its advice from a bounded queue, after
        // any shared decrease is in place for its next send. A fragment's
        // advice names its datagram's remote; `dropped_len` is the
        // dropped fragment's own length.
        if let Selector::Udp {
            destination_port, ..
        }
        | Selector::UdpFirstFragment {
            destination_port, ..
        }
        | Selector::Fragment {
            logical_ports: (_, destination_port),
            ..
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
        Ok(Completed(IcmpOutcome::Advice {
            owner: Some(evidence.owner),
            advice,
            published,
        }))
    }

    // The managed connection a TCP quote is about (`Endpoint::quoted_segment`),
    // with the segment it quotes and its binding's current path.
    pub(crate) fn tcp_quote(
        &self,
        endpoint: &Endpoint,
        key: &QuoteKey,
        zone: Option<LinkId>,
    ) -> Option<(ConnectionId, CorrelatedSegment, path::PathId)> {
        let QuotedSelector::Tcp {
            source_port,
            destination_port,
            sequence,
        } = key.transport
        else {
            return None;
        };
        if key.protocol != ntcp_icmp::PROTOCOL_TCP {
            return None;
        }
        let tuple = ntcp::ScopedTuple::new(
            ntcp::Tuple {
                local: core::net::SocketAddr::new(key.source, source_port),
                remote: core::net::SocketAddr::new(key.destination, destination_port),
            },
            zone,
        )?;
        let (owner, segment) = endpoint.quoted_segment(
            tuple,
            sequence,
            key.packet_len,
            u16::try_from(key.header_len).ok()?,
        )?;
        let path = self.binding(owner).ok()?.snapshot.path();
        Some((owner, segment, path))
    }

    // TCP policy for one correlated report, at arrival or at replay: deferred
    // unapplied while the owner's output is reserved, then applied only to
    // that exact generation.
    fn tcp_report(
        &mut self,
        endpoint: &mut Endpoint,
        now: Instant,
        deferred: DeferredIcmp,
    ) -> Result<IcmpDispatch, Error> {
        use IcmpDispatch::Completed;
        use IcmpOutcome::Discarded;
        let (id, report) = (deferred.owner, deferred.report);
        if !endpoint.connection_exists(id) {
            return Ok(Completed(Discarded(IcmpDiscard::Stale)));
        }
        if endpoint.is_output_reserved(id) {
            return Ok(IcmpDispatch::Deferred(deferred));
        }
        let (segment, ipv4) = (report.segment, report.ipv4);
        let (quoted_packet_len, candidate) = match report.kind {
            CorrelatedKind::PacketTooBig {
                quoted_packet_len,
                candidate,
            } => (quoted_packet_len, candidate),
            CorrelatedKind::NetworkError(error) => {
                let Some(accepted) =
                    live(endpoint.correlated_network_error(now, id, segment, error))?
                else {
                    return Ok(Completed(Discarded(IcmpDiscard::Stale)));
                };
                return Ok(Completed(IcmpOutcome::Tcp {
                    owner: id,
                    report: TcpReport::NetworkError { error, accepted },
                    published: None,
                }));
            }
        };
        let quoted = (quoted_packet_len, u32::from(segment.ip_header_len));
        // Only a path incarnation that is still valid and still this
        // connection's binding may change any estimate. A report replayed
        // after its connection moved to another incarnation remains drop
        // advice for its outstanding data.
        let current = report.path.filter(|path| {
            self.binding(id).is_ok_and(|b| b.snapshot.path() == *path)
                && self
                    .paths
                    .path_snapshot(*path)
                    .is_ok_and(|s| s.status() == PathStatus::Valid)
        });
        // RFC 1191 section 5's current PMTU estimate is the shared one that
        // `host_estimate` reads from the same snapshot, at arrival or replay:
        // the network estimate, never the discovery-policy sending limit.
        let path_estimate =
            current.and_then(|path| self.paths.path_snapshot(path).ok()?.pmtu_estimate().ok());
        let report = CorrelatedPmtu {
            segment,
            quoted_packet_len,
            candidate_mtu: candidate.unwrap_or(0),
            current_path: current.is_some(),
            path_estimate,
        };
        // A Deferred report carries the Host's estimate as its provenance, so
        // that applying it at the quoted data's timeout can be published.
        let estimate = current.and_then(|path| {
            self.host_estimate(path, ipv4, quoted, segment.ip_packet_len, candidate)
        });
        let feedback = match estimate {
            Some(estimate) => {
                endpoint.correlated_pmtu_feedback_with_estimate(now, id, report, estimate)
            }
            None => endpoint.correlated_pmtu_feedback(now, id, report),
        };
        let Some(outcome) = live(feedback)? else {
            return Ok(Completed(Discarded(IcmpDiscard::Stale)));
        };
        // A Deferred report must not be pre-empted through the shared
        // estimate that the connection itself would then adopt, nor restart
        // the shared hold: TCP defers every current-path report below its
        // proven delivery, whatever its loss-inferred estimate, and only that
        // exact report's timeout authorizes publication (`publish_applied`).
        // Any other accepted current-path report is a validated network fact
        // about the shared path, whether or not the connection's own estimate
        // fell (that local label has no shared consequence): the larger of
        // the Host's estimate and the report's own policy-derived size lowers
        // a larger shared record or, when equal or larger, restarts the hold
        // so that no client confirms or submits growth within it. Neither
        // value depends on the connection's loss-inferred estimate.
        let published = match (outcome.feedback, outcome.derived_mtu, current) {
            (
                PmtuFeedback::Decreased { .. } | PmtuFeedback::Unchanged,
                Some(derived),
                Some(path),
            ) => self.publish(
                now,
                path,
                ipv4,
                quoted,
                segment.ip_packet_len,
                candidate,
                Some(derived),
            )?,
            _ => None,
        };
        Ok(Completed(IcmpOutcome::Tcp {
            owner: id,
            report: TcpReport::PacketTooBig(outcome.feedback),
            published,
        }))
    }

    // Shared network fact from a correlated PTB: the reported next-hop MTU
    // (IPv4 floor 68; IPv6 reports below 1280 are discarded), or for an IPv4
    // router without one, RFC 1191's plateau below the corrected length using
    // this Host's table. Never applied to an invalidated incarnation, never
    // larger than or equal to the dropped packet, and held for 600 seconds.
    //
    // `derived`, for a TCP owner, is the size its policy derives from
    // the report itself, independent of its current estimate. The larger of
    // it and the Host's own estimate is published: a shared ceiling must not
    // undercut what the accepting owner's configured policy derives (it
    // would be clamped to it at its next egress), and one connection's
    // plateau override must not lower other clients below the Host's table.
    // Both readings agree for a next-hop report. `quoted` is the returned
    // packet length and header length.
    #[allow(clippy::too_many_arguments)]
    fn publish(
        &mut self,
        now: Instant,
        path: path::PathId,
        ipv4: bool,
        quoted: (u32, u32),
        dropped: u32,
        candidate: Option<u32>,
        derived: Option<u32>,
    ) -> Result<Option<path::EstimateChange>, Error> {
        let Some(mtu) = self.host_estimate(path, ipv4, quoted, dropped, candidate) else {
            return Ok(None);
        };
        debug_assert!(candidate.is_none() || derived.is_none_or(|derived| derived == mtu));
        let mtu = derived.map_or(mtu, |derived| derived.max(mtu));
        if mtu >= dropped {
            return Ok(None);
        }
        Ok(Some(self.trusted_decrease(now, path, mtu)?))
    }

    // The Host's own normalized estimate for a correlated PTB about a valid
    // path incarnation, before any owner policy.
    fn host_estimate(
        &self,
        path: path::PathId,
        ipv4: bool,
        (quoted_len, header_len): (u32, u32),
        dropped: u32,
        candidate: Option<u32>,
    ) -> Option<u32> {
        let snapshot = self
            .paths
            .path_snapshot(path)
            .ok()
            .filter(|s| s.status() == PathStatus::Valid)?;
        match (candidate, ipv4) {
            (None, true) => snapshot
                .ipv4_plateaus()?
                .legacy_fallback(
                    snapshot.pmtu_estimate().ok()?,
                    quoted_len,
                    header_len,
                    dropped,
                )
                .ok(),
            _ => report_mtu(ipv4, dropped, candidate).flatten(),
        }
    }

    /// Obtain authority for a selected reservation: the build-time
    /// validation of its packet against the connection's checked egress
    /// decision (see "Egress validation" in the crate documentation). Keep
    /// this context with a blocked frame: `submit` refuses it once the
    /// context's path has changed.
    pub fn egress_context(
        &mut self,
        endpoint: &mut Endpoint,
        attempt: TransmitAttempt,
    ) -> Result<EgressContext, Error> {
        self.check_endpoint(endpoint)?;
        let packet = endpoint
            .transmit_attempt_packet(attempt)
            .ok_or(Error::Obsolete)?;
        // A connection's packets carry its scoped identity; a stateless reply
        // to a link-local peer carries the arrival link of the input that
        // caused it. Either leaves only on that link.
        let route = match packet.connection {
            Some(owner) => Some(endpoint.managed_route(owner)?),
            None => None,
        };
        let zone = match route {
            Some(route) => route.zone,
            None => endpoint
                .transmit_attempt_zone(attempt)
                .ok_or(Error::Obsolete)?,
        };
        // A reply whose link was removed or replaced can leave on no link:
        // it is counted once and the embedding discards it as certainly
        // unsubmitted, rather than holding it for a link that never returns.
        if packet.connection.is_none()
            && let Some(link) = zone
            && self.port(link).is_err()
        {
            endpoint.count_undeliverable_reply(attempt);
            return Err(Error::Obsolete);
        }
        // The record that holds the attempt's path: its connection's
        // binding, or a stateless reply's lease.
        enum Record {
            Binding(usize),
            Lease(usize),
        }
        let record = if let (Some(owner), Some(route)) = (packet.connection, route) {
            Record::Binding(self.authorized_route(endpoint, owner, route, &packet)?)
        } else if let Some(index) = self
            .leases
            .iter()
            .position(|l| l.as_ref().is_some_and(|l| l.attempt == attempt))
        {
            let lease = self.leases[index].unwrap();
            let mut snapshot = self.paths.snapshot(lease.prepared.client)?;
            let request = self.request(
                packet.ip.source,
                packet.ip.destination,
                zone,
                Dscp::new(packet.dscp)?,
            )?;
            let via = scoped(wire_destination(packet), zone)?;
            let prepared = if snapshot.status() != PathStatus::Valid
                || snapshot.key().request() != request
                || !self.forwards_via(snapshot.key(), via)
            {
                // Resolve and check the actual port before changing pins or
                // client generation. Failure leaves the held lease dirty and
                // retryable when authority/capacity is restored.
                let resolved = self.paths.resolve_via(request, via)?;
                self.forwarding_resolved(resolved.key())?;
                let (client, rebound) =
                    self.paths
                        .rebind_resolved(lease.prepared.client, request, via, resolved)?;
                snapshot = rebound;
                PreparedPath { client, snapshot }
            } else {
                self.forwarding(&snapshot)?;
                PreparedPath {
                    client: lease.prepared.client,
                    snapshot,
                }
            };
            self.leases[index].as_mut().unwrap().prepared = prepared;
            self.paths.acknowledge(prepared.client, snapshot.stamp())?;
            Record::Lease(index)
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
                zone,
                Dscp::new(packet.dscp)?,
            )?;
            let via = scoped(destination, zone)?;
            let resolved = self.paths.resolve_via(request, via)?;
            self.forwarding_resolved(resolved.key())?;
            let (client, snapshot) = self.paths.acquire_resolved(request, via, resolved)?;
            let prepared = PreparedPath { client, snapshot };
            self.leases[index] = Some(Lease { attempt, prepared });
            Record::Lease(index)
        };
        let binding = match record {
            Record::Binding(index) => &self.bindings[index].as_ref().unwrap().prepared,
            Record::Lease(index) => &self.leases[index].as_ref().unwrap().prepared,
        };
        // A connection's binding comes from `refresh`, which checked its
        // forwarding; nothing since changed a path or port.
        if packet.connection.is_none() {
            self.forwarding(&binding.snapshot)?;
        }
        // Refresh checked that a connection's binding forwards via the
        // destination its route names now, the packet's own: the Endpoint
        // takes no input for a connection while its output is reserved, so
        // no later return route changes it under a selected packet.
        let checked = route.is_some_and(|r| r.forwarding_destination == wire_destination(packet));
        debug_assert!(
            !checked
                || scoped(wire_destination(packet), zone)
                    .is_ok_and(|via| self.forwards_via(binding.snapshot.key(), via))
        );
        if packet.dscp != binding.snapshot.key().dscp().value()
            || packet.ip.source != binding.snapshot.key().source_address().address()
            || packet.ip.destination != binding.snapshot.key().destination().address()
            || (!checked
                && !self.forwards_via(
                    binding.snapshot.key(),
                    scoped(wire_destination(packet), zone)?,
                ))
        {
            return Err(Error::Obsolete);
        }
        // A stateless reply's evidence storage is reserved with the
        // authority, before any bytes can reach a backend; validate_egress
        // fills it for each retry. A connection keeps none: ICMP errors
        // about it are checked against its own sequence space.
        let context = EgressContext {
            link: binding.snapshot.key().link(),
            next_hop: binding.snapshot.key().next_hop(),
            attempt,
            client: binding.client,
            stamp: binding.snapshot.stamp(),
            #[cfg(debug_assertions)]
            snapshot: binding.snapshot,
        };
        if packet.connection.is_none() {
            self.reserve_attempt(endpoint, Owner::Stateless, attempt)?;
        }
        Ok(context)
    }

    /// The snapshot of the path `context` was granted on, read in place:
    /// `Obsolete` once that path has changed (its stamp) or its client was
    /// released, when `submit` refuses the context too.
    pub fn egress_snapshot(&self, context: &EgressContext) -> Result<&PathSnapshot, Error> {
        self.granted(context).ok_or(Error::Obsolete)
    }
    // The live snapshot of `context`'s path client while its stamp is the
    // one granted: every change of a snapshot gives it a new stamp, so it is
    // the snapshot granted, which debug builds check.
    fn granted(&self, context: &EgressContext) -> Option<&PathSnapshot> {
        let snapshot = self
            .paths
            .snapshot_ref(context.client)
            .ok()
            .filter(|s| s.stamp() == context.stamp)?;
        #[cfg(debug_assertions)]
        debug_assert_eq!(*snapshot, context.snapshot);
        Some(snapshot)
    }
    // Refresh a connection's live path and budget authority, never its
    // registration authorization, then admit a planned connection's
    // option-bearing output only under the route authority its owner's
    // expected registrations were stated for (RFC 791 section 3.1): another
    // route generation, source, forwarding selection or class, or no route
    // at all, is StaleRoute until the owner revalidates.
    fn authorized_refresh(
        &mut self,
        endpoint: &mut Endpoint,
        owner: ConnectionId,
        packet: &Transmit,
    ) -> Result<(), Error> {
        self.check_endpoint(endpoint)?;
        let index = self.binding_index(owner).ok_or(Error::InvalidContext)?;
        let current = endpoint.managed_route(owner)?;
        self.authorized_index(endpoint, owner, index, current, packet)
    }
    // `authorized_refresh` of a connection whose route `egress_context`
    // read for its packet; its binding record, which holds the path.
    fn authorized_route(
        &mut self,
        endpoint: &mut Endpoint,
        owner: ConnectionId,
        current: ManagedRoute,
        packet: &Transmit,
    ) -> Result<usize, Error> {
        let index = self.binding_index(owner).ok_or(Error::InvalidContext)?;
        self.authorized_index(endpoint, owner, index, current, packet)?;
        Ok(index)
    }
    fn authorized_index(
        &mut self,
        endpoint: &mut Endpoint,
        owner: ConnectionId,
        index: usize,
        current: ManagedRoute,
        packet: &Transmit,
    ) -> Result<(), Error> {
        let registration = self.bindings[index]
            .as_ref()
            .unwrap()
            .registration
            .filter(|_| packet.ipv4_options != OutgoingIpv4Options::default());
        match (
            self.refresh_route(endpoint, owner, index, current),
            registration,
        ) {
            (Ok(()), Some(r))
                if self.bindings[index]
                    .as_ref()
                    .unwrap()
                    .prepared
                    .snapshot
                    .key()
                    != r.authorized =>
            {
                Err(Error::StaleRoute)
            }
            (Err(Error::Path(path::Error::NoRoute)), Some(_)) => Err(Error::StaleRoute),
            (result, _) => result,
        }
    }
    #[cfg(test)]
    fn registration(&self, owner: ConnectionId) -> Option<Registration> {
        self.binding_index(owner)
            .and_then(|index| self.bindings[index].as_ref().unwrap().registration)
    }
    fn planned(&self, owner: ConnectionId) -> Result<(usize, Binding, Registration), Error> {
        self.live_bindings
            .iter()
            .find_map(|index| {
                let b = self.bindings[index]?;
                Some((index, b, b.registration?)).filter(|_| b.owner == Some(owner))
            })
            .ok_or(Error::InvalidContext)
    }

    /// The route authority a planned connection's option-bearing output
    /// would leave under now, for its owner to state the registrations
    /// expected on it: None while no route resolves (a removed route) until
    /// resolution succeeds again. A pure read.
    pub fn registration_candidate(
        &self,
        endpoint: &Endpoint,
        owner: ConnectionId,
    ) -> Result<Option<path::PathKey>, Error> {
        self.check_endpoint(endpoint)?;
        let (_, binding, _) = self.planned(owner)?;
        let key = binding.prepared.snapshot.key();
        let current = endpoint.managed_path(owner)?;
        let request = self.request(
            key.source_address().address(),
            key.destination().address(),
            current.zone,
            key.dscp(),
        )?;
        let via = scoped(current.forwarding_destination, current.zone)?;
        match self.paths.resolve_via(request, via) {
            Ok(resolved) => {
                self.forwarding_resolved(resolved.key())?;
                Ok(Some(resolved.key()))
            }
            Err(path::Error::NoRoute) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Authorize `candidate` for a planned connection whose owner states the
    /// registrations `expected` on it. The expectations must fit the
    /// connection's fixed option capacities (`InsufficientRecords`
    /// otherwise: a new connection is required), and `candidate` must still
    /// be the live authority after refresh (`StaleRoute` otherwise). Any
    /// failure leaves the authorization unchanged. The tuple, source route
    /// and option sizes never change; held output recovers through the
    /// ordinary nonsubmission and reselection accounting.
    pub fn revalidate_registration(
        &mut self,
        endpoint: &mut Endpoint,
        owner: ConnectionId,
        candidate: path::PathKey,
        expected: &ExpectedRegistrations<'_>,
    ) -> Result<(), Error> {
        self.check_endpoint(endpoint)?;
        let (_, _, registration) = self.planned(owner)?;
        let tuple = endpoint.managed_path(owner)?.tuple;
        let plan = Ipv4RegistrationPlan::new(
            tuple.local.ip(),
            tuple.remote.ip(),
            *registration.plan.options(),
            expected,
        )
        .map_err(EndpointError::from)?;
        let live = match self.refresh(endpoint, owner) {
            Err(Error::Path(path::Error::NoRoute)) => return Err(Error::StaleRoute),
            result => result?,
        };
        if live.snapshot.key() != candidate {
            return Err(Error::StaleRoute);
        }
        let (index, _, _) = self.planned(owner)?;
        self.bindings[index].as_mut().unwrap().registration = Some(Registration {
            plan,
            authorized: candidate,
        });
        Ok(())
    }

    // Whether `key` is the path that selection for the forwarding
    // destination `via` gives: that destination itself, or, when `via` is
    // the final destination and the route is an SR route, the first segment
    // S1 the route derives (`PathService::resolve`).
    fn forwards_via(&self, key: path::PathKey, via: ScopedAddress) -> bool {
        key.forwarding_destination() == via
            || (via == key.destination()
                && self
                    .header_plan(key)
                    .is_ok_and(|plan| !plan.segments.is_empty()))
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

    /// The IP header plan of output on the path with `key`, read from the
    /// route generation it selected: the segment list S1..Sn of an SR route
    /// (empty otherwise) and the complete header length H it implies (the
    /// base header, plus the Segment Routing Header of n + 1 entries), which
    /// is the path's `PathSnapshot::ip_header_len`. IPv4 options are the
    /// caller's. Embeddings place an attempt's TCP segment H octets into its
    /// frame and encode the header with `ntcp_ip6::encode_tcp_routed`
    /// (`Host::egress_snapshot` names the key).
    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.1
    //= reason=Host path budgets subtract the complete IPv6 header H of the selected path, the 40-octet base header plus, on an owner-configured Segment Routing route of n segments, its 8 + 16(n + 1)-octet Segment Routing Header (Host::header_plan, PathSnapshot::ip_header_len), from the largest IP packet that can be sent: TCP takes H before construction and admission for its MSS, T16's segment quantum and send space, PLPMTUD probes, exact-range repair and retransmission in scalar, shared, reserved and software GSO output, and an indivisible header that no longer fits fails admission. Host UDP flows report MMS_S as the path budget less H and limit Refuse and Probe payloads to EMTU_S - H - 8. When source fragmentation is selected (Host::udp_send_datagram's Fragment mode and the Host's Echo Replies, where a reply to an IPv4 source-routed Echo Request takes the reversed, policy-authorized return route, registers no adjunct demand and is never sized by an adjunct-confirmed bound, while IPv6 Echo Replies use only owner-configured routes) EMTU_S is the receiver's reassembly guarantee (1500 octets for IPv6) or a capability the application states from upper-layer or deployment knowledge, and the Host creates fragments each limited by the connectionless effective size (never above the PMTU) that repeat the unfragmentable part (base header and Segment Routing Header) before the Fragment header; Refuse and Probe modes and TCP keep EMTU_S at the PMTU (TCP never source-fragments). Host::reassembly_capacity states this Host's own EMTU_R and MMS_R, and every managed TCP factory advertises the MSS Host::receive_ip_capability derives from EMTU_R, the largest IPv6 link and the wire limit independently of the send PMTU (T16, 1191-024). Host segment_routes tests (TCP, UDP Refuse/Probe/Fragment, Echo and ICMP errors with exact chains and checksums over the final destination), the native and tun_echo placement tests and the integration/rfc_host srh cases verify it, per embedding: tun_echo's transit-ptb case repairs a transit router's real Packet Too Big quoting its submitted SRH packets and makes TCP progress through a Linux SRv6 endpoint, and the native runtime's endpoint case makes TCP progress through Linux's own SR endpoint processing to the final destination.
    //# MMS_S is a transport message size calculated by subtracting the size of the IPv6 header (including IPv6 extension headers) from the largest IP packet that can be sent, EMTU_S. MMS_S is limited by a combination of factors, including the PMTU, support for packet fragmentation and reassembly, and the packet reassembly limit (see "Fragment Header", Section 4.5 of [RFC8200]). When source fragmentation is available, EMTU_S is set to EMTU_R, as indicated by the receiver using an upper-layer protocol or based on protocol requirements (1500 octets for IPv6). When a message larger than PMTU is to be transmitted, the source creates fragments, each limited by PMTU. When source fragmentation is not desired, EMTU_S is set to PMTU, and the upper-layer protocol is expected to either perform its own fragmentation and reassembly or otherwise limit the size of its messages accordingly.
    pub fn header_plan(&self, key: path::PathKey) -> Result<HeaderPlan<'_>, Error> {
        let segments = self.paths.route_segments(key.route())?;
        let len = if key.destination().address().is_ipv4() {
            ntcp_ip::IPV4_HEADER
        } else {
            ntcp_ip6::header_len(segments)?
        };
        Ok(HeaderPlan { segments, len })
    }

    // Whether the packet quoted by the ICMP error `message` (behind its
    // 8-octet header) carries the IP header plan that the route generation
    // of `path`, which authorized the submission, encoded: the retained
    // route authority of the submission, read from the path's key and the
    // live route, with no copy kept. A quoted Segment Routing Header must
    // be the one `ntcp_ip6::encode_routed` emitted for that generation's
    // segments S1..Sn, directly after the base header (Routing Type 4, Hdr
    // Ext Len 2(n + 1), Last Entry n, Flags and Tag zero, Segment List[i] =
    // S(n + 1 - i)); only Segments Left and the base Destination Address
    // advance in flight (RFC 8754 4.3.1.1), so Segments Left is at most n
    // and the Destination Address is Segment List[Segments Left]. Segment
    // List[0] is the final destination the ledger compared. A replaced or
    // removed route declines every quote carrying a Routing header, and an
    // ordinary route's output carries none. IPv4 quotes carry no SRH.
    pub(crate) fn quote_authorized(&self, path: path::PathId, message: &[u8]) -> bool {
        let Some(quoted) = message.get(8..) else {
            return false;
        };
        if quoted.first().is_some_and(|b| b >> 4 == 4) {
            return true;
        }
        let segments = self
            .paths
            .path_snapshot(path)
            .ok()
            .and_then(|s| self.paths.route_segments(s.key().route()).ok());
        planned_routing(segments.unwrap_or(&[]), quoted).is_some()
    }

    /// Whether the IP layer must leave DF clear on this attempt's packet
    /// whatever its connection requests: its path is IPv4 and the owner
    /// disabled discovery on its route or path (RFC 1191 section 6.6). The
    /// embedding applies it with `lease_df_clear` immediately before each
    /// physical submission (a fresh Identification for every attempt);
    /// `submit` refuses a DF-set IPv4 packet on such a path. When it no
    /// longer holds for a packet held across a re-enable (and its
    /// connection does not ask for DF clear), the embedding restores the
    /// atomic header with `restore_atomic_header` before the retry.
    pub fn clears_dont_fragment(&self, context: EgressContext) -> bool {
        self.paths
            .snapshot_ref(context.client)
            .is_ok_and(|s| s.clears_dont_fragment())
    }

    /// The checks of one physical attempt, which `submit` makes before the
    /// backend call (see "Egress validation" in the crate documentation):
    /// the context's path is unchanged (its stamp), the packet fits the
    /// path's first hop, and an IPv4 packet on a path that clears DF
    /// carries none; a stateless reply's evidence is recorded. The frame
    /// starts at IP and contains exactly its resident bytes (no Ethernet
    /// padding); shared_payload_len is added exactly once. It is the
    /// attempt's packet as the embedding encoded it, which debug builds
    /// check. Software GSO calls this separately for each actual physical
    /// segment/attempt.
    pub fn validate_egress(
        &mut self,
        endpoint: &mut Endpoint,
        context: EgressContext,
        frame: &[u8],
        shared_payload_len: usize,
    ) -> Result<EgressContext, Error> {
        self.check_endpoint(endpoint)?;
        let packet = endpoint
            .transmit_attempt_packet(context.attempt)
            .ok_or(Error::Obsolete)?;
        self.validate_attempt(endpoint, context, &packet, frame, shared_payload_len)
    }
    // `validate_egress` of the attempt's current `packet`.
    fn validate_attempt(
        &mut self,
        endpoint: &mut Endpoint,
        context: EgressContext,
        packet: &Transmit,
        frame: &[u8],
        shared_payload_len: usize,
    ) -> Result<EgressContext, Error> {
        // `egress_context` granted the authority; it holds while the path
        // is unchanged. Every change of a path's selection, budget or
        // validity gives it a new stamp, and a rebind or release retires the
        // client, so a frame held across one is refused. A connection's
        // binding is brought up to date first, so that it packetizes its
        // output again for the current path; a stateless reply is dropped.
        let Some(snapshot) = self.granted(&context) else {
            if let Some(owner) = packet.connection {
                self.authorized_refresh(endpoint, owner, packet)?;
            }
            return Err(Error::Obsolete);
        };
        let actual = frame
            .len()
            .checked_add(shared_payload_len)
            .ok_or(Error::Capacity)?;
        let ipv4 = packet.ip.source.is_ipv4();
        // Linux's output check (ip_finish_output against the device MTU,
        // as for IP_PMTUDISC_PROBE: discovery probes exceed the estimate),
        // and RFC 1191 section 6.6: no DF on a discovery-disabled route,
        // which the embedding clears (`clears_dont_fragment`).
        if actual > snapshot.first_hop_mtu() as usize
            || (ipv4
                && snapshot.clears_dont_fragment()
                && frame.get(6).is_none_or(|f| f & 0x40 != 0))
        {
            return Err(Error::Obsolete);
        }
        debug_assert_eq!(
            self.attempt_frame(snapshot.key(), packet, frame, shared_payload_len, false),
            Ok(())
        );
        if packet.connection.is_some() {
            return Ok(context);
        }
        let path = snapshot.path();
        // A stateless reply's evidence: the quoted fields an ICMP error
        // about it is correlated with.
        let (_, header, total, protocol) = if ipv4 {
            ntcp_ip::egress_header(frame)?
        } else {
            ntcp_ip6::quote_header(frame)?
        };
        let transport = tcp_selector(frame.get(header..).ok_or(Error::Obsolete)?, total - header)?;
        let pending = self.reserve_attempt(endpoint, Owner::Stateless, context.attempt)?;
        self.ledger.set_evidence(
            pending,
            Evidence {
                link: context.link,
                path,
                owner: Owner::Stateless,
                source: packet.ip.source,
                destination: packet.ip.destination,
                dscp: packet.dscp,
                header_len: header as u32,
                packet_len: total as u32,
                protocol,
                transport,
            },
        );
        Ok(context)
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
        if packet.connection.is_some() {
            return Ok(SubmissionTicket { ticket: None });
        }
        let index = self.reserve_attempt(endpoint, Owner::Stateless, context.attempt)?;
        Ok(SubmissionTicket {
            ticket: Some(self.ledger.issue(index)?),
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
        if let Some(ticket) = ticket.ticket {
            self.ledger.cancel(ticket);
        }
    }

    /// The physical-attempt transaction. Every fallible step happens before
    /// `submit` runs: the O(1) checks of each physical attempt
    /// (`validate_egress`: the context's path stamp and the first-hop MTU,
    /// not a revalidation of what `egress_context` decided), a stateless
    /// reply's evidence reservation, and the Endpoint's acceptance
    /// preflight. Afterwards the outcome is finalized
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
        let packet = endpoint.transmit_attempt_packet(context.attempt);
        let ticketed = match ticket.ticket {
            Some(ticket) => self
                .ledger
                .find_ticket(ticket)
                .and_then(|index| self.ledger.pending(index))
                .is_some_and(|p| p.attempt == Some(context.attempt)),
            None => packet.is_some_and(|p| p.connection.is_some()),
        };
        let Some(packet) = packet.filter(|_| ticketed) else {
            return Err(Refused {
                error: Error::Obsolete,
                ticket,
            });
        };
        let prepared = (|| {
            self.check_endpoint(endpoint)?;
            let live =
                self.validate_attempt(endpoint, context, &packet, frame, shared_payload_len)?;
            if !endpoint.preflight_accept_transmit(now, context.attempt)? {
                return Err(Error::Obsolete);
            }
            Ok(live)
        })();
        let live = match prepared {
            Ok(live) => live,
            Err(error) => return Err(Refused { error, ticket }),
        };
        debug_assert!(ticket.ticket.is_none_or(|ticket| {
            self.ledger
                .find_ticket(ticket)
                .is_some_and(|index| self.ledger.has_evidence(index))
        }));
        self.now = self.now.max(now);
        match submit(live) {
            BackendOutcome::Submitted => {
                if let Some(ticket) = ticket.ticket {
                    self.ledger.seal(ticket, now, false);
                }
                // Only a definite submission certifies the bytes the
                // backend took.
                let receipt = ntcp::PhysicalReceipt {
                    ip_packet_len: (frame.len() + shared_payload_len) as u32,
                    dont_fragment: unfragmentable(frame),
                };
                let accepted = endpoint.accept_transmit_submitted(now, context.attempt, receipt);
                assert!(matches!(accepted, Ok(true)), "preflighted acceptance");
                Ok(Submission::Submitted)
            }
            BackendOutcome::WouldBlock => Ok(Submission::Blocked(ticket)),
            BackendOutcome::Rejected => Ok(Submission::Rejected(ticket)),
            BackendOutcome::NotSubmitted => {
                self.cancel_submission(ticket);
                Ok(Submission::Cancelled)
            }
            BackendOutcome::Unknown => {
                if let Some(ticket) = ticket.ticket {
                    self.ledger.seal(ticket, now, true);
                }
                Ok(Submission::PossiblySubmitted)
            }
        }
    }

    /// `submit` for a transmit group (`Endpoint::prepare_transmit_group`),
    /// one aggregate the backend cuts into its segments. `context` is the
    /// authority `egress_context` gave the attempt the group was prepared
    /// from; `frame` starts at IP and holds the whole aggregate: one IP
    /// header whose length covers it all, the group's TCP header and every
    /// segment's payload. Its checksum fields, an IPv4 header's and the
    /// TCP checksum, are zero: the backend fills them for every segment it
    /// cuts, as Linux's segmentation does (inet_gso_segment, tcp_gso_segment). At
    /// every call, before the backend's, the checks of `validate_egress`
    /// are made, except that each physical segment, not the aggregate, must
    /// fit the first hop (Linux's ip_finish_output_gso), and that the
    /// aggregate must be unfragmentable: an IPv4 path that clears DF
    /// leases each packet its own Identification, which one header cannot
    /// carry for many, and one header without DF would give every segment
    /// the same one (`Unsupported`). Then `Endpoint::validate_transmit_group`.
    /// A definite submission certifies every segment's size evidence
    /// (`Endpoint::accept_transmit_group_submitted`). A connection's output
    /// keeps no ledger evidence, so no ticket is involved; refusals change
    /// nothing, and the caller rejects the group (`Obsolete` after a path
    /// change, which also brings the binding up to date, as for one packet).
    #[allow(clippy::too_many_arguments)]
    pub fn submit_group(
        &mut self,
        endpoint: &mut Endpoint,
        now: Instant,
        context: EgressContext,
        group: TransmitGroup,
        frame: &[u8],
        submit: impl FnOnce(EgressContext) -> BackendOutcome,
    ) -> Result<Submission, Error> {
        let segment = self.validate_group_egress(endpoint, now, context, group, frame)?;
        self.now = self.now.max(now);
        let none = SubmissionTicket { ticket: None };
        match submit(context) {
            BackendOutcome::Submitted => {
                let receipt = ntcp::PhysicalReceipt {
                    ip_packet_len: segment as u32,
                    dont_fragment: true,
                };
                let accepted = endpoint.accept_transmit_group_submitted(now, group, receipt);
                assert!(matches!(accepted, Ok(true)), "validated group acceptance");
                Ok(Submission::Submitted)
            }
            BackendOutcome::WouldBlock => Ok(Submission::Blocked(none)),
            BackendOutcome::Rejected => Ok(Submission::Rejected(none)),
            BackendOutcome::NotSubmitted => Ok(Submission::Cancelled),
            BackendOutcome::Unknown => Ok(Submission::PossiblySubmitted),
        }
    }
    // `submit_group`'s checks; the IP length of each physical segment.
    fn validate_group_egress(
        &mut self,
        endpoint: &mut Endpoint,
        now: Instant,
        context: EgressContext,
        group: TransmitGroup,
        frame: &[u8],
    ) -> Result<usize, Error> {
        self.check_endpoint(endpoint)?;
        let view = endpoint.transmit_group(group).ok_or(Error::Obsolete)?;
        let packet = view.packet;
        let owner = packet.connection.ok_or(Error::Obsolete)?;
        let Some(snapshot) = self.granted(&context) else {
            self.authorized_refresh(endpoint, owner, &packet)?;
            return Err(Error::Obsolete);
        };
        // The aggregate is the IP and TCP headers of one segment and the
        // payload of all of them.
        let segment = frame
            .len()
            .checked_sub(view.payload.len())
            .ok_or(Error::Obsolete)?
            + view.segment_payload_len;
        if segment > snapshot.first_hop_mtu() as usize {
            return Err(Error::Obsolete);
        }
        debug_assert_eq!(
            self.attempt_frame(snapshot.key(), &packet, frame, 0, true),
            Ok(())
        );
        if packet.ip.source.is_ipv4() && (snapshot.clears_dont_fragment() || !unfragmentable(frame))
        {
            return Err(Error::Unsupported);
        }
        if !endpoint.validate_transmit_group(now, group)? {
            return Err(Error::Obsolete);
        }
        Ok(segment)
    }
}

impl Host {
    // Whether `frame` (plus `shared_payload_len` octets elsewhere) is the
    // IP packet of the attempt whose packet is `packet`, encoded for the
    // path `key` as its embedding must: addresses, base destination (the
    // forwarding destination, S1 on an SR route), the path's header plan
    // with its Segment Routing Header unadvanced, protocol, class, ECN
    // codepoint and lengths. The debug cross-check of every physical
    // attempt, which release builds made at each one before (see "Egress
    // validation" in the crate documentation). `group`: a transmit group's
    // aggregate, whose IPv4 header and TCP checksum fields are zero.
    fn attempt_frame(
        &self,
        key: path::PathKey,
        packet: &Transmit,
        frame: &[u8],
        shared_payload_len: usize,
        group: bool,
    ) -> Result<(), Error> {
        let ipv4 = packet.ip.source.is_ipv4();
        let (ip, header, total, protocol) = if ipv4 && group {
            // The header as one packet carries it, its checksum filled.
            let len = frame.first().map_or(0, |b| usize::from(b & 15) * 4);
            if frame.len() < len.max(20) || frame[10..12] != [0, 0] {
                return Err(Error::Obsolete);
            }
            let mut copy = [0; 60];
            copy[..len].copy_from_slice(&frame[..len]);
            let sum = ntcp_ip_common::checksum(&copy[..len]);
            copy[10..12].copy_from_slice(&sum.to_be_bytes());
            ntcp_ip::quote_header(&copy[..len])?
        } else if ipv4 {
            ntcp_ip::egress_header(frame)?
        } else {
            ntcp_ip6::quote_header(frame)?
        };
        let class = if ipv4 {
            frame[1]
        } else {
            (frame[0] << 4) | (frame[1] >> 4)
        };
        let plan = self.header_plan(key)?;
        let expected_header = if let (IpAddr::V4(source), IpAddr::V4(destination)) =
            (packet.ip.source, packet.ip.destination)
        {
            20 + packet
                .ipv4_options
                .encode(source, destination, 0, &mut [0; 40])
                .map_err(|e| Error::Endpoint(EndpointError::Ipv4Options(e)))?
                .1
        } else {
            plan.len
        };
        let destination = if ipv4 {
            IpAddr::V4(core::net::Ipv4Addr::new(
                frame[16], frame[17], frame[18], frame[19],
            ))
        } else {
            IpAddr::V6(core::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[24..40]).unwrap(),
            ))
        };
        (destination == key.forwarding_destination().address()
            && (ipv4 || planned_routing(plan.segments, frame) == Some(plan.segments.len()))
            && protocol == 6
            && ip == packet.ip
            && frame.len() + shared_payload_len == total
            && header == expected_header
            && total == packet.len + header
            && Dscp::from_traffic_class(class).value() == packet.dscp
            && class & 3 == packet.ecn)
            .then_some(())
            .ok_or(Error::Obsolete)
    }
}

// Whether the network may not fragment this physical packet: IPv4 with DF
// set, or IPv6 without a Fragment header (routers never fragment IPv6, RFC
// 8200 section 5). An IPv6 fragment, or IPv4 without DF, is not a probe of
// the path's packet size.
fn unfragmentable(frame: &[u8]) -> bool {
    match frame.first().map(|b| b >> 4) {
        Some(4) => frame.get(6).is_some_and(|f| f & 0x40 != 0),
        Some(6) => frame.get(6).is_some_and(|n| *n != 44),
        _ => false,
    }
}

// Segments Left of the IPv6 packet whose leading bytes are `quoted` when
// its header chain is the one `ntcp_ip6::encode_routed` emits for
// `segments` S1..Sn: no header besides a Fragment header without segments
// (Some(0)), else exactly a Segment Routing Header directly after the base
// header (Routing Type 4, Hdr Ext Len 2(n + 1), Last Entry n, Flags and Tag
// zero, Segment List[i] = S(n + 1 - i)) in which only Segments Left and the
// base Destination Address may have advanced in flight (RFC 8754 4.3.1.1):
// Segments Left at most n and the Destination Address Segment List[Segments
// Left]. Segment List[0] is the final destination, checked by the caller.
fn planned_routing(segments: &[core::net::Ipv6Addr], quoted: &[u8]) -> Option<usize> {
    use ntcp_ip_common::ipv6::{Chain, FRAGMENT, ROUTING};
    let chain = Chain::quote(quoted).ok()?;
    let mut headers = chain.headers().filter(|h| h.kind != FRAGMENT);
    let (srh, rest) = match (headers.next(), headers.next()) {
        (None, _) => return segments.is_empty().then_some(0),
        (Some(srh), rest) => (srh, rest),
    };
    let n = segments.len();
    let b = quoted.get(srh.offset..srh.offset + srh.len)?;
    let entry = |i: usize| &b[8 + 16 * i..8 + 16 * (i + 1)];
    let left = usize::from(b[3]);
    (n != 0
        && rest.is_none()
        && srh.kind == ROUTING
        && srh.offset == ntcp_ip_common::ipv6::BASE_HEADER
        && srh.len == 8 + 16 * (n + 1)
        && b[2] == 4
        && usize::from(b[4]) == n
        && b[5..8] == [0; 3]
        && left <= n
        && (1..=n).all(|i| entry(i) == segments[n - i].octets())
        && quoted[24..40] == *entry(left))
    .then_some(left)
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

// The ledger key of a validated quote.
pub(crate) fn quote_key(quote: &ntcp_icmp::Quote) -> QuoteKey {
    QuoteKey {
        source: quote.ip.source,
        destination: quote.ip.destination,
        header_len: u32::from(quote.ip_header_len),
        packet_len: quote.ip_packet_len,
        protocol: quote.protocol,
        transport: match (quote.fragment, quote.transport) {
            // A quoted fragment of a datagram this Host source-fragmented
            // (RFC 4821 section 8). Fragment zero of a UDP datagram is
            // correlated by its UDP header, which is its leading data;
            // every other fragment only by its exact physical evidence,
            // never by ports and never by the IPv4 Identification (RFC
            // 6864 section 4.1). The Host never originates TCP fragments
            // or IPv6 atomic fragments (RFC 8021), so their quotes find no
            // evidence and never reach TCP repair.
            (
                Some(f),
                QuotedTransport::Udp {
                    source_port,
                    destination_port,
                    length,
                    checksum,
                },
            ) if f.offset == 0 && f.more_fragments => QuotedSelector::UdpFirstFragment {
                source_port,
                destination_port,
                length,
                checksum,
            },
            (Some(f), _) => QuotedSelector::Fragment {
                offset: f.offset,
                more: f.more_fragments,
                prefix: FragmentPrefix::new(f.data()),
            },
            (
                None,
                QuotedTransport::Tcp {
                    source_port,
                    destination_port,
                    sequence,
                },
            ) => QuotedSelector::Tcp {
                source_port,
                destination_port,
                sequence,
            },
            (
                None,
                QuotedTransport::Udp {
                    source_port,
                    destination_port,
                    length,
                    checksum,
                },
            ) => QuotedSelector::Udp {
                source_port,
                destination_port,
                length,
                checksum,
            },
            (None, QuotedTransport::Other) => QuotedSelector::Other,
        },
    }
}

fn quoted(key: &QuoteKey) -> (u32, u32) {
    (key.packet_len, key.header_len)
}

fn is_icmp(packet: &IngressPacket) -> bool {
    packet.protocol == if packet.ip.source.is_ipv4() { 1 } else { 58 }
}

// The ICMP error carried by a processed datagram, decoded from its message
// with the processed outer metadata: the outer header is never parsed again
// (so a source route the Host admitted is not refused here) and its options
// are the ones destination processing produced.
pub(crate) fn icmp_feedback(
    packet: &IngressPacket,
) -> Result<ntcp_icmp::Feedback<ntcp_icmp::Quote>, Error> {
    Ok(ntcp_icmp::decode_error(
        packet.ip,
        packet.options,
        packet.payload,
    )?)
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

// `address` as part of an identity scoped by `zone`: only an IPv6
// link-local address is scoped, by exactly that zone.
pub(crate) fn scoped(address: IpAddr, zone: Option<LinkId>) -> Result<ScopedAddress, Error> {
    let link_local = matches!(address, IpAddr::V6(v) if v.is_unicast_link_local());
    Ok(ScopedAddress::new(address, zone.filter(|_| link_local))?)
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
    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.2
    //= reason=Each IPv6 link keeps its own Path MTU information. PathService keys learned estimates by context, source, destination with its zone, routing DSCP, link, next hop and route generation, and a link-local destination carries an authoritative LinkId zone (context, slot, generation) with which Host::prepare selects and acquires the path on exactly that link before TCP construction. T18 carries this scoped tuple through Endpoint and Host factories, listeners (an exact address and zone beats the wildcard; wildcard children carry the arrival link), TIME-WAIT, digests, Fast Open and MSS caches, Host UDP flows and zone-constrained ICMP correlation; the native runtime resolves sin6_scope_id through its interface-index-to-live-link map over a bounded collection of configured ports, each with its own link, addresses and routes, and IPv6 Ethernet ports resolve next hops by bounded host Neighbor Discovery. Host tests (ntcp-host src/tests/scoped.rs) keep identical link-local pairs on two links as separate connections and UDP flows, and a PTB correlated with one link's submission lowers only that link's estimate; the native two-port test neighbor_discovery_ports_keep_path_mtu_per_link probes each connection up to its own link MTU (1500 and 1400), and a checksummed PTB quoting a packet definitely submitted on one port lowers only that port's estimate and packet sizes while the other port's estimate and both first-hop MTUs stay unchanged; the integration/rfc_host scoped two-link case (one native runtime owning two veth links of MTU 1500 and 1400 to one Linux peer namespace, identical link-local pairs, captured DAD and NS/NA, hashed TCP streams on both links) shows a checksummed, harness-injected PTB quoting a captured packet on link A lowering only A's learned PMTU and packet sizes while link B keeps 1400-octet packets and both first-hop MTUs stay unchanged, and later connections start at their own link's value.
    //# Ideally, a PMTU value should be associated with a specific path traversed by packets exchanged between the source and destination nodes. However, in most cases a node will not have enough information to completely and accurately identify such a path. Rather, a node must associate a PMTU value with some local representation of a path. It is left to the implementation to select the local representation of a path. For nodes with multiple interfaces, Path MTU information should be maintained for each IPv6 link.
    fn prepare(&mut self, request: PathFactoryRequest) -> Result<PreparedFactory, Error> {
        if !self.attached {
            return Err(Error::InvalidContext);
        }
        // Derived before anything is acquired, so that a Host without a
        // receive capability for the family retains nothing.
        let receive = self.receive_ip_capability(request.tuple.local.is_ipv6())?;
        let index = *self.free_bindings.last().ok_or(Error::Capacity)?;
        let destination = request
            .ipv4_options
            .source_route
            .and_then(|r| r.hops().first().copied())
            .map(IpAddr::V4)
            .unwrap_or(request.tuple.remote.ip());
        let plan = request.registration;
        let zone = request.zone;
        let ports = (request.tuple.local.port(), request.tuple.remote.port());
        let request = self.request(
            request.tuple.local.ip(),
            request.tuple.remote.ip(),
            zone,
            request.dscp,
        )?;
        let via = scoped(destination, zone)?;
        let resolved = self.paths.resolve_via(request, via)?;
        self.forwarding_resolved(resolved.key())?;
        let (client, snapshot) = self.paths.acquire_resolved(request, via, resolved)?;
        self.holders[client.index()] = Holder::Binding(index);
        let prepared = PreparedPath { client, snapshot };
        // A planned open is authorized for exactly the authority selected
        // in this serialized preparation.
        self.bindings[index] = Some(Binding {
            owner: None,
            moved: None,
            ports,
            prepared,
            dst: None,
            neighbor: None,
            registration: plan.map(|plan| Registration {
                plan,
                authorized: snapshot.key(),
            }),
        });
        self.free_bindings.pop();
        self.live_bindings.insert(index);
        self.provisional.insert(index);
        debug_assert!(lists_free(&self.free_bindings, &self.bindings));
        Ok(PreparedFactory {
            path: prepared,
            receive,
        })
    }
    fn commit(&mut self, prepared: PreparedPath, connection: ConnectionId) {
        let index = self
            .provisional(prepared)
            .expect("prepared binding preflight");
        // The slot's previous connection, reclaimed before this one took the
        // slot, may not have been collected yet: its binding goes now, so a
        // slot has the one binding `owner_bindings` names.
        if let Some(previous) = self.owner_bindings[connection.index()] {
            debug_assert_ne!(self.bindings[previous].unwrap().owner, Some(connection));
            self.free_binding(previous)
                .expect("live committed binding client");
        }
        self.bindings[index].as_mut().unwrap().owner = Some(connection);
        self.provisional.remove(index);
        self.owner_bindings[connection.index()] = Some(index);
        if self.search_aging.is_some() {
            self.unaged.insert(index);
        }
    }
    fn cancel(&mut self, prepared: PreparedPath) {
        let index = self
            .provisional(prepared)
            .expect("prepared binding preflight");
        self.holders[prepared.client.index()] = Holder::None;
        self.paths
            .release(prepared.client)
            .expect("live provisional client");
        self.bindings[index] = None;
        self.live_bindings.remove(index);
        self.provisional.remove(index);
        self.free_bindings.push(index);
        debug_assert!(lists_free(&self.free_bindings, &self.bindings));
    }
    // The header plan of the path `egress_context` would select for this
    // stateless reply now (on its zone's link); a reply without one fails
    // there instead.
    fn reply_header_len(
        &mut self,
        ip: IpMetadata,
        zone: Option<LinkId>,
        dscp: u8,
    ) -> Option<u16> {
        let request = self
            .request(ip.source, ip.destination, zone, Dscp::new(dscp).ok()?)
            .ok()?;
        let via = scoped(ip.destination, zone).ok()?;
        let resolved = self.paths.resolve_via(request, via).ok()?;
        u16::try_from(self.header_plan(resolved.key()).ok()?.len).ok()
    }
}

#[cfg(test)]
mod tests;
