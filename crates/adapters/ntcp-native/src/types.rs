use std::{fmt, io, net::SocketAddr};

pub use ntcp::{
    CallerTimebase, CloseReason, DropCounts, DropEvent, DropReason, DropSubject, EndpointConfig,
    Instant, Payload, RxReadTimestamps, RxTimestampStatus, SendProgress, State, TimestampClock,
    TxStreamRange, TxTimestampClock, TxTimestampEvent, TxTimestampOutcome, TxTimestampRequest,
    TxTimestampSource, TxTimestampStage,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ConnId {
    pub(crate) instance: u64,
    pub(crate) slot: usize,
    pub(crate) generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ListenerId {
    pub(crate) instance: u64,
    pub(crate) slot: usize,
    pub(crate) generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockReason {
    SendBuffer,
    TimestampCapacity,
    OutputReserved,
    Receive,
    Accept,
    Connecting,
}

#[derive(Debug)]
pub enum Error {
    InvalidConfig(&'static str),
    InvalidHandle,
    // No connection or listener slot is free, or a table of fixed size is
    // full.
    Capacity,
    // An open given no local port found no ephemeral port it may take to
    // this destination: Linux's EADDRNOTAVAIL (__inet_hash_connect).
    AddressNotAvailable,
    // The buffer budget (`tcp.max_buffer_bytes`) or the allocator refused
    // memory to an open whose buffers do not fit, or to a setter: Linux's
    // ENOMEM. A write refused memory waits instead (WouldBlock).
    NoMemory,
    TimeWentBackwards,
    WouldBlock(BlockReason),
    Unsupported(&'static str),
    Tcp(ntcp::EndpointError),
    Host(ntcp_host::Error),
    Backend(io::Error),
    Stopped,
    ConnectionClosed(Option<CloseReason>),
}
impl Error {
    pub fn is_would_block(&self) -> bool {
        matches!(self, Self::WouldBlock(_))
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(s) => write!(f, "invalid native network configuration: {s}"),
            Self::InvalidHandle => f.write_str("handle belongs to another instance or generation"),
            Self::Capacity => f.write_str("native network capacity exhausted"),
            Self::AddressNotAvailable => {
                f.write_str("no ephemeral port is left for this destination")
            }
            Self::NoMemory => f.write_str("native network buffer memory exhausted"),
            Self::TimeWentBackwards => f.write_str("network time went backwards"),
            Self::WouldBlock(reason) => write!(f, "operation would block: {reason:?}"),
            Self::Unsupported(s) => write!(f, "unsupported native operation: {s}"),
            Self::Tcp(e) => write!(f, "TCP: {e:?}"),
            Self::Host(e) => write!(f, "IP host: {e:?}"),
            Self::Backend(e) => write!(f, "packet backend: {e}"),
            Self::Stopped => f.write_str("native network has stopped"),
            Self::ConnectionClosed(reason) => write!(f, "connection closed: {reason:?}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<ntcp_host::Error> for Error {
    fn from(e: ntcp_host::Error) -> Self {
        Self::Host(e)
    }
}
impl From<ntcp::EndpointError> for Error {
    fn from(e: ntcp::EndpointError) -> Self {
        match e {
            ntcp::EndpointError::InvalidHandle => Self::InvalidHandle,
            ntcp::EndpointError::LimitReached => Self::Capacity,
            ntcp::EndpointError::Connection(ntcp::Error::NoMemory) => Self::NoMemory,
            ntcp::EndpointError::OutputReserved => Self::WouldBlock(BlockReason::OutputReserved),
            ntcp::EndpointError::Connection(ntcp::Error::TimeWentBackwards) => {
                Self::TimeWentBackwards
            }
            other => Self::Tcp(other),
        }
    }
}
impl<E: Into<Error>> From<ntcp::ManagedError<E>> for Error {
    fn from(e: ntcp::ManagedError<E>) -> Self {
        match e {
            ntcp::ManagedError::Provider(e) => e.into(),
            ntcp::ManagedError::Endpoint(e) => e.into(),
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WriteOptions {
    pub timestamps: TxTimestampRequest,
}

/// An active open's options (`Network::connect_with`), each what an
/// application sets on a socket before connect(2).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConnectOptions {
    /// The local port, as bind(2) before connect(2); `None` takes an
    /// ephemeral port (`Network::connect_from`).
    pub local_port: Option<u16>,
    /// A send size set and locked before the SYN leaves, as SO_SNDBUF
    /// before connect(2): bytes of payload, converted from a Linux
    /// request as `Network::set_send_buffer` describes.
    pub send_buffer: Option<usize>,
    /// A receive size set and locked before the SYN leaves, as SO_RCVBUF
    /// before connect(2): bytes of window, converted from a Linux request
    /// as `Network::set_receive_buffer` describes (half of sk_rcvbuf). The
    /// SYN's window scale follows it.
    pub receive_buffer: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteReceipt {
    pub accepted: usize,
    pub range: TxStreamRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadOutcome {
    Data {
        len: usize,
        range: TxStreamRange,
        /// The RX timestamps of the last byte of this read, not of every
        /// byte; None when RX timestamps are off
        /// (`NetworkConfig::rx_timestamp_ranges` 0).
        last_byte_timestamps: Option<RxReadTimestamps>,
    },
    Eof,
    EmptyBuffer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionInfo {
    pub local: SocketAddr,
    pub peer: SocketAddr,
    pub state: State,
    pub reason: Option<CloseReason>,
    pub application_closed: bool,
    pub network_stopped: bool,
}

/// What a connection is ready for now (`Network::readiness`), as poll(2)
/// reports a socket.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Readiness {
    /// `try_read` would not block: data, the end of the stream or the end
    /// of the connection is there to read.
    pub readable: bool,
    /// `try_write` would take at least one octet.
    pub writable: bool,
    /// The peer has finished sending, or the connection ended (POLLRDHUP).
    pub read_closed: bool,
    /// Both directions have finished, or the connection ended (POLLHUP);
    /// `connection_info` tells why.
    pub closed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    Connected(ConnId),
    /// Data, the end of the stream or the end of the connection is there to
    /// read. Raised when a read (`try_read`, or `Network::readiness` finding
    /// nothing) is followed by something to read, when a read leaves some,
    /// and on every arrival of data or the peer's FIN, also while earlier
    /// data is unread, as Linux wakes a socket for each segment it queues:
    /// at most once per connection per drain.
    Readable(ConnId),
    Writable(ConnId),
    Closed {
        connection: ConnId,
        reason: Option<CloseReason>,
    },
    Acceptable(ListenerId),
    PassiveError {
        listener: ListenerId,
        peer: SocketAddr,
        error: ntcp::NetworkError,
    },
    RouteAdvice {
        local: SocketAddr,
        peer: SocketAddr,
    },
    NetworkStopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimestampEvent {
    pub connection: ConnId,
    pub observation: TxTimestampEvent,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DrainReport {
    pub written: usize,
    pub more: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkBudget {
    pub receive: usize,
    /// Frames handed to the backend, or tried. An aggregate the backend
    /// segments (TCP segmentation offload) is one, as Linux's qdisc quota
    /// counts a GSO skb once; `DriveReport::transmitted` and
    /// `Counters::transmitted` count its segments, as a device's tx_packets
    /// does.
    pub transmit: usize,
    pub timers: usize,
    pub reclaim: usize,
}
impl WorkBudget {
    pub const fn new(receive: usize, transmit: usize, timers: usize, reclaim: usize) -> Self {
        Self {
            receive,
            transmit,
            timers,
            reclaim,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DriveReport {
    pub received: usize,
    pub transmitted: usize,
    pub discarded: usize,
    pub reclaimed: usize,
    pub more_work: bool,
    pub tx_blocked: bool,
    pub next_deadline: Option<Instant>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimestampSupport {
    pub scheduled: bool,
    pub acknowledged: bool,
    pub software_transmit: bool,
    pub hardware_transmit: bool,
    pub software_receive: bool,
    pub hardware_receive: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counters {
    pub received: u64,
    pub transmitted: u64,
    // Aggregates the backend took to segment, whose segments transmitted
    // counts, and aggregates it refused (Unsupported or InvalidInput),
    // whose output went out a segment at a time instead.
    pub segmented: u64,
    pub segmentation_refused: u64,
    // Every frame, datagram and segment this Network discarded, received or
    // to be sent: the sum of `drops`.
    pub discarded: u64,
    pub backend_backpressure: u64,
    pub timestamp_metadata_lost: u64,
    pub retained_input: usize,
    // ARP frames accepted (to this port's MAC or broadcast) and submitted.
    pub arp_received: u64,
    pub arp_sent: u64,
    // ARP resolutions and unreachability probes that failed.
    pub resolution_failures: u64,
    // A member of shared flows: packets it received for another member's
    // flow and copied into that member's inbox, packets it took from its
    // own inbox, and handoffs it dropped (the owner's inbox full, or no
    // member of the owner's number). A packet copied in as its owner
    // leaves stays in that inbox: the next member of the number discards
    // what is there when it joins and takes in what lands after. The
    // members' handoffs_received fall short of their handed_off by those
    // packets and by what waits.
    pub handed_off: u64,
    pub handoffs_received: u64,
    pub handoffs_dropped: u64,
    // A member of shared flows: SYNs of its own flows that it handed to a
    // member listening on their port, not listening there itself (also in
    // handed_off), and those it dropped instead because its share already
    // had `SharedFlowLimits::redirected_flows` flows held elsewhere (also
    // in discarded).
    pub redirected: u64,
    pub redirects_dropped: u64,
    // SYNs, and last ACKs of handshakes, a listener dropped because its
    // accept queue (established connections not yet accepted, at most
    // backlog + 1) was full: Linux's ListenOverflows
    // (`Endpoint::listen_overflows`). A dropped last ACK leaves its
    // connection half-open, its SYN-ACK retransmitted, and counts again for
    // each such ACK until accept() makes room.
    pub listen_overflows: u64,
    // What a listener dropped for lack of room: listen_overflows, SYNs its
    // full SYN queue (half-open connections, at most backlog + 1) refused,
    // and SYNs refused for want of a connection slot or buffer budget,
    // whose connection could not be allocated or that had no path to answer
    // on: Linux's ListenDrops (`Endpoint::listen_drops`). Each such packet
    // is also in discarded. An active open refused for want of a slot fails
    // with Error::Capacity instead, one for want of an ephemeral port with
    // Error::AddressNotAvailable, and one whose buffers the budget or the
    // allocator refused with Error::NoMemory.
    pub listen_drops: u64,
    // Segments discarded because their TCP checksum was wrong: Linux's Tcp
    // InCsumErrors (`Endpoint::checksum_errors`). Each is also in
    // discarded.
    pub tcp_checksum_errors: u64,
    // Arriving IPv4 packets and fragments discarded for an error in their
    // header, a bad header checksum included: Linux's Ip InHdrErrors
    // (`Host::ipv4_header_errors`). Each is also in discarded; a frame whose
    // Ethernet framing (`ntcp_ethernet::parse_ethernet_fragment`) already
    // failed is in discarded only.
    pub ip_header_errors: u64,
    // Connections in TIME-WAIT now, released or not: Linux's sockstat `tw`
    // (`Endpoint::time_wait_connections`).
    pub time_wait_connections: usize,
    // Released connections closed without TIME-WAIT because the endpoint
    // already kept max_time_wait records: Linux's TCPTimeWaitOverflow
    // (`Endpoint::time_wait_overflows`).
    pub time_wait_overflows: u64,
    // Cumulative loss and retransmission events, after Linux's MIB
    // (`ntcp::LossCounters`, `Endpoint::loss_counters`). A segment counts
    // once the backend took it, each segment of an aggregate once.
    // Segments sent carrying retransmitted sequence space: Linux's
    // RetransSegs.
    pub retransmitted_segments: u64,
    // Of those, the ones sent while recovering from a retransmission
    // timeout (Linux's TCP_CA_Loss: TCPSlowStartRetrans and the timer's own
    // resends).
    pub timeout_retransmitted_segments: u64,
    // Retransmission timeouts, SYN and SYN-ACK ones and each backoff
    // included: Linux's TCPTimeouts.
    pub timeouts: u64,
    // Tail loss probes sent: Linux's TCPLossProbes.
    pub loss_probes: u64,
    // ACKs showing a retransmitting loss probe repaired a loss: Linux's
    // TCPLossProbeRecovery.
    pub loss_probe_recoveries: u64,
    // Entries into SACK-based (RFC 6675 or RACK) loss recovery: Linux's
    // TCPSackRecovery.
    pub sack_recoveries: u64,
    // Entries into NewReno fast recovery, without SACK information: Linux's
    // TCPRenoRecovery.
    pub reno_recoveries: u64,
    // ACKs carrying a D-SACK: Linux's TCPDSACKRecv plus TCPDSACKOfoRecv.
    pub dsack_received: u64,
    // Writes that took fewer octets than offered, or none (WouldBlock),
    // because the buffer budget (tcp.max_buffer_bytes) or the allocator
    // refused their send storage, not because the send buffer was full:
    // where Linux's tcp_sendmsg waits in sk_stream_wait_memory, which no
    // MIB counts (`Endpoint::memory_throttled_writes`). The connection is
    // writable again once memory comes back to the budget.
    pub memory_throttled_writes: u64,
    // Buffer memory (`ntcp::MemoryCounters`, `Endpoint::memory_counters`).
    // The bytes this Network charged now against tcp.max_buffer_bytes, or
    // against its group's cap for a member of shared flows that shares
    // buffer memory: sockstat TCP `mem`, in bytes. The members' values sum
    // to the group's charge, which the group's published count
    // (`ntcp::SharedBufferMemory::buffer_bytes`) trails by less than a
    // batch per member.
    pub buffer_bytes: usize,
    // Under memory pressure now: since the charge exceeded
    // tcp.buffer_memory().pressure, until it fell to its low (Linux's
    // tcp_memory_pressure). For a member of shared buffer memory this and
    // the next two are the group's, as Linux keeps one pressure state for
    // every CPU: the group's charge against its thresholds, its entries
    // and its time, the same in every member. Read them from any one
    // member (`SharedFlows::buffer_memory` gives the group); a sum over
    // members counts each pressure once per member.
    pub memory_pressure: bool,
    // Entries into memory pressure: Linux's TCPMemoryPressures.
    pub memory_pressures: u64,
    // Microseconds under memory pressure, in the Network's clock, the
    // current pressure included up to the last call (Linux's
    // TCPMemoryPressuresChrono counts milliseconds of ended pressures).
    pub memory_pressure_us: u64,
    // Connects refused with Error::NoMemory, and SYNs and Fast Open
    // children dropped because the budget or the allocator refused their
    // storage (also in listen_drops). Linux has no MIB for this.
    pub memory_refused_opens: u64,
    // Storage growths refused by the budget, memory pressure or the
    // allocator, at write or in a buffer setter: Linux's
    // __sk_mem_raise_allocated suppressing an allocation (no MIB).
    pub memory_refused_growths: u64,
    // SACK splits of a RACK ledger entry refused, at twice the send limit
    // plus 128 KiB of send usage (Linux's TCPWqueueTooBig) or where the
    // entries the writes allocated ran out: the entry stays whole and
    // that SACK block yields no loss inference about it.
    pub ledger_split_refusals: u64,
    // Every discard by reason (`ntcp::DropReason`), which `discarded` sums:
    // Linux's per-reason kfree_skb counts. tcp_checksum_errors is
    // `TcpCsum`; ip_header_errors is `IpCsum` plus the IPv4 share of
    // `IpInhdr` and `PktTooSmall`; handoffs_dropped is `CpuBacklog`;
    // redirects_dropped is `RedirectTableFull`; listen_drops is
    // `TcpListenOverflow`, `TcpSynQueueOverflow`, `TcpConnectionLimit`,
    // `MemoryRefused` and the listeners' `IpOutnoroutes`, and
    // listen_overflows `TcpListenOverflow`.
    pub drops: ntcp::DropCounts,
    // Discards the enabled feed had no room to report
    // (`Network::set_drop_feed`).
    pub drop_events_lost: u64,
}
