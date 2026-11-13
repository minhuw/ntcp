extern crate alloc;

#[cfg(all(test, feature = "tfo-linux-cookie"))]
#[path = "mac_cost_tests.rs"]
pub(crate) mod mac_cost_tests;

use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use core::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU8,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{
    FastOpenCookiePolicy, Ipv4Options, Ipv4OptionsError, OutgoingIpv4Options, RxPacketTimestamps,
    RxReadTimestamps, RxTimestampStatus, SendProgress, SourceRoute, TimestampRequest,
    TxTimestampClock, TxTimestampEvent, TxTimestampRequest, TxTimestampSource, TxTimestampStage,
    TxTimestampToken,
    buffer::ReceiveBuffer,
    connection::{Connection, ConnectionConfig, ConnectionEvents, Error, Instant, ScopedTuple, State, Tuple},
    rx_timestamp::RxTimestamps,
    schedule::{Deadlines, ReadyQueue},
    seq::Seq,
    wire::{self, ACK, Header, IpMetadata, RST, SYN},
};

// A managed drain's provider of the complete IP header length of the path a
// stateless reply with these addresses (and zone) leaves on now.
pub(crate) type ReplyHeader<'a> =
    Option<&'a mut dyn FnMut(IpMetadata, Option<ntcp_path::LinkId>) -> Option<u16>>;

// Per-active-open parameters; endpoint allocation and protocol policy remain authoritative.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveOpenOptions {
    pub send_capacity: usize,
    pub receive_capacity: usize,
    // None removes the per-open application cap. Legacy wrappers inherit the
    // endpoint setting through From<&ConnectionConfig>.
    pub user_mss: Option<u16>,
}
impl From<&ConnectionConfig> for ActiveOpenOptions {
    fn from(config: &ConnectionConfig) -> Self {
        Self {
            send_capacity: config.send_capacity,
            receive_capacity: config.receive_capacity,
            user_mss: config.user_mss,
        }
    }
}
impl ActiveOpenOptions {
    fn validate(self) -> Result<(), Error> {
        Connection::validate_buffer_capacities(self.send_capacity, self.receive_capacity)?;
        if self.user_mss == Some(0) {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ConnectionId {
    slot: usize,
    generation: u64,
}
impl ConnectionId {
    /// The connection's slot, below the endpoint's `max_connections` and
    /// shared by the slot's successive generations: an index for tables an
    /// embedding keeps per connection.
    pub fn index(self) -> usize {
        self.slot
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ListenerId {
    slot: usize,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressValidation {
    Bind {
        local: IpAddr,
    },
    Open {
        local: IpAddr,
        remote: IpAddr,
    },
    Incoming {
        source: IpAddr,
        destination: IpAddr,
    },
    Route {
        source: IpAddr,
        destination: IpAddr,
        hop: IpAddr,
    },
}

#[derive(Clone, Debug)]
pub struct EndpointConfig {
    pub max_connections: usize,
    pub preallocate_connections: usize,
    pub ipv4_options_enabled: bool,
    pub error_reports: bool,
    // A SYN that passes RFC 6191's checks reopens a tuple in TIME-WAIT for
    // the listener on its port, as Linux's always does (TCP_TW_SYN). Off in
    // the RFC baseline; an active open never takes a tuple in TIME-WAIT.
    pub reuse_time_wait: bool,
    // TIME-WAIT records kept for released connections, Linux's
    // tcp_max_tw_buckets: beyond it a connection closes without TIME-WAIT.
    pub max_time_wait: usize,
    pub max_listeners: usize,
    pub max_control_packets: usize,
    // Bounded FIFO of local/remote IP pairs with inferred initial/restart loss.
    pub max_setup_cache_entries: usize,
    pub max_route_policies: usize,
    // The hard cap on the bytes charged for connection storage, Linux's
    // tcp_mem[2].
    pub max_buffer_bytes: usize,
    // Where memory pressure begins and ends (`buffer_memory`), Linux's
    // tcp_mem[1] and tcp_mem[0]: None is ⌊max_buffer_bytes·2/3⌋ and
    // ⌊max_buffer_bytes/2⌋. Given, low < pressure ≤ max_buffer_bytes.
    pub buffer_pressure_bytes: Option<usize>,
    pub buffer_low_bytes: Option<usize>,
    pub hop_limit: u8,
    pub dscp: u8,
    pub connection: ConnectionConfig,
}

impl EndpointConfig {
    pub fn validate(&self) -> Result<(), EndpointError> {
        if !(1..=1_024).contains(&self.max_setup_cache_entries)
            || self.max_route_policies > 1024
            || self.connection.advertised_mss == Some(0)
            || self.connection.pmtud.is_some_and(|p| p.first_hop_mtu < 68)
            || !self.connection.valid_timestamp_timebase()
            || !self.connection.valid_pacing()
            // As in ConnectionConfig::validate: TIME-WAIT must outlive the
            // instant it begins so the ACK of the peer's FIN is still sent.
            || self.connection.time_wait_us == 0
            || self.connection.timestamp_bytes_per_tick == 0
            || self.connection.timestamp_bytes_per_tick >= 1 << 31
            || self.connection.challenge_ack_limit == 0
            || self.connection.challenge_ack_interval_us == 0
            || self.max_connections == 0
            || self.max_time_wait > 1 << 30
            || self.connection.send_ip_payload_limit < self.connection.minimum_send_budget()
            || self.max_listeners == 0
            || self.hop_limit == 0
            || self.dscp > 63
            || self.connection.send_capacity_min == 0
            || self.connection.send_capacity_max >= 1 << 30
            || self.connection.receive_capacity_min == 0
            || self.connection.receive_capacity_max > (65535usize << 14)
        {
            return Err(Error::InvalidArgument.into());
        }
        if let Some(p) = self.connection.pmtud {
            p.policy
                .search_aging
                .ticks(self.connection.timebase.units_per_second)?;
            if self.connection.validate(true).is_err() && self.connection.validate(false).is_err() {
                return Err(Error::InvalidArgument.into());
            }
        }
        if self.buffer_pressure_bytes.is_some() || self.buffer_low_bytes.is_some() {
            let memory = self.buffer_memory();
            if memory.low >= memory.pressure || memory.pressure > memory.high {
                return Err(Error::InvalidArgument.into());
            }
        }
        self.preallocation_bytes()?;
        Ok(())
    }

    /// The buffer memory thresholds, Linux's tcp_mem in bytes: `high` is
    /// `max_buffer_bytes`, the hard cap; pressure begins once the charge
    /// exceeds `pressure` and ends once it is at most `low`
    /// (`buffer_pressure_bytes`, `buffer_low_bytes`, by default ⅔ and ½ of
    /// the cap, tcp_init_mem's ratios).
    pub fn buffer_memory(&self) -> crate::BufferMemory {
        crate::BufferMemory::resolve(
            self.max_buffer_bytes,
            self.buffer_pressure_bytes,
            self.buffer_low_bytes,
        )
    }

    /// The buffer configuration in force, as Linux's tcp_wmem, tcp_rmem and
    /// tcp_mem sysctls print it: `ConnectionConfig::send_buffer` and
    /// `receive_buffer`, and `buffer_memory`.
    pub fn buffers(&self) -> crate::Buffers {
        crate::Buffers {
            send: self.connection.send_buffer(),
            receive: self.connection.receive_buffer(),
            memory: self.buffer_memory(),
        }
    }

    /// The share of `max_buffer_bytes` one connection with the configured
    /// buffers and MSS is charged at open, once its TX timestamp phases and
    /// RX timestamp ranges are set to these capacities: what it allocates
    /// before its first write, the receive ring (1.375 bytes per byte of
    /// `receive_capacity`), its MSS-sized scratch segment and its sender
    /// ledgers' first entries. A budget of N of these admits N connections
    /// and no more: each is charged what it actually allocates, so its first
    /// write adds a send ring of 2 bytes per byte of `send_capacity`, and its
    /// RACK and SACK ledgers grow with the bytes it holds queued, 64 and 4
    /// bytes per byte. None if it overflows.
    pub fn connection_charge(
        &self,
        tx_timestamp_phases: usize,
        rx_timestamp_ranges: usize,
    ) -> Option<usize> {
        Connection::open_bytes(
            self.connection.receive_capacity,
            usize::from(self.connection.mss),
        )?
        .checked_add(crate::tx_timestamp::TxTimestamps::allocation_bytes(
            tx_timestamp_phases,
        )?)?
        .checked_add(crate::rx_timestamp::RxTimestamps::allocation_bytes(
            rx_timestamp_ranges,
        )?)
    }

    /// The share of `max_buffer_bytes` taken by `count` output reservations
    /// (`enable_output_reservations_with_packet_bytes` with the same
    /// arguments). Each holds one TCP packet of up to `packet_bytes`, at
    /// most `send_ip_payload_limit`, and with `gso` the payload of one
    /// aggregate. `enable_output_reservations_with_capacity`, or `_with_gso`
    /// with `gso`, charges `packet_bytes` of `usize::MAX`: a packet of the
    /// send limit. None if it overflows.
    pub fn output_reservations_charge(
        &self,
        count: usize,
        packet_bytes: usize,
        gso: Option<crate::GsoLimits>,
    ) -> Option<usize> {
        packet_bytes
            .min(self.connection.send_ip_payload_limit as usize)
            .checked_add(gso.map_or(0, |limits| limits.max_bytes))?
            .checked_add(core::mem::size_of::<
                crate::output_reservation::OutputReservation,
            >())?
            .checked_mul(count)
    }

    fn preallocation_bytes(&self) -> Result<(usize, usize), EndpointError> {
        // A pooled connection is a receive ring at the initial size. It is
        // charged the open charge of the connection that will take it, the
        // ring plus that connection's scratch segment and first ledger
        // entries, so a budget that holds the pool admits its connections.
        let per_connection_bytes = Connection::open_bytes(
            self.connection.receive_capacity,
            usize::from(self.connection.mss),
        )
        .ok_or(EndpointError::LimitReached)?;
        if self.preallocate_connections > self.max_connections {
            return Err(EndpointError::LimitReached);
        }
        let buffer_bytes = self
            .preallocate_connections
            .checked_mul(per_connection_bytes)
            .filter(|&bytes| bytes <= self.max_buffer_bytes)
            .ok_or(EndpointError::LimitReached)?;
        Ok((per_connection_bytes, buffer_bytes))
    }
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            preallocate_connections: 0,
            ipv4_options_enabled: false,
            error_reports: true,
            reuse_time_wait: false,
            // Linux's default for a 2^17-bucket established hash (half of it).
            max_time_wait: 65_536,
            max_listeners: 64,
            max_control_packets: 64,
            max_setup_cache_entries: 64,
            max_route_policies: 64,
            max_buffer_bytes: 256 * 1024 * 1024,
            buffer_pressure_bytes: None,
            buffer_low_bytes: None,
            hop_limit: 64,
            dscp: 0,
            connection: ConnectionConfig::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointError {
    Connection(Error),
    InvalidHandle,
    OutputReserved,
    ReservationMtuTooSmall,
    LimitReached,
    AddressInUse,
    InvalidAddress,
    Ipv4Options(Ipv4OptionsError),
    Registration(crate::Ipv4RegistrationError),
}
impl From<Ipv4OptionsError> for EndpointError {
    fn from(error: Ipv4OptionsError) -> Self {
        Self::Ipv4Options(error)
    }
}
impl From<crate::Ipv4RegistrationError> for EndpointError {
    fn from(error: crate::Ipv4RegistrationError) -> Self {
        Self::Registration(error)
    }
}
impl From<Error> for EndpointError {
    fn from(error: Error) -> Self {
        Self::Connection(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Connection(ConnectionId, ConnectionEvents),
    Acceptable(ListenerId),
    RouteAdvice(Tuple),
    PassiveError {
        listener: ListenerId,
        tuple: Tuple,
        error: crate::NetworkError,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transmit {
    pub tx_timestamp: Option<TxTimestampToken>,
    // Stable owner, including connection-associated final resets.
    pub connection: Option<ConnectionId>,
    pub ipv4_options: OutgoingIpv4Options,
    pub ecn: u8,
    pub ip: IpMetadata,
    pub len: usize,
    pub hop_limit: u8,
    pub dscp: u8,
    // The packet mark (Linux's SO_MARK) for the backend to tag it with:
    // the connection's, kept by its TIME-WAIT record, and 0 for a reply
    // without one, as Linux's control socket has.
    pub mark: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollTransmit {
    pub packet: Option<Transmit>,
    pub more_work: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputDisposition {
    Processed,
    Dropped,
}

#[derive(Clone, Copy)]
enum Entry {
    Empty,
    Deleted,
    Occupied(ScopedTuple, usize),
}

struct TupleTable {
    entries: Vec<Entry>,
}
impl TupleTable {
    fn new(capacity: usize) -> Result<Self, EndpointError> {
        let count = capacity
            .checked_mul(2)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(EndpointError::LimitReached)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count)
            .map_err(|_| Error::NoMemory)?;
        entries.resize(count, Entry::Empty);
        Ok(Self { entries })
    }
    fn find(&self, hash: usize, tuple: ScopedTuple) -> Option<usize> {
        for probe in 0..self.entries.len().min(64) {
            let position = hash.wrapping_add(probe) & (self.entries.len() - 1);
            match self.entries[position] {
                Entry::Occupied(key, slot) if key == tuple => return Some(slot),
                Entry::Empty => return None,
                _ => {}
            }
        }
        None
    }
    fn insert(&mut self, hash: usize, tuple: ScopedTuple, slot: usize) -> Result<(), EndpointError> {
        // A keyed hash plus a fixed probe budget bounds hostile lookup work.
        for probe in 0..self.entries.len().min(64) {
            let position = hash.wrapping_add(probe) & (self.entries.len() - 1);
            if !matches!(self.entries[position], Entry::Occupied(..)) {
                self.entries[position] = Entry::Occupied(tuple, slot);
                return Ok(());
            }
        }
        Err(EndpointError::LimitReached)
    }
    fn replace(&mut self, hash: usize, tuple: ScopedTuple, old: usize, new: usize) -> bool {
        for probe in 0..self.entries.len().min(64) {
            let position = hash.wrapping_add(probe) & (self.entries.len() - 1);
            match self.entries[position] {
                Entry::Occupied(key, slot) if key == tuple => {
                    if slot != old {
                        return false;
                    }
                    self.entries[position] = Entry::Occupied(tuple, new);
                    return true;
                }
                Entry::Empty => return false,
                _ => {}
            }
        }
        false
    }

    fn remove(&mut self, hash: usize, tuple: ScopedTuple, owner: usize) {
        for probe in 0..self.entries.len().min(64) {
            let position = hash.wrapping_add(probe) & (self.entries.len() - 1);
            match self.entries[position] {
                Entry::Occupied(key, slot) if key == tuple => {
                    if slot != owner {
                        return;
                    }
                    self.entries[position] = Entry::Deleted;
                    return;
                }
                Entry::Empty => return,
                _ => {}
            }
        }
    }
}

struct Slot {
    // Boxed, so a table of `max_connections` slots holds pointers rather
    // than ~10 KB connections, and a connection moves into and out of its
    // slot by pointer.
    connection: Box<Connection>,
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.5
    //# Note that a TCP implementation MUST keep track of whether a
    //# connection has reached SYN-RECEIVED state as the result of a passive
    //# OPEN or an active OPEN (MUST-11).
    listener: Option<ListenerId>,
    accepted_ready: bool,
    // Independent of accept-queue ownership: early accept must not free quota.
    fast_open_owner: Option<ListenerId>,
    receive_authority: Option<ListenerId>,
    released: bool,
    closed_output_drained: bool,
    mapped: bool,
    // While the connection waits for memory (`memory_waiters`), when it
    // looks again whether its growth fits (`memory_throttled`).
    memory_retry: Option<Instant>,
    // The connection's state was TIME-WAIT at its last refresh: counted in
    // `time_wait_connections`.
    time_wait: bool,
    hop_limit: u8,
    dscp: u8,
    mark: u32,
    // The application's SO_REUSEADDR, which its TIME-WAIT record keeps.
    reuse_address: bool,
    received_dscp: Option<u8>,
    ipv4_options: OutgoingIpv4Options,
    explicit_route: bool,
    received_ipv4_options: Option<Ipv4Options>,
}

impl Slot {
    // Neither closed nor in TIME-WAIT, counted as it is, with no listener
    // handoff or Fast Open owner left: the state part of Endpoint::refresh
    // has nothing to do.
    fn steady(&self) -> bool {
        !matches!(self.connection.state(), State::Closed | State::TimeWait)
            && !self.time_wait
            && self.fast_open_owner.is_none()
            && (self.listener.is_none() || self.accepted_ready)
    }

    // The slot's next timer: the connection's, or the retry of a wait for
    // memory if that comes first.
    fn deadline(&self) -> Option<Instant> {
        match (self.connection.next_deadline(), self.memory_retry) {
            (Some(deadline), Some(retry)) => Some(deadline.min(retry)),
            (deadline, retry) => deadline.or(retry),
        }
    }
}
// What a segment's tuple names: a connection slot or a TIME-WAIT record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Target {
    Connection(usize),
    TimeWait(u32),
}

// Only Endpoint can construct this invocation-scoped decision. It carries no
// retained key or permission; Connection still validates the crossing SYN.
pub(crate) struct CrossingSynAuthorization {
    early: bool,
    response: Option<wire::FastOpenCookie>,
}

impl CrossingSynAuthorization {
    pub(crate) fn consume(self) -> (bool, Option<wire::FastOpenCookie>) {
        (self.early, self.response)
    }
}

// Why passive admission refuses a SYN (`Endpoint::passive_refusal`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PassiveRefusal {
    // The connection of its tuple may not be reopened: it still owes its
    // reset, or it is in TIME-WAIT and the SYN is not fresh (RFC 6191).
    TimeWait,
    // The listener's SYN queue (its half-open children) is full.
    SynQueue,
    // The listener's accept queue (its established, unaccepted children) is
    // full: Linux's ListenOverflows.
    AcceptQueue,
    // No connection slot for the connection.
    Resources,
    // No buffer budget for the connection's storage.
    Memory,
    // A tuple no connection may have (a zero port).
    Invalid,
}

struct Listener {
    early_data_policy: crate::FastOpenEarlyDataPolicy,
    fast_open_cookie_policy: Option<crate::fast_open::ServerCookieContext>,
    fast_open_limit: usize,
    reset_debt: usize,
    reset_debt_expiry: Option<Instant>,
    rx_timestamp_capacity: usize,
    buffer_capacities: (usize, usize),
    // The send and receive sizes a setter locked (`set_listener_send_buffer`,
    // `set_listener_receive_buffer`): children take them locked, as a
    // child socket inherits its listener's sk_userlocks.
    buffer_locks: (bool, bool),
    application_timeout_us: Option<u64>,
    handshake_retransmission_limit: Option<NonZeroU8>,
    user_mss: Option<u16>,
    address: SocketAddr,
    // Present exactly for a link-local address of a managed Endpoint.
    zone: Option<ntcp_path::LinkId>,
    // The listen() backlog, Linux's sk_max_ack_backlog: it bounds the SYN
    // queue and the accept queue each.
    backlog: usize,
    // Every unaccepted child, half-open or established; `pending` the
    // established ones, in the order they joined the accept queue.
    children: Vec<ConnectionId>,
    pending: VecDeque<ConnectionId>,
    closing: bool,
}

impl Listener {
    // As Linux's inet_csk_reqsk_queue_is_full and sk_acceptq_is_full, a
    // queue is full once it holds more than the backlog, so a SYN or a
    // handshake's last ACK finding one entry fewer makes it backlog + 1.
    fn syn_queue_full(&self) -> bool {
        self.children.len() - self.pending.len() > self.backlog
    }

    fn accept_queue_full(&self) -> bool {
        self.pending.len() > self.backlog
    }

    fn reset_debt(&mut self, now: Instant) -> usize {
        if self.reset_debt_expiry.is_some_and(|expiry| now >= expiry) {
            self.reset_debt = 0;
            self.reset_debt_expiry = None;
        }
        self.reset_debt
    }
}

// An endpoint and its policy are bound to one ingress network context. Policies
// may select routes using the address pair and capture owned network state.
// Ambiguous overlapping ingress domains need separate endpoints, not implicit
// context guessing from addresses.
#[path = "endpoint_managed.rs"]
mod managed;
pub use managed::{
    ConfirmedProbe, CorrelatedPmtu, CorrelatedSegment, PendingPmtuApplied, PhysicalReceipt,
};
pub(crate) use managed::ManagedResults;

pub struct Endpoint {
    managed_context: Option<ntcp_path::ContextId>,
    factory_transaction: Option<crate::managed_path::FactoryTransaction>,
    #[cfg(feature = "packet-test-controls")]
    test_timestamp_default: Option<bool>,
    fast_open_cookie_policy: crate::fast_open::ServerCookieContext,
    fast_open_credentials: crate::fast_open::CredentialRegistry,
    fast_open_hmac_key: [u8; 32],
    fast_open_hmac_error: Option<Error>,
    fast_open: Option<crate::fast_open::FastOpen>,
    reservations: Vec<crate::output_reservation::OutputReservation>,
    // Reservation bookkeeping, kept in step with every change of a slot's
    // `current` or its `attempt` (`check_reservation_index`): the slot held
    // by each connection slot index and by the stateless lane, the number of
    // free slots, and the held slots without a current attempt.
    reservation_owners: Vec<Option<usize>>,
    stateless_reservation: Option<usize>,
    free_reservations: usize,
    unattempted_reservations: ReadyQueue,
    address_policy: Box<dyn Fn(AddressValidation) -> bool>,
    config: EndpointConfig,
    routes: Vec<(IpAddr, crate::RoutePolicy)>,
    // HMAC-SHA256 keyed with the endpoint's secret, before any input: the
    // key's inner and outer pad blocks are hashed once here, not again for
    // every digest (two per connection: its ISN and its TSval offset).
    keyed: Hmac<Sha256>,
    // SipHash key of the connection-table hash (`hash`), derived from the
    // secret.
    lookup_key: [u8; 16],
    now: Instant,
    isn_clock: u32,
    last_isn_time: Instant,
    slots: Vec<Option<Slot>>,
    // The occupied `slots`, for counts over live connections.
    occupied: ReadyQueue,
    generations: Vec<u64>,
    free: Vec<usize>,
    listeners: Vec<Option<Listener>>,
    listener_generations: Vec<u64>,
    tuples: TupleTable,
    output: ReadyQueue,
    events: ReadyQueue,
    advice: ReadyQueue,
    cleanup: ReadyQueue,
    // Managed connections whose SND.UNA moved from `progress_una`, or that
    // hold results to publish, since `next_progress` last gave them.
    progress: ReadyQueue,
    progress_una: Vec<u32>,
    // Connections whose write found its storage growth refused for memory,
    // oldest first, each once: memory coming back wakes them in this order
    // while what each needs fits (`wake_memory_waiters`). Preallocated with
    // a link per slot, so a refusal never allocates and a wake visits only
    // the connections it wakes and the first it cannot.
    memory_waiters: ReadyQueue,
    // Draws for the waiters' random retry delays (`memory_retry_delay`).
    memory_retry_draws: u64,
    // `memory_counters`.
    memory_throttled_writes: u64,
    memory_refused_opens: u64,
    memory_refused_growths: u64,
    // MemoryCounters::ledger_split_refusals, taken from connections at
    // their refresh and reclaim.
    ledger_split_refusals: u64,
    deadlines: Deadlines,
    reclaimed: u64,
    // The last `max_connections` reclaimed connections, the one counted
    // `n` (from 0) at `n % max_connections`: `reclaimed_since`.
    reclaims: Vec<ConnectionId>,
    // `listen_overflows`, `listen_drops` and `time_wait_connections`, the
    // last for connections; records count themselves.
    listen_overflows: u64,
    listen_drops: u64,
    // `checksum_errors`.
    checksum_errors: u64,
    time_wait_slots: usize,
    time_wait: crate::time_wait::TimeWaitTable,
    // Released connections that closed without TIME-WAIT because the table
    // was full (Linux's TCPTimeWaitOverflow).
    time_wait_overflows: u64,
    // `loss_counters`: what connections counted, taken at their refresh or
    // reclaim.
    loss_counters: crate::LossCounters,
    // Stateless replies: addresses, header, IPv4 options, timestamp echo and,
    // when a managed provider stated it at queueing, the complete IP header
    // length (extensions included) of the IPv6 path the reply leaves on (a
    // managed drain states it again for the path selected then), and
    // the arrival link of the input that caused it when one of its addresses
    // is IPv6 link-local (the only link the reply may leave on).
    #[allow(clippy::type_complexity)]
    control: VecDeque<(
        IpMetadata,
        Header,
        OutgoingIpv4Options,
        Option<u32>,
        Option<u16>,
        Option<ntcp_path::LinkId>,
    )>,
    // Stateless replies discarded because even their minimal form could not
    // fit the path: dropped once, never retried.
    oversized_control: u64,
    // Scoped stateless replies whose link was gone before they drained.
    undeliverable_control: u64,
    passive_errors: VecDeque<Event>,
    control_epoch: Instant,
    control_count: usize,
    control_turn: bool,
    // The bytes charged against max_buffer_bytes and the pressure state.
    budget: crate::memory::Budget,
    per_connection_bytes: usize,
    receive_pool: Vec<ReceiveBuffer>,
    // ponytail: conservative FIFO loss retention until eviction; add path-qualified
    // aging only when measured deployment behavior warrants it.
    setup_loss_cache: VecDeque<(IpAddr, IpAddr, Option<ntcp_path::LinkId>)>,
}

// A member of shared buffer memory that goes leaves its group
// (`Endpoint::leave_buffer_memory`).
impl Drop for Endpoint {
    fn drop(&mut self) {
        self.budget.leave_group(self.now);
    }
}

fn keyed_mac(secret: &[u8; 32], domain: &[u8]) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts a 32-byte key");
    mac.update(domain);
    mac
}

// Family-tagged addresses and ports, then the link identity of a scoped
// tuple: the input of the tuple digests and of the lookup hash.
fn encode_tuple(scoped: ScopedTuple, mut write: impl FnMut(&[u8])) {
    let tuple = scoped.tuple();
    for address in [tuple.local, tuple.remote] {
        match address.ip() {
            IpAddr::V4(ip) => {
                write(&[4]);
                write(&ip.octets());
            }
            IpAddr::V6(ip) => {
                write(&[6]);
                write(&ip.octets());
            }
        }
        write(&address.port().to_be_bytes());
    }
    if let Some(zone) = scoped.zone() {
        write(b"zone");
        write(&zone.to_bytes());
    }
}

fn reserved_vec<T>(capacity: usize) -> Result<Vec<T>, EndpointError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(capacity)
        .map_err(|_| Error::NoMemory)?;
    Ok(result)
}

fn supported_socket(address: SocketAddr) -> bool {
    !matches!(address, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.flowinfo() != 0)
}

fn unzoned_link_local(address: IpAddr) -> bool {
    matches!(address, IpAddr::V6(ip) if ip.is_unicast_link_local())
}

fn valid_address(address: IpAddr) -> bool {
    !address.is_unspecified()
        && !address.is_multicast()
        && !matches!(address, IpAddr::V4(ip) if ip.octets()[0] == 0 || ip.octets()[0] >= 224)
}

impl Endpoint {
    /// The most payload references a shared-output packet carries, and the
    /// most spans a connection's shared payload holds apart: Linux's IOV_MAX
    /// (UIO_MAXIOV), the most buffers one writev/sendmsg takes.
    pub const MAX_SHARED_SEGMENTS: usize = 1024;

    // The caller must supply a confidential, unpredictable 32-byte key from an
    // initialized CSPRNG. The required callback captures authoritative network
    // context for this endpoint; the endpoint cannot prove the caller's policy true.
    pub fn new<F: Fn(AddressValidation) -> bool + 'static>(
        mut config: EndpointConfig,
        secret: [u8; 32],
        now: Instant,
        address_policy: F,
    ) -> Result<Self, EndpointError> {
        config.validate()?;
        if config.ipv4_options_enabled {
            // ponytail: reserve all 40 IPv4 option bytes; per-packet budgeting can reclaim slack later.
            config.connection.send_ip_payload_limit = config
                .connection
                .send_ip_payload_limit
                .min(65515)
                .checked_sub(40)
                .filter(|&budget| budget >= config.connection.minimum_send_budget())
                .ok_or(Error::InvalidArgument)?;
        }
        let mut setup_loss_cache = VecDeque::new();
        setup_loss_cache
            .try_reserve_exact(config.max_setup_cache_entries)
            .map_err(|_| Error::NoMemory)?;
        let count = config.max_connections;
        let listeners_count = config.max_listeners;
        let event_capacity = count
            .checked_add(listeners_count)
            .ok_or(EndpointError::LimitReached)?;
        let (per_connection_bytes, buffer_bytes) = config.preallocation_bytes()?;
        let mut budget = crate::memory::Budget::new();
        budget.raise(buffer_bytes, now, config.buffer_memory());
        let mut receive_pool = reserved_vec(config.preallocate_connections)?;
        for _ in 0..config.preallocate_connections {
            receive_pool.push(
                ReceiveBuffer::new(Seq(0), config.connection.receive_capacity)
                    .map_err(|_| Error::NoMemory)?,
            );
        }
        let mut slots = reserved_vec(count)?;
        slots.resize_with(count, || None);
        let mut generations = reserved_vec(count)?;
        generations.resize(count, 1);
        let mut free = reserved_vec(count)?;
        free.extend((0..count).rev());
        let mut reclaims = reserved_vec(count)?;
        reclaims.resize(
            count,
            ConnectionId {
                slot: 0,
                generation: 0,
            },
        );
        let mut listeners = reserved_vec(listeners_count)?;
        listeners.resize_with(listeners_count, || None);
        let mut listener_generations = reserved_vec(listeners_count)?;
        listener_generations.resize(listeners_count, 1);
        let mut control = VecDeque::new();
        control
            .try_reserve_exact(config.max_control_packets)
            .map_err(|_| Error::NoMemory)?;
        let mut passive_errors = VecDeque::new();
        passive_errors
            .try_reserve_exact(count)
            .map_err(|_| Error::NoMemory)?;
        Ok(Self {
            managed_context: None,
            factory_transaction: None,
            #[cfg(feature = "packet-test-controls")]
            test_timestamp_default: None,
            fast_open: None,
            fast_open_cookie_policy: crate::fast_open::ServerCookieContext::new(
                crate::FastOpenServerKey::HmacSha256(secret),
            ),
            fast_open_credentials: crate::fast_open::CredentialRegistry::new(
                &crate::FastOpenServerKey::HmacSha256(secret),
                config.connection.timebase,
                now,
            ),
            fast_open_hmac_key: secret,
            fast_open_hmac_error: None,
            reservations: Vec::new(),
            reservation_owners: Vec::new(),
            stateless_reservation: None,
            free_reservations: 0,
            unattempted_reservations: ReadyQueue::new(0).map_err(|_| Error::NoMemory)?,
            address_policy: Box::new(address_policy),
            passive_errors,
            tuples: TupleTable::new(count)?,
            occupied: ReadyQueue::new(count).map_err(|_| Error::NoMemory)?,
            output: ReadyQueue::new(count).map_err(|_| Error::NoMemory)?,
            advice: ReadyQueue::new(count).map_err(|_| Error::NoMemory)?,
            events: ReadyQueue::new(event_capacity).map_err(|_| Error::NoMemory)?,
            cleanup: ReadyQueue::new(listeners_count).map_err(|_| Error::NoMemory)?,
            progress: ReadyQueue::new(count).map_err(|_| Error::NoMemory)?,
            memory_waiters: ReadyQueue::new(count).map_err(|_| Error::NoMemory)?,
            memory_retry_draws: 0,
            memory_throttled_writes: 0,
            memory_refused_opens: 0,
            memory_refused_growths: 0,
            ledger_split_refusals: 0,
            progress_una: {
                let mut una = reserved_vec(count)?;
                una.resize(count, 0);
                una
            },
            deadlines: Deadlines::new(count).map_err(|_| Error::NoMemory)?,
            reclaimed: 0,
            reclaims,
            listen_overflows: 0,
            checksum_errors: 0,
            listen_drops: 0,
            time_wait_slots: 0,
            time_wait: crate::time_wait::TimeWaitTable::new(config.max_time_wait),
            time_wait_overflows: 0,
            loss_counters: crate::LossCounters::default(),
            isn_clock: (now / config.connection.timebase.ticks_from_us(4)) as u32,
            config,
            routes: Vec::new(),
            lookup_key: keyed_mac(&secret, b"ntcp lookup key")
                .finalize()
                .into_bytes()[..16]
                .try_into()
                .unwrap(),
            keyed: Hmac::<Sha256>::new_from_slice(&secret).expect("HMAC accepts a 32-byte key"),
            setup_loss_cache,
            now,
            last_isn_time: now,
            slots,
            generations,
            free,
            listeners,
            listener_generations,
            control,
            control_epoch: now,
            control_count: 0,
            oversized_control: 0,
            undeliverable_control: 0,
            control_turn: true,
            budget,
            per_connection_bytes,
            receive_pool,
        })
    }

    /// Resolved destination policy snapshot; no route lookup or clock mutation.
    pub fn destination_route(&self, destination: IpAddr) -> Option<crate::RoutePolicy> {
        self.routes
            .iter()
            .find(|(ip, _)| *ip == destination)
            .map(|(_, policy)| *policy)
    }

    /// Update caller-owned same-path parameters for one destination. Creation
    /// hints apply only to future active/passive children. A changed MTU ceiling
    /// applies to all matching retained connections, atomically after preflight.
    /// This is not an OS route table or a notification of a different path.
    //= https://www.rfc-editor.org/rfc/rfc4821#section-4
    //= reason=TCP destination-policy creation parameters are selected before active/passive allocation. This Endpoint policy is TCP-local; the shared IP-layer path cache and Host UDP budgets live in ntcp-path PathService and ntcp-host, and this annotation claims neither.
    //# Implementations MAY use different heuristics to select the initial effective Path MTU for each protocol. Connectionless protocols and protocols that do not support PLPMTUD SHOULD have their own default value for the initial effective Path MTU, which can be set to a more conservative (smaller) value than the initial value used by TCP and other protocols that are well suited to PLPMTUD. There SHOULD be per-protocol and per-route limits on the initial effective Path MTU (eff_pmtu) and the upper searching limit (search_high). See Section 7.2 for further discussion.
    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.2
    //= reason=TCP destination-policy creation parameters are selected before active/passive allocation. This Endpoint policy is TCP-local; the shared IP-layer path cache and Host UDP budgets live in ntcp-path PathService and ntcp-host, and this annotation claims neither.
    //# There SHOULD be per-protocol and per-route configuration options to override initial values for eff_pmtu and other PLPMTUD state variables.
    pub fn set_destination_route(
        &mut self,
        now: Instant,
        destination: IpAddr,
        policy: Option<crate::RoutePolicy>,
    ) -> Result<(), EndpointError> {
        self.check_clock(now)?;
        if !valid_address(destination) {
            return Err(EndpointError::InvalidAddress);
        }
        if let Some(policy) = policy {
            policy.validate(&self.config.connection, destination.is_ipv4())?;
        }
        let index = self.routes.iter().position(|(ip, _)| *ip == destination);
        if policy.is_some()
            && index.is_none()
            && self.routes.len() == self.config.max_route_policies
        {
            return Err(EndpointError::LimitReached);
        }
        let old = self
            .destination_route(destination)
            .unwrap_or_default()
            .route_mtu(&self.config.connection);
        let new = policy
            .unwrap_or_default()
            .route_mtu(&self.config.connection);
        if old != new {
            for (index, slot) in self
                .slots
                .iter()
                .enumerate()
                .filter_map(|(index, slot)| slot.as_ref().map(|s| (index, s)))
            {
                if slot.connection.tuple().remote.ip() == destination {
                    self.reject_if_output_reserved(self.id(index))?;
                    slot.connection.validate_route_mtu(now, new)?;
                }
            }
        }
        if policy.is_some() && index.is_none() {
            self.routes.try_reserve(1).map_err(|_| Error::NoMemory)?;
        }
        self.clock(now)?;
        if old != new {
            for i in 0..self.slots.len() {
                if self.slots[i]
                    .as_ref()
                    .is_some_and(|s| s.connection.tuple().remote.ip() == destination)
                {
                    self.slots[i]
                        .as_mut()
                        .unwrap()
                        .connection
                        .set_route_mtu(now, new)?;
                    self.refresh(i);
                }
            }
        }
        match (index, policy) {
            (Some(i), Some(policy)) => self.routes[i].1 = policy,
            (None, Some(policy)) => self.routes.push((destination, policy)),
            (Some(i), None) => {
                self.routes.swap_remove(i);
            }
            (None, None) => (),
        }
        Ok(())
    }

    /// Whether `route`, the return route reversed from a received datagram,
    /// may carry a reply from `local` to `remote`: every hop passes the base
    /// address checks and the `AddressValidation::Route` policy, as for the
    /// return route of a received TCP segment.
    pub fn admits_return_route(&self, local: IpAddr, remote: IpAddr, route: &SourceRoute) -> bool {
        route
            .hops()
            .iter()
            .all(|&hop| self.valid_route(local, remote, hop.into()))
    }

    fn valid_route(&self, source: IpAddr, destination: IpAddr, hop: IpAddr) -> bool {
        valid_address(source)
            && valid_address(destination)
            && valid_address(hop)
            && (self.address_policy)(AddressValidation::Route {
                source,
                destination,
                hop,
            })
    }

    // Test-only per-network-context configuration control.
    // Existing connections own their configuration and are never changed here.
    #[cfg(feature = "packet-test-controls")]
    pub fn packet_test_timestamp_default(&mut self, enabled: bool) {
        self.test_timestamp_default = Some(enabled);
    }

    fn new_connection_timestamps(&self) -> bool {
        #[cfg(feature = "packet-test-controls")]
        if let Some(enabled) = self.test_timestamp_default {
            return enabled;
        }
        self.config.connection.timestamps
    }

    fn timestamp_clock_required(&self) -> bool {
        #[cfg(feature = "packet-test-controls")]
        if self.test_timestamp_default.is_some() {
            // Never weaken ambiguity checks for any previously created connection.
            return true;
        }
        self.config.connection.timestamps
    }

    //= https://www.rfc-editor.org/rfc/rfc6191#section-1
    //= reason=Native transport ticks come from the characterized CLOCK_BOOTTIME provider, which rejects decreasing samples. Endpoint::check_clock refuses earlier input and timestamp half-range jumps, every TSval is the selected tick plus one constant per-connection offset, and TIME-WAIT reuse inherits the old incarnation's offset, so a reincarnation continues its predecessor's timestamp clock. Embedders supplying their own clock own its monotonicity.
    //# For the purpose of PAWS, the timestamps sent on a connection are
    //# required to be monotonically increasing.
    fn check_clock(&self, now: Instant) -> Result<(), EndpointError> {
        // One caller sample can service timers, input and output. Once it
        // equals the endpoint clock, it cannot jump backwards or across the
        // timestamp half-range, so there is no conversion to repeat.
        if now == self.now {
            return Ok(());
        }
        if now < self.now {
            return Err(Error::TimeWentBackwards.into());
        }
        let granularity = self.config.connection.timestamp_granularity;
        let timebase = self.config.connection.timebase;
        // Fewer than 2^31 - 1 periods cannot advance the tick by 2^31.
        let period = timebase.ticks_from_us(granularity.tick_us());
        if now - self.now >= ((1 << 31) - 1u64).saturating_mul(period)
            && self.timestamp_clock_required()
            && granularity.tick_in(now, timebase) - granularity.tick_in(self.now, timebase)
                >= 1 << 31
        {
            return Err(Error::AmbiguousTimeJump.into());
        }
        Ok(())
    }

    fn clock(&mut self, now: Instant) -> Result<(), EndpointError> {
        self.check_clock(now)?;
        self.now = now;
        Ok(())
    }

    /// One clock sample whose advance includes `suspended` ticks that the
    /// clock provider measured as suspended. Such a jump may reach the
    /// timestamp half-range without being ambiguous; only the time left after
    /// the suspend is checked, and no intermediate sample is manufactured.
    /// Every connection stops sampling RTT across the gap. One whose next
    /// TSval would appear older to a peer that may still hold TS.Recent ends
    /// with a timeout error, sending nothing; with output reserved, once the
    /// reservation is settled. Fails without effect when the sample goes back
    /// or `suspended` exceeds its advance.
    pub fn resume(&mut self, now: Instant, suspended: Instant) -> Result<(), EndpointError> {
        let advance = now
            .checked_sub(self.now)
            .ok_or(Error::TimeWentBackwards)?;
        if suspended > advance {
            return Err(Error::InvalidArgument.into());
        }
        self.check_clock(now - suspended)?;
        let mut stale = Vec::new();
        stale
            .try_reserve_exact(self.time_wait.len())
            .map_err(|_| Error::NoMemory)?;
        self.now = now;
        for index in 0..self.slots.len() {
            let reserved = self.is_output_reserved(self.id(index));
            let Some(slot) = self.slots[index].as_mut() else {
                continue;
            };
            if slot.connection.suspended(now)? && !reserved {
                slot.connection.timeout(now)?;
            }
            self.refresh(index);
        }
        // A TIME-WAIT record whose next TSval would look older ends as its
        // connection would, without output.
        stale.extend(self.time_wait.indices().filter(|&index| {
            self.time_wait
                .record(index)
                .timestamp_appears_older(now, &self.config.connection)
        }));
        for index in stale {
            self.remove_time_wait(index);
        }
        Ok(())
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4.1
    //# F() MUST NOT be computable from the outside (MUST-9), or
    //# an attacker could still guess at sequence numbers from the ISN used
    //# for some other connection.

    // HMAC secrecy depends on the embedding supplying an unpredictable secret.
    // A scoped identity appends its complete link identity after the
    // unscoped encoding, so unscoped digests keep their exact bytes and the
    // same link-local pair on two links (or a recycled link) never shares an
    // ISN, timestamp offset or lookup position.
    fn digest(&self, domain: &[u8], scoped: ScopedTuple) -> [u8; 32] {
        let mut mac = self.keyed.clone();
        mac.update(domain);
        encode_tuple(scoped, |bytes| mac.update(bytes));
        mac.finalize().into_bytes().into()
    }
    // The connection-table hash runs for every segment, so it is a keyed
    // SipHash-1-3 of the digest's tuple encoding, not an HMAC. Its key is
    // secret-derived and the hash never leaves the endpoint: hostile tuples
    // cannot be chosen to collide, and the probe budget bounds the rest.
    fn hash(&self, tuple: ScopedTuple) -> usize {
        use core::hash::Hasher;
        let mut hash = siphasher::sip::SipHasher13::new_with_key(&self.lookup_key);
        encode_tuple(tuple, |bytes| hash.write(bytes));
        hash.finish() as usize
    }
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4.1
    //= reason=isn adds the four-microsecond clock to the tuple-and-secret HMAC below.
    //# A TCP implementation MUST use the above type of "clock" for clock-
    //# driven selection of initial sequence numbers (MUST-8), and SHOULD
    //# generate its initial sequence numbers with the expression:

    fn isn(&mut self, tuple: ScopedTuple) -> u32 {
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4.1
        //# SHOULD
        //# generate its initial sequence numbers with the expression:
        //#
        //# ISN = M + F(localip, localport, remoteip, remoteport, secretkey)
        //#
        //# where M is the 4 microsecond timer, and F() is a pseudorandom
        //# function (PRF) of the connection's identifying parameters ("localip,
        //# localport, remoteip, remoteport") and a secret key ("secretkey")
        //# (SHLD-1).

        let tag = self.digest(b"ntcp initial sequence", tuple);
        let ticks = (self.now / self.config.connection.timebase.ticks_from_us(4))
            .saturating_sub(self.last_isn_time / self.config.connection.timebase.ticks_from_us(4))
            .max(1);
        self.isn_clock = self.isn_clock.wrapping_add(ticks as u32);
        self.last_isn_time = self.now;
        u32::from_be_bytes(tag[..4].try_into().unwrap()).wrapping_add(self.isn_clock)
    }
    // A connection's TSval offset: a keyed function of its tuple alone, the
    // ISN's PRF under another domain (RFC 7323 section 5.4), as Linux draws
    // it from the addresses and ports under net_secret
    // (secure_tcp_seq_and_ts_off). Every incarnation of a tuple shares it,
    // so a peer's TIME-WAIT and PAWS see one timestamp clock across them,
    // while an off-path host learns nothing of another tuple's offset.
    fn timestamp_offset(&self, tuple: ScopedTuple) -> u32 {
        let tag = self.digest(b"ntcp timestamp offset", tuple);
        u32::from_be_bytes(tag[..4].try_into().unwrap())
    }
    fn id(&self, slot: usize) -> ConnectionId {
        ConnectionId {
            slot,
            generation: self.generations[slot],
        }
    }
    // Internal output ownership outlives application release, but not generation reuse.
    fn retained_slot(&self, id: ConnectionId) -> Result<&Slot, EndpointError> {
        if self.generations.get(id.slot) != Some(&id.generation) {
            return Err(EndpointError::InvalidHandle);
        }
        self.slots[id.slot]
            .as_ref()
            .ok_or(EndpointError::InvalidHandle)
    }
    fn retained_slot_mut(&mut self, id: ConnectionId) -> Result<&mut Slot, EndpointError> {
        self.retained_slot(id)?;
        Ok(self.slots[id.slot].as_mut().unwrap())
    }
    fn slot(&self, id: ConnectionId) -> Result<&Slot, EndpointError> {
        let slot = self.retained_slot(id)?;
        if slot.released {
            return Err(EndpointError::InvalidHandle);
        }
        Ok(slot)
    }
    fn slot_mut(&mut self, id: ConnectionId) -> Result<&mut Slot, EndpointError> {
        self.slot(id)?;
        let reserved = self.is_output_reserved(id);
        let slot = self.slots[id.slot].as_mut().unwrap();
        if !reserved {
            slot.connection.update_time(self.now)?;
        }
        Ok(slot)
    }
    fn listener(&self, id: ListenerId) -> Result<&Listener, EndpointError> {
        if self.listener_generations.get(id.slot) != Some(&id.generation) {
            return Err(EndpointError::InvalidHandle);
        }
        self.listeners[id.slot]
            .as_ref()
            .filter(|listener| !listener.closing)
            .ok_or(EndpointError::InvalidHandle)
    }

    /// Validate an explicit local receive authority independently of its port.
    /// Selection grants no early-data permission and reserves no pending quota.
    pub fn validate_fast_open_receive_authority(
        &self,
        id: ListenerId,
        local: IpAddr,
    ) -> Result<(), EndpointError> {
        let address = self.listener(id)?.address.ip();
        if address.is_ipv4() != local.is_ipv4() || !address.is_unspecified() && address != local {
            return Err(EndpointError::InvalidAddress);
        }
        Ok(())
    }

    fn crossing_syn_authorization(
        &mut self,
        listener: ListenerId,
        scoped: ScopedTuple,
        syn: &wire::Segment<'_>,
    ) -> CrossingSynAuthorization {
        let tuple = scoped.tuple;
        let mut decision = CrossingSynAuthorization {
            early: false,
            response: None,
        };
        if self
            .validate_fast_open_receive_authority(listener, tuple.local.ip())
            .is_err()
            || self.fast_open.is_none()
        {
            return decision;
        }
        let record = self.listeners[listener.slot].as_mut().unwrap();
        let limit = record.fast_open_limit;
        if limit == 0 {
            return decision;
        }
        let debt = record.reset_debt(self.now);
        let protected =
            record.early_data_policy == crate::FastOpenEarlyDataPolicy::ApplicationProtected;
        let policy = record
            .fast_open_cookie_policy
            .as_ref()
            .unwrap_or(&self.fast_open_cookie_policy);
        let early = |slot: &&Slot| {
            slot.fast_open_owner == Some(listener)
                && !slot.connection.handshake_complete()
                && slot.connection.state() != State::Closed
        };
        let pending = self
            .occupied
            .iter()
            .filter_map(|index| self.slots[index].as_ref())
            .filter(early)
            .count();
        // The full scan `occupied` replaces, for debug builds.
        debug_assert_eq!(pending, self.slots.iter().flatten().filter(early).count());
        let valid = !protected
            && syn.options.fast_open.is_some_and(|cookie| {
                policy.valid_in(
                    &self.fast_open_credentials,
                    self.now,
                    tuple.local.ip(),
                    tuple.remote.ip(),
                    scoped.zone,
                    cookie,
                )
            });
        let application_authorized = protected
            && (syn.options.fast_open.is_some()
                || !syn.payload.is_empty()
                || syn.header.flags & wire::FIN != 0);
        //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2
        //= reason=Pending children plus reset debt constrain both authorization modes before admitting a new early child.
        //# If this variable goes over a preset system limit, the server MUST disable TFO for all new connection requests until PendingFastOpenRequests drops below the system limit.
        let accept_syn_data =
            (valid || application_authorized) && pending.saturating_add(debt) < limit;
        decision.early = accept_syn_data;
        if !protected
            && syn.options.fast_open.is_some()
            && (!valid || policy.policy().refresh_valid_cookie())
        {
            decision.response = policy.issue_in(
                &self.fast_open_credentials,
                self.now,
                tuple.local.ip(),
                tuple.remote.ip(),
                scoped.zone,
            );
        }
        decision
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.1
    //# Every passive OPEN call either creates a new connection record in
    //# LISTEN state, or it returns an error; it MUST NOT affect any
    //# previously created connection record (MUST-41).
    /// `backlog` is Linux's listen() backlog after its somaxconn clamp
    /// (sk_max_ack_backlog), at most `max_connections`. It bounds the
    /// listener's SYN queue, its half-open children, and its accept queue,
    /// its established children not yet accepted, each to `backlog + 1`, as
    /// Linux does: a SYN finding either full is dropped, and so is the last
    /// ACK of a handshake finding the accept queue full, its child left in
    /// SYN-RECEIVED to retransmit the SYN-ACK.
    pub fn listen(
        &mut self,
        address: SocketAddr,
        backlog: usize,
    ) -> Result<ListenerId, EndpointError> {
        self.listen_scoped(address, None, backlog)
    }

    /// `listen` on a link-local address of a managed Endpoint, which names
    /// its link: exactly that address and zone beats the family wildcard,
    /// and identical link-local addresses on different links listen
    /// independently. An unscoped wildcard listener accepts on every link,
    /// each child carrying its arrival link's zone.
    pub fn listen_scoped(
        &mut self,
        address: SocketAddr,
        zone: Option<ntcp_path::LinkId>,
        backlog: usize,
    ) -> Result<ListenerId, EndpointError> {
        // A raw Endpoint's link-local listener stays unscoped; a managed one
        // needs the zone its arrivals carry.
        let scoped = crate::connection::link_local(address.ip())
            && (zone.is_some() || self.managed_context.is_some());
        if !supported_socket(address)
            || scoped != zone.is_some()
            || zone.is_some_and(|zone| Some(zone.context()) != self.managed_context)
        {
            return Err(EndpointError::InvalidAddress);
        }
        if address.port() == 0
            || (!address.ip().is_unspecified() && !valid_address(address.ip()))
            || !(self.address_policy)(AddressValidation::Bind {
                local: address.ip(),
            })
            || backlog > self.config.max_connections
        {
            return Err(Error::InvalidArgument.into());
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.1
        //# A TCP implementation that supports multiple concurrent connections
        //# MUST provide an OPEN call that will functionally allow an application
        //# to LISTEN on a port while a connection block with the same local port
        //# is in SYN-SENT or SYN-RECEIVED state (MUST-42).
        if self
            .listeners
            .iter()
            .flatten()
            .any(|listener| listener.address == address && listener.zone == zone)
        {
            return Err(EndpointError::AddressInUse);
        }
        let slot = self
            .listeners
            .iter()
            .enumerate()
            .position(|(i, l)| l.is_none() && self.listener_generations[i] != u64::MAX)
            .ok_or(EndpointError::LimitReached)?;
        // Both queues full; a child is a connection, so no more than
        // max_connections in all. Only TIME-WAIT reopens, which skip the SYN
        // queue's bound as in Linux, reserve beyond (`reopen_time_wait`).
        let children = reserved_vec((2 * (backlog + 1)).min(self.config.max_connections))?;
        let mut pending = VecDeque::new();
        pending
            .try_reserve_exact(backlog + 1)
            .map_err(|_| Error::NoMemory)?;
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.1
        //# If passive, enter the LISTEN state and return.
        self.listeners[slot] = Some(Listener {
            early_data_policy: crate::FastOpenEarlyDataPolicy::RequireCookie,
            fast_open_limit: 0,
            reset_debt: 0,
            reset_debt_expiry: None,
            fast_open_cookie_policy: None,
            rx_timestamp_capacity: 0,
            buffer_capacities: (
                self.config.connection.send_capacity,
                self.config.connection.receive_capacity,
            ),
            buffer_locks: (false, false),
            application_timeout_us: None,
            handshake_retransmission_limit: None,
            user_mss: self.config.connection.user_mss,
            address,
            zone,
            backlog,
            children,
            pending,
            closing: false,
        });
        Ok(ListenerId {
            slot,
            generation: self.listener_generations[slot],
        })
    }

    pub fn close_listener(&mut self, id: ListenerId) -> Result<(), EndpointError> {
        if self
            .listener(id)?
            .children
            .iter()
            .any(|&child| self.is_output_reserved(child))
        {
            return Err(EndpointError::OutputReserved);
        }
        self.listeners[id.slot].as_mut().unwrap().closing = true;
        self.events.remove(self.config.max_connections + id.slot);
        self.cleanup.push(id.slot);
        Ok(())
    }

    fn cleanup_one(&mut self) {
        let Some(index) = self.cleanup.pop() else {
            return;
        };
        if self.listeners[index]
            .as_ref()
            .unwrap()
            .children
            .last()
            .is_some_and(|&id| self.is_output_reserved(id))
        {
            self.cleanup.push(index);
            return;
        }
        let child = self.listeners[index].as_mut().unwrap().children.pop();
        if let Some(id) = child {
            if self.generations[id.slot] == id.generation && self.slots[id.slot].is_some() {
                // Listener shutdown explicitly abandons unaccepted children.
                self.slots[id.slot].as_mut().unwrap().listener = None;
                self.slots[id.slot].as_mut().unwrap().connection.abort();
                self.slots[id.slot].as_mut().unwrap().released = true;
                self.refresh(id.slot);
            }
            self.cleanup.push(index);
        } else {
            self.listeners[index] = None;
            self.listener_generations[index] = self.listener_generations[index].saturating_add(1);
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.1
    //= reason=Base checks are unconditional; directed broadcasts and local ownership use the required policy bound to one ingress network context.
    //# A TCP implementation MUST reject as an error a local OPEN call for an
    //# invalid remote IP address (e.g., a broadcast or multicast address)
    //# (MUST-46).

    // Scoped to the embedding policy's bound network; base invalid addresses cannot be allowed.
    fn admission(&self, tuple: ScopedTuple) -> Result<(), EndpointError> {
        self.admission_with_buffers(
            tuple,
            (
                self.config.connection.send_capacity,
                self.config.connection.receive_capacity,
            ),
        )
    }

    fn admission_with_buffers(
        &self,
        scoped: ScopedTuple,
        capacities: (usize, usize),
    ) -> Result<(), EndpointError> {
        let tuple = scoped.tuple;
        if !self.admits_zone(scoped)
            || !supported_socket(tuple.local)
            || !supported_socket(tuple.remote)
            || tuple.local.port() == 0
            || tuple.remote.port() == 0
            || !valid_address(tuple.local.ip())
            || !valid_address(tuple.remote.ip())
            || tuple.local.is_ipv4() != tuple.remote.is_ipv4()
            || !(self.address_policy)(AddressValidation::Open {
                local: tuple.local.ip(),
                remote: tuple.remote.ip(),
            })
        {
            return Err(EndpointError::InvalidAddress);
        }
        self.resource_admission(scoped, capacities)
    }

    // A zone is authority of this Endpoint's managed network context; a raw
    // Endpoint has none, so its tuples are unscoped.
    fn admits_zone(&self, scoped: ScopedTuple) -> bool {
        scoped
            .zone
            .is_none_or(|zone| Some(zone.context()) == self.managed_context)
    }

    // A tuple's identity in the current operation: the zone of the managed
    // factory transaction constructing it. Raw tuples carry no link
    // authority and are unscoped.
    fn scoped(&self, tuple: Tuple) -> ScopedTuple {
        match self.factory_transaction {
            Some(transaction) if transaction.request.tuple == tuple => ScopedTuple {
                tuple,
                zone: transaction.request.zone,
            },
            _ => ScopedTuple::unscoped(tuple),
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.1
    //= reason=Duplicate tuple admission fails without replacing the existing record; independent listener remains legal.
    //# Return "error: connection already exists".
    fn resource_admission(
        &self,
        tuple: ScopedTuple,
        capacities: (usize, usize),
    ) -> Result<(), EndpointError> {
        if tuple.tuple.local.port() == 0 || tuple.tuple.remote.port() == 0 {
            return Err(EndpointError::InvalidAddress);
        }
        if self.lookup(tuple).is_some() {
            return Err(EndpointError::AddressInUse);
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.1
        //# If there is
        //# no room to create a new connection, return "error: insufficient
        //# resources".
        self.room_for(capacities.1)
    }

    // Room for a connection with a `receive`-byte ring: a slot
    // (LimitReached) and its charge at open within the budget (NoMemory).
    fn room_for(&self, receive: usize) -> Result<(), EndpointError> {
        if self.free.is_empty() {
            return Err(EndpointError::LimitReached);
        }
        let (_, credit) = self.pooled_receive_credit(receive);
        if Connection::open_bytes(receive, usize::from(self.config.connection.mss))
            .is_none_or(|charge| charge > self.buffer_room().saturating_add(credit))
        {
            return Err(Error::NoMemory.into());
        }
        Ok(())
    }

    // Remaining endpoint buffer budget, before any caller-specific credit:
    // its own, or its group's as it sees it.
    fn buffer_room(&self) -> usize {
        self.budget
            .high(self.config.max_buffer_bytes)
            .saturating_sub(self.budget.allocated())
    }

    // The thresholds in force: the group's for a member of shared buffer
    // memory (`share_buffer_memory`), else the configuration's.
    fn memory(&self) -> crate::BufferMemory {
        self.budget.memory(self.config.buffer_memory())
    }

    // Charge `bytes` to the budget.
    fn charge(&mut self, bytes: usize) {
        let memory = self.memory();
        self.budget.raise(bytes, self.now, memory);
    }

    // Return `bytes` to the budget. Every return wakes the writers waiting
    // for memory that it can feed (`wake_memory_waiters`), as Linux's
    // sk_stream_write_space follows a release: a connection's storage
    // released, reclaimed or shrunk, and the end of pressure, which lets
    // the writers pressure held back grow again. A wake visits only the
    // waiters it wakes and one more, so a return with none waiting costs
    // one check.
    fn uncharge(&mut self, bytes: usize) {
        let memory = self.memory();
        self.budget.reduce(bytes, self.now, memory);
        self.wake_memory_waiters();
    }

    // Storage charged `old` bytes now holds `new`.
    fn recharge(&mut self, old: usize, new: usize) {
        if new > old {
            self.charge(new - old);
        } else if new < old {
            self.uncharge(old - new);
        }
    }

    // Pooled receive storage a new connection would reuse, and the charge it
    // returns to the budget: pooled storage is already in buffer_bytes.
    fn pooled_receive_credit(&self, receive_capacity: usize) -> (Option<usize>, usize) {
        match self
            .receive_pool
            .iter()
            .position(|r| r.capacity() == receive_capacity)
        {
            Some(index) => (Some(index), self.per_connection_bytes),
            None => (None, 0),
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc7323#section-7.1
    //= reason=Endpoint derives offset using HMAC-SHA256 of the secret and the tuple alone in the separate ntcp timestamp offset domain before first output, the ISN's PRF under another domain (section 5.4) with Linux's inputs (secure_tcp_seq_and_ts_off: addresses and ports). Every incarnation of a tuple shares it, so peer PAWS and TIME-WAIT see no random jump; other tuples' offsets stay unpredictable. Modular addition/subtraction covers wire TS and ordinary/RACK RTT validation. TIME-WAIT reuse inherits the old local offset; failed output/candidate rollback retain the old clock. Unrelated tuple/secret, reincarnation, echo/RTT/wrap and reuse rollback tests cover the policy.
    //# It is therefore RECOMMENDED to generate a random, per-
    //# connection offset to be used with the clock source when generating
    //# the Timestamps option value (see Section 5.4).
    //= https://www.rfc-editor.org/rfc/rfc7323#section-7
    //= reason=Endpoint derives offset using HMAC-SHA256 of the secret and the tuple alone in the separate ntcp timestamp offset domain before first output, the ISN's PRF under another domain (section 5.4) with Linux's inputs (secure_tcp_seq_and_ts_off: addresses and ports). Every incarnation of a tuple shares it, so peer PAWS and TIME-WAIT see no random jump; other tuples' offsets stay unpredictable. Modular addition/subtraction covers wire TS and ordinary/RACK RTT validation. TIME-WAIT reuse inherits the old local offset; failed output/candidate rollback retain the old clock. Unrelated tuple/secret, reincarnation, echo/RTT/wrap and reuse rollback tests cover the policy.
    //# It is therefore
    //# RECOMMENDED to generate a random, per-connection offset to be used
    //# with the clock source when generating the Timestamps option value
    //# (see Section 5.4).
    //= https://www.rfc-editor.org/rfc/rfc6928#section-12
    //= reason=Bounded local/remote-IP FIFO records transport-inferred initial/restart burst loss only, not setup success or unmeasured telemetry. Later connections select RFC3390/Rfc5681; cache capacity/eviction/no-loss behavior are tested. Retention is deliberately conservative until FIFO eviction; no deployment monitoring claim.
    //# The sender SHOULD cache such information about connection setups using an initial window larger than allowed by RFC 3390, and new connections SHOULD fall back to the initial window allowed by RFC 3390 if there is evidence of performance issues.
    fn new_connection(
        &mut self,
        tuple: Tuple,
        iss: u32,
        syn: Option<&wire::Segment<'_>>,
    ) -> Result<Box<Connection>, Error> {
        self.new_connection_with_buffers(
            tuple,
            iss,
            syn,
            (
                self.config.connection.send_capacity,
                self.config.connection.receive_capacity,
            ),
            (false, false),
            0,
            RxPacketTimestamps::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_connection_with_buffers(
        &mut self,
        tuple: Tuple,
        iss: u32,
        syn: Option<&wire::Segment<'_>>,
        capacities: (usize, usize),
        locks: (bool, bool),
        rx_ranges: usize,
        timestamps: RxPacketTimestamps,
    ) -> Result<Box<Connection>, Error> {
        self.new_connection_with_options(
            tuple,
            iss,
            syn,
            ActiveOpenOptions {
                send_capacity: capacities.0,
                receive_capacity: capacities.1,
                ..ActiveOpenOptions::from(&self.config.connection)
            },
            locks,
            rx_ranges,
            timestamps,
            None,
        )
    }

    //= https://www.rfc-editor.org/rfc/rfc7413#section-3
    //# 2. The server generates a cookie and sends it through the Fast Open option of a SYN-ACK packet.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-3
    //# 2. The server validates the cookie: a. If the cookie is valid, the server sends a SYN-ACK
    //# acknowledging both the SYN and the data. The server then delivers the data to the application. b.
    //# Otherwise, the server drops the data and sends a SYN-ACK acknowledging only the SYN sequence number.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.1
    //# The Fast Open option is used to request or to send a Fast Open Cookie. When a cookie is not present
    //# or is empty, the option is used by the client to request a cookie from the server. When the cookie
    //# is present, the option is used to pass the cookie from the server to the client or from the client
    //# back to the server (to perform a Fast Open).
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2
    //# PendingFastOpenRequests: tracks the number of TFO connections in SYN-RCVD state.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.1
    //# This SYN-ACK may contain a Fast Open option if the server currently supports TFO for this listener
    //# port.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
    //# 1. Initialize and reset a local FastOpened flag. If FastOpenEnabled is false, go to step 5.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
    //# 2. If PendingFastOpenRequests is over the system limit, go to step 5.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
    //# 3. If IsCookieValid() (in Section 4.1.2) returns false, go to step 5.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
    //# 4. Buffer the data and notify the application. Set the FastOpened flag and increment
    //# PendingFastOpenRequests.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
    //# 5. Send the SYN-ACK packet. The packet MAY include a Fast Open option. If the FastOpened flag is
    //# set, the packet acknowledges the SYN and data sequence. Otherwise, it acknowledges only the SYN
    //# sequence.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-5.1
    //# To protect the server, it is important to limit the maximum number of total pending TFO connection
    //# requests, i.e., PendingFastOpenRequests (Section 4.2). When the limit is exceeded, the server
    //# temporarily disables TFO entirely as described in "Server Cookie Handling" (Section 4.1.2). Then,
    //# subsequent TFO requests will be downgraded to regular connection requests, i.e., with the data
    //# dropped and only SYNs acknowledged.
    fn construct_connection(
        &mut self,
        tuple: Tuple,
        iss: u32,
        syn: Option<&wire::Segment<'_>>,
        options: ActiveOpenOptions,
        locks: (bool, bool),
        rx_ranges: usize,
        timestamps: RxPacketTimestamps,
        receive_authority: Option<ListenerId>,
    ) -> Result<Box<Connection>, Error> {
        options.validate()?;
        // Managed mode requires a live provisional path before allocation,
        // TFO authorization or controller/initial PMTU construction.
        let (managed_path, receive_capability) = match self.managed_context {
            Some(context) => {
                let transaction = self.factory_transaction.ok_or(Error::InvalidState)?;
                if transaction.request.tuple != tuple
                    || transaction.inserted.is_some()
                    || !crate::managed_path::valid_prepared(context, transaction.request, transaction.prepared)
                    || !crate::managed_path::valid_receive(context, transaction.request, transaction.receive)
                {
                    return Err(Error::InvalidState);
                }
                (Some(transaction.prepared), Some(transaction.receive))
            }
            None => (None, None),
        };
        let initial_ip_header_len = if let Some(transaction) = self.factory_transaction {
            if let (IpAddr::V4(source), IpAddr::V4(destination)) = (tuple.local.ip(), tuple.remote.ip()) {
                Some(20 + transaction.request.ipv4_options.encode(source, destination, 0, &mut [0; 40])
                    .map_err(|_| Error::InvalidArgument)?.1 as u16)
            } else { Some(transaction.prepared.snapshot.ip_header_len() as u16) }
        } else { None };
        let capacities = (options.send_capacity, options.receive_capacity);
        let charge = Connection::open_bytes(capacities.1, usize::from(self.config.connection.mss))
            .ok_or(Error::NoMemory)?;
        let (pool_index, credit) = self.pooled_receive_credit(capacities.1);
        let available = self.buffer_room().saturating_add(credit);
        if charge
            .checked_add(RxTimestamps::allocation_bytes(rx_ranges).ok_or(Error::NoMemory)?)
            .is_none_or(|total| total > available)
        {
            return Err(Error::NoMemory);
        }
        // Stage metadata before touching the receive pool; constructor failures
        // drop it while returning pooled storage through the existing path.
        let mut rx_timestamps = RxTimestamps::default();
        rx_timestamps.resize(rx_ranges, available - charge)?;
        let scoped = self.scoped(tuple);
        let mut connection_config = self.config.connection.clone();
        connection_config.timestamps = self.new_connection_timestamps();
        // A size its listener locked, or one given for this open, is locked,
        // as a size set with SO_SNDBUF or SO_RCVBUF before connect() or
        // listen() is (SOCK_SNDBUF_LOCK, SOCK_RCVBUF_LOCK, which a child
        // inherits): neither autotuning nor pressure changes it, and a
        // locked receive size sets the window scale. A max at the initial
        // size leaves a direction untuned.
        if locks.0 || capacities.0 != connection_config.send_capacity {
            connection_config.send_capacity_max = capacities.0;
        }
        if locks.1 || capacities.1 != connection_config.receive_capacity {
            connection_config.receive_capacity_max = capacities.1;
        }
        connection_config.send_capacity = capacities.0;
        connection_config.receive_capacity = capacities.1;
        connection_config.user_mss = options.user_mss;
        if syn.is_some()
            && let Some(listener) = self.match_listener(tuple.local, scoped.zone)
        {
            connection_config.user_mss = self
                .listener(listener)
                .map_err(|_| Error::InvalidArgument)?
                .user_mss;
        }
        if connection_config.initial_window == crate::InitialWindow::Iw10
            && self
                .setup_loss_cache
                .contains(&(tuple.local.ip(), tuple.remote.ip(), scoped.zone))
        {
            connection_config.initial_window = crate::InitialWindow::Rfc5681;
        }
        if receive_authority.is_some() {
            connection_config.initial_window = crate::InitialWindow::Rfc5681;
        }
        if let Some(route) = self.destination_route(tuple.remote.ip()) {
            route.apply(&mut connection_config)?;
        }
        if let Some(path) = managed_path
            && let Some(pmtud) = &mut connection_config.pmtud
        {
            pmtud.first_hop_mtu = path.snapshot.first_hop_mtu().min(if tuple.local.is_ipv4() { 65535 } else { 65575 });
        }
        let mut receive = pool_index.map(|index| self.receive_pool.swap_remove(index));
        // Apply the same policy to ordinary passive opens and TIME-WAIT reuse.
        let mut fast_open_response = None;
        let mut early = false;
        // RFC 7413 §4.2.2 step 5: recognized TFO needs receive authorization,
        // even when the listener or endpoint service is disabled.
        let mut accept_syn_data = syn.is_none_or(|syn| syn.options.fast_open.is_none());
        let mut filtered_syn = None;
        if let Some(syn) = syn
            && let Some(listener) = self.match_listener(tuple.local, scoped.zone)
        {
            let decision = self.crossing_syn_authorization(listener, scoped, syn);
            early = decision.early;
            if self.fast_open.is_some()
                && self.listeners[listener.slot]
                    .as_ref()
                    .unwrap()
                    .fast_open_limit
                    != 0
            {
                accept_syn_data = early;
            }
            fast_open_response = decision.response;
        }
        if let Some(syn) = syn
            && !accept_syn_data
        {
            let mut header = syn.header;
            header.flags &= !(wire::FIN | wire::PSH | wire::URG);
            header.urgent_pointer = 0;
            filtered_syn = Some(wire::Segment {
                header,
                options: syn.options,
                raw_options: syn.raw_options,
                payload: &[],
            });
        }
        let syn = filtered_syn.as_ref().or(syn);
        let mut result = match syn {
            Some(syn) => Connection::passive_with_receive_path(
                tuple,
                connection_config,
                iss,
                self.now,
                syn,
                early,
                &mut receive,
                rx_timestamps,
                timestamps,
                managed_path,
                receive_capability,
                initial_ip_header_len,
            ),
            None => Connection::active_with_receive_path(
                tuple,
                connection_config,
                iss,
                self.now,
                &mut receive,
                managed_path,
                receive_capability,
                initial_ip_header_len,
            ),
        };
        if result.as_ref().is_ok_and(|connection| {
            connection.buffer_charge() > self.buffer_room().saturating_add(credit)
        }) {
            let connection = result.unwrap();
            if credit != 0 {
                let mut storage = connection.into_receive();
                storage.clear();
                self.receive_pool.push(storage);
            }
            return Err(Error::NoMemory);
        }
        if let Ok(connection) = &mut result {
            connection.set_zone(scoped.zone);
            connection.passive_fast_open(fast_open_response, early);
            connection.set_timestamp_offset(self.timestamp_offset(scoped));
        }
        if let Some(receive) = receive {
            self.receive_pool.push(receive);
        }
        if let Ok(connection) = &result {
            let charge = connection.buffer_charge();
            self.recharge(credit, charge);
        }
        result
    }

    // A connection the cap or the allocator refused storage for counts in
    // `memory_refused_opens`.
    #[allow(clippy::too_many_arguments)]
    fn new_connection_with_options(
        &mut self,
        tuple: Tuple,
        iss: u32,
        syn: Option<&wire::Segment<'_>>,
        options: ActiveOpenOptions,
        locks: (bool, bool),
        rx_ranges: usize,
        timestamps: RxPacketTimestamps,
        receive_authority: Option<ListenerId>,
    ) -> Result<Box<Connection>, Error> {
        let result = self.construct_connection(
            tuple,
            iss,
            syn,
            options,
            locks,
            rx_ranges,
            timestamps,
            receive_authority,
        );
        self.memory_refused_opens += u64::from(result.as_ref().err() == Some(&Error::NoMemory));
        result
    }

    // An active open's admission, a refusal for memory counted in
    // `memory_refused_opens`.
    pub(crate) fn admit_open(
        &mut self,
        admission: Result<(), EndpointError>,
    ) -> Result<(), EndpointError> {
        self.memory_refused_opens += u64::from(admission == Err(Error::NoMemory.into()));
        admission
    }

    fn recycle_connection(&mut self, connection: Box<Connection>) {
        let charge = connection.buffer_charge();
        // A ring the pool keeps stays charged its open charge.
        if self.receive_pool.len() < self.config.preallocate_connections
            && connection.receive_allocation_capacity() == self.config.connection.receive_capacity
            && self.per_connection_bytes <= self.buffer_room().saturating_add(charge)
        {
            let mut receive = connection.into_receive();
            receive.clear();
            self.receive_pool.push(receive);
            self.recharge(charge, self.per_connection_bytes);
        } else {
            self.uncharge(charge);
        }
    }

    // `replaces` names the TIME-WAIT incarnation, a connection the
    // application still holds or a record, whose tuple a reopening SYN gives
    // to `connection`. Its TIME-WAIT ends at once, as Linux deletes the
    // timewait socket before its listener takes the SYN (tcp_v4_rcv,
    // TCP_TW_SYN).
    fn insert(
        &mut self,
        connection: Box<Connection>,
        listener: Option<ListenerId>,
        replaces: Option<Target>,
    ) -> Result<ConnectionId, EndpointError> {
        let tuple = connection.scoped_tuple();
        let admission = (|| {
            let index = *self.free.last().ok_or(EndpointError::LimitReached)?;
            if self.lookup(tuple) != replaces {
                return Err(EndpointError::AddressInUse);
            }
            match replaces {
                Some(Target::Connection(old)) => {
                    if !self.slots[old]
                        .as_ref()
                        .is_some_and(|slot| slot.connection.time_wait_valid(self.now))
                        || !self.tuples.replace(self.hash(tuple), tuple, old, index)
                    {
                        return Err(EndpointError::AddressInUse);
                    }
                }
                Some(Target::TimeWait(old)) => {
                    if !self.time_wait.record(old).valid(self.now) {
                        return Err(EndpointError::AddressInUse);
                    }
                    self.tuples.insert(self.hash(tuple), tuple, index)?;
                }
                None => self.tuples.insert(self.hash(tuple), tuple, index)?,
            }
            Ok(index)
        })();
        let index = match admission {
            Ok(index) => index,
            Err(error) => {
                self.recycle_connection(connection);
                return Err(error);
            }
        };
        match replaces {
            Some(Target::Connection(old)) => {
                // The application sees it CLOSED, as a Linux socket is once
                // tcp_time_wait has handed its TIME-WAIT on.
                let slot = self.slots[old].as_mut().unwrap();
                slot.mapped = false;
                slot.connection.end_time_wait();
                self.output.remove(old);
            }
            Some(Target::TimeWait(old)) => self.remove_time_wait(old),
            None => {}
        }
        self.free.pop();
        self.occupied.push(index);
        self.budget.open_socket();
        let fast_open_owner = if connection.fast_open_early {
            listener
        } else {
            None
        };
        self.slots[index] = Some(Slot {
            fast_open_owner,
            receive_authority: None,
            connection,
            listener,
            accepted_ready: false,
            released: false,
            closed_output_drained: false,
            mapped: true,
            memory_retry: None,
            time_wait: false,
            hop_limit: self.config.hop_limit,
            dscp: self.config.dscp,
            mark: 0,
            reuse_address: false,
            received_dscp: None,
            ipv4_options: OutgoingIpv4Options::default(),
            explicit_route: false,
            received_ipv4_options: None,
        });
        let id = self.id(index);
        if let Some(transaction) = &mut self.factory_transaction {
            debug_assert!(transaction.inserted.is_none());
            transaction.inserted = Some(id);
            let slot = self.slots[index].as_mut().unwrap();
            slot.dscp = transaction.request.dscp.value();
            slot.ipv4_options = transaction.request.ipv4_options;
            // Passive factories carry learned peer return routes. Only an
            // active application's selection (including empty/direct) wins
            // over later validated received route definitions; a planned
            // open's whole option area stays fixed for the connection.
            slot.explicit_route = transaction.request.role == crate::FactoryRole::Active
                && (slot.ipv4_options.source_route.is_some()
                    || transaction.request.registration.is_some());
            Self::sync_ip_header_len(slot);
        }
        if let Some(parent) = listener {
            let children = &mut self.listeners[parent.slot].as_mut().unwrap().children;
            debug_assert!(children.len() < children.capacity());
            children.push(id);
        }
        self.refresh(index);
        if let Some(Target::Connection(old)) = replaces {
            self.refresh(old);
        }
        Ok(id)
    }

    //= https://www.rfc-editor.org/rfc/rfc7413#section-2
    //= reason=Default per-listener RequireCookie and independent disabled service/listener state are exercised; choosing protected policy never enables TFO.
    //# TCP implementations MUST NOT use TFO by default, but only use TFO if requested explicitly by the application on a per-service-port basis.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2
    //= reason=Service and listener enablement remain independent of early-data authorization; disabled listeners keep ordinary handshake and no cookie response.
    //# FastOpenEnabled: default is off. It MUST be turned on explicitly by the application. When this flag is off, the server does not perform any TFO-related operations and MUST ignore all cookie options.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-7.3
    //= reason=ApplicationProtected is an explicit host assertion of independent application defenses, not a proof of application security; tests show authorization replaces MAC checks only for this opt-in. Omitted-option wire behavior is a Linux-compatible choice.
    //# cookies are not necessary if the server has application-level protection or is immune to these attacks.
    /// Set one listener's authorization for future SYNs. This does not enable
    /// endpoint/listener TFO, alter existing children, or change pending/reset
    /// quotas. ApplicationProtected requires independent application protection
    /// and replay tolerance; it bypasses cookie validation and cookie generation.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-7.3
    //# If the server believes it's under a DoS attack through other defense mechanisms, it can switch to regular Fast Open for listener sockets.
    pub fn set_listener_fast_open_early_data_policy(
        &mut self,
        id: ListenerId,
        policy: crate::FastOpenEarlyDataPolicy,
    ) -> Result<(), EndpointError> {
        self.listener(id)?;
        self.listeners[id.slot].as_mut().unwrap().early_data_policy = policy;
        Ok(())
    }

    /// Replace the default server cookie policy for future passive opens.
    /// Does not enable TFO, change quotas/cache/ISN secrets, or alter existing children.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1
    //# The server can expire the cookie at any time to enhance security.
    pub fn set_fast_open_cookie_policy(&mut self, policy: FastOpenCookiePolicy) {
        if let Err(EndpointError::Connection(error)) = self.try_set_fast_open_cookie_policy(policy)
        {
            self.fast_open_cookie_policy.error = Some(error);
        }
    }

    /// Atomic policy selection. Known material retains its original timing,
    /// including an expired lease (selection succeeds but remains inactive).
    /// New identities require memory within max_buffer_bytes; none are evicted.
    pub fn try_set_fast_open_cookie_policy(
        &mut self,
        policy: FastOpenCookiePolicy,
    ) -> Result<(), EndpointError> {
        let key = self.fast_open_server_key(policy);
        let id = self.register_fast_open_credential(
            &key,
            self.fast_open_cookie_policy.lifetime,
            self.now,
            None,
        )?;
        self.fast_open_cookie_policy.replace(key, id);
        Ok(())
    }

    /// Inspect a legacy default selection failure. A blocked selection issues
    /// and accepts no cookies; ordinary TCP remains available.
    pub fn fast_open_cookie_error(&self) -> Option<Error> {
        self.fast_open_cookie_policy.error
    }

    /// Last legacy HMAC registration failure, including a key staged while a
    /// different codec is selected. Contains no key material.
    pub fn fast_open_hmac_key_error(&self) -> Option<Error> {
        self.fast_open_hmac_error
    }

    pub fn listener_fast_open_cookie_error(
        &self,
        id: ListenerId,
    ) -> Result<Option<Error>, EndpointError> {
        let listener = self.listener(id)?;
        Ok(listener
            .fast_open_cookie_policy
            .as_ref()
            .unwrap_or(&self.fast_open_cookie_policy)
            .error)
    }

    /// Permanent identity count and actual dynamic registry allocation charge.
    /// The constructor identity uses inline storage and requires no allocation.
    pub fn fast_open_key_registry_usage(&self) -> (usize, usize) {
        (
            self.fast_open_credentials.len(),
            self.fast_open_credentials.allocation_bytes(),
        )
    }

    fn register_fast_open_credential(
        &mut self,
        key: &crate::FastOpenServerKey,
        lifetime: crate::FastOpenCookieLifetime,
        now: Instant,
        lease: Option<crate::FastOpenKeyLease>,
    ) -> Result<usize, EndpointError> {
        let before = self.fast_open_credentials.allocation_bytes();
        let room = self.buffer_room();
        let id = self.fast_open_credentials.register(
            key,
            lifetime,
            now,
            self.config.connection.timebase,
            lease,
            room,
        )?;
        self.charge(self.fast_open_credentials.allocation_bytes() - before);
        Ok(id)
    }

    /// Register staged administrative material without selecting it. Socket
    /// adapters use this before listen so staging cannot renew an old identity.
    /// Failure changes neither canonical bounds nor the endpoint clock.
    pub fn register_fast_open_key(
        &mut self,
        now: Instant,
        key: crate::FastOpenServerKey,
        lease: crate::FastOpenKeyLease,
    ) -> Result<(), EndpointError> {
        self.check_clock(now)?;
        self.register_fast_open_credential(
            &key,
            self.fast_open_cookie_policy.lifetime,
            now,
            Some(lease),
        )?;
        self.clock(now)
    }

    /// Replace the endpoint-wide HMAC cookie key for future passive opens,
    /// including explicit HMAC listener policies. A changed key immediately
    /// revokes current and previous epoch credentials; the same key is idempotent.
    /// Supply a confidential, unpredictable 32-byte key from an initialized
    /// CSPRNG. Replacing the key leaves TCP identity secrets, live children,
    /// held responses, client caches and quotas unchanged.
    /// This does not select a policy or enable the endpoint or its listeners.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1
    //# The server can expire the cookie at any time to enhance security.
    pub fn set_fast_open_hmac_key(&mut self, key: [u8; 32]) {
        if let Err(EndpointError::Connection(error)) = self.try_set_fast_open_hmac_key(key) {
            // Preserve revocation intent even though the void API cannot return
            // failure. Explicit listeners stay explicit, including blocked ones.
            self.fast_open_hmac_key = key;
            self.fast_open_hmac_error = Some(error);
            self.fast_open_cookie_policy.block_hmac(key, error);
            for listener in self.listeners.iter_mut().flatten() {
                if let Some(context) = &mut listener.fast_open_cookie_policy {
                    context.block_hmac(key, error);
                }
            }
        }
    }

    /// Fallible endpoint-wide HMAC replacement; failure is atomic for all users.
    pub fn try_set_fast_open_hmac_key(&mut self, key: [u8; 32]) -> Result<(), EndpointError> {
        let id = self.register_fast_open_credential(
            &crate::FastOpenServerKey::HmacSha256(key),
            self.fast_open_cookie_policy.lifetime,
            self.now,
            None,
        )?;
        self.fast_open_hmac_key = key;
        self.fast_open_hmac_error = None;
        self.fast_open_cookie_policy.replace_hmac(key, id);
        for listener in self.listeners.iter_mut().flatten() {
            if let Some(context) = &mut listener.fast_open_cookie_policy {
                context.replace_hmac(key, id);
            }
        }
        Ok(())
    }

    /// Override one live listener's policy; `None` inherits the endpoint policy.
    /// Does not enable TFO or alter already-created children or held output.
    pub fn set_listener_fast_open_cookie_policy(
        &mut self,
        id: ListenerId,
        policy: Option<FastOpenCookiePolicy>,
    ) -> Result<(), EndpointError> {
        self.listener(id)?;
        let context = if let Some(policy) = policy {
            let key = self.fast_open_server_key(policy);
            let mut context = self.listeners[id.slot]
                .as_ref()
                .unwrap()
                .fast_open_cookie_policy
                .clone()
                .unwrap_or_else(|| self.fast_open_cookie_policy.clone());
            let credential =
                self.register_fast_open_credential(&key, context.lifetime, self.now, None)?;
            context.replace(key, credential);
            Some(context)
        } else {
            None
        };
        self.listeners[id.slot]
            .as_mut()
            .unwrap()
            .fast_open_cookie_policy = context;
        Ok(())
    }

    fn fast_open_server_key(&self, policy: FastOpenCookiePolicy) -> crate::FastOpenServerKey {
        match policy {
            FastOpenCookiePolicy::HmacSha256 => {
                crate::FastOpenServerKey::HmacSha256(self.fast_open_hmac_key)
            }
            #[cfg(feature = "tfo-linux-cookie")]
            FastOpenCookiePolicy::LinuxSipHash24(key) => {
                crate::FastOpenServerKey::LinuxSipHash24(key)
            }
        }
    }

    /// Configure the duration for future key installations. Existing credentials
    /// keep their epoch and lease deadlines; this cannot renew or revive them.
    /// Client cache aging and negative-cache policy remain independent.
    pub fn set_fast_open_cookie_lifetime(&mut self, lifetime: crate::FastOpenCookieLifetime) {
        self.fast_open_cookie_policy.lifetime = lifetime;
    }

    /// Configure one listener's future key installations. An inherited listener
    /// snapshots the default key context, including its original deadlines.
    pub fn set_listener_fast_open_cookie_lifetime(
        &mut self,
        id: ListenerId,
        lifetime: crate::FastOpenCookieLifetime,
    ) -> Result<(), EndpointError> {
        self.listener(id)?;
        let context = self.listeners[id.slot]
            .as_mut()
            .unwrap()
            .fast_open_cookie_policy
            .get_or_insert_with(|| self.fast_open_cookie_policy.clone());
        context.lifetime = lifetime;
        Ok(())
    }

    /// Install actual key material with absolute deadlines in the endpoint's
    /// timebase. `rotate` retains at most one prior accepting key through its
    /// original deadline; false immediately revokes it. Same-key installs never
    /// extend deadlines, including after expiry. Reuse of a retiring key fails.
    /// Across restart the embedding must preserve trusted lease deadlines or
    /// install fresh keys; this endpoint does not provide persistent time trust.
    /// Does not select protected mode, enable TFO, or mutate children/output.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-3
    //= reason=Actual IPv4/IPv6 endpoints repeatedly reuse credentials before expiry, reject expired SYN data at admission and complete ordinary TCP byte delivery with fresh-cookie learning or no-cookie fallback. HMAC keeps current/previous epochs; LinuxSipHash24 keeps raw bytes under finite key leases. Raw epoch-independent codec vectors are not server acceptance evidence. External raw keys are accepted only with their original lease in CLOCK_BOOTTIME microseconds of the boot socket.fast_open_key_boot_id names: another boot's lease, an expired lease or an external key without one is refused at configuration, a restarted process reinstalling the same key keeps the original deadlines, and setsockopt(TCP_FASTOPEN_KEY) selects only a configured key under its lease. HMAC keys are per-process secrets whose epochs derive from transport time.
    //# 5. The rest of the connection proceeds like a normal TCP connection. The client can repeat many Fast Open operations once it acquires a cookie (until the cookie is expired by the server).
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
    //= reason=Server-selected HMAC/SipHash authenticate addresses; admission now enforces finite HMAC epochs and LinuxSipHash24 key leases, and protected services independently bypass cookies. Raw Linux epoch-independent validation preserves bytes and is not server admission. The full imported property set remains TODO: T6 now supplies release actual-path measurements with source/executable provenance, scoped admission/issuance counts, raw rounds and observer controls in integration/rfc_host/check_mac_cost.py; HMAC overlap remains substantial and the complete relative-cost assessment awaits independent review/T23 disposition. External raw keys keep their original boot-named leases across restarts; only that assessment remains.
    //# The server is in charge of cookie generation and authentication. The cookie SHOULD be a MAC tag with the following properties. We use "SHOULD" because, in some cases, the cookie may be trivially generated as discussed in Section 7.3.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
    //= reason=Passive admission authenticates both address families using current/retiring bounded key contexts consulting one endpoint-owned identity/deadline registry, finite HMAC epochs and LinuxSipHash24 leases. Traffic tests reject expired and invalid credentials exactly at deadlines and complete fallback; raw Linux epoch-independent codec validation alone is not server acceptance. External raw keys are accepted only with their original lease in CLOCK_BOOTTIME microseconds of the boot socket.fast_open_key_boot_id names: another boot's lease, an expired lease or an external key without one is refused at configuration, a restarted process reinstalling the same key keeps the original deadlines, and setsockopt(TCP_FASTOPEN_KEY) selects only a configured key under its lease. HMAC keys are per-process secrets whose epochs derive from transport time.
    //# - IsCookieValid(IP_Address, Cookie): checks if the cookie is valid, i.e., it has not expired and the cookie authenticates the client IP address.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.1
    //= reason=Real request/SYN-ACK exchanges issue usable cookies only within issuance deadlines; finite HMAC epochs and LinuxSipHash24 leases govern admission independently of raw epoch-independent encoding. T6 now measures actual release SYN/SYN-ACK admission/issuance and remaining processing in integration/rfc_host/check_mac_cost.py, retaining raw rounds, multiplicities, source/executable provenance and observer controls; HMAC overlap remains substantial and full relative-cost assessment awaits independent review/T23 disposition. External raw keys keep their original boot-named leases across restarts; the whole clause remains TODO only for that assessment.
    //# 2. The server responds with a SYN-ACK based on the procedures in the "Server Cookie Handling" section (Section 4.1.2).
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
    //= reason=Repeated Fast Open, manual key revocation, finite HMAC epochs and LinuxSipHash24 key leases are exercised through actual endpoints in both IP families. Admission checks issue/accept deadlines without timer service; expired and invalid credentials complete ordinary TCP, fresh keys teach usable replacements, and same-key reinstalls cannot renew expired leases in the endpoint authority across arbitrary key cycles, policy clearing, listener generations, cross-listener reuse and native pre-listen staging. Raw Linux epoch-independent codec tests are not server acceptance. External raw keys are accepted only with their original lease in CLOCK_BOOTTIME microseconds of the boot socket.fast_open_key_boot_id names: another boot's lease, an expired lease or an external key without one is refused at configuration, a restarted process reinstalling the same key keeps the original deadlines, and setsockopt(TCP_FASTOPEN_KEY) selects only a configured key under its lease. HMAC keys are per-process secrets whose epochs derive from transport time.
    //# Once the client obtains the cookie from the target server, it can perform subsequent TFO connections until the cookie is expired by the server.
    pub fn install_fast_open_key(
        &mut self,
        now: Instant,
        key: crate::FastOpenServerKey,
        lease: crate::FastOpenKeyLease,
        rotate: bool,
    ) -> Result<(), EndpointError> {
        self.check_clock(now)?;
        let hmac_key = match &key {
            crate::FastOpenServerKey::HmacSha256(key) => Some(*key),
            #[cfg(feature = "tfo-linux-cookie")]
            crate::FastOpenServerKey::LinuxSipHash24(_) => None,
        };
        self.fast_open_cookie_policy.check_install(&key)?;
        let id = self.register_fast_open_credential(
            &key,
            self.fast_open_cookie_policy.lifetime,
            now,
            Some(lease),
        )?;
        self.fast_open_cookie_policy.install(
            key,
            id,
            &mut self.fast_open_credentials,
            now,
            self.config.connection.timebase,
            rotate,
        );
        if let Some(key) = hmac_key {
            self.fast_open_hmac_key = key;
            self.fast_open_hmac_error = None;
        }
        self.clock(now)
    }

    /// Listener-scoped timed installation using the same bounded key context.
    /// None/default inheritance can subsequently be restored with the policy setter.
    pub fn install_listener_fast_open_key(
        &mut self,
        now: Instant,
        id: ListenerId,
        key: crate::FastOpenServerKey,
        lease: crate::FastOpenKeyLease,
        rotate: bool,
    ) -> Result<(), EndpointError> {
        self.listener(id)?;
        self.check_clock(now)?;
        lease.validate(now, self.config.connection.timebase)?;
        let timebase = self.config.connection.timebase;
        let mut context = self.listeners[id.slot]
            .as_ref()
            .unwrap()
            .fast_open_cookie_policy
            .clone()
            .unwrap_or_else(|| self.fast_open_cookie_policy.clone());
        context.check_install(&key)?;
        let credential =
            self.register_fast_open_credential(&key, context.lifetime, now, Some(lease))?;
        context.install(
            key,
            credential,
            &mut self.fast_open_credentials,
            now,
            timebase,
            rotate,
        );
        self.listeners[id.slot]
            .as_mut()
            .unwrap()
            .fast_open_cookie_policy = Some(context);
        self.clock(now)
    }

    /// Enable the bounded cookie service. Cookies authenticate addresses, not
    /// freshness of application operations; listeners must separately opt in.
    pub fn enable_fast_open(&mut self) -> Result<(), EndpointError> {
        if self.fast_open.is_none() {
            let charge = crate::fast_open::FastOpen::allocation_bytes();
            if charge > self.buffer_room() {
                return Err(Error::NoMemory.into());
            }
            let service = crate::fast_open::FastOpen::new()?;
            self.fast_open = Some(service);
            self.charge(charge);
        }
        Ok(())
    }

    // Explicit administration after server/path maintenance, not an automatic
    // retry heuristic. Clear learned client credentials, peer MSS and per-service
    // failure records, retaining allocated storage. Existing connections keep
    // their snapshots; their later handshakes can learn fresh entries again.
    // Server cookie keys/policies, listeners and output reservations are untouched.
    pub fn clear_fast_open_client_cache(&mut self) {
        if let Some(cache) = &mut self.fast_open {
            cache.clear_client_cache();
        }
    }

    fn fast_open_lifetime(&self) -> u64 {
        self.config
            .connection
            .timebase
            .ticks_from_us(crate::fast_open::LIFETIME_US)
    }

    fn fast_open_negative_lifetime(&self) -> u64 {
        self.config
            .connection
            .timebase
            .ticks_from_us(crate::fast_open::NEGATIVE_LIFETIME_US)
    }

    /// Opt this listener into replay-tolerant early delivery; zero disables it.
    pub fn set_listener_fast_open(
        &mut self,
        id: ListenerId,
        pending_limit: usize,
    ) -> Result<(), EndpointError> {
        self.listener(id)?;
        if pending_limit > self.config.max_connections
            || pending_limit != 0 && self.fast_open.is_none()
        {
            return Err(Error::InvalidArgument.into());
        }
        self.listeners[id.slot].as_mut().unwrap().fast_open_limit = pending_limit;
        Ok(())
    }

    pub fn has_fast_open_cookie(
        &self,
        now: Instant,
        local: IpAddr,
        remote: IpAddr,
    ) -> Result<bool, EndpointError> {
        self.check_clock(now)?;
        Ok(self.fast_open.as_ref().is_some_and(|service| {
            service
                .get_in(now, self.fast_open_lifetime(), local, remote, None)
                .is_some()
        }))
    }

    pub fn can_defer_fast_open(
        &self,
        now: Instant,
        local: IpAddr,
        remote: SocketAddr,
    ) -> Result<bool, EndpointError> {
        self.can_defer_fast_open_with_server_cookie(now, local, remote, None)
    }

    /// A supplied cookie must have been obtained from this target server.
    /// This checks eligibility only; it does not enable TFO or clear failures.
    pub fn can_defer_fast_open_with_server_cookie(
        &self,
        now: Instant,
        local: IpAddr,
        remote: SocketAddr,
        cookie: Option<wire::FastOpenCookie>,
    ) -> Result<bool, EndpointError> {
        self.check_clock(now)?;
        Ok(
            (cookie.is_some() || self.has_fast_open_cookie(now, local, remote.ip())?)
                && self.fast_open.as_ref().is_some_and(|service| {
                    !service.suppressed(now, self.fast_open_negative_lifetime(), local, remote, None)
                }),
        )
    }

    /// Check a protected-service agreement independently of cookie possession.
    /// Negative-response suppression remains authoritative for either policy.
    pub fn can_defer_fast_open_with_policy(
        &self,
        now: Instant,
        local: IpAddr,
        remote: SocketAddr,
        policy: crate::FastOpenClientPolicy,
    ) -> Result<bool, EndpointError> {
        self.check_clock(now)?;
        Ok((policy == crate::FastOpenClientPolicy::ApplicationProtected
            || self.has_fast_open_cookie(now, local, remote.ip())?)
            && self.fast_open.as_ref().is_some_and(|service| {
                !service.suppressed(now, self.fast_open_negative_lifetime(), local, remote, None)
            }))
    }

    /// Deferral eligibility for a peer whose tuple has `zone` (Some exactly
    /// when an address is IPv6 link-local): a supplied `cookie` as
    /// [`Self::can_defer_fast_open_with_server_cookie`], otherwise `policy`
    /// as [`Self::can_defer_fast_open_with_policy`], with that zone's cookie
    /// cache and suppression.
    pub fn can_defer_scoped_fast_open(
        &self,
        now: Instant,
        local: IpAddr,
        remote: SocketAddr,
        zone: Option<ntcp_path::LinkId>,
        cookie: Option<wire::FastOpenCookie>,
        policy: crate::FastOpenClientPolicy,
    ) -> Result<bool, EndpointError> {
        self.check_clock(now)?;
        let lifetime = self.fast_open_lifetime();
        Ok(self.fast_open.as_ref().is_some_and(|service| {
            (cookie.is_some()
                || policy == crate::FastOpenClientPolicy::ApplicationProtected
                || service.get_in(now, lifetime, local, remote.ip(), zone).is_some())
                && !service.suppressed(now, self.fast_open_negative_lifetime(), local, remote, zone)
        }))
    }

    /// Copy initial data before publishing an active TFO connection. A cache
    /// miss accepts zero bytes and sends a cookie request, not cookieless data.
    pub fn connect_fast_open(
        &mut self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
        initial: &[u8],
    ) -> Result<(ConnectionId, usize), EndpointError> {
        self.connect_fast_open_with_buffer_capacities(
            now,
            local,
            remote,
            initial,
            self.config.connection.send_capacity,
            self.config.connection.receive_capacity,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn connect_fast_open_with_buffer_capacities(
        &mut self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
        initial: &[u8],
        send_capacity: usize,
        receive_capacity: usize,
    ) -> Result<(ConnectionId, usize), EndpointError> {
        self.connect_fast_open_with_options(
            now,
            local,
            remote,
            initial,
            ActiveOpenOptions {
                send_capacity,
                receive_capacity,
                ..ActiveOpenOptions::from(&self.config.connection)
            },
        )
    }

    pub fn connect_fast_open_with_options(
        &mut self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
        initial: &[u8],
        options: ActiveOpenOptions,
    ) -> Result<(ConnectionId, usize), EndpointError> {
        self.connect_fast_open_with_server_cookie(now, local, remote, initial, options, None)
    }

    /// Open using a cookie already obtained from `remote` for this local address, or the ordinary
    /// learned cache when `cookie` is None. A supplied zero cookie requires
    /// explicit agreement with a protected service under RFC7413 section7.3.
    /// The option is sent on wire. Without learned peer MSS, protocol defaults
    /// bound initial data. Suppression, memory and output admission still apply.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-7.3
    //= reason=Only an explicit server-provided/agreed zero cookie is admitted through the supplied-cookie API; default misses still request a cookie. The protected server and client opt in independently.
    //# For such applications the server may choose to generate a trivial or even a zero-length cookie to improve performance by avoiding the cookie generation and verification.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1
    //# The cookie is a MAC tag generated by the server and is opaque to the client; the client simply caches the cookie and passes it back on subsequent SYN packets to open new connections.
    pub fn connect_fast_open_with_server_cookie(
        &mut self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
        initial: &[u8],
        options: ActiveOpenOptions,
        cookie: Option<wire::FastOpenCookie>,
    ) -> Result<(ConnectionId, usize), EndpointError> {
        self.connect_fast_open_authorized(
            now,
            local,
            remote,
            initial,
            options,
            cookie,
            crate::FastOpenClientPolicy::RequireCookie,
            None,
        )
    }

    /// Open to an explicitly agreed protected service without a cookie option.
    /// Default policy still requires a cookie. Neither this authorization nor
    /// absence of an option invents a peer MSS or clears failure evidence.
    pub fn connect_fast_open_with_policy(
        &mut self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
        initial: &[u8],
        options: ActiveOpenOptions,
        policy: crate::FastOpenClientPolicy,
    ) -> Result<(ConnectionId, usize), EndpointError> {
        self.connect_fast_open_authorized(now, local, remote, initial, options, None, policy, None)
    }

    /// Active Fast Open with an independent local listener receive authority.
    /// Outgoing supplied/cache cookies and client policy retain their own roles.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_fast_open_with_receive_authority(
        &mut self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
        initial: &[u8],
        options: ActiveOpenOptions,
        cookie: Option<wire::FastOpenCookie>,
        policy: crate::FastOpenClientPolicy,
        receive_authority: Option<ListenerId>,
    ) -> Result<(ConnectionId, usize), EndpointError> {
        self.connect_fast_open_authorized(
            now,
            local,
            remote,
            initial,
            options,
            cookie,
            policy,
            receive_authority,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn connect_fast_open_authorized(
        &mut self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
        initial: &[u8],
        options: ActiveOpenOptions,
        cookie: Option<wire::FastOpenCookie>,
        policy: crate::FastOpenClientPolicy,
        receive_authority: Option<ListenerId>,
    ) -> Result<(ConnectionId, usize), EndpointError> {
        let tuple = Tuple { local, remote };
        let zone = self.scoped(tuple).zone;
        let admission =
            self.active_admission(now, self.scoped(tuple), &options, receive_authority, true);
        self.admit_open(admission)?;
        let service = self.fast_open.as_ref().ok_or(Error::InvalidState)?;
        let suppressed =
            service.suppressed(now, self.fast_open_negative_lifetime(), local.ip(), remote, zone);
        let cached = service.get_in(now, self.fast_open_lifetime(), local.ip(), remote.ip(), zone);
        let peer_mss =
            service.peer_mss(now, self.fast_open_lifetime(), local.ip(), remote.ip(), zone);
        self.clock(now)?;
        let iss = self.isn(self.scoped(tuple));
        let mut connection = self.new_connection_with_options(
            tuple,
            iss,
            None,
            options,
            (false, false),
            0,
            RxPacketTimestamps::default(),
            receive_authority,
        )?;
        let old_charge = connection.buffer_charge();
        let budget = self
            .buffer_room()
            .saturating_add(connection.buffer_charge());
        let accepted = match if suppressed {
            Ok(0)
        } else if let Some(cookie) = cookie {
            connection.prepare_fast_open_with_server_cookie(cookie, peer_mss, initial, budget)
        } else if policy == crate::FastOpenClientPolicy::ApplicationProtected {
            connection.prepare_fast_open_without_cookie(peer_mss, initial, budget)
        } else {
            connection.prepare_fast_open_with_budget(cached, initial, budget)
        } {
            Ok(count) => count,
            Err(error) => {
                // A send ring that grew before the other failed is charged
                // until recycling releases it.
                self.recharge(old_charge, connection.buffer_charge());
                self.recycle_connection(connection);
                return Err(error.into());
            }
        };
        self.recharge(old_charge, connection.buffer_charge());
        let id = self.insert(connection, None, None)?;
        self.slots[id.slot].as_mut().unwrap().receive_authority = receive_authority;
        Ok((id, accepted))
    }

    /// Non-constructing active-open admission in the raw open paths' error
    /// precedence. Managed factories run it before preparing path authority,
    /// so a rejected OPEN draws no ISN, advances no clock and leaves no
    /// provider reservation, and keeps its established error.
    pub(crate) fn active_admission(
        &self,
        now: Instant,
        tuple: ScopedTuple,
        options: &ActiveOpenOptions,
        receive_authority: Option<ListenerId>,
        fast_open: bool,
    ) -> Result<(), EndpointError> {
        options.validate()?;
        if let Some(authority) = receive_authority {
            self.validate_fast_open_receive_authority(authority, tuple.tuple.local.ip())?;
        }
        self.check_clock(now)?;
        if fast_open && self.fast_open.is_none() {
            return Err(Error::InvalidState.into());
        }
        self.admission_with_buffers(tuple, (options.send_capacity, options.receive_capacity))
    }

    pub fn connect(
        &mut self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<ConnectionId, EndpointError> {
        self.check_clock(now)?;
        let tuple = Tuple { local, remote };
        let admission = self.admission(self.scoped(tuple));
        self.admit_open(admission)?;
        self.clock(now)?;
        let iss = self.isn(self.scoped(tuple));
        let connection = self.new_connection(tuple, iss, None)?;
        self.insert(connection, None, None)
    }

    pub fn connect_with_buffer_capacities(
        &mut self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
        send: usize,
        receive: usize,
    ) -> Result<ConnectionId, EndpointError> {
        self.connect_with_options(
            now,
            local,
            remote,
            ActiveOpenOptions {
                send_capacity: send,
                receive_capacity: receive,
                ..ActiveOpenOptions::from(&self.config.connection)
            },
        )
    }

    pub fn connect_with_options(
        &mut self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
        options: ActiveOpenOptions,
    ) -> Result<ConnectionId, EndpointError> {
        self.connect_with_receive_authority(now, local, remote, options, None)
    }

    /// Select a live local listener as receive authority before active output.
    /// The active connection retains its identity and never enters accept queues.
    pub fn connect_with_receive_authority(
        &mut self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
        options: ActiveOpenOptions,
        receive_authority: Option<ListenerId>,
    ) -> Result<ConnectionId, EndpointError> {
        let tuple = Tuple { local, remote };
        let scoped = self.scoped(tuple);
        let admission = self.active_admission(now, scoped, &options, receive_authority, false);
        self.admit_open(admission)?;
        self.clock(now)?;
        let iss = self.isn(scoped);
        let connection = self.new_connection_with_options(
            tuple,
            iss,
            None,
            options,
            (false, false),
            0,
            RxPacketTimestamps::default(),
            receive_authority,
        )?;
        let id = self.insert(connection, None, None)?;
        self.slots[id.slot].as_mut().unwrap().receive_authority = receive_authority;
        Ok(id)
    }

    pub fn buffer_capacities(&self, id: ConnectionId) -> Result<(usize, usize), EndpointError> {
        Ok(self.slot(id)?.connection.buffer_capacities())
    }

    /// Sets the send limit of `id` to `bytes` and locks its send
    /// direction, as SO_SNDBUF sets SOCK_SNDBUF_LOCK: neither autotuning
    /// nor memory pressure changes it. Allocates nothing; the next write
    /// grows the send ring. 0 < `bytes` < 2^30.
    pub fn set_send_buffer(&mut self, id: ConnectionId, bytes: usize) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        Connection::validate_buffer_capacities(bytes, 1)?;
        self.slot_mut(id)?.connection.set_send_buffer(bytes);
        self.refresh(id.slot);
        Ok(())
    }

    /// Sets the receive window of `id` to `bytes` and locks its receive
    /// direction, as SO_RCVBUF sets SOCK_RCVBUF_LOCK: DRS no longer grows
    /// it. A larger size grows the receive ring now, refused with
    /// `NoMemory` if its peak charge does not fit the budget; a smaller one
    /// keeps the ring and never retracts the window offered. Before the SYN
    /// leaves, it also sets the window scale. 0 < `bytes` ≤ 65535·2^14.
    pub fn set_receive_buffer(
        &mut self,
        id: ConnectionId,
        bytes: usize,
    ) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        Connection::validate_buffer_capacities(1, bytes)?;
        let old = self.slot(id)?.connection.buffer_charge();
        let max_charge = self.buffer_room().saturating_add(old);
        let result = self
            .slot_mut(id)?
            .connection
            .set_receive_buffer(bytes, max_charge);
        self.memory_refused_growths += u64::from(result == Err(Error::NoMemory));
        // Charged even when refused: a bitmap that grew before another
        // failed keeps its storage.
        let new = self.slot(id)?.connection.buffer_charge();
        self.recharge(old, new);
        result?;
        self.refresh(id.slot);
        Ok(())
    }

    // Shorthand for tests: both setters, receive first so that a refused
    // growth changes nothing.
    #[cfg(test)]
    pub(crate) fn set_buffer_capacities(
        &mut self,
        id: ConnectionId,
        send: usize,
        receive: usize,
    ) -> Result<(), EndpointError> {
        Connection::validate_buffer_capacities(send, receive)?;
        self.set_receive_buffer(id, receive)?;
        self.set_send_buffer(id, send)
    }

    /// `set_send_buffer` for the connections `id` accepts from now on:
    /// each starts with this send limit, locked.
    pub fn set_listener_send_buffer(
        &mut self,
        id: ListenerId,
        bytes: usize,
    ) -> Result<(), EndpointError> {
        self.listener(id)?;
        Connection::validate_buffer_capacities(bytes, 1)?;
        let listener = self.listeners[id.slot].as_mut().unwrap();
        listener.buffer_capacities.0 = bytes;
        listener.buffer_locks.0 = true;
        Ok(())
    }

    /// `set_receive_buffer` for the connections `id` accepts from now on:
    /// each opens with a ring and window of this size, locked, and takes
    /// its window scale from it. Refused with `NoMemory` if one such
    /// connection's open charge with the listener's RX timestamp capacity
    /// exceeds the cap.
    pub fn set_listener_receive_buffer(
        &mut self,
        id: ListenerId,
        bytes: usize,
    ) -> Result<(), EndpointError> {
        let listener = self.listener(id)?;
        let (send, rx_ranges) = (listener.buffer_capacities.0, listener.rx_timestamp_capacity);
        Connection::validate_buffer_capacities(1, bytes)?;
        self.validate_listener_rx_capacity((send, bytes), rx_ranges)?;
        let listener = self.listeners[id.slot].as_mut().unwrap();
        listener.buffer_capacities.1 = bytes;
        listener.buffer_locks.1 = true;
        Ok(())
    }

    // Shorthand for tests: both listener setters, receive first.
    #[cfg(test)]
    pub(crate) fn set_listener_buffer_capacities(
        &mut self,
        id: ListenerId,
        send: usize,
        receive: usize,
    ) -> Result<(), EndpointError> {
        Connection::validate_buffer_capacities(send, receive)?;
        self.set_listener_receive_buffer(id, receive)?;
        self.set_listener_send_buffer(id, send)
    }

    fn validate_listener_rx_capacity(
        &self,
        capacities: (usize, usize),
        ranges: usize,
    ) -> Result<(), EndpointError> {
        if ranges == 0 {
            return Ok(());
        }
        let metadata = RxTimestamps::allocation_bytes(ranges).ok_or(Error::NoMemory)?;
        let total = Connection::open_bytes(capacities.1, usize::from(self.config.connection.mss))
            .and_then(|bytes| bytes.checked_add(metadata))
            .ok_or(Error::NoMemory)?;
        if total > self.memory().high {
            return Err(Error::NoMemory.into());
        }
        Ok(())
    }

    pub fn set_listener_rx_timestamp_capacity(
        &mut self,
        id: ListenerId,
        ranges: usize,
    ) -> Result<(), EndpointError> {
        let capacities = self.listener(id)?.buffer_capacities;
        self.validate_listener_rx_capacity(capacities, ranges)?;
        self.listeners[id.slot]
            .as_mut()
            .unwrap()
            .rx_timestamp_capacity = ranges;
        Ok(())
    }

    pub fn listener_rx_timestamp_capacity(&self, id: ListenerId) -> Result<usize, EndpointError> {
        Ok(self.listener(id)?.rx_timestamp_capacity)
    }

    // Accepted children waiting for accept, and the configured accept backlog.
    pub fn listener_queue_info(&self, id: ListenerId) -> Result<(usize, usize), EndpointError> {
        let listener = self.listener(id)?;
        Ok((listener.pending.len(), listener.backlog))
    }

    pub fn listener_buffer_capacities(
        &self,
        id: ListenerId,
    ) -> Result<(usize, usize), EndpointError> {
        Ok(self.listener(id)?.buffer_capacities)
    }

    fn validate_ipv4_options(
        &self,
        ip: IpMetadata,
        options: OutgoingIpv4Options,
    ) -> Result<(), EndpointError> {
        if options == OutgoingIpv4Options::default() {
            return Ok(());
        }
        let (IpAddr::V4(source), IpAddr::V4(destination)) = (ip.source, ip.destination) else {
            return Err(EndpointError::InvalidAddress);
        };
        if !self.config.ipv4_options_enabled {
            return Err(Ipv4OptionsError::SourceRouteDisabled.into());
        }
        if options.source_route.is_some_and(|r| {
            r.hops()
                .iter()
                .any(|&a| !self.valid_route(ip.source, ip.destination, a.into()))
        }) {
            return Err(EndpointError::InvalidAddress);
        }
        if let Some(TimestampRequest::Prespecified { addresses, len }) = options.timestamp
            && (usize::from(len) > addresses.len()
                || addresses[..usize::from(len)]
                    .iter()
                    .any(|&a| !self.valid_route(ip.source, ip.destination, a.into())))
        {
            return Err(EndpointError::InvalidAddress);
        }
        options.encode(source, destination, 0, &mut [0; 40])?;
        // An automatic return route can grow to 39 bytes. An explicit route (including
        // an empty direct route) bounds space available to optional RR/TS requests.
        if options.source_route.is_none()
            && (options.record_route_slots.is_some() || options.timestamp.is_some())
        {
            return Err(Ipv4OptionsError::Capacity.into());
        }
        Ok(())
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.1
    //# An application MUST be able to specify a source route when it
    //# actively opens a TCP connection (MUST-51), and this MUST take
    //# precedence over a source route received in a datagram (MUST-52).
    pub fn connect_with_ipv4_options(
        &mut self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
        options: OutgoingIpv4Options,
    ) -> Result<ConnectionId, EndpointError> {
        self.validate_ipv4_options(
            IpMetadata {
                source: local.ip(),
                destination: remote.ip(),
            },
            options,
        )?;
        let id = self.connect(now, local, remote)?;
        let slot = self.slots[id.slot].as_mut().unwrap();
        slot.ipv4_options = options;
        Self::sync_ip_header_len(slot);
        slot.explicit_route = options.source_route.is_some();
        Ok(id)
    }

    pub fn received_ipv4_options(
        &self,
        id: ConnectionId,
    ) -> Result<Option<Ipv4Options>, EndpointError> {
        Ok(self.slot(id)?.received_ipv4_options)
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.1
    //# When a TCP connection is OPENed passively and a packet arrives with a
    //# completed IP Source Route Option (containing a return route), TCP
    //# implementations MUST save the return route and use it for all
    //# segments sent on this connection (MUST-53).  If a different source
    //# route arrives in a later segment, the later definition SHOULD
    //# override the earlier one (SHLD-24).
    fn save_ipv4_options(slot: &mut Slot, options: Ipv4Options, route: Option<SourceRoute>) {
        slot.received_ipv4_options = Some(options);
        if !slot.explicit_route && route.is_some() {
            slot.ipv4_options.source_route = route;
        }
        Self::sync_ip_header_len(slot);
    }

    fn sync_ip_header_len(slot: &mut Slot) {
        let tuple = slot.connection.tuple();
        if let (IpAddr::V4(source), IpAddr::V4(destination)) = (tuple.local.ip(), tuple.remote.ip())
        {
            let len = slot
                .ipv4_options
                .encode(source, destination, 0, &mut [0; 40])
                .map_or(40, |(_, len)| len);
            slot.connection.set_ip_header_len(20 + len as u16);
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.1
    //# The optional "local IP address" parameter MUST be supported to allow
    //# the specification of the local IP address (MUST-43).
    pub fn connect_with_source(
        &mut self,
        now: Instant,
        local: Option<SocketAddr>,
        remote: SocketAddr,
        select_source: impl FnOnce(SocketAddr) -> Result<SocketAddr, EndpointError>,
    ) -> Result<ConnectionId, EndpointError> {
        self.check_clock(now)?;
        self.clock(now)?;
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.1
        //# If an application on a multihomed host does not specify the local IP
        //# address when actively opening a TCP connection, then the TCP
        //# implementation MUST ask the IP layer to select a local IP address
        //# before sending the (first) SYN (MUST-44).

        // Traceability limitation: The callback is supplied by the embedding IP layer.
        let local = match local {
            Some(address) => address,
            None => select_source(remote)?,
        };
        self.connect(now, local, remote)
    }

    fn unlink_child(&mut self, parent: ListenerId, id: ConnectionId) {
        if self.listener_generations[parent.slot] != parent.generation {
            return;
        }
        if let Some(listener) = self.listeners[parent.slot].as_mut() {
            // ponytail: bounded backlog search on admission cleanup, not packet lookup.
            if let Some(position) = listener.children.iter().position(|child| *child == id) {
                listener.children.swap_remove(position);
            }
            listener.pending.retain(|child| *child != id);
        }
    }

    fn reclaim(&mut self, index: usize) {
        let id = self.id(index);
        debug_assert!(!self.is_output_reserved(id));
        let slot = self.slots[index].take().unwrap();
        self.occupied.remove(index);
        self.budget.close_socket();
        let tuple = slot.connection.scoped_tuple();
        if slot.mapped {
            self.tuples.remove(self.hash(tuple), tuple, index);
        }
        if let Some(parent) = slot.listener {
            self.unlink_child(parent, id);
        }
        self.output.remove(index);
        self.events.remove(index);
        self.advice.remove(index);
        self.progress.remove(index);
        self.stop_memory_wait(index);
        self.deadlines.set(index, None);
        if slot.time_wait {
            self.time_wait_slots -= 1;
        }
        self.loss_counters.add(slot.connection.loss_events);
        self.ledger_split_refusals += slot.connection.split_refusals();
        self.recycle_connection(slot.connection);
        let at = (self.reclaimed % self.reclaims.len() as u64) as usize;
        self.reclaims[at] = id;
        self.reclaimed += 1;
        if let Some(generation) = self.generations[index].checked_add(1) {
            self.generations[index] = generation;
            self.free.push(index);
        }
    }

    // The connection or TIME-WAIT record that owns `tuple`. At most one does:
    // a record whose tuple a reopened connection took is not in the index.
    fn lookup(&self, tuple: ScopedTuple) -> Option<Target> {
        let hash = self.hash(tuple);
        match self.tuples.find(hash, tuple) {
            Some(index) => Some(Target::Connection(index)),
            None => self
                .time_wait
                .find(hash as u64, tuple)
                .map(Target::TimeWait),
        }
    }

    // A released connection in TIME-WAIT with nothing left to send keeps
    // only its TIME-WAIT record (Linux's tcp_time_wait): its slot, buffers
    // and timer are freed now, not when TIME-WAIT ends. Over
    // `max_time_wait` it closes without TIME-WAIT, as Linux does over
    // tcp_max_tw_buckets. False if it is not ready to.
    fn enter_time_wait(&mut self, index: usize) -> bool {
        let slot = self.slots[index].as_ref().unwrap();
        let Some(record) = slot.connection.time_wait_record(
            slot.hop_limit,
            slot.dscp,
            slot.mark,
            slot.reuse_address,
            slot.ipv4_options,
        ) else {
            return false;
        };
        // A connection whose tuple went to a reopened one left TIME-WAIT then.
        debug_assert!(slot.mapped);
        let hash = self.hash(record.tuple);
        self.reclaim(index);
        if !self.insert_time_wait(hash as u64, record) {
            self.time_wait_overflows += 1;
        }
        true
    }

    // The one place TIME-WAIT records are stored.
    fn insert_time_wait(&mut self, hash: u64, record: crate::time_wait::Record) -> bool {
        self.time_wait.insert(hash, record)
    }

    // The one place TIME-WAIT records end: expiry, an acceptable RST, a
    // reopening SYN, or an ambiguous timestamp clock.
    fn remove_time_wait(&mut self, index: u32) {
        self.time_wait.remove(index);
    }

    /// Released connections closed without TIME-WAIT because
    /// `max_time_wait` records were kept (Linux's TCPTimeWaitOverflow).
    pub fn time_wait_overflows(&self) -> u64 {
        self.time_wait_overflows
    }

    /// Retransmissions, retransmission timeouts, tail loss probes, loss
    /// recovery entries and D-SACKs received, over every connection since
    /// the endpoint's creation, after Linux's MIB counters (`LossCounters`).
    /// For administrative reporting.
    pub fn loss_counters(&self) -> crate::LossCounters {
        // Every connection's refresh took what it counted.
        debug_assert!(self.occupied.iter().all(|index| {
            self.slots[index]
                .as_ref()
                .is_none_or(|slot| slot.connection.loss_events == crate::LossCounters::default())
        }));
        self.loss_counters
    }

    /// Whether a TIME-WAIT record holds `port` as its local port: a port
    /// stays bound through TIME-WAIT, as in a Linux bind bucket, after the
    /// connection that used it was reclaimed.
    pub fn time_wait_holds_port(&self, port: u16) -> bool {
        self.time_wait.holds_port(port)
    }

    /// The tuple and SO_REUSEADDR (`set_reuse_address`) of every TIME-WAIT
    /// record whose local port is `port`, for a bind to judge, as Linux's
    /// inet_csk_bind_conflict walks the timewait sockets of the port's bind
    /// bucket. None without a pass over the records while no record holds
    /// the port (`time_wait_holds_port`); else a pass over all of them.
    pub fn time_wait_binds(&self, port: u16) -> impl Iterator<Item = (ScopedTuple, bool)> + '_ {
        self.time_wait
            .holds_port(port)
            .then(|| self.time_wait.indices())
            .into_iter()
            .flatten()
            .map(|index| self.time_wait.record(index))
            .filter(move |record| record.tuple.tuple.local.port() == port)
            .map(|record| (record.tuple, record.reuse_address))
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4.1
    //# A connection is defined by a pair of sockets.  Connections can be
    //# reused.
    /// Whether a connection or a TIME-WAIT record has `tuple`, so that an
    /// active open of it would be refused (`EndpointError::AddressInUse`):
    /// the check an adapter's ephemeral port selection makes of each
    /// candidate (`EphemeralPorts::select`), as Linux's
    /// __inet_check_established looks up the established hash. One lookup
    /// in the tuple tables, whatever the number of connections.
    pub fn tuple_in_use(&self, tuple: ScopedTuple) -> bool {
        self.lookup(tuple).is_some()
    }

    //= https://www.rfc-editor.org/rfc/rfc6056#section-3.4
    //# To protect against this, the secret key should be of a reasonable
    //# length.  Key lengths of 128 bits should be adequate.
    /// The state of ephemeral port selection for this endpoint's active
    /// opens (RFC 6056 Algorithm 4), keyed by the endpoint's secret under
    /// its own label, as the ISN and lookup keys are: the ports it selects
    /// are unpredictable to whoever does not know the secret.
    pub fn ephemeral_ports(&self) -> Result<crate::EphemeralPorts, EndpointError> {
        let mut mac = self.keyed.clone();
        mac.update(b"ntcp ephemeral port key");
        let key = mac.finalize().into_bytes()[..16].try_into().unwrap();
        crate::EphemeralPorts::new(key, self.config.connection.timebase)
            .map_err(|_| Error::NoMemory.into())
    }

    // A connection in a steady state (`Slot::steady`) with no rare work
    // pending (`Connection::refresh_work`) needs only its timer, events,
    // output and managed progress: the walk would find nothing else to do,
    // as Linux does that work where it arises, not on every pass.
    fn refresh(&mut self, index: usize) {
        if let Some(slot) = self.slots[index].as_ref()
            && slot.steady()
            && !slot.connection.refresh_work()
        {
            #[cfg(debug_assertions)]
            self.check_refresh_steady(index);
            self.refresh_steady(index);
            return;
        }
        self.refresh_walk(index);
        if let Some(slot) = self.slots[index].as_mut() {
            slot.connection.settle_refresh_work();
        }
    }

    // The part of the walk a steady connection with nothing pending needs.
    fn refresh_steady(&mut self, index: usize) {
        if self.managed_context.is_some()
            && let Some(slot) = &self.slots[index]
            && (slot.connection.unacknowledged() != self.progress_una[index]
                || slot.connection.managed_results.unpublished())
        {
            self.progress.push(index);
        }
        if self.is_output_reserved(self.id(index)) {
            self.deadlines.set(index, None);
            return;
        }
        let slot = self.slots[index].as_ref().unwrap();
        self.deadlines.set(index, slot.deadline());
        if slot.listener.is_none() && !slot.released && slot.connection.events_pending() {
            self.events.push(index);
        }
        if slot.mapped && !slot.connection.output_idle() {
            self.output.push(index);
        }
    }

    // Every test of the walk that `refresh_steady` leaves out finds
    // nothing to do.
    #[cfg(debug_assertions)]
    fn check_refresh_steady(&self, index: usize) {
        let slot = self.slots[index].as_ref().unwrap();
        let connection = &slot.connection;
        let state = connection.state();
        assert!(!connection.send_expand_pending());
        assert!(!connection.ledgers_reclaimable() && !connection.send_ring_reclaimable());
        assert_eq!(slot.time_wait, state == State::TimeWait);
        assert_eq!(connection.loss_events, crate::LossCounters::default());
        assert_eq!(connection.split_refusals(), 0);
        assert!(!connection.fast_open_negative);
        assert!(connection.fast_open_learned.is_none());
        assert!(!connection.fast_open_peer_reset);
        assert!(slot.fast_open_owner.is_none());
        assert!(!connection.iw_setup_loss());
        assert!(!connection.route_advice_pending());
        assert!(!(slot.released && state == State::TimeWait));
        let newly_established = !slot.accepted_ready
            && (connection.handshake_complete() || connection.fast_open_early)
            && state != State::Closed;
        assert!(!(slot.listener.is_some() && newly_established));
        assert_ne!(state, State::Closed);
    }

    //= https://www.rfc-editor.org/rfc/rfc7413#section-3
    //# 3. The client caches the cookie for future TCP Fast Open connections (see below).
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.3
    //# When caching cookies, we recommend that the client also cache the Maximum Segment Size (MSS)
    //# advertised by the server. The client can cache the MSS advertised by the server in order to
    //# determine the maximum amount of data that the client can fit in the SYN packet in subsequent TFO
    //# connections.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.3.1
    //# The client MUST cache negative responses from the server in order to avoid potential connection
    //# failures.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
    //# 1. If the SYN-ACK has a Fast Open option, an MSS option, or both, update the corresponding cookie
    //# and MSS information in the cookie cache.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
    //# Upon receiving an ACK acknowledging the SYN sequence, the server decrements PendingFastOpenRequests
    //# and advances to the ESTABLISHED state. No special handling is required further.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-5.1
    //# For this reason, a TFO server needs to monitor the connections in SYN-RCVD being reset in addition
    //# to imposing a reasonable max queue length. Implementations may combine the two, e.g., by continuing
    //# to account for those connection requests that have just been reset against the listener's
    //# PendingFastOpenRequests until a timeout period has passed.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-7.1
    //# Moreover, the implementation is recommended to negatively cache such incidents to avoid recurring
    //# timeouts.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.1
    //# 3. If the SYN-ACK has a Fast Open option with a cookie, the client replaces the cookie and other information as described in the "Client Cookie Handling" section (Section 4.1.3). Otherwise, if the SYN-ACK is first seen and not a (spurious) retransmission, the client MAY remove the server information from the cookie cache. If the SYN-ACK is a spurious retransmission, the client does nothing to the cookie cache for the reasons below.
    fn refresh_walk(&mut self, index: usize) {
        // RFC 7413 §5.1: retain recent remote resets in admission accounting.
        // Sixty seconds and latest-reset batch retention are local policy.
        let reset_cooldown = self.config.connection.timebase.ticks_from_us(60_000_000);
        if self.slots[index]
            .as_ref()
            .is_some_and(|slot| slot.connection.send_expand_pending())
        {
            // tcp_should_expand_sndbuf: neither under memory pressure nor
            // charged tcp_mem[0] or more.
            let allowed =
                !self.budget.under_pressure() && self.budget.allocated() < self.memory().low;
            let slot = self.slots[index].as_mut().unwrap();
            slot.connection.expand_send(allowed);
        }
        if self.slots[index].as_ref().is_some_and(|slot| {
            slot.connection.ledgers_reclaimable() || slot.connection.send_ring_reclaimable()
        }) {
            // Drained ledgers and send ring above their reserves return to
            // the budget, waking writers waiting for memory.
            let connection = &mut self.slots[index].as_mut().unwrap().connection;
            let old = connection.buffer_charge();
            if connection.ledgers_reclaimable() {
                connection.reclaim_ledgers();
            }
            if connection.send_ring_reclaimable() {
                connection.reclaim_send_ring();
            }
            let new = connection.buffer_charge();
            self.recharge(old, new);
        }
        if let Some(slot) = self.slots[index].as_mut() {
            // Every change of a connection's state is followed by its
            // refresh, or ends in its reclaim.
            let time_wait = slot.connection.state() == State::TimeWait;
            if slot.time_wait != time_wait {
                slot.time_wait = time_wait;
                if time_wait {
                    self.time_wait_slots += 1;
                } else {
                    self.time_wait_slots -= 1;
                }
            }
            self.loss_counters
                .add(core::mem::take(&mut slot.connection.loss_events));
            self.ledger_split_refusals += slot.connection.take_split_refusals();
            if core::mem::take(&mut slot.connection.fast_open_negative)
                && let Some(service) = self.fast_open.as_mut()
            {
                let scoped = slot.connection.scoped_tuple();
                let tuple = scoped.tuple;
                service.fail(self.now, tuple.local.ip(), tuple.remote, scoped.zone);
            }
            if let Some((cookie, mss)) = slot.connection.fast_open_learned.take()
                && let Some(service) = self.fast_open.as_mut()
            {
                let ScopedTuple { tuple, zone } = slot.connection.scoped_tuple();
                if let Some(cookie) = cookie {
                    service.learn_in(self.now, tuple.local.ip(), tuple.remote.ip(), zone, cookie, mss);
                } else if let Some(mss) = mss {
                    service.update_mss(self.now, tuple.local.ip(), tuple.remote.ip(), zone, mss);
                }
            }
            if core::mem::take(&mut slot.connection.fast_open_peer_reset)
                && let Some(owner) = slot.fast_open_owner
                && self.listener_generations.get(owner.slot) == Some(&owner.generation)
                && let Some(listener) = self.listeners[owner.slot].as_mut()
                && !listener.closing
            {
                listener.reset_debt = listener
                    .reset_debt(self.now)
                    .saturating_add(1)
                    .min(self.config.max_connections);
                listener.reset_debt_expiry = Some(self.now.saturating_add(reset_cooldown));
            }
            if slot.connection.handshake_complete() || slot.connection.state() == State::Closed {
                slot.fast_open_owner = None;
            }
        }
        // Reserved connections too: the provider's evidence and results do
        // not wait for the reservation.
        if self.managed_context.is_some()
            && let Some(slot) = &self.slots[index]
            && (slot.connection.unacknowledged() != self.progress_una[index]
                || slot.connection.managed_results.unpublished())
        {
            self.progress.push(index);
        }
        if self.is_output_reserved(self.id(index)) {
            self.deadlines.set(index, None);
            return;
        }
        if let Some(slot) = &self.slots[index]
            && slot.connection.iw_setup_loss()
        {
            let scoped = slot.connection.scoped_tuple();
            let key = (scoped.tuple.local.ip(), scoped.tuple.remote.ip(), scoped.zone);
            if !self.setup_loss_cache.contains(&key) {
                if self.setup_loss_cache.len() == self.config.max_setup_cache_entries {
                    self.setup_loss_cache.pop_front();
                }
                self.setup_loss_cache.push_back(key);
            }
        }
        if self.slots[index]
            .as_mut()
            .is_some_and(|slot| slot.connection.take_route_advice())
        {
            self.advice.push(index);
        }
        let Some(slot) = self.slots[index].as_ref() else {
            return;
        };
        if slot.released
            && slot.connection.state() == State::TimeWait
            && self.enter_time_wait(index)
        {
            return;
        }
        let slot = self.slots[index].as_ref().unwrap();
        let state = slot.connection.state();
        let parent = slot.listener;
        let newly_established = !slot.accepted_ready
            && (slot.connection.handshake_complete() || slot.connection.fast_open_early)
            && state != State::Closed;
        // Accept readiness transfers terminal delivery to the application.
        // Explicit release/listener cleanup still abandons that ownership.
        let retained_ready = slot.accepted_ready && !slot.released;
        let failed_child = parent.is_some() && state == State::Closed && !retained_ready;
        let reset_reserved = slot.connection.reset_pending();
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.5.3
        //# If the receiver was
        //# in SYN-RECEIVED state and had previously been in the LISTEN state,
        //# then the receiver returns to the LISTEN state; otherwise, the
        //# receiver aborts the connection and goes to the CLOSED state.

        // A Closed connection may still owe a reset. Only reclaim after a
        // successful output attempt (including one that finds no packet).
        if state == State::Closed
            && (failed_child || slot.released)
            && slot.closed_output_drained
            && !reset_reserved
        {
            self.reclaim(index);
            return;
        }
        if failed_child {
            self.unlink_child(parent.unwrap(), self.id(index));
            let slot = self.slots[index].as_mut().unwrap();
            slot.listener = None;
            slot.released = true;
            self.events.remove(index);
        }
        if state == State::Closed && !reset_reserved && self.slots[index].as_ref().unwrap().mapped {
            let tuple = self.slots[index].as_ref().unwrap().connection.scoped_tuple();
            self.tuples.remove(self.hash(tuple), tuple, index);
            self.slots[index].as_mut().unwrap().mapped = false;
        }
        if let Some(parent) = parent
            && newly_established
        {
            self.slots[index].as_mut().unwrap().accepted_ready = true;
            let id = self.id(index);
            if let Some(listener) = self.listeners[parent.slot].as_mut()
                && !listener.closing
            {
                // Every connection that joins the queue raises Acceptable,
                // as each new child wakes a Linux listener (sk_data_ready):
                // an edge-triggered caller that took fewer than all pending
                // connections hears of the next one. The ready queue holds
                // the listener once, so joins before a drain coalesce.
                // A child joins only one the queue has room for: its SYN
                // or its handshake's last ACK found the queue not full.
                debug_assert!(!listener.accept_queue_full());
                listener.pending.push_back(id);
                self.events.push(self.config.max_connections + parent.slot);
            }
        }
        let slot = self.slots[index].as_ref().unwrap();
        self.deadlines.set(index, slot.deadline());
        if slot.listener.is_none() && !slot.released && slot.connection.events_pending() {
            self.events.push(index);
        }
        // An idle connection is not offered output: polling it would find
        // nothing, and only a change, followed by this refresh, gives it some.
        if (slot.mapped && state != State::Closed && !slot.connection.output_idle())
            || (state == State::Closed && !slot.closed_output_drained)
        {
            self.output.push(index);
        }
    }

    pub fn accept(&mut self, listener: ListenerId) -> Result<ConnectionId, EndpointError> {
        let pending = &self.listener(listener)?.pending;
        let position = pending
            .iter()
            .position(|&id| !self.is_output_reserved(id))
            .ok_or(if pending.is_empty() {
                Error::WouldBlock.into()
            } else {
                EndpointError::OutputReserved
            })?;
        let id = self.listeners[listener.slot]
            .as_mut()
            .unwrap()
            .pending
            .remove(position)
            .unwrap();
        self.unlink_child(listener, id);
        self.slots[id.slot].as_mut().unwrap().listener = None;
        self.refresh(id.slot);
        Ok(id)
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.1
    //# A passive OPEN call with a specified "local IP address" parameter
    //# will await an incoming connection request to that address.  If the
    //# parameter is unspecified, a passive OPEN will await an incoming
    //# connection request to any local IP address and then bind the local IP
    //# address of the connection to the particular address that is used.
    fn match_listener(
        &self,
        local: SocketAddr,
        zone: Option<ntcp_path::LinkId>,
    ) -> Option<ListenerId> {
        // Listener count is independently bounded; established lookup never scans it.
        let mut wildcard = None;
        for (slot, listener) in self.listeners.iter().enumerate() {
            let Some(listener) = listener else {
                continue;
            };
            if listener.closing
                || listener.address.port() != local.port()
                || listener.address.is_ipv4() != local.is_ipv4()
            {
                continue;
            }
            let id = ListenerId {
                slot,
                generation: self.listener_generations[slot],
            };
            // Only a link-local local address is scoped by the zone.
            if listener.address == local
                && listener.zone == zone.filter(|_| crate::connection::link_local(local.ip()))
            {
                return Some(id);
            }
            if listener.address.ip().is_unspecified() {
                wildcard = Some(id);
            }
        }
        wildcard
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.1
    //# An incoming
    //# segment containing a RST is discarded.  An incoming segment not
    //# containing a RST causes a RST to be sent in response.

    // Traceability limitation: Control replies are capacity- and rate-limited.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.1
    //= reason=Unknown tuple reset suppression and data discarded; control output subject to explicit capacity/rate bounds.
    //# all data in the incoming segment is discarded. An incoming segment containing a RST is
    //# discarded. An incoming segment not containing a RST causes a RST to be sent in response.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.1
    //= reason=Checks ACK-derived reset sequence and non-ACK sequence-space length including SYN/FIN across wrap.
    //# If the ACK bit is off, sequence number zero is used,
    //# <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK> If the ACK bit is on, <SEQ=SEG.ACK><CTL=RST>
    //= https://www.rfc-editor.org/rfc/rfc5961#section-4.2
    //= reason=ACK-derived reset_for output provides the restarted, unsynchronized peer response; end-to-end restart test proves the sequence.
    //# A legitimate peer, after restart, would not have a TCB in the synchronized state. Thus, when the ACK arrives, the peer should send a RST segment back with the sequence number derived from the ACK field that caused the RST.
    //= https://www.rfc-editor.org/rfc/rfc7323#section-5.2
    //= reason=Reactive RST uses (0,incoming TSval) independently of local TS configuration/negotiation when the IP payload budget permits 32 TCP bytes. At budgets 28..31 the optional TS is omitted rather than exceeding the path bound; this bounded SHOULD departure is tested for ACK/no-ACK resets. SYN-SENT and synchronized handshake rejection preserve the same echo policy.
    //# While still under discussion, to enable research into this area it is
    //# now RECOMMENDED that when generating an <RST>, if the segment causing
    //# the <RST> to be generated contains a Timestamps option, the <RST>
    //# should also contain a Timestamps option.
    //= https://www.rfc-editor.org/rfc/rfc7323#section-5.2
    //= reason=Reactive RST uses (0,incoming TSval) independently of local TS configuration/negotiation when the IP payload budget permits 32 TCP bytes. At budgets 28..31 the optional TS is omitted rather than exceeding the path bound; this bounded SHOULD departure is tested for ACK/no-ACK resets. SYN-SENT and synchronized handshake rejection preserve the same echo policy.
    //# In the <RST> segment,
    //# SEG.TSecr SHOULD be set to SEG.TSval from the incoming segment and
    //# SEG.TSval SHOULD be set to zero.
    fn reset_for(
        &mut self,
        ip: IpMetadata,
        zone: Option<ntcp_path::LinkId>,
        segment: &wire::Segment<'_>,
        route: Option<SourceRoute>,
    ) {
        if segment.header.flags & RST != 0
            || self.control.len() >= self.config.max_control_packets
        {
            return;
        }
        if self.now.saturating_sub(self.control_epoch)
            >= self.config.connection.timebase.ticks_from_us(1_000_000)
        {
            self.control_epoch = self.now;
            self.control_count = 0;
        }
        if self.control_count >= self.config.max_control_packets {
            return;
        }
        let incoming = segment.header;
        let ack = incoming.flags & ACK != 0;
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.1
        //# If the ACK bit is off, sequence number zero is used,
        //#
        //# <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
        //#
        //# If the ACK bit is on,
        //#
        //# <SEQ=SEG.ACK><CTL=RST>
        let header = Header {
            source_port: incoming.destination_port,
            destination_port: incoming.source_port,
            sequence: if ack { incoming.acknowledgment } else { 0 },
            acknowledgment: if ack {
                0
            } else {
                incoming
                    .sequence
                    .wrapping_add(segment.payload.len() as u32)
                    .wrapping_add(u32::from(incoming.flags & SYN != 0))
                    .wrapping_add(u32::from(incoming.flags & wire::FIN != 0))
            },
            flags: if ack { RST } else { RST | ACK },
            window: 0,
            urgent_pointer: 0,
        };
        self.control.push_back((
            IpMetadata {
                source: ip.destination,
                destination: ip.source,
            },
            header,
            OutgoingIpv4Options {
                source_route: route,
                ..OutgoingIpv4Options::default()
            },
            //= https://www.rfc-editor.org/rfc/rfc7323#section-5.2
            //= reason=Reactive RST uses (0,incoming TSval) independently of local TS configuration/negotiation when the IP payload budget permits 32 TCP bytes. At budgets 28..31 the optional TS is omitted rather than exceeding the path bound; this bounded SHOULD departure is tested for ACK/no-ACK resets. SYN-SENT and synchronized handshake rejection preserve the same echo policy.
            //# While still under discussion, to enable research into this area it is
            //# now RECOMMENDED that when generating an <RST>, if the segment causing
            //# the <RST> to be generated contains a Timestamps option, the <RST>
            //# should also contain a Timestamps option.
            //= https://www.rfc-editor.org/rfc/rfc7323#section-5.2
            //= reason=Reactive RST uses (0,incoming TSval) independently of local TS configuration/negotiation when the IP payload budget permits 32 TCP bytes. At budgets 28..31 the optional TS is omitted rather than exceeding the path bound; this bounded SHOULD departure is tested for ACK/no-ACK resets. SYN-SENT and synchronized handshake rejection preserve the same echo policy.
            //# In the <RST> segment,
            //# SEG.TSecr SHOULD be set to SEG.TSval from the incoming segment and
            //# SEG.TSval SHOULD be set to zero.
            segment
                .options
                .timestamps
                .map(|ts| ts.0)
                .filter(|_| self.config.connection.send_ip_payload_limit >= 32),
            None,
            zone,
        ));
        self.control_count += 1;
    }

    pub fn input(
        &mut self,
        now: Instant,
        ip: IpMetadata,
        bytes: &[u8],
    ) -> Result<InputDisposition, EndpointError> {
        self.input_with_traffic_class(now, ip, 0, bytes)
    }

    //= https://www.rfc-editor.org/rfc/rfc5961#section-4.2
    //= reason=Confirmed valid reset closes the old connection while its listener remains. A later peer SYN retransmission is routed to that listener and establishes a replacement, proven by the restart trace.
    //# The local TCP endpoint should then rely on SYN retransmission from the remote end to re-establish the connection.
    pub fn input_with_traffic_class(
        &mut self,
        now: Instant,
        ip: IpMetadata,
        traffic_class: u8,
        bytes: &[u8],
    ) -> Result<InputDisposition, EndpointError> {
        self.input_with_ipv4_options(now, ip, traffic_class, Ipv4Options::default(), bytes)
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.2
    //= reason=LISTEN ACK/SYN-ACK/FIN-ACK reset sequence is checked; bounded reset_for output.
    //# Any acknowledgment is bad if it arrives on a connection still in the LISTEN state. An
    //# acceptable reset segment should be formed for any arriving ACK-bearing segment. The RST
    //# should be formatted as follows: <SEQ=SEG.ACK><CTL=RST>
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.2
    //= reason=Drops no-SYN, no-ACK non-RST input before allocating a child.
    //# This should not be reached. Drop the segment and return.
    pub fn input_with_ipv4_options(
        &mut self,
        now: Instant,
        ip: IpMetadata,
        traffic_class: u8,
        options: Ipv4Options,
        bytes: &[u8],
    ) -> Result<InputDisposition, EndpointError> {
        self.input_with_timestamps(
            now,
            ip,
            traffic_class,
            options,
            bytes,
            RxPacketTimestamps::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn input_with_timestamps(
        &mut self,
        now: Instant,
        ip: IpMetadata,
        traffic_class: u8,
        options: Ipv4Options,
        bytes: &[u8],
        timestamps: RxPacketTimestamps,
    ) -> Result<InputDisposition, EndpointError> {
        self.input_with_metadata(
            now,
            ip,
            traffic_class,
            options,
            bytes,
            crate::RxPacketMetadata {
                timestamps,
                ..Default::default()
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn input_with_metadata(
        &mut self,
        now: Instant,
        ip: IpMetadata,
        traffic_class: u8,
        options: Ipv4Options,
        bytes: &[u8],
        metadata: crate::RxPacketMetadata,
    ) -> Result<InputDisposition, EndpointError> {
        self.input_scoped(now, ip, None, traffic_class, options, bytes, metadata)
    }

    // Input whose tuple is scoped by `zone` (the arrival link of a scoped
    // managed input; raw input is unscoped).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn input_scoped(
        &mut self,
        now: Instant,
        ip: IpMetadata,
        zone: Option<ntcp_path::LinkId>,
        traffic_class: u8,
        options: Ipv4Options,
        bytes: &[u8],
        metadata: crate::RxPacketMetadata,
    ) -> Result<InputDisposition, EndpointError> {
        let Some((route, segment)) = self.ingress_admission(ip, zone, options, bytes, metadata)? else {
            return Ok(InputDisposition::Dropped);
        };
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.1
        //# A passive OPEN call with a specified "local IP address" parameter
        //# will await an incoming connection request to that address.  If the
        //# parameter is unspecified, a passive OPEN will await an incoming
        //# connection request to any local IP address and then bind the local IP
        //# address of the connection to the particular address that is used.
        let tuple = Tuple {
            local: SocketAddr::new(ip.destination, segment.header.destination_port),
            remote: SocketAddr::new(ip.source, segment.header.source_port),
        };
        let tuple = ScopedTuple { tuple, zone };
        let target = self.lookup(tuple);
        self.input_admitted(
            now,
            ip,
            tuple,
            target,
            traffic_class,
            options,
            route,
            &segment,
            metadata,
        )
    }

    // `input_scoped` of a segment `ingress_admission` admitted, for `tuple`,
    // whose connection slot or TIME-WAIT record (if any) is `target`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn input_admitted(
        &mut self,
        now: Instant,
        ip: IpMetadata,
        tuple: ScopedTuple,
        target: Option<Target>,
        traffic_class: u8,
        options: Ipv4Options,
        route: Option<SourceRoute>,
        segment: &wire::Segment<'_>,
        metadata: crate::RxPacketMetadata,
    ) -> Result<InputDisposition, EndpointError> {
        let timestamps = metadata.timestamps;
        let zone = tuple.zone;
        if let Some(Target::Connection(index)) = target
            && self.is_output_reserved(self.id(index))
        {
            return Err(EndpointError::OutputReserved);
        }
        self.clock(now)?;
        if let Some(Target::TimeWait(index)) = target {
            //= https://www.rfc-editor.org/rfc/rfc6191#section-2
            //= reason=Only a SYN without ACK or RST to a TIME-WAIT connection reaches reopen_time_wait, whose reuse_syn freshness uses both the incoming sequence number and its Timestamps option when present. Reuse enabled versus disabled leaves results, state, resources, deadlines and emitted bytes identical in CLOSED, LISTEN, SYN-SENT, SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1/2, CLOSE-WAIT, LAST-ACK and CLOSING across flag, checksum, timestamp and sequence variants.
            //# The following paragraphs summarize the processing of SYN segments
            //# received for connections in the TIME-WAIT state. The processing of SYN
            //# segments received for connections in all other states is unchanged. Both
            //# the ISN (Initial Sequence Number) and the Timestamps option (if present)
            //# of the incoming SYN segment are included in the heuristics performed for
            //# allowing a high connection-establishment rate.
            if self.config.reuse_time_wait
                && segment.header.flags & (SYN | ACK | RST) == SYN
                && let Some(disposition) = self.reopen_time_wait(
                    Target::TimeWait(index),
                    tuple,
                    traffic_class,
                    options,
                    segment,
                    timestamps,
                )?
            {
                return Ok(disposition);
            }
            let record = self.time_wait.record_mut(index);
            let deadline = record.deadline;
            match record.input(now, segment, &self.config.connection) {
                crate::time_wait::Input::Reset => self.remove_time_wait(index),
                crate::time_wait::Input::Kept => {
                    let restarted = self.time_wait.record(index).deadline != deadline;
                    self.time_wait.update(index, restarted);
                }
            }
            return Ok(InputDisposition::Processed);
        }
        if let Some(Target::Connection(index)) = target {
            let slot = self.slots[index].as_ref().unwrap();
            // A connection keeps its tuple only until its terminal reset is
            // generated (`poll_transmit`), then is unmapped: Linux sends that
            // reset from tcp_close itself (tcp_send_active_reset) and keeps
            // nothing of the tuple after it.
            if slot.connection.reset_pending() {
                return Ok(InputDisposition::Dropped);
            }
            // Apply freshness to the same connection requests accepted by the
            // passive factory, including SYN data and auxiliary control flags.
            //= https://www.rfc-editor.org/rfc/rfc6191#section-2
            //= reason=Only a SYN without ACK or RST to a TIME-WAIT connection reaches reopen_time_wait, whose reuse_syn freshness uses both the incoming sequence number and its Timestamps option when present. Reuse enabled versus disabled leaves results, state, resources, deadlines and emitted bytes identical in CLOSED, LISTEN, SYN-SENT, SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1/2, CLOSE-WAIT, LAST-ACK and CLOSING across flag, checksum, timestamp and sequence variants.
            //# The following paragraphs summarize the processing of SYN segments
            //# received for connections in the TIME-WAIT state. The processing of SYN
            //# segments received for connections in all other states is unchanged. Both
            //# the ISN (Initial Sequence Number) and the Timestamps option (if present)
            //# of the incoming SYN segment are included in the heuristics performed for
            //# allowing a high connection-establishment rate.
            if self.config.reuse_time_wait
                && slot.connection.state() == State::TimeWait
                && segment.header.flags & (SYN | ACK | RST) == SYN
                && let Some(disposition) = self.reopen_time_wait(
                    Target::Connection(index),
                    tuple,
                    traffic_class,
                    options,
                    segment,
                    timestamps,
                )?
            {
                return Ok(disposition);
            }
            let slot = self.slots[index].as_ref().unwrap();
            let authority = slot.receive_authority.filter(|_| {
                slot.connection.state() == State::SynSent
                    && segment.header.flags & (SYN | ACK | RST) == SYN
            });
            // An unaccepted child yet to join its listener's accept queue
            // completes its handshake only if the queue has room.
            let hold = slot
                .listener
                .filter(|_| !slot.accepted_ready)
                .is_some_and(|parent| {
                    self.listener(parent)
                        .is_ok_and(|listener| listener.accept_queue_full())
                });
            let authorization =
                authority.map(|id| self.crossing_syn_authorization(id, tuple, segment));
            let slot = self.slots[index].as_mut().unwrap();
            slot.connection.hold_establishment = hold;
            slot.received_dscp = Some(traffic_class >> 2);
            let admitted = if let Some(authorization) = authorization {
                slot.connection.input_with_receive_authorization(
                    now,
                    traffic_class,
                    segment,
                    metadata,
                    Some(authorization),
                )?
            } else {
                slot.connection
                    .input_with_metadata(now, traffic_class, segment, metadata)?;
                false
            };
            if admitted {
                slot.fast_open_owner = authority;
            }
            if slot.connection.accepted_metadata {
                Self::save_ipv4_options(slot, options, route);
            }
            slot.connection.hold_establishment = false;
            // Linux counts it at tcp_v4_syn_recv_sock's exit_overflow.
            let held = core::mem::take(&mut slot.connection.establishment_held);
            if held {
                self.count_listen_drop(true);
            }
            self.refresh(index);
            return Ok(if held {
                InputDisposition::Dropped
            } else {
                InputDisposition::Processed
            });
        }
        if let Some(listener) = self.match_listener(tuple.tuple.local, zone) {
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.2
            //# An incoming RST should be ignored.  Return.
            if segment.header.flags & RST != 0 {
                return Ok(InputDisposition::Dropped);
            }
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.2
            //# Any acknowledgment is bad if it arrives on a connection still
            //# in the LISTEN state.  An acceptable reset segment should be
            //# formed for any arriving ACK-bearing segment.
            if segment.header.flags & ACK != 0 {
                self.reset_for(ip, zone, segment, route);
                return Ok(InputDisposition::Processed);
            }
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.2
            //# Drop the segment and return.
            if segment.header.flags & SYN == 0 {
                return Ok(InputDisposition::Dropped);
            }
            if let Some(refusal) = self.passive_refusal(now, None, listener, tuple, segment) {
                if refusal != PassiveRefusal::Invalid {
                    self.count_listen_drop(refusal == PassiveRefusal::AcceptQueue);
                    self.memory_refused_opens += u64::from(refusal == PassiveRefusal::Memory);
                }
                return Ok(InputDisposition::Dropped);
            }
            let record = self.listeners[listener.slot].as_ref().unwrap();
            let application_timeout = record.application_timeout_us;
            let handshake_retransmission_limit = record.handshake_retransmission_limit;
            let buffer_capacities = record.buffer_capacities;
            let buffer_locks = record.buffer_locks;
            let rx_ranges = record.rx_timestamp_capacity;
            let iss = self.isn(tuple);
            let mut connection = match self.new_connection_with_buffers(
                tuple.tuple,
                iss,
                Some(segment),
                buffer_capacities,
                buffer_locks,
                rx_ranges,
                timestamps,
            ) {
                Ok(connection) => connection,
                Err(Error::NoMemory) => {
                    self.count_listen_drop(false);
                    return Ok(InputDisposition::Dropped);
                }
                Err(error) => return Err(error.into()),
            };
            connection.set_handshake_retransmission_limit(handshake_retransmission_limit);
            if let Err(error) = connection.set_application_timeout(application_timeout) {
                self.recycle_connection(connection);
                return Err(error.into());
            }
            match self.insert(connection, Some(listener), None) {
                Ok(id) => {
                    let slot = self.slots[id.slot].as_mut().unwrap();
                    slot.received_dscp = Some(traffic_class >> 2);
                    Self::save_ipv4_options(slot, options, route);
                    return Ok(InputDisposition::Processed);
                }
                Err(EndpointError::LimitReached) => {
                    self.count_listen_drop(false);
                    return Ok(InputDisposition::Dropped);
                }
                Err(error) => return Err(error),
            }
        }
        self.reset_for(ip, zone, segment, route);
        Ok(InputDisposition::Dropped)
    }

    /// Non-constructing wire, address and received-route admission shared by
    /// raw and managed input. A managed factory runs this before preparing
    /// path authority, so input this Endpoint silently discards can neither
    /// consume a provider transaction nor surface as an embedding error.
    /// `Ok(None)` is the ordinary discard.
    pub(crate) fn ingress_admission<'a>(
        &mut self,
        ip: IpMetadata,
        zone: Option<ntcp_path::LinkId>,
        options: Ipv4Options,
        bytes: &'a [u8],
        metadata: crate::RxPacketMetadata,
    ) -> Result<Option<(Option<SourceRoute>, wire::Segment<'a>)>, EndpointError> {
        metadata
            .timestamps
            .validate(self.config.connection.timebase)?;
        if !options.is_empty()
            // Disabled IPv4 options refuse source routes only; RR, Timestamp
            // and unknown options are retained as metadata (RFC 1122 3.2.1.8).
            && ((!self.config.ipv4_options_enabled && options.has_source_route())
                || !ip.source.is_ipv4()
                || !ip.destination.is_ipv4())
        {
            return Ok(None);
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.3
        //= reason=Base checks are unconditional; directed broadcasts and local ownership use the required policy bound to one ingress network context.
        //# |  An incoming SYN with an invalid source address MUST be ignored
        //# |  either by TCP or by the IP layer [(MUST-63)] (see
        //# |  Section 3.2.1.3).

        // Scoped to the required ingress-context policy; no subnet is inferred.
        // Jumbo-link TCP is not supported by this endpoint profile.
        if bytes.len() > u16::MAX as usize
            || !valid_address(ip.source)
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.3
            //= reason=Base checks are unconditional; directed broadcasts and local ownership use the required policy bound to one ingress network context.
            //# |
            //# |  A TCP implementation MUST silently discard an incoming SYN segment
            //# |  that is addressed to a broadcast or multicast address [(MUST-57)].

            // Scoped to the required ingress-context policy; no subnet is inferred.
            || !valid_address(ip.destination)
            || ip.source.is_ipv4() != ip.destination.is_ipv4()
            // Managed path authority needs a zone for an IPv6 link-local
            // address (RFC 4007): input without its arrival link is
            // unsupported here rather than an authority failure.
            || (self.managed_context.is_some()
                && (unzoned_link_local(ip.source) || unzoned_link_local(ip.destination))
                && zone.is_none())
            || !(self.address_policy)(AddressValidation::Incoming {
                source: ip.source, destination: ip.destination,
            })
        {
            return Ok(None);
        }
        let route = match ip.source {
            IpAddr::V4(source) => options.return_route(source),
            _ => None,
        };
        if route.is_some_and(|r| !self.admits_return_route(ip.destination, ip.source, &r)) {
            return Ok(None);
        }
        let segment = if metadata.tcp_checksum_verified {
            wire::parse_unchecked(ip, bytes)
        } else {
            wire::parse(ip, bytes)
        };
        let segment = match segment {
            Ok(segment) => segment,
            Err(error) => {
                self.checksum_errors += u64::from(error == wire::WireError::InvalidChecksum);
                return Ok(None);
            }
        };
        metadata.validate_segment(&segment)?;
        Ok(Some((route, segment)))
    }

    /// Non-constructing passive factory admission shared by the listener and
    /// TIME-WAIT reuse factories and by the managed pre-check: backlog,
    /// transport resources and, for reuse, the old record's reset/freshness
    /// state. A failure is the ordinary silent discard.
    pub(crate) fn passive_room(
        &self,
        now: Instant,
        target: Option<Target>,
        listener: ListenerId,
        tuple: ScopedTuple,
        syn: &wire::Segment<'_>,
    ) -> bool {
        self.passive_refusal(now, target, listener, tuple, syn)
            .is_none()
    }

    // Why `passive_room` refuses a SYN. A SYN that may not reopen its
    // TIME-WAIT connection is that connection's to answer and never reaches
    // the listener's queue, as in Linux, so it is told apart first.
    fn passive_refusal(
        &self,
        now: Instant,
        target: Option<Target>,
        listener: ListenerId,
        tuple: ScopedTuple,
        syn: &wire::Segment<'_>,
    ) -> Option<PassiveRefusal> {
        let fresh = match target {
            Some(Target::Connection(index)) => {
                let slot = self.slots[index].as_ref().unwrap();
                !slot.connection.reset_pending()
                    && slot
                        .connection
                        .reuse_syn(now, syn, self.new_connection_timestamps())
            }
            Some(Target::TimeWait(index)) => {
                self.time_wait
                    .record(index)
                    .reuse_syn(now, syn, self.new_connection_timestamps())
            }
            None => true,
        };
        if !fresh {
            return Some(PassiveRefusal::TimeWait);
        }
        let record = self.listeners[listener.slot].as_ref().unwrap();
        // In Linux's order (tcp_conn_request): the SYN queue, which a SYN
        // reopening a TIME-WAIT skips, then the accept queue. Without SYN
        // cookies a full SYN queue drops the SYN, as Linux's does with
        // tcp_syncookies=0 (TCPReqQFullDrop); Linux's default,
        // tcp_syncookies=1, answers it with a cookie SYN-ACK instead.
        if target.is_none() && record.syn_queue_full() {
            return Some(PassiveRefusal::SynQueue);
        }
        if record.accept_queue_full() {
            return Some(PassiveRefusal::AcceptQueue);
        }
        match target {
            None => match self.resource_admission(tuple, record.buffer_capacities) {
                Ok(()) => None,
                Err(EndpointError::LimitReached) => Some(PassiveRefusal::Resources),
                Err(EndpointError::Connection(Error::NoMemory)) => Some(PassiveRefusal::Memory),
                Err(_) => Some(PassiveRefusal::Invalid),
            },
            Some(_) => self
                .room_for(record.buffer_capacities.1)
                .err()
                .map(|error| {
                    if error == Error::NoMemory.into() {
                        PassiveRefusal::Memory
                    } else {
                        PassiveRefusal::Resources
                    }
                }),
        }
    }

    // A SYN, or the last ACK of a handshake, a listener took and dropped
    // (`listen_drops`), one refused for its full accept queue also an
    // overflow (`listen_overflows`).
    fn count_listen_drop(&mut self, overflow: bool) {
        self.listen_overflows += u64::from(overflow);
        self.listen_drops += 1;
    }

    // RFC 9293 section 3.6.1 MAY-2 is recorded as an exception: the new
    // incarnation's ISN follows the old one's (reuse_iss), but the old
    // TIME-WAIT ends when the new connection takes the tuple, as in Linux,
    // and nothing returns to it if the SYN was an old duplicate.
    //
    // `None` leaves the SYN to the TIME-WAIT, which answers it as it does
    // any SYN, with its challenge ACK: a SYN that is not fresh, or finds no
    // listener. Linux does the same (tcp_timewait_state_process returns
    // TCP_TW_ACK_OOW for the first, and tcp_v4_rcv's TCP_TW_SYN falls through
    // to the timewait ACK for the second), where RFC 6191 drops the SYN
    // silently; duvet/rfc6191-todos.toml records that exception.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.6.1
    //# This algorithm for reducing TIME-WAIT is a Best
    //# Current Practice that SHOULD be implemented since Timestamp Options
    //# are commonly used, and using them to reduce TIME-WAIT provides
    //# benefits for busy Internet servers (SHLD-4).
    //= https://www.rfc-editor.org/rfc/rfc6191#section-2
    //= reason=Freshness applies to passive SYN requests with or without payload; the ordinary factory independently enforces early-data authorization and resource admission.
    //# * If TCP Timestamps would be enabled for the new incarnation of the
    //# connection, and the timestamp contained in the incoming SYN segment is
    //# greater than the last timestamp seen on the previous incarnation of the
    //# connection (for that direction of the data transfer), honor the
    //# connection request (creating a connection in the SYN-RECEIVED state).
    //= https://www.rfc-editor.org/rfc/rfc6191#section-2
    //= reason=New bilateral timestamps admit the request independently of sequence when the old incarnation did not negotiate timestamps.
    //# * If TCP Timestamps would be enabled for the new incarnation of the
    //# connection, honor the incoming connection request (creating a connection
    //# in the SYN-RECEIVED state).
    //= https://www.rfc-editor.org/rfc/rfc6191#section-4
    //= reason=Newer bilateral timestamps admit older ISNs for empty and data-bearing requests; equal timestamps still require a sequence strictly after the peer FIN.
    //# An implementation of the mechanism proposed in this document would
    //# enable recycling of the TIME-WAIT state even in the presence of ISNs
    //# that are not monotonically increasing across connections, except when
    //# the timestamp contained in the incoming SYN is equal to the last
    //# timestamp seen on the connection in the TIME-WAIT state (for that
    //# direction of the data transfer).
    fn reopen_time_wait(
        &mut self,
        target: Target,
        scoped: ScopedTuple,
        traffic_class: u8,
        options: Ipv4Options,
        syn: &wire::Segment<'_>,
        timestamps: RxPacketTimestamps,
    ) -> Result<Option<InputDisposition>, EndpointError> {
        let tuple = scoped.tuple;
        let Some(listener) = self.match_listener(tuple.local, scoped.zone) else {
            return Ok(None);
        };
        match self.passive_refusal(self.now, Some(target), listener, scoped, syn) {
            Some(PassiveRefusal::TimeWait) => return Ok(None),
            Some(refusal) => {
                self.count_listen_drop(refusal == PassiveRefusal::AcceptQueue);
                self.memory_refused_opens += u64::from(refusal == PassiveRefusal::Memory);
                return Ok(Some(InputDisposition::Dropped));
            }
            None => {}
        }
        // Past the SYN queue's bound, the child needs room of its own among
        // the listener's children.
        if self.listeners[listener.slot]
            .as_mut()
            .unwrap()
            .children
            .try_reserve(1)
            .is_err()
        {
            self.count_listen_drop(false);
            return Ok(Some(InputDisposition::Dropped));
        }
        let record = self.listeners[listener.slot].as_ref().unwrap();
        let application_timeout = record.application_timeout_us;
        let handshake_retransmission_limit = record.handshake_retransmission_limit;
        let buffer_capacities = record.buffer_capacities;
        let buffer_locks = record.buffer_locks;
        let rx_ranges = record.rx_timestamp_capacity;
        let candidate = self.isn(scoped);
        let (iss, offset) = match target {
            Target::Connection(index) => {
                let old = &self.slots[index].as_ref().unwrap().connection;
                (old.reuse_iss(candidate), old.timestamp_offset())
            }
            Target::TimeWait(index) => {
                let old = self.time_wait.record(index);
                (old.reuse_iss(candidate), old.timestamp_offset)
            }
        };
        // Allocate the entire bounded child before transferring tuple ownership.
        // The old incarnation keeps TIME-WAIT until the child takes its tuple.
        let mut connection = match self.new_connection_with_buffers(
            tuple,
            iss,
            Some(syn),
            buffer_capacities,
            buffer_locks,
            rx_ranges,
            timestamps,
        ) {
            Ok(connection) => connection,
            Err(Error::NoMemory) => {
                self.count_listen_drop(false);
                return Ok(Some(InputDisposition::Dropped));
            }
            Err(error) => return Err(error.into()),
        };
        // Reuse keeps the old local virtual clock: peer PAWS must not see a
        // random jump. Candidate failure leaves the old offset/timer untouched.
        connection.set_timestamp_offset(offset);
        connection.set_handshake_retransmission_limit(handshake_retransmission_limit);
        if let Err(error) = connection.set_application_timeout(application_timeout) {
            self.recycle_connection(connection);
            return Err(error.into());
        }
        let id = self.insert(connection, Some(listener), Some(target))?;
        let slot = self.slots[id.slot].as_mut().unwrap();
        slot.received_dscp = Some(traffic_class >> 2);
        // Input validated the route before selecting the TIME-WAIT reuse path.
        let route = match tuple.remote.ip() {
            IpAddr::V4(source) => options.return_route(source),
            _ => None,
        };
        Self::save_ipv4_options(slot, options, route);
        Ok(Some(InputDisposition::Processed))
    }

    fn prepare_write_metadata(
        &mut self,
        id: ConnectionId,
        len: usize,
        lowat: Option<u32>,
        timestamp: Option<TxTimestampRequest>,
    ) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        let connection = &self.slot(id)?.connection;
        let own_charge = connection.buffer_charge();
        let available = self
            .send_growth_room(connection, own_charge)
            .saturating_add(own_charge);
        let before = self.budget.allocated();
        let refused = self
            .slot_mut(id)?
            .connection
            .prepare_send_storage(len, lowat, available, timestamp);
        // Charged even when refused: a send ring that grew before the other
        // failed keeps its storage.
        let charge = self.slot(id)?.connection.buffer_charge();
        self.recharge(own_charge, charge);
        if let Some(wanted) = refused? {
            // As __sk_mem_raise_allocated, the allocation tried enters
            // pressure if it passes the threshold, refused or not, and a
            // suppressed send allocation moderates the send limit.
            let memory = self.memory();
            self.budget
                .attempted(before.saturating_add(wanted), self.now, memory);
            if self.budget.under_pressure() {
                self.slot_mut(id)?.connection.moderate_send();
            }
            self.memory_throttled(id.slot);
        } else if !self.slot(id)?.connection.send_memory_throttled() {
            self.stop_memory_wait(id.slot);
        }
        Ok(())
    }

    // What `connection`, charged `charge`, may add to the budget for its send
    // storage, after Linux's __sk_mem_raise_allocated: what the hard cap
    // leaves, except that a tuned send direction which holds at least its
    // floor and its fair share of the cap (charge · live connections ≥ cap)
    // may not pass the pressure threshold, and under pressure may not grow.
    // A fixed (untuned) direction is held to the hard cap alone.
    fn send_growth_room(&self, connection: &Connection, charge: usize) -> usize {
        self.growth_room(
            connection.send_tuned() && !connection.send_below_min(),
            charge,
        )
    }

    // The same for a tuned receive ring's growth (DRS): Linux applies one
    // rule to SK_MEM_RECV, with tcp_rmem[0] as the floor.
    fn receive_growth_room(&self, connection: &Connection, charge: usize) -> usize {
        self.growth_room(!connection.receive_below_min(), charge)
    }

    // What the hard cap leaves, and when `pressured`, Linux's limits past
    // tcp_mem[1] for a connection charged `charge` that holds its fair share.
    fn growth_room(&self, pressured: bool, charge: usize) -> usize {
        let room = self.buffer_room();
        if !pressured {
            return room;
        }
        let memory = self.memory();
        if charge.saturating_mul(self.budget.sockets()) < memory.high {
            room
        } else if self.budget.under_pressure() {
            0
        } else {
            room.min(memory.pressure.saturating_sub(self.budget.allocated()))
        }
    }

    // A write of the connection at `index` found its storage growth refused.
    // Besides the wakes that returns bring (`wake_memory_waiters`), it looks
    // again after a random delay, as Linux's sk_stream_wait_memory sleeps a
    // writer whose send buffer has room but whose memory was refused at
    // most vm_wait before it retries: what decides its growth also changes
    // without a return to wake it (the group's connections and thresholds,
    // another member's return still held in its reserve), and a wake may
    // come late. The first refusal arms it; later ones keep that deadline.
    fn memory_throttled(&mut self, index: usize) {
        self.memory_throttled_writes += 1;
        self.memory_refused_growths += 1;
        self.memory_waiters.push(index);
        if self.slots[index].as_ref().unwrap().memory_retry.is_none() {
            let retry = self.now.saturating_add(self.memory_retry_delay());
            let slot = self.slots[index].as_mut().unwrap();
            slot.memory_retry = Some(retry);
            // A write refused whole refreshes nothing.
            self.deadlines.set(index, slot.deadline());
        }
        // A member of shared buffer memory flags its waiters for the others
        // to wake it, then looks for memory they returned meanwhile.
        self.budget.set_waiting(true);
        if self.budget.poll_returns() {
            self.wake_memory_waiters();
        }
    }

    // Memory came back to the budget. As Linux's sk_stream_write_space
    // wakes a writer once sk_stream_memory_free holds again, wake the
    // connections whose writes were refused, oldest first, while the growth
    // each needed fits what is free, each counted against it so that one
    // release does not wake more than it can feed. The first that does not
    // fit ends the wake and moves to the end, so that a connection wanting
    // more than is ever free holds up no other: a wake visits the
    // connections it wakes and one more. A woken connection that finds less
    // than it needed is refused again and waits at the end.
    // Under pressure, a connection whose growth the pressure would refuse
    // (`send_growth_room`) does not fit: it waits for pressure to end.
    fn wake_memory_waiters(&mut self) {
        let mut room = self.buffer_room();
        loop {
            let Some(index) = self.memory_waiters.iter().next() else {
                self.budget.set_waiting(false);
                break;
            };
            self.memory_waiters.remove(index);
            // Reclaim takes a connection off the list.
            let connection = &self.slots[index].as_ref().unwrap().connection;
            let wanted = connection.send_memory_wanted().unwrap_or(0);
            let allowed = self
                .send_growth_room(connection, connection.buffer_charge())
                .min(room);
            if wanted > allowed {
                self.memory_waiters.push(index);
                break;
            }
            room -= wanted;
            let slot = self.slots[index].as_mut().unwrap();
            slot.memory_retry = None;
            slot.connection.memory_released();
            self.refresh(index);
        }
    }

    // The waiter at `index` reached its retry (`memory_throttled`): as
    // sk_stream_wait_memory returns after vm_wait for tcp_sendmsg to try
    // sk_wmem_schedule again, it is woken if the growth it wanted fits now,
    // and otherwise waits another random delay. Its caller refreshes it.
    fn retry_memory(&mut self, index: usize) {
        let slot = self.slots[index].as_ref().unwrap();
        let connection = &slot.connection;
        let wanted = connection.send_memory_wanted().unwrap_or(0);
        let allowed = self.send_growth_room(connection, connection.buffer_charge());
        if wanted > allowed {
            let retry = self.now.saturating_add(self.memory_retry_delay());
            self.slots[index].as_mut().unwrap().memory_retry = Some(retry);
            return;
        }
        self.stop_memory_wait(index);
        self.slots[index]
            .as_mut()
            .unwrap()
            .connection
            .memory_released();
    }

    // The connection at `index` waits for memory no more.
    fn stop_memory_wait(&mut self, index: usize) {
        self.memory_waiters.remove(index);
        if let Some(slot) = self.slots[index].as_mut() {
            slot.memory_retry = None;
        }
        if self.memory_waiters.is_empty() {
            self.budget.set_waiting(false);
        }
    }

    // Linux's vm_wait, get_random_u32_below(HZ / 5) + 2 jiffies: with HZ
    // 1000, 2 to 201 ms.
    fn memory_retry_delay(&mut self) -> Instant {
        use core::hash::Hasher;
        self.memory_retry_draws += 1;
        let mut hash = siphasher::sip::SipHasher13::new_with_key(&self.lookup_key);
        hash.write(b"ntcp memory retry");
        hash.write_u64(self.memory_retry_draws);
        let ms = hash.finish() % 200 + 2;
        self.config.connection.timebase.ticks_from_us(ms * 1000)
    }

    /// Admit an immutable payload prefix without copying its bytes. The caller
    /// owns the backing allocation's budget; the endpoint charges its bounded
    /// queued-byte and range metadata. Partial ACKs retain the unacknowledged
    /// range. Backend clones can outlive ACK or connection termination.
    /// A payload that continues the last one queued (`Payload::join`) extends
    /// its span. Any other takes a span of its own, and is refused with
    /// `InvalidArgument` while the connection holds MAX_SHARED_SEGMENTS, as
    /// Linux refuses more than UIO_MAXIOV buffers with EINVAL; ACKs free
    /// spans.
    pub fn write_shared(
        &mut self,
        id: ConnectionId,
        payload: crate::Payload,
        more: bool,
        end_of_record: bool,
        lowat: Option<u32>,
    ) -> Result<usize, EndpointError> {
        // A span the connection may not take grows nothing.
        if !payload.is_empty()
            && !self
                .slot(id)?
                .connection
                .admits_shared(&payload, Self::MAX_SHARED_SEGMENTS)
        {
            return Err(Error::InvalidArgument.into());
        }
        self.prepare_write_metadata(id, payload.len(), lowat, None)?;
        if !payload.is_empty() {
            let room = self.buffer_room();
            let before = self.slot(id)?.connection.buffer_charge();
            let result = self.slot_mut(id)?.connection.prepare_shared_storage(
                &payload,
                Self::MAX_SHARED_SEGMENTS,
                room,
            );
            let after = self.slot(id)?.connection.buffer_charge();
            self.recharge(before, after);
            // Span storage refused for memory admits nothing: the payload
            // waits for memory as a copied write would.
            if result == Err(Error::NoMemory) {
                self.slot_mut(id)?.connection.throttle_send(0);
                self.memory_throttled(id.slot);
                return Err(Error::WouldBlock.into());
            }
            result?;
        }
        let result =
            self.slot_mut(id)?
                .connection
                .write_shared(payload, more, end_of_record, lowat);
        self.refresh(id.slot);
        result.map_err(Into::into)
    }

    pub fn write(&mut self, id: ConnectionId, bytes: &[u8]) -> Result<usize, EndpointError> {
        self.prepare_write_metadata(id, bytes.len(), None, None)?;
        let count = self.slot_mut(id)?.connection.write(bytes)?;
        self.refresh(id.slot);
        Ok(count)
    }
    pub fn write_with_push(
        &mut self,
        id: ConnectionId,
        bytes: &[u8],
        push: bool,
    ) -> Result<usize, EndpointError> {
        self.prepare_write_metadata(id, bytes.len(), None, None)?;
        let count = self.slot_mut(id)?.connection.write_with_push(bytes, push)?;
        self.refresh(id.slot);
        Ok(count)
    }
    /// Queue accepted bytes with per-write corking and a local coalescing boundary.
    /// EOR is not TCP framing; the boundary is at the end of the accepted prefix.
    pub fn write_with_options(
        &mut self,
        id: ConnectionId,
        bytes: &[u8],
        more: bool,
        end_of_record: bool,
    ) -> Result<usize, EndpointError> {
        self.prepare_write_metadata(id, bytes.len(), None, None)?;
        let count = self
            .slot_mut(id)?
            .connection
            .write_with_options(bytes, more, end_of_record)?;
        self.refresh(id.slot);
        Ok(count)
    }

    // Finite LOWAT caps accepted bytes at LOWAT minus actual unsent bytes.
    // None and u32::MAX impose no limit beyond available send capacity.
    pub fn write_with_options_and_notsent_lowat(
        &mut self,
        id: ConnectionId,
        bytes: &[u8],
        more: bool,
        end_of_record: bool,
        lowat: Option<u32>,
    ) -> Result<usize, EndpointError> {
        self.prepare_write_metadata(id, bytes.len(), lowat, None)?;
        let count = self
            .slot_mut(id)?
            .connection
            .write_with_options_and_notsent_lowat(bytes, more, end_of_record, lowat)?;
        self.refresh(id.slot);
        Ok(count)
    }

    pub fn send_progress(&self, id: ConnectionId) -> Result<SendProgress, EndpointError> {
        Ok(self.slot(id)?.connection.send_progress())
    }

    /// Configured send buffer capacity of one connection, without sampling
    /// the rest of `transport_info`.
    pub fn send_capacity(&self, id: ConnectionId) -> Result<usize, EndpointError> {
        Ok(self.slot(id)?.connection.send_capacity())
    }

    pub fn set_rx_timestamp_capacity(
        &mut self,
        id: ConnectionId,
        ranges: usize,
    ) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        let old = self.slot(id)?.connection.rx_timestamps.storage_bytes();
        let spare = self.buffer_room();
        self.slot_mut(id)?
            .connection
            .rx_timestamps
            .resize(ranges, spare)?;
        let new = self.slot(id)?.connection.rx_timestamps.storage_bytes();
        self.recharge(old, new);
        Ok(())
    }

    pub fn rx_timestamp_status(
        &self,
        id: ConnectionId,
    ) -> Result<RxTimestampStatus, EndpointError> {
        Ok(self.slot(id)?.connection.rx_timestamps.status())
    }

    pub fn peek_rx_timestamps(
        &self,
        id: ConnectionId,
        count: usize,
    ) -> Result<Option<RxReadTimestamps>, EndpointError> {
        Ok(self.slot(id)?.connection.peek_rx_timestamps(count)?)
    }

    pub fn set_tx_timestamp_capacity(
        &mut self,
        id: ConnectionId,
        phases: usize,
    ) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        let old = self.slot(id)?.connection.tx_timestamps.storage_bytes();
        let spare = self.buffer_room();
        self.slot_mut(id)?
            .connection
            .tx_timestamps
            .resize(phases, spare)?;
        let new = self.slot(id)?.connection.tx_timestamps.storage_bytes();
        self.recharge(old, new);
        Ok(())
    }

    /// Check byte and timestamp admission before consuming an external source.
    /// The caller must not mutate the endpoint between this check and its write.
    pub fn check_write_admission(
        &self,
        id: ConnectionId,
        lowat: Option<u32>,
        request: TxTimestampRequest,
    ) -> Result<usize, EndpointError> {
        self.reject_if_output_reserved(id)?;
        Ok(self
            .slot(id)?
            .connection
            .check_write_admission(lowat, request)?)
    }

    /// Prepare bookkeeping for at most `capacity` bytes before consuming an
    /// external producer. No bytes or timestamp requests are committed here.
    /// Keep exclusive transaction ownership until the corresponding write;
    /// another intervening write can consume the checked byte/phase credit.
    pub fn prepare_write_admission(
        &mut self,
        id: ConnectionId,
        capacity: usize,
        lowat: Option<u32>,
        request: TxTimestampRequest,
    ) -> Result<usize, EndpointError> {
        self.reject_if_output_reserved(id)?;
        let room = self
            .slot(id)?
            .connection
            .check_write_retry(lowat, request)?;
        let count = capacity.min(room);
        self.prepare_write_metadata(id, count, lowat, Some(request))?;
        // Storage refused for memory admits what the allocated storage holds.
        match count.min(self.slot(id)?.connection.send_admission_room(lowat)) {
            0 => Err(Error::WouldBlock.into()),
            count => Ok(count),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn write_with_timestamp(
        &mut self,
        id: ConnectionId,
        bytes: &[u8],
        more: bool,
        end_of_record: bool,
        lowat: Option<u32>,
        request: TxTimestampRequest,
    ) -> Result<usize, EndpointError> {
        self.prepare_write_metadata(id, bytes.len(), lowat, Some(request))?;
        let count = self.slot_mut(id)?.connection.write_with_timestamp(
            bytes,
            more,
            end_of_record,
            lowat,
            request,
        )?;
        self.refresh(id.slot);
        Ok(count)
    }

    pub fn report_tx_timestamp(
        &mut self,
        token: TxTimestampToken,
        source: TxTimestampSource,
        value: u64,
        clock: TxTimestampClock,
    ) -> Result<(), EndpointError> {
        // Observations are never fed into update_time or protocol timers.
        self.slot(token.connection())?;
        if matches!(
            clock,
            TxTimestampClock::CallerTicks(_)
                | TxTimestampClock::DeviceTicks {
                    units_per_second: Some(0),
                    ..
                }
        ) {
            return Err(Error::InvalidArgument.into());
        }
        self.slots[token.connection().slot]
            .as_mut()
            .unwrap()
            .connection
            .tx_timestamps
            .observe(
                token.stream_range(),
                TxTimestampStage::Transmit,
                source,
                value,
                clock,
            );
        self.refresh(token.connection().slot);
        Ok(())
    }

    // Cancel only pending Transmit phases matching this output range and source.
    // Like report_tx_timestamp, validates the connection generation; preserves
    // recorded events, Scheduled/ACK phases, and opaque (possibly equal) cookies.
    // Reservations become Cancelled events in place and are freed only on drain.
    pub fn cancel_tx_timestamp(
        &mut self,
        token: TxTimestampToken,
        source: TxTimestampSource,
    ) -> Result<(), EndpointError> {
        self.slot_mut(token.connection())?
            .connection
            .tx_timestamps
            .cancel_transmit(token.stream_range(), source);
        self.refresh(token.connection().slot);
        Ok(())
    }

    pub fn next_tx_timestamp(
        &mut self,
        id: ConnectionId,
    ) -> Result<Option<TxTimestampEvent>, EndpointError> {
        Ok(self.slot_mut(id)?.connection.tx_timestamps.next())
    }

    // Caller-owned unique cookie: forget a superseded tentative target, including
    // recorded phases. Unlike cancellation, this does not publish events.
    pub fn discard_tx_timestamp_request(
        &mut self,
        id: ConnectionId,
        cookie: u64,
    ) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        self.slot_mut(id)?
            .connection
            .tx_timestamps
            .discard_request(cookie);
        Ok(())
    }

    /// Mark an actual blocking Fast Open writer waiting for this active handshake.
    /// Callers supply syscall context, including a Fast Open fallback with a bare SYN.
    /// The validated handshake consumes the hint; clearing it never erases ACK history.
    pub fn set_fast_open_write_pending(
        &mut self,
        id: ConnectionId,
        pending: bool,
    ) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        self.slot_mut(id)?
            .connection
            .set_fast_open_write_pending(pending)?;
        Ok(())
    }

    /// Record a blocked adapter admission without changing send boundaries.
    /// LOWAT-only exhaustion is not byte-buffer backpressure.
    pub fn record_send_backpressure(&mut self, id: ConnectionId) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        self.slot_mut(id)?.connection.record_send_backpressure();
        Ok(())
    }

    // Finalize an accepted stream prefix without writing or discarding bytes.
    // force releases queued output even under MORE/CORK, not future writes.
    pub fn finish_send(
        &mut self,
        id: ConnectionId,
        end: u64,
        more: bool,
        end_of_record: bool,
        force: bool,
    ) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        self.slot_mut(id)?
            .connection
            .finish_send(end, more, end_of_record, force);
        self.refresh(id.slot);
        Ok(())
    }

    pub fn cancel_tx_timestamps(&mut self, id: ConnectionId) -> Result<(), EndpointError> {
        // Observation cancellation changes neither selected bytes nor their
        // departure accounting. It must remain available while a reservation
        // is quarantined after an uncertain backend submission.
        self.slot_mut(id)?.connection.tx_timestamps.cancel_from(0);
        self.refresh(id.slot);
        Ok(())
    }

    /// Read-only byte admission budget under the same policy as the write API.
    pub fn send_admission_room(
        &self,
        id: ConnectionId,
        lowat: Option<u32>,
    ) -> Result<usize, EndpointError> {
        self.reject_if_output_reserved(id)?;
        Ok(self.slot(id)?.connection.send_admission_room(lowat))
    }

    /// Hold partial output until uncork, explicit NODELAY, or a 200ms timeout.
    pub fn set_cork(&mut self, id: ConnectionId, enabled: bool) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        self.slot_mut(id)?.connection.set_cork(enabled);
        self.refresh(id.slot);
        Ok(())
    }

    pub fn flush(&mut self, id: ConnectionId) -> Result<usize, EndpointError> {
        self.reject_if_output_reserved(id)?;
        let count = self.slot_mut(id)?.connection.flush()?;
        self.refresh(id.slot);
        Ok(count)
    }
    pub fn close(&mut self, id: ConnectionId) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        self.slot_mut(id)?.connection.close()?;
        self.refresh(id.slot);
        Ok(())
    }
    pub fn write_urgent(&mut self, id: ConnectionId, bytes: &[u8]) -> Result<usize, EndpointError> {
        self.prepare_write_metadata(id, bytes.len(), None, None)?;
        let count = self.slot_mut(id)?.connection.write_urgent(bytes)?;
        self.refresh(id.slot);
        Ok(count)
    }
    // Inspect accepted contiguous bytes without consuming receive credit or
    // scheduling output. Terminal eligibility matches read_terminal.
    pub fn peek(&self, id: ConnectionId, out: &mut [u8]) -> Result<usize, EndpointError> {
        Ok(self.slot(id)?.connection.peek(out)?)
    }
    pub fn peek_terminal(&self, id: ConnectionId, out: &mut [u8]) -> Result<usize, EndpointError> {
        Ok(self.slot(id)?.connection.peek_terminal(out)?)
    }

    pub fn read(&mut self, id: ConnectionId, out: &mut [u8]) -> Result<usize, EndpointError> {
        self.reject_if_output_reserved(id)?;
        let connection = &mut self.slot_mut(id)?.connection;
        let count = connection.read(out)?;
        if connection.receive_tuned()
            && let Some(target) = connection.receive_space_adjust()
        {
            self.grow_receive(id, target);
        }
        self.refresh(id.slot);
        Ok(count)
    }

    // DRS asks the receive ring of `id` to grow to `target` bytes. As
    // Linux's __sk_mem_raise_allocated for SK_MEM_RECV, the growth's peak
    // charge must fit the room `receive_growth_room` gives; a refused one
    // is counted, enters pressure if it would have passed the threshold,
    // and leaves the window as it is until the next RTT's measure.
    #[cold]
    #[inline(never)]
    fn grow_receive(&mut self, id: ConnectionId, target: usize) {
        let connection = &self.slots[id.slot].as_ref().unwrap().connection;
        let own = connection.buffer_charge();
        let room = self.receive_growth_room(connection, own);
        let growth = connection
            .receive_growth_peak(target)
            .map_or(usize::MAX, |peak| peak - own);
        let grown = growth <= room
            && self.slots[id.slot]
                .as_mut()
                .unwrap()
                .connection
                .grow_receive(target)
                .is_ok();
        // Charged even when refused: a bitmap that grew before another
        // failed keeps its storage.
        let charge = self.slots[id.slot]
            .as_ref()
            .unwrap()
            .connection
            .buffer_charge();
        let before = self.budget.allocated();
        self.recharge(own, charge);
        if !grown {
            self.memory_refused_growths += 1;
            let memory = self.memory();
            self.budget
                .attempted(before.saturating_add(growth), self.now, memory);
        }
    }
    // Socket adapters may drain accepted bytes after CLOSED; the normal read
    // contract remains unchanged. Eligibility excludes unfinished handshakes
    // and discarded receive sides, and draining schedules no network output.
    pub fn read_terminal(
        &mut self,
        id: ConnectionId,
        out: &mut [u8],
    ) -> Result<usize, EndpointError> {
        self.reject_if_output_reserved(id)?;
        Ok(self.slot_mut(id)?.connection.read_terminal(out)?)
    }

    // Count only bytes eligible for terminal draining.
    pub fn terminal_readable_bytes(&self, id: ConnectionId) -> Result<usize, EndpointError> {
        Ok(self.slot(id)?.connection.terminal_readable_bytes())
    }

    pub fn shutdown(&mut self, id: ConnectionId) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        self.slot_mut(id)?.connection.shutdown()?;
        self.refresh(id.slot);
        Ok(())
    }
    //= https://www.rfc-editor.org/rfc/rfc6429#section-1
    //# This guidance is not intended to preclude resource management by the
    //# operating system or application, which may request that connections be
    //# aborted regardless of whether or not they are in the persist condition.
    //# The TCP implementation needs to, of course, comply by aborting such
    //# connections.
    //= https://www.rfc-editor.org/rfc/rfc6429#section-2
    //# Clearly, a system needs to be robust to such attacks and allow
    //# connections in the persist condition to be aborted in the same way as
    //# any other connection.
    //= https://www.rfc-editor.org/rfc/rfc6429#section-4
    //# Though unstated in RFC 1122, but implicit for system robustness, a TCP
    //# implementation needs to allow connections in the ZWP or persist
    //# condition to be closed or aborted by their applications or other
    //# resource management routines in the operating system.
    pub fn abort(&mut self, id: ConnectionId) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        self.slot_mut(id)?.connection.abort();
        self.refresh(id.slot);
        Ok(())
    }
    pub fn set_nagle(&mut self, id: ConnectionId, enabled: bool) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        self.slot_mut(id)?.connection.set_nagle(enabled);
        self.refresh(id.slot);
        Ok(())
    }
    // The adapter validates the outer ICMP message and quoted IP tuple first.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
    //# TCP implementations MUST act on an ICMP error message passed up from
    //# the IP layer, directing it to the connection that created the error
    //# (MUST-54).

    // Traceability limitation: The adapter must validate and classify the outer ICMP
    // message; the TUN example does not implement ICMP.
    pub fn network_error(
        &mut self,
        now: Instant,
        tuple: Tuple,
        quoted_sequence: u32,
        error: crate::NetworkError,
    ) -> Result<bool, EndpointError> {
        let tuple = ScopedTuple::unscoped(tuple);
        let Some(index) = self.tuples.find(self.hash(tuple), tuple) else {
            return Ok(false);
        };
        self.reject_if_output_reserved(self.id(index))?;
        self.clock(now)?;
        if error == crate::NetworkError::SourceQuench {
            return Ok(false);
        }
        self.deliver_network_error(index, now, quoted_sequence, error)
    }
    // Shared by the tuple-routed and the Host-correlated entrypoints, after
    // reservation and clock checks.
    fn deliver_network_error(
        &mut self,
        index: usize,
        now: Instant,
        quoted_sequence: u32,
        error: crate::NetworkError,
    ) -> Result<bool, EndpointError> {
        let tuple = self.slots[index].as_ref().unwrap().connection.tuple();
        let listener = self.slots[index].as_ref().unwrap().listener;
        if self.config.error_reports
            && listener.is_some()
            && self.passive_errors.len() == self.config.max_connections
        {
            return Err(EndpointError::LimitReached);
        }
        let accepted = self.slots[index]
            .as_mut()
            .unwrap()
            .connection
            .network_error(now, quoted_sequence, error)?;
        if accepted
            && self.config.error_reports
            && let Some(listener) = listener
        {
            self.passive_errors.push_back(Event::PassiveError {
                listener,
                tuple,
                error,
            });
        }
        self.refresh(index);
        Ok(accepted)
    }
    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.2
    //= reason=Endpoint routes the quoted outbound tuple to its connection-local path. IPv6-capable core dispatch only; no IPv6 native socket or shared route-cache claim.
    //# When a Packet Too Big message is received, the node determines which path the
    //# message applies to based on the contents of the Packet Too Big message.
    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.2
    //= reason=Endpoint::pmtu_feedback dispatches the decoded quoted outbound tuple to its connection-local path. IPv6 base-header test from 819b8f2 rejects wrong quoted source/destination addresses and ports and isolates accepted 1280/1400 updates across two distinct local addresses. This does not establish same-address per-interface isolation, Routing Header interpretation or native IPv6 sockets.
    //# When a Packet Too Big message is received, the node determines which path the
    //# message applies to based on the contents of the Packet Too Big message. For
    //# example, if the destination address is used as the local representation of a
    //# path, the destination address from the original packet would be used to
    //# determine which path the message applies to.

    /// Uncorrelated Packet Too Big for the quoted tuple, validated against the
    /// connection's exact recent-transmission ring (start, header and size),
    /// family floors and a candidate below the submitted size. `true` means
    /// accepted as a notification that the quoted transmission was dropped,
    /// not that the estimate decreased: a nondecreasing accepted report
    /// leaves the estimate unchanged.
    pub fn pmtu_feedback(
        &mut self,
        now: Instant,
        tuple: Tuple,
        quoted_sequence: u32,
        ip_packet_len: u32,
        ip_header_len: u16,
        candidate_mtu: u32,
    ) -> Result<bool, EndpointError> {
        let tuple = ScopedTuple::unscoped(tuple);
        let Some(index) = self.tuples.find(self.hash(tuple), tuple) else {
            return Ok(false);
        };
        self.reject_if_output_reserved(self.id(index))?;
        self.clock(now)?;
        let accepted = self.slots[index]
            .as_mut()
            .unwrap()
            .connection
            .pmtu_feedback(
                now,
                quoted_sequence,
                ip_packet_len,
                ip_header_len,
                candidate_mtu,
            )?;
        self.refresh(index);
        Ok(accepted)
    }

    pub fn set_pmtud_policy(
        &mut self,
        now: Instant,
        id: ConnectionId,
        policy: crate::PmtudPolicy,
    ) -> Result<(), EndpointError> {
        // Existing authorized policy repair changes search aging, not selected bytes.
        self.slot(id)?
            .connection
            .validate_pmtud_policy(now, policy)?;
        self.clock(now)?;
        self.slot_mut(id)?
            .connection
            .set_pmtud_policy(now, policy)?;
        self.refresh(id.slot);
        Ok(())
    }

    /// Read-only: whether `set_search_aging(now, id, aging)` succeeds now
    /// (live connection with PLPMTUD, monotonic time, aging of at least 300
    /// seconds or infinity representable in the caller timebase).
    pub fn validate_search_aging(
        &self,
        now: Instant,
        id: ConnectionId,
        aging: crate::SearchAging,
    ) -> Result<(), EndpointError> {
        self.check_clock(now)?;
        let connection = &self.slot(id)?.connection;
        let policy = connection.pmtud_policy().ok_or(Error::InvalidArgument)?;
        connection.validate_pmtud_policy(
            now,
            crate::PmtudPolicy {
                search_aging: aging,
                ..policy
            },
        )?;
        Ok(())
    }

    /// One connection's current PLPMTUD policy; None without PLPMTUD.
    pub fn pmtud_policy(&self, id: ConnectionId) -> Result<Option<crate::PmtudPolicy>, EndpointError> {
        Ok(self.slot(id)?.connection.pmtud_policy())
    }

    /// Change only the RFC 4821 section 7.3 search aging of one connection,
    /// keeping its plateau table; mandatory PTB holds and failure cooldowns
    /// are independent and unchanged.
    pub fn set_search_aging(
        &mut self,
        now: Instant,
        id: ConnectionId,
        aging: crate::SearchAging,
    ) -> Result<(), EndpointError> {
        let policy = self
            .slot(id)?
            .connection
            .pmtud_policy()
            .ok_or(Error::InvalidArgument)?;
        self.set_pmtud_policy(
            now,
            id,
            crate::PmtudPolicy {
                search_aging: aging,
                ..policy
            },
        )
    }

    /// Change one connection's administrative MTU ceiling on the same path.
    /// None removes this ceiling, still respecting interface/peer/allocation
    /// limits and network-discovered evidence. Does not signal a new path,
    /// change the endpoint template, or raise effective MTU without an ACK.
    /// Prepared scalar output must be resolved by the caller first.
    pub fn set_route_mtu(
        &mut self,
        now: Instant,
        id: ConnectionId,
        mtu: Option<u32>,
    ) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        self.slot(id)?.connection.validate_route_mtu(now, mtu)?;
        self.clock(now)?;
        self.slot_mut(id)?.connection.set_route_mtu(now, mtu)?;
        self.refresh(id.slot);
        Ok(())
    }

    pub fn set_first_hop_mtu(
        &mut self,
        now: Instant,
        id: ConnectionId,
        mtu: u32,
    ) -> Result<(), EndpointError> {
        self.slot(id)?.connection.validate_first_hop_mtu(now, mtu)?;
        self.clock(now)?;
        if self.is_output_reserved(id) {
            self.slot_mut(id)?
                .connection
                .set_reserved_first_hop_mtu(now, mtu)?;
        } else {
            self.slot_mut(id)?.connection.set_first_hop_mtu(now, mtu)?;
        }
        self.refresh(id.slot);
        Ok(())
    }

    pub fn set_endpoint_first_hop_mtu(
        &mut self,
        now: Instant,
        mtu: u32,
    ) -> Result<(), EndpointError> {
        if self.config.connection.pmtud.is_none()
            || !(68..=65575).contains(&mtu)
            || mtu > 65535
                && (self.listeners.iter().flatten().any(|l| l.address.is_ipv4())
                    || self.control.iter().any(|(ip, ..)| ip.source.is_ipv4()))
            || mtu < 1280
                && (self.listeners.iter().flatten().any(|l| l.address.is_ipv6())
                    || self.control.iter().any(|(ip, ..)| ip.source.is_ipv6()))
        {
            return Err(Error::InvalidArgument.into());
        }
        let mut template = self.config.connection.clone();
        template.pmtud.as_mut().unwrap().first_hop_mtu = mtu;
        if template.validate(true).is_err() && template.validate(false).is_err() {
            return Err(Error::InvalidArgument.into());
        }
        // Validate the whole occupied set before any clock/path mutation. This
        // includes passive children and closed slots retained for final RSTs.
        for slot in self.slots.iter().flatten() {
            slot.connection.validate_first_hop_mtu(now, mtu)?;
        }
        self.clock(now)?;
        for index in 0..self.slots.len() {
            let reserved = self.is_output_reserved(self.id(index));
            if let Some(slot) = &mut self.slots[index] {
                if reserved {
                    slot.connection.set_reserved_first_hop_mtu(now, mtu)?;
                } else {
                    slot.connection.set_first_hop_mtu(now, mtu)?;
                }
                self.refresh(index);
            }
        }
        // This template also supplies the stateless reply budget. Do not change
        // MSS/scratch/send limits: a link increase never grows allocations.
        self.config.connection.pmtud.as_mut().unwrap().first_hop_mtu = mtu;
        Ok(())
    }

    pub fn path_mtu_info(
        &self,
        id: ConnectionId,
    ) -> Result<Option<crate::PathMtuInfo>, EndpointError> {
        Ok(self.slot(id)?.connection.path_mtu_info())
    }

    pub fn set_user_mss(
        &mut self,
        id: ConnectionId,
        mss: Option<u16>,
    ) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        self.slot_mut(id)?.connection.set_user_mss(mss)?;
        self.refresh(id.slot);
        Ok(())
    }

    pub fn user_mss(&self, id: ConnectionId) -> Result<Option<u16>, EndpointError> {
        Ok(self.slot(id)?.connection.user_mss())
    }

    pub fn set_listener_user_mss(
        &mut self,
        id: ListenerId,
        mss: Option<u16>,
    ) -> Result<(), EndpointError> {
        self.listener(id)?;
        if mss == Some(0) {
            return Err(Error::InvalidArgument.into());
        }
        self.listeners[id.slot].as_mut().unwrap().user_mss = mss;
        Ok(())
    }

    pub fn lower_mss(&mut self, id: ConnectionId, mss: u16) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        self.slot_mut(id)?.connection.lower_mss(mss)?;
        self.refresh(id.slot);
        Ok(())
    }
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
    //# (d)  An application MUST (MUST-21) be able to set the value for R2
    //# for a particular connection.
    pub fn set_user_timeout(
        &mut self,
        id: ConnectionId,
        timeout_us: u64,
    ) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        self.slot_mut(id)?.connection.set_user_timeout(timeout_us)?;
        self.refresh(id.slot);
        Ok(())
    }
    pub fn set_application_timeout(
        &mut self,
        id: ConnectionId,
        timeout_us: Option<u64>,
    ) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        self.slot_mut(id)?
            .connection
            .set_application_timeout(timeout_us)?;
        self.refresh(id.slot);
        Ok(())
    }

    pub fn application_timeout(&self, id: ConnectionId) -> Result<Option<u64>, EndpointError> {
        Ok(self.slot(id)?.connection.application_timeout())
    }

    pub fn set_handshake_retransmission_limit(
        &mut self,
        id: ConnectionId,
        limit: Option<NonZeroU8>,
    ) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        self.slot_mut(id)?
            .connection
            .set_handshake_retransmission_limit(limit);
        self.refresh(id.slot);
        Ok(())
    }

    pub fn handshake_retransmission_limit(
        &self,
        id: ConnectionId,
    ) -> Result<Option<NonZeroU8>, EndpointError> {
        Ok(self.slot(id)?.connection.handshake_retransmission_limit())
    }

    pub fn set_listener_handshake_retransmission_limit(
        &mut self,
        id: ListenerId,
        limit: Option<NonZeroU8>,
    ) -> Result<(), EndpointError> {
        self.listener(id)?;
        self.listeners[id.slot]
            .as_mut()
            .unwrap()
            .handshake_retransmission_limit = limit;
        Ok(())
    }

    pub fn listener_handshake_retransmission_limit(
        &self,
        id: ListenerId,
    ) -> Result<Option<NonZeroU8>, EndpointError> {
        Ok(self.listener(id)?.handshake_retransmission_limit)
    }

    pub fn set_listener_application_timeout(
        &mut self,
        id: ListenerId,
        timeout_us: Option<u64>,
    ) -> Result<(), EndpointError> {
        self.listener(id)?;
        if timeout_us == Some(0) {
            return Err(Error::InvalidArgument.into());
        }
        self.listeners[id.slot]
            .as_mut()
            .unwrap()
            .application_timeout_us = timeout_us;
        Ok(())
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
    //# keep-alives are included, the application MUST be able to turn them
    //# on or off for each TCP connection (MUST-24),
    pub fn set_keepalive(
        &mut self,
        id: ConnectionId,
        keepalive: Option<crate::KeepaliveConfig>,
    ) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
        //# This interval MUST
        //# be configurable (MUST-27)
        self.slot_mut(id)?.connection.set_keepalive(keepalive)?;
        self.refresh(id.slot);
        Ok(())
    }
    pub fn tuple(&self, id: ConnectionId) -> Result<Tuple, EndpointError> {
        Ok(self.slot(id)?.connection.tuple())
    }
    pub fn readable_bytes(&self, id: ConnectionId) -> Result<usize, EndpointError> {
        Ok(self.slot(id)?.connection.readable_bytes())
    }
    pub fn urgent_remaining(&self, id: ConnectionId) -> Result<u64, EndpointError> {
        Ok(self.slot(id)?.connection.urgent_remaining())
    }
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2
    //# Time to Live (TTL):  The TTL value used to send TCP segments MUST be
    //# configurable (MUST-49).
    pub fn set_hop_limit(&mut self, id: ConnectionId, hop_limit: u8) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        if hop_limit == 0 {
            return Err(Error::InvalidArgument.into());
        }
        self.slot_mut(id)?.hop_limit = hop_limit;
        Ok(())
    }
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.9
    //# TCP implementations MAY pass the most recently received
    //# Differentiated Services field up to the application (MAY-9).
    pub fn received_dscp(&self, id: ConnectionId) -> Result<Option<u8>, EndpointError> {
        Ok(self.slot(id)?.received_dscp)
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.9
    //# The application layer MUST be able to specify the Differentiated
    //# Services field for segments that are sent on a connection (MUST-48).
    pub fn set_dscp(&mut self, id: ConnectionId, dscp: u8) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        if dscp > 63 || self.slot(id)?.connection.managed_path
            .is_some_and(|path| path.snapshot.key().dscp().value() != dscp)
        {
            // Managed class changes require atomic provider rebind.
            return Err(Error::InvalidArgument.into());
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.9
        //# It is not required, but the
        //# application SHOULD be able to change the Differentiated Services
        //# field during the connection lifetime (SHLD-21).
        self.slot_mut(id)?.dscp = dscp;
        Ok(())
    }
    // The mark the connection's packets carry from now on (Linux's
    // SO_MARK), its TIME-WAIT record's ACKs included, as Linux's timewait
    // socket keeps tw_mark. A packet already reserved keeps the mark it
    // was built with, so a reservation does not refuse the change.
    pub fn set_mark(&mut self, id: ConnectionId, mark: u32) -> Result<(), EndpointError> {
        self.slot_mut(id)?.mark = mark;
        Ok(())
    }
    pub fn mark(&self, id: ConnectionId) -> Result<u32, EndpointError> {
        Ok(self.slot(id)?.mark)
    }
    // Whether the application lets other sockets bind the connection's
    // local address while it, or its TIME-WAIT record, holds it (Linux's
    // sk_reuse, which the timewait socket keeps as tw_reuse). The Endpoint
    // only keeps it for the adapter's bind checks (`time_wait_binds`).
    pub fn set_reuse_address(
        &mut self,
        id: ConnectionId,
        reuse: bool,
    ) -> Result<(), EndpointError> {
        self.slot_mut(id)?.reuse_address = reuse;
        Ok(())
    }
    // Also of a released connection, until it is reclaimed or a record.
    pub fn reuse_address(&self, id: ConnectionId) -> Result<bool, EndpointError> {
        Ok(self.retained_slot(id)?.reuse_address)
    }
    pub fn close_reason(
        &self,
        id: ConnectionId,
    ) -> Result<Option<crate::CloseReason>, EndpointError> {
        Ok(self.slot(id)?.connection.close_reason())
    }
    // Observe an existing connection without transferring ownership.
    pub fn connection_id(&self, tuple: Tuple) -> Option<ConnectionId> {
        self.scoped_connection_id(ScopedTuple::unscoped(tuple))
    }
    /// `connection_id` for a scoped identity: identical link-local tuples on
    /// two links name two connections.
    pub fn scoped_connection_id(&self, tuple: ScopedTuple) -> Option<ConnectionId> {
        self.tuples
            .find(self.hash(tuple), tuple)
            .map(|index| self.id(index))
    }

    // Connections reclaimed so far. State kept per connection outside the
    // endpoint need be checked for reclaimed generations only when this has
    // changed.
    pub fn reclaimed(&self) -> u64 {
        self.reclaimed
    }

    /// The connections reclaimed since `reclaimed` was `since`, oldest
    /// first. None once more than `max_connections` have been: the endpoint
    /// keeps no more, and the caller checks its state per connection
    /// (`connection_exists`) instead, a pass that many reclaims pay for.
    pub fn reclaimed_since(&self, since: u64) -> Option<impl Iterator<Item = ConnectionId> + '_> {
        debug_assert!(since <= self.reclaimed);
        let count = self.reclaims.len() as u64;
        (self.reclaimed.checked_sub(since)? <= count)
            .then(|| (since..self.reclaimed).map(move |n| self.reclaims[(n % count) as usize]))
    }

    // Includes released records retained for final output, such as a reset
    // still to send; a released connection's TIME-WAIT is a record, not a
    // connection.
    pub fn connection_exists(&self, id: ConnectionId) -> bool {
        self.generations.get(id.slot) == Some(&id.generation)
            && self.slots.get(id.slot).is_some_and(Option::is_some)
    }

    pub fn state(&self, id: ConnectionId) -> Result<State, EndpointError> {
        Ok(self.slot(id)?.connection.state())
    }
    pub fn transport_info(&self, id: ConnectionId) -> Result<crate::TransportInfo, EndpointError> {
        Ok(self.slot(id)?.connection.transport_info_at(self.now))
    }

    pub fn acknowledged(&self, id: ConnectionId) -> Result<u64, EndpointError> {
        Ok(self.slot(id)?.connection.acknowledged())
    }
    pub fn release(&mut self, id: ConnectionId) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        let state = self.slot(id)?.connection.state();
        if !matches!(state, State::Closed | State::TimeWait) {
            return Err(Error::InvalidState.into());
        }
        let slot = self.slot_mut(id)?;
        let charge = slot.connection.tx_timestamps.storage_bytes()
            + slot.connection.rx_timestamps.storage_bytes();
        slot.connection.tx_timestamps = Default::default();
        slot.connection.rx_timestamps = Default::default();
        slot.released = true;
        self.events.remove(id.slot);
        // A released connection writes no more.
        self.stop_memory_wait(id.slot);
        self.uncharge(charge);
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.5
        //# Delete the
        //# TCB, enter CLOSED state, and return.

        self.refresh(id.slot);
        Ok(())
    }
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.8
    //# There MUST be a mechanism for reporting soft TCP error conditions to
    //# the application (MUST-47).

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.8
    //# However, the conditions that are reported asynchronously to the application MUST include:
    pub fn next_event(&mut self) -> Option<Event> {
        if let Some(event) = self.passive_errors.pop_front() {
            return Some(event);
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
        //# When the number of transmissions of the same segment reaches or
        //# exceeds threshold R1, pass negative advice (see Section 3.3.1.4
        //# of [19]) to the IP layer, to trigger dead-gateway diagnosis.

        // Traceability limitation: RouteAdvice supplies the core boundary; actual
        // gateway diagnosis belongs to the IP layer.
        if let Some(index) = self.advice.pop() {
            return Some(Event::RouteAdvice(
                self.slots[index].as_ref().unwrap().connection.tuple(),
            ));
        }
        loop {
            let next = self.events.iter().find(|&index| {
                if index < self.config.max_connections {
                    return !self.is_output_reserved(self.id(index));
                }
                self.listeners[index - self.config.max_connections]
                    .as_ref()
                    .is_none_or(|listener| {
                        listener.closing
                            || listener.pending.is_empty()
                            || listener
                                .pending
                                .iter()
                                .any(|&id| !self.is_output_reserved(id))
                    })
            });
            let Some(index) = next else { break };
            self.events.remove(index);
            if index >= self.config.max_connections {
                let slot = index - self.config.max_connections;
                let listener = self.listeners[slot].as_ref()?;
                if listener.closing || listener.pending.is_empty() {
                    continue;
                }
                return Some(Event::Acceptable(ListenerId {
                    slot,
                    generation: self.listener_generations[slot],
                }));
            }
            let id = self.id(index);
            let slot = self.slots[index].as_mut()?;
            if slot.released || slot.listener.is_some() {
                continue;
            }
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
            //# SHOULD make the information available to the application (SHLD-25).

            let mut events = slot.connection.take_events();
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.8
            //# However, an application program that does not want to receive such
            //# ERROR_REPORT calls SHOULD be able to effectively disable these calls
            //# (SHLD-20).
            if !self.config.error_reports {
                events.network_error = None;
                events.retransmission_warning = false;
                events.urgent = None;
            }
            if !events.is_empty() {
                return Some(Event::Connection(id, events));
            }
        }
        None
    }

    /// Stateless replies discarded because even their form without the
    /// optional timestamp echo could not fit the path they leave on: each is
    /// dropped once, never retried. For administrative reporting.
    pub fn oversized_control_replies(&self) -> u64 {
        self.oversized_control
    }

    /// Stateless replies to a link-local peer dropped because the link they
    /// arrived on, the only one they may leave on, was removed or replaced
    /// before they drained (`count_undeliverable_reply`): each is dropped
    /// once, never sent on another link. For administrative reporting.
    pub fn undeliverable_control_replies(&self) -> u64 {
        self.undeliverable_control
    }

    /// What a listener dropped because its accept queue was full, as Linux
    /// counts LINUX_MIB_LISTENOVERFLOWS: a SYN (tcp_conn_request), and the
    /// last ACK of a handshake, whose child stays half-open
    /// (tcp_v4_syn_recv_sock), counted again for each such ACK the peer
    /// sends. A SYN its full SYN queue refuses is not counted, even when
    /// the accept queue is full too, as Linux checks the SYN queue first.
    /// For administrative reporting.
    pub fn listen_overflows(&self) -> u64 {
        self.listen_overflows
    }

    /// Segments discarded because their TCP checksum was wrong (RFC 9293
    /// MUST-3), as Linux counts TCP_MIB_CSUMERRORS (Tcp InCsumErrors) in
    /// tcp_v4_rcv and tcp_v6_rcv. For administrative reporting.
    pub fn checksum_errors(&self) -> u64 {
        self.checksum_errors
    }

    /// What a listener dropped for lack of room, as Linux counts
    /// LINUX_MIB_LISTENDROPS (tcp_listendrop): `listen_overflows`, SYNs its
    /// full SYN queue refuses (with tcp_syncookies=0, as ntcp has no SYN
    /// cookies; Linux also counts them in TCPReqQFullDrop), and SYNs
    /// refused for want of a connection slot (`max_connections`) or buffer
    /// budget (`max_buffer_bytes`), whose connection could not be
    /// allocated, or that a managed path provider found no path to answer.
    /// A SYN that may not reopen its TIME-WAIT connection is that
    /// connection's to drop and is not counted. For administrative
    /// reporting.
    pub fn listen_drops(&self) -> u64 {
        self.listen_drops
    }

    /// Writes that took fewer bytes than they offered, or none
    /// (WouldBlock), because the buffer budget (`max_buffer_bytes`) or the
    /// allocator refused their send storage, not because the send buffer
    /// was full: where Linux's tcp_sendmsg finds sk_wmem_schedule fail and
    /// waits in sk_stream_wait_memory, which has no MIB counter. The
    /// connection is then not writable until memory comes back to the
    /// budget: a connection's storage released, reclaimed or shrunk.
    pub fn memory_throttled_writes(&self) -> u64 {
        self.memory_throttled_writes
    }

    /// Connections in TIME-WAIT now, as Linux reports its TIME-WAIT sockets
    /// (/proc/net/sockstat `tw`), released or not, kept whole or as a
    /// TIME-WAIT record. A reopening SYN ends the TIME-WAIT of the
    /// incarnation it replaces, as Linux deletes its timewait socket. A
    /// connection that holds its tuple for the TIME-WAIT duration after
    /// sending a reset is CLOSED, not counted. For administrative reporting.
    pub fn time_wait_connections(&self) -> usize {
        debug_assert_eq!(
            self.time_wait_slots,
            self.occupied
                .iter()
                .filter(|&index| self.slots[index]
                    .as_ref()
                    .is_some_and(|slot| slot.connection.state() == State::TimeWait))
                .count()
        );
        self.time_wait_slots + self.time_wait.len()
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        // Only a held slot without a current attempt can wait for pacing.
        self.deadlines
            .first()
            .map(|(time, _)| time)
            .into_iter()
            .chain(self.time_wait.first_expiry().map(|(time, _)| time))
            .chain(self.unattempted_reservations.iter().filter_map(|index| {
                let r = self.reservations[index].current.as_ref()?;
                self.retained_slot(r.packet.connection?)
                    .ok()?
                    .connection
                    .reserved_pacing_deadline(self.now, r.departure.as_ref()?)
            }))
            .min()
    }
    pub fn has_pending_output(&self) -> bool {
        self.free_reservations != self.reservations.len()
            || !self.output.is_empty()
            || self.stateless_pending()
            || !self.cleanup.is_empty()
    }
    // Stateless lane output: queued replies and owed TIME-WAIT ACKs.
    fn stateless_pending(&self) -> bool {
        !self.control.is_empty() || self.time_wait.has_output()
    }
    /// Output waiting to be polled, apart from attempts held in output
    /// reservations: an embedding that keeps a reserved attempt waiting on
    /// an event of its own (a next hop being resolved) has no work to poll
    /// for while this is false.
    pub fn has_queued_output(&self) -> bool {
        let lane_free = |owner| {
            self.reservation_of(owner).is_none_or(|index| {
                self.reservations[index]
                    .current
                    .as_ref()
                    .is_some_and(|r| r.attempt.is_none())
            })
        };
        self.ready_connections().next().is_some()
            || self.stateless_pending() && lane_free(None)
            || !self.cleanup.is_empty()
    }
    pub fn buffer_bytes(&self) -> usize {
        self.budget.charged()
    }

    /// Whether the endpoint is under memory pressure, Linux's
    /// tcp_memory_pressure: since the bytes charged (`buffer_bytes`)
    /// exceeded `EndpointConfig::buffer_memory().pressure`, until they fell
    /// to at most its `low` (`__sk_mem_raise_allocated`,
    /// `__sk_mem_reduce_allocated`).
    pub fn memory_pressure(&self) -> bool {
        self.budget.under_pressure()
    }

    /// Join `shared` as its member `owner` (`SharedBufferMemory`): from now
    /// on this endpoint charges the group's budget, in batches, against the
    /// group's thresholds, and is under pressure whenever the group is.
    /// All it charged and holds open moves into the group; leaving
    /// (`leave_buffer_memory`, or dropping the endpoint) takes it out
    /// again. Once, and `owner` not another member's (InvalidArgument).
    pub fn share_buffer_memory(
        &mut self,
        shared: &crate::SharedBufferMemory,
        owner: usize,
    ) -> Result<(), EndpointError> {
        let own = self.config.buffer_memory();
        self.budget.share(shared, owner, own, self.now)?;
        if !self.memory_waiters.is_empty() {
            self.budget.set_waiting(true);
        }
        self.wake_memory_waiters();
        Ok(())
    }

    /// For a member of shared buffer memory: leave the group, as dropping
    /// the endpoint does. Its unpublished reserve is published and then all
    /// it charged, its connections and, for summed thresholds, its own go
    /// out of the group; pressure ends if what the group still holds is at
    /// most its low threshold; the other members find memory returned
    /// (`poll_shared_memory`), and those `SharedBufferMemory::waiting`
    /// names should drive. The endpoint goes on with a budget of its own,
    /// against its configuration's thresholds. False if it was no member.
    pub fn leave_buffer_memory(&mut self) -> bool {
        if !self.budget.leave_group(self.now) {
            return false;
        }
        // Its own waiters now wait on its own budget.
        self.wake_memory_waiters();
        true
    }

    /// For a member of shared buffer memory: wake the writers waiting for
    /// memory if another member returned some, or pressure ended, since the
    /// last look. One atomic load when nothing came back. Call it as each
    /// drive begins; true if it looked again.
    #[inline]
    pub fn poll_shared_memory(&mut self) -> bool {
        if !self.budget.poll_returns() {
            return false;
        }
        self.wake_memory_waiters();
        true
    }

    /// For a member of shared buffer memory: whether this endpoint returned
    /// memory to its group since the last call (a batch published back, or
    /// the end of pressure). Then the members `SharedBufferMemory::waiting`
    /// names should drive and `poll_shared_memory`.
    #[inline]
    pub fn take_memory_returned(&mut self) -> bool {
        self.budget.take_returned()
    }

    /// The endpoint's buffer memory gauges and counters (`MemoryCounters`).
    pub fn memory_counters(&self) -> crate::MemoryCounters {
        let (pressures, ticks) = self.budget.pressure_totals(self.now);
        crate::MemoryCounters {
            buffer_bytes: self.budget.charged(),
            memory_pressure: self.budget.under_pressure(),
            memory_pressures: pressures,
            memory_pressure_us: self.config.connection.timebase.us_from_ticks(ticks),
            memory_throttled_writes: self.memory_throttled_writes,
            memory_refused_opens: self.memory_refused_opens,
            memory_refused_growths: self.memory_refused_growths,
            ledger_split_refusals: self.ledger_split_refusals,
        }
    }

    pub fn on_timeout(&mut self, now: Instant, budget: usize) -> Result<bool, EndpointError> {
        self.clock(now)?;
        for _ in 0..budget {
            let connection = self
                .deadlines
                .first()
                .filter(|&(deadline, _)| deadline <= now);
            let record = self
                .time_wait
                .first_expiry()
                .filter(|&(deadline, _)| deadline <= now);
            if let Some((deadline, index)) = record
                && connection.is_none_or(|(first, _)| deadline < first)
            {
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.8
                //# If the time-wait timeout expires on a connection, delete the TCB,
                //# enter the CLOSED state, and return.
                self.remove_time_wait(index);
                continue;
            }
            let Some((_, index)) = connection else {
                break;
            };
            self.deadlines.set(index, None);
            let slot = self.slots[index].as_mut().unwrap();
            let retry = slot.memory_retry.is_some_and(|deadline| deadline <= now);
            if !retry
                || slot
                    .connection
                    .next_deadline()
                    .is_some_and(|deadline| deadline <= now)
            {
                slot.connection.timeout(now)?;
            }
            if retry {
                self.retry_memory(index);
            }
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.8
            //# If the time-wait timeout expires on a connection, delete the TCB,
            //# enter the CLOSED state, and return.

            // Traceability limitation: Released TIME-WAIT connections are reclaimed on
            // expiry; unreleased terminal handles retain storage until release.
            self.refresh(index);
        }
        Ok(self
            .deadlines
            .first()
            .map(|(deadline, _)| deadline)
            .into_iter()
            .chain(self.time_wait.first_expiry().map(|(deadline, _)| deadline))
            .any(|deadline| deadline <= now))
    }

    /// Allocate reusable payload-reference descriptors before packet service.
    /// The existing reservation pool must be enabled first and contain no held
    /// output. `max_segments` is a caller/backend resource bound, not a TCP MSS,
    /// at most MAX_SHARED_SEGMENTS.
    pub fn enable_shared_output(&mut self, max_segments: usize) -> Result<(), EndpointError> {
        if max_segments == 0
            || max_segments > Self::MAX_SHARED_SEGMENTS
            || max_segments > self.config.connection.send_capacity
            || self.reservations.is_empty()
        {
            return Err(Error::InvalidArgument.into());
        }
        if self.reservations.iter().any(|s| s.current.is_some()) {
            return Err(EndpointError::OutputReserved);
        }
        if self
            .reservations
            .iter()
            .all(|s| s.shared.capacity() >= max_segments)
        {
            return Ok(());
        }
        let needed = self
            .reservations
            .len()
            .checked_mul(max_segments)
            .and_then(|n| n.checked_mul(core::mem::size_of::<crate::Payload>()))
            .ok_or(Error::NoMemory)?;
        if needed > self.buffer_room() {
            return Err(Error::NoMemory.into());
        }
        let mut staged = reserved_vec(self.reservations.len())?;
        let mut charge = 0usize;
        for _ in &self.reservations {
            let v: Vec<crate::Payload> = reserved_vec(max_segments)?;
            charge = charge
                .checked_add(v.capacity() * core::mem::size_of::<crate::Payload>())
                .ok_or(Error::NoMemory)?;
            staged.push(v);
        }
        if charge > self.buffer_room() {
            return Err(Error::NoMemory.into());
        }
        let mut old = 0;
        for (slot, payload) in self.reservations.iter_mut().zip(staged) {
            old += slot.shared.capacity() * core::mem::size_of::<crate::Payload>();
            slot.shared = payload;
        }
        self.recharge(old, charge);
        Ok(())
    }

    /// Poll one owner with immutable payload references. For shared output,
    /// `packet.len` includes payload but only its TCP header is written to `out`;
    /// subtract payload lengths to obtain the initialized header length. Empty
    /// `payload` denotes a normal/control packet fully encoded into `out`.
    /// Its capacity bounds the entire TCP wire packet even when only a header
    /// is written; size it to the backend's complete-packet TCP budget.
    /// Reuse the ordinary accept/reject/abandon reservation APIs. Do not submit
    /// both representations or reuse an uncertain submission.
    pub fn poll_reserved_transmit_shared_for(
        &mut self,
        now: Instant,
        id: ConnectionId,
        out: &mut [u8],
        payload: &mut Vec<crate::Payload>,
        budget: usize,
    ) -> Result<(PollTransmit, Option<crate::TransmitAttempt>), EndpointError> {
        payload.clear();
        if payload.capacity() == 0
            || self
                .reservations
                .iter()
                .any(|s| s.shared.capacity() < payload.capacity())
        {
            return Err(Error::InvalidArgument.into());
        }
        self.poll_reserved_selected(now, out, budget, Some(id), Some(payload), None)
    }

    pub fn enable_output_reservations(&mut self) -> Result<(), EndpointError> {
        self.enable_output_reservations_with_capacity(1)
    }

    pub fn enable_output_reservations_with_capacity(
        &mut self,
        count: usize,
    ) -> Result<(), EndpointError> {
        self.enable_output_reservations_with_packet_bytes(count, usize::MAX, None)
    }

    pub fn enable_output_reservations_with_gso(
        &mut self,
        count: usize,
        limits: crate::GsoLimits,
    ) -> Result<(), EndpointError> {
        self.enable_output_reservations_with_packet_bytes(count, usize::MAX, Some(limits))
    }

    /// `count` output reservations, each holding one TCP packet of up to
    /// `packet_bytes`, at most `send_ip_payload_limit`, and with `gso` the
    /// payload of one aggregate. A poll encodes into no more of `out` than
    /// this, as if `out` were no longer, and a packet that does not fit is
    /// `OutputTooSmall`: an embedding that always polls with `out` of one
    /// size passes that size and is charged no room it never uses.
    /// `packet_bytes` below what a SYN with its options needs is refused.
    pub fn enable_output_reservations_with_packet_bytes(
        &mut self,
        count: usize,
        packet_bytes: usize,
        gso: Option<crate::GsoLimits>,
    ) -> Result<(), EndpointError> {
        if gso.is_some_and(|limits| {
            limits.max_bytes == 0
                || limits.max_bytes > u32::MAX as usize / 2
                || limits.max_segments < 2
                || limits.max_segments > limits.max_bytes
        }) || packet_bytes < usize::from(self.config.connection.minimum_send_budget())
        {
            return Err(Error::InvalidArgument.into());
        }
        if self.reservations.iter().any(|slot| slot.current.is_some()) {
            return Err(EndpointError::OutputReserved);
        }
        if count == 0 || count > self.config.max_connections.saturating_add(1) {
            return Err(Error::InvalidArgument.into());
        }
        let size = packet_bytes.min(self.config.connection.send_ip_payload_limit as usize);
        if !self.reservations.is_empty() {
            return if count == self.reservations.len()
                && self.reservations[0].gso == gso
                && self.reservations[0].bytes.len() == size
            {
                Ok(())
            } else {
                Err(Error::InvalidArgument.into())
            };
        }
        let payload_size = gso.map_or(0, |limits| limits.max_bytes);
        let charge = self
            .config
            .output_reservations_charge(count, packet_bytes, gso)
            .ok_or(Error::NoMemory)?;
        if charge > self.buffer_room() {
            return Err(Error::NoMemory.into());
        }
        let mut owners = reserved_vec(self.slots.len())?;
        owners.resize(self.slots.len(), None);
        let unattempted = ReadyQueue::new(count).map_err(|_| Error::NoMemory)?;
        let mut slots = reserved_vec(count)?;
        for index in 0..count {
            let mut slot = crate::output_reservation::OutputReservation::new();
            slot.index = index;
            slot.bytes = reserved_vec(size)?;
            slot.bytes.resize(size, 0);
            // Written on first use (poll_reserved_selected), so an
            // aggregate's room costs no page until its reservation selects
            // one. The pool is taken lowest slot first.
            slot.payload = reserved_vec(payload_size)?;
            slot.gso = gso;
            slot.checksum_partial = self.config.connection.tcp_checksum_offload;
            slots.push(slot);
        }
        self.reservations = slots;
        self.reservation_owners = owners;
        self.stateless_reservation = None;
        self.free_reservations = count;
        self.unattempted_reservations = unattempted;
        self.charge(charge);
        Ok(())
    }

    pub fn transmit_segmentation(
        &self,
        attempt: crate::TransmitAttempt,
    ) -> Option<crate::TransmitSegmentation> {
        let r = self
            .reservations
            .get(attempt.reservation)?
            .current
            .as_ref()?;
        (r.attempt == Some(attempt))
            .then_some(r.departure?.segmentation)
            .flatten()
    }

    /// Offer the consecutive full segments of a GSO reservation from the
    /// current attempt's segment on as one backend aggregate, within
    /// `limits`. The attempt must be certainly unsubmitted. Changes no TCP
    /// state: like every reservation, the range was selected when polled,
    /// and its departure (RACK transmission, RTT and PMTU evidence, PRR,
    /// timers) is recorded only by `accept_transmit_group`. None or an
    /// error leaves the attempt intact; success replaces it with the group,
    /// which alone can then be accepted, rejected or abandoned.
    pub fn prepare_transmit_group(
        &mut self,
        attempt: crate::TransmitAttempt,
        limits: crate::TransmitGroupLimits,
    ) -> Result<Option<crate::TransmitGroup>, EndpointError> {
        let index = attempt.reservation;
        let Some(slot) = self.reservations.get(index) else {
            return Ok(None);
        };
        let Some(r) = slot
            .current
            .as_ref()
            .filter(|r| r.attempt == Some(attempt) && !slot.is_shared())
        else {
            return Ok(None);
        };
        let (Some(id), Some(d)) = (r.packet.connection, r.departure) else {
            return Ok(None);
        };
        let Some(s) = d.segmentation else {
            return Ok(None);
        };
        let flags = s.terminal_flags;
        let owner = &self.retained_slot(id)?.connection;
        let original =
            wire::parse_unchecked(r.packet.ip, &slot.bytes[..r.packet.len]).map_err(Error::Wire)?;
        // The aggregate must split into exactly the segments scalar polling
        // emits from here: full-sized at the current path limit but for the
        // reservation's short last one, with the same flags and options.
        // SYN and URG have per-segment meaning a header template cannot
        // carry; GSO selection never sets them. FIN, like PSH, belongs to the
        // last segment.
        if d.syn
            || flags & (wire::SYN | wire::RST | wire::URG) != 0
            || r.emitted_bytes != s.segment_payload_len
            || r.offset % s.segment_payload_len != 0
            || owner.path_payload_limit() < s.tcp_header_len + s.segment_payload_len
            || !limits.allow_cwr && r.offset == 0 && flags & wire::CWR != 0
            || !limits.allow_options && !original.raw_options.is_empty()
        {
            return Ok(None);
        }
        let remaining = s
            .payload_len
            .checked_sub(r.offset)
            .ok_or(Error::InvalidArgument)?;
        let size = s.segment_payload_len;
        let mut segments = remaining.div_ceil(size).min(limits.max_segments).min(
            if remaining <= limits.max_bytes {
                usize::MAX
            } else {
                limits.max_bytes / size
            },
        );
        // Without PSH (and FIN) support the final segment stays scalar.
        if !limits.allow_psh && flags & (wire::PSH | wire::FIN) != 0 && segments * size >= remaining
        {
            segments = segments.saturating_sub(1);
        }
        if segments < 2 {
            return Ok(None);
        }
        let bytes = (segments * size).min(remaining);
        // Every acceptance check of every segment, before issuing a token the
        // backend may submit as one indivisible object.
        owner.validate_reserved_group(self.now, &d, r.offset, bytes)?;
        let token = crate::TransmitGroup(self.reservations[index].token()?);
        let r = self.reservations[index].current.as_mut().unwrap();
        r.group = Some(crate::output_reservation::PreparedGroup {
            token,
            segments,
            bytes,
        });
        // A private attempt identity keeps every held-output barrier.
        r.attempt = Some(token.0);
        r.abandon_attempt = token.0;
        Ok(Some(token))
    }

    pub fn transmit_group(
        &self,
        token: crate::TransmitGroup,
    ) -> Option<crate::TransmitGroupView<'_>> {
        let slot = self.reservations.get(token.0.reservation)?;
        let r = slot.current.as_ref()?;
        let group = r.group.filter(|g| g.token == token)?;
        let s = r.departure?.segmentation?;
        let original = wire::parse_unchecked(r.packet.ip, &slot.bytes[..r.packet.len]).ok()?;
        // The flags `fragment` gives the group's first segment, except that
        // PSH and FIN stay for the backend to place on the last one.
        let mut header = original.header;
        header.sequence = header.sequence.wrapping_add(r.offset as u32);
        header.flags = s.terminal_flags;
        if r.offset + group.bytes != s.payload_len {
            header.flags &= !(wire::PSH | wire::FIN);
        }
        if r.offset != 0 {
            header.flags &= !wire::CWR;
        }
        Some(crate::TransmitGroupView {
            packet: Transmit {
                len: s.tcp_header_len + group.bytes,
                tx_timestamp: None,
                ..r.packet
            },
            header,
            options: original.raw_options,
            payload: &slot.payload[r.offset..r.offset + group.bytes],
            segment_payload_len: s.segment_payload_len,
            segment_count: group.segments,
        })
    }

    /// Read-only form of every check `accept_transmit_group` performs, as
    /// `preflight_accept_transmit` is for one attempt. False for a stale
    /// token. Call immediately before each submission (including WouldBlock
    /// retries), serializing endpoint access through submission and
    /// acceptance: a path that shrank since preparation fails here with
    /// `ReservationMtuTooSmall`, and the group must be rejected and the
    /// reservation polled again, which splits it for the new path.
    pub fn validate_transmit_group(
        &self,
        now: Instant,
        token: crate::TransmitGroup,
    ) -> Result<bool, EndpointError> {
        let Some(r) = self
            .reservations
            .get(token.0.reservation)
            .and_then(|slot| slot.current.as_ref())
        else {
            return Ok(false);
        };
        let Some(group) = r.group.filter(|g| g.token == token) else {
            return Ok(false);
        };
        let d = r.departure.unwrap();
        let s = d.segmentation.unwrap();
        let owner = &self
            .retained_slot(r.packet.connection.ok_or(EndpointError::InvalidHandle)?)?
            .connection;
        owner.validate_reserved_group(now, &d, r.offset, group.bytes)?;
        if owner.path_payload_limit() < s.tcp_header_len + s.segment_payload_len {
            return Err(EndpointError::ReservationMtuTooSmall);
        }
        self.check_clock(now)?;
        Ok(true)
    }

    /// Record the backend's submission of the whole group at `now`, its
    /// submission time: exactly what accepting each of its segments in turn
    /// at `now` records, so every segment departs at `now` (Linux likewise
    /// stamps every segment of a TSO skb with the skb's departure). Errors
    /// are those of `validate_transmit_group` and change nothing.
    pub fn accept_transmit_group(
        &mut self,
        now: Instant,
        token: crate::TransmitGroup,
    ) -> Result<bool, EndpointError> {
        if !self.validate_transmit_group(now, token)? {
            return Ok(false);
        }
        let index = token.0.reservation;
        let r = self.reservations[index].current.as_ref().unwrap();
        let group = r.group.unwrap();
        let mut departure = r.departure.unwrap();
        let (offset, id) = (r.offset, r.packet.connection.unwrap());
        let finished = offset + group.bytes == departure.payload;
        // Checked above.
        self.clock(now)?;
        let owner = &mut self.retained_slot_mut(id)?.connection;
        owner.accept_reserved_group(now, &mut departure, offset, group.bytes, finished);
        let r = self.reservations[index].current.as_mut().unwrap();
        r.emitted_bytes = group.bytes;
        r.emitted_sacks = 0;
        r.group = None;
        self.complete_reserved_accept(index, Some(departure), finished);
        Ok(true)
    }

    /// Only for a backend's synchronous, certainly-unsubmitted refusal of
    /// the group (WouldBlock keeps it for a retry instead). Nothing departed:
    /// the reservation is unattempted again, and polling it emits the same
    /// scalar segment the group started with.
    pub fn reject_unsubmitted_group(
        &mut self,
        token: crate::TransmitGroup,
    ) -> Result<bool, EndpointError> {
        let index = token.0.reservation;
        let Some(r) = self
            .reservations
            .get_mut(index)
            .and_then(|slot| slot.current.as_mut())
        else {
            return Ok(false);
        };
        if !r.group.is_some_and(|g| g.token == token) {
            return Ok(false);
        }
        r.group = None;
        self.set_reservation_attempt(index, None);
        Ok(true)
    }

    /// `abandon_transmit` for a group, with its certainly-unsubmitted
    /// precondition. The handle survives rejection and accepted prefixes
    /// until a later attempt or group replaces it.
    pub fn abandon_transmit_group(
        &mut self,
        token: crate::TransmitGroup,
    ) -> Result<bool, EndpointError> {
        self.abandon_transmit(token.0)
    }

    pub fn is_output_reserved(&self, id: ConnectionId) -> bool {
        let reserved = self.reservation_of(Some(id)).is_some();
        debug_assert_eq!(
            reserved,
            self.reservations.iter().any(|slot| {
                slot.current
                    .as_ref()
                    .is_some_and(|r| r.packet.connection == Some(id))
            })
        );
        reserved
    }

    // The slot holding `owner`'s output; None is the stateless lane.
    fn reservation_of(&self, owner: Option<ConnectionId>) -> Option<usize> {
        let index = match owner {
            Some(id) => *self.reservation_owners.get(id.slot)?,
            None => self.stateless_reservation,
        }?;
        // Indexed by slot index alone; the held packet confirms the generation.
        self.reservations[index]
            .current
            .as_ref()
            .is_some_and(|r| r.packet.connection == owner)
            .then_some(index)
    }

    fn reservation_owner_mut(&mut self, owner: Option<ConnectionId>) -> &mut Option<usize> {
        match owner {
            Some(id) => &mut self.reservation_owners[id.slot],
            None => &mut self.stateless_reservation,
        }
    }

    // Call right after slot `index` captured output with a current attempt.
    fn reservation_held(&mut self, index: usize) {
        let owner = self.reservations[index].current.as_ref().unwrap();
        debug_assert!(owner.attempt.is_some());
        let owner = owner.packet.connection;
        *self.reservation_owner_mut(owner) = Some(index);
        self.free_reservations -= 1;
        self.check_reservation_index();
    }

    fn clear_reservation(&mut self, index: usize) {
        if let Some(r) = &self.reservations[index].current {
            let owner = r.packet.connection;
            *self.reservation_owner_mut(owner) = None;
            self.free_reservations += 1;
            self.unattempted_reservations.remove(index);
        }
        self.reservations[index].clear();
        self.check_reservation_index();
    }

    fn set_reservation_attempt(&mut self, index: usize, attempt: Option<crate::TransmitAttempt>) {
        let r = self.reservations[index].current.as_mut().unwrap();
        match (r.attempt.is_some(), attempt.is_some()) {
            (true, false) => self.unattempted_reservations.push(index),
            (false, true) => self.unattempted_reservations.remove(index),
            _ => {}
        }
        r.attempt = attempt;
        self.check_reservation_index();
    }

    // Full-scan form of the reservation bookkeeping, for debug builds.
    fn check_reservation_index(&self) {
        if cfg!(debug_assertions) {
            let held = self.reservations.iter().filter_map(|s| s.current.as_ref());
            assert_eq!(
                self.free_reservations,
                self.reservations.len() - held.clone().count()
            );
            // A queue holds each slot at most once: the same set.
            let unattempted = |index: usize| {
                self.reservations[index]
                    .current
                    .as_ref()
                    .is_some_and(|r| r.attempt.is_none())
            };
            assert!(self.unattempted_reservations.iter().all(unattempted));
            assert_eq!(
                self.unattempted_reservations.iter().count(),
                held.clone().filter(|r| r.attempt.is_none()).count()
            );
            for (index, slot) in self.reservations.iter().enumerate() {
                if let Some(r) = &slot.current {
                    assert_eq!(self.reservation_of(r.packet.connection), Some(index));
                }
            }
            let indexed = self.reservation_owners.iter().flatten().count()
                + usize::from(self.stateless_reservation.is_some());
            assert_eq!(indexed, self.reservations.len() - self.free_reservations);
        }
    }

    fn reject_if_output_reserved(&self, id: ConnectionId) -> Result<(), EndpointError> {
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
        Ok(())
    }

    pub fn ready_connections(&self) -> impl Iterator<Item = ConnectionId> + '_ {
        self.output
            .iter()
            .map(|index| self.id(index))
            .filter(|&id| {
                self.reservation_of(Some(id)).is_none_or(|index| {
                    self.reservations[index]
                        .current
                        .as_ref()
                        .is_some_and(|r| r.attempt.is_none())
                })
            })
    }

    pub fn poll_reserved_transmit_for(
        &mut self,
        now: Instant,
        id: ConnectionId,
        out: &mut [u8],
        budget: usize,
    ) -> Result<(PollTransmit, Option<crate::TransmitAttempt>), EndpointError> {
        self.retained_slot(id)?;
        self.poll_reserved_selected(now, out, budget, Some(id), None, None)
    }

    pub fn poll_reserved_stateless_transmit(
        &mut self,
        now: Instant,
        out: &mut [u8],
        budget: usize,
    ) -> Result<(PollTransmit, Option<crate::TransmitAttempt>), EndpointError> {
        self.poll_reserved_selected(now, out, budget, None, None, None)
    }

    pub fn poll_reserved_transmit(
        &mut self,
        now: Instant,
        out: &mut [u8],
        budget: usize,
    ) -> Result<(PollTransmit, Option<crate::TransmitAttempt>), EndpointError> {
        self.poll_reserved_any(now, out, budget, None)
    }

    pub(crate) fn poll_reserved_any(
        &mut self,
        now: Instant,
        out: &mut [u8],
        budget: usize,
        mut reply: ReplyHeader<'_>,
    ) -> Result<(PollTransmit, Option<crate::TransmitAttempt>), EndpointError> {
        if self.reservations.is_empty() {
            return Err(Error::InvalidArgument.into());
        }
        let free = self.free_reservations != 0;
        if !free && self.unattempted_reservations.is_empty() {
            return Err(EndpointError::OutputReserved);
        }
        self.clock(now)?;
        for _ in 0..budget {
            let next = self
                .ready_connections()
                .find(|&id| free || self.is_output_reserved(id));
            let control = free && self.stateless_pending() && self.reservation_of(None).is_none();
            let owner = if control && (self.control_turn || next.is_none()) {
                None
            } else {
                next
            };
            if owner.is_none() && !control {
                self.cleanup_one();
                continue;
            }
            let resize = reply.as_mut().map(|f| &mut **f as _);
            let result = self.poll_reserved_selected(now, out, 1, owner, None, resize)?;
            if let Some(id) = owner {
                // Repairs share the ready queue rather than monopolizing its head.
                if self.is_output_reserved(id) {
                    self.output.remove(id.slot);
                    self.output.push(id.slot);
                }
            }
            if result.0.packet.is_some() {
                return Ok(result);
            }
        }
        Ok((
            PollTransmit {
                packet: None,
                more_work: self.has_pending_output(),
            },
            None,
        ))
    }

    // Select exactly one owner; None is the independent stateless lane.
    pub(crate) fn poll_reserved_selected(
        &mut self,
        now: Instant,
        out: &mut [u8],
        budget: usize,
        selected: Option<ConnectionId>,
        mut shared: Option<&mut Vec<crate::Payload>>,
        reply: ReplyHeader<'_>,
    ) -> Result<(PollTransmit, Option<crate::TransmitAttempt>), EndpointError> {
        if self.reservations.is_empty() {
            return Err(Error::InvalidArgument.into());
        }
        let index = self
            .reservation_of(selected)
            .or_else(|| {
                (self.free_reservations != 0)
                    .then(|| {
                        self.reservations
                            .iter()
                            .position(|slot| slot.current.is_none())
                    })
                    .flatten()
            })
            .ok_or(EndpointError::OutputReserved)?;
        if self.reservations[index]
            .current
            .as_ref()
            .is_some_and(|r| r.attempt.is_some())
        {
            return Err(EndpointError::OutputReserved);
        }
        if budget == 0 {
            self.clock(now)?;
            return Ok((
                PollTransmit {
                    packet: None,
                    more_work: self.has_pending_output(),
                },
                None,
            ));
        }
        if let Some(r) = &self.reservations[index].current {
            let connection = r.packet.connection;
            let limit = self
                .retained_slot(connection.ok_or(EndpointError::InvalidHandle)?)?
                .connection
                .path_payload_limit();
            self.clock(now)?;
            let packet = if self.reservations[index].is_shared() {
                self.reservations[index].fragment_shared(
                    limit,
                    out,
                    shared.as_deref_mut().ok_or(Error::InvalidArgument)?,
                )?
            } else {
                self.reservations[index].fragment(limit, out)?
            };
            let r = self.reservations[index].current.as_ref().unwrap();
            if r.emitted_bytes != 0
                && let Some(d) = &r.departure
                && self
                    .retained_slot(connection.unwrap())?
                    .connection
                    .reserved_pacing_deadline(now, d)
                    .is_some()
            {
                return Ok((
                    PollTransmit {
                        packet: None,
                        more_work: true,
                    },
                    None,
                ));
            }
            let attempt = self.reservations[index].token()?;
            self.set_reservation_attempt(index, Some(attempt));
            self.reservations[index]
                .current
                .as_mut()
                .unwrap()
                .abandon_attempt = attempt;
            if let Some(id) = connection {
                self.output.remove(id.slot);
                self.output.push(id.slot);
            }
            self.control_turn = true;
            return Ok((
                PollTransmit {
                    packet: Some(packet),
                    more_work: true,
                },
                Some(attempt),
            ));
        }
        // Reserve identity before selection: exhaustion must not consume output.
        let attempt = self.reservations[index].token()?;
        let capacity = out.len().min(self.reservations[index].bytes.len());
        // Move the preallocated payload backing temporarily to avoid aliasing
        // the endpoint during selection; restore it on every result, no allocation.
        let mut payload = core::mem::take(&mut self.reservations[index].payload);
        let gso = self.reservations[index]
            .gso
            .filter(|_| shared.is_none())
            .map(|limits| {
                if payload.len() != limits.max_bytes {
                    // Within the capacity reserved when enabled: no
                    // allocation. One memset in every build, where resize
                    // writes byte by byte without optimization.
                    assert!(payload.is_empty() && payload.capacity() >= limits.max_bytes);
                    // SAFETY: the capacity holds max_bytes, and write_bytes
                    // initializes all of them before set_len exposes them.
                    unsafe {
                        payload.as_mut_ptr().write_bytes(0, limits.max_bytes);
                        payload.set_len(limits.max_bytes);
                    }
                }
                crate::output_reservation::GsoBuffer {
                    limits,
                    payload: &mut payload[..],
                }
            });
        let output = self.poll_transmit_inner(
            now,
            &mut out[..capacity],
            budget,
            true,
            Some(selected),
            gso,
            shared.as_deref_mut(),
            reply,
        );
        self.reservations[index].payload = payload;
        let (mut output, mut zone) = output?;
        if let Some(packet) = output.packet {
            if let Some(parts) = shared.filter(|p| !p.is_empty()) {
                self.reservations[index].capture_shared(packet, out, parts, attempt)?;
            } else {
                self.reservations[index].capture(packet, out, attempt);
            }
            self.reservation_held(index);
            if let Some(id) = packet.connection {
                zone = self.retained_slot(id)?.connection.scoped_tuple().zone();
            }
            self.reservations[index].current.as_mut().unwrap().zone = zone;
            if let Some(id) = packet.connection {
                let connection = &self.retained_slot(id)?.connection;
                let departure = connection.last_departure;
                // Captured without one; only a probe's intent is copied.
                if let Some(intent) = connection.last_discovery {
                    self.reservations[index].current.as_mut().unwrap().discovery = Some(intent);
                }
                let r = self.reservations[index].current.as_mut().unwrap();
                r.departure = departure;
                if let Some(s) = departure.and_then(|d| d.segmentation) {
                    // Use the same exact-prefix acceptance path as MTU repair.
                    // GSO has no selected PMTU packet, and selection ends it
                    // before any pending Transmit timestamp target, so there
                    // is no observation to cancel on rejection (Scheduled
                    // stands, as for scalar output); physical evidence
                    // commits at accept.
                    r.repaired = true;
                    r.finished = false;
                    r.emitted_bytes = s.segment_payload_len;
                    // The first segment's own token; the reservation keeps
                    // the whole range's.
                    let first = packet
                        .tx_timestamp
                        .map(|token| token.part(0, s.segment_payload_len));
                    r.emitted_packet.tx_timestamp = first;
                    if let Some(p) = &mut output.packet {
                        p.tx_timestamp = first;
                    }
                }
                self.refresh(id.slot);
            }
            Ok((output, Some(attempt)))
        } else {
            Ok((output, None))
        }
    }

    /// Read-only form of every check `accept_transmit` performs. Ok(true)
    /// means an immediately following `accept_transmit` with the same `now`
    /// and no intervening Endpoint call succeeds and returns true, so an
    /// embedding can finish all fallible work before a physical submission.
    pub fn preflight_accept_transmit(
        &self,
        now: Instant,
        attempt: crate::TransmitAttempt,
    ) -> Result<bool, EndpointError> {
        let Some(r) = self
            .reservations
            .get(attempt.reservation)
            .and_then(|slot| slot.current.as_ref())
        else {
            return Ok(false);
        };
        if r.attempt != Some(attempt) {
            return Ok(false);
        }
        let count = if r.repaired {
            r.emitted_bytes
        } else {
            r.departure.map_or(0, |d| d.payload)
        };
        if let Some(id) = r.packet.connection {
            let owner = &self.retained_slot(id)?.connection;
            owner.check_time(now)?;
            if let Some(d) = &r.departure {
                owner.validate_reserved_output(now, d, r.offset, count)?;
            }
        }
        self.check_clock(now)?;
        Ok(true)
    }

    pub fn accept_transmit(
        &mut self,
        now: Instant,
        attempt: crate::TransmitAttempt,
    ) -> Result<bool, EndpointError> {
        // The checks of `preflight_accept_transmit`, but the connection's
        // validation of the departure, which `accept_reserved_output` makes
        // first, before it changes anything.
        let Some(r) = self
            .reservations
            .get(attempt.reservation)
            .and_then(|slot| slot.current.as_ref())
        else {
            return Ok(false);
        };
        if r.attempt != Some(attempt) {
            return Ok(false);
        }
        let index = attempt.reservation;
        let connection = r.packet.connection;
        if let Some(id) = connection
            && r.departure.is_none()
        {
            self.retained_slot(id)?.connection.check_time(now)?;
        }
        self.check_clock(now)?;
        let (mut departure, offset, count, finished) = (
            r.departure,
            r.offset,
            if r.repaired {
                r.emitted_bytes
            } else {
                r.departure.map_or(0, |d| d.payload)
            },
            r.finished,
        );
        let mut withdrawn = false;
        if let Some(id) = connection
            && let Some(d) = &mut departure
        {
            withdrawn = self
                .retained_slot_mut(id)?
                .connection
                .accept_reserved_output(now, d, offset, count, finished)?;
        }
        // Checked above.
        self.clock(now)?;
        // A withdrawn suffix was never submitted: release the reservation so
        // the owner reselects that work under its current admission.
        self.complete_reserved_accept(index, departure, finished || withdrawn);
        Ok(true)
    }

    fn complete_reserved_accept(
        &mut self,
        index: usize,
        departure: Option<crate::output_reservation::Departure>,
        finished: bool,
    ) {
        let r = self.reservations[index].current.as_mut().unwrap();
        let connection = r.packet.connection;
        if finished {
            self.clear_reservation(index);
        } else {
            r.departure = departure;
            r.offset += r.emitted_bytes;
            r.sacks += r.emitted_sacks;
            self.set_reservation_attempt(index, None);
        }
        if let Some(id) = connection {
            self.refresh(id.slot);
            // Intermediate fragments must keep the pending child held.
            if finished {
                self.rearm_pending_accept(id);
            }
        }
    }

    fn rearm_pending_accept(&mut self, id: ConnectionId) {
        // A prior Acceptable may have been consumed for an unheld sibling.
        if let Ok(slot) = self.retained_slot(id)
            && let Some(parent) = slot.listener
            && self
                .listener(parent)
                .is_ok_and(|listener| listener.pending.contains(&id))
        {
            self.events.push(self.config.max_connections + parent.slot);
        }
    }

    // Caller certifies this attempt was synchronously rejected before submission;
    // never use for a timeout, asynchronous error, or an uncertain backend result.
    pub fn reject_unsubmitted(
        &mut self,
        attempt: crate::TransmitAttempt,
    ) -> Result<bool, EndpointError> {
        let index = attempt.reservation;
        let Some(r) = self
            .reservations
            .get(index)
            .and_then(|slot| slot.current.as_ref())
        else {
            return Ok(false);
        };
        if r.attempt != Some(attempt) {
            return Ok(false);
        }
        let Some(connection) = r.packet.connection else {
            self.clear_reservation(index);
            return Ok(true);
        };
        let timestamp = r.packet.tx_timestamp;
        if !r.repaired {
            let owner = &mut self.retained_slot_mut(connection)?.connection;
            owner.reject_reserved_output();
            if let Some(token) = timestamp {
                for source in [TxTimestampSource::Software, TxTimestampSource::Hardware] {
                    owner
                        .tx_timestamps
                        .cancel_transmit(token.stream_range(), source);
                }
            }
        }
        self.set_reservation_attempt(index, None);
        self.reservations[index].current.as_mut().unwrap().repaired = true;
        Ok(true)
    }

    // Synchronous, certainly-unsubmitted first RACK repair only. Unlike MTU
    // rejection, discard the old attempt and resume connection input without
    // aborting. False leaves unsupported selections/prefixes wholly unchanged.
    pub fn cancel_unsubmitted_repair(
        &mut self,
        attempt: crate::TransmitAttempt,
    ) -> Result<bool, EndpointError> {
        self.cancel_local_output(attempt, None)
    }

    // Caller certifies a synchronous local rejection, not a WouldBlock or an
    // unknown/asynchronous result. Unsupported output keeps its reservation.
    pub fn reject_local_output(
        &mut self,
        now: Instant,
        attempt: crate::TransmitAttempt,
    ) -> Result<bool, EndpointError> {
        self.clock(now)?;
        self.cancel_local_output(attempt, Some(now))
    }

    /// Withdraw an attempt certified never submitted because its next hop
    /// could not be resolved (RFC 4861 section 7.2.2), for every segment
    /// kind, without a departure: no RTT sample, retransmission count,
    /// backoff step, ledger commit, departure charge or timestamp
    /// completion. A pure ACK or RST is dropped like any lost control (the
    /// peer's own retransmission elicits another). Retransmittable output
    /// (SYN, SYN-ACK, data, FIN) is restored as unselected and retried by
    /// the connection's local-failure retry clock, no earlier than the
    /// current RTO; its application deadline still ends it. A selection
    /// that cannot be restored exactly, or the suffix after an accepted
    /// prefix, is released as unsent output instead: its sequence space
    /// stays outstanding without a departure, for the connection's own loss
    /// recovery, on the same retry clock. `error` is the owner's advice,
    /// recorded as its soft error (RFC 1122 section 4.2.3.9: no abort).
    /// False only for an attempt that is not the reservation's current one.
    pub fn discard_unsubmitted(
        &mut self,
        now: Instant,
        attempt: crate::TransmitAttempt,
        error: Option<crate::NetworkError>,
    ) -> Result<bool, EndpointError> {
        self.clock(now)?;
        let index = attempt.reservation;
        let Some(r) = self
            .reservations
            .get(index)
            .and_then(|s| s.current.as_ref())
        else {
            return Ok(false);
        };
        if r.attempt != Some(attempt) {
            return Ok(false);
        }
        let Some(id) = r.packet.connection else {
            self.clear_reservation(index);
            return Ok(true);
        };
        let flags = self.reservations[index].bytes[13];
        let sequence = flags & (wire::SYN | wire::FIN) != 0
            || r.departure.is_some_and(|d| d.payload != 0)
            || self.reservations[index].is_shared();
        let (timestamp, departure, offset) = (r.packet.tx_timestamp, r.departure, r.offset);
        let owner = &mut self.retained_slot_mut(id)?.connection;
        if flags & wire::RST != 0 || !sequence {
            owner.reject_reserved_output();
        } else if offset != 0 || !owner.cancel_reserved_unsubmitted(now)? {
            owner.release_reserved_unsubmitted(now, departure.as_ref())?;
        }
        // An accepted prefix keeps the timestamp its departure owns.
        if let Some(token) = timestamp.filter(|_| offset == 0) {
            for source in [TxTimestampSource::Software, TxTimestampSource::Hardware] {
                owner
                    .tx_timestamps
                    .cancel_transmit(token.stream_range(), source);
            }
        }
        self.clear_reservation(index);
        if let Some(error) = error
            && self
                .retained_slot_mut(id)?
                .connection
                .unsubmitted_network_error(now, error)?
            && self.config.error_reports
            && let Some(listener) = self.retained_slot(id)?.listener
            && self.passive_errors.len() < self.config.max_connections
        {
            let tuple = self.retained_slot(id)?.connection.tuple();
            self.passive_errors.push_back(Event::PassiveError {
                listener,
                tuple,
                error,
            });
        }
        self.refresh(id.slot);
        self.rearm_pending_accept(id);
        Ok(true)
    }

    fn cancel_local_output(
        &mut self,
        attempt: crate::TransmitAttempt,
        resource: Option<Instant>,
    ) -> Result<bool, EndpointError> {
        let index = attempt.reservation;
        let Some(r) = self
            .reservations
            .get(index)
            .and_then(|s| s.current.as_ref())
        else {
            return Ok(false);
        };
        if r.attempt != Some(attempt) || r.offset != 0 {
            return Ok(false);
        }
        let Some(id) = r.packet.connection else {
            return Ok(false);
        };
        let timestamp = r.packet.tx_timestamp;
        let owner = &mut self.retained_slot_mut(id)?.connection;
        let cancelled = if let Some(now) = resource {
            owner.cancel_reserved_resource(now)? || owner.cancel_reserved_repair()
        } else {
            owner.cancel_reserved_repair()
        };
        if !cancelled {
            return Ok(false);
        }
        if let Some(token) = timestamp {
            for source in [TxTimestampSource::Software, TxTimestampSource::Hardware] {
                owner
                    .tx_timestamps
                    .cancel_transmit(token.stream_range(), source);
            }
        }
        self.clear_reservation(index);
        self.refresh(id.slot);
        Ok(true)
    }

    pub fn reserved_application_deadline(
        &self,
        attempt: crate::TransmitAttempt,
    ) -> Result<Option<Instant>, EndpointError> {
        let Some(r) = self
            .reservations
            .get(attempt.reservation)
            .and_then(|s| s.current.as_ref())
            .filter(|r| r.abandon_attempt == attempt)
        else {
            return Ok(None);
        };
        let Some(id) = r.packet.connection else {
            return Ok(None);
        };
        Ok(self.retained_slot(id)?.connection.application_deadline())
    }

    // Like abandon_transmit, this requires certain non-submission of the held
    // suffix. Only the application's absolute deadline may authorize expiry.
    pub fn expire_reserved_application(
        &mut self,
        now: Instant,
        attempt: crate::TransmitAttempt,
    ) -> Result<bool, EndpointError> {
        self.clock(now)?;
        let Some(r) = self
            .reservations
            .get(attempt.reservation)
            .and_then(|s| s.current.as_ref())
            .filter(|r| r.abandon_attempt == attempt)
        else {
            return Ok(false);
        };
        let Some(id) = r.packet.connection else {
            return Ok(false);
        };
        if !self
            .retained_slot_mut(id)?
            .connection
            .expire_reserved_application(now)?
        {
            return Ok(false);
        }
        self.clear_reservation(attempt.reservation);
        self.refresh(id.slot);
        self.rearm_pending_accept(id);
        Ok(true)
    }

    // Fail the owner and discard only the remaining reservation. Caller certifies
    // any pending attempt was not submitted (e.g. an adapter-owned WouldBlock
    // deadline). The latest handle survives rejection, accepted prefixes and
    // encoding errors for this operation only. Never use for an uncertain submit.
    pub fn abandon_transmit(
        &mut self,
        attempt: crate::TransmitAttempt,
    ) -> Result<bool, EndpointError> {
        let index = attempt.reservation;
        let Some(r) = self
            .reservations
            .get(index)
            .and_then(|slot| slot.current.as_ref())
        else {
            return Ok(false);
        };
        if r.abandon_attempt != attempt {
            return Ok(false);
        }
        if let Some(id) = r.packet.connection {
            let slot = self.retained_slot_mut(id)?;
            slot.connection.abandon_reserved_output();
            slot.closed_output_drained = true;
            self.clear_reservation(index);
            self.refresh(id.slot);
            self.rearm_pending_accept(id);
        } else {
            self.clear_reservation(index);
        }
        Ok(true)
    }

    // The ACK the first TIME-WAIT record in line owes, built as
    // `Connection::transmit` builds a TIME-WAIT connection's and sent on the
    // stateless lane, as Linux answers for a timewait socket from its
    // control socket. None if it could not fit its path and was discarded,
    // as a stateless reply would be.
    #[allow(clippy::type_complexity)]
    fn time_wait_ack(
        &mut self,
        now: Instant,
        out: &mut [u8],
        reply: Option<&mut &mut dyn FnMut(IpMetadata, Option<ntcp_path::LinkId>) -> Option<u16>>,
    ) -> Result<Option<(PollTransmit, Option<ntcp_path::LinkId>)>, EndpointError> {
        let index = self.time_wait.first_output().unwrap();
        let record = self.time_wait.record(index);
        let tuple = record.tuple;
        let ip = IpMetadata {
            source: tuple.tuple.local.ip(),
            destination: tuple.tuple.remote.ip(),
        };
        let (header, options, option_len) = record.ack(now, &self.config.connection);
        let (ipv4_options, hop_limit, dscp, mark) = (
            record.ipv4_options,
            record.hop_limit,
            record.dscp,
            record.mark,
        );
        let mut path_header = record.reply_header;
        if ip.destination.is_ipv6()
            && let Some(resize) = reply
        {
            path_header = resize(ip, tuple.zone);
        }
        if let Some(policy) = self.config.connection.pmtud {
            let ip_len = match (ip.source, ip.destination) {
                (IpAddr::V4(source), IpAddr::V4(destination)) => {
                    20 + ipv4_options.encode(source, destination, 0, &mut [0; 40])?.1 as u32
                }
                _ => path_header.map_or(40, u32::from),
            };
            let route_mtu = self
                .destination_route(ip.destination)
                .and_then(|route| route.mtu);
            let mtu = policy
                .first_hop_mtu
                .min(policy.route_mtu.unwrap_or(u32::MAX))
                .min(route_mtu.unwrap_or(u32::MAX));
            if mtu.saturating_sub(ip_len) < 20 + option_len as u32 {
                let record = self.time_wait.record_mut(index);
                record.ack_pending = false;
                record.challenge_pending = false;
                self.time_wait.update(index, false);
                self.oversized_control += 1;
                return Ok(None);
            }
        }
        let partial = self.config.connection.tcp_checksum_offload;
        let len = wire::encode_with(ip, header, &options[..option_len], &[], out, partial)
            .map_err(Error::Wire)?;
        self.time_wait
            .record_mut(index)
            .sent(now, &self.config.connection);
        self.time_wait.update(index, false);
        self.control_turn = false;
        Ok(Some((
            PollTransmit {
                packet: Some(Transmit {
                    connection: None,
                    tx_timestamp: None,
                    ecn: 0,
                    ipv4_options,
                    ip,
                    len,
                    hop_limit,
                    dscp,
                    mark,
                }),
                more_work: self.has_pending_output(),
            },
            tuple.zone,
        )))
    }

    pub fn poll_transmit(
        &mut self,
        now: Instant,
        out: &mut [u8],
        budget: usize,
    ) -> Result<PollTransmit, EndpointError> {
        self.poll_transmit_inner(now, out, budget, false, None, None, None, None)
            .map(|(output, _)| output)
    }

    // Also returns the zone a selected stateless reply was queued with.
    #[allow(clippy::too_many_arguments)] // Selection policy and reusable output carriers stay explicit.
    fn poll_transmit_inner(
        &mut self,
        now: Instant,
        out: &mut [u8],
        budget: usize,
        reserve: bool,
        selected: Option<Option<ConnectionId>>,
        mut gso: Option<crate::output_reservation::GsoBuffer<'_>>,
        mut shared: Option<&mut Vec<crate::Payload>>,
        mut reply: ReplyHeader<'_>,
    ) -> Result<(PollTransmit, Option<ntcp_path::LinkId>), EndpointError> {
        self.clock(now)?;
        for _ in 0..budget {
            if !self.cleanup.is_empty() {
                self.cleanup_one();
            }
            let stateless_held = self.reservation_of(None).is_some();
            let next = self.output.iter().find(|&index| {
                let id = self.id(index);
                !self.is_output_reserved(id) && selected.is_none_or(|owner| owner == Some(id))
            });
            if !stateless_held
                && self.stateless_pending()
                && selected.is_none_or(|owner| owner.is_none())
                && (self.control_turn || next.is_none() || selected == Some(None))
            {
                if self.control.is_empty() {
                    match self.time_wait_ack(now, out, reply.as_mut())? {
                        Some(output) => return Ok(output),
                        None => continue,
                    }
                }
                let (ip, header, ipv4_options, mut echo, mut path_header, zone) =
                    *self.control.front().unwrap();
                // A managed drain sizes an IPv6 reply with the header of the
                // path its provider selects for it now: routes replaced since
                // queueing must neither refuse a reply that fits nor shrink
                // one that no longer does.
                if ip.destination.is_ipv6()
                    && let Some(resize) = reply.as_mut()
                {
                    path_header = resize(ip, zone);
                }
                if let Some(policy) = self.config.connection.pmtud {
                    let ip_len = match (ip.source, ip.destination) {
                        (IpAddr::V4(source), IpAddr::V4(destination)) => {
                            20 + ipv4_options.encode(source, destination, 0, &mut [0; 40])?.1 as u32
                        }
                        // The embedding places the reply after its path's
                        // complete header (an SR route's SRH included).
                        _ => path_header.map_or(40, u32::from),
                    };
                    let route_mtu = self
                        .destination_route(ip.destination)
                        .and_then(|route| route.mtu);
                    let mtu = policy
                        .first_hop_mtu
                        .min(policy.route_mtu.unwrap_or(u32::MAX))
                        .min(route_mtu.unwrap_or(u32::MAX));
                    let budget = mtu.saturating_sub(ip_len);
                    if budget < 20 {
                        // Stateless replies cannot fragment or drop a required
                        // source route or Segment Routing Header.
                        self.control.pop_front();
                        self.oversized_control += 1;
                        continue;
                    }
                    if budget < 32 {
                        echo = None;
                    }
                }
                let mut options = [1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0];
                if let Some(echo) = echo {
                    options[8..].copy_from_slice(&echo.to_be_bytes());
                }
                let options = if echo.is_some() { &options[..] } else { &[] };
                let partial = self.config.connection.tcp_checksum_offload;
                let len = wire::encode_with(ip, header, options, &[], out, partial)
                    .map_err(Error::Wire)?;
                self.control.pop_front();
                self.control_turn = false;
                return Ok((
                    PollTransmit {
                        packet: Some(Transmit {
                            connection: None,
                            tx_timestamp: None,
                            ecn: 0,
                            ipv4_options,
                            ip,
                            len,
                            hop_limit: self.config.hop_limit,
                            dscp: self.config.dscp,
                            mark: 0,
                        }),
                        more_work: self.has_pending_output(),
                    },
                    zone,
                ));
            }
            let Some(index) = next else {
                continue;
            };
            self.output.remove(index);
            let connection = self.id(index);
            let slot = self.slots[index].as_mut().unwrap();
            let tuple = slot.connection.tuple();
            let output = if let Some(parts) = shared.as_deref_mut() {
                slot.connection.transmit_shared_selected(now, out, parts)
            } else if reserve {
                slot.connection.transmit_selected_with_gso(
                    now,
                    out,
                    true,
                    gso.as_mut()
                        .map(|buffer| crate::output_reservation::GsoBuffer {
                            limits: buffer.limits,
                            payload: &mut *buffer.payload,
                        }),
                )
            } else {
                slot.connection.transmit(now, out)
            };
            match output {
                Ok(Some(len)) => {
                    slot.closed_output_drained = slot.connection.state() == State::Closed;
                    let hop_limit = slot.hop_limit;
                    let dscp = slot.dscp;
                    let mark = slot.mark;
                    let ecn = slot.connection.last_output_ecn();
                    let ipv4_options = slot.ipv4_options;
                    let tx_timestamp = slot
                        .connection
                        .last_output_range
                        .map(|range| TxTimestampToken::new(connection, range));
                    self.control_turn = true;
                    if !reserve {
                        self.refresh(index);
                    } else {
                        // Preserve candidate order, but do not reclaim before capture.
                        self.output.push(index);
                    }
                    return Ok((
                        PollTransmit {
                            packet: Some(Transmit {
                                connection: Some(connection),
                                tx_timestamp,
                                ecn,
                                ipv4_options,
                                ip: IpMetadata {
                                    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.1
                                    //# At all other times, a previous segment has either been sent or
                                    //# received on this connection, and TCP implementations MUST use the
                                    //# same local address that was used in those previous segments (MUST-
                                    //# 45).
                                    source: tuple.local.ip(),
                                    destination: tuple.remote.ip(),
                                },
                                len,
                                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.9
                                //# TCP implementations
                                //# SHOULD pass the current Differentiated Services field value without
                                //# change to the IP layer, when it sends segments on the connection
                                //# (SHLD-22).
                                hop_limit,
                                dscp,
                                mark,
                            }),
                            more_work: self.has_pending_output(),
                        },
                        None,
                    ));
                }
                Ok(None) => {
                    self.deadlines.set(index, slot.deadline());
                    if slot.connection.state() == State::Closed {
                        slot.closed_output_drained = true;
                        if slot.released && !slot.connection.reset_pending() {
                            self.reclaim(index);
                        }
                    }
                }
                Err(error) => {
                    self.output.push(index);
                    return Err(error.into());
                }
            }
        }
        Ok((
            PollTransmit {
                packet: None,
                more_work: self.has_pending_output(),
            },
            None,
        ))
    }
}

#[cfg(test)]
mod recovery_observation_tests {
    use super::*;
    use crate::InitialWindow;
    use alloc::vec;

    fn packet(endpoint: &mut Endpoint, now: u64) -> (Transmit, Vec<u8>) {
        let mut bytes = vec![0; 2000];
        let packet = endpoint
            .poll_transmit(now, &mut bytes, 16)
            .unwrap()
            .packet
            .unwrap();
        bytes.truncate(packet.len);
        (packet, bytes)
    }

    #[test]
    fn transport_info_samples_endpoint_clock_for_dormant_connection_without_mutation() {
        let cfg = EndpointConfig::default();
        let mut endpoint = Endpoint::new(cfg, [1; 32], 0, |_| true).unwrap();
        let id = endpoint
            .connect(
                0,
                "192.0.2.1:40000".parse().unwrap(),
                "192.0.2.2:8080".parse().unwrap(),
            )
            .unwrap();
        endpoint.write(id, b"queued during handshake").unwrap();
        assert_eq!(
            endpoint
                .slot(id)
                .unwrap()
                .connection
                .transport_info()
                .busy_time_us,
            0
        );
        // Servicing the endpoint need not touch this connection's timer or output.
        endpoint.on_timeout(100_000, 0).unwrap();
        let info = crate::allocation_tests::fail_after(0, || endpoint.transport_info(id).unwrap());
        assert_eq!(info.busy_time_us, 100_000);
        assert_eq!(info.last_data_recv_ms, 100);
        assert_eq!(endpoint.transport_info(id).unwrap(), info);
        assert_eq!(
            endpoint
                .slot(id)
                .unwrap()
                .connection
                .transport_info()
                .busy_time_us,
            0
        );
    }

    #[test]
    fn caller_units_endpoint_isn_control_epoch_deadlines_and_guards() {
        use crate::connection::{CallerTimebase, TimestampGranularity};
        for granularity in [
            TimestampGranularity::Milliseconds,
            TimestampGranularity::Microseconds,
        ] {
            let trace = |scale: u64| {
                let timebase = CallerTimebase {
                    units_per_second: 1_000_000 * scale,
                    ..CallerTimebase::default()
                };
                let cfg = EndpointConfig {
                    max_connections: 1,
                    max_listeners: 1,
                    max_control_packets: 1,
                    connection: ConnectionConfig {
                        timestamps: true,
                        timestamp_granularity: granularity,
                        timebase,
                        send_capacity: 64,
                        receive_capacity: 64,
                        mss: 8,
                        ..ConnectionConfig::default()
                    },
                    ..EndpointConfig::default()
                };
                let tuple = Tuple {
                    local: "192.0.2.1:40000".parse().unwrap(),
                    remote: "192.0.2.2:8080".parse().unwrap(),
                };
                let mut endpoint = Endpoint::new(cfg.clone(), [1; 32], 0, |_| true).unwrap();
                let first_isn = endpoint.isn(ScopedTuple::unscoped(tuple));
                endpoint.clock(4000 * scale).unwrap();
                let next_isn = endpoint.isn(ScopedTuple::unscoped(tuple));
                assert_eq!(next_isn.wrapping_sub(first_isn), 1000);
                let id = endpoint
                    .connect(4000 * scale, tuple.local, tuple.remote)
                    .unwrap();
                let (_, syn) = packet(&mut endpoint, 4000 * scale);
                assert_eq!(endpoint.next_deadline(), Some(1_004_000 * scale));
                assert_eq!(endpoint.transport_info(id).unwrap().rto_us, 1_000_000);
                assert_eq!(
                    endpoint.clock(4000 * scale - 1),
                    Err(Error::TimeWentBackwards.into())
                );
                let half = (1u64 << 31) * granularity.tick_us() * scale;
                assert_eq!(
                    endpoint.clock(4000 * scale + half),
                    Err(Error::AmbiguousTimeJump.into())
                );
                endpoint.clock(4000 * scale + half - 1).unwrap();
                endpoint.clock(4000 * scale + half).unwrap();
                // Control budget counts survive draining output until one physical second.
                let mut control = Endpoint::new(cfg.clone(), [1; 32], 0, |_| true).unwrap();
                let ip = IpMetadata {
                    source: tuple.local.ip(),
                    destination: tuple.remote.ip(),
                };
                let incoming = wire::parse(ip, &syn).unwrap();
                control.reset_for(ip, None, &incoming, None);
                assert_eq!(control.control_count, 1);
                packet(&mut control, 0);
                control.clock(1_000_000 * scale - 1).unwrap();
                control.reset_for(ip, None, &incoming, None);
                assert!(control.control.is_empty());
                control.clock(1_000_000 * scale).unwrap();
                control.reset_for(ip, None, &incoming, None);
                assert_eq!(control.control.len(), 1);
                let (_, reset) = packet(&mut control, 1_000_000 * scale);
                let mut passive = Endpoint::new(cfg.clone(), [2; 32], 0, |_| true).unwrap();
                passive.listen(tuple.remote, 1).unwrap();
                passive.input(0, ip, &syn).unwrap();
                let child = passive
                    .connection_id(Tuple {
                        local: tuple.remote,
                        remote: tuple.local,
                    })
                    .unwrap();
                passive.abort(child).unwrap();
                let (_, reset_child) = packet(&mut passive, 0);
                assert_ne!(reset_child[13] & RST, 0);
                // Its reset sent, the child leaves nothing behind.
                assert!(!passive.connection_exists(child));
                assert_eq!(passive.next_deadline(), None);
                // Absolute end-of-clock deadlines saturate, rather than wrapping early.
                let mut end = Endpoint::new(cfg, [1; 32], u64::MAX - 1, |_| true).unwrap();
                end.connect(u64::MAX - 1, tuple.local, tuple.remote)
                    .unwrap();
                packet(&mut end, u64::MAX - 1);
                assert_eq!(end.next_deadline(), Some(u64::MAX));
                (first_isn, next_isn, syn, reset)
            };
            assert_eq!(trace(1), trace(1000));
        }
    }

    #[test]
    fn sender_metadata_global_peak_precedes_external_producer_admission() {
        let config = EndpointConfig {
            preallocate_connections: 0,
            connection: ConnectionConfig {
                send_capacity: 128,
                receive_capacity: 1,
                mss: 64,
                ..ConnectionConfig::default()
            },
            ..EndpointConfig::default()
        };
        let mut endpoint = Endpoint::new(config, [1; 32], 0, |_| true).unwrap();
        let id = endpoint
            .connect(
                0,
                "192.0.2.1:40000".parse().unwrap(),
                "192.0.2.2:8080".parse().unwrap(),
            )
            .unwrap();
        let charged = endpoint.buffer_bytes();
        endpoint.config.max_buffer_bytes = charged;
        let request = TxTimestampRequest::default();
        let result = crate::allocation_tests::fail_after(0, || {
            endpoint.prepare_write_admission(id, 128, None, request)
        });
        // Refused for memory, it waits, as Linux's sk_stream_wait_memory.
        assert_eq!(result, Err(Error::WouldBlock.into()));
        assert_eq!(endpoint.memory_throttled_writes(), 1);
        assert_eq!(endpoint.send_progress(id).unwrap().queued_end, 0);
        assert_eq!(endpoint.buffer_bytes(), charged);
        // Admission allocates the send ring and grows the ledgers, charged as
        // allocated; the write that follows allocates nothing.
        endpoint.config.max_buffer_bytes = usize::MAX;
        assert_eq!(
            endpoint.prepare_write_admission(id, 128, None, request),
            Ok(128)
        );
        let prepared = endpoint.buffer_bytes();
        assert!(prepared > charged);
        assert_eq!(
            prepared,
            endpoint.slot(id).unwrap().connection.buffer_charge()
        );
        crate::allocation_tests::fail_after(0, || {
            assert_eq!(
                endpoint.write_with_timestamp(id, &[1; 128], false, true, None, request),
                Ok(128)
            );
        });
        assert_eq!(endpoint.buffer_bytes(), prepared);
    }

    #[test]
    fn buffer_resize_admission_accounts_for_staged_peak() {
        for (send, receive) in [(2048, 1), (1024, 2048), (2048, 2048)] {
            let config = EndpointConfig {
                preallocate_connections: 0,
                connection: ConnectionConfig {
                    send_capacity: 1024,
                    receive_capacity: 1,
                    mss: 64,
                    ..ConnectionConfig::default()
                },
                ..EndpointConfig::default()
            };
            let mut endpoint = Endpoint::new(config, [1; 32], 0, |_| true).unwrap();
            let id = endpoint
                .connect(
                    0,
                    "192.0.2.1:40000".parse().unwrap(),
                    "192.0.2.2:8080".parse().unwrap(),
                )
                .unwrap();
            let old = endpoint.buffer_bytes();
            let peak = endpoint
                .slot(id)
                .unwrap()
                .connection
                .resize_peak_charge(receive)
                .unwrap();
            // A send limit allocates nothing; a receive ring is staged
            // beside the original.
            assert_eq!(
                peak - old,
                ReceiveBuffer::allocation_bytes(receive).unwrap() * usize::from(receive > 1)
            );
            if receive > 1 {
                // The final replacement fits, but its staging alongside the
                // original does not.
                endpoint.config.max_buffer_bytes = peak - 1;
                assert_eq!(
                    endpoint.set_buffer_capacities(id, send, receive),
                    Err(Error::NoMemory.into())
                );
                assert_eq!(endpoint.buffer_capacities(id).unwrap(), (1024, 1));
                assert_eq!(endpoint.buffer_bytes(), old);
            }
            endpoint.config.max_buffer_bytes = peak;
            endpoint.set_buffer_capacities(id, send, receive).unwrap();
            assert_eq!(endpoint.buffer_capacities(id).unwrap(), (send, receive));
            assert_eq!(
                endpoint.buffer_bytes(),
                endpoint.slot(id).unwrap().connection.buffer_charge()
            );
            assert!(endpoint.buffer_bytes() < peak || receive == 1);
            endpoint.config.max_buffer_bytes = endpoint.buffer_bytes();
            endpoint.set_buffer_capacities(id, 1, 1).unwrap();
            assert_eq!(endpoint.buffer_bytes(), endpoint.config.max_buffer_bytes);
        }
    }

    #[test]
    fn receive_pool_transfers_charges_and_restores_failed_table_insertions() {
        for target in [0, 1] {
            let config = EndpointConfig {
                max_connections: 1,
                max_listeners: 1,
                preallocate_connections: target,
                connection: ConnectionConfig {
                    receive_capacity: 17,
                    send_capacity: 17,
                    mss: 8,
                    ..ConnectionConfig::default()
                },
                ..EndpointConfig::default()
            };
            let tuple = Tuple {
                local: "192.0.2.1:40000".parse().unwrap(),
                remote: "192.0.2.2:8080".parse().unwrap(),
            };
            let mut endpoint = Endpoint::new(config, [1; 32], 0, |_| true).unwrap();
            let charge = endpoint.per_connection_bytes;
            assert_eq!(charge, Connection::open_bytes(17, 8).unwrap());
            let pool_capacity = endpoint.receive_pool.capacity();
            // A full bounded probe table can fail insertion after construction.
            let mut occupied = tuple;
            occupied.remote.set_port(occupied.remote.port() + 1);
            endpoint.tuples.entries.fill(Entry::Occupied(ScopedTuple::unscoped(occupied), 0));
            let connection = endpoint.new_connection(tuple, 100, None).unwrap();
            assert!(endpoint.receive_pool.is_empty());
            assert_eq!(endpoint.buffer_bytes(), charge);
            assert_eq!(
                endpoint.insert(connection, None, None),
                Err(EndpointError::LimitReached)
            );
            assert_eq!(endpoint.receive_pool.len(), target);
            assert_eq!(endpoint.buffer_bytes(), target * charge);
            endpoint.tuples.entries.fill(Entry::Empty);
            let id = endpoint.connect(0, tuple.local, tuple.remote).unwrap();
            assert!(endpoint.receive_pool.is_empty());
            assert_eq!(endpoint.buffer_bytes(), charge);
            let mut remote = tuple.remote;
            remote.set_port(remote.port() + 1);
            assert_eq!(
                endpoint.connect(0, tuple.local, remote),
                Err(EndpointError::LimitReached)
            );
            endpoint.abort(id).unwrap();
            endpoint.release(id).unwrap();
            endpoint.poll_transmit(0, &mut [0; 128], 16).unwrap();
            assert_eq!(endpoint.receive_pool.len(), target);
            assert_eq!(endpoint.receive_pool.capacity(), pool_capacity);
            assert_eq!(endpoint.buffer_bytes(), target * charge);
            assert_eq!(
                endpoint.buffer_bytes(),
                (endpoint.slots.iter().flatten().count() + endpoint.receive_pool.len()) * charge
            );
        }
    }

    #[test]
    fn reserved_tuple_insert_rejects_duplicates_and_replacing_a_live_owner() {
        let config = EndpointConfig {
            max_connections: 3,
            ..EndpointConfig::default()
        };
        let tuple = Tuple {
            local: "192.0.2.1:40000".parse().unwrap(),
            remote: "192.0.2.2:8080".parse().unwrap(),
        };
        let mut a = Endpoint::new(config.clone(), [1; 32], 0, |_| true).unwrap();
        let mut b = Endpoint::new(config, [2; 32], 0, |_| true).unwrap();
        b.listen(tuple.remote, 1).unwrap();
        a.connect(0, tuple.local, tuple.remote).unwrap();
        let (tx, bytes) = packet(&mut a, 0);
        b.input(0, tx.ip, &bytes).unwrap();
        let tuple = Tuple {
            local: tuple.remote,
            remote: tuple.local,
        };
        let owner = b.connection_id(tuple).unwrap();
        b.abort(owner).unwrap(); // Terminal pending reset, automatically unlinked/released.
        let charge = b.buffer_bytes();
        // The owner is not in TIME-WAIT, and no record holds the tuple.
        for replaces in [
            None,
            Some(Target::Connection(owner.slot)),
            Some(Target::TimeWait(0)),
        ] {
            let connection = b.new_connection(tuple, 100, None).unwrap();
            assert_eq!(
                b.insert(connection, None, replaces),
                Err(EndpointError::AddressInUse)
            );
            assert_eq!(b.connection_id(tuple), Some(owner));
            assert_eq!(b.buffer_bytes(), charge);
        }
        let (tx, _) = packet(&mut b, 0);
        assert_eq!(tx.connection, Some(owner));
        // Its reset sent, the released owner is reclaimed with its tuple.
        assert_eq!(b.next_deadline(), None);
        assert!(!b.connection_exists(owner));
        assert_eq!(b.connection_id(tuple), None);
    }

    #[test]
    fn rack_deadline_budget_ready_queue_and_stable_owner() {
        let config = EndpointConfig {
            max_connections: 4,
            max_listeners: 1,
            connection: ConnectionConfig {
                mss: 1000,
                sack: true,
                rack: true,
                prr: true,
                prr_pacing: false, // Fixed-time ready-queue oracle, not pacing.
                initial_window: InitialWindow::Iw10,
                nagle: false,
                ..ConnectionConfig::default()
            },
            ..EndpointConfig::default()
        };
        let tuple = Tuple {
            local: "192.0.2.1:40000".parse().unwrap(),
            remote: "192.0.2.2:8080".parse().unwrap(),
        };
        let mut a = Endpoint::new(config.clone(), [1; 32], 0, |_| true).unwrap();
        let mut b = Endpoint::new(config, [2; 32], 0, |_| true).unwrap();
        let listener = b.listen(tuple.remote, 4).unwrap();
        let client = a.connect(0, tuple.local, tuple.remote).unwrap();
        assert_eq!(a.connection_id(tuple), Some(client));
        assert!(a.connection_exists(client));
        assert!(!a.connection_exists(ConnectionId {
            generation: client.generation + 1,
            ..client
        }));
        let (tx, bytes) = packet(&mut a, 0);
        assert_eq!(tx.connection, Some(client));
        b.input(0, tx.ip, &bytes).unwrap();
        let (tx, bytes) = packet(&mut b, 0);
        let child = tx.connection.unwrap();
        a.input(100_000, tx.ip, &bytes).unwrap();
        let (tx, bytes) = packet(&mut a, 100_000);
        b.input(100_000, tx.ip, &bytes).unwrap();
        assert_eq!(b.accept(listener).unwrap(), child);
        a.write(client, &[1; 10_000]).unwrap();
        let mut sent = Vec::new();
        for _ in 0..10 {
            sent.push(packet(&mut a, 100_000));
        }
        let (tx, bytes) = &sent[7];
        b.input(200_000, tx.ip, bytes).unwrap();
        let (tx, bytes) = packet(&mut b, 200_000);
        a.input(200_000, tx.ip, &bytes).unwrap();
        assert_eq!(a.next_deadline(), Some(225_000));
        assert!(!a.on_timeout(224_999, 1).unwrap());
        assert!(a.on_timeout(225_000, 0).unwrap());
        assert!(!a.on_timeout(225_000, 1).unwrap());
        assert!(a.has_pending_output());
        let info = a.transport_info(client).unwrap();
        assert_eq!((info.recovery, info.lost, info.sacked), (true, 7, 1));
        assert_eq!(b.transport_info(child).unwrap().receive_used, 1000);
        a.enable_output_reservations().unwrap();
        let mut bytes = vec![0; 1500];
        assert!(a.poll_reserved_transmit(225_000, &mut [0; 20], 16).is_err());
        assert!(a.has_pending_output());
        let (output, attempt) = a.poll_reserved_transmit(225_000, &mut bytes, 16).unwrap();
        let tx = output.packet.unwrap();
        assert_eq!(tx.connection, Some(client));
        assert!(a.reject_unsubmitted(attempt.unwrap()).unwrap());
        let (output, attempt) = a.poll_reserved_transmit(225_000, &mut bytes, 16).unwrap();
        let tx = output.packet.unwrap();
        bytes.truncate(tx.len);
        assert!(a.accept_transmit(225_000, attempt.unwrap()).unwrap());
        assert_eq!(
            wire::parse(tx.ip, &bytes).unwrap().header.sequence,
            wire::parse(sent[0].0.ip, &sent[0].1)
                .unwrap()
                .header
                .sequence
        );
        assert_eq!(wire::parse(tx.ip, &bytes).unwrap().payload.len(), 1000);
        assert!(
            a.poll_transmit(225_000, &mut [0; 1500], 16)
                .unwrap()
                .packet
                .is_none()
        );
        a.abort(client).unwrap();
        a.release(client).unwrap();
        assert!(a.connection_exists(client));
        assert_eq!(a.state(client), Err(EndpointError::InvalidHandle));
        let (tx, bytes) = packet(&mut a, 225_000);
        assert_eq!(tx.connection, Some(client));
        assert_ne!(wire::parse(tx.ip, &bytes).unwrap().header.flags & RST, 0);
        assert_eq!(a.connection_id(tuple), None);
        assert!(!a.connection_exists(client));
        assert_eq!(a.transport_info(client), Err(EndpointError::InvalidHandle));
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.8
    //= type=test
    //= reason=TIME-WAIT expiry removes mapping and reclaims released storage; unreleased terminal handle intentionally survives for status.
    //# If the time-wait timeout expires on a connection, delete the TCB, enter the CLOSED
    //# state, and return.
    fn released_timewait_keeps_its_tuple_and_rejects_reused_generation() {
        let config = EndpointConfig {
            max_connections: 2,
            max_listeners: 1,
            ..EndpointConfig::default()
        };
        let local = "192.0.2.1:40000".parse().unwrap();
        let remote = "192.0.2.2:8080".parse().unwrap();
        let mut a = Endpoint::new(config.clone(), [1; 32], 0, |_| true).unwrap();
        let mut b = Endpoint::new(config, [2; 32], 0, |_| true).unwrap();
        let listener = b.listen(remote, 2).unwrap();
        let client = a.connect(0, local, remote).unwrap();
        let (tx, bytes) = packet(&mut a, 0);
        b.input(0, tx.ip, &bytes).unwrap();
        let (tx, bytes) = packet(&mut b, 0);
        a.input(100, tx.ip, &bytes).unwrap();
        let (tx, bytes) = packet(&mut a, 100);
        b.input(100, tx.ip, &bytes).unwrap();
        let child = b.accept(listener).unwrap();
        a.shutdown(client).unwrap();
        let (tx, bytes) = packet(&mut a, 200);
        b.input(200, tx.ip, &bytes).unwrap();
        let (tx, bytes) = packet(&mut b, 200);
        a.input(200, tx.ip, &bytes).unwrap();
        b.shutdown(child).unwrap();
        let (tx, bytes) = packet(&mut b, 300);
        a.input(300, tx.ip, &bytes).unwrap();
        let (tx, bytes) = packet(&mut a, 300);
        b.input(300, tx.ip, &bytes).unwrap();
        assert_eq!(a.state(client), Ok(State::TimeWait));
        assert!(a.connection_exists(client));
        a.release(client).unwrap();
        // Released, only its TIME-WAIT record remains; the tuple stays taken.
        assert!(!a.connection_exists(client));
        assert_eq!(a.state(client), Err(EndpointError::InvalidHandle));
        let expiry = a.next_deadline().unwrap();
        assert_eq!(
            a.connect(expiry - 1, local, remote),
            Err(EndpointError::AddressInUse)
        );
        a.on_timeout(expiry, 8).unwrap();
        a.poll_transmit(expiry, &mut [0; 2000], 8).unwrap();
        assert!(!a.connection_exists(client));
        let replacement = a.connect(expiry, local, remote).unwrap();
        assert_ne!(replacement, client);
        assert!(a.connection_exists(replacement));
        assert!(!a.connection_exists(client));
        assert_eq!(a.transport_info(client), Err(EndpointError::InvalidHandle));
    }
    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6928#section-12
    //= type=test
    //= reason=Bounded local/remote-IP FIFO records transport-inferred initial/restart burst loss only, not setup success or unmeasured telemetry. Later connections select RFC3390/Rfc5681; cache capacity/eviction/no-loss behavior are tested. Retention is deliberately conservative until FIFO eviction; no deployment monitoring claim.
    //# The sender SHOULD cache such information about connection setups using an initial window larger than allowed by RFC 3390, and new connections SHOULD fall back to the initial window allowed by RFC 3390 if there is evidence of performance issues.
    fn iw10_setup_loss_cache_is_bounded_and_selects_fallback() {
        let cfg = EndpointConfig {
            max_connections: 16,
            max_setup_cache_entries: 1,
            connection: ConnectionConfig {
                mss: 1_000,
                nagle: false,
                initial_window: InitialWindow::Iw10,
                ..ConnectionConfig::default()
            },
            ..EndpointConfig::default()
        };
        let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, |_| true).unwrap();
        let mut now = 0;
        for host in [2, 3] {
            loop {
                let output = a.poll_transmit(now, &mut [0; 2000], 16).unwrap();
                if !output.more_work {
                    break;
                }
            }
            let local = "192.0.2.1:40000".parse().unwrap();
            let remote: SocketAddr = if host == 2 {
                "192.0.2.2:8080"
            } else {
                "192.0.2.3:8080"
            }
            .parse()
            .unwrap();
            let mut b = Endpoint::new(cfg.clone(), [2; 32], now, |_| true).unwrap();
            let listener = b.listen(remote, 4).unwrap();
            let client = a.connect(now, local, remote).unwrap();
            let (tx, bytes) = packet(&mut a, now);
            b.input(now, tx.ip, &bytes).unwrap();
            let (tx, bytes) = packet(&mut b, now + 10);
            a.input(now + 10, tx.ip, &bytes).unwrap();
            let (tx, bytes) = packet(&mut a, now + 20);
            b.input(now + 20, tx.ip, &bytes).unwrap();
            b.accept(listener).unwrap();
            // Merely opting in/establishing is not loss evidence.
            assert!(a.setup_loss_cache.is_empty() || host == 3);
            let mut other = local;
            other.set_port(40_001);
            let fresh = a.connect(now + 20, other, remote).unwrap();
            assert_eq!(a.transport_info(fresh).unwrap().cwnd, 10_000);
            a.write(client, &[7; 5_000]).unwrap();
            // Poll all output including the unrelated fresh SYN, discard data.
            loop {
                let output = a.poll_transmit(now + 30, &mut [0; 2000], 16).unwrap();
                if !output.more_work {
                    break;
                }
            }
            let deadline = a.slot(client).unwrap().connection.next_deadline().unwrap();
            a.on_timeout(deadline, 16).unwrap();
            assert!(a.slot(client).unwrap().connection.iw_setup_loss());
            assert_eq!(a.setup_loss_cache.len(), 1);
            assert_eq!(a.setup_loss_cache[0], (local.ip(), remote.ip(), None));
            other.set_port(40_002);
            let fallback = a.connect(deadline, other, remote).unwrap();
            assert_eq!(a.transport_info(fallback).unwrap().cwnd, 4_000);
            now = deadline + 100;
        }
        let evicted = a
            .connect(
                now,
                "192.0.2.1:40003".parse().unwrap(),
                "192.0.2.2:8080".parse().unwrap(),
            )
            .unwrap();
        assert_eq!(a.transport_info(evicted).unwrap().cwnd, 10_000);
    }
    #[test]
    fn logical_timestamp_discard_releases_only_selected_cookie() {
        let mut endpoint = Endpoint::new(EndpointConfig::default(), [1; 32], 0, |_| true).unwrap();
        let id = endpoint
            .connect(
                0,
                "192.0.2.1:40000".parse().unwrap(),
                "192.0.2.2:8080".parse().unwrap(),
            )
            .unwrap();
        endpoint.set_tx_timestamp_capacity(id, 2).unwrap();
        for cookie in [1, 2] {
            endpoint
                .write_with_timestamp(
                    id,
                    b"x",
                    true,
                    false,
                    None,
                    TxTimestampRequest {
                        cookie,
                        acknowledged: true,
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        endpoint.cancel_tx_timestamps(id).unwrap(); // Ready events are discarded too.
        endpoint.discard_tx_timestamp_request(id, 1).unwrap();
        assert_eq!(endpoint.next_tx_timestamp(id).unwrap().unwrap().cookie, 2);
        assert_eq!(endpoint.next_tx_timestamp(id).unwrap(), None);
        endpoint.set_tx_timestamp_capacity(id, 0).unwrap();
        assert_eq!(endpoint.send_progress(id).unwrap().queued_end, 2);
    }

    #[test]
    fn targeted_tx_cancel_preserves_other_phases_ranges_events_and_generation() {
        use crate::{TxStreamRange, TxTimestampOutcome as Outcome, TxTimestampRequest};
        use TxTimestampSource::{Hardware, Software};
        use TxTimestampStage::{Acknowledged, Scheduled, Transmit};
        let mut endpoint = Endpoint::new(EndpointConfig::default(), [1; 32], 0, |_| true).unwrap();
        let id = endpoint
            .connect(
                0,
                "192.0.2.1:40000".parse().unwrap(),
                "192.0.2.2:8080".parse().unwrap(),
            )
            .unwrap();
        endpoint.set_tx_timestamp_capacity(id, 12).unwrap();
        let request = TxTimestampRequest {
            cookie: 7,
            scheduled: true,
            software_transmit: true,
            hardware_transmit: true,
            acknowledged: true,
        };
        for byte in [b"a", b"b", b"c"] {
            endpoint
                .write_with_timestamp(id, byte, false, false, None, request)
                .unwrap();
        }
        // Equal opaque cookies are deliberately not cancellation identities.
        let range = TxStreamRange { start: 0, end: 2 };
        let token = TxTimestampToken::new(id, range);
        endpoint
            .report_tx_timestamp(token, Software, 123, TxTimestampClock::RealtimeNanoseconds)
            .unwrap();
        endpoint.cancel_tx_timestamp(token, Software).unwrap(); // Preserve ready records.
        endpoint.cancel_tx_timestamp(token, Hardware).unwrap();
        endpoint.cancel_tx_timestamp(token, Hardware).unwrap(); // Idempotent, no extra events.
        endpoint
            .report_tx_timestamp(token, Hardware, 456, TxTimestampClock::RealtimeNanoseconds)
            .unwrap(); // Late completion ignored.
        let mut events = Vec::new();
        while let Some(event) = endpoint.next_tx_timestamp(id).unwrap() {
            events.push(event);
        }
        assert_eq!(events.len(), 4);
        assert!(events.iter().all(|e| e.stage == Transmit && e.target < 2));
        for event in events {
            assert_eq!(
                event.outcome,
                if event.source == Software {
                    Outcome::Recorded {
                        value: 123,
                        clock: TxTimestampClock::RealtimeNanoseconds,
                    }
                } else {
                    Outcome::Cancelled
                }
            );
        }
        let clock = TxTimestampClock::RealtimeNanoseconds;
        let all = TxStreamRange { start: 0, end: 3 };
        for stage in [Scheduled, Acknowledged] {
            endpoint
                .slot_mut(id)
                .unwrap()
                .connection
                .tx_timestamps
                .observe(all, stage, Software, 789, clock);
        }
        for _ in 0..6 {
            let event = endpoint.next_tx_timestamp(id).unwrap().unwrap();
            assert!(matches!(event.stage, Scheduled | Acknowledged));
            assert_eq!(event.outcome, Outcome::Recorded { value: 789, clock });
        }
        let last = TxTimestampToken::new(id, TxStreamRange { start: 2, end: 3 });
        for source in [Software, Hardware] {
            endpoint
                .report_tx_timestamp(last, source, 999, clock)
                .unwrap();
        }
        for _ in 0..2 {
            let event = endpoint.next_tx_timestamp(id).unwrap().unwrap();
            assert_eq!(event.target, 2);
            assert_eq!(event.outcome, Outcome::Recorded { value: 999, clock });
        }
        assert_eq!(endpoint.next_tx_timestamp(id).unwrap(), None);
        endpoint.abort(id).unwrap();
        endpoint.release(id).unwrap();
        assert_eq!(
            endpoint.cancel_tx_timestamp(token, Hardware),
            Err(EndpointError::InvalidHandle)
        );
        endpoint.poll_transmit(1, &mut [0; 128], 16).unwrap();
        endpoint.on_timeout(240_000_001, 16).unwrap();
        endpoint
            .poll_transmit(240_000_001, &mut [0; 128], 16)
            .unwrap();
        let replacement = endpoint
            .connect(
                240_000_001,
                "192.0.2.1:40000".parse().unwrap(),
                "192.0.2.2:8080".parse().unwrap(),
            )
            .unwrap();
        assert_eq!(replacement.slot, id.slot);
        assert_ne!(replacement.generation, id.generation);
        endpoint.set_tx_timestamp_capacity(replacement, 4).unwrap();
        endpoint
            .write_with_timestamp(replacement, b"a", false, false, None, request)
            .unwrap();
        assert_eq!(
            endpoint.cancel_tx_timestamp(token, Hardware),
            Err(EndpointError::InvalidHandle)
        );
        assert_eq!(endpoint.next_tx_timestamp(replacement).unwrap(), None);
    }
    #[test]
    fn tx_timestamp_capacity_peak_budget_allocation_failure_and_buffer_resize() {
        let mut endpoint = Endpoint::new(EndpointConfig::default(), [1; 32], 0, |_| true).unwrap();
        let id = endpoint
            .connect(
                0,
                "192.0.2.1:40000".parse().unwrap(),
                "192.0.2.2:8080".parse().unwrap(),
            )
            .unwrap();
        let baseline = endpoint.buffer_bytes();
        endpoint.config.max_buffer_bytes = baseline;
        assert_eq!(
            endpoint.set_tx_timestamp_capacity(id, 1),
            Err(Error::NoMemory.into())
        );
        assert_eq!(endpoint.buffer_bytes(), baseline);
        endpoint.config.max_buffer_bytes = usize::MAX;
        assert_eq!(
            crate::allocation_tests::fail_after(0, || endpoint.set_tx_timestamp_capacity(id, 4)),
            Err(Error::NoMemory.into())
        );
        assert_eq!(endpoint.buffer_bytes(), baseline);
        endpoint.set_tx_timestamp_capacity(id, 4).unwrap();
        let charge = endpoint.buffer_bytes() - baseline;
        assert!(charge > 0);
        endpoint.config.max_buffer_bytes = baseline + 2 * charge; // Final size fits, staging does not.
        assert_eq!(
            endpoint.set_tx_timestamp_capacity(id, 8),
            Err(Error::NoMemory.into())
        );
        assert_eq!(endpoint.buffer_bytes(), baseline + charge);
        endpoint.config.max_buffer_bytes = baseline + 3 * charge;
        endpoint.set_tx_timestamp_capacity(id, 8).unwrap();
        assert_eq!(endpoint.buffer_bytes(), baseline + 2 * charge);
        assert_eq!(
            crate::allocation_tests::fail_after(0, || endpoint.set_tx_timestamp_capacity(id, 4)),
            Err(Error::NoMemory.into())
        );
        assert_eq!(endpoint.buffer_bytes(), baseline + 2 * charge);
        endpoint.set_tx_timestamp_capacity(id, 4).unwrap();
        assert_eq!(endpoint.buffer_bytes(), baseline + charge);
        let request = crate::TxTimestampRequest {
            cookie: 7,
            scheduled: true,
            software_transmit: true,
            hardware_transmit: true,
            acknowledged: true,
        };
        // The first write allocates the send ring.
        endpoint.config.max_buffer_bytes = usize::MAX;
        endpoint
            .write_with_timestamp(id, b"x", false, false, None, request)
            .unwrap();
        assert_eq!(
            endpoint.set_tx_timestamp_capacity(id, 3),
            Err(Error::WouldBlock.into())
        );
        assert_eq!(
            crate::allocation_tests::fail_after(0, || endpoint.set_tx_timestamp_capacity(id, 8)),
            Err(Error::NoMemory.into())
        );
        endpoint.set_tx_timestamp_capacity(id, 8).unwrap(); // Preserve pending phases.
        endpoint.cancel_tx_timestamps(id).unwrap();
        endpoint.set_tx_timestamp_capacity(id, 4).unwrap(); // Preserve ready events.
        assert_eq!(
            endpoint.set_tx_timestamp_capacity(id, 0),
            Err(Error::WouldBlock.into())
        );
        for _ in 0..4 {
            assert_eq!(
                endpoint.next_tx_timestamp(id).unwrap().unwrap().outcome,
                crate::TxTimestampOutcome::Cancelled
            );
        }
        // Timestamp allocation also remains charged during ordinary buffer resize.
        let (send, receive) = endpoint.buffer_capacities(id).unwrap();
        let peak = endpoint
            .slot(id)
            .unwrap()
            .connection
            .resize_peak_charge(receive * 2)
            .unwrap();
        endpoint.config.max_buffer_bytes = peak - 1;
        assert_eq!(
            endpoint.set_buffer_capacities(id, send * 2, receive * 2),
            Err(Error::NoMemory.into())
        );
        endpoint.config.max_buffer_bytes = peak;
        endpoint
            .set_buffer_capacities(id, send * 2, receive * 2)
            .unwrap();
        assert_eq!(
            endpoint.buffer_bytes(),
            endpoint.slot(id).unwrap().connection.buffer_charge()
        );
        let retained = endpoint.buffer_bytes();
        endpoint.set_tx_timestamp_capacity(id, 0).unwrap();
        assert_eq!(endpoint.buffer_bytes(), retained - charge);
        endpoint.abort(id).unwrap();
        endpoint.release(id).unwrap();
        endpoint.poll_transmit(1, &mut [0; 128], 16).unwrap();
        endpoint.on_timeout(240_000_001, 16).unwrap();
        endpoint
            .poll_transmit(240_000_001, &mut [0; 128], 16)
            .unwrap();
        assert_eq!(endpoint.buffer_bytes(), 0);
        let replacement = endpoint
            .connect(
                240_000_001,
                "192.0.2.1:40000".parse().unwrap(),
                "192.0.2.2:8080".parse().unwrap(),
            )
            .unwrap();
        assert_eq!(replacement.slot, id.slot);
        assert_ne!(replacement.generation, id.generation);
        assert_eq!(
            endpoint.write_with_timestamp(replacement, b"x", false, false, None, request),
            Err(Error::WouldBlock.into())
        );
    }
    #[test]
    fn rx_timestamp_capacity_budget_resize_rollback_and_release() {
        use crate::{RxTimestamp, TimestampClock};
        let mut endpoint = Endpoint::new(EndpointConfig::default(), [1; 32], 0, |_| true).unwrap();
        let id = endpoint
            .connect(
                0,
                "192.0.2.1:40000".parse().unwrap(),
                "192.0.2.2:8080".parse().unwrap(),
            )
            .unwrap();
        let baseline = endpoint.buffer_bytes();
        endpoint.config.max_buffer_bytes = baseline;
        assert_eq!(
            endpoint.set_rx_timestamp_capacity(id, 1),
            Err(Error::NoMemory.into())
        );
        endpoint.config.max_buffer_bytes = usize::MAX;
        assert_eq!(
            crate::allocation_tests::fail_after(0, || endpoint.set_rx_timestamp_capacity(id, 1)),
            Err(Error::NoMemory.into())
        );
        assert_eq!(endpoint.buffer_bytes(), baseline);
        endpoint.set_rx_timestamp_capacity(id, 1).unwrap();
        let charge = endpoint.buffer_bytes() - baseline;
        let timestamps = RxPacketTimestamps {
            software: Some(RxTimestamp {
                value: 7,
                clock: TimestampClock::RealtimeNanoseconds,
            }),
            hardware: None,
        };
        // Direct storage setup isolates allocation accounting; wire acceptance tested separately.
        endpoint
            .slot_mut(id)
            .unwrap()
            .connection
            .rx_timestamps
            .insert(0, 3, timestamps);
        endpoint.config.max_buffer_bytes = baseline + 2 * charge;
        assert_eq!(
            endpoint.set_rx_timestamp_capacity(id, 2),
            Err(Error::NoMemory.into())
        );
        assert_eq!(endpoint.rx_timestamp_status(id).unwrap().retained_ranges, 1);
        assert_eq!(
            endpoint.set_rx_timestamp_capacity(id, 0),
            Err(Error::WouldBlock.into())
        );
        endpoint.config.max_buffer_bytes = baseline + 3 * charge;
        assert_eq!(
            crate::allocation_tests::fail_after(0, || endpoint.set_rx_timestamp_capacity(id, 2)),
            Err(Error::NoMemory.into())
        );
        endpoint.set_rx_timestamp_capacity(id, 2).unwrap();
        assert_eq!(endpoint.buffer_bytes(), baseline + 2 * charge);
        assert_eq!(
            endpoint.slot(id).unwrap().connection.rx_timestamps.at(2),
            timestamps
        );
        let (send, receive) = endpoint.buffer_capacities(id).unwrap();
        let peak = endpoint
            .slot(id)
            .unwrap()
            .connection
            .resize_peak_charge(receive * 2)
            .unwrap();
        endpoint.config.max_buffer_bytes = peak - 1;
        assert_eq!(
            endpoint.set_buffer_capacities(id, send, receive * 2),
            Err(Error::NoMemory.into())
        );
        assert_eq!(
            endpoint.slot(id).unwrap().connection.rx_timestamps.at(2),
            timestamps
        );
        endpoint.config.max_buffer_bytes = peak;
        endpoint
            .set_buffer_capacities(id, send, receive * 2)
            .unwrap();
        assert_eq!(
            endpoint.buffer_bytes(),
            endpoint.slot(id).unwrap().connection.buffer_charge()
        );
        endpoint.set_buffer_capacities(id, send, 1).unwrap();
        assert_eq!(
            endpoint.slot(id).unwrap().connection.rx_timestamps.at(2),
            timestamps
        );
        endpoint
            .slot_mut(id)
            .unwrap()
            .connection
            .rx_timestamps
            .consumed(3);
        let retained = endpoint.buffer_bytes();
        endpoint.set_rx_timestamp_capacity(id, 0).unwrap();
        assert_eq!(endpoint.buffer_bytes(), retained - 2 * charge);
        endpoint.abort(id).unwrap();
        endpoint.release(id).unwrap();
        endpoint.poll_transmit(1, &mut [0; 128], 16).unwrap();
        endpoint.on_timeout(240_000_001, 16).unwrap();
        endpoint
            .poll_transmit(240_000_001, &mut [0; 128], 16)
            .unwrap();
        assert_eq!(endpoint.buffer_bytes(), 0);
    }
    #[test]
    fn listener_rx_timestamp_budget_constructor_failures_restore_pool_and_backlog() {
        let tuple = Tuple {
            local: "192.0.2.2:8080".parse().unwrap(),
            remote: "192.0.2.1:40000".parse().unwrap(),
        };
        let ip = IpMetadata {
            source: tuple.remote.ip(),
            destination: tuple.local.ip(),
        };
        let mut syn = [0; 128];
        let n = wire::encode(
            ip,
            Header {
                source_port: tuple.remote.port(),
                destination_port: tuple.local.port(),
                sequence: 100,
                acknowledgment: 0,
                flags: SYN,
                window: 64,
                urgent_pointer: 0,
            },
            &[],
            b"abc",
            &mut syn,
        )
        .unwrap();
        let stamps = RxPacketTimestamps {
            software: Some(crate::RxTimestamp {
                value: 123,
                clock: crate::TimestampClock::RealtimeNanoseconds,
            }),
            hardware: None,
        };
        let establish = |endpoint: &mut Endpoint, child: ConnectionId| {
            let mut out = [0; 128];
            let tx = endpoint
                .poll_transmit(4, &mut out, 16)
                .unwrap()
                .packet
                .unwrap();
            let reply = wire::parse(tx.ip, &out[..tx.len]).unwrap();
            assert_eq!(reply.header.acknowledgment, 101);
            let header = Header {
                source_port: tuple.remote.port(),
                destination_port: tuple.local.port(),
                sequence: 101,
                acknowledgment: reply.header.sequence.wrapping_add(1),
                flags: ACK,
                window: 64,
                urgent_pointer: 0,
            };
            let n = wire::encode(ip, header, &[], &[], &mut out).unwrap();
            endpoint.input(5, ip, &out[..n]).unwrap();
            assert_eq!(
                endpoint.slot(child).unwrap().connection.rx_timestamps.at(2),
                stamps
            );
            assert_eq!(endpoint.peek(child, &mut out), Ok(3));
            assert_eq!(&out[..3], b"abc");
        };
        let base = Connection::open_bytes(17, 8).unwrap();
        let metadata = RxTimestamps::allocation_bytes(2).unwrap();
        for preallocate in [0, 1] {
            let cfg = EndpointConfig {
                max_connections: 2,
                max_listeners: 1,
                preallocate_connections: preallocate,
                max_buffer_bytes: base + metadata,
                connection: ConnectionConfig {
                    send_capacity: 17,
                    receive_capacity: 17,
                    mss: 8,
                    ..Default::default()
                },
                ..Default::default()
            };
            let make = || {
                let mut endpoint = Endpoint::new(cfg.clone(), [2; 32], 0, |_| true).unwrap();
                let listener = endpoint.listen(tuple.local, 2).unwrap();
                endpoint
                    .set_listener_rx_timestamp_capacity(listener, 2)
                    .unwrap();
                (endpoint, listener)
            };
            let clean = |endpoint: &Endpoint, listener: ListenerId| {
                assert_eq!(endpoint.buffer_bytes(), preallocate * base);
                assert_eq!(endpoint.receive_pool.len(), preallocate);
                assert_eq!(endpoint.free.len(), 2);
                assert!(endpoint.slots.iter().all(Option::is_none));
                let record = endpoint.listener(listener).unwrap();
                assert!(record.children.is_empty());
                assert!(record.pending.is_empty());
                assert_eq!(endpoint.connection_id(tuple), None);
            };
            let (mut endpoint, listener) = make();
            assert_eq!(
                endpoint.set_listener_rx_timestamp_capacity(listener, usize::MAX),
                Err(Error::NoMemory.into())
            );
            assert_eq!(
                endpoint.set_listener_rx_timestamp_capacity(listener, 3),
                Err(Error::NoMemory.into())
            );
            assert_eq!(endpoint.listener_rx_timestamp_capacity(listener), Ok(2));
            assert_eq!(
                endpoint.set_listener_buffer_capacities(listener, 17, 18),
                Err(Error::NoMemory.into())
            );
            assert_eq!(endpoint.listener_buffer_capacities(listener), Ok((17, 17)));
            // Base storage fits, but metadata does not. Reject before taking the pool.
            endpoint.config.max_buffer_bytes -= 1;
            assert_eq!(
                endpoint.input_with_timestamps(1, ip, 0, Ipv4Options::default(), &syn[..n], stamps),
                Ok(InputDisposition::Dropped)
            );
            clean(&endpoint, listener);
            endpoint.config.max_buffer_bytes += 1;
            // Force failure after the complete child (including SYN metadata) exists.
            let mut occupied = tuple;
            occupied.remote.set_port(40001);
            endpoint.tuples.entries.fill(Entry::Occupied(ScopedTuple::unscoped(occupied), 0));
            assert_eq!(
                endpoint.input_with_timestamps(2, ip, 0, Ipv4Options::default(), &syn[..n], stamps),
                Ok(InputDisposition::Dropped)
            );
            clean(&endpoint, listener);
            endpoint.tuples.entries.fill(Entry::Empty);
            assert_eq!(
                endpoint.input_with_timestamps(3, ip, 0, Ipv4Options::default(), &syn[..n], stamps),
                Ok(InputDisposition::Processed)
            );
            let child = endpoint.connection_id(tuple).unwrap();
            assert_eq!(endpoint.buffer_bytes(), base + metadata);
            assert!(endpoint.receive_pool.is_empty());
            assert_eq!(endpoint.rx_timestamp_status(child).unwrap().capacity, 2);
            assert_eq!(
                endpoint.slot(child).unwrap().connection.rx_timestamps.at(0),
                stamps
            );
            establish(&mut endpoint, child);

            // Walk every constructor allocation, not just the first metadata reserve.
            let mut failures = 0;
            let mut succeeded = false;
            for fail_at in 0..32 {
                let (mut endpoint, listener) = make();
                let result = crate::allocation_tests::fail_after(fail_at, || {
                    endpoint.input_with_timestamps(
                        1,
                        ip,
                        0,
                        Ipv4Options::default(),
                        &syn[..n],
                        stamps,
                    )
                });
                if result == Ok(InputDisposition::Processed) {
                    let child = endpoint.connection_id(tuple).unwrap();
                    assert_eq!(
                        endpoint.slot(child).unwrap().connection.rx_timestamps.at(2),
                        stamps
                    );
                    establish(&mut endpoint, child);
                    assert_eq!(endpoint.buffer_bytes(), base + metadata);
                    succeeded = true;
                    break;
                }
                assert_eq!(result, Ok(InputDisposition::Dropped));
                clean(&endpoint, listener);
                assert_eq!(endpoint.next_event(), None);
                assert_eq!(endpoint.next_deadline(), None);
                assert!(!endpoint.has_pending_output());
                failures += 1;
            }
            assert!(succeeded && failures > 1);
        }
    }

    #[test]
    fn listener_rx_timestamp_slot_reuse_defaults_and_zero_policy_preserves_legacy_limits() {
        let mut endpoint = Endpoint::new(EndpointConfig::default(), [1; 32], 0, |_| true).unwrap();
        let address = "192.0.2.2:8080".parse().unwrap();
        let listener = endpoint.listen(address, 1).unwrap();
        endpoint
            .set_listener_rx_timestamp_capacity(listener, 2)
            .unwrap();
        endpoint.close_listener(listener).unwrap();
        endpoint.poll_transmit(0, &mut [0; 128], 16).unwrap();
        let next = endpoint.listen(address, 1).unwrap();
        assert_eq!(next.slot, listener.slot);
        assert_ne!(next.generation, listener.generation);
        assert_eq!(endpoint.listener_rx_timestamp_capacity(next), Ok(0));
        assert_eq!(
            endpoint.listener_rx_timestamp_capacity(listener),
            Err(EndpointError::InvalidHandle)
        );
        // Existing buffer policy can configure future impossible admission when RX is off.
        endpoint.config.max_buffer_bytes = 0;
        endpoint
            .set_listener_buffer_capacities(next, 17, 17)
            .unwrap();
        endpoint
            .set_listener_rx_timestamp_capacity(next, 0)
            .unwrap();
        assert_eq!(
            endpoint.set_listener_rx_timestamp_capacity(next, 1),
            Err(Error::NoMemory.into())
        );
    }
}

#[cfg(test)]
mod endpoint_mtu_update_tests {
    use super::*;

    fn endpoint() -> Endpoint {
        Endpoint::new(
            EndpointConfig {
                max_connections: 8,
                max_listeners: 2,
                connection: ConnectionConfig {
                    pmtud: Some(crate::PmtudConfig::new(1500)),
                    ..ConnectionConfig::default()
                },
                ..EndpointConfig::default()
            },
            [1; 32],
            0,
            |_| true,
        )
        .unwrap()
    }

    #[test]
    fn endpoint_mtu_update_hidden_child_future_template_and_allocation_ceiling() {
        let mut a = endpoint();
        let mut b = endpoint();
        let local = "192.0.2.1:40000".parse().unwrap();
        let remote = "192.0.2.2:8080".parse().unwrap();
        let listener = b.listen(remote, 4).unwrap();
        a.connect(0, local, remote).unwrap();
        let mut bytes = [0; 2048];
        let syn = a.poll_transmit(0, &mut bytes, 16).unwrap().packet.unwrap();
        b.input(1, syn.ip, &bytes[..syn.len]).unwrap();
        let child = b.listener(listener).unwrap().children[0];
        assert!(!b.slot(child).unwrap().accepted_ready);
        let allocated = b.budget.charged();
        let mss = b.config.connection.mss;
        let send_limit = b.config.connection.send_ip_payload_limit;
        crate::allocation_tests::fail_after(0, || {
            b.set_endpoint_first_hop_mtu(2, 68).unwrap();
        });
        assert_eq!(b.path_mtu_info(child).unwrap().unwrap().first_hop_mtu, 68);
        let syn_ack = b.poll_transmit(2, &mut bytes, 16).unwrap().packet.unwrap();
        assert!(syn_ack.len + 20 <= 68);
        assert_eq!(
            wire::parse(syn_ack.ip, &bytes[..syn_ack.len])
                .unwrap()
                .header
                .flags
                & (SYN | ACK),
            SYN | ACK
        );
        assert!(b.listener(listener).unwrap().pending.is_empty());
        // Complete the real handshake, then expose the previously hidden child.
        a.input(2, syn_ack.ip, &bytes[..syn_ack.len]).unwrap();
        let ack = a.poll_transmit(2, &mut bytes, 16).unwrap().packet.unwrap();
        b.input(2, ack.ip, &bytes[..ack.len]).unwrap();
        assert_eq!(b.accept(listener).unwrap(), child);
        let future = b
            .connect(2, "192.0.2.2:40001".parse().unwrap(), local)
            .unwrap();
        assert_eq!(b.path_mtu_info(future).unwrap().unwrap().first_hop_mtu, 68);
        let allocated_after_open = b.budget.charged();
        assert!(allocated_after_open >= allocated);
        crate::allocation_tests::fail_after(0, || {
            b.set_endpoint_first_hop_mtu(3, 9000).unwrap();
        });
        assert_eq!(b.budget.charged(), allocated_after_open);
        assert_eq!(b.config.connection.mss, mss);
        assert_eq!(b.config.connection.send_ip_payload_limit, send_limit);
        assert_eq!(b.path_mtu_info(child).unwrap().unwrap().current_mtu, 68);
        assert_eq!(b.config.connection.pmtud.unwrap().first_hop_mtu, 9000);
    }

    #[test]
    fn endpoint_mtu_update_validation_is_atomic_for_mixed_families_and_listeners() {
        let mut e = endpoint();
        let v4 = e
            .connect(
                0,
                "192.0.2.1:1".parse().unwrap(),
                "192.0.2.2:2".parse().unwrap(),
            )
            .unwrap();
        let v6 = e
            .connect(
                0,
                "[2001:db8::1]:1".parse().unwrap(),
                "[2001:db8::2]:2".parse().unwrap(),
            )
            .unwrap();
        let before = e.path_mtu_info(v4).unwrap();
        assert_eq!(
            e.set_endpoint_first_hop_mtu(10, 1279),
            Err(Error::InvalidArgument.into())
        );
        assert_eq!(e.now, 0);
        assert_eq!(e.path_mtu_info(v4).unwrap(), before);
        assert_eq!(e.config.connection.pmtud.unwrap().first_hop_mtu, 1500);
        e.set_endpoint_first_hop_mtu(1, 1280).unwrap();
        assert_eq!(e.path_mtu_info(v6).unwrap().unwrap().first_hop_mtu, 1280);
        assert_eq!(
            e.set_endpoint_first_hop_mtu(0, 1400),
            Err(Error::TimeWentBackwards.into())
        );
        assert_eq!(e.path_mtu_info(v4).unwrap().unwrap().first_hop_mtu, 1280);
        assert_eq!(
            e.set_first_hop_mtu(10, v6, 68),
            Err(Error::InvalidArgument.into())
        );
        assert_eq!(e.now, 1);

        let mut listener_only = endpoint();
        listener_only
            .listen("[::]:8080".parse().unwrap(), 1)
            .unwrap();
        assert_eq!(
            listener_only.set_endpoint_first_hop_mtu(10, 68),
            Err(Error::InvalidArgument.into())
        );
        assert_eq!(listener_only.now, 0);
        assert_eq!(
            listener_only.set_endpoint_first_hop_mtu(10, 67),
            Err(Error::InvalidArgument.into())
        );

        let mut disabled = Endpoint::new(EndpointConfig::default(), [1; 32], 0, |_| true).unwrap();
        assert_eq!(
            disabled.set_endpoint_first_hop_mtu(10, 1500),
            Err(Error::InvalidArgument.into())
        );
        assert_eq!(disabled.now, 0);
    }

    #[test]
    fn default_route_ceiling_bounds_stateless_reply_and_optional_timestamp() {
        for route in [None, Some(68), Some(80)] {
            let mut policy = crate::PmtudConfig::new(1500);
            policy.route_mtu = route;
            let mut e = Endpoint::new(
                EndpointConfig {
                    connection: ConnectionConfig {
                        pmtud: Some(policy),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                [1; 32],
                0,
                |_| true,
            )
            .unwrap();
            e.control.push_back((
                IpMetadata {
                    source: "192.0.2.1".parse().unwrap(),
                    destination: "192.0.2.2".parse().unwrap(),
                },
                Header {
                    source_port: 1,
                    destination_port: 2,
                    sequence: 0,
                    acknowledgment: 0,
                    flags: RST,
                    window: 0,
                    urgent_pointer: 0,
                },
                OutgoingIpv4Options {
                    record_route_slots: Some(9),
                    ..Default::default()
                },
                Some(100),
                None,
                None,
            ));
            let mut bytes = [0; 256];
            let output = e.poll_transmit(1, &mut bytes, 16).unwrap().packet;
            if route == Some(68) {
                assert!(output.is_none());
            } else {
                let output = output.unwrap();
                assert_eq!(output.len, if route.is_some() { 20 } else { 32 });
                assert!(60 + output.len <= route.unwrap_or(1500) as usize);
                assert_eq!(
                    wire::parse(output.ip, &bytes[..output.len])
                        .unwrap()
                        .header
                        .flags,
                    RST
                );
            }
            assert!(e.control.is_empty());
        }
    }

    #[test]
    fn endpoint_mtu_update_stateless_budget_uses_new_template() {
        let mut e = endpoint();
        let ip = IpMetadata {
            source: "192.0.2.1".parse().unwrap(),
            destination: "192.0.2.2".parse().unwrap(),
        };
        // A queued reply needs 60 IP bytes with these options: the new floor
        // leaves no room for its TCP header, so it must be discarded.
        let options = OutgoingIpv4Options {
            record_route_slots: Some(9),
            ..OutgoingIpv4Options::default()
        };
        e.control.push_back((
            ip,
            Header {
                source_port: 1,
                destination_port: 2,
                sequence: 0,
                acknowledgment: 0,
                flags: RST,
                window: 0,
                urgent_pointer: 0,
            },
            options,
            None,
            None,
            None,
        ));
        e.set_endpoint_first_hop_mtu(1, 68).unwrap();
        assert!(
            e.poll_transmit(1, &mut [0; 256], 16)
                .unwrap()
                .packet
                .is_none()
        );
        assert!(e.control.is_empty());
        assert_eq!(e.oversized_control_replies(), 1);
    }
}

#[cfg(test)]
#[path = "fast_open_simultaneous_tests.rs"]
mod fast_open_simultaneous_tests;

#[cfg(test)]
#[path = "fast_open_key_tests.rs"]
mod fast_open_key_tests;

#[cfg(test)]
#[path = "output_reservation_tests.rs"]
mod output_reservation_tests;

#[cfg(test)]
#[path = "transmit_group_tests.rs"]
mod transmit_group_tests;

#[cfg(test)]
#[path = "autotune_tests.rs"]
mod autotune_tests;

#[cfg(test)]
#[path = "endpoint_ptb_reserved_tests.rs"]
mod ptb_reserved_tests;

#[cfg(test)]
#[path = "endpoint_unsubmitted_discard_tests.rs"]
mod unsubmitted_discard_tests;

#[cfg(test)]
#[path = "endpoint_suspend_tests.rs"]
mod suspend_tests;

#[cfg(test)]
#[path = "endpoint_reset_defense_tests.rs"]
mod reset_defense_tests;

#[cfg(test)]
#[path = "endpoint_loss_counter_tests.rs"]
mod loss_counter_tests;

#[cfg(all(test, feature = "packet-test-controls"))]
mod timestamp_default_control_tests {
    use super::*;

    #[test]
    fn changing_future_default_never_weakens_timestamp_clock_guard() {
        for originally_enabled in [false, true] {
            for future_enabled in [false, true] {
                let mut config = EndpointConfig::default();
                config.connection.timestamps = originally_enabled;
                let mut endpoint = Endpoint::new(config, [1; 32], 0, |_| true).unwrap();
                endpoint.packet_test_timestamp_default(future_enabled);
                assert_eq!(endpoint.new_connection_timestamps(), future_enabled);
                assert!(endpoint.check_clock(1000).is_ok());
                assert_eq!(
                    endpoint.check_clock((1u64 << 31) * 1000),
                    Err(Error::AmbiguousTimeJump.into())
                );
            }
        }
    }
}

// A write whose storage growth the buffer budget refuses waits for memory as
// Linux's tcp_sendmsg does in sk_stream_wait_memory: it takes what fits, then
// would block, and the connection is writable again once memory comes back.
#[cfg(test)]
mod memory_wait_tests {
    use super::*;
    use crate::MemoryCounters;
    use alloc::vec::Vec;

    // Eight-byte segments, so that a write of a few hundred bytes needs
    // more ledger entries than the first write allocated.
    fn config() -> EndpointConfig {
        EndpointConfig {
            max_connections: 4,
            connection: ConnectionConfig {
                mss: 8,
                send_capacity: 1024,
                receive_capacity: 1024,
                nagle: false,
                delayed_ack_us: 0,
                ..ConnectionConfig::default()
            },
            ..EndpointConfig::default()
        }
    }

    // Moves `from`'s packets to `to`; whether there were any.
    fn flush(from: &mut Endpoint, to: &mut Endpoint, now: u64) -> bool {
        let mut moved = false;
        loop {
            let mut bytes = [0; 2048];
            let output = from.poll_transmit(now, &mut bytes, 16).unwrap();
            if let Some(packet) = output.packet {
                to.input(now, packet.ip, &bytes[..packet.len]).unwrap();
                moved = true;
            }
            if !output.more_work {
                return moved;
            }
        }
    }

    fn exchange(a: &mut Endpoint, b: &mut Endpoint, now: u64) {
        for _ in 0..64 {
            if !(flush(a, b, now) | flush(b, a, now)) {
                return;
            }
        }
        panic!("the endpoints did not settle");
    }

    const REMOTE: &str = "192.0.2.2:8080";

    // A client and a server Endpoint, the server listening.
    fn endpoints() -> (Endpoint, Endpoint, ListenerId) {
        let a = Endpoint::new(config(), [1; 32], 0, |_| true).unwrap();
        let mut b = Endpoint::new(config(), [2; 32], 0, |_| true).unwrap();
        let listener = b.listen(REMOTE.parse().unwrap(), 4).unwrap();
        (a, b, listener)
    }

    fn connect(
        a: &mut Endpoint,
        b: &mut Endpoint,
        listener: ListenerId,
        port: u16,
    ) -> (ConnectionId, ConnectionId) {
        let local = SocketAddr::new("192.0.2.1".parse().unwrap(), port);
        let client = a.connect(0, local, REMOTE.parse().unwrap()).unwrap();
        exchange(a, b, 0);
        (client, b.accept(listener).unwrap())
    }

    // The bytes beyond those queued that `id`'s allocated send ring and
    // ledger entries hold: what a write the budget refuses to grow takes.
    fn held(a: &Endpoint, id: ConnectionId) -> usize {
        a.slot(id).unwrap().connection.allocated_send_room()
    }

    // More bytes than the ledgers the first write allocated hold entries
    // for.
    fn long_data() -> Vec<u8> {
        (0..512).map(|i| i as u8).collect()
    }

    // Whether the events since the last call made `id` writable.
    fn writable(endpoint: &mut Endpoint, id: ConnectionId) -> bool {
        let mut writable = false;
        while let Some(event) = endpoint.next_event() {
            if let Event::Connection(of, events) = event
                && of == id
            {
                writable |= events.writable;
            }
        }
        writable
    }

    #[test]
    fn a_refused_write_takes_what_fits_and_completes_after_the_peer_acks() {
        let (mut a, mut b, listener) = endpoints();
        let (client, server) = connect(&mut a, &mut b, listener, 40000);
        // The first write allocates the send ring and the ledgers.
        assert_eq!(a.write(client, &[1; 9]), Ok(9));
        writable(&mut a, client);
        // The budget has no room for the ledgers to grow.
        a.config.max_buffer_bytes = a.buffer_bytes();
        let data = long_data();
        let room = held(&a, client);
        assert!(room > 0 && room < data.len());
        assert_eq!(a.write(client, &data), Ok(room));
        assert_eq!(a.memory_throttled_writes(), 1);
        assert_eq!(
            a.write(client, &data[room..]),
            Err(Error::WouldBlock.into())
        );
        assert_eq!(a.memory_throttled_writes(), 2);
        assert_eq!(a.send_admission_room(client, None), Ok(0));
        assert!(!writable(&mut a, client));
        // The peer's ACK frees ring and ledger room the connection holds.
        let mut now = 1;
        let mut sent = room;
        exchange(&mut a, &mut b, now);
        while sent < data.len() {
            assert!(writable(&mut a, client), "{sent}");
            sent += a.write(client, &data[sent..]).unwrap();
            now += 1;
            exchange(&mut a, &mut b, now);
        }
        let mut out = [0; 1024];
        assert_eq!(b.read(server, &mut out), Ok(9 + data.len()));
        assert_eq!(out[..9], [1; 9]);
        assert_eq!(out[9..9 + data.len()], data[..]);
        assert!(a.buffer_bytes() <= a.config.max_buffer_bytes);
    }

    // A connection whose queue and flight drained frees ledgers grown past
    // a page, as Linux frees an emptied retransmission queue's skbs at ACK
    // and sk_mem_reclaim returns what exceeds its reserve; the return wakes
    // a writer waiting for memory. Ledgers within a page stay: the next
    // small write and its exchange reallocate nothing.
    #[test]
    fn drained_ledgers_above_a_page_are_freed_and_wake_a_waiter() {
        let (mut a, mut b, listener) = endpoints();
        let (bulk, server) = connect(&mut a, &mut b, listener, 40000);
        let (waiter, _) = connect(&mut a, &mut b, listener, 40001);
        let ledgers = |a: &Endpoint| a.slot(bulk).unwrap().connection.ledger_bytes();
        let data = long_data();
        assert_eq!(a.write(bulk, &data), Ok(data.len()));
        let held = ledgers(&a);
        assert!(held > crate::connection::LEDGER_RESERVE);
        writable(&mut a, waiter);
        a.config.max_buffer_bytes = a.buffer_bytes();
        assert_eq!(a.write(waiter, &[1; 9]), Err(Error::WouldBlock.into()));
        assert!(!writable(&mut a, waiter));
        let charged = a.buffer_bytes();
        let mut read = 0;
        for now in 1..64 {
            exchange(&mut a, &mut b, now);
            read += b.read(server, &mut [0; 1024]).unwrap_or(0);
            if a.slot(bulk).unwrap().connection.send_progress().queued_end
                == a.acknowledged(bulk).unwrap()
            {
                break;
            }
        }
        assert_eq!(read, data.len());
        assert_eq!(ledgers(&a), 0);
        assert_eq!(a.buffer_bytes(), charged - held);
        assert!(writable(&mut a, waiter));
        assert_eq!(a.write(waiter, &[1; 9]), Ok(9));
        // A small write allocates ledgers within the reserve, which stay
        // once it is acknowledged.
        a.config.max_buffer_bytes = usize::MAX;
        assert_eq!(a.write(bulk, &[2; 9]), Ok(9));
        let small = ledgers(&a);
        assert!(small > 0 && small <= crate::connection::LEDGER_RESERVE);
        exchange(&mut a, &mut b, 100);
        assert_eq!(b.read(server, &mut [0; 16]), Ok(9));
        let progress = a.slot(bulk).unwrap().connection.send_progress();
        assert_eq!(progress.queued_end, progress.acknowledged);
        assert_eq!(ledgers(&a), small);
    }

    // A connection whose queue drained frees a send ring grown past a
    // page, as Linux frees an emptied write queue's skbs at ACK and
    // sk_mem_reclaim returns what exceeds a page; the return wakes a writer
    // waiting for memory. The send limit stays, and the next write grows
    // the ring again from a page, which a small exchange keeps.
    #[test]
    fn drained_send_ring_above_a_page_is_freed_and_wakes_a_waiter() {
        let (mut a, mut b, listener) = endpoints();
        let (bulk, server) = connect(&mut a, &mut b, listener, 40000);
        let (waiter, _) = connect(&mut a, &mut b, listener, 40001);
        let ring = |a: &Endpoint| a.slot(bulk).unwrap().connection.send_ring_bytes();
        let ledgers = |a: &Endpoint| a.slot(bulk).unwrap().connection.ledger_bytes();
        a.set_send_buffer(bulk, 8192).unwrap();
        let data: Vec<u8> = (0..6000).map(|i| (i % 251) as u8).collect();
        assert_eq!(a.write(bulk, &data), Ok(data.len()));
        assert_eq!(ring(&a), 2 * 8192);
        let held = ring(&a) + ledgers(&a);
        assert!(ledgers(&a) > crate::connection::LEDGER_RESERVE);
        writable(&mut a, waiter);
        a.config.max_buffer_bytes = a.buffer_bytes();
        assert_eq!(a.write(waiter, &[1; 9]), Err(Error::WouldBlock.into()));
        assert!(!writable(&mut a, waiter));
        let charged = a.buffer_bytes();
        let mut read = Vec::new();
        for now in 1..256 {
            exchange(&mut a, &mut b, now);
            let mut out = [0; 1024];
            let len = b.read(server, &mut out).unwrap_or(0);
            read.extend_from_slice(&out[..len]);
            if a.slot(bulk).unwrap().connection.send_progress().queued_end
                == a.acknowledged(bulk).unwrap()
            {
                break;
            }
            // Nothing is freed while bytes are queued.
            assert_eq!(ring(&a), 2 * 8192);
        }
        assert_eq!(read, data);
        assert_eq!((ring(&a), ledgers(&a)), (0, 0));
        assert_eq!(a.buffer_bytes(), charged - held);
        assert_eq!(a.buffer_capacities(bulk).unwrap().0, 8192);
        assert!(writable(&mut a, waiter));
        assert_eq!(a.write(waiter, &[1; 9]), Ok(9));
        // A 600-byte write grows a page of ring, which stays once it is
        // acknowledged.
        a.config.max_buffer_bytes = usize::MAX;
        assert_eq!(a.write(bulk, &[2; 600]), Ok(600));
        assert_eq!(ring(&a), crate::connection::SEND_RING_RESERVE);
        for now in 300..310 {
            exchange(&mut a, &mut b, now);
            let _ = b.read(server, &mut [0; 1024]);
        }
        let progress = a.slot(bulk).unwrap().connection.send_progress();
        assert_eq!(progress.queued_end, progress.acknowledged);
        assert_eq!(ring(&a), crate::connection::SEND_RING_RESERVE);
    }

    #[test]
    fn another_connections_release_wakes_a_waiting_writer() {
        let (mut a, mut b, listener) = endpoints();
        let (waiter, server) = connect(&mut a, &mut b, listener, 40000);
        let (other, _) = connect(&mut a, &mut b, listener, 40001);
        assert_eq!(a.write(other, &[2; 9]), Ok(9));
        exchange(&mut a, &mut b, 1);
        writable(&mut a, waiter);
        a.config.max_buffer_bytes = a.buffer_bytes();
        // No send ring yet, and no room to allocate one.
        assert_eq!(a.write(waiter, &[1; 9]), Err(Error::WouldBlock.into()));
        assert_eq!(a.memory_throttled_writes(), 1);
        assert_eq!(a.send_admission_room(waiter, None), Ok(0));
        assert!(!writable(&mut a, waiter));
        // The other connection's end returns its storage to the budget.
        a.abort(other).unwrap();
        a.release(other).unwrap();
        exchange(&mut a, &mut b, 2);
        // Reclaimed once its reset is out.
        let reclaimed = 2;
        assert!(!a.connection_exists(other));
        assert!(writable(&mut a, waiter));
        assert_eq!(a.write(waiter, &[1; 9]), Ok(9));
        exchange(&mut a, &mut b, reclaimed);
        assert_eq!(b.read(server, &mut [0; 16]), Ok(9));
        assert!(a.buffer_bytes() <= a.config.max_buffer_bytes);
    }

    // As Linux's tcp_mem: pressure begins once the charge exceeds the
    // pressure threshold (__sk_mem_raise_allocated) and ends only once it
    // is at most the low one (__sk_mem_reduce_allocated), whatever it does
    // between them.
    #[test]
    fn pressure_begins_above_its_threshold_and_ends_at_low() {
        let (mut a, _, _) = endpoints();
        let base = a.buffer_bytes();
        a.config.max_buffer_bytes = base + 3000;
        a.config.buffer_pressure_bytes = Some(base + 2000);
        a.config.buffer_low_bytes = Some(base + 1000);
        a.now = 10;
        a.charge(2000);
        assert!(!a.memory_pressure(), "at the threshold");
        a.charge(1);
        assert!(a.memory_pressure());
        a.now = 25;
        a.uncharge(900);
        assert!(a.memory_pressure(), "above low");
        a.charge(800);
        a.uncharge(800);
        assert!(a.memory_pressure(), "above low");
        a.now = 50;
        a.uncharge(101);
        assert_eq!(a.buffer_bytes(), base + 1000);
        assert!(!a.memory_pressure(), "at low");
        a.charge(1000);
        assert!(!a.memory_pressure(), "at the threshold");
        a.now = 100;
        a.charge(1);
        assert!(a.memory_pressure());
        a.uncharge(2001);
        assert_eq!(a.buffer_bytes(), base);
    }

    // The storage connections allocate is what enters and leaves pressure.
    #[test]
    fn connection_storage_enters_and_leaves_pressure() {
        let (mut a, mut b, listener) = endpoints();
        let (client, _) = connect(&mut a, &mut b, listener, 40000);
        let (other, _) = connect(&mut a, &mut b, listener, 40001);
        let open = a.buffer_bytes();
        // The first write allocates the send ring and ledgers.
        assert_eq!(a.write(client, &[1; 9]), Ok(9));
        let written = a.buffer_bytes();
        let per_write = written - open;
        a.config.max_buffer_bytes = written * 4;
        a.config.buffer_pressure_bytes = Some(written + per_write - 1);
        a.config.buffer_low_bytes = Some(written / 2);
        assert!(!a.memory_pressure());
        assert_eq!(a.write(other, &[1; 9]), Ok(9));
        assert!(a.memory_pressure());
        // Reclaiming one connection does not reach low.
        a.abort(other).unwrap();
        a.release(other).unwrap();
        exchange(&mut a, &mut b, 1);
        a.on_timeout(1 + a.config.connection.time_wait_us, 64)
            .unwrap();
        assert!(!a.connection_exists(other));
        assert!(a.buffer_bytes() < written);
        assert!(a.memory_pressure());
        a.config.buffer_low_bytes = Some(a.buffer_bytes());
        a.charge(1);
        assert!(a.memory_pressure(), "only a return leaves");
        a.uncharge(1);
        assert!(!a.memory_pressure());
    }

    #[test]
    fn buffer_memory_resolves_tcp_mem_thresholds() {
        let config = EndpointConfig {
            max_buffer_bytes: 3 << 20,
            ..config()
        };
        let memory = config.buffer_memory();
        assert_eq!(
            (memory.low, memory.pressure, memory.high),
            (3 << 19, 2 << 20, 3 << 20)
        );
        assert_eq!(alloc::format!("{memory}"), "1572864 2097152 3145728");
        assert!(config.validate().is_ok());
        let usize_max = EndpointConfig {
            max_buffer_bytes: usize::MAX,
            ..config.clone()
        };
        assert_eq!(usize_max.buffer_memory().pressure, usize::MAX / 3 * 2);
        for (pressure, low, valid) in [
            (Some(2 << 20), Some(1 << 20), true),
            (Some(3 << 20), None, true),
            (Some(1 << 20), Some(1 << 20), false),
            (None, Some(2 << 20), false),
            (Some((3 << 20) + 1), None, false),
        ] {
            let config = EndpointConfig {
                buffer_pressure_bytes: pressure,
                buffer_low_bytes: low,
                ..config.clone()
            };
            assert_eq!(config.validate().is_ok(), valid, "{pressure:?} {low:?}");
            assert_eq!(Endpoint::new(config, [1; 32], 0, |_| true).is_ok(), valid);
        }
    }

    // A send direction memory pressure applies to: its limit may grow to
    // 4096 bytes (`send_capacity_max` above `send_capacity`), down to a
    // 16-byte floor.
    fn tuned() -> EndpointConfig {
        let mut config = config();
        config.connection.send_capacity_max = 4096;
        config.connection.send_capacity_min = 16;
        config
    }

    // Sends `from`'s packets nowhere: its data stays unacknowledged.
    fn drain(from: &mut Endpoint, now: u64) {
        loop {
            let output = from.poll_transmit(now, &mut [0; 2048], 16).unwrap();
            if !output.more_work {
                return;
            }
        }
    }

    // The bytes a write took, WouldBlock as none.
    fn taken(result: Result<usize, EndpointError>) -> usize {
        match result {
            Err(EndpointError::Connection(Error::WouldBlock)) => 0,
            result => result.unwrap(),
        }
    }

    // Puts `a` into pressure now: the next charge passes `pressure`.
    fn enter_pressure(a: &mut Endpoint, pressure: usize, low: usize) {
        a.config.buffer_pressure_bytes = Some(pressure);
        a.config.buffer_low_bytes = Some(low);
        a.charge(1);
        a.uncharge(1);
        assert!(a.memory_pressure());
    }

    // As Linux's __sk_mem_raise_allocated under pressure: a tuned
    // connection holding its floor and its fair share of the cap grows
    // nothing, and the refusal moderates its send limit to what it has
    // queued (sk_stream_moderate_sndbuf); a connection below its fair share
    // grows, as does one below its floor.
    #[test]
    fn pressure_refuses_growth_past_the_fair_share_and_moderates_the_limit() {
        let mut a = Endpoint::new(tuned(), [1; 32], 0, |_| true).unwrap();
        let mut b = Endpoint::new(tuned(), [2; 32], 0, |_| true).unwrap();
        let listener = b.listen(REMOTE.parse().unwrap(), 4).unwrap();
        // `big`'s large receive ring keeps it above its fair share.
        let local = SocketAddr::new("192.0.2.1".parse().unwrap(), 40000);
        let big = a
            .connect_with_buffer_capacities(0, local, REMOTE.parse().unwrap(), 1024, 65536)
            .unwrap();
        exchange(&mut a, &mut b, 0);
        b.accept(listener).unwrap();
        let (small, _) = connect(&mut a, &mut b, listener, 40001);
        assert_eq!(a.write(big, &[1; 200]), Ok(200));
        assert_eq!(a.write(small, &[2; 20]), Ok(20));
        // Establishment's expansion to ten segments (tcp_init_buffer_space)
        // stays below the initial limit.
        let small_limit = a.buffer_capacities(small).unwrap().0;
        assert_eq!(small_limit, 1024);
        let charged = a.buffer_bytes();
        let big_charge = a.slot(big).unwrap().connection.buffer_charge();
        // Two connections: the fair share is half the cap, which `big`
        // holds and `small` does not.
        a.config.max_buffer_bytes = 2 * big_charge;
        assert!(charged < a.config.max_buffer_bytes);
        enter_pressure(&mut a, charged - 1, charged / 2);
        let room = a.buffer_room();
        let connection = &a.slot(big).unwrap().connection;
        assert_eq!(a.send_growth_room(connection, big_charge), 0);
        writable(&mut a, big);
        // The write takes what the allocated ledgers hold, if anything.
        let taken = taken(a.write(big, &[1; 300]));
        assert!(taken < 300);
        assert_eq!(a.memory_throttled_writes(), 1);
        assert_eq!(a.buffer_capacities(big).unwrap().0, 200 + taken);
        assert_eq!(a.send_admission_room(big, None), Ok(0));
        assert!(!writable(&mut a, big));
        // Below its fair share, `small` grows its ledgers.
        assert!(held(&a, small) < 400);
        assert_eq!(a.write(small, &[2; 400]), Ok(400));
        assert_eq!(a.memory_throttled_writes(), 1);
        assert!(a.buffer_room() < room);
        assert_eq!(a.buffer_capacities(small).unwrap().0, small_limit);
        // Once the peer acknowledges everything, `big` holds less than its
        // floor: it may grow again, within its moderated limit.
        exchange(&mut a, &mut b, 1);
        let connection = &a.slot(big).unwrap().connection;
        let progress = connection.send_progress();
        assert_eq!(progress.queued_end, progress.acknowledged);
        assert_eq!(
            a.send_growth_room(connection, connection.buffer_charge()),
            a.buffer_room()
        );
        assert!(writable(&mut a, big));
        assert_eq!(a.write(big, &[1; 300]), Ok(300.min(200 + taken)));
        assert!(a.memory_pressure());
    }

    // A release that leaves the endpoint in pressure does not wake a writer
    // pressure refused, whatever room the cap has; the release that ends
    // pressure does (__sk_mem_reduce_allocated, sk_stream_write_space).
    #[test]
    fn the_end_of_pressure_wakes_a_writer_pressure_refused() {
        // An aborted connection's slot answers for its reset this long.
        let mut config = tuned();
        config.connection.time_wait_us = 10;
        config.connection.send_capacity_min = 1;
        let mut a = Endpoint::new(config.clone(), [1; 32], 0, |_| true).unwrap();
        let mut b = Endpoint::new(config, [2; 32], 0, |_| true).unwrap();
        let listener = b.listen(REMOTE.parse().unwrap(), 4).unwrap();
        // The writer's large receive ring keeps it above its fair share.
        let local = SocketAddr::new("192.0.2.1".parse().unwrap(), 40000);
        let writer = a
            .connect_with_buffer_capacities(0, local, REMOTE.parse().unwrap(), 1024, 65536)
            .unwrap();
        exchange(&mut a, &mut b, 0);
        b.accept(listener).unwrap();
        let (first, _) = connect(&mut a, &mut b, listener, 40001);
        let (second, _) = connect(&mut a, &mut b, listener, 40002);
        let (_idle, _) = connect(&mut a, &mut b, listener, 40003);
        assert_eq!(a.write(writer, &[1; 9]), Ok(9));
        assert_eq!(a.write(first, &[2; 200]), Ok(200));
        assert_eq!(a.write(second, &[3; 200]), Ok(200));
        drain(&mut a, 1);
        let charged = a.buffer_bytes();
        let charge = |a: &Endpoint, id| a.slot(id).unwrap().connection.buffer_charge();
        let (writer_charge, first_charge, second_charge) =
            (charge(&a, writer), charge(&a, first), charge(&a, second));
        // Two connections left still hold the writer to half the cap.
        a.config.max_buffer_bytes = 2 * writer_charge;
        assert!(charged < a.config.max_buffer_bytes);
        enter_pressure(&mut a, charged - 1, charged - first_charge - second_charge);
        writable(&mut a, writer);
        // The write takes what the allocated ledgers hold, and the limit
        // falls to what is then queued (sk_stream_moderate_sndbuf).
        let usage = a.transport_info(writer).unwrap().send_used;
        let room = held(&a, writer);
        assert_eq!(a.write(writer, &long_data()), Ok(room));
        assert_eq!(a.memory_throttled_writes(), 1);
        let limit = a.buffer_capacities(writer).unwrap().0;
        assert_eq!(limit, usage + room);
        assert!(!writable(&mut a, writer));
        let reclaim = |a: &mut Endpoint, id: ConnectionId, now: u64| {
            a.abort(id).unwrap();
            a.release(id).unwrap();
            drain(a, now);
            a.on_timeout(now + 10, 64).unwrap();
            assert!(!a.connection_exists(id));
        };
        let waiting = |a: &Endpoint| a.slot(writer).unwrap().connection.send_memory_throttled();
        assert!(waiting(&a));
        reclaim(&mut a, first, 2);
        assert!(a.memory_pressure());
        assert!(a.buffer_room() >= first_charge);
        assert!(waiting(&a));
        assert!(!writable(&mut a, writer));
        reclaim(&mut a, second, 20);
        assert!(!a.memory_pressure());
        assert!(!waiting(&a));
        // Its moderated limit is full until the peer acknowledges what
        // `drain` dropped, once the retransmission timer sends it again.
        assert!(!writable(&mut a, writer));
        a.on_timeout(5_000_000, 64).unwrap();
        exchange(&mut a, &mut b, 5_000_000);
        assert!(writable(&mut a, writer));
        assert_eq!(a.write(writer, &[1; 64]), Ok(64.min(limit)));
        assert_eq!(a.memory_throttled_writes(), 1);
    }

    // A fixed send direction (send_capacity_max at send_capacity) is held
    // to the hard cap alone: pressure leaves its trace as it was. A tuned
    // one, which pressure holds back, shows that the comparison sees it.
    #[test]
    fn pressure_leaves_a_fixed_configuration_as_it_was() {
        // The write results, every packet `a` sent and its throttled
        // writes, for a client among four connections that takes more than
        // its fair share: under pressure from the start, or only once a
        // growth passes the cap.
        #[allow(clippy::type_complexity)]
        fn transfer(
            fixed: bool,
            early: bool,
        ) -> (Vec<Result<usize, EndpointError>>, Vec<Vec<u8>>, u64) {
            let mut config = tuned();
            config.connection.send_capacity_min = 1;
            if fixed {
                config.connection.send_capacity_max = config.connection.send_capacity;
            }
            let mut a = Endpoint::new(config.clone(), [1; 32], 0, |_| true).unwrap();
            let mut b = Endpoint::new(config, [2; 32], 0, |_| true).unwrap();
            let listener = b.listen(REMOTE.parse().unwrap(), 4).unwrap();
            // The client's large receive ring keeps it above its fair share.
            let local = SocketAddr::new("192.0.2.1".parse().unwrap(), 40000);
            let client = a
                .connect_with_buffer_capacities(0, local, REMOTE.parse().unwrap(), 1024, 65536)
                .unwrap();
            exchange(&mut a, &mut b, 0);
            let server = b.accept(listener).unwrap();
            for port in 40001..40004 {
                connect(&mut a, &mut b, listener, port);
            }
            // Room to grow the ledgers for a quarter of the limit, not for
            // all of it.
            assert_eq!(a.write(client, &[1; 9]), Ok(9));
            a.config.max_buffer_bytes = a.buffer_bytes() + 16384;
            if early {
                enter_pressure(&mut a, 1, 0);
            } else {
                a.config.buffer_pressure_bytes = Some(a.config.max_buffer_bytes);
            }
            let mut results = Vec::new();
            let mut packets = Vec::new();
            let data: Vec<u8> = (0..1015).map(|i| i as u8).collect();
            let mut sent = 0;
            let mut read = 0;
            for now in 2..200 {
                if sent < data.len() {
                    let result = a.write(client, &data[sent..]);
                    if let Ok(count) = result {
                        sent += count;
                    }
                    results.push(result);
                }
                loop {
                    let mut moved = false;
                    loop {
                        let mut bytes = [0; 2048];
                        let output = a.poll_transmit(now, &mut bytes, 16).unwrap();
                        if let Some(packet) = output.packet {
                            packets.push(bytes[..packet.len].to_vec());
                            b.input(now, packet.ip, &bytes[..packet.len]).unwrap();
                            moved = true;
                        }
                        if !output.more_work {
                            break;
                        }
                    }
                    if !(flush(&mut b, &mut a, now) | moved) {
                        break;
                    }
                }
                read += b.read(server, &mut [0; 512]).unwrap_or(0);
                if read == data.len() + 9 {
                    break;
                }
            }
            (results, packets, a.memory_throttled_writes())
        }
        let late = transfer(true, false);
        assert!(late.2 > 0);
        assert_eq!(late.1.iter().map(|p| p.len() - 20).sum::<usize>(), 1024);
        assert_eq!(transfer(true, true), late);
        assert_ne!(transfer(false, true), transfer(false, false));
    }

    // Pressure time counts in the endpoint's clock, the current pressure
    // included up to it (TCPMemoryPressures, TCPMemoryPressuresChrono).
    #[test]
    fn memory_counters_count_pressures_and_their_time() {
        let (mut a, _, _) = endpoints();
        let base = a.buffer_bytes();
        a.config.max_buffer_bytes = base + 3000;
        a.config.buffer_pressure_bytes = Some(base + 2000);
        a.config.buffer_low_bytes = Some(base + 1000);
        assert_eq!(
            a.memory_counters(),
            MemoryCounters {
                buffer_bytes: base,
                ..MemoryCounters::default()
            }
        );
        a.now = 10;
        a.charge(2001);
        a.now = 50;
        a.uncharge(1001);
        a.now = 100;
        a.charge(1001);
        a.now = 130;
        let counters = a.memory_counters();
        assert!(counters.memory_pressure);
        assert_eq!(counters.memory_pressures, 2);
        assert_eq!(counters.memory_pressure_us, 40 + 30);
        assert_eq!(counters.buffer_bytes, base + 2001);
    }

    // An active open, a SYN and a growth the budget refuses each count, the
    // SYN in listen_drops too.
    #[test]
    fn memory_counters_count_refused_opens_and_growths() {
        let (mut a, mut b, listener) = endpoints();
        let (client, _) = connect(&mut a, &mut b, listener, 40000);
        assert_eq!(a.write(client, &[1; 9]), Ok(9));
        a.config.max_buffer_bytes = a.buffer_bytes();
        let local = SocketAddr::new("192.0.2.1".parse().unwrap(), 40001);
        assert_eq!(
            a.connect(0, local, REMOTE.parse().unwrap()),
            Err(Error::NoMemory.into())
        );
        assert_eq!(a.memory_counters().memory_refused_opens, 1);
        // The ledgers hold entries for `room` more bytes; more is refused.
        let room = held(&a, client);
        assert_eq!(a.write(client, &long_data()), Ok(room));
        assert_eq!(
            a.set_buffer_capacities(client, 1024, 4096),
            Err(Error::NoMemory.into())
        );
        let counters = a.memory_counters();
        assert_eq!(counters.memory_refused_growths, 2);
        assert_eq!(counters.memory_throttled_writes, 1);
        // The server has room for none: its SYN is dropped.
        let mut c = Endpoint::new(config(), [3; 32], 0, |_| true).unwrap();
        b.config.max_buffer_bytes = b.buffer_bytes();
        let local = SocketAddr::new("192.0.2.3".parse().unwrap(), 40002);
        c.connect(0, local, REMOTE.parse().unwrap()).unwrap();
        flush(&mut c, &mut b, 0);
        assert_eq!(b.listen_drops(), 1);
        assert_eq!(b.memory_counters().memory_refused_opens, 1);
        assert_eq!(b.memory_counters().memory_refused_growths, 0);
    }

    // Storage a connection gives back outside pressure wakes a writer as a
    // reclaim does; a released waiter leaves the queue.
    #[test]
    fn returned_slack_wakes_a_waiting_writer() {
        let (mut a, mut b, listener) = endpoints();
        let (writer, _) = connect(&mut a, &mut b, listener, 40000);
        let (other, _) = connect(&mut a, &mut b, listener, 40001);
        let (released, _) = connect(&mut a, &mut b, listener, 40002);
        a.set_rx_timestamp_capacity(other, 1024).unwrap();
        let records = a
            .slot(other)
            .unwrap()
            .connection
            .rx_timestamps
            .storage_bytes();
        writable(&mut a, writer);
        a.config.max_buffer_bytes = a.buffer_bytes();
        assert_eq!(a.write(released, &[1; 9]), Err(Error::WouldBlock.into()));
        assert_eq!(a.write(writer, &[1; 9]), Err(Error::WouldBlock.into()));
        assert_eq!(a.memory_waiters.iter().count(), 2);
        a.abort(released).unwrap();
        a.release(released).unwrap();
        assert_eq!(a.memory_waiters.iter().collect::<Vec<_>>(), [writer.slot]);
        assert!(!a.memory_pressure() || a.buffer_bytes() > a.config.buffer_memory().low);
        assert!(!writable(&mut a, writer));
        let wanted = a
            .slot(writer)
            .unwrap()
            .connection
            .send_memory_wanted()
            .unwrap();
        assert!(records >= wanted, "{records} {wanted}");
        // The other connection's timestamp records shrink.
        a.set_rx_timestamp_capacity(other, 0).unwrap();
        assert!(a.memory_waiters.is_empty());
        assert!(writable(&mut a, writer));
        assert_eq!(a.write(writer, &[1; 9]), Ok(9));
    }

    // Two endpoints of one group, charging through reserves of `batch`
    // bytes: the group sees each member's charge late by less than one
    // batch, members share one pressure state and connection count, and a
    // member that goes takes its charge out.
    #[test]
    fn shared_buffer_memory_publishes_in_batches_with_bounded_lag() {
        let (mut a, mut b, listener) = endpoints();
        connect(&mut a, &mut b, listener, 40000);
        connect(&mut a, &mut b, listener, 40001);
        let (base_a, base_b) = (a.buffer_bytes(), b.buffer_bytes());
        let base = base_a + base_b;
        let memory = crate::BufferMemory {
            low: base + 3000,
            pressure: base + 6000,
            high: base + 10_000,
        };
        let batch = 1000;
        let group = crate::SharedBufferMemory::new(2, Some(memory), batch).unwrap();
        a.share_buffer_memory(&group, 0).unwrap();
        assert_eq!(
            b.share_buffer_memory(&group, 0),
            Err(Error::InvalidArgument.into())
        );
        b.share_buffer_memory(&group, 1).unwrap();
        assert_eq!(
            a.share_buffer_memory(&group, 1),
            Err(Error::InvalidArgument.into())
        );
        assert_eq!(group.buffer_bytes(), base);
        assert_eq!(group.connections(), 4);
        assert_eq!(a.budget.sockets(), 4);
        // Below a batch nothing is published; each member sees its own.
        a.charge(999);
        b.charge(999);
        assert_eq!(group.buffer_bytes(), base);
        assert_eq!(a.budget.allocated(), base + 999);
        let truth = a.buffer_bytes() + b.buffer_bytes();
        assert!(truth - group.buffer_bytes() < 2 * batch);
        a.charge(1);
        assert_eq!(group.buffer_bytes(), base + 1000);
        assert_eq!(b.budget.allocated(), base + 1000 + 999);
        // Past the group's pressure threshold both members are in pressure,
        // and the group counts one entry.
        a.charge(5000);
        assert_eq!(group.buffer_bytes(), base + 6000);
        assert!(!a.memory_pressure());
        a.charge(1);
        assert!(a.memory_pressure() && b.memory_pressure() && group.memory_pressure());
        assert_eq!(b.memory_counters().memory_pressures, 1);
        // The room each sees is the group's.
        assert_eq!(b.buffer_room(), memory.high - (base + 6000 + 999));
        // A return that brings the group to low ends it for both, seen
        // through what has been published.
        a.uncharge(2000);
        assert_eq!(group.buffer_bytes(), base + 4001);
        assert!(a.memory_pressure());
        b.uncharge(999);
        assert!(b.memory_pressure(), "the group is above low");
        a.uncharge(1000);
        assert_eq!(group.buffer_bytes(), base + 3001);
        assert!(a.memory_pressure(), "above low");
        // The member's own reserve counts in what it sees.
        a.uncharge(1);
        assert_eq!(group.buffer_bytes(), base + 3001);
        assert!(!a.memory_pressure() && !b.memory_pressure());
        assert!(a.take_memory_returned());
        assert!(!a.take_memory_returned());
        assert_eq!(a.memory_counters().memory_pressures, 1);
        assert_eq!(a.memory_counters().buffer_bytes, base_a + 3000);
        // b leaves: its charge and connections go with it.
        assert_eq!(b.buffer_bytes(), base_b);
        drop(b);
        assert_eq!(group.buffer_bytes(), base_a + 3001);
        assert_eq!(group.connections(), 2);
    }

    // A member whose writer waits for memory is flagged; another member
    // that returns memory says so, and the waiting member's next poll wakes
    // the writer (sk_stream_write_space after another CPU's release).
    #[test]
    fn shared_buffer_memory_returned_by_one_member_wakes_anothers_writer() {
        let (mut a, mut b, listener) = endpoints();
        let (writer, _) = connect(&mut a, &mut b, listener, 40000);
        assert_eq!(a.write(writer, &[1; 9]), Ok(9));
        writable(&mut a, writer);
        // Storage b will give back.
        b.charge(10_000);
        let base = a.buffer_bytes() + b.buffer_bytes();
        let memory = crate::BufferMemory {
            low: 0,
            pressure: base,
            high: base,
        };
        let group = crate::SharedBufferMemory::new(2, Some(memory), 1).unwrap();
        a.share_buffer_memory(&group, 0).unwrap();
        b.share_buffer_memory(&group, 1).unwrap();
        assert!(!group.waiting(0));
        let data = long_data();
        let room = held(&a, writer);
        assert_eq!(a.write(writer, &data), Ok(room));
        assert!(group.waiting(0));
        assert!(!writable(&mut a, writer));
        assert!(!a.poll_shared_memory());
        b.uncharge(10_000);
        assert!(b.take_memory_returned());
        assert!(group.waiting(0));
        assert!(!writable(&mut a, writer));
        assert!(a.poll_shared_memory());
        assert!(!group.waiting(0));
        assert!(!a.poll_shared_memory());
        exchange(&mut a, &mut b, 1);
        assert!(writable(&mut a, writer));
        assert_eq!(a.write(writer, &data[room..]), Ok(data.len() - room));
    }

    // A member that leaves publishes its reserve and takes its whole charge
    // and connections out of the group; the group leaves pressure if what
    // it holds is then at most low (__sk_mem_reduce_allocated), and the
    // other members' waiting writers look again. A member dropped leaves
    // the same way.
    #[test]
    fn a_leaving_member_releases_its_reserve_and_wakes_the_others() {
        let (mut a, mut b, listener) = endpoints();
        let (writer, _) = connect(&mut a, &mut b, listener, 40000);
        assert_eq!(a.write(writer, &[1; 9]), Ok(9));
        writable(&mut a, writer);
        b.charge(10_000);
        let (base_a, base_b) = (a.buffer_bytes(), b.buffer_bytes());
        let memory = crate::BufferMemory {
            low: base_a + 5000,
            pressure: base_a + base_b,
            high: base_a + base_b,
        };
        let group = crate::SharedBufferMemory::new(2, Some(memory), 1000).unwrap();
        a.share_buffer_memory(&group, 0).unwrap();
        b.share_buffer_memory(&group, 1).unwrap();
        // Charged and unpublished: b's reserve.
        b.charge(600);
        assert_eq!(group.buffer_bytes(), base_a + base_b);
        let data = long_data();
        let room = held(&a, writer);
        assert_eq!(a.write(writer, &data), Ok(room));
        assert!(group.memory_pressure());
        assert!(group.waiting(0));
        assert_eq!(group.connections(), 2);
        assert!(b.leave_buffer_memory());
        assert!(!b.leave_buffer_memory());
        // All b charged goes, its reserve included: a's charge is left.
        assert_eq!(group.buffer_bytes(), base_a);
        assert_eq!(a.budget.allocated(), a.buffer_bytes());
        assert_eq!(b.buffer_bytes(), base_b + 600);
        assert_eq!(group.connections(), 1);
        assert!(!group.memory_pressure(), "the group holds at most low");
        assert!(!b.memory_pressure());
        assert!(!group.waiting(1));
        assert!(group.waiting(0));
        // a's writer looks again, and its growth fits.
        assert!(a.poll_shared_memory());
        assert!(!group.waiting(0));
        exchange(&mut a, &mut b, 1);
        assert!(writable(&mut a, writer));
        assert_eq!(a.write(writer, &data[room..]), Ok(data.len() - room));
        // b's owner number is free again; dropped, b leaves as it did.
        let before = group.buffer_bytes();
        b.share_buffer_memory(&group, 1).unwrap();
        assert_eq!(group.buffer_bytes(), before + base_b + 600);
        assert_eq!(group.connections(), 2);
        assert!(!a.poll_shared_memory());
        drop(b);
        assert_eq!(a.budget.allocated(), a.buffer_bytes());
        assert_eq!(group.connections(), 1);
        assert!(a.poll_shared_memory());
    }

    // When a refused writer looks again (`memory_retry`).
    fn retry_at(a: &Endpoint, id: ConnectionId) -> Option<Instant> {
        a.slot(id).unwrap().memory_retry
    }

    // Linux's vm_wait with HZ 1000: 2 to 201 ms after `from`.
    fn within_vm_wait(from: Instant, at: Instant) -> bool {
        (from + 2_000..=from + 201_000).contains(&at)
    }

    // A member's return smaller than its batch stays in its reserve and
    // wakes no other member, but what it changes reaches a writer waiting
    // on another member at that writer's retry, at most vm_wait after its
    // refusal: here the group's connections, by which the fair share under
    // pressure divides the cap (__sk_mem_raise_allocated reads
    // sk_sockets_allocated again when sk_stream_wait_memory's vm_wait
    // ends and tcp_sendmsg retries).
    #[test]
    fn a_writer_retries_within_vm_wait_after_another_members_small_return() {
        let mut config = tuned();
        // An aborted connection's slot answers for its reset this long.
        config.connection.time_wait_us = 10;
        config.connection.send_capacity_min = 1;
        let mut a = Endpoint::new(config.clone(), [1; 32], 0, |_| true).unwrap();
        let mut b = Endpoint::new(config, [2; 32], 0, |_| true).unwrap();
        let listener = b.listen(REMOTE.parse().unwrap(), 4).unwrap();
        // The writer's large receive ring keeps it above its fair share.
        let local = SocketAddr::new("192.0.2.1".parse().unwrap(), 40000);
        let writer = a
            .connect_with_buffer_capacities(0, local, REMOTE.parse().unwrap(), 1024, 65536)
            .unwrap();
        exchange(&mut a, &mut b, 0);
        b.accept(listener).unwrap();
        let (_, idle) = connect(&mut a, &mut b, listener, 40001);
        assert_eq!(a.write(writer, &[1; 9]), Ok(9));
        drain(&mut a, 1);
        let writer_charge = a.slot(writer).unwrap().connection.buffer_charge();
        let base = a.buffer_bytes() + b.buffer_bytes();
        // Four connections hold the writer to a quarter of the cap, three
        // would not; the group stays in pressure throughout.
        let memory = crate::BufferMemory {
            low: 1,
            pressure: base - 1,
            high: 4 * writer_charge,
        };
        assert!(base < memory.high);
        let group = crate::SharedBufferMemory::new(2, Some(memory), 1 << 20).unwrap();
        a.share_buffer_memory(&group, 0).unwrap();
        b.share_buffer_memory(&group, 1).unwrap();
        assert!(group.memory_pressure());
        assert_eq!(group.connections(), 4);
        writable(&mut a, writer);
        // The write takes what the allocated ledgers hold.
        let room = held(&a, writer);
        assert_eq!(a.write(writer, &long_data()), Ok(room));
        assert_eq!(a.memory_throttled_writes(), 1);
        let refused = a.now;
        let retry = retry_at(&a, writer).unwrap();
        assert!(within_vm_wait(refused, retry), "{refused} {retry}");
        // b's idle connection goes. Its storage, less than a batch, stays in
        // b's reserve: nothing comes back to the group to wake a.
        b.abort(idle).unwrap();
        b.release(idle).unwrap();
        drain(&mut b, 2);
        b.on_timeout(12, 64).unwrap();
        assert!(!b.connection_exists(idle));
        assert_eq!(group.connections(), 3);
        assert!(!b.take_memory_returned());
        assert!(group.memory_pressure());
        assert!(!a.poll_shared_memory());
        let waiting = |a: &Endpoint| a.slot(writer).unwrap().connection.send_memory_throttled();
        a.on_timeout(retry - 1, 64).unwrap();
        assert!(waiting(&a));
        // At its retry the writer fits its fair share again.
        a.on_timeout(retry, 64).unwrap();
        assert!(!waiting(&a));
        assert_eq!(retry_at(&a, writer), None);
        assert!(!group.waiting(0));
        // Its moderated limit is full until the peer acknowledges what
        // `drain` dropped, once the retransmission timer sends it again.
        assert!(!writable(&mut a, writer));
        a.on_timeout(5_000_000, 64).unwrap();
        exchange(&mut a, &mut b, 5_000_000);
        assert!(writable(&mut a, writer));
        assert!(taken(a.write(writer, &[1; 64])) > 0);
        assert_eq!(a.memory_throttled_writes(), 1);
    }

    // Bytes another member returns stay in its reserve below a batch, and a
    // retry does not see them, as Linux's sk_memory_allocated reads the
    // shared counter, not the other CPUs' per_cpu_fw_alloc: the writer
    // waits another random vm_wait. The return that completes the batch
    // publishes it and wakes the writer.
    #[test]
    fn a_retry_that_finds_no_room_waits_another_vm_wait() {
        let (mut a, mut b, listener) = endpoints();
        let (writer, _) = connect(&mut a, &mut b, listener, 40000);
        assert_eq!(a.write(writer, &[1; 9]), Ok(9));
        writable(&mut a, writer);
        b.charge(10_000);
        let base = a.buffer_bytes() + b.buffer_bytes();
        let memory = crate::BufferMemory {
            low: 0,
            pressure: base,
            high: base,
        };
        let group = crate::SharedBufferMemory::new(2, Some(memory), 10_000).unwrap();
        a.share_buffer_memory(&group, 0).unwrap();
        b.share_buffer_memory(&group, 1).unwrap();
        let data = long_data();
        let room = held(&a, writer);
        assert_eq!(a.write(writer, &data), Ok(room));
        let first = retry_at(&a, writer).unwrap();
        b.uncharge(5_000);
        assert!(!b.take_memory_returned());
        assert!(!a.poll_shared_memory());
        a.on_timeout(first, 64).unwrap();
        let waiting = |a: &Endpoint| a.slot(writer).unwrap().connection.send_memory_throttled();
        assert!(waiting(&a));
        assert!(group.waiting(0));
        let second = retry_at(&a, writer).unwrap();
        assert!(within_vm_wait(first, second), "{first} {second}");
        assert!(!writable(&mut a, writer));
        b.uncharge(5_000);
        assert!(b.take_memory_returned());
        assert!(a.poll_shared_memory());
        assert!(!waiting(&a));
        assert_eq!(retry_at(&a, writer), None);
        exchange(&mut a, &mut b, first);
        assert!(writable(&mut a, writer));
        assert_eq!(a.write(writer, &data[room..]), Ok(data.len() - room));
    }

    // A lone endpoint's waiter retries too, as every Linux writer short of
    // memory does: a retry that finds no room changes nothing but when it
    // next looks, each delay drawn anew within vm_wait, and a return still
    // wakes it at once.
    #[test]
    fn a_lone_waiter_retries_at_random_delays_until_a_return_wakes_it() {
        let (mut a, mut b, listener) = endpoints();
        let (waiter, server) = connect(&mut a, &mut b, listener, 40000);
        let (other, _) = connect(&mut a, &mut b, listener, 40001);
        assert_eq!(a.write(other, &[2; 9]), Ok(9));
        exchange(&mut a, &mut b, 1);
        writable(&mut a, waiter);
        a.config.max_buffer_bytes = a.buffer_bytes();
        assert_eq!(a.write(waiter, &[1; 9]), Err(Error::WouldBlock.into()));
        let charged = a.buffer_bytes();
        let mut retry = retry_at(&a, waiter).unwrap();
        assert!(within_vm_wait(1, retry));
        let mut delays = Vec::new();
        for _ in 0..8 {
            a.on_timeout(retry, 64).unwrap();
            assert!(!writable(&mut a, waiter));
            assert_eq!(a.memory_throttled_writes(), 1);
            let next = retry_at(&a, waiter).unwrap();
            assert!(within_vm_wait(retry, next), "{retry} {next}");
            delays.push(next - retry);
            retry = next;
        }
        assert!(delays.iter().any(|&delay| delay != delays[0]), "{delays:?}");
        assert_eq!(a.buffer_bytes(), charged);
        // A later refused write keeps the deadline.
        assert_eq!(a.write(waiter, &[1; 9]), Err(Error::WouldBlock.into()));
        assert_eq!(retry_at(&a, waiter), Some(retry));
        // The other connection's end returns its storage and wakes it.
        a.abort(other).unwrap();
        a.release(other).unwrap();
        exchange(&mut a, &mut b, retry);
        let reclaimed = retry + a.config.connection.time_wait_us;
        a.on_timeout(reclaimed, 64).unwrap();
        assert!(!a.connection_exists(other));
        assert!(writable(&mut a, waiter));
        assert_eq!(retry_at(&a, waiter), None);
        assert_eq!(a.write(waiter, &[1; 9]), Ok(9));
        exchange(&mut a, &mut b, reclaimed);
        assert_eq!(b.read(server, &mut [0; 16]), Ok(9));
    }
}
