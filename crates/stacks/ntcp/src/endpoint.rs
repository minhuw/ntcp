extern crate alloc;

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
    connection::{Connection, ConnectionConfig, ConnectionEvents, Error, Instant, State, Tuple},
    rx_timestamp::RxTimestamps,
    schedule::{Deadlines, ReadyQueue},
    seq::Seq,
    wire::{self, ACK, Header, IpMetadata, RST, SYN},
};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionId {
    slot: usize,
    generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    pub reuse_time_wait: bool,
    pub max_listeners: usize,
    pub max_control_packets: usize,
    // Bounded FIFO of local/remote IP pairs with inferred initial/restart loss.
    pub max_setup_cache_entries: usize,
    pub max_buffer_bytes: usize,
    pub hop_limit: u8,
    pub dscp: u8,
    pub connection: ConnectionConfig,
}

impl EndpointConfig {
    pub fn validate(&self) -> Result<(), EndpointError> {
        if !(1..=1_024).contains(&self.max_setup_cache_entries)
            || self.connection.pmtud.is_some_and(|p| p.first_hop_mtu < 68)
            || !self.connection.valid_timestamp_timebase()
            || !self.connection.valid_pacing()
            || self.connection.time_wait_us < 240_000_000
            || self.connection.time_wait_us < 2 * self.connection.timebase.max_segment_lifetime_us
            || self.connection.timestamp_bytes_per_tick == 0
            || self.connection.timestamp_bytes_per_tick >= 1 << 31
            || self.connection.challenge_ack_limit == 0
            || self.connection.challenge_ack_interval_us == 0
            || self.max_connections == 0
            || self.connection.send_ip_payload_limit < self.connection.minimum_send_budget()
            || self.max_listeners == 0
            || self.hop_limit == 0
            || self.dscp > 63
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
        self.preallocation_bytes()?;
        Ok(())
    }

    fn preallocation_bytes(&self) -> Result<(usize, usize), EndpointError> {
        // The existing conservative 3*receive charge covers payload, the
        // 2-bit presence/PUSH map and the new 1-bit pending-report map.
        // Sender interval storage is a separate additive admission charge.
        let per_connection_bytes = Connection::allocation_bytes(
            self.connection.send_capacity,
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
            max_listeners: 64,
            max_control_packets: 64,
            max_setup_cache_entries: 64,
            max_buffer_bytes: 256 * 1024 * 1024,
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
}
impl From<Ipv4OptionsError> for EndpointError {
    fn from(error: Ipv4OptionsError) -> Self {
        Self::Ipv4Options(error)
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
    Occupied(Tuple, usize),
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
    fn find(&self, hash: usize, tuple: Tuple) -> Option<usize> {
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
    fn insert(&mut self, hash: usize, tuple: Tuple, slot: usize) -> Result<(), EndpointError> {
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
    fn replace(&mut self, hash: usize, tuple: Tuple, old: usize, new: usize) -> bool {
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

    fn remove(&mut self, hash: usize, tuple: Tuple, owner: usize) {
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
    connection: Connection,
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.5
    //# Note that a TCP implementation MUST keep track of whether a
    //# connection has reached SYN-RECEIVED state as the result of a passive
    //# OPEN or an active OPEN (MUST-11).
    listener: Option<ListenerId>,
    accepted_ready: bool,
    // Independent of accept-queue ownership: early accept must not free quota.
    fast_open_owner: Option<ListenerId>,
    released: bool,
    closed_output_drained: bool,
    mapped: bool,
    // ponytail: quarantine retains slot/buffers within existing connection/byte bounds;
    // compact tombstones can reclaim buffer slack if reset churn matters.
    reset_deadline: Option<Instant>,
    fallback: Option<ConnectionId>,
    hop_limit: u8,
    dscp: u8,
    received_dscp: Option<u8>,
    ipv4_options: OutgoingIpv4Options,
    explicit_route: bool,
    received_ipv4_options: Option<Ipv4Options>,
}
struct Listener {
    fast_open_cookie_policy: Option<FastOpenCookiePolicy>,
    fast_open_limit: usize,
    reset_debt: usize,
    reset_debt_expiry: Option<Instant>,
    rx_timestamp_capacity: usize,
    buffer_capacities: (usize, usize),
    application_timeout_us: Option<u64>,
    handshake_retransmission_limit: Option<NonZeroU8>,
    user_mss: Option<u16>,
    address: SocketAddr,
    backlog: usize,
    children: Vec<ConnectionId>,
    pending: VecDeque<ConnectionId>,
    closing: bool,
}

impl Listener {
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
pub struct Endpoint {
    fast_open_cookie_policy: FastOpenCookiePolicy,
    fast_open: Option<crate::fast_open::FastOpen>,
    reservations: Vec<crate::output_reservation::OutputReservation>,
    address_policy: Box<dyn Fn(AddressValidation) -> bool>,
    config: EndpointConfig,
    secret: [u8; 32],
    now: Instant,
    isn_clock: u32,
    last_isn_time: Instant,
    slots: Vec<Option<Slot>>,
    generations: Vec<u64>,
    free: Vec<usize>,
    listeners: Vec<Option<Listener>>,
    listener_generations: Vec<u64>,
    tuples: TupleTable,
    output: ReadyQueue,
    events: ReadyQueue,
    advice: ReadyQueue,
    cleanup: ReadyQueue,
    deadlines: Deadlines,
    control: VecDeque<(IpMetadata, Header, OutgoingIpv4Options, Option<u32>)>,
    passive_errors: VecDeque<Event>,
    control_epoch: Instant,
    control_count: usize,
    control_turn: bool,
    buffer_bytes: usize,
    per_connection_bytes: usize,
    receive_pool: Vec<ReceiveBuffer>,
    // ponytail: conservative FIFO loss retention until eviction; add path-qualified
    // aging only when measured deployment behavior warrants it.
    setup_loss_cache: VecDeque<(IpAddr, IpAddr)>,
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

fn valid_address(address: IpAddr) -> bool {
    !address.is_unspecified()
        && !address.is_multicast()
        && !matches!(address, IpAddr::V4(ip) if ip.octets()[0] == 0 || ip.octets()[0] >= 224)
}

impl Endpoint {
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
            fast_open: None,
            fast_open_cookie_policy: FastOpenCookiePolicy::default(),
            reservations: Vec::new(),
            address_policy: Box::new(address_policy),
            passive_errors,
            tuples: TupleTable::new(count)?,
            output: ReadyQueue::new(count).map_err(|_| Error::NoMemory)?,
            advice: ReadyQueue::new(count).map_err(|_| Error::NoMemory)?,
            events: ReadyQueue::new(event_capacity).map_err(|_| Error::NoMemory)?,
            cleanup: ReadyQueue::new(listeners_count).map_err(|_| Error::NoMemory)?,
            deadlines: Deadlines::new(count).map_err(|_| Error::NoMemory)?,
            isn_clock: (now / config.connection.timebase.ticks_from_us(4)) as u32,
            config,
            secret,
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
            control_turn: true,
            buffer_bytes,
            per_connection_bytes,
            receive_pool,
        })
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

    fn check_clock(&self, now: Instant) -> Result<(), EndpointError> {
        if now < self.now {
            return Err(Error::TimeWentBackwards.into());
        }
        let granularity = self.config.connection.timestamp_granularity;
        if self.config.connection.timestamps
            && granularity.tick_in(now, self.config.connection.timebase)
                - granularity.tick_in(self.now, self.config.connection.timebase)
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

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4.1
    //# F() MUST NOT be computable from the outside (MUST-9), or
    //# an attacker could still guess at sequence numbers from the ISN used
    //# for some other connection.

    // HMAC secrecy depends on the embedding supplying an unpredictable secret.
    fn digest(&self, domain: &[u8], tuple: Tuple) -> [u8; 32] {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.secret).expect("HMAC accepts a 32-byte key");
        mac.update(domain);
        for address in [tuple.local, tuple.remote] {
            match address.ip() {
                IpAddr::V4(ip) => {
                    mac.update(&[4]);
                    mac.update(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    mac.update(&[6]);
                    mac.update(&ip.octets());
                }
            }
            mac.update(&address.port().to_be_bytes());
        }
        mac.finalize().into_bytes().into()
    }
    fn hash(&self, tuple: Tuple) -> usize {
        let tag = self.digest(b"ntcp lookup", tuple);
        u64::from_be_bytes(tag[..8].try_into().unwrap()) as usize
    }
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4.1
    //= reason=isn adds the four-microsecond clock to the tuple-and-secret HMAC below.
    //# A TCP implementation MUST use the above type of "clock" for clock-
    //# driven selection of initial sequence numbers (MUST-8), and SHOULD
    //# generate its initial sequence numbers with the expression:

    fn isn(&mut self, tuple: Tuple) -> u32 {
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

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.1
    //# Every passive OPEN call either creates a new connection record in
    //# LISTEN state, or it returns an error; it MUST NOT affect any
    //# previously created connection record (MUST-41).
    pub fn listen(
        &mut self,
        address: SocketAddr,
        backlog: usize,
    ) -> Result<ListenerId, EndpointError> {
        if !supported_socket(address) {
            return Err(EndpointError::InvalidAddress);
        }
        if address.port() == 0
            || (!address.ip().is_unspecified() && !valid_address(address.ip()))
            || !(self.address_policy)(AddressValidation::Bind {
                local: address.ip(),
            })
            || backlog == 0
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
            .any(|listener| listener.address == address)
        {
            return Err(EndpointError::AddressInUse);
        }
        let slot = self
            .listeners
            .iter()
            .enumerate()
            .position(|(i, l)| l.is_none() && self.listener_generations[i] != u64::MAX)
            .ok_or(EndpointError::LimitReached)?;
        let children = reserved_vec(backlog)?;
        let mut pending = VecDeque::new();
        pending
            .try_reserve_exact(backlog)
            .map_err(|_| Error::NoMemory)?;
        self.listeners[slot] = Some(Listener {
            fast_open_limit: 0,
            reset_debt: 0,
            reset_debt_expiry: None,
            fast_open_cookie_policy: None,
            rx_timestamp_capacity: 0,
            buffer_capacities: (
                self.config.connection.send_capacity,
                self.config.connection.receive_capacity,
            ),
            application_timeout_us: None,
            handshake_retransmission_limit: None,
            user_mss: self.config.connection.user_mss,
            address,
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
    fn admission(&self, tuple: Tuple) -> Result<(), EndpointError> {
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
        tuple: Tuple,
        capacities: (usize, usize),
    ) -> Result<(), EndpointError> {
        if !supported_socket(tuple.local)
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
        self.resource_admission(tuple, capacities)
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.1
    //= reason=Duplicate tuple admission fails without replacing the existing record; independent listener remains legal.
    //# Return "error: connection already exists".
    fn resource_admission(
        &self,
        tuple: Tuple,
        capacities: (usize, usize),
    ) -> Result<(), EndpointError> {
        if tuple.local.port() == 0 || tuple.remote.port() == 0 {
            return Err(EndpointError::InvalidAddress);
        }
        if self.tuples.find(self.hash(tuple), tuple).is_some() {
            return Err(EndpointError::AddressInUse);
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.1
        //# If there is
        //# no room to create a new connection, return "error: insufficient
        //# resources".
        if !self.has_capacity(capacities) {
            return Err(EndpointError::LimitReached);
        }
        Ok(())
    }

    fn has_capacity(&self, capacities: (usize, usize)) -> bool {
        let credit = if self
            .receive_pool
            .iter()
            .any(|r| r.capacity() == capacities.1)
        {
            self.per_connection_bytes
        } else {
            0
        };
        !self.free.is_empty()
            && Connection::allocation_bytes(
                capacities.0,
                capacities.1,
                usize::from(self.config.connection.mss),
            )
            .is_some_and(|charge| {
                charge
                    <= self
                        .config
                        .max_buffer_bytes
                        .saturating_sub(self.buffer_bytes)
                        .saturating_add(credit)
            })
    }

    //= https://www.rfc-editor.org/rfc/rfc7323#section-7.1
    //= reason=Endpoint derives offset using HMAC-SHA256 secret, tuple and ISS nonce in the separate ntcp timestamp offset domain before first output; ISS is an input, never the offset. Modular addition/subtraction covers wire TS and ordinary/RACK RTT validation. TIME-WAIT reuse inherits the old local offset so peer PAWS sees no random jump; failed output/candidate rollback retain the old clock. Unrelated tuple/secret, echo/RTT/wrap and reuse rollback tests cover the policy.
    //# It is therefore RECOMMENDED to generate a random, per-
    //# connection offset to be used with the clock source when generating
    //# the Timestamps option value (see Section 5.4).
    //= https://www.rfc-editor.org/rfc/rfc7323#section-7
    //= reason=Endpoint derives offset using HMAC-SHA256 secret, tuple and ISS nonce in the separate ntcp timestamp offset domain before first output; ISS is an input, never the offset. Modular addition/subtraction covers wire TS and ordinary/RACK RTT validation. TIME-WAIT reuse inherits the old local offset so peer PAWS sees no random jump; failed output/candidate rollback retain the old clock. Unrelated tuple/secret, echo/RTT/wrap and reuse rollback tests cover the policy.
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
    ) -> Result<Connection, Error> {
        self.new_connection_with_buffers(
            tuple,
            iss,
            syn,
            (
                self.config.connection.send_capacity,
                self.config.connection.receive_capacity,
            ),
            0,
            RxPacketTimestamps::default(),
        )
    }

    fn new_connection_with_buffers(
        &mut self,
        tuple: Tuple,
        iss: u32,
        syn: Option<&wire::Segment<'_>>,
        capacities: (usize, usize),
        rx_ranges: usize,
        timestamps: RxPacketTimestamps,
    ) -> Result<Connection, Error> {
        self.new_connection_with_options(
            tuple,
            iss,
            syn,
            ActiveOpenOptions {
                send_capacity: capacities.0,
                receive_capacity: capacities.1,
                ..ActiveOpenOptions::from(&self.config.connection)
            },
            rx_ranges,
            timestamps,
        )
    }

    fn new_connection_with_options(
        &mut self,
        tuple: Tuple,
        iss: u32,
        syn: Option<&wire::Segment<'_>>,
        options: ActiveOpenOptions,
        rx_ranges: usize,
        timestamps: RxPacketTimestamps,
    ) -> Result<Connection, Error> {
        options.validate()?;
        let capacities = (options.send_capacity, options.receive_capacity);
        let charge = Connection::allocation_bytes(
            capacities.0,
            capacities.1,
            usize::from(self.config.connection.mss),
        )
        .ok_or(Error::NoMemory)?;
        let pool_index = self
            .receive_pool
            .iter()
            .position(|r| r.capacity() == capacities.1);
        let credit = if pool_index.is_some() {
            self.per_connection_bytes
        } else {
            0
        };
        let available = self
            .config
            .max_buffer_bytes
            .saturating_sub(self.buffer_bytes)
            .saturating_add(credit);
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
        let mut receive = pool_index.map(|index| self.receive_pool.swap_remove(index));
        let mut connection_config = self.config.connection.clone();
        connection_config.send_capacity = capacities.0;
        connection_config.receive_capacity = capacities.1;
        connection_config.user_mss = options.user_mss;
        if syn.is_some()
            && let Some(listener) = self.match_listener(tuple.local)
        {
            connection_config.user_mss = self
                .listener(listener)
                .map_err(|_| Error::InvalidArgument)?
                .user_mss;
        }
        if connection_config.initial_window == crate::InitialWindow::Iw10
            && self
                .setup_loss_cache
                .contains(&(tuple.local.ip(), tuple.remote.ip()))
        {
            connection_config.initial_window = crate::InitialWindow::Rfc5681;
        }
        // Apply the same policy to ordinary passive opens and TIME-WAIT reuse.
        let mut fast_open_response = None;
        let mut early = false;
        // RFC 7413 §4.2.2 step 5: recognized TFO needs receive authorization,
        // even when the listener or endpoint service is disabled.
        let mut accept_syn_data = syn.is_none_or(|syn| syn.options.fast_open.is_none());
        let mut filtered_syn = None;
        if let Some(syn) = syn
            && let Some(listener) = self.match_listener(tuple.local)
            && self.listeners[listener.slot]
                .as_ref()
                .unwrap()
                .fast_open_limit
                != 0
            && self.fast_open.is_some()
        {
            let limit = self.listeners[listener.slot]
                .as_ref()
                .unwrap()
                .fast_open_limit;
            // ponytail: scan at most max_connections on passive setup only;
            // use a generation-bound counter if measured SYN load warrants it.
            let pending = self
                .slots
                .iter()
                .flatten()
                .filter(|slot| {
                    slot.fast_open_owner == Some(listener)
                        && !slot.connection.handshake_complete()
                        && slot.connection.state() != State::Closed
                })
                .count();
            let reset_debt = self.listeners[listener.slot]
                .as_mut()
                .unwrap()
                .reset_debt(self.now);
            let policy = self.listeners[listener.slot]
                .as_ref()
                .unwrap()
                .fast_open_cookie_policy
                .as_ref()
                .unwrap_or(&self.fast_open_cookie_policy);
            let epoch = self.now / self.fast_open_lifetime();
            let valid = syn.options.fast_open.is_some_and(|cookie| {
                policy.valid(
                    &self.secret,
                    tuple.local.ip(),
                    tuple.remote.ip(),
                    epoch,
                    cookie,
                )
            });
            accept_syn_data = valid && pending.saturating_add(reset_debt) < limit;
            early = accept_syn_data && !syn.payload.is_empty();
            // RFC 7413 §4.2.2 permits omission; Linux does not refresh valid cookies.
            // This decision is independent of payload admission and pending quota.
            if syn.options.fast_open.is_some() && (!valid || policy.refresh_valid_cookie()) {
                fast_open_response =
                    policy.issue(&self.secret, tuple.local.ip(), tuple.remote.ip(), epoch);
            }
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
            Some(syn) => Connection::passive_with_receive(
                tuple,
                connection_config,
                iss,
                self.now,
                syn,
                accept_syn_data && syn.options.fast_open.is_some(),
                &mut receive,
                rx_timestamps,
                timestamps,
            ),
            None => Connection::active_with_receive(
                tuple,
                connection_config,
                iss,
                self.now,
                &mut receive,
            ),
        };
        if result.as_ref().is_ok_and(|connection| {
            connection.buffer_charge()
                > self
                    .config
                    .max_buffer_bytes
                    .saturating_sub(self.buffer_bytes)
                    .saturating_add(credit)
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
            connection.passive_fast_open(fast_open_response, early);
            let mut domain = *b"ntcp timestamp offset\0\0\0\0";
            let len = domain.len();
            domain[len - 4..].copy_from_slice(&iss.to_be_bytes());
            let tag = self.digest(&domain, tuple);
            connection.set_timestamp_offset(u32::from_be_bytes(tag[..4].try_into().unwrap()));
        }
        if let Some(receive) = receive {
            self.receive_pool.push(receive);
        }
        if let Ok(connection) = &result {
            self.buffer_bytes = self.buffer_bytes - credit + connection.buffer_charge();
        }
        result
    }

    fn recycle_connection(&mut self, connection: Connection) {
        let charge = connection.buffer_charge();
        self.buffer_bytes -= charge;
        if self.receive_pool.len() < self.config.preallocate_connections
            && connection.receive_allocation_capacity() == self.config.connection.receive_capacity
            && self.per_connection_bytes
                <= self
                    .config
                    .max_buffer_bytes
                    .saturating_sub(self.buffer_bytes)
        {
            let mut receive = connection.into_receive();
            receive.clear();
            self.receive_pool.push(receive);
            self.buffer_bytes += self.per_connection_bytes;
        }
    }

    fn insert(
        &mut self,
        connection: Connection,
        listener: Option<ListenerId>,
        fallback: Option<ConnectionId>,
    ) -> Result<ConnectionId, EndpointError> {
        let tuple = connection.tuple();
        let admission = (|| {
            let index = *self.free.last().ok_or(EndpointError::LimitReached)?;
            if let Some(old) = fallback {
                if self.generations.get(old.slot) != Some(&old.generation)
                    || !self.slots[old.slot].as_ref().is_some_and(|slot| {
                        slot.mapped
                            && slot.connection.tuple() == tuple
                            && slot.connection.time_wait_valid(self.now)
                    })
                {
                    return Err(EndpointError::AddressInUse);
                }
                if !self
                    .tuples
                    .replace(self.hash(tuple), tuple, old.slot, index)
                {
                    return Err(EndpointError::AddressInUse);
                }
            } else {
                if self.tuples.find(self.hash(tuple), tuple).is_some() {
                    return Err(EndpointError::AddressInUse);
                }
                self.tuples.insert(self.hash(tuple), tuple, index)?;
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
        if let Some(old) = fallback {
            self.slots[old.slot].as_mut().unwrap().mapped = false;
            self.output.remove(old.slot);
        }
        self.free.pop();
        let fast_open_owner = if connection.fast_open_early {
            listener
        } else {
            None
        };
        self.slots[index] = Some(Slot {
            fast_open_owner,
            connection,
            listener,
            accepted_ready: false,
            released: false,
            closed_output_drained: false,
            mapped: true,
            reset_deadline: None,
            fallback,
            hop_limit: self.config.hop_limit,
            dscp: self.config.dscp,
            received_dscp: None,
            ipv4_options: OutgoingIpv4Options::default(),
            explicit_route: false,
            received_ipv4_options: None,
        });
        let id = self.id(index);
        if let Some(parent) = listener {
            self.listeners[parent.slot]
                .as_mut()
                .unwrap()
                .children
                .push(id);
        }
        self.refresh(index);
        Ok(id)
    }

    /// Replace the default server cookie policy for future passive opens.
    /// Does not enable TFO, change quotas/cache/ISN secrets, or alter existing children.
    pub fn set_fast_open_cookie_policy(&mut self, policy: FastOpenCookiePolicy) {
        self.fast_open_cookie_policy = policy;
    }

    /// Override one live listener's policy; `None` inherits the endpoint policy.
    /// Does not enable TFO or alter already-created children or held output.
    pub fn set_listener_fast_open_cookie_policy(
        &mut self,
        id: ListenerId,
        policy: Option<FastOpenCookiePolicy>,
    ) -> Result<(), EndpointError> {
        self.listener(id)?;
        self.listeners[id.slot]
            .as_mut()
            .unwrap()
            .fast_open_cookie_policy = policy;
        Ok(())
    }

    /// Enable the bounded cookie service. Cookies authenticate addresses, not
    /// freshness of application operations; listeners must separately opt in.
    pub fn enable_fast_open(&mut self) -> Result<(), EndpointError> {
        if self.fast_open.is_none() {
            let charge = crate::fast_open::FastOpen::allocation_bytes();
            if charge
                > self
                    .config
                    .max_buffer_bytes
                    .saturating_sub(self.buffer_bytes)
            {
                return Err(Error::NoMemory.into());
            }
            let service = crate::fast_open::FastOpen::new()?;
            self.fast_open = Some(service);
            self.buffer_bytes += charge;
        }
        Ok(())
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
                .get(now, self.fast_open_lifetime(), local, remote)
                .is_some()
        }))
    }

    pub fn can_defer_fast_open(
        &self,
        now: Instant,
        local: IpAddr,
        remote: SocketAddr,
    ) -> Result<bool, EndpointError> {
        Ok(self.has_fast_open_cookie(now, local, remote.ip())?
            && self.fast_open.as_ref().is_some_and(|service| {
                !service.suppressed(now, self.fast_open_negative_lifetime(), local, remote)
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
        options.validate()?;
        self.check_clock(now)?;
        let service = self.fast_open.as_ref().ok_or(Error::InvalidState)?;
        let suppressed =
            service.suppressed(now, self.fast_open_negative_lifetime(), local.ip(), remote);
        let cached = service.get(now, self.fast_open_lifetime(), local.ip(), remote.ip());
        let tuple = Tuple { local, remote };
        self.admission_with_buffers(tuple, (options.send_capacity, options.receive_capacity))?;
        self.clock(now)?;
        let iss = self.isn(tuple);
        let mut connection = self.new_connection_with_options(
            tuple,
            iss,
            None,
            options,
            0,
            RxPacketTimestamps::default(),
        )?;
        let accepted = match if suppressed {
            Ok(0)
        } else {
            connection.prepare_fast_open(cached, initial)
        } {
            Ok(count) => count,
            Err(error) => {
                self.recycle_connection(connection);
                return Err(error.into());
            }
        };
        self.insert(connection, None, None).map(|id| (id, accepted))
    }

    pub fn connect(
        &mut self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<ConnectionId, EndpointError> {
        self.clock(now)?;
        let tuple = Tuple { local, remote };
        self.admission(tuple)?;
        let iss = self.isn(tuple);
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
        options.validate()?;
        self.clock(now)?;
        let tuple = Tuple { local, remote };
        self.admission_with_buffers(tuple, (options.send_capacity, options.receive_capacity))?;
        let iss = self.isn(tuple);
        let connection = self.new_connection_with_options(
            tuple,
            iss,
            None,
            options,
            0,
            RxPacketTimestamps::default(),
        )?;
        self.insert(connection, None, None)
    }

    pub fn buffer_capacities(&self, id: ConnectionId) -> Result<(usize, usize), EndpointError> {
        Ok(self.slot(id)?.connection.buffer_capacities())
    }

    pub fn set_buffer_capacities(
        &mut self,
        id: ConnectionId,
        send: usize,
        receive: usize,
    ) -> Result<(), EndpointError> {
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
        Connection::validate_buffer_capacities(send, receive)?;
        let connection = &self.slot(id)?.connection;
        let old = connection.buffer_charge();
        // This charge includes the original buffers plus all staged replacements.
        let charge = connection
            .resize_peak_charge(send, receive)
            .ok_or(EndpointError::LimitReached)?;
        if charge
            > self
                .config
                .max_buffer_bytes
                .saturating_sub(self.buffer_bytes - old)
        {
            return Err(EndpointError::LimitReached);
        }
        let max_charge = self
            .config
            .max_buffer_bytes
            .saturating_sub(self.buffer_bytes - old);
        self.slot_mut(id)?
            .connection
            .set_buffer_capacities(send, receive, max_charge)?;
        self.buffer_bytes = self.buffer_bytes - old + self.slot(id)?.connection.buffer_charge();
        self.refresh(id.slot);
        Ok(())
    }

    pub fn set_listener_buffer_capacities(
        &mut self,
        id: ListenerId,
        send: usize,
        receive: usize,
    ) -> Result<(), EndpointError> {
        let rx_ranges = self.listener(id)?.rx_timestamp_capacity;
        Connection::validate_buffer_capacities(send, receive)?;
        self.validate_listener_rx_capacity((send, receive), rx_ranges)?;
        self.listeners[id.slot].as_mut().unwrap().buffer_capacities = (send, receive);
        Ok(())
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
        let total = Connection::allocation_bytes(
            capacities.0,
            capacities.1,
            usize::from(self.config.connection.mss),
        )
        .and_then(|bytes| bytes.checked_add(metadata))
        .ok_or(Error::NoMemory)?;
        if total > self.config.max_buffer_bytes {
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
        let slot = self.slots[index].take().unwrap();
        let tuple = slot.connection.tuple();
        if slot.mapped {
            self.tuples.remove(self.hash(tuple), tuple, index);
        }
        if let Some(parent) = slot.listener {
            self.unlink_child(parent, id);
        }
        self.output.remove(index);
        self.events.remove(index);
        self.advice.remove(index);
        self.deadlines.set(index, None);
        self.recycle_connection(slot.connection);
        if let Some(generation) = self.generations[index].checked_add(1) {
            self.generations[index] = generation;
            self.free.push(index);
        }
    }

    fn refresh(&mut self, index: usize) {
        let fast_open_lifetime = self.fast_open_lifetime();
        // RFC 7413 §5.1: retain recent remote resets in admission accounting.
        // Sixty seconds and latest-reset batch retention are local policy.
        let reset_cooldown = self.config.connection.timebase.ticks_from_us(60_000_000);
        if let Some(slot) = self.slots[index].as_mut() {
            if core::mem::take(&mut slot.connection.fast_open_negative)
                && let Some(service) = self.fast_open.as_mut()
            {
                let tuple = slot.connection.tuple();
                service.fail(self.now, tuple.local.ip(), tuple.remote);
            }
            if let Some((cookie, mss)) = slot.connection.fast_open_learned.take()
                && let Some(service) = self.fast_open.as_mut()
            {
                let tuple = slot.connection.tuple();
                if let Some(cookie) = cookie {
                    service.learn(self.now, tuple.local.ip(), tuple.remote.ip(), cookie, mss);
                } else {
                    service.update_mss(
                        self.now,
                        fast_open_lifetime,
                        tuple.local.ip(),
                        tuple.remote.ip(),
                        mss,
                    );
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
        if self.is_output_reserved(self.id(index)) {
            self.deadlines.set(index, None);
            return;
        }
        if let Some(slot) = &self.slots[index]
            && slot.connection.iw_setup_loss()
        {
            let tuple = slot.connection.tuple();
            let key = (tuple.local.ip(), tuple.remote.ip());
            if !self.setup_loss_cache.contains(&key) {
                if self.setup_loss_cache.len() == self.config.max_setup_cache_entries {
                    self.setup_loss_cache.pop_front();
                }
                self.setup_loss_cache.push_back(key);
            }
        }
        if let Some(slot) = self.slots[index].as_ref()
            && (slot.connection.handshake_complete()
                || (slot.connection.state() == State::Closed
                    && !slot.connection.reset_pending()
                    && slot.reset_deadline.is_none()))
            && let Some(old) = slot.fallback
        {
            let failed = slot.connection.state() == State::Closed;
            let tuple = slot.connection.tuple();
            self.slots[index].as_mut().unwrap().fallback = None;
            // Released handles are intentionally eligible; generation, tuple,
            // state, deadline and current mapping ownership must all still match.
            if failed
                && self.generations.get(old.slot) == Some(&old.generation)
                && self.slots[old.slot].as_ref().is_some_and(|slot| {
                    !slot.mapped
                        && slot.connection.tuple() == tuple
                        && slot.connection.time_wait_valid(self.now)
                })
                && self
                    .tuples
                    .replace(self.hash(tuple), tuple, index, old.slot)
            {
                self.slots[index].as_mut().unwrap().mapped = false;
                self.slots[old.slot].as_mut().unwrap().mapped = true;
                self.output.push(old.slot);
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
        let state = slot.connection.state();
        let parent = slot.listener;
        let newly_established = !slot.accepted_ready
            && (slot.connection.handshake_complete() || slot.connection.fast_open_early)
            && state != State::Closed;
        // Early accept readiness already transfers terminal delivery to the app.
        // Explicit release/listener cleanup still abandons that ownership.
        let retained_early =
            slot.accepted_ready && slot.connection.fast_open_early && !slot.released;
        let failed_child = parent.is_some() && state == State::Closed && !retained_early;
        let reset_reserved = slot.connection.reset_pending() || slot.reset_deadline.is_some();
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
            let tuple = self.slots[index].as_ref().unwrap().connection.tuple();
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
                let was_empty = listener.pending.is_empty();
                listener.pending.push_back(id);
                if was_empty {
                    self.events.push(self.config.max_connections + parent.slot);
                }
            }
        }
        let slot = self.slots[index].as_ref().unwrap();
        self.deadlines.set(
            index,
            slot.reset_deadline.or(slot.connection.next_deadline()),
        );
        if slot.listener.is_none() && !slot.released && slot.connection.events_pending() {
            self.events.push(index);
        }
        if (slot.mapped && state != State::Closed)
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
    fn match_listener(&self, local: SocketAddr) -> Option<ListenerId> {
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
            if listener.address == local {
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
        segment: &wire::Segment<'_>,
        route: Option<SourceRoute>,
    ) {
        if segment.header.flags & RST != 0 || self.control.len() >= self.config.max_control_packets
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
            // Scope: Reactive RST uses (0,incoming TSval) independently of local TS configuration/negotiation when the IP payload budget permits 32 TCP bytes. At budgets 28..31 the optional TS is omitted rather than exceeding the path bound; this bounded SHOULD departure is tested for ACK/no-ACK resets. SYN-SENT and synchronized handshake rejection preserve the same echo policy.
            //= https://www.rfc-editor.org/rfc/rfc7323#section-5.2
            //= reason=Reactive RST uses (0,incoming TSval) independently of local TS configuration/negotiation when the IP payload budget permits 32 TCP bytes. At budgets 28..31 the optional TS is omitted rather than exceeding the path bound; this bounded SHOULD departure is tested for ACK/no-ACK resets. SYN-SENT and synchronized handshake rejection preserve the same echo policy.
            //# While still under discussion, to enable research into this area it is
            //# now RECOMMENDED that when generating an <RST>, if the segment causing
            //# the <RST> to be generated contains a Timestamps option, the <RST>
            //# should also contain a Timestamps option.
            // Scope: Reactive RST uses (0,incoming TSval) independently of local TS configuration/negotiation when the IP payload budget permits 32 TCP bytes. At budgets 28..31 the optional TS is omitted rather than exceeding the path bound; this bounded SHOULD departure is tested for ACK/no-ACK resets. SYN-SENT and synchronized handshake rejection preserve the same echo policy.
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
        timestamps.validate(self.config.connection.timebase)?;
        if !options.is_empty()
            && (!self.config.ipv4_options_enabled
                || !ip.source.is_ipv4()
                || !ip.destination.is_ipv4())
        {
            return Ok(InputDisposition::Dropped);
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
            || !(self.address_policy)(AddressValidation::Incoming {
                source: ip.source, destination: ip.destination,
            })
        {
            return Ok(InputDisposition::Dropped);
        }
        let route = match ip.source {
            IpAddr::V4(source) => options.return_route(source),
            _ => None,
        };
        if route.is_some_and(|r| {
            r.hops()
                .iter()
                .any(|&a| !self.valid_route(ip.destination, ip.source, a.into()))
        }) {
            return Ok(InputDisposition::Dropped);
        }
        let segment = match wire::parse(ip, bytes) {
            Ok(segment) => segment,
            Err(_) => return Ok(InputDisposition::Dropped),
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
        let target = self.tuples.find(self.hash(tuple), tuple);
        if target.is_some_and(|index| self.is_output_reserved(self.id(index))) {
            return Err(EndpointError::OutputReserved);
        }
        self.clock(now)?;
        if let Some(index) = target {
            let slot = self.slots[index].as_ref().unwrap();
            if slot.connection.reset_pending() || slot.reset_deadline.is_some() {
                return Ok(InputDisposition::Dropped);
            }
            if self.config.reuse_time_wait
                && self.slots[index].as_ref().unwrap().connection.state() == State::TimeWait
                && segment.header.flags & !(wire::ECE | wire::CWR) == SYN
                && segment.payload.is_empty()
            {
                return self.reopen_time_wait(index, tuple, traffic_class, options, &segment);
            }
            let slot = self.slots[index].as_mut().unwrap();
            slot.received_dscp = Some(traffic_class >> 2);
            slot.connection
                .input_with_timestamps(now, traffic_class, &segment, timestamps)?;
            if slot.connection.accepted_metadata {
                Self::save_ipv4_options(slot, options, route);
            }
            self.refresh(index);
            return Ok(InputDisposition::Processed);
        }
        if let Some(listener) = self.match_listener(tuple.local) {
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
                self.reset_for(ip, &segment, route);
                return Ok(InputDisposition::Processed);
            }
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.2
            //# Drop the segment and return.
            if segment.header.flags & SYN == 0 {
                return Ok(InputDisposition::Dropped);
            }
            let record = self.listeners[listener.slot].as_ref().unwrap();
            if record.children.len() >= record.backlog
                || self
                    .resource_admission(tuple, record.buffer_capacities)
                    .is_err()
            {
                return Ok(InputDisposition::Dropped);
            }
            let application_timeout = record.application_timeout_us;
            let handshake_retransmission_limit = record.handshake_retransmission_limit;
            let buffer_capacities = record.buffer_capacities;
            let rx_ranges = record.rx_timestamp_capacity;
            let iss = self.isn(tuple);
            let mut connection = match self.new_connection_with_buffers(
                tuple,
                iss,
                Some(&segment),
                buffer_capacities,
                rx_ranges,
                timestamps,
            ) {
                Ok(connection) => connection,
                Err(Error::NoMemory) => return Ok(InputDisposition::Dropped),
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
                Err(EndpointError::LimitReached) => return Ok(InputDisposition::Dropped),
                Err(error) => return Err(error),
            }
        }
        self.reset_for(ip, &segment, route);
        Ok(InputDisposition::Dropped)
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.6.1
    //# However, it MAY accept a new SYN from the remote TCP endpoint to
    //# reopen the connection directly from TIME-WAIT state (MAY-2), if it:
    //#
    //# (1)  assigns its initial sequence number for the new connection to be
    //#      larger than the largest sequence number it used on the previous
    //#      connection incarnation, and
    //#
    //# (2)  returns to TIME-WAIT state if the SYN turns out to be an old
    //#      duplicate.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.6.1
    //# This algorithm for reducing TIME-WAIT is a Best
    //# Current Practice that SHOULD be implemented since Timestamp Options
    //# are commonly used, and using them to reduce TIME-WAIT provides
    //# benefits for busy Internet servers (SHLD-4).
    fn reopen_time_wait(
        &mut self,
        index: usize,
        tuple: Tuple,
        traffic_class: u8,
        options: Ipv4Options,
        syn: &wire::Segment<'_>,
    ) -> Result<InputDisposition, EndpointError> {
        let Some(listener) = self.match_listener(tuple.local) else {
            return Ok(InputDisposition::Dropped);
        };
        let record = self.listeners[listener.slot].as_ref().unwrap();
        if record.children.len() >= record.backlog
            || !self.has_capacity(record.buffer_capacities)
            || !self.slots[index].as_ref().unwrap().connection.reuse_syn(
                self.now,
                syn,
                self.config.connection.timestamps,
            )
        {
            return Ok(InputDisposition::Dropped);
        }
        let application_timeout = record.application_timeout_us;
        let handshake_retransmission_limit = record.handshake_retransmission_limit;
        let buffer_capacities = record.buffer_capacities;
        let rx_ranges = record.rx_timestamp_capacity;
        let candidate = self.isn(tuple);
        let iss = self.slots[index]
            .as_ref()
            .unwrap()
            .connection
            .reuse_iss(candidate);
        // Allocate the entire bounded child before transferring tuple ownership.
        // The old timer/record survives independently until its original expiry.
        let mut connection = match self.new_connection_with_buffers(
            tuple,
            iss,
            Some(syn),
            buffer_capacities,
            rx_ranges,
            RxPacketTimestamps::default(),
        ) {
            Ok(connection) => connection,
            Err(Error::NoMemory) => return Ok(InputDisposition::Dropped),
            Err(error) => return Err(error.into()),
        };
        // Reuse keeps the old local virtual clock: peer PAWS must not see a
        // random jump. Candidate failure leaves the old offset/timer untouched.
        connection.set_timestamp_offset(
            self.slots[index]
                .as_ref()
                .unwrap()
                .connection
                .timestamp_offset(),
        );
        connection.set_handshake_retransmission_limit(handshake_retransmission_limit);
        if let Err(error) = connection.set_application_timeout(application_timeout) {
            self.recycle_connection(connection);
            return Err(error.into());
        }
        let id = self.insert(connection, Some(listener), Some(self.id(index)))?;
        let slot = self.slots[id.slot].as_mut().unwrap();
        slot.received_dscp = Some(traffic_class >> 2);
        // Input validated the route before selecting the TIME-WAIT reuse path.
        let route = match tuple.remote.ip() {
            IpAddr::V4(source) => options.return_route(source),
            _ => None,
        };
        Self::save_ipv4_options(slot, options, route);
        Ok(InputDisposition::Processed)
    }

    pub fn write(&mut self, id: ConnectionId, bytes: &[u8]) -> Result<usize, EndpointError> {
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
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
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
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
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
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
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
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

    pub fn set_rx_timestamp_capacity(
        &mut self,
        id: ConnectionId,
        ranges: usize,
    ) -> Result<(), EndpointError> {
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
        let old = self.slot(id)?.connection.rx_timestamps.storage_bytes();
        let spare = self
            .config
            .max_buffer_bytes
            .saturating_sub(self.buffer_bytes);
        self.slot_mut(id)?
            .connection
            .rx_timestamps
            .resize(ranges, spare)?;
        self.buffer_bytes =
            self.buffer_bytes - old + self.slot(id)?.connection.rx_timestamps.storage_bytes();
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
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
        let old = self.slot(id)?.connection.tx_timestamps.storage_bytes();
        let spare = self
            .config
            .max_buffer_bytes
            .saturating_sub(self.buffer_bytes);
        self.slot_mut(id)?
            .connection
            .tx_timestamps
            .resize(phases, spare)?;
        self.buffer_bytes =
            self.buffer_bytes - old + self.slot(id)?.connection.tx_timestamps.storage_bytes();
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
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
        Ok(self
            .slot(id)?
            .connection
            .check_write_admission(lowat, request)?)
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
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
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
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
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
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
        self.slot_mut(id)?
            .connection
            .set_fast_open_write_pending(pending)?;
        Ok(())
    }

    /// Record a blocked adapter admission without changing send boundaries.
    /// LOWAT-only exhaustion is not byte-buffer backpressure.
    pub fn record_send_backpressure(&mut self, id: ConnectionId) -> Result<(), EndpointError> {
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
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
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
        self.slot_mut(id)?
            .connection
            .finish_send(end, more, end_of_record, force);
        self.refresh(id.slot);
        Ok(())
    }

    pub fn cancel_tx_timestamps(&mut self, id: ConnectionId) -> Result<(), EndpointError> {
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
        self.slot_mut(id)?.connection.tx_timestamps.cancel_from(0);
        Ok(())
    }

    /// Read-only byte admission budget under the same policy as the write API.
    pub fn send_admission_room(
        &self,
        id: ConnectionId,
        lowat: Option<u32>,
    ) -> Result<usize, EndpointError> {
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
        Ok(self.slot(id)?.connection.send_admission_room(lowat))
    }

    /// Hold partial output until uncork, explicit NODELAY, or a 200ms timeout.
    pub fn set_cork(&mut self, id: ConnectionId, enabled: bool) -> Result<(), EndpointError> {
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
        self.slot_mut(id)?.connection.set_cork(enabled);
        self.refresh(id.slot);
        Ok(())
    }

    pub fn flush(&mut self, id: ConnectionId) -> Result<usize, EndpointError> {
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
        let count = self.slot_mut(id)?.connection.flush()?;
        self.refresh(id.slot);
        Ok(count)
    }
    pub fn close(&mut self, id: ConnectionId) -> Result<(), EndpointError> {
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
        self.slot_mut(id)?.connection.close()?;
        self.refresh(id.slot);
        Ok(())
    }
    pub fn write_urgent(&mut self, id: ConnectionId, bytes: &[u8]) -> Result<usize, EndpointError> {
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
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
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
        let count = self.slot_mut(id)?.connection.read(out)?;
        self.refresh(id.slot);
        Ok(count)
    }
    // Socket adapters may drain accepted bytes after CLOSED; the normal read
    // contract remains unchanged. Eligibility excludes unfinished handshakes
    // and discarded receive sides, and draining schedules no network output.
    pub fn read_terminal(
        &mut self,
        id: ConnectionId,
        out: &mut [u8],
    ) -> Result<usize, EndpointError> {
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
        Ok(self.slot_mut(id)?.connection.read_terminal(out)?)
    }

    // Count only bytes eligible for terminal draining.
    pub fn terminal_readable_bytes(&self, id: ConnectionId) -> Result<usize, EndpointError> {
        Ok(self.slot(id)?.connection.terminal_readable_bytes())
    }

    pub fn shutdown(&mut self, id: ConnectionId) -> Result<(), EndpointError> {
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
        self.slot_mut(id)?.connection.shutdown()?;
        self.refresh(id.slot);
        Ok(())
    }
    pub fn abort(&mut self, id: ConnectionId) -> Result<(), EndpointError> {
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
        self.slot_mut(id)?.connection.abort();
        self.refresh(id.slot);
        Ok(())
    }
    pub fn set_nagle(&mut self, id: ConnectionId, enabled: bool) -> Result<(), EndpointError> {
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
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
        let Some(index) = self.tuples.find(self.hash(tuple), tuple) else {
            return Ok(false);
        };
        if self.is_output_reserved(self.id(index)) {
            return Err(EndpointError::OutputReserved);
        }
        self.clock(now)?;
        if error == crate::NetworkError::SourceQuench {
            return Ok(false);
        }
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

    pub fn pmtu_feedback(
        &mut self,
        now: Instant,
        tuple: Tuple,
        quoted_sequence: u32,
        ip_packet_len: u32,
        ip_header_len: u16,
        candidate_mtu: u32,
    ) -> Result<bool, EndpointError> {
        let Some(index) = self.tuples.find(self.hash(tuple), tuple) else {
            return Ok(false);
        };
        if self.is_output_reserved(self.id(index)) {
            return Err(EndpointError::OutputReserved);
        }
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
        // A prepared backend object keeps its ledger immutable until rejection.
        if self.is_group_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
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

    pub fn set_first_hop_mtu(
        &mut self,
        now: Instant,
        id: ConnectionId,
        mtu: u32,
    ) -> Result<(), EndpointError> {
        if self.is_group_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
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
        if self
            .reservations
            .iter()
            .any(|slot| slot.current.as_ref().is_some_and(|r| r.group.is_some()))
        {
            return Err(EndpointError::OutputReserved);
        }
        if self.config.connection.pmtud.is_none()
            || !(68..=65575).contains(&mtu)
            || mtu > 65535
                && (self.listeners.iter().flatten().any(|l| l.address.is_ipv4())
                    || self.control.iter().any(|(ip, _, _, _)| ip.source.is_ipv4()))
            || mtu < 1280
                && (self.listeners.iter().flatten().any(|l| l.address.is_ipv6())
                    || self.control.iter().any(|(ip, _, _, _)| ip.source.is_ipv6()))
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
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
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
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
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
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
        self.slot_mut(id)?.connection.set_user_timeout(timeout_us)?;
        self.refresh(id.slot);
        Ok(())
    }
    pub fn set_application_timeout(
        &mut self,
        id: ConnectionId,
        timeout_us: Option<u64>,
    ) -> Result<(), EndpointError> {
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
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
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
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
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
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
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
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
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
        if dscp > 63 {
            return Err(Error::InvalidArgument.into());
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.9
        //# It is not required, but the
        //# application SHOULD be able to change the Differentiated Services
        //# field during the connection lifetime (SHLD-21).
        self.slot_mut(id)?.dscp = dscp;
        Ok(())
    }
    pub fn close_reason(
        &self,
        id: ConnectionId,
    ) -> Result<Option<crate::CloseReason>, EndpointError> {
        Ok(self.slot(id)?.connection.close_reason())
    }
    // Observe an existing connection without transferring ownership.
    pub fn connection_id(&self, tuple: Tuple) -> Option<ConnectionId> {
        self.tuples
            .find(self.hash(tuple), tuple)
            .map(|index| self.id(index))
    }

    // Includes released records retained for final output or TIME-WAIT.
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
        if self.is_output_reserved(id) {
            return Err(EndpointError::OutputReserved);
        }
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
        self.buffer_bytes -= charge;
        self.events.remove(id.slot);
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

    pub fn next_deadline(&self) -> Option<Instant> {
        self.deadlines
            .first()
            .map(|(time, _)| time)
            .into_iter()
            .chain(self.reservations.iter().filter_map(|slot| {
                let r = slot.current.as_ref()?;
                if r.attempt.is_some() {
                    return None;
                }
                self.retained_slot(r.packet.connection?)
                    .ok()?
                    .connection
                    .reserved_pacing_deadline(self.now, r.departure.as_ref()?)
            }))
            .min()
    }
    pub fn has_pending_output(&self) -> bool {
        self.reservations.iter().any(|slot| slot.current.is_some())
            || !self.output.is_empty()
            || !self.control.is_empty()
            || !self.cleanup.is_empty()
    }
    pub fn buffer_bytes(&self) -> usize {
        self.buffer_bytes
    }

    pub fn on_timeout(&mut self, now: Instant, budget: usize) -> Result<bool, EndpointError> {
        self.clock(now)?;
        for _ in 0..budget {
            let Some((deadline, index)) = self.deadlines.first() else {
                break;
            };
            if deadline > now {
                break;
            }
            self.deadlines.set(index, None);
            let slot = self.slots[index].as_mut().unwrap();
            if slot.reset_deadline.is_some_and(|deadline| deadline <= now) {
                slot.reset_deadline = None;
            } else {
                slot.connection.timeout(now)?;
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
            .is_some_and(|(deadline, _)| deadline <= now))
    }

    pub fn enable_output_reservations(&mut self) -> Result<(), EndpointError> {
        self.enable_output_reservations_with_capacity(1)
    }

    pub fn enable_output_reservations_with_capacity(
        &mut self,
        count: usize,
    ) -> Result<(), EndpointError> {
        self.enable_output_pool(count, None)
    }

    pub fn enable_output_reservations_with_gso(
        &mut self,
        count: usize,
        limits: crate::GsoLimits,
    ) -> Result<(), EndpointError> {
        if limits.max_bytes == 0
            || limits.max_bytes > u32::MAX as usize / 2
            || limits.max_segments < 2
            || limits.max_segments > limits.max_bytes
        {
            return Err(Error::InvalidArgument.into());
        }
        self.enable_output_pool(count, Some(limits))
    }

    fn enable_output_pool(
        &mut self,
        count: usize,
        gso: Option<crate::GsoLimits>,
    ) -> Result<(), EndpointError> {
        if self.reservations.iter().any(|slot| slot.current.is_some()) {
            return Err(EndpointError::OutputReserved);
        }
        if count == 0 || count > self.config.max_connections.saturating_add(1) {
            return Err(Error::InvalidArgument.into());
        }
        if !self.reservations.is_empty() {
            return if count == self.reservations.len() && self.reservations[0].gso == gso {
                Ok(())
            } else {
                Err(Error::InvalidArgument.into())
            };
        }
        let size = self.config.connection.send_ip_payload_limit as usize;
        let payload_size = gso.map_or(0, |limits| limits.max_bytes);
        let charge = size
            .checked_add(payload_size)
            .ok_or(Error::NoMemory)?
            .checked_add(core::mem::size_of::<
                crate::output_reservation::OutputReservation,
            >())
            .and_then(|size| size.checked_mul(count))
            .ok_or(Error::NoMemory)?;
        if charge
            > self
                .config
                .max_buffer_bytes
                .saturating_sub(self.buffer_bytes)
        {
            return Err(Error::NoMemory.into());
        }
        let mut slots = reserved_vec(count)?;
        for index in 0..count {
            let mut slot = crate::output_reservation::OutputReservation::new();
            slot.index = index;
            slot.bytes = reserved_vec(size)?;
            slot.bytes.resize(size, 0);
            slot.payload = reserved_vec(payload_size)?;
            slot.payload.resize(payload_size, 0);
            slot.gso = gso;
            slots.push(slot);
        }
        self.reservations = slots;
        self.buffer_bytes += charge;
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

    /// Prepare a full-MSS prefix without allocating or changing sender credit.
    /// The scalar attempt must be certainly unsubmitted, not an unknown result.
    /// None/error leaves the scalar attempt intact. Successful preparation
    /// invalidates it; only the returned group can accept/reject this submission.
    pub fn prepare_transmit_group(
        &mut self,
        attempt: crate::TransmitAttempt,
        limits: crate::TransmitGroupLimits,
    ) -> Result<Option<crate::TransmitGroup>, EndpointError> {
        let Some(slot) = self.reservations.get(attempt.reservation) else {
            return Ok(None);
        };
        let Some(r) = slot
            .current
            .as_ref()
            .filter(|r| r.attempt == Some(attempt) && r.group.is_none())
        else {
            return Ok(None);
        };
        let Some(d) = r.departure.filter(|d| d.segmentation.is_some()) else {
            return Ok(None);
        };
        let s = d.segmentation.unwrap();
        let owner = &self
            .retained_slot(attempt.connection.ok_or(EndpointError::InvalidHandle)?)?
            .connection;
        if s.segment_payload_len == 0
            || owner.reserved_group_mss(s.tcp_header_len) != s.segment_payload_len
            || r.offset % s.segment_payload_len != 0
            || !limits.allow_cwr && r.offset == 0 && s.terminal_flags & wire::CWR != 0
        {
            return Ok(None);
        }
        let remaining = s
            .payload_len
            .checked_sub(r.offset)
            .ok_or(Error::InvalidArgument)?;
        let mut segments = (remaining / s.segment_payload_len)
            .min(limits.max_segments)
            .min(limits.max_bytes / s.segment_payload_len);
        if !limits.allow_psh
            && s.terminal_flags & wire::PSH != 0
            && segments * s.segment_payload_len == remaining
        {
            segments = segments.saturating_sub(1);
        }
        if segments < 2 {
            return Ok(None);
        }
        let bytes = segments
            .checked_mul(s.segment_payload_len)
            .ok_or(Error::InvalidArgument)?;
        // Validate the borrowed header as well as every RACK boundary before
        // issuing a token that the backend may submit as one indivisible object.
        wire::parse(r.packet.ip, &slot.bytes[..r.packet.len]).map_err(Error::Wire)?;
        owner.validate_reserved_group(self.now, &d, r.offset, segments)?;
        let token =
            crate::TransmitGroup(self.reservations[attempt.reservation].token(attempt.connection)?);
        let r = self.reservations[attempt.reservation]
            .current
            .as_mut()
            .unwrap();
        r.group = Some(crate::output_reservation::PreparedGroup {
            token,
            segments,
            bytes,
        });
        // A private scalar-shaped identity preserves all existing owner barriers.
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
        let original = wire::parse(r.packet.ip, &slot.bytes[..r.packet.len]).ok()?;
        let mut header = original.header;
        header.sequence = header.sequence.wrapping_add(r.offset as u32);
        header.flags = s.terminal_flags;
        if r.offset + group.bytes != s.payload_len {
            header.flags &= !wire::PSH;
        }
        if r.offset != 0 {
            header.flags &= !wire::CWR;
        }
        Some(crate::TransmitGroupView {
            packet: Transmit {
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

    /// Read-only, allocation-free acceptance preflight for a prepared group.
    /// Returns false for a stale/invalid token; clock or owner-history violations
    /// return the same errors as acceptance, without consuming the group.
    /// Call immediately before each submission (including WouldBlock retries),
    /// serializing endpoint access through submission and acceptance. Success
    /// does not reserve time: acceptance must still validate its submission time.
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
        let id = token.0.connection.ok_or(EndpointError::InvalidHandle)?;
        self.retained_slot(id)?.connection.validate_reserved_group(
            now,
            &r.departure.unwrap(),
            r.offset,
            group.segments,
        )?;
        self.check_clock(now)?;
        Ok(true)
    }

    /// Commit one accepted backend object as N distinct physical spans. `now`
    /// is the monotonic submission time, NOT a per-segment hardware timestamp.
    /// Preflight errors do not mutate state; after backend acceptance callers
    /// must quarantine integration errors, never resubmit the object.
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
        let size = departure.segmentation.unwrap().segment_payload_len;
        let offset = r.offset;
        let finished = offset + group.bytes == departure.payload;
        let id = token.0.connection.unwrap();
        self.now = now;
        let owner = &mut self.retained_slot_mut(id)?.connection;
        for n in 0..group.segments {
            // Collective preflight proves split capacity for the entire prefix;
            // no external mutation can interleave these commits.
            owner
                .accept_reserved_output(
                    now,
                    &mut departure,
                    offset + n * size,
                    size,
                    finished && n + 1 == group.segments,
                )
                .expect("preflighted group departure");
        }
        let r = self.reservations[index].current.as_mut().unwrap();
        r.emitted_bytes = group.bytes;
        r.emitted_sacks = 0;
        r.group = None;
        self.complete_reserved_accept(index, Some(departure), finished);
        Ok(true)
    }

    /// Only for a backend's synchronous, certainly-unsubmitted rejection.
    /// Unknown submission outcomes must remain quarantined, never retried.
    pub fn reject_unsubmitted_group(
        &mut self,
        token: crate::TransmitGroup,
    ) -> Result<bool, EndpointError> {
        let Some(r) = self
            .reservations
            .get_mut(token.0.reservation)
            .and_then(|slot| slot.current.as_mut())
        else {
            return Ok(false);
        };
        if !r.group.is_some_and(|g| g.token == token) {
            return Ok(false);
        }
        r.group = None;
        r.attempt = None;
        Ok(true)
    }

    /// Same certified-unsubmitted precondition as `abandon_transmit`. The latest
    /// handle also survives rejection or accepted prefixes to abandon only the
    /// remaining suffix, until another scalar/group token replaces it.
    pub fn abandon_transmit_group(
        &mut self,
        token: crate::TransmitGroup,
    ) -> Result<bool, EndpointError> {
        self.abandon_transmit(token.0)
    }

    fn is_group_reserved(&self, id: ConnectionId) -> bool {
        self.reservations.iter().any(|slot| {
            slot.current
                .as_ref()
                .is_some_and(|r| r.packet.connection == Some(id) && r.group.is_some())
        })
    }

    // ponytail: bounded linear pool lookup; add a slot index if measured flow counts warrant it.
    pub fn is_output_reserved(&self, id: ConnectionId) -> bool {
        self.reservations.iter().any(|slot| {
            slot.current
                .as_ref()
                .is_some_and(|r| r.packet.connection == Some(id))
        })
    }

    pub fn ready_connections(&self) -> impl Iterator<Item = ConnectionId> + '_ {
        self.output
            .iter()
            .map(|index| self.id(index))
            .filter(|&id| {
                self.reservations
                    .iter()
                    .find_map(|slot| {
                        slot.current
                            .as_ref()
                            .filter(|r| r.packet.connection == Some(id))
                    })
                    .is_none_or(|r| r.attempt.is_none())
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
        self.poll_reserved_selected(now, out, budget, Some(id))
    }

    pub fn poll_reserved_stateless_transmit(
        &mut self,
        now: Instant,
        out: &mut [u8],
        budget: usize,
    ) -> Result<(PollTransmit, Option<crate::TransmitAttempt>), EndpointError> {
        self.poll_reserved_selected(now, out, budget, None)
    }

    pub fn poll_reserved_transmit(
        &mut self,
        now: Instant,
        out: &mut [u8],
        budget: usize,
    ) -> Result<(PollTransmit, Option<crate::TransmitAttempt>), EndpointError> {
        if self.reservations.is_empty() {
            return Err(Error::InvalidArgument.into());
        }
        let free = self.reservations.iter().any(|slot| slot.current.is_none());
        if !free
            && !self
                .reservations
                .iter()
                .any(|slot| slot.current.as_ref().is_some_and(|r| r.attempt.is_none()))
        {
            return Err(EndpointError::OutputReserved);
        }
        self.clock(now)?;
        for _ in 0..budget {
            let next = self
                .ready_connections()
                .find(|&id| free || self.is_output_reserved(id));
            let control = free
                && !self.control.is_empty()
                && !self.reservations.iter().any(|slot| {
                    slot.current
                        .as_ref()
                        .is_some_and(|r| r.packet.connection.is_none())
                });
            let owner = if control && (self.control_turn || next.is_none()) {
                None
            } else {
                next
            };
            if owner.is_none() && !control {
                self.cleanup_one();
                continue;
            }
            let result = self.poll_reserved_selected(now, out, 1, owner)?;
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
    fn poll_reserved_selected(
        &mut self,
        now: Instant,
        out: &mut [u8],
        budget: usize,
        selected: Option<ConnectionId>,
    ) -> Result<(PollTransmit, Option<crate::TransmitAttempt>), EndpointError> {
        if self.reservations.is_empty() {
            return Err(Error::InvalidArgument.into());
        }
        let existing = self.reservations.iter().position(|slot| {
            slot.current
                .as_ref()
                .is_some_and(|r| r.packet.connection == selected)
        });
        let index = existing
            .or_else(|| {
                self.reservations
                    .iter()
                    .position(|slot| slot.current.is_none())
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
            let packet = self.reservations[index].fragment(limit, out)?;
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
            let attempt = self.reservations[index].token(connection)?;
            let r = self.reservations[index].current.as_mut().unwrap();
            r.attempt = Some(attempt);
            r.abandon_attempt = attempt;
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
        let mut attempt = self.reservations[index].token(None)?;
        let capacity = out.len().min(self.reservations[index].bytes.len());
        // Move the preallocated payload backing temporarily to avoid aliasing
        // the endpoint during selection; restore it on every result, no allocation.
        let mut payload = core::mem::take(&mut self.reservations[index].payload);
        let gso = self.reservations[index]
            .gso
            .map(|limits| crate::output_reservation::GsoBuffer {
                limits,
                payload: &mut payload[..],
            });
        let output =
            self.poll_transmit_inner(now, &mut out[..capacity], budget, true, Some(selected), gso);
        self.reservations[index].payload = payload;
        let output = output?;
        if let Some(packet) = output.packet {
            attempt.connection = packet.connection;
            self.reservations[index].capture(packet, out, attempt);
            if let Some(id) = packet.connection {
                let departure = self.retained_slot(id)?.connection.last_departure;
                let r = self.reservations[index].current.as_mut().unwrap();
                r.departure = departure;
                if let Some(s) = departure.and_then(|d| d.segmentation) {
                    // Use the same exact-prefix acceptance path as MTU repair.
                    // GSO has no selected PMTU packet or timestamp observation
                    // to cancel on rejection; physical evidence commits at accept.
                    r.repaired = true;
                    r.finished = false;
                    r.emitted_bytes = s.segment_payload_len;
                }
                self.refresh(id.slot);
            }
            Ok((output, Some(attempt)))
        } else {
            Ok((output, None))
        }
    }

    pub fn accept_transmit(
        &mut self,
        now: Instant,
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
        if r.attempt != Some(attempt) || r.group.is_some() {
            return Ok(false);
        }
        let connection = r.packet.connection;
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
        if let Some(id) = connection {
            let owner = &self.retained_slot(id)?.connection;
            owner.check_time(now)?;
            if let Some(d) = &departure {
                owner.validate_reserved_output(now, d, offset, count)?;
            }
        }
        self.clock(now)?;
        if let Some(id) = connection
            && let Some(d) = &mut departure
        {
            self.retained_slot_mut(id)?
                .connection
                .accept_reserved_output(now, d, offset, count, finished)?;
        }
        self.complete_reserved_accept(index, departure, finished);
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
            self.reservations[index].current = None;
        } else {
            r.departure = departure;
            r.offset += r.emitted_bytes;
            r.sacks += r.emitted_sacks;
            r.attempt = None;
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
        if r.attempt != Some(attempt) || r.group.is_some() {
            return Ok(false);
        }
        let Some(connection) = r.packet.connection else {
            self.reservations[index].current = None;
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
        let r = self.reservations[index].current.as_mut().unwrap();
        r.attempt = None;
        r.repaired = true;
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
        if r.attempt != Some(attempt) || r.group.is_some() || r.offset != 0 {
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
        self.reservations[index].current = None;
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
        self.reservations[attempt.reservation].current = None;
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
            slot.reset_deadline = None;
            slot.closed_output_drained = true;
            self.reservations[index].current = None;
            self.refresh(id.slot);
            self.rearm_pending_accept(id);
        } else {
            self.reservations[index].current = None;
        }
        Ok(true)
    }

    pub fn poll_transmit(
        &mut self,
        now: Instant,
        out: &mut [u8],
        budget: usize,
    ) -> Result<PollTransmit, EndpointError> {
        self.poll_transmit_inner(now, out, budget, false, None, None)
    }

    fn poll_transmit_inner(
        &mut self,
        now: Instant,
        out: &mut [u8],
        budget: usize,
        reserve: bool,
        selected: Option<Option<ConnectionId>>,
        mut gso: Option<crate::output_reservation::GsoBuffer<'_>>,
    ) -> Result<PollTransmit, EndpointError> {
        self.clock(now)?;
        for _ in 0..budget {
            if !self.cleanup.is_empty() {
                self.cleanup_one();
            }
            let stateless_held = self.reservations.iter().any(|slot| {
                slot.current
                    .as_ref()
                    .is_some_and(|r| r.packet.connection.is_none())
            });
            let next = self.output.iter().find(|&index| {
                let id = self.id(index);
                !self.is_output_reserved(id) && selected.is_none_or(|owner| owner == Some(id))
            });
            if !stateless_held
                && !self.control.is_empty()
                && selected.is_none_or(|owner| owner.is_none())
                && (self.control_turn || next.is_none() || selected == Some(None))
            {
                let (ip, header, ipv4_options, mut echo) = *self.control.front().unwrap();
                if let Some(policy) = self.config.connection.pmtud {
                    let ip_len = match (ip.source, ip.destination) {
                        (IpAddr::V4(source), IpAddr::V4(destination)) => {
                            20 + ipv4_options.encode(source, destination, 0, &mut [0; 40])?.1 as u32
                        }
                        _ => 40,
                    };
                    let budget = policy.first_hop_mtu.saturating_sub(ip_len);
                    if budget < 20 {
                        // Stateless replies cannot fragment or drop a required source route.
                        self.control.pop_front();
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
                let len = wire::encode(ip, header, options, &[], out).map_err(Error::Wire)?;
                self.control.pop_front();
                self.control_turn = false;
                return Ok(PollTransmit {
                    packet: Some(Transmit {
                        connection: None,
                        tx_timestamp: None,
                        ecn: 0,
                        ipv4_options,
                        ip,
                        len,
                        hop_limit: self.config.hop_limit,
                        dscp: self.config.dscp,
                    }),
                    more_work: self.has_pending_output(),
                });
            }
            let Some(index) = next else {
                continue;
            };
            self.output.remove(index);
            let connection = self.id(index);
            let slot = self.slots[index].as_mut().unwrap();
            let tuple = slot.connection.tuple();
            let terminal_reset = slot.connection.reset_pending();
            let output = if reserve {
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
                    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.5.2
                    //= reason=Terminal local reset reserves the tuple for 2MSL independently of immediate application CLOSED; only successful RST generation starts the timer.
                    //# The side of a connection issuing a reset should enter the TIME-WAIT state, as
                    //# this generally helps to reduce the load on busy servers for reasons described
                    //# in [70].
                    if terminal_reset
                        && out
                            .get(..len)
                            .and_then(|bytes| bytes.get(13))
                            .is_some_and(|flags| flags & RST != 0)
                    {
                        slot.reset_deadline = Some(
                            now.saturating_add(
                                self.config
                                    .connection
                                    .timebase
                                    .ticks_from_us(self.config.connection.time_wait_us),
                            ),
                        );
                    }
                    slot.closed_output_drained = slot.connection.state() == State::Closed;
                    let hop_limit = slot.hop_limit;
                    let dscp = slot.dscp;
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
                    return Ok(PollTransmit {
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
                        }),
                        more_work: self.has_pending_output(),
                    });
                }
                Ok(None) => {
                    self.deadlines.set(
                        index,
                        slot.reset_deadline.or(slot.connection.next_deadline()),
                    );
                    if slot.connection.state() == State::Closed {
                        slot.closed_output_drained = true;
                        if slot.released
                            && !slot.connection.reset_pending()
                            && slot.reset_deadline.is_none()
                        {
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
        Ok(PollTransmit {
            packet: None,
            more_work: self.has_pending_output(),
        })
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
                let first_isn = endpoint.isn(tuple);
                endpoint.clock(4000 * scale).unwrap();
                let next_isn = endpoint.isn(tuple);
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
                control.reset_for(ip, &incoming, None);
                assert_eq!(control.control_count, 1);
                packet(&mut control, 0);
                control.clock(1_000_000 * scale - 1).unwrap();
                control.reset_for(ip, &incoming, None);
                assert!(control.control.is_empty());
                control.clock(1_000_000 * scale).unwrap();
                control.reset_for(ip, &incoming, None);
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
                assert_eq!(
                    passive.slots[child.slot].as_ref().unwrap().reset_deadline,
                    Some(240_000_000 * scale)
                );
                assert_eq!(passive.next_deadline(), Some(240_000_000 * scale));
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
    fn buffer_resize_admission_accounts_for_staged_peak() {
        for (send, receive) in [(2048, 1), (1024, 2048), (2048, 2048)] {
            let config = EndpointConfig {
                preallocate_connections: 0,
                max_buffer_bytes: Connection::allocation_bytes(send, receive, 64).unwrap(),
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
            // The final replacement fits, but its staging alongside originals does not.
            assert_eq!(
                endpoint.set_buffer_capacities(id, send, receive),
                Err(EndpointError::LimitReached)
            );
            assert_eq!(endpoint.buffer_capacities(id).unwrap(), (1024, 1));
            assert_eq!(endpoint.buffer_bytes(), old);
            let peak = endpoint
                .slot(id)
                .unwrap()
                .connection
                .resize_peak_charge(send, receive)
                .unwrap();
            endpoint.config.max_buffer_bytes = peak;
            endpoint.set_buffer_capacities(id, send, receive).unwrap();
            assert_eq!(endpoint.buffer_capacities(id).unwrap(), (send, receive));
            assert_eq!(
                endpoint.buffer_bytes(),
                endpoint.slot(id).unwrap().connection.buffer_charge()
            );
            assert!(endpoint.buffer_bytes() < peak);
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
            let pool_capacity = endpoint.receive_pool.capacity();
            // A full bounded probe table can fail insertion after construction.
            let mut occupied = tuple;
            occupied.remote.set_port(occupied.remote.port() + 1);
            endpoint.tuples.entries.fill(Entry::Occupied(occupied, 0));
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
    fn reserved_tuple_insert_rejects_duplicates_and_invalid_fallback_owners() {
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
        for fallback in [
            None,
            Some(owner),
            Some(ConnectionId {
                generation: owner.generation + 1,
                ..owner
            }),
        ] {
            let connection = b.new_connection(tuple, 100, None).unwrap();
            assert_eq!(
                b.insert(connection, None, fallback),
                Err(EndpointError::AddressInUse)
            );
            assert_eq!(b.connection_id(tuple), Some(owner));
            assert_eq!(b.buffer_bytes(), charge);
        }
        let (tx, _) = packet(&mut b, 0);
        assert_eq!(tx.connection, Some(owner));
        assert_eq!(b.next_deadline(), Some(b.config.connection.time_wait_us));
        assert!(b.connection_exists(owner));
    }

    #[test]
    fn rack_deadline_budget_ready_queue_and_stable_owner() {
        {
            let algorithm = crate::PrrAlgorithm::Rfc9937;
            let config = EndpointConfig {
                max_connections: 4,
                max_listeners: 1,
                connection: ConnectionConfig {
                    mss: 1000,
                    sack: true,
                    rack: true,
                    prr: true,
                    prr_algorithm: algorithm,
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
            assert_eq!(a.connection_id(tuple), Some(client));
            assert!(a.connection_exists(client));
            let expiry = a.next_deadline().unwrap();
            a.on_timeout(expiry, 1).unwrap();
            assert_eq!(a.connection_id(tuple), None);
            assert!(!a.connection_exists(client));
            assert_eq!(a.transport_info(client), Err(EndpointError::InvalidHandle));
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.8
    //= type=test
    //= reason=TIME-WAIT expiry removes mapping and reclaims released storage; unreleased terminal handle intentionally survives for status.
    //# If the time-wait timeout expires on a connection, delete the TCB, enter the CLOSED
    //# state, and return.
    fn connection_existence_retains_released_timewait_and_rejects_reused_generation() {
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
        assert!(a.connection_exists(client));
        assert_eq!(a.state(client), Err(EndpointError::InvalidHandle));
        let expiry = a.next_deadline().unwrap();
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
            assert_eq!(a.setup_loss_cache[0], (local.ip(), remote.ip()));
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
            .resize_peak_charge(send * 2, receive)
            .unwrap();
        endpoint.config.max_buffer_bytes = peak - 1;
        assert_eq!(
            endpoint.set_buffer_capacities(id, send * 2, receive),
            Err(EndpointError::LimitReached)
        );
        endpoint.config.max_buffer_bytes = peak;
        endpoint
            .set_buffer_capacities(id, send * 2, receive)
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
            .resize_peak_charge(send, receive * 2)
            .unwrap();
        endpoint.config.max_buffer_bytes = peak - 1;
        assert_eq!(
            endpoint.set_buffer_capacities(id, send, receive * 2),
            Err(EndpointError::LimitReached)
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
        let base = Connection::allocation_bytes(17, 17, 8).unwrap();
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
                endpoint.set_listener_buffer_capacities(listener, 34, 17),
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
            endpoint.tuples.entries.fill(Entry::Occupied(occupied, 0));
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
        let allocated = b.buffer_bytes;
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
        let allocated_after_open = b.buffer_bytes;
        assert!(allocated_after_open >= allocated);
        crate::allocation_tests::fail_after(0, || {
            b.set_endpoint_first_hop_mtu(3, 9000).unwrap();
        });
        assert_eq!(b.buffer_bytes, allocated_after_open);
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
        ));
        e.set_endpoint_first_hop_mtu(1, 68).unwrap();
        assert!(
            e.poll_transmit(1, &mut [0; 256], 16)
                .unwrap()
                .packet
                .is_none()
        );
        assert!(e.control.is_empty());
    }
}

#[cfg(test)]
mod output_reservation_tests {
    include!("output_reservation_tests.rs");
}

#[cfg(test)]
mod reset_defense_tests {
    include!("endpoint_reset_defense_tests.rs");
}
