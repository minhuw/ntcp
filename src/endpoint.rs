extern crate alloc;

use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use core::net::{IpAddr, SocketAddr};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{
    Ipv4Options, Ipv4OptionsError, OutgoingIpv4Options, SourceRoute, TimestampRequest,
    connection::{Connection, ConnectionConfig, ConnectionEvents, Error, Instant, State, Tuple},
    schedule::{Deadlines, ReadyQueue},
    wire::{self, ACK, Header, IpMetadata, RST, SYN},
};

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
    pub ipv4_options_enabled: bool,
    pub error_reports: bool,
    pub reuse_time_wait: bool,
    pub max_listeners: usize,
    pub max_control_packets: usize,
    pub max_buffer_bytes: usize,
    pub hop_limit: u8,
    pub dscp: u8,
    pub connection: ConnectionConfig,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            ipv4_options_enabled: false,
            error_reports: true,
            reuse_time_wait: false,
            max_listeners: 64,
            max_control_packets: 64,
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

    fn remove(&mut self, hash: usize, tuple: Tuple) {
        for probe in 0..self.entries.len().min(64) {
            let position = hash.wrapping_add(probe) & (self.entries.len() - 1);
            match self.entries[position] {
                Entry::Occupied(key, _) if key == tuple => {
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
    released: bool,
    closed_output_drained: bool,
    mapped: bool,
    fallback: Option<ConnectionId>,
    hop_limit: u8,
    dscp: u8,
    received_dscp: Option<u8>,
    ipv4_options: OutgoingIpv4Options,
    explicit_route: bool,
    received_ipv4_options: Option<Ipv4Options>,
}
struct Listener {
    address: SocketAddr,
    backlog: usize,
    children: Vec<ConnectionId>,
    pending: VecDeque<ConnectionId>,
    closing: bool,
}

// An endpoint and its policy are bound to one ingress network context. Policies
// may select routes using the address pair and capture owned network state.
// Ambiguous overlapping ingress domains need separate endpoints, not implicit
// context guessing from addresses.
pub struct Endpoint {
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
        if config.max_connections == 0
            || config.connection.send_ip_payload_limit
                < if config.connection.timestamps { 40 } else { 28 }
            || config.max_listeners == 0
            || config.hop_limit == 0
            || config.dscp > 63
        {
            return Err(Error::InvalidArgument.into());
        }
        if config.ipv4_options_enabled {
            // ponytail: reserve all 40 IPv4 option bytes; per-packet budgeting can reclaim slack later.
            config.connection.send_ip_payload_limit = config
                .connection
                .send_ip_payload_limit
                .min(65515)
                .checked_sub(40)
                .filter(|&budget| budget >= if config.connection.timestamps { 40 } else { 28 })
                .ok_or(Error::InvalidArgument)?;
        }
        let count = config.max_connections;
        let listeners_count = config.max_listeners;
        let event_capacity = count
            .checked_add(listeners_count)
            .ok_or(EndpointError::LimitReached)?;
        let per_connection_bytes = config
            .connection
            .receive_capacity
            .checked_mul(3)
            .and_then(|n| {
                config
                    .connection
                    .send_capacity
                    .checked_mul(2)
                    .and_then(|send| n.checked_add(send))
            })
            .and_then(|n| n.checked_add(usize::from(config.connection.mss)))
            .ok_or(EndpointError::LimitReached)?;
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
            address_policy: Box::new(address_policy),
            passive_errors,
            tuples: TupleTable::new(count)?,
            output: ReadyQueue::new(count).map_err(|_| Error::NoMemory)?,
            advice: ReadyQueue::new(count).map_err(|_| Error::NoMemory)?,
            events: ReadyQueue::new(event_capacity).map_err(|_| Error::NoMemory)?,
            cleanup: ReadyQueue::new(listeners_count).map_err(|_| Error::NoMemory)?,
            deadlines: Deadlines::new(count).map_err(|_| Error::NoMemory)?,
            config,
            secret,
            now,
            isn_clock: (now / 4) as u32,
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
            buffer_bytes: 0,
            per_connection_bytes,
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

    fn clock(&mut self, now: Instant) -> Result<(), EndpointError> {
        if now < self.now {
            return Err(Error::TimeWentBackwards.into());
        }
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
        let ticks = (self.now / 4).saturating_sub(self.last_isn_time / 4).max(1);
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
    fn slot(&self, id: ConnectionId) -> Result<&Slot, EndpointError> {
        if self.generations.get(id.slot) != Some(&id.generation) {
            return Err(EndpointError::InvalidHandle);
        }
        self.slots[id.slot]
            .as_ref()
            .filter(|slot| !slot.released)
            .ok_or(EndpointError::InvalidHandle)
    }
    fn slot_mut(&mut self, id: ConnectionId) -> Result<&mut Slot, EndpointError> {
        self.slot(id)?;
        let slot = self.slots[id.slot].as_mut().unwrap();
        slot.connection.update_time(self.now)?;
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
        self.listener(id)?;
        self.listeners[id.slot].as_mut().unwrap().closing = true;
        self.events.remove(self.config.max_connections + id.slot);
        self.cleanup.push(id.slot);
        Ok(())
    }

    fn cleanup_one(&mut self) {
        let Some(index) = self.cleanup.pop() else {
            return;
        };
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
        self.resource_admission(tuple)
    }

    fn resource_admission(&self, tuple: Tuple) -> Result<(), EndpointError> {
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
        if !self.has_capacity() {
            return Err(EndpointError::LimitReached);
        }
        Ok(())
    }

    fn has_capacity(&self) -> bool {
        !self.free.is_empty()
            && self.per_connection_bytes
                <= self
                    .config
                    .max_buffer_bytes
                    .saturating_sub(self.buffer_bytes)
    }

    fn insert(
        &mut self,
        connection: Connection,
        listener: Option<ListenerId>,
        fallback: Option<ConnectionId>,
    ) -> Result<ConnectionId, EndpointError> {
        let tuple = connection.tuple();
        let index = *self.free.last().ok_or(EndpointError::LimitReached)?;
        if let Some(old) = fallback {
            if !self
                .tuples
                .replace(self.hash(tuple), tuple, old.slot, index)
            {
                return Err(EndpointError::AddressInUse);
            }
            self.slots[old.slot].as_mut().unwrap().mapped = false;
            self.output.remove(old.slot);
        } else {
            self.tuples.insert(self.hash(tuple), tuple, index)?;
        }
        self.free.pop();
        self.slots[index] = Some(Slot {
            connection,
            listener,
            accepted_ready: false,
            released: false,
            closed_output_drained: false,
            mapped: true,
            fallback,
            hop_limit: self.config.hop_limit,
            dscp: self.config.dscp,
            received_dscp: None,
            ipv4_options: OutgoingIpv4Options::default(),
            explicit_route: false,
            received_ipv4_options: None,
        });
        self.buffer_bytes += self.per_connection_bytes;
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

    pub fn connect(
        &mut self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<ConnectionId, EndpointError> {
        self.clock(now)?;
        let tuple = Tuple { local, remote };
        self.admission(tuple)?;
        let connection =
            Connection::active(tuple, self.config.connection.clone(), self.isn(tuple), now)?;
        self.insert(connection, None, None)
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
            self.tuples.remove(self.hash(tuple), tuple);
        }
        if let Some(parent) = slot.listener {
            self.unlink_child(parent, id);
        }
        self.output.remove(index);
        self.events.remove(index);
        self.advice.remove(index);
        self.deadlines.set(index, None);
        self.buffer_bytes -= self.per_connection_bytes;
        if let Some(generation) = self.generations[index].checked_add(1) {
            self.generations[index] = generation;
            self.free.push(index);
        }
    }

    fn refresh(&mut self, index: usize) {
        if let Some(slot) = self.slots[index].as_ref()
            && slot.connection.state() != State::SynReceived
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
            && !matches!(state, State::SynSent | State::SynReceived | State::Closed);
        let failed_half_open = parent.is_some() && !slot.accepted_ready && state == State::Closed;
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.5.3
        //# If the receiver was
        //# in SYN-RECEIVED state and had previously been in the LISTEN state,
        //# then the receiver returns to the LISTEN state; otherwise, the
        //# receiver aborts the connection and goes to the CLOSED state.

        // A Closed connection may still owe a reset. Only reclaim after a
        // successful output attempt (including one that finds no packet).
        if state == State::Closed
            && (failed_half_open || slot.released)
            && slot.closed_output_drained
        {
            self.reclaim(index);
            return;
        }
        if failed_half_open {
            self.slots[index].as_mut().unwrap().released = true;
        }
        if state == State::Closed && self.slots[index].as_ref().unwrap().mapped {
            let tuple = self.slots[index].as_ref().unwrap().connection.tuple();
            self.tuples.remove(self.hash(tuple), tuple);
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
        self.deadlines.set(index, slot.connection.next_deadline());
        if slot.listener.is_none() && !slot.released && slot.connection.events_pending() {
            self.events.push(index);
        }
        if slot.mapped || state == State::Closed {
            self.output.push(index);
        }
    }

    pub fn accept(&mut self, listener: ListenerId) -> Result<ConnectionId, EndpointError> {
        self.listener(listener)?;
        let id = self.listeners[listener.slot]
            .as_mut()
            .unwrap()
            .pending
            .pop_front()
            .ok_or(Error::WouldBlock)?;
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
        if self.now.saturating_sub(self.control_epoch) >= 1_000_000 {
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
            segment.options.timestamps.map(|ts| ts.0).filter(|_| {
                self.config.connection.timestamps
                    && self.config.connection.send_ip_payload_limit >= 32
            }),
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

    pub fn input_with_traffic_class(
        &mut self,
        now: Instant,
        ip: IpMetadata,
        traffic_class: u8,
        bytes: &[u8],
    ) -> Result<InputDisposition, EndpointError> {
        self.input_with_ipv4_options(now, ip, traffic_class, Ipv4Options::default(), bytes)
    }

    pub fn input_with_ipv4_options(
        &mut self,
        now: Instant,
        ip: IpMetadata,
        traffic_class: u8,
        options: Ipv4Options,
        bytes: &[u8],
    ) -> Result<InputDisposition, EndpointError> {
        self.clock(now)?;
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
        if let Some(index) = self.tuples.find(self.hash(tuple), tuple) {
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
                .input_with_traffic_class(now, traffic_class, &segment)?;
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
            if record.children.len() >= record.backlog || self.resource_admission(tuple).is_err() {
                return Ok(InputDisposition::Dropped);
            }
            let connection = match Connection::passive(
                tuple,
                self.config.connection.clone(),
                self.isn(tuple),
                now,
                &segment,
            ) {
                Ok(connection) => connection,
                Err(Error::NoMemory) => return Ok(InputDisposition::Dropped),
                Err(error) => return Err(error.into()),
            };
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
            || !self.has_capacity()
            || !self.slots[index].as_ref().unwrap().connection.reuse_syn(
                self.now,
                syn,
                self.config.connection.timestamps,
            )
        {
            return Ok(InputDisposition::Dropped);
        }
        let candidate = self.isn(tuple);
        let iss = self.slots[index]
            .as_ref()
            .unwrap()
            .connection
            .reuse_iss(candidate);
        // Allocate the entire bounded child before transferring tuple ownership.
        // The old timer/record survives independently until its original expiry.
        let connection =
            match Connection::passive(tuple, self.config.connection.clone(), iss, self.now, syn) {
                Ok(connection) => connection,
                Err(Error::NoMemory) => return Ok(InputDisposition::Dropped),
                Err(error) => return Err(error.into()),
            };
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
        let count = self.slot_mut(id)?.connection.write_with_push(bytes, push)?;
        self.refresh(id.slot);
        Ok(count)
    }
    pub fn flush(&mut self, id: ConnectionId) -> Result<usize, EndpointError> {
        let count = self.slot_mut(id)?.connection.flush()?;
        self.refresh(id.slot);
        Ok(count)
    }
    pub fn close(&mut self, id: ConnectionId) -> Result<(), EndpointError> {
        self.slot_mut(id)?.connection.close()?;
        self.refresh(id.slot);
        Ok(())
    }
    pub fn write_urgent(&mut self, id: ConnectionId, bytes: &[u8]) -> Result<usize, EndpointError> {
        let count = self.slot_mut(id)?.connection.write_urgent(bytes)?;
        self.refresh(id.slot);
        Ok(count)
    }
    pub fn read(&mut self, id: ConnectionId, out: &mut [u8]) -> Result<usize, EndpointError> {
        let count = self.slot_mut(id)?.connection.read(out)?;
        self.refresh(id.slot);
        Ok(count)
    }
    pub fn shutdown(&mut self, id: ConnectionId) -> Result<(), EndpointError> {
        self.slot_mut(id)?.connection.shutdown()?;
        self.refresh(id.slot);
        Ok(())
    }
    pub fn abort(&mut self, id: ConnectionId) -> Result<(), EndpointError> {
        self.slot_mut(id)?.connection.abort();
        self.refresh(id.slot);
        Ok(())
    }
    pub fn set_nagle(&mut self, id: ConnectionId, enabled: bool) -> Result<(), EndpointError> {
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
        self.clock(now)?;
        let Some(index) = self.tuples.find(self.hash(tuple), tuple) else {
            return Ok(false);
        };
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
    pub fn lower_mss(&mut self, id: ConnectionId, mss: u16) -> Result<(), EndpointError> {
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
        self.slot_mut(id)?.connection.set_user_timeout(timeout_us)?;
        self.refresh(id.slot);
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
    pub fn urgent_remaining(&self, id: ConnectionId) -> Result<u64, EndpointError> {
        Ok(self.slot(id)?.connection.urgent_remaining())
    }
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2
    //# Time to Live (TTL):  The TTL value used to send TCP segments MUST be
    //# configurable (MUST-49).
    pub fn set_hop_limit(&mut self, id: ConnectionId, hop_limit: u8) -> Result<(), EndpointError> {
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
    pub fn state(&self, id: ConnectionId) -> Result<State, EndpointError> {
        Ok(self.slot(id)?.connection.state())
    }
    pub fn acknowledged(&self, id: ConnectionId) -> Result<u64, EndpointError> {
        Ok(self.slot(id)?.connection.acknowledged())
    }
    pub fn release(&mut self, id: ConnectionId) -> Result<(), EndpointError> {
        let state = self.slot(id)?.connection.state();
        if !matches!(state, State::Closed | State::TimeWait) {
            return Err(Error::InvalidState.into());
        }
        self.slot_mut(id)?.released = true;
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
        while let Some(index) = self.events.pop() {
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
        self.deadlines.first().map(|(time, _)| time)
    }
    pub fn has_pending_output(&self) -> bool {
        !self.output.is_empty() || !self.control.is_empty() || !self.cleanup.is_empty()
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
            self.slots[index]
                .as_mut()
                .unwrap()
                .connection
                .timeout(now)?;
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

    pub fn poll_transmit(
        &mut self,
        now: Instant,
        out: &mut [u8],
        budget: usize,
    ) -> Result<PollTransmit, EndpointError> {
        self.clock(now)?;
        for _ in 0..budget {
            if !self.cleanup.is_empty() {
                self.cleanup_one();
            }
            if !self.control.is_empty() && (self.control_turn || self.output.is_empty()) {
                let (ip, header, ipv4_options, echo) = *self.control.front().unwrap();
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
            let Some(index) = self.output.pop() else {
                continue;
            };
            let slot = self.slots[index].as_mut().unwrap();
            let tuple = slot.connection.tuple();
            match slot.connection.transmit(now, out) {
                Ok(Some(len)) => {
                    slot.closed_output_drained = slot.connection.state() == State::Closed;
                    let hop_limit = slot.hop_limit;
                    let dscp = slot.dscp;
                    let ecn = slot.connection.last_output_ecn();
                    let ipv4_options = slot.ipv4_options;
                    self.control_turn = true;
                    self.refresh(index);
                    return Ok(PollTransmit {
                        packet: Some(Transmit {
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
                    self.deadlines.set(index, slot.connection.next_deadline());
                    if slot.connection.state() == State::Closed {
                        slot.closed_output_drained = true;
                        if slot.released {
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
