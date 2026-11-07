#![forbid(unsafe_code)]

mod config;
mod driver;
mod types;
pub use config::{Link, NetworkConfig};
pub use types::*;

use ntcp::{AddressValidation, Endpoint, EndpointError, Tuple};
use ntcp_host::{Host, IngressContext, path};
use ntcp_io::PacketIo;
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);

struct Connection {
    core: ntcp::ConnectionId,
    local: SocketAddr,
    peer: SocketAddr,
    state: State,
    reason: Option<CloseReason>,
    close_requested: bool,
    abort_requested: bool,
    released: bool,
    read_cursor: u64,
    trace_count: usize,
    connected_event: bool,
    closed_event: bool,
    readable_event: bool,
    read_waiting: bool,
    write_waiting: Option<TxTimestampRequest>,
}
struct Slot<T> {
    generation: u64,
    value: Option<T>,
}
struct Listener {
    core: ntcp::ListenerId,
    port: u16,
    closing: bool,
    acceptable: bool,
}

// All transport and backend access is confined to the constructing thread.
// Endpoint's local address-policy callback also makes this owner !Send/!Sync.
pub struct Network<P: PacketIo> {
    config: NetworkConfig,
    instance: u64,
    io: P,
    endpoint: Endpoint,
    host: Host,
    ingress: IngressContext,
    now: Instant,
    next_port: u16,
    connections: Vec<Slot<Connection>>,
    connection_map: HashMap<ntcp::ConnectionId, usize>,
    listeners: Vec<Slot<Listener>>,
    listener_map: HashMap<ntcp::ListenerId, usize>,
    events: VecDeque<Event>,
    event_capacity: usize,
    event_cursor: usize,
    timestamp_cursor: usize,
    staged_timestamp: Option<TimestampEvent>,
    backend_clocks: Vec<(u64, ntcp_io::ClockDescriptor)>,
    tx: Vec<driver::TxSlot>,
    // Slots in `tx` holding a pending frame.
    tx_pending: usize,
    tx_cursor: usize,
    rx: Vec<u8>,
    completed: Vec<u8>,
    retained: VecDeque<driver::RetainedInput>,
    receive_free: Vec<Vec<u8>>,
    counters: Counters,
    stopped: bool,
    stopped_event: bool,
    failure: Option<io::Error>,
}

fn table<T>(capacity: usize) -> Result<Vec<Slot<T>>> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(capacity)
        .map_err(|_| Error::Capacity)?;
    result.resize_with(capacity, || Slot {
        generation: 0,
        value: None,
    });
    Ok(result)
}
fn bytes(capacity: usize) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(capacity)
        .map_err(|_| Error::Capacity)?;
    result.resize(capacity, 0);
    Ok(result)
}

impl<P: PacketIo> Network<P> {
    // The embedding supplies a confidential CSPRNG-generated TCP secret and
    // monotonic caller ticks in config.tcp.connection.timebase. Device/queue
    // ownership and any borrowed EAL/pool lifetime remain backend contracts.
    pub fn new(config: NetworkConfig, io: P, secret: [u8; 32], now: Instant) -> Result<Self> {
        config.validate(&io)?;
        if config.tcp.ipv4_options_enabled {
            return Err(Error::Unsupported(
                "IPv4 option origination on native fixed-hop ports",
            ));
        }
        let instance = NEXT_INSTANCE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Error::Capacity)?;
        let local = config.local_address;
        let (path_limits, limits) = ntcp_host::managed_limits(&config.tcp, 1, 1, 1, 1, 0)?;
        let mut host = Host::new(
            path::ContextId::new(u128::from(instance)),
            path_limits,
            limits,
            config.tcp.connection.timebase,
        )?;
        let ingress = host.register_link(
            path::InterfaceKey(1),
            config.mtu,
            ntcp_host::ReceiveCapabilities {
                max_ip_packet: config.mtu as usize,
                ipv4: if local.is_ipv4() {
                    ntcp_host::Ipv4Receive::Enabled {
                        interpretation: false,
                        source_routes: false,
                    }
                } else {
                    ntcp_host::Ipv4Receive::Disabled
                },
                ipv6: if local.is_ipv6() {
                    ntcp_host::Ipv6Receive::Extensions
                } else {
                    ntcp_host::Ipv6Receive::Disabled
                },
                gro: false,
            },
            ntcp_host::Forwarding::Forwarder(path::ForwarderId(1)),
        )?;
        let zone = local.is_ipv6()
            && match local {
                std::net::IpAddr::V6(a) => a.is_unicast_link_local(),
                _ => false,
            };
        host.register_source(
            path::ScopedAddress::new(local, zone.then_some(ingress.link()))
                .map_err(|e| Error::Host(e.into()))?,
            ingress.link(),
        )?;
        host.add_route(path::Route {
            destination: path::IpPrefix::new(
                if local.is_ipv4() {
                    "0.0.0.0".parse().unwrap()
                } else {
                    "::".parse().unwrap()
                },
                0,
            )
            .map_err(|e| Error::Host(e.into()))?,
            source: None,
            dscp: None,
            link: ingress.link(),
            next_hop: path::NextHop::Forwarder(path::ForwarderId(1)),
            metric: 0,
        })?;
        let mut endpoint =
            Endpoint::new(
                config.tcp.clone(),
                secret,
                now,
                move |request| match request {
                    AddressValidation::Bind { local: address }
                    | AddressValidation::Open { local: address, .. } => address == local,
                    AddressValidation::Incoming { destination, .. } => destination == local,
                    AddressValidation::Route { source, .. } => source == local,
                },
            )?;
        host.attach(&mut endpoint)?;
        let owners = config
            .tcp
            .max_connections
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        endpoint.enable_output_reservations_with_capacity(owners)?;
        let retained = config.retained_receive_packets.unwrap_or(owners);
        let ip_capacity = config.mtu as usize;
        let mut tx = Vec::new();
        tx.try_reserve_exact(owners).map_err(|_| Error::Capacity)?;
        for _ in 0..owners {
            tx.push(driver::TxSlot {
                bytes: bytes((ip_capacity + config.link.offset()).max(60))?,
                pending: None,
            });
        }
        let mut receive_free = Vec::new();
        receive_free
            .try_reserve_exact(retained)
            .map_err(|_| Error::Capacity)?;
        for _ in 0..retained {
            receive_free.push(bytes(ip_capacity)?);
        }
        let mut retained_input = VecDeque::new();
        retained_input
            .try_reserve_exact(retained)
            .map_err(|_| Error::Capacity)?;
        let event_capacity = config
            .tcp
            .max_connections
            .checked_add(config.tcp.max_control_packets)
            .and_then(|n| n.checked_add(config.tcp.max_listeners))
            .ok_or(Error::Capacity)?;
        let mut events = VecDeque::new();
        events
            .try_reserve_exact(event_capacity)
            .map_err(|_| Error::Capacity)?;
        let mut connection_map = HashMap::new();
        connection_map
            .try_reserve(config.tcp.max_connections)
            .map_err(|_| Error::Capacity)?;
        let mut listener_map = HashMap::new();
        listener_map
            .try_reserve(config.tcp.max_listeners)
            .map_err(|_| Error::Capacity)?;
        let mut backend_clocks = Vec::new();
        backend_clocks
            .try_reserve_exact(config.timestamp_clock_capacity)
            .map_err(|_| Error::Capacity)?;
        let connections = table(config.tcp.max_connections)?;
        let listeners = table(config.tcp.max_listeners)?;
        let next_port = *config.ephemeral_ports.start();
        Ok(Self {
            config,
            instance,
            io,
            endpoint,
            host,
            ingress,
            now,
            next_port,
            connections,
            connection_map,
            listeners,
            listener_map,
            events,
            event_capacity,
            event_cursor: 0,
            timestamp_cursor: 0,
            staged_timestamp: None,
            backend_clocks,
            tx,
            tx_pending: 0,
            tx_cursor: 0,
            // Capture an oversized physical frame safely before the Host rejects it.
            rx: bytes(65575 + 14)?,
            completed: bytes(ip_capacity)?,
            retained: retained_input,
            receive_free,
            counters: Counters::default(),
            stopped: false,
            stopped_event: false,
            failure: None,
        })
    }
    pub fn config(&self) -> &NetworkConfig {
        &self.config
    }
    pub fn now(&self) -> Instant {
        self.now
    }
    pub fn counters(&self) -> Counters {
        Counters {
            retained_input: self.retained.len(),
            ..self.counters
        }
    }
    pub fn failure(&self) -> Option<&io::Error> {
        self.failure.as_ref()
    }
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }
    pub fn backend(&self) -> &P {
        &self.io
    }
    pub fn timestamp_capabilities(&self) -> TimestampSupport {
        let rx = self.io.timestamp_capabilities();
        TimestampSupport {
            scheduled: self.config.tx_timestamp_phases != 0,
            acknowledged: self.config.tx_timestamp_phases != 0,
            software_transmit: false,
            hardware_transmit: false,
            software_receive: self.config.rx_timestamp_ranges != 0 && rx.rx_software,
            hardware_receive: self.config.rx_timestamp_ranges != 0 && rx.rx_hardware,
        }
    }
    // Device clock IDs in read metadata name the full original descriptor,
    // including its raw-unit calibration identity. They are not Unix time.
    pub fn backend_clock(&self, clock: TimestampClock) -> Option<ntcp_io::ClockDescriptor> {
        match clock {
            TimestampClock::DeviceTicks { identity, .. } => self
                .backend_clocks
                .iter()
                .find(|(id, _)| *id == identity)
                .map(|(_, c)| *c),
            TimestampClock::RealtimeNanoseconds => Some(ntcp_io::ClockDescriptor {
                domain: ntcp_io::ClockDomain::Realtime,
                unit: ntcp_io::TimestampUnit::Nanoseconds,
            }),
            _ => None,
        }
    }

    // Advances logical time without servicing timers or touching packet I/O.
    pub fn advance_time(&mut self, now: Instant) -> Result<()> {
        self.running()?;
        self.endpoint.on_timeout(now, 0)?;
        self.now = now;
        Ok(())
    }
    fn running(&self) -> Result<()> {
        if self.stopped {
            Err(Error::Stopped)
        } else {
            Ok(())
        }
    }
    fn conn(&self, id: ConnId) -> Result<&Connection> {
        if id.instance != self.instance {
            return Err(Error::InvalidHandle);
        }
        self.connections
            .get(id.slot)
            .filter(|s| s.generation == id.generation)
            .and_then(|s| s.value.as_ref())
            .ok_or(Error::InvalidHandle)
    }
    fn conn_mut(&mut self, id: ConnId) -> Result<&mut Connection> {
        if id.instance != self.instance {
            return Err(Error::InvalidHandle);
        }
        self.connections
            .get_mut(id.slot)
            .filter(|s| s.generation == id.generation)
            .and_then(|s| s.value.as_mut())
            .ok_or(Error::InvalidHandle)
    }
    fn conn_id(&self, slot: usize) -> ConnId {
        ConnId {
            instance: self.instance,
            slot,
            generation: self.connections[slot].generation,
        }
    }
    fn listener(&self, id: ListenerId) -> Result<&Listener> {
        if id.instance != self.instance {
            return Err(Error::InvalidHandle);
        }
        self.listeners
            .get(id.slot)
            .filter(|s| s.generation == id.generation)
            .and_then(|s| s.value.as_ref())
            .ok_or(Error::InvalidHandle)
    }
    fn free_connection_slot(&self) -> Result<usize> {
        self.connections
            .iter()
            .position(|s| s.value.is_none() && s.generation < u64::MAX)
            .ok_or(Error::Capacity)
    }
    fn install(&mut self, slot: usize, core: ntcp::ConnectionId) -> Result<ConnId> {
        let tuple = self.endpoint.tuple(core)?;
        let state = self.endpoint.state(core)?;
        self.connections[slot].generation += 1;
        self.connections[slot].value = Some(Connection {
            core,
            local: tuple.local,
            peer: tuple.remote,
            state,
            reason: None,
            close_requested: false,
            abort_requested: false,
            released: false,
            read_cursor: 0,
            trace_count: 0,
            connected_event: state == State::Established,
            closed_event: false,
            readable_event: false,
            read_waiting: true,
            write_waiting: None,
        });
        self.connection_map.insert(core, slot);
        Ok(self.conn_id(slot))
    }
    fn port_in_use(&self, port: u16) -> bool {
        self.connections
            .iter()
            .filter_map(|s| s.value.as_ref())
            .any(|c| c.local.port() == port)
            || self
                .listeners
                .iter()
                .filter_map(|s| s.value.as_ref())
                .any(|l| l.port == port)
    }
    fn scoped(&self, tuple: Tuple) -> ntcp::ScopedTuple {
        let link_local = [tuple.local.ip(), tuple.remote.ip()]
            .into_iter()
            .any(|ip| matches!(ip, std::net::IpAddr::V6(a) if a.is_unicast_link_local()));
        ntcp::ScopedTuple::new(tuple, link_local.then_some(self.ingress.link()))
            .expect("single-port tuple scope")
    }
    fn allocate_port(&mut self) -> Result<u16> {
        let start = self.next_port;
        loop {
            let candidate = self.next_port;
            self.next_port = if candidate == *self.config.ephemeral_ports.end() {
                *self.config.ephemeral_ports.start()
            } else {
                candidate + 1
            };
            if !self.port_in_use(candidate) {
                return Ok(candidate);
            }
            if self.next_port == start {
                return Err(Error::Capacity);
            }
        }
    }
    pub fn connect(&mut self, peer: SocketAddr) -> Result<ConnId> {
        self.connect_from(peer, None)
    }
    pub fn connect_from(&mut self, peer: SocketAddr, local_port: Option<u16>) -> Result<ConnId> {
        self.running()?;
        if matches!(peer, SocketAddr::V6(a) if a.scope_id() != 0 || a.flowinfo() != 0) {
            return Err(Error::Unsupported(
                "OS socket scope IDs and flow labels; native groups select their own link",
            ));
        }
        let slot = self.free_connection_slot()?;
        let port = match local_port {
            Some(0) => return Err(Error::InvalidConfig("zero local port")),
            Some(p) if self.port_in_use(p) => return Err(Error::Tcp(EndpointError::AddressInUse)),
            Some(p) => p,
            None => self.allocate_port()?,
        };
        let local = SocketAddr::new(self.config.local_address, port);
        let options = ntcp::ManagedOpenOptions {
            transport: ntcp::ActiveOpenOptions::from(&self.config.tcp.connection),
            dscp: self.config.tcp.dscp,
            ipv4_options: Default::default(),
            registration: None,
            receive_authority: None,
        };
        let scoped = self.scoped(Tuple {
            local,
            remote: peer,
        });
        let core = self.endpoint.connect_scoped_with_path_provider(
            self.now,
            scoped,
            options,
            &mut self.host,
        )?;
        if let Err(e) = self
            .endpoint
            .set_tx_timestamp_capacity(core, self.config.tx_timestamp_phases)
            .and_then(|_| {
                self.endpoint
                    .set_rx_timestamp_capacity(core, self.config.rx_timestamp_ranges)
            })
        {
            let _ = self.endpoint.abort(core);
            let _ = self.endpoint.release(core);
            self.host.collect(&self.endpoint)?;
            return Err(e.into());
        }
        self.install(slot, core)
    }
    pub fn listen(&mut self, port: u16, backlog: usize) -> Result<ListenerId> {
        self.running()?;
        let slot = self
            .listeners
            .iter()
            .position(|s| s.value.is_none() && s.generation < u64::MAX)
            .ok_or(Error::Capacity)?;
        let address = SocketAddr::new(self.config.local_address, port);
        let zone = match address.ip() {
            std::net::IpAddr::V6(a) if a.is_unicast_link_local() => Some(self.ingress.link()),
            _ => None,
        };
        let core = self.endpoint.listen_scoped(address, zone, backlog)?;
        if let Err(e) = self
            .endpoint
            .set_listener_rx_timestamp_capacity(core, self.config.rx_timestamp_ranges)
        {
            let _ = self.endpoint.close_listener(core);
            return Err(e.into());
        }
        self.listeners[slot].generation += 1;
        self.listeners[slot].value = Some(Listener {
            core,
            port,
            closing: false,
            acceptable: false,
        });
        self.listener_map.insert(core, slot);
        Ok(ListenerId {
            instance: self.instance,
            slot,
            generation: self.listeners[slot].generation,
        })
    }
    pub fn accept(&mut self, listener: ListenerId) -> Result<ConnId> {
        self.running()?;
        let slot = self.free_connection_slot()?;
        let listener_state = self.listener(listener)?;
        if listener_state.closing {
            return Err(Error::InvalidHandle);
        }
        let core_listener = listener_state.core;
        let core = match self.endpoint.accept(core_listener) {
            Ok(core) => core,
            Err(EndpointError::Connection(ntcp::Error::WouldBlock)) => {
                return Err(Error::WouldBlock(BlockReason::Accept));
            }
            Err(e) => return Err(e.into()),
        };
        if let Err(e) = self
            .endpoint
            .set_tx_timestamp_capacity(core, self.config.tx_timestamp_phases)
        {
            let _ = self.endpoint.abort(core);
            let _ = self.endpoint.release(core);
            return Err(e.into());
        }
        self.listeners[listener.slot]
            .value
            .as_mut()
            .unwrap()
            .acceptable = self.endpoint.listener_queue_info(core_listener)?.0 != 0;
        let id = self.install(slot, core)?;
        self.refresh_connection(slot);
        Ok(id)
    }
    pub fn close_listener(&mut self, listener: ListenerId) -> Result<()> {
        self.running()?;
        self.listener(listener)?;
        self.listeners[listener.slot]
            .value
            .as_mut()
            .unwrap()
            .closing = true;
        Ok(())
    }
    pub fn connection_info(&self, id: ConnId) -> Result<ConnectionInfo> {
        let c = self.conn(id)?;
        Ok(ConnectionInfo {
            local: c.local,
            peer: c.peer,
            state: c.state,
            reason: c.reason,
            application_closed: c.close_requested || c.abort_requested,
            network_stopped: self.stopped,
        })
    }
    pub fn send_progress(&self, id: ConnId) -> Result<SendProgress> {
        Ok(self.endpoint.send_progress(self.conn(id)?.core)?)
    }
    pub fn rx_timestamp_status(&self, id: ConnId) -> Result<RxTimestampStatus> {
        Ok(self.endpoint.rx_timestamp_status(self.conn(id)?.core)?)
    }
    fn writable_core(&self, id: ConnId) -> Result<ntcp::ConnectionId> {
        self.running()?;
        let c = self.conn(id)?;
        if c.close_requested || c.abort_requested || c.released {
            return Err(Error::Tcp(EndpointError::Connection(
                ntcp::Error::InvalidState,
            )));
        }
        match self.endpoint.state(c.core)? {
            State::SynSent | State::SynReceived => Err(Error::WouldBlock(BlockReason::Connecting)),
            State::Established | State::CloseWait => Ok(c.core),
            _ => Err(Error::ConnectionClosed(self.endpoint.close_reason(c.core)?)),
        }
    }
    pub fn try_write(
        &mut self,
        id: ConnId,
        data: &[u8],
        options: WriteOptions,
    ) -> Result<WriteReceipt> {
        // This first native service supports core Scheduled/ACK observations.
        // No backend timestamp source is advertised without its completion plumbing.
        if options.timestamps.software_transmit || options.timestamps.hardware_transmit {
            return Err(Error::Unsupported("native backend transmit timestamps"));
        }
        let core = self.writable_core(id)?;
        let before = self.endpoint.send_progress(core)?.queued_end;
        if data.is_empty() {
            return Ok(WriteReceipt {
                accepted: 0,
                range: TxStreamRange {
                    start: before,
                    end: before,
                },
            });
        }
        let phases = usize::from(options.timestamps.scheduled)
            + usize::from(options.timestamps.acknowledged);
        if phases > self.config.tx_timestamp_phases {
            return Err(Error::Unsupported(
                "requested timestamp phases exceed the configured capacity",
            ));
        }
        if phases
            > self
                .config
                .tx_timestamp_phases
                .saturating_sub(self.conn(id)?.trace_count)
        {
            self.conn_mut(id)?.write_waiting = Some(options.timestamps);
            return Err(Error::WouldBlock(BlockReason::TimestampCapacity));
        }
        let result =
            self.endpoint
                .write_with_timestamp(core, data, false, false, None, options.timestamps);
        let accepted = match result {
            Ok(n) => n,
            Err(EndpointError::Connection(ntcp::Error::WouldBlock)) => {
                self.conn_mut(id)?.write_waiting = Some(options.timestamps);
                return Err(Error::WouldBlock(BlockReason::SendBuffer));
            }
            Err(EndpointError::OutputReserved) => {
                self.conn_mut(id)?.write_waiting = Some(options.timestamps);
                return Err(Error::WouldBlock(BlockReason::OutputReserved));
            }
            Err(e) => return Err(e.into()),
        };
        self.conn_mut(id)?.trace_count += phases;
        Ok(WriteReceipt {
            accepted,
            range: TxStreamRange {
                start: before,
                end: before + accepted as u64,
            },
        })
    }
    pub fn try_read(&mut self, id: ConnId, out: &mut [u8]) -> Result<ReadOutcome> {
        self.running()?;
        let c = self.conn(id)?;
        if c.close_requested || c.abort_requested || c.released {
            return Err(Error::InvalidHandle);
        }
        if out.is_empty() {
            return Ok(ReadOutcome::EmptyBuffer);
        }
        let core = c.core;
        let state = self.endpoint.state(core)?;
        if matches!(state, State::SynSent | State::SynReceived) {
            return Err(Error::WouldBlock(BlockReason::Connecting));
        }
        let start = c.read_cursor;
        self.conn_mut(id)?.readable_event = false;
        self.conn_mut(id)?.read_waiting = true;
        let terminal = state == State::Closed;
        let available = if terminal {
            self.endpoint.terminal_readable_bytes(core)?
        } else {
            self.endpoint.readable_bytes(core)?
        };
        let count = out.len().min(available);
        let metadata = if count != 0 {
            self.endpoint.peek_rx_timestamps(core, count)?
        } else {
            None
        };
        let result = if terminal {
            self.endpoint.read_terminal(core, out)
        } else {
            self.endpoint.read(core, out)
        };
        let len = match result {
            Ok(n) => n,
            Err(EndpointError::Connection(ntcp::Error::WouldBlock)) => {
                return Err(Error::WouldBlock(BlockReason::Receive));
            }
            Err(EndpointError::Connection(ntcp::Error::InvalidState))
                if terminal
                    && count == 0
                    && self.endpoint.close_reason(core)? == Some(CloseReason::Normal) =>
            {
                0
            }
            Err(e) => return Err(e.into()),
        };
        if len == 0 {
            if terminal && self.endpoint.close_reason(core)? != Some(CloseReason::Normal) {
                return Err(Error::ConnectionClosed(self.endpoint.close_reason(core)?));
            }
            return Ok(ReadOutcome::Eof);
        }
        self.conn_mut(id)?.read_cursor += len as u64;
        self.refresh_connection(id.slot);
        Ok(ReadOutcome::Data {
            len,
            range: TxStreamRange {
                start,
                end: start + len as u64,
            },
            last_byte_timestamps: metadata,
        })
    }
    // Shared admission retains immutable storage in TCP. The packet backend
    // may still copy it; the remaining suffix stays in the caller's Payload.
    pub fn try_write_shared(&mut self, id: ConnId, payload: &mut Payload) -> Result<WriteReceipt> {
        let core = self.writable_core(id)?;
        let start = self.endpoint.send_progress(core)?.queued_end;
        if payload.is_empty() {
            return Ok(WriteReceipt {
                accepted: 0,
                range: TxStreamRange { start, end: start },
            });
        }
        let accepted = match self
            .endpoint
            .write_shared(core, payload.clone(), false, false, None)
        {
            Ok(n) => n,
            Err(EndpointError::Connection(ntcp::Error::WouldBlock)) => {
                self.conn_mut(id)?.write_waiting = Some(TxTimestampRequest::default());
                return Err(Error::WouldBlock(BlockReason::SendBuffer));
            }
            Err(EndpointError::OutputReserved) => {
                self.conn_mut(id)?.write_waiting = Some(TxTimestampRequest::default());
                return Err(Error::WouldBlock(BlockReason::OutputReserved));
            }
            Err(e) => return Err(e.into()),
        };
        *payload = payload
            .slice(accepted..payload.len())
            .expect("accepted payload prefix");
        Ok(WriteReceipt {
            accepted,
            range: TxStreamRange {
                start,
                end: start + accepted as u64,
            },
        })
    }
    pub fn set_nodelay(&mut self, id: ConnId, enabled: bool) -> Result<()> {
        self.running()?;
        self.endpoint.set_nagle(self.conn(id)?.core, !enabled)?;
        Ok(())
    }
    pub fn shutdown_write(&mut self, id: ConnId) -> Result<()> {
        self.running()?;
        let c = self.conn(id)?;
        if c.close_requested || c.abort_requested || c.released {
            return Err(Error::InvalidHandle);
        }
        self.endpoint.shutdown(c.core)?;
        Ok(())
    }
    pub fn close(&mut self, id: ConnId) -> Result<()> {
        self.running()?;
        let c = self.conn_mut(id)?;
        c.close_requested = true;
        c.readable_event = false;
        c.read_waiting = false;
        c.write_waiting = None;
        Ok(())
    }
    pub fn abort(&mut self, id: ConnId) -> Result<()> {
        self.running()?;
        let c = self.conn_mut(id)?;
        c.abort_requested = true;
        c.readable_event = false;
        c.read_waiting = false;
        c.write_waiting = None;
        Ok(())
    }

    fn refresh_connection(&mut self, slot: usize) {
        if self.stopped {
            return;
        }
        let Some(c) = self.connections[slot].value.as_mut() else {
            return;
        };
        if c.released {
            return;
        }
        if let Ok(state) = self.endpoint.state(c.core) {
            if matches!(state, State::Established | State::CloseWait)
                && matches!(c.state, State::SynSent | State::SynReceived)
            {
                c.connected_event = true;
            }
            if matches!(state, State::Closed | State::TimeWait)
                && !matches!(c.state, State::Closed | State::TimeWait)
            {
                c.closed_event = true;
            }
            c.state = state;
            c.reason = self.endpoint.close_reason(c.core).ok().flatten();
            if c.read_waiting && !self.endpoint.is_output_reserved(c.core) {
                c.readable_event = self.endpoint.readable_bytes(c.core).unwrap_or(0) != 0
                    || self.endpoint.terminal_readable_bytes(c.core).unwrap_or(0) != 0
                    || matches!(
                        state,
                        State::CloseWait
                            | State::Closing
                            | State::LastAck
                            | State::TimeWait
                            | State::Closed
                    );
            }
        }
    }
    fn collect_core_events(&mut self) {
        while self.events.len() < self.event_capacity {
            match self.endpoint.next_event() {
                Some(ntcp::Event::Connection(core, _)) => {
                    if let Some(&slot) = self.connection_map.get(&core) {
                        self.refresh_connection(slot);
                    }
                }
                Some(ntcp::Event::Acceptable(core)) => {
                    if let Some(&slot) = self.listener_map.get(&core)
                        && let Some(l) = &mut self.listeners[slot].value
                    {
                        l.acceptable = true;
                    }
                }
                Some(ntcp::Event::PassiveError {
                    listener,
                    tuple,
                    error,
                }) => {
                    if let Some(&slot) = self.listener_map.get(&listener) {
                        self.events.push_back(Event::PassiveError {
                            listener: ListenerId {
                                instance: self.instance,
                                slot,
                                generation: self.listeners[slot].generation,
                            },
                            peer: tuple.remote,
                            error,
                        });
                    }
                }
                Some(ntcp::Event::RouteAdvice(tuple)) => {
                    self.events.push_back(Event::RouteAdvice {
                        local: tuple.local,
                        peer: tuple.remote,
                    })
                }
                None => break,
            }
        }
    }
    fn next_connection_event(&mut self, slot: usize) -> Option<Event> {
        self.refresh_connection(slot);
        let id = self.conn_id(slot);
        let c = self.connections[slot].value.as_mut()?;
        if c.connected_event {
            c.connected_event = false;
            return Some(Event::Connected(id));
        }
        if c.closed_event {
            c.closed_event = false;
            return Some(Event::Closed {
                connection: id,
                reason: c.reason,
            });
        }
        if c.readable_event {
            c.readable_event = false;
            c.read_waiting = false;
            return Some(Event::Readable(id));
        }
        if let Some(request) = c.write_waiting {
            let phases = usize::from(request.scheduled) + usize::from(request.acknowledged);
            if !self.stopped
                && phases
                    <= self
                        .config
                        .tx_timestamp_phases
                        .saturating_sub(c.trace_count)
                && self
                    .endpoint
                    .check_write_admission(c.core, None, request)
                    .is_ok_and(|n| n != 0)
            {
                c.write_waiting = None;
                return Some(Event::Writable(id));
            }
        }
        None
    }
    pub fn drain_events(&mut self, out: &mut [Event]) -> DrainReport {
        self.collect_core_events();
        let mut written = 0;
        while written < out.len() {
            let Some(event) = self.events.pop_front() else {
                break;
            };
            out[written] = event;
            written += 1;
        }
        if written < out.len() && self.stopped_event {
            out[written] = Event::NetworkStopped;
            written += 1;
            self.stopped_event = false;
        }
        let total = self.connections.len() + self.listeners.len();
        let mut scanned = 0;
        while written < out.len() && scanned < total {
            let slot = self.event_cursor;
            self.event_cursor = (slot + 1) % total;
            scanned += 1;
            let event = if slot < self.connections.len() {
                self.next_connection_event(slot)
            } else {
                let index = slot - self.connections.len();
                let generation = self.listeners[index].generation;
                self.listeners[index]
                    .value
                    .as_mut()
                    .filter(|l| l.acceptable && !l.closing)
                    .map(|l| {
                        l.acceptable = false;
                        Event::Acceptable(ListenerId {
                            instance: self.instance,
                            slot: index,
                            generation,
                        })
                    })
            };
            if let Some(event) = event {
                out[written] = event;
                written += 1;
            }
        }
        let more = !self.events.is_empty()
            || self.stopped_event
            || self.connections.iter().any(|s| {
                s.value.as_ref().is_some_and(|c| {
                    c.connected_event
                        || c.closed_event
                        || c.readable_event
                        || c.write_waiting.is_some_and(|request| {
                            !self.stopped
                                && usize::from(request.scheduled)
                                    + usize::from(request.acknowledged)
                                    <= self
                                        .config
                                        .tx_timestamp_phases
                                        .saturating_sub(c.trace_count)
                                && self
                                    .endpoint
                                    .check_write_admission(c.core, None, request)
                                    .is_ok_and(|n| n != 0)
                        })
                })
            })
            || self
                .listeners
                .iter()
                .any(|s| s.value.as_ref().is_some_and(|l| l.acceptable && !l.closing));
        DrainReport { written, more }
    }
    fn stage_timestamp(&mut self) -> bool {
        if self.staged_timestamp.is_some() {
            return true;
        }
        for _ in 0..self.connections.len() {
            let slot = self.timestamp_cursor;
            self.timestamp_cursor = (slot + 1) % self.connections.len();
            if let Some(c) = &self.connections[slot].value
                && !c.released
                && let Ok(Some(observation)) = self.endpoint.next_tx_timestamp(c.core)
            {
                self.staged_timestamp = Some(TimestampEvent {
                    connection: self.conn_id(slot),
                    observation,
                });
                return true;
            }
        }
        false
    }
    pub fn drain_timestamps(&mut self, out: &mut [TimestampEvent]) -> DrainReport {
        let mut written = 0;
        while written < out.len() && self.stage_timestamp() {
            let event = self.staged_timestamp.take().unwrap();
            if let Ok(c) = self.conn_mut(event.connection) {
                c.trace_count -= 1;
            }
            out[written] = event;
            written += 1;
        }
        DrainReport {
            written,
            more: self.stage_timestamp(),
        }
    }
    // A pending observation can be cancelled explicitly; its Cancelled outcome
    // remains charged and drainable, just like a successful observation.
    pub fn cancel_timestamps(&mut self, id: ConnId) -> Result<()> {
        self.endpoint.cancel_tx_timestamps(self.conn(id)?.core)?;
        Ok(())
    }
}
