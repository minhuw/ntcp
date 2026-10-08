use crate::*;
use ntcp::{
    AddressValidation, CloseReason, ConnectionId, Endpoint, EndpointConfig, EndpointError, Error,
    Event, ListenerId, State,
};
use ntcp_io::{PacketIo, TxOutcome};
use ntcp_io_tun::Tun;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::mpsc::{self, Receiver, SyncSender},
    time::Instant,
};

pub const LIMIT: usize = 512;
pub const BYTES: usize = 65536;
const BUDGET: usize = 32;
// Linux sock_setsockopt clamps the unsigned request before doubling. Fixed
// project cap, not host sysctls: RACK's per-byte ledger also consumes the budget.
const BUFFER_REQUEST_CAP: u32 = 1024 * 1024;
fn socket_buffer_value(name: i32, value: i32) -> usize {
    let minimum = if name == SO_SNDBUF { 4608 } else { 2304 };
    ((value as u32).min(BUFFER_REQUEST_CAP) as usize * 2).max(minimum)
}
#[derive(Clone)]
pub enum Op {
    New(i32),
    Bind(SocketAddr),
    Listen(i32),
    Accept(i32),
    Connect(SocketAddr),
    Read(usize),
    Peek(usize),
    SetTimeout(bool, u64),
    GetTimeout(bool),
    Write(Vec<u8>),
    Close,
    Shutdown(i32),
    Flags(i32, i32),
    Set(i32, i32, i32),
    Get(i32, i32),
    Name(bool),
    Ready,
    Available,
}
#[derive(Default, Debug)]
pub struct Reply {
    pub value: i32,
    pub timeout_us: u64,
    pub bytes: Vec<u8>,
    pub addr: Option<SocketAddr>,
}
struct Request {
    id: u64,
    op: Op,
    reply: SyncSender<Result<Reply>>,
}
pub struct Runtime {
    tx: SyncSender<Request>,
    pub wake: i32,
    pub family: i32,
}
impl Runtime {
    #[cfg(test)]
    pub(crate) fn in_memory_test() -> Self {
        let wake = unsafe { syscall(SYS_eventfd2, 0, EFD_NONBLOCK | EFD_CLOEXEC) as i32 };
        assert!(wake >= 0);
        let (tx, rx) = mpsc::sync_channel::<Request>(LIMIT);
        std::thread::spawn(move || {
            set_internal(true);
            let local = Ipv4Addr::new(10, 73, 0, 2);
            let mut owner =
                Owner::with_endpoint(local, (Ipv4Addr::new(10, 73, 0, 1), 24), [2; 32], None)
                    .unwrap();
            while let Ok(request) = rx.recv() {
                let result = owner.execute(request.id, request.op);
                let _ = request.reply.send(result);
            }
        });
        Self {
            tx,
            wake,
            family: AF_INET,
        }
    }

    pub fn start() -> Result<Self> {
        let name = env("NTCP_SOCKET_TUN").ok_or(EINVAL)?;
        let local: Ipv4Addr = env("NTCP_SOCKET_ADDR")
            .ok_or(EINVAL)?
            .parse()
            .map_err(|_| EAFNOSUPPORT)?;
        let wake = unsafe { syscall(SYS_eventfd2, 0, EFD_NONBLOCK | EFD_CLOEXEC) as i32 };
        if wake < 0 {
            return Err(errno());
        }
        let (tx, rx) = mpsc::sync_channel(LIMIT);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let spawned = std::thread::Builder::new()
            .name("ntcp-socket".into())
            .spawn(move || {
                set_internal(true);
                let result = std::panic::catch_unwind(|| match Owner::new(&name, local) {
                    Ok(mut owner) => {
                        let _ = ready_tx.send(Ok(()));
                        owner.run(rx, wake);
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                    }
                });
                // Dropping rx and all requests wakes callers on panic/failure.
                let _ = result;
                signal(wake);
            });
        let worker = match spawned {
            Ok(worker) => worker,
            Err(_) => {
                unsafe { syscall(SYS_close, wake) };
                return Err(EAGAIN);
            }
        };
        if let Err(e) = ready_rx.recv().unwrap_or(Err(EIO)) {
            close_failed_startup(worker, wake);
            return Err(e);
        }
        Ok(Self {
            tx,
            wake,
            family: AF_INET,
        })
    }
    pub fn call(&self, id: u64, op: Op) -> Result<Reply> {
        let (reply, rx) = mpsc::sync_channel(1);
        let closing = matches!(op, Op::Close);
        let request = Request { id, op, reply };
        if closing {
            // Descriptor teardown must not strand an Endpoint socket when the
            // bounded request channel is temporarily full. No registry lock is held.
            self.tx.send(request).map_err(|_| EIO)?;
        } else {
            self.tx.try_send(request).map_err(|e| match e {
                mpsc::TrySendError::Full(_) => EAGAIN,
                mpsc::TrySendError::Disconnected(_) => EIO,
            })?;
        }
        rx.recv().unwrap_or(Err(EIO))
    }
}
fn close_failed_startup(worker: std::thread::JoinHandle<()>, wake: i32) {
    // The worker may still signal wake after reporting failure.
    let _ = worker.join();
    unsafe { syscall(SYS_close, wake) };
}
pub fn signal(fd: i32) {
    let one = 1u64;
    unsafe {
        syscall(SYS_write, fd, &one, 8);
    }
}
fn engine(e: EndpointError) -> i32 {
    match e {
        EndpointError::AddressInUse => EADDRINUSE,
        EndpointError::LimitReached => ENOBUFS,
        EndpointError::InvalidHandle => EBADF,
        EndpointError::Connection(Error::WouldBlock) => EAGAIN,
        EndpointError::Connection(Error::NoMemory) => ENOMEM,
        EndpointError::Connection(Error::InvalidState) => ENOTCONN,
        _ => EINVAL,
    }
}
#[derive(Clone, Copy)]
enum Handle {
    Fresh,
    Listener(ListenerId),
    Connection(ConnectionId),
}
#[derive(Clone)]
struct Socket {
    send_capacity: usize,
    receive_capacity: usize,
    handle: Handle,
    local: Option<SocketAddr>,
    flags: i32,
    // Adapter bind policy: mutual REUSEADDR permits live connection-port reuse;
    // no kernel bind table or Linux TIME-WAIT option emulation.
    reuse: bool,
    nodelay: bool,
    keepalive: bool,
    idle: i32,
    interval: i32,
    probes: i32,
    error: i32,
    connected: bool,
    acceptable: bool,
    write_shutdown: bool,
    read_shutdown: bool,
    receive_timeout_us: u64,
    send_timeout_us: u64,
}
impl Socket {
    fn new(flags: i32) -> Self {
        Self {
            send_capacity: BYTES,
            receive_capacity: BYTES,
            handle: Handle::Fresh,
            local: None,
            flags,
            reuse: false,
            nodelay: false,
            keepalive: false,
            idle: 7200,
            interval: 75,
            probes: 9,
            error: 0,
            connected: false,
            acceptable: false,
            write_shutdown: false,
            read_shutdown: false,
            receive_timeout_us: 0,
            send_timeout_us: 0,
        }
    }
    fn keepalive_config(&self) -> Option<ntcp::KeepaliveConfig> {
        self.keepalive.then_some(ntcp::KeepaliveConfig {
            idle_us: self.idle as u64 * 1_000_000,
            interval_us: self.interval as u64 * 1_000_000,
            probes: self.probes as u32,
            send_garbage: false,
        })
    }
}
struct Owner {
    endpoint: Endpoint,
    tun: Option<Tun>,
    sockets: BTreeMap<u64, Socket>,
    local: Ipv4Addr,
    epoch: Instant,
    next_port: u16,
    next_id: u64,
    detached: Vec<ConnectionId>,
    pending_packet: Option<Vec<u8>>,
    child_timeouts: Vec<(ConnectionId, u64, u64, u64)>,
}
fn unicast(ip: Ipv4Addr) -> bool {
    ip.octets()[0] != 0 && ip.octets()[0] < 224 && !ip.is_loopback()
}
fn context(name: &str, local: Ipv4Addr) -> Result<(Ipv4Addr, u8)> {
    let requested = env("NTCP_SOCKET_PREFIX")
        .map(|p| p.parse::<u8>().map_err(|_| EINVAL))
        .transpose()?;
    let mut list = ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } < 0 {
        return Err(errno());
    }
    let mut cursor = list;
    let mut found = None;
    let mut duplicate = false;
    unsafe {
        while let Some(entry) = cursor.as_ref() {
            if !entry.ifa_addr.is_null() && (*entry.ifa_addr).sa_family as i32 == AF_INET {
                let addr = &*entry.ifa_addr.cast::<sockaddr_in>();
                let ip = Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());
                duplicate |= ip == local;
                if CStr::from_ptr(entry.ifa_name).to_bytes() == name.as_bytes()
                    && !entry.ifa_netmask.is_null()
                    && (*entry.ifa_netmask).sa_family as i32 == AF_INET
                {
                    let mask = u32::from_be_bytes(
                        (*entry.ifa_netmask.cast::<sockaddr_in>())
                            .sin_addr
                            .s_addr
                            .to_ne_bytes(),
                    );
                    let prefix = mask.leading_ones() as u8;
                    if mask == u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0)
                        && requested.is_none_or(|p| p == prefix)
                        && u32::from(ip) & mask == u32::from(local) & mask
                    {
                        found = Some((ip, prefix));
                    }
                }
            }
            cursor = entry.ifa_next;
        }
        libc::freeifaddrs(list);
    }
    if duplicate || !unicast(local) {
        return Err(EADDRNOTAVAIL);
    }
    let (ip, prefix) = found.ok_or(EADDRNOTAVAIL)?;
    if prefix <= 30 {
        let mask = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
        if u32::from(local) == u32::from(ip) & mask || u32::from(local) == u32::from(ip) | !mask {
            return Err(EADDRNOTAVAIL);
        }
    }
    Ok((ip, prefix))
}
impl Owner {
    fn new(name: &str, local: Ipv4Addr) -> Result<Self> {
        let tun = Tun::open(name).map_err(|e| e.raw_os_error().unwrap_or(EIO))?;
        let subnet = context(name, local)?;
        let mut secret = [0u8; 32];
        let mut offset = 0;
        while offset < secret.len() {
            let n = unsafe {
                syscall(
                    SYS_getrandom,
                    secret[offset..].as_mut_ptr(),
                    secret.len() - offset,
                    0,
                )
            };
            if n < 0 {
                if errno() == EINTR {
                    continue;
                }
                return Err(errno());
            }
            if n == 0 {
                return Err(EIO);
            }
            offset += n as usize;
        }
        Self::with_endpoint(local, subnet, secret, Some(tun))
    }
    fn with_endpoint(
        local: Ipv4Addr,
        (address, prefix): (Ipv4Addr, u8),
        secret: [u8; 32],
        tun: Option<Tun>,
    ) -> Result<Self> {
        let mut config = EndpointConfig {
            max_connections: LIMIT,
            max_listeners: LIMIT,
            max_control_packets: LIMIT,
            max_buffer_bytes: 128 * 1024 * 1024,
            ..EndpointConfig::default()
        };
        config.connection.receive_capacity = BYTES;
        config.connection.send_capacity = BYTES;
        config.connection.mss = 1460;
        config.connection.send_ip_payload_limit = 1480;
        config.connection.receive_ip_payload_limit = 65515;
        let valid = move |ip: IpAddr| {
            matches!(ip, IpAddr::V4(ip) if unicast(ip)
            && (prefix > 30 || u32::from(ip) != u32::from(address) | (u32::MAX.checked_shr(prefix as u32).unwrap_or(0))))
        };
        let endpoint = Endpoint::new(config, secret, 0, move |r| match r {
            AddressValidation::Bind { local: bind } => {
                (bind.is_unspecified() || bind == IpAddr::V4(local))
                    && (bind.is_unspecified() || valid(bind))
            }
            AddressValidation::Open {
                local: source,
                remote,
            } => source == IpAddr::V4(local) && valid(remote),
            AddressValidation::Incoming {
                source,
                destination,
            } => destination == IpAddr::V4(local) && valid(source),
            AddressValidation::Route { .. } => false,
        })
        .map_err(engine)?;
        Ok(Self {
            endpoint,
            tun,
            sockets: BTreeMap::new(),
            local,
            epoch: Instant::now(),
            next_port: 40000,
            next_id: 1,
            detached: Vec::new(),
            pending_packet: None,
            child_timeouts: Vec::new(),
        })
    }
    fn now(&self) -> u64 {
        self.epoch.elapsed().as_micros().min(u64::MAX as u128) as u64
    }
    fn run(&mut self, rx: Receiver<Request>, wake: i32) {
        let mut input = vec![0; 65535];
        loop {
            let now = self.now();
            if self.endpoint.on_timeout(now, BUDGET).is_err() {
                break;
            }
            for _ in 0..BUDGET {
                match self.tun.as_mut().unwrap().receive(&mut input) {
                    Ok(Some(n)) => {
                        if let Ok(p) = ntcp_ip::parse(&input[..n], false)
                            && p.protocol == 6
                        {
                            let _ = self.input(now, p.ip, p.traffic_class, p.payload);
                        }
                    }
                    Ok(None) => break,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::Interrupted
                            || e.kind() == std::io::ErrorKind::InvalidData => {}
                    Err(_) => return,
                }
            }
            self.events();
            for _ in 0..BUDGET {
                if self.pending_packet.is_none() {
                    let mut packet = vec![0; 1500];
                    let transmit =
                        match self
                            .endpoint
                            .poll_transmit(self.now(), &mut packet[20..], BUDGET)
                        {
                            Ok(tx) => tx.packet,
                            Err(_) => return,
                        };
                    let Some(tx) = transmit else {
                        break;
                    };
                    let n = match ntcp_ip::encode(&mut packet, tx, (self.now() / 1000) as u32) {
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    packet.truncate(n);
                    self.pending_packet = Some(packet);
                }
                // Never poll another TCP segment until this complete IP packet is submitted.
                match self
                    .tun
                    .as_mut()
                    .unwrap()
                    .transmit(self.pending_packet.as_ref().unwrap())
                {
                    Ok(TxOutcome::Submitted) => self.pending_packet = None,
                    Ok(TxOutcome::WouldBlock) => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => break,
                    Err(_) => return,
                }
            }
            self.events();
            self.detached.retain(|&id| {
                if matches!(self.endpoint.state(id), Ok(State::Closed | State::TimeWait)) {
                    let _ = self.endpoint.release(id);
                    false
                } else {
                    true
                }
            });
            // Bounded owner work and a 1ms ceiling also cover shared wakefd consumers.
            match rx.recv_timeout(std::time::Duration::from_millis(1)) {
                Ok(r) => {
                    let result = self.execute(r.id, r.op);
                    let _ = r.reply.send(result);
                    for _ in 1..BUDGET {
                        let Ok(r) = rx.try_recv() else {
                            break;
                        };
                        let result = self.execute(r.id, r.op);
                        let _ = r.reply.send(result);
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => (),
            }
            signal(wake);
        }
    }
    fn prune_child_timeouts(&mut self) {
        self.child_timeouts
            .retain(|(cid, _, _, _)| self.endpoint.connection_exists(*cid));
    }
    fn input(
        &mut self,
        now: u64,
        ip: ntcp::IpMetadata,
        traffic_class: u8,
        bytes: &[u8],
    ) -> std::result::Result<ntcp::InputDisposition, EndpointError> {
        // Endpoint validates the packet; the ports are only used to observe
        // generation-aware tuple ownership before and after passive admission.
        let tuple = bytes.get(..4).map(|ports| ntcp::Tuple {
            local: SocketAddr::new(ip.destination, u16::from_be_bytes([ports[2], ports[3]])),
            remote: SocketAddr::new(ip.source, u16::from_be_bytes([ports[0], ports[1]])),
        });
        let before = tuple.and_then(|tuple| self.endpoint.connection_id(tuple));
        let result = self
            .endpoint
            .input_with_traffic_class(now, ip, traffic_class, bytes);
        self.prune_child_timeouts();
        if let Some(tuple) = tuple
            && let Some(cid) = self.endpoint.connection_id(tuple)
            && Some(cid) != before
            && let Some((&listener, s)) = self.sockets.iter().find(|(_, s)| {
                matches!(s.handle, Handle::Listener(_))
                    && s.local.is_some_and(|local| {
                        local.port() == tuple.local.port()
                            && (local.ip().is_unspecified() || local == tuple.local)
                    })
            })
        {
            // Runtime bind policy admits only one listener per port. Input can
            // only create passive children; active opens go through Connect.
            // ponytail: bounded linear metadata lookup, index if LIMIT grows.
            debug_assert!(self.child_timeouts.len() < LIMIT);
            self.child_timeouts
                .push((cid, listener, s.receive_timeout_us, s.send_timeout_us));
        }
        result
    }
    fn events(&mut self) {
        for _ in 0..BUDGET {
            let Some(event) = self.endpoint.next_event() else {
                break;
            };
            for s in self.sockets.values_mut() {
                match (s.handle, &event) {
                    (Handle::Listener(id), Event::Acceptable(other)) if id == *other => {
                        s.acceptable = true
                    }
                    (Handle::Connection(id), Event::Connection(other, e)) if id == *other => {
                        s.connected |= e.connected;
                        if let Some(reason) = e.closed {
                            s.error = match reason {
                                CloseReason::Reset if !s.connected => ECONNREFUSED,
                                CloseReason::Reset => ECONNRESET,
                                CloseReason::TimedOut => ETIMEDOUT,
                                CloseReason::Aborted => ECONNABORTED,
                                CloseReason::NetworkError => EHOSTUNREACH,
                                CloseReason::Normal => 0,
                            };
                        }
                    }
                    _ => (),
                }
            }
        }
    }
    fn alloc(&mut self, s: Socket) -> Result<i32> {
        if self.sockets.len() == LIMIT || self.next_id > i32::MAX as u64 {
            return Err(EMFILE);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.sockets.insert(id, s);
        Ok(id as i32)
    }
    fn port(&mut self) -> Result<u16> {
        for _ in 0..20000 {
            let p = self.next_port;
            self.next_port = if p == 59999 { 40000 } else { p + 1 };
            if !self
                .sockets
                .values()
                .any(|s| s.local.is_some_and(|a| a.port() == p))
            {
                return Ok(p);
            }
        }
        Err(EADDRNOTAVAIL)
    }
    fn apply_options(&mut self, cid: ConnectionId, s: &Socket) -> Result<()> {
        // Validate the fallible option before changing the infallible one.
        self.endpoint
            .set_keepalive(cid, s.keepalive_config())
            .map_err(engine)?;
        self.endpoint.set_nagle(cid, !s.nodelay).map_err(engine)
    }
    fn rollback_connection(&mut self, cid: ConnectionId) {
        // release retains storage until any reset output has drained.
        let _ = self.endpoint.abort(cid);
        let _ = self.endpoint.release(cid);
    }
    fn execute(&mut self, id: u64, op: Op) -> Result<Reply> {
        self.endpoint.on_timeout(self.now(), 0).map_err(engine)?;
        self.prune_child_timeouts();
        let mut out = Reply::default();
        if let Op::New(flags) = op {
            out.value = self.alloc(Socket::new(flags))?;
            return Ok(out);
        }
        let s = self.sockets.get(&id).ok_or(EBADF)?;
        match op {
            Op::Bind(mut addr) => {
                if !matches!(s.handle, Handle::Fresh) || s.local.is_some() {
                    return Err(EINVAL);
                }
                if addr.ip() != IpAddr::V4(self.local) && !addr.ip().is_unspecified() {
                    return Err(EADDRNOTAVAIL);
                }
                let reuse = s.reuse;
                if addr.port() == 0 {
                    addr.set_port(self.port()?);
                }
                if self.sockets.iter().any(|(&other, s)| {
                    other != id
                        && !(reuse && s.reuse && matches!(s.handle, Handle::Connection(_)))
                        && s.local.is_some_and(|a| a.port() == addr.port())
                }) {
                    return Err(EADDRINUSE);
                }
                self.sockets.get_mut(&id).unwrap().local = Some(addr);
            }
            Op::Listen(backlog) => {
                if !matches!(s.handle, Handle::Fresh) {
                    return Err(EOPNOTSUPP);
                }
                let capacities = (s.send_capacity, s.receive_capacity);
                let local = match s.local {
                    Some(a) => a,
                    None => SocketAddr::new(self.local.into(), self.port()?),
                };
                let listener = self
                    .endpoint
                    .listen(local, backlog.clamp(1, LIMIT as i32) as usize)
                    .map_err(engine)?;
                if let Err(e) = self.endpoint.set_listener_buffer_capacities(
                    listener,
                    capacities.0,
                    capacities.1,
                ) {
                    let _ = self.endpoint.close_listener(listener);
                    return Err(engine(e));
                }
                let s = self.sockets.get_mut(&id).unwrap();
                s.local = Some(local);
                s.handle = Handle::Listener(listener);
            }
            Op::Accept(flags) => {
                if self.sockets.len() == LIMIT {
                    return Err(EMFILE);
                }
                let Handle::Listener(listener) = s.handle else {
                    return Err(EINVAL);
                };
                let mut child = Socket::new(flags);
                child.reuse = s.reuse;
                child.nodelay = s.nodelay;
                child.keepalive = s.keepalive;
                child.idle = s.idle;
                child.interval = s.interval;
                child.probes = s.probes;
                let accepted = self.endpoint.accept(listener);
                if matches!(accepted, Err(EndpointError::Connection(Error::WouldBlock))) {
                    self.sockets.get_mut(&id).unwrap().acceptable = false;
                }
                let cid = accepted.map_err(engine)?;
                (child.send_capacity, child.receive_capacity) =
                    self.endpoint.buffer_capacities(cid).map_err(engine)?;
                if let Some(index) = self
                    .child_timeouts
                    .iter()
                    .position(|(other, _, _, _)| *other == cid)
                {
                    let (_, _, receive, send) = self.child_timeouts.swap_remove(index);
                    child.receive_timeout_us = receive;
                    child.send_timeout_us = send;
                }
                let tuple = match self.endpoint.tuple(cid).map_err(engine) {
                    Ok(tuple) => tuple,
                    Err(e) => {
                        self.rollback_connection(cid);
                        return Err(e);
                    }
                };
                child.handle = Handle::Connection(cid);
                child.local = Some(tuple.local);
                child.connected = true;
                if let Err(e) = self.apply_options(cid, &child) {
                    self.rollback_connection(cid);
                    return Err(e);
                }
                out.value = match self.alloc(child) {
                    Ok(id) => id,
                    Err(e) => {
                        self.rollback_connection(cid);
                        return Err(e);
                    }
                };
                out.addr = Some(tuple.remote);
                // Core emits Acceptable on empty->nonempty; stay readable until accept returns EAGAIN.
            }
            Op::Connect(remote) => {
                match s.handle {
                    Handle::Fresh => (),
                    Handle::Listener(_) => return Err(EINVAL),
                    Handle::Connection(cid) => {
                        return Err(
                            if matches!(
                                self.endpoint.state(cid),
                                Ok(State::SynSent | State::SynReceived)
                            ) {
                                EALREADY
                            } else {
                                EISCONN
                            },
                        );
                    }
                }
                if remote.port() == 0 {
                    return Err(EINVAL);
                }
                let options = s.clone();
                let mut local = match s.local {
                    Some(a) => a,
                    None => SocketAddr::new(self.local.into(), self.port()?),
                };
                if local.ip().is_unspecified() {
                    local.set_ip(self.local.into());
                }
                let cid = self
                    .endpoint
                    .connect_with_buffer_capacities(
                        self.now(),
                        local,
                        remote,
                        options.send_capacity,
                        options.receive_capacity,
                    )
                    .map_err(engine)?;
                if let Err(e) = self.apply_options(cid, &options) {
                    self.rollback_connection(cid);
                    return Err(e);
                }
                let s = self.sockets.get_mut(&id).unwrap();
                s.handle = Handle::Connection(cid);
                s.local = Some(local);
                return Err(EINPROGRESS);
            }
            Op::Read(capacity) | Op::Peek(capacity) => {
                let peek = matches!(op, Op::Peek(_));
                let Handle::Connection(cid) = s.handle else {
                    return Err(ENOTCONN);
                };
                if capacity == 0 || s.read_shutdown {
                    return Ok(out);
                }
                // Deliver buffered data before the terminal error/EOF.
                let terminal = self.endpoint.state(cid).map_err(engine)? == State::Closed;
                let available = if terminal {
                    self.endpoint.terminal_readable_bytes(cid)
                } else {
                    self.endpoint.readable_bytes(cid)
                }
                .map_err(engine)?;
                if available == 0 && s.error != 0 {
                    let s = self.sockets.get_mut(&id).unwrap();
                    let e = s.error;
                    s.error = 0;
                    return Err(e);
                }
                out.bytes.resize(capacity.min(BYTES), 0);
                let n = if peek && terminal {
                    self.endpoint.peek_terminal(cid, &mut out.bytes)
                } else if peek {
                    self.endpoint.peek(cid, &mut out.bytes)
                } else if terminal {
                    self.endpoint.read_terminal(cid, &mut out.bytes)
                } else {
                    self.endpoint.read(cid, &mut out.bytes)
                }
                .map_err(engine)?;
                out.bytes.truncate(n);
                out.value = n as i32;
            }
            Op::Write(bytes) => {
                let Handle::Connection(cid) = s.handle else {
                    return Err(ENOTCONN);
                };
                let state = self.endpoint.state(cid).map_err(engine)?;
                if s.write_shutdown || matches!(state, State::Closed | State::TimeWait) {
                    return Err(EPIPE);
                }
                if s.error != 0 {
                    return Err(s.error);
                }
                if matches!(state, State::SynSent | State::SynReceived) {
                    return Err(EAGAIN);
                }
                out.value = if bytes.is_empty() {
                    0
                } else {
                    self.endpoint.write(cid, &bytes).map_err(engine)? as i32
                };
            }
            Op::Close => {
                match s.handle {
                    Handle::Fresh => (),
                    Handle::Listener(l) => self.endpoint.close_listener(l).map_err(engine)?,
                    Handle::Connection(cid) => {
                        if !matches!(
                            self.endpoint.state(cid),
                            Ok(State::Closed | State::TimeWait)
                        ) {
                            let _ = self.endpoint.close(cid);
                        }
                        if matches!(
                            self.endpoint.state(cid),
                            Ok(State::Closed | State::TimeWait)
                        ) {
                            self.endpoint.release(cid).map_err(engine)?;
                        } else {
                            // Endpoint has at most LIMIT records; this attached
                            // record is not yet in detached, so there is room.
                            debug_assert!(self.detached.len() < LIMIT);
                            self.detached.push(cid);
                        }
                    }
                }
                self.child_timeouts
                    .retain(|(_, listener, _, _)| *listener != id);
                self.sockets.remove(&id);
            }
            Op::Shutdown(how) => {
                let Handle::Connection(cid) = s.handle else {
                    return Err(ENOTCONN);
                };
                if !(SHUT_RD..=SHUT_RDWR).contains(&how) {
                    return Err(EINVAL);
                }
                if how != SHUT_RD && !s.write_shutdown {
                    self.endpoint.shutdown(cid).map_err(engine)?;
                }
                let s = self.sockets.get_mut(&id).unwrap();
                s.read_shutdown |= how != SHUT_WR;
                s.write_shutdown |= how != SHUT_RD;
            }
            Op::Flags(cmd, value) => {
                let s = self.sockets.get_mut(&id).unwrap();
                match cmd {
                    F_GETFL => {
                        out.value = O_RDWR
                            | if s.flags & SOCK_NONBLOCK != 0 {
                                O_NONBLOCK
                            } else {
                                0
                            }
                    }
                    F_SETFL => {
                        if value & !(O_ACCMODE | O_NONBLOCK) != 0 {
                            return Err(EOPNOTSUPP);
                        }
                        s.flags = (s.flags & !SOCK_NONBLOCK)
                            | if value & O_NONBLOCK != 0 {
                                SOCK_NONBLOCK
                            } else {
                                0
                            };
                    }
                    _ => return Err(EOPNOTSUPP),
                }
            }
            Op::SetTimeout(send, micros) => {
                let s = self.sockets.get_mut(&id).unwrap();
                if send {
                    s.send_timeout_us = micros;
                } else {
                    s.receive_timeout_us = micros;
                }
            }
            Op::GetTimeout(send) => {
                out.timeout_us = if send {
                    s.send_timeout_us
                } else {
                    s.receive_timeout_us
                };
            }
            Op::Set(level, name, value) => {
                let mut candidate = s.clone();
                let s = &mut candidate;
                match (level, name) {
                    (SOL_SOCKET, SO_REUSEADDR) => s.reuse = value != 0,
                    (SOL_SOCKET, SO_KEEPALIVE) => s.keepalive = value != 0,
                    (SOL_SOCKET, SO_SNDBUF) => s.send_capacity = socket_buffer_value(name, value),
                    (SOL_SOCKET, SO_RCVBUF) => {
                        s.receive_capacity = socket_buffer_value(name, value)
                    }
                    (IPPROTO_TCP, TCP_NODELAY) => s.nodelay = value != 0,
                    (IPPROTO_TCP, TCP_KEEPIDLE) if value > 0 && value <= 32767 => s.idle = value,
                    (IPPROTO_TCP, TCP_KEEPINTVL) if value > 0 && value <= 32767 => {
                        s.interval = value
                    }
                    (IPPROTO_TCP, TCP_KEEPCNT) if (2..=127).contains(&value) => s.probes = value,
                    (IPPROTO_TCP, TCP_KEEPIDLE | TCP_KEEPINTVL | TCP_KEEPCNT) => {
                        return Err(EINVAL);
                    }
                    _ => return Err(ENOPROTOOPT),
                }
                if matches!((level, name), (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF)) {
                    match s.handle {
                        Handle::Connection(cid) => self
                            .endpoint
                            .set_buffer_capacities(cid, s.send_capacity, s.receive_capacity)
                            .map_err(engine)?,
                        Handle::Listener(listener) => self
                            .endpoint
                            .set_listener_buffer_capacities(
                                listener,
                                s.send_capacity,
                                s.receive_capacity,
                            )
                            .map_err(engine)?,
                        Handle::Fresh => (),
                    }
                } else if let Handle::Connection(cid) = s.handle {
                    self.apply_options(cid, s)?;
                }
                self.sockets.insert(id, candidate);
            }
            Op::Get(level, name) => {
                let s = self.sockets.get_mut(&id).unwrap();
                out.value = match (level, name) {
                    (SOL_SOCKET, SO_TYPE) => SOCK_STREAM,
                    (SOL_SOCKET, SO_DOMAIN) => AF_INET,
                    (SOL_SOCKET, SO_PROTOCOL) => IPPROTO_TCP,
                    (SOL_SOCKET, SO_ERROR) => {
                        let e = s.error;
                        s.error = 0;
                        e
                    }
                    (SOL_SOCKET, SO_ACCEPTCONN) => {
                        i32::from(matches!(s.handle, Handle::Listener(_)))
                    }
                    (SOL_SOCKET, SO_REUSEADDR) => s.reuse as i32,
                    (SOL_SOCKET, SO_KEEPALIVE) => s.keepalive as i32,
                    (SOL_SOCKET, SO_SNDBUF) => s.send_capacity as i32,
                    (SOL_SOCKET, SO_RCVBUF) => s.receive_capacity as i32,
                    (IPPROTO_TCP, TCP_NODELAY) => s.nodelay as i32,
                    (IPPROTO_TCP, TCP_KEEPIDLE) => s.idle,
                    (IPPROTO_TCP, TCP_KEEPINTVL) => s.interval,
                    (IPPROTO_TCP, TCP_KEEPCNT) => s.probes,
                    _ => return Err(ENOPROTOOPT),
                };
            }
            Op::Name(peer) => {
                out.addr = Some(if peer {
                    let Handle::Connection(cid) = s.handle else {
                        return Err(ENOTCONN);
                    };
                    if !s.connected {
                        return Err(ENOTCONN);
                    }
                    self.endpoint.tuple(cid).map_err(engine)?.remote
                } else {
                    s.local
                        .unwrap_or(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0))
                });
            }
            Op::Available => {
                out.value = match s.handle {
                    Handle::Connection(cid) => {
                        if s.read_shutdown {
                            0
                        } else if self.endpoint.state(cid).map_err(engine)? == State::Closed {
                            self.endpoint.terminal_readable_bytes(cid).map_err(engine)? as i32
                        } else {
                            self.endpoint.readable_bytes(cid).map_err(engine)? as i32
                        }
                    }
                    Handle::Fresh => 0,
                    Handle::Listener(_) => return Err(EINVAL),
                };
            }
            Op::Ready => {
                if s.error != 0 {
                    out.value |= EPOLLERR;
                }
                match s.handle {
                    Handle::Fresh => (),
                    Handle::Listener(_) => {
                        if s.acceptable {
                            out.value |= EPOLLIN;
                        }
                    }
                    Handle::Connection(cid) => {
                        let state = self.endpoint.state(cid).map_err(engine)?;
                        let info = self.endpoint.transport_info(cid).map_err(engine)?;
                        let eof = matches!(
                            state,
                            State::CloseWait
                                | State::Closing
                                | State::LastAck
                                | State::TimeWait
                                | State::Closed
                        );
                        if info.receive_used != 0 || eof || s.read_shutdown {
                            out.value |= EPOLLIN;
                        }
                        if eof {
                            out.value |= EPOLLRDHUP;
                        }
                        if s.write_shutdown
                            || s.error != 0
                            || matches!(state, State::Closed | State::TimeWait)
                            || (matches!(state, State::Established | State::CloseWait)
                                && info.send_used < info.send_capacity)
                        {
                            out.value |= EPOLLOUT;
                        }
                        if state == State::Closed || (s.write_shutdown && eof) {
                            out.value |= EPOLLHUP;
                        }
                    }
                }
            }
            Op::New(_) => unreachable!(),
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owner(last: u8) -> Owner {
        let local = Ipv4Addr::new(10, 73, 0, last);
        Owner::with_endpoint(local, (Ipv4Addr::new(10, 73, 0, 1), 24), [last; 32], None).unwrap()
    }
    fn new(o: &mut Owner, flags: i32) -> u64 {
        o.execute(0, Op::New(flags)).unwrap().value as u64
    }
    fn pump(a: &mut Owner, b: &mut Owner) {
        for _ in 0..32 {
            let mut progress = false;
            for reverse in [false, true] {
                let (from, to) = if reverse {
                    (&mut *b, &mut *a)
                } else {
                    (&mut *a, &mut *b)
                };
                for _ in 0..32 {
                    let mut bytes = [0u8; 1480];
                    let p = from
                        .endpoint
                        .poll_transmit(from.now(), &mut bytes, 32)
                        .unwrap();
                    let Some(p) = p.packet else {
                        break;
                    };
                    to.input(to.now(), p.ip, p.dscp << 2 | p.ecn, &bytes[..p.len])
                        .unwrap();
                    progress = true;
                }
                from.events();
                to.events();
            }
            if !progress {
                break;
            }
        }
    }
    fn pair() -> (Owner, Owner, u64, u64, u64) {
        let mut a = owner(2);
        let mut b = owner(3);
        let listen = new(&mut b, SOCK_NONBLOCK);
        b.execute(listen, Op::Bind("10.73.0.3:16379".parse().unwrap()))
            .unwrap();
        b.execute(listen, Op::Listen(16)).unwrap();
        let client = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(client, Op::Connect("10.73.0.3:16379".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        assert_eq!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
        pump(&mut a, &mut b);
        assert_ne!(b.execute(listen, Op::Ready).unwrap().value & EPOLLIN, 0);
        let server = b.execute(listen, Op::Accept(SOCK_NONBLOCK)).unwrap().value as u64;
        (a, b, client, server, listen)
    }
    #[test]
    fn peek_dispatch_and_timeout_inheritance() {
        let (mut a, mut b, client, server, listen) = pair();
        assert_eq!(b.execute(server, Op::Peek(8)).unwrap_err(), EAGAIN);
        a.execute(client, Op::Write(b"abcdef".to_vec())).unwrap();
        pump(&mut a, &mut b);
        let Handle::Connection(cid) = b.sockets[&server].handle else {
            panic!()
        };
        let before = b.endpoint.transport_info(cid).unwrap();
        for _ in 0..2 {
            assert_eq!(b.execute(server, Op::Peek(3)).unwrap().bytes, b"abc");
            assert_eq!(
                b.endpoint.transport_info(cid).unwrap().receive_used,
                before.receive_used
            );
        }
        assert_eq!(b.execute(server, Op::Read(8)).unwrap().bytes, b"abcdef");
        b.execute(listen, Op::SetTimeout(false, 123456)).unwrap();
        b.execute(listen, Op::SetTimeout(true, u64::MAX)).unwrap();
        let next = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(next, Op::Connect("10.73.0.3:16379".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        pump(&mut a, &mut b);
        b.execute(listen, Op::SetTimeout(false, 654321)).unwrap();
        b.execute(listen, Op::SetTimeout(true, 987654)).unwrap();
        let child = b.execute(listen, Op::Accept(0)).unwrap().value as u64;
        assert!(b.child_timeouts.is_empty());
        assert_eq!(
            b.execute(child, Op::GetTimeout(false)).unwrap().timeout_us,
            123456
        );
        assert_eq!(
            b.execute(child, Op::GetTimeout(true)).unwrap().timeout_us,
            u64::MAX
        );
        assert_eq!(
            b.execute(child, Op::Flags(F_GETFL, 0)).unwrap().value & O_NONBLOCK,
            0
        );
    }

    #[test]
    fn passive_timeouts_snapshot_at_syn_and_cleanup_on_listener_close() {
        let (mut a, mut b, _, _, listen) = pair();
        b.execute(listen, Op::SetTimeout(false, 123456)).unwrap();
        b.execute(listen, Op::SetTimeout(true, 234567)).unwrap();
        let next = new(&mut a, 0);
        assert_eq!(
            a.execute(next, Op::Connect("10.73.0.3:16379".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        let mut bytes = [0; 1480];
        let syn = a
            .endpoint
            .poll_transmit(a.now(), &mut bytes, BUDGET)
            .unwrap()
            .packet
            .unwrap();
        b.input(b.now(), syn.ip, syn.dscp << 2 | syn.ecn, &bytes[..syn.len])
            .unwrap();
        let cid = b.child_timeouts[0].0;
        assert_eq!(b.endpoint.state(cid).unwrap(), State::SynReceived);
        b.execute(listen, Op::SetTimeout(false, 345678)).unwrap();
        b.execute(listen, Op::SetTimeout(true, 456789)).unwrap();
        // A retransmitted SYN must not replace the initial snapshot.
        b.input(b.now(), syn.ip, syn.dscp << 2 | syn.ecn, &bytes[..syn.len])
            .unwrap();
        assert_eq!(b.child_timeouts.len(), 1);
        pump(&mut a, &mut b);
        let child = b.execute(listen, Op::Accept(0)).unwrap().value as u64;
        assert_eq!(
            b.execute(child, Op::GetTimeout(false)).unwrap().timeout_us,
            123456
        );
        assert_eq!(
            b.execute(child, Op::GetTimeout(true)).unwrap().timeout_us,
            234567
        );
        assert!(b.child_timeouts.is_empty());
        let next = new(&mut a, 0);
        assert_eq!(
            a.execute(next, Op::Connect("10.73.0.3:16379".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        pump(&mut a, &mut b);
        assert_eq!(b.child_timeouts.len(), 1);
        b.execute(listen, Op::Close).unwrap();
        assert!(b.child_timeouts.is_empty());
    }

    #[test]
    fn dispatch_stream_readiness_eof_and_listener_drain() {
        let (mut a, mut b, client, server, listen) = pair();
        assert_ne!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
        assert_eq!(b.execute(listen, Op::Accept(0)).unwrap_err(), EAGAIN);
        assert_eq!(b.execute(listen, Op::Ready).unwrap().value & EPOLLIN, 0);
        assert_eq!(b.execute(server, Op::Read(4)).unwrap_err(), EAGAIN);
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
            .unwrap();
        assert_eq!(
            a.execute(client, Op::Write(b"abcdef".to_vec()))
                .unwrap()
                .value,
            6
        );
        a.execute(client, Op::Shutdown(SHUT_WR)).unwrap();
        pump(&mut a, &mut b);
        assert_ne!(b.execute(server, Op::Ready).unwrap().value & EPOLLIN, 0);
        assert_eq!(b.execute(server, Op::Read(2)).unwrap().bytes, b"ab");
        assert_eq!(b.execute(server, Op::Read(32)).unwrap().bytes, b"cdef");
        assert_eq!(b.execute(server, Op::Read(32)).unwrap().value, 0);
        assert_ne!(b.execute(server, Op::Ready).unwrap().value & EPOLLIN, 0);
        assert_eq!(a.execute(client, Op::Write(vec![1])).unwrap_err(), EPIPE);
        b.execute(server, Op::Close).unwrap();
        a.execute(client, Op::Close).unwrap();
        assert_eq!(a.execute(client, Op::Ready).unwrap_err(), EBADF);
        pump(&mut a, &mut b);
        assert!(!a.endpoint.has_pending_output());
    }
    #[test]
    fn refusal_completes_and_error_is_consumed_once() {
        let mut a = owner(2);
        let mut b = owner(3);
        let id = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(id, Op::Connect("10.73.0.3:12345".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        pump(&mut a, &mut b);
        let ready = a.execute(id, Op::Ready).unwrap().value;
        assert_ne!(ready & EPOLLOUT, 0);
        assert_ne!(ready & EPOLLERR, 0);
        assert_eq!(
            a.execute(id, Op::Get(SOL_SOCKET, SO_ERROR)).unwrap().value,
            ECONNREFUSED
        );
        assert_eq!(
            a.execute(id, Op::Get(SOL_SOCKET, SO_ERROR)).unwrap().value,
            0
        );
    }
    #[test]
    fn bounds_flags_addresses_and_honest_options() {
        let mut a = owner(2);
        let id = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(id, Op::Bind("10.73.0.1:1234".parse().unwrap()))
                .unwrap_err(),
            EADDRNOTAVAIL
        );
        a.execute(id, Op::Bind("0.0.0.0:0".parse().unwrap()))
            .unwrap();
        assert_ne!(
            a.execute(id, Op::Name(false)).unwrap().addr.unwrap().port(),
            0
        );
        a.execute(id, Op::Flags(F_SETFL, 0)).unwrap();
        assert_eq!(
            a.execute(id, Op::Flags(F_GETFL, 0)).unwrap().value & O_NONBLOCK,
            0
        );
        assert_eq!(
            a.execute(id, Op::Set(SOL_SOCKET, SO_REUSEPORT, 1))
                .unwrap_err(),
            ENOPROTOOPT
        );
        assert_eq!(
            a.execute(id, Op::Set(IPPROTO_TCP, TCP_KEEPIDLE, 0))
                .unwrap_err(),
            EINVAL
        );
        a.execute(id, Op::Set(IPPROTO_TCP, TCP_KEEPIDLE, 60))
            .unwrap();
        a.execute(id, Op::Set(SOL_SOCKET, SO_KEEPALIVE, 1)).unwrap();
        assert_eq!(
            a.execute(id, Op::Get(IPPROTO_TCP, TCP_KEEPIDLE))
                .unwrap()
                .value,
            60
        );
        for _ in 1..LIMIT {
            new(&mut a, 0);
        }
        assert_eq!(a.execute(0, Op::New(0)).unwrap_err(), EMFILE);
    }
    #[test]
    fn reset_drains_payload_then_reports_error_once_then_eof() {
        let (mut a, mut b, client, server, _) = pair();
        a.execute(client, Op::Write(b"abcdef".to_vec())).unwrap();
        pump(&mut a, &mut b);
        let Handle::Connection(cid) = a.sockets[&client].handle else {
            panic!()
        };
        a.endpoint.abort(cid).unwrap();
        pump(&mut a, &mut b);
        assert_eq!(b.execute(server, Op::Available).unwrap().value, 6);
        assert_eq!(b.execute(server, Op::Read(2)).unwrap().bytes, b"ab");
        assert_eq!(b.execute(server, Op::Available).unwrap().value, 4);
        assert_eq!(b.execute(server, Op::Read(32)).unwrap().bytes, b"cdef");
        assert_eq!(b.execute(server, Op::Read(32)).unwrap_err(), ECONNRESET);
        for _ in 0..2 {
            assert_eq!(b.execute(server, Op::Read(32)).unwrap().value, 0);
            assert_ne!(b.execute(server, Op::Ready).unwrap().value & EPOLLIN, 0);
        }
    }

    #[test]
    fn keepalive_rejection_is_transactional_in_all_socket_states() {
        let (mut a, mut b, client, server, listen) = pair();
        let fresh = new(&mut b, 0);
        for id in [fresh, listen, server] {
            b.execute(id, Op::Set(IPPROTO_TCP, TCP_KEEPCNT, 4)).unwrap();
            b.execute(id, Op::Set(SOL_SOCKET, SO_KEEPALIVE, 1)).unwrap();
            assert_eq!(
                b.execute(id, Op::Set(IPPROTO_TCP, TCP_KEEPCNT, 1))
                    .unwrap_err(),
                EINVAL
            );
            assert_eq!(
                b.execute(id, Op::Get(IPPROTO_TCP, TCP_KEEPCNT))
                    .unwrap()
                    .value,
                4
            );
            assert_eq!(
                b.execute(id, Op::Get(SOL_SOCKET, SO_KEEPALIVE))
                    .unwrap()
                    .value,
                1
            );
        }
        let second = new(&mut a, 0);
        assert_eq!(
            a.execute(second, Op::Connect("10.73.0.3:16379".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        pump(&mut a, &mut b);
        let accepted = b.execute(listen, Op::Accept(0)).unwrap().value as u64;
        assert_eq!(
            b.execute(accepted, Op::Get(IPPROTO_TCP, TCP_KEEPCNT))
                .unwrap()
                .value,
            4
        );
        a.execute(client, Op::Close).unwrap();
    }

    #[test]
    fn option_application_failure_releases_connect_and_accept_records() {
        let mut a = owner(2);
        let mut b = owner(3);
        let listen = new(&mut b, 0);
        b.execute(listen, Op::Bind("10.73.0.3:16379".parse().unwrap()))
            .unwrap();
        b.execute(listen, Op::Listen(16)).unwrap();
        let client = new(&mut a, 0);
        // Inject an invalid internal configuration to exercise otherwise
        // unreachable failure paths; public sets reject this before mutation.
        a.sockets.get_mut(&client).unwrap().keepalive = true;
        a.sockets.get_mut(&client).unwrap().probes = 1;
        assert_eq!(
            a.execute(client, Op::Connect("10.73.0.3:16379".parse().unwrap()))
                .unwrap_err(),
            EINVAL
        );
        assert!(matches!(a.sockets[&client].handle, Handle::Fresh));
        assert!(a.sockets[&client].local.is_none());
        pump(&mut a, &mut b);
        assert_eq!(a.endpoint.buffer_bytes(), 0);
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_KEEPCNT, 2))
            .unwrap();
        assert_eq!(
            a.execute(client, Op::Connect("10.73.0.3:16379".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        pump(&mut a, &mut b);
        b.sockets.get_mut(&listen).unwrap().keepalive = true;
        b.sockets.get_mut(&listen).unwrap().probes = 1;
        assert_eq!(b.execute(listen, Op::Accept(0)).unwrap_err(), EINVAL);
        assert_eq!(b.sockets.len(), 1);
        assert!(b.child_timeouts.is_empty());
        // The failed child owes a reset: release must retain it until output.
        assert_ne!(b.endpoint.buffer_bytes(), 0);
        pump(&mut a, &mut b);
        // Local resets retain the released record for the core's 2MSL
        // quarantine; expiry must reclaim it rather than leak a slot.
        assert_ne!(b.endpoint.buffer_bytes(), 0);
        b.epoch -=
            std::time::Duration::from_micros(ntcp::ConnectionConfig::default().time_wait_us + 1);
        b.endpoint.on_timeout(b.now(), BUDGET).unwrap();
        assert_eq!(b.endpoint.buffer_bytes(), 0);
        b.execute(listen, Op::Set(IPPROTO_TCP, TCP_KEEPCNT, 2))
            .unwrap();
        let second = new(&mut a, 0);
        assert_eq!(
            a.execute(second, Op::Connect("10.73.0.3:16379".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        pump(&mut a, &mut b);
        assert!(b.execute(listen, Op::Accept(0)).is_ok());
    }

    #[test]
    fn close_delivery_waits_for_space_in_bounded_queue() {
        let (tx, rx) = mpsc::sync_channel(LIMIT);
        for _ in 0..LIMIT {
            let (reply, _) = mpsc::sync_channel(1);
            tx.send(Request {
                id: 1,
                op: Op::Ready,
                reply,
            })
            .unwrap();
        }
        let runtime = Runtime {
            tx,
            wake: -1,
            family: AF_INET,
        };
        let caller = std::thread::spawn(move || runtime.call(1, Op::Close));
        for _ in 0..LIMIT {
            assert!(matches!(rx.recv().unwrap().op, Op::Ready));
        }
        let request = rx.recv().unwrap();
        assert!(matches!(request.op, Op::Close));
        request.reply.send(Ok(Reply::default())).unwrap();
        assert!(caller.join().unwrap().is_ok());
    }

    #[test]
    fn startup_failure_joins_before_closing_wake() {
        // The post-close fd-number assertion needs its own process: parallel
        // tests may legitimately allocate the just-closed number immediately.
        const CHILD: &str = "NTCP_TEST_STARTUP_CLOSE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "runtime::tests::startup_failure_joins_before_closing_wake",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let wake = unsafe { syscall(SYS_eventfd2, 0, EFD_NONBLOCK | EFD_CLOEXEC) as i32 };
        assert!(wake >= 0);
        let (tx, rx) = mpsc::sync_channel(0);
        let open_at_exit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = open_at_exit.clone();
        let worker = std::thread::spawn(move || {
            rx.recv().unwrap();
            observed.store(
                unsafe { syscall(SYS_fcntl, wake, F_GETFD) } >= 0,
                std::sync::atomic::Ordering::SeqCst,
            );
            signal(wake);
        });
        let closer = std::thread::spawn(move || close_failed_startup(worker, wake));
        tx.send(()).unwrap();
        closer.join().unwrap();
        assert!(open_at_exit.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(unsafe { syscall(SYS_fcntl, wake, F_GETFD) }, -1);
    }

    #[test]
    fn socket_buffer_semantics_inherit_at_syn_and_resize_readiness() {
        for (name, minimum) in [(SO_SNDBUF, 4608), (SO_RCVBUF, 2304)] {
            for (request, expected) in [
                (0, minimum),
                (1, minimum),
                (65536, 131072),
                (-1, 2097152),
                (i32::MAX, 2097152),
            ] {
                assert_eq!(socket_buffer_value(name, request), expected);
            }
        }
        let mut a = owner(2);
        let mut b = owner(3);
        let listener = new(&mut b, SOCK_NONBLOCK);
        b.execute(listener, Op::Set(SOL_SOCKET, SO_SNDBUF, 8192))
            .unwrap();
        b.execute(listener, Op::Set(SOL_SOCKET, SO_RCVBUF, 131072))
            .unwrap();
        b.execute(listener, Op::Bind("10.73.0.3:16379".parse().unwrap()))
            .unwrap();
        b.execute(listener, Op::Listen(4)).unwrap();
        let client = new(&mut a, SOCK_NONBLOCK);
        a.execute(client, Op::Set(SOL_SOCKET, SO_SNDBUF, 4096))
            .unwrap();
        a.execute(client, Op::Set(SOL_SOCKET, SO_RCVBUF, 262144))
            .unwrap();
        assert_eq!(
            a.execute(client, Op::Connect("10.73.0.3:16379".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        pump(&mut a, &mut b);
        b.execute(listener, Op::Set(SOL_SOCKET, SO_SNDBUF, 0))
            .unwrap();
        b.execute(listener, Op::Set(SOL_SOCKET, SO_RCVBUF, 0))
            .unwrap();
        let server = b
            .execute(listener, Op::Accept(SOCK_NONBLOCK))
            .unwrap()
            .value as u64;
        assert_eq!(
            b.execute(server, Op::Get(SOL_SOCKET, SO_SNDBUF))
                .unwrap()
                .value,
            16384
        );
        assert_eq!(
            b.execute(server, Op::Get(SOL_SOCKET, SO_RCVBUF))
                .unwrap()
                .value,
            262144
        );
        assert_eq!(
            a.execute(client, Op::Write(vec![42; 8192])).unwrap().value,
            8192
        );
        assert_eq!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
        a.execute(client, Op::Set(SOL_SOCKET, SO_SNDBUF, 0))
            .unwrap();
        assert_eq!(a.execute(client, Op::Write(vec![0])).unwrap_err(), EAGAIN);
        a.execute(client, Op::Set(SOL_SOCKET, SO_SNDBUF, 8192))
            .unwrap();
        assert_ne!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
        b.execute(server, Op::Set(SOL_SOCKET, SO_RCVBUF, 0))
            .unwrap();
        pump(&mut a, &mut b);
        assert_ne!(b.execute(server, Op::Ready).unwrap().value & EPOLLIN, 0);
        // The pre-shrink promised window accepts and retains all queued bytes.
        assert_eq!(
            b.execute(server, Op::Read(8192)).unwrap().bytes,
            vec![42; 8192]
        );
        assert_eq!(
            b.execute(server, Op::Get(SOL_SOCKET, SO_RCVBUF))
                .unwrap()
                .value,
            2304
        );
        let other = a
            .endpoint
            .connect(
                a.now(),
                "10.73.0.2:25000".parse().unwrap(),
                "10.73.0.3:25000".parse().unwrap(),
            )
            .unwrap();
        a.endpoint
            .set_buffer_capacities(other, 2 * BUFFER_REQUEST_CAP as usize, BYTES)
            .unwrap();
        let old = a
            .execute(client, Op::Get(SOL_SOCKET, SO_SNDBUF))
            .unwrap()
            .value;
        assert_eq!(
            a.execute(client, Op::Set(SOL_SOCKET, SO_SNDBUF, i32::MAX))
                .unwrap_err(),
            ENOBUFS
        );
        assert_eq!(
            a.execute(client, Op::Get(SOL_SOCKET, SO_SNDBUF))
                .unwrap()
                .value,
            old
        );
    }

    #[test]
    fn send_buffer_backpressure_and_short_write() {
        let (mut a, mut b, client, _server, _listen) = pair();
        let first = a
            .execute(client, Op::Write(vec![42; BYTES - 10]))
            .unwrap()
            .value;
        assert_eq!(first as usize, BYTES - 10);
        assert_eq!(
            a.execute(client, Op::Write(vec![42; 100])).unwrap().value,
            10
        );
        assert_eq!(
            a.execute(client, Op::Write(vec![42; 1])).unwrap_err(),
            EAGAIN
        );
        assert_eq!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
        pump(&mut a, &mut b);
    }
}
