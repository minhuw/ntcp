// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use crate::*;
use ntcp::{
    AddressValidation, CloseReason, ConnectionId, Endpoint, EndpointConfig, EndpointError, Error,
    Event, ListenerId, State,
};
use ntcp_io::{PacketIo, TxOutcome};
use ntcp_io_tun::Tun;
use std::{
    collections::{BTreeMap, VecDeque},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::mpsc::{self, Receiver, SyncSender},
    time::Instant,
};

#[cfg(feature = "packet-test")]
use std::time::{SystemTime, UNIX_EPOCH};

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
    Wait(Box<Op>, Option<std::time::Duration>),
    FinishConnect,
    #[cfg(all(test, feature = "packet-test"))]
    BlockingConnect(SocketAddr),
    Bind(SocketAddr),
    Listen(i32),
    Accept(i32),
    Connect(SocketAddr),
    Read(usize),
    ReadTo(usize, i32, Vec<(usize, usize)>, Vec<(usize, Vec<u8>)>),
    Peek(usize),
    SetTimeout(bool, u64),
    GetTimeout(bool),
    #[cfg(test)]
    Write(Vec<u8>),
    #[cfg(all(test, feature = "packet-test"))]
    WriteFlags(Vec<u8>, i32),
    Send(Vec<(usize, usize)>, i32),
    ErrorQueueTo(usize),
    Transport(i32),
    #[cfg(feature = "packet-test")]
    Inject(Vec<u8>),
    #[cfg(feature = "packet-test")]
    Capture(usize),
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
    #[cfg(feature = "packet-test")]
    pub stamp: i64,
}
struct Request {
    id: u64,
    op: Op,
    reply: SyncSender<Result<Reply>>,
    deadline: Option<Instant>,
}
pub struct Runtime {
    tx: SyncSender<Request>,
    pub wake: i32,
    pub family: i32,
    pub io_limit: usize,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
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
            io_limit: BYTES,
            stop: Default::default(),
            worker: Mutex::new(None),
        }
    }

    pub fn start() -> Result<Self> {
        let name = env("NTCP_SOCKET_TUN").ok_or(EINVAL)?;
        let local: Ipv4Addr = env("NTCP_SOCKET_ADDR")
            .ok_or(EINVAL)?
            .parse()
            .map_err(|_| EAFNOSUPPORT)?;
        Self::spawn(move || Owner::new(&name, local), false)
    }
    #[cfg(feature = "packet-test")]
    pub fn packet(settings: (Ipv4Addr, crate::packet_profile::Profile)) -> Result<Self> {
        Self::spawn(move || Owner::packet(settings), true)
    }
    fn spawn(
        start: impl FnOnce() -> Result<Owner> + Send + 'static + std::panic::UnwindSafe,
        packet: bool,
    ) -> Result<Self> {
        let wake = unsafe { syscall(SYS_eventfd2, 0, EFD_NONBLOCK | EFD_CLOEXEC) as i32 };
        if wake < 0 {
            return Err(errno());
        }
        let (tx, rx) = mpsc::sync_channel(if packet { 128 } else { LIMIT });
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopping = stop.clone();
        let spawned = std::thread::Builder::new()
            .name("ntcp-socket".into())
            .spawn(move || {
                set_internal(true);
                let result = std::panic::catch_unwind(|| match start() {
                    Ok(mut owner) => {
                        let _ = ready_tx.send(Ok(()));
                        owner.run(rx, wake, &stopping);
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                    }
                });
                // Dropping rx and all requests wakes callers on panic/failure.
                #[cfg(feature = "packet-test")]
                if packet && result.is_err() {
                    crate::packet_profile::diagnostic(
                        "FAILURE",
                        "shared socket owner panicked; adapter stopped",
                    );
                }
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
            io_limit: if packet { 65535 } else { BYTES },
            stop,
            worker: Mutex::new(Some(worker)),
        })
    }
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        signal(self.wake);
        if let Ok(mut worker) = self.worker.lock()
            && let Some(worker) = worker.take()
        {
            let _ = worker.join();
        }
    }
    pub fn call(&self, id: u64, op: Op) -> Result<Reply> {
        if self.stop.load(Ordering::Acquire) {
            return Err(ECANCELED);
        }
        let (reply, rx) = mpsc::sync_channel(1);
        let closing = matches!(op, Op::Close);
        let deadline = if let Op::Wait(_, Some(duration)) = &op {
            Instant::now().checked_add(*duration)
        } else {
            None
        };
        let request = Request {
            id,
            op,
            reply,
            deadline,
        };
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
impl Drop for Runtime {
    fn drop(&mut self) {
        self.stop();
        unsafe {
            syscall(SYS_close, self.wake);
        }
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
    user_timeout_ms: i32,
    tos: u8,
    discover: i32,
    zerocopy: bool,
    zc_next: u32,
    completions: VecDeque<(u32, u32)>,
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
            user_timeout_ms: 0,
            tos: 0,
            discover: IP_PMTUDISC_WANT,
            zerocopy: false,
            zc_next: 0,
            completions: VecDeque::new(),
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
fn user_timeout_us(milliseconds: i32) -> Result<Option<u64>> {
    let ms = u64::try_from(milliseconds).map_err(|_| EINVAL)?;
    Ok((ms != 0).then_some(ms * 1000))
}
// SPDX-License-Identifier: GPL-2.0-or-later (ported copied-completion accounting)
fn extends_completion(range: (u32, u32), next: u32) -> bool {
    range.1.wrapping_add(1) == next && u64::from(range.1.wrapping_sub(range.0)) + 2 < (1u64 << 32)
}
pub(crate) fn unsupported_option(reason: &str) -> i32 {
    #[cfg(feature = "packet-test")]
    return crate::packet_profile::unsupported(reason);
    #[cfg(not(feature = "packet-test"))]
    {
        let _ = reason;
        EOPNOTSUPP
    }
}
#[cfg(feature = "packet-test")]
struct PacketBackend {
    profile: crate::packet_profile::Profile,
    output: VecDeque<Reply>,
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
    pending: VecDeque<Request>,
    child_timeouts: Vec<(ConnectionId, u64, u64, u64)>,
    connection_options: Vec<(ConnectionId, u8, i32, Option<bool>)>,
    #[cfg(feature = "packet-test")]
    packets: Option<PacketBackend>,
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
            pending: VecDeque::new(),
            child_timeouts: Vec::new(),
            connection_options: Vec::new(),
            #[cfg(feature = "packet-test")]
            packets: None,
        })
    }
    #[cfg(feature = "packet-test")]
    fn packet((local, profile): (Ipv4Addr, crate::packet_profile::Profile)) -> Result<Self> {
        // Deterministic key and synthetic address policy are explicit test-only
        // settings, never a production entropy source or TUN routing policy.
        let mut owner = Self::with_endpoint(local, (local, 32), [42; 32], None)?;
        owner.endpoint = Endpoint::new(
            crate::packet_profile::config(profile),
            [42; 32],
            0,
            move |r| match r {
                AddressValidation::Bind { local: addr } => {
                    addr.is_unspecified() || addr == IpAddr::V4(local)
                }
                AddressValidation::Open { local: addr, .. } => addr == IpAddr::V4(local),
                AddressValidation::Incoming { destination, .. } => destination == IpAddr::V4(local),
                AddressValidation::Route { .. } => false,
            },
        )
        .map_err(engine)?;
        owner.packets = Some(PacketBackend {
            profile,
            output: VecDeque::new(),
        });
        Ok(owner)
    }
    fn socket_limit(&self) -> usize {
        #[cfg(feature = "packet-test")]
        if self.packets.is_some() {
            return crate::packet_profile::LIMIT;
        }
        LIMIT
    }
    fn fresh_socket(&self, flags: i32) -> Socket {
        #[cfg(feature = "packet-test")]
        if let Some(packets) = &self.packets {
            let mut socket = Socket::new(flags);
            let config = crate::packet_profile::config(packets.profile);
            socket.receive_capacity = config.connection.receive_capacity;
            socket.send_capacity = config.connection.send_capacity;
            return socket;
        }
        Socket::new(flags)
    }
    fn batch_time(&self) -> Option<u64> {
        #[cfg(feature = "packet-test")]
        if self
            .packets
            .as_ref()
            .is_some_and(|p| p.profile == crate::packet_profile::Profile::UpstreamCubic)
        {
            return Some(self.now());
        }
        None
    }
    fn frame(&self, tx: ntcp::Transmit, tcp: &[u8]) -> Result<Vec<u8>> {
        let mut packet = vec![0; 20 + tcp.len()];
        packet[20..].copy_from_slice(tcp);
        let n = ntcp_ip::encode(&mut packet, tx, (self.now() / 1000) as u32).map_err(|_| EIO)?;
        packet.truncate(n);
        if tx
            .connection
            .and_then(|cid| self.connection_options.iter().find(|p| p.0 == cid))
            .is_some_and(|p| p.2 == IP_PMTUDISC_DONT)
        {
            packet[6] = 0;
            packet[10..12].fill(0);
            let checksum = ntcp_ip::checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        Ok(packet)
    }
    fn now(&self) -> u64 {
        self.epoch.elapsed().as_micros().min(u64::MAX as u128) as u64
    }
    fn packet_wait(&self, op: &Op) -> bool {
        #[cfg(feature = "packet-test")]
        if matches!(op, Op::Wait(op, _) if matches!(**op, Op::Capture(_))) {
            return true;
        }
        let _ = op;
        false
    }
    fn service(&mut self, request: &Request) -> bool {
        let (op, wait) = if let Op::Wait(op, _) = &request.op {
            ((**op).clone(), true)
        } else {
            (request.op.clone(), false)
        };
        let result = self.execute(request.id, op);
        if matches!(result, Err(EAGAIN))
            && wait
            && (self
                .sockets
                .get(&request.id)
                .is_some_and(|s| s.flags & SOCK_NONBLOCK == 0)
                || self.packet_wait(&request.op))
            && request
                .deadline
                .is_none_or(|deadline| Instant::now() < deadline)
        {
            return false;
        }
        let _ = request.reply.send(result);
        true
    }
    fn run(&mut self, rx: Receiver<Request>, wake: i32, stop: &std::sync::atomic::AtomicBool) {
        let mut input = vec![0; 65535];
        while !stop.load(Ordering::Acquire) {
            let now = self.now();
            if self.endpoint.on_timeout(now, BUDGET).is_err() {
                break;
            }
            for _ in 0..BUDGET {
                match self
                    .tun
                    .as_mut()
                    .map(|tun| tun.receive(&mut input))
                    .unwrap_or(Ok(None))
                {
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
            let mut after_output = Vec::with_capacity(BUDGET);
            for _ in 0..self.pending.len().min(BUDGET) {
                let request = self.pending.pop_front().unwrap();
                let early = matches!(&request.op, Op::Wait(op, _) if matches!(**op, Op::Read(_) | Op::Peek(_) | Op::ReadTo(..)))
                    && self.sockets.get(&request.id).is_some_and(|s| s.error == 0);
                if !early || !self.service(&request) {
                    after_output.push((request, early));
                }
            }
            let transmit_now = self.batch_time();
            for _ in 0..BUDGET {
                if self.pending_packet.is_none() {
                    #[cfg(feature = "packet-test")]
                    if self
                        .packets
                        .as_ref()
                        .is_some_and(|p| p.output.len() == crate::packet_profile::LIMIT)
                    {
                        break;
                    }
                    let mut packet = vec![0; if self.tun.is_some() { 1500 } else { 65535 }];
                    let transmit = match self.endpoint.poll_transmit(
                        transmit_now.unwrap_or_else(|| self.now()),
                        &mut packet[20..],
                        BUDGET,
                    ) {
                        Ok(tx) => tx.packet,
                        Err(_) => return,
                    };
                    let Some(tx) = transmit else {
                        break;
                    };
                    packet = match self.frame(tx, &packet[20..20 + tx.len]) {
                        Ok(packet) => packet,
                        Err(_) => return,
                    };
                    self.pending_packet = Some(packet);
                }
                // Never poll another TCP segment until this complete packet is submitted.
                if let Some(tun) = self.tun.as_mut() {
                    match tun.transmit(self.pending_packet.as_ref().unwrap()) {
                        Ok(TxOutcome::Submitted) => self.pending_packet = None,
                        Ok(TxOutcome::WouldBlock) => break,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => break,
                        Err(_) => return,
                    }
                }
                #[cfg(feature = "packet-test")]
                if let Some(packets) = self.packets.as_mut() {
                    let bytes = self.pending_packet.take().unwrap();
                    packets.output.push_back(Reply {
                        value: bytes.len() as i32,
                        bytes,
                        stamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_micros() as i64,
                        ..Reply::default()
                    });
                }
            }
            self.events();
            for (request, retried) in after_output {
                if retried || !self.service(&request) {
                    self.pending.push_back(request);
                }
            }
            self.connection_options
                .retain(|p| self.endpoint.connection_exists(p.0));
            self.detached.retain(|&id| {
                if matches!(self.endpoint.state(id), Ok(State::Closed | State::TimeWait)) {
                    let _ = self.endpoint.release(id);
                    false
                } else {
                    true
                }
            });
            // Bounded owner work and a 1ms ceiling also cover shared wakefd consumers.
            let wait = self
                .endpoint
                .next_deadline()
                .map(|d| std::time::Duration::from_micros(d.saturating_sub(self.now())))
                .unwrap_or(std::time::Duration::from_millis(1))
                .min(std::time::Duration::from_millis(1));
            match rx.recv_timeout(wait) {
                Ok(r) => {
                    if self.pending.len() == self.socket_limit() && !matches!(r.op, Op::Close) {
                        let _ = r.reply.send(Err(EAGAIN));
                    } else if !self.service(&r) {
                        self.pending.push_back(r);
                    }
                    #[cfg(feature = "packet-test")]
                    let requests = if self.packets.is_some() { 1 } else { BUDGET };
                    #[cfg(not(feature = "packet-test"))]
                    let requests = BUDGET;
                    for _ in 1..requests {
                        let Ok(r) = rx.try_recv() else {
                            break;
                        };
                        if self.pending.len() == self.socket_limit() && !matches!(r.op, Op::Close) {
                            let _ = r.reply.send(Err(EAGAIN));
                        } else if !self.service(&r) {
                            self.pending.push_back(r);
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => (),
            }
            signal(wake);
        }
        for request in self.pending.drain(..) {
            let _ = request.reply.send(Err(ECANCELED));
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
        let listener_options = tuple.and_then(|tuple| {
            self.sockets
                .values()
                .find(|s| {
                    matches!(s.handle, Handle::Listener(_))
                        && s.local.is_some_and(|local| {
                            local.port() == tuple.local.port()
                                && (local.ip().is_unspecified() || local == tuple.local)
                        })
                })
                .map(|s| (s.tos, s.discover, s.zerocopy))
        });
        // Reserve only for checked passive SYNs: LISTEN ACKs need stateless
        // resets, and existing TIME-WAIT traffic still needs core processing.
        // TIME-WAIT reopening accepts only a pure SYN (plus ECN), no payload.
        if listener_options.is_some()
            && before
                .is_none_or(|id| matches!(self.endpoint.state(id), Ok(State::TimeWait) | Err(_)))
            && ntcp::wire::parse(ip, bytes).is_ok_and(|segment| {
                let flags = segment.header.flags;
                flags & (ntcp::wire::SYN | ntcp::wire::ACK | ntcp::wire::RST) == ntcp::wire::SYN
                    && (before.is_none()
                        || (flags & !(ntcp::wire::ECE | ntcp::wire::CWR) == ntcp::wire::SYN
                            && segment.payload.is_empty()))
            })
        {
            self.connection_options
                .retain(|p| self.endpoint.connection_exists(p.0));
            if self.connection_options.len() == self.socket_limit() {
                return Err(EndpointError::LimitReached);
            }
        }

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
        if let Some(tuple) = tuple
            && let Some(cid) = self.endpoint.connection_id(tuple)
        {
            if Some(cid) != before
                && let Some((tos, discover, _)) = listener_options
            {
                self.endpoint.set_dscp(cid, tos >> 2)?;
                self.connection_options.push((cid, tos, discover, None));
            }
            if matches!(
                self.endpoint.state(cid),
                Ok(State::Established | State::CloseWait)
            ) && let Some(p) = self.connection_options.iter_mut().find(|p| p.0 == cid)
                && p.3.is_none()
            {
                p.3 = listener_options.map(|p| p.2);
            }
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
        if self.sockets.len() == self.socket_limit() || self.next_id > i32::MAX as u64 {
            return Err(EMFILE);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.sockets.insert(id, s);
        Ok(id as i32)
    }
    fn port(&mut self) -> Result<u16> {
        #[cfg(feature = "packet-test")]
        if self.packets.is_some() && self.next_port >= 60000 {
            return Err(EADDRNOTAVAIL);
        }
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
        self.endpoint
            .set_application_timeout(cid, user_timeout_us(s.user_timeout_ms)?)
            .map_err(engine)?;
        self.endpoint.set_dscp(cid, s.tos >> 2).map_err(engine)?;
        self.endpoint.set_nagle(cid, !s.nodelay).map_err(engine)
    }
    fn rollback_connection(&mut self, cid: ConnectionId) {
        // release retains storage until any reset output has drained.
        let _ = self.endpoint.abort(cid);
        let _ = self.endpoint.release(cid);
    }
    fn send_state(&mut self, id: u64) -> Result<ConnectionId> {
        let s = self.sockets.get_mut(&id).ok_or(EBADF)?;
        let Handle::Connection(cid) = s.handle else {
            return Err(ENOTCONN);
        };
        if s.error != 0 {
            let e = s.error;
            s.error = 0;
            return Err(e);
        }
        let state = self.endpoint.state(cid).map_err(engine)?;
        if s.write_shutdown || matches!(state, State::Closed | State::TimeWait) {
            return Err(EPIPE);
        }
        if matches!(state, State::SynSent | State::SynReceived) {
            return Err(EAGAIN);
        }
        Ok(cid)
    }
    fn reserve_completion(&mut self, id: u64, nonempty: bool, flags: i32) -> Result<bool> {
        let limit = self.socket_limit();
        let s = self.sockets.get_mut(&id).ok_or(EBADF)?;
        let completion = nonempty && s.zerocopy && flags & MSG_ZEROCOPY != 0;
        if completion
            && !s
                .completions
                .back()
                .is_some_and(|&p| extends_completion(p, s.zc_next))
        {
            if s.completions.len() == limit {
                return Err(ENOBUFS);
            }
            s.completions.try_reserve(1).map_err(|_| ENOBUFS)?;
        }
        Ok(completion)
    }
    fn write(&mut self, id: u64, bytes: Vec<u8>, flags: i32) -> Result<i32> {
        let cid = self.send_state(id)?;
        if bytes.is_empty() {
            return Ok(0);
        }
        let completion = self.reserve_completion(id, true, flags)?;
        let s = self.sockets.get_mut(&id).unwrap();
        let n = self.endpoint.write(cid, &bytes).map_err(engine)?;
        if n != 0 && completion {
            let next = s.zc_next;
            if let Some(tail) = s.completions.back_mut()
                && extends_completion(*tail, next)
            {
                tail.1 = next;
            } else {
                s.completions.push_back((next, next));
            }
            s.zc_next = next.wrapping_add(1);
        }
        Ok(n as i32)
    }
    fn execute(&mut self, id: u64, op: Op) -> Result<Reply> {
        self.endpoint.on_timeout(self.now(), 0).map_err(engine)?;
        self.dispatch(id, op)
    }
    fn dispatch(&mut self, id: u64, op: Op) -> Result<Reply> {
        self.prune_child_timeouts();
        let mut out = Reply::default();
        #[cfg(feature = "packet-test")]
        match &op {
            Op::Inject(bytes) => {
                if self.packets.is_none() {
                    return Err(EOPNOTSUPP);
                }
                let packet = crate::packet_profile::parse_frame(bytes)?;
                self.input(self.now(), packet.ip, packet.traffic_class, packet.payload)
                    .map_err(engine)?;
                self.events();
                return Ok(out);
            }
            Op::Capture(capacity) => {
                let packets = self.packets.as_mut().ok_or(EOPNOTSUPP)?;
                let front = packets.output.front().ok_or(EAGAIN)?;
                if front.bytes.len() > *capacity {
                    return Err(EMSGSIZE);
                }
                return Ok(packets.output.pop_front().unwrap());
            }
            _ => (),
        }
        self.events();
        if let Op::New(flags) = op {
            out.value = self.alloc(self.fresh_socket(flags))?;
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
                let application_timeout = user_timeout_us(s.user_timeout_ms)?;
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
                if let Err(e) = self
                    .endpoint
                    .set_listener_application_timeout(listener, application_timeout)
                {
                    let _ = self.endpoint.close_listener(listener);
                    return Err(engine(e));
                }
                let s = self.sockets.get_mut(&id).unwrap();
                s.local = Some(local);
                s.handle = Handle::Listener(listener);
            }
            Op::Accept(flags) => {
                if self.sockets.len() == self.socket_limit() {
                    return Err(EMFILE);
                }
                let Handle::Listener(listener) = s.handle else {
                    return Err(EINVAL);
                };
                let mut child = self.fresh_socket(flags);
                child.reuse = s.reuse;
                child.nodelay = s.nodelay;
                child.keepalive = s.keepalive;
                child.idle = s.idle;
                child.interval = s.interval;
                child.probes = s.probes;
                child.user_timeout_ms = s.user_timeout_ms;
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
                child.user_timeout_ms = self
                    .endpoint
                    .application_timeout(cid)
                    .map_err(engine)?
                    .map_or(0, |us| (us / 1000) as i32);
                if let Some(p) = self.connection_options.iter().find(|p| p.0 == cid) {
                    child.tos = p.1;
                    child.discover = p.2;
                    child.zerocopy = p.3.unwrap_or(false);
                }
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
                self.connection_options
                    .retain(|p| self.endpoint.connection_exists(p.0));
                if self.connection_options.len() == self.socket_limit() {
                    return Err(ENOBUFS);
                }
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
                self.connection_options.push((
                    cid,
                    options.tos,
                    options.discover,
                    Some(options.zerocopy),
                ));
                let s = self.sockets.get_mut(&id).unwrap();
                s.handle = Handle::Connection(cid);
                s.local = Some(local);
                return Err(EINPROGRESS);
            }
            Op::Read(capacity) | Op::Peek(capacity) | Op::ReadTo(capacity, _, _, _) => {
                let foreign = matches!(op, Op::ReadTo(..));
                let peek = matches!(op, Op::Peek(_) | Op::ReadTo(..));
                let Handle::Connection(cid) = s.handle else {
                    return Err(ENOTCONN);
                };
                if capacity == 0 {
                    if let Op::ReadTo(_, _, _, copies) = &op {
                        for (address, bytes) in copies {
                            copy_out(*address as *mut u8, bytes)?;
                        }
                    }
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
                if terminal && !s.connected {
                    return Err(ENOTCONN);
                }
                out.bytes.resize(capacity.min(BYTES), 0);
                let n = if available == 0 && s.read_shutdown {
                    out.bytes.clear();
                    if let Op::ReadTo(_, _, _, copies) = &op {
                        for (address, bytes) in copies {
                            copy_out(*address as *mut u8, bytes)?;
                        }
                    }
                    return Ok(out);
                } else if peek && terminal {
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
                if foreign && let Op::ReadTo(_, flags, destinations, copies) = op {
                    let mut at = 0;
                    for (address, capacity) in destinations {
                        let count = capacity.min(n - at);
                        copy_out(address as *mut u8, &out.bytes[at..at + count])?;
                        at += count;
                        if at == n {
                            break;
                        }
                    }
                    if at != n {
                        return Err(EIO);
                    }
                    for (address, bytes) in copies {
                        copy_out(address as *mut u8, &bytes)?;
                    }
                    if flags & MSG_PEEK == 0 && n != 0 {
                        let consumed = if terminal {
                            self.endpoint.read_terminal(cid, &mut out.bytes)
                        } else {
                            self.endpoint.read(cid, &mut out.bytes)
                        }
                        .map_err(engine)?;
                        if consumed != n {
                            return Err(EIO);
                        }
                    }
                    out.bytes.clear();
                }
            }
            #[cfg(test)]
            Op::Write(bytes) => {
                out.value = self.write(id, bytes, 0)?;
            }
            #[cfg(all(test, feature = "packet-test"))]
            Op::WriteFlags(bytes, flags) => {
                out.value = self.write(id, bytes, flags)?;
            }
            Op::Send(sources, flags) => {
                // Connected/terminal errors precede payload faults. Fresh and
                // listening fds retain the adapter's foreign-input validation.
                let connection = matches!(s.handle, Handle::Connection(_));
                if connection {
                    self.send_state(id)?;
                }
                let total = sources
                    .iter()
                    .try_fold(0usize, |n, p| n.checked_add(p.1).ok_or(EINVAL))?;
                if total > BYTES {
                    return Err(EMSGSIZE);
                }
                if connection {
                    self.reserve_completion(id, total != 0, flags)?;
                }
                let mut bytes = vec![0; total];
                let mut at = 0;
                for (address, len) in sources {
                    memory(bytes[at..].as_mut_ptr(), address as *mut u8, len, false)?;
                    at += len;
                }
                out.value = self.write(id, bytes, flags)?;
            }
            Op::ErrorQueueTo(address) => {
                let completion = *s.completions.front().ok_or(EAGAIN)?;
                let p = address as *mut msghdr;
                copy_completion(p, load(p)?, completion)?;
                self.sockets.get_mut(&id).unwrap().completions.pop_front();
            }
            Op::Transport(option) => {
                let Handle::Connection(cid) = s.handle else {
                    return Err(ENOTCONN);
                };
                out.bytes = crate::transport::transport_option(
                    self.endpoint.transport_info(cid).map_err(engine)?,
                    option,
                )?;
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
                        debug_assert!(self.detached.len() < LIMIT);
                        self.detached.push(cid);
                    }
                }
                self.child_timeouts
                    .retain(|(_, listener, _, _)| *listener != id);
                self.pending.retain(|request| {
                    if request.id == id {
                        let _ = request.reply.send(Err(EBADF));
                        false
                    } else {
                        true
                    }
                });
                self.sockets.remove(&id);
            }
            Op::Shutdown(how) => {
                let Handle::Connection(cid) = s.handle else {
                    return Err(ENOTCONN);
                };
                if matches!(
                    self.endpoint.state(cid),
                    Ok(State::Closed | State::TimeWait)
                ) {
                    return Err(ENOTCONN);
                }
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
                            #[cfg(feature = "packet-test")]
                            if self.packets.is_some() {
                                return Err(unsupported_option("fcntl status flags"));
                            }
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
                    (SOL_SOCKET, SO_ZEROCOPY) => {
                        if !(0..=1).contains(&value) {
                            return Err(EINVAL);
                        }
                        s.zerocopy = value != 0;
                    }
                    (IPPROTO_IP, IP_TOS) => s.tos = value as u8 & !3,
                    (IPPROTO_IP, IP_MTU_DISCOVER) => {
                        match value {
                            IP_PMTUDISC_DONT | IP_PMTUDISC_WANT | IP_PMTUDISC_DO => (),
                            3..=5 => {
                                return Err(unsupported_option(
                                    "IP_MTU_DISCOVER: PROBE/INTERFACE/OMIT require route features",
                                ));
                            }
                            _ => return Err(EINVAL),
                        }
                        s.discover = value;
                    }
                    (IPPROTO_TCP, TCP_USER_TIMEOUT) => {
                        user_timeout_us(value)?;
                        s.user_timeout_ms = value;
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
                    _ => {
                        #[cfg(feature = "packet-test")]
                        if self.packets.is_some() {
                            return Err(unsupported_option("socket option"));
                        }
                        return Err(ENOPROTOOPT);
                    }
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
                if let Handle::Connection(cid) = s.handle
                    && let Some(p) = self.connection_options.iter_mut().find(|p| p.0 == cid)
                {
                    p.1 = s.tos;
                    p.2 = s.discover;
                }
                if let Handle::Listener(listener) = s.handle {
                    self.endpoint
                        .set_listener_application_timeout(
                            listener,
                            user_timeout_us(s.user_timeout_ms)?,
                        )
                        .map_err(engine)?;
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
                    (IPPROTO_TCP, TCP_USER_TIMEOUT) => s.user_timeout_ms,
                    (IPPROTO_IP, IP_TOS) => s.tos as i32,
                    (IPPROTO_IP, IP_MTU_DISCOVER) => s.discover,
                    (SOL_SOCKET, SO_ZEROCOPY) => s.zerocopy as i32,
                    (IPPROTO_TCP, TCP_KEEPIDLE) => s.idle,
                    (IPPROTO_TCP, TCP_KEEPINTVL) => s.interval,
                    (IPPROTO_TCP, TCP_KEEPCNT) => s.probes,
                    _ => {
                        #[cfg(feature = "packet-test")]
                        if self.packets.is_some() {
                            return Err(unsupported_option("socket option"));
                        }
                        return Err(ENOPROTOOPT);
                    }
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
                        if self.endpoint.state(cid).map_err(engine)? == State::Closed {
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
                if s.error != 0 || !s.completions.is_empty() {
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
                        let readable = if state == State::Closed {
                            self.endpoint.terminal_readable_bytes(cid)
                        } else {
                            self.endpoint.readable_bytes(cid)
                        }
                        .map_err(engine)?;
                        if readable != 0 || eof || s.read_shutdown {
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
                        if state == State::Closed || (s.write_shutdown && (eof || s.read_shutdown))
                        {
                            out.value |= EPOLLHUP;
                        }
                    }
                }
            }
            #[cfg(all(test, feature = "packet-test"))]
            Op::BlockingConnect(remote) => {
                if matches!(s.handle, Handle::Fresh) {
                    match self.dispatch(id, Op::Connect(remote)) {
                        Err(EINPROGRESS) => return Err(EAGAIN),
                        other => return other,
                    }
                }
                return self.dispatch(id, Op::FinishConnect);
            }
            Op::FinishConnect => {
                let Handle::Connection(cid) = s.handle else {
                    return Err(ENOTCONN);
                };
                if s.error != 0 {
                    let s = self.sockets.get_mut(&id).unwrap();
                    let e = s.error;
                    s.error = 0;
                    return Err(e);
                }
                match self.endpoint.state(cid).map_err(engine)? {
                    State::Established | State::CloseWait => (),
                    State::Closed => return Err(ECONNREFUSED),
                    _ => return Err(EAGAIN),
                }
            }
            Op::Wait(_, _) => unreachable!(),
            Op::New(_) => unreachable!(),
            #[cfg(feature = "packet-test")]
            Op::Inject(_) | Op::Capture(_) => unreachable!(),
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
    fn finish_connect_after_handshake_and_immediate_fin() {
        let (mut a, mut b, _, _, listen) = pair();
        let client = new(&mut a, 0);
        assert_eq!(
            a.execute(client, Op::Connect("10.73.0.3:16379".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        let (reply, completed) = mpsc::sync_channel(1);
        let request = Request {
            id: client,
            op: Op::Wait(Box::new(Op::FinishConnect), None),
            reply,
            deadline: None,
        };
        assert!(!a.service(&request));
        pump(&mut a, &mut b);
        let server = b.execute(listen, Op::Accept(0)).unwrap().value as u64;
        b.execute(server, Op::Shutdown(SHUT_WR)).unwrap();
        pump(&mut a, &mut b);
        let Handle::Connection(cid) = a.sockets[&client].handle else {
            panic!()
        };
        assert_eq!(a.endpoint.state(cid), Ok(State::CloseWait));
        assert_eq!(a.execute(client, Op::FinishConnect).unwrap().value, 0);
        // The libc blocking connect retry and owner pending-request service
        // share FinishConnect; neither may keep waiting after the peer's FIN.
        assert!(a.service(&request));
        assert_eq!(completed.try_recv().unwrap().unwrap().value, 0);
        assert_eq!(a.execute(client, Op::Read(8)).unwrap().value, 0);
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
                deadline: None,
            })
            .unwrap();
        }
        let runtime = Runtime {
            tx,
            wake: -1,
            family: AF_INET,
            io_limit: BYTES,
            stop: Default::default(),
            worker: Mutex::new(None),
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
        a.endpoint
            .connect_with_buffer_capacities(
                a.now(),
                "10.73.0.2:25000".parse().unwrap(),
                "10.73.0.3:25000".parse().unwrap(),
                2 * BUFFER_REQUEST_CAP as usize,
                BYTES,
            )
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

#[cfg(all(test, feature = "packet-test"))]
#[path = "packet_tests.rs"]
mod packet_tests;
