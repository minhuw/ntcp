// SPDX-License-Identifier: GPL-2.0-or-later
use libc::*;
use ntcp::{
    CloseReason, ConnectionId, Endpoint, EndpointConfig, EndpointError, Error, Event, IpMetadata,
    ListenerId, State,
};
use std::{
    collections::{BTreeMap, VecDeque},
    ffi::CStr,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const LIMIT: usize = 128;
const BYTES: usize = 65535;
const BUDGET: usize = 32;
type Result<T> = std::result::Result<T, i32>;
struct Request {
    op: i32,
    fd: i32,
    a: i32,
    b: i32,
    bytes: Vec<u8>,
    capacity: usize,
    deadline: Option<Instant>,
    started: bool,
    reply: SyncSender<Result<Response>>,
}
#[derive(Default)]
struct Response {
    value: i64,
    bytes: Vec<u8>,
    stamp: i64,
}
struct Adapter {
    tx: SyncSender<Request>,
    stop: std::sync::Arc<AtomicBool>,
    failed: AtomicBool,
    join: Option<JoinHandle<()>>,
}
#[derive(Clone, Copy)]
enum Handle {
    Fresh,
    Listener(ListenerId),
    Connection(ConnectionId),
}
// Stock packetdrill owns the exposed descriptor until explicit plugin close or
// close_all_fds. Keep a duplicate alive so the AF_UNIX socket inode cannot be
// recycled before we check identity. These sockets never carry TCP traffic.
struct Token {
    fd: i32,
    retained: OwnedFd,
}
impl Token {
    fn new() -> Result<Self> {
        Self::with_duplicate(|fd| unsafe { fcntl(fd, F_DUPFD_CLOEXEC, 0) })
    }
    fn with_duplicate(duplicate: impl FnOnce(i32) -> i32) -> Result<Self> {
        let fd = unsafe { libc::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(EIO));
        }
        let exposed = unsafe { OwnedFd::from_raw_fd(fd) };
        let retained = duplicate(fd);
        if retained < 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(EIO));
        }
        Ok(Self {
            fd: exposed.into_raw_fd(),
            retained: unsafe { OwnedFd::from_raw_fd(retained) },
        })
    }
}
impl Drop for Token {
    fn drop(&mut self) {
        // This check/close is NOT atomic against arbitrary host fd mutation.
        // Pinned runner serializes explicit closes on its syscall thread and
        // stops that thread before host close_all_fds; adapterDrop follows host
        // cleanup. The owner never allocates/closes tokens for netdev callbacks.
        // Thus no host close/reuse races this cleanup under that runner contract.
        let mut live: stat = unsafe { std::mem::zeroed() };
        let mut retained: stat = unsafe { std::mem::zeroed() };
        unsafe {
            if fstat(self.fd, &mut live) == 0
                && fstat(self.retained.as_raw_fd(), &mut retained) == 0
                && live.st_dev == retained.st_dev
                && live.st_ino == retained.st_ino
                && live.st_mode == retained.st_mode
            {
                libc::close(self.fd);
            }
        }
    }
}
struct Socket {
    token: Option<Token>,
    handle: Handle,
    local: Option<SocketAddr>,
    nonblock: bool,
    cloexec: bool,
    reuse: bool,
    nodelay: bool,
    user_timeout_ms: i32,
    readable: Option<bool>,
    acceptable: Option<bool>,
    error: i32,
    written: u64,
    write_shutdown: bool,
    connected: bool,
}
impl Socket {
    fn new(flags: i32) -> Self {
        Self {
            token: None,
            handle: Handle::Fresh,
            local: None,
            nonblock: flags & SOCK_NONBLOCK != 0,
            cloexec: flags & SOCK_CLOEXEC != 0,
            reuse: false,
            nodelay: false,
            user_timeout_ms: 0,
            readable: Some(false),
            acceptable: Some(false),
            error: 0,
            written: 0,
            write_shutdown: false,
            connected: false,
        }
    }
}
fn user_timeout_us(milliseconds: i32) -> Result<Option<u64>> {
    let ms = u64::try_from(milliseconds).map_err(|_| EINVAL)?;
    Ok((ms != 0).then_some(ms * 1000))
}
struct Owner {
    endpoint: Endpoint,
    sockets: BTreeMap<i32, Socket>,
    next_port: u32,
    local: Ipv4Addr,
    epoch: Instant,
    output: VecDeque<Response>,
    pending: VecDeque<Request>,
    detached: VecDeque<ConnectionId>,
}
fn diagnostic(kind: &str, reason: &str) {
    let message = format!("NTCP_PACKETDRILL_{kind}: {reason}\n");
    // One bounded write keeps diagnostics intact alongside the C callbacks.
    unsafe {
        libc::write(STDERR_FILENO, message.as_ptr().cast(), message.len());
    }
}
fn unsupported(reason: &str) -> i32 {
    diagnostic("UNSUPPORTED", reason);
    ENOSYS
}
fn error(e: EndpointError) -> i32 {
    match e {
        EndpointError::Connection(Error::WouldBlock) => EAGAIN,
        EndpointError::AddressInUse => EADDRINUSE,
        EndpointError::LimitReached => ENOBUFS,
        EndpointError::InvalidHandle => EBADF,
        EndpointError::Connection(Error::NoMemory) => ENOMEM,
        EndpointError::Connection(Error::InvalidState) => ENOTCONN,
        _ => EINVAL,
    }
}
fn reason(r: CloseReason) -> i32 {
    match r {
        CloseReason::Reset => ECONNRESET,
        CloseReason::TimedOut => ETIMEDOUT,
        CloseReason::Aborted => ECONNABORTED,
        CloseReason::NetworkError => EHOSTUNREACH,
        CloseReason::Normal => 0,
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    Baseline,
    UpstreamWindow8,
}
fn profile(flags: &str) -> Result<(Ipv4Addr, Profile)> {
    let mut local = None;
    let mut selected = None;
    for flag in flags.split(',') {
        if let Some(ip) = flag.strip_prefix("local=") {
            if local.is_some() {
                return Err(unsupported("duplicate local in so_flags"));
            }
            local = Some(
                ip.parse()
                    .map_err(|_| unsupported("invalid local IPv4 in so_flags"))?,
            );
        } else {
            let profile = match flag {
                "baseline" => Profile::Baseline,
                "upstream-window8" => Profile::UpstreamWindow8,
                _ => return Err(unsupported("unknown so_flags token")),
            };
            if selected.replace(profile).is_some() {
                return Err(unsupported("duplicate or conflicting profiles in so_flags"));
            }
        }
    }
    Ok((
        local.ok_or_else(|| unsupported("so_flags requires local=<IPv4>"))?,
        selected.ok_or_else(|| unsupported("so_flags requires exactly one profile"))?,
    ))
}
impl Adapter {
    fn start(settings: (Ipv4Addr, Profile)) -> Result<Self> {
        let (tx, rx) = mpsc::sync_channel(LIMIT);
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let join = thread::Builder::new()
            .name("ntcp-packetdrill".into())
            .spawn(move || {
                // Endpoint is deliberately constructed here: its policy closure is !Send.
                let result = catch_unwind(AssertUnwindSafe(|| match Owner::new(settings) {
                    Ok(mut owner) => {
                        let _ = ready_tx.send(Ok(()));
                        // Keep descriptor ownership alive even if the owner loop
                        // fails: stock host cleanup still precedes adapterDrop.
                        if catch_unwind(AssertUnwindSafe(|| owner.run(rx, &stopping))).is_err() {
                            diagnostic("FAILURE", "endpoint owner panicked; adapter stopped");
                        }
                        // Also cover non-panicking early error returns from run().
                        for request in owner.pending.drain(..) {
                            let _ = request.reply.send(Err(EIO));
                        }
                        while !stopping.load(Ordering::Acquire) {
                            thread::sleep(Duration::from_millis(1));
                        }
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                    }
                }));
                if result.is_err() {
                    diagnostic("FAILURE", "endpoint owner panicked; adapter stopped");
                }
            })
            .map_err(|_| EAGAIN)?;
        if let Err(e) = ready_rx.recv().unwrap_or(Err(EIO)) {
            let _ = join.join();
            return Err(e);
        }
        Ok(Self {
            tx,
            stop,
            failed: AtomicBool::new(false),
            join: Some(join),
        })
    }
    fn call(&self, mut request: Request) -> Result<Response> {
        if self.failed.load(Ordering::Acquire) {
            return Err(EIO);
        }
        let (tx, rx) = mpsc::sync_channel(1);
        request.reply = tx;
        match self.tx.try_send(request) {
            Ok(()) => (),
            Err(TrySendError::Full(_)) => return Err(EAGAIN),
            Err(TrySendError::Disconnected(_)) => return Err(EIO),
        }
        rx.recv().unwrap_or(Err(EIO))
    }
}
impl Drop for Adapter {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}
impl Owner {
    fn new((local, profile): (Ipv4Addr, Profile)) -> Result<Self> {
        let mut config = EndpointConfig {
            max_connections: LIMIT,
            max_listeners: LIMIT,
            max_control_packets: LIMIT,
            max_buffer_bytes: 32 * 1024 * 1024,
            ..EndpointConfig::default()
        };
        config.connection.receive_capacity = match profile {
            Profile::Baseline => 65535,
            // Real receive storage: 8 MiB requires scale 8, not 7 (65535 << 7).
            Profile::UpstreamWindow8 => 8 * 1024 * 1024,
        };
        config.connection.mss = 1460;
        config.connection.timestamps = false;
        config.connection.recovery_algorithm = ntcp::RecoveryAlgorithm::NewReno;
        config.connection.receive_ip_payload_limit = 65515;
        config.connection.send_ip_payload_limit = 65515;
        config.connection.ecn = false;
        // Test-only deterministic key and synthetic address domain, never a
        // production entropy source or routing policy. This crate is unpublished.
        let endpoint = Endpoint::new(config, [42; 32], 0, move |validation| match validation {
            ntcp::AddressValidation::Bind { local: addr } => {
                addr.is_unspecified() || addr == IpAddr::V4(local)
            }
            ntcp::AddressValidation::Open { local: addr, .. } => addr == IpAddr::V4(local),
            ntcp::AddressValidation::Incoming { destination, .. } => {
                destination == IpAddr::V4(local)
            }
            ntcp::AddressValidation::Route { .. } => false,
        })
        .map_err(error)?;
        Ok(Self {
            endpoint,
            sockets: BTreeMap::new(),
            next_port: 40000,
            local,
            epoch: Instant::now(),
            output: VecDeque::new(),
            pending: VecDeque::new(),
            detached: VecDeque::new(),
        })
    }
    fn now(&self) -> u64 {
        self.epoch.elapsed().as_micros() as u64
    }
    fn alloc(&mut self, socket: Socket) -> Result<i32> {
        if self.sockets.len() == LIMIT {
            return Err(EMFILE);
        }
        self.alloc_token(socket, Token::new()?)
    }
    fn alloc_token(&mut self, mut socket: Socket, token: Token) -> Result<i32> {
        if self.sockets.len() == LIMIT || self.sockets.contains_key(&token.fd) {
            return Err(EMFILE);
        }
        let fd = token.fd;
        socket.token = Some(token);
        self.sockets.insert(fd, socket);
        Ok(fd)
    }
    fn connection(&self, fd: i32) -> Result<ConnectionId> {
        match self.sockets.get(&fd).ok_or(EBADF)?.handle {
            Handle::Connection(id) => Ok(id),
            _ => Err(ENOTCONN),
        }
    }
    fn run(&mut self, rx: Receiver<Request>, stop: &AtomicBool) {
        while !stop.load(Ordering::Acquire) {
            let now = self.now();
            if self.endpoint.on_timeout(now, BUDGET).is_err() {
                diagnostic("FAILURE", "endpoint timeout processing failed");
                break;
            }
            self.events();
            for _ in 0..self.detached.len().min(BUDGET) {
                let id = self.detached.pop_front().unwrap();
                if matches!(self.endpoint.state(id), Ok(State::Closed | State::TimeWait)) {
                    let _ = self.endpoint.release(id);
                } else {
                    self.detached.push_back(id);
                }
            }
            for _ in 0..BUDGET {
                if self.output.len() == LIMIT || !self.endpoint.has_pending_output() {
                    break;
                }
                let mut buf = vec![0; BYTES - 20];
                match self.endpoint.poll_transmit(self.now(), &mut buf, BUDGET) {
                    Ok(p) => {
                        if let Some(p) = p.packet {
                            let stamp = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_micros() as i64;
                            buf.truncate(p.len);
                            match frame(p, &buf) {
                                Ok(bytes) => self.output.push_back(Response {
                                    value: bytes.len() as i64,
                                    bytes,
                                    stamp,
                                }),
                                Err(_) => {
                                    diagnostic("FAILURE", "could not frame generated packet");
                                    return;
                                }
                            }
                        } else {
                            break;
                        }
                    }
                    Err(_) => {
                        diagnostic("FAILURE", "endpoint transmit polling failed");
                        return;
                    }
                }
            }
            for _ in 0..self.pending.len().min(BUDGET) {
                let mut request = self.pending.pop_front().unwrap();
                match self.execute_at_now(&mut request) {
                    Ok(Some(response)) => {
                        let _ = request.reply.send(Ok(response));
                    }
                    Ok(None) => self.pending.push_back(request),
                    Err(e) => {
                        let _ = request.reply.send(Err(e));
                    }
                }
            }
            let wait = self
                .endpoint
                .next_deadline()
                .map(|d| Duration::from_micros(d.saturating_sub(self.now())))
                .unwrap_or(Duration::from_millis(1))
                .min(Duration::from_millis(1));
            match rx.recv_timeout(wait) {
                Ok(mut request) => {
                    // Reserve pending capacity before any operation with side effects.
                    if self.pending.len() == LIMIT {
                        let _ = request.reply.send(Err(EAGAIN));
                        continue;
                    }
                    match self.execute_at_now(&mut request) {
                        Ok(Some(response)) => {
                            let _ = request.reply.send(Ok(response));
                        }
                        Ok(None) => self.pending.push_back(request),
                        Err(e) => {
                            let _ = request.reply.send(Err(e));
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => (),
            }
        }
        for request in self.pending.drain(..) {
            let _ = request.reply.send(Err(ECANCELED));
        }
    }
    fn events(&mut self) {
        for _ in 0..BUDGET {
            let Some(event) = self.endpoint.next_event() else {
                break;
            };
            for socket in self.sockets.values_mut() {
                match (&socket.handle, &event) {
                    (Handle::Connection(id), Event::Connection(other, ev)) if id == other => {
                        if ev.readable || ev.half_closed || ev.closed.is_some() {
                            socket.readable = Some(true);
                        }
                        socket.connected |= ev.connected;
                        if let Some(r) = ev.closed {
                            socket.error = if r == CloseReason::Reset && !socket.connected {
                                ECONNREFUSED
                            } else {
                                reason(r)
                            };
                        }
                    }
                    (Handle::Listener(id), Event::Acceptable(other)) if id == other => {
                        socket.acceptable = Some(true)
                    }
                    _ => (),
                }
            }
        }
    }
    fn execute_at_now(&mut self, r: &mut Request) -> Result<Option<Response>> {
        // Application operations must not inherit the clock of an old packet.
        // Budget zero advances time without bypassing the loop's timeout budget.
        self.endpoint.on_timeout(self.now(), 0).map_err(error)?;
        self.execute(r)
    }
    fn execute(&mut self, r: &mut Request) -> Result<Option<Response>> {
        let mut response = Response::default();
        match r.op {
            1 => response.value = self.alloc(Socket::new(r.a))? as i64,
            2 => {
                let address = decode_addr(&r.bytes)?;
                let socket = self.sockets.get(&r.fd).ok_or(EBADF)?;
                if !matches!(socket.handle, Handle::Fresh) || socket.local.is_some() {
                    return Err(EINVAL);
                }
                if !address.ip().is_unspecified() && address.ip() != IpAddr::V4(self.local) {
                    return Err(EADDRNOTAVAIL);
                }
                if address.port() == 0 {
                    return Err(unsupported("bind ephemeral port"));
                }
                if self.sockets.iter().any(|(&fd, s)| {
                    fd != r.fd
                        && s.local.is_some_and(|a| a.port() == address.port())
                        && !(socket.reuse && s.reuse && matches!(s.handle, Handle::Connection(_)))
                }) {
                    return Err(EADDRINUSE);
                }
                self.sockets.get_mut(&r.fd).unwrap().local = Some(address);
            }
            3 => {
                let socket = self.sockets.get_mut(&r.fd).ok_or(EBADF)?;
                if !matches!(socket.handle, Handle::Fresh) {
                    return Err(unsupported("listen backlog update"));
                }
                let address = socket
                    .local
                    .ok_or_else(|| unsupported("listen without bind"))?;
                let id = self
                    .endpoint
                    .listen(address, r.a.clamp(1, LIMIT as i32) as usize)
                    .map_err(error)?;
                self.endpoint
                    .set_listener_application_timeout(id, user_timeout_us(socket.user_timeout_ms)?)
                    .map_err(error)?;
                socket.handle = Handle::Listener(id);
            }
            4 => {
                if self.sockets.len() == LIMIT {
                    return Err(EMFILE);
                }
                let socket = self.sockets.get(&r.fd).ok_or(EBADF)?;
                let Handle::Listener(id) = socket.handle else {
                    return Err(EINVAL);
                };
                let nodelay = socket.nodelay;
                let reuse = socket.reuse;
                // Allocate before consuming an accepted connection: OS allocation
                // failure must leave the connection in the listener queue.
                let token = Token::new()?;
                match self.endpoint.accept(id) {
                    Ok(id) => {
                        let tuple = self.endpoint.tuple(id).map_err(error)?;
                        self.endpoint.set_nagle(id, !nodelay).map_err(error)?;
                        let mut socket = Socket::new(0);
                        socket.handle = Handle::Connection(id);
                        socket.local = Some(tuple.local);
                        socket.nodelay = nodelay;
                        socket.reuse = reuse;
                        socket.user_timeout_ms = self
                            .endpoint
                            .application_timeout(id)
                            .map_err(error)?
                            .map_or(0, |us| (us / 1000) as i32);
                        socket.readable = None;
                        socket.connected = true;
                        response.value = self.alloc_token(socket, token)? as i64;
                        response.bytes = encode_addr(tuple.remote);
                        self.sockets.get_mut(&r.fd).unwrap().acceptable = None;
                    }
                    Err(EndpointError::Connection(Error::WouldBlock)) => {
                        self.sockets.get_mut(&r.fd).unwrap().acceptable = Some(false);
                        return self.block(r);
                    }
                    Err(e) => return Err(error(e)),
                }
            }
            5 => {
                if !r.started {
                    let remote = decode_addr(&r.bytes)?;
                    let socket = self.sockets.get_mut(&r.fd).ok_or(EBADF)?;
                    match socket.handle {
                        Handle::Fresh => (),
                        Handle::Connection(id) => {
                            return Err(
                                if matches!(
                                    self.endpoint.state(id),
                                    Ok(State::SynSent | State::SynReceived)
                                ) {
                                    EALREADY
                                } else {
                                    EISCONN
                                },
                            );
                        }
                        Handle::Listener(_) => return Err(EINVAL),
                    }
                    let mut local = match socket.local {
                        Some(local) => local,
                        None => {
                            // Logical ephemeral ports must not depend on reusable OS fds.
                            // Never wrap and accidentally reuse a previous allocation.
                            if self.next_port >= 60000 {
                                return Err(EADDRNOTAVAIL);
                            }
                            let port = self.next_port as u16;
                            self.next_port += 1;
                            SocketAddr::new(self.local.into(), port)
                        }
                    };
                    if local.ip().is_unspecified() {
                        local.set_ip(self.local.into());
                    }
                    let now = self.epoch.elapsed().as_micros() as u64;
                    let id = self.endpoint.connect(now, local, remote).map_err(error)?;
                    self.endpoint
                        .set_nagle(id, !socket.nodelay)
                        .map_err(error)?;
                    self.endpoint
                        .set_application_timeout(id, user_timeout_us(socket.user_timeout_ms)?)
                        .map_err(error)?;
                    socket.local = Some(local);
                    socket.handle = Handle::Connection(id);
                    r.started = true;
                    if socket.nonblock {
                        return Err(EINPROGRESS);
                    }
                }
                let id = self.connection(r.fd)?;
                match self.endpoint.state(id).map_err(error)? {
                    State::Established => (),
                    State::Closed => {
                        return Err(self
                            .endpoint
                            .close_reason(id)
                            .map_err(error)?
                            .map(|r| {
                                if r == CloseReason::Reset {
                                    ECONNREFUSED
                                } else {
                                    reason(r)
                                }
                            })
                            .filter(|e| *e != 0)
                            .unwrap_or(ECONNREFUSED));
                    }
                    _ => return Ok(None),
                }
            }
            6 | 7 => {
                let id = self.connection(r.fd)?;
                if r.op == 6 && r.capacity == 0 {
                    return Ok(Some(response));
                }
                let socket = self.sockets.get_mut(&r.fd).unwrap();
                if socket.error != 0 {
                    let e = socket.error;
                    socket.error = 0;
                    return Err(e);
                }
                if r.op == 7 {
                    let state = self.endpoint.state(id).map_err(error)?;
                    if socket.write_shutdown || matches!(state, State::Closed | State::TimeWait) {
                        return Err(EPIPE);
                    }
                    // Core allows pre-handshake buffering; socket sends must wait instead.
                    if matches!(state, State::SynSent | State::SynReceived) {
                        return self.block(r);
                    }
                    if r.bytes.is_empty() {
                        return Ok(Some(response));
                    }
                }
                let result = if r.op == 6 {
                    response.bytes.resize(r.capacity, 0);
                    self.endpoint.read(id, &mut response.bytes)
                } else {
                    self.endpoint.write(id, &r.bytes)
                };
                match result {
                    Ok(n) => {
                        response.value = n as i64;
                        if r.op == 6 {
                            response.bytes.truncate(n);
                            socket.readable = if n == 0
                                || matches!(
                                    self.endpoint.state(id),
                                    Ok(State::CloseWait
                                        | State::Closing
                                        | State::LastAck
                                        | State::TimeWait
                                        | State::Closed)
                                ) {
                                Some(true)
                            } else if n < r.capacity {
                                Some(false)
                            } else {
                                None
                            };
                        } else {
                            socket.written += n as u64;
                        }
                    }
                    Err(EndpointError::Connection(Error::WouldBlock)) => {
                        if r.op == 6 {
                            socket.readable = Some(false);
                        }
                        return self.block(r);
                    }
                    Err(e) => return Err(error(e)),
                }
            }
            8 => {
                let socket = self.sockets.get(&r.fd).ok_or(EBADF)?;
                match socket.handle {
                    Handle::Fresh => (),
                    Handle::Listener(id) => self.endpoint.close_listener(id).map_err(error)?,
                    Handle::Connection(id) => {
                        if !matches!(
                            self.endpoint.state(id).map_err(error)?,
                            State::Closed | State::TimeWait
                        ) {
                            self.endpoint.close(id).map_err(error)?;
                        }
                        self.detached.push_back(id);
                    }
                }
                // Cancel old-fd waiters before the OS can reuse this descriptor.
                self.pending.retain(|pending| {
                    if pending.fd == r.fd && !matches!(pending.op, 13..=15) {
                        let _ = pending.reply.send(Err(EBADF));
                        false
                    } else {
                        true
                    }
                });
                self.sockets.remove(&r.fd);
            }
            9 => {
                let id = self.connection(r.fd)?;
                self.endpoint.shutdown(id).map_err(error)?;
                self.sockets.get_mut(&r.fd).unwrap().write_shutdown = true;
            }
            10 => {
                let socket = self.sockets.get_mut(&r.fd).ok_or(EBADF)?;
                match r.a {
                    F_GETFL => {
                        response.value =
                            (O_RDWR | if socket.nonblock { O_NONBLOCK } else { 0 }) as i64
                    }
                    F_SETFL => {
                        if r.b & !(O_NONBLOCK | O_ACCMODE) != 0 {
                            return Err(unsupported("fcntl status flags"));
                        }
                        socket.nonblock = r.b & O_NONBLOCK != 0;
                    }
                    F_GETFD => response.value = if socket.cloexec { FD_CLOEXEC as i64 } else { 0 },
                    F_SETFD => {
                        if r.b & !FD_CLOEXEC != 0 {
                            return Err(EINVAL);
                        }
                        socket.cloexec = r.b != 0;
                    }
                    _ => return Err(unsupported("fcntl")),
                }
            }
            11 | 12 => {
                let socket = self.sockets.get_mut(&r.fd).ok_or(EBADF)?;
                if r.op == 11 {
                    match r.a {
                        1 => socket.reuse = r.b != 0,
                        2 => {
                            if let Handle::Connection(id) = socket.handle {
                                self.endpoint.set_nagle(id, r.b == 0).map_err(error)?;
                            }
                            socket.nodelay = r.b != 0;
                        }
                        5 => {
                            let milliseconds = r.b;
                            let timeout = user_timeout_us(milliseconds)?;
                            match socket.handle {
                                Handle::Connection(id) => self
                                    .endpoint
                                    .set_application_timeout(id, timeout)
                                    .map_err(error)?,
                                Handle::Listener(id) => self
                                    .endpoint
                                    .set_listener_application_timeout(id, timeout)
                                    .map_err(error)?,
                                Handle::Fresh => (),
                            }
                            socket.user_timeout_ms = milliseconds;
                        }
                        _ => return Err(ENOSYS),
                    }
                } else {
                    response.value = match r.a {
                        1 => socket.reuse as i64,
                        2 => socket.nodelay as i64,
                        3 => {
                            let e = socket.error;
                            socket.error = 0;
                            e as i64
                        }
                        4 => SOCK_STREAM as i64,
                        5 => socket.user_timeout_ms as i64,
                        _ => return Err(ENOSYS),
                    };
                }
            }
            13 => {
                response.bytes = r.bytes.clone();
                for chunk in response
                    .bytes
                    .chunks_exact_mut(std::mem::size_of::<pollfd>())
                {
                    let mut p = unsafe { ptr::read_unaligned(chunk.as_ptr().cast::<pollfd>()) };
                    p.revents = 0;
                    if p.events & !(POLLIN | POLLOUT | POLLERR | POLLHUP) != 0 {
                        return Err(unsupported("poll event mask"));
                    }
                    if p.fd >= 0 {
                        match self.sockets.get(&p.fd) {
                            None => p.revents = POLLNVAL,
                            Some(s) => {
                                if p.events & POLLIN != 0 {
                                    let ready = match s.handle {
                                        Handle::Connection(id) => Some(
                                            self.endpoint.readable_bytes(id).map_err(error)? != 0
                                                || matches!(
                                                    self.endpoint.state(id).map_err(error)?,
                                                    State::CloseWait
                                                        | State::Closing
                                                        | State::LastAck
                                                        | State::TimeWait
                                                        | State::Closed
                                                ),
                                        ),
                                        Handle::Listener(_) => s.acceptable,
                                        Handle::Fresh => s.readable,
                                    };
                                    if ready.ok_or_else(|| {
                                        unsupported(
                                            "poll readiness is not exposed for this socket state",
                                        )
                                    })? {
                                        p.revents |= POLLIN;
                                    }
                                }
                                if let Handle::Connection(id) = s.handle
                                    && p.events & POLLOUT != 0
                                    && (s.write_shutdown
                                        || s.error != 0
                                        || matches!(
                                            self.endpoint.state(id),
                                            Ok(State::Closed | State::TimeWait)
                                        )
                                        || (matches!(
                                            self.endpoint.state(id),
                                            Ok(State::Established | State::CloseWait)
                                        ) && s.written.saturating_sub(
                                            self.endpoint.acknowledged(id).map_err(error)?,
                                        ) < 65536))
                                {
                                    p.revents |= POLLOUT;
                                }
                                if s.error != 0 {
                                    p.revents |= POLLERR;
                                }
                                if let Handle::Connection(id) = s.handle {
                                    let state = self.endpoint.state(id).map_err(error)?;
                                    // HUP is unconditional when both socket directions are
                                    // shut, even while TCP retains its TIME-WAIT record.
                                    if state == State::Closed
                                        || s.write_shutdown
                                            && matches!(
                                                state,
                                                State::CloseWait
                                                    | State::Closing
                                                    | State::LastAck
                                                    | State::TimeWait
                                            )
                                    {
                                        p.revents |= POLLHUP;
                                    }
                                }
                            }
                        }
                    }
                    if p.revents != 0 {
                        response.value += 1;
                    }
                    unsafe {
                        ptr::write_unaligned(chunk.as_mut_ptr().cast::<pollfd>(), p);
                    }
                }
                if response.value == 0 && r.a != 0 && r.deadline.is_none_or(|d| Instant::now() < d)
                {
                    return Ok(None);
                }
            }
            14 => {
                let (ip, tcp) = parse_frame(&r.bytes)?;
                self.endpoint
                    .input_with_traffic_class(self.now(), ip, r.bytes[1], tcp)
                    .map_err(error)?;
            }
            15 => {
                let Some(front) = self.output.front() else {
                    return Ok(None);
                };
                if front.bytes.len() > r.capacity {
                    return Err(EMSGSIZE);
                }
                response = self.output.pop_front().unwrap();
            }
            16 => {
                let id = self.connection(r.fd)?;
                response.bytes = encode_addr(self.endpoint.tuple(id).map_err(error)?.remote);
            }
            17 => {
                let socket = self.sockets.get(&r.fd).ok_or(EBADF)?;
                let bytes = match socket.handle {
                    Handle::Fresh => 0,
                    Handle::Listener(_) => return Err(EINVAL),
                    Handle::Connection(id) => self.endpoint.readable_bytes(id).map_err(error)?,
                };
                response.value = i32::try_from(bytes).map_err(|_| EOVERFLOW)? as i64;
            }
            _ => return Err(unsupported("unknown adapter operation")),
        }
        Ok(Some(response))
    }
    fn block(&self, r: &Request) -> Result<Option<Response>> {
        if self.sockets.get(&r.fd).ok_or(EBADF)?.nonblock || r.a & MSG_DONTWAIT != 0 {
            Err(EAGAIN)
        } else {
            Ok(None)
        }
    }
}
fn ip_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|b| u16::from_be_bytes([b[0], *b.get(1).unwrap_or(&0)]) as u32)
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn parse_frame(bytes: &[u8]) -> Result<(IpMetadata, &[u8])> {
    if bytes.len() < 20 {
        return Err(EINVAL);
    }
    if bytes[0] >> 4 != 4 || bytes[9] != 6 {
        return Err(unsupported("packet: only IPv4 TCP"));
    }
    if bytes[0] & 15 != 5 {
        return Err(unsupported("IPv4 options"));
    }
    if u16::from_be_bytes([bytes[6], bytes[7]]) & 0xbfff != 0 {
        return Err(unsupported("IPv4 fragmentation/reserved flag"));
    }
    if usize::from(u16::from_be_bytes([bytes[2], bytes[3]])) != bytes.len()
        || ip_checksum(&bytes[..20]) != 0
    {
        return Err(EINVAL);
    }
    let ip = IpMetadata {
        source: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]).into(),
        destination: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]).into(),
    };
    ntcp::wire::parse(ip, &bytes[20..]).map_err(|_| EINVAL)?;
    Ok((ip, &bytes[20..]))
}
fn frame(tx: ntcp::Transmit, tcp: &[u8]) -> Result<Vec<u8>> {
    let (IpAddr::V4(source), IpAddr::V4(destination)) = (tx.ip.source, tx.ip.destination) else {
        return Err(EINVAL);
    };
    if tcp.len() > BYTES - 20 || tx.ipv4_options != ntcp::OutgoingIpv4Options::default() {
        return Err(EINVAL);
    }
    let mut out = vec![0; tcp.len() + 20];
    out[0] = 0x45;
    out[1] = tx.dscp << 2 | tx.ecn;
    let len = out.len() as u16;
    out[2..4].copy_from_slice(&len.to_be_bytes());
    out[6] = 0x40;
    out[8] = tx.hop_limit;
    out[9] = 6;
    out[12..16].copy_from_slice(&source.octets());
    out[16..20].copy_from_slice(&destination.octets());
    let checksum = ip_checksum(&out[..20]);
    out[10..12].copy_from_slice(&checksum.to_be_bytes());
    out[20..].copy_from_slice(tcp);
    Ok(out)
}
fn decode_addr(bytes: &[u8]) -> Result<SocketAddr> {
    if bytes.len() != std::mem::size_of::<sockaddr_in>() {
        return Err(EINVAL);
    }
    let addr = unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<sockaddr_in>()) };
    if addr.sin_family != AF_INET as u16 {
        return Err(EAFNOSUPPORT);
    }
    Ok(SocketAddr::new(
        Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()).into(),
        u16::from_be(addr.sin_port),
    ))
}
fn encode_addr(addr: SocketAddr) -> Vec<u8> {
    let IpAddr::V4(ip) = addr.ip() else {
        unreachable!()
    };
    let raw = sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: addr.port().to_be(),
        sin_addr: in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_zero: [0; 8],
    };
    unsafe {
        slice::from_raw_parts(
            (&raw as *const sockaddr_in).cast(),
            std::mem::size_of::<sockaddr_in>(),
        )
        .to_vec()
    }
}
unsafe extern "C" {
    fn ntcp_fill(interface: *mut c_void, userdata: *mut c_void);
}
#[unsafe(no_mangle)]
unsafe extern "C" fn packetdrill_interface_init(flags: *const c_char, interface: *mut c_void) {
    let adapter = catch_unwind(AssertUnwindSafe(|| {
        if flags.is_null() {
            return Err(unsupported("missing so_flags"));
        }
        let flags = unsafe { CStr::from_ptr(flags) }
            .to_str()
            .map_err(|_| EINVAL)?;
        Adapter::start(profile(flags)?)
    }));
    let userdata = match adapter {
        Ok(Ok(adapter)) => Box::into_raw(Box::new(adapter)).cast(),
        Ok(Err(_)) => ptr::null_mut(),
        Err(_) => {
            diagnostic("FAILURE", "adapter initialization panicked");
            ptr::null_mut()
        }
    };
    if !interface.is_null() {
        unsafe {
            ntcp_fill(interface, userdata);
        }
    } else if !userdata.is_null() {
        unsafe {
            drop(Box::from_raw(userdata.cast::<Adapter>()));
        }
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn ntcp_free(userdata: *mut c_void) {
    if catch_unwind(AssertUnwindSafe(|| {
        if !userdata.is_null() {
            unsafe {
                drop(Box::from_raw(userdata.cast::<Adapter>()));
            }
        }
    }))
    .is_err()
    {
        diagnostic("FAILURE", "adapter teardown panicked");
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn ntcp_call(
    userdata: *mut c_void,
    op: i32,
    fd: i32,
    a: i32,
    b: i32,
    input: *const c_void,
    input_len: usize,
    output: *mut c_void,
    output_len: usize,
    stamp: *mut i64,
) -> i64 {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<i64> {
        if userdata.is_null() {
            return Err(EIO);
        }
        if input_len > BYTES || (op == 6 && output_len > BYTES) {
            return Err(unsupported("scalar I/O exceeds 65535-byte adapter bound"));
        }
        if input_len != 0 && input.is_null() || output_len != 0 && output.is_null() {
            return Err(EFAULT);
        }
        let bytes = if input_len == 0 {
            Vec::new()
        } else {
            unsafe { slice::from_raw_parts(input.cast::<u8>(), input_len).to_vec() }
        };
        let (reply, _) = mpsc::sync_channel(1);
        let request = Request {
            op,
            fd,
            a,
            b,
            bytes,
            capacity: output_len.min(BYTES),
            deadline: if op == 13 && a > 0 {
                Some(Instant::now() + Duration::from_millis(a as u64))
            } else {
                None
            },
            started: false,
            reply,
        };
        let adapter = unsafe { &*userdata.cast::<Adapter>() };
        let response = adapter.call(request)?;
        if response.bytes.len() > output_len {
            return Err(EIO);
        }
        if !response.bytes.is_empty() {
            unsafe {
                ptr::copy_nonoverlapping(
                    response.bytes.as_ptr(),
                    output.cast::<u8>(),
                    response.bytes.len(),
                );
            }
        }
        if !stamp.is_null() {
            unsafe {
                ptr::write_unaligned(stamp, response.stamp);
            }
        }
        Ok(response.value)
    }));
    match result {
        Ok(Ok(value)) => value,
        other => {
            let e = match other {
                Ok(Err(e)) => e,
                _ => {
                    if !userdata.is_null() {
                        unsafe { &*userdata.cast::<Adapter>() }
                            .failed
                            .store(true, Ordering::Release);
                    }
                    diagnostic("FAILURE", "callback panicked; adapter disabled");
                    EIO
                }
            };
            unsafe {
                *__errno_location() = e;
            }
            -1
        }
    }
}

#[cfg(test)]
mod tests;
