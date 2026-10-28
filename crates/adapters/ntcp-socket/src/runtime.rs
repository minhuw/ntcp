// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
#[path = "runtime_backend.rs"]
mod backend;
#[path = "runtime_egress.rs"]
mod egress;
#[path = "runtime_fast_open.rs"]
mod fast_open;
#[path = "runtime_output.rs"]
mod output;
#[path = "runtime_send.rs"]
mod send;
#[path = "runtime_timestamping.rs"]
mod timestamps;
use crate::socket_options::{effective_notsent_lowat, notsent_writable};
use crate::*;
use ntcp::{
    AddressValidation, CloseReason, ConnectionId, Endpoint, EndpointConfig, EndpointError, Error,
    Event, ListenerId, State,
};
use ntcp_io::{PacketIo, TxOutcome};
use ntcp_io_tun::Tun;
use send::LogicalSend;
use std::{
    collections::{BTreeMap, VecDeque},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU8,
    sync::mpsc::{self, Receiver, SyncSender},
    time::Instant,
};
use timestamps::{ClockPair, Completion, TimestampState};

#[cfg(feature = "packet-test")]
#[path = "runtime_memory.rs"]
mod memory;
#[cfg(feature = "packet-test")]
use memory::PacketBackend;

pub const LIMIT: usize = 512;
pub const BYTES: usize = 65536;
pub(crate) const BUDGET: usize = 32;
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
    NewDomain(i32, i32),
    Wait(Box<Op>, Option<std::time::Duration>),
    FinishConnect,
    SetFastOpenClientEnabled(bool),
    SetFastOpenClientDefaultPolicy(FastOpenClientPolicy),
    SetFastOpenClientPolicy(Option<(SocketAddr, FastOpenClientPolicy)>),
    SetFastOpenServerCookie(Option<(SocketAddr, FastOpenCookie)>),
    SetListenerFastOpenEarlyDataPolicy(ntcp::FastOpenEarlyDataPolicy),
    SetDestinationRoute(IpAddr, Option<ntcp::RoutePolicy>),
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
    #[cfg(test)]
    WriteFlags(Vec<u8>, i32),
    Send(Vec<(usize, usize)>, i32),
    SendTo(Vec<(usize, usize)>, i32, Option<SocketAddr>, Option<u32>),
    Transfer {
        source: i32,
        staging: [i32; 2],
        offset: Option<usize>,
        count: usize,
        flags: i32,
    },
    UrgentRemaining,
    SendTimestamp(Vec<(usize, usize)>, i32, u32),
    RxTimestamp(usize),
    ErrorQueueTo(usize),
    Transport(i32),
    TransportPrefix(i32, usize),
    #[cfg(feature = "packet-test")]
    Inject(Vec<u8>),
    #[cfg(feature = "packet-test")]
    InjectSegmented(Vec<u8>, core::num::NonZeroU16),
    #[cfg(feature = "packet-test")]
    Capture(usize),
    #[cfg(feature = "packet-test")]
    LocalResourceReject(bool),
    #[cfg(feature = "packet-test")]
    TimestampDefault(bool),
    #[cfg(feature = "packet-test")]
    ClearFastOpenClientCache,
    #[cfg(feature = "packet-test")]
    ListenerPresent(u16),
    Close,
    Shutdown(i32),
    Flags(i32, i32),
    Set(i32, i32, i32),
    #[cfg(feature = "tfo-linux-cookie")]
    SetFastOpenKey(LinuxSipHash24Key),
    Get(i32, i32),
    Name(bool),
    Ready,
    Available,
    Inq(usize),
}
#[derive(Default, Debug)]
pub struct Reply {
    pub value: i32,
    pub timeout_us: u64,
    pub readiness_generations: [u64; 5],
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
    send: Option<LogicalSend>,
    closing: Option<ConnectionId>,
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
            let mut owner = Owner::with_config(
                local,
                (Ipv4Addr::new(10, 73, 0, 1), 24),
                [2; 32],
                None,
                SocketConfig::new("test", local).tcp,
            )
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

    pub fn start(config: SocketConfig) -> Result<Self> {
        config.validate().map_err(|_| EINVAL)?;
        let factory = crate::PACKET_IO_FACTORY.lock().map_err(|_| EIO)?.take();
        Self::spawn(
            std::panic::AssertUnwindSafe(move || {
                if let Some(factory) = factory {
                    Owner::external_backend(
                        &config,
                        factory().map_err(|e| e.raw_os_error().unwrap_or(EIO))?,
                    )
                } else {
                    match config.io.backend {
                        Backend::Tun => Owner::new(&config),
                        Backend::AfPacket => Owner::af_packet(&config),
                    }
                }
            }),
            false,
        )
    }
    #[cfg(all(test, feature = "packet-test"))]
    pub fn packet(settings: (impl Into<IpAddr>, crate::packet_profile::Profile)) -> Result<Self> {
        Self::packet_with_options(settings, crate::packet_test::Options::default())
    }
    #[cfg(feature = "packet-test")]
    pub fn packet_with_options(
        settings: (impl Into<IpAddr>, crate::packet_profile::Profile),
        options: crate::packet_test::Options,
    ) -> Result<Self> {
        let settings = (settings.0.into(), settings.1);
        Self::spawn(move || Owner::packet_with_options(settings, options), true)
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
                        let _ = ready_tx.send(Ok(crate::ip::family(owner.local)));
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
        let family = match ready_rx.recv().unwrap_or(Err(EIO)) {
            Ok(family) => family,
            Err(e) => {
                close_failed_startup(worker, wake);
                return Err(e);
            }
        };
        Ok(Self {
            tx,
            wake,
            family,
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
        if matches!(op, Op::Close) {
            // Last-close has removed the public fd already. Retry bounded owner
            // admission rather than leaking its socket; do not block capture
            // behind a channel parked on full deferred commands.
            loop {
                match self.call_once(id, Op::Close) {
                    Err(EAGAIN) => std::thread::sleep(std::time::Duration::from_millis(1)),
                    result => return result,
                }
            }
        }
        self.call_once(id, op)
    }
    fn call_once(&self, id: u64, op: Op) -> Result<Reply> {
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
            send: None,
            closing: None,
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
    domain: i32,
    v6only: bool,
    bound_addr: Option<SocketAddr>,
    ipv6_tclass: u8,
    ipv6_discover: i32,
    send_capacity: usize,
    receive_capacity: usize,
    handle: Handle,
    // Inline, one per socket (bounded by socket_limit), not endpoint buffer
    // storage or a retained connection. Err preserves an unavailable snapshot.
    terminal_transport: Option<Result<ntcp::TransportInfo>>,
    local: Option<SocketAddr>,
    flags: i32,
    // Adapter bind policy: mutual REUSEADDR permits live connection-port reuse;
    // no kernel bind table or Linux TIME-WAIT option emulation.
    reuse: bool,
    freebind: bool,
    nodelay: bool,
    cork: bool,
    inq: bool,
    notsent_lowat: u32,
    user_mss: Option<u16>,
    mark: u32,
    send_batch: Option<send::SendBatch>,
    send_finish: Option<send::SendFinish>,
    fast_open_limit: i32,
    fast_open_cookie_policy: Option<FastOpenCookiePolicy>,
    fast_open_connect: bool,
    server_cookie: Option<(SocketAddr, FastOpenCookie)>,
    client_policy: Option<(SocketAddr, FastOpenClientPolicy)>,
    deferred_client_policy: Option<FastOpenClientPolicy>,
    deferred_peer: Option<SocketAddr>,
    readiness: i32,
    readiness_generations: [u64; 5],
    keepalive: bool,
    idle: i32,
    interval: i32,
    probes: i32,
    error: i32,
    // Nonterminal network notifications are consumable through SO_ERROR,
    // independently of the fatal read/write/connect error path.
    soft_error: i32,
    connected: bool,
    // Linux SS_CONNECTING is independent of transport establishment. All fd
    // aliases address this socket; an API connect completion consumes it once.
    connect_pending: bool,
    // Actual half-close history, independent of consumable socket errors.
    peer_fin: bool,
    acceptable: bool,
    write_shutdown: bool,
    read_shutdown: bool,
    receive_timeout_us: u64,
    send_timeout_us: u64,
    user_timeout_ms: i32,
    syn_retries: Option<NonZeroU8>,
    tos: u8,
    discover: i32,
    zerocopy: bool,
    zc_next: u32,
    zc_reserved: usize,
    zc_leases: VecDeque<crate::zerocopy::Pending>,
    completions: VecDeque<Completion>,
    timestamps: TimestampState,
}
impl Socket {
    fn server_cookie_for(&self, remote: SocketAddr) -> Option<FastOpenCookie> {
        self.server_cookie
            .and_then(|(peer, cookie)| (peer == remote).then_some(cookie))
    }

    fn client_policy_for(
        &self,
        remote: SocketAddr,
        default: FastOpenClientPolicy,
    ) -> FastOpenClientPolicy {
        self.deferred_client_policy
            .or_else(|| {
                self.client_policy
                    .and_then(|(peer, policy)| (peer == remote).then_some(policy))
            })
            .unwrap_or(default)
    }

    fn new(flags: i32) -> Self {
        Self {
            domain: AF_INET,
            v6only: false,
            bound_addr: None,
            //= https://www.rfc-editor.org/rfc/rfc3542#section-6.5
            //# The outgoing traffic class is normally set to 0.
            ipv6_tclass: 0,
            ipv6_discover: IP_PMTUDISC_WANT,
            send_capacity: BYTES,
            receive_capacity: BYTES,
            handle: Handle::Fresh,
            terminal_transport: None,
            local: None,
            flags,
            reuse: false,
            freebind: false,
            nodelay: false,
            cork: false,
            inq: false,
            notsent_lowat: 0,
            user_mss: None,
            mark: 0,
            send_batch: None,
            send_finish: None,
            fast_open_limit: 0,
            fast_open_cookie_policy: None,
            fast_open_connect: false,
            server_cookie: None,
            client_policy: None,
            deferred_client_policy: None,
            deferred_peer: None,
            readiness: 0,
            readiness_generations: [0; 5],
            keepalive: false,
            idle: 7200,
            interval: 75,
            probes: 9,
            error: 0,
            soft_error: 0,
            connected: false,
            connect_pending: false,
            peer_fin: false,
            acceptable: false,
            write_shutdown: false,
            read_shutdown: false,
            receive_timeout_us: 0,
            send_timeout_us: 0,
            user_timeout_ms: 0,
            syn_retries: None,
            tos: 0,
            discover: IP_PMTUDISC_WANT,
            zerocopy: false,
            zc_next: 0,
            zc_reserved: 0,
            zc_leases: VecDeque::new(),
            completions: VecDeque::new(),
            timestamps: TimestampState::default(),
        }
    }
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.8
    //= reason=The shared socket owner exposes nonterminal connection/passive reports through consumable SO_ERROR and EPOLLERR without routing them into fatal I/O errors; terminal reports retain precedence.
    //# There MUST be a mechanism for reporting soft TCP error conditions to
    //# the application (MUST-47).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
    //= reason=IPv4 core network-error events now reach application-visible notifications; a listening socket's failed child does not make accept return a network error.
    //# SHOULD make the information available to the application (SHLD-25).
    fn report_network_error(&mut self, error: ntcp::NetworkError) {
        self.soft_error = match error {
            ntcp::NetworkError::SoftUnreachable | ntcp::NetworkError::HardUnreachable => {
                EHOSTUNREACH
            }
            ntcp::NetworkError::TimeExceeded => ETIMEDOUT,
            ntcp::NetworkError::ParameterProblem => EPROTO,
            ntcp::NetworkError::SourceQuench => return,
        };
        // Each report can wake an edge-triggered observer even while an older
        // notification remains pending. It does not make send_state fail.
        self.readiness_generations[2] = self.readiness_generations[2].wrapping_add(1);
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
type ChildOptionsSnapshot = (
    ConnectionId,
    u64,
    u64,
    u64,
    (bool, bool, bool, u32, bool, u8, i32),
);

struct Owner {
    endpoint: Endpoint,
    defaults: EndpointConfig,
    socket_policy: crate::SocketPolicy,
    tun: Option<Tun>,
    ethernet: Option<backend::EthernetBackend>,
    sockets: BTreeMap<u64, Socket>,
    local: IpAddr,
    epoch: Instant,
    #[cfg(test)]
    test_now: Option<u64>,
    next_port: u16,
    next_id: u64,
    detached: Vec<ConnectionId>,
    egress: Option<egress::Egress>,
    reservation_timeout_us: u64,
    mtu_refresh: Option<output::MtuRefresh>,
    timestamp_cookie: u64,
    child_timestamps: Vec<(ConnectionId, crate::timestamping::Options)>,
    pending: VecDeque<Request>,
    child_timeouts: Vec<ChildOptionsSnapshot>,
    connection_options: Vec<(ConnectionId, u8, i32, Option<bool>, u32)>,
    #[cfg(feature = "packet-test")]
    packets: Option<PacketBackend>,
}
fn unicast(ip: impl Into<IpAddr>) -> bool {
    crate::ip::unicast(ip.into())
}
fn context(io: &crate::IoConfig) -> Result<(IpAddr, u8)> {
    let mut list = ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } < 0 {
        return Err(errno());
    }
    let mut cursor = list;
    let mut found = None;
    let mut duplicate = false;
    unsafe {
        while let Some(entry) = cursor.as_ref() {
            if !entry.ifa_addr.is_null() {
                let family = (*entry.ifa_addr).sa_family as i32;
                let pair = if family == AF_INET {
                    let addr = &*entry.ifa_addr.cast::<sockaddr_in>();
                    let mask = (!entry.ifa_netmask.is_null()).then(|| {
                        (*entry.ifa_netmask.cast::<sockaddr_in>())
                            .sin_addr
                            .s_addr
                            .to_ne_bytes()
                    });
                    mask.map(|m| {
                        (
                            IpAddr::V4(Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes())),
                            IpAddr::V4(m.into()),
                        )
                    })
                } else if family == AF_INET6 {
                    let addr = &*entry.ifa_addr.cast::<sockaddr_in6>();
                    let mask = (!entry.ifa_netmask.is_null()).then(|| {
                        (*entry.ifa_netmask.cast::<sockaddr_in6>())
                            .sin6_addr
                            .s6_addr
                    });
                    mask.map(|m| {
                        (
                            IpAddr::V6(addr.sin6_addr.s6_addr.into()),
                            IpAddr::V6(m.into()),
                        )
                    })
                } else {
                    None
                };
                if let Some((addr, mask)) = pair {
                    duplicate |= addr == io.address;
                    let (bits, ones) = match mask {
                        IpAddr::V4(v) => (32, u32::from(v).leading_ones()),
                        IpAddr::V6(v) => (128, u128::from(v).leading_ones()),
                    };
                    let valid_mask = match mask {
                        IpAddr::V4(v) => {
                            u32::from(v) == u32::MAX.checked_shl(bits - ones).unwrap_or(0)
                        }
                        IpAddr::V6(v) => {
                            u128::from(v) == u128::MAX.checked_shl(bits - ones).unwrap_or(0)
                        }
                    };
                    if valid_mask
                        && CStr::from_ptr(entry.ifa_name).to_bytes() == io.interface.as_bytes()
                        && io.prefix.is_none_or(|p| u32::from(p) == ones)
                        && addr.is_ipv4() == io.address.is_ipv4()
                        && crate::ip::network(addr, ones as u8)
                            == crate::ip::network(io.address, ones as u8)
                    {
                        found = Some((addr, ones as u8));
                    }
                }
            }
            cursor = entry.ifa_next;
        }
        libc::freeifaddrs(list);
    }
    if duplicate || !unicast(io.address) {
        return Err(EADDRNOTAVAIL);
    }
    let pair = found.ok_or(EADDRNOTAVAIL)?;
    if crate::ip::network_or_broadcast(io.address, pair.1) {
        return Err(EADDRNOTAVAIL);
    }
    Ok(pair)
}
// Blocking getrandom with no fallback source: an owner never starts with a
// weak secret.
fn random_secret() -> Result<[u8; 32]> {
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
    Ok(secret)
}
impl Owner {
    fn new(config: &SocketConfig) -> Result<Self> {
        let name = &config.io.interface;
        let local = config.io.address;
        let tun = Tun::open(name).map_err(|e| e.raw_os_error().unwrap_or(EIO))?;
        let ifname = std::ffi::CString::new(name.as_str()).map_err(|_| EINVAL)?;
        let index = unsafe { libc::if_nametoindex(ifname.as_ptr()) };
        if index == 0 {
            return Err(errno());
        }
        let subnet = context(&config.io)?;
        let secret = random_secret()?;
        let tcp = backend::backend_config_family(config.tcp.clone(), &tun, local)?;
        let mut owner = Self::with_config(local, subnet, secret, Some(tun), tcp)?;
        owner.apply_socket_config(config)?;
        owner.enable_reservations(&config.io, index)?;
        Ok(owner)
    }
    fn apply_socket_config(&mut self, config: &SocketConfig) -> Result<()> {
        self.socket_policy = config.socket;
        self.endpoint
            .set_fast_open_cookie_policy(config.fast_open_cookie_policy.clone());
        let now = self.now();
        for &(destination, policy) in &config.routes {
            self.endpoint
                .set_destination_route(now, destination, Some(policy))
                .map_err(engine)?;
        }
        Ok(())
    }
    fn with_config(
        local: impl Into<IpAddr>,
        (address, prefix): (impl Into<IpAddr>, u8),
        secret: [u8; 32],
        tun: Option<Tun>,
        config: EndpointConfig,
    ) -> Result<Self> {
        let local = local.into();
        let address = address.into();
        let defaults = config.clone();
        let valid = move |ip: IpAddr| {
            if ip.is_ipv4() != local.is_ipv4() || !unicast(ip) {
                return false;
            }
            match (ip, address) {
                (IpAddr::V4(ip), IpAddr::V4(address)) => {
                    prefix > 30
                        || u32::from(ip)
                            != u32::from(address) | u32::MAX.checked_shr(prefix as u32).unwrap_or(0)
                }
                (IpAddr::V6(_), IpAddr::V6(_)) => true,
                _ => false,
            }
        };
        let endpoint = Endpoint::new(config, secret, 0, move |r| match r {
            AddressValidation::Bind { local: bind } => {
                // Per-socket local-address permission is checked by Op::Bind.
                // FREEBIND does not relax Open, Incoming, or Route policy.
                bind.is_unspecified() || unicast(bind)
            }
            AddressValidation::Open {
                local: source,
                remote,
            } => source == local && valid(remote),
            AddressValidation::Incoming {
                source,
                destination,
            } => destination == local && valid(source),
            AddressValidation::Route { .. } => false,
        })
        .map_err(engine)?;
        Ok(Self {
            endpoint,
            defaults,
            socket_policy: crate::SocketPolicy::default(),
            tun,
            ethernet: None,
            sockets: BTreeMap::new(),
            local,
            epoch: Instant::now(),
            #[cfg(test)]
            test_now: None,
            next_port: 40000,
            next_id: 1,
            detached: Vec::new(),
            egress: None,
            reservation_timeout_us: 1_000_000,
            mtu_refresh: None,
            timestamp_cookie: 1,
            child_timestamps: Vec::new(),
            pending: VecDeque::new(),
            child_timeouts: Vec::new(),
            connection_options: Vec::new(),
            #[cfg(feature = "packet-test")]
            packets: None,
        })
    }
    #[cfg(all(test, feature = "packet-test"))]
    fn packet(settings: (impl Into<IpAddr>, crate::packet_profile::Profile)) -> Result<Self> {
        Self::packet_with_options(settings, crate::packet_test::Options::default())
    }
    #[cfg(feature = "packet-test")]
    fn packet_with_options(
        (local, profile): (impl Into<IpAddr>, crate::packet_profile::Profile),
        options: crate::packet_test::Options,
    ) -> Result<Self> {
        let local = local.into();
        options.validate()?;
        // Deterministic key and synthetic address policy are explicit test-only
        // settings, never a production entropy source or TUN routing policy.
        let mut owner = Self::with_config(
            local,
            (local, if local.is_ipv4() { 32 } else { 128 }),
            [42; 32],
            None,
            SocketConfig::new("test", local).tcp,
        )?;
        owner.endpoint = Endpoint::new(
            crate::packet_profile::config(profile),
            [42; 32],
            0,
            move |r| match r {
                AddressValidation::Bind { local: addr } => addr.is_unspecified() || unicast(addr),
                AddressValidation::Open { local: addr, .. } => addr == local,
                AddressValidation::Incoming { destination, .. } => destination == local,
                AddressValidation::Route { .. } => false,
            },
        )
        .map_err(engine)?;
        owner
            .endpoint
            .set_fast_open_cookie_policy(crate::packet_profile::cookie_policy(profile));
        if matches!(profile, crate::packet_profile::Profile::Upstream(o) if o.tfo_listen) {
            owner.endpoint.enable_fast_open().map_err(engine)?;
        }
        owner.defaults = crate::packet_profile::config(profile);
        owner.socket_policy.notsent_lowat = crate::packet_profile::notsent_lowat(profile);
        if matches!(profile, crate::packet_profile::Profile::Upstream(o) if o.application_protected_tfo_client)
        {
            owner.socket_policy.fast_open_client_policy =
                FastOpenClientPolicy::ApplicationProtected;
        }
        owner.packets = Some(PacketBackend::new(profile, options.queue_capacity)?);
        owner.enable_egress(options.egress_capacity, crate::packet_profile::gso(profile))?;
        Ok(owner)
    }
    fn check_address(&self, addr: SocketAddr) -> Result<()> {
        if addr.is_ipv4() != self.local.is_ipv4() {
            return Err(EAFNOSUPPORT);
        }
        if let SocketAddr::V6(v) = addr
            && (v.scope_id() != 0
                || v.flowinfo() != 0
                || v.ip().to_ipv4_mapped().is_some()
                || v.ip().is_unicast_link_local())
        {
            return Err(EOPNOTSUPP);
        }
        Ok(())
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
            socket.domain = crate::ip::family(self.local);
            socket.v6only = self.local.is_ipv6();
            let config = crate::packet_profile::config(packets.profile);
            socket.receive_capacity = config.connection.receive_capacity;
            socket.send_capacity = config.connection.send_capacity;
            socket.user_mss = config.connection.user_mss;
            if matches!(packets.profile, crate::packet_profile::Profile::Upstream(o) if o.tfo_listen)
            {
                socket.fast_open_limit = config.max_connections as i32;
            }
            return socket;
        }
        let mut socket = Socket::new(flags);
        socket.domain = crate::ip::family(self.local);
        socket.v6only = self.local.is_ipv6();
        let c = &self.defaults.connection;
        socket.send_capacity = c.send_capacity;
        socket.receive_capacity = c.receive_capacity;
        socket.user_mss = c.user_mss;
        socket.nodelay = !c.nagle;
        socket.tos = self.defaults.dscp << 2;
        socket.ipv6_tclass = socket.tos;
        if let Some(k) = c.keepalive {
            socket.keepalive = true;
            socket.idle = (k.idle_us / 1_000_000) as i32;
            socket.interval = (k.interval_us / 1_000_000) as i32;
            socket.probes = k.probes as i32;
        }
        // TCP_USER_TIMEOUT is a separate application override, not core user_timeout_us.
        socket
    }
    fn packet_backend(&self) -> bool {
        #[cfg(feature = "packet-test")]
        return self.packets.is_some();
        #[cfg(not(feature = "packet-test"))]
        false
    }
    fn admission_command(&self, op: &Op) -> bool {
        if matches!(
            op,
            Op::SetFastOpenClientEnabled(_)
                | Op::SetFastOpenClientDefaultPolicy(_)
                | Op::SetDestinationRoute(..)
        ) {
            return true;
        }
        #[cfg(feature = "packet-test")]
        if self.packet_backend()
            && matches!(
                op,
                Op::Inject(_)
                    | Op::InjectSegmented(..)
                    | Op::Capture(_)
                    | Op::LocalResourceReject(_)
                    | Op::TimestampDefault(_)
                    | Op::ClearFastOpenClientCache
                    | Op::ListenerPresent(_)
            )
        {
            return true;
        }
        let _ = op;
        false
    }
    fn admission_full(&self, request: &Request) -> bool {
        if self.admission_command(&request.op) {
            return false;
        }
        // Reserve a separate, bounded allowance for teardown: ordinary waiters
        // may need Close to cancel them. Both classes stay within socket_limit,
        // including closes deferred by held output or awaiting FIN submission.
        let closing = matches!(request.op, Op::Close);
        self.pending
            .iter()
            .filter(|r| matches!(r.op, Op::Close) == closing)
            .count()
            >= self.socket_limit()
    }
    fn now(&self) -> u64 {
        #[cfg(test)]
        if let Some(now) = self.test_now {
            return now;
        }
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
    fn service(&mut self, request: &mut Request) -> bool {
        self.finish_retained_sends();
        // Last-close must give its already-queued FIN/RST a submission turn
        // before waking a caller that may immediately exit the process. This
        // retained generation survives socket removal; other requests progress.
        if let Some(cid) = request.closing {
            if self.endpoint.is_output_reserved(cid)
                || self.endpoint.ready_connections().any(|id| id == cid)
            {
                return false;
            }
            let _ = request.reply.send(Ok(Reply::default()));
            return true;
        }
        // Defer before inspecting foreign buffers or consuming file/pipe producers.
        if self.command_held(request.id, &request.op) {
            // A continued nonblocking send never waits for backend capacity.
            // Retain boundary metadata until the immutable output plan releases;
            // the accepted prefix and its completions can return immediately.
            if request
                .send
                .as_ref()
                .is_some_and(LogicalSend::continuing_nonblocking)
            {
                let mut send = request.send.take().unwrap();
                let result = self.finish_send(request.id, &mut send, Ok(()));
                let _ = request.reply.send(result);
                return true;
            }
            return false;
        }
        let (op, wait) = if let Op::Wait(op, _) = &request.op {
            (&**op, true)
        } else {
            (&request.op, false)
        };
        if matches!(op, Op::Send(..) | Op::SendTimestamp(..) | Op::SendTo(..)) {
            if request.send.is_none() {
                let (sources, flags, stamp, destination) = match op {
                    Op::Send(sources, flags) => (sources.clone(), *flags, None, None),
                    Op::SendTimestamp(sources, flags, stamp) => {
                        (sources.clone(), *flags, Some(*stamp), None)
                    }
                    Op::SendTo(sources, flags, destination, stamp) => {
                        (sources.clone(), *flags, *stamp, *destination)
                    }
                    _ => unreachable!(),
                };
                match LogicalSend::new(self, request.id, sources, flags, stamp, destination) {
                    Ok(send) => request.send = Some(send),
                    Err(e) => {
                        let _ = request.reply.send(Err(e));
                        return true;
                    }
                }
            }
            return self.service_send(request, wait);
        }
        let closing = if self.egress.is_some() && matches!(op, Op::Close) {
            self.sockets.get(&request.id).and_then(|s| match s.handle {
                Handle::Connection(cid) => Some(cid),
                _ => None,
            })
        } else {
            None
        };
        let op = op.clone();
        let result = self.execute(request.id, op);
        if result.is_ok() && closing.is_some() {
            request.closing = closing;
            return false;
        }
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
    fn output_packet_len(&self) -> usize {
        #[cfg(feature = "packet-test")]
        if self.packets.is_some() {
            return 65535;
        }
        // Include the largest TCP option header, not just the data MSS.
        crate::ip::header_len(self.local)
            + usize::from(self.defaults.connection.send_ip_payload_limit)
                .min(usize::from(self.defaults.connection.mss) + 60)
                .min(65515)
    }
    fn service_before_output(&mut self, after_output: &mut Vec<(Request, bool)>) {
        for _ in 0..self.pending.len().min(BUDGET) {
            let mut request = self.pending.pop_front().unwrap();
            // Admit a retained TFO tail before selecting the handshake ACK.
            // service() still enforces the per-generation output reservation barrier.
            let early = request
                .send
                .as_ref()
                .is_some_and(LogicalSend::waiting_fast_open)
                || (matches!(&request.op, Op::Wait(op, _) if matches!(**op, Op::Read(_) | Op::Peek(_) | Op::ReadTo(..)))
                    && self.sockets.get(&request.id).is_some_and(|s| s.error == 0));
            if !early || !self.service(&mut request) {
                after_output.push((request, early));
            }
        }
    }
    fn run(&mut self, rx: Receiver<Request>, wake: i32, stop: &std::sync::atomic::AtomicBool) {
        // Every runtime constructor enables Egress, the only output path.
        assert!(self.egress.is_some());
        let mut input = vec![0; 65535 + if self.ethernet.is_some() { 14 } else { 0 }];
        // Keep in-flight batches owned through every output/backend exit.
        let mut after_output = Vec::with_capacity(BUDGET);
        'run: while !stop.load(Ordering::Acquire) {
            self.poll_mtu_refresh();
            if self.expire_egress(self.now()).is_err() {
                break;
            }
            let now = self.now();
            if self.endpoint.on_timeout(now, BUDGET).is_err() {
                break;
            }
            if self.receive_batch(&mut input).is_err() || self.poll_backend_timestamps().is_err() {
                break 'run;
            }
            if self
                .ethernet
                .as_mut()
                .is_some_and(|b| b.io.reclaim_transmit(BUDGET).is_err())
            {
                break 'run;
            }
            self.events();
            self.collect_zero_copy();
            self.service_before_output(&mut after_output);
            if self.service_egress().is_err() {
                break 'run;
            }
            self.events();
            self.collect_zero_copy();
            for (mut request, retried) in after_output.drain(..) {
                if retried || !self.service(&mut request) {
                    self.pending.push_back(request);
                }
            }
            self.connection_options
                .retain(|p| self.endpoint.connection_exists(p.0));
            self.detached.retain(|&id| {
                if !self.endpoint.is_output_reserved(id)
                    && matches!(self.endpoint.state(id), Ok(State::Closed | State::TimeWait))
                {
                    let _ = self.endpoint.release(id);
                    false
                } else {
                    true
                }
            });
            // Bounded owner work and a 1ms ceiling also cover shared wakefd consumers.
            let wait = self.output_wait();
            // Keep admission open while teardown has room; packet capture must
            // always remain reachable to free held output.
            if !self.packet_backend()
                && self.pending.len() >= 2 * self.socket_limit()
                && self.egress.as_ref().is_some_and(|e| e.has_held())
            {
                std::thread::sleep(wait);
                continue;
            }
            match rx.recv_timeout(wait) {
                Ok(mut r) => {
                    if self.admission_full(&r) {
                        let _ = r.reply.send(Err(EAGAIN));
                    } else if !self.service(&mut r) {
                        self.pending.push_back(r);
                    }
                    #[cfg(feature = "packet-test")]
                    let requests = if self.packets.is_some() { 1 } else { BUDGET };
                    #[cfg(not(feature = "packet-test"))]
                    let requests = BUDGET;
                    for _ in 1..requests {
                        let Ok(mut r) = rx.try_recv() else {
                            break;
                        };
                        if self.admission_full(&r) {
                            let _ = r.reply.send(Err(EAGAIN));
                        } else if !self.service(&mut r) {
                            self.pending.push_back(r);
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => (),
            }
            signal(wake);
        }
        self.pending
            .extend(after_output.into_iter().map(|(request, _)| request));
        let error = if stop.load(Ordering::Acquire) {
            ECANCELED
        } else {
            EIO
        };
        while let Some(mut request) = self.pending.pop_front() {
            let result = if let Some(mut send) = request.send.take() {
                self.finish_send(request.id, &mut send, Err(error))
            } else {
                Err(error)
            };
            let _ = request.reply.send(result);
        }
    }
    fn prune_child_timeouts(&mut self) {
        self.child_timeouts
            .retain(|(cid, _, _, _, _)| self.endpoint.connection_exists(*cid));
        self.child_timestamps
            .retain(|(cid, _)| self.endpoint.connection_exists(*cid));
    }
    #[cfg(test)]
    fn input(
        &mut self,
        now: u64,
        ip: ntcp::IpMetadata,
        traffic_class: u8,
        bytes: &[u8],
    ) -> std::result::Result<ntcp::InputDisposition, EndpointError> {
        let stamps = ntcp::RxPacketTimestamps {
            software: self.software_rx_enabled().then(|| ntcp::RxTimestamp {
                value: timestamps::realtime(),
                clock: ntcp::TimestampClock::RealtimeNanoseconds,
            }),
            hardware: None,
        };
        self.input_stamped(now, ip, traffic_class, bytes, stamps)
    }
    #[cfg(test)]
    fn input_stamped(
        &mut self,
        now: u64,
        ip: ntcp::IpMetadata,
        traffic_class: u8,
        bytes: &[u8],
        stamps: ntcp::RxPacketTimestamps,
    ) -> std::result::Result<ntcp::InputDisposition, EndpointError> {
        self.input_segmented(now, ip, traffic_class, bytes, stamps, None)
    }
    fn input_segmented(
        &mut self,
        now: u64,
        ip: ntcp::IpMetadata,
        traffic_class: u8,
        bytes: &[u8],
        stamps: ntcp::RxPacketTimestamps,
        segment_size: Option<core::num::NonZeroU16>,
    ) -> std::result::Result<ntcp::InputDisposition, EndpointError> {
        // Endpoint validates the packet; the ports are only used to observe
        // generation-aware tuple ownership before and after passive admission.
        let tuple = bytes.get(..4).map(|ports| ntcp::Tuple {
            local: SocketAddr::new(ip.destination, u16::from_be_bytes([ports[2], ports[3]])),
            remote: SocketAddr::new(ip.source, u16::from_be_bytes([ports[0], ports[1]])),
        });
        let before = tuple.and_then(|tuple| self.endpoint.connection_id(tuple));
        let before_state = before.and_then(|cid| self.endpoint.state(cid).ok());
        let listener_options = tuple.and_then(|tuple| {
            self.sockets
                .values()
                .find(|s| {
                    matches!(s.handle, Handle::Listener(_))
                        && s.local
                            .is_some_and(|local| binding_overlap(local, tuple.local))
                })
                .map(|s| {
                    (
                        s.wire_tos(self.local),
                        s.wire_discover(self.local),
                        s.zerocopy,
                        s.mark,
                    )
                })
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

        let pair = ClockPair::sample(self);
        let result = self.endpoint.input_with_metadata(
            now,
            ip,
            traffic_class,
            ntcp::Ipv4Options::default(),
            bytes,
            ntcp::RxPacketMetadata {
                timestamps: stamps,
                tcp_segment_size: segment_size,
            },
        );
        self.drain_timestamps(pair);
        self.prune_child_timeouts();
        if let Some(tuple) = tuple
            && let Some(cid) = self.endpoint.connection_id(tuple)
            && Some(cid) != before
            && let Some((&listener, s)) = self.sockets.iter().find(|(_, s)| {
                matches!(s.handle, Handle::Listener(_))
                    && s.local
                        .is_some_and(|local| binding_overlap(local, tuple.local))
            })
        {
            // Runtime bind policy admits only one listener per port. Input can
            // only create passive children; active opens go through Connect.
            // ponytail: bounded linear metadata lookup, index if LIMIT grows.
            debug_assert!(self.child_timeouts.len() < LIMIT);
            self.child_timestamps.push((cid, s.timestamps.options));
            self.child_timeouts.push((
                cid,
                listener,
                s.receive_timeout_us,
                s.send_timeout_us,
                (
                    s.nodelay,
                    s.cork,
                    s.inq,
                    s.notsent_lowat,
                    s.freebind,
                    s.other_ip_policy(self.local).0,
                    s.other_ip_policy(self.local).1,
                ),
            ));
        }
        if let Some(tuple) = tuple
            && let Some(cid) = self.endpoint.connection_id(tuple)
        {
            if before_state == Some(State::SynReceived)
                && matches!(
                    self.endpoint.state(cid),
                    Ok(State::Established | State::CloseWait)
                )
                && let Some((_, listener, _, _, _)) =
                    self.child_timeouts.iter().find(|p| p.0 == cid)
                && let Some(s) = self.sockets.get_mut(listener)
                && s.acceptable
            {
                // Core Acceptable covers empty->nonempty. A subsequent child
                // is also a Linux ET wake even while the accept queue is ready.
                s.readiness_generations[0] = s.readiness_generations[0].wrapping_add(1);
            }
            if Some(cid) != before
                && let Some((tos, discover, _, mark)) = listener_options
            {
                self.endpoint.set_dscp(cid, tos >> 2)?;
                self.connection_options
                    .push((cid, tos, discover, None, mark));
            }
            // Snapshot at accept eligibility, before the adapter publishes the
            // child. Only authenticated TFO data is readable in SynReceived;
            // ordinary children retain their final-handshake-ACK snapshot.
            let state = self.endpoint.state(cid);
            if (matches!(state, Ok(State::Established | State::CloseWait))
                || state == Ok(State::SynReceived) && self.endpoint.readable_bytes(cid)? != 0)
                && let Some(p) = self.connection_options.iter_mut().find(|p| p.0 == cid)
                && p.3.is_none()
            {
                p.3 = listener_options.map(|p| p.2);
            }
        }
        result
    }
    fn events(&mut self) {
        self.finish_retained_sends();
        for _ in 0..BUDGET {
            let Some(event) = self.endpoint.next_event() else {
                break;
            };
            for s in self.sockets.values_mut() {
                match (s.handle, &event) {
                    (Handle::Listener(id), Event::Acceptable(other)) if id == *other => {
                        s.acceptable = true;
                        s.readiness_generations[0] = s.readiness_generations[0].wrapping_add(1);
                    }
                    (
                        Handle::Listener(id),
                        Event::PassiveError {
                            listener, error, ..
                        },
                    ) if id == *listener => {
                        // A failed child never turns the listener's accept into
                        // a connection failure. The application can query it.
                        s.report_network_error(*error);
                    }
                    (Handle::Connection(id), Event::Connection(other, e)) if id == *other => {
                        s.connected |= e.connected;
                        s.peer_fin |= e.half_closed;
                        if e.readable {
                            s.readiness_generations[0] = s.readiness_generations[0].wrapping_add(1);
                        }
                        if let Some(reason) = e.closed {
                            s.soft_error = 0; // A terminal event supersedes prior soft reports.
                            s.error = match reason {
                                CloseReason::Reset if !s.connected => ECONNREFUSED,
                                CloseReason::Reset => ECONNRESET,
                                CloseReason::TimedOut => ETIMEDOUT,
                                CloseReason::Aborted => ECONNABORTED,
                                CloseReason::NetworkError => EHOSTUNREACH,
                                CloseReason::Normal => 0,
                            };
                        } else if let Some(error) = e.network_error {
                            s.report_network_error(error);
                        }
                    }
                    _ => (),
                }
            }
        }
        // ponytail: bounded per-socket scan; index changed connections if LIMIT grows.
        let ids: Vec<_> = self.sockets.keys().copied().collect();
        for id in ids {
            let _ = self.refresh_readiness(id);
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
        self.endpoint
            .set_handshake_retransmission_limit(cid, s.syn_retries)
            .map_err(engine)?;
        self.endpoint
            .set_user_mss(cid, s.user_mss)
            .map_err(engine)?;
        self.endpoint
            .set_dscp(cid, s.wire_tos(self.local) >> 2)
            .map_err(engine)?;
        self.endpoint.set_nagle(cid, !s.nodelay).map_err(engine)?;
        self.endpoint.set_cork(cid, s.cork).map_err(engine)?;
        if s.timestamps.options.flags != 0 {
            self.endpoint
                .set_rx_timestamp_capacity(cid, timestamps::PHASES)
                .map_err(engine)?;
            self.endpoint
                .set_tx_timestamp_capacity(cid, timestamps::PHASES)
                .map_err(engine)?;
        }
        Ok(())
    }
    fn rollback_connection(&mut self, cid: ConnectionId) {
        // release retains storage until any reset output has drained.
        let _ = self.endpoint.abort(cid);
        let _ = self.endpoint.release(cid);
    }
    fn send_state(&mut self, id: u64) -> Result<ConnectionId> {
        let s = self.sockets.get_mut(&id).ok_or(EBADF)?;
        let Handle::Connection(cid) = s.handle else {
            return Err(EPIPE);
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
        if state == State::SynSent || state == State::SynReceived && !s.connected {
            return Err(EAGAIN);
        }
        Ok(cid)
    }
    #[cfg(test)]
    fn write(&mut self, id: u64, bytes: Vec<u8>, flags: i32) -> Result<i32> {
        self.write_timestamp(id, bytes, flags, None)
    }
    #[cfg(test)]
    fn write_timestamp(
        &mut self,
        id: u64,
        bytes: Vec<u8>,
        flags: i32,
        override_flags: Option<u32>,
    ) -> Result<i32> {
        if let Some(flags) = override_flags {
            self.sockets
                .get(&id)
                .ok_or(EBADF)?
                .timestamps
                .options
                .per_send(flags)?;
        }
        let cid = self.send_state(id)?;
        if bytes.is_empty() {
            return Ok(0);
        }
        let completion = self.reserve_completion(id, true, flags, override_flags)?;
        let n = self.timestamp_write(id, cid, &bytes, flags, override_flags)?;
        let s = self.sockets.get_mut(&id).unwrap();
        if n != 0 && completion {
            let next = s.zc_next;
            if let Some(Completion::ZeroCopy(lo, hi)) = s.completions.back_mut()
                && extends_completion((*lo, *hi), next)
            {
                *hi = next;
            } else {
                s.completions.push_back(Completion::ZeroCopy(next, next));
            }
            s.zc_next = next.wrapping_add(1);
            // A newly completed send wakes ET error-queue consumers even if
            // an older completion still keeps EPOLLERR asserted.
            s.readiness_generations[2] = s.readiness_generations[2].wrapping_add(1);
        }
        Ok(n as i32)
    }
    fn readiness_bits(&self, id: u64) -> Result<i32> {
        let s = self.sockets.get(&id).ok_or(EBADF)?;
        // A held native owner cannot service its I/O yet, but querying it must
        // not block a poll/epoll scan of unrelated descriptors.
        if self.egress.is_some() && self.command_held(id, &Op::Read(0)) {
            return Ok(0);
        }
        let mut bits = 0;
        if s.error != 0 || s.soft_error != 0 || !s.completions.is_empty() {
            bits |= EPOLLERR;
        }
        match s.handle {
            Handle::Fresh => {
                if s.deferred_peer.is_some() {
                    bits |= EPOLLOUT;
                }
            }
            Handle::Listener(_) => {
                if s.acceptable {
                    bits |= EPOLLIN;
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
                    bits |= EPOLLIN;
                }
                if eof {
                    bits |= EPOLLRDHUP;
                }
                if s.write_shutdown
                    || s.error != 0
                    || matches!(state, State::Closed | State::TimeWait)
                    || ((matches!(state, State::Established | State::CloseWait)
                        || state == State::SynReceived && s.connected)
                        && info.send_used < info.send_capacity
                        && notsent_writable(
                            info.notsent_bytes,
                            effective_notsent_lowat(
                                s.notsent_lowat,
                                self.socket_policy.notsent_lowat,
                            ),
                        ))
                {
                    bits |= EPOLLOUT;
                }
                if state == State::Closed || (s.write_shutdown && (eof || s.read_shutdown)) {
                    bits |= EPOLLHUP;
                }
            }
        }
        Ok(bits)
    }
    fn refresh_readiness(&mut self, id: u64) -> Result<i32> {
        let bits = self.readiness_bits(id)?;
        let s = self.sockets.get_mut(&id).ok_or(EBADF)?;
        for (i, bit) in socket_options::EDGE_BITS.into_iter().enumerate() {
            if bits & !s.readiness & bit != 0 {
                s.readiness_generations[i] = s.readiness_generations[i].wrapping_add(1);
            }
        }
        s.readiness = bits;
        Ok(bits)
    }
    //= https://www.rfc-editor.org/rfc/rfc7413#appendix-A.2
    //# The application only needs to enable the reception of Fast Open requests via a new TCP_FASTOPEN
    //# setsockopt() socket option before listen().
    //= https://www.rfc-editor.org/rfc/rfc7413#appendix-A.2
    //# Traditionally, accept() returns only after a socket is connected. But, for a Fast Open connection,
    //# accept() returns upon receiving a SYN with a valid Fast Open cookie and data, and the data is
    //# available to be read through, e.g., recvmsg(), read().
    fn execute(&mut self, id: u64, op: Op) -> Result<Reply> {
        if let Op::SetDestinationRoute(destination, policy) = op {
            if !unicast(destination) || destination.is_ipv4() != self.local.is_ipv4() {
                return Err(EINVAL);
            }
            self.endpoint
                .set_destination_route(self.now(), destination, policy)
                .map_err(|error| {
                    if error == EndpointError::OutputReserved {
                        EAGAIN
                    } else {
                        engine(error)
                    }
                })?;
            self.events();
            return Ok(Reply::default());
        }
        // Observer snapshots do not drive clocks/timers or consume events.
        #[cfg(feature = "packet-test")]
        if let Op::ListenerPresent(port) = op {
            return self.packet_listener_present(port).map(|present| Reply {
                value: i32::from(present),
                ..Reply::default()
            });
        }
        if self.command_held(id, &op) {
            return Err(EAGAIN);
        }
        self.endpoint.on_timeout(self.now(), 0).map_err(engine)?;
        let result = self.dispatch(id, op);
        let _ = self.refresh_readiness(id);
        result
    }
    fn dispatch(&mut self, id: u64, op: Op) -> Result<Reply> {
        self.prune_child_timeouts();
        let mut out = Reply::default();
        if matches!(op, Op::SetDestinationRoute(..)) {
            unreachable!("route control uses execute preflight");
        }
        if let Op::SetFastOpenClientEnabled(enabled) = op {
            self.socket_policy.fast_open_client_enabled = enabled;
            return Ok(out);
        }
        if let Op::SetFastOpenClientDefaultPolicy(policy) = op {
            self.socket_policy.fast_open_client_policy = policy;
            return Ok(out);
        }
        #[cfg(feature = "packet-test")]
        match &op {
            Op::Inject(bytes) | Op::InjectSegmented(bytes, _) => {
                if self.packets.is_none() {
                    return Err(EOPNOTSUPP);
                }
                if bytes.len() > crate::packet_profile::BYTES {
                    return Err(EMSGSIZE);
                }
                crate::packet_profile::validate_injection(bytes)?;
                // Admission is not TCP processing: retained RX may delay delivery.
                let (bytes, segment_size) = match op {
                    Op::Inject(bytes) => (bytes, None),
                    Op::InjectSegmented(bytes, size) => (bytes, Some(size)),
                    _ => unreachable!(),
                };
                if let Some(size) = segment_size {
                    let packet = crate::packet_profile::parse_frame(&bytes)?;
                    let segment =
                        ntcp::wire::parse(packet.ip, packet.payload).map_err(|_| EINVAL)?;
                    ntcp::RxPacketMetadata {
                        timestamps: Default::default(),
                        tcp_segment_size: Some(size),
                    }
                    .validate_segment(&segment)
                    .map_err(|_| EINVAL)?;
                }
                self.packets
                    .as_mut()
                    .unwrap()
                    .inject_segmented(bytes, segment_size)?;
                return Ok(out);
            }
            Op::TimestampDefault(enabled) => {
                self.packets.as_ref().ok_or(EOPNOTSUPP)?;
                self.endpoint.packet_test_timestamp_default(*enabled);
                return Ok(out);
            }
            Op::ClearFastOpenClientCache => {
                self.packets.as_ref().ok_or(EOPNOTSUPP)?;
                self.endpoint.clear_fast_open_client_cache();
                return Ok(out);
            }
            Op::LocalResourceReject(enabled) => {
                self.packets.as_mut().ok_or(EOPNOTSUPP)?.local_reject = *enabled;
                return Ok(out);
            }
            Op::Capture(capacity) => {
                let packets = self.packets.as_mut().ok_or(EOPNOTSUPP)?;
                let (front, _) = packets.output.front().ok_or(EAGAIN)?;
                if front.bytes.len() > *capacity {
                    return Err(EMSGSIZE);
                }
                return Ok(packets.output.pop_front().unwrap().0);
            }
            _ => (),
        }
        self.events();
        if let Op::New(flags) | Op::NewDomain(_, flags) = op {
            let domain = if let Op::NewDomain(domain, _) = op {
                domain
            } else {
                crate::ip::family(self.local)
            };
            if ![AF_INET, AF_INET6].contains(&domain) || domain == AF_INET && self.local.is_ipv6() {
                return Err(EAFNOSUPPORT);
            }
            let mut socket = self.fresh_socket(flags);
            socket.domain = domain;
            socket.v6only = domain == AF_INET6 && self.local.is_ipv6();
            out.value = self.alloc(socket)?;
            return Ok(out);
        }
        let s = self.sockets.get(&id).ok_or(EBADF)?;
        match op {
            Op::SetFastOpenClientPolicy(policy) => {
                if !matches!(s.handle, Handle::Fresh) || s.deferred_peer.is_some() {
                    return Err(EINVAL);
                }
                let policy = policy
                    .map(|(peer, policy)| {
                        s.normalize_address(peer, self.local, false)
                            .map(|peer| (peer, policy))
                    })
                    .transpose()?;
                if policy.is_some_and(|(peer, _)| peer.port() == 0 || !unicast(peer.ip())) {
                    return Err(EINVAL);
                }
                self.sockets.get_mut(&id).unwrap().client_policy = policy;
            }
            Op::SetFastOpenServerCookie(credential) => {
                if !matches!(s.handle, Handle::Fresh) || s.deferred_peer.is_some() {
                    return Err(EINVAL);
                }
                let credential = credential
                    .map(|(peer, cookie)| {
                        s.normalize_address(peer, self.local, false)
                            .map(|peer| (peer, cookie))
                    })
                    .transpose()?;
                if credential.is_some_and(|(peer, _)| peer.port() == 0 || !unicast(peer.ip())) {
                    return Err(EINVAL);
                }
                self.sockets.get_mut(&id).unwrap().server_cookie = credential;
            }
            Op::SetListenerFastOpenEarlyDataPolicy(policy) => {
                let Handle::Listener(listener) = s.handle else {
                    return Err(EOPNOTSUPP);
                };
                self.endpoint
                    .set_listener_fast_open_early_data_policy(listener, policy)
                    .map_err(engine)?;
            }
            #[cfg(feature = "tfo-linux-cookie")]
            Op::SetFastOpenKey(key) => {
                if s.deferred_peer.is_some()
                    || !matches!(s.handle, Handle::Fresh | Handle::Listener(_))
                {
                    return Err(EINVAL);
                }
                let policy = FastOpenCookiePolicy::LinuxSipHash24(key);
                if let Handle::Listener(listener) = s.handle {
                    self.endpoint
                        .set_listener_fast_open_cookie_policy(listener, Some(policy.clone()))
                        .map_err(engine)?;
                }
                self.sockets.get_mut(&id).unwrap().fast_open_cookie_policy = Some(policy);
            }
            Op::Bind(mut addr) => {
                let mut local = s.normalize_address(addr, self.local, true)?;
                if !matches!(s.handle, Handle::Fresh)
                    || s.local.is_some()
                    || s.deferred_peer.is_some()
                {
                    return Err(EINVAL);
                }
                if !s.freebind && local.ip() != self.local && !local.ip().is_unspecified() {
                    return Err(EADDRNOTAVAIL);
                }
                let reuse = s.reuse;
                let new_v6only = s.v6only;
                if addr.port() == 0 {
                    addr.set_port(self.port()?);
                    local.set_port(addr.port());
                }
                if self.sockets.iter().any(|(&other, s)| {
                    other != id
                        && !(reuse && s.reuse && matches!(s.handle, Handle::Connection(_)))
                        && s.conflicts_binding(addr, local, new_v6only)
                }) {
                    return Err(EADDRINUSE);
                }
                let socket = self.sockets.get_mut(&id).unwrap();
                socket.local = Some(local);
                socket.bound_addr = Some(addr);
            }
            Op::Listen(backlog) => {
                if !matches!(s.handle, Handle::Fresh) || s.deferred_peer.is_some() {
                    return Err(EOPNOTSUPP);
                }
                let fast_open_limit = s.fast_open_limit;
                let cookie_policy = s.fast_open_cookie_policy.clone();
                let capacities = (s.send_capacity, s.receive_capacity);
                let application_timeout = user_timeout_us(s.user_timeout_ms)?;
                let syn_retries = s.syn_retries;
                let user_mss = s.user_mss;
                let local = match s.local {
                    Some(a) => a,
                    None => {
                        let api = SocketAddr::new(
                            if s.domain == AF_INET6 {
                                std::net::Ipv6Addr::UNSPECIFIED.into()
                            } else {
                                self.local
                            },
                            0,
                        );
                        let mut local = s.normalize_address(api, self.local, true)?;
                        local.set_port(self.port()?);
                        local
                    }
                };
                let listener = self
                    .endpoint
                    .listen(local, backlog.clamp(1, LIMIT as i32) as usize)
                    .map_err(engine)?;
                if let Err(e) = self.endpoint.set_listener_user_mss(listener, user_mss) {
                    let _ = self.endpoint.close_listener(listener);
                    return Err(engine(e));
                }
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
                if let Err(e) = self
                    .endpoint
                    .set_listener_handshake_retransmission_limit(listener, syn_retries)
                {
                    let _ = self.endpoint.close_listener(listener);
                    return Err(engine(e));
                }
                if self.sockets[&id].timestamps.options.flags != 0
                    && let Err(e) = self
                        .endpoint
                        .set_listener_rx_timestamp_capacity(listener, timestamps::PHASES)
                {
                    let _ = self.endpoint.close_listener(listener);
                    return Err(engine(e));
                }
                if let Err(e) = self
                    .endpoint
                    .set_listener_fast_open(listener, fast_open_limit as usize)
                {
                    let _ = self.endpoint.close_listener(listener);
                    return Err(engine(e));
                }
                if let Err(e) = self
                    .endpoint
                    .set_listener_fast_open_cookie_policy(listener, cookie_policy)
                {
                    let _ = self.endpoint.close_listener(listener);
                    return Err(engine(e));
                }
                #[cfg(feature = "packet-test")]
                if self.packets.as_ref().is_some_and(|p| {
                    matches!(p.profile,
                    crate::packet_profile::Profile::Upstream(o) if o.application_protected_tfo)
                }) {
                    self.endpoint
                        .set_listener_fast_open_early_data_policy(
                            listener,
                            ntcp::FastOpenEarlyDataPolicy::ApplicationProtected,
                        )
                        .map_err(engine)?;
                }
                let s = self.sockets.get_mut(&id).unwrap();
                s.local = Some(local);
                if s.domain == AF_INET6 && s.bound_addr.is_none() {
                    s.bound_addr = Some(SocketAddr::new(s.api_unspecified(), local.port()));
                }
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
                child.domain = s.domain;
                child.v6only = s.v6only;
                child.set_other_ip_policy(
                    self.local,
                    s.other_ip_policy(self.local).0,
                    s.other_ip_policy(self.local).1,
                );
                child.reuse = s.reuse;
                child.freebind = s.freebind;
                child.nodelay = s.nodelay;
                child.cork = s.cork;
                child.inq = s.inq;
                child.notsent_lowat = s.notsent_lowat;
                child.keepalive = s.keepalive;
                child.idle = s.idle;
                child.interval = s.interval;
                child.probes = s.probes;
                child.user_timeout_ms = s.user_timeout_ms;
                let accepted = self.endpoint.accept(listener);
                if matches!(
                    accepted,
                    Err(EndpointError::Connection(Error::WouldBlock)
                        | EndpointError::OutputReserved)
                ) {
                    // All pending children may be held by backend output. Treat
                    // that accept-only pressure like an empty queue; final child
                    // resolution restores Acceptable and blocking requests retry.
                    self.sockets.get_mut(&id).unwrap().acceptable = false;
                    return Err(EAGAIN);
                }
                let cid = accepted.map_err(engine)?;
                (child.send_capacity, child.receive_capacity) =
                    self.endpoint.buffer_capacities(cid).map_err(engine)?;
                if let Some(index) = self
                    .child_timeouts
                    .iter()
                    .position(|(other, _, _, _, _)| *other == cid)
                {
                    let (
                        _,
                        _,
                        receive,
                        send,
                        (nodelay, cork, inq, lowat, freebind, other_tos, other_discover),
                    ) = self.child_timeouts.swap_remove(index);
                    child.receive_timeout_us = receive;
                    child.send_timeout_us = send;
                    child.nodelay = nodelay;
                    child.cork = cork;
                    child.inq = inq;
                    child.notsent_lowat = lowat;
                    child.freebind = freebind;
                    child.set_other_ip_policy(self.local, other_tos, other_discover);
                }
                let tuple = match self.endpoint.tuple(cid).map_err(engine) {
                    Ok(tuple) => tuple,
                    Err(e) => {
                        self.rollback_connection(cid);
                        return Err(e);
                    }
                };
                child.user_mss = self.endpoint.user_mss(cid).map_err(engine)?;
                child.syn_retries = self
                    .endpoint
                    .handshake_retransmission_limit(cid)
                    .map_err(engine)?;
                child.user_timeout_ms = self
                    .endpoint
                    .application_timeout(cid)
                    .map_err(engine)?
                    .map_or(0, |us| (us / 1000) as i32);
                if let Some(p) = self.connection_options.iter().find(|p| p.0 == cid) {
                    child.set_wire_ip_policy(self.local, p.1, p.2);
                    child.zerocopy = p.3.unwrap_or(false);
                    child.mark = p.4;
                }
                if let Some(index) = self.child_timestamps.iter().position(|p| p.0 == cid) {
                    child.timestamps.options = self.child_timestamps.swap_remove(index).1;
                }
                let peer = child.api_address(tuple.remote);
                child.handle = Handle::Connection(cid);
                child.local = Some(tuple.local);
                child.connected = true;
                child.peer_fin = matches!(
                    self.endpoint.state(cid),
                    Ok(State::CloseWait | State::Closing | State::LastAck | State::TimeWait)
                );
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
                out.addr = Some(peer);
                // Core emits Acceptable on empty->nonempty; stay readable until accept returns EAGAIN.
            }
            Op::Connect(remote) => {
                let remote = s.normalize_address(remote, self.local, false)?;
                self.check_address(remote)?;
                if !self.check_connect(id)? {
                    return Ok(out);
                }
                if remote.port() == 0 {
                    return Err(EINVAL);
                }
                let local = self.connect_local(id)?;
                // Previously saved options do not authorize a new TFO open
                // after administrative disablement. Ordinary connect still works.
                if self.sockets[&id].fast_open_connect
                    && self.socket_policy.fast_open_client_enabled
                {
                    self.endpoint.enable_fast_open().map_err(engine)?;
                    let socket = &self.sockets[&id];
                    let policy = socket
                        .client_policy_for(remote, self.socket_policy.fast_open_client_policy);
                    let allowed = if let Some(cookie) = socket.server_cookie_for(remote) {
                        self.endpoint.can_defer_fast_open_with_server_cookie(
                            self.now(),
                            local.ip(),
                            remote,
                            Some(cookie),
                        )
                    } else {
                        self.endpoint.can_defer_fast_open_with_policy(
                            self.now(),
                            local.ip(),
                            remote,
                            policy,
                        )
                    }
                    .map_err(engine)?;
                    if allowed {
                        let s = self.sockets.get_mut(&id).unwrap();
                        s.local = Some(local);
                        s.deferred_peer = Some(remote);
                        s.deferred_client_policy = Some(policy);
                        return Ok(out);
                    }
                    self.start_connection(id, local, remote, Some(&[]))?;
                } else {
                    self.start_connection(id, local, remote, None)?;
                }
                return Err(EINPROGRESS);
            }
            Op::Read(capacity) | Op::Peek(capacity) | Op::ReadTo(capacity, _, _, _) => {
                let foreign = matches!(op, Op::ReadTo(..));
                let peek = matches!(op, Op::Peek(_) | Op::ReadTo(..));
                let Handle::Connection(cid) = s.handle else {
                    return Err(if s.deferred_peer.is_some() {
                        EAGAIN
                    } else {
                        ENOTCONN
                    });
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
            #[cfg(test)]
            Op::WriteFlags(bytes, flags) => {
                out.value = self.write(id, bytes, flags)?;
            }
            Op::Transfer {
                source,
                staging,
                offset,
                count,
                flags,
            } => {
                out.value = self.transfer_once(id, source, staging, offset, count, flags)?;
            }
            Op::UrgentRemaining => {
                let Handle::Connection(cid) = s.handle else {
                    return Err(ENOTCONN);
                };
                out.timeout_us = self.endpoint.urgent_remaining(cid).map_err(engine)?;
            }
            Op::Send(_, _) | Op::SendTimestamp(..) | Op::SendTo(..) => {
                let (sources, flags, override_flags, destination) = match op {
                    Op::Send(sources, flags) => (sources, flags, None, None),
                    Op::SendTimestamp(sources, flags, stamp) => (sources, flags, Some(stamp), None),
                    Op::SendTo(sources, flags, destination, stamp) => {
                        (sources, flags, stamp, destination)
                    }
                    _ => unreachable!(),
                };
                return self.send_once(id, sources, flags, override_flags, destination);
            }
            Op::RxTimestamp(count) => {
                let Handle::Connection(cid) = s.handle else {
                    return Err(ENOTCONN);
                };
                let flags = s.timestamps.options.flags;
                if let Some(stamp) = self
                    .endpoint
                    .peek_rx_timestamps(cid, count)
                    .map_err(engine)?
                {
                    let ns = |t: Option<ntcp::RxTimestamp>| {
                        t.and_then(|t| match t.clock {
                            ntcp::TimestampClock::RealtimeNanoseconds
                            | ntcp::TimestampClock::DeviceTicks {
                                units_per_second: Some(1_000_000_000),
                                ..
                            } => Some(t.value),
                            _ => None,
                        })
                    };
                    let sw = (flags & crate::timestamping::SOFTWARE != 0
                        && (flags & crate::timestamping::OPT_RX_FILTER == 0
                            || flags & crate::timestamping::RX_SOFTWARE != 0))
                        .then(|| ns(stamp.timestamps.software))
                        .flatten();
                    let hw = (flags & crate::timestamping::RAW_HARDWARE != 0
                        && (flags & crate::timestamping::OPT_RX_FILTER == 0
                            || flags & crate::timestamping::RX_HARDWARE != 0))
                        .then(|| ns(stamp.timestamps.hardware))
                        .flatten();
                    if sw.is_some() || hw.is_some() {
                        out.bytes = crate::timestamping::timestamps(sw, hw).to_vec();
                        out.value = if s.timestamps.options.new_abi { 65 } else { 37 };
                    }
                }
            }
            Op::ErrorQueueTo(address) => {
                let completion = s.completions.front().ok_or(EAGAIN)?;
                let p = address as *mut msghdr;
                out.value = match completion {
                    Completion::ZeroCopy(lo, hi) => {
                        copy_completion_family(p, load(p)?, (*lo, *hi), true, s.domain)?;
                        0
                    }
                    Completion::SharedZeroCopy(lo, hi, copied) => {
                        copy_completion_family(p, load(p)?, (*lo, *hi), *copied, s.domain)?;
                        0
                    }
                    Completion::Timestamp {
                        stamp,
                        error,
                        payload,
                    } => {
                        // Linux reports timestamp CMSGs using the current options,
                        // independently of the generation flags on the old send.
                        let options = s.timestamps.options;
                        let mut reported = *stamp;
                        if options.flags & crate::timestamping::SOFTWARE == 0 {
                            reported[..16].fill(0);
                        }
                        if options.flags & crate::timestamping::RAW_HARDWARE == 0 {
                            reported[32..].fill(0);
                        }
                        copy_timestamp_completion(
                            p,
                            load(p)?,
                            if options.new_abi { 65 } else { 37 },
                            reported.iter().any(|&b| b != 0).then_some(&reported),
                            error,
                            payload,
                            s.domain,
                        )? as i32
                    }
                };
                self.sockets.get_mut(&id).unwrap().completions.pop_front();
            }
            Op::Transport(option) | Op::TransportPrefix(option, _) => {
                let requested = if let Op::TransportPrefix(_, requested) = op {
                    requested
                } else {
                    usize::MAX
                };
                out.bytes = match s.handle {
                    Handle::Connection(cid) => crate::transport::transport_option_prefix(
                        self.endpoint.transport_info(cid).map_err(engine)?,
                        option,
                        requested,
                    )?,
                    Handle::Fresh => match s.terminal_transport {
                        Some(info) => {
                            crate::transport::transport_option_prefix(info?, option, requested)?
                        }
                        None => crate::transport::idle_transport_option(None, option, requested)?,
                    },
                    Handle::Listener(id) => crate::transport::idle_transport_option(
                        Some(self.endpoint.listener_queue_info(id).map_err(engine)?),
                        option,
                        requested,
                    )?,
                };
            }
            Op::Close => {
                match s.handle {
                    Handle::Fresh => (),
                    Handle::Listener(l) => self.endpoint.close_listener(l).map_err(engine)?,
                    Handle::Connection(cid) => {
                        let _ = self.endpoint.set_fast_open_write_pending(cid, false);
                        let _ = self.endpoint.cancel_tx_timestamps(cid);
                        while matches!(self.endpoint.next_tx_timestamp(cid), Ok(Some(_))) {}
                        let _ = self.endpoint.set_tx_timestamp_capacity(cid, 0);
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
                    .retain(|(_, listener, _, _, _)| *listener != id);
                self.pending.retain(|request| {
                    if request.id == id {
                        let result = request.send.as_ref().filter(|s| s.accepted != 0).map_or(
                            Err(EBADF),
                            |s| {
                                Ok(Reply {
                                    value: s.accepted as i32,
                                    ..Reply::default()
                                })
                            },
                        );
                        let _ = request.reply.send(result);
                        false
                    } else {
                        true
                    }
                });
                self.sockets.remove(&id);
                self.cancel_unused_backend_timestamps();
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
            Op::Set(SOL_SOCKET, name @ (37 | 65), value) => {
                self.timestamp_options(id, name, value as u32)?;
            }
            Op::Set(IPPROTO_IPV6, IPV6_V6ONLY, value) if s.domain == AF_INET6 => {
                if !matches!(s.handle, Handle::Fresh) || s.local.is_some() {
                    return Err(EINVAL);
                }
                self.sockets.get_mut(&id).unwrap().v6only = value != 0;
            }
            // Linux IPv6 stream sockets expose the same FREEBIND flag through
            // both option levels; binding permission is independent of wire family.
            Op::Set(IPPROTO_IP, name, _) if self.local.is_ipv6() && name != IP_FREEBIND => {
                return Err(ENOPROTOOPT);
            }
            Op::Set(IPPROTO_IPV6, _, _) if s.domain != AF_INET6 => return Err(ENOPROTOOPT),
            Op::Set(level, name, value) => {
                // RFC3542 section6.5: -1 clears the sticky IPv6 class to0;
                // validate before cloning options or touching live TCP policy.
                //= https://www.rfc-editor.org/rfc/rfc3542#section-6.5
                //# To specify the outgoing traffic class value, just specify
                //# the control information as ancillary data for sendmsg() or
                //# using setsockopt(). Just like the hop limit value, the
                //# interpretation of the integer traffic class value is
                //# x < -1: return an error of EINVAL
                //# x == -1: use kernel default
                //# 0 <= x <= 255: use x
                //# x >= 256: return an error of EINVAL
                //= https://www.rfc-editor.org/rfc/rfc3542#section-6.5
                //# In order to clear a sticky IPV6_TCLASS option the application
                //# can specify -1 as the value.
                let value = if (level, name) == (IPPROTO_IPV6, IPV6_TCLASS) {
                    if !(-1..=255).contains(&value) {
                        return Err(EINVAL);
                    }
                    value.max(0)
                } else {
                    value
                };
                // Reject an unauthorized request before option cloning or any
                // completion/staging capacity is required for a transaction.
                if level == IPPROTO_TCP && name == TCP_FASTOPEN_CONNECT {
                    if !(0..=1).contains(&value) {
                        return Err(EINVAL);
                    }
                    if !self.socket_policy.fast_open_client_enabled {
                        return Err(EOPNOTSUPP);
                    }
                }
                // Account for the transient option snapshot as well as retained
                // queue capacity; cloning Arc packet references copies no payload.
                if self.timestamp_charge()
                    + s.timestamps.staging_charge()
                    + (s.completions.len() + s.timestamps.reserved() + s.zc_reserved)
                        * 2
                        * std::mem::size_of::<Completion>()
                    > timestamps::RUNTIME_BYTES
                {
                    return Err(ENOBUFS);
                }
                let mut candidate = s.clone();
                candidate.timestamps.restore_reservations()?;
                // Clone preserves pending observations but not spare queue slots.
                // Active logical sends already own those slots too.
                if s.zc_leases.capacity() != 0 {
                    candidate
                        .zc_leases
                        .try_reserve_exact(
                            candidate
                                .zc_reserved
                                .saturating_sub(candidate.zc_leases.len()),
                        )
                        .map_err(|_| ENOBUFS)?;
                }
                candidate
                    .completions
                    .try_reserve_exact(candidate.timestamps.reserved() + candidate.zc_reserved)
                    .map_err(|_| ENOBUFS)?;
                let s = &mut candidate;
                match (level, name) {
                    (SOL_SOCKET, SO_MARK) => {
                        if value != 0 && !self.packet_mark_supported() {
                            return Err(EOPNOTSUPP);
                        }
                        // Validate backend privileges and support before committing the option.
                        self.set_backend_mark(value as u32)
                            .map_err(|e| e.raw_os_error().unwrap_or(EOPNOTSUPP))?;
                        s.mark = value as u32;
                    }
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
                    (IPPROTO_IP, IP_FREEBIND) | (IPPROTO_IPV6, IPV6_FREEBIND) => {
                        s.freebind = value != 0
                    }
                    (IPPROTO_IP, IP_TOS) => s.tos = value as u8 & !3,
                    //= https://www.rfc-editor.org/rfc/rfc3542#section-6.5
                    //# There are cases where the kernel needs to control the
                    //# traffic class value and conflicts with the user-specified
                    //# value on the outgoing traffic. An example is an
                    //# implementation of ECN in the kernel, setting 2 bits of the
                    //# traffic class value. In such cases, the kernel should
                    //# override the user-specified value.
                    (IPPROTO_IPV6, IPV6_TCLASS) => s.ipv6_tclass = value as u8 & !3,
                    (IPPROTO_IP, IP_MTU_DISCOVER) | (IPPROTO_IPV6, IPV6_MTU_DISCOVER) => {
                        match value {
                            IP_PMTUDISC_DONT | IP_PMTUDISC_WANT | IP_PMTUDISC_DO => (),
                            3..=5 => {
                                return Err(unsupported_option(
                                    "IP_MTU_DISCOVER: PROBE/INTERFACE/OMIT require route features",
                                ));
                            }
                            _ => return Err(EINVAL),
                        }
                        if level == IPPROTO_IP {
                            s.discover = value;
                        } else {
                            s.ipv6_discover = value;
                        }
                    }
                    (IPPROTO_TCP, TCP_MAXSEG) => {
                        // Linux TCP_MIN_MSS=88, MAX_TCP_WINDOW=32767; zero clears the override.
                        if value != 0 && !(88..=32767).contains(&value) {
                            return Err(EINVAL);
                        }
                        s.user_mss = (value != 0).then_some(value as u16);
                    }
                    (IPPROTO_TCP, TCP_SYNCNT) => {
                        if !(1..=127).contains(&value) {
                            return Err(EINVAL);
                        }
                        s.syn_retries = NonZeroU8::new(value as u8);
                    }
                    (IPPROTO_TCP, TCP_USER_TIMEOUT) => {
                        user_timeout_us(value)?;
                        s.user_timeout_ms = value;
                    }
                    (IPPROTO_TCP, TCP_FASTOPEN) => {
                        if value < 0
                            || !matches!(s.handle, Handle::Fresh | Handle::Listener(_))
                            || s.deferred_peer.is_some()
                        {
                            return Err(EINVAL);
                        }
                        // Linux clamps the queue bound; our endpoint's admission limit is fixed.
                        s.fast_open_limit = value.min(self.defaults.max_connections as i32);
                    }
                    (IPPROTO_TCP, TCP_FASTOPEN_CONNECT) => {
                        if !matches!(s.handle, Handle::Fresh) || s.deferred_peer.is_some() {
                            return Err(EINVAL);
                        }
                        s.fast_open_connect = value != 0;
                    }
                    (IPPROTO_TCP, TCP_NODELAY) => s.nodelay = value != 0,
                    (IPPROTO_TCP, TCP_CORK) => s.cork = value != 0,
                    // Linux copies an int into an unsigned u32, including negative inputs.
                    (IPPROTO_TCP, TCP_NOTSENT_LOWAT) => s.notsent_lowat = value as u32,
                    (IPPROTO_TCP, TCP_INQ) => {
                        if !(0..=1).contains(&value) {
                            return Err(EINVAL);
                        }
                        s.inq = value != 0;
                    }
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
                    // Preserve transactional invalid-handle rejection even for
                    // adapter-only options; querying state does not flush data.
                    self.endpoint.state(cid).map_err(engine)?;
                    // NODELAY is an explicit flush, including when already set. Do
                    // not reapply it for unrelated option changes on a corked stream.
                    match (level, name) {
                        (IPPROTO_TCP, TCP_MAXSEG) => {
                            self.endpoint
                                .set_user_mss(cid, s.user_mss)
                                .map_err(engine)?;
                        }
                        (IPPROTO_TCP, TCP_NODELAY) => {
                            self.endpoint.set_nagle(cid, !s.nodelay).map_err(engine)?
                        }
                        (IPPROTO_TCP, TCP_CORK) => {
                            self.endpoint.set_cork(cid, s.cork).map_err(engine)?
                        }
                        (SOL_SOCKET, SO_KEEPALIVE)
                        | (IPPROTO_TCP, TCP_KEEPIDLE | TCP_KEEPINTVL | TCP_KEEPCNT) => self
                            .endpoint
                            .set_keepalive(cid, s.keepalive_config())
                            .map_err(engine)?,
                        (IPPROTO_TCP, TCP_SYNCNT) => self
                            .endpoint
                            .set_handshake_retransmission_limit(cid, s.syn_retries)
                            .map_err(engine)?,
                        (IPPROTO_TCP, TCP_USER_TIMEOUT) => self
                            .endpoint
                            .set_application_timeout(cid, user_timeout_us(s.user_timeout_ms)?)
                            .map_err(engine)?,
                        //= https://www.rfc-editor.org/rfc/rfc3542#section-4.1
                        //# When the application uses setsockopt to specify the
                        //# above options it is expected that TCP will start using
                        //# the new information when sending segments. However,
                        //# TCP may or may not use the new information when
                        //# retransmitting segments that were originally sent
                        //# when the old sticky options were in effect.
                        (IPPROTO_IP, IP_TOS) | (IPPROTO_IPV6, IPV6_TCLASS) => self
                            .endpoint
                            .set_dscp(cid, s.wire_tos(self.local) >> 2)
                            .map_err(engine)?,
                        _ => (),
                    }
                }
                if let Handle::Connection(cid) = s.handle
                    && let Some(p) = self.connection_options.iter_mut().find(|p| p.0 == cid)
                {
                    p.1 = s.wire_tos(self.local);
                    p.2 = s.wire_discover(self.local);
                    p.4 = s.mark;
                }
                if let Handle::Listener(listener) = s.handle {
                    self.endpoint
                        .set_listener_user_mss(listener, s.user_mss)
                        .map_err(engine)?;
                    self.endpoint
                        .set_listener_application_timeout(
                            listener,
                            user_timeout_us(s.user_timeout_ms)?,
                        )
                        .map_err(engine)?;
                }
                if (level, name) == (IPPROTO_TCP, TCP_SYNCNT)
                    && let Handle::Listener(listener) = s.handle
                {
                    self.endpoint
                        .set_listener_handshake_retransmission_limit(listener, s.syn_retries)
                        .map_err(engine)?;
                }
                if (level, name) == (IPPROTO_TCP, TCP_FASTOPEN) {
                    if s.fast_open_limit != 0 {
                        self.endpoint.enable_fast_open().map_err(engine)?;
                    }
                    if let Handle::Listener(listener) = s.handle {
                        self.endpoint
                            .set_listener_fast_open(listener, s.fast_open_limit as usize)
                            .map_err(engine)?;
                    }
                }
                self.sockets.insert(id, candidate);
                // Linux tcp_setsockopt calls sk_write_space even for a repeated
                // LOWAT value. Notify each ET registration, not just 0->OUT.
                if (level, name) == (IPPROTO_TCP, TCP_NOTSENT_LOWAT)
                    && self.refresh_readiness(id)? & EPOLLOUT != 0
                {
                    let s = self.sockets.get_mut(&id).unwrap();
                    s.readiness_generations[1] = s.readiness_generations[1].wrapping_add(1);
                }
            }
            Op::Get(SOL_SOCKET, name @ (37 | 65)) => {
                out.bytes = s.timestamps.options.get(name)?.to_vec();
                out.value = i32::from_ne_bytes(out.bytes[..4].try_into().unwrap());
            }
            Op::Get(IPPROTO_IP, name) if self.local.is_ipv6() && name != IP_FREEBIND => {
                return Err(ENOPROTOOPT);
            }
            Op::Get(IPPROTO_IPV6, _) if s.domain != AF_INET6 => return Err(ENOPROTOOPT),
            Op::Get(level, name) => {
                let s = self.sockets.get_mut(&id).unwrap();
                out.value = match (level, name) {
                    (SOL_SOCKET, SO_TYPE) => SOCK_STREAM,
                    (SOL_SOCKET, SO_DOMAIN) => s.domain,
                    (IPPROTO_IPV6, IPV6_V6ONLY) if s.domain == AF_INET6 => i32::from(s.v6only),
                    (SOL_SOCKET, SO_PROTOCOL) => IPPROTO_TCP,
                    (SOL_SOCKET, SO_ERROR) => {
                        if s.error != 0 {
                            core::mem::take(&mut s.error)
                        } else {
                            core::mem::take(&mut s.soft_error)
                        }
                    }
                    (SOL_SOCKET, SO_ACCEPTCONN) => {
                        i32::from(matches!(s.handle, Handle::Listener(_)))
                    }
                    (SOL_SOCKET, SO_MARK) => s.mark as i32,
                    (SOL_SOCKET, SO_REUSEADDR) => s.reuse as i32,
                    (SOL_SOCKET, SO_KEEPALIVE) => s.keepalive as i32,
                    (SOL_SOCKET, SO_SNDBUF) => s.send_capacity as i32,
                    (SOL_SOCKET, SO_RCVBUF) => s.receive_capacity as i32,
                    (IPPROTO_TCP, TCP_FASTOPEN) => s.fast_open_limit,
                    (IPPROTO_TCP, TCP_FASTOPEN_CONNECT) => s.fast_open_connect as i32,
                    (IPPROTO_TCP, TCP_MAXSEG) => match s.handle {
                        Handle::Connection(cid) => {
                            self.endpoint.transport_info(cid).map_err(engine)?.mss as i32
                        }
                        _ => s.user_mss.map_or(
                            i32::from(
                                self.defaults
                                    .connection
                                    .mss
                                    .min(self.defaults.connection.send_ip_payload_limit - 20),
                            ),
                            i32::from,
                        ),
                    },
                    (IPPROTO_TCP, TCP_NODELAY) => s.nodelay as i32,
                    (IPPROTO_TCP, TCP_CORK) => s.cork as i32,
                    (IPPROTO_TCP, TCP_INQ) => s.inq as i32,
                    (IPPROTO_TCP, TCP_NOTSENT_LOWAT) => s.notsent_lowat as i32,
                    // Zero reports no application override, not Linux's default count.
                    (IPPROTO_TCP, TCP_SYNCNT) => s.syn_retries.map_or(0, |n| i32::from(n.get())),
                    (IPPROTO_TCP, TCP_USER_TIMEOUT) => s.user_timeout_ms,
                    (IPPROTO_IP, IP_FREEBIND) | (IPPROTO_IPV6, IPV6_FREEBIND) => s.freebind as i32,
                    (IPPROTO_IP, IP_TOS) => s.tos as i32,
                    //= https://www.rfc-editor.org/rfc/rfc3542#section-4
                    //= reason=For selected IPV6_TCLASS, readback returns the stored DSCP bits with the two ECN bits cleared, not the exact integer supplied when user ECN bits are nonzero. Section 6.5 expressly permits overriding outgoing ECN bits, but does not expressly permit changing this sticky readback contract. Preserve the full readback obligation as TODO; tests pin exact masked readback for all values. Other advanced options are outside the selected capability.
                    //# Issuing getsockopt() for the above options will return the
                    //# sticky option value i.e., the value set with setsockopt().
                    //= https://www.rfc-editor.org/rfc/rfc3542#section-4
                    //# For the IPV6_TCLASS option, it will return the kernel default
                    //# value.
                    (IPPROTO_IPV6, IPV6_TCLASS) => s.ipv6_tclass as i32,
                    (IPPROTO_IP, IP_MTU_DISCOVER) => s.discover,
                    (IPPROTO_IPV6, IPV6_MTU_DISCOVER) => s.ipv6_discover,
                    (IPPROTO_IP, IP_MTU) | (IPPROTO_IPV6, IPV6_MTU) => {
                        let Handle::Connection(cid) = s.handle else {
                            return Err(ENOTCONN);
                        };
                        self.endpoint
                            .path_mtu_info(cid)
                            .map_err(engine)?
                            .ok_or(EOPNOTSUPP)?
                            .current_mtu as i32
                    }
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
                    if let Some(peer) = s.deferred_peer {
                        out.addr = Some(s.api_address(peer));
                        return Ok(out);
                    }
                    let Handle::Connection(cid) = s.handle else {
                        return Err(ENOTCONN);
                    };
                    if !s.connected {
                        return Err(ENOTCONN);
                    }
                    s.api_address(self.endpoint.tuple(cid).map_err(engine)?.remote)
                } else if !matches!(s.handle, Handle::Connection(_)) && s.bound_addr.is_some() {
                    s.bound_addr.unwrap()
                } else {
                    s.local
                        .map(|local| s.api_address(local))
                        .unwrap_or_else(|| SocketAddr::new(s.api_unspecified(), 0))
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
                out.value = self.refresh_readiness(id)?;
                out.readiness_generations = self.sockets[&id].readiness_generations;
            }
            Op::Inq(consumed) => {
                let Handle::Connection(cid) = s.handle else {
                    return Err(ENOTCONN);
                };
                out.timeout_us = u64::from(s.inq);
                if s.inq {
                    let state = self.endpoint.state(cid).map_err(engine)?;
                    let available = if state == State::Closed {
                        self.endpoint.terminal_readable_bytes(cid)
                    } else {
                        self.endpoint.readable_bytes(cid)
                    }
                    .map_err(engine)?;
                    out.value = available
                        .saturating_sub(consumed)
                        .saturating_add(usize::from(s.peer_fin))
                        .min(i32::MAX as usize) as i32;
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
            Op::FinishConnect => self.complete_connect(id)?,
            Op::Wait(_, _) => unreachable!(),
            Op::New(_)
            | Op::NewDomain(..)
            | Op::SetFastOpenClientEnabled(_)
            | Op::SetFastOpenClientDefaultPolicy(_)
            | Op::SetDestinationRoute(..) => {
                unreachable!()
            }
            #[cfg(feature = "packet-test")]
            Op::Inject(_)
            | Op::InjectSegmented(..)
            | Op::Capture(_)
            | Op::LocalResourceReject(_)
            | Op::TimestampDefault(_)
            | Op::ClearFastOpenClientCache
            | Op::ListenerPresent(_) => unreachable!(),
        }
        Ok(out)
    }
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;

#[cfg(all(test, feature = "packet-test"))]
#[path = "packet_tests.rs"]
mod packet_tests;

#[cfg(test)]
#[path = "runtime_admission_tests.rs"]
mod admission_tests;

#[cfg(all(test, feature = "tfo-linux-cookie"))]
#[path = "runtime_cookie_policy_tests.rs"]
mod cookie_policy_tests;

#[cfg(test)]
#[path = "runtime_early_data_policy_tests.rs"]
mod early_data_policy_tests;

#[cfg(test)]
#[path = "runtime_ipv6_tests.rs"]
mod ipv6_tests;

#[cfg(all(test, feature = "packet-test"))]
#[path = "runtime_fast_open_tests.rs"]
mod fast_open_tests;

#[cfg(all(test, feature = "packet-test"))]
#[path = "runtime_adaptive_ack_profile_tests.rs"]
mod adaptive_ack_profile_tests;

#[cfg(all(test, feature = "packet-test"))]
#[path = "runtime_pmtud_profile_tests.rs"]
mod pmtud_profile_tests;

#[cfg(all(test, feature = "packet-test"))]
#[path = "runtime_icmp_tests.rs"]
mod icmp_tests;

#[cfg(all(test, feature = "packet-test"))]
#[path = "runtime_fast_open_mss_tests.rs"]
mod fast_open_mss;

#[cfg(all(test, feature = "packet-test"))]
#[path = "runtime_accept_reset_tests.rs"]
mod accept_reset;

#[cfg(all(test, feature = "packet-test"))]
#[path = "runtime_tfo_copied_completion_tests.rs"]
mod tfo_copied_completion;

#[cfg(all(test, feature = "packet-test"))]
#[path = "runtime_tfo_permission_tests.rs"]
mod client_tfo_permission;

#[cfg(all(test, feature = "packet-test"))]
#[path = "runtime_listener_query_tests.rs"]
mod listener_query;

#[path = "runtime_address.rs"]
mod address_policy;
use address_policy::binding_overlap;
