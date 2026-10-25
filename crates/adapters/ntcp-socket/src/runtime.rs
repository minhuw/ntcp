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
    Wait(Box<Op>, Option<std::time::Duration>),
    FinishConnect,
    SetFastOpenClientEnabled(bool),
    SetDestinationRoute(Ipv4Addr, Option<ntcp::RoutePolicy>),
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
    #[cfg(feature = "packet-test")]
    pub packet_mark: u32,
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
        Self::spawn(
            move || match config.io.backend {
                Backend::Tun => Owner::new(&config),
                Backend::AfPacket => Owner::af_packet(&config),
            },
            false,
        )
    }
    #[cfg(all(test, feature = "packet-test"))]
    pub fn packet(settings: (Ipv4Addr, crate::packet_profile::Profile)) -> Result<Self> {
        Self::packet_with_options(settings, crate::packet_test::Options::default())
    }
    #[cfg(feature = "packet-test")]
    pub fn packet_with_options(
        settings: (Ipv4Addr, crate::packet_profile::Profile),
        options: crate::packet_test::Options,
    ) -> Result<Self> {
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
    completions: VecDeque<Completion>,
    timestamps: TimestampState,
}
impl Socket {
    fn new(flags: i32) -> Self {
        Self {
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
fn submit_packet(
    io: &mut impl PacketIo,
    packet: &mut Option<Vec<u8>>,
) -> std::io::Result<TxOutcome> {
    let outcome = io.transmit(packet.as_ref().unwrap())?;
    if outcome == TxOutcome::Submitted {
        *packet = None;
    }
    Ok(outcome)
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
type ChildOptionsSnapshot = (ConnectionId, u64, u64, u64, (bool, bool, bool, u32, bool));

struct Owner {
    endpoint: Endpoint,
    defaults: EndpointConfig,
    socket_policy: crate::SocketPolicy,
    tun: Option<Tun>,
    ethernet: Option<backend::EthernetBackend>,
    sockets: BTreeMap<u64, Socket>,
    local: Ipv4Addr,
    epoch: Instant,
    #[cfg(test)]
    test_now: Option<u64>,
    next_port: u16,
    next_id: u64,
    detached: Vec<ConnectionId>,
    egress: Option<egress::Egress>,
    // Legacy direct-poll fixtures only; native Egress never fills this carrier.
    pending_packet: Option<Vec<u8>>,
    pending_token: Option<ntcp::TxTimestampToken>,
    reservations: bool,
    reservation: Option<ntcp::TransmitAttempt>,
    reservation_owner: Option<ConnectionId>,
    reservation_deadline: Option<u64>,
    reservation_timeout_us: u64,
    waiting_mtu: bool,
    mtu_refresh: Option<output::MtuRefresh>,
    timestamp_cookie: u64,
    child_timestamps: Vec<(ConnectionId, crate::timestamping::Options)>,
    pending: VecDeque<Request>,
    child_timeouts: Vec<ChildOptionsSnapshot>,
    connection_options: Vec<(ConnectionId, u8, i32, Option<bool>, u32)>,
    #[cfg(feature = "packet-test")]
    packets: Option<PacketBackend>,
}
fn unicast(ip: Ipv4Addr) -> bool {
    ip.octets()[0] != 0 && ip.octets()[0] < 224 && !ip.is_loopback()
}
fn context(io: &crate::IoConfig) -> Result<(Ipv4Addr, u8)> {
    let (name, local, requested) = (&io.interface, io.address, io.prefix);
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
        let tcp = backend::backend_config(config.tcp.clone(), &tun)?;
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
                .set_destination_route(now, destination.into(), Some(policy))
                .map_err(engine)?;
        }
        Ok(())
    }
    fn with_config(
        local: Ipv4Addr,
        (address, prefix): (Ipv4Addr, u8),
        secret: [u8; 32],
        tun: Option<Tun>,
        config: EndpointConfig,
    ) -> Result<Self> {
        let defaults = config.clone();
        let valid = move |ip: IpAddr| {
            matches!(ip, IpAddr::V4(ip) if unicast(ip)
            && (prefix > 30 || u32::from(ip) != u32::from(address) | (u32::MAX.checked_shr(prefix as u32).unwrap_or(0))))
        };
        let endpoint = Endpoint::new(config, secret, 0, move |r| match r {
            AddressValidation::Bind { local: bind } => {
                // Per-socket local-address permission is checked by Op::Bind.
                // FREEBIND does not relax Open, Incoming, or Route policy.
                bind.is_unspecified() || valid(bind)
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
            pending_packet: None,
            pending_token: None,
            reservations: false,
            reservation: None,
            reservation_owner: None,
            reservation_deadline: None,
            reservation_timeout_us: 1_000_000,
            waiting_mtu: false,
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
    fn packet(settings: (Ipv4Addr, crate::packet_profile::Profile)) -> Result<Self> {
        Self::packet_with_options(settings, crate::packet_test::Options::default())
    }
    #[cfg(feature = "packet-test")]
    fn packet_with_options(
        (local, profile): (Ipv4Addr, crate::packet_profile::Profile),
        options: crate::packet_test::Options,
    ) -> Result<Self> {
        options.validate()?;
        // Deterministic key and synthetic address policy are explicit test-only
        // settings, never a production entropy source or TUN routing policy.
        let mut owner = Self::with_config(
            local,
            (local, 32),
            [42; 32],
            None,
            SocketConfig::new("test", local).tcp,
        )?;
        owner.endpoint = Endpoint::new(
            crate::packet_profile::config(profile),
            [42; 32],
            0,
            move |r| match r {
                AddressValidation::Bind { local: addr } => {
                    addr.is_unspecified() || matches!(addr, IpAddr::V4(ip) if unicast(ip))
                }
                AddressValidation::Open { local: addr, .. } => addr == IpAddr::V4(local),
                AddressValidation::Incoming { destination, .. } => destination == IpAddr::V4(local),
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
        owner.packets = Some(PacketBackend::new(profile, options.queue_capacity)?);
        owner.enable_egress(options.egress_capacity, crate::packet_profile::gso(profile))?;
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
            socket.user_mss = config.connection.user_mss;
            if matches!(packets.profile, crate::packet_profile::Profile::Upstream(o) if o.tfo_listen)
            {
                socket.fast_open_limit = config.max_connections as i32;
            }
            return socket;
        }
        let mut socket = Socket::new(flags);
        let c = &self.defaults.connection;
        socket.send_capacity = c.send_capacity;
        socket.receive_capacity = c.receive_capacity;
        socket.user_mss = c.user_mss;
        socket.nodelay = !c.nagle;
        socket.tos = self.defaults.dscp << 2;
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
            Op::SetFastOpenClientEnabled(_) | Op::SetDestinationRoute(..)
        ) {
            return true;
        }
        #[cfg(feature = "packet-test")]
        if self.packet_backend()
            && matches!(
                op,
                Op::Inject(_)
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
            let checksum = ntcp_ip_common::checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        Ok(packet)
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
        20 + usize::from(self.defaults.connection.send_ip_payload_limit)
            .min(usize::from(self.defaults.connection.mss) + 60)
            .min(65515)
    }
    // Select at current time, never at a future pacing deadline. Reserved departure
    // commits only at backend acceptance; retain the same bytes through WouldBlock.
    fn prepare_packet(&mut self, transmit_now: Option<u64>) -> Result<bool> {
        if self.pending_packet.is_some() {
            return Ok(true);
        }
        if self.waiting_mtu {
            return Ok(false);
        }
        let mut packet = vec![0; self.output_packet_len()];
        let pair = ClockPair::sample(self);
        let now = transmit_now.unwrap_or_else(|| self.now());
        let tx = if self.reservations {
            match self
                .endpoint
                .poll_reserved_transmit(now, &mut packet[20..], BUDGET)
            {
                Ok((output, attempt)) => {
                    if let Some(attempt) = attempt {
                        self.reservation = Some(attempt);
                    }
                    output.packet
                }
                Err(EndpointError::ReservationMtuTooSmall) => {
                    self.abandon_reservation()?;
                    return Ok(false);
                }
                Err(e) => return Err(engine(e)),
            }
        } else {
            self.endpoint
                .poll_transmit(now, &mut packet[20..], BUDGET)
                .map_err(engine)?
                .packet
        };
        let Some(tx) = tx else {
            return Ok(false);
        };
        if self.reservations {
            self.reservation_owner = tx.connection;
        }
        packet = self.frame(tx, &packet[20..20 + tx.len])?;
        self.timestamp_packet(tx.tx_timestamp, &packet);
        self.drain_timestamps(pair);
        self.pending_token = tx.tx_timestamp;
        self.pending_packet = Some(packet);
        Ok(true)
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
        let mut input = vec![0; 65535 + if self.ethernet.is_some() { 14 } else { 0 }];
        // Keep in-flight batches owned through every output/backend exit.
        let mut after_output = Vec::with_capacity(BUDGET);
        'run: while !stop.load(Ordering::Acquire) {
            self.poll_mtu_refresh();
            if self.expire_reservation(self.now()).is_err() {
                break;
            }
            let now = self.now();
            if self.reservation.is_none() && self.endpoint.on_timeout(now, BUDGET).is_err() {
                break;
            }
            if self.receive_batch(&mut input).is_err() || self.poll_backend_timestamps().is_err() {
                break 'run;
            }
            self.events();
            self.service_before_output(&mut after_output);
            if self.egress.is_some() {
                if self.service_egress().is_err() {
                    break 'run;
                }
            } else {
                for _ in 0..BUDGET {
                    match self.prepare_packet(None) {
                        Ok(true) => (),
                        Ok(false) => break,
                        Err(_) => break 'run,
                    }
                    // Backend acceptance is the only success boundary, including late accepts.
                    if self.tun.is_some() || self.ethernet.is_some() {
                        match self.submit_reserved_packet() {
                            Ok(TxOutcome::Submitted) => (),
                            Ok(TxOutcome::WouldBlock | TxOutcome::Rejected) => break,
                            Err(_) => break 'run,
                        }
                    }
                }
            }
            self.events();
            for (mut request, retried) in after_output.drain(..) {
                if retried || !self.service(&mut request) {
                    self.pending.push_back(request);
                }
            }
            self.connection_options
                .retain(|p| self.endpoint.connection_exists(p.0));
            if self.reservation.is_none() {
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
            }
            // Bounded owner work and a 1ms ceiling also cover shared wakefd consumers.
            let wait = self.output_wait();
            // Keep admission open while teardown has room; packet capture must
            // always remain reachable to free held output.
            if !self.packet_backend()
                && self.pending.len() >= 2 * self.socket_limit()
                && (self.reservation.is_some()
                    || self.egress.as_ref().is_some_and(|e| e.has_held()))
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
    fn input_stamped(
        &mut self,
        now: u64,
        ip: ntcp::IpMetadata,
        traffic_class: u8,
        bytes: &[u8],
        stamps: ntcp::RxPacketTimestamps,
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
                        && s.local.is_some_and(|local| {
                            local.port() == tuple.local.port()
                                && (local.ip().is_unspecified() || local == tuple.local)
                        })
                })
                .map(|s| (s.tos, s.discover, s.zerocopy, s.mark))
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
        let result = self.endpoint.input_with_timestamps(
            now,
            ip,
            traffic_class,
            ntcp::Ipv4Options::default(),
            bytes,
            stamps,
        );
        self.drain_timestamps(pair);
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
            self.child_timestamps.push((cid, s.timestamps.options));
            self.child_timeouts.push((
                cid,
                listener,
                s.receive_timeout_us,
                s.send_timeout_us,
                (s.nodelay, s.cork, s.inq, s.notsent_lowat, s.freebind),
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
        if self.reservation.is_some() {
            return;
        }
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
        self.endpoint.set_dscp(cid, s.tos >> 2).map_err(engine)?;
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
    fn execute(&mut self, id: u64, op: Op) -> Result<Reply> {
        if let Op::SetDestinationRoute(destination, policy) = op {
            if !unicast(destination) {
                return Err(EINVAL);
            }
            self.endpoint
                .set_destination_route(self.now(), destination.into(), policy)
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
        #[cfg(feature = "packet-test")]
        match &op {
            Op::Inject(bytes) => {
                if self.packets.is_none() {
                    return Err(EOPNOTSUPP);
                }
                if bytes.len() > crate::packet_profile::BYTES {
                    return Err(EMSGSIZE);
                }
                crate::packet_profile::validate_injection(bytes)?;
                // Admission is not TCP processing: retained RX may delay delivery.
                let Op::Inject(bytes) = op else {
                    unreachable!()
                };
                self.packets.as_mut().unwrap().inject(bytes)?;
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
                if !matches!(s.handle, Handle::Fresh)
                    || s.local.is_some()
                    || s.deferred_peer.is_some()
                {
                    return Err(EINVAL);
                }
                if !s.freebind && addr.ip() != IpAddr::V4(self.local) && !addr.ip().is_unspecified()
                {
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
                    None => SocketAddr::new(self.local.into(), self.port()?),
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
                    let (_, _, receive, send, (nodelay, cork, inq, lowat, freebind)) =
                        self.child_timeouts.swap_remove(index);
                    child.receive_timeout_us = receive;
                    child.send_timeout_us = send;
                    child.nodelay = nodelay;
                    child.cork = cork;
                    child.inq = inq;
                    child.notsent_lowat = lowat;
                    child.freebind = freebind;
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
                    child.tos = p.1;
                    child.discover = p.2;
                    child.zerocopy = p.3.unwrap_or(false);
                    child.mark = p.4;
                }
                if let Some(index) = self.child_timestamps.iter().position(|p| p.0 == cid) {
                    child.timestamps.options = self.child_timestamps.swap_remove(index).1;
                }
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
                out.addr = Some(tuple.remote);
                // Core emits Acceptable on empty->nonempty; stay readable until accept returns EAGAIN.
            }
            Op::Connect(remote) => {
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
                    if self
                        .endpoint
                        .can_defer_fast_open(self.now(), local.ip(), remote)
                        .map_err(engine)?
                    {
                        let s = self.sockets.get_mut(&id).unwrap();
                        s.local = Some(local);
                        s.deferred_peer = Some(remote);
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
                        copy_completion(p, load(p)?, (*lo, *hi))?;
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
            Op::Set(level, name, value) => {
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
                    (IPPROTO_IP, IP_FREEBIND) => s.freebind = value != 0,
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
                        (IPPROTO_IP, IP_TOS) => {
                            self.endpoint.set_dscp(cid, s.tos >> 2).map_err(engine)?
                        }
                        _ => (),
                    }
                }
                if let Handle::Connection(cid) = s.handle
                    && let Some(p) = self.connection_options.iter_mut().find(|p| p.0 == cid)
                {
                    p.1 = s.tos;
                    p.2 = s.discover;
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
            Op::Get(level, name) => {
                let s = self.sockets.get_mut(&id).unwrap();
                out.value = match (level, name) {
                    (SOL_SOCKET, SO_TYPE) => SOCK_STREAM,
                    (SOL_SOCKET, SO_DOMAIN) => AF_INET,
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
                    (IPPROTO_IP, IP_FREEBIND) => s.freebind as i32,
                    (IPPROTO_IP, IP_TOS) => s.tos as i32,
                    (IPPROTO_IP, IP_MTU_DISCOVER) => s.discover,
                    (IPPROTO_IP, IP_MTU) => {
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
                        out.addr = Some(peer);
                        return Ok(out);
                    }
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
            Op::New(_) | Op::SetFastOpenClientEnabled(_) | Op::SetDestinationRoute(..) => {
                unreachable!()
            }
            #[cfg(feature = "packet-test")]
            Op::Inject(_)
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
mod tests {
    use super::*;
    include!("timestamp_tests.rs");
    include!("large_write_tests.rs");
    include!("file_transfer_tests.rs");
    include!("runtime_pacing_tests.rs");
    include!("runtime_lowat_tests.rs");
    include!("runtime_accounting_expectations_tests.rs");
    #[cfg(feature = "packet-test")]
    mod lowat_upstream_study {
        include!("runtime_lowat_upstream_tests.rs");
    }
    #[cfg(feature = "packet-test")]
    mod timestamp_partial_study {
        include!("runtime_timestamp_partial_tests.rs");
    }
    include!("runtime_syncnt_tests.rs");
    include!("runtime_mss_mark_tests.rs");
    mod route_policy {
        include!("runtime_route_tests.rs");
    }
    fn owner(last: u8) -> Owner {
        owner_with_config(
            last,
            SocketConfig::new("test", Ipv4Addr::new(10, 73, 0, last)).tcp,
        )
    }
    fn owner_with_config(last: u8, config: EndpointConfig) -> Owner {
        let local = Ipv4Addr::new(10, 73, 0, last);
        Owner::with_config(
            local,
            (Ipv4Addr::new(10, 73, 0, 1), 24),
            [last; 32],
            None,
            config,
        )
        .unwrap()
    }
    pub(super) fn new(o: &mut Owner, flags: i32) -> u64 {
        o.execute(0, Op::New(flags)).unwrap().value as u64
    }
    pub(super) fn pump(a: &mut Owner, b: &mut Owner) {
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
                    let pair = ClockPair::sample(from);
                    let p = from
                        .endpoint
                        .poll_transmit(from.now(), &mut bytes, 32)
                        .unwrap();
                    let Some(p) = p.packet else {
                        break;
                    };
                    let frame = from.frame(p, &bytes[..p.len]).unwrap();
                    from.timestamp_packet(p.tx_timestamp, &frame);
                    from.drain_timestamps(pair);
                    from.software_transmitted(p.tx_timestamp, timestamps::realtime());
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
    pub(super) fn pair() -> (Owner, Owner, u64, u64, u64) {
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
    #[cfg(feature = "packet-test")]
    #[test]
    fn timestamp_default_control_rejects_non_packet_backend() {
        let mut owner = owner(2);
        assert!(owner.packets.is_none());
        for enabled in [false, true] {
            assert_eq!(
                owner.execute(0, Op::TimestampDefault(enabled)).err(),
                Some(EOPNOTSUPP)
            );
        }
        assert_eq!(
            owner.execute(0, Op::ClearFastOpenClientCache).err(),
            Some(EOPNOTSUPP)
        );
        assert_eq!(
            owner.execute(0, Op::ListenerPresent(8080)).err(),
            Some(EOPNOTSUPP)
        );
    }

    #[test]
    fn client_tfo_permission_native_configuration_and_management() {
        let mut owner = owner(2);
        let mut config = SocketConfig::new("test", Ipv4Addr::new(10, 73, 0, 2));
        config.socket.fast_open_client_enabled = false;
        owner.apply_socket_config(&config).unwrap();
        let id = new(&mut owner, SOCK_NONBLOCK);
        assert_eq!(
            owner
                .execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                .unwrap_err(),
            EOPNOTSUPP
        );
        owner
            .execute(0, Op::SetFastOpenClientEnabled(true))
            .unwrap();
        assert_eq!(
            owner
                .execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                .unwrap()
                .value,
            0
        );
    }

    #[test]
    fn client_tfo_permission_management_progresses_with_full_waiter_queue() {
        let (mut a, _b, client, _, _) = pair();
        a.execute(client, Op::Flags(F_SETFL, 0)).unwrap();
        let (reply, _) = mpsc::sync_channel(1);
        for _ in 0..a.socket_limit() {
            let mut request = Request {
                id: client,
                op: Op::Wait(Box::new(Op::Read(1)), None),
                reply: reply.clone(),
                deadline: None,
                send: None,
                closing: None,
            };
            assert!(!a.service(&mut request));
            a.pending.push_back(request);
        }
        let (reply, result) = mpsc::sync_channel(1);
        let mut control = Request {
            id: 0,
            op: Op::SetFastOpenClientEnabled(false),
            reply,
            deadline: None,
            send: None,
            closing: None,
        };
        assert_eq!(a.pending.len(), a.socket_limit());
        assert!(!a.admission_full(&control));
        assert!(a.service(&mut control));
        assert!(result.try_recv().unwrap().is_ok());
        assert!(!a.socket_policy.fast_open_client_enabled);
        assert_eq!(a.pending.len(), a.socket_limit());
    }

    #[test]
    fn tcp_info_prefix_survives_ambiguous_data_fin_delivery() {
        use ntcp::wire::{self, ACK, FIN, SYN};
        let mut config = SocketConfig::new("test", Ipv4Addr::new(10, 73, 0, 2)).tcp;
        config.connection.sack = true;
        config.connection.tlp = false;
        config.connection.timestamps = false;
        let mut owner = owner_with_config(2, config);
        owner.test_now = Some(0);
        let id = new(&mut owner, SOCK_NONBLOCK);
        assert_eq!(
            owner
                .execute(id, Op::Connect("10.73.0.3:2000".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        let Handle::Connection(cid) = owner.sockets[&id].handle else {
            panic!()
        };
        let mut out = [0; 2048];
        let tx = owner
            .endpoint
            .poll_transmit(0, &mut out, 16)
            .unwrap()
            .packet
            .unwrap();
        let syn = wire::parse(tx.ip, &out[..tx.len]).unwrap().header;
        let base = syn.sequence.wrapping_add(1);
        let ip = ntcp::IpMetadata {
            source: tx.ip.destination,
            destination: tx.ip.source,
        };
        let mut ack = wire::Header {
            source_port: syn.destination_port,
            destination_port: syn.source_port,
            sequence: 100,
            acknowledgment: base,
            flags: SYN | ACK,
            window: 32000,
            urgent_pointer: 0,
        };
        let input = |owner: &mut Owner, now, header, options: &[u8]| {
            let mut bytes = [0; 64];
            let len = wire::encode(ip, header, options, &[], &mut bytes).unwrap();
            owner.endpoint.input(now, ip, &bytes[..len]).unwrap();
        };
        input(&mut owner, 10, ack, &[1, 1, 4, 2]);
        owner.endpoint.poll_transmit(20, &mut out, 16).unwrap();
        owner.test_now = Some(20);
        let full = owner.execute(id, Op::Transport(1)).unwrap().bytes;
        assert_eq!(full.len(), 280);
        for requested in [0, 1, 192, 193, 280, 512] {
            assert_eq!(
                owner
                    .execute(id, Op::TransportPrefix(1, requested))
                    .unwrap()
                    .bytes,
                full[..requested.min(280)]
            );
        }
        // SACK data sent separately from FIN, then retransmit them together.
        // The core cannot attribute the combined retry to one delivery packet.
        owner.endpoint.write(cid, &[0; 100]).unwrap();
        let tx = owner
            .endpoint
            .poll_transmit(100, &mut out, 16)
            .unwrap()
            .packet
            .unwrap();
        assert_eq!(
            wire::parse(tx.ip, &out[..tx.len]).unwrap().payload.len(),
            100
        );
        owner.endpoint.shutdown(cid).unwrap();
        let tx = owner
            .endpoint
            .poll_transmit(100, &mut out, 16)
            .unwrap()
            .packet
            .unwrap();
        let fin = wire::parse(tx.ip, &out[..tx.len]).unwrap();
        assert!(fin.payload.is_empty());
        assert_ne!(fin.header.flags & FIN, 0);
        ack.sequence = 101;
        ack.flags = ACK;
        let mut sack = vec![5, 10];
        sack.extend_from_slice(&base.to_be_bytes());
        sack.extend_from_slice(&base.wrapping_add(100).to_be_bytes());
        sack.extend_from_slice(&[1, 1]);
        input(&mut owner, 200, ack, &sack);
        let deadline = owner.endpoint.next_deadline().unwrap();
        owner.endpoint.on_timeout(deadline, 16).unwrap();
        let tx = owner
            .endpoint
            .poll_transmit(deadline, &mut out, 16)
            .unwrap()
            .packet
            .unwrap();
        let retry = wire::parse(tx.ip, &out[..tx.len]).unwrap();
        assert_eq!(retry.payload.len(), 100);
        assert_ne!(retry.header.flags & FIN, 0);
        owner.test_now = Some(deadline);
        let info = owner.endpoint.transport_info(cid).unwrap();
        assert!(info.ledger_valid);
        assert!(info.delivered_segments_valid);
        let prefix = owner
            .execute(id, Op::TransportPrefix(1, 280))
            .unwrap()
            .bytes;
        assert_eq!(prefix.len(), 280);
        assert_eq!(prefix[0], 4); // FIN_WAIT1
        for requested in [0, 1, 7, 191] {
            assert_eq!(
                owner
                    .execute(id, Op::TransportPrefix(1, requested))
                    .unwrap()
                    .bytes,
                prefix[..requested]
            );
        }
        for requested in [193, 280, 512] {
            assert_eq!(
                owner
                    .execute(id, Op::TransportPrefix(1, requested))
                    .unwrap()
                    .bytes,
                prefix[..requested.min(280)]
            );
        }
        assert_eq!(owner.execute(id, Op::Transport(1)).unwrap().bytes, prefix);
        assert!(
            owner
                .execute(id, Op::Transport(2))
                .unwrap()
                .bytes
                .is_empty()
        );
    }

    #[test]
    fn errorqueue_fault_preserves_entry_and_short_control_consumes() {
        let (mut owner, _peer, client, _, _) = pair();
        owner
            .execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
            .unwrap();
        for capacity in 0..=56 {
            let before = owner
                .execute(client, Op::Ready)
                .unwrap()
                .readiness_generations[2];
            owner
                .execute(client, Op::WriteFlags(vec![1], MSG_ZEROCOPY))
                .unwrap();
            let ready = owner.execute(client, Op::Ready).unwrap();
            assert_ne!(ready.value & EPOLLERR, 0);
            assert_ne!(ready.readiness_generations[2], before);
            let mut header: msghdr = unsafe { std::mem::zeroed() };
            header.msg_control = std::ptr::dangling_mut::<c_void>();
            header.msg_controllen = 48;
            let address = (&mut header as *mut msghdr) as usize;
            assert_eq!(
                owner
                    .execute(client, Op::ErrorQueueTo(address))
                    .unwrap_err(),
                EFAULT
            );
            assert_eq!(owner.sockets[&client].completions.len(), 1);
            assert_ne!(
                owner.execute(client, Op::Ready).unwrap().value & EPOLLERR,
                0
            );
            let mut control = [0xa5u8; 64];
            header.msg_control = control.as_mut_ptr().cast();
            header.msg_controllen = capacity;
            owner.execute(client, Op::ErrorQueueTo(address)).unwrap();
            assert_eq!(
                header.msg_flags,
                MSG_ERRQUEUE | if capacity < 48 { MSG_CTRUNC } else { 0 }
            );
            assert_eq!(
                header.msg_controllen,
                if capacity < 16 { 0 } else { capacity.min(48) }
            );
            assert!(control[capacity..].iter().all(|b| *b == 0xa5));
            assert!(owner.sockets[&client].completions.is_empty());
            assert_eq!(
                owner.execute(client, Op::Ready).unwrap().value & EPOLLERR,
                0
            );
            assert_eq!(
                owner
                    .execute(client, Op::ErrorQueueTo(address))
                    .unwrap_err(),
                EAGAIN
            );
        }
    }
    #[test]
    fn new_data_generations_and_post_read_inq_fin() {
        let (mut a, mut b, client, server, _) = pair();
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
            .unwrap();
        b.execute(server, Op::Set(IPPROTO_TCP, TCP_INQ, 1)).unwrap();
        a.execute(client, Op::Write(b"abcdef".to_vec())).unwrap();
        pump(&mut a, &mut b);
        let first = b.execute(server, Op::Ready).unwrap();
        assert_ne!(first.value & EPOLLIN, 0);
        for _ in 0..32 {
            assert_eq!(
                b.execute(server, Op::Ready).unwrap().readiness_generations,
                first.readiness_generations
            );
        }
        assert_eq!(b.execute(server, Op::Inq(0)).unwrap().value, 6);
        assert_eq!(b.execute(server, Op::Inq(2)).unwrap().value, 4);
        assert_eq!(b.execute(server, Op::Peek(2)).unwrap().bytes, b"ab");
        assert_eq!(b.execute(server, Op::Inq(0)).unwrap().value, 6);
        b.execute(server, Op::Read(2)).unwrap();
        assert_eq!(
            b.execute(server, Op::Ready).unwrap().readiness_generations,
            first.readiness_generations
        );
        a.execute(client, Op::Write(b"ghi".to_vec())).unwrap();
        pump(&mut a, &mut b);
        let next = b.execute(server, Op::Ready).unwrap();
        assert_ne!(
            next.readiness_generations[0],
            first.readiness_generations[0]
        );
        assert_eq!(b.execute(server, Op::Inq(0)).unwrap().value, 7);
        a.execute(client, Op::Shutdown(SHUT_WR)).unwrap();
        pump(&mut a, &mut b);
        assert_eq!(b.execute(server, Op::Inq(0)).unwrap().value, 8);
        assert_eq!(b.execute(server, Op::Inq(7)).unwrap().value, 1);
        assert_eq!(b.execute(server, Op::Read(32)).unwrap().bytes, b"cdefghi");
        assert_eq!(b.execute(server, Op::Read(32)).unwrap().value, 0);
        assert_eq!(b.execute(server, Op::Inq(0)).unwrap().value, 1);
    }
    #[test]
    fn inq_reset_error_consumption_never_fabricates_fin() {
        for via_so_error in [false, true] {
            let (mut a, mut b, client, server, _) = pair();
            b.execute(server, Op::Set(IPPROTO_TCP, TCP_INQ, 1)).unwrap();
            a.execute(client, Op::Write(b"ab".to_vec())).unwrap();
            pump(&mut a, &mut b);
            let Handle::Connection(cid) = a.sockets[&client].handle else {
                panic!()
            };
            a.endpoint.abort(cid).unwrap();
            pump(&mut a, &mut b);
            assert_eq!(b.execute(server, Op::Inq(0)).unwrap().value, 2);
            assert_eq!(b.execute(server, Op::Read(2)).unwrap().bytes, b"ab");
            assert_eq!(b.execute(server, Op::Inq(0)).unwrap().value, 0);
            if via_so_error {
                assert_eq!(
                    b.execute(server, Op::Get(SOL_SOCKET, SO_ERROR))
                        .unwrap()
                        .value,
                    ECONNRESET
                );
            } else {
                assert_eq!(b.execute(server, Op::Read(1)).unwrap_err(), ECONNRESET);
            }
            assert_eq!(b.execute(server, Op::Read(1)).unwrap().value, 0);
            assert_eq!(b.execute(server, Op::Inq(0)).unwrap().value, 0);
        }
        let (mut a, mut b, client, server, _) = pair();
        b.execute(server, Op::Set(IPPROTO_TCP, TCP_INQ, 1)).unwrap();
        a.execute(client, Op::Shutdown(SHUT_WR)).unwrap();
        pump(&mut a, &mut b);
        b.execute(server, Op::Shutdown(SHUT_WR)).unwrap();
        pump(&mut a, &mut b);
        let Handle::Connection(cid) = b.sockets[&server].handle else {
            panic!()
        };
        assert_eq!(b.endpoint.state(cid).unwrap(), State::Closed);
        assert_eq!(b.execute(server, Op::Read(1)).unwrap().value, 0);
        assert_eq!(
            b.execute(server, Op::Get(SOL_SOCKET, SO_ERROR))
                .unwrap()
                .value,
            0
        );
        assert_eq!(b.execute(server, Op::Inq(0)).unwrap().value, 1);
    }
    #[test]
    fn lowwater_sets_notify_independent_writable_registrations() {
        let (mut a, _b, client, _, _) = pair();
        let mut first = a.execute(client, Op::Ready).unwrap().readiness_generations;
        let mut second = first;
        for value in [4000, 4000, -1, 0] {
            a.execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, value))
                .unwrap();
            let ready = a.execute(client, Op::Ready).unwrap();
            assert_ne!(ready.value & EPOLLOUT, 0);
            assert!(socket_options::edge_changed(
                EPOLLOUT as u32,
                Some(first),
                ready.readiness_generations
            ));
            first = ready.readiness_generations;
            assert!(!socket_options::edge_changed(
                EPOLLOUT as u32,
                Some(first),
                ready.readiness_generations
            ));
            // Consuming one registration must not consume another's edge.
            assert!(socket_options::edge_changed(
                EPOLLOUT as u32,
                Some(second),
                ready.readiness_generations
            ));
            second = ready.readiness_generations;
        }
    }
    #[test]
    fn lowwater_bounds_batch_before_copy_and_preserves_hysteresis() {
        let (mut a, _b, client, _, _) = pair();
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_CORK, 1))
            .unwrap();
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, 4000))
            .unwrap();
        assert_eq!(
            a.execute(client, Op::WriteFlags(vec![1; 1999], MSG_MORE))
                .unwrap()
                .value,
            1999
        );
        assert_ne!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
        assert_eq!(
            a.execute(client, Op::WriteFlags(vec![2], MSG_MORE))
                .unwrap()
                .value,
            1
        );
        // Readiness retains the independent half-threshold rule.
        assert_eq!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
        let Handle::Connection(cid) = a.sockets[&client].handle else {
            panic!()
        };
        let goal = send::batch_goal(&a.endpoint.transport_info(cid).unwrap());
        let tail = vec![3; goal];
        // Bytes outside the batch prefix must not be dereferenced.
        let sources = vec![(tail.as_ptr() as usize, tail.len()), (0, 1)];
        assert_eq!(
            a.execute(client, Op::Send(sources, MSG_MORE | MSG_EOR))
                .unwrap()
                .value as usize,
            goal - 2000
        );
        assert_eq!(a.execute(client, Op::Write(vec![4])).unwrap_err(), EAGAIN);
        assert_eq!(a.endpoint.transport_info(cid).unwrap().notsent_bytes, goal);
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, -1))
            .unwrap();
        assert_eq!(
            a.execute(client, Op::Write(vec![4; 20000])).unwrap().value,
            20000
        );
    }

    #[test]
    fn lowwater_tracks_unsent_not_unacked_and_option_wakes() {
        let (mut a, _b, client, _, _) = pair();
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
            .unwrap();
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, 4000))
            .unwrap();
        assert_eq!(
            a.execute(client, Op::WriteFlags(vec![1; 4000], MSG_EOR))
                .unwrap()
                .value,
            4000
        );
        let blocked = a.execute(client, Op::Ready).unwrap();
        assert_eq!(blocked.value & EPOLLOUT, 0);
        assert_eq!(a.execute(client, Op::Write(vec![2])).unwrap_err(), EAGAIN);
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, -1))
            .unwrap();
        let ready = a.execute(client, Op::Ready).unwrap();
        assert_ne!(ready.value & EPOLLOUT, 0);
        assert_ne!(
            ready.readiness_generations[1],
            blocked.readiness_generations[1]
        );
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, 4000))
            .unwrap();
        let Handle::Connection(cid) = a.sockets[&client].handle else {
            panic!()
        };
        let mut packet = [0; 65535];
        for _ in 0..8 {
            let _ = a.endpoint.poll_transmit(a.now(), &mut packet, 32).unwrap();
        }
        let info = a.endpoint.transport_info(cid).unwrap();
        assert_eq!(info.notsent_bytes, 0);
        assert_eq!(info.send_used, 4000); // No peer ACKs were delivered.
        a.events();
        assert_ne!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
    }
    #[test]
    fn stream_options_inherit_at_child_admission() {
        let mut a = owner(2);
        let mut b = owner(3);
        let listener = new(&mut b, 0);
        b.execute(listener, Op::Bind("10.73.0.3:16379".parse().unwrap()))
            .unwrap();
        for (option, value) in [
            (TCP_INQ, 1),
            (TCP_CORK, 1),
            (TCP_NODELAY, 1),
            (TCP_NOTSENT_LOWAT, -1),
        ] {
            b.execute(listener, Op::Set(IPPROTO_TCP, option, value))
                .unwrap();
        }
        b.execute(listener, Op::Listen(16)).unwrap();
        let client = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(client, Op::Connect("10.73.0.3:16379".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        pump(&mut a, &mut b);
        for option in [TCP_INQ, TCP_CORK, TCP_NODELAY, TCP_NOTSENT_LOWAT] {
            b.execute(listener, Op::Set(IPPROTO_TCP, option, 0))
                .unwrap();
        }
        let child = b.execute(listener, Op::Accept(0)).unwrap().value as u64;
        for (option, value) in [
            (TCP_INQ, 1),
            (TCP_CORK, 1),
            (TCP_NODELAY, 1),
            (TCP_NOTSENT_LOWAT, -1),
        ] {
            assert_eq!(
                b.execute(child, Op::Get(IPPROTO_TCP, option))
                    .unwrap()
                    .value,
                value
            );
        }
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
        let mut request = Request {
            id: client,
            op: Op::Wait(Box::new(Op::FinishConnect), None),
            reply,
            deadline: None,
            send: None,
            closing: None,
        };
        assert!(!a.service(&mut request));
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
        assert!(a.service(&mut request));
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
                send: None,
                closing: None,
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
        let mut config = SocketConfig::new("test", Ipv4Addr::new(10, 73, 0, 2)).tcp;
        // Budget for actual per-byte ledger storage: admit 2 MiB, but reject later growth.
        config.max_buffer_bytes = 160 * 1024 * 1024;
        let mut a = owner_with_config(2, config);
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

#[cfg(test)]
#[path = "runtime_admission_tests.rs"]
mod admission_tests;

#[cfg(all(test, feature = "tfo-linux-cookie"))]
#[path = "runtime_cookie_policy_tests.rs"]
mod cookie_policy_tests;
