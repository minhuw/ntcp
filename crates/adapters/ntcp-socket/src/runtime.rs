// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
#[path = "runtime_backend.rs"]
mod backend;
#[path = "runtime_egress.rs"]
mod egress;
#[path = "runtime_fast_open.rs"]
mod fast_open;
#[path = "runtime_output.rs"]
mod output;
#[path = "runtime_ports.rs"]
mod ports;
#[path = "runtime_send.rs"]
mod send;
#[path = "runtime_timestamping.rs"]
mod timestamps;
use crate::socket_options::{Linger, effective_notsent_lowat, notsent_writable};
use crate::*;
use ntcp::{
    AddressValidation, CloseReason, ConnectionId, Endpoint, EndpointConfig, EndpointError, Error,
    Event, ListenerId, State,
};
use ntcp_io::{PacketIo, TxOutcome};
use ntcp_io_tun::Tun;
use send::LogicalSend;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
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
    SetFastOpenReceiveAuthority(Option<u64>),
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
    // SO_LINGER's struct linger: l_onoff, l_linger.
    SetLinger(i32, i32),
    GetLinger,
    #[cfg(feature = "tfo-linux-cookie")]
    SetFastOpenKey(LinuxSipHash24Key),
    Get(i32, i32),
    Name(bool),
    Ready,
    // An epoll_wait's probe: the sockets whose published readiness changed
    // since change number `since`, and the readiness of sockets `probe`.
    ReadyChanges(u64, Vec<u64>),
    Available,
    Inq(usize),
}
#[derive(Default, Debug)]
pub struct Reply {
    pub value: i32,
    pub timeout_us: u64,
    pub readiness_generations: [u64; 5],
    // Op::ReadyChanges: (socket, readiness bits or -1 for none, generations).
    pub ready: Vec<(u64, i32, [u64; 5])>,
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
    closing: Option<(ConnectionId, LingerWait)>,
}
// How long a last close waits, after its FIN is submitted, for the FIN to be
// acknowledged: Linux sk_stream_wait_close with SO_LINGER's time.
#[derive(Clone, Copy, Debug, PartialEq)]
enum LingerWait {
    Off,
    Until(Instant),
    Unbounded,
}
impl LingerWait {
    fn new(linger: Linger) -> Self {
        match linger.seconds {
            _ if !linger.on || linger.aborts() => Self::Off,
            Some(seconds) => Instant::now()
                .checked_add(std::time::Duration::from_secs(seconds.into()))
                .map_or(Self::Unbounded, Self::Until),
            None => Self::Unbounded,
        }
    }
    fn waiting(self) -> bool {
        match self {
            Self::Off => false,
            Self::Until(deadline) => Instant::now() < deadline,
            Self::Unbounded => true,
        }
    }
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
            // The ABI fixtures' one operator-configured raw key.
            #[cfg(feature = "tfo-linux-cookie")]
            owner
                .external_fast_open_keys
                .push(crate::ConfiguredFastOpenKey {
                    key: LinuxSipHash24Key::new([0xab; 16]),
                    lease: ntcp::FastOpenKeyLease::for_lifetime(
                        0,
                        Default::default(),
                        owner.defaults.connection.timebase,
                        false,
                    )
                    .unwrap(),
                });
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
                let mut owner = if let Some(factory) = factory {
                    Owner::external_backends(
                        &config,
                        factory().map_err(|e| e.raw_os_error().unwrap_or(EIO))?,
                    )
                } else {
                    match config.io.backend {
                        Backend::Tun => Owner::new(&config),
                        Backend::AfPacket => Owner::af_packet(&config),
                    }
                }?;
                owner.start_control(config.control.as_ref())?;
                Ok(owner)
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
fn clock_failure(error: ntcp_clock::TransportError) -> i32 {
    eprintln!("ntcp: transport clock failed ({error})");
    EIO
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
fn host_error(error: ntcp_host::Error) -> i32 {
    use ntcp_host::{Error as H, path::Error as P};
    match error {
        H::Endpoint(EndpointError::OutputReserved) => EAGAIN,
        H::Endpoint(error) => engine(error),
        // Like getrandom(2) before its pool is ready.
        H::Entropy => EAGAIN,
        H::Allocation | H::Path(P::Allocation) => ENOMEM,
        H::Capacity | H::Path(P::Capacity | P::Exhausted) => ENOBUFS,
        H::Path(P::NoRoute) => ENETUNREACH,
        H::Path(P::SourceNotOwned) => EADDRNOTAVAIL,
        H::InvalidContext
        | H::Obsolete
        | H::StaleRoute
        | H::Path(
            P::ForeignContext
            | P::StaleHandle
            | P::Invalidated
            | P::SelectionChanged
            | P::StaleGeneration,
        ) => ESTALE,
        H::Unsupported => EOPNOTSUPP,
        H::Unauthorized => EPERM,
        H::Codec(_) | H::Path(P::InvalidArgument | P::Duplicate | P::Ambiguous) => EINVAL,
    }
}
fn managed_error(error: ntcp::ManagedError<ntcp_host::Error>) -> i32 {
    host_error(error.into())
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
    // How `local`'s port was taken, while there is one (`Owner::set_local`).
    binding: ports::Binding,
    flags: i32,
    // Adapter bind policy: mutual REUSEADDR permits live connection-port
    // reuse, and a bind to the port of a TIME-WAIT record or a connection
    // whose descriptor is closed, when it had REUSEADDR too.
    reuse: bool,
    freebind: bool,
    nodelay: bool,
    cork: bool,
    inq: bool,
    notsent_lowat: u32,
    user_mss: Option<u16>,
    mark: u32,
    linger: Linger,
    send_batch: Option<send::SendBatch>,
    send_finish: Option<send::SendFinish>,
    fast_open_limit: i32,
    fast_open_cookie_policy: Option<FastOpenCookiePolicy>,
    fast_open_key_lease: Option<ntcp::FastOpenKeyLease>,
    fast_open_connect: bool,
    receive_authority: Option<ntcp::ListenerId>,
    server_cookie: Option<(SocketAddr, FastOpenCookie)>,
    client_policy: Option<(SocketAddr, FastOpenClientPolicy)>,
    deferred_client_policy: Option<FastOpenClientPolicy>,
    deferred_peer: Option<SocketAddr>,
    // The link of a socket whose local or peer address has link scope.
    zone: Option<address_policy::Zone>,
    readiness: i32,
    readiness_generations: [u64; 5],
    // The generations at the last change logged (`Owner::change_log`).
    published: [u64; 5],
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
    // Sum of Completion::charge over `completions`.
    completion_charge: usize,
    // This socket's share of Owner::timestamp_total at its last settle.
    timestamp_charged: usize,
    // Its links in the socket lists (`Owner::lists`).
    lists: [Links; LISTS],
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
            binding: ports::Binding::Bound,
            flags,
            reuse: false,
            freebind: false,
            nodelay: false,
            cork: false,
            inq: false,
            notsent_lowat: 0,
            user_mss: None,
            mark: 0,
            linger: Linger::DEFAULT,
            send_batch: None,
            send_finish: None,
            fast_open_limit: 0,
            fast_open_cookie_policy: None,
            fast_open_key_lease: None,
            fast_open_connect: false,
            receive_authority: None,
            server_cookie: None,
            client_policy: None,
            deferred_client_policy: None,
            deferred_peer: None,
            zone: None,
            readiness: 0,
            readiness_generations: [0; 5],
            published: [0; 5],
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
            completion_charge: 0,
            timestamp_charged: 0,
            lists: [Links::default(); LISTS],
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
// The connections `endpoint` reclaimed since its reclaim count was
// `since`, oldest first (`Endpoint::reclaimed_since`); None once its log
// no longer reaches back that far, or for a count from a replaced
// endpoint: the caller checks each of its entries instead.
fn reclaimed_since(
    endpoint: &Endpoint,
    since: u64,
) -> Option<impl Iterator<Item = ConnectionId> + '_> {
    (since <= endpoint.reclaimed())
        .then(|| endpoint.reclaimed_since(since))
        .flatten()
}
// Metadata the owner keeps per connection beside the endpoint, each entry
// starting with its connection: in arrival order, found through an index
// by connection, and removed by moving the last entry into its place
// (`Vec::swap_remove`), as Linux reaches a socket's state from the socket.
#[derive(Clone, Debug)]
struct ByConnection<T> {
    entries: Vec<T>,
    index: HashMap<ConnectionId, usize>,
}
trait Keyed {
    fn key(&self) -> ConnectionId;
}
impl Keyed for ConnectionOptions {
    fn key(&self) -> ConnectionId {
        self.0
    }
}
impl Keyed for ChildOptionsSnapshot {
    fn key(&self) -> ConnectionId {
        self.0
    }
}
impl Keyed for (ConnectionId, crate::timestamping::Options) {
    fn key(&self) -> ConnectionId {
        self.0
    }
}
impl<T> Default for ByConnection<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            index: HashMap::new(),
        }
    }
}
impl<T: Keyed> ByConnection<T> {
    fn push(&mut self, entry: T) {
        let previous = self.index.insert(entry.key(), self.entries.len());
        debug_assert!(previous.is_none(), "one entry per connection");
        self.entries.push(entry);
    }
    fn contains(&self, key: ConnectionId) -> bool {
        self.index.contains_key(&key)
    }
    fn get(&self, key: ConnectionId) -> Option<&T> {
        self.index.get(&key).map(|&at| &self.entries[at])
    }
    fn get_mut(&mut self, key: ConnectionId) -> Option<&mut T> {
        self.index.get(&key).map(|&at| &mut self.entries[at])
    }
    fn remove(&mut self, key: ConnectionId) -> Option<T> {
        let at = self.index.remove(&key)?;
        let entry = self.entries.swap_remove(at);
        if let Some(moved) = self.entries.get(at) {
            self.index.insert(moved.key(), at);
        }
        Some(entry)
    }
    // Keeps the entries `keep` holds for, in their order: a pass over all.
    fn retain(&mut self, keep: impl FnMut(&T) -> bool) {
        self.entries.retain(keep);
        self.index.clear();
        for (at, entry) in self.entries.iter().enumerate() {
            self.index.insert(entry.key(), at);
        }
    }
}
impl<T> std::ops::Deref for ByConnection<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.entries
    }
}
impl<'a, T> IntoIterator for &'a ByConnection<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}
impl<T: PartialEq> PartialEq for ByConnection<T> {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}
// The lists of sockets that passes visit instead of every socket, linked
// through the sockets as Linux links a socket into a wait queue: joining
// one never allocates, and a socket leaves one in constant time.
const LISTS: usize = 4;
// Readiness changes kept for epoll instances to read (`Owner::change_log`):
// one that has not looked for more than this many rescans its
// registrations instead.
const CHANGE_LOG: usize = 4096;
// Readiness may have changed since the last refresh (`Owner::events`).
const CHANGED: usize = 0;
// A finish_send deferred while its output is held (`Socket::send_finish`).
const FINISHING: usize = 1;
// Zero-copy leases outstanding (`Socket::zc_leases`).
const LEASED: usize = 2;
// TX timestamp records at the socket's connection: those its writes
// requested (`TimestampState::pending`), or any the connection reported
// ready (`ConnectionEvents::tx_timestamps`).
const STAMPING: usize = 3;
#[derive(Clone, Copy, Default)]
struct Links {
    member: bool,
    prev: Option<u64>,
    next: Option<u64>,
}
type Heads = [Option<u64>; LISTS];
// Links socket `id` at the head of `list`, once.
fn link(sockets: &mut BTreeMap<u64, Socket>, heads: &mut Heads, list: usize, id: u64) {
    let Some(s) = sockets.get_mut(&id) else {
        return;
    };
    if s.lists[list].member {
        return;
    }
    let next = heads[list].replace(id);
    s.lists[list] = Links {
        member: true,
        prev: None,
        next,
    };
    if let Some(next) = next {
        sockets.get_mut(&next).unwrap().lists[list].prev = Some(id);
    }
}
// Unlinks socket `id` from `list`, if it is on it.
fn unlink(sockets: &mut BTreeMap<u64, Socket>, heads: &mut Heads, list: usize, id: u64) {
    let Some(s) = sockets.get_mut(&id) else {
        return;
    };
    let Links { member, prev, next } = std::mem::take(&mut s.lists[list]);
    if !member {
        return;
    }
    match prev {
        Some(prev) => sockets.get_mut(&prev).unwrap().lists[list].next = next,
        None => heads[list] = next,
    }
    if let Some(next) = next {
        sockets.get_mut(&next).unwrap().lists[list].prev = prev;
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
// A connection's IP options and local address, kept until it is
// reclaimed (`Owner::connection_options`).
type ConnectionOptions = (
    ConnectionId,
    u8,
    i32,
    Option<bool>,
    SocketAddr,
    ports::Binding,
);
type ChildOptionsSnapshot = (
    ConnectionId,
    u64,
    u64,
    u64,
    (bool, bool, bool, u32, bool, u8, i32, Linger),
);

struct ManagedFastOpenKeys {
    policy: FastOpenCookiePolicy,
    lifetime: ntcp::FastOpenCookieLifetime,
    next_rotation: u64,
    last_error: Option<i32>,
}

struct Owner {
    fast_open_keys: Option<ManagedFastOpenKeys>,
    #[cfg(feature = "tfo-linux-cookie")]
    external_fast_open_keys: Vec<crate::ConfiguredFastOpenKey>,
    fast_open_configured: bool,
    #[cfg(test)]
    fast_open_entropy: Option<VecDeque<Result<[u8; 32]>>>,
    endpoint: Endpoint,
    // Absent only during construction or in explicitly backend-less core fixtures.
    host: Option<ntcp_host::Host>,
    // The opt-in local path control server (`control.socket`), served on
    // this owner thread with native descriptors and direct system calls.
    control: Option<ntcp_path_control::Server>,
    // The ports this owner drives, the `io.*` port first, then each
    // `port.<name>` in configuration order; bounded by configuration and
    // allocated with the owner. Each port's interface index and live Host
    // link form the map that resolves sin6_scope_id.
    ports: Vec<backend::Port>,
    // The port the next receive batch starts with, so that no port's input
    // waits behind another's.
    receive_cursor: usize,
    // Host input storage: the destination of each datagram reassembly
    // completes, and the IP packet and wire frame of Host ICMP output. All
    // are allocated with the Host; empty without one.
    completed: Vec<u8>,
    icmp_packet: Vec<u8>,
    icmp_wire: Vec<u8>,
    // IPv4 Timestamp time for destination and origin recording.
    ipv4_clock: backend::Ipv4Clock,
    defaults: EndpointConfig,
    socket_policy: crate::SocketPolicy,
    // Installed with every Host this owner attaches.
    segment_routes: Vec<crate::SegmentRoute>,
    sockets: BTreeMap<u64, Socket>,
    // The socket holding each connection and listener, as Linux's sock
    // leads to its socket: an event, a segment or a timestamp reaches its
    // socket without visiting the others. Kept with `Socket::handle` by
    // `alloc`, `set_handle` and `remove_socket`; one entry per handle.
    connection_holders: HashMap<ConnectionId, u64>,
    listener_holders: HashMap<ListenerId, u64>,
    // The sockets whose readiness may have changed since their last
    // refresh, refreshed by the next event pass, as Linux's sk_data_ready
    // and sk_write_space wake only the socket an event concerns: those an
    // event or an operation concerned, those with a completion queued,
    // those whose connection may transmit (`Endpoint::ready_connections`
    // at the last pass, which moves the unsent count) and those held by
    // output (whose release has no event). The first of the socket lists
    // (`CHANGED`), whose heads these are.
    lists: Heads,
    // The sockets whose published readiness (bits or generations) changed,
    // the last CHANGE_LOG of them, numbered by `changes`: what an epoll
    // instance reads since its last look, as Linux's ep_poll_callback adds
    // only a woken file to its epoll's ready list.
    change_log: Vec<u64>,
    changes: u64,
    // Sockets whose options enable software receive timestamps.
    rx_software: usize,
    // The `io.*` port's address: the runtime's address family and the
    // source of connections no other port's address is selected for.
    local: IpAddr,
    // Transport time (CLOCK_BOOTTIME microseconds) for the Endpoint and the
    // Host, and its first sample, where the Endpoint starts.
    clock: ntcp_clock::TransportClock,
    started: u64,
    #[cfg(test)]
    test_now: Option<u64>,
    // Unit-test owners count from their construction, so fixture schedules
    // stay literal; zero gives the provider's own ticks.
    #[cfg(test)]
    test_origin: u64,
    #[cfg(test)]
    test_clock_failure: bool,
    #[cfg(feature = "packet-test")]
    next_port: u16,
    // The users of each local port, and the order an unbound socket's
    // connect tries ports in (RFC 6056 Algorithm 4), from `ephemeral_ports`.
    port_index: ports::PortIndex,
    // The sockets with a local address on each port, and the connections
    // whose options hold one (a superset: entries a test collected
    // directly may remain), as Linux's bind bucket lists a port's owners:
    // a bind is judged against its port's users only.
    port_sockets: BTreeSet<(u16, u64)>,
    port_connections: HashMap<u16, HashSet<ConnectionId>>,
    ephemeral: ntcp::EphemeralPorts,
    ephemeral_ports: std::ops::RangeInclusive<u16>,
    next_id: u64,
    // Connections whose last descriptor closed, released once CLOSED or in
    // TIME-WAIT with no output held. `detached` are checked at the next
    // owner pass: those just closed, those released by an event, and those
    // whose held output has no event to announce its release (at most one
    // per egress slot). The rest wait in `detached_waiting` for the
    // terminal event every way into CLOSED or TIME-WAIT reports
    // (`ConnectionEvents::closed`), as Linux's orphaned socket is
    // destroyed by its own last state change.
    detached: Vec<ConnectionId>,
    detached_waiting: HashSet<ConnectionId>,
    egress: Option<egress::Egress>,
    reservation_timeout_us: u64,
    timestamp_cookie: u64,
    // Sum of every socket's settled timestamp charge.
    timestamp_total: usize,
    // Unaccepted children's options, taken by accept and forgotten when
    // their connection is reclaimed (`prune_child_timeouts`, from the
    // reclaim count `children_reclaimed`).
    child_timestamps: ByConnection<(ConnectionId, crate::timestamping::Options)>,
    // Of `child_timestamps`, those enabling software receive timestamps.
    rx_software_children: usize,
    pending: VecDeque<Request>,
    child_timeouts: ByConnection<ChildOptionsSnapshot>,
    children_reclaimed: u64,
    // Local tuple survives descriptor close and Endpoint::release until GC
    // (`collect_connection_options`, from the reclaim count
    // `options_reclaimed`), and holds its port in `port_index`.
    connection_options: ByConnection<ConnectionOptions>,
    options_reclaimed: u64,
    #[cfg(feature = "packet-test")]
    packets: Option<PacketBackend>,
}
fn unicast(ip: impl Into<IpAddr>) -> bool {
    crate::ip::unicast(ip.into())
}
fn context(io: &crate::IoConfig) -> Result<(IpAddr, u8)> {
    port_context(&io.interface, io.address, io.prefix)
}
// The kernel's assignment of `address` (with `prefix`, when configured) on
// `interface`: the network the address was configured in.
fn port_context(interface: &str, address: IpAddr, prefix: Option<u8>) -> Result<(IpAddr, u8)> {
    struct Port<'a> {
        interface: &'a str,
        address: IpAddr,
        prefix: Option<u8>,
    }
    let io = Port {
        interface,
        address,
        prefix,
    };
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
                    // A link-local address is unique only on its own link.
                    duplicate |= addr == io.address
                        && (!crate::ip::link_local(addr)
                            || CStr::from_ptr(entry.ifa_name).to_bytes()
                                == io.interface.as_bytes());
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
// Startup secrets and ephemeral selection use the same fail-closed OS source.
fn random_secret() -> Result<[u8; 32]> {
    let mut secret = [0u8; 32];
    ports::fill(&mut secret)?;
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
        let mut ports = Vec::new();
        ports
            .try_reserve_exact(1 + config.ports.len())
            .map_err(|_| ENOMEM)?;
        ports.push(backend::Port::new(local, subnet, Some(tun)));
        // Each additional TUN port is a kernel interface owning its address,
        // exactly like the `io.*` one.
        for port in &config.ports {
            let tun = Tun::open(&port.interface).map_err(|e| e.raw_os_error().unwrap_or(EIO))?;
            let subnet = port_context(&port.interface, port.address, port.prefix)?;
            let mut extra = backend::Port::new(port.address, subnet, Some(tun));
            extra.index = backend::interface_index(&port.interface)?;
            ports.push(extra);
        }
        let mut owner = Self::with_ports(ports, secret, tcp)?;
        owner.initialize_socket_config(config)?;
        owner.attach_backend_host(u64::from(index))?;
        owner.enable_reservations(&config.io)?;
        Ok(owner)
    }
    fn initialize_socket_config(&mut self, config: &SocketConfig) -> Result<()> {
        // Startup setup consumes lease time from the owner's first sample; it
        // must not grant a fresh interval when backend initialization
        // completes later.
        self.segment_routes = config.segment_routes.clone();
        self.apply_socket_config_at(config, self.started)
    }

    #[cfg(test)]
    fn apply_socket_config(&mut self, config: &SocketConfig) -> Result<()> {
        let now = self.clock()?;
        self.apply_socket_config_at(config, now)
    }

    fn apply_socket_config_at(&mut self, config: &SocketConfig, now: u64) -> Result<()> {
        let managed = config.fast_open_keys_managed().map_err(|_| EINVAL)?;
        if self.socket_policy.notsent_lowat != config.socket.notsent_lowat {
            self.touch_all();
        }
        self.socket_policy = config.socket;
        self.endpoint
            .set_fast_open_cookie_lifetime(config.fast_open_cookie_lifetime);
        if managed {
            if self.fast_open_keys.as_ref().is_none_or(|keys| {
                keys.policy != config.fast_open_cookie_policy
                    || keys.lifetime != config.fast_open_cookie_lifetime
            }) {
                self.fast_open_keys = Some(ManagedFastOpenKeys {
                    policy: config.fast_open_cookie_policy.clone(),
                    lifetime: config.fast_open_cookie_lifetime,
                    next_rotation: now,
                    last_error: None,
                });
            }
            self.rotate_fast_open_keys(now)?;
        } else {
            self.fast_open_keys = None;
            if let Some(lease) = config.fast_open_key_lease {
                let key = match &config.fast_open_cookie_policy {
                    FastOpenCookiePolicy::HmacSha256 => {
                        ntcp::FastOpenServerKey::HmacSha256(random_secret()?)
                    }
                    #[cfg(feature = "tfo-linux-cookie")]
                    FastOpenCookiePolicy::LinuxSipHash24(key) => {
                        ntcp::FastOpenServerKey::LinuxSipHash24(key.clone())
                    }
                };
                self.endpoint
                    .install_fast_open_key(now, key, lease, false)
                    .map_err(engine)?;
            } else {
                if !self.fast_open_configured
                    && matches!(
                        config.fast_open_cookie_policy,
                        FastOpenCookiePolicy::HmacSha256
                    )
                {
                    // Install the initial unmanaged HMAC key only after setting
                    // its configured epoch duration. The constructor credential
                    // uses the default duration; same-key selection cannot
                    // change it. Reapplying configuration must not renew keys.
                    let key = self.fast_open_secret()?;
                    self.endpoint
                        .try_set_fast_open_hmac_key(key)
                        .map_err(engine)?;
                }
                self.endpoint
                    .try_set_fast_open_cookie_policy(config.fast_open_cookie_policy.clone())
                    .map_err(engine)?;
            }
        }
        #[cfg(feature = "tfo-linux-cookie")]
        self.configure_external_fast_open_keys(config, managed)?;
        for &(destination, policy) in &config.routes {
            self.endpoint
                .set_destination_route(now, destination, Some(policy))
                .map_err(engine)?;
        }
        self.fast_open_configured = true;
        Ok(())
    }
    // What setsockopt(TCP_FASTOPEN_KEY) may select: the primary key when it
    // is external, and every further configured key.
    #[cfg(feature = "tfo-linux-cookie")]
    fn configure_external_fast_open_keys(
        &mut self,
        config: &SocketConfig,
        managed: bool,
    ) -> Result<()> {
        let mut keys = Vec::new();
        keys.try_reserve_exact(config.fast_open_keys.len() + 1)
            .map_err(|_| ENOMEM)?;
        if let (false, FastOpenCookiePolicy::LinuxSipHash24(key), Some(lease)) = (
            managed,
            &config.fast_open_cookie_policy,
            config.fast_open_key_lease,
        ) {
            keys.push(crate::ConfiguredFastOpenKey {
                key: key.clone(),
                lease,
            });
        }
        keys.extend(config.fast_open_keys.iter().cloned());
        self.external_fast_open_keys = keys;
        Ok(())
    }
    fn fast_open_secret(&mut self) -> Result<[u8; 32]> {
        #[cfg(test)]
        if let Some(reads) = &mut self.fast_open_entropy {
            return reads
                .pop_front()
                .expect("unexpected Fast Open entropy consumption");
        }
        random_secret()
    }

    fn rotate_fast_open_keys(&mut self, now: u64) -> Result<()> {
        let Some(keys) = &self.fast_open_keys else {
            return Ok(());
        };
        if now < keys.next_rotation {
            return Ok(());
        }
        let lifetime = keys.lifetime;
        let policy = keys.policy.clone();
        let result = (|| {
            let lease = ntcp::FastOpenKeyLease::for_lifetime(
                now,
                lifetime,
                self.defaults.connection.timebase,
                true,
            )
            .map_err(|_| EINVAL)?;
            let bytes = self.fast_open_secret()?;
            let key = match policy {
                FastOpenCookiePolicy::HmacSha256 => ntcp::FastOpenServerKey::HmacSha256(bytes),
                #[cfg(feature = "tfo-linux-cookie")]
                FastOpenCookiePolicy::LinuxSipHash24(_) => ntcp::FastOpenServerKey::LinuxSipHash24(
                    LinuxSipHash24Key::new(bytes[..16].try_into().unwrap()),
                ),
            };
            self.endpoint
                .install_fast_open_key(now, key, lease, true)
                .map_err(engine)
        })();
        let keys = self.fast_open_keys.as_mut().unwrap();
        // Bound entropy retries by the configured interval. Failure retains
        // original deadlines; admission expires credentials without a timer.
        keys.next_rotation = now.checked_add(lifetime.as_micros()).unwrap_or(u64::MAX);
        keys.last_error = result.as_ref().err().copied();
        if let Err(error) = result {
            eprintln!(
                "ntcp: Fast Open key rotation failed ({error}); credential deadlines retained"
            );
        }
        result
    }

    // A one-port owner of `local` (fixtures and the packet-test port).
    #[cfg(any(test, feature = "packet-test"))]
    fn with_config(
        local: impl Into<IpAddr>,
        subnet: (impl Into<IpAddr>, u8),
        secret: [u8; 32],
        tun: Option<Tun>,
        config: EndpointConfig,
    ) -> Result<Self> {
        let mut ports = Vec::new();
        ports.try_reserve_exact(1).map_err(|_| ENOMEM)?;
        ports.push(backend::Port::new(
            local.into(),
            (subnet.0.into(), subnet.1),
            tun,
        ));
        Self::with_ports(ports, secret, config)
    }
    // An owner of `ports`, the `io.*` port first.
    fn with_ports(
        ports: Vec<backend::Port>,
        secret: [u8; 32],
        config: EndpointConfig,
    ) -> Result<Self> {
        let local = ports.first().ok_or(EINVAL)?.address;
        let mut addresses = Vec::new();
        addresses.try_reserve_exact(ports.len()).map_err(|_| ENOMEM)?;
        addresses.extend(ports.iter().map(|port| (port.address, port.subnet)));
        let defaults = config.clone();
        let owned = addresses.clone();
        let valid = move |ip: IpAddr| {
            if ip.is_ipv4() != local.is_ipv4() || !unicast(ip) {
                return false;
            }
            // Never the broadcast address of a port's IPv4 subnet.
            owned.iter().all(|&(_, (address, prefix))| match (ip, address) {
                (IpAddr::V4(ip), IpAddr::V4(address)) => {
                    prefix > 30
                        || u32::from(ip)
                            != u32::from(address) | u32::MAX.checked_shr(prefix as u32).unwrap_or(0)
                }
                (IpAddr::V6(_), IpAddr::V6(_)) => true,
                _ => false,
            })
        };
        let own = move |ip: IpAddr| addresses.iter().any(|&(address, _)| address == ip);
        let mut clock = ntcp_clock::TransportClock::new().map_err(clock_failure)?;
        let started = clock.sample().map_err(clock_failure)?.ticks;
        #[cfg(test)]
        let (test_origin, started) = (started, 0);
        let endpoint = Endpoint::new(config, secret, started, move |r| match r {
            AddressValidation::Bind { local: bind } => {
                // Per-socket local-address permission is checked by Op::Bind.
                // FREEBIND does not relax Open, Incoming, or Route policy.
                bind.is_unspecified() || unicast(bind)
            }
            AddressValidation::Open {
                local: source,
                remote,
            } => own(source) && valid(remote),
            AddressValidation::Incoming {
                source,
                destination,
            } => own(destination) && valid(source),
            AddressValidation::Route { .. } => false,
        })
        .map_err(engine)?;
        let ephemeral = endpoint.ephemeral_ports().map_err(engine)?;
        Ok(Self {
            fast_open_keys: None,
            #[cfg(feature = "tfo-linux-cookie")]
            external_fast_open_keys: Vec::new(),
            fast_open_configured: false,
            #[cfg(test)]
            fast_open_entropy: None,
            endpoint,
            host: None,
            ports,
            receive_cursor: 0,
            completed: Vec::new(),
            icmp_packet: Vec::new(),
            icmp_wire: Vec::new(),
            ipv4_clock: Default::default(),
            defaults,
            socket_policy: crate::SocketPolicy::default(),
            segment_routes: Vec::new(),
            sockets: BTreeMap::new(),
            connection_holders: HashMap::new(),
            listener_holders: HashMap::new(),
            lists: [None; LISTS],
            change_log: Vec::new(),
            changes: 0,
            rx_software: 0,
            local,
            clock,
            started,
            control: None,
            #[cfg(test)]
            test_now: None,
            #[cfg(test)]
            test_origin,
            #[cfg(test)]
            test_clock_failure: false,
            #[cfg(feature = "packet-test")]
            next_port: 40000,
            port_index: ports::PortIndex::new(),
            port_sockets: BTreeSet::new(),
            port_connections: HashMap::new(),
            ephemeral,
            ephemeral_ports: ports::RANGE,
            next_id: 1,
            detached: Vec::new(),
            detached_waiting: HashSet::new(),
            egress: None,
            reservation_timeout_us: 1_000_000,
            timestamp_cookie: 1,
            timestamp_total: 0,
            child_timestamps: ByConnection::default(),
            rx_software_children: 0,
            pending: VecDeque::new(),
            child_timeouts: ByConnection::default(),
            children_reclaimed: 0,
            connection_options: ByConnection::default(),
            options_reclaimed: 0,
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
        // A new endpoint's reclaim log starts again.
        (owner.options_reclaimed, owner.children_reclaimed) = (0, 0);
        owner.endpoint = Endpoint::new(
            crate::packet_profile::config(profile),
            [42; 32],
            owner.started,
            move |r| match r {
                AddressValidation::Bind { local: addr } => addr.is_unspecified() || unicast(addr),
                AddressValidation::Open { local: addr, .. } => addr == local,
                AddressValidation::Incoming { destination, .. } => destination == local,
                AddressValidation::Route { .. } => false,
            },
        )
        .map_err(engine)?;
        match crate::packet_profile::cookie_policy(profile) {
            // The script's raw key is operator configuration: a lease on the
            // current boot, from the configured lifetime, starting at setup.
            #[cfg(feature = "tfo-linux-cookie")]
            FastOpenCookiePolicy::LinuxSipHash24(key) => {
                let lease = ntcp::FastOpenKeyLease::for_lifetime(
                    owner.started,
                    Default::default(),
                    crate::packet_profile::config(profile).connection.timebase,
                    false,
                )
                .map_err(|_| EINVAL)?;
                owner
                    .endpoint
                    .install_fast_open_key(
                        owner.started,
                        ntcp::FastOpenServerKey::LinuxSipHash24(key.clone()),
                        lease,
                        false,
                    )
                    .map_err(engine)?;
                owner
                    .external_fast_open_keys
                    .push(crate::ConfiguredFastOpenKey { key, lease });
            }
            policy => owner.endpoint.set_fast_open_cookie_policy(policy),
        }
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
        owner.packets = Some(PacketBackend::new(profile, local, options.queue_capacity)?);
        owner.attach_backend_host(1)?;
        owner.enable_egress(options.egress_capacity, crate::packet_profile::gso(profile))?;
        Ok(owner)
    }
    #[cfg(all(test, feature = "packet-test"))]
    fn replace_packet_endpoint(&mut self, config: EndpointConfig) -> Result<()> {
        // Configuration variants in packet fixtures still attach their actual
        // port through the production bridge before exercising socket startup.
        assert!(self.packets.is_some());
        assert_eq!(self.host.as_ref().unwrap().binding_count(), 0);
        self.endpoint = Endpoint::new(config.clone(), [42; 32], 0, |_| true).map_err(engine)?;
        (self.options_reclaimed, self.children_reclaimed) = (0, 0);
        self.defaults = config;
        let previous = self
            .host
            .take()
            .map(|mut host| host.take_identifiers())
            .transpose()
            .map_err(host_error)?;
        for port in &mut self.ports {
            port.ingress = None;
        }
        self.attach_backend_host_with(1, previous)
    }
    fn check_address(&self, addr: SocketAddr) -> Result<()> {
        if addr.is_ipv4() != self.local.is_ipv4() {
            return Err(EAFNOSUPPORT);
        }
        if let SocketAddr::V6(v) = addr
            && (v.flowinfo() != 0 || v.ip().to_ipv4_mapped().is_some())
        {
            return Err(EOPNOTSUPP);
        }
        Ok(())
    }
    // Whether `port`'s address is assigned. On a Neighbor Discovery port it
    // is not while tentative or once found duplicate (RFC 4862 sections 5.4
    // and 5.4.5), as Linux inet6_bind refuses an IFA_F_TENTATIVE address,
    // which a DAD-failed one keeps; other ports' addresses are assigned by
    // their configuration.
    fn assigned(&self, port: &backend::Port) -> bool {
        let (backend::Resolution::Discovery, Some(link), IpAddr::V6(address)) =
            (&port.resolution, port.link(), port.address)
        else {
            return true;
        };
        self.host.as_ref().is_some_and(|host| {
            host.neighbor_address_state(link, address) == Some(ntcp_host::AddressState::Assigned)
        })
    }
    // Whether `ip` is the address of one of this owner's ports.
    fn owns(&self, ip: IpAddr) -> bool {
        self.ports.iter().any(|port| port.address == ip)
    }
    // The zones of the attached ports: the live interface map.
    fn zones(&self) -> impl Iterator<Item = address_policy::Zone> + '_ {
        self.ports.iter().filter_map(backend::Port::zone)
    }
    // The zone `addr` names: for an address with link scope its nonzero
    // sin6_scope_id resolved through the live interface map (an unknown
    // index is ENODEV, a missing one EINVAL, as for Linux); other addresses
    // have none and their scope is ignored, as Linux does.
    fn resolve_zone(&self, addr: SocketAddr) -> Result<Option<address_policy::Zone>> {
        match addr {
            SocketAddr::V6(v) if v.ip().is_unicast_link_local() => match v.scope_id() {
                0 => Err(EINVAL),
                index => self
                    .zones()
                    .find(|zone| zone.index == index)
                    .map(Some)
                    .ok_or(ENODEV),
            },
            _ => Ok(None),
        }
    }
    // The zone of a connection from socket `id` to the application address
    // `remote`: a link-local peer's scope, which must agree with the link the
    // socket is already on, or that link (Linux's sk_bound_dev_if rule). A
    // zone whose link is gone stays the socket's: it is never retargeted to
    // whichever interface now has its index.
    fn connect_zone(&self, id: u64, remote: SocketAddr) -> Result<Option<address_policy::Zone>> {
        let bound = self.sockets[&id].zone;
        let zone = match remote {
            SocketAddr::V6(v) if v.ip().is_unicast_link_local() && v.scope_id() == 0 => {
                Some(bound.ok_or(EINVAL)?)
            }
            SocketAddr::V6(v) if v.ip().is_unicast_link_local() => {
                // A different index contradicts the socket's link before any
                // lookup; the same index may now name another link.
                if bound.is_some_and(|bound| bound.index != v.scope_id()) {
                    return Err(EINVAL);
                }
                let zone = self.resolve_zone(remote)?;
                if bound.is_some_and(|bound| Some(bound) != zone) {
                    return Err(EINVAL);
                }
                zone
            }
            _ => bound,
        };
        if zone.is_some_and(|zone| !self.zones().any(|live| live == zone)) {
            return Err(ENODEV);
        }
        Ok(zone)
    }
    // The application zone of a connection's scoped tuple.
    fn connection_zone(&self, cid: ConnectionId) -> Result<Option<address_policy::Zone>> {
        let Some(link) = self
            .endpoint
            .retained_scoped_tuple(cid)
            .map_err(engine)?
            .zone()
        else {
            return Ok(None);
        };
        self.zones()
            .find(|zone| zone.link == link)
            .map(Some)
            .ok_or(ENODEV)
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
    // One transport sample, with its measured suspend passed to the
    // Endpoint. A provider failure or a sample the Endpoint rejects is EIO:
    // time stops being available and the owner loop ends, never a frozen time.
    fn clock(&mut self) -> Result<u64> {
        #[cfg(test)]
        {
            if self.test_clock_failure {
                return Err(EIO);
            }
            if let Some(now) = self.test_now {
                return Ok(now);
            }
        }
        let sample = self.clock.sample().map_err(clock_failure)?;
        #[cfg(test)]
        let sample = ntcp_clock::TransportSample {
            ticks: sample.ticks.wrapping_sub(self.test_origin),
            ..sample
        };
        self.accept_sample(sample)
    }
    fn accept_sample(&mut self, sample: ntcp_clock::TransportSample) -> Result<u64> {
        if sample.suspended != 0 {
            self.endpoint
                .resume(sample.ticks, sample.suspended)
                .map_err(|_| EIO)?;
        }
        Ok(sample.ticks)
    }
    // Fixtures read time without taking a sample of the owner's provider.
    #[cfg(test)]
    fn now(&self) -> u64 {
        self.test_now.unwrap_or_else(|| {
            let mut time = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            assert_eq!(
                unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) },
                0
            );
            (time.tv_sec as u64 * 1_000_000 + time.tv_nsec as u64 / 1_000)
                .wrapping_sub(self.test_origin)
        })
    }
    // Real-clock fixtures: as if `micros` more had elapsed.
    #[cfg(test)]
    fn advance_clock(&mut self, micros: u64) {
        self.test_origin = self.test_origin.wrapping_sub(micros);
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
        if let Some((cid, linger)) = request.closing {
            if self.endpoint.is_output_reserved(cid)
                || self.endpoint.ready_connections().any(|id| id == cid)
            {
                return false;
            }
            // Linux sk_stream_wait_close: wait while the FIN is unacknowledged
            // (FIN-WAIT-1, CLOSING, LAST-ACK, entered at close), at most the
            // linger time. Its end returns; the close itself continues.
            if linger.waiting()
                && matches!(
                    self.endpoint.state(cid),
                    Ok(State::SynReceived
                        | State::Established
                        | State::CloseWait
                        | State::FinWait1
                        | State::Closing
                        | State::LastAck)
                )
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
        // Linux inet_release lingers whatever O_NONBLOCK says, and a
        // listener's close never waits.
        let closing = if self.egress.is_some() && matches!(op, Op::Close) {
            self.sockets.get(&request.id).and_then(|s| match s.handle {
                Handle::Connection(cid) => Some((cid, LingerWait::new(s.linger))),
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
        let mut input = vec![0; 65535 + self.link_offset()];
        // Keep in-flight batches owned through every output/backend exit.
        let mut after_output = Vec::with_capacity(BUDGET);
        'run: while !stop.load(Ordering::Acquire) {
            self.poll_mtu_refresh();
            let Ok(now) = self.clock() else {
                break;
            };
            if self.expire_egress(now).is_err() {
                break;
            }
            let Ok(now) = self.clock() else {
                break;
            };
            let _ = self.rotate_fast_open_keys(now);
            if self.endpoint.on_timeout(now, BUDGET).is_err() {
                break;
            }
            if self.receive_batch(&mut input).is_err() || self.poll_backend_timestamps().is_err() {
                break 'run;
            }
            if self.ports.iter_mut().any(|port| {
                port.ethernet
                    .as_mut()
                    .is_some_and(|b| b.io.reclaim_transmit(BUDGET).is_err())
            }) {
                break 'run;
            }
            self.events();
            self.collect_zero_copy();
            self.service_before_output(&mut after_output);
            self.service_discovery();
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
            self.collect_connection_options();
            self.release_detached();
            if self.collect_paths().is_err() {
                break 'run;
            }
            // Before the held-output early continue below: administration
            // stays reachable while output is held (a restriction may be
            // what releases it).
            self.service_control();
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
    // Create the opt-in control server on the owner thread once the Host
    // exists, with the Host-bound administration capability.
    fn start_control(&mut self, config: Option<&ntcp_path_control::ControlConfig>) -> Result<()> {
        let Some(config) = config else {
            return Ok(());
        };
        let host = self.host.as_mut().ok_or(EINVAL)?;
        let server = ntcp_path_control::Server::bind(
            config,
            host.administration(),
            self.endpoint.caller_timebase(),
        )
        .map_err(|e| e.raw_os_error().unwrap_or(EINVAL))?;
        self.control = Some(server);
        Ok(())
    }
    // One bounded control pass at the owner clock.
    fn service_control(&mut self) {
        let Ok(now) = self.clock() else {
            return;
        };
        if let (Some(server), Some(host)) = (&mut self.control, &mut self.host) {
            server.service(host, &mut self.endpoint, now);
        }
    }
    fn collect_paths(&mut self) -> Result<()> {
        if let Some(host) = &mut self.host {
            host.collect(&self.endpoint).map_err(host_error)?;
        }
        Ok(())
    }
    // Forgets the options of children whose connection the endpoint has
    // reclaimed since the last call: those its reclaim log names, as Linux
    // frees a request's state with the request.
    fn prune_child_timeouts(&mut self) {
        let since = self.children_reclaimed;
        let (endpoint, timeouts, stamps, rx) = (
            &self.endpoint,
            &mut self.child_timeouts,
            &mut self.child_timestamps,
            &mut self.rx_software_children,
        );
        match reclaimed_since(endpoint, since) {
            Some(reclaimed) => {
                for cid in reclaimed {
                    timeouts.remove(cid);
                    if let Some((_, options)) = stamps.remove(cid) {
                        *rx -= usize::from(options.flags & crate::timestamping::RX_SOFTWARE != 0);
                    }
                }
            }
            None => {
                timeouts.retain(|p| endpoint.connection_exists(p.0));
                stamps.retain(|p| endpoint.connection_exists(p.0));
                *rx = stamps
                    .iter()
                    .filter(|p| p.1.flags & crate::timestamping::RX_SOFTWARE != 0)
                    .count();
            }
        }
        self.children_reclaimed = self.endpoint.reclaimed();
        debug_assert!(
            self.child_timeouts.iter().map(|p| p.0)
                .chain(self.child_timestamps.iter().map(|p| p.0))
                .all(|cid| self.endpoint.connection_exists(cid))
        );
    }
    #[cfg(test)]
    fn input(
        &mut self,
        now: u64,
        ip: ntcp::IpMetadata,
        traffic_class: u8,
        bytes: &[u8],
    ) -> std::result::Result<ntcp::InputDisposition, ntcp_host::Error> {
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
    ) -> std::result::Result<ntcp::InputDisposition, ntcp_host::Error> {
        let arrival = self.ports[0].link();
        self.input_segmented(
            now,
            arrival,
            ip,
            traffic_class,
            ntcp::Ipv4Options::default(),
            bytes,
            stamps,
            None,
        )
    }
    // The connection `tuple` arriving on `arrival` belongs to: a link-local
    // address belongs to the arrival link. Host-less fixtures, which have
    // no link, look the tuple up unscoped.
    pub(super) fn arrival_connection(
        &self,
        tuple: ntcp::Tuple,
        arrival: Option<ntcp_host::path::LinkId>,
    ) -> Option<ConnectionId> {
        match Self::arrival_zone(tuple, arrival) {
            Some(zone) => self
                .endpoint
                .scoped_connection_id(ntcp::ScopedTuple::new(tuple, zone)?),
            None => self.endpoint.connection_id(tuple),
        }
    }
    // The zone of `tuple` on `arrival`; None for a Host-less fixture.
    fn arrival_zone(
        tuple: ntcp::Tuple,
        arrival: Option<ntcp_host::path::LinkId>,
    ) -> Option<Option<ntcp_host::path::LinkId>> {
        let scoped =
            crate::ip::link_local(tuple.local.ip()) || crate::ip::link_local(tuple.remote.ip());
        arrival.map(|link| scoped.then_some(link))
    }
    fn input_segmented(
        &mut self,
        now: u64,
        arrival: Option<ntcp_host::path::LinkId>,
        ip: ntcp::IpMetadata,
        traffic_class: u8,
        options: ntcp::Ipv4Options,
        bytes: &[u8],
        stamps: ntcp::RxPacketTimestamps,
        segment_size: Option<core::num::NonZeroU16>,
    ) -> std::result::Result<ntcp::InputDisposition, ntcp_host::Error> {
        if let Some(host) = &mut self.host {
            host.collect(&self.endpoint)?;
        }
        // Endpoint validates the packet; the ports are only used to observe
        // generation-aware tuple ownership before and after passive admission.
        let tuple = bytes.get(..4).map(|ports| ntcp::Tuple {
            local: SocketAddr::new(ip.destination, u16::from_be_bytes([ports[2], ports[3]])),
            remote: SocketAddr::new(ip.source, u16::from_be_bytes([ports[0], ports[1]])),
        });
        let before = tuple.and_then(|tuple| self.arrival_connection(tuple, arrival));
        let before_state = before.and_then(|cid| self.endpoint.state(cid).ok());
        let listener = tuple.and_then(|tuple| match Self::arrival_zone(tuple, arrival) {
            Some(zone) => self.endpoint.matching_scoped_listener(tuple.local, zone),
            None => self.endpoint.matching_listener(tuple.local),
        });
        let listener_options = listener.and_then(|listener| {
            self.listener_socket(listener)
                .map(|id| &self.sockets[&id])
                .map(|s| {
                    (
                        s.wire_tos(self.local),
                        s.wire_discover(self.local),
                        s.zerocopy,
                        s.mark,
                        s.reuse,
                    )
                })
        });
        // Reserve only for checked passive SYNs: LISTEN ACKs need stateless
        // resets, and existing TIME-WAIT traffic still needs core processing.
        // TIME-WAIT requests use the same flag eligibility as passive opens;
        // SYN data still needs a bounded metadata slot before core admission.
        if listener_options.is_some()
            && before
                .is_none_or(|id| matches!(self.endpoint.state(id), Ok(State::TimeWait) | Err(_)))
            && ntcp::wire::parse(ip, bytes).is_ok_and(|segment| {
                let flags = segment.header.flags;
                flags & (ntcp::wire::SYN | ntcp::wire::ACK | ntcp::wire::RST) == ntcp::wire::SYN
            })
        {
            self.collect_connection_options();
            if self.connection_options.len() == self.socket_limit() {
                return Err(EndpointError::LimitReached.into());
            }
        }

        // Without time the segment stays unprocessed; the owner loop ends.
        let pair = ClockPair::sample(self)
            .map_err(|_| EndpointError::Connection(Error::AmbiguousTimeJump))?;
        let metadata = ntcp::RxPacketMetadata {
            timestamps: stamps,
            tcp_segment_size: segment_size,
        };
        let result = if let Some(host) = &mut self.host {
            let arrival = arrival.ok_or(ntcp_host::Error::InvalidContext)?;
            self.endpoint
                .input_with_path_provider(
                    now,
                    arrival,
                    ip,
                    traffic_class,
                    options,
                    bytes,
                    metadata,
                    listener_options.map_or(self.defaults.dscp, |p| p.0 >> 2),
                    host,
                )
                .map_err(ntcp_host::Error::from)
        } else {
            self.endpoint
                .input_with_metadata(now, ip, traffic_class, options, bytes, metadata)
                .map_err(ntcp_host::Error::from)
        };
        self.drain_timestamps(pair);
        self.prune_child_timeouts();
        // A failed TIME-WAIT candidate can restore an existing tuple owner.
        // Its generation-aware metadata already exists and must not be
        // duplicated or replaced with the listener's current policy.
        let new_child = tuple
            .and_then(|tuple| self.arrival_connection(tuple, arrival))
            .filter(|cid| {
                Some(*cid) != before && !self.connection_options.contains(*cid)
            });
        if let Some(cid) = new_child
            && let Some(listener) = listener.and_then(|listener| self.listener_socket(listener))
        {
            let s = &self.sockets[&listener];
            // Runtime bind policy admits only one listener per port. Input can
            // only create passive children; active opens go through Connect.
            debug_assert!(self.child_timeouts.len() < LIMIT);
            self.child_timestamps.push((cid, s.timestamps.options));
            self.rx_software_children +=
                usize::from(s.timestamps.options.flags & crate::timestamping::RX_SOFTWARE != 0);
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
                    // Linux sk_clone_lock copies SOCK_LINGER and sk_lingertime.
                    s.linger,
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
                    self.child_timeouts.get(cid)
                && let listener = *listener
                && let Some(s) = self.sockets.get_mut(&listener)
                && s.acceptable
            {
                // A child joining a ready accept queue is a Linux ET wake.
                // The core's Acceptable, drained later in this pass, marks it
                // too; an edge observer compares generations, so the second
                // increment adds no wake.
                s.readiness_generations[0] = s.readiness_generations[0].wrapping_add(1);
                self.touch(listener);
            }
            if Some(cid) == new_child
                && let Some((tos, discover, _, mark, reuse)) = listener_options
            {
                self.endpoint.set_dscp(cid, tos >> 2)?;
                self.endpoint.set_mark(cid, mark)?;
                self.endpoint.set_reuse_address(cid, reuse)?;
                self.push_connection_options((
                    cid,
                    tos,
                    discover,
                    None,
                    tuple.local,
                    ports::Binding::Bound,
                ));
            }
            // Snapshot at accept eligibility, before the adapter publishes the
            // child. Only authenticated TFO data is readable in SynReceived;
            // ordinary children retain their final-handshake-ACK snapshot.
            let state = self.endpoint.state(cid);
            if (matches!(state, Ok(State::Established | State::CloseWait))
                || state == Ok(State::SynReceived) && self.endpoint.readable_bytes(cid)? != 0)
                && let Some(p) = self.connection_options.get_mut(cid)
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
            let holder = match &event {
                Event::Acceptable(listener) | Event::PassiveError { listener, .. } => {
                    self.listener_socket(*listener)
                }
                Event::Connection(cid, _) => self.connection_socket(*cid),
                Event::RouteAdvice(_) => None,
            };
            if let Event::Connection(cid, e) = &event
                && e.closed.is_some()
                && self.detached_waiting.remove(cid)
            {
                self.detached.push(*cid);
            }
            if let Some(id) = holder {
                self.touch(id);
                if matches!(&event, Event::Connection(_, e) if e.tx_timestamps) {
                    link(&mut self.sockets, &mut self.lists, STAMPING, id);
                }
            }
            if let Some(s) = holder.and_then(|id| self.sockets.get_mut(&id)) {
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
        // Output selected since the last pass may hold a connection.
        self.queue_transmitting();
        // Detach the list: a socket queued while it is refreshed (one held
        // by output) joins the next pass's.
        let mut next = self.lists[CHANGED].take();
        while let Some(id) = next {
            let links = &mut self.sockets.get_mut(&id).expect("listed socket").lists[CHANGED];
            next = links.next;
            *links = Links::default();
            let _ = self.refresh_readiness(id);
        }
        // Their unsent counts move as they transmit before the next pass:
        // look at them again then.
        self.queue_transmitting();
        // Debug builds cross-check against the refresh of every socket
        // that this replaces: nothing else changed any socket's readiness.
        if cfg!(debug_assertions) {
            for (&id, s) in &self.sockets {
                if let Ok(bits) = self.readiness_bits(id) {
                    assert_eq!(
                        bits, s.readiness,
                        "readiness of socket {id} changed with nothing to refresh it"
                    );
                    assert_eq!(
                        s.published, s.readiness_generations,
                        "readiness generations of socket {id} moved unpublished"
                    );
                }
            }
        }
    }
    // Releases the detached connections now CLOSED or in TIME-WAIT with no
    // output held; one still short of either waits for its terminal event.
    fn release_detached(&mut self) {
        let (endpoint, waiting) = (&mut self.endpoint, &mut self.detached_waiting);
        self.detached.retain(|&id| {
            let terminal = matches!(endpoint.state(id), Ok(State::Closed | State::TimeWait));
            if terminal && !endpoint.is_output_reserved(id) {
                let _ = endpoint.release(id);
                false
            } else if terminal || endpoint.state(id).is_err() {
                true
            } else {
                waiting.insert(id);
                false
            }
        });
    }
    // Queues the sockets of connections with output to send or held by
    // egress: at most the connections egress is serving.
    fn queue_transmitting(&mut self) {
        let (holders, sockets, lists) = (
            &self.connection_holders,
            &mut self.sockets,
            &mut self.lists,
        );
        let held = self.egress.iter().flat_map(|e| e.held_owners());
        for cid in self.endpoint.ready_connections().chain(held) {
            if let Some(&id) = holders.get(&cid) {
                link(sockets, lists, CHANGED, id);
            }
        }
    }
    // Queues socket `id` for the next event pass's readiness refresh.
    fn touch(&mut self, id: u64) {
        link(&mut self.sockets, &mut self.lists, CHANGED, id);
    }
    // Debug builds check `list`'s links and that every socket `listed`
    // holds for is on it (`exact`: and no other).
    fn check_list(&self, list: usize, listed: impl Fn(&Socket) -> bool, exact: bool) {
        if !cfg!(debug_assertions) {
            return;
        }
        let (mut count, mut prev, mut at) = (0, None, self.lists[list]);
        while let Some(id) = at {
            let links = &self.sockets[&id].lists[list];
            assert!(links.member && links.prev == prev, "list {list} at {id}");
            (count, prev, at) = (count + 1, Some(id), links.next);
        }
        for (id, s) in &self.sockets {
            let (want, member) = (listed(s), s.lists[list].member);
            assert!(
                if exact { want == member } else { !want || member },
                "socket {id}: list {list} membership {member}"
            );
        }
        let members = self.sockets.values().filter(|s| s.lists[list].member);
        assert_eq!(count, members.count(), "list {list} length");
    }
    // Every socket, after a change of policy all of them read.
    fn touch_all(&mut self) {
        let mut next = self.sockets.keys().next().copied();
        while let Some(id) = next {
            self.touch(id);
            next = self.socket_after(id);
        }
    }
    // The socket after `id` in id order: a pass that changes each socket
    // in turn, without a list of them.
    fn socket_after(&self, id: u64) -> Option<u64> {
        use std::ops::Bound::{Excluded, Unbounded};
        self.sockets
            .range((Excluded(id), Unbounded))
            .next()
            .map(|(&id, _)| id)
    }
    // The socket holding connection `cid`.
    fn connection_socket(&self, cid: ConnectionId) -> Option<u64> {
        let id = self.connection_holders.get(&cid).copied().filter(|id| {
            self.sockets
                .get(id)
                .is_some_and(|s| matches!(s.handle, Handle::Connection(c) if c == cid))
        });
        // Debug builds cross-check the index against the pass it replaces.
        debug_assert_eq!(
            id,
            self.sockets
                .iter()
                .find(|(_, s)| matches!(s.handle, Handle::Connection(c) if c == cid))
                .map(|(&id, _)| id)
        );
        id
    }
    // The socket holding listener `listener`.
    fn listener_socket(&self, listener: ListenerId) -> Option<u64> {
        let id = self.listener_holders.get(&listener).copied().filter(|id| {
            self.sockets
                .get(id)
                .is_some_and(|s| matches!(s.handle, Handle::Listener(l) if l == listener))
        });
        debug_assert_eq!(
            id,
            self.sockets
                .iter()
                .find(|(_, s)| matches!(s.handle, Handle::Listener(l) if l == listener))
                .map(|(&id, _)| id)
        );
        id
    }
    // Enters (`held`) or leaves socket `id`'s `handle` in the holders.
    fn hold(&mut self, id: u64, handle: Handle, held: bool) {
        match handle {
            Handle::Connection(cid) if held => {
                debug_assert!(self.sockets.iter().all(|(&other, s)| other == id
                    || !matches!(s.handle, Handle::Connection(c) if c == cid)));
                self.connection_holders.insert(cid, id);
            }
            Handle::Connection(cid) => {
                if self.connection_holders.get(&cid) == Some(&id) {
                    self.connection_holders.remove(&cid);
                }
            }
            Handle::Listener(listener) if held => {
                debug_assert!(self.sockets.iter().all(|(&other, s)| other == id
                    || !matches!(s.handle, Handle::Listener(l) if l == listener)));
                self.listener_holders.insert(listener, id);
            }
            Handle::Listener(listener) => {
                if self.listener_holders.get(&listener) == Some(&id) {
                    self.listener_holders.remove(&listener);
                }
            }
            Handle::Fresh => (),
        }
    }
    // Gives socket `id` `handle`, in the holders too.
    fn set_handle(&mut self, id: u64, handle: Handle) {
        let old = std::mem::replace(&mut self.sockets.get_mut(&id).unwrap().handle, handle);
        self.hold(id, old, false);
        self.hold(id, handle, true);
        self.touch(id);
    }
    fn alloc(&mut self, s: Socket) -> Result<i32> {
        if self.sockets.len() == self.socket_limit() || self.next_id > i32::MAX as u64 {
            return Err(EMFILE);
        }
        let id = self.next_id;
        self.next_id += 1;
        if let Some(local) = s.local {
            self.port_index.socket(local.port(), s.binding, true);
            self.port_sockets.insert((local.port(), id));
        }
        self.hold(id, s.handle, true);
        self.rx_software += usize::from(s.timestamps.options.flags & crate::timestamping::RX_SOFTWARE != 0);
        self.sockets.insert(id, s);
        self.touch(id);
        self.settle_timestamp_charge(id);
        Ok(id as i32)
    }
    //= https://www.rfc-editor.org/rfc/rfc5927#section-4.2
    //# As discussed in the previous sections, in order to perform any of the attacks described in this document, an attacker would need to guess (or know) the four-tuple that identifies the connection to be attacked. Increasing the port number range used for outgoing TCP connections, and randomizing the port number chosen for each outgoing TCP connection, would make it harder for an attacker to perform any of the attacks discussed in this document.
    //= https://www.rfc-editor.org/rfc/rfc5927#section-4.2
    //# [PORT-RANDOM] recommends that transport protocols randomize the ephemeral ports used by clients, and proposes a number of randomization algorithms.
    // The local port of an unbound socket's connect from `local` to
    // `remote`, in the order of RFC 6056 Algorithm 4
    // (`EphemeralPorts::select`), as Linux's __inet_hash_connect: a port is
    // shared by the connects of distinct destinations, the 4-tuple unique
    // among connections, TIME-WAIT records (`Endpoint::tuple_in_use`, as
    // __inet_check_established) and deferred Fast Open connects, and
    // skipped while a socket or connection bind() gave it holds it. A
    // TIME-WAIT record of the tuple is not reused: Linux's tcp_tw_reuse
    // allows that by default over loopback only. Each candidate is a few
    // lookups, whatever the number of sockets.
    fn connect_port(
        &mut self,
        local: IpAddr,
        remote: SocketAddr,
        zone: Option<address_policy::Zone>,
    ) -> Result<u16> {
        #[cfg(feature = "packet-test")]
        if self.packets.is_some() {
            return self.sequential_port();
        }
        let now = self.clock()?;
        let (index, endpoint) = (&self.port_index, &self.endpoint);
        self.ephemeral
            .select(now, local, remote, self.ephemeral_ports.clone(), |port| {
                let local = SocketAddr::new(local, port);
                !index.bound(port)
                    && !index.deferred((local, remote))
                    && !ntcp::ScopedTuple::new(ntcp::Tuple { local, remote }, zone.map(|z| z.link))
                        .is_some_and(|tuple| endpoint.tuple_in_use(tuple))
            })
            .ok_or(EADDRNOTAVAIL)
    }
    // The local port bind(port 0), or listen on an unbound socket, takes:
    // one no socket, connection or TIME-WAIT record holds, as Linux's
    // inet_csk_find_open_port finds one with no owner, starting at random
    // (RFC 6056 section 3.5, `EphemeralPorts::select_unbound`). None left
    // is EADDRINUSE, as inet_csk_get_port returns. Connections the endpoint
    // no longer has hold no port: their options are collected first, once
    // per call.
    fn bind_port(&mut self, reuse: bool) -> Result<u16> {
        self.collect_connection_options();
        #[cfg(feature = "packet-test")]
        if self.packets.is_some() {
            return self.sequential_port();
        }
        let (index, endpoint) = (&self.port_index, &self.endpoint);
        self.ephemeral
            .select_unbound(self.ephemeral_ports.clone(), reuse, |port| {
                !index.used(port) && !endpoint.time_wait_holds_port(port)
            })
            .ok_or(EADDRINUSE)
    }
    // Explicit synthetic packet profiles retain their sequential ports, free
    // of every user.
    #[cfg(feature = "packet-test")]
    fn sequential_port(&mut self) -> Result<u16> {
        if self.next_port >= 60000 {
            return Err(EADDRNOTAVAIL);
        }
        for _ in 0..20000 {
            let port = self.next_port;
            self.next_port = if port == 59999 { 40000 } else { port + 1 };
            if !self.port_index.used(port) && !self.endpoint.time_wait_holds_port(port) {
                return Ok(port);
            }
        }
        Err(EADDRNOTAVAIL)
    }
    // Gives socket `id` local address `local`, its port taken by `binding`,
    // in `port_index` too.
    fn set_local(&mut self, id: u64, local: SocketAddr, binding: ports::Binding) {
        let s = self.sockets.get_mut(&id).unwrap();
        if let Some(old) = s.local.replace(local) {
            self.port_index.socket(old.port(), s.binding, false);
            self.port_sockets.remove(&(old.port(), id));
        }
        s.binding = binding;
        self.port_index.socket(local.port(), binding, true);
        self.port_sockets.insert((local.port(), id));
    }
    // The sockets with a local address on `port`.
    fn sockets_on(&self, port: u16) -> impl Iterator<Item = (u64, &Socket)> + '_ {
        self.port_sockets
            .range((port, 0)..=(port, u64::MAX))
            .map(|&(_, id)| (id, &self.sockets[&id]))
    }
    fn push_connection_options(
        &mut self,
        options: (
            ConnectionId,
            u8,
            i32,
            Option<bool>,
            SocketAddr,
            ports::Binding,
        ),
    ) {
        self.port_index
            .connection(options.4.port(), options.5, true);
        self.port_connections
            .entry(options.4.port())
            .or_default()
            .insert(options.0);
        self.connection_options.push(options);
    }
    // Forgets the options of connections the endpoint has reclaimed since
    // the last call (those its reclaim log names), and the ports they held.
    fn collect_connection_options(&mut self) {
        let since = self.options_reclaimed;
        let (index, endpoint, options, ports) = (
            &mut self.port_index,
            &self.endpoint,
            &mut self.connection_options,
            &mut self.port_connections,
        );
        let mut forget = |p: &ConnectionOptions| {
            index.connection(p.4.port(), p.5, false);
            if let Some(users) = ports.get_mut(&p.4.port()) {
                users.remove(&p.0);
                if users.is_empty() {
                    ports.remove(&p.4.port());
                }
            }
        };
        match reclaimed_since(endpoint, since) {
            Some(reclaimed) => {
                for cid in reclaimed {
                    if let Some(p) = options.remove(cid) {
                        forget(&p);
                    }
                }
            }
            None => options.retain(|p| {
                let exists = endpoint.connection_exists(p.0);
                if !exists {
                    forget(p);
                }
                exists
            }),
        }
        self.options_reclaimed = self.endpoint.reclaimed();
        debug_assert!(
            self.connection_options
                .iter()
                .all(|p| self.endpoint.connection_exists(p.0))
        );
    }
    // Whether a TIME-WAIT record, or a connection whose descriptor is
    // closed and which is not CLOSED (Linux unhashes a closed socket from
    // its bind bucket), holds a local address a bind to `api` (`wire` on the wire,
    // `only` for IPV6_V6ONLY, on `zone`) overlaps, and refuses the bind:
    // unless both it and the bind have SO_REUSEADDR, as Linux's
    // inet_bind_conflict judges the timewait and orphaned sockets of the
    // port's bind bucket (sk_reuse && sk2->sk_reuse, tw_reuse for a
    // timewait socket). Sockets are judged by the caller.
    fn closed_binding_conflict(
        &self,
        api: SocketAddr,
        wire: SocketAddr,
        only: bool,
        zone: Option<address_policy::Zone>,
        reuse: bool,
    ) -> bool {
        let overlaps = |local: SocketAddr, link: Option<ntcp_host::path::LinkId>| {
            zone.zip(link).is_none_or(|(zone, link)| zone.link == link)
                && address_policy::binding_scopes(api, wire, only)
                    .into_iter()
                    .flatten()
                    .any(|bound| address_policy::binding_overlap(bound, local))
        };
        let held = |cid: ConnectionId| self.connection_socket(cid).is_some();
        let conflicts = |p: &ConnectionOptions| {
            p.4.port() == wire.port()
                && !held(p.0)
                && self
                    .endpoint
                    .retained_state(p.0)
                    .is_ok_and(|state| state != State::Closed)
                && !(reuse && self.endpoint.reuse_address(p.0) == Ok(true))
                && self
                    .endpoint
                    .retained_scoped_tuple(p.0)
                    .is_ok_and(|tuple| overlaps(tuple.tuple().local, tuple.zone()))
        };
        // The port's connections only: none elsewhere can overlap.
        let on_port = self.port_connections.get(&wire.port());
        let connection = on_port
            .into_iter()
            .flatten()
            .filter_map(|&cid| self.connection_options.get(cid))
            .any(conflicts);
        debug_assert_eq!(connection, self.connection_options.iter().any(conflicts));
        self.endpoint
            .time_wait_binds(wire.port())
            .any(|(tuple, tw_reuse)| {
                !(reuse && tw_reuse) && overlaps(tuple.tuple().local, tuple.zone())
            })
            || connection
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
        self.endpoint.set_mark(cid, s.mark).map_err(engine)?;
        self.endpoint
            .set_reuse_address(cid, s.reuse)
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
        // Descriptor and accept rollback do not determine binding lifetime:
        // retained final output keeps the exact core generation's authority.
        let _ = self.collect_paths();
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
                s.push_completion(Completion::ZeroCopy(next, next));
            }
            s.zc_next = next.wrapping_add(1);
            // A newly completed send wakes ET error-queue consumers even if
            // an older completion still keeps EPOLLERR asserted.
            s.readiness_generations[2] = s.readiness_generations[2].wrapping_add(1);
            s.settle_timestamp_charge(&mut self.timestamp_total);
        }
        Ok(n as i32)
    }
    fn readiness_bits(&self, id: u64) -> Result<i32> {
        let s = self.sockets.get(&id).ok_or(EBADF)?;
        // A held native owner cannot service its I/O yet, but querying it must
        // not block a poll/epoll scan of unrelated descriptors.
        if self.readiness_held(id) {
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
                let eof = s.peer_fin
                    || matches!(
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
                        && info.send_used < info.send_space
                        // Not while a write waits for memory beyond what its
                        // storage holds (sk_stream_memory_free).
                        && self.endpoint.send_admission_room(cid, None) != Ok(0)
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
    fn readiness_held(&self, id: u64) -> bool {
        self.egress.is_some() && self.command_held(id, &Op::Read(0))
    }
    fn refresh_readiness(&mut self, id: u64) -> Result<i32> {
        let bits = self.readiness_bits(id)?;
        // Releasing held output sends no event: look again next pass.
        if self.readiness_held(id) {
            self.touch(id);
        }
        let s = self.sockets.get_mut(&id).ok_or(EBADF)?;
        for (i, bit) in socket_options::EDGE_BITS.into_iter().enumerate() {
            if bits & !s.readiness & bit != 0 {
                s.readiness_generations[i] = s.readiness_generations[i].wrapping_add(1);
            }
        }
        let changed = bits != s.readiness || s.readiness_generations != s.published;
        s.readiness = bits;
        s.published = s.readiness_generations;
        if changed {
            self.log_change(id);
        }
        Ok(bits)
    }
    fn log_change(&mut self, id: u64) {
        let at = (self.changes % CHANGE_LOG as u64) as usize;
        if at == self.change_log.len() {
            self.change_log.push(id);
        } else {
            self.change_log[at] = id;
        }
        self.changes += 1;
    }
    // The sockets whose readiness changed since change `since` and the
    // readiness of each of `probe`, each socket once; None once the log no
    // longer reaches back to `since`.
    fn ready_changes(&self, since: u64, probe: Vec<u64>) -> Option<Vec<(u64, i32, [u64; 5])>> {
        let missed = self.changes.checked_sub(since)?;
        if missed > CHANGE_LOG as u64 {
            return None;
        }
        let logged = (since..self.changes).map(|n| self.change_log[(n % CHANGE_LOG as u64) as usize]);
        let mut seen = HashSet::new();
        Some(
            logged
                .chain(probe)
                .filter(|&id| seen.insert(id))
                .map(|id| match self.sockets.get(&id) {
                    Some(s) => (id, s.readiness, s.readiness_generations),
                    None => (id, -1, [0; 5]),
                })
                .collect(),
        )
    }
    //= https://www.rfc-editor.org/rfc/rfc7413#appendix-A.2
    //# The application only needs to enable the reception of Fast Open requests via a new TCP_FASTOPEN
    //# setsockopt() socket option before listen().
    //= https://www.rfc-editor.org/rfc/rfc7413#appendix-A.2
    //# Traditionally, accept() returns only after a socket is connected. But, for a Fast Open connection,
    //# accept() returns upon receiving a SYN with a valid Fast Open cookie and data, and the data is
    //# available to be read through, e.g., recvmsg(), read().
    //= https://www.rfc-editor.org/rfc/rfc7413#appendix-A.2
    //# The option enables Fast Open on the listener socket. The option value specifies the PendingFastOpenRequests threshold, i.e., the maximum length of pending SYNs with data payload. Once enabled, the TCP implementation will respond with TFO cookies per request.
    fn execute(&mut self, id: u64, op: Op) -> Result<Reply> {
        if let Op::SetDestinationRoute(destination, policy) = op {
            // Destination policies carry no zone: a link-local key would be ambiguous.
            if !crate::ip::global_unicast(destination)
                || destination.is_ipv4() != self.local.is_ipv4()
            {
                return Err(EINVAL);
            }
            let now = self.clock()?;
            self.endpoint
                .set_destination_route(now, destination, policy)
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
        let now = self.clock()?;
        self.endpoint.on_timeout(now, 0).map_err(engine)?;
        self.collect_paths()?;
        let result = self.dispatch(id, op);
        let _ = self.refresh_readiness(id);
        result
    }
    // Operation `op` on socket `id`. Its effects may move the socket's
    // readiness, and what it queued (output leaving, say) may move it
    // again before the next pass: the socket is refreshed then.
    fn dispatch(&mut self, id: u64, op: Op) -> Result<Reply> {
        let result = self.dispatch_op(id, op);
        self.touch(id);
        result
    }
    fn dispatch_op(&mut self, id: u64, op: Op) -> Result<Reply> {
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
        if let Op::ReadyChanges(since, probe) = op {
            // The pass above refreshed every socket queued for it, so each
            // socket's readiness is current (debug-checked there).
            match self.ready_changes(since, probe) {
                Some(ready) => out.ready = ready,
                None => out.value = 1,
            }
            out.timeout_us = self.changes;
            return Ok(out);
        }
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
                // Keyed by peer address alone, which names no zone.
                if policy.is_some_and(|(peer, _)| {
                    peer.port() == 0 || !crate::ip::global_unicast(peer.ip())
                }) {
                    return Err(EINVAL);
                }
                self.sockets.get_mut(&id).unwrap().client_policy = policy;
            }
            Op::SetFastOpenReceiveAuthority(listener_socket) => {
                if !matches!(s.handle, Handle::Fresh) || s.deferred_peer.is_some() {
                    return Err(EINVAL);
                }
                let authority = listener_socket
                    .map(|listener_socket| {
                        let listener_socket = self.sockets.get(&listener_socket).ok_or(EBADF)?;
                        let Handle::Listener(listener) = listener_socket.handle else {
                            return Err(EINVAL);
                        };
                        let local = s.local.map_or(self.local, |a| {
                            if a.ip().is_unspecified() {
                                self.local
                            } else {
                                a.ip()
                            }
                        });
                        if s.domain == AF_INET6 && s.v6only && local.is_ipv4() {
                            return Err(EAFNOSUPPORT);
                        }
                        self.endpoint
                            .validate_fast_open_receive_authority(listener, local)
                            .map_err(engine)?;
                        Ok(listener)
                    })
                    .transpose()?;
                self.sockets.get_mut(&id).unwrap().receive_authority = authority;
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
                if credential.is_some_and(|(peer, _)| {
                    peer.port() == 0 || !crate::ip::global_unicast(peer.ip())
                }) {
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
                let policy = FastOpenCookiePolicy::LinuxSipHash24(key.clone());
                let now = self.clock()?;
                let s = self.sockets.get(&id).ok_or(EBADF)?;
                // Only a configured key, under its original lease: this
                // call never starts a new lifetime.
                let lease = self
                    .external_fast_open_keys
                    .iter()
                    .find(|configured| configured.key == key)
                    .ok_or(EINVAL)?
                    .lease;
                let key = ntcp::FastOpenServerKey::LinuxSipHash24(key);
                if let Handle::Listener(listener) = s.handle {
                    self.endpoint
                        .install_listener_fast_open_key(now, listener, key, lease, false)
                        .map_err(engine)?;
                } else {
                    self.endpoint
                        .register_fast_open_key(now, key, lease)
                        .map_err(engine)?;
                }
                let socket = self.sockets.get_mut(&id).unwrap();
                socket.fast_open_cookie_policy = Some(policy);
                socket.fast_open_key_lease = Some(lease);
            }
            Op::Bind(addr) => {
                let mut local = s.normalize_address(addr, self.local, true)?;
                if !matches!(s.handle, Handle::Fresh)
                    || s.local.is_some()
                    || s.deferred_peer.is_some()
                {
                    return Err(EINVAL);
                }
                let zone = self.resolve_zone(addr)?;
                // The application address keeps its zone apart, like the wire one.
                let mut addr = addr;
                if let SocketAddr::V6(v) = &mut addr {
                    v.set_scope_id(0);
                }
                // A port's assigned address is local; a link-local one only
                // on the port (link) that owns it. A tentative or duplicate
                // one is not available (EADDRNOTAVAIL).
                let owned = self.ports.iter().any(|port| {
                    port.address == local.ip()
                        && zone.is_none_or(|zone| port.link() == Some(zone.link))
                        && self.assigned(port)
                });
                if !s.freebind && !owned && !local.ip().is_unspecified() {
                    return Err(EADDRNOTAVAIL);
                }
                if let Some(authority) = s.receive_authority {
                    let ip = if local.ip().is_unspecified() {
                        self.local
                    } else {
                        local.ip()
                    };
                    self.endpoint
                        .validate_fast_open_receive_authority(authority, ip)
                        .map_err(engine)?;
                }
                let reuse = s.reuse;
                let new_v6only = s.v6only;
                if addr.port() == 0 {
                    addr.set_port(self.bind_port(reuse)?);
                    local.set_port(addr.port());
                }
                // A binding overlaps only one on its own port.
                let conflicts = |(other, s): (u64, &Socket)| {
                    other != id
                        && !(reuse && s.reuse && matches!(s.handle, Handle::Connection(_)))
                        && s.conflicts_binding(addr, local, new_v6only, zone)
                };
                let socket = self.sockets_on(local.port()).any(conflicts);
                debug_assert_eq!(
                    socket,
                    self.sockets.iter().map(|(&id, s)| (id, s)).any(conflicts)
                );
                if socket || self.closed_binding_conflict(addr, local, new_v6only, zone, reuse) {
                    return Err(EADDRINUSE);
                }
                self.set_local(id, local, ports::Binding::Bound);
                let socket = self.sockets.get_mut(&id).unwrap();
                socket.bound_addr = Some(addr);
                socket.zone = zone;
            }
            Op::Listen(backlog) => {
                if !matches!(s.handle, Handle::Fresh) || s.deferred_peer.is_some() {
                    return Err(EOPNOTSUPP);
                }
                let fast_open_limit = s.fast_open_limit;
                let cookie_policy = s.fast_open_cookie_policy.clone();
                let cookie_lease = s.fast_open_key_lease;
                let capacities = (s.send_capacity, s.receive_capacity);
                let application_timeout = user_timeout_us(s.user_timeout_ms)?;
                let syn_retries = s.syn_retries;
                let user_mss = s.user_mss;
                // Exactly the bound address on its link; otherwise every link.
                let zone = s.zone.map(|zone| zone.link);
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
                        local.set_port(self.bind_port(s.reuse)?);
                        local
                    }
                };
                // As Linux's __sys_listen clamps the unsigned backlog to
                // somaxconn, here the endpoint's connections: a negative
                // one is the largest, and 0 still queues one connection.
                let backlog = (backlog as u32).min(self.defaults.max_connections as u32);
                let listener = self
                    .endpoint
                    .listen_scoped(local, zone, backlog as usize)
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
                #[cfg(feature = "tfo-linux-cookie")]
                let now = self.clock().inspect_err(|_| {
                    let _ = self.endpoint.close_listener(listener);
                })?;
                #[cfg(feature = "tfo-linux-cookie")]
                let installed =
                    if let (Some(FastOpenCookiePolicy::LinuxSipHash24(key)), Some(lease)) =
                        (cookie_policy.clone(), cookie_lease)
                    {
                        self.endpoint.install_listener_fast_open_key(
                            now,
                            listener,
                            ntcp::FastOpenServerKey::LinuxSipHash24(key),
                            lease,
                            false,
                        )
                    } else {
                        self.endpoint
                            .set_listener_fast_open_cookie_policy(listener, cookie_policy)
                    };
                #[cfg(not(feature = "tfo-linux-cookie"))]
                let installed = {
                    let _ = cookie_lease;
                    self.endpoint
                        .set_listener_fast_open_cookie_policy(listener, cookie_policy)
                };
                if let Err(e) = installed {
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
                self.set_local(id, local, ports::Binding::Bound);
                let s = self.sockets.get_mut(&id).unwrap();
                if s.domain == AF_INET6 && s.bound_addr.is_none() {
                    s.bound_addr = Some(SocketAddr::new(s.api_unspecified(), local.port()));
                }
                self.set_handle(id, Handle::Listener(listener));
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
                child.linger = s.linger;
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
                if let Some((
                    _,
                    _,
                    receive,
                    send,
                    (nodelay, cork, inq, lowat, freebind, other_tos, other_discover, linger),
                )) = self.child_timeouts.remove(cid)
                {
                    child.receive_timeout_us = receive;
                    child.send_timeout_us = send;
                    child.nodelay = nodelay;
                    child.cork = cork;
                    child.inq = inq;
                    child.notsent_lowat = lowat;
                    child.freebind = freebind;
                    child.linger = linger;
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
                child.mark = self.endpoint.mark(cid).map_err(engine)?;
                if let Some(p) = self.connection_options.get(cid) {
                    child.set_wire_ip_policy(self.local, p.1, p.2);
                    child.zerocopy = p.3.unwrap_or(false);
                }
                if let Some((_, options)) = self.child_timestamps.remove(cid) {
                    self.rx_software_children -=
                        usize::from(options.flags & crate::timestamping::RX_SOFTWARE != 0);
                    child.timestamps.options = options;
                }
                child.zone = match self.connection_zone(cid) {
                    Ok(zone) => zone,
                    Err(e) => {
                        self.rollback_connection(cid);
                        return Err(e);
                    }
                };
                let peer = address_policy::scoped(child.api_address(tuple.remote), child.zone);
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
                // Core emits Acceptable for each child that joins; stay readable until accept returns EAGAIN.
            }
            Op::Connect(addr) => {
                let remote = s.normalize_address(addr, self.local, false)?;
                self.check_address(remote)?;
                if !self.check_connect(id)? {
                    return Ok(out);
                }
                if remote.port() == 0 {
                    return Err(EINVAL);
                }
                let zone = self.connect_zone(id, addr)?;
                let (local, binding) = self.connect_local(id, remote, zone)?;
                if let Some(authority) = self.sockets[&id].receive_authority {
                    self.endpoint
                        .validate_fast_open_receive_authority(authority, local.ip())
                        .map_err(engine)?;
                }
                // Previously saved options do not authorize a new TFO open
                // after administrative disablement. Ordinary connect still works.
                if self.sockets[&id].fast_open_connect
                    && self.socket_policy.fast_open_client_enabled
                {
                    self.endpoint.enable_fast_open().map_err(engine)?;
                    let now = self.clock()?;
                    let socket = &self.sockets[&id];
                    let policy = socket
                        .client_policy_for(remote, self.socket_policy.fast_open_client_policy);
                    let allowed = self
                        .endpoint
                        .can_defer_scoped_fast_open(
                            now,
                            local.ip(),
                            remote,
                            zone.map(|zone| zone.link),
                            socket.server_cookie_for(remote),
                            policy,
                        )
                        .map_err(engine)?;
                    if allowed {
                        // The deferred open keeps the link resolved now.
                        self.set_local(id, local, binding);
                        self.port_index.defer((local, remote), true);
                        let s = self.sockets.get_mut(&id).unwrap();
                        s.deferred_peer = Some(remote);
                        s.deferred_client_policy = Some(policy);
                        s.zone = zone;
                        return Ok(out);
                    }
                    self.start_connection(id, local, binding, remote, zone, Some(&[]))?;
                } else {
                    self.start_connection(id, local, binding, remote, zone, None)?;
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
                let completed_failure = terminal && !s.connected && !s.connect_pending;
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
                if terminal && !s.connected && available == 0 {
                    return Err(ENOTCONN);
                }
                // Size to what the read can copy, as tcp_recvmsg copies at most
                // what is queued. Core reads take initialized slices; one byte
                // keeps an empty read's would-block/EOF/error result.
                out.bytes
                    .resize(capacity.min(BYTES).min(available.max(1)), 0);
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
                if completed_failure
                    && self.endpoint.terminal_readable_bytes(cid).map_err(engine)? == 0
                {
                    self.release_failed_connect(id, cid);
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
                let s = self.sockets.get_mut(&id).unwrap();
                s.pop_completion();
                s.settle_timestamp_charge(&mut self.timestamp_total);
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
                        // Linux tcp_close: a socket already reset or in
                        // TIME-WAIT sends nothing, whatever SO_LINGER says.
                        if !matches!(
                            self.endpoint.state(cid),
                            Ok(State::Closed | State::TimeWait)
                        ) {
                            // Linux tcp_close checks a zero linger time after
                            // unread data (which Endpoint::close resets for
                            // too) and disconnects: RFC 9293 ABORT.
                            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.6
                            //# This command causes all pending SENDs and RECEIVES to be aborted, the
                            //# TCB to be removed, and a special RST message to be sent to the remote
                            //# TCP peer of the connection.
                            if s.linger.aborts() {
                                let _ = self.endpoint.abort(cid);
                            } else {
                                let _ = self.endpoint.close(cid);
                            }
                        }
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
                let s = self.remove_socket(id).unwrap();
                if let Some(local) = s.local {
                    self.port_index.socket(local.port(), s.binding, false);
                    if let Some(peer) = s.deferred_peer {
                        self.port_index.defer((local, peer), false);
                    }
                }
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
            // Adapter state read at close; a listener's passes to its children.
            Op::SetLinger(onoff, linger) => {
                let s = self.sockets.get_mut(&id).unwrap();
                s.linger = s.linger.set(onoff, linger);
            }
            Op::GetLinger => {
                out.bytes = s
                    .linger
                    .get()
                    .iter()
                    .flat_map(|v| v.to_ne_bytes())
                    .collect();
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
                    // Keep the accepted sticky byte for getsockopt and child
                    // snapshots; only DSCP is passed to TCP's outgoing policy.
                    (IPPROTO_IPV6, IPV6_TCLASS) => s.ipv6_tclass = value as u8,
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
                        (SOL_SOCKET, SO_MARK) => {
                            self.endpoint.set_mark(cid, s.mark).map_err(engine)?
                        }
                        (SOL_SOCKET, SO_REUSEADDR) => self
                            .endpoint
                            .set_reuse_address(cid, s.reuse)
                            .map_err(engine)?,
                        //= https://www.rfc-editor.org/rfc/rfc3542#section-6.5
                        //# There are cases where the kernel needs to control the
                        //# traffic class value and conflicts with the user-specified
                        //# value on the outgoing traffic. An example is an
                        //# implementation of ECN in the kernel, setting 2 bits of the
                        //# traffic class value. In such cases, the kernel should
                        //# override the user-specified value.
                        //= https://www.rfc-editor.org/rfc/rfc3542#section-4.1
                        //# When the application uses setsockopt to specify the
                        //# above options it is expected that TCP will start using
                        //# the new information when sending segments. However,
                        //# TCP may or may not use the new information when
                        //# retransmitting segments that were originally sent
                        //# when the old sticky options were in effect.
                        (IPPROTO_IP, IP_TOS) | (IPPROTO_IPV6, IPV6_TCLASS) => {
                            let dscp = s.wire_tos(self.local) >> 2;
                            if let Some(host) = &mut self.host {
                                host.rebind_dscp(&mut self.endpoint, cid, dscp)
                                    .map_err(host_error)?;
                            } else {
                                self.endpoint.set_dscp(cid, dscp).map_err(engine)?;
                            }
                        }
                        _ => (),
                    }
                }
                if let Handle::Connection(cid) = s.handle
                    && let Some(p) = self.connection_options.get_mut(cid)
                {
                    p.1 = s.wire_tos(self.local);
                    p.2 = s.wire_discover(self.local);
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
                // The list links are the live socket's, not the copy's.
                candidate.lists = self.sockets[&id].lists;
                self.sockets.insert(id, candidate);
                self.settle_timestamp_charge(id);
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
                    //# Issuing getsockopt() for the above options will return the
                    //# sticky option value i.e., the value set with setsockopt().
                    //= https://www.rfc-editor.org/rfc/rfc3542#section-4
                    //# For the IPV6_TCLASS option, it will return the kernel default
                    //# value.
                    (IPPROTO_IPV6, IPV6_TCLASS) => s.ipv6_tclass as i32,
                    (IPPROTO_IP, IP_MTU_DISCOVER) => s.discover,
                    (IPPROTO_IPV6, IPV6_MTU_DISCOVER) => s.ipv6_discover,
                    // Linux reports the connected route's dst_mtu: the bound
                    // path's estimate, never the MSS, the sending budget or
                    // the connection's own discovery state.
                    (IPPROTO_IP, IP_MTU) | (IPPROTO_IPV6, IPV6_MTU) => {
                        let Handle::Connection(cid) = s.handle else {
                            return Err(ENOTCONN);
                        };
                        match &self.host {
                            // A connection whose path authority is already
                            // released has no route, like Linux's reset dst.
                            Some(host) => {
                                host.path_mtu_estimate(&self.endpoint, cid)
                                    .map_err(|error| match error {
                                        ntcp_host::Error::InvalidContext => ENOTCONN,
                                        error => host_error(error),
                                    })? as i32
                            }
                            // A backend-less core fixture has no shared path:
                            // the connection's own estimate is its only one.
                            None => {
                                self.endpoint
                                    .path_mtu_info(cid)
                                    .map_err(engine)?
                                    .ok_or(EOPNOTSUPP)?
                                    .current_mtu as i32
                            }
                        }
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
                let zone = s.zone;
                out.addr = Some(address_policy::scoped(if peer {
                    if let Some(peer) = s.deferred_peer {
                        out.addr = Some(address_policy::scoped(s.api_address(peer), zone));
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
                }, zone));
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
            | Op::SetDestinationRoute(..)
            | Op::ReadyChanges(..) => {
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

#[cfg(test)]
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
#[path = "runtime_handshake_error_tests.rs"]
mod handshake_errors;

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
