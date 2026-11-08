//! Opt-in safe DPDK host: owns EAL, one port per `Port`, one mempool per
//! queue, and rte_flow rules, and hands each queue pair to one worker thread as
//! a `HostedQueue` (a `Dpdk` adapter whose borrowed objects it keeps alive).
//! Teardown order is structural: flows and queues hold the port, so the port
//! is stopped and closed, and its pools freed, only after all of them drop.

use crate::native::Dpdk;
use ntcp_io::{
    ClockDescriptor, ClockDomain, OwnedPacket, PacketIo, PacketLayer, Payload, ReceivedPacket,
    TcpSegmentationCapabilities, TcpSegmentationError, TcpSegmentationRequest,
    TimestampCapabilities, TimestampUnit, TransmitTime, TxOutcome, TxSchedulingCapabilities,
    TxSchedulingError, TxTimestampCompletion, TxTimestampRequest, ZeroCopyCapabilities,
};
use std::{
    cell::Cell,
    ffi::{CStr, CString, c_char, c_void},
    io,
    marker::PhantomData,
    net::Ipv4Addr,
    ptr::NonNull,
    rc::Rc,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

#[repr(C)]
struct PortSetup {
    queues: u16,
    rx_desc: u16,
    tx_desc: u16,
    mtu: u16,
    mbuf_data_size: u16,
    rx_timestamps: u8,
}

unsafe extern "C" {
    fn ntcp_dpdk_eal_init(argc: i32, argv: *mut *mut c_char) -> i32;
    fn ntcp_dpdk_main_lcore() -> u32;
    fn ntcp_dpdk_lcore_id() -> u32;
    fn ntcp_dpdk_thread_register() -> i32;
    fn ntcp_dpdk_thread_unregister();
    fn ntcp_dpdk_port_claim(devargs: *const c_char, owner: *mut u64, port: *mut u16) -> i32;
    fn ntcp_dpdk_port_isolate(port: u16, message: *mut c_char, capacity: usize) -> i32;
    fn ntcp_dpdk_port_socket(port: u16) -> i32;
    fn ntcp_dpdk_pool_create(
        name: *const c_char,
        count: u32,
        data_size: u16,
        socket: i32,
        error: *mut i32,
    ) -> *mut c_void;
    fn ntcp_dpdk_pool_free(pool: *mut c_void) -> i32;
    fn ntcp_dpdk_port_configure(
        port: u16,
        config: *const PortSetup,
        rx_desc: *mut u16,
        tx_desc: *mut u16,
        stage: *mut i32,
    ) -> i32;
    fn ntcp_dpdk_port_queue_setup(
        port: u16,
        queue: u16,
        rx_desc: u16,
        tx_desc: u16,
        socket: i32,
        pool: *mut c_void,
    ) -> i32;
    fn ntcp_dpdk_port_start(port: u16) -> i32;
    fn ntcp_dpdk_port_release(port: u16, owner: u64, started: i32);
    fn ntcp_dpdk_read_clock(port: u16, clock: *mut u64) -> i32;
    fn ntcp_dpdk_port_mac(port: u16, mac: *mut u8) -> i32;
    fn ntcp_dpdk_flow_ipv4(
        port: u16,
        dst: u32,
        queue: u16,
        error: *mut i32,
        message: *mut c_char,
        capacity: usize,
    ) -> *mut c_void;
    fn ntcp_dpdk_flow_destroy(port: u16, flow: *mut c_void) -> i32;
}

const LCORE_ID_ANY: u32 = u32::MAX;

// Negative errno from DPDK, with the failed step named.
fn dpdk_error(context: &str, result: i32) -> io::Error {
    let errno = result.checked_neg().unwrap_or(5); // EIO
    let source = io::Error::from_raw_os_error(errno);
    let kind = match errno {
        // ENOSYS: no ops table (e.g. no rte_flow); ENOTSUP/EOPNOTSUPP share 95.
        38 | 95 => io::ErrorKind::Unsupported,
        _ => source.kind(),
    };
    io::Error::new(kind, format!("{context}: {source}"))
}

fn flow_error(context: &str, result: i32, message: &[c_char]) -> io::Error {
    // SAFETY: the shim always NUL-terminates within capacity (snprintf).
    let detail = unsafe { CStr::from_ptr(message.as_ptr()) }.to_string_lossy();
    let error = dpdk_error(context, result);
    if detail.is_empty() {
        error
    } else {
        io::Error::new(error.kind(), format!("{error} ({detail})"))
    }
}

struct EalState {
    args: Vec<String>,
    result: Result<Eal, (i32, String)>,
}

static EAL: OnceLock<EalState> = OnceLock::new();

/// The process-wide DPDK Environment Abstraction Layer. EAL can be
/// initialized once per process and is never cleaned up implicitly: ports,
/// pools and DMA memory may be referenced until exit.
#[derive(Debug)]
pub struct Eal {
    main_lcore: u32,
}

impl Eal {
    /// Initialize EAL with `args` (EAL options only, without a program name:
    /// e.g. `["-l", "0", "-a", "0000:3b:00.0"]`). `rte_eal_init` pins the
    /// calling thread to the main lcore's CPU set and makes it that lcore.
    /// A later call with identical args returns the same handle; different
    /// args are an error, as is any call after a failed initialization (DPDK
    /// does not support retrying it).
    pub fn init<I, S>(args: I) -> io::Result<&'static Eal>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let args: Vec<String> = args.into_iter().map(Into::into).collect();
        let state = EAL.get_or_init(|| EalState {
            result: init_eal(&args),
            args: args.clone(),
        });
        if state.args != args {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "EAL already initialized with different arguments",
            ));
        }
        state
            .result
            .as_ref()
            .map_err(|(result, context)| dpdk_error(context, *result))
    }

    /// Arguments EAL was initialized with.
    pub fn args(&self) -> &'static [String] {
        &EAL.get().unwrap().args
    }

    pub fn main_lcore(&self) -> u32 {
        self.main_lcore
    }
}

fn init_eal(args: &[String]) -> Result<Eal, (i32, String)> {
    let mut owned = Vec::with_capacity(args.len() + 1);
    for arg in std::iter::once("ntcp").chain(args.iter().map(String::as_str)) {
        owned.push(CString::new(arg).map_err(|_| (-22, "EAL argument contains NUL".into()))?);
    }
    // EAL may keep argv pointers and permute the array; both live forever,
    // like EAL itself.
    let owned = owned.leak();
    let argv: &mut [*mut c_char] = Vec::leak(
        owned
            .iter_mut()
            .map(|arg| arg.as_ptr().cast_mut())
            .collect(),
    );
    // SAFETY: argc matches the leaked, NUL-terminated, never-freed argv. The
    // OnceLock guarantees at most one call per process from this crate.
    let result = unsafe { ntcp_dpdk_eal_init(argv.len() as i32, argv.as_mut_ptr()) };
    if result < 0 {
        return Err((result, "rte_eal_init".into()));
    }
    Ok(Eal {
        // SAFETY: EAL is initialized.
        main_lcore: unsafe { ntcp_dpdk_main_lcore() },
    })
}

/// Port setup. Construct with `PortConfig::new` and adjust fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortConfig {
    /// Devargs: a PCI address (`0000:3b:00.0`, may carry PMD arguments) or a
    /// vdev (`net_ring0`). Probed if no port matches yet; must match exactly one.
    pub device: String,
    /// Number of RX/TX queue pairs; queue `i` is RX `i` and TX `i`.
    pub queues: u16,
    pub rx_desc: u16,
    pub tx_desc: u16,
    /// IP MTU configured on the port.
    pub mtu: u16,
    /// Mbufs in each queue's pool. Must exceed `rx_desc + tx_desc` (after the
    /// PMD rounds them) or the pool can be exhausted by the rings alone.
    pub mbufs_per_queue: u32,
    /// Packet bytes per mbuf, excluding DPDK headroom. Frames longer than
    /// this need RX scatter and TX multi-segment support from the device.
    pub mbuf_data_size: u16,
    /// rte_flow isolated mode, set before configuration. With bifurcated
    /// mlx5 only traffic matched by flows (`Port::steer_ipv4`) reaches DPDK;
    /// the kernel keeps the rest. Without it, unmatched traffic lands on queue 0.
    pub isolate: bool,
    /// Enable RTE_ETH_RX_OFFLOAD_TIMESTAMP (required capability) and expose
    /// device-clock RX timestamps on every hosted queue.
    pub rx_timestamps: bool,
}

impl PortConfig {
    pub fn new(device: impl Into<String>) -> Self {
        Self {
            device: device.into(),
            queues: 1,
            rx_desc: 1024,
            tx_desc: 1024,
            mtu: 1500,
            // 2^n - 1 suits the ring mempool driver.
            mbufs_per_queue: 4095,
            // RTE_MBUF_DEFAULT_DATAROOM.
            mbuf_data_size: 2048,
            isolate: false,
            rx_timestamps: false,
        }
    }
}

// Distinguishes pools and device-clock calibrations across ports, including
// a port id reused after close.
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

struct PortInner {
    _eal: &'static Eal,
    port: u16,
    owner: u64,
    started: bool,
    pools: Vec<NonNull<c_void>>,
    taken: Box<[AtomicBool]>,
    clock: Option<ClockDescriptor>,
}

// SAFETY: the pool pointers are only passed to thread-agnostic DPDK calls
// (adapter construction, free at teardown); ethdev control and flow calls are
// serialized by ethdev or the PMD. Queue exclusivity is enforced by `taken`.
unsafe impl Send for PortInner {}
// SAFETY: as above; shared access only reads immutable fields or atomics.
unsafe impl Sync for PortInner {}

impl Drop for PortInner {
    fn drop(&mut self) {
        // Every Flow and HostedQueue holds this Arc, so all flows are destroyed
        // and every adapter (with its prefetched mbufs) is gone.
        // SAFETY: claimed port; nothing else references it any more.
        unsafe { ntcp_dpdk_port_release(self.port, self.owner, i32::from(self.started)) };
        for pool in &self.pools {
            // SAFETY: the port no longer references the pool. A pool with
            // outstanding mbufs is retained, never freed under them.
            unsafe { ntcp_dpdk_pool_free(pool.as_ptr()) };
        }
    }
}

/// A started Ethernet port owned by this process (ethdev ownership), with
/// one pool per queue pair on the device's NUMA socket. RX keeps complete,
/// untransformed frames: no VLAN/QinQ stripping, LRO or other byte-changing
/// offloads; RX scatter and TX multi-segment are enabled only as described on
/// `PortConfig`. No RSS: queues receive what flows steer to them.
pub struct Port {
    inner: Arc<PortInner>,
}

impl Port {
    pub fn start(eal: &'static Eal, config: PortConfig) -> io::Result<Port> {
        let invalid =
            |message: &str| io::Error::new(io::ErrorKind::InvalidInput, message.to_owned());
        if config.queues == 0 || config.rx_desc == 0 || config.tx_desc == 0 {
            return Err(invalid("queues and descriptor counts must be nonzero"));
        }
        let devargs =
            CString::new(config.device.as_str()).map_err(|_| invalid("device contains NUL"))?;
        let generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
        let (mut owner, mut port) = (0, 0);
        // SAFETY: EAL is initialized (`eal`); devargs is NUL-terminated.
        let result = unsafe { ntcp_dpdk_port_claim(devargs.as_ptr(), &mut owner, &mut port) };
        if result < 0 {
            return Err(dpdk_error(&format!("claim {}", config.device), result));
        }
        // From here, dropping `inner` releases whatever has been set up.
        let mut inner = PortInner {
            _eal: eal,
            port,
            owner,
            started: false,
            pools: Vec::with_capacity(usize::from(config.queues)),
            taken: (0..config.queues).map(|_| AtomicBool::new(false)).collect(),
            clock: config.rx_timestamps.then_some(ClockDescriptor {
                domain: ClockDomain::Device(u64::from(port)),
                unit: TimestampUnit::RawTicks {
                    identity: generation,
                },
            }),
        };
        if config.isolate {
            let mut message = [0; 128];
            // SAFETY: claimed, unconfigured port; buffer capacity is passed.
            let result =
                unsafe { ntcp_dpdk_port_isolate(port, message.as_mut_ptr(), message.len()) };
            if result < 0 {
                return Err(flow_error("rte_flow_isolate", result, &message));
            }
        }
        let setup = PortSetup {
            queues: config.queues,
            rx_desc: config.rx_desc,
            tx_desc: config.tx_desc,
            mtu: config.mtu,
            mbuf_data_size: config.mbuf_data_size,
            rx_timestamps: u8::from(config.rx_timestamps),
        };
        let (mut rx_desc, mut tx_desc, mut stage) = (0, 0, 0);
        // SAFETY: claimed port; all pointers are valid for the call.
        let result = unsafe {
            ntcp_dpdk_port_configure(port, &setup, &mut rx_desc, &mut tx_desc, &mut stage)
        };
        if result < 0 {
            let context = match stage {
                2 => "queue count exceeds device limits",
                3 => "device lacks RTE_ETH_RX_OFFLOAD_TIMESTAMP",
                4 => "frames exceed one mbuf but device lacks RX scatter",
                5 => "frames exceed one mbuf but device lacks TX multi-segment",
                6 => "rte_eth_dev_configure",
                7 => "rte_eth_dev_adjust_nb_rx_tx_desc",
                _ => "rte_eth_dev_info_get",
            };
            return Err(dpdk_error(context, result));
        }
        if u64::from(config.mbufs_per_queue) <= u64::from(rx_desc) + u64::from(tx_desc) {
            return Err(invalid(&format!(
                "mbufs_per_queue {} must exceed rx_desc {rx_desc} + tx_desc {tx_desc}",
                config.mbufs_per_queue
            )));
        }
        // SAFETY: valid port.
        let socket = unsafe { ntcp_dpdk_port_socket(port) };
        for queue in 0..config.queues {
            let name = CString::new(format!("ntcp_p{generation}_q{queue}")).unwrap();
            let mut error = 0;
            // SAFETY: EAL initialized; name is NUL-terminated.
            let pool = unsafe {
                ntcp_dpdk_pool_create(
                    name.as_ptr(),
                    config.mbufs_per_queue,
                    config.mbuf_data_size,
                    socket,
                    &mut error,
                )
            };
            let pool =
                NonNull::new(pool).ok_or_else(|| dpdk_error("rte_pktmbuf_pool_create", error))?;
            inner.pools.push(pool);
            // SAFETY: configured, stopped port; the pool outlives the port
            // (freed after release in PortInner::drop).
            let result = unsafe {
                ntcp_dpdk_port_queue_setup(port, queue, rx_desc, tx_desc, socket, pool.as_ptr())
            };
            if result < 0 {
                return Err(dpdk_error(&format!("queue {queue} setup"), result));
            }
        }
        // SAFETY: fully configured port.
        let result = unsafe { ntcp_dpdk_port_start(port) };
        if result < 0 {
            return Err(dpdk_error("rte_eth_dev_start", result));
        }
        inner.started = true;
        Ok(Port {
            inner: Arc::new(inner),
        })
    }

    pub fn port_id(&self) -> u16 {
        self.inner.port
    }

    pub fn queues(&self) -> u16 {
        self.inner.taken.len() as u16
    }

    /// Device clock of RX timestamps when `rx_timestamps` was enabled. Its
    /// RawTicks identity names this port's calibration: convert timestamps
    /// carrying exactly this descriptor with a `ClockCalibration` fed from
    /// `read_clock`.
    pub fn clock(&self) -> Option<ClockDescriptor> {
        self.inner.clock
    }

    /// Current device clock (rte_eth_read_clock), in the same raw units as
    /// RX timestamps. Unsupported on devices without a readable clock.
    pub fn read_clock(&self) -> io::Result<u64> {
        read_clock(self.inner.port)
    }

    /// The port's default MAC address (rte_eth_macaddr_get), as the device
    /// reports it at the time of the call: the source address of its frames
    /// and the hardware address ARP answers with. Reported as is; a virtual
    /// device without an address (the ring PMD) reports all zeros.
    pub fn mac_address(&self) -> io::Result<[u8; 6]> {
        mac_address(self.inner.port)
    }

    /// Steer IPv4 packets with destination `dst` to `queue` (ETH / IPV4 dst →
    /// QUEUE). The rule is destroyed when the `Flow` drops, always before
    /// the port stops.
    pub fn steer_ipv4(&self, dst: Ipv4Addr, queue: u16) -> io::Result<Flow> {
        if queue >= self.queues() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "flow target queue out of range",
            ));
        }
        let (mut error, mut message) = (0, [0; 128]);
        // SAFETY: started port; buffer capacity is passed.
        let flow = unsafe {
            ntcp_dpdk_flow_ipv4(
                self.inner.port,
                u32::from(dst).to_be(),
                queue,
                &mut error,
                message.as_mut_ptr(),
                message.len(),
            )
        };
        let flow =
            NonNull::new(flow).ok_or_else(|| flow_error("rte_flow_create", error, &message))?;
        Ok(Flow {
            port: self.inner.clone(),
            flow,
        })
    }

    /// Hand out queue pair `index` unless a handle or an attached queue holds
    /// it. A handle dropped unattached, or consumed by a failed `attach`,
    /// returns the index; once attached, the queue stays taken for the port's
    /// lifetime.
    pub fn take_queue(&self, index: u16) -> io::Result<QueueHandle> {
        let taken = self.inner.taken.get(usize::from(index)).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "queue index out of range")
        })?;
        if taken.swap(true, Ordering::AcqRel) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "queue already taken",
            ));
        }
        Ok(QueueHandle {
            port: self.inner.clone(),
            queue: index,
            attached: false,
        })
    }
}

fn read_clock(port: u16) -> io::Result<u64> {
    let mut clock = 0;
    // SAFETY: the caller holds the started port alive; output is writable.
    let result = unsafe { ntcp_dpdk_read_clock(port, &mut clock) };
    if result < 0 {
        return Err(dpdk_error("rte_eth_read_clock", result));
    }
    Ok(clock)
}

fn mac_address(port: u16) -> io::Result<[u8; 6]> {
    let mut mac = [0; 6];
    // SAFETY: the caller holds the port alive; the shim writes six octets.
    let result = unsafe { ntcp_dpdk_port_mac(port, mac.as_mut_ptr()) };
    if result < 0 {
        return Err(dpdk_error("rte_eth_macaddr_get", result));
    }
    Ok(mac)
}

/// An rte_flow rule; keeps its port alive and is destroyed on drop.
pub struct Flow {
    port: Arc<PortInner>,
    flow: NonNull<c_void>,
}

// SAFETY: rte_flow_destroy may run on any thread: ethdev serializes flow
// operations for PMDs that are not flow-thread-safe.
unsafe impl Send for Flow {}

impl Drop for Flow {
    fn drop(&mut self) {
        // SAFETY: flow created on this still-started port, destroyed once.
        unsafe { ntcp_dpdk_flow_destroy(self.port.port, self.flow.as_ptr()) };
    }
}

/// Exclusive right to one queue pair; move it to the worker thread and attach.
pub struct QueueHandle {
    port: Arc<PortInner>,
    queue: u16,
    attached: bool,
}

// Until an adapter exists nothing has polled or transmitted on the queue, so
// the index can go back to the port. A worker that fails to start or attach
// (thread spawn, no free lcore for rte_thread_register) can then be replaced;
// otherwise the queue, and the traffic flows steer to it, would be lost until
// the whole port is dropped. An attached queue is not returned: its rings may
// still hold the previous adapter's mbufs, and no hand-over is defined.
impl Drop for QueueHandle {
    fn drop(&mut self) {
        if !self.attached {
            self.port.taken[usize::from(self.queue)].store(false, Ordering::Release);
        }
    }
}

impl QueueHandle {
    pub fn queue(&self) -> u16 {
        self.queue
    }

    /// Run on the worker thread that will poll the queue. Registers the thread
    /// with EAL (rte_thread_register; this disables DPDK multi-process) unless
    /// it already is an EAL lcore, and builds the adapter. With
    /// `rx_timestamps`, RX timestamps carry `Port::clock()`.
    pub fn attach(mut self) -> io::Result<HostedQueue> {
        let registration = Registration::acquire()?;
        let pool = self.port.pools[usize::from(self.queue)];
        // SAFETY (from_borrowed contract): EAL is initialized and never torn
        // down; the port is started with this queue pair configured and stays
        // so, with its pool, until `port` (held below) is the last reference.
        // `taken` gives the queue to one handle at a time and keeps it once
        // attached, so access is exclusive. The pool is a pktmbuf pool. The
        // thread is an EAL lcore (registration), and HostedQueue is !Send, so
        // every call stays on it. The port has no byte-transforming RX
        // offloads, and multi-segment TX whenever an MTU-sized frame exceeds
        // one mbuf (Port::start).
        let mut io =
            unsafe { Dpdk::from_borrowed(self.port.port, self.queue, self.queue, pool.as_ptr()) }?;
        if let Some(clock) = self.port.clock {
            io.enable_rx_timestamps(clock)?;
        }
        self.attached = true;
        Ok(HostedQueue {
            io,
            port: self.port.clone(),
            _registration: registration,
            queue: self.queue,
        })
    }
}

thread_local! {
    // Live HostedQueues on this thread that rely on our rte_thread_register.
    static REGISTERED: Cell<usize> = const { Cell::new(0) };
}

struct Registration {
    ours: bool,
    _local: PhantomData<Rc<()>>,
}

impl Registration {
    fn acquire() -> io::Result<Self> {
        let count = REGISTERED.get();
        let ours = if count > 0 {
            true
        // SAFETY: EAL is initialized (a Port exists).
        } else if unsafe { ntcp_dpdk_lcore_id() } == LCORE_ID_ANY {
            // SAFETY: EAL initialized; this thread is not an EAL thread.
            let result = unsafe { ntcp_dpdk_thread_register() };
            if result < 0 {
                return Err(dpdk_error("rte_thread_register", result));
            }
            true
        } else {
            false
        };
        if ours {
            REGISTERED.set(count + 1);
        }
        Ok(Self {
            ours,
            _local: PhantomData,
        })
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        if self.ours {
            let count = REGISTERED.get() - 1;
            REGISTERED.set(count);
            if count == 0 {
                // SAFETY: registered by us on this thread; no adapter remains.
                unsafe { ntcp_dpdk_thread_unregister() };
            }
        }
    }
}

/// One queue pair served on its worker thread: PacketIo over the `Dpdk`
/// adapter, keeping the port, its pools and EAL alive. !Send, like `Dpdk`.
pub struct HostedQueue {
    // Drop order: adapter (frees prefetched mbufs), then the port (may stop
    // it), then the thread registration.
    io: Dpdk,
    port: Arc<PortInner>,
    _registration: Registration,
    queue: u16,
}

impl HostedQueue {
    pub fn queue(&self) -> u16 {
        self.queue
    }

    pub fn port_id(&self) -> u16 {
        self.port.port
    }

    /// See `Port::clock`.
    pub fn clock(&self) -> Option<ClockDescriptor> {
        self.port.clock
    }

    /// See `Port::read_clock`.
    pub fn read_clock(&self) -> io::Result<u64> {
        read_clock(self.port.port)
    }

    /// See `Port::mac_address`.
    pub fn mac_address(&self) -> io::Result<[u8; 6]> {
        mac_address(self.port.port)
    }

    pub fn dpdk(&self) -> &Dpdk {
        &self.io
    }

    /// See `Dpdk::enable_zero_copy`; multi-segment TX is enabled when supported.
    pub fn enable_zero_copy(&mut self) -> io::Result<()> {
        self.io.enable_zero_copy()
    }
}

impl PacketIo for HostedQueue {
    fn layer(&self) -> PacketLayer {
        self.io.layer()
    }
    fn zero_copy_capabilities(&self) -> Option<ZeroCopyCapabilities> {
        self.io.zero_copy_capabilities()
    }
    fn reclaim_transmit(&mut self, budget: usize) -> io::Result<usize> {
        self.io.reclaim_transmit(budget)
    }
    fn zero_copy_payload_supported(&self, payload: &Payload) -> bool {
        self.io.zero_copy_payload_supported(payload)
    }
    fn transmit_zero_copy(&mut self, packet: &OwnedPacket) -> io::Result<TxOutcome> {
        self.io.transmit_zero_copy(packet)
    }
    fn local_ip_mtu(&self) -> io::Result<Option<u32>> {
        self.io.local_ip_mtu()
    }
    fn max_packet_len(&self) -> Option<usize> {
        self.io.max_packet_len()
    }
    fn packet_mark_supported(&self) -> bool {
        self.io.packet_mark_supported()
    }
    fn set_packet_mark(&mut self, mark: u32) -> io::Result<()> {
        self.io.set_packet_mark(mark)
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        self.io.receive(out)
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        self.io.transmit(packet)
    }
    fn tcp_segmentation_capabilities(&self) -> Option<TcpSegmentationCapabilities> {
        self.io.tcp_segmentation_capabilities()
    }
    fn transmit_segmented(
        &mut self,
        packet: &[u8],
        request: TcpSegmentationRequest,
    ) -> Result<TxOutcome, TcpSegmentationError> {
        self.io.transmit_segmented(packet, request)
    }
    fn tx_scheduling_capabilities(&self) -> Option<TxSchedulingCapabilities> {
        self.io.tx_scheduling_capabilities()
    }
    fn transmit_at(
        &mut self,
        packet: &[u8],
        when: TransmitTime,
        timestamp: Option<TxTimestampRequest>,
    ) -> io::Result<TxOutcome> {
        self.io.transmit_at(packet, when, timestamp)
    }
    fn poll_tx_scheduling_error(&mut self) -> io::Result<Option<TxSchedulingError>> {
        self.io.poll_tx_scheduling_error()
    }
    fn timestamp_capabilities(&self) -> TimestampCapabilities {
        self.io.timestamp_capabilities()
    }
    fn receive_with_metadata(&mut self, out: &mut [u8]) -> io::Result<Option<ReceivedPacket>> {
        self.io.receive_with_metadata(out)
    }
    fn transmit_with_timestamp(
        &mut self,
        packet: &[u8],
        request: TxTimestampRequest,
    ) -> io::Result<TxOutcome> {
        self.io.transmit_with_timestamp(packet, request)
    }
    fn cancel_tx_timestamp(&mut self, cookie: u64) -> io::Result<bool> {
        self.io.cancel_tx_timestamp(cookie)
    }
    fn poll_tx_timestamp(&mut self) -> io::Result<Option<TxTimestampCompletion>> {
        self.io.poll_tx_timestamp()
    }
}
