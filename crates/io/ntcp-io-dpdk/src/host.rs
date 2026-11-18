//! Opt-in safe DPDK host: owns EAL, one port per `Port`, one mempool per
//! queue, and rte_flow rules, and hands each queue pair to one worker thread as
//! a `HostedQueue` (a `Dpdk` adapter whose borrowed objects it keeps alive).
//! Teardown order is structural: flows and queues hold the port, so the port
//! is stopped and closed, and its pools freed, only after all of them drop.
//! `Eal::init` refuses EAL arguments that would probe PCI devices implicitly
//! (see `eal_args`).

use crate::native::{
    Dpdk, driver_name, pool_geometry, rx_checksum_check, tso_check, tx_checksum_check,
};
use ntcp_io::{
    ClockDescriptor, ClockDomain, DeviceCounters, OwnedPacket, PacketIo, PacketLayer, Payload,
    ReceivedFrame, ReceivedPacket, TcpSegmentationCapabilities, TcpSegmentationError,
    TcpSegmentationRequest, TimestampCapabilities, TimestampUnit, TransmitTime, TxOutcome,
    TxSchedulingCapabilities, TxSchedulingError, TxTimestampCompletion, TxTimestampRequest,
    ZeroCopyCapabilities,
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
        Arc, Mutex, OnceLock,
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
    rss: u8,
    rss_key_len: u8,
    tcp_segmentation: u8,
    checksum_offload: u8,
    rss_key: *const u8,
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
        key_size: *mut u8,
        tcp_segmentation: *mut u8,
        checksums: *mut u8,
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
    fn ntcp_dpdk_port_stats(port: u16, rx_nombuf: *mut u64, imissed: *mut u64) -> i32;
    fn ntcp_dpdk_port_release(port: u16, owner: u64, started: i32);
    fn ntcp_dpdk_read_clock(port: u16, clock: *mut u64) -> i32;
    fn ntcp_dpdk_port_mac(port: u16, mac: *mut u8) -> i32;
    fn ntcp_dpdk_flow_ipv4(
        port: u16,
        dst: u32,
        l4: u8,
        priority: u32,
        queue: u16,
        flow: *mut *mut c_void,
        priority_refused: *mut i32,
        message: *mut c_char,
        capacity: usize,
    ) -> i32;
    fn ntcp_dpdk_flow_tcp_port(
        port: u16,
        dst: u32,
        dst_port: u16,
        mask: u16,
        queue: u16,
        error: *mut i32,
        stage: *mut i32,
        message: *mut c_char,
        capacity: usize,
    ) -> *mut c_void;
    fn ntcp_dpdk_flow_destroy(port: u16, flow: *mut c_void) -> i32;
    fn ntcp_dpdk_rss_sizes(port: u16, key_size: *mut u16, reta_size: *mut u16) -> i32;
    fn ntcp_dpdk_rss_query(
        port: u16,
        key: *mut u8,
        key_capacity: u16,
        reta: *mut u16,
        reta_capacity: u16,
        key_len: *mut u16,
        reta_len: *mut u16,
        hash: *mut u8,
        algorithm: *mut u32,
    ) -> i32;
    fn ntcp_dpdk_rss_reta_update(port: u16, reta: *const u16, length: u16) -> i32;
}

// Hash type bits of ntcp_dpdk_rss_query.
const RSS_IPV4_TCP: u8 = 1;
const RSS_IPV4: u8 = 2;
const RSS_FRAG_IPV4: u8 = 4;

// Rounds of `Port::rss` that may find the device's key or table grown.
const RSS_QUERY_ATTEMPTS: usize = 3;

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

// The rules of one `Port::steer_ipv4`, by IP protocol of the L4 item (0:
// none). A PMD may tie an L3-only pattern to the packets with no L4 header
// it parses: i40e's flow director maps ETH / IPV4 to pctype NONF_IPV4_OTHER
// (i40e_flow.c i40e_flow_parse_fdir_pattern), and a TCP or UDP packet,
// classified NONF_IPV4_TCP or NONF_IPV4_UDP, never matches it. mlx5 matches
// every IPv4 packet with it (flow_dv_translate_item_ipv4 leaves ip_protocol
// unmasked). rte_flow cannot tell which, so every device gets the three.
const IPV4_RULES: [u8; 3] = [6, 17, 0];

// rte_flow priority of the `steer_ipv4` rules, behind `steer_tcp_port`'s 0;
// 0 on a PMD that refuses it. The refusal cannot be recognised by its error:
// i40e's fdir parser refuses the priority (i40e_flow_parse_attr), then its
// parse loop tries the cloud-filter parser, whose "Invalid IPv4 item" is the
// error returned. So any refusal of the first rule is retried once at 0.
const ADDRESS_PRIORITY: u32 = 1;

fn ipv4_pattern(l4: u8) -> &'static str {
    match l4 {
        6 => "eth / ipv4 / tcp",
        17 => "eth / ipv4 / udp",
        _ => "eth / ipv4",
    }
}

// A rule the flow API refused.
struct Refusal {
    error: io::Error,
}

// The flow API calls of `install_ipv4`, apart so that its all-or-nothing
// installation runs without a device.
trait Ipv4Rules {
    fn validate(&mut self, l4: u8, priority: u32) -> Result<(), Refusal>;
    fn create(&mut self, l4: u8, priority: u32) -> Result<NonNull<c_void>, Refusal>;
    fn destroy(&mut self, flow: NonNull<c_void>) -> i32;
}

struct DeviceIpv4Rules {
    port: u16,
    dst: Ipv4Addr,
    queue: u16,
}

impl DeviceIpv4Rules {
    fn call(&self, l4: u8, priority: u32, flow: *mut *mut c_void) -> Result<(), Refusal> {
        // The shim's priority-refused flag is not trusted (`ADDRESS_PRIORITY`).
        let (mut _refused, mut message) = (0, [0; 128]);
        // SAFETY: started port; buffer capacity is passed; flow is null or
        // points to a slot of the caller's.
        let result = unsafe {
            ntcp_dpdk_flow_ipv4(
                self.port,
                u32::from(self.dst).to_be(),
                l4,
                priority,
                self.queue,
                flow,
                &mut _refused,
                message.as_mut_ptr(),
                message.len(),
            )
        };
        if result == 0 {
            return Ok(());
        }
        let step = if flow.is_null() {
            "rte_flow_validate"
        } else {
            "rte_flow_create"
        };
        let context = format!("{step} ({} priority {priority})", ipv4_pattern(l4));
        Err(Refusal {
            error: flow_error(&context, result, &message),
        })
    }
}

impl Ipv4Rules for DeviceIpv4Rules {
    fn validate(&mut self, l4: u8, priority: u32) -> Result<(), Refusal> {
        self.call(l4, priority, std::ptr::null_mut())
    }

    fn create(&mut self, l4: u8, priority: u32) -> Result<NonNull<c_void>, Refusal> {
        let mut flow = std::ptr::null_mut();
        self.call(l4, priority, &mut flow)?;
        NonNull::new(flow).ok_or_else(|| Refusal {
            error: io::Error::other("rte_flow_create returned no flow"),
        })
    }

    fn destroy(&mut self, flow: NonNull<c_void>) -> i32 {
        // SAFETY: flow created on this still-started port, destroyed once.
        unsafe { ntcp_dpdk_flow_destroy(self.port, flow.as_ptr()) }
    }
}

// Validate every rule of `IPV4_RULES`, then create them, all or none: a
// creation refused destroys the rules created before it. A refused
// specification (EINVAL) is Unsupported, as in `steer_tcp_port`.
fn install_ipv4(rules: &mut impl Ipv4Rules) -> io::Result<Vec<NonNull<c_void>>> {
    let unsupported = |refusal: Refusal| match refusal.error.kind() {
        io::ErrorKind::InvalidInput => {
            io::Error::new(io::ErrorKind::Unsupported, refusal.error.to_string())
        }
        _ => refusal.error,
    };
    let (first, rest) = (IPV4_RULES[0], &IPV4_RULES[1..]);
    let priority = match rules.validate(first, ADDRESS_PRIORITY) {
        Ok(()) => ADDRESS_PRIORITY,
        Err(at_address) => match rules.validate(first, 0) {
            Ok(()) => 0,
            Err(at_0) => {
                let error = unsupported(at_0);
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "{error}; at priority {ADDRESS_PRIORITY}: {}",
                        at_address.error
                    ),
                ));
            }
        },
    };
    for &l4 in rest {
        rules.validate(l4, priority).map_err(unsupported)?;
    }
    let mut flows = Vec::with_capacity(IPV4_RULES.len());
    for &l4 in &IPV4_RULES {
        match rules.create(l4, priority) {
            Ok(flow) => flows.push(flow),
            Err(refusal) => {
                let kept: Vec<i32> = flows
                    .drain(..)
                    .rev()
                    .map(|flow| rules.destroy(flow))
                    .filter(|&result| result < 0)
                    .collect();
                let Some(&result) = kept.first() else {
                    return Err(refusal.error);
                };
                let error = refusal.error;
                let left = dpdk_error("rte_flow_destroy", result);
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "{error}; {} rule(s) of the set left installed: {left}",
                        kept.len()
                    ),
                ));
            }
        }
    }
    Ok(flows)
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
    ///
    /// The args must name every PCI device EAL may probe with an allow-list
    /// entry (`-a <pci>[,key=value]...`, also spelled `-a<pci>`, `-a=<pci>`,
    /// `--allow <pci>`, `--allow=<pci>`; one or more), or contain `--no-pci`
    /// for virtual devices only. Without either, DPDK probes every supported
    /// PCI device, and on bifurcated mlx5 that takes all traffic of every
    /// ConnectX port from the kernel, the management (SSH) port included.
    /// `InvalidInput`, naming the flag, for: neither; `--vdev` without
    /// `--no-pci` (it does not stop the PCI probe); a block-list (`-b`,
    /// `--block`) without an allow-list, or with one; an allow entry without
    /// a device (`-a ""`, `-a ,dv_flow_en=1`); `--no-pci` with an allow
    /// entry; the removed `-w`/`--pci-whitelist`; a NUL. These checks run
    /// before EAL, and a refused call leaves EAL uninitialized, so a later
    /// call with valid args can still initialize it.
    pub fn init<I, S>(args: I) -> io::Result<&'static Eal>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let args: Vec<String> = args.into_iter().map(Into::into).collect();
        crate::eal_args::check(&args)?;
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
        owned.push(CString::new(arg).expect("Eal::init refuses NUL"));
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
    /// Mbufs in each queue's pool (default 16383). Must exceed `rx_desc +
    /// tx_desc` (after the PMD rounds them) or the pool can be exhausted by
    /// the rings alone. The RX ring keeps `rx_desc` mbufs posted, sent
    /// frames hold theirs until the device completes them (up to `tx_desc`
    /// descriptors, an aggregate one mbuf of `mbuf_data_size` per
    /// descriptor), and each worker lcore's cache holds up to 384 more; the
    /// rest is what frames held beyond the rings can take.
    ///
    /// A hosted queue hands received mbufs over by reference
    /// (`PacketIo::receive_frame`): a Network holds each until its
    /// application reads the data, charging the mbuf's 2368 octets to the
    /// connection. Its frame budget (`PacketIo::rx_frame_budget`) is F =
    /// `mbufs_per_queue` - `rx_desc` - 2 x `tx_desc` - 1.5 x cache x
    /// `queues` (the pool's cache is min(256, mbufs / 2); each queue's
    /// worker may free this queue's mbufs, through a shared-flow handoff,
    /// into its own cache): 12,927 with the defaults and one queue, 30.6 MB
    /// of mbufs. Past 3/4 F out, a Network copies arrivals instead of
    /// holding them, so readers that stop cannot drain the pool; frames
    /// held long show as `DeviceCounters::rx_nombuf` and `rx_missed` only
    /// when the pool is sized below that. A scatter chain (`mtu` beyond
    /// one mbuf) or an externally attached mbuf (mlx5's `mprq_en`, whose
    /// packets share a stride buffer) is copied, never held.
    ///
    /// Each queue's pool is hugepage memory on the device's NUMA socket,
    /// allocated whole at `Port::start`. With the default `mbuf_data_size`
    /// an mbuf takes 2368 octets (DPDK 26.03: 64 mempool object header, 128
    /// rte_mbuf, 128 headroom, 2048 data, no private area or trailer), and
    /// the pool adds 1.06 MB of per-lcore caches (RTE_MAX_LCORE 128) and its
    /// ring (8 octets per slot, n + 1 rounded up to a power of two, hence
    /// 2^n - 1). On 2 MiB pages a queue's pool takes 10.80 MB at 4095 mbufs
    /// and 40.01 MB at 16383: 43.2 MB and 160.0 MB for a port of 4 queues.
    /// Without hugepages (`--no-huge`, 4 KiB pages) no object may cross a
    /// page, so each mbuf takes 4096 octets: 68.3 MB a queue at 16383.
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
    /// Receive side scaling across all queues (mq_mode RSS) for traffic no
    /// flow rule steers, over the IPv4 hash types the device grants among
    /// unfragmented TCP (addresses and ports), other IPv4 and IPv4 fragments
    /// (addresses). The device must grant at least one. Ignored with a single
    /// queue. Not allowed with `isolate`: an isolated port receives only
    /// what flow rules match, so the table would spread nothing. `Port::rss`
    /// reads the key and redirection table back.
    pub rss: bool,
    /// TCP segmentation offload, when the device offers it: TX offloads
    /// RTE_ETH_TX_OFFLOAD_TCP_TSO, TCP_CKSUM and IPV4_CKSUM, the checksum
    /// offloads filling each segment's checksums, enabled on the port, and
    /// every hosted queue opted in at attach (`Dpdk::enable_tcp_segmentation`),
    /// before any Network reads its `tcp_segmentation_capabilities`. A device
    /// without all three starts without them, and one whose queues that
    /// opt-in refuses (it cannot read a queue's actual configuration, as on
    /// net_tap) keeps them unused; `Port::tcp_segmentation` tells which.
    /// Only frames handed to `transmit_segmented` use them. An aggregate is
    /// a chain of mbufs of `mbuf_data_size` octets, up to 64 KiB, held from
    /// the queue's pool until the device has sent it; a pool short of them
    /// blocks the aggregate (WouldBlock) until the ring drains.
    pub tcp_segmentation: bool,
    /// TCP checksum offload in each direction the device offers it
    /// (default on, as Linux enables rx and tx checksumming): on RX,
    /// RTE_ETH_RX_OFFLOAD_TCP_CKSUM, whose verdict every hosted queue
    /// reports (`Dpdk::enable_rx_checksum`), so that a checksum the device
    /// found good is not verified again; on TX, RTE_ETH_TX_OFFLOAD_TCP_CKSUM,
    /// which every hosted queue offers (`Dpdk::enable_tx_checksum`), so
    /// that a Network leaves each segment's checksum to the device.
    /// `Port::rx_checksum` and `Port::tx_checksum` tell which is in use.
    pub checksum_offload: bool,
    /// Hash key for `rss`, exactly the device's hash key size (40 octets on
    /// mlx5). None keeps the PMD's key. Its length is checked whenever it is
    /// given, also with a single queue, where it goes unused.
    pub rss_key: Option<Vec<u8>>,
}

impl PortConfig {
    pub fn new(device: impl Into<String>) -> Self {
        Self {
            device: device.into(),
            queues: 1,
            rx_desc: 1024,
            tx_desc: 1024,
            mtu: 1500,
            // 2^n - 1: the ring mempool driver's ring has n + 1 slots,
            // rounded up to a power of two. About 14,000 mbufs beyond the
            // default rings for frames held by reference.
            mbufs_per_queue: 16383,
            // RTE_MBUF_DEFAULT_DATAROOM.
            mbuf_data_size: 2048,
            isolate: false,
            rx_timestamps: false,
            rss: false,
            rss_key: None,
            tcp_segmentation: false,
            checksum_offload: true,
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
    // Each queue's ring sizes, as the PMD adjusted them.
    rx_desc: u16,
    tx_desc: u16,
    taken: Box<[AtomicBool]>,
    clock: Option<ClockDescriptor>,
    rss: bool,
    tcp_segmentation: bool,
    rx_checksum: bool,
    tx_checksum: bool,
    // ethdev keeps a pointer to the configured key; it lives with the port.
    _rss_key: Option<Box<[u8]>>,
    // Serializes rte_eth_stats_get among the port's queues, each read on
    // its own worker thread: ethdev control calls are not thread-safe, and
    // mlx5 updates its imissed state in them.
    stats: Mutex<()>,
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
/// offloads; RX scatter, TX multi-segment and TCP segmentation are enabled
/// only as described on `PortConfig`. Queues receive what flows steer to
/// them; without `rss`, unmatched traffic goes to queue 0 (or, isolated, to
/// the kernel).
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
        if config.rss && config.isolate {
            return Err(invalid("rss spreads no traffic on an isolated port"));
        }
        if config.rss_key.is_some() && !config.rss {
            return Err(invalid("rss_key requires rss"));
        }
        let rss = config.rss && config.queues > 1;
        let rss_key = config.rss_key.map(Vec::into_boxed_slice);
        let rss_key_len = match &rss_key {
            Some(key) => u8::try_from(key.len()).map_err(|_| invalid("rss key too long"))?,
            None => 0,
        };
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
            rx_desc: 0,
            tx_desc: 0,
            taken: (0..config.queues).map(|_| AtomicBool::new(false)).collect(),
            clock: config.rx_timestamps.then_some(ClockDescriptor {
                domain: ClockDomain::Device(u64::from(port)),
                unit: TimestampUnit::RawTicks {
                    identity: generation,
                },
            }),
            rss,
            tcp_segmentation: false,
            rx_checksum: false,
            tx_checksum: false,
            _rss_key: rss_key,
            stats: Mutex::new(()),
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
            rss: u8::from(rss),
            rss_key_len,
            tcp_segmentation: u8::from(config.tcp_segmentation),
            checksum_offload: u8::from(config.checksum_offload),
            rss_key: inner
                ._rss_key
                .as_ref()
                .map_or(std::ptr::null(), |key| key.as_ptr()),
        };
        let (mut rx_desc, mut tx_desc, mut stage, mut key_size) = (0, 0, 0, 0);
        let (mut tcp_segmentation, mut checksums) = (0, 0);
        // SAFETY: claimed port; all pointers are valid for the call, and the
        // key for as long as the port (it is owned by `inner`).
        let result = unsafe {
            ntcp_dpdk_port_configure(
                port,
                &setup,
                &mut rx_desc,
                &mut tx_desc,
                &mut stage,
                &mut key_size,
                &mut tcp_segmentation,
                &mut checksums,
            )
        };
        if result < 0 {
            if stage == 9 {
                return Err(invalid(&format!(
                    "rss key has {rss_key_len} octets but the device's hash key has {key_size}"
                )));
            }
            let context = match stage {
                2 => "queue count exceeds device limits",
                3 => "device lacks RTE_ETH_RX_OFFLOAD_TIMESTAMP",
                4 => "frames exceed one mbuf but device lacks RX scatter",
                5 => "frames exceed one mbuf but device lacks TX multi-segment",
                6 => "rte_eth_dev_configure",
                7 => "rte_eth_dev_adjust_nb_rx_tx_desc",
                8 => "device grants none of the ipv4 rss hash types",
                _ => "rte_eth_dev_info_get",
            };
            return Err(dpdk_error(context, result));
        }
        inner.tcp_segmentation = tcp_segmentation != 0;
        (inner.rx_desc, inner.tx_desc) = (rx_desc, tx_desc);
        inner.rx_checksum = checksums & 1 != 0;
        inner.tx_checksum = checksums & 2 != 0;
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
        // The adapter's own check (Dpdk::enable_tcp_segmentation) of every
        // queue: a device can take the offloads yet keep a queue's actual
        // configuration unreadable (net_tap has no txq_info_get), which the
        // check refuses, and then no queue segments.
        inner.tcp_segmentation &= inner.pools.iter().zip(0..).all(|(pool, queue)| {
            // SAFETY: started port with this queue and its pool configured.
            unsafe { tso_check(port, queue, pool.as_ptr()) }.is_ok()
        });
        // Likewise the adapter's checks (Dpdk::enable_rx_checksum,
        // Dpdk::enable_tx_checksum).
        inner.rx_checksum &= (0..config.queues).all(|queue| {
            // SAFETY: started port with this queue configured.
            unsafe { rx_checksum_check(port, queue) }.is_ok()
        });
        inner.tx_checksum &= (0..config.queues).all(|queue| {
            // SAFETY: started port with this queue configured.
            unsafe { tx_checksum_check(port, queue) }.is_ok()
        });
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

    /// Whether `tcp_segmentation` was requested, the device offered it and
    /// every queue passed the adapter's check: every attached queue then
    /// takes TCP aggregates.
    pub fn tcp_segmentation(&self) -> bool {
        self.inner.tcp_segmentation
    }

    /// Whether `checksum_offload` was requested, the device offered RX TCP
    /// checksum verification and every queue passed the adapter's check:
    /// every attached queue then reports the device's verdict.
    pub fn rx_checksum(&self) -> bool {
        self.inner.rx_checksum
    }

    /// Whether `checksum_offload` was requested, the device offered TX TCP
    /// checksum offload and every queue passed the adapter's check: every
    /// attached queue then completes the TCP checksum of its segments.
    pub fn tx_checksum(&self) -> bool {
        self.inner.tx_checksum
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

    /// The ethdev driver serving the port (rte_eth_dev_info driver_name),
    /// such as `mlx5_pci` for a ConnectX PCI function, `net_null` or
    /// `net_ring`. Behaviour rte_flow leaves to the PMD, such as the order
    /// of overlapping rules (`steer_tcp_port`), is known only per driver.
    pub fn driver_name(&self) -> io::Result<String> {
        // SAFETY: EAL is live and the port valid while the Port exists.
        unsafe { driver_name(self.inner.port) }
            .map_err(|result| dpdk_error("rte_eth_dev_info_get", result))
    }

    /// Steer IPv4 packets with destination `dst` to `queue`, with three rules:
    /// ETH / IPV4 dst / TCP, ETH / IPV4 dst / UDP and ETH / IPV4 dst, each →
    /// QUEUE. A PMD may match the L3-only rule only for packets without an
    /// L4 header it parses (i40e: ICMP and other protocols, not TCP or
    /// UDP), so it alone could steer nothing of a TCP connection. All three
    /// are validated first, then created; any refusal returns the error with
    /// none of them installed (Unsupported for a refused specification).
    /// They use rte_flow priority 1, behind `steer_tcp_port`, or 0 on a PMD
    /// that refuses the first rule at 1 (i40e). The rules are destroyed when the
    /// `Flow` drops, always before the port stops.
    ///
    /// On i40e, IPv4 fragments and SCTP (flow director pctypes FRAG_IPV4 and
    /// NONF_IPV4_SCTP) match none of the three and follow RSS, or go to
    /// queue 0.
    pub fn steer_ipv4(&self, dst: Ipv4Addr, queue: u16) -> io::Result<Flow> {
        if queue >= self.queues() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "flow target queue out of range",
            ));
        }
        let flows = install_ipv4(&mut DeviceIpv4Rules {
            port: self.inner.port,
            dst,
            queue,
        })?;
        Ok(Flow {
            port: self.inner.clone(),
            flows,
        })
    }

    /// Steer TCP to IPv4 destination `dst` whose destination port, masked
    /// with `mask`, equals `port` to `queue` (ETH / IPV4 dst / TCP dst_port
    /// spec and mask → QUEUE). The rule is validated first: a device that
    /// cannot match it reports Unsupported and nothing is installed. Like
    /// `steer_ipv4`, the rule is destroyed when the `Flow` drops, always
    /// before the port stops. Without `isolate`, packets to `dst` that match no
    /// rule follow RSS (or go to queue 0); isolated, they go to the kernel
    /// unless a `steer_ipv4` rule takes them.
    ///
    /// The rule uses rte_flow priority 0, ahead of `steer_ipv4`'s rules for
    /// the same address where the PMD takes priorities (mlx5). Where it
    /// refuses them (i40e) both are at 0, and rte_flow leaves overlapping
    /// rules of one priority undefined, so do not combine the two for one
    /// address there (`driver_name`); i40e refuses a full-mask port rule
    /// beside them (one flow director input set per pctype).
    ///
    /// A device may honour only some masks, and validation does not say
    /// which: i40e matches the port only under mask 0xffff and, under any
    /// other mask, accepts the rule as ETH / IPV4 dst / TCP, which steers
    /// all TCP to `dst` to `queue` (i40e_flow.c
    /// i40e_flow_parse_fdir_pattern: the port joins the input set only
    /// for a full mask). Partial masks are reliable only where the PMD
    /// is known to match them (mlx5).
    pub fn steer_tcp_port(
        &self,
        dst: Ipv4Addr,
        port: u16,
        mask: u16,
        queue: u16,
    ) -> io::Result<Flow> {
        if queue >= self.queues() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "flow target queue out of range",
            ));
        }
        if port & !mask != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tcp port has bits outside its mask",
            ));
        }
        let (mut error, mut stage, mut message) = (0, 0, [0; 128]);
        // SAFETY: started port; buffer capacity is passed.
        let flow = unsafe {
            ntcp_dpdk_flow_tcp_port(
                self.inner.port,
                u32::from(dst).to_be(),
                port.to_be(),
                mask,
                queue,
                &mut error,
                &mut stage,
                message.as_mut_ptr(),
                message.len(),
            )
        };
        let flow = NonNull::new(flow).ok_or_else(|| {
            if stage == 1 {
                let error = flow_error("rte_flow_validate", error, &message);
                // A refused specification (EINVAL) is as unsupported as a
                // missing flow API: this rule is well formed by construction.
                match error.kind() {
                    io::ErrorKind::InvalidInput => {
                        io::Error::new(io::ErrorKind::Unsupported, error.to_string())
                    }
                    _ => error,
                }
            } else {
                flow_error("rte_flow_create", error, &message)
            }
        })?;
        Ok(Flow {
            port: self.inner.clone(),
            flows: vec![flow],
        })
    }

    /// RSS in effect: the hash key, the granted hash types, the hash
    /// function and the whole redirection table
    /// (rte_eth_dev_rss_hash_conf_get and rte_eth_dev_rss_reta_query), as
    /// the device reports them now. Ok(None) when the port spreads no traffic
    /// by RSS (`rss` off or a single queue). Unsupported when the device
    /// grants RSS but cannot report its key or table.
    pub fn rss(&self) -> io::Result<Option<Rss>> {
        if !self.inner.rss {
            return Ok(None);
        }
        let rss = query_resized(self.rss_sizes()?, |key_size, reta_size| {
            let mut key = vec![0; usize::from(key_size)];
            let mut reta = vec![0; usize::from(reta_size)];
            let (mut key_len, mut reta_len, mut hash, mut algorithm) = (0, 0, 0, 0);
            // SAFETY: started port; both buffers hold the capacity passed.
            let result = unsafe {
                ntcp_dpdk_rss_query(
                    self.inner.port,
                    key.as_mut_ptr(),
                    key_size,
                    reta.as_mut_ptr(),
                    reta_size,
                    &mut key_len,
                    &mut reta_len,
                    &mut hash,
                    &mut algorithm,
                )
            };
            if result < 0 {
                return Err((result, (key_len, reta_len)));
            }
            key.truncate(usize::from(key_len));
            reta.truncate(usize::from(reta_len));
            Ok(Rss {
                key,
                algorithm: RssAlgorithm::from_dpdk(algorithm),
                ipv4_tcp: hash & RSS_IPV4_TCP != 0,
                ipv4: hash & RSS_IPV4 != 0,
                ipv4_fragments: hash & RSS_FRAG_IPV4 != 0,
                reta,
            })
        })?;
        Ok(Some(rss))
    }

    /// Replace the whole redirection table (rte_eth_dev_rss_reta_update).
    /// `reta` must have exactly the device's current table length, as
    /// `Port::rss` reports it, and name queues of this port. Requires a port
    /// spreading by RSS (`Port::rss` is Some). mlx5 restarts its flows to
    /// apply the table, which may drop packets received meanwhile.
    pub fn set_reta(&self, reta: &[u16]) -> io::Result<()> {
        let invalid =
            |message: &str| io::Error::new(io::ErrorKind::InvalidInput, message.to_owned());
        if !self.inner.rss {
            return Err(invalid("rss is not enabled on this port"));
        }
        let (_, size) = self.rss_sizes()?;
        if reta.len() != usize::from(size) {
            return Err(invalid(&format!(
                "reta has {} entries but the device's table has {size}",
                reta.len()
            )));
        }
        if reta.iter().any(|&queue| queue >= self.queues()) {
            return Err(invalid("reta entry names a queue out of range"));
        }
        // SAFETY: started port; `reta` holds `size` entries.
        let result = unsafe { ntcp_dpdk_rss_reta_update(self.inner.port, reta.as_ptr(), size) };
        if result < 0 {
            return Err(dpdk_error("rte_eth_dev_rss_reta_update", result));
        }
        Ok(())
    }

    // (hash key size, redirection table size) from dev_info, now.
    fn rss_sizes(&self) -> io::Result<(u16, u16)> {
        let (mut key, mut reta) = (0, 0);
        // SAFETY: started port; outputs are writable.
        let result = unsafe { ntcp_dpdk_rss_sizes(self.inner.port, &mut key, &mut reta) };
        if result < 0 {
            return Err(dpdk_error("rte_eth_dev_info_get", result));
        }
        Ok((key, reta))
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

// Runs `query` with buffers of `sizes` (hash key, redirection table), and
// again with the sizes it reports when it fails with ENOSPC because the
// device's grew since they were read, at most RSS_QUERY_ATTEMPTS times in
// all. An ENOSPC without larger sizes came from the PMD itself and is
// returned like any other error, as is one that persists.
fn query_resized<T>(
    mut sizes: (u16, u16),
    mut query: impl FnMut(u16, u16) -> Result<T, (i32, (u16, u16))>,
) -> io::Result<T> {
    let mut attempts = 1;
    loop {
        match query(sizes.0, sizes.1) {
            Err((-28, now)) if now.0 > sizes.0 || now.1 > sizes.1 => {
                if attempts == RSS_QUERY_ATTEMPTS {
                    return Err(io::Error::other(
                        "rss query: the device's key or table keeps growing",
                    ));
                }
                attempts += 1;
                sizes = now;
            }
            result => return result.map_err(|(result, _)| dpdk_error("rss query", result)),
        }
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

/// RSS state of a port, as `Port::rss` reads it from the device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rss {
    /// Hash key.
    pub key: Vec<u8>,
    /// Hash function, as the PMD reports it. A copy of the device's hash
    /// (key and table) predicts its queues only for Toeplitz: Default means
    /// the PMD did not say, and holds Toeplitz only by the PMD's
    /// documentation (mlx5's).
    pub algorithm: RssAlgorithm,
    /// RTE_ETH_RSS_NONFRAG_IPV4_TCP: unfragmented IPv4 TCP hashes over
    /// source and destination addresses and ports.
    pub ipv4_tcp: bool,
    /// RTE_ETH_RSS_IPV4: other IPv4 hashes over source and destination
    /// addresses.
    pub ipv4: bool,
    /// RTE_ETH_RSS_FRAG_IPV4: IPv4 fragments hash over source and destination
    /// addresses.
    pub ipv4_fragments: bool,
    /// Redirection table: the RX queue of each entry, indexed by the hash's
    /// low-order bits. Its length is the device's: on mlx5 the queue count
    /// when that is a power of two, else the device's largest table.
    pub reta: Vec<u16>,
}

/// RSS hash function (enum rte_eth_hash_function).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RssAlgorithm {
    /// RTE_ETH_HASH_FUNCTION_DEFAULT: the PMD's choice, unreported. ethdev
    /// presets this before asking the PMD, and a PMD that does not report
    /// its function leaves it: mlx5 does, and hashes with Toeplitz.
    Default,
    Toeplitz,
    SimpleXor,
    /// Toeplitz over the exclusive or of source and destination.
    SymmetricToeplitz,
    /// Toeplitz over source and destination sorted, addresses and ports
    /// each.
    SymmetricToeplitzSort,
    /// A function this crate does not name, by its DPDK value.
    Other(u32),
}

impl RssAlgorithm {
    fn from_dpdk(value: u32) -> Self {
        // The shim asserts these values.
        match value {
            0 => Self::Default,
            1 => Self::Toeplitz,
            2 => Self::SimpleXor,
            3 => Self::SymmetricToeplitz,
            4 => Self::SymmetricToeplitzSort,
            other => Self::Other(other),
        }
    }
}

/// The rte_flow rules of one steering request; keeps its port alive and
/// destroys them on drop.
pub struct Flow {
    port: Arc<PortInner>,
    flows: Vec<NonNull<c_void>>,
}

// SAFETY: rte_flow_destroy may run on any thread: ethdev serializes flow
// operations for PMDs that are not flow-thread-safe.
unsafe impl Send for Flow {}

impl Drop for Flow {
    fn drop(&mut self) {
        for flow in self.flows.drain(..).rev() {
            // SAFETY: flow created on this still-started port, destroyed once.
            unsafe { ntcp_dpdk_flow_destroy(self.port.port, flow.as_ptr()) };
        }
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
    /// `rx_timestamps`, RX timestamps carry `Port::clock()`; with
    /// `Port::tcp_segmentation`, the queue takes TCP aggregates.
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
        if self.port.tcp_segmentation {
            io.enable_tcp_segmentation()?;
        }
        if self.port.rx_checksum {
            io.enable_rx_checksum()?;
        }
        if self.port.tx_checksum {
            io.enable_tx_checksum()?;
        }
        // SAFETY: the queue's pool is live while the port is.
        let (_, cache, mbufs) = unsafe { pool_geometry(pool.as_ptr()) };
        io.set_rx_frame_budget(Some(rx_frame_budget(
            mbufs,
            self.port.rx_desc,
            self.port.tx_desc,
            cache,
            self.port.taken.len(),
        )));
        self.attached = true;
        Ok(HostedQueue {
            io,
            port: self.port.clone(),
            _registration: registration,
            queue: self.queue,
        })
    }
}

// The receive frames a consumer of a queue may hold by reference
// (`PacketIo::rx_frame_budget`), F: the queue's pool of `mbufs` less the
// mbufs posted to its RX ring, twice its TX ring (frames the device has
// yet to send, and the reference and header mbufs of a frame sent by
// reference), and what the mempool caches of the lcores that may free its
// mbufs keep from it: each holds up to 1.5 x `cache` before it flushes
// (CALC_CACHE_FLUSHTHRESH), and `lcores` of them may, the workers of every
// queue of the port, which free this queue's mbufs when a member of shared
// flows hands one of its frames to another. At the default geometry, one
// queue: 16383 - 1024 - 2 x 1024 - 384 = 12,927.
fn rx_frame_budget(mbufs: u32, rx_desc: u16, tx_desc: u16, cache: u32, lcores: usize) -> usize {
    let rings = u64::from(rx_desc) + 2 * u64::from(tx_desc);
    let caches = u64::from(cache) * 3 / 2 * lcores as u64;
    u64::from(mbufs).saturating_sub(rings + caches) as usize
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

    /// See `PacketIo::device_counters`: this queue's `tx_nombuf`, and the
    /// port's `rx_nombuf` and `rx_missed` (rte_eth_stats `rx_nombuf` and
    /// `imissed`), the same in every queue of the port, as DPDK reports them
    /// per port only. Zero where the PMD reports nothing (the ring PMD's
    /// stats count packets only). A control-plane call, serialized among the
    /// port's queues; mlx5 serves `imissed` with a system call.
    pub fn device_counters(&self) -> DeviceCounters {
        let mut counters = self.io.device_counters();
        let (mut rx_nombuf, mut imissed) = (0, 0);
        let _serial = self.port.stats.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: the port is started and kept so by `port`; calls on it
        // are serialized by the lock; outputs are writable.
        if unsafe { ntcp_dpdk_port_stats(self.port.port, &mut rx_nombuf, &mut imissed) } == 0 {
            counters.rx_nombuf = rx_nombuf;
            counters.rx_missed = imissed;
        }
        counters
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
    fn device_counters(&self) -> DeviceCounters {
        HostedQueue::device_counters(self)
    }
    fn tx_completion(&self) -> ntcp_io::TxCompletion {
        self.io.tx_completion()
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
    fn tcp_checksum_offload(&self) -> bool {
        self.io.tcp_checksum_offload()
    }
    fn transmit_tcp_checksum_offload(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        self.io.transmit_tcp_checksum_offload(packet)
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
    fn receive_frame(&mut self, scratch: &mut [u8]) -> io::Result<Option<ReceivedFrame>> {
        self.io.receive_frame(scratch)
    }
    fn rx_frame_budget(&self) -> Option<usize> {
        self.io.rx_frame_budget()
    }
    fn rx_frames_outstanding(&self) -> Option<usize> {
        self.io.rx_frames_outstanding()
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

#[cfg(test)]
mod tests {
    use super::*;

    const ENOSPC: i32 = -28;

    // A query's reply: a value, or an error with the sizes it reports.
    type Reply = Result<u8, (i32, (u16, u16))>;

    // (result, sizes each call was given)
    fn run(mut replies: Vec<Reply>) -> (io::Result<u8>, Vec<(u16, u16)>) {
        let mut calls = Vec::new();
        replies.reverse();
        let result = query_resized((40, 64), |key, reta| {
            calls.push((key, reta));
            replies.pop().unwrap()
        });
        (result, calls)
    }

    #[derive(Debug, PartialEq)]
    enum Call {
        Validate(u8, u32),
        Create(u8, u32),
        Destroy(usize),
    }

    // A flow API that refuses what `refuse` picks, with an errno, and fails
    // the destructions listed.
    struct Script<F> {
        refuse: F,
        destroy_fails: Vec<usize>,
        calls: Vec<Call>,
        created: usize,
    }

    fn script<F: FnMut(&Call) -> Option<i32>>(refuse: F) -> Script<F> {
        Script {
            refuse,
            destroy_fails: Vec::new(),
            calls: Vec::new(),
            created: 0,
        }
    }

    impl<F: FnMut(&Call) -> Option<i32>> Script<F> {
        fn answer(&mut self, call: Call) -> Result<(), Refusal> {
            let refused = (self.refuse)(&call);
            self.calls.push(call);
            match refused {
                None => Ok(()),
                Some(result) => Err(Refusal {
                    error: dpdk_error("scripted", result),
                }),
            }
        }
    }

    impl<F: FnMut(&Call) -> Option<i32>> Ipv4Rules for Script<F> {
        fn validate(&mut self, l4: u8, priority: u32) -> Result<(), Refusal> {
            self.answer(Call::Validate(l4, priority))
        }

        fn create(&mut self, l4: u8, priority: u32) -> Result<NonNull<c_void>, Refusal> {
            self.answer(Call::Create(l4, priority))?;
            self.created += 1;
            Ok(NonNull::new(self.created as *mut c_void).unwrap())
        }

        fn destroy(&mut self, flow: NonNull<c_void>) -> i32 {
            let flow = flow.as_ptr() as usize;
            self.calls.push(Call::Destroy(flow));
            if self.destroy_fails.contains(&flow) {
                -5
            } else {
                0
            }
        }
    }

    const EINVAL: i32 = -22;
    const ENOSYS: i32 = -38;

    #[test]
    fn ipv4_rules_cover_tcp_udp_and_the_rest_behind_port_rules() {
        let mut rules = script(|_| None);
        let flows = install_ipv4(&mut rules).unwrap();
        assert_eq!(flows.len(), 3);
        use Call::*;
        assert_eq!(
            rules.calls,
            [
                Validate(6, 1),
                Validate(17, 1),
                Validate(0, 1),
                Create(6, 1),
                Create(17, 1),
                Create(0, 1),
            ]
        );
    }

    #[test]
    fn ipv4_rules_drop_to_priority_0_where_priorities_are_refused() {
        // i40e refuses any priority but 0, and reports it as "Invalid IPv4
        // item" (EINVAL, not ATTR_PRIORITY): any refusal at 1 is retried.
        let mut rules = script(|call| match call {
            Call::Validate(_, 1) => Some(EINVAL),
            _ => None,
        });
        install_ipv4(&mut rules).unwrap();
        use Call::*;
        assert_eq!(
            rules.calls,
            [
                Validate(6, 1),
                Validate(6, 0),
                Validate(17, 0),
                Validate(0, 0),
                Create(6, 0),
                Create(17, 0),
                Create(0, 0),
            ]
        );
    }

    #[test]
    fn ipv4_rules_refused_in_validation_install_nothing() {
        // The first rule refused at both priorities: both errors reported.
        let mut rules = script(|call| match call {
            Call::Validate(6, _) => Some(EINVAL),
            _ => None,
        });
        let error = install_ipv4(&mut rules).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("at priority 1:"), "{error}");
        assert_eq!(rules.calls, [Call::Validate(6, 1), Call::Validate(6, 0)]);
        // One rule of the set refused: none is created.
        let mut rules = script(|call| match call {
            Call::Validate(17, _) => Some(EINVAL),
            _ => None,
        });
        let error = install_ipv4(&mut rules).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(rules.calls, [Call::Validate(6, 1), Call::Validate(17, 1)]);
        // No flow API (the ring PMD).
        let mut rules = script(|_| Some(ENOSYS));
        let error = install_ipv4(&mut rules).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(rules.calls, [Call::Validate(6, 1), Call::Validate(6, 0)]);
    }

    #[test]
    fn ipv4_rules_refused_at_creation_destroy_the_ones_created() {
        // i40e checks a pctype's input set against its rules only when
        // creating (i40e_flow_set_fdir_inset).
        let mut rules = script(|call| match call {
            Call::Create(0, _) => Some(EINVAL),
            _ => None,
        });
        let error = install_ipv4(&mut rules).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().starts_with("scripted"), "{error}");
        assert_eq!(
            rules.calls[3..],
            [
                Call::Create(6, 1),
                Call::Create(17, 1),
                Call::Create(0, 1),
                Call::Destroy(2),
                Call::Destroy(1),
            ]
        );
    }

    #[test]
    fn ipv4_rules_left_installed_are_reported() {
        let mut rules = script(|call| match call {
            Call::Create(0, _) => Some(EINVAL),
            _ => None,
        });
        rules.destroy_fails = vec![1];
        let error = install_ipv4(&mut rules).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("1 rule(s) of the set left installed"),
            "{error}"
        );
        assert_eq!(rules.calls[6..], [Call::Destroy(2), Call::Destroy(1)]);
    }

    #[test]
    fn frame_budget_leaves_the_rings_and_the_lcore_caches() {
        // PortConfig::new: one queue, its pool's cache 256.
        assert_eq!(rx_frame_budget(16383, 1024, 1024, 256, 1), 12_927);
        // Four queues: each worker's cache may hold this queue's mbufs.
        assert_eq!(rx_frame_budget(16383, 1024, 1024, 256, 4), 11_775);
        // Rings and caches beyond the pool leave nothing to hold.
        assert_eq!(rx_frame_budget(4095, 1024, 1024, 256, 4), 0);
    }

    #[test]
    fn rss_query_follows_grown_sizes() {
        let (result, calls) = run(vec![Err((ENOSPC, (40, 128))), Ok(7)]);
        assert_eq!(result.unwrap(), 7);
        assert_eq!(calls, [(40, 64), (40, 128)]);
    }

    #[test]
    fn rss_query_retries_a_bounded_number_of_times() {
        let replies = (1..=RSS_QUERY_ATTEMPTS + 1)
            .map(|round| Err((ENOSPC, (40, 64 << round))))
            .collect();
        let (result, calls) = run(replies);
        let error = result.unwrap_err();
        assert!(error.to_string().contains("keeps growing"), "{error}");
        assert_eq!(calls.len(), RSS_QUERY_ATTEMPTS);
    }

    #[test]
    fn rss_query_returns_the_pmds_own_enospc() {
        // The sizes did not grow: the PMD itself refused.
        let (result, calls) = run(vec![Err((ENOSPC, (40, 64)))]);
        assert!(result.unwrap_err().to_string().starts_with("rss query"));
        assert_eq!(calls.len(), 1);
        let (result, _) = run(vec![Err((-95, (40, 64)))]);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
    }
}
