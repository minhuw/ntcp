use ntcp_io::{
    BorrowedFrame, ClockDescriptor, ClockDomain, DeviceCounters, HeapChunkSource, PacketIo,
    PacketLayer, PacketTimestamp, PacketTimestamps, PayloadSlice, ReceivedPacket, RxChecksum,
    RxFrame, RxFrameCount, RxFrameVtable, TcpSegmentationCapabilities, TcpSegmentationError,
    TcpSegmentationRequest, TimestampCapabilities, TimestampPoint, TimestampSource, TimestampUnit,
    TransmitError, TransmitRequest, TransmitTime, TxChunk, TxChunkSource, TxOutcome, TxPacket,
    TxPart, TxSchedulingCapabilities, TxTimestampRequest,
};
use std::{
    ffi::{CStr, c_char, c_void},
    io,
    marker::PhantomData,
    mem::MaybeUninit,
    ptr::{self, NonNull},
    rc::Rc,
};

/// Maximum complete frame size accepted by the bounded copy shim.
pub const MAX_PACKET_LEN: usize = 65_535;

/// Default payload-length threshold at or below which `PacketIo::transmit_packet`
/// copies payload bytes directly into the header mbuf instead of attaching
/// external buffers (D1 copybreak).
pub const DEFAULT_TX_COPYBREAK: usize = 512;

const INLINE_PARTS: usize = 32;

// rte_eth_rx_burst requires a count divisible by eight to support every PMD;
// 32 matches typical vector PMD batch sizes and amortizes ring polls.
pub(crate) const RX_BURST_LEN: usize = 32;

// NTCP_DPDK_NOMBUF: a transmit call found the pool empty and kept nothing.
const NOMBUF: i32 = 2;
// NTCP_DPDK_COPY: ntcp_dpdk_receive_meta leaves an mbuf to be copied.
const COPY: i32 = 2;

#[path = "chunk.rs"]
mod chunk;
#[path = "segmentation.rs"]
mod segmentation;
#[path = "shared.rs"]
mod shared;
pub use shared::DpdkBuffer;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct TsoConfig {
    mtu: u16,
    room: u16,
    max_descriptors: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RxView {
    data: *mut u8,
    length: u16,
    l4_status: u8,
}

#[repr(C)]
#[derive(Default)]
struct RxMeta {
    data: *mut u8,
    timestamp: u64,
    timestamp_valid: i32,
    l4_status: i32,
    length: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TxOffload {
    timestamp_offset: i32,
    timestamp_flag: u64,
    timestamp: u64,
    l3: u16,
    l4: u16,
    mss: u16,
}

impl Default for TxOffload {
    fn default() -> Self {
        Self {
            timestamp_offset: -1,
            timestamp_flag: 0,
            timestamp: 0,
            l3: 0,
            l4: 0,
            mss: 0,
        }
    }
}

const EXT_CHUNK: u8 = 0;
const EXT_SHARED: u8 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct ExtPart {
    kind: u8,
    length: u16,
    offset: u32,
    handle: *mut c_void,
    address: *const c_void,
    iova: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CopyPart {
    ptr: *const u8,
    length: usize,
}

#[derive(Clone, Copy)]
enum MergedPart<'a> {
    Chunk {
        chunk: &'a TxChunk,
        offset: usize,
        len: usize,
    },
    Shared(PayloadSlice<'a>),
}

impl From<&TxPart<'_>> for CopyPart {
    fn from(part: &TxPart<'_>) -> Self {
        let bytes = part.bytes();
        Self {
            ptr: bytes.as_ptr(),
            length: bytes.len(),
        }
    }
}

fn with_copy_parts<R>(payload: &[TxPart<'_>], copy: impl FnOnce(&[CopyPart]) -> R) -> R {
    match payload {
        [] => copy(&[]),
        [part] if part.is_empty() => copy(&[]),
        [part] => copy(&[CopyPart::from(part)]),
        many => {
            let mut parts = SmallBuf::<CopyPart, INLINE_PARTS>::new();
            for part in many {
                if !part.is_empty() {
                    parts.push(CopyPart::from(part));
                }
            }
            copy(parts.as_slice())
        }
    }
}

enum SmallBuf<T: Copy, const N: usize> {
    Inline {
        buf: [MaybeUninit<T>; N],
        len: usize,
    },
    Heap(Vec<T>),
}

impl<T: Copy, const N: usize> SmallBuf<T, N> {
    fn new() -> Self {
        Self::Inline {
            buf: [MaybeUninit::uninit(); N],
            len: 0,
        }
    }

    fn push(&mut self, value: T) {
        match self {
            Self::Inline { buf, len } if *len < N => {
                buf[*len].write(value);
                *len += 1;
            }
            Self::Inline { buf, len } => {
                let mut vec = Vec::with_capacity((*len).saturating_mul(2).max(N + 1));
                // SAFETY: `buf[..*len]` are initialized.
                let slice = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<T>(), *len) };
                vec.extend_from_slice(slice);
                vec.push(value);
                *self = Self::Heap(vec);
            }
            Self::Heap(vec) => vec.push(value),
        }
    }

    fn as_slice(&self) -> &[T] {
        match self {
            Self::Inline { buf, len } => {
                // SAFETY: `buf[..*len]` are initialized.
                unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<T>(), *len) }
            }
            Self::Heap(vec) => vec.as_slice(),
        }
    }

    fn as_mut_slice(&mut self) -> &mut [T] {
        match self {
            Self::Inline { buf, len } => {
                // SAFETY: `buf[..*len]` are initialized.
                unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<T>(), *len) }
            }
            Self::Heap(vec) => vec.as_mut_slice(),
        }
    }

    fn last_mut(&mut self) -> Option<&mut T> {
        self.as_mut_slice().last_mut()
    }
}

unsafe extern "C" {
    fn ntcp_dpdk_tso_check(port: u16, queue: u16, pool: *mut c_void, config: *mut TsoConfig)
    -> i32;
    fn ntcp_dpdk_tso_transmit(
        port: u16,
        queue: u16,
        pool: *mut c_void,
        packet: *const u8,
        len: usize,
        l3: u16,
        mss: u16,
        config: *const TsoConfig,
    ) -> i32;
    fn ntcp_dpdk_get_mtu(port: u16, mtu: *mut u16) -> i32;
    fn ntcp_dpdk_port_driver(port: u16, name: *mut c_char, capacity: usize) -> i32;
    fn ntcp_dpdk_tx_scheduling_check(port: u16, queue: u16) -> i32;
    fn ntcp_dpdk_tx_timestamp_lookup(offset: *mut i32, flag: *mut u64) -> i32;
    fn ntcp_dpdk_valid_port(port: u16) -> i32;
    fn ntcp_dpdk_rx_timestamp_lookup(offset: *mut i32, flag: *mut u64) -> i32;
    fn ntcp_dpdk_rx_timestamp_status(
        port: u16,
        queue: u16,
        supported: *mut i32,
        enabled: *mut i32,
    ) -> i32;
    fn ntcp_dpdk_receive_burst(
        port: u16,
        queue: u16,
        packets: *mut *mut c_void,
        count: u16,
        pool: *const c_void,
        l4_checksum: i32,
        views: *mut RxView,
    ) -> u16;
    fn ntcp_dpdk_packet_free(packet: *mut c_void);
    fn ntcp_dpdk_frame_free(packet: *mut c_void);
    fn ntcp_dpdk_rx_checksum_check(port: u16, queue: u16) -> i32;
    fn ntcp_dpdk_tx_checksum_check(port: u16, queue: u16) -> i32;
    fn ntcp_dpdk_receive_meta(
        packet: *mut c_void,
        pool: *const c_void,
        timestamp_offset: i32,
        timestamp_flag: u64,
        l4_checksum: i32,
        out: *mut RxMeta,
    ) -> i32;
    fn ntcp_dpdk_pool_geometry(
        pool: *const c_void,
        element: *mut u32,
        cache: *mut u32,
        size: *mut u32,
    );
    fn ntcp_dpdk_pool_room(pool: *const c_void) -> u16;
    fn ntcp_dpdk_packet_transmit_ext(
        port: u16,
        queue: u16,
        pool: *mut c_void,
        header: *const u8,
        header_length: u16,
        parts: *const ExtPart,
        count: u16,
        shared_release: unsafe extern "C" fn(*mut c_void),
        offload: *const TxOffload,
    ) -> i32;
    fn ntcp_dpdk_packet_transmit_copy(
        port: u16,
        queue: u16,
        pool: *mut c_void,
        header: *const u8,
        header_length: usize,
        parts: *const CopyPart,
        count: usize,
        offload: *const TxOffload,
        max_descriptors: u16,
    ) -> i32;
    fn ntcp_dpdk_receive(
        packet: *mut c_void,
        out: *mut u8,
        capacity: usize,
        len: *mut usize,
        timestamp_offset: i32,
        timestamp_flag: u64,
        timestamp: *mut u64,
        timestamp_valid: *mut i32,
        l4_checksum: i32,
        l4_status: *mut i32,
    ) -> i32;
    fn ntcp_dpdk_transmit(
        port: u16,
        queue: u16,
        pool: *mut c_void,
        packet: *const u8,
        len: usize,
        timestamp_offset: i32,
        timestamp_flag: u64,
        timestamp: u64,
        l3: u16,
    ) -> i32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RxTimestampStatus {
    pub supported: bool,
    // None: the PMD does not expose queue configuration through the stable API.
    pub queue_enabled: Option<bool>,
}

#[derive(Clone, Copy)]
struct TimestampConfig {
    clock: ClockDescriptor,
    offset: i32,
    flag: u64,
}

// The release of a frame `receive_frame` handed over: the mbuf (`token`)
// goes back to its pool, and the return is counted in the adapter's
// block (`context`), which the last of the adapter and its frames frees.
static MBUF_FRAME: RxFrameVtable = RxFrameVtable {
    release: release_mbuf,
};

// SAFETY (caller): `context` is an adapter's `Box<RxFrameCount>` given up
// with `Box::into_raw`, and `token` the exposed address of an mbuf of the
// adapter's pool that the adapter handed over and nothing else frees.
unsafe fn release_mbuf(context: *mut (), token: usize) {
    // SAFETY: the validated direct, single-segment, refcnt-1 mbuf stayed
    // exclusively in this frame (`direct_frame` + `receive_check`). Returning
    // it to its pool via `ntcp_dpdk_frame_free` (`rte_mbuf_raw_free`) is
    // MT-safe on any thread, and the pool is kept while any of its mbufs is
    // out (PortInner::drop, ntcp_dpdk_pool_free; a borrowing host keeps it as
    // from_borrowed requires).
    unsafe { ntcp_dpdk_frame_free(ptr::with_exposed_provenance_mut(token)) };
    let count = context.cast::<RxFrameCount>();
    // SAFETY: the block lives until the last of the adapter and its
    // frames frees it, which this frame's release decides here.
    if unsafe { &*count }.release() {
        drop(unsafe { Box::from_raw(count) });
    }
}

/// Borrows an already started Ethernet port and its queues. Owns no EAL,
/// devices, pools, or threads. Each operation returns or submits at most one frame;
/// RX retains prefetched mbufs until delivery or drop. Explicit zero-copy submission
/// retains external payload leases until reclaim.
/// Not Send/Sync: the host must enforce DPDK lcore and queue scheduling rules.
pub struct Dpdk {
    port: u16,
    rx_queue: u16,
    tx_queue: u16,
    pool: NonNull<c_void>,
    rx_packets: [*mut c_void; RX_BURST_LEN],
    rx_views: Option<[RxView; RX_BURST_LEN]>,
    rx_next: usize,
    rx_count: usize,
    tso: Option<TsoConfig>,
    // The driver keeps PSH and FIN on an aggregate's last segment only
    // (segmentation::psh_on_last_segment), read with `tso`.
    tso_psh: bool,
    shared_limit: Option<u16>,
    rx_timestamp: Option<TimestampConfig>,
    tx_scheduling: Option<TimestampConfig>,
    // The device's TCP checksum verdict is read (enable_rx_checksum).
    rx_checksum: bool,
    // The device completes TCP checksums (enable_tx_checksum).
    tx_checksum: bool,
    // Transmit attempts that found the pool empty (DeviceCounters).
    tx_nombuf: u64,
    // Mbufs handed over by reference (`receive_frame`): how many, and
    // their returns, which the adapter's block counts (`MBUF_FRAME`).
    frames_taken: u64,
    frames: NonNull<RxFrameCount>,
    // What one mbuf keeps from the pool, a held frame's truesize: the
    // element with its mempool header and trailer.
    frame_truesize: u32,
    // Tailroom of a freshly allocated direct mbuf from `self.pool`.
    pool_room: u16,
    // Payload-length threshold at or below which `transmit_packet` copies
    // directly into the header mbuf instead of attaching extbufs (D1).
    tx_copybreak: usize,
    // `set_rx_frame_budget`.
    rx_frame_budget: Option<usize>,
    _local: PhantomData<Rc<()>>,
}

// enable_tcp_segmentation's check of TX queue `queue`'s actual offloads,
// descriptor limits, MTU and pool geometry, also for the host that
// configured the port (Port::start).
// The caller guarantees that EAL is initialized and that the port, its
// configured queue and the pktmbuf pool are live for the call.
pub(crate) unsafe fn tso_check(port: u16, queue: u16, pool: *mut c_void) -> io::Result<TsoConfig> {
    let mut config = TsoConfig::default();
    // SAFETY: as the caller guarantees; config is writable.
    let result = unsafe { ntcp_dpdk_tso_check(port, queue, pool, &mut config) };
    if result < 0 {
        return Err(io::Error::from_raw_os_error(-result));
    }
    Ok(config)
}

// enable_rx_checksum's check of RX queue `queue`, also for the host that
// configured the port (Port::start). The caller guarantees that EAL is
// initialized and that the port and its configured queue are live.
pub(crate) unsafe fn rx_checksum_check(port: u16, queue: u16) -> io::Result<()> {
    // SAFETY: as the caller guarantees.
    let result = unsafe { ntcp_dpdk_rx_checksum_check(port, queue) };
    if result < 0 {
        return Err(io::Error::from_raw_os_error(-result));
    }
    Ok(())
}

// enable_tx_checksum's check of TX queue `queue`, as rx_checksum_check.
pub(crate) unsafe fn tx_checksum_check(port: u16, queue: u16) -> io::Result<()> {
    // SAFETY: as the caller guarantees.
    let result = unsafe { ntcp_dpdk_tx_checksum_check(port, queue) };
    if result < 0 {
        return Err(io::Error::from_raw_os_error(-result));
    }
    Ok(())
}

// The network header length of an Ethernet frame of one TCP segment that
// the device can checksum: IPv4 with any header length, or IPv6 whose
// base header names TCP. Validates against `header` and `total_len` without
// copying payload bytes.
fn tcp_frame_l3(header: &[u8], total_len: usize) -> Option<u16> {
    let ip = header.get(14..)?;
    let l3 = match (
        u16::from_be_bytes([header[12], header[13]]),
        ip.first()? >> 4,
    ) {
        (0x0800, 4) if *ip.get(9)? == 6 => u16::from(ip[0] & 15) * 4,
        (0x86dd, 6) if *ip.get(6)? == 6 => 40,
        _ => return None,
    };
    (l3 >= 20
        && ip.len() >= usize::from(l3) + 20
        && total_len >= 14 + usize::from(l3) + 20)
        .then_some(l3)
}

fn map_transmit_shim_error(error: i32) -> TransmitError {
    let error = io::Error::from_raw_os_error(-error);
    match error.kind() {
        io::ErrorKind::InvalidInput => TransmitError::InvalidInput,
        io::ErrorKind::Unsupported => TransmitError::Unsupported,
        _ => TransmitError::Other(error),
    }
}

// The ethdev driver serving `port` (rte_eth_dev_info driver_name), or the
// negative errno of rte_eth_dev_info_get. The caller guarantees that EAL is
// initialized and the port is valid.
pub(crate) unsafe fn driver_name(port: u16) -> Result<String, i32> {
    let mut name = [0; 64];
    // SAFETY: as the caller guarantees; buffer capacity is passed.
    let result = unsafe { ntcp_dpdk_port_driver(port, name.as_mut_ptr(), name.len()) };
    if result < 0 {
        return Err(result);
    }
    // SAFETY: the shim NUL-terminates within capacity (snprintf).
    let name = unsafe { CStr::from_ptr(name.as_ptr()) };
    Ok(name.to_string_lossy().into_owned())
}

impl Dpdk {
    /// # Safety
    /// The host must initialize EAL before calling this and keep EAL, the
    /// started port, both configured queues, and the actual `rte_mempool`
    /// pointer alive and unchanged until this adapter and all submitted DMA
    /// buffers have finished. The pool must allocate direct packet mbufs.
    /// Queue access must be exclusive (including other adapters), and calls
    /// must run on a host-selected DPDK-compatible thread/lcore. The host must
    /// configure multi-segment TX if frames exceed one mbuf's tailroom, and
    /// ensure frame sizes meet device limits. TX bytes must already contain
    /// their checksums; ordinary transmit requests no checksum/segmentation offloads. Explicit
    /// transmit_segmented requires zero IP/TCP checksum fields instead.
    /// RX must be configured to deliver complete Ethernet frames in valid,
    /// acyclic DPDK mbuf chains: disable VLAN/QinQ stripping, LRO, and any
    /// other offload that removes or transforms frame bytes. PacketIo cannot
    /// reconstruct transformed frame bytes; flagged stripped/coalesced packets are
    /// rejected, not reconstructed. The host owns TX
    /// completion/reclamation, port stop/close, and pool/EAL teardown.
    /// Construction and destruction do not configure or stop anything.
    pub unsafe fn from_borrowed(
        port: u16,
        rx_queue: u16,
        tx_queue: u16,
        pool: *mut c_void,
    ) -> io::Result<Self> {
        let pool = NonNull::new(pool)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "null DPDK mempool"))?;
        // SAFETY: the caller guarantees that EAL is initialized.
        if unsafe { ntcp_dpdk_valid_port(port) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid DPDK port",
            ));
        }
        // SAFETY: the caller guarantees a live pktmbuf pool; outputs are
        // writable.
        let (element, _, _) = unsafe { pool_geometry(pool.as_ptr()) };
        // SAFETY: the caller guarantees a live pktmbuf pool.
        let pool_room = unsafe { ntcp_dpdk_pool_room(pool.as_ptr()) };
        Ok(Self {
            port,
            rx_queue,
            tx_queue,
            pool,
            rx_packets: [ptr::null_mut(); RX_BURST_LEN],
            rx_views: None,
            rx_next: 0,
            rx_count: 0,
            tso: None,
            tso_psh: false,
            shared_limit: None,
            rx_timestamp: None,
            tx_scheduling: None,
            rx_checksum: false,
            tx_checksum: false,
            tx_nombuf: 0,
            frames_taken: 0,
            frames: NonNull::from(Box::leak(Box::new(RxFrameCount::new()))),
            frame_truesize: element,
            pool_room,
            tx_copybreak: DEFAULT_TX_COPYBREAK,
            rx_frame_budget: None,
            _local: PhantomData,
        })
    }

    /// Payload-length threshold at or below which `transmit_packet` copies
    /// payload bytes into the header mbuf instead of attaching extbufs.
    pub fn tx_copybreak(&self) -> usize {
        self.tx_copybreak
    }

    /// Set the TX copybreak threshold in payload bytes (default:
    /// [`DEFAULT_TX_COPYBREAK`]).
    pub fn set_tx_copybreak(&mut self, bytes: usize) {
        self.tx_copybreak = bytes;
    }

    /// The frame budget this adapter reports (`PacketIo::rx_frame_budget`):
    /// how many of the pool's mbufs a consumer may hold by reference, which
    /// only the host that sized the pool and the queues' rings knows
    /// (`HostedQueue` sets it from its `PortConfig`). None, the default,
    /// leaves consumers on the copying path; `receive_frame` hands mbufs
    /// over by reference either way.
    pub fn set_rx_frame_budget(&mut self, budget: Option<usize>) {
        self.rx_frame_budget = budget;
        self.rx_views = (budget.is_some() && self.rx_timestamp.is_none())
            .then(|| [RxView::default(); RX_BURST_LEN]);
    }

    fn mark_rx_checksum_enabled(&mut self) {
        self.rx_checksum = true;
        if let Some(views) = &mut self.rx_views {
            for view in &mut views[self.rx_next..self.rx_count] {
                view.data = ptr::null_mut();
            }
        }
    }

    fn refill_rx_burst(&mut self) -> bool {
        self.rx_next = 0;
        // SAFETY: the live queue is exclusively borrowed, `self.pool` is
        // live, and the packet array (and optional view array) can hold
        // the requested burst. Each returned mbuf transfers to us.
        self.rx_count = unsafe {
            ntcp_dpdk_receive_burst(
                self.port,
                self.rx_queue,
                self.rx_packets.as_mut_ptr(),
                RX_BURST_LEN as u16,
                self.pool.as_ptr(),
                i32::from(self.rx_checksum),
                self.rx_views
                    .as_mut()
                    .map_or(ptr::null_mut(), |views| views.as_mut_ptr()),
            )
        } as usize;
        self.rx_count > 0
    }

    // The next received mbuf chain, from the prefetched burst or a new one.
    fn next_packet(&mut self) -> Option<usize> {
        if self.rx_next == self.rx_count && !self.refill_rx_burst() {
            return None;
        }
        // Only the unread suffix owns mbufs. The next burst overwrites the prefix.
        let index = self.rx_next;
        self.rx_next += 1;
        Some(index)
    }

    // `packet` copied into `out` and freed, as receive_with_metadata
    // receives it.
    fn copy_packet(&mut self, packet: *mut c_void, out: &mut [u8]) -> io::Result<ReceivedPacket> {
        let (mut len, mut timestamp, mut valid, mut l4) = (0, 0, 0, 0);
        let config = self.rx_timestamp;
        // SAFETY: the shim consumes this owned mbuf chain on success or error;
        // slice/outputs are writable, and the cached offset/flag were validated.
        match unsafe {
            ntcp_dpdk_receive(
                packet,
                out.as_mut_ptr(),
                out.len(),
                &mut len,
                config.map_or(-1, |c| c.offset),
                config.map_or(0, |c| c.flag),
                &mut timestamp,
                &mut valid,
                i32::from(self.rx_checksum),
                &mut l4,
            )
        } {
            1 => Ok(self.metadata(len, timestamp, valid, l4)),
            error => Err(io::Error::from_raw_os_error(-error)),
        }
    }

    fn metadata(&self, len: usize, timestamp: u64, valid: i32, l4: i32) -> ReceivedPacket {
        ReceivedPacket {
            len,
            tcp_segment_size: None,
            l4_checksum: match l4 {
                1 => RxChecksum::Good,
                2 => RxChecksum::Bad,
                _ => RxChecksum::Unknown,
            },
            timestamps: PacketTimestamps {
                software: None,
                hardware: self
                    .rx_timestamp
                    .filter(|_| valid != 0)
                    .map(|c| PacketTimestamp {
                        value: timestamp,
                        source: TimestampSource::Hardware,
                        point: TimestampPoint::DeviceReceive,
                        clock: c.clock,
                    }),
            },
        }
    }

    /// Opt into the already host-enabled SEND_ON_TIMESTAMP offload. No EAL,
    /// port, queue or dynamic registry configuration is changed. Requires a
    /// device clock; RawTicks identity must identify the caller's calibration.
    /// The caller synchronizes/converts targets to the PMD's clock and units:
    /// there is no absolute monotonic-to-device-clock assumption here.
    /// PMD scheduling capability is NOT a precision or delivery guarantee.
    /// The caller must respect PMD ordering/horizon limits (past targets may
    /// send immediately and distant targets may be capped by the PMD).
    pub fn enable_tx_scheduling(&mut self, clock: ClockDescriptor) -> io::Result<()> {
        if !matches!(clock.domain, ClockDomain::Device(_)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DPDK requires a device clock",
            ));
        }
        // SAFETY: the borrowed port/queue remain live and unchanged.
        let result = unsafe { ntcp_dpdk_tx_scheduling_check(self.port, self.tx_queue) };
        if result < 0 {
            return Err(io::Error::from_raw_os_error(-result));
        }
        let (mut offset, mut flag) = (-1, 0);
        // SAFETY: EAL/registry remain live; outputs are writable.
        let result = unsafe { ntcp_dpdk_tx_timestamp_lookup(&mut offset, &mut flag) };
        if result < 0 {
            return Err(io::Error::from_raw_os_error(-result));
        }
        self.tx_scheduling = Some(TimestampConfig {
            clock,
            offset,
            flag,
        });
        Ok(())
    }

    /// Opt into the device's RX TCP checksum verdict
    /// (`ReceivedPacket::l4_checksum`), when the host enabled
    /// RTE_ETH_RX_OFFLOAD_TCP_CKSUM on the port or this queue. Read-only;
    /// nothing is configured. Without it every packet reports Unknown.
    pub fn enable_rx_checksum(&mut self) -> io::Result<()> {
        // SAFETY: the borrowed port/queue remain live and unchanged.
        unsafe { rx_checksum_check(self.port, self.rx_queue) }?;
        self.mark_rx_checksum_enabled();
        Ok(())
    }

    /// Opt into TX TCP checksum offload (`transmit_tcp_checksum_offload`),
    /// when the host enabled RTE_ETH_TX_OFFLOAD_TCP_CKSUM on the port or
    /// this queue. Read-only; nothing is configured.
    pub fn enable_tx_checksum(&mut self) -> io::Result<()> {
        // SAFETY: the borrowed port/queue remain live and unchanged.
        unsafe { tx_checksum_check(self.port, self.tx_queue) }?;
        self.tx_checksum = true;
        Ok(())
    }

    // Read-only control-plane opt-in. The borrowed MTU/config/pool geometry must
    // remain unchanged, as required by from_borrowed. No per-packet query.
    pub fn enable_tcp_segmentation(&mut self) -> io::Result<()> {
        // SAFETY: the host keeps the port, queue and pool live and unchanged.
        let config = unsafe { tso_check(self.port, self.tx_queue, self.pool.as_ptr()) }?;
        // SAFETY: EAL is live and the port valid, as from_borrowed requires.
        let driver =
            unsafe { driver_name(self.port) }.map_err(|r| io::Error::from_raw_os_error(-r))?;
        self.tso_psh = segmentation::psh_on_last_segment(&driver);
        self.tso = Some(config);
        Ok(())
    }

    // `l3`: the network header length of a TCP segment whose checksum the
    // device completes, 0 for none.
    fn submit(
        &mut self,
        packet: &[u8],
        when: Option<TransmitTime>,
        l3: u16,
    ) -> io::Result<TxOutcome> {
        let config = when.and(self.tx_scheduling);
        // SAFETY: shim copies the readable slice; cached metadata was validated
        // against the registry. Only allocated mbufs transfer to the PMD.
        match unsafe {
            ntcp_dpdk_transmit(
                self.port,
                self.tx_queue,
                self.pool.as_ptr(),
                packet.as_ptr(),
                packet.len(),
                config.map_or(-1, |c| c.offset),
                config.map_or(0, |c| c.flag),
                when.map_or(0, |w| w.value),
                l3,
            )
        } {
            0 => Ok(TxOutcome::WouldBlock),
            1 => Ok(TxOutcome::Submitted),
            NOMBUF => Ok(self.pool_empty()),
            error => Err(io::Error::from_raw_os_error(-error)),
        }
    }

    // A transmit attempt the pool had no mbuf for: backpressure, as a full
    // TX ring, since mbufs come back as the device completes frames
    // (reclaim) and RX frames are freed; the caller keeps the packet and
    // retries it.
    #[cold]
    fn pool_empty(&mut self) -> TxOutcome {
        self.tx_nombuf += 1;
        TxOutcome::WouldBlock
    }

    // The copy path packs spans into mbufs by byte count. Only external
    // buffers use a descriptor per span and need to coalesce chunk ranges.
    fn transmit_copied_packet(
        &self,
        packet: &TxPacket<'_>,
        offload: &TxOffload,
        max_descriptors: u16,
    ) -> i32 {
        let copy = |parts: &[CopyPart]| {
            // SAFETY: the port, queue and pool are live. The header and all
            // part ranges borrow initialized bytes for this synchronous copy.
            unsafe {
                ntcp_dpdk_packet_transmit_copy(
                    self.port,
                    self.tx_queue,
                    self.pool.as_ptr(),
                    packet.header.as_ptr(),
                    packet.header.len(),
                    parts.as_ptr(),
                    parts.len(),
                    offload,
                    max_descriptors,
                )
            }
        };
        with_copy_parts(packet.payload, copy)
    }

    fn transmit_external_packet(
        &self,
        packet: &TxPacket<'_>,
        total_len: usize,
        offload: &TxOffload,
        max_descriptors: u16,
        limit: u16,
    ) -> Option<i32> {
        // Skip zero-length parts and merge adjacent TxPart::Chunk slices from
        // the same TxChunk with contiguous byte ranges (invariant I9).
        let mut merged = SmallBuf::<MergedPart<'_>, INLINE_PARTS>::new();
        for &part in packet.payload {
            if part.is_empty() {
                continue;
            }
            match part {
                TxPart::Chunk(slice) => {
                    if let Some(MergedPart::Chunk { chunk, offset, len }) = merged.last_mut()
                        && core::ptr::eq(*chunk, slice.chunk())
                        && *offset + *len == slice.offset()
                    {
                        *len += slice.len();
                        continue;
                    }
                    merged.push(MergedPart::Chunk {
                        chunk: slice.chunk(),
                        offset: slice.offset(),
                        len: slice.len(),
                    });
                }
                TxPart::Shared(slice) => merged.push(MergedPart::Shared(slice)),
            }
        }

        let merged_slice = merged.as_slice();
        let payload_segs = merged_slice.len();
        let pad_segs = usize::from(total_len < 60 && offload.mss == 0);
        let total_segs = 1 + payload_segs + pad_segs;
        let header_fits_head = !packet.header.is_empty()
            && packet.header.len() <= usize::from(self.pool_room)
            && (offload.l3 == 0 || packet.header.len() >= 14 + usize::from(offload.l3) + 20)
            && (offload.mss == 0
                || packet.header.len()
                    >= 14 + usize::from(offload.l3) + usize::from(offload.l4));
        let seg_limit_ok = total_segs <= usize::from(limit)
            && (max_descriptors == 0 || total_segs <= usize::from(max_descriptors));
        let all_dma_backed = payload_segs > 0
            && merged_slice.iter().all(|part| match part {
                MergedPart::Chunk { chunk, .. } => {
                    core::ptr::eq(chunk.vtable(), &chunk::DPDK_CHUNK_VTABLE)
                }
                MergedPart::Shared(slice) => slice.payload().storage::<DpdkBuffer>().is_some(),
            });

        if !(header_fits_head && seg_limit_ok && all_dma_backed) {
            return None;
        }
        let mut ext_parts = SmallBuf::<ExtPart, INLINE_PARTS>::new();
        for &part in merged_slice {
            match part {
                MergedPart::Chunk { chunk, offset, len } => {
                    ext_parts.push(ExtPart {
                        kind: EXT_CHUNK,
                        length: len as u16,
                        offset: offset as u32,
                        handle: chunk.context().cast(),
                        address: ptr::null(),
                        iova: 0,
                    });
                }
                MergedPart::Shared(slice) => {
                    let storage = slice.payload().storage::<DpdkBuffer>().unwrap();
                    let base_offset = slice.payload().offset() + slice.range().start;
                    debug_assert_eq!(
                        slice.bytes().as_ptr(),
                        storage.as_ref().as_ptr().wrapping_add(base_offset)
                    );
                    ext_parts.push(ExtPart {
                        kind: EXT_SHARED,
                        length: slice.len() as u16,
                        offset: 0,
                        handle: ptr::null_mut(),
                        address: slice.bytes().as_ptr().cast(),
                        iova: storage.iova + base_offset as u64,
                    });
                }
            }
        }
        // Populate Shared leases only after ext_parts storage is finalized,
        // so C receives and owns every lease on all paths.
        for (ext, part) in ext_parts.as_mut_slice().iter_mut().zip(merged_slice) {
            if let MergedPart::Shared(slice) = part {
                ext.handle = Box::into_raw(Box::new(slice.to_payload())).cast();
            }
        }
        let ext_slice = ext_parts.as_slice();
        // SAFETY: live borrowed port/queue/pool; `ext_slice` entries point
        // to live DPDK chunks (owner ref held across this call) or freshly
        // boxed `Payload` leases over `DpdkBuffer` (all taken by C on every
        // path).
        Some(unsafe {
            ntcp_dpdk_packet_transmit_ext(
                self.port,
                self.tx_queue,
                self.pool.as_ptr(),
                packet.header.as_ptr(),
                packet.header.len() as u16,
                ext_slice.as_ptr(),
                ext_slice.len() as u16,
                shared::release,
                offload,
            )
        })
    }

    /// Read-only diagnostic; does not configure or register anything.
    pub fn rx_timestamp_status(&self) -> io::Result<RxTimestampStatus> {
        let (mut supported, mut enabled) = (0, -1);
        // SAFETY: construction guarantees live port/queues; outputs are writable.
        let result = unsafe {
            ntcp_dpdk_rx_timestamp_status(self.port, self.rx_queue, &mut supported, &mut enabled)
        };
        if result < 0 {
            return Err(io::Error::from_raw_os_error(-result));
        }
        Ok(RxTimestampStatus {
            supported: supported != 0,
            queue_enabled: (enabled >= 0).then_some(enabled != 0),
        })
    }

    /// Opt into extraction only. The host configures RX_OFFLOAD_TIMESTAMP and
    /// registers the standard dynfield/flag (normally done by the PMD) before
    /// borrowing. No device setting is changed. A virtual PMD may also carry
    /// injected metadata without hardware offload capability. Only flag-valid
    /// packets yield timestamps; device units/epoch require host calibration.
    pub fn enable_rx_timestamps(&mut self, clock: ClockDescriptor) -> io::Result<()> {
        if !matches!(clock.domain, ClockDomain::Device(_))
            || !matches!(clock.unit, TimestampUnit::RawTicks { .. })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DPDK requires a raw device clock",
            ));
        }
        if let Some(config) = &mut self.rx_timestamp {
            config.clock = clock;
            return Ok(());
        }
        let (mut offset, mut flag) = (-1, 0);
        // SAFETY: host keeps EAL and the dynamic registry alive; outputs writable.
        let result = unsafe { ntcp_dpdk_rx_timestamp_lookup(&mut offset, &mut flag) };
        if result < 0 {
            return Err(io::Error::from_raw_os_error(-result));
        }
        self.rx_views = None;
        self.rx_timestamp = Some(TimestampConfig {
            clock,
            offset,
            flag,
        });
        Ok(())
    }
}

impl Drop for Dpdk {
    fn drop(&mut self) {
        for &packet in &self.rx_packets[self.rx_next..self.rx_count] {
            // SAFETY: unread burst entries are owned mbuf chains. The host
            // keeps EAL and the pool live until the adapter has been dropped.
            unsafe { ntcp_dpdk_packet_free(packet) };
        }
        // Frames still held keep the block for their releases.
        // SAFETY: the block is live until this call or the last release
        // frees it, and only the one of them that `leave`/`release` names.
        if unsafe { self.frames.as_ref() }.leave(self.frames_taken) {
            drop(unsafe { Box::from_raw(self.frames.as_ptr()) });
        }
    }
}

// (element, per-lcore cache size, element count) of pktmbuf pool `pool`
// (ntcp_dpdk_pool_geometry). The caller guarantees the pool is live.
pub(crate) unsafe fn pool_geometry(pool: *const c_void) -> (u32, u32, u32) {
    let (mut element, mut cache, mut size) = (0, 0, 0);
    // SAFETY: as the caller guarantees; outputs are writable.
    unsafe { ntcp_dpdk_pool_geometry(pool, &mut element, &mut cache, &mut size) };
    (element, cache, size)
}

// Keep the default Unsupported TX timestamp methods: SEND_ON_TIMESTAMP is
// launch scheduling, and timesync TX targets PTP, not ordinary TCP completion.
impl PacketIo for Dpdk {
    fn reclaim_transmit(&mut self, budget: usize) -> io::Result<usize> {
        self.reclaim_shared(budget)
    }
    fn zero_copy_capabilities(&self) -> Option<ntcp_io::ZeroCopyCapabilities> {
        self.shared_capabilities()
    }
    fn zero_copy_payload_supported(&self, payload: &ntcp_io::Payload) -> bool {
        self.supports_shared(payload)
    }
    fn transmit_zero_copy(&mut self, packet: &ntcp_io::OwnedPacket) -> io::Result<TxOutcome> {
        self.submit_shared(packet)
    }

    fn tcp_segmentation_capabilities(&self) -> Option<TcpSegmentationCapabilities> {
        self.tso.map(|c| TcpSegmentationCapabilities {
            max_aggregate_len: MAX_PACKET_LEN
                .min(usize::from(c.room) * usize::from(c.max_descriptors)),
            max_segments: 64,
            // 63 more copies of the largest header: Ethernet, IPv6, 60-byte TCP.
            max_wire_bytes: MAX_PACKET_LEN + 63 * 114,
            local_ip_mtu: u32::from(c.mtu),
            // mlx5 only (psh_on_last_segment). The evidence is inferred from
            // software, not from the device's documentation:
            // - FIN, high confidence: Linux ORs FIN onto the unsent tail
            //   (tcp_send_fin, net/ipv4/tcp_output.c:3880), which can be a
            //   multi-segment GSO skb, and the mlx5 kernel driver hands that
            //   skb to one LSO WQE without touching its flags
            //   (drivers/net/ethernet/mellanox/mlx5/core/en_tx.c:270-281).
            //   A FIN copied into every segment would end Linux's streams
            //   early on every ConnectX, so the device keeps it on the last.
            // - PSH, medium: Linux forces PSH onto every multi-segment skb
            //   "to expedite GRO flush at receiver" (__tcp_transmit_skb,
            //   tcp_output.c:1639-1648) through the same WQE. Copied into
            //   every segment it would flush receivers' GRO at each one, a
            //   loss of performance but of nothing else, so less certain.
            // - The DPDK 26.03 mlx5 PMD builds the same TSO WQE from the
            //   mbuf's header bytes, flags untouched (drivers/net/mlx5/
            //   mlx5_tx.h:2401-2408, mlx5_tx_packet_multi_tso), and the shim
            //   copies the header as given (ntcp_dpdk_tso_transmit).
            // Linux's tcp_gso_segment clears the two together
            // (net/ipv4/tcp_offload.c:209), so one capability covers both.
            // CWR is unknown and stays refused: mlx5 does not advertise
            // NETIF_F_TSO_ECN (en_main.c, mlx5e_build_nic_netdev), so Linux
            // splits CWR skbs in software and never tells how the device
            // places CWR. A pcap of a ConnectX port's aggregates, taken at a
            // peer with GRO and LRO off, is the confirmation.
            allow_psh: self.tso_psh,
            allow_cwr: false,
        })
    }

    fn transmit_segmented(
        &mut self,
        packet: &[u8],
        request: TcpSegmentationRequest,
    ) -> Result<TxOutcome, TcpSegmentationError> {
        let config = self.tso.ok_or(TcpSegmentationError::Unsupported)?;
        let caps = self.tcp_segmentation_capabilities().unwrap();
        let (l3, l4) = segmentation::validate(packet, request.segment_payload_len, caps)?;
        if config.room < 14 + l3 + l4 {
            return Err(TcpSegmentationError::Unsupported);
        }
        // SAFETY: validated lengths/header subset, live exclusive borrowed queue;
        // shim copies bytes and transfers exactly one complete mbuf chain or none.
        match unsafe {
            ntcp_dpdk_tso_transmit(
                self.port,
                self.tx_queue,
                self.pool.as_ptr(),
                packet.as_ptr(),
                packet.len(),
                l3,
                request.segment_payload_len as u16,
                &config,
            )
        } {
            0 => Ok(TxOutcome::WouldBlock),
            1 => Ok(TxOutcome::Submitted),
            NOMBUF => Ok(self.pool_empty()),
            // Every negative shim result is before tx_burst; only recognized
            // rejections carry a fallback certificate across the public API.
            error => {
                let error = io::Error::from_raw_os_error(-error);
                Err(match error.kind() {
                    io::ErrorKind::InvalidInput => TcpSegmentationError::InvalidInput,
                    io::ErrorKind::Unsupported => TcpSegmentationError::Unsupported,
                    _ => TcpSegmentationError::Other(error),
                })
            }
        }
    }

    // rte_eth_tx_burst reports descriptor admission. There is no ordered
    // per-frame completion here, including for a PMD that immediately
    // releases the mbuf after copying its contents to a device ring.
    fn tx_completion(&self) -> ntcp_io::TxCompletion {
        ntcp_io::TxCompletion::NextPoll
    }
    // Only what this adapter counts: the port's receive counters belong to
    // the host that owns the port (HostedQueue reads them).
    fn device_counters(&self) -> DeviceCounters {
        DeviceCounters {
            tx_nombuf: self.tx_nombuf,
            ..DeviceCounters::default()
        }
    }

    fn local_ip_mtu(&self) -> io::Result<Option<u32>> {
        let mut mtu = 0;
        // SAFETY: borrowed port remains live; output is writable. No reconfiguration.
        let result = unsafe { ntcp_dpdk_get_mtu(self.port, &mut mtu) };
        if result < 0 {
            return Err(io::Error::from_raw_os_error(-result));
        }
        if mtu == 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(Some(u32::from(mtu)))
    }
    fn max_packet_len(&self) -> Option<usize> {
        Some(MAX_PACKET_LEN)
    }

    fn layer(&self) -> PacketLayer {
        PacketLayer::Ethernet
    }

    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        self.receive_with_metadata(out)
            .map(|packet| packet.map(|packet| packet.len))
    }

    fn timestamp_capabilities(&self) -> TimestampCapabilities {
        TimestampCapabilities {
            rx_hardware: self.rx_timestamp.is_some(),
            ..TimestampCapabilities::default()
        }
    }

    fn receive_with_metadata(&mut self, out: &mut [u8]) -> io::Result<Option<ReceivedPacket>> {
        let Some(index) = self.next_packet() else {
            return Ok(None);
        };
        self.copy_packet(self.rx_packets[index], out).map(Some)
    }

    // The mbuf itself, held until the frame drops, when it is one segment
    // of the adapter's pool (`ntcp_dpdk_receive_meta`); a scatter chain,
    // an indirect or extbuf-attached mbuf (mlx5 MPRQ strides, which
    // holding would pin whole) or another pool's is copied into a heap
    // frame of its length instead, through `scratch`. The frame's
    // truesize is the pool element, 2368 octets at the default geometry
    // (decision Q2).
    fn receive_frame(
        &mut self,
        scratch: &mut [u8],
        frame: &mut Option<RxFrame>,
    ) -> io::Result<Option<ReceivedPacket>> {
        let mut metadata = ReceivedPacket::default();
        self.receive_frame_into(scratch, frame, &mut metadata)
            .map(|received| received.then_some(metadata))
    }

    fn receive_frame_into(
        &mut self,
        scratch: &mut [u8],
        frame: &mut Option<RxFrame>,
        metadata: &mut ReceivedPacket,
    ) -> io::Result<bool> {
        let Some(index) = self.next_packet() else {
            return Ok(false);
        };
        let packet = self.rx_packets[index];
        // Enabling RX timestamps discards views, and enabling RX checksum
        // invalidates unread leftover views, so prefetched packets use the
        // settings current at delivery.
        let view = self
            .rx_views
            .as_ref()
            .map(|views| views[index])
            .unwrap_or_default();
        let (data, length, received_meta) = if let Some(data) = NonNull::new(view.data) {
            debug_assert!(
                self.rx_timestamp.is_none(),
                "RX views must be disabled when RX timestamps are enabled"
            );
            (
                data,
                view.length,
                self.metadata(usize::from(view.length), 0, 0, i32::from(view.l4_status)),
            )
        } else {
            let config = self.rx_timestamp;
            let mut received = RxMeta::default();
            // SAFETY: this owned mbuf chain is freed by the shim on error
            // and stays ours otherwise; `received` is writable, and the
            // cached offset/flag were validated.
            let status = unsafe {
                ntcp_dpdk_receive_meta(
                    packet,
                    self.pool.as_ptr(),
                    config.map_or(-1, |c| c.offset),
                    config.map_or(0, |c| c.flag),
                    i32::from(self.rx_checksum),
                    &mut received,
                )
            };
            match status {
                1 => {
                    let received_meta = self.metadata(
                        usize::from(received.length),
                        received.timestamp,
                        received.timestamp_valid,
                        received.l4_status,
                    );
                    (
                        NonNull::new(received.data).expect("an mbuf's data is not null"),
                        received.length,
                        received_meta,
                    )
                }
                COPY => {
                    let received_meta = self.copy_packet(packet, scratch)?;
                    *frame = Some(RxFrame::copy_from_slice(&scratch[..received_meta.len]));
                    *metadata = received_meta;
                    return Ok(true);
                }
                error => return Err(io::Error::from_raw_os_error(-error)),
            }
        };
        self.frames_taken += 1;
        // SAFETY: the shim validated one segment of `length` bytes inside a
        // direct, refcnt-1 mbuf of the adapter's pool (`direct_frame` and
        // `receive_check`), which the device has finished writing and nothing
        // writes again until it is freed. Only `MBUF_FRAME`'s release frees
        // it via `ntcp_dpdk_frame_free`, once, on any thread at any later time
        // (`release_mbuf`), with the block counting the return.
        *frame = Some(unsafe {
            RxFrame::from_raw_parts(
                data,
                u32::from(length),
                self.frame_truesize,
                &MBUF_FRAME,
                self.frames.as_ptr().cast(),
                packet.expose_provenance(),
            )
        });
        *metadata = received_meta;
        Ok(true)
    }

    fn consume_unannotated_frame(
        &mut self,
        consume: impl FnOnce(&[u8], RxChecksum) -> bool,
    ) -> BorrowedFrame {
        if self.rx_views.is_none() {
            return BorrowedFrame::Deferred;
        }
        if self.rx_next == self.rx_count && !self.refill_rx_burst() {
            return BorrowedFrame::Empty;
        }
        let index = self.rx_next;
        let view = self.rx_views.as_ref().expect("rx_views checked")[index];
        if view.data.is_null() {
            return BorrowedFrame::Deferred;
        }
        let checksum = match view.l4_status {
            0 => RxChecksum::Unknown,
            1 => RxChecksum::Good,
            _ => return BorrowedFrame::Deferred,
        };
        // SAFETY: `direct_frame` and `receive_check` validated a direct,
        // single-segment, refcnt-1 mbuf of `view.length` initialized bytes at
        // `view.data`, owned exclusively by `self.rx_packets[index]`.
        let bytes = unsafe { std::slice::from_raw_parts(view.data, usize::from(view.length)) };
        if !consume(bytes, checksum) {
            return BorrowedFrame::Deferred;
        }
        self.rx_next += 1;
        // SAFETY: `self.rx_packets[index]` is a direct, single-segment,
        // refcnt-1 mbuf exclusively owned by this adapter, and `bytes` is no
        // longer borrowed.
        unsafe { ntcp_dpdk_frame_free(self.rx_packets[index]) };
        BorrowedFrame::Consumed
    }

    fn rx_frame_budget(&self) -> Option<usize> {
        self.rx_frame_budget
    }

    fn rx_frames_outstanding(&self) -> Option<usize> {
        // SAFETY: the block lives at least as long as the adapter.
        let released = unsafe { self.frames.as_ref() }.released();
        self.rx_frame_budget
            .map(|_| (self.frames_taken - released) as usize)
    }

    fn tx_scheduling_capabilities(&self) -> Option<TxSchedulingCapabilities> {
        self.tx_scheduling.map(|c| TxSchedulingCapabilities {
            clock: c.clock,
            hardware: true,
        })
    }

    fn transmit_at(
        &mut self,
        packet: &[u8],
        when: TransmitTime,
        timestamp: Option<TxTimestampRequest>,
    ) -> io::Result<TxOutcome> {
        if let Some(request) = timestamp {
            return Err(io::Error::new(
                if request.software || request.hardware {
                    io::ErrorKind::Unsupported
                } else {
                    io::ErrorKind::InvalidInput
                },
                "DPDK TX timestamp observations unsupported",
            ));
        }
        let config = self.tx_scheduling.ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "DPDK TX scheduling disabled")
        })?;
        if when.clock != config.clock {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DPDK TX clock mismatch",
            ));
        }
        self.submit(packet, Some(when), 0)
    }

    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        self.submit(packet, None, 0)
    }

    fn tcp_checksum_offload(&self) -> bool {
        self.tx_checksum
    }

    fn transmit_tcp_checksum_offload(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        if !self.tx_checksum {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "DPDK TX TCP checksum offload disabled",
            ));
        }
        let l3 = tcp_frame_l3(packet, packet.len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "not an Ethernet TCP frame")
        })?;
        self.submit(packet, None, l3)
    }

    fn tx_chunk_source(&self) -> Box<dyn TxChunkSource> {
        if self.shared_limit.is_some() {
            Box::new(chunk::DpdkChunkSource::new(chunk::DEFAULT_DPDK_CHUNK_SIZE))
        } else {
            Box::new(HeapChunkSource::default())
        }
    }

    fn transmit_packet(
        &mut self,
        packet: &TxPacket<'_>,
        request: TransmitRequest,
    ) -> Result<TxOutcome, TransmitError> {
        let total_len = packet.checked_len().ok_or(TransmitError::InvalidInput)?;
        let TransmitRequest {
            tcp_checksum_offload,
            segmentation,
            timestamp,
            when,
        } = request;
        if segmentation.is_some() && (timestamp.is_some() || when.is_some()) {
            return Err(TransmitError::Unsupported);
        }
        if tcp_checksum_offload && (timestamp.is_some() || when.is_some()) {
            return Err(TransmitError::Unsupported);
        }
        if timestamp.is_some() {
            return Err(TransmitError::Unsupported);
        }

        let mut offload = TxOffload::default();
        let mut max_descriptors = 0u16;

        if let Some(seg) = segmentation {
            let config = self.tso.ok_or(TransmitError::Unsupported)?;
            if total_len == 0 || total_len > MAX_PACKET_LEN {
                return Err(TransmitError::InvalidInput);
            }
            let caps = self.tcp_segmentation_capabilities().unwrap();
            let (l3, l4) = segmentation::validate_header(
                packet.header,
                total_len,
                seg.segment_payload_len,
                caps,
            )?;
            if config.room < 14 + l3 + l4 {
                return Err(TransmitError::Unsupported);
            }
            offload.l3 = l3;
            offload.l4 = l4;
            offload.mss = seg.segment_payload_len as u16;
            max_descriptors = config.max_descriptors;
        } else if let Some(when) = when {
            let config = self.tx_scheduling.ok_or(TransmitError::Unsupported)?;
            if when.clock != config.clock {
                return Err(TransmitError::InvalidInput);
            }
            if total_len == 0 || total_len > MAX_PACKET_LEN {
                return Err(TransmitError::InvalidInput);
            }
            offload.timestamp_offset = config.offset;
            offload.timestamp_flag = config.flag;
            offload.timestamp = when.value;
        } else if tcp_checksum_offload {
            if !self.tx_checksum {
                return Err(TransmitError::Unsupported);
            }
            if total_len == 0 || total_len > MAX_PACKET_LEN {
                return Err(TransmitError::InvalidInput);
            }
            let l3 =
                tcp_frame_l3(packet.header, total_len).ok_or(TransmitError::InvalidInput)?;
            offload.l3 = l3;
        } else if total_len == 0 || total_len > MAX_PACKET_LEN {
            return Err(TransmitError::InvalidInput);
        }

        let external = self
            .shared_limit
            .filter(|_| total_len - packet.header.len() > self.tx_copybreak)
            .and_then(|limit| {
                self.transmit_external_packet(packet, total_len, &offload, max_descriptors, limit)
            });
        let result = external
            .unwrap_or_else(|| self.transmit_copied_packet(packet, &offload, max_descriptors));

        match result {
            0 => Ok(TxOutcome::WouldBlock),
            1 => Ok(TxOutcome::Submitted),
            NOMBUF => Ok(self.pool_empty()),
            error => Err(map_transmit_shim_error(error)),
        }
    }
}

#[cfg(all(test, feature = "test-pmd"))]
#[path = "scheduling_tests.rs"]
mod scheduling_tests;
