use ntcp_io::{
    ClockDescriptor, ClockDomain, PacketIo, PacketLayer, PacketTimestamp, PacketTimestamps,
    ReceivedPacket, TcpSegmentationCapabilities, TcpSegmentationError, TcpSegmentationRequest,
    TimestampCapabilities, TimestampPoint, TimestampSource, TimestampUnit, TransmitTime, TxOutcome,
    TxSchedulingCapabilities, TxTimestampRequest,
};
use std::{
    ffi::{CStr, c_char, c_void},
    io,
    marker::PhantomData,
    ptr::{self, NonNull},
    rc::Rc,
};

/// Maximum complete frame size accepted by the bounded copy shim.
pub const MAX_PACKET_LEN: usize = 65_535;

// rte_eth_rx_burst requires a count divisible by eight to support every PMD.
// Use the smallest portable burst to bound prefetching for the one-packet API.
const RX_BURST_LEN: usize = 8;

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
    fn ntcp_dpdk_receive_burst(port: u16, queue: u16, packets: *mut *mut c_void, count: u16)
    -> u16;
    fn ntcp_dpdk_packet_free(packet: *mut c_void);
    fn ntcp_dpdk_receive(
        packet: *mut c_void,
        out: *mut u8,
        capacity: usize,
        len: *mut usize,
        timestamp_offset: i32,
        timestamp_flag: u64,
        timestamp: *mut u64,
        timestamp_valid: *mut i32,
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
    rx_next: usize,
    rx_count: usize,
    tso: Option<TsoConfig>,
    // The driver keeps PSH and FIN on an aggregate's last segment only
    // (segmentation::psh_on_last_segment), read with `tso`.
    tso_psh: bool,
    shared_limit: Option<u16>,
    rx_timestamp: Option<TimestampConfig>,
    tx_scheduling: Option<TimestampConfig>,
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
        Ok(Self {
            port,
            rx_queue,
            tx_queue,
            pool,
            rx_packets: [ptr::null_mut(); RX_BURST_LEN],
            rx_next: 0,
            rx_count: 0,
            tso: None,
            tso_psh: false,
            shared_limit: None,
            rx_timestamp: None,
            tx_scheduling: None,
            _local: PhantomData,
        })
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

    fn submit(&mut self, packet: &[u8], when: Option<TransmitTime>) -> io::Result<TxOutcome> {
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
            )
        } {
            0 => Ok(TxOutcome::WouldBlock),
            1 => Ok(TxOutcome::Submitted),
            error => Err(io::Error::from_raw_os_error(-error)),
        }
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
    }
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
        if self.rx_next == self.rx_count {
            self.rx_next = 0;
            // SAFETY: the live queue is exclusively borrowed, and the array can
            // hold the requested burst. Each returned mbuf transfers to us.
            self.rx_count = unsafe {
                ntcp_dpdk_receive_burst(
                    self.port,
                    self.rx_queue,
                    self.rx_packets.as_mut_ptr(),
                    RX_BURST_LEN as u16,
                )
            } as usize;
            if self.rx_count == 0 {
                return Ok(None);
            }
        }
        let packet = std::mem::replace(&mut self.rx_packets[self.rx_next], ptr::null_mut());
        self.rx_next += 1;
        let (mut len, mut timestamp, mut valid) = (0, 0, 0);
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
            )
        } {
            1 => Ok(Some(ReceivedPacket {
                len,
                tcp_segment_size: None,
                timestamps: PacketTimestamps {
                    software: None,
                    hardware: config.filter(|_| valid != 0).map(|c| PacketTimestamp {
                        value: timestamp,
                        source: TimestampSource::Hardware,
                        point: TimestampPoint::DeviceReceive,
                        clock: c.clock,
                    }),
                },
            })),
            error => Err(io::Error::from_raw_os_error(-error)),
        }
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
        self.submit(packet, Some(when))
    }

    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        self.submit(packet, None)
    }
}

#[cfg(all(test, feature = "test-pmd"))]
#[path = "scheduling_tests.rs"]
mod scheduling_tests;
