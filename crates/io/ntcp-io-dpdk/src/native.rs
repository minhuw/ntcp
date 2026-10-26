use ntcp_io::{
    ClockDescriptor, ClockDomain, PacketIo, PacketLayer, PacketTimestamp, PacketTimestamps,
    ReceivedPacket, TcpSegmentationCapabilities, TcpSegmentationError, TcpSegmentationRequest,
    TimestampCapabilities, TimestampPoint, TimestampSource, TimestampUnit, TransmitTime, TxOutcome,
    TxSchedulingCapabilities, TxTimestampRequest,
};
use std::{ffi::c_void, io, marker::PhantomData, ptr::NonNull, rc::Rc};

/// Maximum complete frame size accepted by the bounded copy shim.
pub const MAX_PACKET_LEN: usize = 65_535;

#[path = "segmentation.rs"]
mod segmentation;
#[path = "shared.rs"]
mod shared;
pub use shared::DpdkBuffer;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TsoConfig {
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
    fn ntcp_dpdk_receive(
        port: u16,
        queue: u16,
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
/// devices, pools, or threads. Each operation submits at most one frame;
/// explicit zero-copy submission retains external payload leases until reclaim.
/// Not Send/Sync: the host must enforce DPDK lcore and queue scheduling rules.
pub struct Dpdk {
    port: u16,
    rx_queue: u16,
    tx_queue: u16,
    pool: NonNull<c_void>,
    tso: Option<TsoConfig>,
    shared_limit: Option<u16>,
    rx_timestamp: Option<TimestampConfig>,
    tx_scheduling: Option<TimestampConfig>,
    _local: PhantomData<Rc<()>>,
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
            tso: None,
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
        let mut config = TsoConfig::default();
        // SAFETY: the host keeps the port, queue and pool live and unchanged.
        let result = unsafe {
            ntcp_dpdk_tso_check(self.port, self.tx_queue, self.pool.as_ptr(), &mut config)
        };
        if result < 0 {
            return Err(io::Error::from_raw_os_error(-result));
        }
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
            max_wire_bytes: MAX_PACKET_LEN + 63 * 74,
            local_ip_mtu: u32::from(c.mtu),
        })
    }

    fn transmit_segmented(
        &mut self,
        packet: &[u8],
        request: TcpSegmentationRequest,
    ) -> Result<TxOutcome, TcpSegmentationError> {
        let config = self.tso.ok_or(TcpSegmentationError::Unsupported)?;
        let caps = self.tcp_segmentation_capabilities().unwrap();
        let l3 = segmentation::validate(packet, request.segment_payload_len, caps)?;
        if usize::from(config.room) < 14 + usize::from(l3) + 20 {
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
        let (mut len, mut timestamp, mut valid) = (0, 0, 0);
        let config = self.rx_timestamp;
        // SAFETY: slice/outputs writable; construction guarantees live exclusive
        // queues. Cached offset/flag were validated against the dynamic registry.
        match unsafe {
            ntcp_dpdk_receive(
                self.port,
                self.rx_queue,
                out.as_mut_ptr(),
                out.len(),
                &mut len,
                config.map_or(-1, |c| c.offset),
                config.map_or(0, |c| c.flag),
                &mut timestamp,
                &mut valid,
            )
        } {
            0 => Ok(None),
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
