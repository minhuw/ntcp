use ntcp_io::{
    ClockDescriptor, ClockDomain, PacketIo, PacketLayer, PacketTimestamp, PacketTimestamps,
    ReceivedPacket, TimestampCapabilities, TimestampPoint, TimestampSource, TimestampUnit,
    TxOutcome,
};
use std::{ffi::c_void, io, marker::PhantomData, ptr::NonNull, rc::Rc};

/// Maximum complete frame size accepted by the bounded copy shim.
pub const MAX_PACKET_LEN: usize = 65_535;

unsafe extern "C" {
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
    ) -> i32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RxTimestampStatus {
    pub supported: bool,
    // None: the PMD does not expose queue configuration through the stable API.
    pub queue_enabled: Option<bool>,
}

#[derive(Clone, Copy)]
struct RxTimestampConfig {
    clock: ClockDescriptor,
    offset: i32,
    flag: u64,
}

/// Borrows an already started Ethernet port and its queues. Owns no EAL,
/// devices, pools, or threads. Each operation copies at most one frame.
/// Not Send/Sync: the host must enforce DPDK lcore and queue scheduling rules.
pub struct Dpdk {
    port: u16,
    rx_queue: u16,
    tx_queue: u16,
    pool: NonNull<c_void>,
    rx_timestamp: Option<RxTimestampConfig>,
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
    /// their checksums; this adapter requests no checksum/segmentation offloads.
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
            rx_timestamp: None,
            _local: PhantomData,
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
        self.rx_timestamp = Some(RxTimestampConfig {
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

    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        // SAFETY: slice is readable; shim copies it before returning and only
        // transfers allocated mbufs (never the Rust borrow) to the TX driver.
        match unsafe {
            ntcp_dpdk_transmit(
                self.port,
                self.tx_queue,
                self.pool.as_ptr(),
                packet.as_ptr(),
                packet.len(),
            )
        } {
            0 => Ok(TxOutcome::WouldBlock),
            1 => Ok(TxOutcome::Submitted),
            error => Err(io::Error::from_raw_os_error(-error)),
        }
    }
}
