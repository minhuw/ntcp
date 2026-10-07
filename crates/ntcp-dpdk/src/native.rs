use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use std::{ffi::c_void, io, marker::PhantomData, ptr::NonNull, rc::Rc};

/// Maximum complete frame size accepted by the bounded copy shim.
pub const MAX_PACKET_LEN: usize = 65_535;

unsafe extern "C" {
    fn ntcp_dpdk_valid_port(port: u16) -> i32;
    fn ntcp_dpdk_receive(
        port: u16,
        queue: u16,
        out: *mut u8,
        capacity: usize,
        len: *mut usize,
    ) -> i32;
    fn ntcp_dpdk_transmit(
        port: u16,
        queue: u16,
        pool: *mut c_void,
        packet: *const u8,
        len: usize,
    ) -> i32;
}

/// Borrows an already started Ethernet port and its queues. Owns no EAL,
/// devices, pools, or threads. Each operation copies at most one frame.
/// Not Send/Sync: the host must enforce DPDK lcore and queue scheduling rules.
pub struct Dpdk {
    port: u16,
    rx_queue: u16,
    tx_queue: u16,
    pool: NonNull<c_void>,
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
    /// represent RX offload metadata; flagged stripped/coalesced packets are
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
            _local: PhantomData,
        })
    }
}

impl PacketIo for Dpdk {
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ethernet
    }

    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        let mut len = 0;
        // SAFETY: slice is writable; construction guarantees live exclusive queues.
        match unsafe {
            ntcp_dpdk_receive(
                self.port,
                self.rx_queue,
                out.as_mut_ptr(),
                out.len(),
                &mut len,
            )
        } {
            0 => Ok(None),
            1 => Ok(Some(len)),
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
