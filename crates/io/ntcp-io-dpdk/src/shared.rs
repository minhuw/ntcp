use super::*;
use ntcp_io::{OwnedPacket, Payload, StablePayloadStorage, ZeroCopyCapabilities};

#[repr(C)]
struct SharedSegment {
    address: *const u8,
    iova: u64,
    length: u16,
    lease: *mut c_void,
}
unsafe extern "C" {
    fn ntcp_dpdk_reclaim(port: u16, queue: u16, budget: u32) -> i32;
    fn ntcp_dpdk_payload_alloc(length: usize, iova: *mut u64) -> *mut u8;
    fn ntcp_dpdk_payload_free(address: *mut u8);
    fn ntcp_dpdk_shared_check(port: u16, queue: u16, pool: *mut c_void, limit: *mut u16) -> i32;
    fn ntcp_dpdk_shared_transmit(
        port: u16,
        queue: u16,
        pool: *mut c_void,
        header: *const u8,
        header_length: u16,
        segments: *const SharedSegment,
        count: u16,
        release: unsafe extern "C" fn(*mut c_void),
    ) -> i32;
}

/// Mutable EAL-allocated memory, frozen into immutable Payload before sending.
/// The unsafe constructor binds its lifetime to the host's EAL/DMA lifetime.
pub struct DpdkBuffer {
    address: NonNull<u8>,
    length: usize,
    iova: u64,
}
impl DpdkBuffer {
    /// # Safety
    /// EAL and its DMA mappings must remain live until this buffer and every
    /// Payload/backend reference derived from it have been released. The host
    /// must map EAL memory for the selected port before using it for DMA.
    pub unsafe fn allocate(length: usize) -> io::Result<Self> {
        let mut iova = 0;
        // SAFETY: caller guarantees EAL lifetime; shim validates a contiguous IOVA span.
        let address = NonNull::new(unsafe { ntcp_dpdk_payload_alloc(length, &mut iova) })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "DPDK payload allocation/mapping failed",
                )
            })?;
        Ok(Self {
            address,
            length,
            iova,
        })
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: exclusive ownership before freeze; allocation is length bytes.
        unsafe { std::slice::from_raw_parts_mut(self.address.as_ptr(), self.length) }
    }
    pub fn freeze(self) -> Payload {
        Payload::new(self)
    }
}
impl AsRef<[u8]> for DpdkBuffer {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: allocation remains live, and shared references allow no mutation.
        unsafe { std::slice::from_raw_parts(self.address.as_ptr(), self.length) }
    }
}
// SAFETY: EAL malloc/free are thread-safe; immutable bytes and mappings stay live
// through ownership. The unsafe constructor requires the host to retain EAL.
unsafe impl Send for DpdkBuffer {}
// SAFETY: the only mutable slice requires exclusive ownership before freezing.
unsafe impl Sync for DpdkBuffer {}
// SAFETY: moving this wrapper never moves its allocation. Payload hides all
// mutation and the allocation/mapping is freed only when the last owner drops.
unsafe impl StablePayloadStorage for DpdkBuffer {}
impl Drop for DpdkBuffer {
    fn drop(&mut self) {
        // SAFETY: original EAL allocation, uniquely owned at final destruction.
        unsafe { ntcp_dpdk_payload_free(self.address.as_ptr()) };
    }
}
unsafe extern "C" fn release(lease: *mut c_void) {
    // SAFETY: shim takes each Box exactly once, either on failure or mbuf reclaim.
    // Payload release callbacks are required not to panic across this boundary.
    drop(unsafe { Box::from_raw(lease.cast::<Payload>()) });
}
impl Dpdk {
    /// Validate enabled multi-segment TX, descriptor limits and idle reclaim.
    /// This may reclaim already completed packets. The host keeps port/queue
    /// configuration unchanged; no offload is enabled here.
    pub fn enable_zero_copy(&mut self) -> io::Result<()> {
        let mut limit = 0;
        // SAFETY: borrowed objects remain live and output is writable.
        let result = unsafe {
            ntcp_dpdk_shared_check(self.port, self.tx_queue, self.pool.as_ptr(), &mut limit)
        };
        if result < 0 {
            return Err(io::Error::from_raw_os_error(-result));
        }
        self.shared_limit = Some(limit);
        Ok(())
    }
    pub(super) fn reclaim_shared(&mut self, budget: usize) -> io::Result<usize> {
        if budget == 0 || self.shared_limit.is_none() {
            return Ok(0);
        }
        // SAFETY: exclusive live borrowed queue. Never pass DPDK's zero/unlimited
        // sentinel. The owner budgets this service alongside RX and timestamps.
        let result = unsafe {
            ntcp_dpdk_reclaim(
                self.port,
                self.tx_queue,
                budget.min(u32::MAX as usize) as u32,
            )
        };
        if result < 0 {
            Err(io::Error::from_raw_os_error(-result))
        } else {
            Ok(result as usize)
        }
    }
    pub(super) fn shared_capabilities(&self) -> Option<ZeroCopyCapabilities> {
        self.shared_limit.map(|limit| ZeroCopyCapabilities {
            // Reserve one descriptor for headers and one for Ethernet padding.
            max_payload_segments: usize::from(limit) - 2,
            max_packet_len: MAX_PACKET_LEN,
        })
    }
    pub(super) fn supports_shared(&self, payload: &Payload) -> bool {
        self.shared_limit.is_some()
            && payload.storage::<DpdkBuffer>().is_some()
            && !payload.is_empty()
    }
    pub(super) fn submit_shared(&mut self, packet: &OwnedPacket) -> io::Result<TxOutcome> {
        let caps = self
            .shared_capabilities()
            .ok_or(io::ErrorKind::Unsupported)?;
        let length = packet.checked_len().ok_or(io::ErrorKind::InvalidInput)?;
        if packet.payload.is_empty()
            || packet.payload.len() > caps.max_payload_segments
            || packet.header.is_empty()
            || packet.header.len() > u16::MAX as usize
            || length > caps.max_packet_len
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if packet.payload.iter().any(|p| !self.supports_shared(p)) {
            return Err(io::ErrorKind::Unsupported.into());
        }
        // Allocate descriptors before transferring any lease to C.
        let mut segments = Vec::new();
        segments
            .try_reserve_exact(packet.payload.len())
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        for payload in &packet.payload {
            let storage = payload.storage::<DpdkBuffer>().unwrap();
            segments.push(SharedSegment {
                address: payload.as_slice().as_ptr(),
                iova: storage.iova + payload.offset() as u64,
                length: payload
                    .len()
                    .try_into()
                    .map_err(|_| io::ErrorKind::InvalidInput)?,
                lease: std::ptr::null_mut(),
            });
        }
        for (segment, payload) in segments.iter_mut().zip(&packet.payload) {
            segment.lease = Box::into_raw(Box::new(payload.clone())).cast();
        }
        // SAFETY: descriptors reference immutable registered allocations; C takes
        // every lease, on all paths. Header is copied, payload bytes are not.
        let result = unsafe {
            ntcp_dpdk_shared_transmit(
                self.port,
                self.tx_queue,
                self.pool.as_ptr(),
                packet.header.as_ptr(),
                packet.header.len() as u16,
                segments.as_ptr(),
                segments.len() as u16,
                release,
            )
        };
        match result {
            0 => Ok(TxOutcome::WouldBlock),
            1 => Ok(TxOutcome::Submitted),
            error => Err(io::Error::from_raw_os_error(-error)),
        }
    }
}

#[cfg(all(test, feature = "test-pmd"))]
pub(super) fn ring_test(io: &mut Dpdk) {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    unsafe extern "C" {
        fn ntcp_test_check_shared(
            first: *const u8,
            first_len: u32,
            second: *const u8,
            second_len: u32,
            header_length: u32,
            total_length: u32,
        );
        fn ntcp_test_available() -> u32;
        fn ntcp_test_hold(leave: u32);
        fn ntcp_test_release();
    }
    assert!(io.enable_zero_copy().is_err()); // ring does not expose queue-info.
    assert!(io.zero_copy_capabilities().is_none());
    // Inject descriptor geometry only in this private test, as for TSO tests.
    // Public opt-in continues to require actual PMD configuration evidence.
    io.shared_limit = Some(8);
    assert_eq!(io.reclaim_transmit(0).unwrap(), 0);
    assert_eq!(
        io.reclaim_transmit(1).unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
    let mut storage = unsafe { DpdkBuffer::allocate(4096) }.unwrap();
    storage.as_mut_slice().fill(0x53);
    let original = storage.as_ref().as_ptr();
    let base = storage.freeze();
    let count = Arc::new(AtomicUsize::new(0));
    for (start, end) in [(1, 14), (97, 397)] {
        let state = count.clone();
        let lease = base.slice(start..end).unwrap().with_release(move || {
            state.fetch_add(1, Ordering::SeqCst);
        });
        let packet = OwnedPacket {
            header: vec![0x42; 34],
            payload: vec![lease],
        };
        assert!(io.zero_copy_payload_supported(&packet.payload[0]));
        assert!(!io.zero_copy_payload_supported(&Payload::from_vec(vec![1])));
        for leave in [0, 1] {
            unsafe { ntcp_test_hold(leave) };
            assert_eq!(
                io.transmit_zero_copy(&packet).unwrap(),
                TxOutcome::WouldBlock
            );
            assert_eq!(unsafe { ntcp_test_available() }, leave);
            unsafe { ntcp_test_release() };
        }
        for _ in 0..7 {
            assert_eq!(
                io.transmit_zero_copy(&packet).unwrap(),
                TxOutcome::Submitted
            );
        }
        let available = unsafe { ntcp_test_available() };
        assert_eq!(
            io.transmit_zero_copy(&packet).unwrap(),
            TxOutcome::WouldBlock
        );
        assert_eq!(unsafe { ntcp_test_available() }, available);
        let prior = count.load(Ordering::SeqCst);
        drop(packet); // all remaining per-send leases now belong to real mbufs.
        for i in 0..7 {
            assert_eq!(count.load(Ordering::SeqCst), prior);
            unsafe {
                ntcp_test_check_shared(
                    original.add(start),
                    (end - start) as u32,
                    std::ptr::null(),
                    0,
                    34,
                    (34 + end - start) as u32,
                )
            };
            assert_eq!(count.load(Ordering::SeqCst), prior + usize::from(i == 6));
        }
        assert_eq!(unsafe { ntcp_test_available() }, 1023);
    }
    assert_eq!(count.load(Ordering::SeqCst), 2);
    assert_eq!(base.as_slice().as_ptr(), original);
    let state = count.clone();
    let lease = base.clone().with_release(move || {
        state.fetch_add(1, Ordering::SeqCst);
    });
    let packet = OwnedPacket {
        header: vec![0x42; 34],
        payload: vec![lease.slice(3..16).unwrap(), lease.slice(100..107).unwrap()],
    };
    assert_eq!(
        io.transmit_zero_copy(&packet).unwrap(),
        TxOutcome::Submitted
    );
    drop(packet);
    drop(lease);
    assert_eq!(count.load(Ordering::SeqCst), 2);
    unsafe { ntcp_test_check_shared(original.add(3), 13, original.add(100), 7, 34, 54) };
    assert_eq!(count.load(Ordering::SeqCst), 3);
    assert_eq!(unsafe { ntcp_test_available() }, 1023);
    io.shared_limit = None;
}
