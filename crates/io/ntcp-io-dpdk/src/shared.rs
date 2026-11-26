use super::*;
use crate::host::dpdk_error;
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
    fn ntcp_dpdk_shared_check(
        port: u16,
        queue: u16,
        pool: *mut c_void,
        limit: *mut u16,
        stage: *mut i32,
    ) -> i32;
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
    pub(super) iova: u64,
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
// The error of ntcp_dpdk_shared_check failing with `result` at `stage`
// (shim.c's NTCP_SHARED_*), the segment limit it read for stage 10.
fn shared_check_error(stage: i32, result: i32, limit: u16) -> io::Error {
    if stage == 10 {
        return dpdk_error(
            &format!("tx segment limit {limit} is below 3 (header, payload and pad)"),
            result,
        );
    }
    let context = match stage {
        1 => "rte_eth_dev_info_get",
        2 => "tx queue exceeds the device's queue count",
        3 => "rte_eth_dev_conf_get",
        4 => "rte_eth_tx_queue_info_get",
        5 => "device lacks RTE_ETH_TX_OFFLOAD_MULTI_SEGS",
        6 => "tx queue does not enable RTE_ETH_TX_OFFLOAD_MULTI_SEGS",
        7 => "device reports no tx segment or descriptor limit",
        8 => "tx queue enables RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE",
        9 => "pool data room leaves under 134 octets past headroom",
        11 => "rte_eth_tx_done_cleanup",
        _ => unreachable!("ntcp_dpdk_shared_check stage {stage}"),
    };
    dpdk_error(context, result)
}

pub(super) unsafe extern "C" fn release(lease: *mut c_void) {
    // SAFETY: shim takes each Box exactly once, either on failure or mbuf reclaim.
    // Payload release callbacks are required not to panic across this boundary.
    drop(unsafe { Box::from_raw(lease.cast::<Payload>()) });
}
impl Dpdk {
    /// Validate enabled multi-segment TX, descriptor limits and idle reclaim.
    /// This may reclaim already completed packets. The host keeps port/queue
    /// configuration unchanged; no offload is enabled here. The error names
    /// the check that failed, with its errno.
    pub fn enable_zero_copy(&mut self) -> io::Result<()> {
        let (mut limit, mut stage) = (0, 0);
        // SAFETY: borrowed objects remain live and outputs are writable.
        let result = unsafe {
            ntcp_dpdk_shared_check(
                self.port,
                self.tx_queue,
                self.pool.as_ptr(),
                &mut limit,
                &mut stage,
            )
        };
        if result < 0 {
            return Err(shared_check_error(stage, result, limit));
        }
        // Require at least 3 descriptors: 1 header + 1 payload + 1 Ethernet pad
        // (mirrors ntcp_dpdk_shared_check in shim.c).
        if limit < 3 {
            return Err(io::ErrorKind::Unsupported.into());
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
        self.shared_limit.and_then(|limit| {
            // Reserve one descriptor for headers and one for Ethernet padding;
            // at least one payload segment must remain (matches
            // ntcp_dpdk_shared_check's `limit >= 3` requirement).
            let max_payload_segments = usize::from(limit).checked_sub(2)?;
            (max_payload_segments > 0).then_some(ZeroCopyCapabilities {
                max_payload_segments,
                max_packet_len: MAX_PACKET_LEN,
            })
        })
    }
    pub(super) fn supports_shared(&self, payload: &Payload) -> bool {
        self.shared_capabilities().is_some()
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
            NOMBUF => Ok(self.pool_empty()),
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
    // The ring PMD has no txq_info_get (rte_eth_ring.c's ops).
    let error = io.enable_zero_copy().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert_eq!(
        error.to_string(),
        format!(
            "rte_eth_tx_queue_info_get: {}",
            io::Error::from_raw_os_error(95)
        )
    );
    assert!(io.zero_copy_capabilities().is_none());
    // Limits below 3 (1 header + 1 payload + 1 Ethernet pad) must never
    // underflow and must report zero-copy unavailable.
    for limit in [0u16, 1, 2] {
        io.shared_limit = Some(limit);
        assert_eq!(io.zero_copy_capabilities(), None);
    }
    io.shared_limit = Some(3);
    assert_eq!(
        io.zero_copy_capabilities(),
        Some(ZeroCopyCapabilities {
            max_payload_segments: 1,
            max_packet_len: MAX_PACKET_LEN,
        })
    );
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
            let before = io.device_counters().tx_nombuf;
            unsafe { ntcp_test_hold(leave) };
            assert_eq!(
                io.transmit_zero_copy(&packet).unwrap(),
                TxOutcome::WouldBlock
            );
            assert_eq!(unsafe { ntcp_test_available() }, leave);
            assert_eq!(io.device_counters().tx_nombuf, before + 1);
            unsafe { ntcp_test_release() };
        }
        for _ in 0..7 {
            assert_eq!(
                io.transmit_zero_copy(&packet).unwrap(),
                TxOutcome::Submitted
            );
        }
        let available = unsafe { ntcp_test_available() };
        let before = io.device_counters().tx_nombuf;
        assert_eq!(
            io.transmit_zero_copy(&packet).unwrap(),
            TxOutcome::WouldBlock
        );
        assert_eq!(unsafe { ntcp_test_available() }, available);
        assert_eq!(io.device_counters().tx_nombuf, before); // The ring was full.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_check_error_names_the_check() {
        let (enotsup, einval) = (-95, -22);
        let expected = [
            (1, "rte_eth_dev_info_get"),
            (2, "tx queue exceeds the device's queue count"),
            (3, "rte_eth_dev_conf_get"),
            (4, "rte_eth_tx_queue_info_get"),
            (5, "device lacks RTE_ETH_TX_OFFLOAD_MULTI_SEGS"),
            (6, "tx queue does not enable RTE_ETH_TX_OFFLOAD_MULTI_SEGS"),
            (7, "device reports no tx segment or descriptor limit"),
            (8, "tx queue enables RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE"),
            (9, "pool data room leaves under 134 octets past headroom"),
            (
                10,
                "tx segment limit 2 is below 3 (header, payload and pad)",
            ),
            (11, "rte_eth_tx_done_cleanup"),
        ];
        let unsupported = io::Error::from_raw_os_error(95);
        for (stage, context) in expected {
            let error = shared_check_error(stage, enotsup, 2);
            assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{stage}");
            assert_eq!(error.to_string(), format!("{context}: {unsupported}"));
        }
        // The errno is kept, also where it is not ENOTSUP.
        let error = shared_check_error(2, einval, 0);
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            error.to_string(),
            format!(
                "tx queue exceeds the device's queue count: {}",
                io::Error::from_raw_os_error(22)
            )
        );
    }
}
