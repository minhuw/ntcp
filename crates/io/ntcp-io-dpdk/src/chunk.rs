use ntcp_io::{TxChunk, TxChunkSource, TxChunkVtable};
use std::{
    ffi::c_void,
    ptr::{self, NonNull},
    sync::{Arc, Mutex},
};
#[cfg(all(test, feature = "test-pmd"))]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(all(test, feature = "test-pmd"))]
static LIVE_DPDK_CHUNKS: AtomicUsize = AtomicUsize::new(0);

#[cfg(all(test, feature = "test-pmd"))]
pub(crate) fn live_dpdk_chunks() -> usize {
    LIVE_DPDK_CHUNKS.load(Ordering::SeqCst)
}

unsafe fn free_dpdk_chunk(raw: *mut c_void) {
    #[cfg(all(test, feature = "test-pmd"))]
    LIVE_DPDK_CHUNKS.fetch_sub(1, Ordering::SeqCst);
    // SAFETY: caller guarantees exclusive ownership (refcnt == 0).
    unsafe { ntcp_dpdk_chunk_free(raw) };
}

pub(crate) const DEFAULT_DPDK_CHUNK_SIZE: usize = 16 * 1024;
pub(crate) const CHUNK_RECYCLER_CAP: usize = 64;

type ChunkFreeFn = unsafe extern "C" fn(*mut c_void, *mut c_void);

unsafe extern "C" {
    fn ntcp_dpdk_chunk_alloc(
        capacity: usize,
        recycler: *mut c_void,
        recycle_cb: ChunkFreeFn,
        data_out: *mut *mut u8,
    ) -> *mut c_void;
    fn ntcp_dpdk_chunk_reset(chunk: *mut c_void, recycler: *mut c_void, data_out: *mut *mut u8);
    fn ntcp_dpdk_chunk_release(chunk: *mut c_void);
    fn ntcp_dpdk_chunk_free(chunk: *mut c_void);
    #[cfg(all(test, feature = "test-pmd"))]
    fn ntcp_dpdk_chunk_refcnt(chunk: *const c_void) -> u16;
}

/// Vtable identifying DMA-backed DPDK chunks allocated by [`DpdkChunkSource`].
/// `context` is the `struct ntcp_dpdk_chunk *` pointer; `token` is capacity.
pub(crate) static DPDK_CHUNK_VTABLE: TxChunkVtable = TxChunkVtable {
    release: release_dpdk_chunk,
};

// SAFETY (caller): `context` is a live `struct ntcp_dpdk_chunk *` built by
// `DpdkChunkSource::allocate`, whose owner reference is given up once here.
unsafe fn release_dpdk_chunk(context: *mut (), _token: usize) {
    // SAFETY: decrements the chunk's embedded extbuf refcnt; if no NIC mbuf
    // still references it, invokes `chunk_recycle_cb` on this thread.
    unsafe { ntcp_dpdk_chunk_release(context.cast()) };
}

struct RawChunk(NonNull<c_void>);

// SAFETY: EAL `rte_free` and chunk recycling are thread-safe; a cached chunk
// has refcnt 0 and is exclusively owned by the recycler's free list.
unsafe impl Send for RawChunk {}

struct RecyclerState {
    chunks: Vec<RawChunk>,
    closed: bool,
}

struct ChunkRecycler {
    chunk_size: usize,
    free: Mutex<RecyclerState>,
}

impl Drop for ChunkRecycler {
    fn drop(&mut self) {
        let state = self.free.get_mut().unwrap_or_else(|e| e.into_inner());
        for raw in state.chunks.drain(..) {
            // SAFETY: exclusively owned by the free list; refcnt is 0.
            unsafe { free_dpdk_chunk(raw.0.as_ptr()) };
        }
    }
}

// Invoked from C on any thread (either `DPDK_CHUNK_VTABLE::release` or
// `rte_pktmbuf_free` during NIC TX reclaim) once `chunk->shared.refcnt` hits 0.
// Must never unwind across C FFI.
unsafe extern "C" fn chunk_recycle_cb(chunk: *mut c_void, recycler_raw: *mut c_void) {
    // SAFETY: each live chunk owns one `Arc<ChunkRecycler>` reference created
    // in `DpdkChunkSource::allocate` and transferred here exactly once.
    let recycler = unsafe { Arc::from_raw(recycler_raw.cast::<ChunkRecycler>()) };
    let mut recycled = false;
    if let Some(raw) = NonNull::new(chunk) {
        if let Ok(mut state) = recycler.free.lock()
            && !state.closed
            && state.chunks.len() < CHUNK_RECYCLER_CAP
            && state.chunks.try_reserve(1).is_ok()
        {
            state.chunks.push(RawChunk(raw));
            recycled = true;
        }
        if !recycled {
            // SAFETY: refcnt reached 0 and the chunk was not returned to the
            // free list, so we hold exclusive ownership to free it into EAL.
            unsafe { free_dpdk_chunk(raw.as_ptr()) };
        }
    }
}

/// DMA-backed EAL transmit chunk source with a bounded, lazily populated
/// free-list recycler.
pub(crate) struct DpdkChunkSource {
    recycler: Arc<ChunkRecycler>,
}

impl DpdkChunkSource {
    pub(crate) fn new(chunk_size: usize) -> Self {
        Self {
            recycler: Arc::new(ChunkRecycler {
                chunk_size,
                free: Mutex::new(RecyclerState {
                    chunks: Vec::new(),
                    closed: false,
                }),
            }),
        }
    }

    #[cfg(all(test, feature = "test-pmd"))]
    pub(crate) fn cached_count(&self) -> usize {
        self.recycler
            .free
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .chunks
            .len()
    }
}

impl Drop for DpdkChunkSource {
    fn drop(&mut self) {
        let drained = {
            let mut state = self.recycler.free.lock().unwrap_or_else(|e| e.into_inner());
            state.closed = true;
            std::mem::take(&mut state.chunks)
        };
        for raw in drained {
            // SAFETY: exclusively owned by the free list; refcnt is 0.
            unsafe { free_dpdk_chunk(raw.0.as_ptr()) };
        }
    }
}

impl TxChunkSource for DpdkChunkSource {
    fn chunk_size(&self) -> usize {
        self.recycler.chunk_size
    }

    fn allocate(&mut self) -> Option<TxChunk> {
        let capacity = u32::try_from(self.recycler.chunk_size).ok()?;
        if capacity == 0 {
            return None;
        }
        let cached = self
            .recycler
            .free
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .chunks
            .pop();
        let recycler_raw = Arc::into_raw(Arc::clone(&self.recycler))
            .cast_mut()
            .cast::<c_void>();
        let mut data: *mut u8 = ptr::null_mut();
        let chunk_ptr = if let Some(raw) = cached {
            // SAFETY: popped exclusively from our free list (refcnt was 0);
            // `ntcp_dpdk_chunk_reset` sets `refcnt = 1` and installs the live
            // recycler Arc reference.
            unsafe { ntcp_dpdk_chunk_reset(raw.0.as_ptr(), recycler_raw, &mut data) };
            raw.0.as_ptr()
        } else {
            // SAFETY: EAL is initialized while any `Dpdk` or `DpdkChunkSource`
            // created from it is in use; `ntcp_dpdk_chunk_alloc` validates a
            // contiguous IOVA span and initializes `refcnt = 1`.
            let ptr = unsafe {
                ntcp_dpdk_chunk_alloc(
                    capacity as usize,
                    recycler_raw,
                    chunk_recycle_cb,
                    &mut data,
                )
            };
            if ptr.is_null() {
                // SAFETY: allocation failed; reclaim the Arc reference we
                // minted for the chunk.
                drop(unsafe { Arc::from_raw(recycler_raw.cast::<ChunkRecycler>()) });
                return None;
            }
            #[cfg(all(test, feature = "test-pmd"))]
            LIVE_DPDK_CHUNKS.fetch_add(1, Ordering::SeqCst);
            ptr
        };
        let data = NonNull::new(data)?;
        // SAFETY: `data..data + capacity` is a valid, 64-byte-aligned,
        // contiguous-IOVA EAL buffer owned exclusively by this chunk until
        // filled prefixes are handed to extbuf mbufs; `DPDK_CHUNK_VTABLE`
        // releases the owner reference once from any thread.
        Some(unsafe {
            TxChunk::from_raw_parts(
                data,
                capacity,
                &DPDK_CHUNK_VTABLE,
                chunk_ptr.cast(),
                capacity as usize,
            )
        })
    }
}

#[cfg(all(test, feature = "test-pmd"))]
pub(crate) fn chunk_refcnt(chunk: &TxChunk) -> u16 {
    assert!(core::ptr::eq(chunk.vtable(), &DPDK_CHUNK_VTABLE));
    // SAFETY: `chunk` is live and backed by `struct ntcp_dpdk_chunk`.
    unsafe { ntcp_dpdk_chunk_refcnt(chunk.context().cast()) }
}
