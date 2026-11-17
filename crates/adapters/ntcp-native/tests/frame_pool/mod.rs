// FramePool: the in-memory stand-in for a DPDK queue. It wraps a backend
// that copies and receives each packet into one element of a fixed pool, as
// a device receives into posted mbufs, handing the element over by
// reference: a 2368-octet element (a DPDK mbuf's at the default geometry),
// its packet 128 octets in, released back to the pool from any thread. An
// arrival with every element out is dropped and counted, as a device with
// no buffer posted drops it (DeviceCounters::rx_missed). The frame budget
// it reports is set by the test.
#![allow(dead_code)]
use ntcp_io::{
    DeviceCounters, PacketIo, PacketLayer, ReceivedFrame, ReceivedPacket, RxFrame, RxFrameVtable,
    TcpSegmentationCapabilities, TcpSegmentationError, TcpSegmentationRequest, TxCompletion,
    TxOutcome,
};
use std::{
    io,
    ptr::NonNull,
    sync::{Arc, Mutex},
};

pub const ELEMENT: usize = 2368;
const HEADROOM: usize = 128;

struct Element(NonNull<u8>);
// SAFETY: an element is a heap allocation of its own, used by one holder at
// a time: the pool while free, a frame while out.
unsafe impl Send for Element {}

struct Shared {
    free: Mutex<Vec<Element>>,
    elements: usize,
}

impl Drop for Shared {
    fn drop(&mut self) {
        let free = self.free.get_mut().unwrap();
        assert_eq!(free.len(), self.elements, "every element is back");
        for element in free.drain(..) {
            // SAFETY: allocated by Pool::new as a Box<[u8; ELEMENT]>, freed once.
            drop(unsafe { Box::from_raw(element.0.as_ptr().cast::<[u8; ELEMENT]>()) });
        }
    }
}

static POOL_FRAME: RxFrameVtable = RxFrameVtable { release };

// What a frame out holds: its element and a reference on the pool.
type Out = (Arc<Shared>, Element);

// SAFETY (caller): `context` is a Box<Out> given up for this frame.
unsafe fn release(context: *mut (), _token: usize) {
    let (shared, element) = *unsafe { Box::from_raw(context.cast::<Out>()) };
    shared.free.lock().unwrap().push(element);
}

/// The pool alone, for a backend that receives through it
/// (`receive_with`).
pub struct Pool {
    shared: Arc<Shared>,
    budget: usize,
    missed: u64,
}

impl Pool {
    /// `elements` elements, of which consumers may hold `budget`.
    pub fn new(elements: usize, budget: usize) -> Self {
        let free = (0..elements)
            .map(|_| {
                let element = Box::into_raw(Box::new([0u8; ELEMENT]));
                Element(NonNull::new(element.cast::<u8>()).unwrap())
            })
            .collect();
        Self {
            shared: Arc::new(Shared {
                free: Mutex::new(free),
                elements,
            }),
            budget,
            missed: 0,
        }
    }
    /// Elements out now.
    pub fn outstanding(&self) -> usize {
        self.shared.elements - self.shared.free.lock().unwrap().len()
    }
    pub fn budget(&self) -> usize {
        self.budget
    }
    /// Arrivals dropped with every element out.
    pub fn missed(&self) -> u64 {
        self.missed
    }
    /// The next packet `receive` delivers, into a free element and handed
    /// over as its frame; with none free, packets are taken and dropped.
    pub fn receive_with(
        &mut self,
        mut receive: impl FnMut(&mut [u8]) -> io::Result<Option<ReceivedPacket>>,
    ) -> io::Result<Option<ReceivedFrame>> {
        loop {
            let element = self.shared.free.lock().unwrap().pop();
            let Some(element) = element else {
                // No buffer posted: the device drops what arrives.
                let mut drop = vec![0; 65536];
                if receive(&mut drop)?.is_none() {
                    return Ok(None);
                }
                self.missed += 1;
                continue;
            };
            let base = element.0.as_ptr();
            // SAFETY: the element is free, so nothing else reads or writes
            // it; the packet lands past the headroom, within the element.
            let room =
                unsafe { std::slice::from_raw_parts_mut(base.add(HEADROOM), ELEMENT - HEADROOM) };
            let Some(metadata) = receive(room)? else {
                self.shared.free.lock().unwrap().push(element);
                return Ok(None);
            };
            let data = NonNull::new(unsafe { base.add(HEADROOM) }).unwrap();
            let out: Box<Out> = Box::new((self.shared.clone(), element));
            let context = Box::into_raw(out).cast();
            // SAFETY: the element's packet bytes are initialized and stay
            // unchanged until `release` puts the element back, once, from
            // any thread, with its own reference on the pool.
            let frame = unsafe {
                RxFrame::from_raw_parts(
                    data,
                    metadata.len as u32,
                    ELEMENT as u32,
                    &POOL_FRAME,
                    context,
                    0,
                )
            };
            return Ok(Some(ReceivedFrame { frame, metadata }));
        }
    }
}

pub struct FramePool<W> {
    pub inner: W,
    pub pool: Pool,
}

impl<W: PacketIo> FramePool<W> {
    /// `elements` elements, of which consumers may hold `budget`.
    pub fn new(inner: W, elements: usize, budget: usize) -> Self {
        Self {
            inner,
            pool: Pool::new(elements, budget),
        }
    }
    /// Elements out now.
    pub fn outstanding(&self) -> usize {
        self.pool.outstanding()
    }
}

impl<W: PacketIo> PacketIo for FramePool<W> {
    fn layer(&self) -> PacketLayer {
        self.inner.layer()
    }
    fn max_packet_len(&self) -> Option<usize> {
        self.inner
            .max_packet_len()
            .map(|len| len.min(ELEMENT - HEADROOM))
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        self.inner.receive(out)
    }
    fn receive_with_metadata(&mut self, out: &mut [u8]) -> io::Result<Option<ReceivedPacket>> {
        self.inner.receive_with_metadata(out)
    }
    fn receive_frame(&mut self, _scratch: &mut [u8]) -> io::Result<Option<ReceivedFrame>> {
        let inner = &mut self.inner;
        self.pool
            .receive_with(|out| inner.receive_with_metadata(out))
    }
    fn rx_frame_budget(&self) -> Option<usize> {
        Some(self.pool.budget())
    }
    fn rx_frames_outstanding(&self) -> Option<usize> {
        Some(self.outstanding())
    }
    fn device_counters(&self) -> DeviceCounters {
        DeviceCounters {
            rx_missed: self.pool.missed(),
            ..self.inner.device_counters()
        }
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        self.inner.transmit(packet)
    }
    fn tcp_segmentation_capabilities(&self) -> Option<TcpSegmentationCapabilities> {
        self.inner.tcp_segmentation_capabilities()
    }
    fn transmit_segmented(
        &mut self,
        packet: &[u8],
        request: TcpSegmentationRequest,
    ) -> Result<TxOutcome, TcpSegmentationError> {
        self.inner.transmit_segmented(packet, request)
    }
    fn tx_completion(&self) -> TxCompletion {
        self.inner.tx_completion()
    }
    fn tx_submissions_completed(&self) -> u64 {
        self.inner.tx_submissions_completed()
    }
}
