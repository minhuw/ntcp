#![cfg(target_os = "linux")]

#[cfg(feature = "host")]
mod host;
#[cfg(feature = "host")]
pub use host::{Address, HostedQueue, Port, PortConfig, QueueHandle, Rule, XdpMode};
#[cfg(feature = "host")]
mod ethtool;
#[cfg(feature = "host")]
pub use ethtool::{Rss, RssFields, RssFunction};

use ntcp_io::{
    DeviceCounters, PacketIo, PacketLayer, ReceivedPacket, RxFrame, RxFrameCount, RxFrameVtable,
    TransmitError, TransmitRequest, TxOutcome, TxPacket,
};
use std::{
    io,
    marker::PhantomData,
    mem::{align_of, size_of},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    ptr::{self, NonNull},
    rc::Rc,
    sync::atomic::{AtomicU32, Ordering},
};

const SOL_XDP: i32 = 283;
const XDP_STATISTICS: i32 = 7;
const KERNEL_HEADROOM: u32 = 256;
const COMPLETION_BUDGET: u32 = 64;
const RX_VALIDATION_BUDGET: u32 = 64;

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub ifindex: u32,
    pub queue_id: u32,
    pub frame_size: u32,
    pub frame_count: u32,
    pub ring_size: u32,
    pub headroom: u32,
    // Configured IP-sized copy budget, NOT the live interface MTU.
    // The adapter frame cap adds 14 bytes. A frame also holds the UMEM and
    // kernel headroom, so mtu is at most frame_size - headroom - 270.
    pub mtu: u32,
}

impl Config {
    fn validate(self) -> io::Result<usize> {
        if self.ifindex == 0
            || self.ifindex > i32::MAX as u32
            || !matches!(self.frame_size, 2048 | 4096)
            || !self.frame_count.is_power_of_two()
            || self.frame_count < 2
            || !self.ring_size.is_power_of_two()
            || self.ring_size > self.frame_count / 2
            || self.ring_size > (1 << 29)
            || self.mtu < 68
        {
            return Err(invalid("invalid AF_XDP configuration"));
        }
        // The frame size is valid here, so it exceeds the kernel headroom and
        // the Ethernet header.
        let max_mtu = (self.frame_size - KERNEL_HEADROOM - 14).saturating_sub(self.headroom);
        if self.mtu > max_mtu {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "AF_XDP mtu {} exceeds {max_mtu}: a {}-octet frame holds {} octets of \
                     headroom, {KERNEL_HEADROOM} of kernel headroom and a 14-octet Ethernet \
                     header besides the IP packet",
                    self.mtu, self.frame_size, self.headroom
                ),
            ));
        }
        let bytes = (self.frame_size as usize)
            .checked_mul(self.frame_count as usize)
            .filter(|&n| n <= isize::MAX as usize)
            .ok_or_else(|| invalid("UMEM size overflow"))?;
        Ok(bytes)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn corrupt(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RingOffset {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
}
#[repr(C)]
#[derive(Default)]
struct Offsets {
    rx: RingOffset,
    tx: RingOffset,
    fill: RingOffset,
    completion: RingOffset,
}
#[repr(C)]
struct UmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
    metadata_len: u32,
}
#[repr(C)]
struct SockAddr {
    family: u16,
    flags: u16,
    ifindex: u32,
    queue: u32,
    shared_fd: u32,
}
// struct xdp_statistics (linux/if_xdp.h); kernels before 5.9 fill the
// first three fields only.
#[repr(C)]
#[derive(Default)]
struct XdpStatistics {
    rx_dropped: u64,
    rx_invalid_descs: u64,
    tx_invalid_descs: u64,
    rx_ring_full: u64,
    rx_fill_ring_empty_descs: u64,
    tx_ring_empty_descs: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Descriptor {
    addr: u64,
    len: u32,
    options: u32,
}

struct Mapping {
    ptr: *mut u8,
    len: usize,
}
impl Mapping {
    fn new(fd: RawFd, offset: libc::off64_t, len: usize) -> io::Result<Self> {
        let flags = if fd == -1 {
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS
        } else {
            libc::MAP_SHARED
        };
        // SAFETY: mmap creates a new mapping; ownership is retained until Drop.
        let p = unsafe {
            libc::mmap64(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                fd,
                offset,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { ptr: p.cast(), len })
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: this mapping is exclusively owned and no references escape it.
        unsafe {
            libc::munmap(self.ptr.cast(), self.len);
        }
    }
}

// Frames `receive_frame` handed over and released since the adapter last
// looked, and the UMEM they live in: the block every frame's release
// reaches, freed by the last of the adapter and its frames
// (`RxFrameCount`), so that a frame held past the adapter's drop keeps its
// memory mapped. The released frames' indices form a stack, pushed by
// releases on any thread and taken whole by the adapter (`take`): a stack
// only ever pushed while one consumer swaps it empty has no ABA hazard, as
// a push that finds the top it read links to it whatever happened between.
struct Returns {
    umem: Mapping,
    count: RxFrameCount,
    // The last frame pushed, NO_FRAME for none; `next` links each frame to
    // the one pushed before it.
    top: AtomicU32,
    next: Box<[AtomicU32]>,
}

const NO_FRAME: u32 = u32::MAX;

impl Returns {
    fn new(umem: Mapping, frames: u32) -> NonNull<Self> {
        let next = (0..frames).map(|_| AtomicU32::new(NO_FRAME)).collect();
        NonNull::from(Box::leak(Box::new(Self {
            umem,
            count: RxFrameCount::new(),
            top: AtomicU32::new(NO_FRAME),
            next,
        })))
    }
    // From any thread: frame `index` is back.
    fn push(&self, index: u32) {
        let mut top = self.top.load(Ordering::Relaxed);
        loop {
            self.next[index as usize].store(top, Ordering::Relaxed);
            // Release: the link, and whatever the releaser did with the
            // frame, happen before the adapter's `take` of it.
            match self
                .top
                .compare_exchange_weak(top, index, Ordering::Release, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(current) => top = current,
            }
        }
    }
    // The adapter: the last frame pushed (follow `next`), every one pushed
    // so far with it, and the stack empty.
    fn take(&self) -> u32 {
        if self.top.load(Ordering::Relaxed) == NO_FRAME {
            return NO_FRAME;
        }
        self.top.swap(NO_FRAME, Ordering::Acquire)
    }
}

// The release of a frame `receive_frame` handed over: its index (`token`)
// goes back on the adapter's stack, and the return is counted.
static UMEM_FRAME: RxFrameVtable = RxFrameVtable {
    release: release_frame,
};

// SAFETY (caller): `context` is an adapter's Returns block, given up with
// Box::leak and live until the last of the adapter and its frames frees
// it, and `token` the index of a frame the adapter handed over, released
// once.
unsafe fn release_frame(context: *mut (), token: usize) {
    let block = context.cast::<Returns>();
    // SAFETY: as the caller guarantees; this release is not yet counted.
    let returns = unsafe { &*block };
    returns.push(token as u32);
    if returns.count.release() {
        // SAFETY: the adapter has left and this was its last frame.
        drop(unsafe { Box::from_raw(block) });
    }
}

// The UMEM the adapter maps, in its Returns block, with the frames it
// handed out. Dropped after the socket and its rings (field order): the
// mapping stays until every frame held past the adapter is released.
struct Umem {
    block: NonNull<Returns>,
    taken: u64,
}
impl Umem {
    fn new(umem: Mapping, frames: u32) -> Self {
        Self {
            block: Returns::new(umem, frames),
            taken: 0,
        }
    }
    fn returns(&self) -> &Returns {
        // SAFETY: the block lives at least as long as the adapter.
        unsafe { self.block.as_ref() }
    }
    fn ptr(&self) -> *mut u8 {
        self.returns().umem.ptr
    }
}
impl Drop for Umem {
    fn drop(&mut self) {
        if self.returns().count.leave(self.taken) {
            // SAFETY: nothing was outstanding: no release can reach it.
            drop(unsafe { Box::from_raw(self.block.as_ptr()) });
        }
    }
}

struct Ring<T: Copy> {
    map: Mapping,
    offsets: RingOffset,
    size: u32,
    _entry: PhantomData<T>,
}
impl<T: Copy> Ring<T> {
    fn new(fd: RawFd, page: libc::off64_t, offsets: RingOffset, size: u32) -> io::Result<Self> {
        if !size.is_power_of_two() || size > (1 << 30) {
            return Err(invalid("invalid ring size"));
        }
        let desc = usize::try_from(offsets.desc).map_err(|_| invalid("ring offset overflow"))?;
        let entries_len = (size as usize)
            .checked_mul(size_of::<T>())
            .ok_or_else(|| invalid("ring length overflow"))?;
        let len = desc
            .checked_add(entries_len)
            .filter(|&n| n <= isize::MAX as usize)
            .ok_or_else(|| invalid("ring length overflow"))?;
        let mut regions = vec![(desc, len)];
        for offset in [offsets.producer, offsets.consumer, offsets.flags] {
            let start = usize::try_from(offset).map_err(|_| invalid("ring offset overflow"))?;
            let end = start
                .checked_add(4)
                .ok_or_else(|| invalid("ring offset overflow"))?;
            if start % align_of::<AtomicU32>() != 0 || end > len {
                return Err(invalid("invalid ring control offset"));
            }
            regions.push((start, end));
        }
        if desc % align_of::<T>() != 0 {
            return Err(invalid("unaligned ring descriptors"));
        }
        regions.sort_unstable();
        if regions.windows(2).any(|r| r[0].1 > r[1].0) {
            return Err(invalid("overlapping ring offsets"));
        }
        Ok(Self {
            map: Mapping::new(fd, page, len)?,
            offsets,
            size,
            _entry: PhantomData,
        })
    }
    fn control(&self, offset: u64) -> &AtomicU32 {
        // SAFETY: Ring::new validated bounds/alignment; kernel shares atomic indices only.
        unsafe { &*self.map.ptr.add(offset as usize).cast::<AtomicU32>() }
    }
    fn indices(&self) -> io::Result<(u32, u32)> {
        let producer = self.control(self.offsets.producer).load(Ordering::Acquire);
        let consumer = self.control(self.offsets.consumer).load(Ordering::Acquire);
        if producer.wrapping_sub(consumer) > self.size {
            return Err(corrupt("invalid ring indices"));
        }
        Ok((producer, consumer))
    }
    fn peek(&self) -> io::Result<Option<T>> {
        let (p, c) = self.indices()?;
        if p == c {
            return Ok(None);
        }
        // SAFETY: acquire observed a published descriptor; masked index is in mapping.
        Ok(Some(unsafe { ptr::read_volatile(self.slot(c)) }))
    }
    fn slot(&self, index: u32) -> *mut T {
        // SAFETY: offsets and complete descriptor array validated at construction.
        unsafe {
            self.map
                .ptr
                .add(self.offsets.desc as usize)
                .cast::<T>()
                .add((index & (self.size - 1)) as usize)
        }
    }
    fn consume(&mut self) {
        let c = self.control(self.offsets.consumer).load(Ordering::Relaxed);
        self.control(self.offsets.consumer)
            .store(c.wrapping_add(1), Ordering::Release);
    }
    fn has_space(&self) -> io::Result<bool> {
        let (p, c) = self.indices()?;
        Ok(p.wrapping_sub(c) < self.size)
    }
    fn push(&mut self, value: T) -> io::Result<bool> {
        let (p, c) = self.indices()?;
        if p.wrapping_sub(c) == self.size {
            return Ok(false);
        }
        // SAFETY: unpublished slot is userspace-owned until release publishes it.
        unsafe {
            ptr::write_volatile(self.slot(p), value);
        }
        self.control(self.offsets.producer)
            .store(p.wrapping_add(1), Ordering::Release);
        Ok(true)
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Frame {
    Rx,
    RxValidated,
    // Received and handed over by reference (`receive_frame`) until its
    // release returns it to `free`.
    Held,
    Free,
    Tx,
    Completed,
}

// Validate a fixed, acquire-observed published backlog before recycling any of
// its frames. Frame states retain duplicate detection across budget boundaries.
// This assumes exclusive userspace ring ownership, not an adversarial kernel:
// descriptors published after the snapshot (including future corrupt duplicates)
// are outside this guarantee. The kernel must not mutate published slots.
struct Backlog {
    next: u32,
    end: u32,
}
impl Backlog {
    fn snapshot<T: Copy>(ring: &Ring<T>) -> io::Result<Self> {
        let (end, next) = ring.indices()?;
        Ok(Self { next, end })
    }
}

/// One AF_XDP socket on one queue, its UMEM and rings: copy mode
/// (XDP_COPY). `receive` copies a packet out of its UMEM frame;
/// `receive_frame` hands the frame itself over, released (from any thread,
/// also after the adapter has gone, which keeps its UMEM mapped until the
/// last is back) to the free frames the fill ring and TX take from.
pub struct AfXdp {
    // Fields drop in declaration order: close socket before unmapping rings/UMEM.
    fd: OwnedFd,
    rx: Ring<Descriptor>,
    tx: Ring<Descriptor>,
    fill: Ring<u64>,
    completion: Ring<u64>,
    umem: Umem,
    config: Config,
    frames: Vec<Frame>,
    free: Vec<u32>,
    poisoned: bool,
    rx_backlog: Option<Backlog>,
    completion_backlog: Option<Backlog>,
    // No concurrent or cross-thread ring access is promised by this adapter.
    _not_send_sync: PhantomData<Rc<()>>,
}

fn set_option<T>(fd: RawFd, option: i32, value: &T) -> io::Result<()> {
    // SAFETY: pointer/length refer to initialized UAPI value for this option.
    if unsafe {
        libc::setsockopt(
            fd,
            SOL_XDP,
            option,
            (value as *const T).cast(),
            size_of::<T>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl AfXdp {
    pub fn new(config: Config) -> io::Result<Self> {
        let len = config.validate()?;
        // Allocate before fd: construction failures also close the socket before UMEM.
        let umem = Umem::new(Mapping::new(-1, 0, len)?, config.frame_count);
        // SAFETY: socket returns a new owned fd, checked before wrapping.
        let raw = unsafe {
            libc::socket(
                libc::AF_XDP,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        set_option(
            raw,
            4,
            &UmemReg {
                addr: umem.ptr() as u64,
                len: len as u64,
                chunk_size: config.frame_size,
                headroom: config.headroom,
                flags: 0,
                metadata_len: 0,
            },
        )?;
        // The fill ring holds twice the RX frames (ring_size). The kernel
        // publishes its fill consumer late: after the RX descriptors of a
        // batch (xsk_flush), and only when it refreshes a cached batch, so a
        // received frame's fill entry may still count as unconsumed. A frame
        // has at most one such lagging entry besides its current one, so a
        // received frame can always be refilled.
        let fill_size = config.ring_size * 2;
        for option in [2, 3, 6] {
            set_option(raw, option, &config.ring_size)?;
        }
        set_option(raw, 5, &fill_size)?;
        let mut offsets = Offsets::default();
        let mut size = size_of::<Offsets>() as libc::socklen_t;
        // SAFETY: output buffer has the supplied length.
        if unsafe {
            libc::getsockopt(
                raw,
                SOL_XDP,
                1,
                (&mut offsets as *mut Offsets).cast(),
                &mut size,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if size as usize != size_of::<Offsets>() {
            return Err(invalid("unsupported AF_XDP offsets ABI"));
        }
        let rx = Ring::new(raw, 0, offsets.rx, config.ring_size)?;
        let tx = Ring::new(raw, 0x80000000, offsets.tx, config.ring_size)?;
        let fill = Ring::new(raw, 0x100000000, offsets.fill, fill_size)?;
        let completion = Ring::new(raw, 0x180000000, offsets.completion, config.ring_size)?;
        let address = SockAddr {
            family: libc::AF_XDP as u16,
            flags: 2,
            ifindex: config.ifindex,
            queue: config.queue_id,
            shared_fd: 0,
        };
        // SAFETY: repr(C) sockaddr_xdp with exact UAPI size; force XDP_COPY.
        if unsafe {
            libc::bind(
                raw,
                (&address as *const SockAddr).cast(),
                size_of::<SockAddr>() as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut frames = vec![Frame::Free; config.frame_count as usize];
        frames[..config.ring_size as usize].fill(Frame::Rx);
        let free = (config.ring_size..config.frame_count).collect();
        let mut adapter = Self {
            fd,
            rx,
            tx,
            fill,
            completion,
            umem,
            config,
            frames,
            free,
            poisoned: false,
            rx_backlog: None,
            completion_backlog: None,
            _not_send_sync: PhantomData,
        };
        for index in 0..config.ring_size {
            adapter
                .fill
                .push(u64::from(index) * u64::from(config.frame_size))?;
        }
        Ok(adapter)
    }

    fn data_offset(&self) -> u32 {
        self.config.headroom + KERNEL_HEADROOM
    }
    fn frame(&self, addr: u64, len: u32) -> io::Result<(usize, usize)> {
        let size = u64::from(self.config.frame_size);
        let index = usize::try_from(addr / size).map_err(|_| corrupt("frame index overflow"))?;
        let offset = addr % size;
        if index >= self.frames.len()
            || offset < u64::from(self.data_offset())
            || len == 0
            || len > self.config.mtu + 14
            || offset + u64::from(len) > size
        {
            return Err(corrupt("invalid packet descriptor"));
        }
        Ok((index, addr as usize))
    }

    fn service(&mut self) -> io::Result<()> {
        if self.poisoned {
            return Err(corrupt("AF_XDP adapter poisoned"));
        }
        let result = self.take_returns().and_then(|()| self.reclaim());
        if result.is_err() {
            self.poisoned = true;
        }
        result?;
        self.kick()
    }
    fn reclaim(&mut self) -> io::Result<()> {
        if self.completion_backlog.is_none() {
            self.completion_backlog = Some(Backlog::snapshot(&self.completion)?);
        }
        self.completion.indices()?;
        let mut budget = COMPLETION_BUDGET;
        while budget != 0 {
            let backlog = self.completion_backlog.as_ref().unwrap();
            if backlog.next == backlog.end {
                break;
            }
            // SAFETY: snapshot acquired this published slot; we have not consumed
            // it, so the kernel cannot reuse it while validation is in progress.
            let addr = unsafe { ptr::read_volatile(self.completion.slot(backlog.next)) };
            let (index, _) = self.frame(addr, 1)?;
            if self.frames[index] != Frame::Tx
                || addr % u64::from(self.config.frame_size) != u64::from(self.data_offset())
            {
                return Err(corrupt("invalid TX completion ownership"));
            }
            self.frames[index] = Frame::Completed;
            let backlog = self.completion_backlog.as_mut().unwrap();
            backlog.next = backlog.next.wrapping_add(1);
            budget -= 1;
        }
        let end = self.completion_backlog.as_ref().unwrap().end;
        if self.completion_backlog.as_ref().unwrap().next != end {
            return Ok(());
        }
        // No frame becomes reusable until the entire snapshot is duplicate-free.
        while budget != 0 {
            let (_, consumer) = self.completion.indices()?;
            if consumer == end {
                break;
            }
            let addr = self.completion.peek()?.unwrap();
            let index = (addr / u64::from(self.config.frame_size)) as usize;
            self.completion.consume();
            self.frames[index] = Frame::Free;
            self.free.push(index as u32);
            budget -= 1;
        }
        if self.completion.indices()?.1 == end {
            self.completion_backlog = None;
        }
        Ok(())
    }
    // Frames released since the last look are free again, for TX and for
    // refilling RX. Each returns once: anything else is corruption.
    fn take_returns(&mut self) -> io::Result<()> {
        let returns = self.umem.returns();
        let mut index = returns.take();
        while index != NO_FRAME {
            match self.frames.get_mut(index as usize) {
                Some(frame @ Frame::Held) => *frame = Frame::Free,
                _ => return Err(corrupt("invalid returned frame")),
            }
            self.free.push(index);
            index = returns.next[index as usize].load(Ordering::Relaxed);
        }
        Ok(())
    }
    fn kick(&self) -> io::Result<()> {
        // SAFETY: zero-length sendto is the AF_XDP TX wakeup operation, not a packet.
        if unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                ptr::null(),
                0,
                libc::MSG_DONTWAIT,
                ptr::null(),
                0,
            )
        } < 0
        {
            let error = io::Error::last_os_error();
            if !matches!(
                error.raw_os_error(),
                Some(libc::EAGAIN | libc::ENOBUFS | libc::EBUSY)
            ) {
                return Err(error);
            }
        }
        Ok(())
    }
    // The next received descriptor once its whole snapshot is validated
    // (`Backlog`), not yet consumed: its frame and the frame's offset.
    fn next_rx(&mut self) -> io::Result<Option<(Descriptor, usize, usize)>> {
        if self.rx_backlog.is_none() {
            self.rx_backlog = Some(Backlog::snapshot(&self.rx)?);
        }
        self.rx.indices()?;
        for _ in 0..RX_VALIDATION_BUDGET {
            let backlog = self.rx_backlog.as_ref().unwrap();
            if backlog.next == backlog.end {
                break;
            }
            // SAFETY: acquire-observed snapshot slot remains unconsumed.
            let desc = unsafe { ptr::read_volatile(self.rx.slot(backlog.next)) };
            if desc.options != 0 {
                return Err(corrupt("unsupported RX descriptor options"));
            }
            let (index, _) = self.frame(desc.addr, desc.len)?;
            if self.frames[index] != Frame::Rx {
                return Err(corrupt("invalid or duplicate RX ownership"));
            }
            self.frames[index] = Frame::RxValidated;
            let backlog = self.rx_backlog.as_mut().unwrap();
            backlog.next = backlog.next.wrapping_add(1);
        }
        let backlog = self.rx_backlog.as_ref().unwrap();
        if backlog.next != backlog.end {
            return Ok(None);
        }
        let (_, consumer) = self.rx.indices()?;
        if consumer == backlog.end {
            self.rx_backlog = None;
            return Ok(None);
        }
        let desc = self.rx.peek()?.unwrap();
        let (index, offset) = self.frame(desc.addr, desc.len)?;
        if !self.fill.has_space()? {
            return Err(corrupt("RX refill ring unexpectedly full"));
        }
        Ok(Some((desc, index, offset)))
    }
    // The descriptor `next_rx` returned is consumed.
    fn consume_rx(&mut self) -> io::Result<()> {
        self.rx.consume();
        let end = self.rx_backlog.as_ref().unwrap().end;
        if self.rx.indices()?.1 == end {
            self.rx_backlog = None;
        }
        Ok(())
    }
    fn receive_one(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        let Some((desc, index, offset)) = self.next_rx()? else {
            return Ok(None);
        };
        let len = desc.len as usize;
        let result = if out.len() < len {
            // Drop whole packet, never return a truncated successful receive.
            Err(invalid("receive buffer too short"))
        } else {
            // SAFETY: complete snapshot validated bounds and unique RX ownership
            // before any of its frames were accessed or republished to FILL.
            unsafe {
                ptr::copy_nonoverlapping(self.umem.ptr().add(offset), out.as_mut_ptr(), len);
            }
            Ok(Some(len))
        };
        self.rx.consume();
        self.fill
            .push(index as u64 * u64::from(self.config.frame_size))?;
        self.frames[index] = Frame::Rx;
        if self.rx.indices()?.1 == self.rx_backlog.as_ref().unwrap().end {
            self.rx_backlog = None;
        }
        result
    }
    // The next received frame by reference: its frame is Held, and a free
    // one refills the fill ring in its place. With none free (every frame
    // held, posted or sending), the fill ring runs short, and the kernel
    // counts the packets it then cannot place (`device_counters`).
    fn receive_held(&mut self) -> io::Result<Option<RxFrame>> {
        let Some((desc, index, offset)) = self.next_rx()? else {
            return Ok(None);
        };
        self.consume_rx()?;
        self.frames[index] = Frame::Held;
        if let Some(refill) = self.free.pop() {
            self.fill
                .push(u64::from(refill) * u64::from(self.config.frame_size))?;
            self.frames[refill as usize] = Frame::Rx;
        }
        self.umem.taken += 1;
        // SAFETY: the complete snapshot validated the descriptor's bounds
        // inside one frame and its unique RX ownership; the kernel wrote it
        // and does not again until the frame is in the fill ring, which
        // only `take_returns` after its release allows. The release is
        // sound on any thread at any later time: it pushes the index on the
        // Returns block, which holds the mapping until the last of the
        // adapter and its frames frees it.
        Ok(Some(unsafe {
            RxFrame::from_raw_parts(
                NonNull::new(self.umem.ptr().add(offset)).unwrap(),
                desc.len,
                self.config.frame_size,
                &UMEM_FRAME,
                self.umem.block.as_ptr().cast(),
                index,
            )
        }))
    }
    fn transmit_one(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        self.transmit_parts(
            &TxPacket {
                header: packet,
                payload: &[],
            },
            packet.len(),
        )
    }
    fn transmit_parts(&mut self, packet: &TxPacket<'_>, total: usize) -> io::Result<TxOutcome> {
        if total > self.max_packet_len().unwrap() {
            return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
        }
        if total == 0 {
            return Err(invalid("invalid transmit length"));
        }
        if !self.tx.has_space()? {
            return Ok(TxOutcome::WouldBlock);
        }
        let Some(&index) = self.free.last() else {
            return Ok(TxOutcome::WouldBlock);
        };
        let addr =
            u64::from(index) * u64::from(self.config.frame_size) + u64::from(self.data_offset());
        // SAFETY: free frame is exclusively userspace-owned and `total` fits the frame
        // (Config::validate guarantees data_offset() + max_packet_len() <= frame_size).
        unsafe {
            let mut offset = 0usize;
            let base = self.umem.ptr().add(addr as usize);
            if !packet.header.is_empty() {
                ptr::copy_nonoverlapping(packet.header.as_ptr(), base, packet.header.len());
                offset += packet.header.len();
            }
            for part in packet.payload {
                let bytes = part.bytes();
                if !bytes.is_empty() {
                    ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(offset), bytes.len());
                    offset += bytes.len();
                }
            }
            debug_assert_eq!(offset, total);
        }
        if !self.tx.push(Descriptor {
            addr,
            len: total as u32,
            options: 0,
        })? {
            return Ok(TxOutcome::WouldBlock);
        }
        self.free.pop();
        self.frames[index as usize] = Frame::Tx;
        // Once published, success must be reported even if wakeup fails: retrying
        // would duplicate a submitted packet. The next call retries the wakeup.
        let _ = self.kick();
        Ok(TxOutcome::Submitted)
    }
}
impl AsRawFd for AfXdp {
    // Borrowed fd is for XSKMAP registration and readiness polling only. Caller
    // must not mutate/map rings, concurrently operate or take ownership of the
    // socket, close it, or dup it to extend socket lifetime beyond this adapter:
    // Drop closes the socket before unmapping its registered UMEM and rings.
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
impl PacketIo for AfXdp {
    fn local_ip_mtu(&self) -> io::Result<Option<u32>> {
        ntcp_io::linux::local_ip_mtu(self.config.ifindex)
    }
    fn max_packet_len(&self) -> Option<usize> {
        // Config validation includes Ethernet header and UMEM/kernel headroom.
        Some((self.config.mtu + 14) as usize)
    }

    fn layer(&self) -> PacketLayer {
        PacketLayer::Ethernet
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        self.service()?;
        let result = self.receive_one(out);
        if result
            .as_ref()
            .is_err_and(|e| e.kind() == io::ErrorKind::InvalidData)
        {
            self.poisoned = true;
        }
        result
    }
    // The UMEM frame itself, held until the frame drops (D7: the kernel's
    // XDP_COPY copy remains; holding removes the copy out of the UMEM and
    // the core's heap copy). Its truesize is the frame size.
    fn receive_frame(
        &mut self,
        _scratch: &mut [u8],
        frame: &mut Option<RxFrame>,
    ) -> io::Result<Option<ReceivedPacket>> {
        self.service()?;
        match self.receive_held() {
            Ok(None) => Ok(None),
            Ok(Some(held)) => {
                let len = held.len();
                *frame = Some(held);
                Ok(Some(ReceivedPacket {
                    len,
                    timestamps: Default::default(),
                    tcp_segment_size: None,
                    l4_checksum: Default::default(),
                }))
            }
            Err(error) => {
                if error.kind() == io::ErrorKind::InvalidData {
                    self.poisoned = true;
                }
                Err(error)
            }
        }
    }
    // F: the UMEM less the fill ring's frames and the TX ring's.
    fn rx_frame_budget(&self) -> Option<usize> {
        Some((self.config.frame_count - 2 * self.config.ring_size) as usize)
    }
    fn rx_frames_outstanding(&self) -> Option<usize> {
        Some((self.umem.taken - self.umem.returns().count.released()) as usize)
    }
    // The socket's XDP_STATISTICS: packets it found no fill-ring frame for
    // (rx_fill_ring_empty_descs, how often the kernel found the fill ring
    // empty) as rx_nombuf, and the packets it dropped for want of one or
    // with its RX ring full (rx_dropped plus rx_ring_full, the sum a
    // kernel reports as rx_dropped to a caller of the version 1 struct) as
    // rx_missed. A failed query, or a kernel without the extended struct,
    // leaves what it cannot report zero.
    fn device_counters(&self) -> DeviceCounters {
        let mut stats = XdpStatistics::default();
        let mut size = size_of::<XdpStatistics>() as libc::socklen_t;
        // SAFETY: the output buffer has the supplied length.
        let result = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                SOL_XDP,
                XDP_STATISTICS,
                (&mut stats as *mut XdpStatistics).cast(),
                &mut size,
            )
        };
        if result < 0 {
            return DeviceCounters::default();
        }
        DeviceCounters {
            rx_nombuf: stats.rx_fill_ring_empty_descs,
            rx_missed: stats.rx_dropped + stats.rx_ring_full,
            tx_nombuf: 0,
        }
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        // Reject before service/kick or any descriptor publication.
        if packet.len() > self.max_packet_len().unwrap() {
            return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
        }
        self.service()?;
        let result = self.transmit_one(packet);
        if result
            .as_ref()
            .is_err_and(|e| e.kind() == io::ErrorKind::InvalidData)
        {
            self.poisoned = true;
        }
        result
    }
    // D7: AF_XDP without XDP_USE_SG copies once straight into the UMEM TX
    // frame, avoiding the default transmit_packet's extra Vec gather copy.
    fn transmit_packet(
        &mut self,
        packet: &TxPacket<'_>,
        request: TransmitRequest,
    ) -> Result<TxOutcome, TransmitError> {
        let total = packet.checked_len().ok_or(TransmitError::InvalidInput)?;
        let TransmitRequest {
            tcp_checksum_offload,
            segmentation,
            timestamp,
            when,
        } = request;
        if segmentation.is_some() || tcp_checksum_offload || when.is_some() {
            return Err(TransmitError::Unsupported);
        }
        if let Some(ts) = timestamp {
            return Err(if !ts.software && !ts.hardware {
                TransmitError::InvalidInput
            } else {
                TransmitError::Unsupported
            });
        }
        // Reject before service/kick or any descriptor publication.
        if total > self.max_packet_len().unwrap() {
            return Err(TransmitError::Other(io::Error::from_raw_os_error(
                libc::EMSGSIZE,
            )));
        }
        self.service().map_err(TransmitError::Other)?;
        let result = self.transmit_parts(packet, total);
        if result
            .as_ref()
            .is_err_and(|e| e.kind() == io::ErrorKind::InvalidData)
        {
            self.poisoned = true;
        }
        result.map_err(TransmitError::Other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            ifindex: 1,
            queue_id: 0,
            frame_size: 4096,
            frame_count: 8,
            ring_size: 4,
            headroom: 32,
            mtu: 1500,
        }
    }
    fn ring<T: Copy>(size: u32) -> Ring<T> {
        Ring::new(
            -1,
            0,
            RingOffset {
                producer: 0,
                consumer: 4,
                flags: 8,
                desc: 16,
            },
            size,
        )
        .unwrap()
    }
    fn adapter() -> AfXdp {
        adapter_with_config(config())
    }
    fn adapter_with_config(config: Config) -> AfXdp {
        let len = config.validate().unwrap();
        let umem = Umem::new(Mapping::new(-1, 0, len).unwrap(), config.frame_count);
        // Miri models no sockets; an eventfd stands in for the frame tests,
        // which never wake the socket.
        let raw = if cfg!(miri) {
            unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) }
        } else {
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) }
        };
        assert!(raw >= 0);
        AfXdp {
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
            rx: ring(config.ring_size),
            tx: ring(config.ring_size),
            fill: ring(2 * config.ring_size),
            completion: ring(config.ring_size),
            umem,
            config,
            frames: (0..config.frame_count)
                .map(|i| {
                    if i < config.ring_size {
                        Frame::Rx
                    } else {
                        Frame::Free
                    }
                })
                .collect(),
            free: (config.ring_size..config.frame_count).collect(),
            poisoned: false,
            rx_backlog: None,
            completion_backlog: None,
            _not_send_sync: PhantomData,
        }
    }
    fn large_adapter() -> AfXdp {
        adapter_with_config(Config {
            ring_size: 128,
            frame_count: 256,
            ..config()
        })
    }
    // Connected socket makes the wakeup syscall succeed without a real AF_XDP socket.
    fn wakeup_peer(a: &mut AfXdp) -> OwnedFd {
        let mut pair = [-1; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, pair.as_mut_ptr()) },
            0
        );
        a.fd = unsafe { OwnedFd::from_raw_fd(pair[0]) };
        unsafe { OwnedFd::from_raw_fd(pair[1]) }
    }
    fn inject(a: &mut AfXdp, index: u32, packet: &[u8]) {
        let addr = index as usize * a.config.frame_size as usize + a.data_offset() as usize;
        unsafe {
            ptr::copy_nonoverlapping(packet.as_ptr(), a.umem.ptr().add(addr), packet.len());
        }
        assert!(
            a.rx.push(Descriptor {
                addr: addr as u64,
                len: packet.len() as u32,
                options: 0
            })
            .unwrap()
        );
    }
    // 8 frames, 2 posted to RX and 2 for TX: F = 4.
    fn frame_adapter() -> AfXdp {
        adapter_with_config(Config {
            frame_count: 8,
            ring_size: 2,
            ..config()
        })
    }
    // The fill ring's entries, oldest first, as frame indices.
    fn fill_frames(a: &mut AfXdp) -> Vec<u64> {
        let mut frames = Vec::new();
        while let Some(addr) = a.fill.peek().unwrap() {
            frames.push(addr / u64::from(a.config.frame_size));
            a.fill.consume();
        }
        frames
    }

    #[test]
    fn a_held_frame_is_its_umem_bytes_and_a_free_frame_refills_for_it() {
        let mut a = frame_adapter();
        assert_eq!(a.rx_frame_budget(), Some(4));
        assert_eq!(a.rx_frames_outstanding(), Some(0));
        inject(&mut a, 0, &[42; 100]);
        let frame = a.receive_held().unwrap().unwrap();
        assert_eq!(frame.as_slice(), &[42; 100]);
        let at = a.umem.ptr().wrapping_add(a.data_offset() as usize);
        assert_eq!(
            frame.as_ptr(),
            at.cast_const(),
            "the UMEM itself, not a copy"
        );
        assert_eq!(frame.truesize(), 4096);
        assert!(!frame.is_heap());
        assert!(a.frames[0] == Frame::Held);
        // The last free frame went to the fill ring in its place.
        assert_eq!(fill_frames(&mut a), [7]);
        assert!(a.frames[7] == Frame::Rx);
        assert_eq!(a.free, [2, 3, 4, 5, 6]);
        assert_eq!(a.rx_frames_outstanding(), Some(1));
        assert!(a.receive_held().unwrap().is_none());
        // Back, and free again for TX or a refill once the adapter looks.
        drop(frame);
        assert_eq!(a.rx_frames_outstanding(), Some(0));
        assert!(a.frames[0] == Frame::Held);
        a.take_returns().unwrap();
        assert!(a.frames[0] == Frame::Free);
        assert_eq!(a.free, [2, 3, 4, 5, 6, 0]);
        a.take_returns().unwrap();
        assert_eq!(a.free.len(), 6);
    }

    #[test]
    fn with_every_frame_held_the_fill_ring_runs_short_until_one_returns() {
        let mut a = frame_adapter();
        let mut held = Vec::new();
        // Frames 0 and 1 posted, 2..8 free: every receive refills until
        // the free frames run out.
        let mut posted = vec![0u32, 1];
        for round in 0..8u8 {
            let index = posted.remove(0);
            inject(&mut a, index, &[round; 64]);
            let frame = a.receive_held().unwrap().unwrap();
            assert_eq!(frame.as_slice(), &[round; 64]);
            held.push(frame);
            posted.extend(fill_frames(&mut a).into_iter().map(|f| f as u32));
        }
        assert!(posted.is_empty() && a.free.is_empty());
        assert!(a.frames.iter().all(|f| *f == Frame::Held));
        assert_eq!(a.rx_frames_outstanding(), Some(8));
        // TX finds no frame either: backpressure, as the ring full.
        assert_eq!(a.transmit_one(&[1; 64]).unwrap(), TxOutcome::WouldBlock);
        // Released on another thread; the next look frees them.
        let last = held.pop().unwrap();
        std::thread::spawn(move || drop(held)).join().unwrap();
        assert_eq!(a.rx_frames_outstanding(), Some(1));
        a.take_returns().unwrap();
        assert_eq!(a.free.len(), 7);
        let still = (last.as_ptr() as usize - a.umem.ptr() as usize) / 4096;
        assert!(!a.free.contains(&(still as u32)) && a.frames[still] == Frame::Held);
        assert_eq!(last.as_slice(), &[7; 64]);
        drop(last);
    }

    #[test]
    fn a_frame_held_past_its_adapter_keeps_the_umem_mapped() {
        let mut a = frame_adapter();
        inject(&mut a, 1, &[9; 1500]);
        inject(&mut a, 0, &[8; 60]);
        let first = a.receive_held().unwrap().unwrap();
        let second = a.receive_held().unwrap().unwrap();
        drop(a);
        // The adapter has gone: the frames still read the UMEM, and the
        // last release frees the block with the mapping (Miri checks the
        // leak and the use after free).
        assert_eq!(first.as_slice(), &[9; 1500]);
        drop(first);
        assert_eq!(second.as_slice(), &[8; 60]);
        std::thread::spawn(move || drop(second)).join().unwrap();
        // An adapter that leaves with nothing out frees it itself.
        let mut a = frame_adapter();
        inject(&mut a, 0, &[1; 64]);
        drop(a.receive_held().unwrap().unwrap());
        drop(a);
    }

    // Through PacketIo: each receive first frees what was released, and
    // reports the frame's length. A socket that is not AF_XDP reports no
    // statistics. (Its socket calls are beyond Miri.)
    #[test]
    #[cfg_attr(miri, ignore)]
    fn receive_frame_takes_releases_back_first() {
        let mut a = frame_adapter();
        let _peer = wakeup_peer(&mut a);
        assert_eq!(a.device_counters(), DeviceCounters::default());
        inject(&mut a, 0, &[5; 70]);
        let mut frame = None;
        let metadata = a.receive_frame(&mut [], &mut frame).unwrap().unwrap();
        assert_eq!(metadata.len, 70);
        assert_eq!(frame.as_ref().unwrap().as_slice(), &[5; 70]);
        drop(frame.take());
        assert!(a.receive_frame(&mut [], &mut frame).unwrap().is_none());
        assert!(frame.is_none());
        assert!(a.frames[0] == Frame::Free && a.free.contains(&0));
    }

    #[test]
    fn capacity_is_not_live_mtu_and_oversize_never_publishes() {
        let mut a = adapter();
        // Model rings/UMEM, but query a real loopback interface, not config.mtu.
        a.config.ifindex = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
        assert_ne!(a.config.ifindex, 0);
        assert_eq!(
            a.local_ip_mtu().unwrap(),
            ntcp_io::linux::local_ip_mtu(a.config.ifindex).unwrap()
        );
        assert_eq!(a.max_packet_len(), Some(1514));
        let before = a.tx.indices().unwrap();
        let free = a.free.clone();
        assert_eq!(
            a.transmit(&[0; 1515]).unwrap_err().raw_os_error(),
            Some(libc::EMSGSIZE)
        );
        assert_eq!(a.tx.indices().unwrap(), before);
        assert_eq!(a.free, free);
        assert!(!a.poisoned);
        // Validated jumbo UMEM capacity remains a frame limit, including L2.
        let jumbo = adapter_with_config(Config {
            frame_size: 4096,
            mtu: 3500,
            ..config()
        });
        assert_eq!(jumbo.max_packet_len(), Some(3514));
    }

    #[test]
    fn configuration_and_offset_validation() {
        assert!(config().validate().is_ok());
        for bad in [
            Config {
                ifindex: 0,
                ..config()
            },
            Config {
                frame_count: 3,
                ..config()
            },
            Config {
                ring_size: 8,
                ..config()
            },
            Config {
                ring_size: 0,
                ..config()
            },
            Config {
                headroom: u32::MAX,
                ..config()
            },
            Config {
                mtu: u32::MAX,
                ..config()
            },
            Config {
                frame_size: 1024,
                ..config()
            },
        ] {
            assert!(bad.validate().is_err());
        }
        // The largest IP packet a 4096-octet frame without headroom holds.
        let fits = Config {
            headroom: 0,
            mtu: 3826,
            ..config()
        };
        assert!(fits.validate().is_ok());
        let error = Config { mtu: 3827, ..fits }.validate().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("exceeds 3826"), "{error}");
        let error = Config {
            mtu: 3827,
            ..config()
        }
        .validate()
        .unwrap_err();
        assert!(error.to_string().contains("exceeds 3794"), "{error}");
        for offsets in [
            RingOffset {
                producer: 1,
                consumer: 4,
                flags: 8,
                desc: 16,
            },
            RingOffset {
                producer: 0,
                consumer: 0,
                flags: 8,
                desc: 16,
            },
            RingOffset {
                producer: 0,
                consumer: 4,
                flags: 8,
                desc: 17,
            },
            RingOffset {
                producer: u64::MAX,
                consumer: 4,
                flags: 8,
                desc: 16,
            },
            RingOffset {
                producer: 0,
                consumer: 4,
                flags: 8,
                desc: u64::MAX,
            },
        ] {
            assert!(Ring::<u64>::new(-1, 0, offsets, 4).is_err());
        }
    }
    #[test]
    fn ring_wrap_full_empty_and_corrupt_indices() {
        let mut r = ring::<u64>(4);
        r.control(r.offsets.producer)
            .store(u32::MAX - 1, Ordering::Relaxed);
        r.control(r.offsets.consumer)
            .store(u32::MAX - 1, Ordering::Relaxed);
        for n in 0..4 {
            assert!(r.push(n).unwrap());
        }
        assert!(!r.push(99).unwrap());
        for n in 0..4 {
            assert_eq!(r.peek().unwrap(), Some(n));
            r.consume();
        }
        assert_eq!(r.peek().unwrap(), None);
        assert!(r.push(10).unwrap());
        r.control(r.offsets.producer).store(100, Ordering::Relaxed);
        assert!(r.peek().is_err());
        assert!(r.push(10).is_err());
    }
    #[test]
    fn receive_copy_and_short_buffer_recycles_whole_frame() {
        let mut a = adapter();
        let packet = [42; 100];
        inject(&mut a, 0, &packet);
        assert!(a.receive_one(&mut [0; 99]).is_err());
        assert!(a.rx.peek().unwrap().is_none());
        assert_eq!(a.fill.peek().unwrap(), Some(0));
        a.fill.consume();
        inject(&mut a, 0, &packet);
        let mut out = [0; 128];
        assert_eq!(a.receive_one(&mut out).unwrap(), Some(100));
        assert_eq!(&out[..100], &packet);
        assert_eq!(a.receive_one(&mut out).unwrap(), None);
    }
    #[test]
    fn duplicate_rx_backlog_never_reads_or_refills_and_poison_is_permanent() {
        // Same frame with different legal offsets must still count as duplicate.
        for short_buffer in [false, true] {
            let mut a = adapter();
            let _peer = wakeup_peer(&mut a);
            inject(&mut a, 0, &[42; 64]);
            a.rx.push(Descriptor {
                addr: u64::from(a.data_offset()) + 1,
                len: 63,
                options: 0,
            })
            .unwrap();
            let mut out = vec![73; if short_buffer { 1 } else { 64 }];
            assert_eq!(
                a.receive(&mut out).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert!(out.iter().all(|&b| b == 73));
            assert_eq!(a.rx.indices().unwrap(), (2, 0));
            assert!(a.fill.peek().unwrap().is_none());
            assert!(a.poisoned);
            assert!(a.receive(&mut out).is_err());
            assert!(a.transmit(&[1; 64]).is_err());
            assert_eq!(a.rx.indices().unwrap(), (2, 0));
            assert!(a.fill.peek().unwrap().is_none());
        }
    }
    #[test]
    fn rx_validation_is_bounded_and_detects_duplicates_across_calls() {
        for duplicate in [false, true] {
            let mut a = large_adapter();
            let _peer = wakeup_peer(&mut a);
            for i in 0..RX_VALIDATION_BUDGET {
                inject(&mut a, i, &[42; 64]);
            }
            inject(
                &mut a,
                if duplicate { 0 } else { RX_VALIDATION_BUDGET },
                &[42; 64],
            );
            let mut out = [73; 64];
            assert_eq!(a.receive(&mut out).unwrap(), None);
            assert_eq!(out, [73; 64]);
            assert!(a.fill.peek().unwrap().is_none());
            assert_eq!(a.rx.indices().unwrap(), (65, 0));
            assert!(a.frames[..64].iter().all(|f| *f == Frame::RxValidated));
            assert!(a.frames[64] == Frame::Rx);
            if duplicate {
                assert_eq!(
                    a.receive(&mut out).unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
                assert!(a.poisoned);
                assert_eq!(out, [73; 64]);
                assert!(a.fill.peek().unwrap().is_none());
            } else {
                for _ in 0..65 {
                    assert_eq!(a.receive(&mut out).unwrap(), Some(64));
                    assert_eq!(out, [42; 64]);
                    a.fill.consume();
                }
                assert!(a.rx_backlog.is_none());
                // Reuse is allowed in a subsequent kernel publication/snapshot.
                inject(&mut a, 0, &[17; 64]);
                assert_eq!(a.receive(&mut out).unwrap(), Some(64));
                assert_eq!(out, [17; 64]);
            }
        }
    }
    #[test]
    fn malformed_rx_never_reads_umem_or_recycles() {
        for desc in [
            Descriptor {
                addr: u64::MAX,
                len: 1,
                options: 0,
            },
            Descriptor {
                addr: 0,
                len: 10,
                options: 0,
            },
            Descriptor {
                addr: 4095,
                len: 2,
                options: 0,
            },
            Descriptor {
                addr: 288,
                len: u32::MAX,
                options: 0,
            },
            Descriptor {
                addr: 288,
                len: 0,
                options: 0,
            },
            Descriptor {
                addr: 288,
                len: 1,
                options: 1,
            },
            Descriptor {
                addr: 4 * 4096 + 288,
                len: 1,
                options: 0,
            },
        ] {
            let mut a = adapter();
            a.rx.push(desc).unwrap();
            let mut out = [73; 32];
            assert!(a.receive_one(&mut out).is_err());
            assert_eq!(out, [73; 32]);
            assert!(a.fill.peek().unwrap().is_none());
        }
    }
    #[test]
    fn corrupt_rx_and_fill_indices_fail_before_copy() {
        let mut a = adapter();
        inject(&mut a, 0, &[42; 64]);
        // More fill entries than twice the RX frames: impossible from the kernel.
        for i in 0..8 {
            a.fill.push(i % 4 * 4096).unwrap();
        }
        let mut out = [17; 64];
        assert_eq!(
            a.receive_one(&mut out).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(out, [17; 64]);
        a.fill.consume();
        a.rx.control(a.rx.offsets.producer)
            .store(10, Ordering::Relaxed);
        assert!(a.receive_one(&mut out).is_err());
        assert_eq!(out, [17; 64]);
        a.rx.control(a.rx.offsets.producer)
            .store(1, Ordering::Relaxed);
        a.fill
            .control(a.fill.offsets.consumer)
            .store(100, Ordering::Relaxed);
        assert!(a.receive_one(&mut out).is_err());
        assert_eq!(out, [17; 64]);
    }

    #[test]
    fn received_frame_refills_before_kernel_publishes_fill_consumption() {
        let mut a = adapter();
        // Every RX frame is in the fill ring; the kernel took frame 0 for a
        // packet and published the descriptor, not yet its fill consumption.
        for i in 0..4 {
            a.fill.push(i * 4096).unwrap();
        }
        inject(&mut a, 0, &[42; 64]);
        let mut out = [0; 64];
        assert_eq!(a.receive_one(&mut out).unwrap(), Some(64));
        assert_eq!(out, [42; 64]);
        assert_eq!(a.fill.indices().unwrap(), (5, 0));
        assert!(!a.poisoned);
    }

    #[test]
    fn transmit_backpressure_partial_completions_and_copy() {
        let mut a = adapter();
        let mut packet = [17; 64];
        let free_before = a.free.clone();
        assert!(a.transmit_one(&[]).is_err());
        assert!(a.transmit_one(&[0; 1515]).is_err());
        assert_eq!(a.free, free_before);
        for _ in 0..4 {
            assert_eq!(a.transmit_one(&packet).unwrap(), TxOutcome::Submitted);
        }
        let first = a.tx.peek().unwrap().unwrap();
        packet.fill(99);
        let copy = unsafe { std::slice::from_raw_parts(a.umem.ptr().add(first.addr as usize), 64) };
        assert_eq!(copy, &[17; 64]);
        assert_eq!(a.transmit_one(&packet).unwrap(), TxOutcome::WouldBlock);
        a.tx.consume();
        // TX ring consumed does not release a UMEM frame until completion.
        assert_eq!(a.transmit_one(&packet).unwrap(), TxOutcome::WouldBlock);
        a.completion.push(first.addr).unwrap();
        a.reclaim().unwrap();
        assert_eq!(a.free.len(), 1);
        assert_eq!(a.transmit_one(&packet).unwrap(), TxOutcome::Submitted);
        assert!(a.free.is_empty());
    }
    #[test]
    fn full_tx_ring_does_not_reserve_a_free_frame() {
        let mut a = adapter();
        for _ in 0..4 {
            a.tx.push(Descriptor::default()).unwrap();
        }
        let before = a.free.clone();
        assert_eq!(a.transmit_one(&[1; 64]).unwrap(), TxOutcome::WouldBlock);
        assert_eq!(a.free, before);
    }
    #[test]
    fn malformed_completions_and_duplicate_fail_closed() {
        for addr in [u64::MAX, 288, 4 * 4096 + 289, 4 * 4096] {
            let mut a = adapter();
            a.completion.push(addr).unwrap();
            let free = a.free.clone();
            assert!(a.service().is_err());
            assert!(a.poisoned);
            assert_eq!(a.free, free);
            assert!(a.service().is_err());
        }
        let mut a = adapter();
        a.transmit_one(&[1; 64]).unwrap();
        let addr = a.tx.peek().unwrap().unwrap().addr;
        a.completion.push(addr).unwrap();
        a.completion.push(addr).unwrap();
        assert!(a.reclaim().is_err());
        assert_eq!(a.free.len(), 3, "duplicate snapshot must release no frames");
    }
    #[test]
    fn completion_duplicate_across_budget_prevents_tx_reuse() {
        let mut a = large_adapter();
        let mut duplicate = 0;
        for i in 0..128 {
            assert_eq!(a.transmit_one(&[1; 64]).unwrap(), TxOutcome::Submitted);
            let desc = a.tx.peek().unwrap().unwrap();
            a.tx.consume();
            if i < COMPLETION_BUDGET {
                assert!(a.completion.push(desc.addr).unwrap());
                duplicate = desc.addr;
            }
        }
        assert!(a.completion.push(duplicate).unwrap());
        a.reclaim().unwrap();
        assert!(
            a.free.is_empty(),
            "entire snapshot must be validated before reuse"
        );
        assert!(a.frames[(duplicate / 4096) as usize] == Frame::Completed);
        assert_eq!(a.completion.indices().unwrap(), (65, 0));
        // Before the fix, the last reclaimed frame was immediately reused here;
        // the queued duplicate then freed that new, still-outstanding transmission.
        assert_eq!(a.transmit_one(&[2; 64]).unwrap(), TxOutcome::WouldBlock);
        assert!(a.tx.peek().unwrap().is_none());
        assert_eq!(
            a.transmit(&[2; 64]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(a.poisoned);
        assert!(a.free.is_empty());
        assert!(a.transmit(&[2; 64]).is_err());
    }
    #[test]
    fn completion_roundtrip_allows_reuse_and_new_snapshots() {
        let mut a = adapter();
        let _peer = wakeup_peer(&mut a);
        for byte in 1..=12 {
            let free_before = a.free.len();
            assert_eq!(a.transmit(&[byte; 64]).unwrap(), TxOutcome::Submitted);
            let desc = a.tx.peek().unwrap().unwrap();
            let index = (desc.addr / 4096) as usize;
            assert!(a.frames[index] == Frame::Tx);
            let copy =
                unsafe { std::slice::from_raw_parts(a.umem.ptr().add(desc.addr as usize), 64) };
            assert_eq!(copy, &[byte; 64]);
            a.tx.consume();
            a.completion.push(desc.addr).unwrap();
            a.service().unwrap();
            assert!(a.frames[index] == Frame::Free);
            assert_eq!(a.free.len(), free_before);
            assert!(a.completion_backlog.is_none());
            assert!(a.completion.peek().unwrap().is_none());
        }
    }
    #[test]
    fn completion_service_is_bounded() {
        let mut a = adapter();
        a.config.frame_count = 256;
        a.frames = vec![Frame::Tx; 256];
        a.free.clear();
        a.completion = ring(128);
        for i in 0..100 {
            a.completion.push(i * 4096 + 288).unwrap();
        }
        a.reclaim().unwrap();
        assert!(a.free.is_empty());
        assert_eq!(a.completion.indices().unwrap(), (100, 0));
        assert!(a.frames[..64].iter().all(|f| *f == Frame::Completed));
        assert!(a.frames[64..100].iter().all(|f| *f == Frame::Tx));
        a.reclaim().unwrap();
        assert_eq!(a.free.len(), 28); // 36 validations + 28 releases = 64 work.
        a.reclaim().unwrap();
        assert_eq!(a.free.len(), 92);
        a.reclaim().unwrap();
        assert_eq!(a.free.len(), 100);
        assert!(a.completion_backlog.is_none());
    }
    #[test]
    fn drop_with_inflight_packets_closes_fd() {
        let mut a = adapter();
        a.transmit_one(&[1; 64]).unwrap();
        inject(&mut a, 0, &[2; 64]);
        let mut pair = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    pair.as_mut_ptr(),
                )
            },
            0
        );
        a.fd = unsafe { OwnedFd::from_raw_fd(pair[0]) };
        let peer = unsafe { OwnedFd::from_raw_fd(pair[1]) };
        drop(a);
        let mut byte = 0u8;
        assert_eq!(
            unsafe {
                libc::recv(
                    peer.as_raw_fd(),
                    (&mut byte as *mut u8).cast(),
                    1,
                    libc::MSG_DONTWAIT,
                )
            },
            0
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn transmit_packet_copies_parts_directly_into_umem_and_enforces_i8() {
        use ntcp_io::{
            ChunkSlice, ClockDescriptor, ClockDomain, Payload, PayloadSlice,
            TcpSegmentationRequest, TimestampUnit, TransmitTime, TxChunk, TxPart,
            TxTimestampRequest,
        };

        let mut a = adapter();
        let _peer = wakeup_peer(&mut a);

        let mut chunk = TxChunk::heap(64);
        chunk.append(b"XXchunk-bodyYY");
        let shared = Payload::from_vec(b"ZZshared-tailWW".to_vec());
        let parts = [
            TxPart::Chunk(ChunkSlice::new(&chunk, 0..0).unwrap()),
            TxPart::Chunk(ChunkSlice::new(&chunk, 2..12).unwrap()),
            TxPart::Shared(PayloadSlice::new(&shared, 4..4).unwrap()),
            TxPart::Shared(PayloadSlice::new(&shared, 2..13).unwrap()),
        ];
        let packet = TxPacket {
            header: b"ETH:",
            payload: &parts,
        };
        let expected = b"ETH:chunk-bodyshared-tail";
        let free_before = a.free.len();
        assert_eq!(
            a.transmit_packet(&packet, TransmitRequest::default())
                .unwrap(),
            TxOutcome::Submitted
        );
        assert_eq!(a.free.len(), free_before - 1);
        let desc = a.tx.peek().unwrap().unwrap();
        assert_eq!(desc.len as usize, expected.len());
        assert_eq!(desc.options, 0);
        assert_eq!(
            desc.addr % u64::from(a.config.frame_size),
            u64::from(a.data_offset())
        );
        let index = (desc.addr / u64::from(a.config.frame_size)) as usize;
        assert!(a.frames[index] == Frame::Tx);
        let written = unsafe {
            std::slice::from_raw_parts(a.umem.ptr().add(desc.addr as usize), desc.len as usize)
        };
        assert_eq!(written, expected);

        // Complete the TX frame and verify reuse.
        a.tx.consume();
        a.completion.push(desc.addr).unwrap();
        a.service().unwrap();
        assert!(a.frames[index] == Frame::Free);
        assert_eq!(a.free.len(), free_before);

        // Payload-only packet (empty header).
        let payload_only = TxPacket {
            header: &[],
            payload: &[TxPart::Shared(PayloadSlice::new(&shared, 2..8).unwrap())],
        };
        assert_eq!(
            a.transmit_packet(&payload_only, TransmitRequest::default())
                .unwrap(),
            TxOutcome::Submitted
        );
        let desc = a.tx.peek().unwrap().unwrap();
        let written = unsafe {
            std::slice::from_raw_parts(a.umem.ptr().add(desc.addr as usize), desc.len as usize)
        };
        assert_eq!(written, b"shared");
        a.tx.consume();
        a.completion.push(desc.addr).unwrap();
        a.service().unwrap();

        // Empty packet rejected with InvalidInput (wrapped in Other, matching transmit()).
        let empty = TxPacket {
            header: &[],
            payload: &[TxPart::Chunk(ChunkSlice::new(&chunk, 0..0).unwrap())],
        };
        match a.transmit_packet(&empty, TransmitRequest::default()) {
            Err(TransmitError::Other(e)) => assert_eq!(e.kind(), io::ErrorKind::InvalidInput),
            other => panic!("unexpected result for empty packet: {other:?}"),
        }
        assert!(a.tx.peek().unwrap().is_none());
        assert_eq!(a.free.len(), free_before);

        // Oversize packet rejected with EMSGSIZE before service or publication.
        let big = Payload::from_vec(vec![0xAB; 1500]);
        let oversize = TxPacket {
            header: &[0u8; 15],
            payload: &[TxPart::Shared(PayloadSlice::new(&big, 0..1500).unwrap())],
        };
        let tx_before = a.tx.indices().unwrap();
        let free_snapshot = a.free.clone();
        match a.transmit_packet(&oversize, TransmitRequest::default()) {
            Err(TransmitError::Other(e)) => assert_eq!(e.raw_os_error(), Some(libc::EMSGSIZE)),
            other => panic!("unexpected result for oversize packet: {other:?}"),
        }
        assert_eq!(a.tx.indices().unwrap(), tx_before);
        assert_eq!(a.free, free_snapshot);
        assert!(!a.poisoned);

        // I8 unsupported features & combinations reject without submitting.
        let when = Some(TransmitTime {
            value: 100,
            clock: ClockDescriptor {
                domain: ClockDomain::Monotonic,
                unit: TimestampUnit::Nanoseconds,
            },
        });
        let segmentation = Some(TcpSegmentationRequest {
            segment_payload_len: 10,
        });
        let timestamp = Some(TxTimestampRequest {
            cookie: 7,
            software: true,
            hardware: false,
        });
        let empty_timestamp = Some(TxTimestampRequest {
            cookie: 8,
            software: false,
            hardware: false,
        });
        for unsupported in [
            TransmitRequest {
                segmentation,
                ..Default::default()
            },
            TransmitRequest {
                segmentation,
                when,
                ..Default::default()
            },
            TransmitRequest {
                segmentation,
                timestamp,
                ..Default::default()
            },
            TransmitRequest {
                segmentation,
                timestamp: empty_timestamp,
                ..Default::default()
            },
            TransmitRequest {
                tcp_checksum_offload: true,
                ..Default::default()
            },
            TransmitRequest {
                tcp_checksum_offload: true,
                when,
                ..Default::default()
            },
            TransmitRequest {
                tcp_checksum_offload: true,
                timestamp,
                ..Default::default()
            },
            TransmitRequest {
                tcp_checksum_offload: true,
                timestamp: empty_timestamp,
                ..Default::default()
            },
            TransmitRequest {
                when,
                ..Default::default()
            },
            TransmitRequest {
                when,
                timestamp,
                ..Default::default()
            },
            TransmitRequest {
                timestamp,
                ..Default::default()
            },
        ] {
            assert!(matches!(
                a.transmit_packet(&packet, unsupported),
                Err(TransmitError::Unsupported)
            ));
        }
        assert!(matches!(
            a.transmit_packet(
                &packet,
                TransmitRequest {
                    timestamp: empty_timestamp,
                    ..Default::default()
                }
            ),
            Err(TransmitError::InvalidInput)
        ));
        assert!(a.tx.peek().unwrap().is_none());
        assert_eq!(a.free.len(), free_before);

        // Exhausting free frames yields WouldBlock.
        for _ in 0..free_before {
            assert_eq!(
                a.transmit_packet(&packet, TransmitRequest::default())
                    .unwrap(),
                TxOutcome::Submitted
            );
        }
        assert_eq!(
            a.transmit_packet(&packet, TransmitRequest::default())
                .unwrap(),
            TxOutcome::WouldBlock
        );

        // Poisoned adapter returns Other(InvalidData) on plain transmit_packet.
        a.poisoned = true;
        match a.transmit_packet(&packet, TransmitRequest::default()) {
            Err(TransmitError::Other(e)) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            other => panic!("unexpected result on poisoned adapter: {other:?}"),
        }
    }
}
