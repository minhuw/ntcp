#![cfg(target_os = "linux")]

use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use std::{
    io,
    marker::PhantomData,
    mem::{align_of, size_of},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    ptr,
    rc::Rc,
    sync::atomic::{AtomicU32, Ordering},
};

const SOL_XDP: i32 = 283;
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
            || self.ring_size > (1 << 30)
            || self.mtu < 68
            || self
                .headroom
                .checked_add(KERNEL_HEADROOM)
                .and_then(|n| n.checked_add(self.mtu))
                .and_then(|n| n.checked_add(14))
                .is_none_or(|n| n > self.frame_size)
        {
            return Err(invalid("invalid AF_XDP configuration"));
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

pub struct AfXdp {
    // Fields drop in declaration order: close socket before unmapping rings/UMEM.
    fd: OwnedFd,
    rx: Ring<Descriptor>,
    tx: Ring<Descriptor>,
    fill: Ring<u64>,
    completion: Ring<u64>,
    umem: Mapping,
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
        let umem = Mapping::new(-1, 0, len)?;
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
                addr: umem.ptr as u64,
                len: len as u64,
                chunk_size: config.frame_size,
                headroom: config.headroom,
                flags: 0,
                metadata_len: 0,
            },
        )?;
        for option in [2, 3, 5, 6] {
            set_option(raw, option, &config.ring_size)?;
        }
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
        let fill = Ring::new(raw, 0x100000000, offsets.fill, config.ring_size)?;
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
        let result = self.reclaim();
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
    fn receive_one(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
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
        let len = desc.len as usize;
        let result = if out.len() < len {
            // Drop whole packet, never return a truncated successful receive.
            Err(invalid("receive buffer too short"))
        } else {
            // SAFETY: complete snapshot validated bounds and unique RX ownership
            // before any of its frames were accessed or republished to FILL.
            unsafe {
                ptr::copy_nonoverlapping(self.umem.ptr.add(offset), out.as_mut_ptr(), len);
            }
            Ok(Some(len))
        };
        self.rx.consume();
        self.fill
            .push(index as u64 * u64::from(self.config.frame_size))?;
        self.frames[index] = Frame::Rx;
        if self.rx.indices()?.1 == backlog.end {
            self.rx_backlog = None;
        }
        result
    }
    fn transmit_one(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        if packet.is_empty() || packet.len() > (self.config.mtu + 14) as usize {
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
        // SAFETY: free frame is exclusively userspace-owned and packet fits the frame.
        unsafe {
            ptr::copy_nonoverlapping(
                packet.as_ptr(),
                self.umem.ptr.add(addr as usize),
                packet.len(),
            );
        }
        if !self.tx.push(Descriptor {
            addr,
            len: packet.len() as u32,
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
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
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
        let umem = Mapping::new(-1, 0, len).unwrap();
        let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        assert!(raw >= 0);
        AfXdp {
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
            rx: ring(config.ring_size),
            tx: ring(config.ring_size),
            fill: ring(config.ring_size),
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
            ptr::copy_nonoverlapping(packet.as_ptr(), a.umem.ptr.add(addr), packet.len());
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
        for i in 0..4 {
            a.fill.push(i * 4096).unwrap();
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
        let copy = unsafe { std::slice::from_raw_parts(a.umem.ptr.add(first.addr as usize), 64) };
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
                unsafe { std::slice::from_raw_parts(a.umem.ptr.add(desc.addr as usize), 64) };
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
}
