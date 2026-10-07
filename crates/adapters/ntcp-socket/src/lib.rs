#![cfg(target_os = "linux")]
#![allow(clippy::missing_safety_doc)]
// Linux preload boundary. Native cancellation points tail-jump through C to
// libc; internal runtime syscalls avoid recursion. Tokens carry no payload.
use libc::*;
use std::{
    cell::Cell,
    collections::BTreeMap,
    ffi::CStr,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicI32, AtomicUsize, Ordering},
    },
};
macro_rules! boundary_entry {
    ($name:ident, $target:literal, ($($arg:ident: $ty:ty),*) -> $ret:ty) => {
        #[unsafe(no_mangle)]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name($($arg: $ty),*) -> $ret {
            #[cfg(target_arch = "x86_64")]
            core::arch::naked_asm!(concat!("jmp ", $target));
            #[cfg(target_arch = "aarch64")]
            core::arch::naked_asm!(concat!("b ", $target));
        }
    };
}

mod readiness;
mod runtime;
mod stdio;
use runtime::{Op, Reply, Runtime};
type Result<T> = std::result::Result<T, i32>;
thread_local! {
    static INTERNAL: Cell<bool> = const { Cell::new(false) };
    static DEPTH: Cell<usize> = const { Cell::new(0) };
    static NATIVE_MUTATION: Cell<usize> = const { Cell::new(0) };
}
unsafe extern "C" {
    fn ntcp_set_internal(value: i32);
}
fn set_internal(value: bool) -> bool {
    unsafe { ntcp_set_internal(value as i32) };
    INTERNAL.with(|v| v.replace(value))
}
static PID: AtomicI32 = AtomicI32::new(0);
static RUNTIME: OnceLock<Result<Runtime>> = OnceLock::new();
static SOCKET_FDS: [AtomicI32; runtime::LIMIT] = [const { AtomicI32::new(-1) }; runtime::LIMIT];
fn inherited(fds: &[AtomicI32], fd: i32) -> bool {
    fd >= 0 && fds.iter().any(|slot| slot.load(Ordering::Acquire) == fd)
}
fn reserve_fd(fds: &[AtomicI32], fd: i32) -> Result<usize> {
    fds.iter()
        .position(|slot| {
            slot.compare_exchange(-1, fd, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        })
        .ok_or(EMFILE)
}
static TOKENS: Mutex<BTreeMap<i32, Token>> = Mutex::new(BTreeMap::new());
// Native close/dup use an atomic read-side guard, never a registry lock. A
// writer pins classification through the syscall and alias publication.
// ponytail: one mutation gate; shard by target fd if contention matters.
static FD_MUTATION: AtomicI32 = AtomicI32::new(0);
struct NativeMutation;
impl NativeMutation {
    fn enter() -> Option<Self> {
        // Constant TLS, no allocation: a managed signal-handler mutation must
        // not wait for the native syscall it interrupted on this same thread.
        NATIVE_MUTATION.with(|depth| depth.set(depth.get() + 1));
        let mut n = FD_MUTATION.load(Ordering::Acquire);
        while n >= 0 {
            match FD_MUTATION.compare_exchange_weak(n, n + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(Self),
                Err(value) => n = value,
            }
        }
        NATIVE_MUTATION.with(|depth| depth.set(depth.get() - 1));
        None
    }
}
impl Drop for NativeMutation {
    fn drop(&mut self) {
        FD_MUTATION.fetch_sub(1, Ordering::Release);
        NATIVE_MUTATION.with(|depth| depth.set(depth.get() - 1));
    }
}
struct Mutation;
impl Mutation {
    // Caller holds TOKENS; readers never acquire it while holding their guard.
    fn enter() -> Self {
        while FD_MUTATION
            .compare_exchange(0, -1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            std::hint::spin_loop();
        }
        Self
    }
}
impl Drop for Mutation {
    fn drop(&mut self) {
        FD_MUTATION.store(0, Ordering::Release);
    }
}
fn mutation_context() -> Result<()> {
    if DEPTH.with(Cell::get) > 1 || INTERNAL.with(Cell::get) || NATIVE_MUTATION.with(Cell::get) != 0
    {
        Err(EDEADLK)
    } else if child() {
        Err(EOWNERDEAD)
    } else {
        Ok(())
    }
}
#[cfg(test)]
thread_local! {
    static CLOSE_BEFORE_LOCK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static DUP_BEFORE_LOCK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static DUP_AFTER_KERNEL: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
struct Token {
    slot: Option<usize>,
    id: u64,
    retained: Arc<Retained>,
    dev: dev_t,
    ino: ino_t,
    input: Arc<Input>,
}
#[derive(Default)]
struct Input {
    bytes: Mutex<Vec<u8>>,
    ready: AtomicUsize,
}
impl Token {
    fn matches(&self, fd: i32) -> bool {
        let mut st: stat = unsafe { std::mem::zeroed() };
        unsafe {
            syscall(SYS_fstat, fd, &mut st) == 0 && st.st_dev == self.dev && st.st_ino == self.ino
        }
    }
}
struct Retained(i32);
impl Drop for Retained {
    fn drop(&mut self) {
        unsafe {
            syscall(SYS_close, self.0);
        }
    }
}
impl Drop for Token {
    fn drop(&mut self) {
        if let Some(slot) = self.slot {
            SOCKET_FDS[slot].store(-1, Ordering::Release);
        }
    }
}
fn errno() -> i32 {
    unsafe { *__errno_location() }
}
fn env(name: &str) -> Option<String> {
    let name = std::ffi::CString::new(name).ok()?;
    unsafe {
        let p = getenv(name.as_ptr());
        (!p.is_null()).then(|| CStr::from_ptr(p).to_string_lossy().into_owned())
    }
}
fn configured() -> bool {
    env("NTCP_SOCKET_TUN").is_some() || env("NTCP_SOCKET_ADDR").is_some()
}
fn child() -> bool {
    let pid = PID.load(Ordering::Acquire);
    pid != 0 && pid != unsafe { syscall(SYS_getpid) as i32 }
}
fn runtime() -> Result<&'static Runtime> {
    if child() {
        return Err(EOWNERDEAD);
    }
    PID.compare_exchange(
        0,
        unsafe { syscall(SYS_getpid) as i32 },
        Ordering::AcqRel,
        Ordering::Acquire,
    )
    .ok();
    RUNTIME
        .get_or_init(|| {
            let old = set_internal(true);
            let result = catch_unwind(Runtime::start).unwrap_or(Err(EIO));
            set_internal(old);
            result
        })
        .as_ref()
        .map_err(|e| *e)
}
fn owned(fd: i32) -> Result<Option<u64>> {
    // Native signal-handler I/O must not touch TLS, allocate, or acquire a lock.
    if !inherited(&SOCKET_FDS, fd) {
        return Ok(None);
    }
    if DEPTH.with(Cell::get) > 1 || INTERNAL.with(Cell::get) {
        return Err(EDEADLK);
    }
    // Check before touching a lock inherited from a vanished fork thread.
    if child() {
        return if inherited(&SOCKET_FDS, fd) {
            Err(EOWNERDEAD)
        } else {
            Ok(None)
        };
    }
    let mut tokens = TOKENS.lock().map_err(|_| EIO)?;
    if let Some(t) = tokens.get(&fd) {
        if t.matches(fd) {
            return Ok(Some(t.id));
        }
        let last = remove_alias(&mut tokens, fd);
        drop(tokens);
        let _ = finish_close(last);
    }
    Ok(None)
}
fn call(id: u64, op: Op) -> Result<Reply> {
    let buffered = if matches!(op, Op::Ready | Op::Available) {
        TOKENS
            .lock()
            .map_err(|_| EIO)?
            .values()
            .find(|t| t.id == id)
            .map_or(0, |t| t.input.ready.load(Ordering::Acquire))
    } else {
        0
    };
    let available = matches!(op, Op::Available);
    let ready = matches!(op, Op::Ready);
    let mut reply = runtime()?.call(id, op)?;
    if available {
        reply.value += buffered as i32;
    }
    if ready && buffered != 0 {
        reply.value |= EPOLLIN;
    }
    Ok(reply)
}
fn ffi(f: impl FnOnce() -> Result<i64>) -> i64 {
    struct Depth;
    impl Drop for Depth {
        fn drop(&mut self) {
            DEPTH.with(|d| d.set(d.get() - 1));
        }
    }
    DEPTH.with(|d| d.set(d.get() + 1));
    let _depth = Depth;
    match catch_unwind(AssertUnwindSafe(f)).unwrap_or(Err(EIO)) {
        Ok(n) => n,
        Err(e) => {
            unsafe {
                *__errno_location() = e;
            }
            -1
        }
    }
}
fn raw(n: c_long) -> Result<i64> {
    if n < 0 { Err(errno()) } else { Ok(n) }
}
// All application memory crosses the kernel's fault-reporting boundary. Never
// form a Rust reference/slice from a foreign pointer (even when non-null).
fn memory(local: *mut u8, remote: *mut u8, len: usize, write: bool) -> Result<()> {
    if len == 0 {
        return Ok(());
    }
    (remote as usize)
        .checked_add(len)
        .filter(|&n| n <= isize::MAX as usize)
        .ok_or(EFAULT)?;
    let local = iovec {
        iov_base: local.cast(),
        iov_len: len,
    };
    let remote = iovec {
        iov_base: remote.cast(),
        iov_len: len,
    };
    let n = unsafe {
        syscall(
            if write {
                SYS_process_vm_writev
            } else {
                SYS_process_vm_readv
            },
            syscall(SYS_getpid),
            &local,
            1usize,
            &remote,
            1usize,
            0usize,
        )
    };
    if n < 0 {
        return Err(errno());
    }
    if n as usize != len {
        return Err(EFAULT);
    }
    Ok(())
}
fn copy_in(p: *const u8, out: &mut [u8]) -> Result<()> {
    memory(out.as_mut_ptr(), p.cast_mut(), out.len(), false)
}
fn copy_out(p: *mut u8, bytes: &[u8]) -> Result<()> {
    memory(bytes.as_ptr().cast_mut(), p, bytes.len(), true)
}
// T is a C ABI POD type at each call site below, with no invalid bit patterns.
fn load<T: Copy>(p: *const T) -> Result<T> {
    let mut value = std::mem::MaybeUninit::<T>::uninit();
    memory(
        value.as_mut_ptr().cast(),
        p.cast_mut().cast(),
        std::mem::size_of::<T>(),
        false,
    )?;
    Ok(unsafe { value.assume_init() })
}
fn store<T: Copy>(p: *mut T, value: &T) -> Result<()> {
    memory(
        (value as *const T).cast_mut().cast(),
        p.cast(),
        std::mem::size_of::<T>(),
        true,
    )
}
fn load_array<T: Copy>(p: *const T, n: usize, cap: usize) -> Result<Vec<T>> {
    if n > cap {
        return Err(EINVAL);
    }
    let len = n.checked_mul(std::mem::size_of::<T>()).ok_or(EINVAL)?;
    let mut out = Vec::<T>::with_capacity(n);
    memory(out.as_mut_ptr().cast(), p.cast_mut().cast(), len, false)?;
    unsafe {
        out.set_len(n);
    }
    Ok(out)
}
fn store_array<T: Copy>(p: *mut T, values: &[T]) -> Result<()> {
    memory(
        values.as_ptr().cast_mut().cast(),
        p.cast(),
        std::mem::size_of_val(values),
        true,
    )
}
// Keep at most BYTES staged bytes per socket until every requested copyout
// succeeds. Partial foreign-memory writes may occur, but a failed read consumes
// no staged stream bytes. Serialize concurrent readers without holding TOKENS.
fn read_into(
    fd: i32,
    id: u64,
    n: usize,
    flags: i32,
    output: impl FnOnce(&[u8]) -> Result<()>,
) -> Result<i64> {
    let deadline = Deadline::socket(id, false, flags & MSG_DONTWAIT != 0)?;
    let input = TOKENS
        .lock()
        .map_err(|_| EIO)?
        .get(&fd)
        .filter(|t| t.id == id)
        .ok_or(EBADF)?
        .input
        .clone();
    let mut bytes = loop {
        match input.bytes.try_lock() {
            Ok(bytes) => break bytes,
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(EIO),
            Err(std::sync::TryLockError::WouldBlock) => {
                if flags & MSG_DONTWAIT != 0 || !blocking(id)? {
                    return Err(EAGAIN);
                }
                wait_until(id, EPOLLIN, &deadline)?;
                std::thread::yield_now();
            }
        }
    };
    if n == 0 {
        call(id, Op::Read(0))?;
        output(&[])?;
        return Ok(0);
    }
    if flags & MSG_PEEK != 0 && bytes.is_empty() {
        let reply = retry_until(
            id,
            Op::Peek(n.min(runtime::BYTES)),
            flags & MSG_DONTWAIT != 0,
            EPOLLIN,
            &deadline,
        )?;
        output(&reply.bytes)?;
        return Ok(reply.bytes.len() as i64);
    }
    if bytes.is_empty() {
        *bytes = retry_until(
            id,
            Op::Read(n.min(runtime::BYTES)),
            flags & MSG_DONTWAIT != 0,
            EPOLLIN,
            &deadline,
        )?
        .bytes;
        input.ready.store(bytes.len(), Ordering::Release);
    }
    let n = n.min(bytes.len());
    output(&bytes[..n])?;
    if flags & MSG_PEEK == 0 {
        bytes.drain(..n);
    }
    input.ready.store(bytes.len(), Ordering::Release);
    Ok(n as i64)
}
fn token(flags: i32) -> Result<(i32, Token)> {
    let fd = unsafe {
        syscall(
            SYS_socket,
            AF_UNIX,
            SOCK_STREAM | (flags & (SOCK_NONBLOCK | SOCK_CLOEXEC)),
            0,
        ) as i32
    };
    if fd < 0 {
        return Err(errno());
    }
    let retained = unsafe { syscall(SYS_fcntl, fd, F_DUPFD_CLOEXEC, 0) as i32 };
    let mut st: stat = unsafe { std::mem::zeroed() };
    if retained < 0 || unsafe { syscall(SYS_fstat, fd, &mut st) } < 0 {
        let e = errno();
        unsafe {
            syscall(SYS_close, fd);
            if retained >= 0 {
                syscall(SYS_close, retained);
            }
        }
        return Err(e);
    }
    Ok((
        fd,
        Token {
            slot: None,
            id: 0,
            retained: Arc::new(Retained(retained)),
            dev: st.st_dev,
            ino: st.st_ino,
            input: Arc::new(Input::default()),
        },
    ))
}
fn install(fd: i32, mut t: Token, id: u64) -> Result<i64> {
    let result = (|| {
        t.id = id;
        t.slot = Some(reserve_fd(&SOCKET_FDS, fd)?);
        TOKENS.lock().map_err(|_| EIO)?.insert(fd, t);
        Ok(fd as i64)
    })();
    if result.is_err() {
        unsafe {
            syscall(SYS_close, fd);
        }
        let _ = call(id, Op::Close);
    }
    result
}
fn blocking(id: u64) -> Result<bool> {
    Ok(call(id, Op::Flags(F_GETFL, 0))?.value & O_NONBLOCK == 0)
}
// Use an elapsed budget rather than Instant + duration: every finite u64
// microsecond timeout remains representable, even beyond Instant's range.
struct Deadline {
    start: std::time::Instant,
    budget: Option<std::time::Duration>,
}
impl Deadline {
    fn socket(id: u64, send: bool, dontwait: bool) -> Result<Self> {
        let start = std::time::Instant::now();
        let micros = if dontwait {
            0
        } else {
            call(id, Op::GetTimeout(send))?.timeout_us
        };
        Ok(Self {
            start,
            budget: (micros != 0).then(|| std::time::Duration::from_micros(micros)),
        })
    }
    fn poll_ms(&self) -> Result<i32> {
        match self.budget {
            None => Ok(10),
            Some(budget) => {
                let left = budget.checked_sub(self.start.elapsed()).ok_or(EAGAIN)?;
                if left.is_zero() {
                    return Err(EAGAIN);
                }
                Ok(left.as_millis().saturating_add(1).min(10) as i32)
            }
        }
    }
}
fn wait_until(id: u64, events: i32, deadline: &Deadline) -> Result<()> {
    loop {
        let ms = deadline.poll_ms()?;
        if call(id, Op::Ready)?.value & (events | EPOLLERR | EPOLLHUP) != 0 {
            return Ok(());
        }
        let mut p = pollfd {
            fd: runtime()?.wake,
            events: POLLIN,
            revents: 0,
        };
        raw(unsafe { syscall(SYS_poll, &mut p, 1, ms) })?;
        drain_wake();
    }
}
fn drain_wake() {
    if let Some(Ok(r)) = RUNTIME.get() {
        let mut n = 0u64;
        unsafe {
            syscall(SYS_read, r.wake, &mut n, 8);
        }
    }
}
fn retry(id: u64, op: Op, dontwait: bool, events: i32) -> Result<Reply> {
    let deadline = Deadline::socket(id, events == EPOLLOUT, dontwait)?;
    retry_until(id, op, dontwait, events, &deadline)
}
fn retry_until(id: u64, op: Op, dontwait: bool, events: i32, deadline: &Deadline) -> Result<Reply> {
    loop {
        match call(id, op.clone()) {
            Err(EAGAIN) if !dontwait && blocking(id)? => wait_until(id, events, deadline)?,
            r => return r,
        }
    }
}
unsafe fn address(p: *const sockaddr, len: socklen_t) -> Result<SocketAddr> {
    if p.is_null() {
        return Err(EFAULT);
    }
    if len < std::mem::size_of::<sockaddr_in>() as u32 {
        return Err(EINVAL);
    }
    let p = load(p.cast::<sockaddr_in>())?;
    if p.sin_family as i32 != AF_INET {
        return Err(EAFNOSUPPORT);
    }
    Ok(SocketAddr::new(
        Ipv4Addr::from(p.sin_addr.s_addr.to_ne_bytes()).into(),
        u16::from_be(p.sin_port),
    ))
}
unsafe fn output_addr(addr: SocketAddr, p: *mut sockaddr, len: *mut socklen_t) -> Result<()> {
    if p.is_null() {
        return Ok(());
    }
    if len.is_null() {
        return Err(EFAULT);
    }
    let IpAddr::V4(ip) = addr.ip() else {
        return Err(EAFNOSUPPORT);
    };
    let addr = sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: addr.port().to_be(),
        sin_addr: in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_zero: [0; 8],
    };
    let size = std::mem::size_of::<sockaddr_in>();
    let n = (load(len)? as usize).min(size);
    memory(
        (&addr as *const sockaddr_in).cast_mut().cast(),
        p.cast(),
        n,
        true,
    )?;
    store(len, &(size as u32))?;
    Ok(())
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_socket(domain: i32, kind: i32, protocol: i32) -> i32 {
    ffi(|| {
        if INTERNAL.with(Cell::get)
            || !configured()
            || ![AF_INET, AF_INET6].contains(&domain)
            || kind & 0xf != SOCK_STREAM
        {
            return raw(unsafe { syscall(SYS_socket, domain, kind, protocol) });
        }
        if DEPTH.with(Cell::get) > 1 {
            return Err(EDEADLK);
        }
        if kind & !(SOCK_NONBLOCK | SOCK_CLOEXEC | 0xf) != 0 {
            return Err(EINVAL);
        }
        if ![0, IPPROTO_TCP].contains(&protocol) {
            return Err(EPROTONOSUPPORT);
        }
        let rt = runtime()?;
        if domain != rt.family {
            return Err(EAFNOSUPPORT);
        }
        let (fd, t) = token(kind)?;
        match rt.call(0, Op::New(kind)) {
            Ok(reply) => install(fd, t, reply.value as u64),
            Err(e) => {
                unsafe {
                    syscall(SYS_close, fd);
                }
                Err(e)
            }
        }
    }) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bind(fd: i32, p: *const sockaddr, len: socklen_t) -> i32 {
    ffi(|| match owned(fd)? {
        Some(id) => {
            call(id, Op::Bind(unsafe { address(p, len)? }))?;
            Ok(0)
        }
        None => raw(unsafe { syscall(SYS_bind, fd, p, len) }),
    }) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn listen(fd: i32, backlog: i32) -> i32 {
    ffi(|| match owned(fd)? {
        Some(id) => {
            call(id, Op::Listen(backlog))?;
            Ok(0)
        }
        None => raw(unsafe { syscall(SYS_listen, fd, backlog) }),
    }) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_accept4(
    fd: i32,
    p: *mut sockaddr,
    len: *mut socklen_t,
    flags: i32,
) -> i32 {
    ffi(|| {
        let Some(id) = owned(fd)? else {
            return raw(unsafe { syscall(SYS_accept4, fd, p, len, flags) });
        };
        if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
            return Err(EINVAL);
        }
        if !p.is_null() && len.is_null() {
            return Err(EFAULT);
        }
        let (newfd, t) = token(flags)?;
        let reply = match retry(id, Op::Accept(flags), false, EPOLLIN) {
            Ok(r) => r,
            Err(e) => {
                unsafe {
                    syscall(SYS_close, newfd);
                }
                return Err(e);
            }
        };
        if let Err(e) = unsafe { output_addr(reply.addr.unwrap(), p, len) } {
            unsafe {
                syscall(SYS_close, newfd);
            }
            let _ = call(reply.value as u64, Op::Close);
            return Err(e);
        }
        install(newfd, t, reply.value as u64)
    }) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_accept(
    fd: i32,
    p: *mut sockaddr,
    len: *mut socklen_t,
) -> i32 {
    unsafe { ntcp_managed_accept4(fd, p, len, 0) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_connect(fd: i32, p: *const sockaddr, len: socklen_t) -> i32 {
    ffi(|| {
        let Some(id) = owned(fd)? else {
            return raw(unsafe { syscall(SYS_connect, fd, p, len) });
        };
        let deadline = Deadline::socket(id, true, false)?;
        match call(id, Op::Connect(unsafe { address(p, len)? })) {
            Err(EINPROGRESS) if blocking(id)? => {
                wait_until(id, EPOLLOUT, &deadline)
                    .map_err(|e| if e == EAGAIN { EINPROGRESS } else { e })?;
                let e = call(id, Op::Get(SOL_SOCKET, SO_ERROR))?.value;
                if e != 0 { Err(e) } else { Ok(0) }
            }
            r => r.map(|_| 0),
        }
    }) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_close(fd: i32) -> i32 {
    if let Some(_native) = NativeMutation::enter()
        && !inherited(&SOCKET_FDS, fd)
        && !readiness::tracked_epoll(fd)
    {
        return unsafe { syscall(SYS_close, fd) as i32 };
    }
    ffi(|| {
        mutation_context()?;
        #[cfg(test)]
        CLOSE_BEFORE_LOCK.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook();
            }
        });
        let (closed, last) = {
            let mut tokens = TOKENS.lock().map_err(|_| EIO)?;
            let _mutation = Mutation::enter();
            // Also remove stale aliases: closing a reused native fd must not
            // leave an owner lifetime pinned by an invalid registry entry.
            let closed = raw(unsafe { syscall(SYS_close, fd) });
            let last = remove_alias(&mut tokens, fd);
            readiness::close_epoll(fd)?;
            (closed, last)
        };
        let engine = finish_close(last);
        closed?;
        engine?;
        Ok(0)
    }) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shutdown(fd: i32, how: i32) -> i32 {
    ffi(|| match owned(fd)? {
        Some(id) => {
            call(id, Op::Shutdown(how))?;
            if how != SHUT_WR {
                let input = TOKENS
                    .lock()
                    .map_err(|_| EIO)?
                    .get(&fd)
                    .ok_or(EBADF)?
                    .input
                    .clone();
                input.bytes.lock().map_err(|_| EIO)?.clear();
                input.ready.store(0, Ordering::Release);
            }
            Ok(0)
        }
        None => raw(unsafe { syscall(SYS_shutdown, fd, how) }),
    }) as i32
}
unsafe fn name(fd: i32, p: *mut sockaddr, len: *mut socklen_t, peer: bool) -> i32 {
    ffi(|| match owned(fd)? {
        Some(id) => {
            if p.is_null() || len.is_null() {
                return Err(EFAULT);
            }
            unsafe {
                output_addr(call(id, Op::Name(peer))?.addr.unwrap(), p, len)?;
            }
            Ok(0)
        }
        None => raw(unsafe {
            syscall(
                if peer {
                    SYS_getpeername
                } else {
                    SYS_getsockname
                },
                fd,
                p,
                len,
            )
        }),
    }) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getsockname(fd: i32, p: *mut sockaddr, len: *mut socklen_t) -> i32 {
    unsafe { name(fd, p, len, false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpeername(fd: i32, p: *mut sockaddr, len: *mut socklen_t) -> i32 {
    unsafe { name(fd, p, len, true) }
}
unsafe fn transfer(fd: i32, p: *mut c_void, n: usize, flags: i32, write: bool) -> Result<i64> {
    let Some(id) = owned(fd)? else {
        return raw(unsafe {
            if write {
                syscall(SYS_sendto, fd, p, n, flags, ptr::null::<sockaddr>(), 0)
            } else {
                syscall(
                    SYS_recvfrom,
                    fd,
                    p,
                    n,
                    flags,
                    ptr::null_mut::<sockaddr>(),
                    ptr::null_mut::<socklen_t>(),
                )
            }
        });
    };
    if flags & !(MSG_DONTWAIT | if write { MSG_NOSIGNAL } else { MSG_PEEK }) != 0 {
        return Err(EOPNOTSUPP);
    }
    if n != 0 && p.is_null() {
        return Err(EFAULT);
    }
    if n > isize::MAX as usize {
        return Err(EINVAL);
    }
    if !write {
        return read_into(fd, id, n, flags, |bytes| copy_out(p.cast(), bytes));
    }
    let mut bytes = vec![0; n.min(runtime::BYTES)];
    copy_in(p.cast(), &mut bytes)?;
    let op = Op::Write(bytes);
    let result = retry(
        id,
        op,
        flags & MSG_DONTWAIT != 0,
        if write { EPOLLOUT } else { EPOLLIN },
    );
    if let Err(EPIPE) = result
        && write
        && flags & MSG_NOSIGNAL == 0
    {
        unsafe {
            syscall(
                SYS_tgkill,
                syscall(SYS_getpid),
                syscall(SYS_gettid),
                SIGPIPE,
            );
        }
    }
    let reply = result?;
    Ok(reply.value as i64)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_send(
    fd: i32,
    p: *const c_void,
    n: usize,
    flags: i32,
) -> ssize_t {
    ffi(|| unsafe { transfer(fd, p.cast_mut(), n, flags, true) }) as ssize_t
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_recv(
    fd: i32,
    p: *mut c_void,
    n: usize,
    flags: i32,
) -> ssize_t {
    ffi(|| unsafe { transfer(fd, p, n, flags, false) }) as ssize_t
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_read(fd: i32, p: *mut c_void, n: usize) -> ssize_t {
    if !inherited(&SOCKET_FDS, fd) {
        return unsafe { syscall(SYS_read, fd, p, n) as ssize_t };
    }
    ffi(|| {
        if owned(fd)?.is_none() {
            raw(unsafe { syscall(SYS_read, fd, p, n) })
        } else {
            unsafe { transfer(fd, p, n, 0, false) }
        }
    }) as ssize_t
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed___read_chk(
    fd: i32,
    p: *mut c_void,
    n: usize,
    size: usize,
) -> ssize_t {
    if n > size {
        unsafe {
            __chk_fail();
        }
    }
    unsafe { ntcp_managed_read(fd, p, n) }
}
unsafe extern "C" {
    fn __chk_fail() -> !;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed___recv_chk(
    fd: i32,
    p: *mut c_void,
    n: usize,
    size: usize,
    flags: i32,
) -> ssize_t {
    if n > size {
        unsafe {
            __chk_fail();
        }
    }
    unsafe { ntcp_managed_recv(fd, p, n, flags) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed___recvfrom_chk(
    fd: i32,
    p: *mut c_void,
    n: usize,
    size: usize,
    flags: i32,
    addr: *mut sockaddr,
    len: *mut socklen_t,
) -> ssize_t {
    if n > size {
        unsafe {
            __chk_fail();
        }
    }
    unsafe { ntcp_managed_recvfrom(fd, p, n, flags, addr, len) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_write(fd: i32, p: *const c_void, n: usize) -> ssize_t {
    if !inherited(&SOCKET_FDS, fd) {
        return unsafe { syscall(SYS_write, fd, p, n) as ssize_t };
    }
    ffi(|| {
        if owned(fd)?.is_none() {
            raw(unsafe { syscall(SYS_write, fd, p, n) })
        } else {
            unsafe { transfer(fd, p.cast_mut(), n, 0, true) }
        }
    }) as ssize_t
}
unsafe fn vectors(fd: i32, v: *const iovec, count: i32, flags: i32, write: bool) -> Result<i64> {
    unsafe { vectors_output(fd, v, count, flags, write, || Ok(())) }
}
unsafe fn vectors_output(
    fd: i32,
    v: *const iovec,
    count: i32,
    flags: i32,
    write: bool,
    done: impl FnOnce() -> Result<()>,
) -> Result<i64> {
    if !(0..=1024).contains(&count) {
        return Err(EINVAL);
    }
    if count != 0 && v.is_null() {
        return Err(EFAULT);
    }
    let vectors = load_array(v, count as usize, 1024)?;
    let mut total = 0usize;
    for v in &vectors {
        if v.iov_len != 0 && v.iov_base.is_null() {
            return Err(EFAULT);
        }
        total = total
            .checked_add(v.iov_len)
            .filter(|&n| n <= isize::MAX as usize)
            .ok_or(EINVAL)?;
    }
    let mut bytes = vec![0u8; total.min(runtime::BYTES)];
    if write {
        let mut offset = 0;
        for v in &vectors {
            let n = v.iov_len.min(bytes.len() - offset);
            if n != 0 {
                copy_in(v.iov_base.cast(), &mut bytes[offset..offset + n])?;
            }
            offset += n;
            if offset == bytes.len() {
                break;
            }
        }
    }
    if write {
        return unsafe { transfer(fd, bytes.as_mut_ptr().cast(), bytes.len(), flags, true) };
    }
    if flags & !(MSG_DONTWAIT | MSG_PEEK) != 0 {
        return Err(EOPNOTSUPP);
    }
    let id = owned(fd)?.ok_or(EBADF)?;
    read_into(fd, id, bytes.len(), flags, |bytes| {
        let mut offset = 0;
        for v in &vectors {
            let len = v.iov_len.min(bytes.len() - offset);
            copy_out(v.iov_base.cast(), &bytes[offset..offset + len])?;
            offset += len;
            if offset == bytes.len() {
                break;
            }
        }
        done()
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_readv(fd: i32, v: *const iovec, n: i32) -> ssize_t {
    ffi(|| {
        if owned(fd)?.is_none() {
            raw(unsafe { syscall(SYS_readv, fd, v, n) })
        } else {
            unsafe { vectors(fd, v, n, 0, false) }
        }
    }) as ssize_t
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_writev(fd: i32, v: *const iovec, n: i32) -> ssize_t {
    ffi(|| {
        if owned(fd)?.is_none() {
            raw(unsafe { syscall(SYS_writev, fd, v, n) })
        } else {
            unsafe { vectors(fd, v, n, 0, true) }
        }
    }) as ssize_t
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_sendmsg(fd: i32, p: *const msghdr, flags: i32) -> ssize_t {
    ffi(|| {
        if owned(fd)?.is_none() {
            return raw(unsafe { syscall(SYS_sendmsg, fd, p, flags) });
        }
        if p.is_null() {
            return Err(EFAULT);
        }
        let m = load(p)?;
        if m.msg_controllen != 0 || !m.msg_name.is_null() {
            return Err(EOPNOTSUPP);
        }
        let n = i32::try_from(m.msg_iovlen).map_err(|_| EINVAL)?;
        unsafe { vectors(fd, m.msg_iov, n, flags, true) }
    }) as ssize_t
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_recvmsg(fd: i32, p: *mut msghdr, flags: i32) -> ssize_t {
    ffi(|| {
        let Some(id) = owned(fd)? else {
            return raw(unsafe { syscall(SYS_recvmsg, fd, p, flags) });
        };
        if p.is_null() {
            return Err(EFAULT);
        }
        let mut m = load(p)?;
        let n = i32::try_from(m.msg_iovlen).map_err(|_| EINVAL)?;
        unsafe {
            vectors_output(fd, m.msg_iov, n, flags, false, || {
                if !m.msg_name.is_null() {
                    output_addr(
                        call(id, Op::Name(true))?.addr.unwrap(),
                        m.msg_name.cast(),
                        &mut m.msg_namelen,
                    )?;
                }
                m.msg_controllen = 0;
                m.msg_flags = 0;
                store(p, &m)
            })
        }
    }) as ssize_t
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_sendto(
    fd: i32,
    p: *const c_void,
    n: usize,
    flags: i32,
    addr: *const sockaddr,
    len: socklen_t,
) -> ssize_t {
    ffi(|| {
        if owned(fd)?.is_none() {
            return raw(unsafe { syscall(SYS_sendto, fd, p, n, flags, addr, len) });
        }
        if !addr.is_null() {
            return Err(EOPNOTSUPP);
        }
        unsafe { transfer(fd, p.cast_mut(), n, flags, true) }
    }) as ssize_t
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_recvfrom(
    fd: i32,
    p: *mut c_void,
    n: usize,
    flags: i32,
    addr: *mut sockaddr,
    len: *mut socklen_t,
) -> ssize_t {
    ffi(|| {
        let Some(id) = owned(fd)? else {
            return raw(unsafe { syscall(SYS_recvfrom, fd, p, n, flags, addr, len) });
        };
        if !addr.is_null() && len.is_null() {
            return Err(EFAULT);
        }
        if flags & !(MSG_DONTWAIT | MSG_PEEK) != 0 {
            return Err(EOPNOTSUPP);
        }
        if n > isize::MAX as usize {
            return Err(EINVAL);
        }
        read_into(fd, id, n, flags, |bytes| {
            copy_out(p.cast(), bytes)?;
            if !addr.is_null() {
                unsafe {
                    output_addr(call(id, Op::Name(true))?.addr.unwrap(), addr, len)?;
                }
            }
            Ok(())
        })
    }) as ssize_t
}
// Linux old timeval and new __kernel_sock_timeval are both two signed
// 64-bit fields on the supported x86_64/aarch64 ABIs.
fn timeout_option(level: i32, name: i32) -> Option<bool> {
    if level != SOL_SOCKET {
        return None;
    }
    match name {
        SO_RCVTIMEO | 66 => Some(false),
        SO_SNDTIMEO | 67 => Some(true),
        _ => None,
    }
}
fn timeout_micros(value: [i64; 2]) -> Result<u64> {
    let [seconds, micros] = value;
    if !(0..1_000_000).contains(&micros) {
        return Err(EDOM);
    }
    if seconds < 0 {
        return Ok(0);
    }
    // Explicit precision policy: exact microseconds, not host jiffy rounding.
    (seconds as u64)
        .checked_mul(1_000_000)
        .and_then(|n| n.checked_add(micros as u64))
        .ok_or(EINVAL)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setsockopt(
    fd: i32,
    level: i32,
    name: i32,
    p: *const c_void,
    len: socklen_t,
) -> i32 {
    ffi(|| {
        let Some(id) = owned(fd)? else {
            return raw(unsafe { syscall(SYS_setsockopt, fd, level, name, p, len) });
        };
        if p.is_null() {
            return Err(EFAULT);
        }
        if let Some(send) = timeout_option(level, name) {
            if len < 16 {
                return Err(EINVAL);
            }
            let micros = timeout_micros(load(p.cast::<[i64; 2]>())?)?;
            call(id, Op::SetTimeout(send, micros))?;
            return Ok(0);
        }
        if len < 4 {
            return Err(EINVAL);
        }
        let value = load(p.cast::<i32>())?;
        call(id, Op::Set(level, name, value))?;
        Ok(0)
    }) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getsockopt(
    fd: i32,
    level: i32,
    name: i32,
    p: *mut c_void,
    len: *mut socklen_t,
) -> i32 {
    ffi(|| {
        let Some(id) = owned(fd)? else {
            return raw(unsafe { syscall(SYS_getsockopt, fd, level, name, p, len) });
        };
        if p.is_null() || len.is_null() {
            return Err(EFAULT);
        }
        if let Some(send) = timeout_option(level, name) {
            let micros = call(id, Op::GetTimeout(send))?.timeout_us;
            let value = [(micros / 1_000_000) as i64, (micros % 1_000_000) as i64];
            let n = (load(len)? as usize).min(16);
            memory(value.as_ptr().cast_mut().cast(), p.cast(), n, true)?;
            store(len, &(n as u32))?;
            return Ok(0);
        }
        let value = call(id, Op::Get(level, name))?.value.to_ne_bytes();
        let n = (load(len)? as usize).min(4);
        copy_out(p.cast(), &value[..n])?;
        store(len, &(n as u32))?;
        Ok(0)
    }) as i32
}
#[unsafe(no_mangle)]
pub extern "C" fn ntcp_fcntl_dispatch(fd: i32, cmd: i32, arg: c_ulong) -> i32 {
    ffi(|| {
        if [F_DUPFD, F_DUPFD_CLOEXEC].contains(&cmd) {
            return duplicate(fd, None, cmd, arg);
        }
        let Some(id) = owned(fd)? else {
            if cmd == F_GETOWN {
                // Linux UAPI constants not exposed by libc on every target.
                const F_GETOWN_EX: i32 = 16;
                const F_OWNER_PGRP: i32 = 2;
                #[repr(C)]
                struct Owner {
                    kind: i32,
                    pid: i32,
                }
                let mut owner = Owner { kind: 0, pid: 0 };
                raw(unsafe { syscall(SYS_fcntl, fd, F_GETOWN_EX, &mut owner) })?;
                return Ok(if owner.kind == F_OWNER_PGRP {
                    -owner.pid
                } else {
                    owner.pid
                } as i64);
            }
            return raw(unsafe { syscall(SYS_fcntl, fd, cmd, arg) });
        };
        match cmd {
            F_GETFL | F_SETFL => Ok(call(id, Op::Flags(cmd, arg as i32))?.value as i64),
            F_GETFD | F_SETFD => raw(unsafe { syscall(SYS_fcntl, fd, cmd, arg) }),
            F_DUPFD | F_DUPFD_CLOEXEC => duplicate(fd, None, cmd, arg),
            _ => Err(EOPNOTSUPP),
        }
    }) as i32
}
#[unsafe(no_mangle)]
pub extern "C" fn ntcp_ioctl_dispatch(fd: i32, cmd: c_ulong, arg: c_ulong) -> i32 {
    ffi(|| {
        let Some(id) = owned(fd)? else {
            return raw(unsafe { syscall(SYS_ioctl, fd, cmd, arg) });
        };
        match cmd {
            FIONBIO => {
                if arg == 0 {
                    return Err(EFAULT);
                }
                let n = load(arg as *const i32)?;
                call(id, Op::Flags(F_SETFL, if n != 0 { O_NONBLOCK } else { 0 }))?;
                Ok(0)
            }
            FIONREAD => {
                if arg == 0 {
                    return Err(EFAULT);
                }
                store(arg as *mut i32, &call(id, Op::Available)?.value)?;
                Ok(0)
            }
            FIOCLEX | FIONCLEX => raw(unsafe { syscall(SYS_ioctl, fd, cmd) }),
            _ => Err(EOPNOTSUPP),
        }
    }) as i32
}
// ABI-preserving tail calls: C, not Rust, decodes optional varargs.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcntl() -> i32 {
    core::arch::naked_asm!("jmp ntcp_variadic_fcntl");
}
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcntl64() -> i32 {
    core::arch::naked_asm!("jmp ntcp_variadic_fcntl");
}
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ioctl() -> i32 {
    core::arch::naked_asm!("jmp ntcp_variadic_ioctl");
}
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcntl() -> i32 {
    core::arch::naked_asm!("b ntcp_variadic_fcntl");
}
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcntl64() -> i32 {
    core::arch::naked_asm!("b ntcp_variadic_fcntl");
}
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ioctl() -> i32 {
    core::arch::naked_asm!("b ntcp_variadic_ioctl");
}
// Registry mutation and the kernel descriptor operation are serialized together.
// Close/dup release TOKENS before epoll cleanup and owner RPCs; ctl alone
// nests the locks in TOKENS -> EPOLLS order.
fn remove_alias(tokens: &mut BTreeMap<i32, Token>, fd: i32) -> Option<u64> {
    let t = tokens.remove(&fd)?;
    (!tokens.values().any(|alias| alias.id == t.id)).then_some(t.id)
}
fn finish_close(last: Option<u64>) -> Result<()> {
    if let Some(id) = last {
        readiness::closed(id);
        call(id, Op::Close)?;
    }
    Ok(())
}
// ponytail: bounded 512-alias scan; index by id if readiness cost matters.
fn live_id(id: u64) -> Result<bool> {
    Ok(TOKENS
        .lock()
        .map_err(|_| EIO)?
        .iter()
        .any(|(&fd, t)| t.id == id && t.matches(fd)))
}
fn duplicate(fd: i32, new: Option<i32>, cmd: i32, arg: c_ulong) -> Result<i64> {
    let kernel = || unsafe {
        match new {
            Some(n) if cmd == SYS_dup3 as i32 => syscall(SYS_dup3, fd, n, arg),
            Some(n) => syscall(SYS_dup2, fd, n),
            None if cmd == SYS_dup as i32 => syscall(SYS_dup, fd),
            None => syscall(SYS_fcntl, fd, cmd, arg),
        }
    };
    // Classify *both* endpoints while protected from managed replacement.
    if let Some(_native) = NativeMutation::enter()
        && !inherited(&SOCKET_FDS, fd)
        && !readiness::tracked_epoll(fd)
        && new.is_none_or(|n| !inherited(&SOCKET_FDS, n) && !readiness::tracked_epoll(n))
    {
        return raw(kernel());
    }
    mutation_context()?;
    #[cfg(test)]
    DUP_BEFORE_LOCK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
    let (result, last) = {
        let mut tokens = TOKENS.lock().map_err(|_| EIO)?;
        let _mutation = Mutation::enter();
        if readiness::is_epoll(fd)? {
            return Err(EOPNOTSUPP);
        }
        if new == Some(fd) {
            return raw(kernel());
        }
        if cmd == SYS_dup3 as i32 && arg & !(O_CLOEXEC as c_ulong) != 0 {
            return Err(EINVAL);
        }
        let alias = tokens.get(&fd).filter(|t| t.matches(fd)).map(|t| Token {
            slot: None,
            id: t.id,
            retained: t.retained.clone(),
            dev: t.dev,
            ino: t.ino,
            input: t.input.clone(),
        });
        let source = alias.as_ref().map(|t| t.id);
        if alias.is_some() {
            let mut limit: rlimit = unsafe { std::mem::zeroed() };
            raw(unsafe { syscall(SYS_getrlimit, RLIMIT_NOFILE, &mut limit) })?;
            if new.is_some_and(|n| n < 0 || n as rlim_t >= limit.rlim_cur) {
                return Err(EBADF);
            }
            if new.is_none()
                && [F_DUPFD, F_DUPFD_CLOEXEC].contains(&cmd)
                && ((arg as i32) < 0 || (arg as i32) as rlim_t >= limit.rlim_cur)
            {
                return Err(EINVAL);
            }
        }
        let reused_slot = new.and_then(|n| tokens.get(&n)).and_then(|t| t.slot);
        let slot = if alias.is_some() {
            Some(match reused_slot {
                Some(slot) => slot,
                None => reserve_fd(&SOCKET_FDS, new.unwrap_or(-2))?,
            })
        } else {
            None
        };
        let result = match raw(kernel()) {
            Ok(n) => n,
            Err(e) => {
                if reused_slot.is_none()
                    && let Some(slot) = slot
                {
                    SOCKET_FDS[slot].store(-1, Ordering::Release);
                }
                return Err(e);
            }
        };
        #[cfg(test)]
        DUP_AFTER_KERNEL.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook();
            }
        });
        if alias.is_some()
            && let Some(t) = new.and_then(|n| tokens.get_mut(&n))
        {
            // Transfer the slot without briefly publishing a native fast path.
            t.slot = None;
        }
        let last = new.and_then(|n| remove_alias(&mut tokens, n));
        if let Some(mut t) = alias {
            t.slot = slot;
            SOCKET_FDS[slot.unwrap()].store(result as i32, Ordering::Release);
            tokens.insert(result as i32, t);
        }
        if let Some(n) = new {
            readiness::close_epoll(n)?;
        }
        // Replacing another alias of the source cannot end its OFD lifetime.
        (result, last.filter(|id| Some(*id) != source))
    };
    // dup2/dup3 ignore errors from the target's implicit close.
    let _ = finish_close(last);
    Ok(result)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dup(fd: i32) -> i32 {
    ffi(|| duplicate(fd, None, SYS_dup as i32, 0)) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dup2(fd: i32, new: i32) -> i32 {
    ffi(|| duplicate(fd, Some(new), SYS_dup2 as i32, 0)) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dup3(fd: i32, new: i32, flags: i32) -> i32 {
    ffi(|| duplicate(fd, Some(new), SYS_dup3 as i32, flags as c_ulong)) as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    static SIGNAL_PIPE: AtomicI32 = AtomicI32::new(-1);
    static SIGNAL_SOCKET: AtomicI32 = AtomicI32::new(-1);
    static SIGNAL_RESULT: AtomicI32 = AtomicI32::new(0);
    extern "C" fn signal_io(_: i32) {
        let byte = 1u8;
        let native = unsafe {
            write(
                SIGNAL_PIPE.load(Ordering::Relaxed),
                (&byte as *const u8).cast(),
                1,
            )
        } == 1;
        let native_alias = unsafe { dup(SIGNAL_PIPE.load(Ordering::Relaxed)) };
        let native_close = native_alias >= 0 && unsafe { close(native_alias) } == 0;
        let mut out = 0u8;
        let recursive = unsafe {
            read(
                SIGNAL_SOCKET.load(Ordering::Relaxed),
                (&mut out as *mut u8).cast(),
                1,
            )
        } == -1
            && errno() == EDEADLK;
        let mut p = pollfd {
            fd: SIGNAL_PIPE.load(Ordering::Relaxed),
            events: POLLOUT,
            revents: 0,
        };
        let zero = timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let native_poll = unsafe { readiness::poll(&mut p, 1, 0) } == 1;
        let native_ppoll = unsafe { readiness::ppoll(&mut p, 1, &zero, ptr::null()) } == 1;
        let mut set: fd_set = unsafe { std::mem::zeroed() };
        unsafe { FD_SET(p.fd, &mut set) };
        let mut timeout = timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        // The unrelated virtual fd is inside nfds but absent from the set.
        let n = p.fd.max(SIGNAL_SOCKET.load(Ordering::Relaxed)) + 1;
        let native_select = unsafe {
            readiness::select(n, ptr::null_mut(), &mut set, ptr::null_mut(), &mut timeout)
        } == 1;
        let native_pselect = unsafe {
            readiness::pselect(
                n,
                ptr::null_mut(),
                &mut set,
                ptr::null_mut(),
                &zero,
                ptr::null(),
            )
        } == 1;
        p.fd = SIGNAL_SOCKET.load(Ordering::Relaxed);
        let virtual_poll = unsafe { readiness::poll(&mut p, 1, 0) } == -1 && errno() == EDEADLK;
        let passed = native
            && native_close
            && recursive
            && native_poll
            && native_ppoll
            && native_select
            && native_pselect
            && virtual_poll;
        SIGNAL_RESULT.store(if passed { 1 } else { -1 }, Ordering::Relaxed);
    }
    #[test]
    fn signal_native_pipe_bypasses_locked_tokens_and_virtual_recursion_fails_closed() {
        let mut pipes = [-1; 2];
        assert_eq!(
            unsafe { syscall(SYS_pipe2, pipes.as_mut_ptr(), O_CLOEXEC) },
            0
        );
        let (fd, t) = token(SOCK_CLOEXEC).unwrap();
        install(fd, t, 993).unwrap();
        PID.store(unsafe { syscall(SYS_getpid) as i32 }, Ordering::Release);
        SIGNAL_PIPE.store(pipes[1], Ordering::Relaxed);
        SIGNAL_SOCKET.store(fd, Ordering::Relaxed);
        let mut action: sigaction = unsafe { std::mem::zeroed() };
        let mut old: sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = signal_io as *const () as usize;
        assert_eq!(unsafe { libc::sigaction(SIGUSR1, &action, &mut old) }, 0);
        unsafe {
            libc::alarm(5);
        }
        assert_eq!(
            ffi(|| {
                let _tokens = TOKENS.lock().unwrap();
                raw(unsafe {
                    syscall(
                        SYS_tgkill,
                        syscall(SYS_getpid),
                        syscall(SYS_gettid),
                        SIGUSR1,
                    )
                })
            }),
            0
        );
        unsafe {
            libc::alarm(0);
            libc::sigaction(SIGUSR1, &old, ptr::null_mut());
        }
        assert_eq!(SIGNAL_RESULT.load(Ordering::Relaxed), 1);
        let mut byte = 0u8;
        assert_eq!(
            unsafe { read(pipes[0], (&mut byte as *mut u8).cast(), 1) },
            1
        );
        TOKENS.lock().unwrap().remove(&fd);
        unsafe {
            syscall(SYS_close, fd);
            close(pipes[0]);
            close(pipes[1]);
        }
    }
    // Hooks are thread-local and test-only: stop exactly at the two reviewer
    // windows rather than relying on scheduling or repeated stress loops.
    #[test]
    fn duplicate_reclassifies_native_source_after_replacement() {
        let (source, t) = token(SOCK_CLOEXEC).unwrap();
        install(source, t, 980).unwrap();
        let (target, t) = token(SOCK_CLOEXEC).unwrap();
        install(target, t, 981).unwrap();
        let native = unsafe { syscall(SYS_eventfd2, 0, EFD_CLOEXEC) as i32 };
        assert!(native >= 0);
        let entered = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        let worker = {
            let entered = entered.clone();
            let resume = resume.clone();
            std::thread::spawn(move || {
                DUP_BEFORE_LOCK.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        entered.wait();
                        resume.wait();
                    }))
                });
                duplicate(native, Some(target), SYS_dup2 as i32, 0)
            })
        };
        entered.wait();
        assert_eq!(
            duplicate(source, Some(native), SYS_dup2 as i32, 0),
            Ok(native as i64)
        );
        resume.wait();
        assert_eq!(worker.join().unwrap(), Ok(target as i64));
        assert_eq!(owned(target), Ok(Some(980)));
        assert_eq!(owned(native), Ok(Some(980)));
        let mut tokens = TOKENS.lock().unwrap();
        for fd in [source, native, target] {
            tokens.remove(&fd);
            unsafe {
                syscall(SYS_close, fd);
            }
        }
    }
    #[test]
    fn close_waits_for_managed_over_native_publication() {
        let (source, t) = token(SOCK_CLOEXEC).unwrap();
        install(source, t, 982).unwrap();
        let target = unsafe { syscall(SYS_eventfd2, 0, EFD_CLOEXEC) as i32 };
        assert!(target >= 0);
        let replaced = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        let worker = {
            let replaced = replaced.clone();
            let resume = resume.clone();
            std::thread::spawn(move || {
                DUP_AFTER_KERNEL.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        replaced.wait();
                        resume.wait();
                    }))
                });
                duplicate(source, Some(target), SYS_dup2 as i32, 0)
            })
        };
        replaced.wait();
        // The target is visible before alias publication and the native fast
        // path cannot enter while the kernel/registry transaction is open.
        assert!(inherited(&SOCKET_FDS, target));
        assert!(NativeMutation::enter().is_none());
        let (entered, waiting) = std::sync::mpsc::channel();
        let closer = std::thread::spawn(move || {
            CLOSE_BEFORE_LOCK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    entered.send(()).unwrap();
                }))
            });
            unsafe { close(target) }
        });
        waiting
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        resume.wait();
        assert_eq!(worker.join().unwrap(), Ok(target as i64));
        assert_eq!(closer.join().unwrap(), 0);
        // Other tests may immediately allocate this fd number. Assert the
        // original OFD has no ghost alias, not that the number stays unused.
        assert!(
            !TOKENS
                .lock()
                .unwrap()
                .iter()
                .any(|(&fd, t)| fd != source && t.id == 982)
        );
        assert_eq!(owned(source), Ok(Some(982)));
        TOKENS.lock().unwrap().remove(&source);
        unsafe {
            syscall(SYS_close, source);
        }
    }
    #[test]
    fn managed_mutation_cannot_wait_on_interrupted_native_reader() {
        let (fd, t) = token(SOCK_CLOEXEC).unwrap();
        install(fd, t, 983).unwrap();
        let native = NativeMutation::enter().unwrap();
        assert_eq!(unsafe { close(fd) }, -1);
        assert_eq!(errno(), EDEADLK);
        drop(native);
        TOKENS.lock().unwrap().remove(&fd);
        unsafe {
            syscall(SYS_close, fd);
        }
    }
    #[test]
    fn native_duplicate_bypasses_locked_tokens() {
        let fd = unsafe { syscall(SYS_eventfd2, 0, EFD_CLOEXEC) as i32 };
        let _tokens = TOKENS.lock().unwrap();
        let alias = duplicate(fd, None, SYS_dup as i32, 0).unwrap() as i32;
        assert_eq!(unsafe { close(alias) }, 0);
        assert_eq!(unsafe { close(fd) }, 0);
    }
    #[test]
    fn timeout_validation_and_absolute_budget() {
        assert_eq!(timeout_micros([0, 1]), Ok(1));
        assert_eq!(timeout_micros([-1, 0]), Ok(0));
        assert_eq!(timeout_micros([1, -1]), Err(EDOM));
        assert_eq!(timeout_micros([1, 1_000_000]), Err(EDOM));
        assert_eq!(timeout_micros([i64::MAX, 0]), Err(EINVAL));
        let mut deadline = Deadline {
            start: std::time::Instant::now(),
            budget: Some(std::time::Duration::from_micros(u64::MAX)),
        };
        assert_eq!(deadline.poll_ms(), Ok(10));
        deadline.budget = Some(std::time::Duration::from_millis(30));
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(deadline.poll_ms(), Err(EAGAIN));
        assert_eq!(deadline.poll_ms(), Err(EAGAIN));
    }

    #[test]
    fn staged_peek_fault_rollback_and_shared_input() {
        let (fd, t) = token(SOCK_CLOEXEC).unwrap();
        let input = t.input.clone();
        *input.bytes.lock().unwrap() = b"abcdef".to_vec();
        input.ready.store(6, Ordering::Release);
        install(fd, t, 995).unwrap();
        let (alias, mut t) = token(SOCK_CLOEXEC).unwrap();
        t.input = input.clone();
        install(alias, t, 995).unwrap();
        let mut out = [0u8; 8];
        for descriptor in [fd, alias] {
            assert_eq!(
                unsafe {
                    recv(
                        descriptor,
                        out.as_mut_ptr().cast(),
                        6,
                        MSG_PEEK | MSG_DONTWAIT,
                    )
                },
                6
            );
            assert_eq!(&out[..6], b"abcdef");
        }
        assert_eq!(
            read_into(fd, 995, 3, MSG_DONTWAIT, |_| Err(EFAULT)),
            Err(EFAULT)
        );
        assert_eq!(input.ready.load(Ordering::Acquire), 6);
        assert_eq!(
            unsafe { recv(alias, out.as_mut_ptr().cast(), 3, MSG_DONTWAIT) },
            3
        );
        assert_eq!(&out[..3], b"abc");
        assert_eq!(
            unsafe { recv(fd, out.as_mut_ptr().cast(), 3, MSG_PEEK | MSG_DONTWAIT) },
            3
        );
        assert_eq!(&out[..3], b"def");
        assert_eq!(
            unsafe { recv(fd, out.as_mut_ptr().cast(), 3, MSG_DONTWAIT) },
            3
        );
        assert_eq!(input.ready.load(Ordering::Acquire), 0);
        for descriptor in [fd, alias] {
            TOKENS.lock().unwrap().remove(&descriptor);
            unsafe {
                syscall(SYS_close, descriptor);
            }
        }
    }

    #[test]
    fn nonblocking_read_does_not_wait_for_another_reader() {
        let (fd, t) = token(SOCK_CLOEXEC).unwrap();
        let input = t.input.clone();
        install(fd, t, 994).unwrap();
        let reader = input.bytes.lock().unwrap();
        let mut byte = 0u8;
        assert_eq!(
            unsafe { recv(fd, (&mut byte as *mut u8).cast(), 1, MSG_DONTWAIT) },
            -1
        );
        assert_eq!(errno(), EAGAIN);
        drop(reader);
        TOKENS.lock().unwrap().remove(&fd);
        unsafe {
            syscall(SYS_close, fd);
        }
    }
    #[test]
    fn token_identity_rejects_closed_and_reused_descriptor() {
        let (fd, t) = token(SOCK_CLOEXEC | SOCK_NONBLOCK).unwrap();
        assert!(t.matches(fd));
        assert_ne!(
            unsafe { syscall(SYS_fcntl, fd, F_GETFD) } & FD_CLOEXEC as i64,
            0
        );
        unsafe {
            syscall(SYS_close, fd);
        }
        assert!(!t.matches(fd));
        let other = unsafe { syscall(SYS_eventfd2, 0, EFD_CLOEXEC) as i32 };
        assert!(other >= 0);
        assert!(!t.matches(other));
        unsafe {
            syscall(SYS_close, other);
        }
    }
    #[test]
    fn address_roundtrip_and_short_output_buffer() {
        let addr: SocketAddr = "10.73.0.2:16379".parse().unwrap();
        let mut out: [u8; 16] = [0; 16];
        let mut n = 16;
        unsafe {
            output_addr(addr, out.as_mut_ptr().cast(), &mut n).unwrap();
        }
        assert_eq!(n, 16);
        assert_eq!(unsafe { address(out.as_ptr().cast(), n).unwrap() }, addr);
        n = 2;
        out.fill(0x55);
        unsafe {
            output_addr(addr, out.as_mut_ptr().cast(), &mut n).unwrap();
        }
        assert_eq!(n, 16);
        assert!(out[2..].iter().all(|&b| b == 0x55));
        assert_eq!(unsafe { address(ptr::null(), 16).unwrap_err() }, EFAULT);
    }
    #[test]
    fn fork_inherited_socket_fails_closed_without_blocking_native_files() {
        let (fd, t) = token(SOCK_CLOEXEC).unwrap();
        install(fd, t, 991).unwrap();
        PID.store(unsafe { syscall(SYS_getpid) as i32 }, Ordering::Release);
        let mut pipes = [-1; 2];
        assert_eq!(
            unsafe { syscall(SYS_pipe2, pipes.as_mut_ptr(), O_CLOEXEC) },
            0
        );
        let pid = unsafe { syscall(SYS_fork) };
        assert!(pid >= 0);
        if pid == 0 {
            let mut byte = 0u8;
            let failed = unsafe { read(fd, (&mut byte as *mut u8).cast(), 1) } == -1
                && errno() == EOWNERDEAD;
            let native = unsafe { write(pipes[1], (&byte as *const u8).cast(), 1) } == 1;
            unsafe {
                syscall(SYS_exit_group, if failed && native { 0 } else { 1 });
            }
            unreachable!();
        }
        let mut status = 0;
        assert_eq!(
            unsafe { syscall(SYS_wait4, pid, &mut status, 0, ptr::null_mut::<rusage>()) },
            pid
        );
        assert_eq!(status, 0);
        TOKENS.lock().unwrap().remove(&fd);
        unsafe {
            syscall(SYS_close, fd);
            syscall(SYS_close, pipes[0]);
            syscall(SYS_close, pipes[1]);
        }
    }
}

boundary_entry!(read, "ntcp_c_read", (fd: i32, p: *mut c_void, n: usize) -> ssize_t);
boundary_entry!(write, "ntcp_c_write", (fd: i32, p: *const c_void, n: usize) -> ssize_t);
boundary_entry!(readv, "ntcp_c_readv", (fd: i32, v: *const iovec, n: i32) -> ssize_t);
boundary_entry!(writev, "ntcp_c_writev", (fd: i32, v: *const iovec, n: i32) -> ssize_t);
boundary_entry!(send, "ntcp_c_send", (fd: i32, p: *const c_void, n: usize, flags: i32) -> ssize_t);
boundary_entry!(recv, "ntcp_c_recv", (fd: i32, p: *mut c_void, n: usize, flags: i32) -> ssize_t);
boundary_entry!(sendto, "ntcp_c_sendto", (fd: i32,
    p: *const c_void,
    n: usize,
    flags: i32,
    addr: *const sockaddr,
    len: socklen_t) -> ssize_t);
boundary_entry!(recvfrom, "ntcp_c_recvfrom", (fd: i32,
    p: *mut c_void,
    n: usize,
    flags: i32,
    addr: *mut sockaddr,
    len: *mut socklen_t) -> ssize_t);
boundary_entry!(sendmsg, "ntcp_c_sendmsg", (fd: i32, p: *const msghdr, flags: i32) -> ssize_t);
boundary_entry!(recvmsg, "ntcp_c_recvmsg", (fd: i32, p: *mut msghdr, flags: i32) -> ssize_t);
boundary_entry!(accept, "ntcp_c_accept", (fd: i32, p: *mut sockaddr, len: *mut socklen_t) -> i32);
boundary_entry!(accept4, "ntcp_c_accept4", (fd: i32,
    p: *mut sockaddr,
    len: *mut socklen_t,
    flags: i32) -> i32);
boundary_entry!(connect, "ntcp_c_connect", (fd: i32, p: *const sockaddr, len: socklen_t) -> i32);
boundary_entry!(close, "ntcp_c_close", (fd: i32) -> i32);
boundary_entry!(__read_chk, "ntcp_c___read_chk", (fd: i32, p: *mut c_void, n: usize, size: usize) -> ssize_t);
boundary_entry!(__recv_chk, "ntcp_c___recv_chk", (fd: i32,
    p: *mut c_void,
    n: usize,
    size: usize,
    flags: i32) -> ssize_t);
boundary_entry!(__recvfrom_chk, "ntcp_c___recvfrom_chk", (fd: i32,
    p: *mut c_void,
    n: usize,
    size: usize,
    flags: i32,
    addr: *mut sockaddr,
    len: *mut socklen_t) -> ssize_t);

// C classifiers return before libc can enter a cancellation point. Native
// descriptors only consult atomics; no locks, allocation, or TLS on that path.
#[unsafe(no_mangle)]
pub extern "C" fn ntcp_boundary_fd(fd: i32) -> i32 {
    inherited(&SOCKET_FDS, fd) as i32
}
#[unsafe(no_mangle)]
pub extern "C" fn ntcp_boundary_epoll(fd: i32) -> i32 {
    readiness::tracked_epoll(fd) as i32
}
#[unsafe(no_mangle)]
pub extern "C" fn ntcp_stdio_id(fd: i32) -> u64 {
    let mut id = 0;
    ffi(|| {
        id = owned(fd)?.unwrap_or(0);
        Ok(0)
    });
    id
}
#[unsafe(no_mangle)]
pub extern "C" fn ntcp_stdio_valid(fd: i32, id: u64) -> i32 {
    ffi(|| {
        if owned(fd)? == Some(id) {
            Ok(0)
        } else {
            Err(EBADF)
        }
    }) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn ntcp_boundary_socket(domain: i32, kind: i32) -> i32 {
    ffi(|| {
        Ok(
            (configured() && [AF_INET, AF_INET6].contains(&domain) && kind & 0xf == SOCK_STREAM)
                as i64,
        )
    }) as i32
}
boundary_entry!(socket, "ntcp_c_socket", (domain: i32, kind: i32, protocol: i32) -> i32);
