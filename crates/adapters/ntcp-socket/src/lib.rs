#![cfg(target_os = "linux")]
#![allow(clippy::missing_safety_doc)]
// Linux preload boundary. Raw syscalls keep libc and the owner thread out of
// interposition recursion; OS socket tokens never carry application payload.
use libc::*;
use std::{
    cell::Cell,
    collections::BTreeMap,
    ffi::CStr,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicI32, Ordering},
    },
};
mod readiness;
mod runtime;
use runtime::{Op, Reply, Runtime};
type Result<T> = std::result::Result<T, i32>;
thread_local! { static INTERNAL: Cell<bool> = const { Cell::new(false) }; }
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
struct Token {
    slot: Option<usize>,
    id: u64,
    retained: i32,
    dev: dev_t,
    ino: ino_t,
}
impl Token {
    fn matches(&self, fd: i32) -> bool {
        let mut st: stat = unsafe { std::mem::zeroed() };
        unsafe {
            syscall(SYS_fstat, fd, &mut st) == 0 && st.st_dev == self.dev && st.st_ino == self.ino
        }
    }
}
impl Drop for Token {
    fn drop(&mut self) {
        if let Some(slot) = self.slot {
            SOCKET_FDS[slot].store(-1, Ordering::Release);
        }
        unsafe {
            syscall(SYS_close, self.retained);
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
            INTERNAL.with(|v| {
                let old = v.replace(true);
                let result = catch_unwind(Runtime::start).unwrap_or(Err(EIO));
                v.set(old);
                result
            })
        })
        .as_ref()
        .map_err(|e| *e)
}
fn owned(fd: i32) -> Result<Option<u64>> {
    if INTERNAL.with(Cell::get) || PID.load(Ordering::Acquire) == 0 {
        return Ok(None);
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
        tokens.remove(&fd);
    }
    Ok(None)
}
fn call(id: u64, op: Op) -> Result<Reply> {
    runtime()?.call(id, op)
}
fn ffi(f: impl FnOnce() -> Result<i64>) -> i64 {
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
            retained,
            dev: st.st_dev,
            ino: st.st_ino,
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
fn wait(id: u64, events: i32) -> Result<()> {
    loop {
        if call(id, Op::Ready)?.value & (events | EPOLLERR | EPOLLHUP) != 0 {
            return Ok(());
        }
        let mut p = pollfd {
            fd: runtime()?.wake,
            events: POLLIN,
            revents: 0,
        };
        raw(unsafe { syscall(SYS_poll, &mut p, 1, 10) })?;
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
    loop {
        match call(id, op.clone()) {
            Err(EAGAIN) if !dontwait && blocking(id)? => wait(id, events)?,
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
    let p = unsafe { ptr::read_unaligned(p.cast::<sockaddr_in>()) };
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
    unsafe {
        ptr::copy_nonoverlapping(
            (&addr as *const sockaddr_in).cast::<u8>(),
            p.cast(),
            (*len as usize).min(size),
        );
        *len = size as u32;
    }
    Ok(())
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn socket(domain: i32, kind: i32, protocol: i32) -> i32 {
    ffi(|| {
        if INTERNAL.with(Cell::get)
            || !configured()
            || ![AF_INET, AF_INET6].contains(&domain)
            || kind & 0xf != SOCK_STREAM
        {
            return raw(unsafe { syscall(SYS_socket, domain, kind, protocol) });
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
pub unsafe extern "C" fn accept4(
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
        unsafe {
            output_addr(reply.addr.unwrap(), p, len)?;
        }
        install(newfd, t, reply.value as u64)
    }) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn accept(fd: i32, p: *mut sockaddr, len: *mut socklen_t) -> i32 {
    unsafe { accept4(fd, p, len, 0) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect(fd: i32, p: *const sockaddr, len: socklen_t) -> i32 {
    ffi(|| {
        let Some(id) = owned(fd)? else {
            return raw(unsafe { syscall(SYS_connect, fd, p, len) });
        };
        match call(id, Op::Connect(unsafe { address(p, len)? })) {
            Err(EINPROGRESS) if blocking(id)? => {
                wait(id, EPOLLOUT)?;
                let e = call(id, Op::Get(SOL_SOCKET, SO_ERROR))?.value;
                if e != 0 { Err(e) } else { Ok(0) }
            }
            r => r.map(|_| 0),
        }
    }) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn close(fd: i32) -> i32 {
    ffi(|| {
        if let Some(id) = owned(fd)? {
            let t = TOKENS.lock().map_err(|_| EIO)?.remove(&fd);
            // OS lifetime ends even when the engine runtime has failed.
            let closed = raw(unsafe { syscall(SYS_close, fd) });
            drop(t);
            readiness::closed(fd, id);
            let engine = call(id, Op::Close);
            closed?;
            engine?;
            Ok(0)
        } else {
            readiness::close_epoll(fd);
            raw(unsafe { syscall(SYS_close, fd) })
        }
    }) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shutdown(fd: i32, how: i32) -> i32 {
    ffi(|| match owned(fd)? {
        Some(id) => {
            call(id, Op::Shutdown(how))?;
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
    if flags & !(MSG_DONTWAIT | if write { MSG_NOSIGNAL } else { 0 }) != 0 {
        return Err(EOPNOTSUPP);
    }
    if n != 0 && p.is_null() {
        return Err(EFAULT);
    }
    if n > isize::MAX as usize {
        return Err(EINVAL);
    }
    let op = if write {
        Op::Write(if n == 0 {
            Vec::new()
        } else {
            unsafe { slice::from_raw_parts(p.cast::<u8>(), n.min(runtime::BYTES)).to_vec() }
        })
    } else {
        Op::Read(n.min(runtime::BYTES))
    };
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
    if !write && !reply.bytes.is_empty() {
        unsafe {
            ptr::copy_nonoverlapping(reply.bytes.as_ptr(), p.cast(), reply.bytes.len());
        }
    }
    Ok(reply.value as i64)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn send(fd: i32, p: *const c_void, n: usize, flags: i32) -> ssize_t {
    ffi(|| unsafe { transfer(fd, p.cast_mut(), n, flags, true) }) as ssize_t
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn recv(fd: i32, p: *mut c_void, n: usize, flags: i32) -> ssize_t {
    ffi(|| unsafe { transfer(fd, p, n, flags, false) }) as ssize_t
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn read(fd: i32, p: *mut c_void, n: usize) -> ssize_t {
    ffi(|| {
        if owned(fd)?.is_none() {
            raw(unsafe { syscall(SYS_read, fd, p, n) })
        } else {
            unsafe { transfer(fd, p, n, 0, false) }
        }
    }) as ssize_t
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __read_chk(fd: i32, p: *mut c_void, n: usize, size: usize) -> ssize_t {
    if n > size {
        unsafe {
            libc::abort();
        }
    }
    unsafe { read(fd, p, n) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn write(fd: i32, p: *const c_void, n: usize) -> ssize_t {
    ffi(|| {
        if owned(fd)?.is_none() {
            raw(unsafe { syscall(SYS_write, fd, p, n) })
        } else {
            unsafe { transfer(fd, p.cast_mut(), n, 0, true) }
        }
    }) as ssize_t
}
unsafe fn vectors(fd: i32, v: *const iovec, count: i32, flags: i32, write: bool) -> Result<i64> {
    if !(0..=1024).contains(&count) {
        return Err(EINVAL);
    }
    if count != 0 && v.is_null() {
        return Err(EFAULT);
    }
    let vectors = if count == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(v, count as usize) }
    };
    let mut total = 0usize;
    for v in vectors {
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
        for v in vectors {
            let n = v.iov_len.min(bytes.len() - offset);
            if n != 0 {
                unsafe {
                    ptr::copy_nonoverlapping(
                        v.iov_base.cast::<u8>(),
                        bytes[offset..].as_mut_ptr(),
                        n,
                    );
                }
            }
            offset += n;
            if offset == bytes.len() {
                break;
            }
        }
    }
    let n = unsafe { transfer(fd, bytes.as_mut_ptr().cast(), bytes.len(), flags, write) }?;
    if !write {
        let mut offset = 0;
        for v in vectors {
            let len = v.iov_len.min(n as usize - offset);
            if len != 0 {
                unsafe {
                    ptr::copy_nonoverlapping(
                        bytes[offset..].as_ptr(),
                        v.iov_base.cast::<u8>(),
                        len,
                    );
                }
            }
            offset += len;
            if offset == n as usize {
                break;
            }
        }
    }
    Ok(n)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn readv(fd: i32, v: *const iovec, n: i32) -> ssize_t {
    ffi(|| {
        if owned(fd)?.is_none() {
            raw(unsafe { syscall(SYS_readv, fd, v, n) })
        } else {
            unsafe { vectors(fd, v, n, 0, false) }
        }
    }) as ssize_t
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn writev(fd: i32, v: *const iovec, n: i32) -> ssize_t {
    ffi(|| {
        if owned(fd)?.is_none() {
            raw(unsafe { syscall(SYS_writev, fd, v, n) })
        } else {
            unsafe { vectors(fd, v, n, 0, true) }
        }
    }) as ssize_t
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sendmsg(fd: i32, p: *const msghdr, flags: i32) -> ssize_t {
    ffi(|| {
        if owned(fd)?.is_none() {
            return raw(unsafe { syscall(SYS_sendmsg, fd, p, flags) });
        }
        if p.is_null() {
            return Err(EFAULT);
        }
        let m = unsafe { &*p };
        if m.msg_controllen != 0 || !m.msg_name.is_null() {
            return Err(EOPNOTSUPP);
        }
        let n = i32::try_from(m.msg_iovlen).map_err(|_| EINVAL)?;
        unsafe { vectors(fd, m.msg_iov, n, flags, true) }
    }) as ssize_t
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn recvmsg(fd: i32, p: *mut msghdr, flags: i32) -> ssize_t {
    ffi(|| {
        let Some(id) = owned(fd)? else {
            return raw(unsafe { syscall(SYS_recvmsg, fd, p, flags) });
        };
        if p.is_null() {
            return Err(EFAULT);
        }
        let m = unsafe { &mut *p };
        let n = i32::try_from(m.msg_iovlen).map_err(|_| EINVAL)?;
        let result = unsafe { vectors(fd, m.msg_iov, n, flags, false) }?;
        if !m.msg_name.is_null() {
            unsafe {
                output_addr(
                    call(id, Op::Name(true))?.addr.unwrap(),
                    m.msg_name.cast(),
                    &mut m.msg_namelen,
                )?;
            }
        }
        m.msg_controllen = 0;
        m.msg_flags = 0;
        Ok(result)
    }) as ssize_t
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sendto(
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
pub unsafe extern "C" fn recvfrom(
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
        let result = unsafe { transfer(fd, p, n, flags, false) }?;
        if !addr.is_null() {
            unsafe {
                output_addr(call(id, Op::Name(true))?.addr.unwrap(), addr, len)?;
            }
        }
        Ok(result)
    }) as ssize_t
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
        if len < 4 {
            return Err(EINVAL);
        }
        let value = unsafe { ptr::read_unaligned(p.cast::<i32>()) };
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
        let value = call(id, Op::Get(level, name))?.value.to_ne_bytes();
        unsafe {
            let n = (*len as usize).min(4);
            ptr::copy_nonoverlapping(value.as_ptr(), p.cast(), n);
            *len = n as u32;
        }
        Ok(0)
    }) as i32
}
#[unsafe(no_mangle)]
pub extern "C" fn ntcp_fcntl_dispatch(fd: i32, cmd: i32, arg: c_ulong) -> i32 {
    ffi(|| {
        let Some(id) = owned(fd)? else {
            if [F_DUPFD, F_DUPFD_CLOEXEC].contains(&cmd) && readiness::is_epoll(fd)? {
                return Err(EOPNOTSUPP);
            }
            return raw(unsafe { syscall(SYS_fcntl, fd, cmd, arg) });
        };
        match cmd {
            F_GETFL | F_SETFL => Ok(call(id, Op::Flags(cmd, arg as i32))?.value as i64),
            F_GETFD | F_SETFD => raw(unsafe { syscall(SYS_fcntl, fd, cmd, arg) }),
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
                let n = unsafe { ptr::read_unaligned(arg as *const i32) };
                call(id, Op::Flags(F_SETFL, if n != 0 { O_NONBLOCK } else { 0 }))?;
                Ok(0)
            }
            FIONREAD => {
                if arg == 0 {
                    return Err(EFAULT);
                }
                unsafe {
                    ptr::write_unaligned(arg as *mut i32, call(id, Op::Available)?.value);
                }
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dup(fd: i32) -> i32 {
    ffi(|| {
        if owned(fd)?.is_some() || readiness::is_epoll(fd)? {
            return Err(EOPNOTSUPP);
        }
        raw(unsafe { syscall(SYS_dup, fd) })
    }) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dup2(fd: i32, new: i32) -> i32 {
    ffi(|| {
        if fd == new {
            return raw(unsafe { syscall(SYS_dup2, fd, new) });
        }
        if owned(fd)?.is_some()
            || owned(new)?.is_some()
            || readiness::is_epoll(fd)?
            || readiness::is_epoll(new)?
        {
            return Err(EOPNOTSUPP);
        }
        raw(unsafe { syscall(SYS_dup2, fd, new) })
    }) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dup3(fd: i32, new: i32, flags: i32) -> i32 {
    ffi(|| {
        if owned(fd)?.is_some()
            || owned(new)?.is_some()
            || readiness::is_epoll(fd)?
            || readiness::is_epoll(new)?
        {
            return Err(EOPNOTSUPP);
        }
        raw(unsafe { syscall(SYS_dup3, fd, new, flags) })
    }) as i32
}

#[cfg(test)]
mod tests {
    use super::*;
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
