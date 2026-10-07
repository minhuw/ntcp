use crate::*;
use std::time::{Duration, Instant};
const LIMIT: usize = 4096;
#[derive(Clone, Copy)]
struct Registration {
    fd: i32,
    id: u64,
    events: u32,
    data: u64,
}
struct Epoll {
    slot: usize,
    retained: i32,
    dev: dev_t,
    ino: ino_t,
    regs: BTreeMap<i32, Registration>,
    cursor: usize,
    native_first: bool,
}
impl Epoll {
    fn matches(&self, fd: i32) -> bool {
        let mut st: stat = unsafe { std::mem::zeroed() };
        // anon_inode epolls share inode numbers, so fstat only rejects non-epoll
        // reuse. Interposed close/dup paths enforce lifecycle; direct syscall mutation
        // of managed descriptors is outside this adapter's contract.
        unsafe {
            syscall(SYS_fstat, fd, &mut st) == 0 && st.st_dev == self.dev && st.st_ino == self.ino
        }
    }
}
impl Drop for Epoll {
    fn drop(&mut self) {
        EPOLL_FDS[self.slot].store(-1, Ordering::Release);
        unsafe {
            syscall(SYS_close, self.retained);
        }
    }
}
static EPOLL_FDS: [AtomicI32; runtime::LIMIT] = [const { AtomicI32::new(-1) }; runtime::LIMIT];
static EPOLLS: Mutex<BTreeMap<i32, Epoll>> = Mutex::new(BTreeMap::new());
pub fn is_epoll(fd: i32) -> Result<bool> {
    if INTERNAL.with(Cell::get) || PID.load(Ordering::Acquire) == 0 {
        return Ok(false);
    }
    if child() {
        return if inherited(&EPOLL_FDS, fd) {
            Err(EOWNERDEAD)
        } else {
            Ok(false)
        };
    }
    Ok(EPOLLS.lock().map_err(|_| EIO)?.contains_key(&fd))
}
pub fn close_epoll(fd: i32) {
    if INTERNAL.with(Cell::get) || child() || PID.load(Ordering::Acquire) == 0 {
        return;
    }
    if let Ok(mut map) = EPOLLS.lock() {
        map.remove(&fd);
    }
}
pub fn closed(fd: i32, id: u64) {
    if let Ok(mut map) = EPOLLS.lock() {
        for ep in map.values_mut() {
            if ep.regs.get(&fd).is_some_and(|r| r.id == id) {
                ep.regs.remove(&fd);
            }
        }
    }
}
fn remaining(deadline: Option<Instant>) -> i32 {
    deadline.map_or(-1, |d| {
        d.saturating_duration_since(Instant::now())
            .as_millis()
            .min(i32::MAX as u128) as i32
    })
}
fn deadline(timeout: i32) -> Option<Instant> {
    (timeout >= 0).then(|| Instant::now() + Duration::from_millis(timeout as u64))
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn epoll_create(size: i32) -> i32 {
    ffi(|| {
        if size <= 0 {
            Err(EINVAL)
        } else {
            raw(unsafe { syscall(SYS_epoll_create, size) })
        }
    }) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn epoll_create1(flags: i32) -> i32 {
    ffi(|| raw(unsafe { syscall(SYS_epoll_create1, flags) })) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn epoll_ctl(epfd: i32, op: i32, fd: i32, p: *mut epoll_event) -> i32 {
    ffi(|| {
        let Some(id) = owned(fd)? else {
            if is_epoll(fd)? {
                return Err(EOPNOTSUPP);
            }
            return raw(unsafe { syscall(SYS_epoll_ctl, epfd, op, fd, p) });
        };
        if fd == epfd {
            return Err(EINVAL);
        }
        if op != EPOLL_CTL_DEL && p.is_null() {
            return Err(EFAULT);
        }
        let event = if op != EPOLL_CTL_DEL {
            unsafe { ptr::read_unaligned(p) }
        } else {
            epoll_event { events: 0, u64: 0 }
        };
        if event.events
            & !(EPOLLIN as u32
                | EPOLLOUT as u32
                | EPOLLERR as u32
                | EPOLLHUP as u32
                | EPOLLRDHUP as u32)
            != 0
        {
            return Err(EOPNOTSUPP);
        }
        let mut map = EPOLLS.lock().map_err(|_| EIO)?;
        if map.get(&epfd).is_some_and(|ep| !ep.matches(epfd)) {
            map.remove(&epfd);
        }
        if !map.contains_key(&epfd) {
            if map.len() == runtime::LIMIT {
                return Err(ENOSPC);
            }
            // A private, empty eventfd validates epfd without leaking a ready
            // wake event to concurrent native epoll_wait callers.
            let probe = raw(unsafe { syscall(SYS_eventfd2, 0, EFD_CLOEXEC) })? as i32;
            let event = epoll_event { events: 0, u64: 0 };
            let validated =
                raw(unsafe { syscall(SYS_epoll_ctl, epfd, EPOLL_CTL_ADD, probe, &event) });
            if validated.is_ok() {
                unsafe {
                    syscall(
                        SYS_epoll_ctl,
                        epfd,
                        EPOLL_CTL_DEL,
                        probe,
                        ptr::null::<epoll_event>(),
                    );
                }
            }
            unsafe {
                syscall(SYS_close, probe);
            }
            validated?;
            let retained = unsafe { syscall(SYS_fcntl, epfd, F_DUPFD_CLOEXEC, 0) as i32 };
            if retained < 0 {
                return Err(errno());
            }
            let mut st: stat = unsafe { std::mem::zeroed() };
            unsafe {
                syscall(SYS_fstat, epfd, &mut st);
            }
            map.insert(
                epfd,
                Epoll {
                    slot: reserve_fd(&EPOLL_FDS, epfd)?,
                    retained,
                    dev: st.st_dev,
                    ino: st.st_ino,
                    regs: BTreeMap::new(),
                    cursor: 0,
                    native_first: false,
                },
            );
        }
        let ep = map.get_mut(&epfd).unwrap();
        match op {
            EPOLL_CTL_ADD => {
                if ep.regs.contains_key(&fd) {
                    return Err(EEXIST);
                }
                if ep.regs.len() == LIMIT {
                    return Err(ENOSPC);
                }
                ep.regs.insert(
                    fd,
                    Registration {
                        fd,
                        id,
                        events: event.events,
                        data: event.u64,
                    },
                );
            }
            EPOLL_CTL_MOD => {
                let r = ep.regs.get_mut(&fd).ok_or(ENOENT)?;
                *r = Registration {
                    fd,
                    id,
                    events: event.events,
                    data: event.u64,
                };
            }
            EPOLL_CTL_DEL => {
                ep.regs.remove(&fd).ok_or(ENOENT)?;
            }
            _ => return Err(EINVAL),
        }
        Ok(0)
    }) as i32
}
unsafe fn epwait(
    epfd: i32,
    p: *mut epoll_event,
    max: i32,
    timeout: i32,
    mask: *const sigset_t,
) -> Result<i64> {
    if INTERNAL.with(Cell::get) {
        return raw(unsafe { syscall(SYS_epoll_pwait, epfd, p, max, timeout, mask, 8) });
    }
    if child() {
        return if inherited(&EPOLL_FDS, epfd) {
            Err(EOWNERDEAD)
        } else {
            raw(unsafe { syscall(SYS_epoll_pwait, epfd, p, max, timeout, mask, 8) })
        };
    }
    if p.is_null() {
        return Err(EFAULT);
    }
    if max <= 0 {
        return Err(EINVAL);
    }
    if !is_epoll(epfd)? {
        return raw(unsafe { syscall(SYS_epoll_pwait, epfd, p, max, timeout, mask, 8) });
    }
    if !mask.is_null() {
        return Err(EOPNOTSUPP);
    }
    let native_first = {
        let mut map = EPOLLS.lock().map_err(|_| EIO)?;
        let ep = map.get_mut(&epfd).ok_or(EBADF)?;
        ep.native_first = !ep.native_first;
        ep.native_first
    };
    let deadline = deadline(timeout);
    // ponytail: bounded 10ms readiness polling; use private wake epoll if latency matters.
    // Bounded result storage independent of the caller's maxevents.
    let cap = (max as usize).min(LIMIT);
    let mut native = vec![epoll_event { events: 0, u64: 0 }; cap];
    loop {
        let regs = {
            let mut map = EPOLLS.lock().map_err(|_| EIO)?;
            let ep = map.get_mut(&epfd).ok_or(EBADF)?;
            let mut regs: Vec<_> = ep.regs.values().copied().collect();
            if !regs.is_empty() {
                let len = regs.len();
                regs.rotate_left(ep.cursor % len);
                ep.cursor = (ep.cursor + cap) % len;
            }
            regs
        };
        let mut count = 0;
        if native_first {
            count =
                raw(unsafe { syscall(SYS_epoll_pwait, epfd, p, cap as i32, 0, mask, 8) })? as usize;
            if count == cap {
                return Ok(count as i64);
            }
        }
        let native_delivered = count != 0;
        for r in regs {
            if owned(r.fd)? != Some(r.id) {
                continue;
            }
            let ready = call(r.id, Op::Ready)?.value as u32
                & (r.events | EPOLLERR as u32 | EPOLLHUP as u32);
            if ready != 0 {
                unsafe {
                    ptr::write_unaligned(
                        p.add(count),
                        epoll_event {
                            events: ready,
                            u64: r.data,
                        },
                    );
                }
                count += 1;
                if count == cap {
                    break;
                }
            }
        }
        let wait = if count != 0 || timeout == 0 {
            0
        } else {
            remaining(deadline).clamp(0, 10)
        };
        let wait = if deadline.is_none() && count == 0 && timeout != 0 {
            10
        } else {
            wait
        };
        let n = if count == cap || native_delivered {
            0
        } else {
            raw(unsafe {
                syscall(
                    SYS_epoll_pwait,
                    epfd,
                    native.as_mut_ptr(),
                    (cap - count) as i32,
                    wait,
                    mask,
                    8,
                )
            })? as usize
        };
        for e in &native[..n] {
            if count < cap {
                unsafe {
                    ptr::write_unaligned(p.add(count), *e);
                }
                count += 1;
            }
        }
        if count != 0 {
            return Ok(count as i64);
        }
        if timeout == 0 || deadline.is_some_and(|d| Instant::now() >= d) {
            return Ok(0);
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn epoll_wait(epfd: i32, p: *mut epoll_event, max: i32, timeout: i32) -> i32 {
    ffi(|| unsafe { epwait(epfd, p, max, timeout, ptr::null()) }) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn epoll_pwait(
    epfd: i32,
    p: *mut epoll_event,
    max: i32,
    timeout: i32,
    mask: *const sigset_t,
) -> i32 {
    ffi(|| unsafe { epwait(epfd, p, max, timeout, mask) }) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poll(p: *mut pollfd, n: nfds_t, timeout: i32) -> i32 {
    ffi(|| unsafe { poll_impl(p, n, timeout, ptr::null()) }) as i32
}
unsafe fn poll_impl(p: *mut pollfd, n: nfds_t, timeout: i32, mask: *const sigset_t) -> Result<i64> {
    if INTERNAL.with(Cell::get) {
        return raw(unsafe { syscall(SYS_poll, p, n, timeout) });
    }
    if !configured() {
        return raw(unsafe { syscall(SYS_poll, p, n, timeout) });
    }
    let mut limit: rlimit = unsafe { std::mem::zeroed() };
    raw(unsafe { syscall(SYS_getrlimit, RLIMIT_NOFILE, &mut limit) })?;
    if n > limit.rlim_cur || n as usize > isize::MAX as usize / std::mem::size_of::<pollfd>() {
        return Err(EINVAL);
    }
    if n != 0 && p.is_null() {
        return Err(EFAULT);
    }
    let original = if n == 0 {
        &mut []
    } else {
        unsafe { slice::from_raw_parts_mut(p, n as usize) }
    };
    let mut owned_fds = Vec::new();
    for (i, fd) in original.iter().enumerate() {
        if let Some(id) = owned(fd.fd)? {
            if owned_fds.len() == LIMIT {
                return Err(EINVAL);
            }
            owned_fds.push((i, id));
        }
    }
    if owned_fds.is_empty() {
        return raw(unsafe { syscall(SYS_poll, p, n, timeout) });
    }
    if original.len() > LIMIT {
        return Err(EINVAL);
    }
    let mut native = original.to_vec();
    for &(i, _) in &owned_fds {
        native[i].fd = -1;
    }
    let deadline = deadline(timeout);
    loop {
        for p in original.iter_mut() {
            p.revents = 0;
        }
        let mut virtual_ready = false;
        for &(i, id) in &owned_fds {
            let requested = original[i].events;
            if requested
                & !(POLLIN
                    | POLLOUT
                    | POLLRDNORM
                    | POLLWRNORM
                    | POLLRDHUP
                    | POLLERR
                    | POLLHUP
                    | POLLNVAL)
                != 0
            {
                return Err(EOPNOTSUPP);
            }
            let revents = if owned(original[i].fd)? != Some(id) {
                POLLNVAL
            } else {
                poll_events(call(id, Op::Ready)?.value, requested)
            };
            original[i].revents = revents;
            virtual_ready |= revents != 0;
        }
        let ms = if virtual_ready || timeout == 0 {
            0
        } else if deadline.is_none() {
            10
        } else {
            remaining(deadline).clamp(0, 10)
        };
        let ts = timespec {
            tv_sec: 0,
            tv_nsec: ms as i64 * 1_000_000,
        };
        raw(unsafe { syscall(SYS_ppoll, native.as_mut_ptr(), n, &ts, mask, 8) })?;
        for (i, fd) in native.iter().enumerate() {
            original[i].revents |= fd.revents;
        }
        let count = original.iter().filter(|p| p.revents != 0).count();
        if count != 0 {
            return Ok(count as i64);
        }
        if timeout == 0 || deadline.is_some_and(|d| Instant::now() >= d) {
            return Ok(0);
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn select(
    n: i32,
    r: *mut fd_set,
    w: *mut fd_set,
    e: *mut fd_set,
    t: *mut timeval,
) -> i32 {
    ffi(|| {
        if n < 0 || n > FD_SETSIZE as i32 {
            return Err(EINVAL);
        }
        let mut polls = Vec::new();
        for fd in 0..n {
            let mut events = 0;
            unsafe {
                if !r.is_null() && FD_ISSET(fd, r) {
                    events |= POLLIN;
                }
                if !w.is_null() && FD_ISSET(fd, w) {
                    events |= POLLOUT;
                }
                if !e.is_null() && FD_ISSET(fd, e) {
                    events |= POLLPRI;
                }
            }
            if events != 0 {
                polls.push(pollfd {
                    fd,
                    events,
                    revents: 0,
                });
            }
        }
        let mut virtual_fd = false;
        for p in &polls {
            virtual_fd |= owned(p.fd)?.is_some();
        }
        if !virtual_fd {
            return raw(unsafe { syscall(SYS_select, n, r, w, e, t) });
        }
        let timeout = if t.is_null() {
            -1
        } else {
            let t = unsafe { &*t };
            if t.tv_sec < 0 || t.tv_usec < 0 || t.tv_usec >= 1_000_000 {
                return Err(EINVAL);
            }
            (t.tv_sec.saturating_mul(1000) + ((t.tv_usec + 999) / 1000)).min(i32::MAX as i64) as i32
        };
        let started = Instant::now();
        let result = unsafe {
            poll_impl(
                polls.as_mut_ptr(),
                polls.len() as nfds_t,
                timeout,
                ptr::null(),
            )
        };
        if !t.is_null() {
            let left = Duration::from_millis(timeout as u64).saturating_sub(started.elapsed());
            unsafe {
                (*t).tv_sec = left.as_secs() as time_t;
                (*t).tv_usec = left.subsec_micros() as suseconds_t;
            }
        }
        result?;
        if polls.iter().any(|p| p.revents & POLLNVAL != 0) {
            return Err(EBADF);
        }
        unsafe {
            if !r.is_null() {
                FD_ZERO(r);
            }
            if !w.is_null() {
                FD_ZERO(w);
            }
            if !e.is_null() {
                FD_ZERO(e);
            }
        }
        let mut count = 0;
        for p in polls {
            unsafe {
                if !r.is_null()
                    && p.events & POLLIN != 0
                    && p.revents & (POLLIN | POLLHUP | POLLERR) != 0
                {
                    FD_SET(p.fd, r);
                    count += 1;
                }
                if !w.is_null() && p.events & POLLOUT != 0 && p.revents & (POLLOUT | POLLERR) != 0 {
                    FD_SET(p.fd, w);
                    count += 1;
                }
                if !e.is_null() && p.events & POLLPRI != 0 && p.revents & POLLPRI != 0 {
                    FD_SET(p.fd, e);
                    count += 1;
                }
            }
        }
        Ok(count)
    }) as i32
}

fn poll_events(bits: i32, requested: i16) -> i16 {
    let mut result = 0;
    if bits & EPOLLIN != 0 {
        result |= requested & (POLLIN | POLLRDNORM);
    }
    if bits & EPOLLOUT != 0 {
        result |= requested & (POLLOUT | POLLWRNORM);
    }
    if bits & EPOLLERR != 0 {
        result |= POLLERR;
    }
    if bits & EPOLLHUP != 0 {
        result |= POLLHUP;
    }
    if bits & EPOLLRDHUP != 0 {
        result |= requested & POLLRDHUP;
    }
    result
}
// These adjacent readiness APIs must not accidentally consult the OS token's
// AF_UNIX state. Signal-mask/time-nanosecond variants are deliberately unsupported
// for virtual sockets; native calls retain their kernel ABI.
unsafe fn virtual_poll(p: *const pollfd, n: nfds_t) -> Result<bool> {
    if INTERNAL.with(Cell::get) {
        return Ok(false);
    }
    if n != 0 && p.is_null() {
        return Err(EFAULT);
    }
    if n as usize > isize::MAX as usize / std::mem::size_of::<pollfd>() {
        return Err(EINVAL);
    }
    if !configured() {
        return Ok(false);
    }
    for i in 0..n as usize {
        if owned(unsafe { (*p.add(i)).fd })?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ppoll(
    p: *mut pollfd,
    n: nfds_t,
    t: *const timespec,
    mask: *const sigset_t,
) -> i32 {
    ffi(|| {
        if unsafe { virtual_poll(p, n)? } {
            return Err(EOPNOTSUPP);
        }
        // Kernel ppoll mutates timeout; libc's interface does not.
        let mut timeout = if t.is_null() {
            timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }
        } else {
            unsafe { *t }
        };
        raw(unsafe {
            syscall(
                SYS_ppoll,
                p,
                n,
                if t.is_null() {
                    ptr::null_mut()
                } else {
                    &mut timeout
                },
                mask,
                8,
            )
        })
    }) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pselect(
    n: i32,
    r: *mut fd_set,
    w: *mut fd_set,
    e: *mut fd_set,
    t: *const timespec,
    mask: *const sigset_t,
) -> i32 {
    ffi(|| {
        if configured() && !INTERNAL.with(Cell::get) {
            if n < 0 || n > FD_SETSIZE as i32 {
                return Err(EINVAL);
            }
            for fd in 0..n {
                let set = unsafe {
                    (!r.is_null() && FD_ISSET(fd, r))
                        || (!w.is_null() && FD_ISSET(fd, w))
                        || (!e.is_null() && FD_ISSET(fd, e))
                };
                if set && owned(fd)?.is_some() {
                    return Err(EOPNOTSUPP);
                }
            }
        }
        #[repr(C)]
        struct Mask {
            ptr: *const sigset_t,
            len: usize,
        }
        let mask = Mask { ptr: mask, len: 8 };
        let mut timeout = if t.is_null() {
            timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }
        } else {
            unsafe { *t }
        };
        raw(unsafe {
            syscall(
                SYS_pselect6,
                n,
                r,
                w,
                e,
                if t.is_null() {
                    ptr::null_mut()
                } else {
                    &mut timeout
                },
                &mask,
            )
        })
    }) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn epoll_pwait2(
    epfd: i32,
    p: *mut epoll_event,
    max: i32,
    t: *const timespec,
    mask: *const sigset_t,
) -> i32 {
    ffi(|| {
        if is_epoll(epfd)? {
            return Err(EOPNOTSUPP);
        }
        raw(unsafe { syscall(SYS_epoll_pwait2, epfd, p, max, t, mask, 8) })
    }) as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requested_readiness_and_unconditional_terminal_events() {
        assert_eq!(poll_events(EPOLLIN | EPOLLOUT, POLLIN), POLLIN);
        assert_eq!(poll_events(EPOLLIN | EPOLLOUT, POLLOUT), POLLOUT);
        assert_eq!(poll_events(EPOLLIN | EPOLLRDHUP, 0), 0);
        assert_eq!(
            poll_events(EPOLLIN | EPOLLRDHUP, POLLIN | POLLRDHUP),
            POLLIN | POLLRDHUP
        );
        assert_eq!(poll_events(EPOLLERR | EPOLLHUP, 0), POLLERR | POLLHUP);
    }
}
