use crate::*;
use std::time::{Duration, Instant};
const LIMIT: usize = 4096;
#[derive(Clone, Copy)]
struct Registration {
    id: u64,
    generation: u64,
    armed: bool,
    events: u32,
    data: u64,
}
struct Epoll {
    slot: usize,
    retained: i32,
    dev: dev_t,
    ino: ino_t,
    regs: BTreeMap<(i32, u64), Registration>,
    generation: u64,
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
    if !inherited(&EPOLL_FDS, fd) {
        return Ok(false);
    }
    mutation_context()?;
    Ok(EPOLLS.lock().map_err(|_| EIO)?.contains_key(&fd))
}
pub fn tracked_epoll(fd: i32) -> bool {
    inherited(&EPOLL_FDS, fd)
}
pub fn close_epoll(fd: i32) -> Result<()> {
    if !inherited(&EPOLL_FDS, fd) {
        return Ok(());
    }
    is_epoll(fd)?;
    EPOLLS.lock().map_err(|_| EIO)?.remove(&fd);
    Ok(())
}
pub fn closed(id: u64) {
    if let Ok(mut map) = EPOLLS.lock() {
        for ep in map.values_mut() {
            ep.regs.retain(|&(_, registered_id), _| registered_id != id);
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
pub unsafe extern "C" fn ntcp_managed_epoll_create(size: i32) -> i32 {
    ffi(|| {
        if size <= 0 {
            Err(EINVAL)
        } else {
            raw(unsafe { syscall(SYS_epoll_create, size) })
        }
    }) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_epoll_create1(flags: i32) -> i32 {
    ffi(|| raw(unsafe { syscall(SYS_epoll_create1, flags) })) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_epoll_ctl(
    epfd: i32,
    op: i32,
    fd: i32,
    p: *mut epoll_event,
) -> i32 {
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
            load(p)?
        } else {
            epoll_event { events: 0, u64: 0 }
        };
        if event.events
            & !(EPOLLIN as u32
                | EPOLLOUT as u32
                | EPOLLERR as u32
                | EPOLLHUP as u32
                | EPOLLRDHUP as u32
                | EPOLLONESHOT as u32)
            != 0
        {
            return Err(EOPNOTSUPP);
        }
        // Lock order is TOKENS -> EPOLLS. Pin this alias through registration
        // so a concurrent final close cannot clean up before our ADD commits.
        // Neither registry is held across an owner RPC.
        let tokens = TOKENS.lock().map_err(|_| EIO)?;
        if !tokens.get(&fd).is_some_and(|t| t.id == id && t.matches(fd)) {
            return Err(EBADF);
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
                    generation: 0,
                    cursor: 0,
                    native_first: false,
                },
            );
        }
        let ep = map.get_mut(&epfd).unwrap();
        ep.generation = ep.generation.wrapping_add(1);
        let generation = ep.generation;
        let key = (fd, id);
        match op {
            EPOLL_CTL_ADD => {
                if ep.regs.contains_key(&key) {
                    return Err(EEXIST);
                }
                if ep.regs.len() == LIMIT {
                    return Err(ENOSPC);
                }
                ep.regs.insert(
                    key,
                    Registration {
                        id,
                        generation,
                        armed: true,
                        events: event.events,
                        data: event.u64,
                    },
                );
            }
            EPOLL_CTL_MOD => {
                let r = ep.regs.get_mut(&key).ok_or(ENOENT)?;
                *r = Registration {
                    id,
                    generation,
                    armed: true,
                    events: event.events,
                    data: event.u64,
                };
            }
            EPOLL_CTL_DEL => {
                ep.regs.remove(&key).ok_or(ENOENT)?;
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
    if !is_epoll(epfd)? {
        return raw(unsafe { syscall(SYS_epoll_pwait, epfd, p, max, timeout, mask, 8) });
    }
    if max <= 0 {
        return Err(EINVAL);
    }
    if p.is_null() {
        return Err(EFAULT);
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
    loop {
        let regs = {
            let mut map = EPOLLS.lock().map_err(|_| EIO)?;
            let ep = map.get_mut(&epfd).ok_or(EBADF)?;
            let mut regs: Vec<_> = ep.regs.iter().map(|(&key, &r)| (key, r)).collect();
            if !regs.is_empty() {
                let len = regs.len();
                regs.rotate_left(ep.cursor % len);
                ep.cursor = (ep.cursor + cap) % len;
            }
            regs
        };
        // Keep native-first copyout in the kernel: native ONESHOT must retain
        // its existing fault handling rather than disarm in a staging buffer.
        let native_count = if native_first {
            raw(unsafe { syscall(SYS_epoll_pwait, epfd, p, cap as i32, 0, mask, 8) })? as usize
        } else {
            0
        };
        if native_count == cap {
            return Ok(native_count as i64);
        }
        let mut virtual_events = Vec::new();
        for (key, r) in regs {
            if !r.armed || !live_id(r.id)? {
                continue;
            }
            let ready = match call(r.id, Op::Ready) {
                Ok(reply) => reply.value as u32,
                Err(EBADF) => continue, // Last alias closed during the query.
                Err(_) if native_count != 0 => return Ok(native_count as i64),
                Err(e) => return Err(e),
            } & (r.events | EPOLLERR as u32 | EPOLLHUP as u32);
            if ready != 0 {
                virtual_events.push((
                    key,
                    r.generation,
                    epoll_event {
                        events: ready,
                        u64: r.data,
                    },
                ));
            }
        }
        let wait = if native_count != 0 || !virtual_events.is_empty() || timeout == 0 {
            0
        } else if deadline.is_none() {
            10
        } else {
            remaining(deadline).clamp(0, 10)
        };
        let available = cap - native_count;
        // Serialize copyout + disarming with MOD and competing waiters. No owner
        // RPC or socket registry lock is taken while EPOLLS is held.
        let mut map = EPOLLS.lock().map_err(|_| EIO)?;
        let ep = map.get_mut(&epfd).ok_or(EBADF)?;
        virtual_events.retain(|(key, generation, _)| {
            ep.regs
                .get(key)
                .is_some_and(|r| r.armed && r.generation == *generation)
        });
        let mut output = Vec::with_capacity(available);
        let mut delivered = Vec::new();
        for (key, generation, event) in virtual_events {
            if output.len() == available {
                break;
            }
            output.push(event);
            delivered.push((key, generation));
        }
        if let Err(e) = store_array(p.wrapping_add(native_count), &output) {
            return if native_count != 0 {
                Ok(native_count as i64)
            } else {
                Err(e)
            };
        }
        for (key, generation) in delivered {
            if let Some(r) = ep.regs.get_mut(&key)
                && r.generation == generation
                && r.events & EPOLLONESHOT as u32 != 0
            {
                r.armed = false;
            }
        }
        drop(map);
        let delivered = native_count + output.len();
        // Virtual-first must finish faultable copyout before consuming native
        // ONESHOT. Let the kernel copy directly to the remaining caller buffer.
        let native_cap = cap - delivered;
        let n = if native_cap == 0 || native_count != 0 {
            0
        } else {
            match raw(unsafe {
                syscall(
                    SYS_epoll_pwait,
                    epfd,
                    p.wrapping_add(delivered),
                    native_cap as i32,
                    wait,
                    mask,
                    8,
                )
            }) {
                Ok(n) => n as usize,
                Err(_) if delivered != 0 => return Ok(delivered as i64),
                Err(e) => return Err(e),
            }
        };
        if delivered + n != 0 {
            return Ok((delivered + n) as i64);
        }
        if timeout == 0 || deadline.is_some_and(|d| Instant::now() >= d) {
            return Ok(0);
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_epoll_wait(
    epfd: i32,
    p: *mut epoll_event,
    max: i32,
    timeout: i32,
) -> i32 {
    ffi(|| unsafe { epwait(epfd, p, max, timeout, ptr::null()) }) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_epoll_pwait(
    epfd: i32,
    p: *mut epoll_event,
    max: i32,
    timeout: i32,
    mask: *const sigset_t,
) -> i32 {
    ffi(|| unsafe { epwait(epfd, p, max, timeout, mask) }) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_poll(p: *mut pollfd, n: nfds_t, timeout: i32) -> i32 {
    ffi(|| unsafe { poll_impl(p, n, timeout, ptr::null()) }) as i32
}
unsafe fn poll_impl(p: *mut pollfd, n: nfds_t, timeout: i32, mask: *const sigset_t) -> Result<i64> {
    // Inspect on bounded stack storage before any allocation or registry lock;
    // native readiness stays callable from an interrupted interposed operation.
    if !any_sockets() || !unsafe { large_poll_virtual(p, n)? } {
        return raw(unsafe { syscall(SYS_poll, p, n, timeout) });
    }
    if n > LIMIT as nfds_t {
        return Err(EINVAL);
    }
    let mut original = load_array(p, poll_count(n)?, LIMIT)?;
    let mut owned_fds = Vec::new();
    for (i, fd) in original.iter().enumerate() {
        if let Some(id) = owned(fd.fd)? {
            owned_fds.push((i, id));
        }
    }
    if owned_fds.is_empty() {
        return raw(unsafe { syscall(SYS_poll, p, n, timeout) });
    }
    let mut native = original.clone();
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
        if count != 0 || timeout == 0 || deadline.is_some_and(|d| Instant::now() >= d) {
            store_array(p, &original)?;
            return Ok(count as i64);
        }
    }
}
fn any_sockets() -> bool {
    SOCKET_FDS.iter().any(|fd| fd.load(Ordering::Acquire) >= 0)
}
fn select_maybe_virtual(n: i32) -> bool {
    SOCKET_FDS.iter().any(|fd| {
        let fd = fd.load(Ordering::Acquire);
        fd >= 0 && fd < n
    })
}
fn large_select_virtual(n: i32, sets: [*const fd_set; 3]) -> Result<bool> {
    for slot in &SOCKET_FDS {
        let fd = slot.load(Ordering::Acquire);
        if fd < 0 || fd >= n {
            continue;
        }
        for set in sets {
            if set.is_null() {
                continue;
            }
            let word = load(set.cast::<u64>().wrapping_add(fd as usize / 64))?;
            if word & (1u64 << (fd % 64)) != 0 && owned(fd)?.is_some() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
fn input_set(p: *const fd_set, n: i32) -> Result<fd_set> {
    let mut set: fd_set = unsafe { std::mem::zeroed() };
    if !p.is_null() {
        let size = (n as usize).div_ceil(64) * 8;
        memory(
            (&mut set as *mut fd_set).cast(),
            p.cast_mut().cast(),
            size,
            false,
        )?;
    }
    Ok(set)
}
fn output_set(p: *mut fd_set, set: &fd_set, n: i32) -> Result<()> {
    if !p.is_null() {
        memory(
            (set as *const fd_set).cast_mut().cast(),
            p.cast(),
            (n as usize).div_ceil(64) * 8,
            true,
        )?;
    }
    Ok(())
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_select(
    n: i32,
    r: *mut fd_set,
    w: *mut fd_set,
    e: *mut fd_set,
    t: *mut timeval,
) -> i32 {
    ffi(|| {
        if !select_maybe_virtual(n) || !large_select_virtual(n, [r, w, e])? {
            return raw(unsafe { syscall(SYS_select, n, r, w, e, t) });
        }
        if n > FD_SETSIZE as i32 {
            return Err(EINVAL);
        }
        let mut rs = input_set(r, n)?;
        let mut ws = input_set(w, n)?;
        let mut es = input_set(e, n)?;
        let mut polls = Vec::new();
        for fd in 0..n {
            let mut events = 0;
            unsafe {
                if !r.is_null() && FD_ISSET(fd, &rs) {
                    events |= POLLIN;
                }
                if !w.is_null() && FD_ISSET(fd, &ws) {
                    events |= POLLOUT;
                }
                if !e.is_null() && FD_ISSET(fd, &es) {
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
            let t = load(t)?;
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
            store(
                t,
                &timeval {
                    tv_sec: left.as_secs() as time_t,
                    tv_usec: left.subsec_micros() as suseconds_t,
                },
            )?;
        }
        result?;
        if polls.iter().any(|p| p.revents & POLLNVAL != 0) {
            return Err(EBADF);
        }
        unsafe {
            if !r.is_null() {
                FD_ZERO(&mut rs);
            }
            if !w.is_null() {
                FD_ZERO(&mut ws);
            }
            if !e.is_null() {
                FD_ZERO(&mut es);
            }
        }
        let mut count = 0;
        for p in polls {
            unsafe {
                if !r.is_null()
                    && p.events & POLLIN != 0
                    && p.revents & (POLLIN | POLLHUP | POLLERR) != 0
                {
                    FD_SET(p.fd, &mut rs);
                    count += 1;
                }
                if !w.is_null() && p.events & POLLOUT != 0 && p.revents & (POLLOUT | POLLERR) != 0 {
                    FD_SET(p.fd, &mut ws);
                    count += 1;
                }
                if !e.is_null() && p.events & POLLPRI != 0 && p.revents & POLLPRI != 0 {
                    FD_SET(p.fd, &mut es);
                    count += 1;
                }
            }
        }
        output_set(r, &rs, n)?;
        output_set(w, &ws, n)?;
        output_set(e, &es, n)?;
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
fn poll_count(n: nfds_t) -> Result<usize> {
    let mut limit: rlimit = unsafe { std::mem::zeroed() };
    raw(unsafe { syscall(SYS_getrlimit, RLIMIT_NOFILE, &mut limit) })?;
    if n > limit.rlim_cur {
        return Err(EINVAL);
    }
    let n = usize::try_from(n).map_err(|_| EINVAL)?;
    n.checked_mul(std::mem::size_of::<pollfd>())
        .filter(|&n| n <= isize::MAX as usize)
        .ok_or(EINVAL)?;
    Ok(n)
}
unsafe fn large_poll_virtual(p: *const pollfd, n: nfds_t) -> Result<bool> {
    let n = poll_count(n)?;
    let mut chunk = [pollfd {
        fd: -1,
        events: 0,
        revents: 0,
    }; runtime::LIMIT];
    for offset in (0..n).step_by(chunk.len()) {
        let len = (n - offset).min(chunk.len());
        memory(
            chunk.as_mut_ptr().cast(),
            p.wrapping_add(offset).cast_mut().cast(),
            len * std::mem::size_of::<pollfd>(),
            false,
        )?;
        for fd in &chunk[..len] {
            if owned(fd.fd)?.is_some() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
unsafe fn virtual_poll(p: *const pollfd, n: nfds_t) -> Result<bool> {
    Ok(any_sockets() && unsafe { large_poll_virtual(p, n)? })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_ppoll(
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
            load(t)?
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
pub unsafe extern "C" fn ntcp_managed_pselect(
    n: i32,
    r: *mut fd_set,
    w: *mut fd_set,
    e: *mut fd_set,
    t: *const timespec,
    mask: *const sigset_t,
) -> i32 {
    ffi(|| {
        if select_maybe_virtual(n) && large_select_virtual(n, [r, w, e])? {
            return Err(EOPNOTSUPP);
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
            load(t)?
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
pub unsafe extern "C" fn ntcp_managed_epoll_pwait2(
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed___poll_chk(
    p: *mut pollfd,
    n: nfds_t,
    timeout: i32,
    size: usize,
) -> i32 {
    if n > (size / std::mem::size_of::<pollfd>()) as nfds_t {
        unsafe {
            __chk_fail();
        }
    }
    unsafe { ntcp_managed_poll(p, n, timeout) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed___ppoll_chk(
    p: *mut pollfd,
    n: nfds_t,
    t: *const timespec,
    mask: *const sigset_t,
    size: usize,
) -> i32 {
    if n > (size / std::mem::size_of::<pollfd>()) as nfds_t {
        unsafe {
            __chk_fail();
        }
    }
    unsafe { ntcp_managed_ppoll(p, n, t, mask) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_close_bypasses_locked_epoll_registry() {
        let fd = unsafe { syscall(SYS_eventfd2, 0, EFD_CLOEXEC) as i32 };
        assert!(fd >= 0);
        let _epolls = EPOLLS.lock().unwrap();
        assert_eq!(unsafe { crate::close(fd) }, 0);
    }
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

boundary_entry!(poll, "ntcp_c_poll", (p: *mut pollfd, n: nfds_t, timeout: i32) -> i32);
boundary_entry!(ppoll, "ntcp_c_ppoll", (p: *mut pollfd,
    n: nfds_t,
    t: *const timespec,
    mask: *const sigset_t) -> i32);
boundary_entry!(select, "ntcp_c_select", (n: i32,
    r: *mut fd_set,
    w: *mut fd_set,
    e: *mut fd_set,
    t: *mut timeval) -> i32);
boundary_entry!(pselect, "ntcp_c_pselect", (n: i32,
    r: *mut fd_set,
    w: *mut fd_set,
    e: *mut fd_set,
    t: *const timespec,
    mask: *const sigset_t) -> i32);
boundary_entry!(epoll_wait, "ntcp_c_epoll_wait", (epfd: i32, p: *mut epoll_event, max: i32, timeout: i32) -> i32);
boundary_entry!(epoll_pwait, "ntcp_c_epoll_pwait", (epfd: i32,
    p: *mut epoll_event,
    max: i32,
    timeout: i32,
    mask: *const sigset_t) -> i32);
boundary_entry!(epoll_pwait2, "ntcp_c_epoll_pwait2", (epfd: i32,
    p: *mut epoll_event,
    max: i32,
    t: *const timespec,
    mask: *const sigset_t) -> i32);
boundary_entry!(__poll_chk, "ntcp_c___poll_chk", (p: *mut pollfd, n: nfds_t, timeout: i32, size: usize) -> i32);
boundary_entry!(__ppoll_chk, "ntcp_c___ppoll_chk", (p: *mut pollfd,
    n: nfds_t,
    t: *const timespec,
    mask: *const sigset_t,
    size: usize) -> i32);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_boundary_poll(p: *const pollfd, n: nfds_t) -> i32 {
    if !any_sockets() {
        return 0;
    }
    ffi(|| Ok(unsafe { large_poll_virtual(p, n)? } as i64)) as i32
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_boundary_select(
    n: i32,
    r: *const fd_set,
    w: *const fd_set,
    e: *const fd_set,
) -> i32 {
    if !select_maybe_virtual(n) {
        return 0;
    }
    ffi(|| Ok(large_select_virtual(n, [r, w, e])? as i64)) as i32
}

boundary_entry!(epoll_create, "ntcp_c_epoll_create", (size: i32) -> i32);
boundary_entry!(epoll_create1, "ntcp_c_epoll_create1", (flags: i32) -> i32);
boundary_entry!(epoll_ctl, "ntcp_c_epoll_ctl", (epfd: i32, op: i32, fd: i32, p: *mut epoll_event) -> i32);
