use crate::*;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
const LIMIT: usize = 4096;
#[derive(Clone, Copy)]
struct Registration {
    id: u64,
    generation: u64,
    armed: bool,
    events: u32,
    data: u64,
    seen: Option<[u64; 5]>,
    exclusive_grant: u32,
    exclusive_seen: [Option<u64>; 5],
}
fn eligible_bits(r: &Registration, ready: u32, observed: [u64; 5]) -> u32 {
    if r.events & EPOLLEXCLUSIVE as u32 == 0 {
        return if r.events & EPOLLET as u32 == 0
            || socket_options::edge_changed(ready, r.seen, observed)
        {
            ready
        } else {
            0
        };
    }
    socket_options::EDGE_BITS
        .iter()
        .enumerate()
        .fold(0, |bits, (i, bit)| {
            let bit = *bit as u32;
            let distance = r.exclusive_seen[i].map(|seen| observed[i].wrapping_sub(seen));
            let current = distance.is_none_or(|d| d < (1 << 63));
            let changed = distance.is_none_or(|d| d != 0 && d < (1 << 63));
            let level = r.events & EPOLLET as u32 == 0 && r.exclusive_grant & bit != 0;
            if ready & bit != 0 && current && (changed || level) {
                bits | bit
            } else {
                bits
            }
        })
}
#[cfg(test)]
fn eligible(r: &Registration, ready: u32, observed: [u64; 5]) -> bool {
    eligible_bits(r, ready, observed) != 0
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
        EPOLL_FDS.release(self.slot);
        unsafe {
            syscall(SYS_close, self.retained);
        }
    }
}
// Tracked epolls and, per socket, the (epfd, fd) keys registering it, as
// Linux's per-file f_ep list: closing a socket or arbitrating its exclusive
// wakeups visits only its own registrations, never every epoll's.
struct Registry {
    epolls: BTreeMap<i32, Epoll>,
    watched: BTreeSet<(u64, i32, i32)>,
}
impl Registry {
    const fn new() -> Self {
        Self {
            epolls: BTreeMap::new(),
            watched: BTreeSet::new(),
        }
    }
    // Debug builds cross-check the index against the sweep it replaces.
    fn check(&self, id: u64) {
        if cfg!(debug_assertions) {
            let swept = self.epolls.iter().flat_map(|(&epfd, ep)| {
                ep.regs
                    .keys()
                    .filter(move |&&(_, registered_id)| registered_id == id)
                    .map(move |&(fd, _)| (id, epfd, fd))
            });
            assert!(
                self.watched.range(Self::span(id)).copied().eq(swept),
                "epoll index of socket {id} differs from a sweep"
            );
        }
    }
    fn span(id: u64) -> std::ops::RangeInclusive<(u64, i32, i32)> {
        (id, i32::MIN, i32::MIN)..=(id, i32::MAX, i32::MAX)
    }
    fn each_watcher(&mut self, id: u64, mut f: impl FnMut(i32, i32, &mut Registration)) {
        self.check(id);
        for &(_, epfd, fd) in self.watched.range(Self::span(id)) {
            let r = self
                .epolls
                .get_mut(&epfd)
                .and_then(|ep| ep.regs.get_mut(&(fd, id)))
                .expect("indexed epoll registration");
            f(epfd, fd, r);
        }
    }
    fn register(&mut self, epfd: i32, key: (i32, u64), r: Registration) -> Result<()> {
        let ep = self.epolls.get_mut(&epfd).expect("tracked epoll");
        if ep.regs.contains_key(&key) {
            return Err(EEXIST);
        }
        if ep.regs.len() == LIMIT {
            return Err(ENOSPC);
        }
        ep.regs.insert(key, r);
        self.watched.insert((key.1, epfd, key.0));
        Ok(())
    }
    fn unregister(&mut self, epfd: i32, key: (i32, u64)) -> Option<Registration> {
        let removed = self.epolls.get_mut(&epfd)?.regs.remove(&key)?;
        self.watched.remove(&(key.1, epfd, key.0));
        Some(removed)
    }
    fn remove(&mut self, epfd: i32) -> Option<Epoll> {
        let ep = self.epolls.remove(&epfd)?;
        for &(fd, id) in ep.regs.keys() {
            self.watched.remove(&(id, epfd, fd));
        }
        Some(ep)
    }
}
static EPOLL_FDS: FdTable = FdTable::new();
static EPOLLS: Mutex<Registry> = Mutex::new(Registry::new());
pub fn is_epoll(fd: i32) -> Result<bool> {
    if !inherited(&EPOLL_FDS, fd) {
        return Ok(false);
    }
    mutation_context()?;
    Ok(EPOLLS.lock().map_err(|_| EIO)?.epolls.contains_key(&fd))
}
pub fn tracked_epoll(fd: i32) -> bool {
    inherited(&EPOLL_FDS, fd)
}
pub fn close_epoll(fd: i32) -> Result<()> {
    if !inherited(&EPOLL_FDS, fd) {
        return Ok(());
    }
    is_epoll(fd)?;
    let mut map = EPOLLS.lock().map_err(|_| EIO)?;
    if let Some(ep) = map.remove(fd) {
        for r in ep.regs.values() {
            if r.exclusive_grant != 0 {
                release_exclusive(&mut map, r.id);
            }
            map.check(r.id);
        }
    }
    Ok(())
}
#[cfg(feature = "packet-test")]
pub(crate) fn stop_packet_backend() {
    let mut epolls = EPOLLS.lock().unwrap_or_else(|e| e.into_inner());
    // Exposed epoll descriptors belong to the caller. In dlopen-only use a host
    // close can bypass our registry, and anon-inode identity cannot distinguish
    // a reused epoll. Only Drop's private retained descriptor is safe to close.
    epolls.epolls.clear();
    epolls.watched.clear();
}
pub fn closed(id: u64) {
    if let Ok(mut map) = EPOLLS.lock() {
        map.check(id);
        let watchers: Vec<_> = map.watched.range(Registry::span(id)).copied().collect();
        for (_, epfd, fd) in watchers {
            map.unregister(epfd, (fd, id));
        }
    }
}
// EPOLLS serializes a readiness-generation claim with successful copyout.
// A source wakes every ordinary registration and one exclusive registration;
// competing pollers revalidate after the winner has consumed the generation.
// LT winners retain readiness; ET winners require a subsequent source event.
fn claim_exclusive(map: &mut Registry, epfd: i32, key: (i32, u64), observed: [u64; 5], ready: u32) {
    map.each_watcher(key.1, |other_epfd, fd, r| {
        if r.events & EPOLLEXCLUSIVE as u32 == 0 {
            return;
        }
        for (i, bit) in socket_options::EDGE_BITS.iter().enumerate() {
            let bit = *bit as u32;
            if ready & bit == 0 {
                continue;
            }
            // Do not consume readiness classes absent from this output,
            // or rewind a newer observation staged by another waiter.
            if r.exclusive_seen[i].is_some_and(|seen| observed[i].wrapping_sub(seen) >= (1 << 63)) {
                continue;
            }
            r.exclusive_seen[i] = Some(observed[i]);
            if (other_epfd, fd) == (epfd, key.0) {
                r.exclusive_grant |= bit;
            } else {
                r.exclusive_grant &= !bit;
            }
        }
    });
}
fn release_exclusive(map: &mut Registry, id: u64) {
    map.each_watcher(id, |_, _, r| {
        if r.events & EPOLLEXCLUSIVE as u32 != 0 {
            r.seen = None;
            r.exclusive_grant = 0;
            r.exclusive_seen = [None; 5];
        }
    });
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
                | EPOLLONESHOT as u32
                | EPOLLET as u32
                | EPOLLEXCLUSIVE as u32)
            != 0
        {
            return Err(EOPNOTSUPP);
        }
        if event.events & EPOLLEXCLUSIVE as u32 != 0
            && (op != EPOLL_CTL_ADD || event.events & (EPOLLONESHOT | EPOLLRDHUP) as u32 != 0)
        {
            return Err(EINVAL);
        }
        // Lock order is TOKENS -> EPOLLS. Pin this alias through registration
        // so a concurrent final close cannot clean up before our ADD commits.
        // Neither registry is held across an owner RPC.
        let tokens = TOKENS.lock().map_err(|_| EIO)?;
        if !tokens.get(&fd).is_some_and(|t| t.id == id && t.matches(fd)) {
            return Err(EBADF);
        }
        let mut map = EPOLLS.lock().map_err(|_| EIO)?;
        if map.epolls.get(&epfd).is_some_and(|ep| !ep.matches(epfd)) {
            map.remove(epfd);
        }
        if !map.epolls.contains_key(&epfd) {
            if map.epolls.len() == runtime::LIMIT {
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
            map.epolls.insert(
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
        let ep = map.epolls.get_mut(&epfd).unwrap();
        ep.generation = ep.generation.wrapping_add(1);
        let key = (fd, id);
        let registration = Registration {
            id,
            generation: ep.generation,
            armed: true,
            events: event.events,
            data: event.u64,
            seen: None,
            exclusive_grant: 0,
            exclusive_seen: [None; 5],
        };
        match op {
            EPOLL_CTL_ADD => map.register(epfd, key, registration)?,
            EPOLL_CTL_MOD => {
                let r = ep.regs.get_mut(&key).ok_or(ENOENT)?;
                if r.events & EPOLLEXCLUSIVE as u32 != 0 {
                    return Err(EINVAL);
                }
                *r = registration;
            }
            EPOLL_CTL_DEL => {
                let removed = map.unregister(epfd, key).ok_or(ENOENT)?;
                if removed.exclusive_grant != 0 {
                    release_exclusive(&mut map, removed.id);
                }
            }
            _ => return Err(EINVAL),
        }
        map.check(id);
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
        let ep = map.epolls.get_mut(&epfd).ok_or(EBADF)?;
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
            let ep = map.epolls.get_mut(&epfd).ok_or(EBADF)?;
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
            let reply = match call(r.id, Op::Ready) {
                Ok(reply) => reply,
                Err(EBADF) => continue, // Last alias closed during the query.
                Err(_) if native_count != 0 => return Ok(native_count as i64),
                Err(e) => return Err(e),
            };
            let ready = reply.value as u32 & (r.events | EPOLLERR as u32 | EPOLLHUP as u32);
            if eligible_bits(&r, ready, reply.readiness_generations) != 0 {
                virtual_events.push((
                    key,
                    r.generation,
                    reply.readiness_generations,
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
        // Pin live aliases through copyout in the established TOKENS -> EPOLLS
        // lock order. Final close cannot commit a stale socket delivery.
        let tokens = TOKENS.lock().map_err(|_| EIO)?;
        let mut map = EPOLLS.lock().map_err(|_| EIO)?;
        let ep = map.epolls.get_mut(&epfd).ok_or(EBADF)?;
        virtual_events.retain(|(key, generation, observed, event)| {
            ep.regs.get(key).is_some_and(|r| {
                r.armed
                    && r.generation == *generation
                    && tokens.holds(r.id)
                    && eligible_bits(r, event.events, *observed) != 0
            })
        });
        let mut output = Vec::with_capacity(available);
        let mut delivered = Vec::new();
        for (key, generation, observed, event) in virtual_events {
            if output.len() == available {
                break;
            }
            // Like poll, report all currently ready requested bits once an
            // event triggers delivery. Only consume classes actually eligible
            // for this exclusive claim (e.g. a new ERR may accompany old OUT).
            let claim = eligible_bits(&ep.regs[&key], event.events, observed);
            output.push(event);
            delivered.push((key, generation, observed, claim));
        }
        if let Err(e) = store_array(p.wrapping_add(native_count), &output) {
            return if native_count != 0 {
                Ok(native_count as i64)
            } else {
                Err(e)
            };
        }
        for (key, generation, observed, ready) in delivered {
            let exclusive = map
                .epolls
                .get(&epfd)
                .and_then(|ep| ep.regs.get(&key))
                .is_some_and(|r| {
                    r.generation == generation && r.events & EPOLLEXCLUSIVE as u32 != 0
                });
            if exclusive {
                claim_exclusive(&mut map, epfd, key, observed, ready);
            }
            if let Some(r) = map
                .epolls
                .get_mut(&epfd)
                .and_then(|ep| ep.regs.get_mut(&key))
                && r.generation == generation
            {
                r.seen = Some(observed);
                if r.events & EPOLLONESHOT as u32 != 0 {
                    r.armed = false;
                }
            }
        }
        drop(map);
        drop(tokens);
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
                return Err(if io_limit() < runtime::BYTES {
                    runtime::unsupported_option("poll event mask")
                } else {
                    EOPNOTSUPP
                });
            }
            let revents = if owned(original[i].fd)? != Some(id) {
                POLLNVAL
            } else {
                poll_events(call(id, Op::Ready)?.value, requested)
            };
            original[i].revents = revents;
            virtual_ready |= revents != 0;
        }
        // ponytail: 1ms readiness polling matches the owner's packet/timer
        // cadence; add per-waiter wakefds if this polling CPU cost matters.
        let ms = if virtual_ready || timeout == 0 {
            0
        } else if deadline.is_none() {
            1
        } else {
            remaining(deadline).clamp(0, 1)
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
    SOCKET_FDS.any()
}
fn select_maybe_virtual(n: i32) -> bool {
    SOCKET_FDS.find_below(n, Some).is_some()
}
fn large_select_virtual(n: i32, sets: [*const fd_set; 3]) -> Result<bool> {
    let selected = |fd: i32| -> Result<bool> {
        for set in sets {
            if set.is_null() {
                continue;
            }
            let word = load(set.cast::<u64>().wrapping_add(fd as usize / 64))?;
            if word & (1u64 << (fd % 64)) != 0 && owned(fd)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    };
    SOCKET_FDS
        .find_below(n, |fd| {
            selected(fd).map(|hit| hit.then_some(())).transpose()
        })
        .transpose()
        .map(|hit| hit.is_some())
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

pub(crate) fn poll_events(bits: i32, requested: i16) -> i16 {
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
    use std::mem::ManuallyDrop;
    // Fixtures reserve no EPOLL_FDS slot and own no retained fd. Epoll::drop
    // would free slot 0 and close fd -1, untracking whichever real epoll a
    // concurrent test holds in that slot, so fixtures are never dropped.
    fn exclusive_fixtures<const N: usize>(entries: [(i32, Epoll); N]) -> ManuallyDrop<Registry> {
        let mut map = ManuallyDrop::new(Registry::new());
        for (epfd, mut ep) in entries {
            let regs = std::mem::take(&mut ep.regs);
            map.epolls.insert(epfd, ep);
            for (key, r) in regs {
                map.register(epfd, key, r).unwrap();
            }
        }
        map
    }
    fn reg(map: &Registry, epfd: i32) -> &Registration {
        &map.epolls[&epfd].regs[&(4, 42)]
    }
    fn exclusive_fixture(events: u32) -> Epoll {
        Epoll {
            slot: 0,
            retained: -1,
            dev: 0,
            ino: 0,
            generation: 1,
            cursor: 0,
            native_first: false,
            regs: BTreeMap::from([(
                (4, 42),
                Registration {
                    id: 42,
                    generation: 1,
                    armed: true,
                    events,
                    data: 4,
                    seen: None,
                    exclusive_grant: 0,
                    exclusive_seen: [None; 5],
                },
            )]),
        }
    }
    #[test]
    fn exclusive_arbitration_preserves_ordinary_observers_edges_and_handoff() {
        for edge in [0, EPOLLET] {
            let mask = (EPOLLIN | EPOLLEXCLUSIVE | edge) as u32;
            let mut map = exclusive_fixtures([
                (1, exclusive_fixture(mask)),
                (2, exclusive_fixture(mask)),
                (3, exclusive_fixture((EPOLLIN | EPOLLET) as u32)),
            ]);
            let first = [1, 0, 0, 0, 0];
            assert!(eligible(reg(&map, 1), EPOLLIN as u32, first));
            // A failed copyout does not claim the source; another waiter remains eligible.
            assert!(eligible(reg(&map, 2), EPOLLIN as u32, first));
            claim_exclusive(&mut map, 1, (4, 42), first, EPOLLIN as u32);
            assert!(!eligible(reg(&map, 2), EPOLLIN as u32, first));
            assert!(eligible(reg(&map, 3), EPOLLIN as u32, first));
            assert_eq!(eligible(reg(&map, 1), EPOLLIN as u32, first), edge == 0);
            let second = [2, 0, 0, 0, 0];
            assert!(eligible(reg(&map, 2), EPOLLIN as u32, second));
            claim_exclusive(&mut map, 2, (4, 42), second, EPOLLIN as u32);
            assert!(!eligible(reg(&map, 1), EPOLLIN as u32, second));
            assert!(!eligible(reg(&map, 2), EPOLLIN as u32, first));
            std::mem::forget(map.remove(2));
            release_exclusive(&mut map, 42);
            assert!(eligible(reg(&map, 1), EPOLLIN as u32, second));
        }
    }
    #[test]
    fn exclusive_claims_do_not_consume_other_readiness_classes() {
        let mask = (EPOLLIN | EPOLLOUT | EPOLLET | EPOLLEXCLUSIVE) as u32;
        let mut map =
            exclusive_fixtures([(1, exclusive_fixture(mask)), (2, exclusive_fixture(mask))]);
        let observed = [1, 1, 0, 0, 0];
        claim_exclusive(&mut map, 1, (4, 42), observed, EPOLLIN as u32);
        assert_eq!(
            eligible_bits(reg(&map, 2), (EPOLLIN | EPOLLOUT) as u32, observed),
            EPOLLOUT as u32
        );
        claim_exclusive(&mut map, 2, (4, 42), observed, EPOLLOUT as u32);
        assert_eq!(
            eligible_bits(reg(&map, 1), (EPOLLIN | EPOLLOUT) as u32, observed),
            0
        );
        let next = [2, 1, 0, 0, 0];
        assert_eq!(
            eligible_bits(reg(&map, 2), (EPOLLIN | EPOLLOUT) as u32, next),
            EPOLLIN as u32
        );
    }
    #[test]
    fn exclusive_abi_rejects_mod_oneshot_and_rdhup() {
        let (fd, t) = token(SOCK_CLOEXEC).unwrap();
        install(fd, t, 982).unwrap();
        PID.store(unsafe { syscall(SYS_getpid) as i32 }, Ordering::Release);
        let epfd = unsafe { syscall(SYS_epoll_create1, EPOLL_CLOEXEC) as i32 };
        assert!(epfd >= 0);
        let mut event = epoll_event {
            events: (EPOLLIN | EPOLLEXCLUSIVE) as u32,
            u64: 7,
        };
        for extra in [EPOLLONESHOT, EPOLLRDHUP] {
            event.events = (EPOLLIN | EPOLLEXCLUSIVE | extra) as u32;
            assert_eq!(
                unsafe { ntcp_managed_epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &mut event) },
                -1
            );
            assert_eq!(errno(), EINVAL);
        }
        event.events = (EPOLLIN | EPOLLEXCLUSIVE) as u32;
        assert_eq!(
            unsafe { ntcp_managed_epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &mut event) },
            0
        );
        event.events = EPOLLIN as u32;
        assert_eq!(
            unsafe { ntcp_managed_epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &mut event) },
            -1
        );
        assert_eq!(errno(), EINVAL);
        assert_eq!(
            unsafe { ntcp_managed_epoll_ctl(epfd, EPOLL_CTL_DEL, fd, ptr::null_mut()) },
            0
        );
        close_epoll(epfd).unwrap();
        TOKENS.lock().unwrap().remove(&fd);
        unsafe {
            syscall(SYS_close, fd);
            syscall(SYS_close, epfd);
        }
    }
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
