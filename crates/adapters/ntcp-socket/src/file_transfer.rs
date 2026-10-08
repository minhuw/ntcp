// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

// Registered private aliases pin the logical socket, not just its eventfd.
// Native duplicates pin the open file description across close/dup replacement.
struct PinnedFd(i32, bool);
impl PinnedFd {
    fn new(fd: i32) -> Result<Self> {
        let (fd, registered) = duplicate_registered(fd, None, F_DUPFD_CLOEXEC, 0)?;
        Ok(Self(fd as i32, registered))
    }
}
impl Drop for PinnedFd {
    fn drop(&mut self) {
        if !self.1 {
            unsafe { syscall(SYS_close, self.0) };
            return;
        }
        let last = if let Ok(mut tokens) = TOKENS.lock() {
            let _mutation = Mutation::enter();
            unsafe { syscall(SYS_close, self.0) };
            remove_alias(&mut tokens, self.0)
        } else {
            None
        };
        let _ = finish_close(last);
    }
}
struct Pipe([i32; 2]);
impl Pipe {
    fn new() -> Result<Self> {
        let mut fds = [-1; 2];
        raw(unsafe { syscall(SYS_pipe2, fds.as_mut_ptr(), O_CLOEXEC | O_NONBLOCK) })?;
        Ok(Self(fds))
    }
}
impl Drop for Pipe {
    fn drop(&mut self) {
        for fd in self.0 {
            unsafe { syscall(SYS_close, fd) };
        }
    }
}
fn mode(fd: i32) -> Result<mode_t> {
    let mut st: stat = unsafe { std::mem::zeroed() };
    raw(unsafe { syscall(SYS_fstat, fd, &mut st) })?;
    Ok(st.st_mode & S_IFMT)
}
fn pipe_nonblock(fd: i32, write: bool, flags: u32) -> Result<bool> {
    let status = raw(unsafe { syscall(SYS_fcntl, fd, F_GETFL) })? as i32;
    if status & O_ACCMODE == if write { O_RDONLY } else { O_WRONLY } {
        return Err(EBADF);
    }
    Ok(flags & SPLICE_F_NONBLOCK != 0 || status & O_NONBLOCK != 0)
}
fn pipe_events(fd: i32, events: i16) -> Result<i16> {
    let mut p = pollfd {
        fd,
        events,
        revents: 0,
    };
    raw(unsafe { syscall(SYS_poll, &mut p, 1, 0) })?;
    Ok(p.revents)
}
fn broken_pipe() -> Result<i64> {
    unsafe {
        syscall(
            SYS_tgkill,
            syscall(SYS_getpid),
            syscall(SYS_gettid),
            SIGPIPE,
        )
    };
    Err(EPIPE)
}
fn pipe_wait(fd: i32, events: i16, deadline: &mut Deadline) -> Result<()> {
    let mut p = pollfd {
        fd,
        events,
        revents: 0,
    };
    // Native pipe availability is independent of the socket timeout. Start
    // a fresh socket budget only after the pipe has become ready.
    raw(unsafe { syscall(SYS_poll, &mut p, 1, -1) })?;
    deadline.start = std::time::Instant::now();
    Ok(())
}
fn send_source(id: u64, source: i32, offset: Option<usize>, n: usize, flags: u32) -> Result<i64> {
    let pipe_nonblock = offset.is_none() && pipe_nonblock(source, false, flags)?;
    let dontwait = !blocking(id)?;
    let mut deadline = Deadline::socket(id, true, false)?;
    let pipe = Pipe::new()?;
    loop {
        if offset.is_none() {
            let events = pipe_events(source, POLLIN)?;
            if events & POLLIN == 0 {
                if events & POLLHUP != 0 {
                    return Ok(0);
                }
                if pipe_nonblock {
                    return Err(EAGAIN);
                }
                pipe_wait(source, POLLIN, &mut deadline)?;
                continue;
            }
        }
        let result = call(
            id,
            Op::Transfer {
                source,
                staging: pipe.0,
                offset,
                count: n,
                flags: if flags & SPLICE_F_MORE != 0 {
                    MSG_MORE
                } else {
                    0
                },
            },
        );
        match result {
            Ok(reply) if reply.value == -EAGAIN => {
                if pipe_nonblock || offset.is_some() {
                    return Err(EAGAIN);
                }
                pipe_wait(source, POLLIN, &mut deadline)?;
            }
            Err(EAGAIN) if !dontwait => wait_until(id, EPOLLOUT, &deadline)?,
            Err(EPIPE) => return broken_pipe(),
            other => return other.map(|reply| reply.value as i64),
        }
    }
}
fn receive_pipe(fd: i32, id: u64, output: i32, n: usize, flags: u32) -> Result<i64> {
    let pipe_nonblock = pipe_nonblock(output, true, flags)?;
    let dontwait = !blocking(id)?;
    let mut deadline = Deadline::socket(id, false, false)?;
    let input = TOKENS
        .lock()
        .map_err(|_| EIO)?
        .get(&fd)
        .ok_or(EBADF)?
        .input
        .clone();
    let mut bytes = loop {
        match input.bytes.try_lock() {
            Ok(bytes) => break bytes,
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(EIO),
            Err(std::sync::TryLockError::WouldBlock) if dontwait => return Err(EAGAIN),
            Err(std::sync::TryLockError::WouldBlock) => {
                deadline.poll_ms()?;
                std::thread::yield_now();
            }
        }
    };
    loop {
        let events = pipe_events(output, POLLOUT)?;
        if events & POLLERR != 0 {
            return broken_pipe();
        }
        if events & POLLOUT == 0 {
            if pipe_nonblock {
                return Err(EAGAIN);
            }
            pipe_wait(output, POLLOUT, &mut deadline)?;
            continue;
        }
        let urgent = call(id, Op::UrgentRemaining)?.timeout_us;
        // The retained urgent endpoint is the byte *after* the urgent octet.
        // splice stops before that octet; ordinary reads remain unchanged.
        if n != 0 && urgent == 1 {
            return Ok(0);
        }
        let count = if urgent > 1 {
            n.min((urgent - 1) as usize)
        } else {
            n
        };
        let mut pipe_blocked = false;
        let result = read_prefix_locked(
            &input,
            &mut bytes,
            id,
            count,
            MSG_DONTWAIT,
            &deadline,
            |bytes| {
                if bytes.is_empty() {
                    return Ok(0);
                }
                let pipe = Pipe::new()?;
                let staged =
                    raw(unsafe { syscall(SYS_write, pipe.0[1], bytes.as_ptr(), bytes.len()) })?
                        as usize;
                let result = raw(unsafe {
                    syscall(
                        SYS_splice,
                        pipe.0[0],
                        ptr::null_mut::<loff_t>(),
                        output,
                        ptr::null_mut::<loff_t>(),
                        staged,
                        flags | SPLICE_F_NONBLOCK,
                    )
                })
                .map(|n| n as usize);
                pipe_blocked = result == Err(EAGAIN);
                result
            },
        );
        match result {
            Err(EAGAIN) if pipe_blocked && !pipe_nonblock => {
                pipe_wait(output, POLLOUT, &mut deadline)?
            }
            Err(EAGAIN) if !pipe_blocked && !dontwait => wait_until(id, EPOLLIN, &deadline)?,
            other => return other,
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_sendfile(
    out: i32,
    input: i32,
    offset: *mut off_t,
    n: usize,
) -> ssize_t {
    ffi(|| {
        if !offset.is_null() {
            let _ = load(offset)?;
        }
        if n > isize::MAX as usize {
            return Err(EINVAL);
        }
        let output = PinnedFd::new(out)?;
        let input = PinnedFd::new(input)?;
        match (owned(input.0)?, owned(output.0)?) {
            (None, Some(id)) => {
                if !matches!(mode(input.0)?, S_IFREG | S_IFBLK) {
                    return Err(EINVAL);
                }
                send_source(id, input.0, Some(offset as usize), n, 0)
            }
            (None, None) => raw(unsafe { syscall(SYS_sendfile, output.0, input.0, offset, n) }),
            _ => Err(EINVAL),
        }
    }) as ssize_t
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_managed_splice(
    input: i32,
    inoff: *mut loff_t,
    out: i32,
    outoff: *mut loff_t,
    n: usize,
    flags: u32,
) -> ssize_t {
    ffi(|| {
        if n == 0 {
            return Ok(0);
        }
        let input = PinnedFd::new(input)?;
        let output = PinnedFd::new(out)?;
        let ids = (owned(input.0)?, owned(output.0)?);
        if ids == (None, None) {
            return raw(unsafe { syscall(SYS_splice, input.0, inoff, output.0, outoff, n, flags) });
        }
        if flags & !(SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT) != 0 {
            return Err(EINVAL);
        }
        match ids {
            (None, Some(id)) if mode(input.0)? == S_IFIFO => {
                if !inoff.is_null() {
                    return Err(ESPIPE);
                }
                if !outoff.is_null() {
                    let _ = load(outoff)?;
                    return Err(EINVAL);
                }
                send_source(id, input.0, None, n, flags)
            }
            (Some(id), None) if mode(output.0)? == S_IFIFO => {
                if !outoff.is_null() {
                    return Err(ESPIPE);
                }
                if !inoff.is_null() {
                    let _ = load(inoff)?;
                    return Err(EINVAL);
                }
                receive_pipe(input.0, id, output.0, n, flags)
            }
            _ => Err(EINVAL),
        }
    }) as ssize_t
}
boundary_entry!(sendfile, "ntcp_c_sendfile", (out: i32, input: i32, offset: *mut off_t, n: usize) -> ssize_t);
boundary_entry!(sendfile64, "ntcp_c_sendfile64", (out: i32, input: i32, offset: *mut off64_t, n: usize) -> ssize_t);
boundary_entry!(splice, "ntcp_c_splice", (input: i32, inoff: *mut loff_t, out: i32, outoff: *mut loff_t, n: usize, flags: u32) -> ssize_t);
