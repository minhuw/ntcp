// SPDX-License-Identifier: GPL-2.0-or-later
// Explicit one-shot packet backend: never enables process-wide socket creation.
pub use crate::packet_profile::{Profile, profile};
use crate::*;

pub fn start(settings: (Ipv4Addr, Profile)) -> Result<()> {
    if RUNTIME.get().is_some() {
        return Err(EBUSY);
    }
    let old = set_internal(true);
    let runtime = catch_unwind(|| Runtime::packet(settings)).unwrap_or(Err(EIO));
    set_internal(old);
    let runtime = runtime?;
    PID.store(unsafe { syscall(SYS_getpid) as i32 }, Ordering::Release);
    if let Err(runtime) = RUNTIME.set(Ok(runtime)) {
        if let Ok(runtime) = runtime {
            runtime.stop();
        }
        return Err(EBUSY);
    }
    Ok(())
}

pub fn inject(bytes: Vec<u8>) -> Result<()> {
    if bytes.len() > packet_profile::BYTES {
        return Err(EMSGSIZE);
    }
    runtime()?.call(0, Op::Inject(bytes))?;
    Ok(())
}

pub fn try_capture(capacity: usize) -> Result<(Vec<u8>, i64)> {
    let reply = runtime()?.call(0, Op::Capture(capacity))?;
    Ok((reply.bytes, reply.stamp))
}
pub fn capture(capacity: usize) -> Result<(Vec<u8>, i64)> {
    loop {
        match try_capture(capacity) {
            Ok(reply) => return Ok(reply),
            Err(EAGAIN) => {
                let mut p = pollfd {
                    fd: runtime()?.wake,
                    events: POLLIN,
                    revents: 0,
                };
                raw(unsafe { syscall(SYS_poll, &mut p, 1, 1) })?;
                drain_wake();
            }
            Err(e) => return Err(e),
        }
    }
}

pub fn stop() {
    if let Some(Ok(runtime)) = RUNTIME.get() {
        runtime.stop();
    }
    // The stock host has stopped its syscall thread before plugin free.
    let mut tokens = TOKENS.lock().unwrap_or_else(|e| e.into_inner());
    let _mutation = Mutation::enter();
    for (&fd, token) in tokens.iter() {
        if token.matches(fd) {
            unsafe {
                syscall(SYS_close, fd);
            }
        }
    }
    tokens.clear();
    readiness::stop_packet_backend();
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntcp_packet_managed_socket(domain: i32, kind: i32, protocol: i32) -> i32 {
    PACKET_SOCKET.with(|gate| {
        let previous = gate.replace(true);
        let result = unsafe { ntcp_managed_socket(domain, kind, protocol) };
        gate.set(previous);
        result
    })
}

// C owns the cancellation mask, as for every other socket boundary.
boundary_entry!(packet_socket, "ntcp_c_packet_socket", (domain: i32, kind: i32, protocol: i32) -> i32);
