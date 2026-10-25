// SPDX-License-Identifier: GPL-2.0-or-later
// Explicit one-shot packet backend: never enables process-wide socket creation.
pub use crate::packet_profile::{Profile, UpstreamOptions, profile};
use crate::*;

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub queue_capacity: usize,
    pub egress_capacity: usize,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            queue_capacity: packet_profile::LIMIT,
            // Keep two independent held flows and baseline buffer-resize headroom.
            egress_capacity: 2,
        }
    }
}
impl Options {
    pub(crate) fn validate(self) -> Result<()> {
        if !(1..=packet_profile::LIMIT).contains(&self.queue_capacity)
            || !(1..=packet_profile::LIMIT).contains(&self.egress_capacity)
        {
            return Err(EINVAL);
        }
        Ok(())
    }
}

pub fn start(settings: (Ipv4Addr, Profile)) -> Result<()> {
    start_with_options(settings, Options::default())
}
pub fn start_with_options(settings: (Ipv4Addr, Profile), options: Options) -> Result<()> {
    if RUNTIME.get().is_some() {
        return Err(EBUSY);
    }
    let old = set_internal(true);
    let runtime =
        catch_unwind(|| Runtime::packet_with_options(settings, options)).unwrap_or(Err(EIO));
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

// Inject one checksummed aggregate together with actual producer segment size.
pub fn inject_segmented(bytes: Vec<u8>, segment_size: core::num::NonZeroU16) -> Result<()> {
    if bytes.len() > packet_profile::BYTES {
        return Err(EMSGSIZE);
    }
    runtime()?.call(0, Op::InjectSegmented(bytes, segment_size))?;
    Ok(())
}

// Capture host-local output policy metadata separately from on-wire bytes.
pub fn try_capture_with_mark(capacity: usize) -> Result<(Vec<u8>, i64, u32)> {
    let reply = runtime()?.call(0, Op::Capture(capacity))?;
    Ok((reply.bytes, reply.stamp, reply.packet_mark))
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

// Changes future negotiation only; existing connection state and caches survive.
pub fn timestamp_default(enabled: bool) -> Result<()> {
    runtime()?.call(0, Op::TimestampDefault(enabled))?;
    Ok(())
}

pub fn clear_fast_open_client_cache() -> Result<()> {
    runtime()?.call(0, Op::ClearFastOpenClientCache)?;
    Ok(())
}

// Inspect managed listener membership at one local port, including core
// generation validity. This neither accepts children nor services TCP work.
pub fn listener_present(port: u16) -> Result<bool> {
    runtime()?
        .call(0, Op::ListenerPresent(port))
        .map(|reply| reply.value != 0)
}

// Called only by the patched runner's exact, audited command capability.
pub fn local_resource_rejection(enabled: bool) -> Result<()> {
    runtime()?.call(0, Op::LocalResourceReject(enabled))?;
    Ok(())
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
