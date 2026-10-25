// SPDX-License-Identifier: GPL-2.0-or-later
use libc::*;
use ntcp_socket::{
    packet_profile::{diagnostic, unsupported},
    packet_test,
};
use std::{
    ffi::CStr,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};
static INITIALIZED: AtomicBool = AtomicBool::new(false);
static ACTIVE: AtomicBool = AtomicBool::new(false);

// Optional symbol, not a change to packetdrill_interface layout. Unknown
// commands fail closed; no command string reaches a shell or host network API.
#[unsafe(no_mangle)]
unsafe extern "C" fn ntcp_packetdrill_control(
    userdata: *mut c_void,
    command: *const c_char,
) -> i32 {
    result(|| {
        if ntcp_plugin_active(userdata) == 0 || command.is_null() {
            return Err(EINVAL);
        }
        match unsafe { CStr::from_ptr(command) }.to_bytes() {
            b"ntcp-local-resource-reject-on" => packet_test::local_resource_rejection(true)?,
            b"ntcp-local-resource-reject-off" => packet_test::local_resource_rejection(false)?,
            b"ntcp-local-timestamps-on" => packet_test::timestamp_default(true)?,
            b"ntcp-local-timestamps-off" => packet_test::timestamp_default(false)?,
            b"ntcp-local-tfo-client-on" => ntcp_socket::set_fast_open_client_enabled(true)
                .map_err(|e| e.raw_os_error().unwrap_or(EIO))?,
            b"ntcp-local-tfo-client-off" => ntcp_socket::set_fast_open_client_enabled(false)
                .map_err(|e| e.raw_os_error().unwrap_or(EIO))?,
            b"ntcp-local-timestamps-on-clear-tfo-cache" => {
                packet_test::timestamp_default(true)?;
                packet_test::clear_fast_open_client_cache()?;
            }
            command if command.starts_with(b"ntcp-local-route-") => {
                let (destination, policy) = route_command(command)?;
                ntcp_socket::set_destination_route(destination, policy)
                    .map_err(|e| e.raw_os_error().unwrap_or(EIO))?;
            }
            command if command.starts_with(b"ntcp-local-assert-listener ") => {
                let port = listener_assertion_port(command)?;
                if !packet_test::listener_present(port)? {
                    return Err(ENOENT);
                }
            }
            _ => return Err(EOPNOTSUPP),
        };
        Ok(0)
    }) as i32
}
fn route_command(
    command: &[u8],
) -> Result<(std::net::Ipv4Addr, Option<ntcp_socket::RoutePolicy>), i32> {
    if command.len() > 96 {
        return Err(EOPNOTSUPP);
    }
    let text = std::str::from_utf8(command).map_err(|_| EOPNOTSUPP)?;
    let fields: Vec<_> = text.split(' ').collect();
    if fields.len() < 2 {
        return Err(EOPNOTSUPP);
    }
    let destination: std::net::Ipv4Addr = fields[1].parse().map_err(|_| EOPNOTSUPP)?;
    if destination.to_string() != fields[1] {
        return Err(EOPNOTSUPP);
    }
    fn number(text: &str) -> Result<Option<u32>, i32> {
        if text == "-" {
            return Ok(None);
        }
        if text.is_empty() || text.starts_with('0') || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(EOPNOTSUPP);
        }
        text.parse().map(Some).map_err(|_| EOPNOTSUPP)
    }
    match (fields[0], fields.len()) {
        ("ntcp-local-route-remove", 2) => Ok((destination, None)),
        ("ntcp-local-route-set", 5) => {
            let mtu = number(fields[2])?;
            let advertised_mss = number(fields[3])?
                .map(u16::try_from)
                .transpose()
                .map_err(|_| EOPNOTSUPP)?;
            let initial_search_low = number(fields[4])?;
            Ok((
                destination,
                Some(ntcp_socket::RoutePolicy {
                    mtu,
                    advertised_mss,
                    initial_search_low,
                    ..Default::default()
                }),
            ))
        }
        _ => Err(EOPNOTSUPP),
    }
}

// Canonical decimal ports only; no shell fragments or alternate spellings.
fn listener_assertion_port(command: &[u8]) -> Result<u16, i32> {
    let port = command
        .strip_prefix(b"ntcp-local-assert-listener ")
        .ok_or(EOPNOTSUPP)?;
    if port.is_empty() || port.len() > 5 || port[0] == b'0' || !port.iter().all(u8::is_ascii_digit)
    {
        return Err(EOPNOTSUPP);
    }
    std::str::from_utf8(port)
        .map_err(|_| EOPNOTSUPP)?
        .parse::<u16>()
        .map_err(|_| EOPNOTSUPP)
}

const USERDATA: *mut c_void = ptr::dangling_mut::<c_void>();
unsafe extern "C" {
    fn ntcp_fill(interface: *mut c_void, userdata: *mut c_void);
}

// Same naked tail-jump layout as ntcp-socket: no Rust frame surrounds the
// C cancellation guard (especially the owner's pthread_join during free).
macro_rules! lifecycle_entry {
    ($name:ident, $target:literal, ($($arg:ident: $ty:ty),*)) => {
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        unsafe extern "C" fn $name($($arg: $ty),*) {
            #[cfg(target_arch = "x86_64")]
            core::arch::naked_asm!(concat!("jmp ", $target));
            #[cfg(target_arch = "aarch64")]
            core::arch::naked_asm!(concat!("b ", $target));
        }
    };
}
lifecycle_entry!(packetdrill_interface_init, "ntcp_c_packet_init", (flags: *const c_char, interface: *mut c_void));
lifecycle_entry!(ntcp_free, "ntcp_c_packet_free", (userdata: *mut c_void));

#[unsafe(no_mangle)]
pub extern "C" fn ntcp_packetdrill_backend() -> *const c_char {
    c"ntcp-socket".as_ptr()
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ntcp_plugin_init(flags: *const c_char, interface: *mut c_void) {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if interface.is_null() {
            return Err(EFAULT);
        }
        if flags.is_null() {
            return Err(unsupported("missing so_flags"));
        }
        let settings = packet_test::profile(
            unsafe { CStr::from_ptr(flags) }
                .to_str()
                .map_err(|_| EINVAL)?,
        )?;
        if INITIALIZED.swap(true, Ordering::AcqRel) {
            return Err(unsupported(
                "only one plugin initialization per process is supported",
            ));
        }
        packet_test::start(settings)?;
        ACTIVE.store(true, Ordering::Release);
        Ok::<(), i32>(())
    }));
    let userdata = match result {
        Ok(Ok(())) => USERDATA,
        Ok(Err(e)) => {
            unsafe {
                *__errno_location() = e;
            }
            ptr::null_mut()
        }
        Err(_) => {
            diagnostic("FAILURE", "adapter initialization panicked");
            ptr::null_mut()
        }
    };
    if !interface.is_null() {
        unsafe {
            ntcp_fill(interface, userdata);
        }
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn ntcp_plugin_free(userdata: *mut c_void) {
    if userdata == USERDATA && ACTIVE.swap(false, Ordering::AcqRel) {
        packet_test::stop();
    }
}
#[unsafe(no_mangle)]
extern "C" fn ntcp_plugin_active(userdata: *mut c_void) -> i32 {
    if userdata == USERDATA && ACTIVE.load(Ordering::Acquire) {
        1
    } else {
        unsafe {
            *__errno_location() = EIO;
        }
        0
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn ntcp_net_send(userdata: *mut c_void, input: *const c_void, len: usize) -> i32 {
    result(|| {
        if ntcp_plugin_active(userdata) == 0 {
            return Err(EIO);
        }
        if len > 65535 {
            return Err(EMSGSIZE);
        }
        let mut bytes = vec![0; len];
        memory(bytes.as_mut_ptr(), input.cast_mut().cast(), len, false)?;
        packet_test::inject(bytes)?;
        Ok(0)
    }) as i32
}
#[unsafe(no_mangle)]
unsafe extern "C" fn ntcp_net_receive(
    userdata: *mut c_void,
    output: *mut c_void,
    len: *mut usize,
    stamp: *mut i64,
) -> i32 {
    let result = result(|| {
        if ntcp_plugin_active(userdata) == 0 {
            return Err(EIO);
        }
        let mut capacity = 0usize;
        memory(
            (&mut capacity as *mut usize).cast(),
            len.cast(),
            std::mem::size_of::<usize>(),
            false,
        )?;
        if output.is_null() || stamp.is_null() {
            return Err(EFAULT);
        }
        let (bytes, timestamp) = match packet_test::try_capture(capacity) {
            Ok(packet) => packet,
            // The existing callback ABI represents an empty capture by count=0.
            // The runner owns the receive deadline and retries, not this callback.
            Err(EAGAIN) => (Vec::new(), 0),
            Err(error) => return Err(error),
        };
        memory(bytes.as_ptr().cast_mut(), output.cast(), bytes.len(), true)?;
        memory(
            (&timestamp as *const i64).cast_mut().cast(),
            stamp.cast(),
            8,
            true,
        )?;
        let n = bytes.len();
        memory(
            (&n as *const usize).cast_mut().cast(),
            len.cast(),
            std::mem::size_of::<usize>(),
            true,
        )?;
        Ok(0)
    }) as i32;
    if result < 0 {
        let error = unsafe { *__errno_location() };
        let zero = 0usize;
        let _ = memory(
            (&zero as *const usize).cast_mut().cast(),
            len.cast(),
            std::mem::size_of::<usize>(),
            true,
        );
        unsafe {
            *__errno_location() = error;
        }
    }
    result
}
fn result(f: impl FnOnce() -> Result<i64, i32>) -> i64 {
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
fn memory(local: *mut u8, remote: *mut u8, len: usize, writing: bool) -> Result<(), i32> {
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
            if writing {
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
        return Err(unsafe { *__errno_location() });
    }
    if n as usize != len {
        return Err(EFAULT);
    }
    Ok(())
}
#[cfg(test)]
mod tests;
