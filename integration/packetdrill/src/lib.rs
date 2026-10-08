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
        let (bytes, timestamp) = packet_test::capture(capacity)?;
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
