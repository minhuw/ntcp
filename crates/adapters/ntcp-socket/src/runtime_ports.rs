// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

// Direct syscall avoids libc symbol interposition by the socket adapter. Blocking
// kernel entropy is required: neither startup secrets nor ports have a fallback.
pub(super) fn fill(bytes: &mut [u8]) -> Result<()> {
    fill_with(bytes, |remaining| {
        let n = unsafe { syscall(SYS_getrandom, remaining.as_mut_ptr(), remaining.len(), 0) };
        if n < 0 { Err(errno()) } else { Ok(n as usize) }
    })
}

// The reader seam also exercises interrupted/partial syscalls without replacing
// the completion and error-handling algorithm used in production.
pub(super) fn fill_with(
    mut bytes: &mut [u8],
    mut read: impl FnMut(&mut [u8]) -> Result<usize>,
) -> Result<()> {
    while !bytes.is_empty() {
        match read(bytes) {
            Err(EINTR) => continue,
            Err(error) => return Err(error),
            Ok(0) => return Err(EIO),
            Ok(n) if n <= bytes.len() => bytes = &mut bytes[n..],
            Ok(_) => return Err(EIO),
        }
    }
    Ok(())
}

pub(super) const FIRST: u16 = 1024;
pub(super) const COUNT: u32 = u16::MAX as u32 - FIRST as u32 + 1;

pub(super) fn allocate(
    fill: impl FnOnce(&mut [u8]) -> Result<()>,
    mut available: impl FnMut(u16) -> bool,
) -> Result<u16> {
    let mut entropy = [0; 8];
    fill(&mut entropy)?;
    // RFC6056 3.2 and 3.3.1 Algorithm 1: enlarge the unprivileged pool and
    // choose a fresh unpredictable start on every allocation. A 64-bit modulo
    // has a tiny reduction bias (at most one input in 2^64 per candidate),
    // avoiding unbounded rejection sampling. Occupied clusters bias the final
    // selection too; this is not a claim of uniformity or full RFC6056 support.
    let start = (u64::from_ne_bytes(entropy) % u64::from(COUNT)) as u32;
    for offset in 0..COUNT {
        // Arithmetic stays in u32 through wrap, including the 65535 boundary.
        let port = (u32::from(FIRST) + (start + offset) % COUNT) as u16;
        if available(port) {
            return Ok(port);
        }
    }
    Err(EADDRNOTAVAIL)
}

#[cfg(test)]
#[path = "runtime_port_tests.rs"]
mod tests;
