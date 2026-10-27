// Shared read-only rtnetlink queries, keyed by ifindex (not a cached name/MTU).
// Uses the caller's current network namespace and a fixed response buffer.
// The response poll is bounded; synchronous kernel request processing is not.
use crate::TxOutcome;
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

fn invalid_link() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid rtnetlink link response",
    )
}

// rtnetlink attributes have a native-endian u16 length/type and 4-byte alignment.
pub fn attribute(mut bytes: &[u8], wanted: u16) -> io::Result<Option<&[u8]>> {
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(invalid_link());
        }
        let length = u16::from_ne_bytes(bytes[..2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(bytes[2..4].try_into().unwrap()) & 0x3fff;
        if length < 4 || length > bytes.len() {
            return Err(invalid_link());
        }
        if kind == wanted {
            return Ok(Some(&bytes[4..length]));
        }
        let aligned = (length + 3) & !3;
        if aligned > bytes.len() {
            return Err(invalid_link());
        }
        bytes = &bytes[aligned..];
    }
    Ok(None)
}

pub fn with_link<T>(index: u32, inspect: impl FnOnce(&[u8]) -> io::Result<T>) -> io::Result<T> {
    if index == 0 || index > i32::MAX as u32 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // Query the current namespace, not sysfs (which may expose another netns).
    // SAFETY: socket takes integers and returns a new owned fd on success.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: ownership of this newly created descriptor is acquired once.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // nlmsghdr (16 bytes), then ifinfomsg (16 bytes); no dump or mutation.
    let mut request = [0u8; 32];
    request[..4].copy_from_slice(&32u32.to_ne_bytes());
    request[4..6].copy_from_slice(&libc::RTM_GETLINK.to_ne_bytes());
    request[6..8].copy_from_slice(&(libc::NLM_F_REQUEST as u16).to_ne_bytes());
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    request[20..24].copy_from_slice(&index.to_ne_bytes());
    // SAFETY: zero is valid for sockaddr_nl; pid 0 addresses the kernel.
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    // SAFETY: live request and correctly sized destination, retained only during sendto.
    if unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
            (&address as *const libc::sockaddr_nl).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut ready = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized pollfd, bounded to 100ms, no retries on signals.
    match unsafe { libc::poll(&mut ready, 1, 100) } {
        -1 => return Err(io::Error::last_os_error()),
        0 => return Err(io::ErrorKind::TimedOut.into()),
        _ => {}
    }
    let mut response = [0u8; 8192];
    let mut address_len = std::mem::size_of_val(&address) as libc::socklen_t;
    // SAFETY: both response and source address are writable and live for recvfrom.
    let count = unsafe {
        libc::recvfrom(
            fd.as_raw_fd(),
            response.as_mut_ptr().cast(),
            response.len(),
            libc::MSG_TRUNC,
            (&mut address as *mut libc::sockaddr_nl).cast(),
            &mut address_len,
        )
    };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    if count < 16 || count as usize > response.len() || address.nl_pid != 0 {
        return Err(invalid_link());
    }
    let response = &response[..count as usize];
    let length = u32::from_ne_bytes(response[..4].try_into().unwrap()) as usize;
    let kind = u16::from_ne_bytes(response[4..6].try_into().unwrap());
    if length > response.len() || length < 16 || response[8..12] != 1u32.to_ne_bytes() {
        return Err(invalid_link());
    }
    if kind == libc::NLMSG_ERROR as u16 && length >= 20 {
        let error = i32::from_ne_bytes(response[16..20].try_into().unwrap());
        return if error < 0 {
            Err(io::Error::from_raw_os_error(error.saturating_neg()))
        } else {
            Err(invalid_link())
        };
    }
    if kind != libc::RTM_NEWLINK || length < 32 || response[20..24] != index.to_ne_bytes() {
        return Err(invalid_link());
    }
    inspect(&response[32..length])
}

pub fn local_ip_mtu(index: u32) -> io::Result<Option<u32>> {
    with_link(index, |attributes| {
        let Some(bytes) = attribute(attributes, 4)? else {
            return Ok(None);
        };
        let mtu = u32::from_ne_bytes(bytes.try_into().map_err(|_| invalid_link())?);
        if mtu == 0 {
            return Err(invalid_link());
        }
        Ok(Some(mtu))
    })
}

/// Maps a packet read/recv result to `PacketIo::receive`: `Ok(None)` when the
/// call would block, and an error for packets larger than `capacity`.
pub fn received(count: isize, capacity: usize) -> io::Result<Option<usize>> {
    if count < 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(error)
        };
    }
    if count as usize > capacity {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "packet exceeds output buffer; packet discarded",
        ));
    }
    Ok(Some(count as usize))
}

/// Maps a packet write/send result for a `length`-byte packet to
/// `PacketIo::transmit`: a short write is an error, never a submission.
pub fn transmitted(count: isize, length: usize) -> io::Result<TxOutcome> {
    if count < 0 {
        let error = io::Error::last_os_error();
        // Linux packet write/send EINTR occurs before any bytes are submitted.
        // Certify retry here, not for arbitrary PacketIo errors or cancellation.
        return if matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            Ok(TxOutcome::WouldBlock)
        } else {
            Err(error)
        };
    }
    if count as usize != length {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short packet write",
        ));
    }
    Ok(TxOutcome::Submitted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_results_map_errno_and_length() {
        // SAFETY: errno is thread-local; model each failed syscall result.
        unsafe { *libc::__errno_location() = libc::EAGAIN };
        assert_eq!(received(-1, 4).unwrap(), None);
        assert_eq!(transmitted(-1, 4).unwrap(), TxOutcome::WouldBlock);
        unsafe { *libc::__errno_location() = libc::EINTR };
        assert_eq!(transmitted(-1, 4).unwrap(), TxOutcome::WouldBlock);
        assert_eq!(
            received(-1, 4).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        unsafe { *libc::__errno_location() = libc::EBADF };
        assert_eq!(
            received(-1, 4).unwrap_err().raw_os_error(),
            Some(libc::EBADF)
        );
        assert_eq!(
            transmitted(-1, 4).unwrap_err().raw_os_error(),
            Some(libc::EBADF)
        );
        assert_eq!(received(0, 4).unwrap(), Some(0));
        assert_eq!(received(4, 4).unwrap(), Some(4));
        assert_eq!(
            received(5, 4).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(transmitted(4, 4).unwrap(), TxOutcome::Submitted);
        assert_eq!(
            transmitted(1, 4).unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
    }
}
