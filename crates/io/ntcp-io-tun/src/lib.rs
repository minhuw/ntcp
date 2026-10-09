#![cfg(target_os = "linux")]

use ntcp_io::linux::attribute;
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use std::{
    fs::OpenOptions,
    io,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd},
        unix::fs::OpenOptionsExt,
    },
};

pub(crate) fn received(count: isize, capacity: usize) -> io::Result<Option<usize>> {
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

pub(crate) fn transmitted(count: isize, length: usize) -> io::Result<TxOutcome> {
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

pub struct Tun {
    fd: OwnedFd,
    name: String,
    ifindex: u32,
}

impl Tun {
    // Creates an exclusively named, nonpersistent TUN in the caller's current
    // namespace. Never attaches to an existing interface or configures routes,
    // addresses, MTU or link state. The interface disappears with the last fd.
    pub fn create(name: &str) -> io::Result<Self> {
        Self::attach(name, true)
    }

    // Attaches a caller-preconfigured IFF_TUN | IFF_NO_PI interface. Missing
    // names are rejected. The caller must not concurrently reconfigure or
    // remove/recreate the interface: TUNSETIFF has no atomic attach-only mode.
    pub fn open(name: &str) -> io::Result<Self> {
        Self::attach(name, false)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn attach(name: &str, exclusive: bool) -> io::Result<Self> {
        if name.is_empty()
            || name.len() >= libc::IFNAMSIZ
            || name == "."
            || name == ".."
            || name
                .bytes()
                .any(|b| b == 0 || b == b'/' || b == b':' || b == b'%' || b.is_ascii_whitespace())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TUN interface name",
            ));
        }
        if !exclusive {
            // Name validation above excludes interior NULs.
            let c_name = std::ffi::CString::new(name).unwrap();
            // SAFETY: c_name is a terminated C string.
            let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
            if index == 0 {
                return Err(io::Error::last_os_error());
            }
            check_existing(index)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/dev/net/tun")?;
        // SAFETY: zero initializes the name buffer and every ifreq union member.
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        for (dst, src) in request.ifr_name.iter_mut().zip(name.bytes()) {
            *dst = src as libc::c_char;
        }
        request.ifr_ifru.ifru_flags =
            (libc::IFF_TUN | libc::IFF_NO_PI | if exclusive { libc::IFF_TUN_EXCL } else { 0 })
                as libc::c_short;
        // SAFETY: live TUN fd and a writable, correctly sized ifreq.
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let c_name = std::ffi::CString::new(name).unwrap();
        // SAFETY: validated, terminated interface name; remember identity across renames.
        let ifindex = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if ifindex == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            ifindex,
            fd: file.into(),
            name: name.to_owned(),
        })
    }
}

fn check_format(attributes: &[u8]) -> io::Result<()> {
    // IFLA_LINKINFO -> IFLA_INFO_KIND / IFLA_INFO_DATA. TUN attributes
    // are from linux/if_link.h (not exposed by every supported libc version).
    let incompatible = || {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "existing interface is not single-queue TUN without PI/VNET_HDR",
        )
    };
    let info = attribute(attributes, 18)?.ok_or_else(incompatible)?;
    if attribute(info, 1)? != Some(b"tun\0".as_slice()) {
        return Err(incompatible());
    }
    let data = attribute(info, 2)?.ok_or_else(incompatible)?;
    for (kind, expected) in [(3, 1), (4, 0), (5, 0), (7, 0)] {
        if attribute(data, kind)? != Some([expected].as_slice()) {
            return Err(incompatible());
        }
    }
    Ok(())
}

fn check_existing(index: u32) -> io::Result<()> {
    ntcp_io::linux::with_link(index, check_format)
}

impl PacketIo for Tun {
    fn local_ip_mtu(&self) -> io::Result<Option<u32>> {
        ntcp_io::linux::local_ip_mtu(self.ifindex)
    }
    // No fixed adapter buffer: do not invent a raw-IP protocol limit (e.g.
    // IPv6 payload length excludes its header). The independent cap is unknown.

    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }

    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        // TUN cannot MSG_PEEK. One extra byte in the readv catches every packet
        // larger than out, including packets larger than the whole iovec. Such
        // packets are consumed, but never returned as valid truncated packets.
        let mut overflow = 0u8;
        let vectors = [
            libc::iovec {
                iov_base: out.as_mut_ptr().cast(),
                iov_len: out.len(),
            },
            libc::iovec {
                iov_base: (&mut overflow as *mut u8).cast(),
                iov_len: 1,
            },
        ];
        // SAFETY: both iovecs point to distinct writable buffers that stay live.
        let count = unsafe { libc::readv(self.as_raw_fd(), vectors.as_ptr(), 2) };
        received(count, out.len())
    }

    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        // SAFETY: packet is readable for its length; write retains no pointer.
        let count = unsafe { libc::write(self.as_raw_fd(), packet.as_ptr().cast(), packet.len()) };
        transmitted(count, packet.len())
    }
}

impl AsFd for Tun {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;
    pub(crate) fn backpressure(a: &mut impl PacketIo, b: &mut impl PacketIo) {
        let mut out = [0; 1024];
        for submitted in 0..10000 {
            let packet = [submitted as u8; 1024];
            if b.transmit(&packet).unwrap() == TxOutcome::WouldBlock {
                for sequence in 0..submitted {
                    assert_eq!(a.receive(&mut out).unwrap(), Some(1024));
                    assert_eq!(out, [sequence as u8; 1024]);
                }
                // The rejected send did not enqueue another copy.
                assert_eq!(a.receive(&mut out).unwrap(), None);
                assert_eq!(b.transmit(&packet).unwrap(), TxOutcome::Submitted);
                assert_eq!(a.receive(&mut out).unwrap(), Some(packet.len()));
                assert_eq!(out, packet);
                assert_eq!(a.receive(&mut out).unwrap(), None);
                return;
            }
        }
        panic!("queue never filled");
    }

    pub(crate) fn flags(fd: RawFd) {
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK,
            0
        );
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }

    pub(crate) fn pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [-1; 2];
        // SAFETY: socketpair initializes two distinct owned fds on success.
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            },
            0
        );
        let size: libc::c_int = 4096;
        for fd in fds {
            // SAFETY: size is a correctly sized socket option integer.
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_SNDBUF,
                        (&size as *const libc::c_int).cast(),
                        std::mem::size_of_val(&size) as libc::socklen_t,
                    )
                },
                0
            );
        }
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    #[test]
    fn interrupted_transmit_is_unsubmitted() {
        // SAFETY: errno is thread-local; model the failed syscall result.
        unsafe { *libc::__errno_location() = libc::EINTR };
        assert_eq!(transmitted(-1, 4).unwrap(), TxOutcome::WouldBlock);
        assert_eq!(transmitted(4, 4).unwrap(), TxOutcome::Submitted);
        assert_eq!(
            transmitted(1, 4).unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
    }

    #[test]
    fn malformed_attributes_fail_closed() {
        for bytes in [
            &[0u8][..],
            &[0, 0, 1, 0],
            &[3, 0, 1, 0],
            &[8, 0, 1, 0],
            &[5, 0, 2, 0, 0],
        ] {
            assert_eq!(
                attribute(bytes, 1).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        assert_eq!(
            check_format(&[]).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        // Nested attribute flag is masked off, and payload is not borrowed
        // beyond the response buffer's lifetime.
        assert_eq!(
            attribute(&[5, 0, 1, 128, 42, 0, 0, 0], 1).unwrap(),
            Some([42].as_slice())
        );
    }

    #[test]
    fn validation() {
        for name in [
            "",
            ".",
            "..",
            "abcdefghijklmnop",
            "a\0b",
            "a/b",
            "a:b",
            "a b",
            "a\nb",
            "tun%d",
        ] {
            assert_eq!(
                Tun::create(name).err().unwrap().kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                Tun::open(name).err().unwrap().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn packets_and_ownership() {
        let (a, b) = pair();
        let mut a = Tun {
            fd: a,
            name: "test-a".into(),
            ifindex: 0,
        };
        let mut b = Tun {
            fd: b,
            name: "test-b".into(),
            ifindex: 0,
        };
        assert_eq!(a.name(), "test-a");
        flags(a.as_raw_fd());
        assert_eq!(a.layer(), PacketLayer::Ip);
        let mut out = [0; 8];
        assert_eq!(a.receive(&mut out).unwrap(), None);
        let mut packet = *b"12345678";
        assert_eq!(b.transmit(&packet).unwrap(), TxOutcome::Submitted);
        packet.fill(0);
        assert_eq!(a.receive(&mut out).unwrap(), Some(8));
        assert_eq!(&out, b"12345678");
        for capacity in [0, 7] {
            b.transmit(&[1; 64]).unwrap();
            assert_eq!(
                a.receive(&mut out[..capacity]).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(a.receive(&mut out).unwrap(), None);
        }
        backpressure(&mut a, &mut b);
        drop(a);
        assert!(b.transmit(b"x").is_err());
    }
}
