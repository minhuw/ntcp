use crate::{
    PacketIo, PacketLayer, TxOutcome,
    af_packet::{received, transmitted},
};
use std::{
    fs::OpenOptions,
    io,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
        unix::fs::OpenOptionsExt,
    },
};

pub struct Tun {
    fd: OwnedFd,
    name: String,
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
        Ok(Self {
            fd: file.into(),
            name: name.to_owned(),
        })
    }
}

fn invalid_link() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid rtnetlink link response",
    )
}

// rtnetlink attributes have a native-endian u16 length/type and 4-byte alignment.
fn attribute(mut bytes: &[u8], wanted: u16) -> io::Result<Option<&[u8]>> {
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
    // Query the current namespace, not sysfs (which may expose another netns).
    // SAFETY: socket takes integers and returns a new owned fd on success.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: ownership of this newly created descriptor is acquired once.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    // SAFETY: timeout is a correctly sized socket option.
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of_val(&timeout) as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
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
    check_format(&response[32..length])
}

impl PacketIo for Tun {
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
    use crate::af_packet::tests::{backpressure, flags, pair};

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
        };
        let mut b = Tun {
            fd: b,
            name: "test-b".into(),
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
