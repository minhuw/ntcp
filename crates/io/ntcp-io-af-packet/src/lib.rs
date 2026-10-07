#![cfg(target_os = "linux")]

use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use std::{
    io,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
};

pub struct AfPacket {
    fd: OwnedFd,
}

impl AfPacket {
    // Protocol is a host-order EtherType (e.g. ETH_P_ALL). No interface settings
    // or promiscuous membership are changed. CAP_NET_RAW is required.
    pub fn bind(ifindex: u32, protocol: u16) -> io::Result<Self> {
        if ifindex == 0 || ifindex > i32::MAX as u32 || protocol == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid interface index or protocol",
            ));
        }
        // SAFETY: zero is valid for ifreq, including its name buffer.
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        // SAFETY: the name buffer holds IF_NAMESIZE bytes.
        if unsafe { libc::if_indextoname(ifindex, request.ifr_name.as_mut_ptr()) }.is_null() {
            return Err(io::Error::last_os_error());
        }
        let probe = socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
        // SAFETY: live socket and writable ifreq with a terminated interface name.
        if unsafe { libc::ioctl(probe.as_raw_fd(), libc::SIOCGIFHWADDR, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: SIOCGIFHWADDR initialized this union member.
        if unsafe { request.ifr_ifru.ifru_hwaddr.sa_family } != libc::ARPHRD_ETHER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface is not Ethernet",
            ));
        }
        // Start with reception disabled; bind enables only the requested
        // protocol/interface, avoiding packets queued from other interfaces.
        let fd = socket(libc::AF_PACKET, libc::SOCK_RAW, 0)?;
        let enabled: libc::c_int = 1;
        // SAFETY: enabled is a live, correctly sized socket option integer.
        if unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_AUXDATA,
                (&enabled as *const libc::c_int).cast(),
                std::mem::size_of_val(&enabled) as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if protocol != libc::ETH_P_ALL as u16 {
            // Protocol-specific taps run after Linux may clear VLAN metadata.
            // Use the early ALL tap, filtering skb protocol in-kernel instead.
            // Specific-protocol taps do not receive outgoing packets.
            let mut instructions = [
                libc::sock_filter {
                    code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                    jt: 0,
                    jf: 0,
                    k: (libc::SKF_AD_OFF + libc::SKF_AD_PKTTYPE) as u32,
                },
                libc::sock_filter {
                    code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    jt: 3,
                    jf: 0,
                    k: libc::PACKET_OUTGOING as u32,
                },
                libc::sock_filter {
                    code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                    jt: 0,
                    jf: 0,
                    k: (libc::SKF_AD_OFF + libc::SKF_AD_PROTOCOL) as u32,
                },
                libc::sock_filter {
                    code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 1,
                    k: u32::from(protocol),
                },
                libc::sock_filter {
                    code: (libc::BPF_RET | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 0,
                    k: u32::MAX,
                },
                libc::sock_filter {
                    code: (libc::BPF_RET | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
            ];
            let filter = libc::sock_fprog {
                len: instructions.len() as u16,
                filter: instructions.as_mut_ptr(),
            };
            // SAFETY: filter and its instructions are live; Linux copies them.
            if unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ATTACH_FILTER,
                    (&filter as *const libc::sock_fprog).cast(),
                    std::mem::size_of_val(&filter) as libc::socklen_t,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        // SAFETY: zero initializes all sockaddr_ll fields and padding.
        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        address.sll_family = libc::AF_PACKET as u16;
        address.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        address.sll_ifindex = ifindex as i32;
        // SAFETY: address is a correctly sized sockaddr_ll, and fd is live.
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_ll).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }
}

fn socket(domain: i32, kind: i32, protocol: i32) -> io::Result<OwnedFd> {
    // SAFETY: socket takes only integer arguments; ownership is acquired once.
    let fd = unsafe {
        libc::socket(
            domain,
            kind | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            protocol,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: socket returned a new owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

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
        return if error.kind() == io::ErrorKind::WouldBlock {
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

// Only called with a msghdr backed by live, aligned control storage.
fn check_auxdata(message: &libc::msghdr) -> io::Result<()> {
    if message.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated packet ancillary data",
        ));
    }
    // SAFETY: recvmsg initialized the bounded control buffer and its length.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(message);
        while !header.is_null() {
            let base = libc::CMSG_LEN(0) as usize;
            let length = (*header).cmsg_len;
            let offset = header as usize - message.msg_control as usize;
            if length < base || length > message.msg_controllen - offset {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid packet ancillary data",
                ));
            }
            if (*header).cmsg_level == libc::SOL_PACKET
                && (*header).cmsg_type == libc::PACKET_AUXDATA
            {
                if length
                    < libc::CMSG_LEN(std::mem::size_of::<libc::tpacket_auxdata>() as u32) as usize
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "short PACKET_AUXDATA",
                    ));
                }
                let aux = libc::CMSG_DATA(header)
                    .cast::<libc::tpacket_auxdata>()
                    .read_unaligned();
                if aux.tp_status & libc::TP_STATUS_VLAN_VALID != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "VLAN-stripped packet discarded",
                    ));
                }
            }
            header = libc::CMSG_NXTHDR(message, header);
        }
    }
    Ok(())
}

impl PacketIo for AfPacket {
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ethernet
    }

    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        // MSG_TRUNC reports the full packet length in this single consuming
        // syscall. AUXDATA tells us whether Linux stripped a VLAN header.
        let mut vector = libc::iovec {
            iov_base: out.as_mut_ptr().cast(),
            iov_len: out.len(),
        };
        // usize provides cmsghdr alignment; enough room for PACKET_AUXDATA.
        let mut control = [0usize; 8];
        // SAFETY: zero is valid for msghdr; all pointers below stay live.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control);
        // SAFETY: message references writable stack buffers; no pointer retained.
        let count = unsafe {
            libc::recvmsg(
                self.as_raw_fd(),
                &mut message,
                libc::MSG_TRUNC | libc::MSG_DONTWAIT,
            )
        };
        let length = received(count, out.len())?;
        if length.is_some() {
            check_auxdata(&message)?;
        }
        Ok(length)
    }

    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        // SAFETY: packet remains readable for the duration of the single send.
        let count = unsafe {
            libc::send(
                self.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        transmitted(count, packet.len())
    }
}

impl AsFd for AfPacket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
impl AsRawFd for AfPacket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn ancillary_validation() {
        let mut control = [0usize; 8];
        // SAFETY: zero is valid for msghdr, cmsghdr and tpacket_auxdata.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen =
            unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::tpacket_auxdata>() as u32) }
                as usize;
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        let length =
            unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::tpacket_auxdata>() as u32) } as usize;
        // SAFETY: the aligned control buffer has room for this header and payload.
        unsafe {
            (*header).cmsg_level = libc::SOL_PACKET;
            (*header).cmsg_type = libc::PACKET_AUXDATA;
            (*header).cmsg_len = length;
            let mut aux: libc::tpacket_auxdata = std::mem::zeroed();
            libc::CMSG_DATA(header)
                .cast::<libc::tpacket_auxdata>()
                .write_unaligned(aux);
            check_auxdata(&message).unwrap();
            // VLAN_VALID is authoritative even for priority-only VLAN (TCI 0).
            aux.tp_status = libc::TP_STATUS_VLAN_VALID;
            libc::CMSG_DATA(header)
                .cast::<libc::tpacket_auxdata>()
                .write_unaligned(aux);
            assert_eq!(
                check_auxdata(&message).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
            message.msg_flags = libc::MSG_CTRUNC;
            assert_eq!(
                check_auxdata(&message).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            message.msg_flags = 0;
            for short in [
                0,
                libc::CMSG_LEN(0) as usize,
                length - 1,
                message.msg_controllen + 1,
            ] {
                (*header).cmsg_len = short;
                assert_eq!(
                    check_auxdata(&message).unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
            }
        }
    }

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

    #[test]
    fn validation() {
        for (index, protocol) in [(0, 3), (u32::MAX, 3), (1, 0)] {
            assert_eq!(
                AfPacket::bind(index, protocol).err().unwrap().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert!(AfPacket::bind(i32::MAX as u32, 3).is_err());
        // Loopback is not Ethernet, even when CAP_NET_RAW is available.
        let name = c"lo";
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        assert!(index != 0);
        assert_eq!(
            AfPacket::bind(index, 3).err().unwrap().kind(),
            io::ErrorKind::InvalidInput
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

    #[test]
    fn packets_and_ownership() {
        let (a, b) = pair();
        let mut a = AfPacket { fd: a };
        let mut b = AfPacket { fd: b };
        flags(a.as_raw_fd());
        assert_eq!(a.layer(), PacketLayer::Ethernet);
        assert_eq!(a.receive(&mut [0; 8]).unwrap(), None);
        let mut packet = *b"12345678";
        assert_eq!(b.transmit(&packet).unwrap(), TxOutcome::Submitted);
        packet.fill(0);
        let mut out = [0; 8];
        assert_eq!(a.receive(&mut out).unwrap(), Some(8));
        assert_eq!(&out, b"12345678");
        for capacity in [0, 7] {
            b.transmit(b"12345678").unwrap();
            assert_eq!(
                a.receive(&mut out[..capacity]).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(a.receive(&mut out).unwrap(), None);
        }
        assert_eq!(
            transmitted(3, 4).unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
        backpressure(&mut a, &mut b);
        drop(a);
        assert!(b.transmit(b"x").is_err()); // peer fd was closed
    }
}
