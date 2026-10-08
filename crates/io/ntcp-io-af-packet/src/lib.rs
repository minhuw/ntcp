#![cfg(target_os = "linux")]

mod timestamp;
use ntcp_io::{
    PacketIo, PacketLayer, ReceivedPacket, TimestampCapabilities, TxOutcome, TxTimestampCompletion,
    TxTimestampRequest,
};
use std::{
    io,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
};
pub use timestamp::TimestampConfig;
use timestamp::{Control, State};

pub struct AfPacket {
    fd: OwnedFd,
    timestamps: Option<State>,
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
        if unsafe { libc::ioctl(probe.as_raw_fd(), libc::SIOCGIFHWADDR as _, &mut request) } < 0 {
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
        Ok(Self {
            fd,
            timestamps: None,
        })
    }

    // One-time opt-in; the host owns NIC timestamp configuration. Explicit TX
    // IDs require Linux 6.13+. An older kernel rejects the send's cmsg before
    // accepting a packet (Unsupported), never guessed counter correlation.
    pub fn enable_timestamps(&mut self, config: TimestampConfig) -> io::Result<()> {
        if self.timestamps.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "timestamps already configured",
            ));
        }
        let flags = config.flags()?;
        let state = State::new(config)?;
        // SAFETY: flags is a live socket-option integer; no NIC ioctl is used.
        if unsafe {
            libc::setsockopt(
                self.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMPING,
                (&flags as *const libc::c_int).cast(),
                std::mem::size_of_val(&flags) as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        self.timestamps = Some(state);
        Ok(())
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

impl PacketIo for AfPacket {
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ethernet
    }

    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        self.receive_with_metadata(out)
            .map(|packet| packet.map(|packet| packet.len))
    }

    fn timestamp_capabilities(&self) -> TimestampCapabilities {
        self.timestamps
            .as_ref()
            .map_or_else(TimestampCapabilities::default, |s| s.config.capabilities())
    }

    #[allow(clippy::unnecessary_cast)] // msghdr lengths differ on musl/glibc
    fn receive_with_metadata(&mut self, out: &mut [u8]) -> io::Result<Option<ReceivedPacket>> {
        // MSG_TRUNC reports full packet length; AUXDATA still rejects VLAN loss.
        let mut vector = libc::iovec {
            iov_base: out.as_mut_ptr().cast(),
            iov_len: out.len(),
        };
        let mut control = Control::new();
        // SAFETY: zero is valid; all pointers below stay live through recvmsg.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        control.attach(&mut message);
        // SAFETY: message references writable stack buffers, none retained.
        let count = unsafe {
            libc::recvmsg(
                self.as_raw_fd(),
                &mut message,
                libc::MSG_TRUNC | libc::MSG_DONTWAIT,
            )
        };
        let Some(len) = received(count, out.len())? else {
            return Ok(None);
        };
        if message.msg_flags & libc::MSG_TRUNC != 0 {
            return Err(timestamp::invalid("truncated packet"));
        }
        let config = self
            .timestamps
            .as_ref()
            .map(|s| s.config)
            .unwrap_or_default();
        let mut timestamps = control
            .parse(
                message.msg_controllen as usize,
                message.msg_flags,
                config.device_clock,
                false,
            )?
            .timestamps;
        if !config.rx_software {
            timestamps.software = None;
        }
        if !config.rx_hardware {
            timestamps.hardware = None;
        }
        Ok(Some(ReceivedPacket { len, timestamps }))
    }

    fn transmit_with_timestamp(
        &mut self,
        packet: &[u8],
        request: TxTimestampRequest,
    ) -> io::Result<TxOutcome> {
        if !request.software && !request.hardware {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty timestamp request",
            ));
        }
        let state = self
            .timestamps
            .as_ref()
            .ok_or_else(timestamp::unsupported)?;
        let Some(id) = state.prepare(request)? else {
            return Ok(TxOutcome::WouldBlock);
        };
        let (mut control, length) = Control::tx(request, id);
        let mut vector = libc::iovec {
            iov_base: packet.as_ptr().cast_mut().cast(),
            iov_len: packet.len(),
        };
        // SAFETY: pointers remain live through sendmsg; send does not mutate iov.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        control.attach(&mut message);
        message.msg_controllen = length as _;
        // SAFETY: message and its readable packet/control buffers are live.
        let count = unsafe {
            libc::sendmsg(
                self.as_raw_fd(),
                &message,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if count < 0
            && matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::EINVAL | libc::ENOPROTOOPT | libc::EOPNOTSUPP)
            )
        {
            return Err(timestamp::unsupported());
        }
        let outcome = transmitted(count, packet.len())?;
        if outcome == TxOutcome::Submitted {
            self.timestamps.as_mut().unwrap().submitted(id, request);
        }
        Ok(outcome)
    }

    fn cancel_tx_timestamp(&mut self, cookie: u64) -> io::Result<bool> {
        let state = self
            .timestamps
            .as_mut()
            .ok_or_else(timestamp::unsupported)?;
        if !state.config.tx_software && !state.config.tx_hardware {
            return Err(timestamp::unsupported());
        }
        Ok(state.cancel(cookie))
    }

    #[allow(clippy::unnecessary_cast)] // msghdr lengths differ on musl/glibc
    fn poll_tx_timestamp(&mut self) -> io::Result<Option<TxTimestampCompletion>> {
        let fd = self.as_raw_fd();
        let state = self
            .timestamps
            .as_mut()
            .ok_or_else(timestamp::unsupported)?;
        if !state.config.tx_software && !state.config.tx_hardware {
            return Err(timestamp::unsupported());
        }
        if let Some(event) = state.pop() {
            return Ok(Some(event));
        }
        // Consume at most ONE error-queue record, including unrelated records.
        let mut control = Control::new();
        // SAFETY: zero msghdr with no packet iov is valid for MSG_ERRQUEUE;
        // OPT_TSONLY means the timestamp does not need a payload buffer.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        control.attach(&mut message);
        // SAFETY: writable control storage is live through recvmsg.
        let count =
            unsafe { libc::recvmsg(fd, &mut message, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT) };
        if count < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(error)
            };
        }
        state.complete(control.parse(
            message.msg_controllen as usize,
            message.msg_flags,
            state.config.device_clock,
            true,
        )?);
        Ok(state.pop())
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
        let mut a = AfPacket {
            fd: a,
            timestamps: None,
        };
        let mut b = AfPacket {
            fd: b,
            timestamps: None,
        };
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
