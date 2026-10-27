#![cfg(target_os = "linux")]

mod timestamp;
mod vnet;
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
    ifindex: u32,
    timestamps: Option<State>,
    packet_mark: u32,
    vnet_header: bool,
}

impl AfPacket {
    // Socket-local opt-in. RX retains original TCP segment size; ordinary TX
    // remains fully checksummed and carries an empty virtio header. No host
    // interface, qdisc or offload setting is changed.
    pub fn enable_receive_aggregation(&mut self) -> io::Result<()> {
        if self.vnet_header {
            return Ok(());
        }
        let enabled: libc::c_int = 1;
        // SAFETY: private live socket, correctly sized option, no retained pointer.
        if unsafe {
            libc::setsockopt(
                self.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_VNET_HDR,
                (&enabled as *const libc::c_int).cast(),
                std::mem::size_of_val(&enabled) as _,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        self.vnet_header = true;
        Ok(())
    }
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
            ifindex,
            fd,
            timestamps: None,
            packet_mark: 0,
            vnet_header: false,
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

impl AfPacket {
    fn send_controlled(
        &mut self,
        packet: &[u8],
        request: Option<TxTimestampRequest>,
    ) -> io::Result<TxOutcome> {
        let (mut control, length, prepared) = if let Some(request) = request {
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
            let (control, length) = Control::tx(request, id);
            (control, length, Some((id, request)))
        } else {
            (Control::new(), 0, None)
        };
        let mut header = [0u8; vnet::LEN];
        let prefix = if self.vnet_header { header.len() } else { 0 };
        let mut vectors = [
            libc::iovec {
                iov_base: header.as_mut_ptr().cast(),
                iov_len: prefix,
            },
            libc::iovec {
                iov_base: packet.as_ptr().cast_mut().cast(),
                iov_len: packet.len(),
            },
        ];
        // SAFETY: pointers remain live through sendmsg; send does not mutate iov.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = vectors.as_mut_ptr();
        message.msg_iovlen = vectors.len() as _;
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
        let outcome = transmitted(count, packet.len() + prefix)?;
        if outcome == TxOutcome::Submitted
            && let Some((id, request)) = prepared
        {
            self.timestamps.as_mut().unwrap().submitted(id, request);
        }
        Ok(outcome)
    }

    #[allow(clippy::unnecessary_cast)]
    fn poll_error_queue(&mut self) -> io::Result<()> {
        let mut control = Control::new();
        // SAFETY: zero msghdr with no payload is valid for MSG_ERRQUEUE.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        control.attach(&mut message);
        // SAFETY: writable control storage remains live through recvmsg.
        let count = unsafe {
            libc::recvmsg(
                self.as_raw_fd(),
                &mut message,
                libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT,
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::WouldBlock {
                Ok(())
            } else {
                Err(error)
            };
        }
        let metadata = control.parse(
            message.msg_controllen as usize,
            message.msg_flags,
            self.timestamps.as_ref().and_then(|s| s.config.device_clock),
            true,
        )?;
        if let Some(state) = self.timestamps.as_mut() {
            state.complete(metadata);
        }
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

impl PacketIo for AfPacket {
    fn local_ip_mtu(&self) -> io::Result<Option<u32>> {
        ntcp_io::linux::local_ip_mtu(self.ifindex)
    }
    // The socket has no independent fixed copy-buffer cap; live MTU is separate.

    fn layer(&self) -> PacketLayer {
        PacketLayer::Ethernet
    }

    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        self.receive_with_metadata(out)
            .map(|packet| packet.map(|packet| packet.len))
    }

    fn packet_mark_supported(&self) -> bool {
        true
    }

    fn set_packet_mark(&mut self, mark: u32) -> io::Result<()> {
        if self.packet_mark == mark {
            return Ok(());
        }
        // SAFETY: a live private socket and a correctly sized u32 socket option.
        if unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                (&mark as *const u32).cast(),
                std::mem::size_of_val(&mark) as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        self.packet_mark = mark;
        Ok(())
    }

    fn timestamp_capabilities(&self) -> TimestampCapabilities {
        self.timestamps
            .as_ref()
            .map_or_else(TimestampCapabilities::default, |s| s.config.capabilities())
    }

    #[allow(clippy::unnecessary_cast)] // msghdr lengths differ on musl/glibc
    fn receive_with_metadata(&mut self, out: &mut [u8]) -> io::Result<Option<ReceivedPacket>> {
        // MSG_TRUNC reports full packet length; AUXDATA still rejects VLAN loss.
        let mut header = [0u8; vnet::LEN];
        let prefix = if self.vnet_header { header.len() } else { 0 };
        let mut vectors = [
            libc::iovec {
                iov_base: header.as_mut_ptr().cast(),
                iov_len: prefix,
            },
            libc::iovec {
                iov_base: out.as_mut_ptr().cast(),
                iov_len: out.len(),
            },
        ];
        let mut control = Control::new();
        // SAFETY: zero is valid; all pointers below stay live through recvmsg.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = vectors.as_mut_ptr();
        message.msg_iovlen = vectors.len() as _;
        control.attach(&mut message);
        // SAFETY: message references writable stack buffers, none retained.
        let count = unsafe {
            libc::recvmsg(
                self.as_raw_fd(),
                &mut message,
                libc::MSG_TRUNC | libc::MSG_DONTWAIT,
            )
        };
        let Some(length) = received(count, out.len() + prefix)? else {
            return Ok(None);
        };
        if length < prefix {
            return Err(timestamp::invalid("short virtio header"));
        }
        let len = length - prefix;
        let tcp_segment_size = if self.vnet_header {
            vnet::decode(&header, &mut out[..len])?
        } else {
            None
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
        Ok(Some(ReceivedPacket {
            len,
            timestamps,
            tcp_segment_size,
        }))
    }

    fn transmit_with_timestamp(
        &mut self,
        packet: &[u8],
        request: TxTimestampRequest,
    ) -> io::Result<TxOutcome> {
        self.send_controlled(packet, Some(request))
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
        self.poll_error_queue()?;
        Ok(self.timestamps.as_mut().unwrap().pop())
    }

    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        if self.vnet_header {
            return self.send_controlled(packet, None);
        }
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
    fn receive_aggregation_option_is_socket_local_and_failure_is_atomic() {
        let fd = match socket(libc::AF_PACKET, libc::SOCK_RAW, 0) {
            Ok(fd) => fd,
            Err(e) => {
                assert_eq!(e.raw_os_error(), Some(libc::EPERM));
                return;
            }
        };
        let mut io = AfPacket {
            fd,
            ifindex: 0,
            timestamps: None,
            packet_mark: 0,
            vnet_header: false,
        };
        io.enable_receive_aggregation().unwrap();
        io.enable_receive_aggregation().unwrap();
        let mut actual = 0;
        let mut len = std::mem::size_of_val(&actual) as libc::socklen_t;
        // SAFETY: private live socket and correctly sized writable option buffer.
        assert_eq!(
            unsafe {
                libc::getsockopt(
                    io.as_raw_fd(),
                    libc::SOL_PACKET,
                    libc::PACKET_VNET_HDR,
                    (&mut actual as *mut libc::c_int).cast(),
                    &mut len,
                )
            },
            0
        );
        assert_eq!(actual, 1);
        assert!(io.vnet_header);
        let (fd, _peer) = pair();
        let mut wrong = AfPacket {
            fd,
            ifindex: 0,
            timestamps: None,
            packet_mark: 0,
            vnet_header: false,
        };
        assert!(wrong.enable_receive_aggregation().is_err());
        assert!(!wrong.vnet_header);
    }

    #[test]
    fn output_mark_reaches_private_kernel_socket_and_can_be_cleared() {
        let mut io = AfPacket {
            fd: socket(libc::AF_INET, libc::SOCK_DGRAM, 0).unwrap(),
            ifindex: 0,
            timestamps: None,
            packet_mark: 0,
            vnet_header: false,
        };
        assert!(io.packet_mark_supported());
        if let Err(error) = io.set_packet_mark(u32::MAX) {
            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
            assert_eq!(io.packet_mark, 0);
            return; // Unprivileged test process; packet metadata isolation is tested separately.
        }
        for mark in [u32::MAX, 0, 666] {
            io.set_packet_mark(mark).unwrap();
            let mut actual = 0u32;
            let mut len = std::mem::size_of_val(&actual) as libc::socklen_t;
            // SAFETY: live socket and correctly sized writable option buffers.
            assert_eq!(
                unsafe {
                    libc::getsockopt(
                        io.fd.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_MARK,
                        (&mut actual as *mut u32).cast(),
                        &mut len,
                    )
                },
                0
            );
            assert_eq!(actual, mark);
        }
    }
    #[test]
    fn packets_and_ownership() {
        let (a, b) = pair();
        let mut a = AfPacket {
            ifindex: 0,
            fd: a,
            timestamps: None,
            packet_mark: 0,
            vnet_header: false,
        };
        let mut b = AfPacket {
            ifindex: 0,
            fd: b,
            timestamps: None,
            packet_mark: 0,
            vnet_header: false,
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
