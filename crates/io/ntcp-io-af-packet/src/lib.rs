#![cfg(target_os = "linux")]

mod timestamp;
mod vnet;
use ntcp_io::linux::{received, transmitted};
use ntcp_io::{
    PacketIo, PacketLayer, ReceivedPacket, TimestampCapabilities, TransmitError, TransmitRequest,
    TxOutcome, TxPacket, TxTimestampCompletion, TxTimestampRequest,
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
        if protocol == libc::ETH_P_ALL as u16 {
            Self::bind_filtered(ifindex, None)
        } else {
            Self::bind_protocols(ifindex, &[protocol])
        }
    }
    // Received frames of any of `protocols` (host-order EtherTypes, at most
    // eight), never this socket's own transmissions: a port that resolves
    // its IPv4 next hops by ARP needs ARP beside IP on one socket.
    pub fn bind_protocols(ifindex: u32, protocols: &[u16]) -> io::Result<Self> {
        if protocols.is_empty()
            || protocols.len() > 8
            || protocols
                .iter()
                .any(|&p| p == 0 || p == libc::ETH_P_ALL as u16)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid interface index or protocol",
            ));
        }
        Self::bind_filtered(ifindex, Some(protocols))
    }
    fn bind_filtered(ifindex: u32, protocols: Option<&[u16]>) -> io::Result<Self> {
        if ifindex == 0 || ifindex > i32::MAX as u32 {
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
        if let Some(protocols) = protocols {
            // Protocol-specific taps run after Linux may clear VLAN metadata.
            // Use the early ALL tap, filtering skb protocol in-kernel instead.
            // Specific-protocol taps do not receive outgoing packets.
            let statement = |code: u32, k: u32, jt: u8, jf: u8| libc::sock_filter {
                code: code as u16,
                jt,
                jf,
                k,
            };
            let count = protocols.len() as u8;
            let mut instructions = Vec::with_capacity(protocols.len() + 5);
            instructions.push(statement(
                libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
                (libc::SKF_AD_OFF + libc::SKF_AD_PKTTYPE) as u32,
                0,
                0,
            ));
            // Outgoing: to the drop after the protocol tests.
            instructions.push(statement(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                libc::PACKET_OUTGOING as u32,
                count + 1,
                0,
            ));
            instructions.push(statement(
                libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
                (libc::SKF_AD_OFF + libc::SKF_AD_PROTOCOL) as u32,
                0,
                0,
            ));
            // A matching protocol: to the accept after the drop.
            for (index, &protocol) in protocols.iter().enumerate() {
                instructions.push(statement(
                    libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                    u32::from(protocol),
                    count - index as u8,
                    0,
                ));
            }
            instructions.push(statement(libc::BPF_RET | libc::BPF_K, 0, 0, 0));
            instructions.push(statement(libc::BPF_RET | libc::BPF_K, u32::MAX, 0, 0));
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
        self.send_controlled_packet(
            &TxPacket {
                header: packet,
                payload: &[],
            },
            packet.len(),
            request,
        )
    }

    #[allow(clippy::unnecessary_cast)] // msghdr lengths differ on musl/glibc
    fn send_controlled_packet(
        &mut self,
        packet: &TxPacket<'_>,
        total: usize,
        request: Option<TxTimestampRequest>,
    ) -> io::Result<TxOutcome> {
        const STACK_IOVS: usize = 16;
        // Linux UIO_MAXIOV / POSIX IOV_MAX (linux/uio.h).
        const MAX_IOVS: usize = 1024;
        let mut prepared = if let Some(request) = request {
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
            Some((control, length, id, request))
        } else {
            None
        };
        let mut vnet_header = [0u8; vnet::LEN];
        let prefix = if self.vnet_header {
            vnet_header.len()
        } else {
            0
        };
        let expected = total
            .checked_add(prefix)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "packet length overflow"))?;

        let mut stack = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        }; STACK_IOVS];
        let mut len = 0usize;
        let mut heap: Vec<libc::iovec> = Vec::new();
        let mut push = |ptr: *mut libc::c_void, bytes_len: usize| {
            if bytes_len == 0 {
                return;
            }
            let iov = libc::iovec {
                iov_base: ptr,
                iov_len: bytes_len,
            };
            if !heap.is_empty() {
                heap.push(iov);
            } else if len < STACK_IOVS {
                stack[len] = iov;
                len += 1;
            } else {
                heap.reserve(STACK_IOVS + 1);
                heap.extend_from_slice(&stack);
                heap.push(iov);
            }
        };
        if self.vnet_header {
            push(vnet_header.as_mut_ptr().cast(), vnet_header.len());
        }
        push(
            packet.header.as_ptr().cast_mut().cast(),
            packet.header.len(),
        );
        for part in packet.payload {
            let bytes = part.bytes();
            push(bytes.as_ptr().cast_mut().cast(), bytes.len());
        }

        let mut fallback: Vec<u8> = Vec::new();
        let iovs: &mut [libc::iovec] = if heap.len() > MAX_IOVS {
            fallback.reserve_exact(expected);
            if self.vnet_header {
                fallback.extend_from_slice(&vnet_header);
            }
            fallback.extend_from_slice(packet.header);
            for part in packet.payload {
                fallback.extend_from_slice(part.bytes());
            }
            stack[0] = libc::iovec {
                iov_base: fallback.as_mut_ptr().cast(),
                iov_len: fallback.len(),
            };
            &mut stack[..1]
        } else if heap.is_empty() {
            &mut stack[..len]
        } else {
            &mut heap
        };

        // SAFETY: pointers remain live through sendmsg; send does not mutate iov.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = iovs.as_mut_ptr();
        message.msg_iovlen = iovs.len() as _;
        if let Some((control, length, _, _)) = prepared.as_mut() {
            control.attach(&mut message);
            message.msg_controllen = *length as _;
        }
        // SAFETY: message and its readable packet/control buffers are live.
        let count = unsafe {
            libc::sendmsg(
                self.as_raw_fd(),
                &message,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if count < 0
            && prepared.is_some()
            && matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::EINVAL | libc::ENOPROTOOPT | libc::EOPNOTSUPP)
            )
        {
            return Err(timestamp::unsupported());
        }
        let outcome = transmitted(count, expected)?;
        if outcome == TxOutcome::Submitted
            && let Some((_, _, id, request)) = prepared
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
        // DATA_VALID (TP_STATUS_CSUM_VALID) is not reported: the stack
        // verifies every checksum (vnet::decode).
        Ok(Some(ReceivedPacket {
            len,
            timestamps,
            tcp_segment_size,
            l4_checksum: ntcp_io::RxChecksum::Unknown,
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

    fn transmit_packet(
        &mut self,
        packet: &TxPacket<'_>,
        request: TransmitRequest,
    ) -> Result<TxOutcome, TransmitError> {
        let total = packet.checked_len().ok_or(TransmitError::InvalidInput)?;
        let TransmitRequest {
            tcp_checksum_offload,
            segmentation,
            timestamp,
            when,
        } = request;
        if segmentation.is_some() || tcp_checksum_offload || when.is_some() {
            return Err(TransmitError::Unsupported);
        }
        if self.vnet_header && total.checked_add(vnet::LEN).is_none() {
            return Err(TransmitError::InvalidInput);
        }
        self.send_controlled_packet(packet, total, timestamp)
            .map_err(|error| {
                if timestamp.is_some() {
                    match error.kind() {
                        io::ErrorKind::Unsupported => TransmitError::Unsupported,
                        io::ErrorKind::InvalidInput => TransmitError::InvalidInput,
                        _ => TransmitError::Other(error),
                    }
                } else {
                    TransmitError::Other(error)
                }
            })
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
        for protocols in [&[][..], &[0x0800, 0], &[3], &[0x0800; 9]] {
            assert_eq!(
                AfPacket::bind_protocols(1, protocols).err().unwrap().kind(),
                io::ErrorKind::InvalidInput
            );
        }
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

    #[test]
    fn transmit_packet_gathers_with_and_without_vnet_handles_backpressure_and_i8() {
        use ntcp_io::{
            ChunkSlice, ClockDescriptor, ClockDomain, Payload, PayloadSlice,
            TcpSegmentationRequest, TimestampUnit, TransmitTime, TxChunk, TxPart,
        };

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

        let mut chunk = TxChunk::heap(64);
        chunk.append(b"XXchunk-bodyYY");
        let shared = Payload::from_vec(b"ZZshared-tailWW".to_vec());
        let parts = [
            TxPart::Chunk(ChunkSlice::new(&chunk, 0..0).unwrap()),
            TxPart::Chunk(ChunkSlice::new(&chunk, 2..12).unwrap()),
            TxPart::Shared(PayloadSlice::new(&shared, 4..4).unwrap()),
            TxPart::Shared(PayloadSlice::new(&shared, 2..13).unwrap()),
        ];
        let packet = TxPacket {
            header: b"ETH:",
            payload: &parts,
        };

        // Plain multi-part send (no vnet_header).
        assert_eq!(
            b.transmit_packet(&packet, TransmitRequest::default())
                .unwrap(),
            TxOutcome::Submitted
        );
        let mut out = [0u8; 64];
        let n = a.receive(&mut out).unwrap().unwrap();
        assert_eq!(&out[..n], b"ETH:chunk-bodyshared-tail");

        // Zero-length packet without vnet_header.
        let empty_packet = TxPacket {
            header: &[],
            payload: &[TxPart::Chunk(ChunkSlice::new(&chunk, 0..0).unwrap())],
        };
        assert_eq!(
            b.transmit_packet(&empty_packet, TransmitRequest::default())
                .unwrap(),
            TxOutcome::Submitted
        );
        assert_eq!(a.receive(&mut out).unwrap(), Some(0));

        // > 16 iovecs (heap spill path).
        let many_storage = Payload::from_vec((0..20u8).collect());
        let many_parts: Vec<TxPart<'_>> = (0..20)
            .map(|i| TxPart::Shared(PayloadSlice::new(&many_storage, i..i + 1).unwrap()))
            .collect();
        let many_packet = TxPacket {
            header: b"H",
            payload: &many_parts,
        };
        assert_eq!(
            b.transmit_packet(&many_packet, TransmitRequest::default())
                .unwrap(),
            TxOutcome::Submitted
        );
        let n = a.receive(&mut out).unwrap().unwrap();
        let mut expected = vec![b'H'];
        expected.extend(0..20u8);
        assert_eq!(&out[..n], expected.as_slice());

        // > UIO_MAXIOV (1024) iovecs (gather fallback path, with vnet_header).
        b.vnet_header = true;
        let huge_storage = Payload::from_vec((0..1025).map(|i| (i & 0xff) as u8).collect());
        let huge_parts: Vec<TxPart<'_>> = (0..1025)
            .map(|i| TxPart::Shared(PayloadSlice::new(&huge_storage, i..i + 1).unwrap()))
            .collect();
        let huge_packet = TxPacket {
            header: b"!",
            payload: &huge_parts,
        };
        assert_eq!(
            b.transmit_packet(&huge_packet, TransmitRequest::default())
                .unwrap(),
            TxOutcome::Submitted
        );
        let mut huge_out = vec![0u8; vnet::LEN + 1026];
        let n = a.receive(&mut huge_out).unwrap().unwrap();
        assert_eq!(n, vnet::LEN + 1026);
        assert_eq!(&huge_out[..vnet::LEN], &[0u8; vnet::LEN]);
        assert_eq!(huge_out[vnet::LEN], b'!');
        assert_eq!(&huge_out[vnet::LEN + 1..], huge_storage.as_slice());
        b.vnet_header = false;

        // With vnet_header enabled on sender: prepends zeroed vnet header in iov[0].
        b.vnet_header = true;
        assert_eq!(
            b.transmit_packet(&packet, TransmitRequest::default())
                .unwrap(),
            TxOutcome::Submitted
        );
        let n = a.receive(&mut out).unwrap().unwrap();
        assert_eq!(n, vnet::LEN + b"ETH:chunk-bodyshared-tail".len());
        assert_eq!(&out[..vnet::LEN], &[0u8; vnet::LEN]);
        assert_eq!(&out[vnet::LEN..n], b"ETH:chunk-bodyshared-tail");

        // With vnet_header enabled on both sender and receiver: stripped cleanly.
        a.vnet_header = true;
        assert_eq!(
            b.transmit_packet(&packet, TransmitRequest::default())
                .unwrap(),
            TxOutcome::Submitted
        );
        let n = a.receive(&mut out).unwrap().unwrap();
        assert_eq!(&out[..n], b"ETH:chunk-bodyshared-tail");
        a.vnet_header = false;
        b.vnet_header = false;

        // I8 unsupported combinations and timestamp validation submit nothing.
        let when = Some(TransmitTime {
            value: 100,
            clock: ClockDescriptor {
                domain: ClockDomain::Monotonic,
                unit: TimestampUnit::Nanoseconds,
            },
        });
        let segmentation = Some(TcpSegmentationRequest {
            segment_payload_len: 10,
        });
        let timestamp = Some(TxTimestampRequest {
            cookie: 7,
            software: true,
            hardware: false,
        });
        let empty_timestamp = Some(TxTimestampRequest {
            cookie: 8,
            software: false,
            hardware: false,
        });
        for unsupported in [
            TransmitRequest {
                segmentation,
                ..Default::default()
            },
            TransmitRequest {
                segmentation,
                when,
                ..Default::default()
            },
            TransmitRequest {
                segmentation,
                timestamp,
                ..Default::default()
            },
            TransmitRequest {
                segmentation,
                timestamp: empty_timestamp,
                ..Default::default()
            },
            TransmitRequest {
                tcp_checksum_offload: true,
                ..Default::default()
            },
            TransmitRequest {
                tcp_checksum_offload: true,
                when,
                ..Default::default()
            },
            TransmitRequest {
                tcp_checksum_offload: true,
                timestamp,
                ..Default::default()
            },
            TransmitRequest {
                tcp_checksum_offload: true,
                timestamp: empty_timestamp,
                ..Default::default()
            },
            TransmitRequest {
                when,
                ..Default::default()
            },
            TransmitRequest {
                when,
                timestamp,
                ..Default::default()
            },
            // Timestamp requested when timestamps not enabled on socket.
            TransmitRequest {
                timestamp,
                ..Default::default()
            },
        ] {
            assert!(matches!(
                b.transmit_packet(&packet, unsupported),
                Err(TransmitError::Unsupported)
            ));
        }
        assert!(matches!(
            b.transmit_packet(
                &packet,
                TransmitRequest {
                    timestamp: empty_timestamp,
                    ..Default::default()
                }
            ),
            Err(TransmitError::InvalidInput)
        ));
        assert_eq!(a.receive(&mut out).unwrap(), None);

        // Timestamp capacity / unsupported source / duplicate cookie checks with State.
        b.timestamps = Some(
            State::new(TimestampConfig {
                tx_software: true,
                tx_completion_capacity: 1,
                ..Default::default()
            })
            .unwrap(),
        );
        // Hardware timestamp requested on software-only config -> Unsupported.
        assert!(matches!(
            b.transmit_packet(
                &packet,
                TransmitRequest {
                    timestamp: Some(TxTimestampRequest {
                        cookie: 1,
                        software: false,
                        hardware: true,
                    }),
                    ..Default::default()
                }
            ),
            Err(TransmitError::Unsupported)
        ));
        // Reserve capacity with a pending entry -> duplicate cookie is InvalidInput,
        // new cookie hits capacity WouldBlock without touching the socket.
        let pending_req = TxTimestampRequest {
            cookie: 10,
            software: true,
            hardware: false,
        };
        let id = b
            .timestamps
            .as_ref()
            .unwrap()
            .prepare(pending_req)
            .unwrap()
            .unwrap();
        b.timestamps.as_mut().unwrap().submitted(id, pending_req);
        assert!(matches!(
            b.transmit_packet(
                &packet,
                TransmitRequest {
                    timestamp: Some(pending_req),
                    ..Default::default()
                }
            ),
            Err(TransmitError::InvalidInput)
        ));
        assert_eq!(
            b.transmit_packet(
                &packet,
                TransmitRequest {
                    timestamp: Some(TxTimestampRequest {
                        cookie: 11,
                        software: true,
                        hardware: false,
                    }),
                    ..Default::default()
                }
            )
            .unwrap(),
            TxOutcome::WouldBlock
        );
        assert_eq!(a.receive(&mut out).unwrap(), None);
        b.timestamps = None;

        // Backpressure (WouldBlock) with multi-part TxPacket.
        let mut rx_buf = [0u8; 1024];
        let mut hit_would_block = false;
        let fill_shared = Payload::from_vec(vec![0xA5u8; 768]);
        let fill_parts = [TxPart::Shared(
            PayloadSlice::new(&fill_shared, 0..768).unwrap(),
        )];
        for submitted in 0..10000usize {
            let hdr = [submitted as u8; 256];
            let pkt = TxPacket {
                header: &hdr,
                payload: &fill_parts,
            };
            if b.transmit_packet(&pkt, TransmitRequest::default()).unwrap() == TxOutcome::WouldBlock
            {
                hit_would_block = true;
                for i in 0..submitted {
                    assert_eq!(a.receive(&mut rx_buf).unwrap(), Some(1024));
                    assert_eq!(&rx_buf[..256], &[i as u8; 256]);
                    assert_eq!(&rx_buf[256..], &[0xA5u8; 768]);
                }
                assert_eq!(a.receive(&mut rx_buf).unwrap(), None);
                assert_eq!(
                    b.transmit_packet(&pkt, TransmitRequest::default()).unwrap(),
                    TxOutcome::Submitted
                );
                assert_eq!(a.receive(&mut rx_buf).unwrap(), Some(1024));
                assert_eq!(&rx_buf[..256], &[submitted as u8; 256]);
                assert_eq!(&rx_buf[256..], &[0xA5u8; 768]);
                break;
            }
        }
        assert!(hit_would_block, "queue never filled");
    }
}
