#![cfg(target_os = "linux")]

mod scheduling;
mod timestamp;
use ntcp_io::{
    PacketIo, PacketLayer, ReceivedPacket, TimestampCapabilities, TransmitTime, TxOutcome,
    TxSchedulingCapabilities, TxSchedulingError, TxTimestampCompletion, TxTimestampRequest,
};
pub use scheduling::TxSchedulingConfig;
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
    scheduling: Option<TxSchedulingConfig>,
    scheduling_error: Option<TxSchedulingError>,
    packet_mark: u32,
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
            ifindex,
            fd,
            timestamps: None,
            scheduling: None,
            scheduling_error: None,
            packet_mark: 0,
        })
    }

    // Caller owns fq and its horizon configuration for this socket's lifetime.
    // fq horizon/queue drops may NOT report individual errors; no delivery ACK.
    pub fn enable_tx_scheduling(&mut self, config: TxSchedulingConfig) -> io::Result<()> {
        if self.scheduling.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "TX scheduling already configured",
            ));
        }
        if !config.caller_owned_fq
            || config.max_future_ns == 0
            || config.max_future_ns > i64::MAX as u64
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "caller-owned fq and bounded horizon required",
            ));
        }
        let option = libc::sock_txtime {
            clockid: libc::CLOCK_MONOTONIC,
            flags: libc::SOF_TXTIME_REPORT_ERRORS,
        };
        // SAFETY: live fd and correctly sized Linux sock_txtime. Strict mode:
        // no DEADLINE_MODE, and this adapter never enables PACKET_QDISC_BYPASS.
        if unsafe {
            libc::setsockopt(
                self.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TXTIME,
                (&option as *const libc::sock_txtime).cast(),
                std::mem::size_of_val(&option) as _,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        self.scheduling = Some(config);
        Ok(())
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
        when: Option<TransmitTime>,
        request: Option<TxTimestampRequest>,
    ) -> io::Result<TxOutcome> {
        let (mut control, mut length, prepared) = if let Some(request) = request {
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
        if let Some(when) = when {
            control.append(&mut length, libc::SOL_SOCKET, libc::SCM_TXTIME, when.value);
        }
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
        if outcome == TxOutcome::Submitted
            && let Some((id, request)) = prepared
        {
            self.timestamps.as_mut().unwrap().submitted(id, request);
        }
        Ok(outcome)
    }

    #[allow(clippy::unnecessary_cast)]
    fn poll_error_queue(&mut self) -> io::Result<()> {
        // A single buffered scheduling error applies backpressure to the shared
        // queue. Never eat timestamp completions or silently overwrite errors.
        if self.scheduling_error.is_some() {
            return Ok(());
        }
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
        self.dispatch_error(metadata);
        Ok(())
    }

    fn dispatch_error(&mut self, metadata: timestamp::Metadata) {
        if let Some(error) = metadata.error.and_then(scheduling::error) {
            self.scheduling_error = Some(error);
        } else if let Some(state) = self.timestamps.as_mut() {
            state.complete(metadata);
        }
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

    fn tx_scheduling_capabilities(&self) -> Option<TxSchedulingCapabilities> {
        self.scheduling.map(|_| TxSchedulingCapabilities {
            clock: scheduling::CLOCK,
            hardware: false,
        })
    }

    fn transmit_at(
        &mut self,
        packet: &[u8],
        when: TransmitTime,
        timestamp: Option<TxTimestampRequest>,
    ) -> io::Result<TxOutcome> {
        let config = self
            .scheduling
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "TX scheduling disabled"))?;
        config.validate(when, scheduling::now()?)?;
        self.send_controlled(packet, Some(when), timestamp)
    }

    fn transmit_with_timestamp(
        &mut self,
        packet: &[u8],
        request: TxTimestampRequest,
    ) -> io::Result<TxOutcome> {
        self.send_controlled(packet, None, Some(request))
    }

    fn poll_tx_scheduling_error(&mut self) -> io::Result<Option<TxSchedulingError>> {
        if self.scheduling.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TX scheduling disabled",
            ));
        }
        if self.scheduling_error.is_none() {
            self.poll_error_queue()?;
        }
        Ok(self.scheduling_error.take())
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
    fn scheduled_validation_backpressure_and_error_demux() {
        let (fd, peer) = pair();
        let config = TxSchedulingConfig {
            caller_owned_fq: true,
            max_future_ns: 1_000_000_000,
        };
        let mut a = AfPacket {
            ifindex: 0,
            fd,
            timestamps: None,
            scheduling: None,
            scheduling_error: None,
            packet_mark: 0,
        };
        let mut b = AfPacket {
            ifindex: 0,
            fd: peer,
            timestamps: None,
            scheduling: None,
            scheduling_error: None,
            packet_mark: 0,
        };
        let when = TransmitTime {
            value: scheduling::now().unwrap() + 500_000_000,
            clock: scheduling::CLOCK,
        };
        assert_eq!(
            a.transmit_at(b"x", when, None).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert!(
            a.enable_tx_scheduling(TxSchedulingConfig {
                caller_owned_fq: false,
                ..config
            })
            .is_err()
        );
        a.scheduling = Some(config); // synthetic config; validation never reaches sendmsg
        for value in [0, u64::MAX] {
            assert_eq!(
                a.transmit_at(b"x", TransmitTime { value, ..when }, None)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let request = TxTimestampRequest {
            cookie: 1,
            software: true,
            hardware: false,
        };
        let mut state = State::new(TimestampConfig {
            tx_software: true,
            tx_completion_capacity: 1,
            ..Default::default()
        })
        .unwrap();
        let id = state.prepare(request).unwrap().unwrap();
        state.submitted(id, request);
        a.timestamps = Some(state);
        assert_eq!(
            a.transmit_at(
                b"x",
                when,
                Some(TxTimestampRequest {
                    cookie: 2,
                    ..request
                })
            )
            .unwrap(),
            TxOutcome::WouldBlock
        );
        assert!(!a.cancel_tx_timestamp(2).unwrap());
        assert_eq!(b.receive(&mut [0; 8]).unwrap(), None);

        // Feed native cmsgs through the same parser and dispatcher as recvmsg.
        let mut control = Control::new();
        let mut used = 0;
        let mut native: libc::sock_extended_err = unsafe { std::mem::zeroed() };
        native.ee_origin = 6; // SO_EE_ORIGIN_TXTIME
        native.ee_data = (when.value >> 32) as u32;
        native.ee_info = when.value as u32;
        native.ee_errno = libc::ECANCELED as u32;
        native.ee_code = 2;
        control.append(
            &mut used,
            libc::SOL_PACKET,
            libc::PACKET_TX_TIMESTAMP,
            native,
        );
        a.dispatch_error(control.parse(used, 0, None, true).unwrap());
        assert!(a.poll_tx_timestamp().unwrap().is_none()); // queued error stalls reads
        assert_eq!(a.poll_tx_scheduling_error().unwrap().unwrap().when, when);
        native.ee_origin = libc::SO_EE_ORIGIN_TIMESTAMPING;
        native.ee_errno = libc::ENOMSG as u32;
        native.ee_info = 0;
        native.ee_data = id;
        let mut used = 0;
        control.append(
            &mut used,
            libc::SOL_PACKET,
            libc::PACKET_TX_TIMESTAMP,
            native,
        );
        control.append(
            &mut used,
            libc::SOL_SOCKET,
            libc::SCM_TIMESTAMPING,
            [
                libc::timespec {
                    tv_sec: 1,
                    tv_nsec: 2,
                },
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
            ],
        );
        a.dispatch_error(control.parse(used, 0, None, true).unwrap());
        assert!(a.poll_tx_scheduling_error().unwrap().is_none());
        assert_eq!(
            a.poll_tx_timestamp().unwrap().unwrap().cookie,
            request.cookie
        );
        assert!(a.poll_tx_timestamp().unwrap().is_none());
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
    fn output_mark_reaches_private_kernel_socket_and_can_be_cleared() {
        let mut io = AfPacket {
            fd: socket(libc::AF_INET, libc::SOCK_DGRAM, 0).unwrap(),
            ifindex: 0,
            timestamps: None,
            scheduling: None,
            scheduling_error: None,
            packet_mark: 0,
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
            scheduling: None,
            scheduling_error: None,
            packet_mark: 0,
        };
        let mut b = AfPacket {
            ifindex: 0,
            fd: b,
            timestamps: None,
            scheduling: None,
            scheduling_error: None,
            packet_mark: 0,
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
