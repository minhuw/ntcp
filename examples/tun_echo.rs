// Run as: tun_echo TUN_NAME LOCAL_IPV4 TCP_PORT [PEER_IPV4:PORT].
// The caller must configure the TUN interface (MTU 1500) and routes beforehand.
// This adapter exchanges IP packets, not Ethernet frames; it does not configure
// the host or implement ARP, routing, IP fragmentation, or ICMP.

#[cfg(target_os = "linux")]
mod linux {
    use ntcp::{
        AddressValidation, ConnectionConfig, ConnectionId, Endpoint, EndpointConfig, EndpointError,
        Error, Event, IpMetadata, Ipv4Options, State,
    };
    use std::{
        fs::{File, OpenOptions},
        io::{self, Read, Write},
        net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
        os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
        time::Instant,
    };

    const MTU: usize = 1500;
    const IP_HEADER: usize = 20;
    const MAX_FLOWS: usize = 128;
    const BUDGET: usize = 32;
    const TICK_US: u64 = 10_000;

    fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message)
    }

    fn engine(error: EndpointError) -> io::Error {
        io::Error::other(format!("TCP engine: {error:?}"))
    }

    fn fill_secret(mut read: impl FnMut(&mut [u8]) -> io::Result<usize>) -> io::Result<[u8; 32]> {
        let mut secret = [0; 32];
        let mut filled = 0;
        while filled < secret.len() {
            match read(&mut secret[filled..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "getrandom made no progress",
                    ));
                }
                Ok(count) if count <= secret.len() - filled => filled += count,
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "getrandom returned an invalid length",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(secret)
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4.1
    //= type=implementation
    //= reason=Bounded evidence: initialized OS CSPRNG acquisition with error propagation, combined with core HMAC key dependence; tests do not prove entropy or confidentiality.
    //# F() MUST NOT be computable from the outside (MUST-9), or
    //# an attacker could still guess at sequence numbers from the ISN used
    //# for some other connection.

    // The runtime must provide a confidential, unpredictable key. Flags 0 waits
    // for Linux's CSPRNG to initialize; errors abort startup without fallback.
    fn acquire_secret() -> io::Result<[u8; 32]> {
        fill_secret(|buffer| {
            // SAFETY: buffer is exclusively borrowed and writable for exactly
            // buffer.len() bytes throughout the syscall; getrandom retains no pointer.
            let count = unsafe { libc::getrandom(buffer.as_mut_ptr().cast(), buffer.len(), 0) };
            if count < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(count as usize)
            }
        })
    }

    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for pair in bytes.chunks(2) {
            sum += u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.3
    //#   A TCP implementation MUST silently discard an incoming SYN segment
    //# |  that is addressed to a broadcast or multicast address [(MUST-57)].

    // This parser rejects address classes; Endpoint additionally validates the
    // configured interface subnet before processing TCP.
    fn unicast(ip: Ipv4Addr) -> bool {
        // Reject unspecified, multicast and reserved IPs.
        ip.octets()[0] != 0 && ip.octets()[0] < 224
    }

    #[cfg(test)]
    fn parse_ipv4(packet: &[u8], local: Ipv4Addr) -> Option<(IpMetadata, &[u8])> {
        parse_ipv4_options(packet, local, false, 0).map(|(ip, tcp, _)| (ip, tcp))
    }

    fn options_enabled(value: Option<&str>) -> io::Result<bool> {
        match value {
            None => Ok(false),
            Some("1") => Ok(true),
            _ => Err(invalid("NTCP_IPV4_OPTIONS must be exactly 1 or unset")),
        }
    }

    fn parse_ipv4_options(
        packet: &[u8],
        local: Ipv4Addr,
        enabled: bool,
        timestamp: u32,
    ) -> Option<(IpMetadata, &[u8], Ipv4Options)> {
        if packet.len() < IP_HEADER || packet[0] >> 4 != 4 {
            return None;
        }
        let header_len = usize::from(packet[0] & 15) * 4;
        let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        if header_len < IP_HEADER
            || header_len > total_len
            || total_len > packet.len()
            || packet[9] != 6
            // Reject reserved flag, MF and every nonzero fragment offset; allow DF.
            || u16::from_be_bytes([packet[6], packet[7]]) & !0x4000 != 0
            || checksum(&packet[..header_len]) != 0
        {
            return None;
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2
        //# When received options are passed up to TCP from the IP layer, a TCP
        //# implementation MUST ignore options that it does not understand (MUST-
        //# 50).
        let options = Ipv4Options::parse(&packet[IP_HEADER..header_len], enabled).ok()?;
        let options = if enabled {
            options.record(local, timestamp).ok()?
        } else {
            Ipv4Options::default()
        };
        let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.3
        //# |  An incoming SYN with an invalid source address MUST be ignored
        //# |  either by TCP or by the IP layer [(MUST-63)] (see
        //# |  Section 3.2.1.3).

        // The required endpoint policy checks directed broadcasts in this TUN context.
        if destination != local || !unicast(source) || !unicast(destination) {
            return None;
        }
        Some((
            IpMetadata {
                source: source.into(),
                destination: destination.into(),
            },
            &packet[header_len..total_len],
            options,
        ))
    }

    #[cfg(test)]
    fn build_ipv4(
        packet: &mut [u8],
        ip: IpMetadata,
        tcp_len: usize,
        hop_limit: u8,
        dscp: u8,
        ecn: u8,
    ) -> io::Result<usize> {
        build_ipv4_options(
            packet,
            ntcp::Transmit {
                connection: None,
                ip,
                len: tcp_len,
                hop_limit,
                dscp,
                ecn,
                ipv4_options: ntcp::OutgoingIpv4Options::default(),
            },
            0,
        )
    }

    fn build_ipv4_options(
        packet: &mut [u8],
        transmit: ntcp::Transmit,
        timestamp: u32,
    ) -> io::Result<usize> {
        let ntcp::Transmit {
            ip,
            len: tcp_len,
            hop_limit,
            dscp,
            ecn,
            ipv4_options,
            ..
        } = transmit;
        let (IpAddr::V4(source), IpAddr::V4(destination)) = (ip.source, ip.destination) else {
            return Err(invalid("TUN adapter only supports IPv4"));
        };
        let mut options = [0; 40];
        let (destination, option_len) = ipv4_options
            .encode(source, destination, timestamp, &mut options)
            .map_err(|_| invalid("invalid outgoing IPv4 options"))?;
        let header_len = IP_HEADER + option_len;
        let total_len = tcp_len
            .checked_add(header_len)
            .ok_or_else(|| invalid("IP length overflow"))?;
        if total_len > MTU || total_len > packet.len() || !unicast(source) || !unicast(destination)
        {
            return Err(invalid("invalid outgoing IPv4 packet or MTU exceeded"));
        }
        packet.copy_within(IP_HEADER..IP_HEADER + tcp_len, header_len);
        let header = &mut packet[..header_len];
        header.fill(0);
        header[0] = 0x40 | (header_len / 4) as u8;
        header[IP_HEADER..].copy_from_slice(&options[..option_len]);
        header[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.1
        //# RFC 1122 allows that if a retransmitted packet is identical to the
        //# original packet (which implies not only that the data boundaries have
        //# not changed, but also that none of the headers have changed), then
        //# the same IPv4 Identification field MAY be used (see Section 3.2.1.5
        //# of RFC 1122) (MAY-4).
        // Atomic IPv4 datagrams need no unique ID (RFC 6864); ID remains zero.
        header[6] = 0x40; // DF: this example never fragments.

        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2
        //# Time to Live (TTL):  The TTL value used to send TCP segments MUST be
        //# configurable (MUST-49).
        header[8] = hop_limit;
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.9
        //# TCP implementations
        //# SHOULD pass the current Differentiated Services field value without
        //# change to the IP layer, when it sends segments on the connection
        //# (SHLD-22).
        header[1] = (dscp << 2) | (ecn & 3);
        header[9] = 6;
        header[12..16].copy_from_slice(&source.octets());
        header[16..20].copy_from_slice(&destination.octets());
        let sum = checksum(header);
        header[10..12].copy_from_slice(&sum.to_be_bytes());
        Ok(total_len)
    }

    fn open_tun(name: &str) -> io::Result<File> {
        if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.as_bytes().contains(&0) {
            return Err(invalid(
                "TUN name must be nonempty, NUL-free and shorter than IFNAMSIZ",
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/dev/net/tun")?;
        // SAFETY: zero is valid for ifreq's integer, byte and pointer fields;
        // it also supplies the trailing name terminator.
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        for (out, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
            *out = byte as libc::c_char;
        }
        request.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
        // SAFETY: the fd is live and request is a writable, correctly sized ifreq.
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(file)
    }

    fn prefix_length(mask: u32) -> io::Result<u8> {
        let prefix = mask.leading_ones();
        if mask != u32::MAX.checked_shl(32 - prefix).unwrap_or(0) {
            return Err(invalid("noncontiguous interface netmask"));
        }
        Ok(prefix as u8)
    }

    fn checked_interface_subnet(
        local: Ipv4Addr,
        address: Ipv4Addr,
        mask: u32,
    ) -> io::Result<(Ipv4Addr, u8)> {
        let prefix = prefix_length(mask)?;
        if u32::from(local) & mask != u32::from(address) & mask {
            return Err(invalid(
                "local IPv4 address must lie in the TUN interface subnet; unrelated routed endpoint addresses are unsupported",
            ));
        }
        Ok((address, prefix))
    }

    fn tun_address_policy(
        local: Ipv4Addr,
        subnet: (Ipv4Addr, u8),
    ) -> impl Fn(AddressValidation) -> bool {
        // The subnet is queried from this TUN, not a union of unrelated interfaces.
        // checked_interface_subnet validates the prefix and local/subnet relationship.
        let (address, prefix) = subnet;
        let valid = move |ip: IpAddr| match ip {
            IpAddr::V4(ip) => {
                unicast(ip)
                    && (prefix > 30 || u32::from(ip) != (u32::from(address) | (u32::MAX >> prefix)))
            }
            IpAddr::V6(_) => false,
        };
        move |request| match request {
            AddressValidation::Bind { local: bind } => bind == IpAddr::V4(local) && valid(bind),
            AddressValidation::Open {
                local: source,
                remote: destination,
            } => source == IpAddr::V4(local) && valid(source) && valid(destination),
            AddressValidation::Route {
                source,
                destination,
                hop,
            } => source == IpAddr::V4(local) && valid(source) && valid(destination) && valid(hop),
            AddressValidation::Incoming {
                source,
                destination,
            } => destination == IpAddr::V4(local) && valid(source) && valid(destination),
        }
    }

    fn interface_subnet(tun: &File, local: Ipv4Addr) -> io::Result<(Ipv4Addr, u8)> {
        // SAFETY: zero initializes every ifreq union member and the name buffer.
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        // SAFETY: live TUN fd and writable, correctly sized ifreq. Querying the
        // actual name also handles kernel-expanded names such as tun%d.
        if unsafe { libc::ioctl(tun.as_raw_fd(), libc::TUNGETIFF, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        // SAFETY: the socket is live and request contains the kernel's interface name.
        if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFNETMASK, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful SIOCGIFNETMASK initialized this union member.
        let mask = unsafe { request.ifr_ifru.ifru_netmask };
        if i32::from(mask.sa_family) != libc::AF_INET {
            return Err(invalid("expected an IPv4 interface netmask"));
        }
        // sockaddr_in's network-order address follows its two-byte port.
        let mask = u32::from_be_bytes([
            mask.sa_data[2] as u8,
            mask.sa_data[3] as u8,
            mask.sa_data[4] as u8,
            mask.sa_data[5] as u8,
        ]);
        // SAFETY: the live socket and kernel-returned interface name remain valid.
        if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFADDR, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful SIOCGIFADDR initialized this union member.
        let address = unsafe { request.ifr_ifru.ifru_addr };
        if i32::from(address.sa_family) != libc::AF_INET {
            return Err(invalid("expected an IPv4 interface address"));
        }
        let address = Ipv4Addr::new(
            address.sa_data[2] as u8,
            address.sa_data[3] as u8,
            address.sa_data[4] as u8,
            address.sa_data[5] as u8,
        );
        checked_interface_subnet(local, address, mask)
    }

    struct Flow {
        id: ConnectionId,
        pending: [u8; 4096],
        start: usize,
        end: usize,
        shutdown: bool,
    }

    impl Flow {
        fn new(id: ConnectionId) -> Self {
            Self {
                id,
                pending: [0; 4096],
                start: 0,
                end: 0,
                shutdown: false,
            }
        }

        // One bounded chunk per flow. Never read again until all pending bytes
        // have been accepted by TCP, even when peer FIN has already arrived.
        fn drive(&mut self, endpoint: &mut Endpoint) -> io::Result<bool> {
            if self.shutdown {
                return Ok(false);
            }
            let mut progress = false;
            if self.start == self.end {
                match endpoint.read(self.id, &mut self.pending) {
                    Ok(0) => {
                        endpoint.shutdown(self.id).map_err(engine)?;
                        self.shutdown = true;
                        return Ok(true);
                    }
                    Ok(count) => {
                        self.start = 0;
                        self.end = count;
                        progress = true;
                    }
                    Err(EndpointError::Connection(Error::WouldBlock)) => return Ok(false),
                    Err(error) => return Err(engine(error)),
                }
            }
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.5
            //# As a result of implementation differences and middlebox interactions,
            //# new applications SHOULD NOT employ the TCP urgent mechanism (SHLD-13).
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
            //# New applications SHOULD NOT set the URGENT flag [39] due to
            //# implementation differences and middlebox issues (SHLD-13).
            match endpoint.write(self.id, &self.pending[self.start..self.end]) {
                Ok(count) => {
                    self.start += count;
                    progress |= count != 0;
                }
                Err(EndpointError::Connection(Error::WouldBlock)) => {}
                Err(error) => return Err(engine(error)),
            }
            Ok(progress)
        }
    }

    fn now(start: Instant) -> u64 {
        start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
    }

    fn wait(tun: &File, timeout_ms: i32) -> io::Result<()> {
        let mut fd = libc::pollfd {
            fd: tun.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: fd points to one initialized pollfd for the duration of poll.
        if unsafe { libc::poll(&mut fd, 1, timeout_ms) } < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::Interrupted {
                Ok(())
            } else {
                Err(error)
            };
        }
        if fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(io::Error::other("TUN poll reported device failure"));
        }
        Ok(())
    }

    pub fn run() -> io::Result<()> {
        let args: Vec<_> = std::env::args().collect();
        if !matches!(args.len(), 4 | 5) {
            return Err(invalid(
                "usage: tun_echo TUN_NAME LOCAL_IPV4 TCP_PORT [PEER_IPV4:PORT]",
            ));
        }
        let local: Ipv4Addr = args[2]
            .parse()
            .map_err(|_| invalid("invalid local IPv4 address"))?;
        let port: u16 = args[3].parse().map_err(|_| invalid("invalid TCP port"))?;
        if !unicast(local) || port == 0 {
            return Err(invalid("expected a unicast IPv4 address and nonzero port"));
        }
        let ipv4_options_enabled = match std::env::var("NTCP_IPV4_OPTIONS") {
            Ok(value) => options_enabled(Some(&value))?,
            Err(std::env::VarError::NotPresent) => options_enabled(None)?,
            Err(_) => return Err(invalid("invalid NTCP_IPV4_OPTIONS")),
        };
        let timestamps = match std::env::var("NTCP_TIMESTAMPS") {
            Ok(value) if value == "1" => true,
            Err(std::env::VarError::NotPresent) => false,
            _ => return Err(invalid("NTCP_TIMESTAMPS must be exactly 1 or unset")),
        };
        let sack = match std::env::var("NTCP_SACK") {
            Ok(value) if value == "1" => true,
            Err(std::env::VarError::NotPresent) => false,
            _ => return Err(invalid("NTCP_SACK must be exactly 1 or unset")),
        };
        let secret = acquire_secret()?;
        let mut tun = open_tun(&args[1])?;
        let start = Instant::now();
        let address_policy = tun_address_policy(local, interface_subnet(&tun, local)?);
        let config = EndpointConfig {
            max_connections: MAX_FLOWS,
            max_listeners: 1,
            max_control_packets: BUDGET,
            max_buffer_bytes: MAX_FLOWS * (5 * 65536 + 1460),
            hop_limit: 64,
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2
            //# Generally, an application SHOULD NOT change the Diffserv field value
            //# during the course of a connection (SHLD-23).
            dscp: 0,
            ipv4_options_enabled,
            error_reports: true,
            reuse_time_wait: false,
            connection: ConnectionConfig {
                timestamps,
                sack,
                send_capacity: 65536,
                receive_capacity: 65536,
                mss: 1460,
                receive_ip_payload_limit: (MTU - IP_HEADER) as u16,
                send_ip_payload_limit: (MTU - IP_HEADER) as u16,
                ..ConnectionConfig::default()
            },
        };
        let mut endpoint =
            Endpoint::new(config, secret, now(start), address_policy).map_err(engine)?;
        let listener = endpoint
            .listen(SocketAddr::new(local.into(), port), MAX_FLOWS)
            .map_err(engine)?;
        let mut flows = Vec::with_capacity(MAX_FLOWS);
        if let Some(peer) = args.get(4) {
            let peer: std::net::SocketAddrV4 =
                peer.parse().map_err(|_| invalid("invalid IPv4 peer"))?;
            let id = endpoint
                .connect(now(start), SocketAddr::new(local.into(), port), peer.into())
                .map_err(engine)?;
            flows.push(Flow::new(id));
        }
        // Enough input space for any IPv4 datagram, so read cannot silently turn
        // an oversized datagram into a seemingly valid truncated packet.
        let mut input = [0u8; 65536];
        // Reserve all output storage BEFORE polling: generation commits a send.
        let mut output = [0u8; MTU];
        let mut accepting = false;
        eprintln!(
            "echo listening on {local}:{port} via {} (caller-configured TUN)",
            args[1]
        );
        loop {
            let mut immediate = false;
            for _ in 0..BUDGET {
                match tun.read(&mut input) {
                    Ok(0) => {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TUN closed"));
                    }
                    Ok(len) => {
                        if let Some((ip, tcp, options)) = parse_ipv4_options(
                            &input[..len],
                            local,
                            ipv4_options_enabled,
                            (start.elapsed().as_millis() as u32) | 0x8000_0000,
                        ) {
                            endpoint
                                .input_with_ipv4_options(now(start), ip, input[1], options, tcp)
                                .map_err(engine)?;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
            immediate |= endpoint.on_timeout(now(start), BUDGET).map_err(engine)?;
            for _ in 0..=MAX_FLOWS {
                match endpoint.next_event() {
                    Some(Event::Acceptable(id)) if id == listener => accepting = true,
                    Some(Event::RouteAdvice(tuple)) => {
                        // This adapter has one caller-configured, fixed TUN route.
                        // A routing adapter would invalidate/reselect its path here.
                        eprintln!("negative route advice for {tuple:?}; no alternate TUN route");
                    }
                    Some(_) => {}
                    None => break,
                }
            }
            if accepting {
                for _ in 0..BUDGET {
                    match endpoint.accept(listener) {
                        Ok(id) => {
                            if flows.len() == MAX_FLOWS {
                                return Err(io::Error::other("application flow limit exceeded"));
                            }
                            flows.push(Flow::new(id));
                        }
                        Err(EndpointError::Connection(Error::WouldBlock)) => {
                            accepting = false;
                            break;
                        }
                        Err(error) => return Err(engine(error)),
                    }
                }
                immediate |= accepting;
            }
            // ponytail: bounded application scan of at most 128 accepted flows;
            // use an application ready queue if increasing that cap substantially.
            // Buffered writes are retried independently of edge-like TCP events.
            let mut index = 0;
            while index < flows.len() {
                let id = flows[index].id;
                if matches!(
                    endpoint.state(id).map_err(engine)?,
                    State::Closed | State::TimeWait
                ) {
                    endpoint.release(id).map_err(engine)?; // Engine still owns TIME-WAIT.
                    flows.swap_remove(index);
                } else {
                    immediate |= flows[index].drive(&mut endpoint)?;
                    index += 1;
                }
            }
            // Each call spends one engine work unit, at most 32 units/packets.
            for _ in 0..BUDGET {
                let polled = endpoint
                    .poll_transmit(now(start), &mut output[IP_HEADER..], 1)
                    .map_err(engine)?;
                if let Some(packet) = polled.packet {
                    let len = build_ipv4_options(
                        &mut output,
                        packet,
                        (start.elapsed().as_millis() as u32) | 0x8000_0000,
                    )?;
                    match tun.write(&output[..len]) {
                        Ok(written) if written == len => {}
                        // Generation already committed: drop locally and let TCP
                        // recover. Do not stage indefinitely or pretend peer ACK.
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        Ok(_) => {
                            return Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "short TUN packet write",
                            ));
                        }
                        Err(error) => return Err(error),
                    }
                }
                if !polled.more_work {
                    break;
                }
            }
            immediate |= endpoint.has_pending_output();
            let current = now(start);
            let delay = endpoint.next_deadline().map_or(TICK_US, |deadline| {
                deadline.saturating_sub(current).min(TICK_US)
            });
            let timeout_ms = if immediate {
                0
            } else {
                delay.div_ceil(1000) as i32
            };
            wait(&tun, timeout_ms)?;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4.1
        //= type=test
        //= reason=Bounded evidence: full/partial fills, EINTR, zero progress, error propagation and live initialized OS CSPRNG acquisition complement core isn_depends_on_secret_and_each_tuple_component HMAC key-dependence coverage; tests do not prove entropy or confidentiality.
        //# F() MUST NOT be computable from the outside (MUST-9), or
        //# an attacker could still guess at sequence numbers from the ISN used
        //# for some other connection.
        #[test]
        fn secret_acquisition() {
            let secret = fill_secret(|buffer| {
                assert_eq!(buffer.len(), 32);
                buffer.fill(0xa5);
                Ok(buffer.len())
            })
            .unwrap();
            assert_eq!(secret, [0xa5; 32]);

            let mut calls = 0;
            let secret = fill_secret(|buffer| {
                calls += 1;
                match calls {
                    1 => {
                        assert_eq!(buffer.len(), 32);
                        buffer[..7].fill(0x11);
                        Ok(7)
                    }
                    2 => {
                        assert_eq!(buffer.len(), 25);
                        Err(io::Error::from_raw_os_error(libc::EINTR))
                    }
                    3 => {
                        assert_eq!(buffer.len(), 25);
                        buffer.fill(0x22);
                        Ok(buffer.len())
                    }
                    _ => panic!("read after full fill"),
                }
            })
            .unwrap();
            assert_eq!(calls, 3);
            assert_eq!(&secret[..7], &[0x11; 7]);
            assert_eq!(&secret[7..], &[0x22; 25]);

            for errno in [libc::EIO, libc::ENOSYS, libc::EAGAIN] {
                let mut calls = 0;
                let error = fill_secret(|buffer| {
                    calls += 1;
                    match calls {
                        1 => {
                            buffer[..1].fill(0x33);
                            Ok(1)
                        }
                        2 => Err(io::Error::from_raw_os_error(errno)),
                        _ => panic!("retried hard error"),
                    }
                })
                .unwrap_err();
                assert_eq!(error.raw_os_error(), Some(errno));
                assert_eq!(calls, 2);
            }
            for (count, kind) in [
                (0, io::ErrorKind::UnexpectedEof),
                (33, io::ErrorKind::InvalidData),
            ] {
                let mut calls = 0;
                let error = fill_secret(|_| {
                    calls += 1;
                    assert_eq!(calls, 1, "retried invalid progress");
                    Ok(count)
                })
                .unwrap_err();
                assert_eq!(error.kind(), kind);
            }

            // Exercise the real OS path, not a statistical entropy test.
            let _secret = acquire_secret().unwrap();
        }

        fn test_policy(local: Ipv4Addr) -> impl Fn(AddressValidation) -> bool {
            tun_address_policy(
                local,
                checked_interface_subnet(local, local, 0xffff_ff00).unwrap(),
            )
        }

        #[test]
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.3
        //= type=test
        //= reason=The actual TUN policy rejects a checksummed broadcast-source SYN after IP parsing in an explicit /24 context; no kernel filtering is assumed.
        //# |  An incoming SYN with an invalid source address MUST be ignored
        //# |  either by TCP or by the IP layer [(MUST-63)] (see
        //# |  Section 3.2.1.3).
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.3
        //= type=test
        //= reason=The adapter rejects the broadcast destination before TCP under its configured-local-address restriction.
        //#   A TCP implementation MUST silently discard an incoming SYN segment
        //# |  that is addressed to a broadcast or multicast address [(MUST-57)].
        fn tun_policy_rejects_broadcast_syn_without_kernel_filtering() {
            let local = Ipv4Addr::new(192, 0, 2, 2);
            let broadcast = Ipv4Addr::new(192, 0, 2, 255);
            let host = Ipv4Addr::new(192, 0, 2, 1);
            let mut endpoint =
                Endpoint::new(EndpointConfig::default(), [1; 32], 0, test_policy(local)).unwrap();
            endpoint
                .listen(SocketAddr::new(local.into(), 8080), 1)
                .unwrap();
            for (source, destination) in [(broadcast, local), (host, broadcast), (host, local)] {
                let ip = IpMetadata {
                    source: source.into(),
                    destination: destination.into(),
                };
                let mut packet = [0; MTU];
                let tcp_len = ntcp::wire::encode(
                    ip,
                    ntcp::wire::Header {
                        source_port: 40000,
                        destination_port: 8080,
                        sequence: 1,
                        acknowledgment: 0,
                        flags: ntcp::wire::SYN,
                        window: 1024,
                        urgent_pointer: 0,
                    },
                    &[],
                    &[],
                    &mut packet[IP_HEADER..],
                )
                .unwrap();
                let len = build_ipv4(&mut packet, ip, tcp_len, 64, 0, 0).unwrap();
                let parsed = parse_ipv4_options(&packet[..len], local, false, 0);
                if destination == broadcast {
                    assert!(parsed.is_none());
                } else {
                    let (ip, tcp, options) = parsed.unwrap();
                    assert!(ntcp::wire::parse(ip, tcp).is_ok());
                    let result = endpoint
                        .input_with_ipv4_options(0, ip, 0, options, tcp)
                        .unwrap();
                    assert_eq!(
                        result,
                        if source == broadcast {
                            ntcp::InputDisposition::Dropped
                        } else {
                            ntcp::InputDisposition::Processed
                        }
                    );
                }
                let output = endpoint.poll_transmit(0, &mut [0; MTU], BUDGET).unwrap();
                if source == broadcast || destination == broadcast {
                    assert_eq!(endpoint.buffer_bytes(), 0);
                    assert!(output.packet.is_none());
                    assert!(!output.more_work);
                } else {
                    assert!(endpoint.buffer_bytes() > 0);
                    assert!(output.packet.is_some());
                }
            }
        }

        #[test]
        fn enabled_option_profile_header_mtu_and_timestamp_roundtrip() {
            use ntcp::{OutgoingIpv4Options, SourceRoute, TimestampRequest};
            assert!(!options_enabled(None).unwrap());
            assert!(options_enabled(Some("1")).unwrap());
            for value in ["", "0", "true", "01", " 1", "1 "] {
                assert!(options_enabled(Some(value)).is_err());
            }
            let source = Ipv4Addr::new(192, 0, 2, 1);
            let local = Ipv4Addr::new(192, 0, 2, 2);
            let hop = Ipv4Addr::new(192, 0, 2, 9);
            let ip = IpMetadata {
                source: source.into(),
                destination: local.into(),
            };
            let mut bytes = [0xa5; MTU];
            let mut transmit = ntcp::Transmit {
                connection: None,
                ip,
                len: 1440,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: OutgoingIpv4Options {
                    source_route: Some(SourceRoute::new(&[hop], false).unwrap()),
                    record_route_slots: Some(2),
                    timestamp: Some(TimestampRequest::Times(4)),
                },
            };
            let len = build_ipv4_options(&mut bytes, transmit, 0x8000_0001).unwrap();
            assert_eq!(len, MTU);
            assert_eq!(bytes[0], 0x4f);
            assert_eq!(checksum(&bytes[..60]), 0);
            assert_eq!(&bytes[16..20], &hop.octets());
            assert_eq!(&bytes[23..27], &local.octets());
            assert_eq!(&bytes[60..], &[0xa5; 1440]);
            // Simulate RFC 791's router swap, not a live kernel source-route path.
            bytes[16..20].copy_from_slice(&local.octets());
            bytes[23..27].copy_from_slice(&hop.octets());
            bytes[22] = 8;
            reseal(&mut bytes);
            assert!(parse_ipv4_options(&bytes, local, false, 0).is_none());
            let (received_ip, tcp, options) =
                parse_ipv4_options(&bytes, local, true, 0x8000_0002).unwrap();
            assert_eq!(received_ip, ip);
            assert_eq!(tcp, &[0xa5; 1440]);
            assert_eq!(options.return_route(source).unwrap().hops(), &[hop]);
            let recorded = options.as_bytes();
            assert_eq!(&recorded[14..18], &local.octets()); // RR's second slot.
            assert_eq!(&recorded[26..30], &0x8000_0002u32.to_be_bytes());
            let before = bytes;
            transmit.len = 1441;
            assert!(build_ipv4_options(&mut bytes, transmit, 0).is_err());
            assert_eq!(bytes, before);
            transmit.len = 1440;
            assert!(build_ipv4_options(&mut bytes[..MTU - 1], transmit, 0).is_err());
            assert_eq!(bytes, before);
        }

        fn packet() -> ([u8; MTU], usize, Ipv4Addr) {
            let local = Ipv4Addr::new(10, 0, 0, 2);
            let mut bytes = [0; MTU];
            bytes[20..40].fill(0x5a);
            let len = build_ipv4(
                &mut bytes,
                IpMetadata {
                    source: Ipv4Addr::new(10, 0, 0, 1).into(),
                    destination: local.into(),
                },
                20,
                64,
                0,
                0,
            )
            .unwrap();
            (bytes, len, local)
        }

        fn reseal(bytes: &mut [u8]) {
            bytes[10..12].fill(0);
            let len = usize::from(bytes[0] & 15) * 4;
            let sum = checksum(&bytes[..len]);
            bytes[10..12].copy_from_slice(&sum.to_be_bytes());
        }

        #[test]
        fn source_routing_and_malformed_ip_options_are_rejected() {
            for option in [[131, 4, 0, 0], [137, 4, 0, 0], [7, 0, 0, 0], [7, 5, 0, 0]] {
                let (mut bytes, len, local) = packet();
                bytes.copy_within(20..len, 24);
                bytes[0] = 0x46;
                bytes[2..4].copy_from_slice(&((len + 4) as u16).to_be_bytes());
                bytes[20..24].copy_from_slice(&option);
                reseal(&mut bytes);
                assert!(parse_ipv4(&bytes[..len + 4], local).is_none());
            }
        }

        #[test]
        fn interface_subnet_rejects_routed_local_mismatch_and_keeps_edge_prefixes() {
            let interface = Ipv4Addr::new(192, 0, 2, 2);
            let local = Ipv4Addr::new(198, 51, 100, 2);
            assert!(checked_interface_subnet(local, interface, 0xffff_ff00).is_err());
            assert_eq!(
                checked_interface_subnet(Ipv4Addr::new(192, 0, 2, 10), interface, 0xffff_ff00)
                    .unwrap(),
                (interface, 24)
            );
            assert_eq!(
                checked_interface_subnet(local, interface, 0).unwrap(),
                (interface, 0)
            );
            for tail in [2, 3] {
                assert_eq!(
                    checked_interface_subnet(
                        Ipv4Addr::new(192, 0, 2, tail),
                        interface,
                        0xffff_fffe
                    )
                    .unwrap(),
                    (interface, 31)
                );
            }
            assert!(
                checked_interface_subnet(Ipv4Addr::new(192, 0, 2, 1), interface, 0xffff_fffe)
                    .is_err()
            );
            assert_eq!(
                checked_interface_subnet(interface, interface, u32::MAX).unwrap(),
                (interface, 32)
            );
            assert!(
                checked_interface_subnet(Ipv4Addr::new(192, 0, 2, 3), interface, u32::MAX).is_err()
            );
        }

        #[test]
        fn interface_netmask_requires_contiguous_prefix() {
            for prefix in 0..=32 {
                let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
                assert_eq!(prefix_length(mask).unwrap(), prefix as u8);
            }
            for mask in [0xff00ff00, 0xffffff01, 1, 0x7fffffff] {
                assert!(prefix_length(mask).is_err());
            }
        }

        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.1
        //= type=test
        //# RFC 1122 allows that if a retransmitted packet is identical to the
        //# original packet (which implies not only that the data boundaries have
        //# not changed, but also that none of the headers have changed), then
        //# the same IPv4 Identification field MAY be used (see Section 3.2.1.5
        //# of RFC 1122) (MAY-4).
        #[test]
        fn identical_atomic_datagrams_reuse_identification() {
            let (mut bytes, len, local) = packet();
            let original = bytes;
            let ip = IpMetadata {
                source: Ipv4Addr::new(10, 0, 0, 1).into(),
                destination: local.into(),
            };
            assert_eq!(build_ipv4(&mut bytes, ip, 20, 64, 0, 0).unwrap(), len);
            assert_eq!(&bytes[..len], &original[..len]);
            assert_eq!(&bytes[4..8], &[0, 0, 0x40, 0]);
        }

        // These assertions apply to this example, not arbitrary embedding applications.
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.5
        //= type=test
        //# As a result of implementation differences and middlebox interactions,
        //# new applications SHOULD NOT employ the TCP urgent mechanism (SHLD-13).
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
        //= type=test
        //# New applications SHOULD NOT set the URGENT flag [39] due to
        //# implementation differences and middlebox issues (SHLD-13).
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2
        //= type=test
        //# Generally, an application SHOULD NOT change the Diffserv field value
        //# during the course of a connection (SHLD-23).
        #[test]
        fn echo_flow_keeps_diffserv_stable_and_never_sends_urgent() {
            fn transfer(from: &mut Endpoint, to: &mut Endpoint, echo: bool) -> usize {
                let mut bytes = [0; MTU];
                let mut data = 0;
                for _ in 0..32 {
                    let output = from.poll_transmit(0, &mut bytes, 16).unwrap();
                    if let Some(packet) = output.packet {
                        let segment = ntcp::wire::parse(packet.ip, &bytes[..packet.len]).unwrap();
                        if echo {
                            assert_eq!(packet.dscp, 37);
                            assert_eq!(segment.header.flags & ntcp::wire::URG, 0);
                            data += segment.payload.len();
                        }
                        to.input_with_traffic_class(
                            0,
                            packet.ip,
                            (packet.dscp << 2) | packet.ecn,
                            &bytes[..packet.len],
                        )
                        .unwrap();
                    }
                    if !output.more_work {
                        return data;
                    }
                }
                panic!("bounded echo transfer did not quiesce");
            }
            let mut cfg = EndpointConfig::default();
            cfg.connection.nagle = false;
            let mut client = Endpoint::new(
                cfg.clone(),
                [1; 32],
                0,
                test_policy(Ipv4Addr::new(10, 0, 0, 1)),
            )
            .unwrap();
            cfg.dscp = 37;
            let mut server =
                Endpoint::new(cfg, [2; 32], 0, test_policy(Ipv4Addr::new(10, 0, 0, 2))).unwrap();
            let local = "10.0.0.1:1234".parse().unwrap();
            let remote = "10.0.0.2:8080".parse().unwrap();
            let listener = server.listen(remote, 1).unwrap();
            let id = client.connect(0, local, remote).unwrap();
            for _ in 0..3 {
                transfer(&mut client, &mut server, false);
                transfer(&mut server, &mut client, true);
            }
            let mut flow = Flow::new(server.accept(listener).unwrap());
            for input in [b"first".as_slice(), b"second".as_slice()] {
                client.write_urgent(id, input).unwrap();
                transfer(&mut client, &mut server, false);
                assert!(flow.drive(&mut server).unwrap());
                assert_eq!(transfer(&mut server, &mut client, true), input.len());
                let mut echoed = [0; 16];
                let count = client.read(id, &mut echoed).unwrap();
                assert_eq!(&echoed[..count], input);
            }
        }

        #[test]
        fn checksum_known_header() {
            let header = [
                0x45, 0, 0, 0x73, 0, 0, 0x40, 0, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0, 1, 0xc0,
                0xa8, 0, 0xc7,
            ];
            assert_eq!(checksum(&header), 0);
        }

        #[test]
        fn ipv4_roundtrip_and_options() {
            let (mut bytes, len, local) = packet();
            assert_eq!(bytes[0], 0x45);
            assert_eq!(&bytes[6..10], &[0x40, 0, 64, 6]);
            assert_eq!(checksum(&bytes[..20]), 0);
            let (ip, tcp) = parse_ipv4(&bytes, local).unwrap();
            assert_eq!(ip.destination, IpAddr::V4(local));
            assert_eq!(tcp, &[0x5a; 20]); // Ignores bytes beyond IP total length.
            bytes.copy_within(20..len, 24);
            bytes[20..24].fill(1); // Four IPv4 NOP options.
            bytes[0] = 0x46;
            bytes[2..4].copy_from_slice(&((len + 4) as u16).to_be_bytes());
            reseal(&mut bytes);
            assert_eq!(parse_ipv4(&bytes[..len + 4], local).unwrap().1, &[0x5a; 20]);
        }

        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2
        //= type=test
        //# When received options are passed up to TCP from the IP layer, a TCP
        //# implementation MUST ignore options that it does not understand (MUST-
        //# 50).
        #[test]
        fn unknown_ipv4_options_preserve_tcp_payload() {
            for option in [[158, 4, 0xa5, 0x5a], [30, 2, 1, 0]] {
                let (mut bytes, len, local) = packet();
                bytes.copy_within(20..len, 24);
                bytes[0] = 0x46;
                bytes[2..4].copy_from_slice(&((len + 4) as u16).to_be_bytes());
                bytes[20..24].copy_from_slice(&option);
                reseal(&mut bytes);
                let (ip, tcp) = parse_ipv4(&bytes[..len + 4], local).unwrap();
                assert_eq!(ip.destination, IpAddr::V4(local));
                assert_eq!(tcp, &[0x5a; 20]);
            }
        }

        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.9
        //= type=test
        //# TCP implementations
        //# SHOULD pass the current Differentiated Services field value without
        //# change to the IP layer, when it sends segments on the connection
        //# (SHLD-22).
        #[test]
        fn outgoing_dscp_and_ttl_are_preserved() {
            let (mut bytes, _, local) = packet();
            let ip = IpMetadata {
                source: local.into(),
                destination: local.into(),
            };
            for dscp in 0..64 {
                for ttl in [1, 64, 255] {
                    build_ipv4(&mut bytes, ip, 20, ttl, dscp, 0).unwrap();
                    assert_eq!(bytes[1], dscp << 2);
                    assert_eq!(bytes[8], ttl);
                    assert_eq!(checksum(&bytes[..20]), 0);
                    assert_eq!(&bytes[20..40], &[0x5a; 20]);
                }
            }
        }

        #[test]
        fn ipv4_dscp_and_ecn_are_independent() {
            let (mut bytes, _, local) = packet();
            let ip = IpMetadata {
                source: local.into(),
                destination: local.into(),
            };
            for dscp in 0..64 {
                for ecn in 0..4 {
                    build_ipv4(&mut bytes, ip, 20, 64, dscp, ecn).unwrap();
                    assert_eq!(bytes[1], (dscp << 2) | ecn);
                    assert_eq!(checksum(&bytes[..20]), 0);
                    assert!(parse_ipv4(&bytes, local).is_some());
                }
            }
        }

        #[test]
        fn rejects_bad_lengths_checksum_and_fragments() {
            let (bytes, len, local) = packet();
            for truncated in 0..len {
                assert!(parse_ipv4(&bytes[..truncated], local).is_none());
            }
            for (offset, value) in [(0, 0x65), (0, 0x44), (0, 0x4f), (2, 1), (3, 19), (9, 17)] {
                let mut bad = bytes;
                bad[offset] = value;
                assert!(parse_ipv4(&bad[..len], local).is_none());
            }
            let mut bad = bytes;
            bad[8] ^= 1;
            assert!(parse_ipv4(&bad[..len], local).is_none());
            for flags in [0x2000u16, 1, 0x8000, 0x4001] {
                let mut bad = bytes;
                bad[6..8].copy_from_slice(&flags.to_be_bytes());
                reseal(&mut bad);
                assert!(parse_ipv4(&bad[..len], local).is_none());
            }
        }

        #[test]
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.3
        //= type=test
        //#   A TCP implementation MUST silently discard an incoming SYN segment
        //# |  that is addressed to a broadcast or multicast address [(MUST-57)].

        // Traceability limitation: Assertions cover multicast and limited broadcast
        // destinations only; no subnet-directed broadcast case.
        fn rejects_wrong_destination_and_nonunicast() {
            let (bytes, len, local) = packet();
            assert!(parse_ipv4(&bytes[..len], Ipv4Addr::new(10, 0, 0, 3)).is_none());
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.3
            //= type=test
            //# |  An incoming SYN with an invalid source address MUST be ignored
            //# |  either by TCP or by the IP layer [(MUST-63)] (see
            //# |  Section 3.2.1.3).

            // Traceability limitation: Assertions cover listed invalid IPv4 sources,
            // not prefix-directed broadcasts.
            for address in [
                [0, 0, 0, 0],
                [224, 0, 0, 1],
                [255, 255, 255, 255],
                [240, 0, 0, 1],
            ] {
                for offset in [12, 16] {
                    let mut bad = bytes;
                    bad[offset..offset + 4].copy_from_slice(&address);
                    reseal(&mut bad);
                    let destination = if offset == 16 {
                        Ipv4Addr::from(address)
                    } else {
                        local
                    };
                    assert!(parse_ipv4(&bad[..len], destination).is_none());
                }
            }
        }

        #[test]
        fn output_mtu_and_capacity() {
            let (mut bytes, _, local) = packet();
            let ip = IpMetadata {
                source: local.into(),
                destination: local.into(),
            };
            assert_eq!(build_ipv4(&mut bytes, ip, 1480, 64, 0, 0).unwrap(), MTU);
            assert_eq!(checksum(&bytes[..20]), 0);
            assert!(build_ipv4(&mut bytes, ip, 1481, 64, 0, 0).is_err());
            assert!(build_ipv4(&mut bytes, ip, usize::MAX, 64, 0, 0).is_err());
            assert!(build_ipv4(&mut bytes[..19], ip, 0, 64, 0, 0).is_err());
            assert!(open_tun("").is_err());
            assert!(open_tun(&"x".repeat(libc::IFNAMSIZ)).is_err());
            assert!(open_tun("bad\0name").is_err());
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "tun_echo requires Linux /dev/net/tun (IFF_TUN | IFF_NO_PI)",
    ))
}
