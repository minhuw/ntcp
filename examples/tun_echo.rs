// Run as: tun_echo TUN_NAME LOCAL_IP TCP_PORT [PEER_SOCKET_ADDR].
// The caller must configure the TUN interface (MTU 1500) and routes beforehand.
// This adapter exchanges IP packets, not Ethernet frames; it does not configure
// the host or implement ARP, routing, IP fragmentation, or ICMP.

#[cfg(target_os = "linux")]
mod linux {
    use ntcp::{
        AddressValidation, ConnectionConfig, ConnectionId, Endpoint, EndpointConfig, EndpointError,
        Error, Event, IpMetadata, Ipv4Options, State,
    };
    use ntcp_io::{PacketIo, TxOutcome, tun::Tun};
    use std::{
        io,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
        os::fd::AsRawFd,
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

    #[cfg(test)]
    use ntcp_ip::checksum;

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
        // Preserve the example's historical IPv4 padding allowance, while the
        // reusable complete-frame codec requires exact bounds.
        let total = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
        let parsed = ntcp_ip::parse(packet.get(..total)?, enabled).ok()?;
        let (IpAddr::V4(source), IpAddr::V4(destination)) =
            (parsed.ip.source, parsed.ip.destination)
        else {
            return None;
        };
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.3
        //# |  An incoming SYN with an invalid source address MUST be ignored
        //# |  either by TCP or by the IP layer [(MUST-63)] (see
        //# |  Section 3.2.1.3).
        // Endpoint additionally checks directed broadcasts in this TUN subnet.
        if parsed.protocol != 6 || destination != local || !unicast(source) || !unicast(destination)
        {
            return None;
        }
        let options = if enabled {
            parsed.ipv4_options.record(local, timestamp).ok()?
        } else {
            Ipv4Options::default()
        };
        Some((parsed.ip, parsed.payload, options))
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
        let (IpAddr::V4(source), IpAddr::V4(destination)) =
            (transmit.ip.source, transmit.ip.destination)
        else {
            return Err(invalid("expected IPv4 transmit addresses"));
        };
        if !unicast(source) || !unicast(destination) {
            return Err(invalid("invalid outgoing IPv4 address"));
        }
        let capacity = packet.len().min(MTU);
        ntcp_ip::encode(&mut packet[..capacity], transmit, timestamp)
            .map_err(|_| invalid("invalid outgoing IPv4 packet or MTU exceeded"))
    }

    const IPV6_HEADER: usize = 40;

    fn unicast_v6(ip: Ipv6Addr) -> bool {
        // No zone handling: reject link/site-local, mapped IPv4 and loopback addresses.
        !ip.is_unspecified()
            && !ip.is_multicast()
            && !ip.is_loopback()
            && !ip.is_unicast_link_local()
            && ip.segments()[0] & 0xffc0 != 0xfec0
            && ip.to_ipv4_mapped().is_none()
    }

    //= https://www.rfc-editor.org/rfc/rfc3168#section-5
    //= type=implementation
    //= reason=Direct-TCP IPv6 base-header adapter extracts the identical ECN field from Traffic Class; extension headers, fragmentation and jumbograms are scoped adapter limits.
    //# Bits 6 and 7 in the IPv4 TOS octet are designated as the ECN field. The IPv4 TOS octet corresponds to the Traffic Class octet in IPv6, and the ECN field is defined identically in both cases.
    fn parse_ipv6(packet: &[u8], local: Ipv6Addr) -> Option<(IpMetadata, u8, &[u8])> {
        let parsed = ntcp_ip::parse(packet, false).ok()?;
        let (IpAddr::V6(source), IpAddr::V6(destination)) =
            (parsed.ip.source, parsed.ip.destination)
        else {
            return None;
        };
        if parsed.protocol != 6
            || destination != local
            || !unicast_v6(source)
            || !unicast_v6(destination)
        {
            return None;
        }
        Some((parsed.ip, parsed.traffic_class, parsed.payload))
    }

    fn build_ipv6(packet: &mut [u8], transmit: ntcp::Transmit) -> io::Result<usize> {
        let (IpAddr::V6(source), IpAddr::V6(destination)) =
            (transmit.ip.source, transmit.ip.destination)
        else {
            return Err(invalid("expected IPv6 transmit addresses"));
        };
        if !unicast_v6(source) || !unicast_v6(destination) {
            return Err(invalid("invalid outgoing IPv6 address"));
        }
        let capacity = packet.len().min(MTU);
        ntcp_ip::encode(&mut packet[..capacity], transmit, 0)
            .map_err(|_| invalid("invalid outgoing IPv6 base-header packet"))
    }

    fn checked_peer(value: &str, local: IpAddr) -> io::Result<SocketAddr> {
        let peer: SocketAddr = value
            .parse()
            .map_err(|_| invalid("invalid peer socket address"))?;
        if peer.is_ipv4() != local.is_ipv4()
            || peer.port() == 0
            || matches!(peer, SocketAddr::V6(ip) if ip.scope_id() != 0 || ip.flowinfo() != 0)
            || !match peer.ip() {
                IpAddr::V4(ip) => unicast(ip),
                IpAddr::V6(ip) => unicast_v6(ip),
            }
        {
            return Err(invalid(
                "peer must be unscoped unicast and match local address family",
            ));
        }
        Ok(peer)
    }

    fn input_frame(
        endpoint: &mut Endpoint,
        time: u64,
        packet: &[u8],
        local: IpAddr,
        options_enabled: bool,
        timestamp: u32,
    ) -> io::Result<()> {
        match local {
            IpAddr::V4(local) => {
                if let Some((ip, tcp, options)) =
                    parse_ipv4_options(packet, local, options_enabled, timestamp)
                {
                    endpoint
                        .input_with_ipv4_options(time, ip, packet[1], options, tcp)
                        .map_err(engine)?;
                }
            }
            IpAddr::V6(local) => {
                if let Some((ip, class, tcp)) = parse_ipv6(packet, local) {
                    endpoint
                        .input_with_traffic_class(time, ip, class, tcp)
                        .map_err(engine)?;
                }
            }
        }
        Ok(())
    }

    fn build_frame(
        packet: &mut [u8],
        transmit: ntcp::Transmit,
        timestamp: u32,
    ) -> io::Result<usize> {
        match transmit.ip.source {
            IpAddr::V4(_) => build_ipv4_options(packet, transmit, timestamp),
            IpAddr::V6(_) => build_ipv6(packet, transmit),
        }
    }

    fn tun_v6_policy(local: Ipv6Addr) -> impl Fn(AddressValidation) -> bool {
        let valid = |ip| matches!(ip, IpAddr::V6(ip) if unicast_v6(ip));
        move |request| match request {
            AddressValidation::Bind { local: bind } => bind == IpAddr::V6(local) && valid(bind),
            AddressValidation::Open {
                local: source,
                remote: destination,
            } => source == IpAddr::V6(local) && valid(source) && valid(destination),
            AddressValidation::Route {
                source,
                destination,
                hop,
            } => source == IpAddr::V6(local) && valid(source) && valid(destination) && valid(hop),
            AddressValidation::Incoming {
                source,
                destination,
            } => destination == IpAddr::V6(local) && valid(source) && valid(destination),
        }
    }

    fn checked_interface_ipv6(
        local: Ipv6Addr,
        address: Ipv6Addr,
        mask: u128,
        scope_id: u32,
    ) -> io::Result<()> {
        let prefix = mask.leading_ones();
        if mask != u128::MAX.checked_shl(128 - prefix).unwrap_or(0) {
            return Err(invalid("noncontiguous IPv6 interface netmask"));
        }
        if !unicast_v6(local)
            || local.segments()[0] & 0xe000 != 0x2000
            || !unicast_v6(address)
            || address.segments()[0] & 0xe000 != 0x2000
            || scope_id != 0
            || local == address
            || u128::from(local) & mask != u128::from(address) & mask
        {
            return Err(invalid(
                "local IPv6 address must be a distinct global-unicast address in the TUN interface subnet",
            ));
        }
        Ok(())
    }

    fn interface_ipv6(tun: &Tun, local: Ipv6Addr) -> io::Result<()> {
        // SAFETY: zero initializes ifreq; the live TUN fd writes its actual name.
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(tun.as_raw_fd(), libc::TUNGETIFF, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut addresses = std::ptr::null_mut();
        // SAFETY: getifaddrs initializes the list pointer on success.
        if unsafe { libc::getifaddrs(&mut addresses) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut found = false;
        let mut kernel_owned = false;
        let mut cursor = addresses;
        // SAFETY: traverse the live getifaddrs list, checking nullable addresses
        // and family before casting; names are NUL-terminated by the kernel.
        unsafe {
            let name = std::ffi::CStr::from_ptr(request.ifr_name.as_ptr());
            while let Some(entry) = cursor.as_ref() {
                if !entry.ifa_addr.is_null() && (*entry.ifa_addr).sa_family as i32 == libc::AF_INET6
                {
                    let address = &*entry.ifa_addr.cast::<libc::sockaddr_in6>();
                    let ip = Ipv6Addr::from(address.sin6_addr.s6_addr);
                    // Any kernel-owned duplicate has a local route that bypasses TUN,
                    // including addresses assigned to another interface.
                    kernel_owned |= ip == local;
                    if std::ffi::CStr::from_ptr(entry.ifa_name) == name
                        && !entry.ifa_netmask.is_null()
                        && (*entry.ifa_netmask).sa_family as i32 == libc::AF_INET6
                    {
                        let mask = &*entry.ifa_netmask.cast::<libc::sockaddr_in6>();
                        found |= checked_interface_ipv6(
                            local,
                            ip,
                            u128::from_be_bytes(mask.sin6_addr.s6_addr),
                            address.sin6_scope_id,
                        )
                        .is_ok();
                    }
                }
                cursor = entry.ifa_next;
            }
            libc::freeifaddrs(addresses);
        }
        if kernel_owned {
            Err(invalid("local IPv6 address is already owned by the kernel"))
        } else if found {
            Ok(())
        } else {
            Err(invalid(
                "local IPv6 address must be a distinct global-unicast address in the TUN interface subnet",
            ))
        }
    }

    fn open_tun(name: &str) -> io::Result<Tun> {
        Tun::open(name)
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

    fn interface_subnet(tun: &Tun, local: Ipv4Addr) -> io::Result<(Ipv4Addr, u8)> {
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

    // Generation commits a TCP send; retain the complete frame until the
    // backend accepts it. No new poll_transmit may overwrite this buffer.
    fn flush_pending(
        output: &[u8],
        pending: &mut usize,
        send: impl FnOnce(&[u8]) -> io::Result<TxOutcome>,
    ) -> io::Result<bool> {
        if *pending == 0 {
            return Ok(true);
        }
        match send(&output[..*pending]) {
            Ok(TxOutcome::Submitted) => {
                *pending = 0;
                Ok(true)
            }
            Ok(TxOutcome::WouldBlock) => Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn transmit_frames(
        endpoint: &mut Endpoint,
        time: u64,
        output: &mut [u8],
        pending: &mut usize,
        header_len: usize,
        timestamp: u32,
        backend: &mut impl PacketIo,
    ) -> io::Result<()> {
        // Each poll spends one engine work unit, at most 32 units/packets.
        for _ in 0..BUDGET {
            if !flush_pending(output, pending, |packet| backend.transmit(packet))? {
                break;
            }
            let polled = endpoint
                .poll_transmit(time, &mut output[header_len..], 1)
                .map_err(engine)?;
            if let Some(packet) = polled.packet {
                *pending = build_frame(output, packet, timestamp)?;
                if !flush_pending(output, pending, |packet| backend.transmit(packet))? {
                    break;
                }
            }
            if !polled.more_work {
                break;
            }
        }
        Ok(())
    }

    fn wait(tun: &Tun, timeout_ms: i32, pending: bool) -> io::Result<()> {
        let mut fd = libc::pollfd {
            fd: tun.as_raw_fd(),
            events: libc::POLLIN | if pending { libc::POLLOUT } else { 0 },
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
                "usage: tun_echo TUN_NAME LOCAL_IP TCP_PORT [PEER_SOCKET_ADDR]",
            ));
        }
        let local: IpAddr = args[2]
            .parse()
            .map_err(|_| invalid("invalid local IP address"))?;
        let port: u16 = args[3].parse().map_err(|_| invalid("invalid TCP port"))?;
        if !match local {
            IpAddr::V4(ip) => unicast(ip),
            IpAddr::V6(ip) => unicast_v6(ip),
        } || port == 0
        {
            return Err(invalid(
                "expected an unscoped unicast IP address and nonzero port",
            ));
        }
        let ipv4_options_enabled = match std::env::var("NTCP_IPV4_OPTIONS") {
            Ok(value) => options_enabled(Some(&value))?,
            Err(std::env::VarError::NotPresent) => options_enabled(None)?,
            Err(_) => return Err(invalid("invalid NTCP_IPV4_OPTIONS")),
        };
        if local.is_ipv6() && ipv4_options_enabled {
            return Err(invalid("IPv4 option configuration is unsupported for IPv6"));
        }
        let peer = args
            .get(4)
            .map(|value| checked_peer(value, local))
            .transpose()?;
        let header_len = if local.is_ipv4() {
            IP_HEADER
        } else {
            IPV6_HEADER
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
        let address_policy: Box<dyn Fn(AddressValidation) -> bool> = match local {
            IpAddr::V4(ip) => Box::new(tun_address_policy(ip, interface_subnet(&tun, ip)?)),
            IpAddr::V6(ip) => {
                interface_ipv6(&tun, ip)?;
                Box::new(tun_v6_policy(ip))
            }
        };
        let config = EndpointConfig {
            max_connections: MAX_FLOWS,
            preallocate_connections: 0,
            max_listeners: 1,
            max_control_packets: BUDGET,
            max_setup_cache_entries: 64,
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
                mss: (MTU - header_len - 20) as u16,
                receive_ip_payload_limit: (MTU - header_len) as u16,
                send_ip_payload_limit: (MTU - header_len) as u16,
                ..ConnectionConfig::default()
            },
        };
        let mut endpoint =
            Endpoint::new(config, secret, now(start), address_policy).map_err(engine)?;
        let listener = endpoint
            .listen(SocketAddr::new(local, port), MAX_FLOWS)
            .map_err(engine)?;
        let mut flows = Vec::with_capacity(MAX_FLOWS);
        if let Some(peer) = peer {
            let id = endpoint
                .connect(now(start), SocketAddr::new(local, port), peer)
                .map_err(engine)?;
            flows.push(Flow::new(id));
        }
        // One byte beyond the largest non-jumbo IPv6 datagram: a truncated
        // oversized frame cannot masquerade as an exact-length base-header packet.
        // IPv4 total-length handling remains unchanged.
        let mut input = [0u8; 65576];
        // Reserve all output storage BEFORE polling: generation commits a send.
        let mut output = [0u8; MTU];
        let mut pending = 0;
        let mut accepting = false;
        eprintln!(
            "echo listening on {local}:{port} via {} (caller-configured TUN)",
            args[1]
        );
        loop {
            let mut immediate = false;
            for _ in 0..BUDGET {
                match tun.receive(&mut input) {
                    Ok(Some(0)) => {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TUN closed"));
                    }
                    Ok(Some(len)) => {
                        input_frame(
                            &mut endpoint,
                            now(start),
                            &input[..len],
                            local,
                            ipv4_options_enabled,
                            (start.elapsed().as_millis() as u32) | 0x8000_0000,
                        )?;
                    }
                    Ok(None) => break,
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
            transmit_frames(
                &mut endpoint,
                now(start),
                &mut output,
                &mut pending,
                header_len,
                (start.elapsed().as_millis() as u32) | 0x8000_0000,
                &mut tun,
            )?;
            immediate |= pending == 0 && endpoint.has_pending_output();
            let current = now(start);
            let delay = endpoint.next_deadline().map_or(TICK_US, |deadline| {
                deadline.saturating_sub(current).min(TICK_US)
            });
            let timeout_ms = if immediate {
                0
            } else {
                delay.div_ceil(1000) as i32
            };
            wait(&tun, timeout_ms, pending != 0)?;
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

        #[test]
        fn pending_packet_survives_backpressure() {
            use ntcp_io::{PacketIo, PacketLayer};
            struct Mock {
                attempts: usize,
                submitted: Vec<Vec<u8>>,
            }
            impl PacketIo for Mock {
                fn layer(&self) -> PacketLayer {
                    PacketLayer::Ip
                }
                fn receive(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> {
                    Ok(None)
                }
                fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
                    self.attempts += 1;
                    if self.attempts <= 2 {
                        return Ok(TxOutcome::WouldBlock);
                    }
                    self.submitted.push(packet.to_vec());
                    Ok(TxOutcome::Submitted)
                }
            }
            let (mut output, len, local) = packet();
            let staged = output[..len].to_vec();
            let mut pending = len;
            let mut backend = Mock {
                attempts: 0,
                submitted: Vec::new(),
            };
            let mut endpoint =
                Endpoint::new(EndpointConfig::default(), [1; 32], 0, test_policy(local)).unwrap();
            endpoint
                .connect(
                    0,
                    SocketAddr::new(local.into(), 1234),
                    "10.0.0.1:8080".parse().unwrap(),
                )
                .unwrap();
            for _ in 0..2 {
                transmit_frames(
                    &mut endpoint,
                    0,
                    &mut output,
                    &mut pending,
                    IP_HEADER,
                    0,
                    &mut backend,
                )
                .unwrap();
                assert_eq!(pending, len);
                assert_eq!(&output[..len], staged);
                assert!(
                    endpoint.has_pending_output(),
                    "next SYN generated while frame blocked"
                );
                assert!(backend.submitted.is_empty());
                assert_eq!(backend.receive(&mut [0; 1]).unwrap(), None);
            }
            transmit_frames(
                &mut endpoint,
                0,
                &mut output,
                &mut pending,
                IP_HEADER,
                0,
                &mut backend,
            )
            .unwrap();
            assert_eq!(pending, 0);
            assert_eq!(backend.submitted.len(), 2);
            assert_eq!(backend.submitted[0], staged);
            let next = ntcp_ip::parse(&backend.submitted[1], false).unwrap();
            assert_ne!(
                ntcp::wire::parse(next.ip, next.payload)
                    .unwrap()
                    .header
                    .flags
                    & ntcp::wire::SYN,
                0
            );
            transmit_frames(
                &mut endpoint,
                0,
                &mut output,
                &mut pending,
                IP_HEADER,
                0,
                &mut backend,
            )
            .unwrap();
            assert_eq!(backend.submitted.len(), 2, "duplicate send");
        }

        fn v6_transmit(len: usize) -> ntcp::Transmit {
            ntcp::Transmit {
                connection: None,
                ip: IpMetadata {
                    source: "2001:db8::1".parse().unwrap(),
                    destination: "2001:db8::2".parse().unwrap(),
                },
                len,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: ntcp::OutgoingIpv4Options::default(),
            }
        }

        //= https://www.rfc-editor.org/rfc/rfc3168#section-5
        //= type=test
        //= reason=All 64 DSCP values and four ECN values are packed/extracted across both IPv6 Traffic Class nibbles; flow-label high nibble is independent. Bounds, address and direct-TCP scope rejection are asserted.
        //# Bits 6 and 7 in the IPv4 TOS octet are designated as the ECN field. The IPv4 TOS octet corresponds to the Traffic Class octet in IPv6, and the ECN field is defined identically in both cases.
        #[test]
        fn ipv6_base_header_matrix_and_rejections() {
            let local = "2001:db8::2".parse().unwrap();
            let mut bytes = [0xa5; MTU];
            for dscp in 0..64 {
                for ecn in 0..4 {
                    for hop_limit in [1, 64, 255] {
                        let mut transmit = v6_transmit(20);
                        transmit.dscp = dscp;
                        transmit.ecn = ecn;
                        transmit.hop_limit = hop_limit;
                        let len = build_frame(&mut bytes, transmit, 0).unwrap();
                        assert_eq!(len, 60);
                        assert_eq!(bytes[0], 0x60 | (dscp >> 2));
                        assert_eq!(bytes[1], ((dscp << 2) | ecn) << 4);
                        assert_eq!(&bytes[4..8], &[0, 20, 6, hop_limit]);
                        assert_eq!(&bytes[40..60], &[0xa5; 20]);
                        for flow_nibble in 0..16 {
                            bytes[1] = (bytes[1] & 0xf0) | flow_nibble;
                            let (ip, class, tcp) = parse_ipv6(&bytes[..len], local).unwrap();
                            assert_eq!(ip, transmit.ip);
                            assert_eq!(class, (dscp << 2) | ecn);
                            assert_eq!(tcp, &[0xa5; 20]);
                        }
                    }
                }
            }
            let len = build_frame(&mut bytes, v6_transmit(20), 0).unwrap();
            for truncated in 0..len {
                assert!(parse_ipv6(&bytes[..truncated], local).is_none());
            }
            assert!(parse_ipv6(&bytes[..len + 1], local).is_none());
            assert!(parse_ipv6(&bytes[..len], "2001:db8::3".parse().unwrap()).is_none());
            for (offset, value) in [(0, 0x40), (4, 1), (5, 19), (5, 21), (7, 0)] {
                let mut bad = bytes;
                bad[offset] = value;
                assert!(parse_ipv6(&bad[..len], local).is_none());
            }
            // Hop-by-hop (including jumbo), routing, fragment, ESP, AH,
            // destination options, no-next-header, UDP and unknown protocols.
            for next in [0, 43, 44, 50, 51, 60, 59, 17, 255] {
                let mut bad = bytes;
                bad[6] = next;
                assert!(parse_ipv6(&bad[..len], local).is_none());
            }
            let mut jumbo = bytes;
            jumbo[4..6].fill(0);
            assert!(parse_ipv6(&jumbo[..40], local).is_none());
            for address in [
                "::",
                "ff02::1",
                "fe80::1",
                "fec0::1",
                "::1",
                "::ffff:192.0.2.1",
            ] {
                let address: Ipv6Addr = address.parse().unwrap();
                for offset in [8, 24] {
                    let mut bad = bytes;
                    bad[offset..offset + 16].copy_from_slice(&address.octets());
                    assert!(
                        parse_ipv6(&bad[..len], if offset == 24 { address } else { local })
                            .is_none()
                    );
                    let mut transmit = v6_transmit(20);
                    if offset == 8 {
                        transmit.ip.source = address.into();
                    } else {
                        transmit.ip.destination = address.into();
                    }
                    assert!(build_frame(&mut bad, transmit, 0).is_err());
                }
            }
            let local_ip = IpAddr::V6(local);
            assert!(checked_peer("[2001:db8::1]:8080", local_ip).is_ok());
            for peer in [
                "192.0.2.1:8080",
                "[2001:db8::1]:0",
                "[2001:db8::1%2]:8080",
                "[fe80::1]:8080",
                "[ff02::1]:8080",
                "invalid",
            ] {
                assert!(checked_peer(peer, local_ip).is_err());
            }
            assert!(checked_peer("[2001:db8::1]:8080", "192.0.2.2".parse().unwrap()).is_err());
            let policy = tun_v6_policy(local);
            assert!(policy(AddressValidation::Bind {
                local: local.into()
            }));
            assert!(!policy(AddressValidation::Bind {
                local: "2001:db8::3".parse().unwrap()
            }));
            assert!(!policy(AddressValidation::Incoming {
                source: "192.0.2.1".parse().unwrap(),
                destination: local.into()
            }));
            for payload in [1, 20, MTU - IPV6_HEADER] {
                let len = build_frame(&mut bytes, v6_transmit(payload), 0).unwrap();
                assert_eq!(len, IPV6_HEADER + payload);
                assert_eq!(parse_ipv6(&bytes[..len], local).unwrap().2.len(), payload);
            }
            let before = bytes;
            for payload in [0, MTU - IPV6_HEADER + 1, usize::MAX] {
                assert!(build_frame(&mut bytes, v6_transmit(payload), 0).is_err());
                assert_eq!(bytes, before);
            }
            assert!(build_frame(&mut bytes[..59], v6_transmit(20), 0).is_err());
            for (dscp, ecn, hop) in [(64, 0, 64), (0, 4, 64), (0, 0, 0)] {
                let mut transmit = v6_transmit(20);
                transmit.dscp = dscp;
                transmit.ecn = ecn;
                transmit.hop_limit = hop;
                assert!(build_frame(&mut bytes, transmit, 0).is_err());
            }
            let mut transmit = v6_transmit(20);
            transmit.ip.destination = "192.0.2.2".parse().unwrap();
            assert!(build_frame(&mut bytes, transmit, 0).is_err());
            transmit = v6_transmit(20);
            transmit.ipv4_options.record_route_slots = Some(1);
            assert!(build_frame(&mut bytes, transmit, 0).is_err());
            let (v4, len, _) = packet();
            assert!(parse_ipv6(&v4[..len], local).is_none());
            assert!(parse_ipv4(&bytes[..60], Ipv4Addr::new(192, 0, 2, 2)).is_none());
        }

        //= https://www.rfc-editor.org/rfc/rfc3168#section-5
        //= type=test
        //= reason=Two actual IPv6 Endpoints negotiate ECN through the runtime base-header encoder/input dispatch, transmit ECT data, receive CE Traffic Class, emit ECE feedback and then CWR data. This is privilege-free adapter evidence, not a live kernel TUN/routing test.
        //# Bits 6 and 7 in the IPv4 TOS octet are designated as the ECN field. The IPv4 TOS octet corresponds to the Traffic Class octet in IPv6, and the ECN field is defined identically in both cases.
        #[test]
        fn ipv6_framed_handshake_and_ecn_feedback() {
            fn transfer(
                from: &mut Endpoint,
                to: &mut Endpoint,
                local: IpAddr,
                time: u64,
                mark_ce: bool,
            ) -> Vec<(u8, u8, usize)> {
                let mut bytes = [0; MTU];
                let mut observed = Vec::new();
                for _ in 0..BUDGET {
                    // Same pre-commit header reservation as the TUN runtime.
                    let polled = from
                        .poll_transmit(time, &mut bytes[IPV6_HEADER..], 1)
                        .unwrap();
                    if let Some(transmit) = polled.packet {
                        let len = build_frame(&mut bytes, transmit, 0).unwrap();
                        let IpAddr::V6(local_v6) = local else {
                            panic!("wrong family")
                        };
                        let (ip, class, tcp) = parse_ipv6(&bytes[..len], local_v6).unwrap();
                        let segment = ntcp::wire::parse(ip, tcp).unwrap();
                        assert_eq!(class >> 2, 37);
                        assert_eq!(bytes[7], 64);
                        observed.push((segment.header.flags, class & 3, segment.payload.len()));
                        if mark_ce && !segment.payload.is_empty() {
                            assert_eq!(class & 3, 2, "negotiated data must be ECT(0)");
                            bytes[1] = (bytes[1] & 0xcf) | 0x30;
                        }
                        input_frame(to, time, &bytes[..len], local, false, 0).unwrap();
                    }
                    if !polled.more_work {
                        return observed;
                    }
                }
                panic!("IPv6 framed transfer exceeded bounded work budget");
            }
            let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
            let b: Ipv6Addr = "2001:db8::2".parse().unwrap();
            let mut cfg = EndpointConfig {
                dscp: 37,
                ..EndpointConfig::default()
            };
            cfg.connection.nagle = false;
            cfg.connection.mss = (MTU - IPV6_HEADER - 20) as u16;
            cfg.connection.receive_ip_payload_limit = (MTU - IPV6_HEADER) as u16;
            cfg.connection.send_ip_payload_limit = (MTU - IPV6_HEADER) as u16;
            let mut client = Endpoint::new(cfg.clone(), [1; 32], 0, tun_v6_policy(a)).unwrap();
            let mut server = Endpoint::new(cfg, [2; 32], 0, tun_v6_policy(b)).unwrap();
            let local = SocketAddr::new(a.into(), 1234);
            let remote = SocketAddr::new(b.into(), 8080);
            let listener = server.listen(remote, 1).unwrap();
            let id = client.connect(0, local, remote).unwrap();
            let syn = transfer(&mut client, &mut server, b.into(), 0, false);
            assert_eq!(syn.len(), 1);
            assert_eq!(
                syn[0],
                (ntcp::wire::SYN | ntcp::wire::ECE | ntcp::wire::CWR, 0, 0)
            );
            let synack = transfer(&mut server, &mut client, a.into(), 0, false);
            assert_eq!(synack.len(), 1);
            assert_eq!(
                synack[0],
                (ntcp::wire::SYN | ntcp::wire::ACK | ntcp::wire::ECE, 0, 0)
            );
            transfer(&mut client, &mut server, b.into(), 0, false);
            let accepted = server.accept(listener).unwrap();
            assert_eq!(client.state(id).unwrap(), State::Established);
            assert_eq!(server.state(accepted).unwrap(), State::Established);
            client.write(id, b"CE-marked data").unwrap();
            let data = transfer(&mut client, &mut server, b.into(), 1, true);
            assert!(data.iter().any(|&(_, ecn, len)| ecn == 2 && len == 14));
            server.on_timeout(300_000, BUDGET).unwrap();
            let feedback = transfer(&mut server, &mut client, a.into(), 300_000, false);
            assert!(
                feedback
                    .iter()
                    .any(|&(flags, ecn, len)| flags & ntcp::wire::ECE != 0 && ecn == 0 && len == 0)
            );
            let mut received = [0; 32];
            let count = server.read(accepted, &mut received).unwrap();
            assert_eq!(&received[..count], b"CE-marked data");
            client.write(id, b"after feedback").unwrap();
            let cwr = transfer(&mut client, &mut server, b.into(), 300_001, false);
            assert!(
                cwr.iter()
                    .any(|&(flags, ecn, len)| flags & ntcp::wire::CWR != 0 && ecn == 2 && len > 0)
            );
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
        fn ipv6_interface_prefix_requires_distinct_unscoped_global_address() {
            let interface: Ipv6Addr = "2001:db8::2".parse().unwrap();
            let local: Ipv6Addr = "2001:db8::3".parse().unwrap();
            for prefix in 0..=127 {
                let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
                assert!(checked_interface_ipv6(local, interface, mask, 0).is_ok());
                assert!(checked_interface_ipv6(interface, interface, mask, 0).is_err());
                if prefix != 0 {
                    let outside = Ipv6Addr::from(u128::from(local) ^ (1 << (128 - prefix)));
                    assert!(checked_interface_ipv6(outside, interface, mask, 0).is_err());
                }
            }
            assert!(checked_interface_ipv6(local, interface, u128::MAX, 0).is_err());
            let mask = u128::MAX << 64;
            assert!(checked_interface_ipv6(local, interface, mask, 1).is_err());
            for ip in [
                "2001:db8:1::3",
                "::",
                "::1",
                "ff02::1",
                "fe80::3",
                "fec0::3",
                "fc00::3",
                "::ffff:192.0.2.3",
            ] {
                assert!(checked_interface_ipv6(ip.parse().unwrap(), interface, mask, 0).is_err());
            }
            for ip in ["fe80::2", "fec0::2", "fc00::2", "::1", "ff02::2"] {
                assert!(checked_interface_ipv6(local, ip.parse().unwrap(), 0, 0).is_err());
            }
            for mask in [1, u128::MAX - 2, (u128::MAX << 64) | 1] {
                assert!(checked_interface_ipv6(local, interface, mask, 0).is_err());
            }
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
        //= https://www.rfc-editor.org/rfc/rfc3168#section-5
        //= type=test
        //= reason=IPv4 ECN/DSCP/checksum/DF matrix complements the IPv6 direct-TCP base-header matrix and two-Endpoint framed ECN feedback test.
        //# Bits 6 and 7 in the IPv4 TOS octet are designated as the ECN field. The IPv4 TOS octet corresponds to the Traffic Class octet in IPv6, and the ECN field is defined identically in both cases.
        // Actor/condition: IP adapter; IPv4 and IPv6 traffic class encoding.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-5.3
        //= type=test
        //= reason=IPv4 example sets DF for all packets; ECN/DSCP matrix explicitly asserts DF and no fragment offset, including both ECT codepoints.
        //# ECN-capable packets MAY have the DF (Don't Fragment) bit set.
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
                    assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 0x4000); // DF, no fragments.
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
