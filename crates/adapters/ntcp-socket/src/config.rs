// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

const MAX_FILE_BYTES: usize = 64 * 1024;
// The local send and allocation ceiling (it sizes send scratch). It does not
// limit the receive MSS offer, which every native connection takes from its
// Host's receive capability for the link (tcp.advertised_mss caps it).
pub(crate) const MSS: u16 = 1460;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Backend {
    #[default]
    Tun,
    AfPacket,
}

#[derive(Clone, Debug)]
pub struct SocketConfig {
    pub tcp: ntcp::EndpointConfig,
    pub socket: SocketPolicy,
    pub fast_open_cookie_policy: ntcp::FastOpenCookiePolicy,
    /// None manages HMAC automatically and treats explicitly supplied Linux
    /// keys as external. Some(true) manages fresh keys for either codec.
    pub fast_open_managed_keys: Option<bool>,
    pub fast_open_cookie_lifetime: ntcp::FastOpenCookieLifetime,
    /// Trusted absolute lease in owner microseconds; external deployments must
    /// preserve its clock mapping across restart, or provide fresh keys.
    pub fast_open_key_lease: Option<ntcp::FastOpenKeyLease>,
    pub io: IoConfig,
    pub routes: Vec<(IpAddr, ntcp::RoutePolicy)>,
    /// The owner's local path control socket (`control.socket`,
    /// `control.allow_uids`), separate from the `route.*` transport
    /// policies: None (the default) serves nothing.
    pub control: Option<ntcp_path_control::ControlConfig>,
    /// Owner-configured Segment Routing routes (`ipv6.srh.<prefix>=S1,...,Sn`,
    /// separate from the `route.*` transport policies), installed over the
    /// configured interface beside its default route. Empty by default:
    /// output carries no extension header.
    pub segment_routes: Vec<SegmentRoute>,
    /// Ports beyond the `io.*` one (`port.<name>.<field>`), on the same
    /// `io.backend` and address family. Empty by default: the runtime owns
    /// exactly the `io.*` port.
    pub ports: Vec<PortConfig>,
}

/// One additional port: its own interface, address and prefix, with the
/// same meaning and validation as `io.interface`, `io.address`, `io.prefix`
/// and `io.next_hop_mac`, and its gateway routes
/// (`port.<name>.gateway.<prefix> = <next hop>`), each next hop on this
/// port's link (a link-local next hop is scoped to it).
///
/// An AF_PACKET port without `next_hop_mac` resolves the IP next hop of
/// each packet instead of forwarding everything through one fixed MAC: an
/// IPv6 port by Neighbor Discovery, with its address tentative until
/// Duplicate Address Detection completes; an IPv4 port through the
/// operator's static neighbors (`port.<name>.neighbor.<address> = <mac>`,
/// on the port's prefix; there is no ARP), which every IPv4 gateway next
/// hop needs. A gateway route is refused on a port that resolves no IP
/// next hop: a TUN device or a port with a fixed `next_hop_mac`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortConfig {
    pub name: String,
    pub interface: String,
    pub address: IpAddr,
    pub prefix: Option<u8>,
    pub next_hop_mac: Option<[u8; 6]>,
    pub gateways: Vec<(ntcp_host::path::IpPrefix, IpAddr)>,
    pub neighbors: Vec<(IpAddr, [u8; 6])>,
}

/// Final destinations of `destination` are sent through `segments` S1..Sn
/// (`PathService::add_segment_route`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentRoute {
    pub destination: ntcp_host::path::IpPrefix,
    pub segments: Vec<Ipv6Addr>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketPolicy {
    pub notsent_lowat: u32,
    pub fast_open_client_enabled: bool,
    pub fast_open_client_policy: ntcp::FastOpenClientPolicy,
}

impl Default for SocketPolicy {
    fn default() -> Self {
        Self {
            notsent_lowat: u32::MAX,
            fast_open_client_enabled: true,
            fast_open_client_policy: ntcp::FastOpenClientPolicy::RequireCookie,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoConfig {
    pub backend: Backend,
    pub interface: String,
    pub address: IpAddr,
    pub prefix: Option<u8>,
    /// The legacy fixed forwarder: everything leaves through this MAC, over
    /// a default route. An AF_PACKET `io.*` port without it resolves its
    /// next hops like a `port.<name>` port without `next_hop_mac`
    /// (`PortConfig`), with `gateways` (`io.gateway.<prefix> = <next hop>`)
    /// and, for IPv4, `neighbors` (`io.neighbor.<address> = <mac>`), and
    /// gets no implicit default route.
    pub next_hop_mac: Option<[u8; 6]>,
    pub gateways: Vec<(ntcp_host::path::IpPrefix, IpAddr)>,
    pub neighbors: Vec<(IpAddr, [u8; 6])>,
    pub output_reservation_timeout_ms: u32,
    pub egress_capacity: usize,
    pub gso: Option<ntcp::GsoLimits>,
    pub receive_aggregation: bool,
    /// `io.source_quiet`: when earlier emission from `address` ceased, the
    /// same operational assertion as tun_echo's NTCP_SOURCE_QUIET.
    pub source_quiet: SourceQuiet,
}

impl IoConfig {
    /// An AF_PACKET port without `next_hop_mac`: it resolves its next hops.
    pub(crate) fn resolves(&self) -> bool {
        self.backend == Backend::AfPacket && self.next_hop_mac.is_none()
    }
}

/// `io.source_quiet = SECONDS | never`: deployment knowledge of when IP
/// packets were last emitted from the configured source address before this
/// runtime started. The Host's identifier allocator issues no IPv4
/// Identification for a source until one maximum datagram lifetime (MDL,
/// 120 s; RFC 6864 sections 1 and 3.2) after earlier emission from it may
/// have ceased, so a datagram still in the network can never share an
/// identifier with a new one (RFC 6864 section 4.3). Unset (`Unknown`, the
/// default), an earlier process may have emitted from the address until
/// now: identifiers wait a full MDL after startup
/// (`Continuity::QuietSince(start)`). Consequently a connection with
/// IP_PMTUDISC_DONT cannot send its DF-clear packets until one MDL after
/// startup; they are held as explicit backpressure, never sent with a
/// reused identifier. `SECONDS` asserts that emission ceased at least that
/// many whole seconds before startup, `never` that there was none (for
/// example an address created for this runtime); identifiers then start at
/// the end of the remaining quiet period (`Continuity::QuietFor`). The
/// assertion states a fact about the deployment; it does not shorten the
/// MDL, and a false assertion can repeat an identifier still in flight.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SourceQuiet {
    #[default]
    Unknown,
    Seconds(u64),
    Never,
}

impl SourceQuiet {
    /// The allocator's start for a Host started at `now`.
    pub(crate) fn continuity(self, now: u64) -> ntcp_host::Continuity {
        match self {
            Self::Unknown => ntcp_host::Continuity::QuietSince(now),
            Self::Seconds(seconds) => ntcp_host::Continuity::QuietFor { at: now, seconds },
            Self::Never => ntcp_host::Continuity::QuietFor {
                at: now,
                seconds: u64::MAX,
            },
        }
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid socket configuration")
}

impl SocketConfig {
    pub fn new(interface: impl Into<String>, address: impl Into<IpAddr>) -> Self {
        let address = address.into();
        let mut tcp = ntcp::EndpointConfig {
            max_connections: crate::runtime::LIMIT,
            max_listeners: crate::runtime::LIMIT,
            max_control_packets: crate::runtime::LIMIT,
            max_buffer_bytes: 128 * 1024 * 1024,
            ..ntcp::EndpointConfig::default()
        };
        tcp.connection.receive_capacity = crate::runtime::BYTES;
        tcp.connection.send_capacity = crate::runtime::BYTES;
        tcp.connection.mss = MSS;
        tcp.connection.send_ip_payload_limit = if address.is_ipv4() { 1480 } else { 1460 };
        // receive_ip_payload_limit keeps the core default: it bounds only a
        // raw Endpoint's legacy offer, and native connections are managed.
        Self {
            tcp,
            socket: SocketPolicy::default(),
            fast_open_cookie_policy: ntcp::FastOpenCookiePolicy::default(),
            fast_open_managed_keys: None,
            fast_open_cookie_lifetime: Default::default(),
            fast_open_key_lease: None,
            routes: Vec::new(),
            control: None,
            segment_routes: Vec::new(),
            ports: Vec::new(),
            io: IoConfig {
                backend: Backend::Tun,
                interface: interface.into(),
                address,
                prefix: None,
                next_hop_mac: None,
                gateways: Vec::new(),
                neighbors: Vec::new(),
                output_reservation_timeout_ms: 1000,
                egress_capacity: crate::runtime::BUDGET,
                gso: None,
                receive_aggregation: false,
                source_quiet: SourceQuiet::Unknown,
            },
        }
    }

    pub(crate) fn fast_open_keys_managed(&self) -> io::Result<bool> {
        let managed = self.fast_open_managed_keys.unwrap_or(matches!(
            self.fast_open_cookie_policy,
            ntcp::FastOpenCookiePolicy::HmacSha256
        ));
        if managed && self.fast_open_key_lease.is_some() {
            return Err(invalid());
        }
        Ok(managed)
    }

    pub fn validate(&self) -> io::Result<()> {
        self.fast_open_keys_managed()?;
        if let Some(lease) = self.fast_open_key_lease {
            lease
                .validate(lease.not_before, self.tcp.connection.timebase)
                .map_err(|_| invalid())?;
        }
        if self.io.receive_aggregation && self.io.backend != Backend::AfPacket {
            return Err(invalid());
        }
        if self.io.gso.is_some_and(|limits| {
            limits.max_bytes == 0
                || limits.max_bytes > u32::MAX as usize / 2
                || limits.max_segments < 2
                || limits.max_segments > limits.max_bytes
                || limits
                    .max_bytes
                    .checked_mul(self.io.egress_capacity)
                    .is_none()
        }) {
            return Err(invalid());
        }
        if self.io.egress_capacity == 0
            || self.io.egress_capacity.checked_mul(65535 + 14).is_none()
            || self.io.output_reservation_timeout_ms == 0
            || !valid_port(
                self.io.backend,
                &self.io.interface,
                self.io.address,
                self.io.prefix,
                self.io.next_hop_mac,
            )
            || !valid_resolution(
                self.io.backend,
                self.io.address,
                self.io.prefix,
                self.io.next_hop_mac,
                &self.io.gateways,
                &self.io.neighbors,
            )
            // Segment Routing routes are installed through the fixed
            // forwarder beside the default route, which a resolving `io.*`
            // port does not have.
            || (!self.segment_routes.is_empty() && self.io.resolves())
        {
            return Err(invalid());
        }
        self.validate_ports()?;
        // Before IO opens, validate against configured allocation ceilings.
        // Backend startup repeats policy validation with the actual interface MTU.
        let mut route_defaults = self.tcp.connection.clone();
        let bound = (u32::from(route_defaults.send_ip_payload_limit)
            + crate::ip::header_len(self.io.address) as u32)
            .min(65535);
        route_defaults
            .pmtud
            .get_or_insert(ntcp::PmtudConfig::new(bound));
        if self.routes.len() > self.tcp.max_route_policies {
            return Err(invalid());
        }
        for (i, (destination, policy)) in self.routes.iter().enumerate() {
            // Route policies are keyed by address alone, without a zone.
            if !crate::ip::global_unicast(*destination)
                || destination.is_ipv4() != self.io.address.is_ipv4()
                || self.routes[..i]
                    .iter()
                    .any(|(other, _)| other == destination)
            {
                return Err(invalid());
            }
            policy
                .validate(&route_defaults, self.io.address.is_ipv4())
                .map_err(|_| invalid())?;
        }
        // Distinct IPv6 prefixes: two lists for one prefix are ambiguous.
        for (i, route) in self.segment_routes.iter().enumerate() {
            if !self.io.address.is_ipv6()
                || ntcp_host::path::check_segment_route(route.destination, &route.segments).is_err()
                || self.segment_routes[..i]
                    .iter()
                    .any(|other| other.destination == route.destination)
            {
                return Err(invalid());
            }
        }
        if let Some(control) = &self.control
            && (!control.socket.is_absolute()
                || control.allow_uids.len() > ntcp_path_control::server::MAX_ALLOWED_UIDS)
        {
            return Err(invalid());
        }
        self.tcp.validate().map_err(|_| invalid())?;
        let c = &self.tcp.connection;
        c.validate(self.io.address.is_ipv4())
            .map_err(|_| invalid())?;
        // The owner clock, IPv4 packet size and descriptor registry are adapter constraints.
        if self.tcp.ipv4_options_enabled // Native TCP neither sends IPv4 options nor admits source routes.
            || c.timebase.units_per_second != 1_000_000
            || c.send_ip_payload_limit > 65515
            || self.tcp.max_connections > crate::runtime::LIMIT
            || self.tcp.max_listeners > crate::runtime::LIMIT
            || c.keepalive.is_some_and(|k| {
                k.send_garbage || k.idle_us % 1_000_000 != 0
                    || k.interval_us % 1_000_000 != 0
                    || !(1..=32767).contains(&(k.idle_us / 1_000_000))
                    || !(1..=32767).contains(&(k.interval_us / 1_000_000))
                    || !(2..=127).contains(&k.probes)
            })
        {
            return Err(invalid());
        }
        Ok(())
    }

    // Every additional port is configured like the `io.*` port, on its own
    // interface. One runtime is one address family (its sockets' domain and
    // its Endpoint configuration are per family). A global address names one
    // node without a zone and so belongs to one port; a link-local address
    // is unique only within its link and may repeat on distinct ports
    // (RFC 4007 section 6).
    fn validate_ports(&self) -> io::Result<()> {
        for (i, port) in self.ports.iter().enumerate() {
            let earlier = &self.ports[..i];
            if !valid_name(&port.name)
                || !valid_port(
                    self.io.backend,
                    &port.interface,
                    port.address,
                    port.prefix,
                    port.next_hop_mac,
                )
                || port.address.is_ipv4() != self.io.address.is_ipv4()
                || port.interface == self.io.interface
                || (port.address == self.io.address && crate::ip::global_unicast(port.address))
                || earlier.iter().any(|other| {
                    other.name == port.name
                        || other.interface == port.interface
                        || (other.address == port.address
                            && crate::ip::global_unicast(port.address))
                })
            {
                return Err(invalid());
            }
            if !valid_resolution(
                self.io.backend,
                port.address,
                port.prefix,
                port.next_hop_mac,
                &port.gateways,
                &port.neighbors,
            ) {
                return Err(invalid());
            }
        }
        Ok(())
    }

    pub fn parse(text: &str) -> io::Result<Self> {
        if text.len() > MAX_FILE_BYTES {
            return Err(invalid());
        }
        let mut config = Self::new("", Ipv4Addr::UNSPECIFIED);
        let mut cookie_mode = "hmac-sha256";
        let mut cookie_key = None;
        let mut gso_bytes = None;
        let mut gso_segments = None;
        let mut pacing_enabled = false;
        let mut pacing = ntcp::PacingConfig::default();
        let mut tuned = false;
        let mut control_uids = None;
        let mut seen = BTreeSet::new();
        let mut ports: Vec<(&str, PortFields)> = Vec::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(invalid)?;
            let (key, value) = (key.trim(), value.trim());
            if !seen.insert(key) || value.is_empty() {
                return Err(invalid());
            }
            if let Some(prefix) = key.strip_prefix("ipv6.srh.") {
                let segments = value
                    .split(',')
                    .map(|s| s.trim().parse::<Ipv6Addr>().map_err(|_| invalid()))
                    .collect::<io::Result<Vec<_>>>()?;
                config.segment_routes.push(SegmentRoute {
                    destination: prefix.parse().map_err(|_| invalid())?,
                    segments,
                });
                continue;
            }
            if let Some(rest) = key.strip_prefix("port.") {
                let (name, field) = rest.split_once('.').ok_or_else(invalid)?;
                if !valid_name(name) {
                    return Err(invalid());
                }
                let index = match ports.iter().position(|(n, _)| *n == name) {
                    Some(index) => index,
                    None => {
                        ports.push((name, PortFields::default()));
                        ports.len() - 1
                    }
                };
                let port = &mut ports[index].1;
                match field {
                    "interface" => port.interface = Some(value.into()),
                    "address" => port.address = Some(value.parse().map_err(|_| invalid())?),
                    "prefix" => port.prefix = Some(number(value)?),
                    "next_hop_mac" => port.next_hop_mac = Some(mac(value)?),
                    _ => {
                        if let Some(address) = field.strip_prefix("neighbor.") {
                            port.neighbors
                                .push((address.parse().map_err(|_| invalid())?, mac(value)?));
                            continue;
                        }
                        let prefix = field.strip_prefix("gateway.").ok_or_else(invalid)?;
                        port.gateways.push((
                            prefix.parse().map_err(|_| invalid())?,
                            value.parse().map_err(|_| invalid())?,
                        ));
                    }
                }
                continue;
            }
            if let Some(route) = key.strip_prefix("route.") {
                let (address, field) = route.rsplit_once('.').ok_or_else(invalid)?;
                let address: IpAddr = address.parse().map_err(|_| invalid())?;
                let index = match config.routes.iter().position(|(ip, _)| *ip == address) {
                    Some(index) => index,
                    None => {
                        if config.routes.len() == config.tcp.max_route_policies {
                            return Err(invalid());
                        }
                        config.routes.push((address, ntcp::RoutePolicy::default()));
                        config.routes.len() - 1
                    }
                };
                let policy = &mut config.routes[index].1;
                match field {
                    "mtu" => policy.mtu = Some(number(value)?),
                    "advertised_mss" => policy.advertised_mss = Some(number(value)?),
                    "initial_mtu" => policy.initial_mtu = Some(number(value)?),
                    "initial_search_low" => policy.initial_search_low = Some(number(value)?),
                    "initial_search_high" => policy.initial_search_high = Some(number(value)?),
                    _ => return Err(invalid()),
                }
                continue;
            }
            match key {
                "socket.fast_open_client_enabled" => {
                    config.socket.fast_open_client_enabled = match value {
                        "true" => true,
                        "false" => false,
                        _ => return Err(invalid()),
                    };
                }
                "socket.fast_open_client_policy" => {
                    config.socket.fast_open_client_policy = match value {
                        "require-cookie" => ntcp::FastOpenClientPolicy::RequireCookie,
                        "application-protected" => ntcp::FastOpenClientPolicy::ApplicationProtected,
                        _ => return Err(invalid()),
                    };
                }
                "socket.fast_open_cookie" => cookie_mode = value,
                "socket.fast_open_managed_keys" => {
                    config.fast_open_managed_keys = Some(match value {
                        "true" => true,
                        "false" => false,
                        _ => return Err(invalid()),
                    })
                }
                "socket.fast_open_cookie_lifetime_us" => {
                    config.fast_open_cookie_lifetime =
                        ntcp::FastOpenCookieLifetime::from_micros(number(value)?)
                            .map_err(|_| invalid())?;
                }
                "socket.fast_open_key_not_before_us"
                | "socket.fast_open_key_issue_until_us"
                | "socket.fast_open_key_accept_until_us" => {
                    let lease = config
                        .fast_open_key_lease
                        .get_or_insert(ntcp::FastOpenKeyLease {
                            not_before: 0,
                            issue_until: 0,
                            accept_until: 0,
                            units_per_second: 1_000_000,
                        });
                    match key {
                        "socket.fast_open_key_not_before_us" => lease.not_before = number(value)?,
                        "socket.fast_open_key_issue_until_us" => lease.issue_until = number(value)?,
                        _ => lease.accept_until = number(value)?,
                    }
                }
                "socket.fast_open_key" => cookie_key = Some(value),
                "socket.notsent_lowat" => config.socket.notsent_lowat = number(value)?,
                "io.backend" => {
                    config.io.backend = match value {
                        "tun" => Backend::Tun,
                        "af-packet" => Backend::AfPacket,
                        _ => return Err(invalid()),
                    }
                }
                "io.interface" => config.io.interface = value.into(),
                "io.address" => config.io.address = value.parse().map_err(|_| invalid())?,
                "io.prefix" => config.io.prefix = Some(number(value)?),
                "io.egress_capacity" => config.io.egress_capacity = number(value)?,
                "io.receive_aggregation" => {
                    config.io.receive_aggregation = match value {
                        "true" => true,
                        "false" => false,
                        _ => return Err(invalid()),
                    }
                }
                "io.source_quiet" => {
                    config.io.source_quiet = match value {
                        "never" => SourceQuiet::Never,
                        seconds => SourceQuiet::Seconds(number(seconds)?),
                    }
                }
                "io.gso_max_bytes" => gso_bytes = Some(number(value)?),
                "io.gso_max_segments" => gso_segments = Some(number(value)?),
                "io.output_reservation_timeout_ms" => {
                    config.io.output_reservation_timeout_ms = number(value)?;
                }
                "io.next_hop_mac" => config.io.next_hop_mac = Some(mac(value)?),
                _ if key.starts_with("io.neighbor.") => {
                    let address = &key["io.neighbor.".len()..];
                    config
                        .io
                        .neighbors
                        .push((address.parse().map_err(|_| invalid())?, mac(value)?));
                }
                _ if key.starts_with("io.gateway.") => {
                    let prefix = &key["io.gateway.".len()..];
                    config.io.gateways.push((
                        prefix.parse().map_err(|_| invalid())?,
                        value.parse().map_err(|_| invalid())?,
                    ));
                }
                "tcp.advertised_mss" => config.tcp.connection.advertised_mss = Some(number(value)?),
                "tcp.pacing" => {
                    pacing_enabled = match value {
                        "true" => true,
                        "false" => false,
                        _ => return Err(invalid()),
                    }
                }
                "tcp.pacing_gain_percent" => {
                    pacing.rate_gain_percent = number(value)?;
                    tuned = true;
                }
                "tcp.pacing_max_bytes_per_second" => {
                    pacing.max_bytes_per_second = Some(number(value)?);
                    tuned = true;
                }
                "tcp.pacing_initial_window_burst" => {
                    pacing.initial_window_burst = match value {
                        "true" => true,
                        "false" => false,
                        _ => return Err(invalid()),
                    };
                    tuned = true;
                }
                "tcp.pacing_burst_segments" => {
                    pacing.max_burst_segments = number(value)?;
                    tuned = true;
                }
                "control.socket" => {
                    config.control = Some(ntcp_path_control::ControlConfig {
                        socket: value.into(),
                        allow_uids: Vec::new(),
                    })
                }
                "control.allow_uids" => {
                    control_uids = Some(
                        ntcp_path_control::ControlConfig::parse_uids(value)
                            .map_err(|_| invalid())?,
                    )
                }
                _ => return Err(invalid()),
            }
        }
        config.fast_open_cookie_policy = match (cookie_mode, cookie_key) {
            ("hmac-sha256", None) => ntcp::FastOpenCookiePolicy::HmacSha256,
            #[cfg(feature = "tfo-linux-cookie")]
            ("linux-siphash24", Some(key)) => {
                if key.len() != 32 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(invalid());
                }
                let mut bytes = [0; 16];
                for (i, byte) in bytes.iter_mut().enumerate() {
                    *byte =
                        u8::from_str_radix(&key[i * 2..i * 2 + 2], 16).map_err(|_| invalid())?;
                }
                ntcp::FastOpenCookiePolicy::LinuxSipHash24(ntcp::LinuxSipHash24Key::new(bytes))
            }
            _ => return Err(invalid()),
        };
        if tuned && !pacing_enabled {
            return Err(invalid());
        }
        config.io.gso = match (gso_bytes, gso_segments) {
            (None, None) => None,
            (Some(max_bytes), Some(max_segments)) => Some(ntcp::GsoLimits {
                max_bytes,
                max_segments,
            }),
            _ => return Err(invalid()),
        };
        config.tcp.connection.pacing = pacing_enabled.then_some(pacing);
        // A port needs its interface and address; the rest is optional as
        // for the `io.*` port.
        config.ports.try_reserve_exact(ports.len()).map_err(|_| invalid())?;
        for (name, port) in ports {
            config.ports.push(PortConfig {
                name: name.into(),
                interface: port.interface.ok_or_else(invalid)?,
                address: port.address.ok_or_else(invalid)?,
                prefix: port.prefix,
                next_hop_mac: port.next_hop_mac,
                gateways: port.gateways,
                neighbors: port.neighbors,
            });
        }
        // An allow-list without a socket would be inert configuration.
        match (&mut config.control, control_uids) {
            (Some(control), Some(uids)) => control.allow_uids = uids,
            (None, Some(_)) => return Err(invalid()),
            _ => {}
        }
        config.validate()?;
        Ok(config)
    }

    pub fn from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        // O_NONBLOCK prevents a FIFO open from waiting before fstat rejects it.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?;
        if !file.metadata()?.is_file() {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        file.take((MAX_FILE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_FILE_BYTES {
            return Err(invalid());
        }
        Self::parse(std::str::from_utf8(&bytes).map_err(|_| invalid())?)
    }
}

// The `port.<name>.*` fields as they are parsed.
#[derive(Default)]
struct PortFields {
    interface: Option<String>,
    address: Option<IpAddr>,
    prefix: Option<u8>,
    next_hop_mac: Option<[u8; 6]>,
    gateways: Vec<(ntcp_host::path::IpPrefix, IpAddr)>,
    neighbors: Vec<(IpAddr, [u8; 6])>,
}

// A port name is one configuration key component.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

// The interface, address, prefix and fixed next hop of one port, as the
// `io.*` keys have always been validated. An AF_PACKET port without a fixed
// next hop resolves its next hops (`valid_resolution`).
fn valid_port(
    backend: Backend,
    interface: &str,
    address: IpAddr,
    prefix: Option<u8>,
    next_hop_mac: Option<[u8; 6]>,
) -> bool {
    !interface.is_empty()
        && interface.len() < libc::IFNAMSIZ
        && !interface.bytes().any(|b| {
            b == 0
                || b.is_ascii_whitespace()
                || b == b'/'
                || b == b':'
                || b == b'\"'
                || b == b'\''
                || b == b'\\'
        })
        && !matches!(interface, "." | "..")
        && crate::ip::unicast(address)
        && prefix.is_none_or(|p| crate::ip::network(address, p).is_some())
        && match (backend, next_hop_mac) {
            (Backend::Tun, None) => true,
            (Backend::AfPacket, Some(mac)) => mac != [0; 6] && mac[0] & 1 == 0,
            (Backend::AfPacket, None) => true,
            _ => false,
        }
}

// The next-hop resolution of one port (`io.*` or `port.<name>`) owning
// `own` on `prefix`: its gateway routes and static neighbors.
fn valid_resolution(
    backend: Backend,
    own: IpAddr,
    prefix: Option<u8>,
    next_hop_mac: Option<[u8; 6]>,
    gateways: &[(ntcp_host::path::IpPrefix, IpAddr)],
    neighbors: &[(IpAddr, [u8; 6])],
) -> bool {
    // A TUN device and a port with a fixed next-hop MAC forward
    // everything through that one next hop and resolve no IP next
    // hop: a gateway route on them could never carry traffic, so it
    // is refused here rather than turning its prefix into a black
    // hole. Static neighbors serve only an IPv4 port that resolves
    // its next hops (an IPv6 one uses Neighbor Discovery).
    let resolves = backend == Backend::AfPacket && next_hop_mac.is_none();
    // A resolving port owns its address on its configured subnet, which
    // is its on-link route; the kernel's addresses never stand in for it.
    if (resolves && prefix.is_none())
        || (!gateways.is_empty() && !resolves)
        || (!neighbors.is_empty() && !(resolves && own.is_ipv4()))
    {
        return false;
    }
    for (j, &(address, mac)) in neighbors.iter().enumerate() {
        let on_link =
            prefix.is_some_and(|p| crate::ip::network(address, p) == crate::ip::network(own, p));
        if !crate::ip::unicast(address)
            || !address.is_ipv4()
            || !on_link
            || address == own
            || crate::ip::network_or_broadcast(address, prefix.unwrap_or(32))
            || mac == [0; 6]
            || mac[0] & 1 != 0
            || neighbors[..j].iter().any(|(other, _)| *other == address)
        {
            return false;
        }
    }
    for (j, &(destination, next_hop)) in gateways.iter().enumerate() {
        // The next hop is a neighbor on this port's link: a
        // link-local address (scoped to the port) or an address of
        // the port's own prefix other than the port's.
        let on_link = crate::ip::link_local(next_hop)
            || prefix.is_some_and(|p| {
                crate::ip::global_unicast(next_hop)
                    && crate::ip::network(next_hop, p) == crate::ip::network(own, p)
            });
        if destination.network().is_ipv4() != own.is_ipv4()
            || next_hop.is_ipv4() != own.is_ipv4()
            || !on_link
            || next_hop == own
            || gateways[..j].iter().any(|(other, _)| *other == destination)
            // Without ARP an IPv4 gateway is reachable only through
            // its static neighbor.
            || (next_hop.is_ipv4()
                && !neighbors.iter().any(|(address, _)| *address == next_hop))
        {
            return false;
        }
    }
    true
}

fn mac(value: &str) -> io::Result<[u8; 6]> {
    let mut mac = [0; 6];
    let fields: Vec<_> = value.split(':').collect();
    if fields.len() != 6 {
        return Err(invalid());
    }
    for (byte, field) in mac.iter_mut().zip(fields) {
        if field.len() != 2 || !field.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid());
        }
        *byte = u8::from_str_radix(field, 16).map_err(|_| invalid())?;
    }
    Ok(mac)
}

fn number<T: std::str::FromStr>(value: &str) -> io::Result<T> {
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    value.parse().map_err(|_| invalid())
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
