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
    /// The configured key's original lease: `CLOCK_BOOTTIME` microseconds of
    /// the boot `fast_open_key_boot_id` names (`socket.fast_open_key_not_before_us`,
    /// `issue_until_us`, `accept_until_us`). A restarted process configured
    /// with the same key and lease keeps these deadlines: nothing renews.
    pub fast_open_key_lease: Option<ntcp::FastOpenKeyLease>,
    /// `socket.fast_open_key_boot_id`: the boot every configured lease
    /// belongs to, required with a lease. Another boot's numbers mean nothing
    /// on this one, so such a configuration is refused.
    pub fast_open_key_boot_id: Option<ntcp_clock::BootId>,
    /// `socket.fast_open_key.<name>`: further raw keys, each with its own
    /// lease, that setsockopt(TCP_FASTOPEN_KEY) may select. Rotation is
    /// operator configuration: a key configured nowhere is EINVAL.
    #[cfg(feature = "tfo-linux-cookie")]
    pub fast_open_keys: Vec<ConfiguredFastOpenKey>,
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

/// One raw key and its original lease.
#[cfg(feature = "tfo-linux-cookie")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfiguredFastOpenKey {
    pub key: ntcp::LinuxSipHash24Key,
    pub lease: ntcp::FastOpenKeyLease,
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
}

impl IoConfig {
    /// An AF_PACKET port without `next_hop_mac`: it resolves its next hops.
    pub(crate) fn resolves(&self) -> bool {
        self.backend == Backend::AfPacket && self.next_hop_mac.is_none()
    }
}

// The endpoint's connections, listeners and control packets unless
// configured (`tcp.max_connections`, `tcp.max_listeners`).
pub(crate) const DEFAULT_CONNECTIONS: usize = 512;
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid socket configuration")
}

impl SocketConfig {
    pub fn new(interface: impl Into<String>, address: impl Into<IpAddr>) -> Self {
        let address = address.into();
        let mut tcp = ntcp::EndpointConfig {
            max_connections: DEFAULT_CONNECTIONS,
            max_listeners: DEFAULT_CONNECTIONS,
            max_control_packets: DEFAULT_CONNECTIONS,
            max_buffer_bytes: 128 * 1024 * 1024,
            ..ntcp::EndpointConfig::default()
        };
        tcp.connection.receive_capacity = crate::runtime::BYTES;
        tcp.connection.send_capacity = crate::runtime::BYTES;
        // Autotuning as ntcp-native's NetworkConfig::new: receive 4 KiB,
        // 64 KiB and 32 MiB, Linux master's tcp_rmem[2] (net/ipv4/tcp.c
        // tcp_init), which also gives the SYN a window scale of 10; send
        // 4 KiB, 64 KiB and 4 MiB, tcp_wmem[2]. These are window and
        // payload bytes: Linux's tcp_rmem[1] of 128 KiB of memory offers a
        // 64 KiB window. SO_RCVBUF and SO_SNDBUF lock a socket's size
        // (`tcp.rmem` and `tcp.wmem` change all three).
        tcp.connection.receive_capacity_max = 32 << 20;
        tcp.connection.send_capacity_max = 4 << 20;
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
            fast_open_key_boot_id: None,
            #[cfg(feature = "tfo-linux-cookie")]
            fast_open_keys: Vec::new(),
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
            },
        }
    }

    pub(crate) fn fast_open_keys_managed(&self) -> io::Result<bool> {
        let generated = matches!(
            self.fast_open_cookie_policy,
            ntcp::FastOpenCookiePolicy::HmacSha256
        );
        let managed = self.fast_open_managed_keys.unwrap_or(generated);
        // A managed key has the lifetime the stack gives it; an external key
        // is accepted only with its original lease.
        if (managed && self.fast_open_key_lease.is_some())
            || (!managed && !generated && self.fast_open_key_lease.is_none())
        {
            return Err(invalid());
        }
        Ok(managed)
    }

    // Whether anything configured here is a lease of a named boot.
    fn leased(&self) -> bool {
        #[cfg(feature = "tfo-linux-cookie")]
        if !self.fast_open_keys.is_empty() {
            return true;
        }
        self.fast_open_key_lease.is_some()
    }

    // The provider is read only when a lease needs it.
    fn validate_fast_open_leases(&self) -> io::Result<()> {
        if !self.leased() {
            return if self.fast_open_key_boot_id.is_some() {
                Err(invalid())
            } else {
                Ok(())
            };
        }
        let failed = |error: ntcp_clock::TransportError| {
            io::Error::other(format!("Fast Open key lease: {error}"))
        };
        let mut clock = ntcp_clock::TransportClock::new().map_err(failed)?;
        let now = clock.sample().map_err(failed)?.ticks;
        self.check_fast_open_leases(clock.characterization().boot_id, now)
    }

    // Leases against the running boot and its `CLOCK_BOOTTIME` microseconds.
    // Any expired one is refused. The primary key is installed at startup, so
    // it must have begun; a further key may be waiting for its `not_before`.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-3
    //= reason=Actual IPv4/IPv6 endpoints repeatedly reuse credentials before expiry, reject expired SYN data at admission and complete ordinary TCP byte delivery with fresh-cookie learning or no-cookie fallback. HMAC keeps current/previous epochs; LinuxSipHash24 keeps raw bytes under finite key leases. Raw epoch-independent codec vectors are not server acceptance evidence. External raw keys are accepted only with their original lease in CLOCK_BOOTTIME microseconds of the boot socket.fast_open_key_boot_id names: another boot's lease, an expired lease or an external key without one is refused at configuration, a restarted process reinstalling the same key keeps the original deadlines, and setsockopt(TCP_FASTOPEN_KEY) selects only a configured key under its lease. HMAC keys are per-process secrets whose epochs derive from transport time.
    //# 5. The rest of the connection proceeds like a normal TCP connection. The
    //# client can repeat many Fast Open operations once it acquires a cookie
    //# (until the cookie is expired by the server).
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
    //= reason=Endpoint admission enforces finite HMAC current/previous epochs and LinuxSipHash24 key leases with absolute issue/accept deadlines, including delayed service, retiring keys and same-key no-renewal through the endpoint-owned identity registry across arbitrary key cycles, policy clearing, listener generations, cross-listener reuse and native pre-listen staging. Raw Linux validation intentionally ignores epoch, including u64::MAX, to preserve wire bytes; that raw codec result is not server acceptance. External raw keys are accepted only with their original lease in CLOCK_BOOTTIME microseconds of the boot socket.fast_open_key_boot_id names: another boot's lease, an expired lease or an external key without one is refused at configuration, a restarted process reinstalling the same key keeps the original deadlines, and setsockopt(TCP_FASTOPEN_KEY) selects only a configured key under its lease. HMAC keys are per-process secrets whose epochs derive from transport time.
    //# 5. The cookie expires after a certain amount of time. The reason for
    //# cookie expiration is detailed in the "Security Considerations" section
    //# (Section 5). This can be done by either periodically changing the server
    //# key used to generate cookies or including a timestamp when generating
    //# the cookie.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
    //= reason=Passive admission authenticates both address families using current/retiring bounded key contexts consulting one endpoint-owned identity/deadline registry, finite HMAC epochs and LinuxSipHash24 leases. Traffic tests reject expired and invalid credentials exactly at deadlines and complete fallback; raw Linux epoch-independent codec validation alone is not server acceptance. External raw keys are accepted only with their original lease in CLOCK_BOOTTIME microseconds of the boot socket.fast_open_key_boot_id names: another boot's lease, an expired lease or an external key without one is refused at configuration, a restarted process reinstalling the same key keeps the original deadlines, and setsockopt(TCP_FASTOPEN_KEY) selects only a configured key under its lease. HMAC keys are per-process secrets whose epochs derive from transport time.
    //# - IsCookieValid(IP_Address, Cookie): checks if the cookie is valid,
    //# i.e., it has not expired and the cookie authenticates the client IP
    //# address.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
    //= reason=Repeated Fast Open, manual key revocation, finite HMAC epochs and LinuxSipHash24 key leases are exercised through actual endpoints in both IP families. Admission checks issue/accept deadlines without timer service; expired and invalid credentials complete ordinary TCP, fresh keys teach usable replacements, and same-key reinstalls cannot renew expired leases in the endpoint authority across arbitrary key cycles, policy clearing, listener generations, cross-listener reuse and native pre-listen staging. Raw Linux epoch-independent codec tests are not server acceptance. External raw keys are accepted only with their original lease in CLOCK_BOOTTIME microseconds of the boot socket.fast_open_key_boot_id names: another boot's lease, an expired lease or an external key without one is refused at configuration, a restarted process reinstalling the same key keeps the original deadlines, and setsockopt(TCP_FASTOPEN_KEY) selects only a configured key under its lease. HMAC keys are per-process secrets whose epochs derive from transport time.
    //# Once the client obtains the cookie from the target server, it can
    //# perform subsequent TFO connections until the cookie is expired by the
    //# server.
    pub(crate) fn check_fast_open_leases(
        &self,
        boot_id: ntcp_clock::BootId,
        now: u64,
    ) -> io::Result<()> {
        if self.fast_open_key_boot_id != Some(boot_id) {
            return Err(invalid());
        }
        let timebase = self.tcp.connection.timebase;
        if let Some(lease) = self.fast_open_key_lease
            && (now >= lease.accept_until || lease.validate(now, timebase).is_err())
        {
            return Err(invalid());
        }
        #[cfg(feature = "tfo-linux-cookie")]
        for (i, configured) in self.fast_open_keys.iter().enumerate() {
            let lease = configured.lease;
            let primary = matches!(
                &self.fast_open_cookie_policy,
                ntcp::FastOpenCookiePolicy::LinuxSipHash24(key) if *key == configured.key
            );
            // One key has one lease.
            if primary
                || self.fast_open_keys[..i].iter().any(|other| other.key == configured.key)
                || now >= lease.accept_until
                || lease.validate(lease.not_before, timebase).is_err()
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> io::Result<()> {
        self.fast_open_keys_managed()?;
        self.validate_fast_open_leases()?;
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
        #[cfg(feature = "tfo-linux-cookie")]
        let mut keys: Vec<(&str, KeyFields)> = Vec::new();
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
            #[cfg(feature = "tfo-linux-cookie")]
            if let Some(rest) = key.strip_prefix("socket.fast_open_key.") {
                let (name, field) = rest
                    .split_once('.')
                    .map_or((rest, None), |(name, field)| (name, Some(field)));
                if !valid_name(name) {
                    return Err(invalid());
                }
                let index = match keys.iter().position(|(n, _)| *n == name) {
                    Some(index) => index,
                    None => {
                        keys.push((name, KeyFields::default()));
                        keys.len() - 1
                    }
                };
                let fields = &mut keys[index].1;
                match field {
                    None => fields.key = Some(raw_key(value)?),
                    Some("not_before_us") => fields.lease.not_before = number(value)?,
                    Some("issue_until_us") => fields.lease.issue_until = number(value)?,
                    Some("accept_until_us") => fields.lease.accept_until = number(value)?,
                    _ => return Err(invalid()),
                }
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
                    let lease = config.fast_open_key_lease.get_or_insert(EMPTY_LEASE);
                    match key {
                        "socket.fast_open_key_not_before_us" => lease.not_before = number(value)?,
                        "socket.fast_open_key_issue_until_us" => lease.issue_until = number(value)?,
                        _ => lease.accept_until = number(value)?,
                    }
                }
                "socket.fast_open_key_boot_id" => {
                    config.fast_open_key_boot_id =
                        Some(ntcp_clock::BootId::parse(value).ok_or_else(invalid)?);
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
                // The endpoint's connections and listeners, which bound
                // the runtime's (`lib.rs`, Limits).
                "tcp.max_connections" => config.tcp.max_connections = number(value)?,
                "tcp.max_listeners" => config.tcp.max_listeners = number(value)?,
                // Linux's tcp_wmem and tcp_rmem, "min initial max", and
                // tcp_mem, "low pressure high" in bytes where Linux counts
                // pages. tcp.wmem and tcp.rmem are ntcp's sizes, payload
                // and window bytes, not Linux's memory: they are the
                // core's BufferSizes, as ntcp-native's, and the receive
                // max serves two roles no one conversion keeps, the window
                // scale, which tcp_select_initial_window takes from the
                // unconverted tcp_rmem[2], and the ceiling DRS grows the
                // window to, tcp_win_from_space(tcp_rmem[2]). Linux's
                // tcp_rmem "a b c" is about tcp.rmem "a/2 b/2 c"
                // (SO_RCVBUF converts in runtime.rs,
                // buffer_size_from_memory); tcp_wmem's payload is about
                // its memory, tcp_sndbuf_expand aside.
                "tcp.wmem" => config
                    .tcp
                    .connection
                    .set_send_buffer(buffer_sizes(value)?)
                    .map_err(|_| invalid())?,
                "tcp.rmem" => config
                    .tcp
                    .connection
                    .set_receive_buffer(buffer_sizes(value)?)
                    .map_err(|_| invalid())?,
                "tcp.mem" => {
                    let [low, pressure, high] = triple(value)?;
                    config.tcp.max_buffer_bytes = high;
                    config.tcp.buffer_pressure_bytes = Some(pressure);
                    config.tcp.buffer_low_bytes = Some(low);
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
                ntcp::FastOpenCookiePolicy::LinuxSipHash24(raw_key(key)?)
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
        #[cfg(feature = "tfo-linux-cookie")]
        for (_, fields) in keys {
            config.fast_open_keys.push(ConfiguredFastOpenKey {
                key: fields.key.ok_or_else(invalid)?,
                lease: fields.lease,
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

// A lease being parsed: an absent deadline stays zero, which validation refuses
// unless the deadlines around it are a valid lease from the boot's start.
const EMPTY_LEASE: ntcp::FastOpenKeyLease = ntcp::FastOpenKeyLease {
    not_before: 0,
    issue_until: 0,
    accept_until: 0,
    units_per_second: 1_000_000,
};

// The `socket.fast_open_key.<name>*` fields as they are parsed.
#[cfg(feature = "tfo-linux-cookie")]
struct KeyFields {
    key: Option<ntcp::LinuxSipHash24Key>,
    lease: ntcp::FastOpenKeyLease,
}

#[cfg(feature = "tfo-linux-cookie")]
impl Default for KeyFields {
    fn default() -> Self {
        Self {
            key: None,
            lease: EMPTY_LEASE,
        }
    }
}

// Sixteen raw key bytes in hexadecimal, never a seed.
#[cfg(feature = "tfo-linux-cookie")]
fn raw_key(text: &str) -> io::Result<ntcp::LinuxSipHash24Key> {
    if text.len() != 32 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let mut bytes = [0; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(|_| invalid())?;
    }
    Ok(ntcp::LinuxSipHash24Key::new(bytes))
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

// Three numbers separated by whitespace, as the sysctls print them.
fn triple(value: &str) -> io::Result<[usize; 3]> {
    let mut fields = value.split_ascii_whitespace();
    let mut triple = [0; 3];
    for field in &mut triple {
        *field = number(fields.next().ok_or_else(invalid)?)?;
    }
    if fields.next().is_some() {
        return Err(invalid());
    }
    Ok(triple)
}

fn buffer_sizes(value: &str) -> io::Result<ntcp::BufferSizes> {
    let [min, initial, max] = triple(value)?;
    Ok(ntcp::BufferSizes { min, initial, max })
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
