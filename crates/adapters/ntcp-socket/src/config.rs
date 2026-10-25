// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::{self, Read},
    net::Ipv4Addr,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

const MAX_FILE_BYTES: usize = 64 * 1024;
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
    pub io: IoConfig,
    pub routes: Vec<(Ipv4Addr, ntcp::RoutePolicy)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketPolicy {
    pub notsent_lowat: u32,
    pub fast_open_client_enabled: bool,
}

impl Default for SocketPolicy {
    fn default() -> Self {
        Self {
            notsent_lowat: u32::MAX,
            fast_open_client_enabled: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoConfig {
    pub backend: Backend,
    pub interface: String,
    pub address: Ipv4Addr,
    pub prefix: Option<u8>,
    pub next_hop_mac: Option<[u8; 6]>,
    pub output_reservation_timeout_ms: u32,
    pub egress_capacity: usize,
    pub gso: Option<ntcp::GsoLimits>,
    pub receive_aggregation: bool,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid socket configuration")
}

impl SocketConfig {
    pub fn new(interface: impl Into<String>, address: Ipv4Addr) -> Self {
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
        tcp.connection.send_ip_payload_limit = 1480;
        tcp.connection.receive_ip_payload_limit = 65515;
        Self {
            tcp,
            socket: SocketPolicy::default(),
            fast_open_cookie_policy: ntcp::FastOpenCookiePolicy::default(),
            routes: Vec::new(),
            io: IoConfig {
                backend: Backend::Tun,
                interface: interface.into(),
                address,
                prefix: None,
                next_hop_mac: None,
                output_reservation_timeout_ms: 1000,
                egress_capacity: crate::runtime::BUDGET,
                gso: None,
                receive_aggregation: false,
            },
        }
    }

    pub fn validate(&self) -> io::Result<()> {
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
            || self.io.interface.is_empty()
            || self.io.interface.len() >= libc::IFNAMSIZ
            || self.io.interface.bytes().any(|b| {
                b == 0
                    || b.is_ascii_whitespace()
                    || b == b'/'
                    || b == b':'
                    || b == b'\"'
                    || b == b'\''
                    || b == b'\\'
            })
            || matches!(self.io.interface.as_str(), "." | "..")
            || self.io.address.octets()[0] == 0
            || self.io.address.octets()[0] >= 224
            || self.io.address.is_loopback()
            || self.io.prefix.is_some_and(|p| p > 32)
        {
            return Err(invalid());
        }
        match (self.io.backend, self.io.next_hop_mac) {
            (Backend::Tun, None) => {}
            (Backend::AfPacket, Some(mac)) if mac != [0; 6] && mac[0] & 1 == 0 => {}
            _ => return Err(invalid()),
        }
        // Before IO opens, validate against configured allocation ceilings.
        // Backend startup repeats policy validation with the actual interface MTU.
        let mut route_defaults = self.tcp.connection.clone();
        let bound = (u32::from(route_defaults.send_ip_payload_limit) + 20).min(65535);
        route_defaults
            .pmtud
            .get_or_insert(ntcp::PmtudConfig::new(bound));
        if self.routes.len() > self.tcp.max_route_policies {
            return Err(invalid());
        }
        for (i, (destination, policy)) in self.routes.iter().enumerate() {
            if destination.is_loopback()
                || destination.octets()[0] == 0
                || destination.octets()[0] >= 224
                || self.routes[..i]
                    .iter()
                    .any(|(other, _)| other == destination)
            {
                return Err(invalid());
            }
            policy
                .validate(&route_defaults, true)
                .map_err(|_| invalid())?;
        }
        self.tcp.validate().map_err(|_| invalid())?;
        let c = &self.tcp.connection;
        c.validate(true).map_err(|_| invalid())?;
        // The owner clock, IPv4 packet size and descriptor registry are adapter constraints.
        if self.tcp.ipv4_options_enabled // Native input strips/rejects IPv4 options.
            || c.timebase.units_per_second != 1_000_000
            || c.send_ip_payload_limit > 65515
            || c.receive_ip_payload_limit > 65515
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
        let mut seen = BTreeSet::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(invalid)?;
            let (key, value) = (key.trim(), value.trim());
            if !seen.insert(key) || value.is_empty() {
                return Err(invalid());
            }
            if let Some(route) = key.strip_prefix("route.") {
                let (address, field) = route.rsplit_once('.').ok_or_else(invalid)?;
                let address: Ipv4Addr = address.parse().map_err(|_| invalid())?;
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
                "socket.fast_open_cookie" => cookie_mode = value,
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
                "io.next_hop_mac" => {
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
                    config.io.next_hop_mac = Some(mac);
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
                "tcp.pacing_burst_segments" => {
                    pacing.max_burst_segments = number(value)?;
                    tuned = true;
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

fn number<T: std::str::FromStr>(value: &str) -> io::Result<T> {
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    value.parse().map_err(|_| invalid())
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
