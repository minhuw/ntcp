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
    pub io: IoConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoConfig {
    pub backend: Backend,
    pub interface: String,
    pub address: Ipv4Addr,
    pub prefix: Option<u8>,
    pub next_hop_mac: Option<[u8; 6]>,
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
            io: IoConfig {
                backend: Backend::Tun,
                interface: interface.into(),
                address,
                prefix: None,
                next_hop_mac: None,
            },
        }
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.io.interface.is_empty()
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
            match key {
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
        if tuned && !pacing_enabled {
            return Err(invalid());
        }
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
