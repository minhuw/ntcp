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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketConfig {
    pub backend: Backend,
    pub interface: String,
    pub address: Ipv4Addr,
    pub prefix: Option<u8>,
    pub next_hop_mac: Option<[u8; 6]>,
    pub pacing: bool,
    pub pacing_gain_percent: Option<u16>,
    pub pacing_max_bytes_per_second: Option<u64>,
    pub pacing_burst_segments: Option<u32>,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid socket configuration")
}

impl SocketConfig {
    pub fn new(interface: impl Into<String>, address: Ipv4Addr) -> Self {
        Self {
            backend: Backend::Tun,
            interface: interface.into(),
            address,
            prefix: None,
            next_hop_mac: None,
            pacing: false,
            pacing_gain_percent: None,
            pacing_max_bytes_per_second: None,
            pacing_burst_segments: None,
        }
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.interface.is_empty()
            || self.interface.len() >= libc::IFNAMSIZ
            || self.interface.bytes().any(|b| {
                b == 0
                    || b.is_ascii_whitespace()
                    || b == b'/'
                    || b == b':'
                    || b == b'\"'
                    || b == b'\''
                    || b == b'\\'
            })
            || matches!(self.interface.as_str(), "." | "..")
            || self.address.octets()[0] == 0
            || self.address.octets()[0] >= 224
            || self.address.is_loopback()
            || self.prefix.is_some_and(|p| p > 32)
        {
            return Err(invalid());
        }
        match (self.backend, self.next_hop_mac) {
            (Backend::Tun, None) => {}
            (Backend::AfPacket, Some(mac)) if mac != [0; 6] && mac[0] & 1 == 0 => {}
            _ => return Err(invalid()),
        }
        if (!self.pacing
            && (self.pacing_gain_percent.is_some()
                || self.pacing_max_bytes_per_second.is_some()
                || self.pacing_burst_segments.is_some()))
            || self.pacing_gain_percent == Some(0)
            || self.pacing_max_bytes_per_second == Some(0)
            || self
                .pacing_burst_segments
                .is_some_and(|n| n == 0 || n.checked_mul(u32::from(MSS)).is_none())
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn pacing_config(&self) -> Option<ntcp::PacingConfig> {
        self.pacing.then(|| {
            let defaults = ntcp::PacingConfig::default();
            ntcp::PacingConfig {
                rate_gain_percent: self
                    .pacing_gain_percent
                    .unwrap_or(defaults.rate_gain_percent),
                max_bytes_per_second: self.pacing_max_bytes_per_second,
                max_burst_segments: self
                    .pacing_burst_segments
                    .unwrap_or(defaults.max_burst_segments),
            }
        })
    }

    pub fn parse(text: &str) -> io::Result<Self> {
        if text.len() > MAX_FILE_BYTES {
            return Err(invalid());
        }
        let mut config = Self::new("", Ipv4Addr::UNSPECIFIED);
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
                "backend" => {
                    config.backend = match value {
                        "tun" => Backend::Tun,
                        "af-packet" => Backend::AfPacket,
                        _ => return Err(invalid()),
                    }
                }
                "interface" => config.interface = value.into(),
                "address" => config.address = value.parse().map_err(|_| invalid())?,
                "prefix" => config.prefix = Some(number(value)?),
                "next_hop_mac" => {
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
                    config.next_hop_mac = Some(mac);
                }
                "pacing" => {
                    config.pacing = match value {
                        "true" => true,
                        "false" => false,
                        _ => return Err(invalid()),
                    }
                }
                "pacing_gain_percent" => config.pacing_gain_percent = Some(number(value)?),
                "pacing_max_bytes_per_second" => {
                    config.pacing_max_bytes_per_second = Some(number(value)?)
                }
                "pacing_burst_segments" => config.pacing_burst_segments = Some(number(value)?),
                _ => return Err(invalid()),
            }
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

fn number<T: std::str::FromStr>(value: &str) -> io::Result<T> {
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    value.parse().map_err(|_| invalid())
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
