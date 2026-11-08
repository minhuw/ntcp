use crate::{EndpointConfig, Error, Result};
use ntcp_io::{PacketIo, PacketLayer};
use std::{
    net::{IpAddr, Ipv4Addr},
    ops::RangeInclusive,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Link {
    Ip,
    Ethernet {
        local_mac: [u8; 6],
        next_hop: EthernetNextHop,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EthernetNextHop {
    // The embedding supplies a fixed next hop; this interface does not run ARP.
    Fixed([u8; 6]),
    // IPv4 next hops are resolved by ARP: destinations inside the local
    // address's prefix are on-link, others leave through the gateway.
    Arp {
        prefix_len: u8,
        gateway: Option<Ipv4Addr>,
    },
}
impl Link {
    pub(crate) fn offset(self) -> usize {
        if self == Self::Ip { 0 } else { 14 }
    }
}

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub local_address: IpAddr,
    pub mtu: u32,
    pub tcp: EndpointConfig,
    pub link: Link,
    pub ephemeral_ports: RangeInclusive<u16>,
    pub tx_timestamp_phases: usize,
    pub rx_timestamp_ranges: usize,
    // A packet can carry independent software and hardware RX clocks.
    pub timestamp_clock_capacity: usize,
    // None derives one receive-retention slot per output owner.
    pub retained_receive_packets: Option<usize>,
    // Dynamic ARP entries of an EthernetNextHop::Arp link.
    pub neighbor_entries: usize,
    // Permanent ARP entries; only valid with EthernetNextHop::Arp.
    pub static_neighbors: Vec<(Ipv4Addr, [u8; 6])>,
}
impl NetworkConfig {
    /// The `tcp.max_buffer_bytes` a Network with this configuration needs
    /// to hold `connections` connections at once: its output reservations,
    /// one per connection slot and one for stateless replies, and each
    /// connection's buffers and timestamp records. None if it overflows.
    pub fn buffer_budget(&self, connections: usize) -> Option<usize> {
        let reservations = self.tcp.max_connections.checked_add(1)?;
        self.tcp
            .connection_charge(self.tx_timestamp_phases, self.rx_timestamp_ranges)?
            .checked_mul(connections)?
            .checked_add(self.tcp.output_reservations_charge(reservations, None)?)
    }
    pub fn new(local_address: IpAddr, mtu: u32) -> Self {
        Self {
            local_address,
            mtu,
            tcp: EndpointConfig::default(),
            link: Link::Ip,
            // IANA's dynamic/private port range; callers partition it per worker.
            ephemeral_ports: 49152..=65535,
            tx_timestamp_phases: 0,
            rx_timestamp_ranges: 0,
            timestamp_clock_capacity: 2,
            retained_receive_packets: None,
            neighbor_entries: 16,
            static_neighbors: Vec::new(),
        }
    }
    // The resolved link's on-link prefix and gateway.
    pub(crate) fn arp(&self) -> Option<(Ipv4Addr, u8, Option<Ipv4Addr>)> {
        match (self.link, self.local_address) {
            (
                Link::Ethernet {
                    next_hop:
                        EthernetNextHop::Arp {
                            prefix_len,
                            gateway,
                        },
                    ..
                },
                IpAddr::V4(local),
            ) => Some((local, prefix_len, gateway)),
            _ => None,
        }
    }
    pub(crate) fn validate(&self, io: &impl PacketIo) -> Result<()> {
        self.tcp.validate()?;
        if self.local_address.is_unspecified()
            || self.local_address.is_multicast()
            || matches!(self.local_address, IpAddr::V4(a) if a.is_broadcast())
            || self.local_address.is_loopback()
        {
            return Err(Error::InvalidConfig(
                "an explicitly owned unicast address is required",
            ));
        }
        if self.mtu
            < if self.local_address.is_ipv4() {
                68
            } else {
                1280
            }
            || self.mtu > 65535
            || *self.ephemeral_ports.start() == 0
            || self.ephemeral_ports.is_empty()
            || self.retained_receive_packets == Some(0)
        {
            return Err(Error::InvalidConfig("MTU, port range or receive capacity"));
        }
        match (self.link, io.layer()) {
            (Link::Ip, PacketLayer::Ip) => {}
            (
                Link::Ethernet {
                    local_mac,
                    next_hop: EthernetNextHop::Fixed(next_hop_mac),
                },
                PacketLayer::Ethernet,
            ) if valid_mac(local_mac) && valid_mac(next_hop_mac) => {}
            (
                Link::Ethernet {
                    local_mac,
                    next_hop: EthernetNextHop::Arp { .. },
                },
                PacketLayer::Ethernet,
            ) if valid_mac(local_mac) => self.validate_arp()?,
            _ => {
                return Err(Error::InvalidConfig(
                    "link configuration does not match the backend",
                ));
            }
        }
        if !self.static_neighbors.is_empty() && self.arp().is_none() {
            return Err(Error::InvalidConfig(
                "static neighbors need an ARP-resolved link",
            ));
        }
        if io.max_packet_len().is_some_and(|n| {
            n < (self.mtu as usize + self.link.offset()).max(if self.link == Link::Ip {
                0
            } else {
                60
            })
        }) {
            return Err(Error::InvalidConfig(
                "backend frame capacity is below the configured MTU",
            ));
        }
        Ok(())
    }
}
// An address of the local prefix that names one station: neither the
// prefix's own (all-zero host part) nor its broadcast address, where the
// prefix has those (RFC 3021: none at /31 and /32).
fn station(address: Ipv4Addr, local: Ipv4Addr, prefix_len: u8) -> bool {
    let mask = u32::MAX
        .checked_shl(32 - u32::from(prefix_len))
        .unwrap_or(0);
    let host = u32::from(address) & !mask;
    u32::from(address) & mask == u32::from(local) & mask
        && !address.is_broadcast()
        && !address.is_multicast()
        && !address.is_unspecified()
        && !address.is_loopback()
        && (prefix_len >= 31 || (host != 0 && host != !mask))
}
impl NetworkConfig {
    fn validate_arp(&self) -> Result<()> {
        let Some((local, prefix_len, gateway)) = self.arp() else {
            return Err(Error::InvalidConfig("ARP resolves IPv4 next hops only"));
        };
        if !(1..=32).contains(&prefix_len) || !station(local, local, prefix_len) {
            return Err(Error::InvalidConfig(
                "the local address is no station of its prefix",
            ));
        }
        if gateway.is_some_and(|g| g == local || !station(g, local, prefix_len)) {
            return Err(Error::InvalidConfig(
                "the gateway must be another on-link unicast address",
            ));
        }
        if self.neighbor_entries == 0 {
            return Err(Error::InvalidConfig("ARP needs neighbor entries"));
        }
        for (index, &(address, mac)) in self.static_neighbors.iter().enumerate() {
            if address == local
                || !station(address, local, prefix_len)
                || !valid_mac(mac)
                || self.static_neighbors[..index]
                    .iter()
                    .any(|(other, _)| *other == address)
            {
                return Err(Error::InvalidConfig(
                    "static neighbors need distinct on-link unicast addresses and MACs",
                ));
            }
        }
        Ok(())
    }
}
fn valid_mac(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}
