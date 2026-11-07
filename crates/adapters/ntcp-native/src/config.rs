use crate::{EndpointConfig, Error, Result};
use ntcp_io::{PacketIo, PacketLayer};
use std::{net::IpAddr, ops::RangeInclusive};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Link {
    Ip,
    // The embedding supplies a fixed next hop; this interface does not run ARP.
    Ethernet {
        local_mac: [u8; 6],
        next_hop_mac: [u8; 6],
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
    // What the caller knows about the host boot and earlier emission from
    // `local_address`, in its own clock's ticks. The default asserts nothing:
    // no TCP connection is admitted until 2*MSL after the network starts.
    pub lifecycle: ntcp::Lifecycle,
}
impl NetworkConfig {
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
            lifecycle: ntcp::Lifecycle::default(),
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
                    next_hop_mac,
                },
                PacketLayer::Ethernet,
            ) if valid_mac(local_mac) && valid_mac(next_hop_mac) => {}
            _ => {
                return Err(Error::InvalidConfig(
                    "link configuration does not match the backend",
                ));
            }
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
fn valid_mac(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}
