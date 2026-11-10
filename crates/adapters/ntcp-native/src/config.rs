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
    /// Fragmented datagrams under reassembly at once, 64 by default, as a
    /// host reassembles (RFC 1122 section 3.3.2 makes it a MUST); 0 opts
    /// out and discards every fragment.
    ///
    /// Each datagram may be as large as the larger of the MTU and its
    /// family's required minimum (576 octets for IPv4, 1500 for IPv6): the
    /// TCP MSS this Network offers follows the MTU, so a conforming peer
    /// sends nothing larger, and a smaller limit would lower that offer.
    /// Each costs about four times the larger of the MTU and 1500 octets
    /// (the Host backs both families' minimums), allocated with the
    /// Network: its octets and the descriptors of its worst conforming
    /// fragmentation (8-octet fragments). The default costs about 400 KB
    /// at an MTU of 1500 and grows with the MTU.
    ///
    /// Size it for the datagrams whose fragments can arrive interleaved. A
    /// fragment refused for room leaves the rest of its datagram holding a
    /// slot until the timeout, 30 seconds after an IPv4 datagram's first
    /// fragment and 60 after an IPv6 one's; this Network sends no ICMP, so
    /// no Time Exceeded follows.
    /// `Network::reassembly_counters` reports every completion and discard.
    pub reassembly_datagrams: usize,
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
    /// A Network's configuration with Linux's TCP defaults, where
    /// `EndpointConfig::default` keeps the RFC baseline that conformance
    /// profiles build on:
    /// - SACK, RACK and tail loss probes (tcp_sack, tcp_recovery);
    /// - timestamps (tcp_timestamps), in milliseconds;
    /// - ECN answered when the peer asks, never asked for (tcp_ecn=2);
    /// - a 10-segment initial window (RFC 6928, Linux's TCP_INIT_CWND);
    /// - CUBIC with HyStart and fast convergence (tcp_congestion_control);
    /// - Proportional Rate Reduction in fast recovery, unpaced, as Linux
    ///   recovers without fq;
    /// - a 200 ms floor under the sampled retransmission timeout
    ///   (TCP_RTO_MIN, below RFC 6298 section 2.4's 1 s SHOULD);
    /// - delayed ACKs that adapt between 40 and 200 ms to the peer's sending
    ///   (TCP_ATO_MIN, TCP_DELACK_MAX).
    ///
    /// Each remains a field of `tcp.connection` to change.
    pub fn new(local_address: IpAddr, mtu: u32) -> Self {
        let mut tcp = EndpointConfig::default();
        let connection = &mut tcp.connection;
        connection.sack = true;
        connection.rack = true;
        connection.tlp = true;
        connection.timestamps = true;
        connection.ecn = true;
        connection.ecn_initiate = false;
        connection.initial_window = ntcp::InitialWindow::Iw10;
        connection.congestion_algorithm = ntcp::CongestionAlgorithm::Cubic;
        connection.cubic_hystart = true;
        connection.cubic_fast_convergence = true;
        connection.prr = true;
        connection.prr_pacing = false;
        connection.rto_min_us = 200_000;
        connection.adaptive_ack = true;
        connection.delayed_ack_us = 200_000;
        Self {
            local_address,
            mtu,
            tcp,
            link: Link::Ip,
            // IANA's dynamic/private port range; callers partition it per worker.
            ephemeral_ports: 49152..=65535,
            tx_timestamp_phases: 0,
            rx_timestamp_ranges: 0,
            timestamp_clock_capacity: 2,
            retained_receive_packets: None,
            neighbor_entries: 16,
            static_neighbors: Vec::new(),
            reassembly_datagrams: 64,
        }
    }
    // The Host's reassembly of `reassembly_datagrams` datagrams, each up to
    // the larger of the MTU and its family's required minimum, held whole
    // at once, with
    // descriptors for 8-octet fragments of the larger family's datagram
    // (an IPv6 first fragment also stores its Fragment header). The IPv4
    // timeout is Linux's ipfrag_time, 30 seconds, below RFC 1122 section
    // 3.3.2's recommended 60 to 120: a datagram's fragments leave its
    // sender together, so a shorter hold seldom discards one that would
    // have completed, and it frees the slots that lost fragments pin
    // sooner. IPv6 keeps RFC 8200's 60 seconds.
    // None if the storage exceeds what the Host addresses.
    pub(crate) fn reassembly(&self) -> Option<ntcp_host::ReassemblyLimits> {
        let datagrams = self.reassembly_datagrams;
        if datagrams == 0 {
            return Some(ntcp_host::ReassemblyLimits::default());
        }
        let mtu = self.mtu as usize;
        let ipv6_datagram = mtu.clamp(1500, 65575);
        let buffered_bytes = datagrams
            .checked_mul(ipv6_datagram + 8)
            .filter(|&n| n <= u32::MAX as usize)?;
        Some(ntcp_host::ReassemblyLimits {
            assemblies: datagrams,
            fragments: ipv6_datagram.div_ceil(8),
            buffered_bytes,
            ipv4_datagram: mtu.clamp(576, 65535),
            ipv6_datagram,
            ipv4_timeout_seconds: 30,
        })
    }
    // The largest IP datagram this Network takes in: a packet of the MTU,
    // or a reassembled datagram of the local family.
    pub(crate) fn datagram_capacity(&self) -> usize {
        self.reassembly()
            .and_then(|r| r.datagram_capacity(self.local_address.is_ipv6()))
            .map_or(self.mtu as usize, |n| n.max(self.mtu as usize))
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
        if self.reassembly().is_none() {
            return Err(Error::InvalidConfig(
                "reassembly datagrams beyond host storage",
            ));
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
