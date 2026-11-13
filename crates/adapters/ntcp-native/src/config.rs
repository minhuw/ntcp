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
    /// The local ports active opens without one choose from (Linux's
    /// ip_local_port_range). A port is shared by opens to distinct
    /// destinations, so the range bounds the connections, TIME-WAIT
    /// included, to each destination, not their number.
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
    /// Storage follows the fragments held: each one's octets and a
    /// descriptor are allocated when it arrives and freed when its datagram
    /// completes or is discarded, as Linux queues fragments. Their total is
    /// bounded by the octets of this many such datagrams (the larger of the
    /// MTU and 1500 octets: the Host backs both families' minimums) plus
    /// the descriptors of one cut into 8-octet fragments, the worst
    /// conforming fragmentation, which reassembly always admits. With the
    /// default that bound is about 100 KB at an MTU of 1500, 610 KB at 9000
    /// and 4.5 MB at 65535; a fragment beyond it is discarded.
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
    /// The smallest `tcp.max_buffer_bytes` with which a Network with this
    /// configuration on backend `io` admits `connections` connections at
    /// once: its output reservations, one per connection slot and one for
    /// stateless replies, each holding the TCP packet of one IP packet of
    /// the MTU, and each connection's charge at open
    /// (`EndpointConfig::connection_charge`), its receive ring, scratch
    /// segment, first ledger entries and timestamp records. None if it
    /// overflows. `buffer_budget(0, io)` is the reservations alone.
    ///
    /// It is a floor for the cap, not a cap to use: it leaves no room to
    /// write. A connection is charged what it allocates, so its first write
    /// adds a send ring of 2 bytes per byte of `send_capacity`, and its RACK
    /// and SACK ledgers grow with the bytes it holds queued (68 bytes per
    /// byte until they are kept per segment). A write whose storage the cap
    /// refuses takes what the connection's storage holds and then waits for
    /// memory, as Linux's: a partial write or `Error::WouldBlock`, the
    /// connection writable again once memory comes back
    /// (`Counters::memory_throttled_writes`). With `NetworkConfig::new`'s
    /// tuned buffers a send limit rises with the congestion window up to
    /// `send_capacity_max`, its ring and ledgers growing at write, and a
    /// receive ring grows at read, 1.375 bytes per byte of window up to
    /// `receive_capacity_max`; a growth the cap or memory pressure refuses
    /// leaves the window as it is (`Counters::memory_refused_growths`).
    ///
    /// On a backend that segments TCP aggregates
    /// (`PacketIo::tcp_segmentation_capabilities`, read here and when the
    /// Network is built, so a backend's segmentation is enabled first) each
    /// reservation also holds the payload of the largest aggregate, about
    /// 64 KiB on a DPDK port.
    pub fn buffer_budget(&self, connections: usize, io: &impl PacketIo) -> Option<usize> {
        let reservations = self.tcp.max_connections.checked_add(1)?;
        self.tcp
            .connection_charge(self.tx_timestamp_phases, self.rx_timestamp_ranges)?
            .checked_mul(connections)?
            .checked_add(self.tcp.output_reservations_charge(
                reservations,
                self.reservation_packet_bytes(),
                self.gso(io),
            )?)
    }
    /// The buffer memory thresholds Linux's tcp_init_mem (net/ipv4/tcp.c)
    /// gives a host whose free buffer memory is `memory_bytes`, as
    /// `(low, pressure, max)` in bytes, for `tcp.buffer_low_bytes`,
    /// `tcp.buffer_pressure_bytes` and `tcp.max_buffer_bytes`. In 4 KiB
    /// pages, limit = max(pages / 16, 128), and tcp_mem = {limit / 4 * 3,
    /// limit, (limit / 4 * 3) * 2}: about 4.7%, 6.25% and 9.4% of memory.
    /// Linux sizes it from nr_free_buffer_pages() at boot; pass the memory
    /// this Network, or its group of shared flows, may use.
    ///
    /// Unlike `buffer_budget`, which is the floor below which connections
    /// cannot even open, this is a cap with room for buffers to grow.
    pub fn memory_cap_for(memory_bytes: usize) -> (usize, usize, usize) {
        const PAGE: usize = 4096;
        let limit = (memory_bytes / PAGE / 16).max(128);
        let low = limit / 4 * 3;
        (low * PAGE, limit * PAGE, low * 2 * PAGE)
    }
    // The TCP packet an output reservation holds: the driver polls each
    // into its frame after the link and IP headers, so no packet it
    // encodes, the first segment of an aggregate included, is larger. An
    // aggregate's further payload has its own room (`gso`).
    pub(crate) fn reservation_packet_bytes(&self) -> usize {
        self.mtu as usize - if self.local_address.is_ipv4() { 20 } else { 40 }
    }
    // The output reservations of a backend that segments TCP aggregates, as
    // Linux hands a TSO device skbs of many segments whenever the device
    // offers it: each reservation selects at most the payload of the
    // largest aggregate, after the link, IP and TCP headers of its frame,
    // and the backend's segments. None without segmentation, or when an
    // aggregate cannot carry two segments of the MTU's size (a DPDK port
    // without multi-segment mbufs): no aggregate could form, and the
    // reservations' room would go unused.
    pub(crate) fn gso(&self, io: &impl PacketIo) -> Option<ntcp::GsoLimits> {
        let capabilities = io.tcp_segmentation_capabilities()?;
        let ip = if self.local_address.is_ipv4() { 20 } else { 40 };
        let max_bytes = capabilities
            .max_aggregate_len
            .checked_sub(self.link.offset() + ip + 20)?;
        let segment = (self.mtu as usize).checked_sub(ip + 20)?;
        (capabilities.max_segments >= 2 && max_bytes >= 2 * segment).then_some(ntcp::GsoLimits {
            max_bytes,
            max_segments: capabilities.max_segments,
        })
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
    ///   (TCP_ATO_MIN, TCP_DELACK_MAX);
    /// - a 60 s TIME-WAIT (TCP_TIMEWAIT_LEN), where the Endpoint's default
    ///   lingers 120 s;
    /// - a SYN that passes RFC 6191's timestamp and sequence checks reopens
    ///   a tuple in TIME-WAIT for the listener on its port
    ///   (`tcp.reuse_time_wait`), as Linux always lets it
    ///   (tcp_timewait_state_process, TCP_TW_SYN). An active open still
    ///   never takes a tuple in TIME-WAIT, as Linux's tcp_tw_reuse allows
    ///   only over loopback by default;
    /// - ephemeral ports 32768 to 60999 (ip_local_port_range);
    /// - receive buffers of 4 KiB, 64 KiB and 32 MiB (min, initial, max):
    ///   each starts at 64 KiB and grows at read with the bytes the
    ///   application takes per round trip, up to 32 MiB, as Linux's
    ///   tcp_rmem = 4096 131072 33554432 with tcp_moderate_rcvbuf (its
    ///   128 KiB of memory starts a window of about 64 KiB; here sizes are
    ///   window bytes). The 32 MiB maximum gives the SYN a window scale of
    ///   10, as tcp_select_initial_window takes it from tcp_rmem[2];
    /// - send limits of 4 KiB, 64 KiB and 4 MiB: each starts at 64 KiB and
    ///   rises with the congestion window, to twice it, up to 4 MiB, as
    ///   Linux's tcp_wmem[2] = 4 MiB with tcp_sndbuf_expand. The 64 KiB
    ///   start (Linux's tcp_wmem[1] is 16 KiB of memory, about 7 KiB of
    ///   payload before expansion) keeps a 64 KiB response in one write.
    ///
    /// Each remains a field of `tcp` or `tcp.connection` to change.
    /// `tcp.buffers()` reads the buffer sizes and memory thresholds in
    /// force; setting a direction's max to its initial size turns its
    /// autotuning off.
    pub fn new(local_address: IpAddr, mtu: u32) -> Self {
        let mut tcp = EndpointConfig {
            reuse_time_wait: true,
            ..EndpointConfig::default()
        };
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
        connection.time_wait_us = 60_000_000;
        connection.receive_capacity_max = 32 << 20;
        connection.send_capacity_max = 4 << 20;
        Self {
            local_address,
            mtu,
            tcp,
            link: Link::Ip,
            // Linux's ip_local_port_range, not RFC 6056's 1024-65535 (an
            // exception in duvet/rfc6056-todos.toml).
            ephemeral_ports: 32768..=60999,
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
    // at once (an IPv6 first fragment also stores its Fragment header),
    // one of them in 8-octet fragments of the larger family's datagram:
    // the charge bound is the octets of the others and that one's whole
    // charge, descriptors included. The IPv4
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
        let mut limits = ntcp_host::ReassemblyLimits {
            assemblies: datagrams,
            fragments: ipv6_datagram.div_ceil(8),
            buffered_bytes: 0,
            ipv4_datagram: mtu.clamp(576, 65535),
            ipv6_datagram,
            ipv4_timeout_seconds: 30,
        };
        let worst = limits
            .datagram_charge(ipv6_datagram, true)
            .max(limits.datagram_charge(limits.ipv4_datagram, false));
        limits.buffered_bytes = (datagrams - 1)
            .checked_mul(ipv6_datagram + 8)
            .and_then(|n| n.checked_add(worst))
            .filter(|&n| n <= u32::MAX as usize)?;
        Some(limits)
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
