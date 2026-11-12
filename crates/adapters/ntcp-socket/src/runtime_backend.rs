// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;
use ntcp_io::{
    ClockDomain, PacketTimestamp, PacketTimestamps, ReceivedPacket, TimestampPoint,
    TimestampSource, TimestampUnit,
};
use ntcp_io_af_packet::{AfPacket, TimestampConfig};
use std::{
    ffi::CString,
    os::fd::{AsFd, AsRawFd},
};

// IPv4 Timestamp time (RFC 791 section 3.1, RFC 1122 section 3.2.2.8) from
// the characterized Linux UTC source: UTC milliseconds since midnight when
// its sample is standard, otherwise the owner clock's elapsed milliseconds
// with the high-order bit set. Each sample is one kernel acquisition, taken
// only when a Timestamp slot will be written; the source keeps only its
// suspend-continuity state across samples.
#[derive(Debug, Default)]
pub(super) struct Ipv4Clock {
    utc: ntcp_clock::UtcClock,
    #[cfg(test)]
    pub(super) acquisitions: usize,
}
impl Ipv4Clock {
    fn sample(&mut self, now: u64) -> Option<ntcp::Ipv4Timestamp> {
        #[cfg(test)]
        {
            self.acquisitions += 1;
        }
        // A standard value is below 86 400 000, a nonstandard one marked.
        ntcp::Ipv4Timestamp::from_wire(self.utc.sample(now / 1000).value).ok()
    }
}
// Destination recording with time sampled at `now` on the owner clock.
pub(super) struct Recording<'a> {
    pub(super) clock: &'a mut Ipv4Clock,
    pub(super) now: u64,
}
impl ntcp::Ipv4TimestampProvider for Recording<'_> {
    fn ipv4_timestamp(&mut self) -> Option<ntcp::Ipv4Timestamp> {
        self.clock.sample(self.now)
    }
}

// The identity of an opened interface's hardware clock: unique to this open
// in this process, never the interface index, which the OS reuses for a later
// interface whose clock is a different device.
fn device_clock() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

// One port of the owner: its backend (an Ethernet PacketIo or a TUN device;
// neither for the in-process packet-test queue and backend-less fixtures),
// its configured address and the network it was assigned within, the
// interface index sin6_scope_id names it by, and its Host link once
// attached. A TUN device or an Ethernet port with a fixed next-hop MAC is
// a legacy forwarder port, which forwards everything it sends through that
// one next hop; an Ethernet port without one resolves the IP next hop of
// each packet (`Resolution`) and may have gateway routes.
pub(super) struct Port {
    pub(super) address: IpAddr,
    pub(super) subnet: (IpAddr, u8),
    pub(super) index: u32,
    pub(super) ingress: Option<ntcp_host::IngressContext>,
    pub(super) ethernet: Option<EthernetBackend>,
    pub(super) tun: Option<Tun>,
    // The kernel port's MTU query (none for userspace-owned ports).
    pub(super) mtu_refresh: Option<output::MtuRefresh>,
    pub(super) resolution: Resolution,
    pub(super) gateways: Vec<(ntcp_host::path::IpPrefix, IpAddr)>,
    // The kernel's IPv6 group memberships on this port's interface (all-nodes
    // and the address's solicited-node group), held for the port's lifetime
    // so the kernel reports them (MLD) and the link delivers the groups.
    memberships: Option<std::os::fd::OwnedFd>,
}
// How a port finds the link-layer destination of its output.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Resolution {
    // Everything through the fixed next hop (`FORWARDER`): the backend's
    // next-hop MAC, or a TUN device's L3 peer.
    Fixed,
    // IPv6 Neighbor Discovery by the Host (`Forwarding::IpNextHop`).
    Discovery,
    // The operator's static IPv4 neighbors (no ARP).
    Static(Vec<(IpAddr, [u8; 6])>),
}
impl Port {
    pub(super) fn new(address: IpAddr, subnet: (IpAddr, u8), tun: Option<Tun>) -> Self {
        Self {
            address,
            subnet,
            index: 0,
            ingress: None,
            ethernet: None,
            tun,
            mtu_refresh: None,
            resolution: Resolution::Fixed,
            gateways: Vec::new(),
            memberships: None,
        }
    }
    fn ethernet(address: IpAddr, subnet: (IpAddr, u8), backend: EthernetBackend) -> Self {
        Self {
            ethernet: Some(backend),
            ..Self::new(address, subnet, None)
        }
    }
    // An Ethernet port without a fixed next hop resolves its next hops: by
    // Neighbor Discovery for IPv6, through `neighbors` for IPv4. Its
    // `gateways` are routes through such next hops.
    fn resolving(
        mut self,
        gateways: &[(ntcp_host::path::IpPrefix, IpAddr)],
        neighbors: &[(IpAddr, [u8; 6])],
    ) -> Result<Self> {
        if self.ethernet.as_ref().is_some_and(|b| b.next_hop.is_some()) {
            if !gateways.is_empty() || !neighbors.is_empty() {
                return Err(EINVAL);
            }
            return Ok(self);
        }
        let copy = |items: &[(ntcp_host::path::IpPrefix, IpAddr)]| -> Result<Vec<_>> {
            let mut out = Vec::new();
            out.try_reserve_exact(items.len()).map_err(|_| ENOMEM)?;
            out.extend_from_slice(items);
            Ok(out)
        };
        self.gateways = copy(gateways)?;
        self.resolution = if self.address.is_ipv6() {
            if !neighbors.is_empty() {
                return Err(EINVAL);
            }
            Resolution::Discovery
        } else {
            let mut table = Vec::new();
            table.try_reserve_exact(neighbors.len()).map_err(|_| ENOMEM)?;
            table.extend_from_slice(neighbors);
            Resolution::Static(table)
        };
        Ok(self)
    }
    // The static-neighbor MAC of an IPv4 next hop; None when this port does
    // not use static neighbors or has no mapping for it.
    pub(super) fn static_neighbor(&self, next_hop: IpAddr) -> Option<[u8; 6]> {
        match &self.resolution {
            Resolution::Static(table) => table
                .iter()
                .find(|(address, _)| *address == next_hop)
                .map(|&(_, mac)| mac),
            _ => None,
        }
    }
    // The zone this port is, once attached.
    pub(super) fn zone(&self) -> Option<address_policy::Zone> {
        Some(address_policy::Zone {
            index: self.index,
            link: self.ingress?.link(),
        })
    }
    pub(super) fn link(&self) -> Option<ntcp_host::path::LinkId> {
        Some(self.ingress?.link())
    }
    // The port's address as the Host knows it: a link-local address is
    // scoped by this port's link.
    fn source(&self) -> Result<ntcp_host::path::ScopedAddress> {
        let zone = crate::ip::link_local(self.address)
            .then(|| self.link())
            .flatten();
        ntcp_host::path::ScopedAddress::new(self.address, zone).map_err(|e| host_error(e.into()))
    }
    // This port's Ethernet header on `frame` (nothing for an IP port), to
    // `destination` when this port resolved one, else to its fixed next hop.
    pub(super) fn frame_header(&self, frame: &mut [u8], destination: Option<[u8; 6]>) {
        if let Some(backend) = &self.ethernet {
            backend.frame_header(frame, self.address, destination);
        }
    }
    fn io(&self) -> Option<&dyn PacketIo> {
        if let Some(backend) = &self.ethernet {
            Some(&*backend.io)
        } else {
            self.tun.as_ref().map(|tun| tun as &dyn PacketIo)
        }
    }
}
// The fixed next hop each legacy port forwards through.
pub(super) const FORWARDER: ntcp_host::path::ForwarderId = ntcp_host::path::ForwarderId(1);

pub(super) struct EthernetBackend {
    pub(super) io: Box<dyn PacketIo>,
    pub(super) local: [u8; 6],
    // The fixed next hop of a legacy port; None when the port resolves each
    // packet's next hop.
    pub(super) next_hop: Option<[u8; 6]>,
    next_cookie: u64,
    pending: Vec<(u64, ntcp::TxTimestampToken, bool, bool)>,
    // Endpoint-side timestamp cancellations recorded during one physical
    // call, which runs inside the Host submission transaction while the Host
    // holds the Endpoint. Drained by `finish_cancellations` after every call:
    // at most every pending entry (<= PHASES) plus the fallback request.
    cancelled: Vec<(ntcp::TxTimestampToken, bool, bool)>,
}
impl EthernetBackend {
    // The resolved `destination` (else the fixed next hop; a resolving
    // port's frame written before resolution gets it at submission), this
    // port's MAC and the EtherType of `family`'s packets.
    pub(super) fn frame_header(
        &self,
        frame: &mut [u8],
        family: IpAddr,
        destination: Option<[u8; 6]>,
    ) {
        frame[..6].copy_from_slice(&destination.or(self.next_hop).unwrap_or_default());
        frame[6..12].copy_from_slice(&self.local);
        frame[12..14].copy_from_slice(&crate::ip::ether_type(family).to_be_bytes());
    }
    pub(super) fn new(io: Box<dyn PacketIo>, local: [u8; 6], next_hop: Option<[u8; 6]>) -> Self {
        Self {
            io,
            local,
            next_hop,
            next_cookie: 1,
            pending: Vec::with_capacity(timestamps::PHASES),
            cancelled: Vec::with_capacity(timestamps::PHASES + 1),
        }
    }
}
impl Drop for EthernetBackend {
    fn drop(&mut self) {
        for (cookie, _, _, _) in self.pending.drain(..) {
            let _ = self.io.cancel_tx_timestamp(cookie);
        }
    }
}
fn core_stamp(stamp: PacketTimestamp) -> Option<ntcp::RxTimestamp> {
    let clock = match (stamp.clock.domain, stamp.clock.unit) {
        (ClockDomain::Realtime, TimestampUnit::Nanoseconds) => {
            ntcp::TimestampClock::RealtimeNanoseconds
        }
        (ClockDomain::Device(identity), TimestampUnit::Nanoseconds) => {
            ntcp::TimestampClock::DeviceTicks {
                identity,
                units_per_second: Some(1_000_000_000),
            }
        }
        (ClockDomain::Device(identity), TimestampUnit::RawTicks { .. }) => {
            ntcp::TimestampClock::DeviceTicks {
                identity,
                units_per_second: None,
            }
        }
        _ => return None,
    };
    Some(ntcp::RxTimestamp {
        value: stamp.value,
        clock,
    })
}
fn core_stamps(stamps: PacketTimestamps) -> ntcp::RxPacketTimestamps {
    ntcp::RxPacketTimestamps {
        software: stamps.software.and_then(core_stamp),
        hardware: stamps.hardware.and_then(core_stamp),
    }
}
// The outcome of one receive loop iteration, shared by both receive loops.
pub(super) enum BackendReceive<'a> {
    Packet {
        // The port the packet arrived on.
        port: usize,
        bytes: &'a [u8],
        stamps: ntcp::RxPacketTimestamps,
        segment_size: Option<core::num::NonZeroU16>,
        // The Ethernet destination was a group (multicast or broadcast)
        // address; the Host then originates no ICMP error about it.
        link_multicast: bool,
    },
    // A transient backend error or a rejected Ethernet frame.
    Skipped,
    Empty,
}
// Startup only: local_ip_mtu may block on the backend's control plane.
#[cfg(test)]
pub(super) fn backend_config(config: EndpointConfig, io: &dyn PacketIo) -> Result<EndpointConfig> {
    backend_config_family(config, io, Ipv4Addr::UNSPECIFIED.into())
}
pub(super) fn backend_config_family(
    mut config: EndpointConfig,
    io: &dyn PacketIo,
    local: IpAddr,
) -> Result<EndpointConfig> {
    let header = crate::ip::header_len(local);
    let minimum = if local.is_ipv4() { 68 } else { 1280 };
    let mtu = io
        .local_ip_mtu()
        .map_err(|e| e.raw_os_error().unwrap_or(EIO))?
        .ok_or(EOPNOTSUPP)?;
    if mtu < minimum {
        return Err(EINVAL);
    }
    let overhead = if io.layer() == ntcp_io::PacketLayer::Ethernet {
        14
    } else {
        0
    };
    let packet_capacity = io.max_packet_len().unwrap_or(65535 + overhead);
    let packet_capacity = io.zero_copy_capabilities().map_or(packet_capacity, |caps| {
        packet_capacity.min(caps.max_packet_len)
    });
    let ip_capacity = packet_capacity
        .checked_sub(overhead)
        .ok_or(EINVAL)?
        .min(65535);
    if ip_capacity < minimum as usize {
        return Err(EINVAL);
    }
    config.connection.send_ip_payload_limit = config
        .connection
        .send_ip_payload_limit
        .min((ip_capacity - header) as u16);
    let mut policy = config
        .connection
        .pmtud
        .unwrap_or(ntcp::PmtudConfig::new(mtu));
    policy.first_hop_mtu = mtu;
    config.connection.pmtud = Some(policy);
    config.validate().map_err(engine)?;
    Ok(config)
}

// Source fragmentation and identifiers for what this Host originates: Echo
// Replies (and, IPv4 only, the Identification of every DF-clear packet of an
// IP_PMTUDISC_DONT connection). TCP itself is never source-fragmented.
fn native_datagrams(
    ipv4: bool,
    largest: usize,
    connections: usize,
) -> ntcp_host::DatagramLimits {
    // Enough fragments for the largest reply the Host can reassemble a
    // request for, cut to the smallest link each family must support (68
    // and 1280 octets): a narrowed path never leaves such a reply unsent for
    // want of fragments. Host ICMP output holds no ledger tickets.
    let room = if ipv4 { 68 - 20 } else { 1280 - 48 };
    let max_fragments = largest.div_ceil(room & !7);
    // Every lease lives for the whole MDL. IPv4 tuples: one per remote of
    // every connection (DONT) plus one receive batch of distinct Echo
    // peers. IPv6 leases: one receive batch of fragmented replies per
    // second, sustained over the MDL. Beyond them, a reply goes out whole
    // when the path allows it and is otherwise counted unsent.
    let lifetime = ntcp_host::DEFAULT_LIFETIME_SECONDS;
    ntcp_host::DatagramLimits {
        max_fragments,
        identifiers: ntcp_host::IdentifierLimits {
            lifetime_seconds: lifetime,
            ipv4_tuples: if ipv4 { connections + BUDGET } else { 0 },
            ipv6_leases: if ipv4 {
                0
            } else {
                BUDGET * lifetime as usize
            },
        },
        // The Echo adjunct confirms larger sizes for the paths of fragmented
        // replies: one entry per receive batch of distinct Echo peers.
        adjunct: ntcp_host::AdjunctLimits {
            paths: BUDGET,
            ..Default::default()
        },
        // No knowledge of any peer's reassembly capacity: the receiver
        // guarantees of RFC 1122 and RFC 8200 hold.
        ..Default::default()
    }
}

// The kernel index of interface `name`.
pub(super) fn interface_index(name: &str) -> Result<u32> {
    let name = CString::new(name).map_err(|_| EINVAL)?;
    match unsafe { libc::if_nametoindex(name.as_ptr()) } {
        0 => Err(errno()),
        index => Ok(index),
    }
}

// An AF_PACKET socket bound to interface `name` for `local`'s family, with
// the interface's hardware address and kernel index.
fn open_af_packet(name: &str, local: IpAddr, aggregation: bool) -> Result<(AfPacket, [u8; 6], u32)> {
    let index = interface_index(name)?;
    let name = CString::new(name).map_err(|_| EINVAL)?;
    let mut io = AfPacket::bind(index, crate::ip::ether_type(local))
        .map_err(|e| e.raw_os_error().unwrap_or(EIO))?;
    if aggregation {
        io.enable_receive_aggregation()
            .map_err(|e| e.raw_os_error().unwrap_or(EIO))?;
    }
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    if name.as_bytes_with_nul().len() > request.ifr_name.len() {
        return Err(EINVAL);
    }
    for (out, &byte) in request.ifr_name.iter_mut().zip(name.as_bytes_with_nul()) {
        *out = byte as _;
    }
    // Query only: never SIOCSHWTSTAMP, ethtool or host-interface mutation.
    if unsafe {
        libc::ioctl(
            io.as_fd().as_raw_fd(),
            libc::SIOCGIFHWADDR as _,
            &mut request,
        )
    } < 0
    {
        return Err(errno());
    }
    let mut hardware = [0; 6];
    for (byte, value) in hardware
        .iter_mut()
        .zip(unsafe { request.ifr_ifru.ifru_hwaddr.sa_data })
    {
        *byte = value as u8;
    }
    io.enable_timestamps(TimestampConfig {
        rx_software: true,
        rx_hardware: true,
        tx_software: true,
        tx_hardware: true,
        device_clock: Some(device_clock()),
        tx_completion_capacity: timestamps::PHASES,
    })
    .map_err(|e| e.raw_os_error().unwrap_or(EOPNOTSUPP))?;
    Ok((io, hardware, index))
}

// Join all-nodes and `address`'s solicited-node group on interface `index`
// (RFC 4861 section 7.2.1, RFC 4862 section 5.4.2): the AF_PACKET socket
// `io` holds the Ethernet memberships (33:33 mapping) it receives them
// through, and the returned kernel socket holds the IPv6 group joins, which
// make the kernel send the MLD reports switches forward the groups by.
fn join_groups(io: &AfPacket, index: u32, address: std::net::Ipv6Addr) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let groups = [ntcp_ethernet::IPV6_ALL_NODES, ntcp_ethernet::solicited_node(address)];
    for group in groups {
        let mac = ntcp_ethernet::ipv6_multicast_mac(group).ok_or(EINVAL)?;
        let mut request: libc::packet_mreq = unsafe { std::mem::zeroed() };
        request.mr_ifindex = index as i32;
        request.mr_type = libc::PACKET_MR_MULTICAST as u16;
        request.mr_alen = 6;
        request.mr_address[..6].copy_from_slice(&mac);
        if unsafe {
            libc::setsockopt(
                io.as_fd().as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                (&raw const request).cast(),
                std::mem::size_of_val(&request) as libc::socklen_t,
            )
        } < 0
        {
            return Err(errno());
        }
    }
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(errno());
    }
    let socket = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    for group in groups {
        let request = libc::ipv6_mreq {
            ipv6mr_multiaddr: libc::in6_addr {
                s6_addr: group.octets(),
            },
            ipv6mr_interface: index,
        };
        if unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_ADD_MEMBERSHIP,
                (&raw const request).cast(),
                std::mem::size_of_val(&request) as libc::socklen_t,
            )
        } < 0
            // The kernel itself is always a member of all-nodes.
            && !(group == ntcp_ethernet::IPV6_ALL_NODES && errno() == libc::EADDRINUSE)
        {
            return Err(errno());
        }
    }
    Ok(socket)
}

impl Owner {
    // Complete the constructor using the actual configured ports, the
    // `io.*` port (`interface` is its interface index) first.
    // InterfaceKey is an embedding assignment within an independently minted
    // context; external ports need no fabricated kernel interface identity.
    pub(super) fn attach_backend_host(&mut self, interface: u64) -> Result<()> {
        self.attach_backend_host_with(interface, None)
    }
    // A replacement Host for the same ports and addresses receives the
    // previous Host's identifier allocator, with every live lease.
    pub(super) fn attach_backend_host_with(
        &mut self,
        interface: u64,
        previous: Option<ntcp_host::IdentifierAllocator>,
    ) -> Result<()> {
        if self.host.is_some() {
            return Err(EINVAL);
        }
        self.ports.first_mut().ok_or(EINVAL)?.index = u32::try_from(interface).map_err(|_| EINVAL)?;
        // Each port's link MTU, wire overhead and largest IP packet.
        let mut links = Vec::new();
        links.try_reserve_exact(self.ports.len()).map_err(|_| ENOMEM)?;
        for i in 0..self.ports.len() {
            let io = self.port_io(i).ok_or(EOPNOTSUPP)?;
            let mtu = io
                .local_ip_mtu()
                .map_err(|e| e.raw_os_error().unwrap_or(EIO))?
                .ok_or(EOPNOTSUPP)?;
            if mtu < if self.local.is_ipv4() { 68 } else { 1280 } {
                return Err(EINVAL);
            }
            let overhead = if io.layer() == ntcp_io::PacketLayer::Ethernet {
                14
            } else {
                0
            };
            let max_ip_packet = io
                .max_packet_len()
                .unwrap_or(65535 + overhead)
                .checked_sub(overhead)
                .ok_or(EINVAL)?
                .min(65535);
            links.push((mtu, overhead, max_ip_packet));
        }
        // The Host-wide receive storage serves the largest port.
        let mtu = links.iter().map(|l| l.0).max().ok_or(EINVAL)?;
        let overhead = links.iter().map(|l| l.1).max().ok_or(EINVAL)?;
        let max_ip_packet = links.iter().map(|l| l.2).max().ok_or(EINVAL)?;
        let mut identity = [0; 8];
        ports::fill(&mut identity)?;
        use ntcp_host::{Forwarding, Ipv4Receive, Ipv6Receive, ReceiveCapabilities, path};
        // Occupied transports + provisional TIME-WAIT generation + stateless
        // lane + one serialized live-class migration. No peer-created routes.
        // One link and one source per port; the routes `port_routes` installs.
        let routes = (0..self.ports.len())
            .map(|i| self.port_route_count(i))
            .sum();
        let ports = self.ports.len();
        let (paths, limits) = ntcp_host::managed_limits(&self.defaults, ports, ports, ports, routes, 1)
            .map_err(host_error)?;
        // Reassembly up to the largest packet this link delivers whole (at
        // least each family's required minimum): the size TCP's receive
        // limits derive from, so a segment some narrower path fragmented
        // still arrives, as does an Echo Request of that size. One receive
        // batch's worth of concurrent datagrams and the charge of one
        // largest datagram buffered at a time in 8-octet fragments, the
        // worst conforming fragmentation: its octets (an IPv6 first
        // fragment also stores its Fragment header) and descriptors. The
        // IPv4 timeout is RFC 1122 section 3.3.2's lower bound.
        let ipv4_datagram = max_ip_packet.clamp(576, 65535);
        let ipv6_datagram = max_ip_packet.clamp(1500, 65575);
        let mut reassembly = ntcp_host::ReassemblyLimits {
            assemblies: BUDGET,
            fragments: ipv6_datagram.div_ceil(8),
            buffered_bytes: 0,
            ipv4_datagram,
            ipv6_datagram,
            ipv4_timeout_seconds: 60,
        };
        reassembly.buffered_bytes = reassembly
            .datagram_charge(ipv6_datagram, true)
            .max(reassembly.datagram_charge(ipv4_datagram, false));
        let largest = if self.local.is_ipv4() {
            ipv4_datagram - 20
        } else {
            ipv6_datagram - 40
        };
        // Echo Replies and reassembly errors: one receive batch's worth of
        // messages, each as large as a reassembled Echo Request (and never
        // smaller than a maximal ICMPv6 error).
        let (paths, mut limits) = ntcp_host::managed_icmp_output_limits(
            paths,
            limits,
            ntcp_host::IcmpOutputLimits {
                messages: BUDGET,
                message_bytes: largest.max(ntcp_icmp::ICMPV6_ERROR_LIMIT),
                hop_limit: self.defaults.hop_limit,
            },
        )
        .map_err(host_error)?;
        limits.reassembly = reassembly;
        // Neighbor Discovery storage: a cache entry for every connection's
        // next hop, every gateway and every queued Host ICMP message, a
        // held attempt for each output lane (one selected attempt per
        // connection, and the stateless lane) and for each queued ICMP
        // message (so held ICMP output never takes a transport lane's
        // slot), each port's one address,
        // and one receive batch's worth of answers.
        let discovery = self
            .ports
            .iter()
            .filter(|p| p.resolution == Resolution::Discovery);
        let gateways: usize = discovery.clone().map(|p| p.gateways.len()).sum();
        let nd_ports = discovery.count();
        if nd_ports != 0 {
            limits.neighbors = ntcp_host::NeighborLimits {
                entries: self
                    .defaults
                    .max_connections
                    .saturating_add(gateways)
                    .saturating_add(BUDGET),
                pending_packets: self
                    .defaults
                    .max_connections
                    .saturating_add(1)
                    .saturating_add(BUDGET),
                addresses: nd_ports,
                answers: BUDGET,
            };
        }
        limits.datagrams = native_datagrams(
            self.local.is_ipv4(),
            largest,
            self.defaults.max_connections,
        );
        let message_bytes = limits.icmp_output.message_bytes;
        // The path cache's hash key, from the blocking kernel CSPRNG as the
        // TCP secret is.
        let mut lookup_key = [0; 16];
        ports::fill(&mut lookup_key)?;
        let mut host = ntcp_host::Host::new(
            path::ContextId::new(u64::from_ne_bytes(identity)),
            paths,
            limits,
            self.endpoint.caller_timebase(),
            lookup_key,
        )
        .map_err(host_error)?;
        // Unpredictable identifiers draw on the same blocking kernel CSPRNG
        // as ports and startup secrets; a failure is the Host's explicit
        // backpressure, never a weaker source.
        host.set_entropy(Box::new(|bytes: &mut [u8]| {
            ports::fill(bytes).map_err(|_| ntcp_host::EntropyError)
        }));
        // A replacement Host in this process takes over the allocator with
        // its leases; a newly started runtime assumes no earlier incarnation
        // emitted from its addresses and issues at once.
        host.start_identifiers(match previous {
            Some(allocator) => ntcp_host::Continuity::Transfer(allocator),
            None => ntcp_host::Continuity::Fresh,
        })
        .map_err(host_error)?;
        for (i, &(mtu, _, max_ip_packet)) in links.iter().enumerate() {
            let receive = ReceiveCapabilities {
                        max_ip_packet,
                        // Record Route and Timestamp are interpreted, with time
                        // from the characterized UTC source (`Ipv4Clock`).
                        // Source routes stay refused: native TCP keeps IPv4
                        // options disabled, so no return route can be used.
                        ipv4: if self.local.is_ipv4() {
                            Ipv4Receive::Enabled {
                                interpretation: true,
                                source_routes: false,
                            }
                        } else {
                            Ipv4Receive::Disabled
                        },
                        ipv6: if self.local.is_ipv6() {
                            Ipv6Receive::Extensions
                        } else {
                            Ipv6Receive::Disabled
                        },
                        // The current input adapter accepts validated segment-size metadata
                        // from this PacketIo. This does not promise aggregation offload.
                        gro: true,
                    };
            let interface = path::InterfaceKey(u64::from(self.ports[i].index));
            let port = &self.ports[i];
            let ingress = match (&port.resolution, &port.ethernet) {
                (Resolution::Discovery, Some(backend)) => {
                    // AF_PACKET never delivers this socket's own output, and
                    // a userspace backend receives only what its link
                    // delivers: no own DAD probe comes back.
                    let nd = ntcp_host::NdPort::new(backend.local);
                    host.register_neighbor_port(interface, mtu, receive, nd)
                }
                (Resolution::Fixed, _) => {
                    host.register_link(interface, mtu, receive, Forwarding::Forwarder(FORWARDER))
                }
                (_, _) => host.register_link(interface, mtu, receive, Forwarding::IpNextHop),
            }
            .map_err(host_error)?;
            self.ports[i].ingress = Some(ingress);
            match (self.ports[i].resolution == Resolution::Discovery, self.ports[i].address) {
                // Tentative until Duplicate Address Detection completes,
                // which starts once its groups are joined: by `af_packet`
                // for a kernel interface, by the embedding for a userspace
                // backend, which receives whatever its link delivers.
                (true, IpAddr::V6(address)) => {
                    host.add_neighbor_address(ingress.link(), address)
                        .map_err(host_error)?;
                    host.neighbor_membership_ready(ingress.link(), address, self.clock()?)
                        .map_err(host_error)?;
                }
                // A link-local address is this port's own, scoped by its link.
                _ => {
                    host.register_source(self.ports[i].source()?, ingress.link())
                        .map_err(host_error)?;
                }
            }
            for (route, segments) in self.port_routes(i, ingress.link())? {
                match segments {
                    Some(segments) => host.add_segment_route(route, segments),
                    None => host.add_route(route),
                }
                .map_err(host_error)?;
            }
        }
        host.attach(&mut self.endpoint).map_err(host_error)?;
        let capacity = host
            .reassembly_capacity(self.local.is_ipv6())
            .map_or(0, |c| c.emtu_r as usize);
        let storage = |len: usize| -> Result<Vec<u8>> {
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(len).map_err(|_| ENOMEM)?;
            bytes.resize(len, 0);
            Ok(bytes)
        };
        self.completed = storage(capacity.max(max_ip_packet))?;
        // A queued message is built whole in this buffer; a fragmented one
        // keeps the complete message beside the fragment being cut, which is
        // never larger than the connectionless effective size and so never
        // larger than the link: the message, an IP header and the link MTU.
        self.icmp_packet =
            storage(message_bytes + crate::ip::header_len(self.local) + mtu as usize)?;
        self.icmp_wire = storage(overhead + max_ip_packet.max(60))?;
        self.host = Some(host);
        Ok(())
    }
    // The number of routes `port_routes` installs for port `i`.
    fn port_route_count(&self, i: usize) -> usize {
        let port = &self.ports[i];
        if i == 0 && port.resolution == Resolution::Fixed {
            return 1 + self.segment_routes.len();
        }
        usize::from(!crate::ip::link_local(port.address))
            + usize::from(port.address.is_ipv6())
            + port.gateways.len()
    }
    // The backend of port `i`; the in-process packet-test queue is the
    // `io.*` port's.
    fn port_io(&self, i: usize) -> Option<&dyn PacketIo> {
        #[cfg(feature = "packet-test")]
        if i == 0
            && let Some(packets) = &self.packets
        {
            return Some(packets);
        }
        self.ports[i].io()
    }
    // The routes of port `i` on its `link`, each with its SR segments. The `io.*` port with a
    // fixed next hop keeps exactly its historical routes: the default route
    // through it and each owner-configured SR route. A port that resolves
    // its next hops, `io.*` included, gets no implicit default route. An
    // additional port gets
    // no default route (two equal-priority defaults are rejected), but its
    // own prefix and, for IPv6, the link-local prefix of its own zone
    // (distinct links are disjoint zones): on a legacy port these go through
    // its fixed next hop, which forwards everything the port sends. A
    // legacy port resolves no IP next hop, so configuration refuses gateway
    // routes on it. On a port that resolves its next hops these are direct
    // (on-link) routes, and its gateway routes go through their next hops,
    // a link-local one scoped by the port's link.
    fn port_routes(
        &self,
        i: usize,
        link: ntcp_host::path::LinkId,
    ) -> Result<Vec<(ntcp_host::path::Route, Option<&[std::net::Ipv6Addr]>)>> {
        use ntcp_host::path::{IpPrefix, NextHop, Route};
        let port = &self.ports[i];
        let prefix = |network: IpAddr, length: u8| {
            IpPrefix::new(network, length).map_err(|e| host_error(e.into()))
        };
        let route = |destination: IpPrefix, next_hop: NextHop| Route {
            destination,
            source: None,
            dscp: None,
            link,
            next_hop,
            metric: 0,
        };
        let forwarder = NextHop::Forwarder(FORWARDER);
        let direct = match port.resolution {
            Resolution::Fixed => forwarder,
            _ => NextHop::OnLink,
        };
        let mut routes = Vec::new();
        routes
            .try_reserve_exact(self.port_route_count(i))
            .map_err(|_| ENOMEM)?;
        if i == 0 && port.resolution == Resolution::Fixed {
            let any = if self.local.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            };
            routes.push((route(prefix(any, 0)?, forwarder), None));
            for sr in &self.segment_routes {
                routes.push((route(sr.destination, forwarder), Some(&sr.segments[..])));
            }
            return Ok(routes);
        }
        let (network, length) = port.subnet;
        let link_local = prefix(IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)), 64)?;
        if !crate::ip::link_local(port.address) {
            let network = crate::ip::network(network, length).ok_or(EINVAL)?;
            routes.push((route(prefix(network, length)?, direct), None));
        }
        if port.address.is_ipv6() {
            routes.push((route(link_local, direct), None));
        }
        for &(destination, next_hop) in &port.gateways {
            let zone = crate::ip::link_local(next_hop).then_some(link);
            let next_hop = ntcp_host::path::ScopedAddress::new(next_hop, zone)
                .map_err(|e| host_error(e.into()))?;
            routes.push((route(destination, NextHop::Gateway(next_hop)), None));
        }
        Ok(routes)
    }
    // The one-port form of `external_backends`.
    #[cfg(test)]
    pub(super) fn external_backend(
        config: &SocketConfig,
        backend: crate::EthernetPacketIo,
    ) -> Result<Self> {
        let mut backends = Vec::new();
        backends.try_reserve_exact(1).map_err(|_| ENOMEM)?;
        backends.push(backend);
        Self::external_backends(config, backends)
    }
    // Userspace-owned ports: the `io.*` port's backend first, then one for
    // each `port.<name>` in configuration order.
    pub(super) fn external_backends(
        config: &SocketConfig,
        backends: Vec<crate::EthernetPacketIo>,
    ) -> Result<Self> {
        if backends.len() != 1 + config.ports.len()
            || backends
                .iter()
                .any(|b| b.io.layer() != ntcp_io::PacketLayer::Ethernet)
        {
            return Err(EINVAL);
        }
        // A userspace-owned port need not have a kernel interface/address.
        // The embedding host explicitly assigns its address and subnet instead
        // of consulting getifaddrs (used by borrowed TUN/AF_PACKET interfaces).
        let subnet = |local: IpAddr, prefix: Option<u8>| -> Result<(IpAddr, u8)> {
            let prefix = prefix.ok_or(EINVAL)?;
            let network = crate::ip::network(local, prefix).ok_or(EINVAL)?;
            if !unicast(local) {
                return Err(EADDRNOTAVAIL);
            }
            if crate::ip::network_or_broadcast(local, prefix) {
                return Err(EADDRNOTAVAIL);
            }
            Ok((network, prefix))
        };
        let local = config.io.address;
        let tcp = backend_config_family(config.tcp.clone(), &*backends[0].io, local)?;
        let mut ports = Vec::new();
        ports.try_reserve_exact(backends.len()).map_err(|_| ENOMEM)?;
        for (i, backend) in backends.into_iter().enumerate() {
            let (address, prefix, gateways, neighbors) = match i.checked_sub(1) {
                None => (
                    local,
                    config.io.prefix,
                    &config.io.gateways[..],
                    &config.io.neighbors[..],
                ),
                Some(j) => {
                    let port = &config.ports[j];
                    (port.address, port.prefix, &port.gateways[..], &port.neighbors[..])
                }
            };
            let mut port = Port::ethernet(
                address,
                subnet(address, prefix)?,
                EthernetBackend::new(backend.io, backend.local_mac, backend.next_hop_mac),
            )
            .resolving(gateways, neighbors)?;
            if i > 0 {
                // The embedding's assignment, like the `io.*` port's 1.
                port.index = u32::try_from(i + 1).map_err(|_| EINVAL)?;
            }
            ports.push(port);
        }
        let secret = random_secret()?;
        let mut owner = Self::with_ports(ports, secret, tcp)?;
        owner.initialize_socket_config(config)?;
        owner.attach_backend_host(1)?;
        owner.enable_egress(config.io.egress_capacity, config.io.gso)?;
        owner.reservation_timeout_us = u64::from(config.io.output_reservation_timeout_ms) * 1000;
        Ok(owner)
    }

    pub(super) fn af_packet(config: &SocketConfig) -> Result<Self> {
        let local = config.io.address;
        let io_port = crate::PortConfig {
            name: String::new(),
            interface: config.io.interface.clone(),
            address: local,
            prefix: config.io.prefix,
            next_hop_mac: config.io.next_hop_mac,
            gateways: config.io.gateways.clone(),
            neighbors: config.io.neighbors.clone(),
        };
        let mut ports = Vec::new();
        ports
            .try_reserve_exact(1 + config.ports.len())
            .map_err(|_| ENOMEM)?;
        // Every port is a kernel interface opened alike, the `io.*` one
        // first. A port with a fixed next hop owns its address in the kernel
        // (identical address ownership and prefix policy to TUN); a port
        // resolving its next hops owns its address itself (the kernel must
        // not answer for it, and Neighbor Discovery defends it), on its
        // configured prefix.
        let mut first = None;
        let mut tcp = None;
        for port in core::iter::once(&io_port).chain(&config.ports) {
            let subnet = match port.next_hop_mac {
                Some(_) => super::port_context(&port.interface, port.address, port.prefix)?,
                None => {
                    let prefix = port.prefix.ok_or(EINVAL)?;
                    (crate::ip::network(port.address, prefix).ok_or(EINVAL)?, prefix)
                }
            };
            let (io, hardware, index) =
                open_af_packet(&port.interface, port.address, config.io.receive_aggregation)?;
            if tcp.is_none() {
                tcp = Some(backend_config_family(config.tcp.clone(), &io, local)?);
            }
            let memberships = match port.address {
                IpAddr::V6(address) if port.next_hop_mac.is_none() => {
                    Some(join_groups(&io, index, address)?)
                }
                _ => None,
            };
            let mut extra = Port::ethernet(
                port.address,
                subnet,
                EthernetBackend::new(Box::new(io), hardware, port.next_hop_mac),
            )
            .resolving(&port.gateways, &port.neighbors)?;
            extra.memberships = memberships;
            if first.is_none() {
                first = Some(index);
            } else {
                extra.index = index;
            }
            ports.push(extra);
        }
        let (Some(index), Some(tcp)) = (first, tcp) else {
            return Err(EINVAL);
        };
        let secret = random_secret()?;
        let mut owner = Self::with_ports(ports, secret, tcp)?;
        owner.initialize_socket_config(config)?;
        owner.attach_backend_host(u64::from(index))?;
        owner.enable_reservations(&config.io)?;
        Ok(owner)
    }
    pub(super) fn receive_backend(
        &mut self,
        port: usize,
        out: &mut [u8],
    ) -> std::io::Result<Option<ReceivedPacket>> {
        if let Some(backend) = &mut self.ports[port].ethernet {
            return backend.io.receive_with_metadata(out);
        }
        let software = self.software_rx_enabled();
        let Some(mut packet) = self.receive_ip_backend(port, out)? else {
            return Ok(None);
        };
        packet.timestamps = PacketTimestamps {
            software: software.then(|| PacketTimestamp {
                value: timestamps::realtime(),
                source: TimestampSource::Software,
                point: TimestampPoint::UserReceive,
                clock: ntcp_io::ClockDescriptor {
                    domain: ClockDomain::Realtime,
                    unit: TimestampUnit::Nanoseconds,
                },
            }),
            hardware: None,
        };
        Ok(Some(packet))
    }
    fn receive_ip_backend(
        &mut self,
        port: usize,
        out: &mut [u8],
    ) -> std::io::Result<Option<ReceivedPacket>> {
        #[cfg(feature = "packet-test")]
        if let Some(packets) = &mut self.packets {
            return packets.receive_with_metadata(out);
        }
        match &mut self.ports[port].tun {
            Some(tun) => tun.receive_with_metadata(out),
            None => Ok(None),
        }
    }
    // Whether this owner's ports carry Ethernet frames (all ports share
    // `io.backend`), and the frame header ahead of each IP packet.
    pub(super) fn ethernet_ports(&self) -> bool {
        self.ports.first().is_some_and(|port| port.ethernet.is_some())
    }
    pub(super) fn link_offset(&self) -> usize {
        if self.ethernet_ports() { 14 } else { 0 }
    }
    // The port attached to `link`.
    pub(super) fn port_of(&self, link: ntcp_host::path::LinkId) -> Option<usize> {
        self.ports.iter().position(|port| port.link() == Some(link))
    }
    pub(super) fn packet_mark_supported(&self) -> bool {
        #[cfg(feature = "packet-test")]
        if let Some(packets) = &self.packets {
            return packets.packet_mark_supported();
        }
        self.ports.iter().all(|port| {
            port.ethernet
                .as_ref()
                .is_some_and(|b| b.io.packet_mark_supported())
        })
    }
    // The mark applies to whichever port the next packet leaves through.
    pub(super) fn set_backend_mark(&mut self, mark: u32) -> std::io::Result<()> {
        #[cfg(feature = "packet-test")]
        if let Some(packets) = &mut self.packets {
            return packets.set_packet_mark(mark);
        }
        for port in &mut self.ports {
            if let Some(backend) = &mut port.ethernet {
                backend.io.set_packet_mark(mark)?;
            } else if let Some(tun) = &mut port.tun {
                tun.set_packet_mark(mark)?;
            } else if mark != 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::Unsupported));
            }
        }
        Ok(())
    }
    // Each rejected frame consumes one iteration, just like an accepted frame.
    pub(super) fn receive_batch(&mut self, input: &mut [u8]) -> std::io::Result<()> {
        if self.egress.is_some() {
            return self.receive_scheduled(input);
        }
        for _ in 0..BUDGET {
            match self.receive_ip_packet(input)? {
                BackendReceive::Packet {
                    port,
                    bytes,
                    stamps,
                    segment_size,
                    link_multicast,
                } => self.input_link(port, bytes, stamps, segment_size, link_multicast),
                BackendReceive::Skipped => {}
                BackendReceive::Empty => break,
            }
        }
        Ok(())
    }
    // One packet from the ports in turn, starting after the port the last
    // packet came from; Empty once every port is. Transient backend errors
    // are skipped; any other error ends the batch.
    pub(super) fn receive_ip_packet<'a>(
        &mut self,
        input: &'a mut [u8],
    ) -> std::io::Result<BackendReceive<'a>> {
        let ports = self.ports.len();
        let mut found = None;
        for turn in 0..ports {
            let port = (self.receive_cursor + turn) % ports;
            match self.receive_backend(port, input) {
                Ok(Some(received)) => {
                    found = Some((port, Ok(received)));
                    break;
                }
                Ok(None) => {}
                Err(error) => {
                    found = Some((port, Err(error)));
                    break;
                }
            }
        }
        let Some((port, result)) = found else {
            return Ok(BackendReceive::Empty);
        };
        self.receive_cursor = (port + 1) % ports;
        let received = match result {
            Ok(received) => received,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::InvalidData
                        | std::io::ErrorKind::Unsupported
                ) =>
            {
                return Ok(BackendReceive::Skipped);
            }
            Err(error) => return Err(error),
        };
        let bytes = &input[..received.len];
        let (bytes, link_multicast) = if self.ports[port].ethernet.is_some() {
            let Ok(frame) = ntcp_ethernet::parse_ethernet_fragment(bytes) else {
                return Ok(BackendReceive::Skipped);
            };
            // IEEE 802 group bit: multicast, broadcast included.
            (frame.payload, frame.destination[0] & 1 != 0)
        } else {
            (bytes, false)
        };
        Ok(BackendReceive::Packet {
            port,
            bytes,
            stamps: core_stamps(received.timestamps),
            segment_size: received.tcp_segment_size,
            link_multicast,
        })
    }
    //= https://www.rfc-editor.org/rfc/rfc1191#section-2
    //= reason=Native IPv4 input validates codec output then dispatches quoted tuple/sequence to endpoint policy; tests reject wrong checksum/tuple/window and observe bounded output after valid PTB.
    //# Upon receipt of such a message (henceforth called a "Datagram Too Big" message), the
    //# source host reduces its assumed PMTU for the path.
    #[cfg(test)]
    pub(super) fn input_ip(&mut self, bytes: &[u8], stamps: ntcp::RxPacketTimestamps) {
        self.input_ip_metadata(bytes, stamps, None);
    }
    /// Managed ICMP: the single Host dispatcher answers Echo Requests and
    /// validates an error, admits it on this context, correlates its quote
    /// with the submission ledger and applies TCP policy or datagram advice.
    /// A report about a reserved owner returns unapplied; the caller retains
    /// the returned token and replays it with `Host::replay_icmp` for that
    /// exact owner generation.
    pub(super) fn input_icmp(
        &mut self,
        datagram: ntcp_host::Processed,
    ) -> Option<ntcp_host::DeferredIcmp> {
        if self.unmapped_redirect(datagram) {
            return None;
        }
        let now = self.clock().ok()?;
        match self
            .host
            .as_mut()?
            .input_icmp_datagram(&mut self.endpoint, now, datagram)
        {
            Ok(ntcp_host::IcmpDispatch::Deferred(deferred)) => Some(deferred),
            _ => None,
        }
    }
    // An IPv4 Redirect naming a new gateway the arrival port has no static
    // neighbor for: IPv4 next hops resolve only through the operator's
    // mappings (there is no ARP), so applying it would leave the
    // destination unreachable. It is discarded before the Host acts on it.
    fn unmapped_redirect(&self, datagram: ntcp_host::Processed) -> bool {
        let Some(packet) = self
            .host
            .as_ref()
            .and_then(|host| host.decode_datagram(datagram).ok())
        else {
            return false;
        };
        let (IpAddr::V4(_), Some(5), Some(gateway)) = (
            packet.ip.source,
            packet.payload.first().copied(),
            packet.payload.get(4..8),
        ) else {
            return false;
        };
        let gateway = IpAddr::V4(std::net::Ipv4Addr::new(
            gateway[0], gateway[1], gateway[2], gateway[3],
        ));
        let link = datagram.context().link();
        self.ports.iter().any(|port| {
            port.link() == Some(link)
                && matches!(port.resolution, Resolution::Static(_))
                && port.static_neighbor(gateway).is_none()
        })
    }
    /// One received IP packet addressed to the `io.*` port's link by unicast.
    pub(super) fn input_ip_metadata(
        &mut self,
        bytes: &[u8],
        stamps: ntcp::RxPacketTimestamps,
        segment_size: Option<core::num::NonZeroU16>,
    ) {
        self.input_link(0, bytes, stamps, segment_size, false);
    }
    /// Physical input on `port`. With a Host it passes framing, local
    /// authority and reassembly first; only a complete datagram is
    /// dispatched.
    pub(super) fn input_link(
        &mut self,
        port: usize,
        bytes: &[u8],
        stamps: ntcp::RxPacketTimestamps,
        segment_size: Option<core::num::NonZeroU16>,
        link_multicast: bool,
    ) {
        if self.host.is_some() {
            let mut completed = std::mem::take(&mut self.completed);
            if let Some(datagram) =
                self.receive_datagram(port, bytes, link_multicast, &mut completed)
                && let Some(datagram) = self.process_datagram(datagram)
            {
                self.input_datagram(datagram, stamps, segment_size);
            }
            self.completed = completed;
            return;
        }
        let Ok(packet) = crate::ip::parse(bytes) else {
            return;
        };
        self.input_packet(None, packet, bytes, stamps, segment_size);
    }
    /// The Host pipeline for one physical packet on `port`: a complete
    /// datagram (in `out` when reassembled) carrying that port's link, or
    /// None for a fragment held or discarded and for anything the Host
    /// refuses.
    pub(super) fn receive_datagram<'a>(
        &mut self,
        port: usize,
        bytes: &'a [u8],
        link_multicast: bool,
        out: &'a mut [u8],
    ) -> Option<ntcp_host::Datagram<'a>> {
        let now = self.clock().ok()?;
        let ingress = self.ports.get(port)?.ingress?;
        match self
            .host
            .as_mut()?
            .receive(ingress, now, bytes, link_multicast, out)
        {
            Ok(ntcp_host::Received::Datagram(datagram)) => Some(datagram),
            _ => None,
        }
    }
    /// Destination processing of one complete datagram, before it is
    /// classified, dispatched or retained (`Host::process`), with time from
    /// the characterized UTC source (`Ipv4Clock`) sampled at most once;
    /// None for a datagram the Host refuses.
    pub(super) fn process_datagram<'a>(
        &mut self,
        datagram: ntcp_host::Datagram<'a>,
    ) -> Option<ntcp_host::Processed<'a>> {
        let now = self.clock().ok()?;
        let host = self.host.as_ref()?;
        let mut recording = Recording {
            clock: &mut self.ipv4_clock,
            now,
        };
        host.process(datagram, Some(&mut recording)).ok()
    }
    /// Dispatch one processed datagram exactly like an unfragmented packet;
    /// its processed options are handed on as they are.
    pub(super) fn input_datagram(
        &mut self,
        datagram: ntcp_host::Processed,
        stamps: ntcp::RxPacketTimestamps,
        segment_size: Option<core::num::NonZeroU16>,
    ) {
        let Some(host) = &self.host else {
            return;
        };
        let ingress = datagram.context();
        let Ok(packet) = host.decode_datagram(datagram) else {
            return;
        };
        if packet.protocol
            == if packet.ip.destination.is_ipv4() {
                1
            } else {
                58
            }
        {
            // Without a retention queue a reserved owner's report is
            // dropped unapplied, as the Endpoint entry used to refuse it.
            let _ = self.input_icmp(datagram);
            return;
        }
        if segment_size.is_some()
            && !host
                .receive_capabilities(ingress)
                .is_ok_and(|caps| caps.gro)
        {
            return;
        }
        let packet = crate::ip::Packet {
            ip: packet.ip,
            traffic_class: packet.traffic_class,
            protocol: packet.protocol,
            ipv4_options: packet.options,
            payload: packet.payload,
        };
        self.input_packet(
            Some(ingress.link()),
            packet,
            datagram.bytes(),
            stamps,
            segment_size,
        );
    }
    // `arrival` is the link a Host admitted the packet on; None for a
    // Host-less fixture.
    fn input_packet(
        &mut self,
        arrival: Option<ntcp_host::path::LinkId>,
        p: crate::ip::Packet,
        bytes: &[u8],
        stamps: ntcp::RxPacketTimestamps,
        segment_size: Option<core::num::NonZeroU16>,
    ) {
        if !self.owns(p.ip.destination) {
            return;
        }
        if p.protocol == 6 {
            let Ok(now) = self.clock() else {
                return;
            };
            let _ = self.input_segmented(
                now,
                arrival,
                p.ip,
                p.traffic_class,
                p.ipv4_options,
                p.payload,
                stamps,
                segment_size,
            );
        } else if let Ok(feedback) = ntcp_icmp::decode_icmp(bytes) {
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
            //= reason=Validated native IPv4 ICMP is correlated using its quoted outbound tuple and live sequence at Endpoint; soft errors stay nonterminal, PTB keeps its exact-sent PMTU validation.
            //# TCP implementations MUST act on an ICMP error message passed up from
            //# the IP layer, directing it to the connection that created the error
            //# (MUST-54).
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
            //= reason=SourceQuench is discarded before time, connection, error-report or PMTU processing; packet admission only validates its framing.
            //# TCP implementations MUST silently discard any received ICMP Source
            //# Quench messages (MUST-55).
            if feedback.kind == ntcp_icmp::FeedbackKind::SourceQuench {
                return;
            }
            let Ok(now) = self.clock() else {
                return;
            };
            let q = feedback.quoted;
            let tuple = ntcp::Tuple {
                local: SocketAddr::new(q.ip.source, q.source_port),
                remote: SocketAddr::new(q.ip.destination, q.destination_port),
            };
            if feedback.kind == ntcp_icmp::FeedbackKind::PacketTooBig {
                let _ = self.endpoint.pmtu_feedback(
                    now,
                    tuple,
                    q.sequence,
                    q.ip_packet_len,
                    q.ip_header_len,
                    feedback.candidate_mtu.unwrap_or(0),
                );
            } else if let Some(error) = feedback
                .ipv4_network_error()
                .or_else(|| feedback.ipv6_network_error())
            {
                let _ = self.endpoint.network_error(now, tuple, q.sequence, error);
            }
        }
    }

    pub(super) fn poll_backend_timestamps(&mut self) -> std::io::Result<()> {
        for backend in self.ports.iter_mut().filter_map(|port| port.ethernet.as_mut()) {
            for _ in 0..BUDGET {
                let completion = match backend.io.poll_tx_timestamp() {
                    Ok(Some(completion)) => completion,
                    Ok(None) => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
                        while !backend.pending.is_empty() {
                            backend.cancel_oldest(&mut self.endpoint)?;
                        }
                        break;
                    }
                    Err(e) => return Err(e),
                };
                let Some(index) = backend
                    .pending
                    .iter()
                    .position(|p| p.0 == completion.cookie)
                else {
                    continue;
                };
                let entry = &mut backend.pending[index];
                let source = match completion.timestamp.source {
                    TimestampSource::Software => {
                        entry.2 = false;
                        ntcp::TxTimestampSource::Software
                    }
                    TimestampSource::Hardware => {
                        entry.3 = false;
                        ntcp::TxTimestampSource::Hardware
                    }
                };
                if let Some(stamp) = core_stamp(completion.timestamp) {
                    let _ = self.endpoint.report_tx_timestamp(
                        entry.1,
                        source,
                        stamp.value,
                        stamp.clock,
                    );
                } else {
                    let _ = self.endpoint.cancel_tx_timestamp(entry.1, source);
                }
                if !entry.2 && !entry.3 {
                    backend.pending.remove(index);
                }
            }
        }
        let pair = ClockPair::sample(self).map_err(std::io::Error::from_raw_os_error)?;
        self.drain_timestamps(pair);
        self.cancel_unused_backend_timestamps();
        Ok(())
    }
    pub(super) fn cancel_unused_backend_timestamps(&mut self) {
        for port in 0..self.ports.len() {
            let Some(mut backend) = self.ports[port].ethernet.take() else {
                continue;
            };
            backend.pending.retain(|&(cookie, token, sw, hw)| {
                let needed = self.backend_sources(token);
                if (needed.0 && sw) || (needed.1 && hw) {
                    true
                } else {
                    let _ = backend.io.cancel_tx_timestamp(cookie);
                    false
                }
            });
            self.ports[port].ethernet = Some(backend);
        }
    }
}

impl EthernetBackend {
    fn cancel_sources(endpoint: &mut Endpoint, token: ntcp::TxTimestampToken, sw: bool, hw: bool) {
        for (enabled, source) in [
            (sw, ntcp::TxTimestampSource::Software),
            (hw, ntcp::TxTimestampSource::Hardware),
        ] {
            if enabled {
                let _ = endpoint.cancel_tx_timestamp(token, source);
            }
        }
    }
    fn cancel_oldest(&mut self, endpoint: &mut Endpoint) -> std::io::Result<()> {
        self.evict_oldest()?;
        self.finish_cancellations(endpoint);
        Ok(())
    }
    fn evict_oldest(&mut self) -> std::io::Result<()> {
        let (cookie, token, sw, hw) = self.pending[0];
        self.io.cancel_tx_timestamp(cookie)?;
        self.pending.remove(0);
        self.cancelled.push((token, sw, hw));
        Ok(())
    }
    /// Apply the Endpoint side of cancellations recorded by `transmit_frame`.
    pub(super) fn finish_cancellations(&mut self, endpoint: &mut Endpoint) {
        for (token, sw, hw) in self.cancelled.drain(..) {
            Self::cancel_sources(endpoint, token, sw, hw);
        }
    }
    /// One physical call, including its timestamp fallback. Endpoint-side
    /// cancellations are only recorded; the caller applies them with
    /// `finish_cancellations` once the call's outcome is finalized.
    pub(super) fn transmit_frame(
        &mut self,
        token: Option<ntcp::TxTimestampToken>,
        sources: (bool, bool),
        frame: &[u8],
    ) -> std::io::Result<TxOutcome> {
        let requested = usize::from(sources.0) + usize::from(sources.1);
        if requested == 0 {
            return self.io.transmit(frame);
        }
        let token = token.unwrap();
        let capabilities = self.io.timestamp_capabilities();
        let capacity = capabilities.tx_completion_capacity.min(timestamps::PHASES);
        if requested <= capacity
            && self.next_cookie != u64::MAX
            && (!sources.0 || capabilities.tx_software)
            && (!sources.1 || capabilities.tx_hardware)
        {
            // Count sources, including callbacks queued inside IO until polled.
            // Ordered removal preserves oldest-submission eviction across sources.
            while self
                .pending
                .iter()
                .map(|p| usize::from(p.2) + usize::from(p.3))
                .sum::<usize>()
                + requested
                > capacity
            {
                // Cancellation errors are not synchronous packet rejection.
                self.evict_oldest().map_err(std::io::Error::other)?;
            }
            let cookie = self.next_cookie;
            match self.io.transmit_with_timestamp(
                frame,
                ntcp_io::TxTimestampRequest {
                    cookie,
                    software: sources.0,
                    hardware: sources.1,
                },
            ) {
                Ok(outcome) => {
                    if outcome == TxOutcome::Submitted {
                        self.pending.push((cookie, token, sources.0, sources.1));
                        self.next_cookie += 1;
                    }
                    return Ok(outcome);
                }
                // PacketIo guarantees Unsupported before submission (also ID exhaustion).
                Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {}
                Err(e) => return Err(e),
            }
        }
        self.cancelled.push((token, sources.0, sources.1));
        self.io.transmit(frame)
    }
}

#[cfg(test)]
#[path = "runtime_backend_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "runtime_accept_tests.rs"]
mod accept_tests;

#[cfg(test)]
#[path = "runtime_shared_tests.rs"]
mod shared_tests;
