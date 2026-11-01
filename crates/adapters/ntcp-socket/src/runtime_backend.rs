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

pub(super) struct EthernetBackend {
    pub(super) io: Box<dyn PacketIo>,
    pub(super) local: [u8; 6],
    pub(super) next_hop: [u8; 6],
    next_cookie: u64,
    pending: Vec<(u64, ntcp::TxTimestampToken, bool, bool)>,
    // Endpoint-side timestamp cancellations recorded during one physical
    // call, which runs inside the Host submission transaction while the Host
    // holds the Endpoint. Drained by `finish_cancellations` after every call:
    // at most every pending entry (<= PHASES) plus the fallback request.
    cancelled: Vec<(ntcp::TxTimestampToken, bool, bool)>,
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
        bytes: &'a [u8],
        stamps: ntcp::RxPacketTimestamps,
        segment_size: Option<core::num::NonZeroU16>,
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

impl Owner {
    // Complete the constructor using the actual configured one-port backend.
    // InterfaceKey is an embedding assignment within an independently minted
    // context; external ports need no fabricated kernel interface identity.
    pub(super) fn attach_backend_host(&mut self, interface: u64) -> Result<()> {
        if self.host.is_some() {
            return Err(EINVAL);
        }
        let io: &dyn PacketIo = if let Some(backend) = &self.ethernet {
            &*backend.io
        } else if let Some(tun) = &self.tun {
            tun
        } else {
            #[cfg(feature = "packet-test")]
            {
                self.packets
                    .as_ref()
                    .map(|io| io as &dyn PacketIo)
                    .ok_or(EOPNOTSUPP)?
            }
            #[cfg(not(feature = "packet-test"))]
            return Err(EOPNOTSUPP);
        };
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
        let mut identity = [0; 16];
        ports::fill(&mut identity)?;
        use ntcp_host::{Forwarding, Ipv4Receive, Ipv6Receive, ReceiveCapabilities, path};
        // Occupied transports + provisional TIME-WAIT generation + stateless
        // lane + one serialized live-class migration. No peer-created routes.
        let (paths, limits) =
            ntcp_host::managed_limits(&self.defaults, 1, 1, 1, 1, 1).map_err(host_error)?;
        let mut host = ntcp_host::Host::new(
            path::ContextId::new(u128::from_ne_bytes(identity)),
            paths,
            limits,
            self.endpoint.caller_timebase(),
        )
        .map_err(host_error)?;
        let forwarder = path::ForwarderId(1);
        let ingress = host
            .register_link(
                path::InterfaceKey(interface),
                mtu,
                ReceiveCapabilities {
                    max_ip_packet,
                    ipv4: if self.local.is_ipv4() {
                        Ipv4Receive::Options {
                            source_routes: false,
                        }
                    } else {
                        Ipv4Receive::Disabled
                    },
                    ipv6: if self.local.is_ipv6() {
                        Ipv6Receive::BaseHeader
                    } else {
                        Ipv6Receive::Disabled
                    },
                    // The current input adapter accepts validated segment-size metadata
                    // from this PacketIo. This does not promise aggregation offload.
                    gro: true,
                },
                Forwarding::Forwarder(forwarder),
            )
            .map_err(host_error)?;
        host.register_source(
            path::ScopedAddress::new(self.local, None).map_err(|e| host_error(e.into()))?,
            ingress.link(),
        )
        .map_err(host_error)?;
        let network = if self.local.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        };
        host.add_route(path::Route {
            destination: path::IpPrefix::new(network, 0).map_err(|e| host_error(e.into()))?,
            source: None,
            dscp: None,
            link: ingress.link(),
            next_hop: path::NextHop::Forwarder(forwarder),
            metric: 0,
        })
        .map_err(host_error)?;
        host.attach(&mut self.endpoint).map_err(host_error)?;
        self.ingress = Some(ingress);
        self.host = Some(host);
        Ok(())
    }
    pub(super) fn external_backend(
        config: &SocketConfig,
        backend: crate::EthernetPacketIo,
    ) -> Result<Self> {
        if backend.io.layer() != ntcp_io::PacketLayer::Ethernet {
            return Err(EINVAL);
        }
        // A userspace-owned port need not have a kernel interface/address.
        // The embedding host explicitly assigns its address and subnet instead
        // of consulting getifaddrs (used by borrowed TUN/AF_PACKET interfaces).
        let local = config.io.address;
        let prefix = config.io.prefix.ok_or(EINVAL)?;
        let network = crate::ip::network(local, prefix).ok_or(EINVAL)?;
        if !unicast(local) {
            return Err(EADDRNOTAVAIL);
        }
        if crate::ip::network_or_broadcast(local, prefix) {
            return Err(EADDRNOTAVAIL);
        }
        let tcp = backend_config_family(config.tcp.clone(), &*backend.io, local)?;
        let secret = random_secret()?;
        let mut owner = Self::with_config(config.io.address, (network, prefix), secret, None, tcp)?;
        owner.initialize_socket_config(config)?;
        owner.ethernet = Some(EthernetBackend {
            io: backend.io,
            local: backend.local_mac,
            next_hop: backend.next_hop_mac,
            next_cookie: 1,
            pending: Vec::with_capacity(timestamps::PHASES),
            cancelled: Vec::with_capacity(timestamps::PHASES + 1),
        });
        owner.attach_backend_host(1)?;
        owner.enable_egress(config.io.egress_capacity, config.io.gso)?;
        owner.reservation_timeout_us = u64::from(config.io.output_reservation_timeout_ms) * 1000;
        Ok(owner)
    }

    pub(super) fn af_packet(config: &SocketConfig) -> Result<Self> {
        let name = &config.io.interface;
        let local = config.io.address;
        let subnet = context(&config.io)?; // Identical address ownership and prefix policy to TUN.
        let name = CString::new(name.as_str()).map_err(|_| EINVAL)?;
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            return Err(errno());
        }
        let next_hop = config.io.next_hop_mac.ok_or(EINVAL)?;
        let mut io = AfPacket::bind(index, crate::ip::ether_type(local))
            .map_err(|e| e.raw_os_error().unwrap_or(EIO))?;
        if config.io.receive_aggregation {
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
            device_clock: Some(u64::from(index)),
            tx_completion_capacity: timestamps::PHASES,
        })
        .map_err(|e| e.raw_os_error().unwrap_or(EOPNOTSUPP))?;
        let secret = random_secret()?;
        let mut owner = Self::with_config(
            local,
            subnet,
            secret,
            None,
            backend_config_family(config.tcp.clone(), &io, local)?,
        )?;
        owner.initialize_socket_config(config)?;
        owner.ethernet = Some(EthernetBackend {
            io: Box::new(io),
            local: hardware,
            next_hop,
            next_cookie: 1,
            pending: Vec::with_capacity(timestamps::PHASES),
            cancelled: Vec::with_capacity(timestamps::PHASES + 1),
        });
        owner.attach_backend_host(u64::from(index))?;
        owner.enable_reservations(&config.io, index)?;
        Ok(owner)
    }
    pub(super) fn receive_backend(
        &mut self,
        out: &mut [u8],
    ) -> std::io::Result<Option<ReceivedPacket>> {
        if let Some(backend) = &mut self.ethernet {
            return backend.io.receive_with_metadata(out);
        }
        let software = self.software_rx_enabled();
        let Some(mut packet) = self.receive_ip_backend(out)? else {
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
    fn receive_ip_backend(&mut self, out: &mut [u8]) -> std::io::Result<Option<ReceivedPacket>> {
        #[cfg(feature = "packet-test")]
        if let Some(packets) = &mut self.packets {
            return packets.receive_with_metadata(out);
        }
        match &mut self.tun {
            Some(tun) => tun.receive_with_metadata(out),
            None => Ok(None),
        }
    }
    pub(super) fn packet_mark_supported(&self) -> bool {
        #[cfg(feature = "packet-test")]
        if let Some(packets) = &self.packets {
            return packets.packet_mark_supported();
        }
        self.ethernet
            .as_ref()
            .is_some_and(|b| b.io.packet_mark_supported())
    }
    pub(super) fn set_backend_mark(&mut self, mark: u32) -> std::io::Result<()> {
        #[cfg(feature = "packet-test")]
        if let Some(packets) = &mut self.packets {
            return packets.set_packet_mark(mark);
        }
        if let Some(backend) = &mut self.ethernet {
            return backend.io.set_packet_mark(mark);
        }
        if let Some(tun) = &mut self.tun {
            return tun.set_packet_mark(mark);
        }
        if mark == 0 {
            Ok(())
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }
    }
    pub(super) fn output_mark(&self, owner: Option<ConnectionId>) -> u32 {
        owner
            .and_then(|cid| self.connection_options.iter().find(|p| p.0 == cid))
            .map_or(0, |p| p.4)
    }
    // Each rejected frame consumes one iteration, just like an accepted frame.
    pub(super) fn receive_batch(&mut self, input: &mut [u8]) -> std::io::Result<()> {
        if self.egress.is_some() {
            return self.receive_scheduled(input);
        }
        for _ in 0..BUDGET {
            match self.receive_ip_packet(input)? {
                BackendReceive::Packet {
                    bytes,
                    stamps,
                    segment_size,
                } => self.input_ip_metadata(bytes, stamps, segment_size),
                BackendReceive::Skipped => {}
                BackendReceive::Empty => break,
            }
        }
        Ok(())
    }
    // Transient backend errors are skipped; any other error ends the batch.
    pub(super) fn receive_ip_packet<'a>(
        &mut self,
        input: &'a mut [u8],
    ) -> std::io::Result<BackendReceive<'a>> {
        let received = match self.receive_backend(input) {
            Ok(Some(received)) => received,
            Ok(None) => return Ok(BackendReceive::Empty),
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
        let bytes = if self.ethernet.is_some() {
            let Ok(frame) = ntcp_ethernet::parse_ethernet(bytes) else {
                return Ok(BackendReceive::Skipped);
            };
            frame.payload
        } else {
            bytes
        };
        Ok(BackendReceive::Packet {
            bytes,
            stamps: core_stamps(received.timestamps),
            segment_size: received.tcp_segment_size,
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
    /// Managed ICMP: the single Host dispatcher validates the error, admits
    /// it on this context, correlates its quote with the submission ledger and
    /// applies TCP policy or datagram advice. A report about a reserved owner
    /// returns unapplied; the caller retains the returned token and replays it
    /// with `Host::replay_icmp` for that exact owner generation.
    pub(super) fn input_icmp(&mut self, bytes: &[u8]) -> Option<ntcp_host::DeferredIcmp> {
        let now = self.now();
        let ingress = self.ingress?;
        match self
            .host
            .as_mut()?
            .input_icmp(&mut self.endpoint, ingress, now, bytes)
        {
            Ok(ntcp_host::IcmpDispatch::Deferred(deferred)) => Some(deferred),
            _ => None,
        }
    }
    pub(super) fn input_ip_metadata(
        &mut self,
        bytes: &[u8],
        stamps: ntcp::RxPacketTimestamps,
        segment_size: Option<core::num::NonZeroU16>,
    ) {
        let p = if let Some(host) = &self.host {
            let Some(ingress) = self.ingress else {
                return;
            };
            let Ok(packet) = host.decode_ingress(ingress, bytes) else {
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
                let _ = self.input_icmp(bytes);
                return;
            }
            if segment_size.is_some()
                && !host
                    .receive_capabilities(ingress)
                    .is_ok_and(|caps| caps.gro)
            {
                return;
            }
            crate::ip::Packet {
                ip: packet.ip,
                traffic_class: packet.traffic_class,
                protocol: packet.protocol,
                // Keep the native adapter's existing known-option policy;
                // complete destination processing remains a separate feature.
                ipv4_options: packet.options.unrecognized(),
                payload: packet.payload,
            }
        } else {
            let Ok(packet) = crate::ip::parse(bytes) else {
                return;
            };
            packet
        };
        if p.ip.destination != self.local {
            return;
        }
        if p.protocol == 6 {
            let _ = self.input_segmented(
                self.now(),
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
            let q = feedback.quoted;
            let tuple = ntcp::Tuple {
                local: SocketAddr::new(q.ip.source, q.source_port),
                remote: SocketAddr::new(q.ip.destination, q.destination_port),
            };
            if feedback.kind == ntcp_icmp::FeedbackKind::PacketTooBig {
                let _ = self.endpoint.pmtu_feedback(
                    self.now(),
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
                let _ = self
                    .endpoint
                    .network_error(self.now(), tuple, q.sequence, error);
            }
        }
    }

    pub(super) fn poll_backend_timestamps(&mut self) -> std::io::Result<()> {
        if let Some(backend) = &mut self.ethernet {
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
        self.drain_timestamps(ClockPair::sample(self));
        self.cancel_unused_backend_timestamps();
        Ok(())
    }
    pub(super) fn cancel_unused_backend_timestamps(&mut self) {
        let Some(mut backend) = self.ethernet.take() else {
            return;
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
        self.ethernet = Some(backend);
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
