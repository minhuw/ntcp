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
    pub(super) io: Box<dyn PacketIo + Send>,
    pub(super) local: [u8; 6],
    pub(super) next_hop: [u8; 6],
    next_cookie: u64,
    pending: Vec<(u64, ntcp::TxTimestampToken, bool, bool)>,
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
pub(super) fn core_stamps(stamps: PacketTimestamps) -> ntcp::RxPacketTimestamps {
    ntcp::RxPacketTimestamps {
        software: stamps.software.and_then(core_stamp),
        hardware: stamps.hardware.and_then(core_stamp),
    }
}
// Startup only: local_ip_mtu may block on the backend's control plane.
pub(super) fn backend_config(
    mut config: EndpointConfig,
    io: &dyn PacketIo,
) -> Result<EndpointConfig> {
    let mtu = io
        .local_ip_mtu()
        .map_err(|e| e.raw_os_error().unwrap_or(EIO))?
        .ok_or(EOPNOTSUPP)?;
    if mtu < 68 {
        return Err(EINVAL);
    }
    let overhead = if io.layer() == ntcp_io::PacketLayer::Ethernet {
        14
    } else {
        0
    };
    let ip_capacity = io
        .max_packet_len()
        .unwrap_or(65535 + overhead)
        .checked_sub(overhead)
        .ok_or(EINVAL)?
        .min(65535);
    if ip_capacity < 68 {
        return Err(EINVAL);
    }
    config.connection.send_ip_payload_limit = config
        .connection
        .send_ip_payload_limit
        .min((ip_capacity - 20) as u16);
    config.connection.pmtud = Some(ntcp::PmtudConfig::new(mtu));
    config.validate().map_err(engine)?;
    Ok(config)
}

impl Owner {
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
        let mut io = AfPacket::bind(index, ntcp_ethernet::ETHERTYPE_IPV4)
            .map_err(|e| e.raw_os_error().unwrap_or(EIO))?;
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
        let mut secret = [0u8; 32];
        let mut at = 0;
        while at < secret.len() {
            let n = unsafe {
                syscall(
                    SYS_getrandom,
                    secret[at..].as_mut_ptr(),
                    secret.len() - at,
                    0,
                )
            };
            if n < 0 {
                if errno() == EINTR {
                    continue;
                }
                return Err(errno());
            }
            if n == 0 {
                return Err(EIO);
            }
            at += n as usize;
        }
        let mut owner = Self::with_config(
            local,
            subnet,
            secret,
            None,
            backend_config(config.tcp.clone(), &io)?,
        )?;
        owner.socket_policy = config.socket;
        owner.ethernet = Some(EthernetBackend {
            io: Box::new(io),
            local: hardware,
            next_hop,
            next_cookie: 1,
            pending: Vec::with_capacity(timestamps::PHASES),
        });
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
        let Some(len) = self.receive_ip_backend(out)? else {
            return Ok(None);
        };
        Ok(Some(ReceivedPacket {
            len,
            timestamps: PacketTimestamps {
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
            },
        }))
    }
    fn receive_ip_backend(&mut self, out: &mut [u8]) -> std::io::Result<Option<usize>> {
        #[cfg(feature = "packet-test")]
        if let Some(packets) = &mut self.packets {
            return packets.receive(out);
        }
        match &mut self.tun {
            Some(tun) => tun.receive(out),
            None => Ok(None),
        }
    }
    pub(super) fn transmit_ip_backend(&mut self, bytes: &[u8]) -> std::io::Result<TxOutcome> {
        #[cfg(feature = "packet-test")]
        if let Some(packets) = &mut self.packets {
            return packets.transmit(bytes);
        }
        match &mut self.tun {
            Some(tun) => tun.transmit(bytes),
            None => Err(std::io::Error::from_raw_os_error(EIO)),
        }
    }
    // Each rejected frame consumes one iteration, just like an accepted frame.
    pub(super) fn receive_batch(&mut self, input: &mut [u8]) -> std::io::Result<()> {
        if self.egress.is_some() {
            return self.receive_scheduled(input);
        }
        // Keep RX in the backend's bounded queue while the endpoint is reserved.
        if self.reservation.is_some() {
            return Ok(());
        }
        for _ in 0..BUDGET {
            match self.receive_backend(input) {
                Ok(Some(received)) => {
                    let bytes = &input[..received.len];
                    let bytes = if self.ethernet.is_some() {
                        let Ok(frame) = ntcp_ethernet::parse_ethernet(bytes) else {
                            continue;
                        };
                        frame.payload
                    } else {
                        bytes
                    };
                    self.input_ip(bytes, core_stamps(received.timestamps));
                }
                Ok(None) => break,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::Interrupted
                            | std::io::ErrorKind::InvalidData
                            | std::io::ErrorKind::Unsupported
                    ) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    //= https://www.rfc-editor.org/rfc/rfc1191#section-2
    //= reason=Native IPv4 input validates codec output then dispatches quoted tuple/sequence to endpoint policy; tests reject wrong checksum/tuple/window and observe bounded output after valid PTB.
    //# Upon receipt of such a message (henceforth called a "Datagram Too Big" message), the
    //# source host reduces its assumed PMTU for the path.
    pub(super) fn input_ip(&mut self, bytes: &[u8], stamps: ntcp::RxPacketTimestamps) {
        let Ok(p) = ntcp_ip::parse(bytes, false) else {
            return;
        };
        if p.ip.destination != IpAddr::V4(self.local) {
            return;
        }
        if p.protocol == 6 {
            let _ = self.input_stamped(self.now(), p.ip, p.traffic_class, p.payload, stamps);
        } else if let Ok(feedback) = ntcp_icmp::decode_icmp(bytes)
            && feedback.kind == ntcp_icmp::FeedbackKind::PacketTooBig
        {
            let q = feedback.quoted;
            let _ = self.endpoint.pmtu_feedback(
                self.now(),
                ntcp::Tuple {
                    local: SocketAddr::new(q.ip.source, q.source_port),
                    remote: SocketAddr::new(q.ip.destination, q.destination_port),
                },
                q.sequence,
                q.ip_packet_len,
                q.ip_header_len,
                feedback.candidate_mtu.unwrap_or(0),
            );
        }
    }
    pub(super) fn transmit_ethernet(&mut self) -> std::io::Result<TxOutcome> {
        let sources = self
            .pending_token
            .map(|token| self.backend_sources(token))
            .unwrap_or_default();
        let result = self.ethernet.as_mut().unwrap().transmit(
            &mut self.endpoint,
            self.pending_token,
            sources,
            self.pending_packet.as_ref().unwrap(),
        );
        // Cancellation frees adapter reservations exactly once, via native events.
        self.drain_timestamps(ClockPair::sample(self));
        result
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
        let (cookie, token, sw, hw) = self.pending[0];
        self.io.cancel_tx_timestamp(cookie)?;
        self.pending.remove(0);
        Self::cancel_sources(endpoint, token, sw, hw);
        Ok(())
    }
    fn transmit(
        &mut self,
        endpoint: &mut Endpoint,
        token: Option<ntcp::TxTimestampToken>,
        sources: (bool, bool),
        packet: &[u8],
    ) -> std::io::Result<TxOutcome> {
        let mut frame = vec![0; (packet.len() + 14).max(60)];
        let n = ntcp_ethernet::encode_ethernet(
            &mut frame,
            self.local,
            self.next_hop,
            ntcp_ethernet::ETHERTYPE_IPV4,
            packet,
        )
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
        self.transmit_frame(endpoint, token, sources, &frame[..n])
    }
    pub(super) fn transmit_frame(
        &mut self,
        endpoint: &mut Endpoint,
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
                self.cancel_oldest(endpoint)
                    .map_err(std::io::Error::other)?;
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
        Self::cancel_sources(endpoint, token, sources.0, sources.1);
        self.io.transmit(frame)
    }
}

#[cfg(test)]
#[path = "runtime_backend_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "runtime_accept_tests.rs"]
mod accept_tests;
