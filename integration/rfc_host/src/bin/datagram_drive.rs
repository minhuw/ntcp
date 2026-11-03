// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// Harness-only datagram driver for the isolated ICMP cases. One ordinary
// Host + Endpoint drive the router namespace's TUN exactly as an embedding
// would, through public APIs only: one Host UDP flow to the Linux peer, the
// Host's operational DatagramLimits and the Echo adjunct. The harness
// chooses only what each send is (mode, size) and how long ingress, the
// change service and the ICMP output drain are serviced afterwards, so a
// capture can attribute every packet. Nothing here is a transport knob.
//
// Run as: datagram_drive TUN_NAME LOCAL_IP PEER_SOCKET_ADDR INITIAL
//         PEER_REASSEMBLY ADJUNCT_PATHS, then on stdin:
//   send MODE SIZE SALT WAIT_MS  one udp_send_datagram of SIZE payload
//                                octets (MODE fragment|refuse|probe), then
//                                WAIT_MS of ordinary service
//   serve WAIT_MS                ordinary service only
//   neighbor DSCP                add a second route (same link and next hop,
//                                selected by DSCP) and open a second flow to
//                                the peer with that DSCP, in Fragment mode
//                                with the stated peer reassembly capacity
//   sendvia FLOW MODE SIZE SALT WAIT_MS
//                                as send, through flow main|neighbor
//   disable ROUTE                disable discovery on route main|neighbor
//                                through the Host owner's administration
//                                capability (one admin_apply transaction)
//   report N OUTCOME             report the outcome (success|isolated-loss|
//                                timeout|inconclusive) of the Nth Probe-mode
//                                receipt (from 0, in issue order) with
//                                Host::udp_report_probe, as an application
//                                that learned it from its own receiver would
//   quit
// INITIAL is the connectionless initial effective PMTU for the local family
// and PEER_REASSEMBLY the peer's reassembly capacity, both complete IP
// octets: deployment configuration stated per case (and recorded by the
// harness). ADJUNCT_PATHS sizes the Echo adjunct (0 disables it).
//
// Identifier continuity (decision D14): the harness creates the namespace,
// the TUN and LOCAL_IP for this run, so nothing emitted from LOCAL_IP
// before; the driver asserts that freshness (Continuity::QuietFor with no
// earlier emission) and reports the assertion in its ready line.
use ntcp::{Endpoint, EndpointConfig, EndpointError};
use ntcp_host::{
    AdjunctCounters, BackendOutcome, Continuity, DatagramReport, Host, IngressContext,
    ProbeReceipt, ProbeRecord, Received, UdpDatagramLimits, UdpEvent, UdpFlowId, UdpProbeOutcome,
    UdpSend, UdpSendMode, path,
};
use ntcp_io::{PacketIo, TxOutcome};
use ntcp_io_tun::Tun;
use std::{
    io::{self, BufRead, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::AsRawFd,
    time::Instant,
};

const MTU: usize = 1500;
const BUDGET: usize = 32;
const MAX_IP_PACKET: usize = 65575;
const LOCAL_PORT: u16 = 18083;
// The largest datagram each family carries (IPv4 Total Length; IPv6 Payload
// Length after the 40-octet header).
const IPV4_DATAGRAM: usize = 65535;
const IPV6_DATAGRAM: usize = 65575;

fn other(message: String) -> io::Error {
    io::Error::other(message)
}
fn host_error(error: ntcp_host::Error) -> io::Error {
    other(format!("IP host: {error:?}"))
}
fn engine(error: EndpointError) -> io::Error {
    other(format!("TCP engine: {error:?}"))
}
fn emit(line: String) {
    println!("{line}");
    io::stdout().flush().unwrap();
}
fn pattern(n: usize, salt: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 31 + salt) % 251) as u8).collect()
}
fn opt(value: Option<impl std::fmt::Display>) -> String {
    value.map_or_else(|| "null".into(), |v| v.to_string())
}
fn text(value: impl std::fmt::Debug) -> String {
    format!("{:?}", format!("{value:?}"))
}

fn limits_json(limits: &UdpDatagramLimits) -> String {
    format!(
        "{{\"mode\":{},\"peer_capability\":{},\"path\":{},\"version\":{},\"mms_s\":{},\
         \"unfragmented_payload\":{},\"effective_size\":{},\"effective_payload\":{},\
         \"fragmentable_payload\":{},\"max_payload\":{},\"guarantee\":{},\"guarantee_stated\":{}}}",
        text(limits.send.mode),
        opt(limits.send.peer_capability),
        text(limits.path.path),
        limits.path.version,
        limits.path.mms_s,
        limits.unfragmented_payload,
        limits.effective_size,
        limits.effective_payload,
        limits.fragmentable_payload,
        limits.max_payload,
        limits.guarantee,
        limits.guarantee_stated
    )
}

fn probe_json(probe: &ProbeRecord) -> String {
    format!(
        "{{\"definite\":{},\"flow_generation\":{},\"path\":{},\"version\":{},\
         \"negative_revision\":{},\"size\":{},\"above\":{},\"submitted_at\":{}}}",
        probe.definite,
        probe.flow_generation,
        text(probe.path),
        probe.version,
        probe.negative_revision,
        probe.size,
        opt(probe.above),
        probe.submitted_at
    )
}

fn report_json(report: &DatagramReport) -> String {
    format!(
        "{{\"ip_len\":{},\"fragments\":{},\"submitted\":{},\"possibly_submitted\":{},\
         \"terminal\":{},\"identification\":{},\"probe\":{}}}",
        report.ip_len,
        report.fragments,
        report.submitted,
        report.possibly_submitted,
        report.terminal.map_or_else(|| "null".into(), text),
        opt(report.identification),
        report
            .probe
            .as_ref()
            .map_or_else(|| "null".into(), probe_json)
    )
}

fn counters_json(c: &AdjunctCounters) -> String {
    format!(
        "{{\"probes\":{},\"confirmed\":{},\"lost\":{},\"too_big\":{},\"unmatched_replies\":{},\
         \"converged\":{},\"demand_dropped\":{},\"not_sent\":{}}}",
        c.probes,
        c.confirmed,
        c.lost,
        c.too_big,
        c.unmatched_replies,
        c.converged,
        c.demand_dropped,
        c.not_sent
    )
}

fn event_json(event: &UdpEvent) -> String {
    match event {
        UdpEvent::PacketTooBig {
            remote,
            mtu,
            dropped_len,
        } => format!(
            "{{\"kind\":\"packet_too_big\",\"remote\":\"{remote}\",\"mtu\":{},\"dropped_len\":{dropped_len}}}",
            opt(*mtu)
        ),
        UdpEvent::NetworkError { remote, error } => format!(
            "{{\"kind\":\"network_error\",\"remote\":\"{remote}\",\"error\":{}}}",
            text(error)
        ),
    }
}

fn mode(name: &str) -> io::Result<UdpSendMode> {
    match name {
        "fragment" => Ok(UdpSendMode::Fragment),
        "refuse" => Ok(UdpSendMode::Refuse),
        "probe" => Ok(UdpSendMode::Probe),
        _ => Err(other(format!("unknown mode {name}"))),
    }
}

// The physical TUN call as the Host transaction's backend outcome.
fn transmit(tun: &mut Tun, frame: &[u8]) -> BackendOutcome {
    match tun.transmit(frame) {
        Ok(TxOutcome::Submitted) => BackendOutcome::Submitted,
        Ok(TxOutcome::WouldBlock | TxOutcome::Rejected) => BackendOutcome::WouldBlock,
        Err(error) if error.kind() == io::ErrorKind::Interrupted => BackendOutcome::WouldBlock,
        Err(_) => BackendOutcome::Unknown,
    }
}

struct Network {
    host: Host,
    ingress: IngressContext,
    tun: Tun,
    flow: UdpFlowId,
    send: UdpSend,
    // The default route, and the neighbor route and flow once added.
    route: path::RouteId,
    neighbor: Option<(path::RouteId, UdpFlowId)>,
    administration: ntcp_host::Administration,
    start: Instant,
    frame: Vec<u8>,
    completed: Vec<u8>,
    output: Vec<u8>,
    received: Vec<u8>,
    events: Vec<UdpEvent>,
    // UDP datagrams the flow received from the peer (none are expected).
    datagrams: usize,
    // Every receipt a definite Probe-mode submission returned, in order
    // (bounded by the commands the harness sends).
    receipts: Vec<ProbeReceipt>,
}

impl Network {
    fn now(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }

    #[allow(clippy::too_many_arguments)]
    fn attach(
        endpoint: &mut Endpoint,
        config: &EndpointConfig,
        local: IpAddr,
        peer: SocketAddr,
        initial: u32,
        peer_reassembly: u32,
        adjunct: usize,
        tun: Tun,
        start: Instant,
    ) -> io::Result<Self> {
        let ipv4 = local.is_ipv4();
        let mut identity = [0u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut identity)?;
        let (paths, mut limits) =
            ntcp_host::managed_limits(config, 1, 1, 1, 2, 1).map_err(host_error)?;
        let (largest, header) = if ipv4 {
            (IPV4_DATAGRAM, 20)
        } else {
            (IPV6_DATAGRAM, 40)
        };
        let lifetime = ntcp_host::DEFAULT_LIFETIME_SECONDS;
        let mut connectionless = ntcp_host::ConnectionlessSizing::default();
        if ipv4 {
            connectionless.ipv4 = initial;
        } else {
            connectionless.ipv6 = initial;
        }
        limits.datagrams = ntcp_host::DatagramLimits {
            // The largest datagram in fragments of the smallest link each
            // family must support (68 / 1280 octets).
            max_fragments: (largest - header).div_ceil(if ipv4 { 48 } else { (1280 - 48) & !7 }),
            identifiers: ntcp_host::IdentifierLimits {
                lifetime_seconds: lifetime,
                // One flow to one peer, plus Echo Replies to it.
                ipv4_tuples: if ipv4 { 4 } else { 0 },
                ipv6_leases: if ipv4 { 0 } else { 1024 },
            },
            connectionless,
            peer_reassembly_ipv4: Some(peer_reassembly).filter(|_| ipv4),
            peer_reassembly_ipv6: Some(peer_reassembly).filter(|_| !ipv4),
            adjunct: ntcp_host::AdjunctLimits {
                paths: adjunct,
                ..Default::default()
            },
        };
        let (paths, limits) = ntcp_host::managed_udp_limits(
            paths,
            limits,
            ntcp_host::UdpLimits {
                // The flow, and the neighbor flow of `neighbor`.
                flows: 2,
                receive_datagrams: BUDGET,
                max_payload: largest - header - 8,
                events: BUDGET,
                evicted_signatures: 256,
                // One receipt per probe a run sends before its outcome is
                // known; unreported ones are reclaimed after expiry.
                probe_receipts: BUDGET,
            },
        )
        .map_err(host_error)?;
        let (paths, mut limits) = ntcp_host::managed_icmp_output_limits(
            paths,
            limits,
            ntcp_host::IcmpOutputLimits {
                messages: BUDGET,
                message_bytes: largest - header,
                hop_limit: config.hop_limit,
            },
        )
        .map_err(host_error)?;
        limits.reassembly = ntcp_host::ReassemblyLimits {
            assemblies: BUDGET,
            fragments: IPV4_DATAGRAM.div_ceil(8),
            buffered_bytes: IPV6_DATAGRAM + 8,
            ipv4_datagram: IPV4_DATAGRAM,
            ipv6_datagram: IPV6_DATAGRAM,
            ipv4_timeout_seconds: 60,
        };
        let mut host = Host::new(
            path::ContextId::new(u128::from_ne_bytes(identity)),
            paths,
            limits,
            endpoint.caller_timebase(),
        )
        .map_err(host_error)?;
        host.set_entropy(Box::new(|bytes: &mut [u8]| {
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(bytes))
                .map_err(|_| ntcp_host::EntropyError)
        }));
        // D14: harness-created namespace and address, no earlier emission.
        host.start_identifiers(Continuity::QuietFor {
            at: 0,
            seconds: u64::MAX,
        })
        .map_err(host_error)?;
        let forwarder = path::ForwarderId(1);
        let ingress = host
            .register_link(
                path::InterfaceKey(1),
                MTU as u32,
                ntcp_host::ReceiveCapabilities {
                    max_ip_packet: MAX_IP_PACKET,
                    ipv4: if ipv4 {
                        ntcp_host::Ipv4Receive::Unrecognized
                    } else {
                        ntcp_host::Ipv4Receive::Disabled
                    },
                    ipv6: if ipv4 {
                        ntcp_host::Ipv6Receive::Disabled
                    } else {
                        ntcp_host::Ipv6Receive::BaseHeader
                    },
                    gro: false,
                },
                ntcp_host::Forwarding::Forwarder(forwarder),
            )
            .map_err(host_error)?;
        host.register_source(
            path::ScopedAddress::new(local, None).map_err(|e| host_error(e.into()))?,
            ingress.link(),
        )
        .map_err(host_error)?;
        let any = if ipv4 {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        let route = host.add_route(path::Route {
            destination: path::IpPrefix::new(any, 0).map_err(|e| host_error(e.into()))?,
            source: None,
            dscp: None,
            link: ingress.link(),
            next_hop: path::NextHop::Forwarder(forwarder),
            metric: 0,
        })
        .map_err(host_error)?;
        endpoint.enable_output_reservations().map_err(engine)?;
        host.attach(endpoint).map_err(host_error)?;
        let flow = host
            .udp_open(
                endpoint,
                SocketAddr::new(local, LOCAL_PORT),
                Some(peer),
                ntcp_host::UdpOptions {
                    dscp: 0,
                    hop_limit: config.hop_limit,
                },
            )
            .map_err(host_error)?;
        // The flow default: Fragment mode with the peer's stated capacity.
        let send = UdpSend {
            mode: UdpSendMode::Fragment,
            peer_capability: Some(peer_reassembly),
        };
        host.udp_set_send(flow, send).map_err(host_error)?;
        let administration = host.administration();
        Ok(Self {
            host,
            ingress,
            tun,
            flow,
            send,
            route,
            neighbor: None,
            administration,
            start,
            frame: vec![0; MAX_IP_PACKET + 1],
            completed: vec![0; MAX_IP_PACKET],
            output: vec![0; largest + MTU],
            received: vec![0; largest],
            events: Vec::new(),
            datagrams: 0,
            receipts: Vec::new(),
        })
    }

    // Malformed or foreign input is a silent discard, as in any embedding.
    fn input(&mut self, endpoint: &mut Endpoint, len: usize) {
        let now = self.now();
        let packet = &self.frame[..len];
        // Pass only the complete IPv4 datagram to the exact-bounds codec.
        let packet = if packet[0] >> 4 == 4 && len >= 4 {
            &packet[..usize::from(u16::from_be_bytes([packet[2], packet[3]])).min(len)]
        } else {
            packet
        };
        let Ok(Received::Datagram(datagram)) =
            self.host
                .receive(self.ingress, now, packet, false, &mut self.completed)
        else {
            return;
        };
        let Ok(decoded) = self.host.decode_datagram(datagram) else {
            return;
        };
        if decoded.protocol == if decoded.ip.source.is_ipv4() { 1 } else { 58 } {
            // PTB correlation, Echo service and adjunct replies: the single
            // Host dispatcher. No TCP owner exists, so nothing is deferred.
            let _ = self.host.input_icmp_datagram(endpoint, now, datagram);
        } else {
            let _ = self.host.input_datagram(
                endpoint,
                now,
                datagram,
                ntcp::RxPacketMetadata::default(),
                0,
                None,
            );
        }
    }

    // Ordinary embedding service for `wait_ms`: ingress, the change service
    // (reassembly and adjunct deadlines), the ICMP output drain (Echo
    // Replies and adjunct probes) and the flow's advice and datagrams.
    fn serve(&mut self, endpoint: &mut Endpoint, wait_ms: u64) -> io::Result<()> {
        let until = self.now() + wait_ms * 1000;
        loop {
            loop {
                match self.tun.receive(&mut self.frame) {
                    Ok(Some(0)) => return Err(other("TUN closed".into())),
                    Ok(Some(len)) => self.input(endpoint, len),
                    Ok(None) => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
            let now = self.now();
            if let Ok(report) = self.host.service_changes(endpoint, now)
                && let Some(error) = report.first_error
            {
                return Err(other(format!("path change service failed: {error:?}")));
            }
            let Self {
                host, tun, output, ..
            } = self;
            for _ in 0..BUDGET {
                match host.icmp_output(now, output, |_, frame| transmit(tun, frame)) {
                    Ok(None) | Ok(Some(BackendOutcome::WouldBlock)) => break,
                    Ok(Some(BackendOutcome::Unknown)) => {
                        return Err(other("unknown TUN outcome".into()));
                    }
                    Ok(Some(_)) | Err(_) => {}
                }
            }
            self.host.collect(endpoint).map_err(host_error)?;
            while let Some(event) = self.host.udp_event(self.flow).map_err(host_error)? {
                self.events.push(event);
            }
            if let Some((_, flow)) = self.neighbor {
                while self.host.udp_event(flow).map_err(host_error)?.is_some() {}
                while self
                    .host
                    .udp_receive(flow, &mut self.received)
                    .map_err(host_error)?
                    .is_some()
                {}
            }
            while self
                .host
                .udp_receive(self.flow, &mut self.received)
                .map_err(host_error)?
                .is_some()
            {
                self.datagrams += 1;
            }
            let now = self.now();
            if now >= until {
                return Ok(());
            }
            let delay = self
                .host
                .next_adjunct_deadline()
                .into_iter()
                .chain(self.host.next_reassembly_deadline())
                .chain(Some(until))
                .min()
                .unwrap()
                .saturating_sub(now)
                .clamp(1000, 10_000);
            let mut fd = libc::pollfd {
                fd: self.tun.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one initialized pollfd for the duration of the call.
            if unsafe { libc::poll(&mut fd, 1, delay.div_ceil(1000) as i32) } < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }

    fn limits(
        &mut self,
        endpoint: &Endpoint,
        send: Option<UdpSend>,
    ) -> io::Result<UdpDatagramLimits> {
        self.host
            .udp_datagram_limits(endpoint, self.flow, None, send)
            .map_err(host_error)
    }

    // The flow's limits under its default send, the shared path state they
    // were read from (learned estimate, budget, revision, hold) and the
    // adjunct counters.
    fn state(&mut self, endpoint: &Endpoint) -> io::Result<String> {
        let limits = self.limits(endpoint, None)?;
        let snapshot = self
            .host
            .paths()
            .path_snapshot(limits.path.path)
            .map_err(|e| host_error(e.into()))?;
        let budget = snapshot
            .ip_packet_budget()
            .map_err(|e| host_error(e.into()))?;
        let events: Vec<String> = self.events.drain(..).map(|e| event_json(&e)).collect();
        Ok(format!(
            "\"limits\":{},\"learned_mtu\":{},\"first_hop_mtu\":{},\"budget\":{budget},\
             \"negative_revision\":{},\"retry_not_before\":{},\"effective_size\":{},\
             \"events\":[{}],\"udp_received\":{},\"adjunct\":{},\"icmp_output\":{},\"now\":{}",
            limits_json(&limits),
            opt(snapshot.learned_mtu()),
            snapshot.first_hop_mtu(),
            snapshot.negative_revision(),
            snapshot.retry_not_before(),
            limits.effective_size,
            events.join(","),
            self.datagrams,
            counters_json(&self.host.adjunct_counters()),
            text(self.host.icmp_output_counters()),
            self.now()
        ))
    }

    // The second route (same link and Forwarder next hop, selected by DSCP)
    // and a Fragment-mode flow to the same peer that resolves through it.
    fn add_neighbor(&mut self, endpoint: &mut Endpoint, dscp: u8, peer: SocketAddr, local: IpAddr) -> io::Result<String> {
        let default = self.host.paths().route(self.route).map_err(|e| host_error(e.into()))?;
        let route = self
            .host
            .add_route(path::Route {
                dscp: Some(path::Dscp::new(dscp).map_err(|e| host_error(e.into()))?),
                ..default
            })
            .map_err(host_error)?;
        let flow = self
            .host
            .udp_open(
                endpoint,
                SocketAddr::new(local, LOCAL_PORT + 1),
                Some(peer),
                ntcp_host::UdpOptions {
                    dscp,
                    hop_limit: config(local).hop_limit,
                },
            )
            .map_err(host_error)?;
        self.host.udp_set_send(flow, self.send).map_err(host_error)?;
        self.neighbor = Some((route, flow));
        let limits = self
            .host
            .udp_datagram_limits(endpoint, flow, None, None)
            .map_err(host_error)?;
        let resolved = self
            .host
            .paths()
            .path_snapshot(limits.path.path)
            .map_err(|e| host_error(e.into()))?
            .key()
            .route();
        Ok(format!(
            "\"dscp\":{dscp},\"local_port\":{},\"separate_route\":{},\"resolved_neighbor_route\":{}",
            LOCAL_PORT + 1,
            route != self.route,
            resolved == route
        ))
    }

    // Disable discovery on one route: one owner administration transaction.
    fn disable(&mut self, endpoint: &mut Endpoint, which: &str) -> io::Result<String> {
        let route = match which {
            "main" => self.route,
            "neighbor" => self.neighbor.ok_or_else(|| other("no neighbor route".into()))?.0,
            _ => return Err(other(format!("invalid route {which}"))),
        };
        let expected = self
            .host
            .admin_routes(&self.administration)
            .map_err(host_error)?
            .find(|r| r.route == route)
            .ok_or_else(|| other("route vanished".into()))?
            .generation;
        let candidate = self
            .host
            .admin_validate(
                &self.administration,
                self.now(),
                path::AdminChange {
                    target: path::AdminTarget::Route(route),
                    expected,
                    policy: path::AdminPolicy {
                        discovery_disabled: true,
                        estimate: None,
                    },
                },
            )
            .map_err(host_error)?;
        let generation = self
            .host
            .admin_apply(&self.administration, endpoint, candidate)
            .map_err(host_error)?;
        Ok(format!("\"route\":\"{which}\",\"generation\":{generation}"))
    }

    fn send(
        &mut self,
        endpoint: &mut Endpoint,
        mode: UdpSendMode,
        size: usize,
        salt: usize,
    ) -> io::Result<String> {
        let flow = self.flow;
        self.send_on(endpoint, flow, mode, size, salt)
    }

    fn send_on(
        &mut self,
        endpoint: &mut Endpoint,
        flow: UdpFlowId,
        mode: UdpSendMode,
        size: usize,
        salt: usize,
    ) -> io::Result<String> {
        let send = UdpSend {
            mode,
            peer_capability: self.send.peer_capability,
        };
        let before = self
            .host
            .udp_datagram_limits(endpoint, flow, None, Some(send))
            .map_err(host_error)?;
        let learned_before = self
            .host
            .paths()
            .path_snapshot(before.path.path)
            .map_err(|e| host_error(e.into()))?
            .learned_mtu();
        let payload = pattern(size, salt);
        let now = self.now();
        let buffer = before.buffer_len(size).min(self.output.len());
        let mut lengths = Vec::new();
        let Self {
            host, tun, output, ..
        } = self;
        let result = host.udp_send_datagram(
            endpoint,
            now,
            flow,
            None,
            Some(send),
            &payload,
            &mut output[..buffer],
            |_, frame| {
                lengths.push(frame.len());
                transmit(tun, frame)
            },
        );
        if let Some(receipt) = result
            .as_ref()
            .ok()
            .and_then(|r| r.probe.as_ref())
            .and_then(|p| p.receipt)
        {
            self.receipts.push(receipt);
        }
        let receipts = self.receipts.len();
        let result = match result {
            Ok(report) => format!(
                "\"report\":{},\"error\":null,\"receipts\":{receipts}",
                report_json(&report)
            ),
            // Refusals (TooBig, PeerLimit), backpressure and certain
            // non-submission: nothing left, reported as is.
            Err(error) => format!("\"report\":null,\"error\":{}", text(error)),
        };
        let packets: Vec<String> = lengths.iter().map(usize::to_string).collect();
        Ok(format!(
            "\"mode\":{},\"size\":{size},\"salt\":{salt},\"limits_before\":{},\
             \"learned_before\":{},\"submitted_lengths\":[{}],{result}",
            text(mode),
            limits_json(&before),
            opt(learned_before),
            packets.join(",")
        ))
    }
}

impl Network {
    // One application outcome report for receipt N (consumed exactly once
    // by the Host; a replay or a stale receipt is reported as its error).
    fn report(&mut self, index: usize, outcome: &str) -> io::Result<String> {
        let outcome = match outcome {
            "success" => UdpProbeOutcome::Success,
            "isolated-loss" => UdpProbeOutcome::IsolatedLoss,
            "timeout" => UdpProbeOutcome::TimeoutFailure,
            "inconclusive" => UdpProbeOutcome::Inconclusive,
            other => return Err(self::other(format!("invalid outcome {other}"))),
        };
        let receipt = *self
            .receipts
            .get(index)
            .ok_or_else(|| other(format!("no receipt {index}")))?;
        let now = self.now();
        Ok(
            match self
                .host
                .udp_report_probe(now, self.flow, receipt, outcome, None)
            {
                Ok(report) => format!(
                    "\"receipt_size\":{},\"confirmed\":{},\"upper\":{},\"suppressed\":{},\
                     \"shared\":{},\"report_error\":null",
                    receipt.size(),
                    opt(report.bounds.confirmed),
                    opt(report.bounds.upper),
                    text(report.bounds.suppressed),
                    text(report.shared)
                ),
                Err(error) => format!(
                    "\"receipt_size\":{},\"report_error\":{}",
                    receipt.size(),
                    text(error)
                ),
            },
        )
    }
}

fn config(local: IpAddr) -> EndpointConfig {
    let header_len = if local.is_ipv4() { 20 } else { 40 };
    EndpointConfig {
        max_connections: 1,
        preallocate_connections: 0,
        max_listeners: 1,
        max_control_packets: BUDGET,
        max_setup_cache_entries: 1,
        max_route_policies: 1,
        max_buffer_bytes: 1 << 20,
        hop_limit: 64,
        dscp: 0,
        ipv4_options_enabled: false,
        error_reports: true,
        reuse_time_wait: false,
        connection: ntcp::ConnectionConfig {
            pmtud: Some(ntcp::PmtudConfig::new(MTU as u32)),
            mss: (MTU - header_len - 20) as u16,
            receive_ip_payload_limit: (MTU - header_len) as u16,
            send_ip_payload_limit: (MTU - header_len) as u16,
            ..ntcp::ConnectionConfig::default()
        },
    }
}

fn main() {
    if let Err(e) = run() {
        emit(format!(
            "{{\"event\":\"error\",\"message\":{:?}}}",
            e.to_string()
        ));
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 {
        return Err(other(
            "usage: datagram_drive TUN_NAME LOCAL_IP PEER_SOCKET_ADDR INITIAL PEER_REASSEMBLY \
             ADJUNCT_PATHS"
                .into(),
        ));
    }
    let local: IpAddr = args[2]
        .parse()
        .map_err(|_| other("invalid local IP".into()))?;
    let peer: SocketAddr = args[3].parse().map_err(|_| other("invalid peer".into()))?;
    let number = |i: usize| -> io::Result<u64> {
        args[i]
            .parse()
            .map_err(|_| other(format!("invalid argument {}", args[i])))
    };
    let (initial, peer_reassembly, adjunct) = (number(4)? as u32, number(5)? as u32, number(6)?);
    let config = config(local);
    let mut secret = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut secret)?;
    let tun = Tun::open(&args[1])?;
    let start = Instant::now();
    // The namespace's own addresses are the only ones this driver uses.
    let mut endpoint = Endpoint::new(config.clone(), secret, 0, move |request| match request {
        ntcp::AddressValidation::Bind { local: bind } => bind == local,
        ntcp::AddressValidation::Open {
            local: source,
            remote,
        } => source == local && remote == peer.ip(),
        ntcp::AddressValidation::Route { source, .. } => source == local,
        ntcp::AddressValidation::Incoming { destination, .. } => destination == local,
    })
    .map_err(engine)?;
    let mut network = Network::attach(
        &mut endpoint,
        &config,
        local,
        peer,
        initial,
        peer_reassembly,
        adjunct as usize,
        tun,
        start,
    )?;
    let initial_state = network.state(&endpoint)?;
    emit(format!(
        "{{\"event\":\"ready\",\"family\":{},\"local\":\"{local}\",\"peer\":\"{peer}\",\
         \"local_port\":{LOCAL_PORT},\"connectionless_initial\":{initial},\
         \"peer_reassembly\":{peer_reassembly},\"adjunct_paths\":{adjunct},\
         \"continuity\":\"QuietFor(no earlier emission: harness-created namespace and address)\",\
         \"mdl_seconds\":{},{initial_state}}}",
        if local.is_ipv4() { 4 } else { 6 },
        ntcp_host::DEFAULT_LIFETIME_SECONDS
    ));
    for line in io::stdin().lock().lines() {
        let line = line?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        let field = |i: usize| -> io::Result<u64> {
            fields
                .get(i)
                .and_then(|f| f.parse().ok())
                .ok_or_else(|| other(format!("invalid command {line}")))
        };
        match fields.first().copied() {
            None => continue,
            Some("quit") => break,
            Some("send") => {
                let mode = mode(fields.get(1).copied().unwrap_or(""))?;
                let sent =
                    network.send(&mut endpoint, mode, field(2)? as usize, field(3)? as usize)?;
                network.serve(&mut endpoint, field(4)?)?;
                let state = network.state(&endpoint)?;
                emit(format!("{{\"event\":\"sent\",{sent},{state}}}"));
            }
            Some("report") => {
                let report =
                    network.report(field(1)? as usize, fields.get(2).copied().unwrap_or(""))?;
                let state = network.state(&endpoint)?;
                emit(format!("{{\"event\":\"reported\",{report},{state}}}"));
            }
            Some("neighbor") => {
                let added = network.add_neighbor(&mut endpoint, field(1)? as u8, peer, local)?;
                network.serve(&mut endpoint, 100)?;
                emit(format!("{{\"event\":\"neighbor\",{added}}}"));
            }
            Some("disable") => {
                let disabled = network.disable(&mut endpoint, fields.get(1).copied().unwrap_or(""))?;
                network.serve(&mut endpoint, 100)?;
                emit(format!("{{\"event\":\"disabled\",{disabled}}}"));
            }
            Some("sendvia") => {
                let flow = match fields.get(1).copied() {
                    Some("main") => network.flow,
                    Some("neighbor") => network.neighbor.ok_or_else(|| other("no neighbor flow".into()))?.1,
                    _ => return Err(other(format!("invalid command {line}"))),
                };
                let mode = mode(fields.get(2).copied().unwrap_or(""))?;
                let sent = network.send_on(&mut endpoint, flow, mode, field(3)? as usize, field(4)? as usize)?;
                network.serve(&mut endpoint, field(5)?)?;
                emit(format!("{{\"event\":\"sent\",{sent}}}"));
            }
            Some("serve") => {
                network.serve(&mut endpoint, field(1)?)?;
                let state = network.state(&endpoint)?;
                emit(format!("{{\"event\":\"served\",{state}}}"));
            }
            Some(command) => return Err(other(format!("unknown command {command}"))),
        }
    }
    Ok(())
}
