// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// Harness-only TCP driver for the two-link receive-MSS and send-space cases.
// Unlike ptb_stage (one TUN, no reassembly), one ordinary Host owns two
// harness-precreated TUNs of unequal MTU: it registers each with its queried
// MTU and the receive capacity of the buffer this driver reads it into,
// configures storage-backed reassembly, services both and submits every
// packet to the TUN of the link its egress context names. The only route
// and source use the smaller link. Every connection goes through the
// production Host factories, so its MSS offer is the Host's derivation; the
// harness chooses only when the application writes, the send-buffer size of
// the send-space case, and how long ingress is held back.
//
// Run as: two_link SMALL_TUN LARGE_TUN LOCAL_IP, then on stdin:
//   listen PORT        listen on LOCAL_IP:PORT
//   accept             service until a child arrives; read to EOF, echo the
//                      bytes back and close, servicing until closed
//   connect PEER       open from the next local port and complete the
//                      handshake (active, one at a time)
//   fill B TOTAL SALT  resize the send buffer to B, then write TOTAL pattern
//                      bytes as admission allows; the first output pass runs
//                      without ingress service; service until acknowledged
//   close              send FIN and service until it is acknowledged
//   quit
use ntcp::{
    ConnectionConfig, ConnectionId, Endpoint, EndpointConfig, EndpointError, Error, ListenerId,
    PmtudConfig, State, Tuple,
};
use ntcp_host::{
    BackendOutcome, DeferredIcmp, EgressContext, Host, IcmpDispatch, IngressContext, Submission,
    SubmissionTicket, path,
};
use ntcp_io::{PacketIo, TxOutcome};
use ntcp_io_tun::Tun;
use std::{
    collections::VecDeque,
    io::{self, BufRead, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::AsRawFd,
    time::Instant,
};

const BUDGET: usize = 32;
// Each TUN is read into a buffer of this size: the largest IPv6 packet
// without a jumbogram, so every non-jumbo packet arrives whole. It is the
// physical receive capacity registered for both links.
const RECEIVE_BUFFER: usize = 65575;
// Storage-backed reassembly of every non-jumbo datagram of either family.
const IPV4_DATAGRAM: usize = 65535;
const IPV6_DATAGRAM: usize = 65575;
const DEADLINE_US: u64 = 30_000_000;
// Each active open takes the next local port from here (one at a time).
const FIRST_LOCAL_PORT: u16 = 18100;

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
fn pattern(n: usize, offset: usize, salt: usize) -> Vec<u8> {
    (offset..offset + n)
        .map(|i| ((i * 31 + salt) % 251) as u8)
        .collect()
}

struct Link {
    tun: Tun,
    ingress: IngressContext,
    mtu: u32,
}

struct Held {
    attempt: ntcp::TransmitAttempt,
    context: Option<EgressContext>,
    ticket: Option<SubmissionTicket>,
    len: usize,
}

struct Network {
    host: Host,
    links: [Link; 2],
    deferred: VecDeque<DeferredIcmp>,
    retained: VecDeque<(usize, ConnectionId, Vec<u8>)>,
    held: Option<Held>,
    header_len: usize,
    start: Instant,
    clock: ntcp_clock::UtcClock,
}

// IPv4 Timestamp time for destination processing (none while this link's
// option interpretation stays disabled), as in ptb_stage.
struct Utc<'a> {
    clock: &'a mut ntcp_clock::UtcClock,
    now: u64,
}
impl ntcp::Ipv4TimestampProvider for Utc<'_> {
    fn ipv4_timestamp(&mut self) -> Option<ntcp::Ipv4Timestamp> {
        ntcp::Ipv4Timestamp::from_wire(self.clock.sample(self.now / 1000).value).ok()
    }
}

fn receive_profile(local: IpAddr) -> ntcp_host::ReceiveCapabilities {
    ntcp_host::ReceiveCapabilities {
        max_ip_packet: RECEIVE_BUFFER,
        ipv4: if local.is_ipv4() {
            ntcp_host::Ipv4Receive::Enabled {
                interpretation: false,
                source_routes: false,
            }
        } else {
            ntcp_host::Ipv4Receive::Disabled
        },
        ipv6: if local.is_ipv6() {
            ntcp_host::Ipv6Receive::BaseHeader
        } else {
            ntcp_host::Ipv6Receive::Disabled
        },
        gro: false,
    }
}

impl Network {
    fn now(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }

    fn attach(
        endpoint: &mut Endpoint,
        config: &EndpointConfig,
        local: IpAddr,
        tuns: [(Tun, u32); 2],
        start: Instant,
    ) -> io::Result<Self> {
        let mut identity = [0u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut identity)?;
        let (paths, mut limits) =
            ntcp_host::managed_limits(config, 2, 1, 1, 1, 1).map_err(host_error)?;
        // One read pass's worth of concurrent datagrams, one largest
        // datagram's bytes (an IPv6 first fragment also stores its Fragment
        // header) and descriptors for it in 8-octet fragments.
        limits.reassembly = ntcp_host::ReassemblyLimits {
            assemblies: BUDGET,
            fragments: IPV6_DATAGRAM.div_ceil(8),
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
        let [(small, small_mtu), (large, large_mtu)] = tuns;
        let mut register = |key, mtu, forwarder| {
            host.register_link(
                path::InterfaceKey(key),
                mtu,
                receive_profile(local),
                ntcp_host::Forwarding::Forwarder(path::ForwarderId(forwarder)),
            )
            .map_err(host_error)
        };
        let small_ingress = register(1, small_mtu, 1)?;
        let large_ingress = register(2, large_mtu, 2)?;
        host.register_source(
            path::ScopedAddress::new(local, None).map_err(|e| host_error(e.into()))?,
            small_ingress.link(),
        )
        .map_err(host_error)?;
        let any = if local.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        host.add_route(path::Route {
            destination: path::IpPrefix::new(any, 0).map_err(|e| host_error(e.into()))?,
            source: None,
            dscp: None,
            link: small_ingress.link(),
            next_hop: path::NextHop::Forwarder(path::ForwarderId(1)),
            metric: 0,
        })
        .map_err(host_error)?;
        endpoint.enable_output_reservations().map_err(engine)?;
        host.attach(endpoint).map_err(host_error)?;
        Ok(Self {
            host,
            links: [
                Link {
                    tun: small,
                    ingress: small_ingress,
                    mtu: small_mtu,
                },
                Link {
                    tun: large,
                    ingress: large_ingress,
                    mtu: large_mtu,
                },
            ],
            deferred: VecDeque::new(),
            retained: VecDeque::new(),
            held: None,
            header_len: if local.is_ipv4() { 20 } else { 40 },
            start,
            clock: ntcp_clock::UtcClock::new(),
        })
    }

    fn owner(&self, endpoint: &Endpoint, link: usize, frame: &[u8]) -> Option<ConnectionId> {
        let packet = self
            .host
            .decode_ingress(self.links[link].ingress, frame)
            .ok()?;
        if packet.protocol != 6 {
            return None;
        }
        let tcp = ntcp::wire::parse(packet.ip, packet.payload).ok()?;
        endpoint.connection_id(Tuple {
            local: SocketAddr::new(packet.ip.destination, tcp.header.destination_port),
            remote: SocketAddr::new(packet.ip.source, tcp.header.source_port),
        })
    }

    // Malformed or foreign input is a silent discard, as in any embedding.
    // Fragments go to the Host, which reassembles them before dispatch.
    fn input(&mut self, endpoint: &mut Endpoint, link: usize, frame: &[u8]) -> io::Result<()> {
        let now = self.now();
        let ingress = self.links[link].ingress;
        if let Ok(decoded) = self.host.decode_ingress(ingress, frame)
            && decoded.protocol == if decoded.ip.source.is_ipv4() { 1 } else { 58 }
        {
            let mut utc = Utc {
                clock: &mut self.clock,
                now,
            };
            if let Ok(IcmpDispatch::Deferred(deferred)) =
                self.host
                    .input_icmp(endpoint, ingress, now, frame, Some(&mut utc))
            {
                self.deferred.push_back(deferred);
            }
            return Ok(());
        }
        if let Some(owner) = self.owner(endpoint, link, frame)
            && endpoint.is_output_reserved(owner)
        {
            self.retained.push_back((link, owner, frame.to_vec()));
            return Ok(());
        }
        let _ = self.host.input_ip(
            endpoint,
            ingress,
            now,
            frame,
            ntcp::RxPacketMetadata::default(),
            0,
            None,
        );
        Ok(())
    }

    fn replay(&mut self, endpoint: &mut Endpoint) -> io::Result<()> {
        let now = self.now();
        for _ in 0..self.deferred.len() {
            let deferred = self.deferred.pop_front().unwrap();
            if endpoint.is_output_reserved(deferred.owner()) {
                self.deferred.push_back(deferred);
            } else if let Ok(IcmpDispatch::Deferred(again)) =
                self.host.replay_icmp(endpoint, deferred, now)
            {
                self.deferred.push_back(again);
            }
        }
        for _ in 0..self.retained.len() {
            let (link, owner, frame) = self.retained.pop_front().unwrap();
            if endpoint.is_output_reserved(owner) {
                self.retained.push_back((link, owner, frame));
            } else if self.owner(endpoint, link, &frame) == Some(owner) {
                self.input(endpoint, link, &frame)?;
            }
        }
        Ok(())
    }

    // Every frame both TUNs hold now; nothing is read while an attempt is held.
    fn receive(&mut self, endpoint: &mut Endpoint) -> io::Result<()> {
        self.replay(endpoint)?;
        let mut frame = vec![0u8; RECEIVE_BUFFER];
        for link in 0..self.links.len() {
            while self.held.is_none() {
                match self.links[link].tun.receive(&mut frame) {
                    Ok(Some(0)) => return Err(other("TUN closed".into())),
                    Ok(Some(len)) => {
                        let packet = &frame[..len];
                        // Pass only the complete IPv4 datagram to the exact-bounds codec.
                        let packet = if packet[0] >> 4 == 4 && len >= 4 {
                            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
                            &packet[..total.min(len)]
                        } else {
                            packet
                        };
                        let packet = packet.to_vec();
                        self.input(endpoint, link, &packet)?;
                    }
                    Ok(None) => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    // One output pass: every packet the Endpoint selects, each submitted as
    // its own physical write to the TUN of the link its egress context names.
    fn transmit(&mut self, endpoint: &mut Endpoint, output: &mut [u8]) -> io::Result<()> {
        let now = self.now();
        if let Ok(report) = self.host.service_changes(endpoint, now)
            && let Some(error) = report.first_error
        {
            return Err(other(format!("path change service failed: {error:?}")));
        }
        let header_len = self.header_len;
        for _ in 0..BUDGET {
            if self.held.is_none() {
                let (polled, attempt) = endpoint
                    .poll_reserved_transmit(now, &mut output[header_len..], 1)
                    .map_err(engine)?;
                let Some(packet) = polled.packet else {
                    if !polled.more_work {
                        break;
                    }
                    continue;
                };
                let attempt = attempt.ok_or_else(|| other("missing transmit attempt".into()))?;
                let built = match packet.ip.source {
                    IpAddr::V4(_) => ntcp_ip::encode(output, packet, 0)
                        .map_err(|e| other(format!("IPv4 encode: {e:?}"))),
                    IpAddr::V6(_) => ntcp_ip6::encode(output, packet)
                        .map_err(|e| other(format!("IPv6 encode: {e:?}"))),
                };
                let len = match built {
                    Ok(len) => len,
                    Err(error) => {
                        endpoint.reject_unsubmitted(attempt).map_err(engine)?;
                        return Err(error);
                    }
                };
                self.held = Some(Held {
                    attempt,
                    context: None,
                    ticket: None,
                    len,
                });
            }
            let held = self.held.as_mut().unwrap();
            let prepared = match (held.context, held.ticket.take()) {
                (Some(context), Some(ticket)) => Ok((context, ticket)),
                (context, _) => context
                    .map_or_else(|| self.host.egress_context(endpoint, held.attempt), Ok)
                    .and_then(|context| {
                        Ok((context, self.host.submission_ticket(endpoint, context)?))
                    }),
            };
            let (context, ticket) = match prepared {
                Ok(prepared) => prepared,
                Err(ntcp_host::Error::Obsolete) => {
                    endpoint.reject_unsubmitted(held.attempt).map_err(engine)?;
                    self.held = None;
                    self.host.collect(endpoint).map_err(host_error)?;
                    continue;
                }
                Err(error) => return Err(host_error(error)),
            };
            let Some(link) = self
                .links
                .iter_mut()
                .find(|link| link.ingress.link() == context.link)
            else {
                return Err(other("egress context names no owned link".into()));
            };
            let frame = &output[..held.len];
            let tun = &mut link.tun;
            let mut failure = None;
            let result = self
                .host
                .submit(endpoint, now, ticket, context, frame, 0, |_| {
                    match tun.transmit(frame) {
                        Ok(TxOutcome::Submitted) => BackendOutcome::Submitted,
                        Ok(TxOutcome::WouldBlock | TxOutcome::Rejected) => {
                            BackendOutcome::WouldBlock
                        }
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                            BackendOutcome::WouldBlock
                        }
                        Err(error) => {
                            failure = Some(error);
                            BackendOutcome::Unknown
                        }
                    }
                });
            match result {
                Ok(Submission::Submitted) => {
                    self.held = None;
                    self.host.collect(endpoint).map_err(host_error)?;
                    self.replay(endpoint)?;
                }
                Ok(Submission::Blocked(ticket)) => {
                    held.context = Some(context);
                    held.ticket = Some(ticket);
                    break;
                }
                Ok(Submission::PossiblySubmitted) => {
                    return Err(failure.unwrap_or_else(|| other("unknown TUN outcome".into())));
                }
                Ok(Submission::Rejected(_) | Submission::Cancelled) => {
                    return Err(other(
                        "TUN reports neither rejection nor cancellation".into(),
                    ));
                }
                Err(refused) => {
                    if refused.error == ntcp_host::Error::Obsolete {
                        self.host.cancel_submission(refused.ticket);
                        endpoint.reject_unsubmitted(held.attempt).map_err(engine)?;
                        self.held = None;
                        self.host.collect(endpoint).map_err(host_error)?;
                        continue;
                    }
                    return Err(host_error(refused.error));
                }
            }
        }
        Ok(())
    }

    fn wait(&self, endpoint: &Endpoint) -> io::Result<()> {
        let now = self.now();
        let deadline = [
            endpoint.next_deadline(),
            self.host.next_reassembly_deadline(),
        ]
        .into_iter()
        .flatten()
        .min();
        let delay = deadline.map_or(10_000, |deadline| deadline.saturating_sub(now).min(10_000));
        let timeout = if self.held.is_some() || endpoint.has_pending_output() {
            1
        } else {
            delay.div_ceil(1000) as i32
        };
        let held = self.held.is_some();
        let mut fds = self.links.each_ref().map(|link| libc::pollfd {
            fd: link.tun.as_raw_fd(),
            events: libc::POLLIN | if held { libc::POLLOUT } else { 0 },
            revents: 0,
        });
        // SAFETY: two initialized pollfds for the duration of the call.
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        Ok(())
    }

    // Ordinary embedding service (ingress, timers, output) until `done`.
    fn serve(
        &mut self,
        endpoint: &mut Endpoint,
        output: &mut [u8],
        what: &str,
        mut done: impl FnMut(&mut Endpoint) -> io::Result<bool>,
    ) -> io::Result<()> {
        let deadline = self.now() + DEADLINE_US;
        loop {
            self.receive(endpoint)?;
            endpoint.on_timeout(self.now(), BUDGET).map_err(engine)?;
            while endpoint.next_event().is_some() {}
            if done(endpoint)? && self.held.is_none() && !endpoint.has_pending_output() {
                return Ok(());
            }
            self.transmit(endpoint, output)?;
            self.host.collect(endpoint).map_err(host_error)?;
            if self.now() > deadline {
                return Err(other(format!("{what} deadline")));
            }
            self.wait(endpoint)?;
        }
    }
}

fn config(local: IpAddr, small_mtu: u32) -> EndpointConfig {
    let header_len = if local.is_ipv4() { 20 } else { 40 };
    // Every route uses the smaller link: its MTU sizes the send ceiling and
    // the output storage. Neither limits the receive MSS offer.
    let payload = small_mtu as usize - header_len;
    EndpointConfig {
        max_connections: 4,
        preallocate_connections: 0,
        max_listeners: 1,
        max_control_packets: BUDGET,
        max_setup_cache_entries: 4,
        max_route_policies: 4,
        max_buffer_bytes: 64 << 20,
        hop_limit: 64,
        dscp: 0,
        ipv4_options_enabled: false,
        error_reports: true,
        reuse_time_wait: false,
        connection: ConnectionConfig {
            sack: true,
            timestamps: true,
            nagle: false,
            pmtud: Some(PmtudConfig::new(small_mtu)),
            send_capacity: 65536,
            receive_capacity: 65536,
            mss: (payload - 20) as u16,
            send_ip_payload_limit: payload as u16,
            ..ConnectionConfig::default()
        },
    }
}

fn info_json(endpoint: &Endpoint, id: ConnectionId) -> io::Result<String> {
    let info = endpoint.transport_info(id).map_err(engine)?;
    Ok(format!(
        "{{\"state\":\"{:?}\",\"mss\":{},\"advertised_mss\":{},\"send_capacity\":{},\"send_space\":{},\"send_used\":{},\"receive_used\":{},\"receive_capacity\":{},\"cwnd\":{},\"max_send_window\":{},\"timestamps\":{},\"window_scaling\":{},\"send_window_scale\":{},\"receive_window_scale\":{}}}",
        info.state,
        info.mss,
        info.advertised_mss,
        info.send_capacity,
        info.send_space,
        info.send_used,
        info.receive_used,
        info.receive_capacity,
        info.cwnd,
        info.max_send_window,
        info.timestamps_negotiated,
        info.window_scaling_negotiated,
        info.send_window_scale,
        info.receive_window_scale
    ))
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
    if args.len() != 4 {
        return Err(other("usage: two_link SMALL_TUN LARGE_TUN LOCAL_IP".into()));
    }
    let local: IpAddr = args[3]
        .parse()
        .map_err(|_| other("invalid local IP".into()))?;
    let mut tuns = Vec::new();
    for name in &args[1..3] {
        let tun = Tun::open(name)?;
        let mtu = tun
            .local_ip_mtu()?
            .ok_or_else(|| other(format!("{name}: MTU unavailable")))?;
        tuns.push((tun, mtu));
    }
    let [small, large]: [(Tun, u32); 2] = tuns.try_into().map_err(|_| other("two TUNs".into()))?;
    if small.1 >= large.1 {
        return Err(other("the first TUN must have the smaller MTU".into()));
    }
    let config = config(local, small.1);
    let mut secret = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut secret)?;
    let start = Instant::now();
    let mut endpoint = Endpoint::new(config.clone(), secret, 0, move |request| match request {
        ntcp::AddressValidation::Bind { local: bind } => bind == local,
        ntcp::AddressValidation::Open { local: source, .. } => source == local,
        ntcp::AddressValidation::Route { source, .. } => source == local,
        ntcp::AddressValidation::Incoming { destination, .. } => destination == local,
    })
    .map_err(engine)?;
    let mut network = Network::attach(&mut endpoint, &config, local, [small, large], start)?;
    let ipv6 = local.is_ipv6();
    let reassembly = network
        .host
        .reassembly_capacity(ipv6)
        .ok_or_else(|| other("reassembly disabled".into()))?;
    let capability = network
        .host
        .receive_ip_capability(ipv6)
        .map_err(host_error)?;
    let mut output = vec![0u8; network.links[0].mtu as usize];
    emit(format!(
        "{{\"event\":\"ready\",\"family\":{},\"links\":[{},{}],\"emtu_r\":{},\"mms_r\":{},\"receive_ip_packet\":{},\"receive_mss\":{},\"config_mss\":{},\"advertised_mss\":null}}",
        if ipv6 { 6 } else { 4 },
        format_args!(
            "{{\"name\":{:?},\"mtu\":{},\"max_ip_packet\":{RECEIVE_BUFFER},\"route\":true}}",
            args[1], network.links[0].mtu
        ),
        format_args!(
            "{{\"name\":{:?},\"mtu\":{},\"max_ip_packet\":{RECEIVE_BUFFER},\"route\":false}}",
            args[2], network.links[1].mtu
        ),
        reassembly.emtu_r,
        reassembly.mms_r,
        capability.ip_packet(),
        capability.mss(),
        config.connection.mss
    ));
    let mut listener: Option<ListenerId> = None;
    let mut id: Option<ConnectionId> = None;
    let mut next_port = FIRST_LOCAL_PORT;
    for line in io::stdin().lock().lines() {
        let line = line?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.as_slice() {
            [] => continue,
            ["quit"] => break,
            ["listen", port] => {
                let port: u16 = port.parse().map_err(|_| other("invalid port".into()))?;
                listener = Some(
                    endpoint
                        .listen(SocketAddr::new(local, port), 4)
                        .map_err(engine)?,
                );
                emit(format!("{{\"event\":\"listening\",\"port\":{port}}}"));
            }
            ["accept"] => {
                let listener = listener.ok_or_else(|| other("accept before listen".into()))?;
                let mut child = None;
                network.serve(&mut endpoint, &mut output, "accept", |endpoint| {
                    match endpoint.accept(listener) {
                        Ok(accepted) => child = Some(accepted),
                        Err(EndpointError::Connection(Error::WouldBlock))
                        | Err(EndpointError::OutputReserved) => {}
                        Err(error) => return Err(engine(error)),
                    }
                    Ok(child.is_some())
                })?;
                let child = child.unwrap();
                let established = info_json(&endpoint, child)?;
                // Read to the peer's FIN, then echo every byte and close.
                let mut received = Vec::new();
                let mut buffer = vec![0u8; 65536];
                let mut eof = false;
                network.serve(&mut endpoint, &mut output, "echo read", |endpoint| {
                    while !eof {
                        match endpoint.read(child, &mut buffer) {
                            Ok(0) => eof = true,
                            Ok(n) => received.extend_from_slice(&buffer[..n]),
                            Err(EndpointError::Connection(Error::WouldBlock))
                            | Err(EndpointError::OutputReserved) => break,
                            Err(error) => return Err(engine(error)),
                        }
                    }
                    Ok(eof)
                })?;
                let (mut written, mut shut) = (0, false);
                network.serve(&mut endpoint, &mut output, "echo write", |endpoint| {
                    if written < received.len() {
                        match endpoint.write(child, &received[written..]) {
                            Ok(n) => written += n,
                            Err(EndpointError::Connection(Error::WouldBlock))
                            | Err(EndpointError::OutputReserved) => {}
                            Err(error) => return Err(engine(error)),
                        }
                    }
                    if written == received.len() && !shut {
                        match endpoint.shutdown(child) {
                            Ok(()) => shut = true,
                            Err(EndpointError::OutputReserved) => {}
                            Err(error) => return Err(engine(error)),
                        }
                    }
                    Ok(matches!(
                        endpoint.state(child),
                        Ok(State::LastAck | State::Closed) | Err(_)
                    ))
                })?;
                network.serve(&mut endpoint, &mut output, "echo close", |endpoint| {
                    Ok(!matches!(endpoint.state(child), Ok(State::LastAck)))
                })?;
                emit(format!(
                    "{{\"event\":\"accepted\",\"echoed\":{},\"info\":{established}}}",
                    received.len()
                ));
            }
            ["connect", peer] => {
                let peer: SocketAddr = peer.parse().map_err(|_| other("invalid peer".into()))?;
                let options = ntcp::ManagedOpenOptions {
                    transport: ntcp::ActiveOpenOptions::from(&config.connection),
                    dscp: 0,
                    ipv4_options: ntcp::OutgoingIpv4Options::default(),
                    registration: None,
                    receive_authority: None,
                };
                let now = network.now();
                let opened = endpoint
                    .connect_with_path_provider(
                        now,
                        SocketAddr::new(local, next_port),
                        peer,
                        options,
                        &mut network.host,
                    )
                    .map_err(|error| other(format!("connect: {error:?}")))?;
                id = Some(opened);
                next_port += 1;
                network.serve(&mut endpoint, &mut output, "handshake", |endpoint| {
                    Ok(endpoint.state(opened).map_err(engine)? == State::Established)
                })?;
                let local_port = next_port - 1;
                emit(format!(
                    "{{\"event\":\"established\",\"local_port\":{local_port},\"info\":{}}}",
                    info_json(&endpoint, opened)?
                ));
            }
            ["fill", capacity, total, salt] => {
                let id = id.ok_or_else(|| other("fill before connect".into()))?;
                let parse = |s: &str| s.parse::<usize>().map_err(|_| other("invalid size".into()));
                let (capacity, total, salt) = (parse(capacity)?, parse(total)?, parse(salt)?);
                network.receive(&mut endpoint)?;
                let (_, receive) = endpoint.buffer_capacities(id).map_err(engine)?;
                endpoint
                    .set_buffer_capacities(id, capacity, receive)
                    .map_err(engine)?;
                let resized = info_json(&endpoint, id)?;
                let bytes = pattern(total, 0, salt);
                let mut written = 0usize;
                let mut largest_used = 0usize;
                let write = |endpoint: &mut Endpoint, written: &mut usize| -> io::Result<()> {
                    if *written < total {
                        match endpoint.write(id, &bytes[*written..]) {
                            Ok(n) => *written += n,
                            Err(EndpointError::Connection(Error::WouldBlock))
                            | Err(EndpointError::OutputReserved) => {}
                            Err(error) => return Err(engine(error)),
                        }
                    }
                    Ok(())
                };
                // The first admission and output pass see no ingress at all.
                write(&mut endpoint, &mut written)?;
                let first_admitted = written;
                network.transmit(&mut endpoint, &mut output)?;
                let after_first_pass = info_json(&endpoint, id)?;
                network.serve(&mut endpoint, &mut output, "fill", |endpoint| {
                    write(endpoint, &mut written)?;
                    let info = endpoint.transport_info(id).map_err(engine)?;
                    largest_used = largest_used.max(info.send_used);
                    let progress = endpoint.send_progress(id).map_err(engine)?;
                    Ok(written == total && progress.acknowledged == progress.queued_end)
                })?;
                emit(format!(
                    "{{\"event\":\"filled\",\"capacity\":{capacity},\"total\":{total},\"salt\":{salt},\"first_admitted\":{first_admitted},\"largest_send_used\":{largest_used},\"resized\":{resized},\"after_first_pass\":{after_first_pass},\"after\":{}}}",
                    info_json(&endpoint, id)?
                ));
            }
            ["close"] => {
                let id = id.ok_or_else(|| other("close before connect".into()))?;
                endpoint.shutdown(id).map_err(engine)?;
                network.serve(&mut endpoint, &mut output, "close", |endpoint| {
                    Ok(matches!(
                        endpoint.state(id).map_err(engine)?,
                        State::FinWait2 | State::TimeWait | State::Closed
                    ))
                })?;
                emit("{\"event\":\"closed\"}".into());
            }
            _ => return Err(other(format!("unknown command {line}"))),
        }
    }
    Ok(())
}
