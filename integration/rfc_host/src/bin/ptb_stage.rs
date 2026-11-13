// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// Harness-only staged TCP sender for the isolated ICMP cases. One ordinary
// Host + Endpoint drive the router namespace's TUN exactly as an embedding
// would; the harness chooses only when the application writes and when
// ingress is serviced, so a capture can attribute PTB-driven repair. Nothing
// here is a transport knob: every write, ICMP report and retransmission goes
// through the public Endpoint/Host APIs with an unmodified configuration.
//
// Run as: ptb_stage TUN_NAME LOCAL_IP PEER_SOCKET_ADDR, then on stdin:
//   connect            open, complete and drain the handshake
//   stage SIZE...      write each SIZE as its own segment, one output pass
//                      per write and no ingress service in between, then
//                      service the connection until every byte is acknowledged
//   close              send FIN and service until it is acknowledged
//   quit
use ntcp::{
    ConnectionConfig, ConnectionId, Endpoint, EndpointConfig, EndpointError, PmtudConfig, State,
    Tuple,
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
};

const MTU: usize = 1500;
const BUDGET: usize = 32;
const MAX_IP_PACKET: usize = 65575;
const LOCAL_PORT: u16 = 18081;
const DEADLINE_US: u64 = 20_000_000;

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

struct Network {
    host: Host,
    ingress: IngressContext,
    tun: Tun,
    // Reports and segments for an owner whose output is reserved, replayed
    // once the reservation ends (the Host's deferred-report contract).
    deferred: VecDeque<DeferredIcmp>,
    retained: VecDeque<(ConnectionId, Vec<u8>)>,
    held: Option<Held>,
    header_len: usize,
    time: ntcp_clock::TransportClock,
    clock: ntcp_clock::UtcClock,
}

// IPv4 Timestamp time for destination processing from the characterized
// Linux UTC source, sampled only for a slot this host may write: none while
// this link's option interpretation stays disabled.
struct Utc<'a> {
    clock: &'a mut ntcp_clock::UtcClock,
    now: u64,
}
impl ntcp::Ipv4TimestampProvider for Utc<'_> {
    fn ipv4_timestamp(&mut self) -> Option<ntcp::Ipv4Timestamp> {
        // A standard value is below 86 400 000, a nonstandard one marked.
        ntcp::Ipv4Timestamp::from_wire(self.clock.sample(self.now / 1000).value).ok()
    }
}

struct Held {
    attempt: ntcp::TransmitAttempt,
    context: Option<EgressContext>,
    ticket: Option<SubmissionTicket>,
    len: usize,
}

impl Network {
    // One transport sample (CLOCK_BOOTTIME microseconds), its measured
    // suspend passed to the Endpoint; every failure ends the driver.
    fn now(&mut self, endpoint: &mut Endpoint) -> io::Result<u64> {
        let sample = self.time.sample().map_err(io::Error::other)?;
        if sample.suspended != 0 {
            endpoint
                .resume(sample.ticks, sample.suspended)
                .map_err(engine)?;
        }
        Ok(sample.ticks)
    }

    fn attach(
        endpoint: &mut Endpoint,
        config: &EndpointConfig,
        local: IpAddr,
        tun: Tun,
        time: ntcp_clock::TransportClock,
    ) -> io::Result<Self> {
        let mut identity = [0u8; 8];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut identity)?;
        let mut lookup_key = [0u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut lookup_key)?;
        let (paths, limits) =
            ntcp_host::managed_limits(config, 1, 1, 1, 1, 1).map_err(host_error)?;
        let mut host = Host::new(
            path::ContextId::new(u64::from_ne_bytes(identity)),
            paths,
            limits,
            endpoint.caller_timebase(),
            lookup_key,
        )
        .map_err(host_error)?;
        let forwarder = path::ForwarderId(1);
        let ingress = host
            .register_link(
                path::InterfaceKey(1),
                MTU as u32,
                ntcp_host::ReceiveCapabilities {
                    max_ip_packet: MAX_IP_PACKET,
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
                },
                ntcp_host::Forwarding::Forwarder(forwarder),
            )
            .map_err(host_error)?;
        host.register_source(
            path::ScopedAddress::new(local, None).map_err(|e| host_error(e.into()))?,
            ingress.link(),
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
            link: ingress.link(),
            next_hop: path::NextHop::Forwarder(forwarder),
            metric: 0,
        })
        .map_err(host_error)?;
        endpoint.enable_output_reservations().map_err(engine)?;
        host.attach(endpoint).map_err(host_error)?;
        Ok(Self {
            host,
            ingress,
            tun,
            deferred: VecDeque::new(),
            retained: VecDeque::new(),
            held: None,
            header_len: if local.is_ipv4() { 20 } else { 40 },
            time,
            clock: ntcp_clock::UtcClock::new(),
        })
    }

    fn owner(&self, endpoint: &Endpoint, frame: &[u8]) -> Option<ConnectionId> {
        let packet = self.host.decode_ingress(self.ingress, frame).ok()?;
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
    fn input(&mut self, endpoint: &mut Endpoint, frame: &[u8]) -> io::Result<()> {
        let now = self.now(endpoint)?;
        let Ok(decoded) = self.host.decode_ingress(self.ingress, frame) else {
            return Ok(());
        };
        if decoded.protocol == if decoded.ip.source.is_ipv4() { 1 } else { 58 } {
            let mut utc = Utc {
                clock: &mut self.clock,
                now,
            };
            if let Ok(IcmpDispatch::Deferred(deferred)) =
                self.host
                    .input_icmp(endpoint, self.ingress, now, frame, Some(&mut utc))
            {
                self.deferred.push_back(deferred);
            }
            return Ok(());
        }
        if let Some(owner) = self.owner(endpoint, frame)
            && endpoint.is_output_reserved(owner)
        {
            self.retained.push_back((owner, frame.to_vec()));
            return Ok(());
        }
        let _ = self.host.input_ip(
            endpoint,
            self.ingress,
            now,
            frame,
            ntcp::RxPacketMetadata::default(),
            0,
            None,
        );
        Ok(())
    }

    fn replay(&mut self, endpoint: &mut Endpoint) -> io::Result<()> {
        let now = self.now(endpoint)?;
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
            let (owner, frame) = self.retained.pop_front().unwrap();
            if endpoint.is_output_reserved(owner) {
                self.retained.push_back((owner, frame));
            } else if self.owner(endpoint, &frame) == Some(owner) {
                self.input(endpoint, &frame)?;
            }
        }
        Ok(())
    }

    // Every frame the TUN holds now; nothing is read while an attempt is held.
    fn receive(&mut self, endpoint: &mut Endpoint) -> io::Result<()> {
        self.replay(endpoint)?;
        let mut frame = vec![0u8; MAX_IP_PACKET + 1];
        while self.held.is_none() {
            match self.tun.receive(&mut frame) {
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
                    self.input(endpoint, &packet)?;
                }
                Ok(None) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    // One output pass: every packet the Endpoint selects, each submitted as
    // its own physical TUN write through the Host transaction.
    fn transmit(&mut self, endpoint: &mut Endpoint, output: &mut [u8]) -> io::Result<()> {
        let now = self.now(endpoint)?;
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
                let capacity = output.len().min(MTU);
                let built = match packet.ip.source {
                    IpAddr::V4(_) => ntcp_ip::encode(&mut output[..capacity], packet, 0)
                        .map_err(|e| other(format!("IPv4 encode: {e:?}"))),
                    IpAddr::V6(_) => ntcp_ip6::encode(&mut output[..capacity], packet)
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
            let frame = &output[..held.len];
            let tun = &mut self.tun;
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

    fn wait(&mut self, endpoint: &mut Endpoint) -> io::Result<()> {
        let now = self.now(endpoint)?;
        let delay = endpoint
            .next_deadline()
            .map_or(10_000, |deadline| deadline.saturating_sub(now).min(10_000));
        let timeout = if self.held.is_some() || endpoint.has_pending_output() {
            1
        } else {
            delay.div_ceil(1000) as i32
        };
        let mut fd = libc::pollfd {
            fd: self.tun.as_raw_fd(),
            events: libc::POLLIN
                | if self.held.is_some() {
                    libc::POLLOUT
                } else {
                    0
                },
            revents: 0,
        };
        // SAFETY: one initialized pollfd for the duration of the call.
        if unsafe { libc::poll(&mut fd, 1, timeout) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        Ok(())
    }

    fn drain_events(endpoint: &mut Endpoint) {
        while endpoint.next_event().is_some() {}
    }

    // Ordinary embedding service (ingress, timers, output) until `done`.
    fn serve(
        &mut self,
        endpoint: &mut Endpoint,
        output: &mut [u8],
        what: &str,
        mut done: impl FnMut(&Endpoint) -> io::Result<bool>,
    ) -> io::Result<()> {
        let deadline = self.now(endpoint)? + DEADLINE_US;
        loop {
            self.receive(endpoint)?;
            let now = self.now(endpoint)?;
            endpoint.on_timeout(now, BUDGET).map_err(engine)?;
            Self::drain_events(endpoint);
            self.transmit(endpoint, output)?;
            self.host.collect(endpoint).map_err(host_error)?;
            if self.held.is_none() && !endpoint.has_pending_output() && done(endpoint)? {
                return Ok(());
            }
            if self.now(endpoint)? > deadline {
                return Err(other(format!("{what} deadline")));
            }
            self.wait(endpoint)?;
        }
    }
}

fn config(local: IpAddr) -> EndpointConfig {
    let header_len = if local.is_ipv4() { 20 } else { 40 };
    EndpointConfig {
        max_connections: 4,
        preallocate_connections: 0,
        max_listeners: 1,
        max_control_packets: BUDGET,
        max_setup_cache_entries: 4,
        max_route_policies: 4,
        // Ample for the one connection and its output reservation.
        max_buffer_bytes: 64 << 20,
        buffer_pressure_bytes: None,
        buffer_low_bytes: None,
        hop_limit: 64,
        dscp: 0,
        ipv4_options_enabled: false,
        error_reports: true,
        reuse_time_wait: false,
        max_time_wait: EndpointConfig::default().max_time_wait,
        connection: ConnectionConfig {
            sack: true,
            // Each application write is its own segment.
            nagle: false,
            pmtud: Some(PmtudConfig::new(MTU as u32)),
            send_capacity: 65536,
            receive_capacity: 65536,
            mss: (MTU - header_len - 20) as u16,
            receive_ip_payload_limit: (MTU - header_len) as u16,
            send_ip_payload_limit: (MTU - header_len) as u16,
            ..ConnectionConfig::default()
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
    if args.len() != 4 {
        return Err(other(
            "usage: ptb_stage TUN_NAME LOCAL_IP PEER_SOCKET_ADDR".into(),
        ));
    }
    let local: IpAddr = args[2]
        .parse()
        .map_err(|_| other("invalid local IP".into()))?;
    let peer: SocketAddr = args[3].parse().map_err(|_| other("invalid peer".into()))?;
    let config = config(local);
    let mut secret = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut secret)?;
    let family_v4 = local.is_ipv4();
    let tun = Tun::open(&args[1])?;
    let mut time = ntcp_clock::TransportClock::new().map_err(io::Error::other)?;
    let started = time.sample().map_err(io::Error::other)?.ticks;
    // The namespace's own addresses are the only ones this sender opens.
    let mut endpoint = Endpoint::new(config.clone(), secret, started, move |request| match request {
        ntcp::AddressValidation::Bind { local: bind } => bind == local,
        ntcp::AddressValidation::Open {
            local: source,
            remote,
        } => source == local && remote == peer.ip(),
        ntcp::AddressValidation::Route { source, .. } => source == local,
        ntcp::AddressValidation::Incoming { destination, .. } => destination == local,
    })
    .map_err(engine)?;
    let mut network = Network::attach(&mut endpoint, &config, local, tun, time)?;
    let mut output = vec![0u8; MTU];
    let mut id = None;
    let mut written = 0usize;
    let salt = 41;
    emit(format!(
        "{{\"event\":\"ready\",\"family\":{},\"sack\":true,\"nagle\":false,\"tlp\":{},\"rack\":{},\"rto_min_us\":{}}}",
        if family_v4 { 4 } else { 6 },
        config.connection.tlp,
        config.connection.rack,
        config.connection.rto_min_us
    ));
    for line in io::stdin().lock().lines() {
        let line = line?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.first().copied() {
            None => continue,
            Some("quit") => break,
            Some("connect") => {
                let options = ntcp::ManagedOpenOptions {
                    transport: ntcp::ActiveOpenOptions::from(&config.connection),
                    dscp: 0,
                    ipv4_options: ntcp::OutgoingIpv4Options::default(),
                    registration: None,
                    receive_authority: None,
                };
                let now = network.now(&mut endpoint)?;
                let opened = endpoint
                    .connect_with_path_provider(
                        now,
                        SocketAddr::new(local, LOCAL_PORT),
                        peer,
                        options,
                        &mut network.host,
                    )
                    .map_err(|error| other(format!("connect: {error:?}")))?;
                id = Some(opened);
                network.serve(&mut endpoint, &mut output, "handshake", |endpoint| {
                    Ok(endpoint.state(opened).map_err(engine)? == State::Established)
                })?;
                emit(format!(
                    "{{\"event\":\"established\",\"local_port\":{LOCAL_PORT}}}"
                ));
            }
            Some("stage") => {
                let id = id.ok_or_else(|| other("stage before connect".into()))?;
                // Ingress queued since the handshake is serviced first; the
                // staged writes themselves then see no ingress at all.
                network.receive(&mut endpoint)?;
                let before = endpoint.send_progress(id).map_err(engine)?;
                let mut segments = Vec::new();
                for size in &fields[1..] {
                    let size: usize = size.parse().map_err(|_| other("invalid size".into()))?;
                    let bytes = pattern(size, written, salt);
                    let count = endpoint.write(id, &bytes).map_err(engine)?;
                    if count != size {
                        return Err(other(format!("short write {count}/{size}")));
                    }
                    written += size;
                    network.transmit(&mut endpoint, &mut output)?;
                    if network.held.is_some() {
                        return Err(other("TUN refused a staged write".into()));
                    }
                    let progress = endpoint.send_progress(id).map_err(engine)?;
                    segments.push(format!("[{},{}]", size, progress.next_write_sequence));
                }
                network.serve(&mut endpoint, &mut output, "stage", |endpoint| {
                    let progress = endpoint.send_progress(id).map_err(engine)?;
                    Ok(progress.acknowledged == progress.queued_end)
                })?;
                let after = endpoint.send_progress(id).map_err(engine)?;
                let mtu = endpoint
                    .path_mtu_info(id)
                    .map_err(engine)?
                    .map(|info| format!("{info:?}"));
                emit(format!(
                    "{{\"event\":\"staged\",\"start_sequence\":{},\"segments\":[{}],\"acknowledged\":{},\"written\":{written},\"path_mtu\":{:?}}}",
                    before.next_write_sequence,
                    segments.join(","),
                    after.acknowledged,
                    mtu.unwrap_or_default()
                ));
            }
            Some("close") => {
                let id = id.ok_or_else(|| other("close before connect".into()))?;
                endpoint.shutdown(id).map_err(engine)?;
                // FIN acknowledged: the peer application need not have closed.
                network.serve(&mut endpoint, &mut output, "close", |endpoint| {
                    Ok(matches!(
                        endpoint.state(id).map_err(engine)?,
                        State::FinWait2 | State::TimeWait | State::Closed
                    ))
                })?;
                emit(format!(
                    "{{\"event\":\"closed\",\"written\":{written},\"salt\":{salt}}}"
                ));
            }
            Some(other_command) => {
                return Err(other(format!("unknown command {other_command}")));
            }
        }
    }
    Ok(())
}
