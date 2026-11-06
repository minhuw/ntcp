use super::*;
use ntcp_io::PacketLayer;
use std::cell::Cell;

struct Backend {
    mtu: Option<u32>,
    errno: Option<i32>,
    queries: Cell<usize>,
    blocked: bool,
    rejected: bool,
    tx_errno: Option<i32>,
    attempts: usize,
    frames: Vec<Vec<u8>>,
}

impl Default for Backend {
    fn default() -> Self {
        Self {
            mtu: Some(MTU as u32),
            errno: None,
            queries: Cell::new(0),
            blocked: false,
            rejected: false,
            tx_errno: None,
            attempts: 0,
            frames: Vec::new(),
        }
    }
}

impl PacketIo for Backend {
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn local_ip_mtu(&self) -> io::Result<Option<u32>> {
        self.queries.set(self.queries.get() + 1);
        match self.errno {
            Some(errno) => Err(io::Error::from_raw_os_error(errno)),
            None => Ok(self.mtu),
        }
    }
    fn receive(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> {
        Ok(None)
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        self.attempts += 1;
        if let Some(errno) = self.tx_errno {
            return Err(io::Error::from_raw_os_error(errno));
        }
        if self.rejected {
            return Ok(TxOutcome::Rejected);
        }
        if self.blocked {
            return Ok(TxOutcome::WouldBlock);
        }
        self.frames.push(packet.to_vec());
        Ok(TxOutcome::Submitted)
    }
}

fn addresses(v6: bool) -> (SocketAddr, SocketAddr) {
    let (a, b) = if v6 {
        ("[2001:db8::1]:1234", "[2001:db8::2]:8080")
    } else {
        ("192.0.2.1:1234", "192.0.2.2:8080")
    };
    (a.parse().unwrap(), b.parse().unwrap())
}

// Whole replies only, the UDP echo's behavior before source fragmentation:
// evidence that relies on whole replies or the refusal wording selects it.
fn refuse_settings() -> DatagramSettings {
    DatagramSettings {
        udp_mode: UdpSendMode::Refuse,
        ..DatagramSettings::default()
    }
}

fn endpoint(local: IpAddr, timestamps: bool) -> (Endpoint, TunHost) {
    endpoint_with_options(local, timestamps, false)
}

fn endpoint_with_options(local: IpAddr, timestamps: bool, options: bool) -> (Endpoint, TunHost) {
    endpoint_with_settings(local, timestamps, options, &DatagramSettings::default())
}

fn endpoint_with_settings(
    local: IpAddr,
    timestamps: bool,
    options: bool,
    settings: &DatagramSettings,
) -> (Endpoint, TunHost) {
    let backend = Backend::default();
    let config = runtime_config(&backend, local, timestamps, true, options).unwrap();
    assert_eq!(backend.queries.get(), 1);
    let policy: Box<dyn Fn(AddressValidation) -> bool> = match local {
        IpAddr::V4(ip) => Box::new(tun_address_policy(ip, (ip, 24))),
        IpAddr::V6(ip) => Box::new(tun_v6_policy(ip)),
    };
    let mut endpoint = Endpoint::new(config.clone(), [7; 32], 0, ntcp::Lifecycle { boot_age: Some(u64::MAX), continuity: ntcp::SourceContinuity::Never }, policy).unwrap();
    let network = TunHost::attach_with(&mut endpoint, &config, local, settings, 0).unwrap();
    (endpoint, network)
}

// run()'s listener and active open with nothing stated: simulated time, the
// logic of the slow start and no evidence about a physical clock.
#[test]
fn premature_syn_is_dropped_and_the_active_open_waits_for_the_deadline() {
    const QUIET: u64 = 240_000_000;
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let settings = DatagramSettings::default();
        assert_eq!(settings.continuity_fact(), ntcp::SourceContinuity::Unknown);
        let lifecycle = ntcp::Lifecycle {
            boot_age: Some(u64::MAX),
            continuity: settings.continuity_fact(),
        };
        let config = runtime_config(&Backend::default(), local.ip(), false, true, false).unwrap();
        let policy: Box<dyn Fn(AddressValidation) -> bool> = match local.ip() {
            IpAddr::V4(ip) => Box::new(tun_address_policy(ip, (ip, 24))),
            IpAddr::V6(ip) => Box::new(tun_v6_policy(ip)),
        };
        let mut a = Endpoint::new(config.clone(), [7; 32], 0, lifecycle, policy).unwrap();
        let mut ahost = TunHost::attach_with(&mut a, &config, local.ip(), &settings, 0).unwrap();
        let listener = a.listen(local, MAX_FLOWS).unwrap();
        let (mut b, mut bhost) = endpoint(remote.ip(), false);
        let options = ntcp::ManagedOpenOptions {
            transport: ntcp::ActiveOpenOptions::from(&config.connection),
            dscp: config.dscp,
            ipv4_options: Default::default(),
            registration: None,
            receive_authority: None,
        };
        b.connect_with_path_provider(1, remote, local, options, &mut bhost.host)
            .unwrap();
        let syn = emit(&mut bhost, &mut b, 1, local.ip());
        assert_eq!(syn.len(), 1);

        let mut peer = Some(remote);
        let mut flows = Vec::new();
        input_frame(&mut ahost, &mut a, QUIET - 1, &syn[0], local.ip(), false, &mut Sample(0)).unwrap();
        open_when_admitted(&mut ahost, &mut a, QUIET - 1, local, &mut peer, options, &mut flows).unwrap();
        assert!(emit(&mut ahost, &mut a, QUIET - 1, remote.ip()).is_empty());
        assert_eq!(a.listener_queue_info(listener).unwrap().0, 0);
        assert_eq!((peer, flows.len()), (Some(remote), 0));

        open_when_admitted(&mut ahost, &mut a, QUIET, local, &mut peer, options, &mut flows).unwrap();
        assert_eq!((peer, flows.len()), (None, 1));
        let opened = emit(&mut ahost, &mut a, QUIET, remote.ip());
        assert_eq!(opened.len(), 1);
        let flags = segment(&opened[0]).header.flags;
        assert_eq!(flags & (ntcp::wire::SYN | ntcp::wire::ACK), ntcp::wire::SYN);
        open_when_admitted(&mut ahost, &mut a, QUIET, local, &mut peer, options, &mut flows).unwrap();
        assert_eq!(flows.len(), 1);
    }
}

#[test]
fn the_source_quiet_setting_states_the_lifecycle_fact() {
    let local = addresses(false).0.ip();
    for (value, fact) in [
        (None, ntcp::SourceContinuity::Unknown),
        (Some("never"), ntcp::SourceContinuity::Never),
        (Some("30"), ntcp::SourceContinuity::CeasedFor(30)),
    ] {
        let settings = DatagramSettings::parse(local, None, None, None, value).unwrap();
        assert_eq!(settings.continuity_fact(), fact);
    }
}

// These assertions use the same constructor, dispatcher and output loop as run.
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.7
//= type=test
//= reason=The supplied fixed-1500 TUN embedding queries and validates the real backend MTU, enables PMTUD with or without PAWS, and dispatches checksummed ICMP PTB through live tuple/sequence/exact-packet validation. Runtime-constructor and framed peer tests prove timestamp negotiation, IPv4 DF, bounded IPv4/IPv6 repairs, receiver/ACK byte progress, rejected feedback, committed-output retention, and ICMP-blackhole R1 fallback with ordinary congestion response and subsequent ACK-confirmed probing. This evidence covers the supplied embedding and existing core discovery, not arbitrary external embeddings, native IPv6 sockets or a full host ICMP service.
//# Setting the DF bit implies the use of Path MTU Discovery as described
//# in [RFC1191], [RFC1981], and [RFC4821]; thus, any TCP implementation
//# that implements PAWS MUST also implement Path MTU Discovery.
#[test]
fn runtime_mtu_and_option_selection() {
    for v6 in [false, true] {
        let local = addresses(v6).0.ip();
        for (timestamps, sack) in [(false, true), (true, false)] {
            let backend = Backend::default();
            let cfg = runtime_config(&backend, local, timestamps, sack, !v6).unwrap();
            assert_eq!(backend.queries.get(), 1);
            assert_eq!(cfg.connection.pmtud, Some(PmtudConfig::new(1500)));
            assert_eq!(cfg.connection.timestamps, timestamps);
            assert_eq!(cfg.connection.sack, sack);
            assert_eq!(cfg.ipv4_options_enabled, !v6);
            let payload = if v6 { 1460 } else { 1480 };
            assert_eq!(cfg.connection.send_ip_payload_limit, payload);
            assert_eq!(cfg.connection.mss, payload - 20);
            // No static receive limit: the managed offer is the Host's
            // derivation (asserted on the wire by Pair::with_options).
            assert_eq!(
                cfg.connection.receive_ip_payload_limit,
                ConnectionConfig::default().receive_ip_payload_limit
            );
            assert_eq!(cfg.connection.send_capacity, 65536);
            assert_eq!(cfg.connection.receive_capacity, 65536);
        }
        for mtu in [
            None,
            Some(0),
            Some(1280),
            Some(1499),
            Some(1501),
            Some(9000),
        ] {
            let backend = Backend {
                mtu,
                ..Default::default()
            };
            let error = runtime_config(&backend, local, true, false, false).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("1500"));
            assert_eq!(backend.queries.get(), 1);
        }
        let backend = Backend {
            errno: Some(libc::EIO),
            ..Default::default()
        };
        let error = runtime_config(&backend, local, false, false, false).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert_eq!(backend.queries.get(), 1);
    }
}

fn header(frame: &[u8]) -> usize {
    if frame[0] >> 4 == 6 {
        IPV6_HEADER
    } else {
        usize::from(frame[0] & 15) * 4
    }
}

// A TCP segment of a frame this embedding sent, checksummed over its final
// destination: after an SR route's Segment Routing Header, Segment List[0].
pub(super) fn segment(frame: &[u8]) -> ntcp::wire::Segment<'_> {
    let (ip, tcp) = if frame[0] >> 4 == 6 {
        let (ip, header, total, protocol) = ntcp_ip6::quote_header(frame).unwrap();
        assert_eq!((total, protocol), (frame.len(), 6));
        (ip, &frame[header..])
    } else {
        let p = ntcp_ip::parse(frame, false).unwrap();
        assert_eq!(
            u16::from_be_bytes([frame[6], frame[7]]),
            0x4000,
            "DF on every control/data/probe/repair"
        );
        (p.ip, p.payload)
    };
    ntcp::wire::parse(ip, tcp).unwrap()
}

pub(super) fn emit(
    network: &mut TunHost,
    endpoint: &mut Endpoint,
    time: u64,
    local: IpAddr,
) -> Vec<Vec<u8>> {
    let mut backend = Backend::default();
    let mut output = [0; MTU];
    let mut pending = None;
    transmit_frames(
        network,
        endpoint,
        time,
        &mut output,
        &mut pending,
        if local.is_ipv4() {
            IP_HEADER
        } else {
            IPV6_HEADER
        },
        &mut Sample(0x8000_0000 | (time / 1000) as u32),
        &mut backend,
    )
    .unwrap();
    assert!(pending.is_none());
    for frame in &backend.frames {
        segment(frame);
    }
    backend.frames
}

struct Pair {
    a: Endpoint,
    ahost: TunHost,
    b: Endpoint,
    bhost: TunHost,
    aid: ConnectionId,
    bid: ConnectionId,
    local: SocketAddr,
    remote: SocketAddr,
    time: u64,
}

impl Pair {
    fn new(v6: bool, timestamps: bool) -> Self {
        Self::with_options(v6, timestamps, false)
    }

    // `options`: the NTCP_IPV4_OPTIONS profile (IPv4 only).
    fn with_options(v6: bool, timestamps: bool, options: bool) -> Self {
        let (local, remote) = addresses(v6);
        let (mut a, mut ahost) = endpoint_with_options(local.ip(), timestamps, options);
        let (mut b, mut bhost) = endpoint_with_options(remote.ip(), timestamps, options);
        // Match run(): an active opener also retains its passive listener.
        a.listen(local, MAX_FLOWS).unwrap();
        let listener = b.listen(remote, MAX_FLOWS).unwrap();
        let cfg = runtime_config(&Backend::default(), local.ip(), timestamps, true, false).unwrap();
        let aid = a
            .connect_with_path_provider(
                0,
                local,
                remote,
                ntcp::ManagedOpenOptions {
                    transport: ntcp::ActiveOpenOptions::from(&cfg.connection),
                    dscp: cfg.dscp,
                    ipv4_options: Default::default(),
                    registration: None,
                    receive_authority: None,
                },
                &mut ahost.host,
            )
            .unwrap();
        for passive in [false, true] {
            let (from_host, from, to_host, to, destination, time, flags) = if passive {
                (
                    &mut bhost,
                    &mut b,
                    &mut ahost,
                    &mut a,
                    local.ip(),
                    2000,
                    ntcp::wire::SYN | ntcp::wire::ACK,
                )
            } else {
                (
                    &mut ahost,
                    &mut a,
                    &mut bhost,
                    &mut b,
                    remote.ip(),
                    1000,
                    ntcp::wire::SYN,
                )
            };
            let frames = emit(from_host, from, time, destination);
            assert_eq!(frames.len(), 1);
            let syn = segment(&frames[0]);
            assert_eq!(
                syn.header.flags & (ntcp::wire::SYN | ntcp::wire::ACK),
                flags
            );
            // The SYN and SYN-ACK offer the sender Host's receive capability:
            // its one 1500-octet link, below the 65535/65575-octet reassembly
            // and 65575-octet backend receive capacity, less the base headers.
            let capability = from_host.host.receive_ip_capability(v6).unwrap();
            assert_eq!(syn.options.mss, Some(capability.mss()));
            assert_eq!(
                usize::from(capability.mss()),
                MTU - if v6 { IPV6_HEADER } else { IP_HEADER } - 20
            );
            assert_eq!(syn.options.timestamps.is_some(), timestamps);
            input_frame(to_host, to, time, &frames[0], destination, options, &mut Sample(0)).unwrap();
        }
        let final_ack = emit(&mut ahost, &mut a, 3000, local.ip());
        assert_eq!(final_ack.len(), 1);
        let ack = segment(&final_ack[0]);
        assert_eq!(
            ack.header.flags & (ntcp::wire::SYN | ntcp::wire::ACK),
            ntcp::wire::ACK
        );
        assert!(ack.payload.is_empty());
        assert_eq!(ack.options.timestamps.is_some(), timestamps);
        for frame in final_ack {
            input_frame(&mut bhost, &mut b, 3000, &frame, remote.ip(), options, &mut Sample(0)).unwrap();
        }
        let bid = b.accept(listener).unwrap();
        for (e, id) in [(&a, aid), (&b, bid)] {
            assert_eq!(e.state(id).unwrap(), State::Established);
            assert_eq!(
                e.transport_info(id).unwrap().timestamps_negotiated,
                timestamps
            );
            assert_eq!(e.path_mtu_info(id).unwrap().unwrap().first_hop_mtu, 1500);
            // The 65536-byte send buffer is reported as configured and
            // rounded down to whole segments for admission (the IPv4
            // options profile's segments are smaller still).
            let info = e.transport_info(id).unwrap();
            assert_eq!(info.send_capacity, 65536);
            let q = info.mss as usize;
            assert_eq!(info.send_space, 65536 / q * q);
            if !options {
                assert_eq!(
                    (info.mss, info.send_space),
                    match (v6, timestamps) {
                        (false, false) => (1460, 44 * 1460),
                        (false, true) => (1448, 45 * 1448),
                        (true, false) => (1440, 45 * 1440),
                        (true, true) => (1428, 45 * 1428),
                    }
                );
            }
        }
        Self {
            a,
            ahost,
            b,
            bhost,
            aid,
            bid,
            local,
            remote,
            time: 3000,
        }
    }

    fn next_timeout(&mut self) {
        let deadline = [self.a.next_deadline(), self.b.next_deadline()]
            .into_iter()
            .flatten()
            .min()
            .expect("outstanding data needs a deadline");
        assert!(deadline >= self.time);
        self.time = deadline;
        self.a.on_timeout(self.time, BUDGET).unwrap();
        self.b.on_timeout(self.time, BUDGET).unwrap();
    }

    // Drop only packets larger than this path. No synthetic ACKs or private
    // transport controls: every byte and ACK traverses the runtime dispatcher.
    fn progress(&mut self, path: usize, expected: &[u8]) -> (usize, Vec<Vec<u8>>) {
        let mut received = Vec::new();
        let mut sent = Vec::new();
        let mut drops = 0;
        for _ in 0..200 {
            for frame in emit(&mut self.ahost, &mut self.a, self.time, self.local.ip()) {
                let tcp = segment(&frame);
                if !tcp.payload.is_empty() {
                    assert!(tcp.options.timestamps.is_some());
                }
                if frame.len() > path {
                    drops += 1;
                } else {
                    input_frame(
                        &mut self.bhost,
                        &mut self.b,
                        self.time,
                        &frame,
                        self.remote.ip(),
                        false,
                        &mut Sample(0),
                    )
                    .unwrap();
                }
                sent.push(frame);
            }
            let mut bytes = [0; 65536];
            match self.b.read(self.bid, &mut bytes) {
                Ok(n) => received.extend_from_slice(&bytes[..n]),
                Err(EndpointError::Connection(Error::WouldBlock)) => {}
                other => panic!("receiver: {other:?}"),
            }
            for frame in emit(&mut self.bhost, &mut self.b, self.time, self.remote.ip()) {
                input_frame(
                    &mut self.ahost,
                    &mut self.a,
                    self.time,
                    &frame,
                    self.local.ip(),
                    false,
                    &mut Sample(0),
                )
                .unwrap();
            }
            let info = self.a.transport_info(self.aid).unwrap();
            if received.len() == expected.len() && info.unacked == 0 && info.notsent_bytes == 0 {
                assert_eq!(
                    received, expected,
                    "ordered stream, no missing or duplicated bytes"
                );
                assert!(matches!(
                    self.b.read(self.bid, &mut bytes),
                    Err(EndpointError::Connection(Error::WouldBlock))
                ));
                return (drops, sent);
            }
            self.next_timeout();
        }
        panic!(
            "receiver stalled at {}/{}: {:?}",
            received.len(),
            expected.len(),
            self.a.transport_info(self.aid)
        );
    }
}

#[test]
fn runtime_zero_mtu_icmp_uses_live_host_plateaus_and_transport_overrides() {
    let mut p = Pair::new(false, false);
    p.a.write(p.aid, &[7; 1460]).unwrap();
    let original = emit(&mut p.ahost, &mut p.a, p.time, p.local.ip()).pop().unwrap();
    assert_eq!(original.len(), 1500);
    let report = ptb(&original, 0);
    let feedback = ntcp_icmp::decode_icmp(&report).unwrap();
    assert_eq!(feedback.kind, ntcp_icmp::FeedbackKind::PacketTooBig);
    assert_eq!(feedback.candidate_mtu, None); // zero-next-hop legacy feedback
    input_frame(&mut p.ahost, &mut p.a, p.time, &report, p.local.ip(), false, &mut Sample(0)).unwrap();
    assert_eq!(p.a.path_mtu_info(p.aid).unwrap().unwrap().current_mtu, 1460);
    p.ahost.host.set_ipv4_plateaus(path::Ipv4Plateaus::new(&[1500, 1200, 68]).unwrap()).unwrap();
    p.ahost.host.refresh(&mut p.a, p.aid).unwrap();
    input_frame(&mut p.ahost, &mut p.a, p.time + 1, &report, p.local.ip(), false, &mut Sample(0)).unwrap();
    assert_eq!(p.a.path_mtu_info(p.aid).unwrap().unwrap().current_mtu, 1200);
    p.a.set_pmtud_policy(p.time + 2, p.aid, ntcp::PmtudPolicy {
        ipv4_plateaus: ntcp::Ipv4Plateaus::HISTORICAL, ..Default::default()
    }).unwrap();
    p.ahost.host.set_ipv4_plateaus(path::Ipv4Plateaus::new(&[1500, 900, 68]).unwrap()).unwrap();
    p.ahost.host.refresh(&mut p.a, p.aid).unwrap();
    input_frame(&mut p.ahost, &mut p.a, p.time + 3, &report, p.local.ip(), false, &mut Sample(0)).unwrap();
    assert_eq!(p.a.path_mtu_info(p.aid).unwrap().unwrap().current_mtu, 1006);
    // The shared publication never undercuts the decrease the owner applied
    // under its own plateau policy: the override keeps its local meaning.
    let path = p.ahost.host.binding(p.aid).unwrap().snapshot.path();
    let learned = |p: &Pair| p.ahost.host.paths().path_snapshot(path).unwrap().learned_mtu();
    assert_eq!(learned(&p), Some(1006), "published the owner's applied decrease");
    p.ahost.host.refresh(&mut p.a, p.aid).unwrap();
    assert_eq!(p.a.managed_path(p.aid).unwrap().ordinary_ip_budget, 1006);
    eprintln!("ZERO_MTU override=HISTORICAL host_table=900 tcp=1006 published={:?} budget={}",
        learned(&p), p.a.managed_path(p.aid).unwrap().ordinary_ip_budget);
    // Following the live Host table again, TCP and the Host agree.
    p.a.set_pmtud_policy(p.time + 4, p.aid, ntcp::PmtudPolicy::default()).unwrap();
    input_frame(&mut p.ahost, &mut p.a, p.time + 5, &report, p.local.ip(), false, &mut Sample(0)).unwrap();
    assert_eq!(p.a.path_mtu_info(p.aid).unwrap().unwrap().current_mtu, 900);
    assert_eq!(learned(&p), Some(900), "correlated decrease from the Host plateau table");
    eprintln!("ZERO_MTU override=INHERIT host_table=900 tcp=900 published={:?}", learned(&p));
}

#[test]
fn runtime_zero_mtu_override_below_host_table_publishes_the_host_value() {
    let mut p = Pair::new(false, false);
    p.a.write(p.aid, &[7; 1460]).unwrap();
    let original = emit(&mut p.ahost, &mut p.a, p.time, p.local.ip()).pop().unwrap();
    assert_eq!(original.len(), 1500);
    let report = ptb(&original, 0);
    p.ahost.host.set_ipv4_plateaus(path::Ipv4Plateaus::new(&[1500, 1200, 68]).unwrap()).unwrap();
    p.a.set_pmtud_policy(p.time + 1, p.aid, ntcp::PmtudPolicy {
        ipv4_plateaus: ntcp::Ipv4Plateaus::HISTORICAL, ..Default::default()
    }).unwrap();
    p.ahost.host.refresh(&mut p.a, p.aid).unwrap();
    input_frame(&mut p.ahost, &mut p.a, p.time + 2, &report, p.local.ip(), false, &mut Sample(0)).unwrap();
    assert_eq!(p.a.path_mtu_info(p.aid).unwrap().unwrap().current_mtu, 1006);
    // One connection's override never lowers other clients below the
    // Host's own table; the connection keeps its lower local value.
    let path = p.ahost.host.binding(p.aid).unwrap().snapshot.path();
    let learned = p.ahost.host.paths().path_snapshot(path).unwrap().learned_mtu();
    assert_eq!(learned, Some(1200));
    p.ahost.host.refresh(&mut p.a, p.aid).unwrap();
    assert_eq!(p.a.managed_path(p.aid).unwrap().ordinary_ip_budget, 1006);
    assert_eq!(p.a.path_mtu_info(p.aid).unwrap().unwrap().current_mtu, 1006);
    eprintln!("ZERO_MTU override=HISTORICAL host_table=1200 tcp=1006 published={learned:?} budget={}",
        p.a.managed_path(p.aid).unwrap().ordinary_ip_budget);
}

#[test]
fn runtime_source_quench_discards_without_touching_reserved_owner_or_clock() {
    let mut p = Pair::new(false, true);
    let payload = vec![0x3c; 12000];
    p.a.write(p.aid, &payload).unwrap();
    let mut backend = Backend { blocked: true, ..Default::default() };
    let mut output = [0; MTU];
    let mut pending = None;
    transmit_frames(&mut p.ahost, &mut p.a, p.time, &mut output,
        &mut pending, IP_HEADER, &mut Sample(0), &mut backend).unwrap();
    let held = pending.as_ref().unwrap();
    let attempt = held.attempt;
    let mut report = ptb(&output[..held.len], 0);
    report[IP_HEADER] = 4;
    report[IP_HEADER + 1] = 0;
    seal_feedback(&mut report);
    assert_eq!(ntcp_icmp::decode_icmp(&report).unwrap().kind,
        ntcp_icmp::FeedbackKind::SourceQuench);
    let Ok(Received::Datagram(datagram)) =
        p.ahost.host.receive(p.ahost.ingress, p.time, &report, false, &mut [])
    else {
        panic!("an unfragmented report is a complete datagram");
    };
    let datagram = p.ahost.host.process(datagram, None).unwrap();
    assert_eq!(p.ahost.owner(&p.a, datagram), None);
    let before = (p.a.transport_info(p.aid).unwrap(), p.a.path_mtu_info(p.aid).unwrap(),
        p.a.next_deadline(), p.a.send_progress(p.aid).unwrap());
    // A discarded message must not advance the caller's clock either.
    input_frame(&mut p.ahost, &mut p.a, p.time + 1_000_000, &report,
        p.local.ip(), false, &mut Sample(0)).unwrap();
    assert_eq!((p.a.transport_info(p.aid).unwrap(), p.a.path_mtu_info(p.aid).unwrap(),
        p.a.next_deadline(), p.a.send_progress(p.aid).unwrap()), before);
    assert!(p.a.is_output_reserved(p.aid));
    assert!(p.a.transmit_attempt_packet(attempt).is_some());
    assert!(p.ahost.received.is_empty());
    backend.blocked = false;
    transmit_frames(&mut p.ahost, &mut p.a, p.time, &mut output,
        &mut pending, IP_HEADER, &mut Sample(0), &mut backend).unwrap();
    assert!(pending.is_none());
    for frame in &backend.frames {
        input_frame(&mut p.bhost, &mut p.b, p.time, frame, p.remote.ip(), false, &mut Sample(0)).unwrap();
    }
    p.progress(MTU, &payload);
}

#[test]
fn runtime_exhausted_timestamp_discards_then_valid_stream_progresses() {
    let (local, remote) = addresses(false);
    let (mut a, mut ahost) = endpoint(local.ip(), false);
    let (mut b, mut bhost) = endpoint_with_options(remote.ip(), false, true);
    let listener = b.listen(remote, MAX_FLOWS).unwrap();
    let cfg = runtime_config(&Backend::default(), local.ip(), false, true, false).unwrap();
    let aid = a.connect_with_path_provider(0, local, remote, ntcp::ManagedOpenOptions {
        transport: ntcp::ActiveOpenOptions::from(&cfg.connection), dscp: 0,
        ipv4_options: Default::default(), registration: None, receive_authority: None,
    }, &mut ahost.host).unwrap();
    let syn = emit(&mut ahost, &mut a, 1, local.ip()).pop().unwrap();
    let mut exhausted = syn.clone();
    exhausted.splice(20..20, [68, 4, 5, 0xf0]);
    exhausted[0] = 0x46;
    let n = exhausted.len() as u16;
    exhausted[2..4].copy_from_slice(&n.to_be_bytes());
    seal_ip(&mut exhausted);
    let packet = bhost.host.decode_ingress(bhost.ingress, &exhausted).unwrap();
    let IpAddr::V4(local_ip) = remote.ip() else { unreachable!() };
    assert!(packet.options.record(local_ip, 123).is_err());
    let before = b.next_deadline();
    input_frame(&mut bhost, &mut b, 1_000_000, &exhausted, remote.ip(), true, &mut Sample(123)).unwrap();
    assert_eq!(b.next_deadline(), before);
    assert_eq!(bhost.host.binding_count(), 0);
    // Use the original time to also prove the failed option did not advance it.
    input_frame(&mut bhost, &mut b, 2, &syn, remote.ip(), true, &mut Sample(124)).unwrap();
    let reply = emit(&mut bhost, &mut b, 3, remote.ip()).pop().unwrap();
    input_frame(&mut ahost, &mut a, 4, &reply, local.ip(), false, &mut Sample(0)).unwrap();
    for frame in emit(&mut ahost, &mut a, 5, local.ip()) {
        input_frame(&mut bhost, &mut b, 6, &frame, remote.ip(), true, &mut Sample(125)).unwrap();
    }
    let bid = b.accept(listener).unwrap();
    let payload = b"valid traffic after exhausted Timestamp";
    a.write(aid, payload).unwrap();
    for frame in emit(&mut ahost, &mut a, 7, local.ip()) {
        input_frame(&mut bhost, &mut b, 8, &frame, remote.ip(), true, &mut Sample(126)).unwrap();
    }
    let ack_time = b.next_deadline().unwrap();
    b.on_timeout(ack_time, BUDGET).unwrap();
    for frame in emit(&mut bhost, &mut b, ack_time, remote.ip()) {
        input_frame(&mut ahost, &mut a, ack_time + 1, &frame, local.ip(), false, &mut Sample(0)).unwrap();
    }
    let mut bytes = [0; 128];
    assert_eq!(b.read(bid, &mut bytes).unwrap(), payload.len());
    assert_eq!(&bytes[..payload.len()], payload);
    assert_eq!(a.transport_info(aid).unwrap().unacked, 0);
}

#[test]
fn runtime_held_stateless_reset_recovers_route_and_source_replacement() {
    for replace_source in [false, true] {
        let (local, remote) = addresses(false);
        let (mut a, mut ahost) = endpoint(local.ip(), false);
        let (mut b, mut bhost) = endpoint(remote.ip(), false);
        let cfg = runtime_config(&Backend::default(), local.ip(), false, true, false).unwrap();
        let id = a.connect_with_path_provider(0, local, remote, ntcp::ManagedOpenOptions {
            transport: ntcp::ActiveOpenOptions::from(&cfg.connection), dscp: 0,
            ipv4_options: Default::default(), registration: None, receive_authority: None,
        }, &mut ahost.host).unwrap();
        let syn = emit(&mut ahost, &mut a, 1, local.ip()).pop().unwrap();
        input_frame(&mut bhost, &mut b, 2, &syn, remote.ip(), false, &mut Sample(0)).unwrap();
        let mut backend = Backend { blocked: true, ..Default::default() };
        let mut output = [0; MTU];
        let mut pending = None;
        transmit_frames(&mut bhost, &mut b, 3, &mut output, &mut pending,
            IP_HEADER, &mut Sample(0), &mut backend).unwrap();
        let held = pending.as_ref().unwrap();
        assert!(b.transmit_attempt_packet(held.attempt).unwrap().connection.is_none());
        let old = held.context.unwrap();
        let staged = output[..held.len].to_vec();
        let route = bhost.host.paths().route(old.binding.snapshot.key().route()).unwrap();
        if replace_source {
            bhost.host.remove_source_owner(old.binding.snapshot.key().source(), bhost.ingress.link()).unwrap();
        } else {
            bhost.host.remove_route(old.binding.snapshot.key().route()).unwrap();
        }
        backend.blocked = false;
        let calls = backend.attempts;
        transmit_frames(&mut bhost, &mut b, 4, &mut output, &mut pending,
            IP_HEADER, &mut Sample(0), &mut backend).unwrap();
        assert_eq!(backend.attempts, calls);
        assert!(pending.as_ref().unwrap().blocked);
        assert!(bhost.host.paths().is_dirty(old.binding.client).unwrap());
        if replace_source {
            bhost.host.register_source(path::ScopedAddress::new(remote.ip(), None).unwrap(), bhost.ingress.link()).unwrap();
        } else {
            bhost.host.add_route(route).unwrap();
        }
        transmit_frames(&mut bhost, &mut b, 5, &mut output, &mut pending,
            IP_HEADER, &mut Sample(0), &mut backend).unwrap();
        assert!(pending.is_none());
        assert_eq!(backend.frames, vec![staged]);
        assert_eq!(bhost.host.lease_count(), 0);
        assert_eq!(bhost.host.paths().usage().clients, 0);
        input_frame(&mut ahost, &mut a, 6, &backend.frames[0], local.ip(), false, &mut Sample(0)).unwrap();
        assert_eq!(a.state(id).unwrap(), State::Closed);
    }
}

// Construct a checksummed PTB with a minimum quote of an actual emitted frame.
// The source is an intermediate router, deliberately distinct from either peer.
fn ptb(frame: &[u8], mtu: u32) -> Vec<u8> {
    let h = header(frame);
    let v6 = frame[0] >> 4 == 6;
    let mut packet = vec![0; h + 8 + h + 8];
    packet[..h].copy_from_slice(&frame[..h]);
    if v6 {
        packet[8..24].copy_from_slice(&"2001:db8::fe".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&frame[8..24]);
        packet[4..6].copy_from_slice(&((8 + h + 8) as u16).to_be_bytes());
        packet[6] = 58;
    } else {
        packet[12..16].copy_from_slice(&[192, 0, 2, 254]);
        packet[16..20].copy_from_slice(&frame[12..16]);
        let total = packet.len() as u16;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[9] = 1;
    }
    packet[h] = if v6 { 2 } else { 3 };
    packet[h + 1] = if v6 { 0 } else { 4 };
    packet[h + 4..h + 8].copy_from_slice(&mtu.to_be_bytes());
    packet[h + 8..].copy_from_slice(&frame[..h + 8]);
    seal_feedback(&mut packet);
    packet
}

fn seal_ip(packet: &mut [u8]) {
    packet[10..12].fill(0);
    let sum = checksum(&packet[..header(packet)]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
}

fn seal_feedback(packet: &mut [u8]) {
    let h = header(packet);
    packet[h + 2..h + 4].fill(0);
    let sum = if packet[0] >> 4 == 6 {
        ntcp_icmp::icmpv6_checksum(
            IpMetadata {
                source: Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap()).into(),
                destination: Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap()).into(),
            },
            &packet[h..],
        )
        .unwrap()
    } else {
        seal_ip(packet);
        checksum(&packet[h..])
    };
    packet[h + 2..h + 4].copy_from_slice(&sum.to_be_bytes());
}

#[test]
fn runtime_active_passive_without_timestamps_still_discovers() {
    for v6 in [false, true] {
        Pair::new(v6, false);
    }
}

//= https://www.rfc-editor.org/rfc/rfc7323#section-5.7
//= type=test
//= reason=The supplied fixed-1500 TUN embedding queries and validates the real backend MTU, enables PMTUD with or without PAWS, and dispatches checksummed ICMP PTB through live tuple/sequence/exact-packet validation. Runtime-constructor and framed peer tests prove timestamp negotiation, IPv4 DF, bounded IPv4/IPv6 repairs, receiver/ACK byte progress, rejected feedback, committed-output retention, and ICMP-blackhole R1 fallback with ordinary congestion response and subsequent ACK-confirmed probing. This evidence covers the supplied embedding and existing core discovery, not arbitrary external embeddings, native IPv6 sockets or a full host ICMP service.
//# Setting the DF bit implies the use of Path MTU Discovery as described
//# in [RFC1191], [RFC1981], and [RFC4821]; thus, any TCP implementation
//# that implements PAWS MUST also implement Path MTU Discovery.
//= https://www.rfc-editor.org/rfc/rfc4821#section-4
//= type=test
//= reason=Host fragmentation mimics IPv6 and happens only in the host: Host UDP datagrams in Fragment mode and the Host's Echo Replies (a reply to an IPv4 source-routed Echo Request takes the reversed, policy-authorized return route, registers no adjunct demand and is never sized by an adjunct-confirmed bound, while IPv6 Echo Replies use only owner-configured routes) leave through one datagram emitter (Host::transmit, crates/stacks/ntcp-host/src/emitter.rs) that cuts an IPv4 datagram larger than the connectionless effective size with ntcp_ip::Fragmenter, which sets DF on every fragment, just as it cuts IPv6 (every fragment repeats the unfragmentable part, the base header and on an owner-configured Segment Routing route its Segment Routing Header, before the Fragment header, and the first fragment holds the complete upper-layer header); the atomic IPv4 encoder (encode_present) sets DF on every unfragmented packet, and TCP never enters source fragmentation. Host tests assert DF on every IPv4 fragment and packet of a fragmented send, the tun_echo IPv4 path asserts DF on TCP packets and PLPMTUD probes, and the integration/rfc_host fragment, fragment-ptb and adjunct-silence cases check DF on every captured IPv4 fragment and probe. User disposition of the SHOULD (recorded): an application that sets IP_MTU_DISCOVER=IP_PMTUDISC_DONT on a native socket gets its ordinary IPv4 TCP output without DF, an application-requested exception; every such packet carries an Identification leased from the Host allocator for its (source, destination, TCP) tuple, the RFC 6864 ceiling holds the packet instead of reusing a value, its PLPMTUD probes keep DF and TCP is never source-fragmented (ntcp-socket tests managed_dont_leases_identifiers_keeps_df_on_probes_and_holds_at_the_ceiling and dont_packets_follow_the_source_quiet_assertion). User disposition for administratively flagged routes (recorded decision B): on an IPv4 route or path whose owner disabled discovery (RFC 1191 section 6.6, which RFC 4821 does not update) every packet of TCP, Host::udp_send, Host::udp_send_datagram and Echo replies, Host source fragments included, leaves DF clear with a leased Identification and a recomputed header checksum under the RFC 1122 section 3.3.3 sending limit, and no probe is sent there; fragments on enabled routes keep DF (ntcp-host tests disabled_ipv4_route_clears_df_on_udp_datagrams_and_source_fragments, disabling_one_ipv4_route_leaves_a_neighbor_route_keeping_df_on_fragments and disabled_ipv4_route_clears_df_on_whole_udp_send_datagrams).
//# All hosts SHOULD use IPv4 fragmentation in a mode that mimics IPv6 functionality. All fragmentation SHOULD be done on the host, and all IPv4 packets, including fragments, SHOULD have the DF bit set such that they will not be fragmented (again) in the network. See Section 8.
#[test]
fn runtime_ptb_repairs_and_receiver_ack_progress() {
    for v6 in [false, true] {
        let mut p = Pair::new(v6, true);
        let payload: Vec<u8> = (0..12000).map(|n| (n % 251) as u8).collect();
        assert_eq!(p.a.write(p.aid, &payload).unwrap(), payload.len());
        let frames = emit(&mut p.ahost, &mut p.a, p.time, p.local.ip());
        let original = &frames[0];
        let path = if v6 { 1280 } else { 1006 };
        assert!(original.len() > path);
        assert!(segment(original).options.timestamps.is_some());
        let report = ptb(original, path as u32);
        assert_ne!(
            ntcp_icmp::decode_icmp(&report).unwrap().outer.source,
            p.remote.ip()
        );
        input_frame(
            &mut p.ahost,
            &mut p.a,
            p.time,
            &report,
            p.local.ip(),
            false,
            &mut Sample(0),
        )
        .unwrap();
        assert_eq!(
            p.a.path_mtu_info(p.aid).unwrap().unwrap().current_mtu,
            path as u32
        );
        let (_, repairs) = p.progress(path, &payload);
        assert!(!repairs.is_empty());
        assert!(
            repairs.iter().all(|frame| frame.len() <= path),
            "full IP budget including timestamp overhead"
        );
        assert!(repairs.iter().any(|f| {
            segment(f).header.sequence == segment(original).header.sequence
                && f.len() < original.len()
        }));
        let before = p.a.path_mtu_info(p.aid).unwrap();
        // An acknowledged original quote is stale, even with a lower candidate.
        let stale = ptb(original, if v6 { 1280 } else { 508 });
        input_frame(
            &mut p.ahost,
            &mut p.a,
            p.time,
            &stale,
            p.local.ip(),
            false,
            &mut Sample(0),
        )
        .unwrap();
        assert_eq!(p.a.path_mtu_info(p.aid).unwrap(), before);
    }
}

// The supplied embedding admits whole segments of its 65536-byte buffer and
// re-rounds on a PMTU change: IPv4's smaller C keeps the bytes already
// admitted above it, IPv6's larger C reopens room, and the receiver gets the
// whole stream.
#[test]
fn runtime_send_space_rounds_to_segments_across_pmtu_change() {
    for v6 in [false, true] {
        let mut p = Pair::new(v6, true);
        let stream: Vec<u8> = (0..200_000).map(|n| (n % 253) as u8).collect();
        let first = p.a.write(p.aid, &stream).unwrap();
        assert_eq!(first, if v6 { 45 * 1428 } else { 45 * 1448 });
        assert!(matches!(
            p.a.write(p.aid, &stream[first..]),
            Err(EndpointError::Connection(Error::WouldBlock))
        ));
        let frames = emit(&mut p.ahost, &mut p.a, p.time, p.local.ip());
        let path = if v6 { 1280 } else { 1006 };
        assert!(frames[0].len() > path);
        let report = ptb(&frames[0], path as u32);
        input_frame(
            &mut p.ahost,
            &mut p.a,
            p.time,
            &report,
            p.local.ip(),
            false,
            &mut Sample(0),
        )
        .unwrap();
        let info = p.a.transport_info(p.aid).unwrap();
        let q = path - if v6 { IPV6_HEADER } else { IP_HEADER } - 20 - 12;
        assert_eq!(info.mss as usize, q);
        assert_eq!(info.send_capacity, 65536);
        assert_eq!(info.send_space, 65536 / q * q);
        assert_eq!(info.send_used, first);
        let more = match p.a.write(p.aid, &stream[first..]) {
            Ok(n) => n,
            Err(EndpointError::Connection(Error::WouldBlock)) => 0,
            other => panic!("{other:?}"),
        };
        // IPv4: 68 * 954 < 45 * 1448; IPv6: 54 * 1208 > 45 * 1428.
        assert_eq!(more, if v6 { 54 * 1208 - first } else { 0 });
        let total = first + more;
        p.progress(path, &stream[..total]);
        let info = p.a.transport_info(p.aid).unwrap();
        let q = info.mss as usize;
        assert_eq!(info.send_space, 65536 / q * q);
        assert_eq!(p.a.write(p.aid, &stream[total..]).unwrap(), info.send_space);
    }
}

//= https://www.rfc-editor.org/rfc/rfc7323#section-5.7
//= type=test
//= reason=The supplied fixed-1500 TUN embedding queries and validates the real backend MTU, enables PMTUD with or without PAWS, and dispatches checksummed ICMP PTB through live tuple/sequence/exact-packet validation. Runtime-constructor and framed peer tests prove timestamp negotiation, IPv4 DF, bounded IPv4/IPv6 repairs, receiver/ACK byte progress, rejected feedback, committed-output retention, and ICMP-blackhole R1 fallback with ordinary congestion response and subsequent ACK-confirmed probing. This evidence covers the supplied embedding and existing core discovery, not arbitrary external embeddings, native IPv6 sockets or a full host ICMP service.
//# Setting the DF bit implies the use of Path MTU Discovery as described
//# in [RFC1191], [RFC1981], and [RFC4821]; thus, any TCP implementation
//# that implements PAWS MUST also implement Path MTU Discovery.
//= https://www.rfc-editor.org/rfc/rfc4821#section-4
//= type=test
//= reason=Host fragmentation mimics IPv6 and happens only in the host: Host UDP datagrams in Fragment mode and the Host's Echo Replies (a reply to an IPv4 source-routed Echo Request takes the reversed, policy-authorized return route, registers no adjunct demand and is never sized by an adjunct-confirmed bound, while IPv6 Echo Replies use only owner-configured routes) leave through one datagram emitter (Host::transmit, crates/stacks/ntcp-host/src/emitter.rs) that cuts an IPv4 datagram larger than the connectionless effective size with ntcp_ip::Fragmenter, which sets DF on every fragment, just as it cuts IPv6 (every fragment repeats the unfragmentable part, the base header and on an owner-configured Segment Routing route its Segment Routing Header, before the Fragment header, and the first fragment holds the complete upper-layer header); the atomic IPv4 encoder (encode_present) sets DF on every unfragmented packet, and TCP never enters source fragmentation. Host tests assert DF on every IPv4 fragment and packet of a fragmented send, the tun_echo IPv4 path asserts DF on TCP packets and PLPMTUD probes, and the integration/rfc_host fragment, fragment-ptb and adjunct-silence cases check DF on every captured IPv4 fragment and probe. User disposition of the SHOULD (recorded): an application that sets IP_MTU_DISCOVER=IP_PMTUDISC_DONT on a native socket gets its ordinary IPv4 TCP output without DF, an application-requested exception; every such packet carries an Identification leased from the Host allocator for its (source, destination, TCP) tuple, the RFC 6864 ceiling holds the packet instead of reusing a value, its PLPMTUD probes keep DF and TCP is never source-fragmented (ntcp-socket tests managed_dont_leases_identifiers_keeps_df_on_probes_and_holds_at_the_ceiling and dont_packets_follow_the_source_quiet_assertion). User disposition for administratively flagged routes (recorded decision B): on an IPv4 route or path whose owner disabled discovery (RFC 1191 section 6.6, which RFC 4821 does not update) every packet of TCP, Host::udp_send, Host::udp_send_datagram and Echo replies, Host source fragments included, leaves DF clear with a leased Identification and a recomputed header checksum under the RFC 1122 section 3.3.3 sending limit, and no probe is sent there; fragments on enabled routes keep DF (ntcp-host tests disabled_ipv4_route_clears_df_on_udp_datagrams_and_source_fragments, disabling_one_ipv4_route_leaves_a_neighbor_route_keeping_df_on_fragments and disabled_ipv4_route_clears_df_on_whole_udp_send_datagrams).
//# All hosts SHOULD use IPv4 fragmentation in a mode that mimics IPv6 functionality. All fragmentation SHOULD be done on the host, and all IPv4 packets, including fragments, SHOULD have the DF bit set such that they will not be fragmented (again) in the network. See Section 8.
#[test]
fn runtime_icmp_blackhole_falls_back_with_paws_and_congestion_response() {
    for v6 in [false, true] {
        let mut p = Pair::new(v6, true);
        let payload: Vec<u8> = (0..12000).map(|n| (n % 239) as u8).collect();
        p.a.write(p.aid, &payload).unwrap();
        let original = emit(&mut p.ahost, &mut p.a, p.time, p.local.ip());
        let path = if v6 { 1280 } else { 1024 };
        assert!(original.iter().any(|f| f.len() > path));
        let initial = p.a.transport_info(p.aid).unwrap();
        // Suppress all ICMP. Drive the real RTO deadlines to R1, checking the
        // ordinary timeout congestion response before allowing smaller repairs.
        for count in 1..=3 {
            let backoff = p.a.transport_info(p.aid).unwrap().rto_backoff;
            for _ in 0..16 {
                p.next_timeout();
                if p.a.transport_info(p.aid).unwrap().rto_backoff > backoff {
                    break;
                }
                // Tail-loss probes also disappear into the same black hole.
                emit(&mut p.ahost, &mut p.a, p.time, p.local.ip());
            }
            let info = p.a.transport_info(p.aid).unwrap();
            assert!(info.rto_backoff > backoff);
            assert_eq!(info.cwnd, info.mss);
            assert!(info.ssthresh < initial.cwnd);
            let mtu = p.a.path_mtu_info(p.aid).unwrap().unwrap().current_mtu;
            assert_eq!(mtu, if count < 3 { 1500 } else { path as u32 });
            if count < 3 {
                let retries = emit(&mut p.ahost, &mut p.a, p.time, p.local.ip());
                assert!(retries.iter().any(|f| f.len() > path));
            }
        }
        let (drops, repairs) = p.progress(path, &payload);
        assert_eq!(drops, 0);
        assert!(repairs.iter().all(|f| f.len() <= path));
        assert!(
            repairs
                .iter()
                .any(|f| segment(f).header.sequence == segment(&original[0]).header.sequence)
        );
        // After the existing cooldown expires, a repaired path may grow again.
        // Admit this later flight on the restored 1500-byte path. Its first
        // larger packet is a real PLPMTUD probe, with DF checked by segment().
        p.next_timeout();
        let followup = vec![0x93; 60000];
        p.a.write(p.aid, &followup).unwrap();
        let probes = emit(&mut p.ahost, &mut p.a, p.time, p.local.ip());
        let mut largest = probes.iter().map(Vec::len).max().unwrap_or(0);
        for frame in probes {
            assert!(segment(&frame).options.timestamps.is_some());
            input_frame(
                &mut p.bhost,
                &mut p.b,
                p.time,
                &frame,
                p.remote.ip(),
                false,
                &mut Sample(0),
            )
            .unwrap();
        }
        let (_, later) = p.progress(MTU, &followup);
        largest = largest.max(later.iter().map(Vec::len).max().unwrap_or(0));
        assert!(
            largest > path && largest <= MTU,
            "ACK-driven congestion credit admits a larger probe"
        );
        assert!(p.a.path_mtu_info(p.aid).unwrap().unwrap().current_mtu > path as u32);
    }
}

//= https://www.rfc-editor.org/rfc/rfc7323#section-5.7
//= type=test
//= reason=The supplied fixed-1500 TUN embedding queries and validates the real backend MTU, enables PMTUD with or without PAWS, and dispatches checksummed ICMP PTB through live tuple/sequence/exact-packet validation. Runtime-constructor and framed peer tests prove timestamp negotiation, IPv4 DF, bounded IPv4/IPv6 repairs, receiver/ACK byte progress, rejected feedback, committed-output retention, and ICMP-blackhole R1 fallback with ordinary congestion response and subsequent ACK-confirmed probing. This evidence covers the supplied embedding and existing core discovery, not arbitrary external embeddings, native IPv6 sockets or a full host ICMP service.
//# Setting the DF bit implies the use of Path MTU Discovery as described
//# in [RFC1191], [RFC1981], and [RFC4821]; thus, any TCP implementation
//# that implements PAWS MUST also implement Path MTU Discovery.
#[test]
fn runtime_dispatch_rejects_uncorrelated_or_malformed_feedback() {
    for v6 in [false, true] {
        let mut p = Pair::new(v6, true);
        p.a.write(p.aid, &[0x5a; 12000]).unwrap();
        let original = emit(&mut p.ahost, &mut p.a, p.time, p.local.ip()).remove(0);
        let h = header(&original);
        let path = if v6 { 1280 } else { 1006 };
        let valid = ptb(&original, path);
        let mut cases = Vec::new();
        for cut in 0..valid.len() {
            cases.push(("truncated", valid[..cut].to_vec(), p.local.ip()));
        }
        let mut bad = valid.clone();
        bad[h + 2] ^= 1;
        cases.push(("ICMP checksum", bad, p.local.ip()));
        for (name, offset) in [
            ("quoted destination", if v6 { 24 } else { 16 }),
            ("quoted source", if v6 { 8 } else { 12 }),
            ("source port", h),
            ("destination port", h + 2),
            ("sequence", h + 7),
        ] {
            let mut quote = original.clone();
            quote[offset] ^= 1;
            if !v6 {
                seal_ip(&mut quote);
            }
            cases.push((name, ptb(&quote, path), p.local.ip()));
        }
        let mut quote = original.clone();
        let stale_sequence = segment(&original).header.sequence.wrapping_sub(1);
        quote[h + 4..h + 8].copy_from_slice(&stale_sequence.to_be_bytes());
        cases.push((
            "already acknowledged SYN sequence",
            ptb(&quote, path),
            p.local.ip(),
        ));
        let mut quote = original.clone();
        let len_offset = if v6 { 4 } else { 2 };
        let size = u16::from_be_bytes([quote[len_offset], quote[len_offset + 1]]) + 1;
        quote[len_offset..len_offset + 2].copy_from_slice(&size.to_be_bytes());
        if !v6 {
            seal_ip(&mut quote);
        }
        cases.push(("exact sent size", ptb(&quote, path), p.local.ip()));
        let mut bad = valid.clone();
        bad[h + 8] ^= 0x10;
        seal_feedback(&mut bad);
        cases.push(("inner version", bad, p.local.ip()));
        if !v6 {
            let mut bad = valid.clone();
            bad[h + 8 + 10] ^= 1;
            seal_feedback(&mut bad);
            cases.push(("inner checksum", bad, p.local.ip()));
        }
        let mut bad = valid.clone();
        let destination = if v6 { 39 } else { 19 };
        bad[destination] ^= 1;
        seal_feedback(&mut bad);
        cases.push(("outer destination", bad, p.local.ip()));
        let mut bad = valid.clone();
        bad[h] = if v6 { 1 } else { 11 };
        bad[h + 1] = 0;
        seal_feedback(&mut bad);
        cases.push(("non PTB", bad, p.local.ip()));
        for mtu in [1500, 2000] {
            cases.push(("nondecreasing", ptb(&original, mtu), p.local.ip()));
        }
        if v6 {
            cases.push(("below IPv6 floor", ptb(&original, 1279), p.local.ip()));
        }
        cases.push(("wrong configured destination", valid.clone(), p.remote.ip()));
        cases.push(("wrong configured family", valid, addresses(!v6).0.ip()));
        let before = p.a.path_mtu_info(p.aid).unwrap();
        let transport = p.a.transport_info(p.aid).unwrap();
        let buffers = p.a.buffer_bytes();
        let deadline = p.a.next_deadline();
        for (name, report, configured) in cases {
            input_frame(
                &mut p.ahost,
                &mut p.a,
                p.time,
                &report,
                configured,
                false,
                &mut Sample(0),
            )
            .unwrap();
            assert_eq!(p.a.path_mtu_info(p.aid).unwrap(), before, "{v6}: {name}");
            assert_eq!(p.a.transport_info(p.aid).unwrap(), transport, "{name}");
            assert_eq!(p.a.buffer_bytes(), buffers, "{name}");
            assert_eq!(p.a.next_deadline(), deadline, "{name}");
            // Even a valid report cannot instantiate an unknown TCP connection.
            let (mut empty, mut empty_host) = endpoint(p.local.ip(), true);
            let reserved_storage = empty.buffer_bytes();
            empty.listen(p.local, 1).unwrap();
            input_frame(
                &mut empty_host,
                &mut empty,
                p.time,
                &report,
                configured,
                false,
                &mut Sample(0),
            )
            .unwrap();
            assert_eq!(empty.buffer_bytes(), reserved_storage, "{name}");
            assert_eq!(
                empty.connection_id(Tuple {
                    local: p.local,
                    remote: p.remote
                }),
                None
            );
            assert!(emit(&mut empty_host, &mut empty, p.time, p.local.ip()).is_empty());
        }
        // Positive control on the identical flight after every rejected report.
        input_frame(
            &mut p.ahost,
            &mut p.a,
            p.time,
            &ptb(&original, path),
            p.local.ip(),
            false,
            &mut Sample(0),
        )
        .unwrap();
        assert_eq!(p.a.path_mtu_info(p.aid).unwrap().unwrap().current_mtu, path);
    }
}

//= https://www.rfc-editor.org/rfc/rfc7323#section-5.7
//= type=test
//= reason=The supplied fixed-1500 TUN embedding queries and validates the real backend MTU, enables PMTUD with or without PAWS, and dispatches checksummed ICMP PTB through live tuple/sequence/exact-packet validation. Runtime-constructor and framed peer tests prove timestamp negotiation, IPv4 DF, bounded IPv4/IPv6 repairs, receiver/ACK byte progress, rejected feedback, committed-output retention, and ICMP-blackhole R1 fallback with ordinary congestion response and subsequent ACK-confirmed probing. This evidence covers the supplied embedding and existing core discovery, not arbitrary external embeddings, native IPv6 sockets or a full host ICMP service.
//# Setting the DF bit implies the use of Path MTU Discovery as described
//# in [RFC1191], [RFC1981], and [RFC4821]; thus, any TCP implementation
//# that implements PAWS MUST also implement Path MTU Discovery.
#[test]
fn runtime_ptb_does_not_overwrite_a_committed_blocked_frame() {
    for v6 in [false, true] {
        let mut p = Pair::new(v6, true);
        let first_len = if v6 { 1428 } else { 1448 };
        let payload = vec![0x6d; first_len + 12000];
        p.a.write(p.aid, &payload[..first_len]).unwrap();
        let submitted = emit(&mut p.ahost, &mut p.a, p.time, p.local.ip());
        assert_eq!(submitted.len(), 1);
        assert_eq!(submitted[0].len(), MTU);
        p.a.write(p.aid, &payload[first_len..]).unwrap();
        let mut backend = Backend {
            blocked: true,
            ..Default::default()
        };
        let mut output = [0; MTU];
        let mut pending = None;
        let h = if v6 { IPV6_HEADER } else { IP_HEADER };
        transmit_frames(
            &mut p.ahost,
            &mut p.a,
            p.time,
            &mut output,
            &mut pending,
            h,
            &mut Sample(0),
            &mut backend,
        )
        .unwrap();
        let selected = output[..pending.as_ref().unwrap().len].to_vec();
        let attempt = pending.as_ref().unwrap().attempt;
        let path = if v6 { 1280 } else { 1006 };
        assert!(selected.len() > path);
        // Feedback quotes a genuinely Submitted packet, not the held attempt.
        let report = ptb(&submitted[0], path as u32);
        for _ in 0..BUDGET {
            input_frame(
                &mut p.ahost,
                &mut p.a,
                p.time,
                &report,
                p.local.ip(),
                false,
                &mut Sample(0),
            )
            .unwrap();
        }
        assert!(
            !p.ahost.can_receive(),
            "full retention backpressures TUN reads"
        );
        assert_eq!(p.ahost.received.len(), BUDGET);
        assert_eq!(p.a.path_mtu_info(p.aid).unwrap().unwrap().current_mtu, 1500);
        let transport = p.a.transport_info(p.aid).unwrap();
        for _ in 0..3 {
            p.ahost.replay(&mut p.a, p.time).unwrap();
            transmit_frames(
                &mut p.ahost,
                &mut p.a,
                p.time,
                &mut output,
                &mut pending,
                h,
                &mut Sample(0),
                &mut backend,
            )
            .unwrap();
            assert_eq!(pending.as_ref().unwrap().attempt, attempt);
            assert_eq!(&output[..pending.as_ref().unwrap().len], selected);
            assert_eq!(p.a.transport_info(p.aid).unwrap(), transport);
            assert!(backend.frames.is_empty());
        }
        backend.blocked = false;
        transmit_frames(
            &mut p.ahost,
            &mut p.a,
            p.time,
            &mut output,
            &mut pending,
            h,
            &mut Sample(0),
            &mut backend,
        )
        .unwrap();
        assert!(pending.is_none());
        assert!(p.ahost.can_receive());
        assert!(p.ahost.received.is_empty());
        assert_eq!(backend.frames[0], selected);
        assert_eq!(backend.frames.iter().filter(|f| **f == selected).count(), 1);
        assert_eq!(
            p.a.path_mtu_info(p.aid).unwrap().unwrap().current_mtu,
            path as u32
        );
        // The two already Submitted oversized packets disappear at the path;
        // only subsequent fitting repairs reach the real peer.
        for frame in &backend.frames[1..] {
            assert!(frame.len() <= path);
            segment(frame);
            input_frame(
                &mut p.bhost,
                &mut p.b,
                p.time,
                frame,
                p.remote.ip(),
                false,
                &mut Sample(0),
            )
            .unwrap();
        }
        p.progress(path, &payload);
    }
}

// A planned flow whose route goes away after its owner stated the expected
// registrations ends explicitly: the held option-bearing frame is never
// submitted or sampled again, and its connection fails without a reset
// instead of pausing output.
#[test]
fn stale_registration_route_terminates_the_flow() {
    let local: IpAddr = "192.0.2.1".parse().unwrap();
    let remote: SocketAddr = "192.0.2.2:8080".parse().unwrap();
    let cfg = runtime_config(&Backend::default(), local, true, true, true).unwrap();
    let mut endpoint = Endpoint::new(
        cfg.clone(),
        [9; 32],
        0,
        ntcp::Lifecycle { boot_age: Some(u64::MAX), continuity: ntcp::SourceContinuity::Never },
        tun_address_policy(
            "192.0.2.1".parse().unwrap(),
            ("192.0.2.1".parse().unwrap(), 24),
        ),
    )
    .unwrap();
    let mut network = TunHost::attach(&mut endpoint, &cfg, local).unwrap();
    let (options, expected) = origination(Some("3,3"), Some("times,3,3"))
        .unwrap()
        .unwrap();
    let plan = ntcp::Ipv4RegistrationPlan::new(local, remote.ip(), options, &expected).unwrap();
    let id = endpoint
        .connect_with_path_provider(
            0,
            SocketAddr::new(local, 1234),
            remote,
            ntcp::ManagedOpenOptions {
                transport: ntcp::ActiveOpenOptions::from(&cfg.connection),
                dscp: cfg.dscp,
                ipv4_options: options,
                registration: Some(plan),
                receive_authority: None,
            },
            &mut network.host,
        )
        .unwrap();
    let mut backend = Backend {
        blocked: true,
        ..Default::default()
    };
    let mut bytes = [0; MTU];
    let mut pending = None;
    let mut utc = Utc::new(std::time::Instant::now());
    transmit_frames(
        &mut network,
        &mut endpoint,
        0,
        &mut bytes,
        &mut pending,
        IP_HEADER,
        &mut utc,
        &mut backend,
    )
    .unwrap();
    let route = pending
        .as_ref()
        .unwrap()
        .context
        .unwrap()
        .binding
        .snapshot
        .key()
        .route();
    network.host.remove_route(route).unwrap();
    backend.blocked = false;
    transmit_frames(
        &mut network,
        &mut endpoint,
        1,
        &mut bytes,
        &mut pending,
        IP_HEADER,
        &mut utc,
        &mut backend,
    )
    .unwrap();
    assert!(pending.is_none());
    assert!(backend.frames.is_empty());
    assert_eq!(endpoint.state(id).unwrap(), State::Closed);
    assert!(!endpoint.is_output_reserved(id));
    assert_eq!(utc.acquisitions, 1);
}

#[test]
fn runtime_retains_source_route_full_header_and_canonical_context_on_retry() {
    let local: IpAddr = "192.0.2.1".parse().unwrap();
    let remote: SocketAddr = "192.0.2.2:8080".parse().unwrap();
    let hop: Ipv4Addr = "192.0.2.9".parse().unwrap();
    let mut cfg = runtime_config(&Backend::default(), local, true, true, true).unwrap();
    cfg.dscp = 37;
    let mut endpoint = Endpoint::new(
        cfg.clone(),
        [9; 32],
        0,
        ntcp::Lifecycle { boot_age: Some(u64::MAX), continuity: ntcp::SourceContinuity::Never },
        tun_address_policy(
            "192.0.2.1".parse().unwrap(),
            ("192.0.2.1".parse().unwrap(), 24),
        ),
    )
    .unwrap();
    let mut network = TunHost::attach(&mut endpoint, &cfg, local).unwrap();
    let options = ntcp::OutgoingIpv4Options {
        source_route: Some(ntcp::SourceRoute::new(&[hop], false).unwrap()),
        record_route_slots: Some(3),
        timestamp: Some(ntcp::TimestampRequest::Times(3)),
    };
    let id = endpoint
        .connect_with_path_provider(
            0,
            SocketAddr::new(local, 1234),
            remote,
            ntcp::ManagedOpenOptions {
                transport: ntcp::ActiveOpenOptions::from(&cfg.connection),
                dscp: cfg.dscp,
                ipv4_options: options,
                registration: Some(
                    // The origin, the listed hop and the destination record.
                    ntcp::Ipv4RegistrationPlan::new(
                        local,
                        remote.ip(),
                        options,
                        &ntcp::ExpectedRegistrations {
                            record_route: Some(3),
                            timestamp: Some(ntcp::ExpectedTimestamps::Count(3)),
                        },
                    )
                    .unwrap(),
                ),
                receive_authority: None,
            },
            &mut network.host,
        )
        .unwrap();
    let mut backend = Backend {
        blocked: true,
        ..Default::default()
    };
    let mut bytes = [0; MTU];
    let mut pending = None;
    // The example's provider, sampled once for the origin's Timestamp slot.
    let mut utc = Utc::new(std::time::Instant::now());
    let before = utc_read();
    transmit_frames(
        &mut network,
        &mut endpoint,
        0,
        &mut bytes,
        &mut pending,
        IP_HEADER,
        &mut utc,
        &mut backend,
    )
    .unwrap();
    let after = utc_read();
    assert_eq!(utc.acquisitions, 1);
    let held = pending.as_ref().unwrap();
    let context = held.context.unwrap();
    let staged = bytes[..held.len].to_vec();
    // The route (7 octets) and Record Route (15) precede the Timestamp.
    assert_eq!(&staged[42..46], &[68, 16, 9, 0]);
    // Standard only within the test's healthy kernel clock bracket,
    // otherwise marked.
    standard_time(
        u32::from_be_bytes(staged[46..50].try_into().unwrap()),
        before,
        after,
    );
    assert_eq!(
        context.binding.snapshot.key().destination().address(),
        remote.ip()
    );
    assert_eq!(
        context
            .binding
            .snapshot
            .key()
            .forwarding_destination()
            .address(),
        IpAddr::V4(hop)
    );
    assert_eq!(&staged[16..20], &hop.octets());
    assert!(header(&staged) > IP_HEADER);
    // Harmless stamp changes retain the exact selected option/timestamp bytes.
    network
        .host
        .set_link_mtu(network.ingress.link(), 1600)
        .unwrap();
    backend.blocked = false;
    transmit_frames(
        &mut network,
        &mut endpoint,
        0,
        &mut bytes,
        &mut pending,
        IP_HEADER,
        &mut utc,
        &mut backend,
    )
    .unwrap();
    assert!(pending.is_none());
    // The held frame was submitted as encoded, without another sample.
    assert_eq!(utc.acquisitions, 1);
    assert_eq!(backend.frames, vec![staged]);
    // This is an originating, not-yet-forwarded source route. The ingress
    // codec correctly rejects it as incomplete at the final destination;
    // quote_header validates the outbound header and its logical peer instead.
    let (ip, header_len, total, protocol) = ntcp_ip::quote_header(&backend.frames[0]).unwrap();
    assert_eq!(ip.destination, remote.ip());
    assert_eq!(total, backend.frames[0].len());
    assert_eq!(protocol, 6);
    assert_eq!(backend.frames[0][1] >> 2, 37);
    assert!(ntcp::wire::parse(ip, &backend.frames[0][header_len..]).is_ok());
    assert_eq!(
        endpoint.managed_path(id).unwrap().forwarding_destination,
        IpAddr::V4(hop)
    );
}

#[test]
fn runtime_rejection_interruption_and_unknown_outcome_never_accept_selected_bytes() {
    for v6 in [false, true] {
        for errno in [None, Some(libc::EINTR), Some(libc::EIO)] {
            let mut p = Pair::new(v6, true);
            let payload = vec![0x2b; 12000];
            p.a.write(p.aid, &payload).unwrap();
            let before = p.a.transport_info(p.aid).unwrap();
            let mut backend = Backend {
                rejected: errno.is_none(),
                tx_errno: errno,
                ..Default::default()
            };
            let mut bytes = [0; MTU];
            let mut pending = None;
            let header = if v6 { IPV6_HEADER } else { IP_HEADER };
            let result = transmit_frames(
                &mut p.ahost,
                &mut p.a,
                p.time,
                &mut bytes,
                &mut pending,
                header,
                &mut Sample(0),
                &mut backend,
            );
            if errno == Some(libc::EIO) {
                assert_eq!(result.unwrap_err().raw_os_error(), errno);
            } else {
                result.unwrap();
            }
            assert_eq!(backend.attempts, 1);
            assert!(backend.frames.is_empty());
            let held = pending.as_ref().unwrap();
            assert!(p.a.transmit_attempt_packet(held.attempt).is_some());
            assert!(p.a.is_output_reserved(p.aid));
            assert_eq!(p.a.transport_info(p.aid).unwrap().unacked, before.unacked);
            if errno == Some(libc::EIO) {
                // run() propagates this unknown outcome and drops the runtime;
                // it never rejects, retries or claims these bytes Submitted.
                continue;
            }
            backend.rejected = false;
            backend.tx_errno = None;
            transmit_frames(
                &mut p.ahost,
                &mut p.a,
                p.time,
                &mut bytes,
                &mut pending,
                header,
                &mut Sample(0),
                &mut backend,
            )
            .unwrap();
            assert!(pending.is_none());
            for frame in &backend.frames {
                input_frame(
                    &mut p.bhost,
                    &mut p.b,
                    p.time,
                    frame,
                    p.remote.ip(),
                    false,
                    &mut Sample(0),
                )
                .unwrap();
            }
            p.progress(MTU, &payload);
        }
    }
}

#[test]
fn runtime_stale_source_pauses_held_output_until_canonical_rebind() {
    for v6 in [false, true] {
        let mut p = Pair::new(v6, true);
        let payload = vec![0x8f; 12000];
        p.a.write(p.aid, &payload).unwrap();
        let mut backend = Backend {
            blocked: true,
            ..Default::default()
        };
        let mut bytes = [0; MTU];
        let mut pending = None;
        let header = if v6 { IPV6_HEADER } else { IP_HEADER };
        transmit_frames(
            &mut p.ahost,
            &mut p.a,
            p.time,
            &mut bytes,
            &mut pending,
            header,
            &mut Sample(0),
            &mut backend,
        )
        .unwrap();
        let attempt = pending.as_ref().unwrap().attempt;
        let old = p.ahost.host.binding(p.aid).unwrap();
        p.ahost
            .host
            .remove_source_owner(old.snapshot.key().source(), p.ahost.ingress.link())
            .unwrap();
        backend.blocked = false;
        let calls = backend.attempts;
        for _ in 0..2 {
            transmit_frames(
                &mut p.ahost,
                &mut p.a,
                p.time,
                &mut bytes,
                &mut pending,
                header,
                &mut Sample(0),
                &mut backend,
            )
            .unwrap();
            assert!(pending.as_ref().unwrap().blocked);
            assert_eq!(pending.as_ref().unwrap().attempt, attempt);
            assert_eq!(
                backend.attempts, calls,
                "no backend call under stale authority"
            );
            assert!(p.ahost.host.paths().is_dirty(old.client).unwrap());
        }
        p.ahost
            .host
            .register_source(
                path::ScopedAddress::new(p.local.ip(), None).unwrap(),
                p.ahost.ingress.link(),
            )
            .unwrap();
        transmit_frames(
            &mut p.ahost,
            &mut p.a,
            p.time,
            &mut bytes,
            &mut pending,
            header,
            &mut Sample(0),
            &mut backend,
        )
        .unwrap();
        assert!(pending.is_none());
        assert_ne!(
            p.ahost.host.binding(p.aid).unwrap().snapshot.path(),
            old.snapshot.path()
        );
        for frame in &backend.frames {
            input_frame(
                &mut p.bhost,
                &mut p.b,
                p.time,
                frame,
                p.remote.ip(),
                false,
                &mut Sample(0),
            )
            .unwrap();
        }
        p.progress(MTU, &payload);
    }
}

#[test]
fn runtime_held_attempt_repacketizes_on_shared_or_physical_decrease() {
    for (v6, physical) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut p = Pair::new(v6, true);
        let payload = vec![0x93; 12000];
        p.a.write(p.aid, &payload).unwrap();
        let before = p.a.transport_info(p.aid).unwrap();
        let mut backend = Backend {
            blocked: true,
            ..Default::default()
        };
        let mut output = [0; MTU];
        let mut pending = None;
        let h = if v6 { IPV6_HEADER } else { IP_HEADER };
        transmit_frames(
            &mut p.ahost,
            &mut p.a,
            p.time,
            &mut output,
            &mut pending,
            h,
            &mut Sample(0),
            &mut backend,
        )
        .unwrap();
        let attempt = pending.as_ref().unwrap().attempt;
        let selected_sequence = segment(&output[..pending.as_ref().unwrap().len])
            .header
            .sequence;
        assert_eq!(
            p.a.transport_info(p.aid).unwrap().unacked,
            before.unacked,
            "WouldBlock does not accept selected stream bytes"
        );
        let path = p.ahost.host.binding(p.aid).unwrap().snapshot.path();
        let limit = if v6 { 1280 } else { 1006 };
        if physical {
            p.ahost
                .host
                .set_link_mtu(p.ahost.ingress.link(), limit)
                .unwrap();
        } else {
            p.ahost.host.trusted_decrease(p.time, path, limit).unwrap();
        }
        backend.blocked = false;
        transmit_frames(
            &mut p.ahost,
            &mut p.a,
            p.time,
            &mut output,
            &mut pending,
            h,
            &mut Sample(0),
            &mut backend,
        )
        .unwrap();
        assert!(pending.is_none());
        assert!(p.a.transmit_attempt_packet(attempt).is_none());
        assert!(!backend.frames.is_empty());
        assert_eq!(
            segment(&backend.frames[0]).header.sequence,
            selected_sequence
        );
        for frame in &backend.frames {
            assert!(
                frame.len() <= limit as usize,
                "no stale oversized submission"
            );
            input_frame(
                &mut p.bhost,
                &mut p.b,
                p.time,
                frame,
                p.remote.ip(),
                false,
                &mut Sample(0),
            )
            .unwrap();
        }
        p.progress(limit as usize, &payload);
    }
}

// A segment on an SR route is placed after the route's Segment Routing
// Header exactly once per pending frame: when the evidence ticket cannot be
// issued after placement, the next pass asks for the ticket again and
// submits the very bytes placed, a valid segment over the final destination.
#[test]
fn routed_placement_survives_a_failed_ticket() {
    let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let b: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let routes = segment_routes(a.into(), Some("2001:db8::2/128=2001:db8:5::1")).unwrap();
    let mut cfg = EndpointConfig::default();
    cfg.connection.nagle = false;
    cfg.connection.mss = (MTU - IPV6_HEADER - 20) as u16;
    cfg.connection.send_ip_payload_limit = (MTU - IPV6_HEADER) as u16;
    let mut client = Endpoint::new(cfg.clone(), [1; 32], 0, ntcp::Lifecycle { boot_age: Some(u64::MAX), continuity: ntcp::SourceContinuity::Never }, tun_v6_policy(a)).unwrap();
    let mut host = TunHost::attach_routed(
        &mut client,
        &cfg,
        a.into(),
        &DatagramSettings::default(),
        &routes,
        0,
        1,
    )
    .unwrap();
    client
        .connect_with_path_provider(
            0,
            SocketAddr::new(a.into(), 1234),
            SocketAddr::new(b.into(), 8080),
            ntcp::ManagedOpenOptions {
                transport: ntcp::ActiveOpenOptions::from(&cfg.connection),
                dscp: cfg.dscp,
                ipv4_options: Default::default(),
                registration: None,
                receive_authority: None,
            },
            &mut host.host,
        )
        .unwrap();
    // The SYN as `transmit_frames` selects and builds it, after the base
    // header, and the frame its route's header plan makes of it.
    let mut output = [0; MTU];
    let (polled, attempt) = client
        .poll_reserved_transmit(0, &mut output[IPV6_HEADER..], 1)
        .unwrap();
    let packet = polled.packet.unwrap();
    let attempt = attempt.unwrap();
    let len = build_frame(&mut output, packet, &mut Sample(0)).unwrap();
    let context = host.host.egress_context(&mut client, attempt).unwrap();
    let plan = host.host.header_plan(context.binding.snapshot.key()).unwrap();
    assert_eq!(plan.len, 80);
    let mut expected = vec![0; plan.len + packet.len];
    expected[plan.len..].copy_from_slice(&output[IPV6_HEADER..len]);
    ntcp_ip6::encode_tcp_routed(&mut expected, packet, plan.segments, packet.len).unwrap();
    // A ticket already issued for this attempt refuses the pass's own.
    let mut issued = Some(host.host.submission_ticket(&mut client, context).unwrap());
    let mut pending = Some(PendingFrame {
        attempt,
        context: None,
        ticket: None,
        len,
        blocked: false,
    });
    let mut backend = Backend::default();
    for time in [1, 2] {
        if time == 2 {
            host.host.cancel_submission(issued.take().unwrap());
        }
        transmit_frames(
            &mut host,
            &mut client,
            time,
            &mut output,
            &mut pending,
            IPV6_HEADER,
            &mut Sample(0),
            &mut backend,
        )
        .unwrap();
        if time == 1 {
            assert!(backend.frames.is_empty());
            assert!(pending.as_ref().is_some_and(|held| held.ticket.is_none()));
        }
    }
    assert!(pending.is_none());
    assert_eq!(backend.frames, [expected]);
    let flags = segment(&backend.frames[0]).header.flags;
    assert_eq!(flags & (ntcp::wire::SYN | ntcp::wire::ACK), ntcp::wire::SYN);
}
