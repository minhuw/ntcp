// IPv6 extension header reception (`Ipv6Receive::Extensions`) through real
// Host dispatch: transport and Echo input of extension-bearing packets, the
// Parameter Problems receive processing originates, and reassembly that
// keeps fragment zero's unfragmentable part.
use super::*;

type Side = (Host, Endpoint, IngressContext);

const UDP: UdpLimits = UdpLimits {
    flows: 1,
    receive_datagrams: 2,
    max_payload: 4000,
    events: 1,
    evicted_signatures: 1,
    probe_receipts: 2,
};
const OUTPUT: IcmpOutputLimits = IcmpOutputLimits {
    messages: 3,
    message_bytes: 4096,
    hop_limit: 64,
};

const REASSEMBLY: ReassemblyLimits = ReassemblyLimits {
    assemblies: 4,
    fragments: 600,
    buffered_bytes: 16384 + 600 * DESCRIPTOR,
    ipv4_datagram: 4096,
    ipv6_datagram: 8192,
    ipv4_timeout_seconds: 60,
};

fn side(local: SocketAddr, identity: u64, cfg: &EndpointConfig) -> Side {
    side_with(local, identity, cfg, REASSEMBLY)
}

fn side_with(
    local: SocketAddr,
    identity: u64,
    cfg: &EndpointConfig,
    reassembly: ReassemblyLimits,
) -> Side {
    let mut side = managed_limited(local, identity, cfg.clone(), false, None, None, |p, l| {
        let (p, l) = managed_udp_limits(p, l, UDP).unwrap();
        let (p, mut l) = managed_icmp_output_limits(p, l, OUTPUT).unwrap();
        l.reassembly = reassembly;
        (p, l, 1)
    });
    side.0.ports[0].as_mut().unwrap().receive.ipv6 = Ipv6Receive::Extensions;
    side
}

fn ip(source: IpAddr, destination: IpAddr) -> IpMetadata {
    IpMetadata {
        source,
        destination,
    }
}

// A complete extension-free IPv6 packet of `protocol` carrying `data`.
fn packet(ip: IpMetadata, protocol: u8, data: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 40 + data.len()];
    packet[40..].copy_from_slice(data);
    let h = ntcp_ip6::Header {
        ip,
        hop_limit: 64,
        dscp: 0,
        ecn: 0,
    };
    ntcp_ip6::encode_datagram(&mut packet, h, protocol, data.len()).unwrap();
    packet
}

// `packet` with its base header's Next Header replaced.
fn selector(packet: &[u8], next_header: u8) -> Vec<u8> {
    let mut packet = packet.to_vec();
    packet[6] = next_header;
    packet
}

fn udp(ip: IpMetadata, ports: (u16, u16), payload: &[u8]) -> Vec<u8> {
    let mut message = vec![0; 8 + payload.len()];
    message[8..].copy_from_slice(payload);
    let n = ntcp_ip_common::encode_udp(
        ip.source,
        ip.destination,
        ports.0,
        ports.1,
        &mut message,
        payload.len(),
    )
    .unwrap();
    packet(ip, 17, &message[..n])
}

fn echo(ip: IpMetadata, sequence: u16, data: &[u8]) -> Vec<u8> {
    let mut message = vec![0; 8 + data.len()];
    message[8..].copy_from_slice(data);
    let n = ntcp_icmp::encode_echo(
        ip,
        ntcp_icmp::EchoKind::Request,
        0x4242,
        sequence,
        &mut message,
        data.len(),
    )
    .unwrap();
    packet(ip, 58, &message[..n])
}

// `packet` with `headers` (selector naming each, its bytes) inserted after
// the base header: every Next Header is filled in, the last naming the
// packet's original upper layer, and the Payload Length is recomputed.
fn chain(packet: &[u8], headers: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut next = packet[6];
    let mut bodies: Vec<Vec<u8>> = headers.iter().map(|h| h.1.clone()).collect();
    for i in (0..bodies.len()).rev() {
        bodies[i][0] = next;
        next = headers[i].0;
    }
    let mut out = packet[..40].to_vec();
    out[6] = next;
    for body in bodies {
        out.extend_from_slice(&body);
    }
    out.extend_from_slice(&packet[40..]);
    let payload = (out.len() - 40) as u16;
    out[4..6].copy_from_slice(&payload.to_be_bytes());
    out
}

// A Hop-by-Hop or Destination Options header holding `options`, padded with
// Pad1 to a multiple of 8 octets.
fn options(options: &[u8]) -> Vec<u8> {
    let mut h = vec![0, 0];
    h.extend_from_slice(options);
    h.resize(h.len().div_ceil(8) * 8, 0);
    h[1] = (h.len() / 8 - 1) as u8;
    h
}

// A Routing header of `kind` with `segments_left` and `units` 8-octet units
// after the first eight; type-specific fields are zero.
fn routing(kind: u8, segments_left: u8, units: u8) -> Vec<u8> {
    let mut h = vec![0; (usize::from(units) + 1) * 8];
    h[1] = units;
    h[2] = kind;
    h[3] = segments_left;
    h
}

fn fragment_header(offset: usize, more: bool, identification: u32) -> Vec<u8> {
    let mut h = vec![0; 8];
    h[2..4].copy_from_slice(&(offset as u16 | u16::from(more)).to_be_bytes());
    h[4..8].copy_from_slice(&identification.to_be_bytes());
    h
}

// The fragment of `whole` (a complete packet whose headers after the base
// header are all fragmentable) holding data octets `offset..offset + len`
// behind the unfragmentable extension headers `prefix`.
fn piece(
    whole: &[u8],
    prefix: &[(u8, Vec<u8>)],
    identification: u32,
    offset: usize,
    len: usize,
) -> Vec<u8> {
    let data = &whole[40..];
    let more = offset + len < data.len();
    let mut base = whole[..40].to_vec();
    base.extend_from_slice(&data[offset..offset + len]);
    let mut headers = prefix.to_vec();
    headers.push((44, fragment_header(offset, more, identification)));
    chain(&base, &headers)
}

fn input(side: &mut Side, now: u64, frame: &[u8]) -> Result<ntcp::InputDisposition, Error> {
    side.0.input_ip(
        &mut side.1,
        side.2,
        now,
        frame,
        RxPacketMetadata::default(),
        0,
        None,
    )
}

// Every queued ICMP message, drained: (outer addresses, message).
fn drain(side: &mut Side, now: u64) -> Vec<(IpMetadata, Vec<u8>)> {
    let mut sent = Vec::new();
    loop {
        let mut packet = vec![0; 8192];
        let mut frame = None;
        match side.0.icmp_output(now, &mut packet, |_, bytes| {
            frame = Some(bytes.to_vec());
            BackendOutcome::Submitted
        }) {
            Ok(None) => return sent,
            Ok(Some(BackendOutcome::Submitted)) => {
                let frame = frame.unwrap();
                let p = ntcp_ip6::parse(&frame).unwrap();
                assert_eq!((p.protocol, frame[6]), (58, 58), "extension-free output");
                sent.push((p.ip, p.payload.to_vec()));
            }
            other => panic!("unexpected ICMP output {other:?}"),
        }
    }
}

// The single Parameter Problem drained: (code, pointer), after checking its
// addresses, its checksum and that it quotes `invoking` from the start.
fn problem(side: &mut Side, now: u64, local: IpAddr, remote: IpAddr, invoking: &[u8]) -> (u8, u32) {
    let sent = drain(side, now);
    assert_eq!(sent.len(), 1, "one Parameter Problem");
    let (outer, message) = &sent[0];
    assert_eq!(*outer, ip(local, remote), "from the owned destination");
    assert_eq!(message[0], 4);
    assert_eq!(ntcp_icmp::icmpv6_checksum(*outer, message), Ok(0));
    let quoted = (message.len() - 8).min(invoking.len());
    assert_eq!(&message[8..8 + quoted], &invoking[..quoted]);
    (
        message[1],
        u32::from_be_bytes(message[4..8].try_into().unwrap()),
    )
}

// Extension-bearing UDP, Echo and TCP reach their consumers exactly as the
// same packets without extensions do: unknown options with action 00,
// Pad1/PadN, Routing headers of every type with Segments Left zero, both
// Destination Options positions, unusual order and repetition.
#[test]
fn extension_bearing_transport_and_echo_are_dispatched() {
    let cfg = config(4);
    let (local, remote) = addresses(true);
    let mut a = side(local, 81, &cfg);
    let to_us = ip(remote.ip(), local.ip());
    let flow =
        a.0.udp_open(
            &a.1,
            local,
            None,
            UdpOptions {
                dscp: 0,
                hop_limit: 64,
            },
        )
        .unwrap();
    let chains: [&[(u8, Vec<u8>)]; 4] = [
        &[(0, options(&[0x3e, 2, 9, 9, 1, 0]))],
        &[
            (0, options(&[])),
            (60, options(&[1, 2, 0, 0])),
            (43, routing(0, 0, 2)),
            (43, routing(4, 0, 4)),
            (43, routing(253, 0, 0)),
            (60, options(&[0x07, 1, 5])),
        ],
        // Unusual order and repetition are not refused at a host.
        &[
            (60, options(&[])),
            (60, options(&[])),
            (43, routing(4, 0, 2)),
        ],
        &[(43, routing(0, 0, 0)), (60, options(&[0; 14]))],
    ];
    let mut bytes = [0; 64];
    for (n, headers) in chains.iter().enumerate() {
        let payload = [n as u8; 21];
        let frame = chain(
            &udp(to_us, (remote.port(), local.port()), &payload),
            headers,
        );
        assert!(frame.len() > 69);
        assert_eq!(
            input(&mut a, 1, &frame),
            Ok(ntcp::InputDisposition::Processed)
        );
        assert_eq!(
            a.0.udp_receive(flow, &mut bytes).unwrap(),
            Some((remote, payload.len()))
        );
        assert_eq!(&bytes[..21], &payload);
        let request = chain(&echo(to_us, n as u16, &payload), headers);
        assert_eq!(
            input(&mut a, 2, &request),
            Ok(ntcp::InputDisposition::Processed)
        );
        let sent = drain(&mut a, 2);
        assert_eq!(sent.len(), 1);
        let reply = ntcp_icmp::decode_echo(sent[0].0, &sent[0].1).unwrap();
        assert_eq!(
            (reply.kind, reply.sequence, reply.data),
            (ntcp_icmp::EchoKind::Reply, n as u16, &payload[..])
        );
    }
    // A checksum error is still one: the UDP checksum covers the datagram
    // after the chain.
    let mut corrupt = chain(
        &udp(to_us, (remote.port(), local.port()), &[1; 8]),
        chains[1],
    );
    *corrupt.last_mut().unwrap() ^= 1;
    input(&mut a, 3, &corrupt).ok();
    assert_eq!(a.0.udp_receive(flow, &mut bytes).unwrap(), None);

    // TCP: every segment toward `a` carries a Destination Options header.
    let mut b = managed(remote, 82, cfg.clone());
    let listener = a.1.listen(local, 4).unwrap();
    let id =
        b.1.connect_with_path_provider(0, remote, local, options_for(&cfg), &mut b.0)
            .unwrap();
    let mut now = 10;
    let mut written = 0;
    for _ in 0..64 {
        now += 10;
        let mut work = false;
        if let Some(frame) = emit(&mut b.0, &mut b.1, now) {
            let frame = chain(&frame, &[(60, options(&[1, 2, 0, 0]))]);
            input(&mut a, now + 1, &frame).unwrap();
            work = true;
        }
        if let Some(frame) = emit(&mut a.0, &mut a.1, now + 2) {
            super::input(&mut b.0, &mut b.1, b.2, now + 3, &frame, 0);
            work = true;
        }
        if !work {
            if written != 0 {
                break;
            }
            written = b.1.write(id, &[7; 300]).unwrap();
        }
    }
    let child = a.1.accept(listener).unwrap();
    let mut read = [0; 600];
    assert_eq!(a.1.read(child, &mut read).unwrap(), 300);
    assert_eq!(&read[..300], &[7; 300][..]);
}

fn options_for(cfg: &EndpointConfig) -> ManagedOpenOptions {
    super::options(cfg, 0)
}

// RFC 8200 section 4 and RFC 4443 section 3.4: each refusal's code and
// pointer, from the owned destination to the source, quoting the packet;
// silent discards stay silent.
#[test]
fn refused_chains_draw_parameter_problems_with_actual_pointers() {
    let cfg = config(2);
    let (local, remote) = addresses(true);
    let mut a = side(local, 83, &cfg);
    let to_us = ip(remote.ip(), local.ip());
    // Each error a second apart: the shared bucket is not what is tested.
    let second = cfg.connection.timebase.units_per_second;
    let base = udp(to_us, (remote.port(), local.port()), &[3; 16]);
    type Case = (Vec<u8>, Option<(u8, u32)>);
    let cases: Vec<Case> = vec![
        // Unknown option, action 10 and 11: code 2 at its Option Type.
        (
            chain(&base, &[(60, options(&[1, 0, 0x9e, 1, 0]))]),
            Some((2, 44)),
        ),
        (chain(&base, &[(0, options(&[0xde, 0]))]), Some((2, 42))),
        // Action 01: silent discard.
        (chain(&base, &[(60, options(&[0x5e, 0]))]), None),
        // Hop-by-Hop after another header: code 1 at the selector naming it.
        (
            chain(&base, &[(60, options(&[])), (0, options(&[]))]),
            Some((1, 40)),
        ),
        // Unrecognized Next Header, an extension's and the base header's:
        // code 1 at that selector (ESP is not processed here).
        (
            chain(&selector(&base, 50), &[(60, options(&[]))]),
            Some((1, 40)),
        ),
        (selector(&base, 51), Some((1, 6))),
        // Segments Left above zero for any type: code 0 at Routing Type.
        (chain(&base, &[(43, routing(0, 1, 2))]), Some((0, 42))),
        (
            chain(&base, &[(60, options(&[])), (43, routing(4, 1, 2))]),
            Some((0, 50)),
        ),
        (chain(&base, &[(43, routing(200, 3, 0))]), Some((0, 42))),
        // An option overrunning its header: code 0 at its length.
        (chain(&base, &[(60, options(&[1, 9]))]), Some((0, 43))),
    ];
    for (n, (frame, expected)) in cases.iter().enumerate() {
        let now = second * n as u64;
        assert!(input(&mut a, now, frame).is_err(), "case {n} refused");
        match expected {
            Some(expected) => assert_eq!(
                problem(&mut a, now, local.ip(), remote.ip(), frame),
                *expected,
                "case {n}"
            ),
            None => assert!(drain(&mut a, now).is_empty(), "case {n} silent"),
        }
    }
    // An extension header overrunning the Payload Length: code 0 at the
    // Payload Length field (its own length field fits the payload).
    let mut short = chain(&packet(to_us, 59, &[]), &[(60, options(&[0; 14]))]);
    short[4..6].copy_from_slice(&8u16.to_be_bytes());
    short.truncate(48);
    assert!(input(&mut a, 20 * second, &short).is_err());
    assert_eq!(
        problem(&mut a, 20 * second, local.ip(), remote.ip(), &short),
        (0, 41)
    );
    // Physical truncation is silent.
    let mut truncated = chain(&base, &[(60, options(&[0xde, 0]))]);
    truncated.pop();
    assert!(input(&mut a, 21 * second, &truncated).is_err());
    assert!(drain(&mut a, 21 * second).is_empty());
    // An ICMPv6 error behind a refused chain draws nothing (RFC 4443
    // section 2.4(e.1)); an Echo Request behind it does.
    let error = chain(
        &packet(to_us, 58, &[1, 4, 0, 0, 0, 0, 0, 0]),
        &[(60, options(&[0xde, 0]))],
    );
    assert!(input(&mut a, 22 * second, &error).is_err());
    assert!(drain(&mut a, 22 * second).is_empty());
    let request = chain(&echo(to_us, 1, &[2; 8]), &[(60, options(&[0xde, 0]))]);
    assert!(input(&mut a, 23 * second, &request).is_err());
    assert_eq!(
        problem(&mut a, 23 * second, local.ip(), remote.ip(), &request),
        (2, 42)
    );
    // The upper layer is classified by generic framing alone: an ICMPv6
    // error or Redirect behind a misplaced Hop-by-Hop header draws no Code 1
    // error, while an Echo Request behind the same chain does.
    let misplaced = [(60, options(&[])), (0, options(&[]))];
    for (n, message) in [[1u8, 4, 0, 0, 0, 0, 0, 0], [137, 0, 0, 0, 0, 0, 0, 0]]
        .iter()
        .enumerate()
    {
        let now = (23 * second) + (n as u64 + 1) * second / 4;
        let error = chain(&packet(to_us, 58, message), &misplaced);
        assert!(input(&mut a, now, &error).is_err());
        assert!(drain(&mut a, now).is_empty(), "message {n} silent");
    }
    let request = chain(&echo(to_us, 2, &[2; 8]), &misplaced);
    assert!(input(&mut a, 23 * second + 3 * second / 4, &request).is_err());
    assert_eq!(
        problem(
            &mut a,
            23 * second + 3 * second / 4,
            local.ip(),
            remote.ip(),
            &request
        ),
        (1, 40)
    );
    // An invalid source draws nothing.
    let mut multicast = chain(&base, &[(60, options(&[0x9e, 0]))]);
    multicast[8] = 0xff;
    assert!(input(&mut a, 24 * second, &multicast).is_err());
    assert!(drain(&mut a, 24 * second).is_empty());
    // No Next Header ends the chain and hides its trailing octets: nothing
    // is refused or reported.
    let mut empty = chain(&packet(to_us, 59, &[0xde; 16]), &[(60, options(&[]))]);
    empty[46] = 59;
    let mut out = vec![0; 8192];
    assert!(matches!(
        a.0.receive(a.2, 25 * second, &empty, false, &mut out),
        Ok(Received::Datagram(_))
    ));
    assert!(drain(&mut a, 25 * second).is_empty());
}

// RFC 4443 section 2.4(e.3)/(e.4): a link-layer multicast or broadcast
// arrival draws only the code 2 error for an option whose action is 10;
// every error shares the Host's token bucket (section 2.4(f)).
#[test]
fn link_layer_multicast_and_the_shared_limiter_suppress_errors() {
    let cfg = config(2);
    let (local, remote) = addresses(true);
    let mut a = side(local, 84, &cfg);
    let to_us = ip(remote.ip(), local.ip());
    let base = udp(to_us, (remote.port(), local.port()), &[3; 16]);
    let report = chain(&base, &[(60, options(&[0x9e, 0]))]);
    let unless = chain(&base, &[(60, options(&[0xde, 0]))]);
    let routed = chain(&base, &[(43, routing(0, 1, 2))]);
    let mut out = vec![0; 8192];
    for frame in [&unless, &routed] {
        assert!(a.0.receive(a.2, 1, frame, true, &mut out).is_err());
        assert!(drain(&mut a, 1).is_empty());
    }
    assert!(a.0.receive(a.2, 1, &report, true, &mut out).is_err());
    assert_eq!(
        problem(&mut a, 1, local.ip(), remote.ip(), &report),
        (2, 42)
    );

    // The default bucket holds ten tokens (one taken above), refilled at
    // ten per second.
    let mut sent = 0;
    for _ in 0..12 {
        assert!(input(&mut a, 2, &unless).is_err());
        sent += drain(&mut a, 2).len();
    }
    assert_eq!(sent, 9);
    let second = cfg.connection.timebase.units_per_second;
    assert!(input(&mut a, 2 + second / 10, &routed).is_err());
    assert_eq!(drain(&mut a, 2 + second / 10).len(), 1);
}

// Reassembly keeps fragment zero's unfragmentable part, whatever its length
// and whatever the other fragments carried before their Fragment headers,
// and processes the headers after it once the packet is complete.
#[test]
fn reassembly_keeps_the_variable_unfragmentable_part() {
    let cfg = config(2);
    let (local, remote) = addresses(true);
    let mut a = side(local, 85, &cfg);
    let to_us = ip(remote.ip(), local.ip());
    let flow =
        a.0.udp_open(
            &a.1,
            local,
            None,
            UdpOptions {
                dscp: 0,
                hop_limit: 64,
            },
        )
        .unwrap();
    let payload: Vec<u8> = (0..3000).map(|i| (i * 11) as u8).collect();
    // A Destination Options header after the Fragment header (fragmentable)
    // and, before it, an unfragmentable part above 255 octets.
    let whole = chain(
        &udp(to_us, (remote.port(), local.port()), &payload),
        &[(60, options(&[1, 4, 0, 0, 0, 0]))],
    );
    let mut padn = vec![1, 244];
    padn.resize(246, 0);
    let long = (60, options(&padn));
    assert_eq!(40 + long.1.len(), 288);
    let zero_prefix = [(0, options(&[])), (43, routing(4, 0, 2)), long.clone()];
    let other_prefix = [(60, options(&[]))];
    let data = whole.len() - 40;
    let mut bytes = vec![0; 4000];
    for (id, zero_last) in [(1, true), (2, false)] {
        let mut frames = [
            piece(&whole, &zero_prefix, id, 0, 1200),
            piece(&whole, &other_prefix, id, 1200, 1200),
            piece(&whole, &[], id, 2400, data - 2400),
        ];
        if zero_last {
            frames.rotate_left(1);
        }
        for frame in &frames[..2] {
            assert_eq!(
                input(&mut a, 1, frame),
                Ok(ntcp::InputDisposition::Processed)
            );
        }
        let mut out = vec![0; 8192];
        let Ok(Received::Datagram(done)) = a.0.receive(a.2, 1, &frames[2], false, &mut out) else {
            panic!("reassembled");
        };
        // Fragment zero's prefix, its Fragment header removed, the selector
        // repaired and Payload Length recomputed with the retained headers.
        let bytes_done = done.bytes();
        assert_eq!(bytes_done.len(), 40 + 8 + 24 + 248 + data);
        let expected = chain(&whole, &zero_prefix);
        assert_eq!(bytes_done, &expected[..]);
        let processed = a.0.process(done, None).unwrap();
        assert_eq!(
            a.0.input_datagram(&mut a.1, 1, processed, RxPacketMetadata::default(), 0),
            Ok(ntcp::InputDisposition::Processed)
        );
        assert_eq!(
            a.0.udp_receive(flow, &mut bytes).unwrap(),
            Some((remote, payload.len()))
        );
        assert_eq!(&bytes[..payload.len()], &payload[..]);
    }
    // An atomic fragment behind an unfragmentable part is the packet itself.
    let atomic = piece(&whole, &zero_prefix, 3, 0, data);
    assert_eq!(
        input(&mut a, 2, &atomic),
        Ok(ntcp::InputDisposition::Processed)
    );
    assert!(a.0.udp_receive(flow, &mut bytes).unwrap().is_some());
    // A refused option after the Fragment header is processed only once the
    // packet is complete, and reported about the reassembled packet.
    let refused = chain(
        &udp(to_us, (remote.port(), local.port()), &payload),
        &[(60, options(&[0x9e, 0]))],
    );
    for (offset, len) in [(1200, data - 1200), (0, 1200)] {
        let frame = piece(&refused, &other_prefix, 4, offset, len);
        assert!(drain(&mut a, 3).is_empty());
        let result = input(&mut a, 3, &frame);
        assert_eq!(result.is_err(), offset == 0);
    }
    let reassembled = chain(&refused, &other_prefix);
    assert_eq!(
        problem(&mut a, 3, local.ip(), remote.ip(), &reassembled),
        (2, 50)
    );
    assert_eq!(a.0.reassembly_counters().completed, 3);
}

// Admission limits and RFC 8200 section 4.5's errors measured from the
// actual chain: the oversize pointer names this fragment's Fragment Offset,
// the reassembled Payload Length counts the retained extension headers, and
// RFC 7112's code 3 answers a first fragment whose chain continues past it.
#[test]
fn fragment_errors_follow_the_actual_chain() {
    let cfg = config(2);
    let (local, remote) = addresses(true);
    let mut a = side(local, 86, &cfg);
    let to_us = ip(remote.ip(), local.ip());
    let base = udp(to_us, (remote.port(), local.port()), &[0; 16]);
    let raw =
        |prefix: &[(u8, Vec<u8>)], protocol: u8, offset: usize, more: bool, data: &[u8], id| {
            let mut p = base[..40].to_vec();
            p[6] = protocol;
            p.extend_from_slice(data);
            let mut headers = prefix.to_vec();
            headers.push((44, fragment_header(offset, more, id)));
            chain(&p, &headers)
        };
    let prefix = [(60, options(&[0; 14]))];
    // 65520 + 8 fits a Payload Length alone, not behind 16 more octets.
    let alone = raw(&[], 17, 65520, false, &[1; 8], 1);
    discarded(&mut a, &alone);
    assert!(drain(&mut a, 1).is_empty(), "beyond capacity only: silent");
    assert_eq!(a.0.reassembly_counters().discarded.capacity, 1);
    let behind = raw(&prefix, 17, 65520, false, &[1; 8], 2);
    discarded(&mut a, &behind);
    assert_eq!(
        problem(&mut a, 1, local.ip(), remote.ip(), &behind),
        (0, 58)
    );
    // Misaligned behind a prefix: code 0 at the Payload Length.
    let misaligned = raw(&prefix, 17, 8, true, &[1; 9], 3);
    discarded(&mut a, &misaligned);
    assert_eq!(
        problem(&mut a, 1, local.ip(), remote.ip(), &misaligned),
        (0, 4)
    );
    // RFC 7112: a header after the Fragment header, or the upper-layer
    // header, extends beyond a physically complete first fragment.
    let mut post = vec![17, 2];
    post.resize(16, 0);
    let chain_past = raw(&prefix, 60, 0, true, &post, 5);
    let mut out = vec![0; 8192];
    assert!(a.0.receive(a.2, 1, &chain_past, false, &mut out).is_err());
    assert_eq!(
        problem(&mut a, 1, local.ip(), remote.ip(), &chain_past),
        (3, 0)
    );
    let mut tcp = vec![0; 16];
    tcp[12] = 0x50;
    let short_tcp = raw(&prefix, 6, 0, true, &tcp, 6);
    discarded(&mut a, &short_tcp);
    assert_eq!(
        problem(&mut a, 1, local.ip(), remote.ip(), &short_tcp),
        (3, 0)
    );
    // An absent optional header is valid, and No Next Header needs no
    // upper-layer header.
    let none = raw(&prefix, 59, 0, true, &[0; 8], 7);
    assert!(matches!(
        a.0.receive(a.2, 1, &none, false, &mut out),
        Ok(Received::Held)
    ));
    // Overlap abandons the datagram silently; its later malformed fragments
    // are discarded silently too, a refused chain (RFC 7112's code 3, an
    // option action 10 before the Fragment header) included.
    let first = raw(&prefix, 17, 0, true, &[0; 32], 8);
    assert!(matches!(
        a.0.receive(a.2, 1, &first, false, &mut out),
        Ok(Received::Held)
    ));
    discarded(&mut a, &raw(&[], 17, 16, true, &[0; 32], 8));
    discarded(&mut a, &raw(&prefix, 17, 64, true, &[1; 9], 8));
    discarded(&mut a, &raw(&prefix, 17, 65520, false, &[1; 8], 8));
    discarded(&mut a, &raw(&prefix, 60, 0, true, &post, 8));
    let reported = [(60, options(&[0x9e, 0]))];
    discarded(&mut a, &raw(&reported, 17, 64, true, &[1; 8], 8));
    assert!(drain(&mut a, 1).is_empty());
    let counters = a.0.reassembly_counters().discarded;
    assert_eq!((counters.overlap, counters.rejected), (1, 4));
    // An atomic fragment with that Identification belongs to no datagram
    // (RFC 6946 section 4): it is processed in isolation and delivered.
    let flow =
        a.0.udp_open(
            &a.1,
            local,
            None,
            UdpOptions {
                dscp: 0,
                hop_limit: 64,
            },
        )
        .unwrap();
    let atomic = raw(&prefix, 17, 0, false, &base[40..], 8);
    assert_eq!(
        input(&mut a, 1, &atomic),
        Ok(ntcp::InputDisposition::Processed)
    );
    let mut bytes = [0; 64];
    assert_eq!(
        a.0.udp_receive(flow, &mut bytes).unwrap(),
        Some((remote, 16))
    );
    assert_eq!(a.0.reassembly_counters().discarded.rejected, 4);
    // The same refused chains of another datagram are reported.
    let reported_chain = raw(&reported, 17, 64, true, &[1; 8], 10);
    assert!(a.0.receive(a.2, 1, &reported_chain, false, &mut out).is_err());
    assert_eq!(
        problem(&mut a, 1, local.ip(), remote.ip(), &reported_chain),
        (2, 42)
    );

    // With the largest capacity, data stored before fragment zero may end
    // at 65528; fragment zero's 16 further octets of unfragmentable part
    // then place it beyond the largest Payload Length, which ends the
    // datagram silently: no single fragment caused it.
    let mut b = side_with(
        local,
        87,
        &cfg,
        ReassemblyLimits {
            assemblies: 1,
            fragments: 8200,
            buffered_bytes: 66000 + 8200 * DESCRIPTOR,
            ipv4_datagram: 4096,
            ipv6_datagram: 65575,
            ipv4_timeout_seconds: 60,
        },
    );
    let stored = raw(&[], 17, 65520, false, &[1; 8], 9);
    assert!(matches!(
        b.0.receive(b.2, 1, &stored, false, &mut out),
        Ok(Received::Held)
    ));
    discarded(&mut b, &raw(&prefix, 17, 0, true, &[0; 8], 9));
    assert!(drain(&mut b, 1).is_empty());
    let counters = b.0.reassembly_counters().discarded;
    assert_eq!((counters.contradiction, counters.oversize), (1, 0));
    assert!(matches!(
        b.0.receive(b.2, 1, &stored, false, &mut out),
        Ok(Received::Held)
    ));
}

#[test]
fn later_fragment_limits_use_fragment_zeros_retained_prefix() {
    // Fragment zero's unfragmentable part is the one kept (RFC 8200
    // section 4.5), so once it is held a later fragment's own longer
    // pre-Fragment headers do not make the reassembled packet too large.
    let cfg = config(2);
    let (local, remote) = addresses(true);
    let to_us = ip(remote.ip(), local.ip());
    let base = udp(to_us, (remote.port(), local.port()), &[0; 16]);
    let raw =
        |prefix: &[(u8, Vec<u8>)], offset: usize, more: bool, data: &[u8], id| {
            let mut p = base[..40].to_vec();
            p[6] = 17;
            p.extend_from_slice(data);
            let mut headers = prefix.to_vec();
            headers.push((44, fragment_header(offset, more, id)));
            chain(&p, &headers)
        };
    let mut a = side_with(
        local,
        88,
        &cfg,
        ReassemblyLimits {
            assemblies: 1,
            fragments: 8200,
            buffered_bytes: 66000 + 8200 * DESCRIPTOR,
            ipv4_datagram: 4096,
            ipv6_datagram: 65575,
            ipv4_timeout_seconds: 60,
        },
    );
    let mut out = vec![0; 8192];
    let zero = raw(&[], 0, true, &base[40..56], 11);
    assert!(matches!(
        a.0.receive(a.2, 1, &zero, false, &mut out),
        Ok(Received::Held)
    ));
    // 65520 + 8 behind fragment zero's 40 octets fits; behind this
    // fragment's own 16 further octets it would not.
    let prefix = [(60, options(&[0; 14]))];
    let last = raw(&prefix, 65520, false, &[1; 8], 11);
    assert!(matches!(
        a.0.receive(a.2, 1, &last, false, &mut out),
        Ok(Received::Held)
    ));
    assert!(drain(&mut a, 1).is_empty());
    assert_eq!(a.0.reassembly_counters().discarded.oversize, 0);
}

fn discarded(a: &mut Side, frame: &[u8]) {
    let mut out = vec![0; 8192];
    assert!(matches!(
        a.0.receive(a.2, 1, frame, false, &mut out),
        Ok(Received::Discarded)
    ));
}
