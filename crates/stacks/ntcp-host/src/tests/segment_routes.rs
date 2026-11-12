// Output over an owner-configured Segment Routing route (RFC 8754 4.1, an
// SR source node): UDP in every send mode, Echo Replies and Host-originated
// Parameter Problems carry the route's Segment Routing Header, are sized
// with its complete header length H and are delivered once the final
// segment endpoint has processed it. The Echo adjunct's probes carry it and
// are certified by replies without it. ICMP quotes of that output are
// validated against the route generation that authorized it, and output
// whose indivisible header no longer fits fails admission. TCP segments
// are sized with H and placed after the header in every output mode, and
// the submission barrier admits only the exact chain of the path's route
// generation. A Packet Too Big quoting such a segment is judged with H and
// lowers only that SR path; stateless replies are sized with H too.
use super::*;
use core::net::Ipv6Addr;
use std::boxed::Box;

type Side = (Host, Endpoint, IngressContext);

const UDP: UdpLimits = UdpLimits {
    flows: 2,
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
// Identifiers start one MDL after the predecessor stopped at 0.
const MDL: u64 = 120_000_000;
// Two segments: H = 40 + 8 + 16 * 3.
const H: usize = 96;

fn segments() -> [Ipv6Addr; 2] {
    [
        "2001:db8:5::1".parse().unwrap(),
        "2001:db8:6::1".parse().unwrap(),
    ]
}

fn side(local: SocketAddr, identity: u64, adjunct_paths: usize) -> Side {
    side_with(
        local,
        identity,
        adjunct_paths,
        ConnectionlessSizing::default(),
    )
}

fn side_with(
    local: SocketAddr,
    identity: u64,
    adjunct_paths: usize,
    connectionless: ConnectionlessSizing,
) -> Side {
    let cfg = config(4);
    let mut side = managed_limited(local, identity, cfg, false, None, None, |p, mut l| {
        l.datagrams = DatagramLimits {
            max_fragments: 8,
            identifiers: IdentifierLimits {
                lifetime_seconds: 120,
                ipv4_tuples: 2,
                ipv6_leases: 16,
            },
            connectionless,
            peer_reassembly_ipv4: None,
            peer_reassembly_ipv6: None,
            adjunct: AdjunctLimits {
                paths: adjunct_paths,
                ..AdjunctLimits::default()
            },
        };
        let (mut p, l) = managed_udp_limits(p, l, UDP).unwrap();
        let (p2, mut l) = managed_icmp_output_limits(p, l, OUTPUT).unwrap();
        l.reassembly = REASSEMBLY;
        p = p2;
        p.routes += 1;
        (p, l, 1)
    });
    side.0.ports[0].as_mut().unwrap().receive.ipv6 = Ipv6Receive::Extensions;
    let mut counter = 0x31u8;
    side.0.set_entropy(Box::new(move |out: &mut [u8]| {
        for b in out.iter_mut() {
            *b = counter;
            counter = counter.wrapping_mul(5).wrapping_add(7);
        }
        Ok(())
    }));
    side.0.start_identifiers(Continuity::Fresh).unwrap();
    side
}

fn route(side: &Side, destination: IpAddr) -> path::Route {
    path::Route {
        destination: path::IpPrefix::new(destination, 128).unwrap(),
        source: None,
        dscp: None,
        link: side.2.link(),
        next_hop: path::NextHop::Forwarder(ForwarderId(9)),
        metric: 0,
    }
}

fn segment_route(side: &mut Side, destination: IpAddr) -> path::RouteId {
    let route = route(side, destination);
    side.0.add_segment_route(route, &segments()).unwrap()
}

fn v6(address: IpAddr) -> Ipv6Addr {
    match address {
        IpAddr::V6(a) => a,
        IpAddr::V4(_) => unreachable!(),
    }
}

fn udp_options() -> UdpOptions {
    UdpOptions {
        dscp: 0,
        hop_limit: 64,
    }
}

// The exact header chain of one packet sent toward D over `segments()`:
// the base Destination Address S1, then the Segment Routing Header of RFC
// 8754 2 and 4.1 (Routing Type 4, Hdr Ext Len 2m, Segments Left and Last
// Entry n, Segment List[0] = D, Segment List[i] = S(n + 1 - i), Flags and
// Tag zero) naming `next`, and a Payload Length counting it.
fn assert_srh(packet: &[u8], destination: Ipv6Addr, next: u8) {
    let [s1, s2] = segments();
    assert_eq!(packet[6], 43, "the SRH follows the base header");
    assert_eq!(&packet[24..40], &s1.octets(), "base destination S1");
    assert_eq!(
        usize::from(u16::from_be_bytes([packet[4], packet[5]])),
        packet.len() - 40
    );
    assert_eq!(&packet[40..48], &[next, 6, 4, 2, 2, 0, 0, 0]);
    assert_eq!(&packet[48..64], &destination.octets());
    assert_eq!(&packet[64..80], &s2.octets());
    assert_eq!(&packet[80..96], &s1.octets());
}

// The packet as the final segment endpoint forwards it (RFC 8754 4.3.1.1,
// End): Segments Left zero and the base Destination Address D.
fn arrive(packet: &[u8]) -> Vec<u8> {
    let mut packet = packet.to_vec();
    packet[43] = 0;
    let destination: [u8; 16] = packet[48..64].try_into().unwrap();
    packet[24..40].copy_from_slice(&destination);
    packet
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

// The Host's next ICMP output: every physical packet of it.
fn drain_one(side: &mut Side, now: u64) -> (Result<Option<BackendOutcome>, Error>, Vec<Vec<u8>>) {
    let mut packet = vec![0; 8192];
    let mut sent = Vec::new();
    let result = side.0.icmp_output(now, &mut packet, |_, bytes| {
        sent.push(bytes.to_vec());
        BackendOutcome::Submitted
    });
    (result, sent)
}

fn echo_request(ip: IpMetadata, sequence: u16, data: &[u8]) -> Vec<u8> {
    echo(ip, ntcp_icmp::EchoKind::Request, 7, sequence, data)
}

// An extension-free Echo message from `ip.source` to `ip.destination`.
fn echo(
    ip: IpMetadata,
    kind: ntcp_icmp::EchoKind,
    identifier: u16,
    sequence: u16,
    data: &[u8],
) -> Vec<u8> {
    let mut message = vec![0; 8 + data.len()];
    message[8..].copy_from_slice(data);
    let n =
        ntcp_icmp::encode_echo(ip, kind, identifier, sequence, &mut message, data.len()).unwrap();
    let mut frame = vec![0; 40 + n];
    frame[40..].copy_from_slice(&message[..n]);
    let header = ntcp_ip6::Header {
        ip,
        hop_limit: 64,
        dscp: 0,
        ecn: 0,
    };
    ntcp_ip6::encode_datagram(&mut frame, header, 58, n).unwrap();
    frame
}

// A UDP datagram to `ip.destination` behind a Destination Options header
// whose unknown option (action 10) draws a Parameter Problem, Code 2.
fn refused_udp(ip: IpMetadata, payload_len: usize) -> Vec<u8> {
    let mut udp = vec![0x5c; 8 + payload_len];
    let n = ntcp_ip_common::encode_udp(ip.source, ip.destination, 9, 1000, &mut udp, payload_len)
        .unwrap();
    let mut frame = vec![0; 48 + n];
    frame[48..].copy_from_slice(&udp[..n]);
    let header = ntcp_ip6::Header {
        ip,
        hop_limit: 64,
        dscp: 0,
        ecn: 0,
    };
    ntcp_ip6::encode_datagram(&mut frame, header, 17, 8 + n).unwrap();
    frame[6] = 60;
    frame[40..48].copy_from_slice(&[17, 0, 0x9e, 0, 1, 2, 0, 0]);
    frame
}

#[test]
fn udp_refuse_and_probe_carry_the_srh_within_h() {
    let (local, remote) = addresses(true);
    let mut a = side(local, 1701, 0);
    segment_route(&mut a, remote.ip());
    let mut b = side(remote, 1702, 0);
    let delivered = b.0.udp_open(&b.1, remote, None, udp_options()).unwrap();
    let flow =
        a.0.udp_open(&a.1, local, Some(remote), udp_options())
            .unwrap();
    // H + 8 octets of every 1500-octet packet are headers.
    let limits = a.0.udp_path_limits(&a.1, flow, None).unwrap();
    assert_eq!(limits.header_len, H);
    assert_eq!(limits.mms_s as usize, 1500 - H);
    assert_eq!(limits.max_payload, 1500 - H - 8);
    let mut packet = vec![0; 4096];
    assert_eq!(
        a.0.udp_send(
            &a.1,
            1,
            flow,
            None,
            &[1; 1500 - H - 7],
            &mut packet,
            |_, _| { BackendOutcome::Submitted }
        ),
        Err(UdpSendError::TooBig {
            max_payload: 1500 - H - 8
        })
    );
    let payload: Vec<u8> = (0..1500 - H - 8).map(|i| (i * 7) as u8).collect();
    let mut wire = Vec::new();
    a.0.udp_send(
        &a.1,
        2,
        flow,
        None,
        &payload,
        &mut packet,
        |egress, bytes| {
            assert_eq!(egress.next_hop, ResolvedNextHop::Forwarder(ForwarderId(9)));
            wire.push(bytes.to_vec());
            BackendOutcome::Submitted
        },
    )
    .unwrap();
    assert_eq!(wire.len(), 1);
    assert_eq!(wire[0].len(), 1500);
    assert_srh(&wire[0], v6(remote.ip()), 17);
    // The UDP checksum covers the final destination D, not S1.
    let udp = ntcp_ip_common::parse_udp(local.ip(), remote.ip(), &wire[0][H..]).unwrap();
    assert_eq!(udp.payload, &payload[..]);
    let record = a.0.ledger.records().last().unwrap();
    assert_eq!(
        (
            record.evidence.header_len,
            record.evidence.packet_len,
            record.evidence.destination
        ),
        (H as u32, 1500, remote.ip())
    );
    // The final segment delivers it to D's flow.
    assert_eq!(
        input(&mut b, 3, &arrive(&wire[0])),
        Ok(ntcp::InputDisposition::Processed)
    );
    let mut bytes = [0; 2048];
    assert_eq!(
        b.0.udp_receive(delivered, &mut bytes).unwrap(),
        Some((local, payload.len()))
    );
    assert_eq!(&bytes[..payload.len()], &payload[..]);

    // Probe: above a learned 1280 estimate, unfragmented within the first
    // hop, sized and recorded with H.
    a.0.trusted_decrease(4, limits.path, 1280).unwrap();
    let probe = UdpSend {
        mode: UdpSendMode::Probe,
        peer_capability: None,
    };
    let limits =
        a.0.udp_datagram_limits(&a.1, flow, None, Some(probe))
            .unwrap();
    assert_eq!(limits.unfragmented_payload, 1280 - H - 8);
    assert_eq!(limits.max_payload, 1500 - H - 8);
    assert_eq!(limits.buffer_len(1300), H + 8 + 1300);
    let send = |a: &mut Side, now: u64, len: usize, packet: &mut [u8]| {
        let mut wire = Vec::new();
        let result = a.0.udp_send_datagram(
            &a.1,
            MDL + now,
            flow,
            None,
            Some(probe),
            &vec![2; len],
            packet,
            |_, bytes| {
                wire.push(bytes.to_vec());
                BackendOutcome::Submitted
            },
        );
        (result, wire)
    };
    let (result, wire) = send(&mut a, 5, 1300, &mut packet);
    let record = result.unwrap().probe.unwrap();
    assert_eq!(wire.len(), 1);
    assert_eq!(wire[0].len(), H + 8 + 1300);
    assert_srh(&wire[0], v6(remote.ip()), 17);
    assert!(record.definite);
    assert_eq!(record.size as usize, H + 8 + 1300);
    assert_eq!(record.above, Some(1280));
    let evidence = a.0.ledger.records().last().unwrap().evidence;
    assert_eq!(
        (evidence.header_len, evidence.destination),
        (H as u32, remote.ip())
    );
    let (result, wire) = send(&mut a, 6, 1500 - H - 7, &mut packet);
    assert_eq!(
        result,
        Err(DatagramError::TooBig {
            max_payload: 1500 - H - 8
        })
    );
    assert!(wire.is_empty());
    assert_eq!(
        input(&mut b, 7, &arrive(&wire_of(&mut a, flow, 8))),
        Ok(ntcp::InputDisposition::Processed)
    );

    // Another destination keeps extension-free output.
    let other: SocketAddr = "[2001:db8::3]:9".parse().unwrap();
    let unconnected = a.0.udp_open(&a.1, local, None, udp_options()).unwrap();
    assert_eq!(
        a.0.udp_path_limits(&a.1, unconnected, Some(other.ip()))
            .unwrap()
            .header_len,
        40
    );
    let mut wire = Vec::new();
    a.0.udp_send(
        &a.1,
        9,
        unconnected,
        Some(other),
        &[3; 100],
        &mut packet,
        |_, bytes| {
            wire.push(bytes.to_vec());
            BackendOutcome::Submitted
        },
    )
    .unwrap();
    assert_eq!((wire[0].len(), wire[0][6]), (148, 17));
    assert_eq!(&wire[0][24..40], &v6(other.ip()).octets());
}

// One Refuse-mode datagram of the connected flow, its physical packet.
fn wire_of(a: &mut Side, flow: UdpFlowId, now: u64) -> Vec<u8> {
    let mut packet = vec![0; 4096];
    let mut wire = Vec::new();
    a.0.udp_send(&a.1, now, flow, None, &[4; 64], &mut packet, |_, bytes| {
        wire.push(bytes.to_vec());
        BackendOutcome::Submitted
    })
    .unwrap();
    wire.pop().unwrap()
}

#[test]
fn udp_fragments_repeat_the_srh_and_reassemble_at_the_final_destination() {
    let (local, remote) = addresses(true);
    let mut a = side(local, 1703, 0);
    segment_route(&mut a, remote.ip());
    let mut b = side(remote, 1704, 0);
    let delivered = b.0.udp_open(&b.1, remote, None, udp_options()).unwrap();
    let flow =
        a.0.udp_open(&a.1, local, Some(remote), udp_options())
            .unwrap();
    let fragment = UdpSend {
        mode: UdpSendMode::Fragment,
        peer_capability: Some(4000),
    };
    // MMS_S = EMTU_S - H: fragments of 1280 octets carry H + 8 header
    // octets before 1176 data octets.
    let limits =
        a.0.udp_datagram_limits(&a.1, flow, None, Some(fragment))
            .unwrap();
    assert_eq!(limits.effective_size, 1280);
    assert_eq!(limits.effective_payload, 1280 - H - 8);
    assert_eq!(limits.unfragmented_payload, 1500 - H - 8);
    assert_eq!(limits.buffer_len(3000), 1280 + 8 + 3000);
    assert_eq!(limits.buffer_len(100), H + 8 + 100);
    let payload: Vec<u8> = (0..3000u32).map(|i| (i * 13) as u8).collect();
    let mut packet = vec![0; limits.buffer_len(payload.len())];
    let mut wire = Vec::new();
    let report =
        a.0.udp_send_datagram(
            &a.1,
            MDL + 1,
            flow,
            None,
            Some(fragment),
            &payload,
            &mut packet,
            |_, bytes| {
                wire.push(bytes.to_vec());
                BackendOutcome::Submitted
            },
        )
        .unwrap();
    assert_eq!(
        (report.fragments, report.submitted, report.ip_len),
        (3, 3, H + 3008)
    );
    let identification = report.identification.unwrap();
    let mut data = Vec::new();
    for (i, bytes) in wire.iter().enumerate() {
        // Every fragment repeats the base header and the SRH, then the
        // Fragment header.
        assert_srh(bytes, v6(remote.ip()), 44);
        let f = &bytes[H..H + 8];
        let field = u16::from_be_bytes([f[2], f[3]]);
        assert_eq!(f[0], 17);
        assert_eq!(usize::from(field & !7), data.len());
        assert_eq!(field & 1 != 0, i != 2);
        assert_eq!(
            u32::from_be_bytes(f[4..8].try_into().unwrap()),
            identification
        );
        assert_eq!(bytes.len(), if i == 2 { H + 8 + 656 } else { 1280 });
        data.extend_from_slice(&bytes[H + 8..]);
    }
    // Fragment zero holds the complete UDP header; one checksum with D
    // covers the whole datagram.
    let udp = ntcp_ip_common::parse_udp(local.ip(), remote.ip(), &data).unwrap();
    assert_eq!(udp.payload, &payload[..]);
    let records: Vec<_> = a.0.ledger.records().map(|r| r.evidence).collect();
    assert_eq!(records.len(), 3);
    for (record, bytes) in records.iter().zip(&wire) {
        assert_eq!(
            (
                record.header_len as usize,
                record.packet_len as usize,
                record.destination
            ),
            (H + 8, bytes.len(), remote.ip())
        );
    }
    // The receiver reassembles the fragments the final segment forwards.
    for (i, bytes) in wire.iter().enumerate() {
        assert!(
            input(&mut b, 2 + i as u64, &arrive(bytes)).is_ok(),
            "fragment {i}"
        );
    }
    let mut bytes = vec![0; 4000];
    assert_eq!(
        b.0.udp_receive(delivered, &mut bytes).unwrap(),
        Some((local, payload.len()))
    );
    assert_eq!(&bytes[..payload.len()], &payload[..]);
}

#[test]
fn echo_replies_carry_the_srh_whole_and_fragmented() {
    let (local, remote) = addresses(true);
    let mut a = side(local, 1705, 0);
    segment_route(&mut a, remote.ip());
    let mut b = side(remote, 1706, 0);
    let to_a = IpMetadata {
        source: remote.ip(),
        destination: local.ip(),
    };
    let reply_ip = IpMetadata {
        source: local.ip(),
        destination: remote.ip(),
    };
    // Whole: H + 8 + 1000 octets within the 1280 connectionless size.
    let data: Vec<u8> = (0..1000u32).map(|i| (i * 3) as u8).collect();
    assert_eq!(
        input(&mut a, 1, &echo_request(to_a, 1, &data)),
        Ok(ntcp::InputDisposition::Processed)
    );
    let (result, wire) = drain_one(&mut a, 2);
    assert_eq!(result, Ok(Some(BackendOutcome::Submitted)));
    assert_eq!(wire.len(), 1);
    assert_eq!(wire[0].len(), H + 8 + 1000);
    assert_srh(&wire[0], v6(remote.ip()), 58);
    let reply = ntcp_icmp::decode_echo(reply_ip, &wire[0][H..]).unwrap();
    assert_eq!(
        (reply.kind, reply.sequence, reply.data),
        (ntcp_icmp::EchoKind::Reply, 1, &data[..])
    );
    // Fragmented: H + 8 + 1300 octets exceed it, within the 1500-octet peer
    // guarantee; each fragment repeats the SRH.
    let data: Vec<u8> = (0..1300u32).map(|i| (i * 5) as u8).collect();
    assert_eq!(
        input(&mut a, 3, &echo_request(to_a, 2, &data)),
        Ok(ntcp::InputDisposition::Processed)
    );
    let (result, wire) = drain_one(&mut a, MDL + 4);
    assert_eq!(result, Ok(Some(BackendOutcome::Submitted)));
    assert_eq!(wire.len(), 2);
    assert_eq!(wire[0].len(), 1280);
    for bytes in &wire {
        assert_srh(bytes, v6(remote.ip()), 44);
    }
    let mut out = vec![0; 8192];
    assert!(matches!(
        b.0.receive(b.2, 5, &arrive(&wire[0]), false, &mut out),
        Ok(Received::Held)
    ));
    let last = arrive(&wire[1]);
    let Ok(Received::Datagram(datagram)) = b.0.receive(b.2, 6, &last, false, &mut out) else {
        panic!("reassembled at the final destination");
    };
    let bytes = datagram.bytes();
    assert_eq!(bytes.len(), H + 8 + 1300);
    let reply = ntcp_icmp::decode_echo(reply_ip, &bytes[H..]).unwrap();
    assert_eq!((reply.sequence, reply.data), (2, &data[..]));
}

#[test]
fn parameter_problems_carry_the_srh_and_are_resized_at_drain() {
    let (local, remote) = addresses(true);
    let mut a = side(local, 1707, 0);
    let ordinary = route(&a, remote.ip());
    let to_a = IpMetadata {
        source: remote.ip(),
        destination: local.ip(),
    };
    let error_ip = IpMetadata {
        source: local.ip(),
        destination: remote.ip(),
    };
    let invoking = refused_udp(to_a, 1300);
    let check = |packet: &[u8], header: usize| {
        let message = &packet[header..];
        assert_eq!(packet.len(), 1280, "as much of the invoking packet as fits");
        assert_eq!((message[0], message[1]), (4, 2));
        assert_eq!(u32::from_be_bytes(message[4..8].try_into().unwrap()), 42);
        assert_eq!(ntcp_icmp::icmpv6_checksum(error_ip, message), Ok(0));
        assert_eq!(&message[8..], &invoking[..1280 - header - 8]);
    };
    // Queued while the destination's route is ordinary, held by WouldBlock,
    // then drained after the route became an SR route: the quote shrinks by
    // the SRH and the checksum covers the new message.
    let id = a.0.add_route(ordinary).unwrap();
    assert!(input(&mut a, 1, &invoking).is_err());
    let mut packet = vec![0; 8192];
    assert_eq!(
        a.0.icmp_output(2, &mut packet, |_, bytes| {
            check(bytes, 40);
            BackendOutcome::WouldBlock
        }),
        Ok(Some(BackendOutcome::WouldBlock))
    );
    assert_eq!(a.0.icmp_output_pending(), 1);
    a.0.remove_route(id).unwrap();
    let id = segment_route(&mut a, remote.ip());
    let (result, wire) = drain_one(&mut a, 3);
    assert_eq!(result, Ok(Some(BackendOutcome::Submitted)));
    assert_eq!(wire.len(), 1, "never fragmented");
    assert_srh(&wire[0], v6(remote.ip()), 58);
    check(&wire[0], H);
    // The reverse: queued and held over the SR route, drained after its
    // replacement by an ordinary route with the longer quote.
    assert!(input(&mut a, 4, &invoking).is_err());
    assert_eq!(
        a.0.icmp_output(5, &mut packet, |_, bytes| {
            assert_srh(bytes, v6(remote.ip()), 58);
            check(bytes, H);
            BackendOutcome::WouldBlock
        }),
        Ok(Some(BackendOutcome::WouldBlock))
    );
    a.0.replace_route(id, ordinary).unwrap();
    let (result, wire) = drain_one(&mut a, 6);
    assert_eq!(result, Ok(Some(BackendOutcome::Submitted)));
    assert_eq!(wire[0][6], 58, "extension-free");
    check(&wire[0], 40);
}

#[test]
fn errors_whose_header_cannot_fit_the_minimum_mtu_are_not_sent() {
    let (local, remote) = addresses(true);
    let mut a = side(local, 1708, 0);
    // 126 segments: H = 40 + 8 + 16 * 127 = 2080 > 1280.
    let segments: Vec<Ipv6Addr> = (1..=126u16)
        .map(|i| Ipv6Addr::new(0x2001, 0xdb8, 0x7, i, 0, 0, 0, 1))
        .collect();
    let route = route(&a, remote.ip());
    a.0.add_segment_route(route, &segments).unwrap();
    let to_a = IpMetadata {
        source: remote.ip(),
        destination: local.ip(),
    };
    assert!(input(&mut a, 1, &refused_udp(to_a, 100)).is_err());
    assert_eq!(a.0.icmp_output_pending(), 1);
    let (result, wire) = drain_one(&mut a, 2);
    assert!(result.is_err());
    assert!(wire.is_empty());
    assert_eq!(a.0.icmp_output_pending(), 0);
    assert_eq!(a.0.icmp_output_counters().unsent, 1);
}

// A router's ICMPv6 error of `kind` to `local` quoting as much of `packet`
// as fits the minimum MTU.
fn icmp_error(local: IpAddr, packet: &[u8], kind: (u8, u8), mtu: u32) -> Vec<u8> {
    let quote = &packet[..packet.len().min(1232)];
    let outer = IpMetadata {
        source: "2001:db8::fe".parse().unwrap(),
        destination: local,
    };
    let mut message = vec![0; 8 + quote.len()];
    (message[0], message[1]) = kind;
    message[4..8].copy_from_slice(&mtu.to_be_bytes());
    message[8..].copy_from_slice(quote);
    let sum = ntcp_icmp::icmpv6_checksum(outer, &message).unwrap();
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    let mut frame = vec![0; 40 + message.len()];
    frame[40..].copy_from_slice(&message);
    let header = ntcp_ip6::Header {
        ip: outer,
        hop_limit: 64,
        dscp: 0,
        ecn: 0,
    };
    ntcp_ip6::encode_datagram(&mut frame, header, 58, message.len()).unwrap();
    frame
}

// `packet` as a segment endpoint forwards it with `left` segments left
// (RFC 8754 4.3.1.1): the base Destination Address becomes Segment
// List[left]; nothing else changes.
fn advanced(packet: &[u8], left: usize) -> Vec<u8> {
    let mut packet = packet.to_vec();
    packet[43] = left as u8;
    let at = 48 + 16 * left;
    let address: [u8; 16] = packet[at..at + 16].try_into().unwrap();
    packet[24..40].copy_from_slice(&address);
    packet
}

fn icmp(side: &mut Side, now: u64, frame: &[u8]) -> Result<IcmpDispatch, Error> {
    side.0.input_icmp(&mut side.1, side.2, now, frame, None)
}

fn declined(dispatch: &Result<IcmpDispatch, Error>) -> bool {
    matches!(
        dispatch,
        Err(_) | Ok(IcmpDispatch::Completed(IcmpOutcome::Discarded(_)))
    )
}

// Alterations of a quoted SR packet that legitimate forwarding never makes:
// Segment List[0] (the final destination), a middle segment, Last Entry,
// Routing Type, flags, tag, Destination Addresses impossible for Segments
// Left, the Payload Length and the UDP source port.
type Alteration = (&'static str, fn(&mut Vec<u8>));

fn alterations() -> Vec<Alteration> {
    vec![
        ("final destination", |p| p[63] ^= 1),
        ("middle segment", |p| p[79] ^= 1),
        ("Last Entry", |p| p[44] = 1),
        ("Routing Type 0", |p| p[42] = 0),
        ("Routing Type 5", |p| p[42] = 5),
        ("flags", |p| p[45] = 0x80),
        ("tag", |p| p[47] = 1),
        ("S2 with Segments Left 2", |p| {
            let s2: [u8; 16] = p[64..80].try_into().unwrap();
            p[24..40].copy_from_slice(&s2);
        }),
        ("S1 with Segments Left 1", |p| p[43] = 1),
        ("D with Segments Left 1", |p| {
            p[43] = 1;
            let d: [u8; 16] = p[48..64].try_into().unwrap();
            p[24..40].copy_from_slice(&d);
        }),
        ("length", |p| p[5] ^= 8),
        ("selector", |p| p[97] ^= 1),
    ]
}

#[test]
fn quotes_of_udp_output_are_validated_against_the_authorizing_route() {
    let (local, remote) = addresses(true);
    let mut a = side(local, 1711, 0);
    let id = segment_route(&mut a, remote.ip());
    let flow =
        a.0.udp_open(&a.1, local, Some(remote), udp_options())
            .unwrap();
    let wire = wire_of(&mut a, flow, 1);
    assert_srh(&wire, v6(remote.ip()), 17);
    let unreachable = (1, 4);
    // Before the first segment endpoint (Segments Left n, Destination
    // Address S1, which differs from Segment List[0] = D) and after each
    // legitimate advancement, the quote correlates by D with the flow.
    for left in [2, 1, 0] {
        let quoted = advanced(&wire, left);
        let dispatch = icmp(&mut a, 2, &icmp_error(local.ip(), &quoted, unreachable, 0));
        assert!(
            matches!(
                dispatch,
                Ok(IcmpDispatch::Completed(IcmpOutcome::Advice {
                    owner: Some(_),
                    advice: Advice::NetworkError(_),
                    ..
                }))
            ),
            "Segments Left {left}: {dispatch:?}"
        );
    }
    for (name, alter) in alterations() {
        let mut quoted = wire.clone();
        alter(&mut quoted);
        let dispatch = icmp(&mut a, 3, &icmp_error(local.ip(), &quoted, unreachable, 0));
        assert!(declined(&dispatch), "{name}: {dispatch:?}");
    }
    // A Packet Too Big about an altered quote publishes nothing.
    let mut quoted = advanced(&wire, 1);
    quoted[79] ^= 1;
    let path = a.0.udp_path_limits(&a.1, flow, None).unwrap().path;
    let dispatch = icmp(&mut a, 4, &icmp_error(local.ip(), &quoted, (2, 0), 1280));
    assert!(declined(&dispatch), "{dispatch:?}");
    assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), None);
    // The route generation that authorized the submission is gone once it
    // is replaced, even by an identical list: the quote is declined.
    a.0.remove_route(id).unwrap();
    segment_route(&mut a, remote.ip());
    let dispatch = icmp(&mut a, 5, &icmp_error(local.ip(), &wire, unreachable, 0));
    assert!(declined(&dispatch), "{dispatch:?}");
}

#[test]
fn adjunct_probes_carry_the_srh_and_plain_replies_certify_the_request() {
    let (local, remote) = addresses(true);
    let mut a = side(local, 1709, 1);
    segment_route(&mut a, remote.ip());
    // The responder sends its 1334-octet reply whole.
    let mut b = side_with(
        remote,
        1712,
        0,
        ConnectionlessSizing {
            ipv6: 1500,
            ..ConnectionlessSizing::default()
        },
    );
    let flow =
        a.0.udp_open(&a.1, local, Some(remote), udp_options())
            .unwrap();
    // A fragmented datagram is the adjunct's demand for the SR path.
    let fragment = UdpSend {
        mode: UdpSendMode::Fragment,
        peer_capability: Some(4000),
    };
    let mut packet = vec![0; 8192];
    let report =
        a.0.udp_send_datagram(
            &a.1,
            MDL + 1,
            flow,
            None,
            Some(fragment),
            &[9; 3000],
            &mut packet,
            |_, _| BackendOutcome::Submitted,
        )
        .unwrap();
    assert!(report.fragments > 1);
    let path = a.0.udp_path_limits(&a.1, flow, None).unwrap().path;
    let request_ip = IpMetadata {
        source: local.ip(),
        destination: remote.ip(),
    };
    // The probe halves (E = 1280, min(first hop, demand) = 1500] and carries
    // the SRH: H of its 1390 octets are headers, its Echo checksum covers D.
    let (result, wire) = drain_one(&mut a, MDL + 10_000_000);
    assert_eq!(result, Ok(Some(BackendOutcome::Submitted)));
    assert_eq!(wire.len(), 1);
    assert_eq!(wire[0].len(), 1390);
    assert_srh(&wire[0], v6(remote.ip()), 58);
    let probe = ntcp_icmp::decode_echo(request_ip, &wire[0][H..]).unwrap();
    assert_eq!(probe.kind, ntcp_icmp::EchoKind::Request);
    assert_eq!(probe.data.len(), 1390 - H - 8);
    // The final destination answers once the last segment endpoint
    // forwarded the probe; its reply has no extension header.
    assert_eq!(
        input(&mut b, MDL + 10_000_001, &arrive(&wire[0])),
        Ok(ntcp::InputDisposition::Processed)
    );
    let (result, replies) = drain_one(&mut b, MDL + 10_000_002);
    assert_eq!(result, Ok(Some(BackendOutcome::Submitted)));
    assert_eq!(replies.len(), 1);
    assert_eq!(
        (replies[0][6], replies[0].len()),
        (58, 40 + 8 + probe.data.len())
    );
    // A reply whose message differs from the request certifies nothing and
    // leaves the probe outstanding.
    let reply_ip = IpMetadata {
        source: remote.ip(),
        destination: local.ip(),
    };
    let short = echo(
        reply_ip,
        ntcp_icmp::EchoKind::Reply,
        probe.identifier,
        probe.sequence,
        &probe.data[..probe.data.len() - 8],
    );
    assert_eq!(
        icmp(&mut a, MDL + 10_000_003, &short),
        Ok(IcmpDispatch::Completed(IcmpOutcome::Probe(
            ProbeOutcome::Unmatched
        )))
    );
    assert_eq!(a.0.adjunct_outstanding(), 1);
    // The exact reply certifies the recorded size, H included, for the SR
    // path the probe took.
    assert!(matches!(
        icmp(&mut a, MDL + 10_000_004, &replies[0]),
        Ok(IcmpDispatch::Completed(IcmpOutcome::Probe(
            ProbeOutcome::Confirmed { size: 1390, .. }
        )))
    ));
    assert_eq!(a.0.adjunct_confirmed(path), 1390);
    // The next probe: a router's Packet Too Big quoting it with an altered
    // segment is declined; one quoting it after legitimate advancement is
    // the probe's.
    let (result, wire) = drain_one(&mut a, MDL + 10_000_005);
    assert_eq!(result, Ok(Some(BackendOutcome::Submitted)));
    assert_eq!(wire[0].len(), 1445);
    assert_srh(&wire[0], v6(remote.ip()), 58);
    let mut altered = advanced(&wire[0], 1);
    altered[79] ^= 1;
    let dispatch = icmp(
        &mut a,
        MDL + 10_000_006,
        &icmp_error(local.ip(), &altered, (2, 0), 1400),
    );
    assert!(declined(&dispatch), "{dispatch:?}");
    assert_eq!(a.0.adjunct_outstanding(), 1);
    let quoted = advanced(&wire[0], 1);
    assert!(matches!(
        icmp(
            &mut a,
            MDL + 10_000_007,
            &icmp_error(local.ip(), &quoted, (2, 0), 1400)
        ),
        Ok(IcmpDispatch::Completed(IcmpOutcome::Probe(
            ProbeOutcome::TooBig { size: 1445, .. }
        )))
    ));
    assert_eq!(a.0.adjunct_outstanding(), 0);
}

#[derive(Clone, Copy, Debug)]
enum Change {
    PathMtu,
    Administrative,
    Link,
}

// Lower `a`'s view of `path` to 1280 octets by `change`.
fn lower(a: &mut Side, now: u64, path: path::PathId, change: Change) {
    match change {
        Change::PathMtu => {
            a.0.trusted_decrease(now, path, 1280).unwrap();
        }
        Change::Administrative => {
            let capability = a.0.administration();
            super::admin::set_estimate(a, &capability, now, path, Some(1280)).unwrap();
        }
        Change::Link => a.0.set_link_mtu(a.2.link(), 1280).unwrap(),
    }
}

fn many_segments(n: u16) -> Vec<Ipv6Addr> {
    (1..=n)
        .map(|i| Ipv6Addr::new(0x2001, 0xdb8, 0x7, i, 0, 0, 0, 1))
        .collect()
}

#[test]
fn output_whose_header_no_longer_fits_fails_admission() {
    // 80 segments: H = 40 + 8 + 16 * 81 = 1344, so H + 8 fits a 1500-octet
    // path but not 1280.
    const BIG: usize = 1344;
    for change in [Change::PathMtu, Change::Administrative, Change::Link] {
        let (local, remote) = addresses(true);
        let mut a = side(local, 1713, 0);
        let route = route(&a, remote.ip());
        a.0.add_segment_route(route, &many_segments(80)).unwrap();
        let flow =
            a.0.udp_open(&a.1, local, Some(remote), udp_options())
                .unwrap();
        let limits = a.0.udp_path_limits(&a.1, flow, None).unwrap();
        assert_eq!(
            (limits.header_len, limits.max_payload),
            (BIG, 1500 - BIG - 8)
        );
        let mut packet = vec![0; 4096];
        let mut sent = 0;
        a.0.udp_send(&a.1, 1, flow, None, &[1; 148], &mut packet, |_, _| {
            sent += 1;
            BackendOutcome::Submitted
        })
        .unwrap();
        assert_eq!(sent, 1);
        lower(&mut a, 2, limits.path, change);
        // No UDP mode admits a datagram, however small, and nothing leaves.
        assert_eq!(
            a.0.udp_path_limits(&a.1, flow, None),
            Err(Error::Unsupported),
            "{change:?}"
        );
        assert_eq!(
            a.0.udp_send(&a.1, 3, flow, None, &[], &mut packet, |_, _| {
                unreachable!()
            }),
            Err(UdpSendError::Host(Error::Unsupported))
        );
        for mode in [
            UdpSendMode::Refuse,
            UdpSendMode::Probe,
            UdpSendMode::Fragment,
        ] {
            let send = UdpSend {
                mode,
                peer_capability: Some(4000),
            };
            assert!(
                a.0.udp_send_datagram(
                    &a.1,
                    MDL + 4,
                    flow,
                    None,
                    Some(send),
                    &[1; 16],
                    &mut packet,
                    |_, _| unreachable!(),
                )
                .is_err(),
                "{change:?} {mode:?}"
            );
        }
        // An Echo Reply is neither cut nor sent over another route.
        let to_a = IpMetadata {
            source: remote.ip(),
            destination: local.ip(),
        };
        assert_eq!(
            input(&mut a, 5, &echo_request(to_a, 1, &[7; 32])),
            Ok(ntcp::InputDisposition::Processed)
        );
        let (result, wire) = drain_one(&mut a, 6);
        assert_eq!(result, Err(Error::Unsupported), "{change:?}");
        assert!(wire.is_empty());
        assert_eq!(a.0.icmp_output_counters().unsent, 1);
    }
}

#[test]
fn adjunct_probe_without_room_for_the_header_is_not_sent() {
    // 82 segments: H = 40 + 8 + 16 * 83 = 1376. Fragments of the 1500-octet
    // connectionless size create demand; after a PMTU decrease to 1280 the
    // search's first probe of 1390 octets cannot hold H, the Echo header
    // and the 16-octet nonce.
    let (local, remote) = addresses(true);
    let mut a = side_with(
        local,
        1714,
        1,
        ConnectionlessSizing {
            ipv6: 1500,
            ..ConnectionlessSizing::default()
        },
    );
    let route = route(&a, remote.ip());
    a.0.add_segment_route(route, &many_segments(82)).unwrap();
    let flow =
        a.0.udp_open(&a.1, local, Some(remote), udp_options())
            .unwrap();
    let fragment = UdpSend {
        mode: UdpSendMode::Fragment,
        peer_capability: Some(4000),
    };
    let mut packet = vec![0; 8192];
    let report =
        a.0.udp_send_datagram(
            &a.1,
            MDL + 1,
            flow,
            None,
            Some(fragment),
            &[9; 300],
            &mut packet,
            |_, _| BackendOutcome::Submitted,
        )
        .unwrap();
    assert_eq!(report.fragments, 3);
    let path = a.0.udp_path_limits(&a.1, flow, None).unwrap().path;
    lower(&mut a, MDL + 2, path, Change::PathMtu);
    let due = a.0.next_adjunct_deadline().unwrap();
    let (result, wire) = drain_one(&mut a, due);
    assert_eq!(result, Err(Error::Unsupported));
    assert!(wire.is_empty());
    let counters = a.0.adjunct_counters();
    assert_eq!((counters.probes, counters.not_sent), (0, 1));
}

fn tcp_side(local: SocketAddr, identity: u64, cfg: EndpointConfig, gso: bool) -> Side {
    let mut side = managed_limited(local, identity, cfg, gso, None, None, |mut p, l| {
        p.routes += 1;
        (p, l, 1)
    });
    side.0.ports[0].as_mut().unwrap().receive.ipv6 = Ipv6Receive::Extensions;
    side
}

// A configuration whose search starts at the 1500-octet first hop, so the
// connection's segments have their full size from the start.
fn full_size_config() -> EndpointConfig {
    let mut cfg = config(4);
    cfg.connection.pmtud.as_mut().unwrap().initial_search_low = Some(1500);
    cfg
}

// The next attempt's frame as the embeddings build it: drained with the
// Host as path provider (a stateless reply sized for the path selected
// now), the TCP segment after the complete IP header of the path its
// authority selected (`Host::header_plan`).
fn routed_frame(side: &mut Side, now: u64) -> Option<(TransmitAttempt, EgressContext, Vec<u8>)> {
    let mut tcp = [0; 2048];
    let (poll, attempt) = side
        .1
        .poll_reserved_transmit_with_path_provider(now, &mut tcp, 32, &mut side.0)
        .unwrap();
    let packet = poll.packet?;
    let attempt = attempt.unwrap();
    let context = side.0.egress_context(&mut side.1, attempt).unwrap();
    let plan = side.0.header_plan(context.binding.snapshot.key()).unwrap();
    assert_eq!(plan.len, context.binding.snapshot.ip_header_len() as usize);
    let mut frame = vec![0; plan.len + packet.len];
    frame[plan.len..].copy_from_slice(&tcp[..packet.len]);
    let n = ntcp_ip6::encode_tcp_routed(&mut frame, packet, plan.segments, packet.len).unwrap();
    assert_eq!(n, frame.len());
    Some((attempt, context, frame))
}

fn submit_frame(
    side: &mut Side,
    now: u64,
    context: EgressContext,
    frame: &[u8],
    shared: usize,
) -> Result<Submission, Refused> {
    let ticket = side.0.submission_ticket(&mut side.1, context).unwrap();
    side.0
        .submit(&mut side.1, now, ticket, context, frame, shared, |_| {
            BackendOutcome::Submitted
        })
}

// Submit the next attempt; a probe's intent is its exact submitted size.
fn emit_routed(side: &mut Side, now: u64) -> Option<Vec<u8>> {
    let (attempt, context, frame) = routed_frame(side, now)?;
    if let Some(intent) = side.1.transmit_discovery_intent(attempt) {
        assert_eq!(intent.ip_packet_len() as usize, frame.len());
    }
    assert!(submit_frame(side, now, context, &frame, 0) == Ok(Submission::Submitted));
    side.0.collect(&mut side.1).unwrap();
    Some(frame)
}

// One TCP segment A sent toward D over `segments()`: the exact chain, at
// most the 1500-octet first hop, and a checksum over the final destination
// (the base Destination Address S1 would not seal it).
fn assert_routed_tcp(frame: &[u8], local: SocketAddr, remote: SocketAddr) {
    assert!(frame.len() <= 1500);
    assert_srh(frame, v6(remote.ip()), 6);
    let tcp = &frame[H..];
    assert_eq!(
        ntcp_ip_common::pseudo_header_checksum(local.ip(), remote.ip(), 6, tcp),
        Ok(0)
    );
    let s1 = IpAddr::V6(segments()[0]);
    assert_ne!(
        ntcp_ip_common::pseudo_header_checksum(local.ip(), s1, 6, tcp),
        Ok(0)
    );
}

// Run both sides in 1 ms steps until `done`. A's output reaches B as the
// final segment endpoint forwards it (`arrive`) when `deliver` accepts it;
// B's replies reach A directly.
fn run(
    a: &mut Side,
    b: &mut Side,
    now: &mut u64,
    mut deliver: impl FnMut(&[u8]) -> bool,
    mut done: impl FnMut(&mut Side, &mut Side) -> bool,
) {
    for _ in 0..4000 {
        if done(a, b) {
            return;
        }
        *now += 1000;
        a.1.on_timeout(*now, 32).unwrap();
        b.1.on_timeout(*now, 32).unwrap();
        while let Some(frame) = emit_routed(a, *now) {
            if deliver(&frame) {
                let packet = if frame[6] == 43 {
                    arrive(&frame)
                } else {
                    frame
                };
                input(b, *now + 1, &packet).unwrap();
            }
        }
        while let Some(frame) = emit_routed(b, *now + 2) {
            input(a, *now + 3, &frame).unwrap();
        }
    }
    panic!("the exchange did not finish");
}

// The handshake, each of A's segments checked by `check`.
fn establish(
    a: &mut Side,
    b: &mut Side,
    now: &mut u64,
    id: ConnectionId,
    listener: ntcp::ListenerId,
    check: impl Fn(&[u8]),
) -> ConnectionId {
    let mut child = None;
    run(
        a,
        b,
        now,
        |frame| {
            check(frame);
            true
        },
        |a, b| {
            if a.1.state(id).unwrap() == State::Established {
                child = child.or_else(|| b.1.accept(listener).ok());
            }
            child.is_some()
        },
    );
    child.unwrap()
}

fn read_all(b: &mut Side, child: ConnectionId, into: &mut Vec<u8>) {
    let mut chunk = [0; 4096];
    while let Ok(n) = b.1.read(child, &mut chunk) {
        if n == 0 {
            break;
        }
        into.extend_from_slice(&chunk[..n]);
    }
}

//= https://www.rfc-editor.org/rfc/rfc8201#section-5.1
//= type=test
//= reason=Host path budgets subtract the complete IPv6 header H of the selected path, the 40-octet base header plus, on an owner-configured Segment Routing route of n segments, its 8 + 16(n + 1)-octet Segment Routing Header (Host::header_plan, PathSnapshot::ip_header_len), from the largest IP packet that can be sent: TCP takes H before construction and admission for its MSS, T16's segment quantum and send space, PLPMTUD probes, exact-range repair and retransmission in scalar, shared, reserved and software GSO output, and an indivisible header that no longer fits fails admission. Host UDP flows report MMS_S as the path budget less H and limit Refuse and Probe payloads to EMTU_S - H - 8. When source fragmentation is selected (Host::udp_send_datagram's Fragment mode and the Host's Echo Replies, where a reply to an IPv4 source-routed Echo Request takes the reversed, policy-authorized return route, registers no adjunct demand and is never sized by an adjunct-confirmed bound, while IPv6 Echo Replies use only owner-configured routes) EMTU_S is the receiver's reassembly guarantee (1500 octets for IPv6) or a capability the application states from upper-layer or deployment knowledge, and the Host creates fragments each limited by the connectionless effective size (never above the PMTU) that repeat the unfragmentable part (base header and Segment Routing Header) before the Fragment header; Refuse and Probe modes and TCP keep EMTU_S at the PMTU (TCP never source-fragments). Host::reassembly_capacity states this Host's own EMTU_R and MMS_R, and every managed TCP factory advertises the MSS Host::receive_ip_capability derives from EMTU_R, the largest IPv6 link and the wire limit independently of the send PMTU (T16, 1191-024). Host segment_routes tests (TCP, UDP Refuse/Probe/Fragment, Echo and ICMP errors with exact chains and checksums over the final destination), the native and tun_echo placement tests and the integration/rfc_host srh cases verify it, per embedding: tun_echo's transit-ptb case repairs a transit router's real Packet Too Big quoting its submitted SRH packets and makes TCP progress through a Linux SRv6 endpoint, and the native runtime's endpoint case makes TCP progress through Linux's own SR endpoint processing to the final destination.
//# MMS_S is a transport message size calculated by subtracting the size of the IPv6 header (including IPv6 extension headers) from the largest IP packet that can be sent, EMTU_S. MMS_S is limited by a combination of factors, including the PMTU, support for packet fragmentation and reassembly, and the packet reassembly limit (see "Fragment Header", Section 4.5 of [RFC8200]). When source fragmentation is available, EMTU_S is set to EMTU_R, as indicated by the receiver using an upper-layer protocol or based on protocol requirements (1500 octets for IPv6). When a message larger than PMTU is to be transmitted, the source creates fragments, each limited by PMTU. When source fragmentation is not desired, EMTU_S is set to PMTU, and the upper-layer protocol is expected to either perform its own fragmentation and reassembly or otherwise limit the size of its messages accordingly.
#[test]
fn tcp_over_a_segment_route_sizes_and_repairs_segments_with_h() {
    let cfg = full_size_config();
    let (local, remote) = addresses(true);
    let mut a = tcp_side(local, 1720, cfg.clone(), false);
    segment_route(&mut a, remote.ip());
    let mut b = tcp_side(remote, 1721, cfg.clone(), false);
    let listener = b.1.listen(remote, 4).unwrap();
    let id =
        a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
    // H is known before construction and fixed by the route generation.
    assert_eq!(
        a.0.binding(id).unwrap().snapshot.ip_header_len() as usize,
        H
    );
    assert_eq!(a.1.managed_path(id).unwrap().ip_header_len as usize, H);
    let (_, context, syn) = routed_frame(&mut a, 1).unwrap();
    assert_routed_tcp(&syn, local, remote);
    // The barrier admits exactly the route generation's chain: not the
    // segment behind a base header toward D or S1, nor an SRH with an
    // altered segment, Segments Left, Last Entry or tag.
    let tcp = &syn[H..];
    let packet = a.1.transmit_attempt_packet(context.attempt).unwrap();
    for destination in [remote.ip(), IpAddr::V6(segments()[0])] {
        let mut base = vec![0; 40 + tcp.len()];
        base[40..].copy_from_slice(tcp);
        ntcp_ip6::encode(&mut base, packet).unwrap();
        base[24..40].copy_from_slice(&v6(destination).octets());
        assert_eq!(
            a.0.validate_egress(&mut a.1, context, &base, 0),
            Err(Error::Obsolete)
        );
    }
    for at in [64, 43, 44, 47] {
        let mut altered = syn.clone();
        altered[at] ^= 1;
        assert!(
            a.0.validate_egress(&mut a.1, context, &altered, 0).is_err(),
            "{at}"
        );
    }
    assert!(submit_frame(&mut a, 1, context, &syn, 0) == Ok(Submission::Submitted));
    a.0.collect(&mut a.1).unwrap();
    assert_eq!(
        syn[H + 13] & (ntcp::wire::SYN | ntcp::wire::ACK),
        ntcp::wire::SYN
    );
    input(&mut b, 2, &arrive(&syn)).unwrap();
    let mut now = 2;
    let child = establish(&mut a, &mut b, &mut now, id, listener, |frame| {
        assert_routed_tcp(frame, local, remote)
    });
    // Q is the 1500-octet path less H, TCP and timestamps; the send space
    // C is the 65536-octet buffer rounded down to whole segments of Q.
    let q = 1500 - H - 20 - 12;
    assert_eq!(a.1.transport_ceilings(id).unwrap().effective_mss, q);
    let payload: Vec<u8> = (0..70000).map(|i| (i * 13 % 251) as u8).collect();
    let admitted = a.1.write(id, &payload).unwrap();
    assert_eq!(admitted, 65536 / q * q);
    // The first data segment is lost once: its retransmission carries the
    // same chain.
    let mut sent = Vec::new();
    let mut lost = None;
    let mut received = Vec::new();
    run(
        &mut a,
        &mut b,
        &mut now,
        |frame| {
            assert_routed_tcp(frame, local, remote);
            let sequence = u32::from_be_bytes(frame[H + 4..H + 8].try_into().unwrap());
            let data = frame.len() > H + 32;
            sent.push((sequence, frame.len(), data));
            if data && lost.is_none() {
                lost = Some(sequence);
                return false;
            }
            true
        },
        |_, b| {
            read_all(b, child, &mut received);
            received.len() == admitted
        },
    );
    assert_eq!(received, payload[..admitted]);
    let lost = lost.unwrap();
    assert_eq!(sent.iter().filter(|(s, _, d)| *s == lost && *d).count(), 2);
    // Full segments fill the first hop exactly with H.
    assert!(sent.iter().any(|&(_, len, _)| len == 1500));
}

// A Packet Too Big quoting a submitted full-size SRH TCP segment, before
// the first segment endpoint (Segments Left 2, base Destination Address S1)
// and after it (Segments Left 1, Segment List[1]); both differ from Segment
// List[0] = D. The report is judged with H: it lowers only that SR path,
// the connection's segments shrink to the new size less H, and the dropped
// range is repaired at once within it.
#[test]
fn ptb_quoting_srh_tcp_lowers_only_that_segment_route() {
    for left in [2usize, 1] {
        let cfg = full_size_config();
        let (local, remote) = addresses(true);
        let mut a = tcp_side(local, 1740 + left as u64, cfg.clone(), false);
        segment_route(&mut a, remote.ip());
        let mut b = tcp_side(remote, 1750 + left as u64, cfg.clone(), false);
        let listener = b.1.listen(remote, 4).unwrap();
        let id =
            a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
                .unwrap();
        let mut now = 0;
        let child = establish(&mut a, &mut b, &mut now, id, listener, |frame| {
            assert_routed_tcp(frame, local, remote)
        });
        let payload: Vec<u8> = (0..20000).map(|i| (i * 7 % 251) as u8).collect();
        let admitted = a.1.write(id, &payload).unwrap();
        now += 1000;
        let dropped = emit_routed(&mut a, now).unwrap();
        assert_eq!(dropped.len(), 1500);
        let start = u32::from_be_bytes(dropped[H + 4..H + 8].try_into().unwrap());
        // An ordinary path on the same Host: S1 itself, over the default
        // route.
        let s1 = SocketAddr::new(IpAddr::V6(segments()[0]), remote.port());
        let other =
            a.1.connect_with_path_provider(now, local, s1, options(&cfg, 0), &mut a.0)
                .unwrap();
        let other_path = a.0.binding(other).unwrap().snapshot.path();
        let path = a.0.binding(id).unwrap().snapshot.path();
        assert_ne!(path, other_path);
        let quoted = if left == 2 {
            dropped.clone()
        } else {
            advanced(&dropped, left)
        };
        assert_ne!(&quoted[24..40], &quoted[48..64]);
        let dispatch = icmp(
            &mut a,
            now + 1,
            &icmp_error(local.ip(), &quoted, (2, 0), 1400),
        );
        assert!(
            matches!(
                dispatch,
                Ok(IcmpDispatch::Completed(IcmpOutcome::Tcp {
                    report: TcpReport::PacketTooBig(PmtuFeedback::Decreased { mtu: 1400 }),
                    published: Some(path::EstimateChange::Decreased),
                    ..
                }))
            ),
            "Segments Left {left}: {dispatch:?}"
        );
        assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), Some(1400));
        assert_eq!(a.0.paths().path_snapshot(path).unwrap().ip_packet_budget(), Ok(1400));
        assert_eq!(a.0.paths().path_snapshot(other_path).unwrap().learned_mtu(), None);
        assert_eq!(a.0.paths().path_snapshot(other_path).unwrap().ip_packet_budget(), Ok(1500));
        let q = 1400 - H - 20 - 12;
        assert_eq!(a.1.transport_ceilings(id).unwrap().effective_mss, q);
        // The dropped range is exact repair work: its first 1400-octet
        // segment leaves at once, before any timer; RFC 1191 6.4's restart
        // admits the rest, exactly the remaining range, after ACK progress.
        // The ordinary connection's SYN leaves extension-free toward S1,
        // where nothing answers.
        let ordinary = |frame: &[u8]| {
            let plain = frame[6] == 6;
            if plain {
                assert_eq!(&frame[24..40], &segments()[0].octets());
            }
            plain
        };
        let sequence = |frame: &[u8]| u32::from_be_bytes(frame[H + 4..H + 8].try_into().unwrap());
        let first = loop {
            let frame = emit_routed(&mut a, now + 2).unwrap();
            if !ordinary(&frame) {
                break frame;
            }
        };
        assert_routed_tcp(&first, local, remote);
        assert_eq!((sequence(&first), first.len()), (start, 1400));
        input(&mut b, now + 3, &arrive(&first)).unwrap();
        let tail = start.wrapping_add(q as u32);
        let mut repaired = Vec::new();
        let mut received = Vec::new();
        run(
            &mut a,
            &mut b,
            &mut now,
            |frame| {
                if ordinary(frame) {
                    return false;
                }
                assert_routed_tcp(frame, local, remote);
                assert!(frame.len() <= 1400);
                if sequence(frame) == tail {
                    repaired.push(frame.len() - H - 32);
                }
                true
            },
            |_, b| {
                read_all(b, child, &mut received);
                received.len() == admitted
            },
        );
        assert_eq!(repaired, [dropped.len() - H - 32 - q]);
        assert_eq!(received, payload[..admitted]);
    }
}

#[test]
fn tcp_probes_on_a_segment_route_count_h() {
    // The search starts below the first hop: PLPMTUD probes carry the SRH
    // and their submitted length, H included, is the size they prove.
    let mut cfg = config(4);
    cfg.connection.pmtud.as_mut().unwrap().initial_mtu = Some(1280);
    let (local, remote) = addresses(true);
    let mut a = tcp_side(local, 1722, cfg.clone(), false);
    segment_route(&mut a, remote.ip());
    let mut b = tcp_side(remote, 1723, cfg.clone(), false);
    let listener = b.1.listen(remote, 4).unwrap();
    let id =
        a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
    let mut now = 0;
    let child = establish(&mut a, &mut b, &mut now, id, listener, |frame| {
        assert_routed_tcp(frame, local, remote)
    });
    let start = a.1.path_mtu_info(id).unwrap().unwrap().current_mtu;
    assert!(start < 1500);
    assert_eq!(
        a.1.transport_ceilings(id).unwrap().effective_mss,
        start as usize - H - 20 - 12
    );
    let payload = vec![0x42; 60000];
    let admitted = a.1.write(id, &payload).unwrap();
    let mut largest = 0;
    let mut received = Vec::new();
    run(
        &mut a,
        &mut b,
        &mut now,
        |frame| {
            assert_routed_tcp(frame, local, remote);
            largest = largest.max(frame.len());
            true
        },
        |_, b| {
            read_all(b, child, &mut received);
            received.len() == admitted
        },
    );
    assert_eq!(received, payload[..admitted]);
    let grown = a.1.path_mtu_info(id).unwrap().unwrap().current_mtu;
    assert!(grown > start, "{grown} {start}");
    assert!(largest as u32 >= grown && largest <= 1500);
    assert_eq!(
        a.1.transport_ceilings(id).unwrap().effective_mss,
        grown as usize - H - 20 - 12
    );
}

#[test]
fn software_gso_on_a_segment_route_resplits_after_route_replacement() {
    let cfg = full_size_config();
    let (local, remote) = addresses(true);
    let mut a = tcp_side(local, 1724, cfg.clone(), true);
    let routed = segment_route(&mut a, remote.ip());
    let mut b = tcp_side(remote, 1725, cfg.clone(), false);
    let listener = b.1.listen(remote, 4).unwrap();
    let id =
        a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
    let mut now = 0;
    let child = establish(&mut a, &mut b, &mut now, id, listener, |_| {});
    let payload: Vec<u8> = (0..6000).map(|i| i as u8).collect();
    a.1.write(id, &payload).unwrap();
    now += 1000;
    // The first physical segment of the aggregate leaves with the SRH.
    let (first, context, frame) = routed_frame(&mut a, now).unwrap();
    let group = a.1.transmit_segmentation(first).unwrap();
    assert!(group.payload_len > group.segment_payload_len);
    assert_eq!(group.segment_payload_len, 1500 - H - 20 - 12);
    assert_routed_tcp(&frame, local, remote);
    assert_eq!(frame.len(), 1500);
    assert!(submit_frame(&mut a, now, context, &frame, 0) == Ok(Submission::Submitted));
    input(&mut b, now + 1, &arrive(&frame)).unwrap();
    // The next one is held while the owner replaces the SR route with an
    // ordinary one: its bytes are refused, nothing was submitted, and the
    // rest of the aggregate is cut again for the base header.
    let (held, context, frame) = routed_frame(&mut a, now + 2).unwrap();
    assert_routed_tcp(&frame, local, remote);
    let progress = a.1.send_progress(id).unwrap();
    let ordinary = route(&a, remote.ip());
    a.0.replace_route(routed, ordinary).unwrap();
    let refused = submit_frame(&mut a, now + 3, context, &frame, 0).unwrap_err();
    assert_eq!(refused.error, Error::Obsolete);
    a.0.cancel_submission(refused.ticket);
    assert_eq!(a.1.send_progress(id).unwrap(), progress);
    assert!(a.1.reject_unsubmitted(held).unwrap());
    let mut received = Vec::new();
    run(
        &mut a,
        &mut b,
        &mut now,
        |frame| {
            // Base header only, toward D, after the replacement.
            assert_eq!(frame[6], 6);
            assert_eq!(&frame[24..40], &v6(remote.ip()).octets());
            assert!(frame.len() <= 1500);
            true
        },
        |_, b| {
            read_all(b, child, &mut received);
            received.len() == payload.len()
        },
    );
    assert_eq!(received, payload);
    assert_eq!(a.1.managed_path(id).unwrap().ip_header_len, 40);
}

#[test]
fn shared_payload_on_a_segment_route_survives_would_block() {
    let cfg = full_size_config();
    let (local, remote) = addresses(true);
    let mut a = tcp_side(local, 1726, cfg.clone(), false);
    segment_route(&mut a, remote.ip());
    let mut b = tcp_side(remote, 1727, cfg.clone(), false);
    let listener = b.1.listen(remote, 4).unwrap();
    let id =
        a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
    let mut now = 0;
    let child = establish(&mut a, &mut b, &mut now, id, listener, |_| {});
    a.1.enable_shared_output(4).unwrap();
    a.1.write_shared(
        id,
        ntcp::Payload::from_vec(vec![7; 4000]),
        false,
        true,
        None,
    )
    .unwrap();
    let mut parts = Vec::with_capacity(4);
    let mut tcp = [0; 2048];
    let mut blocked = false;
    loop {
        now += 1000;
        let (poll, attempt) =
            a.1.poll_reserved_transmit_shared_for(now, id, &mut tcp, &mut parts, 32)
                .unwrap();
        let Some(packet) = poll.packet else {
            break;
        };
        let attempt = attempt.unwrap();
        let payload: usize = parts.iter().map(ntcp::Payload::len).sum();
        assert!(payload > 0);
        let header = packet.len - payload;
        let context = a.0.egress_context(&mut a.1, attempt).unwrap();
        let plan = a.0.header_plan(context.binding.snapshot.key()).unwrap();
        assert_eq!(plan.len, H);
        let mut frame = vec![0; H + header];
        frame[H..].copy_from_slice(&tcp[..header]);
        let n = ntcp_ip6::encode_tcp_routed(&mut frame, packet, plan.segments, header).unwrap();
        assert_eq!(n, frame.len());
        // The external payload is counted exactly once.
        assert_eq!(
            a.0.validate_egress(&mut a.1, context, &frame, payload * 2),
            Err(Error::Obsolete)
        );
        let mut ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
        if !blocked {
            // The backend would block: the same bytes are retried.
            blocked = true;
            match a
                .0
                .submit(&mut a.1, now, ticket, context, &frame, payload, |_| {
                    BackendOutcome::WouldBlock
                }) {
                Ok(Submission::Blocked(retained)) => ticket = retained,
                _ => panic!("not blocked"),
            }
        }
        let submitted =
            a.0.submit(&mut a.1, now, ticket, context, &frame, payload, |_| {
                BackendOutcome::Submitted
            });
        assert!(submitted == Ok(Submission::Submitted));
        a.0.collect(&mut a.1).unwrap();
        for part in &parts {
            frame.extend_from_slice(part.as_slice());
        }
        assert_routed_tcp(&frame, local, remote);
        input(&mut b, now + 1, &arrive(&frame)).unwrap();
    }
    assert!(blocked);
    let mut received = Vec::new();
    run(
        &mut a,
        &mut b,
        &mut now,
        |_| true,
        |_, b| {
            read_all(b, child, &mut received);
            received.len() == 4000
        },
    );
    assert_eq!(received, [7; 4000]);
}

#[test]
fn tcp_whose_header_no_longer_fits_fails_admission() {
    let cfg = full_size_config();
    let (local, remote) = addresses(true);
    // 90 segments: H = 40 + 8 + 16 * 91 = 1504 exceeds the first hop, so
    // no connection is created.
    let mut a = tcp_side(local, 1728, cfg.clone(), false);
    let r = route(&a, remote.ip());
    a.0.add_segment_route(r, &many_segments(90)).unwrap();
    assert!(
        a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
            .is_err()
    );
    assert_eq!(a.0.binding_count(), 0);
    // 80 segments: H = 1344 carries TCP at 1500 octets but not at 1280. An
    // owner's administrative value that the connection's header cannot fit
    // is refused with nothing changed (T12's read-only validation of every
    // TCP binding); a learned or link decrease fails the output instead.
    for change in [Change::PathMtu, Change::Administrative, Change::Link] {
        let mut a = tcp_side(local, 1729, cfg.clone(), false);
        let r = route(&a, remote.ip());
        a.0.add_segment_route(r, &many_segments(80)).unwrap();
        let id =
            a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
                .unwrap();
        assert_eq!(a.1.managed_path(id).unwrap().ip_header_len, 1344);
        let syn = emit_routed(&mut a, 1).unwrap();
        assert_eq!(syn[6], 43);
        assert!(syn.len() <= 1500);
        let path = a.0.binding(id).unwrap().snapshot.path();
        if let Change::Administrative = change {
            let capability = a.0.administration();
            assert_eq!(
                super::admin::set_estimate(&mut a, &capability, 2, path, Some(1280)),
                Err(Error::Endpoint(EndpointError::Connection(
                    ntcp::Error::InvalidArgument
                )))
            );
            assert_eq!(
                a.0.binding(id).unwrap().snapshot.ip_packet_budget(),
                Ok(1500)
            );
            continue;
        }
        lower(&mut a, 2, path, change);
        // The retransmitted SYN is neither cut nor sent over another route.
        let mut tcp = [0; 2048];
        let attempt = (1..100)
            .find_map(|step| {
                a.1.on_timeout(step * 100_000, 32).unwrap();
                let (poll, attempt) =
                    a.1.poll_reserved_transmit(step * 100_000, &mut tcp, 32)
                        .unwrap();
                poll.packet.and(attempt)
            })
            .unwrap();
        assert!(a.0.egress_context(&mut a.1, attempt).is_err(), "{change:?}");
    }
}

// A peer's timestamped SYN to `to`, where nothing listens.
fn closed_port_syn(from: SocketAddr, to: SocketAddr, identity: u64) -> Vec<u8> {
    let cfg = config(4);
    let mut peer = tcp_side(from, identity, cfg.clone(), false);
    peer.1
        .connect_with_path_provider(0, from, to, options(&cfg, 0), &mut peer.0)
        .unwrap();
    let syn = emit_routed(&mut peer, 1).unwrap();
    assert_eq!(syn[6], 6);
    assert!(syn.len() > 40 + 32, "the SYN carries a Timestamps option");
    syn
}

// A managed stateless reply is sized with the complete header of the path
// it leaves on. With 88 segments (H = 40 + 8 + 16 * 89 = 1472) the RST that
// answers a timestamped SYN to a closed port fits the 1500-octet first hop
// only without its timestamp echo; with 89 (H = 1488) not even its 20-octet
// TCP header fits, so it is dropped once and counted while other output
// continues; an ordinary path keeps the echo.
#[test]
fn stateless_replies_are_sized_with_the_path_header() {
    const BIG: usize = 1472;
    let cfg = config(4);
    let (local, remote) = addresses(true);
    let unfit: SocketAddr = "[2001:db8::3]:8080".parse().unwrap();
    let ordinary: SocketAddr = "[2001:db8::4]:8080".parse().unwrap();
    let mut a = tcp_side(local, 1760, cfg, false);
    let segments = many_segments(88);
    a.0.add_segment_route(route(&a, remote.ip()), &segments)
        .unwrap();
    a.0.add_segment_route(route(&a, unfit.ip()), &many_segments(89))
        .unwrap();
    input(&mut a, 2, &closed_port_syn(remote, local, 1761)).unwrap();
    let reply = emit_routed(&mut a, 3).unwrap();
    assert_eq!(reply.len(), BIG + 20);
    assert_eq!(reply[6], 43);
    assert_eq!(&reply[24..40], &segments[0].octets());
    assert_eq!(&reply[40..48], &[6, 2 * 89, 4, 88, 88, 0, 0, 0]);
    assert_eq!(&reply[48..64], &v6(remote.ip()).octets());
    assert_eq!(&reply[48 + 16 * 88..BIG], &segments[0].octets());
    let tcp = &reply[BIG..];
    assert_eq!(tcp[12] >> 4, 5, "no options: the echo is omitted");
    assert_eq!(tcp[13], ntcp::wire::RST | ntcp::wire::ACK);
    assert_eq!(
        ntcp_ip_common::pseudo_header_checksum(local.ip(), remote.ip(), 6, tcp),
        Ok(0)
    );
    assert_ne!(
        ntcp_ip_common::pseudo_header_checksum(local.ip(), IpAddr::V6(segments[0]), 6, tcp),
        Ok(0)
    );
    assert_eq!(a.1.oversized_control_replies(), 0);
    input(&mut a, 4, &closed_port_syn(unfit, local, 1762)).unwrap();
    input(&mut a, 5, &closed_port_syn(ordinary, local, 1763)).unwrap();
    let reply = emit_routed(&mut a, 6).unwrap();
    assert_eq!(reply[6], 6);
    assert_eq!(&reply[24..40], &v6(ordinary.ip()).octets());
    assert_eq!(reply.len(), 40 + 32, "the ordinary path keeps the echo");
    assert_eq!(a.1.oversized_control_replies(), 1);
    assert!(emit_routed(&mut a, 7).is_none());
    assert_eq!(a.1.oversized_control_replies(), 1);
}

// An administrative downward estimate reaches a binding on an SR path
// within `admin_apply`, as it reaches an ordinary binding: the SR
// connection's forwarding destination is S1 while its path key names D,
// and the transaction's fan-out compares the actual outgoing selection.
#[test]
fn admin_estimate_lowers_a_segment_route_binding_at_once() {
    let cfg = full_size_config();
    let (local, remote) = addresses(true);
    let mut a = tcp_side(local, 1940, cfg.clone(), false);
    segment_route(&mut a, remote.ip());
    let mut b = tcp_side(remote, 1941, cfg.clone(), false);
    let listener = b.1.listen(remote, 4).unwrap();
    let routed = a
        .1
        .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
        .unwrap();
    let mut now = 0;
    establish(&mut a, &mut b, &mut now, routed, listener, |_| {});
    let s1 = SocketAddr::new(IpAddr::V6(segments()[0]), remote.port());
    let ordinary = a
        .1
        .connect_with_path_provider(now, local, s1, options(&cfg, 0), &mut a.0)
        .unwrap();
    let capability = a.0.administration();
    for (id, header) in [(routed, H as u32), (ordinary, 40)] {
        let before = a.1.transport_ceilings(id).unwrap().effective_mss;
        let path = a.0.binding(id).unwrap().snapshot.path();
        assert_eq!(
            a.0.binding(id).unwrap().snapshot.ip_packet_budget(),
            Ok(1500)
        );
        super::admin::set_estimate(&mut a, &capability, now, path, Some(1400)).unwrap();
        let binding = a.0.binding(id).unwrap();
        assert!(!a.0.paths().is_dirty(binding.client).unwrap());
        assert_eq!(binding.snapshot.ip_packet_budget(), Ok(1400));
        assert_eq!(binding.snapshot.ip_header_len(), header);
        assert_eq!(a.1.transport_ceilings(id).unwrap().effective_mss, before - 100);
    }
}

// A stateless reply queued before its route is replaced is sized for the
// route selected when it drains: an ordinary route replaced by an 88-segment
// SR route (H = 1472) drops the timestamp echo the queued sizing included,
// which would no longer fit the 1500-octet first hop; an 89-segment SR route
// (H = 1488, no room for the 20-octet TCP header) replaced by an ordinary
// route sends the reply with its echo rather than dropping it as oversized.
#[test]
fn stateless_replies_are_sized_for_the_route_replaced_before_drain() {
    const BIG: usize = 1472;
    let cfg = config(4);
    let (local, remote) = addresses(true);
    let mut a = tcp_side(local, 1770, cfg, false);
    let ordinary = a.0.add_route(route(&a, remote.ip())).unwrap();
    input(&mut a, 2, &closed_port_syn(remote, local, 1771)).unwrap();
    a.0.remove_route(ordinary).unwrap();
    let segments = many_segments(88);
    let routed = a
        .0
        .add_segment_route(route(&a, remote.ip()), &segments)
        .unwrap();
    let reply = emit_routed(&mut a, 3).unwrap();
    assert_eq!(reply.len(), BIG + 20);
    assert_eq!(&reply[40..48], &[6, 2 * 89, 4, 88, 88, 0, 0, 0]);
    let tcp = &reply[BIG..];
    assert_eq!(tcp[12] >> 4, 5, "no options: the echo is omitted");
    assert_eq!(tcp[13], ntcp::wire::RST | ntcp::wire::ACK);
    assert_eq!(
        ntcp_ip_common::pseudo_header_checksum(local.ip(), remote.ip(), 6, tcp),
        Ok(0)
    );
    a.0.remove_route(routed).unwrap();
    let unfit = a
        .0
        .add_segment_route(route(&a, remote.ip()), &many_segments(89))
        .unwrap();
    input(&mut a, 4, &closed_port_syn(remote, local, 1772)).unwrap();
    a.0.replace_route(unfit, route(&a, remote.ip())).unwrap();
    let reply = emit_routed(&mut a, 5).unwrap();
    assert_eq!(reply[6], 6);
    assert_eq!(&reply[24..40], &v6(remote.ip()).octets());
    assert_eq!(reply.len(), 40 + 32, "the ordinary route keeps the echo");
    assert_eq!(a.1.oversized_control_replies(), 0);
    assert!(emit_routed(&mut a, 6).is_none());
}
