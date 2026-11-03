// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// Native Ethernet ingress through the Host pipeline: link-layer destination
// classification, reassembly before classification and retention, the Echo
// service and the Host ICMP output drain.
use super::*;

const UNICAST: [u8; 6] = [2; 6];
const BROADCAST: [u8; 6] = [0xff; 6];

fn peer(v6: bool) -> IpAddr {
    if v6 { "2001:db8::9" } else { "10.73.0.9" }
        .parse()
        .unwrap()
}

fn ethernet(destination: [u8; 6], v6: bool, packet: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; 14 + packet.len()];
    frame[..6].copy_from_slice(&destination);
    frame[6..12].copy_from_slice(&[4; 6]);
    frame[12..14].copy_from_slice(&if v6 { 0x86ddu16 } else { 0x0800 }.to_be_bytes());
    frame[14..].copy_from_slice(packet);
    frame.resize(frame.len().max(60), 0);
    frame
}

fn complete(ip: ntcp::IpMetadata, protocol: u8, data: &[u8]) -> Vec<u8> {
    let v6 = ip.source.is_ipv6();
    let header = if v6 { 40 } else { 20 };
    let mut packet = vec![0; header + data.len()];
    packet[header..].copy_from_slice(data);
    let n = if v6 {
        let h = ntcp_ip6::Header {
            ip,
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
        };
        ntcp_ip6::encode_datagram(&mut packet, h, protocol, data.len()).unwrap()
    } else {
        let h = ntcp_ip::Header {
            ip,
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
            ipv4_options: Default::default(),
        };
        ntcp_ip::encode_datagram(&mut packet, h, protocol, data.len(), 0).unwrap()
    };
    packet.truncate(n);
    packet
}

// A peer's source fragments of an option-free datagram, `chunk` octets each.
fn fragments(packet: &[u8], identification: u32, chunk: usize) -> Vec<Vec<u8>> {
    let v6 = packet[0] >> 4 == 6;
    let (ip, protocol, data) = if v6 {
        let p = ntcp_ip6::parse(packet).unwrap();
        (p.ip, p.protocol, p.payload)
    } else {
        let p = ntcp_ip::parse(packet, false).unwrap();
        (p.ip, p.protocol, p.payload)
    };
    (0..data.len())
        .step_by(chunk)
        .map(|offset| {
            let piece = &data[offset..data.len().min(offset + chunk)];
            let mut out = vec![0; 64 + piece.len()];
            let n = if v6 {
                let h = ntcp_ip6::Header {
                    ip,
                    hop_limit: 64,
                    dscp: 0,
                    ecn: 0,
                };
                ntcp_ip6::Fragmenter::new(h, protocol, identification, data.len())
                    .unwrap()
                    .encode(&mut out, offset, piece)
                    .unwrap()
            } else {
                let h = ntcp_ip::Header {
                    ip,
                    hop_limit: 64,
                    dscp: 0,
                    ecn: 0,
                    ipv4_options: Default::default(),
                };
                ntcp_ip::Fragmenter::new(h, protocol, identification as u16, data.len(), 0)
                    .unwrap()
                    .encode(&mut out, offset, piece)
                    .unwrap()
            };
            out.truncate(n);
            out
        })
        .collect()
}

fn echo_request(ip: ntcp::IpMetadata, data: &[u8]) -> Vec<u8> {
    let mut message = vec![0; 8 + data.len()];
    message[8..].copy_from_slice(data);
    let n = ntcp_icmp::encode_echo(
        ip,
        ntcp_icmp::EchoKind::Request,
        0x7a7a,
        3,
        &mut message,
        data.len(),
    )
    .unwrap();
    complete(ip, if ip.source.is_ipv4() { 1 } else { 58 }, &message[..n])
}

fn deliver(owner: &mut Owner, wire: &Arc<Mutex<State>>, frames: &[Vec<u8>]) {
    wire.lock()
        .unwrap()
        .incoming
        .extend(frames.iter().cloned().map(Ok));
    owner.receive_batch(&mut vec![0; 65535 + 14]).unwrap();
    owner.events();
}

// ICMP messages the owner sent: (outer addresses, ICMP message).
fn sent_icmp(wire: &Arc<Mutex<State>>) -> Vec<(ntcp::IpMetadata, Vec<u8>)> {
    let frames: Vec<_> = wire.lock().unwrap().sent.drain(..).collect();
    frames
        .iter()
        .filter_map(|frame| {
            let eth = ntcp_ethernet::parse_ethernet(frame).unwrap();
            assert_eq!((eth.destination, eth.source), ([4; 6], [2; 6]));
            if eth.payload[0] >> 4 == 6 {
                let p = ntcp_ip6::parse(eth.payload).unwrap();
                (p.protocol == 58).then(|| (p.ip, p.payload.to_vec()))
            } else {
                let p = ntcp_ip::parse(eth.payload, false).unwrap();
                assert_eq!(eth.payload[6] & 0x40, 0x40, "IPv4 output keeps DF");
                (p.protocol == 1).then(|| (p.ip, p.payload.to_vec()))
            }
        })
        .collect()
}

#[test]
fn native_fragmented_echo_requests_are_reassembled_and_answered_exactly() {
    for v6 in [false, true] {
        let (mut a, wire) = native(v6, 2, 2);
        let to_us = ntcp::IpMetadata {
            source: peer(v6),
            destination: a.local,
        };
        let data: Vec<u8> = (0..1000).map(|n| (n * 7) as u8).collect();
        let request = echo_request(to_us, &data);
        let frames: Vec<_> = fragments(&request, 41, 504)
            .iter()
            .rev()
            .map(|piece| ethernet(UNICAST, v6, piece))
            .collect();
        assert_eq!(frames.len(), 2);
        deliver(&mut a, &wire, &frames);
        assert_eq!(a.host.as_ref().unwrap().reassembly_counters().completed, 1);
        assert_eq!(a.host.as_ref().unwrap().icmp_output_pending(), 1);
        a.service_egress().unwrap();
        let sent = sent_icmp(&wire);
        assert_eq!(sent.len(), 1);
        let (outer, message) = &sent[0];
        assert_eq!(
            *outer,
            ntcp::IpMetadata {
                source: a.local,
                destination: peer(v6)
            }
        );
        let reply = ntcp_icmp::decode_echo(*outer, message).unwrap();
        assert_eq!(
            (reply.kind, reply.identifier, reply.sequence, reply.data),
            (ntcp_icmp::EchoKind::Reply, 0x7a7a, 3, &data[..])
        );
        // An unfragmented request is answered by the same service.
        deliver(
            &mut a,
            &wire,
            &[ethernet(UNICAST, v6, &echo_request(to_us, &[1; 8]))],
        );
        a.service_egress().unwrap();
        assert_eq!(sent_icmp(&wire).len(), 1);
        assert_eq!(
            a.host.as_ref().unwrap().icmp_output_counters().echo_replies,
            2
        );
    }
}

// `packet` (IPv4, option-free) with `options` (whole words) after its base
// header.
fn with_ipv4_options(packet: &[u8], options: &[u8]) -> Vec<u8> {
    let mut ip = packet.to_vec();
    ip.splice(20..20, options.iter().copied());
    ip[0] = 0x45 + (options.len() / 4) as u8;
    let len = ip.len() as u16;
    ip[2..4].copy_from_slice(&len.to_be_bytes());
    ip[10..12].fill(0);
    let checksum = ntcp_ip_common::checksum(&ip[..20 + options.len()]);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    ip
}

// The native managed profile interprets Record Route and Timestamp: the
// Echo Reply carries them recorded once with this host's address and the
// owner's high-bit-marked elapsed time. It refuses source routes at the
// Host (the Echo service is not gated by TCP's option setting), so a
// routed request draws no reply.
#[test]
fn native_echo_replies_carry_recorded_options_and_routed_requests_are_refused() {
    let (mut a, wire) = native(false, 2, 2);
    let IpAddr::V4(local) = a.local else {
        unreachable!()
    };
    let to_us = ntcp::IpMetadata {
        source: peer(false),
        destination: a.local,
    };
    let request = echo_request(to_us, &[3; 32]);
    // RR and TS (flag 0), one free slot each and two for TS, EOL-padded.
    let options = [7, 7, 4, 0, 0, 0, 0, 68, 12, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let frame = ethernet(UNICAST, false, &with_ipv4_options(&request, &options));
    deliver(&mut a, &wire, &[frame]);
    a.service_egress().unwrap();
    let frames: Vec<_> = wire.lock().unwrap().sent.drain(..).collect();
    assert_eq!(frames.len(), 1);
    let ip = ntcp_ethernet::parse_ethernet(&frames[0]).unwrap().payload;
    assert_eq!(ip[0], 0x45 + 5);
    assert_eq!(&ip[20..23], &[7, 7, 8]);
    assert_eq!(&ip[23..27], &local.octets());
    assert_eq!(&ip[27..31], &[68, 12, 9, 0]);
    let time = u32::from_be_bytes(ip[31..35].try_into().unwrap());
    assert_ne!(time & 0x8000_0000, 0, "nonstandard time is marked");
    assert_eq!(&ip[35..40], &[0; 5]);
    let reply = ntcp_icmp::decode_echo(
        ntcp::IpMetadata {
            source: a.local,
            destination: peer(false),
        },
        &ip[40..],
    )
    .unwrap();
    assert_eq!(
        (reply.kind, reply.data),
        (ntcp_icmp::EchoKind::Reply, &[3; 32][..])
    );
    // A completed loose source route ahead of the same options.
    let mut routed = vec![131, 7, 8, 192, 0, 2, 9];
    routed.extend_from_slice(&options[..19]);
    routed.resize(28, 0);
    let frame = ethernet(UNICAST, false, &with_ipv4_options(&request, &routed));
    deliver(&mut a, &wire, &[frame]);
    a.service_egress().unwrap();
    assert!(sent_icmp(&wire).is_empty());
    // Refused on arrival, before the Echo service's return-route
    // authorization could count it.
    let host = a.host.as_ref().unwrap();
    let counters = host.icmp_output_counters();
    assert_eq!(
        (counters.echo_replies, counters.unauthorized_routes),
        (1, 0)
    );
    assert_eq!(host.icmp_output_pending(), 0);
}

#[test]
fn native_reassembly_errors_respect_link_layer_group_destinations() {
    for v6 in [false, true] {
        let (mut a, wire) = native(v6, 2, 2);
        let to_us = ntcp::IpMetadata {
            source: peer(v6),
            destination: a.local,
        };
        let request = echo_request(to_us, &[5; 1000]);
        // Fragment zero of two datagrams: one arrived as a link-layer
        // broadcast, the other by unicast. Both expire without traffic.
        let zero = |id| fragments(&request, id, 504).remove(0);
        deliver(&mut a, &wire, &[ethernet(BROADCAST, v6, &zero(51))]);
        deliver(&mut a, &wire, &[ethernet(UNICAST, v6, &zero(52))]);
        a.service_egress().unwrap();
        assert!(sent_icmp(&wire).is_empty());
        let second = a.endpoint.caller_timebase().units_per_second;
        a.test_now = Some(1000 + 61 * second);
        a.service_egress().unwrap();
        assert_eq!(a.host.as_ref().unwrap().reassembly_counters().expired, 2);
        let sent = sent_icmp(&wire);
        assert_eq!(sent.len(), 1, "no error about the broadcast arrival");
        let (outer, message) = &sent[0];
        assert_eq!(outer.destination, peer(v6));
        assert_eq!(&message[..2], if v6 { [3, 1] } else { [11, 1] });
        let quoted = zero(52);
        assert_eq!(&message[8..8 + quoted.len()], &quoted[..]);
    }
}

#[test]
fn native_fragmented_tcp_is_delivered_and_retained_only_when_complete() {
    for v6 in [false, true] {
        let (mut a, wa) = native(v6, 2, 2);
        let (mut b, wb) = native(v6, 3, 2);
        let listen = listener(&mut b);
        let client = new(&mut a, SOCK_NONBLOCK);
        let remote = SocketAddr::new(b.local, 8080);
        assert_eq!(
            a.execute(client, Op::Connect(remote)).unwrap_err(),
            EINPROGRESS
        );
        exchange(&mut a, &mut b, &wa, &wb);
        let server = b.execute(listen, Op::Accept(SOCK_NONBLOCK)).unwrap().value as u64;
        b.execute(server, Op::Write(vec![0x42; 900])).unwrap();
        b.service_egress().unwrap();
        let segment: Vec<_> = wb.lock().unwrap().sent.drain(..).collect();
        assert_eq!(segment.len(), 1);
        let ip = ntcp_ethernet::parse_ethernet(&segment[0])
            .unwrap()
            .payload
            .to_vec();
        let ip = &ip[..if v6 {
            40 + usize::from(u16::from_be_bytes([ip[4], ip[5]]))
        } else {
            usize::from(u16::from_be_bytes([ip[2], ip[3]]))
        }];
        // Reserve the client's output: its selected frame is held by a
        // blocked backend, so complete input for it is retained.
        a.execute(client, Op::Write(vec![1; 100])).unwrap();
        wa.lock().unwrap().block = true;
        a.service_egress().unwrap();
        let id = connection(&a, client);
        assert!(a.endpoint.is_output_reserved(id));
        let pieces = fragments(ip, 61, 256);
        let frames: Vec<_> = pieces.iter().map(|p| ethernet(UNICAST, v6, p)).collect();
        deliver(&mut a, &wa, &frames[..frames.len() - 1]);
        assert!(
            !a.egress.as_ref().unwrap().retained_rx(id),
            "fragments are never retained"
        );
        deliver(&mut a, &wa, &frames[frames.len() - 1..]);
        assert!(a.egress.as_ref().unwrap().retained_rx(id));
        // The reservation resolves; the retained complete segment is delivered.
        wa.lock().unwrap().block = false;
        // The held frame's retry is paced: advance past it.
        a.test_now = Some(a.now() + 2000);
        a.service_egress().unwrap();
        assert!(!a.endpoint.is_output_reserved(id));
        a.receive_batch(&mut vec![0; 65535 + 14]).unwrap();
        a.events();
        assert!(!a.egress.as_ref().unwrap().retained_rx(id));
        assert_eq!(
            a.execute(client, Op::Read(2000)).unwrap().bytes,
            vec![0x42; 900]
        );
        assert_eq!(a.host.as_ref().unwrap().reassembly_counters().completed, 1);
    }
}

// An IPv6 Echo Reply beyond the 1280 link needs source fragments, within
// RFC 8200's 1500-octet reassembly guarantee: none until one maximum
// datagram lifetime after start (no identifier can be issued; the reply is
// counted unsent), then fragments drawn on the kernel CSPRNG's
// unpredictable Identification, drained through the same port.
#[test]
fn native_fragmented_echo_replies_wait_for_the_identifier_quiet_period() {
    let (mut a, wire) = native(true, 2, 2);
    let to_us = ntcp::IpMetadata {
        source: peer(true),
        destination: a.local,
    };
    let data: Vec<u8> = (0..1400).map(|n| (n * 3) as u8).collect();
    let request = echo_request(to_us, &data);
    let frames = |id| -> Vec<Vec<u8>> {
        fragments(&request, id, 1200)
            .iter()
            .map(|piece| ethernet(UNICAST, true, piece))
            .collect()
    };
    deliver(&mut a, &wire, &frames(71));
    a.service_egress().unwrap();
    assert!(wire.lock().unwrap().sent.is_empty());
    assert_eq!(a.host.as_ref().unwrap().icmp_output_counters().unsent, 1);
    a.test_now = Some(121_000_000);
    deliver(&mut a, &wire, &frames(72));
    a.service_egress().unwrap();
    let sent: Vec<_> = wire.lock().unwrap().sent.drain(..).collect();
    assert_eq!(sent.len(), 2);
    let mut message = Vec::new();
    let mut identifiers = Vec::new();
    for frame in &sent {
        // The Ethernet parser hands only atomic packets up; fragments are
        // read raw after the 14-octet header.
        assert_eq!(frame[12..14], 0x86ddu16.to_be_bytes());
        let payload = &frame[14..];
        let fragment = ntcp_ip6::parse_fragment(payload).unwrap();
        assert!(payload.len() <= 1280);
        let header = fragment.fragment.unwrap();
        assert_eq!(usize::from(header.offset), message.len());
        identifiers.push(header.identification);
        message.extend_from_slice(fragment.payload);
    }
    assert_eq!(identifiers[0], identifiers[1]);
    let outer = ntcp::IpMetadata {
        source: a.local,
        destination: peer(true),
    };
    let reply = ntcp_icmp::decode_echo(outer, &message).unwrap();
    assert_eq!(
        (reply.kind, reply.identifier, reply.sequence, reply.data),
        (ntcp_icmp::EchoKind::Reply, 0x7a7a, 3, &data[..])
    );
}
