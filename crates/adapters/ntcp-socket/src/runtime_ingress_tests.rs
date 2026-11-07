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
// Echo Reply carries them recorded once with this host's address and one
// sample of the characterized UTC source: a standard value within the
// test's own kernel clock bracket, or the owner's elapsed time marked
// nonstandard by the high-order bit. It refuses source routes at the
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
    let before = super::utc_read();
    deliver(&mut a, &wire, &[frame]);
    let after = super::utc_read();
    assert_eq!(a.ipv4_clock.acquisitions, 1);
    a.service_egress().unwrap();
    let frames: Vec<_> = wire.lock().unwrap().sent.drain(..).collect();
    assert_eq!(frames.len(), 1);
    let ip = ntcp_ethernet::parse_ethernet(&frames[0]).unwrap().payload;
    assert_eq!(ip[0], 0x45 + 5);
    assert_eq!(&ip[20..23], &[7, 7, 8]);
    assert_eq!(&ip[23..27], &local.octets());
    assert_eq!(&ip[27..31], &[68, 12, 9, 0]);
    let time = u32::from_be_bytes(ip[31..35].try_into().unwrap());
    if !super::standard_time(time, before, after) {
        assert_eq!(time, 0x8000_0000 | (a.now() / 1000) as u32);
    }
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
    // authorization could count it or recording could sample time; the
    // reply's output sampled nothing either.
    let host = a.host.as_ref().unwrap();
    let counters = host.icmp_output_counters();
    assert_eq!(
        (counters.echo_replies, counters.unauthorized_routes),
        (1, 0)
    );
    assert_eq!(host.icmp_output_pending(), 0);
    assert_eq!(a.ipv4_clock.acquisitions, 1);
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

// `packet` (IPv6, extension-free) with one Destination Options header
// holding `options` (padded with Pad1) after its base header.
fn with_destination_options(packet: &[u8], options: &[u8]) -> Vec<u8> {
    let mut header = vec![packet[6], 0];
    header.extend_from_slice(options);
    header.resize(header.len().div_ceil(8) * 8, 0);
    header[1] = (header.len() / 8 - 1) as u8;
    let mut ip = packet[..40].to_vec();
    ip.extend_from_slice(&header);
    ip.extend_from_slice(&packet[40..]);
    ip[6] = 60;
    let payload = (ip.len() - 40) as u16;
    ip[4..6].copy_from_slice(&payload.to_be_bytes());
    ip
}

// Native Ethernet framing delimits IPv6 by its base header alone: a
// complete packet whose Destination Options the Host refuses reaches Host
// receive processing and its Parameter Problem (RFC 8200 section 4.2,
// RFC 4443 section 3.4), including the code 2 exception for a link-layer
// group destination (RFC 4443 section 2.4(e.3)); physical truncation is
// dropped by the framing, and an option-bearing request is answered.
#[test]
fn native_ethernet_ingress_passes_refused_extension_chains_to_host_errors() {
    let (mut a, wire) = native(true, 2, 2);
    let to_us = ntcp::IpMetadata {
        source: peer(true),
        destination: a.local,
    };
    let request = echo_request(to_us, &[5; 16]);
    let report = with_destination_options(&request, &[0x9e, 0]);
    let unless = with_destination_options(&request, &[0xde, 0]);
    let problems = |a: &mut Owner, frame: Vec<u8>| {
        deliver(a, &wire, &[frame]);
        a.service_egress().unwrap();
        sent_icmp(&wire)
            .into_iter()
            .map(|(outer, message)| {
                assert_eq!(
                    outer,
                    ntcp::IpMetadata {
                        source: a.local,
                        destination: peer(true)
                    }
                );
                let pointer = u32::from_be_bytes(message[4..8].try_into().unwrap());
                (message[0], message[1], pointer, message[8..].to_vec())
            })
            .collect::<Vec<_>>()
    };
    let sent = problems(&mut a, ethernet(UNICAST, true, &unless));
    assert_eq!(sent.len(), 1);
    assert_eq!(&sent[0].3[..], &unless[..]);
    assert_eq!((sent[0].0, sent[0].1, sent[0].2), (4, 2, 42));
    assert!(problems(&mut a, ethernet(BROADCAST, true, &unless)).is_empty());
    let sent = problems(&mut a, ethernet(BROADCAST, true, &report));
    assert_eq!(
        sent.iter().map(|p| (p.0, p.1, p.2)).collect::<Vec<_>>(),
        [(4, 2, 42)]
    );
    // One octet short of its Payload Length: dropped by framing.
    let mut short = ethernet(UNICAST, true, &unless);
    short.truncate(14 + unless.len() - 1);
    assert!(problems(&mut a, short).is_empty());
    // Pad options only: the Echo Request is answered.
    let padded = with_destination_options(&request, &[1, 2, 0, 0]);
    let sent = problems(&mut a, ethernet(UNICAST, true, &padded));
    assert_eq!(sent.len(), 1);
    assert_eq!((sent[0].0, &sent[0].3[..]), (129, &request[48..]));
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
// RFC 8200's 1500-octet reassembly guarantee: fragments drawn on the kernel
// CSPRNG's unpredictable Identification from startup on, drained through
// the same port.
#[test]
fn native_fragmented_echo_replies_draw_unpredictable_identifiers() {
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

// Over an owner-configured SR route (`ipv6.srh.*`) the native drain sends
// Echo Replies, whole and source-fragmented, and Host Parameter Problems
// with the route's Segment Routing Header: base Destination Address S1,
// the full segment list with the final destination D in Segment List[0],
// and ICMPv6 checksums computed with D. An error is cut to 1280 octets.
#[test]
fn native_icmp_output_over_a_segment_route_carries_the_srh() {
    let local: IpAddr = "2001:db8::2".parse().unwrap();
    let segments: Vec<std::net::Ipv6Addr> =
        vec!["2001:db8:5::1".parse().unwrap(), "2001:db8:6::1".parse().unwrap()];
    let mut config = SocketConfig::new("external", local);
    config.io.prefix = Some(64);
    config.tcp.connection.timestamps = false;
    config.segment_routes = vec![crate::SegmentRoute {
        destination: path::IpPrefix::new(peer(true), 128).unwrap(),
        segments: segments.clone(),
    }];
    let wire = Arc::new(Mutex::new(State {
        mtu: Some(1500),
        max_packet_len: Some(2048),
        ..Default::default()
    }));
    let mut a = Owner::external_backend(
        &config,
        crate::EthernetPacketIo {
            io: Box::new(Fixture(wire.clone())),
            local_mac: [2; 6],
            next_hop_mac: Some([4; 6]),
        },
    )
    .unwrap();
    a.test_now = Some(1000);
    let std::net::IpAddr::V6(d) = peer(true) else {
        unreachable!()
    };
    let h = 40 + 8 + 16 * 3;
    let reply_ip = ntcp::IpMetadata {
        source: local,
        destination: peer(true),
    };
    let to_us = ntcp::IpMetadata {
        source: peer(true),
        destination: local,
    };
    let sent = |wire: &Arc<Mutex<State>>| -> Vec<Vec<u8>> {
        let frames: Vec<_> = wire.lock().unwrap().sent.drain(..).collect();
        frames
            .iter()
            .map(|frame| {
                // Ethernet framing by hand: the link parser passes only the
                // base layout.
                assert_eq!((&frame[..6], &frame[6..12]), (&[4; 6][..], &[2; 6][..]));
                assert_eq!(&frame[12..14], &[0x86, 0xdd]);
                let ip = &frame[14..];
                let len = 40 + usize::from(u16::from_be_bytes([ip[4], ip[5]]));
                let ip = &ip[..len];
                assert_eq!(ip[6], 43);
                assert_eq!(&ip[24..40], &segments[0].octets());
                assert_eq!(&ip[42..44], &[4, 2]);
                assert_eq!((ip[41], ip[44]), (6, 2));
                assert_eq!(&ip[48..64], &d.octets());
                assert_eq!(&ip[64..80], &segments[1].octets());
                assert_eq!(&ip[80..96], &segments[0].octets());
                ip.to_vec()
            })
            .collect()
    };
    // A whole reply within the connectionless size.
    let data: Vec<u8> = (0..1000).map(|n| (n * 7) as u8).collect();
    deliver(&mut a, &wire, &[ethernet(UNICAST, true, &echo_request(to_us, &data))]);
    a.service_egress().unwrap();
    let packets = sent(&wire);
    assert_eq!(packets.len(), 1);
    assert_eq!((packets[0].len(), packets[0][40]), (h + 8 + 1000, 58));
    let reply = ntcp_icmp::decode_echo(reply_ip, &packets[0][h..]).unwrap();
    assert_eq!((reply.kind, reply.data), (ntcp_icmp::EchoKind::Reply, &data[..]));
    // A larger one leaves as fragments that repeat the SRH.
    let data: Vec<u8> = (0..1300).map(|n| (n * 3) as u8).collect();
    deliver(&mut a, &wire, &[ethernet(UNICAST, true, &echo_request(to_us, &data))]);
    a.test_now = Some(200_000_000);
    a.service_egress().unwrap();
    let mut packets = sent(&wire);
    // The fragmented reply is the Echo adjunct's demand for the SR path:
    // its probe, an Echo Request carrying the SRH, follows the fragments.
    let probe = packets.pop().unwrap();
    assert_eq!((probe[40], probe[h]), (58, 128));
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].len(), 1280);
    let mut message = Vec::new();
    for packet in &packets {
        assert_eq!(packet[40], 44);
        message.extend_from_slice(&packet[h + 8..]);
    }
    let reply = ntcp_icmp::decode_echo(reply_ip, &message).unwrap();
    assert_eq!(reply.data, &data[..]);
    // A Parameter Problem for an unknown option (action 10).
    let mut request = echo_request(to_us, &[5; 1300]);
    let payload = u16::from_be_bytes([request[4], request[5]]) + 8;
    request.splice(40..40, [58, 0, 0x9e, 0, 1, 2, 0, 0]);
    request[6] = 60;
    request[4..6].copy_from_slice(&payload.to_be_bytes());
    deliver(&mut a, &wire, &[ethernet(UNICAST, true, &request)]);
    a.service_egress().unwrap();
    let packets = sent(&wire);
    assert_eq!(packets.len(), 1);
    let error = &packets[0];
    assert_eq!((error.len(), error[40]), (1280, 58));
    assert_eq!((error[h], error[h + 1]), (4, 2));
    assert_eq!(&error[h + 4..h + 8], &42u32.to_be_bytes());
    assert_eq!(ntcp_icmp::icmpv6_checksum(reply_ip, &error[h..]), Ok(0));
    assert_eq!(&error[h + 8..], &request[..1280 - h - 8]);
}
