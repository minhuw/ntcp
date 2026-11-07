// Fragmented input through the same TunHost constructor, input_frame
// dispatcher, retention queue and ICMP output drain as run().
use super::*;

fn complete(ip: IpMetadata, protocol: u8, data: &[u8]) -> Vec<u8> {
    let v6 = ip.source.is_ipv6();
    let header = if v6 { IPV6_HEADER } else { IP_HEADER };
    let mut packet = vec![0; header + data.len()];
    packet[header..].copy_from_slice(data);
    let n = if v6 {
        let h = ntcp_ip6::Header { ip, hop_limit: 64, dscp: 0, ecn: 0 };
        ntcp_ip6::encode_datagram(&mut packet, h, protocol, data.len()).unwrap()
    } else {
        let h = ntcp_ip::Header {
            ip, hop_limit: 64, dscp: 0, ecn: 0, ipv4_options: Default::default(),
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
                let h = ntcp_ip6::Header { ip, hop_limit: 64, dscp: 0, ecn: 0 };
                ntcp_ip6::Fragmenter::new(h, protocol, identification, data.len())
                    .unwrap()
                    .encode(&mut out, offset, piece)
                    .unwrap()
            } else {
                let h = ntcp_ip::Header {
                    ip, hop_limit: 64, dscp: 0, ecn: 0, ipv4_options: Default::default(),
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

fn udp_request(from: SocketAddr, to: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut message = vec![0; 8 + payload.len()];
    message[8..].copy_from_slice(payload);
    let n = ntcp_ip_common::encode_udp(from.ip(), to.ip(), from.port(), to.port(),
        &mut message, payload.len()).unwrap();
    let ip = IpMetadata { source: from.ip(), destination: to.ip() };
    complete(ip, 17, &message[..n])
}

fn echo_request(ip: IpMetadata, identifier: u16, sequence: u16, data: &[u8]) -> Vec<u8> {
    let mut message = vec![0; 8 + data.len()];
    message[8..].copy_from_slice(data);
    let n = ntcp_icmp::encode_echo(ip, ntcp_icmp::EchoKind::Request, identifier, sequence,
        &mut message, data.len()).unwrap();
    complete(ip, if ip.source.is_ipv4() { 1 } else { 58 }, &message[..n])
}

#[test]
fn fragmented_udp_and_echo_requests_are_reassembled_and_answered() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let (a, mut ahost) = endpoint(local.ip(), true);
        let mut a = a;
        let service = SocketAddr::new(local.ip(), 7);
        let config = runtime_config(&Backend::default(), local.ip(), true, true, false).unwrap();
        // Its evidence is the whole-reply refusal: Refuse mode.
        let mut echo = UdpEcho::open(&mut ahost, &a, service, &config, &refuse_settings()).unwrap();
        let capacity = ahost.host.reassembly_capacity(v6).unwrap();
        assert_eq!(capacity.emtu_r as usize, if v6 { 65575 } else { 65535 });
        let mut backend = Backend::default();
        let header = if v6 { IPV6_HEADER } else { IP_HEADER };

        // A request the peer fragmented whose reply fits unfragmented.
        let payload: Vec<u8> = (0..1000).map(|n| (n * 3) as u8).collect();
        let request = udp_request(remote, service, &payload);
        for piece in fragments(&request, 77, 504).iter().rev() {
            assert!(piece.len() < request.len());
            input_frame(&mut ahost, &mut a, 1, piece, local.ip(), false, &mut Sample(0)).unwrap();
        }
        assert!(echo.drive(&mut ahost, &a, 1, &mut backend).unwrap());
        assert_eq!(backend.frames.len(), 1);
        let reply = backend.frames.pop().unwrap();
        assert_eq!(reply.len(), header + 8 + payload.len());
        assert_eq!(&reply[header + 8..], &payload[..]);

        // A request larger than one TUN packet arrives whole; in Refuse mode
        // replies are sent unfragmented only, so this one is refused, not
        // split.
        let large: Vec<u8> = (0..3000).map(|n| (n * 5) as u8).collect();
        for piece in fragments(&udp_request(remote, service, &large), 78, 1400) {
            input_frame(&mut ahost, &mut a, 2, &piece, local.ip(), false, &mut Sample(0)).unwrap();
        }
        assert!(echo.drive(&mut ahost, &a, 2, &mut backend).unwrap());
        assert!(backend.frames.is_empty());
        let limit = MTU - header - 8;
        assert_eq!(echo.notes.last().unwrap(), &format!("UDP echo of 3000 octets to {remote} \
            refused: exceeds the path payload limit of {limit}; replies are never fragmented"));

        // An Echo Request the peer fragmented is answered exactly.
        let to_us = IpMetadata { source: remote.ip(), destination: local.ip() };
        let data: Vec<u8> = (0..1200).map(|n| (n * 11) as u8).collect();
        for piece in fragments(&echo_request(to_us, 0x5151, 9, &data), 79, 800) {
            input_frame(&mut ahost, &mut a, 3, &piece, local.ip(), false, &mut Sample(0)).unwrap();
        }
        assert_eq!(ahost.host.icmp_output_pending(), 1);
        let mut buffer = [0; MTU];
        assert!(ahost.icmp_output(3, &mut buffer, &mut backend).unwrap());
        assert_eq!(backend.frames.len(), 1);
        let reply = backend.frames.pop().unwrap();
        let (outer, message) = if v6 {
            let p = ntcp_ip6::parse(&reply).unwrap();
            (p.ip, p.payload)
        } else {
            let p = ntcp_ip::parse(&reply, false).unwrap();
            (p.ip, p.payload)
        };
        assert_eq!(outer, IpMetadata { source: local.ip(), destination: remote.ip() });
        let decoded = ntcp_icmp::decode_echo(outer, message).unwrap();
        assert_eq!((decoded.kind, decoded.identifier, decoded.sequence),
            (ntcp_icmp::EchoKind::Reply, 0x5151, 9));
        assert_eq!(decoded.data, &data[..]);

        // A blocked TUN keeps the reply queued for the next pass.
        input_frame(&mut ahost, &mut a, 4, &echo_request(to_us, 1, 1, &[7; 32]), local.ip(),
            false, &mut Sample(0)).unwrap();
        backend.blocked = true;
        assert!(!ahost.icmp_output(4, &mut buffer, &mut backend).unwrap());
        assert_eq!(ahost.host.icmp_output_pending(), 1);
        backend.blocked = false;
        assert!(ahost.icmp_output(5, &mut buffer, &mut backend).unwrap());
        assert_eq!(ahost.host.icmp_output_pending(), 0);
        println!("v6={v6}: fragmented UDP/Echo requests reassembled; 3000-octet reply refused");
    }
}

#[test]
fn reserved_owner_retains_the_completed_datagram_never_a_fragment() {
    for v6 in [false, true] {
        let mut p = Pair::new(v6, true);
        // Reserve a's output: its selected frame is held by a blocked TUN.
        p.a.write(p.aid, &[0x21; 2000]).unwrap();
        let mut backend = Backend { blocked: true, ..Default::default() };
        let mut output = [0; MTU];
        let mut pending = None;
        let h = if v6 { IPV6_HEADER } else { IP_HEADER };
        transmit_frames(&mut p.ahost, &mut p.a, p.time, &mut output, &mut pending, h, &mut Sample(0),
            &mut backend).unwrap();
        assert!(p.a.is_output_reserved(p.aid));
        // The peer's data segment arrives fragmented.
        p.b.write(p.bid, &[0x42; 1000]).unwrap();
        let frames = emit(&mut p.bhost, &mut p.b, p.time, p.remote.ip());
        assert_eq!(frames.len(), 1);
        let pieces = fragments(&frames[0], 5, 512);
        assert!(pieces.len() > 1);
        for piece in &pieces[1..] {
            input_frame(&mut p.ahost, &mut p.a, p.time, piece, p.local.ip(), false, &mut Sample(0)).unwrap();
            assert!(p.ahost.received.is_empty(), "a fragment is never retained");
        }
        input_frame(&mut p.ahost, &mut p.a, p.time, &pieces[0], p.local.ip(), false, &mut Sample(0)).unwrap();
        assert_eq!(p.ahost.received.len(), 1);
        let retained = &p.ahost.received[0];
        // The complete segment, never one of its shorter fragments.
        assert!(retained.envelope.is_some());
        assert_eq!(retained.bytes.len(), frames[0].len());
        // Once the reservation resolves, the retained datagram is dispatched.
        backend.blocked = false;
        transmit_frames(&mut p.ahost, &mut p.a, p.time, &mut output, &mut pending, h, &mut Sample(0),
            &mut backend).unwrap();
        assert!(p.ahost.received.is_empty());
        let mut bytes = [0; 2000];
        assert_eq!(p.a.read(p.aid, &mut bytes).unwrap(), 1000);
        assert_eq!(&bytes[..1000], &[0x42; 1000][..]);
    }
}

// `packet` (IPv4) with `options` inserted after its base header.
fn with_ipv4_options(packet: &[u8], options: &[u8]) -> Vec<u8> {
    let mut packet = packet.to_vec();
    packet.splice(IP_HEADER..IP_HEADER, options.iter().copied());
    packet[0] = 0x45 + (options.len() / 4) as u8;
    let len = packet.len() as u16;
    packet[2..4].copy_from_slice(&len.to_be_bytes());
    seal_ip(&mut packet);
    packet
}

// The drain's retention keeps the result of destination processing: a
// segment for a reserved owner is processed (recorded with one sample of the
// example's UTC provider) before it is retained; passes that defer it again
// and its dispatch sample and record nothing more, and a stale owner
// generation never receives it. Option-free output samples nothing. With interpretation disabled every option arrives unrecorded
// and a source route is refused.
#[test]
fn retained_segment_keeps_its_destination_processing() {
    // RR and TS (flag 1) with two free slots each, an opaque copied and a
    // non-copied option.
    let mut raw = vec![30, 2, 158, 3, 0, 7, 11, 4, 0, 0, 0, 0, 0, 0, 0, 0, 68, 20, 5, 1];
    raw.extend_from_slice(&[0; 16]);
    let received = ntcp::Ipv4Options::parse(&raw, false).unwrap();
    for (options, stale) in [(true, false), (true, true), (false, false)] {
        let mut p = Pair::with_options(false, true, options);
        let IpAddr::V4(local) = p.local.ip() else { unreachable!() };
        let mut utc = Utc::new(std::time::Instant::now());
        p.a.write(p.aid, &[0x21; 2000]).unwrap();
        let mut backend = Backend { blocked: true, ..Default::default() };
        let mut output = [0; MTU];
        let mut pending = None;
        transmit_frames(&mut p.ahost, &mut p.a, p.time, &mut output, &mut pending, IP_HEADER,
            &mut utc, &mut backend).unwrap();
        assert!(p.a.is_output_reserved(p.aid));
        let before = p.a.received_ipv4_options(p.aid).unwrap();
        p.b.write(p.bid, b"retained options").unwrap();
        let frames = emit(&mut p.bhost, &mut p.b, p.time, p.remote.ip());
        assert_eq!(frames.len(), 1);
        if !options {
            // A completed source route is refused by the disabled profile.
            let routed = with_ipv4_options(&frames[0], &[131, 7, 8, 192, 0, 2, 9, 0]);
            input_frame(&mut p.ahost, &mut p.a, p.time, &routed, p.local.ip(), options, &mut utc)
                .unwrap();
            assert!(p.ahost.received.is_empty());
        }
        let frame = with_ipv4_options(&frames[0], &raw);
        let utc_before = utc_read();
        input_frame(&mut p.ahost, &mut p.a, p.time, &frame, p.local.ip(), options, &mut utc)
            .unwrap();
        let utc_after = utc_read();
        assert_eq!(p.ahost.received.len(), 1);
        assert_eq!(utc.acquisitions, usize::from(options));
        // Later passes defer it again unchanged.
        for pass in 1..=3 {
            p.ahost.replay(&mut p.a, p.time + pass).unwrap();
            assert_eq!(p.ahost.received.len(), 1);
            assert_eq!(p.a.received_ipv4_options(p.aid).unwrap(), before);
        }
        if stale {
            // Release the reservation without sending, end the generation
            // and reuse its tuple before the drain replays.
            let held = pending.take().unwrap();
            p.ahost.host.cancel_submission(held.ticket.unwrap());
            assert!(p.a.abandon_transmit(held.attempt).unwrap());
            p.a.abort(p.aid).unwrap();
            assert_eq!(p.a.state(p.aid).unwrap(), State::Closed);
            p.a.release(p.aid).unwrap();
            let cfg = runtime_config(&Backend::default(), p.local.ip(), true, true, options)
                .unwrap();
            let id = p.a.connect_with_path_provider(p.time + 5, p.local, p.remote,
                ntcp::ManagedOpenOptions {
                    transport: ntcp::ActiveOpenOptions::from(&cfg.connection),
                    dscp: cfg.dscp,
                    ipv4_options: Default::default(),
                    registration: None,
                    receive_authority: None,
                }, &mut p.ahost.host).unwrap();
            assert_ne!(id, p.aid);
            p.ahost.replay(&mut p.a, p.time + 6).unwrap();
            assert!(p.ahost.received.is_empty());
            // Never dispatched to the new generation, which would answer the
            // old stream's segment with a reset.
            let sent = emit(&mut p.ahost, &mut p.a, p.time + 7, p.local.ip());
            assert_eq!(sent.len(), 1);
            let flags = segment(&sent[0]).header.flags;
            assert_eq!(flags & (ntcp::wire::SYN | ntcp::wire::ACK | ntcp::wire::RST),
                ntcp::wire::SYN);
            assert_eq!(p.a.received_ipv4_options(id).unwrap(), None);
            continue;
        }
        backend.blocked = false;
        transmit_frames(&mut p.ahost, &mut p.a, p.time + 4, &mut output, &mut pending, IP_HEADER,
            &mut utc, &mut backend).unwrap();
        assert!(p.ahost.received.is_empty());
        assert_eq!(utc.acquisitions, usize::from(options));
        // Recorded once, with the value sampled at arrival.
        let delivered = p.a.received_ipv4_options(p.aid).unwrap().unwrap();
        let expected = if options {
            let time = u32::from_be_bytes(delivered.as_bytes()[24..28].try_into().unwrap());
            standard_time(time, utc_before, utc_after);
            let recorded = received.record(local, time).unwrap();
            let out = recorded.as_bytes();
            assert_eq!(&out[5..16], &[7, 11, 8, 192, 0, 2, 1, 0, 0, 0, 0]);
            assert_eq!(&out[16..24], &[68, 20, 13, 1, 192, 0, 2, 1]);
            assert_eq!(&out[28..], &[0; 8]);
            recorded
        } else {
            received
        };
        assert_eq!(delivered, expected);
        let mut bytes = [0; 64];
        assert_eq!(p.a.read(p.aid, &mut bytes).unwrap(), 16);
        assert_eq!(&bytes[..16], b"retained options");
    }
}

// The Host Echo service through the TUN drain. With options enabled
// (NTCP_IPV4_OPTIONS=1) a reply carries the request's Record Route and
// Timestamp recorded once with this host and the test's fixed time, marked
// nonstandard, never the unknown option; a source-routed request is
// answered along its reversed route when the TUN policy authorizes every
// hop, and a structurally valid route through the subnet broadcast address
// is refused and counted. With options disabled the reply carries none.
#[test]
fn echo_replies_carry_processed_options_through_the_tun_drain() {
    let (local, remote) = addresses(false);
    let to_us = IpMetadata { source: remote.ip(), destination: local.ip() };
    // RR with two free slots, TS (flag 1) with one, an unknown option.
    let area = [7, 11, 4, 0, 0, 0, 0, 0, 0, 0, 0, 68, 12, 5, 1, 0, 0, 0, 0, 0, 0, 0, 0, 30, 2, 0,
        0, 0];
    let recorded = [7, 11, 8, 192, 0, 2, 1, 0, 0, 0, 0, 68, 12, 13, 1, 192, 0, 2, 1, 0x80, 0, 4,
        0xd2, 0];
    for options in [true, false] {
        let (mut a, mut ahost) = endpoint_with_options(local.ip(), true, options);
        let mut backend = Backend::default();
        let mut buffer = [0; MTU];
        let data = [0x42; 48];
        let request = with_ipv4_options(&echo_request(to_us, 0x77, 1, &data), &area);
        input_frame(&mut ahost, &mut a, 1, &request, local.ip(), options, &mut Sample(1234)).unwrap();
        assert!(ahost.icmp_output(1, &mut buffer, &mut backend).unwrap());
        let reply = backend.frames.pop().unwrap();
        let header = usize::from(reply[0] & 15) * 4;
        assert_eq!(&reply[20..header], if options { &recorded[..] } else { &[] });
        assert_eq!(&reply[16..20], &[192, 0, 2, 2]);
        let decoded = ntcp_icmp::decode_echo(
            IpMetadata { source: local.ip(), destination: remote.ip() }, &reply[header..]).unwrap();
        assert_eq!((decoded.kind, decoded.identifier, decoded.data),
            (ntcp_icmp::EchoKind::Reply, 0x77, &data[..]));
        if !options {
            continue;
        }
        let routed = [131, 11, 12, 192, 0, 2, 9, 192, 0, 2, 8, 0];
        let request = with_ipv4_options(&echo_request(to_us, 0x77, 2, &data), &routed);
        input_frame(&mut ahost, &mut a, 2, &request, local.ip(), options, &mut Sample(1234)).unwrap();
        assert!(ahost.icmp_output(2, &mut buffer, &mut backend).unwrap());
        let reply = backend.frames.pop().unwrap();
        assert_eq!(&reply[16..20], &[192, 0, 2, 8]);
        assert_eq!(&reply[20..32], &[131, 11, 4, 192, 0, 2, 9, 192, 0, 2, 2, 0]);
        let denied = [131, 7, 8, 192, 0, 2, 255, 0];
        let request = with_ipv4_options(&echo_request(to_us, 0x77, 3, &data), &denied);
        input_frame(&mut ahost, &mut a, 3, &request, local.ip(), options, &mut Sample(1234)).unwrap();
        assert_eq!(ahost.host.icmp_output_pending(), 0);
        assert_eq!(ahost.host.icmp_output_counters().unauthorized_routes, 1);
        assert!(backend.frames.is_empty());
    }
}

#[test]
fn datagram_settings_are_validated_and_reported() {
    let v4: IpAddr = "192.0.2.1".parse().unwrap();
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    let parse = |local, mode, a, b| DatagramSettings::parse(local, mode, a, b);
    assert_eq!(parse(v4, None, None, None).unwrap(), DatagramSettings::default());
    let stated = parse(v4, Some("refuse"), Some("4096"), None).unwrap();
    assert_eq!(stated, DatagramSettings {
        udp_mode: UdpSendMode::Refuse,
        peer_reassembly: Some(4096),
    });
    assert_eq!(parse(v6, None, None, Some("65575")).unwrap().peer_reassembly, Some(65575));
    for (local, mode, a, b) in [
        (v4, Some("split"), None, None),
        (v4, None, Some("575"), None),
        (v4, None, Some("65536"), None),
        (v4, None, Some("many"), None),
        (v4, None, None, Some("2000")),
        (v6, None, None, Some("1499")),
        (v6, None, Some("2000"), None),
    ] {
        let error = parse(local, mode, a, b).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{mode:?} {a:?} {b:?}");
    }
    assert!(stated.report(v4).contains("refuse (whole replies only)"));
    assert!(stated.report(v4).contains("4096 octets (stated)"));
    assert!(DatagramSettings::default().report(v6).contains("1500 octets (receiver guarantee)"));
    // The allocator issues from startup on.
    let (_, mut host) = endpoint_with_settings(v6, true, false, &DatagramSettings::default());
    let lease = host.host.lease_identification(0, v6, "2001:db8::2".parse().unwrap(), 17);
    assert!(lease.is_ok(), "{lease:?}");
}

// Fragment mode (the default) with the peers' stated reassembly capacity:
// a reply beyond the TUN packet leaves as fragments of the connectionless
// effective size (1024 IPv4, 1280 IPv6), every IPv4 one with DF, and the
// peer Host reassembles the exact payload. Without the capacity, or when no
// identifier can be issued, it is refused or sent whole, never split.
#[test]
fn fragment_mode_echoes_large_replies_within_the_stated_capacity() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let service = SocketAddr::new(local.ip(), 7);
        let header = if v6 { IPV6_HEADER } else { IP_HEADER };
        let capacity = if v6 { 4136 } else { 4096 };
        let config = runtime_config(&Backend::default(), local.ip(), true, true, false).unwrap();
        let (mut b, mut bhost) = endpoint(remote.ip(), true);
        let client = bhost.host.udp_open(&b, remote, Some(service), ntcp_host::UdpOptions {
            dscp: 0, hop_limit: 64,
        }).unwrap();
        let large: Vec<u8> = (0..3000).map(|n| (n * 7 + 1) as u8).collect();
        let request = udp_request(remote, service, &large);

        let settings = DatagramSettings {
            peer_reassembly: Some(capacity),
            ..DatagramSettings::default()
        };
        let (mut a, mut ahost) = endpoint_with_settings(local.ip(), true, false, &settings);
        let mut echo = UdpEcho::open(&mut ahost, &a, service, &config, &settings).unwrap();
        let mut backend = Backend::default();
        for piece in fragments(&request, 81, 1400) {
            input_frame(&mut ahost, &mut a, 1, &piece, local.ip(), false, &mut Sample(0)).unwrap();
        }
        assert!(echo.drive(&mut ahost, &a, 1, &mut backend).unwrap());
        assert!(echo.notes.is_empty(), "{:?}", echo.notes);
        let replies: Vec<_> = backend.frames.drain(..).collect();
        assert_eq!(replies.len(), if v6 { 3 } else { 4 });
        for (i, frame) in replies.iter().enumerate() {
            if i + 1 != replies.len() {
                assert_eq!(frame.len(), if v6 { 1280 } else { 1020 });
            }
            if !v6 {
                assert_eq!(frame[6] & 0x40, 0x40, "DF on every IPv4 fragment");
                assert_eq!(frame[6] & 0x20 != 0, i + 1 != replies.len(), "MF");
            }
        }
        for frame in &replies {
            input_frame(&mut bhost, &mut b, 2, frame, remote.ip(), false, &mut Sample(0)).unwrap();
        }
        let mut bytes = vec![0; 4000];
        assert_eq!(bhost.host.udp_receive(client, &mut bytes).unwrap(), Some((service, 3000)));
        assert_eq!(&bytes[..3000], &large[..]);

        // Without a stated capacity the receiver guarantee (576 / 1500)
        // cannot hold 3000 octets: refused in Fragment mode's own terms.
        let plain = DatagramSettings::default();
        let (mut a, mut ahost) = endpoint_with_settings(local.ip(), true, false, &plain);
        let mut echo = UdpEcho::open(&mut ahost, &a, service, &config, &plain).unwrap();
        for piece in fragments(&request, 82, 1400) {
            input_frame(&mut ahost, &mut a, 1, &piece, local.ip(), false, &mut Sample(0)).unwrap();
        }
        echo.drive(&mut ahost, &a, 1, &mut backend).unwrap();
        assert!(backend.frames.is_empty());
        let limit = MTU - header - 8;
        let guarantee = if v6 { 1500 } else { 576 };
        assert_eq!(echo.notes, [format!("UDP echo of 3000 octets to {remote} refused: exceeds \
            the datagram limit of {limit} (peer reassembly capacity {guarantee})")]);

        // Without entropy no identifier can be issued: the 3000 octets
        // cannot leave, while a reply the path carries whole does.
        let (mut a, mut ahost) = endpoint_with_settings(local.ip(), true, false, &settings);
        ahost.host.set_entropy(Box::new(|_: &mut [u8]| Err(ntcp_host::EntropyError)));
        let mut echo = UdpEcho::open(&mut ahost, &a, service, &config, &settings).unwrap();
        for piece in fragments(&request, 83, 1400) {
            input_frame(&mut ahost, &mut a, 1, &piece, local.ip(), false, &mut Sample(0)).unwrap();
        }
        let medium = vec![9u8; 1400];
        input_frame(&mut ahost, &mut a, 1, &udp_request(remote, service, &medium), local.ip(),
            false, &mut Sample(0)).unwrap();
        echo.drive(&mut ahost, &a, 1, &mut backend).unwrap();
        assert_eq!(echo.notes.len(), 1);
        assert!(echo.notes[0].starts_with(&format!("UDP echo of 3000 octets to {remote} not sent: \
            no IP identifier available")), "{:?}", echo.notes);
        assert_eq!(backend.frames.len(), 1);
        assert_eq!(backend.frames[0].len(), header + 8 + 1400);
        println!("v6={v6}: 3000-octet echo as {} fragments within {capacity}", replies.len());
    }
}

// NTCP_IPV6_SRH is parsed and refused at startup, and the routes it names
// are installed with the Host over the TUN link; a connection selecting one
// sends its SYN after the route's Segment Routing Header.
#[test]
fn segment_route_setting_is_validated_and_installed() {
    let v4: IpAddr = "192.0.2.1".parse().unwrap();
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    let a: Ipv6Addr = "2001:db8:5::1".parse().unwrap();
    let b: Ipv6Addr = "2001:db8:6::1".parse().unwrap();
    assert!(segment_routes(v6, None).unwrap().is_empty());
    let routes = segment_routes(
        v6,
        Some("2001:db8:d::/48=2001:db8:5::1, 2001:db8:6::1;2001:db8:e::9/128=2001:db8:5::1"),
    )
    .unwrap();
    assert_eq!(
        routes,
        [
            ("2001:db8:d::/48".parse().unwrap(), vec![a, b]),
            ("2001:db8:e::9/128".parse().unwrap(), vec![a]),
        ]
    );
    let max = (0..126)
        .map(|i| format!("2001:db8:100:{i:x}::1"))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        segment_routes(v6, Some(&format!("2001:db8:d::/48={max}"))).unwrap()[0].1.len(),
        126
    );
    for value in [
        "2001:db8:d::/48=2001:db8:5::1;2001:db8:d::/48=2001:db8:6::1".to_string(),
        "2001:db8:d::/48=2001:db8:5::1;2001:db8:d:0::/48=2001:db8:6::1".to_string(),
        "192.0.2.0/24=2001:db8:5::1".to_string(),
        "fe80::/64=2001:db8:5::1".to_string(),
        "2001:db8:d::1/48=2001:db8:5::1".to_string(),
        "2001:db8:d::/48".to_string(),
        "2001:db8:d::/48=fe80::1".to_string(),
        "2001:db8:d::/48=ff02::1".to_string(),
        "2001:db8:d::/48=::1".to_string(),
        "2001:db8:d::/48=".to_string(),
        "2001:db8:d::/48=2001:db8:5::1;".to_string(),
        format!("2001:db8:d::/48={max},2001:db8:200::1"),
    ] {
        assert!(segment_routes(v6, Some(&value)).is_err(), "{value}");
    }
    assert!(segment_routes(v4, Some("2001:db8:d::/48=2001:db8:5::1")).is_err());

    let config = runtime_config(&Backend::default(), v6, true, true, false).unwrap();
    let mut endpoint =
        Endpoint::new(config.clone(), [7; 32], 0, Box::new(tun_v6_policy("2001:db8::1".parse().unwrap())))
            .unwrap();
    let mut network = TunHost::attach_routed(
        &mut endpoint,
        &config,
        v6,
        &DatagramSettings::default(),
        &routes,
        1,
    )
    .unwrap();
    let paths = network.host.paths();
    for (prefix, segments) in &routes {
        let id = paths.select_route(*prefix).unwrap();
        assert_eq!(paths.route_segments(id).unwrap(), &segments[..]);
    }
    let open = ntcp::ManagedOpenOptions {
        transport: ntcp::ActiveOpenOptions::from(&config.connection),
        dscp: config.dscp,
        ipv4_options: Default::default(),
        registration: None,
        receive_authority: None,
    };
    let peer: Ipv6Addr = "2001:db8:d::9".parse().unwrap();
    endpoint
        .connect_with_path_provider(
            0,
            SocketAddr::new(v6, 7),
            SocketAddr::new(peer.into(), 80),
            open,
            &mut network.host,
        )
        .unwrap();
    // `emit` parses the SYN over the peer, Segment List[0].
    let frames = super::emit(&mut network, &mut endpoint, 1, v6);
    assert_eq!(frames.len(), 1);
    let syn = &frames[0];
    assert_eq!((syn[6], &syn[24..40]), (43, &a.octets()[..]));
    assert_eq!(&syn[40..48], &[6, 6, 4, 2, 2, 0, 0, 0]);
    assert_eq!(&syn[48..64], &peer.octets());
    assert_eq!(&syn[64..80], &b.octets());
    assert_eq!(&syn[80..96], &a.octets());
    assert_ne!(super::segment(syn).header.flags & ntcp::wire::SYN, 0);
}

// The packet as the final segment endpoint forwards it (RFC 8754 4.3.1.1,
// End): Segments Left zero and the base Destination Address D.
fn at_final_segment(packet: &[u8]) -> Vec<u8> {
    let mut packet = packet.to_vec();
    packet[43] = 0;
    let destination: [u8; 16] = packet[48..64].try_into().unwrap();
    packet[24..40].copy_from_slice(&destination);
    packet
}

// Over an NTCP_IPV6_SRH route the UDP echo (Refuse and Fragment modes) and
// the ICMP drain place their output behind the route's Segment Routing
// Header (H = 96 for two segments): base Destination Address S1, the full
// list with D in Segment List[0], checksums with D, every fragment
// repeating it; the peer receives each reply once the final segment has
// processed it.
#[test]
fn udp_and_echo_replies_over_a_segment_route_carry_the_srh() {
    let (local, remote) = addresses(true);
    let IpAddr::V6(d) = remote.ip() else { unreachable!() };
    let s1: Ipv6Addr = "2001:db8:5::1".parse().unwrap();
    let s2: Ipv6Addr = "2001:db8:6::1".parse().unwrap();
    let routes = segment_routes(local.ip(), Some(&format!("{d}/128={s1},{s2}"))).unwrap();
    let h = IPV6_HEADER + 8 + 16 * 3;
    let check = |packet: &[u8], next: u8| {
        assert_eq!((packet[6], &packet[24..40]), (43, &s1.octets()[..]));
        assert_eq!(&packet[40..48], &[next, 6, 4, 2, 2, 0, 0, 0]);
        assert_eq!(&packet[48..64], &d.octets());
        assert_eq!(&packet[64..80], &s2.octets());
        assert_eq!(&packet[80..96], &s1.octets());
    };
    let service = SocketAddr::new(local.ip(), 7);
    let config = runtime_config(&Backend::default(), local.ip(), true, true, false).unwrap();
    let (mut b, mut bhost) = endpoint(remote.ip(), true);
    let client = bhost.host.udp_open(&b, remote, Some(service), ntcp_host::UdpOptions {
        dscp: 0, hop_limit: 64,
    }).unwrap();
    for settings in [refuse_settings(), DatagramSettings {
        peer_reassembly: Some(4136),
        ..DatagramSettings::default()
    }] {
        let mut a = Endpoint::new(config.clone(), [7; 32], 0,
            Box::new(tun_v6_policy("2001:db8::1".parse().unwrap()))).unwrap();
        let mut ahost =
            TunHost::attach_routed(&mut a, &config, local.ip(), &settings, &routes, 1).unwrap();
        let mut echo = UdpEcho::open(&mut ahost, &a, service, &config, &settings).unwrap();
        let mut backend = Backend::default();
        let refuse = settings.udp_mode == UdpSendMode::Refuse;
        let payload: Vec<u8> = (0..if refuse { 1000 } else { 3000 }).map(|n| (n * 3) as u8).collect();
        let request = udp_request(remote, service, &payload);
        let pieces = if refuse { vec![request] } else { fragments(&request, 83, 1400) };
        for piece in pieces {
            input_frame(&mut ahost, &mut a, 1, &piece, local.ip(), false, &mut Sample(0)).unwrap();
        }
        assert!(echo.drive(&mut ahost, &a, 1, &mut backend).unwrap());
        assert!(echo.notes.is_empty(), "{:?}", echo.notes);
        let replies: Vec<_> = backend.frames.drain(..).collect();
        if refuse {
            assert_eq!(replies.len(), 1);
            assert_eq!(replies[0].len(), h + 8 + payload.len());
            check(&replies[0], 17);
            let udp = ntcp_ip_common::parse_udp(local.ip(), remote.ip(), &replies[0][h..]).unwrap();
            assert_eq!(udp.payload, &payload[..]);
        } else {
            assert_eq!(replies.len(), 3);
            for (i, frame) in replies.iter().enumerate() {
                check(frame, 44);
                if i + 1 != replies.len() {
                    assert_eq!(frame.len(), 1280);
                }
            }
        }
        for frame in &replies {
            input_frame(&mut bhost, &mut b, 2, &at_final_segment(frame), remote.ip(), false,
                &mut Sample(0)).unwrap();
        }
        let mut bytes = vec![0; 4000];
        assert_eq!(bhost.host.udp_receive(client, &mut bytes).unwrap(),
            Some((service, payload.len())));
        assert_eq!(&bytes[..payload.len()], &payload[..]);

        // Refuse mode's limit is the path budget less H + 8.
        if refuse {
            let large = vec![1; MTU - h - 7];
            input_frame(&mut ahost, &mut a, 3, &udp_request(remote, service, &large), local.ip(),
                false, &mut Sample(0)).unwrap();
            assert!(echo.drive(&mut ahost, &a, 3, &mut backend).unwrap());
            assert!(backend.frames.is_empty());
            assert!(echo.notes.last().unwrap().contains(&format!("limit of {}", MTU - h - 8)));
        }

        // An Echo Reply through the ICMP drain.
        let to_us = IpMetadata { source: remote.ip(), destination: local.ip() };
        let data: Vec<u8> = (0..1000).map(|n| (n * 11) as u8).collect();
        input_frame(&mut ahost, &mut a, 4, &echo_request(to_us, 0x5151, 9, &data), local.ip(),
            false, &mut Sample(0)).unwrap();
        let mut buffer = vec![0; MTU];
        assert!(ahost.icmp_output(4, &mut buffer, &mut backend).unwrap());
        let mut frames: Vec<_> = backend.frames.drain(..).collect();
        // The fragmented UDP reply was the Echo adjunct's demand for the SR
        // path: its probe, an Echo Request carrying the SRH, follows.
        if !refuse {
            let probe = frames.pop().unwrap();
            check(&probe, 58);
            assert_eq!(probe[h], 128);
        }
        assert_eq!(frames.len(), 1);
        let reply = frames.pop().unwrap();
        assert_eq!(reply.len(), h + 8 + data.len());
        check(&reply, 58);
        let decoded = ntcp_icmp::decode_echo(
            IpMetadata { source: local.ip(), destination: remote.ip() }, &reply[h..]).unwrap();
        assert_eq!((decoded.kind, decoded.sequence, decoded.data),
            (ntcp_icmp::EchoKind::Reply, 9, &data[..]));
    }
}
