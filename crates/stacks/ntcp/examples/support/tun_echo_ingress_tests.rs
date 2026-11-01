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
            input_frame(&mut ahost, &mut a, 1, piece, local.ip(), false, 0).unwrap();
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
            input_frame(&mut ahost, &mut a, 2, &piece, local.ip(), false, 0).unwrap();
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
            input_frame(&mut ahost, &mut a, 3, &piece, local.ip(), false, 0).unwrap();
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
            false, 0).unwrap();
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
        transmit_frames(&mut p.ahost, &mut p.a, p.time, &mut output, &mut pending, h, 0,
            &mut backend).unwrap();
        assert!(p.a.is_output_reserved(p.aid));
        // The peer's data segment arrives fragmented.
        p.b.write(p.bid, &[0x42; 1000]).unwrap();
        let frames = emit(&mut p.bhost, &mut p.b, p.time, p.remote.ip());
        assert_eq!(frames.len(), 1);
        let pieces = fragments(&frames[0], 5, 512);
        assert!(pieces.len() > 1);
        for piece in &pieces[1..] {
            input_frame(&mut p.ahost, &mut p.a, p.time, piece, p.local.ip(), false, 0).unwrap();
            assert!(p.ahost.received.is_empty(), "a fragment is never retained");
        }
        input_frame(&mut p.ahost, &mut p.a, p.time, &pieces[0], p.local.ip(), false, 0).unwrap();
        assert_eq!(p.ahost.received.len(), 1);
        let retained = &p.ahost.received[0];
        assert!(retained.envelope.unwrap().reassembled());
        assert_eq!(retained.bytes.len(), frames[0].len());
        // Once the reservation resolves, the retained datagram is dispatched.
        backend.blocked = false;
        transmit_frames(&mut p.ahost, &mut p.a, p.time, &mut output, &mut pending, h, 0,
            &mut backend).unwrap();
        assert!(p.ahost.received.is_empty());
        let mut bytes = [0; 2000];
        assert_eq!(p.a.read(p.aid, &mut bytes).unwrap(), 1000);
        assert_eq!(&bytes[..1000], &[0x42; 1000][..]);
    }
}

#[test]
fn datagram_settings_are_validated_and_reported() {
    let v4: IpAddr = "192.0.2.1".parse().unwrap();
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    let parse = |local, mode, a, b, quiet| DatagramSettings::parse(local, mode, a, b, quiet);
    assert_eq!(parse(v4, None, None, None, None).unwrap(), DatagramSettings::default());
    let stated = parse(v4, Some("refuse"), Some("4096"), None, Some("30")).unwrap();
    assert_eq!(stated, DatagramSettings {
        udp_mode: UdpSendMode::Refuse,
        peer_reassembly: Some(4096),
        quiet: SourceQuiet::Seconds(30),
    });
    assert_eq!(parse(v6, None, None, Some("65575"), Some("never")).unwrap().quiet,
        SourceQuiet::Never);
    for (local, mode, a, b, quiet) in [
        (v4, Some("split"), None, None, None),
        (v4, None, Some("575"), None, None),
        (v4, None, Some("65536"), None, None),
        (v4, None, Some("many"), None, None),
        (v4, None, None, Some("2000"), None),
        (v6, None, None, Some("1499"), None),
        (v6, None, Some("2000"), None, None),
        (v6, None, None, None, Some("-1")),
        (v6, None, None, None, Some("soon")),
    ] {
        let error = parse(local, mode, a, b, quiet).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{mode:?} {a:?} {b:?} {quiet:?}");
    }
    assert!(stated.report(v4).contains("refuse (whole replies only)"));
    assert!(stated.report(v4).contains("4096 octets (stated)"));
    assert!(stated.report(v4).contains("none for 90 s (asserted"));
    assert!(DatagramSettings::default().report(v6).contains("1500 octets (receiver guarantee)"));
    // The allocator starts one MDL after earlier emission may have ceased.
    let second = 1_000_000;
    for (quiet, until) in [
        (SourceQuiet::Unknown, Some(120 * second)),
        (SourceQuiet::Seconds(30), Some(90 * second)),
        (SourceQuiet::Seconds(500), None),
        (SourceQuiet::Never, None),
    ] {
        let settings = DatagramSettings { quiet, ..DatagramSettings::default() };
        let (_, mut host) = endpoint_with_settings(v6, true, false, &settings);
        let lease = host.host.lease_identification(0, v6, "2001:db8::2".parse().unwrap(), 17);
        match until {
            Some(until) => assert_eq!(lease,
                Err(ntcp_host::IdentifierBackpressure::Unavailable { until: Some(until) })),
            None => assert!(lease.is_ok(), "{quiet:?}: {lease:?}"),
        }
    }
}

// Fragment mode (the default) with the peers' stated reassembly capacity:
// a reply beyond the TUN packet leaves as fragments of the connectionless
// effective size (1024 IPv4, 1280 IPv6), every IPv4 one with DF, and the
// peer Host reassembles the exact payload. Without the capacity, or before
// an identifier can be issued, it is refused or sent whole, never split.
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
            quiet: SourceQuiet::Never,
            ..DatagramSettings::default()
        };
        let (mut a, mut ahost) = endpoint_with_settings(local.ip(), true, false, &settings);
        let mut echo = UdpEcho::open(&mut ahost, &a, service, &config, &settings).unwrap();
        let mut backend = Backend::default();
        for piece in fragments(&request, 81, 1400) {
            input_frame(&mut ahost, &mut a, 1, &piece, local.ip(), false, 0).unwrap();
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
            input_frame(&mut bhost, &mut b, 2, frame, remote.ip(), false, 0).unwrap();
        }
        let mut bytes = vec![0; 4000];
        assert_eq!(bhost.host.udp_receive(client, &mut bytes).unwrap(), Some((service, 3000)));
        assert_eq!(&bytes[..3000], &large[..]);

        // Without a stated capacity the receiver guarantee (576 / 1500)
        // cannot hold 3000 octets: refused in Fragment mode's own terms.
        let plain = DatagramSettings { quiet: SourceQuiet::Never, ..DatagramSettings::default() };
        let (mut a, mut ahost) = endpoint_with_settings(local.ip(), true, false, &plain);
        let mut echo = UdpEcho::open(&mut ahost, &a, service, &config, &plain).unwrap();
        for piece in fragments(&request, 82, 1400) {
            input_frame(&mut ahost, &mut a, 1, &piece, local.ip(), false, 0).unwrap();
        }
        echo.drive(&mut ahost, &a, 1, &mut backend).unwrap();
        assert!(backend.frames.is_empty());
        let limit = MTU - header - 8;
        let guarantee = if v6 { 1500 } else { 576 };
        assert_eq!(echo.notes, [format!("UDP echo of 3000 octets to {remote} refused: exceeds \
            the datagram limit of {limit} (peer reassembly capacity {guarantee})")]);

        // Within the default quiet period no identifier exists: the 3000
        // octets cannot leave, while a reply the path carries whole does.
        let quiet = DatagramSettings { peer_reassembly: Some(capacity), ..DatagramSettings::default() };
        let (mut a, mut ahost) = endpoint_with_settings(local.ip(), true, false, &quiet);
        let mut echo = UdpEcho::open(&mut ahost, &a, service, &config, &quiet).unwrap();
        for piece in fragments(&request, 83, 1400) {
            input_frame(&mut ahost, &mut a, 1, &piece, local.ip(), false, 0).unwrap();
        }
        let medium = vec![9u8; 1400];
        input_frame(&mut ahost, &mut a, 1, &udp_request(remote, service, &medium), local.ip(),
            false, 0).unwrap();
        echo.drive(&mut ahost, &a, 1, &mut backend).unwrap();
        assert_eq!(echo.notes.len(), 1);
        assert!(echo.notes[0].starts_with(&format!("UDP echo of 3000 octets to {remote} not sent: \
            no IP identifier available")), "{:?}", echo.notes);
        assert_eq!(backend.frames.len(), 1);
        assert_eq!(backend.frames[0].len(), header + 8 + 1400);
        println!("v6={v6}: 3000-octet echo as {} fragments within {capacity}", replies.len());
    }
}
