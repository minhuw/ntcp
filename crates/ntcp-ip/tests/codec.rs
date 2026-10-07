use ntcp::{IpMetadata, OutgoingIpv4Options, Transmit};
use ntcp_ip::*;

fn tx(v6: bool, len: usize) -> Transmit {
    Transmit {
        connection: None,
        ip: IpMetadata {
            source: if v6 { "2001:db8::1" } else { "192.0.2.1" }
                .parse()
                .unwrap(),
            destination: if v6 { "2001:db8::2" } else { "192.0.2.2" }
                .parse()
                .unwrap(),
        },
        len,
        hop_limit: 64,
        dscp: 37,
        ecn: 3,
        ipv4_options: OutgoingIpv4Options::default(),
    }
}
fn seal(b: &mut [u8]) {
    b[10..12].fill(0);
    let sum = checksum(&b[..usize::from(b[0] & 15) * 4]);
    b[10..12].copy_from_slice(&sum.to_be_bytes());
}
#[test]
fn fullwidth_and_malformed_frames() {
    for v6 in [false, true] {
        let header = if v6 { 40 } else { 20 };
        let max_payload = if v6 { 65535 } else { 65535 - 20 };
        let mut b = vec![0xa5; header + max_payload + 1];
        let len = encode(&mut b, tx(v6, max_payload), 0).unwrap();
        let p = parse(&b[..len], false).unwrap();
        assert_eq!(p.payload.len(), max_payload);
        assert_eq!(p.ip, tx(v6, 0).ip);
        assert_eq!(p.traffic_class, (37 << 2) | 3);
        assert_eq!(p.hop_limit, 64);
        assert_eq!(parse(&b[..len + 1], false).unwrap_err(), Error::Length);
        for cut in [0, 1, header - 1, header, len - 1] {
            assert!(parse(&b[..cut], false).is_err());
        }
        let before = b.clone();
        for size in [max_payload + 1, usize::MAX] {
            assert!(encode(&mut b, tx(v6, size), 0).is_err());
            assert_eq!(b, before);
        }
        for (dscp, ecn, hop) in [(64, 0, 1), (0, 4, 1), (0, 0, 0)] {
            let mut t = tx(v6, 20);
            t.dscp = dscp;
            t.ecn = ecn;
            t.hop_limit = hop;
            assert!(encode(&mut b, t, 0).is_err());
            assert_eq!(b, before);
        }
    }
    let mut b = [0; 60];
    let len = encode(&mut b, tx(false, 20), 0).unwrap();
    for flags in [0x8000u16, 0x2000, 1, 0x4001] {
        b[6..8].copy_from_slice(&flags.to_be_bytes());
        seal(&mut b);
        assert_eq!(
            parse(&b[..len], false).unwrap_err(),
            Error::FragmentationUnsupported
        );
    }
    encode(&mut b, tx(false, 20), 0).unwrap();
    b[8] ^= 1;
    assert_eq!(parse(&b[..len], false).unwrap_err(), Error::Checksum);
    encode(&mut b, tx(true, 20), 0).unwrap();
    for next in [0, 43, 50, 51, 60, 135, 139, 140] {
        b[6] = next;
        assert_eq!(parse(&b, false).unwrap_err(), Error::ExtensionsUnsupported);
    }
    b[6] = 44;
    assert_eq!(
        parse(&b, false).unwrap_err(),
        Error::FragmentationUnsupported
    );
    b[4..6].fill(0);
    assert_eq!(parse(&b, false).unwrap_err(), Error::JumbogramsUnsupported);
}

#[test]
fn ethernet_padding_bounds_and_types() {
    for v6 in [false, true] {
        let header = if v6 { IPV6_HEADER } else { IPV4_HEADER };
        let mut ip = [0; 60];
        let mut t = tx(v6, 0);
        t.len = ntcp::wire::encode(
            t.ip,
            ntcp::wire::Header {
                source_port: 1234,
                destination_port: 8080,
                sequence: 1,
                acknowledgment: 2,
                flags: ntcp::wire::ACK,
                window: 1024,
                urgent_pointer: 0,
            },
            &[],
            &[],
            &mut ip[header..],
        )
        .unwrap();
        let len = encode(&mut ip, t, 0).unwrap();
        assert_eq!(len, header + 20);
        let ether_type = if v6 { ETHERTYPE_IPV6 } else { ETHERTYPE_IPV4 };
        let ip_end = ETHERNET_HEADER + len;
        let mut frame = [0xa5; 75];
        let total = encode_ethernet(&mut frame, [1; 6], [2; 6], ether_type, &ip[..len]).unwrap();
        assert_eq!(total, ip_end.max(60));
        assert!(frame[ip_end..total].iter().all(|&b| b == 0));
        assert_eq!(frame[total], 0xa5);
        frame[ip_end..total].fill(0xa5); // Inbound padding need not be zero.
        for size in [ip_end, total] {
            let p = parse_ethernet(&frame[..size]).unwrap();
            assert_eq!(p.source, [1; 6]);
            assert_eq!(p.destination, [2; 6]);
            assert_eq!(p.payload, &ip[..len]);
            let packet = parse(p.payload, false).unwrap();
            assert!(ntcp::wire::parse(packet.ip, packet.payload).is_ok());
        }
        for cut in 0..total {
            if cut != ip_end {
                assert!(parse_ethernet(&frame[..cut]).is_err());
            }
        }
        assert_eq!(
            parse_ethernet(&frame[..ip_end - 1]).unwrap_err(),
            Error::Truncated
        );
        if !v6 {
            assert_eq!(parse(&frame[14..total], false).unwrap_err(), Error::Length);
        }
        let before = frame;
        for capacity in [0, ip_end - 1, total - 1] {
            assert_eq!(
                encode_ethernet(
                    &mut frame[..capacity],
                    [1; 6],
                    [2; 6],
                    ether_type,
                    &ip[..len]
                )
                .unwrap_err(),
                Error::Truncated
            );
            assert_eq!(frame, before);
        }
        assert_eq!(
            parse_ethernet(&frame[..total + 1]).unwrap_err(),
            Error::Length
        );
        let mut extra = ip.to_vec();
        extra.resize(len + 1, 0xa5);
        assert_eq!(
            encode_ethernet(&mut frame, [1; 6], [2; 6], ether_type, &extra).unwrap_err(),
            Error::Length
        );
        assert_eq!(frame, before);
        assert!(
            encode_ethernet(
                &mut frame,
                [1; 6],
                [2; 6],
                if v6 { ETHERTYPE_IPV4 } else { ETHERTYPE_IPV6 },
                &ip[..len]
            )
            .is_err()
        );
        assert_eq!(frame, before);
        for tag in [0x8100u16, 0x88a8, 0x9100] {
            frame[12..14].copy_from_slice(&tag.to_be_bytes());
            assert_eq!(
                parse_ethernet(&frame[..total]).unwrap_err(),
                Error::VlanUnsupported
            );
        }
    }
}

#[test]
fn ethernet_short_ipv6_padding() {
    let mut ip = [0xa5; 41];
    let len = encode(&mut ip, tx(true, 1), 0).unwrap();
    let mut frame = [0xa5; 61];
    let total = encode_ethernet(&mut frame, [1; 6], [2; 6], ETHERTYPE_IPV6, &ip).unwrap();
    assert_eq!(total, 60);
    let ip_end = ETHERNET_HEADER + len;
    assert_eq!(&frame[ip_end..total], &[0; 5]);
    frame[ip_end..total].fill(0xff);
    for size in [ip_end, total] {
        assert_eq!(parse_ethernet(&frame[..size]).unwrap().payload, ip);
    }
    assert_eq!(parse(&frame[14..total], false).unwrap_err(), Error::Length);
    assert_eq!(parse_ethernet(&frame[..61]).unwrap_err(), Error::Length);
}

fn tcp_packet(v6: bool, options: OutgoingIpv4Options) -> Vec<u8> {
    let mut t = tx(v6, 0);
    t.ipv4_options = options;
    let header = if v6 { 40 } else { 20 };
    let mut b = vec![0; 200];
    t.len = ntcp::wire::encode(
        t.ip,
        ntcp::wire::Header {
            source_port: 1234,
            destination_port: 8080,
            sequence: 0x12345678,
            acknowledgment: 0,
            flags: ntcp::wire::SYN,
            window: 1024,
            urgent_pointer: 0,
        },
        &[],
        &[],
        &mut b[header..],
    )
    .unwrap();
    let len = encode(&mut b, t, 0).unwrap();
    b.truncate(len);
    b
}
fn error_packet(v6: bool, quote: &[u8]) -> Vec<u8> {
    let header = if v6 { 40 } else { 20 };
    let mut t = tx(v6, 8 + quote.len());
    core::mem::swap(&mut t.ip.source, &mut t.ip.destination);
    let mut b = vec![0; header + t.len];
    encode(&mut b, t, 0).unwrap();
    if v6 {
        b[6] = 58;
    } else {
        b[9] = 1;
        seal(&mut b);
    }
    let icmp = &mut b[header..];
    icmp[0] = if v6 { 2 } else { 3 };
    icmp[1] = if v6 { 0 } else { 4 };
    icmp[4..8].copy_from_slice(&1280u32.to_be_bytes());
    icmp[8..].copy_from_slice(quote);
    let sum = if v6 {
        icmpv6_checksum(t.ip, icmp).unwrap()
    } else {
        checksum(icmp)
    };
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    b
}
#[test]
fn icmp_checked_quotes_and_ptb() {
    for v6 in [false, true] {
        let tcp = tcp_packet(v6, OutgoingIpv4Options::default());
        let header = if v6 { 40 } else { 20 };
        for quote_len in [header + 8, tcp.len()] {
            let b = error_packet(v6, &tcp[..quote_len]);
            let p = decode_icmp(&b).unwrap();
            assert_eq!(p.candidate_mtu, Some(1280));
            assert_eq!(p.kind, FeedbackKind::PacketTooBig);
            assert_eq!(p.quoted.ip, tx(v6, 0).ip);
            assert_eq!(p.quoted.source_port, 1234);
            assert_eq!(p.quoted.destination_port, 8080);
            assert_eq!(p.quoted.sequence, 0x12345678);
            let mut bad = b.clone();
            bad[header + 2] ^= 1;
            assert_eq!(decode_icmp(&bad).unwrap_err(), Error::Checksum);
        }
        for (kind, code, expected) in if v6 {
            [
                (1, 3, FeedbackKind::DestinationUnreachable),
                (3, 0, FeedbackKind::TimeExceeded),
                (4, 2, FeedbackKind::ParameterProblem),
            ]
        } else {
            [
                (3, 3, FeedbackKind::DestinationUnreachable),
                (11, 0, FeedbackKind::TimeExceeded),
                (12, 2, FeedbackKind::ParameterProblem),
            ]
        } {
            let mut b = error_packet(v6, &tcp);
            let ip = parse(&b, false).unwrap().ip;
            let icmp = &mut b[header..];
            icmp[0] = kind;
            icmp[1] = code;
            icmp[2..4].fill(0);
            let sum = if v6 {
                icmpv6_checksum(ip, icmp).unwrap()
            } else {
                checksum(icmp)
            };
            icmp[2..4].copy_from_slice(&sum.to_be_bytes());
            let feedback = decode_icmp(&b).unwrap();
            assert_eq!(feedback.kind, expected);
            assert_eq!(feedback.candidate_mtu, None);
        }
        for cut in 0..header + 8 {
            assert!(decode_icmp(&error_packet(v6, &tcp[..cut])).is_err());
        }
        let other = tcp_packet(!v6, OutgoingIpv4Options::default());
        assert!(decode_icmp(&error_packet(v6, &other)).is_err());
        let mut bad = tcp.clone();
        bad[header..header + 2].fill(0);
        assert_eq!(
            decode_icmp(&error_packet(v6, &bad)).unwrap_err(),
            Error::Quote
        );
    }
}
#[test]
fn time_exceeded_quotes_allow_expired_inner_packets() {
    for v6 in [false, true] {
        let header = if v6 { 40 } else { 20 };
        let mut expired = tcp_packet(v6, OutgoingIpv4Options::default());
        expired[if v6 { 7 } else { 8 }] = 0;
        if !v6 {
            seal(&mut expired);
        }
        assert_eq!(parse(&expired, false).unwrap_err(), Error::Invalid);
        for quote_len in [header + 8, expired.len()] {
            let mut error = error_packet(v6, &expired[..quote_len]);
            let ip = parse(&error, false).unwrap().ip;
            let icmp = &mut error[header..];
            icmp[0] = if v6 { 3 } else { 11 };
            icmp[1] = 0;
            icmp[2..4].fill(0);
            let sum = if v6 {
                icmpv6_checksum(ip, icmp).unwrap()
            } else {
                checksum(icmp)
            };
            icmp[2..4].copy_from_slice(&sum.to_be_bytes());
            let feedback = decode_icmp(&error).unwrap();
            assert_eq!(feedback.kind, FeedbackKind::TimeExceeded);
            assert_eq!(feedback.quoted.ip, tx(v6, 0).ip);
            assert_eq!(feedback.quoted.source_port, 1234);
            assert_eq!(feedback.quoted.destination_port, 8080);
            assert_eq!(feedback.quoted.sequence, 0x12345678);
        }
    }
}

#[test]
fn source_route_logical_checksum_and_quote() {
    let hop = "192.0.2.9".parse().unwrap();
    let tcp = tcp_packet(
        false,
        OutgoingIpv4Options {
            source_route: Some(ntcp::SourceRoute::new(&[hop], false).unwrap()),
            record_route_slots: Some(1),
            timestamp: Some(ntcp::TimestampRequest::Times(1)),
        },
    );
    assert_eq!(&tcp[16..20], &hop.octets());
    let header = usize::from(tcp[0] & 15) * 4;
    assert!(ntcp::wire::parse(tx(false, 0).ip, &tcp[header..]).is_ok());
    let p = decode_icmp(&error_packet(false, &tcp[..header + 8])).unwrap();
    assert_eq!(p.quoted.ip, tx(false, 0).ip);
    let mut arrived = tcp.clone();
    arrived[16..20].copy_from_slice(&[192, 0, 2, 2]);
    arrived[23..27].copy_from_slice(&hop.octets());
    arrived[22] = 8;
    seal(&mut arrived);
    assert!(parse(&arrived, false).is_err());
    let p = parse(&arrived, true).unwrap();
    assert_eq!(p.ip, tx(false, 0).ip);
    assert!(ntcp::wire::parse(p.ip, p.payload).is_ok());
    assert_eq!(
        p.ipv4_options
            .return_route("192.0.2.1".parse().unwrap())
            .unwrap()
            .hops(),
        &[hop]
    );
}

#[test]
fn tcp_flow_over_ip_and_ethernet() {
    use ntcp::{Endpoint, EndpointConfig, State};
    use std::net::SocketAddr;
    fn transfer(from: &mut Endpoint, to: &mut Endpoint, v6: bool) {
        let mut ip = [0; 1500];
        let mut ethernet = [0; 1514];
        let header = if v6 { 40 } else { 20 };
        for _ in 0..32 {
            let output = from.poll_transmit(0, &mut ip[header..], 1).unwrap();
            if let Some(t) = output.packet {
                let len = encode(&mut ip, t, 0).unwrap();
                let len = encode_ethernet(
                    &mut ethernet,
                    [1; 6],
                    [2; 6],
                    if v6 { ETHERTYPE_IPV6 } else { ETHERTYPE_IPV4 },
                    &ip[..len],
                )
                .unwrap();
                let link = parse_ethernet(&ethernet[..len]).unwrap();
                let p = parse(link.payload, false).unwrap();
                to.input_with_traffic_class(0, p.ip, p.traffic_class, p.payload)
                    .unwrap();
            }
            if !output.more_work {
                return;
            }
        }
        panic!("bounded transfer failed to quiesce");
    }
    for v6 in [false, true] {
        let config = EndpointConfig {
            dscp: 37,
            ..EndpointConfig::default()
        };
        let mut a = Endpoint::new(config.clone(), [1; 32], 0, |_| true).unwrap();
        let mut b = Endpoint::new(config, [2; 32], 0, |_| true).unwrap();
        let local = SocketAddr::new(tx(v6, 0).ip.source, 1234);
        let remote = SocketAddr::new(tx(v6, 0).ip.destination, 8080);
        let listener = b.listen(remote, 1).unwrap();
        let id = a.connect(0, local, remote).unwrap();
        transfer(&mut a, &mut b, v6);
        transfer(&mut b, &mut a, v6);
        transfer(&mut a, &mut b, v6);
        let accepted = b.accept(listener).unwrap();
        assert_eq!(a.state(id).unwrap(), State::Established);
        a.write(id, b"framed TCP").unwrap();
        transfer(&mut a, &mut b, v6);
        let mut out = [0; 32];
        let n = b.read(accepted, &mut out).unwrap();
        assert_eq!(&out[..n], b"framed TCP");
    }
}
