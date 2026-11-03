use ntcp::{IpMetadata, OutgoingIpv4Options, Transmit};
use ntcp_icmp::*;
fn tx(v6: bool, len: usize) -> Transmit {
    Transmit {
        connection: None,
        tx_timestamp: None,
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
fn encode(bytes: &mut [u8], t: Transmit, timestamp: u32) -> Result<usize, Error> {
    if t.ip.source.is_ipv6() {
        ntcp_ip6::encode(bytes, t)
    } else {
        ntcp_ip::encode(bytes, t, timestamp)
    }
}
// Test-only projection lets the original mixed-family assertions stay intact.
fn parse(bytes: &[u8], source_routes: bool) -> Result<ntcp_ip::Packet<'_>, Error> {
    if bytes.first().ok_or(Error::Truncated)? >> 4 == 6 {
        let p = ntcp_ip6::parse(bytes)?;
        Ok(ntcp_ip::Packet {
            ip: p.ip,
            traffic_class: p.traffic_class,
            hop_limit: p.hop_limit,
            protocol: p.protocol,
            ipv4_options: ntcp::Ipv4Options::default(),
            payload: p.payload,
        })
    } else {
        ntcp_ip::parse(bytes, source_routes)
    }
}
fn families() -> impl Iterator<Item = bool> {
    [false, true]
        .into_iter()
        .filter(|v6| [cfg!(feature = "ipv4"), cfg!(feature = "ipv6")][usize::from(*v6)])
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
    for v6 in families() {
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
            assert_eq!(p.quoted.ip_packet_len, tcp.len() as u32);
            assert_eq!(p.quoted.ip_header_len, header as u16);
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
            if v6 {
                assert_eq!(feedback.ipv4_network_error(), None);
            }
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
//= https://www.rfc-editor.org/rfc/rfc1191#section-4
//= type=test
//= reason=Decoded quote length is complete original IP length, not quoted byte count or Ethernet frame size; no router-generation claim.
//# The size includes the IP header and IP data, and does not include any lower-level
//# headers.
fn ptb_zero_mtu_and_original_lengths() {
    for v6 in families() {
        let header = if v6 { 40 } else { 20 };
        let mut tcp = tcp_packet(v6, OutgoingIpv4Options::default());
        // A minimal quote of a maximum-sized original packet, not an ICMP-sized packet.
        if v6 {
            tcp[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
        } else {
            tcp[2..4].copy_from_slice(&u16::MAX.to_be_bytes());
            seal(&mut tcp);
        }
        for quote_len in [header + 8, tcp.len()] {
            let mut b = error_packet(v6, &tcp[..quote_len]);
            let ip = parse(&b, false).unwrap().ip;
            let icmp = &mut b[header..];
            icmp[4..8].fill(0);
            icmp[2..4].fill(0);
            let sum = if v6 {
                icmpv6_checksum(ip, icmp).unwrap()
            } else {
                checksum(icmp)
            };
            icmp[2..4].copy_from_slice(&sum.to_be_bytes());
            let p = decode_icmp(&b).unwrap();
            assert_eq!(p.kind, FeedbackKind::PacketTooBig);
            assert_eq!(p.candidate_mtu, if v6 { Some(0) } else { None });
            assert_eq!(p.quoted.ip_packet_len, 65535 + if v6 { 40 } else { 0 });
            assert_eq!(p.quoted.ip_header_len, header as u16);
        }
    }
}

#[test]
fn quote_lengths_and_validation() {
    for v6 in families() {
        let header = if v6 { 40 } else { 20 };
        let tcp = tcp_packet(v6, OutgoingIpv4Options::default());
        for payload in [8u16, 19] {
            let mut bad = tcp.clone();
            if v6 {
                bad[4..6].copy_from_slice(&payload.to_be_bytes());
            } else {
                bad[2..4].copy_from_slice(&(20 + payload).to_be_bytes());
                seal(&mut bad);
            }
            assert_eq!(
                decode_icmp(&error_packet(v6, &bad[..header + 8])).unwrap_err(),
                Error::Quote
            );
        }
        let mut bad = tcp.clone();
        bad.push(0); // Quote cannot exceed the declared original length.
        assert_eq!(
            decode_icmp(&error_packet(v6, &bad)).unwrap_err(),
            Error::Quote
        );
        let mut bad = tcp.clone();
        bad[if v6 { 8 } else { 12 }] ^= 1; // Quoted sender must match outer destination.
        if !v6 {
            seal(&mut bad);
        }
        assert_eq!(
            decode_icmp(&error_packet(v6, &bad)).unwrap_err(),
            Error::Quote
        );
        let mut bad = tcp.clone();
        bad[6] = if v6 { 44 } else { 0x20 };
        if !v6 {
            seal(&mut bad);
        }
        assert_eq!(
            decode_icmp(&error_packet(v6, &bad)).unwrap_err(),
            Error::FragmentationUnsupported
        );
        if v6 {
            for next in [0, 43, 50, 51, 60, 135, 139, 140] {
                bad[6] = next;
                assert_eq!(
                    decode_icmp(&error_packet(true, &bad)).unwrap_err(),
                    Error::ExtensionsUnsupported
                );
            }
        } else {
            let mut bad = tcp;
            bad[8] ^= 1;
            assert_eq!(
                decode_icmp(&error_packet(false, &bad)).unwrap_err(),
                Error::Checksum
            );
        }
    }
}

#[test]
fn time_exceeded_quotes_allow_expired_inner_packets() {
    for v6 in families() {
        let header = if v6 { 40 } else { 20 };
        let mut expired = tcp_packet(v6, OutgoingIpv4Options::default());
        expired[if v6 { 7 } else { 8 }] = 0;
        if !v6 {
            seal(&mut expired);
        }
        let before = expired.clone();
        let packet = parse(&expired, false).unwrap();
        assert_eq!(packet.hop_limit, 0);
        assert_eq!(packet.protocol, 6);
        let segment = ntcp::wire::parse(packet.ip, packet.payload).unwrap();
        assert_eq!(segment.header.source_port, 1234);
        assert_eq!(segment.header.destination_port, 8080);
        assert_eq!(segment.header.sequence, 0x12345678);
        assert_eq!(expired, before);
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
#[cfg(feature = "ipv4")]
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
    assert_eq!(p.quoted.ip_packet_len, tcp.len() as u32);
    assert_eq!(p.quoted.ip_header_len, header as u16);
    assert!(header > 20);
    for cut in 20..header + 8 {
        assert!(decode_icmp(&error_packet(false, &tcp[..cut])).is_err());
    }
    let mut bad = tcp.clone();
    bad[21] = 2; // Source-route option is too short.
    seal(&mut bad);
    assert_eq!(
        decode_icmp(&error_packet(false, &bad)).unwrap_err(),
        Error::Options
    );
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
fn disabled_families_are_rejected() {
    for v6 in [false, true] {
        let enabled = [cfg!(feature = "ipv4"), cfg!(feature = "ipv6")][usize::from(v6)];
        let tcp = tcp_packet(v6, OutgoingIpv4Options::default());
        let packet = error_packet(v6, &tcp);
        if !enabled {
            assert_eq!(decode_icmp(&packet).unwrap_err(), Error::Version);
        } else {
            assert!(decode_icmp(&packet).is_ok());
        }
    }
    assert_eq!(decode_icmp(&[]).unwrap_err(), Error::Truncated);
}

#[test]
#[cfg(feature = "ipv4")]
fn ipv4_error_classification_separates_soft_hard_pmtu_and_source_quench() {
    let tcp = tcp_packet(false, OutgoingIpv4Options::default());
    let mut cases: Vec<_> = (0..=15).map(|code| (3, code)).collect();
    cases.extend([(4, 0), (11, 0), (11, 1), (12, 0), (12, 1), (12, 2)]);
    for (kind, code) in cases {
        let mut bytes = error_packet(false, &tcp[..28]);
        bytes[20] = kind;
        bytes[21] = code;
        if (kind, code) != (3, 4) {
            bytes[24..28].fill(0);
        }
        bytes[22..24].fill(0);
        let sum = checksum(&bytes[20..]);
        bytes[22..24].copy_from_slice(&sum.to_be_bytes());
        let decoded = decode_icmp(&bytes).unwrap();
        let expected = match (kind, code) {
            (3, 2 | 3) => Some(ntcp::NetworkError::HardUnreachable),
            (3, 4) => None,
            (3, _) => Some(ntcp::NetworkError::SoftUnreachable),
            (4, 0) => Some(ntcp::NetworkError::SourceQuench),
            (11, _) => Some(ntcp::NetworkError::TimeExceeded),
            (12, _) => Some(ntcp::NetworkError::ParameterProblem),
            _ => unreachable!(),
        };
        assert_eq!(
            decoded.ipv4_network_error(),
            expected,
            "kind={kind}, code={code}"
        );
        let mut corrupt = bytes.clone();
        corrupt[22] ^= 1;
        assert_eq!(decode_icmp(&corrupt).unwrap_err(), Error::Checksum);
        bytes[54] ^= 1; // Exact quoted sequence bytes are preserved, not reinterpreted.
        bytes[22..24].fill(0);
        let sum = checksum(&bytes[20..]);
        bytes[22..24].copy_from_slice(&sum.to_be_bytes());
        assert_ne!(
            decode_icmp(&bytes).unwrap().quoted.sequence,
            decoded.quoted.sequence
        );
    }
}

// The payload decoder takes the receiver's processed outer metadata as is:
// a source route the receiver admitted is not refused again, the options
// it recorded are the ones reported, and quoted options stay historical.
#[test]
fn payload_decoder_reports_processed_outer_options_without_reparsing() {
    for v6 in families() {
        let tcp = tcp_packet(v6, OutgoingIpv4Options::default());
        let header = if v6 { 40 } else { 20 };
        let frame = error_packet(v6, &tcp[..header + 8]);
        let outer = parse(&frame, false).unwrap();
        let wrapped = decode_icmp_quote(&frame).unwrap();
        let direct = decode_error(outer.ip, outer.ipv4_options, outer.payload).unwrap();
        assert_eq!(direct, wrapped);
        assert!(direct.outer_options.is_empty());
        if v6 {
            // IPv6 has no IPv4 options to carry.
            let options = ntcp::Ipv4Options::parse(&[7, 3, 4, 0], false).unwrap();
            assert_eq!(
                decode_error(outer.ip, options, outer.payload).unwrap_err(),
                Error::Options
            );
            continue;
        }
        // A completed loose source route, then Record Route as processed by
        // the receiver (its own address recorded).
        let raw = [131, 7, 8, 192, 0, 2, 9, 7, 7, 8, 192, 0, 2, 1, 0, 0];
        let mut routed = vec![0; frame.len() + raw.len()];
        routed[..20].copy_from_slice(&frame[..20]);
        routed[0] = 0x40 | ((20 + raw.len()) / 4) as u8;
        let total = routed.len() as u16;
        routed[2..4].copy_from_slice(&total.to_be_bytes());
        routed[20..20 + raw.len()].copy_from_slice(&raw);
        routed[20 + raw.len()..].copy_from_slice(&frame[20..]);
        seal(&mut routed);
        // The stateless full-frame wrapper still refuses source routes.
        assert_eq!(decode_icmp_quote(&routed).unwrap_err(), Error::Options);
        let processed = parse(&routed, true).unwrap();
        let feedback =
            decode_error(processed.ip, processed.ipv4_options, processed.payload).unwrap();
        assert_eq!(feedback.outer_options, processed.ipv4_options);
        assert_eq!(feedback.outer_options.as_bytes(), &raw[..14]);
        assert_eq!(feedback.quoted, wrapped.quoted);
        assert_eq!(feedback.tcp().unwrap().outer_options, processed.ipv4_options);
    }
}
