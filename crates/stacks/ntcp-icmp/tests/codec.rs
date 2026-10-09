use ntcp::OutgoingIpv4Options;
use ntcp_icmp::*;
#[path = "../../ntcp-ip/tests/support/mod.rs"]
mod support;
use support::{encode, parse, seal, tx};
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
