use ntcp::{IpMetadata, OutgoingIpv4Options, Transmit};
use ntcp_icmp::*;

fn ip(v6: bool) -> IpMetadata {
    IpMetadata {
        source: if v6 { "2001:db8::1" } else { "192.0.2.1" }
            .parse()
            .unwrap(),
        destination: if v6 { "2001:db8::2" } else { "192.0.2.2" }
            .parse()
            .unwrap(),
    }
}
fn families() -> impl Iterator<Item = bool> {
    [false, true]
        .into_iter()
        .filter(|v6| [cfg!(feature = "ipv4"), cfg!(feature = "ipv6")][usize::from(*v6)])
}
fn hl(v6: bool) -> usize {
    if v6 { 40 } else { 20 }
}
fn seal(b: &mut [u8]) {
    b[10..12].fill(0);
    let sum = checksum(&b[..usize::from(b[0] & 15) * 4]);
    b[10..12].copy_from_slice(&sum.to_be_bytes());
}
fn transmit(v6: bool, len: usize, options: OutgoingIpv4Options) -> Transmit {
    Transmit {
        connection: None,
        tx_timestamp: None,
        ip: ip(v6),
        len,
        hop_limit: 64,
        dscp: 0,
        ecn: 0,
        ipv4_options: options,
    }
}

// Real UDP datagram built by the production codec.
fn udp_packet(v6: bool, payload_len: usize, options: OutgoingIpv4Options) -> Vec<u8> {
    let mut b = vec![0; 100 + payload_len];
    let start = hl(v6) + 8;
    b[start..start + payload_len].fill(0x5a);
    let t = transmit(v6, 0, options);
    let n = if v6 {
        let h = ntcp_ip6::Header {
            ip: t.ip,
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
        };
        ntcp_ip6::encode_udp(&mut b, h, 4000, 53, payload_len).unwrap()
    } else {
        ntcp_ip::encode_udp(&mut b, t.into(), 4000, 53, payload_len, 0).unwrap()
    };
    b.truncate(n);
    b
}

fn tcp_packet(v6: bool) -> Vec<u8> {
    let mut b = vec![0; 200];
    let mut t = transmit(v6, 0, Default::default());
    t.len = ntcp::wire::encode(
        t.ip,
        ntcp::wire::Header {
            source_port: 1234,
            destination_port: 8080,
            sequence: 0x89abcdef,
            acknowledgment: 0,
            flags: ntcp::wire::SYN,
            window: 1024,
            urgent_pointer: 0,
        },
        &[],
        &[],
        &mut b[hl(v6)..],
    )
    .unwrap();
    let n = if v6 {
        ntcp_ip6::encode(&mut b, t).unwrap()
    } else {
        ntcp_ip::encode(&mut b, t, 0).unwrap()
    };
    b.truncate(n);
    b
}

// Router-originated error (outer source is not the quoted peer).
fn error_packet(v6: bool, kind: u8, code: u8, mtu: u32, quote: &[u8]) -> Vec<u8> {
    let header = hl(v6);
    let outer = IpMetadata {
        source: if v6 {
            "2001:db8:ff::fe"
        } else {
            "198.51.100.254"
        }
        .parse()
        .unwrap(),
        destination: ip(v6).source,
    };
    let len = 8 + quote.len();
    let mut b = vec![0; header + len];
    b[header + 8..].copy_from_slice(quote);
    {
        let icmp = &mut b[header..];
        icmp[0] = kind;
        icmp[1] = code;
        icmp[4..8].copy_from_slice(&mtu.to_be_bytes());
        let sum = if v6 {
            icmpv6_checksum(outer, icmp).unwrap()
        } else {
            checksum(icmp)
        };
        icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    }
    if v6 {
        let h = ntcp_ip6::Header {
            ip: outer,
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
        };
        ntcp_ip6::encode_datagram(&mut b, h, 58, len).unwrap();
    } else {
        let mut t = transmit(false, 0, Default::default());
        t.ip = outer;
        ntcp_ip::encode_datagram(&mut b, t.into(), 1, len, 0).unwrap();
    }
    b
}
fn ptb(v6: bool, quote: &[u8]) -> Vec<u8> {
    if v6 {
        error_packet(true, 2, 0, 1280, quote)
    } else {
        error_packet(false, 3, 4, 1280, quote)
    }
}

#[test]
fn udp_quotes_at_every_truncation_length() {
    for v6 in families() {
        let header = hl(v6);
        let udp = udp_packet(v6, 1200, Default::default());
        let wire_sum = u16::from_be_bytes([udp[header + 6], udp[header + 7]]);
        assert_ne!(wire_sum, 0);
        let mut accepted = 0;
        for cut in 0..=udp.len() {
            let result = decode_icmp_quote(&ptb(v6, &udp[..cut]));
            if cut < header + 8 {
                assert!(result.is_err(), "v6={v6} cut={cut}");
                continue;
            }
            let f = result.unwrap();
            assert_eq!(f.kind, FeedbackKind::PacketTooBig);
            assert_eq!(f.candidate_mtu, Some(1280));
            assert_eq!(f.quoted.ip, ip(v6));
            assert_eq!(f.quoted.protocol, PROTOCOL_UDP);
            assert_eq!(f.quoted.ip_header_len, header as u16);
            assert_eq!(f.quoted.ip_packet_len, udp.len() as u32);
            assert_eq!(
                f.quoted.transport,
                QuotedTransport::Udp {
                    source_port: 4000,
                    destination_port: 53,
                    length: 1208,
                    checksum: wire_sum,
                }
            );
            assert_eq!(f.tcp(), None);
            // The TCP-only decoder never projects a UDP quote.
            assert_eq!(
                decode_icmp(&ptb(v6, &udp[..cut])).unwrap_err(),
                Error::Quote
            );
            accepted += 1;
        }
        // Quote cannot exceed the original packet.
        let mut long = udp.clone();
        long.push(0);
        assert_eq!(
            decode_icmp_quote(&ptb(v6, &long)).unwrap_err(),
            Error::Quote
        );
        println!(
            "v6={v6}: UDP quotes accepted for {accepted} of {} cuts",
            udp.len() + 1
        );
    }
}

#[test]
fn tcp_quotes_at_every_truncation_length_project_exactly() {
    for v6 in families() {
        let header = hl(v6);
        let tcp = tcp_packet(v6);
        for cut in 0..=tcp.len() {
            let packet = ptb(v6, &tcp[..cut]);
            let generic = decode_icmp_quote(&packet);
            let legacy = decode_icmp(&packet);
            if cut < header + 8 {
                assert!(generic.is_err() && legacy.is_err(), "v6={v6} cut={cut}");
                assert_eq!(generic.unwrap_err(), legacy.unwrap_err());
                continue;
            }
            let generic = generic.unwrap();
            assert_eq!(generic.quoted.protocol, PROTOCOL_TCP);
            assert_eq!(
                generic.quoted.transport,
                QuotedTransport::Tcp {
                    source_port: 1234,
                    destination_port: 8080,
                    sequence: 0x89abcdef,
                }
            );
            let legacy = legacy.unwrap();
            assert_eq!(generic.tcp(), Some(legacy));
            assert_eq!(legacy.quoted.ip_packet_len, tcp.len() as u32);
        }
    }
}

#[test]
fn udp_quote_length_port_and_zero_checksum_rules() {
    for v6 in families() {
        let header = hl(v6);
        let udp = udp_packet(v6, 32, Default::default());
        let mutate = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut b = udp.clone();
            f(&mut b);
            decode_icmp_quote(&ptb(v6, &b[..header + 8]))
        };
        // UDP length below the header or beyond the original IP payload.
        for length in [0u16, 7, 41, 0xffff] {
            assert_eq!(
                mutate(&|b| b[header + 4..header + 6].copy_from_slice(&length.to_be_bytes()))
                    .unwrap_err(),
                Error::Quote,
                "length={length}"
            );
        }
        // A shorter UDP length inside the IP payload is structurally valid.
        assert!(
            mutate(&|b| b[header + 4..header + 6].copy_from_slice(&8u16.to_be_bytes())).is_ok()
        );
        assert_eq!(
            mutate(&|b| b[header + 2..header + 4].fill(0)).unwrap_err(),
            Error::Quote
        );
        let unused_source = mutate(&|b| b[header..header + 2].fill(0)).unwrap();
        assert!(matches!(
            unused_source.quoted.transport,
            QuotedTransport::Udp { source_port: 0, .. }
        ));
        // The quoted checksum is reported raw; a quote may be truncated, so
        // the codec cannot verify it, and zero is reported for both families.
        let zero = mutate(&|b| b[header + 6..header + 8].fill(0)).unwrap();
        assert!(matches!(
            zero.quoted.transport,
            QuotedTransport::Udp { checksum: 0, .. }
        ));
        // Quoted sender must be the outer destination.
        let mut moved = udp.clone();
        moved[if v6 { 8 } else { 12 }] ^= 1;
        if !v6 {
            seal(&mut moved);
        }
        assert_eq!(
            decode_icmp_quote(&ptb(v6, &moved)).unwrap_err(),
            Error::Quote
        );
    }
}

#[test]
fn inner_header_and_extension_rules_apply_to_every_protocol() {
    for v6 in families() {
        for protocol in [PROTOCOL_TCP, PROTOCOL_UDP, 1, 58, 132, 253] {
            let mut base = udp_packet(v6, 16, Default::default());
            base[if v6 { 6 } else { 9 }] = protocol;
            if !v6 {
                seal(&mut base);
            }
            if v6 {
                let mut bad = base.clone();
                bad[6] = 44;
                assert_eq!(
                    decode_icmp_quote(&ptb(true, &bad)).unwrap_err(),
                    Error::FragmentationUnsupported
                );
                for next in [0, 43, 50, 51, 60, 135, 139, 140] {
                    bad[6] = next;
                    assert_eq!(
                        decode_icmp_quote(&ptb(true, &bad)).unwrap_err(),
                        Error::ExtensionsUnsupported
                    );
                }
            } else {
                let mut bad = base.clone();
                bad[8] ^= 1; // inner header checksum
                assert_eq!(
                    decode_icmp_quote(&ptb(false, &bad)).unwrap_err(),
                    Error::Checksum
                );
                let mut bad = base.clone();
                bad[6] = 0x20; // MF: fragments are not supported
                seal(&mut bad);
                assert_eq!(
                    decode_icmp_quote(&ptb(false, &bad)).unwrap_err(),
                    Error::FragmentationUnsupported
                );
            }
            // The complete inner header is required for every protocol.
            for cut in 0..hl(v6) {
                assert!(decode_icmp_quote(&ptb(v6, &base[..cut])).is_err());
            }
        }
    }
}

#[test]
fn unknown_protocol_quote_is_structural() {
    for v6 in families() {
        let header = hl(v6);
        let mut packet = udp_packet(v6, 16, Default::default());
        packet[if v6 { 6 } else { 9 }] = 253;
        if !v6 {
            seal(&mut packet);
        }
        // No transport minimum: the bare complete header is a valid quote.
        for cut in header..=packet.len() {
            let f = decode_icmp_quote(&error_packet(
                v6,
                if v6 { 1 } else { 3 },
                3,
                0,
                &packet[..cut],
            ))
            .unwrap();
            assert_eq!(f.kind, FeedbackKind::DestinationUnreachable);
            assert_eq!(f.quoted.protocol, 253);
            assert_eq!(f.quoted.transport, QuotedTransport::Other);
            assert_eq!(f.quoted.ip_packet_len, packet.len() as u32);
            assert_eq!(f.tcp(), None);
            assert_eq!(
                decode_icmp(&error_packet(
                    v6,
                    if v6 { 1 } else { 3 },
                    3,
                    0,
                    &packet[..cut]
                ))
                .unwrap_err(),
                Error::Quote
            );
        }
        let mut long = packet.clone();
        long.push(0);
        assert_eq!(
            decode_icmp_quote(&ptb(v6, &long)).unwrap_err(),
            Error::Quote
        );
    }
}

#[test]
#[cfg(feature = "ipv4")]
fn source_routed_udp_quote_reports_final_destination() {
    let hop = "192.0.2.9".parse().unwrap();
    let options = OutgoingIpv4Options {
        source_route: Some(ntcp::SourceRoute::new(&[hop], false).unwrap()),
        record_route_slots: Some(1),
        timestamp: None,
    };
    let udp = udp_packet(false, 64, options);
    assert_eq!(&udp[16..20], &hop.octets());
    let header = usize::from(udp[0] & 15) * 4;
    assert!(header > 20);
    for cut in 0..header + 8 {
        assert!(decode_icmp_quote(&ptb(false, &udp[..cut])).is_err());
    }
    let f = decode_icmp_quote(&ptb(false, &udp[..header + 8])).unwrap();
    assert_eq!(f.quoted.ip, ip(false));
    assert_eq!(f.quoted.ip_header_len, header as u16);
    assert_eq!(f.quoted.ip_packet_len, udp.len() as u32);
    assert!(matches!(
        f.quoted.transport,
        QuotedTransport::Udp { length: 72, .. }
    ));
}

#[test]
fn error_kinds_and_classification_are_protocol_independent() {
    for v6 in families() {
        let udp = udp_packet(v6, 8, Default::default());
        let cases: &[(u8, u8, FeedbackKind)] = if v6 {
            &[
                (1, 4, FeedbackKind::DestinationUnreachable),
                (3, 0, FeedbackKind::TimeExceeded),
                (4, 1, FeedbackKind::ParameterProblem),
            ]
        } else {
            &[
                (3, 3, FeedbackKind::DestinationUnreachable),
                (4, 0, FeedbackKind::SourceQuench),
                (11, 1, FeedbackKind::TimeExceeded),
                (12, 0, FeedbackKind::ParameterProblem),
            ]
        };
        for &(kind, code, expected) in cases {
            let f = decode_icmp_quote(&error_packet(v6, kind, code, 0, &udp)).unwrap();
            assert_eq!(f.kind, expected);
            assert_eq!(f.candidate_mtu, None);
            let tcp = decode_icmp(&error_packet(v6, kind, code, 0, &tcp_packet(v6))).unwrap();
            assert_eq!(f.ipv4_network_error(), tcp.ipv4_network_error());
            assert_eq!(f.ipv6_network_error(), tcp.ipv6_network_error());
        }
        let mut corrupt = ptb(v6, &udp);
        corrupt[hl(v6) + 2] ^= 1;
        assert_eq!(decode_icmp_quote(&corrupt).unwrap_err(), Error::Checksum);
    }
}
