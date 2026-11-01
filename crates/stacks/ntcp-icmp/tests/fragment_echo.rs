#![cfg(all(feature = "ipv4", feature = "ipv6"))]
use ntcp::{IpMetadata, OutgoingIpv4Options, SourceRoute};
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
fn router(v6: bool) -> IpMetadata {
    IpMetadata {
        source: if v6 {
            "2001:db8:ff::fe"
        } else {
            "198.51.100.254"
        }
        .parse()
        .unwrap(),
        destination: ip(v6).source,
    }
}
fn v4_header(ip: IpMetadata, options: OutgoingIpv4Options) -> ntcp_ip::Header {
    ntcp_ip::Header {
        ip,
        hop_limit: 64,
        dscp: 0,
        ecn: 0,
        ipv4_options: options,
    }
}
fn v6_header(ip: IpMetadata) -> ntcp_ip6::Header {
    ntcp_ip6::Header {
        ip,
        hop_limit: 64,
        dscp: 0,
        ecn: 0,
    }
}

// Fragments of one real UDP datagram of `payload_len` octets on a 1280 path.
fn udp_fragments(v6: bool, payload_len: usize, options: OutgoingIpv4Options) -> Vec<Vec<u8>> {
    let mut data = vec![0; 8 + payload_len];
    for (i, b) in data[8..].iter_mut().enumerate() {
        *b = i as u8;
    }
    ntcp_ip_common::encode_udp(
        ip(v6).source,
        ip(v6).destination,
        4000,
        53,
        &mut data,
        payload_len,
    )
    .unwrap();
    let mut packets = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let mut packet = vec![0; 1280];
        let (len, n) = if v6 {
            let f =
                ntcp_ip6::Fragmenter::new(v6_header(ip(v6)), 17, 0xabcd_0123, data.len()).unwrap();
            let len = f.fragment_len(offset, 1280).unwrap();
            (
                len,
                f.encode(&mut packet, offset, &data[offset..offset + len])
                    .unwrap(),
            )
        } else {
            let f = ntcp_ip::Fragmenter::new(v4_header(ip(v6), options), 17, 0x4321, data.len(), 0)
                .unwrap();
            let len = f.fragment_len(offset, 1280).unwrap();
            (
                len,
                f.encode(&mut packet, offset, &data[offset..offset + len])
                    .unwrap(),
            )
        };
        packet.truncate(n);
        packets.push(packet);
        offset += len;
    }
    packets
}

// Wrap an ICMP message from `outer.source` in a complete IP packet.
fn wrap(outer: IpMetadata, message: &[u8]) -> Vec<u8> {
    let v6 = outer.source.is_ipv6();
    let header = if v6 { 40 } else { 20 };
    let mut b = vec![0; header + message.len()];
    b[header..].copy_from_slice(message);
    if v6 {
        ntcp_ip6::encode_datagram(&mut b, v6_header(outer), 58, message.len()).unwrap();
    } else {
        ntcp_ip::encode_datagram(
            &mut b,
            v4_header(outer, Default::default()),
            1,
            message.len(),
            0,
        )
        .unwrap();
    }
    b
}
fn ptb(v6: bool, quote: &[u8]) -> Vec<u8> {
    let mut message = vec![0; 8 + quote.len()];
    message[0] = if v6 { 2 } else { 3 };
    message[1] = if v6 { 0 } else { 4 };
    message[4..8].copy_from_slice(&1280u32.to_be_bytes());
    if !v6 {
        message[4..6].fill(0);
    }
    message[8..].copy_from_slice(quote);
    let outer = router(v6);
    let sum = if v6 {
        icmpv6_checksum(outer, &message).unwrap()
    } else {
        checksum(&message)
    };
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    wrap(outer, &message)
}

#[test]
fn first_fragment_quote_allows_udp_length_beyond_the_fragment() {
    for v6 in [false, true] {
        let packets = udp_fragments(v6, 3000, Default::default());
        let first = &packets[0];
        let header = if v6 { 48 } else { 20 };
        for quote_len in [header + 8, header + 100, first.len()] {
            let feedback = decode_icmp_quote(&ptb(v6, &first[..quote_len])).unwrap();
            let quote = feedback.quoted;
            assert_eq!(feedback.kind, FeedbackKind::PacketTooBig);
            assert_eq!(quote.ip, ip(v6));
            assert_eq!(quote.ip_packet_len, 1280 - if v6 { 0 } else { 4 });
            assert_eq!(usize::from(quote.ip_header_len), header);
            assert_eq!(quote.protocol, 17);
            assert_eq!(
                quote.transport,
                QuotedTransport::Udp {
                    source_port: 4000,
                    destination_port: 53,
                    length: 3008,
                    checksum: u16::from_be_bytes([first[header + 6], first[header + 7]]),
                }
            );
            let fragment = quote.fragment.unwrap();
            assert_eq!((fragment.offset, fragment.more_fragments), (0, true));
            assert_eq!(fragment.data(), &first[header..header + 8]);
            assert_eq!(
                fragment.identification,
                if v6 {
                    FragmentIdentification::Ipv6 {
                        identification: 0xabcd_0123,
                    }
                } else {
                    FragmentIdentification::Ipv4 {
                        identification: 0x4321,
                        dont_fragment: true,
                    }
                }
            );
            // TCP consumers never see fragment quotes.
            assert_eq!(quote.tcp(), None);
            assert_eq!(
                decode_icmp(&ptb(v6, &first[..quote_len])).unwrap_err(),
                Error::FragmentationUnsupported
            );
        }
        // The UDP header itself must be present.
        for cut in header..header + 8 {
            assert_eq!(
                decode_icmp_quote(&ptb(v6, &first[..cut])).unwrap_err(),
                Error::Quote
            );
        }
        // An undersized UDP length is still refused.
        let mut bad = first.clone();
        bad[header + 4..header + 6].copy_from_slice(&7u16.to_be_bytes());
        assert_eq!(
            decode_icmp_quote(&ptb(v6, &bad[..header + 8])).unwrap_err(),
            Error::Quote
        );
    }
}

#[test]
fn later_fragment_quote_reports_position_and_data_never_ports() {
    for v6 in [false, true] {
        let packets = udp_fragments(v6, 3000, Default::default());
        let header = if v6 { 48 } else { 20 };
        for (index, packet) in packets.iter().enumerate().skip(1) {
            for quote_len in [header, header + 3, header + 8, packet.len()] {
                let quote = decode_icmp_quote(&ptb(v6, &packet[..quote_len]))
                    .unwrap()
                    .quoted;
                // Data octets that happen to look like ports are not parsed.
                assert_eq!(quote.transport, QuotedTransport::Other);
                assert_eq!(quote.ip_packet_len as usize, packet.len());
                let fragment = quote.fragment.unwrap();
                let step = if v6 { 1232 } else { 1256 };
                assert_eq!(usize::from(fragment.offset), index * step);
                assert_eq!(fragment.more_fragments, index + 1 < packets.len());
                let present = (quote_len - header).min(8);
                assert_eq!(fragment.data(), &packet[header..header + present]);
            }
        }
    }
}

#[test]
fn later_fragment_quote_recovers_source_route_final_destination() {
    let options = OutgoingIpv4Options {
        source_route: Some(SourceRoute::new(&["198.51.100.7".parse().unwrap()], false).unwrap()),
        ..Default::default()
    };
    let packets = udp_fragments(false, 3000, options);
    for packet in &packets {
        assert_eq!(packet[0] & 15, 7, "route copied into every fragment");
        let quote = decode_icmp_quote(&ptb(false, packet)).unwrap().quoted;
        assert_eq!(quote.ip, ip(false));
        assert_eq!(quote.ip_header_len, 28);
    }
}

#[test]
fn echo_codec_round_trips_with_checksums_in_both_families() {
    for v6 in [false, true] {
        let mut message = vec![0xa5; 8 + 100];
        for (i, b) in message[8..].iter_mut().enumerate() {
            *b = i as u8 ^ 0x5c;
        }
        let data = message[8..].to_vec();
        for kind in [EchoKind::Request, EchoKind::Reply] {
            let n = encode_echo(ip(v6), kind, 0x1234, 0xfedc, &mut message, 100).unwrap();
            assert_eq!(n, 108);
            assert_eq!(&message[8..], &data[..], "data never modified");
            assert_eq!(
                message[0],
                match (kind, v6) {
                    (EchoKind::Request, false) => 8,
                    (EchoKind::Reply, false) => 0,
                    (EchoKind::Request, true) => 128,
                    (EchoKind::Reply, true) => 129,
                }
            );
            assert_eq!(message[1], 0);
            if v6 {
                assert_eq!(icmpv6_checksum(ip(v6), &message).unwrap(), 0);
            } else {
                assert_eq!(checksum(&message), 0);
            }
            let echo = decode_echo(ip(v6), &message).unwrap();
            assert_eq!(
                echo,
                Echo {
                    kind,
                    identifier: 0x1234,
                    sequence: 0xfedc,
                    data: &data,
                }
            );
            // A reply built over the request's bytes echoes them exactly.
            if kind == EchoKind::Request {
                let reverse = IpMetadata {
                    source: ip(v6).destination,
                    destination: ip(v6).source,
                };
                let mut reply = message.clone();
                encode_echo(
                    reverse,
                    EchoKind::Reply,
                    echo.identifier,
                    echo.sequence,
                    &mut reply,
                    100,
                )
                .unwrap();
                let reply = decode_echo(reverse, &reply).unwrap();
                assert_eq!(
                    (reply.identifier, reply.sequence, reply.data),
                    (0x1234, 0xfedc, &data[..])
                );
            }
            // The ICMPv6 checksum covers the pseudo-header; ICMPv4's does not.
            let other = IpMetadata {
                source: ip(v6).destination,
                ..ip(v6)
            };
            assert_eq!(
                decode_echo(other, &message).map(|_| ()),
                if v6 { Err(Error::Checksum) } else { Ok(()) }
            );
            let mut bad = message.clone();
            bad[20] ^= 1;
            assert_eq!(decode_echo(ip(v6), &bad).unwrap_err(), Error::Checksum);
            // Nonzero code and other types are not Echo messages.
            let mut bad = message.clone();
            bad[1] = 1;
            bad[2..4].fill(0);
            let sum = if v6 {
                icmpv6_checksum(ip(v6), &bad).unwrap()
            } else {
                checksum(&bad)
            };
            bad[2..4].copy_from_slice(&sum.to_be_bytes());
            assert_eq!(decode_echo(ip(v6), &bad).unwrap_err(), Error::Invalid);
            assert_eq!(
                decode_echo(ip(v6), &message[..7]).unwrap_err(),
                Error::Truncated
            );
        }
        let mut not_echo = [0; 36];
        encode_error(
            ip(v6),
            ErrorMessage::ReassemblyTimeExceeded,
            &[0x45; 28],
            &mut not_echo,
        )
        .unwrap();
        assert_eq!(
            decode_echo(ip(v6), &not_echo).unwrap_err(),
            Error::ProtocolUnsupported
        );
        // Buffer and length limits; mixed families never write anything.
        assert_eq!(
            encode_echo(ip(v6), EchoKind::Request, 0, 0, &mut [0; 20], 13).unwrap_err(),
            Error::Length
        );
        assert_eq!(
            encode_echo(ip(v6), EchoKind::Request, 0, 0, &mut vec![0; 70000], 65528).unwrap_err(),
            Error::Length
        );
        let mixed = IpMetadata {
            source: ip(!v6).source,
            destination: ip(v6).destination,
        };
        let mut untouched = [0xa5; 16];
        assert_eq!(
            encode_echo(mixed, EchoKind::Reply, 1, 2, &mut untouched, 8).unwrap_err(),
            Error::Version
        );
        assert_eq!(untouched, [0xa5; 16]);
    }
}

#[test]
fn fragmented_echo_reassembles_to_the_same_message() {
    for v6 in [false, true] {
        let mut message = vec![0; 8 + 4000];
        for (i, b) in message[8..].iter_mut().enumerate() {
            *b = (i % 253) as u8;
        }
        let n = encode_echo(ip(v6), EchoKind::Reply, 7, 9, &mut message, 4000).unwrap();
        let mut reassembled = vec![0; n];
        let mut offset = 0;
        while offset < n {
            let mut packet = vec![0; 1280];
            let (len, written) = if v6 {
                let f = ntcp_ip6::Fragmenter::new(v6_header(ip(v6)), 58, 5, n).unwrap();
                let len = f.fragment_len(offset, 1280).unwrap();
                (
                    len,
                    f.encode(&mut packet, offset, &message[offset..offset + len])
                        .unwrap(),
                )
            } else {
                let f = ntcp_ip::Fragmenter::new(v4_header(ip(v6), Default::default()), 1, 5, n, 0)
                    .unwrap();
                let len = f.fragment_len(offset, 1280).unwrap();
                (
                    len,
                    f.encode(&mut packet, offset, &message[offset..offset + len])
                        .unwrap(),
                )
            };
            let data = if v6 {
                ntcp_ip6::parse_fragment(&packet[..written])
                    .unwrap()
                    .payload
            } else {
                ntcp_ip::parse_fragment(&packet[..written], false)
                    .unwrap()
                    .payload
            };
            reassembled[offset..offset + len].copy_from_slice(data);
            offset += len;
        }
        let echo = decode_echo(ip(v6), &reassembled).unwrap();
        assert_eq!(
            (echo.kind, echo.identifier, echo.sequence),
            (EchoKind::Reply, 7, 9)
        );
        assert_eq!(echo.data, &message[8..]);
    }
}

#[test]
fn reassembly_errors_quote_fragment_zero_and_truncate_to_family_limits() {
    for v6 in [false, true] {
        let packets = udp_fragments(v6, 3000, Default::default());
        let first = &packets[0];
        // The receiver (original destination) reports to the original source.
        let reporter = IpMetadata {
            source: ip(v6).destination,
            destination: ip(v6).source,
        };
        let mut message = vec![0xa5; 2000];
        let n = encode_error(
            reporter,
            ErrorMessage::ReassemblyTimeExceeded,
            first,
            &mut message,
        )
        .unwrap();
        // ICMPv6: the whole error packet fits the 1280 minimum MTU; ICMPv4:
        // within a 576-octet datagram.
        assert_eq!(n, if v6 { 1280 - 40 } else { 576 - 20 });
        assert_eq!(&message[..2], if v6 { &[3, 1] } else { &[11, 1] });
        assert_eq!(&message[4..8], &[0; 4]);
        assert_eq!(&message[8..n], &first[..n - 8]);
        let feedback = decode_icmp_quote(&wrap(reporter, &message[..n])).unwrap();
        assert_eq!(
            (feedback.kind, feedback.code),
            (FeedbackKind::TimeExceeded, 1)
        );
        assert_eq!(feedback.quoted.fragment.unwrap().offset, 0);
        // Smaller buffers truncate further; ICMPv4 keeps header + 8 octets.
        let header = if v6 { 48 } else { 20 };
        let mut small = vec![0; 8 + header + 8];
        assert_eq!(
            encode_error(
                reporter,
                ErrorMessage::ReassemblyTimeExceeded,
                first,
                &mut small
            )
            .unwrap(),
            small.len()
        );
        assert!(decode_icmp_quote(&wrap(reporter, &small)).is_ok());
        let mut smaller = vec![0; 8 + header + 7];
        let short = encode_error(
            reporter,
            ErrorMessage::ReassemblyTimeExceeded,
            first,
            &mut smaller,
        );
        if v6 {
            assert_eq!(short.unwrap(), smaller.len());
        } else {
            assert_eq!(short.unwrap_err(), Error::Length);
        }
        // A short invoking packet is quoted whole.
        let mut whole = vec![0; 200];
        let n = encode_error(
            reporter,
            ErrorMessage::ReassemblyTimeExceeded,
            &first[..60],
            &mut whole,
        )
        .unwrap();
        assert_eq!(n, 68);
        assert_eq!(&whole[8..68], &first[..60]);
        assert_eq!(
            encode_error(
                reporter,
                ErrorMessage::ReassemblyTimeExceeded,
                first,
                &mut [0; 7]
            )
            .unwrap_err(),
            Error::Length
        );
    }
}

#[test]
fn ipv6_parameter_problem_codes_and_pointers() {
    let packets = udp_fragments(true, 3000, Default::default());
    let reporter = IpMetadata {
        source: ip(true).destination,
        destination: ip(true).source,
    };
    // RFC 8200 4.5: unaligned non-final length (code 0, pointer 4 = Payload
    // Length), oversize reconstruction (code 0, pointer 42 = Fragment
    // Offset), incomplete first-fragment header chain (code 3, pointer 0).
    for (code, pointer) in [(0u8, 4u32), (0, 42), (3, 0)] {
        let mut message = vec![0; 1240];
        let n = encode_error(
            reporter,
            ErrorMessage::Ipv6ParameterProblem { code, pointer },
            &packets[0],
            &mut message,
        )
        .unwrap();
        assert_eq!(&message[..2], &[4, code]);
        assert_eq!(&message[4..8], &pointer.to_be_bytes());
        assert_eq!(icmpv6_checksum(reporter, &message[..n]).unwrap(), 0);
        if code == 0 {
            let feedback = decode_icmp_quote(&wrap(reporter, &message[..n])).unwrap();
            assert_eq!(feedback.kind, FeedbackKind::ParameterProblem);
        }
    }
    assert_eq!(
        encode_error(
            reporter,
            ErrorMessage::Ipv6ParameterProblem {
                code: 4,
                pointer: 0
            },
            &packets[0],
            &mut [0; 100]
        )
        .unwrap_err(),
        Error::Invalid
    );
    let v4 = IpMetadata {
        source: ip(false).destination,
        destination: ip(false).source,
    };
    assert_eq!(
        encode_error(
            v4,
            ErrorMessage::Ipv6ParameterProblem {
                code: 0,
                pointer: 4
            },
            &[0x45; 28],
            &mut [0; 100]
        )
        .unwrap_err(),
        Error::Version
    );
}
