use core::net::{IpAddr, Ipv4Addr};
use ntcp::{IpMetadata, OutgoingIpv4Options, SourceRoute, TimestampRequest};
use ntcp_ip::{Fragmenter, Header, IPV4_HEADER, parse, parse_fragment, quote_fragment_header};
use ntcp_ip_common::{Error, PROTOCOL_UDP, checksum, encode_udp, parse_udp};

fn addr(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, n)
}
fn header(options: OutgoingIpv4Options) -> Header {
    Header {
        ip: IpMetadata {
            source: addr(1).into(),
            destination: addr(2).into(),
        },
        hop_limit: 9,
        dscp: 46,
        ecn: 2,
        ipv4_options: options,
    }
}
fn seal(b: &mut [u8]) {
    b[10..12].fill(0);
    let sum = checksum(&b[..usize::from(b[0] & 15) * 4]);
    b[10..12].copy_from_slice(&sum.to_be_bytes());
}
// A complete UDP datagram (checksum over all of it, final destination).
fn udp(payload_len: usize) -> Vec<u8> {
    let mut b = vec![0; 8 + payload_len];
    for (i, byte) in b[8..].iter_mut().enumerate() {
        *byte = (i * 7 + i / 251) as u8;
    }
    encode_udp(
        addr(1).into(),
        addr(2).into(),
        4000,
        53,
        &mut b,
        payload_len,
    )
    .unwrap();
    b
}
// Split `data` at `limit`-octet packets exactly as the Host emitter will.
fn fragment(f: &Fragmenter, data: &[u8], limit: usize) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let len = f.fragment_len(offset, limit).unwrap();
        let mut packet = vec![0xee; limit + 1];
        let n = f
            .encode(&mut packet, offset, &data[offset..offset + len])
            .unwrap();
        packet.truncate(n);
        packets.push(packet);
        offset += len;
    }
    packets
}

#[test]
fn round_trip_on_a_1280_path_uses_1276_octet_fragments_with_df() {
    let data = udp(3000);
    let f = Fragmenter::new(
        header(Default::default()),
        PROTOCOL_UDP,
        0xbeef,
        data.len(),
        0,
    )
    .unwrap();
    let packets = fragment(&f, &data, 1280);
    // 1280 - 20 = 1260 rounds down to 1256 data octets per non-final fragment.
    let lens: Vec<_> = packets.iter().map(Vec::len).collect();
    assert_eq!(lens, [1276, 1276, 20 + 3008 - 2 * 1256]);
    let mut reassembled = vec![0; data.len()];
    for (i, packet) in packets.iter().enumerate() {
        let p = parse_fragment(packet, false).unwrap();
        let fr = p.fragmentation;
        assert_eq!(fr.identification, 0xbeef);
        assert!(fr.dont_fragment, "DF on every originated fragment");
        assert_eq!(fr.more_fragments, i + 1 < packets.len());
        assert_eq!(usize::from(fr.offset), i * 1256);
        assert!(!fr.is_complete());
        assert_eq!(p.header.len(), 20);
        assert_eq!(p.protocol, PROTOCOL_UDP);
        assert_eq!((p.traffic_class, p.hop_limit), ((46 << 2) | 2, 9));
        assert_eq!(packet[6] & 0x80, 0, "reserved flag clear");
        if fr.more_fragments {
            assert_eq!(p.payload.len() % 8, 0);
        }
        let offset = usize::from(fr.offset);
        reassembled[offset..offset + p.payload.len()].copy_from_slice(p.payload);
        // The atomic entrypoints keep refusing every fragment.
        assert_eq!(
            parse(packet, false).unwrap_err(),
            Error::FragmentationUnsupported
        );
        assert_eq!(
            ntcp_ip::quote_header(packet).unwrap_err(),
            Error::FragmentationUnsupported
        );
        assert!(quote_fragment_header(packet).is_ok());
    }
    assert_eq!(reassembled, data);
    // The transport checksum was computed once over the complete datagram.
    let udp = parse_udp(addr(1).into(), addr(2).into(), &reassembled).unwrap();
    assert_eq!(udp.payload, &data[8..]);
}

#[test]
fn copy_projection_with_lsrr_ssrr_rr_and_ts() {
    for strict in [false, true] {
        let options = OutgoingIpv4Options {
            source_route: Some(SourceRoute::new(&[addr(7), addr(8)], strict).unwrap()),
            record_route_slots: Some(2),
            timestamp: Some(TimestampRequest::Times(2)),
        };
        let mut encoded = [0; 40];
        let (first_hop, option_len) = options.encode(addr(1), addr(2), 5, &mut encoded).unwrap();
        assert_eq!(first_hop, addr(7));
        let data = udp(600);
        let f = Fragmenter::new(header(options), PROTOCOL_UDP, 7, data.len(), 5).unwrap();
        assert_eq!(f.header_len(0), 20 + option_len);
        // Only the 11-octet route is copied; padded to 12.
        assert_eq!(f.header_len(8), 32);
        let packets = fragment(&f, &data, 256);
        assert!(packets.len() > 2);
        let mut reassembled = vec![0; data.len()];
        for (i, packet) in packets.iter().enumerate() {
            let header_len = usize::from(packet[0] & 15) * 4;
            assert_eq!(checksum(&packet[..header_len]), 0);
            assert_eq!(packet[6] & 0x40, 0x40);
            assert_eq!(
                &packet[16..20],
                &addr(7).octets(),
                "first hop in the header"
            );
            if i == 0 {
                assert_eq!(&packet[20..header_len], &encoded[..option_len]);
            } else {
                assert_eq!(header_len, 32);
                assert_eq!(packet[20], if strict { 137 } else { 131 });
                assert_eq!(&packet[20..31], &encoded[..11]);
                assert_eq!(packet[31], 0);
            }
            // Every fragment's data offset is a multiple of 8 and the
            // non-final ones fill the packet to 8-octet granularity.
            let offset = usize::from(u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff) * 8;
            let body = &packet[header_len..];
            if i + 1 < packets.len() {
                assert_eq!(body.len(), (256 - header_len) & !7);
            }
            reassembled[offset..offset + body.len()].copy_from_slice(body);
            // Quotes of either kind of fragment recover the final destination.
            let (ip, quoted_header, total, protocol, fr) = quote_fragment_header(packet).unwrap();
            assert_eq!(ip.destination, IpAddr::from(addr(2)));
            assert_eq!(
                (quoted_header, total, protocol),
                (header_len, packet.len(), 17)
            );
            assert_eq!(usize::from(fr.offset), offset);
        }
        assert_eq!(reassembled, data);
        assert!(parse_udp(addr(1).into(), addr(2).into(), &reassembled).is_ok());
    }
}

#[test]
fn flags_and_offset_bit_matrix() {
    let mut base = vec![0; 60];
    let n = ntcp_ip::encode_datagram(&mut base, header(Default::default()), 253, 16, 0).unwrap();
    base.truncate(n);
    for reserved in [false, true] {
        for df in [false, true] {
            for mf in [false, true] {
                for units in [0u16, 1, 2, 0x1000, 0x1fff] {
                    let field = u16::from(reserved) << 15
                        | u16::from(df) << 14
                        | u16::from(mf) << 13
                        | units;
                    let mut b = base.clone();
                    b[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
                    b[6..8].copy_from_slice(&field.to_be_bytes());
                    seal(&mut b);
                    let fragmented = mf || units != 0;
                    // Atomic parse: only DF and a complete datagram pass.
                    match parse(&b, false) {
                        Ok(p) => {
                            assert!(!reserved && !fragmented);
                            assert_eq!(p.payload.len(), 16);
                        }
                        Err(e) => {
                            assert!(reserved || fragmented);
                            assert_eq!(e, Error::FragmentationUnsupported);
                        }
                    }
                    match parse_fragment(&b, false) {
                        Ok(p) => {
                            assert!(!reserved);
                            let fr = p.fragmentation;
                            assert_eq!(fr.identification, 0x1234);
                            assert_eq!((fr.dont_fragment, fr.more_fragments), (df, mf));
                            assert_eq!(fr.offset, units * 8);
                            assert_eq!(fr.is_complete(), !fragmented);
                            assert_eq!(p.payload, &b[20..]);
                        }
                        Err(e) => {
                            assert!(reserved);
                            assert_eq!(e, Error::Invalid);
                        }
                    }
                }
            }
        }
    }
    // Structural checks are shared with the atomic parser.
    let mut b = base.clone();
    b[6] = 0x20;
    seal(&mut b);
    assert_eq!(
        parse_fragment(&b[..b.len() - 1], false).unwrap_err(),
        Error::Length
    );
    b[8] ^= 1;
    assert_eq!(parse_fragment(&b, false).unwrap_err(), Error::Checksum);
}

#[test]
fn fragmenter_refuses_invalid_fragments_and_datagrams() {
    let data = udp(100);
    let h = header(Default::default());
    let f = Fragmenter::new(h, PROTOCOL_UDP, 1, data.len(), 0).unwrap();
    let mut packet = [0; 200];
    // A datagram that fits needs no fragment; atomic fragments are refused.
    assert_eq!(f.fragment_len(0, 200).unwrap(), data.len());
    assert_eq!(f.encode(&mut packet, 0, &data).unwrap_err(), Error::Invalid);
    // Empty, unaligned non-final length, unaligned offset, beyond the end.
    for (offset, slice) in [
        (0, &data[..0]),
        (0, &data[..12]),
        (96, &data[96..103]),
        (4, &data[4..12]),
        (104, &data[96..104]),
    ] {
        assert_eq!(
            f.encode(&mut packet, offset, slice).unwrap_err(),
            Error::Invalid,
            "offset={offset} len={}",
            slice.len()
        );
    }
    // A packet limit with no room for 8 data octets, unaligned offsets and
    // offsets at or past the end are refused.
    assert_eq!(f.fragment_len(0, 27).unwrap_err(), Error::Length);
    assert_eq!(f.fragment_len(0, 28).unwrap(), 8);
    assert_eq!(f.fragment_len(4, 100).unwrap_err(), Error::Invalid);
    assert_eq!(f.fragment_len(data.len(), 100).unwrap_err(), Error::Invalid);
    assert_eq!(
        f.encode(&mut packet[..27], 0, &data[..8]).unwrap_err(),
        Error::Length
    );
    // The final fragment may have any length.
    assert_eq!(f.fragment_len(104, 28).unwrap(), 4);
    assert_eq!(f.encode(&mut packet, 104, &data[104..]).unwrap(), 24);
    // The complete datagram's Total Length is limited to 65535.
    assert!(Fragmenter::new(h, PROTOCOL_UDP, 1, 65515, 0).is_ok());
    assert_eq!(
        Fragmenter::new(h, PROTOCOL_UDP, 1, 65516, 0).unwrap_err(),
        Error::Length
    );
    let max = Fragmenter::new(h, PROTOCOL_UDP, 1, 65515, 0).unwrap();
    let last = (65515 / 8) * 8;
    assert_eq!(max.fragment_len(last, 1500).unwrap(), 65515 - last);
    for (h, error) in [
        (Header { hop_limit: 0, ..h }, Error::Invalid),
        (Header { dscp: 64, ..h }, Error::Invalid),
        (Header { ecn: 4, ..h }, Error::Invalid),
        (
            Header {
                ip: IpMetadata {
                    source: "2001:db8::1".parse().unwrap(),
                    destination: addr(2).into(),
                },
                ..h
            },
            Error::Version,
        ),
    ] {
        assert_eq!(
            Fragmenter::new(h, PROTOCOL_UDP, 1, 100, 0).unwrap_err(),
            error
        );
    }
    assert_eq!(IPV4_HEADER, 20);
}
