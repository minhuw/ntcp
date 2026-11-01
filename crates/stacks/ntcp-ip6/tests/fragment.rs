use ntcp::IpMetadata;
use ntcp_ip_common::{Error, PROTOCOL_UDP, encode_udp, parse_udp};
use ntcp_ip6::{
    FRAGMENT_HEADER, Fragmenter, Header, IPV6_HEADER, parse, parse_fragment, quote_fragment_header,
};

fn ip() -> IpMetadata {
    IpMetadata {
        source: "2001:db8::1".parse().unwrap(),
        destination: "2001:db8::2".parse().unwrap(),
    }
}
fn header() -> Header {
    Header {
        ip: ip(),
        hop_limit: 3,
        dscp: 10,
        ecn: 1,
    }
}
fn udp(payload_len: usize) -> Vec<u8> {
    let mut b = vec![0; 8 + payload_len];
    for (i, byte) in b[8..].iter_mut().enumerate() {
        *byte = (i * 13 + i / 241) as u8;
    }
    encode_udp(ip().source, ip().destination, 4000, 53, &mut b, payload_len).unwrap();
    b
}
fn fragment(f: &Fragmenter, data: &[u8], limit: usize) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let len = f.fragment_len(offset, limit).unwrap();
        let mut packet = vec![0xee; limit];
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
fn base_fragment_upper_layer_round_trip_and_header_placement() {
    let data = udp(3000);
    let f = Fragmenter::new(header(), PROTOCOL_UDP, 0x8765_4321, data.len()).unwrap();
    let packets = fragment(&f, &data, 1280);
    // 1280 - 40 - 8 = 1232, already a multiple of 8.
    let lens: Vec<_> = packets.iter().map(Vec::len).collect();
    assert_eq!(lens, [1280, 1280, 48 + 3008 - 2 * 1232]);
    let mut reassembled = vec![0; data.len()];
    for (i, packet) in packets.iter().enumerate() {
        // Base header names the Fragment header, which names the upper layer.
        assert_eq!(packet[6], 44);
        assert_eq!(
            usize::from(u16::from_be_bytes([packet[4], packet[5]])),
            packet.len() - IPV6_HEADER
        );
        assert_eq!(packet[40], PROTOCOL_UDP);
        assert_eq!(packet[41], 0, "reserved octet sent as zero");
        assert_eq!(packet[43] & 6, 0, "reserved bits sent as zero");
        assert_eq!(&packet[44..48], &0x8765_4321u32.to_be_bytes());
        let p = parse_fragment(packet).unwrap();
        let fr = p.fragment.unwrap();
        assert_eq!(fr.identification, 0x8765_4321);
        assert_eq!(fr.next_header, PROTOCOL_UDP);
        assert_eq!(fr.more_fragments, i + 1 < packets.len());
        assert_eq!(usize::from(fr.offset), i * 1232);
        assert!(!fr.is_atomic());
        assert_eq!(p.header, &packet[..48]);
        assert_eq!((p.traffic_class, p.hop_limit), ((10 << 2) | 1, 3));
        assert_eq!(p.ip, ip());
        let offset = usize::from(fr.offset);
        reassembled[offset..offset + p.payload.len()].copy_from_slice(p.payload);
        // The atomic entrypoints keep refusing every fragment.
        assert_eq!(parse(packet).unwrap_err(), Error::FragmentationUnsupported);
        assert_eq!(
            ntcp_ip6::quote_header(packet).unwrap_err(),
            Error::FragmentationUnsupported
        );
        let (quoted_ip, h, total, protocol, quoted) = quote_fragment_header(packet).unwrap();
        assert_eq!(
            (quoted_ip, h, total, protocol),
            (ip(), 48, packet.len(), 17)
        );
        assert_eq!(quoted, Some(fr));
    }
    assert_eq!(reassembled, data);
    // The final destination is the header destination: no Routing header,
    // so the checksum computed over the complete datagram verifies.
    assert!(parse_udp(ip().source, ip().destination, &reassembled).is_ok());
    // An unfragmented packet parses exactly as before.
    let mut whole = vec![0; 48 + 16];
    let n = ntcp_ip6::encode_datagram(&mut whole, header(), 253, 16).unwrap();
    let p = parse_fragment(&whole[..n]).unwrap();
    assert_eq!(
        (p.fragment, p.protocol, p.payload.len(), p.header.len()),
        (None, 253, 16, 40)
    );
}

#[test]
fn received_reserved_bits_are_ignored_and_later_fragment_data_is_opaque() {
    let data = udp(64);
    let f = Fragmenter::new(header(), PROTOCOL_UDP, 9, data.len()).unwrap();
    let packets = fragment(&f, &data, 96);
    assert_eq!(packets.len(), 2);
    for packet in &packets {
        let expected = parse_fragment(packet).unwrap().fragment.unwrap();
        let mut reserved = packet.clone();
        reserved[41] = 0xff;
        reserved[43] |= 6;
        let p = parse_fragment(&reserved).unwrap();
        assert_eq!(p.fragment, Some(expected));
        assert_eq!(p.payload, &packet[48..]);
    }
    // A later fragment's Next Header need not name a supported protocol,
    // nor even an upper layer.
    for next in [0, 43, 44, 50, 60, 59, 135, 253, 255] {
        let mut later = packets[1].clone();
        later[40] = next;
        let p = parse_fragment(&later).unwrap();
        assert_eq!(p.protocol, next);
        assert_eq!(p.fragment.unwrap().next_header, next);
        assert!(quote_fragment_header(&later).is_ok());
        // Fragment zero selects the reconstructed upper layer, which may not
        // continue an extension chain.
        let mut first = packets[0].clone();
        first[40] = next;
        match next {
            0 | 43 | 44 | 50 | 60 | 135 => {
                assert_eq!(
                    parse_fragment(&first).unwrap_err(),
                    Error::ExtensionsUnsupported
                );
                assert_eq!(
                    quote_fragment_header(&first).unwrap_err(),
                    Error::ExtensionsUnsupported
                );
            }
            _ => assert_eq!(parse_fragment(&first).unwrap().protocol, next),
        }
    }
    // Atomic fragments (offset 0, M clear) are recognized on receive.
    let mut atomic = packets[0].clone();
    atomic[43] &= !1;
    assert!(
        parse_fragment(&atomic)
            .unwrap()
            .fragment
            .unwrap()
            .is_atomic()
    );
    // Truncated or impossible Fragment headers.
    let first = &packets[0];
    assert_eq!(parse_fragment(&first[..44]).unwrap_err(), Error::Truncated);
    assert_eq!(
        quote_fragment_header(&first[..47]).unwrap_err(),
        Error::Truncated
    );
    assert_eq!(
        parse_fragment(&first[..first.len() - 1]).unwrap_err(),
        Error::Length
    );
    let mut short = first[..48].to_vec();
    short[4..6].copy_from_slice(&7u16.to_be_bytes());
    assert_eq!(parse_fragment(&short).unwrap_err(), Error::Length);
    let mut version = first.clone();
    version[0] = 0x40;
    assert_eq!(parse_fragment(&version).unwrap_err(), Error::Version);
}

#[test]
fn fragmenter_never_originates_atomic_fragments_or_extension_chains() {
    let data = udp(100);
    let f = Fragmenter::new(header(), PROTOCOL_UDP, 1, data.len()).unwrap();
    let mut packet = [0; 200];
    assert_eq!(f.fragment_len(0, 200).unwrap(), data.len());
    // RFC 8021: a datagram that fits is sent unfragmented, never as an
    // atomic fragment.
    assert_eq!(f.encode(&mut packet, 0, &data).unwrap_err(), Error::Invalid);
    for (offset, slice) in [
        (0, &data[..0]),
        (0, &data[..12]),
        (4, &data[4..12]),
        (104, &data[96..104]),
    ] {
        assert_eq!(
            f.encode(&mut packet, offset, slice).unwrap_err(),
            Error::Invalid
        );
    }
    assert_eq!(f.fragment_len(0, 55).unwrap_err(), Error::Length);
    assert_eq!(f.fragment_len(0, 56).unwrap(), 8);
    assert_eq!(f.fragment_len(4, 100).unwrap_err(), Error::Invalid);
    assert_eq!(
        f.encode(&mut packet[..55], 0, &data[..8]).unwrap_err(),
        Error::Length
    );
    assert_eq!(f.encode(&mut packet, 104, &data[104..]).unwrap(), 48 + 4);
    for next in [0, 43, 44, 50, 51, 60, 135, 139, 140] {
        assert_eq!(
            Fragmenter::new(header(), next, 1, 100).unwrap_err(),
            Error::Invalid
        );
    }
    assert_eq!(
        Fragmenter::new(header(), PROTOCOL_UDP, 1, 65536).unwrap_err(),
        Error::Length
    );
    let mixed = Header {
        ip: IpMetadata {
            source: "192.0.2.1".parse().unwrap(),
            destination: ip().destination,
        },
        ..header()
    };
    assert_eq!(
        Fragmenter::new(mixed, PROTOCOL_UDP, 1, 100).unwrap_err(),
        Error::Version
    );
    assert_eq!(
        Fragmenter::new(
            Header {
                hop_limit: 0,
                ..header()
            },
            PROTOCOL_UDP,
            1,
            100
        )
        .unwrap_err(),
        Error::Invalid
    );
    assert_eq!(FRAGMENT_HEADER, 8);
}
