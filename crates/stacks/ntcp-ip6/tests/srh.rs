use core::net::{IpAddr, Ipv6Addr};
use ntcp::IpMetadata;
use ntcp_ip_common::{PROTOCOL_UDP, UDP_HEADER, encode_udp, parse_udp};
use ntcp_ip6::{
    Chain, Completeness, FRAGMENT_HEADER, Fragmenter, Header, IPV6_HEADER, encode_routed,
    encode_udp_routed, header_len,
};

// The 8-bit Hdr Ext Len admits at most 126 segments besides D.
const MAX_SEGMENTS: usize = 126;
const SOURCE: &str = "2001:db8:1::1";
const FINAL: &str = "2001:db8:d::9";

fn v6(value: &str) -> Ipv6Addr {
    value.parse().unwrap()
}
fn header() -> Header {
    Header {
        ip: IpMetadata {
            source: SOURCE.parse().unwrap(),
            destination: FINAL.parse().unwrap(),
        },
        hop_limit: 64,
        dscp: 10,
        ecn: 0,
    }
}
fn segments() -> [Ipv6Addr; 3] {
    [
        v6("2001:db8:5::1"),
        v6("2001:db8:6::1"),
        v6("2001:db8:7::1"),
    ]
}

// RFC 8754 2/4.1 for S1..S3 and D, built field by field.
fn expected_srh(next_header: u8) -> Vec<u8> {
    let mut srh = vec![next_header, 8, 4, 3, 3, 0, 0, 0];
    for address in [
        v6(FINAL),
        v6("2001:db8:7::1"),
        v6("2001:db8:6::1"),
        v6("2001:db8:5::1"),
    ] {
        srh.extend_from_slice(&address.octets());
    }
    srh
}

#[test]
fn routed_udp_carries_the_exact_srh_and_checksums_with_the_final_destination() {
    let segments = segments();
    let h = header_len(&segments).unwrap();
    assert_eq!(h, 40 + 8 + 16 * 4);
    let payload = b"segment routed";
    let mut packet = vec![0xee; h + UDP_HEADER + payload.len()];
    packet[h + UDP_HEADER..].copy_from_slice(payload);
    let len = encode_udp_routed(&mut packet, header(), &segments, 4000, 53, payload.len()).unwrap();
    assert_eq!(len, packet.len());
    // Base header: Next Header 43, the SRH counted in Payload Length, S1 as
    // the Destination Address.
    assert_eq!(packet[0] >> 4, 6);
    assert_eq!(
        u16::from_be_bytes([packet[4], packet[5]]) as usize,
        len - IPV6_HEADER
    );
    assert_eq!(packet[6], 43);
    assert_eq!(&packet[8..24], &v6(SOURCE).octets());
    assert_eq!(&packet[24..40], &segments[0].octets());
    assert_eq!(&packet[40..h], &expected_srh(PROTOCOL_UDP)[..]);
    // The UDP checksum covers D, not S1.
    let udp = parse_udp(v6(SOURCE).into(), v6(FINAL).into(), &packet[h..]).unwrap();
    assert_eq!(udp.payload, payload);
    assert!(parse_udp(v6(SOURCE).into(), segments[0].into(), &packet[h..]).is_err());
    // The walker resolves D as Segment List[0] behind the active SRH.
    let chain = Chain::quote(&packet).unwrap();
    assert_eq!(chain.header_len(), h);
    assert_eq!(chain.protocol(), PROTOCOL_UDP);
    assert_eq!(chain.destination(), segments[0]);
    assert_eq!(chain.final_destination(), Some(v6(FINAL)));
    assert_eq!(chain.completeness(), Completeness::Complete);
}

#[test]
fn a_single_segment_and_no_segment() {
    let mut packet = vec![0; 200];
    let one = [v6("2001:db8:5::1")];
    assert_eq!(header_len(&one).unwrap(), 40 + 40);
    let len = encode_routed(&mut packet, header(), &one, 59, 0).unwrap();
    assert_eq!(len, 80);
    let mut srh = vec![59, 4, 4, 1, 1, 0, 0, 0];
    srh.extend_from_slice(&v6(FINAL).octets());
    srh.extend_from_slice(&one[0].octets());
    assert_eq!(&packet[40..80], &srh[..]);
    // Without segments the base header alone is written, addressed to D.
    assert_eq!(header_len(&[]).unwrap(), IPV6_HEADER);
    assert_eq!(
        encode_routed(&mut packet, header(), &[], 59, 0).unwrap(),
        40
    );
    assert_eq!(packet[6], 59);
    assert_eq!(&packet[24..40], &v6(FINAL).octets());
}

#[test]
fn hdr_ext_len_bounds_the_segment_count() {
    let list: Vec<Ipv6Addr> = (0..=MAX_SEGMENTS as u16)
        .map(|i| Ipv6Addr::new(0x2001, 0xdb8, 0x100, i, 0, 0, 0, 1))
        .collect();
    let max = &list[..MAX_SEGMENTS];
    let h = header_len(max).unwrap();
    assert_eq!(h, 40 + 8 + 16 * 127);
    let mut packet = vec![0; h];
    encode_routed(&mut packet, header(), max, 59, 0).unwrap();
    assert_eq!(packet[41], 254);
    assert_eq!((packet[43], packet[44]), (126, 126));
    assert_eq!(&packet[40 + 8 + 16 * 126..], &max[0].octets());
    assert_eq!(
        Chain::quote(&packet).unwrap().final_destination(),
        Some(v6(FINAL))
    );
    assert!(header_len(&list).is_err());
    assert!(encode_routed(&mut vec![0; h + 16], header(), &list, 59, 0).is_err());
    // Transport selectors only: no extension header is encoded as the
    // upper layer, and the buffer must hold the complete header.
    assert!(encode_routed(&mut packet, header(), max, 44, 0).is_err());
    assert!(encode_routed(&mut vec![0; h - 1], header(), max, 59, 0).is_err());
}

#[test]
fn fragments_repeat_the_base_header_and_srh() {
    let segments = segments();
    let payload: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
    let mut datagram = vec![0; UDP_HEADER + payload.len()];
    datagram[UDP_HEADER..].copy_from_slice(&payload);
    let ip = header().ip;
    encode_udp(
        ip.source,
        ip.destination,
        4000,
        53,
        &mut datagram,
        payload.len(),
    )
    .unwrap();
    let f = Fragmenter::routed(
        header(),
        &segments,
        PROTOCOL_UDP,
        0x1234_5678,
        datagram.len(),
    )
    .unwrap();
    let prefix = header_len(&segments).unwrap();
    assert_eq!(f.header_len(), prefix + FRAGMENT_HEADER);
    let mut offset = 0;
    let mut rebuilt = Vec::new();
    while offset < datagram.len() {
        let n = f.fragment_len(offset, 1280).unwrap();
        let mut packet = vec![0; 1280];
        let len = f
            .encode(&mut packet, offset, &datagram[offset..offset + n])
            .unwrap();
        assert!(len <= 1280);
        let packet = &packet[..len];
        assert_eq!(packet[6], 43);
        assert_eq!(&packet[24..40], &segments[0].octets());
        assert_eq!(&packet[40..prefix], &expected_srh(44)[..]);
        assert_eq!(
            u16::from_be_bytes([packet[4], packet[5]]) as usize,
            len - IPV6_HEADER
        );
        let fragment = &packet[prefix..prefix + FRAGMENT_HEADER];
        assert_eq!(fragment[0], PROTOCOL_UDP);
        let field = u16::from_be_bytes([fragment[2], fragment[3]]);
        assert_eq!(usize::from(field & !7), offset);
        assert_eq!(field & 1 == 1, offset + n < datagram.len());
        assert_eq!(&fragment[4..8], &0x1234_5678u32.to_be_bytes());
        let chain = Chain::quote(packet).unwrap();
        assert_eq!(chain.fragment().unwrap().fragment_offset as usize, offset);
        rebuilt.extend_from_slice(&packet[prefix + FRAGMENT_HEADER..]);
        offset += n;
    }
    assert_eq!(rebuilt, datagram);
    let udp = parse_udp(IpAddr::V6(v6(SOURCE)), IpAddr::V6(v6(FINAL)), &rebuilt).unwrap();
    assert_eq!(udp.payload, &payload[..]);
    // The repeated prefix leaves no room in a packet that only fits it.
    assert!(f.fragment_len(0, prefix + FRAGMENT_HEADER + 7).is_err());
    // The original Payload Length counts the SRH.
    assert!(Fragmenter::routed(header(), &segments, PROTOCOL_UDP, 1, 65535 - 72).is_ok());
    assert!(Fragmenter::routed(header(), &segments, PROTOCOL_UDP, 1, 65535 - 71).is_err());
}

// A TCP segment over the SR route: whole or with only its header resident
// (the shared payload follows separately), after the exact SRH, with the
// Payload Length counting the SRH and every TCP octet.
#[test]
fn routed_tcp_places_the_segment_after_the_srh() {
    let segments = segments();
    let h = header_len(&segments).unwrap();
    let ip = header().ip;
    let mut tcp = [0u8; 60];
    let tcp_len = ntcp::wire::encode(
        ip,
        ntcp::wire::Header {
            source_port: 1000,
            destination_port: 80,
            sequence: 7,
            acknowledgment: 9,
            flags: ntcp::wire::ACK,
            window: 512,
            urgent_pointer: 0,
        },
        &[],
        b"routed tcp",
        &mut tcp,
    )
    .unwrap();
    let transmit = ntcp::Transmit {
        connection: None,
        tx_timestamp: None,
        ip,
        len: tcp_len,
        hop_limit: 64,
        dscp: 10,
        ecn: 0,
        ipv4_options: ntcp::OutgoingIpv4Options::default(),
    };
    let mut packet = vec![0; h + tcp_len];
    packet[h..].copy_from_slice(&tcp[..tcp_len]);
    let len = ntcp_ip6::encode_tcp_routed(&mut packet, transmit, &segments, tcp_len).unwrap();
    assert_eq!(len, h + tcp_len);
    assert_eq!(packet[6], 43);
    assert_eq!(&packet[24..40], &segments[0].octets());
    assert_eq!(
        usize::from(u16::from_be_bytes([packet[4], packet[5]])),
        h - IPV6_HEADER + tcp_len
    );
    assert_eq!(packet[IPV6_HEADER..h], expected_srh(6)[..]);
    assert_eq!(&packet[h..], &tcp[..tcp_len]);
    let (quoted, header, total, protocol) = ntcp_ip6::quote_header(&packet).unwrap();
    assert_eq!((quoted, header, total, protocol), (ip, h, len, 6));
    ntcp::wire::parse(ip, &packet[h..]).unwrap();
    // Only the 20-octet header resident: the shared payload is counted in
    // the Payload Length but not encoded.
    let mut shared = vec![0; h + 20];
    shared[h..].copy_from_slice(&tcp[..20]);
    assert_eq!(
        ntcp_ip6::encode_tcp_routed(&mut shared, transmit, &segments, 20),
        Ok(h + 20)
    );
    assert_eq!(shared[..h], packet[..h]);
    // A resident length that is no TCP header is refused.
    assert!(ntcp_ip6::encode_tcp_routed(&mut shared, transmit, &segments, 21).is_err());
    // Without segments it is the base-header encoder.
    let mut base = vec![0; IPV6_HEADER + tcp_len];
    base[IPV6_HEADER..].copy_from_slice(&tcp[..tcp_len]);
    let mut plain = base.clone();
    ntcp_ip6::encode_tcp_routed(&mut base, transmit, &[], tcp_len).unwrap();
    ntcp_ip6::encode(&mut plain, transmit).unwrap();
    assert_eq!(base, plain);
}
