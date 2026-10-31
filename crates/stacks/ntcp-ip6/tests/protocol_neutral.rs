use core::net::IpAddr;
use ntcp::{IpMetadata, OutgoingIpv4Options, Transmit};
use ntcp_ip_common::{Error, parse_udp, pseudo_header_checksum};
use ntcp_ip6::{
    Header, IPV6_HEADER, PROTOCOL_TCP, PROTOCOL_UDP, UDP_HEADER, encode, encode_datagram,
    encode_shared_header, encode_udp, parse,
};

fn tx(len: usize) -> Transmit {
    Transmit {
        connection: None,
        tx_timestamp: None,
        ip: IpMetadata {
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
        },
        len,
        hop_limit: 64,
        dscp: 37,
        ecn: 3,
        ipv4_options: OutgoingIpv4Options::default(),
    }
}

fn header() -> Header {
    Header {
        ip: tx(0).ip,
        hop_limit: 64,
        dscp: 37,
        ecn: 3,
    }
}

// Frozen copy of the TCP-only encoder as of the T8 head (a422289), kept only
// as the reference for byte-identical compatibility of the TCP wrappers.
fn reference_encode_present(
    packet: &mut [u8],
    transmit: Transmit,
    present_tcp_len: usize,
) -> Result<usize, Error> {
    let (IpAddr::V6(source), IpAddr::V6(destination)) =
        (transmit.ip.source, transmit.ip.destination)
    else {
        return Err(Error::Version);
    };
    transmit.len.checked_add(IPV6_HEADER).ok_or(Error::Length)?;
    if transmit.len > usize::from(u16::MAX)
        || present_tcp_len > transmit.len
        || present_tcp_len
            .checked_add(IPV6_HEADER)
            .is_none_or(|n| n > packet.len())
        || transmit.len == 0
        || transmit.hop_limit == 0
        || transmit.dscp > 63
        || transmit.ecn > 3
        || transmit.ipv4_options != OutgoingIpv4Options::default()
    {
        return Err(Error::Invalid);
    }
    let header = &mut packet[..IPV6_HEADER];
    header.fill(0);
    let class = (transmit.dscp << 2) | transmit.ecn;
    header[0] = 0x60 | (class >> 4);
    header[1] = class << 4;
    header[4..6].copy_from_slice(&(transmit.len as u16).to_be_bytes());
    header[6] = 6;
    header[7] = transmit.hop_limit;
    header[8..24].copy_from_slice(&source.octets());
    header[24..40].copy_from_slice(&destination.octets());
    Ok(IPV6_HEADER + present_tcp_len)
}

fn reference_shared(
    packet: &mut [u8],
    transmit: Transmit,
    present_tcp_len: usize,
) -> Result<usize, Error> {
    if !(20..=60).contains(&present_tcp_len)
        || !present_tcp_len.is_multiple_of(4)
        || present_tcp_len > transmit.len
    {
        return Err(Error::Length);
    }
    reference_encode_present(packet, transmit, present_tcp_len)
}

fn transmits() -> Vec<Transmit> {
    let mut out = Vec::new();
    let route = OutgoingIpv4Options {
        record_route_slots: Some(1),
        ..Default::default()
    };
    for options in [OutgoingIpv4Options::default(), route] {
        for len in [
            0,
            1,
            20,
            24,
            60,
            61,
            1440,
            65535,
            65536,
            usize::MAX - 39,
            usize::MAX,
        ] {
            for (hop_limit, dscp, ecn) in [
                (64, 37, 3),
                (1, 0, 0),
                (255, 63, 2),
                (0, 0, 0),
                (1, 64, 0),
                (1, 0, 4),
            ] {
                let mut t = tx(len);
                t.ipv4_options = options;
                t.hop_limit = hop_limit;
                t.dscp = dscp;
                t.ecn = ecn;
                out.push(t);
            }
        }
    }
    for (source, destination) in [("192.0.2.1", "2001:db8::2"), ("2001:db8::1", "192.0.2.2")] {
        for len in [0, 20, usize::MAX] {
            let mut t = tx(len);
            t.ip.source = source.parse().unwrap();
            t.ip.destination = destination.parse().unwrap();
            out.push(t);
        }
    }
    out
}

fn filled(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 3) as u8).collect()
}

#[test]
fn tcp_wrappers_are_byte_identical_to_the_previous_encoder() {
    let mut compared = 0;
    for t in transmits() {
        for capacity in [0, 39, 40, 60, 100, 1600, 65535 + 40] {
            let (mut new, mut old) = (filled(capacity), filled(capacity));
            assert_eq!(
                encode(&mut new, t),
                reference_encode_present(&mut old, t, t.len),
                "{t:?} capacity={capacity}"
            );
            assert_eq!(new, old);
            for present in [0, 20, 22, 24, 60, 64] {
                let (mut new, mut old) = (filled(capacity), filled(capacity));
                assert_eq!(
                    encode_shared_header(&mut new, t, present),
                    reference_shared(&mut old, t, present)
                );
                assert_eq!(new, old);
            }
            compared += 1;
        }
    }
    println!("compared {compared} TCP encodings with the reference encoder");
}

#[test]
fn generic_encoder_selects_upper_layer_and_refuses_extension_headers() {
    for len in [1, 20, 1440, 65535] {
        let (mut generic, mut tcp) = (filled(65535 + 40), filled(65535 + 40));
        assert_eq!(
            encode_datagram(&mut generic, header(), PROTOCOL_TCP, len),
            encode(&mut tcp, tx(len))
        );
        assert_eq!(generic, tcp);
    }
    let mut b = filled(100);
    // An empty upper-layer packet is legal for a generic next header.
    assert_eq!(encode_datagram(&mut b, header(), 59, 0).unwrap(), 40);
    assert_eq!(parse(&b[..40]).unwrap().protocol, 59);
    let before = b.clone();
    for next in [0, 43, 44, 50, 51, 60, 135, 139, 140] {
        assert_eq!(
            encode_datagram(&mut b, header(), next, 8).unwrap_err(),
            Error::Invalid
        );
    }
    assert_eq!(
        encode_datagram(&mut b, header(), 17, 65536).unwrap_err(),
        Error::Invalid
    );
    assert_eq!(b, before);
}

#[test]
fn udp_round_trip_length_and_mandatory_checksum() {
    for payload_len in [0, 1, 2, 3, 512, 1452] {
        let mut b = vec![0; IPV6_HEADER + UDP_HEADER + payload_len];
        let payload = filled(payload_len);
        b[IPV6_HEADER + UDP_HEADER..].copy_from_slice(&payload);
        let n = encode_udp(&mut b, header(), 5353, 7, payload_len).unwrap();
        assert_eq!(n, b.len());
        let p = parse(&b).unwrap();
        assert_eq!(p.protocol, PROTOCOL_UDP);
        assert_eq!(p.ip, tx(0).ip);
        let udp = parse_udp(p.ip.source, p.ip.destination, p.payload).unwrap();
        assert_eq!((udp.source_port, udp.destination_port), (5353, 7));
        assert_eq!(udp.payload, &payload[..]);
        assert!(udp.checksum.is_some_and(|sum| sum != 0));
        for i in 0..p.payload.len() {
            let mut bad = p.payload.to_vec();
            bad[i] ^= 0x10;
            assert!(
                parse_udp(p.ip.source, p.ip.destination, &bad).is_err(),
                "byte {i}"
            );
        }
        // The pseudo-header binds both addresses.
        let other: IpAddr = "2001:db8::3".parse().unwrap();
        assert_eq!(
            parse_udp(p.ip.source, other, p.payload).unwrap_err(),
            Error::Checksum
        );
    }
}

#[test]
fn udp_zero_checksum_rules_ipv6() {
    let ip = tx(0).ip;
    let mut b = vec![0; IPV6_HEADER + UDP_HEADER + 2];
    encode_udp(&mut b, header(), 1, 2, 2).unwrap();
    let sum = u16::from_be_bytes([b[46], b[47]]);
    // Data equal to the previous checksum drives the computed sum to zero,
    // which is transmitted as all ones.
    let mut b = vec![0; IPV6_HEADER + UDP_HEADER + 2];
    b[48..50].copy_from_slice(&sum.to_be_bytes());
    encode_udp(&mut b, header(), 1, 2, 2).unwrap();
    assert_eq!(&b[46..48], &[0xff, 0xff]);
    let mut zeroed = b[40..].to_vec();
    zeroed[6..8].fill(0);
    assert_eq!(
        pseudo_header_checksum(ip.source, ip.destination, 17, &zeroed).unwrap(),
        0
    );
    assert_eq!(
        parse_udp(ip.source, ip.destination, &b[40..])
            .unwrap()
            .checksum,
        Some(0xffff)
    );
    // IPv6 has no "no checksum" value: a received zero is rejected even when
    // the data would otherwise be acceptable.
    assert_eq!(
        parse_udp(ip.source, ip.destination, &zeroed).unwrap_err(),
        Error::Checksum
    );
}

#[test]
fn udp_length_and_port_errors() {
    let ip = tx(0).ip;
    let mut b = vec![0; IPV6_HEADER + UDP_HEADER + 10];
    let n = encode_udp(&mut b, header(), 0, 9, 10).unwrap();
    let datagram = b[40..n].to_vec();
    assert_eq!(
        parse_udp(ip.source, ip.destination, &datagram)
            .unwrap()
            .source_port,
        0
    );
    for cut in 0..8 {
        assert_eq!(
            parse_udp(ip.source, ip.destination, &datagram[..cut]).unwrap_err(),
            Error::Truncated
        );
    }
    for cut in 8..datagram.len() {
        assert_eq!(
            parse_udp(ip.source, ip.destination, &datagram[..cut]).unwrap_err(),
            Error::Length
        );
    }
    let before = b.clone();
    assert_eq!(
        encode_udp(&mut b, header(), 1, 0, 10).unwrap_err(),
        Error::Invalid
    );
    assert_eq!(
        encode_udp(&mut b, header(), 1, 2, 11).unwrap_err(),
        Error::Length
    );
    assert_eq!(b, before);
    let mut big = vec![0; 65535 + 40];
    let n = encode_udp(&mut big, header(), 1, 2, 65535 - 8).unwrap();
    assert_eq!(n, 65535 + 40);
    assert_eq!(
        parse_udp(ip.source, ip.destination, &big[40..])
            .unwrap()
            .payload
            .len(),
        65527
    );
    // The UDP length field cannot describe more; jumbograms are unsupported.
    let mut huge = vec![0; 65536 + 48];
    assert_eq!(
        encode_udp(&mut huge, header(), 1, 2, 65535 - 7).unwrap_err(),
        Error::Length
    );
    let mut mixed = header();
    mixed.ip.source = "192.0.2.1".parse().unwrap();
    assert_eq!(
        encode_udp(&mut b, mixed, 1, 2, 10).unwrap_err(),
        Error::Version
    );
    assert_eq!(b, before);
}
