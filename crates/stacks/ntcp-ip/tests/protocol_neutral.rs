use core::net::{IpAddr, Ipv4Addr};
use ntcp::{IpMetadata, OutgoingIpv4Options, SourceRoute, TimestampRequest, Transmit};
use ntcp_ip::{
    Header, IPV4_HEADER, PROTOCOL_TCP, PROTOCOL_UDP, UDP_HEADER, encode, encode_datagram,
    encode_shared_header, encode_udp, parse, quote_header,
};
use ntcp_ip_common::{Error, checksum, parse_udp, pseudo_header_checksum};

fn tx(len: usize) -> Transmit {
    Transmit {
        connection: None,
        tx_timestamp: None,
        ip: IpMetadata {
            source: "192.0.2.1".parse().unwrap(),
            destination: "192.0.2.2".parse().unwrap(),
        },
        len,
        hop_limit: 64,
        dscp: 37,
        ecn: 3,
        ipv4_options: OutgoingIpv4Options::default(),
    }
}

// Frozen copy of the TCP-only encoder as of the T8 head (a422289), kept only
// as the reference for byte-identical compatibility of the TCP wrappers.
fn reference_encode_present(
    packet: &mut [u8],
    transmit: Transmit,
    timestamp: u32,
    present: usize,
) -> Result<usize, Error> {
    let Transmit {
        ip,
        len: tcp_len,
        hop_limit,
        dscp,
        ecn,
        ipv4_options,
        ..
    } = transmit;
    let (IpAddr::V4(source), IpAddr::V4(destination)) = (ip.source, ip.destination) else {
        return Err(Error::Version);
    };
    let mut options = [0; 40];
    let (destination, option_len) = ipv4_options
        .encode(source, destination, timestamp, &mut options)
        .map_err(|_| Error::Options)?;
    let header_len = 20 + option_len;
    let total_len = tcp_len.checked_add(header_len).ok_or(Error::Length)?;
    let stored_len = header_len.checked_add(present).ok_or(Error::Length)?;
    if total_len > usize::from(u16::MAX) || stored_len > packet.len() {
        return Err(Error::Length);
    }
    if hop_limit == 0 || dscp > 63 || ecn > 3 {
        return Err(Error::Invalid);
    }
    packet.copy_within(20..20 + present, header_len);
    let header = &mut packet[..header_len];
    header.fill(0);
    header[0] = 0x40 | (header_len / 4) as u8;
    header[20..].copy_from_slice(&options[..option_len]);
    header[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    header[6] = 0x40;
    header[8] = hop_limit;
    header[1] = (dscp << 2) | (ecn & 3);
    header[9] = 6;
    header[12..16].copy_from_slice(&source.octets());
    header[16..20].copy_from_slice(&destination.octets());
    let sum = checksum(header);
    header[10..12].copy_from_slice(&sum.to_be_bytes());
    Ok(stored_len)
}

fn reference_shared(
    packet: &mut [u8],
    transmit: Transmit,
    timestamp: u32,
    tcp_header_len: usize,
) -> Result<usize, Error> {
    if !(20..=60).contains(&tcp_header_len)
        || !tcp_header_len.is_multiple_of(4)
        || tcp_header_len > transmit.len
    {
        return Err(Error::Length);
    }
    reference_encode_present(packet, transmit, timestamp, tcp_header_len)
}

fn option_sets() -> Vec<OutgoingIpv4Options> {
    let hop: Ipv4Addr = "192.0.2.9".parse().unwrap();
    vec![
        OutgoingIpv4Options::default(),
        OutgoingIpv4Options {
            source_route: Some(SourceRoute::new(&[hop], false).unwrap()),
            record_route_slots: Some(1),
            timestamp: Some(TimestampRequest::Times(1)),
        },
        OutgoingIpv4Options {
            source_route: Some(SourceRoute::new(&[hop, hop], true).unwrap()),
            ..Default::default()
        },
        OutgoingIpv4Options {
            record_route_slots: Some(9),
            ..Default::default()
        },
        // Too large to fit with a route: exercises the Options error.
        OutgoingIpv4Options {
            source_route: Some(SourceRoute::new(&[hop; 9], false).unwrap()),
            record_route_slots: Some(9),
            ..Default::default()
        },
    ]
}

fn transmits() -> Vec<Transmit> {
    let mut out = Vec::new();
    for options in option_sets() {
        for len in [
            0,
            1,
            20,
            24,
            60,
            61,
            1460,
            65535 - 20,
            65535 - 19,
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
    let mut wrong = tx(20);
    wrong.ip.destination = "2001:db8::2".parse().unwrap();
    out.push(wrong);
    out
}

struct Packet<'a> {
    ip: IpMetadata,
    payload: &'a [u8],
}

fn filled(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 3) as u8).collect()
}

#[test]
fn tcp_wrappers_are_byte_identical_to_the_previous_encoder() {
    let mut compared = 0;
    for t in transmits() {
        for capacity in [0, 19, 40, 100, 1600, 65535 + 40] {
            for timestamp in [0, 0x01020304] {
                let (mut new, mut old) = (filled(capacity), filled(capacity));
                assert_eq!(
                    encode(&mut new, t, timestamp),
                    reference_encode_present(&mut old, t, timestamp, t.len),
                    "{t:?} capacity={capacity}"
                );
                assert_eq!(new, old);
                for tcp_header_len in [0, 20, 22, 24, 60, 64] {
                    let (mut new, mut old) = (filled(capacity), filled(capacity));
                    assert_eq!(
                        encode_shared_header(&mut new, t, timestamp, tcp_header_len),
                        reference_shared(&mut old, t, timestamp, tcp_header_len)
                    );
                    assert_eq!(new, old);
                }
                compared += 1;
            }
        }
    }
    println!("compared {compared} TCP encodings with the reference encoder");
}

#[test]
fn generic_encoder_with_tcp_selector_matches_tcp_wrapper() {
    for t in transmits() {
        for capacity in [40, 1600] {
            let (mut generic, mut tcp) = (filled(capacity), filled(capacity));
            assert_eq!(
                encode_datagram(&mut generic, t.into(), PROTOCOL_TCP, t.len, 7),
                encode(&mut tcp, t, 7)
            );
            assert_eq!(generic, tcp);
        }
    }
    let mut b = filled(100);
    let n = encode_datagram(&mut b, tx(0).into(), 253, 30, 0).unwrap();
    let p = parse(&b[..n], false).unwrap();
    assert_eq!((p.protocol, p.payload.len()), (253, 30));
    assert_eq!(u16::from_be_bytes([b[6], b[7]]), 0x4000);
}

fn udp_header(options: OutgoingIpv4Options) -> Header {
    let mut t = tx(0);
    t.ipv4_options = options;
    t.into()
}

#[test]
fn udp_round_trip_length_and_checksum() {
    for options in option_sets().into_iter().take(4) {
        for payload_len in [0, 1, 2, 3, 512, 1472] {
            let mut b = vec![0; IPV4_HEADER + UDP_HEADER + payload_len + 40];
            let payload = filled(payload_len);
            b[IPV4_HEADER + UDP_HEADER..][..payload_len].copy_from_slice(&payload);
            let n = encode_udp(&mut b, udp_header(options), 5353, 7, payload_len, 0).unwrap();
            b.truncate(n);
            // An unfinished source route places a hop in the header; the
            // checked quote view recovers the final destination, which the
            // pseudo-header uses.
            let (ip, header, total, protocol) = quote_header(&b).unwrap();
            assert_eq!((total, protocol), (n, PROTOCOL_UDP));
            assert_eq!(header > IPV4_HEADER, options != Default::default());
            assert_eq!(
                u16::from_be_bytes([b[6], b[7]]),
                0x4000,
                "DF, never fragmented"
            );
            assert_eq!(ip, tx(0).ip);
            if options.source_route.is_none() {
                assert_eq!(parse(&b, false).unwrap().ip, ip);
            }
            let p = Packet {
                ip,
                payload: &b[header..],
            };
            let udp = parse_udp(p.ip.source, p.ip.destination, p.payload).unwrap();
            assert_eq!((udp.source_port, udp.destination_port), (5353, 7));
            assert_eq!(udp.payload, &payload[..]);
            assert_ne!(udp.checksum, None);
            assert_eq!(
                usize::from(u16::from_be_bytes([p.payload[4], p.payload[5]])),
                8 + payload_len
            );
            for i in 0..p.payload.len() {
                let mut bad = p.payload.to_vec();
                bad[i] ^= 0x10;
                assert!(
                    parse_udp(p.ip.source, p.ip.destination, &bad).is_err(),
                    "byte {i}"
                );
            }
            let mut wrong = p.ip;
            wrong.destination = "192.0.2.3".parse().unwrap();
            assert_eq!(
                parse_udp(wrong.source, wrong.destination, p.payload).unwrap_err(),
                Error::Checksum
            );
        }
    }
}

#[test]
fn udp_zero_checksum_rules_ipv4() {
    let ip = tx(0).ip;
    // Choose payload so the computed checksum is zero: it is sent as 0xffff.
    let mut b = vec![0; IPV4_HEADER + UDP_HEADER + 2];
    encode_udp(&mut b, tx(0).into(), 1, 2, 2, 0).unwrap();
    let sum = u16::from_be_bytes([b[26], b[27]]);
    let mut b = vec![0; IPV4_HEADER + UDP_HEADER + 2];
    // Adding the old checksum value to the data drives the sum to zero.
    b[28..30].copy_from_slice(&sum.to_be_bytes());
    let n = encode_udp(&mut b, tx(0).into(), 1, 2, 2, 0).unwrap();
    assert_eq!(&b[26..28], &[0xff, 0xff]);
    let p = parse(&b[..n], false).unwrap();
    let mut zeroed = p.payload.to_vec();
    zeroed[6..8].fill(0);
    assert_eq!(
        pseudo_header_checksum(ip.source, ip.destination, 17, &zeroed).unwrap(),
        0
    );
    assert_eq!(
        parse_udp(ip.source, ip.destination, p.payload)
            .unwrap()
            .checksum,
        Some(0xffff)
    );
    // A received zero is an IPv4 datagram without a checksum: accepted
    // even though the data does not match any checksum.
    zeroed[8] ^= 0x55;
    let udp = parse_udp(ip.source, ip.destination, &zeroed).unwrap();
    assert_eq!(udp.checksum, None);
    assert_eq!(udp.payload.len(), 2);
}

#[test]
fn udp_length_and_port_errors() {
    let ip = tx(0).ip;
    let mut b = vec![0; IPV4_HEADER + UDP_HEADER + 10];
    let n = encode_udp(&mut b, tx(0).into(), 0, 9, 10, 0).unwrap();
    let p = parse(&b[..n], false).unwrap();
    let datagram = p.payload.to_vec();
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
    for length in [0u16, 7] {
        let mut bad = datagram.clone();
        bad[4..6].copy_from_slice(&length.to_be_bytes());
        assert_eq!(
            parse_udp(ip.source, ip.destination, &bad).unwrap_err(),
            Error::Length
        );
    }
    // Octets past the UDP length are not datagram data.
    let mut padded = datagram.clone();
    padded.extend([0xee; 3]);
    assert_eq!(
        parse_udp(ip.source, ip.destination, &padded)
            .unwrap()
            .payload
            .len(),
        10
    );

    let before = b.clone();
    assert_eq!(
        encode_udp(&mut b, tx(0).into(), 1, 0, 10, 0).unwrap_err(),
        Error::Invalid
    );
    assert_eq!(
        encode_udp(&mut b, tx(0).into(), 1, 2, 11, 0).unwrap_err(),
        Error::Length
    );
    assert_eq!(
        encode_udp(&mut b, tx(0).into(), 1, 2, usize::MAX, 0).unwrap_err(),
        Error::Length
    );
    assert_eq!(b, before);
    // UDP length fits but IPv4 total length does not.
    let mut big = vec![0; 65535 + 20];
    assert_eq!(
        encode_udp(&mut big, tx(0).into(), 1, 2, 65535 - 28 + 1, 0).unwrap_err(),
        Error::Length
    );
    let n = encode_udp(&mut big, tx(0).into(), 1, 2, 65535 - 28, 0).unwrap();
    assert_eq!(n, 65535);
    let mut v6 = udp_header(Default::default());
    v6.ip.destination = "2001:db8::2".parse().unwrap();
    assert_eq!(
        encode_udp(&mut b, v6, 1, 2, 10, 0).unwrap_err(),
        Error::Version
    );
}
