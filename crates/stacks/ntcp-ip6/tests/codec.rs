use ntcp::{IpMetadata, OutgoingIpv4Options, Transmit};
use ntcp_ip_common::Error;
use ntcp_ip6::{encode, parse};
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
        mark: 0,
    }
}
#[test]
fn fullwidth_and_malformed_frames() {
    let header = 40;
    let max_payload = 65535;
    let mut b = vec![0xa5; header + max_payload + 1];
    let len = encode(&mut b, tx(true, max_payload)).unwrap();
    let p = parse(&b[..len]).unwrap();
    assert_eq!(p.payload.len(), max_payload);
    assert_eq!(p.ip, tx(true, 0).ip);
    assert_eq!(p.traffic_class, (37 << 2) | 3);
    assert_eq!(p.hop_limit, 64);
    assert_eq!(parse(&b[..len + 1]).unwrap_err(), Error::Length);
    for cut in [0, 1, header - 1, header, len - 1] {
        assert!(parse(&b[..cut]).is_err());
    }
    let before = b.clone();
    for size in [max_payload + 1, usize::MAX] {
        assert!(encode(&mut b, tx(true, size)).is_err());
        assert_eq!(b, before);
    }
    for (dscp, ecn, hop) in [(64, 0, 1), (0, 4, 1), (0, 0, 0)] {
        let mut t = tx(true, 20);
        t.dscp = dscp;
        t.ecn = ecn;
        t.hop_limit = hop;
        assert!(encode(&mut b, t).is_err());
        assert_eq!(b, before);
    }
    let mut b = [0; 60];
    encode(&mut b, tx(true, 20)).unwrap();
    // Zeroed extension headers are traversed: each names Hop-by-Hop next,
    // which may only follow the base header.
    for next in [0, 43, 60] {
        b[6] = next;
        assert_eq!(parse(&b).unwrap_err(), Error::ExtensionsUnsupported);
        assert_eq!(
            ntcp_ip6::Chain::receive(&b).unwrap_err(),
            ntcp_ip6::Fault::MisplacedHopByHop { pointer: 40 }
        );
    }
    // Unsupported selectors end the chain; only the base layout is what the
    // base-header receivers accept.
    for next in [50, 51, 135, 139, 140] {
        b[6] = next;
        let p = parse(&b).unwrap();
        assert_eq!((p.protocol, p.payload.len()), (next, 20));
        assert!(!p.base_layout());
    }
    b[6] = 6;
    assert!(parse(&b).unwrap().base_layout());
    b[6] = 44;
    b[40] = 6;
    assert_eq!(parse(&b).unwrap_err(), Error::FragmentationUnsupported);
    b[4..6].fill(0);
    assert_eq!(parse(&b).unwrap_err(), Error::Length);
    assert_eq!(parse(&b[..40]).unwrap_err(), Error::Length);
}

#[test]
fn checked_headers_and_wrong_family() {
    let mut bytes = [0; 60];
    let len = encode(&mut bytes, tx(true, 20)).unwrap();
    for cut in 0..40 {
        assert!(ntcp_ip6::ipv6_bounds(&bytes[..cut]).is_err());
        assert!(ntcp_ip6::quote_header(&bytes[..cut]).is_err());
    }
    assert!(ntcp_ip6::ipv6_bounds(&bytes[..len]).is_ok());
    assert!(ntcp_ip6::quote_header(&bytes[..40]).is_ok());
    let before = bytes;
    assert_eq!(
        encode(&mut bytes, tx(false, 20)).unwrap_err(),
        Error::Version
    );
    assert_eq!(bytes, before);
}

#[test]
fn shared_header_describes_external_payload_without_copying_it() {
    for tcp_header in [20, 32, 60] {
        for data in [1, 17, 1460, 65000] {
            let t = tx(true, tcp_header + data);
            let mut full = vec![0xa5; 40 + t.len];
            let total = encode(&mut full, t).unwrap();
            let mut resident = vec![0xa5; 40 + tcp_header];
            let stored = ntcp_ip6::encode_shared_header(&mut resident, t, tcp_header).unwrap();
            assert_eq!(stored, resident.len());
            assert_eq!(resident, full[..stored]);
            assert_eq!(ntcp_ip6::ipv6_bounds(&resident).unwrap(), total);
            assert_eq!(stored + data, total);
        }
    }
    for bad in [0, 19, 21, 61, usize::MAX] {
        let mut bytes = [0xa5; 100];
        assert!(ntcp_ip6::encode_shared_header(&mut bytes, tx(true, 100), bad).is_err());
        assert_eq!(bytes, [0xa5; 100]);
    }
}

//= https://www.rfc-editor.org/rfc/rfc8200#section-3
//= type=test
//# Version 4-bit Internet Protocol version number = 6.
//= https://www.rfc-editor.org/rfc/rfc8200#section-3
//= type=test
//# Traffic Class 8-bit Traffic Class field. See Section 7.
//= https://www.rfc-editor.org/rfc/rfc8200#section-3
//= type=test
//# Flow Label 20-bit flow label. See Section 6.
//= https://www.rfc-editor.org/rfc/rfc8200#section-3
//= type=test
//# Source Address 128-bit address of the originator of the packet. See
//# [RFC4291].
//= https://www.rfc-editor.org/rfc/rfc8200#section-3
//= type=test
//# Destination Address 128-bit address of the intended recipient of the
//# packet (possibly not the ultimate recipient, if a Routing header is
//# present). See [RFC4291] and Section 4.4.
//= https://www.rfc-editor.org/rfc/rfc8200#section-3
//= type=test
//# Next Header 8-bit selector. Identifies the type of header immediately
//# following the IPv6 header. Uses the same values as the IPv4 Protocol
//# field [IANA-PN].
#[test]
fn base_header_fields_and_checked_quotes() {
    let mut t = tx(true, 20);
    t.ip.source = "2001:db8:1234:5678:9abc:def0:1357:2468".parse().unwrap();
    t.ip.destination = "fedc:ba98:7654:3210:ffff:eeee:dddd:cccc".parse().unwrap();
    let mut bytes = [0xa5; 60];
    for class in 0..=255u8 {
        t.dscp = class >> 2;
        t.ecn = class & 3;
        assert_eq!(encode(&mut bytes, t).unwrap(), 60);
        assert_eq!(bytes[0] >> 4, 6);
        assert_eq!((bytes[0] << 4) | (bytes[1] >> 4), class);
        assert_eq!(&bytes[1..4], &[class << 4, 0, 0]);
        let std::net::IpAddr::V6(source) = t.ip.source else {
            unreachable!()
        };
        let std::net::IpAddr::V6(destination) = t.ip.destination else {
            unreachable!()
        };
        assert_eq!(&bytes[8..24], &source.octets());
        assert_eq!(&bytes[24..40], &destination.octets());
        assert_eq!(bytes[6], 6);
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.ip, t.ip);
        assert_eq!(parsed.traffic_class, class);
        assert_eq!(parsed.protocol, 6);
        assert_eq!(parsed.payload, &[0xa5; 20]);
        assert_eq!(ntcp_ip6::quote_header(&bytes[..40]).unwrap(), (t.ip, 40, 60, 6));
        // The parser ignores all 20 flow bits without leaking them into class.
        bytes[1] |= 0x0f;
        bytes[2..4].fill(0xff);
        assert_eq!(parse(&bytes).unwrap().traffic_class, class);
        assert_eq!(parse(&bytes).unwrap().ip, t.ip);
    }
    for version in 0..16 {
        if version == 6 {
            continue;
        }
        bytes[0] = (version << 4) | 0x0f;
        assert_eq!(parse(&bytes).unwrap_err(), Error::Version);
        assert_eq!(ntcp_ip6::quote_header(&bytes[..40]).unwrap_err(), Error::Version);
    }
    bytes[0] = 0x6f;
    for protocol in 0..=255u8 {
        bytes[6] = protocol;
        match protocol {
            // 0xa5 data reads as a later fragment's Fragment header.
            44 => {
                assert_eq!(parse(&bytes).unwrap_err(), Error::FragmentationUnsupported);
                assert_eq!(
                    ntcp_ip6::quote_header(&bytes).unwrap_err(),
                    Error::FragmentationUnsupported
                );
            }
            // 0xa5 data reads as a Hdr Ext Len past the declared payload.
            0 | 43 | 60 => {
                assert_eq!(parse(&bytes).unwrap_err(), Error::Length);
                assert_eq!(ntcp_ip6::quote_header(&bytes).unwrap_err(), Error::Length);
            }
            _ => {
                assert_eq!(parse(&bytes).unwrap().protocol, protocol);
                assert_eq!(ntcp_ip6::quote_header(&bytes[..40]).unwrap(), (t.ip, 40, 60, protocol));
            }
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc8200#section-3
//= type=test
//= reason=This destination codec preserves all Hop Limit values, including zero, while checking structure and declared length. Forwarding and decrement rules remain outside the existing endpoint scope; originating parameter policy is unchanged.
//# Hop Limit 8-bit unsigned integer. Decremented by 1 by each node that
//# forwards the packet. When forwarding, the packet is discarded if Hop
//# Limit was zero when received or is decremented to zero. A node that is
//# the destination of a packet should not discard a packet with Hop Limit
//# equal to zero; it should process the packet normally.
#[test]
fn destination_hop_limit_zero_is_processed_normally() {
    // Construct the receive boundary independently of originating policy.
    let mut bytes = [0xa5; 60];
    bytes[..8].copy_from_slice(&[0x69, 0x70, 0, 0, 0, 20, 6, 0]);
    bytes[8..24].copy_from_slice(
        &"2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets(),
    );
    bytes[24..40].copy_from_slice(
        &"2001:db8::2".parse::<std::net::Ipv6Addr>().unwrap().octets(),
    );
    let mut t = tx(true, 20);
    for hop in [0, 1, 64, 255] {
        bytes[7] = hop;
        let before = bytes;
        let packet = parse(&bytes).unwrap();
        assert_eq!(packet.hop_limit, hop);
        assert_eq!(packet.ip, t.ip);
        assert_eq!(packet.traffic_class, 0x97);
        assert_eq!(packet.protocol, 6);
        assert_eq!(packet.payload, &[0xa5; 20]);
        for cut in [40, 48, 60] {
            assert_eq!(
                ntcp_ip6::quote_header(&bytes[..cut]).unwrap(),
                (t.ip, 40, 60, 6)
            );
        }
        assert_eq!(bytes, before);
        assert_eq!(parse(&bytes[..39]).unwrap_err(), Error::Truncated);
        assert_eq!(parse(&bytes[..59]).unwrap_err(), Error::Length);
        let mut bad = bytes;
        bad[0] = 0x49;
        assert_eq!(parse(&bad).unwrap_err(), Error::Version);
        for length in [0u16, 19, 21] {
            let mut bad = bytes;
            bad[4..6].copy_from_slice(&length.to_be_bytes());
            assert_eq!(parse(&bad).unwrap_err(), Error::Length);
        }
    }
    for hop in [1, 64, 255] {
        t.hop_limit = hop;
        encode(&mut bytes, t).unwrap();
        assert_eq!(bytes[7], hop);
        assert_eq!(parse(&bytes).unwrap().hop_limit, hop);
    }
    t.hop_limit = 0;
    let before = bytes;
    assert_eq!(encode(&mut bytes, t).unwrap_err(), Error::Invalid);
    assert_eq!(bytes, before);
}

//= https://www.rfc-editor.org/rfc/rfc8200#section-3
//= type=test
//= reason=Declared packet length is 40 plus the full unsigned 16-bit field, including zero, and bounds every extension header, which is counted inside it; complete frames require exact bounds and checked quotes retain the original length when truncated. Jumbo Payload options remain unsupported and are refused as unrecognized options.
//# Payload Length 16-bit unsigned integer. Length of the IPv6 payload,
//# i.e., the rest of the packet following this IPv6 header, in octets.
//# (Note that any extension headers (see Section 4) present are considered
//# part of the payload, i.e., included in the length count.)
//= https://www.rfc-editor.org/rfc/rfc8200#section-4.7
//= type=test
//= reason=Selector 59 in the base header or any traversed extension header ends the chain after exact declared-bound checks: no transport payload is exposed and the borrowed input bytes and quoted length/protocol remain intact. Forwarding remains outside the existing endpoint scope.
//# The value 59 in the Next Header field of an IPv6 header or any
//# extension header indicates that there is nothing following that
//# header. If the Payload Length field of the IPv6 header indicates the
//# presence of octets past the end of a header whose Next Header field
//# contains 59, those octets must be ignored and passed on unchanged if
//# the packet is forwarded.
#[test]
fn payload_length_zero_and_no_next_header_boundaries() {
    for payload in [1, 20, 65535] {
        let mut bytes = vec![0xa5; 40 + payload];
        let t = tx(true, payload);
        assert_eq!(encode(&mut bytes, t).unwrap(), 40 + payload);
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]) as usize, payload);
        for protocol in [6, 58, 59, 253] {
            bytes[6] = protocol;
            let before = bytes.clone();
            let parsed = parse(&bytes).unwrap();
            assert_eq!(parsed.protocol, protocol);
            assert_eq!(
                parsed.payload,
                if protocol == 59 { &[][..] } else { &bytes[40..] }
            );
            for cut in [40, 40 + payload / 2, bytes.len()] {
                assert_eq!(
                    ntcp_ip6::quote_header(&bytes[..cut]).unwrap(),
                    (t.ip, 40, 40 + payload, protocol)
                );
            }
            assert_eq!(bytes, before);
            assert_eq!(parse(&bytes[..bytes.len() - 1]).unwrap_err(), Error::Length);
            bytes.push(0);
            assert_eq!(parse(&bytes).unwrap_err(), Error::Length);
            bytes.pop();
        }
    }
    // No extension header or Jumbo Payload option exists in this empty base
    // packet. TCP, ICMP and unknown selectors defer their header checks upward.
    let mut bytes = [0; 40];
    bytes[0] = 0x60;
    for hop in [0, 1, 64, 255] {
        bytes[7] = hop;
        for protocol in 0..=255u8 {
            bytes[6] = protocol;
            let before = bytes;
            match protocol {
                // An empty payload cannot hold any extension header; the
                // Payload Length field is at fault.
                0 | 43 | 44 | 60 => {
                    assert_eq!(parse(&bytes).unwrap_err(), Error::Length);
                    assert_eq!(ntcp_ip6::quote_header(&bytes).unwrap_err(), Error::Length);
                    assert_eq!(
                        ntcp_ip6::Chain::receive(&bytes).unwrap_err(),
                        ntcp_ip6::Fault::Length { pointer: 4 }
                    );
                }
                _ => {
                    let parsed = parse(&bytes).unwrap();
                    assert_eq!(parsed.hop_limit, hop);
                    assert_eq!(parsed.protocol, protocol);
                    assert!(parsed.payload.is_empty());
                    assert_eq!(
                        ntcp_ip6::quote_header(&bytes).unwrap(),
                        (parsed.ip, 40, 40, protocol)
                    );
                    if protocol == 6 {
                        assert!(matches!(
                            ntcp::wire::parse(parsed.ip, parsed.payload),
                            Err(ntcp::wire::WireError::Truncated)
                        ));
                    }
                    let mut extra = bytes.to_vec();
                    extra.push(0xa5);
                    assert_eq!(parse(&extra).unwrap_err(), Error::Length);
                    let mut truncated = bytes;
                    truncated[4..6].copy_from_slice(&1u16.to_be_bytes());
                    assert_eq!(parse(&truncated).unwrap_err(), Error::Length);
                    assert_eq!(
                        ntcp_ip6::quote_header(&truncated).unwrap(),
                        (parsed.ip, 40, 41, protocol)
                    );
                }
            }
            assert_eq!(bytes, before);
        }
    }
    // A jumbogram's zero Payload Length leaves no room for the Hop-by-Hop
    // header that would carry its Jumbo Payload option, so neither complete
    // packets nor truncated quotes reach the option.
    let mut jumbo = vec![0; 40 + 65536];
    jumbo[0] = 0x60;
    jumbo[7] = 64;
    jumbo[40..48].copy_from_slice(&[6, 0, 0xc2, 4, 0, 1, 0, 0]);
    assert_eq!(parse(&jumbo).unwrap_err(), Error::Length);
    assert_eq!(
        ntcp_ip6::quote_header(&jumbo[..48]).unwrap_err(),
        Error::Length
    );
    // Within a declared payload the option is unrecognized (RFC 2675's
    // action bits 11): discarded with a Code 2 report at its type octet.
    jumbo[4..6].copy_from_slice(&8u16.to_be_bytes());
    assert_eq!(parse(&jumbo[..48]).unwrap_err(), Error::Options);
    assert_eq!(
        ntcp_ip6::Chain::receive(&jumbo[..48]).unwrap_err(),
        ntcp_ip6::Fault::Option {
            pointer: 42,
            action: ntcp_ip6::OptionAction::ReportUnlessMulticast
        }
    );
    let before = bytes;
    assert_eq!(encode(&mut bytes, tx(true, 0)).unwrap_err(), Error::Invalid);
    assert_eq!(bytes, before);
}
