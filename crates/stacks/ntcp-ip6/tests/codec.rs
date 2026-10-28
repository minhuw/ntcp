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
    for next in [0, 43, 50, 51, 60, 135, 139, 140] {
        b[6] = next;
        assert_eq!(parse(&b).unwrap_err(), Error::ExtensionsUnsupported);
    }
    b[6] = 44;
    assert_eq!(parse(&b).unwrap_err(), Error::FragmentationUnsupported);
    b[4..6].fill(0);
    assert_eq!(parse(&b).unwrap_err(), Error::JumbogramsUnsupported);
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
            44 => assert_eq!(parse(&bytes).unwrap_err(), Error::FragmentationUnsupported),
            0 | 43 | 50 | 51 | 60 | 135 | 139 | 140 => {
                assert_eq!(parse(&bytes).unwrap_err(), Error::ExtensionsUnsupported);
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
//= reason=Live parse rejects Hop Limit zero as Invalid although the destination rule says to process it normally; checked quote parsing accepts zero. Tests pin zero rejection and positive 1/64/255 preservation. The whole receive obligation remains unresolved; forwarding/decrement behavior is outside the base endpoint codec and does not excuse the destination difference. Encoding also rejects zero; no production fix is authorized.
//# Hop Limit 8-bit unsigned integer. Decremented by 1 by each node that
//# forwards the packet. When forwarding, the packet is discarded if Hop
//# Limit was zero when received or is decremented to zero. A node that is
//# the destination of a packet should not discard a packet with Hop Limit
//# equal to zero; it should process the packet normally.
#[test]
fn destination_hop_limit_zero_remains_rejected() {
    let mut bytes = [0xa5; 60];
    let mut t = tx(true, 20);
    for hop in [1, 64, 255] {
        t.hop_limit = hop;
        encode(&mut bytes, t).unwrap();
        assert_eq!(bytes[7], hop);
        assert_eq!(parse(&bytes).unwrap().hop_limit, hop);
        assert_eq!(ntcp_ip6::quote_header(&bytes[..40]).unwrap(), (t.ip, 40, 60, 6));
    }
    // A complete, otherwise valid packet addressed to the endpoint, not a
    // forwarding fixture. This pins the known destination receive difference.
    bytes[7] = 0;
    assert_eq!(parse(&bytes).unwrap_err(), Error::Invalid);
    assert_eq!(ntcp_ip6::quote_header(&bytes[..40]).unwrap(), (t.ip, 40, 60, 6));
    t.hop_limit = 0;
    let before = bytes;
    assert_eq!(encode(&mut bytes, t).unwrap_err(), Error::Invalid);
    assert_eq!(bytes, before);
}

//= https://www.rfc-editor.org/rfc/rfc8200#section-3
//= type=test
//= reason=Positive lengths through 65535 and checked truncated quotes are implemented, but ipv6_bounds rejects every zero Payload Length as JumbogramsUnsupported, including a bare No Next Header packet without a Jumbo Payload option. Zero alone is not evidence of a jumbogram. Preserve the entire field definition including its extension-header qualification; extension processing remains an explicit unsupported boundary, not a justification for rejecting legal empty base packets.
//# Payload Length 16-bit unsigned integer. Length of the IPv6 payload,
//# i.e., the rest of the packet following this IPv6 header, in octets.
//# (Note that any extension headers (see Section 4) present are considered
//# part of the payload, i.e., included in the length count.)
//= https://www.rfc-editor.org/rfc/rfc8200#section-4.7
//= type=test
//= reason=A zero-length base packet with selector 59 is rejected as JumbogramsUnsupported. With a positive length, the codec exposes selector 59 and uninterpreted trailing bytes; this alone does not establish the entire ignore obligation. Tests pin both boundaries. Extension-header traversal and forwarding are outside this endpoint codec, but legal empty base packets remain a selected-scope gap.
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
        assert_eq!(parse(&bytes).unwrap().payload, &vec![0xa5; payload]);
        assert_eq!(ntcp_ip6::quote_header(&bytes[..40]).unwrap(), (t.ip, 40, 40 + payload, 6));
        assert_eq!(parse(&bytes[..bytes.len() - 1]).unwrap_err(), Error::Length);
        bytes.push(0);
        assert_eq!(parse(&bytes).unwrap_err(), Error::Length);
    }
    let mut bytes = [0xa5; 60];
    encode(&mut bytes, tx(true, 20)).unwrap();
    bytes[6] = 59;
    let before = bytes;
    let parsed = parse(&bytes).unwrap();
    assert_eq!(parsed.protocol, 59);
    assert_eq!(parsed.payload, &[0xa5; 20]);
    assert_eq!(ntcp_ip6::quote_header(&bytes[..40]).unwrap().3, 59);
    assert_eq!(bytes, before);
    // No extension header or Jumbo Payload option exists in these 40 bytes.
    bytes[4..6].fill(0);
    for protocol in [6, 59] {
        bytes[6] = protocol;
        assert_eq!(parse(&bytes[..40]).unwrap_err(), Error::JumbogramsUnsupported);
        assert_eq!(ntcp_ip6::ipv6_bounds(&bytes[..40]).unwrap_err(), Error::JumbogramsUnsupported);
        assert_eq!(ntcp_ip6::quote_header(&bytes[..40]).unwrap_err(), Error::JumbogramsUnsupported);
    }
    let before = bytes;
    assert_eq!(encode(&mut bytes, tx(true, 0)).unwrap_err(), Error::Invalid);
    assert_eq!(bytes, before);
}
