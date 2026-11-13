use ntcp::{IpMetadata, OutgoingIpv4Options, Transmit};
use ntcp_ip::{encode, parse};
use ntcp_ip_common::{Error, checksum};
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
fn seal(b: &mut [u8]) {
    b[10..12].fill(0);
    let sum = checksum(&b[..usize::from(b[0] & 15) * 4]);
    b[10..12].copy_from_slice(&sum.to_be_bytes());
}
//= https://www.rfc-editor.org/rfc/rfc791#section-3.1
//= type=test
//# Total Length is the length of the datagram, measured in octets, including
//# internet header and data. This field allows the length of a datagram to
//# be up to 65,535 octets.
#[test]
fn fullwidth_and_malformed_frames() {
    let header = 20;
    let max_payload = 65535 - 20;
    let mut b = vec![0xa5; header + max_payload + 1];
    let len = encode(&mut b, tx(false, max_payload), 0).unwrap();
    let p = parse(&b[..len], false).unwrap();
    assert_eq!(p.payload.len(), max_payload);
    assert_eq!(p.ip, tx(false, 0).ip);
    assert_eq!(p.traffic_class, (37 << 2) | 3);
    assert_eq!(p.hop_limit, 64);
    assert_eq!(parse(&b[..len + 1], false).unwrap_err(), Error::Length);
    for cut in [0, 1, header - 1, header, len - 1] {
        assert!(parse(&b[..cut], false).is_err());
    }
    let before = b.clone();
    for size in [max_payload + 1, usize::MAX] {
        assert!(encode(&mut b, tx(false, size), 0).is_err());
        assert_eq!(b, before);
    }
    for (dscp, ecn, hop) in [(64, 0, 1), (0, 4, 1), (0, 0, 0)] {
        let mut t = tx(false, 20);
        t.dscp = dscp;
        t.ecn = ecn;
        t.hop_limit = hop;
        assert!(encode(&mut b, t, 0).is_err());
        assert_eq!(b, before);
    }
    let mut b = [0; 60];
    let len = encode(&mut b, tx(false, 20), 0).unwrap();
    for flags in [0x8000u16, 0x2000, 1, 0x4001] {
        b[6..8].copy_from_slice(&flags.to_be_bytes());
        seal(&mut b);
        assert_eq!(
            parse(&b[..len], false).unwrap_err(),
            Error::FragmentationUnsupported
        );
    }
    encode(&mut b, tx(false, 20), 0).unwrap();
    b[8] ^= 1;
    assert_eq!(parse(&b[..len], false).unwrap_err(), Error::Checksum);
}

// The header checksum is verified once per packet: by `parse`,
// `parse_fragment`, `ipv4_bounds`, `ipv4_fragment_bounds` and
// `quote_header`, never by the variants for a packet the receive path
// verified (`parse_received`, `ipv4_received_bounds`) or this host encoded
// (`egress_header`), which keep every other check.
#[test]
fn received_and_egress_variants_skip_only_the_checksum() {
    let mut b = [0; 60];
    let len = encode(&mut b, tx(false, 20), 0).unwrap();
    let good = b;
    b[11] ^= 0x40;
    assert_eq!(parse(&b[..len], false).unwrap_err(), Error::Checksum);
    assert_eq!(
        ntcp_ip::parse_fragment(&b[..len], false).unwrap_err(),
        Error::Checksum
    );
    assert_eq!(
        ntcp_ip::ipv4_fragment_bounds(&b[..len]).unwrap_err(),
        Error::Checksum
    );
    assert_eq!(
        ntcp_ip::quote_header(&b[..len]).unwrap_err(),
        Error::Checksum
    );
    let p = ntcp_ip::parse_received(&b[..len], false).unwrap();
    let q = parse(&good[..len], false).unwrap();
    assert_eq!((p.ip, p.protocol, p.payload), (q.ip, q.protocol, q.payload));
    assert_eq!(
        ntcp_ip::ipv4_received_bounds(&b[..len]).unwrap(),
        ntcp_ip::ipv4_fragment_bounds(&good[..len]).unwrap()
    );
    assert_eq!(
        ntcp_ip::egress_header(&b[..len]).unwrap(),
        ntcp_ip::quote_header(&good[..len]).unwrap()
    );
    // Every other refusal stays.
    assert_eq!(
        ntcp_ip::parse_received(&b[..len + 1], false).unwrap_err(),
        Error::Length
    );
    let fragment = Error::FragmentationUnsupported;
    for (at, value, atomic, received) in [
        (0, 0x65, Error::Version, Some(Error::Version)),
        (0, 0x44, Error::Length, Some(Error::Length)),
        // The reserved flag, and MF, which only the fragment API admits.
        (6, 0xc0, fragment, Some(Error::Invalid)),
        (6, 0x20, fragment, None),
    ] {
        let mut bad = b;
        bad[at] = value;
        assert_eq!(
            ntcp_ip::parse_received(&bad[..len], false).unwrap_err(),
            atomic
        );
        assert_eq!(ntcp_ip::egress_header(&bad[..len]).unwrap_err(), atomic);
        assert_eq!(ntcp_ip::ipv4_received_bounds(&bad[..len]).err(), received);
    }
    for cut in 0..20 {
        assert!(ntcp_ip::parse_received(&b[..cut], false).is_err());
        assert!(ntcp_ip::ipv4_received_bounds(&b[..cut]).is_err());
        assert!(ntcp_ip::egress_header(&b[..cut]).is_err());
    }
}

#[test]
fn checked_headers_and_wrong_family() {
    let mut bytes = [0; 60];
    let len = encode(&mut bytes, tx(false, 20), 0).unwrap();
    for cut in 0..20 {
        assert!(ntcp_ip::ipv4_bounds(&bytes[..cut]).is_err());
        assert!(ntcp_ip::quote_header(&bytes[..cut]).is_err());
    }
    assert!(ntcp_ip::ipv4_bounds(&bytes[..len]).is_ok());
    assert!(ntcp_ip::quote_header(&bytes[..20]).is_ok());
    let before = bytes;
    assert_eq!(
        encode(&mut bytes, tx(true, 20), 0).unwrap_err(),
        Error::Version
    );
    assert_eq!(bytes, before);
}

//= https://www.rfc-editor.org/rfc/rfc791#section-3.1
//= type=test
//# The Version field indicates the format of the internet header. This
//# document describes version 4.

//= https://www.rfc-editor.org/rfc/rfc791#section-3.1
//= type=test
//# Internet Header Length is the length of the internet header in 32 bit
//# words, and thus points to the beginning of the data. Note that the
//# minimum value for a correct header is 5.

//= https://www.rfc-editor.org/rfc/rfc791#section-3.1
//= type=test
//# This field indicates the next level protocol used in the data portion of
//# the internet datagram. The values for various protocols are specified in
//# "Assigned Numbers" [9].

//= https://www.rfc-editor.org/rfc/rfc791#section-3.1
//= type=test
//# The checksum field is the 16 bit one's complement of the one's complement
//# sum of all 16 bit words in the header. For purposes of computing the
//# checksum, the value of the checksum field is zero.

//= https://www.rfc-editor.org/rfc/rfc791#section-1.4
//= type=test
//# The Header Checksum provides a verification that the information used in
//# processing internet datagram has been transmitted correctly. The data may
//# contain errors. If the header checksum fails, the internet datagram is
//# discarded at once by the entity which detects the error.

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.1
//= type=test
//# A datagram whose version number is not 4 MUST be silently discarded.

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.2
//= type=test
//# A host MUST verify the IP header checksum on every received datagram and
//# silently discard every datagram that has a bad checksum.
#[test]
fn ipv4_header_fields_lengths_and_checksum() {
    let mut transmit = tx(false, 7);
    transmit.ipv4_options.record_route_slots = Some(2);
    transmit.ipv4_options.timestamp = Some(ntcp::TimestampRequest::Times(1));
    let mut bytes = [0xa5; 80];
    let len = encode(&mut bytes, transmit, 123).unwrap();
    let header = usize::from(bytes[0] & 15) * 4;
    assert_eq!(bytes[0] >> 4, 4);
    assert_eq!(header, 40);
    assert_eq!(usize::from(u16::from_be_bytes([bytes[2], bytes[3]])), len);
    assert_eq!(len, header + 7);
    assert_eq!(bytes[9], 6);
    assert_eq!(&bytes[12..20], &[192, 0, 2, 1, 192, 0, 2, 2]);
    let parsed = parse(&bytes[..len], false).unwrap();
    assert_eq!(parsed.payload, &[0xa5; 7]);
    assert_eq!(parsed.protocol, 6);
    assert_eq!(parsed.ip, transmit.ip);
    // Independent reference, without using the codec's checksum routine.
    let mut zeroed = bytes[..header].to_vec();
    let emitted = u16::from_be_bytes([zeroed[10], zeroed[11]]);
    zeroed[10..12].fill(0);
    let sum: u64 = zeroed
        .chunks_exact(2)
        .map(|p| u64::from(u16::from_be_bytes([p[0], p[1]])))
        .sum();
    let folded = (sum & 0xffff) + (sum >> 16);
    let folded = (folded & 0xffff) + (folded >> 16);
    assert_eq!(emitted, !(folded as u16));
    assert_eq!(checksum(&bytes[..header]), 0);
    for index in [8, 12, 23, header - 1] {
        let mut bad = bytes;
        bad[index] ^= 1;
        assert_eq!(parse(&bad[..len], false).unwrap_err(), Error::Checksum);
        assert_eq!(
            ntcp_ip::quote_header(&bad[..header]).unwrap_err(),
            Error::Checksum
        );
    }
    let mut changed_data = bytes;
    changed_data[header] ^= 1;
    assert!(parse(&changed_data[..len], false).is_ok());
    for version in 0..16 {
        if version == 4 {
            continue;
        }
        let mut bad = bytes;
        bad[0] = (version << 4) | (bytes[0] & 15);
        seal(&mut bad);
        assert_eq!(parse(&bad[..len], false).unwrap_err(), Error::Version);
    }
    for words in 0..5 {
        let mut bad = bytes;
        bad[0] = 0x40 | words;
        assert_eq!(parse(&bad[..len], false).unwrap_err(), Error::Length);
    }
    for words in 5..=15 {
        let h = words * 4;
        let mut frame = vec![1; h + 9];
        frame[..20].copy_from_slice(&bytes[..20]);
        frame[0] = 0x40 | words as u8;
        frame[2..4].copy_from_slice(&((h + 9) as u16).to_be_bytes());
        frame[h..].fill(0x5a);
        seal(&mut frame);
        assert_eq!(ntcp_ip::ipv4_bounds(&frame).unwrap(), (h, h + 9));
        assert_eq!(parse(&frame, false).unwrap().payload, &[0x5a; 9]);
        for declared in [h - 1, h + 8, h + 10] {
            let mut bad = frame.clone();
            bad[2..4].copy_from_slice(&(declared as u16).to_be_bytes());
            seal(&mut bad);
            assert_eq!(parse(&bad, false).unwrap_err(), Error::Length);
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc791#section-3.1
//= type=test
//# Bit 0: reserved, must be zero
//# Bit 1: (DF) 0 = May Fragment, 1 = Don't Fragment.
//# Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments.

//= https://www.rfc-editor.org/rfc/rfc6864#section-4
//= type=test
//# Atomic datagrams: (DF==1)&&(MF==0)&&(frag_offset==0)

//= https://www.rfc-editor.org/rfc/rfc6864#section-4.1
//= type=test
//# The IPv4 ID field MUST NOT be used for purposes other than fragmentation
//# and reassembly.

//= https://www.rfc-editor.org/rfc/rfc6864#section-4.1
//= type=test
//# Originating sources MAY set the IPv4 ID field of atomic datagrams to any
//# value.

//= https://www.rfc-editor.org/rfc/rfc6864#section-4.1
//= type=test
//# All devices that examine IPv4 headers MUST ignore the IPv4 ID field of
//# atomic datagrams.
#[test]
fn atomic_identification_is_arbitrary_and_ignored() {
    let mut bytes = [0xa5; 80];
    let mut transmit = tx(false, 20);
    transmit.ipv4_options.record_route_slots = Some(2);
    let len = encode(&mut bytes, transmit, 0).unwrap();
    let header = usize::from(bytes[0] & 15) * 4;
    assert_eq!(&bytes[4..8], &[0, 0, 0x40, 0]);
    let expected = parse(&bytes[..len], false).unwrap();
    let quote = ntcp_ip::quote_header(&bytes[..header]).unwrap();
    for id in [0u16, 1, 0x1234, 0xffff] {
        let mut changed = bytes;
        changed[4..6].copy_from_slice(&id.to_be_bytes());
        seal(&mut changed);
        assert_eq!(checksum(&changed[..header]), 0);
        let actual = parse(&changed[..len], false).unwrap();
        assert_eq!(actual.ip, expected.ip);
        assert_eq!(actual.traffic_class, expected.traffic_class);
        assert_eq!(actual.hop_limit, expected.hop_limit);
        assert_eq!(actual.protocol, expected.protocol);
        assert_eq!(actual.ipv4_options, expected.ipv4_options);
        assert_eq!(actual.payload, expected.payload);
        assert_eq!(ntcp_ip::quote_header(&changed[..header]).unwrap(), quote);
    }
    for flags in [0x8000u16, 0x2000, 1, 0x4001] {
        let mut changed = bytes;
        changed[6..8].copy_from_slice(&flags.to_be_bytes());
        seal(&mut changed);
        assert_eq!(
            parse(&changed[..len], false).unwrap_err(),
            Error::FragmentationUnsupported
        );
    }
    for payload in [0x55, 0xaa] {
        let mut next = [payload; 80];
        encode(&mut next, transmit, 0).unwrap();
        assert_eq!(&next[4..8], &[0, 0, 0x40, 0]);
    }
}

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.7
//= type=test
//# A host MUST NOT send a datagram with a Time-to-Live (TTL) value of zero.

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.7
//= type=test
//= reason=Endpoint parsing accepts every TTL, including zero and one, after structural and checksum validation; originating TTL zero remains invalid.
//# A host MUST NOT discard a datagram just because it was received with TTL
//# less than 2.

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.7
//= type=test
//# The IP layer MUST provide a means for the transport layer to set the TTL
//# field of every datagram that is sent. When a fixed TTL value is used, it
//# MUST be configurable. The current suggested value will be published in
//# the "Assigned Numbers" RFC.
#[test]
fn ipv4_ttl_parameters_and_receive_zero_boundary() {
    let mut bytes = [0xa5; 60];
    let mut transmit = tx(false, 20);
    transmit.hop_limit = 0;
    assert_eq!(encode(&mut bytes, transmit, 0), Err(Error::Invalid));
    assert_eq!(bytes, [0xa5; 60]);
    for ttl in [1, 64, 255] {
        transmit.hop_limit = ttl;
        let len = encode(&mut bytes, transmit, 0).unwrap();
        assert_eq!(bytes[8], ttl);
        assert_eq!(parse(&bytes[..len], false).unwrap().hop_limit, ttl);
    }
    // Construct received headers directly: the originating API prohibits TTL 0.
    bytes[..20].copy_from_slice(&[
        0x45, 0x97, 0, 40, 0, 0, 0x40, 0, 0, 6, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
    ]);
    for ttl in [0, 1, 64, 255] {
        bytes[8] = ttl;
        seal(&mut bytes);
        let before = bytes;
        assert_eq!(checksum(&bytes[..20]), 0);
        let packet = parse(&bytes[..40], false).unwrap();
        assert_eq!(packet.hop_limit, ttl);
        assert_eq!(packet.ip, transmit.ip);
        assert_eq!(packet.protocol, 6);
        assert_eq!(packet.traffic_class, 0x97);
        assert_eq!(packet.payload, &[0xa5; 20]);
        for cut in [20, 28, 40] {
            assert_eq!(
                ntcp_ip::quote_header(&bytes[..cut]).unwrap(),
                (transmit.ip, 20, 40, 6)
            );
        }
        assert_eq!(bytes, before);

        let mut bad = bytes;
        bad[12] ^= 1;
        assert_eq!(parse(&bad[..40], false).unwrap_err(), Error::Checksum);
        assert_eq!(
            ntcp_ip::quote_header(&bad[..20]).unwrap_err(),
            Error::Checksum
        );
        bad = bytes;
        bad[0] = 0x65;
        seal(&mut bad);
        assert_eq!(parse(&bad[..40], false).unwrap_err(), Error::Version);
        for declared in [19u16, 39, 41] {
            let mut bad = bytes;
            bad[2..4].copy_from_slice(&declared.to_be_bytes());
            seal(&mut bad);
            assert_eq!(parse(&bad[..40], false).unwrap_err(), Error::Length);
        }
        for flags in [0x8000u16, 0x2000, 1, 0x4001] {
            let mut bad = bytes;
            bad[6..8].copy_from_slice(&flags.to_be_bytes());
            seal(&mut bad);
            assert_eq!(
                parse(&bad[..40], false).unwrap_err(),
                Error::FragmentationUnsupported
            );
            assert_eq!(
                ntcp_ip::quote_header(&bad[..20]).unwrap_err(),
                Error::FragmentationUnsupported
            );
        }
        assert_eq!(parse(&bytes[..19], false).unwrap_err(), Error::Truncated);
        assert_eq!(parse(&bytes[..39], false).unwrap_err(), Error::Length);
        assert_eq!(parse(&bytes[..41], false).unwrap_err(), Error::Length);
    }
}

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
//= type=test
//# A host MUST support originating a source route and MUST be able to act as
//# the final destination of a source route.

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
//= type=test
//# If host receives a datagram containing a completed source route (i.e.,
//# the pointer points beyond the last field), the datagram has reached
//# its final destination; the option as received (the recorded route)
//# MUST be passed up to the transport layer (or to ICMP message
//# processing). This recorded route will be reversed and used to form a
//# return source route for reply datagrams (see discussion of IP Options
//# in Section 4). When a return source route is built, it MUST be
//# correctly formed even if the recorded route included the source host
//# (see case (B) in the discussion below).

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
//= type=test
//# An IP header containing more than one Source Route option MUST NOT be
//# sent; the effect on routing of multiple Source Route options is
//# implementation-specific.
#[test]
fn completed_source_routes_and_old_encoding_form_return_headers() {
    use core::net::Ipv4Addr;
    let source = Ipv4Addr::new(192, 0, 2, 1);
    let destination = Ipv4Addr::new(192, 0, 2, 2);
    let g1 = Ipv4Addr::new(192, 0, 2, 3);
    let g2 = Ipv4Addr::new(192, 0, 2, 4);
    for strict in [false, true] {
        let mut outgoing = tx(false, 8);
        outgoing.ipv4_options.source_route =
            Some(ntcp::SourceRoute::new(&[g1, g2], strict).unwrap());
        let mut original = [0xa5; 80];
        let len = encode(&mut original, outgoing, 0).unwrap();
        assert_eq!(&original[16..20], &g1.octets());
        assert_eq!(&original[20..23], &[if strict { 137 } else { 131 }, 11, 4]);
        assert_eq!(&original[23..27], &g2.octets());
        assert_eq!(&original[27..31], &destination.octets());
        assert_eq!(len, 32 + 8);
        // Model received headers, without claiming intermediate-hop forwarding.
        for old_encoding in [false, true] {
            let recorded: &[Ipv4Addr] = if old_encoding {
                &[source, g1, g2]
            } else {
                &[g1, g2]
            };
            let option_len = 3 + recorded.len() * 4;
            let header = 20 + ((option_len + 3) & !3);
            let mut frame = vec![0; header + 8];
            frame[..20].copy_from_slice(&original[..20]);
            frame[0] = 0x40 | (header / 4) as u8;
            frame[2..4].copy_from_slice(&((header + 8) as u16).to_be_bytes());
            frame[16..20].copy_from_slice(&destination.octets());
            frame[20..23].copy_from_slice(&[
                if strict { 137 } else { 131 },
                option_len as u8,
                (option_len + 1) as u8,
            ]);
            for (i, hop) in recorded.iter().enumerate() {
                frame[23 + i * 4..27 + i * 4].copy_from_slice(&hop.octets());
            }
            seal(&mut frame);
            let incoming = parse(&frame, true).unwrap();
            assert_eq!(incoming.ip.destination, core::net::IpAddr::V4(destination));
            assert_eq!(
                incoming.ipv4_options.as_bytes(),
                &frame[20..20 + option_len]
            );
            let route = incoming.ipv4_options.return_route(source).unwrap();
            assert_eq!(route.hops(), &[g2, g1]);
            assert_eq!(route.strict, strict);
            let mut reply = tx(false, 8);
            reply.ip = IpMetadata {
                source: destination.into(),
                destination: source.into(),
            };
            reply.ipv4_options.source_route = Some(route);
            let mut encoded = [0xa5; 80];
            let reply_len = encode(&mut encoded, reply, 0).unwrap();
            assert_eq!(reply_len, 32 + 8);
            assert_eq!(&encoded[16..20], &g2.octets());
            assert_eq!(&encoded[20..23], &[if strict { 137 } else { 131 }, 11, 4]);
            assert_eq!(&encoded[23..27], &g1.octets());
            assert_eq!(&encoded[27..31], &source.octets());
            assert_eq!(encoded[31], 0); // Exactly one option, then END/padding.
            assert_eq!(checksum(&encoded[..32]), 0);
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
//= type=test
//# There MUST be a means for the transport layer to specify IP options to be
//# included in transmitted IP datagrams (see Section 3.4).
#[test]
fn shared_headers_preserve_ip_options_and_full_wire_lengths_without_payload_copy() {
    for tcp_header in [20, 32, 60] {
        for payload_len in [1, 17, 1460] {
            for options in [
                ntcp::OutgoingIpv4Options::default(),
                ntcp::OutgoingIpv4Options {
                    record_route_slots: Some(2),
                    timestamp: Some(ntcp::TimestampRequest::Times(2)),
                    ..Default::default()
                },
            ] {
                let mut transmit = tx(false, tcp_header + payload_len);
                transmit.ipv4_options = options;
                let mut full = vec![0xa5; 60 + transmit.len];
                let total = encode(&mut full, transmit, 123).unwrap();
                let mut shared = vec![0xa5; 60 + tcp_header];
                let stored =
                    ntcp_ip::encode_shared_header(&mut shared, transmit, 123, tcp_header).unwrap();
                assert_eq!(&shared[..stored], &full[..stored]);
                assert_eq!(ntcp_ip::ipv4_bounds(&shared[..stored]).unwrap().1, total);
                assert!(shared[stored..].iter().all(|&b| b == 0xa5));
                assert_eq!(stored + payload_len, total);
            }
        }
    }
    let mut bytes = [0xa5; 80];
    for bad in [0, 19, 21, 61, usize::MAX] {
        assert!(ntcp_ip::encode_shared_header(&mut bytes, tx(false, 80), 0, bad).is_err());
        assert_eq!(bytes, [0xa5; 80]);
    }
}
