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
    }
}
fn seal(b: &mut [u8]) {
    b[10..12].fill(0);
    let sum = checksum(&b[..usize::from(b[0] & 15) * 4]);
    b[10..12].copy_from_slice(&sum.to_be_bytes());
}
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
