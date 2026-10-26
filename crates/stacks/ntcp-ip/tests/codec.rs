use ntcp_ip::{encode, parse};
use ntcp_ip_common::Error;
#[path = "../../ntcp-ip/tests/support/mod.rs"]
mod support;
use support::seal;
use support::tx;
#[test]
fn fullwidth_and_malformed_frames() {
    for v6 in [false] {
        let header = if v6 { 40 } else { 20 };
        let max_payload = if v6 { 65535 } else { 65535 - 20 };
        let mut b = vec![0xa5; header + max_payload + 1];
        let len = encode(&mut b, tx(v6, max_payload), 0).unwrap();
        let p = parse(&b[..len], false).unwrap();
        assert_eq!(p.payload.len(), max_payload);
        assert_eq!(p.ip, tx(v6, 0).ip);
        assert_eq!(p.traffic_class, (37 << 2) | 3);
        assert_eq!(p.hop_limit, 64);
        assert_eq!(parse(&b[..len + 1], false).unwrap_err(), Error::Length);
        for cut in [0, 1, header - 1, header, len - 1] {
            assert!(parse(&b[..cut], false).is_err());
        }
        let before = b.clone();
        for size in [max_payload + 1, usize::MAX] {
            assert!(encode(&mut b, tx(v6, size), 0).is_err());
            assert_eq!(b, before);
        }
        for (dscp, ecn, hop) in [(64, 0, 1), (0, 4, 1), (0, 0, 0)] {
            let mut t = tx(v6, 20);
            t.dscp = dscp;
            t.ecn = ecn;
            t.hop_limit = hop;
            assert!(encode(&mut b, t, 0).is_err());
            assert_eq!(b, before);
        }
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
