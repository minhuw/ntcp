use ntcp_ip_common::Error;
use ntcp_ip6::{encode, parse};
#[path = "../../ntcp-ip/tests/support/mod.rs"]
mod support;
use support::tx;
#[test]
fn fullwidth_and_malformed_frames() {
    for v6 in [true] {
        let header = if v6 { 40 } else { 20 };
        let max_payload = if v6 { 65535 } else { 65535 - 20 };
        let mut b = vec![0xa5; header + max_payload + 1];
        let len = encode(&mut b, tx(v6, max_payload)).unwrap();
        let p = parse(&b[..len]).unwrap();
        assert_eq!(p.payload.len(), max_payload);
        assert_eq!(p.ip, tx(v6, 0).ip);
        assert_eq!(p.traffic_class, (37 << 2) | 3);
        assert_eq!(p.hop_limit, 64);
        assert_eq!(parse(&b[..len + 1]).unwrap_err(), Error::Length);
        for cut in [0, 1, header - 1, header, len - 1] {
            assert!(parse(&b[..cut]).is_err());
        }
        let before = b.clone();
        for size in [max_payload + 1, usize::MAX] {
            assert!(encode(&mut b, tx(v6, size)).is_err());
            assert_eq!(b, before);
        }
        for (dscp, ecn, hop) in [(64, 0, 1), (0, 4, 1), (0, 0, 0)] {
            let mut t = tx(v6, 20);
            t.dscp = dscp;
            t.ecn = ecn;
            t.hop_limit = hop;
            assert!(encode(&mut b, t).is_err());
            assert_eq!(b, before);
        }
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
