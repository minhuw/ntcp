// Redirect reception: IPv4 (RFC 792) and ICMPv6 (RFC 4861 section 8.1).
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ntcp::{IpMetadata, Transmit};
use ntcp_icmp::*;

const MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xb];

fn ip(source: &str, destination: &str) -> IpMetadata {
    IpMetadata {
        source: source.parse().unwrap(),
        destination: destination.parse().unwrap(),
    }
}

// A UDP datagram from `ip.source` to `ip.destination`, built by the
// production codecs.
fn datagram(ip: IpMetadata) -> Vec<u8> {
    let mut b = vec![0; 128];
    let n = match ip.source {
        IpAddr::V6(_) => {
            let header = ntcp_ip6::Header {
                ip,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
            };
            ntcp_ip6::encode_udp(&mut b, header, 4000, 53, 16).unwrap()
        }
        IpAddr::V4(_) => {
            let t = Transmit {
                connection: None,
                tx_timestamp: None,
                ip,
                len: 0,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: Default::default(),
            };
            ntcp_ip::encode_udp(&mut b, t.into(), 4000, 53, 16, 0).unwrap()
        }
    };
    b.truncate(n);
    b
}

fn ipv4_redirect(code: u8, gateway: Ipv4Addr, quoted: &[u8]) -> Vec<u8> {
    let mut m = vec![5, code, 0, 0];
    m.extend_from_slice(&gateway.octets());
    m.extend_from_slice(quoted);
    let sum = checksum(&m);
    m[2..4].copy_from_slice(&sum.to_be_bytes());
    m
}

fn reseal(ip: IpMetadata, message: &mut [u8]) {
    message[2..4].fill(0);
    let sum = icmpv6_checksum(ip, message).unwrap();
    message[2..4].copy_from_slice(&sum.to_be_bytes());
}

// An ICMPv6 Redirect with `options` (already in 8-octet units).
fn ipv6_redirect(
    ip: IpMetadata,
    target: Ipv6Addr,
    destination: Ipv6Addr,
    options: &[u8],
) -> Vec<u8> {
    let mut m = vec![137, 0, 0, 0, 0, 0, 0, 0];
    m.extend_from_slice(&target.octets());
    m.extend_from_slice(&destination.octets());
    m.extend_from_slice(options);
    reseal(ip, &mut m);
    m
}
fn tllao(mac: [u8; 6]) -> Vec<u8> {
    let mut o = vec![2, 1];
    o.extend_from_slice(&mac);
    o
}
// A Redirected Header carrying `packet` truncated to whole 8-octet units.
fn redirected(packet: &[u8]) -> Vec<u8> {
    let len = packet.len() / 8 * 8;
    let mut o = vec![4, (1 + len / 8) as u8, 0, 0, 0, 0, 0, 0];
    o.extend_from_slice(&packet[..len]);
    o
}

// Quotes are parsed by the family's codec feature.
#[cfg(feature = "ipv4")]
#[test]
fn ipv4_redirect_codes_gateway_and_quote() {
    let outer = ip("192.0.2.1", "192.0.2.10");
    let quoted = datagram(ip("192.0.2.10", "198.51.100.7"));
    let gateway = Ipv4Addr::new(192, 0, 2, 2);
    for (code, expected) in [
        (0, RedirectCode::Network),
        (1, RedirectCode::Host),
        (2, RedirectCode::NetworkAndTos),
        (3, RedirectCode::HostAndTos),
    ] {
        let redirect = decode_ipv4_redirect(outer, &ipv4_redirect(code, gateway, &quoted)).unwrap();
        assert_eq!((redirect.code, redirect.gateway), (expected, gateway));
        assert_eq!(redirect.code.type_of_service(), code >= 2);
        assert_eq!(redirect.quoted.ip, ip("192.0.2.10", "198.51.100.7"));
    }
    // Unknown code, bad checksum, truncation and another type.
    assert_eq!(
        decode_ipv4_redirect(outer, &ipv4_redirect(4, gateway, &quoted)),
        Err(Error::Invalid)
    );
    let mut bad = ipv4_redirect(1, gateway, &quoted);
    bad[9] ^= 1;
    assert_eq!(decode_ipv4_redirect(outer, &bad), Err(Error::Checksum));
    assert_eq!(
        decode_ipv4_redirect(outer, &[5, 1, 0]),
        Err(Error::Truncated)
    );
    let mut unreachable = ipv4_redirect(1, gateway, &quoted);
    unreachable[0] = 3;
    unreachable[2..4].fill(0);
    let sum = checksum(&unreachable);
    unreachable[2..4].copy_from_slice(&sum.to_be_bytes());
    assert_eq!(
        decode_ipv4_redirect(outer, &unreachable),
        Err(Error::ProtocolUnsupported)
    );
    // The quote must be of a datagram the Redirect's destination sent.
    let other = datagram(ip("192.0.2.11", "198.51.100.7"));
    assert_eq!(
        decode_ipv4_redirect(outer, &ipv4_redirect(1, gateway, &other)),
        Err(Error::Quote)
    );
    // A quote without its transport octets names nothing.
    assert!(decode_ipv4_redirect(outer, &ipv4_redirect(1, gateway, &quoted[..24])).is_err());
}

#[cfg(feature = "ipv6")]
#[test]
fn ipv6_redirect_with_and_without_options() {
    let outer = ip("fe80::1", "2001:db8::10");
    let destination: Ipv6Addr = "2001:db8:1::7".parse().unwrap();
    let router: Ipv6Addr = "fe80::2".parse().unwrap();
    let packet = datagram(ip("2001:db8::10", "2001:db8:1::7"));
    let mut options = tllao(MAC);
    // An unknown option is ignored.
    options.extend_from_slice(&[200, 1, 0, 0, 0, 0, 0, 0]);
    options.extend_from_slice(&redirected(&packet));
    let message = ipv6_redirect(outer, router, destination, &options);
    let redirect = decode_ipv6_redirect(outer, 255, &message).unwrap();
    assert_eq!(
        (
            redirect.target,
            redirect.destination,
            redirect.target_link_layer
        ),
        (router, destination, Some(MAC))
    );
    let (quote, option) = redirect.redirected.unwrap();
    assert_eq!(quote.ip, ip("2001:db8::10", "2001:db8:1::7"));
    assert_eq!(&option[8..], &packet[..packet.len() / 8 * 8]);
    // The destination itself is on-link; no option is required to decode.
    let message = ipv6_redirect(outer, destination, destination, &[]);
    let redirect = decode_ipv6_redirect(outer, 255, &message).unwrap();
    assert_eq!(redirect.target, destination);
    assert_eq!(
        (redirect.target_link_layer, redirect.redirected),
        (None, None)
    );
    // A Redirected Header quoting another node's packet is not usable.
    let foreign = datagram(ip("2001:db8::11", "2001:db8:1::7"));
    let message = ipv6_redirect(outer, router, destination, &redirected(&foreign));
    assert_eq!(
        decode_ipv6_redirect(outer, 255, &message)
            .unwrap()
            .redirected,
        None
    );
}

// A router may zero-pad a quoted packet that does not fill the option's
// last 8-octet unit (as BSD routers do); the padding is not quoted data.
#[cfg(feature = "ipv6")]
#[test]
fn ipv6_redirect_padded_quote() {
    let outer = ip("fe80::1", "2001:db8::10");
    let destination: Ipv6Addr = "2001:db8:1::7".parse().unwrap();
    let router: Ipv6Addr = "fe80::2".parse().unwrap();
    let mut packet = vec![0; 128];
    let header = ntcp_ip6::Header {
        ip: ip("2001:db8::10", "2001:db8:1::7"),
        hop_limit: 64,
        dscp: 0,
        ecn: 0,
    };
    let n = ntcp_ip6::encode_udp(&mut packet, header, 4000, 53, 13).unwrap();
    packet.truncate(n);
    assert_eq!(packet.len(), 61);
    let quote_option = |padding: usize| {
        let mut o = vec![
            4,
            ((8 + packet.len() + padding) / 8) as u8,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        o.extend_from_slice(&packet);
        o.resize(o.len() + padding, 0);
        o
    };
    let message = ipv6_redirect(outer, router, destination, &quote_option(3));
    let (quote, option) = decode_ipv6_redirect(outer, 255, &message)
        .unwrap()
        .redirected
        .unwrap();
    assert_eq!(quote.ip, ip("2001:db8::10", "2001:db8:1::7"));
    assert_eq!(quote.ip_packet_len, 61);
    assert_eq!(&option[8..], &packet[..]);
    // A whole unit beyond the quoted packet is not padding.
    let message = ipv6_redirect(outer, router, destination, &quote_option(11));
    assert_eq!(
        decode_ipv6_redirect(outer, 255, &message)
            .unwrap()
            .redirected,
        None
    );
}

#[test]
fn ipv6_redirect_validity_checks() {
    let outer = ip("fe80::1", "2001:db8::10");
    let destination: Ipv6Addr = "2001:db8:1::7".parse().unwrap();
    let router: Ipv6Addr = "fe80::2".parse().unwrap();
    let message = ipv6_redirect(outer, router, destination, &tllao(MAC));
    assert!(decode_ipv6_redirect(outer, 255, &message).is_ok());
    // Forwarded (Hop Limit), nonzero code, bad checksum, short.
    assert_eq!(
        decode_ipv6_redirect(outer, 254, &message),
        Err(Error::Invalid)
    );
    let mut coded = message.clone();
    coded[1] = 1;
    reseal(outer, &mut coded);
    assert_eq!(
        decode_ipv6_redirect(outer, 255, &coded),
        Err(Error::Invalid)
    );
    let mut bad = message.clone();
    bad[20] ^= 1;
    assert_eq!(decode_ipv6_redirect(outer, 255, &bad), Err(Error::Checksum));
    let mut short = message[..39].to_vec();
    reseal(outer, &mut short);
    assert_eq!(
        decode_ipv6_redirect(outer, 255, &short),
        Err(Error::Truncated)
    );
    // A global source is not a router on this link.
    let global = ip("2001:db8::1", "2001:db8::10");
    let message = ipv6_redirect(global, router, destination, &[]);
    assert_eq!(
        decode_ipv6_redirect(global, 255, &message),
        Err(Error::Invalid)
    );
    // A multicast destination; a global target that is not the destination.
    let message = ipv6_redirect(outer, router, "ff02::1".parse().unwrap(), &[]);
    assert_eq!(
        decode_ipv6_redirect(outer, 255, &message),
        Err(Error::Invalid)
    );
    let message = ipv6_redirect(outer, "2001:db8::2".parse().unwrap(), destination, &[]);
    assert_eq!(
        decode_ipv6_redirect(outer, 255, &message),
        Err(Error::Invalid)
    );
    // Zero-length, overrunning, mis-sized or repeated options.
    for options in [
        vec![2, 0, 0, 0, 0, 0, 0, 0],
        vec![200, 2, 0, 0, 0, 0, 0, 0],
        vec![2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [tllao(MAC), tllao(MAC)].concat(),
        [redirected(&[0; 8]), redirected(&[0; 8])].concat(),
        vec![2],
    ] {
        let message = ipv6_redirect(outer, router, destination, &options);
        assert_eq!(
            decode_ipv6_redirect(outer, 255, &message),
            Err(Error::Options),
            "{options:?}"
        );
    }
    // Another ICMPv6 type.
    let mut other = ipv6_redirect(outer, router, destination, &[]);
    other[0] = 136;
    reseal(outer, &mut other);
    assert_eq!(
        decode_ipv6_redirect(outer, 255, &other),
        Err(Error::ProtocolUnsupported)
    );
}
