use core::net::{IpAddr, Ipv6Addr};
use ntcp::IpMetadata;
use ntcp_icmp::*;

const MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xb];
fn ip(source: &str, destination: &str) -> IpMetadata {
    IpMetadata {
        source: source.parse().unwrap(),
        destination: destination.parse().unwrap(),
    }
}
fn target() -> Ipv6Addr {
    "fe80::a".parse().unwrap()
}
fn resolution() -> IpMetadata {
    ip("fe80::b", "ff02::1:ff00:a")
}
fn solicitation(link_layer: Option<[u8; 6]>) -> NeighborSolicitation {
    NeighborSolicitation {
        target: target(),
        source_link_layer: link_layer,
    }
}
fn advertisement(solicited: bool) -> NeighborAdvertisement {
    NeighborAdvertisement {
        router: true,
        solicited,
        override_: true,
        target: target(),
        target_link_layer: Some(MAC),
    }
}
// Recompute the checksum of a hand-modified message.
fn reseal(ip: IpMetadata, message: &mut [u8]) {
    message[2..4].fill(0);
    let sum = icmpv6_checksum(ip, message).unwrap();
    message[2..4].copy_from_slice(&sum.to_be_bytes());
}

#[test]
fn solicitation_and_advertisement_round_trip() {
    let mut out = [0; 64];
    let len = encode_solicitation(resolution(), solicitation(Some(MAC)), &mut out).unwrap();
    assert_eq!(len, 32);
    assert_eq!((out[0], out[1], out[24], out[25]), (135, 0, 1, 1));
    assert_eq!(
        decode_neighbor(resolution(), 255, &out[..len]),
        Ok(NeighborMessage::Solicitation(solicitation(Some(MAC))))
    );
    let unicast = ip("fe80::a", "fe80::b");
    let len = encode_advertisement(unicast, advertisement(true), &mut out).unwrap();
    assert_eq!((out[0], out[4], out[24]), (136, 0xe0, 2));
    assert_eq!(
        decode_neighbor(unicast, 255, &out[..len]),
        Ok(NeighborMessage::Advertisement(advertisement(true)))
    );
    // Duplicate Address Detection: unspecified source, no option.
    let dad = ip("::", "ff02::1:ff00:a");
    let len = encode_solicitation(dad, solicitation(None), &mut out).unwrap();
    assert_eq!(len, 24);
    assert_eq!(
        decode_neighbor(dad, 255, &out[..len]),
        Ok(NeighborMessage::Solicitation(solicitation(None)))
    );
}

#[test]
fn hop_limit_code_checksum_and_truncation_are_validated() {
    let mut out = [0; 64];
    let len = encode_solicitation(resolution(), solicitation(Some(MAC)), &mut out).unwrap();
    // A forwarded message no longer has Hop Limit 255.
    assert_eq!(
        decode_neighbor(resolution(), 254, &out[..len]),
        Err(Error::Invalid)
    );
    let mut bad = out;
    bad[3] ^= 1;
    assert_eq!(
        decode_neighbor(resolution(), 255, &bad[..len]),
        Err(Error::Checksum)
    );
    let mut coded = out;
    coded[1] = 1;
    reseal(resolution(), &mut coded[..len]);
    assert_eq!(
        decode_neighbor(resolution(), 255, &coded[..len]),
        Err(Error::Invalid)
    );
    let mut short = out;
    reseal(resolution(), &mut short[..23]);
    assert_eq!(
        decode_neighbor(resolution(), 255, &short[..23]),
        Err(Error::Truncated)
    );
    // Other ICMPv6 types are not Neighbor Discovery messages.
    let mut echo = out;
    echo[0] = 128;
    assert_eq!(
        decode_neighbor(resolution(), 255, &echo[..len]),
        Err(Error::ProtocolUnsupported)
    );
    assert_eq!(
        decode_neighbor(ip("192.0.2.1", "192.0.2.2"), 255, &out[..len]),
        Err(Error::Version)
    );
}

#[test]
fn multicast_targets_and_malformed_options_are_rejected() {
    let mut out = [0; 64];
    let len = encode_solicitation(resolution(), solicitation(Some(MAC)), &mut out).unwrap();
    let mut multicast = out;
    multicast[8] = 0xff;
    reseal(resolution(), &mut multicast[..len]);
    assert_eq!(
        decode_neighbor(resolution(), 255, &multicast[..len]),
        Err(Error::Invalid)
    );
    assert_eq!(
        encode_solicitation(
            resolution(),
            NeighborSolicitation {
                target: "ff02::1".parse().unwrap(),
                source_link_layer: None,
            },
            &mut out,
        ),
        Err(Error::Invalid)
    );
    // A zero-length option, and one running past the message.
    for length in [0, 2] {
        let mut option = out;
        option[25] = length;
        reseal(resolution(), &mut option[..len]);
        assert_eq!(
            decode_neighbor(resolution(), 255, &option[..len]),
            Err(Error::Options)
        );
    }
    // A truncated option header.
    let mut tail = out;
    reseal(resolution(), &mut tail[..25]);
    assert_eq!(
        decode_neighbor(resolution(), 255, &tail[..25]),
        Err(Error::Options)
    );
    // The used option has the Ethernet length and appears once.
    let mut long = [0; 64];
    long[..len].copy_from_slice(&out[..len]);
    long[25] = 2;
    reseal(resolution(), &mut long[..40]);
    assert_eq!(
        decode_neighbor(resolution(), 255, &long[..40]),
        Err(Error::Options)
    );
    let mut twice = [0; 64];
    twice[..len].copy_from_slice(&out[..len]);
    twice[len..len + 8].copy_from_slice(&out[24..32]);
    reseal(resolution(), &mut twice[..40]);
    assert_eq!(
        decode_neighbor(resolution(), 255, &twice[..40]),
        Err(Error::Options)
    );
    // An option this message does not use is skipped, whatever its length;
    // a solicitation ignores a Target Link-Layer Address option.
    let mut other = [0; 64];
    other[..len].copy_from_slice(&out[..len]);
    other[len..len + 16].copy_from_slice(&[2, 2, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9]);
    reseal(resolution(), &mut other[..48]);
    assert_eq!(
        decode_neighbor(resolution(), 255, &other[..48]),
        Ok(NeighborMessage::Solicitation(solicitation(Some(MAC))))
    );
    // Reserved bits are ignored.
    let mut reserved = out;
    reserved[4..8].fill(0xff);
    reseal(resolution(), &mut reserved[..len]);
    assert!(decode_neighbor(resolution(), 255, &reserved[..len]).is_ok());
}

#[test]
fn unspecified_sources_and_multicast_advertisements_follow_their_rules() {
    let mut out = [0; 64];
    // An unspecified-source solicitation with a link-layer option.
    let dad = ip("::", "ff02::1:ff00:a");
    let len = encode_solicitation(resolution(), solicitation(Some(MAC)), &mut out).unwrap();
    reseal(dad, &mut out[..len]);
    assert_eq!(decode_neighbor(dad, 255, &out[..len]), Err(Error::Invalid));
    assert_eq!(
        encode_solicitation(dad, solicitation(Some(MAC)), &mut out),
        Err(Error::Invalid)
    );
    // ... or to any destination but a solicited-node group.
    let unicast_dad = ip("::", "fe80::a");
    let len = encode_solicitation(resolution(), solicitation(None), &mut out).unwrap();
    reseal(unicast_dad, &mut out[..len]);
    assert_eq!(
        decode_neighbor(unicast_dad, 255, &out[..len]),
        Err(Error::Invalid)
    );
    // A solicited advertisement to a multicast destination.
    let all_nodes = ip("fe80::a", "ff02::1");
    let len =
        encode_advertisement(ip("fe80::a", "fe80::b"), advertisement(true), &mut out).unwrap();
    reseal(all_nodes, &mut out[..len]);
    assert_eq!(
        decode_neighbor(all_nodes, 255, &out[..len]),
        Err(Error::Invalid)
    );
    assert_eq!(
        encode_advertisement(all_nodes, advertisement(true), &mut out),
        Err(Error::Invalid)
    );
    // An unsolicited one is accepted, and an advertisement ignores a Source
    // Link-Layer Address option.
    let len = encode_advertisement(all_nodes, advertisement(false), &mut out).unwrap();
    out[24] = 1;
    reseal(all_nodes, &mut out[..len]);
    assert_eq!(
        decode_neighbor(all_nodes, 255, &out[..len]),
        Ok(NeighborMessage::Advertisement(NeighborAdvertisement {
            target_link_layer: None,
            ..advertisement(false)
        }))
    );
    let _: IpAddr = all_nodes.source;
}
