use ntcp::{IpMetadata, OutgoingIpv4Options, Transmit};
use ntcp_ethernet::*;
use ntcp_ip::IPV4_HEADER;
use ntcp_ip6::IPV6_HEADER;
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
fn encode(bytes: &mut [u8], t: Transmit, timestamp: u32) -> Result<usize, Error> {
    if t.ip.source.is_ipv6() {
        ntcp_ip6::encode(bytes, t)
    } else {
        ntcp_ip::encode(bytes, t, timestamp)
    }
}
// Test-only projection lets the original mixed-family assertions stay intact.
fn parse(bytes: &[u8], source_routes: bool) -> Result<ntcp_ip::Packet<'_>, Error> {
    if bytes.first().ok_or(Error::Truncated)? >> 4 == 6 {
        let p = ntcp_ip6::parse(bytes)?;
        Ok(ntcp_ip::Packet {
            ip: p.ip,
            traffic_class: p.traffic_class,
            hop_limit: p.hop_limit,
            protocol: p.protocol,
            ipv4_options: ntcp::Ipv4Options::default(),
            payload: p.payload,
        })
    } else {
        ntcp_ip::parse(bytes, source_routes)
    }
}
fn families() -> impl Iterator<Item = bool> {
    [false, true]
        .into_iter()
        .filter(|v6| [cfg!(feature = "ipv4"), cfg!(feature = "ipv6")][usize::from(*v6)])
}
#[test]
fn ethernet_padding_bounds_and_types() {
    for v6 in families() {
        let header = if v6 { IPV6_HEADER } else { IPV4_HEADER };
        let mut ip = [0; 60];
        let mut t = tx(v6, 0);
        t.len = ntcp::wire::encode(
            t.ip,
            ntcp::wire::Header {
                source_port: 1234,
                destination_port: 8080,
                sequence: 1,
                acknowledgment: 2,
                flags: ntcp::wire::ACK,
                window: 1024,
                urgent_pointer: 0,
            },
            &[],
            &[],
            &mut ip[header..],
        )
        .unwrap();
        let len = encode(&mut ip, t, 0).unwrap();
        assert_eq!(len, header + 20);
        let ether_type = if v6 { ETHERTYPE_IPV6 } else { ETHERTYPE_IPV4 };
        let ip_end = ETHERNET_HEADER + len;
        let mut frame = [0xa5; 75];
        let total = encode_ethernet(&mut frame, [1; 6], [2; 6], ether_type, &ip[..len]).unwrap();
        assert_eq!(total, ip_end.max(60));
        assert!(frame[ip_end..total].iter().all(|&b| b == 0));
        assert_eq!(frame[total], 0xa5);
        frame[ip_end..total].fill(0xa5); // Inbound padding need not be zero.
        for size in [ip_end, total] {
            let p = parse_ethernet(&frame[..size]).unwrap();
            assert_eq!(p.source, [1; 6]);
            assert_eq!(p.destination, [2; 6]);
            assert_eq!(p.payload, &ip[..len]);
            let packet = parse(p.payload, false).unwrap();
            assert!(ntcp::wire::parse(packet.ip, packet.payload).is_ok());
        }
        for cut in 0..total {
            if cut != ip_end {
                assert!(parse_ethernet(&frame[..cut]).is_err());
            }
        }
        assert_eq!(
            parse_ethernet(&frame[..ip_end - 1]).unwrap_err(),
            Error::Truncated
        );
        if !v6 {
            assert_eq!(parse(&frame[14..total], false).unwrap_err(), Error::Length);
        }
        let before = frame;
        for capacity in [0, ip_end - 1, total - 1] {
            assert_eq!(
                encode_ethernet(
                    &mut frame[..capacity],
                    [1; 6],
                    [2; 6],
                    ether_type,
                    &ip[..len]
                )
                .unwrap_err(),
                Error::Truncated
            );
            assert_eq!(frame, before);
        }
        assert_eq!(
            parse_ethernet(&frame[..total + 1]).unwrap_err(),
            Error::Length
        );
        let mut extra = ip.to_vec();
        extra.resize(len + 1, 0xa5);
        assert_eq!(
            encode_ethernet(&mut frame, [1; 6], [2; 6], ether_type, &extra).unwrap_err(),
            Error::Length
        );
        assert_eq!(frame, before);
        assert!(
            encode_ethernet(
                &mut frame,
                [1; 6],
                [2; 6],
                if v6 { ETHERTYPE_IPV4 } else { ETHERTYPE_IPV6 },
                &ip[..len]
            )
            .is_err()
        );
        assert_eq!(frame, before);
        for tag in [0x8100u16, 0x88a8, 0x9100] {
            frame[12..14].copy_from_slice(&tag.to_be_bytes());
            assert_eq!(
                parse_ethernet(&frame[..total]).unwrap_err(),
                Error::VlanUnsupported
            );
        }
    }
}

#[test]
#[cfg(feature = "ipv6")]
fn ethernet_short_ipv6_padding() {
    let mut ip = [0xa5; 41];
    let len = encode(&mut ip, tx(true, 1), 0).unwrap();
    let mut frame = [0xa5; 61];
    let total = encode_ethernet(&mut frame, [1; 6], [2; 6], ETHERTYPE_IPV6, &ip).unwrap();
    assert_eq!(total, 60);
    let ip_end = ETHERNET_HEADER + len;
    assert_eq!(&frame[ip_end..total], &[0; 5]);
    frame[ip_end..total].fill(0xff);
    for size in [ip_end, total] {
        assert_eq!(parse_ethernet(&frame[..size]).unwrap().payload, ip);
    }
    assert_eq!(parse(&frame[14..total], false).unwrap_err(), Error::Length);
    assert_eq!(parse_ethernet(&frame[..61]).unwrap_err(), Error::Length);
}

#[test]
fn tcp_flow_over_ip_and_ethernet() {
    use ntcp::{Endpoint, EndpointConfig, State};
    use std::net::SocketAddr;
    fn transfer(from: &mut Endpoint, to: &mut Endpoint, v6: bool) {
        let mut ip = [0; 1500];
        let mut ethernet = [0; 1514];
        let header = if v6 { 40 } else { 20 };
        for _ in 0..32 {
            let output = from.poll_transmit(0, &mut ip[header..], 1).unwrap();
            if let Some(t) = output.packet {
                let len = encode(&mut ip, t, 0).unwrap();
                let len = encode_ethernet(
                    &mut ethernet,
                    [1; 6],
                    [2; 6],
                    if v6 { ETHERTYPE_IPV6 } else { ETHERTYPE_IPV4 },
                    &ip[..len],
                )
                .unwrap();
                let link = parse_ethernet(&ethernet[..len]).unwrap();
                let p = parse(link.payload, false).unwrap();
                to.input_with_traffic_class(0, p.ip, p.traffic_class, p.payload)
                    .unwrap();
            }
            if !output.more_work {
                return;
            }
        }
        panic!("bounded transfer failed to quiesce");
    }
    for v6 in families() {
        let config = EndpointConfig {
            dscp: 37,
            ..EndpointConfig::default()
        };
        let mut a = Endpoint::new(config.clone(), [1; 32], 0, |_| true).unwrap();
        let mut b = Endpoint::new(config, [2; 32], 0, |_| true).unwrap();
        let local = SocketAddr::new(tx(v6, 0).ip.source, 1234);
        let remote = SocketAddr::new(tx(v6, 0).ip.destination, 8080);
        let listener = b.listen(remote, 1).unwrap();
        let id = a.connect(0, local, remote).unwrap();
        transfer(&mut a, &mut b, v6);
        transfer(&mut b, &mut a, v6);
        transfer(&mut a, &mut b, v6);
        let accepted = b.accept(listener).unwrap();
        assert_eq!(a.state(id).unwrap(), State::Established);
        a.write(id, b"framed TCP").unwrap();
        transfer(&mut a, &mut b, v6);
        let mut out = [0; 32];
        let n = b.read(accepted, &mut out).unwrap();
        assert_eq!(&out[..n], b"framed TCP");
    }
}

#[test]
fn disabled_families_are_rejected() {
    for v6 in [false, true] {
        let enabled = [cfg!(feature = "ipv4"), cfg!(feature = "ipv6")][usize::from(v6)];
        let mut ip = [0; 60];
        let len = encode(&mut ip, tx(v6, 20), 0).unwrap();
        let ether_type = if v6 { ETHERTYPE_IPV6 } else { ETHERTYPE_IPV4 };
        let mut frame = [0xa5; 74];
        if !enabled {
            let before = frame;
            assert_eq!(
                encode_ethernet(&mut frame, [1; 6], [2; 6], ether_type, &ip[..len]).unwrap_err(),
                Error::EtherTypeUnsupported
            );
            assert_eq!(frame, before);
            frame[12..14].copy_from_slice(&ether_type.to_be_bytes());
            frame[14..14 + len].copy_from_slice(&ip[..len]);
            assert_eq!(
                parse_ethernet(&frame).unwrap_err(),
                Error::EtherTypeUnsupported
            );
        } else {
            let n = encode_ethernet(&mut frame, [1; 6], [2; 6], ether_type, &ip[..len]).unwrap();
            assert!(parse_ethernet(&frame[..n]).is_ok());
        }
    }
}

// Fragments are delimited for a reassembling host only; the atomic parser
// keeps refusing them.
#[test]
fn ethernet_fragment_framing_and_padding() {
    for v6 in families() {
        let ip = tx(v6, 0).ip;
        let data = [9u8; 16];
        let mut packet = [0u8; 128];
        let len = if v6 {
            let h = ntcp_ip6::Header {
                ip,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
            };
            ntcp_ip6::Fragmenter::new(h, 17, 7, 24)
                .unwrap()
                .encode(&mut packet, 0, &data[..8])
        } else {
            let h = ntcp_ip::Header {
                ip,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: Default::default(),
            };
            ntcp_ip::Fragmenter::new(h, 17, 7, 24, 0)
                .unwrap()
                .encode(&mut packet, 0, &data[..8])
        }
        .unwrap();
        let mut frame = [0u8; 200];
        frame[12..14]
            .copy_from_slice(&if v6 { ETHERTYPE_IPV6 } else { ETHERTYPE_IPV4 }.to_be_bytes());
        frame[14..14 + len].copy_from_slice(&packet[..len]);
        let padded = &frame[..(14 + len).max(60)];
        assert_eq!(
            parse_ethernet(padded).unwrap_err(),
            Error::FragmentationUnsupported
        );
        assert_eq!(
            parse_ethernet_fragment(padded).unwrap().payload,
            &packet[..len]
        );
        // Padding beyond the minimum frame is still a length error.
        assert_eq!(
            parse_ethernet_fragment(&frame[..(14 + len).max(60) + 1]).unwrap_err(),
            Error::Length
        );
        // An unfragmented packet parses identically through both.
        let mut whole = [0u8; 128];
        let n = if v6 {
            let h = ntcp_ip6::Header {
                ip,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
            };
            ntcp_ip6::encode_datagram(&mut whole[14..], h, 17, 8)
        } else {
            let h = ntcp_ip::Header {
                ip,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: Default::default(),
            };
            ntcp_ip::encode_datagram(&mut whole[14..], h, 17, 8, 0)
        }
        .unwrap();
        whole[12..14].copy_from_slice(&frame[12..14]);
        let whole = &whole[..(14 + n).max(60)];
        assert_eq!(
            parse_ethernet(whole).unwrap().payload,
            parse_ethernet_fragment(whole).unwrap().payload
        );
    }
}

// Reassembling-host framing delimits IPv6 by the base header alone: complete
// packets whose extension headers carry policy or length faults reach the
// host, which originates their errors; physical truncation is refused. The
// non-reassembling framing still refuses every extension selector.
#[test]
#[cfg(feature = "ipv6")]
fn fragment_framing_passes_complete_ipv6_packets_with_faulty_extensions() {
    let mut ip = vec![0u8; IPV6_HEADER + 24];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&24u16.to_be_bytes());
    ip[7] = 64;
    ip[23] = 1;
    ip[39] = 2;
    let faulty: [&[u8]; 4] = [
        // Destination Options whose PadN overruns the header.
        &[60, 17, 0, 1, 9, 0, 0, 0, 0],
        // Hop-by-Hop Options after a Destination Options header.
        &[60, 0, 0, 1, 4, 0, 0, 0, 0],
        // A Routing header with Segments Left above zero.
        &[43, 17, 0, 0, 1, 0, 0, 0, 0],
        // A header that claims more than the Payload Length holds.
        &[60, 17, 7, 0, 0, 0, 0, 0, 0],
    ];
    for layout in faulty {
        ip[6] = layout[0];
        ip[40..48].copy_from_slice(&layout[1..]);
        let mut frame = vec![0u8; 14 + ip.len()];
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        frame[14..].copy_from_slice(&ip);
        assert_eq!(parse_ethernet_fragment(&frame).unwrap().payload, &ip[..]);
        assert_eq!(
            parse_ethernet(&frame).unwrap_err(),
            Error::ExtensionsUnsupported
        );
        assert_eq!(
            parse_ethernet_fragment(&frame[..frame.len() - 1]).unwrap_err(),
            Error::Truncated
        );
    }
}

#[test]
fn ipv6_multicast_groups_and_their_ethernet_mapping() {
    let address: core::net::Ipv6Addr = "fe80::2aa:ff:fe28:9c5a".parse().unwrap();
    let group = solicited_node(address);
    assert_eq!(
        group,
        "ff02::1:ff28:9c5a".parse::<core::net::Ipv6Addr>().unwrap()
    );
    // Addresses that share their low 24 bits share the group.
    assert_eq!(
        solicited_node("2001:db8::2aa:ff:fe28:9c5a".parse().unwrap()),
        group
    );
    assert_eq!(
        ipv6_multicast_mac(group),
        Some([0x33, 0x33, 0xff, 0x28, 0x9c, 0x5a])
    );
    assert_eq!(
        IPV6_ALL_NODES,
        "ff02::1".parse::<core::net::Ipv6Addr>().unwrap()
    );
    assert_eq!(
        ipv6_multicast_mac(IPV6_ALL_NODES),
        Some([0x33, 0x33, 0, 0, 0, 1])
    );
    // A unicast destination has no multicast mapping.
    assert_eq!(ipv6_multicast_mac(address), None);
}

// A broadcast ARP request in the form Linux emits (target MAC zero), before
// zero padding to the 60-octet minimum frame.
const ARP_REQUEST: [u8; 42] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 0x01, 0x08, 0x06, // Ethernet
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, // htype, ptype, hlen, plen, op
    0x02, 0, 0, 0, 0, 0x01, 192, 0, 2, 1, // sender
    0, 0, 0, 0, 0, 0, 192, 0, 2, 2, // target
];

#[test]
fn arp_frames_parse_and_encode_with_padding() {
    let body = &ARP_REQUEST[ETHERNET_HEADER..];
    let mut out = [0xaa; 64];
    let len = encode_ethernet_arp(&mut out, [2, 0, 0, 0, 0, 1], BROADCAST, body).unwrap();
    assert_eq!(len, 60);
    assert_eq!(&out[..42], &ARP_REQUEST);
    assert!(out[42..60].iter().all(|b| *b == 0));
    assert_eq!(
        encode_ethernet_arp(&mut out[..59], [2, 0, 0, 0, 0, 1], BROADCAST, body),
        Err(Error::Truncated)
    );
    // Padded and unpadded frames both carry the whole remainder.
    for frame in [&out[..60], &ARP_REQUEST[..]] {
        let eth = parse_ethernet_arp(frame).unwrap();
        assert_eq!(eth.ether_type, ETHERTYPE_ARP);
        assert_eq!(eth.destination, BROADCAST);
        assert_eq!(eth.source, [2, 0, 0, 0, 0, 1]);
        assert_eq!(&eth.payload[..28], body);
        assert_eq!(eth.payload.len(), frame.len() - ETHERNET_HEADER);
    }
    assert_eq!(
        parse_ethernet_arp(&ARP_REQUEST[..13]).err(),
        Some(Error::Truncated)
    );
}

#[test]
fn ip_parsers_refuse_arp_and_arp_parser_refuses_others() {
    let mut frame = [0; 60];
    frame[..42].copy_from_slice(&ARP_REQUEST);
    assert_eq!(
        parse_ethernet(&frame).err(),
        Some(Error::EtherTypeUnsupported)
    );
    assert_eq!(
        parse_ethernet_fragment(&frame).err(),
        Some(Error::EtherTypeUnsupported)
    );
    assert_eq!(
        encode_ethernet(
            &mut [0; 60],
            [0; 6],
            BROADCAST,
            ETHERTYPE_ARP,
            &frame[14..42]
        ),
        Err(Error::EtherTypeUnsupported)
    );
    // VLAN-tagged ARP stays unsupported; IP frames are not ARP.
    for (tag, error) in [
        (0x8100u16, Error::VlanUnsupported),
        (0x88a8, Error::VlanUnsupported),
        (0x9100, Error::VlanUnsupported),
        (ETHERTYPE_IPV4, Error::EtherTypeUnsupported),
        (ETHERTYPE_IPV6, Error::EtherTypeUnsupported),
    ] {
        let mut tagged = frame;
        tagged[12..14].copy_from_slice(&tag.to_be_bytes());
        assert_eq!(parse_ethernet_arp(&tagged).err(), Some(error));
    }
}
