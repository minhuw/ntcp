use ntcp_ethernet::*;
use ntcp_ip::IPV4_HEADER;
use ntcp_ip6::IPV6_HEADER;
#[path = "../../ntcp-ip/tests/support/mod.rs"]
mod support;
use support::{encode, parse, tx};
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
