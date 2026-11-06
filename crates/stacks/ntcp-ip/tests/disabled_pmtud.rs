use ntcp::{ConnectionConfig, Endpoint, EndpointConfig, InitialWindow, wire};

#[test]
fn disabled_ipv4_keeps_larger_codec_packets_and_peer_delivery() {
    let make = |secret| {
        Endpoint::new(
            EndpointConfig {
                connection: ConnectionConfig {
                    mss: 4096,
                    nagle: false,
                    delayed_ack_us: 0,
                    initial_window: InitialWindow::Iw10,
                    ..Default::default()
                },
                ..Default::default()
            },
            [secret; 32],
            0,
            ntcp::Lifecycle { boot_age: Some(u64::MAX), continuity: ntcp::SourceContinuity::Never },
            |_| true,
        )
        .unwrap()
    };
    let mut a = make(1);
    let mut b = make(2);
    let local = "192.0.2.1:40000".parse().unwrap();
    let remote = "192.0.2.2:8080".parse().unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let id = a.connect(0, local, remote).unwrap();
    let transfer = |src: &mut Endpoint, dst: &mut Endpoint, now| {
        let mut frame = [0; 8192];
        let tx = src
            .poll_transmit(now, &mut frame[20..], 64)
            .unwrap()
            .packet
            .unwrap();
        let n = ntcp_ip::encode(&mut frame, tx, 0).unwrap();
        let p = ntcp_ip::parse(&frame[..n], false).unwrap();
        assert_eq!(wire::checksum(p.ip, p.payload).unwrap(), 0);
        let tcp = wire::parse(p.ip, p.payload).unwrap();
        if tcp.header.flags & wire::SYN != 0 {
            assert_eq!(tcp.options.mss, Some(4096));
        }
        dst.input(now, p.ip, p.payload).unwrap();
        (n, tcp.payload.len())
    };
    transfer(&mut a, &mut b, 1);
    transfer(&mut b, &mut a, 2);
    transfer(&mut a, &mut b, 3);
    let peer = b.accept(listener).unwrap();
    a.write(id, &[0x5a; 10000]).unwrap();
    assert_eq!(transfer(&mut a, &mut b, 4), (4136, 4096));
    let mut received = [0; 4096];
    assert_eq!(b.read(peer, &mut received).unwrap(), 4096);
    assert_eq!(received, [0x5a; 4096]);
    transfer(&mut b, &mut a, 5);
    assert_eq!(a.acknowledged(id).unwrap(), 4096);
    assert_eq!(a.path_mtu_info(id).unwrap(), None);
}
