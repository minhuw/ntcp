// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
fn paced_owner(last: u8) -> Owner {
    let local = Ipv4Addr::new(10, 73, 0, last);
    let mut config = SocketConfig::new("test", local);
    config.tcp.connection.pacing = Some(ntcp::PacingConfig::default());
    let mut owner = Owner::with_config(
        local,
        (Ipv4Addr::new(10, 73, 0, 1), 24),
        [last; 32],
        None,
        config.tcp,
    )
    .unwrap();
    owner.test_now = Some(1_000);
    owner
}

fn paced_pair() -> (Owner, Owner, u64, u64, u64) {
    let mut a = paced_owner(2);
    let mut b = paced_owner(3);
    let listener = new(&mut b, SOCK_NONBLOCK);
    b.execute(listener, Op::Bind("10.73.0.3:16379".parse().unwrap()))
        .unwrap();
    b.execute(listener, Op::Listen(16)).unwrap();
    let client = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(client, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    pump(&mut a, &mut b);
    let server = b
        .execute(listener, Op::Accept(SOCK_NONBLOCK))
        .unwrap()
        .value as u64;
    (a, b, client, server, listener)
}

// Advance only to real core deadlines: no wall-clock sleeps or invented delay.
fn pacing_tick(a: &mut Owner, b: &mut Owner) {
    let now = [a.endpoint.next_deadline(), b.endpoint.next_deadline()]
        .into_iter()
        .flatten()
        .min()
        .expect("queued work needs a wakeup");
    assert!(
        now > a.now(),
        "deadline must not busy-spin at {}: {now}",
        a.now()
    );
    a.test_now = Some(now);
    b.test_now = Some(now);
    a.endpoint.on_timeout(now, BUDGET).unwrap();
    b.endpoint.on_timeout(now, BUDGET).unwrap();
    pump(a, b);
}

#[test]
fn pacing_production_config_transfers_idles_and_half_closes_without_prr() {
    assert!(!ntcp::ConnectionConfig::default().prr);
    let (mut a, mut b, client, server, listener) = paced_pair();
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    let data: Vec<u8> = (0..BYTES).map(|n| n as u8).collect();
    for round in 0..2 {
        if round == 1 {
            let now = a.now() + 10_000_000;
            a.test_now = Some(now);
            b.test_now = Some(now);
            a.endpoint.on_timeout(now, BUDGET).unwrap();
            b.endpoint.on_timeout(now, BUDGET).unwrap();
            pump(&mut a, &mut b);
        }
        assert_eq!(
            a.execute(client, Op::Write(data.clone())).unwrap().value as usize,
            data.len()
        );
        pump(&mut a, &mut b);
        let mut received = b.execute(server, Op::Read(BYTES)).unwrap().bytes;
        assert!(!received.is_empty());
        assert!(
            received.len() <= 2 * 1460,
            "unbounded startup/idle burst: {}",
            received.len()
        );
        for _ in 0..512 {
            if received.len() == data.len() {
                break;
            }
            pacing_tick(&mut a, &mut b);
            match b.execute(server, Op::Read(BYTES)) {
                Ok(reply) => received.extend(reply.bytes),
                Err(EAGAIN) => (),
                Err(error) => panic!("read: {error}"),
            }
        }
        assert_eq!(received, data);
        // Drain delayed ACKs before the next application write/close.
        let Handle::Connection(cid) = a.sockets[&client].handle else {
            panic!()
        };
        for _ in 0..32 {
            if a.endpoint.transport_info(cid).unwrap().unacked == 0 {
                break;
            }
            pacing_tick(&mut a, &mut b);
        }
        assert_eq!(a.endpoint.transport_info(cid).unwrap().unacked, 0);
    }
    // FIN follows queued paced bytes; EOF and the reverse half-close stay live.
    a.execute(client, Op::Write(vec![7; 8000])).unwrap();
    a.execute(client, Op::Shutdown(SHUT_WR)).unwrap();
    let mut tail = Vec::new();
    let mut eof = false;
    for _ in 0..512 {
        pump(&mut a, &mut b);
        match b.execute(server, Op::Read(BYTES)) {
            Ok(reply) if reply.bytes.is_empty() => {
                eof = true;
                break;
            }
            Ok(reply) => tail.extend(reply.bytes),
            Err(EAGAIN) => (),
            Err(error) => panic!("read: {error}"),
        }
        pacing_tick(&mut a, &mut b);
    }
    assert!(eof);
    assert_eq!(tail, vec![7; 8000]);
    b.execute(server, Op::Write(b"done".to_vec())).unwrap();
    b.execute(server, Op::Shutdown(SHUT_WR)).unwrap();
    pump(&mut a, &mut b);
    assert_eq!(a.execute(client, Op::Read(BYTES)).unwrap().bytes, b"done");
    assert!(a.execute(client, Op::Read(BYTES)).unwrap().bytes.is_empty());
    a.execute(client, Op::Close).unwrap();
    b.execute(server, Op::Close).unwrap();
    b.execute(listener, Op::Close).unwrap();
}

#[test]
fn pacing_blocked_backend_retains_one_commit_and_resumes_at_core_deadline() {
    struct BlockedIo {
        blocked: bool,
        calls: usize,
        sent: Vec<Vec<u8>>,
    }
    impl PacketIo for BlockedIo {
        fn layer(&self) -> ntcp_io::PacketLayer {
            ntcp_io::PacketLayer::Ip
        }
        fn receive(&mut self, _: &mut [u8]) -> std::io::Result<Option<usize>> {
            Ok(None)
        }
        fn transmit(&mut self, packet: &[u8]) -> std::io::Result<TxOutcome> {
            self.calls += 1;
            if self.blocked {
                return Ok(TxOutcome::WouldBlock);
            }
            self.sent.push(packet.to_vec());
            Ok(TxOutcome::Submitted)
        }
    }
    let (mut a, mut b, client, server, _) = paced_pair();
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    a.execute(client, Op::Write(vec![9; 12000])).unwrap();
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        panic!()
    };
    let mut io = BlockedIo {
        blocked: true,
        calls: 0,
        sent: Vec::new(),
    };
    assert!(a.prepare_packet(None).unwrap());
    let pending = a.pending_packet.clone();
    let unsent = a.endpoint.transport_info(cid).unwrap().notsent_bytes;
    for _ in 0..3 {
        // The same production prepare/submit path must not re-encode while blocked.
        assert!(a.prepare_packet(None).unwrap());
        assert_eq!(
            submit_packet(&mut io, &mut a.pending_packet).unwrap(),
            TxOutcome::WouldBlock
        );
        assert_eq!(a.pending_packet, pending);
        assert_eq!(
            a.endpoint.transport_info(cid).unwrap().notsent_bytes,
            unsent
        );
    }
    assert_eq!(io.calls, 3);
    assert!(io.sent.is_empty());
    io.blocked = false;
    assert_eq!(
        submit_packet(&mut io, &mut a.pending_packet).unwrap(),
        TxOutcome::Submitted
    );
    assert!(a.pending_packet.is_none());
    assert_eq!(io.sent, vec![pending.unwrap()]);
    let ip = ntcp_ip::parse(&io.sent[0], false).unwrap();
    b.input(b.now(), ip.ip, ip.traffic_class, ip.payload)
        .unwrap();
    pump(&mut a, &mut b);
    let mut received = b.execute(server, Op::Read(BYTES)).unwrap().bytes;
    assert!(received.len() <= 2 * 1460);
    assert!(
        !a.prepare_packet(None).unwrap(),
        "must wait for pacing, not encode ahead"
    );
    for _ in 0..128 {
        if received.len() == 12000 {
            break;
        }
        pacing_tick(&mut a, &mut b);
        match b.execute(server, Op::Read(BYTES)) {
            Ok(reply) => received.extend(reply.bytes),
            Err(EAGAIN) => (),
            Err(error) => panic!("read: {error}"),
        }
    }
    assert_eq!(received, vec![9; 12000]);
}

#[test]
fn typed_core_settings_reach_native_connections() {
    let local = Ipv4Addr::new(10, 73, 0, 2);
    let mut config = SocketConfig::new("test", local);
    config.tcp.dscp = 11;
    config.tcp.hop_limit = 33;
    let c = &mut config.tcp.connection;
    c.send_capacity = 32768;
    c.receive_capacity = 16384;
    c.mss = 1200;
    c.nagle = false;
    c.user_timeout_us = 8_765_432; // Not the independent TCP_USER_TIMEOUT override.
    c.keepalive = Some(ntcp::KeepaliveConfig {
        idle_us: 5_000_000,
        interval_us: 2_000_000,
        probes: 3,
        send_garbage: false,
    });
    c.pacing = Some(ntcp::PacingConfig {
        rate_gain_percent: 150,
        max_bytes_per_second: Some(1200),
        max_burst_segments: 1,
    });
    config.validate().unwrap();
    let mut a = Owner::with_config(local, (local, 24), [2; 32], None, config.tcp).unwrap();
    a.test_now = Some(1000);
    let mut b = owner(3);
    b.test_now = Some(1000);
    let listener = new(&mut b, SOCK_NONBLOCK);
    b.execute(listener, Op::Bind("10.73.0.3:16379".parse().unwrap()))
        .unwrap();
    b.execute(listener, Op::Listen(4)).unwrap();
    let client = new(&mut a, SOCK_NONBLOCK);
    for (level, option, expected) in [
        (SOL_SOCKET, SO_SNDBUF, 32768),
        (SOL_SOCKET, SO_RCVBUF, 16384),
        (SOL_SOCKET, SO_KEEPALIVE, 1),
        (IPPROTO_TCP, TCP_NODELAY, 1),
        (IPPROTO_TCP, TCP_KEEPIDLE, 5),
        (IPPROTO_TCP, TCP_KEEPINTVL, 2),
        (IPPROTO_TCP, TCP_KEEPCNT, 3),
        (IPPROTO_IP, IP_TOS, 44),
        (IPPROTO_TCP, TCP_USER_TIMEOUT, 0),
    ] {
        assert_eq!(
            a.execute(client, Op::Get(level, option)).unwrap().value,
            expected
        );
    }
    assert_eq!(
        a.execute(client, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    let mut bytes = [0; 1480];
    let syn = a
        .endpoint
        .poll_transmit(a.now(), &mut bytes, BUDGET)
        .unwrap()
        .packet
        .unwrap();
    assert_eq!((syn.dscp, syn.hop_limit), (11, 33));
    b.input(b.now(), syn.ip, syn.dscp << 2 | syn.ecn, &bytes[..syn.len])
        .unwrap();
    pump(&mut a, &mut b);
    let server = b.execute(listener, Op::Accept(0)).unwrap().value as u64;
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        panic!()
    };
    let info = a.endpoint.transport_info(cid).unwrap();
    assert_eq!(
        (info.send_capacity, info.receive_capacity, info.mss),
        (32768, 16384, 1200)
    );
    a.execute(client, Op::Write(vec![42; 3600])).unwrap();
    pump(&mut a, &mut b);
    assert!(a.endpoint.transport_info(cid).unwrap().notsent_bytes > 0);
    for _ in 0..20 {
        if a.endpoint.transport_info(cid).unwrap().send_used == 0 {
            break;
        }
        pacing_tick(&mut a, &mut b);
    }
    assert_eq!(a.endpoint.transport_info(cid).unwrap().send_used, 0);
    assert_eq!(
        b.execute(server, Op::Read(3600)).unwrap().bytes,
        vec![42; 3600]
    );
}

#[cfg(feature = "packet-test")]
#[test]
fn packet_profiles_ignore_native_socket_defaults() {
    use crate::packet_profile::Profile;
    for profile in [Profile::Baseline, Profile::UpstreamCubic, Profile::UpstreamCubicEcn] {
        let local = Ipv4Addr::new(10, 73, 0, 2);
        let mut owner = Owner::packet((local, profile)).unwrap();
        assert_eq!(owner.batch_time().is_some(), profile != Profile::Baseline);
        owner.defaults.connection.send_capacity = 123;
        owner.defaults.connection.receive_capacity = 456;
        owner.defaults.connection.nagle = false;
        owner.defaults.dscp = 31;
        let socket = owner.fresh_socket(0);
        let expected = crate::packet_profile::config(profile);
        assert_eq!(socket.send_capacity, expected.connection.send_capacity);
        assert_eq!(
            socket.receive_capacity,
            expected.connection.receive_capacity
        );
        assert!(!socket.nodelay);
        assert_eq!(socket.tos, 0);
    }
}
