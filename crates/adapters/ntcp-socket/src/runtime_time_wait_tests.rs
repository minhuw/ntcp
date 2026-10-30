use super::*;

fn request(ip: ntcp::IpMetadata, port: u16, seq: u32, ack: u32, flags: u8, data: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 128];
    let n = ntcp::wire::encode(
        ip,
        ntcp::wire::Header {
            source_port: port,
            destination_port: 8080,
            sequence: seq,
            acknowledgment: ack,
            flags,
            window: 1024,
            urgent_pointer: 0,
        },
        &[],
        data,
        &mut bytes,
    )
    .unwrap();
    bytes.truncate(n);
    bytes
}
fn output(b: &mut Owner, now: u64) -> ntcp::wire::Header {
    let mut bytes = [0; 128];
    let tx = b
        .endpoint
        .poll_transmit(now, &mut bytes, BUDGET)
        .unwrap()
        .packet
        .unwrap();
    ntcp::wire::parse(tx.ip, &bytes[..tx.len]).unwrap().header
}

#[test]
fn time_wait_data_syn_reserves_native_metadata_before_replacement_and_snapshots_listener() {
    time_wait_data_syn_metadata(false);
}

#[test]
fn time_wait_data_syn_reset_restores_old_metadata_at_capacity() {
    time_wait_data_syn_metadata(true);
}

fn time_wait_data_syn_metadata(reset_candidate: bool) {
    let mut config = SocketConfig::new("test", Ipv4Addr::new(10, 73, 0, 3)).tcp;
    config.max_connections = LIMIT + 2;
    config.connection.send_capacity = 64;
    config.connection.receive_capacity = 64;
    config.connection.mss = 64;
    config.connection.timestamps = false;
    config.reuse_time_wait = true;
    let mut b = owner_with_config(3, config);
    b.test_now = Some(1_000);
    let listener = new(&mut b, SOCK_NONBLOCK);
    b.execute(listener, Op::Bind("10.73.0.3:8080".parse().unwrap()))
        .unwrap();
    b.execute(listener, Op::Listen(LIMIT as i32)).unwrap();
    let ip = ntcp::IpMetadata {
        source: "10.73.0.2".parse().unwrap(),
        destination: b.local,
    };
    let tuple = ntcp::Tuple {
        local: "10.73.0.3:8080".parse().unwrap(),
        remote: "10.73.0.2:40000".parse().unwrap(),
    };
    let syn = request(ip, 40000, 100, 0, ntcp::wire::SYN, &[]);
    b.input_stamped(1_000, ip, 0, &syn, Default::default())
        .unwrap();
    let synack = output(&mut b, 1_000);
    let ack = request(
        ip,
        40000,
        101,
        synack.sequence.wrapping_add(1),
        ntcp::wire::ACK,
        &[],
    );
    b.input_stamped(2_000, ip, 0, &ack, Default::default())
        .unwrap();
    b.test_now = Some(2_000);
    let server = b
        .execute(listener, Op::Accept(SOCK_NONBLOCK))
        .unwrap()
        .value as u64;
    let old = b.endpoint.connection_id(tuple).unwrap();
    b.execute(server, Op::Shutdown(SHUT_WR)).unwrap();
    let fin = output(&mut b, 2_000);
    let close = request(
        ip,
        40000,
        101,
        fin.sequence.wrapping_add(1),
        ntcp::wire::FIN | ntcp::wire::ACK,
        &[],
    );
    b.input_stamped(3_000, ip, 0, &close, Default::default())
        .unwrap();
    let final_ack = output(&mut b, 3_000);
    assert_eq!(final_ack.acknowledgment, 102);
    assert_eq!(b.endpoint.state(old), Ok(State::TimeWait));
    // Fill the actual production metadata bound using real passive children.
    // Core has spare slots; no test-only limit or fabricated metadata entries.
    for index in 0..LIMIT - 1 {
        let syn = request(ip, 41000 + index as u16, 1000, 0, ntcp::wire::SYN, &[]);
        b.input_stamped(3_000, ip, 0, &syn, Default::default())
            .unwrap();
    }
    for _ in 0..LIMIT - 1 {
        output(&mut b, 3_000);
    }
    assert_eq!(b.connection_options.len(), b.socket_limit());
    assert_eq!(b.child_timeouts.len(), LIMIT - 1);
    let snapshots = (
        b.connection_options.clone(),
        b.child_timeouts.clone(),
        b.child_timestamps.clone(),
    );
    let charge = b.endpoint.buffer_bytes();
    let deadline = b.endpoint.next_deadline();
    let syn = request(
        ip,
        40000,
        102,
        0,
        ntcp::wire::SYN | ntcp::wire::PSH | ntcp::wire::URG,
        b"data",
    );
    assert_eq!(
        b.input_stamped(4_000, ip, 0, &syn, Default::default()),
        Err(EndpointError::LimitReached.into())
    );
    assert_eq!(b.endpoint.connection_id(tuple), Some(old));
    assert_eq!(b.endpoint.state(old), Ok(State::TimeWait));
    assert_eq!(b.endpoint.buffer_bytes(), charge);
    assert_eq!(b.endpoint.next_deadline(), deadline);
    assert_eq!(b.connection_options, snapshots.0);
    assert_eq!(b.child_timeouts, snapshots.1);
    assert_eq!(b.child_timestamps, snapshots.2);
    assert!(
        b.endpoint
            .poll_transmit(4_000, &mut [0; 128], BUDGET)
            .unwrap()
            .packet
            .is_none()
    );
    // Parsing and ACK/RST exclusions remain ahead of passive allocation.
    let mut corrupt = syn.clone();
    corrupt[16] ^= 1;
    assert_eq!(
        b.input_stamped(4_000, ip, 0, &corrupt, Default::default()),
        Ok(ntcp::InputDisposition::Dropped)
    );
    let ack_syn = request(
        ip,
        40000,
        102,
        final_ack.sequence,
        ntcp::wire::SYN | ntcp::wire::ACK,
        b"data",
    );
    assert_ne!(
        b.input_stamped(4_000, ip, 0, &ack_syn, Default::default()),
        Err(EndpointError::LimitReached.into())
    );
    assert_eq!(b.endpoint.connection_id(tuple), Some(old));
    // Free one real pending child, then retry the same data-bearing SYN.
    let pending = b
        .endpoint
        .connection_id(ntcp::Tuple {
            local: tuple.local,
            remote: "10.73.0.2:41000".parse().unwrap(),
        })
        .unwrap();
    let reset = request(ip, 41000, 1001, 0, ntcp::wire::RST, &[]);
    b.input_stamped(5_000, ip, 0, &reset, Default::default())
        .unwrap();
    assert_eq!(b.endpoint.state(pending), Err(EndpointError::InvalidHandle));
    loop {
        let poll = b
            .endpoint
            .poll_transmit(5_000, &mut [0; 128], BUDGET)
            .unwrap();
        if !poll.more_work {
            break;
        }
    }
    assert!(!b.endpoint.connection_exists(pending));
    let Handle::Listener(lid) = b.sockets[&listener].handle else {
        panic!()
    };
    b.endpoint
        .set_listener_rx_timestamp_capacity(lid, 3)
        .unwrap();
    let old_snapshots = (
        b.connection_options.clone(),
        b.child_timeouts.clone(),
        b.child_timestamps.clone(),
    );
    assert_eq!(b.connection_options.len(), b.socket_limit());
    assert_eq!(
        b.connection_options
            .iter()
            .filter(|p| b.endpoint.connection_exists(p.0))
            .count(),
        b.socket_limit() - 1
    );
    b.test_now = Some(6_000);
    b.execute(listener, Op::Set(IPPROTO_IP, IP_TOS, 44))
        .unwrap();
    b.sockets.get_mut(&listener).unwrap().receive_timeout_us = 123_000;
    b.sockets.get_mut(&listener).unwrap().ipv6_tclass = 171;
    let stamps = ntcp::RxPacketTimestamps {
        software: Some(ntcp::RxTimestamp {
            value: 777,
            clock: ntcp::TimestampClock::RealtimeNanoseconds,
        }),
        hardware: None,
    };
    assert_eq!(
        b.input_stamped(6_000, ip, 0, &syn, stamps),
        Ok(ntcp::InputDisposition::Processed)
    );
    let child = b.endpoint.connection_id(tuple).unwrap();
    assert_ne!(child, old);
    assert_eq!(b.endpoint.state(child), Ok(State::SynReceived));
    assert_eq!(b.endpoint.state(old), Ok(State::TimeWait));
    assert_eq!(b.connection_options.len(), LIMIT);
    let snapshot = b.connection_options.iter().find(|p| p.0 == child).unwrap();
    assert_eq!((snapshot.1, snapshot.5), (44, tuple.local));
    let snapshot = b.child_timeouts.iter().find(|p| p.0 == child).unwrap();
    assert_eq!(snapshot.2, 123_000);
    assert_eq!(b.endpoint.rx_timestamp_status(child).unwrap().capacity, 3);
    let synack = output(&mut b, 6_000);
    assert_eq!(synack.acknowledgment, 103);
    if reset_candidate {
        // A reset at RCV.NXT restores the retained owner. Changing listener
        // policy must not reapply it to that existing TIME-WAIT connection.
        b.execute(listener, Op::Set(IPPROTO_IP, IP_TOS, 88))
            .unwrap();
        b.sockets.get_mut(&listener).unwrap().receive_timeout_us = 456_000;
        let admitted_snapshots = (
            b.connection_options.clone(),
            b.child_timeouts.clone(),
            b.child_timestamps.clone(),
        );
        let reset = request(ip, 40000, 103, 0, ntcp::wire::RST, &[]);
        b.input_stamped(7_000, ip, 0, &reset, Default::default())
            .unwrap();
        assert_eq!(b.endpoint.connection_id(tuple), Some(old));
        assert_eq!(b.endpoint.state(old), Ok(State::TimeWait));
        assert_eq!(b.connection_options.len(), admitted_snapshots.0.len());
        assert_eq!(b.connection_options, admitted_snapshots.0);
        assert_eq!(b.child_timeouts, admitted_snapshots.1);
        assert_eq!(b.child_timestamps, admitted_snapshots.2);
        assert_eq!(
            b.connection_options.iter().find(|p| p.0 == old),
            old_snapshots.0.iter().find(|p| p.0 == old)
        );
        assert_eq!(
            b.child_timeouts
                .iter()
                .filter(|p| p.0 == old)
                .collect::<Vec<_>>(),
            old_snapshots
                .1
                .iter()
                .filter(|p| p.0 == old)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            b.child_timestamps
                .iter()
                .filter(|p| p.0 == old)
                .collect::<Vec<_>>(),
            old_snapshots
                .2
                .iter()
                .filter(|p| p.0 == old)
                .collect::<Vec<_>>()
        );
        for (index, record) in b.connection_options.iter().enumerate() {
            assert!(
                !b.connection_options[..index]
                    .iter()
                    .any(|p| p.0 == record.0)
            );
        }
        for (index, record) in b.child_timeouts.iter().enumerate() {
            assert!(!b.child_timeouts[..index].iter().any(|p| p.0 == record.0));
        }
        for (index, record) in b.child_timestamps.iter().enumerate() {
            assert!(!b.child_timestamps[..index].iter().any(|p| p.0 == record.0));
        }
        assert!(b.connection_options.len() <= b.socket_limit());
        assert!(b.child_timeouts.len() <= b.socket_limit());
        assert!(b.child_timestamps.len() <= b.socket_limit());
        // A retransmitted peer FIN elicits an ACK from the restored owner,
        // exposing its actual send policy rather than only the saved snapshot.
        b.input_stamped(8_000, ip, 0, &close, Default::default())
            .unwrap();
        let mut bytes = [0; 128];
        let tx = b
            .endpoint
            .poll_transmit(8_000, &mut bytes, BUDGET)
            .unwrap()
            .packet
            .unwrap();
        assert_eq!(tx.connection, Some(old));
        assert_eq!(
            tx.dscp,
            old_snapshots.0.iter().find(|p| p.0 == old).unwrap().1 >> 2
        );
        let ack = ntcp::wire::parse(tx.ip, &bytes[..tx.len]).unwrap().header;
        assert_eq!(ack.acknowledgment, final_ack.acknowledgment);
        assert_eq!(ack.flags, ntcp::wire::ACK);
        return;
    }
    b.sockets.get_mut(&listener).unwrap().receive_timeout_us = 456_000;
    b.sockets.get_mut(&listener).unwrap().ipv6_tclass = 83;
    let ack = request(
        ip,
        40000,
        103,
        synack.sequence.wrapping_add(1),
        ntcp::wire::ACK,
        &[],
    );
    b.input_stamped(7_000, ip, 0, &ack, Default::default())
        .unwrap();
    b.test_now = Some(7_000);
    let fd = b
        .execute(listener, Op::Accept(SOCK_NONBLOCK))
        .unwrap()
        .value as u64;
    assert_eq!(b.sockets[&fd].receive_timeout_us, 123_000);
    assert_eq!(b.sockets[&fd].ipv6_tclass, 171);
    assert_eq!(
        b.endpoint
            .peek_rx_timestamps(child, 4)
            .unwrap()
            .unwrap()
            .timestamps,
        stamps
    );
    assert_eq!(b.execute(fd, Op::Read(8)).unwrap().bytes, b"data");
}
