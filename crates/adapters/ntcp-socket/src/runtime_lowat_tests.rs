// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
fn lowat_pair(default: u32) -> (Owner, Owner, u64, u64) {
    let mut a = owner(2);
    let mut b = owner(3);
    a.socket_policy.notsent_lowat = default;
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
    (a, b, client, server)
}

#[test]
fn global_lowat_admission_override_reset_and_independent_owners() {
    for kind in 0..4 {
        let (mut a, mut b, client, server) = lowat_pair(4000);
        assert_eq!(
            a.execute(client, Op::Get(IPPROTO_TCP, TCP_NOTSENT_LOWAT))
                .unwrap()
                .value,
            0
        );
        let Handle::Connection(cid) = a.sockets[&client].handle else {
            panic!()
        };
        let goal = send::batch_goal(&a.endpoint.transport_info(cid).unwrap());
        let bytes = vec![7; goal + 17];
        let sources = vec![(bytes.as_ptr() as usize, bytes.len()), (0, 1)];
        let op = match kind {
            0 => Op::Write(bytes.clone()),
            1 => Op::WriteFlags(bytes.clone(), MSG_MORE),
            2 => Op::Send(sources, MSG_MORE),
            _ => Op::SendTimestamp(sources, MSG_MORE, 0),
        };
        assert_eq!(a.execute(client, op).unwrap().value as usize, goal);
        assert_eq!(a.execute(client, Op::Write(vec![1])).unwrap_err(), EAGAIN);
        // Another owner retains its own unlimited policy.
        assert_eq!(
            b.execute(server, Op::WriteFlags(bytes, MSG_MORE))
                .unwrap()
                .value,
            (goal + 17) as i32
        );
        for (raw, admitted) in [(6000, 0), (0, 0), (-1, 9000)] {
            a.execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, raw))
                .unwrap();
            assert_eq!(
                a.execute(client, Op::Get(IPPROTO_TCP, TCP_NOTSENT_LOWAT))
                    .unwrap()
                    .value,
                raw
            );
            // A full batch exceeds the lowat override; readiness remains separate.
            let expected_ready = raw == -1;
            assert_eq!(
                a.execute(client, Op::Ready).unwrap().value & EPOLLOUT != 0,
                expected_ready
            );
            let result = a.execute(client, Op::WriteFlags(vec![2; 9000], MSG_MORE));
            if admitted == 0 {
                assert_eq!(result.unwrap_err(), EAGAIN);
            } else {
                assert_eq!(result.unwrap().value, admitted);
            }
        }
    }
}

#[test]
fn global_zero_is_not_remapped_and_rejects_before_producer_or_copy() {
    let (mut a, _b, client, _) = lowat_pair(0);
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        panic!()
    };
    assert_eq!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
    assert_eq!(
        a.execute(client, Op::Send(vec![(0, 1)], 0)).unwrap_err(),
        EAGAIN
    );
    assert_eq!(
        a.timestamp_write_from::<Vec<u8>>(client, cid, 1, 0, 0, |_| panic!(
            "producer consumed at zero admission"
        ))
        .unwrap_err(),
        EAGAIN
    );
    assert_eq!(a.execute(client, Op::Write(Vec::new())).unwrap().value, 0);
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, 1))
        .unwrap();
    assert_ne!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
    assert_eq!(
        a.execute(client, Op::WriteFlags(vec![1; 2], MSG_MORE))
            .unwrap()
            .value,
        2
    );
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, 0))
        .unwrap();
    assert_eq!(a.execute(client, Op::Write(vec![1])).unwrap_err(), EAGAIN);
}

#[test]
fn global_lowat_blocking_logical_send_and_drain_readiness() {
    let (mut a, mut b, client, server) = lowat_pair(4000);
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        panic!()
    };
    let goal = send::batch_goal(&a.endpoint.transport_info(cid).unwrap());
    let bytes = vec![1; 3 * goal];
    let (mut request, rx) = logical_request(
        &mut a,
        client,
        Op::Send(vec![(bytes.as_ptr() as usize, bytes.len())], MSG_MORE),
    );
    assert!(!a.service(&mut request));
    assert_eq!(request.send.as_ref().unwrap().accepted, goal);
    let blocked = a.execute(client, Op::Ready).unwrap();
    assert_eq!(blocked.value & EPOLLOUT, 0);
    assert!(!a.service(&mut request));
    assert_eq!(request.send.as_ref().unwrap().accepted, goal);
    let mut finished = false;
    for _ in 0..100 {
        advance(&mut a, &mut b);
        while b.execute(server, Op::Read(BYTES)).is_ok() {}
        finished = a.service(&mut request);
        if finished {
            break;
        }
    }
    assert!(finished);
    assert_eq!(rx.recv().unwrap().unwrap().value as usize, bytes.len());
    // MSG_MORE still applies to the completed logical send's final tail.
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    for _ in 0..10 {
        advance(&mut a, &mut b);
        while b.execute(server, Op::Read(BYTES)).is_ok() {}
    }
    let ready = a.execute(client, Op::Ready).unwrap();
    assert_ne!(ready.value & EPOLLOUT, 0);
    assert!(socket_options::edge_changed(
        EPOLLOUT as u32,
        Some(blocked.readiness_generations),
        ready.readiness_generations,
    ));
}

#[test]
fn global_lowat_accept_inherits_raw_listener_snapshot() {
    for raw in [0, 2000, -1] {
        let mut a = owner(2);
        let mut b = owner(3);
        b.socket_policy.notsent_lowat = 4000;
        let listener = new(&mut b, SOCK_NONBLOCK);
        b.execute(listener, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, raw))
            .unwrap();
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
        b.execute(listener, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, 1))
            .unwrap();
        let child = b
            .execute(listener, Op::Accept(SOCK_NONBLOCK))
            .unwrap()
            .value as u64;
        assert_eq!(
            b.execute(child, Op::Get(IPPROTO_TCP, TCP_NOTSENT_LOWAT))
                .unwrap()
                .value,
            raw
        );
        assert_eq!(
            b.execute(child, Op::WriteFlags(vec![1; 9000], MSG_MORE))
                .unwrap()
                .value,
            9000
        );
    }
}

#[test]
fn global_zero_native_transfer_leaves_pipe_unconsumed() {
    let (mut a, _b, client, _) = lowat_pair(0);
    let mut source = [-1; 2];
    let mut staging = [-1; 2];
    unsafe {
        assert_eq!(
            syscall(SYS_pipe2, source.as_mut_ptr(), O_NONBLOCK | O_CLOEXEC),
            0
        );
        assert_eq!(
            syscall(SYS_pipe2, staging.as_mut_ptr(), O_NONBLOCK | O_CLOEXEC),
            0
        );
        assert_eq!(syscall(SYS_write, source[1], b"abc".as_ptr(), 3), 3);
    }
    let _fds: Vec<_> = source.into_iter().chain(staging).map(Retained).collect();
    let op = Op::Transfer {
        source: source[0],
        staging,
        offset: None,
        count: 3,
        flags: MSG_MORE,
    };
    assert_eq!(a.execute(client, op.clone()).unwrap_err(), EAGAIN);
    let mut queued = 0i32;
    assert_eq!(
        unsafe { syscall(SYS_ioctl, source[0], FIONREAD, &mut queued) },
        0
    );
    assert_eq!(queued, 3);
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, 2))
        .unwrap();
    assert_eq!(a.execute(client, op.clone()).unwrap().value, 3);
    assert_eq!(a.execute(client, op).unwrap().value, -EAGAIN);
    assert_eq!(
        unsafe { syscall(SYS_ioctl, source[0], FIONREAD, &mut queued) },
        0
    );
    assert_eq!(queued, 0);
}

#[test]
fn lowat_batched_logical_send_has_one_timestamp_and_zerocopy_completion() {
    let (mut a, mut b, client, server) = lowat_pair(4000);
    a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    timestamp_set(
        &mut a,
        client,
        ts::TX_SCHED
            | ts::TX_SOFTWARE
            | ts::TX_ACK
            | ts::SOFTWARE
            | ts::OPT_TSONLY
            | ts::OPT_ID
            | ts::OPT_ID_TCP,
    );
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        panic!()
    };
    let goal = send::batch_goal(&a.endpoint.transport_info(cid).unwrap());
    let bytes: Vec<u8> = (0..3 * goal).map(|i| (i % 251) as u8).collect();
    let (reply, rx) = mpsc::sync_channel(1);
    let mut request = Request {
        id: client,
        op: Op::Send(
            vec![
                (bytes.as_ptr() as usize, goal + 3),
                (bytes[goal + 3..].as_ptr() as usize, bytes.len() - goal - 3),
            ],
            MSG_ZEROCOPY | MSG_EOR,
        ),
        reply,
        deadline: None,
        send: None,
        closing: None,
    };
    let mut received = Vec::new();
    let mut finished = false;
    for _ in 0..BUDGET + 2 {
        finished = a.service(&mut request);
        if !finished {
            assert_eq!(a.sockets[&client].zc_next, 1);
            assert_eq!(a.sockets[&client].zc_reserved, 1);
            assert!(a.sockets[&client].completions.is_empty());
        }
        advance(&mut a, &mut b);
        while let Ok(part) = b.execute(server, Op::Read(BYTES)) {
            received.extend(part.bytes);
        }
        if finished {
            break;
        }
    }
    assert!(finished);
    let n = rx.try_recv().unwrap().unwrap().value as usize;
    assert!(n >= goal && n <= bytes.len());
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    for _ in 0..20 {
        advance(&mut a, &mut b);
        while let Ok(part) = b.execute(server, Op::Read(BYTES)) {
            received.extend(part.bytes);
        }
    }
    assert_eq!(received, bytes[..n]);
    let records = timestamp_records(&a, client);
    assert_eq!(records.len(), 3, "{records:?}");
    assert!(records.iter().all(|r| r.1 == n as u32 - 1 && r.2 > 0));
    assert_eq!(a.sockets[&client].zc_next, 1);
    assert_eq!(a.sockets[&client].zc_reserved, 0);
    assert_eq!(
        a.sockets[&client]
            .completions
            .iter()
            .filter_map(Completion::range)
            .collect::<Vec<_>>(),
        [(0, 0)]
    );
    assert!(a.sockets[&client].send_batch.is_none());
}
