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
        let bytes = vec![7; 9000];
        let sources = vec![(bytes.as_ptr() as usize, bytes.len()), (0, 1)];
        let op = match kind {
            0 => Op::Write(bytes.clone()),
            1 => Op::WriteFlags(bytes.clone(), MSG_MORE),
            2 => Op::Send(sources, MSG_MORE),
            _ => Op::SendTimestamp(sources, MSG_MORE, 0),
        };
        assert_eq!(a.execute(client, op).unwrap().value, 4000);
        assert_eq!(a.execute(client, Op::Write(vec![1])).unwrap_err(), EAGAIN);
        // Another owner retains its own unlimited policy.
        assert_eq!(
            b.execute(server, Op::WriteFlags(bytes, MSG_MORE))
                .unwrap()
                .value,
            9000
        );
        for (raw, admitted) in [(6000, 2000), (0, 0), (-1, 9000)] {
            a.execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, raw))
                .unwrap();
            assert_eq!(
                a.execute(client, Op::Get(IPPROTO_TCP, TCP_NOTSENT_LOWAT))
                    .unwrap()
                    .value,
                raw
            );
            // 4000 queued bytes exceed half the 6000 admission override.
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
        1
    );
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, 0))
        .unwrap();
    assert_eq!(a.execute(client, Op::Write(vec![1])).unwrap_err(), EAGAIN);
}

#[test]
fn global_lowat_blocking_logical_send_and_drain_readiness() {
    let (mut a, mut b, client, _) = lowat_pair(4000);
    let bytes = vec![1; 9000];
    let (mut request, rx) = logical_request(
        &mut a,
        client,
        Op::Send(vec![(bytes.as_ptr() as usize, bytes.len())], MSG_MORE),
    );
    assert!(!a.service(&mut request));
    assert_eq!(request.send.as_ref().unwrap().accepted, 4000);
    let blocked = a.execute(client, Op::Ready).unwrap();
    assert_eq!(blocked.value & EPOLLOUT, 0);
    assert!(!a.service(&mut request));
    assert_eq!(request.send.as_ref().unwrap().accepted, 4000);
    advance(&mut a, &mut b);
    let ready = a.execute(client, Op::Ready).unwrap();
    assert_ne!(ready.value & EPOLLOUT, 0);
    assert!(socket_options::edge_changed(
        EPOLLOUT as u32,
        Some(blocked.readiness_generations),
        ready.readiness_generations
    ));
    assert!(!a.service(&mut request));
    assert_eq!(request.send.as_ref().unwrap().accepted, 8000);
    advance(&mut a, &mut b);
    assert!(a.service(&mut request));
    assert_eq!(rx.recv().unwrap().unwrap().value, 9000);
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
            match raw {
                0 => 4000,
                -1 => 9000,
                _ => raw,
            }
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
    assert_eq!(a.execute(client, op.clone()).unwrap().value, 2);
    assert_eq!(a.execute(client, op).unwrap_err(), EAGAIN);
    assert_eq!(
        unsafe { syscall(SYS_ioctl, source[0], FIONREAD, &mut queued) },
        0
    );
    assert_eq!(queued, 1);
}
