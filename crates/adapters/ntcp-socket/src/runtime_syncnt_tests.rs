// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

fn syncnt(o: &mut Owner, id: u64) -> i32 {
    o.execute(id, Op::Get(IPPROTO_TCP, TCP_SYNCNT))
        .unwrap()
        .value
}

#[test]
fn syncnt_range_defaults_and_failed_open_are_transactional() {
    let mut a = owner(2);
    let id = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(syncnt(&mut a, id), 0);
    for value in [1, 2, 127] {
        a.execute(id, Op::Set(IPPROTO_TCP, TCP_SYNCNT, value))
            .unwrap();
        for invalid in [0, -1, i32::MIN, 128, 256, i32::MAX] {
            assert_eq!(
                a.execute(id, Op::Set(IPPROTO_TCP, TCP_SYNCNT, invalid))
                    .unwrap_err(),
                EINVAL
            );
            assert_eq!(syncnt(&mut a, id), value);
        }
    }
    // Force apply_options to fail after core admission, exercising rollback.
    a.sockets.get_mut(&id).unwrap().keepalive = true;
    a.sockets.get_mut(&id).unwrap().idle = 0;
    assert_eq!(
        a.execute(id, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINVAL
    );
    assert!(matches!(a.sockets[&id].handle, Handle::Fresh));
    assert_eq!(syncnt(&mut a, id), 127);
}

#[test]
fn syncnt_active_live_budget_and_held_owner() {
    for initial in [None, NonZeroU8::new(3)] {
        let mut a = owner(2);
        a.test_now = Some(1_000_000);
        let id = new(&mut a, SOCK_NONBLOCK);
        if let Some(n) = initial {
            a.execute(id, Op::Set(IPPROTO_TCP, TCP_SYNCNT, i32::from(n.get())))
                .unwrap();
        }
        assert_eq!(
            a.execute(id, Op::Connect("10.73.0.3:16379".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        let Handle::Connection(cid) = a.sockets[&id].handle else {
            panic!()
        };
        assert_eq!(
            a.endpoint.handshake_retransmission_limit(cid).unwrap(),
            initial
        );
        a.endpoint.enable_output_reservations().unwrap();
        let mut bytes = [0; 1480];
        // Original and first retry physically commit; held updates cannot mutate either view.
        for retry in 0..=1 {
            if retry != 0 {
                a.test_now = a.endpoint.next_deadline();
                a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
            }
            let (_, attempt) = a
                .endpoint
                .poll_reserved_transmit(a.now(), &mut bytes, BUDGET)
                .unwrap();
            let attempt = attempt.unwrap();
            assert_eq!(
                a.execute(id, Op::Set(IPPROTO_TCP, TCP_SYNCNT, 1))
                    .unwrap_err(),
                EAGAIN
            );
            // Even a direct dispatch cannot bypass the core owner barrier.
            assert_eq!(
                a.dispatch(id, Op::Set(IPPROTO_TCP, TCP_SYNCNT, 1))
                    .unwrap_err(),
                EINVAL
            );
            assert_eq!(a.sockets[&id].syn_retries, initial);
            assert_eq!(
                a.endpoint.handshake_retransmission_limit(cid).unwrap(),
                initial
            );
            assert!(a.endpoint.accept_transmit(a.now(), attempt).unwrap());
        }
        // Even retries accrued while unset count: lowering must not start a fresh budget.
        a.execute(id, Op::Set(IPPROTO_TCP, TCP_SYNCNT, 1)).unwrap();
        for invalid in [0, -1, 128] {
            assert_eq!(
                a.execute(id, Op::Set(IPPROTO_TCP, TCP_SYNCNT, invalid))
                    .unwrap_err(),
                EINVAL
            );
            assert_eq!(syncnt(&mut a, id), 1);
            assert_eq!(
                a.endpoint.handshake_retransmission_limit(cid).unwrap(),
                NonZeroU8::new(1)
            );
        }
        a.test_now = a.endpoint.next_deadline();
        a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
        a.events();
        assert_eq!(a.endpoint.state(cid).unwrap(), State::Closed);
        let terminal = a.execute(id, Op::Transport(1)).unwrap().bytes;
        assert_eq!(a.execute(id, Op::FinishConnect).unwrap_err(), ETIMEDOUT);
        assert_eq!(syncnt(&mut a, id), 1);
        assert_eq!(a.execute(id, Op::Transport(1)).unwrap().bytes, terminal);
    }
    // Unset preserves the endpoint's existing retry policy beyond one retry.
    let mut a = owner(2);
    a.test_now = Some(1_000_000);
    let id = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(id, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    let Handle::Connection(cid) = a.sockets[&id].handle else {
        panic!()
    };
    for _ in 0..3 {
        assert!(
            a.endpoint
                .poll_transmit(a.now(), &mut [0; 1480], BUDGET)
                .unwrap()
                .packet
                .is_some()
        );
        a.test_now = a.endpoint.next_deadline();
        a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
        assert_eq!(a.endpoint.state(cid).unwrap(), State::SynSent);
    }
    assert_eq!(syncnt(&mut a, id), 0);
}

#[test]
fn syncnt_listener_snapshot_survives_pending_updates_and_accept() {
    for initial in [0, 2] {
        let mut a = owner(2);
        let mut b = owner(3);
        let listener = new(&mut b, SOCK_NONBLOCK);
        if initial != 0 {
            b.execute(listener, Op::Set(IPPROTO_TCP, TCP_SYNCNT, initial))
                .unwrap();
        }
        b.execute(listener, Op::Bind("10.73.0.3:16379".parse().unwrap()))
            .unwrap();
        b.execute(listener, Op::Listen(4)).unwrap();
        let Handle::Listener(lid) = b.sockets[&listener].handle else {
            panic!()
        };
        assert_eq!(
            b.endpoint
                .listener_handshake_retransmission_limit(lid)
                .unwrap()
                .map_or(0, |n| i32::from(n.get())),
            initial
        );
        for expected in [initial, 3] {
            let client = new(&mut a, SOCK_NONBLOCK);
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
            b.input(b.now(), syn.ip, syn.dscp << 2 | syn.ecn, &bytes[..syn.len])
                .unwrap();
            let cid = b.child_timeouts[0].0;
            assert_eq!(b.endpoint.state(cid).unwrap(), State::SynReceived);
            b.execute(listener, Op::Set(IPPROTO_TCP, TCP_SYNCNT, 3))
                .unwrap();
            assert_eq!(
                b.execute(listener, Op::Set(IPPROTO_TCP, TCP_SYNCNT, 0))
                    .unwrap_err(),
                EINVAL
            );
            assert_eq!(syncnt(&mut b, listener), 3);
            assert_eq!(
                b.endpoint
                    .listener_handshake_retransmission_limit(lid)
                    .unwrap(),
                NonZeroU8::new(3)
            );
            // Duplicate SYN does not refresh the pending child's snapshot.
            b.input(b.now(), syn.ip, syn.dscp << 2 | syn.ecn, &bytes[..syn.len])
                .unwrap();
            assert_eq!(
                b.endpoint
                    .handshake_retransmission_limit(cid)
                    .unwrap()
                    .map_or(0, |n| i32::from(n.get())),
                expected
            );
            pump(&mut a, &mut b);
            let child = b.execute(listener, Op::Accept(0)).unwrap().value as u64;
            assert_eq!(syncnt(&mut b, child), expected);
            assert_eq!(
                b.endpoint
                    .handshake_retransmission_limit(cid)
                    .unwrap()
                    .map_or(0, |n| i32::from(n.get())),
                expected
            );
        }
    }
}
