// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// Included by runtime_memory_tests: bounded PacketIo and production Egress only.
fn tfo_listener(b: &mut Owner) -> u64 {
    let listener = new(b, SOCK_NONBLOCK);
    b.execute(listener, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 4))
        .unwrap();
    b.execute(listener, Op::Bind("192.0.2.2:8080".parse().unwrap()))
        .unwrap();
    b.execute(listener, Op::Listen(4)).unwrap();
    listener
}
fn tfo_send(bytes: &[u8], flags: i32) -> Op {
    Op::SendTo(
        vec![(bytes.as_ptr() as usize, bytes.len())],
        flags,
        Some("192.0.2.2:8080".parse().unwrap()),
        None,
    )
}
fn tfo_setup(warm: bool) -> (Owner, Owner, u64) {
    let mut a = owner(1, Profile::Pipeline, 8);
    let mut b = owner(2, Profile::Pipeline, 8);
    let listener = tfo_listener(&mut b);
    if warm {
        let client = new(&mut a, SOCK_NONBLOCK);
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
            .unwrap();
        assert_eq!(
            a.execute(client, Op::Connect("192.0.2.2:8080".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        exchange(&mut a, &mut b);
        let server = b
            .execute(listener, Op::Accept(SOCK_NONBLOCK))
            .unwrap()
            .value as u64;
        a.execute(client, Op::Close).unwrap();
        b.execute(server, Op::Close).unwrap();
        exchange(&mut a, &mut b);
        assert!(!a.sockets.contains_key(&client));
        assert!(
            a.endpoint
                .has_fast_open_cookie(a.now(), a.local.into(), b.local.into())
                .unwrap()
        );
    }
    (a, b, listener)
}
fn tfo_capture(a: &mut Owner) -> Vec<u8> {
    a.service_egress().unwrap();
    a.execute(0, Op::Capture(65535)).unwrap().bytes
}
fn tfo_deliver(b: &mut Owner, bytes: Vec<u8>) {
    b.execute(0, Op::Inject(bytes)).unwrap();
    receive(b);
}
fn tfo_no_output(a: &mut Owner) {
    a.service_egress().unwrap();
    assert_eq!(a.execute(0, Op::Capture(65535)).unwrap_err(), EAGAIN);
}

#[test]
fn fast_open_options_default_off_and_listener_updates() {
    let mut a = owner(1, Profile::Pipeline, 8);
    let id = new(&mut a, SOCK_NONBLOCK);
    for option in [TCP_FASTOPEN, TCP_FASTOPEN_CONNECT] {
        assert_eq!(
            a.execute(id, Op::Get(IPPROTO_TCP, option)).unwrap().value,
            0
        );
        assert_eq!(
            a.execute(id, Op::Set(IPPROTO_TCP, option, -1)).unwrap_err(),
            EINVAL
        );
        a.execute(id, Op::Set(IPPROTO_TCP, option, 1)).unwrap();
        assert_eq!(
            a.execute(id, Op::Get(IPPROTO_TCP, option)).unwrap().value,
            1
        );
        a.execute(id, Op::Set(IPPROTO_TCP, option, 0)).unwrap();
    }
    assert_eq!(
        a.execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 2))
            .unwrap_err(),
        EINVAL
    );
    a.execute(id, Op::Listen(2)).unwrap();
    a.execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 3))
        .unwrap();
    assert_eq!(
        a.execute(id, Op::Get(IPPROTO_TCP, TCP_FASTOPEN))
            .unwrap()
            .value,
        3
    );
    assert_eq!(
        a.execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
            .unwrap_err(),
        EINVAL
    );
    a.execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 0))
        .unwrap();
    let plain = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(plain, Op::Connect("192.0.2.2:8080".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    let syn = tfo_capture(&mut a);
    assert!(segment(&syn).options.fast_open.is_none());
    assert!(segment(&syn).payload.is_empty());
    assert_eq!(
        a.execute(plain, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 1))
            .unwrap_err(),
        EINVAL
    );
}

#[test]
fn fast_open_deferred_fault_retry_partial_and_server_early_response_barrier() {
    let (mut a, mut b, listener) = tfo_setup(true);
    let client = new(&mut a, SOCK_NONBLOCK);
    for option in [TCP_FASTOPEN, TCP_FASTOPEN_CONNECT] {
        a.execute(client, Op::Set(IPPROTO_TCP, option, 1)).unwrap();
    }
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    a.execute(client, Op::Set(SOL_SOCKET, SO_SNDBUF, 2304))
        .unwrap();
    a.execute(client, Op::Set(SOL_SOCKET, SO_RCVBUF, 4096))
        .unwrap();
    let remote = "192.0.2.2:8080".parse().unwrap();
    assert_eq!(a.execute(client, Op::Connect(remote)).unwrap().value, 0);
    assert_eq!(
        a.execute(client, Op::Name(true)).unwrap().addr,
        Some(remote)
    );
    assert_ne!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
    assert_eq!(a.execute(client, Op::Read(1)).unwrap_err(), EAGAIN);
    assert_eq!(a.execute(client, Op::Connect(remote)).unwrap_err(), EISCONN);
    assert_eq!(
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 0))
            .unwrap_err(),
        EINVAL
    );
    tfo_no_output(&mut a);
    let local = a.sockets[&client].local;
    let bytes = vec![42; 4000];
    assert_eq!(
        a.execute(
            client,
            Op::Send(vec![(bytes.as_ptr() as usize, 4), (1, 100)], 0)
        )
        .unwrap_err(),
        EFAULT
    );
    assert!(matches!(a.sockets[&client].handle, Handle::Fresh));
    assert_eq!(a.sockets[&client].deferred_peer, Some(remote));
    assert_eq!(a.sockets[&client].local, local);
    tfo_no_output(&mut a);
    let n = a
        .execute(
            client,
            Op::Send(vec![(bytes.as_ptr() as usize, bytes.len())], 0),
        )
        .unwrap()
        .value as usize;
    assert!(n > 0 && n < bytes.len());
    let connection = cid(&a, client);
    assert_eq!(
        a.endpoint.buffer_capacities(connection).unwrap(),
        (4608, 8192)
    );
    assert_eq!(a.endpoint.transport_info(connection).unwrap().send_used, n);
    let syn = tfo_capture(&mut a);
    let parsed = segment(&syn);
    assert_ne!(parsed.header.flags & ntcp::wire::SYN, 0);
    assert!(!parsed.options.fast_open.unwrap().as_bytes().is_empty());
    assert_eq!(parsed.payload, &bytes[..n]);
    assert_eq!(
        a.execute(client, tfo_send(b"again", MSG_FASTOPEN))
            .unwrap_err(),
        EALREADY
    );
    tfo_deliver(&mut b, syn);
    let server = b
        .execute(listener, Op::Accept(SOCK_NONBLOCK))
        .unwrap()
        .value as u64;
    assert_eq!(
        b.endpoint.state(cid(&b, server)).unwrap(),
        State::SynReceived
    );
    assert_eq!(
        b.execute(server, Op::Read(BYTES)).unwrap().bytes,
        bytes[..n]
    );
    assert_ne!(b.execute(server, Op::Ready).unwrap().value & EPOLLOUT, 0);
    assert_eq!(
        b.execute(server, Op::Send(vec![(b"reply".as_ptr() as usize, 5)], 0))
            .unwrap()
            .value,
        5
    );
    let syn_ack = tfo_capture(&mut b);
    assert_eq!(
        segment(&syn_ack).header.flags & (ntcp::wire::SYN | ntcp::wire::ACK),
        ntcp::wire::SYN | ntcp::wire::ACK
    );
    assert!(segment(&syn_ack).payload.is_empty());
    tfo_no_output(&mut b);
    tfo_deliver(&mut a, syn_ack);
    let ack = tfo_capture(&mut a);
    assert_eq!(segment(&ack).header.flags & ntcp::wire::SYN, 0);
    tfo_no_output(&mut b);
    tfo_deliver(&mut b, ack);
    exchange(&mut a, &mut b);
    assert_eq!(a.execute(client, Op::Read(5)).unwrap().bytes, b"reply");
    assert_eq!(
        a.execute(client, tfo_send(b"again", MSG_FASTOPEN))
            .unwrap_err(),
        EISCONN
    );
    assert_eq!(
        a.execute(
            client,
            Op::Send(vec![(bytes[n..].as_ptr() as usize, bytes.len() - n)], 0)
        )
        .unwrap()
        .value as usize,
        bytes.len() - n
    );
    exchange(&mut a, &mut b);
    assert_eq!(
        b.execute(server, Op::Read(BYTES)).unwrap().bytes,
        bytes[n..]
    );
}

#[test]
fn fast_open_miss_nonblocking_and_dontwait_retries_do_not_accept_payload() {
    for flags in [0, MSG_DONTWAIT] {
        let (mut a, mut b, listener) = tfo_setup(false);
        let client = new(&mut a, if flags == 0 { SOCK_NONBLOCK } else { 0 });
        assert_eq!(
            a.execute(
                client,
                Op::SendTo(
                    vec![(1, 9)],
                    MSG_FASTOPEN | flags,
                    Some("192.0.2.2:8080".parse().unwrap()),
                    None
                )
            )
            .unwrap_err(),
            EFAULT
        );
        tfo_no_output(&mut a);
        assert_eq!(
            a.execute(client, tfo_send(b"hello", MSG_FASTOPEN | flags))
                .unwrap_err(),
            EINPROGRESS
        );
        assert_eq!(
            a.endpoint
                .transport_info(cid(&a, client))
                .unwrap()
                .send_used,
            0
        );
        let syn = tfo_capture(&mut a);
        assert!(segment(&syn).payload.is_empty());
        assert!(
            segment(&syn)
                .options
                .fast_open
                .unwrap()
                .as_bytes()
                .is_empty()
        );
        tfo_deliver(&mut b, syn);
        exchange(&mut a, &mut b);
        let server = b
            .execute(listener, Op::Accept(SOCK_NONBLOCK))
            .unwrap()
            .value as u64;
        assert_eq!(b.execute(server, Op::Read(9)).unwrap_err(), EAGAIN);
        assert_eq!(
            a.execute(client, tfo_send(b"hello", flags)).unwrap().value,
            5
        );
        exchange(&mut a, &mut b);
        assert_eq!(b.execute(server, Op::Read(9)).unwrap().bytes, b"hello");
    }
}

#[test]
fn fast_open_blocking_hit_and_miss_wait_handshake_and_complete_iovecs() {
    for warm in [false, true] {
        let (mut a, mut b, listener) = tfo_setup(warm);
        let client = new(&mut a, 0);
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
            .unwrap();
        let first = vec![1; 2000];
        let second = vec![2; 1000];
        let (reply, rx) = mpsc::sync_channel(1);
        let mut request = Request {
            id: client,
            op: Op::Wait(
                Box::new(Op::SendTo(
                    vec![
                        (0, 0),
                        (first.as_ptr() as usize, first.len()),
                        (second.as_ptr() as usize, second.len()),
                    ],
                    MSG_FASTOPEN,
                    Some("192.0.2.2:8080".parse().unwrap()),
                    None,
                )),
                None,
            ),
            reply,
            deadline: None,
            send: None,
            closing: None,
        };
        assert!(!a.service(&mut request));
        assert!(rx.try_recv().is_err());
        assert!(!a.service(&mut request));
        exchange(&mut a, &mut b);
        assert!(a.service(&mut request));
        assert_eq!(rx.recv().unwrap().unwrap().value, 3000);
        exchange(&mut a, &mut b);
        let server = b
            .execute(listener, Op::Accept(SOCK_NONBLOCK))
            .unwrap()
            .value as u64;
        assert_eq!(
            b.execute(server, Op::Read(BYTES)).unwrap().bytes,
            [first, second].concat()
        );
    }
}

#[test]
fn fast_open_rejects_unsafe_completions_and_deferred_close_sends_nothing() {
    let (mut a, _b, _) = tfo_setup(true);
    let client = new(&mut a, SOCK_NONBLOCK);
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
        .unwrap();
    a.execute(client, Op::Connect("192.0.2.2:8080".parse().unwrap()))
        .unwrap();
    assert_eq!(
        a.execute(client, tfo_send(b"hello", MSG_ZEROCOPY))
            .unwrap_err(),
        EOPNOTSUPP
    );
    a.execute(
        client,
        Op::Set(
            SOL_SOCKET,
            37,
            (crate::timestamping::TX_SOFTWARE | crate::timestamping::SOFTWARE) as i32,
        ),
    )
    .unwrap();
    assert_eq!(
        a.execute(client, tfo_send(b"hello", 0)).unwrap_err(),
        EOPNOTSUPP
    );
    assert_eq!(
        a.execute(
            client,
            Op::Transfer {
                source: -1,
                staging: [-1; 2],
                offset: None,
                count: 1,
                flags: 0
            }
        )
        .unwrap_err(),
        EOPNOTSUPP
    );
    assert!(a.sockets[&client].deferred_peer.is_some());
    tfo_no_output(&mut a);
    a.execute(client, Op::Close).unwrap();
    assert!(!a.sockets.contains_key(&client));
    tfo_no_output(&mut a);
}

#[test]
fn fast_open_empty_payload_destination_and_lowwater() {
    for warm in [false, true] {
        let (mut a, _b, _) = tfo_setup(warm);
        let client = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(client, Op::Send(vec![(0, 0)], MSG_FASTOPEN))
                .unwrap_err(),
            EINVAL
        );
        tfo_no_output(&mut a);
        assert_eq!(
            a.execute(client, tfo_send(&[], MSG_FASTOPEN)).unwrap_err(),
            EINPROGRESS
        );
        assert!(segment(&tfo_capture(&mut a)).payload.is_empty());
    }
    let (mut a, _b, _) = tfo_setup(true);
    let client = new(&mut a, SOCK_NONBLOCK);
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, 7))
        .unwrap();
    assert_eq!(
        a.execute(client, tfo_send(&[3; 100], MSG_FASTOPEN))
            .unwrap()
            .value,
        7
    );
    assert_eq!(segment(&tfo_capture(&mut a)).payload, &[3; 7]);
}

#[test]
fn fast_open_small_blocking_send_waits_even_when_all_bytes_fit_syn() {
    let (mut a, mut b, _) = tfo_setup(true);
    let client = new(&mut a, 0);
    let (reply, rx) = mpsc::sync_channel(1);
    let mut request = Request {
        id: client,
        op: Op::Wait(Box::new(tfo_send(b"hi", MSG_FASTOPEN)), None),
        reply,
        deadline: None,
        send: None,
        closing: None,
    };
    assert!(!a.service(&mut request));
    assert_eq!(request.send.as_ref().unwrap().accepted, 2);
    assert!(!a.service(&mut request));
    assert!(rx.try_recv().is_err());
    exchange(&mut a, &mut b);
    assert!(a.service(&mut request));
    assert_eq!(rx.recv().unwrap().unwrap().value, 2);
}

#[test]
fn fast_open_disabled_listener_falls_back_without_early_accept() {
    let (mut a, mut b, listener) = tfo_setup(true);
    b.execute(listener, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 0))
        .unwrap();
    let client = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(client, tfo_send(b"retry", MSG_FASTOPEN))
            .unwrap()
            .value,
        5
    );
    tfo_deliver(&mut b, tfo_capture(&mut a));
    assert_eq!(
        b.execute(listener, Op::Accept(SOCK_NONBLOCK)).unwrap_err(),
        EAGAIN
    );
    exchange(&mut a, &mut b);
    let server = b
        .execute(listener, Op::Accept(SOCK_NONBLOCK))
        .unwrap()
        .value as u64;
    assert_eq!(b.execute(server, Op::Read(9)).unwrap().bytes, b"retry");
    assert_eq!(b.execute(server, Op::Read(9)).unwrap_err(), EAGAIN);
}

#[test]
fn fast_open_reserved_syn_preserves_last_close_output_barrier() {
    let (mut a, _b, _) = tfo_setup(true);
    for _ in 0..8 {
        assert_eq!(
            a.packets.as_mut().unwrap().transmit(&[0]).unwrap(),
            TxOutcome::Submitted
        );
    }
    let client = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(client, tfo_send(b"held", MSG_FASTOPEN))
            .unwrap()
            .value,
        4
    );
    a.service_egress().unwrap();
    let connection = cid(&a, client);
    assert!(a.endpoint.is_output_reserved(connection));
    let (reply, rx) = mpsc::sync_channel(1);
    let mut request = Request {
        id: client,
        op: Op::Close,
        reply,
        deadline: None,
        send: None,
        closing: None,
    };
    assert!(!a.service(&mut request));
    assert!(a.sockets.contains_key(&client));
    assert!(rx.try_recv().is_err());
    for _ in 0..8 {
        assert_eq!(a.execute(0, Op::Capture(65535)).unwrap().bytes, [0]);
    }
    // Production egress schedules WouldBlock retries exactly 1000 ticks later.
    a.test_now = Some(a.now() + 1000);
    let syn = tfo_capture(&mut a);
    assert_eq!(segment(&syn).payload, b"held");
    assert!(!a.service(&mut request));
    assert!(!a.sockets.contains_key(&client));
    a.service_egress().unwrap();
    assert!(a.service(&mut request));
    rx.recv().unwrap().unwrap();
}

#[test]
fn fast_open_early_child_snapshots_zerocopy_and_completes_both_handshake_sides() {
    let (mut a, mut b, listener) = tfo_setup(true);
    b.execute(listener, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    b.execute(listener, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    let client = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(client, tfo_send(b"request", MSG_FASTOPEN))
            .unwrap()
            .value,
        7
    );
    tfo_deliver(&mut b, tfo_capture(&mut a));
    // Changing the listener after early eligibility must not change the snapshot.
    b.execute(listener, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 0))
        .unwrap();
    let server = b
        .execute(listener, Op::Accept(SOCK_NONBLOCK))
        .unwrap()
        .value as u64;
    let connection = cid(&b, server);
    assert_eq!(b.endpoint.state(connection).unwrap(), State::SynReceived);
    assert_eq!(
        b.execute(server, Op::Get(SOL_SOCKET, SO_ZEROCOPY))
            .unwrap()
            .value,
        1
    );
    assert_eq!(
        b.connection_options
            .iter()
            .find(|p| p.0 == connection)
            .unwrap()
            .3,
        Some(true)
    );
    assert_eq!(b.execute(server, Op::Read(7)).unwrap().bytes, b"request");
    assert_eq!(
        b.execute(
            server,
            Op::Send(vec![(b"early".as_ptr() as usize, 5)], MSG_ZEROCOPY)
        )
        .unwrap()
        .value,
        5
    );
    assert_eq!(b.sockets[&server].zc_next, 1);
    assert_eq!(b.sockets[&server].zc_reserved, 0);
    assert_eq!(
        b.sockets[&server]
            .completions
            .iter()
            .filter_map(Completion::range)
            .collect::<Vec<_>>(),
        [(0, 0)]
    );
    assert_ne!(b.execute(server, Op::Ready).unwrap().value & EPOLLERR, 0);
    assert_eq!(b.endpoint.transport_info(connection).unwrap().send_used, 5);
    let early_end = b.endpoint.send_progress(connection).unwrap().queued_end;
    let syn_ack = tfo_capture(&mut b);
    assert!(segment(&syn_ack).payload.is_empty());
    tfo_no_output(&mut b);
    tfo_deliver(&mut a, syn_ack);
    let ack = tfo_capture(&mut a);
    assert_eq!(segment(&ack).header.flags & ntcp::wire::SYN, 0);
    tfo_no_output(&mut b);
    tfo_deliver(&mut b, ack);
    assert_eq!(b.endpoint.state(connection).unwrap(), State::Established);
    exchange(&mut a, &mut b);
    assert_eq!(a.execute(client, Op::Read(5)).unwrap().bytes, b"early");
    assert_eq!(
        b.execute(
            server,
            Op::Send(vec![(b"later!".as_ptr() as usize, 6)], MSG_ZEROCOPY)
        )
        .unwrap()
        .value,
        6
    );
    assert_eq!(
        b.execute(server, Op::Get(SOL_SOCKET, SO_ZEROCOPY))
            .unwrap()
            .value,
        1
    );
    assert_eq!(b.sockets[&server].zc_next, 2);
    assert_eq!(b.sockets[&server].zc_reserved, 0);
    assert_eq!(
        b.sockets[&server]
            .completions
            .iter()
            .filter_map(Completion::range)
            .collect::<Vec<_>>(),
        [(0, 1)]
    );
    assert_eq!(
        b.endpoint.send_progress(connection).unwrap().queued_end,
        early_end + 6
    );
    exchange(&mut a, &mut b);
    assert_eq!(a.execute(client, Op::Read(6)).unwrap().bytes, b"later!");
}

#[test]
fn fast_open_listener_keeps_ordinary_zerocopy_snapshot_at_final_ack() {
    for initial in [0, 1] {
        let (mut a, mut b, listener) = tfo_setup(false);
        b.execute(listener, Op::Set(SOL_SOCKET, SO_ZEROCOPY, initial))
            .unwrap();
        let client = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(client, Op::Connect("192.0.2.2:8080".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        tfo_deliver(&mut b, tfo_capture(&mut a));
        assert!(b.connection_options.iter().all(|p| p.3.is_none()));
        b.execute(listener, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1 - initial))
            .unwrap();
        exchange(&mut a, &mut b);
        b.execute(listener, Op::Set(SOL_SOCKET, SO_ZEROCOPY, initial))
            .unwrap();
        let server = b
            .execute(listener, Op::Accept(SOCK_NONBLOCK))
            .unwrap()
            .value as u64;
        assert_eq!(
            b.execute(server, Op::Get(SOL_SOCKET, SO_ZEROCOPY))
                .unwrap()
                .value,
            1 - initial
        );
    }
}

#[test]
fn fast_open_blocking_send_reset_finishes_with_error_or_accepted_prefix() {
    for warm in [false, true] {
        let (mut a, mut b, listener) = tfo_setup(warm);
        let client = new(&mut a, 0);
        let (reply, rx) = mpsc::sync_channel(1);
        let mut request = Request {
            id: client,
            op: Op::Wait(Box::new(tfo_send(b"hi", MSG_FASTOPEN)), None),
            reply,
            deadline: None,
            send: None,
            closing: None,
        };
        assert!(!a.service(&mut request));
        assert_eq!(
            request.send.as_ref().unwrap().accepted,
            if warm { 2 } else { 0 }
        );
        // A closed destination produces the valid RST+ACK required in SynSent.
        b.execute(listener, Op::Close).unwrap();
        tfo_deliver(&mut b, tfo_capture(&mut a));
        let reset = tfo_capture(&mut b);
        assert_ne!(segment(&reset).header.flags & ntcp::wire::RST, 0);
        tfo_deliver(&mut a, reset);
        assert!(a.service(&mut request));
        assert!(request.send.is_none());
        let result = rx.try_recv().expect("reset must finish the blocked send");
        if warm {
            // The copied SYN prefix was already accepted before the reset.
            assert_eq!(result.unwrap().value, 2);
        } else {
            assert_eq!(result.unwrap_err(), ECONNREFUSED);
        }
    }
}
