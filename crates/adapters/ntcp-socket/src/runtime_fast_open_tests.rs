// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// TCP Fast Open client and listener socket behavior over the bounded in-memory
// PacketIo and production Egress. The tfo_* helpers are shared with the other
// packet-test suites.
use super::memory::tests::{cid, exchange, owner, receive, segment};
use super::tests::new;
use super::*;
use crate::packet_profile::Profile;

fn tfo_listener(b: &mut Owner) -> u64 {
    let listener = new(b, SOCK_NONBLOCK);
    b.execute(listener, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 4))
        .unwrap();
    b.execute(listener, Op::Bind("192.0.2.2:8080".parse().unwrap()))
        .unwrap();
    b.execute(listener, Op::Listen(4)).unwrap();
    listener
}
pub(super) fn tfo_send(bytes: &[u8], flags: i32) -> Op {
    Op::SendTo(
        vec![(bytes.as_ptr() as usize, bytes.len())],
        flags,
        Some("192.0.2.2:8080".parse().unwrap()),
        None,
    )
}
pub(super) fn tfo_setup(warm: bool) -> (Owner, Owner, u64) {
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
                .has_fast_open_cookie(a.now(), a.local, b.local)
                .unwrap()
        );
    }
    (a, b, listener)
}
pub(super) fn tfo_capture(a: &mut Owner) -> Vec<u8> {
    a.service_egress().unwrap();
    a.execute(0, Op::Capture(65535)).unwrap().bytes
}
pub(super) fn tfo_deliver(b: &mut Owner, bytes: Vec<u8>) {
    b.execute(0, Op::Inject(bytes)).unwrap();
    receive(b);
}
pub(super) fn tfo_no_output(a: &mut Owner) {
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
    // Linux __inet_stream_connect completes SS_CONNECTING here, even though
    // TCP already established. Only the next flagged call sees SS_CONNECTED.
    assert_eq!(
        a.execute(
            client,
            Op::Send(
                vec![(bytes[n..].as_ptr() as usize, bytes.len() - n)],
                MSG_FASTOPEN
            )
        )
        .unwrap()
        .value as usize,
        bytes.len() - n
    );
    assert_eq!(
        a.execute(client, tfo_send(b"again", MSG_FASTOPEN))
            .unwrap_err(),
        EISCONN
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
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
            .unwrap();
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
        // An ordinary retry does not complete the implicit connect API state.
        assert_eq!(
            a.execute(client, tfo_send(b"again", flags | MSG_FASTOPEN))
                .unwrap()
                .value,
            5
        );
        assert_eq!(
            a.execute(client, tfo_send(b"done", MSG_FASTOPEN))
                .unwrap_err(),
            EISCONN
        );
        exchange(&mut a, &mut b);
        assert_eq!(b.execute(server, Op::Read(9)).unwrap().bytes, b"again");
    }
}

#[test]
fn fast_open_blocking_hit_and_miss_wait_handshake_and_complete_iovecs() {
    for (warm, deferred, first_len) in [
        (false, false, 900),
        (true, false, 900),
        (true, true, 900),
        (false, false, 2000),
        (true, false, 2000),
        (true, true, 2000),
    ] {
        let (mut a, mut b, listener) = tfo_setup(warm);
        let client = new(&mut a, 0);
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
            .unwrap();
        if deferred {
            a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                .unwrap();
            a.execute(client, Op::Connect("192.0.2.2:8080".parse().unwrap()))
                .unwrap();
        }
        let first = vec![1; first_len];
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
                    if deferred { 0 } else { MSG_FASTOPEN },
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
        assert_eq!(rx.recv().unwrap().unwrap().value as usize, first_len + 1000);
        assert_eq!(
            a.execute(client, tfo_send(b"done", MSG_FASTOPEN))
                .unwrap_err(),
            EISCONN
        );
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
fn fast_open_rejects_native_timestamps_and_deferred_close_sends_nothing() {
    let (mut a, _b, _) = tfo_setup(true);
    let client = new(&mut a, SOCK_NONBLOCK);
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
        .unwrap();
    a.execute(client, Op::Connect("192.0.2.2:8080".parse().unwrap()))
        .unwrap();
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
        100
    );
    assert_eq!(segment(&tfo_capture(&mut a)).payload, &[3; 100]);
    let (mut a, _b, _) = tfo_setup(true);
    a.socket_policy.notsent_lowat = 0;
    let client = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(
            client,
            Op::SendTo(
                vec![(0, 100)],
                MSG_FASTOPEN,
                Some("192.0.2.2:8080".parse().unwrap()),
                None
            )
        )
        .unwrap_err(),
        EAGAIN
    );
    assert!(matches!(a.sockets[&client].handle, Handle::Fresh));
    tfo_no_output(&mut a);
}

#[test]
fn fast_open_small_blocking_send_waits_even_when_all_bytes_fit_syn() {
    for deferred in [false, true] {
        let (mut a, mut b, _) = tfo_setup(true);
        let client = new(&mut a, 0);
        if deferred {
            a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                .unwrap();
            assert_eq!(
                a.execute(client, Op::Connect("192.0.2.2:8080".parse().unwrap()))
                    .unwrap()
                    .value,
                0
            );
            tfo_no_output(&mut a);
        }
        let (reply, rx) = mpsc::sync_channel(1);
        let mut request = Request {
            id: client,
            op: Op::Wait(
                Box::new(tfo_send(b"hi", if deferred { 0 } else { MSG_FASTOPEN })),
                None,
            ),
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
        assert_eq!(
            a.execute(client, tfo_send(b"done", MSG_FASTOPEN))
                .unwrap_err(),
            EISCONN
        );
    }
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

fn blocking_connect_failure(deferred: bool, timeout: bool) {
    for warm in [true, false] {
        // Deferred opens require a cookie; the cold control uses MSG_FASTOPEN.
        if deferred && !warm {
            continue;
        }
        let (mut a, mut b, listener) = tfo_setup(warm);
        let client = new(&mut a, 0);
        if deferred {
            a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                .unwrap();
            a.execute(client, Op::Connect("192.0.2.2:8080".parse().unwrap()))
                .unwrap();
        }
        let (reply, rx) = mpsc::sync_channel(1);
        let mut request = Request {
            id: client,
            op: Op::Wait(
                Box::new(tfo_send(b"hi", if deferred { 0 } else { MSG_FASTOPEN })),
                None,
            ),
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
        let failed = cid(&a, client);
        if timeout {
            tfo_capture(&mut a);
            for _ in 0..20 {
                if a.endpoint.state(failed).unwrap() == State::Closed {
                    break;
                }
                let now = a.endpoint.next_deadline().unwrap();
                a.test_now = Some(now);
                a.endpoint.on_timeout(now, BUDGET).unwrap();
                a.events();
                a.service_egress().unwrap();
                while a.execute(0, Op::Capture(65535)).is_ok() {}
            }
        } else {
            b.execute(listener, Op::Close).unwrap();
            tfo_deliver(&mut b, tfo_capture(&mut a));
            let reset = tfo_capture(&mut b);
            assert_ne!(segment(&reset).header.flags & ntcp::wire::RST, 0);
            tfo_deliver(&mut a, reset);
        }
        assert_eq!(a.endpoint.state(failed).unwrap(), State::Closed);
        let terminal = a.execute(client, Op::Transport(1)).unwrap().bytes;
        assert_eq!(terminal[0], 7);
        assert_eq!(terminal[5] & 32, 0);
        assert!(a.service(&mut request));
        assert!(request.send.is_none());
        assert!(!a.sockets[&client].connect_pending);
        assert!(matches!(a.sockets[&client].handle, Handle::Fresh));
        assert_eq!(
            rx.try_recv().unwrap().unwrap_err(),
            if timeout { ETIMEDOUT } else { ECONNREFUSED }
        );
        assert_eq!(a.execute(client, Op::Transport(1)).unwrap().bytes, terminal);
        // Timeout may retain a reset until the existing release barrier drains.
        a.service_egress().unwrap();
        while a.execute(0, Op::Capture(65535)).is_ok() {}
        assert!(!a.endpoint.connection_exists(failed));
        assert_eq!(a.sockets[&client].zc_reserved, 0);
        assert!(a.sockets[&client].completions.is_empty());
    }
}

#[test]
fn fast_open_blocking_msg_reset() {
    blocking_connect_failure(false, false);
}
#[test]
fn fast_open_blocking_msg_timeout() {
    blocking_connect_failure(false, true);
}
#[test]
fn fast_open_blocking_deferred_reset() {
    blocking_connect_failure(true, false);
}
#[test]
fn fast_open_blocking_deferred_timeout() {
    blocking_connect_failure(true, true);
}

fn tfo_early_terminal_socket(payload: &[u8]) -> (Owner, u64, Vec<u8>) {
    let (mut a, mut b, listener) = tfo_setup(true);
    let client = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(client, tfo_send(payload, MSG_FASTOPEN))
            .unwrap()
            .value as usize,
        payload.len()
    );
    let syn = tfo_capture(&mut a);
    tfo_deliver(&mut b, syn.clone());
    let server = b
        .execute(listener, Op::Accept(SOCK_NONBLOCK))
        .unwrap()
        .value as u64;
    assert_eq!(
        b.endpoint.state(cid(&b, server)).unwrap(),
        State::SynReceived
    );
    (b, server, syn)
}

fn tfo_early_terminal_input(b: &mut Owner, syn: &[u8], flags: u8) {
    let ip = ntcp_ip::parse(syn, false).unwrap().ip;
    let initial = segment(syn);
    let mut bytes = [0; 128];
    let n = ntcp::wire::encode(
        ip,
        ntcp::wire::Header {
            sequence: initial
                .header
                .sequence
                .wrapping_add(1 + initial.payload.len() as u32),
            flags,
            ..initial.header
        },
        &[],
        &[],
        &mut bytes,
    )
    .unwrap();
    b.input(b.now(), ip, 0, &bytes[..n]).unwrap();
    b.events();
}

#[test]
fn fast_open_early_terminal_reset_reaches_read_and_so_error() {
    for flags in [ntcp::wire::RST, ntcp::wire::SYN] {
        for via_so_error in [false, true] {
            let (mut b, server, syn) = tfo_early_terminal_socket(b"hello");
            assert_eq!(b.execute(server, Op::Read(5)).unwrap().bytes, b"hello");
            let synack = tfo_capture(&mut b);
            assert_eq!(
                segment(&synack).header.acknowledgment,
                segment(&syn).header.sequence.wrapping_add(6)
            );
            tfo_early_terminal_input(&mut b, &syn, flags);
            assert_eq!(b.endpoint.state(cid(&b, server)).unwrap(), State::Closed);
            assert_ne!(b.execute(server, Op::Ready).unwrap().value & EPOLLERR, 0);
            if via_so_error {
                assert_eq!(
                    b.execute(server, Op::Get(SOL_SOCKET, SO_ERROR))
                        .unwrap()
                        .value,
                    ECONNRESET
                );
            } else {
                assert_eq!(b.execute(server, Op::Read(1)).unwrap_err(), ECONNRESET);
            }
            assert_eq!(b.execute(server, Op::Read(1)).unwrap().value, 0);
            assert_eq!(
                b.execute(server, Op::Get(SOL_SOCKET, SO_ERROR))
                    .unwrap()
                    .value,
                0
            );
        }
    }
}

#[test]
fn fast_open_early_terminal_socket_drains_before_reset_or_timeout_error() {
    for timeout in [true, false] {
        let (mut b, server, syn) = tfo_early_terminal_socket(b"abc");
        assert_eq!(b.execute(server, Op::Read(1)).unwrap().bytes, b"a");
        tfo_capture(&mut b);
        let error = if timeout {
            b.test_now = Some(b.now() + 400_000_000);
            b.endpoint.on_timeout(b.now(), BUDGET).unwrap();
            b.events();
            ETIMEDOUT
        } else {
            tfo_early_terminal_input(&mut b, &syn, ntcp::wire::RST);
            ECONNRESET
        };
        assert_eq!(b.endpoint.state(cid(&b, server)).unwrap(), State::Closed);
        for _ in 0..2 {
            assert_eq!(b.execute(server, Op::Peek(9)).unwrap().bytes, b"bc");
        }
        assert_eq!(b.execute(server, Op::Read(1)).unwrap().bytes, b"b");
        assert_eq!(b.execute(server, Op::Read(9)).unwrap().bytes, b"c");
        assert_eq!(b.execute(server, Op::Read(1)).unwrap_err(), error);
        assert_eq!(b.execute(server, Op::Read(1)).unwrap().value, 0);
        assert_eq!(
            b.execute(server, Op::Get(SOL_SOCKET, SO_ERROR))
                .unwrap()
                .value,
            0
        );
        tfo_no_output(&mut b);
    }
}

#[test]
fn fast_open_early_terminal_socket_read_shutdown_reports_reset_after_drain() {
    let (mut b, server, syn) = tfo_early_terminal_socket(b"abc");
    tfo_capture(&mut b);
    b.execute(server, Op::Shutdown(SHUT_RD)).unwrap();
    // SHUT_RD retains already buffered bytes under the existing socket contract.
    assert_eq!(b.execute(server, Op::Read(3)).unwrap().bytes, b"abc");
    tfo_early_terminal_input(&mut b, &syn, ntcp::wire::RST);
    assert_eq!(b.execute(server, Op::Read(3)).unwrap_err(), ECONNRESET);
    assert_eq!(b.execute(server, Op::Peek(3)).unwrap().value, 0);
    assert_eq!(b.execute(server, Op::Read(3)).unwrap().value, 0);
}

#[test]
fn passive_repair_reset_before_accept_wakes_and_drains() {
    for blocking in [false, true] {
        for shutdown in [false, true] {
            let (mut a, mut b, listener) = tfo_setup(true);
            b.sockets.get_mut(&listener).unwrap().flags = if blocking { 0 } else { SOCK_NONBLOCK };
            let (reply, rx) = mpsc::sync_channel(1);
            let mut request = Request {
                id: listener,
                op: Op::Wait(Box::new(Op::Accept(SOCK_NONBLOCK)), None),
                reply,
                deadline: None,
                send: None,
                closing: None,
            };
            if blocking {
                assert!(!b.service(&mut request));
                assert!(rx.try_recv().is_err());
            } else {
                assert_eq!(
                    b.execute(listener, Op::Accept(SOCK_NONBLOCK)).unwrap_err(),
                    EAGAIN
                );
            }
            let client = new(&mut a, SOCK_NONBLOCK);
            assert_eq!(
                a.execute(client, tfo_send(b"early", MSG_FASTOPEN))
                    .unwrap()
                    .value,
                5
            );
            let syn = tfo_capture(&mut a);
            tfo_deliver(&mut b, syn.clone());
            let synack = tfo_capture(&mut b);
            assert_eq!(
                segment(&synack).header.acknowledgment,
                segment(&syn).header.sequence.wrapping_add(6)
            );
            tfo_early_terminal_input(&mut b, &syn, ntcp::wire::RST);
            assert_ne!(b.execute(listener, Op::Ready).unwrap().value & EPOLLIN, 0);
            assert!(b.service(&mut request));
            let server = rx.try_recv().unwrap().unwrap().value as u64;
            assert_eq!(b.endpoint.state(cid(&b, server)).unwrap(), State::Closed);
            assert_ne!(
                b.execute(server, Op::Transport(1)).unwrap().bytes[5] & 32,
                0
            );
            if shutdown {
                assert_eq!(
                    b.execute(server, Op::Shutdown(SHUT_RD)).unwrap_err(),
                    ENOTCONN
                );
            }
            assert_eq!(b.execute(server, Op::Read(20)).unwrap().bytes, b"early");
            assert_eq!(b.execute(server, Op::Read(1)).unwrap_err(), ECONNRESET);
            assert_eq!(b.execute(server, Op::Read(1)).unwrap().value, 0);
            assert_ne!(
                b.execute(server, Op::Transport(1)).unwrap().bytes[5] & 32,
                0
            );
            assert_eq!(
                b.execute(listener, Op::Accept(SOCK_NONBLOCK)).unwrap_err(),
                EAGAIN
            );
            b.execute(server, Op::Close).unwrap();
            b.execute(listener, Op::Close).unwrap();
            b.service_egress().unwrap();
            assert!(!b.sockets.contains_key(&server));
            assert!(!b.sockets.contains_key(&listener));
        }
    }
}

#[test]
fn passive_repair_socket_stat_commit_and_listener_cleanup() {
    for accept_first in [false, true] {
        let (mut a, mut b, listener) = tfo_setup(true);
        let baseline = b.endpoint.buffer_bytes();
        let client = new(&mut a, SOCK_NONBLOCK);
        a.execute(client, tfo_send(b"early", MSG_FASTOPEN)).unwrap();
        let syn = tfo_capture(&mut a);
        tfo_deliver(&mut b, syn.clone());
        let ip = ntcp_ip::parse(&syn, false).unwrap().ip;
        let header = segment(&syn).header;
        let child = b
            .endpoint
            .connection_id(ntcp::Tuple {
                local: SocketAddr::new(ip.destination, header.destination_port),
                remote: SocketAddr::new(ip.source, header.source_port),
            })
            .unwrap();
        assert!(!b.endpoint.transport_info(child).unwrap().syn_data_acked);
        let server = if accept_first {
            let server = b
                .execute(listener, Op::Accept(SOCK_NONBLOCK))
                .unwrap()
                .value as u64;
            assert_eq!(
                b.execute(server, Op::Transport(1)).unwrap().bytes[5] & 32,
                0
            );
            Some(server)
        } else {
            None
        };
        tfo_capture(&mut b);
        assert!(b.endpoint.transport_info(child).unwrap().syn_data_acked);
        tfo_early_terminal_input(&mut b, &syn, ntcp::wire::RST);
        if let Some(server) = server {
            assert_ne!(
                b.execute(server, Op::Transport(1)).unwrap().bytes[5] & 32,
                0
            );
            b.execute(server, Op::Close).unwrap();
            // execute() stages accepted closes; the owner loop releases detached handles.
            assert!(b.detached.contains(&child));
            b.endpoint.release(child).unwrap();
            b.detached.retain(|&id| id != child);
        }
        b.execute(listener, Op::Close).unwrap();
        for _ in 0..16 {
            b.service_egress().unwrap();
        }
        assert!(!b.endpoint.connection_exists(child));
        assert_eq!(b.endpoint.buffer_bytes(), baseline);
    }
}

// Synthetic peer keeps the cached MSS and handshake boundary deterministic.
pub(super) fn tfo_client_synack(a: &mut Owner, syn: &[u8], mss: u16) {
    let incoming = ntcp_ip::parse(syn, false).unwrap().ip;
    let ip = ntcp::IpMetadata {
        source: incoming.destination,
        destination: incoming.source,
    };
    let syn = segment(syn);
    let mut bytes = [0; 128];
    let [hi, lo] = mss.to_be_bytes();
    let n = ntcp::wire::encode(
        ip,
        ntcp::wire::Header {
            source_port: syn.header.destination_port,
            destination_port: syn.header.source_port,
            sequence: 100,
            acknowledgment: syn
                .header
                .sequence
                .wrapping_add(1 + syn.payload.len() as u32),
            flags: ntcp::wire::SYN | ntcp::wire::ACK,
            window: 65535,
            urgent_pointer: 0,
        },
        &[2, 4, hi, lo, 34, 10, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0],
        &[],
        &mut bytes,
    )
    .unwrap();
    a.input(a.now(), ip, 0, &bytes[..n]).unwrap();
    a.events();
    assert_eq!(segment(&tfo_capture(a)).header.flags & ntcp::wire::SYN, 0);
}

#[test]
fn fast_open_multi_iov_flagged_retry_completes_api_once() {
    let mut a = owner(1, Profile::Pipeline, 8);
    let warm = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(warm, tfo_send(&[], MSG_FASTOPEN)).unwrap_err(),
        EINPROGRESS
    );
    let syn = tfo_capture(&mut a);
    tfo_client_synack(&mut a, &syn, 940);
    a.execute(warm, Op::Close).unwrap();
    let _fin = tfo_capture(&mut a);

    let client = new(&mut a, SOCK_NONBLOCK);
    let mut first = [1u8; 500];
    let second = [2u8; 1000];
    let third = [3u8; 400];
    let flags = MSG_FASTOPEN | MSG_DONTWAIT | MSG_NOSIGNAL;
    assert_eq!(
        a.execute(
            client,
            Op::SendTo(
                vec![
                    (first.as_ptr() as usize, 500),
                    (second.as_ptr() as usize, 1000),
                    (third.as_ptr() as usize, 400)
                ],
                flags,
                Some("192.0.2.2:8080".parse().unwrap()),
                None,
            )
        )
        .unwrap()
        .value,
        900
    );
    let connection = cid(&a, client);
    first.fill(9); // Accepted SYN bytes are owned, not retained foreign pointers.
    let syn = tfo_capture(&mut a);
    assert_eq!(
        segment(&syn).payload,
        [&[1; 500][..], &second[..400]].concat()
    );
    assert_eq!(
        a.execute(client, tfo_send(b"pending", flags)).unwrap_err(),
        EALREADY
    );
    tfo_no_output(&mut a);
    tfo_client_synack(&mut a, &syn, 1460);
    assert_eq!(
        a.execute(
            client,
            Op::SendTo(
                vec![
                    (second[400..].as_ptr() as usize, 600),
                    (third.as_ptr() as usize, 400)
                ],
                flags,
                Some("192.0.2.2:8080".parse().unwrap()),
                None,
            )
        )
        .unwrap()
        .value,
        1000
    );
    assert_eq!(cid(&a, client), connection);
    let data = tfo_capture(&mut a);
    assert_eq!(segment(&data).header.flags & ntcp::wire::SYN, 0);
    assert_eq!(
        segment(&data).header.sequence,
        segment(&syn).header.sequence.wrapping_add(901)
    );
    assert_eq!(
        segment(&data).payload,
        [&second[400..], &third[..]].concat()
    );
    assert_eq!(
        a.execute(client, tfo_send(b"done", flags)).unwrap_err(),
        EISCONN
    );
    tfo_no_output(&mut a);
}

#[test]
fn fast_open_completed_retry_uses_ordinary_fault_and_completion_admission() {
    for fault in [false, true] {
        let (mut a, mut b, listener) = tfo_setup(false);
        let client = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(client, tfo_send(b"hello", MSG_FASTOPEN))
                .unwrap_err(),
            EINPROGRESS
        );
        exchange(&mut a, &mut b);
        let server = b
            .execute(listener, Op::Accept(SOCK_NONBLOCK))
            .unwrap()
            .value as u64;
        let connection = cid(&a, client);
        a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
            .unwrap();
        a.execute(
            client,
            Op::Set(
                SOL_SOCKET,
                crate::timestamping::OLD,
                (crate::timestamping::TX_SOFTWARE | crate::timestamping::SOFTWARE) as i32,
            ),
        )
        .unwrap();
        let before = a.endpoint.send_progress(connection).unwrap().queued_end;
        if fault {
            assert_eq!(
                a.execute(client, Op::Send(vec![(1, 5)], MSG_FASTOPEN | MSG_ZEROCOPY))
                    .unwrap_err(),
                EFAULT
            );
            assert_eq!(
                a.endpoint.send_progress(connection).unwrap().queued_end,
                before
            );
            assert_eq!(a.sockets[&client].zc_next, 0);
            assert_eq!(a.sockets[&client].timestamps.reserved(), 0);
            tfo_no_output(&mut a);
        } else {
            assert_eq!(
                a.execute(client, tfo_send(b"hello", MSG_FASTOPEN | MSG_ZEROCOPY))
                    .unwrap()
                    .value,
                5
            );
            assert_eq!(
                a.endpoint.send_progress(connection).unwrap().queued_end,
                before + 5
            );
            assert_eq!(a.sockets[&client].zc_next, 1);
            exchange(&mut a, &mut b);
            assert_eq!(b.execute(server, Op::Read(9)).unwrap().bytes, b"hello");
            assert!(
                a.sockets[&client]
                    .completions
                    .iter()
                    .any(|c| matches!(c, Completion::ZeroCopy(0, 0)))
            );
            assert!(
                a.sockets[&client]
                    .completions
                    .iter()
                    .any(|c| matches!(c, Completion::Timestamp { .. }))
            );
        }
        // API completion precedes ordinary payload admission, including EFAULT.
        assert_eq!(
            a.execute(client, tfo_send(b"done", MSG_FASTOPEN))
                .unwrap_err(),
            EISCONN
        );
        assert_eq!(cid(&a, client), connection);
    }
}

#[test]
fn fast_open_connect_option_and_explicit_completion_share_api_state() {
    for fast_open_connect in [false, true] {
        for explicit_completion in [false, true] {
            let (mut a, mut b, listener) = tfo_setup(false);
            let client = new(&mut a, SOCK_NONBLOCK);
            let remote = "192.0.2.2:8080".parse().unwrap();
            a.execute(
                client,
                Op::Set(
                    IPPROTO_TCP,
                    TCP_FASTOPEN_CONNECT,
                    i32::from(fast_open_connect),
                ),
            )
            .unwrap();
            assert_eq!(
                a.execute(client, Op::Connect(remote)).unwrap_err(),
                EINPROGRESS
            );
            assert_eq!(
                a.execute(client, tfo_send(b"pending", MSG_FASTOPEN))
                    .unwrap_err(),
                EALREADY
            );
            exchange(&mut a, &mut b);
            let server = b
                .execute(listener, Op::Accept(SOCK_NONBLOCK))
                .unwrap()
                .value as u64;
            if explicit_completion {
                assert_eq!(a.execute(client, Op::Connect(remote)).unwrap().value, 0);
            } else {
                assert_eq!(
                    a.execute(client, tfo_send(b"retry", MSG_FASTOPEN))
                        .unwrap()
                        .value,
                    5
                );
                exchange(&mut a, &mut b);
                assert_eq!(b.execute(server, Op::Read(9)).unwrap().bytes, b"retry");
            }
            assert_eq!(
                a.execute(client, tfo_send(b"done", MSG_FASTOPEN))
                    .unwrap_err(),
                EISCONN
            );
            assert_eq!(a.execute(client, Op::Connect(remote)).unwrap_err(), EISCONN);
            // Accepted sockets are already API-connected, never pending.
            assert_eq!(
                b.execute(server, tfo_send(b"done", MSG_FASTOPEN))
                    .unwrap_err(),
                EISCONN
            );
        }
    }
}

#[test]
fn fast_open_failed_implicit_completion_rolls_back_for_retry() {
    for warm in [false, true] {
        for consume_error in [false, true] {
            let (mut a, mut b, listener) = tfo_setup(warm);
            let client = new(&mut a, SOCK_NONBLOCK);
            let result = a.execute(client, tfo_send(b"hello", MSG_FASTOPEN));
            if warm {
                assert_eq!(result.unwrap().value, 5);
            } else {
                assert_eq!(result.unwrap_err(), EINPROGRESS);
            }
            let failed = cid(&a, client);
            b.execute(listener, Op::Close).unwrap();
            tfo_deliver(&mut b, tfo_capture(&mut a));
            let reset = tfo_capture(&mut b);
            assert_ne!(segment(&reset).header.flags & ntcp::wire::RST, 0);
            tfo_deliver(&mut a, reset);
            let terminal = a.execute(client, Op::Transport(1)).unwrap().bytes;
            assert_eq!(terminal[0], 7);
            assert_eq!(terminal[5] & 32, 0);
            if consume_error {
                assert_eq!(
                    a.execute(client, Op::Get(SOL_SOCKET, SO_ERROR))
                        .unwrap()
                        .value,
                    ECONNREFUSED
                );
            }
            assert_eq!(
                a.execute(client, tfo_send(b"retry", MSG_FASTOPEN))
                    .unwrap_err(),
                if consume_error {
                    ECONNABORTED
                } else {
                    ECONNREFUSED
                }
            );
            assert!(matches!(a.sockets[&client].handle, Handle::Fresh));
            assert!(!a.sockets[&client].connect_pending);
            assert!(!a.sockets[&client].connected);
            tfo_no_output(&mut a);
            assert!(!a.endpoint.connection_exists(failed));
            assert_eq!(a.execute(client, Op::Transport(1)).unwrap().bytes, terminal);
            for requested in [0, 1, 7, 192, 193, 280, 512] {
                assert_eq!(
                    a.execute(client, Op::TransportPrefix(1, requested))
                        .unwrap()
                        .bytes,
                    terminal[..requested.min(280)]
                );
            }
            assert_eq!(
                a.execute(client, Op::Get(SOL_SOCKET, SO_ERROR))
                    .unwrap()
                    .value,
                0
            );
            // Invalid destinations and pre-start copy faults cannot erase the snapshot.
            assert_eq!(
                a.execute(
                    client,
                    Op::SendTo(
                        vec![(0, 2)],
                        MSG_FASTOPEN,
                        Some("192.0.2.2:8080".parse().unwrap()),
                        None
                    )
                )
                .unwrap_err(),
                EFAULT
            );
            assert_eq!(
                a.execute(client, Op::Connect("192.0.2.2:0".parse().unwrap()))
                    .unwrap_err(),
                EINVAL
            );
            assert_eq!(
                a.execute(client, Op::Connect("0.0.0.0:8080".parse().unwrap()))
                    .unwrap_err(),
                EINVAL
            );
            assert_eq!(a.execute(client, Op::Transport(1)).unwrap().bytes, terminal);
            // A refusal preserves the cookie without poisoning the next connection.
            let remote = "192.0.2.2:8080".parse().unwrap();
            assert_eq!(
                a.endpoint
                    .can_defer_fast_open(a.now(), a.local, remote)
                    .unwrap(),
                warm
            );
            if warm {
                a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                    .unwrap();
                a.execute(client, Op::Connect("192.0.2.2:8080".parse().unwrap()))
                    .unwrap();
                assert_eq!(a.execute(client, Op::Transport(1)).unwrap().bytes, terminal);
                assert_eq!(
                    a.execute(client, Op::SendTo(vec![(0, 2)], 0, None, None))
                        .unwrap_err(),
                    EFAULT
                );
                assert_eq!(a.execute(client, Op::Transport(1)).unwrap().bytes, terminal);
            }
            let _listener = tfo_listener(&mut b);
            let result = a.execute(client, tfo_send(b"retry", MSG_FASTOPEN));
            match result {
                Ok(reply) => assert_eq!(reply.value, 5),
                Err(error) => assert_eq!(error, EINPROGRESS),
            }
            assert_ne!(cid(&a, client), failed);
            assert_eq!(a.execute(client, Op::Transport(1)).unwrap().bytes[0], 2);
            exchange(&mut a, &mut b);
            assert!(a.sockets[&client].connected);
            assert!(a.sockets[&client].connect_pending);
            assert_eq!(a.execute(client, Op::Transport(1)).unwrap().bytes[0], 1);
        }
    }
}

#[test]
fn fast_open_post_handshake_partial_error_and_peer_fin_controls() {
    for deferred in [false, true] {
        for peer_fin in [false, true] {
            let (mut a, mut b, listener) = tfo_setup(true);
            let client = new(&mut a, 0);
            if deferred {
                a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                    .unwrap();
                a.execute(client, Op::Connect("192.0.2.2:8080".parse().unwrap()))
                    .unwrap();
            }
            let bytes = vec![42; if peer_fin { 2 } else { 2 * BYTES }];
            let (reply, rx) = mpsc::sync_channel(1);
            let mut request = Request {
                id: client,
                op: Op::Wait(
                    Box::new(tfo_send(&bytes, if deferred { 0 } else { MSG_FASTOPEN })),
                    None,
                ),
                reply,
                deadline: None,
                send: None,
                closing: None,
            };
            assert!(!a.service(&mut request));
            exchange(&mut a, &mut b);
            let server = b
                .execute(listener, Op::Accept(SOCK_NONBLOCK))
                .unwrap()
                .value as u64;
            if peer_fin {
                b.execute(server, Op::Shutdown(SHUT_WR)).unwrap();
                exchange(&mut a, &mut b);
                assert_eq!(a.endpoint.state(cid(&a, client)).unwrap(), State::CloseWait);
                assert!(a.service(&mut request));
                assert_eq!(rx.try_recv().unwrap().unwrap().value, 2);
                assert_eq!(
                    a.execute(client, tfo_send(b"still writable", 0))
                        .unwrap()
                        .value,
                    14
                );
                a.execute(client, Op::Shutdown(SHUT_WR)).unwrap();
                assert_eq!(
                    a.execute(client, tfo_send(b"closed", 0)).unwrap_err(),
                    EPIPE
                );
            } else {
                assert!(!a.service(&mut request));
                let accepted = request.send.as_ref().unwrap().accepted;
                assert!(accepted > 2 && accepted < bytes.len());
                // The handshake completed and ordinary data was admitted. A
                // later transport error still returns the ordinary short count.
                b.endpoint.abort(cid(&b, server)).unwrap();
                tfo_deliver(&mut a, tfo_capture(&mut b));
                assert!(a.service(&mut request));
                assert_eq!(rx.try_recv().unwrap().unwrap().value as usize, accepted);
            }
        }
    }
}

#[test]
fn syncnt_blocking_fast_open_and_deferred_timeout_retains_snapshot() {
    for (warm, deferred) in [(false, false), (true, false), (true, true)] {
        let (mut a, _b, _) = tfo_setup(warm);
        let client = new(&mut a, 0);
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_SYNCNT, 1))
            .unwrap();
        if deferred {
            a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                .unwrap();
            a.execute(client, Op::Connect("192.0.2.2:8080".parse().unwrap()))
                .unwrap();
            assert!(matches!(a.sockets[&client].handle, Handle::Fresh));
            tfo_no_output(&mut a);
        }
        let (reply, rx) = mpsc::sync_channel(1);
        let mut request = Request {
            id: client,
            op: Op::Wait(
                Box::new(tfo_send(b"hi", if deferred { 0 } else { MSG_FASTOPEN })),
                None,
            ),
            reply,
            deadline: None,
            send: None,
            closing: None,
        };
        assert!(!a.service(&mut request));
        let failed = cid(&a, client);
        assert_eq!(
            a.endpoint.handshake_retransmission_limit(failed).unwrap(),
            NonZeroU8::new(1)
        );
        let start = a.now();
        let syn = tfo_capture(&mut a);
        assert_ne!(segment(&syn).header.flags & ntcp::wire::SYN, 0);
        // One submitted retry, then abort at the following RTO (not a new budget on fallback).
        let now = start + 1_000_000;
        assert_eq!(a.endpoint.next_deadline(), Some(now));
        a.test_now = Some(now);
        a.endpoint.on_timeout(now, BUDGET).unwrap();
        let retry = tfo_capture(&mut a);
        assert_ne!(segment(&retry).header.flags & ntcp::wire::SYN, 0);
        assert_eq!(a.endpoint.state(failed).unwrap(), State::SynSent);
        assert!(!a.service(&mut request));
        let now = start + 3_000_000;
        assert_eq!(a.endpoint.next_deadline(), Some(now));
        a.test_now = Some(now - 1);
        a.endpoint.on_timeout(now - 1, BUDGET).unwrap();
        assert_eq!(a.endpoint.state(failed).unwrap(), State::SynSent);
        assert!(!a.service(&mut request));
        tfo_no_output(&mut a);
        a.test_now = Some(now);
        a.endpoint.on_timeout(now, BUDGET).unwrap();
        a.events();
        assert_eq!(a.endpoint.state(failed).unwrap(), State::Closed);
        let terminal = a.execute(client, Op::Transport(1)).unwrap().bytes;
        assert_eq!(terminal[0], 7);
        assert!(a.service(&mut request));
        assert_eq!(rx.try_recv().unwrap().unwrap_err(), ETIMEDOUT);
        assert!(matches!(a.sockets[&client].handle, Handle::Fresh));
        assert_eq!(
            a.execute(client, Op::Get(IPPROTO_TCP, TCP_SYNCNT))
                .unwrap()
                .value,
            1
        );
        assert_eq!(a.execute(client, Op::Transport(1)).unwrap().bytes, terminal);
        a.service_egress().unwrap();
        while a.execute(0, Op::Capture(65535)).is_ok() {}
        assert!(!a.endpoint.connection_exists(failed));
        assert_eq!(a.execute(client, Op::Transport(1)).unwrap().bytes, terminal);
    }
}

#[test]
fn fast_open_negative_suppresses_msg_deferred_query_and_already_deferred_write() {
    for mode in 0..3 {
        let (mut a, mut b, listener) = tfo_setup(true);
        let remote = "192.0.2.2:8080".parse().unwrap();
        let client = new(&mut a, SOCK_NONBLOCK);
        if mode != 0 {
            a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                .unwrap();
        }
        if mode == 2 {
            a.execute(client, Op::Connect(remote)).unwrap();
            tfo_no_output(&mut a);
        }
        let failing = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(failing, tfo_send(b"bad", MSG_FASTOPEN))
                .unwrap()
                .value,
            3
        );
        let syn = tfo_capture(&mut a);
        let tuple = a.endpoint.tuple(cid(&a, failing)).unwrap();
        let seq = segment(&syn).header.sequence;
        assert!(
            a.endpoint
                .network_error(a.now(), tuple, seq, ntcp::NetworkError::HardUnreachable)
                .unwrap()
        );
        a.events();
        assert!(
            a.endpoint
                .has_fast_open_cookie(a.now(), tuple.local.ip(), remote.ip())
                .unwrap()
        );
        assert!(
            !a.endpoint
                .can_defer_fast_open(a.now(), tuple.local.ip(), remote)
                .unwrap()
        );
        let result = if mode == 1 {
            a.execute(client, Op::Connect(remote))
        } else {
            a.execute(
                client,
                tfo_send(b"hello", if mode == 0 { MSG_FASTOPEN } else { 0 }),
            )
        };
        assert_eq!(result.unwrap_err(), EINPROGRESS);
        assert!(a.sockets[&client].deferred_peer.is_none());
        let syn = tfo_capture(&mut a);
        assert!(segment(&syn).options.fast_open.is_none());
        assert!(segment(&syn).payload.is_empty());
        assert_eq!(
            a.endpoint
                .transport_info(cid(&a, client))
                .unwrap()
                .send_used,
            0
        );
        tfo_deliver(&mut b, syn);
        exchange(&mut a, &mut b);
        let server = b
            .execute(listener, Op::Accept(SOCK_NONBLOCK))
            .unwrap()
            .value as u64;
        assert_eq!(a.execute(client, tfo_send(b"hello", 0)).unwrap().value, 5);
        exchange(&mut a, &mut b);
        assert_eq!(b.execute(server, Op::Read(5)).unwrap().bytes, b"hello");
    }
}

#[test]
fn fast_open_reset_cookie_reuse_and_independent_suppression_blocking_send() {
    for (timeout, suppress) in [(false, false), (true, false), (false, true), (true, true)] {
        let (mut a, mut b, listener) = tfo_setup(true);
        let failing = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(failing, tfo_send(b"bad", MSG_FASTOPEN))
                .unwrap()
                .value,
            3
        );
        let syn = tfo_capture(&mut a);
        assert_eq!(segment(&syn).payload, b"bad");
        assert!(segment(&syn).options.fast_open.is_some());
        b.execute(listener, Op::Close).unwrap();
        let failed_sequence = segment(&syn).header.sequence;
        tfo_deliver(&mut b, syn);
        let reset = tfo_capture(&mut b);
        assert_ne!(segment(&reset).header.flags & ntcp::wire::RST, 0);
        let failed_tuple = a.endpoint.tuple(cid(&a, failing)).unwrap();
        if suppress {
            assert!(
                a.endpoint
                    .network_error(
                        a.now(),
                        failed_tuple,
                        failed_sequence,
                        ntcp::NetworkError::SoftUnreachable
                    )
                    .unwrap()
            );
            a.events();
        }
        tfo_deliver(&mut a, reset);
        assert_eq!(
            a.execute(failing, tfo_send(b"retry", MSG_FASTOPEN))
                .unwrap_err(),
            ECONNREFUSED
        );
        tfo_no_output(&mut a);
        let remote: SocketAddr = "192.0.2.2:8080".parse().unwrap();
        assert!(
            a.endpoint
                .has_fast_open_cookie(a.now(), a.local, remote.ip())
                .unwrap()
        );
        assert_eq!(
            a.endpoint
                .can_defer_fast_open(a.now(), a.local, remote)
                .unwrap(),
            !suppress
        );
        let listener = tfo_listener(&mut b);
        let client = new(&mut a, 0);
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_SYNCNT, 1))
            .unwrap();
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
            .unwrap();
        let payload = vec![42; 3000];
        let (reply, rx) = mpsc::sync_channel(1);
        let mut request = Request {
            id: client,
            op: Op::Wait(Box::new(tfo_send(&payload, MSG_FASTOPEN)), None),
            reply,
            deadline: None,
            send: None,
            closing: None,
        };
        assert!(!a.service(&mut request));
        let connection = cid(&a, client);
        let start = a.now();
        let syn = tfo_capture(&mut a);
        assert_ne!(
            a.endpoint.tuple(connection).unwrap().local.port(),
            failed_tuple.local.port()
        );
        let initial = segment(&syn).payload.len();
        assert_eq!(initial > 0, !suppress);
        assert_eq!(segment(&syn).options.fast_open.is_some(), !suppress);
        assert_eq!(request.send.as_ref().unwrap().accepted, initial);
        assert_eq!(
            a.endpoint.transport_info(connection).unwrap().send_used,
            initial
        );
        assert!(!a.service(&mut request));
        assert!(rx.try_recv().is_err());
        if timeout {
            for offset in [1_000_000, 3_000_000] {
                let now = start + offset;
                assert_eq!(a.endpoint.next_deadline(), Some(now));
                a.test_now = Some(now);
                a.endpoint.on_timeout(now, BUDGET).unwrap();
                a.events();
                assert_eq!(request.send.as_ref().unwrap().accepted, initial);
                // SYN payload is retained internally until terminal cleanup, but
                // unacknowledged data never becomes TCP_INFO acknowledged bytes.
                if offset == 1_000_000 {
                    let retry = tfo_capture(&mut a);
                    assert!(segment(&retry).payload.is_empty());
                    assert!(segment(&retry).options.fast_open.is_none());
                    assert!(!a.service(&mut request));
                }
            }
            let terminal = a.execute(client, Op::Transport(1)).unwrap().bytes;
            assert_eq!(terminal[0], 7);
            assert_eq!(terminal[5] & 32, 0);
            assert_eq!(
                u64::from_ne_bytes(terminal[120..128].try_into().unwrap()),
                0
            );
            assert!(a.service(&mut request));
            assert_eq!(rx.try_recv().unwrap().unwrap_err(), ETIMEDOUT);
            assert!(matches!(a.sockets[&client].handle, Handle::Fresh));
            assert!(!a.sockets[&client].connect_pending);
            assert_eq!(
                a.execute(client, Op::Get(SOL_SOCKET, SO_ERROR))
                    .unwrap()
                    .value,
                0
            );
            assert_eq!(a.execute(client, Op::Transport(1)).unwrap().bytes, terminal);
            a.service_egress().unwrap();
            while a.execute(0, Op::Capture(65535)).is_ok() {}
            assert!(!a.endpoint.connection_exists(connection));
            assert_eq!(a.execute(client, Op::Transport(1)).unwrap().bytes, terminal);
        } else {
            tfo_deliver(&mut b, syn);
            exchange(&mut a, &mut b);
            let server = b
                .execute(listener, Op::Accept(SOCK_NONBLOCK))
                .unwrap()
                .value as u64;
            if initial == 0 {
                assert_eq!(b.execute(server, Op::Read(BYTES)).unwrap_err(), EAGAIN);
            }
            assert!(a.service(&mut request));
            assert_eq!(rx.try_recv().unwrap().unwrap().value, payload.len() as i32);
            exchange(&mut a, &mut b);
            assert_eq!(b.execute(server, Op::Read(BYTES)).unwrap().bytes, payload);
            assert_eq!(b.execute(server, Op::Read(1)).unwrap_err(), EAGAIN);
            assert_eq!(
                a.execute(client, tfo_send(b"again", MSG_FASTOPEN))
                    .unwrap_err(),
                EISCONN
            );
        }
        assert_eq!(
            a.endpoint
                .can_defer_fast_open(a.now(), a.local, remote)
                .unwrap(),
            !timeout && !suppress
        );
    }
}

#[test]
fn upstream_implicit_fast_open_listener_and_explicit_disable() {
    for disabled in [false, true] {
        let (_, profile) = crate::packet_profile::profile(
            "upstream,local=192.0.2.2,tfo-listen,budget224m,prealloc3",
        )
        .unwrap();
        let mut b = owner(2, profile, 32);
        let mut a = owner(1, Profile::Pipeline, 32);
        let listener = new(&mut b, SOCK_NONBLOCK);
        assert_eq!(
            b.execute(listener, Op::Get(IPPROTO_TCP, TCP_FASTOPEN))
                .unwrap()
                .value,
            128
        );
        if disabled {
            b.execute(listener, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 0))
                .unwrap();
        }
        b.execute(listener, Op::Bind("192.0.2.2:8080".parse().unwrap()))
            .unwrap();
        b.execute(listener, Op::Listen(4)).unwrap();
        // Warm the actual client cookie cache through an ordinary handshake.
        let warmup = new(&mut a, SOCK_NONBLOCK);
        a.execute(warmup, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
            .unwrap();
        assert_eq!(
            a.execute(warmup, Op::Connect("192.0.2.2:8080".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        exchange(&mut a, &mut b);
        let child = b
            .execute(listener, Op::Accept(SOCK_NONBLOCK))
            .unwrap()
            .value as u64;
        a.execute(warmup, Op::Close).unwrap();
        b.execute(child, Op::Close).unwrap();
        exchange(&mut a, &mut b);
        let client = new(&mut a, SOCK_NONBLOCK);
        let data = [42; 10];
        let result = a.execute(client, tfo_send(&data, MSG_FASTOPEN));
        if disabled {
            assert_eq!(result.unwrap_err(), EINPROGRESS);
        } else {
            assert_eq!(result.unwrap().value, 10);
        }
        let syn = tfo_capture(&mut a);
        assert_eq!(segment(&syn).payload.len(), if disabled { 0 } else { 10 });
        tfo_deliver(&mut b, syn);
        let result = b.execute(listener, Op::Accept(SOCK_NONBLOCK));
        if disabled {
            assert_eq!(result.unwrap_err(), EAGAIN);
        } else {
            let child = result.unwrap().value as u64;
            assert_eq!(b.execute(child, Op::Read(10)).unwrap().bytes, data);
        }
    }
}

#[test]
fn fast_open_authenticated_empty_syn_accepts_without_false_readability() {
    let (mut a, mut b, listener) = tfo_setup(true);
    let client = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(client, tfo_send(&[], MSG_FASTOPEN)).unwrap_err(),
        EINPROGRESS
    );
    let syn = tfo_capture(&mut a);
    assert!(segment(&syn).payload.is_empty());
    assert!(
        !segment(&syn)
            .options
            .fast_open
            .unwrap()
            .as_bytes()
            .is_empty()
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
    let ready = b.execute(server, Op::Ready).unwrap().value;
    assert_eq!(ready & EPOLLIN, 0);
    assert_ne!(ready & EPOLLOUT, 0);
    assert_eq!(b.execute(server, Op::Read(32)).unwrap_err(), EAGAIN);
    let synack = tfo_capture(&mut b);
    assert_eq!(
        b.execute(server, Op::Write(vec![9; 100])).unwrap().value,
        100
    );
    tfo_no_output(&mut b); // The ordinary Pipeline policy holds early responses.
    tfo_deliver(&mut a, synack);
    tfo_deliver(&mut b, tfo_capture(&mut a));
    exchange(&mut a, &mut b);
    assert_eq!(a.execute(client, Op::Read(100)).unwrap().bytes, [9; 100]);
    a.execute(client, Op::Write(b"request".to_vec())).unwrap();
    exchange(&mut a, &mut b);
    assert_ne!(b.execute(server, Op::Ready).unwrap().value & EPOLLIN, 0);
    assert_eq!(b.execute(server, Op::Read(32)).unwrap().bytes, b"request");
    assert!(
        !b.endpoint
            .transport_info(cid(&b, server))
            .unwrap()
            .syn_data_fully_acked
    );
}

#[test]
fn server_cookie_blocking_iov_and_deferred_calls_retain_tail_until_handshake() {
    for deferred in [false, true] {
        let (mut a, mut b, listener) = tfo_setup(false);
        let remote = "192.0.2.2:8080".parse().unwrap();
        b.execute(
            listener,
            Op::SetListenerFastOpenEarlyDataPolicy(FastOpenEarlyDataPolicy::ApplicationProtected),
        )
        .unwrap();
        let client = new(&mut a, 0);
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
            .unwrap();
        a.execute(
            client,
            Op::SetFastOpenServerCookie(Some((remote, FastOpenCookie::request()))),
        )
        .unwrap();
        if deferred {
            a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                .unwrap();
            a.execute(client, Op::Connect(remote)).unwrap();
            tfo_no_output(&mut a);
            assert_eq!(
                a.execute(client, Op::SetFastOpenServerCookie(None))
                    .unwrap_err(),
                EINVAL
            );
        }
        let first = vec![1; 1000];
        let second = vec![2; 1000];
        let (reply, rx) = mpsc::sync_channel(1);
        let mut request = Request {
            id: client,
            op: Op::Wait(
                Box::new(Op::SendTo(
                    vec![
                        (first.as_ptr() as usize, first.len()),
                        (second.as_ptr() as usize, second.len()),
                    ],
                    if deferred { 0 } else { MSG_FASTOPEN },
                    Some(remote),
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
        let syn = tfo_capture(&mut a);
        assert_eq!(segment(&syn).payload, &first[..496]);
        assert_eq!(
            segment(&syn).options.fast_open,
            Some(FastOpenCookie::request())
        );
        assert!(rx.try_recv().is_err());
        tfo_deliver(&mut b, syn);
        let server = b
            .execute(listener, Op::Accept(SOCK_NONBLOCK))
            .unwrap()
            .value as u64;
        assert_eq!(
            b.execute(server, Op::Read(BYTES)).unwrap().bytes,
            first[..496]
        );
        exchange(&mut a, &mut b);
        assert!(a.service(&mut request));
        assert_eq!(rx.recv().unwrap().unwrap().value, 2000);
        exchange(&mut a, &mut b);
        assert_eq!(
            b.execute(server, Op::Read(BYTES)).unwrap().bytes,
            [first[496..].to_vec(), second].concat()
        );
    }
}
