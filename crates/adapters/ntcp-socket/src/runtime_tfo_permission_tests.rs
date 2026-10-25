use super::*;

#[test]
fn client_tfo_permission_fresh_denial_precedes_copy_port_and_completion() {
    let (mut a, _, _) = tfo_setup(true);
    let id = new(&mut a, SOCK_NONBLOCK);
    a.execute(id, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1)).unwrap();
    let budget = a.endpoint.buffer_bytes();
    a.execute(0, Op::SetFastOpenClientEnabled(false)).unwrap();
    for value in [0, 1] {
        assert_eq!(a.execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, value)).unwrap_err(), EOPNOTSUPP);
    }
    assert_eq!(a.execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 2)).unwrap_err(), EINVAL);
    assert_eq!(a.execute(id, Op::SendTo(vec![(1, 500)], MSG_FASTOPEN|MSG_ZEROCOPY, Some("192.0.2.2:8080".parse().unwrap()), None)).unwrap_err(), EOPNOTSUPP);
    let s = &a.sockets[&id];
    assert!(matches!(s.handle, Handle::Fresh));
    assert_eq!(s.local, None);
    assert_eq!((s.zc_next, s.zc_reserved, s.completions.len()), (0, 0, 0));
    assert_eq!(a.endpoint.buffer_bytes(), budget);
    assert!(a.endpoint.has_fast_open_cookie(a.now(), a.local.into(), "192.0.2.2".parse().unwrap()).unwrap());
    tfo_no_output(&mut a);
}

#[test]
fn client_tfo_permission_deferred_rejection_retains_peer_and_reenable_retries() {
    let (mut a, mut b, listener) = tfo_setup(true);
    let id = new(&mut a, SOCK_NONBLOCK);
    a.execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1)).unwrap();
    let remote = "192.0.2.2:8080".parse().unwrap();
    assert_eq!(a.execute(id, Op::Connect(remote)).unwrap().value, 0);
    let local = a.sockets[&id].local;
    a.execute(0, Op::SetFastOpenClientEnabled(false)).unwrap();
    assert_eq!(a.execute(id, Op::Send(vec![(1, 500)], 0)).unwrap_err(), EOPNOTSUPP);
    let s = &a.sockets[&id];
    assert_eq!(s.deferred_peer, Some(remote));
    assert_eq!(s.local, local);
    assert!(matches!(s.handle, Handle::Fresh));
    tfo_no_output(&mut a);
    a.execute(0, Op::SetFastOpenClientEnabled(true)).unwrap();
    assert_eq!(a.execute(id, tfo_send(b"hello", 0)).unwrap().value, 5);
    let syn = tfo_capture(&mut a);
    assert_eq!(segment(&syn).payload, b"hello");
    assert!(!segment(&syn).options.fast_open.unwrap().as_bytes().is_empty());
    tfo_deliver(&mut b, syn);
    exchange(&mut a, &mut b);
    let server = b.execute(listener, Op::Accept(SOCK_NONBLOCK)).unwrap().value as u64;
    assert_eq!(b.execute(server, Op::Read(32)).unwrap().bytes, b"hello");
    a.execute(0, Op::SetFastOpenClientEnabled(false)).unwrap();
    assert_eq!(a.execute(id, tfo_send(b"normal", 0)).unwrap().value, 6);
    exchange(&mut a, &mut b);
    assert_eq!(b.execute(server, Op::Read(32)).unwrap().bytes, b"normal");
    assert_eq!(a.execute(id, tfo_send(b"tagged", MSG_FASTOPEN)).unwrap_err(), EOPNOTSUPP);
}

#[test]
fn client_tfo_permission_preconfigured_new_connect_uses_plain_handshake() {
    for warm in [false, true] {
        let (mut a, mut b, listener) = tfo_setup(warm);
        let id = new(&mut a, SOCK_NONBLOCK);
        a.execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1)).unwrap();
        a.execute(0, Op::SetFastOpenClientEnabled(false)).unwrap();
        assert_eq!(a.execute(id, Op::Connect("192.0.2.2:8080".parse().unwrap())).unwrap_err(), EINPROGRESS);
        let syn = tfo_capture(&mut a);
        assert!(segment(&syn).options.fast_open.is_none());
        assert!(segment(&syn).payload.is_empty());
        assert_eq!(a.execute(id, Op::Get(IPPROTO_TCP, TCP_FASTOPEN_CONNECT)).unwrap().value, 1);
        tfo_deliver(&mut b, syn);
        exchange(&mut a, &mut b);
        let server = b.execute(listener, Op::Accept(SOCK_NONBLOCK)).unwrap().value as u64;
        assert_eq!(a.execute(id, tfo_send(b"plain", 0)).unwrap().value, 5);
        exchange(&mut a, &mut b);
        assert_eq!(b.execute(server, Op::Read(32)).unwrap().bytes, b"plain");
    }
}
