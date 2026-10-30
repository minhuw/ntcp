use super::*;

fn listener(owner: &mut Owner, address: SocketAddr) -> u64 {
    let id = new(owner, SOCK_NONBLOCK);
    owner
        .execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 4))
        .unwrap();
    owner.execute(id, Op::Bind(address)).unwrap();
    owner.execute(id, Op::Listen(4)).unwrap();
    id
}
fn warm_pair(profile: Profile, linux: bool) -> (Owner, Owner, u64, u64) {
    let mut a = owner(1, profile, 128);
    let mut b = owner(2, profile, 128);
    let la = listener(&mut a, "192.0.2.1:9000".parse().unwrap());
    let lb = listener(&mut b, "192.0.2.2:9001".parse().unwrap());
    #[cfg(feature = "tfo-linux-cookie")]
    if linux {
        a.execute(la, Op::SetFastOpenKey(LinuxSipHash24Key::new([11; 16])))
            .unwrap();
        b.execute(lb, Op::SetFastOpenKey(LinuxSipHash24Key::new([29; 16])))
            .unwrap();
    }
    let _ = linux;
    for reverse in [false, true] {
        let (from, to, listener, address) = if reverse {
            (&mut b, &mut a, la, "192.0.2.1:9000")
        } else {
            (&mut a, &mut b, lb, "192.0.2.2:9001")
        };
        let client = new(from, SOCK_NONBLOCK);
        from.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
            .unwrap();
        assert_eq!(
            from.execute(client, Op::Connect(address.parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        exchange(from, to);
        to.execute(listener, Op::Accept(SOCK_NONBLOCK)).unwrap();
        assert!(
            from.endpoint
                .has_fast_open_cookie(from.now(), from.local, to.local)
                .unwrap()
        );
    }
    (a, b, la, lb)
}
fn stage(owner: &mut Owner, authority: u64, address: SocketAddr) -> u64 {
    let id = new(owner, SOCK_NONBLOCK);
    owner.execute(id, Op::Bind(address)).unwrap();
    owner
        .execute(id, Op::SetFastOpenReceiveAuthority(Some(authority)))
        .unwrap();
    id
}
fn start(owner: &mut Owner, id: u64, peer: SocketAddr, mode: &str, data: &[u8]) {
    match mode {
        "ordinary" => assert_eq!(
            owner.execute(id, Op::Connect(peer)).unwrap_err(),
            EINPROGRESS
        ),
        "msg" => assert_eq!(
            owner
                .execute(
                    id,
                    Op::SendTo(
                        vec![(data.as_ptr() as usize, data.len())],
                        MSG_FASTOPEN,
                        Some(peer),
                        None
                    )
                )
                .unwrap()
                .value,
            data.len() as i32
        ),
        "deferred" => {
            owner
                .execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                .unwrap();
            owner.execute(id, Op::Connect(peer)).unwrap();
            assert!(matches!(owner.sockets[&id].handle, Handle::Fresh));
            assert_eq!(
                owner
                    .execute(id, Op::SetFastOpenReceiveAuthority(None))
                    .unwrap_err(),
                EINVAL
            );
            owner
                .execute(id, Op::Send(vec![(data.as_ptr() as usize, data.len())], 0))
                .unwrap();
        }
        _ => unreachable!(),
    }
}

#[test]
fn native_simultaneous_staged_authority_all_starts_and_complete_streams() {
    for (mode, profile, linux) in [
        ("msg", Profile::PipelineGso, false),
        ("deferred", Profile::Pipeline, false),
        ("ordinary", Profile::Pipeline, false),
        ("msg", Profile::Pipeline, cfg!(feature = "tfo-linux-cookie")),
    ] {
        let (mut a, mut b, la, lb) = warm_pair(profile, linux);
        let aa = "192.0.2.1:42000".parse().unwrap();
        let ba = "192.0.2.2:42001".parse().unwrap();
        let client_a = stage(&mut a, la, aa);
        let client_b = stage(&mut b, lb, ba);
        start(&mut a, client_a, ba, mode, b"from-A");
        start(&mut b, client_b, aa, "msg", b"from-B");
        let ids = (cid(&a, client_a), cid(&b, client_b));
        let sa = tfo_capture(&mut a);
        let sb = tfo_capture(&mut b);
        let cookie_a = segment(&sb).options.fast_open;
        let cookie_b = segment(&sa).options.fast_open;
        assert!(cookie_a.is_some());
        if mode != "ordinary" {
            assert_ne!(cookie_a, cookie_b);
        }
        tfo_deliver(&mut a, sb.clone());
        tfo_deliver(&mut b, sa.clone());
        for (o, fd, id, listener, early) in [
            (&mut a, client_a, ids.0, la, true),
            (&mut b, client_b, ids.1, lb, mode != "ordinary"),
        ] {
            assert_eq!(o.endpoint.state(id), Ok(State::SynReceived));
            assert!(!o.sockets[&fd].connected);
            assert_eq!(o.execute(fd, Op::FinishConnect).unwrap_err(), EAGAIN);
            assert_eq!(
                o.execute(fd, Op::Ready).unwrap().value & (EPOLLIN | EPOLLOUT),
                if early { EPOLLIN } else { 0 }
            );
            assert_eq!(
                o.execute(fd, Op::Available).unwrap().value,
                if early { 6 } else { 0 }
            );
            if early {
                assert_eq!(o.execute(fd, Op::Peek(2)).unwrap().bytes, b"fr");
            }
            assert_eq!(
                o.execute(listener, Op::Accept(SOCK_NONBLOCK)).unwrap_err(),
                EAGAIN
            );
            assert_eq!(
                o.execute(fd, Op::Get(SOL_SOCKET, SO_ERROR)).unwrap().value,
                0
            );
        }
        assert_eq!(a.execute(client_a, Op::Read(2)).unwrap().bytes, b"fr");
        let ra = tfo_capture(&mut a);
        let rb = tfo_capture(&mut b);
        assert!(segment(&ra).payload.is_empty() && segment(&rb).payload.is_empty());
        assert_eq!(
            segment(&ra).options.fast_open,
            if linux { None } else { cookie_a }
        );
        assert_eq!(
            segment(&rb).options.fast_open,
            if linux || mode == "ordinary" {
                None
            } else {
                cookie_b
            }
        );
        tfo_deliver(&mut a, rb);
        tfo_deliver(&mut b, ra);
        exchange(&mut a, &mut b);
        assert_eq!(cid(&a, client_a), ids.0);
        assert_eq!(cid(&b, client_b), ids.1);
        assert_eq!(a.execute(client_a, Op::Read(64)).unwrap().bytes, b"om-B");
        if mode == "ordinary" {
            a.execute(client_a, Op::Write(b"from-A".to_vec())).unwrap();
            exchange(&mut a, &mut b);
        }
        assert_eq!(b.execute(client_b, Op::Read(64)).unwrap().bytes, b"from-A");
        a.execute(client_a, Op::FinishConnect).unwrap();
        b.execute(client_b, Op::FinishConnect).unwrap();
        let more_a = vec![17; 6000];
        let more_b = vec![29; 6000];
        a.execute(client_a, Op::Write(more_a.clone())).unwrap();
        b.execute(client_b, Op::Write(more_b.clone())).unwrap();
        let mut got_a = Vec::new();
        let mut got_b = Vec::new();
        for _ in 0..16 {
            exchange(&mut a, &mut b);
            if let Ok(r) = a.execute(client_a, Op::Read(8192)) {
                got_a.extend(r.bytes);
            }
            if let Ok(r) = b.execute(client_b, Op::Read(8192)) {
                got_b.extend(r.bytes);
            }
            if got_a.len() == 6000 && got_b.len() == 6000 {
                break;
            }
        }
        assert_eq!(got_a, more_b);
        assert_eq!(got_b, more_a);
        println!(
            "T4_NATIVE {{\"start\":\"{mode}\",\"linux\":{linux},\"early_a\":6,\"early_b\":{},\"complete_each\":6006}}",
            if mode == "ordinary" { 0 } else { 6 }
        );
    }
}

#[test]
fn native_simultaneous_unread_early_data_drains_before_refusal() {
    for complete_first in [false, true] {
        let (mut a, mut b, la, lb) = warm_pair(Profile::Pipeline, false);
        let aa = "192.0.2.1:42000".parse().unwrap();
        let ba = "192.0.2.2:42001".parse().unwrap();
        let ca = stage(&mut a, la, aa);
        let cb = stage(&mut b, lb, ba);
        start(&mut a, ca, ba, "msg", b"from-A");
        start(&mut b, cb, aa, "msg", b"from-B");
        let sa = tfo_capture(&mut a);
        let sb = tfo_capture(&mut b);
        tfo_deliver(&mut a, sb);
        tfo_deliver(&mut b, sa);
        // Closing the peer with unread accepted bytes emits a real exact RST.
        b.execute(cb, Op::Close).unwrap();
        let reset = tfo_capture(&mut b);
        assert_ne!(segment(&reset).header.flags & ntcp::wire::RST, 0);
        tfo_deliver(&mut a, reset);
        let id = cid(&a, ca);
        let terminal = a.endpoint.transport_info(id).unwrap();
        assert_eq!(terminal.state, State::Closed);
        assert!(!a.sockets[&ca].connected);
        assert_eq!(a.sockets[&ca].error, ECONNREFUSED);
        if complete_first {
            assert_eq!(a.execute(ca, Op::FinishConnect).unwrap_err(), ECONNREFUSED);
            assert!(!a.sockets[&ca].connect_pending);
            assert!(!a.sockets[&ca].connected);
            assert_eq!(cid(&a, ca), id);
            assert_eq!(a.sockets[&ca].terminal_transport.unwrap().unwrap(), terminal);
            assert_ne!(a.execute(ca, Op::Ready).unwrap().value & EPOLLIN, 0);
        }
        assert_eq!(a.execute(ca, Op::Available).unwrap().value, 6);
        assert_eq!(a.execute(ca, Op::Peek(3)).unwrap().bytes, b"fro");
        assert_eq!(a.execute(ca, Op::Read(3)).unwrap().bytes, b"fro");
        assert_eq!(a.execute(ca, Op::Available).unwrap().value, 3);
        assert_eq!(a.execute(ca, Op::Read(64)).unwrap().bytes, b"m-B");
        assert_eq!(a.execute(ca, Op::Available).unwrap().value, 0);
        assert_eq!(a.execute(ca, Op::Read(1)).unwrap_err(),
            if complete_first { ENOTCONN } else { ECONNREFUSED });
        assert_eq!(a.execute(ca, Op::Get(SOL_SOCKET, SO_ERROR)).unwrap().value, 0);
        if complete_first {
            assert!(matches!(a.sockets[&ca].handle, Handle::Fresh));
            tfo_no_output(&mut a);
            assert!(!a.endpoint.connection_exists(id));
            assert_eq!(a.sockets[&ca].terminal_transport.unwrap().unwrap(), terminal);
        } else {
            assert_eq!(a.endpoint.transport_info(id).unwrap().state, State::Closed);
        }
    }
}

#[test]
fn native_stale_authority_start_is_atomic_and_clearable_before_deferral() {
    let (mut a, _b, la, _) = warm_pair(Profile::Pipeline, false);
    let fd = stage(&mut a, la, "192.0.2.1:42000".parse().unwrap());
    let selected = a.sockets[&fd].receive_authority;
    assert_eq!(
        a.execute(fd, Op::SetFastOpenReceiveAuthority(Some(fd)))
            .unwrap_err(),
        EINVAL
    );
    assert_eq!(a.sockets[&fd].receive_authority, selected);
    a.execute(la, Op::Close).unwrap();
    let before = a.endpoint.buffer_bytes();
    assert!(
        a.execute(fd, Op::Connect("192.0.2.2:42001".parse().unwrap()))
            .is_err()
    );
    assert!(matches!(a.sockets[&fd].handle, Handle::Fresh));
    assert_eq!(a.endpoint.buffer_bytes(), before);
    a.execute(fd, Op::SetFastOpenReceiveAuthority(None))
        .unwrap();
    assert_eq!(
        a.execute(fd, Op::Connect("192.0.2.2:42001".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
}
