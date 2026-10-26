use super::*;
use ntcp::wire;

#[test]
fn native_listener_authorization_changes_early_delivery_without_changing_crypto_policy() {
    for protected in [false, true] {
        for invalid_cookie in [false, true] {
            let local = Ipv4Addr::new(10, 73, 0, 2);
            let mut owner = Owner::with_config(
                local,
                (local, 32),
                [2; 32],
                None,
                SocketConfig::new("test", local).tcp,
            )
            .unwrap();
            owner.test_now = Some(0);
            let listener = owner.execute(0, Op::New(SOCK_NONBLOCK)).unwrap().value as u64;
            assert_eq!(
                owner
                    .execute(
                        listener,
                        Op::SetListenerFastOpenEarlyDataPolicy(
                            ntcp::FastOpenEarlyDataPolicy::ApplicationProtected
                        )
                    )
                    .unwrap_err(),
                EOPNOTSUPP
            );
            owner
                .execute(listener, Op::Bind(SocketAddr::new(local.into(), 8080)))
                .unwrap();
            owner.execute(listener, Op::Listen(4)).unwrap();
            owner
                .execute(listener, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 1))
                .unwrap();
            owner
                .execute(
                    listener,
                    Op::SetListenerFastOpenEarlyDataPolicy(if protected {
                        ntcp::FastOpenEarlyDataPolicy::ApplicationProtected
                    } else {
                        ntcp::FastOpenEarlyDataPolicy::RequireCookie
                    }),
                )
                .unwrap();
            let ip = ntcp::IpMetadata {
                source: Ipv4Addr::new(10, 73, 0, 3).into(),
                destination: local.into(),
            };
            let mut bytes = [0; 2048];
            let options: &[u8] = if invalid_cookie {
                &[34, 10, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1]
            } else {
                &[]
            };
            let n = wire::encode(
                ip,
                wire::Header {
                    source_port: 40000,
                    destination_port: 8080,
                    sequence: 0,
                    acknowledgment: 0,
                    flags: wire::SYN,
                    window: 10000,
                    urgent_pointer: 0,
                },
                options,
                &[9; 1000],
                &mut bytes,
            )
            .unwrap();
            owner.input(0, ip, 0, &bytes[..n]).unwrap();
            let output = owner
                .endpoint
                .poll_transmit(0, &mut bytes, 64)
                .unwrap()
                .packet
                .unwrap();
            let packet = wire::parse(output.ip, &bytes[..output.len]).unwrap();
            assert_eq!(
                packet.header.acknowledgment,
                if protected { 1001 } else { 1 }
            );
            assert_eq!(
                packet.options.fast_open.is_some(),
                !protected && invalid_cookie
            );
            if protected {
                let child = owner
                    .execute(listener, Op::Accept(SOCK_NONBLOCK))
                    .unwrap()
                    .value as u64;
                assert_eq!(
                    owner.execute(child, Op::Read(1024)).unwrap().bytes,
                    vec![9; 1000]
                );
            } else {
                assert_eq!(
                    owner
                        .execute(listener, Op::Accept(SOCK_NONBLOCK))
                        .unwrap_err(),
                    EAGAIN
                );
            }
            assert_eq!(
                owner
                    .execute(
                        u64::MAX,
                        Op::SetListenerFastOpenEarlyDataPolicy(
                            ntcp::FastOpenEarlyDataPolicy::RequireCookie
                        )
                    )
                    .unwrap_err(),
                EBADF
            );
        }
    }
}

#[test]
fn native_server_cookie_staging_is_peer_scoped_and_does_not_enable_calls() {
    let remote: SocketAddr = "10.73.0.3:8080".parse().unwrap();
    for selection in [0, 1, 2, 3] {
        let local = Ipv4Addr::new(10, 73, 0, 2);
        let mut owner = Owner::with_config(
            local,
            (local, 32),
            [2; 32],
            None,
            SocketConfig::new("test", local).tcp,
        )
        .unwrap();
        owner.test_now = Some(0);
        let fd = owner.execute(0, Op::New(SOCK_NONBLOCK)).unwrap().value as u64;
        let selected = if selection == 1 {
            "10.73.0.3:8081".parse().unwrap()
        } else {
            remote
        };
        owner
            .execute(
                fd,
                Op::SetFastOpenServerCookie(Some((selected, FastOpenCookie::request()))),
            )
            .unwrap();
        if selection == 2 {
            owner
                .execute(fd, Op::SetFastOpenServerCookie(None))
                .unwrap();
        }
        if selection == 3 {
            owner
                .execute(0, Op::SetFastOpenClientEnabled(false))
                .unwrap();
        }
        let data = [7; 1000];
        let result = owner.execute(
            fd,
            Op::SendTo(
                vec![(data.as_ptr() as usize, data.len())],
                MSG_FASTOPEN,
                Some(remote),
                None,
            ),
        );
        if selection == 3 {
            assert_eq!(result.unwrap_err(), EOPNOTSUPP);
            assert!(matches!(owner.sockets[&fd].handle, Handle::Fresh));
            assert!(
                owner
                    .endpoint
                    .poll_transmit(0, &mut [0; 2048], 64)
                    .unwrap()
                    .packet
                    .is_none()
            );
            continue;
        }
        if selection == 0 {
            assert_eq!(result.unwrap().value, 496);
        } else {
            assert_eq!(result.unwrap_err(), EINPROGRESS);
        }
        let mut bytes = [0; 2048];
        let tx = owner
            .endpoint
            .poll_transmit(0, &mut bytes, 64)
            .unwrap()
            .packet
            .unwrap();
        let syn = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
        assert_eq!(syn.options.fast_open, Some(FastOpenCookie::request()));
        assert_eq!(syn.payload.len(), if selection == 0 { 496 } else { 0 });
        assert_eq!(
            owner
                .execute(fd, Op::SetFastOpenServerCookie(None))
                .unwrap_err(),
            EINVAL
        );
    }
}

#[test]
fn native_client_policy_is_exact_peer_scoped_and_explicit_credentials_win() {
    for mode in 0..6 {
        let local = Ipv4Addr::new(10, 73, 0, 2);
        let remote: SocketAddr = "10.73.0.3:8080".parse().unwrap();
        let mut owner = Owner::with_config(
            local,
            (local, 32),
            [2; 32],
            None,
            SocketConfig::new("test", local).tcp,
        )
        .unwrap();
        owner.test_now = Some(0);
        let fd = owner.execute(0, Op::New(SOCK_NONBLOCK)).unwrap().value as u64;
        if mode >= 2 {
            owner
                .execute(
                    0,
                    Op::SetFastOpenClientDefaultPolicy(FastOpenClientPolicy::ApplicationProtected),
                )
                .unwrap();
        }
        if mode <= 1 || mode == 3 {
            owner
                .execute(
                    fd,
                    Op::SetFastOpenClientPolicy(Some((
                        if mode == 1 {
                            "10.73.0.3:8081".parse().unwrap()
                        } else {
                            remote
                        },
                        if mode == 3 {
                            FastOpenClientPolicy::RequireCookie
                        } else {
                            FastOpenClientPolicy::ApplicationProtected
                        },
                    ))),
                )
                .unwrap();
        }
        if mode == 4 {
            owner
                .execute(
                    fd,
                    Op::SetFastOpenServerCookie(Some((remote, FastOpenCookie::request()))),
                )
                .unwrap();
        }
        if mode == 5 {
            owner
                .execute(0, Op::SetFastOpenClientEnabled(false))
                .unwrap();
        }
        let data = [7; 1000];
        let result = owner.execute(
            fd,
            Op::SendTo(
                vec![(data.as_ptr() as usize, data.len())],
                MSG_FASTOPEN,
                Some(remote),
                None,
            ),
        );
        if mode == 5 {
            assert_eq!(result.unwrap_err(), EOPNOTSUPP);
            continue;
        }
        if mode == 2 {
            owner
                .execute(
                    0,
                    Op::SetFastOpenClientDefaultPolicy(FastOpenClientPolicy::RequireCookie),
                )
                .unwrap();
        }
        let early = matches!(mode, 0 | 2 | 4);
        if early {
            assert_eq!(result.unwrap().value, 496);
        } else {
            assert_eq!(result.unwrap_err(), EINPROGRESS);
        }
        let mut out = [0; 2048];
        let tx = owner
            .endpoint
            .poll_transmit(0, &mut out, 64)
            .unwrap()
            .packet
            .unwrap();
        let syn = wire::parse(tx.ip, &out[..tx.len]).unwrap();
        assert_eq!(syn.payload.len(), if early { 496 } else { 0 });
        assert_eq!(syn.options.fast_open.is_none(), matches!(mode, 0 | 2));
        assert_eq!(
            owner
                .execute(fd, Op::SetFastOpenClientPolicy(None))
                .unwrap_err(),
            EINVAL
        );
    }
}

#[test]
fn client_default_mode_changes_leave_deferred_admission_intact() {
    let local = Ipv4Addr::new(10, 73, 0, 2);
    let remote: SocketAddr = "10.73.0.3:8080".parse().unwrap();
    let mut owner = Owner::with_config(
        local,
        (local, 32),
        [2; 32],
        None,
        SocketConfig::new("test", local).tcp,
    )
    .unwrap();
    owner.test_now = Some(0);
    owner
        .execute(
            0,
            Op::SetFastOpenClientDefaultPolicy(FastOpenClientPolicy::ApplicationProtected),
        )
        .unwrap();
    let fd = owner.execute(0, Op::New(SOCK_NONBLOCK)).unwrap().value as u64;
    owner
        .execute(fd, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
        .unwrap();
    owner.execute(fd, Op::Connect(remote)).unwrap();
    assert_eq!(owner.sockets[&fd].deferred_peer, Some(remote));
    owner
        .execute(
            0,
            Op::SetFastOpenClientDefaultPolicy(FastOpenClientPolicy::RequireCookie),
        )
        .unwrap();
    let data = [7; 1000];
    assert_eq!(
        owner
            .execute(fd, Op::Send(vec![(data.as_ptr() as usize, data.len())], 0))
            .unwrap()
            .value,
        496
    );
    let mut out = [0; 2048];
    let tx = owner
        .endpoint
        .poll_transmit(0, &mut out, 64)
        .unwrap()
        .packet
        .unwrap();
    let syn = wire::parse(tx.ip, &out[..tx.len]).unwrap();
    assert_eq!(syn.payload.len(), 496);
    assert!(syn.options.fast_open.is_none());
    let next = owner.execute(0, Op::New(SOCK_NONBLOCK)).unwrap().value as u64;
    assert_eq!(
        owner
            .execute(
                next,
                Op::SendTo(
                    vec![(data.as_ptr() as usize, data.len())],
                    MSG_FASTOPEN,
                    Some(remote),
                    None
                )
            )
            .unwrap_err(),
        EINPROGRESS
    );
}
