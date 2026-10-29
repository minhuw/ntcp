// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;
use ntcp::wire::{self, FastOpenCookie};

fn hostile_option_frame(
    owner: &Owner,
    ip: ntcp::IpMetadata,
    header: wire::Header,
    raw: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let padding = (4 - raw.len() % 4) % 4;
    let mut tcp = vec![0; 60 + payload.len()];
    let n = wire::encode(ip, header, &vec![1; padding + raw.len()], payload, &mut tcp).unwrap();
    tcp.truncate(n);
    tcp[20 + padding..20 + padding + raw.len()].copy_from_slice(raw);
    tcp[16..18].fill(0);
    let sum = wire::checksum(ip, &tcp).unwrap();
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
    super::tests::ip_packet(
        owner,
        ntcp::Transmit {
            tx_timestamp: None,
            connection: None,
            ipv4_options: Default::default(),
            ecn: 0,
            ip,
            len: n,
            hop_limit: 64,
            dscp: 0,
        },
        &tcp,
    )
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.1
//= type=test
//= reason=Invalid incoming Kind 34 lengths discard credential metadata; an unframeable suffix stops traversal without guessing boundaries, preserving validated prefix options and DataOffset payload. Non-SYN credentials are ignored. Strict output, checksum/header and unrelated malformed-option rejection remain enforced.
//# Options with invalid Length values or without the SYN flag set MUST be ignored.
#[test]
fn native_malformed_credentials_retain_framing_timestamps_and_stream() {
    for v6 in [false, true] {
        for suffix in [&[34][..], &[34, 0], &[34, 1], &[34, 6, 2, 4, 0], &[34, 255]] {
            let local: IpAddr = if v6 { "2001:db8::2" } else { "192.0.2.2" }
                .parse()
                .unwrap();
            let mut cfg = SocketConfig::new("test", local).tcp;
            cfg.connection.timestamps = true;
            cfg.connection.sack = true;
            let mut b = Owner::with_config(
                local,
                (local, if v6 { 128 } else { 32 }),
                [2; 32],
                None,
                cfg,
            )
            .unwrap();
            b.test_now = Some(0);
            let listener = listener(&mut b, 8080);
            b.execute(listener, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 4))
                .unwrap();
            b.execute(listener, Op::Listen(8)).unwrap();
            let ip = ntcp::IpMetadata {
                source: if v6 { "2001:db8::1" } else { "192.0.2.1" }
                    .parse()
                    .unwrap(),
                destination: local,
            };
            let header = wire::Header {
                source_port: 40000,
                destination_port: 8080,
                sequence: 100,
                acknowledgment: 0,
                flags: wire::SYN,
                window: 8192,
                urgent_pointer: 0,
            };
            let request = hostile_option_frame(&b, ip, header, &[34, 2], &[]);
            b.input_ip(&request, Default::default());
            let response = super::tests::poll_packet(&mut b).unwrap();
            let p = crate::ip::parse(&response).unwrap();
            let cookie = wire::parse(p.ip, p.payload)
                .unwrap()
                .options
                .fast_open
                .unwrap();
            let header = wire::Header {
                source_port: 40001,
                ..header
            };
            let mut raw = vec![2, 4, 2, 24, 3, 3, 2, 4, 2, 8, 10, 0, 0, 0, 7, 0, 0, 0, 0];
            raw.extend_from_slice(&[34, (cookie.as_bytes().len() + 2) as u8]);
            raw.extend_from_slice(cookie.as_bytes());
            raw.extend_from_slice(suffix);
            let syn = hostile_option_frame(&b, ip, header, &raw, b"hello");
            let mut corrupt = syn.clone();
            *corrupt.last_mut().unwrap() ^= 1;
            b.input_ip(&corrupt, Default::default());
            assert!(super::tests::poll_packet(&mut b).is_none());
            for words in [4, 15] {
                let mut bad_offset = hostile_option_frame(&b, ip, header, &[], &[]);
                let tcp_start = crate::ip::header_len(ip.source);
                bad_offset[tcp_start + 12] = words << 4;
                bad_offset[tcp_start + 16..tcp_start + 18].fill(0);
                let sum = wire::checksum(ip, &bad_offset[tcp_start..]).unwrap();
                bad_offset[tcp_start + 16..tcp_start + 18].copy_from_slice(&sum.to_be_bytes());
                b.input_ip(&bad_offset, Default::default());
                assert!(super::tests::poll_packet(&mut b).is_none());
            }
            for malformed in [&[2, 0][..], &[8, 9, 0, 0, 0, 0, 0, 0, 0]] {
                b.input_ip(
                    &hostile_option_frame(&b, ip, header, malformed, b"hello"),
                    Default::default(),
                );
                assert!(super::tests::poll_packet(&mut b).is_none());
            }
            b.input_ip(&syn, Default::default());
            assert_eq!(
                b.execute(listener, Op::Accept(SOCK_NONBLOCK)).unwrap_err(),
                EAGAIN
            );
            let response = super::tests::poll_packet(&mut b).unwrap();
            let p = crate::ip::parse(&response).unwrap();
            let synack = wire::parse(p.ip, p.payload).unwrap();
            assert_eq!(synack.header.acknowledgment, 101);
            assert!(synack.options.fast_open.is_none());
            assert!(synack.options.sack_permitted);
            assert!(synack.options.window_scale.is_some());
            let (ts, echo) = synack.options.timestamps.unwrap();
            assert_eq!(echo, 7);
            let header = wire::Header {
                sequence: 101,
                acknowledgment: synack.header.sequence.wrapping_add(1),
                flags: wire::ACK,
                ..header
            };
            let mut raw = vec![8, 10, 0, 0, 0, 8];
            raw.extend_from_slice(&ts.to_be_bytes());
            raw.extend_from_slice(suffix);
            let ack = hostile_option_frame(&b, ip, header, &raw, b"hello");
            b.input_ip(&ack, Default::default());
            let child = b
                .execute(listener, Op::Accept(SOCK_NONBLOCK))
                .unwrap()
                .value as u64;
            assert_eq!(b.execute(child, Op::Read(32)).unwrap().bytes, b"hello");
            b.input_ip(&ack, Default::default());
            assert_eq!(b.execute(child, Op::Read(32)).unwrap_err(), EAGAIN);
            let header = wire::Header {
                sequence: 106,
                ..header
            };
            raw[5] = 6;
            b.input_ip(
                &hostile_option_frame(&b, ip, header, &raw, b"next"),
                Default::default(),
            );
            assert_eq!(b.execute(child, Op::Read(32)).unwrap_err(), EAGAIN);
            raw[5] = 9;
            b.input_ip(
                &hostile_option_frame(&b, ip, header, &raw, b"next"),
                Default::default(),
            );
            assert_eq!(b.execute(child, Op::Read(32)).unwrap().bytes, b"next");
        }
    }
}

fn native_pair(v6: bool, reserved: bool) -> (Owner, Owner, u64, SocketAddr) {
    let local: IpAddr = if v6 { "2001:db8::1" } else { "192.0.2.1" }
        .parse()
        .unwrap();
    let remote: IpAddr = if v6 { "2001:db8::2" } else { "192.0.2.2" }
        .parse()
        .unwrap();
    let mut cfg = SocketConfig::new("test", local).tcp;
    cfg.connection.mss = 1460;
    cfg.connection.timestamps = false;
    cfg.connection.nagle = false;
    let mut a = Owner::with_config(
        local,
        (local, if v6 { 128 } else { 32 }),
        [1; 32],
        None,
        cfg.clone(),
    )
    .unwrap();
    cfg.connection.mss = 940;
    let mut b = Owner::with_config(
        remote,
        (remote, if v6 { 128 } else { 32 }),
        [2; 32],
        None,
        cfg,
    )
    .unwrap();
    a.test_now = Some(0);
    b.test_now = Some(0);
    if reserved {
        a.endpoint.enable_output_reservations().unwrap();
    }
    let socket = listener(&mut b, 8080);
    b.execute(socket, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 8))
        .unwrap();
    b.execute(socket, Op::Listen(16)).unwrap();
    (a, b, socket, SocketAddr::new(remote, 8080))
}

fn native_output(owner: &mut Owner, reserved: bool) -> Option<Vec<u8>> {
    if !reserved {
        return super::tests::poll_packet(owner);
    }
    let mut bytes = [0; 2048];
    let now = owner.now();
    let (out, token) = owner
        .endpoint
        .poll_reserved_transmit(now, &mut bytes, 64)
        .unwrap();
    let tx = out.packet?;
    owner.endpoint.accept_transmit(now, token.unwrap()).unwrap();
    Some(super::tests::ip_packet(owner, tx, &bytes[..tx.len]))
}

fn native_pump(a: &mut Owner, b: &mut Owner, reserved: bool) {
    for _ in 0..16 {
        let mut progress = false;
        if let Some(frame) = native_output(a, reserved) {
            b.input_ip(&frame, Default::default());
            progress = true;
        }
        if let Some(frame) = native_output(b, false) {
            a.input_ip(&frame, Default::default());
            progress = true;
        }
        a.events();
        b.events();
        if !progress {
            break;
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
//= type=test
//= reason=The cookie-required branch serializes the selected server cookie and limits SYN data to validated learned MSS or a conservative cold 536 bytes in both families before the full option reserve and other bounds. Explicit ApplicationProtected uses section 7.3 authorization separately. Erratum 8015 remains Held for Document Update and is not needed for this bound.
//# Otherwise, include the Fast Open option with the cookie of the server. Include any data up to the cached server MSS or default 536 bytes.
#[test]
fn native_cold_admission_is_independent_of_family_and_learns_real_mss() {
    for v6 in [false, true] {
        for reserved in [false, true] {
            for deferred in [false, true] {
                for mode in 0..5 {
                    let (mut a, mut b, listener, remote) = native_pair(v6, reserved);
                    b.execute(
                        listener,
                        Op::SetListenerFastOpenEarlyDataPolicy(
                            FastOpenEarlyDataPolicy::ApplicationProtected,
                        ),
                    )
                    .unwrap();
                    let data = vec![7; 1600];
                    for attempt in 0..2 {
                        let socket = super::tests::new(&mut a, SOCK_NONBLOCK);
                        let cookie = match mode {
                            1 => Some(FastOpenCookie::request()),
                            2 => Some(FastOpenCookie::new(&[7; 4]).unwrap()),
                            3 => Some(FastOpenCookie::new(&[8; 16]).unwrap()),
                            _ => None,
                        };
                        if let Some(cookie) = cookie {
                            a.execute(socket, Op::SetFastOpenServerCookie(Some((remote, cookie))))
                                .unwrap();
                        }
                        if mode == 4 {
                            a.execute(
                                socket,
                                Op::SetFastOpenClientPolicy(Some((
                                    remote,
                                    FastOpenClientPolicy::ApplicationProtected,
                                ))),
                            )
                            .unwrap();
                        }
                        if deferred {
                            a.execute(socket, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                                .unwrap();
                            let result = a.execute(socket, Op::Connect(remote));
                            if mode == 0 {
                                assert_eq!(result.unwrap_err(), EINPROGRESS);
                            } else {
                                assert_eq!(result.unwrap().value, 0);
                            }
                        }
                        let send = |flags| {
                            Op::SendTo(
                                vec![(data.as_ptr() as usize, data.len())],
                                flags,
                                Some(remote),
                                None,
                            )
                        };
                        let expected = if mode == 0 {
                            0
                        } else if attempt == 0 {
                            496
                        } else {
                            900
                        };
                        let result = a.execute(
                            socket,
                            send(if deferred { MSG_DONTWAIT } else { MSG_FASTOPEN }),
                        );
                        if mode == 0 {
                            assert_eq!(
                                result.unwrap_err(),
                                if deferred { EAGAIN } else { EINPROGRESS }
                            );
                        } else {
                            assert_eq!(result.unwrap().value, expected);
                        }
                        let frame = native_output(&mut a, reserved).unwrap();
                        let ip = crate::ip::parse(&frame).unwrap();
                        let syn = wire::parse(ip.ip, ip.payload).unwrap();
                        assert_eq!(syn.payload.len(), expected as usize);
                        assert_eq!(syn.options.mss, Some(1460));
                        assert_eq!(
                            syn.options.fast_open,
                            if mode == 0 {
                                Some(FastOpenCookie::request())
                            } else {
                                cookie
                            }
                        );
                        b.input_ip(&frame, Default::default());
                        native_pump(&mut a, &mut b, reserved);
                        let child = b
                            .execute(listener, Op::Accept(SOCK_NONBLOCK))
                            .unwrap()
                            .value as u64;
                        a.execute(socket, Op::Write(data[expected as usize..].to_vec()))
                            .unwrap();
                        native_pump(&mut a, &mut b, reserved);
                        assert_eq!(b.execute(child, Op::Read(2000)).unwrap().bytes, data);
                        assert_eq!(b.execute(child, Op::Read(1)).unwrap_err(), EAGAIN);
                    }
                }
            }
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
//= type=test
//= reason=The cookie-required branch serializes the selected server cookie and limits SYN data to validated learned MSS or a conservative cold 536 bytes in both families before the full option reserve and other bounds. Explicit ApplicationProtected uses section 7.3 authorization separately. Erratum 8015 remains Held for Document Update and is not needed for this bound.
//# Otherwise, include the Fast Open option with the cookie of the server. Include any data up to the cached server MSS or default 536 bytes.
#[test]
fn native_cookie_without_advertised_mss_keeps_all_authorization_modes_cold() {
    for v6 in [false, true] {
        for reserved in [false, true] {
            for deferred in [false, true] {
                for mode in 0..3 {
                    let (mut a, mut b, listener, remote) = native_pair(v6, reserved);
                    if mode != 0 {
                        b.execute(
                            listener,
                            Op::SetListenerFastOpenEarlyDataPolicy(
                                FastOpenEarlyDataPolicy::ApplicationProtected,
                            ),
                        )
                        .unwrap();
                    }
                    let data = vec![7; 1600];
                    for attempt in 0..3 {
                        let socket = super::tests::new(&mut a, SOCK_NONBLOCK);
                        if mode == 1 {
                            a.execute(
                                socket,
                                Op::SetFastOpenServerCookie(Some((
                                    remote,
                                    FastOpenCookie::new(&[7; 16]).unwrap(),
                                ))),
                            )
                            .unwrap();
                        } else if mode == 2 {
                            a.execute(
                                socket,
                                Op::SetFastOpenClientPolicy(Some((
                                    remote,
                                    FastOpenClientPolicy::ApplicationProtected,
                                ))),
                            )
                            .unwrap();
                        }
                        let cold_request = mode == 0 && attempt == 0;
                        if deferred {
                            a.execute(socket, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                                .unwrap();
                            let result = a.execute(socket, Op::Connect(remote));
                            if cold_request {
                                assert_eq!(result.unwrap_err(), EINPROGRESS);
                            } else {
                                assert_eq!(result.unwrap().value, 0);
                            }
                        }
                        let expected = if cold_request {
                            0
                        } else if attempt < 2 {
                            496
                        } else {
                            900
                        };
                        let result = a.execute(
                            socket,
                            Op::SendTo(
                                vec![(data.as_ptr() as usize, data.len())],
                                if deferred { MSG_DONTWAIT } else { MSG_FASTOPEN },
                                Some(remote),
                                None,
                            ),
                        );
                        if cold_request {
                            assert_eq!(
                                result.unwrap_err(),
                                if deferred { EAGAIN } else { EINPROGRESS }
                            );
                        } else {
                            assert_eq!(result.unwrap().value, expected);
                        }
                        let frame = native_output(&mut a, reserved).unwrap();
                        let ip = crate::ip::parse(&frame).unwrap();
                        let syn = wire::parse(ip.ip, ip.payload).unwrap();
                        assert_eq!(syn.payload, &data[..expected as usize]);
                        assert_eq!(syn.options.fast_open.is_some(), mode != 2);
                        b.input_ip(&frame, Default::default());
                        let reply = native_output(&mut b, false).unwrap();
                        let reply = if attempt == 0 {
                            let ip = crate::ip::parse(&reply).unwrap();
                            let synack = wire::parse(ip.ip, ip.payload).unwrap();
                            let mut options = synack.raw_options.to_vec();
                            assert_eq!(&options[..2], &[2, 4]);
                            options[..4].fill(1);
                            hostile_option_frame(&b, ip.ip, synack.header, &options, synack.payload)
                        } else {
                            reply
                        };
                        let ip = crate::ip::parse(&reply).unwrap();
                        assert_eq!(
                            wire::parse(ip.ip, ip.payload).unwrap().options.mss,
                            if attempt == 0 { None } else { Some(940) }
                        );
                        a.input_ip(&reply, Default::default());
                        native_pump(&mut a, &mut b, reserved);
                        let child = b
                            .execute(listener, Op::Accept(SOCK_NONBLOCK))
                            .unwrap()
                            .value as u64;
                        a.execute(socket, Op::Write(data[expected as usize..].to_vec()))
                            .unwrap();
                        native_pump(&mut a, &mut b, reserved);
                        assert_eq!(b.execute(child, Op::Read(2000)).unwrap().bytes, data);
                        assert_eq!(b.execute(child, Op::Read(1)).unwrap_err(), EAGAIN);
                    }
                }
            }
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.1
//= type=test
//= reason=The first RTO of a physically transmitted request trains the existing per-source/service cooldown once. Local output failures and held reservations do not train it; successful fallback and late cookie/MSS learning cannot erase it, and expiry permits future requests.
//# We also RECOMMEND the client to record the set of servers that failed to respond to cookie requests and only attempt another cookie request after a certain period.
#[test]
fn native_first_request_rto_suppresses_service_and_keeps_ordinary_stream() {
    for v6 in [false, true] {
        for reserved in [false, true] {
            for late_original in [false, true] {
                let (mut a, mut b, listener, remote) = native_pair(v6, reserved);
                let socket = super::tests::new(&mut a, SOCK_NONBLOCK);
                let send = |data: &[u8]| {
                    Op::SendTo(
                        vec![(data.as_ptr() as usize, data.len())],
                        MSG_FASTOPEN,
                        Some(remote),
                        None,
                    )
                };
                assert_eq!(a.execute(socket, send(b"cold")).unwrap_err(), EINPROGRESS);
                let original = native_output(&mut a, reserved).unwrap();
                let ip = crate::ip::parse(&original).unwrap();
                assert_eq!(
                    wire::parse(ip.ip, ip.payload).unwrap().options.fast_open,
                    Some(FastOpenCookie::request())
                );
                let deadline = a.endpoint.next_deadline().unwrap();
                a.test_now = Some(deadline);
                b.test_now = Some(deadline);
                a.endpoint.on_timeout(deadline, 64).unwrap();
                let retry = native_output(&mut a, reserved).unwrap();
                let ip = crate::ip::parse(&retry).unwrap();
                let syn = wire::parse(ip.ip, ip.payload).unwrap();
                assert!(syn.options.fast_open.is_none() && syn.payload.is_empty());
                b.input_ip(
                    if late_original { &original } else { &retry },
                    Default::default(),
                );
                native_pump(&mut a, &mut b, reserved);
                let child = b
                    .execute(listener, Op::Accept(SOCK_NONBLOCK))
                    .unwrap()
                    .value as u64;
                a.execute(socket, Op::Write(b"fallback".to_vec())).unwrap();
                native_pump(&mut a, &mut b, reserved);
                assert_eq!(b.execute(child, Op::Read(32)).unwrap().bytes, b"fallback");
                assert_eq!(
                    a.endpoint
                        .has_fast_open_cookie(deadline, a.local, remote.ip())
                        .unwrap(),
                    late_original
                );
                let next = super::tests::new(&mut a, SOCK_NONBLOCK);
                a.execute(next, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                    .unwrap();
                assert_eq!(
                    a.execute(next, Op::Connect(remote)).unwrap_err(),
                    EINPROGRESS
                );
                let frame = native_output(&mut a, reserved).unwrap();
                let ip = crate::ip::parse(&frame).unwrap();
                let syn = wire::parse(ip.ip, ip.payload).unwrap();
                assert!(syn.options.fast_open.is_none() && syn.payload.is_empty());
                b.input_ip(&frame, Default::default());
                native_pump(&mut a, &mut b, reserved);
                let child = b
                    .execute(listener, Op::Accept(SOCK_NONBLOCK))
                    .unwrap()
                    .value as u64;
                a.execute(next, Op::Write(b"ordinary".to_vec())).unwrap();
                native_pump(&mut a, &mut b, reserved);
                assert_eq!(b.execute(child, Op::Read(32)).unwrap().bytes, b"ordinary");
                let cookie = Some(FastOpenCookie::request());
                let expiry = deadline + 60_000_000;
                assert!(
                    !a.endpoint
                        .can_defer_fast_open_with_server_cookie(expiry - 1, a.local, remote, cookie)
                        .unwrap()
                );
                assert!(
                    a.endpoint
                        .can_defer_fast_open_with_server_cookie(expiry, a.local, remote, cookie)
                        .unwrap()
                );
            }
        }
    }
}

#[cfg(feature = "tfo-linux-cookie")]
fn policy(byte: u8) -> FastOpenCookiePolicy {
    FastOpenCookiePolicy::LinuxSipHash24(LinuxSipHash24Key::new([byte; 16]))
}
#[cfg(feature = "tfo-linux-cookie")]
fn set(owner: &mut Owner, id: u64, byte: u8) -> Result<Reply> {
    owner.execute(id, Op::SetFastOpenKey(LinuxSipHash24Key::new([byte; 16])))
}
#[cfg(feature = "tfo-linux-cookie")]
fn syn(owner: &mut Owner, port: u16, remote_port: u16) {
    let ip = ntcp::IpMetadata {
        source: "192.0.2.1".parse().unwrap(),
        destination: owner.local,
    };
    let mut bytes = [0; 128];
    let n = wire::encode(
        ip,
        wire::Header {
            source_port: remote_port,
            destination_port: port,
            sequence: 100,
            acknowledgment: 0,
            flags: wire::SYN,
            window: 8192,
            urgent_pointer: 0,
        },
        &[34, 2, 1, 1],
        &[],
        &mut bytes,
    )
    .unwrap();
    owner.endpoint.input(owner.now(), ip, &bytes[..n]).unwrap();
}
#[cfg(feature = "tfo-linux-cookie")]
fn response(owner: &mut Owner) -> Option<FastOpenCookie> {
    let mut bytes = [0; 2048];
    let tx = owner
        .endpoint
        .poll_transmit(owner.now(), &mut bytes, 64)
        .unwrap()
        .packet
        .unwrap();
    wire::parse(tx.ip, &bytes[..tx.len])
        .unwrap()
        .options
        .fast_open
}
fn listener(owner: &mut Owner, port: u16) -> u64 {
    let id = owner.execute(0, Op::New(SOCK_NONBLOCK)).unwrap().value as u64;
    owner
        .execute(id, Op::Bind(SocketAddr::new(owner.local, port)))
        .unwrap();
    id
}

#[cfg(feature = "tfo-linux-cookie")]
#[test]
fn typed_default_staging_rotation_isolation_and_failed_handles() {
    let local: IpAddr = "192.168.0.1".parse().unwrap();
    let mut config = SocketConfig::new("test", local);
    config.fast_open_cookie_policy = policy(1);
    let mut owner =
        Owner::with_config(local, (local, 32), [42; 32], None, config.tcp.clone()).unwrap();
    owner.test_now = Some(0);
    let budget = owner.endpoint.buffer_bytes();
    owner.apply_socket_config(&config).unwrap();
    let a = listener(&mut owner, 8080);
    set(&mut owner, a, 2).unwrap();
    owner.execute(a, Op::Listen(8)).unwrap();
    assert_eq!(
        owner.endpoint.buffer_bytes(),
        budget + owner.endpoint.fast_open_key_registry_usage().1
    );
    syn(&mut owner, 8080, 40000);
    assert_eq!(response(&mut owner), None); // Policy is not enablement.
    owner
        .execute(a, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 8))
        .unwrap();
    syn(&mut owner, 8080, 40001);
    set(&mut owner, a, 3).unwrap(); // Existing child retains key 2's response.
    let old = response(&mut owner).unwrap();
    syn(&mut owner, 8080, 40002);
    let new = response(&mut owner).unwrap();
    assert_ne!(old, new);
    set(&mut owner, a, 2).unwrap();
    syn(&mut owner, 8080, 40003);
    assert_eq!(response(&mut owner), Some(old));

    let b = listener(&mut owner, 8081);
    owner.execute(b, Op::Listen(8)).unwrap();
    owner
        .execute(b, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 8))
        .unwrap();
    syn(&mut owner, 8081, 40004);
    let inherited = response(&mut owner).unwrap();
    assert_ne!(inherited, old);
    config.fast_open_cookie_policy = policy(2);
    owner.apply_socket_config(&config).unwrap();
    syn(&mut owner, 8081, 40005);
    assert_eq!(response(&mut owner), Some(old));

    let Handle::Listener(handle) = owner.sockets[&a].handle else {
        panic!()
    };
    owner.endpoint.close_listener(handle).unwrap();
    assert_eq!(set(&mut owner, a, 9).unwrap_err(), EBADF);
    // Debug is redacted; verify retained policy by applying it to the live exact listener.
    let retained = owner.sockets[&a].fast_open_cookie_policy.clone();
    let Handle::Listener(handle) = owner.sockets[&b].handle else {
        panic!()
    };
    owner
        .endpoint
        .set_listener_fast_open_cookie_policy(handle, retained)
        .unwrap();
    syn(&mut owner, 8081, 40006);
    assert_eq!(response(&mut owner), Some(old));
    assert_eq!(set(&mut owner, u64::MAX, 9).unwrap_err(), EBADF);

    let active = listener(&mut owner, 8082);
    owner.sockets.get_mut(&active).unwrap().deferred_peer = Some("192.0.2.1:80".parse().unwrap());
    assert_eq!(set(&mut owner, active, 9).unwrap_err(), EINVAL);
    owner.sockets.get_mut(&active).unwrap().deferred_peer = None;
    assert_eq!(
        owner
            .execute(active, Op::Connect("192.0.2.1:80".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    assert_eq!(set(&mut owner, active, 9).unwrap_err(), EINVAL);
    assert!(owner.sockets[&active].fast_open_cookie_policy.is_none());
}

fn native_exchange(
    owner: &mut Owner,
    socket: u64,
    port: u16,
    cookie: Option<FastOpenCookie>,
    early: bool,
) -> (Option<FastOpenCookie>, ConnectionId) {
    let now = owner.now();
    let mut config = EndpointConfig::default();
    config.connection.timestamps = false;
    config.connection.nagle = false;
    let mut client = Endpoint::new(config, [1; 32], now, |_| true).unwrap();
    client.enable_fast_open().unwrap();
    let options = ntcp::ActiveOpenOptions::from(&ntcp::ConnectionConfig::default());
    let local = SocketAddr::new(
        if owner.local.is_ipv6() {
            "2001:db8::1"
        } else {
            "192.0.2.1"
        }
        .parse()
        .unwrap(),
        port,
    );
    let remote = SocketAddr::new(owner.local, 8080);
    let (client_id, admitted) = client
        .connect_fast_open_with_server_cookie(now, local, remote, b"hello", options, cookie)
        .unwrap();
    let mut bytes = [0; 2048];
    let tx = client
        .poll_transmit(now, &mut bytes, 64)
        .unwrap()
        .packet
        .unwrap();
    let sequence = wire::parse(tx.ip, &bytes[..tx.len])
        .unwrap()
        .header
        .sequence;
    owner.endpoint.input(now, tx.ip, &bytes[..tx.len]).unwrap();
    let tx = owner
        .endpoint
        .poll_transmit(now, &mut bytes, 64)
        .unwrap()
        .packet
        .unwrap();
    let parsed = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
    assert_eq!(
        parsed.header.acknowledgment,
        sequence.wrapping_add(if early { 6 } else { 1 })
    );
    let issued = parsed.options.fast_open;
    let Handle::Listener(listener) = owner.sockets[&socket].handle else {
        panic!()
    };
    let child = if early {
        Some(owner.endpoint.accept(listener).unwrap())
    } else {
        None
    };
    client.input(now, tx.ip, &bytes[..tx.len]).unwrap();
    let tx = client
        .poll_transmit(now, &mut bytes, 64)
        .unwrap()
        .packet
        .unwrap();
    owner.endpoint.input(now, tx.ip, &bytes[..tx.len]).unwrap();
    let child = child.unwrap_or_else(|| owner.endpoint.accept(listener).unwrap());
    if admitted == 0 {
        client.write(client_id, b"hello").unwrap();
        let tx = client
            .poll_transmit(now, &mut bytes, 64)
            .unwrap()
            .packet
            .unwrap();
        owner.endpoint.input(now, tx.ip, &bytes[..tx.len]).unwrap();
    }
    let mut data = [0; 5];
    assert_eq!(owner.endpoint.read(child, &mut data), Ok(5));
    assert_eq!(&data, b"hello");
    assert_eq!(client.state(client_id), Ok(State::Established));
    (issued, child)
}

#[test]
fn unmanaged_hmac_initial_lifetime_applies_to_native_traffic() {
    for local in ["192.168.0.1", "2001:db8::2"] {
        let local: IpAddr = local.parse().unwrap();
        let mut config = SocketConfig::new("test", local);
        config.fast_open_managed_keys = Some(false);
        config.fast_open_cookie_lifetime =
            ntcp::FastOpenCookieLifetime::from_micros(1_000_000).unwrap();
        let mut owner = Owner::with_config(
            local,
            (local, if local.is_ipv4() { 32 } else { 128 }),
            [42; 32],
            None,
            config.tcp.clone(),
        )
        .unwrap();
        owner.test_now = Some(0);
        owner.fast_open_entropy = Some(VecDeque::from([Ok([7; 32])]));
        owner.initialize_socket_config(&config).unwrap();
        let id = listener(&mut owner, 8080);
        owner
            .execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 16))
            .unwrap();
        owner.execute(id, Op::Listen(24)).unwrap();
        let cookie = native_exchange(&mut owner, id, 40000, None, false)
            .0
            .unwrap();
        for (port, now) in [(40001, 999_999), (40002, 1_000_000), (40003, 1_999_999)] {
            owner.test_now = Some(now);
            native_exchange(&mut owner, id, port, Some(cookie), true);
        }
        owner.test_now = Some(2_000_000);
        owner.apply_socket_config(&config).unwrap();
        let fresh = native_exchange(&mut owner, id, 40004, Some(cookie), false)
            .0
            .unwrap();
        assert_ne!(fresh, cookie);
        native_exchange(&mut owner, id, 40005, Some(fresh), true);
        assert!(owner.fast_open_keys.is_none());
        assert!(owner.fast_open_entropy.as_ref().unwrap().is_empty());
    }
}

#[test]
fn unmanaged_hmac_initial_entropy_failure_preserves_established_flows() {
    let local: IpAddr = "192.168.0.1".parse().unwrap();
    let mut config = SocketConfig::new("test", local);
    config.fast_open_managed_keys = Some(false);
    config.fast_open_cookie_lifetime = ntcp::FastOpenCookieLifetime::from_micros(100).unwrap();
    let mut owner =
        Owner::with_config(local, (local, 32), [42; 32], None, config.tcp.clone()).unwrap();
    owner.test_now = Some(0);
    let id = listener(&mut owner, 8080);
    owner
        .execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 16))
        .unwrap();
    owner.execute(id, Op::Listen(24)).unwrap();
    let (cookie, live) = native_exchange(&mut owner, id, 40000, None, false);
    let cookie = cookie.unwrap();
    owner.fast_open_entropy = Some(VecDeque::from([Err(EIO), Ok([7; 32])]));
    owner.test_now = Some(1);
    assert_eq!(owner.apply_socket_config(&config), Err(EIO));
    assert!(!owner.fast_open_configured);
    assert_eq!(owner.endpoint.state(live), Ok(State::Established));
    native_exchange(&mut owner, id, 40001, Some(cookie), true);
    owner.apply_socket_config(&config).unwrap();
    let fresh = native_exchange(&mut owner, id, 40002, Some(cookie), false)
        .0
        .unwrap();
    native_exchange(&mut owner, id, 40003, Some(fresh), true);
    assert_eq!(owner.endpoint.write(live, b"still live"), Ok(10));
    assert!(owner.fast_open_keys.is_none());
    assert!(owner.fast_open_entropy.as_ref().unwrap().is_empty());
}

#[test]
fn explicit_hmac_lease_requires_unmanaged_mode_and_enforces_deadlines() {
    let local: IpAddr = "192.168.0.1".parse().unwrap();
    let mut config = SocketConfig::new("test", local);
    config.fast_open_key_lease = Some(ntcp::FastOpenKeyLease {
        not_before: 0,
        issue_until: 50,
        accept_until: 100,
        units_per_second: 1_000_000,
    });
    assert_eq!(
        config.validate().unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    let mut owner =
        Owner::with_config(local, (local, 32), [42; 32], None, config.tcp.clone()).unwrap();
    owner.test_now = Some(0);
    owner.fast_open_entropy = Some(VecDeque::new());
    assert_eq!(owner.apply_socket_config(&config), Err(EINVAL));
    assert!(owner.fast_open_keys.is_none());

    config.fast_open_managed_keys = Some(false);
    config.validate().unwrap();
    owner.apply_socket_config(&config).unwrap();
    let id = listener(&mut owner, 8080);
    owner
        .execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 16))
        .unwrap();
    owner.execute(id, Op::Listen(24)).unwrap();
    let (cookie, live) = native_exchange(&mut owner, id, 40000, None, false);
    let cookie = cookie.unwrap();
    owner.test_now = Some(49);
    assert!(
        native_exchange(&mut owner, id, 40001, Some(cookie), true)
            .0
            .is_some()
    );
    owner.test_now = Some(50);
    assert_eq!(
        native_exchange(&mut owner, id, 40002, Some(cookie), true).0,
        None
    );
    owner.test_now = Some(100);
    assert_eq!(
        native_exchange(&mut owner, id, 40003, Some(cookie), false).0,
        None
    );
    assert_eq!(owner.endpoint.state(live), Ok(State::Established));
    assert!(owner.fast_open_entropy.as_ref().unwrap().is_empty());
}

#[test]
fn automatic_rotation_registry_exhaustion_is_observable_and_preserves_live_flows() {
    for local in ["192.168.0.1", "2001:db8::2"] {
        for selected in [
            FastOpenCookiePolicy::HmacSha256,
            #[cfg(feature = "tfo-linux-cookie")]
            policy(99),
        ] {
            let local: IpAddr = local.parse().unwrap();
            let mut config = SocketConfig::new("test", local);
            config.fast_open_cookie_policy = selected;
            config.fast_open_managed_keys = Some(true);
            config.fast_open_cookie_lifetime =
                ntcp::FastOpenCookieLifetime::from_micros(100).unwrap();
            config.tcp.max_connections = 16;
            config.tcp.preallocate_connections = 16;
            config.tcp.connection.timestamps = false;
            let mut probe = Endpoint::new(config.tcp.clone(), [42; 32], 0, |_| true).unwrap();
            probe.enable_fast_open().unwrap();
            let lease = ntcp::FastOpenKeyLease::for_lifetime(
                0,
                config.fast_open_cookie_lifetime,
                config.tcp.connection.timebase,
                true,
            )
            .unwrap();
            probe
                .register_fast_open_key(0, ntcp::FastOpenServerKey::HmacSha256([1; 32]), lease)
                .unwrap();
            config.tcp.max_buffer_bytes = probe.buffer_bytes();
            let budget = config.tcp.max_buffer_bytes;
            let mut owner = Owner::with_config(
                local,
                (local, if local.is_ipv4() { 32 } else { 128 }),
                [42; 32],
                None,
                config.tcp.clone(),
            )
            .unwrap();
            owner.test_now = Some(0);
            owner.fast_open_entropy = Some(VecDeque::from([Ok([1; 32]), Ok([2; 32]), Ok([3; 32])]));
            owner.apply_socket_config(&config).unwrap();
            let id = listener(&mut owner, 8080);
            owner
                .execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 16))
                .unwrap();
            owner.execute(id, Op::Listen(16)).unwrap();
            let (cookie, live) = native_exchange(&mut owner, id, 40000, None, false);
            let cookie = cookie.unwrap();
            let usage = owner.endpoint.fast_open_key_registry_usage();
            owner.test_now = Some(100);
            assert_eq!(owner.rotate_fast_open_keys(100), Err(ENOMEM));
            assert_eq!(
                owner.fast_open_keys.as_ref().unwrap().last_error,
                Some(ENOMEM)
            );
            assert_eq!(owner.fast_open_keys.as_ref().unwrap().next_rotation, 200);
            native_exchange(&mut owner, id, 40001, Some(cookie), true);
            owner.test_now = Some(200);
            assert_eq!(owner.rotate_fast_open_keys(200), Err(ENOMEM));
            assert_eq!(
                native_exchange(&mut owner, id, 40002, Some(cookie), false).0,
                None
            );
            assert_eq!(owner.endpoint.state(live), Ok(State::Established));
            assert_eq!(owner.endpoint.write(live, b"still live"), Ok(10));
            assert_eq!(owner.endpoint.fast_open_key_registry_usage(), usage);
            assert!(owner.endpoint.buffer_bytes() <= budget);
            // Native administrative failure reports a resource error and leaves
            // a fresh socket's pending selection untouched, even after expiry.
            #[cfg(feature = "tfo-linux-cookie")]
            {
                let fresh = listener(&mut owner, 8081);
                assert_eq!(set(&mut owner, fresh, 55).unwrap_err(), ENOMEM);
                assert!(owner.sockets[&fresh].fast_open_cookie_policy.is_none());
                assert!(owner.sockets[&fresh].fast_open_key_lease.is_none());
                if let FastOpenCookiePolicy::LinuxSipHash24(_) = config.fast_open_cookie_policy {
                    set(&mut owner, fresh, 1).unwrap();
                    assert_eq!(owner.endpoint.fast_open_key_registry_usage(), usage);
                }
            }
            assert!(owner.fast_open_entropy.as_ref().unwrap().is_empty());
        }
    }
}

#[test]
fn automatic_rotation_entropy_failures_expire_credentials_and_preserve_live_flows() {
    for selected in [
        FastOpenCookiePolicy::HmacSha256,
        #[cfg(feature = "tfo-linux-cookie")]
        policy(99),
    ] {
        let local: IpAddr = "192.168.0.1".parse().unwrap();
        let mut config = SocketConfig::new("test", local);
        config.fast_open_cookie_policy = selected.clone();
        config.fast_open_managed_keys = Some(true);
        config.fast_open_cookie_lifetime = ntcp::FastOpenCookieLifetime::from_micros(100).unwrap();
        let mut owner =
            Owner::with_config(local, (local, 32), [42; 32], None, config.tcp.clone()).unwrap();
        owner.test_now = Some(0);
        owner.fast_open_entropy = Some(VecDeque::from([
            Ok([1; 32]),
            Ok([2; 32]),
            Err(EIO),
            Err(EAGAIN),
            Ok([3; 32]),
        ]));
        owner.apply_socket_config(&config).unwrap();
        let id = listener(&mut owner, 8080);
        owner
            .execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 16))
            .unwrap();
        owner.execute(id, Op::Listen(24)).unwrap();
        let (old, live) = native_exchange(&mut owner, id, 40000, None, false);
        let old = old.unwrap();
        native_exchange(&mut owner, id, 40001, Some(old), true);
        // Applying unchanged configuration neither consumes entropy nor renews.
        owner.apply_socket_config(&config).unwrap();
        owner.test_now = Some(100);
        owner.rotate_fast_open_keys(100).unwrap();
        let fresh = native_exchange(&mut owner, id, 40002, None, false)
            .0
            .unwrap();
        assert_ne!(fresh, old);
        native_exchange(&mut owner, id, 40003, Some(old), true);
        native_exchange(&mut owner, id, 40004, Some(fresh), true);
        owner.test_now = Some(200);
        assert_eq!(owner.rotate_fast_open_keys(200), Err(EIO));
        assert_eq!(owner.fast_open_keys.as_ref().unwrap().last_error, Some(EIO));
        assert_eq!(
            native_exchange(&mut owner, id, 40005, Some(old), false).0,
            None
        );
        assert_eq!(
            native_exchange(&mut owner, id, 40006, Some(fresh), true).0,
            None
        );
        owner.test_now = Some(300);
        assert_eq!(owner.rotate_fast_open_keys(300), Err(EAGAIN));
        assert_eq!(
            native_exchange(&mut owner, id, 40007, Some(fresh), false).0,
            None
        );
        assert_eq!(owner.endpoint.state(live), Ok(State::Established));
        assert_eq!(owner.endpoint.write(live, b"still live"), Ok(10));
        owner.test_now = Some(400);
        owner.rotate_fast_open_keys(400).unwrap();
        // Consume the unrelated established flow's queued output first.
        let mut bytes = [0; 2048];
        owner.endpoint.poll_transmit(400, &mut bytes, 64).unwrap();
        let newest = native_exchange(&mut owner, id, 40008, None, false)
            .0
            .unwrap();
        native_exchange(&mut owner, id, 40009, Some(newest), true);
        assert_eq!(owner.fast_open_keys.as_ref().unwrap().last_error, None);
        assert!(owner.fast_open_entropy.as_ref().unwrap().is_empty());
    }
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
//= type=test
//= reason=Endpoint admission enforces finite HMAC current/previous epochs and LinuxSipHash24 key leases with absolute issue/accept deadlines, including delayed service, retiring keys and same-key no-renewal through the endpoint-owned identity registry across arbitrary key cycles, policy clearing, listener generations, cross-listener reuse and native pre-listen staging. Raw Linux validation intentionally ignores epoch, including u64::MAX, to preserve wire bytes; that raw codec result is not server acceptance. Timed interfaces require trusted original lease deadlines or fresh keys across restart. T20/T15 must integrate that host restart/time mapping for external raw-key deployment; the whole lifecycle obligation remains TODO pending that integration.
//# 5. The cookie expires after a certain amount of time. The reason for cookie expiration is detailed in the "Security Considerations" section (Section 5). This can be done by either periodically changing the server key used to generate cookies or including a timestamp when generating the cookie.
#[cfg(feature = "tfo-linux-cookie")]
#[test]
fn native_authority_rejects_prelisten_and_live_cycles_across_socket_generations() {
    for local in ["192.168.0.1", "2001:db8::2"] {
        for staged in [false, true] {
            for length in [2, 3] {
                let local: IpAddr = local.parse().unwrap();
                let config = SocketConfig::new("test", local);
                let prefix = if local.is_ipv4() { 32 } else { 128 };
                let mut reference =
                    Owner::with_config(local, (local, prefix), [42; 32], None, config.tcp.clone())
                        .unwrap();
                reference.test_now = Some(0);
                let reference_id = listener(&mut reference, 8080);
                set(&mut reference, reference_id, 7).unwrap();
                reference
                    .execute(reference_id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 16))
                    .unwrap();
                reference.execute(reference_id, Op::Listen(24)).unwrap();
                let cookie = native_exchange(&mut reference, reference_id, 39999, None, false)
                    .0
                    .unwrap();
                let mut owner =
                    Owner::with_config(local, (local, prefix), [42; 32], None, config.tcp).unwrap();
                owner.test_now = Some(0);
                owner.fast_open_cookie_lifetime =
                    ntcp::FastOpenCookieLifetime::from_micros(100).unwrap();
                let mut id = listener(&mut owner, 8080);
                set(&mut owner, id, 7).unwrap();
                assert_eq!(owner.endpoint.fast_open_key_registry_usage().0, 2);
                owner
                    .execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 16))
                    .unwrap();
                if !staged {
                    owner.execute(id, Op::Listen(24)).unwrap();
                    native_exchange(&mut owner, id, 39999, Some(cookie), true);
                }
                owner.test_now = Some(100);
                for byte in 8..8 + length - 1 {
                    set(&mut owner, id, byte).unwrap();
                }
                owner.test_now = Some(101);
                set(&mut owner, id, 7).unwrap();
                let usage = owner.endpoint.fast_open_key_registry_usage();
                if staged {
                    owner.execute(id, Op::Listen(24)).unwrap();
                    assert_eq!(owner.endpoint.fast_open_key_registry_usage(), usage);
                }
                assert_eq!(
                    native_exchange(&mut owner, id, 40000, Some(cookie), false).0,
                    None
                );
                set(&mut owner, id, 11).unwrap();
                let fresh = native_exchange(&mut owner, id, 40001, Some(cookie), false)
                    .0
                    .unwrap();
                native_exchange(&mut owner, id, 40002, Some(fresh), true);
                owner.test_now = Some(201);
                assert_eq!(
                    native_exchange(&mut owner, id, 40003, Some(fresh), false).0,
                    None
                );
                owner.execute(id, Op::Close).unwrap();
                owner
                    .endpoint
                    .poll_transmit(201, &mut [0; 2048], 64)
                    .unwrap();
                id = listener(&mut owner, 8080);
                set(&mut owner, id, 7).unwrap();
                owner
                    .execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 16))
                    .unwrap();
                owner.execute(id, Op::Listen(24)).unwrap();
                assert_eq!(
                    native_exchange(&mut owner, id, 40004, Some(cookie), false).0,
                    None
                );
            }
        }
    }
}

#[cfg(feature = "tfo-linux-cookie")]
#[test]
fn native_set_key_staging_and_same_key_after_expiry_do_not_renew_lease() {
    let local: IpAddr = "192.168.0.1".parse().unwrap();
    let config = SocketConfig::new("test", local);
    let mut owner = Owner::with_config(local, (local, 32), [42; 32], None, config.tcp).unwrap();
    owner.test_now = Some(0);
    owner.fast_open_cookie_lifetime = ntcp::FastOpenCookieLifetime::from_micros(100).unwrap();
    let id = listener(&mut owner, 8080);
    set(&mut owner, id, 7).unwrap();
    owner.test_now = Some(50);
    set(&mut owner, id, 7).unwrap();
    assert_eq!(
        owner.sockets[&id].fast_open_key_lease.unwrap().accept_until,
        100
    );
    owner
        .execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 16))
        .unwrap();
    owner.execute(id, Op::Listen(24)).unwrap();
    let cookie = native_exchange(&mut owner, id, 40000, None, false)
        .0
        .unwrap();
    owner.test_now = Some(99);
    native_exchange(&mut owner, id, 40001, Some(cookie), true);
    owner.test_now = Some(100);
    set(&mut owner, id, 7).unwrap();
    assert_eq!(
        native_exchange(&mut owner, id, 40002, Some(cookie), false).0,
        None
    );
    owner.test_now = Some(101);
    set(&mut owner, id, 8).unwrap();
    let fresh = native_exchange(&mut owner, id, 40003, Some(cookie), false)
        .0
        .unwrap();
    native_exchange(&mut owner, id, 40004, Some(fresh), true);
}

#[cfg(feature = "tfo-linux-cookie")]
#[test]
fn external_config_lease_survives_reapply_and_expired_absolute_reinstall() {
    let local: IpAddr = "192.168.0.1".parse().unwrap();
    let mut config = SocketConfig::new("test", local);
    config.fast_open_cookie_policy = policy(7);
    config.fast_open_managed_keys = Some(false);
    config.fast_open_key_lease = Some(ntcp::FastOpenKeyLease {
        not_before: 0,
        issue_until: 50,
        accept_until: 100,
        units_per_second: 1_000_000,
    });
    let make = |now| {
        let mut owner =
            Owner::with_config(local, (local, 32), [42; 32], None, config.tcp.clone()).unwrap();
        owner.test_now = Some(now);
        owner.apply_socket_config(&config).unwrap();
        let id = listener(&mut owner, 8080);
        owner
            .execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 16))
            .unwrap();
        owner.execute(id, Op::Listen(24)).unwrap();
        (owner, id)
    };
    let (mut owner, id) = make(0);
    let cookie = native_exchange(&mut owner, id, 40000, None, false)
        .0
        .unwrap();
    owner.test_now = Some(49);
    owner.apply_socket_config(&config).unwrap();
    native_exchange(&mut owner, id, 40001, Some(cookie), true);
    owner.test_now = Some(50);
    assert_eq!(
        native_exchange(&mut owner, id, 40002, Some(cookie), true).0,
        None
    );
    owner.test_now = Some(100);
    owner.apply_socket_config(&config).unwrap();
    assert_eq!(
        native_exchange(&mut owner, id, 40003, Some(cookie), false).0,
        None
    );
    // This supplies an already-trusted original absolute deadline explicitly.
    // It exercises reinstall, not a claim that an OS restart preserves clocks.
    let (mut replacement, id) = make(100);
    assert_eq!(
        native_exchange(&mut replacement, id, 40004, Some(cookie), false).0,
        None
    );
    assert!(replacement.fast_open_keys.is_none());
}

#[cfg(feature = "tfo-linux-cookie")]
#[test]
fn socket_rotation_keeps_held_synack_and_budget_unchanged() {
    let local: IpAddr = "192.168.0.1".parse().unwrap();
    let mut owner = Owner::with_config(
        local,
        (local, 32),
        [42; 32],
        None,
        SocketConfig::new("test", local).tcp,
    )
    .unwrap();
    owner.test_now = Some(0);
    let id = listener(&mut owner, 8080);
    set(&mut owner, id, 1).unwrap();
    owner
        .execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 8))
        .unwrap();
    owner.execute(id, Op::Listen(8)).unwrap();
    owner.endpoint.enable_output_reservations().unwrap();
    syn(&mut owner, 8080, 40000);
    let mut bytes = [0; 2048];
    let (output, attempt) = owner
        .endpoint
        .poll_reserved_transmit(0, &mut bytes, 64)
        .unwrap();
    let tx = output.packet.unwrap();
    let original = bytes[..tx.len].to_vec();
    let budget = owner.endpoint.buffer_bytes();
    let registry_before = owner.endpoint.fast_open_key_registry_usage().1;
    set(&mut owner, id, 2).unwrap();
    assert_eq!(
        owner.endpoint.buffer_bytes() - owner.endpoint.fast_open_key_registry_usage().1,
        budget - registry_before
    );
    assert_eq!(&bytes[..tx.len], original);
    assert!(owner.endpoint.reject_unsubmitted(attempt.unwrap()).unwrap());
    let (output, retry) = owner
        .endpoint
        .poll_reserved_transmit_for(0, tx.connection.unwrap(), &mut bytes, 64)
        .unwrap();
    let tx = output.packet.unwrap();
    let first = wire::parse(tx.ip, &original).unwrap();
    let next = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
    assert_eq!(first.header, next.header);
    assert_eq!(first.options, next.options);
    assert_eq!(first.payload, next.payload);
    assert!(owner.endpoint.accept_transmit(0, retry.unwrap()).unwrap());
    syn(&mut owner, 8080, 40001);
    let (output, attempt) = owner
        .endpoint
        .poll_reserved_transmit(0, &mut bytes, 64)
        .unwrap();
    let tx = output.packet.unwrap();
    assert_ne!(
        wire::parse(tx.ip, &bytes[..tx.len])
            .unwrap()
            .options
            .fast_open,
        first.options.fast_open
    );
    assert!(owner.endpoint.accept_transmit(0, attempt.unwrap()).unwrap());
}
