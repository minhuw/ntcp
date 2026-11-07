// SPDX-License-Identifier: MIT
use super::*;

fn client() -> (Endpoint, ActiveOpenOptions) {
    let config = EndpointConfig {
        max_connections: 24,
        connection: ConnectionConfig {
            mss: 1460,
            send_capacity: 8192,
            receive_capacity: 8192,
            timestamps: false,
            nagle: false,
            ..Default::default()
        },
        ..Default::default()
    };
    let options = ActiveOpenOptions::from(&config.connection);
    let mut a = Endpoint::new(config, [1; 32], 0, |_| true).unwrap();
    a.enable_fast_open().unwrap();
    (a, options)
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.3
//= type=test
//= reason=Cold SYN admission uses a conservative 536-byte ceiling in both families before option, configuration, path and storage limits; true peer defaults remain 536/1220 and validated learned MSS remains usable.
//# Without a cached server MSS, the amount of data in the SYN packet is limited to the default MSS of 536 bytes for IPv4 [RFC1122] and 1220 bytes for IPv6 [RFC2460].
//= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
//= type=test
//= reason=The cookie-required branch serializes the selected server cookie and limits SYN data to validated learned MSS or a conservative cold 536 bytes in both families before the full option reserve and other bounds. Explicit ApplicationProtected uses section 7.3 authorization separately. Erratum 8015 remains Held for Document Update and is not needed for this bound.
//# Otherwise, include the Fast Open option with the cookie of the server. Include any data up to the cached server MSS or default 536 bytes.
#[test]
fn supplied_cookie_cold_limits_options_and_real_mss_learning() {
    for v6 in [false, true] {
        for token in [&[][..], &[7; 4][..], &[9; 16][..]] {
            let (mut a, options) = client();
            let cookie = wire::FastOpenCookie::new(token).unwrap();
            let (local, remote) = addresses(v6, 49000);
            assert!(!a.has_fast_open_cookie(0, local.ip(), remote.ip()).unwrap());
            assert!(
                a.can_defer_fast_open_with_server_cookie(0, local.ip(), remote, Some(cookie))
                    .unwrap()
            );
            let (id, n) = a
                .connect_fast_open_with_server_cookie(
                    0,
                    local,
                    remote,
                    &[7; 1600],
                    options,
                    Some(cookie),
                )
                .unwrap();
            assert_eq!(n, 496);
            assert!(!a.transport_info(id).unwrap().syn_data_acked);
            let syn = packet(&mut a, 0);
            let decoded = wire::parse(syn.0, &syn.1).unwrap();
            assert_eq!(decoded.options.fast_open, Some(cookie));
            assert_eq!(decoded.payload, &[7; 1600][..n]);
            assert_eq!(a.acknowledged(id).unwrap(), 0);
            // A validated reply without a cookie still teaches peer MSS.
            deliver(&mut a, 10, &cache_reply(&syn, 940, None));
            assert_eq!(a.acknowledged(id).unwrap(), n as u64);
            assert!(a.transport_info(id).unwrap().syn_data_acked);
            packet(&mut a, 10);
            assert!(!a.has_fast_open_cookie(10, local.ip(), remote.ip()).unwrap());
            let (mut next, _) = addresses(v6, 49001);
            let (_, n) = a
                .connect_fast_open_with_server_cookie(
                    20,
                    next,
                    remote,
                    &[8; 1600],
                    options,
                    Some(cookie),
                )
                .unwrap();
            assert_eq!(n, 900);
            let syn = packet(&mut a, 20);
            assert_eq!(wire::parse(syn.0, &syn.1).unwrap().payload, &[8; 900]);
            // MSS alone is not early-send authorization on the default API.
            next.set_port(49002);
            assert_eq!(
                a.connect_fast_open(20, next, remote, b"no agreement")
                    .unwrap()
                    .1,
                0
            );
            let syn = packet(&mut a, 20);
            assert!(wire::parse(syn.0, &syn.1).unwrap().payload.is_empty());
        }
    }
}

#[test]
fn cold_admission_modes_complete_stream_and_use_learned_mss() {
    for v6 in [false, true] {
        for reserved in [false, true] {
            for mode in 0..5 {
                let (mut a, options) = client();
                let (local, remote) = addresses(v6, 49600);
                let mut cfg = EndpointConfig::default();
                cfg.connection.mss = 940;
                cfg.connection.nagle = false;
                let mut b = Endpoint::new(cfg, [2; 32], 0, |_| true).unwrap();
                b.enable_fast_open().unwrap();
                let listener = b.listen(remote, 8).unwrap();
                b.set_listener_fast_open(listener, 4).unwrap();
                b.set_listener_fast_open_early_data_policy(
                    listener,
                    FastOpenEarlyDataPolicy::ApplicationProtected,
                )
                .unwrap();
                if reserved {
                    a.enable_output_reservations().unwrap();
                }
                let cookie = match mode {
                    1 => Some(wire::FastOpenCookie::request()),
                    2 => Some(wire::FastOpenCookie::new(&[7; 4]).unwrap()),
                    3 => Some(wire::FastOpenCookie::new(&[8; 16]).unwrap()),
                    _ => None,
                };
                let data: Vec<u8> = (0..1600).map(|i| (i % 251) as u8).collect();
                let open = |a: &mut Endpoint, now, local| {
                    if mode == 4 {
                        a.connect_fast_open_with_policy(
                            now,
                            local,
                            remote,
                            &data,
                            options,
                            FastOpenClientPolicy::ApplicationProtected,
                        )
                    } else {
                        a.connect_fast_open_with_server_cookie(
                            now, local, remote, &data, options, cookie,
                        )
                    }
                };
                let (id, n) = open(&mut a, 0, local).unwrap();
                assert_eq!(n, if mode == 0 { 0 } else { 496 });
                let syn = emit(&mut a, 0, id, reserved);
                let parsed = wire::parse(syn.0, &syn.1).unwrap();
                assert_eq!(parsed.payload, &data[..n]);
                assert_eq!(
                    parsed.options.fast_open,
                    if mode == 0 {
                        Some(wire::FastOpenCookie::request())
                    } else {
                        cookie
                    }
                );
                assert!(parsed.raw_options.len() <= 40);
                deliver(&mut b, 1, &syn);
                let child = b.accept(listener).unwrap();
                deliver(&mut a, 3, &packet(&mut b, 2));
                deliver(&mut b, 4, &emit(&mut a, 3, id, reserved));
                assert_eq!(a.acknowledged(id), Ok(n as u64));
                a.write(id, &data[n..]).unwrap();
                let mut received = vec![0; 1600];
                let mut used = b.read(child, &mut received).unwrap_or(0);
                for step in 0..16 {
                    let now = 10 + step * 250_000;
                    a.on_timeout(now, 64).unwrap();
                    b.on_timeout(now, 64).unwrap();
                    for _ in 0..4 {
                        let mut bytes = [0; 2048];
                        if reserved {
                            let (out, token) = a
                                .poll_reserved_transmit_for(now, id, &mut bytes, 64)
                                .unwrap();
                            if let Some(tx) = out.packet {
                                a.accept_transmit(now, token.unwrap()).unwrap();
                                b.input(now, tx.ip, &bytes[..tx.len]).unwrap();
                            }
                        } else if let Some(tx) =
                            a.poll_transmit(now, &mut bytes, 64).unwrap().packet
                        {
                            b.input(now, tx.ip, &bytes[..tx.len]).unwrap();
                        }
                        if let Some(tx) = b.poll_transmit(now, &mut bytes, 64).unwrap().packet {
                            a.input(now, tx.ip, &bytes[..tx.len]).unwrap();
                        }
                    }
                    used += b.read(child, &mut received[used..]).unwrap_or(0);
                    if used == data.len() && a.acknowledged(id).unwrap() == 1600 {
                        break;
                    }
                }
                assert_eq!(used, 1600);
                assert_eq!(received, data);
                assert_eq!(a.acknowledged(id), Ok(1600));
                let (next_local, _) = addresses(v6, 49601);
                let (next, n) = open(&mut a, 4_000_010, next_local).unwrap();
                assert_eq!(n, if mode == 0 { 0 } else { 900 });
                let syn = emit(&mut a, 4_000_010, next, reserved);
                assert_eq!(wire::parse(syn.0, &syn.1).unwrap().payload, &data[..n]);
            }
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.3
//= type=test
//= reason=Cold SYN admission uses a conservative 536-byte ceiling in both families before option, configuration, path and storage limits; true peer defaults remain 536/1220 and validated learned MSS remains usable.
//# Without a cached server MSS, the amount of data in the SYN packet is limited to the default MSS of 536 bytes for IPv4 [RFC1122] and 1220 bytes for IPv6 [RFC2460].
//= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
//= type=test
//= reason=The cookie-required branch serializes the selected server cookie and limits SYN data to validated learned MSS or a conservative cold 536 bytes in both families before the full option reserve and other bounds. Explicit ApplicationProtected uses section 7.3 authorization separately. Erratum 8015 remains Held for Document Update and is not needed for this bound.
//# Otherwise, include the Fast Open option with the cookie of the server. Include any data up to the cached server MSS or default 536 bytes.
#[test]
fn absent_synack_mss_keeps_cookie_supplied_and_protected_admission_cold() {
    for v6 in [false, true] {
        for reserved in [false, true] {
            for mode in 0..3 {
                let (mut a, options) = client();
                let (_, remote) = addresses(v6, 49800);
                let mut cfg = EndpointConfig::default();
                cfg.connection.mss = 940;
                cfg.connection.timestamps = false;
                cfg.connection.nagle = false;
                let mut b = Endpoint::new(cfg, [2; 32], 0, |_| true).unwrap();
                b.enable_fast_open().unwrap();
                let listener = b.listen(remote, 8).unwrap();
                b.set_listener_fast_open(listener, 4).unwrap();
                if mode != 0 {
                    b.set_listener_fast_open_early_data_policy(
                        listener,
                        FastOpenEarlyDataPolicy::ApplicationProtected,
                    )
                    .unwrap();
                }
                if reserved {
                    a.enable_output_reservations().unwrap();
                }
                let data: Vec<u8> = (0..1600).map(|i| (i % 251) as u8).collect();
                for round in 0..3 {
                    let now = round * 4_000_000;
                    let (local, _) = addresses(v6, 49800 + round as u16);
                    let (id, n) = match mode {
                        0 => a.connect_fast_open(now, local, remote, &data),
                        1 => a.connect_fast_open_with_server_cookie(
                            now,
                            local,
                            remote,
                            &data,
                            options,
                            Some(wire::FastOpenCookie::new(&[7; 16]).unwrap()),
                        ),
                        _ => a.connect_fast_open_with_policy(
                            now,
                            local,
                            remote,
                            &data,
                            options,
                            FastOpenClientPolicy::ApplicationProtected,
                        ),
                    }
                    .unwrap();
                    assert_eq!(
                        n,
                        if mode == 0 && round == 0 {
                            0
                        } else if round < 2 {
                            496
                        } else {
                            900
                        }
                    );
                    let syn = emit(&mut a, now, id, reserved);
                    let parsed = wire::parse(syn.0, &syn.1).unwrap();
                    assert_eq!(parsed.payload, &data[..n]);
                    assert_eq!(parsed.options.fast_open.is_some(), mode != 2);
                    deliver(&mut b, now + 1, &syn);
                    let mut reply = packet(&mut b, now + 2);
                    if round == 0 {
                        // Remove the advertised MSS without changing DataOffset or
                        // any other option; ingress must still validate the checksum.
                        assert_eq!(&reply.1[20..22], &[2, 4]);
                        reply.1[20..24].fill(1);
                        repair_cache_checksum(reply.0, &mut reply.1);
                    }
                    assert_eq!(
                        wire::parse(reply.0, &reply.1).unwrap().options.mss,
                        if round == 0 { None } else { Some(940) }
                    );
                    deliver(&mut a, now + 3, &reply);
                    assert_eq!(a.state(id), Ok(State::Established));
                    deliver(&mut b, now + 4, &emit(&mut a, now + 3, id, reserved));
                    let child = b.accept(listener).unwrap();
                    assert_eq!(a.acknowledged(id), Ok(n as u64));
                    a.write(id, &data[n..]).unwrap();
                    let stream = emit(&mut a, now + 5, id, reserved);
                    if v6 && round == 0 {
                        // Ordinary IPv6 sends retain the true 1220-byte default.
                        assert!(wire::parse(stream.0, &stream.1).unwrap().payload.len() > 496);
                    }
                    deliver(&mut b, now + 5, &stream);
                    let mut received = vec![0; data.len()];
                    let mut used = b.read(child, &mut received).unwrap_or(0);
                    for step in 0..16 {
                        let tick = now + 10 + step * 200_000;
                        a.on_timeout(tick, 64).unwrap();
                        b.on_timeout(tick, 64).unwrap();
                        for _ in 0..4 {
                            let mut bytes = [0; 2048];
                            if reserved {
                                let (out, token) = a
                                    .poll_reserved_transmit_for(tick, id, &mut bytes, 64)
                                    .unwrap();
                                if let Some(tx) = out.packet {
                                    a.accept_transmit(tick, token.unwrap()).unwrap();
                                    b.input(tick, tx.ip, &bytes[..tx.len]).unwrap();
                                }
                            } else if let Some(tx) =
                                a.poll_transmit(tick, &mut bytes, 64).unwrap().packet
                            {
                                b.input(tick, tx.ip, &bytes[..tx.len]).unwrap();
                            }
                            if let Some(tx) = b.poll_transmit(tick, &mut bytes, 64).unwrap().packet
                            {
                                a.input(tick, tx.ip, &bytes[..tx.len]).unwrap();
                            }
                        }
                        used += b.read(child, &mut received[used..]).unwrap_or(0);
                        if used == data.len() && a.acknowledged(id).unwrap() == data.len() as u64 {
                            break;
                        }
                    }
                    assert_eq!(received, data);
                    assert_eq!(used, data.len());
                    assert_eq!(a.acknowledged(id), Ok(data.len() as u64));
                }
            }
        }
    }
}

#[test]
fn cold_and_learned_admission_obey_independent_resource_and_path_bounds() {
    for v6 in [false, true] {
        for reserved in [false, true] {
            for protected in [false, true] {
                for (mss, user_mss, path, capacity, expected) in [
                    (360, None, 1500, 8192, 320),
                    (1460, Some(100), 1500, 8192, 60),
                    (1460, None, 300, 8192, 240),
                    (1460, None, 1500, 31, 31),
                    (1460, Some(20), 1500, 8192, 0),
                ] {
                    let mut cfg = EndpointConfig::default();
                    cfg.connection.mss = mss;
                    cfg.connection.timestamps = false;
                    cfg.connection.send_ip_payload_limit = path;
                    let options = ActiveOpenOptions {
                        user_mss,
                        send_capacity: capacity,
                        ..ActiveOpenOptions::from(&cfg.connection)
                    };
                    let mut a = Endpoint::new(cfg, [1; 32], 0, |_| true).unwrap();
                    a.enable_fast_open().unwrap();
                    if reserved {
                        a.enable_output_reservations().unwrap();
                    }
                    let (local, remote) = addresses(v6, 49700);
                    for learned in [false, true] {
                        let mut local = local;
                        local.set_port(if learned { 49701 } else { 49700 });
                        let (id, n) = if protected {
                            a.connect_fast_open_with_policy(
                                u64::from(learned) * 20,
                                local,
                                remote,
                                &[7; 1600],
                                options,
                                FastOpenClientPolicy::ApplicationProtected,
                            )
                        } else {
                            a.connect_fast_open_with_server_cookie(
                                u64::from(learned) * 20,
                                local,
                                remote,
                                &[7; 1600],
                                options,
                                Some(wire::FastOpenCookie::new(&[7; 16]).unwrap()),
                            )
                        }
                        .unwrap();
                        assert_eq!(n, expected);
                        let now = u64::from(learned) * 20;
                        let syn = emit(&mut a, now, id, reserved);
                        assert_eq!(wire::parse(syn.0, &syn.1).unwrap().payload.len(), expected);
                        deliver(&mut a, now + 1, &cache_reply(&syn, 940, None));
                        emit(&mut a, now + 1, id, reserved);
                    }
                }
            }
        }
    }
}

#[test]
fn supplied_cookie_user_mss_capacity_and_invalid_options_are_transactional() {
    for v6 in [false, true] {
        let (mut a, defaults) = client();
        let (local, remote) = addresses(v6, 49100);
        let zero = wire::FastOpenCookie::request();
        let charge = a.buffer_bytes();
        let invalid = ActiveOpenOptions {
            user_mss: Some(0),
            ..defaults
        };
        assert_eq!(
            a.connect_fast_open_with_server_cookie(20, local, remote, b"x", invalid, Some(zero)),
            Err(EndpointError::Connection(Error::InvalidArgument))
        );
        assert_eq!(a.buffer_bytes(), charge);
        assert!(a.connection_id(Tuple { local, remote }).is_none());
        let constrained = ActiveOpenOptions {
            user_mss: Some(100),
            send_capacity: 31,
            ..defaults
        };
        let (_, n) = a
            .connect_fast_open_with_server_cookie(
                0,
                local,
                remote,
                &[1; 1000],
                constrained,
                Some(zero),
            )
            .unwrap();
        assert_eq!(n, 31);
        let syn = packet(&mut a, 0);
        assert_eq!(wire::parse(syn.0, &syn.1).unwrap().payload.len(), 31);
    }
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
//= type=test
//= reason=Supplied cookies use the existing first-SYN-only data/option selection; actual timer retry drops both and preserves service failure evidence.
//# To deal with network or servers dropping SYN packets with payload or unknown options, when the SYN timer fires, the client SHOULD retransmit a SYN packet without data and Fast Open options.
#[test]
fn supplied_cookie_timeout_retries_without_option_or_data_and_keeps_negative_cache() {
    for v6 in [false, true] {
        let (mut a, options) = client();
        let (local, remote) = addresses(v6, 49200);
        let zero = wire::FastOpenCookie::request();
        let (id, n) = a
            .connect_fast_open_with_server_cookie(0, local, remote, b"hello", options, Some(zero))
            .unwrap();
        assert_eq!(n, 5);
        let syn = packet(&mut a, 0);
        assert_eq!(wire::parse(syn.0, &syn.1).unwrap().payload, b"hello");
        a.on_timeout(1_000_000, 64).unwrap();
        let retry = packet(&mut a, 1_000_000);
        let parsed = wire::parse(retry.0, &retry.1).unwrap();
        assert!(parsed.payload.is_empty());
        assert_eq!(parsed.options.fast_open, None);
        assert!(
            !a.can_defer_fast_open_with_server_cookie(1_000_000, local.ip(), remote, Some(zero))
                .unwrap()
        );
        deliver(&mut a, 1_000_010, &cache_reply(&retry, 1460, None));
        assert!(!a.transport_info(id).unwrap().syn_data_acked);
        let repair = packet(&mut a, 1_000_010);
        assert_eq!(wire::parse(repair.0, &repair.1).unwrap().payload, b"hello");
        let (next, _) = addresses(v6, 49201);
        assert_eq!(
            a.connect_fast_open_with_server_cookie(
                1_000_020,
                next,
                remote,
                b"later",
                options,
                Some(zero)
            )
            .unwrap()
            .1,
            0
        );
        let ordinary = packet(&mut a, 1_000_020);
        let parsed = wire::parse(ordinary.0, &ordinary.1).unwrap();
        assert_eq!(parsed.options.fast_open, None);
        assert!(parsed.payload.is_empty());
        assert!(
            a.can_defer_fast_open_with_server_cookie(61_000_000, local.ip(), remote, Some(zero))
                .unwrap()
        );
    }
}

#[test]
fn supplied_cookie_reserved_output_reject_and_commit_preserve_truthful_progress() {
    for abandon in [false, true] {
        let (mut a, options) = client();
        a.enable_output_reservations().unwrap();
        let (local, remote) = addresses(false, 49300);
        let (id, n) = a
            .connect_fast_open_with_server_cookie(
                0,
                local,
                remote,
                b"hello",
                options,
                Some(wire::FastOpenCookie::request()),
            )
            .unwrap();
        assert_eq!(n, 5);
        let mut bytes = [0; 2048];
        let (output, attempt) = a.poll_reserved_transmit_for(0, id, &mut bytes, 64).unwrap();
        let tx = output.packet.unwrap();
        let attempt = attempt.unwrap();
        let syn = (tx.ip, bytes[..tx.len].to_vec());
        assert_eq!(wire::parse(syn.0, &syn.1).unwrap().payload, b"hello");
        assert_eq!(a.acknowledged(id).unwrap(), 0);
        assert!(!a.transport_info(id).unwrap().syn_data_acked);
        if abandon {
            a.abandon_transmit(attempt).unwrap();
            assert!(!a.accept_transmit(0, attempt).unwrap());
            assert!(!a.transport_info(id).unwrap().syn_data_acked);
        } else {
            a.reject_unsubmitted(attempt).unwrap();
            let (output, retry) = a.poll_reserved_transmit_for(0, id, &mut bytes, 64).unwrap();
            let tx = output.packet.unwrap();
            let retried = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
            let selected = wire::parse(syn.0, &syn.1).unwrap();
            assert_eq!(retried.header.sequence, selected.header.sequence);
            assert_eq!(retried.header.flags, selected.header.flags);
            assert_eq!(retried.options.fast_open, selected.options.fast_open);
            assert_eq!(retried.options.mss, selected.options.mss);
            assert_eq!(retried.payload, selected.payload);
            a.accept_transmit(0, retry.unwrap()).unwrap();
            deliver(&mut a, 10, &cache_reply(&syn, 1460, None));
            assert_eq!(a.acknowledged(id).unwrap(), 5);
            assert!(a.transport_info(id).unwrap().syn_data_acked);
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-7.3
//= type=test
//= reason=Only an explicit server-provided/agreed zero cookie is admitted through the supplied-cookie API; default misses still request a cookie. The protected server and client opt in independently.
//# For such applications the server may choose to generate a trivial or even a zero-length cookie to improve performance by avoiding the cookie generation and verification.
#[test]
fn supplied_zero_cookie_interoperates_with_protected_server_and_delivers_once() {
    for v6 in [false, true] {
        let (mut a, options) = client();
        let (local, remote) = addresses(v6, 49400);
        let mut b = endpoint(2, v6);
        b.enable_fast_open().unwrap();
        let listener = b.listen(remote, 8).unwrap();
        b.set_listener_fast_open(listener, 1).unwrap();
        b.set_listener_fast_open_early_data_policy(
            listener,
            FastOpenEarlyDataPolicy::ApplicationProtected,
        )
        .unwrap();
        let (id, n) = a
            .connect_fast_open_with_server_cookie(
                0,
                local,
                remote,
                b"request",
                options,
                Some(wire::FastOpenCookie::request()),
            )
            .unwrap();
        assert_eq!(n, 7);
        let syn = packet(&mut a, 0);
        deliver(&mut b, 10, &syn);
        let child = b.accept(listener).unwrap();
        assert_eq!(b.state(child), Ok(State::SynReceived));
        let mut bytes = [0; 32];
        assert_eq!(b.read(child, &mut bytes), Ok(7));
        assert_eq!(&bytes[..7], b"request");
        deliver(&mut b, 10, &syn);
        assert_eq!(b.readable_bytes(child), Ok(0));
        let response = packet(&mut b, 20);
        deliver(&mut a, 30, &response);
        assert_eq!(a.acknowledged(id).unwrap(), 7);
        deliver(&mut b, 40, &packet(&mut a, 30));
        assert_eq!(b.state(child), Ok(State::Established));
    }
}

#[test]
fn actual_server_cookie_can_be_transferred_to_a_cold_client_context() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6, 49500);
        let mut bootstrap = endpoint(1, v6);
        let mut b = endpoint(2, v6);
        bootstrap.enable_fast_open().unwrap();
        b.enable_fast_open().unwrap();
        let listener = b.listen(remote, 8).unwrap();
        b.set_listener_fast_open(listener, 4).unwrap();
        bootstrap.connect_fast_open(0, local, remote, &[]).unwrap();
        deliver(&mut b, 10, &packet(&mut bootstrap, 0));
        let response = packet(&mut b, 20);
        let obtained = wire::parse(response.0, &response.1)
            .unwrap()
            .options
            .fast_open
            .unwrap();
        assert!(!obtained.as_bytes().is_empty());
        deliver(&mut bootstrap, 30, &response);
        deliver(&mut b, 40, &packet(&mut bootstrap, 30));
        b.accept(listener).unwrap();
        let (mut a, options) = client();
        let (local, _) = addresses(v6, 49501);
        let (_, accepted) = a
            .connect_fast_open_with_server_cookie(
                0,
                local,
                remote,
                &[3; 1600],
                options,
                Some(obtained),
            )
            .unwrap();
        assert_eq!(accepted, 496);
        let syn = packet(&mut a, 0);
        assert_eq!(
            wire::parse(syn.0, &syn.1).unwrap().options.fast_open,
            Some(obtained)
        );
        deliver(&mut b, 50, &syn);
        let child = b.accept(listener).unwrap();
        let mut received = [0; 1600];
        assert_eq!(b.read(child, &mut received), Ok(accepted));
        assert_eq!(&received[..accepted], &[3; 1600][..accepted]);
    }
}
