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
//= reason=Cold supplied-cookie admission uses the address-family peer MSS default before applying configuration, path, option and storage limits.
//# Without a cached server MSS, the amount of data in the SYN packet is limited to the default MSS of 536 bytes for IPv4 [RFC1122] and 1220 bytes for IPv6 [RFC2460].
//= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
//= type=test
//= reason=Early-send credentials remain serialized in a kind34 option; output selects SYN data only when the option fits, and admission applies known-peer or conservative default MSS.
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
            assert_eq!(n, if v6 { 1180 } else { 496 });
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
        assert_eq!(accepted, if v6 { 1180 } else { 496 });
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
