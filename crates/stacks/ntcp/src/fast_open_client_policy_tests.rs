use super::*;

fn client(v6: bool) -> Endpoint {
    let cfg = EndpointConfig {
        max_connections: 16,
        connection: ConnectionConfig {
            mss: 1460,
            timestamps: false,
            send_capacity: 8192,
            receive_capacity: 8192,
            send_ip_payload_limit: if v6 { 1500 } else { 1480 },
            ..ConnectionConfig::default()
        },
        ..EndpointConfig::default()
    };
    let mut a = Endpoint::new(cfg, [1; 32], 0, |_| true).unwrap();
    a.enable_fast_open().unwrap();
    a
}
fn options(user_mss: Option<u16>) -> ActiveOpenOptions {
    ActiveOpenOptions {
        send_capacity: 8192,
        receive_capacity: 8192,
        user_mss,
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7413#section-7.3
//= type=test
//= reason=Explicit protected-service client policy sends an option-free SYN with actual bounded data; required-cookie default and explicitly agreed zero-cookie exchange remain distinct in both families. This tests a deliberate omitted-option alternative, not ordinary section4.2 credential acquisition.
//# cookies are not necessary if the server has application-level protection or is immune to these attacks.
fn explicit_client_policy_separates_wire_option_and_cold_mss() {
    for v6 in [false, true] {
        for mode in 0..3 {
            for user_mss in [None, Some(512)] {
                for bytes in [0, 1000, 5000] {
                    let mut a = client(v6);
                    let (local, remote) = addresses(v6, 40000);
                    let (id, n) = if mode == 2 {
                        a.connect_fast_open_with_server_cookie(
                            0,
                            local,
                            remote,
                            &vec![7; bytes],
                            options(user_mss),
                            Some(wire::FastOpenCookie::request()),
                        )
                    } else {
                        a.connect_fast_open_with_policy(
                            0,
                            local,
                            remote,
                            &vec![7; bytes],
                            options(user_mss),
                            if mode == 1 {
                                FastOpenClientPolicy::ApplicationProtected
                            } else {
                                FastOpenClientPolicy::RequireCookie
                            },
                        )
                    }
                    .unwrap();
                    let bound = usize::from(user_mss.unwrap_or(if v6 { 1220 } else { 536 }))
                        .saturating_sub(40);
                    assert_eq!(n, if mode == 0 { 0 } else { bytes.min(bound) });
                    let syn = packet(&mut a, 0);
                    let syn = wire::parse(syn.0, &syn.1).unwrap();
                    assert_eq!(syn.payload, &vec![7; n]);
                    assert_eq!(syn.options.fast_open.is_some(), mode != 1);
                    assert!(!a.transport_info(id).unwrap().syn_data_acked);
                }
            }
        }
    }
}

#[test]
fn optionless_handshake_learns_mss_without_unsolicited_credentials() {
    for v6 in [false, true] {
        let mut a = client(v6);
        let (_, remote) = addresses(v6, 40000);
        for (index, mss, expected) in [
            (0, 940, if v6 { 1000 } else { 496 }),
            (1, 1460, 900),
            (2, 1460, 1000),
        ] {
            let (local, _) = addresses(v6, 40000 + index);
            let (id, n) = a
                .connect_fast_open_with_policy(
                    index as u64 * 10,
                    local,
                    remote,
                    &[7; 1000],
                    options(None),
                    FastOpenClientPolicy::ApplicationProtected,
                )
                .unwrap();
            assert_eq!(n, expected);
            let syn = packet(&mut a, index as u64 * 10);
            assert!(
                wire::parse(syn.0, &syn.1)
                    .unwrap()
                    .options
                    .fast_open
                    .is_none()
            );
            // A real, validated SYNACK carries an unsolicited opaque cookie.
            deliver(
                &mut a,
                index as u64 * 10 + 1,
                &cache_reply(&syn, mss, Some(&[1, 2, 3, 4])),
            );
            assert!(a.transport_info(id).unwrap().syn_data_acked);
            packet(&mut a, index as u64 * 10 + 1);
            assert!(
                !a.has_fast_open_cookie(index as u64 * 10 + 1, local.ip(), remote.ip())
                    .unwrap()
            );
        }
        let (local, _) = addresses(v6, 40010);
        let (_, n) = a
            .connect_fast_open_with_policy(
                30,
                local,
                remote,
                &[7; 1000],
                options(None),
                FastOpenClientPolicy::RequireCookie,
            )
            .unwrap();
        assert_eq!(n, 0);
        let syn = packet(&mut a, 30);
        assert_eq!(
            wire::parse(syn.0, &syn.1).unwrap().options.fast_open,
            Some(wire::FastOpenCookie::request())
        );
        deliver(&mut a, 31, &cache_reply(&syn, 1460, Some(&[5, 5, 5, 5])));
        packet(&mut a, 31);
        let (local, _) = addresses(v6, 40011);
        a.connect_fast_open_with_policy(
            40,
            local,
            remote,
            &[7; 1000],
            options(None),
            FastOpenClientPolicy::ApplicationProtected,
        )
        .unwrap();
        let syn = packet(&mut a, 40);
        deliver(&mut a, 41, &cache_reply(&syn, 940, Some(&[9, 9, 9, 9])));
        packet(&mut a, 41);
        let (local, _) = addresses(v6, 40012);
        let (_, n) = a.connect_fast_open(50, local, remote, &[7; 1000]).unwrap();
        assert_eq!(n, 900);
        let syn = packet(&mut a, 50);
        assert_eq!(
            wire::parse(syn.0, &syn.1).unwrap().options.fast_open,
            Some(wire::FastOpenCookie::new(&[5; 4]).unwrap())
        );
    }
}

#[test]
fn protected_client_timeout_retries_plain_and_preserves_negative_service() {
    for v6 in [false, true] {
        for empty in [false, true] {
            let mut a = client(v6);
            let (local, remote) = addresses(v6, 40000);
            let data: &[u8] = if empty { &[] } else { &[7; 1000] };
            let (_, n) = a
                .connect_fast_open_with_policy(
                    0,
                    local,
                    remote,
                    data,
                    options(None),
                    FastOpenClientPolicy::ApplicationProtected,
                )
                .unwrap();
            assert_eq!(n != 0, !empty);
            let first = packet(&mut a, 0);
            let first = wire::parse(first.0, &first.1).unwrap();
            let deadline = a.next_deadline().unwrap();
            a.on_timeout(deadline, 64).unwrap();
            let retry = packet(&mut a, deadline);
            let retry = wire::parse(retry.0, &retry.1).unwrap();
            assert_eq!(retry.header.sequence, first.header.sequence);
            assert!(retry.payload.is_empty() && retry.options.fast_open.is_none());
            let (local, _) = addresses(v6, 40001);
            let allowed = a
                .can_defer_fast_open_with_policy(
                    deadline,
                    local.ip(),
                    remote,
                    FastOpenClientPolicy::ApplicationProtected,
                )
                .unwrap();
            assert_eq!(allowed, empty); // A plain empty SYN was no early-data attempt.
            let (_, n) = a
                .connect_fast_open_with_policy(
                    deadline,
                    local,
                    remote,
                    &[7; 1000],
                    options(None),
                    FastOpenClientPolicy::ApplicationProtected,
                )
                .unwrap();
            assert_eq!(n != 0, empty);
            let (local, _) = addresses(v6, 40002);
            assert!(
                a.can_defer_fast_open_with_policy(
                    deadline,
                    local.ip(),
                    SocketAddr::new(remote.ip(), 8081),
                    FastOpenClientPolicy::ApplicationProtected
                )
                .unwrap()
            );
        }
    }
}

#[test]
fn protected_client_reserved_syn_and_real_server_deliver_once() {
    for v6 in [false, true] {
        for reserved in [false, true] {
            let mut a = client(v6);
            let (local, remote) = addresses(v6, 40000);
            let mut b = client(v6);
            let listener = b.listen(remote, 8).unwrap();
            b.set_listener_fast_open(listener, 2).unwrap();
            b.set_listener_fast_open_early_data_policy(
                listener,
                FastOpenEarlyDataPolicy::ApplicationProtected,
            )
            .unwrap();
            if reserved {
                a.enable_output_reservations().unwrap();
            }
            let (cid, n) = a
                .connect_fast_open_with_policy(
                    0,
                    local,
                    remote,
                    &[7; 1000],
                    options(None),
                    FastOpenClientPolicy::ApplicationProtected,
                )
                .unwrap();
            let syn = if reserved {
                let mut bytes = [0; 2048];
                let (out, attempt) = a.poll_reserved_transmit(0, &mut bytes, 64).unwrap();
                let tx = out.packet.unwrap();
                assert!(!a.transport_info(cid).unwrap().syn_data_acked);
                let first = bytes[..tx.len].to_vec();
                // Retained SYN payload/sequence/options survive header re-encoding.
                assert!(a.reject_unsubmitted(attempt.unwrap()).unwrap());
                let (again, token) = a.poll_reserved_transmit(1, &mut bytes, 64).unwrap();
                let again = again.packet.unwrap();
                let replay = bytes[..again.len].to_vec();
                let initial = wire::parse(tx.ip, &first).unwrap();
                let repeated = wire::parse(again.ip, &replay).unwrap();
                assert_eq!(initial.header, repeated.header);
                assert_eq!(initial.payload, repeated.payload);
                assert_eq!(initial.options.mss, repeated.options.mss);
                assert_eq!(initial.options.window_scale, repeated.options.window_scale);
                assert!(repeated.options.fast_open.is_none());
                a.accept_transmit(1, token.unwrap()).unwrap();
                (again.ip, replay)
            } else {
                packet(&mut a, 0)
            };
            deliver(&mut b, 10, &syn);
            let child = b.accept(listener).unwrap();
            assert_eq!(b.readable_bytes(child).unwrap(), n);
            deliver(&mut b, 11, &syn);
            assert_eq!(b.readable_bytes(child).unwrap(), n);
            let reply = packet(&mut b, 20);
            deliver(&mut a, 30, &reply);
            assert!(a.transport_info(cid).unwrap().syn_data_acked);
            let ack = packet(&mut a, 30);
            deliver(&mut b, 40, &ack);
            let mut received = [0; 2048];
            assert_eq!(b.read(child, &mut received).unwrap(), n);
            assert_eq!(&received[..n], &[7; 1000][..n]);
            assert!(!a.has_fast_open_cookie(30, local.ip(), remote.ip()).unwrap());
            assert_eq!(a.transport_info(cid).unwrap().send_used, 0);
        }
    }
}

#[test]
fn optionless_syn_only_ack_keeps_failure_separate_from_learned_mss() {
    for v6 in [false, true] {
        let mut a = client(v6);
        let (local, remote) = addresses(v6, 40000);
        let (id, n) = a
            .connect_fast_open_with_policy(
                0,
                local,
                remote,
                &[7; 1000],
                options(None),
                FastOpenClientPolicy::ApplicationProtected,
            )
            .unwrap();
        assert!(n != 0);
        let syn = packet(&mut a, 0);
        let original = wire::parse(syn.0, &syn.1).unwrap();
        let reply = cache_reply(&syn, 940, Some(&[8; 4]));
        let parsed = wire::parse(reply.0, &reply.1).unwrap();
        let mut header = parsed.header;
        header.acknowledgment = original.header.sequence.wrapping_add(1);
        let mut bytes = [0; 2048];
        let len = wire::encode(
            reply.0,
            header,
            parsed.raw_options,
            parsed.payload,
            &mut bytes,
        )
        .unwrap();
        deliver(&mut a, 10, &(reply.0, bytes[..len].to_vec()));
        assert!(!a.transport_info(id).unwrap().syn_data_acked);
        assert!(!a.has_fast_open_cookie(10, local.ip(), remote.ip()).unwrap());
        let (other, _) = addresses(v6, 40001);
        assert!(
            !a.can_defer_fast_open_with_policy(
                10,
                other.ip(),
                remote,
                FastOpenClientPolicy::ApplicationProtected
            )
            .unwrap()
        );
        let target = SocketAddr::new(remote.ip(), 8081);
        let (_, count) = a
            .connect_fast_open_with_policy(
                10,
                other,
                target,
                &[7; 1000],
                options(None),
                FastOpenClientPolicy::ApplicationProtected,
            )
            .unwrap();
        assert_eq!(count, 900); // Valid MSS shared by IP pair, suppression by service.
    }
}
