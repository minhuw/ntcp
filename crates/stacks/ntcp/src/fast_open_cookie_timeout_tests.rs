use super::*;

fn cold(scale: u64, reserved: bool) -> Endpoint {
    let cfg = EndpointConfig {
        max_connections: 16,
        connection: ConnectionConfig {
            mss: 1460,
            timestamps: false,
            initial_window: InitialWindow::Iw10,
            timebase: CallerTimebase {
                units_per_second: 1_000_000 * scale,
                ..CallerTimebase::default()
            },
            ..ConnectionConfig::default()
        },
        ..EndpointConfig::default()
    };
    let mut endpoint = Endpoint::new(cfg, [1; 32], 0, |_| true).unwrap();
    endpoint.enable_fast_open().unwrap();
    if reserved {
        endpoint.enable_output_reservations().unwrap();
    }
    endpoint
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.1
//= type=test
//= reason=The first RTO of a physically transmitted request trains the existing per-source/service cooldown once. Local output failures and held reservations do not train it; successful fallback and late cookie/MSS learning cannot erase it, and expiry permits future requests.
//# We also RECOMMEND the client to record the set of servers that failed to respond to cookie requests and only attempt another cookie request after a certain period.
#[test]
fn cookie_request_first_timeout_success_preserves_cooldown() {
    let initial = [0x55; 10_000];
    for v6 in [false, true] {
        for scale in [1, 1000] {
            for reserved in [false, true] {
                for timeout in [false, true] {
                    for returned_cookie in [false, true] {
                        let mut a = cold(scale, reserved);
                        let (local, remote) = addresses(v6, 40000);
                        let (id, accepted) = a.connect_fast_open(0, local, remote, &[]).unwrap();
                        assert_eq!(accepted, 0);
                        let syn = emit(&mut a, 0, id, reserved);
                        let first = wire::parse(syn.0, &syn.1).unwrap();
                        assert_eq!(
                            first.options.fast_open,
                            Some(wire::FastOpenCookie::request())
                        );
                        assert!(first.payload.is_empty());
                        let deadline = a.next_deadline().unwrap();
                        assert_eq!(deadline, 1_000_000 * scale);
                        let handshake_at = if timeout {
                            a.on_timeout(deadline, 64).unwrap();
                            let retry = emit(&mut a, deadline, id, reserved);
                            let retry = wire::parse(retry.0, &retry.1).unwrap();
                            assert!(retry.options.fast_open.is_none());
                            assert!(retry.payload.is_empty());
                            deadline + 10_000 * scale
                        } else {
                            10_000 * scale
                        };
                        let cookie =
                            returned_cookie.then_some(&[0xaa, 0xaa, 0xbb, 0xbb, 0xcc, 0xcc][..]);
                        deliver(&mut a, handshake_at, &cache_reply(&syn, 1240, cookie));
                        assert_eq!(a.state(id).unwrap(), State::Established);
                        emit(&mut a, handshake_at, id, reserved);
                        let cached = a
                            .has_fast_open_cookie(handshake_at, local.ip(), remote.ip())
                            .unwrap();
                        assert_eq!(cached, returned_cookie);
                        let next_at = handshake_at + 70_000 * scale;
                        let (next_local, _) = addresses(v6, 40001);
                        let (next_id, next_accepted) = a
                            .connect_fast_open(next_at, next_local, remote, &initial)
                            .unwrap();
                        let next = emit(&mut a, next_at, next_id, reserved);
                        let next = wire::parse(next.0, &next.1).unwrap();
                        // A late original reply can teach cookie/MSS, but cannot
                        // erase the independent service failure at the first RTO.
                        assert_eq!(next.options.fast_open.is_some(), !timeout);
                        let learned = if !returned_cookie {
                            0
                        } else if v6 {
                            1180
                        } else {
                            1200
                        };
                        assert_eq!(next_accepted, if timeout { 0 } else { learned });
                        assert_eq!(next.payload.len(), next_accepted);
                        let other_service = SocketAddr::new(remote.ip(), remote.port() + 1);
                        let (other_local, _) = addresses(v6, 40002);
                        let other_at = next_at + scale;
                        let (other_id, other_accepted) = a
                            .connect_fast_open(other_at, other_local, other_service, &initial)
                            .unwrap();
                        let other = emit(&mut a, other_at, other_id, reserved);
                        let other = wire::parse(other.0, &other.1).unwrap();
                        assert!(other.options.fast_open.is_some());
                        assert_eq!(other_accepted, learned);
                        let expiry = deadline + 60_000_000 * scale;
                        let (expired_local, _) = addresses(v6, 40003);
                        let (expired, n) = a
                            .connect_fast_open(expiry, expired_local, remote, &initial)
                            .unwrap();
                        let expired = emit(&mut a, expiry, expired, reserved);
                        assert!(
                            wire::parse(expired.0, &expired.1)
                                .unwrap()
                                .options
                                .fast_open
                                .is_some()
                        );
                        assert_eq!(n, learned);
                    }
                }
            }
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
//= type=test
//= reason=An emitted regular retry followed by a SYN-only acknowledgment without a cookie realizes the loss heuristic and preserves service suppression with ordinary stream progress. Delayed original, spurious, partial and returned-cookie controls keep independent RTO/rejection evidence authoritative. This is a presumption, not proof of intentional physical middlebox loss.
//# If the client has timed out and retransmitted only regular SYN packets, it can heuristically detect paths that intentionally drop SYNs with the Fast Open option or data. If the SYN-ACK acknowledges only the initial sequence and does not carry a Fast Open cookie option, presumably it is triggered by a retransmitted (regular) SYN and the original SYN or the corresponding SYN-ACK was lost.
#[test]
fn cookie_request_fallback_trace_keeps_service_cooldown_and_stream_progress() {
    for v6 in [false, true] {
        for reserved in [false, true] {
            let mut a = cold(1, reserved);
            let mut b = endpoint(2, v6);
            b.enable_fast_open().unwrap();
            let (local, remote) = addresses(v6, 40000);
            let listener = b.listen(remote, 8).unwrap();
            b.set_listener_fast_open(listener, 4).unwrap();
            let (id, _) = a.connect_fast_open(0, local, remote, &[]).unwrap();
            let original = emit(&mut a, 0, id, reserved);
            let initial_seq = wire::parse(original.0, &original.1)
                .unwrap()
                .header
                .sequence;
            let timeout = a.next_deadline().unwrap();
            a.on_timeout(timeout, 64).unwrap();
            let retry = emit(&mut a, timeout, id, reserved);
            let bare = wire::parse(retry.0, &retry.1).unwrap();
            assert_eq!(bare.header.sequence, initial_seq);
            assert!(bare.options.fast_open.is_none() && bare.payload.is_empty());
            // Deliver only the regular SYN. This realizes the full heuristic
            // conjunction without claiming knowledge of a physical middlebox.
            deliver(&mut b, timeout + 1, &retry);
            let reply = packet(&mut b, timeout + 2);
            let synack = wire::parse(reply.0, &reply.1).unwrap();
            assert_eq!(synack.header.acknowledgment, initial_seq.wrapping_add(1));
            assert!(synack.options.fast_open.is_none());
            deliver(&mut a, timeout + 3, &reply);
            deliver(
                &mut b,
                timeout + 4,
                &emit(&mut a, timeout + 3, id, reserved),
            );
            let child = b.accept(listener).unwrap();
            assert_eq!(a.write(id, b"fallback stream"), Ok(15));
            deliver(
                &mut b,
                timeout + 6,
                &emit(&mut a, timeout + 5, id, reserved),
            );
            let mut bytes = [0; 32];
            assert_eq!(b.read(child, &mut bytes), Ok(15));
            assert_eq!(&bytes[..15], b"fallback stream");
            // A delayed original SYN-ACK is now spurious and cannot teach a
            // cookie/MSS or erase/extend the independent cooldown.
            deliver(
                &mut a,
                timeout + 7,
                &cache_reply(&original, 940, Some(&[9; 8])),
            );
            assert!(
                !a.has_fast_open_cookie(timeout + 7, local.ip(), remote.ip())
                    .unwrap()
            );
            for _ in 0..4 {
                let mut bytes = [0; 2048];
                if let Some(tx) = a.poll_transmit(timeout + 7, &mut bytes, 64).unwrap().packet {
                    b.input(timeout + 7, tx.ip, &bytes[..tx.len]).unwrap();
                }
                if let Some(tx) = b.poll_transmit(timeout + 7, &mut bytes, 64).unwrap().packet {
                    a.input(timeout + 7, tx.ip, &bytes[..tx.len]).unwrap();
                }
            }
            let (next_local, _) = addresses(v6, 40001);
            let (next, n) = a
                .connect_fast_open(timeout + 8, next_local, remote, b"ordinary")
                .unwrap();
            assert_eq!(n, 0);
            let ordinary = emit(&mut a, timeout + 8, next, reserved);
            assert!(
                wire::parse(ordinary.0, &ordinary.1)
                    .unwrap()
                    .options
                    .fast_open
                    .is_none()
            );
            deliver(&mut b, timeout + 9, &ordinary);
            deliver(&mut a, timeout + 11, &packet(&mut b, timeout + 10));
            deliver(
                &mut b,
                timeout + 12,
                &emit(&mut a, timeout + 11, next, reserved),
            );
            let child = b.accept(listener).unwrap();
            a.write(next, b"ordinary").unwrap();
            deliver(
                &mut b,
                timeout + 14,
                &emit(&mut a, timeout + 13, next, reserved),
            );
            assert_eq!(b.read(child, &mut bytes), Ok(8));
            assert_eq!(&bytes[..8], b"ordinary");
            let expiry = timeout + 60_000_000;
            let cookie = Some(wire::FastOpenCookie::request());
            assert!(
                !a.can_defer_fast_open_with_server_cookie(expiry - 1, local.ip(), remote, cookie)
                    .unwrap()
            );
            assert!(
                a.can_defer_fast_open_with_server_cookie(expiry, local.ip(), remote, cookie)
                    .unwrap()
            );
        }
    }
    // Controls: full/partial original SYN-data ACKs and returned cookies do
    // not prove a regular retry caused the reply. RTO evidence stays separate;
    // without RTO, only SYN-only rejection trains this service's negative cache.
    for v6 in [false, true] {
        for reserved in [false, true] {
            for timeout in [false, true] {
                for acked in [0, 2, 5] {
                    for returned_cookie in [false, true] {
                        let mut a = cold(1, reserved);
                        let (local, remote) = addresses(v6, 40000);
                        let options = ActiveOpenOptions::from(&ConnectionConfig::default());
                        let (id, n) = a
                            .connect_fast_open_with_server_cookie(
                                0,
                                local,
                                remote,
                                b"hello",
                                options,
                                Some(wire::FastOpenCookie::new(&[7; 8]).unwrap()),
                            )
                            .unwrap();
                        assert_eq!(n, 5);
                        let syn = emit(&mut a, 0, id, reserved);
                        let seq = wire::parse(syn.0, &syn.1).unwrap().header.sequence;
                        let now = if timeout {
                            let deadline = a.next_deadline().unwrap();
                            a.on_timeout(deadline, 64).unwrap();
                            let retry = emit(&mut a, deadline, id, reserved);
                            let retry = wire::parse(retry.0, &retry.1).unwrap();
                            assert!(retry.options.fast_open.is_none() && retry.payload.is_empty());
                            deadline + 1
                        } else {
                            1
                        };
                        let mut reply =
                            cache_reply(&syn, 940, returned_cookie.then_some(&[9; 8][..]));
                        reply.1[8..12].copy_from_slice(&seq.wrapping_add(1 + acked).to_be_bytes());
                        repair_cache_checksum(reply.0, &mut reply.1);
                        deliver(&mut a, now, &reply);
                        assert_eq!(a.state(id), Ok(State::Established));
                        assert_eq!(a.acknowledged(id), Ok(u64::from(acked)));
                        assert_eq!(
                            a.has_fast_open_cookie(now, local.ip(), remote.ip())
                                .unwrap(),
                            returned_cookie
                        );
                        assert_eq!(
                            a.can_defer_fast_open_with_server_cookie(
                                now,
                                local.ip(),
                                remote,
                                Some(wire::FastOpenCookie::request())
                            )
                            .unwrap(),
                            !timeout && acked != 0
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn cookie_request_repeated_timeout_icmp_and_terminal_keep_suppression() {
    for v6 in [false, true] {
        for scale in [1, 1000] {
            for reserved in [false, true] {
                // 0: second RTO, 1: ICMP, 2: retry limit, 3: ICMP after fallback.
                for cause in 0..4 {
                    let mut a = cold(scale, reserved);
                    let (local, remote) = addresses(v6, 40000);
                    let (id, _) = a.connect_fast_open(0, local, remote, &[]).unwrap();
                    if cause == 2 {
                        a.set_handshake_retransmission_limit(id, core::num::NonZeroU8::new(1))
                            .unwrap();
                    }
                    let syn = emit(&mut a, 0, id, reserved);
                    let now = if cause == 1 {
                        let seq = wire::parse(syn.0, &syn.1).unwrap().header.sequence;
                        assert!(
                            a.network_error(
                                scale,
                                Tuple { local, remote },
                                seq,
                                NetworkError::SoftUnreachable
                            )
                            .unwrap()
                        );
                        scale
                    } else {
                        let first = a.next_deadline().unwrap();
                        a.on_timeout(first, 64).unwrap();
                        let retry = emit(&mut a, first, id, reserved);
                        assert!(
                            wire::parse(retry.0, &retry.1)
                                .unwrap()
                                .options
                                .fast_open
                                .is_none()
                        );
                        if cause == 3 {
                            let seq = wire::parse(syn.0, &syn.1).unwrap().header.sequence;
                            assert!(
                                a.network_error(
                                    first + scale,
                                    Tuple { local, remote },
                                    seq,
                                    NetworkError::SoftUnreachable
                                )
                                .unwrap()
                            );
                            first + scale
                        } else {
                            let second = a.next_deadline().unwrap();
                            assert_eq!(second, 3_000_000 * scale);
                            a.on_timeout(second, 64).unwrap();
                            second
                        }
                    };
                    let cookie = &[0xaa, 0xaa, 0xbb, 0xbb, 0xcc, 0xcc];
                    if cause == 2 {
                        assert_eq!(a.state(id).unwrap(), State::Closed);
                        a.release(id).unwrap();
                        // Learn a positive cookie on another service; it must
                        // not erase the original service's independent failure.
                        let other = SocketAddr::new(remote.ip(), remote.port() + 1);
                        let (other_local, _) = addresses(v6, 40001);
                        let (warm, _) = a
                            .connect_fast_open(now + scale, other_local, other, &[])
                            .unwrap();
                        let request = emit(&mut a, now + scale, warm, reserved);
                        assert!(
                            wire::parse(request.0, &request.1)
                                .unwrap()
                                .options
                                .fast_open
                                .is_some()
                        );
                        deliver(
                            &mut a,
                            now + 2 * scale,
                            &cache_reply(&request, 1240, Some(cookie)),
                        );
                        emit(&mut a, now + 2 * scale, warm, reserved);
                    } else {
                        deliver(&mut a, now + scale, &cache_reply(&syn, 1240, Some(cookie)));
                        assert_eq!(a.state(id).unwrap(), State::Established);
                        emit(&mut a, now + scale, id, reserved);
                    }
                    assert!(
                        a.has_fast_open_cookie(now + 3 * scale, local.ip(), remote.ip())
                            .unwrap()
                    );
                    assert!(
                        !a.can_defer_fast_open(now + 3 * scale, local.ip(), remote)
                            .unwrap()
                    );
                    let (next_local, _) = addresses(v6, 40002);
                    let (next, accepted) = a
                        .connect_fast_open(now + 3 * scale, next_local, remote, &[0x55; 10000])
                        .unwrap();
                    assert_eq!(accepted, 0);
                    let next = emit(&mut a, now + 3 * scale, next, reserved);
                    let next = wire::parse(next.0, &next.1).unwrap();
                    assert!(next.options.fast_open.is_none());
                    assert!(next.payload.is_empty());
                }
            }
        }
    }
}

#[test]
fn cookie_request_local_output_failures_do_not_train_service() {
    for v6 in [false, true] {
        for scale in [1, 1000] {
            for action in 0..3 {
                let mut a = cold(scale, true);
                let (local, remote) = addresses(v6, 40000);
                let (id, _) = a.connect_fast_open(0, local, remote, &[]).unwrap();
                let mut tiny = [0xa5; 1];
                assert!(a.poll_reserved_transmit_for(0, id, &mut tiny, 64).is_err());
                assert_eq!(tiny, [0xa5; 1]);
                let mut bytes = [0; 2048];
                let (_, token) = a.poll_reserved_transmit_for(0, id, &mut bytes, 64).unwrap();
                let token = token.unwrap();
                if action == 1 {
                    a.reject_unsubmitted(token).unwrap();
                }
                if action == 2 {
                    a.abandon_transmit(token).unwrap();
                }
                let now = 4_000_000 * scale;
                a.on_timeout(now, 64).unwrap();
                assert!(
                    a.can_defer_fast_open_with_server_cookie(
                        now,
                        local.ip(),
                        remote,
                        Some(wire::FastOpenCookie::request())
                    )
                    .unwrap()
                );
                if action == 2 {
                    continue;
                }
                let token = if action == 1 {
                    a.poll_reserved_transmit_for(now, id, &mut bytes, 64)
                        .unwrap()
                        .1
                        .unwrap()
                } else {
                    token
                };
                a.accept_transmit(now, token).unwrap();
                let deadline = a.next_deadline().unwrap();
                assert_eq!(deadline, now + 1_000_000 * scale);
                a.on_timeout(deadline - 1, 64).unwrap();
                assert!(
                    a.can_defer_fast_open_with_server_cookie(
                        deadline - 1,
                        local.ip(),
                        remote,
                        Some(wire::FastOpenCookie::request())
                    )
                    .unwrap()
                );
                a.on_timeout(deadline, 64).unwrap();
                assert!(
                    !a.can_defer_fast_open_with_server_cookie(
                        deadline,
                        local.ip(),
                        remote,
                        Some(wire::FastOpenCookie::request())
                    )
                    .unwrap()
                );
            }
        }
    }
}

#[test]
fn cookie_request_first_committed_timeout_does_not_wait_for_reserved_retry() {
    for v6 in [false, true] {
        for scale in [1, 1000] {
            let mut a = cold(scale, true);
            let (local, remote) = addresses(v6, 40000);
            let (id, _) = a.connect_fast_open(0, local, remote, &[]).unwrap();
            emit(&mut a, 0, id, true);
            let first = a.next_deadline().unwrap();
            a.on_timeout(first, 64).unwrap();
            assert!(
                !a.can_defer_fast_open_with_server_cookie(
                    first,
                    local.ip(),
                    remote,
                    Some(wire::FastOpenCookie::request())
                )
                .unwrap()
            );
            let mut bytes = [0; 2048];
            let (poll, attempt) = a
                .poll_reserved_transmit_for(first, id, &mut bytes, 16)
                .unwrap();
            assert!(poll.packet.is_some());
            let attempt = attempt.unwrap();
            // Local backpressure is not another network retransmission timeout.
            let accepted_at = 4_000_000 * scale;
            a.on_timeout(accepted_at, 64).unwrap();
            assert!(a.accept_transmit(accepted_at, attempt).unwrap());
            let second = a.next_deadline().unwrap();
            assert_eq!(second, 6_000_000 * scale);
            let (other_local, _) = addresses(v6, 40001);
            let (warm, _) = a
                .connect_fast_open(accepted_at + scale, other_local, remote, &[])
                .unwrap();
            let request = emit(&mut a, accepted_at + scale, warm, true);
            assert!(
                wire::parse(request.0, &request.1)
                    .unwrap()
                    .options
                    .fast_open
                    .is_none()
            );
            deliver(
                &mut a,
                accepted_at + 2 * scale,
                &cache_reply(&request, 1240, Some(&[7; 8])),
            );
            emit(&mut a, accepted_at + 2 * scale, warm, true);
            assert!(
                !a.can_defer_fast_open(accepted_at + 2 * scale, local.ip(), remote)
                    .unwrap()
            );
            a.on_timeout(second - 1, 64).unwrap();
            assert!(
                !a.can_defer_fast_open(second - 1, local.ip(), remote)
                    .unwrap()
            );
            a.on_timeout(second, 64).unwrap();
            assert!(!a.can_defer_fast_open(second, local.ip(), remote).unwrap());
            // An ordinary suppressed open does not acquire unsolicited cookies.
            assert!(
                !a.has_fast_open_cookie(second, local.ip(), remote.ip())
                    .unwrap()
            );
            let expiry = first + 60_000_000 * scale;
            assert!(
                !a.can_defer_fast_open_with_server_cookie(
                    expiry - 1,
                    local.ip(),
                    remote,
                    Some(wire::FastOpenCookie::request())
                )
                .unwrap()
            );
            assert!(
                a.can_defer_fast_open_with_server_cookie(
                    expiry,
                    local.ip(),
                    remote,
                    Some(wire::FastOpenCookie::request())
                )
                .unwrap()
            );
        }
    }
}
