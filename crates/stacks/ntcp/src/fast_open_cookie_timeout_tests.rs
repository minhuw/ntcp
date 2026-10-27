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

fn emit(
    endpoint: &mut Endpoint,
    now: u64,
    id: ConnectionId,
    reserved: bool,
) -> (IpMetadata, Vec<u8>) {
    if !reserved {
        return packet(endpoint, now);
    }
    let mut bytes = [0; 2048];
    let (poll, attempt) = endpoint
        .poll_reserved_transmit_for(now, id, &mut bytes, 16)
        .unwrap();
    let tx = poll.packet.unwrap();
    let ip = tx.ip;
    let bytes = bytes[..tx.len].to_vec();
    assert!(endpoint.accept_transmit(now, attempt.unwrap()).unwrap());
    (ip, bytes)
}

#[test]
fn cookie_request_first_timeout_success_preserves_next_attempt() {
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
                        // One ambiguous request-only timeout stays connection-local;
                        // a successful fallback permits another request or cached TFO.
                        assert!(next.options.fast_open.is_some());
                        assert_eq!(next_accepted, if returned_cookie { 1200 } else { 0 });
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
                        assert_eq!(other_accepted, if returned_cookie { 1200 } else { 0 });
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
fn cookie_request_timeout_threshold_uses_committed_retry() {
    for v6 in [false, true] {
        for scale in [1, 1000] {
            let mut a = cold(scale, true);
            let (local, remote) = addresses(v6, 40000);
            let (id, _) = a.connect_fast_open(0, local, remote, &[]).unwrap();
            emit(&mut a, 0, id, true);
            let first = a.next_deadline().unwrap();
            a.on_timeout(first, 64).unwrap();
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
            assert_eq!(
                wire::parse(request.0, &request.1)
                    .unwrap()
                    .options
                    .fast_open,
                Some(wire::FastOpenCookie::request())
            );
            deliver(
                &mut a,
                accepted_at + 2 * scale,
                &cache_reply(&request, 1240, Some(&[7; 8])),
            );
            emit(&mut a, accepted_at + 2 * scale, warm, true);
            assert!(
                a.can_defer_fast_open(accepted_at + 2 * scale, local.ip(), remote)
                    .unwrap()
            );
            a.on_timeout(second - 1, 64).unwrap();
            assert!(
                a.can_defer_fast_open(second - 1, local.ip(), remote)
                    .unwrap()
            );
            a.on_timeout(second, 64).unwrap();
            assert!(!a.can_defer_fast_open(second, local.ip(), remote).unwrap());
            assert!(
                a.has_fast_open_cookie(second, local.ip(), remote.ip())
                    .unwrap()
            );
        }
    }
}
