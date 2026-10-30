// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

#[test]
fn startup_capacity_is_real_transactional_admission_not_a_handshake_timeout() {
    for v6 in [false, true] {
        for mode in OPENS {
            let (mut a, _b, _, remote) = setup_bounded(v6, mode.warm(), 1);
            let holder = new(&mut a, SOCK_NONBLOCK);
            assert_eq!(
                a.execute(holder, Op::Connect(SocketAddr::new(remote.ip(), 8090)))
                    .unwrap_err(),
                EINPROGRESS
            );
            tfo_capture(&mut a);
            let client = socket(&mut a, mode, remote, false);
            let buffers = a.endpoint.buffer_bytes();
            let options = a.connection_options.clone();
            let terminal = a.execute(client, Op::Transport(1)).unwrap().bytes;
            let deferred = a.sockets[&client].deferred_peer;
            assert_eq!(a.execute(client, mode.op(remote)).unwrap_err(), ENOBUFS);
            assert!(matches!(a.sockets[&client].handle, Handle::Fresh));
            assert_eq!(a.sockets[&client].deferred_peer, deferred);
            assert_eq!(a.endpoint.buffer_bytes(), buffers);
            assert_eq!(a.connection_options, options);
            assert_eq!(a.execute(client, Op::Transport(1)).unwrap().bytes, terminal);
            assert_eq!(
                a.execute(client, Op::Get(SOL_SOCKET, SO_ERROR))
                    .unwrap()
                    .value,
                0
            );
            assert_eq!(a.sockets[&client].zc_next, 0);
            assert_eq!(a.sockets[&client].zc_reserved, 0);
            assert!(a.sockets[&client].completions.is_empty());
            tfo_no_output(&mut a);
            if mode.warm() {
                assert!(
                    a.endpoint
                        .can_defer_fast_open(a.now(), a.local, remote)
                        .unwrap()
                );
            }
            let held = cid(&a, holder);
            a.endpoint.abort(held).unwrap();
            a.events();
            assert_eq!(
                a.execute(holder, Op::FinishConnect).unwrap_err(),
                ECONNABORTED
            );
            tfo_no_output(&mut a);
            assert!(!a.endpoint.connection_exists(held));
            let result = a.execute(client, mode.op(remote));
            if mode.warm() {
                assert_eq!(result.unwrap().value, 5);
            } else {
                assert_eq!(result.unwrap_err(), EINPROGRESS);
            }
            assert_eq!(
                segment(&tfo_capture(&mut a)).payload,
                if mode.warm() { &b"hello"[..] } else { &[][..] }
            );
            eprintln!(
                "T5_ERROR_STARTUP {{\"v6\":{v6},\"open\":\"{mode:?}\",\"cause\":\"capacity\",\"errno\":{ENOBUFS},\"wire\":false,\"retry\":true}}"
            );
        }
    }
}

#[test]
fn startup_entropy_uses_existing_native_port_seam_and_never_falls_back() {
    for v6 in [false, true] {
        for mode in OPENS {
            let (mut a, _b, _, remote) = setup(v6, mode.warm());
            let client = new(&mut a, SOCK_NONBLOCK);
            if mode.deferred() {
                a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                    .unwrap();
            }
            // Synthetic packet profiles intentionally use sequential test ports.
            // Select native port allocation while retaining the real warmed core.
            let backend = a.packets.take();
            a.port_entropy = Some(VecDeque::from([Err(EPERM)]));
            let buffers = a.endpoint.buffer_bytes();
            let options = a.connection_options.clone();
            let terminal = a.execute(client, Op::Transport(1)).unwrap().bytes;
            let operation = if mode.deferred() {
                Op::Connect(remote)
            } else {
                mode.op(remote)
            };
            assert_eq!(a.execute(client, operation).unwrap_err(), EPERM);
            assert!(a.port_entropy.as_ref().unwrap().is_empty());
            assert!(matches!(a.sockets[&client].handle, Handle::Fresh));
            assert!(a.sockets[&client].local.is_none());
            assert!(a.sockets[&client].deferred_peer.is_none());
            assert_eq!(a.endpoint.buffer_bytes(), buffers);
            assert_eq!(a.connection_options, options);
            assert_eq!(a.execute(client, Op::Transport(1)).unwrap().bytes, terminal);
            assert_eq!(
                a.execute(client, Op::Get(SOL_SOCKET, SO_ERROR))
                    .unwrap()
                    .value,
                0
            );
            a.packets = backend;
            tfo_no_output(&mut a);
            if mode.warm() {
                assert!(
                    a.endpoint
                        .can_defer_fast_open(a.now(), a.local, remote)
                        .unwrap()
                );
            }
            eprintln!(
                "T5_ERROR_STARTUP {{\"v6\":{v6},\"open\":\"{mode:?}\",\"cause\":\"port_entropy\",\"errno\":{EPERM},\"wire\":false,\"fallback\":false}}"
            );
        }
    }
}

#[test]
fn startup_foreign_copy_and_address_rejections_preserve_attempt_ownership() {
    for v6 in [false, true] {
        for mode in OPENS {
            let (mut a, _b, _, remote) = setup(v6, mode.warm());
            let client = new(&mut a, SOCK_NONBLOCK);
            if mode.deferred() {
                a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                    .unwrap();
            }
            let before = a.execute(client, Op::Transport(1)).unwrap().bytes;
            let buffers = a.endpoint.buffer_bytes();
            for invalid in [
                SocketAddr::new(remote.ip(), 0),
                SocketAddr::new(if v6 { "::" } else { "0.0.0.0" }.parse().unwrap(), 8080),
            ] {
                let operation = if mode.connect() || mode.deferred() {
                    Op::Connect(invalid)
                } else {
                    Op::SendTo(
                        vec![(b"hello".as_ptr() as usize, 5)],
                        MSG_FASTOPEN,
                        Some(invalid),
                        None,
                    )
                };
                assert_eq!(a.execute(client, operation).unwrap_err(), EINVAL);
                assert!(matches!(a.sockets[&client].handle, Handle::Fresh));
                assert!(a.sockets[&client].deferred_peer.is_none());
                assert_eq!(a.execute(client, Op::Transport(1)).unwrap().bytes, before);
                assert_eq!(a.endpoint.buffer_bytes(), buffers);
                tfo_no_output(&mut a);
            }
            if !mode.connect() {
                if mode.deferred() {
                    a.execute(client, Op::Connect(remote)).unwrap();
                }
                let deferred = a.sockets[&client].deferred_peer;
                let options = a.connection_options.clone();
                assert_eq!(
                    a.execute(
                        client,
                        Op::SendTo(
                            vec![(0, 5)],
                            if mode.deferred() { 0 } else { MSG_FASTOPEN },
                            Some(remote),
                            None
                        )
                    )
                    .unwrap_err(),
                    EFAULT
                );
                assert_eq!(a.connection_options, options);
                assert_eq!(a.sockets[&client].deferred_peer, deferred);
                assert_eq!(a.endpoint.buffer_bytes(), buffers);
                assert_eq!(a.execute(client, Op::Transport(1)).unwrap().bytes, before);
                assert_eq!(a.sockets[&client].zc_next, 0);
                assert_eq!(a.sockets[&client].zc_reserved, 0);
                assert_eq!(
                    a.execute(client, Op::Get(SOL_SOCKET, SO_ERROR))
                        .unwrap()
                        .value,
                    0
                );
                tfo_no_output(&mut a);
            }
            if mode.warm() {
                assert!(
                    a.endpoint
                        .can_defer_fast_open(a.now(), a.local, remote)
                        .unwrap()
                );
            }
            eprintln!(
                "T5_ERROR_STARTUP {{\"v6\":{v6},\"open\":\"{mode:?}\",\"cause\":\"address_copy\",\"address_errno\":{EINVAL},\"copy_applicable\":{},\"wire\":false}}",
                !mode.connect()
            );
        }
    }
}

#[test]
fn handshake_feedback_rejects_forged_checksums_tuples_and_unsubmitted_sequences() {
    for v6 in [false, true] {
        for mode in OPENS {
            let (mut a, _b, _, remote) = setup(v6, mode.warm());
            let client = socket(&mut a, mode, remote, false);
            let _ = a.execute(client, mode.op(remote));
            let id = cid(&a, client);
            // A second deterministic endpoint predicts the complete future SYN
            // without reserving or submitting output on the endpoint under test.
            // This deliberately strong forgery even knows its exact live ISS.
            let (mut predictor, _, _, _) = setup(v6, mode.warm());
            let predicted = socket(&mut predictor, mode, remote, false);
            let _ = predictor.execute(predicted, mode.op(remote));
            let syn = tfo_capture(&mut predictor);
            let hard = feedback(&syn, if v6 { 1 } else { 3 }, if v6 { 4 } else { 3 });
            assert!(!a.endpoint.is_output_reserved(id));
            tfo_deliver(&mut a, hard.clone());
            assert_eq!(a.endpoint.state(id).unwrap(), State::SynSent);
            assert_eq!(
                a.execute(client, Op::Get(SOL_SOCKET, SO_ERROR))
                    .unwrap()
                    .value,
                0
            );
            assert_eq!(a.endpoint.transport_info(id).unwrap().retransmitted, 0);
            assert_eq!(a.endpoint.transport_info(id).unwrap().rto_backoff, 0);
            if mode.warm() {
                assert!(
                    a.endpoint
                        .can_defer_fast_open(a.now(), a.local, remote)
                        .unwrap()
                );
            }
            // A later physical commit makes the same quote eligible. Before
            // accepting it, independently reject tuple/sequence/checksum forgeries.
            let sent = tfo_capture(&mut a);
            assert_eq!(
                segment(&sent).header.sequence,
                segment(&syn).header.sequence
            );
            let before = a.endpoint.transport_info(id).unwrap();
            let ip_len = crate::ip::header_len(a.local);
            for index in [ip_len, ip_len + 4, ip_len + 7] {
                let mut wrong = sent.clone();
                wrong[index] ^= 0x40;
                // Outer feedback is fully checksummed; only its quoted TCP
                // selector differs. Quoted TCP checksums are not required by ICMP.
                tfo_deliver(
                    &mut a,
                    feedback(&wrong, if v6 { 1 } else { 3 }, if v6 { 4 } else { 3 }),
                );
                assert_eq!(a.endpoint.transport_info(id).unwrap(), before);
                assert_eq!(
                    a.execute(client, Op::Get(SOL_SOCKET, SO_ERROR))
                        .unwrap()
                        .value,
                    0
                );
            }
            let mut corrupt = hard.clone();
            corrupt[if v6 { 42 } else { 22 }] ^= 1;
            assert_eq!(a.execute(0, Op::Inject(corrupt)).unwrap_err(), EINVAL);
            assert_eq!(a.endpoint.transport_info(id).unwrap(), before);
            tfo_deliver(&mut a, hard);
            assert_eq!(a.endpoint.state(id).unwrap(), State::Closed);
            assert_eq!(
                a.execute(client, Op::Get(SOL_SOCKET, SO_ERROR))
                    .unwrap()
                    .value,
                EHOSTUNREACH
            );
            eprintln!(
                "T5_ERROR_PROVENANCE {{\"v6\":{v6},\"open\":\"{mode:?}\",\"unsubmitted_ignored\":true,\"forged_ignored\":true,\"checksum_rejected\":true,\"committed_accepted\":true}}"
            );
        }
    }
}
