// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

#[test]
fn paired_completion_preserves_authorized_terminal_prefix_for_every_start() {
    for mode in [
        "connect",
        "msg-cold",
        "msg-warm",
        "deferred-cold",
        "deferred-warm",
    ] {
        for cause in ["reset", "hard-icmp", "application", "abort", "abandon"] {
            for consumed in [false, true] {
                let (mut a, mut b, la, lb) = warm_pair(Profile::Pipeline, false);
                let aa = "192.0.2.1:42000".parse().unwrap();
                let ba = "192.0.2.2:42001".parse().unwrap();
                let ca = stage(&mut a, la, aa);
                let cb = stage(&mut b, lb, ba);
                if mode.ends_with("cold") {
                    a.endpoint.clear_fast_open_client_cache();
                }
                if cause == "application" {
                    a.execute(ca, Op::Set(IPPROTO_TCP, TCP_USER_TIMEOUT, 100))
                        .unwrap();
                }
                if mode.starts_with("deferred") {
                    a.execute(ca, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                        .unwrap();
                }
                match mode {
                    "connect" | "deferred-cold" => {
                        assert_eq!(a.execute(ca, Op::Connect(ba)).unwrap_err(), EINPROGRESS)
                    }
                    "msg-cold" => assert_eq!(
                        a.execute(
                            ca,
                            Op::SendTo(
                                vec![(b"from-A".as_ptr() as usize, 6)],
                                MSG_FASTOPEN,
                                Some(ba),
                                None
                            )
                        )
                        .unwrap_err(),
                        EINPROGRESS
                    ),
                    "msg-warm" => start(&mut a, ca, ba, "msg", b"from-A"),
                    "deferred-warm" => start(&mut a, ca, ba, "deferred", b"from-A"),
                    _ => unreachable!(),
                }
                start(&mut b, cb, aa, "msg", b"from-B");
                let sa = tfo_capture(&mut a);
                let sb = tfo_capture(&mut b);
                tfo_deliver(&mut a, sb);
                tfo_deliver(&mut b, sa.clone());
                let id = cid(&a, ca);
                assert_eq!(a.endpoint.state(id).unwrap(), State::SynReceived);
                assert_eq!(a.execute(ca, Op::Available).unwrap().value, 6);
                let expected = match cause {
                    "reset" => {
                        // Close the crossed active peer while it still has a
                        // pending SYN. abort emits an ACK-bearing validated RST.
                        b.endpoint.abort(cid(&b, cb)).unwrap();
                        tfo_deliver(&mut a, tfo_capture(&mut b));
                        ECONNREFUSED
                    }
                    "hard-icmp" => {
                        tfo_deliver(
                            &mut a,
                            crate::runtime::handshake_errors::feedback(&sa, 3, 3),
                        );
                        EHOSTUNREACH
                    }
                    "application" => {
                        a.test_now = Some(a.now() + 100_000);
                        a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
                        ETIMEDOUT
                    }
                    "abort" => {
                        a.endpoint.abort(id).unwrap();
                        ECONNABORTED
                    }
                    "abandon" => {
                        a.execute(0, Op::LocalResourceReject(true)).unwrap();
                        a.service_egress().unwrap();
                        assert!(a.endpoint.is_output_reserved(id));
                        a.test_now = Some(a.now() + a.reservation_timeout_us);
                        a.expire_egress(a.now()).unwrap();
                        a.execute(0, Op::LocalResourceReject(false)).unwrap();
                        ECONNABORTED
                    }
                    _ => unreachable!(),
                };
                a.events();
                assert_eq!(a.endpoint.state(id).unwrap(), State::Closed);
                let terminal = a.execute(ca, Op::Transport(1)).unwrap().bytes;
                if consumed {
                    assert_eq!(
                        a.execute(ca, Op::Get(SOL_SOCKET, SO_ERROR)).unwrap().value,
                        expected
                    );
                }
                assert_eq!(
                    a.execute(ca, Op::FinishConnect).unwrap_err(),
                    if consumed { ECONNABORTED } else { expected }
                );
                assert_eq!(cid(&a, ca), id); // Receive ownership survives completion.
                assert_eq!(a.execute(ca, Op::Available).unwrap().value, 6);
                assert_ne!(a.execute(ca, Op::Ready).unwrap().value & EPOLLIN, 0);
                assert_eq!(a.execute(ca, Op::Peek(6)).unwrap().bytes, b"from-B");
                assert_eq!(a.execute(ca, Op::Read(2)).unwrap().bytes, b"fr");
                assert_eq!(a.execute(ca, Op::Peek(6)).unwrap().bytes, b"om-B");
                assert_eq!(a.execute(ca, Op::Read(6)).unwrap().bytes, b"om-B");
                assert!(matches!(a.sockets[&ca].handle, Handle::Fresh));
                assert_eq!(a.execute(ca, Op::Read(1)).unwrap_err(), ENOTCONN);
                assert_eq!(
                    a.execute(ca, Op::Get(SOL_SOCKET, SO_ERROR)).unwrap().value,
                    0
                );
                a.service_egress().unwrap();
                while a.execute(0, Op::Capture(65535)).is_ok() {}
                // A local RST, once emitted, keeps nothing of the connection.
                assert!(!a.endpoint.connection_exists(id));
                assert_eq!(a.execute(ca, Op::Transport(1)).unwrap().bytes, terminal);
                eprintln!(
                    "T5_ERROR_EARLY {{\"open\":\"{mode}\",\"cause\":\"{cause}\",\"consumed\":{consumed},\"fatal_errno\":{expected},\"completion_keeps_prefix\":6,\"drained_once\":true,\"snapshot_after_reclaim\":true}}"
                );
            }
        }
    }
}
