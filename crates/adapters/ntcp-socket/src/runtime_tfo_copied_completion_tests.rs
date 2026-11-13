// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::fast_open_tests::{tfo_capture, tfo_deliver, tfo_no_output, tfo_send, tfo_setup};
use super::memory::tests::{cid, exchange, segment};
use super::tests::new;
use super::*;

struct Flight {
    a: Owner,
    b: Owner,
    listener: u64,
    client: u64,
    request: Request,
    result: Receiver<Result<Reply>>,
    payload: Vec<u8>,
    initial_done: bool,
}
impl Flight {
    fn new(deferred: bool, warm: bool, nonblocking: bool, size: usize) -> Self {
        let (mut a, b, listener) = tfo_setup(warm);
        let client = new(&mut a, if nonblocking { SOCK_NONBLOCK } else { 0 });
        a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
            .unwrap();
        if deferred {
            a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                .unwrap();
            a.execute(client, Op::Connect("192.0.2.2:8080".parse().unwrap()))
                .unwrap();
        }
        let data = vec![7; size];
        let (reply, result) = mpsc::sync_channel(1);
        let mut request = Request {
            id: client,
            op: Op::Wait(
                Box::new(tfo_send(
                    &data,
                    MSG_ZEROCOPY | if deferred { 0 } else { MSG_FASTOPEN },
                )),
                None,
            ),
            reply,
            deadline: None,
            send: None,
            closing: None,
        };
        let initial_done = a.service(&mut request);
        Self {
            a,
            b,
            listener,
            client,
            request,
            result,
            payload: data,
            initial_done,
        }
    }
    fn fail(&mut self, timeout: bool) {
        let failed = cid(&self.a, self.client);
        if timeout {
            tfo_capture(&mut self.a);
            for _ in 0..20 {
                if self.a.endpoint.state(failed).unwrap() == State::Closed {
                    break;
                }
                let now = self.a.endpoint.next_deadline().unwrap();
                self.a.test_now = Some(now);
                self.a.endpoint.on_timeout(now, BUDGET).unwrap();
                self.a.events();
                self.a.service_egress().unwrap();
                while self.a.execute(0, Op::Capture(65535)).is_ok() {}
            }
        } else {
            self.b.execute(self.listener, Op::Close).unwrap();
            tfo_deliver(&mut self.b, tfo_capture(&mut self.a));
            let reset = tfo_capture(&mut self.b);
            tfo_deliver(&mut self.a, reset);
        }
        assert_eq!(self.a.endpoint.state(failed).unwrap(), State::Closed);
    }
}

#[test]
fn failed_initial_tfo_does_not_publish_copied_completion() {
    for (deferred, warm) in [(false, false), (false, true), (true, true)] {
        for timeout in [false, true] {
            let mut f = Flight::new(deferred, warm, false, 500);
            assert!(!f.initial_done);
            assert_eq!(f.a.sockets[&f.client].zc_next, 0);
            assert_eq!(f.a.sockets[&f.client].zc_reserved, usize::from(warm));
            assert_eq!(
                f.request.send.as_ref().unwrap().accepted,
                if warm { 500 } else { 0 }
            );
            f.fail(timeout);
            assert!(f.a.service(&mut f.request));
            let error = f.result.try_recv().unwrap().unwrap_err();
            assert_eq!(error, if timeout { ETIMEDOUT } else { ECONNREFUSED });
            let s = &f.a.sockets[&f.client];
            assert_eq!(s.zc_next, 0);
            assert_eq!(s.zc_reserved, 0);
            assert!(s.completions.is_empty());
        }
    }
}

#[test]
fn copied_initial_tfo_lifecycle_success_matrix() {
    for (deferred, warm) in [(false, false), (false, true), (true, true)] {
        for nonblocking in [false, true] {
            for size in [0, 500, 5000] {
                let mut f = Flight::new(deferred, warm, nonblocking, size);
                if !nonblocking {
                    assert!(!f.initial_done);
                    assert_eq!(f.a.sockets[&f.client].zc_next, 0);
                    assert_eq!(
                        f.a.sockets[&f.client].zc_reserved,
                        usize::from(warm && size != 0)
                    );
                    exchange(&mut f.a, &mut f.b);
                    for _ in 0..16 {
                        if f.a.service(&mut f.request) {
                            break;
                        }
                        exchange(&mut f.a, &mut f.b);
                    }
                }
                let result = f.result.try_recv().unwrap();
                let accepted = if nonblocking && (!warm || size == 0) {
                    assert_eq!(result.unwrap_err(), EINPROGRESS);
                    0
                } else {
                    let accepted = result.unwrap().value as usize;
                    if nonblocking {
                        assert!(accepted > 0 && accepted <= size);
                    } else {
                        assert_eq!(accepted, size);
                    }
                    accepted
                };
                f.payload.fill(9);
                let s = &f.a.sockets[&f.client];
                assert_eq!(s.zc_next, u32::from(accepted != 0));
                assert_eq!(s.zc_reserved, 0);
                if accepted != 0 {
                    assert!(matches!(
                        s.completions.front(),
                        Some(Completion::ZeroCopy(0, 0))
                    ));
                }
                assert_eq!(s.completions.len(), usize::from(accepted != 0));
                exchange(&mut f.a, &mut f.b);
                let server =
                    f.b.execute(f.listener, Op::Accept(SOCK_NONBLOCK))
                        .unwrap()
                        .value as u64;
                if accepted != 0 {
                    assert_eq!(
                        f.b.execute(server, Op::Read(BYTES)).unwrap().bytes,
                        vec![7; accepted]
                    );
                }
                assert_eq!(
                    f.a.sockets[&f.client].completions.len(),
                    usize::from(accepted != 0)
                );
            }
        }
    }
}

#[test]
fn copied_initial_tfo_deadline_and_runtime_cancel_release_unassigned_reservation() {
    for (deferred, warm) in [(false, false), (false, true), (true, true)] {
        for cancelled in [false, true] {
            let mut f = Flight::new(deferred, warm, false, 500);
            assert!(!f.initial_done);
            if cancelled {
                let mut send = f.request.send.take().unwrap();
                assert_eq!(
                    f.a.finish_send(f.client, &mut send, Err(ECANCELED))
                        .unwrap_err(),
                    ECANCELED
                );
            } else {
                f.request.deadline = Some(Instant::now() - std::time::Duration::from_millis(1));
                assert!(f.a.service(&mut f.request));
                assert_eq!(f.result.try_recv().unwrap().unwrap_err(), EAGAIN);
            }
            assert_eq!(f.a.sockets[&f.client].zc_next, 0);
            assert_eq!(f.a.sockets[&f.client].zc_reserved, 0);
            assert!(f.a.sockets[&f.client].completions.is_empty());
        }
    }
}

#[test]
fn copied_initial_tfo_close_drops_socket_scoped_reservations() {
    for (deferred, warm) in [(false, false), (false, true), (true, true)] {
        let mut f = Flight::new(deferred, warm, false, 500);
        let charge = f.a.timestamp_charge();
        f.a.pending.push_back(f.request);
        f.a.execute(f.client, Op::Close).unwrap();
        assert!(!f.a.sockets.contains_key(&f.client));
        assert!(f.a.pending.is_empty());
        let result = f.result.try_recv().unwrap();
        if warm {
            assert_eq!(result.unwrap().value, 500);
        } else {
            assert_eq!(result.unwrap_err(), EBADF);
        }
        assert!(f.a.timestamp_charge() <= charge);
        assert_eq!(
            f.a.sockets.values().map(|s| s.zc_reserved).sum::<usize>(),
            0
        );
        let next = new(&mut f.a, SOCK_NONBLOCK);
        assert_ne!(next, f.client);
        assert_eq!(f.a.sockets[&next].zc_next, 0);
        assert!(f.a.sockets[&next].completions.is_empty());
    }
}

#[test]
fn copied_initial_tfo_stale_request_cannot_consume_new_attempt_id_or_reservation() {
    for deferred in [false, true] {
        let mut f = Flight::new(deferred, true, false, 500);
        let old = cid(&f.a, f.client);
        f.fail(false);
        assert_eq!(
            f.a.execute(f.client, tfo_send(b"observe", MSG_FASTOPEN))
                .unwrap_err(),
            ECONNREFUSED
        );
        assert!(matches!(f.a.sockets[&f.client].handle, Handle::Fresh));
        assert_eq!(f.a.sockets[&f.client].zc_reserved, 1);
        assert_eq!(
            f.a.execute(
                f.client,
                tfo_send(b"new", MSG_FASTOPEN | MSG_ZEROCOPY | MSG_DONTWAIT)
            )
            .unwrap()
            .value,
            3
        );
        let current = cid(&f.a, f.client);
        assert_ne!(old, current);
        assert_eq!(f.a.sockets[&f.client].zc_next, 1);
        assert_eq!(f.a.sockets[&f.client].zc_reserved, 1);
        assert!(f.a.service(&mut f.request));
        assert_eq!(f.result.try_recv().unwrap().unwrap_err(), EBADF);
        assert_eq!(cid(&f.a, f.client), current);
        assert_eq!(f.a.endpoint.state(current).unwrap(), State::SynSent);
        assert!(f.a.sockets[&f.client].connect_pending);
        assert_eq!(f.a.sockets[&f.client].zc_next, 1);
        assert_eq!(f.a.sockets[&f.client].zc_reserved, 0);
        assert_eq!(f.a.sockets[&f.client].completions.len(), 1);
        assert!(matches!(
            f.a.sockets[&f.client].completions.front(),
            Some(Completion::ZeroCopy(0, 0))
        ));
    }
}

#[test]
fn copied_initial_tfo_overlapping_successes_assign_unique_ids_at_commit() {
    for deferred in [false, true] {
        let mut f = Flight::new(deferred, true, false, 500);
        exchange(&mut f.a, &mut f.b);
        assert_eq!(f.a.sockets[&f.client].zc_reserved, 1);
        assert_eq!(f.a.sockets[&f.client].zc_next, 0);
        assert_eq!(
            f.a.execute(
                f.client,
                Op::Send(vec![(b"next".as_ptr() as usize, 4)], MSG_ZEROCOPY)
            )
            .unwrap()
            .value,
            4
        );
        assert_eq!(f.a.sockets[&f.client].zc_next, 1);
        assert_eq!(f.a.sockets[&f.client].zc_reserved, 1);
        assert!(f.a.service(&mut f.request));
        assert_eq!(f.result.try_recv().unwrap().unwrap().value, 500);
        assert_eq!(f.a.sockets[&f.client].zc_next, 2);
        assert_eq!(f.a.sockets[&f.client].zc_reserved, 0);
        assert_eq!(f.a.sockets[&f.client].completions.len(), 1);
        assert!(matches!(
            f.a.sockets[&f.client].completions.front(),
            Some(Completion::ZeroCopy(0, 1))
        ));
    }
}

#[test]
fn copied_initial_tfo_pending_reservation_stays_charged_and_counter_wraps_once() {
    let mut f = Flight::new(false, true, false, 500);
    let limit = f.a.request_limit();
    for i in 0..limit - 1 {
        f.a.sockets
            .get_mut(&f.client)
            .unwrap()
            .completions
            .push_back(Completion::ZeroCopy(i as u32 * 2, i as u32 * 2));
    }
    f.a.recount_timestamp_charge(f.client);
    assert_eq!(
        f.a.reserve_send_completion(f.client, true, true, 0, true),
        Err(ENOBUFS)
    );
    f.fail(false);
    assert!(f.a.service(&mut f.request));
    assert_eq!(f.result.try_recv().unwrap().unwrap_err(), ECONNREFUSED);
    assert!(
        f.a.reserve_send_completion(f.client, true, true, 0, true)
            .unwrap()
    );
    assert_eq!(f.a.sockets[&f.client].zc_next, 0);
    assert_eq!(f.a.sockets[&f.client].zc_reserved, 0);
    let mut f = Flight::new(true, true, false, 500);
    f.a.sockets.get_mut(&f.client).unwrap().zc_next = u32::MAX;
    exchange(&mut f.a, &mut f.b);
    assert!(f.a.service(&mut f.request));
    assert_eq!(f.result.try_recv().unwrap().unwrap().value, 500);
    assert_eq!(f.a.sockets[&f.client].zc_next, 0);
    assert!(matches!(
        f.a.sockets[&f.client].completions.front(),
        Some(Completion::ZeroCopy(u32::MAX, u32::MAX))
    ));
    assert_eq!(
        f.a.execute(
            f.client,
            Op::Send(vec![(b"next".as_ptr() as usize, 4)], MSG_ZEROCOPY)
        )
        .unwrap()
        .value,
        4
    );
    assert_eq!(f.a.sockets[&f.client].zc_next, 1);
    assert!(matches!(
        f.a.sockets[&f.client].completions.front(),
        Some(Completion::ZeroCopy(u32::MAX, 0))
    ));
}

#[test]
fn copied_initial_tfo_multi_iovec_dontwait_and_disabled_option_follow_real_copy() {
    for deferred in [false, true] {
        for zerocopy in [false, true] {
            let (mut a, mut b, listener) = tfo_setup(true);
            let client = new(&mut a, 0);
            if zerocopy {
                a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
                    .unwrap();
            }
            if deferred {
                a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                    .unwrap();
                a.execute(client, Op::Connect("192.0.2.2:8080".parse().unwrap()))
                    .unwrap();
            }
            let mut first = vec![1; 500];
            let mut second = vec![2; 500];
            let mut third = vec![3; 1000];
            let expected = [first.clone(), second.clone(), third.clone()].concat();
            let op = Op::SendTo(
                vec![
                    (first.as_ptr() as usize, first.len()),
                    (second.as_ptr() as usize, second.len()),
                    (third.as_ptr() as usize, third.len()),
                ],
                MSG_ZEROCOPY | MSG_DONTWAIT | if deferred { 0 } else { MSG_FASTOPEN },
                Some("192.0.2.2:8080".parse().unwrap()),
                None,
            );
            let (reply, rx) = mpsc::sync_channel(1);
            let mut request = Request {
                id: client,
                op: Op::Wait(Box::new(op), None),
                reply,
                deadline: None,
                send: None,
                closing: None,
            };
            assert!(a.service(&mut request));
            let n = rx.try_recv().unwrap().unwrap().value as usize;
            assert!(n > 0 && n < expected.len());
            first.fill(9);
            second.fill(9);
            third.fill(9);
            let syn = tfo_capture(&mut a);
            assert_eq!(segment(&syn).payload, &expected[..n]);
            assert_eq!(a.sockets[&client].zc_next, u32::from(zerocopy));
            assert_eq!(a.sockets[&client].zc_reserved, 0);
            assert_eq!(a.sockets[&client].completions.len(), usize::from(zerocopy));
            tfo_deliver(&mut b, syn);
            exchange(&mut a, &mut b);
            let server = b
                .execute(listener, Op::Accept(SOCK_NONBLOCK))
                .unwrap()
                .value as u64;
            assert_eq!(
                b.execute(server, Op::Read(BYTES)).unwrap().bytes,
                &expected[..n]
            );
        }
    }
}

#[test]
fn copied_initial_tfo_confirmed_prefix_survives_later_copy_fault_with_one_id() {
    for deferred in [false, true] {
        let (mut a, mut b, listener) = tfo_setup(true);
        let client = new(&mut a, 0);
        a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
            .unwrap();
        if deferred {
            a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                .unwrap();
            a.execute(client, Op::Connect("192.0.2.2:8080".parse().unwrap()))
                .unwrap();
        }
        let len = 8192;
        let memory = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(memory, libc::MAP_FAILED);
        unsafe {
            core::ptr::write_bytes(memory.cast::<u8>(), 7, len);
        }
        let op = Op::SendTo(
            vec![(memory as usize, 5000)],
            MSG_ZEROCOPY | if deferred { 0 } else { MSG_FASTOPEN },
            Some("192.0.2.2:8080".parse().unwrap()),
            None,
        );
        let (reply, rx) = mpsc::sync_channel(1);
        let mut request = Request {
            id: client,
            op: Op::Wait(Box::new(op), None),
            reply,
            deadline: None,
            send: None,
            closing: None,
        };
        assert!(!a.service(&mut request));
        let prefix = request.send.as_ref().unwrap().accepted;
        assert!(prefix > 0 && prefix < 5000);
        assert_eq!(a.sockets[&client].zc_next, 0);
        assert_eq!(a.sockets[&client].zc_reserved, 1);
        assert_eq!(unsafe { libc::mprotect(memory, len, libc::PROT_NONE) }, 0);
        exchange(&mut a, &mut b);
        assert!(a.service(&mut request));
        assert_eq!(rx.try_recv().unwrap().unwrap().value as usize, prefix);
        assert_eq!(a.sockets[&client].zc_next, 1);
        assert_eq!(a.sockets[&client].zc_reserved, 0);
        assert!(matches!(
            a.sockets[&client].completions.front(),
            Some(Completion::ZeroCopy(0, 0))
        ));
        let server = b
            .execute(listener, Op::Accept(SOCK_NONBLOCK))
            .unwrap()
            .value as u64;
        assert_eq!(
            b.execute(server, Op::Read(BYTES)).unwrap().bytes,
            vec![7; prefix]
        );
        assert_eq!(unsafe { libc::munmap(memory, len) }, 0);
    }
}

#[test]
fn initial_tfo_copy_completion_fault_and_full_queue_do_not_start_or_consume_id() {
    for warm in [false, true] {
        for full in [false, true] {
            let (mut a, _b, _) = tfo_setup(warm);
            let client = new(&mut a, SOCK_NONBLOCK);
            a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
                .unwrap();
            if full {
                let limit = a.request_limit();
                let s = a.sockets.get_mut(&client).unwrap();
                for i in 0..limit {
                    s.completions
                        .push_back(Completion::ZeroCopy(i as u32 * 2, i as u32 * 2));
                }
                a.recount_timestamp_charge(client);
            }
            let original_count = a.sockets[&client].completions.len();
            let result = a.execute(
                client,
                Op::SendTo(
                    vec![(1, 500)],
                    MSG_FASTOPEN | MSG_ZEROCOPY,
                    Some("192.0.2.2:8080".parse().unwrap()),
                    None,
                ),
            );
            assert_eq!(result.unwrap_err(), if full { ENOBUFS } else { EFAULT });
            assert!(matches!(a.sockets[&client].handle, Handle::Fresh));
            assert_eq!(a.sockets[&client].zc_next, 0);
            assert_eq!(a.sockets[&client].zc_reserved, 0);
            assert_eq!(a.sockets[&client].completions.len(), original_count);
            tfo_no_output(&mut a);
        }
    }
}

#[test]
fn client_tfo_permission_admitted_blocking_send_and_completion_survive_disable() {
    for (deferred, warm) in [(false, false), (false, true), (true, true)] {
        let mut f = Flight::new(deferred, warm, false, 500);
        assert!(!f.initial_done);
        assert_eq!(
            f.request.send.as_ref().unwrap().accepted,
            if warm { 500 } else { 0 }
        );
        assert_eq!(f.a.sockets[&f.client].zc_reserved, usize::from(warm));
        f.a.execute(0, Op::SetFastOpenClientEnabled(false)).unwrap();
        exchange(&mut f.a, &mut f.b);
        for _ in 0..16 {
            if f.a.service(&mut f.request) {
                break;
            }
            exchange(&mut f.a, &mut f.b);
        }
        assert_eq!(f.result.try_recv().unwrap().unwrap().value, 500);
        let s = &f.a.sockets[&f.client];
        assert_eq!((s.zc_next, s.zc_reserved, s.completions.len()), (1, 0, 1));
        assert!(matches!(
            s.completions.front(),
            Some(Completion::ZeroCopy(0, 0))
        ));
        // Copied completion releases the user's buffer; it is not wire delivery.
        exchange(&mut f.a, &mut f.b);
        let server =
            f.b.execute(f.listener, Op::Accept(SOCK_NONBLOCK))
                .unwrap()
                .value as u64;
        assert_eq!(
            f.b.execute(server, Op::Read(BYTES)).unwrap().bytes,
            f.payload
        );
    }
}
