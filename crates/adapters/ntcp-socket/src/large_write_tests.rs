// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
fn logical_request(a: &mut Owner, id: u64, op: Op) -> (Request, Receiver<Result<Reply>>) {
    a.execute(id, Op::Flags(F_SETFL, 0)).unwrap();
    let (reply, rx) = mpsc::sync_channel(1);
    (
        Request {
            id,
            op: Op::Wait(Box::new(op), None),
            reply,
            deadline: None,
            send: None,
        },
        rx,
    )
}
fn advance(a: &mut Owner, b: &mut Owner) {
    pump(a, b);
    b.epoch -= std::time::Duration::from_millis(210);
    b.endpoint.on_timeout(b.now(), BUDGET).unwrap();
    pump(a, b);
}
#[test]
fn logical_large_iov_tiny_buffer_progress_single_timestamp_and_zerocopy() {
    let (mut a, mut b, client, server, _) = pair();
    a.execute(client, Op::Set(SOL_SOCKET, SO_SNDBUF, 1000))
        .unwrap();
    a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    let report = ts::SOFTWARE | ts::OPT_ID | ts::OPT_ID_TCP | ts::OPT_TSONLY;
    timestamp_set(
        &mut a,
        client,
        report | ts::TX_SCHED | ts::TX_SOFTWARE | ts::TX_ACK,
    );
    let bytes: Vec<u8> = (0..150000).map(|n| (n % 251) as u8).collect();
    let sources = vec![
        (0, 0),
        (bytes.as_ptr() as usize, 71003),
        (bytes[71003..].as_ptr() as usize, bytes.len() - 71003),
    ];
    let (mut request, rx) = logical_request(
        &mut a,
        client,
        Op::Send(sources, MSG_ZEROCOPY | MSG_MORE | MSG_EOR),
    );
    let mut received = Vec::new();
    let mut finished = false;
    for turn in 0..300 {
        finished = a.service(&mut request);
        if turn == 0 {
            assert!(!finished);
            // Per-send generation is frozen; report options remain live.
            timestamp_set(&mut a, client, report);
        }
        advance(&mut a, &mut b);
        while let Ok(reply) = b.execute(server, Op::Read(BYTES)) {
            received.extend(reply.bytes);
        }
        if finished {
            break;
        }
        assert!(a.sockets[&client].completions.is_empty());
        assert_eq!(a.sockets[&client].zc_next, 1);
        assert_eq!(a.sockets[&client].zc_reserved, 1);
        assert_eq!(a.sockets[&client].timestamps.reserved(), 3);
    }
    assert!(finished);
    assert_eq!(rx.recv().unwrap().unwrap().value, bytes.len() as i32);
    assert_eq!(received, bytes);
    advance(&mut a, &mut b);
    let records = timestamp_records(&a, client);
    assert_eq!(records.len(), 3, "{records:?}");
    for stage in 0..3 {
        assert_eq!(
            records
                .iter()
                .filter(|r| r.0 == stage && r.1 == 149999 && r.2 > 0)
                .count(),
            1
        );
    }
    assert_eq!(
        a.sockets[&client]
            .completions
            .iter()
            .filter_map(Completion::range)
            .collect::<Vec<_>>(),
        [(0, 0)]
    );
    assert_eq!(a.sockets[&client].zc_reserved, 0);
}
#[test]
fn logical_partial_timeout_retains_observed_last_byte_and_original_deadline() {
    let (mut a, mut b, client, _, _) = pair();
    a.execute(client, Op::Set(SOL_SOCKET, SO_SNDBUF, 1000))
        .unwrap();
    timestamp_set(
        &mut a,
        client,
        ts::TX_SCHED
            | ts::TX_SOFTWARE
            | ts::TX_ACK
            | ts::SOFTWARE
            | ts::OPT_ID
            | ts::OPT_ID_TCP
            | ts::OPT_TSONLY,
    );
    a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    let bytes = vec![7; 150000];
    let (mut request, rx) = logical_request(
        &mut a,
        client,
        Op::Send(
            vec![(bytes.as_ptr() as usize, bytes.len())],
            MSG_EOR | MSG_ZEROCOPY,
        ),
    );
    let deadline = Instant::now() + std::time::Duration::from_secs(1);
    request.deadline = Some(deadline);
    assert!(!a.service(&mut request));
    let n = request.send.as_ref().unwrap().accepted;
    assert_eq!(n, 4608);
    advance(&mut a, &mut b); // The tentative target has now been scheduled/sent/ACKed.
    assert!(a.sockets[&client].completions.is_empty());
    assert_eq!(request.deadline, Some(deadline));
    let observed_before = timestamps::realtime();
    // Change OPT_ID after observation: IDs must not be normalized at return.
    timestamp_set(&mut a, client, 0);
    request.deadline = Some(Instant::now());
    assert!(a.service(&mut request));
    assert_eq!(rx.recv().unwrap().unwrap().value, n as i32);
    assert_eq!(
        a.sockets[&client]
            .completions
            .iter()
            .filter_map(Completion::range)
            .collect::<Vec<_>>(),
        [(0, 0)]
    );
    let records = timestamp_records(&a, client);
    assert_eq!(records.len(), 3);
    assert!(
        records
            .iter()
            .all(|r| r.1 == n as u32 - 1 && r.2 > 0 && r.2 <= observed_before)
    );
}
#[test]
fn logical_fault_prefix_capacity_lowat_and_nonblocking_short_return() {
    let (mut a, mut b, client, server, _) = pair();
    let bytes = vec![9; 150000];
    let n = a
        .execute(
            client,
            Op::Send(vec![(bytes.as_ptr() as usize, bytes.len())], 0),
        )
        .unwrap()
        .value;
    assert_eq!(n, BYTES as i32);
    assert_eq!(
        a.execute(client, Op::Send(vec![(1, 1)], 0)).unwrap_err(),
        EAGAIN
    );
    advance(&mut a, &mut b);
    b.execute(server, Op::Read(BYTES)).unwrap();
    advance(&mut a, &mut b);
    assert_eq!(
        a.execute(
            client,
            Op::Send(vec![(bytes.as_ptr() as usize, 713), (1, 999)], MSG_EOR),
        )
        .unwrap_err(),
        EFAULT
    );
    advance(&mut a, &mut b);
    assert_eq!(b.execute(server, Op::Read(BYTES)).unwrap_err(), EAGAIN);
}
#[test]
fn logical_later_epipe_and_close_return_prefix_without_replay() {
    for close in [false, true] {
        let (mut a, _, client, _, _) = pair();
        let bytes = vec![1; 150000];
        let (mut request, rx) = logical_request(
            &mut a,
            client,
            Op::Send(vec![(bytes.as_ptr() as usize, bytes.len())], 0),
        );
        assert!(!a.service(&mut request));
        if close {
            a.pending.push_back(request);
            a.execute(client, Op::Close).unwrap();
        } else {
            a.execute(client, Op::Shutdown(SHUT_WR)).unwrap();
            assert!(a.service(&mut request));
        }
        assert_eq!(rx.recv().unwrap().unwrap().value, BYTES as i32);
    }
}
#[test]
fn logical_max_count_and_page_fault_without_large_allocation() {
    assert_eq!(
        send::max_rw_count(),
        (i32::MAX as usize) & !(unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize - 1)
    );
    let (mut a, _, client, _, _) = pair();
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    unsafe {
        let p = libc::mmap(
            ptr::null_mut(),
            page * 2,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(p, MAP_FAILED);
        assert_eq!(libc::mprotect(p.add(page), page, PROT_NONE), 0);
        assert_eq!(
            a.execute(client, Op::Send(vec![(p as usize, page * 2)], 0))
                .unwrap_err(),
            EFAULT
        );
        assert_eq!(libc::munmap(p, page * 2), 0);
        let huge = send::max_rw_count() + page;
        let p = libc::mmap(
            ptr::null_mut(),
            huge,
            PROT_READ,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
            -1,
            0,
        );
        assert_ne!(p, MAP_FAILED);
        let send = LogicalSend::new(&a, client, vec![(p as usize, huge)], 0, None).unwrap();
        assert_eq!(send.total_for_test(), send::max_rw_count());
        assert!(
            a.execute(client, Op::Send(vec![(p as usize, huge)], 0))
                .unwrap()
                .value
                > 0
        );
        assert_eq!(libc::munmap(p, huge), 0);
    }
}
#[test]
fn logical_large_per_send_override_and_shared_nonblock_change() {
    let (mut a, mut b, client, server, _) = pair();
    timestamp_set(
        &mut a,
        client,
        ts::TX_ACK | ts::SOFTWARE | ts::OPT_ID | ts::OPT_ID_TCP | ts::OPT_TSONLY,
    );
    let bytes = vec![3; 150000];
    let (mut request, rx) = logical_request(
        &mut a,
        client,
        Op::SendTimestamp(
            vec![(bytes.as_ptr() as usize, bytes.len())],
            0,
            ts::TX_SCHED | ts::TX_SOFTWARE,
        ),
    );
    assert!(!a.service(&mut request));
    advance(&mut a, &mut b);
    b.execute(server, Op::Read(BYTES)).unwrap();
    // An alias changes the shared OFD: return promptly, never start a new send.
    a.execute(client, Op::Flags(F_SETFL, O_NONBLOCK)).unwrap();
    assert!(a.service(&mut request));
    let n = rx.recv().unwrap().unwrap().value as usize;
    assert!(n > BYTES && n < bytes.len());
    advance(&mut a, &mut b);
    b.execute(server, Op::Read(BYTES)).unwrap();
    advance(&mut a, &mut b);
    let records = timestamp_records(&a, client);
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|r| r.0 <= 1 && r.1 == n as u32 - 1));
}
#[test]
fn logical_owner_stop_returns_accepted_prefix() {
    let (mut a, _, client, _, _) = pair();
    let bytes = vec![1; 150000];
    let (mut request, result) = logical_request(
        &mut a,
        client,
        Op::Send(vec![(bytes.as_ptr() as usize, bytes.len())], 0),
    );
    assert!(!a.service(&mut request));
    a.pending.push_back(request);
    let (_tx, rx) = mpsc::sync_channel(1);
    a.run(rx, -1, &std::sync::atomic::AtomicBool::new(true));
    assert_eq!(result.recv().unwrap().unwrap().value, BYTES as i32);
}

#[test]
fn logical_later_copy_fault_preserves_only_prior_admitted_chunk_and_metadata() {
    for vector in [false, true] {
        let (mut a, mut b, client, server, _) = pair();
        timestamp_set(
            &mut a,
            client,
            ts::TX_SCHED
                | ts::TX_SOFTWARE
                | ts::TX_ACK
                | ts::SOFTWARE
                | ts::OPT_ID
                | ts::OPT_ID_TCP
                | ts::OPT_TSONLY,
        );
        a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
            .unwrap();
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let len = BYTES + page * 2;
        unsafe {
            let p = libc::mmap(
                ptr::null_mut(),
                len,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            );
            assert_ne!(p, MAP_FAILED);
            ptr::write_bytes(p, 35, BYTES + page);
            assert_eq!(libc::mprotect(p.add(BYTES + page), page, PROT_NONE), 0);
            let sources = if vector {
                vec![
                    (p as usize, BYTES + page),
                    (p.add(BYTES + page) as usize, page),
                ]
            } else {
                vec![(p as usize, len)]
            };
            let (mut request, reply) =
                logical_request(&mut a, client, Op::Send(sources, MSG_ZEROCOPY | MSG_EOR));
            assert!(!a.service(&mut request));
            assert_eq!(request.send.as_ref().unwrap().accepted, BYTES);
            let cookie = a.timestamp_cookie;
            advance(&mut a, &mut b);
            assert_eq!(
                b.execute(server, Op::Read(BYTES)).unwrap().bytes,
                vec![35; BYTES]
            );
            advance(&mut a, &mut b);
            assert!(a.sockets[&client].completions.is_empty());
            assert!(a.service(&mut request));
            assert_eq!(reply.recv().unwrap().unwrap().value, BYTES as i32);
            assert_eq!(a.timestamp_cookie, cookie);
            advance(&mut a, &mut b);
            assert_eq!(b.execute(server, Op::Read(BYTES)).unwrap_err(), EAGAIN);
            let records = timestamp_records(&a, client);
            assert_eq!(records.len(), 3);
            assert!(records.iter().all(|r| r.1 == BYTES as u32 - 1));
            assert_eq!(
                a.sockets[&client]
                    .completions
                    .iter()
                    .filter_map(Completion::range)
                    .collect::<Vec<_>>(),
                [(0, 0)]
            );
            assert_eq!(libc::munmap(p, len), 0);
        }
    }
}
