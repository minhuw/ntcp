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

#[test]
fn logical_option_change_preserves_deferred_completion_reservations() {
    let (mut a, mut b, client, _, _) = pair();
    a.execute(client, Op::Set(SOL_SOCKET, SO_SNDBUF, 1000))
        .unwrap();
    a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    let flags = ts::TX_SCHED | ts::TX_SOFTWARE | ts::TX_ACK | ts::SOFTWARE | ts::OPT_TSONLY;
    timestamp_set(&mut a, client, flags);
    // A queued non-coalescing completion makes the joint reservation five
    // slots; reserving only three timestamp phases after cloning leaves four.
    a.sockets
        .get_mut(&client)
        .unwrap()
        .completions
        .push_back(Completion::ZeroCopy(10, 10));
    let bytes = vec![1; 150000];
    let (mut request, reply) = logical_request(
        &mut a,
        client,
        Op::Send(vec![(bytes.as_ptr() as usize, bytes.len())], MSG_ZEROCOPY),
    );
    assert!(!a.service(&mut request));
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        unreachable!()
    };
    let progress = a.endpoint.send_progress(cid).unwrap();
    let charge = a.timestamp_charge();
    let capacity = a.sockets[&client].completions.capacity();
    // Readiness, queue and pending clones allocate first. Fail restoration of
    // empty observations, then the joint queue, leaving the original untouched.
    for after in [3, 4] {
        assert_eq!(
            timestamp_allocator::fail_after(after, || a
                .execute(client, Op::Set(IPPROTO_TCP, TCP_INQ, 1)))
            .unwrap_err(),
            ENOBUFS
        );
        assert!(!a.sockets[&client].inq);
        assert_eq!(a.sockets[&client].completions.len(), 1);
        assert_eq!(a.sockets[&client].completions[0].range(), Some((10, 10)));
        assert_eq!(a.timestamp_charge(), charge);
        assert_eq!(a.sockets[&client].completions.capacity(), capacity);
        assert_eq!(a.sockets[&client].timestamps.reserved(), 3);
        assert_eq!(a.sockets[&client].zc_reserved, 1);
        assert_eq!(a.endpoint.send_progress(cid).unwrap(), progress);
    }
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_INQ, 1)).unwrap();
    assert!(a.sockets[&client].completions.capacity() >= 5);
    // Timestamp options mutate in place and must preserve the same reservations.
    timestamp_set(&mut a, client, flags);
    let capacity = a.sockets[&client].completions.capacity();
    assert_eq!(a.timestamp_charge(), charge);
    advance(&mut a, &mut b);
    // Also restore a partially filled observation vector, whose clone has len
    // capacity rather than the four slots reserved before acceptance.
    let charge = a.timestamp_charge();
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_INQ, 0)).unwrap();
    assert_eq!(a.timestamp_charge(), charge);
    let mut send = request.send.take().unwrap();
    let result = timestamp_allocator::failing(|| a.finish_send(client, &mut send, Err(EAGAIN)));
    assert_eq!(result.unwrap().value, 4608);
    assert_eq!(timestamp_records(&a, client).len(), 3);
    drop(reply);
    assert_eq!(a.sockets[&client].completions.capacity(), capacity);
    assert_eq!(a.sockets[&client].zc_reserved, 0);
    assert!(
        a.sockets[&client]
            .completions
            .iter()
            .any(|c| c.range() == Some((0, 0)))
    );
}

#[test]
fn logical_zero_progress_backpressure_counts_byte_capacity_not_lowat() {
    for lowat in [false, true] {
        let (mut a, mut b, client, server, _) = pair();
        // Grow cwnd before measuring application starvation, without holding ACKs
        // during setup. The measured phase below withholds all ACKs.
        a.execute(client, Op::Write(vec![0; 20000])).unwrap();
        advance(&mut a, &mut b);
        advance(&mut a, &mut b);
        assert_eq!(
            b.execute(server, Op::Read(BYTES)).unwrap().bytes.len(),
            20000
        );
        advance(&mut a, &mut b);
        a.execute(client, Op::Set(SOL_SOCKET, SO_SNDBUF, 1000))
            .unwrap();
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
            .unwrap();
        if lowat {
            a.execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, 4608))
                .unwrap();
            // LOWAT blocks first, but subsequently filling exactly must not
            // retroactively turn that LOWAT-only rejection into NOSPACE.
            a.execute(client, Op::Set(SOL_SOCKET, SO_SNDBUF, 4608))
                .unwrap();
        }
        let bytes = vec![1; 4608];
        assert_eq!(
            a.execute(
                client,
                Op::Send(vec![(bytes.as_ptr() as usize, bytes.len())], MSG_EOR)
            )
            .unwrap()
            .value,
            4608
        );
        assert_eq!(
            a.execute(client, Op::Send(vec![(1, 1)], MSG_MORE | MSG_EOR))
                .unwrap_err(),
            EAGAIN
        );
        let Handle::Connection(cid) = a.sockets[&client].handle else {
            unreachable!()
        };
        if lowat {
            // Keep LOWAT unchanged: output frees unsent credit, not byte capacity.
            let mut packet = [0; 1480];
            while a
                .endpoint
                .poll_transmit(a.now(), &mut packet, 32)
                .unwrap()
                .packet
                .is_some()
            {}
            assert_eq!(
                a.execute(
                    client,
                    Op::Send(vec![(bytes.as_ptr() as usize, bytes.len())], 0)
                )
                .unwrap()
                .value,
                4608
            );
        }
        let mut packet = [0; 1480];
        while a
            .endpoint
            .poll_transmit(a.now(), &mut packet, 32)
            .unwrap()
            .packet
            .is_some()
        {}
        assert_eq!(a.endpoint.transport_info(cid).unwrap().notsent_bytes, 0);
        a.epoch -= std::time::Duration::from_millis(20);
        a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
        let limited = a.endpoint.transport_info(cid).unwrap().sndbuf_limited_us;
        if lowat {
            assert_eq!(limited, 0);
        } else {
            assert!(limited >= 20_000, "{limited}");
        }
    }
}

// Diagnostic replay of tcp_info/tcp-info-sndbuf-limited.pkt, not a Linux
// chronograph equivalence assertion. Keep upstream-basic (Reno) unchanged.
#[cfg(feature = "packet-test")]
#[test]
fn logical_sndbuf_upstream_ack_timeline() {
    use ntcp::wire::{self, ACK, SYN};
    let mut a = Owner::packet((
        Ipv4Addr::new(192, 168, 0, 1),
        crate::packet_profile::Profile::UpstreamBasic,
    ))
    .unwrap();
    a.test_now = Some(0);
    let client = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(client, Op::Connect("192.0.2.1:8080".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        unreachable!()
    };
    let mut packet = [0; 65515];
    let tx = a
        .endpoint
        .poll_transmit(0, &mut packet, BUDGET)
        .unwrap()
        .packet
        .unwrap();
    let syn = wire::parse(tx.ip, &packet[..tx.len]).unwrap().header;
    let ip = ntcp::IpMetadata {
        source: tx.ip.destination,
        destination: tx.ip.source,
    };
    let mut header = wire::Header {
        source_port: syn.destination_port,
        destination_port: syn.source_port,
        sequence: 0,
        acknowledgment: syn.sequence.wrapping_add(1),
        flags: SYN | ACK,
        window: 10000,
        urgent_pointer: 0,
    };
    // Exact peer SYN-ACK options: MSS 1000, SACK permitted, scale 8, no TS.
    let n = wire::encode(
        ip,
        header,
        &[2, 4, 3, 232, 4, 2, 1, 1, 1, 3, 3, 8],
        &[],
        &mut packet,
    )
    .unwrap();
    a.test_now = Some(10000);
    a.input(10000, ip, 0, &packet[..n]).unwrap();
    a.events();
    a.execute(client, Op::Set(SOL_SOCKET, SO_SNDBUF, 10000))
        .unwrap();
    assert_eq!(
        a.execute(client, Op::Get(SOL_SOCKET, SO_SNDBUF))
            .unwrap()
            .value,
        20000
    );
    let bytes = vec![0; 150000];
    let (mut request, reply) = logical_request(
        &mut a,
        client,
        Op::Send(vec![(bytes.as_ptr() as usize, bytes.len())], 0),
    );
    header.sequence = 1;
    header.flags = ACK;
    let mut high = 1;
    for now in (10000..=170000).step_by(1000) {
        a.test_now = Some(now);
        a.endpoint.on_timeout(now, BUDGET).unwrap();
        let ack = match now {
            110000 => Some(10001),
            120000 => Some(30001),
            130000 => Some(70001),
            150000 => Some(95001),
            170000 => Some(150001),
            _ => None,
        };
        if let Some(ack) = ack {
            let before = a.endpoint.send_progress(cid).unwrap();
            eprintln!(
                "TIMELINE before ACK{ack} t={now} high={high} progress={before:?} info={:?}",
                a.endpoint.transport_info(cid).unwrap()
            );
            header.acknowledgment = syn.sequence.wrapping_add(ack);
            let n = wire::encode(ip, header, &[], &[], &mut packet).unwrap();
            a.input(now, ip, 0, &packet[..n]).unwrap();
            let after = a.endpoint.send_progress(cid).unwrap();
            if ack == 10001 {
                assert_eq!(a.endpoint.transport_info(cid).unwrap().cwnd, 11000);
            } else {
                // Script ACKs exceed the actual transmitted frontier. They
                // cannot reclaim bytes or clear the blocked logical write.
                assert!(ack > high);
                assert_eq!(after, before);
            }
        }
        a.events();
        // Owner::run outputs before retrying pending sends; new requests also
        // arrive after output. Subsequent turns flush/refill the same request.
        for _ in 0..BUDGET {
            let Some(tx) = a
                .endpoint
                .poll_transmit(now, &mut packet, BUDGET)
                .unwrap()
                .packet
            else {
                break;
            };
            let segment = wire::parse(tx.ip, &packet[..tx.len]).unwrap();
            if !segment.payload.is_empty() {
                let end = segment.header.sequence.wrapping_sub(syn.sequence)
                    + segment.payload.len() as u32;
                high = high.max(end);
                eprintln!(
                    "TIMELINE output t={now} end={end} info={:?}",
                    a.endpoint.transport_info(cid).unwrap()
                );
            }
        }
        a.events();
        if now >= 100000 {
            assert!(!a.service(&mut request));
        }
        if ack.is_some() {
            let info = a.endpoint.transport_info(cid).unwrap();
            let accepted = request.send.as_ref().unwrap().accepted;
            eprintln!("TIMELINE after retry t={now} accepted={accepted} high={high} info={info:?}");
            assert_eq!(accepted, 30000);
            assert_eq!(info.busy_time_us, now - 100000);
            assert_eq!(info.send_used, 20000);
            assert!(info.notsent_bytes > 0);
            if ack != Some(10001) {
                assert!(info.send_used - info.notsent_bytes >= info.cwnd as usize);
            }
            assert_eq!(info.sndbuf_limited_us, 0);
        }
    }
    assert!(reply.try_recv().is_err());
}
