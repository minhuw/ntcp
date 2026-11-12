// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;
use crate::timestamping as ts;

pub(super) fn timestamp_set(o: &mut Owner, id: u64, flags: u32) {
    o.execute(id, Op::Set(SOL_SOCKET, ts::OLD, flags as i32))
        .unwrap();
}
pub(super) fn timestamp_records(o: &Owner, id: u64) -> Vec<(u32, u32, u64, u64, usize)> {
    o.sockets[&id]
        .completions
        .iter()
        .filter_map(|c| match c {
            Completion::Timestamp {
                stamp,
                error,
                payload,
                ..
            } => {
                let ns = |at| {
                    u64::from_ne_bytes(stamp[at..at + 8].try_into().unwrap()) * 1_000_000_000
                        + u64::from_ne_bytes(stamp[at + 8..at + 16].try_into().unwrap())
                };
                Some((
                    u32::from_ne_bytes(error[8..12].try_into().unwrap()),
                    u32::from_ne_bytes(error[12..16].try_into().unwrap()),
                    ns(0),
                    ns(32),
                    payload.len(),
                ))
            }
            _ => None,
        })
        .collect()
}
#[test]
fn timestamp_runtime_phases_ids_reset_and_zero_copy_interleave() {
    let (mut a, mut b, client, server, _) = pair();
    let flags = ts::TX_SCHED | ts::TX_SOFTWARE | ts::TX_ACK | ts::SOFTWARE | ts::OPT_ID;
    timestamp_set(&mut a, client, flags);
    a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    a.execute(
        client,
        Op::WriteFlags(b"first".to_vec(), MSG_MORE | MSG_ZEROCOPY),
    )
    .unwrap();
    // Pending observations use the current base at completion, not at write.
    timestamp_set(&mut a, client, 0);
    timestamp_set(&mut a, client, flags | ts::OPT_ID_TCP);
    a.execute(client, Op::Write(b"second".to_vec())).unwrap();
    pump(&mut a, &mut b);
    std::thread::sleep(std::time::Duration::from_millis(220));
    b.endpoint.on_timeout(b.now(), 32).unwrap();
    pump(&mut a, &mut b);
    assert_eq!(
        b.execute(server, Op::Read(99)).unwrap().bytes,
        b"firstsecond"
    );
    let records = timestamp_records(&a, client);
    assert_eq!(records.len(), 6);
    for id in [u32::MAX, 5] {
        for stage in 0..3 {
            assert_eq!(
                records
                    .iter()
                    .filter(|r| r.0 == stage && r.1 == id && r.2 > 0 && r.3 == 0 && r.4 > 0)
                    .count(),
                1
            );
        }
    }
    assert!(matches!(
        a.sockets[&client].completions.front(),
        Some(Completion::ZeroCopy(0, 0))
    ));
    let generations = a.sockets[&client].readiness_generations[2];
    assert!(generations >= 7);
    assert!(
        a.endpoint
            .transport_info(match a.sockets[&client].handle {
                Handle::Connection(cid) => cid,
                _ => unreachable!(),
            })
            .unwrap()
            .rtt_us
            .unwrap()
            > 0
    );
}
#[test]
fn timestamp_runtime_partial_failed_zero_per_send_and_budget() {
    let (mut a, mut b, client, _, _) = pair();
    a.execute(client, Op::Set(SOL_SOCKET, SO_SNDBUF, 1000))
        .unwrap();
    timestamp_set(
        &mut a,
        client,
        ts::TX_ACK | ts::SOFTWARE | ts::OPT_ID | ts::OPT_ID_TCP | ts::OPT_TSONLY,
    );
    a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    let bytes = vec![7; 10000];
    let n = a
        .execute(client, Op::WriteFlags(bytes, MSG_ZEROCOPY))
        .unwrap()
        .value as u32;
    assert!(n > 0 && n < 10000);
    assert_eq!(
        a.execute(client, Op::WriteFlags(vec![1], MSG_ZEROCOPY))
            .unwrap_err(),
        EAGAIN
    );
    assert_eq!(
        a.execute(client, Op::WriteFlags(vec![], MSG_ZEROCOPY))
            .unwrap()
            .value,
        0
    );
    assert_eq!(a.sockets[&client].zc_next, 1);
    assert_eq!(a.sockets[&client].timestamps.reserved(), 1);
    pump(&mut a, &mut b);
    std::thread::sleep(std::time::Duration::from_millis(220));
    b.endpoint.on_timeout(b.now(), 32).unwrap();
    pump(&mut a, &mut b);
    assert_eq!(
        timestamp_records(&a, client)
            .iter()
            .map(|r| (r.0, r.1, r.4))
            .collect::<Vec<_>>(),
        [(2, n - 1, 0)]
    );
    let data = [9u8; 3];
    a.execute(
        client,
        Op::SendTimestamp(vec![(data.as_ptr() as usize, 3)], 0, ts::TX_SCHED),
    )
    .unwrap();
    pump(&mut a, &mut b);
    std::thread::sleep(std::time::Duration::from_millis(220));
    b.endpoint.on_timeout(b.now(), 32).unwrap();
    pump(&mut a, &mut b);
    assert_eq!(
        timestamp_records(&a, client).last().map(|r| (r.0, r.1)),
        Some((1, n + 2))
    );
    assert_eq!(
        a.execute(client, Op::SendTimestamp(vec![], 0, ts::SOFTWARE))
            .unwrap_err(),
        EINVAL
    );
    // Receive-memory bounds apply to reservations before any write is accepted.
    a.execute(client, Op::Set(SOL_SOCKET, SO_RCVBUF, 1))
        .unwrap();
    timestamp_set(
        &mut a,
        client,
        ts::TX_HARDWARE | ts::RAW_HARDWARE | ts::OPT_ID | ts::OPT_TSONLY,
    );
    let mut accepted = 0;
    loop {
        match a.execute(client, Op::Write(vec![8])) {
            Ok(_) => accepted += 1,
            Err(ENOBUFS) => break,
            other => panic!("unexpected {other:?}"),
        }
        assert!(accepted < 128);
    }
    assert!(accepted > 0);
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        unreachable!()
    };
    let before = a.endpoint.send_progress(cid).unwrap();
    assert_eq!(a.execute(client, Op::Write(vec![8])).unwrap_err(), ENOBUFS);
    assert_eq!(a.endpoint.send_progress(cid).unwrap(), before);
    a.execute(client, Op::Close).unwrap();
    assert_eq!(a.endpoint.next_tx_timestamp(cid).unwrap(), None);
}
#[test]
fn timestamp_runtime_payload_fault_control_fault_and_all_truncations() {
    let (mut a, mut b, client, _, _) = pair();
    timestamp_set(&mut a, client, ts::TX_SOFTWARE | ts::SOFTWARE | ts::OPT_ID);
    a.execute(client, Op::Write(b"timestamp payload".to_vec()))
        .unwrap();
    pump(&mut a, &mut b);
    std::thread::sleep(std::time::Duration::from_millis(220));
    b.endpoint.on_timeout(b.now(), 32).unwrap();
    pump(&mut a, &mut b);
    // Reporting ABI is selected at receive time, not when this event was queued.
    a.execute(
        client,
        Op::Set(SOL_SOCKET, ts::NEW, (ts::SOFTWARE | ts::OPT_ID) as i32),
    )
    .unwrap();
    let original = a.sockets[&client].completions.front().unwrap().clone();
    let Completion::Timestamp { payload, .. } = &original else {
        unreachable!()
    };
    assert!(payload.ends_with(b"timestamp payload"));
    let mut m: msghdr = unsafe { std::mem::zeroed() };
    let mut v = iovec {
        iov_base: std::ptr::dangling_mut::<c_void>(),
        iov_len: payload.len(),
    };
    m.msg_iov = &mut v;
    m.msg_iovlen = 1;
    assert_eq!(
        a.execute(client, Op::ErrorQueueTo(&mut m as *mut _ as usize))
            .unwrap_err(),
        EFAULT
    );
    assert_eq!(a.sockets[&client].completions.front(), Some(&original));
    let mut out = vec![0; payload.len()];
    v.iov_base = out.as_mut_ptr().cast();
    m.msg_control = std::ptr::dangling_mut::<c_void>();
    m.msg_controllen = 112;
    assert_eq!(
        a.execute(client, Op::ErrorQueueTo(&mut m as *mut _ as usize))
            .unwrap_err(),
        EFAULT
    );
    assert_eq!(a.sockets[&client].completions.front(), Some(&original));
    for capacity in 0..=120 {
        a.sockets.get_mut(&client).unwrap().completions.clear();
        a.sockets
            .get_mut(&client)
            .unwrap()
            .completions
            .push_back(original.clone());
        a.recount_timestamp_charge(client);
        let mut control = [0u8; 120];
        m.msg_control = control.as_mut_ptr().cast();
        m.msg_controllen = capacity;
        v.iov_len = if capacity % 2 == 0 { 0 } else { out.len() };
        let reply = a
            .execute(client, Op::ErrorQueueTo(&mut m as *mut _ as usize))
            .unwrap();
        assert_eq!(reply.value as usize, v.iov_len);
        assert_eq!(m.msg_flags & MSG_CTRUNC != 0, capacity < 112);
        assert_eq!(m.msg_flags & MSG_TRUNC != 0, v.iov_len == 0);
        if capacity >= 16 {
            assert_eq!(
                i32::from_ne_bytes(control[12..16].try_into().unwrap()),
                ts::NEW
            );
        }
        assert!(a.sockets[&client].completions.is_empty());
        assert_eq!(
            a.execute(client, Op::ErrorQueueTo(&mut m as *mut _ as usize))
                .unwrap_err(),
            EAGAIN
        );
    }
}
#[test]
fn timestamp_runtime_injected_hardware_rx_last_byte_and_tx_after_ack() {
    let (mut a, mut b, client, server, _) = pair();
    timestamp_set(
        &mut b,
        server,
        ts::RX_SOFTWARE | ts::RX_HARDWARE | ts::SOFTWARE | ts::RAW_HARDWARE | ts::OPT_RX_FILTER,
    );
    timestamp_set(
        &mut a,
        client,
        ts::TX_HARDWARE
            | ts::TX_SOFTWARE
            | ts::OPT_TX_SWHW
            | ts::SOFTWARE
            | ts::RAW_HARDWARE
            | ts::OPT_TSONLY,
    );
    a.execute(client, Op::Write(b"abcdef".to_vec())).unwrap();
    let now = a.now();
    let pair = ClockPair::sample(&mut a).unwrap();
    let mut bytes = [0; 1480];
    let tx = a
        .endpoint
        .poll_transmit(now, &mut bytes, 32)
        .unwrap()
        .packet
        .unwrap();
    a.drain_timestamps(pair);
    a.software_transmitted(tx.tx_timestamp, 1234567890);
    let stamps = ntcp::RxPacketTimestamps {
        software: Some(ntcp::RxTimestamp {
            value: 2_000_000_010,
            clock: ntcp::TimestampClock::RealtimeNanoseconds,
        }),
        hardware: Some(ntcp::RxTimestamp {
            value: 3_000_000_020,
            clock: ntcp::TimestampClock::DeviceTicks {
                identity: 7,
                units_per_second: Some(1_000_000_000),
            },
        }),
    };
    b.input_stamped(b.now(), tx.ip, 0, &bytes[..tx.len], stamps)
        .unwrap();
    let expected = ts::timestamps(Some(2_000_000_010), Some(3_000_000_020));
    assert_eq!(
        b.execute(server, Op::RxTimestamp(2)).unwrap().bytes,
        expected
    );
    assert_eq!(b.execute(server, Op::Peek(2)).unwrap().bytes, b"ab");
    assert_eq!(
        b.execute(server, Op::RxTimestamp(2)).unwrap().bytes,
        expected
    );
    b.execute(server, Op::Read(2)).unwrap();
    assert_eq!(
        b.execute(server, Op::RxTimestamp(4)).unwrap().bytes,
        expected
    );
    pump(&mut a, &mut b);
    std::thread::sleep(std::time::Duration::from_millis(220));
    b.endpoint.on_timeout(b.now(), 32).unwrap();
    pump(&mut a, &mut b);
    a.endpoint
        .report_tx_timestamp(
            tx.tx_timestamp.unwrap(),
            ntcp::TxTimestampSource::Hardware,
            4_000_000_030,
            ntcp::TxTimestampClock::DeviceTicks {
                identity: 7,
                units_per_second: Some(1_000_000_000),
            },
        )
        .unwrap();
    let current = ClockPair::sample(&mut a).unwrap();
    a.drain_timestamps(current);
    let records = timestamp_records(&a, client);
    assert_eq!(records.len(), 2);
    assert_eq!((records[0].2, records[0].3), (1234567890, 0));
    assert_eq!((records[1].2, records[1].3), (0, 4_000_000_030));
    timestamp_set(
        &mut b,
        server,
        ts::SOFTWARE | ts::RAW_HARDWARE | ts::OPT_RX_FILTER,
    );
    assert!(
        b.execute(server, Op::RxTimestamp(4))
            .unwrap()
            .bytes
            .is_empty()
    );
}

#[test]
fn timestamp_runtime_listener_snapshot_covers_preaccept_bytes() {
    let mut a = owner(2);
    let mut b = owner(3);
    let listener = new(&mut b, SOCK_NONBLOCK);
    timestamp_set(
        &mut b,
        listener,
        ts::RX_SOFTWARE | ts::SOFTWARE | ts::OPT_RX_FILTER,
    );
    b.execute(listener, Op::Bind("10.73.0.3:16379".parse().unwrap()))
        .unwrap();
    b.execute(listener, Op::Listen(4)).unwrap();
    let Handle::Listener(lid) = b.sockets[&listener].handle else {
        unreachable!()
    };
    assert_eq!(
        b.endpoint.listener_rx_timestamp_capacity(lid).unwrap(),
        timestamps::PHASES
    );
    let client = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(client, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    pump(&mut a, &mut b);
    // Options are an admission snapshot, not whatever the listener says at accept.
    timestamp_set(&mut b, listener, 0);
    a.execute(client, Op::Write(b"before accept".to_vec()))
        .unwrap();
    pump(&mut a, &mut b);
    let child = b
        .execute(listener, Op::Accept(SOCK_NONBLOCK))
        .unwrap()
        .value as u64;
    assert_eq!(
        b.sockets[&child].timestamps.options.flags,
        ts::RX_SOFTWARE | ts::SOFTWARE | ts::OPT_RX_FILTER
    );
    assert!(
        !b.execute(child, Op::RxTimestamp(13))
            .unwrap()
            .bytes
            .is_empty()
    );
    timestamp_set(
        &mut b,
        child,
        ts::OPT_ID | ts::OPT_ID_TCP | ts::TX_SOFTWARE | ts::SOFTWARE | ts::OPT_TSONLY,
    );
    b.execute(child, Op::Write(vec![1, 2, 3])).unwrap();
    pump(&mut a, &mut b);
    assert_eq!(timestamp_records(&b, child)[0].1, 2);
}

#[test]
fn timestamp_runtime_generation_reporting_and_syn_id_bases() {
    for tcp_id in [false, true] {
        let mut a = owner(2);
        let mut b = owner(3);
        let listener = new(&mut b, SOCK_NONBLOCK);
        b.execute(listener, Op::Bind("10.73.0.3:16379".parse().unwrap()))
            .unwrap();
        b.execute(listener, Op::Listen(4)).unwrap();
        let client = new(&mut a, SOCK_NONBLOCK);
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
            .unwrap();
        assert_eq!(
            a.execute(client, Op::Connect("10.73.0.3:16379".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        let flags = ts::TX_SOFTWARE
            | ts::SOFTWARE
            | ts::OPT_ID
            | ts::OPT_TSONLY
            | if tcp_id { ts::OPT_ID_TCP } else { 0 };
        timestamp_set(&mut a, client, flags);
        pump(&mut a, &mut b);
        a.execute(client, Op::Write(vec![1, 2, 3])).unwrap();
        pump(&mut a, &mut b);
        assert_eq!(
            timestamp_records(&a, client)[0].1,
            if tcp_id { 2 } else { 3 }
        );
        a.sockets.get_mut(&client).unwrap().completions.clear();
        a.recount_timestamp_charge(client);
        timestamp_set(&mut a, client, ts::TX_SOFTWARE | ts::OPT_TSONLY);
        a.execute(client, Op::Write(vec![4])).unwrap();
        pump(&mut a, &mut b);
        assert_eq!(a.sockets[&client].completions.len(), 1);
        // Generation still queues ENOMSG, reporting disabled omits only the timestamp CMSG.
        let mut control = [0u8; 128];
        let mut message: msghdr = unsafe { std::mem::zeroed() };
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = 128;
        a.execute(client, Op::ErrorQueueTo(&mut message as *mut _ as usize))
            .unwrap();
        assert_eq!(message.msg_controllen, 48);
        assert_eq!(
            i32::from_ne_bytes(control[8..12].try_into().unwrap()),
            SOL_IP
        );
        assert!(a.sockets[&client].completions.is_empty());
        timestamp_set(&mut a, client, ts::SOFTWARE | ts::OPT_TSONLY);
        a.execute(client, Op::Write(vec![5])).unwrap();
        pump(&mut a, &mut b);
        assert!(a.sockets[&client].completions.is_empty());
        assert_eq!(
            a.execute(
                client,
                Op::Set(SOL_SOCKET, 37, (ts::TX_SOFTWARE | ts::TX_HARDWARE) as i32)
            )
            .unwrap_err(),
            EOPNOTSUPP
        );
    }
}

// Thread-local fault injection does not disturb parallel tests or the harness.
pub(super) mod timestamp_allocator {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    std::thread_local! { static FAIL: Cell<Option<usize>> = const { Cell::new(None) }; }
    struct Allocator;
    #[global_allocator]
    static ALLOCATOR: Allocator = Allocator;
    unsafe impl GlobalAlloc for Allocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if should_fail() {
                std::ptr::null_mut()
            } else {
                unsafe { System.alloc(layout) }
            }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            if should_fail() {
                std::ptr::null_mut()
            } else {
                unsafe { System.realloc(ptr, layout, size) }
            }
        }
    }
    fn should_fail() -> bool {
        FAIL.try_with(|remaining| match remaining.get() {
            None => false,
            Some(0) => true,
            Some(n) => {
                remaining.set(Some(n - 1));
                false
            }
        })
        .unwrap_or(false)
    }
    pub(crate) fn failing<T>(f: impl FnOnce() -> T) -> T {
        fail_after(0, f)
    }
    pub(crate) fn fail_after<T>(count: usize, f: impl FnOnce() -> T) -> T {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                FAIL.set(None);
            }
        }
        FAIL.set(Some(count));
        let _reset = Reset;
        f()
    }
}

#[test]
fn timestamp_runtime_pending_and_queued_ids_use_different_option_epochs() {
    let (mut a, mut b, client, _, _) = pair();
    let flags = ts::TX_SCHED
        | ts::TX_HARDWARE
        | ts::TX_ACK
        | ts::SOFTWARE
        | ts::RAW_HARDWARE
        | ts::OPT_ID
        | ts::OPT_ID_TCP
        | ts::OPT_TSONLY;
    timestamp_set(&mut a, client, flags);
    a.execute(client, Op::Write(b"first".to_vec())).unwrap();
    let mut bytes = [0; 1480];
    let tx = a
        .endpoint
        .poll_transmit(a.now(), &mut bytes, 32)
        .unwrap()
        .packet
        .unwrap();
    let frame = ip_packet(&a, tx, &bytes[..tx.len]);
    a.timestamp_packet(tx.tx_timestamp, &frame);
    let current = ClockPair::sample(&mut a).unwrap();
    a.drain_timestamps(current);
    assert_eq!(timestamp_records(&a, client)[0].1, 4);
    timestamp_set(&mut a, client, ts::OPT_TSONLY);
    a.endpoint
        .report_tx_timestamp(
            tx.tx_timestamp.unwrap(),
            ntcp::TxTimestampSource::Hardware,
            17,
            ntcp::TxTimestampClock::RealtimeNanoseconds,
        )
        .unwrap();
    let current = ClockPair::sample(&mut a).unwrap();
    a.drain_timestamps(current);
    assert_eq!(timestamp_records(&a, client)[1].1, 0);
    timestamp_set(&mut a, client, flags);
    b.input(b.now(), tx.ip, 0, &bytes[..tx.len]).unwrap();
    pump(&mut a, &mut b);
    std::thread::sleep(std::time::Duration::from_millis(220));
    b.endpoint.on_timeout(b.now(), 32).unwrap();
    pump(&mut a, &mut b);
    assert_eq!(
        timestamp_records(&a, client)
            .iter()
            .map(|r| (r.0, r.1))
            .collect::<Vec<_>>(),
        [(1, 4), (0, 0), (2, u32::MAX)]
    );
    timestamp_set(&mut a, client, 0);
    assert_eq!(timestamp_records(&a, client)[2].1, u32::MAX);
}

#[test]
fn timestamp_runtime_pending_tsonly_toggles_keep_actual_packet_or_drop_honestly() {
    for (initial_tsonly, final_tsonly, starve) in [
        (true, false, false),
        (false, true, false),
        (true, false, true),
        (true, true, true),
    ] {
        let (mut a, mut b, client, _, _) = pair();
        let flags = ts::TX_HARDWARE | ts::TX_ACK | ts::SOFTWARE | ts::RAW_HARDWARE;
        timestamp_set(
            &mut a,
            client,
            flags | if initial_tsonly { ts::OPT_TSONLY } else { 0 },
        );
        a.execute(client, Op::Write(b"real retained packet".to_vec()))
            .unwrap();
        let mut bytes = [0; 1480];
        let tx = a
            .endpoint
            .poll_transmit(a.now(), &mut bytes, 32)
            .unwrap()
            .packet
            .unwrap();
        let frame = ip_packet(&a, tx, &bytes[..tx.len]);
        let capacity = a.sockets[&client].receive_capacity;
        if starve {
            a.sockets.get_mut(&client).unwrap().receive_capacity = 1;
        }
        a.timestamp_packet(tx.tx_timestamp, &frame);
        a.sockets.get_mut(&client).unwrap().receive_capacity = capacity;
        timestamp_set(
            &mut a,
            client,
            flags | if final_tsonly { ts::OPT_TSONLY } else { 0 },
        );
        b.input(b.now(), tx.ip, 0, &bytes[..tx.len]).unwrap();
        pump(&mut a, &mut b);
        std::thread::sleep(std::time::Duration::from_millis(220));
        b.endpoint.on_timeout(b.now(), 32).unwrap();
        pump(&mut a, &mut b);
        a.endpoint
            .report_tx_timestamp(
                tx.tx_timestamp.unwrap(),
                ntcp::TxTimestampSource::Hardware,
                123,
                ntcp::TxTimestampClock::RealtimeNanoseconds,
            )
            .unwrap();
        let pair = ClockPair::sample(&mut a).unwrap();
        timestamp_allocator::failing(|| a.drain_timestamps(pair));
        let records = timestamp_records(&a, client);
        if starve && !final_tsonly {
            assert!(records.is_empty());
        } else {
            assert_eq!(records.len(), 2);
            assert_eq!((records[0].0, records[1].0), (2, 0));
            for completion in &a.sockets[&client].completions {
                let Completion::Timestamp { payload, .. } = completion else {
                    unreachable!()
                };
                assert_eq!(
                    &payload[..],
                    if final_tsonly { &[][..] } else { &frame[..] }
                );
            }
        }
        assert_eq!(a.sockets[&client].timestamps.reserved(), 0);
        let queued = a.sockets[&client].completions.clone();
        timestamp_set(
            &mut a,
            client,
            flags | if final_tsonly { 0 } else { ts::OPT_TSONLY },
        );
        assert_eq!(a.sockets[&client].completions, queued);
    }
}

#[test]
fn timestamp_runtime_joint_zerocopy_reservation_is_fallible_before_acceptance() {
    let (mut a, _, client, _, _) = pair();
    timestamp_set(
        &mut a,
        client,
        ts::TX_HARDWARE | ts::RAW_HARDWARE | ts::OPT_TSONLY,
    );
    a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    // Prepare pending storage, but force the reviewed len=3/cap=4 queue case.
    a.reserve_completion(client, true, 0, None).unwrap();
    a.sockets.get_mut(&client).unwrap().completions = VecDeque::with_capacity(4);
    for n in 1..=3 {
        a.sockets
            .get_mut(&client)
            .unwrap()
            .completions
            .push_back(Completion::ZeroCopy(n, n));
    }
    a.recount_timestamp_charge(client);
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        unreachable!()
    };
    let before = a.endpoint.send_progress(cid).unwrap();
    let cookie = a.timestamp_cookie;
    assert_eq!(
        timestamp_allocator::failing(|| a.reserve_completion(client, true, MSG_ZEROCOPY, None)),
        Err(ENOBUFS)
    );
    assert_eq!(a.endpoint.send_progress(cid).unwrap(), before);
    assert_eq!(a.timestamp_cookie, cookie);
    assert_eq!(a.sockets[&client].zc_next, 0);
    a.execute(client, Op::WriteFlags(vec![1], MSG_ZEROCOPY))
        .unwrap();
    let capacity = a.sockets[&client].completions.capacity();
    assert!(capacity >= 5);
    let mut bytes = [0; 1480];
    let tx = a
        .endpoint
        .poll_transmit(a.now(), &mut bytes, 32)
        .unwrap()
        .packet
        .unwrap();
    a.endpoint
        .report_tx_timestamp(
            tx.tx_timestamp.unwrap(),
            ntcp::TxTimestampSource::Hardware,
            123,
            ntcp::TxTimestampClock::RealtimeNanoseconds,
        )
        .unwrap();
    let pair = ClockPair::sample(&mut a).unwrap();
    timestamp_allocator::failing(|| a.drain_timestamps(pair));
    assert_eq!(a.sockets[&client].completions.len(), 5);
    assert_eq!(a.sockets[&client].completions.capacity(), capacity);
}

#[test]
fn timestamp_runtime_joint_127_boundary_and_zerocopy_coalescing() {
    let (mut a, _, client, _, _) = pair();
    timestamp_set(&mut a, client, ts::TX_HARDWARE | ts::OPT_TSONLY);
    a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        unreachable!()
    };
    for n in 1..=127 {
        a.sockets
            .get_mut(&client)
            .unwrap()
            .completions
            .push_back(Completion::ZeroCopy(n, n));
    }
    a.recount_timestamp_charge(client);
    let before = a.endpoint.send_progress(cid).unwrap();
    let cookie = a.timestamp_cookie;
    assert_eq!(
        a.execute(client, Op::WriteFlags(vec![1], MSG_ZEROCOPY))
            .unwrap_err(),
        ENOBUFS
    );
    assert_eq!(a.endpoint.send_progress(cid).unwrap(), before);
    assert_eq!(a.timestamp_cookie, cookie);
    assert_eq!(a.sockets[&client].timestamps.reserved(), 0);
    assert_eq!(a.sockets[&client].zc_next, 0);
    // A contiguous last zero-copy record needs no extra slot: 127 + 1 fits.
    a.sockets.get_mut(&client).unwrap().zc_next = 128;
    a.execute(client, Op::WriteFlags(vec![1], MSG_ZEROCOPY))
        .unwrap();
    assert_eq!(a.sockets[&client].completions.len(), 127);
    assert_eq!(
        a.sockets[&client].completions.back().unwrap().range(),
        Some((127, 128))
    );
    assert_eq!(a.sockets[&client].timestamps.reserved(), 1);
    // Even a non-timestamped ZC send must count the existing native phase.
    assert_eq!(
        a.reserve_completion(client, true, MSG_ZEROCOPY, Some(0)),
        Ok(true)
    );
    a.sockets.get_mut(&client).unwrap().zc_next = 999;
    assert_eq!(
        a.reserve_completion(client, true, MSG_ZEROCOPY, Some(0)),
        Err(ENOBUFS)
    );
}

#[test]
fn timestamp_runtime_fin_does_not_replace_last_accepted_byte() {
    let (mut a, mut b, client, _, _) = pair();
    let flags = ts::TX_ACK | ts::OPT_ID | ts::OPT_ID_TCP | ts::OPT_TSONLY;
    timestamp_set(&mut a, client, flags);
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        unreachable!()
    };
    let first = a.endpoint.send_progress(cid).unwrap().next_write_sequence;
    a.execute(client, Op::WriteFlags(vec![1, 2, 3], MSG_MORE))
        .unwrap();
    a.execute(client, Op::Shutdown(SHUT_WR)).unwrap();
    timestamp_set(&mut a, client, 0);
    timestamp_set(&mut a, client, flags);
    let base = a.endpoint.send_progress(cid).unwrap().next_write_sequence;
    pump(&mut a, &mut b);
    std::thread::sleep(std::time::Duration::from_millis(220));
    b.endpoint.on_timeout(b.now(), 32).unwrap();
    pump(&mut a, &mut b);
    let records = timestamp_records(&a, client);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].1, first.wrapping_add(2).wrapping_sub(base));
}

#[test]
fn timestamp_runtime_packet_allocation_failure_preserves_tsonly_completion() {
    let (mut a, _, client, _, _) = pair();
    timestamp_set(&mut a, client, ts::TX_HARDWARE | ts::OPT_TSONLY);
    a.execute(client, Op::Write(vec![42])).unwrap();
    let mut bytes = [0; 1480];
    let tx = a
        .endpoint
        .poll_transmit(a.now(), &mut bytes, 32)
        .unwrap()
        .packet
        .unwrap();
    let frame = ip_packet(&a, tx, &bytes[..tx.len]);
    // No bytes are copied if the fallible packet reservation fails.
    let before = a.timestamp_charge();
    timestamp_allocator::failing(|| a.timestamp_packet(tx.tx_timestamp, &frame));
    assert_eq!(a.timestamp_charge(), before);
    a.endpoint
        .report_tx_timestamp(
            tx.tx_timestamp.unwrap(),
            ntcp::TxTimestampSource::Hardware,
            123,
            ntcp::TxTimestampClock::RealtimeNanoseconds,
        )
        .unwrap();
    let pair = ClockPair::sample(&mut a).unwrap();
    timestamp_allocator::failing(|| a.drain_timestamps(pair));
    assert_eq!(timestamp_records(&a, client)[0].4, 0);
    assert!(a.timestamp_charge() < before);
}

#[test]
fn timestamp_runtime_timestamp_between_zerocopy_records_prevents_coalescing() {
    let (mut a, mut b, client, _, _) = pair();
    timestamp_set(&mut a, client, ts::TX_SOFTWARE | ts::OPT_TSONLY);
    a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    a.execute(client, Op::WriteFlags(vec![1], MSG_ZEROCOPY))
        .unwrap();
    pump(&mut a, &mut b);
    assert_eq!(a.sockets[&client].completions.len(), 2);
    assert!(matches!(
        a.sockets[&client].completions.back(),
        Some(Completion::Timestamp { .. })
    ));
    a.write_timestamp(client, vec![2], MSG_ZEROCOPY, Some(0))
        .unwrap();
    assert_eq!(a.sockets[&client].completions.len(), 3);
    assert_eq!(
        a.sockets[&client].completions.front().unwrap().range(),
        Some((0, 0))
    );
    assert_eq!(
        a.sockets[&client].completions.back().unwrap().range(),
        Some((1, 1))
    );
    a.write_timestamp(client, vec![3], MSG_ZEROCOPY, Some(0))
        .unwrap();
    assert_eq!(a.sockets[&client].completions.len(), 3);
    assert_eq!(
        a.sockets[&client].completions.back().unwrap().range(),
        Some((1, 2))
    );
}
