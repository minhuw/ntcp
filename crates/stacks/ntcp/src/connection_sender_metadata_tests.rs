use super::*;
use alloc::format;

// What a refused growth must leave as it was: the queued bytes, both
// ledgers and the send boundaries.
fn storage(a: &Connection) -> alloc::string::String {
    format!(
        "{:?} {:?} {:?} {:?}",
        a.send,
        a.rack,
        a.scoreboard,
        a.send_progress()
    )
}

// The bytes queued, from the first unacknowledged one.
fn queued(a: &Connection) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec![0; a.send.len()];
    let mut at = 0;
    while at < out.len() {
        at += a.send.copy(at, &mut out[at..]);
    }
    out
}

fn metadata_bytes(a: &Connection) -> usize {
    a.rack.allocation_bytes() + a.scoreboard.storage_bytes()
}

#[test]
fn idle_sender_backing_is_independent_of_configured_payload_limit() {
    for limit in [64, 65536, 2 * 1024 * 1024] {
        let (mut a, _) = pair(config(limit, 64), 100);
        assert_eq!(
            a.rack.allocation_bytes(),
            Rack::storage_bytes(crate::rack::SPARE).unwrap()
        );
        assert_eq!(
            a.scoreboard.storage_bytes(),
            Scoreboard::allocation_bytes(0).unwrap()
        );
        let charge = a.buffer_charge();
        let idle = metadata_bytes(&a);
        assert_eq!(a.send.storage_bytes(), 0);
        a.write(&[1; 18]).unwrap();
        assert_eq!(
            metadata_bytes(&a),
            Rack::storage_bytes(32).unwrap() + Scoreboard::allocation_bytes(32).unwrap()
        );
        // The first write allocates a page of ring, within the limit, and
        // is charged what it allocates.
        let ring = 2 * limit.min(SEND_RING_RESERVE / 2);
        assert_eq!(a.send.storage_bytes(), ring);
        assert_eq!(a.buffer_charge(), charge + ring + metadata_bytes(&a) - idle);
        assert!(metadata_bytes(&a) < 4096);
    }
}

// The ring grows with the bytes queued, doubling within the limit, as
// Linux's tcp_sendmsg allocates skbs as bytes are written rather than
// sk_sndbuf at once: a stream of writes grows it logarithmically many
// times, it never holds more than twice the queued bytes beyond its first
// page, and the bytes survive every growth.
#[test]
fn send_ring_grows_geometrically_within_the_limit() {
    for limit in [3000, 1 << 20] {
        let (mut a, _) = pair(config(limit, 1000), u32::MAX - 20);
        let mut written = alloc::vec::Vec::new();
        let mut held = alloc::vec::Vec::new();
        while a.send.len() < limit {
            let chunk: alloc::vec::Vec<u8> = (0..1000).map(|i| (written.len() + i) as u8).collect();
            let count = a.write(&chunk).unwrap();
            written.extend_from_slice(&chunk[..count]);
            let ring = a.send.allocation_capacity();
            assert!(ring >= a.send.len() && ring <= 2 * a.send.len().max(1024));
            assert_eq!(a.send.storage_bytes(), 2 * ring);
            if held.last() != Some(&ring) {
                held.push(ring);
            }
        }
        let expected: alloc::vec::Vec<usize> = (11..)
            .map(|shift| (1usize << shift).min(limit))
            .take_while(|&ring| ring < limit)
            .chain([limit])
            .collect();
        assert_eq!(held, expected);
        assert_eq!(queued(&a), written);
    }
}

// A write whose storage growth fails takes what the storage it could
// grow holds, as Linux's tcp_sendmsg copies until sk_wmem_schedule
// refuses: a partial write or WouldBlock, never an error. The connection
// then takes no more until memory comes back.
#[test]
fn failed_growth_takes_what_the_storage_holds() {
    for failed in 0..3 {
        let (mut a, _) = pair(config(128, 8), u32::MAX - 20);
        a.write_with_options(b"abcdefgh", true, false).unwrap();
        let taken = match crate::allocation_tests::fail_after(failed, || {
            a.write_with_options(b"ijklmnopq", false, true)
        }) {
            Ok(n) => n,
            Err(Error::WouldBlock) => 0,
            other => panic!("{other:?}"),
        };
        assert_eq!(a.send.len(), 8 + taken);
        if taken < 9 {
            assert!(a.send_memory_throttled());
            a.memory_released();
        }
        assert_eq!(
            a.write_with_options(&b"ijklmnopq"[taken..], false, true),
            Ok(9 - taken)
        );
        assert_eq!(queued(&a), b"abcdefghijklmnopq");
    }
}

#[test]
fn metadata_peak_rejection_happens_before_allocating_or_consuming() {
    let (mut a, _) = pair(config(128, 8), 100);
    let before = storage(&a);
    let rejected_without_allocation = crate::allocation_tests::fail_after(0, || {
        assert_eq!(a.prepare_send_metadata(64, None, 0, None), Ok(true));
        SendBuffer::new(1).is_err()
    });
    assert!(rejected_without_allocation);
    assert_eq!(storage(&a), before);
    // Nothing is held: the write takes nothing.
    assert!(a.send_memory_throttled());
    assert_eq!(a.write(&[1; 64]), Err(Error::WouldBlock));
}

#[test]
fn growing_with_live_sack_and_retry_history_preserves_records() {
    // The 6 entries held for 24 bytes cost 3 * ENTRY_BYTES of send usage
    // beyond the payload: a 1 KiB limit still admits the 200 bytes below.
    let mut cfg = config(1024, 8);
    cfg.sack = true;
    cfg.rack = true;
    let (mut a, _) = pair(cfg, u32::MAX - 20);
    a.write(&[1; 24]).unwrap();
    for _ in 0..3 {
        packet(&mut a, 40);
    }
    let base = a.snd_una;
    let next = a.receive.next();
    inject_sack(
        &mut a,
        50,
        next,
        base,
        ACK,
        256,
        &[],
        &[(base.wrapping_add(9).0, base.wrapping_add(15).0)],
    );
    // Retain an actual retry and split its byte interval before growing.
    a.rack.transmit(base, base.wrapping_add(3), 60, true);
    let rack = format!("{:?}", a.rack.grown(64).unwrap());
    let scoreboard = format!("{:?}", a.scoreboard.grown(64).unwrap());
    let deadline = a.loss_timer;
    let delivered = a.acknowledged;
    // 200 more bytes take 25 segments: with the 6 entries held, the
    // ledgers grow from 32 entries to 64.
    a.prepare_send_metadata(200, None, usize::MAX, None)
        .unwrap();
    assert_eq!(format!("{:?}", a.rack), rack);
    assert_eq!(format!("{:?}", a.scoreboard), scoreboard);
    assert_eq!(a.loss_timer, deadline);
    assert_eq!(a.acknowledged, delivered);
    // Exact byte ranges and duplicate delivery accounting remain valid.
    let before = a.scoreboard.ranges().to_vec();
    inject_sack(
        &mut a,
        70,
        next,
        base,
        ACK,
        256,
        &[],
        &[(base.wrapping_add(9).0, base.wrapping_add(15).0)],
    );
    assert_eq!(a.scoreboard.ranges(), before);
}

#[test]
fn prepared_write_output_ack_and_reuse_need_no_more_allocations() {
    let (mut a, mut b) = pair(config(128, 64), u32::MAX - 20);
    a.prepare_send_metadata(64, None, usize::MAX, None).unwrap();
    let retained = metadata_bytes(&a);
    let mut bytes = [0; 256];
    crate::allocation_tests::fail_after(0, || {
        assert_eq!(a.write(&[7; 64]), Ok(64));
        let n = a.transmit(40, &mut bytes).unwrap().unwrap();
        let segment = wire::parse(ip(a.tuple()), &bytes[..n]).unwrap();
        b.input(40, &segment).unwrap();
        b.timeout(300_040).unwrap();
        let n = b.transmit(300_040, &mut bytes).unwrap().unwrap();
        let ack = wire::parse(ip(b.tuple()), &bytes[..n]).unwrap();
        a.input(300_040, &ack).unwrap();
        assert_eq!(a.send.len(), 0);
        assert_eq!(a.write(&[8; 64]), Ok(64));
        assert!(a.transmit(300_050, &mut bytes).unwrap().is_some());
    });
    assert_eq!(metadata_bytes(&a), retained);
}

#[test]
fn resizing_payload_quota_does_not_eagerly_expand_sender_ledgers() {
    let (mut a, _) = pair(config(256, 8), 100);
    a.write(&[1; 18]).unwrap();
    let rack = format!("{:?}", a.rack);
    let scoreboard = format!("{:?}", a.scoreboard);
    a.set_buffer_capacities(65536, 256, usize::MAX).unwrap();
    assert_eq!(format!("{:?}", a.rack), rack);
    assert_eq!(format!("{:?}", a.scoreboard), scoreboard);
    a.set_buffer_capacities(8, 256, usize::MAX).unwrap();
    assert_eq!(a.write(b"x"), Err(Error::WouldBlock));
    assert_eq!(format!("{:?}", a.rack), rack);
    assert_eq!(format!("{:?}", a.scoreboard), scoreboard);
}

#[test]
fn empty_and_backpressured_writes_do_not_allocate_metadata() {
    let (mut a, _) = pair(config(64, 8), 100);
    let initial = metadata_bytes(&a);
    crate::allocation_tests::fail_after(0, || assert_eq!(a.write(&[]), Ok(0)));
    assert_eq!(metadata_bytes(&a), initial);
    a.write(&[1; 64]).unwrap();
    let backed = metadata_bytes(&a);
    crate::allocation_tests::fail_after(0, || assert_eq!(a.write(b"x"), Err(Error::WouldBlock)));
    assert_eq!(metadata_bytes(&a), backed);
}

#[test]
fn timestamp_request_is_consumed_only_by_the_bytes_a_refused_growth_takes() {
    let request = TxTimestampRequest {
        cookie: 9,
        scheduled: true,
        ..Default::default()
    };
    for failed in 0..3 {
        let (mut a, _) = pair(config(128, 8), 100);
        a.tx_timestamps.resize(1, usize::MAX).unwrap();
        match crate::allocation_tests::fail_after(failed, || {
            a.write_with_timestamp(&[3; 64], false, true, None, request)
        }) {
            Ok(n) => {
                assert_eq!(a.send.len(), n);
                assert!(!a.tx_timestamps.is_empty());
            }
            Err(Error::WouldBlock) => {
                assert!(a.tx_timestamps.is_empty());
                assert_eq!(a.send.len(), 0);
                a.memory_released();
                assert_eq!(
                    a.write_with_timestamp(&[3; 64], false, true, None, request),
                    Ok(64)
                );
                assert!(!a.tx_timestamps.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn fast_open_reserves_metadata_before_accepting_syn_payload() {
    let mut cache = crate::fast_open::FastOpen::new().unwrap();
    cache.learn(
        0,
        tuple().local.ip(),
        tuple().remote.ip(),
        wire::FastOpenCookie::new(&[7; 8]).unwrap(),
        Some(536),
    );
    let cached = cache.get(0, 100, tuple().local.ip(), tuple().remote.ip());
    for failure in [None, Some(0), Some(1), Some(2)] {
        let mut a = Connection::active(tuple(), config(8192, 536), 100, 0).unwrap();
        let result = match failure {
            None => a.prepare_fast_open_with_budget(cached, &[4; 64], 0),
            Some(n) => crate::allocation_tests::fail_after(n, || {
                a.prepare_fast_open_with_budget(cached, &[4; 64], usize::MAX)
            }),
        };
        // Storage refused for the data leaves a plain SYN, as Linux's
        // tcp_send_syn_data falls back when it cannot allocate the data.
        assert_eq!(result, Ok(0));
        assert!(!a.send_memory_throttled());
        assert_eq!(a.send.len(), 0);
        assert_eq!(a.fast_open_initial, 0);
        assert_eq!(a.snd_nxt, a.iss);
        assert_eq!(
            a.prepare_fast_open_with_budget(cached, &[4; 64], usize::MAX),
            Ok(64)
        );
        let bytes = packet(&mut a, 0);
        assert_eq!(
            wire::parse(ip(a.tuple()), &bytes).unwrap().payload,
            &[4; 64]
        );
    }
    let mut a = Connection::active(tuple(), config(8192, 536), 100, 0).unwrap();
    let before = metadata_bytes(&a);
    assert_eq!(a.prepare_fast_open_with_budget(None, &[4; 64], 0), Ok(0));
    assert_eq!(metadata_bytes(&a), before);
}

#[test]
fn block_growth_keeps_large_queued_writes_inside_original_pool_budget() {
    let mut cfg = config(400_000, 1460);
    cfg.receive_capacity = 65535;
    let (mut a, _) = pair(cfg, 100);
    let data = vec![5; 150_000];
    let budget = 32 * 1024 * 1024;
    for count in [150_000, 65_536, 65_536, 18_928] {
        a.prepare_send_metadata(count, None, budget, None).unwrap();
        assert_eq!(a.write(&data[..count]), Ok(count));
        assert!(a.buffer_charge() <= budget);
    }
    assert_eq!(a.send.len(), 300_000);
}

#[test]
fn failure_at_any_multiblock_growth_allocation_preserves_live_history() {
    for failed in 0..6 {
        let (mut a, _) = pair(config(8192, 1024), 100);
        a.write(&[1; 1024]).unwrap();
        packet(&mut a, 40);
        let before = queued(&a);
        let data = [2; 3072];
        let taken = match crate::allocation_tests::fail_after(failed, || a.write(&data)) {
            Ok(n) => n,
            Err(Error::WouldBlock) => 0,
            other => panic!("{other:?}"),
        };
        assert_eq!(queued(&a)[..1024], before[..]);
        assert_eq!(a.send.len(), 1024 + taken);
        if taken < 3072 {
            a.memory_released();
        }
        assert_eq!(a.write(&data[taken..]), Ok(3072 - taken));
        assert_eq!(a.send.len(), 4096);
    }
}

// Send usage (send_usage) as TransportInfo reports it, and whether a write
// is admitted, which must agree with it: room below the send space.
fn usage(a: &Connection) -> usize {
    let info = a.transport_info();
    assert_eq!(
        info.send_used < info.send_space,
        a.send_admission_room(None) != 0,
        "{info:?}"
    );
    info.send_used
}

// Data the peer acknowledges up to `ack`, with SACK `blocks`.
fn acknowledge(a: &mut Connection, now: Instant, ack: Seq, blocks: &[(u32, u32)]) {
    inject_sack(a, now, a.receive.next(), ack, ACK, 65535, &[], blocks);
}

// One-byte NODELAY writes, each leaving at once as its own segment (cwnd
// counts bytes, so its ten segments' worth admits every one) while the
// peer acknowledges none, so every byte stays queued as its own ledger
// entry. Send usage is n + ENTRY_BYTES * (n - ceil(n / MSS)) for n such
// entries, and writes stop once it reaches the limit, as Linux's
// sk_stream_memory_free stops tcp_sendmsg at sk_sndbuf by sk_wmem_queued
// (each skb's truesize): at about limit / (1 + ENTRY_BYTES) entries. A write
// is admitted while any room is left, so the last one may pass the limit
// by up to its own entry: the bound holds within 2 entries. The ledgers
// stay far below the entries at which SACK splits are refused.
#[test]
fn one_byte_writes_stop_at_the_send_limit_by_usage() {
    let limit = 16384;
    let mut cfg = config(limit, 1000);
    cfg.nagle = false;
    cfg.initial_window = crate::InitialWindow::Iw10;
    let (mut a, mut b) = pair(cfg, u32::MAX - 20);
    let mut out = [0; 2048];
    let mut segments = alloc::vec::Vec::new();
    loop {
        let before = usage(&a);
        match a.write(&[5]) {
            Ok(1) => assert!(before < limit),
            Err(Error::WouldBlock) => {
                assert!(before >= limit);
                break;
            }
            other => panic!("{other:?}"),
        }
        let n = a.transmit(100, &mut out).unwrap().unwrap();
        assert_eq!(wire::parse(ip(a.tuple()), &out[..n]).unwrap().payload, [5]);
        segments.push(out[..n].to_vec());
        assert_eq!(a.transmit(100, &mut out), Ok(None));
    }
    let entries = a.rack.len();
    let bound = limit / (1 + crate::rack::ENTRY_BYTES);
    assert!((bound..=bound + 2).contains(&entries), "{entries} {bound}");
    assert_eq!(entries, segments.len());
    assert_eq!((a.send.len(), a.notsent_bytes()), (entries, 0));
    let used = entries + crate::rack::ENTRY_BYTES * (entries - entries.div_ceil(1000));
    assert_eq!(usage(&a), used);
    assert!(used < limit + 1 + crate::rack::ENTRY_BYTES);
    assert!(a.rack.capacity() < crate::rack::SplitBound::entries(limit) / 4);
    assert!(metadata_bytes(&a) < 64 * 1024);
    assert_eq!(
        a.check_write_retry(None, TxTimestampRequest::default()),
        Err(Error::WouldBlock)
    );
    // The peer's ACK frees the room: writable again, and the next write's
    // bytes leave in a full segment with no more allocation.
    let ack = a.snd_nxt;
    for bytes in &segments {
        b.input(150, &wire::parse(ip(a.tuple()), bytes).unwrap())
            .unwrap();
    }
    a.take_events();
    while let Some(n) = b.transmit(150, &mut out).unwrap() {
        a.input(200, &wire::parse(ip(b.tuple()), &out[..n]).unwrap())
            .unwrap();
    }
    assert_eq!(a.snd_una, ack);
    assert_eq!(usage(&a), 0);
    assert!(a.take_events().writable);
    let charged = metadata_bytes(&a);
    let n = crate::allocation_tests::fail_after(0, || {
        assert_eq!(a.write(&[6; 1000]), Ok(1000));
        a.transmit(200, &mut out)
    })
    .unwrap()
    .unwrap();
    let segment = wire::parse(ip(a.tuple()), &out[..n]).unwrap();
    assert_eq!(segment.payload.len(), 1000);
    assert_eq!(metadata_bytes(&a), charged);
}

// Writes in whole segments, sent in full-size segments and acknowledged on
// segment edges: send usage is the queued payload at every step, so each
// write takes exactly the payload room (limit - queued) the send limit left
// before this rule, and the segments are those it sent.
#[test]
fn full_size_writes_are_admitted_on_payload_alone() {
    let limit = 16000;
    let mut cfg = config(limit, 1000);
    cfg.nagle = false;
    cfg.initial_window = crate::InitialWindow::Iw10;
    let (mut a, _) = pair(cfg, u32::MAX - 20);
    let base = a.snd_una;
    let mut out = [0; 2048];
    let mut sent = 0;
    let mut write = |a: &mut Connection, now: Instant, sent: &mut u32| {
        let room = limit - a.send.len();
        let taken = a.write(&[7; 3000]);
        let expected = if room == 0 {
            Err(Error::WouldBlock)
        } else {
            Ok(room.min(3000))
        };
        assert_eq!(taken, expected);
        while let Some(n) = a.transmit(now, &mut out).unwrap() {
            let segment = wire::parse(ip(a.tuple()), &out[..n]).unwrap();
            assert_eq!(segment.header.sequence, base.wrapping_add(*sent).0);
            assert_eq!(segment.payload.len(), 1000);
            *sent += 1000;
        }
        assert_eq!(usage(a), a.send.len());
    };
    for _ in 0..7 {
        write(&mut a, 100, &mut sent);
    }
    assert_eq!((a.send.len(), sent), (limit, 10_000));
    acknowledge(&mut a, 110, base.wrapping_add(2000), &[]);
    assert_eq!(usage(&a), limit - 2000);
    write(&mut a, 110, &mut sent);
    acknowledge(&mut a, 120, base.wrapping_add(5000), &[]);
    assert_eq!(usage(&a), limit - 3000);
    for _ in 0..2 {
        write(&mut a, 120, &mut sent);
    }
    assert_eq!(a.send.len(), limit);
    assert!(sent > 10_000);
}

// Full segments with a short tail. The tail of one write costs nothing
// while the queued bytes need as many full-size segments as they hold
// entries; a second such tail costs ENTRY_BYTES. Unsent bytes count an
// entry per MSS; acknowledging the short segments' run removes the charge.
#[test]
fn short_tails_charge_the_entries_beyond_full_size_segments() {
    let limit = 16384;
    let mut cfg = config(limit, 1000);
    cfg.nagle = false;
    cfg.initial_window = crate::InitialWindow::Iw10;
    let (mut a, _) = pair(cfg, u32::MAX - 20);
    let base = a.snd_una;
    let mut out = [0; 2048];
    let mut drain = |a: &mut Connection, now: Instant| {
        let mut sizes = alloc::vec::Vec::new();
        while let Some(n) = a.transmit(now, &mut out).unwrap() {
            sizes.push(wire::parse(ip(a.tuple()), &out[..n]).unwrap().payload.len());
        }
        sizes
    };
    assert_eq!(a.write(&[1; 3100]), Ok(3100));
    assert_eq!(drain(&mut a, 100), [1000, 1000, 1000, 100]);
    // 4 entries for 3,100 bytes: ceil(3.1) = 4 full-size segments.
    assert_eq!(usage(&a), 3100);
    assert_eq!(a.write(&[2; 3100]), Ok(3100));
    assert_eq!(drain(&mut a, 100), [1000, 1000, 1000, 100]);
    // 8 entries for 6,200 bytes, which need 7.
    let entry = crate::rack::ENTRY_BYTES;
    assert_eq!(usage(&a), 6200 + entry);
    assert_eq!(a.send_admission_room(None), limit - 6200 - entry);
    // 2,000 bytes not yet sent count two entries: 10 for 8,200 bytes, which
    // need 9.
    assert_eq!(a.write(&[3; 2000]), Ok(2000));
    assert_eq!(usage(&a), 8200 + entry);
    // The first write acknowledged: 6 entries for 5,100 bytes, which need 6.
    acknowledge(&mut a, 120, base.wrapping_add(3100), &[]);
    assert_eq!(usage(&a), 5100);
    assert_eq!(drain(&mut a, 120), [1000, 1000]);
    assert_eq!(usage(&a), 5100);
    // The next write takes the room left. Its 11,284 bytes count 12 entries
    // beside the 6 sent, one more than 16,384 bytes need: a write admitted
    // on the room left before it may pass the limit by one entry.
    assert_eq!(a.write(&[4; 16384]), Ok(limit - 5100));
    assert_eq!(usage(&a), limit + entry);
    assert_eq!(a.send_admission_room(None), 0);
    // Three full segments acknowledged: the 100-byte one still queued.
    acknowledge(&mut a, 130, base.wrapping_add(6100), &[]);
    assert_eq!(usage(&a), limit - 3000 + entry);
    assert_eq!(a.send_admission_room(None), 3000 - entry);
}
