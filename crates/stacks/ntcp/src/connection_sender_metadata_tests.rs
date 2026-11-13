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
    let mut cfg = config(256, 8);
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

// One-byte NODELAY writes take a ledger entry per segment. Writes grow the
// ledgers only up to the entries at which SACK splits start being refused
// (2 * (limit + 128 KiB) of send usage), so they cost at most that much
// memory: then fresh output waits for ACKs to free entries, as Linux's
// tcp_write_xmit stops when it cannot allocate the skb it would split off,
// while further writes queue their bytes, which leave coalesced.
#[test]
fn one_byte_writes_hold_at_most_the_split_bound_in_entries() {
    let mut cfg = config(16384, 1000);
    cfg.nagle = false;
    cfg.initial_window = crate::InitialWindow::Iw10;
    let (mut a, mut b) = pair(cfg, u32::MAX - 20);
    let ceiling = crate::rack::SplitBound::entries(16384) + crate::rack::SPARE;
    let mut out = [0; 2048];
    let mut segments = alloc::vec::Vec::new();
    for _ in 0..10_000 {
        assert_eq!(a.write(&[5]), Ok(1));
        while let Some(n) = a.transmit(100, &mut out).unwrap() {
            segments.push(out[..n].to_vec());
        }
        assert!(a.rack.capacity() <= ceiling);
    }
    let sent = segments.len();
    // Every entry but the spare ones holds a one-byte segment; the rest of
    // the bytes wait unsent.
    assert_eq!(a.rack.capacity(), ceiling);
    assert_eq!(a.rack.len(), ceiling - crate::rack::SPARE);
    assert_eq!(sent, a.rack.len());
    assert_eq!(a.send.len(), 10_000);
    assert_eq!(a.notsent_bytes(), 10_000 - sent);
    assert_eq!(
        metadata_bytes(&a),
        Rack::storage_bytes(ceiling).unwrap() + Scoreboard::allocation_bytes(ceiling).unwrap()
    );
    // Once the peer acknowledges them, the queued bytes leave in full
    // segments, with no more allocation.
    let ack = a.snd_nxt;
    for bytes in &segments {
        b.input(150, &wire::parse(ip(a.tuple()), bytes).unwrap())
            .unwrap();
    }
    while let Some(n) = b.transmit(150, &mut out).unwrap() {
        a.input(200, &wire::parse(ip(b.tuple()), &out[..n]).unwrap())
            .unwrap();
    }
    assert_eq!(a.snd_una, ack);
    let charged = metadata_bytes(&a);
    let n = crate::allocation_tests::fail_after(0, || a.transmit(200, &mut out))
        .unwrap()
        .unwrap();
    let segment = wire::parse(ip(a.tuple()), &out[..n]).unwrap();
    assert_eq!(segment.payload.len(), 1000);
    assert_eq!(metadata_bytes(&a), charged);
}
