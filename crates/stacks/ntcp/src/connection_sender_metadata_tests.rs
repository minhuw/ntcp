use super::*;
use alloc::format;

fn snapshot(a: &Connection) -> alloc::string::String {
    format!(
        "{:?} {:?} {:?} {:?} {:?} {:?} {} {} {:?}",
        a.send,
        a.rack,
        a.scoreboard,
        a.events,
        a.loss_timer,
        a.state,
        a.send_issued,
        a.send_backpressured,
        a.send_progress()
    )
}

fn metadata_bytes(a: &Connection) -> usize {
    a.rack.allocation_bytes() + a.scoreboard.storage_bytes()
}

#[test]
fn idle_sender_backing_is_independent_of_configured_payload_limit() {
    for limit in [64, 65536, 2 * 1024 * 1024] {
        let (mut a, _) = pair(config(limit, 64), 100);
        assert_eq!(a.rack.allocation_bytes(), Rack::storage_bytes(0).unwrap());
        assert_eq!(
            a.scoreboard.storage_bytes(),
            Scoreboard::allocation_bytes(0).unwrap()
        );
        let charge = a.buffer_charge();
        a.write(&[1; 18]).unwrap();
        assert_eq!(
            metadata_bytes(&a),
            Rack::storage_bytes(32).unwrap() + Scoreboard::allocation_bytes(32).unwrap()
        );
        assert_eq!(a.buffer_charge(), charge);
        assert!(metadata_bytes(&a) < 4096);
    }
}

#[test]
fn failed_growth_never_accepts_bytes_or_changes_send_boundaries() {
    for failed in 0..3 {
        let (mut a, _) = pair(config(128, 8), u32::MAX - 20);
        a.write_with_options(b"abcdefgh", true, false).unwrap();
        let before = snapshot(&a);
        assert_eq!(
            crate::allocation_tests::fail_after(failed, || a.write_with_options(
                b"ijklmnopq",
                false,
                true
            )),
            Err(Error::NoMemory)
        );
        assert_eq!(snapshot(&a), before);
        assert_eq!(a.write_with_options(b"ijklmnopq", false, true), Ok(9));
        assert_eq!(a.send.len(), 17);
    }
}

#[test]
fn metadata_peak_rejection_happens_before_allocating_or_consuming() {
    let (mut a, _) = pair(config(128, 8), 100);
    let before = snapshot(&a);
    let rejected_without_allocation = crate::allocation_tests::fail_after(0, || {
        assert_eq!(
            a.prepare_send_metadata(64, None, 0, None),
            Err(Error::NoMemory)
        );
        SendBuffer::new(1).is_err()
    });
    assert!(rejected_without_allocation);
    assert_eq!(snapshot(&a), before);
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
    a.prepare_send_metadata(20, None, usize::MAX, None).unwrap();
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
fn timestamp_request_is_not_consumed_when_metadata_growth_fails() {
    let (mut a, _) = pair(config(128, 8), 100);
    a.tx_timestamps.resize(1, usize::MAX).unwrap();
    let request = TxTimestampRequest {
        cookie: 9,
        scheduled: true,
        ..Default::default()
    };
    for failed in 0..3 {
        assert_eq!(
            crate::allocation_tests::fail_after(failed, || a
                .write_with_timestamp(&[3; 64], false, true, None, request)),
            Err(Error::NoMemory)
        );
        assert!(a.tx_timestamps.is_empty());
        assert_eq!(a.send.len(), 0);
        assert_eq!(a.tx_timestamps.admit(request), Ok(()));
    }
    assert_eq!(
        a.write_with_timestamp(&[3; 64], false, true, None, request),
        Ok(64)
    );
    assert!(!a.tx_timestamps.is_empty());
}

#[test]
fn fast_open_reserves_metadata_before_accepting_syn_payload() {
    let mut cache = crate::fast_open::FastOpen::new().unwrap();
    cache.learn(
        0,
        tuple().local.ip(),
        tuple().remote.ip(),
        wire::FastOpenCookie::new(&[7; 8]).unwrap(),
        536,
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
        assert_eq!(result, Err(Error::NoMemory));
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
        let before = snapshot(&a);
        let data = [2; 3072];
        assert_eq!(
            crate::allocation_tests::fail_after(failed, || a.write(&data)),
            Err(Error::NoMemory)
        );
        assert_eq!(snapshot(&a), before);
        assert_eq!(a.write(&data), Ok(3072));
    }
}
