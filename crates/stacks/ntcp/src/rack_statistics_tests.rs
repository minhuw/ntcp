use super::*;
use alloc::vec;

fn commit(rack: &mut Rack, start: Seq, end: Seq, now: u64, retry: bool) {
    rack.transmit(start, end, now, retry);
    let token = rack.departure_selection().unwrap();
    assert!(rack.commit_departure(token, start, end, now));
}

#[test]
fn statistics_physical_boundaries_partial_sacks_cumulative_and_wrap() {
    for base in [Seq(0), Seq(u32::MAX - 15)] {
        let seq = |n| base.wrapping_add(n);
        let mut rack = Rack::with_capacity(64).unwrap();
        let mut scoreboard = Scoreboard::with_capacity(64).unwrap();
        rack.transmit(base, seq(30), 0, false);
        let token = rack.departure_selection().unwrap();
        // A single logical admission becomes three physical GSO/MTU segments.
        for (start, end) in [(0, 7), (7, 19), (19, 30)] {
            assert!(rack.commit_departure(token, seq(start), seq(end), 10));
        }
        assert_eq!(rack.counts().unacked, 1); // Never use this logical count.
        assert_eq!(rack.delivered_segments, 0);
        for (ack, blocks, expected) in [
            (3, vec![], 0),
            (7, vec![(25, 30)], 1),
            (7, vec![(19, 25)], 2), // Completes the retained suffix SACK.
            (7, vec![(19, 30)], 2), // Duplicate SACK.
            (8, vec![], 2),
            (30, vec![], 3),
            (30, vec![(19, 30)], 3), // DSACK is not new delivery.
        ] {
            let blocks: Vec<_> = blocks
                .into_iter()
                .map(|(l, r)| (seq(l).0, seq(r).0))
                .collect();
            sack(
                &mut rack,
                &mut scoreboard,
                seq(ack).0,
                seq(30).0,
                100,
                &blocks,
            );
            assert_eq!(rack.delivered_segments, expected);
            assert!(rack.delivered_segments_valid);
        }
    }
}

#[test]
fn statistics_rto_reneging_keeps_packet_credit_independent_of_byte_credit() {
    let mut rack = Rack::with_capacity(64).unwrap();
    let mut scoreboard = Scoreboard::with_capacity(64).unwrap();
    for (start, end) in [(0, 10), (10, 20)] {
        commit(&mut rack, Seq(start), Seq(end), 0, false);
    }
    assert_eq!(
        sack(&mut rack, &mut scoreboard, 0, 20, 100, &[(10, 20)]),
        10
    );
    assert_eq!(rack.delivered_segments, 1);
    rack.rto(1000, Seq(0), Some(100));
    scoreboard.clear();
    commit(&mut rack, Seq(0), Seq(10), 1100, true);
    commit(&mut rack, Seq(10), Seq(20), 1100, true);
    // Existing PRR byte accounting intentionally renews delivery after RTO;
    // cumulative packet evidence never counts the previously SACKed packet twice.
    assert_eq!(sack(&mut rack, &mut scoreboard, 20, 20, 1200, &[]), 20);
    assert_eq!(rack.delivered_segments, 2);
    assert!(rack.delivered_segments_valid);
}

#[test]
fn statistics_partial_cumulative_then_suffix_retry_is_one_packet() {
    for base in [Seq(0), Seq(u32::MAX - 5)] {
        let seq = |n| base.wrapping_add(n);
        let mut rack = Rack::with_capacity(64).unwrap();
        let mut scoreboard = Scoreboard::with_capacity(64).unwrap();
        commit(&mut rack, base, seq(20), 0, false);
        sack(&mut rack, &mut scoreboard, seq(9).0, seq(20).0, 100, &[]);
        assert_eq!(rack.delivered_segments, 0);
        commit(&mut rack, seq(9), seq(20), 1000, true);
        sack(&mut rack, &mut scoreboard, seq(20).0, seq(20).0, 2000, &[]);
        assert_eq!(rack.delivered_segments, 1);
        assert!(rack.delivered_segments_valid);
    }
}

#[test]
fn statistics_full_retry_resegmentation_counts_accepted_packets_not_mss() {
    let mut rack = Rack::with_capacity(64).unwrap();
    let mut scoreboard = Scoreboard::with_capacity(64).unwrap();
    commit(&mut rack, Seq(0), Seq(30), 0, false);
    rack.rto(1000, Seq(0), Some(100));
    rack.transmit(Seq(0), Seq(30), 1100, true);
    let token = rack.departure_selection().unwrap();
    assert!(rack.commit_departure(token, Seq(0), Seq(7), 1200));
    assert!(!rack.commit_departure(token, Seq(0), Seq(7), 1300));
    assert_eq!(rack.delivered_segments, 0);
    assert!(rack.commit_departure(token, Seq(7), Seq(19), 1300));
    assert!(rack.commit_departure(token, Seq(19), Seq(30), 1400));
    sack(&mut rack, &mut scoreboard, 30, 30, 2000, &[]);
    assert_eq!(rack.delivered_segments, 3);
    assert!(rack.delivered_segments_valid);
}

#[test]
fn statistics_unsubmitted_suffix_and_failed_selection_cannot_deliver() {
    let mut rack = Rack::with_capacity(64).unwrap();
    let mut scoreboard = Scoreboard::with_capacity(64).unwrap();
    rack.transmit(Seq(0), Seq(30), 0, false);
    let token = rack.departure_selection().unwrap();
    assert!(!rack.commit_departure(token, Seq(0), Seq(31), 10));
    assert_eq!(rack.delivered_segments, 0);
    assert!(rack.commit_departure(token, Seq(0), Seq(7), 10));
    sack(&mut rack, &mut scoreboard, 7, 30, 100, &[]);
    assert_eq!(rack.delivered_segments, 1);
    // Synthetic ACK of an unsubmitted suffix must never manufacture delivery.
    sack(&mut rack, &mut scoreboard, 30, 30, 200, &[]);
    assert_eq!(rack.delivered_segments, 1);
}

#[test]
fn statistics_overlapping_retry_reports_unavailable_without_changing_recovery() {
    for retry in [(0, 9), (9, 20), (5, 15)] {
        let mut rack = Rack::with_capacity(64).unwrap();
        let mut scoreboard = Scoreboard::with_capacity(64).unwrap();
        commit(&mut rack, Seq(0), Seq(20), 0, false);
        rack.transmit(Seq(retry.0), Seq(retry.1), 1000, true);
        let token = rack.departure_selection().unwrap();
        assert!(rack.delivered_segments_valid); // Selection is not acceptance.
        assert!(!rack.commit_departure(token, Seq(retry.0), Seq(21), 1000));
        assert!(rack.delivered_segments_valid);
        let counts = rack.counts();
        let pipe = rack.pipe();
        assert!(rack.commit_departure(token, Seq(retry.0), Seq(retry.1), 1000));
        assert!(!rack.delivered_segments_valid);
        assert!(rack.valid());
        assert_eq!(rack.pipe(), pipe);
        assert_eq!(rack.counts().unacked, counts.unacked);
        assert_eq!(sack(&mut rack, &mut scoreboard, 20, 20, 2000, &[]), 20);
        assert_eq!(rack.delivered_segments, 0); // Known prefix, not a guessed total.
        assert!(!rack.delivered_segments_valid); // Does not recover with flight drain.
        commit(&mut rack, Seq(20), Seq(30), 3000, false);
        sack(&mut rack, &mut scoreboard, 30, 30, 4000, &[]);
        assert_eq!(rack.delivered_segments, 0);
    }
}

#[test]
fn statistics_abandonment_and_skipped_inference_are_sticky_and_count_saturates() {
    let mut rack = Rack::with_capacity(64).unwrap();
    let mut scoreboard = Scoreboard::with_capacity(64).unwrap();
    rack.delivered_segments = u64::MAX;
    commit(&mut rack, Seq(0), Seq(10), 0, false);
    sack(&mut rack, &mut scoreboard, 10, 10, 100, &[]);
    assert_eq!(rack.delivered_segments, u64::MAX);
    commit(&mut rack, Seq(10), Seq(20), 200, false);
    rack.trim_cumulative(Seq(20)); // SACK fallback bypassed ACK inference.
    assert!(!rack.delivered_segments_valid);
    assert!(rack.valid());
    rack.abandon(Seq(20));
    rack.trim_cumulative(Seq(20));
    assert!(rack.valid());
    assert!(!rack.delivered_segments_valid);
}
