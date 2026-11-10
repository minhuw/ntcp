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
fn statistics_overlapping_retry_repacketizes_delivery_without_changing_recovery() {
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
        assert!(rack.delivered_segments_valid);
        assert!(rack.valid());
        assert_eq!(rack.pipe(), pipe);
        assert_eq!(rack.counts().unacked, counts.unacked);
        assert_eq!(sack(&mut rack, &mut scoreboard, 20, 20, 2000, &[]), 20);
        let units = if retry == (5, 15) { 3 } else { 2 };
        assert_eq!(rack.delivered_segments, units);
        assert!(rack.delivered_segments_valid);
        sack(&mut rack, &mut scoreboard, 20, 20, 2001, &[]);
        assert_eq!(rack.delivered_segments, units);
        commit(&mut rack, Seq(20), Seq(30), 3000, false);
        sack(&mut rack, &mut scoreboard, 30, 30, 4000, &[]);
        assert_eq!(rack.delivered_segments, units + 1);
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
    rack.trim_cumulative(Seq(20)); // Cumulative statistics do not need RACK inference.
    assert!(rack.delivered_segments_valid);
    assert!(rack.valid());
    rack.abandon(Seq(20));
    rack.trim_cumulative(Seq(20));
    assert!(rack.valid());
    assert!(!rack.delivered_segments_valid);
}

#[test]
fn statistics_mixed_credit_is_checked_per_accepted_packet_not_reservation() {
    for ends in [&[10, 20][..], &[4, 10, 20][..], &[20][..]] {
        let mut rack = Rack::with_capacity(64).unwrap();
        let mut scoreboard = Scoreboard::with_capacity(64).unwrap();
        commit(&mut rack, Seq(0), Seq(10), 0, false);
        commit(&mut rack, Seq(10), Seq(20), 0, false);
        sack(&mut rack, &mut scoreboard, 0, 20, 100, &[(10, 20)]);
        assert_eq!(rack.delivered_segments, 1);
        rack.rto(1000, Seq(0), Some(100));
        scoreboard.clear();
        rack.transmit(Seq(0), Seq(20), 1100, true);
        let token = rack.departure_selection().unwrap();
        assert!(rack.delivered_segments_valid); // Selection alone is not evidence.
        assert!(!rack.commit_departure(token, Seq(0), Seq(21), 1200));
        assert!(rack.delivered_segments_valid);
        let mut start = Seq(0);
        for &end in ends {
            assert!(rack.commit_departure(token, start, Seq(end), 1200));
            assert!(rack.delivered_segments_valid);
            start = Seq(end);
        }
        assert_eq!(sack(&mut rack, &mut scoreboard, 20, 20, 2000, &[]), 20);
        assert_eq!(
            rack.delivered_segments,
            if ends.len() == 1 {
                2
            } else {
                ends.len() as u64
            }
        );
        assert!(rack.valid());
    }
}

#[test]
fn statistics_fin_credit_follows_the_credited_packet_not_an_uncredited_old_copy() {
    for credited_before_data_only_replacement in [false, true] {
        let mut rack = Rack::with_capacity(64).unwrap();
        let mut scoreboard = Scoreboard::with_capacity(64).unwrap();
        commit(&mut rack, Seq(0), Seq(10), 0, false);
        rack.record_fin_payload(Seq(0), Seq(10));
        if credited_before_data_only_replacement {
            sack(&mut rack, &mut scoreboard, 0, 10, 100, &[(0, 10)]);
        }
        rack.rto(1000, Seq(0), Some(100));
        scoreboard.clear();
        rack.transmit(Seq(0), Seq(10), 1100, true);
        assert!(rack.intervals[0].stats_flag(PACKET_INCLUDES_FIN)); // Selection cannot change attribution.
        let token = rack.departure_selection().unwrap();
        assert!(!rack.commit_departure(token, Seq(0), Seq(11), 1200));
        assert!(rack.intervals[0].stats_flag(PACKET_INCLUDES_FIN));
        assert!(rack.commit_departure(token, Seq(0), Seq(10), 1200)); // No FIN in this copy.
        sack(&mut rack, &mut scoreboard, 0, 10, 1300, &[(0, 10)]);
        assert_eq!(rack.delivered_segments, 1);
        assert_eq!(
            rack.intervals[0].stats_flag(PACKET_INCLUDES_FIN),
            credited_before_data_only_replacement
        );
        rack.rto(2000, Seq(0), Some(100));
        scoreboard.clear();
        commit(&mut rack, Seq(0), Seq(10), 2100, true);
        rack.record_fin_payload(Seq(0), Seq(10));
        assert!(rack.delivered_segments_valid);
        sack(&mut rack, &mut scoreboard, 10, 10, 2200, &[]);
        assert_eq!(rack.delivered_segments, 1);
    }
}

#[test]
fn statistics_interval_fits_original_allocation_budget() {
    let size = core::mem::size_of::<Interval>();
    assert!(size <= 64, "Interval grew to {size} bytes");
    assert_eq!(
        Rack::storage_bytes(400_000),
        Some(
            400_002 * size
                + 400_002_usize.div_ceil(64 * 1024 / size) * core::mem::size_of::<Vec<Interval>>()
        )
    );
    assert!(Rack::storage_bytes(400_000).unwrap() <= 26_000_000);
}

#[test]
fn statistics_flags_split_and_update_independently() {
    for base in [Seq(0), Seq(u32::MAX - 5)] {
        for flags in 0..8 {
            let mut rack = Rack::with_capacity(2).unwrap();
            commit(&mut rack, base, base.wrapping_add(10), 10, false);
            rack.intervals[0].stats_flags = flags;
            let original = rack.intervals[0];
            assert!(rack.split(base.wrapping_add(5)));
            assert_eq!(
                rack.intervals[0],
                Interval {
                    end: base.wrapping_add(5),
                    ..original
                }
            );
            assert_eq!(
                rack.intervals[1],
                Interval {
                    start: base.wrapping_add(5),
                    ..original
                }
            );
            for bit in [PACKET_DELIVERED, PACKET_INCLUDES_FIN, SYN_PAYLOAD] {
                assert_eq!(original.stats_flag(bit), flags & bit != 0);
                for index in 0..2 {
                    let before = rack.intervals[index];
                    let sibling = rack.intervals[1 - index];
                    for value in [true, false] {
                        rack.intervals[index].set_stats_flag(bit, value);
                        assert_eq!(rack.intervals[index].stats_flag(bit), value);
                        assert_eq!(
                            rack.intervals[index],
                            Interval {
                                stats_flags: if value {
                                    before.stats_flags | bit
                                } else {
                                    before.stats_flags & !bit
                                },
                                ..before
                            }
                        );
                        assert_eq!(rack.intervals[1 - index], sibling);
                    }
                    rack.intervals[index] = before;
                }
            }
        }
    }
}

#[test]
fn statistics_syn_payload_pmtu_partial_retry_retains_packet_count_and_byte_ledger() {
    for base in [Seq(1), Seq(u32::MAX - 500)] {
        for first_len in [760, 800] {
            let seq = |n| base.wrapping_add(n);
            let mut rack = Rack::with_capacity(32).unwrap();
            commit(&mut rack, base, seq(1000), 0, false);
            rack.record_syn_payload(base, seq(1000));
            assert!(rack.delivered_segments_valid);
            // SYN-only ACK leaves all SYN payload outstanding. The first
            // smaller retry overlaps the original 1000-byte packet identity.
            rack.transmit(base, seq(first_len), 20, true);
            let first = rack.departure_selection().unwrap();
            assert!(rack.delivered_segments_valid); // Not committed yet.
            assert!(rack.commit_departure(first, base, seq(first_len), 20));
            assert!(rack.delivered_segments_valid);
            assert!(rack.valid());
            commit(&mut rack, seq(first_len), seq(1000), 20, true);
            let mut scoreboard = Scoreboard::with_capacity(32).unwrap();
            assert_eq!(
                sack(
                    &mut rack,
                    &mut scoreboard,
                    seq(1000).0,
                    seq(1000).0,
                    40,
                    &[]
                ),
                1000
            );
            assert!(rack.valid());
            assert!(rack.delivered_segments_valid);
            assert_eq!(rack.delivered_segments, 2);
            assert_eq!(rack.counts().unacked, 0);
        }
    }
}

#[test]
fn statistics_overlapping_repacketization_sack_and_ack_keep_independent_units() {
    for base in [Seq(0), Seq(u32::MAX - 6)] {
        let seq = |n| base.wrapping_add(n);
        let mut rack = Rack::with_capacity(64).unwrap();
        let mut scoreboard = Scoreboard::with_capacity(64).unwrap();
        commit(&mut rack, base, seq(12), 0, false);
        commit(&mut rack, base, seq(8), 10, true);
        commit(&mut rack, seq(4), seq(12), 20, true);
        // Current queued units are [0,4) and [4,12), independent of the
        // old [0,8) latest transmission still retained for the first bytes.
        sack(
            &mut rack,
            &mut scoreboard,
            base.0,
            seq(12).0,
            30,
            &[(seq(4).0, seq(10).0)],
        );
        assert_eq!(rack.delivered_segments, 0);
        sack(
            &mut rack,
            &mut scoreboard,
            base.0,
            seq(12).0,
            40,
            &[(seq(4).0, seq(12).0)],
        );
        assert_eq!(rack.delivered_segments, 1);
        sack(&mut rack, &mut scoreboard, seq(2).0, seq(12).0, 50, &[]);
        assert_eq!(rack.delivered_segments, 1);
        sack(&mut rack, &mut scoreboard, seq(4).0, seq(12).0, 60, &[]);
        assert_eq!(rack.delivered_segments, 2);
        sack(&mut rack, &mut scoreboard, seq(12).0, seq(12).0, 70, &[]);
        sack(&mut rack, &mut scoreboard, seq(12).0, seq(12).0, 80, &[]);
        assert_eq!(rack.delivered_segments, 2);
        assert!(rack.delivered_segments_valid);
        assert!(rack.valid());
    }
}

#[test]
fn statistics_every_single_subrange_retry_counts_queued_units_once() {
    for base in [Seq(10), Seq(u32::MAX - 9)] {
        for start in 0..20 {
            for end in start + 1..=20 {
                let seq = |n| base.wrapping_add(n);
                let mut rack = Rack::with_capacity(64).unwrap();
                let mut scoreboard = Scoreboard::with_capacity(64).unwrap();
                commit(&mut rack, base, seq(20), 0, false);
                commit(&mut rack, seq(start), seq(end), 100, true);
                let units = 1 + u64::from(start != 0) + u64::from(end != 20);
                for ack in 1..=20 {
                    sack(&mut rack, &mut scoreboard, seq(ack).0, seq(20).0, 200, &[]);
                    let expected = u64::from(start != 0 && ack >= start)
                        + u64::from(ack >= end)
                        + u64::from(end != 20 && ack == 20);
                    assert_eq!(
                        rack.delivered_segments, expected,
                        "start={start}, end={end}, ack={ack}"
                    );
                }
                sack(&mut rack, &mut scoreboard, seq(20).0, seq(20).0, 300, &[]);
                assert_eq!(rack.delivered_segments, units);
                assert!(rack.delivered_segments_valid);
            }
        }
    }
}

#[test]
fn physical_packet_counts_keep_logical_admissions_and_retry_units_separate() {
    for base in [Seq(0), Seq(u32::MAX - 12)] {
        let seq = |n| base.wrapping_add(n);
        let mut rack = Rack::with_capacity(64).unwrap();
        let mut scoreboard = Scoreboard::with_capacity(64).unwrap();
        rack.transmit(base, seq(40), 0, false);
        let token = rack.departure_selection().unwrap();
        for offset in (0..40).step_by(10) {
            assert!(rack.commit_departure(token, seq(offset), seq(offset + 10), 1));
        }
        assert_eq!(rack.counts().unacked, 1);
        assert_eq!(rack.packet_counts().unacked, 4);
        sack(
            &mut rack,
            &mut scoreboard,
            base.0,
            seq(40).0,
            10,
            &[(seq(10).0, seq(35).0)],
        );
        assert_eq!(rack.counts().sacked, 0);
        assert_eq!(rack.packet_counts().sacked, 2);
        assert!(rack.reo_window(false, Some(100)) > 0);
        sack(
            &mut rack,
            &mut scoreboard,
            base.0,
            seq(40).0,
            11,
            &[(seq(35).0, seq(40).0)],
        );
        assert_eq!(rack.packet_counts().sacked, 3);
        assert_eq!(rack.reo_window(false, Some(100)), 0);
        // One original packet retried in smaller pieces remains one original
        // packet. A partial cumulative ACK also cannot create a new unit.
        rack.mark_head_lost();
        assert_eq!(rack.packet_counts().lost, 1);
        for (start, end) in [(0, 4), (4, 10)] {
            commit(&mut rack, seq(start), seq(end), 20, true);
        }
        let counts = rack.packet_counts();
        assert_eq!(counts.retransmitted, 1);
        assert_eq!(counts.lost, 1);
        assert_eq!(counts.sacked, 3);
        assert_eq!(counts.unacked, 4);
        sack(&mut rack, &mut scoreboard, seq(4).0, seq(40).0, 30, &[]);
        assert_eq!(rack.packet_counts().unacked, 4);
        sack(&mut rack, &mut scoreboard, seq(10).0, seq(40).0, 31, &[]);
        assert_eq!(rack.packet_counts().unacked, 3);
        assert_eq!(rack.counts().unacked, 1);
        sack(&mut rack, &mut scoreboard, seq(40).0, seq(40).0, 40, &[]);
        assert_eq!(rack.packet_counts().unacked, 0);
    }
}

// One evidence stage per ACK in this prefix; cumulative and SACK stages
// are exercised together by the separate combined-ACK regression.
#[test]
fn reordering_events_deduplicate_each_stage_across_splits_and_wrap() {
    for base in [Seq(0), Seq(u32::MAX - 4999)] {
        for split in [false, true] {
            let seq = |n| base.wrapping_add(n);
            let mut rack = Rack::with_capacity(64).unwrap();
            let mut scoreboard = Scoreboard::with_capacity(64).unwrap();
            rack.sample(20_000, 20_000);
            for offset in (0..10_000).step_by(1000) {
                commit(&mut rack, seq(offset), seq(offset + 1000), 20_000, false);
            }
            if split {
                for offset in [125, 375, 3500] {
                    assert!(rack.split(seq(offset)));
                }
            }
            for (_event, ack, blocks, expected) in [
                ("first_sack", 0, vec![(9000, 10_000)], 0),
                ("lower_sack", 0, vec![(3000, 4000), (9000, 10_000)], 1),
                ("repeated_sack", 0, vec![(3000, 4000), (9000, 10_000)], 1),
                ("cumulative_ack", 10_000, vec![], 2),
                ("dsack_after_retirement", 10_000, vec![(3000, 4000)], 2),
            ] {
                let mut wire = [None; 4];
                for (slot, &(l, r)) in wire.iter_mut().zip(&blocks) {
                    *slot = Some((seq(l).0, seq(r).0));
                }
                let update = scoreboard.update(seq(ack), seq(10_000), &wire);
                rack.acknowledge(
                    seq(ack),
                    seq(10_000),
                    &scoreboard,
                    40_000,
                    None,
                    None,
                    1000,
                    update.dsack,
                );
                assert_eq!(rack.reordering_events, expected);
                assert_eq!(rack.reordering_seen, expected != 0);
                assert_eq!(rack.min_rtt, Some(20_000));
            }
            assert_eq!(rack.reordering, 10);
        }
    }
}

#[test]
fn reordering_events_combined_ack_counts_sack_and_cumulative_stages_separately() {
    for base in [Seq(0), Seq(u32::MAX - 4999)] {
        for split in [false, true] {
            for initial in [0, u64::MAX - 1] {
                let seq = |n| base.wrapping_add(n);
                let mut rack = Rack::with_capacity(64).unwrap();
                let mut scoreboard = Scoreboard::with_capacity(64).unwrap();
                for offset in (0..10_000).step_by(1000) {
                    commit(&mut rack, seq(offset), seq(offset + 1000), 0, false);
                }
                if split {
                    for edge in [125, 375, 3500] {
                        assert!(rack.split(seq(edge)));
                    }
                }
                sack(
                    &mut rack,
                    &mut scoreboard,
                    base.0,
                    seq(10_000).0,
                    100,
                    &[(seq(9000).0, seq(10_000).0)],
                );
                assert_eq!(rack.reordering_events, 0);
                rack.reordering_events = initial;
                for _ in 0..3 {
                    sack(
                        &mut rack,
                        &mut scoreboard,
                        seq(2000).0,
                        seq(10_000).0,
                        110,
                        &[(seq(3000).0, seq(4000).0), (seq(9000).0, seq(10_000).0)],
                    );
                    assert_eq!(rack.reordering_events, initial.saturating_add(2));
                }
                let count = rack.reordering_events;
                let minimum = rack.min_rtt();
                let mut rack = rack.grown(128).unwrap();
                assert_eq!((rack.reordering_events, rack.min_rtt()), (count, minimum));
                rack.rto(1000, seq(2000), Some(100));
                assert_eq!((rack.reordering_events, rack.min_rtt()), (count, minimum));
                rack.abandon(seq(10_000));
                assert_eq!((rack.reordering_events, rack.min_rtt()), (count, minimum));
            }
        }
    }
}

#[test]
fn reordering_events_exclude_retransmitted_originals_and_dsack_only_adaptation() {
    for prefix in [250, 1000] {
        let mut rack = Rack::with_capacity(32).unwrap();
        let mut scoreboard = Scoreboard::with_capacity(32).unwrap();
        for start in [0, 1000] {
            commit(&mut rack, Seq(start), Seq(start + 1000), 0, false);
        }
        sack(&mut rack, &mut scoreboard, 0, 2000, 100, &[(1000, 2000)]);
        commit(&mut rack, Seq(0), Seq(prefix), 110, true);
        sack(&mut rack, &mut scoreboard, 0, 2000, 210, &[(0, 2000)]);
        assert_eq!(rack.reordering_events, 0);
        sack(&mut rack, &mut scoreboard, 2000, 2000, 220, &[]);
        sack(&mut rack, &mut scoreboard, 2000, 2000, 230, &[(0, 1000)]);
        assert!(rack.reordering_seen); // DSACK adaptation remains independent.
        assert_eq!(rack.reordering_events, 0);
    }
}
