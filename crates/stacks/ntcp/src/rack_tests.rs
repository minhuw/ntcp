use super::*;

#[path = "rack_statistics_tests.rs"]
mod statistics;

// Original physical wire span/time plus whether any of that original
// packet has been retransmitted.
pub(crate) fn original_packet(rack: &Rack, start: Seq) -> Option<(Seq, Seq, u64, bool)> {
    rack.intervals
        .iter()
        .find(|r| !r.start.after(start) && r.end.after(start))
        .map(|r| {
            (
                r.original_wire_start,
                r.original_wire_end,
                r.original_sent,
                r.original_retransmitted,
            )
        })
}

#[test]
fn blocked_storage_preserves_cross_block_packet_identity_and_byte_splits() {
    let mut rack = Rack::with_capacity(2048).unwrap();
    let base = Seq(u32::MAX - 1000);
    let end = base.wrapping_add(2048);
    rack.transmit(base, end, 10, false);
    let token = rack.departure_selection().unwrap();
    assert!(rack.commit_departure(token, base, end, 10));
    crate::allocation_tests::fail_after(0, || {
        for byte in 0..2048 {
            rack.transmit(
                base.wrapping_add(byte),
                base.wrapping_add(byte + 1),
                20,
                true,
            );
        }
        assert!(rack.valid());
        assert_eq!(rack.intervals.len(), 2048);
        assert_eq!(rack.counts().unacked, 1);
        assert_eq!(rack.counts().retransmitted, 1);
        assert_eq!(
            rack.head_transmission(base),
            Some((base.wrapping_add(1), 20))
        );
    });
    let first = rack.intervals.as_ptr();
    let grown = rack.prepare_growth(4094).unwrap();
    rack.commit_growth(grown, 4094);
    assert_eq!(rack.intervals.as_ptr(), first); // Full blocks never move.
    crate::allocation_tests::fail_after(0, || rack.trim_cumulative(base.wrapping_add(1500)));
    assert_eq!(rack.intervals.len(), 548);
    assert_eq!(rack.intervals[0].start, base.wrapping_add(1500));
    assert_eq!(rack.intervals.last().unwrap().end, end);
    assert_eq!(rack.counts().unacked, 1);
}

#[path = "rack_local_repair_tests.rs"]
mod local_repair;

fn sack(
    rack: &mut Rack,
    scoreboard: &mut Scoreboard,
    ack: u32,
    high: u32,
    now: u64,
    blocks: &[(u32, u32)],
) -> u32 {
    let mut wire = [None; 4];
    for (slot, &block) in wire.iter_mut().zip(blocks) {
        *slot = Some(block);
    }
    let update = scoreboard.update(Seq(ack), Seq(high), &wire);
    rack.acknowledge(
        Seq(ack),
        Seq(high),
        scoreboard,
        now,
        None,
        None,
        1000,
        update.dsack,
    )
}

#[test]
fn departure_timestamp_evidence_requires_unchanged_encoding_time() {
    for scale in [1, 1000] {
        let timebase = CallerTimebase {
            units_per_second: 1_000_000 * scale,
            ..CallerTimebase::default()
        };
        for granularity in [
            TimestampGranularity::Milliseconds,
            TimestampGranularity::Microseconds,
        ] {
            let tick = timebase.ticks_from_us(granularity.tick_us());
            let selected = 300_000 * scale;
            // One caller tick includes sub-wire-tick delays where supported.
            for delay in [0, 1, tick] {
                let accepted = selected + delay;
                for echo_time in [selected, accepted] {
                    for retransmit in [false, true] {
                        for timestamps in [None, Some(granularity)] {
                            let mut rack = Rack::with_timebase(4, timebase).unwrap();
                            rack.sample(100_000 * scale, 0);
                            if retransmit {
                                rack.transmit(Seq(0), Seq(8), 100_000 * scale, false);
                            }
                            rack.transmit(Seq(0), Seq(8), selected, retransmit);
                            let token = rack.departure_selection().unwrap();
                            assert!(rack.commit_departure(token, Seq(0), Seq(8), accepted));
                            assert_eq!(rack.intervals[0].timestamp_eligible, delay == 0);
                            assert_eq!(
                                rack.acknowledge(
                                    Seq(8),
                                    Seq(8),
                                    &Scoreboard::new(),
                                    accepted + 100_000 * scale,
                                    Some(granularity.tick_in(echo_time, timebase) as u32),
                                    timestamps,
                                    1000,
                                    false,
                                ),
                                8
                            );
                            let eligible = !retransmit || timestamps.is_none() || delay == 0;
                            assert_eq!(rack.latest, eligible.then_some((accepted, Seq(8))));
                            assert_eq!(rack.ack_sample, (!retransmit).then_some(100_000 * scale));
                            assert_eq!(rack.min_rtt, Some(100_000 * scale));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn departure_timestamp_eligibility_survives_splits_and_renews_only_on_transmit() {
    let mut rack = Rack::with_capacity(24).unwrap();
    rack.sample(100_000, 0);
    rack.transmit(Seq(0), Seq(24), 100_000, false);
    rack.transmit(Seq(0), Seq(24), 300_000, true);
    let token = rack.departure_selection().unwrap();
    // Accept a delayed middle first, then independently accept its siblings.
    assert!(rack.commit_departure(token, Seq(8), Seq(16), 300_001));
    assert!(rack.commit_departure(token, Seq(0), Seq(8), 300_000));
    assert!(rack.commit_departure(token, Seq(16), Seq(24), 301_000));
    assert_eq!(
        rack.intervals
            .iter()
            .map(|r| r.timestamp_eligible)
            .collect::<Vec<_>>(),
        [true, false, false]
    );
    let mut scoreboard = Scoreboard::new();
    scoreboard.update(Seq(0), Seq(24), &[Some((10, 14)), None, None, None]);
    assert_eq!(
        rack.acknowledge(
            Seq(0),
            Seq(24),
            &scoreboard,
            401_000,
            Some(300),
            Some(TimestampGranularity::Milliseconds),
            1000,
            false,
        ),
        4
    );
    assert_eq!(rack.latest, None);
    assert!(
        rack.intervals
            .iter()
            .filter(|r| r.start != Seq(0))
            .all(|r| !r.timestamp_eligible)
    );
    // The on-time sibling qualifies despite both delayed siblings.
    assert_eq!(
        rack.acknowledge(
            Seq(8),
            Seq(24),
            &scoreboard,
            401_000,
            Some(300),
            Some(TimestampGranularity::Milliseconds),
            1000,
            false,
        ),
        8
    );
    assert_eq!(rack.latest, Some((300_000, Seq(8))));
    // Newly encoded network retransmission renews only its exact byte span,
    // including pieces created by the earlier SACK split.
    rack.transmit(Seq(8), Seq(16), 500_000, true);
    let token = rack.departure_selection().unwrap();
    assert!(rack.commit_departure(token, Seq(8), Seq(16), 500_000));
    assert!(
        rack.intervals
            .iter()
            .all(|r| r.timestamp_eligible == (r.end.0 <= 16))
    );
    assert_eq!(
        rack.acknowledge(
            Seq(24),
            Seq(24),
            &Scoreboard::new(),
            600_000,
            Some(500),
            Some(TimestampGranularity::Milliseconds),
            1000,
            false,
        ),
        12
    );
    assert_eq!(rack.latest, Some((500_000, Seq(16))));
    assert_eq!(rack.ack_sample, None);
}

#[test]
fn departure_fresh_fragments_preserve_logical_coverage_and_wrap() {
    for base in [Seq(100), Seq(u32::MAX - 9)] {
        let seq = |n| base.wrapping_add(n);
        let mut rack = Rack::with_capacity(24).unwrap();
        rack.transmit(base, seq(24), 10, false);
        rack.commit_original_window(base, seq(24), true);
        let token = rack.departure_selection().unwrap();
        let span = rack.original_retry_span(base, seq(24)).unwrap();
        let counts = rack.counts();
        assert!(rack.commit_departure(token, seq(4), seq(12), 100));
        assert!(rack.commit_departure(token, base, seq(4), 200));
        assert_eq!(rack.head_transmission(base), Some((seq(4), 200)));
        assert_eq!(rack.head_transmission(seq(4)), Some((seq(12), 100)));
        assert_eq!(rack.head_transmission(seq(12)), Some((seq(24), 10)));
        assert_eq!(
            original_packet(&rack, base),
            Some((base, seq(4), 200, false))
        );
        assert_eq!(
            original_packet(&rack, seq(4)),
            Some((seq(4), seq(12), 100, false))
        );
        assert_eq!(rack.original_retry_span(base, seq(24)), Some(span));
        assert!(rack.commit_departure(token, seq(12), seq(24), 300));
        assert_eq!(rack.head_transmission(base), Some((seq(4), 200)));
        assert_eq!(
            original_packet(&rack, seq(12)),
            Some((seq(12), seq(24), 300, false))
        );
        assert_eq!(rack.counts().unacked, counts.unacked);
        assert_eq!(rack.counts().lost, 0);
        assert_eq!(rack.counts().retransmitted, 0);
        assert_eq!(rack.pipe(), 24);
        assert!(rack.intervals.iter().all(|r| !r.delivered
            && !r.sacked
            && !r.retransmitted
            && !r.loss_response_pending
            && r.successful_retries == 0));

        assert_eq!(rack.tail_segment(100), Some((seq(12), seq(24))));
        rack.mark_head_lost();
        assert_eq!(rack.lowest_lost(100), Some((base, seq(4))));
        assert!(
            !rack
                .intervals
                .iter()
                .find(|r| r.start == seq(4))
                .unwrap()
                .needs_retransmit
        );

        // A real retry now makes only its physical original ambiguous,
        // without splitting the original window/first-retry permission.
        rack.transmit(base, seq(2), 400, true);
        rack.commit_retry_span(base, seq(2));
        assert!(original_packet(&rack, seq(3)).unwrap().3);
        assert!(!original_packet(&rack, seq(4)).unwrap().3);
        assert_eq!(
            rack.original_retry_span(seq(4), seq(24))
                .unwrap()
                .successful_retries,
            0
        );
    }
}

#[test]
fn departure_retry_preserves_history_and_one_shot_delivery() {
    for base in [Seq(100), Seq(u32::MAX - 9)] {
        let seq = |n| base.wrapping_add(n);
        let mut rack = Rack::with_capacity(24).unwrap();
        rack.transmit(base, seq(24), 10, false);
        rack.commit_original_window(base, seq(24), true);
        rack.mark_head_lost();
        rack.transmit(base, seq(24), 20, true);
        rack.commit_retry_span(base, seq(24));
        rack.transmit(seq(4), seq(20), 30, true);
        rack.commit_retry_span(seq(4), seq(20));
        let token = rack.departure_selection().unwrap();
        // Existing delivery, SACK and loss state is not reset by departure.
        let r = &mut rack.intervals[1];
        r.delivered = true;
        r.sacked = true;
        r.needs_retransmit = true;
        r.set_stats_flag(DIAGNOSTIC_LOST, true);
        let before = *r;
        let counts = rack.counts();
        let pipe = rack.pipe();
        let original = original_packet(&rack, seq(4));
        assert!(rack.commit_departure(token, seq(8), seq(16), 100));
        let accepted = rack.intervals.iter().find(|r| r.start == seq(8)).unwrap();
        let expected = Interval {
            start: seq(8),
            end: seq(16),
            sent: 100,
            timestamp_eligible: false,
            transmission_start: seq(8),
            transmission_end: seq(16),
            departure_committed: true,
            stats_flags: (before.stats_flags | DELIVERY_END | DIAGNOSTIC_RETRY) & !DIAGNOSTIC_LOST,
            ..before
        };
        assert_eq!(*accepted, expected);
        assert_eq!(rack.head_transmission(seq(4)), Some((seq(8), 30)));
        assert_eq!(rack.head_transmission(seq(16)), Some((seq(20), 30)));
        assert_eq!(original_packet(&rack, seq(8)), original);
        assert_eq!(rack.counts().unacked, counts.unacked);
        assert_eq!(rack.counts().sacked, counts.sacked);
        assert_eq!(rack.counts().lost, counts.lost);
        assert_eq!(rack.counts().retransmitted, counts.retransmitted);
        assert_eq!(rack.pipe(), pipe);
        assert!(rack.commit_departure(token, seq(4), seq(8), 110));
        assert!(rack.commit_departure(token, seq(16), seq(20), 120));
        assert_eq!(rack.head_transmission(seq(8)), Some((seq(16), 100)));
        let mut scoreboard = Scoreboard::new();
        assert_eq!(
            sack(&mut rack, &mut scoreboard, seq(24).0, seq(24).0, 500, &[]),
            8
        );
        assert_eq!(rack.ack_sample, None); // Karn still applies.
        assert_eq!(
            sack(&mut rack, &mut scoreboard, seq(24).0, seq(24).0, 600, &[]),
            0
        );
    }
}

#[test]
fn departure_retry_crosses_physical_originals_without_rewriting_history() {
    let mut rack = Rack::with_capacity(24).unwrap();
    rack.transmit(Seq(0), Seq(24), 10, false);
    let fresh = rack.departure_selection().unwrap();
    assert!(rack.commit_departure(fresh, Seq(0), Seq(8), 20));
    assert!(rack.commit_departure(fresh, Seq(8), Seq(24), 30));
    rack.transmit(Seq(4), Seq(20), 40, true);
    rack.commit_retry_span(Seq(4), Seq(20));
    let retry = rack.departure_selection().unwrap();
    assert!(rack.commit_departure(retry, Seq(6), Seq(16), 50));
    assert_eq!(
        original_packet(&rack, Seq(6)),
        Some((Seq(0), Seq(8), 20, true))
    );
    assert_eq!(
        original_packet(&rack, Seq(8)),
        Some((Seq(8), Seq(24), 30, true))
    );
    assert_eq!(rack.head_transmission(Seq(6)), Some((Seq(16), 50)));
    assert!(
        rack.intervals
            .iter()
            .filter(|r| !Seq(4).after(r.start) && !r.end.after(Seq(20)))
            .all(|r| r.successful_retries == 1 && r.retransmitted && r.loss_response_pending)
    );
    rack.abandon(Seq(24));
    let before = alloc::format!("{rack:?}");
    assert!(!rack.commit_departure(retry, Seq(4), Seq(6), 60));
    assert_eq!(alloc::format!("{rack:?}"), before);
    assert_eq!(rack.departure_selection(), None);
}

#[test]
fn group_departure_preflight_capacity_wrap_and_distinct_physical_identity() {
    for base in [Seq(100), Seq(u32::MAX - 15)] {
        for capacity in [3, 4] {
            let mut rack = Rack::with_capacity(capacity).unwrap();
            rack.transmit(base, base.wrapping_add(32), 10, false);
            let token = rack.departure_selection().unwrap();
            let before = alloc::format!("{rack:?}");
            for (size, bytes, now) in [
                (0, 24, 20),
                (8, 0, 20),
                (8, usize::MAX, 20),
                (8, 24, 9),
                (u32::MAX, 3 * u32::MAX as usize, 20),
            ] {
                assert!(!rack.validate_departure_group(token, base, size, bytes, now));
            }
            assert_eq!(
                rack.validate_departure_group(token, base, 8, 24, 20),
                capacity == 4
            );
            // A short last segment ends at its own edge, not a full one: two
            // inner edges and the end split the interval.
            assert_eq!(
                rack.validate_departure_group(token, base, 8, 20, 20),
                capacity == 4
            );
            assert!(rack.validate_departure_group(token, base, 16, 20, 20));
            assert_eq!(alloc::format!("{rack:?}"), before);
            if capacity == 3 {
                // Scalar fallback still works when the whole prefix cannot.
                assert!(rack.commit_departure(token, base, base.wrapping_add(8), 20));
                continue;
            }
            crate::allocation_tests::fail_after(0, || {
                for n in 0..3 {
                    assert!(rack.commit_departure(
                        token,
                        base.wrapping_add(n * 8),
                        base.wrapping_add((n + 1) * 8),
                        20
                    ));
                }
            });
            for n in 0..3 {
                let start = base.wrapping_add(n * 8);
                let end = base.wrapping_add((n + 1) * 8);
                assert_eq!(rack.head_transmission(start), Some((end, 20)));
                assert_eq!(original_packet(&rack, start), Some((start, end, 20, false)));
            }
            assert!(!rack.intervals.last().unwrap().departure_committed);
            assert!(!rack.validate_departure_group(token, base, 8, 24, 20));
            assert!(rack.commit_departure(token, base.wrapping_add(24), base.wrapping_add(32), 30));
            assert_eq!(
                rack.head_transmission(base.wrapping_add(24)),
                Some((base.wrapping_add(32), 30))
            );
        }
    }
}

#[test]
fn departure_capacity_no_allocation_and_failure_atomicity() {
    let mut rack = Rack::with_capacity(256).unwrap();
    rack.transmit(Seq(0), Seq(256), 10, false);
    let token = rack.departure_selection().unwrap();
    let bytes = rack.allocation_bytes();
    let ptr = rack.intervals.as_ptr();
    crate::allocation_tests::fail_after(0, || {
        for n in 0..256 {
            assert!(rack.commit_departure(token, Seq(n), Seq(n + 1), 100 + u64::from(n)));
        }
        assert_eq!(rack.intervals.len(), rack.capacity);
        assert_eq!(rack.intervals.as_ptr(), ptr);
        assert_eq!(rack.allocation_bytes(), bytes);
    });
    for (n, r) in rack.intervals.iter().enumerate() {
        assert_eq!(r.sent, 100 + n as u64);
        assert_eq!(r.original_sent, r.sent);
        assert_eq!(r.successful_retries, 0);
    }
    // Two edges need two slots: do not apply the first split on failure.
    let mut rack = Rack::with_capacity(2).unwrap();
    rack.transmit(Seq(0), Seq(8), 10, false);
    let token = rack.departure_selection().unwrap();
    let before = alloc::format!("{rack:?}");
    assert!(!rack.commit_departure(token, Seq(2), Seq(6), 20));
    assert_eq!(alloc::format!("{rack:?}"), before);
    assert!(rack.commit_departure(token, Seq(0), Seq(4), 20));
    // A full ledger still accepts an already aligned suffix without a slot.
    crate::allocation_tests::fail_after(0, || {
        assert!(rack.commit_departure(token, Seq(4), Seq(8), 30));
    });
}

#[test]
fn departure_rejects_stale_duplicate_invalid_and_exhausted_tokens() {
    let mut rack = Rack::with_capacity(24).unwrap();
    rack.transmit(Seq(0), Seq(24), 10, false);
    let old = rack.departure_selection().unwrap();
    rack.transmit(Seq(0), Seq(24), 10, true);
    let older_retry = rack.departure_selection().unwrap();
    rack.transmit(Seq(0), Seq(24), 10, true);
    let token = rack.departure_selection().unwrap();
    for (t, start, end, now) in [
        (old, 0, 24, 20),
        (older_retry, 0, 24, 20),
        (token, 0, 24, 9),
        (token, 0, 25, 20),
        (token, u32::MAX, 10, 20),
        (token, 4, 4, 20),
        (token, 10, 4, 20),
    ] {
        let before = alloc::format!("{rack:?}");
        assert!(!rack.commit_departure(t, Seq(start), Seq(end), now));
        assert_eq!(alloc::format!("{rack:?}"), before);
    }
    assert!(rack.commit_departure(token, Seq(0), Seq(8), 10));
    let before = alloc::format!("{rack:?}");
    assert!(!rack.commit_departure(token, Seq(0), Seq(8), 10));
    assert!(!rack.commit_departure(token, Seq(4), Seq(12), 20));
    assert_eq!(alloc::format!("{rack:?}"), before);
    // A removed byte cannot be silently covered by a departure commit.
    rack.intervals[1].start = Seq(9);
    let before = alloc::format!("{rack:?}");
    assert!(!rack.commit_departure(token, Seq(8), Seq(24), 20));
    assert_eq!(alloc::format!("{rack:?}"), before);
    rack.selection_generation = u64::MAX;
    rack.transmit(Seq(0), Seq(24), 10, true);
    assert_eq!(rack.departure_selection(), None);
    assert!(!rack.commit_departure(token, Seq(8), Seq(24), 20));
    rack.transmit(Seq(0), Seq(24), 10, true);
    assert_eq!(rack.departure_selection(), None);
}

#[test]
fn departure_fresh_ack_uses_physical_packet_boundary_and_age() {
    let mut rack = Rack::with_capacity(24).unwrap();
    rack.transmit(Seq(0), Seq(24), 10, false);
    let token = rack.departure_selection().unwrap();
    assert!(rack.commit_departure(token, Seq(0), Seq(8), 100));
    assert!(rack.commit_departure(token, Seq(8), Seq(24), 200));
    let mut scoreboard = Scoreboard::new();
    assert_eq!(sack(&mut rack, &mut scoreboard, 8, 24, 210, &[]), 8);
    assert_eq!(rack.latest, Some((100, Seq(8))));
    assert_eq!(rack.ack_sample, Some(110));
    assert_eq!(rack.head_transmission(Seq(8)), Some((Seq(24), 200)));
    assert_eq!(sack(&mut rack, &mut scoreboard, 24, 24, 220, &[]), 16);
    assert_eq!(rack.ack_sample, Some(20));
}

#[test]
fn transmissions_before_a_suspend_give_no_rtt_sample() {
    let mut rack = Rack::with_capacity(24).unwrap();
    rack.transmit(Seq(0), Seq(8), 100, false);
    rack.discard_samples_before(1_000);
    rack.transmit(Seq(8), Seq(16), 1_000, false);
    let mut scoreboard = Scoreboard::new();
    assert_eq!(sack(&mut rack, &mut scoreboard, 8, 8, 1_500, &[]), 8);
    assert_eq!(rack.ack_sample, None);
    assert_eq!(rack.min_rtt(), None);
    assert_eq!(rack.latest, None);
    assert_eq!(sack(&mut rack, &mut scoreboard, 16, 16, 1_500, &[]), 8);
    assert_eq!(rack.ack_sample, Some(500));
    assert_eq!(rack.min_rtt(), Some(500));
    assert_eq!(rack.latest, Some((1_000, Seq(16))));
}

#[test]
fn original_retry_identity_and_coverage_survive_sack_ack_and_replacement() {
    for base in [Seq(100), Seq(u32::MAX - 9)] {
        let end = base.wrapping_add(24);
        let mut rack = Rack::with_capacity(26).unwrap();
        let mut scoreboard = Scoreboard::new();
        rack.transmit(base, end, 10, false);
        rack.commit_original_window(base, end, true);
        rack.transmit(base, base.wrapping_add(8), 20, true);
        rack.commit_retry_span(base, base.wrapping_add(8));
        // A replacement changes RACK's copy/time, not original identity.
        rack.transmit(base.wrapping_add(4), base.wrapping_add(6), 30, true);
        rack.commit_retry_span(base.wrapping_add(4), base.wrapping_add(6));
        sack(
            &mut rack,
            &mut scoreboard,
            base.wrapping_add(2).0,
            end.0,
            40,
            &[(base.wrapping_add(5).0, base.wrapping_add(10).0)],
        );
        for (offset, retries, retry_end) in [(2, 1, 4), (4, 2, 6), (6, 1, 8), (8, 0, 24)] {
            let span = rack
                .original_retry_span(base.wrapping_add(offset), end)
                .unwrap();
            assert_eq!(span.original_start, base);
            assert_eq!(span.original_end, end);
            assert!(span.originally_in_window);
            assert_eq!(span.successful_retries, retries);
            assert_eq!(span.retry_end, base.wrapping_add(retry_end));
            assert_eq!(
                original_packet(&rack, base.wrapping_add(offset)),
                Some((base, end, 10, true))
            );
        }
        assert_eq!(rack.original_retry_span(base, end), None);
        // Pure queries, unrelated ACKs and splits never spend suffix credit.
        let suffix = rack
            .original_retry_span(base.wrapping_add(10), end)
            .unwrap();
        sack(
            &mut rack,
            &mut scoreboard,
            base.wrapping_add(3).0,
            end.0,
            50,
            &[],
        );
        assert_eq!(
            rack.original_retry_span(base.wrapping_add(10), end)
                .unwrap(),
            suffix
        );
    }
}

#[test]
fn retry_coverage_overflow_discards_permission_not_payload_or_inferred_time() {
    let mut rack = Rack::with_capacity(1).unwrap();
    rack.transmit(Seq(100), Seq(108), 10, false);
    rack.commit_original_window(Seq(100), Seq(108), true);
    assert!(
        rack.original_retry_span(Seq(100), Seq(108))
            .unwrap()
            .originally_in_window
    );
    rack.commit_retry_span(Seq(100), Seq(104));
    assert!(!rack.valid());
    assert_eq!(rack.original_retry_span(Seq(104), Seq(108)), None);
    assert_eq!(rack.head_transmission(Seq(100)), None);
    rack.transmit(Seq(104), Seq(108), 20, true);
    assert_eq!(rack.original_retry_span(Seq(104), Seq(108)), None);
    assert_eq!(rack.fallback, Some(Seq(108)));
}
#[test]
fn caller_units_scale_minimum_aging_and_retransmission_echoes() {
    for scale in [1, 1000] {
        let timebase = CallerTimebase {
            units_per_second: 1_000_000 * scale,
            ..CallerTimebase::default()
        };
        let mut rack = Rack::with_timebase(4, timebase).unwrap();
        rack.sample(50 * scale, 0);
        rack.sample(400 * scale, MIN_RTT_WINDOW * scale);
        assert_eq!(rack.min_rtt, Some(50 * scale));
        rack.sample(400 * scale, (MIN_RTT_WINDOW + MIN_RTT_BUCKET) * scale);
        assert_eq!(rack.min_rtt, Some(400 * scale));
        let mut bounded = Rack::with_timebase(1, timebase).unwrap();
        bounded.transmit(Seq(0), Seq(2), 0, false);
        bounded.transmit(Seq(1), Seq(2), scale, true);
        assert!(!bounded.valid()); // Capacity fallback is unit-independent.
        for granularity in [
            TimestampGranularity::Milliseconds,
            TimestampGranularity::Microseconds,
        ] {
            let mut rack = Rack::with_timebase(4, timebase).unwrap();
            rack.sample(100_000 * scale, 0);
            rack.transmit(Seq(0), Seq(1000), 100_000 * scale, false);
            rack.transmit(Seq(0), Seq(1000), 300_000 * scale, true);
            rack.acknowledge(
                Seq(1000),
                Seq(1000),
                &Scoreboard::new(),
                400_000 * scale,
                Some(granularity.tick(300_000) as u32),
                Some(granularity),
                1000,
                false,
            );
            assert_eq!(rack.latest, Some((300_000 * scale, Seq(1000))));
            assert_eq!(rack.rtt, 100_000 * scale);
            assert_eq!(rack.ack_sample, None); // Karn exclusion unchanged.
        }
    }
}

#[test]
fn capacity_backing_keeps_every_byte_timestamp_after_splits() {
    let mut rack = Rack::with_capacity(514).unwrap();
    let storage = (rack.intervals.as_ptr(), rack.intervals.capacity());
    rack.transmit(Seq(0), Seq(512), 0, false);
    for byte in 0..512 {
        rack.transmit(Seq(byte), Seq(byte + 1), byte as u64 + 1, true);
    }
    assert!(rack.valid());
    assert_eq!(
        (rack.intervals.as_ptr(), rack.intervals.capacity()),
        storage
    );
    assert_eq!(rack.intervals.len(), 512);
    assert_eq!(
        original_packet(&rack, Seq(255)),
        Some((Seq(0), Seq(512), 0, true))
    );
    for byte in 0..512 {
        assert_eq!(
            rack.head_transmission(Seq(byte)),
            Some((Seq(byte + 1), byte as u64 + 1))
        );
    }
    rack.acknowledge(
        Seq(511),
        Seq(512),
        &Scoreboard::new(),
        1000,
        None,
        None,
        512,
        false,
    );
    assert_eq!(
        (rack.intervals.as_ptr(), rack.intervals.capacity()),
        storage
    );
    assert_eq!(Rack::storage_bytes(usize::MAX), None);
    assert!(Rack::with_capacity(usize::MAX).is_err());
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Checks partial SACK and tail probe credit, repeated SACK no credit, and RTO reneging reset.
//# Given the information provided in an ACK, each segment
//# cumulatively ACKed or SACKed is marked as delivered in the
//# scoreboard.
fn partial_sack_delivery_is_one_shot_across_tail_probe_and_resets_at_rto() {
    for base in [Seq(0), Seq(u32::MAX - 1999)] {
        let seq = |n: u32| base.wrapping_add(n);
        let mut rack = Rack::new().unwrap();
        let mut scoreboard = Scoreboard::new();
        rack.sample(100_000, 0);
        for n in 0..4 {
            rack.transmit(seq(n * 1000), seq((n + 1) * 1000), 100_000, false);
        }
        assert_eq!(
            sack(
                &mut rack,
                &mut scoreboard,
                base.0,
                seq(4000).0,
                200_000,
                &[(seq(3500).0, seq(4000).0)]
            ),
            500
        );
        rack.transmit(seq(3000), seq(4000), 300_000, true);
        assert_eq!(
            sack(
                &mut rack,
                &mut scoreboard,
                base.0,
                seq(4000).0,
                400_000,
                &[(seq(3000).0, seq(4000).0)]
            ),
            500
        );
        assert_eq!(
            sack(
                &mut rack,
                &mut scoreboard,
                base.0,
                seq(4000).0,
                400_001,
                &[(seq(3000).0, seq(4000).0)]
            ),
            0
        );
        rack.rto(500_000, base, Some(100_000));
        scoreboard.clear(); // Possible receiver reneging starts fresh attribution.
        assert_eq!(
            sack(
                &mut rack,
                &mut scoreboard,
                base.0,
                seq(4000).0,
                600_000,
                &[(seq(3000).0, seq(4000).0)]
            ),
            1000
        );
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Longer-path samples replace expired minima; bucket boundaries never discard in-window minima, idle time alone retains the guard, and equal/shorter samples update immediately.
//# The sender SHOULD
//# track a windowed min-filtered estimate of recent RTT measurements
//# that can adapt when migrating to significantly longer paths rather
//# than tracking a simple global minimum of all RTT measurements.
fn windowed_minimum_path_migration_and_boundaries() {
    for start in [0, MIN_RTT_BUCKET - 1, MIN_RTT_BUCKET] {
        let mut rack = Rack::new().unwrap();
        rack.sample(100, start);
        rack.sample(400, start + MIN_RTT_WINDOW);
        assert_eq!(rack.min_rtt, Some(100)); // Inclusive window boundary.
        rack.sample(400, start + MIN_RTT_WINDOW + MIN_RTT_BUCKET);
        assert_eq!(rack.min_rtt, Some(400));
        assert_eq!(rack.reo_window(false, Some(400)), 100);
        rack.sample(50, start + MIN_RTT_WINDOW + MIN_RTT_BUCKET);
        assert_eq!(rack.min_rtt, Some(50));
    }
    let mut boundary = Rack::new().unwrap();
    boundary.sample(100, 0);
    boundary.sample(400, 4 * MIN_RTT_BUCKET - 1);
    assert_eq!(boundary.min_rtt, Some(100));
    boundary.sample(400, 4 * MIN_RTT_BUCKET);
    assert_eq!(boundary.min_rtt, Some(400)); // Old ring slot reused exactly here.

    let mut rack = Rack::new().unwrap();
    let mut scoreboard = Scoreboard::new();
    rack.sample(100, 0);
    rack.detect(10 * MIN_RTT_WINDOW, false, Some(400));
    assert_eq!(rack.min_rtt, Some(100)); // No accepted sample, no aging.
    let sent = 10 * MIN_RTT_WINDOW;
    rack.transmit(Seq(0), Seq(1000), sent, false);
    sack(&mut rack, &mut scoreboard, 1000, 1000, sent + 400, &[]);
    assert_eq!(rack.min_rtt, Some(400));
    assert_eq!(rack.ack_sample, Some(400));
    // The new path minimum is also the retransmission ambiguity threshold.
    rack.transmit(Seq(1000), Seq(2000), sent + 500, false);
    rack.transmit(Seq(1000), Seq(2000), sent + 600, true);
    let latest = rack.latest;
    sack(&mut rack, &mut scoreboard, 2000, 2000, sent + 999, &[]);
    assert_eq!(rack.latest, latest);
    assert_eq!(rack.ack_sample, None);
    assert_eq!(rack.min_rtt, Some(400));

    // Epoch arithmetic does not overflow at the clock's representable end.
    rack.sample(800, u64::MAX - 1);
    assert_eq!(rack.min_rtt, Some(800));
    rack.sample(700, u64::MAX);
    assert_eq!(rack.min_rtt, Some(700));
    rack.sample(0, u64::MAX);
    assert_eq!(rack.min_rtt, Some(0));
    assert_eq!(rack.reo_window(false, Some(u64::MAX)), 0);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Four hundred distinct DSACK rounds grow beyond 255 to SRTT, duplicate same-round ACKs do not grow, and widened arithmetic reaches even u64::MAX caps without overflow.
//# If RACK.dsack_round is None AND
//# any DSACK option is present on latest received ACK:
//# RACK.dsack_round = SND.NXT
//# RACK.reo_wnd_mult += 1
//# RACK.reo_wnd_persist = 16
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Checks multiplication before division, absent/zero SRTT, and overflow-safe SRTT bounds for all representative u64 minima.
//# Return min(RACK.reo_wnd_mult * RACK.min_RTT / 4, SRTT)
//= https://www.rfc-editor.org/rfc/rfc8985#section-3.3.2
//= type=test
//= reason=Effective window never exceeds SRTT, including maximum representable inputs.
//# The RACK reordering window MUST be bounded, and this bound SHOULD
//# be SRTT.
fn dsack_more_than_255_rounds_and_full_width_window_cap() {
    let mut rack = Rack::new().unwrap();
    let scoreboard = Scoreboard::new();
    rack.sample(4, 0);
    for round in 1..=400 {
        let ack = Seq(round * 1000);
        let high = ack.wrapping_add(1000);
        rack.acknowledge(ack, high, &scoreboard, 0, None, None, 1000, true);
        assert_eq!(rack.multiplier, u128::from(round) + 1);
        assert_eq!(
            rack.reo_window(false, Some(400)),
            u64::from(round + 1).min(400)
        );
        rack.acknowledge(ack, high, &scoreboard, 0, None, None, 1000, true);
        assert_eq!(rack.multiplier, u128::from(round) + 1);
    }
    for minimum in [1, 2, 3, 4, u64::MAX] {
        rack.min_rtt = Some(minimum);
        rack.multiplier = MAX_MULTIPLIER;
        assert_eq!(rack.reo_window(false, Some(u64::MAX)), u64::MAX);
        assert_eq!(rack.reo_window(true, Some(123)), 123);
        assert_eq!(rack.reo_window(false, None), 0);
        assert_eq!(rack.reo_window(false, Some(0)), 0);
    }
    rack.min_rtt = Some(3);
    rack.multiplier = 2;
    assert_eq!(rack.reo_window(false, Some(100)), 1);
    rack.multiplier = MAX_MULTIPLIER;
    rack.acknowledge(
        Seq(500_000),
        Seq(501_000),
        &scoreboard,
        0,
        None,
        None,
        1000,
        true,
    );
    assert_eq!(rack.multiplier, MAX_MULTIPLIER);
    for _ in 0..16 {
        rack.recovery_exit(false);
    }
    assert_eq!(rack.multiplier, 1);
}

#[test]
fn lost_selection_keeps_packet_boundary_and_charges_redundant_suffix() {
    for base in [Seq(1), Seq(u32::MAX - 499)] {
        for prefix in [0, 123] {
            let seq = |n: u32| base.wrapping_add(n);
            let mut rack = Rack::new().unwrap();
            let mut scoreboard = Scoreboard::new();
            rack.sample(100, 0);
            rack.transmit(base, seq(1000), 0, false);
            rack.transmit(seq(1000), seq(2000), 0, false);
            rack.rto(200, base, Some(100));
            let blocks = [(seq(999).0, seq(2000).0), (base.0, seq(prefix).0)];
            let blocks = &blocks[..if prefix == 0 { 1 } else { 2 }];
            assert_eq!(
                sack(&mut rack, &mut scoreboard, base.0, seq(2000).0, 300, blocks),
                1001 + prefix
            );
            assert_eq!(rack.pipe(), 0);
            assert_eq!(rack.counts().sacked, 1);
            let advice = scoreboard.ranges().to_vec();
            // Large credit must not reach the wholly SACKed next packet.
            assert_eq!(rack.lowest_lost(2000), Some((seq(prefix), seq(1000))));
            // MSS or congestion credit clips even the redundant suffix.
            assert_eq!(
                rack.lowest_lost(300),
                Some((seq(prefix), seq(prefix + 300)))
            );
            let (start, end) = rack.lowest_lost(1000).unwrap();
            rack.transmit(start, end, 400, true);
            assert_eq!(rack.pipe(), 1000 - prefix);
            assert_eq!(rack.lowest_lost(1000), None);
            assert_eq!(scoreboard.ranges(), advice);
            assert_eq!(
                sack(&mut rack, &mut scoreboard, base.0, seq(2000).0, 500, blocks),
                0
            );
            assert_eq!(rack.pipe(), 999 - prefix);
            assert_eq!(
                sack(
                    &mut rack,
                    &mut scoreboard,
                    seq(2000).0,
                    seq(2000).0,
                    600,
                    &[]
                ),
                999 - prefix
            );
            assert_eq!(rack.pipe(), 0);
            assert_eq!(rack.lowest_lost(1000), None);
        }
    }
}

#[test]
fn lost_selection_never_extends_past_transmitted_high() {
    for base in [Seq(1), Seq(u32::MAX - 499)] {
        let end = base.wrapping_add(777);
        let mut rack = Rack::new().unwrap();
        let mut scoreboard = Scoreboard::new();
        rack.transmit(base, end, 0, false);
        rack.rto(200, base, None);
        sack(
            &mut rack,
            &mut scoreboard,
            base.0,
            end.0,
            300,
            &[(base.wrapping_add(776).0, end.0)],
        );
        assert_eq!(rack.lowest_lost(1000), Some((base, end)));
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Retransmitting suffix marks untouched prefix ambiguous; immediate full SACK cannot create RTT/latest evidence.
//# To avoid spurious inferences, ignore a segment as invalid if any of
//# its sequence range has been retransmitted before and if either of two
//# conditions is true:
//#
//# 1.  The Timestamp Echo Reply field (TSecr) of the ACK's timestamp
//# option [RFC7323], if available, indicates the ACK was not
//# acknowledging the last retransmission of the segment.
//#
//# 2.  The segment was last retransmitted less than RACK.min_rtt ago.
fn clipped_retransmit_makes_untouched_original_prefix_rtt_ambiguous() {
    for base in [Seq(0), Seq(u32::MAX - 499)] {
        let end = base.wrapping_add(1000);
        let mut rack = Rack::new().unwrap();
        let mut scoreboard = Scoreboard::new();
        rack.sample(100_000, 0);
        rack.transmit(base, end, 100_000, false);
        rack.transmit(base.wrapping_add(12), end, 300_000, true);
        assert!(!rack.intervals[0].retransmitted);
        assert!(rack.intervals[0].original_retransmitted);
        assert!(rack.intervals[1].retransmitted);
        assert_eq!(
            sack(
                &mut rack,
                &mut scoreboard,
                base.0,
                end.0,
                300_001,
                &[(base.0, end.0)]
            ),
            1000
        );
        assert_eq!(rack.ack_sample, None);
        assert_eq!(rack.latest, None);
        assert_eq!(rack.min_rtt, Some(100_000));
        assert!(!rack.detect(300_001, false, Some(100_000)));
        assert_eq!(rack.deadline, None);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
//= type=test
//= reason=Checks SACK split, partial cumulative ACK, MSS-clipped tail and sequence wrap.
//# If such an unsent segment is not available, then the sender SHOULD
//# retransmit the highest-sequence segment sent so far and set
//# TLP.is_retrans to true.
fn tail_segment_retains_original_sack_boundaries_partial_ack_and_wrap() {
    for base in [Seq(1), Seq(u32::MAX - 499)] {
        let mut rack = Rack::new().unwrap();
        let mut scoreboard = Scoreboard::new();
        let end = base.wrapping_add(2000);
        rack.transmit(base, base.wrapping_add(1000), 0, false);
        rack.transmit(base.wrapping_add(1000), end, 0, false);
        sack(
            &mut rack,
            &mut scoreboard,
            base.0,
            end.0,
            10,
            &[(base.wrapping_add(1999).0, end.0)],
        );
        assert_eq!(
            rack.tail_segment(1000),
            Some((base.wrapping_add(1000), end))
        );
        sack(
            &mut rack,
            &mut scoreboard,
            base.wrapping_add(1500).0,
            end.0,
            20,
            &[],
        );
        assert_eq!(
            rack.tail_segment(1000),
            Some((base.wrapping_add(1500), end))
        );
        assert_eq!(rack.tail_segment(300), Some((base.wrapping_add(1700), end)));
        rack.abandon(end);
        assert_eq!(rack.tail_segment(1000), None);
    }
}

#[test]
fn cumulative_reclamation_needs_no_split_capacity_or_advice() {
    for base in [Seq(10), Seq(u32::MAX - 5)] {
        let mut rack = Rack::with_capacity(3).unwrap();
        for i in 0..3 {
            rack.transmit(
                base.wrapping_add(4 * i),
                base.wrapping_add(4 * i + 4),
                100 + u64::from(i),
                false,
            );
        }
        rack.trim_cumulative(base.wrapping_add(2));
        assert!(rack.valid());
        assert_eq!(rack.intervals.len(), 3);
        assert_eq!(rack.intervals[0].start, base.wrapping_add(2));
        assert_eq!(
            original_packet(&rack, base.wrapping_add(2)),
            Some((base, base.wrapping_add(4), 100, false))
        );
        assert_eq!(rack.latest, None);
        assert_eq!(rack.ack_sample, None);
        rack.trim_cumulative(base.wrapping_add(4));
        rack.transmit(base.wrapping_add(12), base.wrapping_add(13), 200, false);
        assert!(rack.valid());
        assert_eq!(rack.intervals.len(), 3);
        assert_eq!(
            rack.head_transmission(base.wrapping_add(12)),
            Some((base.wrapping_add(13), 200))
        );
    }
}

#[test]
fn abandoned_ledger_cumulative_reclamation_waits_for_extended_boundary() {
    let base = Seq(u32::MAX - 3);
    let mut rack = Rack::with_capacity(1).unwrap();
    rack.transmit(base, base.wrapping_add(2), 100, false);
    rack.transmit(base.wrapping_add(2), base.wrapping_add(4), 200, false);
    assert!(!rack.valid()); // Explicit defensive capacity exhaustion.
    rack.trim_cumulative(base.wrapping_add(2));
    assert!(!rack.valid());
    rack.transmit(base.wrapping_add(4), base.wrapping_add(5), 300, false);
    rack.trim_cumulative(base.wrapping_add(4));
    assert!(!rack.valid());
    rack.trim_cumulative(base.wrapping_add(5));
    assert!(rack.valid());
    rack.transmit(base.wrapping_add(5), base.wrapping_add(6), 400, false);
    assert_eq!(
        rack.head_transmission(base.wrapping_add(5)),
        Some((base.wrapping_add(6), 400))
    );
    assert_eq!(rack.latest, None);
}

#[test]
fn interval_splits_wrap_unique_delivery_and_identity() {
    let base = u32::MAX - 1999;
    let mut rack = Rack::new().unwrap();
    let mut scoreboard = Scoreboard::new();
    for i in 0..3 {
        rack.transmit(
            Seq(base.wrapping_add(i * 1000)),
            Seq(base.wrapping_add((i + 1) * 1000)),
            0,
            false,
        );
    }
    let high = base.wrapping_add(3000);
    let block = [(base.wrapping_add(1111), base.wrapping_add(1555))];
    assert_eq!(
        sack(&mut rack, &mut scoreboard, base, high, 100, &block),
        444
    );
    assert_eq!(rack.counts().unacked, 3);
    assert_eq!(rack.counts().sacked, 0);
    assert_eq!(sack(&mut rack, &mut scoreboard, base, high, 101, &block), 0);
    assert_eq!(
        sack(
            &mut rack,
            &mut scoreboard,
            base.wrapping_add(1700),
            high,
            102,
            &[]
        ),
        1256
    );
    assert_eq!(rack.counts().unacked, 2);
    assert_eq!(rack.latest, Some((0, Seq(base.wrapping_add(1000)))));
    assert_eq!(rack.counts().sacked, 0);
    assert_eq!(sack(&mut rack, &mut scoreboard, high, high, 103, &[]), 1300);
    assert_eq!(rack.counts().unacked, 0);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Partial bytes cannot update minimum RTT; completing the transmission can.
//# Use the RTT measurements obtained via [RFC6298] or [RFC7323] to
//# update the estimated minimum RTT in RACK.min_RTT.
//= https://www.rfc-editor.org/rfc/rfc8985#section-5.1
//= type=test
//= reason=One-byte tail SACK does not advance RACK; completing the full original or retransmitted range does.
//# Denotes the time when the full sequence range of RACK.segment was
//# selectively or cumulatively acknowledged.
fn partial_delivery_waits_for_complete_transmission_across_wrap() {
    for base in [0u32, u32::MAX - 1357] {
        let seq = |offset| base.wrapping_add(offset);
        let mut rack = Rack::new().unwrap();
        let mut scoreboard = Scoreboard::new();
        for i in 0..3 {
            rack.transmit(Seq(seq(i * 1000)), Seq(seq((i + 1) * 1000)), 10, false);
        }
        assert_eq!(
            sack(
                &mut rack,
                &mut scoreboard,
                seq(0),
                seq(3000),
                110,
                &[(seq(2999), seq(3000))]
            ),
            1
        );
        assert_eq!(rack.latest, None);
        assert_eq!(rack.min_rtt, None);
        assert_eq!(rack.counts().sacked, 0);
        rack.detect(200, false, Some(100));
        assert_eq!(rack.lowest_lost(1000), None);
        assert_eq!(
            sack(
                &mut rack,
                &mut scoreboard,
                seq(0),
                seq(3000),
                210,
                &[(seq(2000), seq(3000))]
            ),
            999
        );
        assert_eq!(rack.latest, Some((10, Seq(seq(3000)))));
        assert_eq!(rack.min_rtt, Some(200));
        assert_eq!(rack.counts().sacked, 1);
        // Retransmission boundaries can cross original logical identities.
        rack.transmit(Seq(seq(500)), Seq(seq(1500)), 220, true);
        let latest = rack.latest;
        sack(
            &mut rack,
            &mut scoreboard,
            seq(0),
            seq(3000),
            420,
            &[(seq(1000), seq(1500))],
        );
        assert_eq!(rack.latest, latest);
        sack(
            &mut rack,
            &mut scoreboard,
            seq(0),
            seq(3000),
            421,
            &[(seq(500), seq(1500))],
        );
        assert_eq!(rack.latest, Some((220, Seq(seq(1500)))));
        assert_eq!(rack.counts().sacked, 1);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Asserts maximum deadline and timeout marking, then lost retransmission detection.
//# For timely loss detection, it is RECOMMENDED that the
//# sender install a reordering timer.
//= https://www.rfc-editor.org/rfc/rfc8985#section-9.2
//= type=test
//= reason=Detects loss of a retransmission and makes it selectable again.
//# Therefore, the algorithm [RFC6675]
//# MUST NOT be used with RACK-TLP; instead, a modified recovery
//# algorithm that carefully addresses such a case is needed.
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Retransmitted eligible packet advances reference used for lost-retransmission detection.
//# Among all the segments newly ACKed or SACKed by this ACK that pass
//# the checks above, update the RACK.rtt to be the RTT sample calculated
//# using this ACK.  Furthermore, record the most recent Segment.xmit_ts
//# in RACK.xmit_ts if it is ahead of RACK.xmit_ts.  If Segment.xmit_ts
//# equals RACK.xmit_ts (e.g., due to clock granularity limits), then
//# compare Segment.end_seq and RACK.end_seq to break the tie when
//# deciding whether to update the RACK.segment's associated state.
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Checks maximum remaining timer, original loss, retransmit reset and one-shot lost retransmission detection.
//# RACK_detect_loss():
//# timeout = 0
//# RACK.reo_wnd = RACK_update_reo_wnd()
//# For each segment, Segment, not acknowledged yet:
//# If RACK_sent_after(RACK.xmit_ts, RACK.end_seq,
//# Segment.xmit_ts, Segment.end_seq):
//# remaining = Segment.xmit_ts + RACK.rtt +
//# RACK.reo_wnd - Now()
//# If remaining <= 0:
//# Segment.lost = TRUE
//# Segment.xmit_ts = INFINITE_TS
//# Else:
//# timeout = max(remaining, timeout)
//# Return timeout
fn maximum_timer_remaining_and_lost_retransmission() {
    let mut rack = Rack::new().unwrap();
    let mut scoreboard = Scoreboard::new();
    rack.sample(100, 0);
    for (i, time) in [0, 10, 20].into_iter().enumerate() {
        rack.transmit(
            Seq(i as u32 * 1000),
            Seq((i as u32 + 1) * 1000),
            time,
            false,
        );
    }
    sack(&mut rack, &mut scoreboard, 0, 3000, 100, &[(2000, 3000)]);
    assert!(!rack.detect(100, false, Some(100)));
    assert_eq!(rack.deadline, Some(110));
    rack.detect(110, false, Some(100));
    assert_eq!(rack.counts().lost, 2);
    rack.transmit(Seq(0), Seq(1000), 125, true);
    rack.transmit(Seq(1000), Seq(2000), 126, true);
    assert_eq!((rack.counts().lost, rack.counts().retransmitted), (2, 2));
    sack(&mut rack, &mut scoreboard, 0, 3000, 226, &[(1000, 3000)]);
    assert!(rack.detect(226, true, Some(100)));
    assert_eq!(rack.lowest_lost(1000), Some((Seq(0), Seq(1000))));
    assert_eq!((rack.counts().lost, rack.counts().retransmitted), (1, 0));
    rack.transmit(Seq(0), Seq(1000), 227, true);
    assert_eq!((rack.counts().lost, rack.counts().retransmitted), (1, 1));
}

#[test]
fn retransmission_copy_windows_survive_splits_and_renew_on_commit() {
    for base in [0, u32::MAX - 1999] {
        let seq = |offset| Seq(base).wrapping_add(offset);
        let mut rack = Rack::new().unwrap();
        let mut scoreboard = Scoreboard::new();
        rack.sample(100, 0);
        for i in 0..4 {
            rack.transmit(seq(i * 1000), seq((i + 1) * 1000), 0, false);
            rack.transmit(seq(i * 1000), seq((i + 1) * 1000), 100 + u64::from(i), true);
        }
        sack(
            &mut rack,
            &mut scoreboard,
            base,
            seq(4000).0,
            201,
            &[(seq(1000).0, seq(2000).0)],
        );
        assert!(rack.detect(201, true, Some(100)));
        assert!(rack.intervals.iter().all(|r| !r.loss_response_pending));
        // A split of an accounted, still outstanding copy stays accounted.
        assert!(rack.split(seq(2500)));
        sack(
            &mut rack,
            &mut scoreboard,
            base,
            seq(4000).0,
            203,
            &[(seq(1000).0, seq(2000).0), (seq(3000).0, seq(4000).0)],
        );
        assert!(!rack.detect(203, true, Some(100))); // Older third copy, later ACK.
        assert!(
            rack.intervals
                .iter()
                .filter(|r| r.start == seq(2000) || r.start == seq(2500))
                .all(|r| r.needs_retransmit && !r.loss_response_pending)
        );
        // Two successful replacements share the timestamp of the prior
        // detect call, but constitute new, unaccounted committed copies.
        rack.transmit(seq(0), seq(1000), 203, true);
        assert!(rack.split(seq(500)));
        assert!(
            rack.intervals
                .iter()
                .filter(|r| r.start == seq(0) || r.start == seq(500))
                .all(|r| r.loss_response_pending)
        );
        rack.transmit(seq(2000), seq(3000), 203, true);
        sack(
            &mut rack,
            &mut scoreboard,
            base,
            seq(4000).0,
            303,
            &[(seq(1000).0, seq(4000).0)],
        );
        assert!(rack.detect(303, true, Some(100)));
        assert!(!rack.detect(303, true, Some(100))); // Response is one-shot.
        // Partial retransmission renews just its successfully sent range.
        rack.transmit(seq(0), seq(500), 303, true);
        assert!(rack.intervals[0].loss_response_pending);
        assert!(!rack.intervals[1].loss_response_pending);
    }
}

#[test]
fn capacity_overflow_disables_inference_until_flight_is_acked() {
    for split_overflow in [false, true] {
        let mut rack = Rack::new().unwrap();
        let mut scoreboard = Scoreboard::new();
        for i in 0..CAPACITY as u32 {
            rack.transmit(Seq(i * 1000), Seq((i + 1) * 1000), 0, false);
        }
        let mut high = CAPACITY as u32 * 1000;
        if split_overflow {
            sack(&mut rack, &mut scoreboard, 0, high, 100, &[(1111, 1555)]);
        } else {
            rack.transmit(Seq(high), Seq(high + 1000), 1, false);
            high += 1000;
        }
        assert!(!rack.valid());
        assert!(rack.intervals.len() <= CAPACITY);
        assert_eq!(rack.lowest_lost(1000), None);
        rack.transmit(Seq(high), Seq(high + 1000), 2, false);
        sack(&mut rack, &mut scoreboard, high, high + 1000, 101, &[]);
        assert!(!rack.valid());
        sack(
            &mut rack,
            &mut scoreboard,
            high + 1000,
            high + 1000,
            102,
            &[],
        );
        assert!(rack.valid());
        rack.transmit(Seq(high + 1000), Seq(high + 2000), 103, false);
        assert_eq!(rack.counts().unacked, 1);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.3
//= type=test
//= reason=Asserts only first loss when another segment is recent and rejects early ACK of retransmission.
//# Upon RTO timer expiration, RACK marks the first outstanding segment
//# as lost (since it was sent an RTO ago); for all the other segments,
//# RACK only marks the segment as lost if the time elapsed since the
//# segment was transmitted is at least the sum of the recent RTT and the
//# reordering window.
fn rto_marks_first_and_age_eligible_only_and_karn_rejects_early_retx_ack() {
    let mut rack = Rack::new().unwrap();
    let mut scoreboard = Scoreboard::new();
    rack.sample(100, 0);
    rack.transmit(Seq(0), Seq(1000), 0, false);
    rack.transmit(Seq(1000), Seq(2000), 999, false);
    rack.rto(1000, Seq(0), Some(100));
    assert_eq!(rack.counts().lost, 1);
    rack.transmit(Seq(0), Seq(1000), 1000, true);
    sack(&mut rack, &mut scoreboard, 1000, 2000, 1001, &[]);
    assert_eq!(rack.latest, None);
    assert_eq!(rack.ack_sample, None);
    assert_eq!(rack.counts().lost, 0);
    assert_eq!(rack.lowest_lost(1000), None);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-4
//= type=test
//= reason=Checks original/retransmission timestamp storage and retransmitted state, not physical clock granularity.
//# For each data segment sent, the sender MUST store its most recent
//# transmission time with a timestamp whose granularity is finer
//# than 1/4 of the minimum RTT of the connection.
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
//= type=test
//= reason=Checks timestamp/lost flag reset for the shared transmit procedure.
//# The sender MUST follow the RACK transmission procedures in the "Upon
//# Transmitting a Data Segment" section upon sending either a
//# retransmission or a new data loss probe.
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.1
//= type=test
//= reason=Asserts committed timestamps, retransmitted flag, pending-loss reset and pipe restoration.
//# Upon transmitting a new segment or retransmitting an old segment,
//# record the time in Segment.xmit_ts and set Segment.lost to FALSE.
//# Upon retransmitting a segment, set Segment.retransmitted to TRUE.
fn transmission_commit_updates_timestamp_and_clears_pending_loss() {
    let mut rack = Rack::new().unwrap();
    rack.transmit(Seq(0), Seq(1000), 10, false);
    assert_eq!(rack.intervals[0].sent, 10);
    assert!(!rack.intervals[0].retransmitted);
    assert!(!rack.intervals[0].needs_retransmit);
    rack.rto(20, Seq(0), None);
    assert!(rack.intervals[0].needs_retransmit);
    assert_eq!(rack.pipe(), 0);
    rack.transmit(Seq(0), Seq(1000), 30, true);
    assert_eq!(rack.intervals[0].sent, 30);
    assert!(rack.intervals[0].retransmitted);
    assert!(!rack.intervals[0].needs_retransmit);
    assert_eq!(rack.pipe(), 1000);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Separately rejects too-fast retransmission ACK and nonmatching old echo, accepts matching echo at min RTT without feeding ordinary estimator.
//# To avoid spurious inferences, ignore a segment as invalid if any of
//# its sequence range has been retransmitted before and if either of two
//# conditions is true:
//#
//# 1.  The Timestamp Echo Reply field (TSecr) of the ACK's timestamp
//# option [RFC7323], if available, indicates the ACK was not
//# acknowledging the last retransmission of the segment.
//#
//# 2.  The segment was last retransmitted less than RACK.min_rtt ago.
//= https://www.rfc-editor.org/rfc/rfc6298#section-3
//= type=test
//= reason=RACK retransmission feedback versus ordinary RTO sample.
//# TCP MUST use Karn's algorithm [KP87] for taking RTT samples.
//= https://www.rfc-editor.org/rfc/rfc6298#section-3
//= type=test
//= reason=RACK retransmission feedback versus ordinary RTO sample.
//# That is, RTT samples MUST NOT be made using segments that were retransmitted (and thus
//# for which it is ambiguous whether the reply was for the first instance of the packet
//# or a later instance).
fn retransmitted_ack_requires_min_rtt_and_matching_timestamp() {
    for (now, echo, valid) in [
        (399_999, 300, false), // Matching echo, but below minimum RTT.
        (400_000, 100, false), // Old original transmission echo.
        (400_000, 300, true),
    ] {
        let mut rack = Rack::new().unwrap();
        let scoreboard = Scoreboard::new();
        rack.sample(100_000, 0);
        rack.transmit(Seq(0), Seq(1000), 100_000, false);
        rack.transmit(Seq(0), Seq(1000), 300_000, true);
        assert_eq!(
            rack.acknowledge(
                Seq(1000),
                Seq(1000),
                &scoreboard,
                now,
                Some(echo),
                Some(TimestampGranularity::Milliseconds),
                1000,
                false,
            ),
            1000
        );
        assert_eq!(rack.latest, valid.then_some((300_000, Seq(1000))));
        assert_eq!(rack.ack_sample, None); // Karn exclusion, even when RACK qualifies.
        assert_eq!(rack.min_rtt, Some(100_000));
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-3.3.2
//= type=test
//= reason=Checks unknown RTT, fractional window, three-SACK threshold and recovery zeroing; observed original reordering disables zeroing.
//# The reordering window SHOULD be set to zero if no reordering has
//# been observed on the connection so far, and either (a) three
//# segments have been SACKed since the last recovery or (b) the
//# sender is already in fast or RTO recovery.
//= https://www.rfc-editor.org/rfc/rfc8985#section-3.3.2
//= type=test
//= reason=Checks initial fractional and unavailable RTT windows.
//# Otherwise, the
//# reordering window SHOULD start from a small fraction of the
//# round-trip time or zero if no round-trip time estimate is
//# available.
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Checks original reordered delivery versus retransmitted lower segment and its effect on window zeroing.
//# If a never-retransmitted segment
//# that's below RACK.fack is (selectively or cumulatively) acknowledged,
//# it has been delivered out of order.  The sender sets
//# RACK.reordering_seen to TRUE if such a segment is identified.
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Checks a positive settling window remains after original reordering.
//# Otherwise, if some reordering has been observed, then RACK does not
//# trigger fast recovery based on DupThresh.
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Checks initial and unknown windows, three-SACK zeroing, original reordering and recovery zeroing.
//# If RACK.reordering_seen is FALSE:
//# If in Fast or RTO recovery:
//# Return 0
//# Else if RACK.segs_sacked >= DupThresh:
//# Return 0
//# Return min(RACK.reo_wnd_mult * RACK.min_RTT / 4, SRTT)
fn original_reordering_and_zero_window_rules() {
    let mut unknown = Rack::new().unwrap();
    assert_eq!(unknown.reo_window(false, None), 0);
    unknown.sample(100, 0);
    assert_eq!(unknown.reo_window(false, Some(100)), 25);
    assert_eq!(unknown.reo_window(true, Some(100)), 0);
    for retransmit in [false, true] {
        let mut rack = Rack::new().unwrap();
        let mut scoreboard = Scoreboard::new();
        rack.sample(100, 0);
        for i in 0..4 {
            rack.transmit(Seq(i * 1000), Seq((i + 1) * 1000), 0, false);
        }
        sack(&mut rack, &mut scoreboard, 0, 4000, 100, &[(1000, 4000)]);
        assert_eq!(rack.counts().sacked, 3);
        assert_eq!(rack.reo_window(false, Some(100)), 0);
        if retransmit {
            rack.transmit(Seq(0), Seq(1000), 110, true);
        }
        sack(&mut rack, &mut scoreboard, 1000, 4000, 210, &[]);
        assert_eq!(rack.reordering_seen, !retransmit);
        assert_eq!(
            rack.reo_window(false, Some(100)),
            if retransmit { 0 } else { 25 }
        );
        assert_eq!(
            rack.reo_window(true, Some(100)),
            if retransmit { 0 } else { 25 }
        );
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Checks equal-timestamp tie ordering and wrap, preserving latest while later ACK of older transmission updates RTT.
//# Among all the segments newly ACKed or SACKed by this ACK that pass
//# the checks above, update the RACK.rtt to be the RTT sample calculated
//# using this ACK.  Furthermore, record the most recent Segment.xmit_ts
//# in RACK.xmit_ts if it is ahead of RACK.xmit_ts.  If Segment.xmit_ts
//# equals RACK.xmit_ts (e.g., due to clock granularity limits), then
//# compare Segment.end_seq and RACK.end_seq to break the tie when
//# deciding whether to update the RACK.segment's associated state.
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Checks equal timestamp end-sequence ordering across wrap.
//# RACK_detect_loss():
//# timeout = 0
//# RACK.reo_wnd = RACK_update_reo_wnd()
//# For each segment, Segment, not acknowledged yet:
//# If RACK_sent_after(RACK.xmit_ts, RACK.end_seq,
//# Segment.xmit_ts, Segment.end_seq):
//# remaining = Segment.xmit_ts + RACK.rtt +
//# RACK.reo_wnd - Now()
//# If remaining <= 0:
//# Segment.lost = TRUE
//# Segment.xmit_ts = INFINITE_TS
//# Else:
//# timeout = max(remaining, timeout)
//# Return timeout
fn equal_timestamp_tie_breaks_in_serial_sequence_space() {
    for base in [0u32, u32::MAX - 499] {
        let seq = |n| Seq(base.wrapping_add(n));
        let mut rack = Rack::new().unwrap();
        let mut scoreboard = Scoreboard::new();
        rack.transmit(seq(0), seq(1000), 10, false);
        rack.transmit(seq(1000), seq(2000), 10, false);
        sack(
            &mut rack,
            &mut scoreboard,
            base,
            seq(2000).0,
            110,
            &[(seq(1000).0, seq(2000).0)],
        );
        assert_eq!(rack.latest, Some((10, seq(2000))));
        rack.detect(134, false, Some(100));
        assert_eq!(rack.lowest_lost(1000), None);
        assert_eq!(rack.deadline, Some(135));
        rack.detect(135, false, Some(100));
        assert_eq!(rack.lowest_lost(1000), Some((seq(0), seq(1000))));
        // The older original can update the RTT but cannot regress the reference.
        sack(
            &mut rack,
            &mut scoreboard,
            seq(2000).0,
            seq(2000).0,
            210,
            &[],
        );
        assert_eq!(rack.latest, Some((10, seq(2000))));
        assert_eq!(rack.rtt, 200);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-3.3.2
//= type=test
//= reason=Checks repeated DSACK in a round, advancement into a new round, SRTT cap and sixteen exits.
//# The RACK reordering window SHOULD adaptively increase (using the
//# algorithm in "Step 4: Update RACK reordering window" below) if
//# the sender receives a Duplicate Selective Acknowledgment (DSACK)
//# option [RFC2883].
//= https://www.rfc-editor.org/rfc/rfc8985#section-3.3.2
//= type=test
//= reason=Exercises multiplier growth past the SRTT bound.
//# The RACK reordering window MUST be bounded, and this bound SHOULD
//# be SRTT.
//= https://www.rfc-editor.org/rfc/rfc8985#section-4
//= type=test
//= reason=Checks round-bounded growth, cap and persistence.
//# RACK DSACK-based reordering window adaptation is RECOMMENDED but
//# is not required.
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Covers repeated same-round DSACK, boundary advancement and SRTT cap.
//# If RACK.dsack_round is not None AND
//# SND.UNA >= RACK.dsack_round:
//# RACK.dsack_round = None
//# /* Grow the reordering window per round that sees DSACK.
//# Reset the window after 16 DSACK-free recoveries */
//# If RACK.dsack_round is None AND
//# any DSACK option is present on latest received ACK:
//# RACK.dsack_round = SND.NXT
//# RACK.reo_wnd_mult += 1
//# RACK.reo_wnd_persist = 16
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Checks helper persistence through 15 exits and reset at 16; does not cover RTO integration.
//# Else if exiting Fast or RTO recovery:
//# RACK.reo_wnd_persist -= 1
//# If RACK.reo_wnd_persist <= 0:
//# RACK.reo_wnd_mult = 1
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Checks DSACK growth, SRTT cap and persistence reset.
//# If RACK.reordering_seen is FALSE:
//# If in Fast or RTO recovery:
//# Return 0
//# Else if RACK.segs_sacked >= DupThresh:
//# Return 0
//# Return min(RACK.reo_wnd_mult * RACK.min_RTT / 4, SRTT)
fn dsack_new_round_cap_and_sixteen_recovery_decay() {
    let mut rack = Rack::new().unwrap();
    let mut scoreboard = Scoreboard::new();
    rack.sample(100, 0);
    rack.transmit(Seq(1000), Seq(2000), 0, false);
    sack(&mut rack, &mut scoreboard, 1000, 2000, 100, &[(0, 1000)]);
    assert_eq!(rack.multiplier, 2);
    sack(&mut rack, &mut scoreboard, 1000, 2000, 101, &[(0, 1000)]);
    assert_eq!(rack.multiplier, 2);
    for high in [3000, 4000, 5000] {
        let ack = high - 1000;
        rack.transmit(Seq(ack), Seq(high), 102, false);
        sack(
            &mut rack,
            &mut scoreboard,
            ack,
            high,
            202,
            &[(ack - 1000, ack)],
        );
    }
    assert_eq!(rack.multiplier, 5);
    assert_eq!(rack.reo_window(false, Some(100)), 100); // Uncapped value is 125.
    for _ in 0..15 {
        rack.recovery_exit(false);
        assert_eq!(rack.multiplier, 5);
    }
    rack.recovery_exit(false);
    assert_eq!(rack.multiplier, 1);
    assert_eq!(rack.reo_window(false, Some(100)), 25);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.3
//= type=test
//= reason=Checks nonzero reordering window before/at age deadline and the first-outstanding exception.
//# Upon RTO timer expiration, RACK marks the first outstanding segment
//# as lost (since it was sent an RTO ago); for all the other segments,
//# RACK only marks the segment as lost if the time elapsed since the
//# segment was transmitted is at least the sum of the recent RTT and the
//# reordering window.
fn rto_nonzero_window_age_boundary_and_first_exception() {
    for now in [124, 125] {
        let mut rack = Rack::new().unwrap();
        rack.sample(100, 0);
        rack.reordering_seen = true;
        rack.transmit(Seq(0), Seq(1000), 124, false);
        rack.transmit(Seq(1000), Seq(2000), 0, false);
        rack.transmit(Seq(2000), Seq(3000), 100, false);
        assert_eq!(rack.reo_window(true, Some(100)), 25);
        rack.rto(now, Seq(0), Some(100));
        assert!(rack.intervals[0].needs_retransmit); // First: no age requirement.
        assert_eq!(rack.intervals[1].needs_retransmit, now == 125);
        assert!(!rack.intervals[2].needs_retransmit);
        assert_eq!(rack.deadline, None);
    }
}

#[test]
fn dsack_is_not_delivery_and_growth_is_bounded_per_round() {
    let mut rack = Rack::new().unwrap();
    let mut scoreboard = Scoreboard::new();
    rack.sample(100, 0);
    rack.transmit(Seq(1000), Seq(2000), 0, false);
    assert_eq!(
        sack(&mut rack, &mut scoreboard, 1000, 2000, 100, &[(0, 1000)]),
        0
    );
    assert_eq!(rack.reo_window(false, Some(100)), 50);
    sack(&mut rack, &mut scoreboard, 1000, 2000, 101, &[(0, 1000)]);
    assert_eq!(rack.reo_window(false, Some(100)), 50);
    for _ in 0..16 {
        rack.recovery_exit(false);
    }
    assert_eq!(rack.reo_window(false, Some(100)), 25);
}
