use super::*;

// Actual wire ranges, not a cwnd/pipe-only assertion. Ignore independent pure ACKs.
fn outputs(a: &mut Connection, now: u64, base: Seq) -> Vec<(u32, usize)> {
    let mut ranges = Vec::new();
    let mut out = [0; 1500];
    while let Some(size) = a.transmit(now, &mut out).unwrap() {
        let segment = wire::parse(ip(tuple()), &out[..size]).unwrap();
        if !segment.payload.is_empty() {
            ranges.push((
                Seq(segment.header.sequence).distance_from(base),
                segment.payload.len(),
            ));
        }
        assert!(ranges.len() < 2000);
    }
    ranges
}

#[test]
fn active_prr_mss_lowering_preserves_bytes_and_updates_allowances() {
    for iss in [0, u32::MAX - 4999] {
        let (mut a, _) = primed_pair(
            ConnectionConfig {
                prr: true,
                initial_window: InitialWindow::Iw10,
                ..config(65_536, 1000)
            },
            iss,
        );
        let base = a.snd_una;
        let seq = a.receive.next();
        let window = (a.snd_wnd >> a.peer_scale) as u16;
        a.write(&[0x55; 10_000]).unwrap();
        assert_eq!(outputs(&mut a, 40, base).len(), 10);
        for _ in 0..3 {
            inject(&mut a, 50, seq, base, ACK, window, &[]);
        }
        assert!(!a.sack_send && a.prr.is_some());
        let before = a.prr.unwrap();
        assert_eq!(before.counters(), (10_000, 1000, 0));
        assert_eq!(before.credit(), 500);
        a.lower_mss(250).unwrap();
        assert_eq!(a.prr.unwrap().counters(), before.counters());
        assert_eq!(a.prr.unwrap().credit(), before.credit());
        assert_eq!(outputs(&mut a, 50, base), vec![(0, 250), (250, 250)]);
        assert_eq!(a.prr.unwrap().counters(), (10_000, 1000, 500));
        inject(&mut a, 51, seq, base, ACK, window, &[]);
        assert_eq!(a.prr.unwrap().counters(), (10_000, 1250, 500));
        assert_eq!(a.prr.unwrap().credit(), 125);
        // Keep the old 1000-byte estimate plus the new 250-byte estimate.
        for (now, advance) in [(52, 1000), (53, 1250)] {
            inject(&mut a, now, seq, base.wrapping_add(advance), ACK, window, &[]);
            assert_eq!(a.prr.unwrap().counters(), (10_000, 1250, 500));
            assert_eq!(a.prr.unwrap().credit(), 125);
        }
        assert_eq!(prr_packet(&mut a, 53).1, 125);

        let mut a = strict_flight(iss);
        strict_ack(&mut a, 200_000, 0, &[(7000, 10_000)]);
        assert_eq!(prr_packet(&mut a, 200_000).1, 1000);
        let before = a.prr.unwrap();
        a.lower_mss(250).unwrap();
        assert_eq!(a.prr.unwrap().counters(), before.counters());
        assert_eq!(a.prr.unwrap().credit(), before.credit());
        strict_ack(&mut a, 200_001, 1000, &[(7000, 10_000)]);
        assert_eq!(a.prr.unwrap().counters(), (10_000, 4000, 1000));
        assert_eq!(a.prr.unwrap().credit(), 3250); // 3000 bytes plus SafeACK's new MSS.
        let base = a.snd_una;
        let ranges = outputs(&mut a, 200_001, base);
        assert!(ranges.iter().all(|&(_, len)| len <= 250));
        assert_eq!(ranges.iter().map(|&(_, len)| len).sum::<usize>(), 3250);
        assert_eq!(a.prr.unwrap().counters(), (10_000, 4000, 4250));
        assert_eq!(a.prr.unwrap().credit(), 0);

        let mut a = strict_flight(iss);
        strict_ack(&mut a, 200_000, 0, &[(7000, 8000)]);
        a.timeout(225_000).unwrap();
        let before = a.prr.unwrap();
        assert_eq!(before.counters().2, 0);
        a.lower_mss(250).unwrap();
        assert_eq!(a.prr.unwrap().counters(), before.counters());
        assert_eq!(a.prr.unwrap().credit(), before.credit());
        // Isolate the forced-first equation, then exercise real output/rollback.
        a.prr.as_mut().unwrap().acknowledge(1, 5000, 5000, false);
        assert_eq!(a.prr.unwrap().credit(), 250);
        assert_eq!(prr_packet(&mut a, 225_000).1, 250);
        a.prr.as_mut().unwrap().acknowledge(1, 6000, 5000, false);
        assert_eq!(a.prr.unwrap().credit(), 0);
        let base = a.snd_una;
        assert!(outputs(&mut a, 225_000, base).is_empty());
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc5681#section-2
//= type=test
//= reason=Selected output-policy matrix: ordinary min(rwnd,cwnd) in slow start/avoidance and reduced-cwnd exit; section3.2 Limited Transmit; RFC6675 non-RACK/non-PRR pipe; RFC9937 PRR credit (LegacyInitialCredit excluded); RFC8985 modified RACK pipe and one accounted TLP overcommit. Separate shrink/probe matrix limits receive-window exceptions to prescribed retry/probe policies. Not a literal sequence-edge assertion in enhanced recovery or a section4.3 half-flight proof.
//# At any given time, a TCP MUST NOT send data with a sequence number higher than the sum of the highest acknowledged sequence number and the minimum of cwnd and rwnd.
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
//= type=test
//= reason=Ordinary ACK byte counting and exact emitted ranges are asserted in slow start and congestion avoidance; reduced-cwnd handoff and the separately selected recovery/probe policies have their own wire matrix. LegacyInitialCredit is not RFC9937 evidence; section4.3 segment-count TODO remains independent.
//# The slow start and congestion avoidance algorithms MUST be used by a TCP sender to control the amount of outstanding data being injected into the network.
//= https://www.rfc-editor.org/rfc/rfc5681#section-3
//= type=test
//= reason=Policy-specific output bounds, not an unconditional waiver: ordinary min(rwnd,cwnd), controlled Limited Transmit extension, RFC6675 pipe, RFC9937 PRR byte credit, RFC8985 modified recovery and single accounted TLP probe. Shrink allows only prescribed old-data retry/probe exceptions. Literal half-flight segments-per-RTT is separately unresolved, and LegacyInitialCredit does not meet the strict equations.
//# In some situations, it may be beneficial for a TCP sender to be more conservative than the algorithms allow; however, a TCP MUST NOT be more aggressive than the following algorithms allow (that is, MUST NOT send data when the value of cwnd computed by the following algorithms would not allow the data to be sent).
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
//= type=test
//= reason=Selected algorithms, ECN on/off: normal ACKs use slow start/byte-counting avoidance and min windows; eligible duplicate ACKs use Limited Transmit/NewReno or negotiated SACK/strict PRR/RACK; RTO sends old data after reduction. TLP is the RFC8985 single-accounted-probe extension. These are output-policy claims, not whole external RFC conformance; RFC5681 section4.3 segment-count TODO remains separate. LegacyInitialCredit is excluded from RFC9937 evidence.
//# TCP follows existing algorithms for sending data packets in response to incoming ACKs, multiple duplicate acknowledgments, or retransmit timeouts [RFC2581].
//= https://www.rfc-editor.org/rfc/rfc9937#section-11.2
//= type=test
//= reason=No PRR outside response; wire matrix asserts ordinary slow start and avoidance. strict_prr_default_timer_entry_and_current_ack_epoch asserts no pre-entry PRR/delivery replay; exit traces assert ordinary reduced-cwnd handoff.
//# PRR does not modify
//# the congestion control cwnd increase or decrease mechanisms outside
//# of congestion control response episodes.
fn ordinary_output_policy_matrix() {
    for ecn in [false, true] {
        for iss in [100, u32::MAX - 20] {
            for window in [8, 128] {
                let (mut a, _) = pair(
                    ConnectionConfig {
                        ecn,
                        ..config(128, 4)
                    },
                    iss,
                );
                let base = a.snd_una;
                let next = a.receive.next();
                inject(&mut a, 35, next, base, ACK, window, &[]);
                a.write(&[1; 64]).unwrap();
                let initial = u32::from(window).min(16);
                assert_eq!(
                    outputs(&mut a, 40, base),
                    (0..initial).step_by(4).map(|n| (n, 4)).collect::<Vec<_>>()
                );
                assert_eq!(a.flight(), initial);
                inject(&mut a, 50, next, base.wrapping_add(4), ACK, window, &[]);
                assert_eq!(a.congestion.cwnd(), 20); // slow start: min(N,SMSS)
                let budget = u32::from(window).min(20) - (initial - 4);
                assert_eq!(
                    outputs(&mut a, 51, base),
                    (initial..initial + budget)
                        .step_by(4)
                        .map(|n| (n, 4))
                        .collect::<Vec<_>>()
                );
            }
            // Real NewReno entry and covering ACK select avoidance even below ssthresh.
            let (mut a, _) = primed_pair(
                ConnectionConfig {
                    ecn,
                    initial_window: InitialWindow::Iw10,
                    ..config(128, 4)
                },
                iss,
            );
            let base = a.snd_una;
            let next = a.receive.next();
            inject(&mut a, 35, next, base, ACK, 128, &[]);
            a.write(&[2; 64]).unwrap();
            assert_eq!(outputs(&mut a, 40, base).len(), 10);
            for _ in 0..3 {
                inject(&mut a, 50, next, base, ACK, 128, &[]);
            }
            assert_eq!(outputs(&mut a, 51, base), vec![(0, 4)]);
            let end = a.snd_nxt;
            inject(&mut a, 60, next, end, ACK, 128, &[]);
            assert_eq!((a.congestion.cwnd(), a.congestion.ssthresh()), (8, 20));
            assert_eq!(outputs(&mut a, 61, base), vec![(40, 4), (44, 4)]);
            inject(&mut a, 70, next, end.wrapping_add(4), ACK, 128, &[]);
            assert_eq!(a.congestion.cwnd(), 8);
            assert_eq!(outputs(&mut a, 71, base), vec![(48, 4)]);
            inject(&mut a, 80, next, end.wrapping_add(8), ACK, 128, &[]);
            assert_eq!(a.congestion.cwnd(), 12);
            assert_eq!(outputs(&mut a, 81, base), vec![(52, 4), (56, 4)]);
        }
    }
}

#[test]
fn selected_recovery_output_policy_matrix() {
    for iss in [100, u32::MAX - 4999] {
        // Limited Transmit is one packet per eligible ACK, never rwnd overcommit.
        for window in [16, 24] {
            let (mut a, _) = primed_pair(config(128, 4), iss);
            let base = a.snd_una;
            let next = a.receive.next();
            inject(&mut a, 35, next, base, ACK, window, &[]);
            a.write(&[1; 40]).unwrap();
            assert_eq!(outputs(&mut a, 40, base).len(), 4);
            for i in 0..2 {
                inject(&mut a, 50 + i, next, base, ACK, window, &[]);
                let expected = if window == 24 {
                    vec![(16 + i as u32 * 4, 4)]
                } else {
                    vec![]
                };
                assert_eq!(outputs(&mut a, 50 + i, base), expected);
                assert_eq!(a.congestion.cwnd(), 16);
            }
        }
        let mut a = sack_flight(128, iss, 12);
        let base = a.snd_una;
        let ranges = [(128, 256), (512, 1152)]
            .map(|(l, r)| (base.wrapping_add(l).0, base.wrapping_add(r).0));
        a.write(&[9; 128]).unwrap();
        sack_ack(&mut a, 200, base, &ranges);
        assert_eq!(
            outputs(&mut a, 201, base),
            vec![(0, 128), (256, 128), (384, 128)]
        );
        assert_eq!(a.sack_recovery.unwrap().pipe, a.congestion.cwnd());
        sack_ack(&mut a, 210, base.wrapping_add(256), &ranges[1..]);
        assert_eq!(outputs(&mut a, 211, base), vec![(1536, 128)]);

        // RFC8985 modified RACK selection without PRR is still pipe-limited.
        let mut a = strict_flight(iss);
        a.config.prr = false;
        let base = a.snd_una;
        strict_ack(&mut a, 200_000, 0, &[(7000, 10_000)]);
        assert_eq!(
            outputs(&mut a, 200_000, base),
            vec![
                (0, 1000),
                (1000, 1000),
                (2000, 1000),
                (3000, 1000),
                (4000, 1000)
            ]
        );
        assert_eq!(a.rack.pipe(), a.congestion.cwnd());

        // Actual ACK-driven PRR entry with RFC6675 candidate selection;
        // credit controls quantity; the forced-first floor is tested separately.
        let mut a = strict_flight(iss);
        a.config.rack = false;
        let base = a.snd_una;
        strict_ack(&mut a, 200_000, 0, &[(7000, 10_000)]);
        assert_eq!(
            outputs(&mut a, 200_000, base),
            vec![(0, 1000), (1000, 1000), (2000, 1000)]
        );
        assert_eq!(a.prr.unwrap().counters(), (10_000, 3000, 3000));

        // Timer-driven RACK entry has no ACK delivery and therefore zero strict credit.
        let mut a = strict_flight(iss);
        assert_eq!(a.config.prr_algorithm, PrrAlgorithm::Rfc9937);
        let base = a.snd_una;
        strict_ack(&mut a, 200_000, 0, &[(7000, 8000)]);
        a.timeout(225_000).unwrap();
        assert_eq!(outputs(&mut a, 225_000, base), vec![]);
        assert_eq!(a.prr.unwrap().counters(), (9000, 0, 0));
        strict_ack(&mut a, 226_000, 0, &[(7000, 9000)]);
        assert_eq!(a.prr.unwrap().credit(), 1000);
        assert_eq!(outputs(&mut a, 226_000, base), vec![(0, 1000)]);
        assert_eq!(a.prr.unwrap().counters(), (9000, 1000, 1000));
        strict_ack(&mut a, 227_000, 0, &[(7000, 9000)]);
        assert_eq!(outputs(&mut a, 227_000, base), vec![]);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9937#section-3
//= type=test
//= reason=rwnd reconciliation is limited to RFC9293 sections3.8.6/3.8.6.1 old-data shrink retries and prescribed zero-window probes, with RFC7323 section2.4 items4/5 stricter scaled limits. This matrix asserts no fresh TLP overcommit of rwnd, unscaled shrink clipping, a single octet persist probe and no additional output; it runs scaled first/sub-scale/subsequent/configuration/ledger/wrap/failed-output checks and strict PRR cancellation before persist. ordinary_output_policy_matrix and selected_recovery_output_policy_matrix separately bound ordinary and recovery output. No blanket recovery waiver.
//# At any given time, a connection MUST
//# NOT send data with a sequence number higher than the sum of
//# SND.UNA and rwnd.
//= https://www.rfc-editor.org/rfc/rfc9937#section-3
//= type=test
//= reason=cwnd reconciliation retains only selected protocol extensions: RFC9937 section5 recommends RACK-TLP, whose RFC8985 sections7.3/9.3 permit one accounted outstanding probe. This wire matrix asserts flight=cwnd before the probe, flight=cwnd+SMSS after, committed probe endpoints, RTO fallback and no second output. ordinary_output_policy_matrix and selected_recovery_output_policy_matrix cover normal cwnd/pipe/strict-PRR bounds and RFC3042 section2 bounded Limited Transmit separately; LegacyInitialCredit is not strict PRR evidence.
//# At any given time, a connection MUST
//# NOT send data if inflight (see below) matches or exceeds cwnd.
fn probe_and_shrink_output_policy_matrix() {
    for iss in [100, u32::MAX - 1999] {
        let (mut a, _) = tlp_pair(iss);
        let base = a.snd_una;
        a.write(&[1; 6000]).unwrap();
        assert_eq!(
            outputs(&mut a, 100_000, base),
            vec![(0, 1000), (1000, 1000), (2000, 1000), (3000, 1000)]
        );
        let pto = a.tlp_deadline.unwrap();
        assert_eq!(a.flight(), a.congestion.cwnd());
        assert!(a.prr.is_none()); // PTO exception is outside active PRR.
        a.timeout(pto).unwrap();
        assert_eq!(outputs(&mut a, pto, base), vec![(4000, 1000)]);
        assert_eq!(a.flight(), a.congestion.cwnd() + 1000);
        assert_eq!(
            a.tlp_end,
            Some((base.wrapping_add(4000), base.wrapping_add(5000), false))
        );
        assert_eq!(a.tlp_flight, Some(base.wrapping_add(5000)));
        assert!(!a.tlp_pending);
        assert_eq!(a.loss_timer.unwrap().0, LossTimer::Rto);
        assert_eq!(outputs(&mut a, pto + 1, base), vec![]);
        let (mut a, _) = tlp_pair(iss);
        let base = a.snd_una;
        let next = a.receive.next();
        a.write(&[1; 6000]).unwrap();
        assert_eq!(outputs(&mut a, 100_000, base).len(), 4);
        let window = (4000 >> a.peer_scale) as u16;
        inject(&mut a, 200_000, next, base, ACK, window, &[]);
        let pto = a.tlp_deadline.unwrap();
        a.timeout(pto).unwrap();
        assert_eq!(outputs(&mut a, pto, base), vec![(3000, 1000)]);
        assert_eq!(a.flight(), 4000); // no fresh-data receive-window overcommit

        let (mut a, _) = pair(config(128, 8), iss);
        a.scaling = false; // conservative unscaled retry policy
        let base = a.snd_una;
        let next = a.receive.next();
        a.write(b"abcdefghijkl").unwrap();
        packet(&mut a, 40);
        let high = a.snd_nxt;
        inject(&mut a, 50, next, base, ACK, 3, &[]);
        assert_eq!(outputs(&mut a, 51, base), vec![]);
        let rto = a.rto_deadline.unwrap();
        a.timeout(rto).unwrap();
        assert_eq!(outputs(&mut a, rto, base), vec![(0, 3)]);
        assert_eq!(a.snd_nxt, high);
        inject(&mut a, rto + 1, next, base, ACK, 0, &[]);
        assert_eq!(outputs(&mut a, rto + 1, base), vec![]);
        let probe = a.loss_timer.unwrap().1;
        a.timeout(probe).unwrap();
        assert_eq!(outputs(&mut a, probe, base), vec![(0, 1)]);
        assert_eq!(a.snd_nxt, high);
        assert_eq!(outputs(&mut a, probe + 1, base), vec![]);
    }
    // Scaled original-valid retries and optional old-data beyond-window policy
    // already have exact wire/rollback tests; neither permits unsent tail data.
    scaled_retry_wire_commit_partial_ack_and_persist_are_independent();
    scaled_retry_strict_sequence_distance_and_conservative_fallbacks();
    strict_prr_zero_window_cancels_epoch_before_persist_and_rearms_rto();
}

#[test]
fn half_flight_segment_output_observations() {
    // Receiver/packet-budget driven observations, not a section4.3 proof.
    // A same-time poll burst cannot include an ACK of a recovery transmission.
    for mss in [1u16, 13, 128] {
        let (mut a, _) = primed_pair(
            ConnectionConfig {
                initial_window: InitialWindow::Iw10,
                ..config(4096, mss)
            },
            100,
        );
        let base = a.snd_una;
        let next = a.receive.next();
        inject(&mut a, 35, next, base, ACK, 4096, &[]);
        a.write(&vec![1; 20 * mss as usize]).unwrap();
        assert_eq!(outputs(&mut a, 100_000, base).len(), 10);
        for _ in 0..3 {
            inject(&mut a, 200_000, next, base, ACK, 4096, &[]);
        }
        assert_eq!(outputs(&mut a, 200_000, base), vec![(0, mss as usize)]);
        inject(
            &mut a,
            300_000,
            next,
            base.wrapping_add(mss as u32),
            ACK,
            4096,
            &[],
        );
        assert_eq!(
            outputs(&mut a, 300_000, base),
            vec![(mss as u32, mss as usize)]
        );
        assert!(a.congestion.in_fast_recovery());

        for duplex in [false, true] {
            let (mut a, _) = pair(
                ConnectionConfig {
                    sack: true,
                    initial_window: InitialWindow::Iw10,
                    send_ip_payload_limit: (20 + mss).max(32),
                    ..config(4096, mss)
                },
                100,
            );
            let base = a.snd_una;
            let next = a.receive.next();
            a.write(&vec![1; 10 * mss as usize]).unwrap();
            assert_eq!(outputs(&mut a, 100_000, base).len(), 10);
            let ranges = [(
                base.wrapping_add(7 * mss as u32).0,
                base.wrapping_add(10 * mss as u32).0,
            )];
            // One ACK proves three delivered segments and enters RFC6675;
            // duplex out-of-order data additionally requires outgoing SACK.
            inject_sack(
                &mut a,
                200_000,
                if duplex { next.wrapping_add(2) } else { next },
                base,
                ACK,
                4096,
                if duplex { b"x" } else { b"" },
                &ranges,
            );
            let sack = outputs(&mut a, 200_000, base);
            if duplex && mss == 13 {
                // A negotiated 12-byte SACK option leaves one payload byte
                // within the fixed 33-byte path budget: no state mutation.
                assert_eq!(sack, (0..53).map(|offset| (offset, 1)).collect::<Vec<_>>());
                assert_eq!(a.sack_recovery.unwrap().pipe, 53);
            } else if duplex && mss == 128 {
                // Piggybacked SACK clips each original to 116 bytes, then
                // retransmits its 12-byte suffix as a distinct wire packet.
                assert_eq!(
                    sack,
                    vec![
                        (0, 116),
                        (116, 12),
                        (128, 116),
                        (244, 12),
                        (256, 116),
                        (372, 12),
                        (384, 116),
                        (500, 12),
                        (512, 116)
                    ]
                );
                assert_eq!(a.sack_recovery.unwrap().pipe, 628);
            } else {
                assert_eq!(
                    sack,
                    (0..5)
                        .map(|i| (i * mss as u32, mss as usize))
                        .collect::<Vec<_>>()
                );
                assert_eq!(a.sack_recovery.unwrap().pipe, 5 * mss as u32);
            }
            assert!(a.sack_recovery.is_some()); // unresolved holes
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
//= type=test
//= reason=Real advancing ACK with fresh SACK evidence marks loss through both RACK and RFC6675; independently calculated credit excludes the extra SMSS, without target clipping; the rescue counterpart independently proves genuine safe advancement grants it.
//# SafeACK = (SND.UNA advances and no further loss indicated)
fn rfc9937_safe_ack_advancing_new_loss_denies_extra_smss() {
    for iss in [0, u32::MAX - 4999] {
        for rack in [false, true] {
            let mut a = strict_flight(iss);
            a.config.rack = rack;
            let base = a.snd_una;
            assert_eq!(a.rack.counts().lost, 0);
            rack_sack(&mut a, 200_000, 500, &[(7000, 10_000)]);
            assert_eq!(a.snd_una, base.wrapping_add(500));
            assert!(a.rack.counts().lost > 0);
            assert!(!a.retx_pending);
            assert_eq!(a.prr.unwrap().counters(), (10_000, 3500, 0));
            assert_eq!(a.sack_recovery.unwrap().pipe, 0);
            assert_eq!(a.congestion.ssthresh(), 4750);
            // DeliveredData = 500 cumulative + 3000 newly SACKed.
            // Unsafe: min(4750 - 0, max(3500 - 0, 3500)) = 3500.
            // Safe would grant 4500: neither target nor entry floor hides SMSS.
            assert_eq!(a.prr.unwrap().credit(), 3500);
            assert_eq!(a.congestion.cwnd(), 3500);
            assert_eq!(
                outputs(&mut a, 200_000, base),
                vec![(500, 500), (1000, 1000), (2000, 1000), (3000, 1000)]
            );
            assert_eq!(a.prr.unwrap().counters(), (10_000, 3500, 3500));
            assert_eq!(a.prr.unwrap().credit(), 0);
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
//= type=test
//= reason=Real RFC6675 retransmissions establish HighRxt and RescueRxt; an advancing ACK with no new loss indicates a tail rescue and denies an extra SMSS. Identical flight with queued new data instead grants the safe bonus; independent byte equations and parsed output distinguish them.
//# SafeACK = (SND.UNA advances and no further loss indicated)
fn rfc9937_safe_ack_advancing_rescue_denies_extra_smss() {
    for iss in [0, u32::MAX - 4999] {
        for new_data in [false, true] {
            let mut a = strict_flight(iss);
            a.config.rack = false;
            let base = a.snd_una;
            let sacks = [(5000, 8000), (9500, 10_000)];
            strict_ack(&mut a, 200_000, 0, &sacks);
            assert_eq!(
                outputs(&mut a, 200_000, base),
                vec![(0, 1000), (1000, 1000), (2000, 1000), (3000, 500)]
            );
            strict_ack(&mut a, 201_000, 1000, &sacks);
            assert_eq!(
                outputs(&mut a, 201_000, base),
                vec![(3500, 500), (4000, 500)]
            );
            strict_ack(&mut a, 202_000, 2000, &sacks);
            assert_eq!(
                outputs(&mut a, 202_000, base),
                vec![(4500, 500), (8000, 500)]
            );
            strict_ack(&mut a, 203_000, 3000, &sacks);
            assert_eq!(
                outputs(&mut a, 203_000, base),
                vec![(8500, 500), (9000, 500)]
            );
            let recovery = a.sack_recovery.unwrap();
            assert!(!recovery.entry_pending);
            assert_eq!(recovery.high_rxt, base.wrapping_add(9500));
            assert_eq!(recovery.rescue_rxt, Some(base.wrapping_add(1000)));
            assert_eq!(recovery.pipe, 5000);
            assert_eq!(a.prr.unwrap().counters(), (10_000, 6500, 6500));
            assert_eq!(a.rack.counts().lost, 2); // Original lost head, cleared by the ACK.
            assert!(!a.retx_pending);
            if new_data {
                a.write(&[0x66; 4000]).unwrap();
            }
            // Cumulative ACK trims 3000 previously SACKed bytes and delivers
            // 2000 lost/retransmitted + 1000 speculatively retransmitted bytes.
            // It creates no loss; the only remaining hole is [9000,9500),
            // below HighRxt, and HighACK has passed the entry RescueRxt.
            rack_sack(&mut a, 204_000, 9000, &[(9500, 10_000)]);
            assert_eq!(a.snd_una, base.wrapping_add(9000));
            assert_eq!(a.rack.counts().lost, 0);
            assert!(!a.retx_pending);
            assert_eq!(a.prr.unwrap().counters(), (10_000, 9500, 6500));
            assert_eq!(a.sack_recovery.unwrap().pipe, 1000);
            assert_eq!(a.congestion.ssthresh(), 5000);
            // Unsafe: min(5000 - 1000, max(9500 - 6500, 3000)) = 3000.
            // Safe, when NextSeg can send new data instead: 3000 + SMSS = 4000.
            let credit = if new_data { 4000 } else { 3000 };
            assert_eq!(a.prr.unwrap().credit(), credit);
            assert_eq!(a.congestion.cwnd(), 1000 + credit);
            let sent = outputs(&mut a, 204_000, base);
            if new_data {
                assert_eq!(
                    sent,
                    vec![
                        (10_000, 1000),
                        (11_000, 1000),
                        (12_000, 1000),
                        (13_000, 1000)
                    ]
                );
                assert_eq!(a.prr.unwrap().credit(), 0);
                assert_eq!(a.sack_recovery.unwrap().rescue_rxt, recovery.rescue_rxt);
            } else {
                assert_eq!(sent, vec![(9000, 500)]);
                assert_eq!(a.prr.unwrap().credit(), 2500);
                assert_eq!(a.sack_recovery.unwrap().high_rxt, recovery.high_rxt);
                assert_eq!(
                    a.sack_recovery.unwrap().rescue_rxt,
                    Some(recovery.recovery_point)
                );
            }
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9937#section-6.4
//= type=test
//# It is RECOMMENDED that implementations use pacing to reduce the
//# burstiness of data traffic.
fn pacing_wire_spacing_units_idle_and_failed_output() {
    assert!(ConnectionConfig::default().prr_pacing);
    for scale in [1, 1000] {
        for mss in [1, 64, 1000] {
            let cfg = ConnectionConfig {
                prr: true,
                nagle: false,
                timebase: CallerTimebase {
                    units_per_second: 1_000_000 * scale,
                    ..CallerTimebase::default()
                },
                mss,
                send_capacity: 65_536,
                receive_capacity: 65_536,
                ..ConnectionConfig::default()
            };
            let (mut a, _) = pair(cfg, 0);
            a.rtt = RttEstimator::with_timebase(1_000_000, a.config.timebase);
            a.rtt.sample(100_003 * scale);
            let start = 100_000 * scale;
            let bytes = mss as usize;
            let cwnd = a.congestion.cwnd() as u64;
            a.write(&vec![0x55; bytes * 2 + 1]).unwrap();
            let state = (a.snd_nxt, a.now, a.rack.pipe(), a.pacing_deadline);
            assert_eq!(a.transmit(start, &mut [0; 19]), Err(Error::OutputTooSmall));
            assert_eq!((a.snd_nxt, a.now, a.rack.pipe(), a.pacing_deadline), state);
            let first = packet(&mut a, start);
            assert_eq!(
                wire::parse(ip(tuple()), &first).unwrap().payload.len(),
                bytes
            );
            let spacing = (bytes as u64 * 100_003 * scale).div_ceil(cwnd).max(1);
            let deadline = start + spacing;
            assert_eq!(a.next_deadline(), Some(deadline));
            assert!(a.transmit(start, &mut [0; 1500]).unwrap().is_none());
            assert!(a.transmit(deadline - 1, &mut [0; 1500]).unwrap().is_none());
            assert_eq!(
                a.transmit(deadline, &mut [0; 19]),
                Err(Error::OutputTooSmall)
            );
            assert_eq!(a.pacing_deadline, Some(deadline));
            let second = packet(&mut a, deadline);
            assert_eq!(
                wire::parse(ip(tuple()), &second).unwrap().payload.len(),
                bytes
            );
            assert!(a.transmit(deadline, &mut [0; 1500]).unwrap().is_none());
            // Delayed polling must not accumulate credit; ACK the old flight,
            // then restart after an idle interval with a short first segment.
            let idle = deadline + 2_000_000 * scale;
            let seq = a.receive.next();
            let high = a.snd_nxt;
            inject(&mut a, idle, seq, high, ACK, 65_535, &[]);
            let short = packet(&mut a, idle);
            assert_eq!(wire::parse(ip(tuple()), &short).unwrap().payload.len(), 1);
            let rtt = a.rtt.srtt().unwrap();
            let short_spacing = rtt.div_ceil(a.congestion.cwnd() as u64).max(1);
            assert_eq!(a.pacing_deadline, Some(idle + short_spacing));
            a.write(&vec![0x55; bytes * 2]).unwrap();
            assert!(a.transmit(idle, &mut [0; 1500]).unwrap().is_none());
            packet(&mut a, idle + short_spacing);
            assert!(
                a.transmit(idle + short_spacing, &mut [0; 1500])
                    .unwrap()
                    .is_none()
            );
        }
    }
    // No SRTT uses the initial estimator's one-second RTO. Sub-tick byte
    // spacing rounds up to one caller tick rather than allowing same-time data.
    let (mut a, _) = pair(
        ConnectionConfig {
            prr: true,
            nagle: false,
            mss: 1,
            ..ConnectionConfig::default()
        },
        0,
    );
    a.rtt = RttEstimator::new(1_000_000);
    a.write(b"abc").unwrap();
    packet(&mut a, 40);
    assert_eq!(
        a.pacing_deadline,
        Some(40 + 1_000_000u64.div_ceil(a.congestion.cwnd() as u64))
    );
    let due = a.pacing_deadline.unwrap();
    a.rtt.sample(1);
    packet(&mut a, due);
    assert_eq!(a.pacing_deadline, Some(due + 1));
    assert!(a.transmit(due, &mut [0; 1500]).unwrap().is_none());
}

#[test]
fn pacing_recovery_budget_exit_and_control() {
    for rack in [false, true] {
        let mut a = strict_flight(0);
        // Flight helper is an equation oracle; enable pacing for every repair
        // and all output after the actual recovery completion below.
        a.config.prr_pacing = true;
        a.config.rack = rack;
        strict_ack(&mut a, 200_000, 0, &[(7000, 10_000)]);
        let before = a.prr.unwrap();
        assert!(before.credit() >= 1000);
        let first = prr_packet(&mut a, 200_000);
        assert_eq!(first.1, 1000);
        assert_eq!(a.prr.unwrap().counters().2, before.counters().2 + 1000);
        let deadline = a.pacing_deadline.unwrap();
        let snapshot = a.prr.unwrap().counters();
        assert!(a.transmit(200_000, &mut [0; 1500]).unwrap().is_none());
        assert_eq!(a.prr.unwrap().counters(), snapshot);
        // A pending head retry and ACK must survive a blocked data poll.
        a.retx_pending = true;
        a.immediate_ack();
        let ack = packet(&mut a, 200_000);
        let ack = wire::parse(ip(tuple()), &ack).unwrap();
        assert!(ack.payload.is_empty());
        assert_eq!(ack.header.flags & (FIN | RST), 0);
        assert!(a.retx_pending);
        assert_eq!(a.prr.unwrap().counters(), snapshot);
        a.challenge_ack_pending = true;
        let challenge = packet(&mut a, 200_000);
        assert!(
            wire::parse(ip(tuple()), &challenge)
                .unwrap()
                .payload
                .is_empty()
        );
        assert!(a.retx_pending);
        assert_eq!(a.pacing_deadline, Some(deadline));
        assert!(a.transmit(deadline - 1, &mut [0; 1500]).unwrap().is_none());
        assert_eq!(
            a.transmit(deadline, &mut [0; 19]),
            Err(Error::OutputTooSmall)
        );
        assert!(a.retx_pending);
        assert_eq!(a.prr.unwrap().counters(), snapshot);
        let sent = prr_packet(&mut a, deadline).1;
        assert!(sent as u32 <= before.credit() - 1000);
        assert!(!a.retx_pending);
        let exit_deadline = a.pacing_deadline.unwrap();
        a.write(&[0x55; 6000]).unwrap();
        strict_ack(&mut a, deadline, 10_000, &[]);
        assert!(a.prr.is_none());
        assert_eq!(a.congestion.cwnd(), a.congestion.ssthresh());
        assert_eq!(a.pacing_deadline, Some(exit_deadline));
        // This is a real full boundary ACK, with enough cwnd/queued data for
        // several packets, not a synthetic call to complete_prr.
        assert!(a.transmit(deadline, &mut [0; 1500]).unwrap().is_none());
        let base = a.snd_una;
        assert_eq!(outputs(&mut a, exit_deadline, base).len(), 1);
        a.abort();
        assert_eq!(a.pacing_deadline, None);
        let reset = packet(&mut a, exit_deadline);
        assert_ne!(
            wire::parse(ip(tuple()), &reset).unwrap().header.flags & RST,
            0
        );
        assert_eq!(a.pacing_deadline, None);
    }
}

#[test]
fn pacing_selection_gates_protocol_probes_and_widened_rate() {
    for (prr, algorithm, pacing) in [
        (false, PrrAlgorithm::Rfc9937, true),
        (true, PrrAlgorithm::LegacyInitialCredit, true),
        (true, PrrAlgorithm::Rfc9937, false),
    ] {
        let (mut a, _) = pair(
            ConnectionConfig {
                prr,
                prr_algorithm: algorithm,
                prr_pacing: pacing,
                nagle: false,
                ..config(65_536, 1000)
            },
            0,
        );
        a.write(&[0x55; 2000]).unwrap();
        assert_eq!(outputs(&mut a, 40, Seq(1)).len(), 2);
        assert_eq!(a.pacing_deadline, None);
    }
    let (mut a, _) = pair(
        ConnectionConfig {
            prr: true,
            prr_pacing: true,
            nagle: false,
            ..config(65_536, 1000)
        },
        0,
    );
    a.rtt = RttEstimator::new(1_000_000);
    a.rtt.sample(u64::MAX / 8);
    a.write(&[0x55; 1000]).unwrap();
    let cwnd = a.congestion.cwnd();
    packet(&mut a, 40);
    let spacing = (1000u128 * (u64::MAX / 8) as u128).div_ceil(cwnd as u128) as u64;
    assert_eq!(a.pacing_deadline, Some(40 + spacing));
    // A due RTO must honor its protocol deadline even if eligibility is far
    // later. Failed encoding leaves both obligations intact.
    let expiry = a.loss_timer.unwrap().1;
    a.timeout(expiry).unwrap();
    assert!(a.retx_pending);
    assert!(a.pacing_deadline.unwrap() > expiry);
    assert_eq!(a.transmit(expiry, &mut [0; 19]), Err(Error::OutputTooSmall));
    assert!(a.retx_pending);
    let bytes = packet(&mut a, expiry);
    assert_eq!(
        wire::parse(ip(tuple()), &bytes).unwrap().payload.len(),
        1000
    );
    assert!(!a.retx_pending);

    for probe in [false, true] {
        let (mut a, _) = tlp_pair(0);
        a.config.prr_algorithm = PrrAlgorithm::Rfc9937;
        a.config.prr_pacing = true;
        a.write(&[0x55; 2000]).unwrap();
        packet(&mut a, 100_000);
        // Keep eligibility beyond the actual protocol expiration to exercise
        // the scoped bypass, independently of the normal RTO>SRTT relation.
        if probe {
            let seq = a.receive.next();
            let una = a.snd_una;
            inject(&mut a, 100_001, seq, una, ACK, 0, &[]);
        }
        let expiry = a.loss_timer.unwrap().1;
        a.pacing_deadline = Some(expiry + 1_000_000);
        a.timeout(expiry).unwrap();
        assert!(if probe {
            a.probe_pending
        } else {
            a.tlp_pending
        });
        let old_nxt = a.snd_nxt;
        let bytes = packet(&mut a, expiry);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.payload.len(), if probe { 1 } else { 1000 });
        if probe {
            assert_eq!(a.snd_nxt, old_nxt);
        }
        let spacing = (segment.payload.len() as u128 * a.rtt.srtt().unwrap() as u128)
            .div_ceil(a.congestion.cwnd() as u128)
            .max(1) as u64;
        assert_eq!(a.pacing_deadline, Some(expiry + spacing));
    }
    // A due pacer never supplies PRR credit of its own.
    let mut a = strict_flight(0);
    a.config.prr_pacing = true;
    strict_ack(&mut a, 200_000, 0, &[(7000, 10_000)]);
    while a.prr.unwrap().credit() != 0 {
        let now = a.pacing_deadline.unwrap_or(200_000);
        prr_packet(&mut a, now);
    }
    let deadline = a.pacing_deadline.unwrap();
    let before = a.prr.unwrap().counters();
    a.timeout(deadline).unwrap();
    assert!(a.transmit(deadline, &mut [0; 1500]).unwrap().is_none());
    assert_eq!(a.prr.unwrap().counters(), before);
    assert!(a.next_deadline().is_none_or(|next| next > deadline));
}

#[test]
fn pacing_no_sack_retries_with_default_policy() {
    let (mut a, _) = primed_pair(
        ConnectionConfig {
            prr: true,
            nagle: false,
            initial_window: InitialWindow::Iw10,
            mss: 1000,
            send_capacity: 65_536,
            receive_capacity: 65_536,
            ..ConnectionConfig::default()
        },
        0,
    );
    assert!(!a.sack_send && a.config.prr_pacing);
    a.rtt = RttEstimator::new(1_000_000);
    a.rtt.sample(100_000);
    a.write(&[0x55; 10_000]).unwrap();
    let mut now = 100_000;
    for _ in 0..10 {
        let bytes = packet(&mut a, now);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().payload.len(),
            1000
        );
        assert!(a.transmit(now, &mut [0; 1500]).unwrap().is_none());
        now = a.pacing_deadline.unwrap();
    }
    let seq = a.receive.next();
    let una = a.snd_una;
    let window = (a.snd_wnd >> a.peer_scale) as u16;
    for _ in 0..3 {
        inject(&mut a, now, seq, una, ACK, window, &[]);
    }
    assert_eq!(a.prr.unwrap().counters(), (10_000, 1000, 0));
    assert_eq!(a.prr.unwrap().credit(), 500);
    assert_eq!(prr_packet(&mut a, now).1, 500);
    let deadline = a.pacing_deadline.unwrap();
    // Further delivered-byte estimates grant credit, but not elapsed time.
    inject(&mut a, now, seq, una, ACK, window, &[]);
    let counters = a.prr.unwrap().counters();
    let credit = a.prr.unwrap().credit();
    assert!(credit != 0);
    assert!(a.transmit(now, &mut [0; 1500]).unwrap().is_none());
    assert!(a.transmit(deadline - 1, &mut [0; 1500]).unwrap().is_none());
    assert_eq!(a.prr.unwrap().counters(), counters);
    assert!(prr_packet(&mut a, deadline).1 as u32 <= credit);
}
