use super::*;

fn isolated_config(mode: u8, prr: bool, cubic: bool, paced: bool) -> ConnectionConfig {
    ConnectionConfig {
        pmtud: Some(crate::PmtudConfig::new(1500)),
        initial_window: InitialWindow::Iw10,
        sack: mode != 0,
        rack: mode == 2,
        prr,
        prr_algorithm: PrrAlgorithm::Rfc9937,
        prr_pacing: paced,
        pacing: paced.then_some(PacingConfig::default()),
        congestion_algorithm: if cubic {
            crate::CongestionAlgorithm::Cubic
        } else {
            crate::CongestionAlgorithm::Reno
        },
        ecn: true,
        timestamps: false,
        nagle: false,
        delayed_ack_us: 0,
        ..config(65_536, 1460)
    }
}

fn paced_packet(a: &mut Connection, now: &mut u64) -> Vec<u8> {
    let mut out = vec![0; 2000];
    for _ in 0..10 {
        if let Some(len) = a.transmit(*now, &mut out).unwrap() {
            out.truncate(len);
            return out;
        }
        let deadline = a
            .pacing_deadline
            .expect("repair must have admission, not wait for RTO");
        *now = (*now).max(deadline);
        a.timeout(*now).unwrap();
    }
    panic!("pacing did not release output");
}

fn real_ack(a: &mut Connection, b: &mut Connection, bytes: &[u8], now: u64, ce: bool) {
    let segment = wire::parse(ip(a.tuple), bytes).unwrap();
    b.input_with_traffic_class(now, if ce { 3 } else { 0 }, &segment)
        .unwrap();
    deliver(b, a, now);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-4
//= type=test
//= reason=Partial no-PTB evidence from 76800de plus a4b9a0c: provisional normal repair admission and PRR remain active; only finite preloss extended-tail cumulative proof followed by recovery/PRR exit suppresses the logical loss response. Real receiver NewReno/SACK/RACK, PRR, Reno/CUBIC and pacing matrices assert isolated suppression and normal response on other loss; disqualifiers cover ECE, RTO and ordinary loss. Replenishment retains nonempty flight and resumes ACK growth. Independent MSS decrease scaling remains, not literal unchanged-cwnd advice. Partial gap: RFC4821 sections 2, 4 and 7.6.2 cover isolated loss with or without matching PTB. apply_ptb cancels probe classification; resolve_probe_response commits normal congestion response even when only the probe is lost and trailing packets are delivered, as asserted by the IPv6 two-PTB fixture. No-PTB evidence does not close this full span.
//# Normal congestion control algorithms MUST remain in effect under all conditions
//# except when only an isolated probe packet is detected as lost. In this case
//# alone, the normal congestion (window or data rate) reduction SHOULD be
//# suppressed. If any other data loss is detected, standard congestion control MUST
//# take place.

//= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.2
//= type=test
//= reason=Partial no-PTB evidence from 76800de plus a4b9a0c: provisional normal repair admission and PRR remain active; only finite preloss extended-tail cumulative proof followed by recovery/PRR exit suppresses the logical loss response. Real receiver NewReno/SACK/RACK, PRR, Reno/CUBIC and pacing matrices assert isolated suppression and normal response on other loss; disqualifiers cover ECE, RTO and ordinary loss. Replenishment retains nonempty flight and resumes ACK growth. Independent MSS decrease scaling remains, not literal unchanged-cwnd advice. Pmtud::ack narrows search_high to probe size minus one after the finite proof. Partial gap: RFC4821 sections 2, 4 and 7.6.2 cover isolated loss with or without matching PTB. apply_ptb cancels probe classification; resolve_probe_response commits normal congestion response even when only the probe is lost and trailing packets are delivered, as asserted by the IPv6 two-PTB fixture. No-PTB evidence does not close this full span.
//# When only the probe is lost, it is treated as an indication that the Path MTU is
//# smaller than the probe size. In this case alone, the loss SHOULD NOT be
//# interpreted as congestion signal.

//= https://www.rfc-editor.org/rfc/rfc4821#section-4
//= type=test
//= reason=Reviewed 76800de plus a4b9a0c: isolated suppression waits for finite cumulative proof and recovery exit; pmtu_cooldown uses the unsuppressed logical window, not transient PRR admission, with one RTT per packet plus a strict extra interval/tick and an RTO floor. Real receiver matrix checks no target before the deadline and a target at it; dedicated arithmetic test distinguishes logical14600 from admission1000. Mandatory failure cooldown is independent of configurable periodic aging.
//# Suppressed congestion control MUST be rate limited such that it occurs less
//# frequently than the worst-case loss rate for TCP congestion control at a
//# comparable data rate over the same path (i.e., less than the "TCP-friendly" loss
//# rate [tcp-friendly]). This SHOULD be enforced by requiring a minimum headway
//# between a suppressed congestion adjustment (due to a failed probe) and the next
//# attempted probe, which is equal to one round-trip time for each packet permitted
//# by the congestion window. This is discussed further in Section 7.6.2.

//= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.2
//= type=test
//= reason=Partial no-PTB evidence from 76800de plus a4b9a0c: isolated suppression waits for finite cumulative proof and recovery exit; pmtu_cooldown uses the unsuppressed logical window, not transient PRR admission, with one RTT per packet plus a strict extra interval/tick and an RTO floor. Real receiver matrix checks no target before the deadline and a target at it; dedicated arithmetic test distinguishes logical14600 from admission1000. Mandatory failure cooldown is independent of configurable periodic aging. Partial gap: RFC4821 sections 2, 4 and 7.6.2 cover isolated loss with or without matching PTB. apply_ptb cancels probe classification; resolve_probe_response commits normal congestion response even when only the probe is lost and trailing packets are delivered, as asserted by the IPv6 two-PTB fixture. No-PTB evidence does not close this full span.
//# A probe failure event is the one situation under which the Packetization Layer
//# SHOULD ignore loss as a congestion signal. Because there is some small risk that
//# suppressing congestion control might have unanticipated consequences (even for
//# one isolated loss), it is REQUIRED that probe failure events be less frequent
//# than the normal period for losses under standard congestion control.
//# Specifically, after a probe failure event and suppressed congestion control,
//# PLPMTUD MUST NOT probe again until an interval that is larger than the expected
//# interval between congestion control events. See Section 4 for details. The
//# simplest estimate of the interval to the next congestion event is the same
//# number of round trips as the current congestion window in packets.

fn isolated_probe_cc_real_receiver_recovery_matrix() {
    for mode in 0..3 {
        for prr in [false, true] {
            for cubic in [false, true] {
                for paced in [false, true] {
                    for second_hole in [false, true] {
                        let (mut a, mut b) =
                            pair(isolated_config(mode, prr, cubic, paced), u32::MAX - 4000);
                        a.write(b"x").unwrap();
                        deliver(&mut a, &mut b, 32);
                        deliver(&mut b, &mut a, 33);
                        a.write(&[7; 20_000]).unwrap();
                        let mut now = 40;
                        paced_packet(&mut a, &mut now); // Only the explicit probe is dropped.
                        let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
                        let (window, threshold, old_mss) =
                            (a.congestion.cwnd(), a.congestion.ssthresh(), a.mss);
                        let mut trailing = Vec::new();
                        for _ in 0..8 {
                            trailing.push(paced_packet(&mut a, &mut now));
                        }
                        let trailing_end = a.snd_nxt;
                        assert!(after(trailing_end, probe.trailing_end));
                        now += 100;
                        for (n, bytes) in trailing.iter().enumerate() {
                            if second_hole && n == 5 {
                                continue;
                            }
                            real_ack(&mut a, &mut b, bytes, now, false);
                        }
                        if !a.congestion.in_recovery() {
                            now = a.rack.deadline.expect("RACK must schedule loss detection");
                            a.timeout(now).unwrap();
                        }
                        assert!(a.congestion.in_recovery());
                        if !second_hole || mode == 0 {
                            assert_eq!(a.congestion.pending_probe_response(), Some(probe.start));
                            assert_eq!(a.congestion.unsuppressed_cwnd(), window);
                            assert_eq!(a.congestion.ssthresh(), threshold);
                        }
                        let initial_prr = a.prr.map(|p| p.counters());
                        assert_eq!(initial_prr.is_some(), prr);
                        let mut sent = 0;
                        // PRR counters immediately before the ACK that concludes the episode.
                        let mut concluding = None;
                        for _ in 0..20 {
                            now += 1;
                            let bytes = paced_packet(&mut a, &mut now);
                            let segment = wire::parse(ip(a.tuple), &bytes).unwrap();
                            sent += segment.payload.len() as u64;
                            if let Some(p) = a.prr {
                                assert_eq!(p.counters().0, initial_prr.unwrap().0);
                                assert_eq!(p.counters().2, sent);
                                assert!(p.counters().1 <= u64::from(p.counters().0));
                            }
                            let active = a.prr.map(|p| p.counters());
                            real_ack(&mut a, &mut b, &bytes, now, false);
                            if active.is_some() && a.prr.is_none() {
                                concluding = active;
                            }
                            if a.pmtud.as_ref().unwrap().probe.is_none() {
                                break;
                            }
                        }
                        assert!(
                            a.pmtud.as_ref().unwrap().probe.is_none(),
                            "mode={mode}, prr={prr}, cubic={cubic}, paced={paced}, second={second_hole}"
                        );
                        assert!(a.congestion.pending_probe_response().is_none());
                        if second_hole {
                            assert!(a.congestion.ssthresh() < threshold);
                            assert!(a.congestion.cwnd() < window);
                        } else {
                            assert_eq!(a.snd_una, trailing_end);
                            assert_eq!(
                                a.congestion.cwnd(),
                                (u64::from(window) * a.mss as u64 / old_mss as u64) as u32
                            );
                            assert_eq!(a.congestion.ssthresh(), threshold);
                            assert!(a.prr.is_none());
                            if prr {
                                assert_eq!(concluding.unwrap().2, sent);
                            }
                            let deadline = a.pmtud.as_ref().unwrap().deadline.unwrap();
                            let interval =
                                (u64::from(window) / old_mss as u64) * a.rtt.srtt().unwrap();
                            assert!(deadline - now > interval);
                            let p = a.pmtud.as_mut().unwrap();
                            p.tick(deadline - 1);
                            assert!(p.target().is_none());
                            p.tick(deadline);
                            assert!(p.target().is_some());
                        }
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Disqualifier {
    Leading,
    Timeout,
    Ecn,
    Implicit,
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-4
//= type=test
//= reason=Partial no-PTB evidence from 76800de plus a4b9a0c: provisional normal repair admission and PRR remain active; only finite preloss extended-tail cumulative proof followed by recovery/PRR exit suppresses the logical loss response. Real receiver NewReno/SACK/RACK, PRR, Reno/CUBIC and pacing matrices assert isolated suppression and normal response on other loss; disqualifiers cover ECE, RTO and ordinary loss. Replenishment retains nonempty flight and resumes ACK growth. Independent MSS decrease scaling remains, not literal unchanged-cwnd advice. Partial gap: RFC4821 sections 2, 4 and 7.6.2 cover isolated loss with or without matching PTB. apply_ptb cancels probe classification; resolve_probe_response commits normal congestion response even when only the probe is lost and trailing packets are delivered, as asserted by the IPv6 two-PTB fixture. No-PTB evidence does not close this full span.
//# Normal congestion control algorithms MUST remain in effect under all conditions
//# except when only an isolated probe packet is detected as lost. In this case
//# alone, the normal congestion (window or data rate) reduction SHOULD be
//# suppressed. If any other data loss is detected, standard congestion control MUST
//# take place.

//= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.3
//= type=test
//= reason=Reviewed 76800de: real receiver disqualifier matrix drops a probe repair and fires actual TCP RTO, asserting one-MSS cwnd, reduced threshold and committed response throughout cumulative repair. Non-SACK NewReno as well as SACK/RACK, PRR and Reno/CUBIC are exercised. Pmtud::timeout applies five times cooldown; exact deadline unit test and integrated timeout trace prove later inconclusive retry loss cannot erase it. This is TCP timeout repair, not a new generic go-back-n transport.
//# If the loss was detected with a timeout and repaired with go-back-n
//# retransmission, then congestion window reduction will be necessary. The
//# relatively high price of a failed probe in this case may merit a longer time
//# interval until the next probe. A time interval that is five times the
//# non-timeout failure case (Section 7.6.2) is RECOMMENDED.

fn isolated_probe_cc_real_receiver_disqualifiers() {
    for mode in 0..3 {
        for prr in [false, true] {
            for cubic in [false, true] {
                for cause in [
                    Disqualifier::Leading,
                    Disqualifier::Timeout,
                    Disqualifier::Ecn,
                    Disqualifier::Implicit,
                ] {
                    let (mut a, mut b) = pair(isolated_config(mode, prr, cubic, false), 0);
                    a.write(b"x").unwrap();
                    deliver(&mut a, &mut b, 32);
                    deliver(&mut b, &mut a, 33);
                    if matches!(cause, Disqualifier::Leading) {
                        a.write(b"l").unwrap();
                        packet(&mut a, 39); // Separate ordinary leading loss.
                    }
                    if matches!(cause, Disqualifier::Implicit) {
                        a.pmtud.as_mut().unwrap().deadline = Some(100_000_000);
                    }
                    a.write(&[7; 20_000]).unwrap();
                    packet(&mut a, 40);
                    let probe = a.pmtud.as_ref().unwrap().probe;
                    assert_eq!(probe.is_none(), matches!(cause, Disqualifier::Implicit));
                    let old_threshold = a.congestion.ssthresh();
                    let mut trailing = Vec::new();
                    for _ in 0..8 {
                        trailing.push(packet(&mut a, 41));
                    }
                    let mut now = 140;
                    for (n, bytes) in trailing.iter().enumerate() {
                        real_ack(
                            &mut a,
                            &mut b,
                            bytes,
                            now,
                            matches!(cause, Disqualifier::Ecn) && n == 5,
                        );
                    }
                    if !a.congestion.in_recovery() {
                        now = a.rack.deadline.unwrap();
                        a.timeout(now).unwrap();
                    }
                    let timeout_delay = if matches!(cause, Disqualifier::Timeout) {
                        assert_eq!(
                            a.congestion.pending_probe_response(),
                            Some(probe.unwrap().start)
                        );
                        packet(&mut a, now + 1); // Drop first repair too; actual RTO must commit CC.
                        now = a.rto_deadline.unwrap();
                        a.timeout(now).unwrap();
                        assert_eq!(a.consecutive_timeouts, 1);
                        assert_eq!(a.congestion.cwnd(), a.mss as u32);
                        let delay = a.pmtud.as_ref().unwrap().deadline.unwrap();
                        assert!(delay > now + 5 * a.rtt.srtt().unwrap());
                        Some(delay)
                    } else {
                        None
                    };
                    assert!(
                        a.congestion.pending_probe_response().is_none(),
                        "{cause:?}, mode={mode}"
                    );
                    assert!(a.congestion.ssthresh() < old_threshold);
                    let committed = a.congestion.ssthresh();
                    // Real cumulative proof must never undo the committed event.
                    for _ in 0..24 {
                        now += 1;
                        let mut bytes = vec![0; 2000];
                        let mut len = a.transmit(now, &mut bytes).unwrap();
                        for _ in 0..10 {
                            if len.is_some() {
                                break;
                            }
                            now = a.next_deadline().expect("remaining gap needs a loss timer");
                            a.timeout(now).unwrap();
                            len = a.transmit(now, &mut bytes).unwrap();
                        }
                        bytes.truncate(len.expect("recovery must make progress"));
                        real_ack(&mut a, &mut b, &bytes, now, false);
                        assert!(a.congestion.pending_probe_response().is_none());
                        if probe.is_none() || a.pmtud.as_ref().unwrap().probe.is_none() {
                            break;
                        }
                    }
                    assert!(a.pmtud.as_ref().unwrap().probe.is_none());
                    assert!(a.congestion.ssthresh() < old_threshold);
                    if !matches!(cause, Disqualifier::Timeout) {
                        assert!(a.congestion.ssthresh() <= committed);
                    }
                    if let Some(delay) = timeout_delay {
                        // Lost retry makes the classification inconclusive, but
                        // cannot erase the timeout's fivefold holdoff.
                        assert!(
                            a.pmtud
                                .as_ref()
                                .unwrap()
                                .deadline
                                .is_some_and(|d| d >= delay)
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn isolated_probe_cc_commit_matches_normal_repair_and_mss_scaling() {
    for cubic in [false, true] {
        for sack in [false, true] {
            for event in 0..5 {
                let make = || {
                    crate::recovery::Congestion::new(
                        1460,
                        RecoveryAlgorithm::NewReno,
                        InitialWindow::Iw10,
                        Seq(0),
                    )
                    .with_congestion(
                        if cubic {
                            crate::CongestionAlgorithm::Cubic
                        } else {
                            crate::CongestionAlgorithm::Reno
                        },
                        CallerTimebase::default(),
                    )
                };
                let (mut ordinary, mut deferred) = (make(), make());
                let start = Seq(2);
                let end = Seq(12_002);
                if sack {
                    assert!(ordinary.on_sack_recovery(start, 12_000, end));
                    assert!(deferred.on_sack_recovery_with_probe(start, 12_000, end, Some(start)));
                } else {
                    for _ in 0..3 {
                        ordinary.on_duplicate_ack(start, 12_000, end, false);
                        deferred.on_duplicate_ack_with_probe(
                            start,
                            12_000,
                            end,
                            false,
                            Some(start),
                        );
                    }
                }
                assert_eq!(ordinary.cwnd(), deferred.cwnd());
                assert_eq!(ordinary.ssthresh(), deferred.recovery_target());
                assert_eq!(deferred.unsuppressed_cwnd(), 14_600);
                assert_eq!(deferred.ssthresh(), 0x7fff_ffff);
                ordinary.prr_window(7000);
                deferred.prr_window(7000);
                ordinary.set_path_mss(984);
                deferred.set_path_mss(984);
                assert_eq!(ordinary.cwnd(), deferred.cwnd());
                assert_eq!(ordinary.ssthresh(), deferred.recovery_target());
                assert_eq!(deferred.unsuppressed_cwnd(), 9840);
                // Neither logical nor repair byte windows increase with MSS.
                let admission = deferred.cwnd();
                deferred.set_path_mss(1460);
                ordinary.set_path_mss(1460);
                assert_eq!(deferred.cwnd(), admission);
                assert_eq!(deferred.unsuppressed_cwnd(), 9840);
                match event {
                    0 => deferred.commit_probe_response(),
                    1 => {
                        ordinary.on_ecn(start, 8000, end);
                        deferred.on_ecn(start, 8000, end);
                    }
                    2 => {
                        ordinary.on_tlp_repair(start, 8000, end);
                        deferred.on_tlp_repair(start, 8000, end);
                    }
                    3 => {
                        ordinary.retransmission_lost(8000);
                        deferred.retransmission_lost(8000);
                    }
                    _ => {
                        ordinary.on_timeout(8000, end);
                        deferred.on_timeout(8000, end);
                    }
                }
                assert!(deferred.pending_probe_response().is_none());
                assert_eq!(ordinary.cwnd(), deferred.cwnd());
                assert_eq!(ordinary.ssthresh(), deferred.ssthresh());
                let committed = (deferred.cwnd(), deferred.ssthresh());
                deferred.suppress_probe_response(start); // stale isolated proof is inert
                assert_eq!((deferred.cwnd(), deferred.ssthresh()), committed);
            }
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.2
//= type=test
//= reason=Partial no-PTB evidence from 76800de plus a4b9a0c: provisional normal repair admission and PRR remain active; only finite preloss extended-tail cumulative proof followed by recovery/PRR exit suppresses the logical loss response. Real receiver NewReno/SACK/RACK, PRR, Reno/CUBIC and pacing matrices assert isolated suppression and normal response on other loss; disqualifiers cover ECE, RTO and ordinary loss. Replenishment retains nonempty flight and resumes ACK growth. Independent MSS decrease scaling remains, not literal unchanged-cwnd advice. Pmtud::ack narrows search_high to probe size minus one after the finite proof. Partial gap: RFC4821 sections 2, 4 and 7.6.2 cover isolated loss with or without matching PTB. apply_ptb cancels probe classification; resolve_probe_response commits normal congestion response even when only the probe is lost and trailing packets are delivered, as asserted by the IPv6 two-PTB fixture. No-PTB evidence does not close this full span.
//# When only the probe is lost, it is treated as an indication that the Path MTU is
//# smaller than the probe size. In this case alone, the loss SHOULD NOT be
//# interpreted as congestion signal.

fn isolated_probe_cc_terminal_proof_once_and_only_after_extended_tail() {
    for start in [Seq(100), Seq(u32::MAX - 500)] {
        for disqualifier in 0..4 {
            let mut p =
                crate::pmtud::Pmtud::new(crate::PmtudConfig::new(1500), 1500, true, 600_000_000);
            p.start_probe(start, 1200, 3000, 1240);
            p.sent(start, start.wrapping_add(1200), 1240, 20, false);
            p.sent(
                start.wrapping_add(4200),
                start.wrapping_add(6000),
                1840,
                20,
                false,
            );
            p.loss(start, false);
            // Fresh output between loss detection and the first repair cannot
            // extend the already-emitted tail that the proof must cover.
            p.sent(
                start.wrapping_add(6000),
                start.wrapping_add(7200),
                1240,
                20,
                false,
            );
            p.sent(start, start.wrapping_add(984), 1024, 20, true);
            if disqualifier == 1 {
                p.loss(start.wrapping_add(5000), false);
            }
            if disqualifier == 2 {
                p.timeout(1, start, 1, 1000);
            }
            if disqualifier == 3 {
                p.sent(start, start.wrapping_add(984), 1024, 20, true);
            }
            p.ack(start.wrapping_add(4200), 10, 1000, 1000);
            assert!(p.take_probe_outcome(start.wrapping_add(6000)).is_none());
            assert!(p.probe.is_some());
            p.ack(start.wrapping_add(6000), 11, 1000, 1000);
            assert!(p.take_probe_outcome(start.wrapping_add(5999)).is_none());
            let outcome = p.take_probe_outcome(start.wrapping_add(6000)).unwrap();
            assert_eq!(outcome.start, start);
            assert_eq!(outcome.isolated, disqualifier == 0);
            assert!(p.take_probe_outcome(start.wrapping_add(6000)).is_none());
            assert!(p.probe.is_none());
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-4
//= type=test
//= reason=Reviewed 76800de plus a4b9a0c: isolated suppression waits for finite cumulative proof and recovery exit; pmtu_cooldown uses the unsuppressed logical window, not transient PRR admission, with one RTT per packet plus a strict extra interval/tick and an RTO floor. Real receiver matrix checks no target before the deadline and a target at it; dedicated arithmetic test distinguishes logical14600 from admission1000. Mandatory failure cooldown is independent of configurable periodic aging.
//# Suppressed congestion control MUST be rate limited such that it occurs less
//# frequently than the worst-case loss rate for TCP congestion control at a
//# comparable data rate over the same path (i.e., less than the "TCP-friendly" loss
//# rate [tcp-friendly]). This SHOULD be enforced by requiring a minimum headway
//# between a suppressed congestion adjustment (due to a failed probe) and the next
//# attempted probe, which is equal to one round-trip time for each packet permitted
//# by the congestion window. This is discussed further in Section 7.6.2.

//= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.2
//= type=test
//= reason=Partial no-PTB evidence from 76800de plus a4b9a0c: isolated suppression waits for finite cumulative proof and recovery exit; pmtu_cooldown uses the unsuppressed logical window, not transient PRR admission, with one RTT per packet plus a strict extra interval/tick and an RTO floor. Real receiver matrix checks no target before the deadline and a target at it; dedicated arithmetic test distinguishes logical14600 from admission1000. Mandatory failure cooldown is independent of configurable periodic aging. Partial gap: RFC4821 sections 2, 4 and 7.6.2 cover isolated loss with or without matching PTB. apply_ptb cancels probe classification; resolve_probe_response commits normal congestion response even when only the probe is lost and trailing packets are delivered, as asserted by the IPv6 two-PTB fixture. No-PTB evidence does not close this full span.
//# A probe failure event is the one situation under which the Packetization Layer
//# SHOULD ignore loss as a congestion signal. Because there is some small risk that
//# suppressing congestion control might have unanticipated consequences (even for
//# one isolated loss), it is REQUIRED that probe failure events be less frequent
//# than the normal period for losses under standard congestion control.
//# Specifically, after a probe failure event and suppressed congestion control,
//# PLPMTUD MUST NOT probe again until an interval that is larger than the expected
//# interval between congestion control events. See Section 4 for details. The
//# simplest estimate of the interval to the next congestion event is the same
//# number of round trips as the current congestion window in packets.

fn isolated_probe_cc_headway_uses_logical_not_prr_admission_window() {
    let (mut a, _) = pair(isolated_config(1, true, false, false), 0);
    a.rtt = crate::recovery::RttEstimator::new(1);
    a.rtt.sample(1000);
    assert!(
        a.congestion
            .on_sack_recovery_with_probe(Seq(2), 12_000, Seq(12_002), Some(Seq(2)))
    );
    a.congestion.prr_window(1000);
    assert_eq!(a.congestion.unsuppressed_cwnd(), 14_600);
    assert_eq!(a.pmtu_cooldown(), 11_001);
    assert!(a.pmtu_cooldown() > 10 * a.rtt.srtt().unwrap());
}

#[test]
fn isolated_probe_cc_rack_lost_retry_commits_without_resetting_prr() {
    for prr in [false, true] {
        for cubic in [false, true] {
            let (mut a, mut b) = pair(isolated_config(2, prr, cubic, false), u32::MAX - 4000);
            a.write(b"x").unwrap();
            deliver(&mut a, &mut b, 32);
            deliver(&mut b, &mut a, 33);
            a.write(&[7; 20_000]).unwrap();
            packet(&mut a, 40);
            let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
            let mut trailing = Vec::new();
            for _ in 0..8 {
                trailing.push(packet(&mut a, 41));
            }
            for bytes in &trailing {
                real_ack(&mut a, &mut b, bytes, 140, false);
            }
            assert_eq!(a.congestion.pending_probe_response(), Some(probe.start));
            let first = packet(&mut a, 200); // Lost repair, not another original loss.
            let second = packet(&mut a, 201);
            let first = wire::parse(ip(a.tuple), &first).unwrap();
            let second_segment = wire::parse(ip(a.tuple), &second).unwrap();
            assert_eq!(first.header.sequence, probe.start.0);
            assert_eq!(
                second_segment.header.sequence,
                probe.start.wrapping_add(first.payload.len() as u32).0
            );
            assert_eq!(
                second_segment
                    .header
                    .sequence
                    .wrapping_add(second_segment.payload.len() as u32),
                probe.end.0
            );
            let target = a.congestion.recovery_target();
            let counters = a.prr.map(|p| p.counters());
            real_ack(&mut a, &mut b, &second, 401, false);
            if a.congestion.pending_probe_response().is_some() {
                a.timeout(a.rack.deadline.unwrap()).unwrap();
            }
            assert!(a.congestion.pending_probe_response().is_none());
            assert!(a.pmtud.as_ref().unwrap().eligible_probe_loss().is_none());
            assert_eq!(a.snd_una, probe.start);
            assert!(a.rack.lowest_lost(a.mss as u32).is_some());
            if prr {
                let after = a.prr.unwrap().counters();
                let before = counters.unwrap();
                assert_eq!(after.0, before.0);
                assert_eq!(after.1, before.1 + second_segment.payload.len() as u64);
                assert_eq!(after.2, before.2);
                assert_eq!(a.congestion.ssthresh(), target);
            } else {
                assert!(a.congestion.ssthresh() < target);
            }
            let committed = a.congestion.ssthresh();
            a.congestion.suppress_probe_response(probe.start);
            assert_eq!(a.congestion.ssthresh(), committed);
        }
    }
}

#[test]
fn isolated_probe_cc_cancellation_without_mss_change_commits_once() {
    for cancellation in 0..3 {
        let (mut a, _) = pair(isolated_config(1, true, true, false), 0);
        a.pmtud.as_mut().unwrap().info.current_mtu = 1024;
        a.refresh_path_mss();
        let start = a.snd_nxt;
        let end = start.wrapping_add(1222);
        a.pmtud
            .as_mut()
            .unwrap()
            .start_probe(start, 1222, 3000, 1262);
        a.pmtud.as_mut().unwrap().sent(start, end, 1262, 20, false);
        assert!(a.congestion.on_sack_recovery_with_probe(
            start,
            8000,
            end.wrapping_add(3000),
            Some(start)
        ));
        let target = a.congestion.recovery_target();
        let old_mss = a.mss;
        match cancellation {
            0 => a.lower_mss(1100).unwrap(), // Bound cancels probe, effective MSS stays984.
            1 => {
                a.last_pmtu_output = Some((start, end));
                a.reject_reserved_output();
            }
            _ => a.terminal(CloseReason::Aborted),
        }
        assert_eq!(a.mss, old_mss);
        assert!(a.pmtud.as_ref().unwrap().probe.is_none());
        assert!(a.congestion.pending_probe_response().is_none());
        assert_eq!(a.congestion.ssthresh(), target);
        a.congestion.suppress_probe_response(start);
        a.resolve_probe_response();
        assert_eq!(a.congestion.ssthresh(), target);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-4
//= type=test
//= reason=Partial no-PTB evidence from 76800de plus a4b9a0c: provisional normal repair admission and PRR remain active; only finite preloss extended-tail cumulative proof followed by recovery/PRR exit suppresses the logical loss response. Real receiver NewReno/SACK/RACK, PRR, Reno/CUBIC and pacing matrices assert isolated suppression and normal response on other loss; disqualifiers cover ECE, RTO and ordinary loss. Replenishment retains nonempty flight and resumes ACK growth. Independent MSS decrease scaling remains, not literal unchanged-cwnd advice. Partial gap: RFC4821 sections 2, 4 and 7.6.2 cover isolated loss with or without matching PTB. apply_ptb cancels probe classification; resolve_probe_response commits normal congestion response even when only the probe is lost and trailing packets are delivered, as asserted by the IPv6 two-PTB fixture. No-PTB evidence does not close this full span.
//# Normal congestion control algorithms MUST remain in effect under all conditions
//# except when only an isolated probe packet is detected as lost. In this case
//# alone, the normal congestion (window or data rate) reduction SHOULD be
//# suppressed. If any other data loss is detected, standard congestion control MUST
//# take place.

fn isolated_probe_cc_replenishment_does_not_extend_recovery_proof() {
    for mode in 0..3 {
        for prr in [false, true] {
            for cubic in [false, true] {
                let (mut a, mut b) =
                    pair(isolated_config(mode, prr, cubic, false), u32::MAX - 4000);
                a.write(b"x").unwrap();
                deliver(&mut a, &mut b, 32);
                deliver(&mut b, &mut a, 33);
                a.write(&[7; 60_000]).unwrap();
                packet(&mut a, 40); // Drop only the explicit probe.
                let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
                let (window, threshold, old_mss) =
                    (a.congestion.cwnd(), a.congestion.ssthresh(), a.mss);
                let trailing: Vec<_> = (0..8).map(|_| packet(&mut a, 41)).collect();
                let proof_end = a.snd_nxt;
                assert!(after(proof_end, probe.trailing_end));
                let mut now = 140;
                for bytes in &trailing {
                    real_ack(&mut a, &mut b, bytes, now, false);
                }
                if !a.congestion.in_recovery() {
                    now = a.rack.deadline.unwrap();
                    a.timeout(now).unwrap();
                }
                assert_eq!(a.congestion.pending_probe_response(), Some(probe.start));
                // ACK split repairs, but hold the one that will end recovery.
                let ending_repair = loop {
                    now += 1;
                    let bytes = packet(&mut a, now);
                    let segment = wire::parse(ip(a.tuple), &bytes).unwrap();
                    let end = Seq(segment.header.sequence)
                        .wrapping_add(segment.payload.len() as u32);
                    if end == probe.end {
                        break bytes;
                    }
                    assert!(after(probe.end, end));
                    real_ack(&mut a, &mut b, &bytes, now, false);
                };
                assert!(a.congestion.in_recovery());
                now += 1;
                let outstanding = packet(&mut a, now);
                assert_eq!(
                    wire::parse(ip(a.tuple), &outstanding).unwrap().header.sequence,
                    proof_end.0
                ); // Fresh output before the recovery-ending ACK.
                real_ack(&mut a, &mut b, &ending_repair, now, false);
                assert_eq!(a.snd_una, proof_end);
                assert!(!a.congestion.in_recovery());
                assert!(a.prr.is_none());
                assert!(a.flight() > 0);
                let mut drain = [0; 65_536];
                b.read(&mut drain).unwrap();
                let mut outstanding = alloc::collections::VecDeque::from([outstanding]);
                // Refill the admitted window before each ACK, including for CUBIC's
                // cwnd-limited growth test. Neither fixed nor broken code drains flight.
                for _ in 0..8 {
                    now += 1;
                    loop {
                        let mut fresh = vec![0; 2000];
                        let Some(len) = a.transmit(now, &mut fresh).unwrap() else {
                            break;
                        };
                        fresh.truncate(len);
                        outstanding.push_back(fresh);
                    }
                    let bytes = outstanding.pop_front().unwrap();
                    real_ack(&mut a, &mut b, &bytes, now, false);
                    assert!(a.flight() > 0);
                    assert!(!outstanding.is_empty());
                    b.read(&mut drain).unwrap();
                    a.write(&[7; 1460]).unwrap();
                }
                assert!(
                    a.congestion.pending_probe_response().is_none(),
                    "mode={mode}, prr={prr}, cubic={cubic}: replenishment pinned proof"
                );
                let p = a.pmtud.as_mut().unwrap();
                assert!(p.probe.is_none());
                assert!(p.take_probe_outcome(a.snd_una).is_none()); // Already consumed once.
                assert!(p.deadline.is_some());
                assert_eq!(a.congestion.ssthresh(), threshold);
                let scaled_window =
                    (u64::from(window) * a.mss as u64 / old_mss as u64) as u32;
                assert!(
                    a.congestion.cwnd() > scaled_window,
                    "mode={mode}, prr={prr}, cubic={cubic}: cwnd={} scaled={scaled_window}",
                    a.congestion.cwnd()
                ); // Ordinary ACK growth resumed.
            }
        }
    }
}

#[test]
fn isolated_probe_cc_loss_freezes_original_minimum_tail() {
    for cause in 0..3 {
        let mut p =
            crate::pmtud::Pmtud::new(crate::PmtudConfig::new(1500), 1500, true, 600_000_000);
        let start = Seq(u32::MAX - 500);
        let end = start.wrapping_add(1200);
        let tail = end.wrapping_add(3000);
        p.start_probe(start, 1200, 3000, 1240);
        p.sent(start, end, 1240, 20, false);
        match cause {
            0 => p.loss(start, false),
            1 => p.timeout(1, start, 1, 1000),
            _ => p.sent(start, end, 1240, 20, true),
        }
        p.sent(end, tail.wrapping_add(1200), 4240, 20, false);
        assert_eq!(p.probe.unwrap().trailing_end, tail);
        if cause != 2 {
            p.sent(start, end, 1240, 20, true);
        }
        p.ack(end, 2, 1000, 1000);
        assert!(p.probe.is_some()); // Freezing cannot discard the unsent minimum.
        assert!(p.take_probe_outcome(end).is_none());
        p.ack(tail, 3, 1000, 1000);
        assert_eq!(p.take_probe_outcome(tail).unwrap().isolated, cause != 1);
        assert!(p.take_probe_outcome(tail).is_none());
    }
}
