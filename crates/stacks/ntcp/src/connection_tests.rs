use super::*;
use alloc::{vec, vec::Vec};

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-8
//= type=test
//# The RACK reordering timer, the TLP PTO timer, the RTO, and Zero
//# Window Probe (ZWP) timer [RFC793] are mutually exclusive and are used
//# in different scenarios.
//= https://www.rfc-editor.org/rfc/rfc8985#section-8
//= type=test
//# When arming a RACK reordering timer or TLP
//# PTO timer, the sender SHOULD cancel any other pending timers.
fn selected_loss_timer_transition_matrix_and_independent_ack() {
    let (mut a, _) = tlp_baseline_pair(0);
    assert_eq!(a.loss_timer, None);
    a.write(&[1; 4000]).unwrap();
    for _ in 0..4 {
        packet(&mut a, 100_000);
    }
    assert_eq!(a.loss_timer, Some((LossTimer::Pto, 300_000)));
    assert_eq!(a.rto_deadline, Some(400_000)); // unarmed reference
    a.ack_deadline = Some(150_000);
    assert_eq!(a.next_deadline(), Some(150_000));
    a.timeout(150_000).unwrap();
    assert!(a.ack_pending);
    assert_eq!(a.loss_timer, Some((LossTimer::Pto, 300_000)));
    packet(&mut a, 150_000);
    rack_sack(&mut a, 200_000, 0, &[(3000, 4000)]);
    assert_eq!(a.loss_timer, Some((LossTimer::Rack, 225_000)));
    assert_eq!(a.tlp_deadline, None);
    a.timeout(225_000).unwrap();
    assert_eq!(a.loss_timer, Some((LossTimer::Rto, 400_000)));
    assert_eq!(
        a.transmit(225_000, &mut [0; 19]),
        Err(Error::OutputTooSmall)
    );
    assert_eq!(a.loss_timer, Some((LossTimer::Rto, 400_000)));
    packet(&mut a, 225_000);
    let rto = a.rto();
    let rto_expiry = 225_000 + rto;
    let seq = a.receive.next();
    let una = a.snd_una;
    inject(&mut a, 226_000, seq, una, ACK, 0, &[]);
    assert_eq!(a.loss_timer, Some((LossTimer::Rto, rto_expiry)));
    assert_eq!(a.persist_deadline, None);
    let cwnd = a.congestion.cwnd();
    a.timeout(rto_expiry).unwrap();
    assert!(a.probe_pending);
    assert_eq!(a.loss_timer, None);
    packet(&mut a, rto_expiry);
    assert_eq!(a.congestion.cwnd(), cwnd); // flow control is not congestion
    assert_eq!(a.loss_timer, Some((LossTimer::Rto, rto_expiry + 2 * rto)));
    let high = a.snd_nxt;
    inject(&mut a, rto_expiry + 1, seq, high, ACK, 0, &[]);
    assert_eq!(a.loss_timer, None);
    a.write(b"x").unwrap();
    assert_eq!(a.loss_timer.unwrap().0, LossTimer::Zwp);
    let expiry = a.loss_timer.unwrap().1;
    a.timeout(expiry).unwrap();
    assert_eq!(a.transmit(expiry, &mut [0; 19]), Err(Error::OutputTooSmall));
    assert_eq!(a.loss_timer, None);
    packet(&mut a, expiry);
    assert_eq!(a.loss_timer.unwrap().0, LossTimer::Zwp); // control created no flight
    let high = a.snd_nxt;
    inject(&mut a, expiry + 1, seq, high, ACK, 64, &[]);
    assert_eq!(a.loss_timer, None);
    a.shutdown().unwrap();
    packet(&mut a, expiry + 2);
    assert_eq!(a.state, State::FinWait1);
    assert_eq!(
        a.loss_timer,
        a.tlp_deadline.map(|deadline| (LossTimer::Pto, deadline))
    );
    assert!(a.tlp_deadline.is_some());
    a.time_wait();
    assert_eq!(a.loss_timer, None);
    assert_eq!(a.next_deadline(), a.time_wait_deadline);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.2
//= type=test
//# Second, when there is no SRTT estimate available, the PTO SHOULD be 1
//# second.
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
//= type=test
//# If either one of these two conditions is not met, then the sender
//# MUST skip sending a loss probe and MUST proceed to re-arm the RTO
//# timer, as specified at the end of this section.
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
//= type=test
//# After attempting to send a loss probe, regardless of whether a loss
//# probe was sent, the sender MUST re-arm the RTO timer, not the PTO
//# timer, if the FlightSize is not zero.
fn pto_arming_is_independent_of_expiry_gates_and_restores_rto() {
    for gate in 0..4 {
        let (mut a, _) = tlp_baseline_pair(0);
        if gate == 0 {
            a.rtt = RttEstimator::new(1_000_000);
            a.tlp_fresh_rtt = false;
        }
        a.write(&[1; 1000]).unwrap();
        packet(&mut a, 100_000);
        if gate == 1 {
            a.tlp_fresh_rtt = false;
        }
        if gate == 2 {
            a.tlp_end = Some((a.snd_una, a.snd_nxt, true));
        }
        let expiry = a.tlp_deadline.unwrap();
        assert_eq!(expiry, if gate == 0 { 1_100_000 } else { 300_000 });
        if gate == 3 {
            // Already-armed PTO observes a zero window at expiry; RTO is
            // mandatory even though its eventual output is a window probe.
            a.snd_wnd = 0;
        }
        let now = expiry + 1_000_000; // elapsed unarmed RTO must not also fire
        let rto = a.rto();
        a.timeout(now).unwrap();
        assert!(!a.tlp_pending);
        assert!(!a.retx_pending);
        assert_eq!(a.rto(), rto);
        assert_eq!(a.loss_timer, Some((LossTimer::Rto, now + rto)));
        assert_eq!(a.transmit(now, &mut [0; 2000]), Ok(None));
    }
    // Scheduling also occurs with an old probe still tracked, and uses
    // the reference cap without arming that reference as a second timer.
    let (mut a, _) = tlp_baseline_pair(0);
    a.tlp_end = Some((a.snd_una, a.snd_una.wrapping_add(1), true));
    a.write(&[1; 1000]).unwrap();
    packet(&mut a, 100_000);
    a.rto_deadline = Some(150_000);
    a.schedule_tlp();
    assert_eq!(a.loss_timer, Some((LossTimer::Pto, 150_000)));
    a.timeout(150_000).unwrap();
    assert!(!a.tlp_pending);
    assert_eq!(a.loss_timer, Some((LossTimer::Rto, 450_000)));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-9.4
//= type=test
//# To mitigate this
//# complication, before sending a TLP loss probe retransmission, the
//# sender should attempt to wait long enough that the receiver has sent
//# any delayed ACKs that it is withholding.
fn pto_peer_ack_budget_covers_delayed_and_stretched_short_packets() {
    for stretched in [false, true] {
        let (mut a, _) = tlp_baseline_pair(0);
        a.config.peer_max_ack_delay_us = 499_999;
        a.config.rto_min_us = 1_000_000;
        a.rtt = RttEstimator::new(1_000_000);
        a.rtt.sample(100_000);
        a.set_nagle(false);
        a.write(&[1; 300]).unwrap();
        packet(&mut a, 100_000);
        if stretched {
            a.write(&[2; 300]).unwrap();
            packet(&mut a, 100_001);
        }
        let deadline = a.loss_timer.unwrap().1;
        assert!(deadline >= 600_000);
        a.timeout(599_999).unwrap();
        assert!(!a.tlp_pending);
        let next = a.receive.next();
        let ack = a.snd_nxt;
        inject(&mut a, 600_000, next, ack, ACK, 16_000, &[]);
        assert_eq!(a.loss_timer, None);
        assert_eq!(a.tlp_end, None);
    }
}

#[test]
fn full_mss_flight_partial_sack_preserves_two_srtt_pto_and_rto_fallback() {
    for iss in [0, u32::MAX - 1999] {
        for acknowledged in [0, 1] {
            let (mut a, _) = tlp_baseline_pair(iss);
            a.config.peer_max_ack_delay_us = 499_999;
            let base = a.snd_una;
            a.write(&[0x55; 4000]).unwrap();
            for _ in 0..4 {
                packet(&mut a, 100_000);
            }
            assert_eq!(a.loss_timer, Some((LossTimer::Pto, 300_000)));
            let next = a.receive.next();
            inject_sack(
                &mut a,
                200_000,
                next,
                base.wrapping_add(acknowledged),
                ACK,
                65_535,
                b"",
                &[(base.wrapping_add(3999).0, base.wrapping_add(4000).0)],
            );
            // Only the last byte is SACKed, not a complete transmission:
            // no RACK timer, recovery, or new RTT sample. Interval splits
            // do not turn the original full-sized packets into short ones.
            assert_eq!(a.rack.counts().sacked, 0);
            assert_eq!(a.rack.ack_sample, None);
            assert_eq!(a.rack.deadline, None);
            assert!(a.sack_recovery.is_none());
            assert!(!a.rack.has_short_transmission(a.mss as u32));
            let pto = if acknowledged == 0 { 300_000 } else { 400_000 };
            assert_eq!(a.loss_timer, Some((LossTimer::Pto, pto)));
            let rto = a.rto();
            a.timeout(pto - 1).unwrap();
            assert!(!a.tlp_pending);
            a.timeout(pto).unwrap();
            assert!(a.tlp_pending);
            assert!(!a.retx_pending);
            assert_eq!(a.loss_timer, Some((LossTimer::Rto, pto + rto)));
            assert_eq!(a.transmit(pto, &mut [0; 22]), Err(Error::OutputTooSmall));
            assert!(a.tlp_pending);
            let bytes = packet(&mut a, pto);
            let seg = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(seg.header.sequence, base.wrapping_add(3000).0);
            assert_eq!(seg.payload, &[0x55; 1000]);
            assert_eq!(
                a.rack.head_transmission(base.wrapping_add(3000)),
                Some((base.wrapping_add(4000), pto))
            );
            assert_eq!(a.loss_timer, Some((LossTimer::Rto, pto + rto)));
            a.timeout(pto + rto).unwrap();
            let bytes = packet(&mut a, pto + rto);
            let seg = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(seg.header.sequence, base.wrapping_add(acknowledged).0);
            assert_eq!(seg.payload, &[0x55; 1000][acknowledged as usize..]);
            assert!(a.rack.valid());
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6298#section-5
//= type=test
//# An implementation MUST manage the retransmission timer(s) in such a way that a segment
//# is never retransmitted too early, i.e., less than one RTO after the previous
//# transmission of that segment.
//= https://www.rfc-editor.org/rfc/rfc6298#section-5
//= type=test
//= reason=First-send arming, advancing-ACK restart, running new-data nonrestart, earliest wire-span retry, output rollback and last-emission age are asserted; window probing/selected timer transitions are separately covered.
//# The following is the RECOMMENDED algorithm for managing the
//# retransmission timer:
//= https://www.rfc-editor.org/rfc/rfc6298#section-1
//= type=test
//= reason=Default/configured >=1s timer evidence plus explicitly selected subsecond compatibility departure; asserts no early retry, per-copy boundaries, ACK restart and failed-output preservation. Sampling cadence and estimator bounds are separately tested; not universal MUST conformance for subsecond floors.
//# However, a TCP MUST NOT be more aggressive than the following algorithms allow.
//= https://www.rfc-editor.org/rfc/rfc6928#section-2
//= type=test
//= reason=Inherited timer evidence; IW10 ACK restart/fallback and causal-round sampling are separately tested. Approved subsecond compatibility is separately excepted, not universal inherited RFC6298 conformance.
//# Implementations must also follow RFC 6298 [RFC6298] in order to avoid spurious RTO as described in Section 9.
fn rto_variable_packets_partial_ack_fresh_tail_and_failed_output() {
    for iss in [100, u32::MAX - 3] {
        for floor in [100_000, 1_000_000] {
            for mode in 0..3 {
                let mut cfg = config(64, 8);
                cfg.rto_min_us = floor;
                cfg.sack = mode != 0;
                cfg.rack = mode == 2;
                let (mut a, _) = pair(cfg, iss);
                a.set_nagle(false);
                a.write(b"abcde").unwrap();
                packet(&mut a, 40);
                let seq = a.receive.next();
                let partial = a.snd_una.wrapping_add(2);
                inject(&mut a, 50, seq, partial, ACK, 64, &[]);
                let expiry = a.rto_deadline.unwrap();
                a.write(b"fgh").unwrap();
                packet(&mut a, expiry - 1);
                assert_eq!(a.loss_timer, Some((LossTimer::Rto, expiry)));
                a.timeout(expiry - 1).unwrap();
                assert!(!a.retx_pending);
                let old_rto = a.rto();
                a.timeout(expiry).unwrap();
                let before = (
                    a.loss_timer,
                    a.now,
                    a.rack.head_transmission(partial),
                    a.sample,
                );
                assert_eq!(
                    a.transmit(expiry + 1, &mut [0; 22]),
                    Err(Error::OutputTooSmall)
                );
                assert_eq!(
                    (
                        a.loss_timer,
                        a.now,
                        a.rack.head_transmission(partial),
                        a.sample
                    ),
                    before
                );
                let bytes = packet(&mut a, expiry + 1);
                let seg = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(seg.payload, b"cde");
                assert_eq!(seg.header.sequence, partial.0);
                assert!(expiry + 1 - 40 >= old_rto);
                let tail = partial.wrapping_add(3);
                assert_eq!(a.rack.head_transmission(tail).unwrap().1, expiry - 1);
                inject(&mut a, expiry + 2, seq, tail, ACK, 64, &[]);
                let expiry2 = a.loss_timer.unwrap().1;
                let interval = a.rto();
                a.timeout(expiry2 - 1).unwrap();
                assert!(!a.retx_pending);
                a.timeout(expiry2).unwrap();
                let bytes = packet(&mut a, expiry2);
                assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, b"fgh");
                assert!(expiry2 - (expiry - 1) >= interval);
            }
        }
    }
}

#[test]
fn sack_fallback_partial_ack_refill_preserves_fresh_tail_timer_ledger() {
    for iss in [100, u32::MAX - 255] {
        for exercise_overflow in [false, true] {
            let cfg = ConnectionConfig {
                sack: true,
                rack: true,
                prr: true,
                initial_window: InitialWindow::Iw10,
                ..config(512, 128)
            };
            let (mut a, _) = pair(cfg, iss);
            a.set_nagle(false);
            let base = a.snd_una;
            a.write(b"abcd").unwrap();
            packet(&mut a, 100);
            for _ in 4..a.config.send_capacity {
                a.write(b"x").unwrap();
                packet(&mut a, 100);
            }
            let end = a.data_high();
            let congestion = a.congestion.clone();
            if exercise_overflow {
                // Discover exhaustion, rather than assuming a fixed number
                // of ranges. Capacity-backed scoreboards need not overflow.
                for offset in (5..a.config.send_capacity as u32).step_by(2) {
                    sack_ack(
                        &mut a,
                        200,
                        base,
                        &[(base.wrapping_add(offset).0, base.wrapping_add(offset + 1).0)],
                    );
                    if a.sack_fallback.is_some() {
                        break;
                    }
                }
            }
            if a.sack_fallback.is_none() {
                // Keep the explicit fallback path covered independently of
                // whether the scoreboard can exhaust its advice storage.
                a.scoreboard.clear();
                a.sack_fallback = Some(end);
                a.sack_guard = Some(end);
                a.sack_recovery = None;
                a.sack_post_rto = None;
                a.prr = None;
                a.rack.deadline = None;
                a.congestion.cancel_sack_recovery();
            }
            // Isolate storage refill from reductions caused by the advice
            // used to reach overflow; keep real packet admission checks.
            a.congestion = congestion;
            assert!(a.rack.valid());
            let partial = base.wrapping_add(2);
            sack_ack(&mut a, 300, partial, &[(partial.0, end.0)]);
            assert_eq!(
                a.rack.head_transmission(partial),
                Some((base.wrapping_add(4), 100))
            );
            assert_eq!(
                crate::rack::tests::original_packet(&a.rack, partial),
                Some((base, base.wrapping_add(4), 100, false))
            );
            let head = base.wrapping_add(257);
            sack_ack(&mut a, 301, head, &[(head.0, end.0)]);
            assert_eq!(a.send.len(), 255);
            assert!(a.scoreboard.ranges().is_empty());
            assert_eq!(a.sack_fallback, Some(end));
            assert!(a.prr.is_none());
            assert!(a.sack_recovery.is_none());
            assert!(!a.rack_enabled());
            let expiry = a.rto_deadline.unwrap();
            for i in 0..257 {
                let sent = expiry - 257 + i;
                a.write(b"y").unwrap();
                let bytes = packet(&mut a, sent);
                let seg = wire::parse(ip(tuple()), &bytes).unwrap();
                let start = end.wrapping_add(i as u32);
                assert_eq!(seg.header.sequence, start.0);
                assert_eq!(seg.payload, b"y");
                assert!(a.rack.valid());
                assert_eq!(
                    a.rack.head_transmission(start),
                    Some((start.wrapping_add(1), sent))
                );
            }
            assert_eq!(a.send.len(), a.config.send_capacity);
            assert_eq!(a.rto_deadline, Some(expiry));
            let tail = a.data_high().wrapping_add(u32::MAX);
            a.timeout(expiry).unwrap();
            let bytes = packet(&mut a, expiry);
            let seg = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(seg.header.sequence, head.0);
            assert_eq!(seg.payload, b"x");
            assert_eq!(
                a.rack.head_transmission(head),
                Some((head.wrapping_add(1), expiry))
            );
            assert_eq!(
                a.rack.head_transmission(tail),
                Some((tail.wrapping_add(1), expiry - 1))
            );
            assert!(a.rack.valid());
            assert!(a.prr.is_none());
            sack_ack(&mut a, expiry + 1, end, &[]);
            assert!(a.sack_fallback.is_none());
            assert!(a.rack_enabled());
            assert!(a.prr.is_none());
            assert_eq!(
                a.rack.head_transmission(end),
                Some((end.wrapping_add(1), expiry - 257))
            );
            let next_expiry = a.rto_deadline.unwrap();
            let interval = a.rto();
            a.timeout(next_expiry - 1).unwrap();
            assert!(!a.retx_pending);
            a.timeout(next_expiry).unwrap();
            let bytes = packet(&mut a, next_expiry);
            let seg = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(seg.header.sequence, end.0);
            assert_eq!(seg.payload, b"y");
            assert!(next_expiry - (expiry - 257) >= interval);
            assert_eq!(
                a.rack.head_transmission(tail),
                Some((tail.wrapping_add(1), expiry - 1))
            );
            assert!(a.rack.valid());
        }
    }
}

#[test]
fn pto_new_data_fin_and_closing_ack_keep_loss_timer() {
    for close_wait in [false, true] {
        let (mut a, _) = tlp_baseline_pair(0);
        if close_wait {
            a.state = State::CloseWait;
        }
        a.write(b"closing").unwrap();
        a.shutdown().unwrap();
        packet(&mut a, 100_000);
        assert_eq!(
            a.state,
            if close_wait {
                State::LastAck
            } else {
                State::FinWait1
            }
        );
        assert_eq!(a.loss_timer.unwrap().0, LossTimer::Pto);
        if !close_wait {
            a.state = State::Closing;
        }
        let next = a.receive.next();
        let ack = a.snd_una.wrapping_add(1);
        inject(&mut a, 110_000, next, ack, ACK, 16_000, &[]);
        assert_eq!(a.loss_timer.unwrap().0, LossTimer::Pto);
        let expiry = a.loss_timer.unwrap().1;
        a.timeout(expiry).unwrap();
        let bytes = packet(&mut a, expiry);
        assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, b"losing");
        assert_eq!(a.loss_timer.unwrap().0, LossTimer::Rto);
    }
}

#[test]
fn rto_reference_cannot_retransmit_fresh_data_or_fin_or_starve_ack_timer() {
    for fin in [false, true] {
        let (mut a, _) = pair(config(64, 8), 100);
        if fin {
            a.shutdown().unwrap();
        } else {
            a.write(b"abc").unwrap();
        }
        packet(&mut a, 40);
        let rto = a.rto();
        // A stale reference (for example after RTT growth on SACK feedback)
        // cannot bypass the latest successful emission's elapsed-age gate.
        a.rto_deadline = Some(50);
        a.ack_deadline = Some(50);
        a.select_loss_timer();
        a.timeout(50).unwrap();
        assert!(a.ack_pending);
        assert!(!a.retx_pending);
        assert_eq!(a.rto(), rto);
        assert_eq!(a.loss_timer, Some((LossTimer::Rto, 40 + rto)));
        packet(&mut a, 50); // independent ACK, not an early retransmission
        a.timeout(40 + rto - 1).unwrap();
        assert!(!a.retx_pending);
        a.timeout(40 + rto).unwrap();
        assert!(a.retx_pending);
        let bytes = packet(&mut a, 40 + rto);
        let seg = wire::parse(ip(tuple()), &bytes).unwrap();
        if fin {
            assert_ne!(seg.header.flags & FIN, 0);
        } else {
            assert_eq!(seg.payload, b"abc");
        }
    }
}

#[test]
fn tiny_rtt_keeps_rack_and_tlp_active() {
    for minimum in 0..=5 {
        let cfg = ConnectionConfig {
            sack: true,
            rack: true,
            tlp: true,
            peer_max_ack_delay_us: 0,
            initial_window: InitialWindow::Iw10,
            ..config(16_000, 1000)
        };
        let (mut a, _) = pair(cfg, 0);
        a.write(&[1; 8000]).unwrap();
        for _ in 0..8 {
            packet(&mut a, 100_000);
        }
        rack_sack(&mut a, 100_000 + minimum, 1000, &[]);
        assert!(a.rack_enabled());
        assert!(a.rack.valid());
        assert_eq!(a.loss_timer.unwrap().0, LossTimer::Pto);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.4
//= type=test
//= reason=Successful original validity, failure rollback, persist/challenge exclusion, partial ACK coverage and original packet caps are asserted at the wire boundary, including wrap and retransmit_beyond_window both false and true.
//# 4)  On first retransmission, or if the sequence number is out of
//# window by less than 2^Rcv.Wind.Shift, then do normal
//# retransmission(s) without regard to the receiver window as long
//# as the original segment was in window when it was sent.
fn scaled_retry_wire_commit_partial_ack_and_persist_are_independent() {
    for (iss, beyond_window) in [100, u32::MAX - 4]
        .into_iter()
        .flat_map(|iss| [false, true].map(|enabled| (iss, enabled)))
    {
        let (mut a, _) = pair(config(65_536, 8), iss);
        a.config.retransmit_beyond_window = beyond_window;
        assert!(a.scaling && a.peer_scale == 1);
        a.write(b"abcdefghijklmnop").unwrap();
        packet(&mut a, 40);
        packet(&mut a, 41);
        let una = a.snd_una;
        let next = a.receive.next();
        let original = a.rack.original_retry_span(una, a.snd_nxt).unwrap();
        assert!(original.originally_in_window);
        assert_eq!(original.original_end, una.wrapping_add(8));
        assert_eq!(original.successful_retries, 0);
        inject(&mut a, 50, next, una, ACK, 0, b"");
        let persist = a.loss_timer.unwrap().1;
        a.timeout(persist).unwrap();
        let bytes = packet(&mut a, persist);
        assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, b"a");
        assert_eq!(
            a.rack.original_retry_span(una, a.snd_nxt).unwrap(),
            original
        );
        inject(&mut a, persist + 1, next, una, ACK, 1, b"");
        a.retx_pending = true;
        a.config.send_ip_payload_limit = 24; // actually emit only the prefix
        assert_eq!(
            a.transmit(persist + 2, &mut [0; 23]),
            Err(Error::OutputTooSmall)
        );
        assert_eq!(
            a.rack.original_retry_span(una, a.snd_nxt).unwrap(),
            original
        );
        a.challenge_ack_pending = true;
        let bytes = packet(&mut a, persist + 2);
        assert!(wire::parse(ip(tuple()), &bytes).unwrap().payload.is_empty());
        assert_eq!(
            a.rack.original_retry_span(una, a.snd_nxt).unwrap(),
            original
        );
        let bytes = packet(&mut a, persist + 3);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.header.sequence, una.0);
        assert_eq!(segment.payload, b"abcd"); // exceeds the two-byte current window
        let prefix = a.rack.original_retry_span(una, a.snd_nxt).unwrap();
        assert_eq!(prefix.successful_retries, 1);
        assert_eq!(prefix.retry_end, una.wrapping_add(4));
        let suffix = a
            .rack
            .original_retry_span(una.wrapping_add(4), a.snd_nxt)
            .unwrap();
        assert_eq!(suffix.successful_retries, 0);
        assert_eq!(suffix.original_start, una);
        assert_eq!(suffix.original_end, una.wrapping_add(8));
        a.config.send_ip_payload_limit = 65_535;
        inject(&mut a, persist + 4, next, una.wrapping_add(2), ACK, 1, b"");
        a.retx_pending = true;
        let bytes = packet(&mut a, persist + 5);
        assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, b"cd");
        assert_eq!(
            a.rack
                .original_retry_span(a.snd_una, a.snd_nxt)
                .unwrap()
                .successful_retries,
            2
        );
        inject(&mut a, persist + 6, next, una.wrapping_add(4), ACK, 1, b"");
        a.retx_pending = true;
        let bytes = packet(&mut a, persist + 7);
        assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, b"efgh");
        assert_eq!(
            a.rack
                .original_retry_span(a.snd_una, a.snd_nxt)
                .unwrap()
                .successful_retries,
            1
        );
        // Neither retry ever crossed into the second original packet.
        assert_eq!(
            a.rack
                .original_retry_span(una.wrapping_add(8), a.snd_nxt)
                .unwrap()
                .successful_retries,
            0
        );
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.4
//= type=test
//= reason=With retransmit_beyond_window both false and true, first/original-valid retries and strict sub-scale SEG.SEQ distance are asserted through wrap at scales0/1/14. Subsequent far retries, originally invalid spans and missing ledger are clipped to the latest window. Only unscaled opt-in can bypass it; zero window still requires separate persist.
//# 5)  Subsequent retransmissions MAY only be sent if they are within
//# the window announced by the most recent <ACK>.
fn scaled_retry_strict_sequence_distance_and_conservative_fallbacks() {
    for (iss, beyond_window) in [100, u32::MAX - 20000]
        .into_iter()
        .flat_map(|iss| [false, true].map(|enabled| (iss, enabled)))
    {
        for scale in [0, 1, 14] {
            let (mut a, _) = pair(config(131_072, 32_768), iss);
            // Negotiation extremes without allocating a 1GiB receive buffer.
            a.peer_scale = scale;
            a.snd_wnd = 65_536;
            a.write(&[0x55; 32_768]).unwrap();
            packet(&mut a, 40);
            let una = a.snd_una;
            let high = a.snd_nxt;
            a.config.retransmit_beyond_window = beyond_window;
            a.snd_wnd = 1;
            // Even a first retry needs evidence the original was in-window.
            a.rack.commit_original_window(una, high, false);
            assert_eq!(a.retry_limit(una, 32_768), 1);
            assert_eq!(a.retry_limit(una.wrapping_add(20_000), 16), 0);
            a.rack.commit_original_window(una, high, true);
            assert_eq!(a.retry_limit(una, 32_768), 32_768);
            // First retry is allowed even far outside the shrunken window.
            assert_eq!(a.retry_limit(una.wrapping_add(20_000), 16), 16);
            a.rack.commit_retry_span(una, high);
            let edge = una.wrapping_add(1);
            let unit = 1u32 << scale;
            for distance in [unit - 1, unit, unit + 1] {
                let seq = edge.wrapping_add(distance);
                assert_eq!(a.retry_limit(seq, 16), if distance < unit { 16 } else { 0 });
            }
            // Serially inside the latest window is normal retransmission.
            assert_eq!(a.retry_limit(una, 32_768), 32_768);
            a.scaling = false;
            assert_eq!(
                a.retry_limit(una, 32_768),
                if beyond_window { 32_768 } else { 1 }
            );
            a.scaling = true;
            a.rack.commit_original_window(una, high, false);
            assert_eq!(a.retry_limit(una, 32_768), 1);
            assert_eq!(a.retry_limit(una.wrapping_add(20_000), 16), 0);
            a.rack.abandon(high);
            assert!(a.rack.original_retry_span(una, high).is_none());
            assert_eq!(a.retry_limit(una, 32_768), 1);
            a.config.retransmit_beyond_window = true;
            assert_eq!(a.retry_limit(una, 32_768), 1);
            assert_eq!(a.retry_limit(una.wrapping_add(20_000), 16), 0);
            a.scaling = false;
            assert_eq!(a.retry_limit(una, 32_768), 32_768);
            a.snd_wnd = 0;
            assert_eq!(a.retry_limit(una, 32_768), 0);
        }
    }
}

#[test]
fn rack_retransmission_echo_normalizes_secret_timestamp_offset() {
    for granularity in [
        TimestampGranularity::Milliseconds,
        TimestampGranularity::Microseconds,
    ] {
        for sack in [false, true] {
            for offset in [42, u32::MAX - 250] {
                for echo_tick in [
                    granularity.tick(200_000) as u32,
                    granularity.tick(300_000) as u32,
                    granularity.tick(300_000) as u32 + 1,
                ] {
                    let cfg = ConnectionConfig {
                        timestamps: true,
                        timestamp_granularity: granularity,
                        sack,
                        rack: sack,
                        ..config(64, 20)
                    };
                    let (mut a, _) = pair(cfg, 100);
                    a.set_timestamp_offset(offset);
                    a.set_nagle(false);
                    a.rack = Rack::with_capacity(a.config.send_capacity + 2).unwrap();
                    a.rack.sample(100_000, 30);
                    let base = a.snd_una;
                    a.write(b"a").unwrap();
                    packet(&mut a, 200_000);
                    a.write(b"b").unwrap();
                    packet(&mut a, 210_000);
                    a.snd_wnd = 1; // Clip retry to the head, leaving an older tail.
                    a.retx_pending = true;
                    let bytes = packet(&mut a, 300_000);
                    let seg = wire::parse(ip(tuple()), &bytes).unwrap();
                    assert_eq!(seg.payload, b"a");
                    assert_eq!(
                        seg.options.timestamps.unwrap().0,
                        (granularity.tick(300_000) as u32).wrapping_add(offset)
                    );
                    let next = a.receive.next();
                    timestamp_input(
                        &mut a,
                        400_000,
                        next,
                        base.wrapping_add(1),
                        ACK,
                        Some((400, echo_tick.wrapping_add(offset))),
                        b"",
                    );
                    assert_eq!(a.snd_una, base.wrapping_add(1));
                    assert_eq!(a.rack.ack_sample, None); // Karn, even on matching echo.
                    a.rack.detect(400_000, true, Some(100_000));
                    assert_eq!(
                        a.rack.lowest_lost(a.mss as u32),
                        (echo_tick == granularity.tick(300_000) as u32)
                            .then_some((base.wrapping_add(1), base.wrapping_add(2))),
                    );
                }
            }
        }
    }
}

#[test]
fn scaled_reno_and_newreno_entry_use_original_valid_window() {
    for algorithm in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
        for iss in [100, u32::MAX - 20] {
            let cfg = ConnectionConfig {
                recovery_algorithm: algorithm,
                initial_window: InitialWindow::Iw10,
                ..config(65_536, 8)
            };
            let (mut a, _) = primed_pair(cfg, iss);
            a.write(b"abcdefghijklmnopqrstuvwx").unwrap();
            for now in 40..43 {
                packet(&mut a, now);
            }
            let una = a.snd_una;
            let next = a.receive.next();
            for now in 50..54 {
                inject(&mut a, now, next, una, ACK, 1, b"");
            }
            assert!(a.retx_pending);
            let before = a.rack.original_retry_span(una, a.snd_nxt).unwrap();
            assert_eq!(a.transmit(54, &mut [0; 27]), Err(Error::OutputTooSmall));
            assert_eq!(a.rack.original_retry_span(una, a.snd_nxt).unwrap(), before);
            let bytes = packet(&mut a, 54);
            let segment = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(segment.header.sequence, una.0);
            assert_eq!(segment.payload, b"abcdefgh");
            assert_eq!(
                a.rack
                    .original_retry_span(una, a.snd_nxt)
                    .unwrap()
                    .successful_retries,
                1
            );
            if algorithm == RecoveryAlgorithm::NewReno {
                inject(&mut a, 55, next, una.wrapping_add(8), ACK, 1, b"");
                let bytes = packet(&mut a, 56);
                assert_eq!(
                    wire::parse(ip(tuple()), &bytes).unwrap().payload,
                    b"ijklmnop"
                );
                assert_eq!(
                    a.rack
                        .original_retry_span(a.snd_una, a.snd_nxt)
                        .unwrap()
                        .successful_retries,
                    1
                );
            }
        }
    }
}

#[test]
fn scaled_sack_entry_nextseg_rescue_and_post_rto_commit_exact_coverage() {
    for iss in [100, u32::MAX - 500] {
        let mut a = sack_flight(128, iss, 8);
        a.peer_scale = 1;
        let una = a.snd_una;
        let ranges = [
            (una.wrapping_add(128).0, una.wrapping_add(256).0),
            (una.wrapping_add(384).0, una.wrapping_add(768).0),
        ];
        sack_ack(&mut a, 200, una, &ranges);
        for (now, offset) in [(201, 0), (202, 256)] {
            // Entry then NextSeg: both originals were valid, even though
            // this latest window contains neither complete wire segment.
            a.snd_wnd = 2;
            let seq = una.wrapping_add(offset);
            let before = a.rack.original_retry_span(seq, a.snd_nxt).unwrap();
            assert_eq!(before.successful_retries, 0);
            assert_eq!(a.transmit(now, &mut [0; 147]), Err(Error::OutputTooSmall));
            assert_eq!(a.rack.original_retry_span(seq, a.snd_nxt).unwrap(), before);
            let bytes = packet(&mut a, now);
            let segment = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(segment.header.sequence, seq.0);
            assert_eq!(segment.payload, &[0x77; 128]);
            assert_eq!(
                a.rack
                    .original_retry_span(seq, a.snd_nxt)
                    .unwrap()
                    .successful_retries,
                1
            );
        }
        let next = a.receive.next();
        inject_sack(&mut a, 210, next, una.wrapping_add(384), ACK, 1, &[], &[]);
        let bytes = packet(&mut a, 211);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.header.sequence, una.wrapping_add(896).0);
        assert_eq!(segment.payload, &[0x77; 128]);
        assert_eq!(a.sack_recovery.unwrap().rescue_rxt, Some(a.snd_nxt));
        assert_eq!(
            a.rack
                .original_retry_span(una.wrapping_add(896), a.snd_nxt)
                .unwrap()
                .successful_retries,
            1
        );

        let mut a = sack_flight(128, iss, 8);
        a.peer_scale = 1;
        let una = a.snd_una;
        let deadline = a.rto_deadline.unwrap();
        a.timeout(deadline).unwrap();
        a.snd_wnd = 2;
        let bytes = packet(&mut a, deadline);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().payload,
            &[0x77; 128]
        );
        let ranges = [(384, 512), (640, 768), (896, 1024)]
            .map(|(l, r)| (una.wrapping_add(l).0, una.wrapping_add(r).0));
        sack_ack(&mut a, deadline + 1, una.wrapping_add(256), &ranges);
        for (time, offset) in [(2, 256), (3, 512)] {
            a.snd_wnd = 2;
            let bytes = packet(&mut a, deadline + time);
            let segment = wire::parse(ip(tuple()), &bytes).unwrap();
            let seq = una.wrapping_add(offset);
            assert_eq!(segment.header.sequence, seq.0);
            assert_eq!(segment.payload, &[0x77; 128]);
            assert_eq!(
                a.rack
                    .original_retry_span(seq, a.snd_nxt)
                    .unwrap()
                    .successful_retries,
                1
            );
        }
    }
}

#[test]
fn scaled_tlp_tail_retry_commits_but_zero_window_persist_does_not() {
    for iss in [100, u32::MAX - 1999] {
        let (mut a, _) = tlp_baseline_pair(iss);
        a.write(&[0x55; 4000]).unwrap();
        for _ in 0..4 {
            packet(&mut a, 100_000);
        }
        let base = a.send_base;
        let tail = base.wrapping_add(3000);
        let pto = a.tlp_deadline.unwrap();
        a.timeout(pto).unwrap();
        a.snd_wnd = 2;
        let before = a.rack.original_retry_span(tail, a.snd_nxt).unwrap();
        assert_eq!(a.transmit(pto, &mut [0; 1019]), Err(Error::OutputTooSmall));
        assert_eq!(a.rack.original_retry_span(tail, a.snd_nxt).unwrap(), before);
        let bytes = packet(&mut a, pto);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.header.sequence, tail.0);
        assert_eq!(segment.payload, &[0x55; 1000]);
        assert_eq!(
            a.rack
                .original_retry_span(tail, a.snd_nxt)
                .unwrap()
                .successful_retries,
            1
        );
        assert_eq!(a.retry_limit(tail, 1000), 0); // already retried and far outside
        let next = a.receive.next();
        inject(&mut a, pto + 1, next, base, ACK, 0, &[]);
        let before = a.rack.original_retry_span(base, a.snd_nxt).unwrap();
        let deadline = a.loss_timer.unwrap().1;
        a.timeout(deadline).unwrap();
        let bytes = packet(&mut a, deadline);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().payload,
            &[0x55; 1]
        );
        assert_eq!(a.rack.original_retry_span(base, a.snd_nxt).unwrap(), before);
    }
}
fn config(capacity: usize, mss: u16) -> ConnectionConfig {
    ConnectionConfig {
        // Fixed-time equation/admission oracles intentionally bypass pacing.
        prr_pacing: false,
        send_capacity: capacity,
        receive_capacity: capacity,
        mss,
        ..ConnectionConfig::default()
    }
}

fn tuple() -> Tuple {
    Tuple {
        local: "192.0.2.1:1000".parse().unwrap(),
        remote: "192.0.2.2:2000".parse().unwrap(),
    }
}

fn reverse(tuple: Tuple) -> Tuple {
    Tuple {
        local: tuple.remote,
        remote: tuple.local,
    }
}

fn ip(tuple: Tuple) -> IpMetadata {
    IpMetadata {
        source: tuple.local.ip(),
        destination: tuple.remote.ip(),
    }
}

fn packet(connection: &mut Connection, now: Instant) -> Vec<u8> {
    let mut out = vec![0; 65535];
    let length = connection
        .transmit(now, &mut out)
        .unwrap()
        .expect("packet ready");
    out.truncate(length);
    out
}

fn deliver(from: &mut Connection, to: &mut Connection, now: Instant) -> Vec<u8> {
    let bytes = packet(from, now);
    let segment = wire::parse(ip(from.tuple()), &bytes).unwrap();
    to.input(now, &segment).unwrap();
    bytes
}

fn pair(cfg: ConnectionConfig, iss: u32) -> (Connection, Connection) {
    let mut a = Connection::active(tuple(), cfg.clone(), iss, 0).unwrap();
    let bytes = packet(&mut a, 0);
    let syn = wire::parse(ip(tuple()), &bytes).unwrap();
    let mut b = Connection::passive(reverse(tuple()), cfg, 900, 10, &syn).unwrap();
    deliver(&mut b, &mut a, 20);
    deliver(&mut a, &mut b, 30);
    assert_eq!(a.state(), State::Established);
    assert_eq!(b.state(), State::Established);
    assert!(a.take_events().connected);
    assert!(b.take_events().connected);
    (a, b)
}

#[path = "connection_persist_idle_restart_tests.rs"]
mod persist_idle_restart;

#[path = "connection_sender_metadata_tests.rs"]
mod sender_metadata;

#[path = "connection_pto_margin_tests.rs"]
mod pto_margin;

#[path = "connection_adaptive_ack_tests.rs"]
mod adaptive_ack_tests;

#[path = "connection_statistics_tests.rs"]
mod statistics;

#[path = "connection_persist_reopen_tests.rs"]
mod persist_reopen;

#[path = "fast_open_connection_tests.rs"]
mod fast_open_tests;

#[path = "connection_early_response_tests.rs"]
mod early_response;

#[path = "connection_early_ack_handoff_tests.rs"]
mod early_ack_handoff;

#[path = "connection_handshake_limit_tests.rs"]
mod handshake_limit;

#[path = "connection_syn_echo_tests.rs"]
mod syn_echo;

#[path = "connection_syn_deferral_tests.rs"]
mod syn_deferral;

#[path = "connection_ecn_prr_tests.rs"]
mod ecn_prr;

#[test]
fn transport_info_cubic_ecn_epoch_lifecycle() {
    for (enabled, timeout) in [(false, false), (true, false), (true, true)] {
        let mut cfg = config(8192, 1000);
        cfg.ecn = enabled;
        cfg.initial_window = InitialWindow::Iw10;
        cfg.congestion_algorithm = CongestionAlgorithm::Cubic;
        cfg.sack = true;
        cfg.rack = true;
        cfg.prr = true;
        let (_, mut a) = pair(cfg, 0); // Passive sender, as in the CC19 case.
        assert!(!a.transport_info().ecn_response);
        a.write(&[1; 4000]).unwrap();
        for _ in 0..4 {
            packet(&mut a, 40);
        }
        assert_eq!(a.transport_info().cwnd, 10000);
        assert!(!a.transport_info().ecn_response); // Negotiation is not CWR.
        let base = a.snd_una;
        let next = a.receive.next();
        inject(
            &mut a,
            50,
            next,
            base.wrapping_add(1000),
            ACK | ECE,
            8192,
            &[],
        );
        assert_eq!(a.transport_info().ecn_response, enabled);
        assert_eq!(a.prr.is_some(), enabled); // Modern CUBIC ECN starts PRR.
        if !enabled {
            continue;
        }
        assert_eq!(
            (
                a.transport_info().cwnd,
                a.transport_info().ssthresh,
                a.data_flight()
            ),
            (5000, 7000, 3000)
        );
        assert!(a.ecn_cwr_pending);
        // RTO clears the ECN epoch and the snapshot reports actual loss.
        if timeout {
            a.timeout(a.rto_deadline.unwrap()).unwrap();
            assert!(a.transport_info().loss);
            assert!(!a.transport_info().ecn_response);
            continue;
        }
        // Equality does not end the existing core epoch.
        inject(&mut a, 60, next, base.wrapping_add(4000), ACK, 8192, &[]);
        assert!(a.transport_info().ecn_response);
        a.write(&[2; 1000]).unwrap();
        let bytes = packet(&mut a, 61);
        assert_ne!(
            wire::parse(ip(a.tuple()), &bytes).unwrap().header.flags & CWR,
            0
        );
        assert!(!a.ecn_cwr_pending);
        assert!(a.transport_info().ecn_response); // Not the pending packet flag.
        inject(&mut a, 70, next, base.wrapping_add(5000), ACK, 8192, &[]);
        assert!(!a.transport_info().ecn_response);
    }
}

#[test]
fn transport_info_ecn_epoch_ends_on_recovery_exit() {
    for (recovery, sack) in [
        (RecoveryAlgorithm::Reno, false),
        (RecoveryAlgorithm::NewReno, false),
        (RecoveryAlgorithm::NewReno, true),
    ] {
        for iss in [100, u32::MAX - 5999] {
            let mut cfg = config(32_000, 1000);
            cfg.ecn = true;
            cfg.initial_window = InitialWindow::Iw10;
            cfg.congestion_algorithm = CongestionAlgorithm::Cubic;
            cfg.recovery_algorithm = recovery;
            cfg.sack = sack;
            let (mut a, _) = pair(cfg, iss);
            let base = a.snd_una;
            let next = a.receive.next();
            a.write(&[1; 6000]).unwrap();
            for _ in 0..6 {
                packet(&mut a, 40);
            }
            let ack = base.wrapping_add(3000);
            inject(&mut a, 50, next, ack, ACK | ECE, 32_000, &[]);
            assert!(a.transport_info().ecn_response);
            // Extend the flight beyond the ECN boundary before loss entry.
            a.write(&[2; 1000]).unwrap();
            packet(&mut a, 60);
            let end = base.wrapping_add(7000);
            assert_eq!(a.snd_nxt, end);
            if sack {
                inject_sack(
                    &mut a,
                    70,
                    next,
                    ack,
                    ACK,
                    32_000,
                    &[],
                    &[(base.wrapping_add(4000).0, end.0)],
                );
            } else {
                for _ in 0..3 {
                    inject(&mut a, 70, next, ack, ACK, 32_000, &[]);
                }
            }
            let info = a.transport_info();
            assert!(info.recovery && info.ecn_response);
            inject(&mut a, 80, next, end, ACK, 32_000, &[]);
            let info = a.transport_info();
            assert!(!info.recovery && !info.loss);
            assert!(!info.ecn_response, "{recovery:?}, sack={sack}, iss={iss}");
            assert_eq!(a.transport_info(), info); // Sampling is read-only.
        }
    }
}

#[test]
fn transport_info_ecn_epoch_ends_on_fin_only_ack() {
    for iss in [100, u32::MAX - 4000] {
        let mut cfg = config(8192, 1000);
        cfg.ecn = true;
        cfg.initial_window = InitialWindow::Iw10;
        cfg.congestion_algorithm = CongestionAlgorithm::Cubic;
        let (mut a, _) = pair(cfg, iss);
        let base = a.snd_una;
        let next = a.receive.next();
        a.write(&[1; 4000]).unwrap();
        for _ in 0..4 {
            packet(&mut a, 40);
        }
        inject(
            &mut a,
            50,
            next,
            base.wrapping_add(1000),
            ACK | ECE,
            8192,
            &[],
        );
        let end = base.wrapping_add(4000);
        inject(&mut a, 60, next, end, ACK, 8192, &[]);
        assert!(a.transport_info().ecn_response); // Equality remains active, including wrap.
        assert_eq!(a.send_base, end);
        a.shutdown().unwrap();
        let bytes = packet(&mut a, 70);
        let fin = wire::parse(ip(a.tuple()), &bytes).unwrap();
        assert_ne!(fin.header.flags & FIN, 0);
        assert!(fin.payload.is_empty());
        inject(&mut a, 80, next, end.wrapping_add(1), ACK, 8192, &[]);
        assert_eq!(a.state(), State::FinWait2);
        assert_eq!(a.send_base, end); // DATA edge did not advance; SND.UNA did.
        assert_eq!(a.snd_una, end.wrapping_add(1));
        assert!(!a.transport_info().ecn_response);
    }
}

#[test]
fn transport_info_notsent_tracks_original_payload_across_wrap_ack_retry_and_fin() {
    for iss in [100, u32::MAX - 3] {
        let mut cfg = config(64, 8);
        cfg.nagle = false;
        let (mut a, _) = pair(cfg, iss);
        a.write(&[7; 16]).unwrap();
        assert_eq!(a.transport_info().notsent_bytes, 16);
        let before = a.transport_info();
        assert_eq!(a.transmit(40, &mut [0; 20]), Err(Error::OutputTooSmall));
        assert_eq!(a.transport_info(), before);
        packet(&mut a, 40);
        assert_eq!(a.transport_info().notsent_bytes, 8);
        let next = a.receive.next();
        let ack = a.send_base.wrapping_add(3);
        inject(&mut a, 50, next, ack, ACK, 64, &[]);
        assert_eq!(
            (
                a.transport_info().send_used,
                a.transport_info().notsent_bytes
            ),
            (13, 8)
        );
        a.retx_pending = true;
        let retry = packet(&mut a, 60);
        assert_eq!(
            wire::parse(ip(tuple()), &retry).unwrap().header.sequence,
            ack.0
        );
        assert_eq!(a.transport_info().notsent_bytes, 8);
        packet(&mut a, 70);
        assert_eq!(a.transport_info().notsent_bytes, 0);
        a.shutdown().unwrap();
        packet(&mut a, 80);
        assert_eq!(a.transport_info().notsent_bytes, 0);
        let end = a.snd_nxt;
        inject(&mut a, 90, next, end, ACK, 64, &[]);
        assert_eq!(a.transport_info().send_used, 0);
        let done = a.transport_info().busy_time_us;
        a.update_time(100_000).unwrap();
        assert_eq!(a.transport_info().busy_time_us, done);
    }
}

#[test]
fn transport_info_receive_idle_clock_only_new_accepted_payload_resets() {
    let (mut a, _) = pair(config(64, 8), 100);
    a.update_time(1_000_020).unwrap();
    assert_eq!(a.transport_info().last_data_recv_ms, 1000);
    let next = a.receive.next();
    let ack = a.snd_una;
    inject(&mut a, 1_010_020, next, ack, ACK, 64, &[]);
    assert_eq!(a.transport_info().last_data_recv_ms, 1010);
    inject(&mut a, 1_020_020, next, ack, ACK, 64, b"abc");
    assert_eq!(a.transport_info().last_data_recv_ms, 0);
    // Duplicate and out-of-window text are not newly accepted payload.
    inject(&mut a, 1_030_020, next, ack, ACK, 64, b"abc");
    inject(
        &mut a,
        1_040_020,
        next.wrapping_add(1000),
        ack,
        ACK,
        64,
        b"bad",
    );
    assert_eq!(a.transport_info().last_data_recv_ms, 20);
    inject(
        &mut a,
        1_050_020,
        next.wrapping_add(8),
        ack,
        ACK,
        64,
        b"ooo",
    );
    assert_eq!(a.transport_info().last_data_recv_ms, 0);
    assert_eq!(a.readable_bytes(), 3); // INQ excludes the out-of-order tail.
    let mut out = [0; 3];
    assert_eq!(a.read(&mut out), Ok(3));
    assert_eq!(a.transport_info_at(1_060_020).last_data_recv_ms, 10);
    inject(
        &mut a,
        1_060_020,
        next.wrapping_add(3),
        ack,
        ACK,
        64,
        b"defgh",
    );
    assert_eq!(a.read(&mut [0; 8]), Ok(8));
    inject(
        &mut a,
        1_070_020,
        next.wrapping_add(11),
        ack,
        ACK | FIN,
        64,
        &[],
    );
    assert_eq!(a.transport_info().last_data_recv_ms, 10);
    assert_eq!(a.readable_bytes(), 0);
    assert_eq!(a.read(&mut out), Ok(0));
    assert_eq!(a.transport_info().busy_time_us, 0);
}

#[test]
fn transport_info_rwnd_and_busy_accrue_real_intervals_in_both_caller_units() {
    for scale in [1, 1000] {
        let mut cfg = config(4096, 1000);
        cfg.nagle = false;
        cfg.timebase.units_per_second = 1_000_000 * scale;
        let (mut a, _) = pair(cfg, 100);
        let start = 100 * scale;
        let next = a.receive.next();
        let ack = a.snd_una;
        inject(&mut a, start, next, ack, ACK, 0, &[]);
        assert_eq!(
            a.transport_info_at(start + 50_000 * scale).rwnd_limited_us,
            0
        );
        a.write(&[1; 1000]).unwrap();
        assert_eq!(
            a.transport_info_at(start + 100_000 * scale).rwnd_limited_us,
            100_000
        );
        inject(&mut a, start + 200_000 * scale, next, ack, ACK, 2000, &[]);
        assert_eq!(a.transport_info().rwnd_limited_us, 200_000);
        packet(&mut a, start + 200_000 * scale);
        let ack = a.snd_nxt;
        inject(&mut a, start + 230_000 * scale, next, ack, ACK, 10, &[]);
        a.write(&[2; 1000]).unwrap();
        inject(&mut a, start + 330_000 * scale, next, ack, ACK, 2000, &[]);
        let info = a.transport_info();
        assert_eq!(
            (
                info.rwnd_limited_us,
                info.busy_time_us,
                info.sndbuf_limited_us
            ),
            (300_000, 330_000, 0)
        );
        packet(&mut a, start + 330_000 * scale);
        let ack = a.snd_nxt;
        inject(&mut a, start + 350_000 * scale, next, ack, ACK, 2000, &[]);
        assert_eq!(a.transport_info().busy_time_us, 350_000);
        a.update_time(start + 450_000 * scale).unwrap();
        assert_eq!(a.transport_info().busy_time_us, 350_000);
    }
}

#[test]
fn upstream_rwnd_limited_reopen_event_orders() {
    for probe_first in [false, true] {
        let cfg = ConnectionConfig {
            timestamps: true,
            sack: true,
            rack: true,
            prr: true,
            tlp: true,
            initial_window: InitialWindow::Iw10,
            rto_min_us: 200_000,
            peer_max_ack_delay_us: 200_000,
            delayed_ack_us: 0,
            recovery_algorithm: RecoveryAlgorithm::Reno,
            ..config(65_536, 1460)
        };
        let mut a = Connection::active(tuple(), cfg, 100, 0).unwrap();
        packet(&mut a, 0);
        let metadata = ip(reverse(tuple()));
        let mut synack = [0; 28];
        let size = wire::encode(
            metadata,
            Header {
                source_port: tuple().remote.port(),
                destination_port: tuple().local.port(),
                sequence: 900,
                acknowledgment: 101,
                flags: SYN | ACK,
                window: 0,
                urgent_pointer: 0,
            },
            &[2, 4, 3, 232, 1, 1, 4, 2], // MSS 1000, no TS or WS.
            &[],
            &mut synack,
        )
        .unwrap();
        a.input(10_000, &wire::parse(metadata, &synack[..size]).unwrap())
            .unwrap();
        packet(&mut a, 10_000);
        assert!(!a.timestamps && !a.scaling);
        assert_eq!(a.transport_info().rwnd_limited_us, 0);
        a.write(&[1; 1000]).unwrap();
        assert_eq!(a.transport_info_at(110_000).rwnd_limited_us, 100_000);
        assert_eq!(a.loss_timer, Some((LossTimer::Zwp, 210_000)));
        if probe_first {
            a.timeout(210_000).unwrap();
            let bytes = packet(&mut a, 210_000);
            let probe = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!((probe.header.sequence, probe.payload.len()), (100, 0));
            assert_eq!(a.snd_nxt, Seq(101));
            assert_eq!(a.congestion.cwnd(), 10_000);
        }
        // Both event orders share the script's 200ms reopen/probe boundary.
        inject(&mut a, 210_000, Seq(901), Seq(101), ACK, 2000, &[]);
        assert_eq!(a.snd_wnd, 2000);
        assert!(!a.probe_pending);
        assert_eq!(a.transport_info().rwnd_limited_us, 200_000);
        let bytes = packet(&mut a, 210_000);
        let data = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!((data.header.sequence, data.payload.len()), (101, 1000));
        assert_eq!(data.header.flags, PSH | ACK);
        let first_ack_at = 240_000;
        inject(&mut a, first_ack_at, Seq(901), Seq(1101), ACK, 10, &[]);
        a.write(&[2; 1000]).unwrap();
        assert_eq!(a.transmit(first_ack_at, &mut [0; 1500]), Ok(None));
        inject(
            &mut a,
            first_ack_at + 100_000,
            Seq(901),
            Seq(1101),
            ACK,
            2000,
            &[],
        );
        let info = a.transport_info();
        assert_eq!(
            (info.rwnd_limited_us, info.busy_time_us),
            (300_000, first_ack_at + 90_000)
        );
        let bytes = packet(&mut a, first_ack_at + 100_000);
        let data = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!((data.header.sequence, data.payload.len()), (1101, 1000));
        assert_eq!(data.header.flags, PSH | ACK);
        inject(
            &mut a,
            first_ack_at + 120_000,
            Seq(901),
            Seq(2101),
            ACK,
            2000,
            &[],
        );
        assert_eq!(a.transport_info().busy_time_us, first_ack_at + 110_000);
    }
}

#[test]
fn transport_info_zero_window_standalone_fin_accrues_until_window_opens() {
    for iss in [100, u32::MAX] {
        for scale in [1, 1000] {
            let mut cfg = config(64, 8);
            cfg.timebase.units_per_second = 1_000_000 * scale;
            let (mut a, _) = pair(cfg, iss);
            let start = 100 * scale;
            let next = a.receive.next();
            let ack = a.snd_una;
            inject(&mut a, start, next, ack, ACK, 0, &[]);
            a.shutdown().unwrap();
            assert_eq!(a.send.len(), 0);
            let now = a.now;
            let ticks = a.transport_ticks;
            let events = a.events.clone();
            let open = start + 100_000 * scale;
            let info = a.transport_info_at(open);
            assert_eq!(
                (info.busy_time_us, info.rwnd_limited_us, info.notsent_bytes),
                (100_000, 100_000, 0)
            );
            assert_eq!(info.sndbuf_limited_us, 0);
            assert_eq!(a.transport_info_at(open), info);
            assert_eq!((a.now, a.transport_ticks, &a.events), (now, ticks, &events));
            a.update_time(open).unwrap();
            assert_eq!(a.transport_info(), info);
            inject(&mut a, open, next, ack, ACK, 1, &[]);
            let bytes = packet(&mut a, open);
            let fin = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(fin.header.flags, ACK | FIN);
            assert!(fin.payload.is_empty());
            let end = a.snd_nxt;
            assert_eq!(end, ack.wrapping_add(1));
            // In-flight FIN stays busy, but is not an unsent window demand.
            assert_eq!(
                a.transport_info_at(open + 10_000 * scale).rwnd_limited_us,
                100_000
            );
            inject(&mut a, open + 10_000 * scale, next, end, ACK, 1, &[]);
            let done = a.transport_info();
            assert_eq!(
                (done.busy_time_us, done.rwnd_limited_us, done.notsent_bytes),
                (110_000, 100_000, 0)
            );
            a.update_time(open + 110_000 * scale).unwrap();
            assert_eq!(a.transport_info().busy_time_us, done.busy_time_us);
            assert_eq!(a.transport_info().rwnd_limited_us, done.rwnd_limited_us);
        }
    }
}

#[test]
fn transport_info_standalone_fin_window_limitation_matches_recovery_gates() {
    for iss in [100, u32::MAX - 5_000] {
        let cfg = ConnectionConfig {
            initial_window: InitialWindow::Iw10,
            nagle: false,
            ..config(32_768, 1_000)
        };
        let (mut a, _) = pair(cfg, iss);
        a.write(&[1; 10_000]).unwrap();
        for _ in 0..10 {
            packet(&mut a, 40);
        }
        assert_eq!(a.flight(), a.congestion.cwnd());
        a.shutdown().unwrap();
        a.snd_wnd = a.flight();
        let info = a.transport_info_at(100_040);
        assert_eq!(
            (info.busy_time_us, info.rwnd_limited_us, info.notsent_bytes),
            (100_010, 100_000, 0)
        );
        a.prr = Some(Prr::new(a.flight(), a.mss as u32));
        assert_eq!(a.transport_info_at(100_040).rwnd_limited_us, 0);
        a.snd_wnd += 1;
        assert_eq!(a.transmit(40, &mut [0; 64]), Ok(None));
        a.snd_wnd -= 1;
        a.prr.as_mut().unwrap().acknowledge(1, 0, 5_000, false);
        assert_eq!(a.prr.unwrap().credit(), 1);
        assert_eq!(a.transport_info_at(100_040).rwnd_limited_us, 100_000);
        a.sack_recovery = Some(SackRecovery {
            recovery_point: a.snd_nxt,
            high_rxt: a.snd_una,
            rescue_rxt: None,
            entry_pending: false,
            pipe: a.flight(),
        });
        // SACK recovery requires a full MSS of credit, even for FIN.
        assert_eq!(a.transport_info_at(100_040).rwnd_limited_us, 0);
        a.prr.as_mut().unwrap().acknowledge(999, 0, 5_000, false);
        assert_eq!(a.prr.unwrap().credit(), 1_000);
        assert_eq!(a.transport_info_at(100_040).rwnd_limited_us, 100_000);
        a.sack_recovery.as_mut().unwrap().entry_pending = true;
        assert_eq!(a.transport_info_at(100_040).rwnd_limited_us, 0);
        // Without PRR, standalone FIN bypasses congestion/recovery credit.
        a.prr = None;
        assert_eq!(a.transport_info_at(100_040).rwnd_limited_us, 100_000);
        a.sack_recovery = None;
        a.snd_wnd += 1;
        let bytes = packet(&mut a, 40);
        let fin = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(fin.header.flags, ACK | FIN);
        assert!(fin.payload.is_empty());
        assert_eq!(a.transport_info_at(100_040).rwnd_limited_us, 0);
    }
}

#[test]
fn transport_info_sndbuf_requires_application_backpressure_and_send_starvation() {
    let mut cfg = config(16, 8);
    cfg.nagle = false;
    let (mut a, _) = pair(cfg, 100);
    a.update_time(100).unwrap();
    assert_eq!(a.write(&[1; 24]), Ok(16)); // Genuine byte-buffer short write.
    assert_eq!(a.transport_info_at(200).sndbuf_limited_us, 0); // Still unsent.
    packet(&mut a, 200);
    packet(&mut a, 200);
    assert_eq!(a.write(&[2]), Err(Error::WouldBlock));
    let info = a.transport_info_at(20_200);
    assert_eq!(
        (
            info.busy_time_us,
            info.sndbuf_limited_us,
            info.rwnd_limited_us
        ),
        (20_100, 20_000, 0)
    );
    let next = a.receive.next();
    let partial = a.send_base.wrapping_add(3);
    inject(&mut a, 20_200, next, partial, ACK, 64, &[]);
    assert_eq!(a.transport_info_at(40_200).sndbuf_limited_us, 20_000);
    // An exactly satisfied write is application-limited, not NOSPACE.
    assert_eq!(a.write(&[2; 3]), Ok(3));
    packet(&mut a, 20_200);
    assert_eq!(a.transport_info_at(40_200).sndbuf_limited_us, 20_000);
    let end = a.snd_nxt;
    inject(&mut a, 40_200, next, end, ACK, 64, &[]);
    assert_eq!(a.transport_info_at(100_000).busy_time_us, 40_100);
}

#[test]
fn transport_info_congestion_exhaustion_is_not_rwnd_or_sndbuf_limitation() {
    let mut cfg = config(128, 8);
    cfg.nagle = false;
    let (mut a, _) = pair(cfg, 100);
    a.update_time(100).unwrap();
    assert_eq!(a.write(&[1; 129]), Ok(128));
    let cwnd = a.congestion.cwnd();
    while a.flight() < cwnd {
        packet(&mut a, 100);
    }
    let next = a.receive.next();
    let ack = a.snd_una;
    inject(&mut a, 100, next, ack, ACK, 0, &[]);
    let info = a.transport_info_at(100_100);
    assert_eq!(
        (
            info.busy_time_us,
            info.rwnd_limited_us,
            info.sndbuf_limited_us
        ),
        (100_000, 0, 0)
    );
    assert!(info.notsent_bytes > 0);
}

#[test]
fn transport_info_sampling_is_read_only_and_preserves_fractional_caller_ticks() {
    let mut cfg = config(64, 8);
    cfg.timebase.units_per_second = 1_000_000_000;
    let (mut a, _) = pair(cfg, 100);
    a.write(&[1; 8]).unwrap();
    let now = a.now;
    let ticks = a.transport_ticks;
    let events = a.events.clone();
    let info = crate::allocation_tests::fail_after(0, || a.transport_info_at(now + 2500));
    assert_eq!(info.busy_time_us, 2);
    assert_eq!(a.transport_info_at(now + 2500), info);
    assert_eq!((a.now, a.transport_ticks, &a.events), (now, ticks, &events));
    for delta in 1..=2500 {
        a.update_time(now + delta).unwrap();
    }
    assert_eq!(a.transport_info().busy_time_us, 2);
    assert_eq!(a.transport_ticks[0], 2500);
    a.abort();
    a.update_time(now + 1_000_000).unwrap();
    assert_eq!(a.transport_info().busy_time_us, 2);
    assert_eq!(a.transport_info_at(u64::MAX).last_data_recv_ms, u32::MAX);
}

#[test]
fn resize_peak_is_checked_before_allocation_and_leaves_syn_offer_unchanged() {
    let cfg = ConnectionConfig {
        send_capacity: 1024,
        receive_capacity: 1,
        mss: 64,
        ..ConnectionConfig::default()
    };
    let mut connection = Connection::active(tuple(), cfg, 100, 0).unwrap();
    let max_charge = Connection::allocation_bytes(2048, 1, 64).unwrap();
    let (result, allocation_failed) = crate::allocation_tests::fail_after(0, || {
        let result = connection.set_buffer_capacities(2048, 1, max_charge);
        // The failure injection remains armed: admission made no allocation.
        (result, SendBuffer::new(1).is_err())
    });
    assert_eq!(result, Err(Error::NoMemory));
    assert!(allocation_failed);
    assert_eq!(connection.buffer_capacities(), (1024, 1));
    assert_eq!(connection.syn_window, 1);
    assert_eq!(connection.local_scale, 0);
    for allocation in 0..3 {
        assert_eq!(
            crate::allocation_tests::fail_after(allocation, || {
                connection.set_buffer_capacities(1024, 262144, usize::MAX)
            }),
            Err(Error::NoMemory)
        );
        assert_eq!(connection.buffer_capacities(), (1024, 1));
        assert_eq!(connection.syn_window, 1);
        assert_eq!(connection.local_scale, 0);
    }
}

#[test]
fn resize_before_first_syn_updates_offer_but_successful_output_freezes_it() {
    for passive in [false, true] {
        for failed_output in [false, true] {
            for (receive, window, scale) in [(32, 32, 0), (262144, 65535, 3)] {
                let cfg = ConnectionConfig {
                    send_capacity: 1024,
                    receive_capacity: 1024,
                    mss: 64,
                    ..ConnectionConfig::default()
                };
                let mut peer = Connection::active(reverse(tuple()), cfg.clone(), 900, 0).unwrap();
                let bytes = packet(&mut peer, 0);
                let syn = wire::parse(ip(peer.tuple()), &bytes).unwrap();
                let mut connection = if passive {
                    Connection::passive(tuple(), cfg, 100, 0, &syn).unwrap()
                } else {
                    Connection::active(tuple(), cfg, 100, 0).unwrap()
                };
                if failed_output {
                    connection
                        .set_buffer_capacities(1024, 131072, usize::MAX)
                        .unwrap();
                    assert_eq!(connection.transmit(0, &mut []), Err(Error::OutputTooSmall));
                    assert_eq!(connection.snd_nxt, connection.iss);
                }
                connection
                    .set_buffer_capacities(1024, receive, usize::MAX)
                    .unwrap();
                let bytes = packet(&mut connection, 0);
                let offer = wire::parse(ip(connection.tuple()), &bytes).unwrap();
                assert_eq!(offer.header.window, window);
                assert_eq!(offer.options.window_scale, Some(scale));
                let edge = connection.advertised_edge;
                connection
                    .set_buffer_capacities(1024, 16, usize::MAX)
                    .unwrap();
                connection
                    .set_buffer_capacities(1024, 524288, usize::MAX)
                    .unwrap();
                assert_eq!(connection.advertised_edge, edge);
                assert_eq!(connection.local_scale, scale);
                connection
                    .timeout(connection.rto_deadline.unwrap())
                    .unwrap();
                let now = connection.now;
                let bytes = packet(&mut connection, now);
                let retry = wire::parse(ip(connection.tuple()), &bytes).unwrap();
                assert_eq!(retry.header.window, window);
                assert_eq!(retry.options.window_scale, Some(scale));
            }
        }
    }
}

#[test]
fn pre_syn_resize_preserves_accepted_handshake_payload() {
    for fin in [false, true] {
        let cfg = ConnectionConfig {
            send_capacity: 1024,
            receive_capacity: 1024,
            mss: 64,
            ..ConnectionConfig::default()
        };
        let mut peer = Connection::active(reverse(tuple()), cfg.clone(), 900, 0).unwrap();
        let bytes = packet(&mut peer, 0);
        let mut syn = wire::parse(ip(peer.tuple()), &bytes).unwrap();
        syn.payload = b"accepted handshake payload";
        if fin {
            syn.header.flags |= FIN;
        }
        let mut connection = Connection::passive(tuple(), cfg, 100, 0, &syn).unwrap();
        let next = connection.receive.next();
        for receive in [8, 32, 262144] {
            connection
                .set_buffer_capacities(1024, receive, usize::MAX)
                .unwrap();
            assert_eq!(connection.receive.next(), next);
            assert_eq!(connection.receive_used, syn.payload.len());
            assert_eq!(connection.syn_window as usize, receive.min(65535));
        }
        let bytes = packet(&mut connection, 0);
        let offer = wire::parse(ip(connection.tuple()), &bytes).unwrap();
        assert_eq!(offer.header.window as usize, 65535);
        assert_eq!(offer.options.window_scale, Some(3));
        inject(&mut connection, 10, next, Seq(101), ACK, 1024, b"");
        let mut payload = [0; 64];
        assert_eq!(connection.read(&mut payload), Ok(syn.payload.len()));
        assert_eq!(&payload[..syn.payload.len()], syn.payload);
    }
}

#[test]
fn live_buffer_resize_is_atomic_and_preserves_recovery_and_window_promises() {
    let cfg = ConnectionConfig {
        send_capacity: 128,
        receive_capacity: 128,
        mss: 32,
        nagle: false,
        rack: true,
        sack: true,
        ..ConnectionConfig::default()
    };
    let (mut a, mut b) = pair(cfg, u32::MAX - 40);
    a.write(b"abcdefghijklmnopqrstuvwxyz").unwrap();
    deliver(&mut a, &mut b, 40);
    let scale = b.local_scale;
    let promised = b.advertised_edge;
    let next = b.receive.next();
    let before_rack = alloc::format!("{:?}", a.rack);
    a.scoreboard.update(
        a.snd_una,
        a.data_high(),
        &[
            Some((a.send_base.0 + 2, a.send_base.0 + 4)),
            None,
            None,
            None,
        ],
    );
    let before_sack = a.scoreboard.ranges().to_vec();
    for allocation in 0..4 {
        let result = crate::allocation_tests::fail_after(allocation, || {
            a.set_buffer_capacities(256, 256, usize::MAX)
        });
        assert_eq!(result, Err(Error::NoMemory));
        assert_eq!(a.buffer_capacities(), (128, 128));
        assert_eq!(a.send.len(), 26);
        assert_eq!(alloc::format!("{:?}", a.rack), before_rack);
        assert_eq!(a.scoreboard.ranges(), &before_sack);
    }
    a.set_buffer_capacities(256, 256, usize::MAX).unwrap();
    assert_eq!(a.scoreboard.ranges(), &before_sack);
    assert_eq!(alloc::format!("{:?}", a.rack), before_rack);
    a.set_buffer_capacities(4, 4, usize::MAX).unwrap();
    assert_eq!(a.write(b"!"), Err(Error::WouldBlock));
    assert!(!a.take_events().writable);
    a.accept_ack(
        a.send_base.wrapping_add(10),
        false,
        None,
        a.snd_wnd,
        false,
        0,
    );
    assert_eq!(a.send.len(), 16);
    assert!(!a.take_events().writable);
    a.accept_ack(
        a.send_base.wrapping_add(13),
        false,
        None,
        a.snd_wnd,
        false,
        0,
    );
    assert_eq!(a.send.len(), 3);
    assert!(a.take_events().writable);
    b.set_buffer_capacities(4, 4, usize::MAX).unwrap();
    assert_eq!(b.advertised_edge, promised);
    assert_eq!(b.receive.next(), next);
    assert_eq!(b.receive_window(), promised.distance_from(next));
    b.set_buffer_capacities(256, 262144, usize::MAX).unwrap();
    assert_eq!(b.local_scale, scale);
    let mut out = [0; 32];
    assert_eq!(b.read(&mut out), Ok(26));
    assert_eq!(&out[..26], b"abcdefghijklmnopqrstuvwxyz");
    assert_eq!(b.local_scale, scale);
    let window = b.advertised_window(false);
    // Large backing growth cannot renegotiate a scale of zero.
    assert_eq!(window, u16::MAX);
}

#[test]
fn resizing_scaled_receive_credit_keeps_negotiated_scale_and_old_edge() {
    let cfg = ConnectionConfig {
        send_capacity: 1024,
        receive_capacity: 131072,
        mss: 32,
        nagle: false,
        ..ConnectionConfig::default()
    };
    let (mut a, mut b) = pair(cfg, u32::MAX - 12);
    assert_eq!(b.local_scale, 2);
    a.write(b"abcdefghijklmnopqrstuvwxyz").unwrap();
    deliver(&mut a, &mut b, 40);
    let edge = b.advertised_edge;
    b.set_buffer_capacities(1024, 4, usize::MAX).unwrap();
    b.immediate_ack();
    let shrunk = packet(&mut b, 50);
    let shrunk = wire::parse(ip(b.tuple()), &shrunk).unwrap();
    assert_eq!(b.advertised_edge, edge);
    assert!(b.receive.right_edge().at_or_after(b.advertised_edge));
    assert_eq!(b.local_scale, 2);
    assert!(u32::from(shrunk.header.window) << 2 <= b.receive_window());
    let mut out = [0; 32];
    assert_eq!(b.read(&mut out), Ok(26));
    assert_eq!(&out[..26], b"abcdefghijklmnopqrstuvwxyz");
    b.set_buffer_capacities(1024, 262144, usize::MAX).unwrap();
    assert_eq!(b.local_scale, 2); // not the scale=3 a fresh buffer would select
    let grown = packet(&mut b, 60);
    let grown = wire::parse(ip(b.tuple()), &grown).unwrap();
    assert_eq!(grown.header.window, u16::MAX);
    assert!(b.advertised_edge.after(edge));
    assert!(b.receive.right_edge().at_or_after(b.advertised_edge));
}

// Exact physical-time traces in both caller units, independently of wire TS units.
#[test]
fn caller_units_wire_rtt_and_timer_equivalence() {
    for granularity in [
        TimestampGranularity::Milliseconds,
        TimestampGranularity::Microseconds,
    ] {
        for rack in [false, true] {
            let trace = |scale: u64| {
                let cfg = ConnectionConfig {
                    timestamps: true,
                    timestamp_granularity: granularity,
                    timebase: CallerTimebase {
                        units_per_second: 1_000_000 * scale,
                        ..CallerTimebase::default()
                    },
                    sack: true,
                    rack,
                    tlp: rack,
                    nagle: false,
                    peer_max_ack_delay_us: 0,
                    rto_min_us: 200_000,
                    keepalive: Some(KeepaliveConfig {
                        idle_us: 7_200_000_000,
                        interval_us: 75_000_000,
                        probes: 9,
                        send_garbage: false,
                    }),
                    ..config(16_000, 1000)
                };
                // Start just before wire TS wrap; caller nanoseconds do not alter it.
                let start = (u64::from(u32::MAX) - 100) * granularity.tick_us();
                let at = |us| (start + us) * scale;
                let mut a = Connection::active(tuple(), cfg.clone(), 100, at(0)).unwrap();
                let syn_bytes = packet(&mut a, at(0));
                let syn = wire::parse(ip(tuple()), &syn_bytes).unwrap();
                let mut b =
                    Connection::passive(reverse(tuple()), cfg, 900, at(50_000), &syn).unwrap();
                let synack = deliver(&mut b, &mut a, at(100_000));
                let ack = deliver(&mut a, &mut b, at(100_000));
                assert_eq!(a.rtt.srtt(), Some(100_000 * scale));
                assert_eq!(a.transport_info().rtt_us, Some(100_000));
                assert_eq!(a.rto(), 300_000 * scale);
                a.write(&[1; 1976]).unwrap();
                let first = deliver(&mut a, &mut b, at(100_001));
                assert_eq!(b.ack_deadline, Some(at(300_001)));
                let data_rto = a.rto_deadline.unwrap() / scale;
                let pto = a.tlp_deadline.map(|ticks| ticks / scale);
                let second = deliver(&mut a, &mut b, at(100_001));
                let data_ack = deliver(&mut b, &mut a, at(200_001));
                let info = a.transport_info();
                assert_eq!(info.rtt_us, Some(100_000));
                assert_eq!(info.rttvar_us, 37_500);
                assert_eq!(info.rto_us, 250_000);
                // All public setters take us; their resulting deadlines are caller ticks.
                a.set_keepalive(Some(KeepaliveConfig {
                    idle_us: 100,
                    interval_us: 50,
                    probes: 2,
                    send_garbage: false,
                }))
                .unwrap();
                assert_eq!(a.keepalive_deadline, Some(at(200_101)));
                a.timeout(at(200_101)).unwrap();
                let keepalive = packet(&mut a, at(200_101));
                assert_eq!(a.keepalive_deadline, Some(at(200_151)));
                a.set_keepalive(None).unwrap();
                a.write(b"timeout").unwrap();
                assert_eq!(a.sws_deadline, Some(at(700_101)));
                a.set_user_timeout(123).unwrap();
                a.set_application_timeout(Some(321)).unwrap();
                assert_eq!(a.user_deadline(), Some(at(200_224)));
                assert_eq!(a.application_deadline(), Some(at(200_422)));
                assert_eq!(a.next_deadline(), Some(at(200_224)));
                // Per-connection challenge epochs are physical durations, too.
                a.challenge_ack_start = Some(at(200_101));
                a.challenge_ack_sent = a.config.challenge_ack_limit;
                a.refresh_challenge_budget(at(1_200_100));
                assert_eq!(a.challenge_ack_sent, a.config.challenge_ack_limit);
                a.refresh_challenge_budget(at(1_200_101));
                assert_eq!(a.challenge_ack_sent, 0);
                a.update_time(at(200_102)).unwrap();
                assert_eq!(a.update_time(at(200_101)), Err(Error::TimeWentBackwards));
                a.time_wait();
                assert_eq!(a.time_wait_deadline, Some(at(120_200_102)));
                (
                    vec![syn_bytes, synack, ack, first, second, data_ack, keepalive],
                    info,
                    data_rto,
                    pto,
                )
            };
            assert_eq!(trace(1), trace(1000));
        }
    }
}

#[test]
fn nanoseconds_preserve_sub_microsecond_rtt_and_rack_window() {
    for rack in [false, true] {
        let cfg = ConnectionConfig {
            sack: true,
            rack,
            tlp: rack,
            peer_max_ack_delay_us: 0,
            timebase: CallerTimebase {
                units_per_second: 1_000_000_000,
                ..CallerTimebase::default()
            },
            ..config(16_000, 1000)
        };
        let mut a = Connection::active(tuple(), cfg.clone(), 100, 0).unwrap();
        let bytes = packet(&mut a, 0);
        let syn = wire::parse(ip(tuple()), &bytes).unwrap();
        let mut b = Connection::passive(reverse(tuple()), cfg, 900, 0, &syn).unwrap();
        deliver(&mut b, &mut a, 500);
        deliver(&mut a, &mut b, 500);
        assert_eq!(a.rtt.srtt(), Some(500));
        assert_eq!(a.rtt.variance(), 250);
        assert_eq!(a.transport_info().rtt_us, Some(0)); // diagnostics truncate, not internal samples
        assert_eq!(a.rack_enabled(), rack);
        a.write(&[1; 2000]).unwrap();
        packet(&mut a, 1000);
        packet(&mut a, 1000);
        rack_sack(&mut a, 1500, 0, &[(1000, 2000)]);
        assert_eq!(a.rack.ack_sample, Some(500));
        assert_eq!(a.rack_enabled(), rack);
        assert_eq!(a.rack.deadline, rack.then_some(1625));
    }
}

#[test]
fn caller_units_syn_timeout_guard_and_persist_cap() {
    for scale in [1, 1000] {
        let cfg = ConnectionConfig {
            timebase: CallerTimebase {
                units_per_second: 1_000_000 * scale,
                ..CallerTimebase::default()
            },
            rto_min_us: 200_000,
            user_timeout_us: 1,
            ..config(64, 8)
        };
        let mut a = Connection::active(tuple(), cfg.clone(), 100, 0).unwrap();
        assert_eq!(a.user_deadline(), Some(180_000_000 * scale));
        packet(&mut a, 0);
        a.timeout(1_000_000 * scale).unwrap();
        let bytes = packet(&mut a, 1_000_000 * scale);
        let syn = wire::parse(ip(tuple()), &bytes).unwrap();
        let mut b =
            Connection::passive(reverse(tuple()), cfg, 900, 1_000_000 * scale, &syn).unwrap();
        deliver(&mut b, &mut a, 1_100_000 * scale);
        deliver(&mut a, &mut b, 1_100_000 * scale);
        assert_eq!(a.rto(), 3_000_000 * scale);
        a.set_user_timeout(u64::MAX).unwrap();
        a.write(b"a").unwrap();
        deliver(&mut a, &mut b, 1_100_000 * scale);
        b.timeout(1_300_000 * scale).unwrap();
        deliver(&mut b, &mut a, 1_300_000 * scale);
        assert_eq!(a.rto(), 600_000 * scale);
        // Zero-window probe interval doubles in ticks but caps at physical 60s.
        a.write(b"b").unwrap();
        let seq = a.receive.next();
        let ack = a.snd_una;
        inject(&mut a, 1_300_000 * scale, seq, ack, ACK, 0, b"");
        a.persist_interval = 40_000_000 * scale;
        a.probe_pending = true;
        packet(&mut a, 1_300_000 * scale);
        assert_eq!(a.persist_interval, 60_000_000 * scale);
    }
}

#[test]
fn caller_ticks_timestamp_wakeup_wrap_paws_and_overflow() {
    for scale in [1, 1000] {
        for granularity in [
            TimestampGranularity::Milliseconds,
            TimestampGranularity::Microseconds,
        ] {
            let cfg = ConnectionConfig {
                timestamps: true,
                timestamp_granularity: granularity,
                timestamp_bytes_per_tick: 1,
                timebase: CallerTimebase {
                    units_per_second: 1_000_000 * scale,
                    ..CallerTimebase::default()
                },
                ..config(64, 8)
            };
            let period = granularity.tick_us() * scale;
            let wrap = (1u64 << 32) * period;
            let mut a = Connection::active(tuple(), cfg.clone(), 100, wrap - period).unwrap();
            packet(&mut a, wrap - period);
            a.syn_pending = true;
            assert_eq!(a.next_deadline(), Some(wrap));
            assert_eq!(a.timestamp_value(wrap - period), u32::MAX);
            assert_eq!(a.timestamp_value(wrap), 0);
            a.update_time(wrap).unwrap();
            assert_eq!(a.update_time(wrap - 1), Err(Error::TimeWentBackwards));
            // Independent physical PAWS lifetime, regardless of either unit choice.
            a.timestamps = true;
            a.state = State::Established;
            a.snd_una = a.snd_nxt;
            a.ts_recent = 100;
            a.ts_recent_at = wrap;
            let next = a.receive.next();
            let ack = a.snd_una;
            timestamp_input(
                &mut a,
                wrap + PAWS_RECENT_EXPIRY_US * scale - 1,
                next,
                ack,
                ACK,
                Some((99, 0)),
                b"",
            );
            assert_eq!(a.ts_recent, 100);
            timestamp_input(
                &mut a,
                wrap + PAWS_RECENT_EXPIRY_US * scale,
                next,
                ack,
                ACK,
                Some((99, 0)),
                b"",
            );
            assert_eq!(a.ts_recent, 99);
            let mut end = Connection::active(tuple(), cfg, 100, u64::MAX - 1).unwrap();
            packet(&mut end, u64::MAX - 1);
            assert_eq!(end.rto_deadline, Some(u64::MAX));
            end.syn_pending = true;
            assert_eq!(end.next_deadline(), Some(u64::MAX));
            end.set_user_timeout(u64::MAX).unwrap();
            end.set_application_timeout(Some(u64::MAX)).unwrap();
            assert_eq!(end.user_deadline(), Some(u64::MAX));
            assert_eq!(end.application_deadline(), Some(u64::MAX));
            end.time_wait();
            assert_eq!(end.time_wait_deadline, Some(u64::MAX));
        }
    }
}

// Establish actual cumulative progress beyond ISS, retaining the original
// congestion window so each recovery scenario still starts at its chosen IW.
fn prime_newreno(sender: &mut Connection) {
    let congestion = sender.congestion.clone();
    sender.write(b"x").unwrap();
    packet(sender, sender.now + 1);
    let next = sender.receive.next();
    let end = sender.snd_nxt;
    let window = (sender.snd_wnd >> sender.peer_scale) as u16;
    inject(sender, sender.now + 1, next, end, ACK, window, b"");
    sender.congestion = congestion;
    sender.congestion.observe_ack(end);
}

fn primed_pair(cfg: ConnectionConfig, iss: u32) -> (Connection, Connection) {
    let (mut a, mut b) = pair(cfg, iss);
    let congestion = a.congestion.clone();
    a.write(b"x").unwrap();
    deliver(&mut a, &mut b, 31);
    b.immediate_ack();
    deliver(&mut b, &mut a, 32);
    a.congestion = congestion;
    a.congestion.observe_ack(a.snd_una);
    (a, b)
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
//= type=test
//= reason=Initial ssthresh is the maximum serial-safe window; real initial-guard and first-loss traces assert it and its reduction.
//# The initial value of ssthresh SHOULD be set arbitrarily high (e.g., to the size of the largest
//# possible advertised window), but ssthresh MUST be reduced in response to congestion.
//= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
//= type=test
//= reason=Inclusive initial ISS is stored as exclusive ISS+1; unknown ACK history retains the strict initial guard, while real handshake history permits the optional section4.1 exception. Loss-epoch equality and timeout guards are retained.
//# When the TCP protocol control block is initialized, recover is set to the initial send sequence
//# number.
//= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
//= type=test
//= reason=Unknown-history initial and retained loss-epoch third-duplicate suppression leaves threshold unchanged; initial validated handshake history enables the optional section4.1 exception. Active-recovery RTO and ECN shared epochs remain guarded.
//# When the third duplicate ACK is received, the TCP sender first checks the value of recover to
//# see if the Cumulative Acknowledgment field covers more than recover. If so, the value of
//# recover is incremented to the value of the highest sequence number transmitted by the TCP so
//# far. The TCP then enters fast retransmit (step 2 of Section 3.2 of [RFC5681]). If not, the TCP
//# does not enter fast retransmit and does not reset ssthresh.
//= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
//= type=test
//= reason=Basic NewReno uses exclusive boundaries requiring strictly greater cumulative ACK. The optional section4.1 heuristic applies only to the initial boundary with validated ACK history; retained loss boundaries remain strict, including after RTO and wrap.
//# Because the acknowledgment field contains the sequence number that the sender next expects to
//# receive, the acknowledgment "ack_number" covers more than recover when ack_number - 1 >
//# recover; i.e., at least one byte more of data is acknowledged beyond the highest byte that was
//# outstanding when fast retransmit was last entered.
//= https://www.rfc-editor.org/rfc/rfc6582#section-6
//= type=test
//= reason=Basic NewReno uses exclusive boundaries requiring strictly greater cumulative ACK. The optional section4.1 heuristic applies only to the initial boundary with validated ACK history; retained loss boundaries remain strict, including after RTO and wrap.
//# Entry into fast recovery is only possible when the Cumulative Acknowledgment field covers more
//# than the state variable recover.
fn newreno_initial_boundary_and_loss_epoch_are_distinct() {
    for iss in [100, u32::MAX - 1, u32::MAX] {
        for algorithm in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
            let cfg = ConnectionConfig {
                recovery_algorithm: algorithm,
                ..config(128, 4)
            };
            let (mut a, _) = pair(cfg, iss);
            // Explicit unknown-history controller control. Real wire
            // handshakes are covered by the initial heuristic regressions.
            a.congestion = Congestion::new(4, algorithm, a.config.initial_window, Seq(iss));
            assert_eq!(a.congestion.ssthresh(), 0x7fff_ffff);
            a.write(&[1; 32]).unwrap();
            for _ in 0..4 {
                packet(&mut a, 40);
            }
            let base = a.snd_una;
            let seq = a.receive.next();
            for _ in 0..3 {
                inject(&mut a, 50, seq, base, ACK, 128, b"");
            }
            assert_eq!(a.retx_pending, algorithm == RecoveryAlgorithm::Reno);
            if algorithm == RecoveryAlgorithm::Reno {
                continue;
            }
            assert_eq!(a.congestion.ssthresh(), 0x7fff_ffff);
            // One data byte beyond ISS is enough; the SYN ACK alone was not.
            inject(&mut a, 60, seq, base.wrapping_add(1), ACK, 128, b"");
            for _ in 0..3 {
                inject(&mut a, 70, seq, base.wrapping_add(1), ACK, 128, b"");
            }
            assert!(a.retx_pending);
            assert_eq!(a.congestion.ssthresh(), 8);
            let end = a.snd_nxt;
            packet(&mut a, 80);
            inject(&mut a, 90, seq, end, ACK, 128, b"");
            assert_eq!(a.congestion.cwnd(), 8);
            for _ in 0..2 {
                packet(&mut a, 100);
            }
            let threshold = a.congestion.ssthresh();
            for _ in 0..3 {
                inject(&mut a, 110, seq, end, ACK, 128, b"");
            }
            assert!(!a.retx_pending); // Loss-epoch equality remains guarded.
            assert_eq!(a.congestion.ssthresh(), threshold);
            let deadline = a.rto_deadline.unwrap();
            a.timeout(deadline).unwrap();
            packet(&mut a, deadline);
            let threshold = a.congestion.ssthresh();
            for _ in 0..3 {
                inject(&mut a, deadline + 1, seq, end, ACK, 128, b"");
            }
            assert!(!a.retx_pending);
            assert_eq!(a.congestion.ssthresh(), threshold);
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6582#section-1
//= type=test
//= reason=Local receive-SACK permission is directional. Actual ACK scoreboard evidence selects RFC6675; absent evidence ordinary NewReno repairs two holes, for local sack=true/peer sack=false with RACK/PRR on or off. Limited Transmit still requires new SACK if permitted; existing first-flight directional SACK tests remain intact.
//# This document applies to TCP connections that are unable to use the TCP Selective
//# Acknowledgment (SACK) option, either because the option is not locally supported or because the
//# TCP peer did not indicate a willingness to use SACK.
fn unavailable_sack_feedback_uses_newreno_without_bilateral_permission() {
    for (rack, prr) in [(false, false), (true, false), (true, true)] {
        for iss in [100, u32::MAX - 20] {
            let cfg = ConnectionConfig {
                sack: true,
                rack,
                prr,
                initial_window: InitialWindow::Iw10,
                ..config(128, 4)
            };
            let mut a = Connection::active(tuple(), cfg.clone(), iss, 0).unwrap();
            let syn = packet(&mut a, 0);
            let syn = wire::parse(ip(tuple()), &syn).unwrap();
            let mut b = Connection::passive(
                reverse(tuple()),
                ConnectionConfig { sack: false, ..cfg },
                900,
                10,
                &syn,
            )
            .unwrap();
            deliver(&mut b, &mut a, 20);
            deliver(&mut a, &mut b, 30);
            assert!(a.sack_receive && !a.sack_send);
            a.write(b"x").unwrap();
            deliver(&mut a, &mut b, 31);
            b.immediate_ack();
            deliver(&mut b, &mut a, 32);
            a.write(&[0x55; 40]).unwrap();
            let mut flight = Vec::new();
            for _ in 0..10 {
                flight.push(packet(&mut a, 40));
            }
            let base = a.snd_una;
            let cwnd = a.congestion.cwnd();
            for (i, bytes) in flight.iter().enumerate().skip(1) {
                if i == 2 {
                    continue;
                } // Two losses in the same window.
                b.input(50, &wire::parse(ip(tuple()), bytes).unwrap())
                    .unwrap();
                let ack = deliver(&mut b, &mut a, 50);
                assert!(
                    wire::parse(ip(reverse(tuple())), &ack)
                        .unwrap()
                        .options
                        .sack_blocks
                        .iter()
                        .all(Option::is_none)
                );
                if a.duplicate_acks <= 2 {
                    assert!(!a.limited_pending); // No new SACK => no Limited Transmit.
                    assert_eq!(a.congestion.cwnd(), cwnd);
                }
            }
            assert!(a.congestion.in_fast_recovery());
            assert!(a.sack_recovery.is_none());
            assert_eq!(a.prr.is_some(), prr);
            let retry = deliver(&mut a, &mut b, 60);
            assert_eq!(
                wire::parse(ip(tuple()), &retry).unwrap().header.sequence,
                base.0
            );
            deliver(&mut b, &mut a, 61);
            assert!(a.congestion.in_fast_recovery() && a.retx_pending);
            let retry = deliver(&mut a, &mut b, 62);
            assert_eq!(
                wire::parse(ip(tuple()), &retry).unwrap().header.sequence,
                base.wrapping_add(8).0
            );
            deliver(&mut b, &mut a, 63);
            assert!(!a.congestion.in_recovery());
            assert_eq!(a.flight(), 0);
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc5681#section-4.3
//= type=test
//= reason=NewReno/SACK/RACK entries without PRR and covering ACK exits give cwnd2000 below ssthresh4000; first next MSS ACK leaves cwnd unchanged, second grows by one MSS; RTO restores slow start. No global PRR/half-flight claim.
//# has been successfully retransmitted, cwnd MUST be set to no more than ssthresh and congestion
//# avoidance MUST be used to further increase cwnd.
//= https://www.rfc-editor.org/rfc/rfc5681#section-4.3
//= type=test
//= reason=NewReno/SACK/RACK entries without PRR and covering ACK exits give cwnd2000 below ssthresh4000; first next MSS ACK leaves cwnd unchanged, second grows by one MSS; RTO restores slow start. No global PRR/half-flight claim.
//# Finally, after all loss in the given window of segments has been successfully retransmitted,
//# cwnd MUST be set to no more than ssthresh and congestion avoidance MUST be used to further
//# increase cwnd.
fn enhanced_exit_uses_avoidance_below_threshold_until_rto() {
    for mode in 0..3 {
        for iss in [100, u32::MAX - 20] {
            let cfg = ConnectionConfig {
                sack: mode != 0,
                rack: mode >= 2,
                prr: mode == 3,
                initial_window: InitialWindow::Iw10,
                ..config(8192, 1000)
            };
            let (mut a, _) = pair(cfg, iss);
            prime_newreno(&mut a);
            a.write(&[1; 8000]).unwrap();
            for _ in 0..8 {
                packet(&mut a, 100_000);
            }
            let base = a.snd_una;
            let end = a.snd_nxt;
            let seq = a.receive.next();
            if mode == 0 {
                for _ in 0..3 {
                    inject(&mut a, 200_000, seq, base, ACK, 8192, b"");
                }
            } else {
                inject_sack(
                    &mut a,
                    200_000,
                    seq,
                    base,
                    ACK,
                    8192,
                    b"",
                    &[(base.wrapping_add(1000).0, end.0)],
                );
                if a.sack_recovery.is_none() {
                    let deadline = a.rack.deadline.unwrap();
                    a.timeout(deadline).unwrap();
                }
                assert!(a.sack_recovery.is_some());
                assert_eq!(a.prr.is_some(), mode == 3);
            }
            let now = a.now + 1;
            packet(&mut a, now);
            inject(&mut a, now + 1, seq, end, ACK, 8192, b"");
            assert!(!a.congestion.in_recovery());
            assert_eq!((a.congestion.cwnd(), a.congestion.ssthresh()), (2000, 4000));
            a.write(&[2; 4000]).unwrap();
            for _ in 0..2 {
                packet(&mut a, now + 2);
            }
            // First MSS does not grow: slow start would have added 1000.
            inject(
                &mut a,
                now + 100_002,
                seq,
                end.wrapping_add(1000),
                ACK,
                8192,
                b"",
            );
            assert_eq!(a.congestion.cwnd(), 2000);
            inject(
                &mut a,
                now + 100_003,
                seq,
                end.wrapping_add(2000),
                ACK,
                8192,
                b"",
            );
            assert_eq!(a.congestion.cwnd(), 3000);
            for _ in 0..2 {
                packet(&mut a, now + 100_004);
            }
            let deadline = a.rto_deadline.unwrap();
            a.timeout(deadline).unwrap();
            assert_eq!(a.congestion.cwnd(), 1000);
            packet(&mut a, deadline);
            let una = a.snd_una;
            inject(
                &mut a,
                deadline + 1,
                seq,
                una.wrapping_add(1000),
                ACK,
                8192,
                b"",
            );
            assert_eq!(a.congestion.cwnd(), 2000); // RTO restores slow start.
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
//= type=test
//= reason=Actual bounded flight output followed one RTT later by delayed or one-byte divided ACKs: exact cumulative byte ledger and at most one SMSS increase for each of three flights, including wrap.
//# * SHOULD increment cwnd per equation (2) once per RTT
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
//= type=test
//= reason=Actual bounded flight output followed one RTT later by delayed or one-byte divided ACKs: exact cumulative byte ledger and at most one SMSS increase for each of three flights, including wrap.
//# * MUST NOT increment cwnd by more than SMSS bytes
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
//= type=test
//= reason=Actual bounded flight output followed one RTT later by delayed or one-byte divided ACKs: exact cumulative byte ledger and at most one SMSS increase for each of three flights, including wrap.
//# Note that during congestion avoidance, cwnd MUST NOT be
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
//= type=test
//= reason=Connection ACK parsing frees only new cumulative payload bytes, with one-byte division and delayed cumulative ACK byte ledger through wrap; data_flight_excludes_control_and_retains_sacked_payload separately excludes FIN ACK growth and SACK-only release.
//# where N is the number of previously unacknowledged bytes acknowledged in the incoming ACK.
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
//= type=test
//= reason=Actual bounded flight output followed one RTT later by delayed or one-byte divided ACKs: exact cumulative byte ledger and at most one SMSS increase for each of three flights, including wrap.
//# The RECOMMENDED way to increase cwnd during congestion avoidance is to count the number of
//# bytes that have been acknowledged by ACKs for new data. (A drawback of this implementation is
//# that it requires maintaining an additional state variable.) When the number of bytes
//# acknowledged reaches cwnd, then cwnd can be incremented by up to SMSS bytes. Note that during
//# congestion avoidance, cwnd MUST NOT be increased by more than SMSS bytes per RTT. This method
//# both allows TCPs to increase cwnd by one segment per RTT in the face of delayed ACKs and
//# provides robustness against ACK Division attacks.
fn congestion_avoidance_rtt_flights_resist_delayed_and_divided_acks() {
    for divided in [false, true] {
        let (mut a, _) = pair(config(32768, 1000), u32::MAX - 2000);
        prime_newreno(&mut a);
        // RTO supplies a real threshold, then slow start reaches equality.
        a.write(&[1; 4000]).unwrap();
        for _ in 0..4 {
            packet(&mut a, 100_000);
        }
        let d = a.rto_deadline.unwrap();
        a.timeout(d).unwrap();
        packet(&mut a, d);
        let seq = a.receive.next();
        let base = a.snd_una;
        inject(
            &mut a,
            d + 100_000,
            seq,
            base.wrapping_add(1000),
            ACK,
            32768,
            b"",
        );
        assert_eq!((a.congestion.cwnd(), a.congestion.ssthresh()), (2000, 2000));
        inject(
            &mut a,
            d + 100_001,
            seq,
            base.wrapping_add(4000),
            ACK,
            32768,
            b"",
        );
        let mut now = d + 100_002;
        for _ in 0..3 {
            let cwnd = a.congestion.cwnd();
            let before = a.acknowledged();
            a.write(&vec![2; cwnd as usize]).unwrap();
            let base = a.snd_una;
            let mut outputs = 0;
            while let Some(n) = a.transmit(now, &mut [0; 2048]).unwrap() {
                assert!(n > 20);
                outputs += 1;
            }
            assert_eq!(outputs, cwnd / 1000);
            assert_eq!(a.data_flight(), cwnd);
            assert_eq!(a.transmit(now + 99_999, &mut [0; 2048]), Ok(None));
            now += 100_000; // ACKs from this entire flight return one RTT later.
            let step = if divided { 1 } else { 2000 };
            let mut covered = 0;
            while covered < cwnd {
                covered = (covered + step).min(cwnd);
                inject(
                    &mut a,
                    now,
                    seq,
                    base.wrapping_add(covered),
                    ACK,
                    32768,
                    b"",
                );
                assert_eq!(a.acknowledged() - before, u64::from(covered));
                assert_eq!(a.data_flight(), cwnd - covered);
                assert_eq!(
                    a.congestion.cwnd(),
                    cwnd + if covered == cwnd { 1000 } else { 0 }
                );
            }
            now += 1;
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc5681#section-2
//= type=test
//= reason=Integrated outstanding-data, empty-payload, SYN/FIN, cumulative-equality and unchanged/nonzero-window predicate matrix; advancing and data-bearing ACKs reset duplicate count, and the third eligible duplicate repairs current UNA.
//# DUPLICATE ACKNOWLEDGMENT: An acknowledgment is considered a "duplicate" in the following
//# algorithms when (a) the receiver of the ACK has outstanding data, (b) the incoming
//# acknowledgment carries no data, (c) the SYN and FIN bits are both off, (d) the acknowledgment
//# number is equal to the greatest acknowledgment received on the given connection (TCP.UNA from
//# [RFC793]) and (e) the advertised window in the incoming acknowledgment equals the advertised
//# window in the last incoming acknowledgment.
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
//= type=test
//= reason=Integrated advancing/ineligible ACK reset trace denies premature retransmission and checks repair sequence at the third eligible duplicate after reset. Initial NewReno guard is separately asserted, not waived as a duplicate-eligibility exception.
//# The fast retransmit algorithm uses the arrival of 3 duplicate ACKs (as defined in section 2,
//# without any intervening ACKs which move SND.UNA) as an indication that a segment has been lost.
//# After receiving 3 duplicate ACKs, TCP performs a retransmission of what appears to be the
//# missing segment, without waiting for the retransmission timer to expire.
fn duplicate_ack_eligibility_and_intervening_advancement_reset() {
    for variant in 0..8 {
        let (mut a, _) = pair(config(128, 4), 100);
        prime_newreno(&mut a);
        if variant == 7 {
            a.shutdown().unwrap();
            packet(&mut a, 40);
            assert_eq!((a.flight(), a.data_flight()), (1, 0));
        } else if variant != 0 {
            a.write(&[1; 16]).unwrap();
            for _ in 0..4 {
                packet(&mut a, 40);
            }
        }
        let seq = a.receive.next();
        let una = a.snd_una;
        let (ack, flags, window, payload): (_, _, _, &[u8]) = match variant {
            1 => (una, ACK, 128, b"data"),
            2 => (una, ACK | SYN, 128, b""),
            3 => (una, ACK | FIN, 128, b""),
            4 => (una.wrapping_add(u32::MAX), ACK, 128, b""),
            5 => (una, ACK, 127, b""),
            6 => (una, ACK, 0, b""),
            _ => (una, ACK, 128, b""),
        };
        inject(&mut a, 50, seq, ack, flags, window, payload);
        assert_eq!(a.duplicate_acks, 0);
        assert!(!a.retx_pending);
    }
    let (mut a, _) = pair(config(128, 4), u32::MAX - 7);
    prime_newreno(&mut a);
    a.write(&[1; 16]).unwrap();
    for _ in 0..4 {
        packet(&mut a, 40);
    }
    let seq = a.receive.next();
    let una = a.snd_una;
    for _ in 0..2 {
        inject(&mut a, 50, seq, una, ACK, 128, b"");
    }
    inject(&mut a, 60, seq, una.wrapping_add(1), ACK, 128, b"");
    assert_eq!(a.duplicate_acks, 0);
    for _ in 0..2 {
        inject(&mut a, 70, seq, una.wrapping_add(1), ACK, 128, b"");
    }
    assert!(!a.retx_pending);
    // An ineligible data-bearing ACK resets the ordinary duplicate count.
    inject(&mut a, 71, seq, una.wrapping_add(1), ACK, 128, b"x");
    assert_eq!(a.duplicate_acks, 0);
    let seq = a.receive.next();
    for count in 1..=3 {
        inject(&mut a, 80, seq, una.wrapping_add(1), ACK, 128, b"");
        assert_eq!(a.retx_pending, count == 3);
    }
    let retry = packet(&mut a, 81);
    assert_eq!(
        wire::parse(ip(tuple()), &retry).unwrap().header.sequence,
        una.wrapping_add(1).0
    );
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
//= type=test
//= reason=Non-SACK and SACK receivers immediately emit cumulative ACKs after only part of an existing gap is filled, and after full fill; each input produces at most one committed ACK.
//# In addition, a TCP receiver SHOULD send an immediate ACK when the incoming segment fills in all
//# or part of a gap in the sequence space.
//= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
//= type=test
//= reason=Non-SACK and SACK receivers immediately emit cumulative ACKs after only part of an existing gap is filled, and after full fill; each input produces at most one committed ACK.
//# To provide feedback to senders recovering from losses, the receiver SHOULD send an immediate
//# ACK when it receives a data segment that fills in all or part of a gap in the sequence space.
fn partial_gap_ack_is_immediate_and_output_is_coalesced() {
    for sack in [false, true] {
        let (mut a, _) = pair(
            ConnectionConfig {
                sack,
                ..config(128, 8)
            },
            100,
        );
        let base = a.receive.next();
        let ack = a.snd_nxt;
        for (seq, data, immediate) in [
            (base.wrapping_add(8), &b"ijkl"[..], true),
            (base, &b"ab"[..], true),
            (base.wrapping_add(2), &b"cd"[..], true),
            (base.wrapping_add(4), &b"efgh"[..], true),
            (base.wrapping_add(12), &b"mn"[..], false),
        ] {
            inject(&mut a, 40, seq, ack, ACK, 128, data);
            assert_eq!(a.ack_pending, immediate);
            if !immediate {
                a.timeout(200_040).unwrap();
            }
            let now = a.now;
            let bytes = packet(&mut a, now);
            assert_eq!(
                wire::parse(ip(tuple()), &bytes)
                    .unwrap()
                    .header
                    .acknowledgment,
                a.receive.next().0
            );
            assert_eq!(a.transmit(now, &mut [0; 128]), Ok(None));
            a.timeout(now).unwrap();
            assert_eq!(a.transmit(now, &mut [0; 128]), Ok(None));
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc5681#section-2
//= type=test
//= reason=Separate payload FlightSize from transport sequence-space flight: SYN0/FIN0 payload accounting, SACK-only preservation, divided cumulative release and unchanged cwnd on FIN-only ACK are directly asserted through wrap. RFC9937 PRR snapshots unsacked payload and includes the triggering ACK delivery.
//# FLIGHT SIZE: The amount of data that has been sent but not yet cumulatively acknowledged.
fn data_flight_excludes_control_and_retains_sacked_payload() {
    let cfg = sack_config(128);
    let mut a = Connection::active(tuple(), cfg, u32::MAX, 0).unwrap();
    packet(&mut a, 0);
    assert_eq!((a.flight(), a.data_flight()), (1, 0)); // SYN
    let (mut a, _) = pair(
        ConnectionConfig {
            initial_window: InitialWindow::Iw10,
            ..sack_config(128)
        },
        u32::MAX - 100,
    );
    a.write(&[1; 512]).unwrap();
    a.shutdown().unwrap();
    for _ in 0..4 {
        packet(&mut a, 40);
    }
    let base = a.snd_una;
    let end = a.data_high();
    assert_eq!((a.flight(), a.data_flight()), (513, 512)); // FIN
    sack_ack(&mut a, 50, base, &[(base.wrapping_add(128).0, end.0)]);
    assert_eq!((a.flight(), a.data_flight(), a.send.len()), (513, 512, 512));
    assert_eq!(a.congestion.ssthresh(), 256); // SYN/FIN never inflate FlightSize.
    sack_ack(&mut a, 60, base.wrapping_add(1), &[]);
    assert_eq!((a.flight(), a.data_flight(), a.send.len()), (512, 511, 511));
    sack_ack(&mut a, 70, end, &[]);
    assert_eq!((a.flight(), a.data_flight()), (1, 0));
    let cwnd = a.congestion.cwnd();
    sack_ack(&mut a, 80, end.wrapping_add(1), &[]);
    assert_eq!((a.flight(), a.data_flight()), (0, 0));
    assert_eq!(a.congestion.cwnd(), cwnd); // FIN ACK is not new payload.
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
//= type=test
//= reason=Actual fourth eligible duplicate grants one fresh SMSS, with sequence and payload assertions; exhausted cwnd and rwnd independently deny further output.
//# When previously unsent data is available and the new value of cwnd and the receiver's
//# advertised window allow, a TCP SHOULD send 1*SMSS bytes of previously unsent data.
fn fourth_duplicate_grants_fresh_mss_only_with_both_windows() {
    for window in [20, 24, 128] {
        let (mut a, _) = primed_pair(config(128, 4), 100);
        a.write(&[1; 32]).unwrap();
        for _ in 0..4 {
            packet(&mut a, 40);
        }
        let seq = a.receive.next();
        let una = a.snd_una;
        let end = a.snd_nxt;
        inject(&mut a, 49, seq, una, ACK, window, b""); // Window update, not duplicate.
        for _ in 0..3 {
            inject(&mut a, 50, seq, una, ACK, window, b"");
        }
        packet(&mut a, 51); // Repair at UNA.
        let fresh = packet(&mut a, 51); // Initial recovery credit.
        assert_eq!(
            wire::parse(ip(tuple()), &fresh).unwrap().header.sequence,
            end.0
        );
        assert_eq!(a.flight(), 20);
        assert_eq!(a.transmit(51, &mut [0; 128]), Ok(None));
        inject(&mut a, 52, seq, una, ACK, window, b"");
        assert_eq!(a.congestion.cwnd(), 24);
        if window == 20 {
            assert_eq!(a.transmit(53, &mut [0; 128]), Ok(None));
        } else {
            let fresh = packet(&mut a, 53);
            let seg = wire::parse(ip(tuple()), &fresh).unwrap();
            assert_eq!(seg.header.sequence, end.wrapping_add(4).0);
            assert_eq!(seg.payload.len(), 4);
            assert_eq!(a.transmit(53, &mut [0; 128]), Ok(None));
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc5681#section-4.3
//= type=test
//= reason=Ordinary Reno/NewReno wire retransmissions, successive flights and wrap assert both window/threshold reductions; lost-fast-retransmission RTO uses bounded prior threshold rather than unchanged flight. Repeat RTO retains threshold. RACK lost-retransmission response is separately asserted in rack_replacement_loss_renews_response_without_cumulative_progress.
//# Loss in two successive windows of data, or the loss of a retransmission, should be taken as two
//# indications of congestion and, therefore, cwnd (and ssthresh) MUST be lowered twice in this
//# case.
fn successive_loss_windows_and_lost_fast_retransmission_reduce_twice() {
    for algorithm in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
        for lost_retransmission in [false, true] {
            for iss in [100, u32::MAX - 20] {
                let cfg = ConnectionConfig {
                    recovery_algorithm: algorithm,
                    initial_window: InitialWindow::Iw10,
                    ..config(128, 4)
                };
                let (mut a, _) = pair(cfg, iss);
                prime_newreno(&mut a);
                a.write(&[1; 40]).unwrap();
                for _ in 0..10 {
                    packet(&mut a, 40);
                }
                let seq = a.receive.next();
                let una = a.snd_una;
                let end = a.snd_nxt;
                for _ in 0..3 {
                    inject(&mut a, 50, seq, una, ACK, 128, b"");
                }
                assert_eq!((a.congestion.cwnd(), a.congestion.ssthresh()), (32, 20));
                packet(&mut a, 51); // Lost or repaired fast retransmission.
                if lost_retransmission {
                    let d = a.rto_deadline.unwrap();
                    a.timeout(d).unwrap();
                    assert_eq!((a.congestion.cwnd(), a.congestion.ssthresh()), (4, 10));
                    packet(&mut a, d);
                    let d = a.rto_deadline.unwrap();
                    a.timeout(d).unwrap();
                    assert_eq!(a.congestion.ssthresh(), 10); // Repeat RTO holds threshold.
                } else {
                    inject(&mut a, 60, seq, end, ACK, 128, b"");
                    let cwnd = a.congestion.cwnd();
                    assert_eq!(
                        cwnd,
                        if algorithm == RecoveryAlgorithm::Reno {
                            20
                        } else {
                            8
                        }
                    );
                    a.write(&[2; 40]).unwrap();
                    let mut remaining = cwnd;
                    while remaining != 0 {
                        packet(&mut a, 70);
                        remaining -= 4;
                    }
                    // First byte covers more than the retained loss epoch.
                    inject(&mut a, 80, seq, end.wrapping_add(1), ACK, 128, b"");
                    for _ in 0..3 {
                        inject(&mut a, 90, seq, end.wrapping_add(1), ACK, 128, b"");
                    }
                    assert!(a.retx_pending);
                    assert!(a.congestion.ssthresh() < 20);
                    assert!(a.congestion.cwnd() < 32);
                    assert_eq!(a.congestion.ssthresh(), ((cwnd - 1) / 2).max(8));
                }
            }
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
//= type=test
//= reason=Actual output counts after delayed data, piggyback reply and deadline/second-packet races; partial_gap_ack_is_immediate_and_output_is_coalesced covers gap and partial-fill immediate feedback. No receive-credit update is counted as a data ACK.
//# A TCP receiver MUST NOT generate more than one ACK for every incoming segment, other than to
//# update the offered window as the receiving application consumes new data (see [RFC813] and page
//# 42 of [RFC793]).
fn ack_output_coalesces_duplex_piggyback_and_timer_races() {
    for piggyback in [false, true] {
        let (mut a, _) = pair(config(128, 8), 100);
        let next = a.receive.next();
        let ack = a.snd_nxt;
        inject(&mut a, 40, next, ack, ACK, 128, b"ab");
        assert_eq!(a.ack_deadline, Some(200_040));
        if piggyback {
            a.write(b"reply").unwrap();
        } else {
            a.timeout(200_040).unwrap();
        }
        let now = a.now;
        let bytes = packet(&mut a, now);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes)
                .unwrap()
                .header
                .acknowledgment,
            next.wrapping_add(2).0
        );
        assert_eq!(a.transmit(now, &mut [0; 128]), Ok(None));
        a.timeout(200_040).unwrap();
        assert_eq!(a.transmit(200_040, &mut [0; 128]), Ok(None));
        // A second packet arriving exactly at the first packet's deadline
        // converts pending delayed feedback into one immediate ACK.
        let next = a.receive.next();
        let ack = a.snd_nxt;
        inject(&mut a, 200_050, next, ack, ACK, 128, b"cd");
        inject(&mut a, 400_050, next.wrapping_add(2), ack, ACK, 128, b"ef");
        a.timeout(400_050).unwrap();
        packet(&mut a, 400_050);
        assert_eq!(a.transmit(400_050, &mut [0; 128]), Ok(None));
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
//= type=test
//= reason=Positive-window ECE no-growth remains in ecn_duplicate_entry_below_threshold_and_covering_ack_exit. Narrow SHOULD departure: only zero-cwnd/zero-flight NewReno full exit restores RFC6582 option1 to avoid a permanent no-ACK/no-RTO deadlock, with an RTO-length ECN send pause. This test traces partial-zero, actual full covering ACK with ECE, queued write, denied pre-pause output, and fresh CWR data after pause.
//# The sending TCP SHOULD NOT increase the congestion window in response to the receipt of an ECN-Echo ACK packet.
fn newreno_partial_zero_full_ece_restarts_after_ecn_pause() {
    for iss in [100, u32::MAX - 20] {
        for ece in [false, true] {
            let cfg = ConnectionConfig {
                initial_window: InitialWindow::Iw10,
                ..config(128, 4)
            };
            let (mut a, mut b) = primed_pair(cfg, iss);
            a.write(&[0x55; 40]).unwrap();
            let mut flight = Vec::new();
            for _ in 0..10 {
                flight.push(packet(&mut a, 40));
            }
            for (count, bytes) in flight[1..9].iter().enumerate() {
                b.input(50, &wire::parse(ip(tuple()), bytes).unwrap())
                    .unwrap();
                let ack = packet(&mut b, 50);
                if count < 3 {
                    a.input(50, &wire::parse(ip(reverse(tuple())), &ack).unwrap())
                        .unwrap();
                }
            }
            deliver(&mut a, &mut b, 60);
            deliver(&mut b, &mut a, 61);
            assert_eq!((a.congestion.cwnd(), a.data_flight()), (0, 4));
            deliver(&mut a, &mut b, 62);
            b.timeout(200_062).unwrap();
            let ack = packet(&mut b, 200_062);
            let ack = wire::parse(ip(reverse(tuple())), &ack).unwrap();
            let end = Seq(ack.header.acknowledgment);
            assert_eq!(end, a.snd_nxt);
            let seq = Seq(ack.header.sequence);
            inject(
                &mut a,
                200_062,
                seq,
                end,
                ACK | if ece { ECE } else { 0 },
                ack.header.window,
                b"",
            );
            assert!(!a.congestion.in_recovery());
            assert_eq!(
                (a.congestion.cwnd(), a.congestion.ssthresh(), a.flight()),
                (8, 20, 0)
            );
            assert_eq!(a.rto_deadline, None);
            a.write(b"live").unwrap();
            let now = if ece {
                let pause = a.ecn_pause.unwrap();
                assert_eq!(a.transmit(pause - 1, &mut [0; 128]), Ok(None));
                assert_eq!(a.congestion.cwnd(), 8);
                a.timeout(pause).unwrap();
                pause
            } else {
                200_063
            };
            let fresh = deliver(&mut a, &mut b, now);
            let fresh = wire::parse(ip(tuple()), &fresh).unwrap();
            assert_eq!(fresh.header.sequence, end.0);
            assert_eq!(fresh.payload, b"live");
            assert_ne!(fresh.header.flags & CWR, 0);
        }
    }
}

fn opening_for_close(cfg: ConnectionConfig, iss: u32, simultaneous: bool) -> (Connection, Vec<u8>) {
    let mut peer = Connection::active(reverse(tuple()), cfg.clone(), 900, 0).unwrap();
    let bytes = packet(&mut peer, 0);
    let syn = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
    let connection = if simultaneous {
        let mut connection = Connection::active(tuple(), cfg, iss, 0).unwrap();
        packet(&mut connection, 0);
        connection.input(10, &syn).unwrap();
        connection
    } else {
        Connection::passive(tuple(), cfg, iss, 10, &syn).unwrap()
    };
    (connection, bytes)
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
//= type=test
//= reason=on_timeout stores exclusive highest_sent and clears recovery; timeout_marker_boundaries_and_wrap directly asserts active flag clear and marker replacement. newreno_partial_ack_wire_timer_and_exit_boundaries asserts active wire RTO at exact expiry.
//# After a retransmit timeout, record the highest sequence number transmitted in the variable recover, and exit the fast recovery procedure if applicable.
//= https://www.rfc-editor.org/rfc/rfc6582#section-3.1
//= type=test
//= reason=No-SACK NewReno wire entry, partial-ACK continuation, full-ACK exit and active-recovery RTO exit are asserted by newreno_partial_ack_wire_timer_and_exit_boundaries. timeout_marker_boundaries_and_wrap asserts timeout marker replacement; initial guard and strict admission are asserted by newreno_initial_boundary_and_loss_epoch_are_distinct.
//# The NewReno modification applies to the fast recovery procedure that begins when three duplicate ACKs are received and ends when either a retransmission timeout occurs or an ACK arrives that acknowledges all of the data up to and including the data that was outstanding when the fast recovery procedure began.
//= https://www.rfc-editor.org/rfc/rfc6582#section-5
//= type=test
//= reason=newreno_partial_ack_wire_timer_and_exit_boundaries asserts immediate ACK pending and no delayed deadline for OOO pure data and hole-fill partial ACKs, with other pure-data holes still outstanding.
//# [RFC5681] specifies that "Out-of-order data segments SHOULD be acknowledged
//# immediately, in order to accelerate loss recovery".
//= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
//= type=test
//= reason=NewReno partial ACK schedules retx_pending; committed output starts at snd_una. newreno_partial_ack_wire_timer_and_exit_boundaries asserts each missing sequence/payload, continued recovery and failed-output rollback, including wrap.
//# In this case, retransmit the first unacknowledged segment.
//= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
//= type=test
//= reason=No-SACK IW10 wire trace: partial ACK head retransmission, pure-data hole fills, first/later advancing ACK timer restart, stale duplicate nonrestart, output rollback, full-ACK zero/nonzero flight burst cap and active recovery RTO; controller timeout_marker_boundaries_and_wrap asserts replaced exclusive marker.
//# For the first partial ACK that arrives during fast recovery, also reset the
//# retransmit timer.
//= https://www.rfc-editor.org/rfc/rfc6582#section-5
//= type=test
//= reason=newreno_partial_ack_wire_timer_and_exit_boundaries receives pure-data hole fills while another hole remains, asserts ack_pending and ack_deadline=None despite delayed ACK enabled, and immediately emits cumulative partial ACKs.
//# Echoing [RFC5681], our recommendation is that the data receiver send an
//# immediate acknowledgment for an out-of-order segment, even when that
//# out-of-order segment fills a hole in the buffer.
//= https://www.rfc-editor.org/rfc/rfc6582#section-6
//= type=test
//= reason=Selected full-ACK option1 cwnd=min(ssthresh,max(FlightSize,SMSS)+SMSS). Lost-duplicate-ACK wire trace newreno_partial_ack_wire_timer_and_exit_boundaries polls to exhaustion: two fresh MSS at zero flight, one at residual one-MSS flight.
//# In Section 3.2, step 3 above, it is noted that implementations should take
//# measures to avoid a possible burst of data when leaving fast recovery, in case
//# the amount of new data that the sender is eligible to send due to the new value
//# of the congestion window is large.
//= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
//= type=test
//= reason=newreno_partial_ack_wire_timer_and_exit_boundaries asserts no fresh output with flight>=cwnd, one fresh MSS with credit, rwnd/SWS suppression then permission, MSS payload bounds and failed-output rollback.
//# Send a new segment if permitted by the new value of cwnd.
//= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
//= type=test
//= reason=No-SACK NewReno RFC5681 section3.2 layer: duplicate_ack_eligibility_and_intervening_advancement_reset, limited_transmit_is_one_packet_per_duplicate_and_excluded_from_threshold, fourth_duplicate_grants_fresh_mss_only_with_both_windows and wire partial/exit traces assert eligibility, exclusions, inflation and bounded output. Initial guard and zero partial deflation have dedicated tests; this is not a global enhanced-PRR/half-flight assertion.
//# The procedures specified in Section 3.2 of [RFC5681] are followed, with the modifications
//# listed below.
fn newreno_partial_ack_wire_timer_and_exit_boundaries() {
    for iss in [100, u32::MAX - 20] {
        for (send_credit, limit_window, timeout_exit) in [
            (false, false, false),
            (true, false, false),
            (true, true, false),
            (false, false, true),
        ] {
            let fresh_bytes = if send_credit { 4 } else { 0 };
            let cfg = ConnectionConfig {
                initial_window: InitialWindow::Iw10,
                ..config(128, 4)
            };
            let (mut a, mut b) = primed_pair(cfg, iss);
            a.set_nagle(false);
            let data: Vec<u8> = (0..80).collect();
            a.write(&data).unwrap();
            let base = a.snd_una;
            let mut flight = Vec::new();
            for _ in 0..10 {
                flight.push(packet(&mut a, 40));
            }
            let original_end = a.snd_nxt;
            for i in [1, 3, 5, 7, 8, 9] {
                let seg = wire::parse(ip(tuple()), &flight[i]).unwrap();
                b.input(50, &seg).unwrap();
                assert!(b.ack_pending);
                assert_eq!(b.ack_deadline, None);
                let ack = packet(&mut b, 50);
                if i <= 5 {
                    a.input(50, &wire::parse(ip(reverse(tuple())), &ack).unwrap())
                        .unwrap();
                } // Later duplicate ACKs are lost: no artificial inflation.
            }
            assert!(a.congestion.in_recovery());
            assert_eq!((a.flight(), a.congestion.cwnd()), (40, 32));
            if timeout_exit {
                let bytes = packet(&mut a, 60); // Fast retransmit is lost.
                assert_eq!(
                    wire::parse(ip(tuple()), &bytes).unwrap().payload,
                    &data[..4]
                );
                let deadline = a.rto_deadline.unwrap();
                let next = a.receive.next();
                let una = a.snd_una;
                inject(&mut a, 61, next, una, ACK, 128, b"");
                assert_eq!(a.rto_deadline, Some(deadline));
                a.timeout(deadline - 1).unwrap();
                assert!(a.congestion.in_recovery());
                assert_eq!(a.transmit(deadline - 1, &mut [0; 128]), Ok(None));
                a.timeout(deadline).unwrap();
                assert!(!a.congestion.in_recovery());
                assert_eq!(a.congestion.cwnd(), 4);
                assert_eq!(
                    a.transmit(deadline, &mut [0; 19]),
                    Err(Error::OutputTooSmall)
                );
                assert!(a.retx_pending);
                let bytes = packet(&mut a, deadline);
                let seg = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(seg.header.sequence, base.0);
                assert_eq!(seg.payload, &data[..4]);
                assert_eq!(a.snd_nxt, original_end);
                assert_eq!(a.rto_deadline, Some(deadline + a.rto()));
                continue;
            }
            for (index, now) in [(0, 60), (2, 80), (4, 100), (6, 120)] {
                let before = (a.snd_nxt, a.rto_deadline, a.retx_pending, a.now);
                assert_eq!(a.transmit(now, &mut [0; 19]), Err(Error::OutputTooSmall));
                assert_eq!((a.snd_nxt, a.rto_deadline, a.retx_pending, a.now), before);
                let bytes = deliver(&mut a, &mut b, now);
                let seg = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(seg.header.sequence, base.wrapping_add(index * 4).0);
                assert_eq!(
                    seg.payload,
                    &data[index as usize * 4..index as usize * 4 + 4]
                );
                assert_eq!(a.rto_deadline, Some(now + a.rto()));
                if index == 2 || index == 4 {
                    assert!(a.flight() >= a.congestion.cwnd());
                    assert_eq!(a.transmit(now, &mut [0; 128]), Ok(None));
                }
                if index == 6 && fresh_bytes != 0 {
                    if limit_window {
                        let next = a.receive.next();
                        let una = a.snd_una;
                        inject(&mut a, now, next, una, ACK, 18, b"");
                        assert_eq!(a.snd_wnd, 18); // SWS avoids a two-byte fragment.
                        assert_eq!(a.transmit(now, &mut [0; 128]), Ok(None));
                        inject(&mut a, now, next, una, ACK, 20, b"");
                        assert_eq!(a.snd_wnd, 20);
                    }
                    let deadline = a.rto_deadline;
                    let high = a.snd_nxt;
                    assert_eq!(a.transmit(now, &mut [0; 19]), Err(Error::OutputTooSmall));
                    assert_eq!((a.snd_nxt, a.rto_deadline), (high, deadline));
                    let fresh = packet(&mut a, now);
                    let seg = wire::parse(ip(tuple()), &fresh).unwrap();
                    assert_eq!(seg.header.sequence, original_end.0);
                    assert_eq!(seg.payload, &data[40..40 + fresh_bytes]);
                    assert_eq!(a.rto_deadline, deadline);
                }
                assert!(b.ack_pending);
                assert_eq!(b.ack_deadline, None); // Pure-data hole fill, delayed ACK enabled.
                let ack_bytes = deliver(&mut b, &mut a, now + 1);
                let ack = wire::parse(ip(reverse(tuple())), &ack_bytes).unwrap();
                let covered = if index == 6 { 40 } else { index * 4 + 8 };
                assert_eq!(ack.header.acknowledgment, base.wrapping_add(covered).0);
                assert_eq!(a.acknowledged(), 1 + covered as u64);
                if index != 6 {
                    assert_eq!(a.flight(), 40 - covered);
                    assert_eq!(a.congestion.cwnd(), 32 - covered + (index / 2 + 1) * 4);
                    assert!(a.congestion.in_recovery());
                    assert_eq!(a.rto_deadline, Some(now + 1 + a.rto()));
                    let deadline = a.rto_deadline;
                    let next = a.receive.next();
                    let una = a.snd_una;
                    inject(
                        &mut a,
                        now + 2,
                        next,
                        una.wrapping_add(u32::MAX),
                        ACK,
                        128,
                        b"",
                    );
                    assert_eq!(a.rto_deadline, deadline);
                }
            }
            assert!(!a.congestion.in_recovery());
            assert_eq!(a.flight(), fresh_bytes as u32);
            assert_eq!(a.congestion.cwnd(), 8);
            let deadline = a.rto_deadline;
            let next = a.receive.next();
            let una = a.snd_una;
            inject(&mut a, 125, next, una, ACK, 128, b"");
            assert_eq!(a.rto_deadline, deadline);
            let mut sent = 0;
            let mut out = [0; 128];
            let mut next_data = 40 + fresh_bytes;
            while let Some(n) = a.transmit(130, &mut out).unwrap() {
                let seg = wire::parse(ip(tuple()), &out[..n]).unwrap();
                assert_eq!(seg.header.sequence, base.wrapping_add(next_data as u32).0);
                assert_eq!(seg.payload, &data[next_data..next_data + 4]);
                next_data += 4;
                sent += 1;
            }
            assert_eq!(sent, if fresh_bytes == 4 { 1 } else { 2 });
            assert_eq!(a.flight(), 8);
        }
    }
}

#[test]
// Lost ACKs can validly deflate cwnd to zero; hole retransmission must
// still progress independently of fresh-data credit.
//= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
//= type=test
//= reason=Actual ten-segment loss trace with lost duplicate ACKs yields literal32-36+4=0, not an MSS floor. Partial hole repair ignores fresh-data credit; lost repair RTO restores one-MSS progress. Controller signed-expression vectors cover positive remainder and negative saturation. newreno_partial_zero_full_ece_restarts_after_ecn_pause covers zero/full-ECE liveness with an explicitly scoped RFC3168 SHOULD departure.
//# Deflate the congestion window by the amount of new data acknowledged by the Cumulative
//# Acknowledgment field. If the partial ACK acknowledges at least one SMSS of new data, then add
//# back SMSS bytes to the congestion window.
fn newreno_nearly_full_partial_ack_zero_window_progress() {
    for iss in [100, u32::MAX - 20] {
        for delivered_duplicates in [3, 8] {
            let cfg = ConnectionConfig {
                initial_window: InitialWindow::Iw10,
                ..config(128, 4)
            };
            let (mut a, mut b) = primed_pair(cfg, iss);
            a.write(&[0x55; 40]).unwrap();
            let mut flight = Vec::new();
            for _ in 0..10 {
                flight.push(packet(&mut a, 40));
            }
            for (count, bytes) in flight[1..9].iter().enumerate() {
                b.input(50, &wire::parse(ip(tuple()), bytes).unwrap())
                    .unwrap();
                let ack = packet(&mut b, 50);
                if count < delivered_duplicates {
                    a.input(50, &wire::parse(ip(reverse(tuple())), &ack).unwrap())
                        .unwrap();
                }
            }
            assert_eq!(a.flight(), 40);
            let cwnd = a.congestion.cwnd();
            assert_eq!(cwnd, if delivered_duplicates == 3 { 32 } else { 52 });
            deliver(&mut a, &mut b, 60);
            deliver(&mut b, &mut a, 61);
            assert_eq!(a.acknowledged(), 37);
            assert_eq!(a.flight(), 4);
            assert!(a.congestion.in_recovery());
            assert_eq!(
                a.congestion.cwnd(),
                if delivered_duplicates == 3 { 0 } else { 20 }
            );
            // Literal cwnd - newly_acked + SMSS is zero in the lost-ACK case.
            if delivered_duplicates == 3 {
                assert_eq!(cwnd as i64 - 36 + 4, 0);
            }
            if delivered_duplicates == 3 {
                let bytes = packet(&mut a, 62); // The hole repair is lost.
                assert_eq!(
                    wire::parse(ip(tuple()), &bytes).unwrap().payload,
                    &[0x55; 4]
                );
                assert_eq!(a.congestion.cwnd(), 0);
                assert_eq!(a.transmit(63, &mut [0; 128]), Ok(None));
                let deadline = a.rto_deadline.unwrap();
                a.timeout(deadline).unwrap();
                assert!(!a.congestion.in_recovery());
                assert_eq!(a.congestion.cwnd(), 4);
                deliver(&mut a, &mut b, deadline);
                b.timeout(deadline + 200_000).unwrap();
                deliver(&mut b, &mut a, deadline + 200_000);
                assert_eq!(a.flight(), 0);
                continue;
            }
            let bytes = deliver(&mut a, &mut b, 62);
            assert_eq!(
                wire::parse(ip(tuple()), &bytes).unwrap().payload,
                &[0x55; 4]
            );
            b.timeout(200_062).unwrap();
            deliver(&mut b, &mut a, 200_062);
            assert!(!a.congestion.in_recovery());
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6298#section-5
//= type=test
//= reason=Passive and simultaneous-open SYN-ACK RTO, wrap and failed output; first data exactly now+3s, fresh unambiguous data sample releases guard and next output arms now+1s. Active role separately covered by tlp_small_rto_floor_preserves_initial_and_syn_timeout_guard.
//# (5.7) If the timer expires awaiting the ACK of a SYN segment and the TCP
//# implementation is using an RTO less than 3 seconds, the RTO MUST be
//# re-initialized to 3 seconds when data transmission begins (i.e., after the
//# three-way handshake completes).
fn synack_timeout_roles_first_data_and_fresh_sample_guard() {
    for simultaneous in [false, true] {
        for iss in [100, u32::MAX] {
            let (mut a, _) = opening_for_close(config(64, 8), iss, simultaneous);
            let lost = packet(&mut a, 20);
            assert_eq!(
                wire::parse(ip(tuple()), &lost).unwrap().header.flags & (SYN | ACK),
                SYN | ACK
            );
            let deadline = 1_000_020;
            assert_eq!(a.rto_deadline, Some(deadline));
            a.timeout(deadline - 1).unwrap();
            assert_eq!(a.transmit(deadline - 1, &mut [0; 128]), Ok(None));
            a.timeout(deadline).unwrap();
            let before = (a.snd_nxt, a.rto_deadline, a.syn_pending, a.now);
            assert_eq!(
                a.transmit(deadline, &mut [0; 19]),
                Err(Error::OutputTooSmall)
            );
            assert_eq!((a.snd_nxt, a.rto_deadline, a.syn_pending, a.now), before);
            packet(&mut a, deadline);
            assert!(!a.syn_delivered);
            assert_eq!(a.rto(), 2_000_000);
            assert_eq!(a.rto_deadline, Some(3_000_020));
            let next = a.receive.next();
            inject(
                &mut a,
                deadline + 10,
                next,
                Seq(iss).wrapping_add(1),
                ACK,
                64,
                b"",
            );
            assert_eq!(a.state(), State::Established);
            assert!(a.syn_timed_out);
            assert_eq!(a.rto(), 3_000_000);
            a.write(b"abcdefgh").unwrap();
            let bytes = packet(&mut a, deadline + 20);
            assert_eq!(
                wire::parse(ip(tuple()), &bytes).unwrap().payload,
                b"abcdefgh"
            );
            assert_eq!(a.rto_deadline, Some(deadline + 20 + 3_000_000));
            let end = a.snd_nxt;
            inject(&mut a, deadline + 100_020, next, end, ACK, 64, b"");
            assert!(!a.syn_timed_out);
            assert_eq!(a.rto(), 1_000_000);
            assert_eq!(a.rto_deadline, None);
            a.write(b"fresh").unwrap();
            packet(&mut a, deadline + 100_030);
            assert_eq!(a.rto_deadline, Some(deadline + 1_100_030));
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.4
//= type=test
//= reason=Passive and simultaneous CLOSE before/after SYN-ACK, transactional output, wrap, and separate SYN/FIN ACK boundaries.
//# If no SENDs have been issued and there is no pending data to send, then form a
//# FIN segment and send it, and enter FIN-WAIT-1 state; otherwise, queue for
//# processing after entering ESTABLISHED state.
fn syn_received_close_commits_early_fin_without_completing_handshake() {
    for simultaneous in [false, true] {
        for synack_sent in [false, true] {
            for iss in [100, u32::MAX - 1, u32::MAX] {
                for both in [false, true] {
                    let (mut a, _) = opening_for_close(config(64, 8), iss, simultaneous);
                    if synack_sent {
                        packet(&mut a, 20);
                    }
                    a.shutdown().unwrap();
                    assert!(!a.handshake_complete());
                    assert_eq!(a.state(), State::SynReceived);
                    if !synack_sent {
                        let before = (a.now, a.snd_nxt, a.syn_pending, a.rto_deadline);
                        assert_eq!(a.transmit(20, &mut [0; 19]), Err(Error::OutputTooSmall));
                        assert_eq!((a.now, a.snd_nxt, a.syn_pending, a.rto_deadline), before);
                        let bytes = packet(&mut a, 20);
                        let synack = wire::parse(ip(tuple()), &bytes).unwrap();
                        assert_eq!(synack.header.flags & (SYN | ACK | FIN), SYN | ACK);
                        assert_eq!(synack.header.sequence, iss);
                        assert!(synack.payload.is_empty());
                    }
                    let before = (
                        a.now,
                        a.snd_nxt,
                        a.state,
                        a.fin_sequence,
                        a.rto_deadline,
                        a.sample,
                    );
                    assert_eq!(a.transmit(30, &mut [0; 19]), Err(Error::OutputTooSmall));
                    assert_eq!(
                        (
                            a.now,
                            a.snd_nxt,
                            a.state,
                            a.fin_sequence,
                            a.rto_deadline,
                            a.sample
                        ),
                        before
                    );
                    let bytes = packet(&mut a, 30);
                    let fin = wire::parse(ip(tuple()), &bytes).unwrap();
                    assert_eq!(fin.header.flags & (SYN | ACK | FIN), ACK | FIN);
                    assert_eq!(fin.header.sequence, iss.wrapping_add(1));
                    assert!(fin.payload.is_empty());
                    assert_eq!(a.state(), State::FinWait1);
                    assert_eq!(a.snd_nxt, Seq(iss.wrapping_add(2)));
                    assert!(!a.handshake_complete());
                    assert!(!a.synchronized());
                    assert!(!a.events_pending());
                    assert_eq!(a.read(&mut [0; 1]), Err(Error::WouldBlock));
                    assert_eq!(a.transmit(31, &mut [0; 64]), Ok(None));
                    // Old and future ACKs cannot complete the handshake.
                    inject(&mut a, 32, Seq(901), Seq(iss), ACK, 64, b"bad");
                    assert!(!a.handshake_complete());
                    packet(&mut a, 32); // Reset for unacceptable handshake ACK.
                    inject(
                        &mut a,
                        33,
                        Seq(901),
                        Seq(iss.wrapping_add(3)),
                        ACK,
                        64,
                        b"bad",
                    );
                    assert!(!a.handshake_complete());
                    packet(&mut a, 33); // Challenge ACK for unsent sequence space.
                    let ack = Seq(iss.wrapping_add(if both { 2 } else { 1 }));
                    inject(&mut a, 40, Seq(901), ack, ACK, 64, b"");
                    assert!(a.handshake_complete());
                    assert!(a.synchronized());
                    assert_eq!(
                        a.state(),
                        if both {
                            State::FinWait2
                        } else {
                            State::FinWait1
                        }
                    );
                    assert_eq!(a.acknowledged(), 0);
                    let events = a.take_events();
                    assert!(events.connected);
                    assert!(!events.writable);
                    assert_eq!(events.acknowledged, None);
                    if !both {
                        inject(&mut a, 50, Seq(901), Seq(iss.wrapping_add(2)), ACK, 64, b"");
                        assert_eq!(a.state(), State::FinWait2);
                        assert!(!a.take_events().connected);
                    }
                    assert!(a.handshake_complete());
                    a.abort();
                    assert!(a.reset_pending());
                    assert!(a.handshake_complete());
                    packet(&mut a, 60);
                    assert!(!a.reset_pending());
                }
            }
        }
    }
}

#[test]
fn syn_received_close_peer_fin_completes_handshake_and_read_half() {
    for iss in [100, u32::MAX] {
        for simultaneous in [false, true] {
            for acknowledges_fin in [false, true] {
                let (mut a, _) = opening_for_close(config(64, 8), iss, simultaneous);
                a.shutdown().unwrap();
                packet(&mut a, 20); // SYN-ACK.
                packet(&mut a, 30); // Our FIN, handshake still pending.
                assert!(!a.handshake_complete());
                inject(
                    &mut a,
                    40,
                    Seq(901),
                    Seq(iss.wrapping_add(if acknowledges_fin { 2 } else { 1 })),
                    ACK | FIN,
                    64,
                    b"reply",
                );
                assert!(a.handshake_complete());
                assert_eq!(
                    a.state(),
                    if acknowledges_fin {
                        State::TimeWait
                    } else {
                        State::Closing
                    }
                );
                assert_eq!(a.acknowledged(), 0);
                let events = a.take_events();
                assert!(events.connected && events.half_closed);
                let mut reply = [0; 8];
                assert_eq!(a.read(&mut reply), Ok(5));
                assert_eq!(&reply[..5], b"reply");
                assert_eq!(a.read(&mut reply), Ok(0));
                let bytes = packet(&mut a, 41);
                let ack = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(ack.header.flags & (ACK | SYN | FIN), ACK);
                assert_eq!(ack.header.sequence, iss.wrapping_add(2));
                assert_eq!(ack.header.acknowledgment, 907);
                if !acknowledges_fin {
                    inject(&mut a, 50, Seq(907), Seq(iss.wrapping_add(2)), ACK, 64, b"");
                    assert_eq!(a.state(), State::TimeWait);
                    assert!(!a.take_events().connected);
                }
                assert!(a.time_wait_valid(50));
            }
        }
    }
}

#[test]
fn syn_received_close_send_history_survives_flush_and_empty_send() {
    for simultaneous in [false, true] {
        for mode in 0..3 {
            let (mut a, _) = opening_for_close(config(64, 8), 100, simultaneous);
            match mode {
                0 => assert_eq!(a.write(b"queued"), Ok(6)),
                1 => {
                    assert_eq!(a.write(b"discard"), Ok(7));
                    a.snd_wnd = 0;
                    assert_eq!(a.flush(), Ok(7));
                }
                _ => assert_eq!(a.write(b""), Ok(0)),
            }
            assert!(a.send_issued);
            a.shutdown().unwrap();
            let bytes = packet(&mut a, 20);
            assert!(wire::parse(ip(tuple()), &bytes).unwrap().payload.is_empty());
            assert_eq!(a.transmit(30, &mut [0; 64]), Ok(None));
            assert_eq!(a.state(), State::SynReceived);
            inject(&mut a, 40, Seq(901), Seq(101), ACK, 64, b"");
            let bytes = packet(&mut a, 50);
            let fin = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(
                fin.payload,
                if mode == 0 { b"queued".as_slice() } else { b"" }
            );
            assert_eq!(fin.header.flags & FIN, FIN);
            assert_eq!(fin.header.sequence, 101);
            assert_eq!(a.fin_sequence, Some(Seq(if mode == 0 { 107 } else { 101 })));
        }
    }
    // A SEND issued in SYN-SENT also rules out the no-SEND branch after
    // simultaneous open, even if FLUSH leaves no queued bytes.
    let (_, syn_bytes) = opening_for_close(config(64, 8), 100, false);
    let mut a = Connection::active(tuple(), config(64, 8), 100, 0).unwrap();
    a.write(b"prior").unwrap();
    packet(&mut a, 0);
    a.input(10, &wire::parse(ip(reverse(tuple())), &syn_bytes).unwrap())
        .unwrap();
    a.snd_wnd = 0;
    assert_eq!(a.flush(), Ok(5));
    a.snd_wnd = 64;
    a.shutdown().unwrap();
    packet(&mut a, 20);
    assert_eq!(a.transmit(30, &mut [0; 64]), Ok(None));
    assert_eq!(a.state(), State::SynReceived);
    inject(&mut a, 40, Seq(901), Seq(101), ACK, 64, b"");
    packet(&mut a, 50);
    assert_eq!(a.state(), State::FinWait1);

    let (mut a, _) = opening_for_close(config(64, 8), 100, false);
    a.send.write(&[0; 64]); // Exhaust storage without a successful application SEND.
    assert_eq!(a.write(b"failed"), Err(Error::WouldBlock));
    assert!(!a.send_issued);
    a.snd_wnd = 0;
    a.flush().unwrap();
    a.snd_wnd = 64;
    a.shutdown().unwrap();
    assert_eq!(a.write(b"late"), Err(Error::InvalidState));
    assert!(!a.send_issued);
    packet(&mut a, 20);
    packet(&mut a, 30);
    assert_eq!(a.state(), State::FinWait1);
}

#[test]
fn early_fin_retransmits_syn_until_ack_then_retransmits_fin() {
    for simultaneous in [false, true] {
        let mut cfg = config(64, 8);
        cfg.user_timeout_us = 1_000_000;
        let (mut a, syn_bytes) = opening_for_close(cfg, u32::MAX, simultaneous);
        a.set_application_timeout(Some(200_000_000)).unwrap();
        a.shutdown().unwrap();
        packet(&mut a, 20); // Lost SYN-ACK.
        packet(&mut a, 30); // FIN also lost.
        assert_eq!(a.user_deadline(), Some(a.progress_at + 180_000_000));
        assert_eq!(
            a.application_deadline(),
            Some(a.application_progress_at + 200_000_000)
        );
        for duplicate in [true, false] {
            let now = if duplicate {
                a.input(40, &wire::parse(ip(reverse(tuple())), &syn_bytes).unwrap())
                    .unwrap();
                40
            } else {
                let end = a.rto_deadline.unwrap();
                a.timeout(end).unwrap();
                end
            };
            assert!(a.syn_pending);
            assert!(!a.handshake_complete());
            let before = (a.now, a.snd_nxt, a.syn_pending, a.rto_deadline);
            assert_eq!(a.transmit(now, &mut [0; 19]), Err(Error::OutputTooSmall));
            assert_eq!((a.now, a.snd_nxt, a.syn_pending, a.rto_deadline), before);
            let bytes = packet(&mut a, now);
            let synack = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(synack.header.flags & (SYN | ACK | FIN), SYN | ACK);
            assert_eq!(synack.header.sequence, u32::MAX);
            assert!(synack.payload.is_empty());
            assert_eq!(a.snd_nxt, Seq(1));
            assert_eq!(a.state(), State::FinWait1);
            assert!(a.rto_deadline.is_some());
        }
        let now = a.now + 10;
        inject(&mut a, now, Seq(901), Seq(0), ACK, 64, b"");
        assert!(a.handshake_complete());
        assert_eq!(a.state(), State::FinWait1);
        assert_eq!(a.acknowledged(), 0);
        assert!(a.syn_delivered && a.syn_timed_out);
        assert_eq!(a.rto(), 3_000_000);
        assert_eq!(a.rto_deadline, Some(now + 3_000_000));
        assert_eq!(a.user_deadline(), Some(now + 1_000_000));
        // Lengthen post-handshake R2 so this test can service the backed-off RTO.
        a.config.user_timeout_us = 300_000_000;
        let end = a.rto_deadline.unwrap();
        a.timeout(end).unwrap();
        assert!(!a.syn_pending);
        let bytes = packet(&mut a, end);
        let fin = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(fin.header.flags & (SYN | ACK | FIN), ACK | FIN);
        assert_eq!(fin.header.sequence, 0);
        assert!(fin.payload.is_empty());
        inject(&mut a, end + 10, Seq(901), Seq(1), ACK, 64, b"");
        assert_eq!(a.state(), State::FinWait2);
    }
    let (mut a, _) = opening_for_close(config(64, 8), 100, false);
    a.shutdown().unwrap();
    packet(&mut a, 20);
    packet(&mut a, 30);
    a.timeout(a.user_deadline().unwrap()).unwrap();
    assert_eq!(a.close_reason(), Some(CloseReason::TimedOut));
    assert!(!a.handshake_complete());
    assert_eq!(a.next_deadline(), None);
    assert!(!a.reset_pending());
}

#[test]
fn early_fin_timestamp_validation_and_simultaneous_synack_preserve_negotiation() {
    for simultaneous in [false, true] {
        let mut cfg = config(131072, 1460);
        cfg.timestamps = true;
        cfg.sack = true;
        let mut peer = Connection::active(reverse(tuple()), cfg.clone(), 900, 0).unwrap();
        let syn_bytes = packet(&mut peer, 0);
        let syn = wire::parse(ip(reverse(tuple())), &syn_bytes).unwrap();
        let mut a = if simultaneous {
            let mut a = Connection::active(tuple(), cfg, 100, 0).unwrap();
            deliver(&mut a, &mut peer, 0);
            a.input(10, &syn).unwrap();
            a
        } else {
            Connection::passive(tuple(), cfg, 100, 10, &syn).unwrap()
        };
        a.shutdown().unwrap();
        let synack_bytes = packet(&mut a, 20);
        let synack = wire::parse(ip(tuple()), &synack_bytes).unwrap();
        let bytes = packet(&mut a, 30);
        let fin = wire::parse(ip(tuple()), &bytes).unwrap();
        assert!(fin.options.timestamps.is_some());
        assert_eq!(fin.options.window_scale, None);
        assert!(!fin.options.sack_permitted);
        assert_eq!(a.snd_wnd, 65535); // The SYN window is unscaled.
        assert_eq!(a.peer_scale, 2);
        assert!(a.scaling && a.timestamps && a.sack_receive && a.sack_send);
        // A duplicate SYN must still retransmit a fully negotiated SYN-ACK.
        a.input(40, &syn).unwrap();
        let bytes = packet(&mut a, 40);
        let retry = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(retry.header.flags & (SYN | ACK | FIN), SYN | ACK);
        assert_eq!(retry.options.window_scale, synack.options.window_scale);
        assert_eq!(retry.options.timestamps, synack.options.timestamps);
        assert!(retry.options.sack_permitted);
        assert_eq!(retry.header.window, synack.header.window);
        inject(&mut a, 50, Seq(901), Seq(101), ACK, 1, b"bad");
        assert!(!a.handshake_complete()); // Negotiated timestamp missing.
        let metadata = ip(reverse(tuple()));
        let header = Header {
            source_port: 2000,
            destination_port: 1000,
            sequence: 901,
            acknowledgment: 101,
            flags: ACK,
            window: 1,
            urgent_pointer: 0,
        };
        let mut bytes = [0; 64];
        let options = [1, 1, 8, 10, 255, 255, 255, 255, 0, 0, 0, 0];
        let size = wire::encode(metadata, header, &options, b"bad", &mut bytes).unwrap();
        a.input(60, &wire::parse(metadata, &bytes[..size]).unwrap())
            .unwrap();
        assert!(!a.handshake_complete()); // PAWS rejects stale timestamp.
        assert_eq!(a.snd_wnd, 65535);
        assert_eq!(a.readable_bytes(), 0);
        packet(&mut a, 60); // PAWS ACK does not consume SYN retransmission state.
        if !simultaneous {
            peer.input(10_000, &synack).unwrap();
        }
        let bytes = deliver(&mut peer, &mut a, 10_010);
        let completion = wire::parse(metadata, &bytes).unwrap();
        assert_eq!(completion.header.flags & SYN != 0, simultaneous);
        assert!(a.handshake_complete());
        assert_eq!(a.state(), State::FinWait1);
        assert_eq!(a.snd_una, Seq(101)); // SYN-ACK/ACK did not acknowledge FIN.
        assert_eq!(a.acknowledged(), 0);
        assert!(a.take_events().connected);
        assert_eq!(a.snd_wnd, if simultaneous { 65535 } else { 131072 });
        assert_eq!(a.peer_scale, 2);
        let options = [1, 1, 8, 10, 0, 0, 0, 11, 0, 0, 0, 0];
        let header = Header {
            acknowledgment: 102,
            window: 10,
            ..header
        };
        let mut buffer = [0; 64];
        let size = wire::encode(metadata, header, &options, b"x", &mut buffer).unwrap();
        a.input(11_000, &wire::parse(metadata, &buffer[..size]).unwrap())
            .unwrap();
        assert_eq!(a.state(), State::FinWait2);
        assert_eq!(a.snd_wnd, 10 << 2); // Non-SYN windows use negotiated scale.
        assert_eq!(a.read(&mut [0; 1]), Ok(1));
        assert!(!a.take_events().connected);
    }
}

#[test]
fn early_fin_retains_handshake_receive_and_reset_rules() {
    for simultaneous in [false, true] {
        let cfg = config(64, 8);
        let metadata = ip(reverse(tuple()));
        let mut bytes = [0; 64];
        let header = Header {
            source_port: 2000,
            destination_port: 1000,
            sequence: 900,
            acknowledgment: 0,
            flags: SYN | PSH | URG,
            window: 64,
            urgent_pointer: 4,
        };
        let size = wire::encode(metadata, header, &[], b"abc", &mut bytes).unwrap();
        let syn = wire::parse(metadata, &bytes[..size]).unwrap();
        let mut a = if simultaneous {
            let mut a = Connection::active(tuple(), cfg, 100, 0).unwrap();
            packet(&mut a, 0);
            a.input(10, &syn).unwrap();
            a
        } else {
            Connection::passive(tuple(), cfg, 100, 10, &syn).unwrap()
        };
        a.shutdown().unwrap();
        packet(&mut a, 20);
        packet(&mut a, 30);
        assert_eq!(a.state(), State::FinWait1);
        assert_eq!(a.readable_bytes(), 0);
        assert_eq!(a.urgent_remaining(), 0);
        assert_eq!(a.read(&mut [0; 3]), Err(Error::WouldBlock));
        assert!(!a.events_pending());
        inject(&mut a, 40, Seq(904), Seq(101), ACK, 64, b"");
        assert!(a.handshake_complete());
        assert_eq!(a.state(), State::FinWait1);
        let events = a.take_events();
        assert!(events.connected && events.readable && events.pushed);
        assert_eq!(events.urgent, Some(3));
        assert_eq!(a.urgent_remaining(), 3);
        assert_eq!(a.read(&mut [0; 3]), Ok(3));

        let (mut a, _) = opening_for_close(config(64, 8), 100, simultaneous);
        a.shutdown().unwrap();
        packet(&mut a, 20);
        packet(&mut a, 30);
        inject(&mut a, 40, Seq(902), Seq(102), RST | ACK, 64, b"bad");
        assert_eq!(a.state(), State::FinWait1);
        assert!(!a.handshake_complete());
        let bytes = packet(&mut a, 40);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.flags & (RST | SYN | FIN | ACK),
            ACK
        );
        inject(&mut a, 50, Seq(901), Seq(102), RST | ACK, 64, b"bad");
        assert_eq!(a.close_reason(), Some(CloseReason::Reset));
        assert!(!a.handshake_complete());
        assert!(!a.reset_pending());
        assert_eq!(a.next_deadline(), None);
        assert_eq!(
            a.take_events().closed,
            if simultaneous {
                Some(CloseReason::Reset)
            } else {
                None
            }
        );
    }
}

#[test]
fn syn_received_close_zero_window_defers_fin_but_not_synack() {
    for simultaneous in [false, true] {
        let (mut a, _) = opening_for_close(config(64, 8), 100, simultaneous);
        a.snd_wnd = 0;
        a.shutdown().unwrap();
        let bytes = packet(&mut a, 20);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.flags & (SYN | ACK | FIN),
            SYN | ACK
        );
        assert_eq!(a.transmit(30, &mut [0; 64]), Ok(None));
        assert_eq!(a.state(), State::SynReceived);
        inject(&mut a, 40, Seq(901), Seq(101), ACK, 0, b"");
        assert!(a.handshake_complete());
        assert_eq!(a.state(), State::Established);
        assert_eq!(a.transmit(50, &mut [0; 64]), Ok(None));
        assert!(a.persist_deadline.is_some());
        inject(&mut a, 60, Seq(901), Seq(101), ACK, 64, b"");
        let bytes = packet(&mut a, 70);
        let fin = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(fin.header.flags & (SYN | ACK | FIN), ACK | FIN);
        assert_eq!(fin.header.sequence, 101);
        assert_eq!(a.state(), State::FinWait1);
    }
}

#[test]
fn send_state_matrix_preserves_queue_on_rejection() {
    for state in [
        State::Closed,
        State::SynSent,
        State::SynReceived,
        State::Established,
        State::FinWait1,
        State::FinWait2,
        State::CloseWait,
        State::Closing,
        State::LastAck,
        State::TimeWait,
    ] {
        let (mut a, _) = pair(config(4, 4), 100);
        a.state = state;
        let allowed = matches!(
            state,
            State::SynSent | State::SynReceived | State::Established | State::CloseWait
        );
        let before = (a.send.len(), a.snd_una, a.snd_nxt, a.acknowledged());
        if allowed {
            assert_eq!(a.write(b"abc"), Ok(3));
            assert_eq!(a.write(b"de"), Ok(1));
            assert_eq!(a.write(b"f"), Err(Error::WouldBlock));
            let mut queued = [0; 4];
            assert_eq!(a.send.copy(0, &mut queued), 4);
            assert_eq!(&queued, b"abcd");
            assert_eq!(
                (a.snd_una, a.snd_nxt, a.acknowledged()),
                (before.1, before.2, before.3)
            );
        } else {
            assert_eq!(a.write(b"late"), Err(Error::InvalidState));
            assert_eq!(
                (a.send.len(), a.snd_una, a.snd_nxt, a.acknowledged()),
                before
            );
        }
        assert_eq!(a.state(), state);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.4
//= type=test
//= reason=Unpushed writes flush before FIN; read half remains available.
//# Close also implies push function.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.3
//= type=test
//= reason=CLOSE-WAIT drains accepted bytes then returns EOF (0), the nonblocking API equivalent of closing notification.
//# Since the remote side has already sent FIN, RECEIVEs must be satisfied by data already
//# on hand, but not yet delivered to the user. If no text is awaiting delivery, the RECEIVE
//# will get an "error: connection closing" response. Otherwise, any remaining data can be
//# used to satisfy the RECEIVE.
fn shutdown_pushes_unpushed_fifo_and_close_wait_drains_before_eof() {
    let (mut a, mut b) = pair(config(64, 4), u32::MAX - 2);
    a.set_nagle(false);
    a.write_with_push(b"abc", false).unwrap();
    a.write_with_push(b"def", false).unwrap();
    a.shutdown().unwrap();
    let first = deliver(&mut a, &mut b, 40);
    let first = wire::parse(ip(tuple()), &first).unwrap();
    assert_eq!(first.payload, b"abcd");
    assert_eq!(first.header.flags & FIN, 0);
    let last = deliver(&mut a, &mut b, 50);
    let last = wire::parse(ip(tuple()), &last).unwrap();
    assert_eq!(last.payload, b"ef");
    assert_ne!(last.header.flags & FIN, 0);
    assert_eq!(b.state(), State::CloseWait);
    assert!(b.take_events().half_closed);
    for expected in [b"ab", b"cd", b"ef"] {
        let mut out = [0; 2];
        assert_eq!(b.read(&mut out), Ok(2));
        assert_eq!(&out, expected);
    }
    assert_eq!(b.read(&mut [0; 2]), Ok(0));
    assert_eq!(b.write(b"reply"), Ok(5));
    deliver(&mut b, &mut a, 60);
    let mut out = [0; 8];
    assert_eq!(a.read(&mut out), Ok(4));
    assert_eq!(&out[..4], b"repl");
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//= reason=Focused edge test covers duplicate-prefix and out-of-window suffix trimming, wrap and zero-window rejection.
//# If a segment's contents straddle the boundary between old and new, only the new parts
//# are processed.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//= reason=Rejected input leaves receive state unchanged and replies with current ACK; invalid RST is silent.
//# If an incoming segment is not acceptable, an acknowledgment should be sent in reply
//# (unless the RST bit is set, if so drop the segment and return):
//# <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK> o After sending the acknowledgment, drop the
//# unacceptable segment and return.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
//= type=test
//= reason=Output ACK field is the receive frontier; established reply flags and sequence are explicitly checked.
//# If the ACK control bit is set, this field contains the value of the next sequence number
//# the sender of the segment is expecting to receive. Once a connection is established,
//# this is always sent.
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
//= type=test
//= reason=Ordinary shared acceptability check follows PAWS; outside-window old-data D-SACK path reports evidence without admitting text or metadata.
//# R2)  If the segment is outside the window, reject it (normal TCP
//# processing).
fn receive_acceptability_edges_trim_duplicates_and_wrap() {
    for next in [Seq(901), Seq(u32::MAX - 1)] {
        for (offset, payload, flags, used, readable, reply) in [
            (u32::MAX - 1, b"xxAB".as_slice(), ACK, 2, 2, true),
            (30, b"WXYZ".as_slice(), ACK, 2, 0, true),
            (32, b"bad".as_slice(), ACK, 0, 0, true),
            (u32::MAX - 3, b"old".as_slice(), ACK, 0, 0, true),
            (32, b"bad".as_slice(), RST | ACK, 0, 0, false),
        ] {
            let (mut a, _) = pair(config(32, 8), 100);
            a.receive.reset_start(next).unwrap();
            a.advertised_edge = next.wrapping_add(32);
            let ack = a.snd_una;
            inject(
                &mut a,
                40,
                next.wrapping_add(offset),
                ack,
                flags,
                32,
                payload,
            );
            assert_eq!(a.state(), State::Established);
            assert_eq!(a.receive_used, used);
            assert_eq!(a.readable_bytes(), readable);
            assert_eq!(a.receive.next(), next.wrapping_add(readable as u32));
            let mut out = [0; 64];
            let packet = a.transmit(40, &mut out).unwrap();
            assert_eq!(packet.is_some(), reply);
            if let Some(len) = packet {
                let segment = wire::parse(ip(tuple()), &out[..len]).unwrap();
                assert_eq!(segment.header.flags, ACK);
                assert_eq!(segment.header.sequence, a.snd_nxt.0);
                assert_eq!(segment.header.acknowledgment, a.receive.next().0);
                assert!(segment.payload.is_empty());
            }
            if readable != 0 {
                let mut out = [0; 8];
                assert_eq!(a.read(&mut out), Ok(2));
                assert_eq!(&out[..2], b"AB");
            }
        }
        for (offset, payload, reply) in [
            (0, b"".as_slice(), false),
            (1, b"".as_slice(), true),
            (0, b"bad".as_slice(), true),
        ] {
            let (mut a, _) = pair(config(32, 8), 100);
            a.receive.reset_start(next).unwrap();
            a.advertised_edge = next;
            let ack = a.snd_una;
            inject(&mut a, 40, next.wrapping_add(offset), ack, ACK, 32, payload);
            assert_eq!(a.receive.next(), next);
            assert_eq!(a.receive_used, 0);
            assert_eq!(a.ack_pending, reply);
            assert_eq!(a.state(), State::Established);
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
//= type=test
//= reason=Both initial-window policies, active and passive handshakes: accept_ack suppresses congestion growth for SYN ACK; test compares unchanged active/passive cwnd after handshake. No claim about IW formula correctness.
//# As specified in [RFC3390], the SYN/ACK and the acknowledgment of the SYN/ACK MUST NOT
//# increase the size of the congestion window.
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
//= type=test
//= reason=set_mss scales cwnd by new/old MSS on a decrease; negotiated/path/timestamp vectors assert exact byte ratio. No claim that discovery itself is supplied by TCP.
//# When initial congestion windows of more than one segment are implemented along with Path
//# MTU Discovery [RFC1191], and the MSS being used is found to be too large, the congestion
//# window cwnd SHOULD be reduced to prevent large bursts of smaller segments.
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
//= type=test
//= reason=set_mss scales cwnd by new/old MSS on a decrease; negotiated/path/timestamp vectors assert exact byte ratio. No claim that discovery itself is supplied by TCP.
//# Specifically, cwnd SHOULD be reduced by the ratio of the old segment size to the new
//# segment size.
//= https://www.rfc-editor.org/rfc/rfc6928#section-12
//= type=test
//= reason=No monitoring-backed default deployment is claimed: InitialWindow default and ConnectionConfig default select Rfc5681, and test explicitly asserts this. Iw10 is only explicit opt-in; deployment monitoring remains owed by the enabling actor outside this implementation audit; bounded cache/fallback is implemented.
//# An increased initial window MUST NOT be turned on by default on systems without such
//# monitoring capabilities.
//= https://www.rfc-editor.org/rfc/rfc6928#section-2
//= type=test
//= reason=IW10 is optional and InitialWindow::default is Rfc5681; config default assertion confirms opt-in. This permission does not discharge IW10 fallback/monitoring obligations. Default RFC5681 arithmetic is covered by default_initial_window_piecewise_boundaries and initial_window_uses_negotiated_effective_mss.
//# This increase is optional: a TCP MAY start with an initial window that is smaller than
//# 10 segments.
//= https://www.rfc-editor.org/rfc/rfc6928#section-2
//= type=test
//= reason=Explicit InitialWindow::Iw10 computes min(10*MSS,max(2*MSS,14600)) with conservative integer cap. Tests assert representative small/normal/jumbo/overflow vectors, negotiated MSS/path/options and initial handshake value. Default RFC5681 arithmetic is covered separately by default_initial_window_piecewise_boundaries and initial_window_uses_negotiated_effective_mss.
//# min (10*MSS, max (2*MSS, 14600)) (1)
//= https://www.rfc-editor.org/rfc/rfc6928#section-2
//= type=test
//= reason=IW10 first data-flight bound and handshake no-growth: negotiation test checks cwnd after active/passive handshake; idle/data-RTO trace emits exactly ten MSS before blocking. IW10 first-retry relaxation and bounded loss fallback are covered separately; no deployment monitoring claim.
//# This change applies to the initial window of the connection in the first round-trip time
//# (RTT) of data transmission during or following the TCP three-way handshake. Neither the
//# SYN/ACK nor its ACK in the three-way handshake should increase the initial window size.
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
//= type=test
//= reason=Negotiated MSS, timestamp overhead and path limits select the piecewise default window; actual first-flight output is bounded, including failed encoding.
//# IW, the initial value of cwnd, MUST be set using the following guidelines as an upper bound.
//= https://www.rfc-editor.org/rfc/rfc6928#section-1
//= type=test
//= reason=Settable Rfc5681/Iw10 selection with default-disabled IW10; deployment monitoring/application interactions remain enabling-actor obligations explicitly excluded from this implementation audit, not satisfied. No evidence for IW>10 is claimed.
//# We recommend that all TCP implementations have a settable TCP IW parameter, as long as there is a reasonable effort to monitor for possible interactions with other Internet applications and services as described in Section 12. Furthermore, Section 10 details why 10 segments may be an appropriate value, and while that value may continue to rise in the future, this document does not include any supporting evidence for values of IW larger than 10.
fn initial_window_uses_negotiated_effective_mss() {
    assert_eq!(
        ConnectionConfig::default().initial_window,
        InitialWindow::Rfc5681
    );
    for policy in [InitialWindow::Rfc5681, InitialWindow::Iw10] {
        for (configured, peer, timestamps, path_limit, effective, default_iw, iw10) in [
            (1_000, 1_000, false, 65_515, 1_000, 4_000, 10_000),
            (1_460, 1_460, false, 65_515, 1_460, 4_380, 14_600),
            (3_000, 3_000, false, 65_515, 3_000, 6_000, 14_600),
            (8_000, 8_000, false, 65_515, 8_000, 16_000, 16_000),
            (3_000, 1_000, false, 65_515, 1_000, 4_000, 10_000),
            (3_000, 1_460, false, 65_515, 1_460, 4_380, 14_600),
            (1_000, 3_000, false, 65_515, 1_000, 4_000, 10_000),
            (1_095, 1_095, false, 65_515, 1_095, 4_380, 10_950),
            (1_096, 1_096, false, 65_515, 1_096, 3_288, 10_960),
            (2_190, 2_190, false, 65_515, 2_190, 6_570, 14_600),
            (2_191, 2_191, false, 65_515, 2_191, 4_382, 14_600),
            (3_000, 1_460, true, 65_515, 1_448, 4_344, 14_480),
            (3_000, 3_000, true, 1_032, 1_000, 4_000, 10_000),
        ] {
            let mut cfg = config(65_536, configured);
            cfg.initial_window = policy;
            cfg.nagle = false;
            cfg.timestamps = timestamps;
            cfg.send_ip_payload_limit = path_limit;
            let mut peer_cfg = config(65_536, peer);
            peer_cfg.initial_window = policy;
            peer_cfg.timestamps = timestamps;
            let mut a = Connection::active(tuple(), cfg, 100, 0).unwrap();
            let bytes = packet(&mut a, 0);
            let syn = wire::parse(ip(tuple()), &bytes).unwrap();
            let mut b = Connection::passive(reverse(tuple()), peer_cfg, 900, 10, &syn).unwrap();
            let passive_iw = b.congestion.cwnd();
            deliver(&mut b, &mut a, 20);
            deliver(&mut a, &mut b, 30);
            assert_eq!(a.mss, effective);
            assert_eq!(
                a.congestion.cwnd(),
                if policy == InitialWindow::Iw10 {
                    iw10
                } else {
                    default_iw
                }
            );
            assert_eq!(a.congestion.cwnd(), a.initial_window());
            assert_eq!(b.congestion.cwnd(), passive_iw);
            a.write(&vec![7; 2 * a.initial_window() as usize]).unwrap();
            assert_eq!(a.transmit(40, &mut [0; 19]), Err(Error::OutputTooSmall));
            let mut sent = 0;
            let mut out = vec![0; 65_535];
            while let Some(size) = a.transmit(40, &mut out).unwrap() {
                let segment = wire::parse(ip(tuple()), &out[..size]).unwrap();
                assert!(segment.payload.len() <= effective);
                sent += segment.payload.len();
            }
            // Sender SWS avoidance may retain a fractional-MSS IW10 tail.
            assert!(sent <= a.initial_window() as usize);
            assert_eq!(sent / effective, a.initial_window() as usize / effective);
            if policy == InitialWindow::Rfc5681 {
                assert_eq!(sent, a.initial_window() as usize);
            }
            let before = a.congestion.cwnd();
            let lowered = effective / 2;
            a.lower_mss(lowered as u16 + if timestamps { 12 } else { 0 })
                .unwrap();
            assert_eq!(a.mss, lowered);
            assert_eq!(
                a.congestion.cwnd(),
                (before as u64 * lowered as u64 / effective as u64) as u32
            );
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
//= type=test
//= reason=Default RFC5681 SYN/SYNACK timeout reduces to one effective MSS. Opt-in IW10 preserves IW after one committed SYN retry and reduces only after more than one; failed output does not count. This is an inference policy, not proof of physical loss.
//# Further, if the SYN or SYN/ACK is lost, the initial window used by a sender after a
//# correctly transmitted SYN MUST be one segment consisting of at most SMSS bytes.
//= https://www.rfc-editor.org/rfc/rfc6928#section-2
//= type=test
//= reason=IW10 retains its initial window after a first potentially spurious SYN timeout; only successfully encoded retransmissions count. More than one committed SYN/SYNACK retry reduces to one MSS; failed output and both endpoint roles tested. This is conservative inference, not physical loss proof.
//# For this reason, it is RECOMMENDED that implementations refrain from resetting the initial window to 1 segment, unless there have been more than one SYN or SYN/ACK retransmissions or true loss detection has been made.
fn initial_window_syn_loss_and_output_retries_remain_conservative() {
    for policy in [InitialWindow::Rfc5681, InitialWindow::Iw10] {
        for lose_synack in [false, true] {
            for retries in [1, 2] {
                let mut cfg = config(65_536, 3_000);
                cfg.initial_window = policy;
                let mut peer_cfg = cfg.clone();
                peer_cfg.mss = 1_000;
                let mut a = Connection::active(tuple(), cfg, 100, 0).unwrap();
                let initial = a.congestion.cwnd();
                assert_eq!(a.transmit(0, &mut [0; 19]), Err(Error::OutputTooSmall));
                assert_eq!(a.congestion.cwnd(), initial);
                assert_eq!(a.rto_deadline, None);
                let bytes = packet(&mut a, 0);
                let syn = wire::parse(ip(tuple()), &bytes).unwrap();
                let mut b = Connection::passive(reverse(tuple()), peer_cfg, 900, 10, &syn).unwrap();
                if lose_synack {
                    packet(&mut b, 10);
                }
                let sender = if lose_synack { &mut b } else { &mut a };
                let mut now = 0;
                let mut retry_bytes = Vec::new();
                for retry in 1..=retries {
                    now = sender.rto_deadline.unwrap();
                    sender.timeout(now).unwrap();
                    let before = sender.syn_retransmissions;
                    assert_eq!(
                        sender.transmit(now, &mut [0; 19]),
                        Err(Error::OutputTooSmall)
                    );
                    assert_eq!(sender.syn_retransmissions, before);
                    retry_bytes = packet(sender, now);
                    assert_eq!(sender.syn_retransmissions, retry);
                    assert_eq!(
                        sender.congestion.cwnd(),
                        if policy == InitialWindow::Iw10 && retry == 1 {
                            sender.initial_window()
                        } else {
                            sender.mss as u32
                        }
                    );
                }
                if lose_synack {
                    let segment = wire::parse(ip(reverse(tuple())), &retry_bytes).unwrap();
                    a.input(now + 10, &segment).unwrap();
                } else {
                    deliver(&mut b, &mut a, now + 10);
                }
                deliver(&mut a, &mut b, now + 20);
                let selected = if policy == InitialWindow::Iw10 {
                    10_000
                } else {
                    4_000
                };
                let reduced = policy == InitialWindow::Rfc5681 || retries > 1;
                assert_eq!(
                    a.congestion.cwnd(),
                    if !lose_synack && reduced {
                        1_000
                    } else {
                        selected
                    }
                );
                assert_eq!(
                    b.congestion.cwnd(),
                    if lose_synack && reduced {
                        1_000
                    } else {
                        selected
                    }
                );
            }
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
//= type=test
//= reason=Both Reno/NewReno and default/IW10 retain a one-effective-MSS loss window. Helper verifies cwnd reset and ACK-driven transition; IW10 wire test asserts exactly one retransmission and no second output.
//# Furthermore, upon a timeout (as specified in [RFC2988]) cwnd MUST be set to no more than
//# the loss window, LW, which equals 1 full-sized segment (regardless of the value of IW).
//= https://www.rfc-editor.org/rfc/rfc6928#section-2
//= type=test
//= reason=Selected IW10 restart choice uses min(current cwnd, IW10); helper covers grown and reduced cwnd and changing MSS, and wire idle trace asserts burst limited to ten MSS. iw10_transmit_idle_restart_and_data_rto covers the last-data idle trigger despite received requests and emitted pure ACKs; this evidence is the optional window value only.
//# Optionally, a TCP MAY set the restart window to the minimum of the value used for the
//# initial window and the current value of cwnd (in other words, using a larger value for
//# the restart window should never increase the size of cwnd).
//= https://www.rfc-editor.org/rfc/rfc6928#section-2
//= type=test
//= reason=IW10 first data-flight bound and handshake no-growth: negotiation test checks cwnd after active/passive handshake; idle/data-RTO trace emits exactly ten MSS before blocking. IW10 first-retry relaxation and bounded loss fallback are covered separately; no deployment monitoring claim.
//# This change applies to the initial window of the connection in the first round-trip time
//# (RTT) of data transmission during or following the TCP three-way handshake. Neither the
//# SYN/ACK nor its ACK in the three-way handshake should increase the initial window size.
//= https://www.rfc-editor.org/rfc/rfc6928#section-2
//= type=test
//= reason=IW10 loss window remains one effective MSS; helper and wire trace assert timeout reduction, one retransmit and denied next output.
//# These changes do NOT change the loss window, which must remain 1 segment of MSS bytes
//# (to permit the lowest possible window size in the case of severe congestion).
//= https://www.rfc-editor.org/rfc/rfc5681#section-4.1
//= type=test
//= reason=Default and IW10 restart after idle despite a received request and emitted pure ACK; failed output preserves cwnd and successful data stays within RW.
//# Therefore, a TCP SHOULD set cwnd to no more than RW before beginning transmission
//# if the TCP has not sent data in an interval exceeding the retransmission timeout.
fn iw10_transmit_idle_restart_and_data_rto() {
    for (policy, mss) in [
        (InitialWindow::Rfc5681, 1_000),
        (InitialWindow::Rfc5681, 1_460),
        (InitialWindow::Iw10, 1_000),
        (InitialWindow::Iw10, 1_460),
    ] {
        let mut cfg = config(65_536, mss);
        cfg.initial_window = policy;
        cfg.nagle = false;
        let (mut a, mut b) = pair(cfg, 100);
        let iw = a.initial_window();
        a.write(&vec![1; mss as usize]).unwrap();
        deliver(&mut a, &mut b, 40);
        b.immediate_ack();
        deliver(&mut b, &mut a, 50);
        assert!(a.congestion.cwnd() > iw);
        let now = 50 + a.rto();
        let grown = a.congestion.cwnd();
        b.write(&[9]).unwrap();
        deliver(&mut b, &mut a, now);
        a.immediate_ack();
        let ack = packet(&mut a, now);
        assert!(wire::parse(ip(tuple()), &ack).unwrap().payload.is_empty());
        assert_eq!(a.last_sent, 40);
        assert_eq!(a.congestion.cwnd(), grown);
        a.write(&vec![2; 2 * iw as usize]).unwrap();
        assert_eq!(a.transmit(now, &mut [0; 19]), Err(Error::OutputTooSmall));
        assert_eq!(a.congestion.cwnd(), grown);
        let mut sent = 0;
        let mut out = vec![0; 65_535];
        while let Some(size) = a.transmit(now, &mut out).unwrap() {
            sent += wire::parse(ip(tuple()), &out[..size])
                .unwrap()
                .payload
                .len();
        }
        assert_eq!(sent, iw as usize);
        assert_eq!(a.congestion.cwnd(), iw);
        a.timeout(a.rto_deadline.unwrap()).unwrap();
        assert_eq!(a.congestion.cwnd(), mss as u32);
        let now = a.now;
        let retry = packet(&mut a, now);
        assert_eq!(
            wire::parse(ip(tuple()), &retry).unwrap().payload.len(),
            mss as usize
        );
        assert_eq!(a.congestion.cwnd(), mss as u32);
        assert_eq!(a.transmit(now, &mut out).unwrap(), None);
    }
}

fn inject(
    to: &mut Connection,
    now: Instant,
    seq: Seq,
    ack: Seq,
    flags: u8,
    window: u16,
    payload: &[u8],
) {
    let mut bytes = vec![0; 20 + payload.len()];
    let metadata = ip(reverse(to.tuple()));
    let header = Header {
        source_port: to.tuple.remote.port(),
        destination_port: to.tuple.local.port(),
        sequence: seq.0,
        acknowledgment: ack.0,
        flags,
        window,
        urgent_pointer: 0,
    };
    let size = wire::encode(metadata, header, &[], payload, &mut bytes).unwrap();
    let segment = wire::parse(metadata, &bytes[..size]).unwrap();
    to.input(now, &segment).unwrap();
}

#[allow(clippy::too_many_arguments)]
fn inject_sack(
    to: &mut Connection,
    now: Instant,
    seq: Seq,
    ack: Seq,
    flags: u8,
    window: u16,
    payload: &[u8],
    blocks: &[(u32, u32)],
) {
    let mut options = vec![];
    if to.timestamps {
        options.extend_from_slice(&[1, 1, 8, 10]);
        options.extend_from_slice(&((now / 1_000) as u32).to_be_bytes());
        options.extend_from_slice(&to.ts_recent.to_be_bytes());
    }
    if !blocks.is_empty() {
        options.extend_from_slice(&[1, 1, 5, (2 + 8 * blocks.len()) as u8]);
        for &(left, right) in blocks {
            options.extend_from_slice(&left.to_be_bytes());
            options.extend_from_slice(&right.to_be_bytes());
        }
    }
    let metadata = ip(reverse(to.tuple()));
    let mut bytes = vec![0; 60 + payload.len()];
    let size = wire::encode(
        metadata,
        Header {
            source_port: to.tuple.remote.port(),
            destination_port: to.tuple.local.port(),
            sequence: seq.0,
            acknowledgment: ack.0,
            flags,
            window,
            urgent_pointer: 0,
        },
        &options,
        payload,
        &mut bytes,
    )
    .unwrap();
    to.input(now, &wire::parse(metadata, &bytes[..size]).unwrap())
        .unwrap();
}

fn rack_flight(iss: u32) -> Connection {
    let cfg = ConnectionConfig {
        sack: true,
        rack: true,
        prr: true,
        initial_window: InitialWindow::Iw10,
        ..config(65_536, 1000)
    };
    let mut a = Connection::active(tuple(), cfg.clone(), iss, 0).unwrap();
    let bytes = packet(&mut a, 0);
    let syn = wire::parse(ip(tuple()), &bytes).unwrap();
    let mut b = Connection::passive(reverse(tuple()), cfg, 900, 0, &syn).unwrap();
    deliver(&mut b, &mut a, 100_000);
    deliver(&mut a, &mut b, 100_000);
    a.write(&[0x55; 10_000]).unwrap();
    for _ in 0..10 {
        packet(&mut a, 100_000);
    }
    assert_eq!(a.transport_info().unacked, 10);
    a
}

#[test]
fn reordered_ack_delivers_fresh_sack_once_and_commits_only_successful_output() {
    for iss in [0, u32::MAX - 4999] {
        for rack in [false, true] {
            let mut a = rack_flight(iss);
            a.config.rack = rack;
            rack_sack(&mut a, 200_000, 4000, &[(7000, 8000)]);
            assert!(a.prr.is_none());
            if rack {
                // RACK allows reordered originals a settling interval;
                // enter on its existing timer, not RFC6675 IsLost.
                a.timeout(225_000).unwrap();
                assert!(a.prr.is_some());
            }
            let delivered_before = a.prr.map_or(0, |p| p.counters().1);
            let base = a.iss.wrapping_add(1);
            let storage = (a.snd_una, a.send_base, a.send.len(), a.snd_nxt);
            let window = (a.snd_wnd, a.wl1, a.wl2, a.max_snd_wnd);
            let timer = a.rto_deadline;
            // Packet ACK=3001 after UNA=4001, SACK=5001:7001.
            inject_sack(
                &mut a,
                226_000,
                Seq(901),
                base.wrapping_add(3000),
                ACK | ECE,
                1,
                &[],
                &[(base.wrapping_add(5000).0, base.wrapping_add(7000).0)],
            );
            assert!(a.ecn_feedback());
            assert_eq!((a.snd_una, a.send_base, a.send.len(), a.snd_nxt), storage);
            assert_eq!((a.snd_wnd, a.wl1, a.wl2, a.max_snd_wnd), window);
            assert_eq!(a.rto_deadline, timer);
            assert_eq!(a.congestion.ssthresh(), 3000); // Loss, not stale ECE.
            assert_eq!(
                a.scoreboard.ranges(),
                &[(base.wrapping_add(5000), base.wrapping_add(8000))]
            );
            let prr = a.prr.unwrap();
            assert_eq!(prr.counters().1, delivered_before + 2000); // No replay of earlier delivery.
            assert!(prr.credit() > 0);
            let recovery = a.sack_recovery.unwrap();
            assert_eq!(recovery.pipe, a.recovery_pipe(recovery.high_rxt));
            assert_eq!(
                a.transmit(226_000, &mut [0; 20]),
                Err(Error::OutputTooSmall)
            );
            assert_eq!(a.prr.unwrap().counters(), prr.counters());
            assert_eq!(a.prr.unwrap().credit(), prr.credit());
            assert_eq!(a.sack_recovery.unwrap().high_rxt, recovery.high_rxt);
            // Replaying the ACK cannot grant delivery or extra credit.
            rack_sack(&mut a, 227_000, 3000, &[(5000, 7000)]);
            assert_eq!(a.prr.unwrap().counters(), prr.counters());
            assert_eq!(a.prr.unwrap().credit(), prr.credit());
            assert_eq!(a.rack.ack_sample, None);
            let (_, bytes) = prr_packet(&mut a, 227_000);
            assert!(bytes > 0 && bytes <= prr.credit() as usize);
            assert_eq!(a.prr.unwrap().counters().2, bytes as u64);
            let committed = a.prr.unwrap();
            rack_sack(&mut a, 228_000, 3000, &[(5000, 7000)]);
            assert_eq!(a.prr.unwrap().counters(), committed.counters());
            assert_eq!(a.prr.unwrap().credit(), committed.credit());
            // Cumulative coverage of already SACKed data adds only the hole.
            rack_sack(&mut a, 229_000, 8000, &[]);
            assert_eq!(a.prr.unwrap().counters().1, delivered_before + 3000);
            assert!(a.scoreboard.ranges().is_empty());
            assert_eq!(a.send.len(), 2000);
        }
    }
}

#[test]
fn reordered_ack_wire_dsack_classification_and_live_trim_are_independent() {
    for iss in [0, u32::MAX - 4999] {
        let mut a = rack_flight(iss);
        a.config.rack = false; // Keep loss detection out of this classification check.
        rack_sack(&mut a, 200_000, 4000, &[]);
        let state = (a.snd_una, a.send_base, a.send.len());
        let adaptation = a.rack.adaptation();
        // Below current UNA, but ABOVE the ACK in this packet: not DSACK.
        rack_sack(&mut a, 201_000, 3000, &[(3100, 3900)]);
        assert_eq!(a.rack.adaptation(), adaptation);
        assert!(a.scoreboard.ranges().is_empty());
        assert_eq!(a.rack.ack_sample, None);
        // A crossing ordinary block records only the still-live suffix.
        rack_sack(&mut a, 202_000, 3000, &[(3500, 4500)]);
        let base = a.iss.wrapping_add(1);
        assert_eq!(
            a.scoreboard.ranges(),
            &[(base.wrapping_add(4000), base.wrapping_add(4500))]
        );
        assert_eq!(a.rack.adaptation(), adaptation);
        // Containment must be classified before clipping to the live base.
        rack_sack(&mut a, 203_000, 3000, &[(3200, 3300), (3100, 3900)]);
        assert_eq!(a.rack.adaptation().0, adaptation.0 + 1);
        assert_eq!(a.rack.ack_sample, None);
        assert_eq!((a.snd_una, a.send_base, a.send.len()), state);
        // Below the packet ACK is a true DSACK, still never delivery.
        let mut b = rack_flight(iss);
        b.config.rack = false;
        rack_sack(&mut b, 200_000, 4000, &[]);
        let adaptation = b.rack.adaptation();
        rack_sack(&mut b, 201_000, 3000, &[(2000, 2500)]);
        assert_eq!(b.rack.adaptation().0, adaptation.0 + 1);
        assert!(b.scoreboard.ranges().is_empty());
        assert_eq!(b.rack.ack_sample, None);
        assert_eq!((b.snd_una, b.send_base, b.send.len()), state);
    }
}

#[test]
fn reordered_ack_sack_security_bounds_and_fallback_remain_gated() {
    for iss in [0, u32::MAX - 4999] {
        let mut a = rack_flight(iss);
        a.config.rack = false;
        rack_sack(&mut a, 200_000, 4000, &[]);
        let base = a.iss.wrapping_add(1);
        let state = (a.snd_una, a.send_base, a.send.len(), a.snd_wnd);
        for (i, block) in [
            (5000, 5000),
            (7000, 5000),
            (5000, 10_001),
            (5000 + (1 << 31), 7000),
            (2000, 5000),
        ]
        .into_iter()
        .enumerate()
        {
            rack_sack(&mut a, 201_000 + i as u64, 3000, &[block]);
            assert!(a.scoreboard.ranges().is_empty());
            assert!(a.prr.is_none());
            assert_eq!(a.rack.ack_sample, None);
        }
        let seq = a.receive.next();
        for (i, ack) in [
            a.snd_nxt.wrapping_add(1),
            a.snd_una.wrapping_add(0u32.wrapping_sub(a.max_snd_wnd + 1)),
        ]
        .into_iter()
        .enumerate()
        {
            inject_sack(
                &mut a,
                202_000 + i as u64,
                seq,
                ack,
                ACK | ECE,
                1,
                &[],
                &[(base.wrapping_add(5000).0, base.wrapping_add(7000).0)],
            );
            assert!(a.scoreboard.ranges().is_empty());
            assert!(a.prr.is_none());
        }
        assert_eq!((a.snd_una, a.send_base, a.send.len(), a.snd_wnd), state);
        // Advice exhaustion/RTO fallback cannot be bypassed by an old ACK.
        a.sack_fallback = Some(a.data_high());
        rack_sack(&mut a, 203_000, 3000, &[(5000, 7000)]);
        assert!(a.scoreboard.ranges().is_empty());
        assert!(a.prr.is_none());
        assert_eq!(a.sack_fallback, Some(a.data_high()));
    }
}

#[test]
fn reordered_ack_scoreboard_overflow_cancels_recovery_without_delivery() {
    for iss in [0, u32::MAX - 4999] {
        let mut a = rack_flight(iss);
        a.config.rack = false;
        rack_sack(&mut a, 200_000, 4000, &[(7000, 8000)]);
        rack_sack(&mut a, 201_000, 3000, &[(5000, 7000)]);
        assert!(a.prr.is_some());
        let state = (a.snd_una, a.send_base, a.send.len(), a.snd_nxt);
        // Production backing fits every live byte union. Artificially
        // shrink it to exercise defensive overflow on a reordered ACK.
        a.scoreboard = Scoreboard::with_capacity(2).unwrap();
        rack_sack(&mut a, 202_000, 3000, &[(5000, 5001), (7000, 7001)]);
        assert!(a.scoreboard.ranges().is_empty());
        assert!(a.prr.is_none() && a.sack_recovery.is_none());
        assert_eq!(a.sack_fallback, Some(a.data_high()));
        assert_eq!((a.snd_una, a.send_base, a.send.len(), a.snd_nxt), state);
        rack_sack(&mut a, 203_000, 3000, &[(5000, 7000)]);
        assert!(a.scoreboard.ranges().is_empty());
        assert!(a.prr.is_none());
    }
}

#[test]
fn reordered_ack_does_not_enable_sack_on_default_connection() {
    for iss in [0, u32::MAX - 4999] {
        let (mut a, _) = pair(config(16_384, 1000), iss);
        assert!(!a.sack_receive && !a.config.sack);
        a.write(&[0x55; 4000]).unwrap();
        for _ in 0..4 {
            packet(&mut a, 100_000);
        }
        rack_sack(&mut a, 200_000, 1000, &[]);
        let state = (
            a.snd_una,
            a.send_base,
            a.send.len(),
            a.snd_wnd,
            a.congestion.cwnd(),
        );
        rack_sack(&mut a, 201_000, 0, &[(2000, 4000)]);
        assert_eq!(
            (
                a.snd_una,
                a.send_base,
                a.send.len(),
                a.snd_wnd,
                a.congestion.cwnd()
            ),
            state
        );
        assert!(a.scoreboard.ranges().is_empty());
        assert!(a.sack_recovery.is_none() && a.prr.is_none());
        assert_eq!(a.duplicate_acks, 0);
    }
}

// Independent RFC9937 equation oracle for every ACK and successful
// packet in the strict traces. The boundary ACK exits the epoch; it cannot
// grant PRR output afterward. RTO/overflow/persist cancellation is separate.
fn strict_ack(a: &mut Connection, now: u64, ack: u32, blocks: &[(u32, u32)]) {
    let una = a.snd_una;
    let flight = a.data_flight();
    let sackd = a.flight() - a.scoreboard.unsacked_bytes(una, a.data_high());
    let before = a.prr;
    let old_pipe = a.rack.pipe();
    let old_threshold = a.congestion.ssthresh();
    rack_sack(a, now, ack, blocks);
    if let Some(p) = a.prr {
        let (fs, delivered, out) = p.counters();
        let new_sackd = a.flight() - a.scoreboard.unsacked_bytes(a.snd_una, a.data_high());
        let delta =
            i64::from(a.snd_una.distance_from(una)) + i64::from(new_sackd) - i64::from(sackd);
        assert!(delta >= 0);
        let new_episode = before.is_none() || a.congestion.ssthresh() != old_threshold;
        let (before_delivered, before_out) = if new_episode {
            (0, 0)
        } else {
            let (_, d, o) = before.unwrap().counters();
            (d, o)
        };
        assert_eq!(delivered, before_delivered + delta as u64);
        assert_eq!(out, before_out);
        if new_episode {
            assert_eq!(fs, flight - sackd);
        } else {
            assert_eq!(fs, before.unwrap().counters().0);
        }
        let pipe = a.sack_recovery.unwrap().pipe;
        let target = a.congestion.ssthresh();
        if delta == 0 {
            assert_eq!(p.credit(), before.map_or(0, |p| p.credit()));
        } else {
            let safe = a.snd_una != una
                && !a.retx_pending
                && pipe >= old_pipe.saturating_sub(delta as u32);
            let mut expected = if pipe > target {
                (delivered * u64::from(target))
                    .div_ceil(u64::from(fs))
                    .saturating_sub(out)
            } else {
                delivered
                    .saturating_sub(out)
                    .max(delta as u64)
                    .saturating_add(if safe { a.mss as u64 } else { 0 })
                    .min(u64::from(target - pipe))
            };
            if out == 0 && expected == 0 {
                expected = a.mss as u64;
            }
            assert_eq!(u64::from(p.credit()), expected);
            assert_eq!(a.congestion.cwnd(), pipe + p.credit());
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9937#section-5
//= type=test
//= reason=PRR uses the ssthresh target; strict_ack covers loss and cubic_ecn_prr covers eligible ECN and SafeACK credit. Optional ECN PRR is omitted/cancelled if the post-MSS logical target differs from ssthresh, preserving direct CUBIC below the threshold floor.
//# PRR MAY be used in conjunction with any congestion control algorithm
//# that intends to make a multiplicative decrease in its sending rate
//# over approximately the time scale of one round-trip time, as long as
//# the current volume of in-flight data is limited by a congestion
//# window (cwnd) and the target volume of in-flight data during that
//# reduction is a fixed value given by ssthresh.
//= https://www.rfc-editor.org/rfc/rfc9937#section-6.1
//= type=test
//= reason=Snapshot post-ACK unsacked payload and add current signed delivery, excluding earlier SACKs; exact 9000 RecoverFS/6000 delivery plus wrap and later invariance asserted by independent strict_ack oracle.
//# RecoverFS = SND.NXT - SND.UNA
//# // Bytes SACKed before entering recovery will not be
//# // marked as delivered during recovery:
//# RecoverFS -= (bytes SACKed in scoreboard)
//# // Include the (common) case of selectively ACKed bytes:
//# RecoverFS += (bytes newly SACKed)
//# // Include the (rare) case of cumulatively ACKed bytes:
//# RecoverFS += (bytes newly cumulatively acknowledged)
//= https://www.rfc-editor.org/rfc/rfc9937#section-6.1
//= type=test
//= reason=include_entry_delivery is called only for ACK-driven new episodes; later ACKs leave the denominator fixed. A new congestion response completes and replaces the old episode, not a mutation of its denominator.
//# Upon entering fast
//# recovery, PRR initializes RecoverFS, and RecoverFS remains constant
//# during a given fast recovery episode.
fn rfc9937_entry_excludes_prior_sack_and_includes_current_cumulative_and_sack() {
    for iss in [0, u32::MAX - 4999] {
        let mut a = rack_flight(iss);
        a.config.rack = false;
        strict_ack(&mut a, 200_000, 0, &[(8000, 9000)]);
        assert!(a.prr.is_none());
        strict_ack(&mut a, 201_000, 1000, &[(4000, 10_000)]);
        assert_eq!(a.prr.unwrap().counters(), (9000, 6000, 0));
        let fs = a.prr.unwrap().counters().0;
        strict_ack(&mut a, 202_000, 2000, &[(4000, 10_000)]);
        assert_eq!(a.prr.unwrap().counters().0, fs);
        assert_eq!(a.prr.unwrap().counters(), (9000, 7000, 0));
        strict_ack(&mut a, 203_000, 10_000, &[]);
        assert!(a.prr.is_none());
        assert_eq!(a.congestion.cwnd(), a.congestion.ssthresh());
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
//= type=test
//= reason=Current entry ACK is processed; ending ACK clears PRR without running its per-ACK steps, before ordinary output. No deferred causative ACK replay; timer/default trace asserts that separately.
//# On every ACK starting or during fast recovery, excluding the ACK that
//# concludes a PRR episode, PRR executes the following steps.
//= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
//= type=test
//= reason=strict_ack independently checks per-ACK byte window and credit; shrinking nonzero rwnd clips committed output without consuming unsent credit. Normal supported TCP window range is bounded by MAX_WINDOW.
//# cwnd = inflight + SndCnt
//= https://www.rfc-editor.org/rfc/rfc9937#section-6.3
//= type=test
//= reason=Committed active-PRR payload increments out by actual bytes; timer-entry reservations charge accepted fragments and discard unused admission after the repair. Failed encoding changes neither. Strict mode cancels PRR before persist; legacy probe bypass is excluded.
//# On any data transmission or retransmission, PRR executes the
//# following:
//#
//#    prr_out += (data sent)
//= https://www.rfc-editor.org/rfc/rfc9937#section-6.4
//= type=test
//= reason=Ending ACK sets cwnd to episode target even with short output or window stall; no-SACK completion independently asserts target and unchanged episode counters.
//# On the completion of a PRR episode, PRR executes the following:
//#
//#    cwnd = ssthresh
fn rfc9937_safe_ack_short_output_window_stall_and_ending_ack() {
    for iss in [0, u32::MAX - 4999] {
        let mut a = rack_flight(iss);
        a.write(&[0x66; 10_000]).unwrap();
        strict_ack(&mut a, 200_000, 0, &[(7000, 10_000)]);
        assert_eq!(a.prr.unwrap().credit(), 3000); // Non-advancing, unsafe.
        prr_packet(&mut a, 200_000);
        strict_ack(&mut a, 201_000, 1000, &[(7000, 10_000)]);
        assert_eq!(a.prr.unwrap().credit(), 4000); // Banked 3000 plus safe SMSS.
        assert_eq!(a.congestion.cwnd(), 4000);
        // Nonzero shrinking rwnd clips the actual retry and retains the remainder.
        let seq = a.receive.next();
        let una = a.snd_una;
        inject(&mut a, 202_000, seq, una, ACK, 250, &[]);
        let before = a.prr.unwrap();
        assert_eq!(
            a.transmit(202_000, &mut [0; 20]),
            Err(Error::OutputTooSmall)
        );
        assert_eq!(a.prr.unwrap().counters(), before.counters());
        a.config.send_ip_payload_limit = 270;
        let mut small = [0; 270];
        let size = a.transmit(202_000, &mut small).unwrap().unwrap();
        let sent = wire::parse(ip(tuple()), &small[..size])
            .unwrap()
            .payload
            .len();
        assert_eq!(sent, 250);
        assert_eq!(a.prr.unwrap().counters().2, before.counters().2 + 250);
        assert_eq!(a.prr.unwrap().credit(), before.credit() - 250);
        assert_eq!(a.prr.unwrap().counters(), (10_000, 4000, 1250));
        strict_ack(&mut a, 203_000, 10_000, &[]);
        assert!(a.prr.is_none());
        assert_eq!(a.congestion.cwnd(), 5000);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
//= type=test
//= reason=Nonzero delivery only; failure consumes nothing, successful short output prevents another floor. This test injects the equation state then exercises real transactional output; timer entry has a separate bounded first-repair contract.
//# if (prr_out is 0 AND SndCnt is 0) {
//#    // Force a fast retransmit upon entering recovery
//#    SndCnt = SMSS
//# }
fn rfc9937_forced_credit_failed_and_short_output_does_not_force_again() {
    let mut a = rack_flight(0);
    strict_ack(&mut a, 200_000, 0, &[(7000, 8000)]);
    a.timeout(225_000).unwrap();
    // Exercise the forced count through the real transactional output path.
    a.prr.as_mut().unwrap().acknowledge(1, 5000, 5000, false);
    let before = a.prr.unwrap();
    assert_eq!(before.credit(), 1000);
    assert_eq!(
        a.transmit(225_000, &mut [0; 20]),
        Err(Error::OutputTooSmall)
    );
    strict_ack(&mut a, 226_000, 0, &[(7000, 8000)]);
    assert_eq!(a.prr.unwrap().counters(), before.counters());
    assert_eq!(a.prr.unwrap().credit(), 1000);
    a.config.send_ip_payload_limit = 270;
    let mut small = [0; 270];
    let size = a.transmit(226_000, &mut small).unwrap().unwrap();
    assert_eq!(
        wire::parse(ip(tuple()), &small[..size])
            .unwrap()
            .payload
            .len(),
        250
    );
    assert_eq!(a.prr.unwrap().credit(), 750);
    assert_eq!(a.prr.unwrap().counters().2, 250);
    a.prr.as_mut().unwrap().acknowledge(1, 6000, 5000, false);
    assert_eq!(a.prr.unwrap().credit(), 0);
}

#[test]
fn rfc9937_negotiated_sack_bare_duplicates_do_not_estimate_delivery() {
    for iss in [0, u32::MAX - 4999] {
        let mut a = rack_flight(iss);
        a.config.rack = false;
        rack_sack(&mut a, 200_000, 1000, &[]); // Clear the first-flight guard.
        for _ in 0..3 {
            rack_sack(&mut a, 201_000, 1000, &[]);
        }
        assert!(a.prr.is_some() && a.sack_recovery.is_none());
        assert_eq!(a.prr.unwrap().counters(), (9000, 0, 0));
        assert_eq!(a.prr.unwrap().credit(), 0);
        assert_eq!(a.transmit(201_000, &mut [0; 1500]), Ok(None));
        rack_sack(&mut a, 202_000, 1000, &[(7000, 8000)]);
        assert_eq!(a.prr.unwrap().counters(), (9000, 1000, 0));
        assert_eq!(a.prr.unwrap().credit(), 500);
        assert_eq!(a.congestion.cwnd(), 7500);
        assert_eq!(
            prr_packet(&mut a, 202_000),
            (a.iss.wrapping_add(1001).0, 500)
        );
        assert_eq!(a.prr.unwrap().counters(), (9000, 1000, 500));
        rack_sack(&mut a, 203_000, 10_000, &[]);
        assert!(a.prr.is_none());
        assert_eq!(a.congestion.cwnd(), 4500);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
//= type=test
//= reason=Repeated extraneous duplicates cannot increase delivered above 10000-byte episode RecoverFS; capped ACK preserves counters, credit and cwnd, through wrap.
//# As a mitigation, if not using SACK, then PRR
//# disallows incrementing DeliveredData when the total bytes delivered
//# in a PRR episode would exceed the estimated data outstanding upon
//# entering recovery (RecoverFS).
fn rfc9937_no_sack_wire_delivery_cap_zero_ack_and_completion() {
    for (iss, zero_window) in [
        (0, false),
        (u32::MAX - 4999, false),
        (0, true),
        (u32::MAX - 4999, true),
    ] {
        let cfg = ConnectionConfig {
            prr: true,
            initial_window: InitialWindow::Iw10,
            ..config(65_536, 1000)
        };
        let mut a = Connection::active(tuple(), cfg.clone(), iss, 0).unwrap();
        let syn = packet(&mut a, 0);
        let syn = wire::parse(ip(tuple()), &syn).unwrap();
        let mut b = Connection::passive(reverse(tuple()), cfg, 900, 0, &syn).unwrap();
        deliver(&mut b, &mut a, 100_000);
        deliver(&mut a, &mut b, 100_000);
        // Clear the independent first-flight NewReno guard.
        a.write(&[0x55; 1000]).unwrap();
        deliver(&mut a, &mut b, 100_001);
        b.immediate_ack();
        deliver(&mut b, &mut a, 100_002);
        assert!(!a.sack_receive && !a.sack_send);
        a.write(&[0x55; 10_000]).unwrap();
        for _ in 0..10 {
            packet(&mut a, 100_003);
        }
        let base = a.snd_una;
        let seq = a.receive.next();
        let window = (a.snd_wnd >> a.peer_scale) as u16;
        for _ in 0..3 {
            inject(&mut a, 200_000, seq, base, ACK, window, &[]);
        }
        assert!(a.sack_recovery.is_none() && a.prr.is_some());
        assert_eq!(a.prr.unwrap().counters(), (10_000, 1000, 0));
        assert_eq!(a.congestion.cwnd(), 8000 + a.prr.unwrap().credit());
        let before = a.prr.unwrap();
        assert_eq!(
            a.transmit(200_000, &mut [0; 20]),
            Err(Error::OutputTooSmall)
        );
        assert_eq!(a.prr.unwrap().counters(), before.counters());
        a.config.send_ip_payload_limit = 270;
        let mut small = [0; 270];
        let size = a.transmit(200_000, &mut small).unwrap().unwrap();
        let retry = wire::parse(ip(tuple()), &small[..size]).unwrap();
        assert_eq!((retry.header.sequence, retry.payload.len()), (base.0, 250));
        assert_eq!(a.prr.unwrap().counters().2, 250);
        assert_eq!(a.rack.pipe(), 9250); // Only the committed part re-enters flight.
        a.config.send_ip_payload_limit = 1500;
        let retry = prr_packet(&mut a, 200_000);
        assert_eq!(
            retry,
            (base.wrapping_add(250).0, (before.credit() - 250) as usize)
        );
        let prior_cwnd = a.congestion.cwnd();
        // Cumulative progress deducts the preceding duplicate's estimate.
        inject(
            &mut a,
            200_001,
            seq,
            base.wrapping_add(1000),
            ACK,
            window,
            &[],
        );
        assert_eq!(a.prr.unwrap().counters().1, 1000);
        assert_eq!(a.congestion.cwnd(), prior_cwnd);
        for _ in 0..20 {
            inject(
                &mut a,
                200_002,
                seq,
                base.wrapping_add(1000),
                ACK,
                window,
                &[],
            );
        }
        assert_eq!(a.prr.unwrap().counters().1, 10_000);
        let before = a.prr.unwrap();
        let cwnd = a.congestion.cwnd();
        inject(
            &mut a,
            200_003,
            seq,
            base.wrapping_add(1000),
            ACK,
            window,
            &[],
        );
        assert_eq!(a.prr.unwrap().counters(), before.counters());
        assert_eq!(a.prr.unwrap().credit(), before.credit());
        assert_eq!(a.congestion.cwnd(), cwnd); // No Reno inflation on capped delivery.
        assert_eq!(a.prr.unwrap().counters(), (10_000, 10_000, 500));
        if zero_window {
            inject(&mut a, 200_004, seq, base.wrapping_add(1000), ACK, 0, &[]);
            assert!(a.prr.is_none() && !a.congestion.in_recovery());
            assert_eq!(a.congestion.cwnd(), a.congestion.ssthresh());
            let deadline = a.rto_deadline.unwrap();
            a.timeout(deadline).unwrap();
            assert!(a.probe_pending);
            assert_eq!(
                a.transmit(deadline, &mut [0; 20]),
                Err(Error::OutputTooSmall)
            );
            let bytes = packet(&mut a, deadline);
            assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload.len(), 1);
            inject(
                &mut a,
                deadline + 1,
                seq,
                base.wrapping_add(1000),
                ACK,
                window,
                &[],
            );
            for _ in 0..3 {
                inject(
                    &mut a,
                    deadline + 2,
                    seq,
                    base.wrapping_add(1000),
                    ACK,
                    window,
                    &[],
                );
            }
            assert!(a.prr.is_none() && !a.congestion.in_recovery());
            continue;
        }
        inject(
            &mut a,
            200_004,
            seq,
            base.wrapping_add(10_000),
            ACK,
            window,
            &[],
        );
        assert!(a.prr.is_none());
        assert_eq!(a.congestion.cwnd(), a.congestion.ssthresh());
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9937#section-5
//= type=test
//= reason=Opt-in prr=true/rack=true composes PRR with modified RACK loss recovery; lost-copy ACK and timer detection preserve the active episode and target. Default prr=false is not evidence of enabling PRR by default.
//# Because of the
//# performance properties of RACK-TLP, including resilience to tail
//# loss, reordering, and lost retransmissions, it is RECOMMENDED that
//# PRR is implemented together with RACK-TLP loss recovery [RFC8985].
//= https://www.rfc-editor.org/rfc/rfc9937#section-6.1
//= type=test
//= reason=Rfc9937 only: lost retransmission detection preserves initial episode counters; entry and no-SACK traces independently assert initialization on actual congestion responses.
//# At the beginning of a congestion control response episode initiated
//# by the congestion control algorithm, a data sender using PRR MUST
//# initialize the PRR state.
//= https://www.rfc-editor.org/rfc/rfc9937#section-6.4
//= type=test
//= reason=Lost-copy ACK/timer detection alone does not initiate a congestion response or end active PRR; boundary ACK traces separately assert completion and unchanged ending counters.
//# A PRR episode ends upon either completing fast recovery or before
//# initiating a new PRR episode due to a new congestion control response
//# episode.
fn rfc9937_lost_retransmission_ack_and_timer_preserve_episode() {
    for iss in [0, u32::MAX - 4999] {
        let mut a = rack_flight(iss);
        strict_ack(&mut a, 200_000, 0, &[(7000, 10_000)]);
        for _ in 0..3 {
            prr_packet(&mut a, 200_000);
        }
        strict_ack(&mut a, 300_000, 0, &[(1000, 2000), (7000, 10_000)]);
        assert_eq!(a.prr.unwrap().counters(), (10_000, 4000, 3000));
        assert_eq!(a.congestion.ssthresh(), 5000);
        let before = a.prr.unwrap();
        strict_ack(&mut a, 300_001, 0, &[(1000, 2000), (7000, 10_000)]);
        assert_eq!(a.prr.unwrap().counters(), before.counters());
        assert_eq!(a.congestion.ssthresh(), 5000);
        prr_packet(&mut a, 300_001);
        // A later retransmission's ACK makes the replacement head eligible
        // for loss detection; the reordering timer completes that detection.
        strict_ack(&mut a, 301_000, 0, &[(1000, 2000), (6000, 10_000)]);
        assert_eq!(prr_packet(&mut a, 301_000).0, a.iss.wrapping_add(3001).0);
        strict_ack(
            &mut a,
            450_000,
            0,
            &[(1000, 2000), (3000, 4000), (6000, 10_000)],
        );
        assert_eq!(a.congestion.ssthresh(), 5000);
        let deadline = a.rack.deadline.unwrap();
        let before_timer = a.prr.unwrap();
        assert_eq!(a.rack.pipe(), 1000);
        assert!(a.rack.counts().retransmitted > 0);
        a.timeout(deadline).unwrap();
        assert_eq!(a.congestion.ssthresh(), 5000);
        assert_eq!(a.prr.unwrap().counters(), before_timer.counters());
        assert_eq!(a.prr.unwrap().credit(), before_timer.credit()); // No ACK replay.
        assert_eq!(a.rack.pipe(), 0);
    }
}

#[test]
fn rfc9937_ecn_echo_does_not_repeat_loss_response_or_mint_credit() {
    let mut a = rack_flight(0);
    a.ecn_sent_setup = true;
    a.ecn_peer_setup = true;
    a.ecn_peer_plain = false;
    assert!(a.ecn_feedback());
    strict_ack(&mut a, 200_000, 0, &[(7000, 10_000)]);
    let before = a.prr.unwrap();
    let target = a.congestion.ssthresh();
    let cwnd = a.congestion.cwnd();
    let seq = a.receive.next();
    let una = a.snd_una;
    for now in 201_000..201_004 {
        inject(&mut a, now, seq, una, ACK | ECE, 65_535, &[]);
        assert_eq!(a.prr.unwrap().counters(), before.counters());
        assert_eq!(a.prr.unwrap().credit(), before.credit());
        assert_eq!(a.congestion.ssthresh(), target);
        assert_eq!(a.congestion.cwnd(), cwnd);
    }
    prr_packet(&mut a, 201_004);
    strict_ack(&mut a, 201_005, 1000, &[(7000, 10_000)]);
    assert_eq!(a.prr.unwrap().credit(), 4000);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
//= type=test
//= reason=Signed scoreboard delta prevents recounting SACKed bytes when cumulative ACK trims them; current advancing entry ACK and wrapped sequence space are asserted. Bare negotiated-SACK duplicates grant no estimates in rfc9937_negotiated_sack_bare_duplicates_do_not_estimate_delivery.
//# With SACK, DeliveredData can be computed precisely as the
//# change in SND.UNA, plus the signed change in quantity of data marked
//# SACKed in the scoreboard.  Thus, in the special case when there are
//# no SACKed sequence ranges in the scoreboard before or after the ACK,
//# DeliveredData is the change in SND.UNA.
fn strict_prr_default_timer_entry_and_current_ack_epoch() {
    assert!(!ConnectionConfig::default().prr);
    for iss in [0, u32::MAX - 4999] {
        let mut a = rack_flight(iss);
        strict_ack(&mut a, 200_000, 0, &[(7000, 8000)]);
        assert!(a.prr.is_none()); // Outside recovery: SACK is detection evidence.
        a.timeout(225_000).unwrap();
        assert_eq!(a.prr.unwrap().counters(), (9000, 0, 0));
        assert_eq!(a.prr.unwrap().credit(), 1000);
        assert_eq!(a.congestion.cwnd(), a.rack.pipe() + 1000);
        assert!(a.congestion.recovery_target() > a.congestion.cwnd());
        assert_eq!(prr_packet(&mut a, 225_000), (iss.wrapping_add(1), 1000));
        assert_eq!(a.prr.unwrap().counters(), (9000, 0, 1000));
        assert_eq!(a.transmit(225_000, &mut [0; 1500]), Ok(None));
        strict_ack(&mut a, 226_000, 0, &[(7000, 8000)]);
        assert_eq!(a.prr.unwrap().credit(), 0); // No old ACK replay/floor.
        strict_ack(&mut a, 227_000, 0, &[(7000, 9000)]);
        assert_eq!(a.prr.unwrap().counters().1, 1000);
        prr_packet(&mut a, 227_000);
        assert_eq!(a.prr.unwrap().counters().2, 2000);
        strict_ack(&mut a, 228_000, 8000, &[(8000, 9000)]);
        assert_eq!(a.prr.unwrap().counters().1, 8000); // signed SACK trimming
        let rto = a.rto_deadline.unwrap();
        a.timeout(rto).unwrap();
        assert!(a.prr.is_none()); // No delivery carries to another epoch.

        let mut a = rack_flight(iss);
        a.config.rack = false;
        strict_ack(&mut a, 200_000, 1000, &[(4000, 10_000)]);
        assert_eq!(a.prr.unwrap().counters(), (10_000, 7000, 0));
        // Current advancing entry ACK is included in RecoverFS and delivery.
        prr_packet(&mut a, 200_000);
        strict_ack(&mut a, 200_001, 1000, &[(4000, 10_000)]);
    }
}

#[test]
fn strict_prr_zero_window_cancels_epoch_before_persist_and_rearms_rto() {
    for iss in [0, u32::MAX - 4999] {
        let mut a = rack_flight(iss);
        strict_ack(&mut a, 200_000, 0, &[(7000, 10_000)]);
        while a.prr.unwrap().credit() >= 1000 {
            prr_packet(&mut a, 200_000);
        }
        let point = a.sack_recovery.unwrap().recovery_point;
        let target = a.congestion.ssthresh();
        let seq = a.receive.next();
        let una = a.snd_una;
        inject(&mut a, 201_000, seq, una, ACK, 0, &[]);
        assert!(a.prr.is_none());
        assert!(a.sack_recovery.is_none());
        assert_eq!(a.sack_guard, Some(point));
        assert_eq!(a.congestion.cwnd(), target);
        assert_eq!(a.rack.deadline, None);
        // Outstanding data probes on the selected RTO; only unsent data
        // uses the separate persist timer.
        assert_eq!(a.persist_deadline, None);
        let persist = a.rto_deadline.unwrap();
        a.timeout(persist).unwrap();
        assert_eq!(
            a.transmit(persist, &mut [0; 20]),
            Err(Error::OutputTooSmall)
        );
        assert!(a.probe_pending);
        let bytes = packet(&mut a, persist);
        assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload.len(), 1);
        assert!(a.rto_deadline.is_some());
        assert!(a.persist_deadline.is_none());
        // Responsive persist must stay live even across the user timeout.
        inject(&mut a, persist + 1, seq, una, ACK, 0, &[]);
        assert!(a.user_deadline().is_none());
        inject(&mut a, persist + 2, seq, una, ACK, 65_535, &[]);
        assert!(a.persist_deadline.is_none());
        assert!(a.rto_deadline.is_some());
        assert!(a.prr.is_none());
        assert!(!a.start_sack_recovery()); // Old flight cannot reenter.
        let rto = a.rto_deadline.unwrap();
        a.timeout(rto).unwrap();
        let bytes = packet(&mut a, rto);
        // The latest one-byte probe split the head transmission. RTO
        // retains that copy boundary instead of including its suffix.
        assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload.len(), 1);
    }
}

#[test]
fn strict_prr_full_minimal_isolated_and_burst_loss_traces() {
    // Nonpaced equation oracle (config helper): burst here describes loss,
    // not the default paced output policy tested by pacing_recovery_budget_exit_and_control.
    // Bulk queued data, no rwnd/application stall, losses below half the
    // flight. RACK's RFC 8985 modified pipe, not literal RFC 6675 NextSeg.
    // Measure the boundary-ACK handoff separately: output after exit is
    // ordinary reduced-cwnd output, NOT an active-epoch PRR proof. The
    // trace verifies that it fills only the equation's remaining headroom.
    for iss in [0, u32::MAX - 4999] {
        for losses in [
            &[0][..],
            &[0, 3][..],
            &[0, 1][..],
            &[0, 1, 2][..],
            &[0, 1, 2, 3, 4][..],
        ] {
            let mut final_windows = Vec::new();
            for reordered in [false, true] {
                let mut a = rack_flight(iss);
                a.write(&[0x66; 20_000]).unwrap();
                let base = a.send_base;
                let mut received = [false; 30_000];
                let mut pending = Vec::new();
                let mut now = 200_000;
                let mut active_outputs = 0;
                let mut voluntary = 0;
                let mut undone = 0;
                let mut below_target = false;
                let mut target: u32 = 0;
                // Deliver originals in order, except dropped segments. Each
                // ACK reports the receiver's actual union (at most four ranges).
                for i in 0..10 {
                    if !losses.contains(&i) {
                        pending.push((i * 1000, (i + 1) * 1000, 0));
                    }
                }
                if reordered {
                    // Three later originals arrive first and cause premature
                    // loss inference. Then the delayed original corrects it.
                    let original = pending.remove(0);
                    pending.insert(3, original);
                }
                for (i, event) in pending.iter_mut().enumerate() {
                    event.2 = 200_000 + i as u64 * 1000;
                }
                let mut index = 0;
                while index < pending.len() {
                    let (left, right, arrival) = pending[index];
                    index += 1;
                    now = now.max(arrival);
                    a.timeout(now).unwrap();
                    received[left..right].fill(true);
                    let ack = received.iter().take_while(|&&r| r).count();
                    let mut blocks = Vec::new();
                    let mut j = ack;
                    while j < received.len() {
                        if !received[j] {
                            j += 1;
                            continue;
                        }
                        let left = j;
                        while j < received.len() && received[j] {
                            j += 1;
                        }
                        blocks.push((left as u32, j as u32));
                    }
                    assert!(blocks.len() <= 4);
                    // The boundary ACK terminates recovery before output. Measure
                    // its actual pipe and remaining equation budget explicitly;
                    // do not mistake cwnd deflation for actual convergence.
                    let boundary = a.sack_recovery.map_or(usize::MAX, |r| {
                        r.recovery_point.distance_from(base) as usize
                    });
                    if ack >= boundary {
                        let before_pipe = a.rack.pipe();
                        let delivered = a
                            .scoreboard
                            .unsacked_bytes(a.snd_una, base.wrapping_add(boundary as u32));
                        let final_pipe = before_pipe - delivered;
                        let (_, epoch_delivery, epoch_out) = a.prr.unwrap().counters();
                        let remaining = u64::from(target.saturating_sub(final_pipe));
                        strict_ack(&mut a, now, ack as u32, &blocks);
                        assert!(a.prr.is_none());
                        assert_eq!(a.congestion.cwnd(), target);
                        assert_eq!(a.rack.pipe(), final_pipe);
                        let mut handoff_output = 0;
                        let mut output = [0; 1500];
                        while let Some(size) = a.transmit(now, &mut output).unwrap() {
                            handoff_output += wire::parse(ip(tuple()), &output[..size])
                                .unwrap()
                                .payload
                                .len() as u64;
                        }
                        assert!(handoff_output <= remaining);
                        voluntary += u64::from(delivered).saturating_sub(handoff_output);
                        undone += handoff_output.saturating_sub(u64::from(delivered));
                        assert_eq!(
                            voluntary - undone,
                            epoch_delivery + u64::from(delivered) - epoch_out - handoff_output
                        );
                        final_windows.push((a.rack.pipe(), target));
                        assert_eq!(a.rack.pipe(), target, "losses={losses:?}");
                        assert_eq!(a.flight(), target, "actual outstanding bytes: {losses:?}");
                        assert_eq!(a.congestion.cwnd(), target);
                        break;
                    }
                    let before_delivery = a.prr.map_or(0, |p| p.counters().1);
                    strict_ack(&mut a, now, ack as u32, &blocks);
                    if a.prr.is_some() {
                        let ack_delivery = a.prr.unwrap().counters().1 - before_delivery;
                        target = a.congestion.ssthresh();
                        let pipe = a.rack.pipe();
                        below_target |= pipe < target;
                        let before_out = a.prr.unwrap().counters().2;
                        loop {
                            let before = a.prr.unwrap();
                            // Poll until the actual selector says no output;
                            // a partial-byte retransmission may use sub-MSS
                            // credit even though new data would have to bank it.
                            let attempt = a.transmit(now, &mut [0; 20]);
                            assert_eq!(a.prr.unwrap().counters(), before.counters());
                            assert_eq!(a.prr.unwrap().credit(), before.credit());
                            if attempt == Ok(None) {
                                break;
                            }
                            assert_eq!(attempt, Err(Error::OutputTooSmall));
                            let wire = packet(&mut a, now);
                            let segment = wire::parse(ip(tuple()), &wire).unwrap();
                            let bytes = segment.payload.len();
                            assert!(bytes > 0 && bytes as u32 <= before.credit());
                            assert_eq!(
                                a.prr.unwrap().counters().2,
                                before.counters().2 + bytes as u64
                            );
                            let sent = Seq(segment.header.sequence).distance_from(base) as usize;
                            pending.push((sent, sent + bytes, now + 100_000));
                            active_outputs += 1;
                            let p = a.prr.unwrap();
                            assert!(p.counters().2 <= p.counters().1);
                        }
                        // Use actual ACK delivery and emitted bytes, including
                        // duplicate copies and banked catch-up, not fixed outputs.
                        let actual = a.prr.unwrap().counters().2 - before_out;
                        voluntary += ack_delivery.saturating_sub(actual);
                        undone += actual.saturating_sub(ack_delivery);
                    } else {
                        // The bulk sender also polls BEFORE PRR entry: real
                        // Limited Transmit packets extend RecoverFS/boundary.
                        // Their ACKs belong to this same receiver event queue.
                        let mut output = [0; 1500];
                        while let Some(size) = a.transmit(now, &mut output).unwrap() {
                            let segment = wire::parse(ip(tuple()), &output[..size]).unwrap();
                            let bytes = segment.payload.len();
                            if bytes != 0 {
                                let sent =
                                    Seq(segment.header.sequence).distance_from(base) as usize;
                                pending.push((sent, sent + bytes, now + 100_000));
                            }
                        }
                    }
                    assert!(now < 1_000_000);
                }
                assert!(a.prr.is_none(), "recovery did not finish: {losses:?}");
                assert!(active_outputs > 0);
                assert!(below_target);
                if losses.len() < 5 {
                    assert!(
                        voluntary > undone,
                        "losses={losses:?}, reordered={reordered}"
                    );
                } else {
                    // Five losses plus two pre-entry SACKs exhaust the
                    // reduction of the twelve-segment LT-extended flight:
                    // do not claim the conditional burst
                    // theorem for this case merely because the handoff fills cwnd.
                    assert_eq!(voluntary, undone);
                }
            }
            // Same delivery interval/loss pattern, corrected premature time
            // loss versus ordinary ordering: actual final window agrees.
            assert_eq!(final_windows.len(), 2);
            assert_eq!(final_windows[0], final_windows[1]);
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-9.2
//= type=test
//= reason=Strict PRR with modified RACK recovery: reordered originals, committed retransmissions and repeated copy loss exercise Rack::pipe and both credit branches. This is not literal RFC6675 Scoreboard::pipe evidence; the non-RACK ACK-driven trace covers that composition separately.
//# Therefore, the algorithm [RFC6675]
//# MUST NOT be used with RACK-TLP; instead, a modified recovery
//# algorithm that carefully addresses such a case is needed.
//= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
//= type=test
//= reason=Valid payload ledger: unsacked and not-needs_retransmit intervals count once; successful retransmission clears needs_retransmit for only emitted bytes. Exact reordered original, lost-copy and replacement pipe values are asserted. SYN/FIN sequence space is not payload data.
//# SACK-enabled connections using RACK-TLP loss detection
//# [RFC8985] or other loss detection algorithms MUST calculate inflight
//# by starting with SND.NXT - SND.UNA, subtracting out bytes SACKed in
//# the scoreboard, subtracting out bytes marked lost in the scoreboard,
//# and adding bytes in the scoreboard that have been retransmitted since
//# they were last marked lost.
//= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
//= type=test
//= reason=Uses selected estimator, not raw cumulative flight: RACK excludes lost and SACKed bytes and restores committed copies. RFC6675/non-SACK estimators have separate exact tests.
//# inflight = (estimated volume of in-flight data)
fn strict_prr_rack_pipe_reordered_originals_and_lost_retransmissions() {
    for iss in [0, u32::MAX - 4999] {
        let mut a = rack_flight(iss);
        strict_ack(&mut a, 200_000, 0, &[(7000, 8000)]);
        assert_eq!(a.rack.pipe(), 9000); // SACKed bytes excluded, originals live.
        a.timeout(225_000).unwrap();
        assert_eq!(a.rack.pipe(), 2000); // Seven premature time losses excluded.
        assert_eq!(a.prr.unwrap().credit(), 1000); // Separate timer-entry repair.
        // Reordered originals actually arrive. Loss assumptions do not add
        // delivery; each ACK adds only new scoreboard bytes and the equation
        // limits the emitted replacement. This is modified RACK recovery.
        strict_ack(&mut a, 226_000, 0, &[(3000, 4000), (7000, 8000)]);
        assert!(a.transport_info().reordering > 3);
        assert_eq!(a.rack.pipe(), 2000);
        prr_packet(&mut a, 226_000);
        assert_eq!(a.rack.pipe(), 3000); // The committed copy is in pipe.
        strict_ack(&mut a, 227_000, 0, &[(3000, 5000), (7000, 8000)]);
        assert_eq!(a.rack.pipe(), 3000);
        prr_packet(&mut a, 227_000);
        assert_eq!(a.rack.pipe(), 4000);

        let mut a = rack_flight(iss);
        strict_ack(&mut a, 200_000, 0, &[(7000, 10_000)]);
        assert_eq!(a.rack.pipe(), 0);
        for _ in 0..3 {
            prr_packet(&mut a, 200_000);
        }
        assert_eq!(a.rack.pipe(), 3000);
        strict_ack(&mut a, 300_000, 0, &[(1000, 2000), (7000, 10_000)]);
        assert_eq!(a.congestion.ssthresh(), 5000);
        assert_eq!(a.rack.pipe(), 1000); // SACKed copy + lost copy excluded.
        let (seq, _) = prr_packet(&mut a, 300_000);
        assert_eq!(seq, a.iss.wrapping_add(1).0); // Below HighRxt, not NextSeg.
        assert_eq!(a.rack.pipe(), 2000);
        strict_ack(&mut a, 400_000, 2000, &[(7000, 10_000)]);
        assert_eq!(a.congestion.ssthresh(), 5000); // Same copy-loss window.
        assert_eq!(a.rack.pipe(), 0);
        let (seq, _) = prr_packet(&mut a, 400_000);
        assert_eq!(seq, a.iss.wrapping_add(2001).0);
        assert_eq!(a.rack.pipe(), 1000);

        // With bulk new data, the same lost-copy event preserves the target
        // and accumulated delivery/output. CRB uses the current ACK's bytes
        // without a SafeACK bonus, even though pipe is below the target.
        let mut a = rack_flight(iss);
        a.write(&[0x66; 10_000]).unwrap();
        strict_ack(&mut a, 200_000, 0, &[(3000, 10_000)]);
        while a.prr.unwrap().credit() >= 1000 {
            prr_packet(&mut a, 200_000);
        }
        assert_eq!(a.rack.pipe(), 5000);
        strict_ack(&mut a, 300_000, 0, &[(1000, 2000), (3000, 10_000)]);
        assert_eq!(a.congestion.ssthresh(), 5000);
        assert_eq!(a.rack.pipe(), 3000);
        assert_eq!(a.prr.unwrap().counters(), (10_000, 8000, 5000));
        assert_eq!(a.prr.unwrap().credit(), 2000);
        assert_eq!(prr_packet(&mut a, 300_000).1, 1000);
        let rto = a.rto_deadline.unwrap();
        a.timeout(rto).unwrap();
        assert!(a.prr.is_none());
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9937#section-5
//= type=test
//= reason=Selected RFC6675 SACK, RACK and non-SACK NewReno compositions are covered separately by strict_prr_rack_pipe_reordered_originals_and_lost_retransmissions and rfc9937_no_sack_wire_delivery_cap_zero_ack_and_completion; no FACK claim.
//# Thus, PRR MAY be used in
//# conjunction with the loss detection algorithms specified or described
//# in the following documents: Reno [RFC5681], NewReno [RFC6582], SACK
//# [RFC6675], Forward Acknowledgment (FACK) [FACK], and Recent
//# Acknowledgment Tail Loss Probe (RACK-TLP) [RFC8985].
//= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
//= type=test
//= reason=rack=false, negotiated SACK and valid byte ledger: literal Scoreboard::pipe values and successful committed HighRxt are asserted, independently of the RACK estimator.
//# To
//# calculate inflight, connections with SACK enabled and using [RFC6675]
//# loss detection MAY use the "pipe" algorithm as specified in
//# [RFC6675].
fn strict_prr_nonrack_ack_driven_entry_and_scoreboard_pipe() {
    for iss in [0, u32::MAX - 4999] {
        for (acks, delivered, credit, pipe, recover_fs) in [
            // The first two ACKs are outside the epoch, not replayed.
            (
                vec![vec![(9000, 9001)], vec![(9000, 9002)], vec![(9000, 9003)]],
                1,
                1,
                9997,
                9998,
            ),
            // Three discontiguous ranges infer head loss on the first ACK.
            (
                vec![vec![(3000, 3001), (6000, 6001), (9000, 9001)]],
                3,
                2,
                6997,
                10_000,
            ),
            // More than 2*SMSS delivered infers loss; pipe is below target.
            (
                vec![vec![(7000, 8000)], vec![(7000, 9000)], vec![(7000, 10_000)]],
                1000,
                1000,
                0,
                8000,
            ),
        ] {
            let mut a = rack_flight(iss);
            a.config.rack = false;
            let base = a.snd_una;
            let point = a.data_high();
            for (index, blocks) in acks.iter().enumerate() {
                assert!(a.sack_recovery.is_none());
                strict_ack(&mut a, 200_000 + index as u64, 0, blocks);
                if index + 1 < acks.len() {
                    assert!(a.prr.is_none());
                    assert!(a.sack_recovery.is_none());
                }
            }
            let now = 200_000 + acks.len() as u64;
            let recovery = a.sack_recovery.unwrap();
            assert!(recovery.entry_pending);
            assert_eq!(recovery.recovery_point, point);
            assert_eq!(recovery.high_rxt, base);
            assert_eq!(recovery.rescue_rxt, None);
            assert_eq!(recovery.pipe, pipe);
            assert_eq!(a.recovery_pipe(base), pipe);
            assert_eq!(a.congestion.ssthresh(), 5000);
            assert_eq!(a.prr.unwrap().counters(), (recover_fs, delivered, 0));
            assert_eq!(a.prr.unwrap().credit(), credit);

            assert_eq!(a.transmit(now, &mut [0; 20]), Err(Error::OutputTooSmall));
            let retry = a.sack_recovery.unwrap();
            assert!(retry.entry_pending);
            assert_eq!(retry.high_rxt, base);
            assert_eq!(retry.rescue_rxt, None);
            assert_eq!(retry.pipe, pipe);
            assert_eq!(a.prr.unwrap().counters(), (recover_fs, delivered, 0));
            assert_eq!(a.prr.unwrap().credit(), credit);
            // RFC6675 step 4.3 selects HighACK+1 and permits sub-SMSS.
            assert_eq!(prr_packet(&mut a, now), (base.0, credit as usize));
            let committed = a.sack_recovery.unwrap();
            let end = base.wrapping_add(credit);
            assert!(!committed.entry_pending);
            assert_eq!(committed.high_rxt, end);
            assert_eq!(committed.rescue_rxt, Some(end));
            assert_eq!(committed.recovery_point, point);
            assert_eq!(committed.pipe, pipe + credit);
            assert_eq!(a.recovery_pipe(end), pipe + credit);
            assert_eq!(
                a.prr.unwrap().counters(),
                (recover_fs, delivered, u64::from(credit))
            );
            assert_eq!(a.prr.unwrap().credit(), 0);
            assert_eq!(a.transmit(now, &mut [0; 1500]), Ok(None));

            strict_ack(&mut a, now + 1, 0, acks.last().unwrap());
            assert_eq!(
                a.prr.unwrap().counters(),
                (recover_fs, delivered, u64::from(credit))
            );
            assert_eq!(a.prr.unwrap().credit(), 0); // No repeated-ACK floor.
            assert_eq!(a.sack_recovery.unwrap().pipe, pipe + credit);
            assert_eq!(a.transmit(now + 1, &mut [0; 1500]), Ok(None));
            assert_eq!(
                a.prr.unwrap().counters(),
                (recover_fs, delivered, u64::from(credit))
            );
            assert_eq!(a.prr.unwrap().credit(), 0);
            strict_ack(&mut a, now + 2, 10_000, &[]);
            assert_eq!(a.snd_una, point);
            assert!(a.sack_recovery.is_none());
            assert!(a.prr.is_none());
            assert_eq!(a.congestion.cwnd(), 5000);
            assert_eq!(a.recovery_pipe(end), 0);
            assert_eq!(a.transmit(now + 2, &mut [0; 1500]), Ok(None));
        }
    }
}

#[test]
fn strict_prr_capacity_backed_ledger_preserves_credit_past_old_limit() {
    let mut a = rack_flight(0);
    strict_ack(&mut a, 200_000, 0, &[(3000, 10_000)]);
    for _ in 0..3 {
        prr_packet(&mut a, 200_000);
    }
    for _ in 0..256 {
        a.write(&[0x66]).unwrap();
        let before = a.prr.unwrap();
        let bytes = packet(&mut a, 200_000);
        let count = wire::parse(ip(tuple()), &bytes).unwrap().payload.len() as u32;
        assert_eq!(count, 1);
        assert!(count <= before.credit());
        assert!(before.counters().2 + u64::from(count) <= before.counters().1);
        assert!(a.rack.valid());
        assert_eq!(a.prr.unwrap().counters().2, before.counters().2 + 1);
    }
    assert!(a.prr.is_some());
}

#[test]
fn rack_single_sacked_segment_uses_same_rtt_window_for_four_and_ten_packets() {
    for iss in [100, u32::MAX - 4999] {
        for (segments, sacked_index) in [(4, 3), (10, 7)] {
            let cfg = ConnectionConfig {
                sack: true,
                rack: true,
                prr: true,
                initial_window: InitialWindow::Iw10,
                ..config(65_536, 1000)
            };
            let mut a = Connection::active(tuple(), cfg.clone(), iss, 0).unwrap();
            let bytes = packet(&mut a, 0);
            let syn = wire::parse(ip(tuple()), &bytes).unwrap();
            let mut b = Connection::passive(reverse(tuple()), cfg, 900, 0, &syn).unwrap();
            deliver(&mut b, &mut a, 100_000);
            deliver(&mut a, &mut b, 100_000);
            a.write(&vec![0x55; segments * 1000]).unwrap();
            for _ in 0..segments {
                packet(&mut a, 100_000);
            }
            rack_sack(
                &mut a,
                200_000,
                0,
                &[(sacked_index * 1000, (sacked_index + 1) * 1000)],
            );
            // RFC 8985: one SACKed segment and no observed reordering use
            // min_RTT/4. Flight length changes the loss count, not this delay.
            assert_eq!(a.rtt.srtt(), Some(100_000));
            assert_eq!(a.rack.deadline, Some(225_000));
            assert_eq!(a.next_deadline(), Some(225_000));
            a.timeout(224_999).unwrap();
            assert!(!a.transport_info().recovery);
            assert_eq!(a.transmit(224_999, &mut [0; 1500]), Ok(None));
            a.timeout(225_000).unwrap();
            assert!(a.transport_info().recovery);
            let bytes = packet(&mut a, 225_000);
            let retransmit = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(retransmit.header.sequence, iss.wrapping_add(1));
            assert_eq!(retransmit.payload.len(), 1000);
        }
    }
}

fn rack_sack(a: &mut Connection, now: u64, ack_offset: u32, blocks: &[(u32, u32)]) {
    let base = a.iss.wrapping_add(1);
    let blocks: Vec<_> = blocks
        .iter()
        .map(|&(l, r)| (base.wrapping_add(l).0, base.wrapping_add(r).0))
        .collect();
    inject_sack(
        a,
        now,
        a.receive.next(),
        base.wrapping_add(ack_offset),
        ACK,
        65_535,
        &[],
        &blocks,
    );
}

#[test]
fn cubic_two_rtt_samples_cap_pto_before_rto() {
    for peer_delay in [0, 200_000, 499_999] {
        let cfg = ConnectionConfig {
            sack: true,
            rack: true,
            prr: true,
            tlp: true,
            timestamps: true,
            initial_window: InitialWindow::Iw10,
            congestion_algorithm: CongestionAlgorithm::Cubic,
            peer_max_ack_delay_us: peer_delay,
            rto_min_us: 200_000,
            ..config(65_536, 1000)
        };
        // Match packetdrill: passive sender, no peer timestamp offer.
        let mut peer_cfg = cfg.clone();
        peer_cfg.timestamps = false;
        let mut peer = Connection::active(tuple(), peer_cfg, 0, 0).unwrap();
        let syn_bytes = packet(&mut peer, 0);
        let syn = wire::parse(ip(tuple()), &syn_bytes).unwrap();
        let mut sender = Connection::passive(reverse(tuple()), cfg, 0, 0, &syn).unwrap();
        let synack_bytes = packet(&mut sender, 0);
        let synack = wire::parse(ip(sender.tuple()), &synack_bytes).unwrap();
        peer.input(100_000, &synack).unwrap();
        deliver(&mut peer, &mut sender, 100_000);
        assert!(!sender.timestamps);
        // Exactly one 100ms sample: RTTVAR = R/2.
        assert_eq!(
            (sender.rtt.srtt(), sender.rtt.variance(), sender.rto()),
            (Some(100_000), 50_000, 300_000)
        );

        sender.write(&[0x55; 1000]).unwrap();
        packet(&mut sender, 100_000);
        rack_sack(&mut sender, 200_000, 1000, &[]);
        // Ordinary and RACK candidates on the same ACK count only once:
        // a third 100ms sample would leave RTTVAR at 28125.
        assert_eq!(
            (sender.rtt.srtt(), sender.rtt.variance(), sender.rto()),
            (Some(100_000), 37_500, 250_000)
        );
        assert_eq!(sender.congestion.cwnd(), 10_000);
        sender.write(&[0x66; 1000]).unwrap();
        packet(&mut sender, 200_000);
        let pto = 200_000 + (200_000 + peer_delay).min(250_000);
        assert_eq!(sender.rto_deadline, Some(450_000));
        assert_eq!(sender.loss_timer, Some((LossTimer::Pto, pto)));
        sender.timeout(pto - 1).unwrap();
        assert!(!sender.tlp_pending);
        sender.timeout(pto).unwrap();
        assert!(sender.tlp_pending);
        assert!(!sender.retx_pending);
        let probe_bytes = packet(&mut sender, pto);
        let probe = wire::parse(ip(sender.tuple()), &probe_bytes).unwrap();
        assert_eq!((probe.header.sequence, probe.payload.len()), (1001, 1000));
        assert_eq!(sender.congestion.cwnd(), 10_000);
        assert_eq!(sender.rto(), 250_000);
        assert_eq!(sender.loss_timer, Some((LossTimer::Rto, pto + 250_000)));
        sender.timeout(pto + 250_000).unwrap();
        assert!(sender.retx_pending);
        assert_eq!(sender.congestion.cwnd(), 1000);
        assert_eq!(sender.rto(), 500_000);
        let retry_bytes = packet(&mut sender, pto + 250_000);
        let retry = wire::parse(ip(sender.tuple()), &retry_bytes).unwrap();
        assert_eq!((retry.header.sequence, retry.payload.len()), (1001, 1000));
        assert_eq!(
            (sender.rtt.srtt(), sender.rtt.variance()),
            (Some(100_000), 37_500)
        );
    }
}

fn tlp_baseline_pair(iss: u32) -> (Connection, Connection) {
    let cfg = ConnectionConfig {
        sack: true,
        rack: true,
        prr: true,
        tlp: true,
        // This helper fixes the RFC8985 baseline for recovery/ECT/PRR
        // equation traces. Default-margin behavior has independent real
        // wire tests in pto_margin, plus socket/packetdrill regressions.
        tlp_timer_margin_us: 0,
        peer_max_ack_delay_us: 0,
        rto_min_us: 200_000,
        ..config(65_536, 1000)
    };
    let mut a = Connection::active(tuple(), cfg.clone(), iss, 0).unwrap();
    let bytes = packet(&mut a, 0);
    let syn = wire::parse(ip(tuple()), &bytes).unwrap();
    let mut b = Connection::passive(reverse(tuple()), cfg, 900, 0, &syn).unwrap();
    deliver(&mut b, &mut a, 100_000);
    deliver(&mut a, &mut b, 100_000);
    assert_eq!(a.rto(), 300_000);
    assert!(a.tlp_fresh_rtt);
    (a, b)
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
//= type=test
//= reason=Partial/repeated SACK does not mint retransmission credit after initial entry output.
//# A segment marked
//# as lost by RACK-TLP MUST NOT be retransmitted until congestion
//# control deems this appropriate.
fn tlp_partial_sack_then_full_tail_delivery_cannot_inflate_prr_credit() {
    for iss in [0, u32::MAX - 1999] {
        let (mut a, _) = tlp_baseline_pair(iss);
        let base = a.send_base;
        a.write(&[0x55; 4000]).unwrap();
        for _ in 0..4 {
            packet(&mut a, 100_000);
        }
        rack_sack(&mut a, 200_000, 0, &[(3500, 4000)]);
        assert!(a.prr.is_none());
        a.timeout(300_000).unwrap();
        let bytes = packet(&mut a, 300_000);
        let p = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(p.header.sequence, base.wrapping_add(3000).0);
        assert_eq!(p.payload.len(), 1000);
        rack_sack(&mut a, 400_000, 0, &[(3000, 4000)]);
        assert!(a.sack_recovery.is_some());
        assert_eq!(a.prr.unwrap().counters().1, 500);
        assert_eq!(a.prr.unwrap().credit(), 500); // Only this ACK's new delivery.
        packet(&mut a, 400_000);
        assert_eq!(a.prr.unwrap().credit(), 0);
        rack_sack(&mut a, 400_001, 0, &[(0, 500), (3000, 4000)]);
        // The new head half supplies exactly 500 further bytes of delivery.
        assert_eq!(a.prr.unwrap().counters().1, 1000);
        assert_eq!(a.prr.unwrap().counters().2, 500);
        assert_eq!(a.prr.unwrap().credit(), 500);
        let bytes = packet(&mut a, 400_001);
        assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload.len(), 500);
        assert_eq!(a.prr.unwrap().credit(), 0);
        rack_sack(&mut a, 400_002, 0, &[(0, 500), (3000, 4000)]);
        assert_eq!(a.prr.unwrap().counters(), (3500, 1000, 1000));
        assert_eq!(a.transmit(400_002, &mut [0; 1500]), Ok(None));
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.4.2
//= type=test
//= reason=Asserts TLP reduction and recovery of later original loss without a second same-flight reduction.
//# The sender then
//# SHOULD invoke a congestion control response equivalent to a fast
//# recovery.
//= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
//= type=test
//= reason=Later original loss in the already-reduced TLP flight starts recovery without a second reduction.
//# If multiple original transmissions or retransmissions were lost in a
//# window, the congestion control specified in [RFC5681] only reacts
//# once per window.
fn tlp_repaired_loss_epoch_never_bars_recovery_of_later_original_loss() {
    for iss in [0, u32::MAX - 4999] {
        let cfg = ConnectionConfig {
            sack: true,
            rack: true,
            prr: true,
            tlp: true,
            peer_max_ack_delay_us: 0,
            rto_min_us: 200_000,
            initial_window: InitialWindow::Iw10,
            ..config(65_536, 1000)
        };
        let mut a = Connection::active(tuple(), cfg.clone(), iss, 0).unwrap();
        let bytes = packet(&mut a, 0);
        let syn = wire::parse(ip(tuple()), &bytes).unwrap();
        let mut b = Connection::passive(reverse(tuple()), cfg, 900, 0, &syn).unwrap();
        deliver(&mut b, &mut a, 100_000);
        deliver(&mut a, &mut b, 100_000);
        let base = a.send_base;
        a.write(&[0x55; 4000]).unwrap();
        for _ in 0..4 {
            packet(&mut a, 100_000);
        }
        let pto = a.tlp_deadline.unwrap();
        assert_eq!(pto, 302_000);
        a.timeout(pto).unwrap();
        packet(&mut a, pto); // Retransmitted tail ends at offset 4000.
        a.write(&[0x66; 6000]).unwrap();
        for _ in 0..6 {
            packet(&mut a, pto + 1);
        }
        assert_eq!(a.snd_nxt, base.wrapping_add(10_000));
        rack_sack(&mut a, pto + 100_001, 5000, &[]);
        assert_eq!(a.tlp_end, None);
        assert_eq!((a.congestion.cwnd(), a.congestion.ssthresh()), (5000, 5000));
        assert!(!a.congestion.in_recovery());
        assert!(a.sack_recovery.is_none());
        // Later SACKs prove the original segment at offset 5000 was lost
        // in the already-reduced flight. Recovery must retransmit it now.
        rack_sack(&mut a, pto + 200_001, 5000, &[(6000, 10_000)]);
        assert_eq!(a.rack.counts().lost, 1);
        assert!(a.sack_recovery.is_some());
        assert_eq!(a.congestion.ssthresh(), 5000); // No second original-flight reduction.
        let bytes = packet(&mut a, pto + 200_001);
        let p = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(p.header.sequence, base.wrapping_add(5000).0);
        assert_eq!(p.payload, &[0x66; 1000]);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
//= type=test
//= reason=Immediate SACK of partly retransmitted original cannot replenish freshness.
//# Second, the sender has obtained an RTT measurement since the last
//# loss probe transmission or the start of the connection, whichever
//# was later.
fn tlp_options_clipped_suffix_full_sack_cannot_grant_fresh_rtt() {
    for iss in [0, u32::MAX - 1999] {
        let (mut a, _) = tlp_baseline_pair(iss);
        a.config.send_ip_payload_limit = 1020;
        let base = a.send_base;
        a.write(&[0x55; 4000]).unwrap();
        for _ in 0..4 {
            packet(&mut a, 100_000);
        }
        // Duplex out-of-order data adds a 12-byte SACK report to the probe,
        // shrinking its packet budget, not the identity of the original tail.
        let next = a.receive.next();
        inject_sack(
            &mut a,
            200_000,
            next.wrapping_add(1000),
            base,
            ACK,
            65_535,
            &[0x66; 100],
            &[],
        );
        assert_eq!(a.tlp_deadline, Some(300_000));
        a.timeout(300_000).unwrap();
        let bytes = packet(&mut a, 300_000);
        let p = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(p.header.sequence, base.wrapping_add(3012).0);
        assert_eq!(p.payload.len(), 988);
        assert!(p.options.sack_blocks[0].is_some());
        assert!(!a.tlp_fresh_rtt);
        assert!(a.sample.is_none());
        rack_sack(&mut a, 300_001, 0, &[(3000, 4000)]);
        assert!(a.rack.ack_sample.is_none());
        assert!(!a.tlp_fresh_rtt);
        assert_eq!(a.rtt.srtt(), Some(100_000));
        assert!(a.sack_recovery.is_none());
        assert_eq!(a.rack.deadline, None);
        assert_eq!(a.tlp_deadline, None);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
//= type=test
//= reason=Checks tail retransmission, output retry state, RTO fallback and no repeated probe.
//# If such an unsent segment is not available, then the sender SHOULD
//# retransmit the highest-sequence segment sent so far and set
//# TLP.is_retrans to true.
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
//= type=test
//= reason=Output-too-small does not change RACK retransmitted counts or probe state; successful output does.
//# The sender MUST follow the RACK transmission procedures in the "Upon
//# Transmitting a Data Segment" section upon sending either a
//# retransmission or a new data loss probe.
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.1
//= type=test
//= reason=RTO after pending/committed probe clears episode and preserves last-resort recovery.
//# Reset TLP.is_retrans and TLP.end_seq when initiating a connection,
//# fast recovery, or RTO recovery.
fn tlp_four_packets_partial_byte_sack_output_retry_and_rto_sequence() {
    for iss in [0, u32::MAX - 1999] {
        let (mut a, _) = tlp_baseline_pair(iss);
        let base = a.send_base;
        a.write(&[0x55; 4000]).unwrap();
        for i in 0..4 {
            let bytes = packet(&mut a, 100_000);
            let p = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(p.header.sequence, base.wrapping_add(i * 1000).0);
            assert_eq!(p.payload, &[0x55; 1000]);
        }
        assert_eq!(a.tlp_deadline, Some(300_000));
        rack_sack(&mut a, 200_000, 0, &[(3999, 4000)]);
        assert_eq!(a.rack.counts().sacked, 0);
        assert_eq!(a.rack.deadline, None);
        assert!(a.sack_recovery.is_none());
        assert_eq!(a.tlp_deadline, Some(300_000));
        a.timeout(300_000).unwrap();
        let before = (
            a.snd_nxt,
            a.sample,
            a.tlp_end,
            a.tlp_flight,
            a.tlp_fresh_rtt,
            a.rto_deadline,
            a.congestion.cwnd(),
            a.rack.counts().retransmitted,
        );
        assert_eq!(
            a.transmit(300_000, &mut [0; 19]),
            Err(Error::OutputTooSmall)
        );
        assert!(a.tlp_pending);
        assert_eq!(
            before,
            (
                a.snd_nxt,
                a.sample,
                a.tlp_end,
                a.tlp_flight,
                a.tlp_fresh_rtt,
                a.rto_deadline,
                a.congestion.cwnd(),
                a.rack.counts().retransmitted
            )
        );
        let bytes = packet(&mut a, 300_000);
        let p = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(p.header.sequence, base.wrapping_add(3000).0);
        assert_eq!(p.payload, &[0x55; 1000]); // includes the SACKed last byte
        assert_eq!(a.rto_deadline, Some(600_000));
        assert_eq!(a.congestion.cwnd(), 4000);
        assert_eq!(a.tlp_deadline, None);
        assert!(!a.tlp_fresh_rtt);
        assert_eq!(a.rack.counts().retransmitted, 1);
        assert_eq!(a.limited_sent, 0);
        assert!(!a.limited_pending);
        assert_eq!(a.transmit(300_001, &mut [0; 1500]), Ok(None));
        rack_sack(&mut a, 400_000, 0, &[(3999, 4000)]);
        assert_eq!(a.tlp_deadline, None);
        a.timeout(599_999).unwrap();
        assert_eq!(a.transmit(599_999, &mut [0; 1500]), Ok(None));
        a.timeout(600_000).unwrap();
        assert_eq!(a.tlp_end, None);
        assert_eq!(a.congestion.cwnd(), 1000);
        assert_eq!(a.rto(), 600_000);
        let bytes = packet(&mut a, 600_000);
        let p = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(p.header.sequence, base.0);
        assert_eq!(p.payload.len(), 1000);
        rack_sack(&mut a, 1_100_000, 1000, &[(3999, 4000)]);
        for offset in [1000, 2000] {
            let bytes = packet(&mut a, 1_100_000);
            let p = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(p.header.sequence, base.wrapping_add(offset).0);
            assert_eq!(p.payload.len(), 1000);
        }
        rack_sack(&mut a, 1_200_000, 3000, &[(3999, 4000)]);
        let bytes = packet(&mut a, 1_200_000);
        let p = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(p.header.sequence, base.wrapping_add(3000).0);
        // RACK retains the original packet boundary while the scoreboard
        // still preserves advisory delivery of the final byte.
        assert_eq!(p.payload, &[0x55; 1000]);
        rack_sack(&mut a, 1_300_000, 4000, &[]);
        assert_eq!(a.flight(), 0);
        assert_eq!(a.rto_deadline, None);
        assert_eq!(a.tlp_deadline, None);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
//= type=test
//= reason=At full cwnd one new segment probe increases flight by one MSS and a second output is blocked.
//# When the PTO timer expires, the sender MUST check whether both of the
//# following conditions are met before sending a loss probe:
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
//= type=test
//= reason=Asserts new-data choice, one MSS cwnd overcommit, flight charge and no loss response for its ACK.
//# If both conditions are met, then the sender SHOULD transmit a
//# previously unsent data segment, if one exists and the receive window
//# allows, and increment the FlightSize accordingly.
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
//= type=test
//= reason=Blocks a second output while probe is outstanding despite additional unsent data.
//# First, there is no other previous loss probe still in flight.
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.4.2
//= type=test
//= reason=New-data probe ACK clears episode without threshold reduction.
//# TLP_process_ack(ACK):
//# If TLP.end_seq is not None AND ACK's ack. number >= TLP.end_seq:
//# If not TLP.is_retrans:
//# TLP.end_seq = None    /* TLP of new data delivered */
//# Else if ACK has a DSACK option matching TLP.end_seq:
//# TLP.end_seq = None    /* Case 1, above */
//# Else If ACK's ack. number > TLP.end_seq:
//# TLP.end_seq = None    /* Repaired the single loss */
//# (Invoke congestion control to react to
//# the loss event the probe has repaired)
//# Else If ACK is a DupAck without any SACK option:
//# TLP.end_seq = None     /* Case 2, above */
//= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
//= type=test
//= reason=Checks full-window overcommit, flight=5000 for cwnd=4000, no second output and cumulative ACK exit.
//# The only exception -- the only way in which RACK-TLP modulates the
//# congestion control algorithm -- is that one outstanding loss probe
//# can be sent even if the congestion window is fully used.  However,
//# this temporary overcommit is accounted for and credited in the in-
//# flight data tracked for congestion control, so that congestion
//# control will erase the overcommit upon the next ACK.
fn tlp_prefers_new_data_beyond_cwnd_and_ack_is_not_loss() {
    for iss in [0, u32::MAX - 1999] {
        let (mut a, _) = tlp_baseline_pair(iss);
        let base = a.send_base;
        a.write(&[0x55; 6000]).unwrap();
        for _ in 0..4 {
            packet(&mut a, 100_000);
        }
        assert_eq!(a.transmit(100_000, &mut [0; 1500]), Ok(None));
        a.timeout(300_000).unwrap();
        let bytes = packet(&mut a, 300_000);
        assert_eq!(a.last_output_ecn(), 2); // Original TLP data is loss-detectable.
        let p = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(p.header.sequence, base.wrapping_add(4000).0);
        assert_eq!(p.payload.len(), 1000);
        assert_eq!(p.header.flags & CWR, 0); // No reduction on PTO alone.
        assert_eq!(a.flight(), 5000);
        assert_eq!(
            a.tlp_end,
            Some((base.wrapping_add(4000), base.wrapping_add(5000), false))
        );
        assert_eq!(a.rto_deadline, Some(600_000));
        assert_eq!(a.transmit(300_001, &mut [0; 1500]), Ok(None));
        let threshold = a.congestion.ssthresh();
        rack_sack(&mut a, 400_000, 5000, &[]);
        assert_eq!(a.tlp_end, None);
        assert_eq!(a.congestion.ssthresh(), threshold);
        assert!(!a.congestion.in_recovery());
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
//= type=test
//= reason=No fresh RTT after retransmitted probe, no second PTO; a new sampled flight permits another.
//# When the PTO timer expires, the sender MUST check whether both of the
//# following conditions are met before sending a loss probe:
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.4.2
//= type=test
//= reason=Checks equality, matching and unrelated DSACK, bare DupACK, later ACK loss reduction and fresh-sample gate.
//# If the TLP
//# sender does not receive such an indication, then it MUST assume that
//# the original data segment, the TLP retransmission, or a corresponding
//# ACK was lost for congestion control purposes.
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
//= type=test
//= reason=Retransmitted probe does not yield a new ordinary RTT sample; new unambiguous data ACK restores freshness.
//# Second, the sender has obtained an RTT measurement since the last
//# loss probe transmission or the start of the connection, whichever
//# was later.
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.4.2
//= type=test
//= reason=Checks retransmission equality, DSACK match/unrelated, DupACK and beyond-end loss.
//# TLP_process_ack(ACK):
//# If TLP.end_seq is not None AND ACK's ack. number >= TLP.end_seq:
//# If not TLP.is_retrans:
//# TLP.end_seq = None    /* TLP of new data delivered */
//# Else if ACK has a DSACK option matching TLP.end_seq:
//# TLP.end_seq = None    /* Case 1, above */
//# Else If ACK's ack. number > TLP.end_seq:
//# TLP.end_seq = None    /* Repaired the single loss */
//# (Invoke congestion control to react to
//# the loss event the probe has repaired)
//# Else If ACK is a DupAck without any SACK option:
//# TLP.end_seq = None     /* Case 2, above */
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
//= type=test
//= reason=First-fresh CWR tests cover RTO, Reno/NewReno fast retransmit, SACK and RACK/PRR reductions; TLP repaired-loss trace asserts CWR only after actual reduction. ECN and idle tests plus shared successful fresh-data commit cover other causes and failed encoding.
//# When an ECN-Capable TCP sender reduces its congestion window for any reason (because of a retransmit timeout, a Fast Retransmit, or in response to an ECN Notification), the TCP sender sets the CWR flag in the TCP header of the first new data packet sent after the window reduction.
fn tlp_retransmit_ack_equality_dsack_dupack_and_single_loss_response() {
    for iss in [0, u32::MAX - 1999] {
        // 0: ACK beyond probe = loss; 1: matching DSACK; 2: bare DupACK;
        // 3: unrelated DSACK must not suppress the later loss response.
        for case in 0..4 {
            let (mut a, _) = tlp_baseline_pair(iss);
            a.write(&[0x55; 4000]).unwrap();
            for _ in 0..4 {
                packet(&mut a, 100_000);
            }
            a.timeout(300_000).unwrap();
            let probe = packet(&mut a, 300_000);
            assert_eq!(a.last_output_ecn(), 0);
            assert_eq!(
                wire::parse(ip(tuple()), &probe).unwrap().header.flags & CWR,
                0
            );
            let threshold = a.congestion.ssthresh();
            rack_sack(
                &mut a,
                400_000,
                4000,
                match case {
                    1 => &[(3000, 4000)][..],
                    3 => &[(2000, 3000)][..],
                    _ => &[],
                },
            );
            assert_eq!(a.congestion.ssthresh(), threshold);
            assert_eq!(a.tlp_end.is_none(), case == 1);
            assert!(!a.tlp_fresh_rtt); // Karn: no new measurement from the probe
            if case == 2 {
                rack_sack(&mut a, 400_001, 4000, &[]);
                assert_eq!(a.tlp_end, None);
            }
            a.write(&[0x66; 1000]).unwrap();
            packet(&mut a, 400_002);
            assert_eq!(a.loss_timer.unwrap().0, LossTimer::Pto); // arming is separate from send eligibility
            rack_sack(&mut a, 500_002, 5000, &[]);
            assert_eq!(a.tlp_end, None);
            assert_eq!(
                a.congestion.ssthresh(),
                if case == 0 || case == 3 {
                    2000
                } else {
                    threshold
                }
            );
            assert!(!a.congestion.in_recovery());
            assert!(a.tlp_fresh_rtt);
            assert_eq!(a.tlp_deadline, None);
            a.write(&[0x77; 1000]).unwrap();
            let fresh = packet(&mut a, 500_003);
            assert_eq!(a.last_output_ecn(), 2);
            assert_eq!(
                wire::parse(ip(tuple()), &fresh).unwrap().header.flags & CWR != 0,
                case == 0 || case == 3
            );
            assert!(!a.ecn_cwr_pending);
            assert!(a.tlp_deadline.is_some()); // a genuinely new sampled flight
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-1
//= type=test
//= reason=Opt-in packet-level feedback enters RACK recovery and retransmits earlier losses.
//# This document presents RACK-TLP, a TCP loss detection algorithm that
//# improves upon the widely implemented duplicate acknowledgment
//# (DupAck) counting approach described in [RFC5681] and [RFC6675]; it
//# is RECOMMENDED as an alternative to that earlier approach.
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.1
//= type=test
//= reason=Feedback-triggered fast recovery clears probe episode.
//# Reset TLP.is_retrans and TLP.end_seq when initiating a connection,
//# fast recovery, or RTO recovery.
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.4.1
//= type=test
//= reason=Actual packet delivery of tail probe solicits SACK and causes earlier losses, threshold reduction and retransmission.
//# More specifically, RACK_detect_loss() (Step 5) would mark those
//# earlier segments as lost.  Then the sender would trigger a fast
//# recovery to recover those losses.
fn tlp_packet_feedback_detects_earlier_losses_and_enters_rack_recovery() {
    for iss in [0, u32::MAX - 1999] {
        let (mut a, mut b) = tlp_baseline_pair(iss);
        let base = a.send_base;
        a.write(&[0x55; 4000]).unwrap();
        for _ in 0..4 {
            packet(&mut a, 100_000);
        } // drop all original packets
        a.timeout(300_000).unwrap();
        let probe = deliver(&mut a, &mut b, 300_000);
        let p = wire::parse(ip(tuple()), &probe).unwrap();
        assert_eq!(p.header.sequence, base.wrapping_add(3000).0);
        let ack = deliver(&mut b, &mut a, 400_000);
        let feedback = wire::parse(ip(reverse(tuple())), &ack).unwrap();
        assert_eq!(feedback.header.acknowledgment, base.0);
        assert_eq!(
            feedback.options.sack_blocks[0],
            Some((base.wrapping_add(3000).0, base.wrapping_add(4000).0))
        );
        assert!(a.sack_recovery.is_some());
        assert_eq!(a.tlp_end, None);
        assert_eq!(a.tlp_deadline, None);
        assert_eq!(a.congestion.ssthresh(), 2000);
        assert_eq!(a.rack.counts().lost, 3);
        let bytes = packet(&mut a, 400_000);
        let p = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(p.header.sequence, base.0);
        assert_eq!(p.payload, &[0x55; 1000]);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.2
//= type=test
//= reason=Checks advancing ACK reschedule and cancellation for full SACK, zero window and invalid ledger.
//# The sender SHOULD start or
//# restart a loss probe PTO timer after transmitting new data (that was
//# not itself a loss probe) or upon receiving an ACK that cumulatively
//# acknowledges new data unless it is already in fast recovery, RTO
//# recovery, or segments have been SACKed (i.e., RACK.segs_sacked is not
//# zero).
fn tlp_zero_window_complete_sack_and_recovery_cancel_probe() {
    for mode in 0..4 {
        let (mut a, _) = tlp_baseline_pair(0);
        a.write(&[0x55; 4000]).unwrap();
        for _ in 0..4 {
            packet(&mut a, 100_000);
        }
        a.timeout(300_000).unwrap();
        assert!(a.tlp_pending);
        if mode == 0 {
            inject_sack(&mut a, 300_001, Seq(901), Seq(1), ACK, 0, &[], &[]);
            assert!(a.persist_deadline.is_none());
            assert_eq!(a.loss_timer.unwrap().0, LossTimer::Rto);
        } else if mode == 1 {
            rack_sack(&mut a, 300_001, 0, &[(3000, 4000)]);
            assert_eq!(a.rack.counts().sacked, 1);
            assert_eq!(a.rack.deadline, Some(325_001));
        } else if mode == 2 {
            rack_sack(&mut a, 300_001, 1000, &[]);
            assert_eq!(a.tlp_deadline, Some(525_001));
        } else {
            a.rack.abandon(a.data_high());
            a.arm_work();
        }
        assert!(!a.tlp_pending);
        assert_eq!(a.tlp_end, None);
        if mode != 2 {
            assert_eq!(a.tlp_deadline, None);
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6298#section-2
//= type=test
//= reason=Active lost SYN with negotiated SACK/RACK/TLP and configured 200ms floor.
//# (2.1) Until a round-trip time (RTT) measurement has been made for a segment sent
//# between the sender and receiver, the sender SHOULD set RTO <- 1 second, though the
//# "backing off" on repeated retransmission discussed in (5.5) still applies.
//= https://www.rfc-editor.org/rfc/rfc6298#section-5
//= type=test
//= reason=Partial evidence only; TODO remains. Active lost SYN with negotiated SACK/RACK/TLP and configured 200ms floor.
//# (5.7) If the timer expires awaiting the ACK of a SYN segment and the TCP
//# implementation is using an RTO less than 3 seconds, the RTO MUST be re-initialized to
//# 3 seconds when data transmission begins (i.e., after the three-way handshake
//# completes).
//= https://www.rfc-editor.org/rfc/rfc6298#section-5
//= type=test
//= reason=Partial evidence only; TODO remains. Active lost SYN with negotiated SACK/RACK/TLP and configured 200ms floor.
//# (5.1) Every time a packet containing data is sent (including a retransmission), if the
//# timer is not running, start it running so that it will expire after RTO seconds (for
//# the current value of RTO).
//= https://www.rfc-editor.org/rfc/rfc6298#section-5
//= type=test
//= reason=Active lost SYN with negotiated SACK/RACK/TLP and configured 200ms floor.
//# Note that after retransmitting, once a new RTT measurement is obtained (which can only
//# happen when new data has been sent and acknowledged), the computations outlined in
//# Section 2 are performed, including the computation of RTO, which may result in
//# "collapsing" RTO back down after it has been subject to exponential back off (rule
//# 5.5).
fn tlp_small_rto_floor_preserves_initial_and_syn_timeout_guard() {
    let cfg = ConnectionConfig {
        sack: true,
        rack: true,
        tlp: true,
        peer_max_ack_delay_us: 0,
        rto_min_us: 200_000,
        ..config(65_536, 1000)
    };
    let mut a = Connection::active(tuple(), cfg.clone(), 0, 0).unwrap();
    assert_eq!(a.rto(), 1_000_000);
    packet(&mut a, 0); // lose SYN
    a.timeout(1_000_000).unwrap();
    let bytes = packet(&mut a, 1_000_000);
    assert!(!a.syn_delivered);
    assert_eq!(a.rto(), 2_000_000);
    assert_eq!(a.rto_deadline, Some(3_000_000));
    let syn = wire::parse(ip(tuple()), &bytes).unwrap();
    let mut b = Connection::passive(reverse(tuple()), cfg, 900, 1_000_000, &syn).unwrap();
    deliver(&mut b, &mut a, 1_100_000);
    deliver(&mut a, &mut b, 1_100_000);
    assert_eq!(a.state(), State::Established);
    assert_eq!(a.rto(), 3_000_000);
    assert!(!a.tlp_fresh_rtt);
    a.write(&[0x55; 1000]).unwrap();
    deliver(&mut a, &mut b, 1_100_000);
    assert_eq!(a.rto_deadline, Some(4_100_000));
    assert_eq!(a.tlp_deadline, Some(2_100_000)); // unsampled PTO is armed
    b.timeout(1_300_000).unwrap();
    deliver(&mut b, &mut a, 1_300_000);
    assert!(!a.syn_timed_out);
    assert!(a.tlp_fresh_rtt);
    assert_eq!(a.rto(), 600_000);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
//= type=test
//= reason=Failed output preserves sample/probe state and subsequent RTO emits the first outstanding packet.
//# After attempting to send a loss probe, regardless of whether a loss
//# probe was sent, the sender MUST re-arm the RTO timer, not the PTO
//# timer, if the FlightSize is not zero.
fn tlp_failed_output_falls_back_to_rto_without_consuming_a_probe() {
    let (mut a, _) = tlp_baseline_pair(0);
    a.write(&[0x55; 5000]).unwrap();
    for _ in 0..4 {
        packet(&mut a, 100_000);
    }
    a.timeout(300_000).unwrap();
    assert_eq!(
        a.transmit(300_000, &mut [0; 19]),
        Err(Error::OutputTooSmall)
    );
    assert_eq!(a.snd_nxt, Seq(4001));
    assert_eq!(a.flight(), 4000);
    assert_eq!(a.tlp_end, None);
    assert_eq!(a.tlp_flight, None);
    assert!(a.tlp_pending);
    assert!(a.tlp_fresh_rtt);
    a.timeout(600_000).unwrap();
    assert!(!a.tlp_pending);
    assert_eq!(a.tlp_end, None);
    assert_eq!(a.rack.counts().retransmitted, 0);
    assert_eq!(a.rto(), 600_000);
    let bytes = packet(&mut a, 600_000);
    let p = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(p.header.sequence, 1);
    assert_eq!(p.payload, &[0x55; 1000]);
    assert_eq!(a.tlp_deadline, None);
}

#[test]
fn tlp_fin_tail_wire_retry_ack_and_backoff() {
    for iss in [0, u32::MAX - 500] {
        for mode in 0..4 {
            for acknowledge in [false, true] {
                let (mut a, _) = tlp_baseline_pair(iss);
                let base = a.send_base;
                // Empty, combined, standalone after full cwnd, or combined
                // with all payload cumulatively acknowledged before PTO.
                let payload = match mode {
                    0 => 0,
                    2 => 4000,
                    _ => 500,
                };
                if payload != 0 {
                    a.write(&vec![0x55; payload]).unwrap();
                }
                if mode == 2 {
                    for _ in 0..4 {
                        packet(&mut a, 100_000);
                    }
                }
                a.shutdown().unwrap();
                let bytes = packet(&mut a, 100_000);
                let original = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_ne!(original.header.flags & FIN, 0);
                assert_eq!(
                    original.payload.len(),
                    if mode == 1 || mode == 3 { 500 } else { 0 }
                );
                let fin = base.wrapping_add(payload as u32);
                if mode == 3 {
                    rack_sack(&mut a, 110_000, 500, &[]);
                }
                let pto = a.tlp_deadline.unwrap();
                let rto = a.rto();
                let cwnd = a.congestion.cwnd();
                let nxt = a.snd_nxt;
                let acknowledged = a.acknowledged;
                assert_eq!(a.loss_timer, Some((LossTimer::Pto, pto)));
                a.timeout(pto - 1).unwrap();
                assert_eq!(a.transmit(pto - 1, &mut [0; 1500]), Ok(None));
                a.timeout(pto).unwrap();
                let before = (
                    a.now,
                    a.sample,
                    a.tlp_end,
                    a.tlp_flight,
                    a.tlp_fresh_rtt,
                    a.rto_deadline,
                    a.fin_sent_at,
                    a.rack.counts().retransmitted,
                );
                assert_eq!(a.transmit(pto, &mut [0; 19]), Err(Error::OutputTooSmall));
                assert_eq!(
                    before,
                    (
                        a.now,
                        a.sample,
                        a.tlp_end,
                        a.tlp_flight,
                        a.tlp_fresh_rtt,
                        a.rto_deadline,
                        a.fin_sent_at,
                        a.rack.counts().retransmitted
                    )
                );
                assert!(a.tlp_pending);
                let bytes = packet(&mut a, pto);
                let probe = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(
                    probe.header.sequence,
                    if mode == 1 { base.0 } else { fin.0 }
                );
                assert_eq!(probe.payload.len(), if mode == 1 { 500 } else { 0 });
                assert_ne!(probe.header.flags & FIN, 0);
                assert_eq!(a.snd_nxt, nxt);
                assert_eq!(a.acknowledged, acknowledged);
                assert_eq!(a.rack.counts().retransmitted, u32::from(mode == 1));
                assert_eq!(a.tlp_end, Some((Seq(probe.header.sequence), nxt, true)));
                assert!(!a.tlp_fresh_rtt);
                assert!(a.sample.is_none());
                assert_eq!(a.congestion.cwnd(), cwnd);
                assert_eq!(a.rto(), rto);
                assert_eq!(a.loss_timer, Some((LossTimer::Rto, pto + rto)));
                assert_eq!(a.transmit(pto + 1, &mut [0; 1500]), Ok(None));
                if acknowledge {
                    rack_sack(&mut a, pto + 10_000, payload as u32 + 1, &[]);
                    assert_eq!(a.state, State::FinWait2);
                    assert_eq!(a.acknowledged, payload as u64);
                    if mode == 0 || mode == 3 {
                        assert_eq!(a.congestion.cwnd(), cwnd);
                    }
                    assert_eq!(a.flight(), 0);
                    assert_eq!(a.loss_timer, None);
                    // Only never-retransmitted payload (mode2), not the
                    // retried FIN, can provide a new RACK RTT measurement.
                    assert_eq!(a.tlp_fresh_rtt, mode == 2);
                    // Equality remains ambiguous. Matching DSACK clears the
                    // episode without crediting FIN as acknowledged payload.
                    assert!(!a.tlp_ack(
                        nxt,
                        false,
                        true,
                        &[Some((probe.header.sequence, nxt.0)), None, None, None],
                        true
                    ));
                    assert_eq!(a.tlp_end, None);
                    assert_eq!(a.acknowledged, payload as u64);
                } else {
                    a.timeout(pto + rto - 1).unwrap();
                    assert!(!a.retx_pending);
                    a.timeout(pto + rto).unwrap();
                    assert!(a.retx_pending);
                    assert_eq!(a.rto(), rto * 2);
                    assert_eq!(a.tlp_end, None);
                    let bytes = packet(&mut a, pto + rto);
                    let retry = wire::parse(ip(tuple()), &bytes).unwrap();
                    assert_eq!(retry.header.sequence, a.snd_una.0);
                    if mode != 2 {
                        assert_ne!(retry.header.flags & FIN, 0);
                    }
                    assert_eq!(a.rto_deadline, Some(pto + rto * 3));
                }
            }
        }
    }
}

#[test]
fn tlp_fin_failed_probe_restores_rto_and_charges_timestamp_sequence_space() {
    let (mut a, _) = tlp_baseline_pair(u32::MAX);
    a.timestamps = true;
    a.config.timestamp_bytes_per_tick = 1;
    a.shutdown().unwrap();
    packet(&mut a, 100_000);
    assert_eq!(a.timestamp_bytes, 1); // FIN is sequence space, not payload.
    let pto = a.tlp_deadline.unwrap();
    a.timeout(pto).unwrap();
    a.timestamp_tick = a
        .config
        .timestamp_granularity
        .tick_in(pto, a.config.timebase);
    a.timestamp_bytes = 1;
    let before = (
        a.now,
        a.fin_sent_at,
        a.tlp_fresh_rtt,
        a.snd_nxt,
        a.rto_deadline,
    );
    assert_eq!(
        a.transmit(pto, &mut [0; 1500]),
        Err(Error::TimestampBudgetExceeded)
    );
    assert_eq!(
        before,
        (
            a.now,
            a.fin_sent_at,
            a.tlp_fresh_rtt,
            a.snd_nxt,
            a.rto_deadline
        )
    );
    assert!(a.tlp_pending);
    assert_eq!(a.tlp_end, None);
    let rto = a.rto_deadline.unwrap();
    a.timeout(rto).unwrap();
    assert!(a.retx_pending);
    assert!(!a.tlp_pending);
    assert_eq!(a.rto(), 600_000);
    let bytes = packet(&mut a, rto);
    let segment = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(segment.header.sequence, 0);
    assert_ne!(segment.header.flags & FIN, 0);
    assert!(segment.payload.is_empty());
    assert_eq!(a.timestamp_bytes, 1);
    assert_eq!(a.rack.counts().retransmitted, 0);
}

#[test]
fn tlp_fin_gates_and_application_timeout_origin() {
    for gate in ["freshness", "zero-window", "fin-outside-window"] {
        let (mut a, _) = tlp_baseline_pair(0);
        if gate == "fin-outside-window" {
            a.write(&[0x55; 4000]).unwrap();
            for _ in 0..4 {
                packet(&mut a, 100_000);
            }
        }
        a.shutdown().unwrap();
        packet(&mut a, 100_000);
        let pto = a.tlp_deadline.unwrap();
        match gate {
            "freshness" => a.tlp_fresh_rtt = false,
            "zero-window" => {
                let una = a.snd_una;
                let next = a.receive.next();
                inject(&mut a, 100_001, next, una, ACK, 0, &[]);
                assert_eq!(a.tlp_deadline, None);
            }
            _ => a.snd_wnd = 4000,
        }
        a.timeout(pto).unwrap();
        assert_eq!(a.transmit(pto, &mut [0; 1500]), Ok(None));
        assert_eq!(a.tlp_end, None);
        assert!(a.tlp_fresh_rtt || gate == "freshness");
    }
    let (mut a, _) = tlp_baseline_pair(0);
    a.config.peer_max_ack_delay_us = 200_000;
    a.timeout(2_100_000).unwrap();
    a.set_application_timeout(Some(3_000_000)).unwrap();
    a.shutdown().unwrap();
    packet(&mut a, 2_100_000);
    assert_eq!(a.application_deadline(), Some(5_100_000));
    for retry in [2_400_000, 2_700_000, 3_300_000] {
        a.timeout(retry).unwrap();
        let bytes = packet(&mut a, retry);
        assert_ne!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.flags & FIN,
            0
        );
        assert_eq!(a.application_deadline(), Some(5_100_000));
    }
    a.timeout(5_099_999).unwrap();
    assert_ne!(a.state, State::Closed);
    a.timeout(5_100_000).unwrap();
    assert_eq!(a.reason, Some(CloseReason::TimedOut));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.2
//= type=test
//= reason=Asserts capped tie, no RTO backoff and successful probe RTO rearm, not the unestimated RTT branch.
//# Summarizing these considerations in pseudocode form, a sender SHOULD
//# use the following logic to select the duration of a PTO:
//= https://www.rfc-editor.org/rfc/rfc8985#section-4
//= type=test
//= reason=Asserts default-off TLP and rejects all TLP/RACK/SACK invalid combinations.
//# TLP requires RACK.
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.2
//= type=test
//= reason=Directly asserts cap tie and RTO rearm after successful probe.
//# TLP_calc_PTO():
//# If SRTT is available:
//# PTO = 2 * SRTT
//# If FlightSize is one segment:
//# PTO += TLP.max_ack_delay
//# Else:
//# PTO = 1 sec
//#
//# If Now() + PTO > TCP_RTO_expiration():
//# PTO = TCP_RTO_expiration() - Now()
fn tlp_opt_in_rto_floor_validation_fresh_rtt_and_capped_pto() {
    assert!(!ConnectionConfig::default().tlp);
    assert_eq!(ConnectionConfig::default().rto_min_us, 1_000_000);
    for (sack, rack) in [(false, false), (true, false), (false, true)] {
        let cfg = ConnectionConfig {
            tlp: true,
            peer_max_ack_delay_us: 0,
            sack,
            rack,
            ..config(4096, 1000)
        };
        assert!(matches!(
            Connection::active(tuple(), cfg, 0, 0),
            Err(Error::InvalidArgument)
        ));
    }
    for floor in [0, 60_000_001, u64::MAX] {
        let cfg = ConnectionConfig {
            rto_min_us: floor,
            ..config(4096, 1000)
        };
        assert!(matches!(
            Connection::active(tuple(), cfg, 0, 0),
            Err(Error::InvalidArgument)
        ));
    }
    let (mut a, _) = tlp_baseline_pair(0);
    a.tlp_fresh_rtt = false;
    a.write(&[0x55; 1000]).unwrap();
    packet(&mut a, 100_000);
    assert_eq!(a.tlp_deadline, Some(300_000));
    a.tlp_fresh_rtt = true;
    a.rto_deadline = Some(150_000);
    a.schedule_tlp();
    assert_eq!(a.tlp_deadline, Some(150_000));
    a.timeout(150_000).unwrap();
    assert!(a.tlp_pending);
    assert!(!a.retx_pending);
    assert_eq!(a.rto(), 300_000); // capped PTO does not back off
    packet(&mut a, 150_000);
    assert_eq!(a.rto_deadline, Some(450_000));
    assert_eq!(a.congestion.cwnd(), 4000);
}

#[test]
fn prr_active_delivery_matches_signed_scoreboard_delta() {
    for iss in [0, u32::MAX - 4999] {
        let mut a = rack_flight(iss);
        rack_sack(&mut a, 200_000, 0, &[(7000, 8000)]);
        a.timeout(225_000).unwrap();
        assert!(a.prr.is_some());
        for (ack, blocks, expected) in [
            (0, vec![(7500, 8500), (8000, 9000)], 1000),
            (0, vec![], 0), // Omitted advice remains in the scoreboard.
            (0, vec![(7000, 9000)], 0),
            (1000, vec![(7000, 9000)], 1000),
            (8000, vec![(8000, 9000)], 6000),
            (9000, vec![], 0), // deltaSACKd=-1000 offsets deltaUNA=1000.
            (9000, vec![(9500, 9750)], 250),
        ] {
            let una = a.snd_una;
            let sackd = a.flight() - a.scoreboard.unsacked_bytes(una, a.data_high());
            let delivered = a.prr.unwrap().counters().1;
            rack_sack(&mut a, 226_000, ack, &blocks);
            let new_sackd = a.flight() - a.scoreboard.unsacked_bytes(a.snd_una, a.data_high());
            let signed =
                i64::from(a.snd_una.distance_from(una)) + i64::from(new_sackd) - i64::from(sackd);
            assert_eq!(signed, expected);
            assert_eq!(a.prr.unwrap().counters().1 - delivered, expected as u64);
            assert!(a.rack.valid());
            assert!(a.sack_recovery.is_some());
        }
        a.timeout(a.rto_deadline.unwrap()).unwrap();
        assert!(a.prr.is_none());
        assert!(a.sack_recovery.is_none());

        let mut a = rack_flight(iss);
        rack_sack(&mut a, 200_000, 0, &[(7000, 8000)]);
        a.timeout(225_000).unwrap();
        assert!(a.prr.is_some());
        // More than 64 intervals no longer invalidate SACK/PRR state.
        for i in 0..65 {
            rack_sack(&mut a, 226_000, 0, &[(i * 2, i * 2 + 1)]);
        }
        assert!(a.rack.valid());
        assert!(a.prr.is_some());
        assert!(a.sack_recovery.is_some());
        assert!(a.scoreboard.ranges().len() > 64);
    }
}

#[test]
fn prr_entry_snapshots_flight_after_advancing_ack() {
    for iss in [0, u32::MAX - 4999] {
        let mut a = rack_flight(iss);
        a.config.rack = false; // Exercise ACK-driven RFC 6675 entry, not timer entry.
        let nxt = a.snd_nxt;
        rack_sack(&mut a, 200_000, 1000, &[(4000, 10_000)]);
        assert!(a.sack_recovery.unwrap().entry_pending);
        assert_eq!(a.snd_nxt, nxt);
        assert_eq!(a.snd_una, a.iss.wrapping_add(1001));
        assert_eq!(a.prr.unwrap().counters().0, 10_000);
        rack_sack(&mut a, 300_000, 10_000, &[]);
        assert!(a.prr.is_none());
        assert!(!a.start_sack_recovery());
    }
}

// Every ordinary output poll checks cumulative actual bytes and pre-poll allowance.
fn prr_packet(a: &mut Connection, now: u64) -> (u32, usize) {
    let before = a.prr.unwrap();
    assert_eq!(a.transmit(now, &mut [0; 20]), Err(Error::OutputTooSmall));
    assert_eq!(a.prr.unwrap().counters(), before.counters());
    assert_eq!(a.prr.unwrap().credit(), before.credit());
    let bytes = packet(a, now);
    let segment = wire::parse(ip(tuple()), &bytes).unwrap();
    let count = segment.payload.len();
    assert!(count > 0);
    assert!(count as u32 <= before.credit());
    assert!(Seq(segment.header.sequence).distance_from(a.snd_una) + count as u32 <= a.snd_wnd);
    assert_eq!(
        a.prr.unwrap().counters().2,
        before.counters().2 + count as u64
    );
    assert_eq!(a.prr.unwrap().credit(), before.credit() - count as u32);
    (segment.header.sequence, count)
}

#[test]
fn prr_short_output_and_sub_mss_new_data_gate() {
    for iss in [0, u32::MAX - 4999] {
        let mut a = rack_flight(iss);
        // An originally out-of-window packet has no RFC7323 exception.
        a.rack
            .commit_original_window(a.snd_una, a.snd_una.wrapping_add(1000), false);
        rack_sack(&mut a, 200_000, 0, &[(1000, 7000)]);
        a.timeout(225_000).unwrap();
        // Shrink rwnd to bound the entry retransmit to a short payload.
        let seq = a.receive.next();
        let una = a.snd_una;
        let short_window = (250 >> a.peer_scale) as u16;
        inject(&mut a, 225_000, seq, una, ACK, short_window, &[]);
        assert_eq!(a.snd_wnd, 250);
        assert_eq!(prr_packet(&mut a, 225_000), (una.0, 250));
        assert_eq!(a.prr.unwrap().counters().2, 250);
        // Reopen without delivery. Finish the actual lost head, then earn
        // credit from still-unacknowledged original tail bytes.
        inject(&mut a, 225_000, seq, una, ACK, 65_535, &[]);
        assert_eq!(prr_packet(&mut a, 225_000).1, 750);
        a.write(&[0x66; 1250]).unwrap();
        rack_sack(&mut a, 226_000, 0, &[(1000, 7500)]);
        assert_eq!(a.prr.unwrap().credit(), 1500);
        assert_eq!(prr_packet(&mut a, 226_000).1, 1000);
        assert_eq!(a.prr.unwrap().credit(), 500);
        let before = a.prr.unwrap().counters();
        assert_eq!(a.transmit(226_000, &mut [0; 1500]), Ok(None));
        assert_eq!(a.prr.unwrap().counters(), before);
        rack_sack(&mut a, 226_000, 0, &[(1000, 8000)]);
        assert_eq!(a.prr.unwrap().credit(), 1000);
        let nxt = a.snd_nxt;
        let short_window = ((a.flight() + 126) >> a.peer_scale) as u16;
        inject(&mut a, 226_000, seq, una, ACK, short_window, &[]);
        assert_eq!(a.snd_wnd - a.flight(), 126);
        assert_eq!(prr_packet(&mut a, 226_000), (nxt.0, 126));
        assert_eq!(a.prr.unwrap().credit(), 874);
        // Further delivery restores >=MSS allowance; queued short data,
        // not MSS, determines actual output.
        rack_sack(&mut a, 226_000, 0, &[(1000, 8500)]);
        assert_eq!(prr_packet(&mut a, 226_000), (nxt.wrapping_add(126).0, 124));
    }
}

#[test]
fn prr_stall_resume_catches_unstalled_active_epoch() {
    for iss in [0, u32::MAX - 4999] {
        for rwnd_stall in [false, true] {
            let mut results = vec![];
            for stalled in [false, true] {
                let mut a = rack_flight(iss);
                rack_sack(&mut a, 200_000, 0, &[(1000, 7000)]);
                a.timeout(225_000).unwrap();
                prr_packet(&mut a, 225_000);
                let stalled_window = (a.flight() >> a.peer_scale) as u16;
                let boundary = a.sack_recovery.unwrap().recovery_point;
                if !stalled || rwnd_stall {
                    a.write(&[0x66; 3000]).unwrap();
                }
                if stalled && rwnd_stall {
                    let seq = a.receive.next();
                    let una = a.snd_una;
                    inject(&mut a, 225_000, seq, una, ACK, stalled_window, &[]);
                }
                for right in [8000, 9000] {
                    let base = a.iss.wrapping_add(1);
                    let seq = a.receive.next();
                    let una = a.snd_una;
                    inject_sack(
                        &mut a,
                        226_000,
                        seq,
                        una,
                        ACK,
                        if stalled && rwnd_stall {
                            stalled_window
                        } else {
                            65_535
                        },
                        &[],
                        &[(base.wrapping_add(1000).0, base.wrapping_add(right).0)],
                    );
                    if stalled {
                        assert_eq!(a.transmit(226_000, &mut [0; 1500]), Ok(None));
                        assert_eq!(a.prr.unwrap().counters().2, 1000);
                    } else {
                        for _ in 0..if right == 8000 { 2 } else { 1 } {
                            assert_eq!(prr_packet(&mut a, 226_000).1, 1000);
                        }
                    }
                }
                if stalled {
                    assert_eq!(a.prr.unwrap().credit(), 3000);
                    assert_eq!(
                        a.prr.unwrap().counters().1 - a.prr.unwrap().counters().2,
                        7000
                    );
                    if rwnd_stall {
                        let seq = a.receive.next();
                        let una = a.snd_una;
                        inject(&mut a, 226_000, seq, una, ACK, 65_535, &[]);
                    } else {
                        a.write(&[0x66; 3000]).unwrap();
                    }
                    for _ in 0..3 {
                        assert_eq!(prr_packet(&mut a, 226_000).1, 1000);
                    }
                }
                assert_eq!(a.sack_recovery.unwrap().recovery_point, boundary);
                assert!(!a.sack_recovery.unwrap().entry_pending);
                assert_eq!(a.prr.unwrap().credit(), 0);
                assert_eq!(a.transmit(226_000, &mut [0; 1500]), Ok(None));
                results.push((a.prr.unwrap().counters(), a.snd_nxt, a.rack.pipe()));
            }
            assert_eq!(results[0], results[1]);
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Checks next_deadline, deferred entry and emitted retransmission after timer expiry.
//# For timely loss detection, it is RECOMMENDED that the
//# sender install a reordering timer.
//= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
//= type=test
//= reason=Exercises RACK timer recovery, unique delivery credit and PRR output gating.
//# The Proportional Rate
//# Reduction (PRR) algorithm [RFC6937] is RECOMMENDED for the specific
//# congestion control actions taken upon the losses detected by RACK-
//# TLP.
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Services deadline and confirms deferred recovery and output selection.
//# When an ACK
//# is received or the RACK reordering timer expires, call
//# RACK_detect_loss_and_arm_timer().
fn rack_shift_timer_loss_and_reordered_sack_counts() {
    for iss in [0, u32::MAX - 4999] {
        for low in [3000, 5000] {
            let mut a = rack_flight(iss);
            rack_sack(&mut a, 200_000, 0, &[(7000, 8000)]);
            assert_eq!(a.rack.deadline, Some(225_000));
            assert_eq!(a.next_deadline(), Some(225_000));
            assert!(!a.transport_info().recovery);
            a.timeout(227_000).unwrap();
            let before = a.transport_info();
            assert_eq!(
                (before.recovery, before.lost, before.reordering),
                (true, 7, 3)
            );
            assert_eq!(
                a.transmit(227_000, &mut [0; 20]),
                Err(Error::OutputTooSmall)
            );
            assert_eq!(a.transport_info(), before);
            let bytes = packet(&mut a, 227_000);
            let h = wire::parse(ip(tuple()), &bytes).unwrap().header;
            assert_eq!(h.sequence, iss.wrapping_add(1));
            assert_eq!(
                (a.transport_info().lost, a.transport_info().retransmitted),
                (7, 1)
            );
            rack_sack(&mut a, 229_000, 0, &[(low, low + 1000), (7000, 8000)]);
            assert_eq!(
                (a.transport_info().lost, a.transport_info().reordering),
                (6, if low == 3000 { 5 } else { 3 })
            );
            let bytes = packet(&mut a, 229_000);
            assert_eq!(
                wire::parse(ip(tuple()), &bytes).unwrap().header.sequence,
                iss.wrapping_add(1001)
            );
            assert_eq!(a.transport_info().retransmitted, 2);
            rack_sack(&mut a, 229_000, 0, &[(low, low + 1000), (7000, 8000)]);
            assert_eq!(a.prr.unwrap().credit(), 0);
            rack_sack(&mut a, 231_000, 0, &[(low, low + 2000), (7000, 8000)]);
            assert_eq!(a.transport_info().lost, 5);
            rack_sack(&mut a, 233_000, 0, &[(low, low + 2000), (7000, 9000)]);
            rack_sack(&mut a, 235_000, 0, &[(low, low + 2000), (7000, 10_000)]);
            rack_sack(&mut a, 335_000, 10_000, &[]);
            let info = a.transport_info();
            assert!(!info.recovery);
            assert_eq!(
                (info.unacked, info.sacked, info.lost, info.retransmitted),
                (0, 0, 0, 0)
            );
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Same-ACK DSACK growth takes precedence at fast/RTO exit; 16 real DSACK-free RTO exits decay persistence across wrap.
//# Else if exiting Fast or RTO recovery:
//# RACK.reo_wnd_persist -= 1
//# If RACK.reo_wnd_persist <= 0:
//# RACK.reo_wnd_mult = 1
fn rack_dsack_exit_precedence_and_sixteen_rto_exits() {
    for iss in [0, u32::MAX - 4999] {
        for rto_exit in [false, true] {
            let mut a = rack_flight(iss);
            rack_sack(&mut a, 200_000, 0, &[(7000, 8000)]);
            a.timeout(225_000).unwrap();
            packet(&mut a, 225_000);
            let mut now = 325_000;
            if rto_exit {
                now = a.rto_deadline.unwrap();
                a.timeout(now).unwrap();
                packet(&mut a, now);
                assert!(a.sack_post_rto.is_some());
            }
            rack_sack(&mut a, now + 100_000, 10_000, &[(0, 1000)]);
            assert!(a.sack_recovery.is_none());
            assert!(a.sack_post_rto.is_none());
            assert_eq!(a.rack.adaptation(), (2, 16));
            now += 100_001;
            for round in 1..=16 {
                a.write(&[0x55; 1000]).unwrap();
                packet(&mut a, now);
                now = a.rto_deadline.unwrap();
                a.timeout(now).unwrap();
                assert!(a.sack_post_rto.is_some());
                packet(&mut a, now);
                now += 100_000;
                rack_sack(&mut a, now, 10_000 + round * 1000, &[]);
                assert!(a.sack_post_rto.is_none());
                assert_eq!(
                    a.rack.adaptation(),
                    (if round == 16 { 1 } else { 2 }, 16 - round as u8)
                );
                // Duplicate ACK must not count the same exit again.
                rack_sack(&mut a, now + 1, 10_000 + round * 1000, &[]);
                assert_eq!(a.rack.adaptation().1, 16 - round as u8);
                now += 2;
            }
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
//= type=test
//= reason=Original out-of-order delivery establishes reordering before three additional complete segments are newly SACKed by one ACK; recovery waits until the reordering deadline.
//# Otherwise, if some reordering has been observed, then RACK does not
//# trigger fast recovery based on DupThresh.
fn rack_observed_reordering_three_sacks_wait_for_window() {
    for iss in [0, u32::MAX - 4999] {
        let mut a = rack_flight(iss);
        rack_sack(&mut a, 200_000, 0, &[(7000, 8000)]);
        rack_sack(&mut a, 201_000, 0, &[(4000, 5000), (7000, 8000)]);
        assert!(a.transport_info().reordering > 3);
        assert_eq!(a.transport_info().sacked, 2);
        // This ACK newly SACKs three whole segments, not partial bytes.
        rack_sack(&mut a, 202_000, 0, &[(4000, 5000), (6000, 10_000)]);
        assert_eq!(a.transport_info().sacked, 5);
        assert_eq!(a.transport_info().lost, 0);
        assert!(!a.transport_info().recovery);
        let deadline = a.rack.deadline.unwrap();
        assert_eq!(deadline, 227_000);
        a.timeout(deadline - 1).unwrap();
        assert!(!a.transport_info().recovery);
        a.timeout(deadline).unwrap();
        assert!(a.transport_info().recovery);
        assert_eq!(a.transport_info().lost, 5);
        let bytes = packet(&mut a, deadline);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.sequence,
            iss.wrapping_add(1)
        );
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-9.2
//= type=test
//= reason=Packet feedback loses two retransmissions on separate ACKs and selects them again below HighRxt, with PRR both enabled and disabled.
//# Therefore, the algorithm [RFC6675]
//# MUST NOT be used with RACK-TLP; instead, a modified recovery
//# algorithm that carefully addresses such a case is needed.
//= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
//= type=test
//= reason=Without active PRR, reduce once per committed-copy window; active PRR preserves its target. Output failure commits no transmission or credit.
//# In the absence of PRR [RFC6937], when RACK-TLP detects a lost
//# retransmission, the congestion control MUST trigger an additional
//# congestion response per the aforementioned principle in [RFC5681].
//= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
//= type=test
//# If multiple original transmissions or retransmissions were lost in a
//# window, the congestion control specified in [RFC5681] only reacts
//# once per window.
fn rack_lost_retransmissions_select_again_and_reduce_once_per_window() {
    for iss in [0, u32::MAX - 4999] {
        for (configured, prr) in [(false, false), (true, false), (true, true)] {
            let mut a = rack_flight(iss);
            a.config.prr = prr;
            rack_sack(&mut a, 200_000, 0, &[(7000, 8000)]);
            a.timeout(225_000).unwrap();
            for (now, offset) in [(225_000, 0), (226_000, 1000), (227_000, 2000)] {
                if offset != 0 {
                    rack_sack(&mut a, now, 0, &[(7000, 8000 + offset)]);
                }
                let bytes = packet(&mut a, now);
                assert_eq!(
                    wire::parse(ip(tuple()), &bytes).unwrap().header.sequence,
                    iss.wrapping_add(1 + offset)
                );
            }
            assert_eq!(a.congestion.ssthresh(), 5000);
            assert_eq!(a.prr.is_some(), prr);
            // Configuration is not an active episode (e.g. fallback).
            a.config.prr = configured;
            // Deliver the second retransmission: the first is lost again.
            rack_sack(&mut a, 326_000, 0, &[(1000, 2000), (7000, 10_000)]);
            assert_eq!(
                (a.congestion.cwnd(), a.congestion.ssthresh()),
                if prr {
                    (a.rack.pipe() + a.prr.unwrap().credit(), 5000)
                } else {
                    (2500, 2500)
                }
            );
            let send_credit = a.recovery_credit(a.sack_recovery.unwrap());
            assert_eq!(send_credit, if prr { 1000 } else { 1500 });
            let before = a.transport_info();
            let credit = a.prr.map(|p| p.credit());
            assert_eq!(
                a.transmit(326_000, &mut [0; 20]),
                Err(Error::OutputTooSmall)
            );
            assert_eq!(a.transport_info(), before);
            assert_eq!(a.prr.map(|p| p.credit()), credit);
            let bytes = packet(&mut a, 326_000);
            assert!(wire::parse(ip(tuple()), &bytes).unwrap().payload.len() as u32 <= send_credit);
            assert_eq!(
                wire::parse(ip(tuple()), &bytes).unwrap().header.sequence,
                iss.wrapping_add(1)
            );
            // Its ACK now loses the third retransmission on another ACK,
            // still inside the original 10-MSS sequence window.
            rack_sack(&mut a, 426_000, 2000, &[(7000, 10_000)]);
            assert_eq!(a.congestion.ssthresh(), if prr { 5000 } else { 2500 });
            let bytes = packet(&mut a, 426_000);
            assert_eq!(
                wire::parse(ip(tuple()), &bytes).unwrap().header.sequence,
                iss.wrapping_add(2001)
            );
            rack_sack(&mut a, 427_000, 2000, &[(7000, 10_000)]);
            assert_eq!(a.congestion.ssthresh(), if prr { 5000 } else { 2500 });
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
//= type=test
//= reason=Loss of a committed replacement triggers another response only without active PRR; active PRR keeps its target. Covers unchanged cumulative hole/SND.NXT, wrap, timestamp ties and failed encoding.
//# In the absence of PRR [RFC6937], when RACK-TLP detects a lost
//# retransmission, the congestion control MUST trigger an additional
//# congestion response per the aforementioned principle in [RFC5681].
fn rack_replacement_loss_renews_response_without_cumulative_progress() {
    for iss in [0, u32::MAX - 4999] {
        for (configured, prr) in [(false, false), (true, false), (true, true)] {
            for same_timestamp in [false, true] {
                let mut a = rack_flight(iss);
                a.config.prr = prr;
                rack_sack(&mut a, 200_000, 0, &[(7000, 8000)]);
                a.timeout(225_000).unwrap();
                for (now, offset) in [(225_000, 0), (226_000, 1000), (227_000, 2000)] {
                    if offset != 0 {
                        rack_sack(&mut a, now, 0, &[(7000, 8000 + offset)]);
                    }
                    a.snd_wnd = 2; // first valid retry even for out-of-window originals
                    let bytes = packet(&mut a, now);
                    let seq = a.iss.wrapping_add(1 + offset);
                    assert_eq!(
                        a.rack
                            .original_retry_span(seq, a.snd_nxt)
                            .unwrap()
                            .successful_retries,
                        1
                    );
                    assert_eq!(
                        wire::parse(ip(tuple()), &bytes).unwrap().header.sequence,
                        iss.wrapping_add(1 + offset)
                    );
                }
                assert_eq!(a.prr.is_some(), prr);
                // Exercise configured PRR without an active episode too.
                a.config.prr = configured;
                let flight = (a.snd_una, a.snd_nxt);
                rack_sack(&mut a, 326_000, 0, &[(1000, 2000), (7000, 10_000)]);
                assert_eq!(a.congestion.ssthresh(), if prr { 5000 } else { 2500 });
                // Failed output cannot renew the accounted first copy.
                let copies = alloc::format!("{:?}", a.rack);
                let credit = a.prr.map(|p| p.credit());
                assert_eq!(
                    a.transmit(326_000, &mut [0; 20]),
                    Err(Error::OutputTooSmall)
                );
                assert_eq!(alloc::format!("{:?}", a.rack), copies);
                assert_eq!(a.prr.map(|p| p.credit()), credit);
                rack_sack(&mut a, 326_000, 0, &[(1000, 2000), (7000, 10_000)]);
                assert_eq!(a.congestion.ssthresh(), if prr { 5000 } else { 2500 });
                // This actual commit renews the first copy, not SND.NXT.
                a.snd_wnd = 2; // replacement SEG.SEQ is still in window
                let bytes = packet(&mut a, 326_000);
                assert_eq!(
                    a.rack
                        .original_retry_span(a.snd_una, a.snd_nxt)
                        .unwrap()
                        .successful_retries,
                    2
                );
                assert_eq!(
                    wire::parse(ip(tuple()), &bytes).unwrap().header.sequence,
                    iss.wrapping_add(1)
                );
                let sent = if same_timestamp { 326_000 } else { 327_000 };
                rack_sack(&mut a, sent, 0, &[(1000, 3000), (7000, 10_000)]);
                let bytes = packet(&mut a, sent);
                assert_eq!(
                    wire::parse(ip(tuple()), &bytes).unwrap().header.sequence,
                    iss.wrapping_add(3001)
                );
                // Deliver the later-sequence copy. Even a timestamp tie
                // detects the replacement at offset 0 as lost again.
                rack_sack(&mut a, sent + 100_000, 0, &[(1000, 4000), (7000, 10_000)]);
                assert_eq!((a.snd_una, a.snd_nxt), flight);
                assert_eq!(
                    (a.congestion.cwnd(), a.congestion.ssthresh()),
                    if prr {
                        (a.rack.pipe() + a.prr.unwrap().credit(), 5000)
                    } else {
                        (2000, 2000)
                    }
                );
                a.snd_wnd = 2;
                let bytes = packet(&mut a, sent + 100_000);
                assert_eq!(
                    a.rack
                        .original_retry_span(a.snd_una, a.snd_nxt)
                        .unwrap()
                        .successful_retries,
                    3
                );
                assert_eq!(
                    wire::parse(ip(tuple()), &bytes).unwrap().header.sequence,
                    iss.wrapping_add(1)
                );
            }
        }
    }
}

#[test]
fn fresh_burst_push_uses_normal_window_not_limited_credit() {
    for push in [false, true] {
        let mut a = rack_flight(0);
        // Start another flight with a deliberately fixed window.
        rack_sack(&mut a, 200_000, 10_000, &[]);
        a.congestion = Congestion::new(
            1000,
            RecoveryAlgorithm::NewReno,
            InitialWindow::Iw10,
            Seq(u32::MAX),
        );
        a.write_with_push(&[0x55; 15_000], push).unwrap();
        for i in 0..10 {
            if i == 9 {
                assert_eq!(
                    a.transmit(200_000, &mut [0; 20]),
                    Err(Error::OutputTooSmall)
                );
            }
            let bytes = packet(&mut a, 200_000);
            let segment = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(segment.header.flags & PSH != 0, push && i == 9);
        }
        rack_sack(&mut a, 201_000, 10_000, &[(11_000, 12_000)]);
        let bytes = packet(&mut a, 201_000);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.flags & PSH,
            0
        );
        rack_sack(&mut a, 202_000, 10_000, &[(11_000, 13_000)]);
        let bytes = packet(&mut a, 202_000);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.flags & PSH,
            0
        );
        rack_sack(&mut a, 203_000, 13_000, &[]);
        for i in 0..2 {
            let bytes = packet(&mut a, 203_000);
            assert_eq!(
                wire::parse(ip(tuple()), &bytes).unwrap().header.flags & PSH != 0,
                push && i == 1
            );
        }
    }
}

#[test]
fn recovery_burst_push_preserves_explicit_control_and_unsent_suffix() {
    for (iss, holes) in [
        (0, 1),
        (0, 2),
        (u32::MAX - 12_000, 1),
        (u32::MAX - 12_000, 2),
    ] {
        for push in [false, true] {
            for unsent in [false, true] {
                let mut a = rack_flight(iss);
                rack_sack(&mut a, 200_000, 10_000, &[]);
                a.write_with_push(&[0x55; 6000], push).unwrap();
                for _ in 0..6 {
                    packet(&mut a, 200_000);
                }
                if unsent {
                    a.write_with_push(&[0x66; 1000], push).unwrap();
                }
                rack_sack(&mut a, 300_000, 10_000, &[(10_000 + holes * 1000, 16_000)]);
                for i in 0..holes {
                    assert_eq!(
                        a.transmit(300_000, &mut [0; 20]),
                        Err(Error::OutputTooSmall)
                    );
                    let bytes = packet(&mut a, 300_000);
                    let segment = wire::parse(ip(tuple()), &bytes).unwrap();
                    assert_eq!(
                        segment.header.sequence,
                        a.iss.wrapping_add(10_001 + i * 1000).0
                    );
                    assert_eq!(segment.payload.len(), 1000);
                    assert_eq!(
                        segment.header.flags & PSH != 0,
                        push && !unsent && holes > 1 && i + 1 == holes
                    );
                }
                assert_eq!(a.send.pushed(5999, 1), push);
            }
        }
    }
}

#[test]
fn rack_shift_three_sacks_nofack_and_cumulative_delivery() {
    for iss in [0, u32::MAX - 4999] {
        let mut a = rack_flight(iss);
        rack_sack(&mut a, 200_000, 0, &[(2000, 3000)]);
        rack_sack(&mut a, 201_000, 0, &[(2000, 3000), (6000, 7000)]);
        rack_sack(
            &mut a,
            202_000,
            0,
            &[(2000, 3000), (6000, 7000), (8000, 9000)],
        );
        assert_eq!(a.transport_info().lost, 6);
        packet(&mut a, 202_000);
        rack_sack(
            &mut a,
            209_000,
            0,
            &[(2000, 4000), (6000, 7000), (8000, 9000)],
        );
        assert_eq!(
            (a.transport_info().lost, a.transport_info().reordering),
            (5, 6)
        );
        packet(&mut a, 209_000);
        assert_eq!(a.prr.unwrap().credit(), 0);
        rack_sack(
            &mut a,
            209_000,
            0,
            &[(2000, 4000), (6000, 7000), (8000, 9000)],
        );
        assert_eq!(a.prr.unwrap().credit(), 0);
        rack_sack(
            &mut a,
            219_000,
            0,
            &[(2000, 4000), (6000, 7000), (8000, 10_000)],
        );
        assert_eq!(a.transport_info().lost, 5);
        rack_sack(
            &mut a,
            302_000,
            1000,
            &[(2000, 4000), (6000, 7000), (8000, 10_000)],
        );
        assert_eq!(a.transport_info().lost, 4);
        rack_sack(&mut a, 319_000, 4000, &[(6000, 7000), (8000, 10_000)]);
        assert_eq!(a.transport_info().lost, 3);
        rack_sack(&mut a, 329_000, 7000, &[(8000, 10_000)]);
        rack_sack(&mut a, 429_000, 10_000, &[]);
        let info = a.transport_info();
        assert_eq!(
            (info.unacked, info.sacked, info.lost, info.retransmitted),
            (0, 0, 0, 0)
        );
        assert!(!info.recovery);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
//= type=test
//= reason=After initial MSS consumes PRR credit, further timer-marked loss cannot emit without new delivery credit.
//# A segment marked
//# as lost by RACK-TLP MUST NOT be retransmitted until congestion
//# control deems this appropriate.
fn rack_mixed_immediate_deferred_loss_timer_cannot_mint_prr_entry_credit() {
    for iss in [0, u32::MAX - 1999] {
        let (mut a, _) = tlp_baseline_pair(iss);
        a.config.tlp = false;
        a.write(&[0x55; 4000]).unwrap();
        for now in [100_000, 200_000, 300_000, 300_000] {
            packet(&mut a, now);
        }
        rack_sack(&mut a, 400_000, 0, &[(3000, 4000)]);
        assert_eq!(a.rack.counts().lost, 2);
        assert_eq!(a.rack.deadline, Some(425_000));
        assert!(a.sack_recovery.unwrap().entry_pending);
        assert_eq!(a.prr.unwrap().credit(), 1000);
        packet(&mut a, 400_000);
        assert!(!a.sack_recovery.unwrap().entry_pending);
        assert_eq!(a.prr.unwrap().credit(), 0);
        let window = a.congestion.cwnd();
        a.timeout(425_000).unwrap();
        assert_eq!(a.congestion.cwnd(), window);
        assert_eq!(a.rack.counts().lost, 3);
        assert_eq!(a.prr.unwrap().credit(), 0);
        assert_eq!(a.transmit(425_000, &mut [0; 1500]), Ok(None));
    }
}

#[test]
fn rack_ack_splits_preserve_active_prr_beyond_old_ledger_limit() {
    for iss in [0, u32::MAX - 99] {
        let (mut a, _) = tlp_baseline_pair(iss);
        a.set_nagle(false);
        let base = a.send_base;
        a.write(&[0x55; 2]).unwrap();
        packet(&mut a, 100_000);
        for _ in 0..255 {
            a.write(&[0x55; 1]).unwrap();
            packet(&mut a, 100_000);
        }
        assert_eq!(a.rack.counts().unacked, 256);
        assert!(a.start_sack_recovery());
        rack_sack(&mut a, 200_000, 1, &[(256, 257)]);
        assert!(a.rack.valid());
        assert!(a.prr.is_some());
        assert_eq!(a.snd_una, base.wrapping_add(1));
        assert_eq!(a.flight(), 256);
        assert_eq!(a.scoreboard.unsacked_bytes(a.snd_una, a.data_high()), 255);
        assert_eq!(a.rack.head_transmission(a.snd_una).unwrap().1, 100_000);
    }
}

#[test]
fn rack_partial_sack_credit_rto_ecn_and_peer_fallback() {
    let mut a = rack_flight(0);
    rack_sack(&mut a, 200_000, 0, &[(7501, 7999)]);
    assert_eq!(a.transport_info().sacked, 0);
    assert_eq!(a.rack.deadline, None);
    a.timeout(225_000).unwrap();
    assert!(!a.transport_info().recovery);
    // Completing the original packet supplies RACK evidence; byte advice
    // still credits only the 502 bytes not already SACKed.
    rack_sack(&mut a, 300_000, 0, &[(7000, 8000)]);
    a.timeout(a.rack.deadline.unwrap()).unwrap();
    packet(&mut a, 350_000);
    assert_eq!(a.transport_info().sacked, 1);
    rack_sack(&mut a, 400_000, 7999, &[]);
    assert_eq!(a.prr.unwrap().credit(), 3000);
    let mut a = rack_flight(0);
    assert!(a.congestion.on_ecn(a.snd_una, a.flight(), a.data_high()));
    let threshold = a.congestion.ssthresh();
    rack_sack(&mut a, 200_000, 0, &[(7000, 8000)]);
    a.timeout(225_000).unwrap();
    assert_eq!(a.congestion.ssthresh(), threshold);
    packet(&mut a, 225_000);
    let rto = a.rto_deadline.unwrap();
    a.timeout(rto).unwrap();
    assert!(a.prr.is_none());
    assert_eq!(a.transport_info().sacked, 0);
    assert_eq!(a.congestion.cwnd(), 1000);
    packet(&mut a, rto);
    assert!(a.transport_info().lost > 0);
    let cfg = ConnectionConfig {
        sack: false,
        rack: true,
        prr: true,
        ..config(4096, 1000)
    };
    let (mut a, mut b) = pair(cfg, 0);
    assert!(!a.rack_enabled());
    a.write(&[1; 1000]).unwrap();
    deliver(&mut a, &mut b, 100);
    b.immediate_ack();
    deliver(&mut b, &mut a, 200);
    assert_eq!(a.transport_info().unacked, 0);
    assert!(a.prr.is_none());
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-4
//= type=test
//= reason=Peer without negotiated SACK uses NewReno selection with RFC9937 byte accounting, not RACK detection.
//# The connection MUST use selective acknowledgment (SACK) options
//# [RFC2018], and the sender MUST keep SACK scoreboard information
//# on a per-connection basis ("SACK scoreboard" has the same meaning
//# here as in [RFC6675], Section 3).
//= https://www.rfc-editor.org/rfc/rfc6582#section-1
//= type=test
//= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim.
//# This document applies to TCP connections that are unable to use the TCP Selective
//# Acknowledgment (SACK) option, either because the option is not locally supported or
//# because the TCP peer did not indicate a willingness to use SACK.
fn rack_peer_without_sack_uses_newreno_selection_with_byte_prr() {
    let cfg = ConnectionConfig {
        sack: true,
        rack: true,
        prr: true,
        ..config(65_536, 1000)
    };
    let mut a = Connection::active(tuple(), cfg.clone(), 0, 0).unwrap();
    let bytes = packet(&mut a, 0);
    let syn = wire::parse(ip(tuple()), &bytes).unwrap();
    let mut b = Connection::passive(
        reverse(tuple()),
        ConnectionConfig { sack: false, ..cfg },
        900,
        0,
        &syn,
    )
    .unwrap();
    deliver(&mut b, &mut a, 100_000);
    deliver(&mut a, &mut b, 100_000);
    assert!(a.sack_receive);
    assert!(!a.sack_send);
    prime_newreno(&mut a);
    a.write(&[1; 4000]).unwrap();
    for _ in 0..4 {
        packet(&mut a, 100_010);
    }
    let ack = a.snd_una;
    inject_sack(&mut a, 199_999, b.snd_nxt, ack, ACK, 32_768, &[], &[]);
    for now in 200_000..200_003 {
        let ack = a.snd_una;
        let window = (a.snd_wnd >> a.peer_scale) as u16;
        inject_sack(&mut a, now, b.snd_nxt, ack, ACK, window, &[], &[]);
    }
    assert!(a.retx_pending);
    assert!(a.prr.is_some());
    assert!(!a.rack_enabled());
    assert_eq!(a.prr.unwrap().counters().1, 1000);
    let bytes = packet(&mut a, 200_003);
    assert_eq!(
        wire::parse(ip(tuple()), &bytes).unwrap().header.sequence,
        ack.0
    );
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc2018#section-2
//= type=test
//# It MUST NOT be sent on non-SYN segments.
//= https://www.rfc-editor.org/rfc/rfc2018#section-4
//= type=test
//= reason=All active/passive permission combinations, both directions and timestamp modes inject kind 4 on accepted non-SYN OOO data. ACK wire output retains only SYN-negotiated kind-5 permission; disabled directions retain data but emit no SACK.
//# If the data receiver has not received a SACK-Permitted option for a given
//# connection, it MUST NOT send SACK options on that connection.
fn sack_negotiation_directional_and_disabled_layout() {
    assert!(!ConnectionConfig::default().sack);
    for active in [false, true] {
        for passive in [false, true] {
            for timestamps in [false, true] {
                let cfg = ConnectionConfig {
                    sack: active,
                    timestamps,
                    ..config(1024, 128)
                };
                let mut a = Connection::active(tuple(), cfg.clone(), 100, 0).unwrap();
                assert_eq!(a.transmit(0, &mut [0; 8]), Err(Error::OutputTooSmall));
                assert!(!a.sack_receive);
                let bytes = packet(&mut a, 0);
                assert_eq!(&bytes[20..24], &[2, 4, 0, 128]);
                assert_eq!(&bytes[bytes.len() - 4..], &[1, 3, 3, 0]);
                if active {
                    assert_eq!(
                        &bytes[24..28],
                        if timestamps {
                            &[4, 2, 8, 10]
                        } else {
                            &[1, 1, 4, 2]
                        }
                    );
                }
                let syn = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(syn.options.sack_permitted, active);
                assert_eq!(
                    bytes.len(),
                    28 + if timestamps {
                        12
                    } else {
                        4 * usize::from(active)
                    }
                );
                let mut b = Connection::passive(
                    reverse(tuple()),
                    ConnectionConfig {
                        sack: passive,
                        ..cfg
                    },
                    900,
                    10,
                    &syn,
                )
                .unwrap();
                let bytes = deliver(&mut b, &mut a, 20);
                let reply = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
                assert_eq!(reply.options.sack_permitted, active && passive);
                let ack = deliver(&mut a, &mut b, 30);
                let ack = wire::parse(ip(tuple()), &ack).unwrap();
                assert_eq!(ack.header.flags & SYN, 0);
                assert!(!ack.options.sack_permitted);
                a.write(b"data").unwrap();
                let data = packet(&mut a, 31);
                let data = wire::parse(ip(tuple()), &data).unwrap();
                assert_eq!(data.payload, b"data");
                assert!(!data.options.sack_permitted);
                assert_eq!((a.sack_receive, a.sack_send), (active, active && passive));
                assert_eq!(
                    (b.sack_receive, b.sack_send),
                    (active && passive, active && passive)
                );
                for receiver in [&mut a, &mut b] {
                    let permission = receiver.sack_send;
                    let next = receiver.receive.next();
                    let metadata = ip(reverse(receiver.tuple()));
                    let mut options = vec![1; 4];
                    if timestamps {
                        options.extend_from_slice(&[1, 1, 8, 10]);
                        options.extend_from_slice(&0u32.to_be_bytes());
                        options.extend_from_slice(&receiver.ts_recent.to_be_bytes());
                    }
                    let mut bytes = [0; 128];
                    let len = wire::encode(
                        metadata,
                        Header {
                            source_port: receiver.tuple.remote.port(),
                            destination_port: receiver.tuple.local.port(),
                            sequence: next.wrapping_add(10).0,
                            acknowledgment: receiver.snd_una.0,
                            flags: ACK,
                            window: 1024,
                            urgent_pointer: 0,
                        },
                        &options,
                        b"ooo",
                        &mut bytes,
                    )
                    .unwrap();
                    // Encoder correctly forbids non-SYN kind 4; inject it as peer input.
                    bytes[20..24].copy_from_slice(&[4, 2, 1, 1]);
                    bytes[16..18].fill(0);
                    let checksum = wire::checksum(metadata, &bytes[..len]).unwrap();
                    bytes[16..18].copy_from_slice(&checksum.to_be_bytes());
                    let injected = wire::parse(metadata, &bytes[..len]).unwrap();
                    assert!(injected.options.sack_permitted);
                    assert_eq!(injected.header.flags & SYN, 0);
                    receiver.input(40, &injected).unwrap();
                    assert!(receiver.accepted_metadata);
                    assert_eq!(receiver.sack_send, permission);
                    assert_eq!(
                        receiver.receive.sack_blocks(4)[0],
                        Some((next.wrapping_add(10).0, next.wrapping_add(13).0))
                    );
                    let bytes = packet(receiver, 41);
                    let ack = wire::parse(ip(receiver.tuple()), &bytes).unwrap();
                    assert_eq!(ack.header.acknowledgment, next.0);
                    assert_eq!(
                        ack.options.sack_blocks[0],
                        permission.then_some((next.wrapping_add(10).0, next.wrapping_add(13).0))
                    );
                    assert!(ack.options.sack_blocks.iter().skip(1).all(Option::is_none));
                }
            }
        }
    }
}

#[test]
fn sack_passive_without_scale_and_repeated_syn() {
    let cfg = ConnectionConfig {
        sack: true,
        ..config(1024, 128)
    };
    let metadata = ip(tuple());
    let mut bytes = [0; 64];
    let len = wire::encode(
        metadata,
        Header {
            source_port: 1000,
            destination_port: 2000,
            sequence: 100,
            acknowledgment: 0,
            flags: SYN,
            window: 1024,
            urgent_pointer: 0,
        },
        &[2, 4, 0, 128, 1, 1, 4, 2],
        &[],
        &mut bytes,
    )
    .unwrap();
    let syn = wire::parse(metadata, &bytes[..len]).unwrap();
    let mut b = Connection::passive(reverse(tuple()), cfg, 900, 10, &syn).unwrap();
    let reply = packet(&mut b, 20);
    assert_eq!(&reply[20..], &[2, 4, 0, 128, 1, 1, 4, 2]);
    b.input(30, &syn).unwrap();
    assert_eq!(packet(&mut b, 40), reply);
    assert!(b.sack_receive && b.sack_send);
}

#[test]
fn sack_syn_path_budget_validated() {
    for sack in [false, true] {
        for timestamps in [false, true] {
            let bound = if timestamps && sack {
                44
            } else if timestamps {
                40
            } else if sack {
                32
            } else {
                28
            };
            let mut cfg = ConnectionConfig {
                sack,
                timestamps,
                nagle: false,
                send_ip_payload_limit: bound - 1,
                ..config(1024, 128)
            };
            assert!(matches!(
                Connection::active(tuple(), cfg.clone(), 100, 0),
                Err(Error::InvalidArgument)
            ));
            cfg.send_ip_payload_limit = bound;
            let mut a = Connection::active(tuple(), cfg.clone(), 100, 0).unwrap();
            let syn = packet(&mut a, 0);
            assert_eq!(
                syn.len(),
                if timestamps && sack {
                    40
                } else {
                    bound as usize
                }
            );
            let syn = wire::parse(ip(tuple()), &syn).unwrap();
            let mut b = Connection::passive(reverse(tuple()), cfg, 900, 10, &syn).unwrap();
            assert_eq!(
                deliver(&mut b, &mut a, 20).len(),
                if timestamps && sack {
                    40
                } else {
                    bound as usize
                }
            );
            deliver(&mut a, &mut b, 30);
            let payload = usize::from(bound) - 20 - if timestamps { 12 } else { 0 };
            assert_eq!(a.mss, payload);
            a.write(&[7; 32]).unwrap();
            let data = deliver(&mut a, &mut b, 40);
            assert_eq!(data.len(), bound as usize);
            let data = wire::parse(ip(tuple()), &data).unwrap();
            assert_eq!(data.payload, vec![7; payload]);
            assert_eq!(data.raw_options.len(), if timestamps { 12 } else { 0 });
            a.lower_mss(if timestamps { 16 } else { 4 }).unwrap();
            assert_eq!(a.mss, 4);
            assert_eq!(
                packet(&mut a, 50).len(),
                24 + if timestamps { 12 } else { 0 }
            );
        }
    }
}

#[test]
fn sack_disabled_ignores_peer_kind5() {
    let (mut a, _) = pair(config(1024, 128), 100);
    prime_newreno(&mut a);
    a.write(&[1; 512]).unwrap();
    for now in 40..44 {
        packet(&mut a, now);
    }
    let una = a.snd_una;
    let next = a.receive.next();
    let timer = a.rto_deadline;
    for now in 50..53 {
        inject_sack(
            &mut a,
            now,
            next,
            una,
            ACK,
            1024,
            &[],
            &[(una.wrapping_add(128).0, una.wrapping_add(512).0)],
        );
    }
    assert!(a.retx_pending); // Classic Reno/NewReno duplicate ACK handling.
    assert_eq!(a.rto_deadline, timer);
    assert_eq!(a.send.len(), 512);
    let bytes = packet(&mut a, 60);
    let segment = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(segment.header.sequence, una.0);
    assert!(segment.options.sack_blocks.iter().all(Option::is_none));
}

#[test]
fn sack_simultaneous_open_and_syn_retransmit() {
    for timestamps in [false, true] {
        let cfg = ConnectionConfig {
            sack: true,
            timestamps,
            ..config(1024, 128)
        };
        let mut a = Connection::active(tuple(), cfg.clone(), 100, 0).unwrap();
        let mut b = Connection::active(reverse(tuple()), cfg, 900, 0).unwrap();
        let a_syn = packet(&mut a, 0);
        let b_syn = packet(&mut b, 0);
        let mut expected = vec![2, 4, 0, 128];
        if timestamps {
            expected.extend_from_slice(&[4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0]);
        } else {
            expected.extend_from_slice(&[1, 1, 4, 2]);
        }
        expected.extend_from_slice(&[1, 3, 3, 0]);
        assert_eq!(&a_syn[20..], expected);
        assert_eq!(&b_syn[20..], expected);
        let deadline = a.rto_deadline.unwrap();
        a.timeout(deadline).unwrap();
        let retry = packet(&mut a, deadline);
        let mut retry_options = expected.clone();
        if timestamps {
            retry_options[8..12].copy_from_slice(&((deadline / 1_000) as u32).to_be_bytes());
        }
        assert_eq!(&retry[20..], retry_options);
        a.input(
            deadline + 10,
            &wire::parse(ip(reverse(tuple())), &b_syn).unwrap(),
        )
        .unwrap();
        b.input(deadline + 10, &wire::parse(ip(tuple()), &a_syn).unwrap())
            .unwrap();
        let a_reply = packet(&mut a, deadline + 20);
        let b_reply = packet(&mut b, deadline + 20);
        if timestamps {
            expected[8..12].copy_from_slice(&(((deadline + 20) / 1_000) as u32).to_be_bytes());
        }
        assert_eq!(&a_reply[20..], expected);
        assert_eq!(&b_reply[20..], expected);
        assert!(
            wire::parse(ip(tuple()), &a_reply)
                .unwrap()
                .options
                .sack_permitted
        );
        a.input(
            deadline + 30,
            &wire::parse(ip(reverse(tuple())), &b_reply).unwrap(),
        )
        .unwrap();
        b.input(deadline + 30, &wire::parse(ip(tuple()), &a_reply).unwrap())
            .unwrap();
        assert_eq!((a.state, b.state), (State::Established, State::Established));
        assert!(a.sack_send && a.sack_receive && b.sack_send && b.sack_receive);
        let bytes = deliver(&mut a, &mut b, deadline + 40);
        assert!(
            !wire::parse(ip(tuple()), &bytes)
                .unwrap()
                .options
                .sack_permitted
        );
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6675#section-4
//= type=test
//= reason=SMSS 128 remains the loss threshold with a piggybacked-SACK budget of 116; 240 and 256 SACKed bytes do not outrank fresh data, but 257 do. Failed encoding does not advance recovery markers.
//# (1.c) IsLost (S2) returns true.
fn sack_nextseg_piggyback_budget_does_not_change_loss_threshold() {
    for covered in [240, 256, 257] {
        let mut a = sack_flight(128, 100, 12);
        let una = a.snd_una;
        let point = a.data_high();
        let tail = (una.wrapping_add(1024).0, una.wrapping_add(1024 + covered).0);
        sack_ack(
            &mut a,
            200,
            una,
            &[(una.wrapping_add(128).0, una.wrapping_add(896).0), tail],
        );
        packet(&mut a, 201); // Entry retransmission.
        a.write(&[9; 128]).unwrap();
        let next = a.receive.next();
        inject_sack(
            &mut a,
            210,
            next.wrapping_add(1),
            una.wrapping_add(896),
            ACK,
            8192,
            &[1], // Retained receive hole adds a 12-byte SACK option.
            &[tail],
        );
        assert_eq!(a.scoreboard.is_lost(a.snd_una, 128), covered > 256);
        let recovery = a.sack_recovery.unwrap();
        let nxt = a.snd_nxt;
        let deadline = a.rto_deadline;
        assert_eq!(a.transmit(211, &mut [0; 8]), Err(Error::OutputTooSmall));
        assert_eq!(a.snd_nxt, nxt);
        assert_eq!(a.rto_deadline, deadline);
        let unchanged = a.sack_recovery.unwrap();
        assert_eq!(unchanged.high_rxt, recovery.high_rxt);
        assert_eq!(unchanged.rescue_rxt, recovery.rescue_rxt);
        assert_eq!(unchanged.pipe, recovery.pipe);
        let bytes = packet(&mut a, 211);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.payload.len(), 116);
        assert!(segment.options.sack_blocks[0].is_some());
        assert_eq!(
            segment.header.sequence,
            if covered > 256 { a.snd_una.0 } else { point.0 }
        );
        assert_eq!(a.sack_recovery.unwrap().recovery_point, point);
        if covered <= 256 {
            assert_eq!(segment.payload, &[9; 116]);
            assert_eq!(a.snd_nxt, point.wrapping_add(116));
            assert_eq!(a.sack_recovery.unwrap().high_rxt, recovery.high_rxt);
        } else {
            assert_eq!(a.snd_nxt, point);
            assert_eq!(
                a.sack_recovery.unwrap().high_rxt,
                a.snd_una.wrapping_add(116)
            );
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=One SACK ACK leaves pipe 256 under cwnd 512; successive pulls send two packets and stop at credit or window limits. Options clip packets without lowering SMSS credit; failed output preserves pending work and accounting.
//# (3.3) If (cwnd - pipe) >= 1 SMSS, there exists previously unsent data, and
//# the receiver's advertised window allows, transmit up to 1 SMSS of data
//# starting with the octet HighData+1 and update HighData to reflect this
//# transmission, then return to (3.2).
//= https://www.rfc-editor.org/rfc/rfc3042#section-2
//= type=test
//= reason=Non-RACK/non-PRR RFC6675 profile: two-MSS SACK delivery permits two outputs on one ACK, not Reno one-packet credit. Assert total sequence-space flight <= cwnd+2*SMSS, peer-window bound and exhaustion with/without outgoing SACK option clipping.
//# The amount of outstanding data would remain less than or equal to the congestion window
//# plus 2 segments. In other words, the sender can only send two segments beyond the
//# congestion window (cwnd).
//= https://www.rfc-editor.org/rfc/rfc3042#section-2
//= type=test
//= reason=Peer window with one-MSS headroom limits repeated SetPipe admission to one packet; every matrix case checks total flight <= peer window.
//# The receiver's advertised window allows the transmission of the segment.
fn sack_limited_transmit_repeats_setpipe_on_same_ack() {
    for (piggyback, window, queued, packets) in [
        (false, 8192, 1024, 2),
        (true, 8192, 1024, 2),
        (false, 640, 1024, 1),
        (false, 8192, 640, 1),
    ] {
        let (mut a, _) = pair(sack_config(128), 100);
        a.write(&vec![1; queued]).unwrap();
        for now in 40..44 {
            packet(&mut a, now);
        }
        let una = a.snd_una;
        let end = a.snd_nxt;
        assert_eq!(a.flight(), 512);
        assert_eq!(a.congestion.cwnd(), 512);
        let next = a.receive.next();
        inject_sack(
            &mut a,
            50,
            if piggyback {
                next.wrapping_add(1)
            } else {
                next
            },
            una,
            ACK,
            window,
            if piggyback { &[1] } else { &[] },
            &[(una.wrapping_add(128).0, una.wrapping_add(384).0)],
        );
        assert_eq!(a.recovery_pipe(una), 256);
        assert_eq!(a.duplicate_acks, 1);
        assert!(a.limited_pending);
        let budget = if piggyback { 116 } else { 128 };
        for i in 0..packets {
            let nxt = a.snd_nxt;
            let sent = a.limited_sent;
            let limited_end = a.limited_end;
            let deadline = a.rto_deadline;
            assert_eq!(a.transmit(51, &mut [0; 8]), Err(Error::OutputTooSmall));
            assert_eq!(a.snd_nxt, nxt);
            assert_eq!(a.limited_sent, sent);
            assert_eq!(a.limited_end, limited_end);
            assert_eq!(a.rto_deadline, deadline);
            assert!(a.limited_pending);
            let bytes = packet(&mut a, 51);
            let segment = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(segment.header.sequence, end.wrapping_add(i * budget).0);
            assert_eq!(segment.payload.len(), budget as usize);
            assert_eq!(a.limited_sent, (i + 1) * budget);
            assert_eq!(a.limited_end, Some(a.snd_nxt));
        }
        assert!(!a.limited_pending);
        assert_eq!(a.transmit(52, &mut [0; 1024]), Ok(None));
        assert_eq!(a.duplicate_acks, 1);
        assert!(a.recovery_pipe(una) <= a.congestion.cwnd());
        assert!(a.flight() <= a.snd_wnd);
        assert!(a.flight() <= a.congestion.cwnd() + 2 * a.mss as u32);
    }
}

fn sack_config(mss: u16) -> ConnectionConfig {
    ConnectionConfig {
        sack: true,
        nagle: false,
        delayed_ack_us: 0,
        ..config(8192, mss)
    }
}

fn sack_ack(a: &mut Connection, now: Instant, ack: Seq, blocks: &[(u32, u32)]) {
    inject_sack(a, now, a.receive.next(), ack, ACK, 8192, &[], blocks);
}

fn sack_flight(mss: u16, iss: u32, segments: usize) -> Connection {
    let (mut a, mut b) = pair(sack_config(mss), iss);
    // Grow cwnd through real cumulative acknowledgments, not test-only setters.
    for round in 0..segments {
        a.write(&vec![0x55; mss as usize]).unwrap();
        deliver(&mut a, &mut b, 40 + round as u64 * 2);
        deliver(&mut b, &mut a, 41 + round as u64 * 2);
        b.read(&mut vec![0; mss as usize]).unwrap();
    }
    a.write(&vec![0x77; mss as usize * segments]).unwrap();
    for i in 0..segments {
        packet(&mut a, 100 + i as u64);
    }
    a
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc2018#section-4
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Enabled receiver emits kind 5 after SYN permission; reordered data yields SACK and gap fill removes it.
//# If the data receiver has received a SACK-Permitted option on the SYN for
//# this connection, the data receiver MAY elect to generate SACK options as
//# described below.
//= https://www.rfc-editor.org/rfc/rfc2018#section-4
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Ordinary reordered arrivals schedule immediate ACKs, output includes retained ranges; tests parse emitted ACKs.
//# If the data receiver generates SACK options under any circumstance, it
//# SHOULD generate them under all permitted circumstances.
//= https://www.rfc-editor.org/rfc/rfc2018#section-4
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Ordinary reordered arrivals schedule immediate ACKs, output includes retained ranges; tests parse emitted ACKs.
//# If sent at all, SACK options SHOULD be included in all ACKs which do not ACK
//# the highest sequence number in the data receiver's queue.
//= https://www.rfc-editor.org/rfc/rfc2018#section-4
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Ordinary reordered arrivals schedule immediate ACKs, output includes retained ranges; tests parse emitted ACKs.
//# The receiver SHOULD send an ACK for every valid segment that arrives
//# containing new data, and each of these "duplicate" ACKs SHOULD bear a SACK
//# option.
//= https://www.rfc-editor.org/rfc/rfc2018#section-3
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Wire ACK remains cumulative across SACK reports and advances to end only after gap fill.
//# When missing segments are received, the data receiver acknowledges the data
//# normally by advancing the left window edge in the Acknowledgement Number
//# Field of the TCP header. The SACK option does not change the meaning of the
//# Acknowledgement Number field.
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
//= type=test
//= reason=Receiver ACK scheduling applies regardless of sender recovery choice; SACK receive trace polls immediate ACK after reordered data and full gap fill and checks cumulative sequence. Partial-only gap fill is asserted by partial_gap_ack_is_immediate_and_output_is_coalesced.
//# A TCP receiver SHOULD send an immediate duplicate ACK when an out- of-order segment
//# arrives.
//= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
//= type=test
//= reason=Receiver scheduling after reorder/full gap fill is directly observed in SACK wire trace, with expected cumulative ACK sequence. Applies regardless of local sender recovery profile; partial-only gap fill is asserted by partial_gap_ack_is_immediate_and_output_is_coalesced.
//# Out-of-order data segments SHOULD be acknowledged immediately, in order to accelerate
//# loss recovery.
//= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
//= type=test
//= reason=Receiver scheduling after reorder/full gap fill is directly observed in SACK wire trace, with expected cumulative ACK sequence. Applies regardless of local sender recovery profile; partial-only gap fill is asserted by partial_gap_ack_is_immediate_and_output_is_coalesced.
//# To trigger the fast retransmit algorithm, the receiver SHOULD send an immediate
//# duplicate ACK when it receives a data segment above a gap in the sequence space.
//= https://www.rfc-editor.org/rfc/rfc2883#section-2
//= type=test
//= reason=D-SACK alters option contents only; cumulative ACK still follows receive frontier and ACK scheduling remains normal TCP.
//# This document does not make any changes to TCP's use of the
//# cumulative acknowledgement field, or to the TCP receiver's decision
//# of *when* to send an acknowledgement packet.
//= https://www.rfc-editor.org/rfc/rfc2883#section-2
//= type=test
//= reason=Existing SACK negotiation gates duplicate reports, no separate D-SACK capability flag or handshake option.
//# The use of D-SACK does not require separate negotiation between a TCP
//# sender and receiver that have already negotiated SACK capability.
//= https://www.rfc-editor.org/rfc/rfc2883#section-4
//= type=test
//= reason=Planning/retry does not consume pending report; successful SACK-bearing ACK consumes it once. Second identical report requires fresh duplicate recording.
//# (2) Each duplicate contiguous sequence of data received is reported
//# in at most one D-SACK block.  (I.e., the receiver sends two identical
//# D-SACK blocks in subsequent packets only if the receiver receives two
//# duplicate segments.)
//= https://www.rfc-editor.org/rfc/rfc2883#section-4
//= type=test
//= reason=Pending raw duplicate occupies first block, ahead of containing/other ordinary SACK ranges; option budget may decline duplicate report, not mislabel an ordinary block as DSACK.
//# When D-SACK is used, the
//# first block of the SACK option should be a D-SACK block specifying
//# the sequence numbers for the duplicate segment that triggers the
//# acknowledgement.
fn sack_receiver_reorder_gap_fill_and_dsack_transaction() {
    for iss in [100, u32::MAX - 20] {
        let (mut a, mut b) = pair(sack_config(128), iss);
        a.write(&[1; 384]).unwrap();
        let first = packet(&mut a, 40);
        let second = packet(&mut a, 41);
        let third = packet(&mut a, 42);
        let start = wire::parse(ip(tuple()), &first).unwrap().header.sequence;
        b.input(50, &wire::parse(ip(tuple()), &second).unwrap())
            .unwrap();
        let ack = packet(&mut b, 51);
        let ack = wire::parse(ip(reverse(tuple())), &ack).unwrap();
        assert_eq!(ack.header.acknowledgment, start);
        assert_eq!(
            ack.options.sack_blocks[0],
            Some((start.wrapping_add(128), start.wrapping_add(256)))
        );
        b.input(52, &wire::parse(ip(tuple()), &third).unwrap())
            .unwrap();
        packet(&mut b, 53);
        b.input(54, &wire::parse(ip(tuple()), &third).unwrap())
            .unwrap();
        assert_eq!(b.transmit(55, &mut [0; 20]), Err(Error::OutputTooSmall));
        let bytes = packet(&mut b, 55);
        let ack = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
        assert_eq!(
            ack.options.sack_blocks[..2],
            [
                Some((start.wrapping_add(256), start.wrapping_add(384))),
                Some((start.wrapping_add(128), start.wrapping_add(384)))
            ]
        );
        b.immediate_ack();
        let bytes = packet(&mut b, 56);
        assert_eq!(
            wire::parse(ip(reverse(tuple())), &bytes)
                .unwrap()
                .options
                .sack_blocks[0],
            Some((start.wrapping_add(128), start.wrapping_add(384)))
        );
        b.input(57, &wire::parse(ip(tuple()), &first).unwrap())
            .unwrap();
        let bytes = packet(&mut b, 58);
        let ack = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
        assert_eq!(ack.header.acknowledgment, start.wrapping_add(384));
        assert!(ack.options.sack_blocks.iter().all(Option::is_none));
        b.read(&mut [0; 384]).unwrap();
        b.input(59, &wire::parse(ip(tuple()), &first).unwrap())
            .unwrap();
        assert!(!b.accepted_metadata); // Narrow old-data path accepts no metadata.
        let bytes = packet(&mut b, 60);
        assert_eq!(
            wire::parse(ip(reverse(tuple())), &bytes)
                .unwrap()
                .options
                .sack_blocks[0],
            Some((start, start.wrapping_add(128)))
        );
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc2018#section-4
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Output uses available TCP/path option budget; tests assert 4 ordinary slots or 3 with timestamps, payload clipping and failed-output rollback.
//# * The data receiver SHOULD include as many distinct SACK blocks as possible
//# in the SACK option.
fn sack_options_budget_ts_payload_fin_and_failed_output() {
    for timestamps in [false, true] {
        let cfg = ConnectionConfig {
            timestamps,
            send_ip_payload_limit: 160,
            ..sack_config(128)
        };
        let (mut a, _) = pair(cfg, 100);
        let next = a.receive.next();
        for (i, offset) in [10, 30, 50, 70].into_iter().enumerate() {
            let una = a.snd_una;
            inject_sack(
                &mut a,
                1000 + i as u64,
                next.wrapping_add(offset),
                una,
                ACK,
                8192,
                &[1; 5],
                &[],
            );
            packet(&mut a, 1000 + i as u64);
        }
        // Restore a pending option report and send final queued bytes with FIN.
        let una = a.snd_una;
        inject_sack(
            &mut a,
            2000,
            next.wrapping_add(70),
            una,
            ACK,
            8192,
            &[1; 5],
            &[],
        );
        a.write(&[2; 128]).unwrap();
        a.shutdown().unwrap();
        let before = (
            a.snd_nxt,
            a.fin_sequence,
            a.now,
            a.rto_deadline,
            a.last_ack_sent,
        );
        assert_eq!(a.transmit(3000, &mut [0; 20]), Err(Error::OutputTooSmall));
        assert_eq!(
            before,
            (
                a.snd_nxt,
                a.fin_sequence,
                a.now,
                a.rto_deadline,
                a.last_ack_sent
            )
        );
        let bytes = packet(&mut a, 3000);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(
            segment.options.sack_blocks.iter().flatten().count(),
            if timestamps { 3 } else { 4 }
        );
        assert_eq!(
            segment.payload.len(),
            a.mss - if timestamps { 28 } else { 36 }
        );
        assert!(bytes.len() <= 160);
        assert_eq!(segment.header.flags & (FIN | PSH), 0);
        let bytes = packet(&mut a, 4000);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.header.flags & (FIN | PSH), FIN | PSH);
        assert_eq!(
            a.fin_sequence,
            Some(Seq(segment.header.sequence).wrapping_add(segment.payload.len() as u32))
        );
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Validated negotiated ACKs, including reordered ACKs, update live in-flight ranges; malformed/future/DSACK-only blocks cannot count as fresh delivery.
//# Upon the receipt of any ACK containing SACK information, the scoreboard MUST
//# be updated via the Update () routine.
//= https://www.rfc-editor.org/rfc/rfc2883#section-4.3
//= type=test
//= reason=Wrapped prior-cycle D-SACK below UNA or within already-SACKed data remains advisory during RACK/PRR recovery: no send storage release, UNA advance, congestion undo, new delivery or RTT credit. Reordering adaptation is bounded; duplicate reports cannot authenticate a sequence cycle.
//# TCP senders receiving D-SACK blocks should be aware that a segment
//# reported as a duplicate segment could possibly have been from a prior
//# cycle through the sequence number space.
fn sack_invalid_future_out_of_bounds_ack_and_dsack_are_not_delivery() {
    let mut a = sack_flight(128, 100, 6);
    let una = a.snd_una;
    let end = a.data_high();
    let next = a.receive.next();
    let timer = a.rto_deadline;
    for (i, (ack, block)) in [
        (end.wrapping_add(1), (una.wrapping_add(128).0, end.0)),
        (
            una.wrapping_add(0u32.wrapping_sub(a.max_snd_wnd + 1)),
            (una.wrapping_add(128).0, end.0),
        ),
        (una, (una.wrapping_add(128).0, end.wrapping_add(1).0)),
        (una, (end.0, una.0)),
        (una, (una.0, una.0)),
        (una, (una.wrapping_add(1 << 31).0, end.0)),
        (una, (una.wrapping_add(u32::MAX - 9).0, una.0)),
    ]
    .into_iter()
    .enumerate()
    {
        inject_sack(&mut a, 200 + i as u64, next, ack, ACK, 8192, &[], &[block]);
        assert_eq!(a.duplicate_acks, 0);
        assert!(a.sack_recovery.is_none());
        assert_eq!(
            a.scoreboard.pipe(una, end, una, 128),
            end.distance_from(una)
        );
    }
    assert_eq!(a.rto_deadline, timer);
    assert_eq!(a.send.len(), 768);
    let ack = a.snd_una;
    // The second enclosing block is evidence once; the first DSACK is not.
    sack_ack(
        &mut a,
        220,
        ack,
        &[
            (una.wrapping_add(140).0, una.wrapping_add(150).0),
            (una.wrapping_add(128).0, una.wrapping_add(256).0),
        ],
    );
    assert_eq!(a.duplicate_acks, 1);
    sack_ack(
        &mut a,
        221,
        ack,
        &[
            (una.wrapping_add(140).0, una.wrapping_add(150).0),
            (una.wrapping_add(128).0, una.wrapping_add(256).0),
        ],
    );
    assert_eq!(a.duplicate_acks, 1);
    assert_eq!(a.send.len(), 768);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6675#section-4
//= type=test
//= reason=Negotiated non-RACK/non-PRR SACK; full-budget and piggybacked-SACK regressions exercise lost/new/speculative/rescue priority. IsLost uses SMSS independently of output clipping; markers commit only after encoding.
//# NextSeg () MUST return the
//# sequence number range of the next segment that is to be
//# transmitted, per the following rules:
//= https://www.rfc-editor.org/rfc/rfc2018#section-8
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Only validated cumulative ACK calls SendBuffer::acknowledge; test asserts 1024 bytes retained across selective recovery and zero only after full ACK.
//# Since the data receiver may later discard data reported in a SACK option,
//# the sender MUST NOT discard data before it is acknowledged by the
//# Acknowledgment Number field in the TCP header.
//= https://www.rfc-editor.org/rfc/rfc6675#section-4
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Update/IsLost/SetPipe are byte-range scoreboard functions; NextSeg is in poll-driven output selection, not a literal function. Focused scoreboard reference and priority tests provide behavioral evidence.
//# For the purposes of the algorithm defined in this document, the scoreboard
//# SHOULD implement the following functions:
//= https://www.rfc-editor.org/rfc/rfc6675#section-4
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. SACK updates never release send bytes; cumulative ACK is the release path and is asserted separately.
//# Note: SACK information is advisory and therefore SACKed data MUST NOT be
//# removed from the TCP's retransmission buffer until the data is cumulatively
//# acknowledged [RFC2018].
//= https://www.rfc-editor.org/rfc/rfc6675#section-4
//= type=test
//= reason=Negotiated non-RACK/non-PRR SACK; lowest_hole uses SMSS for IsLost and output is clipped to the packet budget. Integrated 240/256/257-byte SACK cases verify the strict loss threshold and fresh-data priority with SMSS 128 and budget 116.
//# (1) If there exists a smallest unSACKed sequence number 'S2' that meets the
//# following three criteria for determining loss, the sequence range of one
//# segment of up to SMSS octets starting with S2 MUST be returned.
//= https://www.rfc-editor.org/rfc/rfc6675#section-4
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. No remaining permitted candidate yields Ok(None); rescue test separately denies repeated rescue.
//# (5) If the conditions for each of (1), (2), (3), and (4) are not met, then
//# NextSeg () MUST indicate failure, and no segment is returned.
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Exclusive recovery boundary is cumulatively ACKed; recovery terminates, send storage releases and cwnd is deflated.
//# (A) An incoming cumulative ACK for a sequence number greater than
//# RecoveryPoint signals the end of loss recovery, and the loss recovery phase
//# MUST be terminated.
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Output uses scoreboard lowest/tail-hole selection and fails without a candidate; test checks multiple output ranges then Ok(None).
//# (C.1) The scoreboard MUST be queried via NextSeg () for the sequence number
//# range of the next segment to transmit (if any), and the given segment sent.
//= https://www.rfc-editor.org/rfc/rfc2018#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Equivalent byte-range strategy skips SACKed intervals in retransmission selection; test sends only missing offsets 0 and 256. RTO intentionally clears advice.
//# After the SACKed bit is turned on (as the result of processing a received
//# SACK option), the data sender will skip that segment during any later
//# retransmission.
//= https://www.rfc-editor.org/rfc/rfc2018#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Byte buffer is retained across SACKs and released only by cumulative ACK.
//# A segment will not be dequeued and its buffer freed until the left window
//# edge is advanced over it.
//= https://www.rfc-editor.org/rfc/rfc6675#section-4
//= type=test
//= reason=Negotiated non-RACK/non-PRR SACK; lowest_hole uses SMSS for IsLost and output is clipped to the packet budget. Integrated 240/256/257-byte SACK cases verify the strict loss threshold and fresh-data priority with SMSS 128 and budget 116.
//# (1.a) S2 is greater than HighRxt.
//= https://www.rfc-editor.org/rfc/rfc6675#section-4
//= type=test
//= reason=Negotiated non-RACK/non-PRR SACK; lowest_hole uses SMSS for IsLost and output is clipped to the packet budget. Integrated 240/256/257-byte SACK cases verify the strict loss threshold and fresh-data priority with SMSS 128 and budget 116.
//# (1.b) S2 is less than the highest octet covered by any received SACK.
//= https://www.rfc-editor.org/rfc/rfc6675#section-4
//= type=test
//= reason=Negotiated non-RACK/non-PRR SACK; lowest_hole uses SMSS for IsLost and output is clipped to the packet budget. Integrated 240/256/257-byte SACK cases verify the strict loss threshold and fresh-data priority with SMSS 128 and budget 116.
//# (1.c) IsLost (S2) returns true.
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Entry records fixed data_high boundary; cumulative ACK at exclusive boundary ends recovery.
//# (4.1) RecoveryPoint = HighData When the TCP sender receives a cumulative ACK
//# for this data octet, the loss recovery phase is terminated.
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. entry_pending retransmits snd_una regardless of advisory SACK, bounded by real data high, output and peer window; sack_entry_retransmits_sacked_head_transactionally checks committed exclusive HighRxt/RescueRxt and SetPipe after success, not failure.
//# (4.3) Retransmit the first data segment presumed dropped -- the segment
//# starting with sequence number HighACK + 1. To prevent repeated
//# retransmission of the same data or a premature rescue retransmission, set
//# both HighRxt and RescueRxt to the highest sequence number in the
//# retransmitted segment.
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Entry initializes pipe from scoreboard and successful entry retransmission recomputes SetPipe with committed HighRxt, including when advisory SACK covers the head.
//# (4.4) Run SetPipe () Set a "pipe" variable to the number of outstanding
//# octets currently "in the pipe"; this is the data which has been sent by the
//# TCP sender but for which no cumulative or selective acknowledgment has been
//# received and the data has not been determined to have been dropped in the
//# network. It is assumed that the data is still traversing the network path.
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. No candidate returns no segment; multiloss and rescue tests assert Ok(None).
//# If NextSeg () returns failure (no data to send), return without sending
//# anything (i.e., terminate steps C.1 -- C.5).
//= https://www.rfc-editor.org/rfc/rfc6675#section-6
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Optional timer variant uses the shared successful-retransmission commit path. sack_multiloss_selective_recovery_and_transactional_entry asserts exact send_time+rto after both retransmissions, failed-output stability and nonadvancing-SACK nonrestart; sack_rto_discards_advice_retransmits_head_and_guards_epoch checks entry and expiry.
//# Therefore, we give implementers the latitude to use the standard
//# [RFC6298]-style RTO management or, optionally, a more careful variant that
//# re-arms the RTO timer on each retransmission that is sent during recovery
//# MAY be used.
//= https://www.rfc-editor.org/rfc/rfc5681#section-4.3
//= type=test
//= reason=Recommendation to employ multi-loss recovery: default NewReno handles partial ACKs; opt-in negotiated SACK repairs multiple holes. These tests evidence algorithm selection and multi-loss repair only, not every section4.3 general bound (TODOs remain).
//# We RECOMMEND that TCP implementors employ some form of advanced loss recovery that can
//# cope with multiple losses in a window of data. The algorithms detailed in [RFC3782] and
//# [RFC3517] conform to the general principles outlined above. We note that while these are
//# not the only two algorithms that conform to the above general principles these two
//# algorithms have been vetted by the community and are currently on the Standards Track.
fn sack_multiloss_selective_recovery_and_transactional_entry() {
    for iss in [100, u32::MAX - 1000] {
        let mut a = sack_flight(128, iss, 8);
        let una = a.snd_una;
        let point = a.data_high();
        // Losses at 0 and 256; enough new bytes above both to mark both lost.
        sack_ack(
            &mut a,
            200,
            una,
            &[
                (una.wrapping_add(128).0, una.wrapping_add(256).0),
                (una.wrapping_add(384).0, point.0),
            ],
        );
        let recovery = a.sack_recovery.unwrap();
        assert!(recovery.entry_pending);
        assert_eq!(recovery.high_rxt, una);
        let original_deadline = a.rto_deadline;
        assert_eq!(a.transmit(201, &mut [0; 8]), Err(Error::OutputTooSmall));
        assert_eq!(a.rto_deadline, original_deadline);
        assert!(a.sack_recovery.unwrap().entry_pending);
        assert_eq!(a.sack_recovery.unwrap().rescue_rxt, None);
        let bytes = packet(&mut a, 201);
        let first = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(first.header.sequence, una.0);
        assert_eq!(first.payload.len(), 128);
        assert_eq!(a.rto_deadline, Some(201 + a.rto()));
        assert_eq!(a.sack_recovery.unwrap().high_rxt, una.wrapping_add(128));
        let first_deadline = a.rto_deadline;
        assert_eq!(a.transmit(202, &mut [0; 8]), Err(Error::OutputTooSmall));
        assert_eq!(a.rto_deadline, first_deadline);
        let bytes = packet(&mut a, 202);
        let second = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(second.header.sequence, una.wrapping_add(256).0);
        assert_eq!(second.payload.len(), 128);
        assert_eq!(a.rto_deadline, Some(202 + a.rto()));
        let second_deadline = a.rto_deadline;
        sack_ack(
            &mut a,
            203,
            una,
            &[
                (una.wrapping_add(128).0, una.wrapping_add(256).0),
                (una.wrapping_add(384).0, point.0),
            ],
        );
        assert_eq!(a.snd_una, una);
        assert_eq!(a.rto_deadline, second_deadline);
        assert_eq!(a.transmit(203, &mut [0; 1024]), Ok(None));
        assert_eq!(a.send.len(), 1024); // SACK never frees send bytes.
        assert_eq!(a.acknowledged, 1024); // Only the warmup was ACKed.
        sack_ack(&mut a, 210, point, &[]);
        assert!(a.sack_recovery.is_none());
        assert_eq!(a.send.len(), 0);
        assert_eq!(a.congestion.cwnd(), 256);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Non-RACK/non-PRR entry with a valid SACKed head retransmits snd_una across wrap, clips to output/peer/data limits, and commits exclusive HighRxt/RescueRxt and recomputed pipe only after successful encoding.
//# (4.3) Retransmit the first data segment presumed dropped -- the segment
//# starting with sequence number HighACK + 1. To prevent repeated
//# retransmission of the same data or a premature rescue retransmission, set
//# both HighRxt and RescueRxt to the highest sequence number in the
//# retransmitted segment.
fn sack_entry_retransmits_sacked_head_transactionally() {
    for iss in [100, u32::MAX - 1000] {
        for (tail, window, ooo, expected) in [
            (1024, 8192, false, 128),
            (1024, 63, false, 63),
            (1024, 8192, true, 116),
            (31, 8192, false, 31),
        ] {
            let mut a = sack_flight(128, iss, 8);
            // Exercise the conservative policy without negotiated scaling.
            a.scaling = false;
            let una = a.data_high().wrapping_add(0u32.wrapping_sub(tail));
            sack_ack(&mut a, 190, una, &[]);
            if ooo {
                let seq = a.receive.next().wrapping_add(10);
                inject_sack(&mut a, 191, seq, una, ACK, window, b"ooo", &[]);
            }
            for (i, size) in [8, 16, 24].into_iter().enumerate() {
                let seq = a.receive.next();
                inject_sack(
                    &mut a,
                    200 + i as u64,
                    seq,
                    una,
                    ACK,
                    window,
                    &[],
                    &[(una.0, una.wrapping_add(size).0)],
                );
            }
            assert_eq!(a.scoreboard.ranges(), &[(una, una.wrapping_add(24))]);
            let before = a.sack_recovery.unwrap();
            assert!(before.entry_pending);
            let deadline = a.rto_deadline;
            assert_eq!(a.transmit(203, &mut [0; 8]), Err(Error::OutputTooSmall));
            let retry = a.sack_recovery.unwrap();
            assert_eq!(
                (
                    retry.high_rxt,
                    retry.rescue_rxt,
                    retry.pipe,
                    retry.entry_pending
                ),
                (
                    before.high_rxt,
                    before.rescue_rxt,
                    before.pipe,
                    before.entry_pending
                )
            );
            assert_eq!(a.rto_deadline, deadline);
            let bytes = packet(&mut a, 204);
            let segment = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(segment.header.sequence, una.0);
            assert_eq!(segment.payload, &[0x77; 128][..expected]);
            let recovery = a.sack_recovery.unwrap();
            let end = una.wrapping_add(expected as u32);
            assert!(!recovery.entry_pending);
            assert_eq!(recovery.high_rxt, end);
            assert_eq!(recovery.rescue_rxt, Some(end));
            assert_eq!(recovery.pipe, a.recovery_pipe(end));
            assert_eq!(a.scoreboard.ranges(), &[(una, una.wrapping_add(24))]);
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Non-RACK/non-PRR recovery sends new bytes beyond fixed RecoveryPoint, SACKs their suffix, exits with advice retained across wrap, recomputes pipe and uses retained advice to trigger later recovery on one new SACK ACK.
//# Any information contained in the scoreboard for sequence numbers greater
//# than the new value of HighACK SHOULD NOT be cleared when leaving the loss
//# recovery phase.
fn sack_recovery_exit_retains_new_data_advice_for_later_recovery() {
    for iss in [100, u32::MAX - 1800] {
        let mut a = sack_flight(128, iss, 12);
        let una = a.snd_una;
        let point = a.data_high();
        a.write(&[9; 512]).unwrap();
        sack_ack(&mut a, 200, una, &[(una.wrapping_add(128).0, point.0)]);
        packet(&mut a, 201); // Entry retransmission.
        for i in 0..4 {
            let bytes = packet(&mut a, 202 + i);
            let segment = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(
                segment.header.sequence,
                point.wrapping_add(i as u32 * 128).0
            );
            assert_eq!(segment.payload, &[9; 128]);
            assert_eq!(a.sack_recovery.unwrap().recovery_point, point);
        }
        let retained = (point.wrapping_add(128), point.wrapping_add(512));
        sack_ack(&mut a, 210, una, &[(retained.0.0, retained.1.0)]);
        let recovery = a.sack_recovery.unwrap();
        assert_eq!(recovery.pipe, a.recovery_pipe(recovery.high_rxt));
        sack_ack(&mut a, 211, point, &[]);
        assert!(a.sack_recovery.is_none());
        assert!(!a.congestion.in_recovery());
        assert_eq!(a.scoreboard.ranges(), &[retained]);
        assert_eq!(a.send.len(), 512);
        assert_eq!(a.recovery_pipe(point), 0); // 384 retained SACKed bytes mark the head lost.
        a.write(&[8; 128]).unwrap();
        let bytes = packet(&mut a, 212);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.sequence,
            retained.1.0
        );
        let high = a.snd_nxt;
        sack_ack(&mut a, 213, point, &[(retained.1.0, high.0)]);
        let recovery = a.sack_recovery.unwrap();
        assert!(recovery.entry_pending); // Only one fresh SACK; retained bytes supply IsLost evidence.
        assert_eq!(recovery.recovery_point, point.wrapping_add(640));
        assert_eq!(recovery.pipe, 0);
        assert_eq!(
            a.scoreboard.ranges(),
            &[(retained.0, point.wrapping_add(640))]
        );
        let bytes = packet(&mut a, 214);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.header.sequence, point.0);
        assert_eq!(segment.payload, &[9; 128]);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. A single ACK carrying three one-byte discontiguous SACK ranges starts recovery immediately and emits one SMSS starting at snd_una regardless of advisory SACK edges.
//# (2) If DupAcks < DupThresh but IsLost (HighACK + 1) returns true --
//# indicating at least three segments have arrived above the current cumulative
//# acknowledgment point, which is taken to indicate loss -- go to step (4).
fn sack_discontiguous_evidence_and_unaligned_retransmit() {
    let mut a = sack_flight(128, 100, 8);
    let una = a.snd_una;
    sack_ack(
        &mut a,
        200,
        una,
        &[
            (una.wrapping_add(17).0, una.wrapping_add(18).0),
            (una.wrapping_add(91).0, una.wrapping_add(92).0),
            (una.wrapping_add(201).0, una.wrapping_add(202).0),
        ],
    );
    assert!(a.sack_recovery.is_some()); // Three ranges, not three SMSS.
    let bytes = packet(&mut a, 201);
    let segment = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(segment.header.sequence, una.0);
    assert_eq!(segment.payload.len(), 128); // Entry does not clip at advisory SACK edges.
    // ACK trims arbitrary bytes; a retransmission starts from that offset.
    sack_ack(&mut a, 202, una.wrapping_add(7), &[]);
    assert_eq!(a.snd_una, una.wrapping_add(7));
    assert_eq!(a.send.len(), 1017);
    assert_eq!(
        a.sack_recovery.unwrap().recovery_point,
        una.wrapping_add(1024)
    );
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. New SACK evidence increments once even on duplex/window-changing ACK; repeated blocks do not earn new credit.
//# If the incoming ACK is a duplicate acknowledgment per the definition in
//# Section 2 (regardless of its status as a cumulative acknowledgment), and the
//# TCP is not currently in loss recovery, the TCP MUST increase DupAcks by one
//# and take the following steps:
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated non-RACK/non-PRR SACK; each output poll recomputes SetPipe and sends up to the packet budget while SMSS credit and peer window permit. Integrated tests exhaust two-SMSS credit from one ACK, check window/option limits and failed-output rollback.
//# (3) The TCP MAY transmit previously unsent data segments as per Limited
//# Transmit [RFC5681], except that the number of octets which may be sent is
//# governed by pipe and cwnd as follows:
//= https://www.rfc-editor.org/rfc/rfc6675#section-2
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. New in-flight SACK bytes qualify even when ACK carries duplex data or changes window; advancing-ACK test separately checks reset then increment.
//# For the purposes of this specification, we define a "duplicate
//# acknowledgment" as a segment that arrives carrying a SACK block that
//# identifies previously unacknowledged and un-SACKed octets between HighACK
//# and HighData. Note that an ACK which carries new SACK data is counted as a
//# duplicate acknowledgment under this definition even if it carries new data,
//# changes the advertised window, or moves the cumulative acknowledgment point,
//# which is different from the definition of duplicate acknowledgment in
//# [RFC5681].
//= https://www.rfc-editor.org/rfc/rfc6675#section-2
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Threshold is three fresh-evidence ACKs; recovery starts on third, not repeated SACK blocks.
//# Per [RFC5681], this threshold is defined to be 3 duplicate acknowledgments.
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Three fresh evidence ACKs start recovery; repeated evidence is not counted.
//# (1) If DupAcks >= DupThresh, go to step (4).
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Limited-transmit pipe passes snd_una (exclusive HighACK) as high_rxt.
//# (3.1) Set HighRxt to HighACK.
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated non-RACK/non-PRR SACK; each output poll recomputes SetPipe and sends up to the packet budget while SMSS credit and peer window permit. Integrated tests exhaust two-SMSS credit from one ACK, check window/option limits and failed-output rollback.
//# (3.2) Run SetPipe ().
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated non-RACK/non-PRR SACK; each output poll recomputes SetPipe and sends up to the packet budget while SMSS credit and peer window permit. Integrated tests exhaust two-SMSS credit from one ACK, check window/option limits and failed-output rollback.
//# (3.3) If (cwnd - pipe) >= 1 SMSS, there exists previously unsent data, and
//# the receiver's advertised window allows, transmit up to 1 SMSS of data
//# starting with the octet HighData+1 and update HighData to reflect this
//# transmission, then return to (3.2).
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Event input returns; output is poll-driven and repeated evidence gives no extra credit.
//# (3.4) Terminate processing of this ACK.
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
//= type=test
//= reason=Negotiated SACK (non-RACK/non-PRR test profile): empty/repeated SACK grants no Limited Transmit output; new SACK including duplex data grants one packet. No assertion that bare non-SACK DupACKs are SACK delivery.
//# Note that a sender using SACK [RFC2018] MUST NOT send new data unless the incoming
//# duplicate acknowledgment contains new SACK information.
//= https://www.rfc-editor.org/rfc/rfc5681#section-2
//= type=test
//= reason=Negotiated SACK fresh byte evidence defines duplicate ACK, including duplex input; repeated/no SACK cannot grant new credit. Non-SACK five-predicate definition remains TODO.
//# Alternatively, a TCP that utilizes selective acknowledgments (SACKs) [RFC2018, RFC2883]
//# can leverage the SACK information to determine when an incoming ACK is a "duplicate"
//# (e.g., if the ACK contains previously unknown SACK information).
//= https://www.rfc-editor.org/rfc/rfc3042#section-2
//= type=test
//= reason=Empty and repeated SACK produce no fresh packet. Newly SACKed sent ranges grant new sequence data, including a duplex ACK; tests hold cwnd constant.
//# Note: If the connection is using selective acknowledgments [RFC2018], the data sender MUST
//# NOT send new segments in response to duplicate ACKs that contain no new SACK information,
//# as a misbehaving receiver can generate such ACKs to trigger inappropriate transmission of
//# data segments.
//= https://www.rfc-editor.org/rfc/rfc3042#section-2
//= type=test
//= reason=Both fresh SACK ACKs and their Limited Transmit output preserve the original cwnd.
//# The congestion window (cwnd) MUST NOT be changed when these new segments are transmitted.
fn sack_limited_transmit_requires_new_evidence_including_duplex_ack() {
    let (mut a, _) = pair(sack_config(128), 100);
    a.write(&[1; 1024]).unwrap();
    for now in 40..44 {
        packet(&mut a, now);
    }
    let cwnd = a.congestion.cwnd();
    let una = a.snd_una;
    let end = a.snd_nxt;
    sack_ack(&mut a, 50, una, &[]);
    assert_eq!(a.transmit(51, &mut [0; 1024]), Ok(None));
    let next = a.receive.next();
    inject_sack(
        &mut a,
        52,
        next,
        una,
        ACK,
        8000,
        b"duplex",
        &[(una.wrapping_add(128).0, una.wrapping_add(256).0)],
    );
    assert_eq!(a.duplicate_acks, 1);
    assert_eq!(a.congestion.cwnd(), cwnd);
    let bytes = packet(&mut a, 53);
    assert_eq!(
        wire::parse(ip(tuple()), &bytes).unwrap().header.sequence,
        end.0
    );
    assert_eq!(a.limited_sent, 128);
    assert_eq!(a.congestion.cwnd(), cwnd);
    sack_ack(
        &mut a,
        54,
        una,
        &[(una.wrapping_add(128).0, una.wrapping_add(256).0)],
    );
    assert_eq!(a.transmit(55, &mut [0; 1024]), Ok(None));
    sack_ack(
        &mut a,
        56,
        una,
        &[(una.wrapping_add(256).0, una.wrapping_add(384).0)],
    );
    packet(&mut a, 57);
    assert_eq!(a.limited_sent, 256);
    assert_eq!(a.congestion.cwnd(), cwnd);
    sack_ack(&mut a, 58, una, &[(una.wrapping_add(384).0, end.0)]);
    assert!(a.sack_recovery.is_some());
    assert_eq!(a.congestion.ssthresh(), 256); // Excludes 256 limited bytes.
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc2018#section-5.1
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Congestion controller halves eligible flight, excludes limited bytes and avoids duplicate ECN reductions. This cites integration, not all congestion-control recommendations.
//# However, the congestion control algorithms present in the de facto standard
//# TCP implementations MUST be preserved [Stevens94].
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Congestion on_sack_recovery sets cwnd=ssthresh=half eligible flight with RFC5681 minimum; outstanding limited bytes excluded even after partial ACK. ECN epoch guards prevent second reduction.
//# (4.2) ssthresh = cwnd = (FlightSize / 2) The congestion window (cwnd) and
//# slow start threshold (ssthresh) are reduced to half of FlightSize per
//# [RFC5681]. Additionally, note that [RFC5681] requires that any segments sent
//# as part of the Limited Transmit mechanism not be counted in FlightSize for
//# the purpose of the above equation.
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
//= type=test
//= reason=Non-SACK third DupACK threshold uses flight minus limited_sent; wire assertion flight=24, limited=8, ssthresh=8 at MSS4. Negotiated SACK partial advancing ACK trace additionally retains unacknowledged Limited Transmit exclusion. ECN reduction epoch sharing is separately scoped.
//# When the third duplicate ACK is received, a TCP MUST set ssthresh to no more than the
//# value given in equation (4).
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
//= type=test
//= reason=Non-SACK third DupACK threshold uses flight minus limited_sent; wire assertion flight=24, limited=8, ssthresh=8 at MSS4. Negotiated SACK partial advancing ACK trace additionally retains unacknowledged Limited Transmit exclusion. ECN reduction epoch sharing is separately scoped.
//# When [RFC3042] is in use, additional data sent in limited transmit MUST NOT be included
//# in this calculation.
fn sack_advancing_ack_keeps_unacked_limited_bytes_out_of_reduction() {
    let (mut a, _) = pair(sack_config(128), 100);
    a.write(&[1; 1024]).unwrap();
    for now in 40..44 {
        packet(&mut a, now);
    }
    let una = a.snd_una;
    sack_ack(
        &mut a,
        50,
        una,
        &[(una.wrapping_add(128).0, una.wrapping_add(256).0)],
    );
    packet(&mut a, 51);
    sack_ack(
        &mut a,
        52,
        una,
        &[(una.wrapping_add(256).0, una.wrapping_add(384).0)],
    );
    packet(&mut a, 53);
    assert_eq!(a.limited_sent, 256);
    let end = a.snd_nxt;
    sack_ack(
        &mut a,
        54,
        una.wrapping_add(64),
        &[(una.wrapping_add(128).0, end.0)],
    );
    assert!(a.sack_recovery.is_some());
    assert_eq!(a.limited_sent, 256);
    assert_eq!(a.congestion.ssthresh(), 256);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
//= type=test
//# RecoveryPoint MUST be set to HighData.
//= https://www.rfc-editor.org/rfc/rfc2018#section-5.1
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Timeout clears scoreboard and RTO sends left edge before acting on fresh SACKs. Implementation satisfies even the original stronger wording; verified erratum 1610 changes MUST to SHOULD, rejected erratum 6602 is not applied.
//# Because the data receiver is allowed to discard SACKed data, when a
//# retransmit timeout occurs the data sender MUST ignore prior SACK information
//# in determining which data to retransmit.
//= https://www.rfc-editor.org/rfc/rfc2018#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Timeout clears advisory ranges; test observes full pipe after timeout.
//# After a retransmit timeout the data sender SHOULD turn off all of the SACKed
//# bits, since the timeout might indicate that the data receiver has reneged.
//= https://www.rfc-editor.org/rfc/rfc2018#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. sack_rto_discards_advice_retransmits_head_and_guards_epoch accepts a valid first SACK block covering snd_una through data_high before RTO, then verifies wire head sequence/payload and guard after timeout clears advice.
//# The data sender MUST retransmit the segment at the left edge of the window
//# after a retransmit timeout, whether or not the SACKed bit is on for that
//# segment.
//= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Clears prior advice and sends the head. Erratum 1610 permits a weaker SHOULD but implementation takes conservative clearing path.
//# As a result, [RFC2018] suggests that a TCP sender SHOULD expunge the SACK
//# information gathered from a receiver upon a retransmission timeout (RTO)
//# "since the timeout might indicate that the data receiver has reneged."
//# Additionally, a TCP sender MUST "ignore prior SACK information in
//# determining which data to retransmit." However, since the publication of
//# [RFC2018], this has come to be viewed by some as too strong.
//= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Timeout replaces recovery with sack_guard=data_high; fresh SACKs cannot reenter until cumulative boundary is covered. Exclusive boundary equals RFC highest byte plus one.
//# If an RTO occurs during loss recovery as specified in this document,
//# RecoveryPoint MUST be set to HighData.
//= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Timeout replaces recovery with sack_guard=data_high; fresh SACKs cannot reenter until cumulative boundary is covered. Exclusive boundary equals RFC highest byte plus one.
//# Further, the new value of RecoveryPoint MUST be preserved and the loss
//# recovery algorithm outlined in this document MUST be terminated.
//= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Timeout replaces recovery with sack_guard=data_high; fresh SACKs cannot reenter until cumulative boundary is covered. Exclusive boundary equals RFC highest byte plus one.
//# In addition, a new recovery phase (as described in Section 5) MUST NOT be
//# initiated until HighACK is greater than or equal to the new value of
//# RecoveryPoint.
//= https://www.rfc-editor.org/rfc/rfc6675#section-6
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Optional timer variant uses the shared successful-retransmission commit path. sack_multiloss_selective_recovery_and_transactional_entry asserts exact send_time+rto after both retransmissions, failed-output stability and nonadvancing-SACK nonrestart; sack_rto_discards_advice_retransmits_head_and_guards_epoch checks entry and expiry.
//# Therefore, we give implementers the latitude to use the standard
//# [RFC6298]-style RTO management or, optionally, a more careful variant that
//# re-arms the RTO timer on each retransmission that is sent during recovery
//# MAY be used.
//= https://www.rfc-editor.org/rfc/rfc6298#section-5
//= type=test
//= reason=Negotiated non-RACK/non-PRR SACK RTO clears prior SACK advice.
//# (5.4) Retransmit the earliest segment that has not been acknowledged by the TCP
//# receiver.
fn sack_rto_discards_advice_retransmits_head_and_guards_epoch() {
    let mut a = sack_flight(128, 100, 8);
    let una = a.snd_una;
    let point = a.data_high();
    sack_ack(&mut a, 200, una, &[(una.wrapping_add(128).0, point.0)]);
    let original_deadline = a.rto_deadline;
    assert_eq!(a.transmit(201, &mut [0; 8]), Err(Error::OutputTooSmall));
    assert_eq!(a.rto_deadline, original_deadline);
    packet(&mut a, 201);
    assert_eq!(a.rto_deadline, Some(201 + a.rto()));
    let deadline = a.rto_deadline.unwrap();
    sack_ack(&mut a, 202, una, &[(una.0, point.0)]);
    assert_eq!(a.scoreboard.ranges(), &[(una, point)]); // Valid first block covers snd_una.
    assert_eq!(a.snd_una, una);
    assert_eq!(a.rto_deadline, Some(deadline));
    a.timeout(deadline).unwrap();
    assert!(a.sack_recovery.is_none());
    assert_eq!(a.sack_guard, Some(point));
    assert_eq!(a.scoreboard.pipe(una, point, una, 128), 1024);
    assert!(a.sample.is_none());
    let bytes = packet(&mut a, deadline);
    let segment = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(segment.header.sequence, una.0);
    assert_eq!(segment.payload, &[0x77; 128]);
    sack_ack(
        &mut a,
        deadline + 1,
        una,
        &[(una.wrapping_add(128).0, point.0)],
    );
    assert!(a.sack_recovery.is_none());
    assert_eq!(a.send.len(), 1024);
    sack_ack(&mut a, deadline + 2, point, &[]);
    assert!(a.sack_guard.is_none());
    assert_eq!(a.send.len(), 0);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Fresh post-RTO SACKs update scoreboard and select missing offset 256 without fast-recovery reentry.
//# Further, a SACK TCP sender SHOULD utilize all SACK information made
//# available during the loss recovery following an RTO.
//= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Fresh post-RTO SACKs update scoreboard and select missing offset 256 without fast-recovery reentry.
//# As described in Sections 4 and 5, Update () SHOULD continue to be used
//# appropriately upon receipt of ACKs.
//= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Fresh post-RTO SACKs update scoreboard and select missing offset 256 without fast-recovery reentry.
//# In this case, a TCP sender SHOULD use this SACK information when determining
//# what data should be sent in each segment following an RTO.
//= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Post-RTO selection fills fresh holes without the normal fast-recovery NextSeg priorities/rescue and stays guarded until old flight is cumulatively covered.
//# The exact algorithm for this selection is not specified in this document
//# (specifically NextSeg () is inappropriate during loss recovery after an
//# RTO).
fn sack_after_rto_uses_fresh_holes_without_reentering_recovery() {
    let mut a = sack_flight(128, 100, 8);
    let una = a.snd_una;
    let point = a.data_high();
    let deadline = a.rto_deadline.unwrap();
    a.timeout(deadline).unwrap();
    let bytes = packet(&mut a, deadline);
    let segment = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(segment.header.sequence, una.0);
    assert_eq!(segment.payload, &[0x77; 128]);
    sack_ack(
        &mut a,
        deadline + 1,
        una.wrapping_add(256),
        &[(una.wrapping_add(384).0, point.0)],
    );
    assert!(a.sack_recovery.is_none());
    assert_eq!(a.sack_guard, Some(point));
    let bytes = packet(&mut a, deadline + 2);
    let seg = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(seg.header.sequence, una.wrapping_add(256).0);
    assert_eq!(seg.payload.len(), 128);
    assert_eq!(a.transmit(deadline + 3, &mut [0; 1024]), Ok(None));
    sack_ack(&mut a, deadline + 4, point, &[]);
    assert!(a.sack_post_rto.is_none());
}

#[test]
fn sack_sender_alternating_flight_retains_advice_until_rto() {
    let mut a = sack_flight(128, u32::MAX - 100, 8);
    let una = a.snd_una;
    let end = a.data_high();
    let storage = a.scoreboard.ranges().as_ptr();
    for i in 0..512 {
        sack_ack(
            &mut a,
            200 + i as u64,
            una,
            &[(una.wrapping_add(2 * i + 1).0, una.wrapping_add(2 * i + 2).0)],
        );
    }
    assert!(a.sack_fallback.is_none());
    assert_eq!(a.scoreboard.ranges().len(), 512);
    assert_eq!(a.scoreboard.ranges().as_ptr(), storage);
    assert_eq!(a.scoreboard.unsacked_bytes(una, end), 512);
    assert_eq!(a.send.len(), 1024); // Advice never frees payload.
    a.timeout(a.rto_deadline.unwrap()).unwrap();
    assert!(a.scoreboard.ranges().is_empty());
    let deadline = a.now;
    let bytes = packet(&mut a, deadline);
    let seg = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(seg.header.sequence, una.0);
    assert!(!seg.payload.is_empty());
    assert_eq!(a.send.len(), 1024);
    sack_ack(&mut a, deadline + 1, end, &[]);
    assert_eq!(a.send.len(), 0);
}

#[test]
fn sack_receiver_more_than_64_fragments_survive_failed_output() {
    let (mut a, _) = pair(sack_config(128), 100);
    let next = a.receive.next();
    let una = a.snd_una;
    for i in 0..64 {
        inject_sack(
            &mut a,
            40 + i as u64,
            next.wrapping_add(2 * i + 1),
            una,
            ACK,
            8192,
            &[1],
            &[],
        );
        packet(&mut a, 40 + i as u64);
    }
    inject_sack(
        &mut a,
        110,
        next.wrapping_add(201),
        una,
        ACK,
        8192,
        &[2],
        &[],
    );
    assert!(!a.sack_omit);
    assert_eq!(a.receive_used, 65);
    assert_eq!(a.transmit(111, &mut [0; 8]), Err(Error::OutputTooSmall));
    assert!(!a.sack_omit);
    let bytes = packet(&mut a, 111);
    let ack = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(ack.header.acknowledgment, next.0);
    assert_eq!(
        ack.options.sack_blocks[0],
        Some((next.wrapping_add(201).0, next.wrapping_add(202).0))
    );
    inject_sack(&mut a, 112, next, una, ACK, 8192, &[3; 128], &[]);
    let bytes = packet(&mut a, 113);
    assert_eq!(
        wire::parse(ip(tuple()), &bytes)
            .unwrap()
            .header
            .acknowledgment,
        next.wrapping_add(128).0
    );
    assert_eq!(a.read(&mut [0; 128]), Ok(128));
    assert_eq!(a.read(&mut [0; 1]), Err(Error::WouldBlock));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6675#section-4
//= type=test
//= reason=Together with multiloss and speculative/rescue tests, checks the selected sequence ranges and NextSeg priorities.
//# NextSeg () MUST return the
//# sequence number range of the next segment that is to be
//# transmitted, per the following rules:
//= https://www.rfc-editor.org/rfc/rfc6675#section-4
//= type=test
//= reason=Negotiated non-RACK/non-PRR SACK; full-budget and piggybacked-SACK regressions exercise lost/new/speculative/rescue priority. IsLost uses SMSS independently of output clipping; markers commit only after encoding.
//# NextSeg () MUST return the sequence number range of the next segment that is
//# to be transmitted, per the following rules:
//= https://www.rfc-editor.org/rfc/rfc6675#section-4
//= type=test
//= reason=Negotiated non-RACK/non-PRR SACK; full-budget and budget-116 tests send fresh data before nonlost holes and keep RecoveryPoint fixed.
//# (2) If no sequence number 'S2' per rule (1) exists but there exists
//# available unsent data and the receiver's advertised window allows, the
//# sequence range of one segment of up to SMSS octets of previously unsent data
//# starting with sequence number HighData+1 MUST be returned.
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated non-RACK/non-PRR SACK; active recovery polls consume pipe/cwnd credit and stop below SMSS; separate limited-transmit regression checks the pre-recovery loop.
//# (C) If cwnd - pipe >= 1 SMSS, the sender SHOULD transmit one or more
//# segments as follows:
//= https://www.rfc-editor.org/rfc/rfc6675#section-2
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. data_high is the exclusive transmitted data edge; new output advances snd_nxt but excludes FIN.
//# "HighData" is the highest sequence number transmitted at a given point.
//= https://www.rfc-editor.org/rfc/rfc6675#section-2
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Recovery pipe bounds output; independent scoreboard per-byte oracle checks computation.
//# "Pipe" is a sender's estimate of the number of bytes outstanding in the
//# network. This is used during recovery for limiting the sender's sending
//# rate. The pipe variable allows TCP to use fundamentally different congestion
//# control than the algorithm specified in [RFC5681]. The congestion control
//# algorithm using the pipe estimate is often referred to as the "pipe
//# algorithm".
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Poll-driven output continues recovery candidates until cwnd credit exhausted.
//# (4.5) In order to take advantage of potential additional available cwnd,
//# proceed to step (C) below.
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. ACK below recovery boundary recomputes pipe; test gains credit after partial ACK then sends new data.
//# (B.2) Use SetPipe () to re-calculate the number of octets still in the
//# network.
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Successful new data advances exclusive snd_nxt; test checks one-SMSS advance while recovery point remains fixed.
//# (C.3) If any of the data octets sent in (C.1) are above HighData, HighData
//# must be updated to reflect the transmission of previously unsent data.
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Non-RACK pipe increments by actual successfully encoded bytes; test fills pipe exactly to cwnd and denies next poll.
//# (C.4) The estimate of the amount of data outstanding in the network must be
//# updated by incrementing pipe by the number of octets transmitted in (C.1).
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. One segment per output poll; successive polls select ranges until credit less than SMSS, equivalent to loop.
//# (C.5) If cwnd - pipe >= 1 SMSS, return to (C.1)
fn sack_nextseg_new_data_precedes_speculative_holes_and_bounds_pipe() {
    let mut a = sack_flight(128, 100, 12);
    let una = a.snd_una;
    let point = a.data_high();
    let ranges = [
        (una.wrapping_add(128).0, una.wrapping_add(256).0),
        (una.wrapping_add(512).0, una.wrapping_add(1152).0),
    ];
    a.write(&[9; 128]).unwrap();
    sack_ack(&mut a, 200, una, &ranges);
    for (now, offset) in [(201, 0), (202, 256), (203, 384)] {
        let bytes = packet(&mut a, now);
        assert_eq!(a.last_output_ecn(), 0);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.flags & CWR,
            0
        );
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.sequence,
            una.wrapping_add(offset).0
        );
    }
    assert_eq!(a.sack_recovery.unwrap().pipe, a.congestion.cwnd());
    assert_eq!(a.transmit(204, &mut [0; 1024]), Ok(None));
    sack_ack(&mut a, 210, una.wrapping_add(256), &ranges[1..]);
    let bytes = packet(&mut a, 211);
    let seg = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(seg.header.sequence, point.0); // Rule 2 before rule 3.
    assert_eq!(seg.payload, &[9; 128]);
    assert_eq!(a.last_output_ecn(), 2);
    assert_ne!(seg.header.flags & CWR, 0);
    assert!(!a.ecn_cwr_pending);
    assert_eq!(a.sack_recovery.unwrap().recovery_point, point);
    assert_eq!(a.snd_nxt, point.wrapping_add(128));
    assert_eq!(a.transmit(212, &mut [0; 1024]), Ok(None));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6675#section-4
//= type=test
//= reason=Negotiated non-RACK/non-PRR SACK; full-budget and piggybacked-SACK regressions exercise lost/new/speculative/rescue priority. IsLost uses SMSS independently of output clipping; markers commit only after encoding.
//# NextSeg () MUST return the
//# sequence number range of the next segment that is to be
//# transmitted, per the following rules:
//= https://www.rfc-editor.org/rfc/rfc6675#section-4
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. With no new/lost segment, speculative offset 768 is sent before tail rescue, then high_rxt advances.
//# (3) If the conditions for rules (1) and (2) fail, but there exists an
//# unSACKed sequence number 'S3' that meets the criteria for detecting loss
//# given in steps (1.a) and (1.b) above (specifically excluding step (1.c)),
//# then one segment of up to SMSS octets starting with S3 SHOULD be returned.
//= https://www.rfc-editor.org/rfc/rfc6675#section-4
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Rescue contains the highest outstanding unsacked byte; success sets RescueRxt to fixed recovery boundary, retry does not consume it and a second rescue is denied.
//# If HighACK is greater than RescueRxt (or RescueRxt is undefined), then one
//# segment of up to SMSS octets that MUST include the highest outstanding
//# unSACKed sequence number SHOULD be returned, and RescueRxt set to
//# RecoveryPoint.
//= https://www.rfc-editor.org/rfc/rfc6675#section-4
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Rescue leaves high_rxt unchanged, explicitly asserted.
//# HighRxt MUST NOT be updated.
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Successful nonrescue output advances high_rxt; rescue explicitly leaves it unchanged; failed encode does not commit either.
//# (C.2) If any of the data octets sent in (C.1) are below HighData, HighRxt
//# MUST be set to the highest sequence number of the retransmitted segment
//# unless NextSeg () rule (4) was invoked for this retransmission.
//= https://www.rfc-editor.org/rfc/rfc6675#section-9
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Section 9 restates rule (3), not a new algorithm; speculative retransmission is selected and asserted before rescue.
//# Rule (3) of NextSeg() has been changed from MAY to SHOULD, to appropriately
//# reflect the opinion of the authors and working group that it should be left
//# in, rather than out, if an implementor does not have a compelling reason to
//# do otherwise.
//= https://www.rfc-editor.org/rfc/rfc6675#section-2
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. high_rxt is exclusive; only successful nonrescue retransmissions advance it.
//# "HighRxt" is the highest sequence number which has been retransmitted during
//# the current loss recovery phase.
//= https://www.rfc-editor.org/rfc/rfc6675#section-2
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. rescue_rxt grants a single tail retransmission and tracks recovery boundary after success.
//# "RescueRxt" is the highest sequence number which has been optimistically
//# retransmitted to prevent stalling of the ACK clock when there is loss at the
//# end of the window and no new data is available for transmission.
fn sack_nextseg_speculative_then_single_transactional_tail_rescue() {
    for speculative in [false, true] {
        let mut a = sack_flight(128, 100, 8);
        let una = a.snd_una;
        let point = a.data_high();
        let ranges = [
            (una.wrapping_add(128).0, una.wrapping_add(256).0),
            (una.wrapping_add(384).0, una.wrapping_add(768).0),
        ];
        sack_ack(&mut a, 200, una, &ranges);
        packet(&mut a, 201);
        packet(&mut a, 202);
        assert_eq!(a.transmit(203, &mut [0; 1024]), Ok(None));
        let blocks = if speculative {
            &[(una.wrapping_add(896).0, point.0)][..]
        } else {
            &[][..]
        };
        sack_ack(&mut a, 210, una.wrapping_add(384), blocks);
        if speculative {
            let bytes = packet(&mut a, 211);
            let seg = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(seg.header.sequence, una.wrapping_add(768).0); // Rule 3.
            assert_eq!(seg.payload.len(), 128);
            assert_eq!(a.sack_recovery.unwrap().high_rxt, una.wrapping_add(896));
        }
        let old = a.sack_recovery.unwrap();
        assert_eq!(a.transmit(212, &mut [0; 8]), Err(Error::OutputTooSmall));
        assert_eq!(a.sack_recovery.unwrap().rescue_rxt, old.rescue_rxt);
        assert_eq!(a.sack_recovery.unwrap().pipe, old.pipe);
        let bytes = packet(&mut a, 212);
        let rescue = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(
            rescue.header.sequence,
            una.wrapping_add(if speculative { 768 } else { 896 }).0
        );
        assert_eq!(rescue.payload.len(), 128);
        assert_eq!(a.sack_recovery.unwrap().high_rxt, old.high_rxt);
        assert_eq!(a.sack_recovery.unwrap().rescue_rxt, Some(point));
        assert_eq!(a.transmit(213, &mut [0; 1024]), Ok(None));
        // More credit and identical SACK cannot grant another rescue.
        sack_ack(&mut a, 214, una.wrapping_add(512), &[]);
        assert_eq!(a.transmit(215, &mut [0; 1024]), Ok(None));
    }
}

#[test]
fn sack_fin_is_not_scoreboard_data_and_remains_rto_retransmittable() {
    let mut a = sack_flight(128, 100, 8);
    a.shutdown().unwrap();
    let bytes = packet(&mut a, 150);
    let fin = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(fin.header.flags & FIN, FIN);
    assert!(fin.payload.is_empty());
    let una = a.snd_una;
    let data_end = a.fin_sequence.unwrap();
    sack_ack(
        &mut a,
        200,
        una,
        &[(una.wrapping_add(128).0, data_end.wrapping_add(1).0)],
    );
    assert!(a.sack_recovery.is_none()); // A block including FIN is invalid.
    sack_ack(&mut a, 201, una, &[(una.wrapping_add(128).0, data_end.0)]);
    assert_eq!(a.sack_recovery.unwrap().recovery_point, data_end);
    let bytes = packet(&mut a, 202);
    assert_eq!(
        wire::parse(ip(tuple()), &bytes).unwrap().header.flags & FIN,
        0
    );
    sack_ack(&mut a, 203, data_end, &[]);
    assert!(a.sack_recovery.is_none());
    assert_eq!(a.send.len(), 0);
    assert_eq!(a.flight(), 1);
    // FIN-only SACK reports cannot start data recovery.
    for now in 204..208 {
        sack_ack(
            &mut a,
            now,
            data_end,
            &[(data_end.0, data_end.wrapping_add(1).0)],
        );
    }
    assert!(a.sack_recovery.is_none());
    let deadline = a.rto_deadline.unwrap();
    a.timeout(deadline).unwrap();
    let bytes = packet(&mut a, deadline);
    let fin = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(fin.header.sequence, data_end.0);
    assert_eq!(fin.header.flags & FIN, FIN);
    sack_ack(&mut a, deadline + 1, data_end.wrapping_add(1), &[]);
    assert_eq!(a.state, State::FinWait2);
}

#[test]
fn sack_ecn_shares_reduction_but_preserves_loss_retransmit() {
    let mut a = sack_flight(128, 100, 8);
    let una = a.snd_una;
    let point = a.data_high();
    let next = a.receive.next();
    inject_sack(
        &mut a,
        200,
        next,
        una,
        ACK | ECE,
        8192,
        &[],
        &[(una.wrapping_add(128).0, point.0)],
    );
    assert!(a.sack_recovery.is_some());
    assert_eq!(a.congestion.ssthresh(), 512);
    assert_eq!(a.congestion.cwnd(), 512);
    assert!(a.ecn_cwr_pending);
    let bytes = packet(&mut a, 201);
    let seg = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(seg.header.sequence, una.0);
    assert_eq!(seg.header.flags & CWR, 0);
    assert_eq!(a.last_output_ecn(), 0);
    assert!(a.ecn_cwr_pending);
    inject_sack(
        &mut a,
        202,
        next,
        una,
        ACK | ECE,
        8192,
        &[],
        &[(una.wrapping_add(128).0, point.0)],
    );
    assert_eq!(a.congestion.cwnd(), 512);
    assert_eq!(a.transmit(203, &mut [0; 1024]), Ok(None));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Cumulative ACK resets duplicate counter before new SACK evidence increments it; test explicitly observes count one after advancing ACK.
//# If the incoming ACK is a cumulative acknowledgment, the TCP MUST reset
//# DupAcks to zero.
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Recovery ACK processing updates scoreboard/pipe and exits on boundary; partial cumulative ACK keeps recovery active without cwnd growth.
//# Once a TCP is in the loss recovery phase, the following procedure MUST be
//# used for each arriving ACK:
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. ACK below recovery boundary updates scoreboard and recomputes recovery.pipe; partial ACK remains in recovery.
//# (B) Upon receipt of an ACK that does not cover RecoveryPoint, the following
//# actions MUST be taken:
//= https://www.rfc-editor.org/rfc/rfc6675#section-2
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. snd_una is the exclusive cumulative edge, equivalent to HighACK+1.
//# "HighACK" is the sequence number of the highest byte of data that has been
//# cumulatively ACKed at a given point.
//= https://www.rfc-editor.org/rfc/rfc6675#section-2
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. duplicate_acks resets on cumulative ACK and increments on new delivery evidence.
//# "DupAcks" is the number of duplicate acknowledgments received since the last
//# cumulative acknowledgment.
//= https://www.rfc-editor.org/rfc/rfc6675#section-2
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Advancing ACK with new SACK evidence remains counted as one duplicate after reset.
//# For the purposes of this specification, we define a "duplicate
//# acknowledgment" as a segment that arrives carrying a SACK block that
//# identifies previously unacknowledged and un-SACKed octets between HighACK
//# and HighData. Note that an ACK which carries new SACK data is counted as a
//# duplicate acknowledgment under this definition even if it carries new data,
//# changes the advertised window, or moves the cumulative acknowledgment point,
//# which is different from the definition of duplicate acknowledgment in
//# [RFC5681].
//= https://www.rfc-editor.org/rfc/rfc6675#section-5
//= type=test
//= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Every valid recovery ACK records SACK union before cumulative ACK and recovery state processing.
//# (B.1) Use Update () to record the new SACK information conveyed by the
//# incoming ACK.
fn sack_advancing_ack_resets_count_before_new_evidence_and_partial_cwnd() {
    let mut a = sack_flight(128, 100, 8);
    let una = a.snd_una;
    sack_ack(
        &mut a,
        200,
        una,
        &[(una.wrapping_add(128).0, una.wrapping_add(256).0)],
    );
    assert_eq!(a.duplicate_acks, 1);
    sack_ack(
        &mut a,
        201,
        una.wrapping_add(17),
        &[(una.wrapping_add(256).0, una.wrapping_add(384).0)],
    );
    assert_eq!(a.duplicate_acks, 1);
    sack_ack(
        &mut a,
        202,
        una.wrapping_add(17),
        &[(una.wrapping_add(384).0, una.wrapping_add(512).0)],
    );
    assert!(a.sack_recovery.is_some());
    let cwnd = a.congestion.cwnd();
    packet(&mut a, 203);
    sack_ack(&mut a, 204, una.wrapping_add(30), &[]);
    assert_eq!(a.congestion.cwnd(), cwnd);
    assert!(a.sack_recovery.is_some());
}

#[test]
fn sack_three_blocks_with_timestamps_fit_data_mss_and_path() {
    let cfg = ConnectionConfig {
        timestamps: true,
        send_ip_payload_limit: 148,
        ..sack_config(128)
    };
    let (mut a, _) = pair(cfg, 100);
    let next = a.receive.next();
    let una = a.snd_una;
    for offset in [10, 30, 50] {
        inject_sack(
            &mut a,
            40,
            next.wrapping_add(offset),
            una,
            ACK,
            8192,
            &[2; 5],
            &[],
        );
    }
    a.write(&[7; 128]).unwrap();
    let before = (a.now, a.snd_nxt, a.last_timestamp_sent_at, a.ack_pending);
    assert_eq!(a.transmit(1_000, &mut [0; 147]), Err(Error::OutputTooSmall));
    assert_eq!(
        (a.now, a.snd_nxt, a.last_timestamp_sent_at, a.ack_pending),
        before
    );
    let bytes = packet(&mut a, 1_000);
    let data = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(bytes.len(), 148);
    assert_eq!(data.raw_options.len(), 40);
    assert_eq!(
        &data.raw_options[..12],
        &[1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0]
    );
    assert_eq!(&data.raw_options[12..16], &[1, 1, 5, 26]);
    assert_eq!(
        data.options.sack_blocks[..3],
        [
            Some((next.wrapping_add(50).0, next.wrapping_add(55).0)),
            Some((next.wrapping_add(10).0, next.wrapping_add(15).0)),
            Some((next.wrapping_add(30).0, next.wrapping_add(35).0)),
        ]
    );
    assert_eq!(data.payload, &[7; 88]);
    assert_eq!(data.payload.len() + data.raw_options.len(), 128);
}

#[test]
fn sack_small_mss_ack_report_does_not_starve_data() {
    for (mss, timestamps) in [(8, false), (24, true)] {
        let cfg = ConnectionConfig {
            timestamps,
            ..sack_config(mss)
        };
        let (mut a, _) = pair(cfg, 100);
        let next = a.receive.next();
        let una = a.snd_una;
        inject_sack(
            &mut a,
            40,
            next.wrapping_add(10),
            una,
            ACK,
            8192,
            &[2; 5],
            &[],
        );
        a.write(&[1; 8]).unwrap();
        assert_eq!(a.transmit(41, &mut [0; 20]), Err(Error::OutputTooSmall));
        let bytes = packet(&mut a, 41);
        let seg = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(
            seg.options.sack_blocks[0],
            Some((next.wrapping_add(10).0, next.wrapping_add(15).0))
        );
        assert!(seg.payload.is_empty());
        let bytes = packet(&mut a, 42);
        let seg = wire::parse(ip(tuple()), &bytes).unwrap();
        assert!(!seg.payload.is_empty());
        assert!(seg.payload.len() + seg.raw_options.len() <= mss as usize);
    }
}

#[test]
fn sack_only_ack_preserves_pending_rto_retransmission() {
    for (mss, timestamps) in [(8, false), (24, true)] {
        let cfg = ConnectionConfig {
            timestamps,
            ..sack_config(mss)
        };
        let (mut a, _) = pair(cfg, 100);
        let una = a.snd_una;
        a.write(&[7; 8]).unwrap();
        let sent = packet(&mut a, 40);
        assert_eq!(wire::parse(ip(tuple()), &sent).unwrap().payload, &[7; 8]);
        let timeout = a.rto_deadline.unwrap();
        a.timeout(timeout).unwrap();
        assert!(a.retx_pending);
        let next = a.receive.next();
        inject_sack(
            &mut a,
            timeout,
            next.wrapping_add(10),
            una,
            ACK,
            8192,
            &[2; 5],
            &[],
        );
        assert_eq!(
            a.transmit(timeout, &mut [0; 20]),
            Err(Error::OutputTooSmall)
        );
        assert!(a.retx_pending);
        let bytes = packet(&mut a, timeout);
        let seg = wire::parse(ip(tuple()), &bytes).unwrap();
        assert!(seg.payload.is_empty());
        assert!(seg.options.sack_blocks[0].is_some());
        assert!(a.retx_pending);
        let bytes = packet(&mut a, timeout);
        let seg = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(seg.header.sequence, una.0);
        assert_eq!(seg.payload, &[7; 8]);
        assert!(!a.retx_pending);
    }
}

#[test]
fn sack_options_leave_path_space_for_probe_and_keepalive_octets() {
    for timestamps in [false, true] {
        for probing in [false, true] {
            let limit = if timestamps { 44 } else { 32 };
            let cfg = ConnectionConfig {
                timestamps,
                send_ip_payload_limit: limit,
                keepalive: Some(KeepaliveConfig {
                    idle_us: 100_000,
                    interval_us: 100_000,
                    probes: 3,
                    send_garbage: true,
                }),
                ..sack_config(64)
            };
            let (mut a, _) = pair(cfg, 100);
            if probing {
                a.write(&[7; 3]).unwrap();
                packet(&mut a, 40);
            }
            let next = a.receive.next();
            let una = a.snd_una;
            inject_sack(
                &mut a,
                41,
                next.wrapping_add(10),
                una,
                ACK,
                if probing { 0 } else { 8192 },
                &[2; 5],
                &[],
            );
            let deadline = if probing {
                a.loss_timer.map(|(_, deadline)| deadline)
            } else {
                a.keepalive_deadline
            }
            .unwrap();
            a.timeout(deadline).unwrap();
            assert!(if probing {
                a.probe_pending
            } else {
                a.keepalive_pending
            });
            let bytes = packet(&mut a, deadline);
            assert!(bytes.len() <= limit as usize);
            assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload.len(), 1);
        }
    }
}

#[test]
fn sack_rescue_waits_for_tail_to_fit_reopened_window() {
    let mut a = sack_flight(128, 100, 8);
    // Exercise the conservative policy without negotiated scaling.
    a.scaling = false;
    let una = a.snd_una;
    let ranges = [
        (una.wrapping_add(128).0, una.wrapping_add(256).0),
        (una.wrapping_add(384).0, una.wrapping_add(768).0),
    ];
    sack_ack(&mut a, 200, una, &ranges);
    for (now, offset) in [(201, 0), (202, 256)] {
        let bytes = packet(&mut a, now);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.sequence,
            una.wrapping_add(offset).0
        );
    }
    let next = a.receive.next();
    inject_sack(&mut a, 210, next, una.wrapping_add(384), ACK, 576, &[], &[]);
    let old = a.sack_recovery.unwrap().rescue_rxt;
    assert_eq!(a.transmit(211, &mut [0; 1024]), Ok(None));
    assert_eq!(a.sack_recovery.unwrap().rescue_rxt, old);
    inject_sack(
        &mut a,
        212,
        next,
        una.wrapping_add(384),
        ACK,
        8192,
        &[],
        &[],
    );
    let bytes = packet(&mut a, 213);
    let seg = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(seg.header.sequence, una.wrapping_add(896).0);
    assert_eq!(seg.payload.len(), 128);
    assert_eq!(
        a.sack_recovery.unwrap().rescue_rxt,
        Some(una.wrapping_add(1024))
    );
}

#[test]
fn sack_post_rto_alternating_losses_fill_cwnd_with_retransmissions() {
    let mut a = sack_flight(128, 100, 8);
    let una = a.snd_una;
    let point = a.data_high();
    let deadline = a.rto_deadline.unwrap();
    a.timeout(deadline).unwrap();
    packet(&mut a, deadline);
    let ranges = [(384, 512), (640, 768), (896, 1024)]
        .map(|(l, r)| (una.wrapping_add(l).0, una.wrapping_add(r).0));
    sack_ack(&mut a, deadline + 1, una.wrapping_add(256), &ranges);
    assert_eq!(a.congestion.cwnd(), 256);
    for (time, offset) in [(2, 256), (3, 512)] {
        let bytes = packet(&mut a, deadline + time);
        let seg = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(seg.header.sequence, una.wrapping_add(offset).0);
        assert_eq!(seg.payload.len(), 128);
    }
    assert_eq!(a.transmit(deadline + 4, &mut [0; 1024]), Ok(None));
    assert_eq!(a.sack_guard, Some(point));
    assert!(a.sack_recovery.is_none());
    assert_eq!(a.send.len(), 768);
    assert!(a.sample.is_none());

    // New data consumes this slow-start window too, using the fixed RTO
    // snapshot rather than the advancing HighData as its lower boundary.
    a.write(&[9; 256]).unwrap();
    sack_ack(&mut a, deadline + 5, una.wrapping_add(768), &ranges[2..]);
    assert_eq!(a.congestion.cwnd(), 384);
    for (time, offset) in [(6, 768), (7, 1024), (8, 1152)] {
        let bytes = packet(&mut a, deadline + time);
        let seg = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(seg.header.sequence, una.wrapping_add(offset).0);
        assert_eq!(seg.payload.len(), 128);
    }
    assert_eq!(a.post_rto_pipe(), 384);
    assert_eq!(a.transmit(deadline + 9, &mut [0; 1024]), Ok(None));
    sack_ack(&mut a, deadline + 10, point, &[]);
    assert!(a.sack_post_rto.is_none());
}

#[test]
fn sack_fin_only_input_clears_previous_batched_dsack() {
    let (mut a, _) = pair(sack_config(128), 100);
    let next = a.receive.next();
    let una = a.snd_una;
    inject_sack(
        &mut a,
        40,
        next.wrapping_add(10),
        una,
        ACK,
        8192,
        &[1; 10],
        &[],
    );
    inject_sack(
        &mut a,
        41,
        next.wrapping_add(12),
        una,
        ACK,
        8192,
        &[1; 3],
        &[],
    );
    inject_sack(
        &mut a,
        42,
        next.wrapping_add(30),
        una,
        ACK | FIN,
        8192,
        &[],
        &[],
    );
    let bytes = packet(&mut a, 43);
    let seg = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(
        seg.options.sack_blocks[0],
        Some((next.wrapping_add(10).0, next.wrapping_add(20).0))
    );
    assert!(seg.options.sack_blocks[1].is_none());
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc2018#section-4
//= type=test
//= reason=Six batched arrivals preserve individual full-report ACK work; failed encoding commits neither report history nor pending anchors, and successful first-block history differs from unreported arrival order.
//# * The SACK option SHOULD be filled out by repeating the most recently
//# reported SACK blocks (based on first SACK blocks in previous SACK options)
//# that are not subsets of a SACK block already included in the SACK option
//# being constructed.
//= https://www.rfc-editor.org/rfc/rfc2018#section-4
//= type=test
//= reason=Six arrivals before output produce six SACK-bearing ACKs within poll-driven work, without collapsing the pending arrival bitmap to one ACK boolean.
//# The receiver SHOULD send an ACK for every valid segment that arrives
//# containing new data, and each of these "duplicate" ACKs SHOULD bear a SACK
//# option.
fn sack_history_and_batched_reports_commit_only_after_encode() {
    for iss in [100, u32::MAX - 100] {
        let (mut a, _) = pair(sack_config(128), iss);
        let next = a.receive.next();
        let una = a.snd_una;
        let block = |offset| Some((next.wrapping_add(offset).0, next.wrapping_add(offset + 1).0));
        for offset in [10, 30, 50, 70, 90, 110] {
            inject_sack(
                &mut a,
                40,
                next.wrapping_add(offset),
                una,
                ACK,
                8192,
                &[1],
                &[],
            );
        }
        let mut firsts = alloc::vec::Vec::new();
        for offset in [110, 10, 30, 50, 70, 90] {
            let planned = a.receive.sack_blocks(4);
            assert_eq!(planned[0], block(offset));
            let before = alloc::format!("{:?}", a.receive);
            assert_eq!(a.transmit(41, &mut [0; 8]), Err(Error::OutputTooSmall));
            assert_eq!(alloc::format!("{:?}", a.receive), before);
            assert_eq!(a.receive.sack_blocks(4), planned);
            let bytes = packet(&mut a, 41);
            let report = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(report.options.sack_blocks, planned);
            firsts.push(report.options.sack_blocks[0]);
            if offset == 30 {
                assert_eq!(
                    report.options.sack_blocks,
                    [block(30), block(10), block(110), block(50)]
                );
            }
        }
        assert_eq!(firsts.len(), 6);
        assert_eq!(a.transmit(41, &mut [0; 256]), Ok(None));
        inject_sack(
            &mut a,
            42,
            next.wrapping_add(130),
            una,
            ACK,
            8192,
            &[1],
            &[],
        );
        let bytes = packet(&mut a, 42);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes)
                .unwrap()
                .options
                .sack_blocks,
            [block(130), block(90), block(70), block(50)]
        );
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc2018#section-4
//= type=test
//= reason=Full 4/3-slot reports alternate with data at MSS 1/4/12/13; no full report is discarded to make progress, output failure preserves report work, and all payload reaches the wire.
//# * The data receiver SHOULD include as many distinct SACK blocks as possible
//# in the SACK option.
fn sack_full_reports_do_not_starve_low_mss_data() {
    for timestamps in [false, true] {
        for mss in [1, 4, 12, 13] {
            let (mut a, _) = pair(
                ConnectionConfig {
                    timestamps,
                    ..sack_config(mss)
                },
                100,
            );
            let next = a.receive.next();
            let una = a.snd_una;
            for offset in [10, 30, 50, 70, 90, 110] {
                inject_sack(
                    &mut a,
                    40,
                    next.wrapping_add(offset),
                    una,
                    ACK,
                    8192,
                    &[1],
                    &[],
                );
            }
            a.write(&[7; 20]).unwrap();
            let slots = if timestamps { 3 } else { 4 };
            let mut sent = 0;
            let mut full = 0;
            for now in 41..141 {
                assert_eq!(a.transmit(now, &mut [0; 8]), Err(Error::OutputTooSmall));
                let bytes = packet(&mut a, now);
                let report = wire::parse(ip(tuple()), &bytes).unwrap();
                if report.payload.is_empty() {
                    assert_eq!(
                        report.options.sack_blocks.iter().flatten().count(),
                        slots,
                        "ts={timestamps} mss={mss} now={now} turn={} flight={} pending={} flags={}",
                        a.sack_data_turn,
                        a.flight(),
                        a.ack_pending,
                        report.header.flags
                    );
                    full += 1;
                } else {
                    assert!(report.payload.iter().all(|&byte| byte == 7));
                    sent += report.payload.len();
                    let ack = a.snd_nxt;
                    sack_ack(&mut a, now, ack, &[]);
                }
                if sent == 20 && !a.ack_pending {
                    break;
                }
            }
            assert_eq!(sent, 20);
            assert!(full >= 6);
            assert!(!a.ack_pending);
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
//= type=test
//= reason=Timestamp-valid 128 disjoint bytes are retained across sequence wrap, failed output and bridging, while a PAWS-stale extra byte is rejected rather than fabricated.
//# R5)  Otherwise, treat the segment as a normal in-window,
//# out-of-sequence TCP segment (e.g., queue it for later delivery
//# to the user).
fn timestamp_fragmentation_retains_every_allowed_byte() {
    let (mut a, _) = pair(
        ConnectionConfig {
            timestamps: true,
            ..sack_config(128)
        },
        u32::MAX - 100,
    );
    let next = a.receive.next();
    let una = a.snd_una;
    timestamp_input(&mut a, 39_000, next, una, ACK, Some((40, 0)), b"i");
    assert_eq!(a.read(&mut [0; 1]), Ok(1));
    packet(&mut a, 39_000);
    let next = a.receive.next();
    for offset in (1..256).step_by(2) {
        timestamp_input(
            &mut a,
            40_000,
            next.wrapping_add(offset),
            una,
            ACK,
            Some((40, 0)),
            &[1],
        );
    }
    assert_eq!(a.receive_used, 128);
    assert_eq!(a.transmit(41_000, &mut [0; 8]), Err(Error::OutputTooSmall));
    packet(&mut a, 41_000);
    timestamp_input(
        &mut a,
        42_000,
        next.wrapping_add(300),
        una,
        ACK,
        Some((1, 0)),
        &[9],
    );
    assert_eq!(a.receive_used, 128);
    timestamp_input(&mut a, 43_000, next, una, ACK, Some((43, 0)), &[2; 256]);
    assert_eq!(a.receive_used, 256);
    let mut out = [0; 256];
    assert_eq!(a.read(&mut out), Ok(256));
    assert!(
        out.iter()
            .enumerate()
            .all(|(i, &byte)| byte == if i % 2 == 0 { 2 } else { 1 })
    );
    assert_eq!(a.receive_used, 0);
}

#[test]
fn sack_tiny_mss_option_budget_and_shrink_remain_safe() {
    for mss in [1, 4, 12, 13] {
        let (mut a, _) = pair(sack_config(mss), 100);
        // Exercise the conservative policy without negotiated scaling.
        a.scaling = false;
        let una = a.snd_una;
        let next = a.receive.next();
        inject_sack(&mut a, 40, next.wrapping_add(4), una, ACK, 8192, &[2], &[]);
        a.write(&[1; 20]).unwrap();
        let bytes = packet(&mut a, 41);
        let seg = wire::parse(ip(tuple()), &bytes).unwrap();
        assert!(seg.payload.len() <= mss as usize);
        assert!(seg.options.sack_blocks.iter().flatten().count() <= 1);
    }
    let mut a = sack_flight(128, 100, 8);
    // Exercise the conservative policy without negotiated scaling.
    a.scaling = false;
    let una = a.snd_una;
    let end = a.data_high();
    sack_ack(&mut a, 200, una, &[(una.wrapping_add(128).0, end.0)]);
    let next = a.receive.next();
    inject_sack(&mut a, 201, next, una, ACK, 7, &[], &[]);
    let bytes = packet(&mut a, 202);
    assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload.len(), 7);
    assert!(!a.sack_recovery.unwrap().entry_pending);
    a.lower_mss(32).unwrap();
    assert_eq!(a.mss, 32);
    assert!(a.rto_deadline.is_some());
}

#[test]
fn sack_future_ack_and_paws_cannot_forge_old_duplicate_evidence() {
    let cfg = ConnectionConfig {
        timestamps: true,
        ..sack_config(128)
    };
    let (mut a, mut b) = pair(cfg, 100);
    a.write(&[1; 20]).unwrap();
    let bytes = deliver(&mut a, &mut b, 2_000);
    deliver(&mut b, &mut a, 3_000);
    b.read(&mut [0; 20]).unwrap();
    let old = wire::parse(ip(tuple()), &bytes).unwrap();
    let next = Seq(old.header.sequence);
    let future = b.snd_nxt.wrapping_add(1);
    inject_sack(&mut b, 4_000, next, future, ACK, 8192, &[1; 20], &[]);
    let bytes = packet(&mut b, 4_000);
    assert!(
        wire::parse(ip(reverse(tuple())), &bytes)
            .unwrap()
            .options
            .sack_blocks
            .iter()
            .all(Option::is_none)
    );
    // Old timestamp is rejected before recording a duplicate.
    b.ts_recent = 100;
    b.ts_recent_at = 4_000;
    b.input(5_000, &old).unwrap();
    let bytes = packet(&mut b, 5_000);
    assert!(
        wire::parse(ip(reverse(tuple())), &bytes)
            .unwrap()
            .options
            .sack_blocks
            .iter()
            .all(Option::is_none)
    );
}

#[test]
fn sack_seeded_lossy_reordered_duplex_delivers_and_closes() {
    for seed in [1u64, 17, 0xdead_beef] {
        let (mut a, mut b) = pair(sack_config(128), u32::MAX - 200);
        let left: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let right: Vec<u8> = (0..3072).map(|i| (i % 239) as u8).collect();
        a.write(&left).unwrap();
        b.write(&right).unwrap();
        a.shutdown().unwrap();
        b.shutdown().unwrap();
        let mut a_read = vec![];
        let mut b_read = vec![];
        let mut pending: Vec<(bool, Vec<u8>)> = vec![];
        let mut random = seed;
        let mut scratch = [0; 2048];
        for tick in 1..20_000 {
            let now = 100 + tick * 10_000;
            for (direction, conn) in [(true, &mut a), (false, &mut b)] {
                if conn.next_deadline().is_some_and(|deadline| now >= deadline) {
                    conn.timeout(now).unwrap();
                }
                for _ in 0..8 {
                    if let Some(len) = conn.transmit(now, &mut scratch).unwrap() {
                        random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
                        if random % 7 != 0 {
                            pending.push((direction, scratch[..len].to_vec()));
                        }
                    } else {
                        break;
                    }
                }
            }
            // Retain some packets and select the rest out of order.
            for _ in 0..4 {
                if pending.is_empty() {
                    break;
                }
                random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
                let index = random as usize % pending.len();
                let (direction, bytes) = pending.swap_remove(index);
                let (sender, receiver) = if direction {
                    (tuple(), &mut b)
                } else {
                    (reverse(tuple()), &mut a)
                };
                receiver
                    .input(now, &wire::parse(ip(sender), &bytes).unwrap())
                    .unwrap();
            }
            for (conn, received) in [(&mut a, &mut a_read), (&mut b, &mut b_read)] {
                while let Ok(count) = conn.read(&mut scratch) {
                    if count == 0 {
                        break;
                    }
                    received.extend_from_slice(&scratch[..count]);
                }
            }
            if a_read == right && b_read == left && a.flight() == 0 && b.flight() == 0 {
                break;
            }
        }
        assert_eq!(a_read, right, "seed={seed}");
        assert_eq!(b_read, left, "seed={seed}");
        assert_eq!((a.flight(), b.flight()), (0, 0));
        assert!(matches!(a.state, State::TimeWait | State::Closed));
        assert!(matches!(b.state, State::TimeWait | State::Closed));
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.2
//= type=test
//# Queue the data for transmission after entering ESTABLISHED state.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.2
//= type=test
//= reason=Handshake SEND queue; focused send_state_matrix_preserves_queue_on_rejection additionally tests exhaustion.
//# Queue the data for transmission after entering ESTABLISHED state. If no space to queue,
//# respond with "error: insufficient resources".
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.1
//= type=test
//= reason=ISS/ISS+1 are checked on committed SYN output; active API enqueues SYN and driver polls, rather than emitting inline.
//# A SYN segment of the form <SEQ=ISS><CTL=SYN> is sent. Set SND.UNA to ISS, SND.NXT to
//# ISS+1, enter SYN-SENT state, and return.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.2
//= type=test
//= reason=Passive constructor consumes SYN sequence, learns peer, and schedules SYN-ACK. SYN text buffering/delivery scope separately cited.
//# Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ, and any other control or text should be
//# queued for processing later. ISS should be selected and a SYN segment sent of the form:
//# <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.2
//= type=test
//= reason=Passive state is SYN-RECEIVED; transmit commits ISS+1 only after SYN-ACK encoding succeeds.
//# SND.NXT is set to ISS+1 and SND.UNA to ISS. The connection state should be changed to
//# SYN-RECEIVED.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
//= type=test
//= reason=SYN-ACK establishes active side and schedules ACK, which may carry queued data; no inline output.
//# If SND.UNA > ISS (our SYN has been ACKed), change the connection state to ESTABLISHED,
//# form an ACK segment <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
fn handshake_queues_sends_until_established() {
    let cfg = config(64, 8);
    let mut a = Connection::active(tuple(), cfg.clone(), 100, 0).unwrap();
    assert_eq!(a.write(b"active"), Ok(6));
    let bytes = packet(&mut a, 0);
    let syn = wire::parse(ip(tuple()), &bytes).unwrap();
    assert!(syn.payload.is_empty());
    assert_eq!(a.state(), State::SynSent);
    assert_eq!(a.snd_nxt, Seq(101));
    assert_eq!(a.snd_una, Seq(100));
    assert_eq!(syn.header.flags & (SYN | ACK), SYN);
    assert_eq!(syn.header.sequence, 100);
    assert_eq!(a.transmit(1, &mut [0; 64]), Ok(None));
    let mut b = Connection::passive(reverse(tuple()), cfg, 900, 10, &syn).unwrap();
    assert_eq!(b.write(b"passive"), Ok(7));
    assert_eq!(b.irs, Some(Seq(100)));
    assert_eq!(b.receive.next(), Seq(101));
    assert_eq!(b.snd_una, Seq(900));
    let bytes = deliver(&mut b, &mut a, 20);
    let synack = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
    assert_eq!(synack.header.flags & (SYN | ACK), SYN | ACK);
    assert_eq!(synack.header.sequence, 900);
    assert_eq!(synack.header.acknowledgment, 101);
    assert!(
        wire::parse(ip(reverse(tuple())), &bytes)
            .unwrap()
            .payload
            .is_empty()
    );
    assert_eq!(b.state(), State::SynReceived);
    assert_eq!(b.snd_nxt, Seq(901));
    assert_eq!(b.transmit(21, &mut [0; 64]), Ok(None));
    assert_eq!(a.state(), State::Established);
    assert_eq!(a.snd_una, Seq(101));
    let bytes = deliver(&mut a, &mut b, 30);
    let final_ack = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(final_ack.header.flags & (SYN | ACK), ACK);
    assert_eq!(final_ack.header.sequence, 101);
    assert_eq!(final_ack.header.acknowledgment, 901);
    assert_eq!(final_ack.payload, b"active");
    assert_eq!(b.state(), State::Established);
    let bytes = deliver(&mut b, &mut a, 40);
    assert_eq!(
        wire::parse(ip(reverse(tuple())), &bytes).unwrap().payload,
        b"passive"
    );
    let mut out = [0; 8];
    assert_eq!(b.read(&mut out), Ok(6));
    assert_eq!(&out[..6], b"active");
    assert_eq!(a.read(&mut out), Ok(7));
    assert_eq!(&out[..7], b"passive");
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
//= type=test
//# If there are other controls or text in the segment, queue them for
//# processing after the ESTABLISHED state has been reached, return.
fn simultaneous_open_defers_syn_text_and_push_until_established() {
    let mut a = Connection::active(tuple(), config(64, 8), 100, 0).unwrap();
    packet(&mut a, 0);
    inject(&mut a, 10, Seq(u32::MAX - 1), Seq(0), SYN | PSH, 64, b"abc");
    assert_eq!(a.state(), State::SynReceived);
    assert_eq!(a.read(&mut [0; 8]), Err(Error::WouldBlock));
    assert!(!a.events_pending());
    let bytes = packet(&mut a, 20);
    let synack = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(synack.header.flags & (SYN | ACK), SYN | ACK);
    assert_eq!(synack.header.acknowledgment, u32::MAX);
    inject(&mut a, 30, Seq(2), Seq(101), ACK, 64, b"");
    assert_eq!(a.state(), State::Established);
    let events = a.take_events();
    assert!(events.connected && events.readable && events.pushed);
    let mut out = [0; 8];
    assert_eq!(a.read(&mut out), Ok(3));
    assert_eq!(&out[..3], b"abc");
    assert_eq!(a.read(&mut out), Err(Error::WouldBlock));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.4
//= type=test
//# Queue this until all preceding SENDs have been segmentized, then form a
//# FIN segment and send it.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
//= type=test
//= reason=SYN precedes queued data, FIN follows it; sequence numbers checked across wrap, handshake_queues_sends_until_established checks SYN consumes one.
//# For sequence number purposes, the SYN is considered to occur before the first actual
//# data octet of the segment in which it occurs, while the FIN is considered to occur after
//# the last actual data octet in a segment in which it occurs.
fn fin_follows_all_queued_sends_across_segments() {
    let (mut a, mut b) = pair(config(64, 4), u32::MAX - 2);
    a.set_nagle(false);
    a.write(b"abcdef").unwrap();
    a.write(b"ghij").unwrap();
    a.shutdown().unwrap();
    for (index, expected) in [b"abcd".as_slice(), b"efgh", b"ij"].into_iter().enumerate() {
        let bytes = deliver(&mut a, &mut b, 40 + index as u64);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.payload, expected);
        assert_eq!(
            segment.header.sequence,
            (u32::MAX - 1).wrapping_add(index as u32 * 4)
        );
        if index < 2 {
            assert_eq!(segment.header.flags & FIN, 0);
            assert_eq!(a.state(), State::Established);
            assert_eq!(b.state(), State::Established);
        } else {
            assert_ne!(segment.header.flags & FIN, 0);
            assert_eq!(a.state(), State::FinWait1);
            assert_eq!(b.state(), State::CloseWait);
        }
    }
    let mut out = [0; 16];
    assert_eq!(b.read(&mut out), Ok(10));
    assert_eq!(&out[..10], b"abcdefghij");
    assert_eq!(b.read(&mut out), Ok(0));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.4
//= type=test
//= reason=Full IW10 payload flight permits a standalone FIN, but exhausted peer window and zero PRR credit still defer it; failed encoding cannot commit sequence, state or timers.
//# Queue this until all preceding SENDs have been segmentized, then form a
//# FIN segment and send it.
fn standalone_fin_at_full_cwnd_preserves_window_prr_and_output_commit() {
    let cfg = ConnectionConfig {
        initial_window: InitialWindow::Iw10,
        nagle: false,
        ..config(32_768, 1_000)
    };
    for iss in [100, u32::MAX - 5_000] {
        let (mut a, _) = pair(cfg.clone(), iss);
        assert_eq!(a.congestion.cwnd(), 10_000);
        a.write(&[1; 10_000]).unwrap();
        for _ in 0..10 {
            let bytes = packet(&mut a, 40);
            let segment = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(segment.payload.len(), 1_000);
            assert_eq!(segment.header.flags & FIN, 0);
        }
        assert_eq!(a.flight(), a.congestion.cwnd());
        a.shutdown().unwrap();
        let next = a.snd_nxt;
        let window = a.snd_wnd;
        for closed_window in [0, a.flight()] {
            a.snd_wnd = closed_window;
            assert_eq!(a.transmit(50, &mut [0; 64]), Ok(None));
            assert_eq!(a.fin_sequence, None);
            assert_eq!(a.snd_nxt, next);
            assert_eq!(a.state(), State::Established);
        }
        a.snd_wnd = window;
        a.prr = Some(Prr::new(a.flight(), a.mss as u32));
        assert_eq!(a.prr.unwrap().credit(), 0);
        assert_eq!(a.transmit(50, &mut [0; 64]), Ok(None));
        assert_eq!(a.prr.unwrap().credit(), 0);
        a.prr = None;
        let before = (a.now, a.rto_deadline, a.last_sent, a.fin_sent_at);
        assert_eq!(a.transmit(50, &mut [0; 19]), Err(Error::OutputTooSmall));
        assert_eq!((a.now, a.rto_deadline, a.last_sent, a.fin_sent_at), before);
        assert_eq!(a.fin_sequence, None);
        assert_eq!(a.snd_nxt, next);
        assert_eq!(a.state(), State::Established);
        let bytes = packet(&mut a, 50);
        let fin = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(fin.header.flags, FIN | ACK);
        assert!(fin.payload.is_empty());
        assert_eq!(fin.header.sequence, next.0);
        assert_eq!(a.fin_sequence, Some(next));
        assert_eq!(a.snd_nxt, next.wrapping_add(1));
        assert_eq!(a.state(), State::FinWait1);
        assert_eq!(a.congestion.cwnd(), 10_000);
        assert_eq!(a.transmit(50, &mut [0; 64]), Ok(None));
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK)), set
//# SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.
fn window_updates_order_by_sequence_then_ack() {
    for iss in [100, u32::MAX - 4] {
        let (mut a, _) = pair(config(64, 8), iss);
        a.write(b"abcdefgh").unwrap();
        packet(&mut a, 40);
        let seq = a.receive.next();
        let ack = a.snd_una;
        // Newer SEQ; equal SEQ with equal, advancing, and stale ACK;
        // older SEQ despite newer ACK; finally newer SEQ with equal ACK.
        for (i, (seq, ack, window, accepted)) in [
            (seq.wrapping_add(1), ack, 40, true),
            (seq.wrapping_add(1), ack, 41, true),
            (seq.wrapping_add(1), ack.wrapping_add(1), 42, true),
            (seq.wrapping_add(1), ack, 43, false),
            (seq, ack.wrapping_add(2), 44, false),
            (seq.wrapping_add(2), ack.wrapping_add(2), 45, true),
        ]
        .into_iter()
        .enumerate()
        {
            let before = (a.snd_wnd, a.wl1, a.wl2);
            inject(&mut a, 50 + i as u64, seq, ack, ACK, window, b"");
            assert_eq!(
                (a.snd_wnd, a.wl1, a.wl2),
                if accepted {
                    (u32::from(window), seq, ack)
                } else {
                    before
                }
            );
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# This should not occur since a FIN has been received from the remote side. Ignore
//# the segment text.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//= reason=Closing-state test additionally checks URG after FIN cannot advance the urgent endpoint.
//# This should not occur since a FIN has been received from the remote side. Ignore the
//# URG.
fn text_after_fin_is_ignored_in_closing_states() {
    for closing in [false, true] {
        let (mut a, mut b) = pair(config(64, 8), 100);
        if closing {
            a.shutdown().unwrap();
            packet(&mut a, 40); // Peer has not acknowledged our FIN.
        }
        b.write(b"last").unwrap();
        b.shutdown().unwrap();
        deliver(&mut b, &mut a, 50);
        assert_eq!(
            a.state(),
            if closing {
                State::Closing
            } else {
                State::CloseWait
            }
        );
        // Test CLOSE-WAIT (or CLOSING), then LAST-ACK (or TIME-WAIT).
        for step in 0..2 {
            a.take_events();
            let next = a.receive.next();
            let ack = a.snd_una;
            let state = a.state();
            let total = a.received_total;
            let urgent_before = (a.rcv_up, a.urgent_remaining());
            inject(
                &mut a,
                60 + step * 20,
                next,
                ack,
                ACK | PSH | URG,
                64,
                b"bad",
            );
            assert_eq!((a.rcv_up, a.urgent_remaining()), urgent_before);
            assert_eq!(a.state(), state);
            assert_eq!(a.receive.next(), next);
            assert_eq!(a.received_total, total);
            assert_eq!(a.receive.readable(), if step == 0 { 4 } else { 0 });
            let events = a.take_events();
            assert!(!events.readable && !events.pushed);
            let mut out = [0; 8];
            if step == 0 {
                assert_eq!(a.read(&mut out), Ok(4));
                assert_eq!(&out[..4], b"last");
                if closing {
                    let ack = a.snd_nxt;
                    inject(&mut a, 70, next, ack, ACK, 64, b"");
                    assert_eq!(a.state(), State::TimeWait);
                } else {
                    a.shutdown().unwrap();
                    packet(&mut a, 70);
                    assert_eq!(a.state(), State::LastAck);
                }
            }
            assert_eq!(a.read(&mut out), Ok(0));
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.2.2
//= type=test
//# A TCP implementation MUST include a SWS avoidance algorithm in the receiver
//# (MUST-39).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//= reason=RCV.NXT reflects accepted contiguous bytes and advertised credit; scaled rounding exception scoped in existing SHLD-14 evidence.
//# Once the TCP endpoint takes responsibility for the data, it advances RCV.NXT over the
//# data accepted, and adjusts RCV.WND as appropriate to the current buffer availability.
//# The total of RCV.NXT and RCV.WND should not be reduced.
fn handshake_data_backpressure_partial_reads_and_sequence_wrap() {
    let (mut a, mut b) = pair(config(8, 4), u32::MAX - 2);
    assert_eq!(a.write(b"abcdefghij"), Ok(8));
    assert_eq!(a.write(b"i"), Err(Error::WouldBlock));
    assert_eq!(b.read(&mut [0; 1]), Err(Error::WouldBlock));
    assert_eq!(b.read(&mut []), Err(Error::InvalidArgument));
    deliver(&mut a, &mut b, 40);
    assert!(!b.ack_pending);
    assert_eq!(b.ack_deadline, Some(200_040));
    deliver(&mut a, &mut b, 50);
    assert!(b.ack_pending);
    deliver(&mut b, &mut a, 60);
    assert_eq!(a.acknowledged(), 8);
    assert_eq!(a.take_events().acknowledged, Some(8));
    assert_eq!(a.write(b"ijkl"), Ok(4));
    let mut out = [0; 8];
    assert_eq!(b.read(&mut out[..2]), Ok(2));
    assert_eq!(&out[..2], b"ab");
    assert!(!b.ack_pending); // SWS: wait for four bytes of credit.
    assert_eq!(b.read(&mut out[..2]), Ok(2));
    assert_eq!(&out[..2], b"cd");
    deliver(&mut b, &mut a, 70);
    deliver(&mut a, &mut b, 80);
    assert_eq!(b.read(&mut out), Ok(8));
    assert_eq!(&out, b"efghijkl");
    assert_eq!(b.received_total, 12);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.4
//= type=test
//# However, there MUST be a way for an application to disable the Nagle algorithm
//# on an individual connection (MUST-17).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.4
//= type=test
//# A TCP implementation SHOULD implement the Nagle algorithm to coalesce short
//# segments (SHLD-7).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.2.1
//= type=test
//# A TCP implementation MUST include a SWS avoidance algorithm in the sender
//# (MUST-38).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.3
//= type=test
//# A TCP endpoint SHOULD implement a delayed ACK (SHLD-18), but an ACK should not
//# be excessively delayed; in particular, the delay MUST be less than 0.5 seconds
//# (MUST-40).
//= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
//= type=test
//= reason=Receiver role, all recovery profiles. Default 200ms timer; configuration rejects >=500ms. Existing tests assert no early output, timeout at first packet+200ms, and immediate second full-RMSS ACK; caller must service scheduled timeout/poll. Not a guarantee when host ignores deadlines.
//# The delayed ACK algorithm specified in [RFC1122] SHOULD be used by a TCP receiver.
//= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
//= type=test
//= reason=Receiver role, all recovery profiles. Default 200ms timer; configuration rejects >=500ms. Existing tests assert no early output, timeout at first packet+200ms, and immediate second full-RMSS ACK; caller must service scheduled timeout/poll. Not a guarantee when host ignores deadlines.
//# When using delayed ACKs, a TCP receiver MUST NOT excessively delay acknowledgments.
//= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
//= type=test
//= reason=Receiver role, all recovery profiles. Default 200ms timer; configuration rejects >=500ms. Existing tests assert no early output, timeout at first packet+200ms, and immediate second full-RMSS ACK; caller must service scheduled timeout/poll. Not a guarantee when host ignores deadlines.
//# Specifically, an ACK SHOULD be generated for at least every second full-sized segment,
//# and MUST be generated within 500 ms of the arrival of the first unacknowledged packet.
//= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
//= type=test
//= reason=Receiver role, all recovery profiles. Default 200ms timer; configuration rejects >=500ms. Existing tests assert no early output, timeout at first packet+200ms, and immediate second full-RMSS ACK; caller must service scheduled timeout/poll. Not a guarantee when host ignores deadlines.
//# Finally, we repeat that an ACK MUST NOT be delayed for more than 500 ms waiting on a
//# second full-sized segment to arrive.
fn delayed_ack_nagle_and_override_deadlines() {
    let (mut a, mut b) = pair(config(64, 4), 100);
    a.write(b"abcde").unwrap();
    deliver(&mut a, &mut b, 40);
    assert_eq!(a.transmit(50, &mut [0; 64]), Ok(None));
    assert_eq!(b.transmit(50, &mut [0; 64]), Ok(None));
    b.timeout(200_040).unwrap();
    deliver(&mut b, &mut a, 200_040);
    deliver(&mut a, &mut b, 200_050);
    a.write(b"f").unwrap();
    assert_eq!(a.transmit(200_060, &mut [0; 64]), Ok(None));
    a.timeout(700_050).unwrap();
    assert_eq!(a.transmit(700_050, &mut [0; 64]), Ok(None));
    a.set_nagle(false);
    let bytes = packet(&mut a, 700_050);
    assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, b"f");

    let (mut a, _) = pair(config(64, 4), 100);
    a.set_nagle(false);
    let next = a.receive.next();
    let ack = a.snd_nxt;
    inject(&mut a, 40, next, ack, ACK, 2, b"");
    a.write(b"abcdef").unwrap();
    assert_eq!(a.transmit(50, &mut [0; 64]), Ok(None));
    a.timeout(500_040).unwrap();
    let bytes = packet(&mut a, 500_040);
    assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, b"ab");
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.5
//= type=test
//# A TCP implementation MUST support simultaneous open attempts (MUST- 10).
fn simultaneous_open_and_lost_final_ack() {
    let cfg = config(64, 8);
    let mut a = Connection::active(tuple(), cfg.clone(), 10, 0).unwrap();
    let mut b = Connection::active(reverse(tuple()), cfg, 50, 0).unwrap();
    let a_syn = packet(&mut a, 0);
    let b_syn = packet(&mut b, 0);
    a.input(10, &wire::parse(ip(reverse(tuple())), &b_syn).unwrap())
        .unwrap();
    b.input(10, &wire::parse(ip(tuple()), &a_syn).unwrap())
        .unwrap();
    assert_eq!(a.state(), State::SynReceived);
    let a_synack = packet(&mut a, 20);
    let b_synack = packet(&mut b, 20);
    let sa = wire::parse(ip(tuple()), &a_synack).unwrap();
    let sb = wire::parse(ip(reverse(tuple())), &b_synack).unwrap();
    assert_eq!(sa.header.sequence, 10);
    assert_eq!(sb.header.sequence, 50);
    assert_eq!(sa.header.flags, SYN | ACK | ECE);
    assert_eq!(sb.header.flags, SYN | ACK | ECE);
    a.input(30, &sb).unwrap();
    b.input(30, &sa).unwrap();
    assert_eq!(a.state(), State::Established);
    assert_eq!(b.state(), State::Established);
    assert!(a.ecn_send() && b.ecn_send());
    let _lost = packet(&mut a, 40);
    a.input(50, &sb).unwrap();
    let ack = packet(&mut a, 50);
    assert_eq!(wire::parse(ip(tuple()), &ack).unwrap().header.flags, ACK);
    assert_eq!(a.snd_nxt, Seq(11));
}

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
//= type=test
//# The following procedure MUST be used to handle excessive retransmissions of data
//# segments (MUST-20):
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
//= type=test
//# SYN retransmissions MUST be handled in the general way just described for data
//# retransmissions, including notification of the application layer.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
//= type=test
//# (e) TCP implementations SHOULD inform the application of the delivery problem
//# (unless such information has been disabled by the application; see the
//# "Asynchronous Reports" section (Section 3.9.1.8)), when R1 is reached and before R2
//# (SHLD-9).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
//= type=test
//# The value of R2 SHOULD correspond to at least 100 seconds (SHLD-11).
#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.8
//= type=test
//= reason=Default SYN/data R2 terminal behavior; storage reclaimed by release, timer servicing belongs to driver; explicit application stall timeout is separate.
//# For any state if the user timeout expires, flush all queues, signal the user "error:
//# connection aborted due to user timeout" in general and for any outstanding calls, delete
//# the TCB, enter the CLOSED state, and return.
fn syn_and_data_failures_warn_before_default_r2_expires() {
    for handshake in [true, false] {
        let cfg = config(64, 8);
        assert!(cfg.user_timeout_us >= 100_000_000);
        let mut a = if handshake {
            Connection::active(tuple(), cfg, 100, 0).unwrap()
        } else {
            pair(cfg, 100).0
        };
        a.take_events();
        if !handshake {
            a.write(b"lost").unwrap();
        }
        let original = packet(&mut a, 40);
        let original = wire::parse(ip(tuple()), &original).unwrap();
        for attempt in 0..3 {
            let deadline = a.rto_deadline.unwrap();
            a.timeout(deadline).unwrap();
            assert_eq!(a.take_events().retransmission_warning, attempt == 2);
            assert_eq!(a.take_route_advice(), attempt == 2);
            assert_ne!(a.state(), State::Closed);
            let retry = packet(&mut a, deadline);
            let retry = wire::parse(ip(tuple()), &retry).unwrap();
            assert_eq!(retry.header.sequence, original.header.sequence);
            assert_eq!(retry.payload, original.payload);
            assert_eq!(retry.header.flags & SYN, original.header.flags & SYN);
        }
        let deadline = a.user_deadline().unwrap();
        a.timeout(deadline - 1).unwrap();
        assert_ne!(a.state(), State::Closed);
        a.timeout(deadline).unwrap();
        assert_eq!(a.take_events().closed, Some(CloseReason::TimedOut));
    }
}

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
//= type=test
//# The transmitter SHOULD collapse successive bits when it packetizes data, to send
//# the largest possible segment (SHLD-27).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
//= type=test
//# However, a TCP implementation SHOULD send a maximum-sized segment whenever
//# possible (SHLD-28) to improve performance (see Section 3.8.6.2.1).
#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
//= type=test
//= reason=FIFO byte queue across successive writes, not per-write completion records.
//# Multiple SENDs are served in first come, first served order, so the TCP endpoint will
//# queue those it cannot service immediately.
fn successive_writes_coalesce_to_mss_and_push_the_final_segment() {
    let (mut a, _) = pair(config(64, 8), 100);
    a.set_nagle(false);
    for bytes in [&b"ab"[..], &b"cdef"[..], &b"ghijk"[..]] {
        assert_eq!(a.write(bytes), Ok(bytes.len()));
    }
    for expected in [&b"abcdefgh"[..], &b"ijk"[..]] {
        let bytes = packet(&mut a, 40);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.payload, expected);
        assert_ne!(segment.header.flags & PSH, 0);
    }
    assert_eq!(a.transmit(40, &mut [0; 64]), Ok(None));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.2
//= type=test
//= reason=Scaling-capable endpoint offers WS in active SYN and echoes only peer-offered WS in passive SYN-ACK; scale fixed for connection.
//# The three-byte Window Scale option MAY be sent in a <SYN> segment by
//# a TCP.
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.2
//= type=test
//= reason=Scaling-capable endpoint offers WS in active SYN and echoes only peer-offered WS in passive SYN-ACK; scale fixed for connection.
//# Thus, a TCP that is prepared to scale windows SHOULD send the option,
//# even if its own scale factor is 1 and the exponent 0.
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.2
//= type=test
//= reason=Scaling-capable endpoint offers WS in active SYN and echoes only peer-offered WS in passive SYN-ACK; scale fixed for connection.
//# This option MAY be sent in an initial <SYN> segment (i.e., a segment
//# with the SYN bit on and the ACK bit off).
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.2
//= type=test
//= reason=Scaling-capable endpoint offers WS in active SYN and echoes only peer-offered WS in passive SYN-ACK; scale fixed for connection.
//# If a Window Scale option
//# was received in the initial <SYN> segment, then this option MAY be
//# sent in the <SYN,ACK> segment.
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.3
//= type=test
//= reason=SYN-only WS output sends capacity-derived local_scale, including passive echo after peer offer; selected R=2 is asserted on wire.
//# o  If a TCP receives a <SYN> segment containing a Window Scale
//# option, it SHOULD send its own Window Scale option in the
//# <SYN,ACK> segment.
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.3
//= type=test
//= reason=SYN-only WS output sends capacity-derived local_scale, including passive echo after peer offer; selected R=2 is asserted on wire.
//# o  The Window Scale option MUST be sent with shift.cnt = R, where R
//# is the value that the TCP would like to use for its receive
//# window.
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.1
//= type=test
//= reason=Wire tests inject changed WS on established data/ACK, including zero/nonzero/absent negotiation, and assert fixed shifts, unchanged effective window expansion and no outgoing non-SYN WS.
//# This option is sent only in a <SYN> segment (a
//# segment with the SYN bit on), hence the window scale is fixed in each
//# direction when a connection is opened.
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.2
//= type=test
//= reason=WS wire kind fixed at 3 in SYN layout; independent option parser/clamp assertions use literal kind 3.
//# Kind: 3
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.2
//= type=test
//= reason=WS emits [NOP,3,3,local_scale], parser only accepts option length 3.
//# Length: 3 bytes
fn syn_option_layout_and_short_output_are_transactional() {
    for (synack, scaling) in [(false, true), (true, false), (true, true)] {
        for local_ts in [false, true] {
            for peer_ts in [false, true] {
                if !synack && peer_ts {
                    continue;
                }
                for (local_sack, peer_sack) in
                    [(false, false), (false, true), (true, false), (true, true)]
                {
                    let mut cfg = config(131072, 300);
                    cfg.ecn = false;
                    cfg.receive_ip_payload_limit = 200;
                    cfg.send_ip_payload_limit = if local_ts && local_sack {
                        44
                    } else if local_ts {
                        40
                    } else if local_sack {
                        32
                    } else {
                        28
                    };
                    cfg.sack = local_sack;
                    cfg.timestamps = local_ts;
                    let mut c = if synack {
                        let mut options = vec![2, 4, 1, 44];
                        if peer_sack {
                            options.extend_from_slice(&[1, 1, 4, 2]);
                        }
                        if scaling {
                            options.extend_from_slice(&[1, 3, 3, 7]);
                        }
                        if peer_ts {
                            options.extend_from_slice(&[1, 1, 8, 10, 0, 0, 0, 2, 0, 0, 0, 0]);
                        }
                        let mut input = [0; 60];
                        let size = wire::encode(
                            ip(reverse(tuple())),
                            Header {
                                source_port: tuple().remote.port(),
                                destination_port: tuple().local.port(),
                                sequence: 900,
                                acknowledgment: 0,
                                flags: SYN,
                                window: 65535,
                                urgent_pointer: 0,
                            },
                            &options,
                            &[],
                            &mut input,
                        )
                        .unwrap();
                        let syn = wire::parse(ip(reverse(tuple())), &input[..size]).unwrap();
                        Connection::passive(tuple(), cfg, 100, 3_000, &syn).unwrap()
                    } else {
                        Connection::active(tuple(), cfg, 100, 3_000).unwrap()
                    };
                    let timestamps = local_ts && (!synack || peer_ts);
                    let mut expected = vec![2, 4, 0, 180];
                    let sack_offer = local_sack && (!synack || peer_sack);
                    if timestamps {
                        let echo = if synack { 2 } else { 0 };
                        expected.extend_from_slice(if sack_offer {
                            &[4, 2, 8, 10]
                        } else {
                            &[1, 1, 8, 10]
                        });
                        expected.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, echo]);
                    } else if sack_offer {
                        expected.extend_from_slice(&[1, 1, 4, 2]);
                    }
                    if scaling {
                        expected.extend_from_slice(&[1, 3, 3, 2]);
                    }
                    let size = 20 + expected.len();
                    let before = (
                        c.now,
                        c.snd_nxt,
                        c.last_sent,
                        c.last_ack_sent,
                        c.advertised_edge,
                        c.ts_recent,
                        c.last_timestamp_sent_at,
                        c.sample,
                        c.next_deadline(),
                        c.syn_pending,
                        (
                            c.ack_pending,
                            c.sack_receive,
                            c.sack_send,
                            c.timestamps,
                            c.scaling,
                            c.state,
                        ),
                    );
                    for len in 0..size {
                        let mut short = vec![0xa5; len];
                        assert_eq!(c.transmit(4_000, &mut short), Err(Error::OutputTooSmall));
                        assert_eq!(short, vec![0xa5; len]);
                        assert_eq!(
                            (
                                c.now,
                                c.snd_nxt,
                                c.last_sent,
                                c.last_ack_sent,
                                c.advertised_edge,
                                c.ts_recent,
                                c.last_timestamp_sent_at,
                                c.sample,
                                c.next_deadline(),
                                c.syn_pending,
                                (
                                    c.ack_pending,
                                    c.sack_receive,
                                    c.sack_send,
                                    c.timestamps,
                                    c.scaling,
                                    c.state
                                ),
                            ),
                            before
                        );
                    }
                    let mut out = vec![0; size];
                    assert_eq!(c.transmit(4_000, &mut out), Ok(Some(size)));
                    let segment = wire::parse(ip(tuple()), &out).unwrap();
                    assert_eq!(segment.raw_options, expected);
                    assert_eq!(segment.header.flags, SYN | if synack { ACK } else { 0 });
                    assert_eq!(segment.header.window, 65535);
                    assert_eq!(segment.options.mss, Some(180));
                    assert_eq!(segment.options.window_scale, scaling.then_some(2));
                    assert_eq!(
                        segment.options.timestamps,
                        timestamps.then_some((4, if synack { 2 } else { 0 }))
                    );
                    assert_eq!(segment.options.sack_permitted, sack_offer);
                    assert_eq!(c.sack_receive, sack_offer);
                    assert!(segment.payload.is_empty());
                    assert!(!c.syn_pending);
                }
            }
        }
    }
}

#[test]
fn output_small_and_none_do_not_commit_protocol_state() {
    let mut a = Connection::active(tuple(), config(64, 8), 42, 0).unwrap();
    let before = (a.snd_nxt, a.next_deadline(), a.now, a.advertised_edge);
    assert_eq!(a.transmit(100, &mut [0; 27]), Err(Error::OutputTooSmall));
    assert_eq!(
        (a.snd_nxt, a.next_deadline(), a.now, a.advertised_edge),
        before
    );
    assert!(a.syn_pending);
    assert_eq!(a.write(b"queued"), Ok(6));
    let bytes = packet(&mut a, 100);
    assert!(wire::parse(ip(tuple()), &bytes).unwrap().payload.is_empty());
    let before = (a.snd_nxt, a.next_deadline(), a.now);
    assert_eq!(a.transmit(200, &mut [0; 128]), Ok(None));
    assert_eq!((a.snd_nxt, a.next_deadline(), a.now), before);
    //= https://www.rfc-editor.org/rfc/rfc7323#section-5.4
    //= type=test
    //= reason=Every input/transmit checks nondecreasing Instant, TSval derived by fixed selected local tick scaling (default milliseconds) modulo2^32; repeated Instant intentionally repeats TSval. Physical rate/precision remain caller obligations; endpoint timestamp half-range gap checks are separate.
    //# The PAWS mechanism also puts a strong monotonicity requirement on the
    //# sender's timestamp clock.
    assert_eq!(a.transmit(99, &mut [0; 128]), Err(Error::TimeWentBackwards));
    let (mut a, _) = pair(config(64, 8), 42);
    a.write(b"data").unwrap();
    let before = (a.snd_nxt, a.next_deadline(), a.now, a.advertised_edge);
    assert_eq!(a.transmit(100, &mut [0; 23]), Err(Error::OutputTooSmall));
    assert_eq!(
        (a.snd_nxt, a.next_deadline(), a.now, a.advertised_edge),
        before
    );
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.8
//= type=test
//# For any state if the retransmission timeout expires on a segment in the
//# retransmission queue, send the segment at the front of the retransmission
//# queue again, reinitialize the retransmission timer, and return.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//= reason=Partial cumulative ACK removes only covered bytes and reports progress; future ACK rejection additionally in rfc5961_ack_bounds_are_inclusive_and_reject_all_incoming_side_effects.
//# If SND.UNA < SEG.ACK =< SND.NXT, then set SND.UNA <- SEG.ACK. Any segments on the
//# retransmission queue that are thereby entirely acknowledged are removed. Users should
//# receive positive acknowledgments for buffers that have been SENT and fully acknowledged
//# (i.e., SEND buffer should be returned with "ok" response). If the ACK is a duplicate
//# (SEG.ACK =< SND.UNA), it can be ignored. If the ACK acks something not yet sent (SEG.ACK
//# > SND.NXT), then send an ACK, drop the segment, and return.
//= https://www.rfc-editor.org/rfc/rfc6298#section-5
//= type=test
//= reason=Partial-ACK/wrap trace verifies successful emission times and original packet boundaries; rto_variable_packets_partial_ack_fresh_tail_and_failed_output also covers configured floors and SACK/RACK.
//# An implementation MUST manage the retransmission timer(s) in such a way that a segment
//# is never retransmitted too early, i.e., less than one RTO after the previous
//# transmission of that segment.
//= https://www.rfc-editor.org/rfc/rfc6298#section-5
//= type=test
//= reason=Ordinary non-SACK RTO with partial cumulative ACK and sequence wrap.
//# (5.5) The host MUST set RTO <- RTO * 2 ("back off the timer").
//= https://www.rfc-editor.org/rfc/rfc6298#section-5
//= type=test
//= reason=Partial-ACK/wrap trace verifies successful emission times and original packet boundaries; rto_variable_packets_partial_ack_fresh_tail_and_failed_output also covers configured floors and SACK/RACK.
//# (5.1) Every time a packet containing data is sent (including a retransmission), if the
//# timer is not running, start it running so that it will expire after RTO seconds (for
//# the current value of RTO).
//= https://www.rfc-editor.org/rfc/rfc6298#section-5
//= type=test
//= reason=Ordinary non-SACK RTO with partial cumulative ACK and sequence wrap.
//# (5.2) When all outstanding data has been acknowledged, turn off the retransmission
//# timer.
//= https://www.rfc-editor.org/rfc/rfc6298#section-5
//= type=test
//= reason=Partial-ACK/wrap trace verifies successful emission times and original packet boundaries; rto_variable_packets_partial_ack_fresh_tail_and_failed_output also covers configured floors and SACK/RACK.
//# (5.3) When an ACK is received that acknowledges new data, restart the retransmission
//# timer so that it will expire after RTO seconds (for the current value of RTO).
//= https://www.rfc-editor.org/rfc/rfc6298#section-5
//= type=test
//= reason=Ordinary non-SACK RTO with partial cumulative ACK and sequence wrap.
//# (5.4) Retransmit the earliest segment that has not been acknowledged by the TCP
//# receiver.
//= https://www.rfc-editor.org/rfc/rfc6298#section-5
//= type=test
//= reason=Ordinary non-SACK RTO with partial cumulative ACK and sequence wrap.
//# (5.6) Start the retransmission timer, such that it expires after RTO seconds (for the
//# value of RTO after the doubling operation outlined in 5.5).
fn retransmission_uses_partial_ack_base_and_never_sends_unsent_tail() {
    let (mut a, mut b) = pair(config(64, 8), u32::MAX - 4);
    a.set_nagle(false);
    a.write(b"abcdefghijk").unwrap();
    let _lost = packet(&mut a, 40);
    let ack = a.send_base.wrapping_add(3);
    let next = a.receive.next();
    inject(&mut a, 50, next, ack, ACK, 64, b"");
    assert_eq!(a.acknowledged(), 3);
    let high = a.snd_nxt;
    assert_eq!(a.rto_deadline, Some(50 + a.rto()));
    let next = a.receive.next();
    inject(&mut a, 60, next, ack, ACK, 64, b"");
    assert_eq!(a.rto_deadline, Some(50 + a.rto()));
    let deadline = a.rto_deadline.unwrap();
    a.timeout(deadline - 1).unwrap();
    assert!(!a.retx_pending);
    a.timeout(deadline).unwrap();
    assert!(a.retx_pending);
    assert_eq!(a.snd_nxt, high);
    let before = a.next_deadline();
    assert_eq!(
        a.transmit(deadline, &mut [0; 24]),
        Err(Error::OutputTooSmall)
    );
    assert!(a.retx_pending);
    assert_eq!(a.next_deadline(), before);
    let bytes = packet(&mut a, deadline);
    let retransmit = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(retransmit.header.sequence, ack.0);
    assert_eq!(retransmit.payload, b"defgh");
    assert_eq!(a.snd_nxt, high);
    assert!(a.sample.is_none());
    assert!(a.rto() >= 2_000_000);
    assert_eq!(a.rto_deadline, Some(deadline + a.rto()));
    let interval = a.rto();
    let second = deadline + interval;
    a.timeout(second - 1).unwrap();
    let fresh = packet(&mut a, second - 1);
    let seg = wire::parse(ip(tuple()), &fresh).unwrap();
    assert_eq!(seg.header.sequence, high.0);
    assert_eq!(seg.payload, b"ijk");
    assert_eq!(a.rto_deadline, Some(second));
    assert!(!a.retx_pending);
    a.timeout(second).unwrap();
    let bytes = packet(&mut a, second);
    let seg = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(seg.header.sequence, ack.0);
    assert_eq!(seg.payload, b"defgh"); // fresh tail is only 1us old
    assert_eq!(second - deadline, interval);
    assert_eq!(a.rto_deadline, Some(second + a.rto()));
    // Separately exercise actual two-peer loss recovery.
    let (mut c, mut d) = pair(config(64, 8), 100);
    c.write(b"lost").unwrap();
    let _lost = packet(&mut c, 40);
    let deadline = c.rto_deadline.unwrap();
    c.timeout(deadline).unwrap();
    deliver(&mut c, &mut d, deadline);
    d.timeout(deadline + 200_000).unwrap();
    deliver(&mut d, &mut c, deadline + 200_000);
    assert_eq!(c.acknowledged(), 4);
    assert_eq!(c.rto_deadline, None);
    assert_eq!(d.read(&mut [0; 4]), Ok(4));
    // Keep this peer alive to ensure the original test never delivered
    // falsely acknowledged bytes into the receiver.
    assert_eq!(b.read(&mut [0; 1]), Err(Error::WouldBlock));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.6
//= type=test
//# The user who CLOSEs may continue to RECEIVE until the TCP receiver is told that
//# the remote peer has CLOSED also.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# if the FIN segment is now acknowledged, then enter FIN- WAIT-2 and continue
//# processing in that state.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# The only thing that can arrive in this state is a retransmission of the remote
//# FIN. Acknowledge it, and restart the 2 MSL timeout.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# If our FIN is now acknowledged, delete the TCB, enter the CLOSED
//# state, and return.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.2
//= type=test
//# Return "error: connection closing" and do not service request.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.4
//= type=test
//= reason=CLOSE-WAIT sends final reply data with FIN and enters LAST-ACK only on committed output.
//# Queue this request until all preceding SENDs have been segmentized; then send a FIN
//# segment, enter LAST-ACK state.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//= reason=FIN advances receive sequence and half_closed event, sends ACK, preserves buffered bytes for subsequent read.
//# If the FIN bit is set, signal the user "connection closing" and return any pending
//# RECEIVEs with same message, advance RCV.NXT over the FIN, and send an acknowledgment for
//# the FIN. Note that FIN implies PUSH for any segment text not yet delivered to the user.
fn fin_half_close_time_wait_and_duplicate_fin_restart() {
    let (mut a, mut b) = pair(config(64, 8), 100);
    a.write(b"last").unwrap();
    a.shutdown().unwrap();
    assert_eq!(a.write(b"no"), Err(Error::InvalidState));
    deliver(&mut a, &mut b, 40);
    assert_eq!(a.state(), State::FinWait1);
    assert_eq!(a.write(b"no"), Err(Error::InvalidState));
    assert_eq!(a.send.len(), 4);
    assert_eq!(b.state(), State::CloseWait);
    let events = b.take_events();
    assert!(events.readable && events.half_closed);
    assert_eq!(b.read(&mut [0; 8]), Ok(4));
    assert_eq!(b.read(&mut [0; 8]), Ok(0));
    deliver(&mut b, &mut a, 50);
    assert_eq!(a.state(), State::FinWait2);
    assert_eq!(a.write(b"no"), Err(Error::InvalidState));
    assert_eq!(a.send.len(), 0);
    b.write(b"reply").unwrap();
    b.shutdown().unwrap();
    let fin = deliver(&mut b, &mut a, 60);
    assert_eq!(b.state(), State::LastAck);
    assert_eq!(b.write(b"no"), Err(Error::InvalidState));
    assert_eq!(b.send.len(), 5);
    assert_eq!(a.state(), State::TimeWait);
    assert_eq!(a.write(b"no"), Err(Error::InvalidState));
    assert_eq!(a.send.len(), 0);
    assert_eq!(a.take_events().closed, Some(CloseReason::Normal));
    let deadline = a.next_deadline().unwrap();
    a.input(70, &wire::parse(ip(reverse(tuple())), &fin).unwrap())
        .unwrap();
    assert_eq!(deadline, 60 + 120_000_000);
    assert_eq!(a.next_deadline(), Some(70 + 120_000_000));
    deliver(&mut a, &mut b, 80);
    assert_eq!(b.state(), State::Closed);
    assert_eq!(b.close_reason(), Some(CloseReason::Normal));
    assert_eq!(b.next_deadline(), None);
    assert_eq!(b.transmit(80, &mut [0; 64]), Ok(None));
    assert_eq!(a.read(&mut [0; 8]), Ok(5));
    assert_eq!(a.read(&mut [0; 8]), Ok(0));
    a.timeout(deadline).unwrap();
    assert_eq!(a.state(), State::TimeWait);
    a.timeout(a.next_deadline().unwrap()).unwrap();
    assert_eq!(a.state(), State::Closed);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# if the ACK acknowledges our FIN, then enter the TIME-WAIT state;
//# otherwise, ignore the segment.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//= reason=Unacknowledged local FIN enters CLOSING; fin_half_close_time_wait_and_duplicate_fin_restart covers acknowledged branch and timer cancellation.
//# If our FIN has been ACKed (perhaps in this segment), then enter TIME-WAIT, start the
//# time-wait timer, turn off the other timers; otherwise, enter the CLOSING state.
fn simultaneous_close_and_fin_retransmission() {
    let (mut a, mut b) = pair(config(64, 8), 100);
    a.shutdown().unwrap();
    b.shutdown().unwrap();
    let af = packet(&mut a, 40);
    let bf = packet(&mut b, 40);
    a.input(50, &wire::parse(ip(reverse(tuple())), &bf).unwrap())
        .unwrap();
    b.input(50, &wire::parse(ip(tuple()), &af).unwrap())
        .unwrap();
    assert_eq!(a.state(), State::Closing);
    assert_eq!(b.state(), State::Closing);
    assert_eq!(a.write(b"no"), Err(Error::InvalidState));
    assert_eq!(a.send.len(), 0);
    let next = a.receive.next();
    let una = a.snd_una;
    inject(&mut a, 55, next, una, ACK, 64, b"");
    assert_eq!(a.state(), State::Closing);
    assert_eq!(a.time_wait_deadline, None);
    let _lost = packet(&mut b, 60);
    deliver(&mut a, &mut b, 60);
    assert_eq!(b.state(), State::TimeWait);
    let deadline = a.rto_deadline.unwrap();
    a.timeout(deadline).unwrap();
    let fin = deliver(&mut a, &mut b, deadline);
    assert_ne!(
        wire::parse(ip(tuple()), &fin).unwrap().header.flags & FIN,
        0
    );
    deliver(&mut b, &mut a, deadline);
    assert_eq!(a.state(), State::TimeWait);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# 3) If the RST bit is set and the sequence number does not exactly match the
//# next expected sequence value, yet is within the current receive window, TCP
//# endpoints MUST send an acknowledgment (challenge ACK):
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# After sending the challenge ACK, TCP endpoints MUST drop the unacceptable
//# segment and stop processing the incoming packet further.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# if the ACK bit is off, drop the segment and return
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
//= type=test
//= reason=ACK-only/text without SYN cannot establish a SYN-SENT connection.
//# Fifth, if neither of the SYN or RST bits is set, then drop the segment and return.
fn invalid_ack_reset_and_unsynchronized_text_are_not_processed() {
    let (mut a, _) = pair(config(64, 8), 100);
    a.write(b"retained").unwrap();
    packet(&mut a, 40);
    let next = a.receive.next();
    let high = a.snd_nxt;
    inject(&mut a, 50, next, high.wrapping_add(1), ACK, 0, b"bad");
    assert_eq!(a.send.len(), 8);
    assert_eq!(a.receive.readable(), 0);
    assert_eq!(a.snd_wnd, 64);
    packet(&mut a, 55); // Drain the invalid-ACK response before testing silent discard.
    inject(&mut a, 60, next, high, FIN | PSH, 0, b"bad");
    assert_eq!(a.receive.readable(), 0);
    assert_eq!(a.receive.next(), next);
    assert_eq!(a.state(), State::Established);
    assert_eq!(a.send.len(), 8);
    assert_eq!(a.snd_wnd, 64);
    assert!(!a.events_pending());
    assert_eq!(a.transmit(60, &mut [0; 64]), Ok(None));
    inject(&mut a, 70, next.wrapping_add(64), high, RST | ACK, 0, b"");
    assert_eq!(a.state(), State::Established);
    assert!(!a.ack_pending);
    inject(
        &mut a,
        80,
        next.wrapping_add(1),
        high,
        RST | ACK,
        0,
        b"rejected",
    );
    assert_eq!(a.state(), State::Established);
    assert!(a.challenge_ack_pending);
    assert_eq!(a.receive.readable(), 0);
    assert_eq!(a.receive.next(), next);
    assert_eq!(a.send.len(), 8);
    let response = packet(&mut a, 80);
    let response = wire::parse(ip(tuple()), &response).unwrap();
    assert_eq!(response.header.flags, ACK);
    assert_eq!(response.header.acknowledgment, next.0);
    // Filling the gap must not expose text from the rejected RST.
    inject(&mut a, 85, next, high, ACK, 64, b"x");
    let mut data = [0; 16];
    assert_eq!(a.read(&mut data), Ok(1));
    assert_eq!(data[0], b'x');
    let next = a.receive.next();
    // RST validation precedes ACK validation, including a bogus ACK.
    inject(&mut a, 90, next, high.wrapping_add(999), RST | ACK, 0, b"");
    assert_eq!(a.close_reason(), Some(CloseReason::Reset));
    assert_eq!(a.state(), State::Closed);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
//= type=test
//# Otherwise (no ACK), drop the segment and return.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
//= type=test
//# If SEG.ACK =< ISS or SEG.ACK > SND.NXT, send a reset (unless the RST bit
//# is set, if so drop the segment and return)
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
//= type=test
//= reason=SYN-SENT validates ACK before RST; no response to unacceptable RST. Erratum 8167 remains separate.
//# If SEG.ACK =< ISS or SEG.ACK > SND.NXT, send a reset (unless the RST bit is set, if so
//# drop the segment and return) <SEQ=SEG.ACK><CTL=RST>
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
//= type=test
//= reason=SYN-SENT reset acceptance uses ACK of SYN, not RCV.NXT; terminal reason distinguishes reset.
//# If the ACK was acceptable, then signal to the user "error: connection reset", drop the
//# segment, enter CLOSED state, delete TCB, and return. Otherwise (no ACK), drop the
//# segment and return.
//= https://www.rfc-editor.org/rfc/rfc5961#section-1.1
//= type=test
//= reason=All three defenses are selected for ordinary endpoint operation; RST/SYN/ACK assertion matrices establish the operative behavior, not cryptographic/on-path protection or administrator threat assessment.
//# The mitigations suggested in this document
//# SHOULD be implemented in devices that regularly need to maintain TCP
//# connections of the kind most vulnerable to the attacks described in
//# this document.
// Actor/condition: TCP endpoint; selected blind-attack mitigation.
//= https://www.rfc-editor.org/rfc/rfc5961#section-1.1
//= type=test
//= reason=All three defenses are selected for ordinary endpoint operation; RST/SYN/ACK assertion matrices establish the operative behavior, not cryptographic/on-path protection or administrator threat assessment.
//# These mitigations
//# MAY be implemented in other cases.
// Actor/condition: TCP endpoint; selected blind-attack mitigation.
//= https://www.rfc-editor.org/rfc/rfc5961#section-3.2
//= type=test
//= reason=SYN-SENT reset validation assertion matrix includes arbitrary peer sequences, invalid/missing ACK silence and valid reset closure.
//# In all
//# other cases the receiver MUST silently discard the segment.
// Actor/condition: TCP endpoint; SYN-SENT reset validation.
fn syn_sent_resets_require_ack_and_abort_outputs_once() {
    // Verified erratum 8167 removes the SYN-SENT RCV.NXT check:
    // https://www.rfc-editor.org/errata/eid8167
    // No peer sequence has been learned; only acknowledgment of our SYN matters.
    for iss in [100u32, u32::MAX] {
        for sequence in [0, 0x1234_5678, u32::MAX] {
            let mut a = Connection::active(tuple(), config(64, 8), iss, 0).unwrap();
            packet(&mut a, 0);
            for (flags, ack) in [
                (RST, iss.wrapping_add(1)),
                (RST | ACK, iss),
                (RST | ACK, iss.wrapping_add(2)),
            ] {
                inject(&mut a, 10, Seq(sequence), Seq(ack), flags, 0, b"");
                assert_eq!(a.state(), State::SynSent);
                assert_eq!(a.transmit(10, &mut [0; 64]), Ok(None));
            }
            for ack in [iss.wrapping_sub(1), iss, iss.wrapping_add(2)] {
                inject(&mut a, 15, Seq(sequence), Seq(ack), SYN | ACK, 64, b"bad");
                let bytes = packet(&mut a, 15);
                let reset = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(reset.header.flags, RST);
                assert_eq!(reset.header.sequence, ack);
                assert!(reset.payload.is_empty());
                assert_eq!(a.state(), State::SynSent);
                assert_eq!(a.snd_una, Seq(iss));
                assert_eq!(a.snd_nxt, Seq(iss.wrapping_add(1)));
                assert_eq!(a.irs, None);
                assert_eq!(a.receive.readable(), 0);
                assert!(!a.events_pending());
                assert_eq!(a.transmit(15, &mut [0; 64]), Ok(None));
            }
            inject(
                &mut a,
                20,
                Seq(sequence),
                Seq(iss.wrapping_add(1)),
                RST | ACK,
                0,
                b"",
            );
            assert_eq!(a.state(), State::Closed);
            assert_eq!(a.close_reason(), Some(CloseReason::Reset));
            assert_eq!(a.transmit(20, &mut [0; 64]), Ok(None));
        }
    }
    let (mut a, mut b) = pair(config(64, 8), 100);
    a.abort();
    assert_eq!(a.state(), State::Closed);
    assert_eq!(a.close_reason(), Some(CloseReason::Aborted));
    assert_eq!(a.transmit(40, &mut [0; 1]), Err(Error::OutputTooSmall));
    deliver(&mut a, &mut b, 40);
    assert_eq!(b.close_reason(), Some(CloseReason::Reset));
    assert_eq!(a.transmit(50, &mut [0; 64]), Ok(None));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1
//= type=test
//# Probing of zero (offered) windows MUST be supported (MUST-36).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1
//= type=test
//# As long as the receiving TCP peer continues to send acknowledgments in response
//# to the probe segments, the sending TCP peer MUST allow the connection to stay
//# open (MUST-37).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1
//= type=test
//= reason=Receiver replies to persist probes with current next sequence/window; responsive sender survives.
//# When the receiving TCP peer has a zero window and a segment arrives, it must still send
//# an acknowledgment showing its next expected sequence number and current window (zero).
//= https://www.rfc-editor.org/rfc/rfc6429#section-1
//= type=test
//# Therefore, zero window probing needs to be supported to prevent a
//# connection from hanging forever if ACK segments that re-open the window
//# are lost.
//= https://www.rfc-editor.org/rfc/rfc6429#section-2
//= type=test
//# Although this may result in a prolonged ZWP state, it would be premature
//# for TCP to take action on its own and close the printer connection
//# merely due to its lack of progress. Once the printer's paper tray is
//# reloaded (which may be minutes, hours, or days later), the print job
//# needs to be able to continue uninterrupted over the same TCP connection.
fn zero_window_probe_recovers_lost_update_and_responsive_peer_survives() {
    let mut cfg = config(4, 4);
    cfg.user_timeout_us = 5_000_000;
    let (mut a, mut b) = pair(cfg, 100);
    a.write(b"abcd").unwrap();
    deliver(&mut a, &mut b, 40);
    deliver(&mut b, &mut a, 50);
    assert_eq!(a.snd_wnd, 0);
    a.write(b"efgh").unwrap();
    for _ in 0..3 {
        let when = a.loss_timer.unwrap().1;
        a.timeout(when).unwrap();
        deliver(&mut a, &mut b, when);
        deliver(&mut b, &mut a, when);
        assert_eq!(a.state(), State::Established);
    }
    assert_eq!(b.read(&mut [0; 4]), Ok(4));
    let when = a.now + 10;
    let _lost = packet(&mut b, when);
    let when = a.loss_timer.unwrap().1;
    // No timeout while waiting to send a probe, even when persist
    // backoff exceeds the configured data timeout.
    assert_eq!(a.user_deadline(), None);
    a.timeout(when).unwrap();
    deliver(&mut a, &mut b, when);
    b.timeout(when + 200_000).unwrap();
    deliver(&mut b, &mut a, when + 200_000);
    assert!(a.snd_wnd > 0);
    a.set_nagle(false);
    deliver(&mut a, &mut b, when + 200_010);
    assert_eq!(b.read(&mut [0; 4]), Ok(4));
}

#[test]
fn freed_receive_credit_is_not_accepted_until_advertised() {
    let (mut a, mut b) = pair(config(4, 4), 100);
    a.write(b"abcd").unwrap();
    deliver(&mut a, &mut b, 40);
    deliver(&mut b, &mut a, 50);
    assert_eq!(b.read(&mut [0; 4]), Ok(4));
    let next = b.receive.next();
    let ack = b.snd_nxt;
    inject(&mut b, 60, next, ack, ACK, 4, b"X");
    assert_eq!(b.receive.readable(), 0);
    packet(&mut b, 70);
    inject(&mut b, 80, next, ack, ACK, 4, b"X");
    assert_eq!(b.receive.readable(), 1);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# All incoming segments
//# whose ACK value doesn't satisfy the above condition MUST be
//# discarded and an ACK sent back.
fn passive_handshake_applies_blind_ack_check_before_state_specific_reset() {
    let mut active = Connection::active(tuple(), config(64, 8), 100, 0).unwrap();
    let syn = packet(&mut active, 0);
    let syn = wire::parse(ip(tuple()), &syn).unwrap();
    let mut passive = Connection::passive(reverse(tuple()), config(64, 8), 200, 0, &syn).unwrap();
    packet(&mut passive, 0);
    inject(&mut passive, 1, Seq(101), Seq(202), ACK, 64, &[]);
    let response = packet(&mut passive, 1);
    let response = wire::parse(ip(reverse(tuple())), &response).unwrap();
    assert_eq!(response.header.flags, ACK);
    assert_eq!(response.header.sequence, 201);
    assert_eq!(passive.state(), State::SynReceived);
    // Within the RFC 5961 range, but not an ACK of our SYN: state-specific RST.
    inject(&mut passive, 2, Seq(101), Seq(200), ACK, 64, &[]);
    let response = packet(&mut passive, 2);
    let response = wire::parse(ip(reverse(tuple())), &response).unwrap();
    assert_eq!(response.header.flags, RST);
    assert_eq!(response.header.sequence, 200);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.5
//= type=test
//# The urgent pointer MUST point to the sequence number of the octet following the
//# urgent data (MUST-62).
fn zero_urgent_offset_can_advance_the_stream_urgent_mark() {
    let (_, mut receiver) = pair(config(64, 4), 100);
    receiver.take_events();
    let sequence = receiver.receive.next().wrapping_add(2);
    let ack = receiver.snd_nxt;
    inject(&mut receiver, 40, sequence, ack, ACK | URG, 64, &[]);
    assert_eq!(receiver.urgent_remaining(), 2);
    assert_eq!(receiver.take_events().urgent, Some(2));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.5
//= type=test
//# However, TCP implementations MUST still include support for the urgent mechanism
//# (MUST-30).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# Segments with higher beginning sequence numbers SHOULD be held for later
//# processing (SHLD-31).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# o A TCP implementation MAY send an ACK segment acknowledging RCV.NXT when a
//# valid segment arrives that is in the window but not at the left window edge
//# (MAY-13).
//= https://www.rfc-editor.org/rfc/rfc6582#section-5
//= type=test
//= reason=newreno_partial_ack_wire_timer_and_exit_boundaries asserts immediate ACK pending and no delayed deadline for OOO pure data and hole-fill partial ACKs, with other pure-data holes still outstanding.
//# [RFC5681] specifies that "Out-of-order data segments SHOULD be acknowledged
//# immediately, in order to accelerate loss recovery".
//= https://www.rfc-editor.org/rfc/rfc6582#section-5
//= type=test
//= reason=newreno_partial_ack_wire_timer_and_exit_boundaries receives pure-data hole fills while another hole remains, asserts ack_pending and ack_deadline=None despite delayed ACK enabled, and immediately emits cumulative partial ACKs.
//# Echoing [RFC5681], our recommendation is that the data receiver send an immediate
//# acknowledgment for an out-of-order segment, even when that out-of-order segment fills
//# a hole in the buffer.
fn out_of_order_data_fin_and_inline_urgent() {
    let (mut a, mut b) = pair(config(64, 4), u32::MAX - 2);
    a.write_urgent(b"abcdef").unwrap();
    let first = packet(&mut a, 40);
    a.set_nagle(false);
    a.shutdown().unwrap();
    let second = packet(&mut a, 50);
    b.input(60, &wire::parse(ip(tuple()), &second).unwrap())
        .unwrap();
    assert_eq!(b.receive.readable(), 0);
    assert!(!b.receive.eof());
    assert!(b.ack_pending);
    assert_eq!(b.take_events().urgent, Some(6));
    b.input(70, &wire::parse(ip(tuple()), &first).unwrap())
        .unwrap();
    assert_eq!(b.state(), State::CloseWait);
    let mut out = [0; 8];
    assert_eq!(b.read(&mut out), Ok(6));
    assert_eq!(&out[..6], b"abcdef");
    assert_eq!(b.read(&mut out), Ok(0));
    assert_eq!(b.take_events().urgent, None);
}

#[test]
fn readable_bytes_defers_syn_payload_and_matches_inline_reads() {
    let metadata = ip(tuple());
    let header = Header {
        source_port: 1000,
        destination_port: 2000,
        sequence: 100,
        acknowledgment: 0,
        flags: SYN | URG,
        window: 64,
        urgent_pointer: 4,
    };
    let mut bytes = [0; 64];
    let n = wire::encode(metadata, header, &[], b"abc", &mut bytes).unwrap();
    let syn = wire::parse(metadata, &bytes[..n]).unwrap();
    let mut b = Connection::passive(reverse(tuple()), config(64, 8), 900, 0, &syn).unwrap();
    assert_eq!(b.readable_bytes(), 0);
    packet(&mut b, 10);
    inject(&mut b, 20, Seq(104), Seq(901), ACK, 64, b"");
    assert_eq!(b.readable_bytes(), 3);
    assert_eq!(b.read(&mut [0; 1]), Ok(1));
    assert_eq!(b.readable_bytes(), 2);
    b.abort();
    assert_eq!(b.readable_bytes(), 0);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
//= type=test
//# Consequently, if a keep-alive mechanism is implemented it MUST NOT interpret
//# failure to respond to any specific probe as a dead connection (MUST-29).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
//= type=test
//# Implementers MAY include "keep-alives" in their TCP implementations (MAY-5),
//# although this practice is not universally accepted.
fn syn_timeout_data_rto_user_timeout_and_keepalive() {
    let cfg = config(64, 8);
    let mut a = Connection::active(tuple(), cfg.clone(), 100, 0).unwrap();
    let _lost = packet(&mut a, 0);
    a.timeout(1_000_000).unwrap();
    let bytes = packet(&mut a, 1_000_000);
    let syn = wire::parse(ip(tuple()), &bytes).unwrap();
    let mut b = Connection::passive(reverse(tuple()), cfg, 200, 1_000_000, &syn).unwrap();
    deliver(&mut b, &mut a, 1_000_010);
    deliver(&mut a, &mut b, 1_000_020);
    a.write(b"data").unwrap();
    packet(&mut a, 1_000_030);
    assert!(a.rto_deadline.unwrap() >= 4_000_030);
    a.timeout(a.progress_at + a.config.user_timeout_us).unwrap();
    assert_eq!(a.close_reason(), Some(CloseReason::TimedOut));

    let mut cfg = config(64, 8);
    cfg.keepalive = Some(KeepaliveConfig {
        idle_us: 7_200_000_000,
        interval_us: 1_000_000,
        probes: 2,
        send_garbage: false,
    });
    let (mut a, mut b) = pair(cfg, 100);
    let deadline = a.keepalive_deadline.unwrap();
    a.timeout(deadline).unwrap();
    deliver(&mut a, &mut b, deadline);
    deliver(&mut b, &mut a, deadline);
    assert_eq!(a.keepalive_probes, 0);
    let deadline = a.keepalive_deadline.unwrap();
    a.timeout(deadline).unwrap();
    packet(&mut a, deadline);
    let deadline = a.keepalive_deadline.unwrap();
    a.timeout(deadline).unwrap();
    packet(&mut a, deadline);
    assert_eq!(a.state(), State::Established);
    a.timeout(a.keepalive_deadline.unwrap()).unwrap();
    assert_eq!(a.close_reason(), Some(CloseReason::TimedOut));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
//= type=test
//# The window size MUST be treated as an unsigned number, or else large window
//# sizes will appear like negative windows and TCP will not work (MUST-1).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
//= type=test
//# It is RECOMMENDED that implementations will reserve 32-bit fields for the send
//# and receive window sizes in the connection record and do all window computations
//# with 32 bits (REC- 1).
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.2
//= type=test
//= reason=SYN windows are learned raw and advertised_window returns raw syn_window; ordinary ACK scaling is separate.
//# The window field in a segment where the SYN bit is set (i.e., a <SYN>
//# or <SYN,ACK>) MUST NOT be scaled.
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.3
//= type=test
//= reason=Incoming non-SYN SEG.WND is expanded with fixed negotiated peer_scale; raw SYN values stay unscaled.
//# o  The window field (SEG.WND) in the header of every incoming
//# segment, with the exception of <SYN> segments, MUST be left-
//# shifted by Snd.Wind.Shift bits before updating SND.WND:
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.3
//= type=test
//= reason=snd_wnd and receive acceptance credit are 32-bit; internal/congestion bytes are not scaled header values.
//# The scale factor applies only to the window field as transmitted in
//# the TCP header; each TCP using extended windows will maintain the
//# window values locally as 32-bit numbers.
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.1
//= type=test
//= reason=Capacity-derived exponent is frozen after first successful SYN output; maximum negotiated true window bounded by receive allocation.
//# The maximum receive window, and therefore the scale factor, is
//# determined by the maximum receive buffer space.
fn window_scaling_is_negotiated_but_syn_windows_are_unscaled() {
    let (mut a, mut b) = pair(config(131072, 1460), 100);
    assert!(a.scaling && b.scaling);
    assert_eq!(a.local_scale, 2);
    assert_eq!(a.peer_scale, 2);
    assert_eq!(a.snd_wnd, 65535); // From SYN+ACK, never scaled.
    assert!(b.snd_wnd > 65535); // Final ACK is scaled.
    b.immediate_ack();
    deliver(&mut b, &mut a, 40);
    assert!(a.snd_wnd > 65535);
    assert!(a.snd_wnd <= 131072);
    assert!(b.receive_window() <= 131072);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.5
//= type=test
//# The TCP implementation MUST (MUST-33) provide a way for the application to learn
//# how much urgent data remains to be read from the connection, or at least to
//# determine whether more urgent data remains to be read [19].
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.5
//= type=test
//= reason=SYN data is buffered internally, not readable nor notified to application before handshake completes.
//# so long as the receiving TCP endpoint doesn't deliver the data to the user until it is
//# clear the data is valid (e.g., the data is buffered at the receiver until the connection
//# reaches the ESTABLISHED state, given that the three-way handshake reduces the
//# possibility of false connections).
fn syn_text_is_retained_but_not_readable_before_establishment() {
    let metadata = ip(tuple());
    let header = Header {
        source_port: 1000,
        destination_port: 2000,
        sequence: u32::MAX - 1,
        acknowledgment: 0,
        flags: SYN | URG | PSH,
        window: 64,
        urgent_pointer: 4,
    };
    let mut bytes = [0; 64];
    let size = wire::encode(metadata, header, &[], b"abc", &mut bytes).unwrap();
    let syn = wire::parse(metadata, &bytes[..size]).unwrap();
    let mut uncompleted =
        Connection::passive(reverse(tuple()), config(64, 8), 900, 0, &syn).unwrap();
    uncompleted.abort();
    assert_eq!(uncompleted.receive.readable(), 0);
    assert_eq!(uncompleted.terminal_readable_bytes(), 0);
    assert_eq!(uncompleted.peek_terminal(&mut [0; 8]), Ok(0));
    assert_eq!(uncompleted.read_terminal(&mut [0; 8]), Ok(0));
    assert_eq!(uncompleted.receive_used, 0);
    let mut b = Connection::passive(reverse(tuple()), config(64, 8), 900, 0, &syn).unwrap();
    assert_eq!(b.receive.next(), Seq(u32::MAX));
    assert!(!b.events_pending());
    assert_eq!(b.read(&mut [0; 8]), Err(Error::WouldBlock));
    assert_eq!(b.peek(&mut [0; 8]), Err(Error::WouldBlock));
    assert_eq!(b.urgent_remaining(), 0);
    let synack_bytes = packet(&mut b, 10);
    let synack = wire::parse(ip(reverse(tuple())), &synack_bytes).unwrap();
    assert_eq!(synack.header.acknowledgment, u32::MAX);
    assert_eq!(synack.header.window, 64);
    inject(&mut b, 20, Seq(2), Seq(901), ACK, 64, b"");
    let events = b.take_events();
    assert!(events.connected && events.readable);
    assert_eq!(events.urgent, Some(3));
    assert!(events.pushed);
    assert_eq!(b.urgent_remaining(), 3);
    let mut out = [0; 8];
    assert_eq!(b.read(&mut out[..1]), Ok(1));
    assert_eq!(b.urgent_remaining(), 2);
    assert_eq!(b.read(&mut out[1..]), Ok(2));
    assert_eq!(&out[..3], b"abc");
    assert_eq!(b.urgent_remaining(), 0);
}

#[test]
fn peek_does_not_release_credit_or_schedule_ack_and_respects_shutdown() {
    let (mut a, mut b) = pair(config(64, 8), 100);
    a.write(b"abc").unwrap();
    deliver(&mut a, &mut b, 40);
    let used = b.receive_used;
    let read = b.received_read;
    let edge = b.receive.right_edge();
    let ack = b.ack_pending;
    let mut out = [0; 8];
    for _ in 0..2 {
        assert_eq!(b.peek(&mut out), Ok(3));
        assert_eq!(&out[..3], b"abc");
        assert_eq!(b.receive_used, used);
        assert_eq!(b.received_read, read);
        assert_eq!(b.receive.right_edge(), edge);
        assert_eq!(b.ack_pending, ack);
    }
    assert_eq!(b.read(&mut out), Ok(3));
    b.read_closed = true;
    assert_eq!(b.peek(&mut out), Err(Error::InvalidState));
}

#[test]
fn terminal_drain_preserves_read_contract_and_excludes_out_of_order_data() {
    let (mut a, mut b) = pair(config(64, 8), 100);
    assert_eq!(b.read_terminal(&mut [0; 8]), Err(Error::InvalidState));
    a.write(b"abc").unwrap();
    deliver(&mut a, &mut b, 40);
    let next = b.receive.next();
    let ack = b.snd_nxt;
    inject(&mut b, 50, next.wrapping_add(4), ack, ACK, 64, b"ooo");
    assert_eq!(b.receive_used, 6);
    inject(&mut b, 60, next, ack, RST | ACK, 64, b"ignored");
    assert_eq!(b.state(), State::Closed);
    assert_eq!(b.readable_bytes(), 0);
    assert_eq!(b.read(&mut [0; 8]), Err(Error::InvalidState));
    assert_eq!(b.terminal_readable_bytes(), 3);
    let read_before = b.received_read;
    let mut out = [0; 8];
    for _ in 0..2 {
        assert_eq!(b.peek_terminal(&mut out), Ok(3));
        assert_eq!(&out[..3], b"abc");
        assert_eq!(b.receive_used, 6);
        assert_eq!(b.received_read, read_before);
        assert!(!b.ack_pending);
    }
    assert_eq!(b.read_terminal(&mut out[..1]), Ok(1));
    assert_eq!(&out[..1], b"a");
    assert_eq!(b.terminal_readable_bytes(), 2);
    assert_eq!(b.read_terminal(&mut out), Ok(2));
    assert_eq!(&out[..2], b"bc");
    assert_eq!(b.received_read, read_before + 3);
    assert_eq!(b.receive_used, 3);
    assert_eq!(b.read_terminal(&mut out), Ok(0));
    assert!(!b.ack_pending);
    assert!(b.transmit(70, &mut [0; 128]).unwrap().is_none());

    let (mut a, mut b) = pair(config(64, 8), 100);
    a.write(b"abc").unwrap();
    deliver(&mut a, &mut b, 40);
    b.close().unwrap(); // Explicitly discards the read side and aborts.
    assert_eq!(b.state(), State::Closed);
    assert_eq!(b.terminal_readable_bytes(), 0);
    assert_eq!(b.read_terminal(&mut out), Ok(0));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
//= type=test
//# A TCP receiver MUST process the RST and URG fields of all incoming segments,
//# even when the receive window is zero (MUST-66).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.5.3
//= type=test
//# TCP implementations SHOULD allow a received RST segment to include data
//# (SHLD-2).
fn zero_window_still_processes_reset_and_urgent_controls_with_text() {
    let (mut a, mut b) = pair(config(4, 4), 100);
    a.write(b"abcd").unwrap();
    deliver(&mut a, &mut b, 40);
    deliver(&mut b, &mut a, 50);
    assert_eq!(b.receive_window(), 0);
    let header = Header {
        source_port: 1000,
        destination_port: 2000,
        sequence: b.receive.next().0,
        acknowledgment: b.snd_nxt.0,
        flags: ACK | URG,
        window: 4,
        urgent_pointer: 1,
    };
    let mut bytes = [0; 64];
    let size = wire::encode(ip(tuple()), header, &[], b"x", &mut bytes).unwrap();
    b.input(60, &wire::parse(ip(tuple()), &bytes[..size]).unwrap())
        .unwrap();
    assert_eq!(b.receive.readable(), 4);
    assert_eq!(b.take_events().urgent, Some(5));
    assert_eq!(b.urgent_remaining(), 5);
    let next = b.receive.next();
    let ack = b.snd_nxt.wrapping_add(999);
    inject(&mut b, 70, next, ack, RST | ACK, 4, b"ignored");
    assert_eq!(b.close_reason(), Some(CloseReason::Reset));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.5
//= type=test
//= reason=Exercises a 70000-byte urgent run across sequence wrap, not every possible length.
//# A TCP implementation MUST support a sequence of urgent data of any length
//# (MUST-31) [19].
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.5
//= type=test
//# A TCP implementation MUST (MUST-32) inform the application layer asynchronously
//# whenever it receives an urgent pointer and there was previously no pending
//# urgent data, or whenever the urgent pointer advances in the data stream.
//= https://www.rfc-editor.org/rfc/rfc7323#appendix-A
//= type=test
//= reason=Appendix A suggestion implemented as saturating wire offset; retained full urgent endpoint lets later packets advance receiver urgent pointer without leaving urgent mode.
//# If it does overflow, than a value of 65535
//# should be inserted into the Urgent Pointer.
fn urgent_run_larger_than_pointer_keeps_urg_set_from_first_packet() {
    let (mut a, mut b) = pair(config(131072, 1460), u32::MAX - 100);
    assert_eq!(a.write_urgent(&vec![42; 70000]), Ok(70000));
    let bytes = deliver(&mut a, &mut b, 40);
    let first = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_ne!(first.header.flags & URG, 0);
    assert_eq!(first.header.urgent_pointer, 65535);
    assert_eq!(b.take_events().urgent, Some(65535));
    let bytes = deliver(&mut a, &mut b, 50);
    let second = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_ne!(second.header.flags & URG, 0);
    assert_eq!(b.take_events().urgent, Some(65535 + 1460));
    assert_eq!(b.urgent_remaining(), 65535 + 1460);
}

#[test]
fn configured_recovery_reaches_active_and_passive_connections() {
    assert_eq!(
        ConnectionConfig::default().recovery_algorithm,
        RecoveryAlgorithm::NewReno
    );
    for choice in [
        None,
        Some(RecoveryAlgorithm::Reno),
        Some(RecoveryAlgorithm::NewReno),
    ] {
        let mut cfg = config(64, 4);
        if let Some(algorithm) = choice {
            cfg.recovery_algorithm = algorithm;
        }
        let newreno = cfg.recovery_algorithm == RecoveryAlgorithm::NewReno;
        let (a, b) = pair(cfg, u32::MAX - 7);
        for mut sender in [a, b] {
            prime_newreno(&mut sender);
            sender.write(&[1; 16]).unwrap();
            for _ in 0..4 {
                packet(&mut sender, 40);
            }
            let seq = sender.receive.next();
            let una = sender.snd_una;
            for _ in 0..3 {
                inject(&mut sender, 41, seq, una, ACK, 64, b"");
            }
            assert!(sender.retx_pending);
            packet(&mut sender, 42);
            inject(&mut sender, 43, seq, una.wrapping_add(4), ACK, 64, b"");
            assert_eq!(sender.retx_pending, newreno);
            assert_eq!(sender.congestion.cwnd(), if newreno { 20 } else { 8 });
            if newreno {
                let bytes = packet(&mut sender, 44);
                let segment = wire::parse(ip(sender.tuple()), &bytes).unwrap();
                assert_eq!(segment.header.sequence, una.wrapping_add(4).0);
            }
            inject(&mut sender, 45, seq, una.wrapping_add(16), ACK, 64, b"");
            assert!(!sender.retx_pending);
            assert_eq!(sender.flight(), 0);
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.4
//= type=test
//= reason=Repeated shutdown is idempotent and never creates a second FIN.
//# An "ok" response would be acceptable, too, as long as a second FIN is not emitted (the
//# first FIN may be retransmitted, though).
//= https://www.rfc-editor.org/rfc/rfc6582#section-5
//= type=test
//= reason=newreno_partial_ack_wire_timer_and_exit_boundaries asserts immediate ACK pending and no delayed deadline for OOO pure data and hole-fill partial ACKs, with other pure-data holes still outstanding.
//# [RFC5681] specifies that "Out-of-order data segments SHOULD be acknowledged
//# immediately, in order to accelerate loss recovery".
// Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Ordinary end-to-end single-loss fast retransmit after cumulative progress beyond initial ISS.
//= https://www.rfc-editor.org/rfc/rfc6582#section-3.1
//= type=test
//= reason=No-SACK NewReno wire entry, partial-ACK continuation, full-ACK exit and active-recovery RTO exit are asserted by newreno_partial_ack_wire_timer_and_exit_boundaries. timeout_marker_boundaries_and_wrap asserts timeout marker replacement; initial guard and strict admission are asserted by newreno_initial_boundary_and_loss_epoch_are_distinct.
//# The NewReno modification applies to the fast recovery procedure that begins when three
//# duplicate ACKs are received and ends when either a retransmission timeout occurs or an
//# ACK arrives that acknowledges all of the data up to and including the data that was
//# outstanding when the fast recovery procedure began.
//= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
//= type=test
//= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Ordinary end-to-end single-loss fast retransmit after cumulative progress beyond initial ISS.
//# The procedures specified in Section 3.2 of [RFC5681] are followed, with the
//# modifications listed below.
//= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
//= type=test
//= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Ordinary end-to-end single-loss fast retransmit after cumulative progress beyond initial ISS.
//# When the TCP protocol control block is initialized, recover is set to the initial send
//# sequence number.
//= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
//= type=test
//= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Ordinary end-to-end single-loss fast retransmit after cumulative progress beyond initial ISS.
//# This document also does not address issues of adjusting the duplicate acknowledgment
//# threshold, but assumes the threshold specified in the IETF standards; the current
//# standard is [RFC5681], which specifies a threshold of three duplicate acknowledgments.
//= https://www.rfc-editor.org/rfc/rfc6582#section-5
//= type=test
//= reason=newreno_partial_ack_wire_timer_and_exit_boundaries receives pure-data hole fills while another hole remains, asserts ack_pending and ack_deadline=None despite delayed ACK enabled, and immediately emits cumulative partial ACKs.
//# Echoing [RFC5681], our recommendation is that the data receiver send an immediate
//# acknowledgment for an out-of-order segment, even when that out-of-order segment fills
//# a hole in the buffer.
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
//= type=test
//= reason=Non-SACK Reno/NewReno fallback uses three eligible duplicate ACKs without RTO backoff; wire trace asserts retransmission of SND.UNA payload. Negotiated SACK/RACK loss inference is separately RFC6675/8985, not this fallback test.
//# The TCP sender SHOULD use the "fast retransmit" algorithm to detect and repair loss,
//# based on incoming duplicate ACKs.
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
//= type=test
//= reason=Non-SACK Reno/NewReno fast entry: helper asserts cwnd=ssthresh+3SMSS (7000=4000+3000); wire test asserts SND.UNA retransmission. Negotiated SACK/RACK/PRR instead follow section4.3 modified recovery and do not use Reno inflation.
//# The lost segment starting at SND.UNA MUST be retransmitted and cwnd set to ssthresh plus
//# 3*SMSS.
fn fast_retransmit_uses_three_duplicate_acks_and_fin_shutdown_is_idempotent() {
    let (mut a, mut b) = primed_pair(config(64, 4), 100);
    a.write(b"abcdefghijklmnop").unwrap();
    let _lost = packet(&mut a, 40);
    for now in [50, 60, 70] {
        deliver(&mut a, &mut b, now);
        deliver(&mut b, &mut a, now);
    }
    assert!(a.retx_pending);
    assert_eq!(a.rtt.rto(), 1_000_000); // Fast retransmit does not back off.
    let bytes = deliver(&mut a, &mut b, 80);
    let retransmit = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(retransmit.payload, b"abcd");
    assert_eq!(retransmit.header.sequence, 102);
    deliver(&mut b, &mut a, 90);
    assert_eq!(a.acknowledged(), 17);
    assert!(!a.retx_pending);
    a.shutdown().unwrap();
    a.shutdown().unwrap();
    deliver(&mut a, &mut b, 100);
    a.shutdown().unwrap();
    deliver(&mut b, &mut a, 110);
    a.shutdown().unwrap();
    b.shutdown().unwrap();
    deliver(&mut b, &mut a, 120);
    b.shutdown().unwrap();
    a.shutdown().unwrap();
    deliver(&mut a, &mut b, 130);
    b.shutdown().unwrap();
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
//= type=test
//# In particular, R2 for a SYN segment MUST be set large enough to provide
//# retransmission of the segment for at least 3 minutes (MUST-23).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
//= type=test
//# (d) An application MUST (MUST-21) be able to set the value for R2 for a
//# particular connection.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
//= type=test
//# The value of R1 SHOULD correspond to at least 3 retransmissions, at the current
//# RTO (SHLD-10).
fn handshake_minimum_timeout_warning_and_fresh_app_clock() {
    let mut cfg = config(64, 8);
    cfg.user_timeout_us = 1_000;
    let mut a = Connection::active(tuple(), cfg, 100, 0).unwrap();
    assert_eq!(a.user_deadline(), Some(180_000_000));
    packet(&mut a, 0);
    for attempt in 0..3 {
        let deadline = a.rto_deadline.unwrap();
        a.timeout(deadline).unwrap();
        assert_eq!(a.take_events().retransmission_warning, attempt == 2);
        assert_eq!(a.take_route_advice(), attempt == 2);
        assert!(!a.take_route_advice());
        packet(&mut a, deadline);
    }
    a.timeout(179_999_999).unwrap();
    assert_eq!(a.state(), State::SynSent);
    a.timeout(180_000_000).unwrap();
    assert_eq!(a.close_reason(), Some(CloseReason::TimedOut));
    let (mut a, _) = pair(config(64, 8), 100);
    a.set_user_timeout(10_000).unwrap();
    assert_eq!(a.set_user_timeout(0), Err(Error::InvalidArgument));
    a.update_time(10_000_000).unwrap();
    a.write(b"new").unwrap();
    assert_eq!(a.user_deadline(), Some(10_010_000));
    assert_eq!(a.update_time(9_999_999), Err(Error::TimeWentBackwards));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
//= type=test
//# Source Quench
//# TCP implementations MUST silently discard any received ICMP Source
//# Quench messages (MUST-55).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
//= type=test
//= reason=The soft-error event is observable and the connection remains Established; outer ICMP validation belongs to the adapter.
//# Since these Unreachable messages indicate soft error conditions, a
//# TCP implementation MUST NOT abort the connection (MUST-56), and it
//# SHOULD make the information available to the application (SHLD-25).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
//= type=test
//# These are hard error conditions, so TCP implementations SHOULD abort the
//# connection (SHLD-26).
//= https://www.rfc-editor.org/rfc/rfc5927#section-5.2
//= type=test
//= reason=Selected connection-local policy: network_error mutates only the matched Connection and PMTU feedback has no cross-connection cache. The existing validation test checks live-sequence rejection and error processing on that instance.
//# Additionally, they do not extrapolate ICMP errors across TCP connections. This
//# policy is based on the premise that TCP should be as robust as possible. Aborting
//# the connection would be to ignore the valuable feature of the Internet -- that for
//# many internal failures, it reconstructs its function without any disruption of the
//# endpoints [RFC0816].

fn network_errors_validate_quote_and_mss_reduction_repacketizes() {
    let (mut a, mut b) = pair(config(64, 8), 100);
    a.write(b"abcdefgh").unwrap();
    let original = packet(&mut a, 40);
    assert_eq!(
        a.network_error(50, 100, NetworkError::HardUnreachable),
        Ok(false)
    );
    assert_eq!(
        a.network_error(50, 109, NetworkError::HardUnreachable),
        Ok(false)
    );
    assert_eq!(
        a.network_error(50, 101, NetworkError::SourceQuench),
        Ok(false)
    );
    assert!(!a.events_pending());
    assert_eq!(
        a.network_error(60, 101, NetworkError::SoftUnreachable),
        Ok(true)
    );
    assert_eq!(
        a.take_events().network_error,
        Some(NetworkError::SoftUnreachable)
    );
    assert_eq!(a.state(), State::Established);
    assert_eq!(
        a.network_error(70, 108, NetworkError::TimeExceeded),
        Ok(true)
    );
    assert_eq!(
        a.take_events().network_error,
        Some(NetworkError::TimeExceeded)
    );
    assert_eq!(a.lower_mss(0), Err(Error::InvalidArgument));
    assert_eq!(a.lower_mss(9), Err(Error::InvalidArgument));
    let storage = (a.scratch.as_ptr(), a.scratch.capacity());
    let high = a.snd_nxt;
    a.lower_mss(3).unwrap();
    assert!(a.retx_pending);
    assert_eq!((a.scratch.as_ptr(), a.scratch.capacity()), storage);
    let bytes = packet(&mut a, 80);
    let segment = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(segment.payload, b"abc");
    assert_eq!(a.snd_nxt, high);
    assert!(a.sample.is_none());
    assert_eq!(
        a.network_error(90, 101, NetworkError::ParameterProblem),
        Ok(true)
    );
    assert_eq!(a.close_reason(), None);
    assert_eq!(
        a.take_events().network_error,
        Some(NetworkError::ParameterProblem)
    );
    b.input(100, &wire::parse(ip(tuple()), &original).unwrap())
        .unwrap();
    b.timeout(200_100).unwrap();
    deliver(&mut b, &mut a, 200_100);
    assert_eq!(a.acknowledged(), 8);
    assert_eq!(a.state(), State::Established);
    let mut data = [0; 8];
    assert_eq!(b.read(&mut data), Ok(8));
    assert_eq!(&data, b"abcdefgh");
    a.write(b"new").unwrap();
    deliver(&mut a, &mut b, 200_110);
    assert_eq!(
        a.network_error(200_120, 109, NetworkError::HardUnreachable),
        Ok(true)
    );
    assert_eq!(a.close_reason(), Some(CloseReason::NetworkError));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.1
//= type=test
//# If an MSS Option is not received at connection setup, TCP implementations MUST
//# assume a default send MSS of 536 (576 - 40) for IPv4 or 1220 (1280 - 60) for
//# IPv6 (MUST-15).
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.2
//= type=test
//= reason=Active always offers WS; passive enables only after peer offer. Missing peer WS disables effective shifts in both directions, not necessarily the stored capacity-derived exponent.
//# This option is an offer, not a promise; both sides MUST send Window
//# Scale options in their <SYN> segments to enable window scaling in
//# either direction.
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.3
//= type=test
//= reason=Effective incoming/outgoing shifts use negotiated scaling; absent peer WS means zero effective shifts even though local_scale retains its configured value.
//# o  Upon receiving a <SYN> segment with a Window Scale option
//# containing shift.cnt = S, a TCP MUST set Snd.Wind.Shift to S and
//# MUST set Rcv.Wind.Shift to R; otherwise, it MUST set both
//# Snd.Wind.Shift and Rcv.Wind.Shift to zero.
fn invalid_configuration_and_unscaled_peer_defaults() {
    assert!(Connection::active(tuple(), config(64, 65495), 100, 0).is_ok());
    assert!(matches!(
        Connection::active(tuple(), config(64, 65496), 100, 0),
        Err(Error::InvalidArgument)
    ));
    let mut cfg = config(64, 8);
    cfg.delayed_ack_us = 500_000;
    assert!(matches!(
        Connection::active(tuple(), cfg, 100, 0),
        Err(Error::InvalidArgument)
    ));
    let header = Header {
        source_port: 1000,
        destination_port: 2000,
        sequence: 100,
        acknowledgment: 0,
        flags: SYN,
        window: 65535,
        urgent_pointer: 0,
    };
    let syn = Segment {
        header,
        options: wire::Options::default(),
        raw_options: &[],
        payload: &[],
    };
    let mut b =
        Connection::passive(reverse(tuple()), ConnectionConfig::default(), 900, 0, &syn).unwrap();
    assert_eq!(b.mss, 536);
    assert!(!b.scaling);
    let bytes = packet(&mut b, 10);
    assert_eq!(
        wire::parse(ip(reverse(tuple())), &bytes)
            .unwrap()
            .options
            .window_scale,
        None
    );
    let v6_tuple = Tuple {
        local: "[2001:db8::1]:1000".parse().unwrap(),
        remote: "[2001:db8::2]:2000".parse().unwrap(),
    };
    let b = Connection::passive(v6_tuple, ConnectionConfig::default(), 900, 0, &syn).unwrap();
    assert_eq!(b.mss, 1220);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
//= type=test
//# A TCP receiver SHOULD NOT shrink the window, i.e., move the right
//# window edge to the left (SHLD-14).
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.3
//= type=test
//= reason=Ordinary outgoing receive window divides by scale unit (floor), SYN is raw; backing and encoded edge tested through sub-scale advances.
//# o  The window field (SEG.WND) of every outgoing segment, with the
//# exception of <SYN> segments, MUST be right-shifted by
//# Rcv.Wind.Shift bits:
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.4
//= type=test
//= reason=Previously committed receive promises remain valid across scaled rounding and wrap. Capacity-backed presence bits accept arbitrary fragmentation without an interval-count limit; tests combine delayed promised bytes, batching and complete retained delivery.
//# 1)  The receiver MUST honor, as in window, any segment that would
//# have been in window for any <ACK> sent by the receiver.
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.4
//= type=test
//= reason=Tracks maximum successful advertised edge independently of current quantized field; not advanced on failed output.
//# 2)  When window scaling is in effect, the receiver SHOULD track the
//# actual maximum window sequence number (which is likely to be
//# greater than the window announced by the most recent <ACK>, if
//# more than one segment has arrived since the application consumed
//# any data in the receive buffer).
//= https://www.rfc-editor.org/rfc/rfc7323#section-7
//= type=test
//= reason=Receive window bounded by explicit configured receive allocation, never rounds beyond backing; no speculative unlimited window growth.
//# Hence, implementers should take care to not open the TCP window
//# drastically beyond the requirements of the connection.
fn scaled_window_rounding_never_overruns_storage_or_revokes_old_credit() {
    let (mut a, mut b) = pair(config(65536, 1460), 100);
    let backing = b.receive.right_edge();
    for step in 0..32 {
        let now = 40 + step * 10;
        a.write(b"x").unwrap();
        deliver(&mut a, &mut b, now);
        b.immediate_ack();
        let promised = b.advertised_edge;
        let bytes = deliver(&mut b, &mut a, now);
        let ack = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
        let edge = Seq(ack.header.acknowledgment)
            .wrapping_add((ack.header.window as u32) << b.local_scale);
        assert!(backing.at_or_after(edge));
        assert!(backing.at_or_after(b.advertised_edge));
        assert!(b.advertised_edge.at_or_after(promised));
    }
    assert_eq!(b.read(&mut [0; 32]), Ok(32));
}

#[test]
fn read_credit_unscaled_wire_cap_does_not_schedule_redundant_ack() {
    let cfg = ConnectionConfig {
        delayed_ack_us: 0,
        ..config(8 * 1024 * 1024, 1460)
    };
    // Peer offers MSS=1000 but no WS, as in ioctl-siocinq-fin.pkt.
    let mut bytes = [0; 64];
    let n = wire::encode(
        ip(tuple()),
        Header {
            source_port: 1000,
            destination_port: 2000,
            sequence: 0,
            acknowledgment: 0,
            flags: SYN,
            window: 20000,
            urgent_pointer: 0,
        },
        &[2, 4, 3, 232],
        b"",
        &mut bytes,
    )
    .unwrap();
    let syn = wire::parse(ip(tuple()), &bytes[..n]).unwrap();
    let mut b = Connection::passive(reverse(tuple()), cfg, 900, 0, &syn).unwrap();
    packet(&mut b, 10);
    let ack = b.snd_nxt;
    inject(&mut b, 20, Seq(1), ack, ACK, 20000, b"");
    assert!(!b.scaling);
    assert_eq!(b.window_threshold(), 1000);
    for (time, count, window) in [
        (30, 500, u16::MAX - 500), // Capped credit below MSS stays withheld.
        (40, 500, u16::MAX),
        (50, 1000, u16::MAX),
        (60, 2000, u16::MAX),
    ] {
        let next = b.receive.next();
        inject(&mut b, time, next, ack, ACK, 20000, &vec![1; count]);
        let bytes = packet(&mut b, time);
        let segment = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
        assert_eq!(segment.header.window, window);
        let promised = b.advertised_edge;
        assert_eq!(b.read(&mut vec![0; count]), Ok(count));
        assert_eq!(b.advertised_window(false), window);
        assert_eq!(b.advertised_edge, promised);
        assert!(!b.ack_pending);
        assert_eq!(b.transmit(time + 1, &mut [0; 64]), Ok(None));
    }
    let next = b.receive.next();
    inject(&mut b, 70, next, ack, ACK | FIN, 20000, b"");
    let bytes = packet(&mut b, 70);
    let segment = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
    assert_eq!(segment.header.acknowledgment, next.wrapping_add(1).0);
}

#[test]
fn read_credit_scaled_waits_for_encodable_sws_credit() {
    for mss in [1000, 1460] {
        let cfg = ConnectionConfig {
            delayed_ack_us: 0,
            // Exercise the eager opt-out's encodable one-MSS boundary.
            coalesce_read_window_updates: false,
            ..config(8 * 1024 * 1024, mss)
        };
        let (_, mut b) = pair(cfg, u32::MAX - 2048);
        assert_eq!(b.local_scale, 8);
        let next = b.receive.next();
        let ack = b.snd_una;
        let count = if mss == 1000 { 1000 } else { 2048 };
        inject(&mut b, 40, next, ack, ACK, 20000, &vec![1; count]);
        packet(&mut b, 40);
        let promised = b.advertised_edge;
        assert_eq!(b.read(&mut [0; 1000]), Ok(1000));
        if mss == 1460 {
            assert!(!b.ack_pending);
            assert_eq!(b.transmit(41, &mut [0; 64]), Ok(None));
            // Raw freed credit meets MSS, but floor(1460 / 256) does not.
            assert_eq!(b.read(&mut [0; 460]), Ok(460));
            assert!(!b.ack_pending);
            assert_eq!(b.transmit(42, &mut [0; 64]), Ok(None));
            assert_eq!(b.read(&mut [0; 76]), Ok(76));
        }
        // The eager opt-out sends the first encodable one-MSS update.
        assert!(b.ack_pending);
        let bytes = packet(&mut b, 43);
        let segment = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
        let encoded_edge = Seq(segment.header.acknowledgment)
            .wrapping_add(u32::from(segment.header.window) << b.local_scale);
        let credit = if mss == 1000 { 1024 } else { 1536 };
        assert_eq!(encoded_edge.distance_from(promised), credit);
        assert_eq!(b.advertised_edge, encoded_edge);
        assert!(b.receive.right_edge().at_or_after(encoded_edge));
        assert_eq!(b.transmit(44, &mut [0; 64]), Ok(None));
    }
}

#[test]
fn coalesced_read_credit_is_bounded_and_commits_only_on_output() {
    assert!(ConnectionConfig::default().coalesce_read_window_updates);
    for (capacity, mss) in [
        (64, 8),
        (65536, 1460),
        (8 * 1024 * 1024, 1000),
        (8 * 1024 * 1024, 1460),
    ] {
        for iss in [100, u32::MAX - 32] {
            let cfg = ConnectionConfig {
                delayed_ack_us: 0,
                coalesce_read_window_updates: true,
                ..config(capacity, mss)
            };
            let (_, mut b) = pair(cfg, iss);
            b.immediate_ack();
            packet(&mut b, 40);
            let ack = b.snd_una;
            let count = usize::from(mss);
            let mut remaining = capacity * 3 / 4;
            while remaining != 0 {
                let received = remaining.min(32768);
                let next = b.receive.next();
                inject(&mut b, 41, next, ack, ACK, 20000, &vec![1; received]);
                packet(&mut b, 41);
                remaining -= received;
            }
            let promised = b.advertised_edge;
            let old = b.receive_window();
            assert_eq!(old as usize, capacity / 4);
            let unit = 1usize << b.local_scale;
            let below = old as usize - unit;
            assert!(below >= count);
            assert_eq!(b.read(&mut vec![0; below]), Ok(below));
            assert!(!b.ack_pending);
            assert_eq!(b.transmit(42, &mut [0; 64]), Ok(None));
            assert_eq!(b.advertised_edge, promised);
            assert_eq!(b.read(&mut vec![0; unit]), Ok(unit));
            assert!(b.ack_pending);
            assert_eq!(b.transmit(43, &mut [0; 19]), Err(Error::OutputTooSmall));
            assert!(b.ack_pending);
            assert_eq!(b.advertised_edge, promised);
            let bytes = packet(&mut b, 44);
            let segment = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
            let edge = Seq(segment.header.acknowledgment)
                .wrapping_add(u32::from(segment.header.window) << b.local_scale);
            assert_eq!(u32::from(segment.header.window) << b.local_scale, 2 * old);
            assert_eq!(edge.distance_from(promised), old);
            assert_eq!(b.advertised_edge, edge);
            assert!(b.receive.right_edge().at_or_after(edge));
            assert_eq!(b.transmit(45, &mut [0; 64]), Ok(None));

            // Continued incoming traffic carries one-MSS read credit on
            // its ordinary ACK, without waiting for window doubling.
            let next = b.receive.next();
            inject(&mut b, 46, next, ack, ACK, 20000, &vec![1; count]);
            packet(&mut b, 46);
            let promised = b.advertised_edge;
            assert_eq!(b.read(&mut vec![0; count]), Ok(count));
            assert!(!b.ack_pending);
            let next = b.receive.next();
            inject(&mut b, 47, next, ack, ACK, 20000, &vec![2; count]);
            assert!(b.ack_pending);
            packet(&mut b, 47);
            assert!(b.advertised_edge.after(promised));
            assert!(b.receive.right_edge().at_or_after(b.advertised_edge));
            assert_eq!(b.read(&mut vec![0; count]), Ok(count));
        }
    }
}

#[test]
fn coalesced_reads_preserve_ack_triggers_and_suppress_eof_updates() {
    for iss in [100, u32::MAX - 32] {
        for trigger in [0, 1, 2, 3] {
            let (_, mut b) = pair(config(64, 8), iss);
            let next = b.receive.next();
            let ack = b.snd_una;
            inject(&mut b, 40, next, ack, ACK, 20000, &[1; 8]);
            let deadline = b.ack_deadline.unwrap();
            if trigger == 1 {
                b.immediate_ack();
            } else if trigger == 2 {
                b.write(b"reply").unwrap();
            } else if trigger == 3 {
                let next = b.receive.next();
                inject(&mut b, 41, next, ack, ACK | FIN, 20000, b"");
                assert!(b.receive.eof());
            }
            let pending = b.ack_pending;
            let scheduled = b.ack_deadline;
            assert_eq!(b.read(&mut [0; 8]), Ok(8));
            assert_eq!(b.ack_pending, pending);
            assert_eq!(b.ack_deadline, scheduled);
            let now = if trigger == 0 {
                assert_eq!(b.transmit(42, &mut [0; 64]), Ok(None));
                b.timeout(deadline).unwrap();
                deadline
            } else {
                42
            };
            let bytes = packet(&mut b, now);
            let segment = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
            assert_eq!(segment.header.flags & ACK, ACK);
            assert_eq!(segment.header.acknowledgment, b.receive.next().0);
            assert_eq!(segment.header.window, if trigger == 3 { 0 } else { 64 });
            assert_eq!(
                segment.payload,
                if trigger == 2 { &b"reply"[..] } else { b"" }
            );
            assert_eq!(b.transmit(now + 1, &mut [0; 64]), Ok(None));
            if trigger == 3 {
                assert_eq!(b.read(&mut [0; 8]), Ok(0));
                assert_eq!(b.transmit(now + 2, &mut [0; 64]), Ok(None));
            }
        }
        // A FIN ACK already sent must not be recreated by draining text.
        let (_, mut b) = pair(config(64, 8), iss);
        let next = b.receive.next();
        let ack = b.snd_una;
        inject(&mut b, 40, next, ack, ACK | FIN, 20000, &[1; 48]);
        packet(&mut b, 40);
        assert_eq!(b.read(&mut [0; 48]), Ok(48));
        assert_eq!(b.transmit(41, &mut [0; 64]), Ok(None));
    }
}

#[test]
fn coalesced_read_credit_unscaled_large_mss_buffer_drain() {
    for iss in [100, u32::MAX - 32] {
        for coalesce in [false, true] {
            let cfg = ConnectionConfig {
                delayed_ack_us: 0,
                coalesce_read_window_updates: coalesce,
                ..config(262144, 40000)
            };
            // Real peer SYN offers a large MSS but no Window Scale.
            let mut bytes = [0; 64];
            let n = wire::encode(
                ip(tuple()),
                Header {
                    source_port: 1000,
                    destination_port: 2000,
                    sequence: iss,
                    acknowledgment: 0,
                    flags: SYN,
                    window: u16::MAX,
                    urgent_pointer: 0,
                },
                &[2, 4, 156, 64], // MSS = 40000.
                b"",
                &mut bytes,
            )
            .unwrap();
            let syn = wire::parse(ip(tuple()), &bytes[..n]).unwrap();
            let mut b = Connection::passive(reverse(tuple()), cfg, 900, 0, &syn).unwrap();
            let bytes = packet(&mut b, 10);
            let synack = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
            assert_eq!(synack.options.window_scale, None);
            assert_eq!(synack.header.window, u16::MAX);
            let ack = b.snd_nxt;
            inject(
                &mut b,
                20,
                Seq(iss).wrapping_add(1),
                ack,
                ACK,
                u16::MAX,
                b"",
            );
            assert_eq!(b.state(), State::Established);
            assert!(!b.scaling);
            assert_eq!(b.window_threshold(), 40000);
            for step in 0..5 {
                let next = b.receive.next();
                inject(&mut b, 30 + step, next, ack, ACK, u16::MAX, &vec![1; 40000]);
                let bytes = packet(&mut b, 30 + step);
                let segment = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
                assert_eq!(segment.header.acknowledgment, next.wrapping_add(40000).0);
                assert_eq!(
                    segment.header.window,
                    if step < 4 { u16::MAX } else { 25535 }
                );
            }
            assert_eq!(b.receive_window(), 25535);
            let promised = b.advertised_edge;
            let mut drained = vec![0; 200000];
            assert_eq!(b.read(&mut drained), Ok(200000));
            assert!(drained.iter().all(|&byte| byte == 1));
            assert_eq!(b.receive_used, 0);
            assert_eq!(b.advertised_window(false), u16::MAX);
            // Only 40000 bytes of new credit fit on the wire, even after
            // draining all 200000 bytes from the larger backing buffer.
            assert!(b.ack_pending);
            assert_eq!(
                b.read_window_threshold(),
                if coalesce { 25535 } else { 40000 }
            );
            assert_eq!(b.advertised_edge, promised);
            assert_eq!(b.transmit(40, &mut [0; 19]), Err(Error::OutputTooSmall));
            assert_eq!(b.advertised_edge, promised);
            let bytes = packet(&mut b, 41);
            let segment = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
            assert_eq!(segment.header.flags, ACK);
            assert_eq!(segment.header.window, u16::MAX);
            assert!(segment.payload.is_empty());
            assert_eq!(b.advertised_edge.distance_from(promised), 40000);
            assert!(b.receive.right_edge().at_or_after(b.advertised_edge));
            assert_eq!(b.transmit(42, &mut [0; 64]), Ok(None));
        }
    }
}

#[test]
fn coalesced_read_credit_reopens_scaled_zero_with_retained_promise() {
    let cfg = ConnectionConfig {
        delayed_ack_us: 0,
        coalesce_read_window_updates: true,
        ..config(65536, 1460)
    };
    let (_, mut b) = pair(cfg, u32::MAX - 32);
    b.immediate_ack();
    packet(&mut b, 40);
    let ack = b.snd_una;
    for count in [32768, 32767] {
        let next = b.receive.next();
        inject(&mut b, 41, next, ack, ACK, 20000, &vec![1; count]);
        packet(&mut b, 41);
    }
    assert_eq!(b.receive_window(), 1); // Retained acceptance promise.
    assert_eq!(b.advertised_window(false), 0); // Sender is stalled.
    let promised = b.advertised_edge;
    let count = usize::from(b.config.mss) + (1 << b.local_scale);
    assert_eq!(b.read(&mut vec![0; count]), Ok(count));
    assert_eq!(b.read_window_threshold(), b.window_threshold());
    assert!(b.ack_pending);
    assert_eq!(b.transmit(42, &mut [0; 19]), Err(Error::OutputTooSmall));
    assert_eq!(b.advertised_edge, promised);
    // The sender may still deliver the last byte promised before the
    // scaled zero advertisement, even while reopening output has failed.
    let next = b.receive.next();
    inject(&mut b, 43, next, ack, ACK, 20000, b"x");
    assert_eq!(b.receive.next(), next.wrapping_add(1));
    assert_eq!(b.advertised_edge, promised);
    let bytes = packet(&mut b, 43);
    let segment = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
    assert_ne!(segment.header.window, 0);
    assert!(b.advertised_edge.after(promised));
    assert!(b.receive.right_edge().at_or_after(b.advertised_edge));
}

#[test]
fn coalesced_read_credit_small_capacity_and_validation() {
    for capacity in [1, 2, 3, 16, 64] {
        let cfg = ConnectionConfig {
            coalesce_read_window_updates: true,
            ..config(capacity, 32)
        };
        let (_, mut b) = pair(cfg, u32::MAX);
        let threshold = (capacity / 2).max(1);
        assert_eq!(b.read_window_threshold(), capacity as u32);
        let next = b.receive.next();
        let ack = b.snd_una;
        inject(&mut b, 40, next, ack, ACK, 20000, &vec![1; capacity]);
        packet(&mut b, 40);
        assert_eq!(b.receive_window(), 0);
        assert_eq!(b.read(&mut vec![0; threshold]), Ok(threshold));
        assert!(b.ack_pending);
        packet(&mut b, 41);
        assert_eq!(b.receive_window(), threshold as u32);
    }
    for (capacity, mss) in [(0, 8), ((65535usize << 14) + 1, 8), (64, 0), (64, 65496)] {
        let cfg = ConnectionConfig {
            coalesce_read_window_updates: true,
            ..config(capacity, mss)
        };
        assert!(matches!(
            Connection::active(tuple(), cfg, 100, 0),
            Err(Error::InvalidArgument)
        ));
    }
    // Credit comparison avoids multiplying even the largest retained
    // window. Negotiated scaling only affects the reopening exception.
    let (_, mut b) = pair(config(64, 8), 100);
    b.config.coalesce_read_window_updates = true;
    b.config.receive_capacity = 65535usize << 14;
    b.local_scale = 14;
    b.advertised_edge = b.receive.next().wrapping_add(65535 << 14);
    b.mss = 65495;
    assert_eq!(b.read_window_threshold(), 65535 << 14);
    b.scaling = false;
    assert_eq!(b.read_window_threshold(), 65535 << 14);
}

#[test]
fn read_credit_reopens_zero_window_at_sws_threshold() {
    for (capacity, mss, coalesce) in [
        (64, 32, false),
        (65536, 1460, false),
        (64, 32, true),
        (65536, 1460, true),
    ] {
        let cfg = ConnectionConfig {
            delayed_ack_us: 0,
            coalesce_read_window_updates: coalesce,
            ..config(capacity, mss)
        };
        let (_, mut b) = pair(cfg, u32::MAX - 32);
        b.immediate_ack();
        packet(&mut b, 40); // Advertise full scaled credit after SYN.
        let ack = b.snd_una;
        let mut remaining = capacity;
        while remaining != 0 {
            let count = remaining.min(32768);
            let next = b.receive.next();
            inject(&mut b, 41, next, ack, ACK, 20000, &vec![1; count]);
            packet(&mut b, 41);
            remaining -= count;
        }
        assert_eq!(b.receive_window(), 0);
        assert_eq!(b.advertised_window(false), 0);
        let promised = b.advertised_edge;
        let threshold = b.window_threshold() as usize;
        assert_eq!(b.read(&mut vec![0; threshold - 1]), Ok(threshold - 1));
        assert!(!b.ack_pending);
        assert_eq!(b.advertised_window(false), 0);
        assert_eq!(b.transmit(42, &mut [0; 64]), Ok(None));
        assert_eq!(b.read(&mut [0; 1]), Ok(1));
        assert!(b.ack_pending);
        assert_eq!(b.transmit(43, &mut [0; 19]), Err(Error::OutputTooSmall));
        assert_eq!(b.receive_window(), 0);
        assert_eq!(b.advertised_edge, promised);
        assert!(b.ack_pending);
        let bytes = packet(&mut b, 43);
        let segment = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
        assert_eq!(
            u32::from(segment.header.window) << b.local_scale,
            threshold as u32
        );
        assert_eq!(b.advertised_edge.distance_from(promised), threshold as u32);
        assert_eq!(b.transmit(44, &mut [0; 64]), Ok(None));
    }
}

#[test]
fn eof_reads_do_not_generate_an_unbounded_ack_stream() {
    let (mut a, mut b) = pair(config(64, 8), 100);
    b.shutdown().unwrap();
    deliver(&mut b, &mut a, 40);
    deliver(&mut a, &mut b, 50);
    for now in 60..100 {
        assert_eq!(a.read(&mut [0; 8]), Ok(0));
        assert_eq!(a.transmit(now, &mut [0; 64]), Ok(None));
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
//= type=test
//= reason=Non-SACK Limited Transmit: each of first two duplicate ACKs yields one unsent SMSS; output then stops, total extra flight is two MSS, and third ACK threshold excludes those bytes. SACK fresh-evidence gating is tested separately; not a PRR output claim.
//# On the first and second duplicate ACKs received at a sender, a TCP SHOULD send a segment
//# of previously unsent data per [RFC3042] provided that the receiver's advertised window
//# allows, the total FlightSize would remain less than or equal to cwnd plus 2*SMSS, and
//# that new data is available for transmission.
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
//= type=test
//= reason=Non-SACK third DupACK threshold uses flight minus limited_sent; wire assertion flight=24, limited=8, ssthresh=8 at MSS4. Negotiated SACK partial advancing ACK trace additionally retains unacknowledged Limited Transmit exclusion. ECN reduction epoch sharing is separately scoped.
//# When the third duplicate ACK is received, a TCP MUST set ssthresh to no more than the
//# value given in equation (4).
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
//= type=test
//= reason=Non-SACK third DupACK threshold uses flight minus limited_sent; wire assertion flight=24, limited=8, ssthresh=8 at MSS4. Negotiated SACK partial advancing ACK trace additionally retains unacknowledged Limited Transmit exclusion. ECN reduction epoch sharing is separately scoped.
//# When [RFC3042] is in use, additional data sent in limited transmit MUST NOT be included
//# in this calculation.
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
//= type=test
//= reason=Explicit before-ACK/after-ACK/after-output cwnd invariance for first two ordinary duplicates; sack_limited_transmit_requires_new_evidence_including_duplex_ack asserts SACK invariance and evidence gating separately.
//# Further, the TCP sender MUST NOT change cwnd to reflect these two segments [RFC3042].
//= https://www.rfc-editor.org/rfc/rfc3042#section-2
//= type=test
//= reason=Non-SACK first two consecutive duplicates grant fresh output; advancing/ineligible ACKs reset the epoch. Wire tests assert fresh sequence, one packet per grant, cwnd invariance, and denial with exhausted window or queue. Negotiated SACK uses RFC6675 SetPipe, not a claim of one output packet per SACK ACK.
//# When a TCP sender has previously unsent data queued for transmission it SHOULD use the
//# Limited Transmit algorithm, which calls for a TCP sender to transmit new data upon the
//# arrival of the first two consecutive duplicate ACKs when the following conditions are
//# satisfied:
//= https://www.rfc-editor.org/rfc/rfc3042#section-2
//= type=test
//= reason=Before duplicate ACK, after input and after output cwnd are equal for both grants; third duplicate enters fast retransmit independently.
//# The congestion window (cwnd) MUST NOT be changed when these new segments are transmitted.
//= https://www.rfc-editor.org/rfc/rfc3042#section-2
//= type=test
//= reason=Four original MSS fill cwnd; two duplicate ACKs each admit one fresh MSS and then stop. Final flight=cwnd+2*SMSS; third ACK repairs original UNA.
//# The amount of outstanding data would remain less than or equal to the congestion window
//# plus 2 segments. In other words, the sender can only send two segments beyond the
//# congestion window (cwnd).
fn limited_transmit_is_one_packet_per_duplicate_and_excluded_from_threshold() {
    let (mut a, mut b) = primed_pair(config(64, 4), 100);
    a.write(b"abcdefghijklmnopqrstuvwxyzABCDEF").unwrap();
    let _lost = packet(&mut a, 40);
    let second = packet(&mut a, 40);
    let third = packet(&mut a, 40);
    let fourth = packet(&mut a, 40);
    assert_eq!(a.flight(), 16);
    assert_eq!(a.transmit(40, &mut [0; 64]), Ok(None));
    let cwnd = a.congestion.cwnd();
    for (now, bytes) in [(50, second), (60, third)] {
        b.input(now, &wire::parse(ip(tuple()), &bytes).unwrap())
            .unwrap();
        deliver(&mut b, &mut a, now);
        assert!(a.limited_pending);
        assert_eq!(a.congestion.cwnd(), cwnd);
        let next = a.snd_nxt;
        let extra = packet(&mut a, now);
        assert_eq!(
            wire::parse(ip(tuple()), &extra).unwrap().header.sequence,
            next.0
        );
        assert_eq!(a.congestion.cwnd(), cwnd);
        assert_eq!(wire::parse(ip(tuple()), &extra).unwrap().payload.len(), 4);
        assert!(!a.limited_pending);
        assert_eq!(a.transmit(now, &mut [0; 64]), Ok(None));
    }
    assert_eq!(a.flight(), 24);
    assert_eq!(a.limited_sent, 8);
    b.input(70, &wire::parse(ip(tuple()), &fourth).unwrap())
        .unwrap();
    deliver(&mut b, &mut a, 70);
    assert!(a.retx_pending);
    assert_eq!(a.congestion.ssthresh(), 8);
    let bytes = packet(&mut a, 80);
    assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, b"abcd");
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc3042#section-2
//= type=test
//= reason=Ordinary first two duplicate ACKs: no peer-window headroom emits nothing; one-MSS headroom emits one fresh packet only. Queue exhaustion independently emits nothing. Failed encoding preserves grant/accounting and successful output preserves cwnd.
//# The receiver's advertised window allows the transmission of the segment.
fn limited_transmit_window_queue_and_failed_output() {
    for (window, queued, packets) in [(16, 32, 0), (20, 32, 1), (64, 16, 0)] {
        let (mut a, _) = primed_pair(config(64, 4), u32::MAX - 7);
        a.write(&vec![1; queued]).unwrap();
        for _ in 0..4 {
            packet(&mut a, 40);
        }
        // Establish the peer window before counting consecutive duplicates.
        let seq = a.receive.next();
        let una = a.snd_una;
        if a.snd_wnd != u32::from(window) {
            inject(&mut a, 45, seq, una, ACK, window, b"");
        }
        let cwnd = a.congestion.cwnd();
        let end = a.snd_nxt;
        for duplicate in 1..=2 {
            let now = 50 + u64::from(duplicate) * 10;
            inject(&mut a, now, seq, una, ACK, window, b"");
            assert_eq!(a.duplicate_acks, duplicate);
            assert!(a.limited_pending);
            if duplicate <= packets {
                assert_eq!(a.transmit(now, &mut [0; 8]), Err(Error::OutputTooSmall));
                assert_eq!(a.snd_nxt, end);
                assert_eq!(a.limited_sent, 0);
                assert!(a.limited_pending);
                let bytes = packet(&mut a, now);
                let segment = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(segment.header.sequence, end.0);
                assert_eq!(segment.payload.len(), 4);
            }
            assert_eq!(a.transmit(now, &mut [0; 64]), Ok(None));
            assert_eq!(a.congestion.cwnd(), cwnd);
            assert!(a.flight() <= u32::from(window));
            assert!(a.flight() <= cwnd + 2 * a.mss as u32);
            assert_eq!(a.limited_sent, u32::from(packets) * 4);
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6298#section-3
//= type=test
//= reason=Ordinary retransmitted flight followed by newly sent data.
//# TCP MUST use Karn's algorithm [KP87] for taking RTT samples.
//= https://www.rfc-editor.org/rfc/rfc6298#section-3
//= type=test
//= reason=Ordinary retransmitted flight followed by newly sent data.
//# That is, RTT samples MUST NOT be made using segments that were retransmitted (and thus
//# for which it is ambiguous whether the reply was for the first instance of the packet
//# or a later instance).
//= https://www.rfc-editor.org/rfc/rfc6298#section-5
//= type=test
//= reason=Ordinary retransmitted flight followed by newly sent data.
//# Note that after retransmitting, once a new RTT measurement is obtained (which can only
//# happen when new data has been sent and acknowledged), the computations outlined in
//# Section 2 are performed, including the computation of RTO, which may result in
//# "collapsing" RTO back down after it has been subject to exponential back off (rule
//# 5.5).
fn karn_discards_retransmission_samples_but_can_time_fresh_sequence_space() {
    let (mut a, _) = pair(config(64, 4), 100);
    a.write(b"abcdefghijkl").unwrap();
    packet(&mut a, 40);
    packet(&mut a, 40);
    let deadline = a.rto_deadline.unwrap();
    a.timeout(deadline).unwrap();
    packet(&mut a, deadline);
    assert!(a.sample.is_none());
    let seq = a.receive.next();
    inject(&mut a, deadline + 10, seq, Seq(105), ACK, 64, b"");
    // Go-back-N resends the rest of the timed-out flight first, untimed.
    let rest = packet(&mut a, deadline + 20);
    assert_eq!(wire::parse(ip(tuple()), &rest).unwrap().payload, b"efgh");
    assert!(a.sample.is_none());
    let fresh = packet(&mut a, deadline + 20);
    assert_eq!(wire::parse(ip(tuple()), &fresh).unwrap().payload, b"ijkl");
    assert_eq!(a.sample, Some((Seq(113), deadline + 20)));
    inject(&mut a, deadline + 30, seq, Seq(113), ACK, 64, b"");
    assert!(a.sample.is_none());
    assert_eq!(a.rto(), 1_000_000);
}

// Without SACK a timed-out flight is resent in order under slow start: each
// cumulative ACK releases the next segments below the timeout's data
// boundary (an ACK past the frontier skips data the receiver holds), not one
// segment per backed-off RTO; fresh data follows the boundary.
#[test]
fn non_sack_timeout_resends_the_flight_go_back_n_under_slow_start() {
    for iss in [100, u32::MAX - 150] {
        let (mut a, _) = pair(config(4096, 100), iss);
        a.set_nagle(false);
        a.write(&[7; 1200]).unwrap();
        let base = a.snd_una;
        let mut out = vec![0; 2048];
        let mut originals = 0;
        while a.transmit(40, &mut out).unwrap().is_some() {
            originals += 1;
        }
        assert!(originals >= 4, "{originals}");
        let high = a.snd_nxt;
        let deadline = a.rto_deadline.unwrap();
        a.timeout(deadline).unwrap();
        assert_eq!(a.congestion.cwnd(), 100);
        let sent = |a: &mut Connection, now| {
            super::test_support::drain_wire(a, now, 2048, 16)
                .into_iter()
                .map(|(seq, len, _)| (Seq(seq).distance_from(base), len))
                .collect::<Vec<_>>()
        };
        assert_eq!(sent(&mut a, deadline), [(0, 100)]);
        let seq = a.receive.next();
        inject(
            &mut a,
            deadline + 10,
            seq,
            base.wrapping_add(100),
            ACK,
            4096,
            b"",
        );
        // Slow start: two segments, both below the boundary, no fresh data.
        assert_eq!(sent(&mut a, deadline + 10), [(100, 100), (200, 100)]);
        assert_eq!(a.snd_nxt, high);
        // The receiver held [200, 300): the frontier skips it.
        inject(
            &mut a,
            deadline + 20,
            seq,
            base.wrapping_add(300),
            ACK,
            4096,
            b"",
        );
        // cwnd 300, nothing outstanding: the rest of the flight in order,
        // then fresh data up to the window.
        let flight = high.distance_from(base);
        let next = sent(&mut a, deadline + 20);
        let expected: Vec<_> = (3..6).map(|i| (i * 100, 100)).collect();
        assert_eq!(next, expected, "{flight}");
        let mut now = deadline + 20;
        while a.sack_post_rto.is_some() {
            now += 10;
            assert!(now < a.rto_deadline.unwrap(), "repair waited for a timeout");
            let ack = a.data_high();
            inject(&mut a, now, seq, ack, ACK, 4096, b"");
            super::test_support::drain_wire(&mut a, now, 2048, 16);
        }
        assert!(a.snd_una.at_or_after(high));
        assert_eq!(a.consecutive_timeouts, 0);
        // Fresh data continues past the timed-out flight.
        assert!(a.snd_nxt.after(high) || a.send.len() == 0);
    }
}

#[test]
fn lost_payload_and_fin_are_retransmitted_together() {
    let (mut a, mut b) = pair(config(64, 8), 100);
    a.write(b"last").unwrap();
    a.shutdown().unwrap();
    let _lost = packet(&mut a, 40);
    let high = a.snd_nxt;
    let deadline = a.rto_deadline.unwrap();
    a.timeout(deadline).unwrap();
    let bytes = deliver(&mut a, &mut b, deadline);
    let segment = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(segment.payload, b"last");
    assert_ne!(segment.header.flags & FIN, 0);
    assert_eq!(a.snd_nxt, high);
    assert_eq!(b.read(&mut [0; 8]), Ok(4));
    assert_eq!(b.read(&mut [0; 8]), Ok(0));
    deliver(&mut b, &mut a, deadline);
    assert_eq!(a.state(), State::FinWait2);
    assert_eq!(a.rto_deadline, None);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
//= type=test
//# This interval MUST be configurable (MUST-27) and MUST default to no less than
//# two hours (MUST-28).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
//= type=test
//= reason=Default configuration is off; per-connection enable, override and disable update the timers.
//# If
//# keep-alives are included, the application MUST be able to turn them
//# on or off for each TCP connection (MUST-24), and they MUST default to
//# off (MUST-25).
fn keepalive_can_be_disabled_or_overridden_without_reusing_stale_deadlines() {
    assert_eq!(ConnectionConfig::default().keepalive, None);
    assert_eq!(KeepaliveConfig::default().idle_us, 7_200_000_000);
    let (mut a, _) = pair(config(64, 8), 100);
    a.update_time(1_000_000).unwrap();
    let keepalive = KeepaliveConfig {
        idle_us: 100,
        interval_us: 50,
        probes: 2,
        send_garbage: false,
    };
    a.set_keepalive(Some(keepalive)).unwrap();
    assert_eq!(a.next_deadline(), Some(1_000_100));
    a.timeout(1_000_100).unwrap();
    packet(&mut a, 1_000_100);
    assert_eq!(a.keepalive_probes, 1);
    a.update_time(1_000_120).unwrap();
    a.set_keepalive(Some(keepalive)).unwrap();
    assert_eq!(a.keepalive_probes, 0);
    assert_eq!(a.next_deadline(), Some(1_000_220));
    a.timeout(1_000_220).unwrap();
    assert!(a.keepalive_pending);
    a.set_keepalive(None).unwrap();
    assert!(!a.keepalive_pending);
    assert_eq!(a.next_deadline(), None);
    assert_eq!(a.transmit(1_000_220, &mut [0; 64]), Ok(None));
    for invalid in [
        KeepaliveConfig {
            idle_us: 0,
            ..keepalive
        },
        KeepaliveConfig {
            interval_us: 0,
            ..keepalive
        },
        KeepaliveConfig {
            probes: 1,
            ..keepalive
        },
    ] {
        assert_eq!(a.set_keepalive(Some(invalid)), Err(Error::InvalidArgument));
    }
    let mut cfg = config(64, 8);
    cfg.keepalive = Some(keepalive);
    assert!(Connection::active(tuple(), cfg, 100, 0).is_ok());
}
#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.4
//= type=test
//# Delete the TCB and return "error: closing" responses to any queued
//# SENDs, or RECEIVEs.
fn syn_sent_shutdown_cancels_unsent_and_sent_open() {
    for sent in [false, true] {
        let mut a = Connection::active(tuple(), config(64, 8), 100, 0).unwrap();
        a.write(b"queued").unwrap();
        if sent {
            packet(&mut a, 0);
            // Even an already queued response must not escape local cancellation.
            inject(&mut a, 10, Seq(0), Seq(999), ACK, 64, b"");
            assert!(a.pending_rst.is_some());
        }
        a.shutdown().unwrap();
        assert_eq!(a.state(), State::Closed);
        assert_eq!(a.close_reason(), Some(CloseReason::Normal));
        assert_eq!(a.take_events().closed, Some(CloseReason::Normal));
        assert_eq!(a.write(b"late"), Err(Error::InvalidState));
        assert_eq!(a.read(&mut [0; 1]), Err(Error::InvalidState));
        assert_eq!(a.next_deadline(), None);
        assert_eq!(a.transmit(20, &mut []), Ok(None));
        a.timeout(180_000_000).unwrap();
        assert_eq!(a.transmit(180_000_000, &mut [0; 64]), Ok(None));
        a.shutdown().unwrap();
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.5
//= type=test
//= reason=Default abort_with_ack=false retains the illustrated bare reset; enabled formatting has separate byte-exact coverage.
//# Send a reset segment:
//# <SEQ=SND.NXT><CTL=RST>
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.5
//= type=test
//# All queued SENDs and RECEIVEs should be given "connection reset"
//# notification. Delete the TCB, enter CLOSED state, and return.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.5
//= type=test
//# Respond with "ok" and delete the TCB, enter CLOSED state, and return.
fn abort_state_matrix_cancels_work_and_only_resets_required_states() {
    for state in [
        State::SynSent,
        State::SynReceived,
        State::Established,
        State::FinWait1,
        State::FinWait2,
        State::CloseWait,
        State::Closing,
        State::LastAck,
        State::TimeWait,
    ] {
        let (mut a, _) = pair(config(64, 8), 100);
        a.write(b"queued").unwrap();
        a.state = state;
        a.pending_rst = Some((Seq(999), true));
        a.abort();
        assert_eq!(a.state(), State::Closed);
        assert_eq!(a.close_reason(), Some(CloseReason::Aborted));
        assert_eq!(a.take_events().closed, Some(CloseReason::Aborted));
        assert_eq!(a.next_deadline(), None);
        assert_eq!(a.write(b"late"), Err(Error::InvalidState));
        assert_eq!(a.read(&mut [0; 1]), Err(Error::InvalidState));
        a.abort(); // Idempotence must not erase the required reset.
        if matches!(
            state,
            State::SynReceived
                | State::Established
                | State::FinWait1
                | State::FinWait2
                | State::CloseWait
        ) {
            assert_eq!(a.transmit(40, &mut [0; 19]), Err(Error::OutputTooSmall));
            let bytes = packet(&mut a, 40);
            let reset = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(reset.header.flags, RST);
            assert_eq!(reset.header.sequence, a.snd_nxt.0);
            assert!(reset.payload.is_empty());
        }
        assert_eq!(a.transmit(50, &mut []), Ok(None));
    }
}

#[test]
fn abort_with_ack_does_not_change_handshake_rejection_resets() {
    for enabled in [false, true] {
        let cfg = ConnectionConfig {
            abort_with_ack: enabled,
            ..config(64, 8)
        };
        let mut a = Connection::active(tuple(), cfg.clone(), u32::MAX, 0).unwrap();
        let bytes = packet(&mut a, 0);
        let syn = wire::parse(ip(tuple()), &bytes).unwrap();
        let mut b = Connection::passive(reverse(tuple()), cfg, 900, 10, &syn).unwrap();
        packet(&mut b, 20);
        let next = b.receive.next();
        let una = b.snd_una;
        inject(&mut b, 30, next, una, ACK, 64, b"");
        let rejected = packet(&mut b, 30);
        let reset = wire::parse(ip(b.tuple()), &rejected).unwrap();
        assert_eq!(reset.header.flags, RST);
        assert_eq!(reset.header.sequence, una.0);
        assert_eq!(reset.header.acknowledgment, 0);
        assert_eq!(reset.header.window, 0);
        assert_eq!(b.state(), State::SynReceived);
        inject(&mut a, 30, Seq(900), Seq(1), SYN | ACK, 64, b"");
        let rejected = packet(&mut a, 30);
        let reset = wire::parse(ip(a.tuple()), &rejected).unwrap();
        assert_eq!(reset.header.flags, RST);
        assert_eq!(reset.header.sequence, 1);
        assert_eq!(reset.header.acknowledgment, 0);
        assert_eq!(reset.header.window, 0);
        assert_eq!(a.state(), State::SynSent);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
//= type=test
//= reason=Byte-exact default/opt-in abort resets, completed/incomplete handshake, state matrix, sequence/timestamp wrap and failed-output retry. Bare RST echoes zero; RST|ACK echoes TS.Recent.
//# When the ACK bit is set
//# in an outgoing segment, the sender MUST echo a recently received
//# TSval sent by the remote TCP in the TSval field of a Timestamps
//# option.
fn abort_with_ack_is_scoped_and_byte_exact() {
    assert!(!ConnectionConfig::default().abort_with_ack);
    for enabled in [false, true] {
        for timestamps in [false, true] {
            for complete in [false, true] {
                for state in [
                    State::Closed,
                    State::SynSent,
                    State::SynReceived,
                    State::Established,
                    State::FinWait1,
                    State::FinWait2,
                    State::CloseWait,
                    State::Closing,
                    State::LastAck,
                    State::TimeWait,
                ] {
                    let cfg = ConnectionConfig {
                        abort_with_ack: enabled,
                        timestamps,
                        ..config(64, 8)
                    };
                    // Both directions exercise SND.NXT or RCV.NXT wrapping to zero.
                    let (a, b) = pair(cfg, u32::MAX);
                    for mut c in [a, b] {
                        c.state = state;
                        c.handshake_complete = complete;
                        c.set_timestamp_offset(u32::MAX);
                        c.ts_recent = u32::MAX;
                        c.reset_echo = Some(123); // Superseded reactive-reset timestamp.
                        c.reset_reply = true;
                        let seq = c.snd_nxt;
                        let ack = c.receive.next();
                        let window = c.advertised_window(false);
                        let ip = ip(c.tuple());
                        let emits = matches!(
                            state,
                            State::SynReceived
                                | State::Established
                                | State::FinWait1
                                | State::FinWait2
                                | State::CloseWait
                        );
                        let with_ack = enabled && complete && state != State::SynReceived;
                        c.abort();
                        c.abort(); // Retry/idempotence retains ACK policy and receive state.
                        if !emits {
                            assert_eq!(c.transmit(2_000, &mut []), Ok(None));
                            continue;
                        }
                        let before = (c.pending_rst, c.now, c.last_timestamp_sent_at);
                        let size = if timestamps { 32 } else { 20 };
                        assert_eq!(
                            c.transmit(2_000, &mut vec![0; size - 1]),
                            Err(Error::OutputTooSmall)
                        );
                        assert_eq!((c.pending_rst, c.now, c.last_timestamp_sent_at), before);
                        let bytes = packet(&mut c, 2_000);
                        let mut options = Vec::new();
                        if timestamps {
                            options.extend_from_slice(&[1, 1, 8, 10]);
                            options.extend_from_slice(&1u32.to_be_bytes()); // MAX + 2 ticks
                            options.extend_from_slice(
                                &(if with_ack { u32::MAX } else { 0 }).to_be_bytes(),
                            );
                        }
                        let mut expected = vec![0; size];
                        assert_eq!(
                            wire::encode(
                                ip,
                                Header {
                                    source_port: c.tuple.local.port(),
                                    destination_port: c.tuple.remote.port(),
                                    sequence: seq.0,
                                    acknowledgment: ack.0,
                                    flags: RST | if with_ack { ACK } else { 0 },
                                    window,
                                    urgent_pointer: 0,
                                },
                                &options,
                                &[],
                                &mut expected
                            )
                            .unwrap(),
                            size
                        );
                        assert_eq!(
                            bytes, expected,
                            "{state:?} enabled={enabled} complete={complete}"
                        );
                        assert_eq!(c.transmit(3_000, &mut []), Ok(None));
                    }
                }
            }
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.3
//= type=test
//# An ACK SHOULD be generated for at least every second full-sized segment
//# or 2*RMSS bytes of new data (where RMSS is the MSS specified by the TCP
//# endpoint receiving the segments to be acknowledged, or the default value
//# if not specified) (SHLD-19).
//= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
//= type=test
//= reason=Newly received small segments now count toward second-segment feedback regardless of RMSS, without changing PMTU or MSS. Both small-segment tests assert immediate second ACK, transactional failed output, piggyback reset and RMSS-sized feedback; operative delayed timer is separately asserted.
//# In some cases, the sender and receiver may not agree on what constitutes a full-sized segment.
//# An implementation is deemed to comply with this requirement if it sends at least one
//# acknowledgment every time it receives 2*RMSS bytes of new data from the sender, where RMSS is
//# the Maximum Segment Size specified by the receiver to the sender (or the default value of 536
//# bytes, per [RFC1122], if the receiver does not specify an MSS option during connection
//# establishment). The sender may be forced to use a segment size less than RMSS due to the
//# maximum transmission unit (MTU), the path MTU discovery algorithm or other factors. For
//# instance, consider the case when the receiver announces an RMSS of X bytes but the sender ends
//# up using a segment size of Y bytes (Y < X) due to path MTU discovery (or the sender's MTU
//# size). The receiver will generate stretch ACKs if it waits for 2*X bytes to arrive before an
//# ACK is sent. Clearly this will take more than 2 segments of size Y bytes. Therefore, while a
//# specific algorithm is not defined, it is desirable for receivers to attempt to prevent this
//# situation, for example, by acknowledging at least every second segment, regardless of size.
//# Finally, we repeat that an ACK MUST NOT be delayed for more than 500 ms waiting on a second
//# full-sized segment to arrive.
fn delayed_ack_counts_small_segments_and_commits_only_with_output() {
    let (mut a, _) = pair(config(128, 8), 100);
    // Effective send MSS is not the local receive MSS used for this threshold.
    a.mss = 4;
    let ack = a.snd_nxt;
    for i in 0..2 {
        let next = a.receive.next();
        inject(&mut a, 40 + i, next, ack, ACK, 128, b"ab");
        assert_eq!(a.unacked_bytes, 2 * (i + 1) as u32);
        assert_eq!(a.unacked_segments, (i + 1) as u8);
        assert_eq!(a.ack_pending, i == 1);
    }
    let before = (a.unacked_bytes, a.unacked_segments, a.ack_pending, a.now);
    assert_eq!(a.transmit(50, &mut [0; 19]), Err(Error::OutputTooSmall));
    assert_eq!(
        (a.unacked_bytes, a.unacked_segments, a.ack_pending, a.now),
        before
    );
    packet(&mut a, 50);
    assert_eq!(a.unacked_bytes, 0);
    let next = a.receive.next();
    inject(&mut a, 60, next, ack, ACK, 128, b"ab");
    assert!(!a.ack_pending);
    assert_eq!(a.unacked_bytes, 2);
    assert_eq!(a.transmit(70, &mut [0; 64]), Ok(None));
    assert_eq!(a.unacked_bytes, 2);
    // A piggyback ACK also commits the reset.
    a.write(b"reply").unwrap();
    packet(&mut a, 70);
    assert_eq!(a.unacked_bytes, 0);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
//= type=test
//= reason=Receiver role, all recovery profiles. Default 200ms timer; configuration rejects >=500ms. Existing tests assert no early output, timeout at first packet+200ms, and immediate second full-RMSS ACK; caller must service scheduled timeout/poll. Not a guarantee when host ignores deadlines.
//# The delayed ACK algorithm specified in [RFC1122] SHOULD be used by a TCP receiver.
//= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
//= type=test
//= reason=Receiver role, all recovery profiles. Default 200ms timer; configuration rejects >=500ms. Existing tests assert no early output, timeout at first packet+200ms, and immediate second full-RMSS ACK; caller must service scheduled timeout/poll. Not a guarantee when host ignores deadlines.
//# When using delayed ACKs, a TCP receiver MUST NOT excessively delay acknowledgments.
//= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
//= type=test
//= reason=Receiver role, all recovery profiles. Default 200ms timer; configuration rejects >=500ms. Existing tests assert no early output, timeout at first packet+200ms, and immediate second full-RMSS ACK; caller must service scheduled timeout/poll. Not a guarantee when host ignores deadlines.
//# Specifically, an ACK SHOULD be generated for at least every second full-sized segment,
//# and MUST be generated within 500 ms of the arrival of the first unacknowledged packet.
//= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
//= type=test
//= reason=Receiver role, all recovery profiles. Default 200ms timer; configuration rejects >=500ms. Existing tests assert no early output, timeout at first packet+200ms, and immediate second full-RMSS ACK; caller must service scheduled timeout/poll. Not a guarantee when host ignores deadlines.
//# Finally, we repeat that an ACK MUST NOT be delayed for more than 500 ms waiting on a
//# second full-sized segment to arrive.
fn delayed_ack_uses_advertised_receive_mss_not_peer_send_mss() {
    for receive_limit in [28, 100] {
        let mut cfg = config(128, 16);
        cfg.receive_ip_payload_limit = receive_limit;
        let mut a = Connection::active(tuple(), cfg, 100, 0).unwrap();
        let bytes = packet(&mut a, 0);
        let syn = wire::parse(ip(tuple()), &bytes).unwrap();
        let rmss = syn.options.mss.unwrap();
        assert_eq!(rmss, 16.min(receive_limit - 20));
        let mut b = Connection::passive(reverse(tuple()), config(128, 4), 900, 10, &syn).unwrap();
        deliver(&mut b, &mut a, 20);
        deliver(&mut a, &mut b, 30);
        assert_eq!(a.mss, 4);
        let ack = a.snd_nxt;
        for (i, now) in [40, 50].into_iter().enumerate() {
            let next = a.receive.next();
            inject(&mut a, now, next, ack, ACK, 128, b"abcd");
            assert_eq!(a.unacked_segments, (i + 1) as u8);
            assert_eq!(a.ack_pending, i == 1);
            if i == 0 {
                assert_eq!(a.transmit(now, &mut [0; 64]), Ok(None));
            }
        }
        // Small peer segments no longer stretch ACKs to 2*RMSS.
        assert_eq!(a.ack_deadline, None);
        packet(&mut a, 50);
        for i in 0..2 {
            let now = 200_050 + i;
            let next = a.receive.next();
            inject(&mut a, now, next, ack, ACK, 128, &vec![0; rmss as usize]);
            assert_eq!(a.unacked_segments, (i + 1) as u8);
            assert_eq!(a.unacked_bytes, (i + 1) as u32 * u32::from(rmss));
            assert_eq!(a.ack_pending, i == 1);
            if i == 0 {
                assert_eq!(a.transmit(now, &mut [0; 64]), Ok(None));
            }
        }
        packet(&mut a, 200_052);
        assert_eq!((a.unacked_segments, a.unacked_bytes), (0, 0));
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1
//= type=test
//= reason=Asserts the initial RTO deadline and successive doubled intervals, including failed output attempts.
//# The transmitting host SHOULD send the first zero-window probe when a
//# zero window has existed for the retransmission timeout period (SHLD-
//# 29) (Section 3.8.1), and SHOULD increase exponentially the interval
//# between successive probes (SHLD-30).
fn persist_uses_updated_rto_once_per_episode() {
    let (mut a, _) = pair(config(64, 4), 100);
    a.write(b"abcdefgh").unwrap();
    packet(&mut a, 40);
    let old_rto = a.rto();
    let next = a.receive.next();
    let ack = a.snd_nxt;
    inject(&mut a, 2_000_040, next, ack, ACK, 0, b"");
    assert!(a.rto() > old_rto);
    let first_rto = a.rto();
    assert_eq!(a.persist_interval, first_rto);
    assert_eq!(a.persist_deadline, Some(a.now + first_rto));
    let deadline = a.loss_timer.unwrap().1;
    a.arm_work();
    assert_eq!(a.persist_deadline, Some(deadline));
    a.timeout(deadline).unwrap();
    a.arm_work();
    assert_eq!(a.persist_deadline, None);
    assert!(a.probe_pending);
    assert_eq!(
        a.transmit(deadline, &mut [0; 19]),
        Err(Error::OutputTooSmall)
    );
    assert_eq!(a.persist_interval, first_rto);
    packet(&mut a, deadline);
    assert_eq!(a.persist_interval, 2 * first_rto);
    let second = a.loss_timer.unwrap().1;
    // A responsive, still-closed window must not restart the backoff.
    let ack = a.snd_nxt;
    inject(&mut a, deadline + 1, next, ack, ACK, 0, b"");
    a.arm_work();
    assert_eq!(a.persist_deadline, Some(second));
    assert_eq!(a.persist_interval, 2 * first_rto);
    a.timeout(second).unwrap();
    packet(&mut a, second);
    assert_eq!(a.persist_interval, 4 * first_rto);
    let ack = a.snd_nxt;
    inject(&mut a, second + 1, next, ack, ACK, 64, b"");
    assert_eq!(a.persist_interval, 0);
    assert_eq!(a.persist_deadline, None);
    inject(&mut a, second + 2, next, ack, ACK, 0, b"");
    assert_eq!(a.persist_interval, a.rto());
    assert_eq!(a.persist_deadline, Some(second + 2 + a.rto()));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.4.2
//= type=test
//# For this specification the MSL is taken to be 2 minutes.
fn time_wait_defaults_to_120_seconds_beside_a_two_minute_msl() {
    let cfg = ConnectionConfig::default();
    assert_eq!(cfg.timebase.max_segment_lifetime_us, 120_000_000);
    assert_eq!(cfg.time_wait_us, 120_000_000);
    let mut a = Connection::active(tuple(), config(64, 8), 100, 5).unwrap();
    a.time_wait();
    assert_eq!(a.time_wait_deadline, Some(5 + 120_000_000));
}

#[test]
fn time_wait_accepts_any_positive_duration_and_ends_at_its_deadline() {
    // Durations below the default (down to one microsecond, which the former
    // 2xMSL floor refused), above it, and one whose deadline saturates.
    for units_per_second in [1_000_000, 1_000_000_000] {
        for time_wait_us in [1, 2, 1_000, 59_999_999, 120_000_000, 240_000_001, u64::MAX] {
            let mut cfg = config(64, 8);
            cfg.timebase.units_per_second = units_per_second;
            cfg.time_wait_us = time_wait_us;
            let mut a = Connection::active(tuple(), cfg, 100, 5).unwrap();
            a.time_wait();
            let deadline =
                5u64.saturating_add(time_wait_us.saturating_mul(units_per_second / 1_000_000));
            assert_eq!(a.time_wait_deadline, Some(deadline));
            assert_eq!(a.next_deadline(), Some(deadline));
            a.timeout(deadline - 1).unwrap();
            assert_eq!(a.state(), State::TimeWait);
            assert!(a.time_wait_valid(deadline - 1));
            assert!(!a.time_wait_valid(deadline));
            if deadline < u64::MAX {
                a.timeout(deadline).unwrap();
                assert_eq!(a.state(), State::Closed);
                assert_eq!(a.next_deadline(), None);
            }
        }
    }
    let mut cfg = config(64, 8);
    cfg.time_wait_us = 0;
    assert!(matches!(
        Connection::active(tuple(), cfg, 100, 0),
        Err(Error::InvalidArgument)
    ));
}

#[test]
fn shortest_time_wait_still_acknowledges_the_peer_fin() {
    let mut cfg = config(64, 8);
    cfg.time_wait_us = 1;
    let (mut a, mut b) = pair(cfg, 100);
    a.shutdown().unwrap();
    deliver(&mut a, &mut b, 40);
    deliver(&mut b, &mut a, 50);
    assert_eq!(a.state(), State::FinWait2);
    b.shutdown().unwrap();
    deliver(&mut b, &mut a, 60);
    assert_eq!(a.state(), State::TimeWait);
    assert_eq!(b.state(), State::LastAck);
    // Timers serviced at the instant TIME-WAIT begins leave it, and the
    // acknowledgment it owes, in place.
    a.timeout(60).unwrap();
    assert_eq!(a.state(), State::TimeWait);
    deliver(&mut a, &mut b, 60);
    assert_eq!(b.state(), State::Closed);
    assert_eq!(b.close_reason(), Some(CloseReason::Normal));
    assert_eq!(a.next_deadline(), Some(61));
    a.timeout(61).unwrap();
    assert_eq!(a.state(), State::Closed);
    assert_eq!(a.transmit(61, &mut [0; 64]), Ok(None));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.1
//= type=test
//# TCP endpoints MUST implement both sending and receiving the MSS Option
//# (MUST-14).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.1
//= type=test
//# TCP implementations SHOULD send an MSS Option in every SYN segment when its
//# receive MSS differs from the default 536 for IPv4 or 1220 for IPv6 (SHLD-5),
//# and MAY send it always (MAY-3).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.1
//= type=test
//# The maximum size of a segment that a TCP endpoint really sends, the
//# "effective send MSS", MUST be the smaller (MUST-16) of the send MSS
//# (that reflects the available reassembly buffer size at the remote
//# host, the EMTU_R [19]) and the largest transmission size permitted by
//# the IP layer (EMTU_S [19]):
fn mss_offers_and_asymmetric_send_limits_for_both_address_families() {
    let v6 = Tuple {
        local: "[2001:db8::1]:1000".parse().unwrap(),
        remote: "[2001:db8::2]:2000".parse().unwrap(),
    };
    for tuple in [tuple(), v6] {
        let default_mss = if tuple.local.is_ipv4() { 536 } else { 1220 };
        for (local_mss, peer_mss) in [(default_mss, 300), (300, default_mss), (1460, 1460)] {
            let mut a = Connection::active(tuple, config(8192, local_mss), 100, 0).unwrap();
            let bytes = packet(&mut a, 0);
            let syn = wire::parse(ip(tuple), &bytes).unwrap();
            assert_eq!(syn.options.mss, Some(local_mss));
            let mut b =
                Connection::passive(reverse(tuple), config(8192, peer_mss), 900, 10, &syn).unwrap();
            let bytes = deliver(&mut b, &mut a, 20);
            let synack = wire::parse(ip(reverse(tuple)), &bytes).unwrap();
            assert_eq!(synack.options.mss, Some(peer_mss));
            deliver(&mut a, &mut b, 30);
            let effective = usize::from(local_mss.min(peer_mss).min(if tuple.local.is_ipv4() {
                u16::MAX
            } else {
                1220 // Disabled discovery constrains sends independently of the SYN offer.
            }));
            assert_eq!(a.mss, effective);
            assert_eq!(b.mss, effective);
            for sender in [&mut a, &mut b] {
                sender.write(&vec![42; 4096]).unwrap();
                let bytes = packet(sender, 40);
                let data = wire::parse(ip(sender.tuple()), &bytes).unwrap();
                assert_eq!(data.payload.len(), effective);
                assert_eq!(data.options.mss, None);
            }
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
//= type=test
//# and they MUST default to off (MUST-25).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
//= type=test
//# Keep-alive packets MUST only be sent when no sent data is outstanding, and
//# no data or acknowledgment packets have been received for the connection
//# within an interval (MUST-26).
fn keepalive_defaults_off_and_is_suppressed_by_outstanding_data() {
    assert_eq!(ConnectionConfig::default().keepalive, None);
    let (mut a, _) = pair(config(64, 8), 100);
    a.timeout(7_200_000_100).unwrap();
    assert_eq!(a.keepalive_deadline, None);
    assert!(!a.keepalive_pending);
    assert_eq!(a.transmit(7_200_000_100, &mut [0; 64]), Ok(None));

    let (mut a, _) = pair(config(64, 8), 100);
    a.set_keepalive(Some(KeepaliveConfig {
        idle_us: 100,
        interval_us: 50,
        probes: 2,
        send_garbage: false,
    }))
    .unwrap();
    a.timeout(a.keepalive_deadline.unwrap()).unwrap();
    assert!(a.keepalive_pending);
    a.write(b"data").unwrap();
    assert!(!a.keepalive_pending);
    packet(&mut a, 130);
    assert_eq!(a.flight(), 4);
    assert_eq!(a.keepalive_deadline, None);
    a.timeout(230).unwrap();
    assert_eq!(a.transmit(230, &mut [0; 64]), Ok(None));
    let next = a.receive.next();
    let ack = a.snd_nxt;
    inject(&mut a, 240, next, ack, ACK, 64, b"");
    assert_eq!(a.keepalive_deadline, Some(340));
    a.timeout(339).unwrap();
    assert_eq!(a.transmit(339, &mut [0; 64]), Ok(None));
    a.timeout(340).unwrap();
    let bytes = packet(&mut a, 340);
    let probe = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(probe.header.sequence, a.snd_nxt.wrapping_add(u32::MAX).0);
    assert!(probe.payload.is_empty());
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.6
//= type=test
//# If the local TCP connection is closed by the remote side due to a FIN or RST
//# received from the remote side, then the local application MUST be informed
//# whether it closed normally or was aborted (MUST-12).
fn remote_fin_and_reset_have_distinct_close_notifications() {
    let (mut a, mut b) = pair(config(64, 8), 100);
    b.shutdown().unwrap();
    deliver(&mut b, &mut a, 40);
    let events = a.take_events();
    assert!(events.half_closed);
    assert_eq!(events.closed, None);
    assert_eq!(a.read(&mut [0; 1]), Ok(0));
    a.shutdown().unwrap();
    deliver(&mut a, &mut b, 50);
    deliver(&mut b, &mut a, 60);
    assert_eq!(a.take_events().closed, Some(CloseReason::Normal));
    assert_eq!(a.close_reason(), Some(CloseReason::Normal));

    let (mut a, _) = pair(config(64, 8), 100);
    let next = a.receive.next();
    let ack = a.snd_nxt;
    inject(&mut a, 40, next, ack, RST, 64, b"");
    let events = a.take_events();
    assert!(!events.half_closed);
    assert_eq!(events.closed, Some(CloseReason::Reset));
    assert_eq!(a.close_reason(), Some(CloseReason::Reset));
    assert_eq!(a.read(&mut [0; 1]), Err(Error::InvalidState));
}
#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
//= type=test
//# However, a sending TCP peer MUST
//# be robust against window shrinking, which may cause the "usable
//# window" (see Section 3.8.6.2.1) to become negative (MUST-34).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
//= type=test
//# If this happens, the sender SHOULD NOT send new data (SHLD-15), but
//# SHOULD retransmit normally the old unacknowledged data between
//# SND.UNA and SND.UNA+SND.WND (SHLD-16).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
//= type=test
//# but SHOULD NOT
//# time out the connection if data beyond the right window edge is not
//# acknowledged (SHLD-17).
// Scope: Shrinking windows retain payload; original validity and retry coverage implement scaled first/sub-scale permission with conservative overflow fallback and separate persist.
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.4
//= type=test
//= reason=Shrinking windows retain payload; capacity-backed original validity and retry coverage implement scaled first/sub-scale retry permission with conservative overflow fallback and separate persist behavior.
//# Implementations MUST ensure that they handle a shrinking
//# window, as specified in Section 4.2.2.16 of [RFC1122].
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.4
//= type=test
//= reason=Fresh-data branch saturates latest-window credit after flight subtraction; no new data after shrinking below flight; retransmit policy never sends unsent tail.
//# 3)  The initial transmission MUST be within the window announced by
//# the most recent <ACK>.
// Scope: Capacity-backed original identity and per-coverage successful retries implement first/sub-scale permission; normal retries share pure planning and post-encode commit, with persist separate.
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.4
//= type=test
//= reason=Capacity-backed original identity and per-coverage successful retries implement first/sub-scale permission; all normal retry paths share pure planning and post-encode commit, while zero-window persist is separate.
//# 4)  On first retransmission, or if the sequence number is out of
//# window by less than 2^Rcv.Wind.Shift, then do normal
//# retransmission(s) without regard to the receiver window as long
//# as the original segment was in window when it was sent.
fn nonzero_shrink_below_flight_retains_bytes_retransmits_inside_and_reopens() {
    for iss in [100, u32::MAX - 4] {
        let mut cfg = config(64, 8);
        cfg.user_timeout_us = 5_000_000;
        let (mut a, _) = pair(cfg, iss);
        // Exercise the conservative policy without negotiated scaling.
        a.scaling = false;
        a.write(b"abcdefghijkl").unwrap();
        packet(&mut a, 40);
        let next = a.receive.next();
        let una = a.snd_una;
        let high = a.snd_nxt;
        inject(&mut a, 50, next, una, ACK, 3, b"");
        assert_eq!(a.flight(), 8);
        assert_eq!(a.send.len(), 12);
        assert_eq!(a.transmit(60, &mut [0; 64]), Ok(None));
        let when = a.rto_deadline.unwrap();
        a.timeout(when).unwrap();
        let before = (a.snd_nxt, a.rto_deadline, a.now, a.retx_pending);
        assert_eq!(
            a.transmit(when + 1, &mut [0; 22]),
            Err(Error::OutputTooSmall)
        );
        assert_eq!((a.snd_nxt, a.rto_deadline, a.now, a.retx_pending), before);
        let bytes = packet(&mut a, when + 1);
        let seg = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(seg.header.sequence, una.0);
        assert_eq!(seg.payload, b"abc");
        assert_eq!(a.snd_nxt, high);
        // No ACK progress for longer than the user timeout, but validated
        // window feedback proves the shrunken peer is still responsive.
        for now in [4_000_000, 8_000_000, 12_000_000, 16_000_000] {
            inject(&mut a, now, next, una, ACK, 3, b"");
            assert_eq!(a.user_deadline(), None);
            a.timeout(now).unwrap();
            assert_eq!(a.state(), State::Established);
            if a.retx_pending && now != 16_000_000 {
                let bytes = packet(&mut a, now);
                assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, b"abc");
            }
            assert_eq!(a.snd_nxt, high);
            assert_eq!(a.send.len(), 12);
        }
        inject(&mut a, 16_000_001, next, una, ACK, 64, b"");
        assert_eq!(a.user_deadline(), Some(21_000_001));
        // Reopening retries the latest head transmission, not untouched bytes.
        let bytes = packet(&mut a, 16_000_001);
        assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, b"abc");
        assert_eq!(a.snd_nxt, high);
        // ACK only the original flight; the unsent tail survived the shrink.
        inject(&mut a, 16_000_002, next, high, ACK, 64, b"");
        assert_eq!(a.acknowledged(), 8);
        let bytes = packet(&mut a, 16_000_003);
        assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, b"ijkl");
        let end = a.snd_nxt;
        inject(&mut a, 16_000_004, next, end, ACK, 64, b"");
        assert_eq!(a.acknowledged(), 12);
        assert_eq!(a.send.len(), 0);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
//= type=test
//# but SHOULD NOT
//# time out the connection if data beyond the right window edge is not
//# acknowledged (SHLD-17).
fn shrink_liveness_rejects_stale_feedback_and_keeps_ordinary_boundary_timeout() {
    for iss in [100, u32::MAX - 4] {
        for window in [1, 7, 8, 9] {
            let mut cfg = config(64, 8);
            cfg.user_timeout_us = 5_000_000;
            let (mut a, _) = pair(cfg, iss);
            a.write(b"abcdefgh").unwrap();
            packet(&mut a, 40);
            let seq = a.receive.next().wrapping_add(1);
            let una = a.snd_una;
            inject(&mut a, 50, seq, una, ACK, window, b"");
            let baseline = a.user_deadline();
            inject(&mut a, 100, seq, una, ACK, window, b"");
            if window < 8 {
                assert_eq!(a.user_deadline(), None);
                let when = a.rto_deadline.unwrap();
                a.timeout(when).unwrap();
                packet(&mut a, when);
                assert_eq!(a.user_deadline(), Some(when + 5_000_000));
            } else {
                assert_eq!(a.user_deadline(), baseline);
            }
            let deadline = a.user_deadline().unwrap();
            let feedback_at = a.now + 1;
            // Acceptable old ACK, stale SEQ/window, future ACK, RST and SYN
            // cannot reset the liveness clock or update the send window.
            for (seq, ack, flags) in [
                (seq, una.wrapping_add(u32::MAX), ACK),
                (a.receive.next(), una, ACK),
                (seq, a.snd_nxt.wrapping_add(1), ACK),
                (seq, una, RST | ACK),
                (seq, una, SYN | ACK),
            ] {
                inject(&mut a, feedback_at, seq, ack, flags, 64, b"");
                assert_eq!(a.user_deadline(), Some(deadline));
                assert_eq!(a.snd_wnd, window as u32);
            }
            a.timeout(deadline - 1).unwrap();
            assert_eq!(a.state(), State::Established);
            a.timeout(deadline).unwrap();
            assert_eq!(a.close_reason(), Some(CloseReason::TimedOut));
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.1
//= type=test
//# The maximum size of a segment that a TCP endpoint really sends, the
//# "effective send MSS", MUST be the smaller (MUST-16) of the send MSS
//# (that reflects the available reassembly buffer size at the remote
//# host, the EMTU_R [19]) and the largest transmission size permitted by
//# the IP layer (EMTU_S [19]):
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.1
//= type=test
//# where MMS_R is the maximum size for a transport-layer message that
//# can be received (and reassembled at the IP layer) (MUST-67).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.3
//= type=test
//# As a result, when the effective MTU of an interface varies packet-to-
//# packet, TCP implementations SHOULD use the smallest effective MTU of
//# the interface to calculate the value to advertise in the MSS Option
//# (SHLD-6).
fn ip_limits_bound_receive_offer_send_payload_options_and_allocations() {
    let v6 = Tuple {
        local: "[2001:db8::1]:1000".parse().unwrap(),
        remote: "[2001:db8::2]:2000".parse().unwrap(),
    };
    for tuple in [tuple(), v6] {
        let family_limit = if tuple.local.is_ipv4() { 65515 } else { 65535 };
        let max_mss = family_limit - 20;
        for (configured, receive, send, peer) in [
            (64, 25, 40, 64),
            (64, 100, 40, 9),
            (64, 21, 28, 64),
            (8, 100, 100, 64),
            (max_mss, u16::MAX, u16::MAX, max_mss),
        ] {
            let mut cfg = config(131072, configured);
            cfg.receive_ip_payload_limit = receive;
            cfg.send_ip_payload_limit = send;
            let mut a = Connection::active(tuple, cfg, 100, 0).unwrap();
            let storage = (a.scratch.as_ptr(), a.scratch.capacity());
            assert_eq!(a.scratch.len(), configured as usize);
            let before = (a.snd_nxt, a.now, a.next_deadline());
            assert_eq!(a.transmit(1, &mut [0; 27]), Err(Error::OutputTooSmall));
            assert_eq!((a.snd_nxt, a.now, a.next_deadline()), before);
            assert!(a.syn_pending);
            let bytes = packet(&mut a, 1);
            assert_eq!(bytes.len(), 28);
            assert!(bytes.len() <= send as usize);
            let syn = wire::parse(ip(tuple), &bytes).unwrap();
            assert_eq!(
                syn.options.mss,
                Some(configured.min(receive.min(family_limit) - 20))
            );
            assert!(syn.options.window_scale.is_some());
            let mut b =
                Connection::passive(reverse(tuple), config(131072, peer), 900, 10, &syn).unwrap();
            deliver(&mut b, &mut a, 20);
            let ack = deliver(&mut a, &mut b, 30);
            assert_eq!(ack.len(), 20);
            let send_limit = send.min(if tuple.local.is_ipv4() { family_limit } else { 1240 });
            let effective = configured.min(peer).min(send_limit - 20) as usize;
            assert_eq!(a.mss, effective);
            a.write(&vec![42; effective + 1]).unwrap();
            let before = (a.snd_nxt, a.now, a.next_deadline());
            assert_eq!(
                a.transmit(40, &mut vec![0; 19 + effective]),
                Err(Error::OutputTooSmall)
            );
            assert_eq!((a.snd_nxt, a.now, a.next_deadline()), before);
            let bytes = packet(&mut a, 40);
            assert_eq!(bytes.len(), 20 + effective);
            assert!(bytes.len() <= send_limit as usize);
            assert_eq!(
                wire::parse(ip(tuple), &bytes).unwrap().payload.len(),
                effective
            );
            a.lower_mss(1).unwrap();
            assert_eq!((a.scratch.as_ptr(), a.scratch.capacity()), storage);
            assert_eq!(packet(&mut a, 50).len(), 21);
            a.abort();
            assert_eq!(packet(&mut a, 60).len(), 20);
        }
        for (receive, send) in [
            (0, 100),
            (20, 100),
            (100, 0),
            (100, 20),
            (100, 21),
            (100, 27),
        ] {
            let mut cfg = config(64, 8);
            cfg.receive_ip_payload_limit = receive;
            cfg.send_ip_payload_limit = send;
            assert!(matches!(
                Connection::active(tuple, cfg, 100, 0),
                Err(Error::InvalidArgument)
            ));
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# o  RFC 5961 [9], Section 5 describes a potential blind data
//# injection attack, and mitigation that implementations MAY
//# choose to include (MAY-12).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# TCP stacks that implement RFC
//# 5961 MUST add an input check that the ACK value is
//# acceptable only if it is in the range of ((SND.UNA -
//# MAX.SND.WND) =< SEG.ACK =< SND.NXT).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# All incoming segments
//# whose ACK value doesn't satisfy the above condition MUST be
//# discarded and an ACK sent back.
//= https://www.rfc-editor.org/rfc/rfc5961#section-1.1
//= type=test
//= reason=All three defenses are selected for ordinary endpoint operation; RST/SYN/ACK assertion matrices establish the operative behavior, not cryptographic/on-path protection or administrator threat assessment.
//# The mitigations suggested in this document
//# SHOULD be implemented in devices that regularly need to maintain TCP
//# connections of the kind most vulnerable to the attacks described in
//# this document.
// Actor/condition: TCP endpoint; selected blind-attack mitigation.
//= https://www.rfc-editor.org/rfc/rfc5961#section-1.1
//= type=test
//= reason=All three defenses are selected for ordinary endpoint operation; RST/SYN/ACK assertion matrices establish the operative behavior, not cryptographic/on-path protection or administrator threat assessment.
//# These mitigations
//# MAY be implemented in other cases.
// Actor/condition: TCP endpoint; selected blind-attack mitigation.
//= https://www.rfc-editor.org/rfc/rfc5961#section-5.2
//= type=test
//= reason=Selected DATA/FIN mitigation: inclusive serial ACK bounds, adjacent rejection, challenge fields and no receive/URG/FIN/window/send/timer effects are asserted. RST/SYN state validation remains prior to ordinary ACK/data handling.
//# All TCP stacks MAY implement the following mitigation.
// Actor/condition: TCP endpoint; ACK-bearing segments after state/control validation.
//= https://www.rfc-editor.org/rfc/rfc5961#section-5.2
//= type=test
//= reason=Selected DATA/FIN mitigation: inclusive serial ACK bounds, adjacent rejection, challenge fields and no receive/URG/FIN/window/send/timer effects are asserted. RST/SYN state validation remains prior to ordinary ACK/data handling.
//# TCP stacks
//# that implement this mitigation MUST add an additional input check to
//# any incoming segment.
// Actor/condition: TCP endpoint; ACK-bearing segments after state/control validation.
//= https://www.rfc-editor.org/rfc/rfc5961#section-5.2
//= type=test
//= reason=Selected DATA/FIN mitigation: inclusive serial ACK bounds, adjacent rejection, challenge fields and no receive/URG/FIN/window/send/timer effects are asserted. RST/SYN state validation remains prior to ordinary ACK/data handling.
//# All incoming segments whose ACK value doesn't satisfy the
//# above condition MUST be discarded and an ACK sent back.
// Actor/condition: TCP endpoint; ACK-bearing segments after state/control validation.
//= https://www.rfc-editor.org/rfc/rfc5961#section-5.2
//= type=test
//= reason=Inclusive lower/upper bounds, adjacent invalid values and modular wrap are explicitly asserted.
//# The ACK value is considered acceptable only if it is in the range of ((SND.UNA - MAX.SND.WND) <= SEG.ACK <= SND.NXT).
// Actor/condition: TCP endpoint; selected ACK bound mitigation.
fn rfc5961_ack_bounds_are_inclusive_and_reject_all_incoming_side_effects() {
    for iss in [100, u32::MAX - 4] {
        for bound in 0..4 {
            let (mut a, _) = pair(config(64, 8), iss);
            a.write(b"retained").unwrap();
            packet(&mut a, 40);
            let oldest = a.snd_una.wrapping_add(0u32.wrapping_sub(a.max_snd_wnd));
            let high = a.snd_nxt;
            let ack = [
                oldest,
                high,
                oldest.wrapping_add(u32::MAX),
                high.wrapping_add(1),
            ][bound];
            let next = a.receive.next();
            let seq = next.wrapping_add(1); // URG offset zero still advances the mark.
            let before = (
                a.snd_una,
                a.snd_wnd,
                a.wl1,
                a.wl2,
                a.progress_at,
                a.last_received,
                a.rto_deadline,
            );
            inject(&mut a, 50, seq, ack, ACK | URG | FIN, 1, b"bad");
            if bound < 2 {
                assert_eq!(a.urgent_remaining(), 1);
                assert_eq!(a.send.len(), if bound == 0 { 8 } else { 0 });
                // The accepted out-of-order text and FIN become visible on filling the gap.
                inject(&mut a, 60, next, high, ACK, 64, b"x");
                let mut data = [0; 4];
                assert_eq!(a.read(&mut data), Ok(4));
                assert_eq!(&data, b"xbad");
                assert_eq!(a.state(), State::CloseWait);
            } else {
                assert_eq!(
                    (
                        a.snd_una,
                        a.snd_wnd,
                        a.wl1,
                        a.wl2,
                        a.progress_at,
                        a.last_received,
                        a.rto_deadline
                    ),
                    before
                );
                assert_eq!(a.urgent_remaining(), 0);
                assert_eq!(a.send.len(), 8);
                assert_eq!(a.receive.next(), next);
                assert_eq!(a.state(), State::Established);
                assert!(!a.events_pending());
                let bytes = packet(&mut a, 50);
                let response = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(response.header.flags, ACK);
                assert_eq!(response.header.sequence, high.0);
                assert_eq!(response.header.acknowledgment, next.0);
                inject(&mut a, 60, next, high, ACK, 64, b"x");
                assert_eq!(a.read(&mut [0; 8]), Ok(1));
                assert_eq!(a.state(), State::Established);
            }
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# 2)  If the RST bit is set and the sequence number exactly
//# matches the next expected sequence number (RCV.NXT), then
//# TCP endpoints MUST reset the connection in the manner
//# prescribed below according to the connection state.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# RFC 5961 recommends that in
//# these synchronized states, if the SYN bit is set,
//# irrespective of the sequence number, TCP endpoints MUST send
//# a "challenge ACK" to the remote peer:
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# o  After sending the acknowledgment, TCP implementations MUST
//# drop the unacceptable segment and stop processing further.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//= reason=Exact-sequence inbound reset terminates, cancels all protocol output/deadlines, reports Reset; explicit release governs terminal handle storage.
//# If the RST bit is set, then any outstanding RECEIVEs and SEND should receive "reset"
//# responses. All segment queues should be flushed. Users should also receive an
//# unsolicited general "connection reset" signal. Enter the CLOSED state, delete the TCB,
//# and return.
//= https://www.rfc-editor.org/rfc/rfc5961#section-1.1
//= type=test
//= reason=All three defenses are selected for ordinary endpoint operation; RST/SYN/ACK assertion matrices establish the operative behavior, not cryptographic/on-path protection or administrator threat assessment.
//# The mitigations suggested in this document
//# SHOULD be implemented in devices that regularly need to maintain TCP
//# connections of the kind most vulnerable to the attacks described in
//# this document.
// Actor/condition: TCP endpoint; selected blind-attack mitigation.
//= https://www.rfc-editor.org/rfc/rfc5961#section-1.1
//= type=test
//= reason=All three defenses are selected for ordinary endpoint operation; RST/SYN/ACK assertion matrices establish the operative behavior, not cryptographic/on-path protection or administrator threat assessment.
//# These mitigations
//# MAY be implemented in other cases.
// Actor/condition: TCP endpoint; selected blind-attack mitigation.
//= https://www.rfc-editor.org/rfc/rfc5961#section-3.2
//= type=test
//= reason=Selected RST/SYN defenses: existing state/sequence matrix asserts exact reset termination, outside reset silence, nonexact in-window challenge and SYN challenge fields/drop. Matrix exercises sequence wrap and rejects appended text/URG/FIN/ACK effects.
//# Instead, implementations SHOULD implement the following steps in
//# place of those specified in [RFC0793] (as listed above).
// Actor/condition: TCP endpoint; selected blind-attack mitigation.
//= https://www.rfc-editor.org/rfc/rfc5961#section-3.2
//= type=test
//= reason=Selected RST/SYN defenses: existing state/sequence matrix asserts exact reset termination, outside reset silence, nonexact in-window challenge and SYN challenge fields/drop. Matrix exercises sequence wrap and rejects appended text/URG/FIN/ACK effects.
//# 2) If the RST bit is set and the sequence number exactly matches the
//# next expected sequence number (RCV.NXT), then TCP MUST reset the
//# connection.
// Actor/condition: TCP endpoint; selected blind-attack mitigation.
//= https://www.rfc-editor.org/rfc/rfc5961#section-3.2
//= type=test
//= reason=Selected RST/SYN defenses: existing state/sequence matrix asserts exact reset termination, outside reset silence, nonexact in-window challenge and SYN challenge fields/drop. Matrix exercises sequence wrap and rejects appended text/URG/FIN/ACK effects.
//# 3) If the RST bit is set and the sequence number does not exactly
//# match the next expected sequence value, yet is within the current
//# receive window (RCV.NXT < SEG.SEQ < RCV.NXT+RCV.WND), TCP MUST
//# send an acknowledgment (challenge ACK):
// Actor/condition: TCP endpoint; selected blind-attack mitigation.
//= https://www.rfc-editor.org/rfc/rfc5961#section-3.2
//= type=test
//= reason=Selected RST/SYN defenses: existing state/sequence matrix asserts exact reset termination, outside reset silence, nonexact in-window challenge and SYN challenge fields/drop. Matrix exercises sequence wrap and rejects appended text/URG/FIN/ACK effects.
//# After sending the challenge ACK, TCP MUST drop the unacceptable
//# segment and stop processing the incoming packet further.
// Actor/condition: TCP endpoint; selected blind-attack mitigation.
//= https://www.rfc-editor.org/rfc/rfc5961#section-3.2
//= type=test
//= reason=Selected RST/SYN defenses: existing state/sequence matrix asserts exact reset termination, outside reset silence, nonexact in-window challenge and SYN challenge fields/drop. Matrix exercises sequence wrap and rejects appended text/URG/FIN/ACK effects.
//# In all other cases, where
//# the SEQ-field does not match and is outside the window, the receiver
//# MUST silently discard the segment.
// Actor/condition: TCP endpoint; selected blind-attack mitigation.
//= https://www.rfc-editor.org/rfc/rfc5961#section-4.2
//= type=test
//= reason=Selected RFC5961 mitigation challenges and drops synchronized non-handshake SYN regardless of TS presence/sequence, under the existing bounded challenge budget. Narrow RFC7323 missing-TS SHOULD departure accepts no data/ACK/metadata/TS updates; valid/stale TS still traverse PAWS and RST remains exempt. Precedence/output rollback matrix covers all three TS cases.
//# Instead, the handling of the SYN in the synchronized state SHOULD be
//# performed as follows:
// Actor/condition: TCP endpoint; selected blind-attack mitigation.
//= https://www.rfc-editor.org/rfc/rfc5961#section-4.2
//= type=test
//= reason=Selected RFC5961 mitigation challenges and drops synchronized non-handshake SYN regardless of TS presence/sequence, under the existing bounded challenge budget. Narrow RFC7323 missing-TS SHOULD departure accepts no data/ACK/metadata/TS updates; valid/stale TS still traverse PAWS and RST remains exempt. Precedence/output rollback matrix covers all three TS cases.
//# 1) If the SYN bit is set, irrespective of the sequence number, TCP
//# MUST send an ACK (also referred to as challenge ACK) to the remote
//# peer:
// Actor/condition: TCP endpoint; selected blind-attack mitigation.
//= https://www.rfc-editor.org/rfc/rfc5961#section-4.2
//= type=test
//= reason=Selected RFC5961 mitigation challenges and drops synchronized non-handshake SYN regardless of TS presence/sequence, under the existing bounded challenge budget. Narrow RFC7323 missing-TS SHOULD departure accepts no data/ACK/metadata/TS updates; valid/stale TS still traverse PAWS and RST remains exempt. Precedence/output rollback matrix covers all three TS cases.
//# After sending the acknowledgment, TCP MUST drop the unacceptable
//# segment and stop processing further.
// Actor/condition: TCP endpoint; selected blind-attack mitigation.
//= https://www.rfc-editor.org/rfc/rfc5961#section-4.2
//= type=test
//= reason=Selected RST/SYN defenses: existing state/sequence matrix asserts exact reset termination, outside reset silence, nonexact in-window challenge and SYN challenge fields/drop. Matrix exercises sequence wrap and rejects appended text/URG/FIN/ACK effects.
//# Upon receipt of a valid RST, the local TCP
//# endpoint MUST terminate its connection.
// Actor/condition: TCP endpoint; selected blind-attack mitigation.
//= https://www.rfc-editor.org/rfc/rfc5961#section-3.2
//= type=test
//= reason=This is the operative replacement list, not the preceding historical RFC793 rule. State matrix asserts outside-window RST does not schedule ACK or mutate state; verified erratum 4845 corrects only the historical list inequality.
//# 1) If the RST bit is set and the sequence number is outside the current receive window, silently drop the segment.
// Actor/condition: TCP endpoint; replacement RST mitigation, outside window.
fn rfc5961_reset_and_syn_state_matrix_drops_text_urgent_fin_and_ack() {
    for state in [
        State::SynReceived,
        State::Established,
        State::FinWait1,
        State::FinWait2,
        State::CloseWait,
        State::Closing,
        State::LastAck,
        State::TimeWait,
    ] {
        for control in [RST, SYN] {
            for offset in [0, 1, 64, u32::MAX] {
                let (mut a, _) = pair(config(64, 8), u32::MAX - 4);
                a.write(b"retained").unwrap();
                packet(&mut a, 40);
                a.state = state;
                // Exercise receive wrap as well as send wrap.
                a.receive = ReceiveBuffer::new(Seq(u32::MAX), 64).unwrap();
                a.advertised_edge = Seq(63);
                let next = a.receive.next();
                let high = a.snd_nxt;
                let before = (
                    a.snd_una,
                    a.snd_wnd,
                    a.wl1,
                    a.wl2,
                    a.progress_at,
                    a.last_received,
                );
                inject(
                    &mut a,
                    50,
                    next.wrapping_add(offset),
                    high,
                    control | ACK | URG | FIN,
                    0,
                    b"bad",
                );
                if control == RST && offset == 0 {
                    assert_eq!(a.state(), State::Closed);
                    assert_eq!(a.close_reason(), Some(CloseReason::Reset));
                    assert_eq!(a.next_deadline(), None);
                } else {
                    assert_eq!(a.state(), state);
                    assert_eq!(
                        (
                            a.snd_una,
                            a.snd_wnd,
                            a.wl1,
                            a.wl2,
                            a.progress_at,
                            a.last_received
                        ),
                        before
                    );
                    assert_eq!(
                        a.ack_pending || a.challenge_ack_pending,
                        control == SYN || offset == 1
                    );
                    if a.ack_pending || a.challenge_ack_pending {
                        let bytes = packet(&mut a, 50);
                        let ack = wire::parse(ip(tuple()), &bytes).unwrap();
                        assert_eq!(ack.header.flags, ACK);
                        assert_eq!(ack.header.sequence, high.0);
                        assert_eq!(ack.header.acknowledgment, next.0);
                    }
                }
                assert_eq!(a.receive.next(), next);
                assert_eq!(a.receive.readable(), 0);
                assert!(!a.receive.eof());
                assert_eq!(a.rcv_up, None);
                assert_eq!(a.send.len(), 8);
            }
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc5961#section-3.2
//= type=test
//= reason=Packet assertions cover real pending RTO/TLP/persist, new/urgent data, FIN and failed output; sender work and deadlines are unchanged and the next poll emits preserved work.
//# <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
//= https://www.rfc-editor.org/rfc/rfc5961#section-4.2
//= type=test
//= reason=Packet assertions cover real pending RTO/TLP/persist, new/urgent data, FIN and failed output; sender work and deadlines are unchanged and the next poll emits preserved work.
//# <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
fn rfc5961_challenge_preempts_sender_work_transactionally() {
    for control in [RST, SYN] {
        for work in ["rto", "tlp", "persist", "new"] {
            let (mut a, _) = if work == "tlp" {
                tlp_baseline_pair(u32::MAX - 500)
            } else {
                pair(config(4096, 1000), u32::MAX - 500)
            };
            a.set_nagle(false);
            let mut now = 100_001;
            if work != "new" {
                a.write(&[7; 1000]).unwrap();
                packet(&mut a, now);
                if work == "persist" {
                    let next = a.receive.next();
                    let una = a.snd_una;
                    inject(&mut a, now, next, una, ACK, 0, b"");
                }
                now = match work {
                    "tlp" => a.tlp_deadline.unwrap(),
                    "persist" => a.loss_timer.unwrap().1,
                    _ => a.rto_deadline.unwrap(),
                };
                a.timeout(now).unwrap();
            }
            assert_eq!(a.retx_pending, work == "rto");
            assert_eq!(a.tlp_pending, work == "tlp");
            assert_eq!(a.probe_pending, work == "persist");
            a.write_urgent(b"tail").unwrap();
            a.shutdown().unwrap();
            let high = a.snd_nxt;
            let next = a.receive.next();
            let deadlines = |c: &Connection| {
                [
                    c.rto_deadline,
                    c.tlp_deadline,
                    c.rack.deadline,
                    c.persist_deadline,
                    c.sws_deadline,
                    c.keepalive_deadline,
                    c.time_wait_deadline,
                    c.ecn_pause,
                ]
            };
            let work_state = |c: &Connection| {
                (
                    c.snd_una,
                    c.snd_nxt,
                    c.sample,
                    c.last_sent,
                    c.send.len(),
                    c.retx_pending,
                    c.tlp_pending,
                    c.probe_pending,
                    c.limited_pending,
                    c.persist_interval,
                    c.fin_sequence,
                    c.retransmit_burst,
                )
            };
            let before = (deadlines(&a), work_state(&a));
            inject(
                &mut a,
                now,
                next.wrapping_add(1),
                high,
                control | ACK | FIN | URG,
                0,
                b"bad",
            );
            assert!(a.challenge_ack_pending);
            assert!(!a.accepted_metadata);
            assert_eq!(a.receive.next(), next);
            assert_eq!(
                a.transmit(now + 1, &mut [0; 19]),
                Err(Error::OutputTooSmall)
            );
            assert!(a.challenge_ack_pending);
            assert_eq!(a.now, now);
            assert_eq!(a.challenge_ack_sent, 0);
            assert_eq!((deadlines(&a), work_state(&a)), before);
            let bytes = packet(&mut a, now + 2);
            let p = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(p.header.flags, ACK);
            assert_eq!(p.header.sequence, high.0);
            assert_eq!(p.header.acknowledgment, next.0);
            assert_eq!(p.header.urgent_pointer, 0);
            assert!(p.payload.is_empty());
            assert_eq!(a.last_output_ecn, 0);
            assert_eq!((deadlines(&a), work_state(&a)), before);
            assert!(!a.challenge_ack_pending);
            assert_eq!(a.challenge_ack_sent, 1);
            let bytes = packet(&mut a, now + 3);
            let p = wire::parse(ip(tuple()), &bytes).unwrap();
            assert!(!p.payload.is_empty());
            assert_eq!(
                p.payload[0],
                if work == "new" || work == "tlp" {
                    b't'
                } else {
                    7
                }
            );
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc5961#section-3.2
//= type=test
//= reason=Real passive and simultaneous-open SYN-RECEIVED RST challenges preempt pending initial/retransmitted SYN-ACK without consuming handshake work or changing timers; failed encode retries are pure ACKs.
//# <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
fn rfc5961_rst_challenge_preserves_pending_handshake_output() {
    for simultaneous in [false, true] {
        for synack_sent in [false, true] {
            let (mut a, _) = opening_for_close(config(64, 8), 100, simultaneous);
            if synack_sent {
                packet(&mut a, 20);
                let deadline = a.rto_deadline.unwrap();
                a.timeout(deadline).unwrap();
            }
            assert!(a.syn_pending);
            let now = a.now;
            let next = a.receive.next();
            let high = a.snd_nxt;
            let before = (a.syn_pending, a.rto_deadline, a.next_deadline(), a.sample);
            inject(&mut a, now, next.wrapping_add(1), high, RST, 0, b"bad");
            assert!(a.challenge_ack_pending);
            assert_eq!(a.transmit(now, &mut [0; 19]), Err(Error::OutputTooSmall));
            let bytes = packet(&mut a, now);
            let p = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(p.header.flags, ACK);
            assert_eq!(p.header.sequence, high.0);
            assert_eq!(p.header.acknowledgment, next.0);
            assert!(p.payload.is_empty());
            assert_eq!(
                (a.syn_pending, a.rto_deadline, a.next_deadline(), a.sample),
                before
            );
            let bytes = packet(&mut a, now);
            let p = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(p.header.flags & (SYN | ACK | FIN | RST), SYN | ACK);
            assert_eq!(p.header.sequence, a.iss.0);
        }
    }
}

#[test]
fn rfc5961_timestamp_syn_precedence_and_ecn_feedback() {
    for control in [SYN, RST] {
        for timestamp in [None, Some((0, u32::MAX)), Some((500, u32::MAX))] {
            for offset in [1, 1 << 30] {
                let cfg = ConnectionConfig {
                    timestamps: true,
                    ..config(64, 8)
                };
                let (mut a, _) = pair(cfg, 100);
                a.ts_recent = 100;
                a.ts_latest = 100;
                a.ecn_echo = true;
                a.ecn_cwr_pending = true;
                a.write(b"queued").unwrap();
                let next = a.receive.next();
                let high = a.snd_nxt;
                let before = (
                    a.ts_recent,
                    a.ts_latest,
                    a.ts_recent_at,
                    a.last_received,
                    a.snd_wnd,
                    a.rcv_up,
                );
                let segment = Segment {
                    header: Header {
                        source_port: 2000,
                        destination_port: 1000,
                        sequence: next.wrapping_add(offset).0,
                        acknowledgment: high.0,
                        flags: control | ACK | FIN | URG | CWR,
                        window: 0,
                        urgent_pointer: 9,
                    },
                    options: wire::Options {
                        timestamps: timestamp,
                        ..wire::Options::default()
                    },
                    raw_options: &[],
                    payload: b"rejected",
                };
                a.input_with_traffic_class(1000, 3, &segment).unwrap();
                assert_eq!(
                    (
                        a.ts_recent,
                        a.ts_latest,
                        a.ts_recent_at,
                        a.last_received,
                        a.snd_wnd,
                        a.rcv_up
                    ),
                    before
                );
                assert!(!a.accepted_metadata);
                assert_eq!(a.receive.next(), next);
                let expected = (control == SYN) || (control == RST && offset == 1);
                assert_eq!(a.challenge_ack_pending, expected);
                if expected {
                    let sent_at = a.last_timestamp_sent_at;
                    assert_eq!(a.transmit(1001, &mut [0; 31]), Err(Error::OutputTooSmall));
                    assert!(a.challenge_ack_pending);
                    assert_eq!(a.challenge_ack_sent, 0);
                    assert_eq!(a.last_timestamp_sent_at, sent_at);
                    assert_eq!(a.now, 1000);
                    let bytes = packet(&mut a, 1001);
                    let p = wire::parse(ip(tuple()), &bytes).unwrap();
                    assert_eq!(p.header.flags, ACK | ECE);
                    assert_eq!(p.header.sequence, high.0);
                    assert_eq!(p.header.acknowledgment, next.0);
                    assert_eq!(p.options.timestamps, Some((1, 100)));
                    assert!(p.payload.is_empty());
                    assert_eq!(a.last_output_ecn, 0);
                    assert!(a.ecn_cwr_pending);
                }
            }
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc5961#section-7
//= type=test
//= reason=Asserts nonzero validation, emission cap, coalescing/failed-output accounting, exact interval reset, independent connections and unthrottled normal ACKs.
//# 2) The values for both the time and number of ACKs SHOULD be tunable
//# by the system administrator to accommodate different perceived
//# levels of threat and/or system resources.
//= https://www.rfc-editor.org/rfc/rfc5961#section-7
//= type=test
//= reason=Asserts nonzero validation, emission cap, coalescing/failed-output accounting, exact interval reset, independent connections and unthrottled normal ACKs.
//# An implementation SHOULD include an ACK throttling mechanism to be
//# conservative.
//= https://www.rfc-editor.org/rfc/rfc5961#section-7
//= type=test
//= reason=Asserts nonzero validation, emission cap, coalescing/failed-output accounting, exact interval reset, independent connections and unthrottled normal ACKs.
//# The time limit SHOULD be tunable to help timeout brute force attacks
//# faster than a potential legitimate flood of RSTs.
//= https://www.rfc-editor.org/rfc/rfc5961#section-7
//= type=test
//= reason=Asserts nonzero validation, emission cap, coalescing/failed-output accounting, exact interval reset, independent connections and unthrottled normal ACKs.
//# 1) The system administrator can configure the number of challenge ACKs that can be sent out in a given interval. For example, in any 5 second window, no more than 10 challenge ACKs should be sent.
fn rfc5961_challenge_budget_reset_isolation_and_validation() {
    let cfg = ConnectionConfig {
        challenge_ack_limit: 2,
        challenge_ack_interval_us: 100,
        ..config(64, 8)
    };
    let (mut a, mut b) = pair(cfg.clone(), 100);
    for now in [40, 41] {
        let next = a.receive.next();
        let high = a.snd_nxt;
        for _ in 0..10 {
            inject(&mut a, now, next.wrapping_add(1), high, RST, 0, b"");
        }
        assert!(a.challenge_ack_pending);
        assert_eq!(a.transmit(now, &mut [0; 19]), Err(Error::OutputTooSmall));
        packet(&mut a, now);
        assert_eq!(a.challenge_ack_sent, (now - 39) as u32);
    }
    for now in [42, 139] {
        let next = a.receive.next();
        let high = a.snd_nxt;
        inject(&mut a, now, next.wrapping_add(1), high, RST, 0, b"");
        assert!(!a.challenge_ack_pending);
        assert_eq!(a.transmit(now, &mut [0; 64]), Ok(None));
    }
    let next = b.receive.next();
    let high = b.snd_nxt;
    inject(&mut b, 139, next.wrapping_add(1), high, RST, 0, b"");
    packet(&mut b, 139);
    assert_eq!(b.challenge_ack_sent, 1);
    let next = a.receive.next();
    let high = a.snd_nxt;
    inject(&mut a, 140, next.wrapping_add(1), high, RST, 0, b"");
    packet(&mut a, 140);
    assert_eq!(a.challenge_ack_sent, 1);
    // Ordinary ACK scheduling is neither throttled nor counted.
    a.immediate_ack();
    packet(&mut a, 141);
    assert_eq!(a.challenge_ack_sent, 1);
    inject(&mut a, 142, next, high, RST, 0, b"");
    assert_eq!(a.state(), State::Closed);
    assert!(!a.challenge_ack_pending);
    for cfg in [
        ConnectionConfig {
            challenge_ack_limit: 0,
            ..cfg.clone()
        },
        ConnectionConfig {
            challenge_ack_interval_us: 0,
            ..cfg
        },
    ] {
        assert!(matches!(
            Connection::active(tuple(), cfg, 100, 0),
            Err(Error::InvalidArgument)
        ));
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc5961#section-5.2
//= type=test
//= reason=Negotiated scale, growth/shrink/zero updates, historical maximum >65535 and modular inclusive ACK lower bound are asserted.
//# A new state variable MAX.SND.WND is defined as the largest window that the local sender has ever received from its peer. This window may be scaled to a value larger than 65,535 bytes ([RFC1323]).
fn rfc5961_max_sender_window_scaled_history() {
    let (mut a, _) = pair(config(262144, 1000), u32::MAX - 4);
    assert!(a.scaling && a.peer_scale > 0);
    // SYN-ACK initializes the history without applying negotiated scaling.
    assert_eq!(a.snd_wnd, 65535);
    assert_eq!(a.max_snd_wnd, 65535);
    let mut maximum = a.max_snd_wnd;
    for (i, window) in [10000, 60000, 1000, 0].into_iter().enumerate() {
        let next = a.receive.next();
        let una = a.snd_una;
        inject(&mut a, 40 + i as u64, next, una, ACK, window, b"");
        assert_eq!(a.snd_wnd, (window as u32) << a.peer_scale);
        maximum = maximum.max(a.snd_wnd);
        assert_eq!(a.max_snd_wnd, maximum);
    }
    assert!(maximum > 65535);
    let next = a.receive.next();
    let oldest = a.snd_una.wrapping_add(0u32.wrapping_sub(maximum));
    inject(&mut a, 50, next, oldest, ACK, 0, b"accepted");
    assert_eq!(a.receive.readable(), 8);
    let next = a.receive.next();
    inject(
        &mut a,
        51,
        next,
        oldest.wrapping_add(u32::MAX),
        ACK,
        0,
        b"bad",
    );
    assert_eq!(a.receive.readable(), 8);
    assert_eq!(a.max_snd_wnd, maximum);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# 2)  If the RST bit is set and the sequence number exactly
//# matches the next expected sequence number (RCV.NXT), then
//# TCP endpoints MUST reset the connection in the manner
//# prescribed below according to the connection state.
fn passive_syn_received_exception_releases_child_without_user_notification() {
    for control in [RST, SYN] {
        let mut a = Connection::active(tuple(), config(64, 8), 100, 0).unwrap();
        let bytes = packet(&mut a, 0);
        let syn = wire::parse(ip(tuple()), &bytes).unwrap();
        let mut b = Connection::passive(reverse(tuple()), config(64, 8), 900, 10, &syn).unwrap();
        packet(&mut b, 20);
        let next = b.receive.next();
        let high = b.snd_nxt;
        inject(
            &mut b,
            30,
            next,
            high,
            control | ACK | URG | FIN,
            0,
            b"ignored",
        );
        assert_eq!(b.state(), State::Closed);
        assert!(!b.events_pending());
        assert_eq!(b.receive.readable(), 0);
        assert_eq!(b.rcv_up, None);
        assert_eq!(b.next_deadline(), None);
        assert_eq!(b.transmit(40, &mut [0; 64]), Ok(None));
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1
//= type=test
//# A TCP implementation MAY keep its offered receive window closed
//# indefinitely (MAY-8).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
//= type=test
//# A TCP receiver SHOULD NOT shrink the window, i.e., move the right
//# window edge to the left (SHLD-14).
//= https://www.rfc-editor.org/rfc/rfc6429#section-1
//= type=test
//# A TCP MAY keep its offered receive window closed indefinitely.
fn receiver_zero_window_persists_without_reads_and_sender_probes_after_shrink() {
    let (mut a, mut b) = pair(config(4, 4), u32::MAX - 2);
    a.write(b"abcd").unwrap();
    let edge = b.advertised_edge;
    deliver(&mut a, &mut b, 40);
    let bytes = deliver(&mut b, &mut a, 50);
    assert_eq!(
        wire::parse(ip(reverse(tuple())), &bytes)
            .unwrap()
            .header
            .window,
        0
    );
    assert_eq!(b.advertised_edge, edge);
    a.write(b"efgh").unwrap();
    for _ in 0..10 {
        let deadline = a.loss_timer.unwrap().1;
        a.timeout(deadline).unwrap();
        let bytes = deliver(&mut a, &mut b, deadline);
        assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload.len(), 0);
        b.timeout(deadline).unwrap();
        let bytes = deliver(&mut b, &mut a, deadline);
        assert_eq!(
            wire::parse(ip(reverse(tuple())), &bytes)
                .unwrap()
                .header
                .window,
            0
        );
        assert_eq!(b.receive.readable(), 4);
        assert_eq!(b.advertised_edge, edge);
        assert_eq!(b.user_deadline(), None);
        assert_eq!(a.state(), State::Established);
    }
    // No response to the next probe: retain the resource/liveness bound.
    let when = a.loss_timer.unwrap().1;
    a.timeout(when).unwrap();
    packet(&mut a, when);
    let deadline = a.user_deadline().unwrap();
    a.timeout(deadline).unwrap();
    assert_eq!(a.close_reason(), Some(CloseReason::TimedOut));
    b.timeout(deadline).unwrap();
    assert_eq!(b.state(), State::Established);
    assert_eq!(b.advertised_window(false), 0);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
//= type=test
//# If the window shrinks to zero, the TCP
//# implementation MUST probe it in the standard way (described below)
//# (MUST-35).
fn shrink_to_zero_with_outstanding_bytes_probes_and_validates_liveness_feedback() {
    for iss in [100, u32::MAX - 4] {
        let (mut a, _) = pair(config(64, 8), iss);
        a.write(b"abcdefgh").unwrap();
        packet(&mut a, 40);
        let seq = a.receive.next();
        let una = a.snd_una;
        let high = a.snd_nxt;
        inject(&mut a, 50, seq, una, ACK, 0, b"");
        assert_eq!(a.loss_timer.unwrap().0, LossTimer::Rto);
        assert_eq!(a.user_deadline(), None);
        let when = a.loss_timer.unwrap().1;
        a.timeout(when).unwrap();
        let bytes = packet(&mut a, when);
        let probe = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(probe.header.sequence, una.0);
        assert_eq!(probe.payload, b"a");
        assert_eq!(a.snd_nxt, high);
        assert_eq!(a.send.len(), 8);
        let deadline = a.user_deadline();
        inject(
            &mut a,
            when + 1,
            seq,
            una.wrapping_add(u32::MAX),
            ACK,
            64,
            b"",
        );
        assert_eq!(a.user_deadline(), deadline);
        assert_eq!(a.snd_wnd, 0);
        inject(&mut a, when + 2, seq, una, ACK, 0, b"");
        assert_eq!(a.user_deadline(), None);
        inject(&mut a, when + 3, seq, una, ACK, 64, b"");
        assert_eq!(a.persist_deadline, None);
        assert_eq!(a.user_deadline(), Some(when + 3 + a.user_timeout()));
        let when = a.rto_deadline.unwrap();
        a.timeout(when).unwrap();
        let bytes = packet(&mut a, when);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().payload,
            b"a" // timer retry respects the latest probe transmission boundary
        );
    }
}
#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
//= type=test
//# but SHOULD NOT
//# time out the connection if data beyond the right window edge is not
//# acknowledged (SHLD-17).
fn shrink_peer_replying_only_to_retransmissions_survives_long_backoff() {
    for iss in [100, u32::MAX - 4] {
        let mut cfg = config(64, 8);
        cfg.user_timeout_us = 5_000_000;
        let (mut a, _) = pair(cfg, iss);
        // Exercise the conservative policy without negotiated scaling.
        a.scaling = false;
        a.write(b"abcdefgh").unwrap();
        packet(&mut a, 40);
        let seq = a.receive.next();
        let una = a.snd_una;
        inject(&mut a, 50, seq, una, ACK, 3, b"");
        for _ in 0..6 {
            assert_eq!(a.user_deadline(), None);
            let when = a.next_deadline().unwrap();
            assert_eq!(Some(when), a.rto_deadline);
            a.timeout(when).unwrap();
            assert_eq!(a.state(), State::Established);
            let bytes = packet(&mut a, when);
            let retransmit = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(retransmit.header.sequence, una.0);
            assert_eq!(retransmit.payload, b"abc");
            assert_eq!(a.user_deadline(), Some(when + 5_000_000));
            // No unsolicited feedback between emitted retransmissions.
            inject(&mut a, when + 1, seq, una, ACK, 3, b"");
            assert_eq!(a.shrink_unanswered_since, None);
            assert_eq!(a.flight(), 8);
            assert_eq!(a.send.len(), 8);
        }
        assert!(a.rto() > a.user_timeout());
        let when = a.next_deadline().unwrap();
        a.timeout(when).unwrap();
        packet(&mut a, when);
        // Reopening to exactly flight restores the ordinary progress timer.
        inject(&mut a, when + 1, seq, una, ACK, 8, b"");
        assert_eq!(a.shrink_unanswered_since, None);
        assert_eq!(a.user_deadline(), Some(when + 1 + 5_000_000));
        a.timeout(a.user_deadline().unwrap()).unwrap();
        assert_eq!(a.close_reason(), Some(CloseReason::TimedOut));
    }
}

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
//= type=test
//= reason=Checks both retransmission policies and survival beyond the user timeout while the shrunken peer answers without ACK progress.
//# The sender MAY also
//# retransmit old data beyond SND.UNA+SND.WND (MAY-7), but SHOULD NOT
//# time out the connection if data beyond the right window edge is not
//# acknowledged (SHLD-17).
#[test]
fn optional_beyond_window_retransmission_never_sends_new_bytes() {
    for iss in [100, u32::MAX - 3] {
        for enabled in [false, true] {
            let mut cfg = config(64, 8);
            cfg.retransmit_beyond_window = enabled;
            cfg.user_timeout_us = 5_000_000;
            let (mut a, _) = pair(cfg, iss);
            // Exercise the conservative policy without negotiated scaling.
            a.scaling = false;
            a.write(b"abcdefghijklmnop").unwrap();
            packet(&mut a, 40); // Only the first eight bytes have been sent.
            let seq = a.receive.next();
            let una = a.snd_una;
            let next = a.snd_nxt;
            inject(&mut a, 50, seq, una, ACK, 3, b"");
            assert_eq!(a.transmit(60, &mut [0; 64]), Ok(None));
            let deadline = a.rto_deadline.unwrap();
            a.timeout(deadline).unwrap();
            let retry = packet(&mut a, deadline);
            let segment = wire::parse(ip(tuple()), &retry).unwrap();
            assert_eq!(segment.header.sequence, una.0);
            assert_eq!(
                segment.payload,
                if enabled { &b"abcdefgh"[..] } else { b"abc" }
            );
            assert_eq!(a.last_output_ecn(), 0);
            assert_eq!(a.snd_nxt, next);
            assert_eq!(a.send.len(), 16);
            let mut last = deadline;
            for _ in 0..6 {
                inject(&mut a, last + 1, seq, una, ACK, 3, b"");
                assert_eq!(a.user_deadline(), None);
                last = a.rto_deadline.unwrap();
                a.timeout(last).unwrap();
                assert_eq!(a.state(), State::Established);
                let retry = packet(&mut a, last);
                assert_eq!(
                    wire::parse(ip(tuple()), &retry).unwrap().payload,
                    if enabled { &b"abcdefgh"[..] } else { b"abc" }
                );
                assert_eq!(a.snd_nxt, next);
            }
            assert!(last - 50 > a.user_timeout());
            inject(&mut a, last + 1, seq, una, ACK, 0, b"");
            let deadline = a.loss_timer.unwrap().1;
            a.timeout(deadline).unwrap();
            let probe = packet(&mut a, deadline);
            assert_eq!(wire::parse(ip(tuple()), &probe).unwrap().payload, b"a");
            assert_eq!(a.snd_nxt, next);
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
//= type=test
//= reason=Negotiated non-SACK Reno/NewReno: ecn_duplicate_and_advancing_ack_growth_boundaries asserts entry/later duplicate-ECE suppression and advancing/non-ECE contrasts; ecn_duplicate_entry_below_threshold_and_covering_ack_exit traces successive reductions to cwnd<ssthresh, capped ECE entry and covering-ECE exit, normal non-ECE exit and preserved wire retransmission. No general inherited recovery-compliance claim.
//# The sending
//# TCP SHOULD NOT increase the congestion window in response to the
//# receipt of an ECN-Echo ACK packet.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
//= type=test
//= reason=Connection-boundary otherwise-identical ACK traces contrast ordinary MSS growth with advancing ECE suppression and non-ECE duplicate recovery inflation, for Reno/NewReno and ECN on/off.
//# TCP also follows the normal procedures for increasing the congestion window when it receives ACK packets without the ECN-Echo bit set [RFC2581].
fn ecn_duplicate_and_advancing_ack_growth_boundaries() {
    for algorithm in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
        for enabled in [false, true] {
            for marked in [false, true] {
                let mut cfg = config(8192, 64);
                cfg.recovery_algorithm = algorithm;
                cfg.ecn = enabled;
                let (mut a, _) = pair(cfg.clone(), u32::MAX - 255);
                prime_newreno(&mut a);
                a.write(&[1; 256]).unwrap();
                for _ in 0..4 {
                    packet(&mut a, 40);
                }
                let una = a.snd_una;
                let seq = a.receive.next();
                let flags = ACK | if marked { ECE } else { 0 };
                let accepted_ece = enabled && marked;
                for count in 1..=5 {
                    let before = a.congestion.cwnd();
                    inject(&mut a, 41, seq, una, flags, 8192, b"");
                    if accepted_ece {
                        assert!(a.congestion.cwnd() <= before);
                    }
                    if count == 3 {
                        assert!(a.retx_pending);
                        let threshold = a.congestion.ssthresh();
                        assert_eq!(a.transmit(41, &mut [0; 20]), Err(Error::OutputTooSmall));
                        assert!(a.retx_pending);
                        let bytes = packet(&mut a, 41);
                        let retry = wire::parse(ip(tuple()), &bytes).unwrap();
                        assert_eq!(retry.header.sequence, una.0);
                        assert_eq!(retry.header.flags & CWR, 0);
                        assert_eq!(a.last_output_ecn(), 0);
                        assert_eq!(a.congestion.ssthresh(), threshold);
                    }
                    if count > 3 && !accepted_ece {
                        assert_eq!(a.congestion.cwnd(), before + 64);
                    }
                }
                // Same accepted advancing ACK: ordinary growth versus ECE suppression.
                let (mut a, _) = pair(cfg, 10);
                a.write(&[1; 128]).unwrap();
                packet(&mut a, 40);
                packet(&mut a, 40);
                let before = a.congestion.cwnd();
                let seq = a.receive.next();
                let ack = a.snd_una.wrapping_add(64);
                inject(&mut a, 41, seq, ack, flags, 8192, b"");
                if accepted_ece {
                    assert!(a.congestion.cwnd() < before);
                } else {
                    assert_eq!(a.congestion.cwnd(), before + 64);
                }
            }
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
//= type=test
//= reason=Reno/NewReno wire/control traces use successive ECE reductions to reach cwnd=64 below ssthresh=128, then assert duplicate-ECE recovery entry, Not-ECT retransmission and covering-ECE exit keep cwnd=64; otherwise-identical non-ECE exit restores 128. Includes sequence wrap; no private congestion state overrides.
//# The sending
//# TCP SHOULD NOT increase the congestion window in response to the
//# receipt of an ECN-Echo ACK packet.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
//= type=test
//= reason=Otherwise-identical Reno/NewReno recovery traces contrast ECE exit capped at 64 with non-ECE exit restoring ssthresh/flight-bound 128, after duplicate-ECE entry below threshold.
//# TCP also follows the normal procedures for increasing the congestion window when it receives ACK packets without the ECN-Echo bit set [RFC2581].
fn ecn_duplicate_entry_below_threshold_and_covering_ack_exit() {
    for algorithm in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
        for iss in [100, u32::MAX - 95] {
            for exit_ece in [false, true] {
                let mut cfg = config(8192, 64);
                cfg.recovery_algorithm = algorithm;
                cfg.ecn = true;
                let (mut a, _) = pair(cfg, iss);
                let seq = a.receive.next();
                // Two real, separately covered ECN flights reach the MSS floor.
                for (now, expected) in [(40, 128), (50, 64)] {
                    a.write(&[1; 64]).unwrap();
                    let bytes = packet(&mut a, now);
                    let data = wire::parse(ip(tuple()), &bytes).unwrap();
                    assert_eq!(data.header.sequence, a.snd_una.0);
                    assert_eq!(data.payload, &[1; 64]);
                    assert_eq!(a.last_output_ecn(), 2);
                    assert_eq!(data.header.flags & CWR != 0, now == 50);
                    let end = a.snd_nxt;
                    inject(&mut a, now + 1, seq, end, ACK | ECE, 8192, b"");
                    assert_eq!(a.flight(), 0);
                    assert_eq!(
                        (a.congestion.cwnd(), a.congestion.ssthresh()),
                        (expected, 128)
                    );
                    assert!(!a.retx_pending);
                }
                a.write(&[2; 64]).unwrap();
                let bytes = packet(&mut a, 60);
                let data = wire::parse(ip(tuple()), &bytes).unwrap();
                let una = a.snd_una;
                let end = a.snd_nxt;
                assert_eq!(data.header.sequence, una.0);
                assert_eq!(data.payload, &[2; 64]);
                assert_ne!(data.header.flags & CWR, 0);
                assert_eq!(a.flight(), 64);
                for count in 1..=3 {
                    inject(&mut a, 60 + count, seq, una, ACK | ECE, 8192, b"");
                    assert_eq!((a.congestion.cwnd(), a.congestion.ssthresh()), (64, 128));
                    assert_eq!(a.congestion.in_recovery(), count == 3);
                    assert_eq!(a.retx_pending, count == 3);
                }
                let bytes = packet(&mut a, 63);
                let retry = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(retry.header.sequence, una.0);
                assert_eq!(retry.payload, &[2; 64]);
                assert_eq!(retry.header.flags & CWR, 0);
                assert_eq!(a.last_output_ecn(), 0);
                assert_eq!(a.snd_nxt, end);
                assert!(!a.retx_pending);
                let flags = ACK | if exit_ece { ECE } else { 0 };
                inject(&mut a, 64, seq, end, flags, 8192, b"");
                assert_eq!(a.congestion.cwnd(), if exit_ece { 64 } else { 128 });
                assert_eq!(a.congestion.ssthresh(), 128);
                assert!(!a.congestion.in_recovery());
                assert!(!a.retx_pending);
                assert_eq!(a.flight(), 0);
                assert_eq!(a.send.len(), 0);
                assert_eq!(a.rto_deadline, None);
            }
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.6
//= type=test
//= reason=Validated exact-sequence zero-window ACK probes latch CE and return ECE without admitting payload or granting receive credit; boundary tests assert invalid sequence/ACK rejection, ECN-off, failed output and unchanged receive stream. Sender probes remain Not-ECT without CWR.
//# Therefore, if
//# a window probe arrives with the CE codepoint set, then the receiver
//# SHOULD respond to the ECN indications.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Negotiated receive commitment gates CE handling after sequence/control/ACK validation, including exact-sequence zero-window probes without receive credit. Tests cover normal CE, repeated feedback, fallback commitment, invalid packets and ECN-off receive.
//# * If a host has sent at least one ECN-setup SYN or ECN-setup SYN-
//# ACK packet, and has received no non-ECN-setup SYN or non-ECN-
//# setup SYN-ACK packet, then if that host receives TCP data
//# packets with ECT and CE codepoints set in the IP header, then
//# that host MUST process these packets as specified for an ECN-
//# capable connection.
fn ecn_zero_window_ce_probe_validation_and_no_receive_credit() {
    for enabled in [false, true] {
        let mut cfg = config(64, 64);
        cfg.ecn = enabled;
        let (mut a, mut b) = pair(cfg, u32::MAX - 63);
        a.write(&[1; 64]).unwrap();
        deliver(&mut a, &mut b, 40);
        deliver(&mut b, &mut a, 40);
        assert_eq!(b.receive_window(), 0);
        a.write(&[2; 64]).unwrap();
        let deadline = a.loss_timer.unwrap().1;
        a.timeout(deadline).unwrap();
        a.ecn_cwr_pending = enabled;
        let bytes = packet(&mut a, deadline);
        let mut probe = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(probe.payload.len(), 0);
        assert_eq!(a.last_output_ecn(), 0);
        assert_eq!(probe.header.flags & CWR, 0);
        assert_eq!(a.ecn_cwr_pending, enabled);
        let next = b.receive.next();
        assert_eq!(probe.header.sequence, next.wrapping_add(u32::MAX).0);
        // Our empty old-sequence control does not admit stream data.
        // Still accept and validate data-octet probes used by other peers.
        probe.payload = &[2];
        for (seq, ack, flags) in [
            (next.wrapping_add(1).0, b.snd_una.0, ACK),
            (next.wrapping_add(u32::MAX).0, b.snd_una.0, ACK),
            (next.0, b.snd_nxt.wrapping_add(1).0, ACK),
            (
                next.0,
                b.snd_una
                    .wrapping_add(0u32.wrapping_sub(b.max_snd_wnd + 1))
                    .0,
                ACK,
            ),
            (next.0, b.snd_una.0, 0),
        ] {
            probe.header.sequence = seq;
            probe.header.acknowledgment = ack;
            probe.header.flags = flags;
            b.input_with_traffic_class(deadline, 3, &probe).unwrap();
            assert!(!b.ecn_echo);
            assert_eq!(b.receive.next(), next);
        }
        probe.header.sequence = next.0;
        probe.header.acknowledgment = b.snd_una.0;
        probe.header.flags = ACK;
        b.input_with_traffic_class(deadline, 3, &probe).unwrap();
        assert_eq!(b.ecn_echo, enabled);
        assert_eq!(b.receive.next(), next);
        assert_eq!(b.receive_window(), 0);
        assert_eq!(
            b.transmit(deadline, &mut [0; 19]),
            Err(Error::OutputTooSmall)
        );
        assert_eq!(b.ecn_echo, enabled);
        let ack = packet(&mut b, deadline);
        let ack = wire::parse(ip(reverse(tuple())), &ack).unwrap();
        assert_eq!(ack.header.acknowledgment, next.0);
        assert_eq!(ack.header.window, 0);
        assert_eq!(ack.header.flags & ECE != 0, enabled);
        assert_eq!(b.last_output_ecn(), 0);
        let mut read = [0; 128];
        assert_eq!(b.read(&mut read), Ok(64));
        assert_eq!(&read[..64], &[1; 64]);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.3
//= type=test
//= reason=Receive CE latch survives to the next ACK; two-packet aggregate tests mark either first or second segment, assert cumulative coverage of both and ECE, and contrast ECN-off. Immediate ACK scheduling on CE is retained.
//# When TCP receives a CE data packet at the destination end-system, the TCP data receiver sets the ECN-Echo flag in the TCP header of the subsequent ACK packet. If there is any ACK withholding implemented, as in current "delayed-ACK" TCP implementations where the TCP receiver can send an ACK for two arriving data packets, then the ECN-Echo flag in the ACK packet will be set to '1' if the CE codepoint is set in any of the data packets being acknowledged. That is, if any of the received data packets are CE packets, then the returning ACK has the ECN-Echo flag set.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1.1
//= type=test
//= reason=Setup flags alone establish ECN capability; explicit ECN-off receive tests inject CE and ECT without enabling ECN or ECE, then assert outgoing data remains Not-ECT.
//# a host is forbidden from using the reception of ECT data packets as an implicit signal that the other host is ECN- capable.
fn ecn_delayed_ack_aggregate_and_nonnegotiated_ect() {
    for enabled in [false, true] {
        for marked in [0, 1] {
            let mut cfg = config(1024, 64);
            cfg.ecn = enabled;
            let (mut a, mut b) = pair(cfg, 10);
            a.write(&[1; 128]).unwrap();
            let first = packet(&mut a, 40);
            let second = packet(&mut a, 40);
            for (index, bytes) in [first, second].iter().enumerate() {
                let segment = wire::parse(ip(tuple()), bytes).unwrap();
                b.input_with_traffic_class(40, if index == marked { 3 } else { 2 }, &segment)
                    .unwrap();
                assert_eq!(b.ecn_send(), enabled);
                if index == 0 && marked == 1 {
                    assert_eq!(b.transmit(40, &mut [0; 2048]), Ok(None));
                }
            }
            let bytes = packet(&mut b, 40);
            let ack = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
            assert_eq!(ack.header.acknowledgment, a.snd_nxt.0);
            assert_eq!(ack.header.flags & ECE != 0, enabled);
            b.write(&[2; 64]).unwrap();
            packet(&mut b, 41);
            assert_eq!(b.last_output_ecn(), if enabled { 2 } else { 0 });
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Terminal entry disables receive/send ECN commitment and clears echo/CWR; TIME-WAIT/CLOSED tests assert ignored negotiation and fresh same-tuple connections require new setup.
//# When a TCP host enters TIME-WAIT or CLOSED state, it should ignore any previous state about the negotiation of ECN for that connection.
fn ecn_terminal_and_reused_tuple_require_new_negotiation() {
    for timewait in [false, true] {
        let (mut a, _) = pair(config(1024, 64), 10);
        assert!(a.ecn_send());
        a.ecn_echo = true;
        a.ecn_cwr_pending = true;
        if timewait {
            a.time_wait();
        } else {
            a.terminal(CloseReason::Reset);
        }
        assert!(!a.ecn_send() && !a.ecn_feedback());
        assert!(!a.ecn_echo && !a.ecn_cwr_pending);
        let mut cfg = config(1024, 64);
        cfg.ecn = false;
        let (mut fresh, _) = pair(cfg, 1000);
        assert_eq!(fresh.tuple(), a.tuple());
        assert!(!fresh.ecn_send() && !fresh.ecn_feedback());
        fresh.write(&[0; 64]).unwrap();
        let bytes = packet(&mut fresh, 40);
        assert_eq!(fresh.last_output_ecn(), 0);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.flags & (ECE | CWR),
            0
        );
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
//= type=test
//= reason=First-fresh CWR tests cover RTO, Reno/NewReno fast retransmit, SACK and RACK/PRR reductions; TLP repaired-loss trace asserts CWR only after actual reduction. ECN and idle tests plus shared successful fresh-data commit cover other causes and failed encoding.
//# When an ECN-Capable TCP sender reduces its congestion window for any reason (because of a retransmit timeout, a Fast Retransmit, or in response to an ECN Notification), the TCP sender sets the CWR flag in the TCP header of the first new data packet sent after the window reduction.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Shared fresh-data-only CWR predicate and transactional commit preserve signaling through failed outputs, pure ACK, persist, keepalive, FIN-only and retransmissions; tests assert first-fresh CWR and clearing after ECN, RTO, Reno/NewReno, SACK, RACK/PRR, TLP repaired loss and idle reduction.
//# * If a host ever sets the ECT codepoint on a data packet, then
//# that host MUST correctly set/clear the CWR TCP bit on all
//# subsequent packets in the connection.
fn ecn_first_fresh_cwr_after_each_loss_recovery_mode() {
    for mode in 0..5 {
        for iss in [100, u32::MAX - 20_000] {
            let mut a = match mode {
                3 => sack_flight(1000, iss, 6),
                4 => rack_flight(iss),
                _ => {
                    let mut cfg = config(32_000, 1000);
                    cfg.recovery_algorithm = if mode == 1 {
                        RecoveryAlgorithm::Reno
                    } else {
                        RecoveryAlgorithm::NewReno
                    };
                    let (mut a, _) = pair(cfg, iss);
                    prime_newreno(&mut a);
                    a.write(&[1; 4000]).unwrap();
                    for _ in 0..4 {
                        packet(&mut a, 100_000);
                    }
                    a
                }
            };
            let next = a.snd_nxt;
            let seq = a.receive.next();
            let una = a.snd_una;
            let now = match mode {
                0 => {
                    let d = a.rto_deadline.unwrap();
                    a.timeout(d).unwrap();
                    d
                }
                1 | 2 => {
                    for _ in 0..3 {
                        inject(&mut a, 200_000, seq, una, ACK, 32_000, b"");
                    }
                    200_000
                }
                3 => {
                    sack_ack(&mut a, 200_000, una, &[(una.wrapping_add(1000).0, next.0)]);
                    200_000
                }
                _ => {
                    rack_sack(&mut a, 200_000, 0, &[(7000, 8000)]);
                    a.timeout(225_000).unwrap();
                    225_000
                }
            };
            assert!(a.ecn_cwr_pending);
            assert_eq!(a.transmit(now, &mut [0; 20]), Err(Error::OutputTooSmall));
            assert!(a.ecn_cwr_pending);
            let retry = packet(&mut a, now);
            assert_eq!(
                wire::parse(ip(tuple()), &retry).unwrap().header.flags & CWR,
                0
            );
            assert_eq!(a.last_output_ecn(), 0);
            if mode >= 3 {
                sack_ack(&mut a, now + 1, next, &[]);
            } else {
                inject(&mut a, now + 1, seq, next, ACK, 32_000, b"");
            }
            a.write(&[2; 2000]).unwrap();
            a.set_nagle(false);
            assert_eq!(
                a.transmit(now + 2, &mut [0; 20]),
                Err(Error::OutputTooSmall)
            );
            assert!(a.ecn_cwr_pending);
            let bytes = packet(&mut a, now + 2);
            let first = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(first.header.sequence, next.0);
            assert_ne!(first.header.flags & CWR, 0);
            assert_eq!(a.last_output_ecn(), 2);
            let ack = a.snd_nxt;
            inject(&mut a, now + 3, seq, ack, ACK, 8192, b"");
            let bytes = packet(&mut a, now + 4);
            assert_eq!(
                wire::parse(ip(tuple()), &bytes).unwrap().header.flags & CWR,
                0
            );
            assert_eq!(a.last_output_ecn(), 2);
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc3168#section-5.2
//= type=test
//= reason=Shared fresh-data output predicate excludes setup, pure ACK, reset, FIN-only, keepalive, persist and retransmitted packets. Fresh FIFO bytes (including Limited Transmit, recovery new data, data/FIN and original TLP) advance tracked sequence space and remain subject to loss recovery. Assertions cover special ECT/Not-ECT outputs, original TLP loss RTO and corrupted CE loss congestion response; no router marking claim.
//# To ensure the reliable delivery of the congestion indication
//# of the CE codepoint, an ECT codepoint MUST NOT be set in a packet
//# unless the loss of that packet in the network would be detected by
//# the end nodes and interpreted as an indication of congestion.
fn ecn_limited_transmit_and_original_tlp_loss_remain_congestion_signals() {
    let (mut a, _) = pair(config(8192, 64), 10);
    prime_newreno(&mut a);
    a.write(&[1; 384]).unwrap();
    for _ in 0..4 {
        packet(&mut a, 40);
    }
    let seq = a.receive.next();
    let una = a.snd_una;
    let cwnd = a.congestion.cwnd();
    for _ in 0..2 {
        inject(&mut a, 41, seq, una, ACK, 8192, b"");
        let bytes = packet(&mut a, 41);
        assert_eq!(a.last_output_ecn(), 2);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.flags & CWR,
            0
        );
        assert_eq!(a.congestion.cwnd(), cwnd);
    }
    assert_eq!(a.limited_sent, 128);
    inject(&mut a, 42, seq, una, ACK, 8192, b"");
    assert_eq!(a.congestion.ssthresh(), 128); // Limited bytes excluded.
    let retry = packet(&mut a, 42);
    assert_eq!(a.last_output_ecn(), 0);
    assert_eq!(
        wire::parse(ip(tuple()), &retry).unwrap().header.flags & CWR,
        0
    );

    let (mut a, _) = tlp_baseline_pair(u32::MAX - 1999);
    a.write(&[1; 6000]).unwrap();
    for _ in 0..4 {
        packet(&mut a, 100_000);
    }
    a.timeout(300_000).unwrap();
    packet(&mut a, 300_000);
    assert_eq!(a.last_output_ecn(), 2);
    assert!(a.tlp_end.is_some_and(|(_, _, retransmit)| !retransmit));
    let before = a.congestion.cwnd();
    let deadline = a.rto_deadline.unwrap();
    a.timeout(deadline).unwrap();
    assert!(a.congestion.cwnd() < before);
    assert!(a.ecn_cwr_pending);
    packet(&mut a, deadline);
    assert_eq!(a.last_output_ecn(), 0);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Shared fresh-data-only CWR predicate and transactional commit preserve signaling through failed outputs, pure ACK, persist, keepalive, FIN-only and retransmissions; tests assert first-fresh CWR and clearing after ECN, RTO, Reno/NewReno, SACK, RACK/PRR, TLP repaired loss and idle reduction.
//# * If a host ever sets the ECT codepoint on a data packet, then
//# that host MUST correctly set/clear the CWR TCP bit on all
//# subsequent packets in the connection.
//= https://www.rfc-editor.org/rfc/rfc3168#section-5.2
//= type=test
//= reason=Shared fresh-data output predicate excludes setup, pure ACK, reset, FIN-only, keepalive, persist and retransmitted packets. Fresh FIFO bytes (including Limited Transmit, recovery new data, data/FIN and original TLP) advance tracked sequence space and remain subject to loss recovery. Assertions cover special ECT/Not-ECT outputs, original TLP loss RTO and corrupted CE loss congestion response; no router marking claim.
//# To ensure the reliable delivery of the congestion indication
//# of the CE codepoint, an ECT codepoint MUST NOT be set in a packet
//# unless the loss of that packet in the network would be detected by
//# the end nodes and interpreted as an indication of congestion.
fn ecn_special_controls_preserve_cwr_for_fresh_fin_data() {
    for garbage in [false, true] {
        let (mut a, _) = pair(config(1024, 64), 10);
        a.ecn_cwr_pending = true;
        a.immediate_ack();
        let bytes = packet(&mut a, 40);
        assert_eq!(a.last_output_ecn(), 0);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.flags & CWR,
            0
        );
        assert!(a.ecn_cwr_pending);
        a.set_keepalive(Some(KeepaliveConfig {
            idle_us: 100,
            interval_us: 50,
            probes: 2,
            send_garbage: garbage,
        }))
        .unwrap();
        let deadline = a.keepalive_deadline.unwrap();
        a.timeout(deadline).unwrap();
        let bytes = packet(&mut a, deadline);
        assert_eq!(a.last_output_ecn(), 0);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.flags & CWR,
            0
        );
        assert!(a.ecn_cwr_pending);
        a.write(&[1; 64]).unwrap();
        a.shutdown().unwrap();
        let bytes = packet(&mut a, deadline + 1);
        let data_fin = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(data_fin.payload, &[1; 64]);
        assert_ne!(data_fin.header.flags & CWR, 0);
        assert_ne!(data_fin.header.flags & FIN, 0);
        assert_eq!(a.last_output_ecn(), 2);
        assert!(!a.ecn_cwr_pending);
        a.abort();
        let bytes = packet(&mut a, deadline + 2);
        assert_ne!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.flags & RST,
            0
        );
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.flags & CWR,
            0
        );
        assert_eq!(a.last_output_ecn(), 0);
    }
    let (mut a, _) = pair(config(1024, 64), 10);
    a.ecn_cwr_pending = true;
    a.shutdown().unwrap();
    let bytes = packet(&mut a, 40);
    assert_ne!(
        wire::parse(ip(tuple()), &bytes).unwrap().header.flags & FIN,
        0
    );
    assert_eq!(
        wire::parse(ip(tuple()), &bytes).unwrap().header.flags & CWR,
        0
    );
    assert_eq!(a.last_output_ecn(), 0);
    assert!(a.ecn_cwr_pending);
}

#[test]
fn ecn_duplex_reordering_old_ack_preserves_receive_feedback() {
    for iss in [100, u32::MAX - 63] {
        let (mut a, mut b) = pair(config(1024, 64), iss);
        a.write(&[1; 192]).unwrap();
        let old_cwr = packet(&mut a, 40);
        let ce = packet(&mut a, 40);
        let new_cwr = packet(&mut a, 40);
        let old_ack = b.snd_una;
        // Reverse-direction data is ACKed while the duplex packets are delayed.
        b.write(&[2; 128]).unwrap();
        deliver(&mut b, &mut a, 41);
        packet(&mut b, 41); // Leave some reverse-direction data in flight.
        a.immediate_ack();
        deliver(&mut a, &mut b, 42);
        assert_eq!(b.snd_una, old_ack.wrapping_add(64));
        assert_eq!(b.flight(), 64);
        let cwnd = b.congestion.cwnd();
        let mut ce = wire::parse(ip(tuple()), &ce).unwrap();
        assert_eq!(Seq(ce.header.acknowledgment), old_ack);
        ce.header.flags |= ECE;
        b.input_with_traffic_class(43, 3, &ce).unwrap();
        assert!(b.ecn_echo);
        assert_eq!(b.congestion.cwnd(), cwnd); // Stale ECE is still ignored.
        assert!(!b.ecn_cwr_pending);
        let echo = packet(&mut b, 43);
        assert_ne!(
            wire::parse(ip(reverse(tuple())), &echo)
                .unwrap()
                .header
                .flags
                & ECE,
            0
        );
        // The earlier CWR is sequence-valid (fills the hole), but predates CE.
        let mut old_cwr = wire::parse(ip(tuple()), &old_cwr).unwrap();
        old_cwr.header.flags |= CWR;
        b.input(44, &old_cwr).unwrap();
        assert!(b.ecn_echo);
        let echo = packet(&mut b, 44);
        assert_ne!(
            wire::parse(ip(reverse(tuple())), &echo)
                .unwrap()
                .header
                .flags
                & ECE,
            0
        );
        // A later CWR clears CE even though its duplex ACK is also old.
        let mut new_cwr = wire::parse(ip(tuple()), &new_cwr).unwrap();
        new_cwr.header.flags |= CWR;
        b.input(45, &new_cwr).unwrap();
        assert!(!b.ecn_echo);
        assert_eq!(b.ecn_ce_end, None);
        assert_eq!(b.read(&mut [0; 192]), Ok(192));
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
//= type=test
//= reason=Reno/NewReno helper epoch/threshold assertions plus connection emitted-retransmission-versus-pending-loss RTO assertions. No router congestion-detection claim.
//# TCP should not react to congestion indications more than once every window of data (or more loosely, more than once every round-trip time). That is, the TCP sender's congestion window should be reduced only once in response to a series of dropped and/or CE packets from a single window of data. In addition, the TCP source should not decrease the slow-start threshold, ssthresh, if it has been decreased within the last round trip time. However, if any retransmitted packets are dropped, then this is interpreted by the source TCP as a new instance of congestion.
// Actor/condition: TCP endpoint; mixed ECN/loss epoch and lost retransmission.
//= https://www.rfc-editor.org/rfc/rfc3168#section-5
//= type=test
//= reason=Original-flight reduction epoch assertions combine ECN and actual loss; retransmission loss remains a new event, as refined in section 6.1.2.
//# An additional goal is that the end-systems should react to congestion at most once per window of data (i.e., at most once per round-trip time), to avoid reacting multiple times to multiple indications of congestion within a round-trip time.
// Actor/condition: TCP endpoint; multiple indications within original-flight epoch.
fn ecn_rto_distinguishes_emitted_retransmission_from_pending_original_loss() {
    for iss in [100, u32::MAX - 20_000] {
        for emit_partial_retransmission in [false, true] {
            let (mut a, _) = pair(config(32_000, 1000), iss);
            let seq = a.receive.next();
            // Grow a real send window to sixteen MSS before inducing congestion.
            for _ in 0..12 {
                a.write(&[1; 1000]).unwrap();
                packet(&mut a, 40);
                let ack = a.snd_nxt;
                inject(&mut a, 40, seq, ack, ACK, 32_000, b"");
            }
            a.write(&[2; 16_000]).unwrap();
            for _ in 0..16 {
                packet(&mut a, 41);
            }
            assert_eq!(a.flight(), 16_000);
            let una = a.snd_una;
            for _ in 0..3 {
                inject(&mut a, 42, seq, una, ACK | ECE, 32_000, b"");
            }
            assert_eq!(a.congestion.ssthresh(), 8000);
            assert!(a.retx_pending);
            packet(&mut a, 43); // Fast retransmit is delivered; its ACK is partial.
            inject(&mut a, 44, seq, una.wrapping_add(12_000), ACK, 32_000, b"");
            assert_eq!(a.flight(), 4000);
            assert!(a.retx_pending);
            assert_eq!(a.transmit(45, &mut [0; 20]), Err(Error::OutputTooSmall));
            if emit_partial_retransmission {
                let bytes = packet(&mut a, 45); // This retransmission is lost.
                let segment = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(segment.header.sequence, a.snd_una.0);
                assert_eq!(segment.payload.len(), 1000);
            }
            let deadline = a.rto_deadline.unwrap();
            a.timeout(deadline).unwrap();
            let threshold = if emit_partial_retransmission {
                2000
            } else {
                8000
            };
            assert_eq!(a.congestion.ssthresh(), threshold);
            assert_eq!(a.congestion.cwnd(), 1000);
            packet(&mut a, deadline);
            a.timeout(a.rto_deadline.unwrap()).unwrap();
            assert_eq!(a.congestion.ssthresh(), threshold); // Repeated RTO.
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc3168#section-5
//= type=test
//= reason=TCP sender reduction only: helper asserts cwnd/threshold reduction, mixed loss/ECN epoch and no duplicate response; connection asserts repeated ECE and no ECN-driven retransmission. Generic non-TCP transports are not provided.
//# Upon the receipt by an ECN-Capable transport of a single CE packet,
//# the congestion control algorithms followed at the end-systems MUST be
//# essentially the same as the congestion control response to a *single*
//# dropped packet.
// Actor/condition: TCP sender/congestion controller; single CE indication in eligible original-flight epoch.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Negotiated receive commitment gates CE handling after sequence/control/ACK validation, including exact-sequence zero-window probes without receive credit. Tests cover normal CE, repeated feedback, fallback commitment, invalid packets and ECN-off receive.
//# * If a host has sent at least one ECN-setup SYN or ECN-setup SYN-
//# ACK packet, and has received no non-ECN-setup SYN or non-ECN-
//# setup SYN-ACK packet, then if that host receives TCP data
//# packets with ECT and CE codepoints set in the IP header, then
//# that host MUST process these packets as specified for an ECN-
//# capable connection.
// Actor/condition: TCP receiver; sent setup and received no plain setup; ECN data received.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.5
//= type=test
//= reason=Sender retransmission Not-ECT asserted at endpoint; receiver invalid/out-of-window CE rejection asserted at sequence/ACK boundaries. TCP roles only, no network marking behavior.
//# This document specifies ECN-capable TCP implementations MUST NOT set
//# either ECT codepoint (ECT(0) or ECT(1)) in the IP header for
//# retransmitted data packets, and that the TCP data receiver SHOULD
//# ignore the ECN field on arriving data packets that are outside of the
//# receiver's current window.
// Actor/condition: TCP sender and receiver; retransmitted data output and out-of-window received data.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.5
//= type=test
//= reason=Sender retransmission Not-ECT asserted at endpoint; receiver invalid/out-of-window CE rejection asserted at sequence/ACK boundaries. TCP roles only, no network marking behavior.
//# To prevent such a denial-of-service attack, we
//# specify that a legitimate TCP data sender MUST NOT set an ECT
//# codepoint on retransmitted data packets, and that the TCP data
//# receiver SHOULD ignore the CE codepoint on out-of-window packets.
// Actor/condition: TCP sender and receiver; retransmitted data output and out-of-window received data.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.3
//= type=test
//= reason=Receive CE latch survives to the next ACK; two-packet aggregate tests mark either first or second segment, assert cumulative coverage of both and ECE, and contrast ECN-off. Immediate ACK scheduling on CE is retained.
//# When TCP receives a CE data packet at the destination end-system, the TCP data receiver sets the ECN-Echo flag in the TCP header of the subsequent ACK packet. If there is any ACK withholding implemented, as in current "delayed-ACK" TCP implementations where the TCP receiver can send an ACK for two arriving data packets, then the ECN-Echo flag in the ACK packet will be set to '1' if the CE codepoint is set in any of the data packets being acknowledged. That is, if any of the received data packets are CE packets, then the returning ACK has the ECN-Echo flag set.
// Actor/condition: TCP endpoint; CE data including delayed-ACK aggregation.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.3
//= type=test
//= reason=Dropped feedback/repeated echo, unmarked CWR clearing, subsequent CE and CE-marked CWR assertions establish latch behavior. Erratum 3639 clarifies CWR-before-CE; reordered older CWR is guarded by CE epoch sequence.
//# After a TCP receiver sends an ACK packet with the ECN-Echo bit set, that TCP receiver continues to set the ECN-Echo flag in all the ACK packets it sends (whether they acknowledge CE data packets or non-CE data packets) until it receives a CWR packet (a packet with the CWR flag set). After the receipt of the CWR packet, acknowledgments for subsequent non-CE data packets do not have the ECN-Echo flag set.
// Actor/condition: TCP endpoint; echo persistence until CWR and later CE.
fn ecn_validation_wrap_repeated_marks_and_transactional_output() {
    let (mut a, mut b) = pair(config(1024, 64), u32::MAX - 63);
    a.write(&[1; 128]).unwrap();
    let data = packet(&mut a, 40);
    assert_eq!(a.last_output_ecn(), 2);
    let data2 = packet(&mut a, 40);
    let parsed = wire::parse(ip(tuple()), &data).unwrap();
    let mut segment = wire::parse(ip(tuple()), &data).unwrap();
    // Rejected sequence, missing ACK and out-of-range ACKs never latch CE.
    for (seq, ack, flags) in [
        (
            parsed.header.sequence.wrapping_sub(64),
            parsed.header.acknowledgment,
            ACK,
        ),
        (
            parsed.header.sequence.wrapping_add(4096),
            parsed.header.acknowledgment,
            ACK,
        ),
        (parsed.header.sequence, parsed.header.acknowledgment, 0),
        (
            parsed.header.sequence,
            parsed.header.acknowledgment.wrapping_add(1),
            ACK,
        ),
        (
            parsed.header.sequence,
            parsed.header.acknowledgment.wrapping_sub(b.max_snd_wnd + 1),
            ACK,
        ),
    ] {
        segment.header.sequence = seq;
        segment.header.acknowledgment = ack;
        segment.header.flags = flags;
        b.input_with_traffic_class(40, 3, &segment).unwrap();
        assert!(!b.ecn_echo);
    }
    b.input_with_traffic_class(40, 3, &parsed).unwrap();
    assert!(b.ecn_echo);
    let ece = packet(&mut b, 40);
    let mut feedback = wire::parse(ip(reverse(tuple())), &ece).unwrap();
    let cwnd = a.congestion.cwnd();
    // ECE cannot bypass the future ACK check.
    let valid_ack = feedback.header.acknowledgment;
    feedback.header.acknowledgment = a.snd_nxt.wrapping_add(1).0;
    a.input(40, &feedback).unwrap();
    assert_eq!(a.congestion.cwnd(), cwnd);
    assert!(!a.ecn_cwr_pending);
    feedback.header.acknowledgment = valid_ack;
    a.input(40, &feedback).unwrap();
    let reduced = a.congestion.cwnd();
    assert!(reduced < cwnd);
    assert!(!a.retx_pending);
    for _ in 0..2 {
        a.input(40, &feedback).unwrap();
        assert_eq!(a.congestion.cwnd(), reduced);
    }
    // Finish this flight with repeated CE; equality with the epoch end cannot reduce twice.
    let parsed2 = wire::parse(ip(tuple()), &data2).unwrap();
    b.input_with_traffic_class(40, 3, &parsed2).unwrap();
    let ece = packet(&mut b, 40);
    a.input(40, &wire::parse(ip(reverse(tuple())), &ece).unwrap())
        .unwrap();
    assert_eq!(a.congestion.cwnd(), reduced);
    a.write(&[2; 64]).unwrap();
    let before = (a.snd_nxt, a.last_output_ecn(), a.ecn_cwr_pending, a.now);
    assert_eq!(a.transmit(41, &mut [0; 20]), Err(Error::OutputTooSmall));
    assert_eq!(
        (a.snd_nxt, a.last_output_ecn(), a.ecn_cwr_pending, a.now),
        before
    );
    let cwr = packet(&mut a, 41);
    let cwr = wire::parse(ip(tuple()), &cwr).unwrap();
    assert_ne!(cwr.header.flags & CWR, 0);
    // A newly marked CWR packet starts (or preserves) echo, rather than clearing CE.
    b.input_with_traffic_class(41, 3, &cwr).unwrap();
    assert!(b.ecn_echo);
    let ece = packet(&mut b, 41);
    a.input(41, &wire::parse(ip(reverse(tuple())), &ece).unwrap())
        .unwrap();
    assert!(a.ecn_cwr_pending); // Next flight can signal a new congestion episode.
    a.write(&[3; 64]).unwrap();
    let cwr2 = packet(&mut a, 42);
    b.input(42, &wire::parse(ip(tuple()), &cwr2).unwrap())
        .unwrap();
    assert!(!b.ecn_echo);
    assert_eq!(b.ecn_ce_end, None);
    // An old CE/CWR retransmission is outside the receive window.
    b.input_with_traffic_class(42, 3, &cwr).unwrap();
    assert!(!b.ecn_echo);
    a.abort();
    packet(&mut a, 42);
    assert_eq!(a.last_output_ecn(), 0);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc3168#section-5.2
//= type=test
//= reason=Shared fresh-data output predicate excludes setup, pure ACK, reset, FIN-only, keepalive, persist and retransmitted packets. Fresh FIFO bytes (including Limited Transmit, recovery new data, data/FIN and original TLP) advance tracked sequence space and remain subject to loss recovery. Assertions cover special ECT/Not-ECT outputs, original TLP loss RTO and corrupted CE loss congestion response; no router marking claim.
//# To ensure the reliable delivery of the congestion indication
//# of the CE codepoint, an ECT codepoint MUST NOT be set in a packet
//# unless the loss of that packet in the network would be detected by
//# the end nodes and interpreted as an indication of congestion.
// Actor/condition: TCP sender and IP adapter; all ECT outputs.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Shared fresh-data-only CWR predicate and transactional commit preserve signaling through failed outputs, pure ACK, persist, keepalive, FIN-only and retransmissions; tests assert first-fresh CWR and clearing after ECN, RTO, Reno/NewReno, SACK, RACK/PRR, TLP repaired loss and idle reduction.
//# * If a host ever sets the ECT codepoint on a data packet, then
//# that host MUST correctly set/clear the CWR TCP bit on all
//# subsequent packets in the connection.
// Actor/condition: TCP sender; ever transmitted ECT within this connection.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
//= type=test
//= reason=One-MSS ECE rate reduction: existing assertion proves no fresh output before RTO-length pause and output at expiry, not merely an MSS cwnd floor.
//# Therefore, the sending TCP MUST reset the
//# retransmit timer on receiving the ECN-Echo packet when the congestion
//# window is one.
// Actor/condition: TCP sender; accepted ECE at one-MSS cwnd.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.6
//= type=test
//= reason=Persist probe output explicitly excludes fresh data; assertions prove Not-ECT, no CWR, pending CWR preserved for later eligible data.
//# Therefore, the TCP data sender MUST NOT set either an ECT codepoint
//# or the CWR bit on window probe packets.
// Actor/condition: TCP sender; zero-window probe output.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
//= type=test
//= reason=Existing assertion blocks fresh output until RTO-length pause deadline and permits fresh ECT/CWR output at expiry.
//# The sending TCP will then be able to send a new packet only when the retransmit timer expires.
// Actor/condition: TCP endpoint; ECE at one-MSS cwnd.
fn ecn_one_mss_waits_rto_and_zero_window_probe_is_not_ect() {
    let (mut a, mut b) = pair(config(1024, 64), 10);
    // Model a previous timeout followed by enough ACK progress to leave recovery.
    a.congestion
        .on_timeout(64, a.snd_una.wrapping_add(u32::MAX));
    a.write(&[1; 128]).unwrap();
    let data = packet(&mut a, 40);
    b.input_with_traffic_class(40, 3, &wire::parse(ip(tuple()), &data).unwrap())
        .unwrap();
    deliver(&mut b, &mut a, 40);
    assert_eq!(a.congestion.cwnd(), 64);
    let pause = a.ecn_pause.unwrap();
    assert_eq!(a.transmit(pause - 1, &mut [0; 2048]), Ok(None));
    a.timeout(pause).unwrap();
    let data = packet(&mut a, pause);
    assert_eq!(a.last_output_ecn(), 2);
    assert_ne!(
        wire::parse(ip(tuple()), &data).unwrap().header.flags & CWR,
        0
    );
    // Closed offered window; persist probes cannot carry ECT or CWR.
    a.snd_wnd = 0;
    a.ecn_cwr_pending = true;
    a.arm_work();
    let deadline = a.loss_timer.unwrap().1;
    a.timeout(deadline).unwrap();
    let probe = packet(&mut a, deadline);
    assert_eq!(a.last_output_ecn(), 0);
    assert_eq!(
        wire::parse(ip(tuple()), &probe).unwrap().header.flags & CWR,
        0
    );
    assert!(a.ecn_cwr_pending);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.6
//= type=test
//= reason=Accepted duplicate ECE starts one pause but repetitions, partial progress within that flight and replay after expiry cannot double or prolong it. PTO cannot bypass the pause, pure ACK remains live, and genuine loss RTO remains independent.
//# If congestion events indicated by ECN-Echo ACKs persist,
//# a sender with a _cwnd_ of 1 SMSS MUST reduce its sending rate even
//# further.
fn persistent_ecn_duplicate_flight_timer_and_control_liveness() {
    for algorithm in [CongestionAlgorithm::Cubic, CongestionAlgorithm::Reno] {
        let mut cfg = config(4096, 64);
        cfg.congestion_algorithm = algorithm;
        cfg.sack = true;
        cfg.rack = true;
        cfg.tlp = true;
        let (mut a, mut b) = pair(cfg, u32::MAX - 32);
        a.congestion
            .on_timeout(64, a.snd_una.wrapping_add(u32::MAX));
        a.write(&[1; 128]).unwrap();
        let data = packet(&mut a, 40);
        b.input_with_traffic_class(50, 3, &wire::parse(ip(tuple()), &data).unwrap())
            .unwrap();
        let feedback_bytes = packet(&mut b, 50);
        let mut feedback = wire::parse(ip(reverse(tuple())), &feedback_bytes).unwrap();
        let end = feedback.header.acknowledgment;
        feedback.header.acknowledgment = a.snd_una.0;
        a.input(50, &feedback).unwrap();
        let pause = a.ecn_pause.unwrap();
        let backoff = a.ecn_backoff;
        assert_eq!(a.loss_timer, Some((LossTimer::Rto, pause)));
        assert_eq!(a.tlp_deadline, None);
        for now in [51, 52] {
            a.input(now, &feedback).unwrap();
            assert_eq!(a.ecn_pause, Some(pause));
            assert_eq!(a.ecn_backoff, backoff);
            assert_eq!(a.loss_timer, Some((LossTimer::Rto, pause)));
        }
        feedback.header.flags &= !ECE;
        a.input(52, &feedback).unwrap();
        assert_eq!(a.ecn_backoff, backoff);
        assert_eq!(a.ecn_pause, Some(pause));
        feedback.header.flags |= ECE;
        // Advance within (not beyond) the marked flight; RTT sampling and
        // ACK timer restart must not shorten the reset retransmit timer.
        feedback.header.acknowledgment = a.snd_una.wrapping_add(1).0;
        a.input(53, &feedback).unwrap();
        assert_eq!(a.ecn_pause, Some(pause));
        assert_eq!(a.ecn_backoff, backoff);
        let (timer, loss_deadline) = a.loss_timer.unwrap();
        assert_eq!(timer, LossTimer::Rto);
        assert!(loss_deadline >= pause);
        let pause = loss_deadline;
        a.immediate_ack();
        let ack = packet(&mut a, 54);
        assert!(wire::parse(ip(tuple()), &ack).unwrap().payload.is_empty());
        assert_eq!(a.transmit(pause - 1, &mut [0; 2048]), Ok(None));
        a.timeout(pause).unwrap();
        assert!(a.retx_pending);
        assert_eq!(a.consecutive_timeouts, 1);
        let retry = packet(&mut a, pause);
        assert!(!wire::parse(ip(tuple()), &retry).unwrap().payload.is_empty());
        assert_eq!(a.last_output_ecn(), 0);
        assert_eq!(a.ecn_backoff, backoff);
        feedback.header.acknowledgment = end;
        a.input(pause + 1, &feedback).unwrap();
        assert_eq!(a.ecn_pause, None);
        assert_eq!(a.ecn_backoff, backoff);
        // Replayed feedback while the next original flight is outstanding
        // is not a new persistent-congestion event.
        packet(&mut a, pause + 2);
        a.input(pause + 3, &feedback).unwrap();
        assert_eq!(a.ecn_pause, None);
        assert_eq!(a.ecn_backoff, backoff);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.6
//= type=test
//= reason=Real CE/ECE/CWR wire flights at one MSS demonstrate increasing silence despite fresh low RTT samples, duplicate/reordered feedback immunity, congestion-free progress reset, sequence wrap, caller-unit cap and transactional output for CUBIC and Reno.
//# If congestion events indicated by ECN-Echo ACKs persist,
//# a sender with a _cwnd_ of 1 SMSS MUST reduce its sending rate even
//# further.
//= https://www.rfc-editor.org/rfc/rfc9438#section-5.5
//= type=test
//= reason=Eighteen independently delivered marked flights double the independent timer to the existing 60-second cap without loss timeouts; expiry and successful fresh output remain live.
//# CUBIC also satisfies the "full backoff" requirement as described in
//# [RFC5033].  After reducing the sending rate to one packet per RTT in
//# response to congestion events detected by ECN-Echo ACKs, CUBIC then
//# exponentially increases the transmission timer for each packet
//# retransmission while congestion persists.
fn persistent_ecn_wire_flights_backoff_reset_and_cap() {
    for (algorithm, prr) in [
        (CongestionAlgorithm::Cubic, false),
        (CongestionAlgorithm::Reno, false),
        (CongestionAlgorithm::Cubic, true),
        (CongestionAlgorithm::Reno, true),
    ] {
        for scale in [1, 1000] {
            let mut cfg = config(4096, 64);
            cfg.congestion_algorithm = algorithm;
            cfg.prr = prr;
            cfg.rto_min_us = 1000;
            cfg.timebase.units_per_second = 1_000_000 * scale;
            let (mut a, mut b) = pair(cfg, u32::MAX - 100);
            a.congestion
                .on_timeout(64, a.snd_una.wrapping_add(u32::MAX));
            a.write(&[1; 64]).unwrap();
            let mut now = 40 * scale;
            let mut interval = 0;
            let mut previous: Option<Vec<u8>> = None;
            for _ in 0..18 {
                let data = packet(&mut a, now);
                let data = wire::parse(ip(tuple()), &data).unwrap();
                assert_eq!(data.payload.len(), 64);
                assert_eq!(a.last_output_ecn(), 2);
                // Old feedback replayed with a new flight outstanding is
                // neither a new ECE episode nor congestion-free progress.
                if let Some(old) = &previous {
                    let before = (a.ecn_backoff, a.ecn_pause);
                    let mut old = wire::parse(ip(reverse(tuple())), old).unwrap();
                    a.input(now, &old).unwrap();
                    old.header.flags &= !ECE;
                    a.input(now, &old).unwrap();
                    assert_eq!((a.ecn_backoff, a.ecn_pause), before);
                }
                b.input_with_traffic_class(now, 3, &data).unwrap();
                now += 10 * scale;
                let feedback_bytes = packet(&mut b, now);
                let feedback = wire::parse(ip(reverse(tuple())), &feedback_bytes).unwrap();
                assert_ne!(feedback.header.flags & ECE, 0);
                a.input(now, &feedback).unwrap();
                interval = if interval == 0 {
                    a.rto()
                } else {
                    (interval * 2).min(60_000_000 * scale)
                };
                assert_eq!(a.ecn_backoff, Some((a.snd_nxt, interval)));
                assert_eq!(a.ecn_pause, Some(now + interval));
                assert_eq!(a.congestion.cwnd(), 64);
                assert_eq!(a.consecutive_timeouts, 0);
                assert_eq!(a.loss_timer, None);
                assert!(a.rto() <= 2000 * scale);
                a.write(&[2; 64]).unwrap();
                let snapshot = (a.ecn_backoff, a.ecn_pause, a.rto_deadline);
                a.input(now + scale, &feedback).unwrap();
                let mut clear_duplicate =
                    wire::parse(ip(reverse(tuple())), &feedback_bytes).unwrap();
                clear_duplicate.header.flags &= !ECE;
                a.input(now + scale, &clear_duplicate).unwrap();
                if let Some(old) = &previous {
                    let mut old = wire::parse(ip(reverse(tuple())), old).unwrap();
                    a.input(now + scale, &old).unwrap();
                    old.header.flags &= !ECE;
                    a.input(now + scale, &old).unwrap();
                }
                assert_eq!((a.ecn_backoff, a.ecn_pause, a.rto_deadline), snapshot);
                previous = Some(feedback_bytes);
                let deadline = now + interval;
                assert_eq!(a.transmit(deadline - 1, &mut [0; 2048]), Ok(None));
                a.timeout(deadline).unwrap();
                assert_eq!(a.ecn_pause, None);
                assert_eq!(a.ecn_backoff, snapshot.0);
                let before = (a.snd_nxt, a.ecn_backoff, a.ecn_cwr_pending, a.now);
                assert_eq!(
                    a.transmit(deadline, &mut [0; 20]),
                    Err(Error::OutputTooSmall)
                );
                assert_eq!((a.snd_nxt, a.ecn_backoff, a.ecn_cwr_pending, a.now), before);
                now = deadline;
            }
            assert_eq!(interval, 60_000_000 * scale);
            // Unmarked CWR data clears the receiver latch and delivers fresh,
            // validated congestion-free progress beyond the marked epoch.
            let data = packet(&mut a, now);
            let data = wire::parse(ip(tuple()), &data).unwrap();
            assert_ne!(data.header.flags & CWR, 0);
            b.input(now, &data).unwrap();
            assert!(!b.ecn_echo);
            now += 10 * scale;
            b.immediate_ack();
            deliver(&mut b, &mut a, now);
            assert_eq!(a.ecn_backoff, None);
            assert_eq!(a.ecn_pause, None);
            // A subsequent marked flight starts from the RTT-derived RTO,
            // not the prior capped interval.
            a.congestion
                .on_timeout(64, a.snd_una.wrapping_add(u32::MAX));
            a.write(&[3; 64]).unwrap();
            let data = packet(&mut a, now);
            b.input_with_traffic_class(now, 3, &wire::parse(ip(tuple()), &data).unwrap())
                .unwrap();
            now += 10 * scale;
            deliver(&mut b, &mut a, now);
            assert_eq!(a.ecn_backoff, Some((a.snd_nxt, a.rto())));
            assert_eq!(a.ecn_pause, Some(now + a.rto()));
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Setup/opt-out evidence: exact SYN/SYN-ACK flag interpretation, plain setup forbids ECT, all SYN-ACK ECE/CWR forms are asserted. Earlier receive commitment is separately retained.
//# * A host MUST NOT set ECT on data packets unless it has sent at
//# least one ECN-setup SYN or ECN-setup SYN-ACK packet, and has
//# received at least one ECN-setup SYN or ECN-setup SYN-ACK packet,
//# and has sent no non-ECN-setup SYN or non-ECN-setup SYN-ACK
//# packet.
// Actor/condition: TCP sender; ECT eligibility after bilateral setup with no local plain setup.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Setup/opt-out evidence: exact SYN/SYN-ACK flag interpretation, plain setup forbids ECT, all SYN-ACK ECE/CWR forms are asserted. Earlier receive commitment is separately retained.
//# If a host has received at least one non-ECN-setup SYN
//# or non-ECN-setup SYN-ACK packet, then it SHOULD NOT set ECT on
//# data packets.
// Actor/condition: TCP sender; received any plain setup packet.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Negotiated receive commitment gates CE handling after sequence/control/ACK validation, including exact-sequence zero-window probes without receive credit. Tests cover normal CE, repeated feedback, fallback commitment, invalid packets and ECN-off receive.
//# * If a host has sent at least one ECN-setup SYN or ECN-setup SYN-
//# ACK packet, and has received no non-ECN-setup SYN or non-ECN-
//# setup SYN-ACK packet, then if that host receives TCP data
//# packets with ECT and CE codepoints set in the IP header, then
//# that host MUST process these packets as specified for an ECN-
//# capable connection.
// Actor/condition: TCP receiver; sent setup and received no plain setup; ECN data received.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Setup/opt-out evidence: exact SYN/SYN-ACK flag interpretation, plain setup forbids ECT, all SYN-ACK ECE/CWR forms are asserted. Earlier receive commitment is separately retained.
//# * A host that is not willing to use ECN on a TCP connection SHOULD
//# clear both the ECE and CWR flags in all non-ECN-setup SYN and/or
//# SYN-ACK packets that it sends to indicate this unwillingness.
// Actor/condition: TCP setup sender; unwilling to use ECN.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Setup/opt-out evidence: exact SYN/SYN-ACK flag interpretation, plain setup forbids ECT, all SYN-ACK ECE/CWR forms are asserted. Earlier receive commitment is separately retained.
//# Receivers MUST correctly handle all forms of the non-ECN-setup
//# SYN and SYN-ACK packets.
// Actor/condition: TCP setup receiver; any non-ECN-setup SYN/SYN-ACK flag combination.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Explicit receive commitment assertion after delayed setup SYN-ACK and local plain-SYN fallback; sender no longer sets ECT, receiver still latches CE.
//# However, the commitment to respond appropriately to incoming packets with the CE codepoint set remains even if the TCP sender in a later transmission, within this TCP connection, sends a SYN packet without ECE and CWR set.
// Actor/condition: TCP endpoint; ECN setup followed by local plain-SYN fallback.
fn ecn_fallback_retains_receive_commitment() {
    let cfg = config(1024, 64);
    let mut a = Connection::active(tuple(), cfg.clone(), 10, 0).unwrap();
    let syn = packet(&mut a, 0);
    let mut b = Connection::passive(
        reverse(tuple()),
        cfg,
        900,
        0,
        &wire::parse(ip(tuple()), &syn).unwrap(),
    )
    .unwrap();
    let synack = packet(&mut b, 0);
    a.timeout(1_000_000).unwrap();
    packet(&mut a, 1_000_000); // Lost plain SYN, delayed ECN SYN-ACK arrives instead.
    a.input(
        1_000_000,
        &wire::parse(ip(reverse(tuple())), &synack).unwrap(),
    )
    .unwrap();
    deliver(&mut a, &mut b, 1_000_000);
    assert!(!a.ecn_send());
    assert!(a.ecn_feedback());
    b.write(&[0; 64]).unwrap();
    let data = packet(&mut b, 1_000_001);
    assert_eq!(b.last_output_ecn(), 2);
    a.input_with_traffic_class(
        1_000_001,
        3,
        &wire::parse(ip(reverse(tuple())), &data).unwrap(),
    )
    .unwrap();
    assert!(a.ecn_echo);
}
#[test]
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Setup/opt-out evidence: exact SYN/SYN-ACK flag interpretation, plain setup forbids ECT, all SYN-ACK ECE/CWR forms are asserted. Earlier receive commitment is separately retained.
//# * A host MUST NOT set ECT on data packets unless it has sent at
//# least one ECN-setup SYN or ECN-setup SYN-ACK packet, and has
//# received at least one ECN-setup SYN or ECN-setup SYN-ACK packet,
//# and has sent no non-ECN-setup SYN or non-ECN-setup SYN-ACK
//# packet.
// Actor/condition: TCP sender; ECT eligibility after bilateral setup with no local plain setup.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Setup/opt-out evidence: exact SYN/SYN-ACK flag interpretation, plain setup forbids ECT, all SYN-ACK ECE/CWR forms are asserted. Earlier receive commitment is separately retained.
//# If a host has received at least one non-ECN-setup SYN
//# or non-ECN-setup SYN-ACK packet, then it SHOULD NOT set ECT on
//# data packets.
// Actor/condition: TCP sender; received any plain setup packet.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Setup/opt-out evidence: exact SYN/SYN-ACK flag interpretation, plain setup forbids ECT, all SYN-ACK ECE/CWR forms are asserted. Earlier receive commitment is separately retained.
//# * A host that is not willing to use ECN on a TCP connection SHOULD
//# clear both the ECE and CWR flags in all non-ECN-setup SYN and/or
//# SYN-ACK packets that it sends to indicate this unwillingness.
// Actor/condition: TCP setup sender; unwilling to use ECN.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Setup/opt-out evidence: exact SYN/SYN-ACK flag interpretation, plain setup forbids ECT, all SYN-ACK ECE/CWR forms are asserted. Earlier receive commitment is separately retained.
//# Receivers MUST correctly handle all forms of the non-ECN-setup
//# SYN and SYN-ACK packets.
// Actor/condition: TCP setup receiver; any non-ECN-setup SYN/SYN-ACK flag combination.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1.2
//= type=test
//= reason=Exact flag-combination assertion enables ECN only for ECE-only SYN-ACK, rejecting reflected ECE|CWR.
//# the sending TCP correctly interprets a receiver's reflection of its own flags in the Reserved field as an indication that the receiver is not ECN-capable.
// Actor/condition: TCP endpoint; SYN-ACK reflects both ECE/CWR.
fn ecn_setup_output_is_atomic_and_synack_flags_are_not_echoed_reserved_bits() {
    for flags in [0, ECE, CWR, ECE | CWR] {
        let cfg = config(1024, 64);
        let mut a = Connection::active(tuple(), cfg.clone(), 10, 0).unwrap();
        assert_eq!(a.transmit(1, &mut [0; 19]), Err(Error::OutputTooSmall));
        assert!(!a.ecn_sent_setup && !a.ecn_sent_plain);
        assert_eq!(a.last_output_ecn(), 0);
        let syn = packet(&mut a, 1);
        let mut b = Connection::passive(
            reverse(tuple()),
            cfg,
            900,
            1,
            &wire::parse(ip(tuple()), &syn).unwrap(),
        )
        .unwrap();
        let synack = packet(&mut b, 1);
        let mut parsed = wire::parse(ip(reverse(tuple())), &synack).unwrap();
        parsed.header.flags = SYN | ACK | flags;
        a.input(1, &parsed).unwrap();
        assert_eq!(a.ecn_send(), flags == ECE);
        a.write(&[1; 64]).unwrap();
        packet(&mut a, 1);
        assert_eq!(a.last_output_ecn(), if flags == ECE { 2 } else { 0 });
    }
}

#[test]
fn ecn_without_initiation_answers_a_setup_syn_but_sends_none() {
    // As Linux's tcp_ecn=2: the active open asks for no ECN, so neither side
    // marks; a peer that asks is answered, and the connection is ECN-capable.
    for (client_initiates, negotiated) in [(false, false), (true, true)] {
        let mut client = config(1024, 64);
        client.ecn_initiate = client_initiates;
        let mut server = config(1024, 64);
        server.ecn_initiate = false;
        let mut a = Connection::active(tuple(), client, 10, 0).unwrap();
        let syn = packet(&mut a, 1);
        let parsed = wire::parse(ip(tuple()), &syn).unwrap();
        assert_eq!(
            parsed.header.flags & (ECE | CWR),
            if client_initiates { ECE | CWR } else { 0 }
        );
        let mut b = Connection::passive(reverse(tuple()), server, 900, 1, &parsed).unwrap();
        let synack = deliver(&mut b, &mut a, 2);
        let synack = wire::parse(ip(reverse(tuple())), &synack).unwrap();
        assert_eq!(
            synack.header.flags & (ECE | CWR),
            if negotiated { ECE } else { 0 }
        );
        deliver(&mut a, &mut b, 3);
        assert_eq!((a.ecn_send(), b.ecn_send()), (negotiated, negotiated));
        a.write(&[1; 64]).unwrap();
        packet(&mut a, 4);
        assert_eq!(a.last_output_ecn(), if negotiated { 2 } else { 0 });
    }
}

#[test]
fn shrink_silence_times_out_from_first_committed_unanswered_retransmission() {
    for iss in [100, u32::MAX - 4] {
        let mut cfg = config(64, 8);
        cfg.user_timeout_us = 5_000_000;
        let (mut a, _) = pair(cfg, iss);
        a.write(b"abcdefgh").unwrap();
        packet(&mut a, 40);
        let seq = a.receive.next().wrapping_add(1);
        let una = a.snd_una;
        inject(&mut a, 50, seq, una, ACK, 3, b"");
        assert_eq!(a.transmit(60, &mut [0; 64]), Ok(None));
        assert_eq!(a.shrink_unanswered_since, None);
        let when = a.next_deadline().unwrap();
        a.timeout(when).unwrap();
        assert_eq!(a.user_deadline(), None);
        let before = (a.now, a.next_deadline(), a.retx_pending);
        assert_eq!(
            a.transmit(when + 1, &mut [0; 22]),
            Err(Error::OutputTooSmall)
        );
        assert_eq!((a.now, a.next_deadline(), a.retx_pending), before);
        assert_eq!(a.shrink_unanswered_since, None);
        // Adapter backpressure is not peer silence either.
        let sent = when + 6_000_000;
        a.timeout(sent).unwrap();
        assert_eq!(a.state(), State::Established);
        packet(&mut a, sent);
        let deadline = sent + 5_000_000;
        assert_eq!(a.shrink_unanswered_since, Some(sent));
        assert_eq!(a.user_deadline(), Some(deadline));
        let when = a.next_deadline().unwrap();
        assert!(when < deadline);
        a.timeout(when).unwrap();
        packet(&mut a, when);
        assert_eq!(a.shrink_unanswered_since, Some(sent));
        assert_eq!(a.user_deadline(), Some(deadline));
        // Both an old ACK and a stale window SEQ must leave the first
        // unanswered timestamp intact, even if they advertise reopening.
        for (seq, ack) in [(seq, una.wrapping_add(u32::MAX)), (a.receive.next(), una)] {
            inject(&mut a, when + 1, seq, ack, ACK, 64, b"");
            assert_eq!(a.shrink_unanswered_since, Some(sent));
            assert_eq!(a.user_deadline(), Some(deadline));
            assert_eq!(a.snd_wnd, 3);
        }
        assert_eq!(a.next_deadline(), Some(deadline));
        a.timeout(deadline - 1).unwrap();
        assert_eq!(a.state(), State::Established);
        a.timeout(deadline).unwrap();
        assert_eq!(a.close_reason(), Some(CloseReason::TimedOut));
        assert_eq!(a.shrink_unanswered_since, None);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1.1
//= type=test
//= reason=Optional timeout fallback selected; asserts plain setup after timeout and ECT suppression, retaining earlier receive commitment. No RST-triggered retry claim.
//# A host that receives no reply to an ECN-setup SYN within the normal
//# SYN retransmission timeout interval MAY resend the SYN and any
//# subsequent SYN retransmissions with CWR and ECE cleared.
// Actor/condition: TCP setup initiator/responder; no setup reply before SYN retransmission timeout.
fn ecn_synack_timeout_fallback_and_invalid_handshake_ack() {
    let cfg = config(1024, 64);
    let mut a = Connection::active(tuple(), cfg.clone(), 10, 0).unwrap();
    let syn = packet(&mut a, 0);
    let mut b = Connection::passive(
        reverse(tuple()),
        cfg,
        900,
        0,
        &wire::parse(ip(tuple()), &syn).unwrap(),
    )
    .unwrap();
    packet(&mut b, 0); // Lost setup SYN-ACK.
    let mut invalid = wire::parse(ip(tuple()), &syn).unwrap();
    invalid.header.flags = SYN | ACK;
    invalid.header.acknowledgment = 123;
    b.input(0, &invalid).unwrap();
    assert!(!b.ecn_peer_plain);
    b.timeout(1_000_000).unwrap();
    let fallback = packet(&mut b, 1_000_000);
    assert_eq!(
        wire::parse(ip(reverse(tuple())), &fallback)
            .unwrap()
            .header
            .flags,
        SYN | ACK
    );
    a.input(
        1_000_000,
        &wire::parse(ip(reverse(tuple())), &fallback).unwrap(),
    )
    .unwrap();
    deliver(&mut a, &mut b, 1_000_000);
    assert!(!a.ecn_send() && !b.ecn_send());
    assert!(b.ecn_feedback()); // Original receive promise is retained.
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.3
//= type=test
//= reason=Dropped feedback/repeated echo, unmarked CWR clearing, subsequent CE and CE-marked CWR assertions establish latch behavior. Erratum 3639 clarifies CWR-before-CE; reordered older CWR is guarded by CE epoch sequence.
//# After a TCP receiver sends an ACK packet with the ECN-Echo bit set, that TCP receiver continues to set the ECN-Echo flag in all the ACK packets it sends (whether they acknowledge CE data packets or non-CE data packets) until it receives a CWR packet (a packet with the CWR flag set). After the receipt of the CWR packet, acknowledgments for subsequent non-CE data packets do not have the ECN-Echo flag set.
// Actor/condition: TCP endpoint; echo persistence until CWR and later CE.
fn ecn_reordered_cwr_cannot_clear_newer_ce() {
    let (mut a, mut b) = pair(config(1024, 64), u32::MAX - 127);
    a.write(&[1; 192]).unwrap();
    packet(&mut a, 40); // Keep a receive hole so older CWR remains in-window.
    let old = packet(&mut a, 40);
    let marked = packet(&mut a, 40);
    b.input_with_traffic_class(40, 3, &wire::parse(ip(tuple()), &marked).unwrap())
        .unwrap();
    let mut old = wire::parse(ip(tuple()), &old).unwrap();
    old.header.flags |= CWR;
    b.input(40, &old).unwrap();
    assert!(b.ecn_echo);
    let ack = packet(&mut b, 40);
    assert_ne!(
        wire::parse(ip(reverse(tuple())), &ack)
            .unwrap()
            .header
            .flags
            & ECE,
        0
    );
}
#[test]
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
//= type=test
//= reason=First-fresh CWR tests cover RTO, Reno/NewReno fast retransmit, SACK and RACK/PRR reductions; TLP repaired-loss trace asserts CWR only after actual reduction. ECN and idle tests plus shared successful fresh-data commit cover other causes and failed encoding.
//# When an ECN-Capable TCP sender reduces its congestion window for any reason (because of a retransmit timeout, a Fast Retransmit, or in response to an ECN Notification), the TCP sender sets the CWR flag in the TCP header of the first new data packet sent after the window reduction.
// Actor/condition: TCP endpoint; any reduction cause including timeout, fast retransmit and ECN.
fn ecn_idle_window_reduction_signals_cwr_on_committed_fresh_data() {
    let (mut a, mut b) = pair(config(1024, 64), 10);
    a.write(&[0; 64]).unwrap();
    deliver(&mut a, &mut b, 40);
    b.timeout(200_040).unwrap();
    deliver(&mut b, &mut a, 200_040);
    assert!(a.congestion.cwnd() > a.initial_window());
    a.write(&[0; 64]).unwrap();
    let now = 200_040 + a.rto();
    let before = a.congestion.cwnd();
    assert_eq!(a.transmit(now, &mut [0; 19]), Err(Error::OutputTooSmall));
    assert_eq!(a.congestion.cwnd(), before);
    let data = packet(&mut a, now);
    assert_eq!(a.congestion.cwnd(), a.initial_window());
    assert_ne!(
        wire::parse(ip(tuple()), &data).unwrap().header.flags & CWR,
        0
    );
    assert_eq!(a.last_output_ecn(), 2);
}
#[test]
fn ecn_valid_cwr_control_clears_echo_but_pure_ack_ce_does_not_set_it() {
    let (mut a, mut b) = pair(config(1024, 64), 10);
    a.write(&[0; 64]).unwrap();
    let data = packet(&mut a, 40);
    let mut control = wire::parse(ip(tuple()), &data).unwrap();
    b.input_with_traffic_class(40, 3, &control).unwrap();
    assert!(b.ecn_echo);
    control.header.sequence = a.snd_nxt.0;
    control.header.flags = ACK | CWR;
    control.payload = &[];
    b.input_with_traffic_class(40, 3, &control).unwrap();
    assert!(!b.ecn_echo);
    assert_eq!(b.ecn_ce_end, None);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
//= type=test
//# A TCP endpoint MAY implement PUSH flags on SEND calls (MAY-15).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
//= type=test
//# When an application issues a series of SEND calls without setting the PUSH
//# flag, the TCP implementation MAY aggregate the data internally without
//# sending it (MAY-16).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
//= type=test
//= reason=Explicit PUSH marks survive packetization and partial acknowledgment; Nagle still applies.
//# If the PUSH flag is set, the application intends the data to be transmitted promptly to
//# the receiver, and the PSH bit will be set in the last TCP segment created from the
//# buffer.
fn explicit_push_aggregates_crosses_marks_and_retransmits_after_partial_ack() {
    let (mut a, _) = pair(config(16, 8), u32::MAX - 3);
    a.set_nagle(false);
    a.write_with_push(b"ab", false).unwrap();
    assert_eq!(a.transmit(40, &mut [0; 64]), Ok(None));
    a.write_with_push(b"cd", true).unwrap();
    a.write_with_push(b"efghij", false).unwrap();
    let before = (a.snd_nxt, a.send.len(), a.next_deadline());
    assert_eq!(a.transmit(40, &mut [0; 27]), Err(Error::OutputTooSmall));
    assert_eq!((a.snd_nxt, a.send.len(), a.next_deadline()), before);
    let bytes = packet(&mut a, 40);
    let segment = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(segment.payload, b"abcdefgh");
    assert_ne!(segment.header.flags & PSH, 0); // Crossed cd, not a record boundary.
    let ack = a.send_base.wrapping_add(2);
    inject(&mut a, 50, Seq(901), ack, ACK, 16, b"");
    a.retx_pending = true;
    let bytes = packet(&mut a, 60);
    let segment = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(segment.payload, b"cdefgh");
    assert_ne!(segment.header.flags & PSH, 0);
    let ack = a.send_base.wrapping_add(4); // Past original PUSH, before wire PSH.
    inject(&mut a, 65, Seq(901), ack, ACK, 16, b"");
    a.retx_pending = true;
    let bytes = packet(&mut a, 66);
    let segment = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(segment.payload, b"gh");
    assert_ne!(segment.header.flags & PSH, 0);
    let ack = a.snd_nxt;
    inject(&mut a, 70, Seq(901), ack, ACK, 16, b"");
    assert_eq!(a.transmit(80, &mut [0; 64]), Ok(None));
    a.write_with_push(b"", true).unwrap();
    let bytes = packet(&mut a, 80);
    let segment = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(segment.payload, b"ij");
    assert_ne!(segment.header.flags & PSH, 0);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
//= type=test
//= reason=Tests automatic-PUSH write packetization and deadline-serviced aggregation; explicit PUSH is implemented, so the conditional is not a claim about write_with_push(false).
//# If
//# PUSH flags are not implemented, then the sending TCP peer: (1) MUST
//# NOT buffer data indefinitely (MUST-60), and (2) MUST set the PSH bit
//# in the last buffered segment (i.e., when there is no more queued data
//# to be sent) (MUST-61).
fn automatic_push_final_segment_partial_write_and_bounded_aggregation() {
    let (mut a, _) = pair(config(10, 8), 100);
    a.set_nagle(false);
    assert_eq!(a.write(b"abcdefghijkl"), Ok(10));
    assert_eq!(a.write_with_push(b"x", false), Err(Error::WouldBlock));
    for (expected, pushed) in [(&b"abcdefgh"[..], false), (&b"ij"[..], true)] {
        let bytes = packet(&mut a, 40);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.payload, expected);
        assert_eq!(segment.header.flags & PSH != 0, pushed);
    }
    let (mut a, _) = pair(config(16, 8), 100);
    a.write_with_push(b"abc", false).unwrap();
    assert_eq!(a.transmit(40, &mut [0; 64]), Ok(None));
    let deadline = a.sws_deadline.unwrap();
    a.timeout(deadline).unwrap();
    let bytes = packet(&mut a, deadline);
    assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, b"abc");

    let (mut a, _) = pair(config(16, 8), 100);
    a.write_with_push(b"abc", false).unwrap();
    a.shutdown().unwrap();
    let bytes = packet(&mut a, 40);
    let segment = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(segment.payload, b"abc");
    assert_ne!(segment.header.flags & FIN, 0);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.7
//= type=test
//# The FLUSH call MAY be implemented (MAY-14).
fn flush_retains_advertised_urgency_and_push_after_partial_ack() {
    let (mut a, _) = pair(config(16, 8), u32::MAX - 3);
    a.write_with_push(b"ab", true).unwrap();
    a.write_urgent(b"cdefghijklmnop").unwrap();
    packet(&mut a, 40);
    let ack = a.send_base.wrapping_add(2);
    inject(&mut a, 50, Seq(901), ack, ACK, 6, b"");
    let next = a.snd_nxt;
    let urgent_end = a.send_base.wrapping_add(14);
    assert_eq!(a.flush(), Ok(0));
    assert_eq!(a.send.len(), 14);
    assert_eq!(a.snd_nxt, next);
    assert_eq!(a.snd_up, Some(urgent_end));
    assert_eq!(a.advertised_snd_up, Some(urgent_end));
    assert!(a.take_events().writable);
    a.retx_pending = true;
    let bytes = packet(&mut a, 60);
    let segment = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(segment.payload, b"cdefgh");
    assert_ne!(segment.header.flags & PSH, 0); // Retained on-wire mark survives the partial ACK.
    assert_eq!(segment.header.urgent_pointer, 14);
    inject(&mut a, 70, Seq(901), next, ACK, 16, b"");
    let bytes = packet(&mut a, 71);
    assert_eq!(
        wire::parse(ip(tuple()), &bytes).unwrap().payload,
        b"ijklmnop"
    );
    inject(&mut a, 72, Seq(901), urgent_end, ACK, 16, b"");
    assert_eq!(a.advertised_snd_up, None);
    let next = a.snd_nxt;
    a.write(b"new").unwrap();
    let bytes = packet(&mut a, 80);
    let segment = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(segment.header.sequence, next.0);
    assert_eq!(segment.payload, b"new");
    assert_ne!(segment.header.flags & PSH, 0);
    assert_eq!(segment.header.flags & URG, 0);
    a.shutdown().unwrap();
    assert_eq!(a.flush(), Err(Error::InvalidState));
    a.abort();
    assert_eq!(a.flush(), Err(Error::InvalidState));

    let mut a = Connection::active(tuple(), config(16, 8), 100, 0).unwrap();
    a.write_urgent(b"queued").unwrap();
    assert_eq!(a.flush(), Ok(6));
    assert_eq!(a.snd_nxt, Seq(100));
    assert_eq!(a.snd_up, None);
    a.write(b"new").unwrap();
    packet(&mut a, 0); // Flushing SYN-SENT must not discard or advance SYN.
    assert_eq!(a.snd_nxt, Seq(101));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.7
//= type=test
//# The FLUSH call MAY be implemented (MAY-14).
fn flush_cannot_reclassify_replacement_bytes_as_urgent_at_peer() {
    for iss in [100, u32::MAX - 3] {
        let (mut a, mut b) = pair(config(16, 8), iss);
        a.write_urgent(b"abcdefghijklmnop").unwrap();
        let bytes = deliver(&mut a, &mut b, 40);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes)
                .unwrap()
                .header
                .urgent_pointer,
            16
        );
        assert_eq!(a.flush(), Ok(0));
        assert_eq!(a.write(b"ordinary"), Err(Error::WouldBlock));
        let mut out = [0; 8];
        assert_eq!(b.read(&mut out), Ok(8));
        assert_eq!(&out, b"abcdefgh");
        assert_eq!(b.urgent_remaining(), 8);
        deliver(&mut b, &mut a, 50);
        assert_eq!(a.write(b"ordinary"), Ok(8));
        let bytes = deliver(&mut a, &mut b, 60);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().payload,
            b"ijklmnop"
        );
        assert_eq!(b.read(&mut out), Ok(8));
        assert_eq!(b.urgent_remaining(), 0);
        deliver(&mut b, &mut a, 70);
        let bytes = deliver(&mut a, &mut b, 80);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.payload, b"ordinary");
        assert_eq!(segment.header.flags & URG, 0);
        assert_eq!(b.urgent_remaining(), 0);
        assert_eq!(b.read(&mut out), Ok(8));
        assert_eq!(&out, b"ordinary");
        assert_eq!(a.send.capacity(), 16);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.7
//= type=test
//# The FLUSH call MAY be implemented (MAY-14).
fn flush_retains_offered_window_not_congestion_window() {
    for (window, discarded) in [(8, 4), (12, 0), (16, 0), (0, 12)] {
        let (mut a, _) = pair(config(16, 2), u32::MAX - 3);
        let base = a.send_base;
        inject(&mut a, 40, Seq(901), base, ACK, window, b"");
        assert_eq!(a.snd_wnd, window as u32);
        assert!(a.congestion.cwnd() < 12);
        a.write(b"abcdefghijkl").unwrap();
        assert_eq!(a.flight(), 0);
        a.take_events();
        assert_eq!(a.flush(), Ok(discarded));
        assert_eq!(a.send.len(), 12 - discarded);
        assert_eq!(a.snd_nxt, base);
        assert_eq!(a.take_events().writable, discarded != 0);
        // Reopening and replacing the suffix must not create a sequence hole.
        inject(&mut a, 50, Seq(901), base, ACK, 16, b"");
        a.write(b"XY").unwrap();
        let bytes = packet(&mut a, 60);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.header.sequence, base.0);
        assert_eq!(segment.payload, if window == 0 { b"XY" } else { b"ab" });
    }
}

#[test]
fn flush_shrunk_window_retains_flight_after_partial_ack_and_wrap() {
    for window in [0, 2, 8] {
        let (mut a, _) = pair(config(16, 8), u32::MAX - 3);
        a.write(b"abcdefgh").unwrap();
        a.write(b"ijklmnop").unwrap();
        packet(&mut a, 40);
        let next = a.snd_nxt;
        let ack = a.send_base.wrapping_add(5);
        assert_eq!(ack, Seq(2));
        inject(&mut a, 50, Seq(901), ack, ACK, window, b"");
        let retained = 3usize.max(window as usize);
        assert_eq!(a.flush(), Ok(11 - retained));
        assert_eq!(a.send.len(), retained);
        assert_eq!(a.snd_nxt, next);
        inject(&mut a, 60, Seq(901), ack, ACK, 16, b"");
        a.retx_pending = true;
        let bytes = packet(&mut a, 61);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.header.sequence, ack.0);
        assert_eq!(segment.payload, b"fgh");
        assert_ne!(segment.header.flags & PSH, 0);
        inject(&mut a, 70, Seq(901), next, ACK, 16, b"");
        a.write(b"XY").unwrap();
        let bytes = packet(&mut a, 71);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.header.sequence, next.0);
        assert_eq!(
            segment.payload,
            if window == 8 { &b"ijklmXY"[..] } else { b"XY" }
        );
    }
}

#[test]
fn flush_handshake_window_accounts_for_syn_sequence_space() {
    for iss in [100, u32::MAX] {
        for sent_syn in [false, true] {
            let mut a = Connection::active(tuple(), config(16, 8), iss, 0).unwrap();
            if sent_syn {
                packet(&mut a, 0);
            }
            a.write(b"queued").unwrap();
            let next = a.snd_nxt;
            assert_eq!(a.flush(), Ok(6)); // No window offered in SYN-SENT.
            assert_eq!(a.snd_nxt, next);
            assert_eq!(a.send_base, Seq(iss).wrapping_add(1));

            for window in [0, 1, 8] {
                let mut peer = Connection::active(tuple(), config(16, 8), 900, 0).unwrap();
                let bytes = packet(&mut peer, 0);
                let mut syn = wire::parse(ip(tuple()), &bytes).unwrap();
                syn.header.window = window;
                let mut b =
                    Connection::passive(reverse(tuple()), config(16, 8), iss, 0, &syn).unwrap();
                if sent_syn {
                    packet(&mut b, 0);
                }
                assert_eq!(b.state(), State::SynReceived);
                b.write(b"abcdefghijkl").unwrap();
                let next = b.snd_nxt;
                let retained = window.saturating_sub(1) as usize;
                assert_eq!(b.flush(), Ok(12 - retained));
                assert_eq!(b.send.len(), retained);
                assert_eq!(b.snd_nxt, next);
                assert_eq!(b.send_base, Seq(iss).wrapping_add(1));
            }
        }
    }
}

#[test]
fn flush_discards_only_unadvertised_suffix_even_after_failed_output() {
    let (mut a, _) = pair(config(24, 8), u32::MAX - 3);
    a.write_urgent(b"abcdefghijklmnop").unwrap();
    packet(&mut a, 40); // Commits coverage of sixteen bytes, only eight sent.
    let committed = a.advertised_snd_up;
    a.write_urgent(b"qrstuvwx").unwrap();
    assert_eq!(a.transmit(50, &mut [0; 27]), Err(Error::OutputTooSmall));
    assert_eq!(a.advertised_snd_up, committed);
    let ack = a.snd_una;
    inject(&mut a, 51, Seq(901), ack, ACK, 8, b"");
    assert_eq!(a.flush(), Ok(8));
    assert_eq!(a.send.len(), 16);
    assert_eq!(a.snd_up, committed);
    assert_eq!(a.send.capacity(), 24);

    let (mut a, _) = pair(config(16, 8), 100);
    a.write_urgent(b"abcdefghijklmnop").unwrap();
    assert_eq!(a.transmit(40, &mut [0; 27]), Err(Error::OutputTooSmall));
    let ack = a.snd_una;
    inject(&mut a, 41, Seq(901), ack, ACK, 0, b"");
    assert_eq!(a.flush(), Ok(16)); // Outside the window, urgency never committed.
    assert_eq!(a.snd_up, None);
    assert_eq!(a.advertised_snd_up, None);
    inject(&mut a, 42, Seq(901), ack, ACK, 16, b"");
    a.write(b"ordinary").unwrap();
    let bytes = packet(&mut a, 50);
    assert_eq!(
        wire::parse(ip(tuple()), &bytes).unwrap().header.flags & URG,
        0
    );

    let (mut a, _) = pair(config(131072, 1460), u32::MAX - 100);
    a.write_urgent(&vec![42; 70000]).unwrap();
    packet(&mut a, 40);
    packet(&mut a, 50); // Advances the capped wire endpoint by one MSS.
    a.retx_pending = true;
    packet(&mut a, 60); // Older retransmission cannot retract that endpoint.
    let ack = a.snd_una;
    inject(&mut a, 61, Seq(901), ack, ACK, 0, b"");
    assert_eq!(a.flush(), Ok(70000 - 65535 - 1460));
    assert_eq!(a.send.len(), 65535 + 1460);
    assert_eq!(a.snd_up, a.advertised_snd_up);
    assert_eq!(a.send.capacity(), 131072);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.3
//= type=test
//# A TCP receiver MAY pass a received PSH bit to the application layer
//# via the PUSH flag in the interface (MAY-17), but it is not required
//# (this was clarified in RFC 1122, Section 4.2.2.2).
fn receive_push_waits_for_gap_and_ignores_duplicate_empty_and_trimmed_marks() {
    let (_, mut b) = pair(config(16, 8), u32::MAX - 2);
    let start = b.receive.next();
    inject(
        &mut b,
        40,
        start.wrapping_add(2),
        Seq(901),
        ACK | PSH,
        16,
        b"cd",
    );
    assert!(!b.take_events().pushed);
    inject(&mut b, 50, start, Seq(901), ACK, 16, b"ab");
    let events = b.take_events();
    assert!(events.pushed && events.readable);
    inject(
        &mut b,
        60,
        start.wrapping_add(2),
        Seq(901),
        ACK | PSH,
        16,
        b"cd",
    );
    assert!(!b.take_events().pushed);
    let next = b.receive.next();
    inject(&mut b, 70, next, Seq(901), ACK | PSH, 16, b"");
    assert!(!b.take_events().pushed);
    inject(&mut b, 80, next, Seq(901), ACK | PSH, 16, b"efghijklmnopq");
    assert!(!b.take_events().pushed); // PSH endpoint was outside the window.
    assert_eq!(b.read(&mut [0; 16]), Ok(16));
    packet(&mut b, 80); // Advertise the newly freed receive credit.
    let next = b.receive.next();
    inject(&mut b, 90, next, Seq(901), ACK | PSH, 16, b"x");
    inject(
        &mut b,
        100,
        next.wrapping_add(1),
        Seq(901),
        ACK | PSH,
        16,
        b"y",
    );
    assert!(b.take_events().pushed); // Coalesced, not a queue of records.
    assert!(!b.take_events().pushed);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.6.1
//= type=test
//# A host MAY implement a "half-duplex" TCP close sequence, so that an
//# application that has called CLOSE cannot continue to read data from
//# the connection (MAY-1).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.6.1
//= type=test
//# If such a host issues a CLOSE call while received data is still pending in
//# the TCP connection, or if new data is received after CLOSE is called, its
//# TCP implementation SHOULD send a RST to show that data was lost (SHLD-3).
fn optional_close_resets_only_accepted_data_loss_shutdown_still_reads() {
    for offset in [0, 2] {
        let (mut a, _) = pair(config(16, 8), 100);
        inject(&mut a, 40, Seq(901 + offset), Seq(101), ACK | PSH, 16, b"x");
        a.close().unwrap();
        assert_eq!(a.read(&mut [0]), Err(Error::InvalidState));
        let events = a.take_events();
        assert_eq!(events.closed, Some(CloseReason::Aborted));
        assert!(!events.readable && !events.pushed);
        let bytes = packet(&mut a, 50);
        assert_ne!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.flags & RST,
            0
        );
    }
    let (mut a, _) = pair(config(16, 8), 100);
    inject(&mut a, 40, Seq(901), Seq(101), ACK, 16, b"x");
    assert_eq!(a.read(&mut [0]), Ok(1));
    a.take_events();
    a.close().unwrap();
    let bytes = packet(&mut a, 50);
    assert_ne!(
        wire::parse(ip(tuple()), &bytes).unwrap().header.flags & FIN,
        0
    );
    // Old data, out-of-window data, missing ACK, and unacceptable ACK do not reset.
    for (seq, ack, flags) in [
        (901, 102, ACK),
        (950, 102, ACK),
        (902, 102, PSH),
        (902, 999, ACK),
    ] {
        inject(&mut a, 60, Seq(seq), Seq(ack), flags, 16, b"x");
        assert_ne!(a.state(), State::Closed);
    }
    inject(&mut a, 70, Seq(904), Seq(102), ACK | PSH, 16, b"x");
    assert_eq!(a.state(), State::Closed); // Accepted out-of-order bytes also lose data.
    assert_eq!(a.take_events().closed, Some(CloseReason::Aborted));
    let bytes = packet(&mut a, 80);
    assert_ne!(
        wire::parse(ip(tuple()), &bytes).unwrap().header.flags & RST,
        0
    );

    let (mut a, _) = pair(config(16, 8), 100);
    a.shutdown().unwrap();
    packet(&mut a, 40);
    inject(&mut a, 50, Seq(901), Seq(102), ACK | FIN, 16, b"reply");
    let mut out = [0; 8];
    assert_eq!(a.read(&mut out), Ok(5));
    assert_eq!(&out[..5], b"reply");
    assert_eq!(a.read(&mut out), Ok(0));

    let (mut a, _) = pair(config(16, 8), 100);
    a.close().unwrap();
    packet(&mut a, 40);
    inject(&mut a, 50, Seq(901), Seq(102), ACK | FIN, 16, b"");
    assert_eq!(a.state(), State::TimeWait);
    assert!(!a.take_events().readable);
}

#[test]
fn half_duplex_payload_reset_is_reactive_and_retry_owned() {
    for enabled in [false, true] {
        // No TS, negotiated TS, and TS received without negotiation.
        for timestamps in 0..3 {
            for iss in [100, u32::MAX - 1, u32::MAX] {
                // FIN remains unacked, is acked by the data, or was acked earlier.
                for fin_ack in 0..3 {
                    for offset in [0, 2] {
                        let cfg = ConnectionConfig {
                            abort_with_ack: enabled,
                            timestamps: timestamps == 1,
                            ..config(64, 8)
                        };
                        let (a, b) = pair(cfg, iss);
                        for mut a in [a, b] {
                            let next = a.receive.next();
                            let fin_seq = a.snd_nxt;
                            a.close().unwrap();
                            packet(&mut a, 40);
                            assert_eq!(a.state(), State::FinWait1);
                            let ack = fin_seq.wrapping_add(u32::from(fin_ack != 0));
                            let ts = (timestamps != 0).then_some((u32::MAX, 0));
                            if timestamps != 0 {
                                a.ts_recent = u32::MAX - 1;
                            }
                            if fin_ack == 2 {
                                timestamp_input(&mut a, 50, next, ack, ACK, ts, b"");
                                assert_eq!(a.state(), State::FinWait2);
                            }
                            timestamp_input(
                                &mut a,
                                60,
                                next.wrapping_add(offset),
                                ack,
                                ACK | PSH | FIN | URG,
                                ts,
                                b"lost",
                            );
                            assert_eq!(a.state(), State::Closed);
                            assert_eq!(a.close_reason(), Some(CloseReason::Aborted));
                            assert_eq!(a.next_deadline(), None);
                            assert_eq!(a.receive_used, 0);
                            assert!(!a.receive.has_data());
                            assert_eq!(a.receive.next(), next);
                            assert_eq!(a.terminal_readable_bytes(), 0);
                            let events = a.take_events();
                            assert_eq!(events.closed, Some(CloseReason::Aborted));
                            assert!(!events.readable && !events.pushed && !events.writable);
                            assert!(!events.half_closed && events.urgent.is_none());
                            let before = (a.pending_rst, a.reset_echo, a.reset_reply, a.now);
                            let size = if timestamps != 0 { 32 } else { 20 };
                            assert_eq!(
                                a.transmit(70, &mut vec![0; size - 1]),
                                Err(Error::OutputTooSmall)
                            );
                            assert_eq!((a.pending_rst, a.reset_echo, a.reset_reply, a.now), before);
                            a.abort(); // Local abort after terminal entry cannot replace the retry.
                            timestamp_input(&mut a, 70, next, ack, ACK, ts, b"later");
                            assert_eq!(a.pending_rst, before.0);
                            let bytes = packet(&mut a, 80);
                            let reset = wire::parse(ip(a.tuple()), &bytes).unwrap();
                            assert_eq!(reset.header.flags, RST);
                            assert_eq!(reset.header.sequence, ack.0);
                            assert_eq!(reset.header.acknowledgment, 0);
                            assert_eq!(reset.header.window, 0);
                            assert!(reset.payload.is_empty());
                            assert_eq!(reset.options.timestamps, ts.map(|(value, _)| (0, value)));
                            assert!(!a.reset_pending());
                            assert_eq!(a.reset_echo, None);
                            assert_eq!(a.transmit(90, &mut []), Ok(None));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn half_duplex_reset_rejects_invalid_segments_before_data_loss() {
    for enabled in [false, true] {
        for iss in [100, u32::MAX] {
            for invalid in 0..7 {
                let cfg = ConnectionConfig {
                    timestamps: true,
                    abort_with_ack: enabled,
                    ..config(64, 8)
                };
                let (mut a, _) = pair(cfg, iss);
                let next = a.receive.next();
                a.close().unwrap();
                packet(&mut a, 40);
                a.ts_recent = 100;
                let oldest = a.snd_una.wrapping_add(0u32.wrapping_sub(a.max_snd_wnd));
                let (seq, ack, flags, ts) = match invalid {
                    0 => (next, a.snd_nxt, ACK, None),
                    1 => (next, a.snd_nxt, ACK, Some((99, 0))),
                    2 => (next.wrapping_add(64), a.snd_nxt, ACK, Some((101, 0))),
                    3 => (next, a.snd_nxt, PSH, Some((101, 0))),
                    4 => (next, a.snd_nxt.wrapping_add(1), ACK, Some((101, 0))),
                    5 => (next, oldest.wrapping_add(u32::MAX), ACK, Some((101, 0))),
                    _ => (next, a.snd_nxt, SYN | ACK, Some((101, 0))),
                };
                let before = (a.receive.next(), a.snd_una, a.ts_recent, a.ts_latest);
                timestamp_input(&mut a, 50, seq, ack, flags, ts, b"bad");
                assert_eq!(a.state(), State::FinWait1);
                assert!(!a.reset_pending());
                assert_eq!(a.receive_used, 0);
                assert_eq!(
                    (a.receive.next(), a.snd_una, a.ts_recent, a.ts_latest),
                    before
                );
                let mut out = [0; 128];
                if let Some(n) = a.transmit(60, &mut out).unwrap() {
                    let reply = wire::parse(ip(tuple()), &out[..n]).unwrap();
                    assert_eq!(reply.header.flags & (RST | ACK), ACK);
                }
                let ack = a.snd_nxt;
                timestamp_input(&mut a, 70, next, ack, ACK, Some((101, 0)), b"new");
                assert_eq!(a.pending_rst, Some((ack, false)));
                assert_eq!(a.state(), State::Closed);
            }
        }
    }
}

#[test]
fn half_duplex_reset_requires_completed_handshake() {
    for enabled in [false, true] {
        for iss in [100, u32::MAX] {
            for simultaneous in [false, true] {
                let cfg = ConnectionConfig {
                    abort_with_ack: enabled,
                    ..config(64, 8)
                };
                let (mut a, _) = opening_for_close(cfg, iss, simultaneous);
                a.close().unwrap();
                packet(&mut a, 20); // SYN-ACK.
                packet(&mut a, 30); // FIN before handshake completion.
                let next = a.receive.next();
                inject(&mut a, 40, next, Seq(iss), ACK, 64, b"bad");
                assert!(!a.handshake_complete());
                assert_ne!(a.state(), State::Closed);
                assert_eq!(a.receive_used, 0);
                packet(&mut a, 40); // Existing nonterminal handshake rejection reset.
                let ack = Seq(iss.wrapping_add(1));
                inject(
                    &mut a,
                    50,
                    if simultaneous {
                        next.wrapping_add(u32::MAX)
                    } else {
                        next
                    },
                    ack,
                    ACK | if simultaneous { SYN } else { 0 },
                    64,
                    b"lost",
                );
                assert!(a.handshake_complete());
                assert_eq!(a.state(), State::Closed);
                assert_eq!(a.pending_rst, Some((ack, false)));
                let bytes = packet(&mut a, 60);
                let reset = wire::parse(ip(a.tuple()), &bytes).unwrap();
                assert_eq!(reset.header.flags, RST);
                assert_eq!(reset.header.sequence, ack.0);
            }
        }
    }
}

#[test]
fn close_after_write_shutdown_preserves_fin_or_resets_unread_data() {
    for passive in [false, true] {
        let (mut a, _) = pair(config(16, 8), 100);
        if passive {
            inject(&mut a, 40, Seq(901), Seq(101), ACK | FIN, 16, b"");
        }
        a.shutdown().unwrap();
        packet(&mut a, 50);
        if !passive {
            inject(&mut a, 60, Seq(901), Seq(101), ACK | FIN, 16, b"");
            packet(&mut a, 60); // Drain the FIN acknowledgment before close.
        }
        let state = if passive {
            State::LastAck
        } else {
            State::Closing
        };
        assert_eq!(a.state(), state);
        a.close().unwrap();
        a.close().unwrap();
        assert_eq!(a.state(), state);
        assert_eq!(a.snd_nxt, Seq(102));
        assert_eq!(a.transmit(70, &mut [0; 128]), Ok(None));
    }
    for phase in 0..3 {
        for unread in [false, true] {
            let (mut a, _) = pair(config(16, 8), 100);
            a.shutdown().unwrap();
            if phase >= 1 {
                let bytes = packet(&mut a, 40);
                assert_ne!(
                    wire::parse(ip(tuple()), &bytes).unwrap().header.flags & FIN,
                    0
                );
                assert_eq!(a.state(), State::FinWait1);
            }
            if phase == 2 {
                inject(&mut a, 50, Seq(901), Seq(102), ACK, 16, b"");
                assert_eq!(a.state(), State::FinWait2);
            }
            if unread {
                let ack = a.snd_nxt;
                inject(&mut a, 60, Seq(901), ack, ACK, 16, b"x");
            }
            let state = a.state();
            let next = a.snd_nxt;
            a.close().unwrap();
            assert_eq!(a.read(&mut [0]), Err(Error::InvalidState));
            if unread {
                assert_eq!(a.state(), State::Closed);
                assert_eq!(a.close_reason(), Some(CloseReason::Aborted));
                let bytes = packet(&mut a, 70);
                assert_ne!(
                    wire::parse(ip(tuple()), &bytes).unwrap().header.flags & RST,
                    0
                );
            } else {
                assert_eq!(a.state(), state);
                assert_eq!(a.snd_nxt, next);
                a.close().unwrap();
                if phase == 0 {
                    let bytes = packet(&mut a, 70);
                    assert_ne!(
                        wire::parse(ip(tuple()), &bytes).unwrap().header.flags & FIN,
                        0
                    );
                }
                assert_eq!(a.snd_nxt, Seq(102));
                assert_eq!(a.transmit(70, &mut [0; 128]), Ok(None));
            }
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
//= type=test
//= reason=Checks both default empty and configured one-octet payloads, without advancing the stream.
//# An implementation SHOULD send a keep-alive segment with no data
//# (SHLD-12); however, it MAY be configurable to send a keep-alive
//# segment containing one garbage octet (MAY-6), for compatibility with
//# erroneous TCP implementations.
fn keepalive_garbage_is_initialized_atomic_and_outside_stream_accounting() {
    assert!(!KeepaliveConfig::default().send_garbage);
    for garbage in [false, true] {
        let (mut a, mut b) = pair(config(16, 8), u32::MAX);
        a.set_keepalive(Some(KeepaliveConfig {
            idle_us: 100,
            interval_us: 50,
            probes: 2,
            send_garbage: garbage,
        }))
        .unwrap();
        let deadline = a.keepalive_deadline.unwrap();
        a.timeout(deadline).unwrap();
        let before = (
            a.snd_nxt,
            a.snd_una,
            a.acknowledged,
            a.sample,
            a.rto_deadline,
            a.keepalive_probes,
            a.next_deadline(),
            a.last_sent,
        );
        assert_eq!(
            a.transmit(deadline, &mut [0; 19]),
            Err(Error::OutputTooSmall)
        );
        if garbage {
            assert_eq!(
                a.transmit(deadline, &mut [0; 20]),
                Err(Error::OutputTooSmall)
            );
        }
        assert_eq!(
            (
                a.snd_nxt,
                a.snd_una,
                a.acknowledged,
                a.sample,
                a.rto_deadline,
                a.keepalive_probes,
                a.next_deadline(),
                a.last_sent
            ),
            before
        );
        assert!(a.keepalive_pending);
        let bytes = deliver(&mut a, &mut b, deadline);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.header.sequence, u32::MAX);
        assert_eq!(segment.payload, if garbage { &b"\0"[..] } else { &b""[..] });
        assert_eq!(segment.header.flags, ACK);
        assert_eq!(
            (
                a.snd_nxt,
                a.snd_una,
                a.acknowledged,
                a.sample,
                a.rto_deadline
            ),
            (before.0, before.1, before.2, before.3, before.4)
        );
        assert_eq!(a.send.len(), 0);
        assert_eq!(a.keepalive_probes, 1);
        assert_eq!(b.read(&mut [0]), Err(Error::WouldBlock));
        assert!(!b.take_events().pushed);
        deliver(&mut b, &mut a, deadline);
        assert_eq!(a.acknowledged, 0);
    }
}
#[test]
//= https://www.rfc-editor.org/rfc/rfc2883#section-4
//= type=test
//= reason=Latest checked arrival supersedes D-SACK before ACK-only, sequence/ACK rejection, missing TS and PAWS drops; failed output without new input preserves it. Cumulative and queued duplicates are exercised across wrap.
//# (1) A D-SACK block is only used to report a duplicate contiguous
//# sequence of data received by the receiver in the most recent packet.
fn dsack_latest_checked_arrival_supersedes_pending_report() {
    for queued in [false, true] {
        // None means output retry without another arrival.
        for newer in [None, Some(0), Some(1), Some(2), Some(3), Some(4)] {
            let cfg = ConnectionConfig {
                timestamps: true,
                ..sack_config(128)
            };
            let (mut a, mut b) = pair(cfg, u32::MAX - 4);
            a.write(b"abcdefgh").unwrap();
            let bytes = packet(&mut a, 2_000);
            let mut data = wire::parse(ip(tuple()), &bytes).unwrap();
            if queued {
                data.header.sequence = data.header.sequence.wrapping_add(2);
            }
            // Re-encode so both initial and duplicate arrivals are checked packets.
            let mut bytes = [0; 128];
            let n = wire::encode(
                ip(tuple()),
                data.header,
                data.raw_options,
                data.payload,
                &mut bytes,
            )
            .unwrap();
            let data = wire::parse(ip(tuple()), &bytes[..n]).unwrap();
            b.input(2_000, &data).unwrap();
            packet(&mut b, 2_000);
            b.input(3_000, &data).unwrap();
            let duplicate = (data.header.sequence, data.header.sequence.wrapping_add(8));
            assert_eq!(b.receive.sack_blocks(3)[0], Some(duplicate));
            assert_eq!(b.transmit(3_000, &mut [0; 19]), Err(Error::OutputTooSmall));
            assert_eq!(b.receive.sack_blocks(3)[0], Some(duplicate));
            let next = b.receive.next();
            let ack = b.snd_una;
            let edge = b.receive.right_edge();
            match newer {
                None => {}
                Some(0) => timestamp_input(&mut b, 4_000, next, ack, ACK, Some((4, 0)), b""),
                Some(1) => {
                    timestamp_input(&mut b, 4_000, edge, ack, ACK, Some((4, 0)), b"rejected")
                }
                Some(2) => timestamp_input(
                    &mut b,
                    4_000,
                    next,
                    ack.wrapping_add(1),
                    ACK,
                    Some((4, 0)),
                    b"bad ACK",
                ),
                Some(3) => timestamp_input(&mut b, 4_000, next, ack, ACK, None, b"missing"),
                Some(4) => {
                    timestamp_input(&mut b, 4_000, next, ack, ACK, Some((u32::MAX, 0)), b"stale")
                }
                _ => unreachable!(),
            }
            assert_eq!(b.transmit(4_000, &mut [0; 19]), Err(Error::OutputTooSmall));
            let bytes = packet(&mut b, 4_000);
            let report = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
            if newer.is_none() {
                assert_eq!(report.options.sack_blocks[0], Some(duplicate));
                assert_eq!(report.options.sack_blocks[1], queued.then_some(duplicate));
            } else {
                assert_eq!(report.options.sack_blocks[0], queued.then_some(duplicate));
                assert_eq!(report.options.sack_blocks[1], None);
            }
            b.immediate_ack();
            let bytes = packet(&mut b, 5_000);
            assert_eq!(
                wire::parse(ip(reverse(tuple())), &bytes)
                    .unwrap()
                    .options
                    .sack_blocks[1],
                None
            );
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc2883#section-4.3
//= type=test
//= reason=Prior-cycle reports with wrapped old or already-SACKed intervals are advisory even during RACK/PRR recovery: no UNA/storage release, congestion undo, fresh delivery or RTT credit.
//# TCP senders receiving D-SACK blocks should be aware that a segment
//# reported as a duplicate segment could possibly have been from a prior
//# cycle through the sequence number space.
fn dsack_prior_cycle_wrap_is_advisory_during_recovery() {
    for above_ack in [false, true] {
        let mut a = rack_flight(u32::MAX - 4999);
        let base = a.send_base;
        rack_sack(&mut a, 200_000, 6000, &[(8000, 10_000)]);
        a.timeout(225_000).unwrap();
        packet(&mut a, 225_000);
        assert!(a.sack_recovery.is_some());
        let before = (
            a.snd_una,
            a.send.len(),
            a.congestion.cwnd(),
            a.congestion.ssthresh(),
            a.rtt.srtt(),
            a.rtt.rto(),
            a.sample,
            a.prr.unwrap().counters(),
        );
        let blocks = if above_ack {
            vec![
                (base.wrapping_add(8100).0, base.wrapping_add(8200).0),
                (base.wrapping_add(8000).0, base.wrapping_add(10_000).0),
            ]
        } else {
            vec![(base.wrapping_add(4000).0, base.wrapping_add(6000).0)]
        };
        let una = a.snd_una;
        sack_ack(&mut a, 226_000, una, &blocks);
        assert_eq!(
            (
                a.snd_una,
                a.send.len(),
                a.congestion.cwnd(),
                a.congestion.ssthresh(),
                a.rtt.srtt(),
                a.rtt.rto(),
                a.sample,
                a.prr.unwrap().counters()
            ),
            before
        );
        assert!(a.sack_recovery.is_some());
        assert!(a.rack.ack_sample.is_none());
        assert!(a.rack.adaptation().0 <= 2);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
//= type=test
//= reason=Forged nonzero SYN and synchronized no-ACK echoes cannot acknowledge data or consume/update RTT samples; SYN TSval still initializes PAWS.
//# When the ACK bit is not set, the receiver MUST ignore
//# the value of the TSecr field.
fn timestamps_non_ack_echo_is_ignored() {
    let cfg = ConnectionConfig {
        timestamps: true,
        ..sack_config(128)
    };
    let mut a = Connection::active(tuple(), cfg.clone(), 100, 0).unwrap();
    packet(&mut a, 1_000);
    let before = (a.snd_una, a.rtt.srtt(), a.rtt.rto());
    let end = a.snd_nxt;
    timestamp_input(&mut a, 2_000, Seq(900), end, SYN, Some((9, 1)), b"");
    assert_eq!((a.snd_una, a.rtt.srtt(), a.rtt.rto()), before);
    assert_eq!(a.ts_recent, 9);
    assert!(a.sample.is_none()); // Simultaneous SYN deliberately cancels sampling.
    let (mut a, _) = pair(cfg, 100);
    a.write(b"sample").unwrap();
    packet(&mut a, 2_000);
    let before = (
        a.snd_una,
        a.snd_wnd,
        a.send.len(),
        a.sample,
        a.rtt.srtt(),
        a.rtt.rto(),
        a.receive.next(),
    );
    let next = a.receive.next();
    let end = a.snd_nxt;
    timestamp_input(&mut a, 3_000, next, end, 0, Some((3, 2)), b"ignored");
    assert_eq!(
        (
            a.snd_una,
            a.snd_wnd,
            a.send.len(),
            a.sample,
            a.rtt.srtt(),
            a.rtt.rto(),
            a.receive.next()
        ),
        before
    );
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
//= type=test
//= reason=Established fallback accepts TS-bearing ACK/data normally without late negotiation, PAWS/echo state changes or outgoing TS; forged echo cannot suppress normal local-clock RTT.
//# If a TSopt is received on a connection where TSopt was not negotiated
//# in the initial three-way handshake, the TSopt MUST be ignored and the
//# packet processed normally.
fn timestamps_unnegotiated_established_options_are_ignored() {
    let mut a = Connection::active(
        tuple(),
        ConnectionConfig {
            timestamps: true,
            ..sack_config(128)
        },
        100,
        0,
    )
    .unwrap();
    let syn_bytes = packet(&mut a, 0);
    let syn = wire::parse(ip(tuple()), &syn_bytes).unwrap();
    let mut b = Connection::passive(reverse(tuple()), sack_config(128), 900, 10, &syn).unwrap();
    deliver(&mut b, &mut a, 20);
    deliver(&mut a, &mut b, 30);
    assert!(!a.timestamps && !b.timestamps);
    a.rtt = RttEstimator::new(1_000_000);
    a.write(b"sample").unwrap();
    packet(&mut a, 2_000_000);
    let before = (a.ts_recent, a.ts_recent_at, a.ts_latest);
    let next = a.receive.next();
    let ack = a.snd_nxt;
    timestamp_input(
        &mut a,
        2_600_000,
        next,
        ack,
        ACK,
        Some((0x8000_0000, u32::MAX)),
        b"normal",
    );
    assert_eq!(a.snd_una, ack);
    assert_eq!(a.snd_wnd, 1024);
    assert_eq!(a.rtt.rto(), 1_800_000);
    assert_eq!((a.ts_recent, a.ts_recent_at, a.ts_latest), before);
    assert!(!a.timestamps);
    assert_eq!(a.read(&mut [0; 6]), Ok(6));
    let bytes = packet(&mut a, 2_600_000);
    assert!(
        wire::parse(ip(tuple()), &bytes)
            .unwrap()
            .options
            .timestamps
            .is_none()
    );
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
//= type=test
//= reason=Older TS queued data is delivered after newer hole filler without second PAWS; a fresh raw arrival with the same old TS is still rejected.
//# It is important to note that the timestamp MUST be checked only when
//# a segment first arrives at the receiver, regardless of whether it is
//# in sequence or it must be queued for later delivery.
fn timestamps_queued_old_data_is_not_rechecked_after_hole_fill() {
    let (mut a, _) = pair(
        ConnectionConfig {
            timestamps: true,
            ..sack_config(128)
        },
        100,
    );
    let next = a.receive.next();
    let ack = a.snd_una;
    timestamp_input(
        &mut a,
        1_000,
        next.wrapping_add(1),
        ack,
        ACK,
        Some((1, 0)),
        b"b",
    );
    assert_eq!(a.receive.next(), next);
    packet(&mut a, 1_000);
    timestamp_input(&mut a, 2_000, next, ack, ACK, Some((2, 0)), b"a");
    assert_eq!(a.ts_recent, 2);
    assert_eq!(a.receive.next(), next.wrapping_add(2));
    let mut out = [0; 2];
    assert_eq!(a.read(&mut out), Ok(2));
    assert_eq!(&out, b"ab");
    timestamp_input(
        &mut a,
        3_000,
        next.wrapping_add(2),
        ack,
        ACK,
        Some((1, 0)),
        b"c",
    );
    assert_eq!(a.receive.next(), next.wrapping_add(2));
    assert_eq!(a.read(&mut out), Err(Error::WouldBlock));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-4.3
//= type=test
//= reason=Equality at both TS.Recent and Last.ACK.sent refreshes timestamp age; later sequence cannot replace echo, older TS fails PAWS, serial wrap accepts zero.
//# SEG.TSval >= TS.Recent and SEG.SEQ <= Last.ACK.sent
//#
//# then SEG.TSval is copied to TS.Recent; otherwise, it is ignored.
fn timestamps_echo_predicates_are_inclusive() {
    let (mut a, _) = pair(
        ConnectionConfig {
            timestamps: true,
            ..sack_config(128)
        },
        100,
    );
    let next = a.receive.next();
    let ack = a.snd_una;
    a.ts_recent = u32::MAX;
    a.ts_latest = u32::MAX;
    timestamp_input(&mut a, 1_000, next, ack, ACK, Some((u32::MAX, 0)), b"");
    assert_eq!(a.ts_recent_at, 1_000);
    timestamp_input(
        &mut a,
        2_000,
        next.wrapping_add(1),
        ack,
        ACK,
        Some((0, 0)),
        b"b",
    );
    assert_eq!(a.ts_recent, u32::MAX);
    timestamp_input(&mut a, 3_000, next, ack, ACK, Some((0, 0)), b"a");
    assert_eq!(a.ts_recent, 0);
    let bytes = packet(&mut a, 3_000);
    assert_eq!(
        wire::parse(ip(tuple()), &bytes).unwrap().options.timestamps,
        Some((3, 0))
    );
    timestamp_input(
        &mut a,
        4_000,
        next.wrapping_add(2),
        ack,
        ACK,
        Some((u32::MAX, 0)),
        b"stale",
    );
    assert_eq!(a.ts_recent_at, 3_000);
    assert_eq!(a.receive.next(), next.wrapping_add(2));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.2
//= type=test
//= reason=SYN and SYN-ACK explicitly encode Some(0) for small buffers, distinct from absent WS; both have unscaled effective windows.
//# MAY be zero (offering to scale, while applying a scale factor of 1 to
//# the receive window).
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.2
//= type=test
//= reason=Changed WS on established data and ACK cannot change negotiated shifts or effective subsequent windows, with zero/nonzero and absent negotiation.
//# A Window Scale option in a segment
//# without a SYN bit MUST be ignored.
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.1
//= type=test
//= reason=Established data/ACK WS does not renegotiate either direction or affect effective subsequent windows.
//# This option is sent only in a <SYN> segment (a
//# segment with the SYN bit on), hence the window scale is fixed in each
//# direction when a connection is opened.
fn window_scale_zero_offer_absence_and_non_syn_options() {
    for capacity in [64, 131072] {
        for offered in [false, true] {
            let cfg = config(capacity, 128);
            let mut a = Connection::active(tuple(), cfg.clone(), 100, 0).unwrap();
            let bytes = packet(&mut a, 0);
            let syn = wire::parse(ip(tuple()), &bytes).unwrap();
            let exponent = if capacity == 64 { 0 } else { 2 };
            assert_eq!(syn.options.window_scale, Some(exponent));
            let mut options = vec![2, 4, 0, 128];
            if offered {
                options.extend_from_slice(&[1, 3, 3, exponent]);
            }
            let mut bytes = [0; 64];
            let n = wire::encode(ip(tuple()), syn.header, &options, b"", &mut bytes).unwrap();
            let syn = wire::parse(ip(tuple()), &bytes[..n]).unwrap();
            let mut b = Connection::passive(reverse(tuple()), cfg, 900, 10, &syn).unwrap();
            let bytes = deliver(&mut b, &mut a, 20);
            assert_eq!(
                wire::parse(ip(reverse(tuple())), &bytes)
                    .unwrap()
                    .options
                    .window_scale,
                offered.then_some(exponent)
            );
            deliver(&mut a, &mut b, 30);
            assert_eq!((a.scaling, b.scaling), (offered, offered));
            let before = (a.scaling, a.local_scale, a.peer_scale);
            let shift = if offered { exponent } else { 0 };
            let next = a.receive.next();
            let ack = a.snd_una;
            for (i, payload) in [b"x".as_slice(), b"".as_slice()].into_iter().enumerate() {
                let mut bytes = [0; 64];
                let n = wire::encode(
                    ip(reverse(tuple())),
                    Header {
                        source_port: 2000,
                        destination_port: 1000,
                        sequence: next.wrapping_add(i as u32).0,
                        acknowledgment: ack.0,
                        flags: SYN | ACK,
                        window: 7,
                        urgent_pointer: 0,
                    },
                    &[1, 3, 3, 14],
                    payload,
                    &mut bytes,
                )
                .unwrap();
                // The encoder refuses illegal output options; inject peer input.
                bytes[13] = ACK;
                bytes[16..18].fill(0);
                let sum = wire::checksum(ip(reverse(tuple())), &bytes[..n]).unwrap();
                bytes[16..18].copy_from_slice(&sum.to_be_bytes());
                a.input(
                    40 + i as u64,
                    &wire::parse(ip(reverse(tuple())), &bytes[..n]).unwrap(),
                )
                .unwrap();
                assert_eq!((a.scaling, a.local_scale, a.peer_scale), before);
                assert_eq!(a.snd_wnd, 7u32 << shift);
            }
            inject(&mut a, 42, next.wrapping_add(1), ack, ACK, 9, b"");
            assert_eq!(a.snd_wnd, 9u32 << shift);
            a.immediate_ack();
            // Without WS, the one byte below the wire cap is sub-MSS
            // credit: preserve the old edge rather than advancing it.
            let expected = if offered {
                ((capacity - 1) >> shift).min(65535) as u16
            } else {
                (capacity.min(65535) - 1) as u16
            };
            let promised = a.advertised_edge;
            let bytes = packet(&mut a, 43);
            let seg = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(seg.header.window, expected);
            if !offered {
                assert_eq!(a.advertised_edge, promised);
            }
            assert!(seg.options.window_scale.is_none());
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.4
//= type=test
//= reason=Delayed byte beyond quantized latest edge but below prior committed ACK edge is accepted and delivered after batched hole fill across wrap; receive allocation stays bounded. Arbitrary 65-range fragmentation remains a separate TODO.
//# 1)  The receiver MUST honor, as in window, any segment that would
//# have been in window for any <ACK> sent by the receiver.
fn scaled_window_accepts_previously_promised_retracted_byte() {
    for iss in [100, u32::MAX - 4] {
        let (_, mut b) = pair(config(65536, 1460), iss);
        b.immediate_ack();
        packet(&mut b, 40);
        let next = b.receive.next();
        let ack = b.snd_una;
        let promised = b.advertised_edge;
        assert_eq!(promised.distance_from(next), 65536);
        inject(&mut b, 41, next, ack, ACK, 8192, b"a");
        b.immediate_ack();
        let bytes = packet(&mut b, 42);
        let seg = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
        assert_eq!(seg.header.window, 32767); // floor(65535 / 2), never round up.
        let encoded_edge = Seq(seg.header.acknowledgment)
            .wrapping_add(u32::from(seg.header.window) << b.local_scale);
        assert_eq!(encoded_edge, promised.wrapping_add(u32::MAX));
        assert_eq!(b.advertised_edge, promised);
        inject(&mut b, 43, encoded_edge, ack, ACK, 8192, b"z");
        assert_eq!(b.receive_used, 2);
        assert_eq!(b.receive.next(), next.wrapping_add(1));
        // Process the entire batch before output, including the retained tail.
        inject(
            &mut b,
            44,
            next.wrapping_add(1),
            ack,
            ACK,
            8192,
            &[b'b'; 32767],
        );
        inject(
            &mut b,
            44,
            next.wrapping_add(32768),
            ack,
            ACK,
            8192,
            &[b'c'; 32767],
        );
        assert_eq!(b.receive.next(), promised);
        assert_eq!(b.receive_used, b.config.receive_capacity);
        assert_eq!(b.receive_window(), 0);
        let mut out = vec![0; 65536];
        assert_eq!(b.read(&mut out), Ok(65536));
        assert_eq!(out[0], b'a');
        assert!(out[1..32768].iter().all(|&v| v == b'b'));
        assert!(out[32768..65535].iter().all(|&v| v == b'c'));
        assert_eq!(out[65535], b'z');
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-4.1
//= type=test
//= reason=Matching echo on duplicate/SACK-only ACK leaves ordinary pending sample untouched; RACK samples local original send time independently of forged or matching TSecr, without advancing UNA.
//# RTTM Rule: A TSecr value received in a segment MAY be used to update
//# the averaged RTT measurement only if the segment advances
//# the left edge of the send window, i.e., SND.UNA is
//# increased.
fn timestamps_nonadvancing_echo_does_not_consume_ordinary_sample() {
    for rack in [false, true] {
        for echo in [2, u32::MAX] {
            let cfg = ConnectionConfig {
                timestamps: true,
                rack,
                initial_window: InitialWindow::Iw10,
                ..sack_config(128)
            };
            let (mut a, _) = pair(cfg, 100);
            a.rtt = RttEstimator::new(1_000_000);
            a.write(&[1; 256]).unwrap();
            packet(&mut a, 2_000);
            let bytes = packet(&mut a, 2_000);
            let second = Seq(wire::parse(ip(tuple()), &bytes).unwrap().header.sequence);
            let end = a.snd_nxt;
            let pending = a.sample;
            let una = a.snd_una;
            let next = a.receive.next();
            timestamp_input(&mut a, 2_500, next, una, ACK, Some((2, echo)), b"");
            assert_eq!(a.sample, pending);
            assert_eq!(a.rtt.srtt(), None);
            let options = [1, 1, 8, 10, 0, 0, 0, 3];
            let mut options = options.to_vec();
            options.extend_from_slice(&echo.to_be_bytes());
            options.extend_from_slice(&[1, 1, 5, 10]);
            options.extend_from_slice(&second.0.to_be_bytes());
            options.extend_from_slice(&end.0.to_be_bytes());
            let mut bytes = [0; 64];
            let n = wire::encode(
                ip(reverse(tuple())),
                Header {
                    source_port: 2000,
                    destination_port: 1000,
                    sequence: next.0,
                    acknowledgment: una.0,
                    flags: ACK,
                    window: 8192,
                    urgent_pointer: 0,
                },
                &options,
                b"",
                &mut bytes,
            )
            .unwrap();
            a.input(
                3_000,
                &wire::parse(ip(reverse(tuple())), &bytes[..n]).unwrap(),
            )
            .unwrap();
            assert_eq!(a.snd_una, una);
            assert_eq!(a.sample, pending);
            assert_eq!(a.rtt.srtt(), rack.then_some(1_000));
            assert_eq!(a.rack.ack_sample, Some(1_000)); // Consumed by RTO only with RACK enabled.
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-4.2
//= type=test
//= reason=Dense SACK and cumulative ACKs share one update per causal round; four bulk flights assert exact RFC6298 estimator history and actual update counts.
//# to update the RTT estimator, an implementation SHOULD try to adhere
//# to the spirit of the history specified in [RFC6298].
fn timestamps_bulk_flight_history_and_mixed_rack_samples() {
    for rack in [false, true] {
        let cfg = ConnectionConfig {
            timestamps: true,
            rack,
            initial_window: InitialWindow::Iw10,
            ..sack_config(128)
        };
        let (mut a, _) = pair(cfg, 100);
        a.rtt = RttEstimator::new(1_000_000);
        let mut expected = RttEstimator::new(1_000_000);
        for round in 0..4u64 {
            let sent = 2_000_000 + round * 2_000_000;
            let latency = if round < 2 { 100_000 } else { 200_000 };
            a.write(&[1; 8 * 116]).unwrap(); // MSS less the negotiated TS option.
            let mut ends = vec![];
            for _ in 0..8 {
                let bytes = packet(&mut a, sent);
                let seg = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(seg.payload.len(), 116);
                ends.push(Seq(seg.header.sequence).wrapping_add(116));
            }
            let pending = a.sample;
            let next = a.receive.next();
            let una = a.snd_una;
            if rack {
                // Dense SACK delivery uses the same estimator gate as RTTM:
                // only the round's first SACK updates the estimator.
                expected.sample(latency);
                for end in &ends {
                    let mut options = vec![1, 1, 8, 10];
                    options.extend_from_slice(&((sent / 1000) as u32).to_be_bytes());
                    options.extend_from_slice(&u32::MAX.to_be_bytes());
                    options.extend_from_slice(&[1, 1, 5, 10]);
                    options.extend_from_slice(
                        &ends[0].wrapping_add(0u32.wrapping_sub(116)).0.to_be_bytes(),
                    );
                    options.extend_from_slice(&end.0.to_be_bytes());
                    let mut bytes = [0; 64];
                    let n = wire::encode(
                        ip(reverse(tuple())),
                        Header {
                            source_port: 2000,
                            destination_port: 1000,
                            sequence: next.0,
                            acknowledgment: una.0,
                            flags: ACK,
                            window: 8192,
                            urgent_pointer: 0,
                        },
                        &options,
                        b"",
                        &mut bytes,
                    )
                    .unwrap();
                    a.input(
                        sent + latency,
                        &wire::parse(ip(reverse(tuple())), &bytes[..n]).unwrap(),
                    )
                    .unwrap();
                    assert_eq!(
                        (a.rtt.srtt(), a.rtt.variance(), a.rtt.rto()),
                        (expected.srtt(), expected.variance(), expected.rto())
                    );
                    assert_eq!(a.sample, pending);
                }
            }
            for (i, end) in ends.into_iter().enumerate() {
                timestamp_input(
                    &mut a,
                    sent + latency + 1000 + i as u64,
                    next,
                    end,
                    ACK,
                    Some(((sent / 1000) as u32, (sent / 1000) as u32)),
                    b"",
                );
                if i == 0 && !rack {
                    expected.sample(latency + 1000);
                }
                assert_eq!(a.sample, None);
                assert_eq!(
                    (a.rtt.srtt(), a.rtt.variance(), a.rtt.rto()),
                    (expected.srtt(), expected.variance(), expected.rto())
                );
            }
            assert_eq!(a.send.len(), 0);
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6298#section-3
//= type=test
//= reason=Continuous eight/64-packet sliding flights, immediate/delayed/stretched ACKs and repeated millisecond TSvals assert eight actual estimator updates in eight causal RTTs, with and without timestamps/RACK. All-invalid echo streams assert exact local SRTT/RTTVAR/RTO for three different forgeries, independent of TSecr.
//# A TCP implementation MUST take at least one RTT measurement per RTT (unless that is
//# not possible per Karn's algorithm).
//= https://www.rfc-editor.org/rfc/rfc6298#section-3
//= type=test
//= reason=64-packet windows intentionally use one update per causal RTT, retaining fixed-weight history instead of suggested per-ACK sampling; increasing rate requires adjusted weights.
//# However, when using the timestamp option, each ACK can be used as an RTT sample. RFC
//# 1323 [JBB92] suggests that TCP connections utilizing large congestion windows should
//# take many RTT samples per window of data to avoid aliasing effects in the estimated
//# RTT.
fn rtt_cadence_continuous_delayed_stretched_and_same_tick() {
    for width in [8usize, 64] {
        for timestamps in [false, true] {
            for forge in if timestamps {
                &[0u32, 1, 0x8000_0000, 0x4000_0000][..]
            } else {
                &[0][..]
            } {
                for rack in [false, true] {
                    for batch in [1usize, 2, 8] {
                        for step in [100u64, 1_000, 10_000] {
                            let cfg = ConnectionConfig {
                                timestamps,
                                rack,
                                nagle: false,
                                initial_window: InitialWindow::Iw10,
                                ..sack_config(128)
                            };
                            let (mut a, _) = pair(cfg, u32::MAX - 100);
                            a.timestamp_offset = u32::MAX - 2000;
                            a.rtt = RttEstimator::new(1_000_000);
                            let mut expected = RttEstimator::new(1_000_000);
                            let mut expected_local = RttEstimator::new(1_000_000);
                            a.rtt_sample_after = None;
                            let mut flight = alloc::collections::VecDeque::new();
                            let base = 2_000_000;
                            let send_one = |a: &mut Connection, sent| {
                                a.write(b"x").unwrap();
                                let bytes = packet(a, sent);
                                let seg = wire::parse(ip(tuple()), &bytes).unwrap();
                                assert_eq!(seg.payload, b"x");
                                (
                                    Seq(seg.header.sequence).wrapping_add(1),
                                    sent,
                                    seg.options.timestamps.map(|ts| ts.0),
                                )
                            };
                            for i in 0..width {
                                flight.push_back(send_one(&mut a, base + i as u64 * step));
                            }
                            for group in 0..width * 8 / batch {
                                let mut delivered = Vec::new();
                                for _ in 0..batch {
                                    delivered.push(flight.pop_front().unwrap());
                                }
                                let &(ack, sent, echo) = delivered.last().unwrap();
                                let now = sent + width as u64 * step;
                                let next = a.receive.next();
                                if timestamps {
                                    if *forge != 0 {
                                        assert!(a.sample.is_none_or(|(end, sent)| {
                                            !ack.at_or_after(end)
                                                || echo.unwrap().wrapping_add(*forge)
                                                    != a.timestamp_value(sent)
                                        }));
                                    }
                                    timestamp_input(
                                        &mut a,
                                        now,
                                        next,
                                        ack,
                                        ACK,
                                        Some((
                                            now as u32 / 1000,
                                            echo.unwrap().wrapping_add(*forge),
                                        )),
                                        b"",
                                    );
                                } else {
                                    inject(&mut a, now, next, ack, ACK, 8192, b"");
                                }
                                // One update per window-sized causal round, even though
                                // flight never drains and delayed ACKs cover multiple sends:
                                // 1 + group * batch / width updates so far, eight in all.
                                // The round's first ACK takes one sample. Without timestamps
                                // the ordinary timed segment times the round's first
                                // original; with timestamps a valid RTTM echo times that
                                // same original, otherwise the local ledger times the
                                // latest one. RTTVAR stays positive, so a missing or extra
                                // update changes the estimator.
                                if group * batch % width == 0 {
                                    let (_, first_sent, first_echo) = delivered[0];
                                    let rttm = !timestamps || (*forge == 0 && first_echo == echo);
                                    expected.sample(now - if rttm { first_sent } else { sent });
                                }
                                assert_eq!(
                                    (a.rtt.srtt(), a.rtt.variance(), a.rtt.rto()),
                                    (expected.srtt(), expected.variance(), expected.rto()),
                                    "TS={timestamps} RACK={rack} batch={batch} step={step}"
                                );
                                if *forge != 0 {
                                    // Every ACK has rejected TSecr. Differing forgeries
                                    // must yield the same exact local-clock estimator.
                                    if group * batch % width == 0 {
                                        expected_local.sample(width as u64 * step);
                                    }
                                    assert_eq!(
                                        (a.rtt.srtt(), a.rtt.variance(), a.rtt.rto()),
                                        (
                                            expected_local.srtt(),
                                            expected_local.variance(),
                                            expected_local.rto()
                                        ),
                                        "forge={forge} RACK={rack} width={width} batch={batch} step={step}"
                                    );
                                }
                                for (i, _) in delivered.iter().enumerate() {
                                    flight.push_back(send_one(&mut a, now + i as u64 * step));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn rtt_cadence_invalid_echo_ledger_fallback_and_karn_counts() {
    for rack in [false, true] {
        let cfg = ConnectionConfig {
            timestamps: true,
            rack,
            nagle: false,
            initial_window: InitialWindow::Iw10,
            ..sack_config(128)
        };
        let (mut a, _) = pair(cfg.clone(), u32::MAX - 100);
        // Exercise the secret offset and millisecond wrap, not raw TSecr arithmetic.
        a.timestamp_offset = u32::MAX - 2000;
        a.rtt = RttEstimator::new(1_000_000);
        a.rtt_sample_after = None;
        a.write(&[1; 232]).unwrap();
        packet(&mut a, 2_000_000);
        let first = a.snd_nxt;
        packet(&mut a, 2_000_000);
        let end = a.snd_nxt;
        let next = a.receive.next();
        let echo = a.timestamp_value(2_000_000);
        timestamp_input(
            &mut a,
            2_100_000,
            next,
            first,
            ACK,
            Some((3000, echo.wrapping_sub(1))),
            b"",
        );
        // Invalid RTTM is not eligible; both algorithms use local original timing.
        // Exactly one 100ms sample: RTTVAR = R/2.
        assert_eq!(
            (a.rtt.srtt(), a.rtt.variance(), a.rtt.rto()),
            (Some(100_000), 50_000, 1_000_000)
        );
        assert!(a.sample.is_none());
        timestamp_input(&mut a, 2_100_000, next, end, ACK, Some((3000, echo)), b"");
        // No new output needed to rearm; a second sample would reduce RTTVAR.
        assert_eq!(
            (a.rtt.srtt(), a.rtt.variance(), a.rtt.rto()),
            (Some(100_000), 50_000, 1_000_000)
        );

        let (mut a, _) = pair(cfg, 100);
        a.rtt = RttEstimator::new(1_000_000);
        a.rtt_sample_after = None;
        a.write(b"lost").unwrap();
        packet(&mut a, 2_000_000);
        a.timeout(3_000_000).unwrap();
        packet(&mut a, 3_000_000);
        let end = a.snd_nxt;
        let next = a.receive.next();
        let echo = a.timestamp_value(3_000_000);
        timestamp_input(&mut a, 3_100_000, next, end, ACK, Some((4000, echo)), b"");
        assert_eq!(a.rtt.srtt(), None); // Matching echo does not undo Karn.
        a.write(b"fresh").unwrap();
        packet(&mut a, 3_100_000);
        let end = a.snd_nxt;
        let echo = a.timestamp_value(3_100_000);
        timestamp_input(&mut a, 3_200_000, next, end, ACK, Some((4000, echo)), b"");
        assert_eq!((a.rtt.srtt(), a.rtt.variance()), (Some(100_000), 50_000));
    }
}

fn timestamp_input(
    c: &mut Connection,
    now: u64,
    sequence: Seq,
    acknowledgment: Seq,
    flags: u8,
    ts: Option<(u32, u32)>,
    payload: &[u8],
) {
    let mut options = [1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0];
    if let Some((value, echo)) = ts {
        options[4..8].copy_from_slice(&value.to_be_bytes());
        options[8..].copy_from_slice(&echo.to_be_bytes());
    }
    let mut bytes = vec![0; 32 + payload.len()];
    let ip = ip(reverse(c.tuple));
    let n = wire::encode(
        ip,
        Header {
            source_port: c.tuple.remote.port(),
            destination_port: c.tuple.local.port(),
            sequence: sequence.0,
            acknowledgment: acknowledgment.0,
            flags,
            window: 1024,
            urgent_pointer: 0,
        },
        if ts.is_some() { &options } else { &[] },
        payload,
        &mut bytes,
    )
    .unwrap();
    c.input(now, &wire::parse(ip, &bytes[..n]).unwrap())
        .unwrap();
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
//= type=test
//= reason=Timestamp negotiation is config/peer-SYN gated; SYN TSecr=0, ACK replies echo ts_recent, bool timestamps retains negotiated state.
//# If
//# the ACK bit is not set in the outgoing TCP header, the sender of that
//# segment SHOULD set the TSecr field to zero.
//= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
//= type=test
//= reason=Timestamp negotiation is config/peer-SYN gated; SYN TSecr=0, ACK replies echo ts_recent, bool timestamps retains negotiated state.
//# When the ACK bit is set
//# in an outgoing segment, the sender MUST echo a recently received
//# TSval sent by the remote TCP in the TSval field of a Timestamps
//# option.
//= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
//= type=test
//= reason=Timestamp negotiation is config/peer-SYN gated; SYN TSecr=0, ACK replies echo ts_recent, bool timestamps retains negotiated state.
//# A TCP MAY send the TSopt in an initial <SYN> segment (i.e., segment
//# containing a SYN bit and no ACK bit), and MAY send a TSopt in
//# <SYN,ACK> only if it received a TSopt in the initial <SYN> segment
//# for the connection.
//= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
//= type=test
//= reason=Negotiated non-RST output always allocates TS; timestamp-enabled path budget minimum 40 preserves SYN options, ordinary data/ACK/FIN/probe/keepalive and user-abort RST retain TS. Reactive reset limits audited separately in section 5.2.
//# Once TSopt has been successfully negotiated, that is both <SYN> and
//# <SYN,ACK> contain TSopt, the TSopt MUST be sent in every non-<RST>
//# segment for the duration of the connection, and SHOULD be sent in an
//# <RST> segment (see Section 5.2 for details).
//= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
//= type=test
//= reason=Timestamp negotiation is config/peer-SYN gated; SYN TSecr=0, ACK replies echo ts_recent, bool timestamps retains negotiated state.
//# The TCP SHOULD remember
//# this state by setting a flag, referred to as Snd.TS.OK, to one.
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.2
//= type=test
//= reason=learn_syn copies offered TSval into TS.Recent and ts_latest on both active/passive negotiation.
//# TSval timestamps sent on <SYN> and <SYN,ACK> segments are used to
//# initialize PAWS.
fn timestamps_negotiate_fallback_and_atomic_output() {
    for active_ts in [false, true] {
        for passive_ts in [false, true] {
            let mut ac = config(1024, 128);
            ac.timestamps = active_ts;
            let mut bc = ac.clone();
            bc.timestamps = passive_ts;
            let mut a = Connection::active(tuple(), ac, 10, 1_000).unwrap();
            let syn = packet(&mut a, 2_000);
            let syn = wire::parse(ip(tuple()), &syn).unwrap();
            assert_eq!(syn.options.timestamps, active_ts.then_some((2, 0)));
            let mut b = Connection::passive(reverse(tuple()), bc, 20, 3_000, &syn).unwrap();
            let old = (
                b.now,
                b.snd_nxt,
                b.last_ack_sent,
                b.ts_recent,
                b.sample,
                b.next_deadline(),
            );
            assert_eq!(b.transmit(4_000, &mut [0; 23]), Err(Error::OutputTooSmall));
            assert_eq!(
                (
                    b.now,
                    b.snd_nxt,
                    b.last_ack_sent,
                    b.ts_recent,
                    b.sample,
                    b.next_deadline()
                ),
                old
            );
            let synack = deliver(&mut b, &mut a, 4_000);
            assert_eq!(
                wire::parse(ip(reverse(tuple())), &synack)
                    .unwrap()
                    .options
                    .timestamps,
                (active_ts && passive_ts).then_some((4, 2))
            );
            let ack = deliver(&mut a, &mut b, 5_000);
            assert_eq!(
                wire::parse(ip(tuple()), &ack).unwrap().options.timestamps,
                (active_ts && passive_ts).then_some((5, 4))
            );
            assert_eq!(b.state, State::Established);
            assert_eq!(a.timestamps, active_ts && passive_ts);
            assert_eq!(b.timestamps, a.timestamps);
            b.write(b"hello").unwrap();
            let data = deliver(&mut b, &mut a, 6_000);
            assert_eq!(
                wire::parse(ip(reverse(tuple())), &data)
                    .unwrap()
                    .options
                    .timestamps
                    .is_some(),
                a.timestamps
            );
        }
    }
    let mut cfg = config(1024, 128);
    cfg.timestamps = true;
    cfg.send_ip_payload_limit = 39;
    assert!(matches!(
        Connection::active(tuple(), cfg, 0, 0),
        Err(Error::InvalidArgument)
    ));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
//= type=test
//= reason=Cross-reference to section 4.3: earliest delayed echo, OOO retained echo and hole-fill replacement use TS.Recent/Last.ACK.sent algorithm.
//# The exact rules on which TSval MUST be echoed are given in
//# Section 4.3.
//= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
//= type=test
//= reason=Negotiated missing-TS data/ACK silently drops without abort; RST exempt. Only synchronized non-handshake SYN is challenged and dropped under selected RFC5961 MUST, never accepted or used to update TS/ACK/payload/metadata. Handshake paths retain TS checks. Narrow justified departure from silent SHOULD, not a blanket waiver.
//# non-<RST> segment is received without a TSopt, a TCP SHOULD silently
//# drop the segment.
//= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
//= type=test
//= reason=Negotiated missing-TS data/ACK silently drops without abort; RST exempt. Only synchronized non-handshake SYN is challenged and dropped under selected RFC5961 MUST, never accepted or used to update TS/ACK/payload/metadata. Handshake paths retain TS checks. Narrow justified departure from silent SHOULD, not a blanket waiver.
//# A TCP MUST NOT abort a TCP connection because any
//# segment lacks an expected TSopt.
//= https://www.rfc-editor.org/rfc/rfc7323#section-4.3
//= type=test
//= reason=TS.Recent updates only for sequence<=Last.ACK.sent and nondecreasing/expired TSval. Existing test asserts delayed earliest echo, unchanged echo across OOO hole, and replacement/frontier advance on hole fill.
//# Thus,
//# when delayed ACKs are in use, the receiver SHOULD reply with the
//# TSval field from the earliest unacknowledged segment.
//= https://www.rfc-editor.org/rfc/rfc7323#section-4.3
//= type=test
//= reason=TS.Recent updates only for sequence<=Last.ACK.sent and nondecreasing/expired TSval. Existing test asserts delayed earliest echo, unchanged echo across OOO hole, and replacement/frontier advance on hole fill.
//# An <ACK> for an out-of-order segment
//# SHOULD, therefore, contain the timestamp from the most recent
//# segment that advanced RCV.NXT.
//= https://www.rfc-editor.org/rfc/rfc7323#section-4.3
//= type=test
//= reason=TS.Recent updates only for sequence<=Last.ACK.sent and nondecreasing/expired TSval. Existing test asserts delayed earliest echo, unchanged echo across OOO hole, and replacement/frontier advance on hole fill.
//# Thus, the timestamp from the
//# latest segment (which filled the hole) MUST be echoed.
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.2
//= type=test
//= reason=Valid TS.Recent uses modular serial nondecrease; expiry explicitly invalidates old baseline at 2147s; same SYN initializes it.
//# The choice of incoming timestamps to be saved for this comparison
//# MUST guarantee a value that is monotonically non-decreasing.
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.2
//= type=test
//= reason=RST bypasses PAWS and terminates/challenges before TS.Recent/ts_latest updates; no timestamp or stale timestamp cannot veto sequence-valid RST.
//# When an <RST> segment is
//# received, it MUST NOT be subjected to the PAWS check by verifying an
//# acceptable value in SEG.TSval, and information from the Timestamps
//# option MUST NOT be used to update connection state information.
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
//= type=test
//= reason=Negotiated PAWS/missing TS gate precedes receive-window, RST-exempt, ACK and metadata processing. R1 drop schedules ACK; regular R2/R4/R5 follows for accepted TS.
//# If the PAWS algorithm is used, the following processing MUST be
//# performed on all incoming segments for a synchronized connection.
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
//= type=test
//= reason=Negotiated PAWS/missing TS gate precedes receive-window, RST-exempt, ACK and metadata processing. R1 drop schedules ACK; regular R2/R4/R5 follows for accepted TS.
//# Also, PAWS processing MUST take precedence over the regular TCP
//# acceptability check (Section 3.3 in [RFC0793]), which is performed
//# after verification of the received Timestamps option:
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
//= type=test
//= reason=Older timestamp data queued before a newer hole filler is delivered/read without a second PAWS check; a fresh raw arrival with the same old TS is rejected after the baseline advances.
//# It is important to note that the timestamp MUST be checked only when
//# a segment first arrives at the receiver, regardless of whether it is
//# in sequence or it must be queued for later delivery.
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.5
//= type=test
//= reason=Stores ts_recent_at on eligible TS.Recent refresh, not pending ACKs; 2147s expiry boundary tests reject at -1us and accept at equality/+1us in both local modes.
//# To detect how long the connection has been idle, the TCP MAY update a
//# clock or timestamp value associated with the connection whenever
//# TS.Recent is updated, for example.
//= https://www.rfc-editor.org/rfc/rfc7323#section-4.3
//= type=test
//= reason=Negotiated ordinary ACK output echoes single retained TS.Recent; reactive RST overrides follow section 5.2.
//# (3)  When a TSopt is sent, its TSecr field is set to the current
//# TS.Recent value.
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
//= type=test
//= reason=R1 stale negotiated non-RST schedules immediate ACK and returns without accepting data; missing TS is silent per section 3.2.
//# Send an acknowledgment in reply as specified in Section 3.9
//# of [RFC0793], page 69, and drop the segment.
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.5
//= type=test
//= reason=Tracks last TS.Recent refresh and invalidates at 2147s, before the RFC 24-day maximum; peer clocks <=1MHz are supported independent of local ticks, with TCP validation and R3 refresh retained.
//# We therefore require that an implementation of PAWS include a
//# mechanism to "invalidate" the TS.Recent value when a connection is
//# idle for more than 24 days.
//= https://www.rfc-editor.org/rfc/rfc7323#section-4.3
//= type=test
//= reason=Retains one pending echo value and last successfully committed ACK; separate ts_latest is TIME-WAIT freshness bookkeeping, not extra unprocessed echo queue.
//# TS.Recent holds a timestamp to be echoed in TSecr whenever a
//# segment is sent, and Last.ACK.sent holds the ACK field from the
//# last segment sent.  Last.ACK.sent will equal RCV.NXT except when
//# <ACK>s have been delayed.
//= https://www.rfc-editor.org/rfc/rfc7323#section-4.3
//= type=test
//= reason=Synchronized valid baseline uses serial timestamp comparison and last ACK sequence gate; expired baseline handled by section5.5 exception to stale test.
//# SEG.TSval >= TS.Recent and SEG.SEQ <= Last.ACK.sent
//#
//# then SEG.TSval is copied to TS.Recent; otherwise, it is ignored.
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.2
//= type=test
//= reason=TS values use same modular serial comparisons as sequence values. Wrap accepted, older values rejected; ambiguous half-space accepted only after baseline expiry.
//# s < t  if 0 < (t - s) < 2^31,
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
//= type=test
//= reason=Shared negotiated PAWS gate precedes window and ACK metadata acceptance, with explicit RST and expired-baseline exemptions.
//# R1)  If there is a Timestamps option in the arriving segment,
//# SEG.TSval < TS.Recent, TS.Recent is valid (see later
//# discussion), and if the RST bit is not set, then treat the
//# arriving segment as not acceptable:
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
//= type=test
//= reason=Accepted synchronized non-RST traffic uses serial nondecrease and last successful ACK gate; expired baseline is separate section5.5 path.
//# R3)  If an arriving segment satisfies SEG.TSval >= TS.Recent and
//# SEG.SEQ <= Last.ACK.sent (see Section 4.3), then record its
//# timestamp in TS.Recent.
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
//= type=test
//= reason=PAWS-valid in-sequence text advances receive frontier; later gap fill advances through queued data. Negotiated TS assertion covers this path.
//# R4)  If an arriving segment is in sequence (i.e., at the left window
//# edge), then accept it normally.
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
//= type=test
//= reason=Timestamp-validated in-window data uses capacity-backed presence bits, without a range-count admission gate. Alternating-window and timestamp fragmentation tests cover more than 64 intervals, gap filling, retained delivery and wrap.
//# R5)  Otherwise, treat the segment as a normal in-window,
//# out-of-sequence TCP segment (e.g., queue it for later delivery
//# to the user).
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.5
//= type=test
//= reason=2147s expired baseline does not reject older/half-space value; sequence/ACK validation still gates R3 refresh and receive frontier advance.
//# If
//# TS.Recent is found to be invalid, then the segment is accepted,
//# regardless of the failure of the timestamp check, and rule R3 updates
//# TS.Recent with the TSval from the new segment.
fn timestamps_paws_echo_order_wrap_idle_and_rst_exemption() {
    for granularity in [
        TimestampGranularity::Milliseconds,
        TimestampGranularity::Microseconds,
    ] {
        let mut cfg = config(1024, 128);
        cfg.timestamps = true;
        cfg.timestamp_granularity = granularity;
        let (mut a, _) = pair(cfg.clone(), 10);
        a.ts_recent = u32::MAX - 2;
        a.ts_latest = a.ts_recent;
        let next = a.receive.next();
        let ack = a.snd_nxt;
        timestamp_input(&mut a, 1_000, next, ack, ACK, None, b"missing");
        assert_eq!(a.receive.next(), next);
        assert!(!a.ack_pending);
        timestamp_input(
            &mut a,
            2_000,
            next,
            ack,
            ACK,
            Some((u32::MAX - 3, 0)),
            b"stale",
        );
        assert_eq!(a.receive.next(), next);
        assert!(a.ack_pending);
        packet(&mut a, 2_000);
        timestamp_input(&mut a, 3_000, next, ack, ACK, Some((u32::MAX - 1, 0)), b"a");
        timestamp_input(
            &mut a,
            4_000,
            next.wrapping_add(1),
            ack,
            ACK,
            Some((1, 0)),
            b"b",
        );
        assert_eq!(a.ts_recent, u32::MAX - 1); // Earliest unacknowledged segment.
        a.immediate_ack();
        let bytes = packet(&mut a, 4_000);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().options.timestamps,
            Some((granularity.tick(4_000) as u32, u32::MAX - 1))
        );
        assert_eq!(a.last_ack_sent, next.wrapping_add(2));
        timestamp_input(
            &mut a,
            5_000,
            next.wrapping_add(3),
            ack,
            ACK,
            Some((4, 0)),
            b"d",
        );
        assert_eq!(a.ts_recent, u32::MAX - 1); // Hole must not advance echo.
        packet(&mut a, 5_000);
        timestamp_input(
            &mut a,
            6_000,
            next.wrapping_add(2),
            ack,
            ACK,
            Some((3, 0)),
            b"c",
        );
        assert_eq!(a.ts_recent, 3); // Filling the hole replaces the echo.
        assert_eq!(a.receive.next(), next.wrapping_add(4));
        packet(&mut a, 6_000);
        // Fresh baseline still rejects the oldest stale peer timestamp;
        // receiver expiry is independent of local timestamp granularity.
        timestamp_input(
            &mut a,
            6_000 + PAWS_RECENT_EXPIRY_US - 1,
            next.wrapping_add(4),
            ack,
            ACK,
            Some((2, 0)),
            b"stale",
        );
        assert_eq!(a.receive.next(), next.wrapping_add(4));
        assert_eq!(a.ts_recent, 3);
        let idle = 6_000 + PAWS_RECENT_EXPIRY_US;
        timestamp_input(
            &mut a,
            idle,
            next.wrapping_add(4),
            ack,
            ACK,
            Some((0x8000_0003, 0)),
            b"e",
        );
        assert_eq!(a.ts_recent, 0x8000_0003);
        assert_eq!(a.receive.next(), next.wrapping_add(5));
        let recent = a.ts_recent;
        timestamp_input(
            &mut a,
            idle + 1,
            next.wrapping_add(5),
            ack,
            RST,
            Some((0, 0)),
            b"",
        );
        assert_eq!(a.state, State::Closed);
        assert_eq!(a.ts_recent, recent);
        let (mut a, _) = pair(cfg, 10);
        let next = a.receive.next();
        let ack = a.snd_nxt;
        timestamp_input(&mut a, 40, next, ack, RST, None, b"");
        assert_eq!(a.state, State::Closed);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6298#section-3
//= type=test
//= reason=Negotiated timestamp option remains conservatively Karn-excluding retransmissions.
//# TCP MUST use Karn's algorithm [KP87] for taking RTT samples.
//= https://www.rfc-editor.org/rfc/rfc6298#section-3
//= type=test
//= reason=Negotiated timestamp option remains conservatively Karn-excluding retransmissions.
//# That is, RTT samples MUST NOT be made using segments that were retransmitted (and thus
//# for which it is ambiguous whether the reply was for the first instance of the packet
//# or a later instance).
//= https://www.rfc-editor.org/rfc/rfc7323#section-4.1
//= type=test
//= reason=Matching TSecr on duplicate and SACK-only ACK cannot consume/update the ordinary pending RTTM sample or advance UNA. Under negotiated TS, original-transmission RACK samples now-minus-local-send-time independently of matching/forged TSecr; only RACK-enabled connections feed that separate sample into RTO.
//# RTTM Rule: A TSecr value received in a segment MAY be used to update
//# the averaged RTT measurement only if the segment advances
//# the left edge of the send window, i.e., SND.UNA is
//# increased.
//= https://www.rfc-editor.org/rfc/rfc7323#section-4.2
//= type=test
//= reason=Ordinary RTTM and local-clock RACK delivery share a causal-round gate: next eligible original must be sent at or after the prior sampling ACK. Continuous sliding, delayed/stretched and same-tick flights count actual updates; dense SACK and mixed cumulative delivery retain exact RFC6298 history. Conservative one-per-RTT sampling avoids fixed-weight history truncation; Appendix G and many-per-window sampling are suggestions, not mandatory formulas.
//# to update the RTT estimator, an implementation SHOULD try to adhere
//# to the spirit of the history specified in [RFC6298].
fn timestamps_rtt_validated_echo_and_karn() {
    let mut cfg = config(1024, 128);
    cfg.timestamps = true;
    cfg.nagle = false;
    for echo in [2000, 1999, 0, u32::MAX, 200_000] {
        let (mut a, _) = pair(cfg.clone(), 10);
        a.rtt = RttEstimator::new(1_000_000);
        a.write(b"sample").unwrap();
        packet(&mut a, 2_000_000);
        assert!(a.sample.is_some());
        let next = a.receive.next();
        let ack = a.snd_nxt;
        timestamp_input(&mut a, 2_600_000, next, ack, ACK, Some((5, echo)), b"");
        // Only a matching echo qualifies for RTTM. Every other value falls
        // back to the same unambiguous local 600ms measurement, never the echo.
        // Exactly one sample: RTTVAR = R/2.
        assert_eq!(
            (a.rtt.srtt(), a.rtt.variance(), a.rtt.rto()),
            (Some(600_000), 300_000, 1_800_000)
        );
        assert!(a.sample.is_none());
    }
    for echo in [3000, 2000, 0, u32::MAX] {
        let (mut a, _) = pair(cfg.clone(), 10);
        a.rtt = RttEstimator::new(1_000_000);
        a.rtt_sample_after = None;
        a.write(b"lost").unwrap();
        packet(&mut a, 2_000_000);
        a.timeout(3_000_000).unwrap();
        let bytes = packet(&mut a, 3_000_000);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes)
                .unwrap()
                .options
                .timestamps
                .unwrap()
                .0,
            3000
        );
        assert!(a.sample.is_none());
        let rto = a.rtt.rto();
        let next = a.receive.next();
        let ack = a.snd_nxt;
        timestamp_input(&mut a, 3_600_000, next, ack, ACK, Some((6, echo)), b"");
        assert_eq!(a.rtt.rto(), rto);
        assert_eq!(a.rtt.srtt(), None);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
//= type=test
//= reason=Negotiated TS survives ordinary data/FIN/keepalive and clock wrap under minimum path budget; assertions include output rollback.
//# Once TSopt has been successfully negotiated, that is both <SYN> and
//# <SYN,ACK> contain TSopt, the TSopt MUST be sent in every non-<RST>
//# segment for the duration of the connection, and SHOULD be sent in an
//# <RST> segment (see Section 5.2 for details).
//= https://www.rfc-editor.org/rfc/rfc7323#section-4.1
//= type=test
//= reason=Native and tun_echo time is the characterized CLOCK_BOOTTIME provider, which rejects decreasing samples and measures suspend; other embedders owe physically monotonic, consistent-rate time with sufficient precision for protocol timing; violation leaves timing guarantees unspecified, never Rust UB or memory-safety violations. CallerTimebase accepts microsecond/nanosecond units and MSL <=255s, independently of wire ms/us periods. Nondecreasing input, endpoint timestamp half-range gaps and resource bounds are checked; physical rate/drift/precision and actual network MSL cannot be established here. Peer PAWS expires independently at2147s. Fixed wire cadence and opt-in microsecond frequency remain scoped policy exceptions, not literal conformance.
//# Values of this
//# clock MUST be at least approximately proportional to real time, in
//# order to measure actual RTT.
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.4
//= type=test
//= reason=Native and tun_echo time is the characterized CLOCK_BOOTTIME provider, which rejects decreasing samples and measures suspend; other embedders owe physically monotonic, consistent-rate time with sufficient precision for protocol timing; violation leaves timing guarantees unspecified, never Rust UB or memory-safety violations. CallerTimebase accepts microsecond/nanosecond units and MSL <=255s, independently of wire ms/us periods. Nondecreasing input, endpoint timestamp half-range gaps and resource bounds are checked; physical rate/drift/precision and actual network MSL cannot be established here. Peer PAWS expires independently at2147s. Fixed wire cadence and opt-in microsecond frequency remain scoped policy exceptions, not literal conformance.
//# The recycling time of the timestamp clock MUST be greater than
//# MSL seconds.
//= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
//= type=test
//= reason=Wire TS fields u32 network-order; TSval uses selected local ticks (default milliseconds) modulo 32 bits. Physical rate guarantees separately TODO.
//# The Timestamps option carries two four-byte timestamp fields.  The
//# TSval field contains the current value of the timestamp clock of the
//# TCP sending the option.
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.4
//= type=test
//= reason=Approved timestamp frequency policy exception: default1ms is within the quoted chosen1ms..1s range; explicit opt-in1us is outside it, like Linux tcp_usec_ts at pinned22430ae5d90ab288b0ee2ad99ae941f4a666b694 include/net/tcp.h. No literal range compliance is claimed for microseconds. Independent2147s peer PAWS expiry remains; native monotonicity comes from the characterized CLOCK_BOOTTIME provider; physical rate/precision and actual network MSL are not measured or declared resolution gates, and other embedders' clocks remain caller obligations.
//# Based upon these considerations, we choose a timestamp clock
//# frequency in the range 1 ms to 1 sec per tick.
fn timestamps_ip_budget_data_fin_keepalive_and_clock_wrap() {
    for v6 in [false, true] {
        let mut cfg = config(1024, 128);
        cfg.timestamps = true;
        cfg.send_ip_payload_limit = 40;
        cfg.nagle = false;
        cfg.keepalive = Some(KeepaliveConfig {
            idle_us: 100_000,
            ..KeepaliveConfig::default()
        });
        let t = if v6 {
            Tuple {
                local: "[2001:db8::1]:1000".parse().unwrap(),
                remote: "[2001:db8::2]:2000".parse().unwrap(),
            }
        } else {
            tuple()
        };
        let now = (u32::MAX as u64) * 1000;
        let mut a = Connection::active(t, cfg.clone(), 10, now).unwrap();
        let syn = packet(&mut a, now);
        assert_eq!(syn.len(), 40);
        let mut b =
            Connection::passive(reverse(t), cfg, 20, now, &wire::parse(ip(t), &syn).unwrap())
                .unwrap();
        deliver(&mut b, &mut a, now + 1_000);
        let ack = deliver(&mut a, &mut b, now + 2_000);
        assert_eq!(
            wire::parse(ip(t), &ack)
                .unwrap()
                .options
                .timestamps
                .unwrap()
                .0,
            1
        );
        a.write(b"12345678").unwrap();
        let before = (a.now, a.snd_nxt, a.last_ack_sent, a.sample);
        assert_eq!(
            a.transmit(now + 3_000, &mut [0; 39]),
            Err(Error::OutputTooSmall)
        );
        assert_eq!((a.now, a.snd_nxt, a.last_ack_sent, a.sample), before);
        let data = deliver(&mut a, &mut b, now + 3_000);
        assert_eq!(data.len(), 40);
        b.immediate_ack();
        deliver(&mut b, &mut a, now + 4_000);
        a.timeout(now + 104_000).unwrap();
        assert_eq!(packet(&mut a, now + 104_000).len(), 32);
        a.shutdown().unwrap();
        let fin = packet(&mut a, now + 105_000);
        assert_eq!(fin.len(), 32);
        assert_ne!(wire::parse(ip(t), &fin).unwrap().header.flags & FIN, 0);
    }
}

#[test]
fn time_wait_iss_projection_is_strict_serial_and_secret_candidate_dependent() {
    let (mut a, _) = pair(config(1024, 128), 10);
    for frontier in [0, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
        a.snd_nxt = Seq(frontier);
        for candidate in [0, 1, 12345, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            let iss = a.reuse_iss(candidate);
            assert!(Seq(iss).after(Seq(frontier)));
            if Seq(candidate).after(Seq(frontier)) {
                assert_eq!(iss, candidate);
            }
        }
    }
    a.snd_nxt = Seq(100_000);
    assert_ne!(a.reuse_iss(1), a.reuse_iss(2));
}
#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
//= type=test
//= reason=Negotiated TS probe and user-abort RST asserted; same-feature simultaneous opens retain negotiation.
//# Once TSopt has been successfully negotiated, that is both <SYN> and
//# <SYN,ACK> contain TSopt, the TSopt MUST be sent in every non-<RST>
//# segment for the duration of the connection, and SHOULD be sent in an
//# <RST> segment (see Section 5.2 for details).
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.2
//= type=test
//= reason=Local user abort on negotiated connection emits TS; not a reactive RST requiring TSval=0.
//# If an <RST> is being generated
//# because of a user abort, and Snd.TS.OK is set, then a Timestamps
//# option SHOULD be included in the <RST>.
fn timestamps_lower_mss_probe_garbage_keepalive_abort_and_simultaneous_open() {
    let mut cfg = config(1024, 128);
    cfg.timestamps = true;
    cfg.nagle = false;
    let (mut a, _) = pair(cfg.clone(), 10);
    a.lower_mss(64).unwrap();
    assert_eq!(a.mss, 52);
    a.write(&[1; 100]).unwrap();
    let bytes = packet(&mut a, 1_000);
    assert_eq!(bytes.len(), 84); // 64-byte MSS plus fixed TCP header.
    a.probe_pending = true;
    a.snd_wnd = 0;
    let probe = packet(&mut a, 2_000);
    assert_eq!(probe.len(), 33);
    assert!(
        wire::parse(ip(tuple()), &probe)
            .unwrap()
            .options
            .timestamps
            .is_some()
    );
    let (mut a, _) = pair(cfg.clone(), 10);
    a.config.keepalive = Some(KeepaliveConfig {
        send_garbage: true,
        ..KeepaliveConfig::default()
    });
    a.keepalive_pending = true;
    assert_eq!(packet(&mut a, 1_000).len(), 33);
    a.abort();
    let reset = packet(&mut a, 2_000);
    let reset = wire::parse(ip(tuple()), &reset).unwrap();
    assert_ne!(reset.header.flags & RST, 0);
    assert_eq!(reset.options.timestamps.unwrap().0, 2);

    let mut a = Connection::active(tuple(), cfg.clone(), 10, 0).unwrap();
    let mut b = Connection::active(reverse(tuple()), cfg, 20, 0).unwrap();
    let a_syn = packet(&mut a, 1_000);
    let b_syn = packet(&mut b, 1_000);
    a.input(2_000, &wire::parse(ip(reverse(tuple())), &b_syn).unwrap())
        .unwrap();
    b.input(2_000, &wire::parse(ip(tuple()), &a_syn).unwrap())
        .unwrap();
    let a_synack = packet(&mut a, 3_000);
    let b_synack = packet(&mut b, 3_000);
    a.input(
        4_000,
        &wire::parse(ip(reverse(tuple())), &b_synack).unwrap(),
    )
    .unwrap();
    b.input(4_000, &wire::parse(ip(tuple()), &a_synack).unwrap())
        .unwrap();
    assert_eq!((a.state, b.state), (State::Established, State::Established));
    assert_eq!((a.ts_recent, b.ts_recent), (3, 3));
}
#[test]
fn time_wait_timestamp_freshness_uses_latest_not_echo_and_handles_wrap() {
    for granularity in [
        TimestampGranularity::Milliseconds,
        TimestampGranularity::Microseconds,
    ] {
        let (mut a, _) = pair(
            ConnectionConfig {
                timestamp_granularity: granularity,
                ..config(1024, 128)
            },
            10,
        );
        a.time_wait();
        a.timestamps = true;
        a.ts_recent = 1;
        a.ts_latest = 9;
        let mut syn = Segment {
            header: Header {
                source_port: 2000,
                destination_port: 1000,
                sequence: 1,
                acknowledgment: 0,
                flags: SYN,
                window: 1024,
                urgent_pointer: 0,
            },
            options: wire::Options {
                timestamps: Some((8, 0)),
                ..wire::Options::default()
            },
            raw_options: &[],
            payload: &[],
        };
        assert!(!a.reuse_syn(40, &syn, true));
        a.ts_latest = u32::MAX;
        syn.options.timestamps = Some((0, 0));
        assert!(a.reuse_syn(40, &syn, true));
        syn.options.timestamps = Some((0x7fff_ffff, 0));
        assert!(!a.reuse_syn(40, &syn, true));
        a.timestamps = false;
        assert!(a.reuse_syn(40, &syn, true));
        assert!(!a.reuse_syn(40, &syn, false));
        assert!(!a.reuse_syn(240_000_030, &syn, true));
    }
}
#[test]
//= https://www.rfc-editor.org/rfc/rfc6429#section-1
//= type=test
//# As long as the receiving TCP continues to send acknowledgments in
//# response to the probe segments, the sending TCP MUST allow the
//# connection to stay open.
//= https://www.rfc-editor.org/rfc/rfc6429#section-2
//= type=test
//# Per [RFC1122], as long as the ACKs are being received for window probes,
//# a connection can continue to stay in the persist condition.
//= https://www.rfc-editor.org/rfc/rfc6429#section-4
//= type=test
//# As stated in [RFC1122], a TCP implementation MUST NOT close a connection
//# merely because it seems to be stuck in the ZWP or persist condition.
fn application_stall_bounds_responsive_persist_and_window_shrink() {
    for window in [0, 3] {
        for explicit in [false, true] {
            let (mut a, _) = pair(config(64, 8), 100);
            if explicit {
                a.set_application_timeout(Some(5_000_000)).unwrap();
            }
            a.write(b"abcdefgh").unwrap();
            packet(&mut a, 40);
            let seq = a.receive.next();
            let una = a.snd_una;
            inject(&mut a, 50, seq, una, ACK, window, b"");
            let deadline = 30 + 5_000_000;
            for now in [1_000_000, 2_000_000, 4_000_000, deadline - 1] {
                a.timeout(now).unwrap();
                // Actual retransmission/probe feedback remains responsive.
                a.transmit(now, &mut [0; 128]).unwrap();
                inject(&mut a, now, seq, una, ACK, window, b"");
                assert_eq!(a.user_deadline(), None);
                assert_eq!(a.application_deadline(), explicit.then_some(deadline));
                assert_eq!(a.state(), State::Established);
            }
            a.timeout(deadline).unwrap();
            if explicit {
                assert_eq!(a.close_reason(), Some(CloseReason::TimedOut));
                assert_eq!(a.take_events().closed, Some(CloseReason::TimedOut));
            } else {
                assert_eq!(a.state(), State::Established);
            }
        }
    }
}

#[test]
fn application_progress_requires_cumulative_ack_not_output_or_window_feedback() {
    let (mut a, _) = pair(config(64, 8), 100);
    assert_eq!(
        a.set_application_timeout(Some(0)),
        Err(Error::InvalidArgument)
    );
    a.set_application_timeout(Some(1_000)).unwrap();
    a.write(b"abcdefgh").unwrap();
    assert_eq!(a.application_deadline(), Some(1_030));
    assert_eq!(a.transmit(100, &mut [0; 1]), Err(Error::OutputTooSmall));
    assert_eq!(a.application_deadline(), Some(1_030));
    assert_eq!(a.acknowledged, 0);
    packet(&mut a, 100);
    assert_eq!(a.application_deadline(), Some(1_030));
    let seq = a.receive.next();
    let una = a.snd_una;
    inject(&mut a, 200, seq, una.wrapping_add(4), ACK, 64, b"");
    assert_eq!(a.acknowledged, 4);
    assert_eq!(a.application_deadline(), Some(1_200));
    inject(&mut a, 300, seq, una.wrapping_add(4), ACK, 0, b"");
    inject(&mut a, 400, seq, una.wrapping_add(4), ACK, 64, b"");
    assert_eq!(a.application_deadline(), Some(1_200));
    inject(&mut a, 500, seq, una.wrapping_add(8), ACK, 64, b"");
    assert_eq!(a.application_deadline(), None);
    assert_eq!(a.acknowledged, 8);
    a.timeout(2_000).unwrap();
    a.write(b"new").unwrap();
    assert_eq!(a.application_deadline(), Some(3_000));
    a.set_application_timeout(None).unwrap();
    assert_eq!(a.application_deadline(), None);
    assert_eq!(a.user_deadline(), Some(2_000 + a.config.user_timeout_us));
}
#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-2.3
//= type=test
//= reason=Invalid SYN Window Scale is clamped to 14 and emits at most one invalid_window_scale event per connection; the existing coalesced bounded endpoint event queue carries the diagnostic. Values 15/255 and repeated negotiation are covered without unbounded logging.
//# If a
//# Window Scale option is received with a shift.cnt value larger than
//# 14, the TCP SHOULD log the error but MUST use 14 instead of the
//# specified value.
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.4
//= type=test
//= reason=Successful TS-bearing sequence-space bytes (including retransmitted copies and SYN/FIN) are transactionally limited by configured nonzero timestamp_bytes_per_tick <2^31. Exhaustion returns TimestampBudgetExceeded with caller time and protocol state unchanged; next tick resets credit. Boundary/wrap/output rollback tests verify the gate. Physical clock truth remains separately external.
//# It MUST tick at least once for each 2^31 bytes sent.
fn timestamp_contract_offset_budget_and_scale_diagnostic() {
    for units in [0, 1_000, 1_000_001, u64::MAX] {
        let mut cfg = config(64, 8);
        cfg.timebase = CallerTimebase {
            units_per_second: units,
            ..CallerTimebase::default()
        };
        assert!(matches!(
            Connection::active(tuple(), cfg, 100, 0),
            Err(Error::InvalidArgument)
        ));
    }
    let cfg = ConnectionConfig {
        timestamps: true,
        timestamp_bytes_per_tick: 8,
        ..config(64, 20)
    };
    let mut a = Connection::active(tuple(), cfg.clone(), 100, 0).unwrap();
    a.set_timestamp_offset(u32::MAX);
    let mut bytes = packet(&mut a, 1_000);
    let syn = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(syn.options.timestamps, Some((0, 0)));
    let scale_byte = 20
        + syn
            .raw_options
            .windows(3)
            .position(|w| w[..2] == [3, 3])
            .unwrap()
        + 2;
    bytes[scale_byte] = 15;
    bytes[16..18].fill(0);
    let checksum = wire::checksum(ip(tuple()), &bytes).unwrap();
    bytes[16..18].copy_from_slice(&checksum.to_be_bytes());
    let syn = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(syn.options.window_scale, Some(14));
    assert_eq!(syn.options.invalid_window_scale, Some(15));
    let mut invalid = Connection::passive(reverse(tuple()), cfg.clone(), 800, 1_000, &syn).unwrap();
    assert_eq!(invalid.peer_scale, 14);
    assert_eq!(invalid.take_events().invalid_window_scale, Some(15));
    bytes[scale_byte] = 255;
    bytes[16..18].fill(0);
    let checksum = wire::checksum(ip(tuple()), &bytes).unwrap();
    bytes[16..18].copy_from_slice(&checksum.to_be_bytes());
    let syn = wire::parse(ip(tuple()), &bytes).unwrap();
    let mut b = Connection::passive(reverse(tuple()), cfg, 900, 1_000, &syn).unwrap();
    b.set_timestamp_offset(42);
    assert_eq!(b.peer_scale, 14);
    assert_eq!(b.take_events().invalid_window_scale, Some(255));
    b.learn_syn(&syn, false);
    assert_eq!(b.take_events().invalid_window_scale, None);
    deliver(&mut b, &mut a, 2_000);
    deliver(&mut a, &mut b, 2_000);
    a.write(b"abcdefghijklmnop").unwrap();
    let first = packet(&mut a, 3_000);
    assert_eq!(
        wire::parse(ip(tuple()), &first)
            .unwrap()
            .options
            .timestamps
            .unwrap()
            .0,
        2
    );
    let before = (
        a.now,
        a.snd_nxt,
        a.timestamp_bytes,
        a.sample,
        a.rto_deadline,
    );
    assert_eq!(
        a.transmit(3_000, &mut [0; 128]),
        Err(Error::TimestampBudgetExceeded)
    );
    assert_eq!(
        (
            a.now,
            a.snd_nxt,
            a.timestamp_bytes,
            a.sample,
            a.rto_deadline
        ),
        before
    );
    let incoming = wire::parse(ip(tuple()), &first).unwrap();
    b.input(3_500, &incoming).unwrap();
    b.immediate_ack();
    deliver(&mut b, &mut a, 4_000);
    assert_eq!(a.rtt.srtt(), Some(1_000));
    assert!(a.transmit(4_000, &mut [0; 128]).unwrap().is_some());
    let now = a.now;
    let resumed = now + (1u64 << 31) * 1_000;
    a.update_time(resumed).unwrap();
    assert_eq!(a.now, resumed);
    assert_eq!(a.sample, None);
    assert_eq!(a.last_timestamp_sent_at, None);
    assert_eq!(a.update_time(now - 1), Err(Error::TimeWentBackwards));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.4
//= type=test
//= reason=Approved frequency exception: default milliseconds lies in the chosen1ms..1s range, explicit microseconds lies outside it. Both local/peer modes, secret-offset wrap, mixed echoes and caller-unit validation are asserted, not universal literal range compliance or physical clock evidence.
//# Based upon these considerations, we choose a timestamp clock
//# frequency in the range 1 ms to 1 sec per tick.
fn timestamp_units_mixed_peer_echo_wrap_and_timebase() {
    use crate::{Endpoint, EndpointConfig};
    assert_eq!(
        ConnectionConfig::default().timestamp_granularity,
        TimestampGranularity::Milliseconds
    );
    for granularity in [
        TimestampGranularity::Milliseconds,
        TimestampGranularity::Microseconds,
    ] {
        for peer_granularity in [
            TimestampGranularity::Milliseconds,
            TimestampGranularity::Microseconds,
        ] {
            let cfg = ConnectionConfig {
                timestamps: true,
                timestamp_granularity: granularity,
                nagle: false,
                ..config(256, 64)
            };
            let mut peer_cfg = cfg.clone();
            peer_cfg.timestamp_granularity = peer_granularity;
            let now = u32::MAX as u64 * granularity.tick_us();
            let mut a = Connection::active(tuple(), cfg.clone(), 100, now).unwrap();
            a.set_timestamp_offset(42);
            let syn = packet(&mut a, now);
            let syn = wire::parse(ip(tuple()), &syn).unwrap();
            assert_eq!(syn.options.timestamps, Some((41, 0)));
            let mut b = Connection::passive(reverse(tuple()), peer_cfg, 900, now, &syn).unwrap();
            b.set_timestamp_offset(u32::MAX);
            let synack = deliver(&mut b, &mut a, now + 1);
            let synack = wire::parse(ip(reverse(tuple())), &synack).unwrap();
            let peer_value = (peer_granularity.tick(now + 1) as u32).wrapping_add(u32::MAX);
            assert_eq!(synack.options.timestamps, Some((peer_value, 41)));
            let ack = deliver(&mut a, &mut b, now + 2);
            assert_eq!(
                wire::parse(ip(tuple()), &ack).unwrap().options.timestamps,
                Some((a.timestamp_value(now + 2), peer_value))
            );
            for connection in [&mut a, &mut b] {
                let old = connection.timestamp_value(now + 2);
                connection.immediate_ack();
                let bytes = packet(connection, now + 3);
                let ts = wire::parse(ip(connection.tuple), &bytes)
                    .unwrap()
                    .options
                    .timestamps
                    .unwrap();
                assert_eq!(
                    ts.0.wrapping_sub(old),
                    if connection.config.timestamp_granularity == TimestampGranularity::Microseconds
                    {
                        1
                    } else {
                        0
                    }
                );
                assert_eq!(
                    connection.timestamp_value(u64::MAX),
                    (connection.config.timestamp_granularity.tick(u64::MAX) as u32)
                        .wrapping_add(connection.timestamp_offset)
                );
            }
            a.sample = Some((a.snd_nxt, now));
            a.last_timestamp_sent_at = Some(now);
            let half = (1u64 << 31) * granularity.tick_us();
            a.update_time(now + half - granularity.tick_us()).unwrap();
            assert!(a.sample.is_some());
            a.update_time(now + half).unwrap();
            assert_eq!(a.sample, None);
            assert_eq!(a.last_timestamp_sent_at, None);
            let mut endpoint = Endpoint::new(
                EndpointConfig {
                    connection: cfg.clone(),
                    ..EndpointConfig::default()
                },
                [1; 32],
                0,
                |_| true,
            )
            .unwrap();
            assert_eq!(
                endpoint.on_timeout(half, 64),
                Err(crate::EndpointError::Connection(Error::AmbiguousTimeJump))
            );
            endpoint.on_timeout(half - 1, 64).unwrap();
            endpoint.on_timeout(half, 64).unwrap();
        }
    }
}

#[test]
fn timestamp_boundary_saturates_and_disabled_units_are_inert() {
    for granularity in [
        TimestampGranularity::Milliseconds,
        TimestampGranularity::Microseconds,
    ] {
        let cfg = ConnectionConfig {
            timestamps: true,
            timestamp_granularity: granularity,
            timestamp_bytes_per_tick: 1,
            ..config(64, 20)
        };
        let mut a = Connection::active(tuple(), cfg.clone(), 100, u64::MAX).unwrap();
        packet(&mut a, u64::MAX);
        a.syn_pending = true;
        assert_eq!(a.next_deadline(), Some(u64::MAX));
        let mut cfg = cfg;
        cfg.timestamps = false;
        let (mut a, _) = pair(cfg.clone(), 100);
        a.sample = Some((a.snd_nxt, 30));
        a.update_time(30 + (1u64 << 31)).unwrap();
        assert_eq!(a.sample, Some((a.snd_nxt, 30)));
        let mut endpoint = crate::Endpoint::new(
            crate::EndpointConfig {
                connection: cfg,
                ..crate::EndpointConfig::default()
            },
            [1; 32],
            0,
            |_| true,
        )
        .unwrap();
        endpoint.on_timeout(1u64 << 40, 64).unwrap();
    }
}

#[test]
fn timestamp_credit_clips_below_mss_and_defers_full_packet_fin() {
    for granularity in [
        TimestampGranularity::Milliseconds,
        TimestampGranularity::Microseconds,
    ] {
        for budget in [1, 8, 52] {
            let cfg = ConnectionConfig {
                timestamps: true,
                timestamp_granularity: granularity,
                nagle: false,
                timestamp_bytes_per_tick: budget,
                ..config(256, 64)
            };
            let (mut a, mut b) = pair(cfg, 100);
            assert_eq!(a.mss, 52);
            let data = [b'x'; 104];
            a.write(&data).unwrap();
            a.shutdown().unwrap();
            let start = a.snd_nxt;
            let mut received = Vec::new();
            let mut now = 1_000;
            while a.fin_sequence.is_none() {
                let before = (
                    a.now,
                    a.snd_nxt,
                    a.timestamp_bytes,
                    a.sample,
                    a.rto_deadline,
                );
                assert_eq!(a.transmit(now, &mut [0; 31]), Err(Error::OutputTooSmall));
                assert_eq!(
                    (
                        a.now,
                        a.snd_nxt,
                        a.timestamp_bytes,
                        a.sample,
                        a.rto_deadline
                    ),
                    before
                );
                let bytes = deliver(&mut a, &mut b, now);
                let segment = wire::parse(ip(tuple()), &bytes).unwrap();
                let fin = segment.header.flags & FIN != 0;
                assert!(segment.payload.len() as u32 + u32::from(fin) <= budget);
                assert_eq!(
                    segment.header.sequence,
                    start.wrapping_add(received.len() as u32).0
                );
                received.extend_from_slice(segment.payload);
                if segment.payload.len() as u32 == budget {
                    assert!(!fin);
                }
                if !fin {
                    assert_eq!(a.next_deadline(), Some(now + granularity.tick_us()));
                    let before = (a.now, a.snd_nxt, a.sample, a.rto_deadline);
                    assert_eq!(
                        a.transmit(now, &mut [0; 256]),
                        Err(Error::TimestampBudgetExceeded)
                    );
                    assert_eq!((a.now, a.snd_nxt, a.sample, a.rto_deadline), before);
                }
                b.immediate_ack();
                deliver(&mut b, &mut a, now + granularity.tick_us() / 10);
                now += granularity.tick_us();
                a.timeout(now).unwrap();
                assert!(a.next_deadline().is_none_or(|deadline| deadline > now));
                assert!(now <= 106_000);
            }
            assert_eq!(received, data);
            assert_eq!(a.fin_sequence, Some(start.wrapping_add(data.len() as u32)));
            assert_eq!(a.state, State::FinWait2);
            assert_eq!(a.rto_deadline, None);
            let mut read = [0; 104];
            assert_eq!(b.read(&mut read).unwrap(), data.len());
            assert_eq!(read, data);
        }
    }
}

#[test]
fn timestamp_partial_credit_syn_fin_retransmit_and_zero_window_wakeup() {
    for granularity in [
        TimestampGranularity::Milliseconds,
        TimestampGranularity::Microseconds,
    ] {
        let cfg = ConnectionConfig {
            timestamps: true,
            timestamp_granularity: granularity,
            timestamp_bytes_per_tick: 8,
            nagle: false,
            ..config(256, 64)
        };
        let (mut a, mut b) = pair(cfg, 100);
        a.write(b"seven!!").unwrap();
        deliver(&mut a, &mut b, 1_000);
        a.write(b"tail").unwrap();
        let bytes = packet(&mut a, 1_000);
        assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, b"t");
        assert_eq!(a.timestamp_bytes, 8);
        assert_eq!(a.next_deadline(), Some(1_000 + granularity.tick_us()));
        let before = (a.now, a.snd_nxt, a.rto_deadline);
        assert_eq!(
            a.transmit(1_000, &mut [0; 256]),
            Err(Error::TimestampBudgetExceeded)
        );
        assert_eq!((a.now, a.snd_nxt, a.rto_deadline), before);
        // Closing the window must leave persist/loss timers intact; the credit
        // wake fires once, not repeatedly at the same timestamp.
        a.snd_wnd = 0;
        a.arm_work();
        let loss = a.loss_timer;
        a.timeout(2_000).unwrap();
        assert_eq!(a.loss_timer, loss);
        assert!(a.next_deadline().is_some_and(|deadline| deadline > 2_000));
        assert_eq!(a.transmit(2_000, &mut [0; 256]), Ok(None));
        a.snd_wnd = 256;
        a.arm_work();
        a.retx_pending = true;
        let bytes = packet(&mut a, 2_000);
        let retry = wire::parse(ip(tuple()), &bytes).unwrap();
        // Retry credit also respects the original seven-byte packet boundary.
        assert_eq!(retry.payload, b"seven!!");
        assert_eq!(a.timestamp_bytes, 7);
        assert_eq!(retry.header.sequence, 101);

        // SYN spends one byte even before negotiation; pure ACK spends none.
        let cfg = ConnectionConfig {
            timestamps: true,
            timestamp_granularity: granularity,
            timestamp_bytes_per_tick: 1,
            ..config(64, 20)
        };
        let mut c = Connection::active(tuple(), cfg, 100, 0).unwrap();
        packet(&mut c, 0);
        assert_eq!(c.timestamp_bytes, 1);
        c.syn_pending = true;
        assert_eq!(
            c.transmit(0, &mut [0; 256]),
            Err(Error::TimestampBudgetExceeded)
        );
        assert_eq!(c.next_deadline(), Some(granularity.tick_us()));
        c.timeout(1_000).unwrap();
        let retry = packet(&mut c, 1_000);
        assert_eq!(
            wire::parse(ip(tuple()), &retry).unwrap().header.flags & SYN,
            SYN
        );
    }
}

#[test]
fn timestamp_staleness_is_exact_at_the_half_range_tick_boundary() {
    let cfg = ConnectionConfig {
        timestamps: true,
        timestamp_granularity: TimestampGranularity::Milliseconds,
        ..config(256, 64)
    };
    let (mut a, _) = pair(cfg, 100);
    a.write(b"old").unwrap();
    // Sent in the last microsecond of tick 1: 2^31 - 1 whole periods later
    // the tick has advanced by 2^31 - 1, one microsecond more by 2^31.
    packet(&mut a, 1_999);
    let sample = a.sample;
    assert!(sample.is_some());
    let boundary = 1_999 + ((1u64 << 31) - 1) * 1_000;
    a.update_time(boundary).unwrap();
    assert_eq!(a.sample, sample);
    a.update_time(boundary + 1).unwrap();
    assert_eq!(a.sample, None);
    assert_eq!(a.last_timestamp_sent_at, None);
}

#[test]
fn timestamp_stale_rtt_echo_cannot_alias_after_clock_recycle() {
    for granularity in [
        TimestampGranularity::Milliseconds,
        TimestampGranularity::Microseconds,
    ] {
        for timestamps in [false, true] {
            let cfg = ConnectionConfig {
                timestamps,
                timestamp_granularity: granularity,
                sack: true,
                rack: true,
                ..config(256, 64)
            };
            let (mut a, _) = pair(cfg, 100);
            a.write(b"old").unwrap();
            packet(&mut a, 1_000);
            let sample = a.sample;
            let srtt = a.rtt.srtt();
            let deadline = a.rto_deadline;
            let end = a.snd_nxt;
            let after_recycle = 1_000
                + (1u64 << 32)
                    * if timestamps {
                        granularity.tick_us()
                    } else {
                        1_000
                    };
            // An ACK encode failure may not invalidate state before commit.
            a.immediate_ack();
            assert_eq!(
                a.transmit(after_recycle, &mut [0; 19]),
                Err(Error::OutputTooSmall)
            );
            assert_eq!(a.now, 1_000);
            assert_eq!(a.sample, sample);
            assert_eq!(a.rto_deadline, deadline);
            a.update_time(after_recycle).unwrap();
            assert_eq!(a.sample, None);
            assert_eq!(a.last_timestamp_sent_at, None);
            assert!(!a.rack.valid());
            assert_eq!(a.rto_deadline, deadline);
            assert_eq!(a.send.len(), 3);
            let next = a.receive.next();
            // Local recycle is not permission to expire the peer's PAWS clock.
            let peer_value = a.ts_recent;
            let echo = granularity.tick(1_000) as u32;
            timestamp_input(
                &mut a,
                after_recycle,
                next,
                end,
                ACK,
                Some((peer_value, echo)),
                b"",
            );
            assert_eq!(a.snd_una, end);
            assert_eq!(a.rtt.srtt(), srtt);
            assert_eq!(a.send.len(), 0);
            assert_eq!(a.rto_deadline, None);
        }
    }
}

fn assert_timestamp_interop_on_serviced_clocks(
    granularity: TimestampGranularity,
    interval: Instant,
    exchanges: u32,
    accepted: bool,
) {
    use crate::{Endpoint, EndpointConfig};

    fn transfer(from: &mut Endpoint, to: &mut Endpoint, now: Instant) -> Vec<u8> {
        let mut out = [0; 256];
        let tx = from
            .poll_transmit(now, &mut out, 64)
            .unwrap()
            .packet
            .unwrap();
        to.input(now, tx.ip, &out[..tx.len]).unwrap();
        out[..tx.len].to_vec()
    }

    let cfg = EndpointConfig {
        max_connections: 2,
        connection: ConnectionConfig {
            timestamps: true,
            timestamp_granularity: granularity,
            nagle: false,
            ..config(256, 64)
        },
        ..EndpointConfig::default()
    };
    let mut peer_cfg = cfg.clone();
    peer_cfg.connection.timestamp_granularity = TimestampGranularity::Milliseconds;
    let mut a = Endpoint::new(cfg, [1; 32], 0, |_| true).unwrap();
    let mut b = Endpoint::new(peer_cfg, [2; 32], 0, |_| true).unwrap();
    let listener = b.listen(tuple().remote, 1).unwrap();
    let id = a.connect(0, tuple().local, tuple().remote).unwrap();
    transfer(&mut a, &mut b, 0);
    transfer(&mut b, &mut a, 10);
    let handshake_ack = transfer(&mut a, &mut b, 20);
    let peer = b.accept(listener).unwrap();
    let mut previous_ts = wire::parse(ip(tuple()), &handshake_ack)
        .unwrap()
        .options
        .timestamps
        .unwrap()
        .0;
    let mut clock = 20;
    for exchange in 1..=exchanges {
        let now = 20 + interval * u64::from(exchange);
        // Service both endpoint clocks every <=10min without sending packets.
        // This satisfies the local clock contract, not the peer's idle policy.
        while clock < now {
            clock = (clock + 600_000_000).min(now);
            assert!(!a.on_timeout(clock, 64).unwrap());
            assert!(!b.on_timeout(clock, 64).unwrap());
        }
        assert_eq!(a.write(id, b"x").unwrap(), 1);
        let bytes = transfer(&mut a, &mut b, now);
        let data = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(data.payload, b"x");
        let ts = data.options.timestamps.unwrap().0;
        assert_eq!(
            ts.wrapping_sub(previous_ts),
            (interval / granularity.tick_us()) as u32
        );
        previous_ts = ts;
        assert_eq!(b.readable_bytes(peer).unwrap(), usize::from(accepted));
        if accepted {
            assert_eq!(b.read(peer, &mut [0; 1]).unwrap(), 1);
        }
        let ack_time = now + 500_000;
        b.on_timeout(ack_time, 64).unwrap();
        let bytes = transfer(&mut b, &mut a, ack_time);
        let ack = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
        assert!(ack.payload.is_empty());
        assert_eq!(ack.header.flags & ACK, ACK);
        assert_eq!(
            ack.header.acknowledgment,
            data.header.sequence.wrapping_add(u32::from(accepted))
        );
        assert_eq!(
            a.acknowledged(id).unwrap(),
            if accepted { u64::from(exchange) } else { 0 }
        );
        clock = ack_time;
    }
}

#[test]
fn timestamp_paws_expiry_boundary_preserves_tcp_validation_and_refresh() {
    for granularity in [
        TimestampGranularity::Milliseconds,
        TimestampGranularity::Microseconds,
    ] {
        for offset in [0, u32::MAX] {
            for recent in [3u32, u32::MAX - 2] {
                for age in [
                    PAWS_RECENT_EXPIRY_US - 1,
                    PAWS_RECENT_EXPIRY_US,
                    PAWS_RECENT_EXPIRY_US + 1,
                ] {
                    let cfg = ConnectionConfig {
                        timestamps: true,
                        timestamp_granularity: granularity,
                        ..config(256, 64)
                    };
                    let (mut a, _) = pair(cfg, u32::MAX - 2);
                    a.set_timestamp_offset(offset);
                    a.ts_recent = recent;
                    a.ts_latest = recent;
                    // Use a non-second-aligned refresh to test elapsed microseconds,
                    // not Linux's floor-second comparison or connection creation time.
                    a.ts_recent_at = 123_456;
                    let now = a.ts_recent_at + age;
                    let next = a.receive.next();
                    let ack = a.snd_nxt;
                    let stale = recent.wrapping_sub(4);
                    let before = (a.ts_recent, a.ts_recent_at, a.ts_latest);
                    timestamp_input(
                        &mut a,
                        now,
                        next.wrapping_add(10_000),
                        ack,
                        ACK,
                        Some((stale, 0)),
                        b"x",
                    );
                    assert_eq!(a.receive.next(), next);
                    assert_eq!((a.ts_recent, a.ts_recent_at, a.ts_latest), before);
                    for invalid_ack in [
                        ack.wrapping_add(1),
                        a.snd_una
                            .wrapping_add(0u32.wrapping_sub(a.max_snd_wnd))
                            .wrapping_add(u32::MAX),
                    ] {
                        timestamp_input(
                            &mut a,
                            now,
                            next,
                            invalid_ack,
                            ACK,
                            Some((stale, 0)),
                            b"x",
                        );
                        assert_eq!(a.receive.next(), next);
                        assert_eq!((a.ts_recent, a.ts_recent_at, a.ts_latest), before);
                    }
                    // Missing TS still drops after expiry; pending ACK transmission
                    // must not extend ts_recent_at or turn an expired baseline fresh.
                    timestamp_input(&mut a, now, next, ack, ACK, None, b"x");
                    assert_eq!(a.receive.next(), next);
                    a.immediate_ack();
                    let bytes = packet(&mut a, now);
                    let ts = wire::parse(ip(tuple()), &bytes)
                        .unwrap()
                        .options
                        .timestamps
                        .unwrap();
                    assert_eq!(ts, (a.timestamp_value(now), recent));
                    assert_eq!((a.ts_recent, a.ts_recent_at, a.ts_latest), before);
                    timestamp_input(&mut a, now, next, ack, ACK, Some((stale, 0)), b"x");
                    if age < PAWS_RECENT_EXPIRY_US {
                        assert_eq!(a.receive.next(), next);
                        assert_eq!((a.ts_recent, a.ts_recent_at, a.ts_latest), before);
                    } else {
                        assert_eq!(a.receive.next(), next.wrapping_add(1));
                        assert_eq!(
                            (a.ts_recent, a.ts_recent_at, a.ts_latest),
                            (stale, now, stale)
                        );
                        // Expiry only discards the old baseline; the refreshed one
                        // must reject subsequent stale arrivals immediately.
                        timestamp_input(
                            &mut a,
                            now + 1,
                            next.wrapping_add(1),
                            ack,
                            ACK,
                            Some((stale.wrapping_sub(1), 0)),
                            b"y",
                        );
                        assert_eq!(a.receive.next(), next.wrapping_add(1));
                        assert_eq!(
                            (a.ts_recent, a.ts_recent_at, a.ts_latest),
                            (stale, now, stale)
                        );
                    }
                }
            }
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.4
//= type=test
//= reason=Approved fixed-tick SHOULD exception preserves network-rate small-window output: two one-byte windows in one default1ms tick with local Karn-safe RTT updates. Separate per-2^31-byte MUST credit remains enforced; no pacing or synthetic ticks.
//# In fact,
//# in order to be useful to the sender for round-trip timing, the
//# clock SHOULD tick at least once per window's worth of data, and
//# even with the window extension defined in Section 2.2, 2^31
//# bytes must be at least two windows.
fn timestamp_fixed_tick_preserves_small_window_network_rate_and_local_rtt() {
    let cfg = ConnectionConfig {
        timestamps: true,
        nagle: false,
        receive_capacity: 1,
        ..config(256, 64)
    };
    let (mut a, mut b) = pair(cfg, 100);
    let mut expected_rtt = a.rtt.clone();
    let mut values = Vec::new();
    for now in [100, 110] {
        assert_eq!(a.snd_wnd, 1);
        a.write(b"x").unwrap();
        let bytes = deliver(&mut a, &mut b, now);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.payload, b"x");
        values.push(segment.options.timestamps.unwrap().0);
        assert_eq!(b.read(&mut [0; 1]).unwrap(), 1);
        b.immediate_ack();
        deliver(&mut b, &mut a, now + 10);
        assert_eq!(a.send.len(), 0);
        expected_rtt.sample(10);
        assert_eq!(a.rtt.srtt(), expected_rtt.srtt());
        assert_eq!(
            (a.rtt.variance(), a.rtt.rto()),
            (expected_rtt.variance(), expected_rtt.rto())
        );
    }
    assert_eq!(values[0], values[1]);
}

#[test]
fn timestamp_mixed_units_idle_half_range_resumes_after_paws_expiry() {
    let minute = 60_000_000;
    assert_timestamp_interop_on_serviced_clocks(
        TimestampGranularity::Microseconds,
        30 * minute,
        1,
        true,
    );
    // 2.4e9 microsecond ticks compare stale, but the ntcp receiver baseline
    // has expired independently of its own millisecond timestamp mode.
    assert_timestamp_interop_on_serviced_clocks(
        TimestampGranularity::Microseconds,
        40 * minute,
        1,
        true,
    );
    assert_timestamp_interop_on_serviced_clocks(
        ConnectionConfig::default().timestamp_granularity,
        40 * minute,
        1,
        true,
    );
}

#[test]
fn timestamp_mixed_units_real_data_refreshes_recent_over_sixty_minutes() {
    // Three actual data/ACK exchanges refresh the peer baseline every 20min,
    // below half-range over a total duration exceeding half-range. Pure
    // keepalives need not refresh TS.Recent and are not sufficient evidence.
    assert_timestamp_interop_on_serviced_clocks(
        TimestampGranularity::Microseconds,
        20 * 60_000_000,
        3,
        true,
    );
}

#[test]
// Long idle expires peer PAWS and local RTT history; separate 40min
// coverage verifies mixed-unit expiry without bypassing endpoint servicing.
fn timestamp_long_idle_connections_resume_on_serviced_endpoint_clock() {
    for granularity in [
        TimestampGranularity::Milliseconds,
        TimestampGranularity::Microseconds,
    ] {
        use crate::{Endpoint, EndpointConfig};

        fn transfer(from: &mut Endpoint, to: &mut Endpoint, now: Instant) {
            let mut out = [0; 256];
            let tx = from
                .poll_transmit(now, &mut out, 64)
                .unwrap()
                .packet
                .unwrap();
            to.input(now, tx.ip, &out[..tx.len]).unwrap();
        }

        for negotiated in [false, true] {
            let cfg = EndpointConfig {
                max_connections: 2,
                connection: ConnectionConfig {
                    timestamps: true,
                    timestamp_granularity: granularity,
                    ..config(256, 64)
                },
                ..EndpointConfig::default()
            };
            let mut peer_cfg = cfg.clone();
            peer_cfg.connection.timestamps = negotiated;
            // Mixed units remain opaque to the peer, including after physical PAWS expiry.
            peer_cfg.connection.timestamp_granularity = TimestampGranularity::Milliseconds;
            let mut a = Endpoint::new(cfg, [1; 32], 0, |_| true).unwrap();
            let mut b = Endpoint::new(peer_cfg, [2; 32], 0, |_| true).unwrap();
            let listener = b.listen(tuple().remote, 1).unwrap();
            let id = a.connect(0, tuple().local, tuple().remote).unwrap();
            transfer(&mut a, &mut b, 0);
            transfer(&mut b, &mut a, 10);
            transfer(&mut a, &mut b, 20);
            let peer = b.accept(listener).unwrap();
            assert_eq!(a.next_deadline(), None);
            let day = 86_400_000_000;
            let step = (1u64 << 30) * granularity.tick_us();
            let mut clock: Instant = 20;
            while clock < 26 * day {
                clock = clock.saturating_add(step).min(26 * day);
                assert!(!a.on_timeout(clock, 64).unwrap());
                assert!(!b.on_timeout(clock, 64).unwrap());
            }
            // Endpoint time advances, while this idle connection has no work.
            assert_eq!(a.write(id, b"resumed").unwrap(), 7);
            transfer(&mut a, &mut b, 26 * day);
            let mut read = [0; 7];
            assert_eq!(b.read(peer, &mut read).unwrap(), 7);
            assert_eq!(&read, b"resumed");
            b.on_timeout(26 * day + 500_000, 64).unwrap();
            transfer(&mut b, &mut a, 26 * day + 500_000);
            assert_eq!(a.acknowledged(id).unwrap(), 7);
            clock = 26 * day + 500_000;
            while clock < 52 * day {
                clock = clock.saturating_add(step).min(52 * day);
                a.on_timeout(clock, 64).unwrap();
                b.on_timeout(clock, 64).unwrap();
            }
            a.abort(id).unwrap();
            a.release(id).unwrap();
            transfer(&mut a, &mut b, 52 * day);
            assert_eq!(b.state(peer).unwrap(), State::Closed);
            a.on_timeout(52 * day + 240_000_000, 64).unwrap();
            a.poll_transmit(52 * day + 240_000_000, &mut [0; 256], 64)
                .unwrap();
            assert!(!a.connection_exists(id));
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6928#section-2
//= type=test
//= reason=Initial/restart epoch retains original byte range and bytes sent before first advancing data ACK. RTO, Reno/SACK/RACK loss and TLP repair latch inferred loss; >4096 bytes selects future RFC3390 restart bound without increasing cwnd. Wrap, initial/restart, fast/RTO, 4096/4097 and actual future burst tests cover fallback.
//# Furthermore, to limit any negative effect that a larger initial window may have on links with limited bandwidth or buffer space, implementations SHOULD fall back to RFC 3390 for the restart window (RW) if any packet loss is detected during either the initial window or a restart window, and more than 4 KB of data is sent.
//= https://www.rfc-editor.org/rfc/rfc6928#section-9
//= type=test
//= reason=IW10 divided/delayed new ACKs with outstanding flight restart at ACKtime+current RTO after estimator update; duplicate ACK does not restart, last new ACK cancels. RFC6298 universal timing audit remains separate.
//# To minimize spurious retransmissions, implementations MUST follow RFC 6298 [RFC6298] to restart the retransmission timer with the current value of RTO for each ACK received that acknowledges new data.
fn iw10_loss_fallback_boundaries_restart_and_new_ack_timer() {
    for total in [4_096, 4_097] {
        for fast in [false, true] {
            for restart in [false, true] {
                let cfg = ConnectionConfig {
                    initial_window: InitialWindow::Iw10,
                    // NewReno's initial guard requires prior data progress.
                    // Reno covers first-flight fast loss; restarted flights
                    // also exercise NewReno after the warmup ACK.
                    recovery_algorithm: if fast && !restart {
                        RecoveryAlgorithm::Reno
                    } else {
                        RecoveryAlgorithm::NewReno
                    },
                    nagle: false,
                    rto_min_us: 1_000,
                    ..config(65_536, 1_000)
                };
                let (mut a, _) = pair(cfg, u32::MAX - 2_000);
                let next = a.receive.next();
                let una = a.snd_una;
                inject(&mut a, 35, next, una, ACK, 32_767, b"");
                if restart {
                    a.write(b"warmup").unwrap();
                    packet(&mut a, 40);
                    let next = a.receive.next();
                    let end = a.snd_nxt;
                    inject(&mut a, 100, next, end, ACK, 32_767, b"");
                    a.update_time(2_000_000).unwrap();
                }
                a.write(&vec![7; total]).unwrap();
                a.flush().unwrap();
                let sent_at = if restart { 2_000_001 } else { 1_000 };
                let mut out = vec![0; 2_000];
                let start = a.snd_nxt;
                let mut bytes = 0;
                while let Some(n) = a.transmit(sent_at, &mut out).unwrap() {
                    bytes += wire::parse(ip(tuple()), &out[..n]).unwrap().payload.len();
                }
                assert_eq!(bytes, total);
                assert_eq!(a.iw_epoch.unwrap().bytes, total as u32);
                if fast {
                    let next = a.receive.next();
                    for i in 1..=3 {
                        inject(&mut a, sent_at + i, next, start, ACK, 32_767, b"");
                    }
                    assert!(a.retx_pending);
                } else {
                    a.timeout(a.rto_deadline.unwrap()).unwrap();
                    assert_eq!(a.congestion.cwnd(), 1_000);
                }
                assert!(a.iw_setup_loss());
                assert_eq!(a.iw_fallback, total > 4_096);
                let end = a.snd_nxt;
                let next = a.receive.next();
                let now = a.now + 100;
                let previous_rto = a.rto();
                // Divided new-data ACKs each restart; duplicates do not.
                for offset in [500, 1_000, total as u32] {
                    inject(
                        &mut a,
                        now + u64::from(offset),
                        next,
                        start.wrapping_add(offset),
                        ACK,
                        32_767,
                        b"",
                    );
                    if offset < total as u32 {
                        assert_eq!(a.rto_deadline, Some(a.now + a.rto()));
                        let deadline = a.rto_deadline;
                        let duplicate_at = a.now + 1;
                        inject(
                            &mut a,
                            duplicate_at,
                            next,
                            start.wrapping_add(offset),
                            ACK,
                            32_767,
                            b"",
                        );
                        assert_eq!(a.rto_deadline, deadline);
                    } else {
                        assert_eq!(a.rto_deadline, None);
                    }
                }
                assert_eq!(a.snd_una, end);
                if fast {
                    assert_ne!(a.rto(), previous_rto);
                }
                // Grow after recovery, then observe the actual idle restart burst.
                a.congestion = Congestion::new(
                    1_000,
                    RecoveryAlgorithm::NewReno,
                    InitialWindow::Iw10,
                    a.iss,
                );
                a.write(&vec![9; 20_000]).unwrap();
                let now = a.now + a.rto() + 1;
                let mut sent = 0;
                while let Some(n) = a.transmit(now, &mut out).unwrap() {
                    sent += wire::parse(ip(tuple()), &out[..n]).unwrap().payload.len();
                }
                assert_eq!(sent, if total > 4_096 { 4_000 } else { 10_000 });
            }
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6928#section-3
//= type=test
//= reason=Default storage advertises >=10 local RMSS on initial SYN/SYNACK; explicitly configured slow-link storage advertises <10. No bandwidth autodetection or deployment performance claim.
//# Some implementations advertise a small initial receive window (Table 2 in [Duk10]), effectively limiting how much window a remote host may use. In order to realize the full benefit of the large initial window, implementations are encouraged to advertise an initial receive window of at least 10 segments, except for the circumstances where a larger initial window is deemed harmful. (See Section 8 below.)
//= https://www.rfc-editor.org/rfc/rfc6928#section-8
//= type=test
//= reason=Manual receive_capacity=4000 with local RMSS=1000 advertises four segments on both handshake directions; default capacity advertises >=10. Manual mitigation selected, no low-speed autodetection claim.
//# The negative impact can be mitigated by hosts directly connected to a low-speed link advertising an initial receive window smaller than 10 segments. This can be achieved either through manual configuration by the users or through the host stack auto-detecting the low- bandwidth links.
fn iw10_initial_receive_window_and_manual_slow_link() {
    for capacity in [65_536, 4_000] {
        let cfg = ConnectionConfig {
            initial_window: InitialWindow::Iw10,
            ..config(capacity, 1_000)
        };
        let mut a = Connection::active(tuple(), cfg.clone(), 100, 0).unwrap();
        let bytes = packet(&mut a, 0);
        let syn = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(syn.header.window, capacity.min(65_535) as u16);
        assert_eq!(syn.header.window >= 10 * cfg.mss, capacity >= 10_000);
        let mut b = Connection::passive(reverse(tuple()), cfg, 900, 10, &syn).unwrap();
        let bytes = packet(&mut b, 10);
        assert_eq!(
            wire::parse(ip(reverse(tuple())), &bytes)
                .unwrap()
                .header
                .window,
            syn.header.window
        );
    }
}
#[test]
fn iw10_sack_and_rack_losses_latch_initial_epoch() {
    for rack in [false, true] {
        let cfg = ConnectionConfig {
            initial_window: InitialWindow::Iw10,
            sack: true,
            rack,
            nagle: false,
            ..config(65_536, 1_000)
        };
        let (mut a, _) = pair(cfg, u32::MAX - 2_000);
        a.rack.sample(1_000, 30);
        a.write(&[7; 5_000]).unwrap();
        let start = a.snd_nxt;
        for n in 1..=5 {
            packet(&mut a, n * 1_000);
        }
        let next = a.receive.next();
        let high = a.snd_nxt;
        inject_sack(
            &mut a,
            10_000,
            next,
            start,
            ACK,
            32_767,
            b"",
            &[(start.wrapping_add(1_000).0, high.0)],
        );
        if !a.iw_fallback {
            a.timeout(a.rack.deadline.unwrap()).unwrap();
        }
        assert!(a.iw_fallback && a.iw_setup_loss());
        assert_eq!(a.restart_window(), 4_000);
    }
}

#[test]
fn reactive_syn_sent_reset_echo_and_clock_profile_validation() {
    for budget in [0, 1 << 31] {
        let mut cfg = config(64, 8);
        cfg.timestamp_bytes_per_tick = budget;
        assert!(matches!(
            Connection::active(tuple(), cfg, 100, 0),
            Err(Error::InvalidArgument)
        ));
    }
    for msl in [0, 255_000_001] {
        let mut cfg = config(64, 8);
        cfg.timebase.max_segment_lifetime_us = msl;
        assert!(matches!(
            Connection::active(tuple(), cfg, 100, 0),
            Err(Error::InvalidArgument)
        ));
    }
    let timebase = CallerTimebase::default();
    assert!((1u64 << 32) * 1_000 > timebase.max_segment_lifetime_us);
    for budget in [28, 31, 32] {
        let cfg = ConnectionConfig {
            send_ip_payload_limit: budget,
            ..config(64, 8)
        };
        let mut a = Connection::active(tuple(), cfg, 100, 0).unwrap();
        packet(&mut a, 0);
        timestamp_input(&mut a, 1_000, Seq(900), Seq(99), ACK, Some((77, 0)), b"");
        let output = packet(&mut a, 1_000);
        let reset = wire::parse(ip(tuple()), &output).unwrap();
        assert_eq!(reset.header.flags, RST);
        assert_eq!(reset.options.timestamps, (budget >= 32).then_some((0, 77)));
    }
}
#[test]
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.6
//= type=test
//= reason=Actual ten-MSS loss lowers threshold immediately to7000, existing PRR controls repairs and exits to reduced cwnd for both recovery selectors; peer/packet format unchanged. Floor helpers complement this flight vector.
//# ssthresh =  flight_size * β      new  ssthresh
//# cubic
//# cwnd      = cwnd                 save  cwnd
//# prior
//# ⎧max(ssthresh, 2)    reduction on loss, cwnd >= 2 SMSS
//# cwnd =      ⎨max(ssthresh, 1)    reduction on ECE, cwnd >= 1 SMSS
//# ⎩
//# ssthresh =  max(ssthresh, 2)     ssthresh >= 2 SMSS
//#
//# Figure 5
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.6
//= type=test
//= reason=Actual ten-MSS loss lowers threshold immediately to7000, existing PRR controls repairs and exits to reduced cwnd for both recovery selectors; peer/packet format unchanged. Floor helpers complement this flight vector.
//# In the case of packet loss, the
//# sender MUST reduce _cwnd_ and _ssthresh_ immediately upon entering
//# loss recovery, similar to [RFC5681] (and [RFC6675]).
//= https://www.rfc-editor.org/rfc/rfc9438#section-5.10
//= type=test
//= reason=Actual ten-MSS loss lowers threshold immediately to7000, existing PRR controls repairs and exits to reduced cwnd for both recovery selectors; peer/packet format unchanged. Floor helpers complement this flight vector.
//# CUBIC requires only changes to congestion control at the sender, and
//# it does not require any changes at receivers.  That is, a CUBIC
//# sender works correctly with Reno receivers.  In addition, CUBIC does
//# not require any changes to routers and does not require any
//# assistance from routers.
fn cubic_ten_mss_loss_threshold_and_existing_prr_wire_exit() {
    assert_eq!(
        ConnectionConfig::default().congestion_algorithm,
        CongestionAlgorithm::Reno
    );
    for algorithm in [CongestionAlgorithm::Reno, CongestionAlgorithm::Cubic] {
        for recovery in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
            for iss in [100, u32::MAX - 4999] {
                let cfg = ConnectionConfig {
                    congestion_algorithm: algorithm,
                    recovery_algorithm: recovery,
                    initial_window: InitialWindow::Iw10,
                    prr: true,
                    nagle: false,
                    ..config(32_000, 1000)
                };
                let (mut a, b) = primed_pair(cfg, iss);
                // Both active and passive construction forward the selector.
                assert_eq!(
                    alloc::format!("{:?}", a.congestion).contains("cubic: Some"),
                    algorithm == CongestionAlgorithm::Cubic
                );
                assert_eq!(
                    alloc::format!("{:?}", b.congestion).contains("cubic: Some"),
                    algorithm == CongestionAlgorithm::Cubic
                );
                let base = a.snd_una;
                a.write(&[0x55; 20_000]).unwrap();
                for _ in 0..10 {
                    let bytes = packet(&mut a, 100_000);
                    assert_eq!(
                        wire::parse(ip(tuple()), &bytes).unwrap().payload.len(),
                        1000
                    );
                }
                assert_eq!(a.data_flight(), 10_000);
                assert_eq!(a.transmit(100_000, &mut [0; 1500]), Ok(None));
                let next = a.receive.next();
                let window = (a.snd_wnd >> a.peer_scale) as u16;
                for now in 200_000..200_003 {
                    inject(&mut a, now, next, base, ACK, window, b"");
                }
                let threshold = if algorithm == CongestionAlgorithm::Cubic {
                    7000
                } else {
                    5000
                };
                assert_eq!(a.congestion.ssthresh(), threshold);
                assert!(a.prr.is_some());
                let state = alloc::format!("{:?}", a.congestion);
                let counters = a.prr.unwrap().counters();
                let repair_credit = a.prr.unwrap().credit().min(1000);
                assert_eq!(
                    a.transmit(200_003, &mut [0; 20]),
                    Err(Error::OutputTooSmall)
                );
                assert_eq!(alloc::format!("{:?}", a.congestion), state);
                assert_eq!(a.prr.unwrap().counters(), counters);
                let repair = packet(&mut a, 200_003);
                let repair = wire::parse(ip(tuple()), &repair).unwrap();
                assert_eq!(repair.header.sequence, base.0);
                assert_eq!(repair.payload.len(), repair_credit as usize);
                assert!(repair.payload.iter().all(|&byte| byte == 0x55));
                assert_eq!(
                    a.prr.unwrap().counters(),
                    (10_000, 1000, u64::from(repair_credit))
                );
                inject(
                    &mut a,
                    300_000,
                    next,
                    base.wrapping_add(10_000),
                    ACK,
                    window,
                    b"",
                );
                assert!(a.prr.is_none());
                // Existing RFC9937 completion sets cwnd=ssthresh for BOTH
                // congestion algorithms. No CUBIC-only exit override.
                assert_eq!(a.congestion.cwnd(), threshold);
                for i in 0..threshold / 1000 {
                    let bytes = packet(&mut a, 300_000);
                    let segment = wire::parse(ip(tuple()), &bytes).unwrap();
                    assert_eq!(
                        segment.header.sequence,
                        base.wrapping_add(10_000 + i * 1000).0
                    );
                    assert_eq!(segment.payload.len(), 1000);
                }
                assert_eq!(a.transmit(300_000, &mut [0; 1500]), Ok(None));
                assert_eq!(a.data_flight(), threshold);
            }
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
//= type=test
//= reason=Real handshake supplies SRTT; actual loss/recovery/CA ACKs, unfilled suffix and idle/output failure prove composed byte growth and caller-unit timing.
//# *  _RTT_: Smoothed round-trip time in seconds, calculated as
//# described in [RFC6298].
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.2
//= type=test
//= reason=Real handshake supplies SRTT; actual loss/recovery/CA ACKs, unfilled suffix and idle/output failure prove composed byte growth and caller-unit timing.
//# CUBIC maintains the ACK clocking of Reno by increasing the congestion
//# window only at the reception of a new ACK.  It does not make any
//# changes to the TCP Fast Recovery and Fast Retransmit algorithms
//# [RFC6582] [RFC6675].
fn cubic_wire_growth_idle_and_transactional_clocks_in_caller_units() {
    let trace = |scale: u64| {
        let cfg = ConnectionConfig {
            congestion_algorithm: CongestionAlgorithm::Cubic,
            recovery_algorithm: RecoveryAlgorithm::Reno,
            initial_window: InitialWindow::Iw10,
            timebase: CallerTimebase {
                units_per_second: 1_000_000 * scale,
                ..CallerTimebase::default()
            },
            prr: true,
            nagle: false,
            ..config(32_000, 1000)
        };
        let mut a = Connection::active(tuple(), cfg.clone(), 100, 0).unwrap();
        let bytes = packet(&mut a, 0);
        let syn = wire::parse(ip(tuple()), &bytes).unwrap();
        let mut b = Connection::passive(reverse(tuple()), cfg, 900, 50_000 * scale, &syn).unwrap();
        deliver(&mut b, &mut a, 100_000 * scale);
        deliver(&mut a, &mut b, 100_000 * scale);
        assert_eq!(a.rtt.srtt(), Some(100_000 * scale));
        // Application/rwnd-limited originals cannot inflate CUBIC slow start.
        let base = a.snd_una;
        let next = a.receive.next();
        a.write(&[0x55; 1000]).unwrap();
        packet(&mut a, 200_000 * scale);
        inject(
            &mut a,
            300_000 * scale,
            next,
            base.wrapping_add(1000),
            ACK,
            32_000,
            b"",
        );
        assert_eq!(a.congestion.cwnd(), 10_000);
        let base = a.snd_una;
        a.write(&[0x55; 20_000]).unwrap();
        for _ in 0..10 {
            packet(&mut a, 400_000 * scale);
        }
        for i in 0..3 {
            inject(&mut a, (500_000 + i) * scale, next, base, ACK, 32_000, b"");
        }
        packet(&mut a, 500_003 * scale);
        inject(
            &mut a,
            600_000 * scale,
            next,
            base.wrapping_add(10_000),
            ACK,
            32_000,
            b"",
        );
        assert_eq!(a.congestion.cwnd(), 7000);
        for _ in 0..7 {
            packet(&mut a, 700_000 * scale);
        }
        inject(
            &mut a,
            800_000 * scale,
            next,
            base.wrapping_add(17_000),
            ACK,
            32_000,
            b"",
        );
        let grown = a.congestion.cwnd();
        assert!(grown > 7000 && grown < 8000); // Reno-friendly ACK-counted W_est.
        // Drain an unfilled suffix, which must not grant growth credit.
        for _ in 0..3 {
            packet(&mut a, 800_000 * scale);
        }
        inject(
            &mut a,
            900_000 * scale,
            next,
            base.wrapping_add(20_000),
            ACK,
            32_000,
            b"",
        );
        assert_eq!(a.congestion.cwnd(), grown);
        // Long idle: failed output changes neither epoch nor restart state.
        a.write(&[0x66; 20_000]).unwrap();
        let before = alloc::format!("{:?}", a.congestion);
        assert_eq!(
            a.transmit(10_000_000 * scale, &mut [0; 20]),
            Err(Error::OutputTooSmall)
        );
        assert_eq!(alloc::format!("{:?}", a.congestion), before);
        let start = a.snd_una;
        let restart = grown.min(a.restart_window()); // Existing IW10 loss fallback.
        while a
            .transmit(10_000_000 * scale, &mut [0; 1500])
            .unwrap()
            .is_some()
        {}
        let flight = restart / 1000 * 1000; // SWS leaves fractional-MSS credit.
        assert_eq!(a.data_flight(), flight);
        inject(
            &mut a,
            10_100_000 * scale,
            next,
            start.wrapping_add(flight),
            ACK,
            32_000,
            b"",
        );
        let resumed = a.congestion.cwnd();
        // The idle interval does not yield a huge cubic target.
        assert!(resumed > restart && resumed < restart + 1000);
        // RFC6298 integer rounding depends on caller-unit precision;
        // CUBIC consumes that estimator in ticks, without truncating to us.
        assert!((100_000..120_000).contains(&(a.rtt.srtt().unwrap() / scale)));
        (grown, resumed)
    };
    assert_eq!(trace(1), trace(1000));
}

#[test]
fn cubic_sack_rack_prr_loss_threshold_and_completion() {
    for algorithm in [CongestionAlgorithm::Reno, CongestionAlgorithm::Cubic] {
        for iss in [0, u32::MAX - 4999] {
            let cfg = ConnectionConfig {
                congestion_algorithm: algorithm,
                initial_window: InitialWindow::Iw10,
                sack: true,
                rack: true,
                prr: true,
                nagle: false,
                ..config(32_000, 1000)
            };
            let (mut a, _) = primed_pair(cfg, iss);
            let base = a.snd_una;
            let next = a.receive.next();
            let window = (a.snd_wnd >> a.peer_scale) as u16;
            a.write(&[0x55; 20_000]).unwrap();
            for _ in 0..10 {
                packet(&mut a, 100_000);
            }
            inject_sack(
                &mut a,
                200_000,
                next,
                base,
                ACK,
                window,
                b"",
                &[(base.wrapping_add(7000).0, base.wrapping_add(10_000).0)],
            );
            let timer_entry = a.prr.is_none();
            if timer_entry {
                let deadline = a.rack.deadline.expect("RACK loss deadline");
                a.timeout(deadline).unwrap();
            }
            let threshold = if algorithm == CongestionAlgorithm::Cubic {
                7000
            } else {
                5000
            };
            assert_eq!(a.congestion.ssthresh(), threshold);
            assert!(a.sack_recovery.is_some());
            let (recover_fs, _, _) = a.prr.unwrap().counters();
            // ACK entry includes its delivery; timer entry excludes advice
            // already received. RFC9937 keeps this denominator fixed.
            assert_eq!(recover_fs, if timer_entry { 7000 } else { 10_000 });
            let now = a.now;
            let bytes = packet(&mut a, now);
            let repair = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(repair.header.sequence, base.0);
            assert_eq!(repair.payload.len(), 1000);
            assert_eq!(a.prr.unwrap().counters(), (recover_fs, 3000, 1000));
            inject_sack(
                &mut a,
                now + 100_000,
                next,
                base.wrapping_add(10_000),
                ACK,
                window,
                b"",
                &[],
            );
            assert!(a.sack_recovery.is_none() && a.prr.is_none());
            assert_eq!(a.congestion.cwnd(), threshold);
        }
    }
}

#[test]
fn cubic_receiver_limited_ack_does_not_grow_previous_full_flight() {
    for algorithm in [CongestionAlgorithm::Reno, CongestionAlgorithm::Cubic] {
        let cfg = ConnectionConfig {
            congestion_algorithm: algorithm,
            initial_window: InitialWindow::Iw10,
            nagle: false,
            ..config(32_000, 1000)
        };
        let (mut a, _) = pair(cfg, 100);
        let base = a.snd_una;
        let next = a.receive.next();
        a.write(&[0x55; 10_000]).unwrap();
        for _ in 0..10 {
            packet(&mut a, 100_000);
        }
        inject(
            &mut a,
            200_000,
            next,
            base.wrapping_add(1000),
            ACK,
            2000,
            b"",
        );
        let expected = if algorithm == CongestionAlgorithm::Cubic {
            10_000
        } else {
            11_000
        };
        assert_eq!(a.congestion.cwnd(), expected);
        inject(
            &mut a,
            300_000,
            next,
            base.wrapping_add(10_000),
            ACK,
            2000,
            b"",
        );
        if algorithm == CongestionAlgorithm::Cubic {
            assert_eq!(a.congestion.cwnd(), 10_000);
            a.write(&[0x66; 20_000]).unwrap();
            for _ in 0..2 {
                packet(&mut a, 300_000);
            }
            inject(
                &mut a,
                400_000,
                next,
                base.wrapping_add(12_000),
                ACK,
                2000,
                b"",
            );
            assert_eq!(a.congestion.cwnd(), 10_000);
        }
    }
}

#[path = "connection_advertised_mss_tests.rs"]
mod advertised_mss;
#[path = "connection_output_tests.rs"]
mod output_policy;
#[path = "connection_reservation_tests.rs"]
mod output_reservation_policy;
#[path = "pmtud_isolated_cc_tests.rs"]
mod pmtud_isolated_cc;
#[path = "pmtud_detector_boundary_tests.rs"]
mod pmtud_detector_boundary;
#[path = "pmtud_lifecycle_tests.rs"]
mod pmtud_lifecycle;
#[path = "pmtud_tests.rs"]
mod pmtud_policy;
#[path = "pmtud_reset_trace_tests.rs"]
mod pmtud_reset_trace;
#[path = "connection_ptb_tests.rs"]
mod ptb_repair;
#[path = "connection_ptb_scheduler_tests.rs"]
mod ptb_scheduler;
#[path = "connection_ptb_boundary_tests.rs"]
mod ptb_boundary;
#[path = "connection_reservation_rtt_tests.rs"]
mod reservation_rtt;

#[path = "connection_route_mtu_tests.rs"]
mod route_mtu;

#[path = "pmtud_config_tests.rs"]
mod pmtud_config;
#[path = "pmtud_growth_tests.rs"]
mod pmtud_growth;
#[path = "connection_managed_tests.rs"]
mod managed_paths;
#[test]
fn logical_send_finish_marks_only_selected_byte_and_releases_cork() {
    let (mut a, _) = pair(config(32, 4), 100);
    a.set_cork(true);
    a.write_with_options(b"abcdef", true, false).unwrap();
    let end = a.acknowledged + 6;
    a.write_with_options(b"gh", true, false).unwrap();
    a.finish_send(end, false, true, false);
    assert_eq!(a.send.record_len(0, 8), 6);
    assert!(a.send.pushed(5, 1));
    assert!(!a.send.pushed(6, 2));
    assert!(a.more); // A later write owns the current MORE state.
    a.finish_send(end, true, false, true);
    assert!(a.cork_flush.is_some());
    a.send.acknowledge(6).unwrap();
    a.acknowledged += 6;
    a.finish_send(end, false, true, false);
    assert_eq!(a.send.record_len(0, 2), 2);
    assert!(!a.send.pushed(0, 2));
}

#[test]
fn tx_timestamp_partial_coalesced_segmented_output_failure_and_ack_crossing() {
    use crate::{TxTimestampOutcome, TxTimestampSource::Software, TxTimestampStage::*};
    for iss in [100, u32::MAX - 3] {
        let mut cfg = config(8, 4);
        cfg.nagle = false;
        let (mut a, _) = pair(cfg, iss);
        a.tx_timestamps.resize(4, usize::MAX).unwrap();
        let request = |cookie| TxTimestampRequest {
            cookie,
            scheduled: true,
            acknowledged: true,
            ..Default::default()
        };
        assert_eq!(
            a.write_with_timestamp(b"abc", true, false, None, request(1)),
            Ok(3)
        );
        assert_eq!(
            a.write_with_timestamp(b"defghijkl", false, false, None, request(2)),
            Ok(5)
        );
        assert_eq!(
            a.write_with_timestamp(b"x", false, false, None, request(3)),
            Err(Error::WouldBlock)
        );
        assert_eq!(
            a.write_with_timestamp(b"", false, false, None, request(4)),
            Ok(0)
        );
        assert_eq!(a.transmit(40, &mut []), Err(Error::OutputTooSmall));
        assert_eq!(a.tx_timestamps.next(), None);
        let bytes = packet(&mut a, 41);
        assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, b"abcd");
        assert_eq!(
            a.last_output_range,
            Some(TxStreamRange { start: 0, end: 4 })
        );
        let first = a.tx_timestamps.next().unwrap();
        assert_eq!(
            (first.cookie, first.target, first.stage, first.source),
            (1, 2, Scheduled, Software)
        );
        assert_eq!(
            first.outcome,
            TxTimestampOutcome::Recorded {
                value: 41,
                clock: TxTimestampClock::CallerTicks(a.config.timebase)
            }
        );
        assert_eq!(a.tx_timestamps.next(), None); // Earlier fragment cannot complete target 7.
        let bytes = packet(&mut a, 42);
        assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, b"efgh");
        let second = a.tx_timestamps.next().unwrap();
        assert_eq!(
            (second.cookie, second.target, second.stage),
            (2, 7, Scheduled)
        );
        assert_eq!(
            second.outcome,
            TxTimestampOutcome::Recorded {
                value: 42,
                clock: TxTimestampClock::CallerTicks(a.config.timebase)
            }
        );
        let base = Seq(iss).wrapping_add(1);
        let next = a.receive.next();
        inject_sack(
            &mut a,
            50,
            next,
            base,
            ACK,
            8,
            &[],
            &[(base.wrapping_add(4).0, base.wrapping_add(8).0)],
        );
        inject(&mut a, 51, next, base.wrapping_add(2), ACK, 8, &[]);
        assert_eq!(a.tx_timestamps.next(), None);
        inject(&mut a, 52, next, base.wrapping_add(3), ACK, 8, &[]);
        inject(&mut a, 53, next, base.wrapping_add(8), ACK, 8, &[]);
        inject(&mut a, 54, next, base.wrapping_add(8), ACK, 8, &[]);
        // Drain much later: retain each exact cumulative crossing time.
        a.update_time(100).unwrap();
        for (cookie, target, value) in [(1, 2, 52), (2, 7, 53)] {
            let event = a.tx_timestamps.next().unwrap();
            assert_eq!(
                (event.cookie, event.target, event.stage),
                (cookie, target, Acknowledged)
            );
            assert_eq!(
                event.outcome,
                TxTimestampOutcome::Recorded {
                    value,
                    clock: TxTimestampClock::CallerTicks(a.config.timebase)
                }
            );
        }
        assert_eq!(a.tx_timestamps.next(), None);
        a.tx_timestamps.resize(0, 0).unwrap();
        assert_eq!(a.tx_timestamps.storage_bytes(), 0);
    }
}

#[test]
fn tx_timestamp_flush_cancels_tail_reuses_offsets_not_reservations_across_wrap() {
    use crate::{TxTimestampOutcome, TxTimestampSource::Hardware, TxTimestampStage::*};
    for iss in [100, u32::MAX - 3] {
        let mut cfg = config(16, 8);
        cfg.nagle = false;
        let (mut a, _) = pair(cfg, iss);
        a.tx_timestamps.resize(6, usize::MAX).unwrap();
        let request = |cookie| TxTimestampRequest {
            cookie,
            scheduled: true,
            hardware_transmit: true,
            acknowledged: true,
            ..Default::default()
        };
        a.write_with_timestamp(b"abcdefgh", false, false, None, request(10))
            .unwrap();
        a.write_with_timestamp(b"ijklmnop", false, false, None, request(20))
            .unwrap();
        packet(&mut a, 40);
        let original_range = a.last_output_range.unwrap();
        assert_eq!(original_range, TxStreamRange { start: 0, end: 8 });
        let base = Seq(iss).wrapping_add(1);
        let next = a.receive.next();
        inject(&mut a, 41, next, base, ACK, 8, &[]);
        assert_eq!(a.flush(), Ok(8));
        assert_eq!(a.send.len(), 8);
        assert_eq!(
            a.write_with_timestamp(b"QRSTUVWX", false, false, None, request(30)),
            Err(Error::WouldBlock)
        );
        let event = a.tx_timestamps.next().unwrap();
        assert_eq!((event.cookie, event.stage), (10, Scheduled));
        for stage in [Scheduled, Transmit, Acknowledged] {
            let event = a.tx_timestamps.next().unwrap();
            assert_eq!(
                (event.cookie, event.target, event.stage, event.outcome),
                (20, 15, stage, TxTimestampOutcome::Cancelled)
            );
        }
        assert_eq!(a.tx_timestamps.next(), None); // Retained byte phases still pending.
        assert_eq!(
            a.write_with_timestamp(b"QRSTUVWX", false, false, None, request(30)),
            Ok(8)
        );
        let clock = TxTimestampClock::DeviceTicks {
            identity: 7,
            units_per_second: None,
        };
        a.tx_timestamps
            .observe(original_range, Transmit, Hardware, 123, clock);
        let event = a.tx_timestamps.next().unwrap();
        assert_eq!((event.cookie, event.target, event.stage), (10, 7, Transmit));
        assert_eq!(a.tx_timestamps.next(), None); // Old token cannot hit reused tail.
        inject(&mut a, 50, next, base.wrapping_add(8), ACK, 16, &[]);
        assert_eq!(a.tx_timestamps.next().unwrap().cookie, 10);
        let bytes = packet(&mut a, 60);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.header.sequence, base.wrapping_add(8).0);
        assert_eq!(segment.payload, b"QRSTUVWX");
        let replacement_range = a.last_output_range.unwrap();
        assert_eq!(replacement_range, TxStreamRange { start: 8, end: 16 });
        let event = a.tx_timestamps.next().unwrap();
        assert_eq!(
            (event.cookie, event.target, event.stage),
            (30, 15, Scheduled)
        );
        inject(&mut a, 70, next, base.wrapping_add(16), ACK, 16, &[]);
        assert_eq!(a.tx_timestamps.next().unwrap().cookie, 30);
        a.tx_timestamps
            .observe(original_range, Transmit, Hardware, 124, clock);
        assert_eq!(a.tx_timestamps.next(), None);
        a.tx_timestamps
            .observe(replacement_range, Transmit, Hardware, 125, clock);
        assert_eq!(a.tx_timestamps.next().unwrap().cookie, 30);
        assert_eq!(a.tx_timestamps.next(), None);
        assert_eq!(a.acknowledged(), 16);
        a.tx_timestamps.resize(0, 0).unwrap();
    }
}

#[test]
fn tx_timestamp_write_error_lowat_eor_and_cursor_exhaustion_rollback() {
    let mut cfg = config(16, 8);
    cfg.nagle = false;
    let (mut a, _) = pair(cfg, 100);
    let request = TxTimestampRequest {
        cookie: 1,
        scheduled: true,
        ..Default::default()
    };
    a.tx_timestamps.resize(2, usize::MAX).unwrap();
    assert_eq!(
        a.write_with_timestamp(b"", true, true, Some(0), request),
        Ok(0)
    );
    assert_eq!(
        a.write_with_timestamp(b"abc", true, true, Some(1), request),
        Ok(1)
    );
    // The accepted prefix exhausts LOWAT, without reserving a rejected write.
    assert_eq!(
        a.write_with_timestamp(b"xyz", false, false, Some(1), request),
        Err(Error::WouldBlock)
    );
    a.tx_timestamps.resize(1, usize::MAX).unwrap(); // Only successful write reserved.
    a.tx_timestamps.cancel_from(0);
    a.tx_timestamps.next().unwrap();
    a.shutdown().unwrap();
    assert_eq!(
        a.write_with_timestamp(b"x", false, false, None, request),
        Err(Error::InvalidState)
    );
    a.tx_timestamps.resize(0, 0).unwrap();

    let (mut a, _) = pair(config(8, 4), 100);
    a.tx_timestamps.resize(1, usize::MAX).unwrap();
    a.acknowledged = u64::MAX - 2;
    assert_eq!(
        a.write_with_timestamp(b"abc", false, false, None, request),
        Ok(2)
    );
    packet(&mut a, 40);
    let event = a.tx_timestamps.next().unwrap();
    assert_eq!(event.target, u64::MAX - 1);
    assert_eq!(a.last_output_range.unwrap().end, u64::MAX);
    assert_eq!(
        a.write_with_timestamp(b"x", false, false, None, request),
        Err(Error::WouldBlock)
    );
    a.tx_timestamps.resize(0, 0).unwrap();
}
#[path = "connection_rx_tests.rs"]
mod rx_metadata;
