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
//= https://www.rfc-editor.org/rfc/rfc5681#section-2
//= type=test
//= reason=Selected output-policy matrix: ordinary min(rwnd,cwnd) in slow start/avoidance and reduced-cwnd exit; section3.2 Limited Transmit; RFC6675 non-RACK/non-PRR pipe; strict RFC6937 CRB credit (LegacyInitialCredit excluded); RFC8985 modified RACK pipe and one accounted TLP overcommit. Separate shrink/probe matrix limits receive-window exceptions to prescribed retry/probe policies. Not a literal sequence-edge assertion in enhanced recovery or a section4.3 half-flight proof.
//# At any given time, a TCP MUST NOT send data with a sequence number higher than the sum of the highest acknowledged sequence number and the minimum of cwnd and rwnd.
//= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
//= type=test
//= reason=Ordinary ACK byte counting and exact emitted ranges are asserted in slow start and congestion avoidance; reduced-cwnd handoff and the separately selected recovery/probe policies have their own wire matrix. LegacyInitialCredit is not strict RFC6937 evidence; section4.3 segment-count TODO remains independent.
//# The slow start and congestion avoidance algorithms MUST be used by a TCP sender to control the amount of outstanding data being injected into the network.
//= https://www.rfc-editor.org/rfc/rfc5681#section-3
//= type=test
//= reason=Policy-specific output bounds, not an unconditional waiver: ordinary min(rwnd,cwnd), controlled Limited Transmit extension, RFC6675 pipe, strict RFC6937 CRB byte credit, RFC8985 modified recovery and single accounted TLP probe. Shrink allows only prescribed old-data retry/probe exceptions. Literal half-flight segments-per-RTT is separately unresolved, and LegacyInitialCredit does not meet the strict equations.
//# In some situations, it may be beneficial for a TCP sender to be more conservative than the algorithms allow; however, a TCP MUST NOT be more aggressive than the following algorithms allow (that is, MUST NOT send data when the value of cwnd computed by the following algorithms would not allow the data to be sent).
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
//= type=test
//= reason=Selected algorithms, ECN on/off: normal ACKs use slow start/byte-counting avoidance and min windows; eligible duplicate ACKs use Limited Transmit/NewReno or negotiated SACK/strict PRR/RACK; RTO sends old data after reduction. TLP is the RFC8985 single-accounted-probe extension. These are output-policy claims, not whole external RFC conformance; RFC5681 section4.3 segment-count TODO remains separate. LegacyInitialCredit is excluded from strict RFC6937 evidence.
//# TCP follows existing algorithms for sending data packets in response to incoming ACKs, multiple duplicate acknowledgments, or retransmit timeouts [RFC2581].
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

        // Actual ACK-driven strict CRB entry with RFC6675 candidate selection;
        // credit controls quantity, not the unselected forced-entry SMSS rule.
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
        assert_eq!(a.config.prr_algorithm, PrrAlgorithm::Rfc6937Crb);
        let base = a.snd_una;
        strict_ack(&mut a, 200_000, 0, &[(7000, 8000)]);
        a.timeout(225_000).unwrap();
        assert_eq!(outputs(&mut a, 225_000, base), vec![]);
        assert_eq!(a.prr.unwrap().counters(), (10_000, 0, 0));
        strict_ack(&mut a, 226_000, 0, &[(7000, 9000)]);
        assert_eq!(a.prr.unwrap().credit(), 1000);
        assert_eq!(outputs(&mut a, 226_000, base), vec![(0, 1000)]);
        assert_eq!(a.prr.unwrap().counters(), (10_000, 1000, 1000));
        strict_ack(&mut a, 227_000, 0, &[(7000, 9000)]);
        assert_eq!(outputs(&mut a, 227_000, base), vec![]);
    }
}

#[test]
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
        a.timeout(pto).unwrap();
        assert_eq!(outputs(&mut a, pto, base), vec![(4000, 1000)]);
        assert_eq!(a.flight(), a.congestion.cwnd() + 1000);
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
