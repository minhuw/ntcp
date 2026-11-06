use super::*;
use alloc::format;

fn isolated_config(mode: u8, prr: bool, cubic: bool, paced: bool) -> ConnectionConfig {
    ConnectionConfig {
        pmtud: Some(crate::PmtudConfig::new(1500)),
        initial_window: InitialWindow::Iw10,
        sack: mode != 0,
        rack: mode == 2,
        prr,
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

fn original_probe_ptb(a: &mut Connection, bytes: &[u8], now: u64, ip_header: u16, mtu: u32) {
    let sequence = wire::parse(ip(a.tuple), bytes).unwrap().header.sequence;
    assert!(
        a.pmtu_feedback(
            now,
            sequence,
            bytes.len() as u32 + u32::from(ip_header),
            ip_header,
            mtu
        )
        .unwrap()
    );
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-4
//= type=test
//= reason=Finite original-probe proof survives exact matching PTB while its size result is invalidated. Receiver-driven IPv4/IPv6 traces cover PTB before/after loss, decreasing quotes, wrap, split repairs and finite extended-tail delivery followed by recovery/PRR exit. Normal repair admission, MSS rescaling and PRR remain active; additional original loss, ECE, repair-copy loss, timeout and non-probe PTB commit normal congestion response. Replenishment resumes ACK growth; encoding failure and reservation rejection preserve conservative state.
//# Normal congestion control algorithms MUST remain in effect under all conditions
//# except when only an isolated probe packet is detected as lost. In this case
//# alone, the normal congestion (window or data rate) reduction SHOULD be
//# suppressed. If any other data loss is detected, standard congestion control MUST
//# take place.

//= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.2
//= type=test
//= reason=Only actual probe repair followed by finite extended-tail cumulative delivery and recovery/PRR exit can suppress the logical congestion response. Dual-family real receiver matrices cover exact matching PTB before/after loss, decreasing ceilings, wrap, PRR, Reno/CUBIC and pacing; other loss, ECE, repair-copy loss and RTO retain normal response. Without PTB the isolated result narrows search_high to probe-1; with matching PTB its invalidated size result cannot undo the accepted ceiling, even on an unexpected original ACK. Independent MSS scaling remains active.
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
//= reason=Isolated suppression with or without matching PTB waits for finite cumulative proof and recovery/PRR exit. pmtu_cooldown uses the unsuppressed logical window with one RTT per packet, a strict extra interval/tick and an RTO floor; the arithmetic test distinguishes logical14600 from admission1000. Receiver matrices assert exclusion before the deadline and admission at expiry. Matching PTB additionally retains its mandatory600-second hold through original, split-repair and trailing ACKs; periodic aging cannot disable failure headway.
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

//= https://www.rfc-editor.org/rfc/rfc4821#section-2
//= type=test
//= reason=Isolated original-probe loss with or without exact matching PTB suppresses only the logical congestion response after finite cumulative delivery and recovery/PRR exit. Dual-family receiver traces assert conservative split repairs, unchanged threshold, independently MSS-scaled window and mandatory headway; all other loss and timeout responses remain active. Literal unchanged-cwnd conflicts at1191-082/8201-076 remain TODO.
//# The isolated loss of a probe packet (with or without an ICMP Packet Too Big message) is treated as an indication of an MTU limit, and not as a congestion indicator. In this case alone, the Packetization Protocol is permitted to retransmit any missing data without adjusting the congestion window.
//= https://www.rfc-editor.org/rfc/rfc8201#section-5.4
//= type=test
//= reason=Implemented operative behavior: a PTB indicating a lost PMTU probe is not a congestion notification. Probe attribution invalidates the probe size for Unchanged, Deferred, Decreased and older-incarnation reports alike while finite isolated-probe proof survives, a congestion-loss response is suppressed only after receiver delivery and recovery exit, and neither the PTB nor its exact-range repair reduces cwnd or ssthresh, enters or extends recovery or starts PRR. Accepted lower PMTU still calls refresh_path_mss and Congestion::set_mss, rescaling the byte congestion window when MSS decreases; the dual-family receiver matrix asserts that ratio. Remaining (T23, AC-27): only the standards decision whether that RFC 5681/RFC 4821 MSS-decrease rescaling conflicts with "the congestion window may not change"; required MSS rescaling is preserved.
//# A loss caused by a PMTU probe indicated by the reception of a Packet Too Big message must not be considered as a congestion notification, and hence the congestion window may not change.
fn isolated_probe_cc_real_receiver_recovery_matrix() {
    for mode in 0..3 {
        for prr in [false, true] {
            for cubic in [false, true] {
                for paced in [false, true] {
                    for (ipv4, ptb_timing, second_hole) in [
                        (true, 0, false),
                        (true, 0, true),
                        (true, 1, false),
                        (true, 2, false),
                        (false, 1, false),
                        (false, 2, false),
                        (true, 2, true),
                        (false, 2, true),
                    ] {
                        let ip_header = if ipv4 { 20 } else { 40 };
                        let low = if ipv4 { 1024 } else { 1280 };
                        let (mut a, mut b) = super::pmtud_policy::family_pair(
                            isolated_config(mode, prr, cubic, paced),
                            ipv4,
                            u32::MAX - 4000,
                        );
                        a.write(b"x").unwrap();
                        deliver(&mut a, &mut b, 32);
                        deliver(&mut b, &mut a, 33);
                        a.write(&[7; 20_000]).unwrap();
                        let mut now = 40;
                        let original = paced_packet(&mut a, &mut now); // Drop only the probe.
                        let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
                        let (window, threshold, old_mss) =
                            (a.congestion.cwnd(), a.congestion.ssthresh(), a.mss);
                        let mut trailing = Vec::new();
                        for _ in 0..8 {
                            trailing.push(paced_packet(&mut a, &mut now));
                        }
                        let trailing_end = a.snd_nxt;
                        assert!(trailing_end.after(probe.trailing_end));
                        if ptb_timing == 1 {
                            original_probe_ptb(&mut a, &original, now, ip_header, probe.size - 1);
                            original_probe_ptb(&mut a, &original, now + 1, ip_header, low);
                            assert_eq!(a.congestion.ssthresh(), threshold);
                            now += 1;
                        }
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
                        if ptb_timing == 2 {
                            original_probe_ptb(&mut a, &original, now, ip_header, probe.size - 1);
                            original_probe_ptb(&mut a, &original, now + 1, ip_header, low);
                            now += 1;
                        }
                        let ptb_deadline =
                            (ptb_timing != 0).then(|| a.pmtud.as_ref().unwrap().deadline.unwrap());
                        if !second_hole || mode == 0 {
                            assert_eq!(a.congestion.pending_probe_response(), Some(probe.start));
                            assert_eq!(
                                a.congestion.unsuppressed_cwnd(),
                                (u64::from(window) * a.mss as u64 / old_mss as u64) as u32
                            );
                            assert_eq!(a.congestion.ssthresh(), threshold);
                        }
                        let initial_prr = a.prr.map(|p| p.counters());
                        assert_eq!(initial_prr.is_some(), prr);
                        let mut sent = 0;
                        if ptb_timing != 0 {
                            // Encoding failure cannot consume evidence or PRR credit.
                            let before = format!("{:?}{:?}{:?}", a.pmtud, a.congestion, a.prr);
                            for reserved in [false, true] {
                                assert_eq!(
                                    a.transmit_selected(now, &mut [0; 19], reserved),
                                    Err(Error::OutputTooSmall)
                                );
                                assert_eq!(
                                    format!("{:?}{:?}{:?}", a.pmtud, a.congestion, a.prr),
                                    before
                                );
                            }
                        }
                        // PRR counters immediately before the ACK that concludes the episode.
                        let mut concluding = None;
                        for _ in 0..20 {
                            now += 1;
                            let bytes = if ptb_timing == 2 && !paced {
                                let mut bytes = vec![0; 2000];
                                let len =
                                    a.transmit_selected(now, &mut bytes, true).unwrap().unwrap();
                                let payload = wire::parse(ip(a.tuple), &bytes[..len])
                                    .unwrap()
                                    .payload
                                    .len();
                                let mut departure = a.last_departure.unwrap();
                                a.accept_reserved_output(now, &mut departure, 0, payload, true)
                                    .unwrap();
                                bytes.truncate(len);
                                bytes
                            } else {
                                paced_packet(&mut a, &mut now)
                            };
                            let segment = wire::parse(ip(a.tuple), &bytes).unwrap();
                            if !second_hole {
                                assert!(
                                    segment.payload.len() as u32
                                        <= probe.end.distance_from(Seq(segment.header.sequence))
                                );
                                assert!(trailing_end.after(a.snd_una));
                                assert_eq!(
                                    a.congestion.pending_probe_response(),
                                    Some(probe.start)
                                );
                            }
                            assert!(bytes.len() as u32 + u32::from(ip_header) <= low);
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
                            if let Some(ptb_deadline) = ptb_deadline {
                                assert!(deadline >= ptb_deadline);
                                assert_eq!(p.info.current_mtu, low);
                                assert!(p.info.search_low <= low);
                                assert_eq!(p.info.search_high, low);
                            }
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

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.4
//= type=test
//# Before sending a probe, the flow MUST meet at least the following conditions:
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.4
//= type=test
//# o It has no outstanding probes or losses.
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.4
//= type=test
//# o If the last probe failed or was inconclusive, then the probe timeout has expired (see Section 7.6.2).
//= https://www.rfc-editor.org/rfc/rfc4821#section-2
//= type=test
//# The most likely (and least serious) probe failure is due to the link experiencing congestion-related losses while probing. In this case, it is appropriate to retry a probe of the same size as soon as the Packetization Layer has fully adapted to the congestion and recovered from the losses. In other cases, additional losses or timeouts indicate problems with the link or Packetization Layer. In these situations, it is desirable to use longer delays depending on the severity of the error.
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.4
//= type=test
//# The presence of other losses near the loss of the probe may indicate that the probe was lost due to congestion rather than due to an MTU limitation. In this case, the state variables eff_pmtu, search_low, and search_high SHOULD NOT be updated, and the same-sized probe SHOULD be attempted again as soon as the probing preconditions are met (i.e., once the packetization layer has no outstanding unrecovered losses). At this point, it is particularly appropriate to re-probe since the flow's congestion window will be at its lowest point, minimizing the probability of congestive losses.
//= https://www.rfc-editor.org/rfc/rfc4821#section-2
//= type=test
//= reason=Timeout/additional-loss completion supplies no failed-size ceiling and marks the outcome non-isolated, retaining normal congestion recovery. Receiver-driven IPv4/IPv6 NewReno/SACK/RACK with PRR on/off assert reduced window/threshold, one-MSS RTO response, unchanged bounds, repair-only output, cooldown exclusion and same-sized re-probing with available credit. Exact deadline tests retain the fivefold timeout hold and longer PTB holds; independent delivery, PTB, verification and black-hole evidence remain operative.
//# If there is a timeout or additional packets are lost during the probing process,
//# the probe is considered to be inconclusive (e.g., the lost probe does not
//# necessarily indicate that the probe exceeded the Path MTU). Furthermore, the
//# losses are treated like any other congestion indication: window or rate
//# adjustments are mandatory per the relevant congestion control standards
//# [RFC2914]. Probing can resume after a delay that is determined by the nature
//# of the detected failure.
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.6
//= type=test
//= reason=Categorized processing retains success/verification evidence at137/138, isolated loss with or without matching PTB at139/142, timeout congestion response and fivefold cooldown at143, and multiple-loss unchanged bounds plus same-sized re-probing at144. The real-probe success/failed-encode test, verification lifecycle, recovery/disqualifier matrices and probe_admission_real_loss_recovery_and_cooldown_output execute these outcomes. Independent PTB ceilings survive original or repair ACKs; timeout alone supplies no failed-size bound.
//# When a probe has completed, the result SHOULD be processed as follows, categorized by the probe's result type.
fn probe_admission_real_loss_recovery_and_cooldown_output() {
    for (ipv4, mode) in [true, false]
        .into_iter()
        .flat_map(|ipv4| (0..3).map(move |mode| (ipv4, mode)))
    {
        for prr in [false, true] {
            for failure in 0..4 {
                let second_hole = failure == 1;
                let low = if ipv4 { 1024 } else { 1280 };
                let ip_header = if ipv4 { 20 } else { 40 };
                let header = ip_header as u32 + 20;
                let mut cfg = isolated_config(mode, prr, false, false);
                cfg.pmtud.as_mut().unwrap().initial_mtu = Some(low);
                let (mut a, mut b) = super::pmtud_policy::family_pair(cfg, ipv4, u32::MAX - 4000);
                a.write(b"x").unwrap();
                deliver(&mut a, &mut b, 32);
                deliver(&mut b, &mut a, 33);
                a.write(&[7; 30_000]).unwrap();
                let first = packet(&mut a, 40); // Drop just the probe, or a second trailing hole too.
                let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
                assert_eq!(first.len() + ip_header, probe.size as usize);
                assert!(probe.size > low);
                let before = a.path_mtu_info().unwrap();
                let (window, threshold) = (a.congestion.cwnd(), a.congestion.ssthresh());
                let mut trailing = Vec::new();
                for _ in 0..8 {
                    let bytes = packet(&mut a, 41);
                    assert!(bytes.len() + ip_header <= low as usize);
                    assert_eq!(a.pmtud.as_ref().unwrap().probe.unwrap().start, probe.start);
                    trailing.push(bytes);
                }
                let mut now = 140;
                for (n, bytes) in trailing.iter().enumerate() {
                    if second_hole && n == 5 {
                        continue;
                    }
                    real_ack(&mut a, &mut b, bytes, now, false);
                }
                if !a.congestion.in_recovery() {
                    now = a.rack.deadline.expect("RACK loss detection");
                    a.timeout(now).unwrap();
                }
                assert!(a.congestion.in_recovery());
                let timeout_deadline = if failure >= 2 {
                    if failure == 2 {
                        // Drop the first repair too. Its second copy provides
                        // additional-loss evidence independent of the timeout.
                        let bytes = packet(&mut a, now + 1);
                        assert!(bytes.len() + ip_header <= low as usize);
                    }
                    // Also exercise timeout without a prior repair: its first
                    // repair ACK must not turn the timeout into MTU evidence.
                    now = a.rto_deadline.unwrap();
                    a.timeout(now).unwrap();
                    assert_eq!(a.consecutive_timeouts, 1);
                    let deadline = a.pmtud.as_ref().unwrap().deadline.unwrap();
                    assert!(deadline >= now + 5 * a.rto());
                    assert_eq!(a.congestion.cwnd(), a.mss as u32);
                    assert!(a.congestion.ssthresh() < threshold);
                    assert!(a.congestion.pending_probe_response().is_none());
                    Some(deadline)
                } else {
                    None
                };
                for _ in 0..64 {
                    now += 1;
                    let mut out = [0; 2000];
                    let Some(len) = a.transmit(now, &mut out).unwrap() else {
                        now = a.next_deadline().expect("probe repair needs a loss timer");
                        a.timeout(now).unwrap();
                        continue;
                    };
                    // OUTPUT, not merely target(): recovery never emits a new oversized probe.
                    assert!(len + ip_header <= low as usize);
                    real_ack(&mut a, &mut b, &out[..len], now, false);
                    if failure != 0 {
                        assert_eq!(a.path_mtu_info().unwrap(), before);
                    }
                    if timeout_deadline.is_some() {
                        assert!(a.congestion.pending_probe_response().is_none());
                        assert!(a.congestion.ssthresh() < threshold);
                    }
                    if a.pmtud.as_ref().unwrap().probe.is_none() {
                        break;
                    }
                }
                assert!(a.pmtud.as_ref().unwrap().probe.is_none());
                assert!(!a.congestion.in_recovery());
                assert!(a.prr.is_none());
                assert_eq!(a.flight(), 0);
                let info = a.path_mtu_info().unwrap();
                assert_eq!(info.current_mtu, before.current_mtu);
                assert_eq!(info.search_low, before.search_low);
                if failure != 0 {
                    assert_eq!(info.search_high, before.search_high);
                    assert!(a.congestion.cwnd() < window);
                    assert!(a.congestion.ssthresh() < threshold);
                }
                if second_hole {
                    assert_eq!(info.search_high, before.search_high);
                    assert!(a.pmtud.as_ref().unwrap().deadline.is_none());
                } else {
                    if failure == 0 {
                        assert_eq!(info.search_high, probe.size - 1);
                    }
                    let deadline = a.pmtud.as_ref().unwrap().deadline.unwrap();
                    if let Some(timeout_deadline) = timeout_deadline {
                        assert!(deadline >= timeout_deadline);
                    }
                    let needed = ((info.search_low + info.search_high).div_ceil(2) - header)
                        + 3 * a.mss as u32;
                    for _ in 0..16 {
                        if a.congestion.cwnd() >= needed {
                            break;
                        }
                        now += 1;
                        assert!(now < deadline - 1);
                        let bytes = packet(&mut a, now);
                        assert!(bytes.len() + ip_header <= low as usize);
                        assert!(a.pmtud.as_ref().unwrap().probe.is_none());
                        real_ack(&mut a, &mut b, &bytes, now, false);
                    }
                    assert!(a.congestion.cwnd() >= needed);
                    assert!(a.snd_wnd >= needed);
                    a.timeout(deadline - 1).unwrap();
                    let bytes = packet(&mut a, deadline - 1);
                    assert!(bytes.len() + ip_header <= low as usize);
                    assert!(a.pmtud.as_ref().unwrap().probe.is_none());
                    real_ack(&mut a, &mut b, &bytes, deadline - 1, false);
                    a.timeout(deadline).unwrap();
                    now = deadline - 1;
                }
                // Grow the ordinary congestion window if recovery left too little
                // credit for a probe plus its trailing window. Every ACK is real.
                let mut next = None;
                for _ in 0..32 {
                    now += 1;
                    let probe_room = a
                        .snd_wnd
                        .min(a.congestion.cwnd())
                        .saturating_sub(a.flight());
                    let bytes = packet(&mut a, now);
                    if let Some(probe) = a.pmtud.as_ref().unwrap().probe {
                        assert_eq!(bytes.len() + ip_header, probe.size as usize);
                        next = Some(probe);
                        break;
                    }
                    if failure != 0 {
                        assert!(
                            probe_room < probe.size - header + 3 * a.mss as u32,
                            "same-size retry must occur as soon as congestion credit permits"
                        );
                    }
                    assert!(
                        second_hole,
                        "failed probe must re-probe at the expiry boundary with available credit"
                    );
                    assert!(bytes.len() + ip_header <= low as usize);
                    real_ack(&mut a, &mut b, &bytes, now, false);
                }
                let next = next.expect("probe admission must resume after recovery and cooldown");
                assert!(next.size > low);
                if failure != 0 {
                    assert_eq!(a.path_mtu_info().unwrap(), before);
                    assert_eq!(next.size, probe.size);
                }
            }
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.4
//= type=test
//# o It has no outstanding probes or losses.
fn probe_admission_ordinary_loss_without_active_probe() {
    for mode in 0..3 {
        for prr in [false, true] {
            for rto in [false, true] {
                let mut cfg = isolated_config(mode, prr, false, false);
                cfg.pmtud.as_mut().unwrap().initial_mtu = Some(1024);
                let (mut a, mut b) = pair(cfg, 0);
                a.write(b"x").unwrap();
                deliver(&mut a, &mut b, 32);
                deliver(&mut b, &mut a, 33);
                let mut flight = Vec::new();
                for _ in 0..8 {
                    // Each write is too short to admit a probe and its tail.
                    a.write(&[8; 984]).unwrap();
                    let bytes = packet(&mut a, 40);
                    assert_eq!(bytes.len() + 20, 1024);
                    assert!(a.pmtud.as_ref().unwrap().probe.is_none());
                    flight.push(bytes);
                }
                let mut now = 140;
                if rto {
                    now = a.rto_deadline.unwrap();
                    a.timeout(now).unwrap();
                    assert_eq!(a.consecutive_timeouts, 1);
                } else {
                    for bytes in &flight[1..] {
                        real_ack(&mut a, &mut b, bytes, now, false);
                    }
                    if !a.congestion.in_recovery() {
                        now = a.rack.deadline.unwrap();
                        a.timeout(now).unwrap();
                    }
                    assert!(a.congestion.in_recovery());
                }
                // PMTUD itself is ready. Transport loss recovery must veto it.
                assert!(a.pmtud.as_ref().unwrap().target().is_some());
                a.write(&[9; 30_000]).unwrap();
                let recovery_end = a.snd_nxt;
                for _ in 0..64 {
                    now += 1;
                    let mut out = [0; 2000];
                    let len = match a.transmit(now, &mut out).unwrap() {
                        Some(len) => len,
                        None => {
                            now = a.next_deadline().expect("outstanding loss needs a timer");
                            a.timeout(now).unwrap();
                            continue;
                        }
                    };
                    assert!(len + 20 <= 1024);
                    assert!(a.pmtud.as_ref().unwrap().probe.is_none());
                    real_ack(&mut a, &mut b, &out[..len], now, false);
                    if a.snd_una.at_or_after(recovery_end) {
                        break;
                    }
                }
                assert!(a.snd_una.at_or_after(recovery_end));
                assert!(!a.congestion.in_recovery());
                assert!(a.sack_recovery.is_none());
                assert!(a.sack_post_rto.is_none());
                assert!(a.prr.is_none());
                assert_eq!(a.consecutive_timeouts, 0);
                let mut resumed = false;
                for _ in 0..32 {
                    now += 1;
                    let bytes = packet(&mut a, now);
                    if let Some(probe) = a.pmtud.as_ref().unwrap().probe {
                        assert_eq!(bytes.len() + 20, probe.size as usize);
                        assert!(probe.size > 1024);
                        resumed = true;
                        break;
                    }
                    real_ack(&mut a, &mut b, &bytes, now, false);
                }
                assert!(resumed, "mode={mode}, prr={prr}, rto={rto}");
            }
        }
    }
}

// Delay is bounded by the selected detector, not by an oracle about the path:
// release the leading original after one out-of-order ACK, before DupThresh or
// the RACK settling deadline. The lost-leading control crosses that boundary.
// A third control delivers the probe too, proving reorder alone need not fail it.
//= https://www.rfc-editor.org/rfc/rfc4821#section-6.1
//= type=test
//= reason=Real receiver NewReno/SACK/RACK traces in both families across serial wrap contrast leading-original delivery before DupThresh/RACK settling, actual leading-plus-probe loss, late leading delivery after detection, and reorder without probe loss. Table-driven detector-boundary schedules through real receiver Endpoints (pmtud_detector_boundary_tests.rs; both families, serial wrap, PRR off and on, reproducible seeds) add NewReno two versus three eligible duplicate ACKs, RFC 6675 IsLost two versus three discontiguous SACKed ranges and exactly 2*SMSS versus one byte more above the candidate, and RACK at the settling deadline - 1, = and + 1 with ACK-before-timer and timer-before-ACK orderings at equality, observed reordering and the three-SACK transition. At each boundary they lose the decisive or leading-progress ACK, batch genuine receiver ACKs at one tick, reorder leading and trailing originals and lose a repair copy, asserting the provisional classification before finite tail proof, the final isolated, other-loss or timeout outcome, MTU bounds, congestion commitment, packets within the MTU bound and complete delivery, including controls where ACK loss leaves insufficient evidence and recovery waits for a timer; seeded schedules never report an isolated probe loss when another original or a repair copy was lost. Finite tail/recovery proof gates isolation; other detected loss commits congestion response with unchanged MTU bounds and eventual stream progress. Existing trailing-hole, repair-copy, ECN, matching-PTB and inconclusive-RTO controls remain complementary. With PRR, byte-granular repair can end a NewReno isolated probe loss at the RTO, or leave the probe's tail as the RFC 6675 rescue retransmission, which commits the response: more conservative outcomes, with packet-aware recovery left to T22. Full timing/reordering robustness beyond these detector conditions remains unestablished: a finite-time ambiguity, not a missing detector function; sufficiently late leading originals are conservatively treated as other loss, not magically identified as reorder. Counterexample, for the T23 disposition: Drop the probe and withhold its leading original until after the selected loss detector fires. Through that decision, the sender's observations are identical to a run in which both packets were lost. Later delivery of the leading original cannot make the earlier decision distinguish those runs. Losing its progress ACK extends the ambiguity. Retain the whole timely/robust loss-reporting advice as TODO for that evidence/interpretation boundary.
//# It is important that the Packetization Layer has a timely and robust mechanism for detecting and reporting losses. PLPMTUD makes MTU adjustments on the basis of detected losses. Any delays or inaccuracy in loss notification is likely to result in incorrect MTU decisions or slow convergence. It is important that the mechanism can robustly distinguish between the isolated loss of just a probe and other losses in the probe's leading and trailing windows.
#[test]
fn isolated_probe_cc_reordered_leading_receiver_delivery_and_loss() {
    for ipv4 in [true, false] {
        for iss in [0, u32::MAX - 4000] {
            for mode in 0..3 {
                // NewReno, RFC6675 SACK, RACK.
                for prr in [false, true] {
                    for outcome in 0..4 {
                        // Isolated, other loss, no loss, late leading original.
                        let low = if ipv4 { 1024 } else { 1280 };
                        let ip_header = if ipv4 { 20 } else { 40 };
                        let mut cfg = isolated_config(mode, prr, false, false);
                        cfg.pmtud.as_mut().unwrap().initial_mtu = Some(low);
                        let (mut a, mut b) = super::pmtud_policy::family_pair(cfg, ipv4, iss);
                        let warmup = vec![0x11; low as usize - ip_header - 20];
                        // Earn ordinary flight credit with a real ACK. Its RTT
                        // must not collapse RACK's settling window to zero via
                        // sub-tick rounding before the reordering experiment.
                        a.write(&warmup).unwrap();
                        deliver(&mut a, &mut b, 32);
                        deliver(&mut b, &mut a, 1033);
                        let leading_data = vec![0x31; 800];
                        a.write(&leading_data).unwrap();
                        let leading = packet(&mut a, 1039);
                        assert!(a.pmtud.as_ref().unwrap().probe.is_none());
                        let payload = vec![0x72; 20000];
                        a.write(&payload).unwrap();
                        let original = packet(&mut a, 1040);
                        let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
                        assert!(probe.size > low);
                        let before = a.path_mtu_info().unwrap();
                        let (mut window, threshold) = (a.congestion.cwnd(), a.congestion.ssthresh());
                        let mut trailing = Vec::new();
                        for _ in 0..8 {
                            trailing.push(packet(&mut a, 1041));
                        }
                        let tail_end = a.snd_nxt;
                        assert!(tail_end.after(probe.trailing_end));
                        if iss != 0 {
                            assert!(tail_end.0 < probe.start.0, "proof crosses serial wrap");
                        }
                        let mut now = 1140;
                        let segment = wire::parse(ip(a.tuple), &trailing[0]).unwrap();
                        b.input(now, &segment).unwrap();
                        let ack = deliver(&mut b, &mut a, now);
                        let ack = wire::parse(ip(b.tuple), &ack).unwrap();
                        assert_eq!(ack.header.acknowledgment, probe.start.0.wrapping_sub(800));
                        assert_eq!(ack.options.sack_blocks[0].is_some(), mode != 0);
                        assert!(!a.congestion.in_recovery());
                        assert_eq!(a.path_mtu_info().unwrap(), before);
                        if let Some(deadline) = a.rack.deadline {
                            assert!(deadline > now);
                        }
                        if outcome == 0 || outcome == 2 {
                            real_ack(&mut a, &mut b, &leading, now, false);
                            assert!(!a.congestion.in_recovery());
                            assert_eq!(a.snd_una, probe.start);
                            // Ordinary leading delivery earns normal ACK growth.
                            window = a.congestion.cwnd();
                        }
                        if outcome == 2 {
                            real_ack(&mut a, &mut b, &original, now, false);
                            assert!(!a.congestion.in_recovery());
                        }
                        // Deliver disjoint then gap-filling tail packets, so both
                        // cumulative ACK and (when negotiated) real SACK matter.
                        for n in [2, 1, 4, 3, 6, 5, 7] {
                            real_ack(&mut a, &mut b, &trailing[n], now, false);
                        }
                        if outcome != 2 {
                            if !a.congestion.in_recovery() {
                                now = a.rack.deadline.expect("RACK must detect the remaining gap");
                                a.timeout(now).unwrap();
                            }
                            assert!(a.congestion.in_recovery());
                            assert_eq!(a.path_mtu_info().unwrap(), before);
                            if outcome == 0 {
                                assert_eq!(a.congestion.pending_probe_response(), Some(probe.start));
                                assert_eq!(a.congestion.ssthresh(), threshold);
                            } else {
                                assert!(a.congestion.pending_probe_response().is_none());
                                assert!(a.congestion.ssthresh() < threshold);
                                if outcome == 3 {
                                    // An original arriving after the detector's
                                    // decision cannot retroactively establish
                                    // isolated loss or justify an MTU shrink.
                                    real_ack(&mut a, &mut b, &leading, now, false);
                                    assert!(a.congestion.pending_probe_response().is_none());
                                }
                            }
                            for _ in 0..64 {
                                now += 1;
                                let mut bytes = vec![0; 2000];
                                let Some(len) = a.transmit(now, &mut bytes).unwrap() else {
                                    now = a.next_deadline().expect("unrepaired gap needs a timer");
                                    a.timeout(now).unwrap();
                                    continue;
                                };
                                assert!(len + ip_header <= low as usize);
                                // Isolation is provisional until the finite tail
                                // is cumulatively proven and recovery exits.
                                if outcome == 0 && tail_end.after(a.snd_una) {
                                    assert_eq!(
                                        a.congestion.pending_probe_response(),
                                        Some(probe.start),
                                        "ipv4={ipv4}, iss={iss}, mode={mode}, prr={prr}, now={now}, timeouts={}",
                                        a.consecutive_timeouts
                                    );
                                    assert_eq!(a.path_mtu_info().unwrap(), before);
                                }
                                real_ack(&mut a, &mut b, &bytes[..len], now, false);
                                if a.pmtud.as_ref().unwrap().probe.is_none() {
                                    break;
                                }
                            }
                        }
                        assert!(a.pmtud.as_ref().unwrap().probe.is_none());
                        assert!(!a.congestion.in_recovery());
                        assert!(a.prr.is_none());
                        assert!(a.congestion.pending_probe_response().is_none());
                        assert!(a.snd_una.at_or_after(tail_end));
                        let after = a.path_mtu_info().unwrap();
                        if outcome == 0 {
                            assert_eq!(after.current_mtu, before.current_mtu);
                            assert_eq!(after.search_high, probe.size - 1);
                            assert_eq!(a.congestion.ssthresh(), threshold);
                            assert_eq!(a.congestion.cwnd(), window);
                            let deadline = a.pmtud.as_ref().unwrap().deadline.unwrap();
                            assert!(
                                deadline - now
                                    > (u64::from(window) / a.mss as u64) * a.rtt.srtt().unwrap()
                            );
                            assert!(a.pmtud.as_ref().unwrap().target().is_none());
                        } else if outcome == 1 || outcome == 3 {
                            assert_eq!(after, before, "other loss supplies no MTU ceiling");
                            assert!(a.congestion.ssthresh() < threshold);
                            assert!(a.congestion.cwnd() < window);
                        } else {
                            assert_eq!(after.current_mtu, probe.size);
                            assert_eq!(a.congestion.ssthresh(), threshold);
                        }
                        // Finish the whole stream, rather than stopping at a
                        // classifier flag. Keep later probes out of this flight
                        // by staying within the existing failure headway.
                        for _ in 0..64 {
                            if a.acknowledged()
                                == (warmup.len() + leading_data.len() + payload.len()) as u64
                            {
                                break;
                            }
                            now += 1;
                            let bytes = packet(&mut a, now);
                            real_ack(&mut a, &mut b, &bytes, now, false);
                        }
                        let mut received = vec![0; 30000];
                        let n = b.read(&mut received).unwrap();
                        let mut expected = warmup;
                        expected.extend_from_slice(&leading_data);
                        expected.extend_from_slice(&payload);
                        assert_eq!(&received[..n], expected);
                        assert_eq!(a.acknowledged(), expected.len() as u64);
                        if outcome == 0 {
                            let deadline = a.pmtud.as_ref().unwrap().deadline.unwrap();
                            a.timeout(deadline - 1).unwrap();
                            assert!(a.pmtud.as_ref().unwrap().target().is_none());
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
//= reason=Finite original-probe proof survives exact matching PTB while its size result is invalidated. Receiver-driven IPv4/IPv6 traces cover PTB before/after loss, decreasing quotes, wrap, split repairs and finite extended-tail delivery followed by recovery/PRR exit. Normal repair admission, MSS rescaling and PRR remain active; additional original loss, ECE, repair-copy loss, timeout and non-probe PTB commit normal congestion response. Replenishment resumes ACK growth; encoding failure and reservation rejection preserve conservative state.
//# Normal congestion control algorithms MUST remain in effect under all conditions
//# except when only an isolated probe packet is detected as lost. In this case
//# alone, the normal congestion (window or data rate) reduction SHOULD be
//# suppressed. If any other data loss is detected, standard congestion control MUST
//# take place.

//= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.3
//= type=test
//= reason=Reviewed 76800de: real receiver disqualifier matrix drops a probe repair and fires actual TCP RTO, asserting one-MSS cwnd, reduced threshold and committed response throughout cumulative repair. Non-SACK NewReno as well as SACK/RACK, PRR and Reno/CUBIC are exercised. Pmtud::timeout applies five times cooldown; exact deadline unit test and integrated timeout trace prove later inconclusive retry loss cannot erase it. The repair after the timeout is T19's non-SACK go-back-N after RTO: the timed-out flight is resent in order from SND.UNA under slow start, each cumulative ACK releasing the next segments below the timeout's data boundary instead of one segment per backed-off RTO; a SACK connection whose receiver reported no SACKed range after the RTO uses the same in-order selection.
//# If the loss was detected with a timeout and repaired with go-back-n
//# retransmission, then congestion window reduction will be necessary. The
//# relatively high price of a failed probe in this case may merit a longer time
//# interval until the next probe. A time interval that is five times the
//# non-timeout failure case (Section 7.6.2) is RECOMMENDED.

fn isolated_probe_cc_real_receiver_disqualifiers() {
    for mode in 0..3 {
        for prr in [false, true] {
            for cubic in [false, true] {
                for (ipv4, with_ptb, cause) in [
                    Disqualifier::Leading,
                    Disqualifier::Timeout,
                    Disqualifier::Ecn,
                    Disqualifier::Implicit,
                ]
                .into_iter()
                .flat_map(|cause| {
                    [
                        (true, false, cause),
                        (true, true, cause),
                        (false, true, cause),
                    ]
                }) {
                    let ip_header = if ipv4 { 20 } else { 40 };
                    let low = if ipv4 { 1024 } else { 1280 };
                    let (mut a, mut b) = super::pmtud_policy::family_pair(
                        isolated_config(mode, prr, cubic, false),
                        ipv4,
                        0,
                    );
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
                    let original = packet(&mut a, 40);
                    let probe = a.pmtud.as_ref().unwrap().probe;
                    assert_eq!(probe.is_none(), matches!(cause, Disqualifier::Implicit));
                    let old_threshold = a.congestion.ssthresh();
                    let mut trailing = Vec::new();
                    for _ in 0..8 {
                        trailing.push(packet(&mut a, 41));
                    }
                    if with_ptb {
                        original_probe_ptb(&mut a, &original, 42, ip_header, low);
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
//= reason=Only actual probe repair followed by finite extended-tail cumulative delivery and recovery/PRR exit can suppress the logical congestion response. Dual-family real receiver matrices cover exact matching PTB before/after loss, decreasing ceilings, wrap, PRR, Reno/CUBIC and pacing; other loss, ECE, repair-copy loss and RTO retain normal response. Without PTB the isolated result narrows search_high to probe-1; with matching PTB its invalidated size result cannot undo the accepted ceiling, even on an unexpected original ACK. Independent MSS scaling remains active.
//# When only the probe is lost, it is treated as an indication that the Path MTU is
//# smaller than the probe size. In this case alone, the loss SHOULD NOT be
//# interpreted as congestion signal.

fn isolated_probe_cc_terminal_proof_once_and_only_after_extended_tail() {
    for start in [Seq(100), Seq(u32::MAX - 500)] {
        for disqualifier in 0..4 {
            let mut p =
                crate::pmtud::Pmtud::new(crate::PmtudConfig::new(1500), 1500, true, 600_000_000)
                    .unwrap();
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
//= reason=Isolated suppression with or without matching PTB waits for finite cumulative proof and recovery/PRR exit. pmtu_cooldown uses the unsuppressed logical window with one RTT per packet, a strict extra interval/tick and an RTO floor; the arithmetic test distinguishes logical14600 from admission1000. Receiver matrices assert exclusion before the deadline and admission at expiry. Matching PTB additionally retains its mandatory600-second hold through original, split-repair and trailing ACKs; periodic aging cannot disable failure headway.
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
        for (cubic, ipv4, with_ptb) in [false, true].into_iter().flat_map(|cubic| {
            [
                (cubic, true, false),
                (cubic, true, true),
                (cubic, false, true),
            ]
        }) {
            let ip_header = if ipv4 { 20 } else { 40 };
            let low = if ipv4 { 1024 } else { 1280 };
            let (mut a, mut b) = super::pmtud_policy::family_pair(
                isolated_config(2, prr, cubic, false),
                ipv4,
                u32::MAX - 4000,
            );
            a.write(b"x").unwrap();
            deliver(&mut a, &mut b, 32);
            deliver(&mut b, &mut a, 33);
            a.write(&[7; 20_000]).unwrap();
            let original = packet(&mut a, 40);
            let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
            let mut trailing = Vec::new();
            for _ in 0..8 {
                trailing.push(packet(&mut a, 41));
            }
            if with_ptb {
                original_probe_ptb(&mut a, &original, 42, ip_header, low);
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
            let mut now = a.now;
            for _ in 0..24 {
                now += 1;
                let bytes = packet(&mut a, now);
                real_ack(&mut a, &mut b, &bytes, now, false);
                assert!(a.congestion.pending_probe_response().is_none());
                if a.pmtud.as_ref().unwrap().probe.is_none() {
                    break;
                }
            }
            assert!(a.snd_una.at_or_after(probe.trailing_end));
            assert!(a.pmtud.as_ref().unwrap().probe.is_none());
            assert!(a.congestion.ssthresh() <= committed);
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
//= reason=Finite original-probe proof survives exact matching PTB while its size result is invalidated. Receiver-driven IPv4/IPv6 traces cover PTB before/after loss, decreasing quotes, wrap, split repairs and finite extended-tail delivery followed by recovery/PRR exit. Normal repair admission, MSS rescaling and PRR remain active; additional original loss, ECE, repair-copy loss, timeout and non-probe PTB commit normal congestion response. Replenishment resumes ACK growth; encoding failure and reservation rejection preserve conservative state.
//# Normal congestion control algorithms MUST remain in effect under all conditions
//# except when only an isolated probe packet is detected as lost. In this case
//# alone, the normal congestion (window or data rate) reduction SHOULD be
//# suppressed. If any other data loss is detected, standard congestion control MUST
//# take place.

fn isolated_probe_cc_replenishment_does_not_extend_recovery_proof() {
    for mode in 0..3 {
        for prr in [false, true] {
            for (cubic, ipv4, with_ptb) in [false, true].into_iter().flat_map(|cubic| {
                [
                    (cubic, true, false),
                    (cubic, true, true),
                    (cubic, false, true),
                ]
            }) {
                let ip_header = if ipv4 { 20 } else { 40 };
                let low = if ipv4 { 1024 } else { 1280 };
                let (mut a, mut b) = super::pmtud_policy::family_pair(
                    isolated_config(mode, prr, cubic, false),
                    ipv4,
                    u32::MAX - 4000,
                );
                a.write(b"x").unwrap();
                deliver(&mut a, &mut b, 32);
                deliver(&mut b, &mut a, 33);
                a.write(&[7; 60_000]).unwrap();
                let original = packet(&mut a, 40); // Drop only the explicit probe.
                let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
                let (window, threshold, old_mss) =
                    (a.congestion.cwnd(), a.congestion.ssthresh(), a.mss);
                let trailing: Vec<_> = (0..8).map(|_| packet(&mut a, 41)).collect();
                let proof_end = a.snd_nxt;
                assert!(proof_end.after(probe.trailing_end));
                if with_ptb {
                    original_probe_ptb(&mut a, &original, 42, ip_header, low);
                }
                let mut now = 140;
                // SACK permits this partial cumulative proof without NewReno's
                // partial-ACK loss or RACK's zero-window loss classification.
                let hold_tail = with_ptb && mode == 1;
                for (n, bytes) in trailing.iter().enumerate() {
                    if !hold_tail || n != 7 {
                        real_ack(&mut a, &mut b, bytes, now, false);
                    }
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
                    let end =
                        Seq(segment.header.sequence).wrapping_add(segment.payload.len() as u32);
                    if end == probe.end {
                        break bytes;
                    }
                    assert!(probe.end.after(end));
                    real_ack(&mut a, &mut b, &bytes, now, false);
                };
                assert!(a.congestion.in_recovery());
                now += 1;
                let outstanding = packet(&mut a, now);
                assert_eq!(
                    wire::parse(ip(a.tuple), &outstanding)
                        .unwrap()
                        .header
                        .sequence,
                    proof_end.0
                ); // Fresh output before the recovery-ending ACK.
                real_ack(&mut a, &mut b, &ending_repair, now, false);
                if hold_tail {
                    // Delivering the repaired gap plus seven trailing packets
                    // still falls short of the finite original flight boundary.
                    assert!(proof_end.after(a.snd_una));
                    assert!(a.pmtud.as_ref().unwrap().probe.is_some());
                    assert_eq!(a.congestion.pending_probe_response(), Some(probe.start));
                    assert_eq!(a.congestion.ssthresh(), threshold);
                    real_ack(&mut a, &mut b, &trailing[7], now, false);
                }
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
                let scaled_window = (u64::from(window) * a.mss as u64 / old_mss as u64) as u32;
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
fn isolated_probe_ptb_rack_proof_ack_with_fresh_loss_commits_congestion() {
    for ipv4 in [true, false] {
        for prr in [false, true] {
            for cubic in [false, true] {
                let ip_header = if ipv4 { 20 } else { 40 };
                let low = if ipv4 { 1024 } else { 1280 };
                let (mut a, mut b) = super::pmtud_policy::family_pair(
                    isolated_config(2, prr, cubic, false),
                    ipv4,
                    u32::MAX - 4000,
                );
                a.write(b"x").unwrap();
                deliver(&mut a, &mut b, 32);
                deliver(&mut b, &mut a, 33);
                a.write(&[7; 60_000]).unwrap();
                let original = packet(&mut a, 40); // Drop the explicit probe.
                let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
                let threshold = a.congestion.ssthresh();
                let trailing: Vec<_> = (0..8).map(|_| packet(&mut a, 41)).collect();
                let proof_end = a.snd_nxt;
                original_probe_ptb(&mut a, &original, 42, ip_header, low);
                let accepted = a.path_mtu_info();
                let hold = a.pmtud.as_ref().unwrap().deadline;
                for bytes in &trailing {
                    real_ack(&mut a, &mut b, bytes, 140, false);
                }
                assert!(a.congestion.in_recovery());
                assert_eq!(a.congestion.pending_probe_response(), Some(probe.start));
                assert_eq!(a.congestion.ssthresh(), threshold);
                let mut now = 200;
                // Deliver the split repair except its last segment, keeping
                // recovery open while new packets are admitted beyond proof_end.
                let ending_repair = loop {
                    let bytes = packet(&mut a, now);
                    let segment = wire::parse(ip(a.tuple), &bytes).unwrap();
                    let end = Seq(segment.header.sequence)
                        .wrapping_add(segment.payload.len() as u32);
                    if end == probe.end {
                        break bytes;
                    }
                    assert!(probe.end.after(end));
                    real_ack(&mut a, &mut b, &bytes, now, false);
                    now += 1;
                };
                now += 1;
                let lost = packet(&mut a, now); // Lose fresh data during recovery.
                let lost_segment = wire::parse(ip(a.tuple), &lost).unwrap();
                assert_eq!(Seq(lost_segment.header.sequence), proof_end);
                let lost_end = proof_end.wrapping_add(lost_segment.payload.len() as u32);
                now += 10;
                let fresh = packet(&mut a, now);
                let fresh_segment = wire::parse(ip(a.tuple), &fresh).unwrap();
                assert_eq!(Seq(fresh_segment.header.sequence), lost_end);
                let fresh_end = lost_end.wrapping_add(fresh_segment.payload.len() as u32);
                assert_eq!(a.pmtud.as_ref().unwrap().probe.unwrap().trailing_end, proof_end);
                assert_eq!(a.congestion.pending_probe_response(), Some(probe.start));
                assert_eq!(a.prr.is_some(), prr);
                now += 100;
                // Coalesce real receiver evidence into one ACK: gap repair
                // cumulatively completes the old proof, while SACK of the later
                // fresh packet lets RACK detect the new loss on that same input.
                b.input(now, &fresh_segment).unwrap();
                let repair_segment = wire::parse(ip(a.tuple), &ending_repair).unwrap();
                b.input(now, &repair_segment).unwrap();
                let ack_bytes = packet(&mut b, now);
                let ack = wire::parse(ip(b.tuple), &ack_bytes).unwrap();
                assert_eq!(Seq(ack.header.acknowledgment), proof_end);
                assert_eq!(ack.options.sack_blocks[0], Some((lost_end.0, fresh_end.0)));
                assert_eq!(ack.options.sack_blocks.iter().flatten().count(), 1);
                a.input(now, &ack).unwrap();
                assert_eq!(a.snd_una, proof_end);
                assert!(a.pmtud.as_ref().unwrap().probe.is_none());
                assert_eq!(a.rack.lowest_lost(a.mss as u32).unwrap().0, proof_end);
                assert!(a.congestion.in_recovery());
                assert!(a.congestion.pending_probe_response().is_none());
                assert!(a.pmtud.as_ref().unwrap().eligible_probe_loss().is_none());
                assert!(a.congestion.ssthresh() < threshold);
                let committed = a.congestion.ssthresh();
                // Ordinary repair and PRR must finish with the congestion
                // response committed, never inherit the old probe exemption.
                for _ in 0..4 {
                    now += 1;
                    let bytes = packet(&mut a, now);
                    let segment = wire::parse(ip(a.tuple), &bytes).unwrap();
                    assert_eq!(Seq(segment.header.sequence), a.snd_una);
                    assert!(lost_end.at_or_after(
                        Seq(segment.header.sequence).wrapping_add(segment.payload.len() as u32)
                    ));
                    real_ack(&mut a, &mut b, &bytes, now, false);
                    assert!(a.congestion.pending_probe_response().is_none());
                    assert_eq!(a.congestion.ssthresh(), committed);
                    if a.snd_una == fresh_end {
                        break;
                    }
                }
                assert_eq!(a.snd_una, fresh_end);
                assert!(!a.congestion.in_recovery());
                assert!(a.prr.is_none());
                assert!(a.congestion.cwnd() <= committed);
                assert_eq!(a.path_mtu_info(), accepted);
                assert_eq!(a.pmtud.as_ref().unwrap().deadline, hold);
                assert!(a.pmtud.as_mut().unwrap().take_probe_outcome(a.snd_una).is_none());
                let mut received = [0; 65_536];
                assert_eq!(b.read(&mut received).unwrap(), 1 + fresh_end.distance_from(probe.start) as usize);
            }
        }
    }
}

#[test]
fn isolated_probe_ptb_original_ack_cannot_restore_size_or_shorten_hold() {
    for ipv4 in [true, false] {
        for iss in [0, u32::MAX - 4000] {
            let ip_header = if ipv4 { 20 } else { 40 };
            let low = if ipv4 { 1024 } else { 1280 };
            let (mut a, mut b) =
                super::pmtud_policy::family_pair(isolated_config(1, true, false, false), ipv4, iss);
            a.write(b"x").unwrap();
            deliver(&mut a, &mut b, 32);
            deliver(&mut b, &mut a, 33);
            a.write(&[7; 20_000]).unwrap();
            let original = packet(&mut a, 40);
            let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
            let (window, threshold, mss) = (a.congestion.cwnd(), a.congestion.ssthresh(), a.mss);
            let trailing: Vec<_> = (0..8).map(|_| packet(&mut a, 41)).collect();
            let before = format!("{:?}", a.pmtud);
            for (seq, size, header) in [
                (probe.start.0.wrapping_add(1), probe.size, ip_header),
                (probe.end.0, probe.size, ip_header),
                (probe.start.0, probe.size - 1, ip_header),
                (probe.start.0, probe.size, ip_header + 4),
            ] {
                assert!(!a.pmtu_feedback(42, seq, size, header, low).unwrap());
                assert_eq!(format!("{:?}", a.pmtud), before);
            }
            original_probe_ptb(&mut a, &original, 43, ip_header, probe.size - 1);
            original_probe_ptb(&mut a, &original, 44, ip_header, low);
            let accepted = a.path_mtu_info();
            let deadline = a.pmtud.as_ref().unwrap().deadline;
            assert_eq!(a.congestion.ssthresh(), threshold);
            assert!(a.congestion.pending_probe_response().is_none()); // PTB alone is not loss proof.
            // The supposedly dropped original actually arrives, with no repair.
            real_ack(&mut a, &mut b, &original, 45, false);
            assert_eq!(a.path_mtu_info(), accepted);
            assert!(a.pmtud.as_ref().unwrap().probe.is_none());
            for bytes in &trailing {
                real_ack(&mut a, &mut b, bytes, 46, false);
                assert_eq!(a.path_mtu_info(), accepted);
                assert_eq!(a.pmtud.as_ref().unwrap().deadline, deadline);
            }
            assert_eq!(a.flight(), 0);
            assert_eq!(a.congestion.ssthresh(), threshold);
            assert!(a.congestion.cwnd() >= (u64::from(window) * a.mss as u64 / mss as u64) as u32);
            assert!(
                !a.pmtu_feedback(47, probe.start.0, probe.size, ip_header, low - 1)
                    .unwrap()
            );
            let p = a.pmtud.as_mut().unwrap();
            assert!(p.take_probe_outcome(a.snd_una).is_none());
            p.tick(deadline.unwrap() - 1);
            assert!(p.target().is_none());
            assert_eq!(p.info.current_mtu, low);
            assert_eq!(p.info.search_high, low);
        }
    }
}

#[test]
fn isolated_probe_ptb_reserved_repair_rejection_commits_once() {
    for (ipv4, cancel) in [true, false]
        .into_iter()
        .flat_map(|ipv4| [(ipv4, false), (ipv4, true)])
    {
        let ip_header = if ipv4 { 20 } else { 40 };
        let low = if ipv4 { 1024 } else { 1280 };
        let (mut a, mut b) = super::pmtud_policy::family_pair(
            isolated_config(2, true, true, false),
            ipv4,
            u32::MAX - 4000,
        );
        a.write(b"x").unwrap();
        deliver(&mut a, &mut b, 32);
        deliver(&mut b, &mut a, 60); // Keep a real nonzero RACK settling window.
        a.write(&[7; 20_000]).unwrap();
        let original = packet(&mut a, 70);
        let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
        let trailing: Vec<_> = (0..if cancel { 3 } else { 8 })
            .map(|_| packet(&mut a, 71))
            .collect();
        original_probe_ptb(&mut a, &original, 72, ip_header, low);
        let selected_at = if cancel {
            real_ack(&mut a, &mut b, &trailing[0], 170, false);
            let at = a
                .rack
                .deadline
                .expect("single SACK schedules RACK settling");
            a.timeout(at).unwrap();
            assert!(a.prr.unwrap().timer_repair());
            at
        } else {
            for bytes in &trailing {
                real_ack(&mut a, &mut b, bytes, 170, false);
            }
            171
        };
        assert_eq!(a.congestion.pending_probe_response(), Some(probe.start));
        let info = a.path_mtu_info();
        let deadline = a.pmtud.as_ref().unwrap().deadline;
        let edges = (a.snd_una, a.snd_nxt);
        let target = a.congestion.recovery_target();
        let mut bytes = [0; 2000];
        let len = a
            .transmit_selected(selected_at, &mut bytes, true)
            .unwrap()
            .unwrap();
        let payload = wire::parse(ip(a.tuple), &bytes[..len])
            .unwrap()
            .payload
            .len();
        let mut departure = a.last_departure.unwrap();
        let counters = a.prr.unwrap().counters();
        if cancel {
            assert!(a.cancel_reserved_repair());
        } else {
            // Other repairs retain immutable ownership across local rejection.
            assert!(!a.cancel_reserved_repair());
            a.reject_reserved_output();
        }
        assert_eq!(a.prr.unwrap().counters(), counters);
        assert_eq!((a.snd_una, a.snd_nxt), edges);
        assert_eq!(a.path_mtu_info(), info);
        assert_eq!(a.pmtud.as_ref().unwrap().deadline, deadline);
        assert!(a.pmtud.as_ref().unwrap().probe.is_none());
        assert!(a.congestion.pending_probe_response().is_none());
        assert_eq!(a.congestion.ssthresh(), target);
        a.reject_reserved_output();
        assert_eq!(a.congestion.ssthresh(), target);
        if cancel {
            for bytes in &trailing[1..] {
                real_ack(&mut a, &mut b, bytes, selected_at, false);
            }
        } else {
            a.accept_reserved_output(selected_at, &mut departure, 0, payload, true)
                .unwrap();
            real_ack(&mut a, &mut b, &bytes[..len], selected_at, false);
        }
        let mut now = selected_at;
        for _ in 0..16 {
            now += 1;
            let bytes = packet(&mut a, now);
            real_ack(&mut a, &mut b, &bytes, now, false);
            assert!(a.congestion.pending_probe_response().is_none());
            if a.snd_una.at_or_after(probe.trailing_end) {
                break;
            }
        }
        assert!(a.snd_una.at_or_after(probe.trailing_end));
        assert!(a.prr.is_none());
        assert_eq!(a.congestion.ssthresh(), target);
    }
}

#[test]
fn isolated_probe_ptb_deferred_below_delivery_waits_for_head_timeout() {
    for ipv4 in [true, false] {
        for (timeout, other_quote) in [(false, false), (true, false), (true, true)] {
            let ip_header = if ipv4 { 20 } else { 40 };
            let low = if ipv4 { 1024 } else { 1280 };
            let proven = low + 40;
            let (mut a, mut b) = super::pmtud_policy::family_pair(
                isolated_config(1, true, false, false),
                ipv4,
                u32::MAX - 4000,
            );
            a.write(&vec![6; proven as usize - ip_header as usize - 20])
                .unwrap();
            let bytes = packet(&mut a, 32);
            assert_eq!(bytes.len() as u32 + u32::from(ip_header), proven);
            assert!(a.pmtud.as_ref().unwrap().probe.is_none());
            real_ack(&mut a, &mut b, &bytes, 33, false);
            a.write(&[7; 20_000]).unwrap();
            let original = packet(&mut a, 40);
            let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
            let trailing: Vec<_> = (0..8).map(|_| packet(&mut a, 41)).collect();
            let proof_end = a.snd_nxt;
            let before = a.path_mtu_info();
            let threshold = a.congestion.ssthresh();
            original_probe_ptb(&mut a, &original, 42, ip_header, low);
            assert_eq!(a.path_mtu_info(), before); // Proven delivery requires cautious deferral.
            let hold = a.pmtud.as_ref().unwrap().deadline.unwrap();
            if !timeout {
                real_ack(&mut a, &mut b, &original, 43, false);
                for bytes in &trailing {
                    real_ack(&mut a, &mut b, bytes, 44, false);
                }
                assert!(a.snd_una.at_or_after(proof_end));
                assert_eq!(a.path_mtu_info().unwrap().current_mtu, 1500);
                assert_eq!(a.congestion.ssthresh(), threshold);
                a.timeout(hold).unwrap(); // Progress cleared the pending decrease.
                assert_eq!(a.path_mtu_info().unwrap().current_mtu, 1500);
                continue;
            }
            for bytes in &trailing {
                real_ack(&mut a, &mut b, bytes, 140, false);
            }
            assert_eq!(a.congestion.pending_probe_response(), Some(probe.start));
            if other_quote {
                original_probe_ptb(&mut a, &trailing[0], 141, ip_header, low);
                assert_eq!(a.path_mtu_info(), before);
                assert!(a.congestion.pending_probe_response().is_none());
                assert!(a.congestion.ssthresh() < threshold);
                for n in 0..16 {
                    let bytes = packet(&mut a, 142 + n);
                    real_ack(&mut a, &mut b, &bytes, 142 + n, false);
                    assert!(a.congestion.pending_probe_response().is_none());
                    if a.snd_una.at_or_after(proof_end) {
                        break;
                    }
                }
                assert!(a.snd_una.at_or_after(proof_end));
                assert_eq!(a.path_mtu_info().unwrap().current_mtu, 1500);
                assert!(a.congestion.ssthresh() < threshold);
                assert!(a.pmtud.as_ref().unwrap().deadline.unwrap() >= hold);
                continue;
            }
            let mut now = a.rto_deadline.unwrap();
            a.timeout(now).unwrap();
            assert_eq!(a.consecutive_timeouts, 1);
            assert_eq!(a.path_mtu_info().unwrap().current_mtu, low);
            assert_eq!(a.congestion.cwnd(), a.mss as u32);
            assert!(a.congestion.pending_probe_response().is_none());
            assert!(a.congestion.ssthresh() < threshold);
            assert!(a.pmtud.as_ref().unwrap().deadline.unwrap() >= hold);
            for _ in 0..32 {
                now += 1;
                let mut bytes = [0; 2000];
                let Some(len) = a.transmit(now, &mut bytes).unwrap() else {
                    now = a.next_deadline().unwrap();
                    a.timeout(now).unwrap();
                    continue;
                };
                assert!(len as u32 + u32::from(ip_header) <= low);
                real_ack(&mut a, &mut b, &bytes[..len], now, false);
                assert!(a.congestion.pending_probe_response().is_none());
                assert!(a.congestion.ssthresh() < threshold);
                if a.snd_una.at_or_after(proof_end) {
                    break;
                }
            }
            assert!(a.snd_una.at_or_after(proof_end));
            assert!(a.prr.is_none());
            assert_eq!(a.path_mtu_info().unwrap().current_mtu, low);
        }
    }
}

#[test]
fn isolated_probe_ptb_other_packet_commits_and_repairs_make_peer_progress() {
    for ipv4 in [true, false] {
        for quote_repair in [false, true] {
            let ip_header = if ipv4 { 20 } else { 40 };
            let low = if ipv4 { 1100 } else { 1320 };
            let ceiling = if ipv4 { 1000 } else { 1280 };
            let mut cfg = isolated_config(1, true, false, false);
            cfg.pmtud.as_mut().unwrap().initial_search_low = Some(low);
            let (mut a, mut b) = super::pmtud_policy::family_pair(cfg, ipv4, u32::MAX - 4000);
            a.write(b"x").unwrap();
            deliver(&mut a, &mut b, 32);
            deliver(&mut b, &mut a, 33);
            a.write(&[7; 20_000]).unwrap();
            let original = packet(&mut a, 40);
            let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
            let threshold = a.congestion.ssthresh();
            let trailing: Vec<_> = (0..8).map(|_| packet(&mut a, 41)).collect();
            let proof_end = a.snd_nxt;
            original_probe_ptb(&mut a, &original, 42, ip_header, probe.size - 1);
            for bytes in &trailing {
                real_ack(&mut a, &mut b, bytes, 140, false);
            }
            assert_eq!(a.congestion.pending_probe_response(), Some(probe.start));
            let quote = if quote_repair {
                let repair = packet(&mut a, 141); // Lose a smaller repair copy as well.
                assert_eq!(
                    wire::parse(ip(a.tuple), &repair).unwrap().header.sequence,
                    probe.start.0
                );
                assert!(repair.len() as u32 + u32::from(ip_header) < probe.size);
                repair
            } else {
                trailing[0].clone() // An exact live packet, but not the original probe.
            };
            original_probe_ptb(&mut a, &quote, 142, ip_header, ceiling);
            assert_eq!(a.path_mtu_info().unwrap().current_mtu, ceiling);
            assert!(a.pmtud.as_ref().unwrap().probe.is_none());
            assert!(a.congestion.pending_probe_response().is_none());
            assert!(a.congestion.ssthresh() < threshold);
            let mut now = 142;
            for _ in 0..32 {
                now += 1;
                let mut bytes = [0; 2000];
                let Some(len) = a.transmit(now, &mut bytes).unwrap() else {
                    now = a.next_deadline().unwrap();
                    a.timeout(now).unwrap();
                    continue;
                };
                assert!(len as u32 + u32::from(ip_header) <= ceiling);
                real_ack(&mut a, &mut b, &bytes[..len], now, false);
                assert!(a.congestion.pending_probe_response().is_none());
                assert!(a.congestion.ssthresh() < threshold);
                if a.snd_una.at_or_after(proof_end) {
                    break;
                }
            }
            assert!(a.snd_una.at_or_after(proof_end));
            assert!(!a.congestion.in_recovery());
            assert!(a.prr.is_none());
            assert_eq!(a.path_mtu_info().unwrap().current_mtu, ceiling);
        }
    }
}

#[test]
fn isolated_probe_cc_loss_freezes_original_minimum_tail() {
    for cause in 0..3 {
        let mut p =
            crate::pmtud::Pmtud::new(crate::PmtudConfig::new(1500), 1500, true, 600_000_000)
                .unwrap();
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
