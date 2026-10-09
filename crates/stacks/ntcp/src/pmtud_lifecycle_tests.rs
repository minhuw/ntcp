use super::*;
use crate::{Endpoint, EndpointConfig, PmtudConfig};

fn cfg() -> ConnectionConfig {
    ConnectionConfig {
        pmtud: Some(PmtudConfig::new(1500)),
        initial_window: InitialWindow::Iw10,
        nagle: false,
        timestamps: false,
        sack: false,
        delayed_ack_us: 0,
        ..config(65_536, 1460)
    }
}

fn unscaled_pair(iss: u32) -> (Connection, Connection) {
    let mut a = Connection::active(tuple(), cfg(), iss, 0).unwrap();
    let bytes = packet(&mut a, 0);
    let mut syn = wire::parse(ip(tuple()), &bytes).unwrap();
    // Model a legacy peer that does not negotiate WS or SACK.
    syn.options.window_scale = None;
    let mut peer_cfg = cfg();
    peer_cfg.pmtud = None;
    let mut b = Connection::passive(reverse(tuple()), peer_cfg, 900, 10, &syn).unwrap();
    deliver(&mut b, &mut a, 20);
    deliver(&mut a, &mut b, 30);
    assert!(!a.scaling && !a.sack_receive);
    (a, b)
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.2
//= type=test
//= reason=Real receiver ACKs resolve full trailing flight before isolated classification; upper bound becomes probe-1 and invalid eff falls to low; second hole preserves bounds. No congestion-suppression claim.
//# In the absence of other indications, set search_high to the probe size minus one. The
//# eff_pmtu might be larger than the probe size if the flow has not been using the full MTU
//# of the path because it is subject to some other limitation, such as available data in an
//# interactive session. If eff_pmtu is larger than the probe size, eff_pmtu MUST be reduced
//# to no larger than search_high, and SHOULD be reduced to search_low, as the eff_pmtu has
//# been determined to be invalid, similar to after a full-stop timeout (see Section 7.7).

//= https://www.rfc-editor.org/rfc/rfc4821#section-10.1
//= type=test
//= reason=Selected non-overlapping real-data probes; actual receiver-generated ACKs exercise multiple smaller gap repairs and prevent crossing the probe boundary.
//# In the non-overlapping method, data is segmented such that the probe and any subsequent
//# segments contain no overlapping data. If the probe is lost, the "probe gap" will be a
//# full probe size minus headers. Data in the probe gap will need to be retransmitted with
//# multiple smaller segments.

//= https://www.rfc-editor.org/rfc/rfc4821#section-4
//= type=test
//= reason=TCP duplicate-ACK recovery reports probe loss; real receiver ACKs distinguish an isolated loss from a second hole beyond the minimum trailing window. This covers a loss-reporting mechanism, not suppression of congestion control.
//# To use PLPMTUD, a Packetization Layer MUST have a loss reporting mechanism that
//# provides the sender with timely and accurate indications of which packets were
//# lost in the network.

//= https://www.rfc-editor.org/rfc/rfc4821#section-6.1
//= type=test
//= reason=The allowed implicit TCP duplicate-ACK mechanism is used in this non-SACK fixture: actual receiver ACKs trigger repairs and distinguish the second hole. SACK is not mandatory in this paragraph.
//# It is best if Packetization Protocols use an explicit loss detection mechanism
//# such as a Selective Acknowledgment (SACK) scoreboard [RFC3517] or ACK Vector
//# [RFC4340] to distinguish real losses from reordered data, although implicit
//# mechanisms such as TCP Reno style duplicate acknowledgments counting are
//# sufficient.

//= https://www.rfc-editor.org/rfc/rfc4821#section-6.1
//= type=test
//= reason=Timeout is not the primary loss detector: real receiver duplicate ACKs trigger probe repair before any timeout in the non-SACK lifecycle test.
//# PLPMTUD can also be implemented in protocols that rely on timeouts as their
//# primary mechanism for loss recovery; however, timeouts SHOULD NOT be used as the
//# primary mechanism for loss indication unless there are no other alternatives.

//= https://www.rfc-editor.org/rfc/rfc4821#section-10.1
//= type=test
//= reason=Non-overlapping segmentation is the selected simple TCP method; the real-receiver lifecycle test already demonstrates bounded multiple gap repairs (164). No additional receiver-evidence gap exists in this choice statement.
//# The choice of which segmentation method to use should be based on what is simplest
//# and most efficient for a given TCP implementation.

fn pmtud_lifecycle_real_repairs_isolated_and_second_hole_beyond_three_mss() {
    for second_hole in [false, true] {
        for iss in [0, u32::MAX - 4000] {
            let (mut a, mut b) = unscaled_pair(iss);
            a.write(b"x").unwrap();
            deliver(&mut a, &mut b, 32);
            deliver(&mut b, &mut a, 33);
            a.write(&[7; 20_000]).unwrap();
            packet(&mut a, 40); // Drop the probe.
            let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
            let before = a.path_mtu_info().unwrap();
            // Send eight trailing packets before feedback. The second hole is
            // beyond the old, fixed three-MSS classification boundary.
            let mut trailing = Vec::new();
            for _ in 0..8 {
                trailing.push(packet(&mut a, 41));
            }
            let trailing_end = a.snd_nxt;
            assert!(after(trailing_end, probe.trailing_end));
            assert_eq!(
                a.pmtud.as_ref().unwrap().probe.unwrap().trailing_end,
                trailing_end
            );
            for (n, bytes) in trailing.iter().enumerate() {
                if second_hole && n == 5 {
                    continue;
                }
                b.input(43, &wire::parse(ip(a.tuple), bytes).unwrap())
                    .unwrap();
                deliver(&mut b, &mut a, 43);
            }
            assert!(a.retx_pending);
            let mut repaired_probe = false;
            for n in 0..16 {
                let now = 50 + n;
                let start = a.snd_una;
                let bytes = deliver(&mut a, &mut b, now);
                let repair = wire::parse(ip(a.tuple), &bytes).unwrap();
                if start.in_window(probe.start, probe.end.distance_from(probe.start)) == Some(true)
                {
                    assert!(repair.payload.len() as u32 <= probe.end.distance_from(start));
                    assert!(bytes.len() + 20 <= before.search_low as usize);
                }
                // Every recovery ACK is generated by the receiver, never injected.
                deliver(&mut b, &mut a, now);
                if !repaired_probe && !after(probe.end, a.snd_una) {
                    repaired_probe = true;
                    if second_hole {
                        assert!(after(a.snd_una, probe.trailing_end));
                        assert!(after(trailing_end, a.snd_una));
                        assert!(a.pmtud.as_ref().unwrap().probe.is_some());
                        assert_eq!(a.path_mtu_info().unwrap(), before);
                    }
                }
                if a.pmtud.as_ref().unwrap().probe.is_none() {
                    break;
                }
            }
            assert!(repaired_probe);
            assert!(a.pmtud.as_ref().unwrap().probe.is_none());
            let info = a.path_mtu_info().unwrap();
            if second_hole {
                assert_eq!(info, before);
            } else {
                assert_eq!(info.search_high, probe.size - 1);
                assert_eq!(info.current_mtu, before.search_low);
            }
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.8
//= type=test
//= reason=Selected verification heuristic tracks retry/original ratio >10% across two RTO intervals, preserves prior verified baseline and restores it after repeated increases. Not empirical multipath validation.
//# Striping in this manner is often operationally undesirable for other reasons (e.g., due
//# to packet reordering) and is usually avoided by hashing each flow to a single path.
//# However, to increase robustness, an implementation SHOULD implement some form of MTU
//# verification, such that if increasing eff_pmtu results in a sharp increase in loss rate,
//# it will fall back to using a lower MTU.

//= https://www.rfc-editor.org/rfc/rfc4821#section-7.8
//= type=test
//= reason=Selected verification heuristic tracks retry/original ratio >10% across two RTO intervals, preserves prior verified baseline and restores it after repeated increases. Not empirical multipath validation.
//# A RECOMMENDED strategy would be to save the value of eff_pmtu before raising it. Then,
//# if loss rate rises above a threshold for a period of time (e.g., loss rate is higher
//# than 10% over multiple retransmission timeout (RTO) intervals), then the new MTU is

//= https://www.rfc-editor.org/rfc/rfc4821#section-7.8
//= type=test
//= reason=Selected verification heuristic tracks retry/original ratio >10% across two RTO intervals, preserves prior verified baseline and restores it after repeated increases. Not empirical multipath validation.
//# considered incorrect. The saved value of eff_pmtu SHOULD be restored, and search_high
//# reduced in the same manner as in a probe failure. PLPMTUD implementations SHOULD
//# implement MTU verification.

//= https://www.rfc-editor.org/rfc/rfc4821#section-2
//= type=test
//= reason=Selected MTU verification observes retry/original loss ratio and restores the prior baseline after repeated increases; no physical multipath experiment is claimed.
//# An optional verification process can be used to detect situations where raising
//# the MTU raises the packet loss rate. For example, if a link is striped across
//# multiple physical channels with inconsistent MTUs, it is possible that a probe
//# will be delivered even if it is too large for some of the physical channels. In
//# such cases, raising the Path MTU to the probe size can cause severe packet loss
//# and abysmal performance. After raising the MTU, the new MTU size can be verified
//# by monitoring the loss rate.

//= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.1
//= type=test
//= reason=MTU verification is implemented and the multi-increase lifecycle test restores the original verified baseline after sustained loss; the same evidence supports 150-152. No size-below-eff test is needed for this verification recommendation.
//# Note that if a flow's packets are routed via multiple paths, or over a path with a
//# non-deterministic MTU, delivery of a single probe packet does not indicate that
//# all packets of that size will be delivered. To be robust in such a case, the
//# Packetization Layer SHOULD conduct MTU verification as described in Section 7.8.

fn pmtud_lifecycle_multi_increase_keeps_verification_baseline_and_loss_evidence() {
    let mut p = crate::pmtud::Pmtud::new(PmtudConfig::new(1500), 1500, true, 600_000_000);
    p.info.current_mtu = 1024;
    let mut seq = Seq(u32::MAX - 1000);
    for (now, size) in [(100, 1240), (1000, 1380), (2000, 1440)] {
        let end = seq.wrapping_add(size - 40);
        p.start_probe(seq, size - 40, 3000, size);
        p.sent(seq, end, size, 20, false);
        p.ack(end, now, 1000, 1000);
        assert_eq!(p.info.current_mtu, size);
        seq = end;
        for _ in 0..4 {
            let end = seq.wrapping_add(size - 40);
            p.sent(seq, end, size, 20, false);
            p.sent(seq, end, size, 20, true); // sustained lossy path, still progressing
            seq = end;
        }
    }
    p.ack(seq, 2100, 1000, 1000);
    assert_eq!(p.info.current_mtu, 1440);
    p.ack(seq, 3999, 1000, 1000);
    assert_eq!(p.info.current_mtu, 1440);
    p.ack(seq, 4000, 1000, 1000);
    assert_eq!(p.info.current_mtu, 1024);
    assert_eq!(p.info.search_low, 1024);
    assert_eq!(p.info.search_high, 1439);
}

#[test]
fn pmtud_lifecycle_increase_on_verification_expiry_requires_new_observation_interval() {
    for prior_loss in [false, true] {
        let mut p = crate::pmtud::Pmtud::new(PmtudConfig::new(1500), 1500, true, 600_000_000);
        p.info.current_mtu = 1024;
        p.start_probe(Seq(0), 1200, 3000, 1240);
        p.sent(Seq(0), Seq(1200), 1240, 20, false);
        p.ack(Seq(1200), 100, 1000, 1000);
        let mut seq = Seq(1200);
        for _ in 0..4 {
            let end = seq.wrapping_add(1200);
            p.sent(seq, end, 1240, 20, false);
            if prior_loss {
                p.sent(seq, end, 1240, 20, true);
            }
            seq = end;
        }
        p.ack(seq, 2000, 1000, 1000);
        assert_eq!(p.info.current_mtu, 1240);
        let end = seq.wrapping_add(1340);
        p.start_probe(seq, 1340, 3000, 1380);
        p.sent(seq, end, 1380, 20, false);
        // This ACK expires the first increase's window and proves a new size.
        p.ack(end, 2100, 1000, 1000);
        seq = end;
        if prior_loss {
            // Restarting observation must not postpone an already-due rollback.
            assert_eq!(p.info.current_mtu, 1024);
            assert_eq!(p.info.search_low, 1024);
            assert_eq!(p.info.search_high, 1379);
            continue;
        }
        assert_eq!(p.info.current_mtu, 1380);
        for n in 0..4 {
            let end = seq.wrapping_add(1340);
            p.sent(seq, end, 1380, 20, false);
            if n < 2 {
                p.sent(seq, end, 1380, 20, true);
            }
            seq = end;
        }
        p.ack(seq, 4099, 1000, 1000);
        assert_eq!(p.info.current_mtu, 1380);
        p.ack(seq, 4100, 1000, 1000);
        assert_eq!(p.info.current_mtu, 1024);
        assert_eq!(p.info.search_low, 1024);
        assert_eq!(p.info.search_high, 1379);
    }
}

fn endpoint_packet(a: &mut Endpoint, now: u64) -> (IpMetadata, Vec<u8>) {
    let mut bytes = vec![0; 2000];
    let tx = a
        .poll_transmit(now, &mut bytes, 16)
        .unwrap()
        .packet
        .unwrap();
    bytes.truncate(tx.len);
    (tx.ip, bytes)
}

#[test]
fn pmtud_lifecycle_endpoint_input_before_due_timeout_preserves_search_timer() {
    let mut a = Endpoint::new(
        EndpointConfig {
            connection: cfg(),
            ..EndpointConfig::default()
        },
        [1; 32],
        0,
        |_| true,
    )
    .unwrap();
    let id = a.connect(0, tuple().local, tuple().remote).unwrap();
    let (meta, bytes) = endpoint_packet(&mut a, 0);
    let syn = wire::parse(meta, &bytes).unwrap();
    let mut peer_cfg = cfg();
    peer_cfg.pmtud = None;
    let mut b = Connection::passive(reverse(tuple()), peer_cfg, 900, 10, &syn).unwrap();
    let bytes = packet(&mut b, 20);
    a.input(20, ip(b.tuple), &bytes).unwrap();
    let (meta, bytes) = endpoint_packet(&mut a, 30);
    b.input(30, &wire::parse(meta, &bytes).unwrap()).unwrap();
    a.write(id, &[1; 1460]).unwrap();
    let (meta, bytes) = endpoint_packet(&mut a, 40);
    let data = wire::parse(meta, &bytes).unwrap();
    assert!(
        a.pmtu_feedback(41, tuple(), data.header.sequence, 1500, 20, 1006)
            .unwrap()
    );
    // Deliver the original and its real ACK; no data timer remains.
    b.input(42, &data).unwrap();
    let ack = packet(&mut b, 43);
    a.input(43, ip(b.tuple), &ack).unwrap();
    let deadline = a.next_deadline().unwrap();
    assert_eq!(deadline, 600_000_041);
    // A duplicate input at the exact deadline must not erase the unconsumed timer.
    a.input(deadline, ip(b.tuple), &ack).unwrap();
    assert_eq!(a.next_deadline(), Some(deadline));
    assert!(!a.on_timeout(deadline, 1).unwrap());
    assert_eq!(a.path_mtu_info(id).unwrap().unwrap().search_high, 1500);
    a.write(id, &[9; 20_000]).unwrap();
    let (_, probe) = endpoint_packet(&mut a, deadline);
    assert!(probe.len() + 20 > 1006);
}

#[test]
fn pmtud_lifecycle_saturated_deadline_is_consumed_once() {
    let (mut a, _) = unscaled_pair(0);
    a.pmtud.as_mut().unwrap().deadline = Some(u64::MAX);
    a.update_time(u64::MAX).unwrap();
    assert_eq!(a.next_deadline(), Some(u64::MAX));
    a.timeout(u64::MAX).unwrap();
    assert_eq!(a.pmtud.as_ref().unwrap().deadline, None);
    assert_eq!(a.next_deadline(), None);
}

#[test]
fn pmtud_lifecycle_detected_trailing_loss_survives_delivery_without_retry() {
    let mut p = crate::pmtud::Pmtud::new(PmtudConfig::new(1500), 1500, true, 600_000_000);
    p.start_probe(Seq(0), 1200, 3000, 1240);
    p.sent(Seq(0), Seq(1200), 1240, 20, false);
    for n in 0..5 {
        p.sent(Seq(1200 + n * 1000), Seq(2200 + n * 1000), 1040, 20, false);
    }
    p.sent(Seq(0), Seq(984), 1024, 20, true);
    let mut before = p.info;
    // Unretried trailing delivery is an implicit probe, independent of the
    // inconclusive explicit probe: only its proven lower bound may change.
    before.search_low = 1040;
    // Detection precedes retransmission. Even if the second hole's original
    // arrives before its repair is emitted, retain the loss classification.
    p.loss(Seq(5200), false);
    p.ack(Seq(5200), 100, 1000, 1000);
    assert!(p.probe.is_some());
    assert_eq!(p.info, before);
    p.ack(Seq(6200), 110, 1000, 1000);
    assert!(p.probe.is_none());
    assert_eq!(p.info, before);
}

#[test]
fn pmtud_lifecycle_local_rejection_invalidates_only_latest_evidence_without_loss() {
    let mut p = crate::pmtud::Pmtud::new(PmtudConfig::new(1500), 1500, true, 600_000_000);
    p.sent(Seq(0), Seq(1460), 1500, 20, false);
    p.start_probe(Seq(1460), 1200, 3000, 1240);
    p.sent(Seq(1460), Seq(2660), 1240, 20, false);
    let before = p.info;
    assert!(!p.reject_latest(Seq(0), Seq(1460)));
    assert!(p.probe.is_some());
    assert!(p.reject_latest(Seq(1460), Seq(2660)));
    assert!(!p.reject_latest(Seq(1460), Seq(2660)));
    assert!(p.probe.is_none());
    assert_eq!(p.info, before);
    assert_eq!(p.deadline, None);
    assert!(!p.feedback(10, Seq(1460), 1240, 20, 1006));
    assert!(p.feedback(10, Seq(0), 1500, 20, 1006)); // earlier real output survives

    for rejected_retry in [false, true] {
        let mut p = crate::pmtud::Pmtud::new(PmtudConfig::new(1500), 1500, true, 600_000_000);
        p.info.current_mtu = 1024;
        p.start_probe(Seq(0), 1200, 3000, 1240);
        p.sent(Seq(0), Seq(1200), 1240, 20, false);
        p.ack(Seq(1200), 100, 1000, 1000);
        let originals = if rejected_retry { 10 } else { 9 };
        for n in 1..=originals {
            p.sent(Seq(n * 1200), Seq((n + 1) * 1200), 1240, 20, false);
        }
        p.sent(Seq(1200), Seq(2400), 1240, 20, true);
        p.sent(Seq(2400), Seq(3600), 1240, 20, rejected_retry);
        assert!(p.reject_latest(Seq(2400), Seq(3600)));
        p.ack(Seq(13_200), 2100, 1000, 1000);
        // Remove exactly the rejected attempt from the >10% loss test;
        // neither erase prior loss nor reset the pending baseline/start time.
        assert_eq!(p.info.current_mtu, if rejected_retry { 1240 } else { 1024 });
    }
}
