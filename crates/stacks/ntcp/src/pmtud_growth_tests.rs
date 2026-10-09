use super::*;
use crate::{PmtudConfig, pmtud::Pmtud};

fn growth_pair(ipv4: bool, iss: u32, mtu: Option<u32>) -> (Connection, Connection) {
    let cfg = ConnectionConfig {
        pmtud: mtu.map(PmtudConfig::new),
        initial_window: InitialWindow::Iw10,
        nagle: false,
        timestamps: false,
        sack: false,
        delayed_ack_us: 0,
        ..config(65_536, 1460)
    };
    let tuple = if ipv4 {
        tuple()
    } else {
        Tuple {
            local: "[2001:db8::1]:1000".parse().unwrap(),
            remote: "[2001:db8::2]:2000".parse().unwrap(),
        }
    };
    let mut a = Connection::active(tuple, cfg.clone(), iss, 0).unwrap();
    let bytes = packet(&mut a, 0);
    let syn = wire::parse(ip(tuple), &bytes).unwrap();
    let mut peer = cfg;
    peer.pmtud = None;
    let mut b = Connection::passive(reverse(tuple), peer, 900, 10, &syn).unwrap();
    deliver(&mut b, &mut a, 20);
    deliver(&mut a, &mut b, 30);
    (a, b)
}

//= https://www.rfc-editor.org/rfc/rfc4821#section-7.1
//= type=test
//= reason=Pmtud::ack raises search_low only from fully cumulatively acknowledged, unambiguous ordinary sent packets within effective MTU, search_high and path bounds; explicit-probe overlap retains separate timeout/verification rules. Tests from 742e320 cover real ordinary ACKs in both families/wrap, retry ambiguity, partial ACK, local rejection, PTB/link ceilings, stale quotes, holdoff and probe timeout. Ordinary loss does not enter explicit probe-failure handling; mixed ordinary/explicit success preserves larger ordinary proof.
//# If eff_pmtu is larger than search_low, it is explicitly permitted to send
//# non-probe packets larger than search_low. When such a packet is acknowledged, it
//# is effectively an "implicit probe" and search_low SHOULD be raised to the size
//# of the acknowledged packet. However, if an "implicit probe" is lost, it MUST NOT
//# be treated as a probe failure as a true probe would be. If eff_pmtu is too
//# large, this condition will only be detected with ICMP PTB messages or black hole
//# discovery (see Section 7.7).

#[test]
fn pmtud_growth_ordinary_wire_ack_with_trailing_flight_and_legacy() {
    for ipv4 in [true, false] {
        for iss in [100, u32::MAX - 1000] {
            for enabled in [true, false] {
                let (mut a, mut b) = growth_pair(ipv4, iss, enabled.then_some(1500));
                let mss = a.mss;
                a.write(&vec![7; 2 * mss]).unwrap();
                let first = packet(&mut a, 40);
                let tail = packet(&mut a, 41);
                assert!(a.pmtud.as_ref().is_none_or(|p| p.probe.is_none()));
                let before = a.path_mtu_info();
                let window = a.congestion.cwnd();
                b.input(42, &wire::parse(ip(a.tuple), &first).unwrap())
                    .unwrap();
                deliver(&mut b, &mut a, 43);
                assert_eq!(a.flight(), mss as u32);
                assert!(!a.retx_pending);
                assert_eq!(a.transmit(44, &mut [0; 1600]), Ok(None));
                if enabled {
                    let info = a.path_mtu_info().unwrap();
                    assert_eq!(
                        info.search_low,
                        first.len() as u32 + if ipv4 { 20 } else { 40 }
                    );
                    assert!(info.search_low > before.unwrap().search_low);
                    assert_eq!(info.current_mtu, before.unwrap().current_mtu);
                    assert_eq!(info.search_high, before.unwrap().search_high);
                    assert!(a.pmtud.as_ref().unwrap().next_deadline().is_some());
                } else {
                    assert_eq!(a.path_mtu_info(), None);
                }
                // Normal ACK growth is distinct from an MTU-only window change.
                assert_eq!(a.congestion.cwnd(), window + mss as u32);
                assert_eq!(a.mss, mss);
                b.input(45, &wire::parse(ip(a.tuple), &tail).unwrap())
                    .unwrap();
                deliver(&mut b, &mut a, 46);
                assert_eq!(a.flight(), 0);
            }
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc1191#section-6.3
//= type=test
//= reason=Connection::set_path_mss creates retx_pending/SYN retry work only on decreases; growth leaves legitimate pending work and timers intact. Tests from 742e320 exercise MSS-only growth with remaining flight and no output, actual RTO retry preservation, SYN work, and real upward-probe ACKs followed by new data rather than trailing-byte retransmission (both families and wrap).
//# An upper layer MUST not retransmit datagrams in response to an increase in the
//# PMTU estimate, since this increase never comes in response to an indication of a
//# dropped datagram.

#[test]
fn pmtud_growth_real_probe_ack_does_not_retry_trailing_bytes() {
    for ipv4 in [true, false] {
        for iss in [100, u32::MAX - 1500] {
            let initial = if ipv4 { 1100 } else { 1280 };
            let (mut a, mut b) = growth_pair(ipv4, iss, Some(initial));
            a.set_first_hop_mtu(31, 1500).unwrap();
            let now = a.pmtud.as_ref().unwrap().next_deadline().unwrap();
            a.timeout(now).unwrap();
            a.write(&[7; 20_000]).unwrap();
            let first = packet(&mut a, now + 1);
            let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
            let tail = packet(&mut a, now + 2);
            let next = a.snd_nxt;
            let old_mss = a.mss;
            let window = a.congestion.cwnd();
            let threshold = a.congestion.ssthresh();
            assert_eq!(first.len() as u32 + if ipv4 { 20 } else { 40 }, probe.size);
            b.input(now + 3, &wire::parse(ip(a.tuple), &first).unwrap())
                .unwrap();
            deliver(&mut b, &mut a, now + 4);
            assert!(a.mss > old_mss);
            assert_eq!(a.path_mtu_info().unwrap().search_low, probe.size);
            assert_eq!(a.path_mtu_info().unwrap().current_mtu, probe.size);
            assert!(a.flight() > 0);
            assert!(!a.retx_pending);
            assert_eq!(a.congestion.cwnd(), window + a.mss as u32);
            assert_eq!(a.congestion.ssthresh(), threshold);
            let output = packet(&mut a, now + 5);
            let segment = wire::parse(ip(a.tuple), &output).unwrap();
            assert_eq!(segment.header.sequence, next.0); // New data, not the tail again.
            assert_eq!(
                wire::parse(ip(a.tuple), &tail).unwrap().header.sequence,
                probe.end.0
            );
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc1191#section-6.3
//= type=test
//= reason=Connection::set_path_mss creates retx_pending/SYN retry work only on decreases; growth leaves legitimate pending work and timers intact. Tests from 742e320 exercise MSS-only growth with remaining flight and no output, actual RTO retry preservation, SYN work, and real upward-probe ACKs followed by new data rather than trailing-byte retransmission (both families and wrap).
//# An upper layer MUST not retransmit datagrams in response to an increase in the
//# PMTU estimate, since this increase never comes in response to an indication of a
//# dropped datagram.

#[test]
fn pmtud_growth_mss_changes_preserve_existing_retry_and_syn_work() {
    let (mut a, mut b) = growth_pair(true, 100, Some(1500));
    a.write(&[7; 1460]).unwrap();
    packet(&mut a, 40); // Lost data; RTO creates a real retry obligation.
    let now = a.rto_deadline.unwrap();
    a.timeout(now).unwrap();
    assert!(a.retx_pending);
    let end = a.snd_nxt;
    let deadline = a.rto_deadline;
    a.set_path_mss(1400);
    assert!(a.retx_pending);
    a.set_path_mss(1460);
    assert!(a.retx_pending);
    assert_eq!(a.snd_nxt, end);
    assert_eq!(a.rto_deadline, deadline);
    let repair = deliver(&mut a, &mut b, now + 1);
    assert_eq!(
        wire::parse(ip(a.tuple), &repair).unwrap().header.sequence,
        a.snd_una.0
    );
    deliver(&mut b, &mut a, now + 2);
    assert!(!a.retx_pending);

    a.set_ip_header_len(60);
    a.write(&[8; 1000]).unwrap();
    let original = packet(&mut a, now + 3);
    assert!(!a.retx_pending);
    let deadline = a.rto_deadline;
    let next = a.snd_nxt;
    a.set_ip_header_len(20); // MSS-only growth with unacknowledged wire data.
    assert!(!a.retx_pending);
    assert_eq!(a.snd_nxt, next);
    assert_eq!(a.rto_deadline, deadline);
    assert_eq!(a.transmit(now + 4, &mut [0; 1600]), Ok(None));
    b.input(now + 5, &wire::parse(ip(a.tuple), &original).unwrap())
        .unwrap();
    deliver(&mut b, &mut a, now + 6);
    assert_eq!(a.flight(), 0);

    let mut syn = Connection::active(tuple(), config(4096, 1460), 100, 0).unwrap();
    packet(&mut syn, 0);
    assert!(!syn.syn_pending);
    syn.set_path_mss(1500);
    assert!(!syn.syn_pending);
    syn.set_path_mss(1400);
    assert!(syn.syn_pending);
    syn.set_path_mss(1460);
    assert!(syn.syn_pending);
}

//= https://www.rfc-editor.org/rfc/rfc4821#section-7.1
//= type=test
//= reason=Pmtud::ack raises search_low only from fully cumulatively acknowledged, unambiguous ordinary sent packets within effective MTU, search_high and path bounds; explicit-probe overlap retains separate timeout/verification rules. Tests from 742e320 cover real ordinary ACKs in both families/wrap, retry ambiguity, partial ACK, local rejection, PTB/link ceilings, stale quotes, holdoff and probe timeout. Ordinary loss does not enter explicit probe-failure handling; mixed ordinary/explicit success preserves larger ordinary proof.
//# If eff_pmtu is larger than search_low, it is explicitly permitted to send
//# non-probe packets larger than search_low. When such a packet is acknowledged, it
//# is effectively an "implicit probe" and search_low SHOULD be raised to the size
//# of the acknowledged packet. However, if an "implicit probe" is lost, it MUST NOT
//# be treated as a probe failure as a true probe would be. If eff_pmtu is too
//# large, this condition will only be detected with ICMP PTB messages or black hole
//# discovery (see Section 7.7).

#[test]
fn pmtud_growth_evidence_security_bounds_holdoff_and_probe_timeout() {
    for iss in [100, u32::MAX - 500] {
        let start = Seq(iss);
        let end = start.wrapping_add(1360);
        let state = || Pmtud::new(PmtudConfig::new(1500), 1500, true, 600_000_000);
        for kind in 0..6 {
            let mut p = state();
            p.sent(start, end, 1400, 20, false);
            match kind {
                0 => p.sent(start, start.wrapping_add(984), 1024, 20, true),
                1 => assert!(p.reject_latest(start, end)),
                2 => {
                    assert!(p.feedback(1, start, 1400, 20, 1200));
                }
                3 => p.link(1200, 1200, 1),
                4 => {
                    p.start_probe(start, 1360, 3000, 1400);
                    p.timeout(1, start, 1, 1000);
                }
                5 => {
                    // Partial delivery is not proof of the original packet size.
                    p.ack(end.wrapping_add(u32::MAX), 1, 1000, 1000);
                }
                _ => unreachable!(),
            }
            let before = p.info;
            let deadline = p.deadline;
            if kind == 5 {
                assert_eq!(p.info.search_low, 1024);
                continue;
            }
            p.ack(end, 2, 1000, 1000);
            assert_eq!(p.info, before, "evidence kind {kind}");
            assert_eq!(p.deadline, deadline);
            assert!(!p.feedback(3, start, 1400, 20, 1100)); // ACKed/rejected quote is stale.
        }
        let mut p = state();
        p.sent(start, end, 1400, 20, false);
        p.ack(end, 1, 1000, 1000);
        assert_eq!(p.info.search_low, 1400);
        p.sent(end, end.wrapping_add(1460), 1500, 20, false);
        assert!(p.feedback(2, end, 1500, 20, 1200)); // Below proven delivery: deferred.
        let deadline = p.deadline;
        p.ack(end.wrapping_add(1460), 3, 1000, 1000);
        assert_eq!(p.info.search_low, 1500);
        assert_eq!(p.deadline, deadline); // Ordinary proof cannot bypass PTB holdoff.
        assert!(p.target().is_none());

        let mut p = state();
        let probe_end = start.wrapping_add(1200);
        let tail_end = probe_end.wrapping_add(1360);
        p.start_probe(start, 1200, 1360, 1240);
        p.sent(start, probe_end, 1240, 20, false);
        p.sent(probe_end, tail_end, 1400, 20, false);
        p.ack(tail_end, 1, 1000, 1000);
        // An earlier smaller explicit probe cannot overwrite larger ordinary proof.
        assert_eq!(p.info.search_low, 1400);
        assert_eq!(p.info.current_mtu, 1500);
        assert!(p.probe.is_none());
    }
}

//= https://www.rfc-editor.org/rfc/rfc4821#section-4
//= type=test
//= reason=Enabled PMTUD uses Congestion::set_path_mss: generic MSS unit bookkeeping is retained, but upward changes restore byte cwnd/ssthresh without changing pacing. Tests from 742e320 assert exact no-ACK header-budget growth after real data RTO for Reno and CUBIC, plus a real RTO/recovery/ordinary-ACK/upward-probe trace separating allowed ACK growth from MTU-only threshold inflation. This is not full CUBIC trajectory evidence or closure of unrelated ACK/MSS obligations.
//# Whenever the MTU is raised, the congestion state variables MUST be rescaled so
//# as not to raise the window size in bytes (or data rate in bytes per seconds).

#[test]
fn pmtud_growth_after_loss_preserves_byte_threshold_not_ack_growth() {
    let (mut a, mut b) = growth_pair(true, 100, Some(1100));
    a.write(&vec![7; a.mss]).unwrap();
    packet(&mut a, 40); // A single lost segment makes ssthresh = 2 * old MSS.
    let mut now = a.rto_deadline.unwrap();
    a.timeout(now).unwrap();
    deliver(&mut a, &mut b, now + 1);
    deliver(&mut b, &mut a, now + 2);
    assert_eq!(a.congestion.ssthresh(), 2120);
    now += 3;
    a.set_first_hop_mtu(now, 1500).unwrap();
    // Real delivery grows cwnd past probe admission; ssthresh remains low.
    for _ in 0..40 {
        now += 10;
        a.write(&vec![7; a.mss]).unwrap();
        deliver(&mut a, &mut b, now);
        deliver(&mut b, &mut a, now + 1);
    }
    assert!(a.congestion.cwnd() > 5000);
    assert_eq!(a.congestion.ssthresh(), 2120);
    now = a.pmtud.as_ref().unwrap().next_deadline().unwrap();
    a.timeout(now).unwrap();
    a.write(&[7; 20_000]).unwrap();
    let bytes = packet(&mut a, now + 1);
    let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
    packet(&mut a, now + 2); // Leave trailing bytes outstanding.
    let mut ack_only = a.congestion.clone();
    let threshold = a.congestion.ssthresh();
    let window = a.congestion.cwnd();
    b.input(now + 3, &wire::parse(ip(a.tuple), &bytes).unwrap())
        .unwrap();
    deliver(&mut b, &mut a, now + 4);
    // Compare with ordinary congestion ACK processing at the new MSS,
    // starting from exactly the same byte window/threshold.
    let mut generic = ack_only.clone();
    generic.set_mss(a.mss as u32);
    assert_eq!(generic.ssthresh(), 2520); // Measured pre-fix MTU-only clamp.
    ack_only.set_path_mss(a.mss as u32);
    assert_eq!(ack_only.cwnd(), window);
    assert_eq!(ack_only.ssthresh(), threshold);
    ack_only.on_ack(
        probe.end,
        probe.end.distance_from(probe.start),
        a.data_flight(),
    );
    assert_eq!(a.congestion.ssthresh(), threshold);
    assert_eq!(a.congestion.cwnd(), ack_only.cwnd());
    assert!(!a.retx_pending);
}

//= https://www.rfc-editor.org/rfc/rfc4821#section-4
//= type=test
//= reason=Enabled PMTUD uses Congestion::set_path_mss: generic MSS unit bookkeeping is retained, but upward changes restore byte cwnd/ssthresh without changing pacing. Tests from 742e320 assert exact no-ACK header-budget growth after real data RTO for Reno and CUBIC, plus a real RTO/recovery/ordinary-ACK/upward-probe trace separating allowed ACK growth from MTU-only threshold inflation. This is not full CUBIC trajectory evidence or closure of unrelated ACK/MSS obligations.
//# Whenever the MTU is raised, the congestion state variables MUST be rescaled so
//# as not to raise the window size in bytes (or data rate in bytes per seconds).

#[test]
fn pmtud_growth_header_budget_does_not_inflate_post_rto_byte_windows() {
    for algorithm in [CongestionAlgorithm::Reno, CongestionAlgorithm::Cubic] {
        let cfg = ConnectionConfig {
            pmtud: Some(PmtudConfig::new(1500)),
            congestion_algorithm: algorithm,
            initial_window: InitialWindow::Iw10,
            nagle: false,
            ..config(65_536, 1460)
        };
        let (mut a, _) = pair(cfg, 100);
        a.set_ip_header_len(60);
        a.write(&vec![7; a.mss]).unwrap();
        packet(&mut a, 40);
        let now = a.rto_deadline.unwrap();
        a.timeout(now).unwrap();
        let window = a.congestion.cwnd();
        let threshold = a.congestion.ssthresh();
        assert_eq!(window, a.mss as u32);
        assert_eq!(threshold, 2 * window);
        assert!(a.retx_pending);
        // Removing IP options increases the path payload budget, without an ACK.
        a.set_ip_header_len(20);
        assert_eq!(a.mss as u32, window + 40);
        assert_eq!(a.congestion.cwnd(), window);
        assert_eq!(a.congestion.ssthresh(), threshold);
        assert!(a.retx_pending);
    }
}
