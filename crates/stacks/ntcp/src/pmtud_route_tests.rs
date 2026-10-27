use super::*;

fn state() -> Pmtud {
    Pmtud::new(PmtudConfig::new(1500), 1500, true, 600_000_000).unwrap()
}

#[test]
fn route_ceiling_preserves_ptb_limit_and_hold_even_when_bounds_coincide() {
    for rejected_mtu in [600, 1280] {
        let mut p = state();
        p.sent(Seq(1), Seq(1461), 1500, 20, false);
        assert!(p.feedback(10, Seq(1), 1500, 20, rejected_mtu));
        let hold = p.deadline;
        p.set_route_mtu(Some(500));
        assert_eq!(p.info.search_high, 500);
        p.set_route_mtu(Some(rejected_mtu));
        p.set_route_mtu(None);
        assert_eq!(p.info.search_high, rejected_mtu);
        assert_eq!(p.info.current_mtu, 500);
        assert_eq!(p.deadline, hold);
        assert_eq!(p.target(), None);
        p.set_route_mtu(None); // An idempotent update cannot rearm/release a timer.
        assert_eq!(p.deadline, hold);
        p.tick(hold.unwrap() - 1);
        assert_eq!(p.target(), None);
        p.tick(hold.unwrap());
        assert_eq!(p.info.search_high, 1500);
        assert!(p.target().unwrap() <= 1500);
        assert_eq!(p.info.current_mtu, 500);
    }
}

#[test]
fn route_ceiling_retains_failed_probe_limit_after_cooldown() {
    let mut p = state();
    p.info.current_mtu = 1024;
    p.start_probe(Seq(0), 1200, 3000, 1240);
    p.sent(Seq(0), Seq(1200), 1240, 20, false);
    p.sent(Seq(0), Seq(1200), 1024, 20, true);
    p.ack(Seq(4200), 100, 1000, 1000);
    assert_eq!(p.info.search_high, 1239);
    let hold = p.deadline;
    p.set_route_mtu(Some(700));
    p.set_route_mtu(None);
    assert_eq!(p.info.search_high, 1239);
    assert_eq!(p.deadline, hold);
    assert_eq!(p.target(), None);
    p.tick(hold.unwrap());
    assert_eq!(p.info.search_high, 1239); // Failure cooldown does not erase evidence.
    p.set_route_mtu(Some(1239));
    p.set_route_mtu(Some(1500));
    assert_eq!(p.info.search_high, 1239);
    assert!(p.target().unwrap() <= 1239);
    assert_eq!(p.info.current_mtu, 700);
}

#[test]
fn route_ceiling_preserves_timeout_and_deferred_ptb_hold() {
    let mut p = state();
    p.start_probe(Seq(0), 1200, 3000, 1240);
    p.sent(Seq(0), Seq(1200), 1240, 20, false);
    p.timeout(100, Seq(0), 1, 1000);
    assert_eq!(p.deadline, Some(5100));
    p.set_route_mtu(Some(700));
    p.set_route_mtu(None);
    assert_eq!(p.deadline, Some(5100));
    assert_eq!(p.target(), None);

    let mut p = state();
    p.sent(Seq(0), Seq(1460), 1500, 20, false);
    p.ack(Seq(1460), 10, 1000, 1000);
    p.sent(Seq(1460), Seq(2920), 1500, 20, false);
    assert!(p.feedback(20, Seq(1460), 1500, 20, 1200));
    let pending = p.pending;
    let hold = p.deadline;
    p.set_route_mtu(Some(700));
    p.set_route_mtu(None);
    assert_eq!(p.pending, pending);
    assert_eq!(p.deadline, hold);
    p.timeout(30, Seq(1460), 1, 1000);
    assert_eq!(p.info.search_high, 1200);
    assert_eq!(p.info.current_mtu, 700);
    assert_eq!(p.target(), None);
}

#[test]
fn route_decrease_cancels_probe_classification_not_repair_or_late_ack_progress() {
    for start in [Seq(1), Seq(u32::MAX - 499)] {
        let mut p = state();
        p.info.current_mtu = 1024;
        p.start_probe(start, 1200, 3000, 1240);
        let end = start.wrapping_add(1200);
        p.sent(start, end, 1240, 20, false);
        p.set_route_mtu(Some(700));
        assert!(p.probe.is_none());
        assert_eq!(p.repair_limit(start, 1460), 1200);
        p.set_route_mtu(None);
        assert_eq!(p.target(), None); // Outstanding repair boundary still holds.
        p.ack(end, 10, 1000, 1000);
        assert_eq!(p.info.current_mtu, 700); // Old probe ACK cannot restore old MTU.
        assert_eq!(p.info.search_low, 700);
        assert!(p.repair_range.is_none());
        assert!(p.target().is_some());
    }
}

#[test]
fn route_increase_keeps_inflight_probe_valid_on_same_path() {
    let mut c = PmtudConfig::new(1500);
    c.route_mtu = Some(1300);
    c.initial_mtu = Some(1100);
    let mut p = Pmtud::new(c, 1500, true, 600_000_000).unwrap();
    p.start_probe(Seq(1), 1160, 3000, 1200);
    p.sent(Seq(1), Seq(1161), 1200, 20, false);
    p.set_route_mtu(None);
    assert!(p.probe.is_some());
    assert_eq!(p.info.current_mtu, 1100);
    p.ack(Seq(1161), 10, 1000, 1000);
    assert_eq!(p.info.current_mtu, 1200);
}

#[test]
fn route_ceiling_never_overrides_interface_or_creation_ceiling() {
    let mut c = PmtudConfig::new(1500);
    c.initial_search_high = Some(1400);
    let mut p = Pmtud::new(c, 1500, true, 600_000_000).unwrap();
    p.set_route_mtu(Some(700));
    p.set_route_mtu(Some(9000));
    assert_eq!(p.info.search_high, 1400);
    assert_eq!(p.info.first_hop_mtu, 1500);
    assert_eq!(p.info.current_mtu, 700);
    p.link(1300, 1300, 1);
    p.set_route_mtu(None);
    assert_eq!(p.info.search_high, 1300);
    assert_eq!(p.info.current_mtu, 700);
}

#[test]
fn route_policy_decrease_does_not_turn_verification_into_network_loss() {
    let mut p = state();
    p.info.current_mtu = 1024;
    p.start_probe(Seq(0), 1200, 3000, 1240);
    p.sent(Seq(0), Seq(1200), 1240, 20, false);
    p.ack(Seq(1200), 10, 1000, 1000);
    assert!(p.verification.is_some());
    p.set_route_mtu(Some(1100));
    assert!(p.verification.is_none());
    assert!(p.discovered_high.is_none());
    p.set_route_mtu(None);
    assert_eq!(p.info.current_mtu, 1100);
    assert_eq!(p.info.search_high, 1500);
}

#[test]
fn route_unclipping_restores_work_without_resetting_network_evidence() {
    let mut c = PmtudConfig::new(1500);
    c.route_mtu = Some(640);
    let mut p = Pmtud::new(c, 1500, true, 600_000_000).unwrap();
    p.ack(Seq(0), 10, 1000, 1000); // Converged solely at the route ceiling.
    assert!(p.periodic_deadline.is_some());
    p.set_route_mtu(None);
    assert_eq!(p.info.current_mtu, 640);
    assert_eq!(p.info.search_high, 1500);
    assert!(p.periodic_deadline.is_none());
    assert!(p.target().unwrap() > 640);
}

#[test]
fn route_ceiling_preserves_ipv6_ptb_hold_and_family_floor() {
    let mut p = Pmtud::new(PmtudConfig::new(1500), 1500, false, 600_000_000).unwrap();
    p.sent(Seq(1), Seq(1441), 1500, 40, false);
    assert!(p.feedback(10, Seq(1), 1500, 40, 1400));
    let deadline = p.deadline.unwrap();
    p.set_route_mtu(Some(1280));
    p.set_route_mtu(None);
    assert_eq!(p.info.current_mtu, 1280);
    assert_eq!(p.info.search_high, 1400);
    assert_eq!(p.deadline, Some(deadline));
    p.tick(deadline - 1);
    assert_eq!(p.target(), None);
    p.tick(deadline);
    assert_eq!(p.info.current_mtu, 1280);
    assert_eq!(p.info.search_high, 1500);
    assert_eq!(p.target(), Some(1390));
}

#[test]
fn local_link_decrease_cannot_invent_network_limit_for_clipped_size() {
    let mut p = state();
    p.info.current_mtu = 1024;
    p.start_probe(Seq(0), 1200, 3000, 1240);
    p.sent(Seq(0), Seq(1200), 1240, 20, false);
    p.ack(Seq(1200), 10, 1000, 1000);
    assert!(p.verification.is_some());
    // Loss counters belong to the previous larger packetization, not to640.
    for n in 1..=3 {
        let start = Seq(n * 1200);
        p.sent(start, start.wrapping_add(1200), 1240, 20, false);
        p.sent(start, start.wrapping_add(1200), 1240, 20, true);
    }
    p.link(640, 640, 20);
    assert!(p.verification.is_none());
    p.ack(Seq(4800), 3000, 1000, 1000);
    assert_eq!(p.info.current_mtu, 640);
    assert!(p.discovered_high.is_none());
    p.link(1500, 1500, 3001);
    p.set_route_mtu(Some(640));
    p.set_route_mtu(None);
    assert_eq!(p.info.search_high, 1500); // No spurious639-byte network ceiling.
    assert_eq!(p.info.current_mtu, 640);
}
