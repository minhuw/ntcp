use super::*;

fn controller(recovery: RecoveryAlgorithm, mss: u32) -> Congestion {
    Congestion::new(mss, recovery, InitialWindow::Iw10, Seq(u32::MAX))
        .with_congestion(CongestionAlgorithm::Cubic, CallerTimebase::default())
}

#[test]
fn cubic_selection_is_independent_and_default_is_unchanged() {
    assert_eq!(CongestionAlgorithm::default(), CongestionAlgorithm::Reno);
    for recovery in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
        let mut cubic = controller(recovery, 1000);
        let mut reno = Congestion::new(1000, recovery, InitialWindow::Iw10, Seq(u32::MAX));
        for c in [&mut cubic, &mut reno] {
            for _ in 0..2 {
                assert!(!c.on_duplicate_ack(Seq(1), 10_000, Seq(10_001), false));
            }
            assert!(c.on_duplicate_ack(Seq(1), 10_000, Seq(10_001), false));
        }
        assert_eq!((cubic.ssthresh, cubic.cwnd), (7000, 10_000));
        assert_eq!((reno.ssthresh, reno.cwnd), (5000, 8000));
        assert_eq!(
            cubic.on_ack(Seq(1001), 1000, 9000),
            recovery == RecoveryAlgorithm::NewReno
        );
        assert_eq!(
            cubic.cwnd,
            if recovery == RecoveryAlgorithm::Reno {
                7000
            } else {
                10_000
            }
        );
        // No CUBIC-only recovery exit override: NewReno's option (1) cap stays.
        assert!(!cubic.on_ack(Seq(10_001), 9000, 0));
        assert_eq!(
            cubic.cwnd,
            if recovery == RecoveryAlgorithm::Reno {
                7000
            } else {
                2000
            }
        );
    }
}

#[test]
fn cubic_ecn_loss_tlp_and_rto_share_existing_epoch_guards() {
    for recovery in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
        for base in [Seq(1), Seq(u32::MAX - 4999)] {
            let end = base.wrapping_add(10_000);
            let mut c = controller(recovery, 1000);
            assert!(c.on_ecn(base, 10_000, end));
            assert_eq!((c.cwnd, c.ssthresh), (7000, 7000));
            assert!(!c.on_ecn(end, 7000, end));
            // Real loss still enters recovery but shares the ECN reduction.
            assert!(c.on_sack_recovery(base, 7000, end));
            assert_eq!(c.ssthresh, 7000);
            c.on_timeout(7000, end);
            assert_eq!((c.cwnd, c.ssthresh), (1000, 7000));
            c.on_timeout(3000, end);
            assert_eq!(c.ssthresh, 7000);

            let mut c = controller(recovery, 1000);
            assert!(c.on_tlp_repair(base, 10_000, end));
            assert_eq!((c.cwnd, c.ssthresh), (7000, 7000));
            assert!(!c.on_tlp_repair(base, 10_000, end));
            assert!(c.on_sack_recovery(base, 10_000, end));
            assert_eq!(c.ssthresh, 7000);
            c.on_retransmit(base.wrapping_add(1000));
            c.on_timeout(10_000, end);
            assert_eq!((c.cwnd, c.ssthresh), (1000, 4900));
            c.on_timeout(2000, end);
            assert_eq!(c.ssthresh, 4900);

            let mut c = controller(recovery, 1000);
            c.on_timeout(10_000, end);
            assert_eq!((c.cwnd, c.ssthresh), (1000, 7000));
            c.on_timeout(2000, end);
            assert_eq!(c.ssthresh, 7000);
            c.on_ack(end, 10_000, 0);
            c.on_timeout(20_000, end.wrapping_add(20_000));
            assert_eq!((c.cwnd, c.ssthresh), (1000, 14_000));
        }
    }
}

#[test]
fn cubic_ecn_one_mss_floor_no_ece_growth_and_idle_restart() {
    let mut c = controller(RecoveryAlgorithm::NewReno, 1000);
    let mut ack = Seq(1);
    let mut flight = 10_000;
    for _ in 0..10 {
        let end = ack.wrapping_add(flight);
        c.on_data_sent(0, flight, end, false);
        assert!(c.on_ecn(ack, flight, end));
        assert!(c.cwnd >= 1000 && c.ssthresh >= 2000);
        let before = c.cwnd;
        c.prepare_ack(1, Some(1), end, flight, MAX_WINDOW);
        c.on_ack_with_ecn(end, flight, 0, true);
        assert_eq!(c.cwnd, before);
        ack = end.wrapping_add(1);
        flight = c.cwnd;
    }
    assert_eq!((c.cwnd, c.ssthresh), (1000, 2000));
    c.restart_after_idle();
    assert_eq!(c.cwnd, 1000);
}

#[test]
fn cubic_mss_byte_bounds_and_growth_protection() {
    let mut c = controller(RecoveryAlgorithm::NewReno, 1000);
    c.on_timeout(10_000, Seq(10_001));
    c.set_mss(500);
    assert_eq!((c.cwnd, c.ssthresh), (500, 3500));
    c.set_mss(1000);
    assert_eq!((c.cwnd, c.ssthresh), (1000, 3500));
    c.prepare_ack(100, Some(100), Seq(1001), 1000, MAX_WINDOW);
    c.on_ack(Seq(1001), 1000, 0);
    assert_eq!(c.cwnd, 1000); // No committed output validating a full window.
    c.on_data_sent(200, 1000, Seq(2001), false);
    c.prepare_ack(300, Some(100), Seq(2001), 1000, MAX_WINDOW);
    c.on_ack(Seq(2001), 1000, 0);
    assert_eq!(c.cwnd, 2000);
    c.restart_after_idle();
    assert_eq!(c.cwnd, 2000); // Restart never increases the reduced window.
    for mss in [1, 1000, u32::MAX] {
        let mut c = controller(RecoveryAlgorithm::Reno, mss);
        c.on_data_sent(u64::MAX - 1, u32::MAX, Seq(u32::MAX), false);
        c.prepare_ack(
            u64::MAX,
            Some(u64::MAX),
            Seq(u32::MAX),
            u32::MAX,
            MAX_WINDOW,
        );
        c.on_ack(Seq(u32::MAX), u32::MAX, 0);
        c.on_timeout(u32::MAX, Seq(0));
        c.set_mss(u32::MAX);
        assert_eq!((c.cwnd, c.ssthresh), (MAX_WINDOW, MAX_WINDOW));
    }
}
