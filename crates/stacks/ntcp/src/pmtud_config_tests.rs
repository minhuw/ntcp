use super::*;
use crate::{Ipv4Plateaus, PmtudConfig, PmtudPolicy, SearchAging, pmtud::Pmtud};

fn policy(aging: SearchAging) -> PmtudPolicy {
    PmtudPolicy {
        search_aging: aging,
        ..PmtudPolicy::default()
    }
}

fn settings() -> ConnectionConfig {
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

fn family_tuple(ipv4: bool) -> Tuple {
    if ipv4 {
        tuple()
    } else {
        Tuple {
            local: "[2001:db8::1]:1000".parse().unwrap(),
            remote: "[2001:db8::2]:2000".parse().unwrap(),
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.2
//= type=test
//= reason=Reviewed 0030a96: independent creation-only initial_search_low is validated with initial_mtu/initial_search_high, family and allocation bounds. Defaults remain conservative IPv4 min(mtu,1024) and IPv6 min(mtu,1280); dual-family tests assert defaults, independent overrides, rejection rather than silent clamping, and subsequent peer caps. Per-route policy remains open at 071/119.
//# It is RECOMMENDED that search_low be initially set to an MTU size that is likely
//# to work over a very wide range of environments. Given today's technologies, a
//# value of 1024 bytes is probably safe enough. The initial value for search_low
//# SHOULD be configurable.

fn pmtud_config_initial_bounds_defaults_and_independent_overrides() {
    for ipv4 in [true, false] {
        let low = if ipv4 { 1024 } else { 1280 };
        for field in 0..4 {
            let mut cfg = settings();
            let p = cfg.pmtud.as_mut().unwrap();
            match field {
                1 => p.initial_mtu = Some(1350),
                2 => p.initial_search_low = Some(1300),
                3 => p.initial_search_high = Some(1400),
                _ => {}
            }
            let a = Connection::active(family_tuple(ipv4), cfg, 0, 0).unwrap();
            let info = a.path_mtu_info().unwrap();
            assert_eq!(
                info.current_mtu,
                if field == 1 {
                    1350
                } else if field == 3 {
                    1400
                } else {
                    1500
                }
            );
            assert_eq!(info.search_low, if field == 2 { 1300 } else { low });
            assert_eq!(info.search_high, if field == 3 { 1400 } else { 1500 });
            assert_eq!(a.config.mss, 1460);
            assert!(a.mss <= (info.current_mtu - if ipv4 { 40 } else { 60 }) as usize);
        }
        let mut cfg = settings();
        let p = cfg.pmtud.as_mut().unwrap();
        p.initial_mtu = Some(1320);
        p.initial_search_low = Some(1300);
        p.initial_search_high = Some(1400);
        let mut a = Connection::active(family_tuple(ipv4), cfg, 0, 0).unwrap();
        let cwnd = a.congestion.cwnd();
        a.set_first_hop_mtu(1, 9000).unwrap();
        a.timeout(600_000_001).unwrap();
        assert_eq!(a.path_mtu_info().unwrap().search_high, 1400);
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, 1320);
        assert_eq!(a.congestion.cwnd(), cwnd);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.2
//= type=test
//= reason=Reviewed 0030a96: independent creation-only initial_search_low is validated with initial_mtu/initial_search_high, family and allocation bounds. Defaults remain conservative IPv4 min(mtu,1024) and IPv6 min(mtu,1280); dual-family tests assert defaults, independent overrides, rejection rather than silent clamping, and subsequent peer caps. Per-route policy remains open at 071/119.
//# It is RECOMMENDED that search_low be initially set to an MTU size that is likely
//# to work over a very wide range of environments. Given today's technologies, a
//# value of 1024 bytes is probably safe enough. The initial value for search_low
//# SHOULD be configurable.

fn pmtud_config_invalid_explicit_values_are_not_silently_clamped() {
    for ipv4 in [true, false] {
        let floor = if ipv4 { 68 } else { 1280 };
        for field in 0..3 {
            for invalid in [0, floor - 1, 1501, u32::MAX] {
                let mut cfg = settings();
                let p = cfg.pmtud.as_mut().unwrap();
                match field {
                    0 => p.initial_mtu = Some(invalid),
                    1 => p.initial_search_low = Some(invalid),
                    _ => p.initial_search_high = Some(invalid),
                }
                assert_eq!(cfg.validate(ipv4), Err(Error::InvalidArgument));
            }
        }
        for (low, mtu, high) in [(1400, 1300, 1500), (1300, 1500, 1400)] {
            let mut cfg = settings();
            let p = cfg.pmtud.as_mut().unwrap();
            p.initial_search_low = Some(low);
            p.initial_mtu = Some(mtu);
            p.initial_search_high = Some(high);
            assert_eq!(cfg.validate(ipv4), Err(Error::InvalidArgument));
        }
        for allocation in [true, false] {
            let mut cfg = settings();
            if allocation {
                cfg.mss = 1300;
            } else {
                cfg.send_ip_payload_limit = 1320;
            }
            assert!(cfg.validate(ipv4).is_ok()); // Defaults clamp to the allocation.
            cfg.pmtud.as_mut().unwrap().initial_mtu = Some(1400);
            assert_eq!(cfg.validate(ipv4), Err(Error::InvalidArgument));
        }
        let mut cfg = settings();
        cfg.pmtud.as_mut().unwrap().first_hop_mtu = if ipv4 { 65536 } else { 65576 };
        assert_eq!(cfg.validate(ipv4), Err(Error::InvalidArgument));
    }
}

#[test]
fn pmtud_config_peer_caps_apply_to_defaults_and_explicit_initial_settings() {
    for ipv4 in [true, false] {
        for explicit in [true, false] {
            let mut cfg = settings();
            if explicit {
                let p = cfg.pmtud.as_mut().unwrap();
                p.initial_mtu = Some(1400);
                p.initial_search_low = Some(1300);
                p.initial_search_high = Some(1450);
            }
            let t = family_tuple(ipv4);
            let mut a = Connection::active(t, cfg.clone(), 0, 0).unwrap();
            let syn = packet(&mut a, 0);
            cfg.pmtud = None;
            cfg.mss = 536;
            let mut b =
                Connection::passive(reverse(t), cfg, 900, 10, &wire::parse(ip(t), &syn).unwrap())
                    .unwrap();
            deliver(&mut b, &mut a, 20);
            deliver(&mut a, &mut b, 30);
            assert_eq!(a.mss, 536);
            let info = a.path_mtu_info().unwrap();
            assert_eq!(info.current_mtu, if ipv4 { 576 } else { 1280 });
            assert_eq!(info.search_low, info.current_mtu);
            assert_eq!(info.search_high, info.current_mtu);
            assert_eq!(a.config.mss, 1460);
            a.write(&[7; 2000]).unwrap();
            assert!(
                wire::parse(ip(t), &packet(&mut a, 40))
                    .unwrap()
                    .payload
                    .len()
                    <= 536
            );
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.3
//= type=test
//= reason=Reviewed 0030a96: PmtudPolicy exposes SearchAging::Seconds (validated >=300 with checked caller-timebase conversion) and Infinity through creation and live Endpoint::set_pmtud_policy. Tests exercise finite rearming, disabled periodic aging and both families retaining independent mandatory 600-second PTB hold and failure cooldown. No route/cache or socket-parser integration is claimed.
//# Note: an implementation should provide a means for changing the timeout
//# duration, including setting it to "infinity". For example, hosts attached to an
//# FDDI network which is then attached to the rest of the Internet via a slow
//# serial line are never going to discover a new non-local PMTU, so they should not
//# have to put up with dropped datagrams every 10 minutes.

//= https://www.rfc-editor.org/rfc/rfc1191#section-6.6
//= type=test
//= reason=Reviewed 0030a96: PmtudPolicy exposes SearchAging::Seconds (validated >=300 with checked caller-timebase conversion) and Infinity through creation and live Endpoint::set_pmtud_policy. Tests exercise finite rearming, disabled periodic aging and both families retaining independent mandatory 600-second PTB hold and failure cooldown. No route/cache or socket-parser integration is claimed.
//# The implementation should also provide a way to change the timeout period for
//# aging stale PMTU information.

//= https://www.rfc-editor.org/rfc/rfc8201#section-5.3
//= type=test
//= reason=Reviewed 0030a96: PmtudPolicy exposes SearchAging::Seconds (validated >=300 with checked caller-timebase conversion) and Infinity through creation and live Endpoint::set_pmtud_policy. Tests exercise finite rearming, disabled periodic aging and both families retaining independent mandatory 600-second PTB hold and failure cooldown. No route/cache or socket-parser integration is claimed.
//# Note: an implementation should provide a means for changing the timeout
//# duration, including setting it to "infinity". For example, nodes attached to a
//# link with a large MTU that is then attached to the rest of the Internet via a
//# link with a small MTU are never going to discover a new non-local PMTU, so they
//# should not have to put up with dropped packets every 10 minutes.

//= https://www.rfc-editor.org/rfc/rfc8201#section-5.6
//= type=test
//= reason=Reviewed 0030a96: PmtudPolicy exposes SearchAging::Seconds (validated >=300 with checked caller-timebase conversion) and Infinity through creation and live Endpoint::set_pmtud_policy. Tests exercise finite rearming, disabled periodic aging and both families retaining independent mandatory 600-second PTB hold and failure cooldown. No route/cache or socket-parser integration is claimed.
//# The implementation should also provide a way to change the timeout period for
//# aging stale PMTU information.

fn pmtud_config_checked_aging_timebases_and_live_rearming() {
    for units in [1_000_000, 1_000_000_000] {
        for seconds in [0, 299, u64::MAX / units + 1] {
            let mut cfg = settings();
            cfg.timebase.units_per_second = units;
            cfg.pmtud.as_mut().unwrap().policy = policy(SearchAging::Seconds(seconds));
            assert_eq!(cfg.validate(true), Err(Error::InvalidArgument));
        }
        let mut config = settings();
        config.timebase.units_per_second = units;
        config.pmtud.as_mut().unwrap().policy = policy(SearchAging::Seconds(u64::MAX / units));
        assert!(config.validate(true).is_ok());
        let mut a = Connection::active(tuple(), config, 0, 0).unwrap();
        let p = a.pmtud.as_mut().unwrap();
        p.info.search_low = p.info.search_high;
        p.ack(Seq(0), 10, units, units);
        a.set_pmtud_policy(20, policy(SearchAging::Seconds(300)))
            .unwrap();
        assert_eq!(
            a.pmtud.as_ref().unwrap().next_deadline(),
            Some(20 + 300 * units)
        );
        assert_eq!(
            a.set_pmtud_policy(30, policy(SearchAging::Seconds(u64::MAX / units + 1))),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            a.pmtud.as_ref().unwrap().next_deadline(),
            Some(20 + 300 * units)
        );
        for seconds in [300, 600, 1200] {
            let mut cfg = PmtudConfig::new(1500);
            cfg.policy = policy(SearchAging::Seconds(seconds));
            let mut p = Pmtud::new(cfg, 1500, true, 600 * units);
            p.info.search_low = 1500;
            p.ack(Seq(0), 10, units, units);
            assert_eq!(p.next_deadline(), Some(10 + seconds * units));
            p.set_policy(20, policy(SearchAging::Infinity), None);
            assert_eq!(p.next_deadline(), None);
            p.tick(100_000 * units);
            assert_eq!(p.target(), None);
            p.link(9000, 9000, 100_000 * units);
            assert_eq!(p.next_deadline(), None);
            p.set_policy(
                100_001 * units,
                policy(SearchAging::Seconds(300)),
                Some(300 * units),
            );
            assert_eq!(p.next_deadline(), Some(100_301 * units));
            p.tick(100_301 * units - 1);
            assert_eq!(p.target(), None);
            p.tick(100_301 * units);
            assert!(p.target().unwrap() > 1500);
            assert_eq!(p.info.current_mtu, 1500);
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.3
//= type=test
//= reason=Reviewed 0030a96: PmtudPolicy exposes SearchAging::Seconds (validated >=300 with checked caller-timebase conversion) and Infinity through creation and live Endpoint::set_pmtud_policy. Tests exercise finite rearming, disabled periodic aging and both families retaining independent mandatory 600-second PTB hold and failure cooldown. No route/cache or socket-parser integration is claimed.
//# Note: an implementation should provide a means for changing the timeout
//# duration, including setting it to "infinity". For example, hosts attached to an
//# FDDI network which is then attached to the rest of the Internet via a slow
//# serial line are never going to discover a new non-local PMTU, so they should not
//# have to put up with dropped datagrams every 10 minutes.

//= https://www.rfc-editor.org/rfc/rfc1191#section-6.6
//= type=test
//= reason=Reviewed 0030a96: PmtudPolicy exposes SearchAging::Seconds (validated >=300 with checked caller-timebase conversion) and Infinity through creation and live Endpoint::set_pmtud_policy. Tests exercise finite rearming, disabled periodic aging and both families retaining independent mandatory 600-second PTB hold and failure cooldown. No route/cache or socket-parser integration is claimed.
//# The implementation should also provide a way to change the timeout period for
//# aging stale PMTU information.

//= https://www.rfc-editor.org/rfc/rfc8201#section-5.3
//= type=test
//= reason=Reviewed 0030a96: PmtudPolicy exposes SearchAging::Seconds (validated >=300 with checked caller-timebase conversion) and Infinity through creation and live Endpoint::set_pmtud_policy. Tests exercise finite rearming, disabled periodic aging and both families retaining independent mandatory 600-second PTB hold and failure cooldown. No route/cache or socket-parser integration is claimed.
//# Note: an implementation should provide a means for changing the timeout
//# duration, including setting it to "infinity". For example, nodes attached to a
//# link with a large MTU that is then attached to the rest of the Internet via a
//# link with a small MTU are never going to discover a new non-local PMTU, so they
//# should not have to put up with dropped packets every 10 minutes.

//= https://www.rfc-editor.org/rfc/rfc8201#section-5.6
//= type=test
//= reason=Reviewed 0030a96: PmtudPolicy exposes SearchAging::Seconds (validated >=300 with checked caller-timebase conversion) and Infinity through creation and live Endpoint::set_pmtud_policy. Tests exercise finite rearming, disabled periodic aging and both families retaining independent mandatory 600-second PTB hold and failure cooldown. No route/cache or socket-parser integration is claimed.
//# The implementation should also provide a way to change the timeout period for
//# aging stale PMTU information.

fn pmtud_config_infinity_keeps_ptb_hold_and_failure_retry() {
    for ipv4 in [true, false] {
        let header = if ipv4 { 20 } else { 40 };
        for units in [1_000_000, 1_000_000_000] {
            let mut cfg = PmtudConfig::new(1500);
            cfg.policy = policy(SearchAging::Infinity);
            let mut p = Pmtud::new(cfg, 1500, ipv4, 600 * units);
            p.sent(Seq(0), Seq(1400), 1500, header, false);
            assert!(p.feedback(10, Seq(0), 1500, header, 1300));
            p.set_policy(11, policy(SearchAging::Seconds(300)), Some(300 * units));
            p.set_policy(12, cfg.policy, None);
            p.ack(Seq(1400), 13, units, units);
            assert_eq!(p.next_deadline(), Some(10 + 600 * units));
            p.tick(10 + 600 * units - 1);
            assert_eq!(p.target(), None);
            p.tick(10 + 600 * units);
            assert!(p.target().is_some());
            assert_eq!(p.info.current_mtu, 1300);
            // Both isolated and timed-out failure suppressions remain finite.
            for timeout in [false, true] {
                let mut p = Pmtud::new(cfg, 1500, ipv4, 600 * units);
                p.start_probe(Seq(0), 1300, 3000, 1360);
                p.sent(Seq(0), Seq(1300), 1360, header, false);
                if timeout {
                    p.timeout(20, Seq(0), 1, units);
                }
                p.sent(Seq(0), Seq(1300), 1340, header, true);
                p.ack(Seq(4300), 30, units, units);
                let deadline = 30 + units * if timeout { 5 } else { 1 };
                assert_eq!(p.next_deadline(), Some(deadline));
                p.set_policy(31, cfg.policy, None);
                p.tick(deadline - 1);
                assert_eq!(p.target(), None);
                p.tick(deadline);
                assert!(p.target().unwrap() < 1360);
                assert_eq!(p.info.search_high, 1359);
            }
        }
    }
}

#[test]
fn pmtud_config_plateaus_bounded_validated_and_strictly_decreasing_feedback() {
    for invalid in [
        &[][..],
        &[1500, 1500, 68],
        &[68, 1500],
        &[1500],
        &[67],
        &[65536, 68],
        &[68; 17],
    ] {
        assert_eq!(Ipv4Plateaus::new(invalid), Err(Error::InvalidArgument));
    }
    assert_eq!(
        Ipv4Plateaus::default().as_slice(),
        &[
            65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68
        ]
    );
    let custom = Ipv4Plateaus::new(&[65535, 1500, 1480, 1400, 1300, 68]).unwrap();
    let maximum = core::array::from_fn::<_, 16, _>(|i| 83 - i as u32);
    assert_eq!(Ipv4Plateaus::new(&maximum).unwrap().as_slice(), maximum);
    assert!(core::mem::size_of::<PmtudConfig>() <= 128);
    fn copy<T: Copy>(v: T) -> T {
        v
    }
    let mut cfg = copy(PmtudConfig::new(1500));
    cfg.policy.ipv4_plateaus = custom;
    for (size, expected) in [(1500, 1400), (1520, 1480)] {
        let mut p = Pmtud::new(cfg, 1500, true, 600_000_000);
        p.sent(Seq(0), Seq(1460), 1500, 20, false);
        assert!(p.feedback(1, Seq(0), size, 20, 0));
        assert_eq!(p.info.current_mtu, expected);
        let before = p.info;
        p.set_policy(2, PmtudPolicy::default(), Some(600_000_000));
        let accepted = p.feedback(3, Seq(0), size, 20, 0);
        assert_eq!(accepted, size == 1500);
        assert!(p.info.current_mtu <= before.current_mtu);
    }
    for plateaus in [Ipv4Plateaus::default(), custom] {
        for size in [68, 80] {
            let mut cfg = PmtudConfig::new(size);
            cfg.policy.ipv4_plateaus = plateaus;
            let mut p = Pmtud::new(cfg, size, true, 600_000_000);
            p.sent(Seq(0), Seq(size - 40), size, 20, false);
            // Exact quotes correct below 68; only 80 can legally decrease to 68.
            assert_eq!(p.feedback(1, Seq(0), size, 20, 0), size > 68);
            assert_eq!(p.info.current_mtu, 68);
        }
    }
}

#[test]
fn pmtud_config_live_update_preserves_probe_repair_and_connection_state_without_allocating() {
    let cfg = settings();
    let t = tuple();
    let mut a = Connection::active(t, cfg.clone(), 0, 0).unwrap();
    let syn = packet(&mut a, 0);
    let mut b =
        Connection::passive(reverse(t), cfg, 900, 10, &wire::parse(ip(t), &syn).unwrap()).unwrap();
    deliver(&mut b, &mut a, 20);
    deliver(&mut a, &mut b, 30);
    a.write(&[7; 20_000]).unwrap();
    packet(&mut a, 40);
    let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
    let before = (
        a.path_mtu_info(),
        a.mss,
        a.congestion.cwnd(),
        a.flight(),
        a.rto_deadline,
    );
    let invalid = policy(SearchAging::Seconds(299));
    assert_eq!(
        a.set_pmtud_policy(1_000_000, invalid),
        Err(Error::InvalidArgument)
    );
    let valid = PmtudPolicy {
        search_aging: SearchAging::Infinity,
        ipv4_plateaus: Ipv4Plateaus::new(&[1500, 1300, 68]).unwrap(),
    };
    crate::allocation_tests::fail_after(0, || a.set_pmtud_policy(41, valid)).unwrap();
    assert_eq!(
        (
            a.path_mtu_info(),
            a.mss,
            a.congestion.cwnd(),
            a.flight(),
            a.rto_deadline
        ),
        before
    );
    assert_eq!(a.pmtud.as_ref().unwrap().probe.unwrap().size, probe.size);
    assert_eq!(
        a.pmtud.as_ref().unwrap().repair_limit(probe.start, 9999),
        probe.end.distance_from(probe.start)
    );
    assert!(
        a.pmtu_feedback(42, probe.start.0, probe.size, 20, 0)
            .unwrap()
    );
    assert_eq!(a.path_mtu_info().unwrap().current_mtu, 68); // custom table, below 1262-byte probe
    assert!(a.pmtud.as_ref().unwrap().probe.is_none());
    let repair = a.pmtud.as_ref().unwrap().repair_limit(probe.start, 9999);
    crate::allocation_tests::fail_after(0, || a.set_pmtud_policy(43, PmtudPolicy::default()))
        .unwrap();
    assert_eq!(
        a.pmtud.as_ref().unwrap().repair_limit(probe.start, 9999),
        repair
    );
    assert!(a.pmtud.as_ref().unwrap().target().is_none());
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.3
//= type=test
//= reason=Reviewed 0030a96: PmtudPolicy exposes SearchAging::Seconds (validated >=300 with checked caller-timebase conversion) and Infinity through creation and live Endpoint::set_pmtud_policy. Tests exercise finite rearming, disabled periodic aging and both families retaining independent mandatory 600-second PTB hold and failure cooldown. No route/cache or socket-parser integration is claimed.
//# Note: an implementation should provide a means for changing the timeout
//# duration, including setting it to "infinity". For example, hosts attached to an
//# FDDI network which is then attached to the rest of the Internet via a slow
//# serial line are never going to discover a new non-local PMTU, so they should not
//# have to put up with dropped datagrams every 10 minutes.

//= https://www.rfc-editor.org/rfc/rfc1191#section-6.6
//= type=test
//= reason=Reviewed 0030a96: PmtudPolicy exposes SearchAging::Seconds (validated >=300 with checked caller-timebase conversion) and Infinity through creation and live Endpoint::set_pmtud_policy. Tests exercise finite rearming, disabled periodic aging and both families retaining independent mandatory 600-second PTB hold and failure cooldown. No route/cache or socket-parser integration is claimed.
//# The implementation should also provide a way to change the timeout period for
//# aging stale PMTU information.

//= https://www.rfc-editor.org/rfc/rfc8201#section-5.3
//= type=test
//= reason=Reviewed 0030a96: PmtudPolicy exposes SearchAging::Seconds (validated >=300 with checked caller-timebase conversion) and Infinity through creation and live Endpoint::set_pmtud_policy. Tests exercise finite rearming, disabled periodic aging and both families retaining independent mandatory 600-second PTB hold and failure cooldown. No route/cache or socket-parser integration is claimed.
//# Note: an implementation should provide a means for changing the timeout
//# duration, including setting it to "infinity". For example, nodes attached to a
//# link with a large MTU that is then attached to the rest of the Internet via a
//# link with a small MTU are never going to discover a new non-local PMTU, so they
//# should not have to put up with dropped packets every 10 minutes.

//= https://www.rfc-editor.org/rfc/rfc8201#section-5.6
//= type=test
//= reason=Reviewed 0030a96: PmtudPolicy exposes SearchAging::Seconds (validated >=300 with checked caller-timebase conversion) and Infinity through creation and live Endpoint::set_pmtud_policy. Tests exercise finite rearming, disabled periodic aging and both families retaining independent mandatory 600-second PTB hold and failure cooldown. No route/cache or socket-parser integration is claimed.
//# The implementation should also provide a way to change the timeout period for
//# aging stale PMTU information.

fn pmtud_config_endpoint_policy_update_preserves_reserved_output_and_is_transactional() {
    let mut e = crate::Endpoint::new(
        crate::EndpointConfig {
            connection: settings(),
            ..crate::EndpointConfig::default()
        },
        [1; 32],
        0,
        |_| true,
    )
    .unwrap();
    let id = e.connect(0, tuple().local, tuple().remote).unwrap();
    e.enable_output_reservations().unwrap();
    let mut bytes = [0; 1600];
    let (_, attempt) = e.poll_reserved_transmit(0, &mut bytes, 16).unwrap();
    let before = (
        e.path_mtu_info(id).unwrap(),
        e.buffer_bytes(),
        e.next_deadline(),
    );
    assert_eq!(
        e.set_pmtud_policy(1000, id, policy(SearchAging::Seconds(299))),
        Err(Error::InvalidArgument.into())
    );
    crate::allocation_tests::fail_after(0, || {
        e.set_pmtud_policy(1, id, policy(SearchAging::Infinity))
    })
    .unwrap();
    assert_eq!(
        (
            e.path_mtu_info(id).unwrap(),
            e.buffer_bytes(),
            e.next_deadline()
        ),
        before
    );
    assert!(e.accept_transmit(2, attempt.unwrap()).unwrap());
    assert_eq!(e.path_mtu_info(id).unwrap(), before.0);
}

#[test]
fn pmtud_config_endpoint_template_link_update_preserves_creation_policy() {
    let mut cfg = settings();
    let p = cfg.pmtud.as_mut().unwrap();
    p.initial_mtu = Some(1300);
    p.initial_search_high = Some(1400);
    p.policy = policy(SearchAging::Infinity);
    let mut e = crate::Endpoint::new(
        crate::EndpointConfig {
            connection: cfg,
            ..crate::EndpointConfig::default()
        },
        [1; 32],
        0,
        |_| true,
    )
    .unwrap();
    let id = e.connect(0, tuple().local, tuple().remote).unwrap();
    let before = e.path_mtu_info(id).unwrap();
    assert_eq!(
        e.set_endpoint_first_hop_mtu(1000, 1280),
        Err(Error::InvalidArgument.into())
    );
    assert_eq!(e.path_mtu_info(id).unwrap(), before);
    crate::allocation_tests::fail_after(0, || e.set_endpoint_first_hop_mtu(1, 9000)).unwrap();
    let new_id = e
        .connect(1, "192.0.2.1:1001".parse().unwrap(), tuple().remote)
        .unwrap();
    let info = e.path_mtu_info(new_id).unwrap().unwrap();
    assert_eq!(info.current_mtu, 1300);
    assert_eq!(info.search_high, 1400);
    assert_eq!(info.first_hop_mtu, 9000);
}

#[test]
fn pmtud_config_converged_failure_rearms_finite_aging_after_cooldown() {
    let mut p = Pmtud::new(PmtudConfig::new(1500), 1500, true, 600_000_000);
    p.info.current_mtu = 1024;
    p.start_probe(Seq(0), 985, 3000, 1025);
    p.sent(Seq(0), Seq(985), 1025, 20, false);
    p.sent(Seq(0), Seq(985), 1024, 20, true);
    p.ack(Seq(3985), 10, 1000, 1000);
    assert_eq!(p.info.search_low, p.info.search_high);
    assert_eq!(p.next_deadline(), Some(1010));
    p.tick(1010);
    assert_eq!(p.target(), None);
    assert_eq!(p.next_deadline(), Some(600_001_010));
    p.tick(600_001_010);
    assert!(p.target().unwrap() > 1024);
    assert_eq!(p.info.current_mtu, 1024);
    p.info.search_low = p.info.search_high;
    p.ack(Seq(3985), u64::MAX, 1000, 1000);
    assert_eq!(p.next_deadline(), None); // no saturated-timer busy loop
}
