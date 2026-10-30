use super::*;
use ntcp_path::{
    ContextId, Dscp, InterfaceKey, IpPrefix, Limits, NextHop, PathRequest, PathService, Route,
    ScopedAddress,
};

fn authority(tuple: Tuple, timebase: CallerTimebase) -> (PathService, crate::PreparedPath, Route) {
    let mut service = PathService::new(
        ContextId::new(101),
        Limits {
            links: 1,
            sources: 1,
            source_owners: 1,
            routes: 2,
            paths: 3,
            clients: 3,
        },
    )
    .unwrap();
    let link = service.register_link(InterfaceKey(1), 1500).unwrap();
    let source = service
        .register_source(ScopedAddress::new(tuple.local.ip(), None).unwrap(), link)
        .unwrap();
    let route = Route {
        destination: IpPrefix::new(
            if tuple.local.is_ipv4() {
                "0.0.0.0"
            } else {
                "::"
            }
            .parse()
            .unwrap(),
            0,
        )
        .unwrap(),
        source: None,
        dscp: None,
        link,
        next_hop: NextHop::OnLink,
        metric: 0,
    };
    service.add_route(route).unwrap();
    let (client, snapshot) = service
        .acquire(PathRequest {
            source,
            destination: ScopedAddress::new(tuple.remote.ip(), None).unwrap(),
            dscp: Dscp::new(0).unwrap(),
        })
        .unwrap();
    assert!(timebase.units_per_second > 0);
    (service, crate::PreparedPath { client, snapshot }, route)
}
fn managed_pair(ipv4: bool, units: u64) -> (Connection, Connection, PathService, Route) {
    managed_pair_configured(ipv4, units, |_| {})
}

fn managed_pair_configured(
    ipv4: bool,
    units: u64,
    configure: impl FnOnce(&mut ConnectionConfig),
) -> (Connection, Connection, PathService, Route) {
    let tuple = if ipv4 {
        tuple()
    } else {
        Tuple {
            local: "[2001:db8::1]:1000".parse().unwrap(),
            remote: "[2001:db8::2]:2000".parse().unwrap(),
        }
    };
    let mut cfg = ConnectionConfig {
        pmtud: Some(crate::PmtudConfig::new(1500)),
        initial_window: InitialWindow::Iw10,
        nagle: false,
        timestamps: false,
        sack: false,
        delayed_ack_us: 0,
        timebase: CallerTimebase {
            units_per_second: units,
            ..CallerTimebase::default()
        },
        ..config(65536, 1460)
    };
    configure(&mut cfg);
    let (service, prepared, route) = authority(tuple, cfg.timebase);
    let mut a = Connection::active_with_receive_path(
        tuple,
        cfg.clone(),
        u32::MAX - 1000,
        0,
        &mut None,
        Some(prepared),
        None,
    )
    .unwrap();
    let syn_bytes = packet(&mut a, 1);
    let syn = wire::parse(ip(tuple), &syn_bytes).unwrap();
    let mut b = Connection::passive(reverse(tuple), cfg, 900, 2, &syn).unwrap();
    deliver(&mut b, &mut a, 3);
    deliver(&mut a, &mut b, 4);
    (a, b, service, route)
}
fn decrease(
    a: &mut Connection,
    service: &mut PathService,
    mtu: u32,
    deadline: u64,
) -> crate::PreparedPath {
    let old = a.managed_path.unwrap();
    service
        .trusted_decrease_with_hold(old.snapshot.path(), mtu, deadline)
        .unwrap();
    let prepared = crate::PreparedPath {
        client: old.client,
        snapshot: service.snapshot(old.client).unwrap(),
    };
    a.apply_managed_budget(prepared).unwrap();
    prepared
}

#[test]
fn managed_physical_decrease_preserves_isolated_probe_through_split_partial_acks() {
    for ipv4 in [true, false] {
        for mode in 0..3 {
            for prr in [false, true] {
                for cubic in [false, true] {
                    let (mut a, mut b, mut service, route) = managed_pair_configured(ipv4, 1_000_000, |cfg| {
                        cfg.sack = mode != 0;
                        cfg.rack = mode == 2;
                        cfg.prr = prr;
                        cfg.congestion_algorithm = if cubic { crate::CongestionAlgorithm::Cubic } else { crate::CongestionAlgorithm::Reno };
                    });
                    a.write(b"x").unwrap();
                    deliver(&mut a, &mut b, 32);
                    deliver(&mut b, &mut a, 33);
                    a.write(&[7; 20000]).unwrap();
                    packet(&mut a, 40); // The only dropped original is the actual probe.
                    let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
                    let header = if ipv4 { 20 } else { 40 };
                    let threshold = a.congestion.ssthresh();
                    let window = a.congestion.cwnd();
                    let old_mss = a.mss;
                    let mut trailing = Vec::new();
                    for _ in 0..8 { trailing.push(packet(&mut a, 41)); }
                    let tail = a.snd_nxt;
                    let mut now = 140;
                    for bytes in &trailing {
                        b.input(now, &wire::parse(ip(a.tuple), bytes).unwrap()).unwrap();
                        deliver(&mut b, &mut a, now);
                    }
                    if !a.congestion.in_recovery() {
                        now = a.rack.deadline.unwrap();
                        a.timeout(now).unwrap();
                    }
                    assert_eq!(a.congestion.pending_probe_response(), Some(probe.start));
                    let mtu = if ipv4 { 1100 } else { 1280 };
                    assert!(mtu < probe.size);
                    service.set_link_mtu(route.link, mtu).unwrap();
                    let old = a.managed_path.unwrap();
                    a.apply_managed_budget(crate::PreparedPath {
                        client: old.client, snapshot: service.snapshot(old.client).unwrap(),
                    }).unwrap();
                    let mut partial = false;
                    for _ in 0..8 {
                        now += 1;
                        let bytes = packet(&mut a, now);
                        let seg = wire::parse(ip(a.tuple), &bytes).unwrap();
                        assert!(bytes.len() + header <= mtu as usize);
                        assert!(probe.end.after(Seq(seg.header.sequence)));
                        b.input(now, &seg).unwrap();
                        deliver(&mut b, &mut a, now);
                        if probe.end.after(a.snd_una) {
                            partial = true;
                            assert!(a.pmtud.as_ref().unwrap().probe.is_some(), "partial ACK lost probe evidence");
                            assert_eq!(a.congestion.pending_probe_response(), Some(probe.start));
                        }
                        assert_eq!(a.congestion.ssthresh(), threshold, "snapshot must not commit congestion loss");
                        if a.pmtud.as_ref().unwrap().probe.is_none() { break; }
                    }
                    assert!(partial, "repair must exercise an advancing partial ACK");
                    assert_eq!(a.snd_una, tail);
                    assert!(a.congestion.pending_probe_response().is_none());
                    assert!(a.prr.is_none());
                    assert_eq!(a.congestion.cwnd(), (u64::from(window) * a.mss as u64 / old_mss as u64) as u32);
                    let mut received = [0; 20000];
                    let n = b.read(&mut received).unwrap();
                    assert_eq!(n, tail.distance_from(probe.start) as usize + 1);
                    assert_eq!(received[0], b'x');
                    assert!(received[1..n].iter().all(|v| *v == 7));
                }
            }
        }
    }
}

#[test]
fn managed_link_growth_retains_failed_probe_bound_until_search_aging() {
    let (mut a, mut b, mut service, route) = managed_pair(true, 1_000_000);
    a.write(b"x").unwrap();
    deliver(&mut a, &mut b, 32);
    deliver(&mut b, &mut a, 33);
    a.write(&[7; 20000]).unwrap();
    packet(&mut a, 40);
    let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
    let mut trailing = Vec::new();
    for _ in 0..8 { trailing.push(packet(&mut a, 41)); }
    for bytes in &trailing {
        b.input(140, &wire::parse(ip(a.tuple), bytes).unwrap()).unwrap();
        deliver(&mut b, &mut a, 140);
    }
    assert!(a.congestion.pending_probe_response().is_some());
    let mut now = 141;
    for _ in 0..8 {
        let bytes = packet(&mut a, now);
        b.input(now, &wire::parse(ip(a.tuple), &bytes).unwrap()).unwrap();
        deliver(&mut b, &mut a, now);
        if a.pmtud.as_ref().unwrap().probe.is_none() { break; }
        now += 1;
    }
    assert_eq!(a.path_mtu_info().unwrap().search_high, probe.size - 1);
    let deadline = a.pmtud.as_ref().unwrap().deadline.unwrap();
    service.set_link_mtu(route.link, 1600).unwrap();
    let old = a.managed_path.unwrap();
    a.apply_managed_budget(crate::PreparedPath {
        client: old.client, snapshot: service.snapshot(old.client).unwrap(),
    }).unwrap();
    let p = a.pmtud.as_mut().unwrap();
    assert_eq!(p.info.search_high, probe.size - 1);
    assert_eq!(p.deadline, Some(deadline));
    p.tick(deadline);
    assert!(p.target().unwrap() < probe.size);
    // Converge within the retained negative bound; only existing aging may
    // then authorize reopening it. This is independent of physical growth.
    p.info.search_low = p.info.search_high;
    p.ack(a.snd_una, deadline, 1, 1);
    let aging = p.next_deadline().unwrap();
    p.tick(aging - 1);
    assert_eq!(p.info.search_high, probe.size - 1);
    p.tick(aging);
    assert!(p.info.search_high >= probe.size);
}

#[test]
fn managed_plateau_constructor_and_live_transport_override_precedence() {
    for table in [crate::Ipv4Plateaus::INHERIT, crate::Ipv4Plateaus::HISTORICAL,
        crate::Ipv4Plateaus::new(&[1500, 1300, 68]).unwrap()] {
        let (mut a, _, mut service, _) = managed_pair_configured(true, 1_000_000, |cfg| {
            cfg.pmtud.as_mut().unwrap().policy.ipv4_plateaus = table;
        });
        a.write(&[7; 1460]).unwrap();
        let bytes = packet(&mut a, 40);
        assert_eq!(bytes.len() + 20, 1500);
        let seq = wire::parse(ip(a.tuple), &bytes).unwrap().header.sequence;
        assert!(a.pmtu_feedback(41, seq, 1500, 20, 0).unwrap());
        let expected = if table == crate::Ipv4Plateaus::INHERIT { 1460 }
            else if table == crate::Ipv4Plateaus::HISTORICAL { 1006 } else { 1300 };
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, expected);
        service.set_ipv4_plateaus(ntcp_path::Ipv4Plateaus::new(&[1500, 900, 68]).unwrap()).unwrap();
        let old = a.managed_path.unwrap();
        let timers = (a.rto_deadline, a.pmtud.as_ref().unwrap().deadline);
        a.apply_managed_budget(crate::PreparedPath {
            client: old.client, snapshot: service.snapshot(old.client).unwrap(),
        }).unwrap();
        assert_eq!((a.rto_deadline, a.pmtud.as_ref().unwrap().deadline), timers);
        let accepted = a.pmtu_feedback(42, seq, 1500, 20, 0).unwrap();
        assert_eq!(accepted, table == crate::Ipv4Plateaus::INHERIT);
        assert_eq!(a.path_mtu_info().unwrap().current_mtu,
            if table == crate::Ipv4Plateaus::INHERIT { 900 } else { expected });
        // A live explicit historical override wins immediately, including
        // across later canonical updates; INHERIT restores the live host table.
        a.set_pmtud_policy(43, crate::PmtudPolicy {
            ipv4_plateaus: crate::Ipv4Plateaus::HISTORICAL, ..Default::default()
        }).unwrap();
        assert_eq!(a.pmtu_feedback(44, seq, 1500, 20, 0).unwrap(), expected == 1300);
        assert_eq!(a.path_mtu_info().unwrap().current_mtu,
            if table == crate::Ipv4Plateaus::INHERIT { 900 } else { 1006 });
        a.set_pmtud_policy(45, crate::PmtudPolicy::default()).unwrap();
        assert_eq!(a.pmtu_feedback(46, seq, 1500, 20, 0).unwrap(), table != crate::Ipv4Plateaus::INHERIT);
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, 900);
    }
}

#[test]
fn budget_only_shared_decrease_preserves_real_flight_timer_and_retry_work() {
    for ipv4 in [false, true] {
        let (mut a, mut b, mut service, _) = managed_pair(ipv4, 1_000_000);
        a.write(&[7; 1000]).unwrap();
        let bytes = packet(&mut a, 10);
        let old_pmtu = a.path_mtu_info();
        let timers = (a.rto_deadline, a.loss_timer, a.tlp_deadline);
        let threshold = a.congestion.ssthresh();
        let mtu = if ipv4 { 1100 } else { 1280 };
        let first = decrease(&mut a, &mut service, mtu, 600_000_010);
        assert_eq!(a.path_mtu_info(), old_pmtu);
        assert_eq!((a.rto_deadline, a.loss_timer, a.tlp_deadline), timers);
        assert_eq!(a.congestion.ssthresh(), threshold);
        assert!(!a.retx_pending && !a.syn_pending);
        assert_eq!(a.transmit(11, &mut [0; 2048]), Ok(None));
        a.apply_managed_budget(first).unwrap();
        assert_eq!((a.rto_deadline, a.loss_timer, a.tlp_deadline), timers);
        // A real transport RTO remains real work after an independent decrease.
        let expiry = a.rto_deadline.unwrap();
        a.timeout(expiry).unwrap();
        assert!(a.retx_pending);
        let after_rto = (
            a.congestion.cwnd(),
            a.congestion.ssthresh(),
            a.pmtud.as_ref().unwrap().probe.map(|p| p.start),
        );
        decrease(
            &mut a,
            &mut service,
            mtu - if ipv4 { 50 } else { 0 },
            600_000_020,
        );
        assert!(a.retx_pending);
        assert_eq!(a.congestion.cwnd(), a.mss as u32); // genuine MSS rescaling of the RTO window
        assert_eq!(
            (
                a.congestion.ssthresh(),
                a.pmtud.as_ref().unwrap().probe.map(|p| p.start)
            ),
            (after_rto.1, after_rto.2)
        );
        let retry = packet(&mut a, expiry + 1);
        assert_eq!(
            wire::parse(ip(a.tuple), &retry).unwrap().header.sequence,
            wire::parse(ip(a.tuple), &bytes).unwrap().header.sequence
        );
        b.input(expiry + 2, &wire::parse(ip(a.tuple), &retry).unwrap())
            .unwrap();
        deliver(&mut b, &mut a, expiry + 3);
        assert_eq!(a.flight(), 0);
    }
}

#[test]
fn shared_holdoff_real_probe_and_stale_ack_do_not_escape_ordinary_budget() {
    for ipv4 in [false, true] {
        for units in [1_000_000, 1_000_000_000] {
            let (mut a, mut b, mut service, _) = managed_pair(ipv4, units);
            let mtu = if ipv4 { 1100 } else { 1280 };
            let hold = 600 * units;
            let first = decrease(&mut a, &mut service, mtu, hold);
            a.write(&[7; 1000]).unwrap();
            let mut bytes = [0; 2048];
            let n = a
                .transmit_selected(hold - 1, &mut bytes, true)
                .unwrap()
                .unwrap();
            assert!(a.last_departure.unwrap().discovery.is_none());
            test_support::commit_reserved(&mut a, hold - 1);
            b.input(hold - 1, &wire::parse(ip(a.tuple), &bytes[..n]).unwrap())
                .unwrap();
            deliver(&mut b, &mut a, hold);
            // Idempotent reread cannot restart the shared absolute deadline.
            a.apply_managed_budget(first).unwrap();
            a.write(&[8; 20000]).unwrap();
            let n = a
                .transmit_selected(hold + 1, &mut bytes, true)
                .unwrap()
                .unwrap();
            let intent = a
                .last_departure
                .unwrap()
                .discovery
                .expect("actual eligible upward probe");
            assert!(intent.ip_packet_len() > mtu);
            assert_eq!(
                intent.ip_packet_len(),
                n as u32 + if ipv4 { 20 } else { 40 }
            );
            test_support::commit_reserved(&mut a, hold + 1);
            let before = a.managed_path.unwrap().snapshot.ip_packet_budget().unwrap();
            let next_mtu = if ipv4 { 1050 } else { 1280 };
            if ipv4 {
                decrease(&mut a, &mut service, next_mtu, hold * 2);
                assert_ne!(
                    intent.binding().snapshot.negative_revision(),
                    a.managed_path.unwrap().snapshot.negative_revision()
                );
            }
            b.input(hold + 2, &wire::parse(ip(a.tuple), &bytes[..n]).unwrap())
                .unwrap();
            deliver(&mut b, &mut a, hold + 3);
            assert!(a.path_payload_limit() as u32 + if ipv4 { 20 } else { 40 } <= before);
            assert!(a.mss <= (next_mtu - if ipv4 { 40 } else { 60 }) as usize);
            let n = a
                .transmit_selected(hold + 4, &mut bytes, true)
                .unwrap()
                .unwrap();
            if a.last_departure.unwrap().discovery.is_none() {
                assert!(n as u32 + if ipv4 { 20 } else { 40 } <= next_mtu);
            } else {
                assert!(!ipv4); // IPv4 has a newer negative hold; IPv6 may probe again.
                assert_eq!(
                    a.last_departure
                        .unwrap()
                        .discovery
                        .unwrap()
                        .binding()
                        .snapshot
                        .negative_revision(),
                    first.snapshot.negative_revision()
                );
            }
        }
    }
}

#[test]
fn replacement_generation_revokes_size_proof_without_a_loss_event() {
    for ipv4 in [false, true] {
        let (mut a, mut b, mut service, route) = managed_pair(ipv4, 1_000_000);
        a.write(&[7; 20000]).unwrap();
        let bytes = packet(&mut a, 10);
        assert!(a.pmtud.as_ref().unwrap().probe.is_some());
        let old = a.managed_path.unwrap();
        let old_route = old.snapshot.key().route();
        service.replace_route(old_route, route).unwrap();
        let (client, snapshot) = service
            .rebind(old.client, old.snapshot.key().request())
            .unwrap();
        let threshold = a.congestion.ssthresh();
        let probe = a
            .pmtud
            .as_ref()
            .unwrap()
            .probe
            .map(|p| (p.start, p.end, p.size));
        a.apply_managed_budget(crate::PreparedPath { client, snapshot })
            .unwrap();
        assert_ne!(old.snapshot.path(), snapshot.path());
        assert_eq!(
            a.pmtud
                .as_ref()
                .unwrap()
                .probe
                .map(|p| (p.start, p.end, p.size)),
            probe
        );
        let conservative = a.path_mtu_info().unwrap().current_mtu;
        b.input(11, &wire::parse(ip(a.tuple), &bytes).unwrap())
            .unwrap();
        deliver(&mut b, &mut a, 12);
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, conservative);
        assert_eq!(a.congestion.ssthresh(), threshold);
        assert!(!a.retx_pending);
    }
}

#[test]
fn managed_disabled_discovery_keeps_byte_window_and_real_retry_on_budget_growth() {
    let cfg = ConnectionConfig {
        pmtud: None,
        nagle: false,
        delayed_ack_us: 0,
        initial_window: InitialWindow::Iw10,
        ..config(65536, 1460)
    };
    let tuple = tuple();
    let (mut service, mut prepared, _) = authority(tuple, cfg.timebase);
    service
        .set_link_mtu(prepared.snapshot.key().link(), 1100)
        .unwrap();
    prepared.snapshot = service.snapshot(prepared.client).unwrap();
    let mut a = Connection::active_with_receive_path(
        tuple,
        cfg.clone(),
        100,
        0,
        &mut None,
        Some(prepared),
        None,
    )
    .unwrap();
    let syn = packet(&mut a, 1);
    let mut b = Connection::passive(
        reverse(tuple),
        cfg,
        900,
        2,
        &wire::parse(ip(tuple), &syn).unwrap(),
    )
    .unwrap();
    deliver(&mut b, &mut a, 3);
    deliver(&mut a, &mut b, 4);
    a.write(&[7; 1000]).unwrap();
    packet(&mut a, 10);
    a.timeout(a.rto_deadline.unwrap()).unwrap();
    assert!(a.retx_pending);
    service
        .set_link_mtu(prepared.snapshot.key().link(), 900)
        .unwrap();
    prepared.snapshot = service.snapshot(prepared.client).unwrap();
    a.apply_managed_budget(prepared).unwrap();
    let window = a.congestion.cwnd();
    service
        .set_link_mtu(prepared.snapshot.key().link(), 1500)
        .unwrap();
    prepared.snapshot = service.snapshot(prepared.client).unwrap();
    a.apply_managed_budget(prepared).unwrap();
    assert!(a.mss as u32 > window);
    assert_eq!(a.congestion.cwnd(), window);
    assert!(a.pmtud.is_none());
    assert!(a.retx_pending);
}
