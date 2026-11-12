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
        [1; 16],
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
    managed_pair_with_peer(ipv4, units, configure, |_| {})
}

// `peer` adjusts only the passive side's configuration (e.g. its MSS offer).
fn managed_pair_with_peer(
    ipv4: bool,
    units: u64,
    configure: impl FnOnce(&mut ConnectionConfig),
    peer: impl FnOnce(&mut ConnectionConfig),
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
        crate::ReceiveIpCapability::new(ContextId::new(101), tuple.local.is_ipv6(), 1500),
        None,
    )
    .unwrap();
    let syn_bytes = packet(&mut a, 1);
    let syn = wire::parse(ip(tuple), &syn_bytes).unwrap();
    let mut cfg = cfg;
    peer(&mut cfg);
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
        // Every report about the still-outstanding packet is an accepted
        // drop notification; only the policy decides whether the estimate falls.
        assert!(a.pmtu_feedback(42, seq, 1500, 20, 0).unwrap());
        assert_eq!(a.path_mtu_info().unwrap().current_mtu,
            if table == crate::Ipv4Plateaus::INHERIT { 900 } else { expected });
        // A live explicit historical override wins immediately, including
        // across later canonical updates; INHERIT restores the live host table.
        a.set_pmtud_policy(43, crate::PmtudPolicy {
            ipv4_plateaus: crate::Ipv4Plateaus::HISTORICAL, ..Default::default()
        }).unwrap();
        assert!(a.pmtu_feedback(44, seq, 1500, 20, 0).unwrap());
        assert_eq!(a.path_mtu_info().unwrap().current_mtu,
            if table == crate::Ipv4Plateaus::INHERIT { 900 } else { 1006 });
        a.set_pmtud_policy(45, crate::PmtudPolicy::default()).unwrap();
        assert!(a.pmtu_feedback(46, seq, 1500, 20, 0).unwrap());
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
            assert!(a.last_discovery.is_none());
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
            let intent = a.last_discovery.expect("actual eligible upward probe");
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
            if let Some(intent) = a.last_discovery {
                assert!(!ipv4); // IPv4 has a newer negative hold; IPv6 may probe again.
                assert_eq!(
                    intent.binding().snapshot.negative_revision(),
                    first.snapshot.negative_revision()
                );
            } else {
                assert!(n as u32 + if ipv4 { 20 } else { 40 } <= next_mtu);
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
        crate::ReceiveIpCapability::new(ContextId::new(101), tuple.local.is_ipv6(), 1100),
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

// Every packet `a` has ready reaches `b`; then `b`'s response reaches `a`.
fn exchange(a: &mut Connection, b: &mut Connection, now: Instant) {
    let mut out = vec![0; 65535];
    while let Some(n) = a.transmit(now, &mut out).unwrap() {
        b.input(now, &wire::parse(ip(a.tuple), &out[..n]).unwrap()).unwrap();
    }
    while let Some(n) = b.transmit(now, &mut out).unwrap() {
        a.input(now, &wire::parse(ip(b.tuple), &out[..n]).unwrap()).unwrap();
    }
}

// Proven full-size delivery, then one outstanding segment and its exact report.
fn deferred_setup(ipv4: bool) -> (Connection, Connection, PathService, Route, crate::CorrelatedPmtu, Vec<u8>) {
    let (mut a, mut b, service, route) = managed_pair(ipv4, 1_000_000);
    a.write(&vec![7; a.mss]).unwrap();
    exchange(&mut a, &mut b, 10);
    assert_eq!(a.flight(), 0);
    a.write(&vec![8; a.mss]).unwrap();
    let bytes = packet(&mut a, 20);
    let header = if ipv4 { 20 } else { 40 };
    let seg = wire::parse(ip(a.tuple), &bytes).unwrap();
    let len = bytes.len() as u32 + header;
    let report = crate::CorrelatedPmtu {
        segment: crate::CorrelatedSegment {
            start: seg.header.sequence,
            end: seg.header.sequence.wrapping_add(seg.payload.len() as u32),
            ip_packet_len: len,
            ip_header_len: header as u16,
        },
        quoted_packet_len: len,
        candidate_mtu: if ipv4 { 1000 } else { 1280 },
        current_path: true,
        path_estimate: a.managed_path.unwrap().snapshot.pmtu_estimate().ok(),
    };
    assert!(report.candidate_mtu < len);
    (a, b, service, route, report, bytes)
}

fn rto(a: &mut Connection) -> Instant {
    let deadline = a.rto_deadline.unwrap();
    a.timeout(deadline).unwrap();
    deadline
}

#[test]
fn pending_report_applied_at_its_timeout_yields_exactly_one_result() {
    for ipv4 in [true, false] {
        let (mut a, _b, _service, _route, report, _) = deferred_setup(ipv4);
        let binding = a.managed_path.unwrap();
        let before = a.path_mtu_info().unwrap().current_mtu;
        assert_eq!(
            a.correlated_pmtu_feedback(21, report, Some(1100)).map(|r| r.feedback),
            Ok(crate::PmtuFeedback::Deferred)
        );
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, before);
        assert!(a.managed_results.applied.is_none());
        rto(&mut a);
        let applied = a.managed_results.applied.take().expect("applied pending report");
        assert_eq!(applied.binding(), binding);
        assert_eq!(applied.report(), report);
        assert_eq!(applied.host_estimate(), 1100);
        assert_eq!(applied.applied_mtu(), report.candidate_mtu);
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, report.candidate_mtu);
        assert!(a.managed_results.pending.is_none());
        // Later timeouts, whatever they infer locally, never fabricate another
        // result: only the exact pending report's application records one.
        for _ in 0..3 {
            // Emit the retransmission that rearms the next real RTO.
            let now = a.now;
            packet(&mut a, now);
            rto(&mut a);
        }
        assert!(a.managed_results.applied.is_none());
    }
}

#[test]
fn replaced_cancelled_rebound_or_unattributed_pending_reports_yield_nothing() {
    for ipv4 in [true, false] {
        let lower = |r: crate::CorrelatedPmtu| crate::CorrelatedPmtu {
            candidate_mtu: if ipv4 { 900 } else { 1280 },
            ..r
        };
        // A larger report for the same data does not replace the pending one.
        let (mut a, _b, _s, _r, report, _) = deferred_setup(ipv4);
        a.correlated_pmtu_feedback(21, report, Some(1100)).unwrap();
        let larger = crate::CorrelatedPmtu {
            candidate_mtu: report.candidate_mtu + 10,
            ..report
        };
        assert_eq!(
            a.correlated_pmtu_feedback(22, larger, Some(1200)).map(|r| r.feedback),
            Ok(crate::PmtuFeedback::Deferred)
        );
        rto(&mut a);
        assert_eq!(a.managed_results.applied.take().unwrap().report(), report);

        if ipv4 {
            // A lower report without provenance replaces it: nothing publishes.
            let (mut a, _b, _s, _r, report, _) = deferred_setup(ipv4);
            a.correlated_pmtu_feedback(21, report, Some(1100)).unwrap();
            a.correlated_pmtu_feedback(22, lower(report), None).unwrap();
            assert!(a.managed_results.pending.is_none());
            rto(&mut a);
            assert_eq!(a.path_mtu_info().unwrap().current_mtu, 900);
            assert!(a.managed_results.applied.is_none());
            // With provenance the replacement alone describes the result.
            let (mut a, _b, _s, _r, report, _) = deferred_setup(ipv4);
            a.correlated_pmtu_feedback(21, report, Some(1100)).unwrap();
            a.correlated_pmtu_feedback(22, lower(report), Some(950)).unwrap();
            rto(&mut a);
            let applied = a.managed_results.applied.take().unwrap();
            assert_eq!((applied.report(), applied.host_estimate()), (lower(report), 950));
        }

        // Cumulative ACK of the quoted data cancels the pending report.
        let (mut a, mut b, _s, _r, report, bytes) = deferred_setup(ipv4);
        a.correlated_pmtu_feedback(21, report, Some(1100)).unwrap();
        b.input(23, &wire::parse(ip(a.tuple), &bytes).unwrap()).unwrap();
        a.write(&[9; 100]).unwrap();
        deliver(&mut b, &mut a, 24);
        assert!(a.managed_results.pending.is_none());
        exchange(&mut a, &mut b, 25);
        let _ = a.rto_deadline.map(|d| a.timeout(d).unwrap());
        assert!(a.managed_results.applied.is_none());

        // Path replacement discards both provenance and the local pending report.
        let (mut a, _b, mut service, route, report, _) = deferred_setup(ipv4);
        a.correlated_pmtu_feedback(21, report, Some(1100)).unwrap();
        let old = a.managed_path.unwrap();
        service.replace_route(old.snapshot.key().route(), route).unwrap();
        let (client, snapshot) = service.rebind(old.client, old.snapshot.key().request()).unwrap();
        a.apply_managed_budget(crate::PreparedPath { client, snapshot }).unwrap();
        assert!(a.managed_results.pending.is_none());
        rto(&mut a);
        assert!(a.managed_results.applied.is_none());

        // The legacy entry point attaches no provenance.
        let (mut a, _b, _s, _r, report, _) = deferred_setup(ipv4);
        a.correlated_pmtu_feedback(21, report, None).unwrap();
        rto(&mut a);
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, report.candidate_mtu);
        assert!(a.managed_results.applied.is_none());
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Receipt {
    Exact,
    Missing,
    WrongLength,
    Fragmentable,
}

// A real reserved upward probe after the shared hold, committed as Submitted.
fn submitted_probe(
    a: &mut Connection,
    b: &mut Connection,
    service: &mut PathService,
    ipv4: bool,
    converged: bool,
) -> (Vec<u8>, crate::DiscoveryIntent, u64) {
    let mtu = if ipv4 { 1100 } else { 1280 };
    let hold = 600 * 1_000_000;
    decrease(a, service, mtu, hold);
    a.write(&[7; 1000]).unwrap();
    exchange(a, b, hold - 1);
    if converged {
        // Local proof already exceeds the shared ceiling: only real data can
        // challenge it, re-confirming the larger local size.
        let p = a.pmtud.as_mut().unwrap();
        p.info.search_low = p.info.search_high;
    }
    a.write(&[8; 20000]).unwrap();
    let mut bytes = vec![0; 2048];
    let n = a.transmit_selected(hold + 1, &mut bytes, true).unwrap().unwrap();
    bytes.truncate(n);
    let intent = a.last_discovery.expect("eligible upward probe");
    assert!(intent.ip_packet_len() > mtu);
    (bytes, intent, hold + 1)
}

fn accept_probe(a: &mut Connection, intent: crate::DiscoveryIntent, now: Instant, receipt: Receipt) {
    let departure = a.last_departure.unwrap();
    let start = Seq(departure.start);
    test_support::commit_reserved(a, now);
    let receipt = match receipt {
        Receipt::Missing => return,
        Receipt::Exact => crate::PhysicalReceipt { ip_packet_len: intent.ip_packet_len(), dont_fragment: true },
        Receipt::WrongLength => crate::PhysicalReceipt { ip_packet_len: intent.ip_packet_len() + 1, dont_fragment: true },
        Receipt::Fragmentable => crate::PhysicalReceipt { ip_packet_len: intent.ip_packet_len(), dont_fragment: false },
    };
    // As Endpoint::accept_transmit_submitted: final-byte provenance first.
    a.certify_submission(&departure, 0, departure.payload, receipt);
    a.retain_probe_receipt(start, intent, receipt);
}

#[test]
fn confirmed_probe_requires_exact_definitely_submitted_receipt() {
    for ipv4 in [true, false] {
        for converged in [false, true] {
            for receipt in [Receipt::Exact, Receipt::Missing, Receipt::WrongLength, Receipt::Fragmentable] {
                let (mut a, mut b, mut service, _) = managed_pair(ipv4, 1_000_000);
                let (bytes, intent, now) = submitted_probe(&mut a, &mut b, &mut service, ipv4, converged);
                let local = a.path_mtu_info().unwrap().current_mtu;
                if converged {
                    assert_eq!(intent.ip_packet_len(), local);
                }
                accept_probe(&mut a, intent, now, receipt);
                b.input(now + 1, &wire::parse(ip(a.tuple), &bytes).unwrap()).unwrap();
                // Submission alone confirms nothing: only the probe's ACK does.
                assert!(a.managed_results.confirmed.is_none());
                deliver(&mut b, &mut a, now + 2);
                let confirmed = a.managed_results.confirmed.take();
                let expected = receipt == Receipt::Exact || receipt == Receipt::Fragmentable && !ipv4;
                assert_eq!(confirmed.is_some(), expected, "ipv4={ipv4} converged={converged}");
                let Some(confirmed) = confirmed else { continue };
                assert_eq!(confirmed.intent(), intent);
                assert_eq!(confirmed.receipt().ip_packet_len, intent.ip_packet_len());
                assert!(a.managed_results.receipt.is_none());
                // Ordinary output stays capped until the shared fact is published.
                let header = if ipv4 { 20 } else { 40 };
                assert!(a.path_payload_limit() as u32 + header <= a.managed_path.unwrap().snapshot.ip_packet_budget().unwrap());
                // The result satisfies the PathService rules with real data.
                let binding = intent.binding();
                assert_eq!(
                    service.confirm_delivery(
                        binding.snapshot.path(),
                        intent.ip_packet_len(),
                        binding.snapshot.negative_revision(),
                        intent.selected_at(),
                        now + 2,
                    ),
                    Ok(ntcp_path::DeliveryConfirmation::Raised)
                );
                // Ordinary ACKs afterwards record nothing further.
                exchange(&mut a, &mut b, now + 3);
                assert!(a.managed_results.confirmed.is_none());
            }
        }
    }
}

#[test]
fn stale_probe_after_negative_revision_route_change_or_fresh_hold_yields_nothing() {
    for ipv4 in [true, false] {
        for case in 0..3 {
            if case == 0 && !ipv4 {
                continue; // IPv6 is already at its family floor.
            }
            let (mut a, mut b, mut service, route) = managed_pair(ipv4, 1_000_000);
            let (bytes, intent, now) = submitted_probe(&mut a, &mut b, &mut service, ipv4, false);
            let old = a.managed_path.unwrap();
            match case {
                0 => {
                    // Newer negative evidence before the probe's ACK.
                    accept_probe(&mut a, intent, now, Receipt::Exact);
                    assert!(a.managed_results.receipt.is_some());
                    decrease(&mut a, &mut service, 1050, now + 600 * 1_000_000);
                    assert!(a.managed_results.receipt.is_none());
                }
                1 => {
                    accept_probe(&mut a, intent, now, Receipt::Exact);
                    service.replace_route(old.snapshot.key().route(), route).unwrap();
                    let (client, snapshot) = service.rebind(old.client, old.snapshot.key().request()).unwrap();
                    a.apply_managed_budget(crate::PreparedPath { client, snapshot }).unwrap();
                    assert!(a.managed_results.receipt.is_none());
                }
                _ => {
                    // A fresh unchanged report between selection and submission
                    // restarts the hold: the selection is now early.
                    service
                        .trusted_decrease_with_hold(old.snapshot.path(), 1400, now + 600 * 1_000_000)
                        .unwrap();
                    let fresh = crate::PreparedPath { client: old.client, snapshot: service.snapshot(old.client).unwrap() };
                    assert_eq!(fresh.snapshot.negative_revision(), old.snapshot.negative_revision());
                    assert!(fresh.snapshot.retry_not_before() > intent.selected_at());
                    a.apply_managed_budget(fresh).unwrap();
                    accept_probe(&mut a, intent, now, Receipt::Exact);
                    assert!(a.managed_results.receipt.is_none());
                }
            }
            b.input(now + 1, &wire::parse(ip(a.tuple), &bytes).unwrap()).unwrap();
            deliver(&mut b, &mut a, now + 2);
            assert!(a.managed_results.confirmed.is_none(), "case {case}");
        }
    }
}

// T12 search transition through a real managed binding: the owner's
// administrative estimate arrives as a PathService snapshot through
// apply_managed_budget (caller time, production 600-second hold).
const ADMIN_HOLD: u64 = 600 * 1_000_000;

fn administer(a: &mut Connection, service: &mut PathService, now: Instant, policy: ntcp_path::AdminPolicy) {
    let old = a.managed_path.unwrap();
    let path = old.snapshot.path();
    let expected = service.path_administration(path).unwrap().generation;
    let plan = service
        .prepare_admin(
            ntcp_path::AdminChange { target: ntcp_path::AdminTarget::Path(path), expected, policy },
            now,
            ADMIN_HOLD,
        )
        .unwrap();
    service.commit_admin(plan).unwrap();
    a.apply_managed_budget(crate::PreparedPath { client: old.client, snapshot: service.snapshot(old.client).unwrap() })
        .unwrap();
}

fn estimate(value: u32) -> ntcp_path::AdminPolicy {
    ntcp_path::AdminPolicy { discovery_disabled: false, estimate: Some(value) }
}

// A validated decrease to 1300 with its hold, an RTT sample inside the hold,
// then the upward administrative value 1450 (cached only).
fn admin_setup(a: &mut Connection, b: &mut Connection, service: &mut PathService) {
    decrease(a, service, 1300, ADMIN_HOLD);
    administer(a, service, 20, estimate(1450));
    a.write(&[7; 1000]).unwrap();
    exchange(a, b, ADMIN_HOLD - 1);
}

fn pending(deferred: Option<crate::AdministrativeDeferral>) -> Option<crate::AdministrativeSearch> {
    Some(crate::AdministrativeSearch::Pending { target: 1450, deferred })
}

#[test]
fn administrative_cap_arrives_through_budget_and_targets_the_first_probe_on_the_wire() {
    for ipv4 in [true, false] {
        let header = if ipv4 { 20 } else { 40 };
        let (mut a, mut b, mut service, _) = managed_pair(ipv4, 1_000_000);
        decrease(&mut a, &mut service, 1300, ADMIN_HOLD);
        let before = a.path_mtu_info().unwrap();
        let snapshot = a.managed_path.unwrap().snapshot;
        assert_eq!(a.administrative_search(), None);
        administer(&mut a, &mut service, 20, estimate(1450));
        // Delivered with the snapshot: a search cap, not an estimate change.
        let delivered = a.managed_path.unwrap().snapshot;
        assert_eq!(delivered.administrative_estimate(), Some(1450));
        assert_eq!(delivered.ip_packet_budget(), snapshot.ip_packet_budget());
        assert_eq!(delivered.retry_not_before(), snapshot.retry_not_before());
        assert_eq!(delivered.negative_revision(), snapshot.negative_revision());
        let info = a.path_mtu_info().unwrap();
        assert_eq!(info.search_high, before.search_high.min(1450));
        assert_eq!(info.search_low, before.search_low);
        // The conservative baseline case: the budget-only decrease left the
        // unvalidated working size (1500) at or above the administrative
        // value, so it is lowered to the shared budget for revalidation;
        // nothing is raised.
        assert_eq!((before.current_mtu, info.current_mtu), (1500, 1300));
        assert_eq!(a.administrative_search(), pending(None));
        // Real output inside the hold stays ordinary and records the hold.
        a.write(&[7; 1000]).unwrap();
        let bytes = deliver(&mut a, &mut b, 30);
        assert!(bytes.len() + header <= 1300);
        assert_eq!(a.administrative_search(), pending(Some(crate::AdministrativeDeferral::Hold)));
        deliver(&mut b, &mut a, 31);
        exchange(&mut a, &mut b, ADMIN_HOLD - 1);
        // First eligible probe after the hold: the administrative value, not
        // the midpoint, as one complete IP packet on the wire.
        a.write(&[8; 20000]).unwrap();
        let mut out = vec![0; 2048];
        let n = a.transmit_selected(ADMIN_HOLD, &mut out, true).unwrap().unwrap();
        let intent = a.last_discovery.expect("targeted probe");
        assert_eq!(n + header, 1450, "ipv4={ipv4}");
        assert_eq!(intent.ip_packet_len(), 1450);
        assert_eq!(
            a.administrative_search(),
            Some(crate::AdministrativeSearch::Attempted { target: 1450, size: 1450, clipped: None })
        );
        assert_eq!(a.pmtud.as_ref().unwrap().administrative_target(), None);
    }
}

#[test]
fn administrative_deferral_reasons_are_recorded_during_real_output() {
    use crate::AdministrativeDeferral::{Cooldown, DataOrWindow, LossRecovery};
    for ipv4 in [true, false] {
        let mut out = vec![0; 2048];
        // Too little queued data for a probe and its trailing segments.
        let (mut a, mut b, mut service, _) = managed_pair(ipv4, 1_000_000);
        admin_setup(&mut a, &mut b, &mut service);
        a.write(&[9; 1000]).unwrap();
        packet(&mut a, ADMIN_HOLD + 1);
        assert_eq!(a.administrative_search(), pending(Some(DataOrWindow)), "ipv4={ipv4}");

        // An outstanding (midpoint) probe blocks the targeted one.
        let (mut a, mut b, mut service, _) = managed_pair(ipv4, 1_000_000);
        decrease(&mut a, &mut service, 1300, ADMIN_HOLD);
        a.write(&[7; 1000]).unwrap();
        exchange(&mut a, &mut b, ADMIN_HOLD - 1);
        a.write(&[8; 20000]).unwrap();
        a.transmit_selected(ADMIN_HOLD + 1, &mut out, true).unwrap().unwrap();
        assert!(a.pmtud.as_ref().unwrap().probe.is_some());
        test_support::commit_reserved(&mut a, ADMIN_HOLD + 1);
        administer(&mut a, &mut service, ADMIN_HOLD + 2, estimate(1450));
        assert_eq!(a.administrative_search(), pending(None));
        packet(&mut a, ADMIN_HOLD + 3);
        assert_eq!(a.administrative_search(), pending(Some(Cooldown)), "ipv4={ipv4}");

        // Loss recovery: the first of a flight sent inside the hold is lost;
        // the duplicate ACKs arrive after the hold.
        let (mut a, mut b, mut service, _) = managed_pair(ipv4, 1_000_000);
        admin_setup(&mut a, &mut b, &mut service);
        a.write(&[8; 20000]).unwrap();
        let flight: Vec<_> = (0..8).map(|_| packet(&mut a, ADMIN_HOLD - 1)).collect();
        for bytes in &flight[1..] {
            b.input(ADMIN_HOLD + 2, &wire::parse(ip(a.tuple), bytes).unwrap()).unwrap();
            deliver(&mut b, &mut a, ADMIN_HOLD + 2);
            while a.transmit(ADMIN_HOLD + 2, &mut out).unwrap().is_some() {}
        }
        assert!(a.congestion.in_recovery());
        assert_eq!(a.administrative_search(), pending(Some(LossRecovery)), "ipv4={ipv4}");
        assert!(a.pmtud.as_ref().unwrap().probe.is_none());
    }
}

// The targeted size is clipped by a transport ceiling, the user's or the
// peer's MSS, and the diagnostic names it; the wire carries the clip.
#[test]
fn administrative_target_clipped_by_user_or_peer_mss_reports_transport() {
    for ipv4 in [true, false] {
        let header = if ipv4 { 20 } else { 40 };
        for user in [true, false] {
            let (mut a, mut b, mut service, _) =
                managed_pair_with_peer(ipv4, 1_000_000, |_| {}, |cfg| {
                    if !user {
                        cfg.mss = 1360;
                    }
                });
            if user {
                a.set_user_mss(Some(1350)).unwrap();
            }
            let expected = if user { 1350 } else { 1360 } + header + 20;
            admin_setup(&mut a, &mut b, &mut service);
            a.write(&[8; 20000]).unwrap();
            let mut out = vec![0; 2048];
            let n = a.transmit_selected(ADMIN_HOLD, &mut out, true).unwrap().unwrap();
            assert!(a.last_discovery.is_some());
            assert_eq!(n as u32 + header, expected, "ipv4={ipv4} user={user}");
            assert_eq!(
                a.administrative_search(),
                Some(crate::AdministrativeSearch::Attempted {
                    target: 1450,
                    size: expected,
                    clipped: Some(crate::AdministrativeClip::Transport)
                }),
                "ipv4={ipv4} user={user}"
            );
        }
    }
}

#[path = "connection_send_space_tests.rs"]
mod send_space;
