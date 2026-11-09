// The change service through real Host/Endpoint owners: shared fanout,
// failed-client isolation, coalescing, and publication of connection results.
use super::dispatch::{ptb, seal_ipv4, tcp_report};
use super::*;

type Side = (Host, Endpoint, IngressContext);

const UDP: UdpLimits = UdpLimits {
    flows: 3,
    receive_datagrams: 1,
    max_payload: 1500,
    events: 2,
    evicted_signatures: 1,
    probe_receipts: 2,
};

fn udp_side(local: SocketAddr, identity: u64, cfg: &EndpointConfig) -> Side {
    managed_limited(local, identity, cfg.clone(), false, None, None, |p, l| {
        let (p, l) = managed_udp_limits(p, l, UDP).unwrap();
        (p, l, 1)
    })
}
fn other_remote(v6: bool) -> IpAddr {
    if v6 { "2001:db8::3" } else { "192.0.2.3" }
        .parse()
        .unwrap()
}
fn flow(side: &mut Side, port: u16, remote: IpAddr, dscp: u8) -> UdpFlowId {
    let local = SocketAddr::new(addresses(remote.is_ipv6()).0.ip(), port);
    let options = UdpOptions {
        dscp,
        hop_limit: 64,
    };
    side.0
        .udp_open(&side.1, local, Some(SocketAddr::new(remote, 7)), options)
        .unwrap()
}
fn limits(side: &mut Side, id: UdpFlowId) -> UdpPathLimits {
    side.0.udp_path_limits(&side.1, id, None).unwrap()
}
fn overhead(v6: bool) -> (u32, usize) {
    if v6 { (40, 48) } else { (20, 28) }
}
fn connect(side: &mut Side, cfg: &EndpointConfig, port: u16, dscp: u8) -> ConnectionId {
    let (local, remote) = addresses(local_v6(side));
    side.1
        .connect_with_path_provider(
            0,
            SocketAddr::new(local.ip(), port),
            remote,
            options(cfg, dscp),
            &mut side.0,
        )
        .unwrap()
}
fn connect_from(side: &mut Side, cfg: &EndpointConfig, source: IpAddr, port: u16) -> ConnectionId {
    let remote = addresses(source.is_ipv6()).1;
    side.1
        .connect_with_path_provider(
            0,
            SocketAddr::new(source, port),
            remote,
            options(cfg, 0),
            &mut side.0,
        )
        .unwrap()
}
fn second_source(v6: bool) -> IpAddr {
    if v6 { "2001:db8::11" } else { "192.0.2.11" }
        .parse()
        .unwrap()
}
fn link_remote(v6: bool) -> IpAddr {
    if v6 { "2001:db8::4" } else { "192.0.2.4" }
        .parse()
        .unwrap()
}

// `udp_side` plus two more path representations: a second local source on
// the same link (paths that differ only by source), and a second link
// reached by its own host route (a path whose link differs; a route selects
// links by destination, source and DSCP only, so it is a distinct
// destination's route).
fn isolating_side(local: SocketAddr, identity: u64, cfg: &EndpointConfig) -> Side {
    let v6 = local.is_ipv6();
    let source = second_source(v6);
    let (paths, limits) = managed_limits(cfg, 2, 2, 2, 4, 1).unwrap();
    let (mut paths, limits) =
        managed_udp_limits(paths, limits, UdpLimits { flows: 4, ..UDP }).unwrap();
    paths.paths += 2;
    let mut host = Host::new(
        ContextId::new(identity),
        paths,
        limits,
        cfg.connection.timebase,
    )
    .unwrap();
    let capabilities = ReceiveCapabilities {
        max_ip_packet: 65575,
        ipv4: Ipv4Receive::Enabled {
            interpretation: true,
            source_routes: false,
        },
        ipv6: Ipv6Receive::BaseHeader,
        gro: true,
    };
    let first = host
        .register_link(
            InterfaceKey(1),
            1500,
            capabilities,
            Forwarding::Forwarder(ForwarderId(9)),
        )
        .unwrap();
    let second = host
        .register_link(
            InterfaceKey(2),
            1500,
            capabilities,
            Forwarding::Forwarder(ForwarderId(10)),
        )
        .unwrap();
    for address in [local.ip(), source] {
        host.register_source(ScopedAddress::new(address, None).unwrap(), first.link())
            .unwrap();
    }
    let any = if v6 { "::" } else { "0.0.0.0" }.parse().unwrap();
    let host_route = if v6 { 128 } else { 32 };
    for (destination, length, link, hop) in [
        (any, 0, first.link(), 9),
        (link_remote(v6), host_route, second.link(), 10),
    ] {
        host.add_route(path::Route {
            destination: path::IpPrefix::new(destination, length).unwrap(),
            source: None,
            dscp: None,
            link,
            next_hop: path::NextHop::Forwarder(ForwarderId(hop)),
            metric: 0,
        })
        .unwrap();
    }
    let owned = move |address| address == local.ip() || address == source;
    let mut endpoint = Endpoint::new(
        cfg.clone(),
        [identity as u8; 32],
        0,
        move |request| match request {
            ntcp::AddressValidation::Bind { local: address }
            | ntcp::AddressValidation::Open { local: address, .. } => owned(address),
            ntcp::AddressValidation::Incoming { destination, .. } => owned(destination),
            ntcp::AddressValidation::Route { source, .. } => owned(source),
        },
    )
    .unwrap();
    host.attach(&mut endpoint).unwrap();
    endpoint
        .enable_output_reservations_with_capacity(1)
        .unwrap();
    (host, endpoint, first)
}
fn local_v6(side: &Side) -> bool {
    side.0
        .paths()
        .sources()
        .next()
        .is_some_and(|(_, a)| a.address().is_ipv6())
}
fn send(side: &mut Side, now: u64, outcome: BackendOutcome) -> Option<(Vec<u8>, Submission)> {
    let (attempt, _, frame) = selected(&mut side.1, now)?;
    let context = side.0.egress_context(&mut side.1, attempt).unwrap();
    let ticket = side.0.submission_ticket(&mut side.1, context).unwrap();
    let result = side
        .0
        .submit(&mut side.1, now, ticket, context, &frame, 0, |_| outcome)
        .unwrap();
    Some((frame, result))
}
fn service(side: &mut Side, now: u64) -> ServiceReport {
    side.0.service_changes(&mut side.1, now).unwrap()
}
fn dirty(side: &Side, id: ConnectionId) -> bool {
    side.0
        .paths()
        .is_dirty(side.0.binding(id).unwrap().client)
        .unwrap()
}
fn decreased(dispatch: IcmpDispatch) -> bool {
    matches!(
        dispatch,
        IcmpDispatch::Completed(IcmpOutcome::Tcp {
            report: TcpReport::PacketTooBig(PmtuFeedback::Decreased { .. }),
            published: Some(path::EstimateChange::Decreased),
            ..
        })
    )
}

// Two TCP owners and an already-bound UDP flow share one path; a router PTB
// quotes only TCP flow A. One service pass brings every subscriber to the
// newest version: B by budget alone (no repair), the UDP flow by a change
// notification without sending. Paths differing in DSCP or destination are
// untouched.
#[test]
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
//= type=test
//= reason=PathService marks every client of a path dirty on each trusted decrease and on link MTU, route, source, link or plateau changes. Host::service_changes, run on every native service_egress and MTU-refresh pass and every tun_echo transmit pass, brings each dirty TCP binding (reserved owners included, budget only, no repair) and each Host UDP flow (a coalesced per-flow change slot carrying MMS_S and the payload limit) to the newest snapshot and acknowledges exactly that version; a failing client stays dirty without stopping the others, and stateless leases and every physical submission revalidate against the current version. Dual-family Host tests (two TCP flows plus a UDP flow, held scalar, zero-copy and partial software GSO reservations, a randomized multi-client model), native reservation-race tests and the isolated namespace shared-fanout case, in which a real router PTB quotes only TCP flow A, verify it.
//# The packetization layers must be notified about decreases in the PMTU. Any packetization layer instance (for example, a TCP connection) that is actively using the path must be notified if the PMTU estimate is decreased.
//= https://www.rfc-editor.org/rfc/rfc8201#section-5.2
//= type=test
//= reason=PathService marks every client of a path dirty on each trusted decrease and on link MTU, route, source, link or plateau changes. Host::service_changes, run on every native service_egress and MTU-refresh pass and every tun_echo transmit pass, brings each dirty TCP binding (reserved owners included, budget only, no repair) and each Host UDP flow (a coalesced per-flow change slot carrying MMS_S and the payload limit) to the newest snapshot and acknowledges exactly that version; a failing client stays dirty without stopping the others, and stateless leases and every physical submission revalidate against the current version. Dual-family Host tests (two TCP flows plus a UDP flow, held scalar, zero-copy and partial software GSO reservations, a randomized multi-client model), native reservation-race tests and the isolated namespace shared-fanout case, in which a real router PTB quotes only TCP flow A, verify it.
//# The packetization layers must be notified about decreases in the PMTU. Any packetization layer instance (for example, a TCP connection) that is actively using the path must be notified if the PMTU estimate is decreased.
//= https://www.rfc-editor.org/rfc/rfc8201#section-5.1
//= type=test
//= reason=PathService stores IPv6 estimates and Host ICMPv6 dispatch processes correlated Packet Too Big messages. TCP learns MMS_S changes through Host::service_changes budget application; a Host UDP flow reads MMS_S and its payload limit with Host::udp_path_limits and receives each shared change through Host::udp_path_change (coalesced to the newest version and not consumed by sends), without a failed send. Dual-family Host tests, tun_echo and the isolated namespace shared-fanout case verify it.
//# It is therefore suggested that the IP layer store PMTU information and that the ICMPv6 layer process received Packet Too Big messages. The packetization layers may respond to changes in the PMTU by changing the size of the messages they send. To support this layering, packetization layers require a way to learn of changes in the value of MMS_S, the "maximum send transport-message size" [RFC1122].
fn quoted_flow_decrease_reaches_every_subscriber_and_isolated_paths_stay_unchanged() {
    for v6 in [false, true] {
        let cfg = config(4);
        let (local, remote) = addresses(v6);
        let mut a = isolating_side(local, 4100 + u64::from(v6), &cfg);
        let mut b = managed(remote, 4200 + u64::from(v6), cfg.clone());
        let listener = b.1.listen(remote, 4).unwrap();
        let flow_a = connect(&mut a, &cfg, 1000, 0);
        let flow_b = connect(&mut a, &cfg, 1001, 0);
        let isolated_tcp = connect(&mut a, &cfg, 1002, 8);
        // Differs from the shared path only by its local source.
        let source_tcp = connect_from(&mut a, &cfg, second_source(v6), 1003);
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        let children: Vec<_> = (0..4).map(|_| b.1.accept(listener).unwrap()).collect();
        let shared = flow(&mut a, 5000, remote.ip(), 0);
        let isolated_class = flow(&mut a, 5001, remote.ip(), 8);
        let isolated_host = flow(&mut a, 5002, other_remote(v6), 0);
        let isolated_link = flow(&mut a, 5003, link_remote(v6), 0);
        let path = a.0.binding(flow_a).unwrap().snapshot.path();
        assert_eq!(a.0.binding(flow_b).unwrap().snapshot.path(), path);
        assert_eq!(limits(&mut a, shared).path, path);
        let (class_path, host_path, link_path) = (
            limits(&mut a, isolated_class).path,
            limits(&mut a, isolated_host).path,
            limits(&mut a, isolated_link).path,
        );
        let isolated = [
            a.0.binding(isolated_tcp).unwrap().snapshot,
            a.0.paths().path_snapshot(class_path).unwrap(),
            a.0.paths().path_snapshot(host_path).unwrap(),
            a.0.binding(source_tcp).unwrap().snapshot,
            a.0.paths().path_snapshot(link_path).unwrap(),
        ];
        assert!(isolated.iter().all(|s| s.path() != path));
        let key = a.0.binding(flow_a).unwrap().snapshot.key();
        let (by_source, by_link) = (isolated[3].key(), isolated[4].key());
        assert_ne!(by_source.source(), key.source());
        assert_eq!(
            (by_source.destination(), by_source.dscp(), by_source.link()),
            (key.destination(), key.dscp(), key.link())
        );
        assert_ne!(by_link.link(), key.link());
        assert_eq!((by_link.source(), by_link.dscp()), (key.source(), key.dscp()));
        assert_eq!(service(&mut a, now), ServiceReport::default());
        let before_b = a.1.transport_info(flow_b).unwrap();
        let mss_isolated = a.1.transport_info(isolated_tcp).unwrap().mss;
        let budget_source = a.1.managed_path(source_tcp).unwrap().ordinary_ip_budget;

        a.1.write(flow_a, &[1; 1400]).unwrap();
        now += 10;
        let (quoted, _) = send(&mut a, now, BackendOutcome::Submitted).unwrap();
        let mtu = if v6 { 1280 } else { 1100 };
        assert!(decreased(
            a.0.input_icmp(&mut a.1, a.2, now + 1, &ptb(&quoted, mtu), None)
                .unwrap()
        ));
        assert!(dirty(&a, flow_b));
        assert_eq!(a.0.udp_path_change(shared).unwrap(), None, "nothing sent");
        let report = service(&mut a, now + 2);
        assert_eq!(
            (
                report.decreased + report.raised,
                report.applied,
                report.failed,
                report.first_error
            ),
            (0, 3, 0, None)
        );
        let newest = a.0.paths().path_snapshot(path).unwrap();
        assert_eq!(newest.learned_mtu(), Some(mtu));
        for id in [flow_a, flow_b] {
            assert_eq!(a.0.binding(id).unwrap().snapshot, newest);
            assert!(!dirty(&a, id));
            assert_eq!(a.1.managed_path(id).unwrap().binding.snapshot, newest);
        }
        let (min_ip, udp_overhead) = overhead(v6);
        let change = a.0.udp_path_change(shared).unwrap().unwrap();
        assert_eq!(
            (change.path, change.version),
            (newest.path(), newest.version())
        );
        assert_eq!(change.destination, remote.ip());
        assert_eq!(change.mms_s, mtu - min_ip);
        assert_eq!(change.max_payload, mtu as usize - udp_overhead);
        assert_eq!(a.0.udp_path_change(shared).unwrap(), None, "consumed once");
        let after_b = a.1.transport_info(flow_b).unwrap();
        assert_eq!(after_b.mss, mtu - if v6 { 72 } else { 52 });
        assert_eq!(
            (after_b.lost, after_b.retransmitted, after_b.unacked),
            (before_b.lost, before_b.retransmitted, before_b.unacked),
            "no repair on the unquoted flow"
        );
        // Isolated paths: same version, no notification, unchanged budget.
        assert_eq!(a.0.binding(isolated_tcp).unwrap().snapshot, isolated[0]);
        assert_eq!(a.1.transport_info(isolated_tcp).unwrap().mss, mss_isolated);
        assert_eq!(a.0.binding(source_tcp).unwrap().snapshot, isolated[3]);
        assert_eq!(
            a.1.managed_path(source_tcp).unwrap().ordinary_ip_budget,
            budget_source
        );
        for (id, old) in [
            (isolated_class, isolated[1]),
            (isolated_host, isolated[2]),
            (isolated_link, isolated[4]),
        ] {
            assert_eq!(a.0.udp_path_change(id).unwrap(), None);
            let current = a.0.paths().path_snapshot(old.path()).unwrap();
            assert_eq!(
                (current.version(), current.learned_mtu()),
                (old.version(), None)
            );
        }
        // B completes a transfer within the new limit.
        a.1.write(flow_b, &[2; 1400]).unwrap();
        now += 10;
        for _ in 0..64 {
            now += 10;
            let Some(frame) = emit(&mut a.0, &mut a.1, now) else {
                break;
            };
            assert!(frame.len() <= mtu as usize);
            input(&mut b.0, &mut b.1, b.2, now + 1, &frame, 0);
            pump(&mut b, &mut a, &mut now);
        }
        pump(&mut a, &mut b, &mut now);
        let mut bytes = [0; 2000];
        assert_eq!(b.1.read(children[1], &mut bytes).unwrap(), 1400);
        std::println!(
            "FANOUT v6={v6} version={} mtu={mtu} applied={} udp_payload={} isolated=5 (dscp, destination, source, link) unchanged",
            newest.version(),
            report.applied,
            change.max_payload
        );
    }
}

// Paths that differ from the shared one only by local source (a real TCP
// owner) or by link (a Host UDP flow) keep their version, learned MTU, TCP
// ordinary budget and UDP change slot through every kind of shared
// publication: an immediate decrease, a timeout-applied pending report and
// a probe-confirmed raise.
#[test]
fn source_and_link_isolated_paths_survive_every_shared_publication() {
    for v6 in [false, true] {
        let cfg = config(4);
        let units = cfg.connection.timebase.units_per_second;
        let (local, remote) = addresses(v6);
        let mut a = isolating_side(local, 5500 + u64::from(v6), &cfg);
        let mut b = managed(remote, 5600 + u64::from(v6), cfg.clone());
        let listener = b.1.listen(remote, 4).unwrap();
        let flow_a = connect(&mut a, &cfg, 1000, 0);
        let flow_b = connect(&mut a, &cfg, 1001, 0);
        let source_tcp = connect_from(&mut a, &cfg, second_source(v6), 1002);
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        for _ in 0..3 {
            b.1.accept(listener).unwrap();
        }
        let link_udp = flow(&mut a, 5001, link_remote(v6), 0);
        let path = a.0.binding(flow_a).unwrap().snapshot.path();
        let source_path = a.0.binding(source_tcp).unwrap().snapshot.path();
        let link_path = limits(&mut a, link_udp).path;
        assert!(source_path != path && link_path != path && source_path != link_path);
        assert_eq!(service(&mut a, now), ServiceReport::default());
        let observe = |a: &mut Side| {
            (
                a.0.paths().path_snapshot(source_path).unwrap(),
                a.0.binding(source_tcp).unwrap().snapshot,
                a.1.managed_path(source_tcp).unwrap().ordinary_ip_budget,
                a.0.paths().path_snapshot(link_path).unwrap(),
                a.0.udp_path_change(link_udp).unwrap(),
            )
        };
        let initial = observe(&mut a);
        assert_eq!((initial.0.learned_mtu(), initial.3.learned_mtu()), (None, None));
        assert_eq!(initial.4, None);

        // (1) An immediate decrease quoting A.
        let first = if v6 { 1400 } else { 1200 };
        a.1.write(flow_a, &[1; 1400]).unwrap();
        now += 10;
        let (quoted, _) = send(&mut a, now, BackendOutcome::Submitted).unwrap();
        assert!(decreased(
            a.0.input_icmp(&mut a.1, a.2, now + 1, &ptb(&quoted, first), None)
                .unwrap()
        ));
        assert_eq!(service(&mut a, now + 2).failed, 0);
        assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), Some(first));
        assert_eq!(observe(&mut a), initial, "after the decrease");
        // Its delivery proves the original size.
        input(&mut b.0, &mut b.1, b.2, now + 3, &quoted, 0);
        pump(&mut b, &mut a, &mut now);
        assert_eq!(a.1.transport_info(flow_a).unwrap().unacked, 0);

        // (2) A report below that proof, applied at its own timeout.
        let second = if v6 { 1300 } else { 1000 };
        a.1.write(flow_a, &[2; 1400]).unwrap();
        now += 10;
        let (quoted, _) = send(&mut a, now, BackendOutcome::Submitted).unwrap();
        let (report, published) = tcp_report(
            a.0.input_icmp(&mut a.1, a.2, now + 1, &ptb(&quoted, second), None)
                .unwrap(),
        );
        assert_eq!(
            (report, published),
            (TcpReport::PacketTooBig(PmtuFeedback::Deferred), None)
        );
        let mut pending = 0;
        for _ in 0..16 {
            now = now.max(a.1.next_deadline().unwrap());
            a.1.on_timeout(now, 32).unwrap();
            while send(&mut a, now, BackendOutcome::Submitted).is_some() {}
            pending += service(&mut a, now + 1).decreased;
            assert_eq!(observe(&mut a), initial, "while pending");
            if pending > 0 {
                break;
            }
        }
        assert_eq!(pending, 1);
        assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), Some(second));
        for _ in 0..16 {
            if a.1.transport_info(flow_a).unwrap().unacked == 0 {
                break;
            }
            now = now.max(a.1.next_deadline().unwrap());
            a.1.on_timeout(now, 32).unwrap();
            pump(&mut a, &mut b, &mut now);
        }
        assert_eq!(a.1.transport_info(flow_a).unwrap().unacked, 0);
        assert_eq!(service(&mut a, now).failed, 0);
        assert_eq!(observe(&mut a), initial, "after the pending publication");

        // (3) B's real probe after the hold, acknowledged by the peer.
        let hold = a.0.binding(flow_b).unwrap().snapshot.retry_not_before();
        now = now.max(hold) + 601 * units;
        a.1.write(flow_b, &[7; 6000]).unwrap();
        let (attempt, _, probe) = selected(&mut a.1, now).unwrap();
        let intent = a.1.transmit_discovery_intent(attempt).expect("real probe");
        let context = a.0.egress_context(&mut a.1, attempt).unwrap();
        let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
        let submitted =
            a.0.submit(&mut a.1, now, ticket, context, &probe, 0, |_| BackendOutcome::Submitted)
                .unwrap();
        assert!(submitted == Submission::Submitted);
        input(&mut b.0, &mut b.1, b.2, now + 1, &probe, 0);
        let ack = emit(&mut b.0, &mut b.1, now + 2).unwrap();
        input(&mut a.0, &mut a.1, a.2, now + 3, &ack, 0);
        let report = service(&mut a, now + 4);
        assert_eq!((report.raised, report.failed), (1, 0));
        let raised = a.0.paths().path_snapshot(path).unwrap().learned_mtu();
        assert_eq!(raised, Some(intent.ip_packet_len()));
        assert!(raised.unwrap() > second);
        assert_eq!(observe(&mut a), initial, "after the raise");
        std::println!(
            "ISOLATED v6={v6} shared={first}->{second}->{} source_version={} link_version={} unchanged after decrease, pending and raise",
            raised.unwrap(),
            initial.0.version(),
            initial.3.version()
        );
    }
}

// A route change replaces the shared path's generation. Feedback quoting a
// pre-change submission, which like Linux applies to the connection's
// current path, decreases the new generation, and a confirmed raise follows
// on it; both leave the retired record unchanged and never resurrect it.
#[test]
fn retired_route_generation_is_never_changed_or_resurrected() {
    for v6 in [false, true] {
        let cfg = config(4);
        let units = cfg.connection.timebase.units_per_second;
        let (local, remote) = addresses(v6);
        let mut a = udp_side(local, 5700 + u64::from(v6), &cfg);
        let mut b = managed(remote, 5800 + u64::from(v6), cfg.clone());
        let listener = b.1.listen(remote, 4).unwrap();
        let flow_a = connect(&mut a, &cfg, 1000, 0);
        let flow_b = connect(&mut a, &cfg, 1001, 0);
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        for _ in 0..2 {
            b.1.accept(listener).unwrap();
        }
        let udp = flow(&mut a, 5000, remote.ip(), 0);
        let old = a.0.binding(flow_a).unwrap().snapshot.path();
        a.1.write(flow_a, &[3; 1400]).unwrap();
        now += 10;
        let (stale, _) = send(&mut a, now, BackendOutcome::Submitted).unwrap();
        a.0.add_route(path::Route {
            destination: path::IpPrefix::new(remote.ip(), if v6 { 128 } else { 32 }).unwrap(),
            source: None,
            dscp: None,
            link: a.2.link(),
            next_hop: path::NextHop::Forwarder(ForwarderId(9)),
            metric: 0,
        })
        .unwrap();
        assert_eq!(service(&mut a, now + 1).failed, 0);
        let new = a.0.binding(flow_a).unwrap().snapshot.path();
        assert_ne!(new, old);
        assert_eq!(a.0.binding(flow_b).unwrap().snapshot.path(), new);
        assert_eq!(limits(&mut a, udp).path, new);
        a.0.udp_path_change(udp).unwrap();
        let retired = a.0.paths().path_snapshot(old);
        assert!(retired.is_err() || retired.unwrap().status() != path::PathStatus::Valid);
        let not_resurrected = |a: &Side| {
            let now = a.0.paths().path_snapshot(old);
            assert_eq!(now, retired, "retired record unchanged");
            assert!(now.is_err() || now.unwrap().status() != path::PathStatus::Valid);
            assert!([flow_a, flow_b]
                .iter()
                .all(|&id| a.0.binding(id).unwrap().snapshot.path() == new));
        };

        // A PTB quoting the pre-change submission is about the connection,
        // whose current path is the new generation.
        let mtu = if v6 { 1350 } else { 1100 };
        let (report, published) = tcp_report(
            a.0.input_icmp(&mut a.1, a.2, now + 2, &ptb(&stale, mtu), None)
                .unwrap(),
        );
        assert!(matches!(report, TcpReport::PacketTooBig(_)));
        assert_ne!(report, TcpReport::PacketTooBig(PmtuFeedback::Rejected));
        assert_eq!(published, Some(path::EstimateChange::Decreased));
        assert_eq!(service(&mut a, now + 3).failed, 0);
        assert_eq!(
            a.0.paths().path_snapshot(new).unwrap().learned_mtu(),
            Some(mtu)
        );
        assert_eq!(a.0.udp_path_change(udp).unwrap().unwrap().path, new);
        not_resurrected(&a);
        input(&mut b.0, &mut b.1, b.2, now + 7, &stale, 0);
        pump(&mut b, &mut a, &mut now);
        for _ in 0..16 {
            if a.1.transport_info(flow_a).unwrap().unacked == 0 {
                break;
            }
            now = now.max(a.1.next_deadline().unwrap());
            a.1.on_timeout(now, 32).unwrap();
            pump(&mut a, &mut b, &mut now);
        }
        assert_eq!(a.1.transport_info(flow_a).unwrap().unacked, 0);

        // A confirmed raise on the new generation (B's real probe).
        let hold = a.0.binding(flow_b).unwrap().snapshot.retry_not_before();
        now = now.max(hold) + 601 * units;
        a.1.write(flow_b, &[7; 6000]).unwrap();
        let (attempt, _, probe) = selected(&mut a.1, now).unwrap();
        let intent = a.1.transmit_discovery_intent(attempt).expect("real probe");
        assert_eq!(intent.binding().snapshot.path(), new);
        let context = a.0.egress_context(&mut a.1, attempt).unwrap();
        let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
        assert!(
            a.0.submit(&mut a.1, now, ticket, context, &probe, 0, |_| BackendOutcome::Submitted)
                .unwrap()
                == Submission::Submitted
        );
        input(&mut b.0, &mut b.1, b.2, now + 1, &probe, 0);
        let ack = emit(&mut b.0, &mut b.1, now + 2).unwrap();
        input(&mut a.0, &mut a.1, a.2, now + 3, &ack, 0);
        assert_eq!(service(&mut a, now + 4).raised, 1);
        assert_eq!(
            a.0.paths().path_snapshot(new).unwrap().learned_mtu(),
            Some(intent.ip_packet_len())
        );
        not_resurrected(&a);
        std::println!(
            "ROUTE_GENERATION v6={v6} retired_retained={} pre-change ptb on new: {mtu}->{} retired unchanged",
            retired.is_ok(),
            intent.ip_packet_len()
        );
    }
}

// A router PTB quoting a Host UDP datagram lowers the shared path; the
// change service then notifies every TCP connection using that path (budget
// only, no repair) and the sending UDP flow, without any TCP output.
#[test]
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
//= type=test
//= reason=A correlated router PTB quoting a Host UDP datagram publishes the decrease to the shared path, and Host::service_changes then applies it to every TCP connection bound to that path (budget only, no repair) on the next native or tun_echo service pass, before any TCP output. Dual-family Host tests and the tun_echo and isolated namespace udp-quoted cases verify it. Sentence continuation is preserved in 1191-060.
//# Note: even if the Datagram Too Big message contains an Original Datagram Header that refers to a UDP packet, the TCP layer must be notified if any of its connections use the given
//= https://www.rfc-editor.org/rfc/rfc8201#section-5.2
//= type=test
//= reason=A correlated router PTB quoting a Host UDP datagram publishes the decrease to the shared path, and Host::service_changes then applies it to every TCP connection bound to that path (budget only, no repair) on the next native or tun_echo service pass, before any TCP output. Dual-family Host tests and the tun_echo and isolated namespace udp-quoted cases verify it.
//# Note: even if the Packet Too Big message contains an Original Packet Header that refers to a UDP packet, the TCP layer must be notified if any of its connections use the given path.
fn udp_quoted_decrease_notifies_every_tcp_connection_on_the_path() {
    for v6 in [false, true] {
        let cfg = config(4);
        let (local, remote) = addresses(v6);
        let mut a = udp_side(local, 4150 + u64::from(v6), &cfg);
        let mut b = managed(remote, 4250 + u64::from(v6), cfg.clone());
        b.1.listen(remote, 4).unwrap();
        let tcp = [
            connect(&mut a, &cfg, 1000, 0),
            connect(&mut a, &cfg, 1001, 0),
        ];
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        let udp = flow(&mut a, 5000, remote.ip(), 0);
        let path = a.0.binding(tcp[0]).unwrap().snapshot.path();
        assert_eq!(limits(&mut a, udp).path, path);
        let before: Vec<_> = tcp
            .iter()
            .map(|&id| a.1.transport_info(id).unwrap())
            .collect();
        let mut packet = [0; 1600];
        let Ok(UdpSent::Submitted(n)) =
            a.0.udp_send(&a.1, now, udp, None, &[3; 1400], &mut packet, |_, _| {
                BackendOutcome::Submitted
            })
        else {
            panic!("datagram not submitted");
        };
        let mtu = if v6 { 1280 } else { 1000 };
        let dispatch =
            a.0.input_icmp(&mut a.1, a.2, now + 1, &ptb(&packet[..n], mtu), None);
        assert!(matches!(
            dispatch,
            Ok(IcmpDispatch::Completed(IcmpOutcome::Advice {
                published: Some(path::EstimateChange::Decreased),
                ..
            }))
        ));
        assert!(tcp.iter().all(|&id| dirty(&a, id)));
        let report = service(&mut a, now + 2);
        assert_eq!((report.applied, report.failed), (3, 0));
        let newest = a.0.paths().path_snapshot(path).unwrap();
        assert_eq!(newest.learned_mtu(), Some(mtu));
        for (&id, old) in tcp.iter().zip(&before) {
            assert_eq!(a.0.binding(id).unwrap().snapshot, newest);
            let info = a.1.transport_info(id).unwrap();
            assert_eq!(info.mss, mtu - if v6 { 72 } else { 52 });
            assert_eq!(
                (info.lost, info.retransmitted),
                (old.lost, old.retransmitted)
            );
        }
        assert_eq!(
            a.0.udp_path_change(udp).unwrap().unwrap().version,
            newest.version()
        );
        std::println!(
            "UDP_QUOTED v6={v6} tcp_notified=2 mss={}",
            mtu - if v6 { 72 } else { 52 }
        );
    }
}

// A quoted fragment is evidence only of a fragment this Host submitted: one
// built from an unfragmented datagram (a first fragment with its UDP header,
// or a later fragment carrying its bytes) matches nothing even when its
// addresses and leading bytes match a live datagram, and changes nothing;
// the unfragmented quote still correlates afterwards.
#[test]
fn fragment_quotes_of_unfragmented_datagrams_do_not_correlate() {
    for v6 in [false, true] {
        let cfg = config(4);
        let (local, remote) = addresses(v6);
        let mut a = udp_side(local, 4170 + u64::from(v6), &cfg);
        let udp = flow(&mut a, 5000, remote.ip(), 0);
        let path = limits(&mut a, udp).path;
        let mut packet = [0; 1600];
        let Ok(UdpSent::Submitted(n)) =
            a.0.udp_send(&a.1, 0, udp, None, &[3; 1400], &mut packet, |_, _| {
                BackendOutcome::Submitted
            })
        else {
            panic!("datagram not submitted");
        };
        let sent = &packet[..n];
        let fragment = if v6 {
            // The same bytes behind a Fragment header: a later fragment.
            let mut f = sent[..40].to_vec();
            f[6] = 44;
            let payload = u16::from_be_bytes([f[4], f[5]]) + 8;
            f[4..6].copy_from_slice(&payload.to_be_bytes());
            f.extend_from_slice(&[17, 0, 0, 8 | 1, 0, 0, 0, 1]);
            f.extend_from_slice(&sent[40..]);
            f
        } else {
            // MF set: a first fragment with the datagram's UDP header.
            let mut f = sent.to_vec();
            f[6] |= 0x20;
            seal_ipv4(&mut f);
            f
        };
        let mtu: u32 = if v6 { 1280 } else { 1000 };
        // A router error quoting the fragment's header and 8 data octets.
        let quote = &fragment[..if v6 { 56 } else { 28 }];
        let outer = IpMetadata {
            source: if v6 { "2001:db8::fe" } else { "192.0.2.254" }
                .parse()
                .unwrap(),
            destination: local.ip(),
        };
        let mut message = vec![0; 8 + quote.len()];
        message[0] = if v6 { 2 } else { 3 };
        message[1] = if v6 { 0 } else { 4 };
        message[4..8].copy_from_slice(&mtu.to_be_bytes());
        message[8..].copy_from_slice(quote);
        let sum = if v6 {
            ntcp_icmp::icmpv6_checksum(outer, &message).unwrap()
        } else {
            ntcp_icmp::checksum(&message)
        };
        message[2..4].copy_from_slice(&sum.to_be_bytes());
        let mut report = vec![0; 40 + message.len()];
        let n = if v6 {
            report[40..].copy_from_slice(&message);
            let h = ntcp_ip6::Header {
                ip: outer,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
            };
            ntcp_ip6::encode_datagram(&mut report, h, 58, message.len()).unwrap()
        } else {
            report[20..20 + message.len()].copy_from_slice(&message);
            let h = ntcp_ip::Header {
                ip: outer,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: Default::default(),
            };
            ntcp_ip::encode_datagram(&mut report, h, 1, message.len(), 0).unwrap()
        };
        assert_eq!(
            a.0.input_icmp(&mut a.1, a.2, 1, &report[..n], None).unwrap(),
            IcmpDispatch::Completed(IcmpOutcome::Discarded(IcmpDiscard::Uncorrelated))
        );
        assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), None);
        assert_eq!(a.0.udp_event(udp).unwrap(), None);
        assert!(matches!(
            a.0.input_icmp(&mut a.1, a.2, 2, &ptb(sent, mtu), None),
            Ok(IcmpDispatch::Completed(IcmpOutcome::Advice {
                published: Some(path::EstimateChange::Decreased),
                ..
            }))
        ));
    }
}

// A client whose rebind fails stays dirty and reports the failure without
// stopping service of the others; it converges once authority returns.
#[test]
fn failed_client_stays_dirty_while_others_are_served() {
    for v6 in [false, true] {
        let cfg = config(4);
        let (local, remote) = addresses(v6);
        let mut a = udp_side(local, 4300 + u64::from(v6), &cfg);
        let mut b = managed(remote, 4400 + u64::from(v6), cfg.clone());
        b.1.listen(remote, 4).unwrap();
        let flow_a = connect(&mut a, &cfg, 1000, 0);
        let flow_b = connect(&mut a, &cfg, 1001, 0);
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        let shared = flow(&mut a, 5000, remote.ip(), 0);
        let stranded = flow(&mut a, 5002, other_remote(v6), 0);
        let old = limits(&mut a, stranded);
        // A TCP connection to the same other host, never sent (its SYN would
        // reach no peer); its binding exists from connect.
        let stranded_tcp =
            a.1.connect_with_path_provider(
                now,
                SocketAddr::new(local.ip(), 1002),
                SocketAddr::new(other_remote(v6), remote.port()),
                options(&cfg, 0),
                &mut a.0,
            )
            .unwrap();
        let old_tcp = a.0.binding(stranded_tcp).unwrap().snapshot;
        assert_eq!(old_tcp.path(), old.path);
        // A more specific route through a forwarder this port does not serve
        // invalidates only the stranded clients' path, and rebinding fails.
        let bad =
            a.0.add_route(path::Route {
                destination: path::IpPrefix::new(other_remote(v6), if v6 { 128 } else { 32 })
                    .unwrap(),
                source: None,
                dscp: None,
                link: a.2.link(),
                next_hop: path::NextHop::Forwarder(ForwarderId(7)),
                metric: 0,
            })
            .unwrap();
        let path = a.0.binding(flow_a).unwrap().snapshot.path();
        a.0.trusted_decrease(now, path, if v6 { 1300 } else { 1200 })
            .unwrap();
        let report = service(&mut a, now);
        assert_eq!(
            (report.applied, report.failed, report.first_error),
            (3, 2, Some(Error::Unsupported))
        );
        assert!(!dirty(&a, flow_a) && !dirty(&a, flow_b));
        assert!(
            dirty(&a, stranded_tcp),
            "the failed TCP binding stays dirty"
        );
        assert_eq!(a.0.binding(stranded_tcp).unwrap().snapshot, old_tcp);
        assert!(a.0.udp_path_change(shared).unwrap().is_some());
        assert_eq!(a.0.udp_path_change(stranded).unwrap(), None);
        assert_eq!(service(&mut a, now).failed, 2, "retried, still dirty");
        a.0.remove_route(bad).unwrap();
        let report = service(&mut a, now);
        assert_eq!((report.applied, report.failed), (2, 0));
        assert!(!dirty(&a, stranded_tcp));
        let rebound = a.0.binding(stranded_tcp).unwrap().snapshot;
        assert_eq!(
            a.1.managed_path(stranded_tcp).unwrap().binding.snapshot,
            rebound
        );
        let change = a.0.udp_path_change(stranded).unwrap().unwrap();
        assert!(change.version > old.version);
        assert_eq!(
            (change.path, change.version),
            (rebound.path(), rebound.version())
        );
        assert_eq!(change.max_payload, old.max_payload);
        assert_eq!(service(&mut a, now), ServiceReport::default());
        std::println!(
            "ISOLATION v6={v6}: failed=2 (TCP+UDP) others served, recovered after route removal"
        );
    }
}

// Many changes before the application reads leave one notification, the
// newest; a send that acknowledges the path meanwhile does not consume it;
// the advice queue is separate; a closed flow's successor inherits nothing.
#[test]
fn change_notifications_coalesce_survive_sends_and_end_with_the_flow() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (local, remote) = addresses(v6);
        let mut a = udp_side(local, 4500 + u64::from(v6), &cfg);
        let id = flow(&mut a, 5000, remote.ip(), 0);
        let path = limits(&mut a, id).path;
        let sizes: &[u32] = if v6 {
            &[1480, 1450, 1400, 1350, 1320, 1300]
        } else {
            &[1400, 1300, 1200, 1100, 1000, 900]
        };
        let mut sent = 0;
        for (n, mtu) in sizes.iter().enumerate() {
            a.0.trusted_decrease(n as u64, path, *mtu).unwrap();
            if n % 2 == 0 {
                service(&mut a, n as u64);
            } else {
                // The send acknowledges the newest version itself.
                let mut packet = [0; 1500];
                let result = a.0.udp_send(
                    &a.1,
                    n as u64,
                    id,
                    None,
                    &[n as u8; 64],
                    &mut packet,
                    |_, _| BackendOutcome::Submitted,
                );
                assert!(matches!(result, Ok(UdpSent::Submitted(_))));
                sent += 1;
            }
        }
        a.0.set_link_mtu(a.2.link(), 1400).unwrap();
        service(&mut a, 10);
        let newest = a.0.paths().path_snapshot(path).unwrap();
        let change = a.0.udp_path_change(id).unwrap().unwrap();
        assert_eq!(
            (change.path, change.version),
            (newest.path(), newest.version())
        );
        assert_eq!(change, limits(&mut a, id));
        assert_eq!(a.0.udp_path_change(id).unwrap(), None);
        assert_eq!(a.0.udp_event(id).unwrap(), None, "advice is separate");
        // A change acknowledged by a send before service is still reported.
        a.0.trusted_decrease(10, path, sizes[sizes.len() - 1] - 8)
            .unwrap();
        let mut packet = [0; 1500];
        assert!(matches!(
            a.0.udp_send(&a.1, 10, id, None, &[1; 64], &mut packet, |_, _| {
                BackendOutcome::Submitted
            }),
            Ok(UdpSent::Submitted(_))
        ));
        assert_eq!(service(&mut a, 10).applied, 0, "the send acknowledged it");
        let raced = a.0.udp_path_change(id).unwrap().unwrap();
        assert!(raced.version > change.version);
        assert_eq!(raced.max_payload, change.max_payload.min(raced.max_payload));
        let change = raced;
        // An oversized datagram is refused with the same limit, unsent.
        let mut packet = [0; 1500];
        let too_big = a.0.udp_send(
            &a.1,
            11,
            id,
            None,
            &vec![0; change.max_payload + 1],
            &mut packet,
            |_, _| unreachable!("refused before any backend call"),
        );
        assert_eq!(
            too_big,
            Err(UdpSendError::TooBig {
                max_payload: change.max_payload
            })
        );
        // Close with a pending change; the slot's successor starts clean.
        a.0.set_link_mtu(a.2.link(), 1500).unwrap();
        a.0.udp_close(id).unwrap();
        assert_eq!(a.0.udp_path_change(id), Err(Error::Obsolete));
        let reopened = flow(&mut a, 5000, remote.ip(), 0);
        service(&mut a, 13);
        assert_eq!(a.0.udp_path_change(reopened).unwrap(), None);
        std::println!(
            "COALESCE v6={v6}: {} changes, {sent} sends, one notification version={}",
            sizes.len() + 1,
            newest.version()
        );
    }
}

// An unconnected flow pinned to X re-pins to Y before X's change is
// serviced: the notification names X with X's newest limits (nothing once
// X's path is no longer valid), never Y, and Y's sizing is Y's own.
#[test]
fn repinned_flow_reports_the_changed_destination_never_the_new_pin() {
    for v6 in [false, true] {
        for invalidated in [false, true] {
            for send_to_y in [false, true] {
                let cfg = config(2);
                let (local, remote) = addresses(v6);
                let mut a = udp_side(local, 4550 + u64::from(v6), &cfg);
                let options = UdpOptions {
                    dscp: 0,
                    hop_limit: 64,
                };
                let local = SocketAddr::new(local.ip(), 5000);
                let id = a.0.udp_open(&a.1, local, None, options).unwrap();
                let (x, y) = (remote.ip(), other_remote(v6));
                let mut packet = [0; 1600];
                let mut send = |a: &mut Side, to: IpAddr, len: usize| {
                    let to = Some(SocketAddr::new(to, 7));
                    a.0.udp_send(&a.1, 1, id, to, &vec![5; len], &mut packet, |_, _| {
                        BackendOutcome::Submitted
                    })
                };
                assert!(matches!(send(&mut a, x, 64), Ok(UdpSent::Submitted(_))));
                let pinned = a.0.udp_path_limits(&a.1, id, Some(x)).unwrap();
                let lowered = if v6 { 1300 } else { 1000 };
                a.0.trusted_decrease(2, pinned.path, lowered).unwrap();
                if invalidated {
                    a.0.add_route(path::Route {
                        destination: path::IpPrefix::new(x, if v6 { 128 } else { 32 }).unwrap(),
                        source: None,
                        dscp: None,
                        link: a.2.link(),
                        next_hop: path::NextHop::Forwarder(ForwarderId(9)),
                        metric: 0,
                    })
                    .unwrap();
                }
                let x_newest = a.0.paths().path_snapshot(pinned.path).unwrap();
                assert_eq!(x_newest.status() == path::PathStatus::Valid, !invalidated);
                let (_, udp_overhead) = overhead(v6);
                if send_to_y {
                    // Larger than X's new limit, within Y's own.
                    let len = lowered as usize - udp_overhead + 1;
                    assert!(matches!(send(&mut a, y, len), Ok(UdpSent::Submitted(_))));
                }
                let y_limits = a.0.udp_path_limits(&a.1, id, Some(y)).unwrap();
                let y_snapshot = a.0.paths().path_snapshot(y_limits.path).unwrap();
                assert_ne!(y_limits.path, pinned.path);
                assert_eq!(
                    (y_limits.destination, y_limits.version, y_limits.max_payload),
                    (
                        y,
                        y_snapshot.version(),
                        y_snapshot.ip_packet_budget().unwrap() as usize - udp_overhead
                    )
                );
                assert!(y_limits.max_payload > lowered as usize - udp_overhead);
                let change = a.0.udp_path_change(id).unwrap();
                if invalidated {
                    assert_eq!(change, None, "no invented limits for an invalid path");
                } else {
                    let change = change.unwrap();
                    assert_eq!(
                        (change.destination, change.path, change.version),
                        (x, pinned.path, x_newest.version())
                    );
                    assert_eq!(change.max_payload, lowered as usize - udp_overhead);
                }
                assert_eq!(a.0.udp_path_change(id).unwrap(), None, "nothing for Y");
                service(&mut a, 3);
                assert_eq!(a.0.udp_path_change(id).unwrap(), None, "nothing for Y");
                std::println!(
                    "REPIN v6={v6} invalidated={invalidated} send_to_y={send_to_y} y_payload={} x_reported={}",
                    y_limits.max_payload,
                    !invalidated
                );
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Pending {
    Applied,
    AckCancelled,
    Released,
    Rebound,
    Subsumed,
}

// A report deferred below proven delivery and later applied at the quoted
// data's own timeout is published exactly once, for the same live owner and
// unchanged path incarnation; cancelled, released, rebound or subsumed
// results publish nothing.
#[test]
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
//= type=test
//= reason=PathService keeps per-host learned estimates keyed by the path, created on first use with the current route's first hop, and never changes forwarding routes. Host ICMP dispatch derives the estimate from a nonzero Next-Hop MTU or the RFC1191 section 5 plateau below the quoted length, corrected against the Host's shared path estimate, RFC 1191 section 5's current PMTU estimate, never the connection's estimate, requires a correlated quote (for a TCP connection, its four-tuple and an in-window quoted sequence, RFC 5927 section 4.1 as Linux checks it, about the connection's current path; otherwise committed submission evidence of a stateless reply or datagram) and lowers the per-host record only when lower. A correlated TCP report about the connection's current path at or above its proven delivery lowers the record at once (the larger of the Host and TCP estimates) and otherwise restarts its hold. One below proven delivery is deferred whatever the connection's loss-inferred estimate and changes nothing shared (no decrease, hold restart or notification) until the connection applies exactly that report at the quoted data's timeout; Host::service_changes then publishes the larger of the Host estimate and the report's own policy-derived size, so a loss-inferred value never leaks. Cumulative progress past the quoted data refutes it, and released owners, rebound paths and subsumed results publish nothing. Stale or evicted path incarnations are never resurrected or changed. Dual-family Host tests (including legacy IPv4 reports without a Next-Hop MTU, compared with and without prior black-hole loss inference: identical derived size, deferral and publication) and real router PTBs in the isolated namespace gate verify it.
//# When a Datagram Too Big message is received, the ICMP layer determines a new estimate for the Path MTU (either from a non-zero Next-Hop MTU value in the packet, or using the method described in section 5). If a per-host route for this path does not exist, then one is created (almost as if a per-host ICMP Redirect is being processed; the new route uses the same first-hop router as the current route). If the PMTU estimate associated with the per-host route is higher than the new estimate, then the value in the routing entry is changed.
fn applied_deferred_report_publishes_exactly_once_and_stale_results_never() {
    use Pending::*;
    for v6 in [false, true] {
        for case in [Applied, AckCancelled, Released, Rebound, Subsumed] {
            let cfg = config(4);
            let (local, remote) = addresses(v6);
            let mut a = managed(local, 4600 + u64::from(v6), cfg.clone());
            let mut b = managed(remote, 4700 + u64::from(v6), cfg.clone());
            let listener = b.1.listen(remote, 4).unwrap();
            let flow_a = connect(&mut a, &cfg, 1000, 0);
            let flow_b = connect(&mut a, &cfg, 1001, 0);
            let mut now = 0;
            pump(&mut a, &mut b, &mut now);
            b.1.accept(listener).unwrap();
            a.1.write(flow_a, &[2; 1400]).unwrap();
            pump(&mut a, &mut b, &mut now);
            a.1.write(flow_a, &[3; 1400]).unwrap();
            now += 10;
            let (outstanding, _) = send(&mut a, now, BackendOutcome::Submitted).unwrap();
            let mtu = if v6 { 1300 } else { 1100 };
            let dispatch =
                a.0.input_icmp(&mut a.1, a.2, now + 1, &ptb(&outstanding, mtu), None);
            assert!(matches!(
                dispatch,
                Ok(IcmpDispatch::Completed(IcmpOutcome::Tcp {
                    report: TcpReport::PacketTooBig(PmtuFeedback::Deferred),
                    published: None,
                    ..
                }))
            ));
            let path = a.0.binding(flow_a).unwrap().snapshot.path();
            let report = service(&mut a, now + 2);
            assert_eq!((report.decreased, report.raised), (0, 0));
            assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), None);
            if case == AckCancelled {
                input(&mut b.0, &mut b.1, b.2, now + 3, &outstanding, 0);
                pump(&mut b, &mut a, &mut now);
            }
            // Run the connection's timers until it retransmits the quoted
            // data (applying the report) or, cancelled, has nothing to send.
            for _ in 0..16 {
                let Some(deadline) = a.1.next_deadline() else {
                    break;
                };
                now = now.max(deadline);
                a.1.on_timeout(now, 32).unwrap();
                if send(&mut a, now, BackendOutcome::Submitted).is_some()
                    && a.1.path_mtu_info(flow_a).unwrap().unwrap().current_mtu <= mtu
                {
                    break;
                }
                if case == AckCancelled {
                    break;
                }
            }
            let applied = a.1.path_mtu_info(flow_a).unwrap().unwrap().current_mtu <= mtu;
            assert_eq!(applied, case != AckCancelled);
            let lower = if v6 { 1280 } else { 1000 };
            match case {
                Released => {
                    a.1.abort(flow_a).unwrap();
                    while emit(&mut a.0, &mut a.1, now).is_some() {}
                    a.1.release(flow_a).unwrap();
                }
                Rebound => {
                    a.0.add_route(path::Route {
                        destination: path::IpPrefix::new(remote.ip(), if v6 { 128 } else { 32 })
                            .unwrap(),
                        source: None,
                        dscp: None,
                        link: a.2.link(),
                        next_hop: path::NextHop::Forwarder(ForwarderId(9)),
                        metric: 0,
                    })
                    .unwrap();
                }
                Subsumed => {
                    a.0.trusted_decrease(now, path, lower).unwrap();
                }
                _ => {}
            }
            let report = service(&mut a, now + 1);
            let expected = usize::from(case == Applied);
            assert_eq!(
                (report.decreased, report.raised, report.failed),
                (expected, 0, 0),
                "{case:?}"
            );
            let again = service(&mut a, now + 2);
            assert_eq!((again.decreased, again.raised), (0, 0), "exactly once");
            let shared = a.0.paths().path_snapshot(path).unwrap();
            let learned = match case {
                Applied => Some(mtu),
                Subsumed => Some(lower),
                _ => None,
            };
            assert_eq!(shared.learned_mtu(), learned, "{case:?}");
            if case == Applied {
                // Every subscriber adopted it at the service pass.
                assert!(a.1.managed_path(flow_b).unwrap().ordinary_ip_budget <= mtu);
            }
            std::println!(
                "PENDING v6={v6} case={case:?} published={} learned={learned:?}",
                report.decreased
            );
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Probe {
    Confirmed,
    NewerDecrease,
    FreshUnchangedReport,
    PossiblySubmitted,
    Early,
    BeyondFirstHop,
    RouteChanged,
}

// A real probe selected after the real 600 s hold, definitely submitted and
// acknowledged, raises the shared ceiling: the other flow's ordinary budget
// rises without local delivery proof, and later ordinary ACKs never raise it
// again. A decrease or even a fresh unchanged report between the probe's
// selection and its ACK, a possibly submitted probe, output selected before
// the hold, a probe the first hop no longer carries, and a probe whose path
// a route change replaced publish nothing.
#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-5.2
//= type=test
//= reason=PathService is the IP-layer store of per-path state, keyed by context, source, destination/scope, routing DSCP, link, next hop and route generation. Host stores correlated ICMP PTB MTUs there (TCP reports at or above the connection's proven delivery at once; reports below it only when that exact report's quoted-data timeout applies it, never because of loss inference, with a derived size that is independent of the connection's estimate because a legacy IPv4 report without a Next-Hop MTU is corrected against the Host's shared path estimate, RFC 1191 section 5's current PMTU estimate, never the connection's estimate; UDP datagram and fragment, Echo adjunct probe and path-level reports) with a 600-second hold, and Host::service_changes publishes TCP's PLPMTUD-confirmed size through PathService::confirm_delivery only for a definitely submitted, unfragmented probe selected after the hold under an unchanged negative revision, raising other flows' ordinary ceiling without local delivery proof; the Host's ICMP Echo adjunct offers the forward delivery an exact Echo Reply certifies through the same confirm_delivery rules. Loss-inferred decreases and probe state stay connection-local. Dual-family Host tests with real probes across the 600-second deadline verify it.
//# The IP layer SHOULD be used to store the cached PMTU value and other shared state such as MTU values reported by ICMP PTB messages. Ideally, this shared state should be associated with a specific path traversed by packets exchanged between the source and destination nodes. However, in most cases a node will not have enough information to completely and accurately identify such a path. Rather, a node must associate a PMTU value with some local representation of a path. It is left to the implementation to select the local representation of a path.
fn delivered_probe_after_hold_raises_shared_ceiling_and_stale_proof_never() {
    use Probe::*;
    for v6 in [false, true] {
        for case in [
            Confirmed,
            NewerDecrease,
            FreshUnchangedReport,
            PossiblySubmitted,
            Early,
            BeyondFirstHop,
            RouteChanged,
        ] {
            let cfg = config(4);
            let (local, remote) = addresses(v6);
            let mut a = managed(local, 4800 + u64::from(v6), cfg.clone());
            let mut b = managed(remote, 4900 + u64::from(v6), cfg.clone());
            b.1.listen(remote, 4).unwrap();
            let flow_a = connect(&mut a, &cfg, 1000, 24);
            let flow_b = connect(&mut a, &cfg, 1001, 24);
            let mut now = 0;
            pump(&mut a, &mut b, &mut now);
            let path = a.0.binding(flow_a).unwrap().snapshot.path();
            let mtu = if v6 { 1350 } else { 1100 };
            a.0.trusted_decrease(now, path, mtu).unwrap();
            assert_eq!(service(&mut a, now).applied, 2);
            let hold = a.0.binding(flow_a).unwrap().snapshot.retry_not_before();
            assert_eq!(hold - now, 600 * cfg.connection.timebase.units_per_second);
            let local_b = a.1.path_mtu_info(flow_b).unwrap().unwrap();
            // Enough for one probe and the three segments RFC 4821 section
            // 7.4 requires after it, too little for a second probe.
            a.1.write(flow_a, &[7; 6000]).unwrap();
            // Before the deadline the connection selects ordinary output only.
            let at = if case == Early { hold - 1 } else { hold };
            let (attempt, _, probe) = selected(&mut a.1, at).unwrap();
            let intent = a.1.transmit_discovery_intent(attempt);
            if case == Early {
                assert!(intent.is_none() && probe.len() <= mtu as usize);
            } else {
                assert!(intent.is_some(), "real probe");
                assert!(probe.len() > mtu as usize);
            }
            let context = a.0.egress_context(&mut a.1, attempt).unwrap();
            let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
            let outcome = if case == PossiblySubmitted {
                BackendOutcome::Unknown
            } else {
                BackendOutcome::Submitted
            };
            let submitted =
                a.0.submit(&mut a.1, at, ticket, context, &probe, 0, |_| outcome)
                    .unwrap();
            if case == PossiblySubmitted {
                // The caller's quarantine treats the bytes as possibly sent;
                // that is never delivery provenance for the path.
                assert_eq!(submitted, Submission::PossiblySubmitted);
                assert!(a.1.accept_transmit(at, attempt).unwrap());
            } else {
                assert!(submitted == Submission::Submitted);
            }
            let link = a.0.binding(flow_a).unwrap().snapshot.key().link();
            let before = a.0.paths().path_snapshot(path).unwrap();
            match case {
                NewerDecrease => {
                    a.0.trusted_decrease(hold + 1, path, if v6 { 1300 } else { 1050 })
                        .unwrap();
                }
                FreshUnchangedReport => {
                    // The bottleneck reports the learned MTU for the probe:
                    // A's search falls back to it, and the shared estimate
                    // stays while its hold restarts from this report.
                    let dispatch =
                        a.0.input_icmp(&mut a.1, a.2, hold + 1, &ptb(&probe, mtu), None)
                            .unwrap();
                    assert!(
                        matches!(
                            dispatch,
                            IcmpDispatch::Completed(IcmpOutcome::Tcp {
                                report: TcpReport::PacketTooBig(PmtuFeedback::Decreased { mtu: m }),
                                published: Some(path::EstimateChange::Unchanged),
                                ..
                            }) if m == mtu
                        ),
                        "{dispatch:?}"
                    );
                    let after = a.0.paths().path_snapshot(path).unwrap();
                    assert_eq!(after.learned_mtu(), Some(mtu));
                    assert_eq!(after.negative_revision(), before.negative_revision());
                    assert_eq!(
                        after.retry_not_before(),
                        hold + 1 + 600 * cfg.connection.timebase.units_per_second
                    );
                }
                BeyondFirstHop => {
                    // The first hop shrinks below the probe but stays above
                    // the learned estimate: same incarnation and revision.
                    a.0.set_link_mtu(link, probe.len() as u32 - 10).unwrap();
                    let after = a.0.paths().path_snapshot(path).unwrap();
                    assert_eq!(after.negative_revision(), before.negative_revision());
                    assert_eq!(after.learned_mtu(), Some(mtu));
                    assert!(after.first_hop_mtu() < probe.len() as u32);
                }
                RouteChanged => {
                    // A more specific route replaces the probe's path
                    // incarnation before its ACK arrives.
                    a.0.add_route(path::Route {
                        destination: path::IpPrefix::new(remote.ip(), if v6 { 128 } else { 32 })
                            .unwrap(),
                        source: None,
                        dscp: None,
                        link,
                        next_hop: path::NextHop::Forwarder(ForwarderId(9)),
                        metric: 0,
                    })
                    .unwrap();
                    let after = a.0.paths().path_snapshot(path).unwrap();
                    assert_ne!(after.status(), path::PathStatus::Valid);
                }
                Confirmed | PossiblySubmitted | Early => {}
            }
            input(&mut b.0, &mut b.1, b.2, hold + 2, &probe, 0);
            now = hold + 2;
            let ack = emit(&mut b.0, &mut b.1, now + 1).unwrap();
            input(&mut a.0, &mut a.1, a.2, now + 2, &ack, 0);
            let report = service(&mut a, now + 3);
            let shared = a.0.paths().path_snapshot(path).unwrap();
            let ordinary_b = a.1.managed_path(flow_b).unwrap().ordinary_ip_budget;
            match case {
                Confirmed => {
                    let intent = intent.unwrap();
                    assert_eq!((report.raised, report.decreased), (1, 0));
                    assert_eq!(shared.learned_mtu(), Some(intent.ip_packet_len()));
                    assert_eq!(ordinary_b, intent.ip_packet_len());
                    // Ordinary permission only: B's own search is unchanged.
                    let info_b = a.1.path_mtu_info(flow_b).unwrap().unwrap();
                    assert_eq!(info_b.search_low, local_b.search_low);
                }
                NewerDecrease => {
                    assert_eq!((report.raised, report.decreased), (0, 0));
                    assert_eq!(shared.learned_mtu(), Some(if v6 { 1300 } else { 1050 }));
                }
                RouteChanged => {
                    // The stale proof is discarded, not an error; both flows
                    // move to the new incarnation, which inherits no raise.
                    assert_eq!((report.raised, report.decreased, report.failed), (0, 0, 0));
                    assert_eq!(shared.learned_mtu(), Some(mtu));
                    let rebound = a.0.binding(flow_b).unwrap().snapshot;
                    assert_ne!(rebound.path(), path);
                    assert_eq!(a.0.binding(flow_a).unwrap().snapshot.path(), rebound.path());
                    let current = a.0.paths().path_snapshot(rebound.path()).unwrap();
                    assert_eq!(current.learned_mtu(), None, "no fact carried over");
                }
                FreshUnchangedReport | PossiblySubmitted | Early | BeyondFirstHop => {
                    assert_eq!((report.raised, report.decreased), (0, 0));
                    assert_eq!(shared.learned_mtu(), Some(mtu));
                    assert!(ordinary_b <= mtu);
                }
            }
            if matches!(case, FreshUnchangedReport | PossiblySubmitted) {
                // B's hold has expired locally, so it probes with enough data
                // unless a report about A's probe restarted the shared hold.
                a.1.write(flow_b, &[8; 6000]).unwrap();
                // B's own first packet: A's unsent remainder is ready first.
                let (attempt, frame, ..) = reserve(&mut a, flow_b, now + 3, Held::Scalar).unwrap();
                let grows = a.1.transmit_discovery_intent(attempt).is_some();
                assert_eq!(grows, case == PossiblySubmitted, "{case:?}");
                assert_eq!(frame.len() > mtu as usize, grows);
            }
            let again = service(&mut a, now + 4);
            assert_eq!((again.raised, again.decreased), (0, 0), "consumed once");
            let raised = shared.learned_mtu();
            let (mut ordinary, mut probes) = (0, 0);
            if case == Confirmed {
                // Ordinary ACKs after the raise: A's remainder, then small
                // writes from both flows, and a replay of the probe's own ACK.
                // Each segment is definitely submitted and acknowledged, yet
                // none is a probe (too little data queued to fill one), so
                // the shared ceiling never moves.
                for round in 0..24 {
                    if round >= 8 {
                        let id = if round % 2 == 0 { flow_a } else { flow_b };
                        a.1.write(id, &[9; 500]).unwrap();
                    }
                    now += 10;
                    let Some((attempt, _, frame)) = selected(&mut a.1, now) else {
                        continue;
                    };
                    if a.1.transmit_discovery_intent(attempt).is_some() {
                        probes += 1;
                    } else {
                        ordinary += 1;
                    }
                    assert!(raised.is_some_and(|raised| frame.len() as u32 <= raised));
                    let context = a.0.egress_context(&mut a.1, attempt).unwrap();
                    let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
                    let submitted =
                        a.0.submit(&mut a.1, now, ticket, context, &frame, 0, |_| {
                            BackendOutcome::Submitted
                        })
                        .unwrap();
                    assert!(submitted == Submission::Submitted);
                    input(&mut b.0, &mut b.1, b.2, now + 1, &frame, 0);
                    while let Some(ack) = emit(&mut b.0, &mut b.1, now + 2) {
                        input(&mut a.0, &mut a.1, a.2, now + 3, &ack, 0);
                    }
                    input(&mut a.0, &mut a.1, a.2, now + 4, &ack, 0);
                    let report = service(&mut a, now + 5);
                    assert_eq!((report.raised, report.decreased), (0, 0));
                    assert_eq!(
                        a.0.paths().path_snapshot(path).unwrap().learned_mtu(),
                        raised
                    );
                }
                assert!(ordinary >= 16 && probes == 0, "{ordinary} {probes}");
                assert_eq!(a.1.transport_info(flow_a).unwrap().unacked, 0);
                assert_eq!(a.1.transport_info(flow_b).unwrap().unacked, 0);
                std::println!(
                    "ORDINARY v6={v6} acked_segments={ordinary} probes={probes} learned={raised:?}"
                );
            }
            std::println!(
                "PROBE v6={v6} case={case:?} selected_ip={} published={} learned={raised:?} ordinary_b={ordinary_b}",
                probe.len(),
                report.raised,
            );
        }
    }
}

// TCP leaves a correlated report Unchanged when its own estimate is already
// no larger, yet the report is a validated fact about the shared path. After
// A's loss-inferred (connection-local) decrease, a late PTB for A's earlier
// larger packet lowers the shared record for B and the UDP flow; a fresh
// duplicate of it restarts the shared hold, so B cannot probe when the first
// hold expires (the control, without the duplicate, does).
#[test]
fn unchanged_tcp_report_still_lowers_shared_record_and_restarts_hold() {
    for v6 in [false, true] {
        for duplicate in [true, false] {
            let cfg = config(4);
            let (local, remote) = addresses(v6);
            let mut a = udp_side(local, 5100 + u64::from(v6), &cfg);
            let mut b = managed(remote, 5200 + u64::from(v6), cfg.clone());
            b.1.listen(remote, 4).unwrap();
            let flow_a = connect(&mut a, &cfg, 1000, 0);
            let flow_b = connect(&mut a, &cfg, 1001, 0);
            let mut now = 0;
            pump(&mut a, &mut b, &mut now);
            let shared = flow(&mut a, 5000, remote.ip(), 0);
            let path = a.0.binding(flow_a).unwrap().snapshot.path();
            assert_eq!(service(&mut a, now), ServiceReport::default());
            let initial = a.1.path_mtu_info(flow_a).unwrap().unwrap().current_mtu;

            a.1.write(flow_a, &[3; 1400]).unwrap();
            now += 10;
            let (original, _) = send(&mut a, now, BackendOutcome::Submitted).unwrap();
            // Undelivered retransmissions until A's black-hole detection
            // lowers its own estimate; that inference stays local.
            for _ in 0..16 {
                if a.1.path_mtu_info(flow_a).unwrap().unwrap().current_mtu < initial {
                    break;
                }
                now = now.max(a.1.next_deadline().unwrap());
                a.1.on_timeout(now, 32).unwrap();
                while send(&mut a, now, BackendOutcome::Submitted).is_some() {}
            }
            let local_a = a.1.path_mtu_info(flow_a).unwrap().unwrap().current_mtu;
            let mtu = if v6 { 1350 } else { 1100 };
            assert!(local_a < mtu && mtu < original.len() as u32, "{local_a}");
            assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), None);
            assert_eq!(a.0.udp_path_change(shared).unwrap(), None);

            now += 1;
            let (report, published) = tcp_report(
                a.0.input_icmp(&mut a.1, a.2, now, &ptb(&original, mtu), None)
                    .unwrap(),
            );
            assert_eq!(report, TcpReport::PacketTooBig(PmtuFeedback::Unchanged));
            assert_eq!(published, Some(path::EstimateChange::Decreased));
            let first = now;
            let units = cfg.connection.timebase.units_per_second;
            let lowered = a.0.paths().path_snapshot(path).unwrap();
            assert_eq!(lowered.learned_mtu(), Some(mtu));
            assert_eq!(lowered.retry_not_before(), first + 600 * units);
            let report = service(&mut a, now + 1);
            assert_eq!((report.applied, report.failed), (3, 0));
            assert_eq!(a.1.managed_path(flow_b).unwrap().ordinary_ip_budget, mtu);
            let change = a.0.udp_path_change(shared).unwrap().unwrap();
            assert_eq!(change.max_payload, mtu as usize - overhead(v6).1);
            assert_eq!(
                a.1.path_mtu_info(flow_a).unwrap().unwrap().current_mtu,
                local_a,
                "A keeps its own smaller estimate"
            );

            if duplicate {
                now += 10;
                let (report, published) = tcp_report(
                    a.0.input_icmp(&mut a.1, a.2, now, &ptb(&original, mtu), None)
                        .unwrap(),
                );
                assert_eq!(report, TcpReport::PacketTooBig(PmtuFeedback::Unchanged));
                assert_eq!(published, Some(path::EstimateChange::Unchanged));
                let restarted = a.0.paths().path_snapshot(path).unwrap();
                assert_eq!(restarted.learned_mtu(), Some(mtu));
                assert_eq!(restarted.negative_revision(), lowered.negative_revision());
                assert_eq!(restarted.retry_not_before(), now + 600 * units);
            }
            // Retire A so that only B selects output.
            a.1.abort(flow_a).unwrap();
            while emit(&mut a.0, &mut a.1, now).is_some() {}
            a.1.release(flow_a).unwrap();
            let after_hold = first + 600 * units;
            service(&mut a, after_hold);
            a.1.write(flow_b, &[8; 6000]).unwrap();
            let (attempt, _, frame) = selected(&mut a.1, after_hold).unwrap();
            let grows = a.1.transmit_discovery_intent(attempt).is_some();
            assert_eq!(grows, !duplicate, "duplicate={duplicate}");
            assert_eq!(frame.len() > mtu as usize, grows);
            std::println!(
                "UNCHANGED v6={v6} duplicate={duplicate} local_a={local_a} shared={mtu} b_probes_at_first_hold_expiry={grows}"
            );
        }
    }
}

// A correlated PTB below A's proven delivery has the same shared outcome
// whether or not A's black-hole timeouts already lowered its own estimate
// under the report (variant L) or not (C): nothing at once (no decrease, no
// hold restart, no notification), nothing ever when cumulative progress
// refutes it, and one publication of the same value when the quoted data's
// timeout authorizes exactly that report. A legacy IPv4 PTB (no next-hop
// MTU) is sized by A's explicit RFC 1191 table (1006 below the quoted 1452
// octets), above the Host's CONTEMPORARY estimate (576): the report's own
// size is published, never A's loss-inferred estimate under it.
#[test]
fn below_proven_delivery_report_shared_outcome_ignores_loss_inference() {
    for (v6, legacy) in [(false, false), (true, false), (false, true)] {
        let (mtu, next_hop) = match (v6, legacy) {
            (true, _) => (1350, 1350),
            (false, false) => (1100, 1100),
            (false, true) => (1006, 0),
        };
        let mut published = [None, None];
        for (index, inferred) in [false, true].into_iter().enumerate() {
            for progress in [true, false] {
                let mut cfg = config(4);
                if legacy {
                    cfg.connection.pmtud.as_mut().unwrap().policy.ipv4_plateaus =
                        ntcp::Ipv4Plateaus::RFC1191;
                }
                let (local, remote) = addresses(v6);
                let mut a = udp_side(local, 5300 + u64::from(v6), &cfg);
                let mut b = managed(remote, 5400 + u64::from(v6), cfg.clone());
                b.1.listen(remote, 4).unwrap();
                let flow_a = connect(&mut a, &cfg, 1000, 0);
                let flow_b = connect(&mut a, &cfg, 1001, 0);
                let mut now = 0;
                pump(&mut a, &mut b, &mut now);
                let shared = flow(&mut a, 5000, remote.ip(), 0);
                let path = a.0.binding(flow_a).unwrap().snapshot.path();
                assert_eq!(limits(&mut a, shared).path, path);
                assert_eq!(service(&mut a, now), ServiceReport::default());
                // Proven delivery: the real peer acknowledges 1400 octets.
                a.1.write(flow_a, &[2; 1400]).unwrap();
                pump(&mut a, &mut b, &mut now);
                assert_eq!(a.1.transport_info(flow_a).unwrap().unacked, 0);
                a.1.write(flow_a, &[3; 1400]).unwrap();
                now += 10;
                let (quoted, _) = send(&mut a, now, BackendOutcome::Submitted).unwrap();
                assert!(mtu < quoted.len() as u32);
                for _ in 0..16 {
                    if !inferred
                        || a.1.path_mtu_info(flow_a).unwrap().unwrap().current_mtu < mtu
                    {
                        break;
                    }
                    now = now.max(a.1.next_deadline().unwrap());
                    a.1.on_timeout(now, 32).unwrap();
                    while send(&mut a, now, BackendOutcome::Submitted).is_some() {}
                }
                let local_a = a.1.path_mtu_info(flow_a).unwrap().unwrap().current_mtu;
                assert_eq!(local_a < mtu, inferred, "{local_a}");
                let before = a.0.paths().path_snapshot(path).unwrap();
                let bindings = [
                    a.0.binding(flow_a).unwrap().snapshot,
                    a.0.binding(flow_b).unwrap().snapshot,
                ];
                let budget_b = a.1.managed_path(flow_b).unwrap().ordinary_ip_budget;

                // (1) Immediately: deferred, nothing reaches shared state.
                now += 1;
                let (report, change) = tcp_report(
                    a.0.input_icmp(&mut a.1, a.2, now, &ptb(&quoted, next_hop), None)
                        .unwrap(),
                );
                assert_eq!(report, TcpReport::PacketTooBig(PmtuFeedback::Deferred));
                assert_eq!(change, None);
                let unchanged = |a: &Side| {
                    let current = a.0.paths().path_snapshot(path).unwrap();
                    current == before
                        && a.0.binding(flow_a).unwrap().snapshot == bindings[0]
                        && a.0.binding(flow_b).unwrap().snapshot == bindings[1]
                        && a.1.managed_path(flow_b).unwrap().ordinary_ip_budget == budget_b
                        && !dirty(a, flow_a)
                        && !dirty(a, flow_b)
                };
                assert!(unchanged(&a));
                assert_eq!(before.learned_mtu(), None);
                let report = service(&mut a, now + 1);
                assert_eq!((report.decreased, report.applied), (0, 0));
                assert!(unchanged(&a));
                assert_eq!(a.0.udp_path_change(shared).unwrap(), None);

                if progress {
                    // (2a) Cumulative progress past the quoted data refutes it.
                    input(&mut b.0, &mut b.1, b.2, now + 2, &quoted, 0);
                    pump(&mut b, &mut a, &mut now);
                    assert_eq!(a.1.transport_info(flow_a).unwrap().unacked, 0);
                }
                let mut decreased = 0;
                for _ in 0..16 {
                    let Some(deadline) = a.1.next_deadline() else {
                        break;
                    };
                    now = now.max(deadline);
                    a.1.on_timeout(now, 32).unwrap();
                    while send(&mut a, now, BackendOutcome::Submitted).is_some() {}
                    let report = service(&mut a, now + 1);
                    assert_eq!(report.failed, 0);
                    decreased += report.decreased;
                    if decreased > 0 {
                        break;
                    }
                }
                assert_eq!(service(&mut a, now + 2).decreased, 0, "exactly once");
                let newest = a.0.paths().path_snapshot(path).unwrap();
                if progress {
                    assert_eq!(decreased, 0);
                    assert_eq!(newest, before, "never published");
                    assert_eq!(a.0.udp_path_change(shared).unwrap(), None);
                    std::println!("BELOW_PROVEN v6={v6} legacy={legacy} inferred={inferred} local_a={local_a} report={mtu} progress: published=0");
                    continue;
                }
                // (2b) The quoted data's timeout authorized exactly it.
                assert_eq!(decreased, 1);
                let learned = newest.learned_mtu().unwrap();
                assert!(!inferred || learned > local_a, "no loss-inferred value");
                assert_eq!(a.0.binding(flow_b).unwrap().snapshot, newest);
                assert!(a.1.managed_path(flow_b).unwrap().ordinary_ip_budget <= learned);
                let udp = a.0.udp_path_change(shared).unwrap().unwrap();
                assert_eq!((udp.version, udp.destination), (newest.version(), remote.ip()));
                assert_eq!(udp.max_payload, learned as usize - overhead(v6).1);
                published[index] = Some(learned);
                std::println!("BELOW_PROVEN v6={v6} legacy={legacy} inferred={inferred} local_a={local_a} report={mtu} timeout: published=1 learned={learned}");
            }
        }
        assert_eq!(published, [Some(mtu), Some(mtu)], "same value for C and L");
    }
}

// RFC 1191 section 5 without a next-hop MTU: a correlated IPv4 quote is
// reduced by its header when not less than the Host's shared path estimate
// (the IP layer's current PMTU estimate, never A's own estimate), so the
// derived size, deferral and shared publication are the same whether or not
// black-hole timeouts first lowered A's own estimate (L) or not (C). Every
// plain submitted packet is smaller than the 1500-octet shared estimate, so
// neither its exact nor its header-inflated quote is reduced: A derives the
// same size from both, and the Host, which keeps no record of the submitted
// length, publishes its own estimate below the quoted length when that is
// larger. After the shared decrease to 1000 every submitted packet is not
// smaller than the estimate: section 5 then mandates reducing both quotes,
// and an exact quote of a packet derives what a smaller inflated packet
// would. A connection keeps no record of the path each segment left on, so,
// as in Linux, a quote of a segment sent before A moved to another path
// incarnation is about A's current path.
// Only A's local label may differ (Decreased versus Unchanged). Scenarios:
// A's explicit RFC 1191 table with no prior delivery (quoted 1452); the
// default table after an acknowledged 1480-octet packet (quoted 1495); the
// explicit table after acknowledged 1452 octets (quoted 1010), applied at
// its timeout. Each with an exact and a header-inflated quote, and each also
// after a previous shared decrease (a UDP flow's PTB first lowered the Host
// record to 1000) and about a submission of an older path incarnation (A was
// rebound to another DSCP after sending it: the report lowers the new
// incarnation, where A has proven no delivery yet). Repair follows
// eligibility, never the label: in C the
// quoted range is repaired at once (labelled Decreased or Unchanged); in L the
// black-hole timeouts already retransmitted the quoted bytes and own their
// flight, so the same report adds no repair work there.
#[test]
fn legacy_ipv4_report_outcome_is_independent_of_loss_inference() {
    const SHARED: u32 = 1000;
    for (label, rfc1191, acked, written, stop) in [
        ("immediate", true, None, 1400usize, 1006u32),
        ("default-table", false, Some(1428usize), 1443usize, 1495u32),
        ("deferred", true, Some(1400usize), 958usize, 1010u32),
    ] {
        for variant in ["plain", "shared-decrease", "older-path"] {
            let older = variant == "older-path";
            let mut by_quote = Vec::new();
            for inflated in [false, true] {
                let mut outcomes = Vec::new();
                for inferred in [false, true] {
                    let mut cfg = config(4);
                    if rfc1191 {
                        cfg.connection.pmtud.as_mut().unwrap().policy.ipv4_plateaus =
                            ntcp::Ipv4Plateaus::RFC1191;
                    }
                    let (local, remote) = addresses(false);
                    let mut a = udp_side(local, 5500, &cfg);
                    let mut b = managed(remote, 5600, cfg.clone());
                    b.1.listen(remote, 4).unwrap();
                    let flow_a = connect(&mut a, &cfg, 1000, 0);
                    let _flow_b = connect(&mut a, &cfg, 1001, 0);
                    let mut now = 0;
                    pump(&mut a, &mut b, &mut now);
                    let old = a.0.binding(flow_a).unwrap().snapshot.path();
                    service(&mut a, now);
                    if let Some(len) = acked {
                        a.1.write(flow_a, &vec![2; len]).unwrap();
                        pump(&mut a, &mut b, &mut now);
                        assert_eq!(a.1.transport_info(flow_a).unwrap().unacked, 0);
                    }
                    a.1.write(flow_a, &vec![3; written]).unwrap();
                    now += 10;
                    let (quoted, _) = send(&mut a, now, BackendOutcome::Submitted).unwrap();
                    for _ in 0..32 {
                        if !inferred
                            || a.1.path_mtu_info(flow_a).unwrap().unwrap().current_mtu < stop
                        {
                            break;
                        }
                        now = now.max(a.1.next_deadline().unwrap());
                        a.1.on_timeout(now, 32).unwrap();
                        while send(&mut a, now, BackendOutcome::Submitted).is_some() {}
                    }
                    let local_a = a.1.path_mtu_info(flow_a).unwrap().unwrap().current_mtu;
                    assert_eq!(local_a < stop, inferred, "{label} {local_a}");
                    if variant == "shared-decrease" {
                        let udp = flow(&mut a, 5000, remote.ip(), 0);
                        let mut packet = [0; 1600];
                        let Ok(UdpSent::Submitted(n)) = a.0.udp_send(
                            &a.1,
                            now,
                            udp,
                            None,
                            &[4; 1400],
                            &mut packet,
                            |_, _| BackendOutcome::Submitted,
                        ) else {
                            panic!("datagram not submitted");
                        };
                        assert!(matches!(
                            a.0.input_icmp(&mut a.1, a.2, now, &ptb(&packet[..n], SHARED), None),
                            Ok(IcmpDispatch::Completed(IcmpOutcome::Advice {
                                published: Some(path::EstimateChange::Decreased),
                                ..
                            }))
                        ));
                        service(&mut a, now);
                        assert_eq!(
                            a.1.managed_path(flow_a).unwrap().ordinary_ip_budget,
                            local_a.min(SHARED)
                        );
                    }
                    if older {
                        a.0.rebind_dscp(&mut a.1, flow_a, 8).unwrap();
                    }
                    let path = a.0.binding(flow_a).unwrap().snapshot.path();
                    assert_eq!(path != old, older);
                    let mut copy = quoted.clone();
                    if inflated {
                        let total = u16::from_be_bytes([copy[2], copy[3]]) + 20;
                        copy[2..4].copy_from_slice(&total.to_be_bytes());
                        super::dispatch::seal_ipv4(&mut copy);
                    }
                    // The shared estimate the Host corrects the quote against.
                    let estimate =
                        a.0.paths()
                            .path_snapshot(path)
                            .unwrap()
                            .pmtu_estimate()
                            .unwrap();
                    now += 1;
                    let (report, published) =
                        tcp_report(a.0.input_icmp(&mut a.1, a.2, now, &ptb(&copy, 0), None).unwrap());
                    let TcpReport::PacketTooBig(class) = report else {
                        panic!("{report:?}");
                    };
                    assert_ne!(class, PmtuFeedback::Rejected);
                    service(&mut a, now + 1);
                    let immediate = a.0.paths().path_snapshot(path).unwrap().learned_mtu();
                    let start = u32::from_be_bytes(quoted[24..28].try_into().unwrap());
                    let payload = quoted.len() - 20 - usize::from(quoted[32] >> 4) * 4;
                    let end = start.wrapping_add(payload as u32 + u32::from(quoted[33] & 1));
                    // The first output after the report, before any ACK.
                    let repair = send(&mut a, now + 1, BackendOutcome::Submitted).map(|(f, _)| {
                        let seq = u32::from_be_bytes(f[24..28].try_into().unwrap());
                        (seq, f.len() - 20 - usize::from(f[32] >> 4) * 4)
                    });
                    if inferred {
                        assert_eq!(repair, None, "{label} {variant}: L's RTO owns the quoted flight");
                    } else {
                        let (seq, len) = repair.expect("C repairs the quoted range");
                        assert_eq!(seq, start, "{label} {variant}");
                        assert!(0 < len && len <= payload, "{label} {variant} {len}");
                    }
                    // The report's own size, read back with an identical repeat
                    // under the shared estimate it was dispatched with.
                    let derived = a
                        .1
                        .correlated_pmtu_feedback(
                            now + 1,
                            flow_a,
                            ntcp::CorrelatedPmtu {
                                segment: ntcp::CorrelatedSegment {
                                    start,
                                    end,
                                    ip_packet_len: quoted.len() as u32,
                                    ip_header_len: 20,
                                },
                                quoted_packet_len: quoted.len() as u32
                                    + if inflated { 20 } else { 0 },
                                candidate_mtu: 0,
                                current_path: true,
                                path_estimate: Some(estimate),
                            },
                        )
                        .unwrap()
                        .derived_mtu;
                    let mut decreased = 0;
                    for _ in 0..16 {
                        let Some(deadline) = a.1.next_deadline() else { break };
                        now = now.max(deadline);
                        a.1.on_timeout(now, 32).unwrap();
                        while send(&mut a, now, BackendOutcome::Submitted).is_some() {}
                        decreased += service(&mut a, now + 1).decreased;
                        if decreased > 0 {
                            break;
                        }
                    }
                    let eventual = a.0.paths().path_snapshot(path).unwrap().learned_mtu();
                    if older && let Ok(snapshot) = a.0.paths().path_snapshot(old) {
                        assert_eq!(snapshot.learned_mtu(), None);
                    }
                    std::println!(
                        "LEGACY {label} {variant} inflated={inflated} inferred={inferred} quoted={} local_a={local_a} class={class:?} derived={derived:?} published={published:?} immediate={immediate:?} repair={repair:?} timeout_decreased={decreased} eventual={eventual:?}",
                        quoted.len()
                    );
                    let deferred = class == PmtuFeedback::Deferred;
                    // (A's policy-derived size, deferred, the size its
                    // publication carries). The Host publishes the larger of
                    // the derived size and its own estimate (CONTEMPORARY
                    // table, same shared reference), never above an already
                    // lower shared record. Plain and older incarnation:
                    // 1452 and 1010 are below 1500, so both quotes give RFC
                    // 1191's 1006, and the Host's own estimate below an
                    // inflated 1472 is 1460; 1495 gives the default table's
                    // 1492, at or above the delivered 1480. On the new
                    // incarnation A has proven no delivery, so nothing is
                    // deferred. After the decrease to 1000, exact quotes are
                    // reduced by 20: 1432 -> 1006, 1475 -> 1460 (below 1480:
                    // deferred, timeout publishes max(1460, 1460)), 990 ->
                    // 508 (timeout publishes max(576, 508)); inflated quotes
                    // recover 1452, 1495 and 1010.
                    let expected = match (variant, label, inflated) {
                        ("shared-decrease", "immediate", _) => (1006, false, 1006),
                        (_, "immediate", false) => (1006, false, 1006),
                        (_, "immediate", true) => (1006, false, 1460),
                        ("shared-decrease", "default-table", false) => (1460, true, 1460),
                        (_, "default-table", _) => (1492, false, 1492),
                        ("plain", _, _) => (1006, true, 1006),
                        ("older-path", _, _) => (1006, false, 1006),
                        (_, _, false) => (508, true, 576),
                        _ => (1006, true, 1006),
                    };
                    assert_eq!(derived, Some(expected.0), "{label} {variant}");
                    match variant {
                        "plain" | "older-path" => {
                            assert_eq!((deferred, eventual), (expected.1, Some(expected.2)));
                            assert_eq!(immediate.is_some(), !deferred);
                            assert_eq!(
                                published,
                                (!deferred).then_some(path::EstimateChange::Decreased)
                            );
                            assert_eq!(decreased, usize::from(deferred));
                        }
                        "shared-decrease" => {
                            assert_eq!(
                                (deferred, immediate, eventual),
                                (expected.1, Some(SHARED), Some(expected.2.min(SHARED)))
                            );
                            assert_eq!(decreased, usize::from(deferred && expected.2 < SHARED));
                        }
                        _ => unreachable!(),
                    }
                    outcomes.push((derived, deferred, published, immediate, decreased, eventual));
                }
                assert_eq!(
                    outcomes[0], outcomes[1],
                    "{label} {variant} inflated={inflated}: C and L differ"
                );
                by_quote.push(outcomes[0]);
            }
            // Below the shared estimate an inflated quote is not corrected,
            // and the Host knows no submitted length to bound it by: in the
            // immediate scenario its own estimate from the inflated 1472
            // octets (1460) is published instead of 1006.
            if variant == "plain" && label != "immediate" {
                assert_eq!(
                    by_quote[0], by_quote[1],
                    "{label}: exact and inflated quotes differ"
                );
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Held {
    Scalar,
    ZeroCopy,
    PartialGso,
}

// One reserved packet of `id`: the encoded frame (zero-copy: headers only),
// its external payload length, and the complete wire bytes for the peer.
// Set `route`'s owner policy through the Host administration capability.
fn set_route_policy(a: &mut Side, route: path::RouteId, policy: path::AdminPolicy, now: u64) {
    let capability = a.0.administration();
    let expected = a
        .0
        .admin_routes(&capability)
        .unwrap()
        .find(|r| r.route == route)
        .unwrap()
        .generation;
    let candidate = a
        .0
        .admin_validate(
            &capability,
            now,
            path::AdminChange {
                target: path::AdminTarget::Route(route),
                expected,
                policy,
            },
        )
        .unwrap();
    a.0.admin_apply(&capability, &mut a.1, candidate).unwrap();
    assert_eq!(service(a, now).failed, 0);
}

// RFC 1191 section 5's current PMTU estimate is the accepted network
// estimate, never the discovery-policy sending limit (RFC 1122 section
// 3.3.3's 576 octets through the default Forwarder route, IPv6's 1280): a
// validated PTB for a DF-set segment submitted before the owner disabled
// discovery, arriving after the disable, gives the same TCP feedback and
// derived size, the same shared learned estimate and the same hold as on
// an enabled route. The disabled route's packet budget stays the sending
// limit while disabled and is the learned value after re-enabling, with no
// new hold. `estimate` is an owner value set with the policy in both runs.
// The local TCP state (current size, search lower bound) is compared too:
// nothing in the connection's own sending state differs between the runs.
fn disabled_route_ptb_matches_enabled(
    v6: bool,
    table: ntcp::Ipv4Plateaus,
    written: usize,
    quoted_len: usize,
    learned: u32,
    estimate: Option<u32>,
) {
    let limit = if v6 { 1280 } else { 576 };
    let mut outcomes = Vec::new();
    for disable in [false, true] {
        let case = std::format!("v6={v6} {table:?} estimate={estimate:?} disable={disable}");
        let mut cfg = config(4);
        cfg.connection.pmtud.as_mut().unwrap().policy.ipv4_plateaus = table;
        let (local, remote) = addresses(v6);
        let mut a = managed_identified(local, 7700, cfg.clone());
        let mut b = managed(remote, 7800, cfg.clone());
        b.1.listen(remote, 4).unwrap();
        let tcp = a
            .1
            .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        service(&mut a, now);
        a.1.write(tcp, &vec![3; written]).unwrap();
        now += 10;
        let (quoted, _) = send(&mut a, now, BackendOutcome::Submitted).unwrap();
        assert_eq!(quoted.len(), quoted_len, "{case}");
        if !v6 {
            assert_ne!(quoted[6] & 0x40, 0, "submitted with DF");
        }
        let snapshot = a.0.binding(tcp).unwrap().snapshot;
        let (route, path) = (snapshot.key().route(), snapshot.path());
        now += 10;
        if disable || estimate.is_some() {
            let policy = path::AdminPolicy {
                discovery_disabled: disable,
                estimate,
            };
            set_route_policy(&mut a, route, policy, now);
        }
        if disable {
            let disabled = a.0.paths().path_snapshot(path).unwrap();
            assert_eq!(disabled.ip_packet_budget(), Ok(limit), "{case}");
            assert_eq!(disabled.pmtu_estimate(), Ok(estimate.unwrap_or(1500)), "{case}");
        }
        now += 10;
        let report = ptb(&quoted, if v6 { learned } else { 0 });
        let (report, published) = tcp_report(a.0.input_icmp(&mut a.1, a.2, now, &report, None).unwrap());
        assert_eq!(
            report,
            TcpReport::PacketTooBig(PmtuFeedback::Decreased { mtu: learned }),
            "{case}"
        );
        service(&mut a, now);
        let shared = a.0.paths().path_snapshot(path).unwrap();
        assert_eq!(shared.learned_mtu(), Some(learned), "{case}");
        assert_eq!(
            shared.ip_packet_budget(),
            Ok(if disable { limit } else { learned }),
            "{case}: the sending limit holds while disabled"
        );
        let hold = shared.retry_not_before();
        let info = a.1.path_mtu_info(tcp).unwrap().unwrap();
        if disable {
            now += 10;
            let policy = path::AdminPolicy {
                discovery_disabled: false,
                estimate,
            };
            set_route_policy(&mut a, route, policy, now);
            let enabled = a.0.paths().path_snapshot(path).unwrap();
            assert_eq!(enabled.ip_packet_budget(), Ok(learned), "{case}: not {limit}");
            assert_eq!(enabled.learned_mtu(), Some(learned), "{case}");
            assert_eq!(enabled.retry_not_before(), hold, "{case}: no new hold");
            let after = a.1.path_mtu_info(tcp).unwrap().unwrap();
            assert_eq!(
                (after.current_mtu, after.search_low),
                (info.current_mtu, info.search_low),
                "{case}"
            );
        }
        outcomes.push((report, published, shared.learned_mtu(), hold, info.current_mtu, info.search_low));
    }
    assert_eq!(outcomes[0], outcomes[1], "v6={v6} {table:?}: enabled and disabled differ");
}

// IPv4 legacy reports (Next-Hop MTU 0) on the default Forwarder route:
// TCP's RFC 1191 table reads a 1010-octet quote as 1006 (the Host's
// CONTEMPORARY table gives 576, so TCP's larger size is published), and the
// CONTEMPORARY table reads a 1480-octet quote as 1460, against the network
// estimate of 1500, not the 576-octet sending limit.
#[test]
fn ipv4_legacy_ptb_after_disable_learns_the_network_value() {
    disabled_route_ptb_matches_enabled(false, ntcp::Ipv4Plateaus::RFC1191, 958, 1010, 1006, None);
    disabled_route_ptb_matches_enabled(false, ntcp::Ipv4Plateaus::CONTEMPORARY, 1428, 1480, 1460, None);
}

// IPv6: a 1400-octet PTB for a 1500-octet segment learns 1400 on a disabled
// path as on an enabled one, without and with an owner value of 1450 above
// the 1280-octet sending limit (the value, not the sending limit, is the
// conservative TCP search baseline the policy lowers to).
#[test]
fn ipv6_ptb_after_disable_learns_the_network_value() {
    for estimate in [None, Some(1450)] {
        disabled_route_ptb_matches_enabled(true, ntcp::Ipv4Plateaus::CONTEMPORARY, 1428, 1500, 1400, estimate);
    }
}

pub(super) fn reserve(
    side: &mut Side,
    id: ConnectionId,
    now: u64,
    mode: Held,
) -> Option<(TransmitAttempt, Vec<u8>, usize, Vec<u8>)> {
    let mut tcp = [0; 2048];
    let mut parts = Vec::with_capacity(4);
    let (poll, attempt) = if mode == Held::ZeroCopy {
        side.1
            .poll_reserved_transmit_shared_for(now, id, &mut tcp, &mut parts, 32)
            .unwrap()
    } else {
        side.1
            .poll_reserved_transmit_for(now, id, &mut tcp, 32)
            .unwrap()
    };
    let packet = poll.packet?;
    let external: usize = parts.iter().map(ntcp::Payload::len).sum();
    let header = packet.len - external;
    let v6 = packet.ip.source.is_ipv6();
    let base = if v6 { 40 } else { 20 };
    let mut frame = vec![0; 2108];
    frame[base..base + header].copy_from_slice(&tcp[..header]);
    let n = match (v6, external > 0) {
        (true, true) => ntcp_ip6::encode_shared_header(&mut frame, packet, header).unwrap(),
        (false, true) => ntcp_ip::encode_shared_header(&mut frame, packet, 123, header).unwrap(),
        (true, false) => ntcp_ip6::encode(&mut frame, packet).unwrap(),
        (false, false) => ntcp_ip::encode(&mut frame, packet, 123).unwrap(),
    };
    frame.truncate(n);
    let mut wire = frame.clone();
    for part in &parts {
        wire.extend_from_slice(part.as_slice());
    }
    Some((attempt.unwrap(), frame, external, wire))
}

#[derive(Debug, PartialEq)]
struct Charges {
    progress: ntcp::SendProgress,
    unacked: u32,
    lost: u32,
    retransmitted: u32,
    // A congestion response would lower ssthresh or enter recovery; the byte
    // window of an idle flow merely follows its MSS.
    ssthresh: u32,
    rto_backoff: u32,
    recovery: bool,
    delivered_segments: u64,
}
fn charges(side: &Side, id: ConnectionId) -> Charges {
    let info = side.1.transport_info(id).unwrap();
    Charges {
        progress: side.1.send_progress(id).unwrap(),
        unacked: info.unacked,
        lost: info.lost,
        retransmitted: info.retransmitted,
        ssthresh: info.ssthresh,
        rto_backoff: info.rto_backoff,
        recovery: info.recovery,
        delivered_segments: info.delivered_segments,
    }
}

// Successive shared decreases (two PTB estimates, then a physical first-hop
// decrease) reach a held reservation through the change service while its
// owner keeps the reservation; each retry of the held bytes is refused
// before any backend call and charges nothing. A first-hop increase then
// raises both flows back to the learned estimate. The remainder is
// repacketized within the current budget, the accepted prefix is delivered
// once and the receiver reads exactly the written stream, with no
// retransmission, loss, recovery or ssthresh change on either flow.
#[test]
fn successive_decreases_during_held_reservation_then_increase_keep_prefix_and_charges() {
    use Held::*;
    for v6 in [false, true] {
        for mode in [Scalar, ZeroCopy, PartialGso] {
            let mut cfg = config(4);
            cfg.connection.pmtud.as_mut().unwrap().initial_search_low = Some(1500);
            let (local, remote) = addresses(v6);
            let identity = 5000 + u64::from(v6);
            let mut a = managed_configured(local, identity, cfg.clone(), mode == PartialGso, None);
            let mut b = managed(remote, 5100 + u64::from(v6), cfg.clone());
            let listener = b.1.listen(remote, 4).unwrap();
            let flow_a = connect(&mut a, &cfg, 1000, 0);
            let flow_b = connect(&mut a, &cfg, 1001, 0);
            let mut now = 0;
            pump(&mut a, &mut b, &mut now);
            let child = b.1.accept(listener).unwrap();
            b.1.accept(listener).unwrap();
            let payload: Vec<u8> = (0..6000).map(|i| (i % 251) as u8).collect();
            if mode == ZeroCopy {
                a.1.enable_shared_output(4).unwrap();
                a.1.write_shared(
                    flow_a,
                    ntcp::Payload::from_vec(payload.clone()),
                    false,
                    true,
                    None,
                )
                .unwrap();
            } else {
                a.1.write(flow_a, &payload).unwrap();
            }
            now += 10;
            let mut prefix = None;
            if mode == PartialGso {
                // One physical segment of the software GSO aggregate is
                // accepted and delivered; the aggregate stays reserved.
                let (attempt, frame, _, wire) = reserve(&mut a, flow_a, now, mode).unwrap();
                assert!(a.1.transmit_segmentation(attempt).is_some());
                let context = a.0.egress_context(&mut a.1, attempt).unwrap();
                let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
                let submitted =
                    a.0.submit(&mut a.1, now, ticket, context, &frame, 0, |_| {
                        BackendOutcome::Submitted
                    })
                    .unwrap();
                assert!(submitted == Submission::Submitted);
                assert!(a.1.is_output_reserved(flow_a), "aggregate continues");
                input(&mut b.0, &mut b.1, b.2, now + 1, &wire, 0);
                prefix = Some(wire);
            }
            let (held, frame, external, _) = reserve(&mut a, flow_a, now + 2, mode).unwrap();
            assert_eq!(external > 0, mode == ZeroCopy);
            let held_len = frame.len() + external;
            let context = a.0.egress_context(&mut a.1, held).unwrap();
            let mut ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
            let before = (charges(&a, flow_a), charges(&a, flow_b));
            let path = a.0.binding(flow_a).unwrap().snapshot.path();
            let link = a.0.binding(flow_a).unwrap().snapshot.key().link();
            let (m1, m2, l3) = if v6 {
                (1420, 1350, 1280)
            } else {
                (1300, 1100, 1000)
            };
            assert!(held_len > m1 as usize);
            let mut backend_calls = 0;
            let mut t = now + 3;
            for (step, budget) in [(0, m1), (1, m2), (2, l3)] {
                match step {
                    2 => a.0.set_link_mtu(link, l3).unwrap(),
                    _ => assert_eq!(
                        a.0.trusted_decrease(t, path, budget).unwrap(),
                        path::EstimateChange::Decreased
                    ),
                }
                let report = service(&mut a, t);
                assert_eq!(
                    (report.applied, report.failed),
                    (2, 0),
                    "{mode:?} step {step}"
                );
                let newest = a.0.paths().path_snapshot(path).unwrap();
                assert!(
                    a.1.is_output_reserved(flow_a),
                    "the owner keeps its reservation"
                );
                for id in [flow_a, flow_b] {
                    assert_eq!(a.0.binding(id).unwrap().snapshot, newest);
                    assert_eq!(a.1.managed_path(id).unwrap().ordinary_ip_budget, budget);
                }
                let refused =
                    a.0.submit(&mut a.1, t, ticket, context, &frame, external, |_| {
                        backend_calls += 1;
                        BackendOutcome::Submitted
                    })
                    .unwrap_err();
                assert_eq!(refused.error, Error::Obsolete);
                ticket = refused.ticket;
                assert_eq!(
                    (charges(&a, flow_a), charges(&a, flow_b)),
                    before,
                    "{mode:?}"
                );
                t += 1;
            }
            assert_eq!(backend_calls, 0, "held bytes never reach the backend");
            assert!(a.1.reject_unsubmitted(held).unwrap());
            a.0.cancel_submission(ticket);
            assert_eq!((charges(&a, flow_a), charges(&a, flow_b)), before);
            // A first-hop increase restores the learned estimate for both.
            a.0.set_link_mtu(link, 1500).unwrap();
            assert_eq!(service(&mut a, t).applied, 2);
            for id in [flow_a, flow_b] {
                assert_eq!(a.1.managed_path(id).unwrap().ordinary_ip_budget, m2);
            }
            // Repacketized remainder: every physical submission fits m2.
            let mut submitted = 0;
            for _ in 0..64 {
                t += 10;
                let Some((attempt, frame, external, wire)) = reserve(&mut a, flow_a, t, mode)
                else {
                    break;
                };
                let context = a.0.egress_context(&mut a.1, attempt).unwrap();
                let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
                let result =
                    a.0.submit(&mut a.1, t, ticket, context, &frame, external, |live| {
                        assert!(
                            frame.len() + external
                                <= live.binding.snapshot.ip_packet_budget().unwrap() as usize
                        );
                        BackendOutcome::Submitted
                    })
                    .unwrap();
                assert!(result == Submission::Submitted);
                assert!(wire.len() <= m2 as usize);
                submitted += 1;
                input(&mut b.0, &mut b.1, b.2, t + 1, &wire, 0);
                // Serialized ingress waits for the aggregate's last segment.
                while !a.1.is_output_reserved(flow_a)
                    && let Some(ack) = emit(&mut b.0, &mut b.1, t + 2)
                {
                    input(&mut a.0, &mut a.1, a.2, t + 3, &ack, 0);
                }
            }
            now = t;
            pump(&mut a, &mut b, &mut now);
            let mut bytes = vec![0; payload.len() + 1];
            assert_eq!(b.1.read(child, &mut bytes).unwrap(), payload.len());
            assert_eq!(&bytes[..payload.len()], &payload[..], "{mode:?}");
            assert_eq!(a.1.acknowledged(flow_a).unwrap(), payload.len() as u64);
            let after = a.1.transport_info(flow_a).unwrap();
            assert_eq!(
                (after.lost, after.retransmitted, after.recovery),
                (0, 0, false)
            );
            assert_eq!(charges(&a, flow_b), before.1, "the sibling is untouched");
            std::println!(
                "RESERVED v6={v6} mode={mode:?} held_ip={held_len} prefix_ip={:?} budgets={m1}->{m2}->{l3}->{m2} retries_refused=3 backend_calls={backend_calls} resubmitted={submitted} delivered={}",
                prefix.as_ref().map(Vec::len),
                payload.len()
            );
        }
    }
}

// Submit one held attempt of `owner`; if the barrier refuses it, return the
// reservation and resubmit the repacketized remainder. Each backend call
// checks the packet against the live budget. Returns whether the held bytes
// were refused and every submitted frame.
fn submit_or_repacketize(
    side: &mut Side,
    owner: ConnectionId,
    now: u64,
    held: (TransmitAttempt, Vec<u8>, EgressContext, SubmissionTicket),
) -> (bool, Vec<Vec<u8>>) {
    let (mut attempt, mut frame, mut context, mut ticket) = held;
    let mut refused = false;
    let mut frames = Vec::new();
    loop {
        let result = side
            .0
            .submit(&mut side.1, now, ticket, context, &frame, 0, |live| {
                // Never a newly invalid physical submission.
                assert!(frame.len() <= live.binding.snapshot.ip_packet_budget().unwrap() as usize);
                BackendOutcome::Submitted
            });
        match result {
            Ok(submitted) => {
                assert!(submitted == Submission::Submitted);
                frames.push(frame);
            }
            Err(refusal) => {
                assert_eq!(refusal.error, Error::Obsolete);
                assert!(side.1.reject_unsubmitted(attempt).unwrap());
                side.0.cancel_submission(refusal.ticket);
                refused = true;
            }
        }
        side.0.collect(&side.1).unwrap();
        if !side.1.is_output_reserved(owner) {
            return (refused, frames);
        }
        let next = reserve(side, owner, now, Held::Scalar).unwrap();
        (attempt, frame) = (next.0, next.1);
        context = side.0.egress_context(&mut side.1, attempt).unwrap();
        ticket = side.0.submission_ticket(&mut side.1, context).unwrap();
    }
}

pub(super) struct Rng(pub(super) u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub(super) fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    pub(super) fn pick<T: Copy>(&mut self, values: &[T]) -> T {
        values[self.below(values.len() as u64) as usize]
    }
}

#[derive(Default, Debug)]
struct Coverage {
    quoted_decreases: usize,
    deferred_reports: usize,
    pending_published: usize,
    probes_sent: usize,
    probe_raises: usize,
    direct_decreases: usize,
    link_changes: usize,
    direct_confirmations: usize,
    served_while_reserved: usize,
    refused_held: usize,
    submitted_held: usize,
    udp_notifications: usize,
    udp_refused: usize,
    udp_sent: usize,
    convergence_checks: usize,
    isolation_checks: usize,
    dscp_isolated: usize,
    destination_isolated: usize,
    source_isolated: usize,
    link_isolated: usize,
    unquoted_checks: usize,
}

// Randomized operations over four TCP owners and four UDP flows on one
// shared path and four isolated paths (another routing DSCP, destination,
// local source or link): router PTBs quoting one real flow (immediate or
// deferred, the latter applied at its own timeout and published), direct
// trusted decreases, first-hop decreases and increases, real TCP probes after
// the hold (submitted, acknowledged by the peer and published by the change
// service), direct PathService confirmations, held reservations, sends and
// change reads, with the change service
// run at random points. After every service pass every active client of each
// path holds that path's newest snapshot and every UDP flow reports exactly
// the newest unseen version; an operation on one path never changes another,
// and flows a PTB did not quote never repair.
#[test]
fn randomized_shared_fanout_converges_and_isolates_paths() {
    let mut total = Coverage::default();
    for seed in 1..=24u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let v6 = seed % 2 == 0;
        let cfg = config(4);
        let second = cfg.connection.timebase.units_per_second;
        let (local, remote) = addresses(v6);
        let mut a = isolating_side(local, 6000 + u64::from(seed), &cfg);
        let mut b = managed(remote, 7000 + u64::from(seed), cfg.clone());
        let listener = b.1.listen(remote, 4).unwrap();
        let tcp = [
            connect(&mut a, &cfg, 1000, 0),
            connect(&mut a, &cfg, 1001, 0),
            connect(&mut a, &cfg, 1002, 8),
            connect_from(&mut a, &cfg, second_source(v6), 1003),
        ];
        // The path index each TCP owner uses.
        const OWNER_PATH: [usize; 4] = [0, 0, 1, 3];
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        let children: Vec<_> = (0..4).map(|_| b.1.accept(listener).unwrap()).collect();
        // Proven delivery of full segments, so later reports below it defer
        // (until it delivers data, B's reports apply immediately).
        for id in [tcp[0], tcp[2], tcp[3]] {
            a.1.write(id, &[1; 1400]).unwrap();
        }
        pump(&mut a, &mut b, &mut now);
        let udp = [
            flow(&mut a, 5000, remote.ip(), 0),
            flow(&mut a, 5001, remote.ip(), 0),
            flow(&mut a, 5002, other_remote(v6), 0),
            flow(&mut a, 5003, link_remote(v6), 0),
        ];
        let tcp_path = |a: &Side, id| a.0.binding(id).unwrap().snapshot.path();
        let shared = tcp_path(&a, tcp[0]);
        let paths = [
            shared,
            tcp_path(&a, tcp[2]),
            limits(&mut a, udp[2]).path,
            tcp_path(&a, tcp[3]),
            limits(&mut a, udp[3]).path,
        ];
        assert_eq!(tcp_path(&a, tcp[1]), shared);
        assert_eq!(limits(&mut a, udp[0]).path, shared);
        assert_eq!(limits(&mut a, udp[1]).path, shared);
        for (p, &one) in paths.iter().enumerate() {
            assert!(paths[p + 1..].iter().all(|&other| other != one));
        }
        let mut seen: Vec<u64> = udp.iter().map(|&u| limits(&mut a, u).version).collect();
        let link = a.2.link();
        let sizes: &[u32] = if v6 {
            &[1480, 1420, 1400, 1350, 1300, 1280]
        } else {
            &[1400, 1300, 1200, 1100, 1000, 900, 576]
        };
        let mut held: Option<(
            ConnectionId,
            TransmitAttempt,
            Vec<u8>,
            EgressContext,
            SubmissionTicket,
        )> = None;
        let mut cov = Coverage::default();
        let mut bytes = [0; 65536];
        for _ in 0..80 {
            now += 1 + rng.below(20);
            let mut versions: Vec<u64> = paths
                .iter()
                .map(|&p| a.0.paths().path_snapshot(p).unwrap().version())
                .collect();
            let repairs: Vec<(u32, u32)> = tcp
                .iter()
                .map(|&id| {
                    let info = a.1.transport_info(id).unwrap();
                    (info.lost, info.retransmitted)
                })
                .collect();
            // Which path the operation may change (None: the link, all), and
            // whether any flow may legitimately repair (Some(f): only f).
            let mut target = Some(usize::MAX);
            let mut may_repair = Some(usize::MAX);
            match rng.below(11) {
                0 => {
                    let p = rng.below(paths.len() as u64) as usize;
                    if a.0
                        .trusted_decrease(now, paths[p], rng.pick(sizes))
                        .unwrap()
                        == path::EstimateChange::Decreased
                    {
                        cov.direct_decreases += 1;
                    }
                    target = Some(p);
                }
                1 | 2 if held.is_none() => {
                    let f = rng.below(tcp.len() as u64) as usize;
                    let _ = a.1.write(tcp[f], &[f as u8; 1300]);
                    if let Some((attempt, frame, _, _)) = reserve(&mut a, tcp[f], now, Held::Scalar)
                    {
                        let context = a.0.egress_context(&mut a.1, attempt).unwrap();
                        let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
                        let (_, frames) = submit_or_repacketize(
                            &mut a,
                            tcp[f],
                            now,
                            (attempt, frame, context, ticket),
                        );
                        let frame = &frames[0];
                        match a
                            .0
                            .input_icmp(&mut a.1, a.2, now + 1, &ptb(frame, rng.pick(sizes)), None)
                        {
                            Ok(IcmpDispatch::Completed(IcmpOutcome::Tcp { report, .. })) => {
                                match report {
                                    TcpReport::PacketTooBig(PmtuFeedback::Decreased { .. }) => {
                                        cov.quoted_decreases += 1
                                    }
                                    TcpReport::PacketTooBig(PmtuFeedback::Deferred) => {
                                        cov.deferred_reports += 1
                                    }
                                    _ => {}
                                }
                            }
                            _ => {}
                        }
                        target = Some(OWNER_PATH[f]);
                        may_repair = Some(f);
                    }
                }
                3 => {
                    a.0.set_link_mtu(link, rng.pick(&[1500, 1500, 1450, 1400, 1300]))
                        .unwrap();
                    cov.link_changes += 1;
                    target = None;
                }
                4 => {
                    // A probe's network fact written directly to PathService
                    // after the real hold (no connection, receipt or Host).
                    now += 601 * second;
                    let p = rng.below(paths.len() as u64) as usize;
                    let s = a.0.paths().path_snapshot(paths[p]).unwrap();
                    if let Some(learned) = s.learned_mtu() {
                        let len = (learned + 1 + rng.below(200) as u32).min(s.first_hop_mtu());
                        let confirmed = a.0.paths.confirm_delivery(
                            paths[p],
                            len,
                            s.negative_revision(),
                            now,
                            now,
                        );
                        if confirmed == Ok(path::DeliveryConfirmation::Raised) {
                            cov.direct_confirmations += 1;
                        }
                    }
                    target = Some(p);
                }
                5 if held.is_none() => {
                    let f = rng.below(tcp.len() as u64) as usize;
                    let _ = a.1.write(tcp[f], &[f as u8; 1400]);
                    if let Some((attempt, frame, _, _)) = reserve(&mut a, tcp[f], now, Held::Scalar)
                    {
                        let context = a.0.egress_context(&mut a.1, attempt).unwrap();
                        let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
                        held = Some((tcp[f], attempt, frame, context, ticket));
                    }
                }
                6 => {
                    if let Some((owner, attempt, frame, context, ticket)) = held.take() {
                        let (refused, frames) = submit_or_repacketize(
                            &mut a,
                            owner,
                            now,
                            (attempt, frame, context, ticket),
                        );
                        for frame in &frames {
                            input(&mut b.0, &mut b.1, b.2, now + 1, frame, 0);
                        }
                        if refused {
                            cov.refused_held += 1;
                        } else {
                            cov.submitted_held += 1;
                        }
                    }
                    may_repair = None;
                }
                7 if held.is_none() => {
                    // Timers apply deferred reports at the quoted data's own
                    // timeout; then the wire delivers and acknowledges.
                    for _ in 0..rng.below(4) + 1 {
                        if let Some(deadline) = a.1.next_deadline() {
                            now = now.max(deadline);
                            a.1.on_timeout(now, 32).unwrap();
                        }
                        pump(&mut a, &mut b, &mut now);
                    }
                    for &child in &children {
                        while b.1.read(child, &mut bytes).unwrap_or(0) > 0 {}
                    }
                    pump(&mut a, &mut b, &mut now);
                    may_repair = None;
                }
                8 => {
                    let u = rng.below(3) as usize;
                    let limit = limits(&mut a, udp[u]);
                    let len = rng.pick(&[64, limit.max_payload, limit.max_payload + 1, 1472]);
                    let mut packet = [0; 1600];
                    let result = a.0.udp_send(
                        &a.1,
                        now,
                        udp[u],
                        None,
                        &vec![7; len],
                        &mut packet,
                        |_, _| BackendOutcome::Submitted,
                    );
                    if len <= limit.max_payload {
                        assert!(matches!(result, Ok(UdpSent::Submitted(_))));
                        cov.udp_sent += 1;
                    } else {
                        assert_eq!(
                            result,
                            Err(UdpSendError::TooBig {
                                max_payload: limit.max_payload
                            })
                        );
                        cov.udp_refused += 1;
                    }
                }
                9 | 10 if held.is_none() => {
                    // A real TCP probe on a shared-path owner after the hold:
                    // drain outstanding data, publish earlier results, then
                    // submit, deliver and acknowledge the probe and publish it.
                    now += 601 * second;
                    for _ in 0..4 {
                        if let Some(deadline) = a.1.next_deadline() {
                            now = now.max(deadline);
                            a.1.on_timeout(now, 32).unwrap();
                        }
                        pump(&mut a, &mut b, &mut now);
                    }
                    for &child in &children {
                        while b.1.read(child, &mut bytes).unwrap_or(0) > 0 {}
                    }
                    pump(&mut a, &mut b, &mut now);
                    let report = service(&mut a, now);
                    cov.pending_published += report.decreased;
                    cov.probe_raises += report.raised;
                    versions = paths
                        .iter()
                        .map(|&p| a.0.paths().path_snapshot(p).unwrap().version())
                        .collect();
                    let f = rng.below(2) as usize;
                    let _ = a.1.write(tcp[f], &[9; 6000]);
                    // Past the peer's clock after the last exchange.
                    now += 10;
                    target = None;
                    if let Some((attempt, _, frame)) = selected(&mut a.1, now) {
                        let probe = a.1.transmit_discovery_intent(attempt);
                        let context = a.0.egress_context(&mut a.1, attempt).unwrap();
                        let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
                        let submitted =
                            a.0.submit(&mut a.1, now, ticket, context, &frame, 0, |_| {
                                BackendOutcome::Submitted
                            })
                            .unwrap();
                        assert!(submitted == Submission::Submitted);
                        input(&mut b.0, &mut b.1, b.2, now + 1, &frame, 0);
                        pump(&mut b, &mut a, &mut now);
                        let report = service(&mut a, now);
                        assert_eq!(report.failed, 0, "seed {seed}");
                        cov.pending_published += report.decreased;
                        cov.probe_raises += report.raised;
                        if let Some(intent) = probe {
                            cov.probes_sent += 1;
                            let at = intent.binding().snapshot.path();
                            if report.decreased == 0 {
                                target = paths.iter().position(|&p| p == at);
                            }
                            if report.raised > 0 {
                                // The exchange may confirm a later, larger probe of
                                // the same transfer too; never beyond the first hop.
                                let raised = a.0.paths().path_snapshot(at).unwrap();
                                assert!(
                                    raised.learned_mtu().is_some_and(|mtu| {
                                        mtu >= intent.ip_packet_len() && mtu <= raised.first_hop_mtu()
                                    }),
                                    "seed {seed}"
                                );
                            }
                        } else {
                            assert_eq!(report.raised, 0, "seed {seed}: ordinary ACK");
                        }
                    }
                    // The reverse exchange left A's clock ahead of `now`.
                    now += 10;
                    may_repair = None;
                }
                _ => {}
            }
            if held.is_some() {
                // Even a service pass must not let held bytes repair.
                may_repair = may_repair.or(Some(usize::MAX));
            }
            if let Some(p) = target {
                for (q, &version) in versions.iter().enumerate() {
                    if q != p {
                        let current = a.0.paths().path_snapshot(paths[q]).unwrap().version();
                        assert_eq!(current, version, "seed {seed}: path {q} isolated from {p}");
                        cov.isolation_checks += 1;
                        if p == 0 {
                            match q {
                                1 => cov.dscp_isolated += 1,
                                2 => cov.destination_isolated += 1,
                                3 => cov.source_isolated += 1,
                                _ => cov.link_isolated += 1,
                            }
                        }
                    }
                }
            }
            if rng.below(3) != 0 {
                let before: Vec<_> = paths
                    .iter()
                    .map(|&p| a.0.paths().path_snapshot(p).unwrap())
                    .collect();
                let report = service(&mut a, now);
                assert_eq!(
                    (report.failed, report.first_error),
                    (0, None),
                    "seed {seed}"
                );
                // A pass changes shared state only by publishing results, and
                // only on a TCP owner's path: a published deferred report is a
                // new negative fact there (lower estimate, new revision); a
                // pass that publishes nothing changes no path.
                let after: Vec<_> = paths
                    .iter()
                    .map(|&p| a.0.paths().path_snapshot(p).unwrap())
                    .collect();
                for p in [2, 4] {
                    assert_eq!(after[p], before[p], "seed {seed}: UDP-only path");
                }
                let lowered = [0, 1, 3]
                    .into_iter()
                    .filter(|&p| {
                        after[p].negative_revision() != before[p].negative_revision()
                            && after[p].learned_mtu().is_some_and(|mtu| {
                                before[p].learned_mtu().is_none_or(|old| mtu < old)
                            })
                    })
                    .count();
                if report.decreased == 0 {
                    assert_eq!(lowered, 0, "seed {seed}: {report:?}");
                } else {
                    assert!(
                        (1..=report.decreased).contains(&lowered),
                        "seed {seed}: {report:?} lowered {lowered}"
                    );
                }
                if report.decreased + report.raised == 0 {
                    assert_eq!(after, before, "seed {seed}");
                } else {
                    let again = service(&mut a, now);
                    assert_eq!((again.decreased, again.raised), (0, 0), "seed {seed}: once");
                }
                cov.pending_published += report.decreased;
                cov.probe_raises += report.raised;
                if held.is_some() {
                    cov.served_while_reserved += 1;
                }
                for &id in &tcp {
                    let binding = a.0.binding(id).unwrap();
                    let newest = a.0.paths().path_snapshot(binding.snapshot.path()).unwrap();
                    assert_eq!(binding.snapshot, newest, "seed {seed}");
                    assert!(!dirty(&a, id));
                    assert_eq!(a.1.managed_path(id).unwrap().binding.snapshot, newest);
                }
                for (u, &id) in udp.iter().enumerate() {
                    let current = limits(&mut a, id);
                    let newest = a.0.paths().path_snapshot(current.path).unwrap();
                    assert_eq!(current.version, newest.version());
                    let change = a.0.udp_path_change(id).unwrap();
                    if newest.version() > seen[u] {
                        assert_eq!(change, Some(current), "seed {seed}: newest unseen version");
                        seen[u] = current.version;
                        cov.udp_notifications += 1;
                    } else {
                        assert_eq!(change, None, "seed {seed}");
                    }
                }
                cov.convergence_checks += 1;
            }
            if let Some(quoted) = may_repair {
                for (f, &id) in tcp.iter().enumerate() {
                    if f != quoted {
                        let info = a.1.transport_info(id).unwrap();
                        assert_eq!((info.lost, info.retransmitted), repairs[f], "seed {seed}");
                        cov.unquoted_checks += 1;
                    }
                }
            }
        }
        macro_rules! add {
            ($($field:ident),*) => { $(total.$field += cov.$field;)* };
        }
        add!(
            quoted_decreases,
            deferred_reports,
            pending_published,
            probes_sent,
            probe_raises,
            direct_decreases,
            link_changes,
            direct_confirmations,
            served_while_reserved,
            refused_held,
            submitted_held,
            udp_notifications,
            udp_refused,
            udp_sent,
            convergence_checks,
            isolation_checks,
            dscp_isolated,
            destination_isolated,
            source_isolated,
            link_isolated,
            unquoted_checks
        );
    }
    std::println!("FANOUT_MODEL seeds=24 {total:?}");
    let t = &total;
    for (name, count) in [
        ("quoted_decreases", t.quoted_decreases),
        ("deferred_reports", t.deferred_reports),
        ("pending_published", t.pending_published),
        ("direct_decreases", t.direct_decreases),
        ("link_changes", t.link_changes),
        ("probes_sent", t.probes_sent),
        ("probe_raises", t.probe_raises),
        ("direct_confirmations", t.direct_confirmations),
        ("dscp_isolated", t.dscp_isolated),
        ("destination_isolated", t.destination_isolated),
        ("source_isolated", t.source_isolated),
        ("link_isolated", t.link_isolated),
        ("served_while_reserved", t.served_while_reserved),
        ("refused_held", t.refused_held),
        ("submitted_held", t.submitted_held),
        ("udp_notifications", t.udp_notifications),
        ("udp_refused", t.udp_refused),
        ("udp_sent", t.udp_sent),
    ] {
        assert!(count > 0, "uncovered: {name}");
    }
}
