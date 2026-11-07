use crate::*;
use alloc::vec::Vec;
fn endpoint(limit: usize) -> Endpoint {
    Endpoint::new(
        EndpointConfig {
            max_connections: 8,
            max_route_policies: limit,
            connection: ConnectionConfig {
                pmtud: Some(PmtudConfig::new(1500)),
                initial_window: InitialWindow::Iw10,
                timestamps: false,
                nagle: false,
                delayed_ack_us: 0,
                ..Default::default()
            },
            ..Default::default()
        },
        [1; 32],
        0,
        |_| true,
    )
    .unwrap()
}
fn policy(mtu: u32, mss: u16, low: u32) -> RoutePolicy {
    RoutePolicy {
        mtu: Some(mtu),
        advertised_mss: Some(mss),
        initial_search_low: Some(low),
        ..Default::default()
    }
}
fn transmit(e: &mut Endpoint, now: u64) -> (Transmit, Vec<u8>) {
    let mut b = [0; 2048];
    let p = e.poll_transmit(now, &mut b, 64).unwrap().packet.unwrap();
    (p, b[..p.len].to_vec())
}

#[test]
fn destination_policy_selects_active_and_passive_creation_from_actual_peer() {
    for ipv4 in [true, false] {
        let (local, peer, other): (core::net::IpAddr, _, _) = if ipv4 {
            (
                "192.0.2.1".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
                "192.0.2.3".parse().unwrap(),
            )
        } else {
            (
                "2001:db8::1".parse().unwrap(),
                "2001:db8::2".parse().unwrap(),
                "2001:db8::3".parse().unwrap(),
            )
        };
        let mtu = if ipv4 { 640 } else { 1280 };
        let low = if ipv4 { 552 } else { 1280 };
        let mut e = endpoint(4);
        e.set_destination_route(0, peer, Some(policy(mtu, 600, low)))
            .unwrap();
        e.set_destination_route(0, other, Some(policy(1400, 900, 1300)))
            .unwrap();
        let active = e
            .connect(
                0,
                core::net::SocketAddr::new(local, 40000),
                core::net::SocketAddr::new(peer, 8080),
            )
            .unwrap();
        let (p, b) = transmit(&mut e, 0);
        assert_eq!(wire::parse(p.ip, &b).unwrap().options.mss, Some(600));
        assert_eq!(e.path_mtu_info(active).unwrap().unwrap().current_mtu, mtu);
        let listener = e
            .listen(core::net::SocketAddr::new(local, 8080), 4)
            .unwrap();
        let ip = IpMetadata {
            source: other,
            destination: local,
        };
        let mut b = [0; 128];
        let n = wire::encode(
            ip,
            wire::Header {
                source_port: 40001,
                destination_port: 8080,
                sequence: 100,
                acknowledgment: 0,
                flags: wire::SYN,
                window: 50000,
                urgent_pointer: 0,
            },
            &[2, 4, 5, 180],
            &[],
            &mut b,
        )
        .unwrap();
        e.input(1, ip, &b[..n]).unwrap();
        let (p, b) = transmit(&mut e, 1);
        let synack = wire::parse(p.ip, &b).unwrap();
        assert_eq!(synack.options.mss, Some(900));
        let mut b = [0; 128];
        let n = wire::encode(
            ip,
            wire::Header {
                source_port: 40001,
                destination_port: 8080,
                sequence: 101,
                acknowledgment: synack.header.sequence.wrapping_add(1),
                flags: wire::ACK,
                window: 50000,
                urgent_pointer: 0,
            },
            &[],
            &[],
            &mut b,
        )
        .unwrap();
        e.input(2, ip, &b[..n]).unwrap();
        let child = e.accept(listener).unwrap();
        let info = e.path_mtu_info(child).unwrap().unwrap();
        assert_eq!(
            (info.current_mtu, info.search_low, info.search_high),
            (1400, 1300, 1400)
        );
    }
}

#[test]
fn destination_update_is_atomic_across_held_and_unheld_connections_and_future_opens() {
    let mut e = endpoint(4);
    let peer = "192.0.2.2".parse().unwrap();
    let original = policy(640, 600, 552);
    e.set_destination_route(0, peer, Some(original)).unwrap();
    let one = e
        .connect(
            0,
            "192.0.2.1:40000".parse().unwrap(),
            "192.0.2.2:8080".parse().unwrap(),
        )
        .unwrap();
    let two = e
        .connect(
            0,
            "192.0.2.1:40001".parse().unwrap(),
            "192.0.2.2:8080".parse().unwrap(),
        )
        .unwrap();
    let other = e
        .connect(
            0,
            "192.0.2.1:40002".parse().unwrap(),
            "192.0.2.3:8080".parse().unwrap(),
        )
        .unwrap();
    e.enable_output_reservations().unwrap();
    let mut b = [0; 2048];
    let (_, token) = e.poll_reserved_transmit_for(0, two, &mut b, 64).unwrap();
    let before = (
        e.path_mtu_info(one).unwrap(),
        e.path_mtu_info(two).unwrap(),
        e.path_mtu_info(other).unwrap(),
        e.next_deadline(),
    );
    assert_eq!(
        e.set_destination_route(1000, peer, Some(policy(1500, 1460, 552))),
        Err(EndpointError::OutputReserved)
    );
    assert_eq!(e.destination_route(peer), Some(original));
    assert_eq!(
        (
            e.path_mtu_info(one).unwrap(),
            e.path_mtu_info(two).unwrap(),
            e.path_mtu_info(other).unwrap(),
            e.next_deadline()
        ),
        before
    );
    assert!(e.accept_transmit(1, token.unwrap()).unwrap());
    crate::allocation_tests::fail_after(0, || {
        e.set_destination_route(2, peer, Some(policy(1500, 1460, 552)))
    })
    .unwrap();
    assert_eq!(e.path_mtu_info(one).unwrap().unwrap().route_mtu, Some(1500));
    assert_eq!(e.path_mtu_info(two).unwrap().unwrap().route_mtu, Some(1500));
    assert_eq!(e.path_mtu_info(other).unwrap(), before.2);
    assert_eq!(e.transport_info(one).unwrap().advertised_mss, 600);
    let next = e
        .connect(
            3,
            "192.0.2.1:40003".parse().unwrap(),
            "192.0.2.2:8080".parse().unwrap(),
        )
        .unwrap();
    assert_eq!(e.transport_info(next).unwrap().advertised_mss, 1460);
    e.set_destination_route(4, peer, None).unwrap();
    assert_eq!(e.destination_route(peer), None);
    assert_eq!(e.path_mtu_info(one).unwrap().unwrap().route_mtu, None);
}

#[test]
fn destination_configuration_validation_capacity_and_allocation_failure_are_atomic() {
    let mut e = endpoint(1);
    let peer = "192.0.2.2".parse().unwrap();
    assert!(
        crate::allocation_tests::fail_after(0, || e.set_destination_route(
            1000,
            peer,
            Some(policy(640, 600, 552))
        ))
        .is_err()
    );
    assert_eq!(e.destination_route(peer), None);
    e.set_destination_route(1, peer, Some(policy(640, 600, 552)))
        .unwrap();
    assert_eq!(
        e.set_destination_route(
            1000,
            "192.0.2.3".parse().unwrap(),
            Some(policy(640, 600, 552))
        ),
        Err(EndpointError::LimitReached)
    );
    assert!(
        e.set_destination_route(1000, peer, Some(policy(500, 0, 552)))
            .is_err()
    );
    assert_eq!(e.destination_route(peer), Some(policy(640, 600, 552)));
    e.set_destination_route(2, peer, None).unwrap();
    e.set_destination_route(
        3,
        "192.0.2.3".parse().unwrap(),
        Some(policy(1280, 900, 1024)),
    )
    .unwrap();
    let mut defaults = ConnectionConfig {
        advertised_mss: Some(500),
        pmtud: Some(PmtudConfig::new(1500)),
        ..Default::default()
    };
    defaults.pmtud.as_mut().unwrap().route_mtu = Some(1280);
    assert!(policy(1500, 1460, 1024).validate(&defaults, true).is_ok());
    let mut e = Endpoint::new(
        EndpointConfig {
            connection: defaults,
            ..Default::default()
        },
        [1; 32],
        0,
        |_| true,
    )
    .unwrap();
    e.set_destination_route(0, peer, Some(policy(1500, 1460, 1024)))
        .unwrap();
    let id = e
        .connect(
            0,
            "192.0.2.1:40000".parse().unwrap(),
            "192.0.2.2:8080".parse().unwrap(),
        )
        .unwrap();
    assert_eq!(e.path_mtu_info(id).unwrap().unwrap().current_mtu, 1280);
    assert_eq!(e.transport_info(id).unwrap().advertised_mss, 500);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-4
//= type=test
//= reason=TCP actor: endpoint protocol defaults plus bounded destination policies independently select initial effective MTU/search bounds for active and passive peers in IPv4/IPv6. Connectionless-protocol defaults are outside this TCP implementation; the shared IP-layer path cache (ntcp-path PathService) and OS route lookup are not claimed by this test.
//# Implementations MAY use different heuristics to select the initial effective Path MTU for each protocol. Connectionless protocols and protocols that do not support PLPMTUD SHOULD have their own default value for the initial effective Path MTU, which can be set to a more conservative (smaller) value than the initial value used by TCP and other protocols that are well suited to PLPMTUD. There SHOULD be per-protocol and per-route limits on the initial effective Path MTU (eff_pmtu) and the upper searching limit (search_high). See Section 7.2 for further discussion.
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.2
//= type=test
//= reason=Real destination lookup supplies independent initial effective/low/high values before construction; unrelated peer defaults and invalid-update atomicity are observed through public Endpoint APIs. Native parser and IO-preservation tests provide the application configuration path.
//# There SHOULD be per-protocol and per-route configuration options to override initial values for eff_pmtu and other PLPMTUD state variables.
fn destination_initial_effective_and_search_bounds_are_independent() {
    for ipv4 in [true, false] {
        let (local, one, two, other): (core::net::IpAddr, _, _, _) = if ipv4 {
            (
                "192.0.2.1".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
                "192.0.2.3".parse().unwrap(),
                "192.0.2.4".parse().unwrap(),
            )
        } else {
            (
                "2001:db8::1".parse().unwrap(),
                "2001:db8::2".parse().unwrap(),
                "2001:db8::3".parse().unwrap(),
                "2001:db8::4".parse().unwrap(),
            )
        };
        let mut e = endpoint(4);
        e.set_destination_route(
            0,
            one,
            Some(RoutePolicy {
                mtu: Some(1400),
                initial_mtu: Some(1320),
                initial_search_low: Some(1280),
                initial_search_high: Some(1380),
                ..Default::default()
            }),
        )
        .unwrap();
        e.set_destination_route(
            0,
            two,
            Some(RoutePolicy {
                mtu: Some(1500),
                initial_mtu: Some(1400),
                initial_search_low: Some(1300),
                initial_search_high: Some(1450),
                ..Default::default()
            }),
        )
        .unwrap();
        for (i, remote, expected) in [
            (0, one, (1320, 1280, 1380)),
            (1, two, (1400, 1300, 1450)),
            (2, other, (1500, if ipv4 { 1024 } else { 1280 }, 1500)),
        ] {
            let id = e
                .connect(
                    1,
                    core::net::SocketAddr::new(local, 40000 + i),
                    core::net::SocketAddr::new(remote, 8080),
                )
                .unwrap();
            let info = e.path_mtu_info(id).unwrap().unwrap();
            assert_eq!(
                (info.current_mtu, info.search_low, info.search_high),
                expected
            );
        }
    }
}
