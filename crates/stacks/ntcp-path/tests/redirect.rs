// Redirect overrides beneath administrative routes: installation,
// replacement, type-of-service scope, every end event, bounded eviction,
// and the administrative restrictions a forwarding transition keeps.
use ntcp_path::*;

fn address(value: &str) -> ScopedAddress {
    ScopedAddress::new(value.parse().unwrap(), None).unwrap()
}

struct Fixture {
    service: PathService,
    link: LinkId,
    default: RouteId,
    request: PathRequest,
}

// One IPv4 link with a default route through gateway 192.0.2.1 and the
// directly connected 192.0.2.0/24.
fn fixture(paths: usize) -> Fixture {
    let mut service = PathService::new(
        ContextId::new(901),
        Limits {
            links: 2,
            sources: 1,
            source_owners: 1,
            routes: 3,
            paths,
            clients: paths,
        },
        [1; 16],
    )
    .unwrap();
    let link = service.register_link(InterfaceKey(1), 1500).unwrap();
    let source = service
        .register_source(address("192.0.2.10"), link)
        .unwrap();
    let default = service
        .add_route(Route {
            destination: IpPrefix::new("0.0.0.0".parse().unwrap(), 0).unwrap(),
            source: None,
            dscp: None,
            link,
            next_hop: NextHop::Gateway(address("192.0.2.1")),
            metric: 0,
        })
        .unwrap();
    service
        .add_route(Route {
            destination: IpPrefix::new("192.0.2.0".parse().unwrap(), 24).unwrap(),
            source: None,
            dscp: None,
            link,
            next_hop: NextHop::OnLink,
            metric: 0,
        })
        .unwrap();
    let request = PathRequest {
        source,
        destination: address("198.51.100.7"),
        dscp: Dscp::new(0).unwrap(),
    };
    Fixture {
        service,
        link,
        default,
        request,
    }
}

fn hop(value: &str) -> ResolvedNextHop {
    ResolvedNextHop::Address(address(value))
}

#[test]
fn redirect_moves_one_destination_beneath_its_route_and_notifies() {
    let mut f = fixture(4);
    let (client, before) = f.service.acquire(f.request).unwrap();
    f.service.acknowledge(client, before.stamp()).unwrap();
    let key = before.key();
    assert_eq!(key.next_hop(), hop("192.0.2.1"));
    // Only the current first hop may redirect, never to this host.
    for (sender, target) in [
        ("192.0.2.2", "192.0.2.3"),
        ("192.0.2.1", "192.0.2.10"),
        ("192.0.2.1", "192.0.2.1"),
    ] {
        assert_eq!(
            f.service
                .redirect(key, address(sender), address(target), false),
            Err(Error::InvalidArgument)
        );
    }
    let revision = f.service.revision();
    assert_eq!(
        f.service
            .redirect(key, address("192.0.2.1"), address("192.0.2.2"), false),
        Ok(())
    );
    assert!(f.service.revision() > revision);
    // The bound path is invalidated and its client notified.
    assert!(f.service.is_dirty(client).unwrap());
    assert_eq!(
        f.service.snapshot(client).unwrap().status(),
        PathStatus::Invalidated(InvalidationReason::SelectionChanged)
    );
    let (client, after) = f.service.rebind(client, f.request).unwrap();
    let redirected = after.key();
    assert_eq!(redirected.next_hop(), hop("192.0.2.2"));
    // The administrative route still selects it.
    assert_eq!(redirected.route(), f.default);
    assert_ne!(redirected, key);
    // Another destination of the same route keeps its gateway.
    let other = PathRequest {
        destination: address("203.0.113.9"),
        ..f.request
    };
    assert_eq!(
        f.service.resolve(other).unwrap().key().next_hop(),
        hop("192.0.2.1")
    );
    // The old router no longer forwards it; the old key is stale.
    assert_eq!(
        f.service.redirect(
            redirected,
            address("192.0.2.2"),
            address("192.0.2.2"),
            false
        ),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        f.service
            .redirect(key, address("192.0.2.1"), address("192.0.2.2"), false),
        Err(Error::SelectionChanged)
    );
    // The new first hop may redirect again; then the destination is
    // reached directly and is not redirected further.
    f.service
        .redirect(
            redirected,
            address("192.0.2.2"),
            address("198.51.100.7"),
            false,
        )
        .unwrap();
    let (_, direct) = f.service.rebind(client, f.request).unwrap();
    assert_eq!(direct.key().next_hop(), hop("198.51.100.7"));
    assert_eq!(
        f.service.redirect(
            direct.key(),
            address("198.51.100.7"),
            address("192.0.2.3"),
            false
        ),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn type_of_service_redirects_apply_only_to_their_dscp() {
    let mut f = fixture(4);
    let key = f.service.resolve(f.request).unwrap().key();
    f.service
        .redirect(key, address("192.0.2.1"), address("192.0.2.2"), true)
        .unwrap();
    assert_eq!(
        f.service.resolve(f.request).unwrap().key().next_hop(),
        hop("192.0.2.2")
    );
    let marked = PathRequest {
        dscp: Dscp::new(46).unwrap(),
        ..f.request
    };
    let marked_key = f.service.resolve(marked).unwrap().key();
    assert_eq!(marked_key.next_hop(), hop("192.0.2.1"));
    // A Redirect for every type of service yields to the specific one.
    f.service
        .redirect(
            marked_key,
            address("192.0.2.1"),
            address("192.0.2.3"),
            false,
        )
        .unwrap();
    assert_eq!(
        f.service.resolve(marked).unwrap().key().next_hop(),
        hop("192.0.2.3")
    );
    assert_eq!(
        f.service.resolve(f.request).unwrap().key().next_hop(),
        hop("192.0.2.2")
    );
}

// A router that is the first hop of one type of service only, through a
// type-of-service override, redirects only that type of service, even
// with a Redirect for every type of service.
#[test]
fn general_redirect_from_a_type_of_service_target_stays_specific() {
    let mut f = fixture(4);
    let marked = PathRequest {
        dscp: Dscp::new(24).unwrap(),
        ..f.request
    };
    let key = f.service.resolve(marked).unwrap().key();
    f.service
        .redirect(key, address("192.0.2.1"), address("192.0.2.253"), true)
        .unwrap();
    let (client, specific) = f.service.acquire(marked).unwrap();
    f.service.acknowledge(client, specific.stamp()).unwrap();
    assert_eq!(specific.key().next_hop(), hop("192.0.2.253"));
    // The type-of-service target is no first hop of the other flows.
    assert_eq!(
        f.service.redirect(
            f.service.resolve(f.request).unwrap().key(),
            address("192.0.2.253"),
            address("192.0.2.252"),
            false
        ),
        Err(Error::InvalidArgument)
    );
    f.service
        .redirect(
            specific.key(),
            address("192.0.2.253"),
            address("192.0.2.252"),
            false,
        )
        .unwrap();
    // The quoted type of service moves and its client is notified.
    assert!(f.service.is_dirty(client).unwrap());
    assert_eq!(
        f.service.resolve(marked).unwrap().key().next_hop(),
        hop("192.0.2.252")
    );
    // Every other type of service keeps the configured gateway.
    assert_eq!(
        f.service.resolve(f.request).unwrap().key().next_hop(),
        hop("192.0.2.1")
    );
}

#[test]
fn general_redirect_from_the_first_hop_of_every_flow_moves_every_flow() {
    let mut f = fixture(4);
    let marked = PathRequest {
        dscp: Dscp::new(24).unwrap(),
        ..f.request
    };
    let key = f.service.resolve(marked).unwrap().key();
    f.service
        .redirect(key, address("192.0.2.1"), address("192.0.2.253"), true)
        .unwrap();
    let key = f.service.resolve(f.request).unwrap().key();
    f.service
        .redirect(key, address("192.0.2.1"), address("192.0.2.253"), false)
        .unwrap();
    // 192.0.2.253 is now the first hop of every type of service.
    let (plain, unmarked) = f.service.acquire(f.request).unwrap();
    f.service.acknowledge(plain, unmarked.stamp()).unwrap();
    let (client, specific) = f.service.acquire(marked).unwrap();
    f.service.acknowledge(client, specific.stamp()).unwrap();
    assert_eq!(unmarked.key().next_hop(), hop("192.0.2.253"));
    assert_eq!(specific.key().next_hop(), hop("192.0.2.253"));
    // Its Redirect for every type of service, quoting a marked packet,
    // moves both.
    f.service
        .redirect(
            specific.key(),
            address("192.0.2.253"),
            address("192.0.2.252"),
            false,
        )
        .unwrap();
    assert!(f.service.is_dirty(plain).unwrap());
    assert!(f.service.is_dirty(client).unwrap());
    for request in [f.request, marked] {
        assert_eq!(
            f.service.resolve(request).unwrap().key().next_hop(),
            hop("192.0.2.252")
        );
    }
}

#[test]
fn overrides_end_only_by_events() {
    let resolve = |f: &Fixture| f.service.resolve(f.request).unwrap().key().next_hop();
    let install = |f: &mut Fixture| {
        let key = f.service.resolve(f.request).unwrap().key();
        f.service
            .redirect(key, address("192.0.2.1"), address("192.0.2.2"), false)
            .unwrap();
        assert_eq!(resolve(f), hop("192.0.2.2"));
    };
    // Route replacement, even with identical text, ends it.
    let mut f = fixture(4);
    install(&mut f);
    let definition = f.service.route(f.default).unwrap();
    f.default = f.service.replace_route(f.default, definition).unwrap();
    assert_eq!(resolve(&f), hop("192.0.2.1"));
    // Route removal ends it (the destination then has no route).
    install(&mut f);
    f.service.remove_route(f.default).unwrap();
    assert!(f.service.resolve(f.request).is_err());
    // Neighbor loss: the target or the sender unreachable.
    let mut f = fixture(4);
    for neighbor in ["192.0.2.2", "192.0.2.1"] {
        install(&mut f);
        assert_eq!(
            f.service
                .end_redirects(f.link, address("192.0.2.9"), NeighborLoss::Unreachable),
            Ok(0)
        );
        assert_eq!(
            f.service
                .end_redirects(f.link, address(neighbor), NeighborLoss::Unreachable),
            Ok(1)
        );
        assert_eq!(resolve(&f), hop("192.0.2.1"));
    }
    // A router target that is no longer a router; an on-link target is not
    // used as a router.
    install(&mut f);
    assert!(f.service.redirect_router(f.link, address("192.0.2.2")));
    f.service
        .end_redirects(f.link, address("192.0.2.2"), NeighborLoss::NotRouter)
        .unwrap();
    assert_eq!(resolve(&f), hop("192.0.2.1"));
    let key = f.service.resolve(f.request).unwrap().key();
    f.service
        .redirect(key, address("192.0.2.1"), address("198.51.100.7"), false)
        .unwrap();
    assert!(!f.service.redirect_router(f.link, address("198.51.100.7")));
    assert_eq!(
        f.service
            .end_redirects(f.link, address("198.51.100.7"), NeighborLoss::NotRouter),
        Ok(0)
    );
    assert_eq!(resolve(&f), hop("198.51.100.7"));
    // Time alone never ends it; removing the link does.
    f.service.remove_link(f.link).unwrap();
    assert!(f.service.resolve(f.request).is_err());
}

#[test]
fn bounded_population_evicts_the_oldest_override() {
    let mut f = fixture(2);
    let destinations = ["198.51.100.1", "198.51.100.2", "198.51.100.3"];
    for destination in destinations {
        let request = PathRequest {
            destination: address(destination),
            ..f.request
        };
        let key = f.service.resolve(request).unwrap().key();
        f.service
            .redirect(key, address("192.0.2.1"), address("192.0.2.2"), false)
            .unwrap();
    }
    let next_hops: Vec<_> = destinations
        .iter()
        .map(|d| {
            let request = PathRequest {
                destination: address(d),
                ..f.request
            };
            f.service.resolve(request).unwrap().key().next_hop()
        })
        .collect();
    assert_eq!(
        next_hops,
        [hop("192.0.2.1"), hop("192.0.2.2"), hop("192.0.2.2")]
    );
}

#[test]
fn exact_path_restrictions_survive_the_forwarding_transition() {
    let mut f = fixture(4);
    let (client, snapshot) = f.service.acquire(f.request).unwrap();
    let path = snapshot.path();
    let plan = f
        .service
        .prepare_admin(
            AdminChange {
                target: AdminTarget::Path(path),
                expected: 0,
                policy: AdminPolicy {
                    discovery_disabled: false,
                    estimate: Some(1200),
                },
            },
            0,
            600,
        )
        .unwrap();
    f.service.commit_admin(plan).unwrap();
    let restricted = f.service.snapshot(client).unwrap();
    assert_eq!(restricted.pmtu_estimate(), Ok(1200));
    f.service
        .redirect(
            restricted.key(),
            address("192.0.2.1"),
            address("192.0.2.2"),
            false,
        )
        .unwrap();
    let (client, moved) = f.service.rebind(client, f.request).unwrap();
    assert_eq!(moved.key().next_hop(), hop("192.0.2.2"));
    // The owner's exact-path policy and its restriction moved with the flow.
    let admin = f.service.path_administration(moved.path()).unwrap();
    assert_eq!(admin.policy.estimate, Some(1200));
    assert_eq!(moved.administrative_estimate(), Some(1200));
    assert_eq!(moved.pmtu_estimate(), Ok(1200));
    assert!(moved.retry_not_before() >= restricted.retry_not_before());
    // The superseded incarnation no longer holds it.
    assert!(
        f.service
            .path_administration(path)
            .unwrap()
            .policy
            .is_empty()
    );
    // Ending the override moves it back with the flow.
    f.service
        .end_redirects(f.link, address("192.0.2.2"), NeighborLoss::Unreachable)
        .unwrap();
    let (_, back) = f.service.rebind(client, f.request).unwrap();
    assert_eq!(back.key().next_hop(), hop("192.0.2.1"));
    assert_eq!(back.pmtu_estimate(), Ok(1200));
    // A route replacement is no forwarding transition: exact-path policy
    // does not move to the new route generation.
    let definition = f.service.route(f.default).unwrap();
    f.service.replace_route(f.default, definition).unwrap();
    let (_, replaced) = f.service.acquire(f.request).unwrap();
    assert!(
        f.service
            .path_administration(replaced.path())
            .unwrap()
            .policy
            .is_empty()
    );
}

// Every type of service whose first hop is a Redirect's sender moves with
// a Redirect for every type of service (IPv4 codes 0 and 1); a
// type-of-service Redirect (codes 2 and 3) moves only the quoted packet's
// DSCP. A seeded sequence of both forms, each from the current first hop
// of the quoted DSCP (the route's gateway or an override's target),
// against a model of every DSCP's first hop: DSCP 10 is never quoted and
// follows only the Redirects for every type of service. Each flow whose
// first hop changes has its client notified.
#[test]
fn redirect_sequences_follow_each_type_of_service_first_hop() {
    const DSCPS: [u8; 4] = [0, 24, 46, 10];
    const QUOTED: usize = 3;
    let targets = [
        "192.0.2.2",
        "192.0.2.3",
        "192.0.2.4",
        "192.0.2.1",
        "198.51.100.7",
    ];
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move |bound: usize| {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (seed >> 33) as usize % bound
    };
    for _ in 0..64 {
        let mut f = fixture(8);
        let requests = DSCPS.map(|dscp| PathRequest {
            dscp: Dscp::new(dscp).unwrap(),
            ..f.request
        });
        let mut model = [hop("192.0.2.1"); DSCPS.len()];
        let mut clients = requests.map(|request| {
            let (client, snapshot) = f.service.acquire(request).unwrap();
            f.service.acknowledge(client, snapshot.stamp()).unwrap();
            client
        });
        let mut trace = Vec::new();
        for _ in 0..12 {
            let quoted = next(QUOTED);
            let type_of_service = next(2) == 0;
            let target = address(targets[next(targets.len())]);
            let ResolvedNextHop::Address(sender) = model[quoted] else {
                unreachable!()
            };
            let key = f.service.resolve(requests[quoted]).unwrap().key();
            assert_eq!(key.next_hop(), model[quoted], "{trace:?}");
            trace.push((DSCPS[quoted], type_of_service, target));
            let result = f.service.redirect(key, sender, target, type_of_service);
            // The destination reached directly is never redirected, and a
            // Redirect to its own sender changes nothing.
            if sender == f.request.destination || target == sender {
                assert_eq!(result, Err(Error::InvalidArgument), "{trace:?}");
                continue;
            }
            assert_eq!(result, Ok(()), "{trace:?}");
            let before = model;
            for (i, first) in model.iter_mut().enumerate() {
                if (type_of_service && i == quoted)
                    || (!type_of_service && *first == ResolvedNextHop::Address(sender))
                {
                    *first = ResolvedNextHop::Address(target);
                }
            }
            for i in 0..DSCPS.len() {
                assert_eq!(
                    f.service.resolve(requests[i]).unwrap().key().next_hop(),
                    model[i],
                    "DSCP {} after {trace:?}",
                    DSCPS[i]
                );
                if model[i] != before[i] {
                    assert!(
                        f.service.is_dirty(clients[i]).unwrap(),
                        "DSCP {} not notified after {trace:?}",
                        DSCPS[i]
                    );
                }
                let (client, snapshot) = f.service.rebind(clients[i], requests[i]).unwrap();
                f.service.acknowledge(client, snapshot.stamp()).unwrap();
                clients[i] = client;
            }
        }
    }
}

// An override moved by a Redirect for every type of service is the moving
// Redirect's: it ends with its new sender or target, not with the router
// that sent the override it replaced, and each end notifies the flows it
// moves back. An override that ends and is installed again never names
// the earlier path incarnation.
#[test]
fn moved_overrides_end_with_their_new_sender_or_target() {
    let marked = |f: &Fixture| PathRequest {
        dscp: Dscp::new(24).unwrap(),
        ..f.request
    };
    let resolve = |f: &Fixture, request| f.service.resolve(request).unwrap().key().next_hop();
    for (lost, loss, ends) in [
        ("192.0.2.1", NeighborLoss::Unreachable, false),
        ("192.0.2.2", NeighborLoss::Unreachable, true),
        ("192.0.2.3", NeighborLoss::Unreachable, true),
        ("192.0.2.2", NeighborLoss::NotRouter, false),
        ("192.0.2.3", NeighborLoss::NotRouter, true),
    ] {
        let mut f = fixture(4);
        let key = f.service.resolve(marked(&f)).unwrap().key();
        f.service
            .redirect(key, address("192.0.2.1"), address("192.0.2.2"), true)
            .unwrap();
        let key = f.service.resolve(marked(&f)).unwrap().key();
        f.service
            .redirect(key, address("192.0.2.2"), address("192.0.2.3"), false)
            .unwrap();
        assert_eq!(resolve(&f, marked(&f)), hop("192.0.2.3"));
        assert_eq!(resolve(&f, f.request), hop("192.0.2.1"));
        let (client, snapshot) = f.service.acquire(marked(&f)).unwrap();
        f.service.acknowledge(client, snapshot.stamp()).unwrap();
        let ended = f
            .service
            .end_redirects(f.link, address(lost), loss)
            .unwrap();
        assert_eq!(ended, usize::from(ends), "{lost} {loss:?}");
        assert_eq!(f.service.is_dirty(client).unwrap(), ends, "{lost} {loss:?}");
        assert_eq!(
            resolve(&f, marked(&f)),
            hop(if ends { "192.0.2.1" } else { "192.0.2.3" }),
            "{lost} {loss:?}"
        );
        assert_eq!(resolve(&f, f.request), hop("192.0.2.1"));
    }

    let mut f = fixture(4);
    let key = f.service.resolve(f.request).unwrap().key();
    f.service
        .redirect(key, address("192.0.2.1"), address("192.0.2.2"), false)
        .unwrap();
    let first = f.service.resolve(f.request).unwrap().key();
    f.service
        .end_redirects(f.link, address("192.0.2.2"), NeighborLoss::Unreachable)
        .unwrap();
    let key = f.service.resolve(f.request).unwrap().key();
    f.service
        .redirect(key, address("192.0.2.1"), address("192.0.2.2"), false)
        .unwrap();
    let again = f.service.resolve(f.request).unwrap().key();
    assert_eq!(again.next_hop(), first.next_hop());
    assert_ne!(again, first);
    assert_eq!(
        f.service.validate_selection(first).map(|_| ()),
        Err(Error::SelectionChanged)
    );
}

// Link-local addresses are unique only on their link (RFC 4007): the
// target of an ICMPv6 Redirect must not be this host's own address on the
// key's link, but the same link-local address that this host owns on
// another link is another node here, and a valid target.
#[test]
fn redirect_target_ownership_is_scoped_to_the_link() {
    let mut service = PathService::new(
        ContextId::new(902),
        Limits {
            links: 2,
            sources: 3,
            source_owners: 3,
            routes: 1,
            paths: 4,
            clients: 4,
        },
        [1; 16],
    )
    .unwrap();
    let a = service.register_link(InterfaceKey(1), 1500).unwrap();
    let b = service.register_link(InterfaceKey(2), 1500).unwrap();
    let scoped =
        |value: &str, link| ScopedAddress::new(value.parse().unwrap(), Some(link)).unwrap();
    let source = service.register_source(address("2001:db8::10"), a).unwrap();
    service.register_source(scoped("fe80::20", a), a).unwrap();
    service.register_source(scoped("fe80::10", b), b).unwrap();
    service
        .add_route(Route {
            destination: IpPrefix::new("::".parse().unwrap(), 0).unwrap(),
            source: None,
            dscp: None,
            link: a,
            next_hop: NextHop::Gateway(scoped("fe80::1", a)),
            metric: 0,
        })
        .unwrap();
    let request = PathRequest {
        source,
        destination: address("2001:db8:1::7"),
        dscp: Dscp::new(0).unwrap(),
    };
    let key = service.resolve(request).unwrap().key();
    let router = scoped("fe80::1", a);
    // This host's own address on the key's link, and an address of
    // another link, are refused.
    for target in [scoped("fe80::20", a), scoped("fe80::10", b)] {
        assert_eq!(
            service.redirect(key, router, target, false),
            Err(Error::InvalidArgument),
            "{target:?}"
        );
    }
    // fe80::10 on link A is another node.
    assert_eq!(
        service.redirect(key, router, scoped("fe80::10", a), false),
        Ok(())
    );
    assert_eq!(
        service.resolve(request).unwrap().key().next_hop(),
        ResolvedNextHop::Address(scoped("fe80::10", a))
    );
}
