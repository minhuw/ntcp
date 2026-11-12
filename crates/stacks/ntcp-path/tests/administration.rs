use ntcp_path::*;

fn address(text: &str) -> ScopedAddress {
    ScopedAddress::new(text.parse().unwrap(), None).unwrap()
}
fn prefix(network: &str, length: u8) -> IpPrefix {
    IpPrefix::new(network.parse().unwrap(), length).unwrap()
}
fn route(link: LinkId, network: &str, length: u8, metric: u32) -> Route {
    Route {
        destination: prefix(network, length),
        source: None,
        dscp: None,
        link,
        next_hop: NextHop::OnLink,
        metric,
    }
}
struct Fixture {
    service: PathService,
    link: LinkId,
    route: RouteId,
    request: PathRequest,
    ipv6: bool,
}
fn setup(ipv6: bool, paths: usize) -> Fixture {
    setup_in(ContextId::new(7), ipv6, paths)
}
fn setup_in(context: ContextId, ipv6: bool, paths: usize) -> Fixture {
    let mut service = PathService::new(
        context,
        Limits {
            links: 2,
            sources: 2,
            source_owners: 2,
            routes: 4,
            paths,
            clients: 4,
        },
        [1; 16],
    )
    .unwrap();
    let link = service.register_link(InterfaceKey(1), 1500).unwrap();
    let source = service
        .register_source(address(if ipv6 { "2001:db8::1" } else { "192.0.2.1" }), link)
        .unwrap();
    let route = service
        .add_route(self::route(link, if ipv6 { "::" } else { "0.0.0.0" }, 0, 0))
        .unwrap();
    let request = PathRequest {
        source,
        destination: address(if ipv6 { "2001:db8:1::9" } else { "198.51.100.9" }),
        dscp: Dscp::new(0).unwrap(),
    };
    Fixture {
        service,
        link,
        route,
        request,
        ipv6,
    }
}
fn other(f: &Fixture, last: u8) -> PathRequest {
    PathRequest {
        destination: address(&if f.ipv6 {
            format!("2001:db8:2::{last}")
        } else {
            format!("203.0.113.{last}")
        }),
        ..f.request
    }
}
fn apply(service: &mut PathService, change: AdminChange) -> Result<u64, Error> {
    let plan = service.prepare_admin(change, 0, 600)?;
    service.commit_admin(plan)?;
    Ok(plan.generation())
}
fn disable(estimate: Option<u32>) -> AdminPolicy {
    AdminPolicy {
        discovery_disabled: true,
        estimate,
    }
}

#[test]
fn route_policy_compare_and_set_and_stored_only() {
    for ipv6 in [false, true] {
        let mut f = setup(ipv6, 2);
        let (client, before) = f.service.acquire(f.request).unwrap();
        f.service.acknowledge(client, before.stamp()).unwrap();
        let revision = f.service.revision();
        let target = AdminTarget::Route(f.route);
        // Wrong expected generation changes nothing.
        let stale = AdminChange {
            target,
            expected: 1,
            policy: disable(None),
        };
        assert_eq!(f.service.prepare_admin(stale, 0, 600), Err(Error::StaleGeneration));
        assert_eq!(f.service.admin_revision(), 0);
        let generation = apply(
            &mut f.service,
            AdminChange {
                target,
                expected: 0,
                policy: disable(Some(1500)),
            },
        )
        .unwrap();
        assert_eq!(generation, 1);
        // Equal to the accepted (first-hop) estimate: no estimate, hold or
        // negative revision change; the policy itself is delivered to the
        // path's clients in a new snapshot version.
        assert_eq!(f.service.revision(), revision + 1);
        assert_eq!(f.service.is_dirty(client), Ok(true));
        let delivered = f.service.snapshot(client).unwrap();
        assert_eq!(delivered.learned_mtu(), before.learned_mtu());
        assert_eq!(delivered.negative_revision(), before.negative_revision());
        assert_eq!(delivered.retry_not_before(), before.retry_not_before());
        // The disable caps every IPv6 packet at the minimum link MTU (RFC
        // 8201 section 5.6); the IPv4 budget is unchanged.
        let budget = before.ip_packet_budget().unwrap();
        assert_eq!(
            delivered.ip_packet_budget().unwrap(),
            if ipv6 { budget.min(1280) } else { budget }
        );
        assert_eq!(delivered.administrative_estimate(), Some(1500));
        assert!(delivered.discovery_disabled());
        assert_eq!(delivered.discovery_revision(), generation);
        assert_eq!(before.discovery_revision(), 0);
        let report = f.service.path_administration(before.path()).unwrap();
        assert_eq!(report.route_policy, Some(disable(Some(1500))));
        assert_eq!(
            report.effective,
            EffectivePolicy {
                discovery_disabled: Some(PolicySource::Route),
                estimate: Some(AdministrativeEstimate {
                    value: 1500,
                    source: PolicySource::Route
                }),
            }
        );
        assert_eq!(
            report.accepted,
            Some(AcceptedEstimate {
                value: 1500,
                provenance: EstimateProvenance::Unlearned
            })
        );
        // The previous generation is now stale; an identical set is a no-op.
        assert_eq!(
            f.service.prepare_admin(AdminChange {
                expected: 0,
                ..stale
            }, 0, 600),
            Err(Error::StaleGeneration)
        );
        let same = f
            .service
            .prepare_admin(AdminChange {
                target,
                expected: 1,
                policy: disable(Some(1500)),
            }, 0, 600)
            .unwrap();
        assert!(same.is_noop());
        f.service.commit_admin(same).unwrap();
        assert_eq!(f.service.admin_revision(), 1);
        // Family and first-hop bounds.
        let floor = if ipv6 { 1279 } else { 67 };
        for value in [floor, 1501] {
            assert_eq!(
                f.service.prepare_admin(AdminChange {
                    target,
                    expected: 1,
                    policy: disable(Some(value)),
                }, 0, 600),
                Err(Error::InvalidArgument)
            );
        }
        // A plan validated before an intervening change is stale.
        let plan = f
            .service
            .prepare_admin(AdminChange {
                target,
                expected: 1,
                policy: AdminPolicy::default(),
            }, 0, 600)
            .unwrap();
        f.service.set_link_mtu(f.link, 1400).unwrap();
        assert_eq!(f.service.commit_admin(plan), Err(Error::StaleGeneration));
        assert_eq!(
            f.service.route_administration(f.route).unwrap().policy,
            disable(Some(1500))
        );
        // Clearing is the empty policy.
        apply(
            &mut f.service,
            AdminChange {
                target,
                expected: 1,
                policy: AdminPolicy::default(),
            },
        )
        .unwrap();
        assert_eq!(
            f.service.path_administration(before.path()).map(|a| a.effective),
            Ok(EffectivePolicy::default())
        );
    }
}

#[test]
fn foreign_and_stale_targets_are_rejected() {
    let mut f = setup(false, 2);
    let mut foreign = setup_in(ContextId::new(9), false, 2);
    let (_, snapshot) = foreign.service.acquire(foreign.request).unwrap();
    for target in [
        AdminTarget::Route(foreign.route),
        AdminTarget::Path(snapshot.path()),
    ] {
        assert_eq!(
            f.service.prepare_admin(AdminChange {
                target,
                expected: 0,
                policy: disable(None),
            }, 0, 600),
            Err(Error::ForeignContext)
        );
    }
    let foreign_context = PathService::new(
        ContextId::new(8),
        Limits {
            links: 1,
            sources: 1,
            source_owners: 1,
            routes: 1,
            paths: 1,
            clients: 1,
        },
        [1; 16],
    )
    .unwrap();
    assert_eq!(
        foreign_context.prepare_admin(AdminChange {
            target: AdminTarget::Route(f.route),
            expected: 0,
            policy: disable(None),
        }, 0, 600),
        Err(Error::ForeignContext)
    );
    let replaced = f
        .service
        .replace_route(f.route, route(f.link, "0.0.0.0", 0, 0))
        .unwrap();
    assert_ne!(replaced, f.route);
    assert_eq!(
        f.service.prepare_admin(AdminChange {
            target: AdminTarget::Route(f.route),
            expected: 0,
            policy: disable(None),
        }, 0, 600),
        Err(Error::StaleHandle)
    );
    foreign.service.remove_route(foreign.route).unwrap();
    assert_eq!(
        foreign.service.prepare_admin(AdminChange {
            target: AdminTarget::Path(snapshot.path()),
            expected: 0,
            policy: disable(None),
        }, 0, 600),
        Err(Error::Invalidated)
    );
}

#[test]
fn route_disable_dominates_and_restrictions_intersect() {
    for ipv6 in [false, true] {
        let mut f = setup(ipv6, 2);
        let (_, snapshot) = f.service.acquire(f.request).unwrap();
        let path = snapshot.path();
        apply(
            &mut f.service,
            AdminChange {
                target: AdminTarget::Path(path),
                expected: 0,
                policy: AdminPolicy {
                    discovery_disabled: false,
                    estimate: Some(1300),
                },
            },
        )
        .unwrap();
        apply(
            &mut f.service,
            AdminChange {
                target: AdminTarget::Route(f.route),
                expected: 0,
                policy: disable(Some(1450)),
            },
        )
        .unwrap();
        let effective = f.service.path_administration(path).unwrap().effective;
        assert_eq!(effective.discovery_disabled, Some(PolicySource::Route));
        assert_eq!(
            effective.estimate,
            Some(AdministrativeEstimate {
                value: 1300,
                source: PolicySource::Path
            })
        );
        // Clearing the path overlay reveals the route policy.
        let generation = f.service.path_administration(path).unwrap().generation;
        apply(
            &mut f.service,
            AdminChange {
                target: AdminTarget::Path(path),
                expected: generation,
                policy: AdminPolicy::default(),
            },
        )
        .unwrap();
        let effective = f.service.path_administration(path).unwrap().effective;
        assert_eq!(effective.discovery_disabled, Some(PolicySource::Route));
        assert_eq!(effective.estimate.unwrap().value, 1450);
        assert_eq!(effective.estimate.unwrap().source, PolicySource::Route);
    }
}

#[test]
fn route_policy_survives_idle_eviction_without_promotion() {
    for ipv6 in [false, true] {
        // One path slot: the second destination evicts the idle first one.
        let mut f = setup(ipv6, 1);
        let (client, first) = f.service.acquire(f.request).unwrap();
        f.service
            .trusted_decrease_with_hold(first.path(), 1400, 77)
            .unwrap();
        // An upward administrative request above the accepted estimate.
        apply(
            &mut f.service,
            AdminChange {
                target: AdminTarget::Route(f.route),
                expected: 0,
                policy: AdminPolicy {
                    discovery_disabled: false,
                    estimate: Some(1500),
                },
            },
        )
        .unwrap();
        f.service.release(client).unwrap();
        let (client, _) = f.service.acquire(other(&f, 5)).unwrap();
        f.service.release(client).unwrap();
        assert_eq!(f.service.path_snapshot(first.path()), Err(Error::StaleHandle));
        let (_, again) = f.service.acquire(f.request).unwrap();
        assert_ne!(again.path(), first.path());
        // The deferred upward request is still only an administrative value.
        let report = f.service.path_administration(again.path()).unwrap();
        assert_eq!(report.effective.estimate.unwrap().value, 1500);
        assert_eq!(report.snapshot.learned_mtu(), None);
        assert_eq!(report.snapshot.retry_not_before(), 0);
        assert_eq!(report.accepted.unwrap().provenance, EstimateProvenance::Unlearned);
        assert_eq!(f.service.route_administration(f.route).unwrap().generation, 1);
    }
}

#[test]
fn exact_path_policy_pins_and_invalidation_releases_it() {
    for ipv6 in [false, true] {
        let mut f = setup(ipv6, 1);
        let (client, snapshot) = f.service.acquire(f.request).unwrap();
        let path = snapshot.path();
        apply(
            &mut f.service,
            AdminChange {
                target: AdminTarget::Path(path),
                expected: 0,
                policy: disable(None),
            },
        )
        .unwrap();
        f.service.release(client).unwrap();
        // The administrative pin keeps the idle incarnation out of eviction.
        assert!(!f.service.path_administration(path).unwrap().policy.is_empty());
        assert_eq!(f.service.acquire(other(&f, 6)), Err(Error::Capacity));
        // Reacquisition of the same key finds the same pinned incarnation.
        let (client, again) = f.service.acquire(f.request).unwrap();
        assert_eq!(again.path(), path);
        assert_eq!(
            f.service.path_administration(path).unwrap().effective.discovery_disabled,
            Some(PolicySource::Path)
        );
        f.service.release(client).unwrap();
        // A replacement route invalidates the path: pin and policy go with it,
        // and the policy does not migrate to the re-resolved incarnation.
        let new_route = f
            .service
            .replace_route(f.route, route(f.link, if ipv6 { "::" } else { "0.0.0.0" }, 0, 0))
            .unwrap();
        let report = f.service.path_administration(path).unwrap();
        assert!(report.policy.is_empty());
        assert_eq!(report.accepted, None);
        let (_, fresh) = f.service.acquire(other(&f, 7)).unwrap();
        assert_eq!(fresh.key().route(), new_route);
        assert_eq!(
            f.service.path_administration(fresh.path()).map(|a| a.effective),
            Ok(EffectivePolicy::default())
        );
    }
}

#[test]
fn source_link_and_dscp_isolation() {
    let mut f = setup(false, 4);
    let (_, a) = f.service.acquire(f.request).unwrap();
    let (_, b) = f
        .service
        .acquire(PathRequest {
            dscp: Dscp::new(10).unwrap(),
            ..f.request
        })
        .unwrap();
    assert_ne!(a.path(), b.path());
    apply(
        &mut f.service,
        AdminChange {
            target: AdminTarget::Path(a.path()),
            expected: 0,
            policy: disable(None),
        },
    )
    .unwrap();
    assert_eq!(f.service.path_administration(b.path()).map(|a| a.effective),
        Ok(EffectivePolicy::default()));
    // A DSCP-specific route administers only its own selections.
    let dscp_route = f
        .service
        .add_route(Route {
            dscp: Some(Dscp::new(20).unwrap()),
            ..route(f.link, "0.0.0.0", 0, 0)
        })
        .unwrap();
    apply(
        &mut f.service,
        AdminChange {
            target: AdminTarget::Route(dscp_route),
            expected: 0,
            policy: disable(None),
        },
    )
    .unwrap();
    let (_, c) = f
        .service
        .acquire(PathRequest {
            dscp: Dscp::new(20).unwrap(),
            ..f.request
        })
        .unwrap();
    assert_eq!(
        f.service.path_administration(c.path()).unwrap().effective.discovery_disabled,
        Some(PolicySource::Route)
    );
    assert_eq!(f.service.path_administration(b.path()).map(|a| a.effective),
        Ok(EffectivePolicy::default()));
}

#[test]
fn replacement_transfers_policy_only_explicitly() {
    for ipv6 in [false, true] {
        let mut f = setup(ipv6, 2);
        let default = if ipv6 { "::" } else { "0.0.0.0" };
        let policy = disable(Some(1400));
        apply(
            &mut f.service,
            AdminChange {
                target: AdminTarget::Route(f.route),
                expected: 0,
                policy,
            },
        )
        .unwrap();
        // Single replacement carries the policy with fresh authority.
        let replaced = f
            .service
            .replace_route(f.route, route(f.link, default, 0, 3))
            .unwrap();
        let admin = f.service.route_administration(replaced).unwrap();
        assert_eq!(admin.policy, policy);
        assert_eq!(admin.generation, 1);
        // Mapped bulk replacement carries it only along the mapping.
        let narrow = if ipv6 { "2001:db8:1::" } else { "198.51.100.0" };
        let routes = [route(f.link, narrow, if ipv6 { 48 } else { 24 }, 0), route(f.link, default, 0, 0)];
        f.service
            .replace_routes_mapped(&routes, &[(replaced, 1)])
            .unwrap();
        let listed: Vec<_> = f.service.route_administrations().collect();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].policy, AdminPolicy::default());
        assert_eq!(listed[1].policy, policy);
        assert_eq!(listed[1].definition, routes[1]);
        // Invalid mappings change nothing.
        let revision = f.service.revision();
        for carry in [
            [(listed[1].route, 2)],
            [(replaced, 0)],
        ] {
            assert!(f.service.replace_routes_mapped(&routes, &carry).is_err());
        }
        assert_eq!(
            f.service.replace_routes_mapped(
                &routes,
                &[(listed[1].route, 0), (listed[1].route, 1)]
            ),
            Err(Error::InvalidArgument)
        );
        assert_eq!(f.service.revision(), revision);
        assert_eq!(f.service.route_administrations().nth(1).unwrap().policy, policy);
        // Unmapped bulk replacement drops it.
        f.service.replace_routes(&routes).unwrap();
        assert!(f
            .service
            .route_administrations()
            .all(|r| r.policy == AdminPolicy::default() && r.generation == 0));
        // Removal followed by an unrelated addition inherits nothing.
        let id = f.service.route_administrations().nth(1).unwrap().route;
        let generation = apply(
            &mut f.service,
            AdminChange {
                target: AdminTarget::Route(id),
                expected: 0,
                policy,
            },
        )
        .unwrap();
        assert!(generation > 1);
        f.service.remove_route(id).unwrap();
        let added = f.service.add_route(route(f.link, default, 0, 9)).unwrap();
        assert_eq!(
            f.service.route_administration(added).unwrap().policy,
            AdminPolicy::default()
        );
    }
}

// The fixture route carrying a downward estimate that restricted a live
// path (so the record holds a policy, a hold until 700 and a restriction),
// plus a source of the other family for paths through a replacement of
// that family. Returns the other family's request.
fn administered_with_other_family(ipv6: bool, estimate: u32) -> (Fixture, AdminPolicy, PathRequest) {
    let mut f = setup(ipv6, 2);
    let (client, _) = f.service.acquire(f.request).unwrap();
    let policy = disable(Some(estimate));
    let plan = f
        .service
        .prepare_admin(
            AdminChange {
                target: AdminTarget::Route(f.route),
                expected: 0,
                policy,
            },
            100,
            600,
        )
        .unwrap();
    f.service.commit_admin(plan).unwrap();
    let restricted = f.service.snapshot(client).unwrap();
    assert_eq!((restricted.learned_mtu(), restricted.retry_not_before()), (Some(estimate), 700));
    f.service.release(client).unwrap();
    let source = f
        .service
        .register_source(address(if ipv6 { "192.0.2.1" } else { "2001:db8::1" }), f.link)
        .unwrap();
    let request = PathRequest {
        source,
        destination: address(if ipv6 { "198.51.100.9" } else { "2001:db8:1::9" }),
        dscp: Dscp::new(0).unwrap(),
    };
    (f, policy, request)
}

// A replacement that changes the destination family is an unrelated route
// for administration: the IPv4 value 576 (below the IPv6 minimum) or an
// IPv6 value never reaches a path of the other family, nor do the hold,
// the retained restriction or the discovery flag.
#[test]
fn family_changing_single_replacement_carries_nothing() {
    for ipv6 in [false, true] {
        let estimate = if ipv6 { 1300 } else { 576 };
        let (mut f, _, request) = administered_with_other_family(ipv6, estimate);
        let replaced = f
            .service
            .replace_route(f.route, route(f.link, if ipv6 { "0.0.0.0" } else { "::" }, 0, 0))
            .unwrap();
        let admin = f.service.route_administration(replaced).unwrap();
        assert_eq!((admin.policy, admin.generation), (AdminPolicy::default(), 0));
        let (_, path) = f.service.acquire(request).unwrap();
        assert_eq!(path.key().route(), replaced);
        assert_eq!(path.learned_mtu(), None);
        assert_eq!(path.administrative_estimate(), None);
        assert_eq!(path.administrative_restriction(), None);
        assert!(!path.discovery_disabled());
        assert_eq!(path.retry_not_before(), 0);
        assert_eq!(path.pmtu_estimate(), Ok(1500));
        assert_eq!(path.ip_packet_budget(), Ok(1500));
        assert_eq!(
            accepted(&f, path.path()),
            AcceptedEstimate {
                value: 1500,
                provenance: EstimateProvenance::Unlearned
            }
        );
    }
}

// An explicit mapping onto a route of the other family is invalid input,
// rejected before routes, generations, revision or policies change.
#[test]
fn family_changing_mapped_carry_is_rejected_with_nothing_changed() {
    for ipv6 in [false, true] {
        let (mut f, policy, _) = administered_with_other_family(ipv6, if ipv6 { 1300 } else { 576 });
        let routes = [route(f.link, if ipv6 { "0.0.0.0" } else { "::" }, 0, 0)];
        let revision = f.service.revision();
        let admin_revision = f.service.admin_revision();
        let before: Vec<_> = f.service.route_administrations().collect();
        assert_eq!(
            f.service.replace_routes_mapped(&routes, &[(f.route, 0)]),
            Err(Error::InvalidArgument)
        );
        assert_eq!(f.service.revision(), revision);
        assert_eq!(f.service.admin_revision(), admin_revision);
        assert_eq!(f.service.route_administrations().collect::<Vec<_>>(), before);
        assert_eq!(f.service.route_administration(f.route).unwrap().policy, policy);
        let (_, path) = f.service.acquire(f.request).unwrap();
        assert_eq!(path.key().route(), f.route);
        assert_eq!(path.pmtu_estimate(), Ok(if ipv6 { 1300 } else { 576 }));
        assert_eq!(path.retry_not_before(), 700);
        // Unmapped, the same replacement succeeds and drops the record.
        f.service.replace_routes(&routes).unwrap();
        assert!(f
            .service
            .route_administrations()
            .all(|r| r.policy == AdminPolicy::default() && r.generation == 0));
    }
}

// A same-family replacement onto a smaller link keeps the record, single
// and mapped: the carried value caps nothing above the new first hop, so a
// path through the replacement has budget min(first hop, value).
#[test]
fn same_family_replacement_onto_a_smaller_link_keeps_the_policy() {
    for ipv6 in [false, true] {
        for value in [1450, 1300] {
            let mut f = setup(ipv6, 2);
            let default = if ipv6 { "::" } else { "0.0.0.0" };
            let (client, _) = f.service.acquire(f.request).unwrap();
            let policy = AdminPolicy {
                discovery_disabled: false,
                estimate: Some(value),
            };
            let plan = f
                .service
                .prepare_admin(
                    AdminChange {
                        target: AdminTarget::Route(f.route),
                        expected: 0,
                        policy,
                    },
                    100,
                    600,
                )
                .unwrap();
            f.service.commit_admin(plan).unwrap();
            f.service.release(client).unwrap();
            let small = f.service.register_link(InterfaceKey(2), 1400).unwrap();
            let replaced = f
                .service
                .replace_route(f.route, route(small, default, 0, 0))
                .unwrap();
            assert_eq!(f.service.route_administration(replaced).unwrap().policy, policy);
            let (client, path) = f.service.acquire(f.request).unwrap();
            assert_eq!(path.first_hop_mtu(), 1400);
            assert_eq!(path.administrative_estimate(), Some(value));
            assert_eq!(path.ip_packet_budget(), Ok(1400.min(value)));
            assert_eq!(path.retry_not_before(), 700);
            f.service.release(client).unwrap();
            f.service
                .replace_routes_mapped(&[route(small, default, 0, 1)], &[(replaced, 0)])
                .unwrap();
            let mapped = f.service.route_administrations().next().unwrap();
            assert_eq!(mapped.policy, policy);
            let (_, path) = f.service.acquire(f.request).unwrap();
            assert_eq!(path.key().route(), mapped.route);
            assert_eq!(path.ip_packet_budget(), Ok(1400.min(value)));
        }
    }
}

#[test]
fn prefix_selector_requires_an_unambiguous_route() {
    let mut f = setup(false, 2);
    assert_eq!(f.service.select_route(prefix("0.0.0.0", 0)), Ok(f.route));
    assert_eq!(
        f.service.select_route(prefix("10.0.0.0", 8)),
        Err(Error::NoRoute)
    );
    f.service.add_route(route(f.link, "0.0.0.0", 0, 5)).unwrap();
    assert_eq!(
        f.service.select_route(prefix("0.0.0.0", 0)),
        Err(Error::Ambiguous)
    );
}

// A downward route estimate restricts every current path resolved through
// the route in one negative revision, dirtying each client; paths through
// another route are untouched. A path already below the value is unchanged.
#[test]
fn downward_route_restriction_reaches_every_current_path_of_the_route_only() {
    for ipv6 in [false, true] {
        let mut f = setup(ipv6, 4);
        let specific = f
            .service
            .add_route(route(f.link, if ipv6 { "2001:db8:2::" } else { "203.0.113.0" }, if ipv6 { 48 } else { 24 }, 0))
            .unwrap();
        let (one, a) = f.service.acquire(f.request).unwrap();
        let (two, b) = f.service.acquire(other(&f, 7)).unwrap();
        let (three, c) = f.service.acquire(PathRequest {
            destination: address(if ipv6 { "2001:db8:1::10" } else { "198.51.100.10" }),
            ..f.request
        })
        .unwrap();
        assert_eq!(b.key().route(), specific);
        for (client, snapshot) in [(one, a), (two, b), (three, c)] {
            f.service.acknowledge(client, snapshot.stamp()).unwrap();
        }
        let low = if ipv6 { 1300 } else { 1000 };
        // `c` already learned less than the restriction.
        f.service.trusted_decrease_with_hold(c.path(), low - 10, 5).unwrap();
        f.service.acknowledge(three, f.service.snapshot(three).unwrap().stamp()).unwrap();
        let change = AdminChange {
            target: AdminTarget::Route(f.route),
            expected: 0,
            policy: AdminPolicy {
                discovery_disabled: false,
                estimate: Some(low),
            },
        };
        // Hold arithmetic is checked before anything changes.
        assert_eq!(f.service.prepare_admin(change, u64::MAX, 1), Err(Error::Exhausted));
        let plan = f.service.prepare_admin(change, 100, 600).unwrap();
        let revision = f.service.revision();
        f.service.commit_admin(plan).unwrap();
        assert_eq!(f.service.revision(), revision + 1);
        let a2 = f.service.path_snapshot(a.path()).unwrap();
        assert_eq!(a2.learned_mtu(), Some(low));
        assert_eq!(a2.negative_revision(), revision + 1);
        assert_eq!(a2.retry_not_before(), 700);
        assert_eq!(f.service.is_dirty(one), Ok(true));
        // Other route: untouched.
        assert_eq!(f.service.path_snapshot(b.path()).unwrap(), b);
        assert_eq!(f.service.is_dirty(two), Ok(false));
        // Already below: estimate unchanged, no new hold; only the
        // administrative value is delivered.
        let c2 = f.service.path_snapshot(c.path()).unwrap();
        assert_eq!(c2.learned_mtu(), Some(low - 10));
        assert_eq!(c2.retry_not_before(), 5);
        assert_eq!(c2.negative_revision(), f.service.snapshot(three).unwrap().negative_revision());
        assert!(c2.negative_revision() < revision + 1);
        assert_eq!(c2.administrative_estimate(), Some(low));
        assert_eq!(f.service.is_dirty(three), Ok(true));
    }
}

// Prepare and commit one estimate change of the fixture route at caller
// time `now` (600-second hold), returning whether it restricted some path
// (a restriction advances the path's negative revision).
fn set_estimate(f: &mut Fixture, estimate: Option<u32>, now: u64) -> bool {
    let target = AdminTarget::Route(f.route);
    let expected = f.service.route_administration(f.route).unwrap().generation;
    let negative = |f: &Fixture| {
        f.service
            .path_administrations()
            .map(|p| (p.snapshot.path(), p.snapshot.negative_revision()))
            .collect::<Vec<_>>()
    };
    let before = negative(f);
    let plan = f
        .service
        .prepare_admin(
            AdminChange {
                target,
                expected,
                policy: AdminPolicy {
                    discovery_disabled: false,
                    estimate,
                },
            },
            now,
            600,
        )
        .unwrap();
    f.service.commit_admin(plan).unwrap();
    negative(f) != before
}

// Release `client`, evict the idle path through another destination of the
// route and reacquire the original destination.
fn evict_and_reacquire(f: &mut Fixture, client: ClientId, evicted: PathId) -> (ClientId, PathSnapshot) {
    f.service.release(client).unwrap();
    let (other_client, _) = f.service.acquire(other(f, 5)).unwrap();
    assert_eq!(f.service.path_snapshot(evicted), Err(Error::StaleHandle));
    f.service.release(other_client).unwrap();
    f.service.acquire(f.request).unwrap()
}

fn accepted(f: &Fixture, path: PathId) -> AcceptedEstimate {
    f.service.path_administration(path).unwrap().accepted.unwrap()
}

// A downward route estimate and the hold it created stay with the route
// record across idle eviction. A path installed through the route later
// (after eviction, or for another destination) starts from its unlearned
// first-hop estimate, capped by the administrative value as a restriction
// with administrative provenance, and retry_not_before at least the
// outstanding hold. Clearing keeps both the restriction and the applied
// hold; only confirmed delivery on the incarnation relaxes the restriction.
#[test]
fn downward_route_restriction_and_hold_survive_eviction_as_a_cap() {
    for ipv6 in [false, true] {
        let mut f = setup(ipv6, 1);
        let low = if ipv6 { 1300 } else { 1000 };
        let (client, first) = f.service.acquire(f.request).unwrap();
        assert!(set_estimate(&mut f, Some(low), 100));
        // The live path: its accepted estimate fell (learned restriction).
        let live = f.service.path_snapshot(first.path()).unwrap();
        assert_eq!((live.learned_mtu(), live.retry_not_before()), (Some(low), 700));
        f.service.release(client).unwrap();
        // Another destination of the route evicts the idle path.
        let (mut client, _) = f.service.acquire(other(&f, 5)).unwrap();
        assert_eq!(f.service.path_snapshot(first.path()), Err(Error::StaleHandle));
        for round in 0..2 {
            if round == 1 {
                // Reacquisition of the evicted destination.
                f.service.release(client).unwrap();
                client = f.service.acquire(f.request).unwrap().0;
            }
            let snapshot = f.service.snapshot(client).unwrap();
            assert_eq!(snapshot.learned_mtu(), None);
            assert_eq!(snapshot.negative_revision(), 0);
            assert_eq!(snapshot.administrative_restriction(), Some(low));
            assert_eq!(snapshot.administrative_estimate(), Some(low));
            assert_eq!(snapshot.ip_packet_budget(), Ok(low));
            assert_eq!(snapshot.retry_not_before(), 700);
            assert_eq!(
                accepted(&f, snapshot.path()),
                AcceptedEstimate {
                    value: low,
                    provenance: EstimateProvenance::Administrative
                }
            );
        }
        let again = f.service.path_administrations().next().unwrap().snapshot;
        // Inside the hold nothing grows; after it, the cap still bounds
        // delivery evidence and the cap itself is never learned proof.
        let confirm = |f: &mut Fixture, len, selected, now| {
            f.service.confirm_delivery(again.path(), len, 0, selected, now)
        };
        assert_eq!(confirm(&mut f, low, 699, 700), Ok(DeliveryConfirmation::Held));
        assert_eq!(confirm(&mut f, low, 700, 699), Ok(DeliveryConfirmation::Held));
        assert_eq!(confirm(&mut f, low + 1, 700, 700), Ok(DeliveryConfirmation::ExceedsAdministrative));
        assert_eq!(confirm(&mut f, low, 700, 700), Ok(DeliveryConfirmation::NotLarger));
        assert_eq!(f.service.path_snapshot(again.path()).unwrap().learned_mtu(), None);
        // Clearing removes the administrative value (delivered to clients)
        // but keeps the restriction it imposed and the applied hold: the
        // accepted estimate does not return to the first hop.
        assert!(!set_estimate(&mut f, None, 200));
        let cleared = f.service.path_snapshot(again.path()).unwrap();
        assert_eq!(cleared.administrative_restriction(), Some(low));
        assert_eq!(cleared.administrative_estimate(), None);
        assert_eq!(cleared.ip_packet_budget(), Ok(low));
        assert_eq!(cleared.learned_mtu(), None);
        assert_eq!(cleared.retry_not_before(), 700);
        assert_eq!(cleared.negative_revision(), again.negative_revision());
        assert!(cleared.version() > again.version());
        assert_eq!(accepted(&f, again.path()).provenance, EstimateProvenance::Administrative);
        // Post-hold confirmed delivery above the restriction relaxes it on
        // this incarnation: the proven length becomes the learned ceiling.
        let proven = low + 100;
        assert_eq!(confirm(&mut f, proven, 699, 700), Ok(DeliveryConfirmation::Held));
        assert_eq!(confirm(&mut f, proven, 700, 700), Ok(DeliveryConfirmation::Raised));
        let grown = f.service.path_snapshot(again.path()).unwrap();
        assert_eq!(grown.administrative_restriction(), None);
        assert_eq!((grown.learned_mtu(), grown.ip_packet_budget()), (Some(proven), Ok(proven)));
        assert_eq!(accepted(&f, again.path()).provenance, EstimateProvenance::Learned);
    }
}

// The review scenario of a deferred upward request: a downward route set
// on a live path (learned low, hold until 700), then an upward route set
// (deferred: the live path keeps low), then idle eviction and
// reacquisition. The new incarnation's accepted estimate is still low,
// with the outstanding hold; the upward value is only the cached
// administrative estimate.
#[test]
fn downward_then_upward_then_eviction_keeps_the_accepted_estimate() {
    for ipv6 in [false, true] {
        let (low, high) = if ipv6 { (1300, 1450) } else { (1000, 1400) };
        let mut f = setup(ipv6, 1);
        let (client, live) = f.service.acquire(f.request).unwrap();
        assert!(set_estimate(&mut f, Some(low), 100));
        assert!(!set_estimate(&mut f, Some(high), 150));
        let deferred = f.service.path_snapshot(live.path()).unwrap();
        assert_eq!(deferred.ip_packet_budget(), Ok(low));
        assert_eq!(deferred.retry_not_before(), 700);
        let (_, again) = evict_and_reacquire(&mut f, client, live.path());
        assert_eq!(again.learned_mtu(), None);
        assert_eq!(again.administrative_estimate(), Some(high));
        assert_eq!(again.administrative_restriction(), Some(low));
        assert_eq!(again.ip_packet_budget(), Ok(low));
        assert_eq!(again.retry_not_before(), 700);
        assert_eq!(
            accepted(&f, again.path()),
            AcceptedEstimate {
                value: low,
                provenance: EstimateProvenance::Administrative
            }
        );
        // Inside the hold no delivery raises it.
        assert_eq!(
            f.service.confirm_delivery(again.path(), high, 0, 600, 650),
            Ok(DeliveryConfirmation::Held)
        );
        assert_eq!(f.service.path_snapshot(again.path()).unwrap().ip_packet_budget(), Ok(low));
    }
}

// Downward route set on a live path, idle eviction, upward set,
// reacquisition: the route's retained restriction and hold still apply, for
// the evicted destination and for a new one, so the deferred upward value
// is never promoted. An explicit single replacement carries that admission
// state to the fresh route generation. Clearing the value withdraws the
// restriction for later paths and keeps the hold; an unmapped bulk
// replacement drops the hold with the policy.
#[test]
fn downward_then_eviction_keeps_the_restriction_until_cleared() {
    for ipv6 in [false, true] {
        let (low, high) = if ipv6 { (1300, 1450) } else { (1000, 1400) };
        let default = if ipv6 { "::" } else { "0.0.0.0" };
        let mut f = setup(ipv6, 1);
        let (client, live) = f.service.acquire(f.request).unwrap();
        assert!(set_estimate(&mut f, Some(low), 100));
        f.service.release(client).unwrap();
        let (other_client, _) = f.service.acquire(other(&f, 5)).unwrap();
        assert_eq!(f.service.path_snapshot(live.path()), Err(Error::StaleHandle));
        f.service.release(other_client).unwrap();
        assert!(!set_estimate(&mut f, Some(high), 200));
        for request in [f.request, other(&f, 9)] {
            let (client, again) = f.service.acquire(request).unwrap();
            assert_eq!(again.administrative_estimate(), Some(high));
            assert_eq!(again.administrative_restriction(), Some(low));
            assert_eq!(again.ip_packet_budget(), Ok(low));
            assert_eq!(again.learned_mtu(), None);
            assert_eq!(again.retry_not_before(), 700);
            assert_eq!(accepted(&f, again.path()).provenance, EstimateProvenance::Administrative);
            f.service.release(client).unwrap();
        }
        f.route = f
            .service
            .replace_route(f.route, route(f.link, default, 0, 3))
            .unwrap();
        let (client, carried) = f.service.acquire(f.request).unwrap();
        assert_eq!(carried.ip_packet_budget(), Ok(low));
        assert_eq!(carried.retry_not_before(), 700);
        f.service.release(client).unwrap();
        assert!(!set_estimate(&mut f, None, 300));
        let (client, cleared) = f.service.acquire(other(&f, 9)).unwrap();
        assert_eq!(cleared.administrative_restriction(), None);
        assert_eq!(cleared.ip_packet_budget(), Ok(1500));
        assert_eq!(cleared.retry_not_before(), 700);
        f.service.release(client).unwrap();
        f.service
            .replace_routes(&[route(f.link, default, 0, 0)])
            .unwrap();
        let (_, dropped) = f.service.acquire(f.request).unwrap();
        assert_eq!(dropped.administrative_restriction(), None);
        assert_eq!(dropped.ip_packet_budget(), Ok(1500));
        assert_eq!(dropped.retry_not_before(), 0);
    }
}

// A path installed under a route's retained downward restriction, then an
// upward route set: the incarnation keeps its restriction (no growth, hold,
// negative revision or learned change, administrative provenance), and
// post-hold confirmed delivery at the new value raises it, exactly as for
// a path that was live during the downward set.
#[test]
fn upward_route_set_after_reacquisition_grows_only_through_confirmed_delivery() {
    for ipv6 in [false, true] {
        let (low, high) = if ipv6 { (1300, 1450) } else { (1000, 1400) };
        let mut f = setup(ipv6, 1);
        let (client, live) = f.service.acquire(f.request).unwrap();
        assert!(set_estimate(&mut f, Some(low), 100));
        let (client, installed) = evict_and_reacquire(&mut f, client, live.path());
        assert_eq!(installed.administrative_restriction(), Some(low));
        assert_eq!(installed.learned_mtu(), None);

        assert!(!set_estimate(&mut f, Some(high), 200), "upward: no restriction");
        let raised = f.service.snapshot(client).unwrap();
        assert_eq!(raised.administrative_estimate(), Some(high));
        assert_eq!(raised.administrative_restriction(), Some(low));
        assert_eq!(raised.learned_mtu(), None);
        assert_eq!(raised.ip_packet_budget(), Ok(low), "an upward set grows nothing");
        assert_eq!(raised.retry_not_before(), 700);
        assert_eq!(raised.negative_revision(), installed.negative_revision());
        assert_eq!(
            accepted(&f, raised.path()),
            AcceptedEstimate {
                value: low,
                provenance: EstimateProvenance::Administrative
            }
        );
        let path = raised.path();
        let negative = raised.negative_revision();
        let mut confirm = |len, selected, now| {
            f.service
                .confirm_delivery(path, len, negative, selected, now)
        };
        assert_eq!(confirm(high, 699, 700), Ok(DeliveryConfirmation::Held));
        assert_eq!(confirm(high + 1, 700, 700), Ok(DeliveryConfirmation::ExceedsAdministrative));
        assert_eq!(confirm(low, 700, 700), Ok(DeliveryConfirmation::NotLarger));
        assert_eq!(confirm(high, 700, 700), Ok(DeliveryConfirmation::Raised));
        let grown = f.service.snapshot(client).unwrap();
        assert_eq!((grown.learned_mtu(), grown.ip_packet_budget()), (Some(high), Ok(high)));
        assert_eq!(grown.administrative_restriction(), None);
        assert_eq!(accepted(&f, path).provenance, EstimateProvenance::Learned);
    }
}

// A route value that restricted no live path when set (the live path had
// learned less by PTB) imposes nothing on the route: the learned value
// does not survive eviction (existing semantics), and the reacquired path
// starts from its first hop capped by the value in force, with no hold.
// That cap is a restriction of this incarnation, kept on it through a
// clear (no older larger value is restored on a live path); clearing the
// route's value withdraws it for paths installed afterwards, which start
// from their fresh unlearned estimate.
#[test]
fn upward_route_value_only_caps_a_reacquired_path() {
    for ipv6 in [false, true] {
        let mut f = setup(ipv6, 1);
        let (client, first) = f.service.acquire(f.request).unwrap();
        f.service
            .trusted_decrease_with_hold(first.path(), 1400, 77)
            .unwrap();
        assert!(!set_estimate(&mut f, Some(1450), 100));
        let live = f.service.path_snapshot(first.path()).unwrap();
        assert_eq!((live.learned_mtu(), live.retry_not_before()), (Some(1400), 77));
        let (client, again) = evict_and_reacquire(&mut f, client, first.path());
        assert_eq!(again.learned_mtu(), None);
        assert_eq!(again.retry_not_before(), 0);
        assert_eq!(again.administrative_restriction(), Some(1450));
        assert_eq!(again.ip_packet_budget(), Ok(1450));
        assert_eq!(accepted(&f, again.path()).provenance, EstimateProvenance::Administrative);
        assert_eq!(
            f.service.confirm_delivery(again.path(), 1450, 0, 0, 0),
            Ok(DeliveryConfirmation::NotLarger)
        );
        assert!(!set_estimate(&mut f, None, 200));
        let kept = f.service.path_snapshot(again.path()).unwrap();
        assert_eq!(kept.ip_packet_budget(), Ok(1450));
        assert_eq!(kept.administrative_restriction(), Some(1450));
        let (_, later) = evict_and_reacquire(&mut f, client, again.path());
        assert_eq!(later.administrative_restriction(), None);
        assert_eq!(later.ip_packet_budget(), Ok(1500));
        assert_eq!(accepted(&f, later.path()).provenance, EstimateProvenance::Unlearned);
        assert_eq!(later.retry_not_before(), 0);
    }
}

// After a clear, a path installed through the route for a new destination
// is no longer capped by the withdrawn value (fresh unlearned estimate) but
// starts no earlier than the outstanding administrative hold; the live
// path the downward set restricted keeps its lowered accepted estimate.
#[test]
fn cleared_route_keeps_its_hold_but_not_its_restriction_for_new_paths() {
    for ipv6 in [false, true] {
        let mut f = setup(ipv6, 1);
        let low = if ipv6 { 1300 } else { 1000 };
        let (client, live) = f.service.acquire(f.request).unwrap();
        assert!(set_estimate(&mut f, Some(low), 100));
        assert!(!set_estimate(&mut f, None, 100));
        let kept = f.service.path_snapshot(live.path()).unwrap();
        assert_eq!(kept.ip_packet_budget(), Ok(low));
        f.service.release(client).unwrap();
        let (_, fresh) = f.service.acquire(other(&f, 9)).unwrap();
        assert_eq!(fresh.administrative_restriction(), None);
        assert_eq!(fresh.ip_packet_budget(), Ok(1500));
        assert_eq!(accepted(&f, fresh.path()).provenance, EstimateProvenance::Unlearned);
        assert_eq!(fresh.retry_not_before(), 700);
    }
}

// RFC 1191 section 6.6 with the RFC 1122 section 3.3.3 sending limit: a
// discovery-disabled IPv4 route leaves DF clear and sends at the owner's
// administrative value when one is set (never above the accepted estimate),
// otherwise at most 576 octets through a gateway or forwarder and the
// accepted estimate (bounded by the link MTU) on-link. IPv6 is capped at
// the minimum link MTU whatever the next hop (RFC 8201 section 5.6), and
// re-enabling restores the accepted estimate without growing it.
#[test]
fn disabled_ipv4_route_sending_limit_follows_the_next_hop_and_owner_value() {
    for ipv6 in [false, true] {
        for (name, hop) in [
            ("on-link", NextHop::OnLink),
            (
                "gateway",
                NextHop::Gateway(address(if ipv6 { "2001:db8::fe" } else { "192.0.2.254" })),
            ),
            ("forwarder", NextHop::Forwarder(ForwarderId(3))),
        ] {
            let mut f = setup(ipv6, 2);
            let on_link = matches!(hop, NextHop::OnLink);
            let route = f
                .service
                .add_route(Route {
                    next_hop: hop,
                    ..self::route(
                        f.link,
                        if ipv6 { "2001:db8:2::" } else { "203.0.113.0" },
                        if ipv6 { 48 } else { 24 },
                        0,
                    )
                })
                .unwrap();
            let (_, before) = f.service.acquire(other(&f, 9)).unwrap();
            let path = before.path();
            assert_eq!(before.key().route(), route);
            assert_eq!(before.ip_packet_budget(), Ok(1500));
            assert!(!before.clears_dont_fragment());
            let set = |f: &mut Fixture, policy: AdminPolicy| {
                let expected = f.service.route_administration(route).unwrap().generation;
                apply(
                    &mut f.service,
                    AdminChange {
                        target: AdminTarget::Route(route),
                        expected,
                        policy,
                    },
                )
                .unwrap();
                f.service.path_snapshot(path).unwrap()
            };
            let off_link = |budget: u32| {
                if ipv6 {
                    budget.min(1280)
                } else if on_link {
                    budget
                } else {
                    budget.min(576)
                }
            };
            // No owner value: 576 off-link, the link MTU on-link.
            let disabled = set(&mut f, disable(None));
            assert_eq!(disabled.clears_dont_fragment(), !ipv6, "{name}");
            assert_eq!(
                disabled.ip_packet_budget(),
                Ok(off_link(1500)),
                "{name} v6={ipv6}"
            );
            // The sending limit is not RFC 1191 section 5's current PMTU
            // estimate, which stays the network value.
            assert_eq!(disabled.pmtu_estimate(), Ok(1500), "{name} v6={ipv6}");
            // A smaller learned estimate bounds every case.
            f.service.trusted_decrease_with_hold(path, 1400, 0).unwrap();
            let learned = f.service.path_snapshot(path).unwrap();
            assert_eq!(
                learned.ip_packet_budget(),
                Ok(off_link(1400)),
                "{name} v6={ipv6}"
            );
            assert_eq!(learned.pmtu_estimate(), Ok(1400), "{name} v6={ipv6}");
            // An owner value above the accepted estimate is not used beyond
            // it; one below is actual knowledge, above 576 off-link too.
            let above = set(&mut f, disable(Some(1450)));
            assert_eq!(
                above.ip_packet_budget(),
                Ok(if ipv6 { 1280 } else { 1400 }),
                "{name}"
            );
            let value = if ipv6 { 1300 } else { 800 };
            let below = set(&mut f, disable(Some(value)));
            assert_eq!(
                below.ip_packet_budget(),
                Ok(value.min(if ipv6 { 1280 } else { value })),
                "{name}"
            );
            assert_eq!(below.clears_dont_fragment(), !ipv6);
            // Re-enabling restores the accepted estimate (the owner's
            // restriction stays until cleared), never a larger one.
            let enabled = set(
                &mut f,
                AdminPolicy {
                    discovery_disabled: false,
                    estimate: None,
                },
            );
            assert!(!enabled.clears_dont_fragment());
            assert_eq!(enabled.ip_packet_budget(), Ok(value), "{name}");
        }
    }
}
