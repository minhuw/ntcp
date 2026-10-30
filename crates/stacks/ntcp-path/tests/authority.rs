use ntcp_path::*;

fn address(text: &str) -> ScopedAddress {
    ScopedAddress::new(text.parse().unwrap(), None).unwrap()
}
fn prefix(text: &str, length: u8) -> IpPrefix {
    IpPrefix::new(text.parse().unwrap(), length).unwrap()
}
fn service(context: u128) -> PathService {
    PathService::new(
        ContextId::new(context),
        Limits {
            links: 4,
            sources: 6,
            source_owners: 8,
            routes: 12,
            paths: 8,
            clients: 12,
        },
    )
    .unwrap()
}
fn route(link: LinkId, destination: &str, length: u8) -> Route {
    Route {
        destination: prefix(destination, length),
        source: None,
        dscp: None,
        link,
        next_hop: NextHop::OnLink,
        metric: 100,
    }
}
fn request(source: SourceId, destination: &str) -> PathRequest {
    PathRequest {
        source,
        destination: address(destination),
        dscp: Dscp::new(0).unwrap(),
    }
}

#[test]
fn default_network_host_routes_and_new_shadowing_authority() {
    let mut service = service(1);
    let a = service.register_link(InterfaceKey(4), 9001).unwrap();
    let b = service.register_link(InterfaceKey(9), 1500).unwrap();
    let source = service.register_source(address("192.0.2.1"), a).unwrap();
    let mut default = route(a, "0.0.0.0", 0);
    default.next_hop = NextHop::Gateway(address("192.0.2.254"));
    let default_id = service.add_route(default).unwrap();
    let req = request(source, "198.51.100.20");
    let old = service.resolve(req).unwrap();
    assert_eq!(old.key().route(), default_id);
    assert_eq!(old.key().next_hop(), address("192.0.2.254"));
    assert_eq!(old.first_hop_mtu(), 9001);
    let network_id = service.add_route(route(b, "198.51.100.0", 24)).unwrap();
    assert_eq!(service.route(default_id), Ok(default)); // Still live but shadowed.
    assert_eq!(
        service.validate_selection(old.key()),
        Err(Error::SelectionChanged)
    );
    let network = service.resolve(req).unwrap();
    assert_eq!(network.key().route(), network_id);
    assert_eq!(network.key().next_hop(), req.destination);
    assert_eq!(network.first_hop_mtu(), 1500);
    // Global source ownership on a does not accidentally restrict egress to a.
    assert_eq!(network.key().link(), b);
    let host_id = service.add_route(route(a, "198.51.100.20", 32)).unwrap();
    assert_eq!(
        service.validate_selection(network.key()),
        Err(Error::SelectionChanged)
    );
    assert_eq!(service.resolve(req).unwrap().key().route(), host_id);
    service.remove_route(host_id).unwrap();
    assert_eq!(service.resolve(req).unwrap().key(), network.key());
    service.remove_route(network_id).unwrap();
    assert_eq!(service.resolve(req).unwrap().key(), old.key());
}

#[test]
fn selectors_metric_and_duplicate_ties_do_not_depend_on_allocation_order() {
    for reverse in [false, true] {
        let mut service = service(2);
        let a = service.register_link(InterfaceKey(1), 1500).unwrap();
        let b = service.register_link(InterfaceKey(2), 1492).unwrap();
        let source = service.register_source(address("192.0.2.1"), a).unwrap();
        let other = service.register_source(address("203.0.113.1"), a).unwrap();
        let broad = route(a, "0.0.0.0", 0);
        let cheaper = Route {
            link: b,
            metric: 50,
            ..broad
        };
        for r in if reverse {
            [cheaper, broad]
        } else {
            [broad, cheaper]
        } {
            service.add_route(r).unwrap();
        }
        let req = request(source, "198.51.100.1");
        let initial = service.resolve(req).unwrap();
        assert_eq!(initial.key().link(), b);
        let revision = service.revision();
        assert_eq!(
            service.add_route(Route { link: a, ..cheaper }),
            Err(Error::Duplicate)
        );
        assert_eq!(service.revision(), revision);
        let source_route = Route {
            source: Some(prefix("192.0.2.0", 24)),
            metric: 999,
            ..broad
        };
        let source_id = service.add_route(source_route).unwrap();
        assert_eq!(service.resolve(req).unwrap().key().route(), source_id);
        assert_eq!(
            service
                .resolve(request(other, "198.51.100.1"))
                .unwrap()
                .key()
                .link(),
            b
        );
        let dscp = Dscp::new(46).unwrap();
        let special = service
            .add_route(Route {
                dscp: Some(dscp),
                link: b,
                ..source_route
            })
            .unwrap();
        assert_eq!(
            service
                .resolve(PathRequest { dscp, ..req })
                .unwrap()
                .key()
                .route(),
            special
        );
        assert_eq!(service.resolve(req).unwrap().key().route(), source_id);
        // Destination prefix wins over source, DSCP and metric specificity.
        let network = service.add_route(route(a, "198.51.100.0", 24)).unwrap();
        assert_eq!(
            service
                .resolve(PathRequest { dscp, ..req })
                .unwrap()
                .key()
                .route(),
            network
        );
        assert_eq!(
            service.validate_selection(initial.key()),
            Err(Error::SelectionChanged)
        );
    }
}

#[test]
fn adding_and_replacing_lower_metric_reconsiders_still_live_routes() {
    let mut service = service(3);
    let a = service.register_link(InterfaceKey(1), 1500).unwrap();
    let b = service.register_link(InterfaceKey(2), 1460).unwrap();
    let source = service.register_source(address("192.0.2.1"), a).unwrap();
    let original = service.add_route(route(a, "0.0.0.0", 0)).unwrap();
    let req = request(source, "203.0.113.99");
    let old = service.resolve(req).unwrap().key();
    let alternative = service
        .add_route(Route {
            metric: 200,
            ..route(b, "0.0.0.0", 0)
        })
        .unwrap();
    assert_eq!(service.validate_selection(old).unwrap().key(), old);
    let new = service
        .replace_route(
            alternative,
            Route {
                metric: 10,
                ..route(b, "0.0.0.0", 0)
            },
        )
        .unwrap();
    assert!(service.route(original).is_ok());
    assert_eq!(
        service.validate_selection(old),
        Err(Error::SelectionChanged)
    );
    assert_eq!(service.resolve(req).unwrap().key().route(), new);
    assert_eq!(service.route(alternative), Err(Error::StaleHandle));
}

#[test]
fn source_identity_is_shared_across_owners_and_revoked_only_at_last_owner() {
    let mut service = service(4);
    let a = service.register_link(InterfaceKey(1), 1500).unwrap();
    let b = service.register_link(InterfaceKey(2), 9001).unwrap();
    let source = service.register_source(address("192.0.2.1"), a).unwrap();
    assert_eq!(service.register_source(address("192.0.2.1"), b), Ok(source));
    let revision = service.revision();
    assert_eq!(service.register_source(address("192.0.2.1"), a), Ok(source));
    assert_eq!(service.revision(), revision);
    assert_eq!(service.usage().sources, 1);
    assert_eq!(service.usage().source_owners, 2);
    service.add_route(route(b, "0.0.0.0", 0)).unwrap();
    let key = service
        .resolve(request(source, "198.51.100.1"))
        .unwrap()
        .key();
    service.remove_link(a).unwrap();
    assert_eq!(service.validate_selection(key).unwrap().key(), key);
    assert_eq!(service.usage().source_owners, 1);
    service.remove_source_owner(source, b).unwrap();
    assert_eq!(service.validate_selection(key), Err(Error::StaleHandle));
    let replacement = service.register_source(address("192.0.2.1"), b).unwrap();
    assert_ne!(source, replacement);
    assert_eq!(service.source_address(source), Err(Error::StaleHandle));
    assert_eq!(service.usage().sources, 1);
}

#[test]
fn removing_one_claim_preserves_global_authority_and_unrelated_source() {
    let mut service = service(5);
    let a = service.register_link(InterfaceKey(1), 1500).unwrap();
    let b = service.register_link(InterfaceKey(2), 1500).unwrap();
    let source = service.register_source(address("2001:db8::1"), a).unwrap();
    assert_eq!(
        service.register_source(address("2001:db8::1"), b),
        Ok(source)
    );
    let unrelated = service.register_source(address("2001:db8::2"), a).unwrap();
    service.add_route(route(b, "::", 0)).unwrap();
    let key = service
        .resolve(request(source, "2001:db8:1::99"))
        .unwrap()
        .key();
    let other = service
        .resolve(request(unrelated, "2001:db8:1::99"))
        .unwrap()
        .key();
    service.remove_source_owner(source, b).unwrap();
    assert_eq!(service.validate_selection(key).unwrap().key(), key);
    service.remove_source_owner(source, a).unwrap();
    assert_eq!(service.validate_selection(key), Err(Error::StaleHandle));
    assert_eq!(service.validate_selection(other).unwrap().key(), other);
    assert_eq!(
        service.remove_source_owner(unrelated, b),
        Err(Error::SourceNotOwned)
    );
}

#[test]
fn scoped_ipv6_same_octets_are_distinct_and_never_infer_a_zone() {
    let mut service = service(6);
    let a = service.register_link(InterfaceKey(1), 1500).unwrap();
    let b = service.register_link(InterfaceKey(2), 1280).unwrap();
    let scoped = |text: &str, link| ScopedAddress::new(text.parse().unwrap(), Some(link)).unwrap();
    let source_a = service.register_source(scoped("fe80::1", a), a).unwrap();
    let source_b = service.register_source(scoped("fe80::1", b), b).unwrap();
    assert_ne!(source_a, source_b);
    service.add_route(route(a, "fe80::", 64)).unwrap();
    service.add_route(route(b, "fe80::", 64)).unwrap();
    let req = PathRequest {
        source: source_a,
        destination: scoped("fe80::99", a),
        dscp: Dscp::new(0).unwrap(),
    };
    let key_a = service.resolve(req).unwrap().key();
    let key_b = service
        .resolve(PathRequest {
            source: source_b,
            destination: scoped("fe80::99", b),
            ..req
        })
        .unwrap()
        .key();
    assert_ne!(key_a, key_b);
    assert_eq!(key_a.link(), a);
    assert_eq!(key_b.link(), b);
    assert_eq!(
        service.resolve(PathRequest {
            destination: scoped("fe80::99", b),
            ..req
        }),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        ScopedAddress::new("fe80::99".parse().unwrap(), None),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        ScopedAddress::new("2001:db8::1".parse().unwrap(), Some(a)),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        service.register_source(scoped("fe80::1", a), b),
        Err(Error::InvalidArgument)
    );
    service.remove_link(a).unwrap();
    assert_eq!(service.validate_selection(key_a), Err(Error::StaleHandle));
    assert_eq!(service.validate_selection(key_b).unwrap().key(), key_b);
}

#[test]
fn scoped_source_to_global_destination_selects_only_its_authoritative_link() {
    let mut service = service(17);
    let a = service.register_link(InterfaceKey(1), 1500).unwrap();
    let b = service.register_link(InterfaceKey(2), 1500).unwrap();
    let scoped = ScopedAddress::new("fe80::1".parse().unwrap(), Some(a)).unwrap();
    let source = service.register_source(scoped, a).unwrap();
    let req = request(source, "2001:db8::2");
    let other_link = service.add_route(route(b, "2001:db8::2", 128)).unwrap();
    assert_eq!(service.resolve(req), Err(Error::NoRoute));
    let same_link = service.add_route(route(a, "2001:db8::", 64)).unwrap();
    let resolved = service.resolve(req).unwrap();
    assert_eq!(resolved.key().source_address(), scoped);
    assert_eq!(resolved.key().destination(), req.destination);
    assert_eq!(resolved.key().link(), a);
    assert_eq!(resolved.key().route(), same_link);
    assert_eq!(resolved.key().next_hop(), req.destination);
    let (client, initial) = service.acquire(req).unwrap();
    service.acknowledge(client, initial.stamp()).unwrap();

    // Replacing an ineligible route on b cannot shadow a scoped source's route.
    service
        .replace_route(other_link, route(b, "::", 0))
        .unwrap();
    assert_eq!(service.snapshot(client), Ok(initial));
    assert_eq!(service.is_dirty(client), Ok(false));
    service.remove_route(same_link).unwrap();
    assert_eq!(service.resolve(req), Err(Error::NoRoute));
    let invalidated = service.snapshot(client).unwrap();
    assert_eq!(invalidated.path(), initial.path());
    assert_eq!(
        invalidated.status(),
        PathStatus::Invalidated(InvalidationReason::RouteRemoved)
    );
    assert_eq!(service.is_dirty(client), Ok(true));
    assert_eq!(service.rebind(client, req), Err(Error::NoRoute));
    assert_eq!(service.snapshot(client), Ok(invalidated));
}

#[test]
fn identity_contains_network_facts_and_excludes_ecn_and_ports() {
    let mut service = service(7);
    let a = service.register_link(InterfaceKey(1), 1500).unwrap();
    let source = service.register_source(address("192.0.2.1"), a).unwrap();
    let other = service.register_source(address("192.0.2.2"), a).unwrap();
    let id = service.add_route(route(a, "0.0.0.0", 0)).unwrap();
    let req = request(source, "198.51.100.1");
    let key = service.resolve(req).unwrap().key();
    // There is no port input in PathRequest: flows supply the same IP facts.
    for ecn in 0..4 {
        assert_eq!(
            service
                .resolve(PathRequest {
                    dscp: Dscp::from_traffic_class(ecn),
                    ..req
                })
                .unwrap()
                .key(),
            key
        );
    }
    assert_ne!(
        service
            .resolve(PathRequest {
                source: other,
                ..req
            })
            .unwrap()
            .key(),
        key
    );
    assert_ne!(
        service
            .resolve(request(source, "198.51.100.2"))
            .unwrap()
            .key(),
        key
    );
    assert_ne!(
        service
            .resolve(PathRequest {
                dscp: Dscp::new(1).unwrap(),
                ..req
            })
            .unwrap()
            .key(),
        key
    );
    assert_eq!(Dscp::new(64), Err(Error::InvalidArgument));
    assert_eq!(Dscp::from_traffic_class(255).value(), 63);
    let new = service
        .replace_route(
            id,
            Route {
                next_hop: NextHop::Gateway(address("192.0.2.254")),
                ..route(a, "0.0.0.0", 0)
            },
        )
        .unwrap();
    let new_key = service.resolve(req).unwrap().key();
    assert_ne!(key, new_key);
    assert_ne!(key.next_hop(), new_key.next_hop());
    assert_eq!(new_key.route(), new);
    assert_eq!(service.validate_selection(key), Err(Error::StaleHandle));
}

#[test]
fn foreign_and_recreated_handles_fail_without_cross_context_mutation() {
    let mut a = service(8);
    let mut b = service(9);
    let link = a.register_link(InterfaceKey(1), 1500).unwrap();
    let foreign = b.register_link(InterfaceKey(1), 1500).unwrap();
    assert_ne!(link, foreign);
    assert_eq!(a.remove_link(foreign), Err(Error::ForeignContext));
    let source = a.register_source(address("192.0.2.1"), link).unwrap();
    let foreign_source = b.register_source(address("192.0.2.1"), foreign).unwrap();
    assert_eq!(a.source_address(foreign_source), Err(Error::ForeignContext));
    let definition = route(link, "0.0.0.0", 0);
    let id = a.add_route(definition).unwrap();
    b.add_route(route(foreign, "0.0.0.0", 0)).unwrap();
    let key = a.resolve(request(source, "198.51.100.1")).unwrap().key();
    assert_eq!(b.validate_selection(key), Err(Error::ForeignContext));
    a.remove_route(id).unwrap();
    let recreated = a.add_route(definition).unwrap();
    assert_ne!(id, recreated);
    assert_eq!(a.remove_route(id), Err(Error::StaleHandle));
    a.remove_link(link).unwrap();
    let new_link = a.register_link(InterfaceKey(1), 1500).unwrap();
    assert_ne!(link, new_link);
    assert_eq!(a.source_address(source), Err(Error::StaleHandle));
    assert_eq!(a.add_route(definition), Err(Error::StaleHandle));
    assert_eq!(a.usage().routes, 0);
    assert_eq!(a.link(new_link).unwrap().mtu, 1500);
}

#[test]
fn families_sources_gateways_and_canonical_prefixes_are_checked() {
    let mut service = service(10);
    let a = service.register_link(InterfaceKey(1), 1500).unwrap();
    let b = service.register_link(InterfaceKey(2), 1500).unwrap();
    let v4 = service.register_source(address("192.0.2.1"), a).unwrap();
    let v6 = service.register_source(address("2001:db8::1"), a).unwrap();
    for text in ["0.0.0.0", "224.0.0.1", "255.255.255.255", "::", "ff02::1"] {
        assert_eq!(
            ScopedAddress::new(text.parse().unwrap(), None),
            Err(Error::InvalidArgument)
        );
    }
    for (text, length) in [
        ("192.0.2.1", 24),
        ("192.0.2.0", 0),
        ("::1", 0),
        ("0.0.0.0", 33),
        ("::", 129),
    ] {
        assert_eq!(
            IpPrefix::new(text.parse().unwrap(), length),
            Err(Error::InvalidArgument)
        );
    }
    assert_eq!(
        service.resolve(request(v4, "2001:db8::2")),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        service.resolve(request(v6, "192.0.2.2")),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        service.resolve(request(v4, "192.0.2.2")),
        Err(Error::NoRoute)
    );
    let r = route(a, "::", 0);
    assert_eq!(
        service.add_route(Route {
            source: Some(prefix("0.0.0.0", 0)),
            ..r
        }),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        service.add_route(Route {
            next_hop: NextHop::Gateway(address("192.0.2.254")),
            ..r
        }),
        Err(Error::InvalidArgument)
    );
    let wrong_zone = ScopedAddress::new("fe80::ff".parse().unwrap(), Some(b)).unwrap();
    assert_eq!(
        service.add_route(Route {
            next_hop: NextHop::Gateway(wrong_zone),
            ..r
        }),
        Err(Error::InvalidArgument)
    );
    let gateway = ScopedAddress::new("fe80::ff".parse().unwrap(), Some(a)).unwrap();
    let id = service
        .add_route(Route {
            next_hop: NextHop::Gateway(gateway),
            ..r
        })
        .unwrap();
    let selected = service.resolve(request(v6, "2001:db8:2::9")).unwrap();
    assert_eq!(selected.key().route(), id);
    assert_eq!(selected.key().next_hop(), gateway);
}

#[test]
fn physical_mtu_admin_keeps_identity_and_wire_jumbo_fact() {
    let mut service = service(11);
    let link = service.register_link(InterfaceKey(1), 100_000).unwrap();
    let source = service
        .register_source(address("2001:db8::1"), link)
        .unwrap();
    service.add_route(route(link, "::", 0)).unwrap();
    let old = service.resolve(request(source, "2001:db8::2")).unwrap();
    assert_eq!(old.first_hop_mtu(), 100_000);
    service.set_link_mtu(link, 1280).unwrap();
    let decreased = service.validate_selection(old.key()).unwrap();
    assert_eq!(decreased.key(), old.key());
    assert_eq!(decreased.first_hop_mtu(), 1280);
    assert!(decreased.link_version() > old.link_version());
    let revision = service.revision();
    assert_eq!(
        service.set_link_mtu(link, 1279),
        Err(Error::InvalidArgument)
    );
    assert_eq!(service.revision(), revision);
    assert_eq!(service.validate_selection(old.key()).unwrap(), decreased);
    service.set_link_mtu(link, 9001).unwrap();
    assert_eq!(
        service
            .validate_selection(old.key())
            .unwrap()
            .first_hop_mtu(),
        9001
    );
    let low = service.register_link(InterfaceKey(2), 68).unwrap();
    assert_eq!(
        service.register_source(address("2001:db8::2"), low),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        service.add_route(route(low, "::", 0)),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn capacity_failures_are_transactional_and_slots_are_reusable() {
    let mut service = PathService::new(
        ContextId::new(12),
        Limits {
            links: 2,
            sources: 1,
            source_owners: 2,
            routes: 1,
            paths: 2,
            clients: 2,
        },
    )
    .unwrap();
    let a = service.register_link(InterfaceKey(1), 1500).unwrap();
    let b = service.register_link(InterfaceKey(2), 1492).unwrap();
    let source = service.register_source(address("192.0.2.1"), a).unwrap();
    service.register_source(address("192.0.2.1"), b).unwrap();
    let route = route(a, "0.0.0.0", 0);
    let id = service.add_route(route).unwrap();
    let key = service
        .resolve(request(source, "198.51.100.1"))
        .unwrap()
        .key();
    let usage = service.usage();
    let revision = service.revision();
    assert_eq!(
        service.register_link(InterfaceKey(3), 1500),
        Err(Error::Capacity)
    );
    assert_eq!(
        service.register_source(address("192.0.2.2"), a),
        Err(Error::Capacity)
    );
    assert_eq!(
        service.add_route(Route { metric: 0, ..route }),
        Err(Error::Capacity)
    );
    assert_eq!(
        service.replace_routes(&[route, Route { metric: 0, ..route }]),
        Err(Error::Capacity)
    );
    assert_eq!(service.usage(), usage);
    assert_eq!(service.revision(), revision);
    assert_eq!(service.validate_selection(key).unwrap().key(), key);
    // An in-place route replacement succeeds even when every route slot is full.
    let new_id = service
        .replace_route(id, Route { link: b, ..route })
        .unwrap();
    assert_ne!(id, new_id);
    assert_eq!(service.usage(), usage);
    service.remove_link(a).unwrap();
    assert_eq!(service.source_address(source), Ok(address("192.0.2.1")));
    service.remove_link(b).unwrap();
    assert_eq!(
        service.usage(),
        Usage {
            links: 0,
            sources: 0,
            source_owners: 0,
            routes: 0,
            paths: 0,
            clients: 0
        }
    );
    let new_a = service.register_link(InterfaceKey(1), 1500).unwrap();
    let new_source = service
        .register_source(address("192.0.2.1"), new_a)
        .unwrap();
    assert_ne!(a, new_a);
    assert_ne!(source, new_source);
}

#[test]
fn source_and_owner_limits_are_independent_without_partial_claims() {
    let mut service = PathService::new(
        ContextId::new(13),
        Limits {
            links: 2,
            sources: 2,
            source_owners: 1,
            routes: 0,
            paths: 2,
            clients: 2,
        },
    )
    .unwrap();
    let a = service.register_link(InterfaceKey(1), 1500).unwrap();
    let b = service.register_link(InterfaceKey(2), 1500).unwrap();
    let source = service.register_source(address("192.0.2.1"), a).unwrap();
    let before = (service.usage(), service.revision());
    assert_eq!(
        service.register_source(address("192.0.2.1"), b),
        Err(Error::Capacity)
    );
    assert_eq!(
        service.register_source(address("192.0.2.2"), a),
        Err(Error::Capacity)
    );
    assert_eq!((service.usage(), service.revision()), before);
    assert_eq!(service.owns_source(source, b), Ok(false));
    service.remove_source_owner(source, a).unwrap();
    assert!(service.register_source(address("192.0.2.2"), b).is_ok());
    let mut no_sources = PathService::new(
        ContextId::new(14),
        Limits {
            links: 1,
            sources: 0,
            source_owners: 2,
            routes: 0,
            paths: 2,
            clients: 2,
        },
    )
    .unwrap();
    let link = no_sources.register_link(InterfaceKey(1), 1500).unwrap();
    let revision = no_sources.revision();
    assert_eq!(
        no_sources.register_source(address("192.0.2.1"), link),
        Err(Error::Capacity)
    );
    assert_eq!(no_sources.usage().source_owners, 0);
    assert_eq!(no_sources.revision(), revision);
    for limits in [
        Limits {
            links: usize::MAX,
            sources: 0,
            source_owners: 0,
            routes: 0,
            paths: 0,
            clients: 0,
        },
        Limits {
            links: 0,
            sources: usize::MAX,
            source_owners: 0,
            routes: 0,
            paths: 0,
            clients: 0,
        },
        Limits {
            links: 0,
            sources: 0,
            source_owners: usize::MAX,
            routes: 0,
            paths: 0,
            clients: 0,
        },
        Limits {
            links: 0,
            sources: 0,
            source_owners: 0,
            routes: usize::MAX,
            paths: 0,
            clients: 0,
        },
    ] {
        assert!(matches!(
            PathService::new(ContextId::new(15), limits),
            Err(Error::Capacity)
        ));
    }
}

#[test]
fn batch_route_replacement_preflights_all_definitions_and_retires_old_ids() {
    let mut service = service(16);
    let link = service.register_link(InterfaceKey(1), 1500).unwrap();
    let source = service.register_source(address("192.0.2.1"), link).unwrap();
    let original = route(link, "0.0.0.0", 0);
    let old = service.add_route(original).unwrap();
    let key = service
        .resolve(request(source, "198.51.100.1"))
        .unwrap()
        .key();
    let revision = service.revision();
    assert_eq!(
        service.replace_routes(&[original, original]),
        Err(Error::Duplicate)
    );
    assert_eq!(
        service.replace_routes(&[original, route(link, "::", 0)]),
        Ok(())
    );
    assert_eq!(service.route(old), Err(Error::StaleHandle));
    assert_eq!(service.validate_selection(key), Err(Error::StaleHandle));
    assert!(service.revision() > revision);
    let current = service.resolve(key.request()).unwrap().key();
    let revision = service.revision();
    let invalid = Route {
        next_hop: NextHop::Gateway(address("2001:db8::99")),
        ..original
    };
    assert_eq!(
        service.replace_routes(&[original, invalid]),
        Err(Error::InvalidArgument)
    );
    assert_eq!(service.revision(), revision);
    assert_eq!(service.validate_selection(current).unwrap().key(), current);
    service.replace_routes(&[]).unwrap();
    assert_eq!(service.usage().routes, 0);
    assert_eq!(service.resolve(key.request()), Err(Error::NoRoute));
}
