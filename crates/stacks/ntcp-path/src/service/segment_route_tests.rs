use crate::*;
use alloc::vec::Vec;
use core::net::Ipv6Addr;

fn address(value: &str) -> ScopedAddress {
    ScopedAddress::new(value.parse().unwrap(), None).unwrap()
}
fn v6(value: &str) -> Ipv6Addr {
    value.parse().unwrap()
}
fn prefix(value: &str, length: u8) -> IpPrefix {
    IpPrefix::new(value.parse().unwrap(), length).unwrap()
}

struct Fixture {
    service: PathService,
    link: LinkId,
    other_link: LinkId,
    source: SourceId,
}

fn fixture() -> Fixture {
    let mut service = PathService::new(
        ContextId::new(1701),
        Limits {
            links: 2,
            sources: 1,
            source_owners: 1,
            routes: 4,
            paths: 4,
            clients: 4,
        },
    )
    .unwrap();
    let link = service.register_link(InterfaceKey(1), 1500).unwrap();
    let other_link = service.register_link(InterfaceKey(2), 9000).unwrap();
    let source = service
        .register_source(address("2001:db8:1::1"), link)
        .unwrap();
    Fixture {
        service,
        link,
        other_link,
        source,
    }
}

fn route(destination: IpPrefix, link: LinkId) -> Route {
    Route {
        destination,
        source: None,
        dscp: None,
        link,
        next_hop: NextHop::OnLink,
        metric: 0,
    }
}

fn request(f: &Fixture, destination: &str) -> PathRequest {
    PathRequest {
        source: f.source,
        destination: address(destination),
        dscp: Dscp::new(0).unwrap(),
    }
}

#[test]
fn final_destination_selects_the_route_and_its_first_segment_forwards() {
    let mut f = fixture();
    // D lies outside S1's prefix, and a competing ordinary route covers S1
    // through another link: selection follows D, never S1.
    let sr = f
        .service
        .add_segment_route(
            route(prefix("2001:db8:d::", 48), f.link),
            &[v6("2001:db8:5::1"), v6("2001:db8:6::1")],
        )
        .unwrap();
    let competing = f
        .service
        .add_route(route(prefix("2001:db8:5::", 48), f.other_link))
        .unwrap();
    let resolved = f.service.resolve(request(&f, "2001:db8:d::9")).unwrap();
    let key = resolved.key();
    assert_eq!(key.route(), sr);
    assert_eq!(key.destination(), address("2001:db8:d::9"));
    assert_eq!(key.forwarding_destination(), address("2001:db8:5::1"));
    assert_eq!(key.link(), f.link);
    assert_eq!(
        key.next_hop(),
        ResolvedNextHop::Address(address("2001:db8:5::1"))
    );
    assert_eq!(resolved.first_hop_mtu(), 1500);
    assert_eq!(
        f.service.route_segments(sr).unwrap(),
        &[v6("2001:db8:5::1"), v6("2001:db8:6::1")]
    );
    assert!(f.service.route_segments(competing).unwrap().is_empty());
    // Traffic to S1 itself takes the competing ordinary route.
    let direct = f.service.resolve(request(&f, "2001:db8:5::1")).unwrap();
    assert_eq!(direct.key().route(), competing);
    assert_eq!(direct.key().link(), f.other_link);
    // resolve_via with D as the forwarding destination is resolve.
    assert_eq!(
        f.service
            .resolve_via(request(&f, "2001:db8:d::9"), address("2001:db8:d::9"))
            .unwrap(),
        resolved
    );
    // An explicit, different forwarding destination never takes the SR route.
    assert_eq!(
        f.service
            .resolve_via(request(&f, "2001:db8:d::9"), address("2001:db8:d::7")),
        Err(Error::NoRoute)
    );
    // The PMTU state is per SR path, and validation reselects by D: an
    // unrelated revision keeps the path valid although S1 lies outside the
    // route's prefix.
    let (client, snapshot) = f.service.acquire(request(&f, "2001:db8:d::9")).unwrap();
    assert_eq!(snapshot.key(), key);
    f.service.set_link_mtu(f.other_link, 8000).unwrap();
    assert_eq!(f.service.validate_selection(key).unwrap().key(), key);
    assert_eq!(
        f.service.snapshot(client).unwrap().status(),
        PathStatus::Valid
    );
}

#[test]
fn routes_sharing_a_first_segment_keep_distinct_lists_and_paths() {
    let mut f = fixture();
    let a = f
        .service
        .add_segment_route(
            route(prefix("2001:db8:a::", 48), f.link),
            &[v6("2001:db8:5::1"), v6("2001:db8:7::1")],
        )
        .unwrap();
    let b = f
        .service
        .add_segment_route(
            route(prefix("2001:db8:b::", 48), f.link),
            &[v6("2001:db8:5::1"), v6("2001:db8:8::1")],
        )
        .unwrap();
    let (_, pa) = f.service.acquire(request(&f, "2001:db8:a::1")).unwrap();
    let (_, pb) = f.service.acquire(request(&f, "2001:db8:b::1")).unwrap();
    assert_eq!(
        pa.key().forwarding_destination(),
        pb.key().forwarding_destination()
    );
    assert_eq!((pa.key().route(), pb.key().route()), (a, b));
    assert_ne!(pa.path(), pb.path());
    assert_eq!(f.service.route_segments(a).unwrap()[1], v6("2001:db8:7::1"));
    assert_eq!(f.service.route_segments(b).unwrap()[1], v6("2001:db8:8::1"));
}

#[test]
fn replacement_and_removal_invalidate_the_segment_path() {
    let mut f = fixture();
    let definition = route(prefix("2001:db8:d::", 48), f.link);
    let old = f
        .service
        .add_segment_route(definition, &[v6("2001:db8:5::1")])
        .unwrap();
    let req = request(&f, "2001:db8:d::9");
    let (client, before) = f.service.acquire(req).unwrap();
    assert_eq!(
        before.key().forwarding_destination(),
        address("2001:db8:5::1")
    );
    // A replacement is an ordinary route: the list ends with the old
    // generation and D is forwarded directly.
    let plain = f.service.replace_route(old, definition).unwrap();
    assert_eq!(f.service.route_segments(old), Err(Error::StaleHandle));
    assert!(f.service.route_segments(plain).unwrap().is_empty());
    assert!(matches!(
        f.service.snapshot(client).unwrap().status(),
        PathStatus::Invalidated(_)
    ));
    let (client, direct) = f.service.rebind(client, req).unwrap();
    assert_ne!(direct.path(), before.path());
    assert_eq!(direct.key().route(), plain);
    assert_eq!(direct.key().forwarding_destination(), req.destination);
    // Removal and a new SR route: S1 is derived from the new generation.
    f.service.remove_route(plain).unwrap();
    assert_eq!(f.service.route_segments(plain), Err(Error::StaleHandle));
    assert_eq!(f.service.resolve(req), Err(Error::NoRoute));
    let sr = f
        .service
        .add_segment_route(definition, &[v6("2001:db8:6::1"), v6("2001:db8:7::1")])
        .unwrap();
    let (_, again) = f.service.rebind(client, req).unwrap();
    assert_eq!(again.key().route(), sr);
    assert_eq!(
        again.key().forwarding_destination(),
        address("2001:db8:6::1")
    );
    f.service.remove_route(sr).unwrap();
    assert_eq!(f.service.route_segments(sr), Err(Error::StaleHandle));
    assert_eq!(f.service.resolve(req), Err(Error::NoRoute));
}

#[test]
fn failed_replacement_changes_nothing() {
    let mut f = fixture();
    let definition = route(prefix("2001:db8:d::", 48), f.link);
    let id = f
        .service
        .add_segment_route(definition, &[v6("2001:db8:5::1")])
        .unwrap();
    let policy = AdminPolicy {
        discovery_disabled: true,
        estimate: None,
    };
    let plan = f
        .service
        .prepare_admin(
            AdminChange {
                target: AdminTarget::Route(id),
                expected: 0,
                policy,
            },
            0,
            600,
        )
        .unwrap();
    f.service.commit_admin(plan).unwrap();
    let (client, snapshot) = f.service.acquire(request(&f, "2001:db8:d::9")).unwrap();
    // Replacing the SR route with a definition another route already
    // covers fails before any change.
    let other = route(prefix("2001:db8:e::", 48), f.link);
    let other_id = f.service.add_route(other).unwrap();
    let revision = f.service.revision();
    assert_eq!(
        f.service.replace_route(id, other),
        Err(Error::Duplicate)
    );
    assert_eq!(f.service.revision(), revision);
    assert_eq!(f.service.route(id), Ok(definition));
    assert_eq!(
        f.service.route_segments(id).unwrap(),
        &[v6("2001:db8:5::1")]
    );
    assert_eq!(f.service.route_administration(id).unwrap().policy, policy);
    assert_eq!(f.service.snapshot(client).unwrap(), snapshot);
    assert_eq!(f.service.route(other_id), Ok(other));
    // A successful same-family replacement keeps the owner's policy and
    // invalidates the learned path state.
    let new = f.service.replace_route(id, definition).unwrap();
    assert_eq!(f.service.route_administration(new).unwrap().policy, policy);
    assert!(matches!(
        f.service.snapshot(client).unwrap().status(),
        PathStatus::Invalidated(_)
    ));
}

#[test]
fn segment_list_bounds_and_families() {
    let mut f = fixture();
    let max: Vec<Ipv6Addr> = (0..MAX_SEGMENTS as u16)
        .map(|i| Ipv6Addr::new(0x2001, 0xdb8, 0x100, i, 0, 0, 0, 1))
        .collect();
    assert_eq!(MAX_SEGMENTS, 126);
    let id = f
        .service
        .add_segment_route(route(prefix("2001:db8:d::", 48), f.link), &max)
        .unwrap();
    assert_eq!(f.service.route_segments(id).unwrap(), &max[..]);
    let mut over = max.clone();
    over.push(v6("2001:db8:200::1"));
    assert_eq!(
        f.service
            .add_segment_route(route(prefix("2001:db8:e::", 48), f.link), &over),
        Err(Error::InvalidArgument)
    );
    // IPv4 and link-local destination prefixes never carry segments.
    assert_eq!(
        f.service.add_segment_route(
            route(prefix("192.0.2.0", 24), f.link),
            &[v6("2001:db8:5::1")]
        ),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        f.service
            .add_segment_route(route(prefix("fe80::", 64), f.link), &[v6("2001:db8:5::1")]),
        Err(Error::InvalidArgument)
    );
    // An ambiguous definition is a duplicate whatever its segments.
    assert_eq!(
        f.service.add_segment_route(
            route(prefix("2001:db8:d::", 48), f.link),
            &[v6("2001:db8:9::1")]
        ),
        Err(Error::Duplicate)
    );
    assert_eq!(f.service.usage().routes, 1);
}

#[test]
fn snapshots_carry_the_complete_header_of_their_route() {
    let mut f = fixture();
    f.service.add_route(route(prefix("::", 0), f.link)).unwrap();
    f.service
        .add_segment_route(
            route(prefix("2001:db8:d::", 48), f.link),
            &[v6("2001:db8:5::1"), v6("2001:db8:6::1")],
        )
        .unwrap();
    let many: Vec<Ipv6Addr> = (1..=MAX_SEGMENTS as u16)
        .map(|i| Ipv6Addr::new(0x2001, 0xdb8, 7, i, 0, 0, 0, 1))
        .collect();
    f.service
        .add_segment_route(route(prefix("2001:db8:e::", 48), f.link), &many)
        .unwrap();
    for (destination, header) in [
        ("2001:db8:9::1", 40),
        ("2001:db8:d::9", 40 + 8 + 16 * 3),
        ("2001:db8:e::9", 40 + 8 + 16 * 127),
    ] {
        let (_, snapshot) = f.service.acquire(request(&f, destination)).unwrap();
        assert_eq!(snapshot.ip_header_len(), header, "{destination}");
    }
}
