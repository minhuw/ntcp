use ntcp_path::*;

fn address(value: &str) -> ScopedAddress {
    ScopedAddress::new(value.parse().unwrap(), None).unwrap()
}

#[test]
fn opaque_forwarder_is_explicit_canonical_link_authority() {
    let mut service = PathService::new(
        ContextId::new(501),
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
    let link = service.register_link(InterfaceKey(9), 1500).unwrap();
    let source = service.register_source(address("192.0.2.1"), link).unwrap();
    let route = Route {
        destination: IpPrefix::new("0.0.0.0".parse().unwrap(), 0).unwrap(),
        source: None,
        dscp: None,
        link,
        next_hop: NextHop::Forwarder(ForwarderId(17)),
        metric: 0,
    };
    let route_id = service.add_route(route).unwrap();
    let request = PathRequest {
        source,
        destination: address("198.51.100.8"),
        dscp: Dscp::new(24).unwrap(),
    };
    let (client, snapshot) = service.acquire(request).unwrap();
    assert_eq!(
        snapshot.key().next_hop(),
        ResolvedNextHop::Forwarder(ForwarderId(17))
    );
    assert_eq!(snapshot.key().destination(), request.destination);
    let mut replacement = route;
    replacement.next_hop = NextHop::Forwarder(ForwarderId(18));
    service.replace_route(route_id, replacement).unwrap();
    assert!(service.validate_selection(snapshot.key()).is_err());
    assert!(matches!(
        service.snapshot(client).unwrap().status(),
        PathStatus::Invalidated(_)
    ));
    let (_, current) = service.rebind(client, request).unwrap();
    assert_ne!(current.path(), snapshot.path());
    assert_eq!(
        current.key().next_hop(),
        ResolvedNextHop::Forwarder(ForwarderId(18))
    );
}

#[test]
fn source_route_first_hop_and_final_peer_both_qualify_the_same_canonical_path() {
    let mut service = PathService::new(
        ContextId::new(502),
        Limits {
            links: 1,
            sources: 1,
            source_owners: 1,
            routes: 2,
            paths: 4,
            clients: 4,
        },
        [1; 16],
    )
    .unwrap();
    let link = service.register_link(InterfaceKey(9), 1500).unwrap();
    let source = service.register_source(address("192.0.2.1"), link).unwrap();
    let route = service
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
        destination: address("198.51.100.8"),
        dscp: Dscp::new(24).unwrap(),
    };
    assert_eq!(service.resolve(request), Err(Error::NoRoute));
    let hop = address("192.0.2.254");
    let (a, first) = service.acquire_via(request, hop).unwrap();
    let (b, second) = service
        .acquire_via(
            PathRequest {
                destination: address("203.0.113.8"),
                ..request
            },
            hop,
        )
        .unwrap();
    assert_ne!(first.path(), second.path());
    assert_eq!(first.key().destination(), request.destination);
    assert_eq!(first.key().forwarding_destination(), hop);
    assert_eq!(first.key().next_hop(), hop);
    service
        .trusted_decrease_with_hold(first.path(), 1200, 600_000_000)
        .unwrap();
    assert_eq!(service.snapshot(a).unwrap().learned_mtu(), Some(1200));
    assert_eq!(service.snapshot(b).unwrap().learned_mtu(), None);
    assert_eq!(
        service.validate_selection(first.key()).unwrap().key(),
        first.key()
    );
    service.remove_route(route).unwrap();
    assert!(service.validate_selection(first.key()).is_err());
    assert!(service.rebind_via(a, request, hop).is_err());
    assert!(service.is_dirty(a).unwrap());
}
