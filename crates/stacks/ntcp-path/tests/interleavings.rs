use ntcp_path::*;

fn address(text: &str) -> ScopedAddress {
    ScopedAddress::new(text.parse().unwrap(), None).unwrap()
}
fn service() -> (
    PathService,
    LinkId,
    RouteId,
    PathRequest,
    ClientId,
    PathSnapshot,
) {
    let mut service = PathService::new(
        ContextId::new(700),
        Limits {
            links: 1,
            sources: 1,
            source_owners: 1,
            routes: 1,
            paths: 2,
            clients: 2,
        },
        [1; 16],
    )
    .unwrap();
    let link = service.register_link(InterfaceKey(1), 9001).unwrap();
    let source = service.register_source(address("192.0.2.1"), link).unwrap();
    let route = service
        .add_route(Route {
            destination: IpPrefix::new("0.0.0.0".parse().unwrap(), 0).unwrap(),
            source: None,
            dscp: None,
            link,
            next_hop: NextHop::Gateway(address("192.0.2.254")),
            metric: 100,
        })
        .unwrap();
    let req = PathRequest {
        source,
        destination: address("198.51.100.1"),
        dscp: Dscp::new(0).unwrap(),
    };
    let (client, snapshot) = service.acquire(req).unwrap();
    service.acknowledge(client, snapshot.stamp()).unwrap();
    (service, link, route, req, client, snapshot)
}

#[test]
fn every_full_authority_table_failure_preserves_bound_state_and_notification() {
    for dirty in [false, true] {
        let (mut service, link, route, req, client, initial) = service();
        if dirty {
            service.trusted_decrease(initial.path(), 1492).unwrap();
        }
        let before = (
            service.revision(),
            service.usage(),
            service.snapshot(client),
            service.is_dirty(client),
        );
        assert_eq!(
            service.register_link(InterfaceKey(2), 1500),
            Err(Error::Capacity)
        );
        assert_eq!(
            service.register_source(address("192.0.2.2"), link),
            Err(Error::Capacity)
        );
        let definition = service.route(route).unwrap();
        assert_eq!(
            service.add_route(Route {
                metric: 0,
                ..definition
            }),
            Err(Error::Capacity)
        );
        assert_eq!(
            service.replace_routes(&[
                definition,
                Route {
                    metric: 0,
                    ..definition
                }
            ]),
            Err(Error::Capacity)
        );
        assert_eq!(
            (
                service.revision(),
                service.usage(),
                service.snapshot(client),
                service.is_dirty(client)
            ),
            before
        );
        assert_eq!(service.path_pins(initial.path()), Ok(1));
        assert_eq!(service.resolve(req).unwrap().key(), initial.key());
        assert_eq!(service.route(route), Ok(definition));
    }
}

#[test]
fn invalidation_while_a_client_holds_an_old_read_cannot_be_lost_by_either_ack() {
    let (mut service, _, route, req, a, initial) = service();
    let (b, _) = service.acquire(req).unwrap();
    service.acknowledge(b, initial.stamp()).unwrap();
    service.trusted_decrease(initial.path(), 1500).unwrap();
    let read_n = service.snapshot(a).unwrap();
    service.trusted_decrease(initial.path(), 1492).unwrap();
    // Both clients remain logically blocked while authoritative route deletion
    // supersedes both pending decreases. This models no real output reservation.
    service.remove_route(route).unwrap();
    let invalidated = service.snapshot(a).unwrap();
    assert_eq!(
        invalidated.status(),
        PathStatus::Invalidated(InvalidationReason::RouteRemoved)
    );
    assert!(invalidated.version() > read_n.version());
    for client in [a, b] {
        service.acknowledge(client, read_n.stamp()).unwrap();
        assert!(service.is_dirty(client).unwrap());
        assert_eq!(service.snapshot(client), Ok(invalidated));
        assert_eq!(service.rebind(client, req), Err(Error::NoRoute));
        assert_eq!(service.snapshot(client), Ok(invalidated));
    }
    service.acknowledge(a, invalidated.stamp()).unwrap();
    assert_eq!(service.dirty_clients().collect::<Vec<_>>(), vec![b]);
    assert_eq!(
        service.snapshot(a).unwrap().mms_s(),
        Err(Error::Invalidated)
    );
    service.release(a).unwrap();
    assert_eq!(service.path_pins(initial.path()), Ok(1));
    assert!(service.is_dirty(b).unwrap());
}

#[test]
fn source_owner_claim_capacity_preserves_an_active_global_source() {
    let mut service = PathService::new(
        ContextId::new(701),
        Limits {
            links: 2,
            sources: 2,
            source_owners: 1,
            routes: 1,
            paths: 1,
            clients: 1,
        },
        [1; 16],
    )
    .unwrap();
    let a = service.register_link(InterfaceKey(1), 1500).unwrap();
    let b = service.register_link(InterfaceKey(2), 1500).unwrap();
    let source = service.register_source(address("192.0.2.1"), a).unwrap();
    service
        .add_route(Route {
            destination: IpPrefix::new("0.0.0.0".parse().unwrap(), 0).unwrap(),
            source: None,
            dscp: None,
            link: b,
            next_hop: NextHop::OnLink,
            metric: 0,
        })
        .unwrap();
    let (client, initial) = service
        .acquire(PathRequest {
            source,
            destination: address("198.51.100.1"),
            dscp: Dscp::new(0).unwrap(),
        })
        .unwrap();
    service.trusted_decrease(initial.path(), 1400).unwrap();
    let before = (
        service.revision(),
        service.usage(),
        service.snapshot(client),
        service.is_dirty(client),
    );
    assert_eq!(
        service.register_source(address("192.0.2.1"), b),
        Err(Error::Capacity)
    );
    assert_eq!(
        service.register_source(address("192.0.2.2"), b),
        Err(Error::Capacity)
    );
    assert_eq!(
        (
            service.revision(),
            service.usage(),
            service.snapshot(client),
            service.is_dirty(client)
        ),
        before
    );
    assert_eq!(service.owns_source(source, a), Ok(true));
    assert_eq!(service.owns_source(source, b), Ok(false));
    assert_eq!(service.path_pins(initial.path()), Ok(1));
}

#[test]
fn live_fallback_descends_to_floor_under_each_runtime_table_without_touching_first_hop() {
    for table in [
        Ipv4Plateaus::CONTEMPORARY,
        Ipv4Plateaus::RFC1191,
        Ipv4Plateaus::new(&[9001, 1500, 1400, 68]).unwrap(),
    ] {
        for header in [20, 60] {
            let (mut service, link, route, _, client, initial) = service();
            service.set_ipv4_plateaus(table).unwrap();
            let forwarding = service.route(route).unwrap();
            let mut current = 9001;
            let mut steps = 0;
            while current > 68 {
                let expected = table.next_lower((current - header).min(current));
                assert_eq!(
                    service.trusted_ipv4_fallback(initial.path(), current, header, current),
                    Ok(EstimateChange::Decreased)
                );
                let now = service.snapshot(client).unwrap();
                assert_eq!(now.ip_packet_budget(), Ok(expected));
                assert_eq!(now.learned_mtu(), Some(expected));
                assert_eq!(now.key(), initial.key());
                assert_eq!(now.first_hop_mtu(), 9001);
                assert_eq!(service.link(link).unwrap().mtu, 9001);
                assert_eq!(service.route(route), Ok(forwarding));
                current = expected;
                steps += 1;
                assert!(steps <= Ipv4Plateaus::CAPACITY);
            }
            let last = service.snapshot(client).unwrap();
            service.acknowledge(client, last.stamp()).unwrap();
            assert_eq!(
                service.trusted_ipv4_fallback(initial.path(), 68, header, 68),
                Ok(EstimateChange::Unchanged)
            );
            assert_eq!(service.snapshot(client), Ok(last));
            assert!(!service.is_dirty(client).unwrap());
            assert_eq!(
                last.payload_budget(60, 20, None),
                Err(Error::InvalidArgument)
            );
            assert_eq!(last.payload_budget(60, 8, None), Ok(0));
            assert_eq!(last.mms_s(), Ok(48));
        }
    }
}
