use super::*;

fn setup() -> (
    PathService,
    LinkId,
    RouteId,
    PathRequest,
    ClientId,
    PathSnapshot,
) {
    let mut service = PathService::new(
        ContextId::new(1),
        Limits {
            links: 2,
            sources: 2,
            source_owners: 2,
            routes: 2,
            paths: 2,
            clients: 2,
        },
    )
    .unwrap();
    let link = service.register_link(InterfaceKey(1), 1500).unwrap();
    let source = service
        .register_source(
            ScopedAddress::new("192.0.2.1".parse().unwrap(), None).unwrap(),
            link,
        )
        .unwrap();
    let route = service
        .add_route(Route {
            destination: IpPrefix::new("0.0.0.0".parse().unwrap(), 0).unwrap(),
            source: None,
            dscp: None,
            link,
            next_hop: NextHop::OnLink,
            metric: 10,
        })
        .unwrap();
    let req = PathRequest {
        source,
        destination: ScopedAddress::new("198.51.100.1".parse().unwrap(), None).unwrap(),
        dscp: Dscp::new(0).unwrap(),
    };
    let (client, snapshot) = service.acquire(req).unwrap();
    service.acknowledge(client, snapshot.stamp()).unwrap();
    (service, link, route, req, client, snapshot)
}

#[test]
fn version_exhaustion_preflights_all_bound_authority_and_estimate_mutations() {
    for pending in [false, true] {
        for operation in 0..10 {
            let (mut service, link, id, req, client, initial) = setup();
            if pending {
                service.trusted_decrease(initial.path(), 1492).unwrap();
            }
            service.revision = u64::MAX;
            let snapshot = service.snapshot(client).unwrap();
            let before = (
                service.usage(),
                service.generation,
                service.revision,
                service.is_dirty(client),
            );
            let route = service.route(id).unwrap();
            let alternative = Route { metric: 0, ..route };
            let result = match operation {
                0 => service.set_link_mtu(link, 1400),
                1 => service.remove_link(link),
                2 => service.remove_source_owner(req.source, link),
                3 => service.add_route(alternative).map(|_| ()),
                4 => service.replace_route(id, alternative).map(|_| ()),
                5 => service.remove_route(id),
                6 => service.replace_routes(&[alternative]),
                7 => service.trusted_decrease(initial.path(), 1300).map(|_| ()),
                8 => service.set_ipv4_plateaus(Ipv4Plateaus::RFC1191),
                9 => service
                    .rebind(
                        client,
                        PathRequest {
                            dscp: Dscp::new(1).unwrap(),
                            ..req
                        },
                    )
                    .map(|_| ()),
                _ => unreachable!(),
            };
            assert_eq!(
                result,
                Err(Error::Exhausted),
                "operation {operation}, pending {pending}"
            );
            assert_eq!(
                (
                    service.usage(),
                    service.generation,
                    service.revision,
                    service.is_dirty(client)
                ),
                before
            );
            assert_eq!(service.snapshot(client), Ok(snapshot));
            assert_eq!(service.path_pins(initial.path()), Ok(1));
            assert_eq!(service.route(id), Ok(route));
            assert_eq!(service.link(link).unwrap().mtu, 1500);
            assert_eq!(
                service.source_address(req.source),
                Ok(initial.key().source_address())
            );
            assert_eq!(service.ipv4_plateaus(), Ipv4Plateaus::CONTEMPORARY);
        }
    }
}

#[test]
fn masked_network_decrease_preflights_revision_before_changing_learned_state() {
    for prior_estimate in [None, Some(1400)] {
        for pending in [false, true] {
            let (mut service, link, _, req, a, initial) = setup();
            let (b, _) = service.acquire(req).unwrap();
            if let Some(estimate) = prior_estimate {
                service.trusted_decrease(initial.path(), estimate).unwrap();
            }
            service.set_link_mtu(link, 1280).unwrap();
            if !pending {
                for client in [a, b] {
                    let stamp = service.snapshot(client).unwrap().stamp();
                    service.acknowledge(client, stamp).unwrap();
                }
            }
            service.revision = u64::MAX;
            let before = service.snapshot(a).unwrap();
            let usage = service.usage();
            let generation = service.generation;
            assert_eq!(before.learned_mtu(), prior_estimate);
            assert_eq!(before.ip_packet_budget(), Ok(1280));
            assert_eq!(
                service.trusted_decrease(initial.path(), 1300),
                Err(Error::Exhausted)
            );
            assert_eq!(service.revision, u64::MAX);
            assert_eq!(service.generation, generation);
            assert_eq!(service.usage(), usage);
            assert_eq!(service.path_pins(initial.path()), Ok(2));
            for client in [a, b] {
                assert_eq!(service.snapshot(client), Ok(before));
                assert_eq!(service.is_dirty(client), Ok(pending));
            }
        }
    }
}

#[test]
fn initial_nondecreasing_feedback_needs_no_revision_even_at_exhaustion() {
    for masked in [false, true] {
        for pending in [false, true] {
            let (mut service, link, _, _, client, initial) = setup();
            if masked {
                service.set_link_mtu(link, 1280).unwrap();
            }
            if pending {
                // A policy update leaves an unlearned path dirty.
                service.set_ipv4_plateaus(Ipv4Plateaus::RFC1191).unwrap();
            } else {
                let stamp = service.snapshot(client).unwrap().stamp();
                service.acknowledge(client, stamp).unwrap();
            }
            service.revision = u64::MAX;
            let before = service.snapshot(client).unwrap();
            let usage = service.usage();
            let generation = service.generation;
            for candidate in [1500, 9001, 65535] {
                assert_eq!(
                    service.trusted_decrease(initial.path(), candidate),
                    Ok(EstimateChange::Unchanged)
                );
                assert_eq!(service.snapshot(client), Ok(before));
                assert_eq!(service.is_dirty(client), Ok(pending));
                assert_eq!(service.revision, u64::MAX);
                assert_eq!(service.generation, generation);
                assert_eq!(service.usage(), usage);
                assert_eq!(service.path_pins(initial.path()), Ok(1));
            }
        }
    }
}

#[test]
fn generation_preflight_reserves_both_path_and_binding_before_evicting() {
    for remaining in [0, 1] {
        for rebind in [false, true] {
            let (mut service, _, _, req, client, initial) = setup();
            service.generation = u64::MAX - remaining;
            let before = (
                service.usage(),
                service.revision(),
                service.snapshot(client),
                service.is_dirty(client),
            );
            let request = PathRequest {
                dscp: Dscp::new(1).unwrap(),
                ..req
            };
            let result = if rebind {
                service.rebind(client, request)
            } else {
                service.acquire(request)
            };
            assert_eq!(result, Err(Error::Exhausted));
            assert_eq!(
                (
                    service.usage(),
                    service.revision(),
                    service.snapshot(client),
                    service.is_dirty(client)
                ),
                before
            );
            assert_eq!(service.path_pins(initial.path()), Ok(1));
            assert_eq!(service.generation, u64::MAX - remaining);
        }
    }
    let (mut service, _, _, req, client, initial) = setup();
    service.generation = u64::MAX;
    assert_eq!(service.acquire(req), Err(Error::Exhausted));
    assert_eq!(service.path_pins(initial.path()), Ok(1));
    // Release needs no new generation and remains available at exhaustion.
    service.release(client).unwrap();
    assert_eq!(service.path_pins(initial.path()), Ok(0));
    assert_eq!(service.usage().clients, 0);
}

#[test]
fn future_ack_cannot_suppress_a_pending_change_and_max_version_does_not_wrap() {
    let (mut service, _, _, _, client, initial) = setup();
    let future = ChangeStamp {
        version: initial.version() + 1,
        ..initial.stamp()
    };
    assert_eq!(
        service.acknowledge(client, future),
        Err(Error::InvalidArgument)
    );
    service.revision = u64::MAX - 1;
    service.trusted_decrease(initial.path(), 1400).unwrap();
    let last = service.snapshot(client).unwrap();
    assert_eq!(last.version(), u64::MAX);
    service.acknowledge(client, initial.stamp()).unwrap();
    assert!(service.is_dirty(client).unwrap());
    assert_eq!(
        service.trusted_decrease(initial.path(), 1300),
        Err(Error::Exhausted)
    );
    assert_eq!(service.snapshot(client), Ok(last));
    assert!(service.is_dirty(client).unwrap());
    service.acknowledge(client, last.stamp()).unwrap();
    assert!(!service.is_dirty(client).unwrap());
}

#[test]
fn vector_capacity_overflow_is_a_fallible_allocation_error() {
    assert!(matches!(
        Table::<LinkInfo>::new(usize::MAX),
        Err(Error::Allocation)
    ));
}
