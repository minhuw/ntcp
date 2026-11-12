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
        [1; 16],
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

// Whether the index lists every cached path on its flow's chain, the idle
// paths and the lowest free slot, as full scans find them.
fn index_holds(service: &PathService) -> bool {
    let first_free = service.paths.slots.iter().position(|s| s.value.is_none());
    service.index.lists_chains(|slot| {
        let path = service.paths.slots[slot].value.as_ref()?;
        Some(service.index.bucket(&path.snapshot.key))
    }) && service.index.lists_idle(|slot| {
        service.paths.slots[slot]
            .value
            .as_ref()
            .is_some_and(CachedPath::idle)
    }) && service.index.free() == first_free
}

// A seeded sequence of acquisitions, rebinds, releases, decreases, route
// changes, Redirects (installed and ended) and exact-path policy through a
// gateway route, against a full table: after every step the index matches
// the scans it replaced, and every flow's cache lookup chooses the slot the
// scan chooses, with distinct buckets and with every flow on one chain.
#[test]
fn index_matches_the_scans_under_random_operations() {
    let address = |text: &str| ScopedAddress::new(text.parse().unwrap(), None).unwrap();
    for collide in [false, true] {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move |bound: usize| {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) as usize % bound
        };
        let mut service = PathService::new(
            ContextId::new(3),
            Limits {
                links: 1,
                sources: 1,
                source_owners: 1,
                routes: 2,
                paths: 6,
                clients: 8,
            },
            [9; 16],
        )
        .unwrap();
        if collide {
            service.index.collide();
        }
        let link = service.register_link(InterfaceKey(1), 1500).unwrap();
        let source = service
            .register_source(address("192.0.2.10"), link)
            .unwrap();
        let gateway = Route {
            destination: IpPrefix::new("0.0.0.0".parse().unwrap(), 0).unwrap(),
            source: None,
            dscp: None,
            link,
            next_hop: NextHop::Gateway(address("192.0.2.1")),
            metric: 0,
        };
        let mut default = service.add_route(gateway).unwrap();
        let shadow = Route {
            destination: IpPrefix::new("198.51.100.0".parse().unwrap(), 30).unwrap(),
            next_hop: NextHop::Gateway(address("192.0.2.3")),
            ..gateway
        };
        let mut shadowing = None;
        let request = |n: usize| PathRequest {
            source,
            destination: address(&alloc::format!("198.51.100.{}", n % 5 + 1)),
            dscp: Dscp::new(if n >= 5 { 46 } else { 0 }).unwrap(),
        };
        let mut clients: Vec<ClientId> = Vec::new();
        for step in 0..4000 {
            let pick = next(clients.len().max(1));
            match next(10) {
                0..=2 => {
                    if let Ok((client, _)) = service.acquire(request(next(10))) {
                        clients.push(client);
                    }
                }
                3 if !clients.is_empty() => {
                    service.release(clients.swap_remove(pick)).unwrap();
                }
                4 if !clients.is_empty() => {
                    if let Ok((client, _)) = service.rebind(clients[pick], request(next(10))) {
                        clients[pick] = client;
                    }
                }
                5 if !clients.is_empty() => {
                    let path = service.snapshot(clients[pick]).unwrap().path();
                    let _ = service.trusted_decrease(path, 1200 + next(200) as u32);
                }
                6 => match shadowing.take() {
                    Some(id) => service.remove_route(id).unwrap(),
                    None => shadowing = Some(service.add_route(shadow).unwrap()),
                },
                7 if !clients.is_empty() => {
                    let snapshot = service.snapshot(clients[pick]).unwrap();
                    let target = address(["192.0.2.1", "192.0.2.2", "192.0.2.4"][next(3)]);
                    if let ResolvedNextHop::Address(sender) = snapshot.key().next_hop() {
                        let _ = service.redirect(snapshot.key(), sender, target, next(2) == 0);
                    }
                }
                8 => {
                    let neighbor = address(["192.0.2.2", "192.0.2.4"][next(2)]);
                    service
                        .end_redirects(link, neighbor, NeighborLoss::Unreachable)
                        .unwrap();
                }
                9 => {
                    // Any cached path, idle ones included.
                    let paths: Vec<_> = service.path_administrations().collect();
                    if let Some(admin) = paths.get(next(paths.len().max(1))) {
                        let path = admin.snapshot.path();
                        let policy = AdminPolicy {
                            discovery_disabled: next(2) == 0,
                            estimate: None,
                        };
                        let change = AdminChange {
                            target: AdminTarget::Path(path),
                            expected: admin.generation,
                            policy,
                        };
                        if let Ok(plan) = service.prepare_admin(change, step as u64, 600) {
                            service.commit_admin(plan).unwrap();
                        }
                    }
                }
                _ if step % 97 == 0 => {
                    // A replacement invalidates every path through the route.
                    default = service.replace_route(default, gateway).unwrap();
                }
                _ => {}
            }
            assert!(index_holds(&service), "step {step}, collide {collide}");
            for n in 0..10 {
                if let Ok(resolved) = service.resolve(request(n)) {
                    assert_eq!(
                        service.path_slot(resolved.key()),
                        service.scan_path_slot(resolved.key()),
                        "step {step}, collide {collide}"
                    );
                }
            }
        }
    }
}

// With every slot occupied, a new flow takes the lowest-index idle slot,
// whichever order paths became idle in, and Capacity when none is idle.
#[test]
fn a_full_cache_evicts_the_lowest_index_idle_path() {
    let address = |text: &str| ScopedAddress::new(text.parse().unwrap(), None).unwrap();
    let mut service = PathService::new(
        ContextId::new(4),
        Limits {
            links: 1,
            sources: 1,
            source_owners: 1,
            routes: 1,
            paths: 130,
            clients: 130,
        },
        [5; 16],
    )
    .unwrap();
    let link = service.register_link(InterfaceKey(1), 1500).unwrap();
    let source = service
        .register_source(address("192.0.2.10"), link)
        .unwrap();
    service
        .add_route(Route {
            destination: IpPrefix::new("0.0.0.0".parse().unwrap(), 0).unwrap(),
            source: None,
            dscp: None,
            link,
            next_hop: NextHop::OnLink,
            metric: 0,
        })
        .unwrap();
    let request = |n: usize| PathRequest {
        source,
        destination: address(&alloc::format!("198.51.{}.{}", n / 200, n % 200 + 1)),
        dscp: Dscp::new(0).unwrap(),
    };
    let mut clients: Vec<_> = (0..130)
        .map(|n| {
            let (client, snapshot) = service.acquire(request(n)).unwrap();
            assert_eq!(snapshot.path().0.slot, n);
            Some(client)
        })
        .collect();
    assert_eq!(service.acquire(request(130)), Err(Error::Capacity));
    // Idle in descending order, across the idle bitmap's words.
    for slot in [129, 70, 64, 3] {
        service.release(clients[slot].take().unwrap()).unwrap();
    }
    for (n, slot) in [3, 64, 70, 129].into_iter().enumerate() {
        let (_, snapshot) = service.acquire(request(200 + n)).unwrap();
        assert_eq!(snapshot.path().0.slot, slot);
        assert!(index_holds(&service));
    }
    assert_eq!(service.acquire(request(300)), Err(Error::Capacity));
}
