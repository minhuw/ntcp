use ntcp_path::*;

fn address(text: &str) -> ScopedAddress {
    ScopedAddress::new(text.parse().unwrap(), None).unwrap()
}
fn route(link: LinkId, network: &str, length: u8, metric: u32) -> Route {
    Route {
        destination: IpPrefix::new(network.parse().unwrap(), length).unwrap(),
        source: None,
        dscp: None,
        link,
        next_hop: NextHop::OnLink,
        metric,
    }
}
fn limits(paths: usize, clients: usize) -> Limits {
    Limits {
        links: 4,
        sources: 6,
        source_owners: 8,
        routes: 12,
        paths,
        clients,
    }
}
fn setup(
    paths: usize,
    clients: usize,
    ipv6: bool,
    mtu: u32,
) -> (PathService, LinkId, RouteId, PathRequest) {
    let mut service = PathService::new(ContextId::new(100), limits(paths, clients)).unwrap();
    let link = service.register_link(InterfaceKey(1), mtu).unwrap();
    let source = service
        .register_source(
            address(if ipv6 { "2001:db8::1" } else { "192.0.2.1" }),
            link,
        )
        .unwrap();
    let id = service
        .add_route(route(link, if ipv6 { "::" } else { "0.0.0.0" }, 0, 100))
        .unwrap();
    let request = PathRequest {
        source,
        destination: address(if ipv6 {
            "2001:db8:1::99"
        } else {
            "198.51.100.99"
        }),
        dscp: Dscp::new(0).unwrap(),
    };
    (service, link, id, request)
}
fn clean(service: &mut PathService, client: ClientId) -> PathSnapshot {
    let snapshot = service.snapshot(client).unwrap();
    service.acknowledge(client, snapshot.stamp()).unwrap();
    assert_eq!(service.is_dirty(client), Ok(false));
    snapshot
}
fn invalid(
    service: &PathService,
    client: ClientId,
    previous: PathSnapshot,
    reason: InvalidationReason,
) -> PathSnapshot {
    let now = service.snapshot(client).unwrap();
    assert_eq!(now.path(), previous.path());
    assert_eq!(now.key(), previous.key());
    assert!(now.version() > previous.version());
    assert_eq!(now.status(), PathStatus::Invalidated(reason));
    assert_eq!(now.ip_packet_budget(), Err(Error::Invalidated));
    assert_eq!(service.is_dirty(client), Ok(true));
    now
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.1
//= type=test
//= reason=T7 PathService exposes minimum-header MMS_S, complete-header budgets and versioned notifications with exact acknowledgements. T8 Host applies snapshots to actual native/TUN TCP owners and gates every reserved physical submission. Independent-reader/coalescing tests preserve readN/update/ackN; validated cross-protocol publication remains T9/T10.
//# A way to learn of changes in the value of MMS_S, the "maximum send transport-message size", which is derived from the Path MTU by subtracting the minimum IP header size.
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
//= type=test
//= reason=Managed factories acquire per-host records from configured network/default routes before TCP construction, initializing unlearned budgets from the physical first hop. Trusted decreases change only per-host learned estimates, preserving forwarding routes and independent first-hop facts. Dual-family two-Endpoint tests exercise both route selections, first SYN/hidden child and later decreases without forwarding-route mutation. Generic ICMP publication remains the separate 1191-057 obligation.
//# When the first packet is sent to a host for which no per-host route exists, a route is chosen either from the set of per-network routes, or from the set of default routes. The PMTU fields in these route entries should be initialized to be the MTU of the associated first-hop data link, and must never be changed by the PMTU Discovery process. (PMTU Discovery only creates or changes entries for per-host routes). Until a Datagram Too Big message is received, the PMTU associated with the initially-chosen route is presumed to be accurate.
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
//= type=test
//= reason=T7 PathService coalesces dirty snapshots with exact acknowledgements. T8 Host refreshes actual native/TUN TCP owners, including reserved/released generations, without inventing repair or loss events; two-flow and held-output tests exercise trusted decreases. Generic validated ICMP producers and actual datagram consumers/fanout remain T9/T10.
//# The packetization layers must be notified about decreases in the PMTU. Any packetization layer instance (for example, a TCP connection) that is actively using the path must be notified if the PMTU estimate is decreased.
fn independent_clients_share_network_decreases_and_coalesce_without_consuming_reads() {
    for ipv6 in [false, true] {
        let (mut service, link, parent, req) = setup(4, 4, ipv6, 9001);
        let (a, initial) = service.acquire(req).unwrap();
        let (b, sibling) = service.acquire(req).unwrap();
        assert_ne!(a, b);
        assert_eq!(initial, sibling);
        assert_eq!(service.path_pins(initial.path()), Ok(2));
        clean(&mut service, a);
        clean(&mut service, b);
        let parent_before = service.route(parent).unwrap();
        // Two logical packetization clients; no TCP delivery/reservation or
        // physical UDP submission is fabricated by these service-level clients.
        let retained_submission_path = initial.path();
        assert_eq!(
            service.trusted_decrease(retained_submission_path, 1500),
            Ok(EstimateChange::Decreased)
        );
        assert_eq!(
            service.trusted_decrease(retained_submission_path, 1492),
            Ok(EstimateChange::Decreased)
        );
        let read_n = service.snapshot(a).unwrap();
        assert_eq!(read_n.learned_mtu(), Some(1492));
        assert_eq!(read_n.mms_s(), Ok(if ipv6 { 1452 } else { 1472 }));
        assert_eq!(service.snapshot(b), Ok(read_n));
        assert_eq!(service.dirty_clients().collect::<Vec<_>>(), vec![a, b]);
        // Read N, accept another older-version submission's network decrease,
        // then ack N. Neither consumer can erase N+1 with its old read.
        assert_eq!(
            service.trusted_decrease(retained_submission_path, 1460),
            Ok(EstimateChange::Decreased)
        );
        service.acknowledge(a, read_n.stamp()).unwrap();
        assert!(service.is_dirty(a).unwrap());
        let newest = clean(&mut service, a);
        assert_eq!(newest.learned_mtu(), Some(1460));
        assert_eq!(service.dirty_clients().collect::<Vec<_>>(), vec![b]);
        service.acknowledge(b, read_n.stamp()).unwrap();
        assert!(service.is_dirty(b).unwrap());
        clean(&mut service, b);
        let state = (service.revision(), service.usage(), service.snapshot(a));
        for candidate in [1460, 1492, 9001] {
            assert_eq!(
                service.trusted_decrease(initial.path(), candidate),
                Ok(EstimateChange::Unchanged)
            );
        }
        for candidate in [
            0,
            if ipv6 { 1279 } else { 67 },
            if ipv6 { 65576 } else { 65536 },
        ] {
            assert_eq!(
                service.trusted_decrease(initial.path(), candidate),
                Err(Error::InvalidArgument)
            );
        }
        assert_eq!(
            (service.revision(), service.usage(), service.snapshot(a)),
            state
        );
        assert_eq!(service.dirty_clients().count(), 0);
        assert_eq!(service.link(link).unwrap().mtu, 9001);
        assert_eq!(service.route(parent), Ok(parent_before));
        // Per-host learning never changes network/default forwarding entries.
        let (_, other_host) = service
            .acquire(PathRequest {
                destination: address(if ipv6 {
                    "2001:db8:1::100"
                } else {
                    "198.51.100.100"
                }),
                ..req
            })
            .unwrap();
        assert_eq!(other_host.learned_mtu(), None);
        assert_eq!(other_host.ip_packet_budget(), Ok(9001));
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
//= type=test
//= reason=T7 PathService keys learned estimates by canonical context, source, destination/scope, routing DSCP, link, next-hop and route generation, excluding ECN and ports. T8 Host binds actual native/TUN TCP owners to these records; public tests preserve source/destination/DSCP/scoped-link isolation. Generic validated ICMP publication remains T9.
//# In general, the IP layer should associate each PMTU value that it has learned with a specific path. A path is identified by a source address, a destination address and an IP type-of-service. (Some implementations do not record the source address of paths; this is acceptable for single-homed hosts, which have only one possible source address.)
fn cached_estimates_are_isolated_by_source_dscp_destination_and_ecn_is_excluded() {
    let (mut service, link, _, req) = setup(8, 12, false, 9001);
    let source = service.register_source(address("192.0.2.2"), link).unwrap();
    let (first, initial) = service.acquire(req).unwrap();
    service.trusted_decrease(initial.path(), 1400).unwrap();
    for ecn in 0..4 {
        let (_, same) = service
            .acquire(PathRequest {
                dscp: Dscp::from_traffic_class(ecn),
                ..req
            })
            .unwrap();
        assert_eq!(same.path(), initial.path());
        assert_eq!(same.learned_mtu(), Some(1400));
    }
    // Ports have no input in this IP service; these are independent client ids.
    let (_, other_source) = service.acquire(PathRequest { source, ..req }).unwrap();
    let (_, other_dscp) = service
        .acquire(PathRequest {
            dscp: Dscp::new(46).unwrap(),
            ..req
        })
        .unwrap();
    let (_, other_host) = service
        .acquire(PathRequest {
            destination: address("198.51.100.100"),
            ..req
        })
        .unwrap();
    for snapshot in [other_source, other_dscp, other_host] {
        assert_ne!(snapshot.path(), initial.path());
        assert_eq!(snapshot.learned_mtu(), None);
        assert_eq!(snapshot.ip_packet_budget(), Ok(9001));
    }
    assert_eq!(service.snapshot(first).unwrap().learned_mtu(), Some(1400));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.3
//= type=test
//= reason=T7 PathService invalidates bound paths on route/source/link changes, including shadowing routes. T8 Host rebinds actual native/TUN TCP owners and gates held physical output; failed rebind preserves dirty authority and bounded backpressure. T9 correlation never lets a stale or invalidated path incarnation change an estimate. ICMP Redirect is decoded as unsupported because no production backend has an IP gateway route: Redirect-driven route changes and their notification are scheduled with the first real Gateway forwarding in T18 (topology evidence T19); full cross-protocol physical races remain T10.
//# PMTU estimates may disappear from the routing table if the per-host routes are removed; this can happen in response to an ICMP Redirect message, or because certain routing-table daemons delete old routes after several minutes. Also, on a multi-homed host a topology change may result in the use of a different source interface. When this happens, if the packetization layer is not notified then it may continue to use a cached PMTU value that is now too small. One solution is to notify the packetization layer of a possible PMTU change whenever a Redirect message causes a route change, and whenever a route is simply deleted from the routing table.
fn every_route_mutation_reconsiders_pinned_paths_including_live_shadowed_routes() {
    // add more-specific; add cheaper; replace alternative to cheaper; replace
    // chosen route; remove chosen route; replace whole table (even same text).
    for operation in 0..6 {
        let (mut service, link, parent, req) = setup(4, 4, false, 9001);
        let b = service.register_link(InterfaceKey(2), 1500).unwrap();
        let alternate = service.add_route(route(b, "0.0.0.0", 0, 200)).unwrap();
        let (a, original) = service.acquire(req).unwrap();
        let (sibling, _) = service.acquire(req).unwrap();
        service.trusted_decrease(original.path(), 1300).unwrap();
        let before = clean(&mut service, a);
        clean(&mut service, sibling);
        let unaffected_req = PathRequest {
            destination: address("203.0.113.1"),
            ..req
        };
        let (other, other_before) = service.acquire(unaffected_req).unwrap();
        clean(&mut service, other);
        match operation {
            0 => {
                service
                    .add_route(route(b, "198.51.100.0", 24, 100))
                    .unwrap();
            }
            1 => {
                service.add_route(route(b, "0.0.0.0", 0, 50)).unwrap();
            }
            2 => {
                service
                    .replace_route(alternate, route(b, "0.0.0.0", 0, 50))
                    .unwrap();
            }
            3 => {
                service
                    .replace_route(
                        parent,
                        Route {
                            next_hop: NextHop::Gateway(address("192.0.2.254")),
                            ..route(link, "0.0.0.0", 0, 100)
                        },
                    )
                    .unwrap();
            }
            4 => {
                service.remove_route(parent).unwrap();
            }
            5 => {
                service
                    .replace_routes(&[route(b, "0.0.0.0", 0, 100)])
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let reason = if operation < 3 {
            InvalidationReason::SelectionChanged
        } else {
            InvalidationReason::RouteRemoved
        };
        let invalidated = invalid(&service, a, before, reason);
        assert_eq!(service.snapshot(sibling), Ok(invalidated));
        if operation == 0 {
            assert_eq!(service.route(parent).unwrap().link, link);
            assert_eq!(service.snapshot(other), Ok(other_before));
            assert!(!service.is_dirty(other).unwrap());
        }
        // Acknowledging an invalidation never grants output authority.
        clean(&mut service, a);
        assert_eq!(
            service.snapshot(a).unwrap().ip_packet_budget(),
            Err(Error::Invalidated)
        );
        assert_eq!(
            service.trusted_decrease(original.path(), 1200),
            Err(Error::Invalidated)
        );
        let (new_client, rebound) = service.rebind(a, req).unwrap();
        assert_ne!(new_client, a);
        assert_eq!(service.snapshot(a), Err(Error::StaleHandle));
        assert_ne!(rebound.path(), original.path());
        assert_eq!(rebound.learned_mtu(), None);
        assert_eq!(
            rebound.first_hop_mtu(),
            if operation == 3 { 9001 } else { 1500 }
        );
        assert_eq!(service.path_pins(original.path()), Ok(1));
        assert_eq!(
            service.acknowledge(new_client, before.stamp()),
            Err(Error::InvalidArgument)
        );
        assert!(service.is_dirty(new_client).unwrap());
        service.release(sibling).unwrap();
        assert_eq!(service.path_pins(original.path()), Ok(0));
    }
}

#[test]
fn invalidation_is_sticky_even_when_the_original_default_becomes_best_again() {
    let (mut service, link, _, req) = setup(2, 2, false, 1500);
    let (client, old) = service.acquire(req).unwrap();
    clean(&mut service, client);
    let shadow = service
        .add_route(route(link, "198.51.100.99", 32, 0))
        .unwrap();
    let invalidated = service.snapshot(client).unwrap();
    service.remove_route(shadow).unwrap();
    assert_eq!(service.resolve(req).unwrap().key(), old.key());
    assert_eq!(service.snapshot(client), Ok(invalidated));
    let (_, new) = service.rebind(client, req).unwrap();
    assert_eq!(new.key(), old.key());
    assert_ne!(new.path(), old.path());
}

#[test]
fn source_ownership_and_link_deletion_only_revoke_lost_authority() {
    for ipv6 in [false, true] {
        for remove_link in [false, true] {
            let (mut service, a, _, req) = setup(6, 6, ipv6, 1500);
            let b = service.register_link(InterfaceKey(2), 9001).unwrap();
            let address = service.source_address(req.source).unwrap();
            assert_eq!(service.register_source(address, b), Ok(req.source));
            // Route egress b is independent from ownership a/b for global IPs.
            service
                .replace_routes(&[route(b, if ipv6 { "::" } else { "0.0.0.0" }, 0, 0)])
                .unwrap();
            let unrelated_source = service.register_source(super_address(ipv6), b).unwrap();
            let (client, initial) = service.acquire(req).unwrap();
            let (other, other_initial) = service
                .acquire(PathRequest {
                    source: unrelated_source,
                    ..req
                })
                .unwrap();
            clean(&mut service, client);
            clean(&mut service, other);
            if remove_link {
                service.remove_link(a).unwrap();
            } else {
                service.remove_source_owner(req.source, a).unwrap();
            }
            assert_eq!(service.snapshot(client), Ok(initial));
            assert!(!service.is_dirty(client).unwrap());
            service.remove_source_owner(req.source, b).unwrap();
            invalid(&service, client, initial, InvalidationReason::SourceRemoved);
            assert_eq!(service.snapshot(other), Ok(other_initial));
            assert!(!service.is_dirty(other).unwrap());
            let recreated = service.register_source(address, b).unwrap();
            assert_ne!(recreated, req.source);
            assert_eq!(service.rebind(client, req), Err(Error::StaleHandle));
            let (_, new) = service
                .rebind(
                    client,
                    PathRequest {
                        source: recreated,
                        ..req
                    },
                )
                .unwrap();
            assert_ne!(new.path(), initial.path());
            // Removing the egress link invalidates the unrelated path too.
            service.remove_link(b).unwrap();
            assert!(matches!(
                service.snapshot(other).unwrap().status(),
                PathStatus::Invalidated(_)
            ));
        }
    }
}
fn super_address(ipv6: bool) -> ScopedAddress {
    address(if ipv6 { "2001:db8::2" } else { "192.0.2.2" })
}

#[test]
fn egress_link_removal_and_recreation_never_reuses_a_bound_path() {
    let (mut service, a, _, req) = setup(3, 3, false, 1500);
    let b = service.register_link(InterfaceKey(2), 1492).unwrap();
    let selected = service.add_route(route(b, "198.51.100.0", 24, 0)).unwrap();
    let (client, initial) = service.acquire(req).unwrap();
    service.trusted_decrease(initial.path(), 1400).unwrap();
    let before = clean(&mut service, client);
    service.remove_link(b).unwrap();
    invalid(&service, client, before, InvalidationReason::LinkRemoved);
    assert_eq!(service.route(selected), Err(Error::StaleHandle));
    let recreated = service.register_link(InterfaceKey(2), 1492).unwrap();
    assert_ne!(b, recreated);
    service
        .add_route(route(recreated, "198.51.100.0", 24, 0))
        .unwrap();
    let (_, new) = service.rebind(client, req).unwrap();
    assert_eq!(new.key().link(), recreated);
    assert_eq!(new.learned_mtu(), None);
    assert_eq!(service.link(a).unwrap().mtu, 1500);
}

#[test]
fn physical_link_admin_changes_refresh_every_user_without_erasing_learned_facts() {
    for ipv6 in [false, true] {
        let (mut service, link, _, req) = setup(3, 4, ipv6, 9001);
        let (a, first) = service.acquire(req).unwrap();
        let (b, _) = service.acquire(req).unwrap();
        let (c, _) = service
            .acquire(PathRequest {
                destination: address(if ipv6 {
                    "2001:db8:1::100"
                } else {
                    "198.51.100.100"
                }),
                ..req
            })
            .unwrap();
        service.trusted_decrease(first.path(), 1400).unwrap();
        for client in [a, b, c] {
            clean(&mut service, client);
        }
        for (mtu, learned_budget, unlearned_budget) in [
            (1280, 1280, 1280),
            (9001, 1400, 9001),
            (100_000, 1400, if ipv6 { 65575 } else { 65535 }),
        ] {
            let old = service.snapshot(a).unwrap();
            service.set_link_mtu(link, mtu).unwrap();
            for client in [a, b, c] {
                let now = service.snapshot(client).unwrap();
                assert!(service.is_dirty(client).unwrap());
                assert_eq!(now.first_hop_mtu(), mtu);
                assert_eq!(now.status(), PathStatus::Valid);
                assert!(now.version() > old.version());
                clean(&mut service, client);
            }
            let learned = service.snapshot(a).unwrap();
            assert_eq!(learned.path(), first.path());
            assert_eq!(learned.learned_mtu(), Some(1400));
            assert_eq!(learned.ip_packet_budget(), Ok(learned_budget));
            assert_eq!(
                service.snapshot(c).unwrap().ip_packet_budget(),
                Ok(unlearned_budget)
            );
        }
    }
}

#[test]
fn initial_nondecreasing_feedback_preserves_unlearned_state_and_administrative_growth() {
    for ipv6 in [false, true] {
        for (initial_mtu, exposed_mtu) in [(1500, 1500), (1280, 1500), (100_000, 100_000)] {
            for masked in [false, true] {
                let (mut service, link, _, req) = setup(1, 2, ipv6, initial_mtu);
                let (a, initial) = service.acquire(req).unwrap();
                let (b, _) = service.acquire(req).unwrap();
                // Growth before feedback exposes a larger network estimate.
                service.set_link_mtu(link, exposed_mtu).unwrap();
                let estimate = service.snapshot(a).unwrap().ip_packet_budget().unwrap();
                if masked {
                    service.set_link_mtu(link, 1280).unwrap();
                }
                clean(&mut service, a);
                let before = clean(&mut service, b);
                let revision = service.revision();
                let usage = service.usage();
                let wire_ceiling = if ipv6 { 65575 } else { 65535 };
                for candidate in [
                    estimate,
                    estimate.saturating_add(1).min(wire_ceiling),
                    wire_ceiling,
                ] {
                    assert_eq!(
                        service.trusted_decrease(initial.path(), candidate),
                        Ok(EstimateChange::Unchanged)
                    );
                    assert_eq!(service.revision(), revision);
                    assert_eq!(service.usage(), usage);
                    assert_eq!(service.path_pins(initial.path()), Ok(2));
                    for client in [a, b] {
                        assert_eq!(service.snapshot(client), Ok(before));
                        assert_eq!(service.is_dirty(client), Ok(false));
                    }
                    assert_eq!(service.dirty_clients().count(), 0);
                }
                // Feedback that never lowered the estimate must not cap growth.
                service.set_link_mtu(link, 100_001).unwrap();
                let grown = service.snapshot(a).unwrap();
                assert_eq!(grown.path(), initial.path());
                assert_eq!(grown.learned_mtu(), None);
                assert_eq!(grown.ip_packet_budget(), Ok(wire_ceiling));
                assert_eq!(service.snapshot(b), Ok(grown));
                assert_eq!(service.dirty_clients().collect::<Vec<_>>(), vec![a, b]);
                // The newly exposed budget can subsequently be lowered.
                assert_eq!(
                    service.trusted_decrease(initial.path(), 9001),
                    Ok(EstimateChange::Decreased)
                );
                assert_eq!(service.snapshot(a).unwrap().learned_mtu(), Some(9001));
            }
        }
    }
}

#[test]
fn older_submission_feedback_during_link_reduction_retains_the_lower_network_ceiling() {
    for ipv6 in [false, true] {
        for prior_estimate in [None, Some(1400)] {
            let (mut service, link, parent, req) = setup(1, 2, ipv6, 1500);
            let (a, submitted) = service.acquire(req).unwrap();
            let (b, _) = service.acquire(req).unwrap();
            let parent_before = service.route(parent).unwrap();
            if let Some(estimate) = prior_estimate {
                service.trusted_decrease(submitted.path(), estimate).unwrap();
            }
            service.set_link_mtu(link, 1280).unwrap();
            let masked = clean(&mut service, a);
            clean(&mut service, b);
            let usage = service.usage();
            assert_eq!(masked.learned_mtu(), prior_estimate);
            assert_eq!(masked.ip_packet_budget(), Ok(1280));

            // The later host validates feedback for an older physical submission.
            // Its unchanged path generation remains useful while the current
            // physical MTU masks this new, independently retained network fact.
            assert_eq!(
                service.trusted_decrease(submitted.path(), 1300),
                Ok(EstimateChange::Decreased)
            );
            let learned = service.snapshot(a).unwrap();
            assert_eq!(learned.path(), submitted.path());
            assert_eq!(learned.key(), submitted.key());
            assert_eq!(learned.status(), PathStatus::Valid);
            assert_eq!(learned.first_hop_mtu(), 1280);
            assert_eq!(learned.link_version(), masked.link_version());
            assert_eq!(learned.learned_mtu(), Some(1300));
            assert_eq!(learned.ip_packet_budget(), Ok(1280));
            assert!(learned.version() > masked.version());
            assert_eq!(service.snapshot(b), Ok(learned));
            assert_eq!(service.dirty_clients().collect::<Vec<_>>(), vec![a, b]);
            for client in [a, b] {
                service.acknowledge(client, masked.stamp()).unwrap();
                assert!(service.is_dirty(client).unwrap());
                clean(&mut service, client);
            }
            let revision = service.revision();
            for candidate in [1300, 1400, 1500] {
                assert_eq!(
                    service.trusted_decrease(submitted.path(), candidate),
                    Ok(EstimateChange::Unchanged)
                );
            }
            assert_eq!(service.revision(), revision);
            assert_eq!(service.snapshot(a), Ok(learned));
            assert_eq!(service.dirty_clients().count(), 0);

            service.set_link_mtu(link, 1500).unwrap();
            let grown = service.snapshot(a).unwrap();
            assert_eq!(grown.path(), submitted.path());
            assert_eq!(grown.key(), submitted.key());
            assert_eq!(grown.status(), PathStatus::Valid);
            assert_eq!(grown.first_hop_mtu(), 1500);
            assert_eq!(grown.learned_mtu(), Some(1300));
            assert_eq!(grown.ip_packet_budget(), Ok(1300));
            assert!(grown.version() > learned.version());
            assert_eq!(service.snapshot(b), Ok(grown));
            assert_eq!(service.dirty_clients().collect::<Vec<_>>(), vec![a, b]);
            assert_eq!(service.usage(), usage);
            assert_eq!(service.path_pins(submitted.path()), Ok(2));
            assert_eq!(service.route(parent), Ok(parent_before));
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
//= type=test
//= reason=T7 PathService maintains bounded per-host resolved routing records with independent learned estimates and exact first-hop authority. Every acquired active destination is pinned by its clients; capacity exhaustion preserves active records, and deterministic idle eviction uses fresh generations. Public tests exercise shared pinning, full-cache backpressure, idle reuse and repeated release cycles. ICMP Redirect processing remains a separate T9 producer obligation.
//# The obvious place to store this association is as a field in the routing table entries. A host will not have a route for every possible destination, but it should be able to cache a per-host route for every active destination. (This requirement is already imposed by the need to process ICMP Redirect messages.)
fn active_pinning_full_cache_atomic_rebind_idle_eviction_and_stale_handles() {
    let (mut service, link, _, req) = setup(1, 3, false, 1500);
    let (a, original) = service.acquire(req).unwrap();
    let (b, _) = service.acquire(req).unwrap();
    service.trusted_decrease(original.path(), 1400).unwrap();
    clean(&mut service, a);
    clean(&mut service, b);
    let different = PathRequest {
        destination: address("198.51.100.100"),
        ..req
    };
    let state = (
        service.usage(),
        service.revision(),
        service.snapshot(a),
        service.is_dirty(a),
    );
    assert_eq!(service.acquire(different), Err(Error::Capacity));
    assert_eq!(service.rebind(a, different), Err(Error::Capacity));
    assert_eq!(
        (
            service.usage(),
            service.revision(),
            service.snapshot(a),
            service.is_dirty(a)
        ),
        state
    );
    assert_eq!(service.path_pins(original.path()), Ok(2));
    let shadow = service
        .add_route(route(link, "198.51.100.0", 24, 0))
        .unwrap();
    let pending = service.snapshot(a).unwrap();
    let state = (
        service.usage(),
        service.revision(),
        service.snapshot(a),
        service.is_dirty(a),
    );
    assert_eq!(service.rebind(a, req), Err(Error::Capacity));
    assert_eq!(
        (
            service.usage(),
            service.revision(),
            service.snapshot(a),
            service.is_dirty(a)
        ),
        state
    );
    assert_eq!(service.path_pins(original.path()), Ok(2));
    service.release(b).unwrap();
    assert_eq!(service.release(b), Err(Error::StaleHandle));
    assert_eq!(service.path_pins(original.path()), Ok(1));
    assert_eq!(service.rebind(a, req), Err(Error::Capacity));
    service.release(a).unwrap();
    // Only explicit release frees the final pin; the now idle invalidated slot
    // can be reused with a fresh path and client incarnation.
    let (new_client, new) = service.acquire(req).unwrap();
    assert_ne!(new_client, a);
    assert_ne!(new.path(), original.path());
    assert_eq!(new.key().route(), shadow);
    assert_eq!(new.learned_mtu(), None);
    assert_eq!(
        service.path_snapshot(original.path()),
        Err(Error::StaleHandle)
    );
    assert_eq!(
        service.acknowledge(new_client, pending.stamp()),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        service.trusted_decrease(original.path(), 1200),
        Err(Error::StaleHandle)
    );
    assert_eq!(service.release(a), Err(Error::StaleHandle));
    assert_eq!(service.path_pins(new.path()), Ok(1));
}

#[test]
fn client_capacity_failures_do_not_evict_idle_paths_or_lose_metadata() {
    let (mut service, _, _, req) = setup(2, 1, false, 1500);
    let (a, old) = service.acquire(req).unwrap();
    service.trusted_decrease(old.path(), 1400).unwrap();
    service.release(a).unwrap();
    let other_req = PathRequest {
        destination: address("203.0.113.1"),
        ..req
    };
    let (other, other_path) = service.acquire(other_req).unwrap();
    let before = (
        service.usage(),
        service.revision(),
        service.snapshot(other),
        service.is_dirty(other),
    );
    for _ in 0..64 {
        assert_eq!(service.acquire(req), Err(Error::Capacity));
        assert_eq!(
            (
                service.usage(),
                service.revision(),
                service.snapshot(other),
                service.is_dirty(other)
            ),
            before
        );
        assert_eq!(
            service.path_snapshot(old.path()).unwrap().learned_mtu(),
            Some(1400)
        );
    }
    // Rebinding reuses the client slot at client capacity, preserving cached
    // network facts and incrementing the binding generation.
    let (new, cached) = service.rebind(other, req).unwrap();
    assert_ne!(new, other);
    assert_eq!(cached.path(), old.path());
    assert_eq!(cached.learned_mtu(), Some(1400));
    assert_eq!(service.path_pins(old.path()), Ok(1));
    assert_eq!(service.path_pins(other_path.path()), Ok(0));
    assert_eq!(service.release(other), Err(Error::StaleHandle));
}

#[test]
fn deterministic_idle_eviction_and_repeated_lifecycle_has_no_pin_or_client_leaks() {
    let (mut service, _, _, req) = setup(2, 2, false, 1500);
    let (a, first) = service.acquire(req).unwrap();
    let (b, second) = service
        .acquire(PathRequest {
            destination: address("203.0.113.1"),
            ..req
        })
        .unwrap();
    service.release(a).unwrap();
    service.release(b).unwrap();
    for n in 1..=100 {
        let request = PathRequest {
            destination: address(&format!("198.18.0.{n}")),
            ..req
        };
        let (client, snapshot) = service.acquire(request).unwrap();
        assert_eq!(service.usage().paths, 2);
        assert_eq!(service.usage().clients, 1);
        assert_eq!(service.path_pins(snapshot.path()), Ok(1));
        assert_eq!(service.path_snapshot(second.path()), Ok(second));
        assert_eq!(service.path_snapshot(first.path()), Err(Error::StaleHandle));
        service.trusted_decrease(snapshot.path(), 1300).unwrap();
        service.release(client).unwrap();
        assert_eq!(service.usage().clients, 0);
        assert_eq!(service.path_pins(snapshot.path()), Ok(0));
        assert_eq!(service.is_dirty(client), Err(Error::StaleHandle));
    }
}

#[test]
fn zero_and_overflowing_path_client_capacities_are_checked() {
    for (paths, clients) in [(0, 1), (1, 0), (0, 0)] {
        let (mut service, _, _, req) = setup(paths, clients, false, 1500);
        let before = (service.usage(), service.revision());
        assert_eq!(service.acquire(req), Err(Error::Capacity));
        assert_eq!((service.usage(), service.revision()), before);
    }
    for (paths, clients) in [(usize::MAX, 0), (0, usize::MAX)] {
        assert!(matches!(
            PathService::new(ContextId::new(1), limits(paths, clients)),
            Err(Error::Capacity)
        ));
    }
}

#[test]
fn complete_header_budgets_mms_s_and_query_caps_have_independent_expected_values() {
    for (ipv6, mtu, mms, cases) in [
        (
            false,
            1500,
            1480,
            vec![
                (20, 20, 1460),
                (60, 20, 1420),
                (60, 60, 1380),
                (24, 32, 1444),
            ],
        ),
        (
            true,
            1500,
            1460,
            vec![
                (40, 20, 1440),
                (48, 20, 1432),
                (64, 32, 1404),
                (80, 60, 1360),
            ],
        ),
        (false, 68, 48, vec![(20, 20, 28), (60, 8, 0)]),
        (true, 1280, 1240, vec![(40, 20, 1220), (80, 60, 1140)]),
        (
            false,
            100_000,
            65515,
            vec![(20, 20, 65495), (60, 60, 65415)],
        ),
        (true, 100_000, 65535, vec![(40, 20, 65515), (80, 60, 65435)]),
    ] {
        let (mut service, _, _, req) = setup(1, 1, ipv6, mtu);
        let (client, snapshot) = service.acquire(req).unwrap();
        clean(&mut service, client);
        assert_eq!(snapshot.first_hop_mtu(), mtu);
        assert_eq!(snapshot.mms_s(), Ok(mms));
        for (ip, transport, expected) in cases {
            assert_eq!(snapshot.payload_budget(ip, transport, None), Ok(expected));
            assert_eq!(
                snapshot.payload_budget(ip, transport, Some(1000)),
                Ok(expected.min(1000))
            );
            assert_eq!(snapshot.payload_budget(ip, transport, Some(0)), Ok(0));
        }
        for (ip, transport) in if ipv6 {
            vec![(20, 20), (39, 20), (41, 20), (40, u32::MAX), (65576, 20)]
        } else {
            vec![(0, 20), (19, 20), (21, 20), (64, 20), (20, u32::MAX)]
        } {
            assert_eq!(
                snapshot.payload_budget(ip, transport, None),
                Err(Error::InvalidArgument)
            );
        }
        assert_eq!(
            snapshot.payload_budget(if ipv6 { 40 } else { 20 }, mtu, None),
            Err(Error::InvalidArgument)
        );
        assert_eq!(service.snapshot(client), Ok(snapshot));
        assert!(!service.is_dirty(client).unwrap());
    }
}

#[test]
fn scoped_paths_foreign_context_and_binding_acknowledgements_stay_isolated() {
    let mut service = PathService::new(ContextId::new(200), limits(4, 4)).unwrap();
    let mut clients = Vec::new();
    for i in 1..=2 {
        let link = service.register_link(InterfaceKey(i), 1500).unwrap();
        let scoped = |text: &str| ScopedAddress::new(text.parse().unwrap(), Some(link)).unwrap();
        let source = service.register_source(scoped("fe80::1"), link).unwrap();
        service.add_route(route(link, "fe80::", 64, 0)).unwrap();
        let req = PathRequest {
            source,
            destination: scoped("fe80::99"),
            dscp: Dscp::new(0).unwrap(),
        };
        let pair = service.acquire(req).unwrap();
        clean(&mut service, pair.0);
        clients.push(pair);
    }
    let [(a, first), (b, second)] = clients[..] else {
        unreachable!()
    };
    service.trusted_decrease(first.path(), 1280).unwrap();
    assert_eq!(service.snapshot(b), Ok(second));
    assert!(!service.is_dirty(b).unwrap());
    assert_eq!(
        service.acknowledge(a, second.stamp()),
        Err(Error::InvalidArgument)
    );
    assert!(service.is_dirty(a).unwrap());
    let (mut foreign, _, _, req) = setup(1, 1, true, 1500);
    let (other, snapshot) = foreign.acquire(req).unwrap();
    for result in [service.release(other), foreign.release(a)] {
        assert_eq!(result, Err(Error::ForeignContext));
    }
    assert_eq!(
        service.path_snapshot(snapshot.path()),
        Err(Error::ForeignContext)
    );
    assert_eq!(
        service.trusted_decrease(snapshot.path(), 1280),
        Err(Error::ForeignContext)
    );
    assert_eq!(
        service.acknowledge(a, snapshot.stamp()),
        Err(Error::InvalidArgument)
    );
    assert_eq!(service.path_pins(first.path()), Ok(1));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
//= type=test
//= reason=T7 PathService stores per-host learned estimates and the legacy plateau fallback without changing first-hop routes; T8 Host binds actual native/TUN TCP owners. T9 Host ICMP dispatch derives the estimate from a nonzero Next-Hop MTU or the RFC1191 section5 plateau below the corrected quoted length, requires correlation with committed submission evidence, and lowers the bound per-host record only when lower (immediate TCP decreases, UDP and path-level reports; real router PTBs in the isolated namespace gate). Stale or evicted path incarnations are never resurrected or changed. Remaining T10: a TCP report deferred below proven delivery is held connection-locally and never reaches the shared record, so the routing entry is not changed for it.
//# When a Datagram Too Big message is received, the ICMP layer determines a new estimate for the Path MTU (either from a non-zero Next-Hop MTU value in the packet, or using the method described in section 5). If a per-host route for this path does not exist, then one is created (almost as if a per-host ICMP Redirect is being processed; the new route uses the same first-hop router as the current route). If the PMTU estimate associated with the per-host route is higher than the new estimate, then the value in the routing entry is changed.
//= https://www.rfc-editor.org/rfc/rfc1191#section-7
//= type=test
//= reason=T7 canonical bounded16 IPv4 policy selects nine contemporary values from AWS EC2 and Google VPC MTU documentation, RFC2516 PPPoE and RFC791 wire/fallback/floor limits. PathService defaults to this compact policy and atomically replaces validated tables at runtime without source changes; public tests exercise historical/custom/contemporary replacement and fallback. The low-level ntcp adapter preserves historical defaults and Error compatibility. Owner-authorized utility integration is independently T12, not a prerequisite imposed by this example ioctl advice.
//# We do not expect that the values in the table, especially for higher MTU levels, are going to be valid forever. The values given here are an implementation suggestion, NOT a specification or requirement. Implementors should use up-to-date references to pick a set of plateaus; it is important that the table not contain too many entries or the process of searching for a PMTU might waste Internet resources. Implementors should also make it convenient for customers without source code to update the table values in their systems (for example, the table in a BSD-derived Unix kernel could be changed using a new "ioctl" command).
fn live_policy_replacement_notifies_ipv4_only_and_preserves_all_learned_estimates() {
    let (mut service, link, _, req) = setup(4, 4, false, 9001);
    let v6 = service
        .register_source(address("2001:db8::1"), link)
        .unwrap();
    service.add_route(route(link, "::", 0, 0)).unwrap();
    let (a, initial) = service.acquire(req).unwrap();
    let (b, _) = service.acquire(req).unwrap();
    let (other, _) = service
        .acquire(PathRequest {
            source: v6,
            destination: address("2001:db8::2"),
            ..req
        })
        .unwrap();
    service.trusted_decrease(initial.path(), 1500).unwrap();
    for client in [a, b, other] {
        clean(&mut service, client);
    }
    let v6_before = service.snapshot(other).unwrap();
    for table in [
        Ipv4Plateaus::RFC1191,
        Ipv4Plateaus::new(&[9001, 1500, 1400, 68]).unwrap(),
        Ipv4Plateaus::CONTEMPORARY,
    ] {
        let before = service.snapshot(a).unwrap();
        service.set_ipv4_plateaus(table).unwrap();
        for client in [a, b] {
            let now = service.snapshot(client).unwrap();
            assert_eq!(now.path(), initial.path());
            assert_eq!(now.learned_mtu(), Some(1500));
            assert_eq!(now.ipv4_plateaus(), Some(table));
            assert!(now.version() > before.version());
            assert!(service.is_dirty(client).unwrap());
            service.acknowledge(client, before.stamp()).unwrap();
            assert!(service.is_dirty(client).unwrap());
            clean(&mut service, client);
        }
        assert_eq!(service.snapshot(other), Ok(v6_before));
        assert!(!service.is_dirty(other).unwrap());
        let revision = service.revision();
        service.set_ipv4_plateaus(table).unwrap();
        assert_eq!(service.revision(), revision);
        assert_eq!(service.dirty_clients().count(), 0);
    }
    assert_eq!(
        service.trusted_ipv4_fallback(initial.path(), 1500, 20, 1500),
        Ok(EstimateChange::Decreased)
    );
    assert_eq!(service.snapshot(a).unwrap().learned_mtu(), Some(1460));
    assert_eq!(service.snapshot(a), service.snapshot(b));
    assert_eq!(
        service.trusted_ipv4_fallback(v6_before.path(), 1500, 20, 1500),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn failed_authority_transactions_preserve_notifications_versions_and_pins() {
    let (mut service, link, id, req) = setup(2, 2, false, 1500);
    let (client, initial) = service.acquire(req).unwrap();
    clean(&mut service, client);
    let definition = service.route(id).unwrap();
    let invalid_route = Route {
        next_hop: NextHop::Gateway(address("2001:db8::ff")),
        ..definition
    };
    let before = (
        service.revision(),
        service.usage(),
        service.snapshot(client),
    );
    let unrelated = service.register_link(InterfaceKey(2), 1500).unwrap();
    for result in [
        service.replace_routes(&[definition, definition]),
        service.replace_route(id, invalid_route).map(|_| ()),
        service.remove_source_owner(req.source, unrelated),
    ] {
        assert!(result.is_err());
    }
    // Link registration was deliberately successful; its unrelated authority
    // must not dirty this binding. Failed operations themselves changed no path.
    assert_eq!(service.snapshot(client), before.2);
    assert_eq!(service.path_pins(initial.path()), Ok(1));
    assert!(!service.is_dirty(client).unwrap());
    let before = (
        service.revision(),
        service.usage(),
        service.snapshot(client),
    );
    assert_eq!(
        service.replace_routes(&[definition, invalid_route]),
        Err(Error::InvalidArgument)
    );
    assert_eq!(service.set_link_mtu(link, 67), Err(Error::InvalidArgument));
    assert_eq!(
        (
            service.revision(),
            service.usage(),
            service.snapshot(client)
        ),
        before
    );
}
