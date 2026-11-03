use super::*;
use core::net::Ipv4Addr;
use ntcp::{
    ExpectedTimestamps, Ipv4RegistrationError, RegisteredOption, SourceRoute, TimestampRequest,
};

type Peer = (Host, Endpoint, IngressContext);

fn expected(record_route: u8, timestamp: u8) -> ExpectedRegistrations<'static> {
    ExpectedRegistrations {
        record_route: Some(record_route),
        timestamp: Some(ExpectedTimestamps::Count(timestamp)),
    }
}
// Record Route and timestamp-only Timestamp with three records each on the
// direct route: 15 + 16 octets, padded to 32.
fn direct_request() -> OutgoingIpv4Options {
    OutgoingIpv4Options {
        source_route: Some(SourceRoute::new(&[], false).unwrap()),
        record_route_slots: Some(3),
        timestamp: Some(TimestampRequest::Times(3)),
    }
}
fn planned(
    cfg: &EndpointConfig,
    tuple: Tuple,
    request: OutgoingIpv4Options,
    expected: &ExpectedRegistrations<'_>,
) -> ManagedOpenOptions {
    let mut open = options(cfg, 24);
    open.ipv4_options = request;
    open.registration = Some(
        Ipv4RegistrationPlan::new(tuple.local.ip(), tuple.remote.ip(), request, expected).unwrap(),
    );
    open
}
fn registration_error(error: Ipv4RegistrationError) -> Error {
    Error::Endpoint(EndpointError::Registration(error))
}
fn resources(peer: &Peer) -> (usize, usize, path::Usage) {
    (
        peer.0.binding_count(),
        peer.0.lease_count(),
        peer.0.paths().usage(),
    )
}

// Every frame `a` emits carries the planned area at its fixed size: Record
// Route then timestamp-only Timestamp, three slots each, with the origin's
// registration (the test encoder's timestamp is 123) in the first slots and
// the zero initialization of the rest, then zero padding.
fn assert_planned_area(frame: &[u8]) {
    let (ip, header, _, _) = ntcp_ip::quote_header(frame).unwrap();
    let IpAddr::V4(origin) = ip.source else {
        panic!()
    };
    assert_eq!(header, 52);
    assert_eq!(ntcp_ip::checksum(&frame[..header]), 0);
    assert_eq!(&frame[20..23], &[7, 15, 8]);
    assert_eq!(&frame[23..27], &origin.octets());
    assert_eq!(&frame[27..35], &[0; 8]);
    assert_eq!(&frame[35..39], &[68, 16, 9, 0]);
    assert_eq!(&frame[39..43], &123u32.to_be_bytes());
    assert_eq!(&frame[43..52], &[0; 9]);
}

// A planned direct connection from `a` (Record Route and Timestamp, whose
// owner expects the origin and the destination to register) to an
// established child of `b`.
fn planned_pair(cfg: &EndpointConfig, now: &mut u64) -> (Peer, Peer, ConnectionId, ConnectionId) {
    let (local, remote) = addresses(false);
    let mut a = managed(local, 171, cfg.clone());
    let mut b = managed(remote, 172, cfg.clone());
    let listener = b.1.listen(remote, 1).unwrap();
    let open = planned(
        cfg,
        Tuple { local, remote },
        direct_request(),
        &expected(2, 2),
    );
    let id =
        a.1.connect_with_path_provider(0, local, remote, open, &mut a.0)
            .unwrap();
    exchange(&mut a, &mut b, now);
    let child = b.1.accept(listener).unwrap();
    assert_eq!(a.1.state(id).unwrap(), State::Established);
    (a, b, id, child)
}
fn exchange(a: &mut Peer, b: &mut Peer, now: &mut u64) {
    for _ in 0..256 {
        *now += 10;
        let mut work = false;
        if let Some(frame) = emit(&mut a.0, &mut a.1, *now) {
            assert_planned_area(&frame);
            input(&mut b.0, &mut b.1, b.2, *now + 1, &frame, 12);
            work = true;
        }
        if let Some(frame) = emit(&mut b.0, &mut b.1, *now + 2) {
            input(&mut a.0, &mut a.1, a.2, *now + 3, &frame, 24);
            work = true;
        }
        if !work {
            return;
        }
    }
    panic!("planned exchange did not quiesce");
}
fn read_all(peer: &mut Peer, id: ConnectionId, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len + 1];
    assert_eq!(peer.1.read(id, &mut bytes).unwrap(), len);
    bytes.truncate(len);
    bytes
}

//= https://www.rfc-editor.org/rfc/rfc791#section-3.1
//= type=test
//# A recorded route is composed of a series of internet addresses. Each
//# internet address is 32 bits or 4 octets. If the pointer is greater than
//# the length, the recorded route data area is full. The originating host
//# must compose this option with a large enough route data area to hold all
//# the address expected. The size of the option does not change due to
//# adding addresses. The intitial contents of the route data area must be
//# zero.

//= https://www.rfc-editor.org/rfc/rfc791#section-3.1
//= type=test
//# The originating host must compose this option with a large enough
//# timestamp data area to hold all the timestamp information expected. The
//# size of the option does not change due to adding timestamps. The
//# intitial contents of the timestamp data area must be zero or internet
//# address/zero pairs.
#[test]
fn planned_opens_check_the_plan_before_any_path_or_connection_allocation() {
    use Ipv4RegistrationError::*;
    let mut cfg = config(10);
    cfg.ipv4_options_enabled = true;
    let (local, remote) = addresses(false);
    let tuple = Tuple { local, remote };
    let mut a = managed(local, 161, cfg.clone());
    a.1.enable_fast_open().unwrap();
    let direct = direct_request();
    let plan = |request, expected: &ExpectedRegistrations<'_>| {
        Ipv4RegistrationPlan::new(local.ip(), remote.ip(), request, expected).unwrap()
    };
    let hops = [Ipv4Addr::new(192, 0, 2, 9), Ipv4Addr::new(192, 0, 2, 10)];
    let suffix = [hops[0], Ipv4Addr::new(192, 0, 2, 11)];
    // Two listed hops leave room for Record Route alone: the origin, both
    // hops and the destination register, 11 + 19 octets.
    let routed = |hops: &[Ipv4Addr], strict| OutgoingIpv4Options {
        source_route: Some(SourceRoute::new(hops, strict).unwrap()),
        record_route_slots: Some(4),
        timestamp: None,
    };
    let rr_only = ExpectedRegistrations {
        record_route: Some(4),
        timestamp: None,
    };
    let mut rejected = vec![
        (
            OutgoingIpv4Options {
                timestamp: None,
                ..direct
            },
            None,
            MissingExpectation {
                option: RegisteredOption::RecordRoute,
            },
        ),
        (
            OutgoingIpv4Options {
                record_route_slots: None,
                ..direct
            },
            None,
            MissingExpectation {
                option: RegisteredOption::Timestamp,
            },
        ),
        // Another slot count than the plan's.
        (
            OutgoingIpv4Options {
                timestamp: Some(TimestampRequest::Times(4)),
                ..direct
            },
            Some(plan(direct, &expected(2, 2))),
            PlanMismatch,
        ),
        // A plan for another destination.
        (
            direct,
            Some(
                Ipv4RegistrationPlan::new(
                    local.ip(),
                    "192.0.2.3".parse().unwrap(),
                    direct,
                    &expected(2, 2),
                )
                .unwrap(),
            ),
            PlanMismatch,
        ),
    ];
    for strict in [false, true] {
        let stated = Some(plan(routed(&hops, strict), &rr_only));
        // A changed suffix behind the unchanged first hop, or the other
        // strictness, is another route than the plan was stated for.
        rejected.push((routed(&suffix, strict), stated, PlanMismatch));
        rejected.push((routed(&hops, !strict), stated, PlanMismatch));
    }
    let before = resources(&a);
    for (request, registration, error) in rejected {
        let mut open = options(&cfg, 24);
        open.ipv4_options = request;
        open.registration = registration;
        let refused = Err(ManagedError::Endpoint(EndpointError::Registration(error)));
        assert_eq!(
            a.1.connect_with_path_provider(1, local, remote, open, &mut a.0),
            refused
        );
        assert_eq!(
            a.1.connect_fast_open_with_path_provider(
                1,
                local,
                remote,
                &[1; 10],
                open,
                None,
                FastOpenClientPolicy::ApplicationProtected,
                &mut a.0,
            )
            .map(|(id, _)| id),
            refused
        );
        assert_eq!(resources(&a), before, "{request:?}");
        assert!(a.1.connection_id(tuple).is_none());
        assert!(selected(&mut a.1, 1).is_none());
    }

    // An IPv4 plan never describes an IPv6 open.
    let (local6, remote6) = addresses(true);
    let mut v6 = managed(local6, 163, cfg.clone());
    v6.1.enable_fast_open().unwrap();
    let mut open = options(&cfg, 24);
    open.ipv4_options = direct;
    open.registration = Some(plan(direct, &expected(2, 2)));
    let before = resources(&v6);
    let refused = Err(ManagedError::Endpoint(EndpointError::Registration(
        WrongFamily,
    )));
    assert_eq!(
        v6.1.connect_with_path_provider(0, local6, remote6, open, &mut v6.0),
        refused
    );
    assert_eq!(
        v6.1.connect_fast_open_with_path_provider(
            0,
            local6,
            remote6,
            &[1; 10],
            open,
            None,
            FastOpenClientPolicy::ApplicationProtected,
            &mut v6.0,
        )
        .map(|(id, _)| id),
        refused
    );
    assert_eq!(resources(&v6), before);

    // Each accepted planned open, ordinary or Fast Open, binds its plan to
    // the authority selected in its own serialized preparation, and its
    // first segment carries exactly the planned area.
    let mut port = 2000;
    let IpAddr::V4(origin) = local.ip() else {
        panic!()
    };
    let IpAddr::V4(final_peer) = remote.ip() else {
        panic!()
    };
    let visits = [origin, final_peer];
    let addressed = OutgoingIpv4Options {
        timestamp: Some(TimestampRequest::AddressTimes(2)),
        ..direct
    };
    let prespecified = OutgoingIpv4Options {
        timestamp: Some(TimestampRequest::Prespecified {
            addresses: [origin, final_peer, origin, final_peer],
            len: 2,
        }),
        ..direct
    };
    let prespecified_visits = ExpectedRegistrations {
        record_route: Some(2),
        timestamp: Some(ExpectedTimestamps::Prespecified(&visits)),
    };
    for (request, stated) in [
        (direct, expected(2, 2)),
        (addressed, expected(2, 2)),
        (prespecified, prespecified_visits),
        (routed(&hops, false), rr_only),
        (routed(&hops, true), rr_only),
    ] {
        for fast_open in [false, true] {
            port += 1;
            let local = SocketAddr::new(local.ip(), port);
            let open = planned(&cfg, Tuple { local, remote }, request, &stated);
            let id = if fast_open {
                a.1.connect_fast_open_with_path_provider(
                    1,
                    local,
                    remote,
                    &[1; 10],
                    open,
                    None,
                    FastOpenClientPolicy::ApplicationProtected,
                    &mut a.0,
                )
                .unwrap()
                .0
            } else {
                a.1.connect_with_path_provider(1, local, remote, open, &mut a.0)
                    .unwrap()
            };
            let binding = a.0.binding(id).unwrap();
            let registration = a.0.registration(id).unwrap();
            assert_eq!(registration.authorized, binding.snapshot.key());
            assert_eq!(registration.plan, open.registration.unwrap());
            assert_eq!(
                a.0.registration_candidate(&a.1, id),
                Ok(Some(binding.snapshot.key()))
            );
            let (attempt, packet, frame) = selected(&mut a.1, 1).unwrap();
            assert_eq!(packet.connection, Some(id));
            assert_eq!(packet.ipv4_options, request);
            let (ip, header, _, _) = ntcp_ip::quote_header(&frame).unwrap();
            assert_eq!(ip.destination, remote.ip());
            assert_eq!(header, 20 + registration.plan.option_octets());
            let first = request.source_route.unwrap().hops().first().copied();
            assert_eq!(&frame[16..20], &first.unwrap_or(final_peer).octets());
            let context = a.0.egress_context(&mut a.1, attempt).unwrap();
            a.0.validate_egress(&mut a.1, context, &frame, 0).unwrap();
            assert!(a.1.accept_transmit(1, attempt).unwrap());
        }
    }
}

#[test]
fn pmtu_only_changes_keep_the_authorized_route() {
    let mut cfg = config(2);
    cfg.ipv4_options_enabled = true;
    let mut now = 0;
    let (mut a, mut b, id, child) = planned_pair(&cfg, &mut now);
    let authorized = a.0.registration(id).unwrap().authorized;
    let path = a.0.binding(id).unwrap().snapshot.path();
    a.0.set_link_mtu(a.2.link(), 1600).unwrap();
    a.0.trusted_decrease(now, path, 1100).unwrap();
    // As the embeddings' service pass does before selecting output.
    a.0.service_changes(&mut a.1, now).unwrap();
    let payload: Vec<u8> = (0..6000).map(|i| i as u8).collect();
    a.1.write(id, &payload).unwrap();
    exchange(&mut a, &mut b, &mut now);
    let binding = a.0.binding(id).unwrap();
    assert_eq!(binding.snapshot.pmtu_estimate(), Ok(1100));
    assert_eq!(binding.snapshot.key(), authorized);
    assert_eq!(a.0.registration(id).unwrap().authorized, authorized);
    assert_eq!(a.0.registration_candidate(&a.1, id), Ok(Some(authorized)));
    assert_eq!(read_all(&mut b, child, payload.len()), payload);
}

#[test]
fn route_replacement_holds_option_output_until_revalidated_with_fitting_expectations() {
    use Ipv4RegistrationError::InsufficientRecords;
    let mut cfg = config(2);
    cfg.ipv4_options_enabled = true;
    let mut now = 0;
    let (mut a, mut b, id, child) = planned_pair(&cfg, &mut now);
    let authorized = a.0.registration(id).unwrap().authorized;
    let payload: Vec<u8> = (0..4000).map(|i| (i * 7) as u8).collect();
    a.1.write(id, &payload).unwrap();
    // A submitted prefix before the route changes.
    now += 10;
    let prefix = emit(&mut a.0, &mut a.1, now).unwrap();
    assert_planned_area(&prefix);
    input(&mut b.0, &mut b.1, b.2, now + 1, &prefix, 12);
    let progress = a.1.send_progress(id).unwrap();
    let (attempt, packet, frame) = selected(&mut a.1, now + 2).unwrap();
    let context = a.0.egress_context(&mut a.1, attempt).unwrap();
    let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();

    // Replacing the route with identical text mints a new authority.
    let route = authorized.route();
    let replacement =
        a.0.replace_route(route, a.0.paths().route(route).unwrap())
            .unwrap();
    let mut submitted = false;
    let refused =
        a.0.submit(&mut a.1, now + 3, ticket, context, &frame, 0, |_| {
            submitted = true;
            BackendOutcome::Submitted
        })
        .unwrap_err();
    assert_eq!(refused.error, Error::StaleRoute);
    assert!(!submitted);
    assert_eq!(a.1.send_progress(id).unwrap(), progress);
    assert_eq!(a.1.transmit_attempt_packet(attempt), Some(packet));
    // Refresh moved the live path and budget, not the authorization.
    let candidate = a.0.registration_candidate(&a.1, id).unwrap().unwrap();
    assert_eq!(candidate.route(), replacement);
    assert_ne!(candidate, authorized);
    assert_eq!(a.0.binding(id).unwrap().snapshot.key(), candidate);
    assert_eq!(a.0.registration(id).unwrap().authorized, authorized);

    // Expectations beyond the connection's fixed capacities need a new
    // connection; the authorization stays as it was.
    for (stated, option) in [
        (expected(4, 3), RegisteredOption::RecordRoute),
        (expected(3, 4), RegisteredOption::Timestamp),
    ] {
        assert_eq!(
            a.0.revalidate_registration(&mut a.1, id, candidate, &stated),
            Err(registration_error(InsufficientRecords {
                option,
                expected: 4,
                available: 3,
            }))
        );
    }
    assert_eq!(a.0.registration(id).unwrap().authorized, authorized);
    assert_eq!(
        a.0.egress_context(&mut a.1, attempt).err(),
        Some(Error::StaleRoute)
    );
    // The statement must be for the live authority.
    assert_eq!(
        a.0.revalidate_registration(&mut a.1, id, authorized, &expected(3, 3)),
        Err(Error::StaleRoute)
    );
    // A recording router on the new route still fits three records each.
    a.0.revalidate_registration(&mut a.1, id, candidate, &expected(3, 3))
        .unwrap();
    let registration = a.0.registration(id).unwrap();
    assert_eq!(registration.authorized, candidate);
    assert_eq!(registration.plan.options(), &direct_request());

    // Held output recovers through nonsubmission and reselection.
    assert!(a.1.reject_unsubmitted(attempt).unwrap());
    assert_eq!(a.1.send_progress(id).unwrap(), progress);
    let (next, _, frame) = selected(&mut a.1, now + 4).unwrap();
    assert_planned_area(&frame);
    let context = a.0.egress_context(&mut a.1, next).unwrap();
    let resubmitted =
        a.0.submit(
            &mut a.1,
            now + 4,
            refused.ticket,
            context,
            &frame,
            0,
            |_| BackendOutcome::Submitted,
        )
        .unwrap();
    assert!(resubmitted == Submission::Submitted);
    input(&mut b.0, &mut b.1, b.2, now + 5, &frame, 12);
    now += 10;
    exchange(&mut a, &mut b, &mut now);
    assert_eq!(read_all(&mut b, child, payload.len()), payload);
}

#[test]
fn route_removal_reports_stale_route_without_candidate_until_resolution_returns() {
    let mut cfg = config(2);
    cfg.ipv4_options_enabled = true;
    let mut now = 0;
    let (mut a, mut b, id, child) = planned_pair(&cfg, &mut now);
    let authorized = a.0.registration(id).unwrap().authorized;
    let route = a.0.paths().route(authorized.route()).unwrap();
    a.0.remove_route(authorized.route()).unwrap();
    assert_eq!(a.0.registration_candidate(&a.1, id), Ok(None));
    a.1.write(id, b"held").unwrap();
    now += 10;
    let (attempt, _, frame) = selected(&mut a.1, now).unwrap();
    assert_eq!(
        a.0.egress_context(&mut a.1, attempt).err(),
        Some(Error::StaleRoute)
    );
    assert_eq!(
        a.0.revalidate_registration(&mut a.1, id, authorized, &expected(2, 2)),
        Err(Error::StaleRoute)
    );
    // A restored route is a new authority the owner has not yet confirmed.
    let restored = a.0.add_route(route).unwrap();
    let candidate = a.0.registration_candidate(&a.1, id).unwrap().unwrap();
    assert_eq!(candidate.route(), restored);
    assert_ne!(candidate, authorized);
    assert_eq!(
        a.0.egress_context(&mut a.1, attempt).err(),
        Some(Error::StaleRoute)
    );
    a.0.revalidate_registration(&mut a.1, id, candidate, &expected(2, 2))
        .unwrap();
    let context = a.0.egress_context(&mut a.1, attempt).unwrap();
    let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
    let submitted =
        a.0.submit(&mut a.1, now, ticket, context, &frame, 0, |_| {
            BackendOutcome::Submitted
        })
        .unwrap();
    assert!(submitted == Submission::Submitted);
    input(&mut b.0, &mut b.1, b.2, now + 1, &frame, 12);
    exchange(&mut a, &mut b, &mut now);
    assert_eq!(read_all(&mut b, child, 4), b"held");
}
