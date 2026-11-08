// Owner administration: Host-bound capability, query of the three values
// with provenance, read-only candidate validation, and the estimate
// operations (downward restriction with hold; equal, upward and clear change
// no shared estimate).
use super::*;
use path::{
    AdminChange, AdminPolicy, AdminTarget, EffectivePolicy, EstimateProvenance, PolicySource,
};

type Side = (Host, Endpoint, IngressContext);

fn udp_side(local: SocketAddr, identity: u64, cfg: &EndpointConfig) -> Side {
    managed_limited(local, identity, cfg.clone(), false, None, None, |p, l| {
        let (p, l) = managed_udp_limits(
            p,
            l,
            UdpLimits {
                flows: 1,
                receive_datagrams: 1,
                max_payload: 1500,
                events: 1,
                evicted_signatures: 1,
                probe_receipts: 2,
            },
        )
        .unwrap();
        (p, l, 1)
    })
}

#[test]
fn capability_is_bound_to_the_issuing_host_instance() {
    let cfg = config(2);
    let (local, _) = addresses(false);
    // Same ContextId: the capability names the instance, not the context.
    let mut a = managed(local, 9100, cfg.clone());
    let mut b = managed(local, 9100, cfg);
    let foreign = b.0.administration();
    let owner = a.0.administration();
    let route = a.0.admin_routes(&owner).unwrap().next().unwrap().route;
    let change = AdminChange {
        target: AdminTarget::Route(route),
        expected: 0,
        policy: AdminPolicy {
            discovery_disabled: true,
            estimate: None,
        },
    };
    assert_eq!(a.0.admin_routes(&foreign).err(), Some(Error::Unauthorized));
    assert_eq!(a.0.admin_paths(&foreign).err(), Some(Error::Unauthorized));
    assert_eq!(
        a.0.admin_ipv4_plateaus(&foreign),
        Err(Error::Unauthorized)
    );
    assert_eq!(a.0.admin_validate(&foreign, 0, change), Err(Error::Unauthorized));
    // A candidate validated by another Host is not accepted either.
    let route_b = b.0.admin_routes(&foreign).unwrap().next().unwrap().route;
    let candidate_b = b
        .0
        .admin_validate(
            &foreign, 0,
            AdminChange {
                target: AdminTarget::Route(route_b),
                ..change
            },
        )
        .unwrap();
    assert_eq!(a.0.admin_apply(&owner, &mut a.1, candidate_b), Err(Error::Unauthorized));
    let candidate = a.0.admin_validate(&owner, 0, change).unwrap();
    assert_eq!(a.0.admin_apply(&foreign, &mut a.1, candidate), Err(Error::Unauthorized));
    assert_eq!(a.0.paths().admin_revision(), 0);
    assert_eq!(a.0.admin_apply(&owner, &mut a.1, candidate), Ok(1));
    assert_eq!(
        a.0.admin_routes(&owner).unwrap().next().unwrap().policy,
        change.policy
    );
    // Stale compare-and-set: the same candidate cannot be applied twice.
    assert_eq!(
        a.0.admin_apply(&owner, &mut a.1, candidate),
        Err(Error::Path(path::Error::StaleGeneration))
    );
    assert_eq!(
        a.0.admin_validate(&owner, 0, change),
        Err(Error::Path(path::Error::StaleGeneration))
    );
    let _ = &mut b;
}

#[test]
fn query_reports_three_values_and_clients_and_policy_alone_changes_no_estimate() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (local, remote) = addresses(v6);
        let mut a = udp_side(local, 9200 + u64::from(v6), &cfg);
        let mut b = managed(remote, 9300 + u64::from(v6), cfg.clone());
        let listener = b.1.listen(remote, 2).unwrap();
        let tcp = a
            .1
            .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        b.1.accept(listener).unwrap();
        a.1.set_user_mss(tcp, Some(1000)).unwrap();
        let flow = a
            .0
            .udp_open(
                &a.1,
                SocketAddr::new(local.ip(), 5000),
                Some(SocketAddr::new(remote.ip(), 7)),
                UdpOptions {
                    dscp: 0,
                    hop_limit: 64,
                },
            )
            .unwrap();
        let capability = a.0.administration();
        let path = a.0.binding(tcp).unwrap().snapshot.path();
        let route = a.0.binding(tcp).unwrap().snapshot.key().route();
        let prefix = path::IpPrefix::new(
            if v6 { "::" } else { "0.0.0.0" }.parse().unwrap(),
            0,
        )
        .unwrap();
        assert_eq!(a.0.admin_select_route(&capability, prefix), Ok(route));
        let snapshot = a.0.binding(tcp).unwrap().snapshot;
        let revision = a.0.paths().revision();
        // Path overlay and route policy: an upward estimate, a disable.
        for (target, policy) in [
            (
                AdminTarget::Path(path),
                AdminPolicy {
                    discovery_disabled: false,
                    estimate: Some(1500),
                },
            ),
            (
                AdminTarget::Route(route),
                AdminPolicy {
                    discovery_disabled: true,
                    estimate: None,
                },
            ),
        ] {
            let candidate = a
                .0
                .admin_validate(
                    &capability, 0,
                    AdminChange {
                        target,
                        expected: 0,
                        policy,
                    },
                )
                .unwrap();
            let affected: Vec<_> = a.0.admin_affected(&capability, &candidate).unwrap().collect();
            assert_eq!(affected.len(), 1);
            assert_eq!(affected[0].path, path);
            assert_ne!(affected[0].candidate, affected[0].current);
            // Validation is read-only.
            assert_eq!(a.0.admin_path(&capability, path).unwrap().effective, affected[0].current);
            a.0.admin_apply(&capability, &mut a.1, candidate).unwrap();
            assert_eq!(a.0.admin_path(&capability, path).unwrap().effective, affected[0].candidate);
        }
        // No estimate, hold or negative-revision change: each change only
        // delivers the effective policy to the path's clients (one snapshot
        // version each), which the transaction applies at once. On IPv6 the
        // disable caps the packet budget at the minimum link MTU.
        assert_eq!(a.0.paths().revision(), revision + 2);
        let delivered = a.0.paths().path_snapshot(path).unwrap();
        assert_eq!(delivered.learned_mtu(), snapshot.learned_mtu());
        assert_eq!(delivered.retry_not_before(), snapshot.retry_not_before());
        assert_eq!(delivered.negative_revision(), snapshot.negative_revision());
        let budget = snapshot.ip_packet_budget().unwrap();
        assert_eq!(delivered.ip_packet_budget().unwrap(), if v6 { budget.min(1280) } else { budget });
        assert_eq!(delivered.administrative_estimate(), Some(1500));
        assert!(delivered.discovery_disabled());
        assert!(!a.0.paths().is_dirty(a.0.binding(tcp).unwrap().client).unwrap());
        assert_eq!(a.0.binding(tcp).unwrap().snapshot, delivered);
        let report = a.0.service_changes(&mut a.1, now).unwrap();
        assert_eq!((report.applied, report.failed, report.decreased, report.raised), (0, 0, 0, 0));
        let report = a.0.admin_path(&capability, path).unwrap();
        assert_eq!(
            report.effective,
            EffectivePolicy {
                discovery_disabled: Some(PolicySource::Route),
                estimate: Some(path::AdministrativeEstimate {
                    value: 1500,
                    source: PolicySource::Path
                }),
            }
        );
        // Accepted network estimate: first hop, unlearned.
        let accepted = report.accepted.unwrap();
        assert_eq!((accepted.value, accepted.provenance), (1500, EstimateProvenance::Unlearned));
        assert!(!report.policy.is_empty());
        assert_eq!(report.snapshot.learned_mtu(), None);
        // Per-client usable size and transport ceilings, separately.
        let clients: Vec<_> = a.0.admin_clients(&capability, &a.1, path).unwrap().collect();
        assert_eq!(clients.len(), 2);
        assert_eq!(clients[0].client, AdminClient::Tcp(tcp));
        let ceilings = clients[0].transport.unwrap();
        assert_eq!(ceilings.user_mss, Some(1000));
        assert!(ceilings.effective_mss <= 1000);
        // The IPv6 disable caps the connection at the minimum link MTU.
        assert_eq!(clients[0].usable_ip_packet, Some(if v6 { 1280 } else { 1500 }));
        assert_eq!(clients[1].client, AdminClient::Udp(flow));
        assert!(clients[1].transport.is_none());
        assert!(clients[1].usable_ip_packet.unwrap() <= 1500);
        // A value below the accepted estimate is a trusted administrative
        // restriction (covered with its hold arithmetic below).
        let generation = a.0.admin_path(&capability, path).unwrap().generation;
        let candidate = a
            .0
            .admin_validate(
                &capability, now,
                AdminChange {
                    target: AdminTarget::Path(path),
                    expected: generation,
                    policy: AdminPolicy {
                        discovery_disabled: false,
                        estimate: Some(1300),
                    },
                },
            )
            .unwrap();
        a.0.admin_apply(&capability, &mut a.1, candidate).unwrap();
        let report = a.0.admin_path(&capability, path).unwrap();
        assert_eq!(report.accepted.unwrap().value, 1300);
        assert_eq!(report.effective.estimate.unwrap().value, 1300);
        assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), Some(1300));
        assert_eq!(snapshot.learned_mtu(), None);
        // Applied to the binding in the same transaction.
        assert!(!a.0.paths().is_dirty(a.0.binding(tcp).unwrap().client).unwrap());
        assert_eq!(a.0.binding(tcp).unwrap().snapshot.learned_mtu(), Some(1300));
    }
}

pub(super) fn set_estimate(
    side: &mut Side,
    capability: &Administration,
    now: Instant,
    path: path::PathId,
    estimate: Option<u32>,
) -> Result<u64, Error> {
    let expected = side.0.admin_path(capability, path)?.generation;
    let candidate = side.0.admin_validate(
        capability,
        now,
        AdminChange {
            target: AdminTarget::Path(path),
            expected,
            policy: AdminPolicy {
                discovery_disabled: false,
                estimate,
            },
        },
    )?;
    side.0.admin_apply(capability, &mut side.1, candidate)
}

// Every set compares with the accepted network estimate. Downward: the
// accepted estimate falls at once with a fresh negative revision, the hold
// becomes max(old, now + 600 s) and clients are notified through the change
// service. Equal: no revision, no hold restart (unlike a trusted decrease of
// an equal value). Upward: cached only. Clear: holds and the lowered value
// stay. While set, the value caps confirmed growth; hold boundaries use
// caller time.
#[test]
fn administrative_estimate_operations_compare_with_the_accepted_estimate() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (local, remote) = addresses(v6);
        let mut a = managed(local, 9400 + u64::from(v6), cfg.clone());
        let mut b = managed(remote, 9500 + u64::from(v6), cfg.clone());
        let listener = b.1.listen(remote, 2).unwrap();
        let tcp = a
            .1
            .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        b.1.accept(listener).unwrap();
        let capability = a.0.administration();
        let hold = 600 * a.1.caller_timebase().units_per_second;
        let path = a.0.binding(tcp).unwrap().snapshot.path();
        let low = if v6 { 1400 } else { 1200 };

        // Downward, with hold arithmetic checked before anything changes.
        let expected = a.0.admin_path(&capability, path).unwrap().generation;
        let change = AdminChange {
            target: AdminTarget::Path(path),
            expected,
            policy: AdminPolicy {
                discovery_disabled: false,
                estimate: Some(low),
            },
        };
        let before = a.0.paths().revision();
        assert_eq!(
            a.0.admin_validate(&capability, u64::MAX - 1, change),
            Err(Error::Path(path::Error::Exhausted))
        );
        assert_eq!(a.0.paths().revision(), before);
        let at = now + 100;
        let snapshot = a.0.binding(tcp).unwrap().snapshot;
        set_estimate(&mut a, &capability, at, path, Some(low)).unwrap();
        let fresh = a.0.paths().path_snapshot(path).unwrap();
        assert_eq!(fresh.learned_mtu(), Some(low));
        assert_eq!(fresh.retry_not_before(), at + hold);
        assert!(fresh.negative_revision() > snapshot.negative_revision());
        // The transaction notified the connection: nothing left to fan out.
        assert!(!a.0.paths().is_dirty(a.0.binding(tcp).unwrap().client).unwrap());
        assert_eq!(a.0.binding(tcp).unwrap().snapshot, fresh);
        let report = a.0.service_changes(&mut a.1, at).unwrap();
        assert_eq!((report.applied, report.failed), (0, 0));
        assert!(a.1.managed_path(tcp).unwrap().ordinary_ip_budget <= low);
        let report = a.0.admin_path(&capability, path).unwrap().accepted.unwrap();
        assert_eq!((report.value, report.provenance), (low, EstimateProvenance::Learned));

        // Equal to the accepted estimate (another policy, same value): no
        // revision, hold restart or notification.
        let revision = a.0.paths().revision();
        let expected = a.0.admin_path(&capability, path).unwrap().generation;
        let candidate = a
            .0
            .admin_validate(
                &capability,
                at + 50,
                AdminChange {
                    target: AdminTarget::Path(path),
                    expected,
                    policy: AdminPolicy {
                        discovery_disabled: false,
                        estimate: Some(low),
                    },
                },
            )
            .unwrap();
        assert!(candidate.plan().is_noop());
        a.0.admin_apply(&capability, &mut a.1, candidate).unwrap();
        let route = a.0.binding(tcp).unwrap().snapshot.key().route();
        let candidate = a
            .0
            .admin_validate(
                &capability,
                at + 50,
                AdminChange {
                    target: AdminTarget::Route(route),
                    expected: a.0.admin_routes(&capability).unwrap().find(|r| r.route == route).unwrap().generation,
                    policy: AdminPolicy {
                        discovery_disabled: false,
                        estimate: Some(low),
                    },
                },
            )
            .unwrap();
        a.0.admin_apply(&capability, &mut a.1, candidate).unwrap();
        assert_eq!(a.0.paths().revision(), revision);
        assert_eq!(a.0.paths().path_snapshot(path).unwrap().retry_not_before(), at + hold);

        // Upward (path overlay above the accepted estimate, route still at
        // `low`): the combined value stays `low`. Raise the route too.
        let up = 1500;
        let expected = a.0.admin_routes(&capability).unwrap().find(|r| r.route == route).unwrap().generation;
        let candidate = a
            .0
            .admin_validate(
                &capability,
                at + 60,
                AdminChange {
                    target: AdminTarget::Route(route),
                    expected,
                    policy: AdminPolicy::default(),
                },
            )
            .unwrap();
        a.0.admin_apply(&capability, &mut a.1, candidate).unwrap();
        set_estimate(&mut a, &capability, at + 60, path, Some(up)).unwrap();
        let fresh = a.0.paths().path_snapshot(path).unwrap();
        assert_eq!(fresh.learned_mtu(), Some(low));
        assert_eq!(fresh.retry_not_before(), at + hold);
        // Only the administrative value is delivered (a version), no
        // estimate, hold or negative revision change.
        assert_eq!(a.0.paths().revision(), revision + 1);
        assert_eq!(fresh.administrative_estimate(), Some(up));
        assert!(!a.0.paths().is_dirty(a.0.binding(tcp).unwrap().client).unwrap());
        assert_eq!(a.0.binding(tcp).unwrap().snapshot, fresh);
        let report = a.0.admin_path(&capability, path).unwrap();
        assert_eq!(report.accepted.unwrap().value, low);
        assert_eq!(report.effective.estimate.unwrap().value, up);

        // Growth needs delivery evidence after the hold, and never past the
        // administrative value: deterministic caller-time boundaries.
        let negative = fresh.negative_revision();
        let confirm = |a: &mut Side, len, selected, at| {
            a.0.paths.confirm_delivery(path, len, negative, selected, at)
        };
        assert_eq!(confirm(&mut a, low + 20, at + hold - 1, at + hold), Ok(path::DeliveryConfirmation::Held));
        assert_eq!(confirm(&mut a, low + 20, at + hold, at + hold - 1), Ok(path::DeliveryConfirmation::Held));
        set_estimate(&mut a, &capability, at + hold, path, Some(low + 10)).unwrap();
        // That set is upward too (above `low`): cached, no new hold.
        assert_eq!(a.0.paths().path_snapshot(path).unwrap().retry_not_before(), at + hold);
        assert_eq!(confirm(&mut a, low + 20, at + hold, at + hold), Ok(path::DeliveryConfirmation::ExceedsAdministrative));
        assert_eq!(confirm(&mut a, low + 10, at + hold, at + hold), Ok(path::DeliveryConfirmation::Raised));
        assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), Some(low + 10));

        // Clear: the constraint goes; the learned value and hold stay.
        let revision = a.0.paths().revision();
        set_estimate(&mut a, &capability, at + hold + 1, path, None).unwrap();
        let cleared = a.0.paths().path_snapshot(path).unwrap();
        assert_eq!(cleared.learned_mtu(), Some(low + 10));
        assert_eq!(cleared.retry_not_before(), at + hold);
        assert_eq!(cleared.administrative_estimate(), None);
        assert_eq!(a.0.paths().revision(), revision + 1);
        assert!(a.0.admin_path(&capability, path).unwrap().effective.estimate.is_none());

        // A second downward set keeps a later existing hold: max(old, now+hold).
        let late = at + hold + 2;
        a.0.trusted_decrease(late, path, low + 5).unwrap();
        set_estimate(&mut a, &capability, late - hold / 2, path, Some(low)).unwrap();
        let fresh = a.0.paths().path_snapshot(path).unwrap();
        assert_eq!(fresh.learned_mtu(), Some(low));
        assert_eq!(fresh.retry_not_before(), late + hold);
    }
}

// ---- Search transition through real Host connections (caller time) ----

const UP: u32 = 1450;
fn low(v6: bool) -> u32 {
    if v6 { 1400 } else { 1200 }
}

// `pump`, asserting every frame `a` emits is at most `limit` octets.
fn pump_within(a: &mut Side, b: &mut Side, now: &mut u64, limit: usize) {
    for _ in 0..512 {
        *now += 10;
        let mut work = false;
        if let Some(frame) = emit(&mut a.0, &mut a.1, *now) {
            assert!(frame.len() <= limit, "{} > {limit}", frame.len());
            input(&mut b.0, &mut b.1, b.2, *now + 1, &frame, 0);
            work = true;
        }
        if let Some(frame) = emit(&mut b.0, &mut b.1, *now + 2) {
            input(&mut a.0, &mut a.1, a.2, *now + 3, &frame, 0);
            work = true;
        }
        if !work {
            return;
        }
    }
    panic!("wire exchange did not quiesce");
}

// A connected pair whose shared path a router's validated PTB lowered to
// `low` (with its 600-second hold); the repair is delivered at that size.
fn lowered_by_ptb(v6: bool, identity: u64) -> (Side, Side, ConnectionId, u64) {
    let cfg = config(2);
    let (local, remote) = addresses(v6);
    let mut a = managed(local, identity, cfg.clone());
    let mut b = managed(remote, identity + 1, cfg.clone());
    let listener = b.1.listen(remote, 2).unwrap();
    let tcp = a
        .1
        .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
        .unwrap();
    let mut now = 0;
    pump(&mut a, &mut b, &mut now);
    b.1.accept(listener).unwrap();
    a.1.write(tcp, &[1; 1400]).unwrap();
    now += 10;
    let quoted = emit(&mut a.0, &mut a.1, now).unwrap();
    assert!(quoted.len() as u32 > low(v6));
    let report = super::dispatch::ptb(&quoted, low(v6));
    let (_, published) =
        super::dispatch::tcp_report(a.0.input_icmp(&mut a.1, a.2, now + 1, &report, None).unwrap());
    assert_eq!(published, Some(path::EstimateChange::Decreased));
    now += 2;
    assert_eq!(a.0.service_changes(&mut a.1, now).unwrap().failed, 0);
    pump_within(&mut a, &mut b, &mut now, low(v6) as usize);
    assert_eq!(a.1.send_progress(tcp).unwrap().acknowledged, a.1.send_progress(tcp).unwrap().queued_end);
    (a, b, tcp, now)
}

// Network state an upward administrative set must not touch.
#[derive(Debug, PartialEq)]
struct Network {
    accepted: path::AcceptedEstimate,
    learned: Option<u32>,
    hold: u64,
    negative: u64,
    search_low: u32,
    current_mtu: u32,
}
fn network(a: &Side, capability: &Administration, tcp: ConnectionId) -> Network {
    let path = a.0.binding(tcp).unwrap().snapshot.path();
    let snapshot = a.0.paths().path_snapshot(path).unwrap();
    let info = a.1.path_mtu_info(tcp).unwrap().unwrap();
    Network {
        accepted: a.0.admin_path(capability, path).unwrap().accepted.unwrap(),
        learned: snapshot.learned_mtu(),
        hold: snapshot.retry_not_before(),
        negative: snapshot.negative_revision(),
        search_low: info.search_low,
        current_mtu: info.current_mtu,
    }
}
fn client(a: &Side, capability: &Administration, tcp: ConnectionId) -> ClientReport {
    let path = a.0.binding(tcp).unwrap().snapshot.path();
    let clients: Vec<_> = a.0.admin_clients(capability, &a.1, path).unwrap().collect();
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0].client, AdminClient::Tcp(tcp));
    clients[0]
}
fn three_values(a: &Side, capability: &Administration, tcp: ConnectionId) -> (Option<u32>, u32, Option<u32>) {
    let path = a.0.binding(tcp).unwrap().snapshot.path();
    let admin = a.0.admin_path(capability, path).unwrap();
    (
        admin.effective.estimate.map(|e| e.value),
        admin.accepted.unwrap().value,
        client(a, capability, tcp).usable_ip_packet,
    )
}

// Run the connection's due timers (its local PTB hold among them) at `now`.
fn expire(a: &mut Side, now: u64) {
    while a.1.next_deadline().is_some_and(|d| d <= now) {
        a.1.on_timeout(now, 32).unwrap();
    }
}

// Select (and return) the next reserved packet, submitted as Submitted.
fn submit_next(a: &mut Side, now: u64) -> (Vec<u8>, Option<ntcp::DiscoveryIntent>) {
    let (attempt, _, mut frame) = selected(&mut a.1, now).unwrap();
    let intent = a.1.transmit_discovery_intent(attempt);
    let context = a.0.egress_context(&mut a.1, attempt).unwrap();
    // As the embeddings do: DF clear on a discovery-disabled IPv4 path.
    if a.0.clears_dont_fragment(context) {
        a.0.lease_df_clear(now, &mut frame).unwrap();
    }
    let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
    let result = a
        .0
        .submit(&mut a.1, now, ticket, context, &frame, 0, |_| BackendOutcome::Submitted)
        .unwrap();
    assert!(result == Submission::Submitted);
    (frame, intent)
}

// After a validated PTB: an upward administrative set inside the hold is
// cached only (no larger packet, no estimate, hold, search or proof change)
// and is reported deferred by the hold. After the hold the first TCP probe
// targets the administrative value (or its transport clip); its proven ACK
// grows the accepted estimate through confirm_delivery to that size and no
// further.
#[test]
fn upward_set_inside_hold_defers_then_the_targeted_probe_grows_only_to_the_value() {
    use ntcp::{AdministrativeClip, AdministrativeDeferral, AdministrativeSearch};
    for v6 in [false, true] {
        for clip in [false, true] {
            let identity = 9700 + 4 * u64::from(v6) + 2 * u64::from(clip);
            let (mut a, mut b, tcp, mut now) = lowered_by_ptb(v6, identity);
            let low = low(v6);
            let capability = a.0.administration();
            let path = a.0.binding(tcp).unwrap().snapshot.path();
            if clip {
                a.1.set_user_mss(tcp, Some(1350)).unwrap();
            }
            let before = network(&a, &capability, tcp);
            assert_eq!(before.accepted.value, low);
            assert_eq!(before.learned, Some(low));
            let hold = before.hold;
            assert!(hold > now);
            assert_eq!(three_values(&a, &capability, tcp), (None, low, Some(low)));
            assert_eq!(client(&a, &capability, tcp).search, None);

            set_estimate(&mut a, &capability, now, path, Some(UP)).unwrap();
            // Applied by the transaction itself.
            let report = a.0.service_changes(&mut a.1, now).unwrap();
            assert_eq!((report.applied, report.failed, report.decreased, report.raised), (0, 0, 0, 0));
            assert_eq!(network(&a, &capability, tcp), before);
            assert_eq!(three_values(&a, &capability, tcp), (Some(UP), low, Some(low)));
            assert_eq!(a.1.path_mtu_info(tcp).unwrap().unwrap().search_high, low);
            // Real output inside the hold: nothing larger, deferred by it.
            a.1.write(tcp, &[2; 6000]).unwrap();
            pump_within(&mut a, &mut b, &mut now, low as usize);
            assert!(now < hold);
            assert_eq!(a.0.service_changes(&mut a.1, now).unwrap().raised, 0);
            let during = network(&a, &capability, tcp);
            assert_eq!(
                (during.accepted, during.learned, during.hold, during.negative),
                (before.accepted, before.learned, before.hold, before.negative)
            );
            assert!(during.current_mtu <= low && during.search_low <= low);
            assert_eq!(
                client(&a, &capability, tcp).search,
                Some(AdministrativeSearch::Pending {
                    target: UP,
                    deferred: Some(AdministrativeDeferral::Hold)
                }),
                "v6={v6} clip={clip}"
            );

            // The first eligible probe after the hold.
            now = hold;
            expire(&mut a, now);
            a.0.service_changes(&mut a.1, now).unwrap();
            a.1.write(tcp, &[3; 20000]).unwrap();
            let (probe, intent) = submit_next(&mut a, now);
            let header = if v6 { 40 } else { 20 };
            let size = if clip { 1350 + header + 20 } else { UP };
            assert_eq!(probe.len() as u32, size, "v6={v6} clip={clip}");
            assert_eq!(intent.expect("probe").ip_packet_len(), size);
            assert_eq!(
                client(&a, &capability, tcp).search,
                Some(AdministrativeSearch::Attempted {
                    target: UP,
                    size,
                    clipped: clip.then_some(AdministrativeClip::Transport),
                })
            );
            // Submission alone changes nothing shared.
            assert_eq!(network(&a, &capability, tcp).accepted, before.accepted);
            input(&mut b.0, &mut b.1, b.2, now + 1, &probe, 0);
            let ack = emit(&mut b.0, &mut b.1, now + 2).unwrap();
            input(&mut a.0, &mut a.1, a.2, now + 3, &ack, 0);
            now += 4;
            let report = a.0.service_changes(&mut a.1, now).unwrap();
            assert_eq!((report.raised, report.failed), (1, 0));
            let grown = network(&a, &capability, tcp);
            assert_eq!(grown.learned, Some(size));
            assert_eq!(grown.accepted.value, size);
            assert_eq!(grown.hold, hold);
            assert_eq!(grown.search_low, size);
            // No further: the rest of the stream stays within the value.
            pump_within(&mut a, &mut b, &mut now, size as usize);
            a.0.service_changes(&mut a.1, now).unwrap();
            let after = network(&a, &capability, tcp);
            assert_eq!((after.learned, after.accepted.value), (Some(size), size));
            // The value still caps the search; the user MSS (not a network
            // bound) keeps the clipped connection's later probes at `size`.
            assert_eq!(a.1.path_mtu_info(tcp).unwrap().unwrap().search_high, UP);
            assert_eq!(three_values(&a, &capability, tcp), (Some(UP), size, Some(size)));
            let progress = a.1.send_progress(tcp).unwrap();
            assert_eq!(progress.acknowledged, progress.queued_end);
        }
    }
}

// A targeted probe that fails (isolated loss, repaired below it) sets
// search_high below the value; clearing and setting the value again (two
// new administrative revisions) does not reopen the failed size.
#[test]
fn failed_targeted_probe_is_not_reopened_by_new_administrative_revisions() {
    for v6 in [false, true] {
        let (mut a, mut b, tcp, mut now) = lowered_by_ptb(v6, 9720 + u64::from(v6) * 2);
        let capability = a.0.administration();
        let path = a.0.binding(tcp).unwrap().snapshot.path();
        set_estimate(&mut a, &capability, now, path, Some(UP)).unwrap();
        a.0.service_changes(&mut a.1, now).unwrap();
        a.1.write(tcp, &[2; 3000]).unwrap();
        pump_within(&mut a, &mut b, &mut now, low(v6) as usize);
        now = a.0.paths().path_snapshot(path).unwrap().retry_not_before();
        expire(&mut a, now);
        a.1.write(tcp, &[3; 20000]).unwrap();
        let (probe, intent) = submit_next(&mut a, now);
        assert_eq!((probe.len() as u32, intent.unwrap().ip_packet_len()), (UP, UP));
        // The probe is lost; the trailing data and its repair are delivered.
        pump_within(&mut a, &mut b, &mut now, UP as usize - 1);
        for _ in 0..8 {
            if a.1.send_progress(tcp).unwrap().acknowledged == a.1.send_progress(tcp).unwrap().queued_end {
                break;
            }
            now = now.max(a.1.next_deadline().unwrap());
            a.1.on_timeout(now, 32).unwrap();
            pump_within(&mut a, &mut b, &mut now, UP as usize - 1);
        }
        let progress = a.1.send_progress(tcp).unwrap();
        assert_eq!(progress.acknowledged, progress.queued_end);
        assert_eq!(a.0.service_changes(&mut a.1, now).unwrap().raised, 0);
        assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), Some(low(v6)));
        assert_eq!(a.1.path_mtu_info(tcp).unwrap().unwrap().search_high, UP - 1, "v6={v6}");
        for value in [None, Some(UP)] {
            set_estimate(&mut a, &capability, now, path, value).unwrap();
            a.0.service_changes(&mut a.1, now).unwrap();
            assert_eq!(a.1.path_mtu_info(tcp).unwrap().unwrap().search_high, UP - 1);
        }
        a.1.write(tcp, &[4; 20000]).unwrap();
        pump_within(&mut a, &mut b, &mut now, UP as usize - 1);
        assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), Some(low(v6)));
    }
}

// A downward set while the targeted probe is outstanding: the accepted
// estimate falls at once with a fresh hold, the probe's later ACK publishes
// nothing, and output stays within the new value, also after its hold.
#[test]
fn downward_set_during_an_active_search_invalidates_the_probe_result() {
    for v6 in [false, true] {
        let (mut a, mut b, tcp, mut now) = lowered_by_ptb(v6, 9730 + u64::from(v6) * 2);
        let capability = a.0.administration();
        let path = a.0.binding(tcp).unwrap().snapshot.path();
        let down = if v6 { 1300 } else { 1100 };
        set_estimate(&mut a, &capability, now, path, Some(UP)).unwrap();
        a.0.service_changes(&mut a.1, now).unwrap();
        a.1.write(tcp, &[2; 3000]).unwrap();
        pump_within(&mut a, &mut b, &mut now, low(v6) as usize);
        now = a.0.paths().path_snapshot(path).unwrap().retry_not_before();
        expire(&mut a, now);
        a.1.write(tcp, &[3; 20000]).unwrap();
        let (probe, _) = submit_next(&mut a, now);
        assert_eq!(probe.len() as u32, UP);
        now += 1;
        set_estimate(&mut a, &capability, now, path, Some(down)).unwrap();
        let hold = 600 * a.1.caller_timebase().units_per_second;
        let snapshot = a.0.paths().path_snapshot(path).unwrap();
        assert_eq!((snapshot.learned_mtu(), snapshot.retry_not_before()), (Some(down), now + hold));
        assert_eq!(a.0.binding(tcp).unwrap().snapshot, snapshot);
        assert_eq!(a.0.service_changes(&mut a.1, now).unwrap().applied, 0);
        assert_eq!(three_values(&a, &capability, tcp).0, Some(down));
        input(&mut b.0, &mut b.1, b.2, now + 1, &probe, 0);
        pump_within(&mut a, &mut b, &mut now, down as usize);
        assert_eq!(a.0.service_changes(&mut a.1, now).unwrap().raised, 0);
        assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), Some(down));
        assert_eq!(three_values(&a, &capability, tcp), (Some(down), down, Some(down)));
        // After the new hold the value still caps the search.
        now = now.max(snapshot.retry_not_before());
        expire(&mut a, now);
        a.1.write(tcp, &[4; 20000]).unwrap();
        pump_within(&mut a, &mut b, &mut now, down as usize);
        a.0.service_changes(&mut a.1, now).unwrap();
        assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), Some(down));
        let progress = a.1.send_progress(tcp).unwrap();
        assert_eq!(progress.acknowledged, progress.queued_end);
    }
}

// A connection whose local working size is above a downward value: the
// set lowers the shared budget to exactly the value, and the connection's
// baseline follows it (historical max_acked kept), so neither ordinary
// output nor the challenge of a shared ceiling with local proof sends a
// packet above the owner's cap, also after the hold and repeated search
// aging intervals (SEMANTICS 2: a persistent cap on search until changed).
#[test]
fn downward_set_below_a_working_size_caps_every_later_packet_after_hold_and_aging() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (local, remote) = addresses(v6);
        let identity = 9760 + u64::from(v6) * 2;
        let mut a = managed(local, identity, cfg.clone());
        let mut b = managed(remote, identity + 1, cfg.clone());
        let listener = b.1.listen(remote, 2).unwrap();
        let tcp = a
            .1
            .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        b.1.accept(listener).unwrap();
        a.1.write(tcp, &[1; 8000]).unwrap();
        pump(&mut a, &mut b, &mut now);
        let capability = a.0.administration();
        let path = a.0.binding(tcp).unwrap().snapshot.path();
        let before = a.1.path_mtu_info(tcp).unwrap().unwrap();
        let down = if v6 { 1300 } else { 1100 };
        assert!(before.current_mtu > down, "{before:?}");
        set_estimate(&mut a, &capability, now, path, Some(down)).unwrap();
        a.0.service_changes(&mut a.1, now).unwrap();
        let info = a.1.path_mtu_info(tcp).unwrap().unwrap();
        assert_eq!((info.current_mtu, info.search_low), (down, down.min(before.search_low)));
        assert_eq!(info.search_high, down);
        let units = a.1.caller_timebase().units_per_second;
        now = now.max(a.0.paths().path_snapshot(path).unwrap().retry_not_before());
        for _ in 0..3 {
            expire(&mut a, now);
            a.0.service_changes(&mut a.1, now).unwrap();
            a.1.write(tcp, &[2; 8000]).unwrap();
            pump_within(&mut a, &mut b, &mut now, down as usize);
            for _ in 0..16 {
                let progress = a.1.send_progress(tcp).unwrap();
                if progress.acknowledged == progress.queued_end {
                    break;
                }
                now = now.max(a.1.next_deadline().unwrap());
                expire(&mut a, now);
                pump_within(&mut a, &mut b, &mut now, down as usize);
            }
            // Past the hold and any search aging interval.
            now += 3600 * units;
        }
        assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), Some(down));
        let progress = a.1.send_progress(tcp).unwrap();
        assert_eq!(progress.acknowledged, progress.queued_end);
    }
}

// An administration transaction applies only the bindings whose path it
// changed and validated. A binding dirtied by an earlier deferred topology
// change (here a link MTU change under an IPv6 connection, which a new IPv4
// plateau table does not touch) keeps its notification for
// service_changes, whose refresh performs the forwarding checks.
#[test]
fn administration_leaves_bindings_dirtied_by_deferred_topology_changes_to_service_changes() {
    let cfg = config(2);
    let (local, remote) = addresses(true);
    let mut a = managed(local, 9990, cfg.clone());
    let mut b = managed(remote, 9991, cfg.clone());
    let listener = b.1.listen(remote, 2).unwrap();
    let tcp = a
        .1
        .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
        .unwrap();
    let mut now = 0;
    pump(&mut a, &mut b, &mut now);
    b.1.accept(listener).unwrap();
    let capability = a.0.administration();
    let before = a.0.binding(tcp).unwrap();
    a.0.set_link_mtu(before.snapshot.key().link(), 1400).unwrap();
    assert!(a.0.paths().is_dirty(before.client).unwrap());
    let table = path::Ipv4Plateaus::new(&[1400, 1000, 576, 68]).unwrap();
    a.0.admin_set_ipv4_plateaus(&capability, &mut a.1, table).unwrap();
    assert!(a.0.paths().is_dirty(before.client).unwrap(), "left to service_changes");
    assert_eq!(a.0.binding(tcp).unwrap().snapshot, before.snapshot);
    let report = a.0.service_changes(&mut a.1, now).unwrap();
    assert_eq!((report.applied, report.failed), (1, 0));
    assert!(!a.0.paths().is_dirty(before.client).unwrap());
    assert_eq!(a.0.binding(tcp).unwrap().snapshot.first_hop_mtu(), 1400);
}

// Size results selected and definitely submitted under one discovery-policy
// revision lose eligibility when the transaction delivers another one
// before their ACK: either submitted before a disable (outstanding across
// disable and re-enable) or submitted while disabled and acknowledged after
// the re-enable. Each submission's real receipt reaches the connection
// through Host::submit -> Endpoint::accept_transmit_submitted; the ACK
// raises no search_low and publishes nothing; delivery accounting stays.
// (A packet only reserved under the old revision and submitted under the
// current one is a transmission under that policy and remains evidence.)
#[test]
fn policy_revision_invalidates_outstanding_ordinary_and_probe_results() {
    for v6 in [false, true] {
        for (probe, while_disabled) in [(false, false), (true, false), (false, true)] {
            let cfg = config(2);
            let (local, remote) = addresses(v6);
            let identity = 9740 + 8 * u64::from(v6) + 4 * u64::from(probe) + 2 * u64::from(while_disabled);
            // Its IPv4 output on the disabled route needs Identifications.
            let mut a = managed_identified(local, identity, cfg.clone());
            let mut b = managed(remote, identity + 1, cfg.clone());
            let listener = b.1.listen(remote, 2).unwrap();
            let tcp = a
                .1
                .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
                .unwrap();
            let mut now = 0;
            pump(&mut a, &mut b, &mut now);
            b.1.accept(listener).unwrap();
            if probe {
                // An RTT sample first.
                a.1.write(tcp, &[1; 500]).unwrap();
                pump(&mut a, &mut b, &mut now);
                a.1.write(tcp, &[2; 20000]).unwrap();
            } else {
                a.1.write(tcp, &[2; 1448]).unwrap();
            }
            let capability = a.0.administration();
            let route = a.0.binding(tcp).unwrap().snapshot.key().route();
            let path = a.0.binding(tcp).unwrap().snapshot.path();
            let before = a.1.path_mtu_info(tcp).unwrap().unwrap();
            let revision = a.0.paths().path_snapshot(path).unwrap().discovery_revision();
            let set_disabled = |a: &mut Side, disabled: bool, now: u64| {
                let expected = a.0.admin_routes(&capability).unwrap().find(|r| r.route == route).unwrap().generation;
                let candidate = a
                    .0
                    .admin_validate(
                        &capability,
                        now,
                        AdminChange {
                            target: AdminTarget::Route(route),
                            expected,
                            policy: AdminPolicy { discovery_disabled: disabled, estimate: None },
                        },
                    )
                    .unwrap();
                a.0.admin_apply(&capability, &mut a.1, candidate).unwrap();
                let report = a.0.service_changes(&mut a.1, now).unwrap();
                assert_eq!((report.applied, report.failed), (0, 0));
                assert_eq!(a.0.binding(tcp).unwrap().snapshot.discovery_disabled(), disabled);
            };
            now += 10;
            if while_disabled {
                set_disabled(&mut a, true, now);
            }
            let (frame, intent) = submit_next(&mut a, now);
            assert_eq!(intent.is_some(), probe);
            if while_disabled && v6 {
                // The disabled IPv6 path carries at most 1280 octets, which
                // is no larger than search_low.
                assert!(frame.len() <= 1280);
            } else if while_disabled {
                // The disabled IPv4 route (a forwarder next hop) sends at
                // most 576 octets (RFC 1122 section 3.3.3), without DF.
                assert!(frame.len() <= 576);
                assert_eq!(frame[6] & 0x40, 0);
            } else {
                assert!(frame.len() as u32 > before.search_low);
            }
            input(&mut b.0, &mut b.1, b.2, now + 1, &frame, 0);
            if !while_disabled {
                set_disabled(&mut a, true, now + 1);
            }
            set_disabled(&mut a, false, now + 1);
            assert!(a.0.binding(tcp).unwrap().snapshot.discovery_revision() > revision);
            let ack = emit(&mut b.0, &mut b.1, now + 2).unwrap();
            input(&mut a.0, &mut a.1, a.2, now + 3, &ack, 0);
            now += 4;
            let after = a.1.path_mtu_info(tcp).unwrap().unwrap();
            assert_eq!(after.search_low, before.search_low, "v6={v6} probe={probe} disabled={while_disabled}");
            assert_eq!(a.0.service_changes(&mut a.1, now).unwrap().raised, 0);
            assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), None);
            pump(&mut a, &mut b, &mut now);
            let progress = a.1.send_progress(tcp).unwrap();
            assert_eq!(progress.acknowledged, progress.queued_end);
        }
    }
}

// RFC 8201 section 5.6: a route discovery disable on IPv6 applies through
// the transaction to an existing connection (its reserved full-size output
// and the retransmission of a dropped full-size segment are rebuilt at most
// 1280 octets; no PLPMTUD probe leaves) and to a connection created after
// it. Clearing the policy restores the creation configuration without any
// learned size: the shared estimate stays unlearned and nothing larger than
// 1280 was acknowledged as size evidence.
#[test]
//= https://www.rfc-editor.org/rfc/rfc8201#section-5.6
//= type=test
//= reason=The owner's discovery-disable flag on a path, or on the route it resolves through, set through Host::administration and by the ntcp-pathctl utility (8201-080), caps that path's IPv6 packet budget at the IPv6 minimum link MTU of 1280 octets (PathSnapshot::ip_packet_budget), counting every IP header and any Fragment header; the uncapped network estimate is still the one compared with administrative values, and an administrative value above 1280 stays cached. Every packet the Host sends on the path obeys it: Host::admin_apply applies the budget to existing TCP connections in the same transaction (reservation-safe budget application keeps submitted prefixes) and future connections are created under it, the submission barrier refuses a larger packet, each physical software-GSO segment is cut to it, UDP Refuse admits only datagrams that fit whole, Fragment mode and Echo replies cut packets to at most 1280 octets, and Host::udp_send's payload limit follows the same budget. Connections created with PMTUD disabled enforce the same ceiling on their own (8201-004); the path flag is the separate administrative control. Tests: ntcp-host src/tests/admin.rs (existing and future TCP output and retransmissions, SYN, SYN-ACK, FIN and RST control segments and stateless resets, and every physical GSO segment of an aggregate held across the disable and of new aggregates, at most 1280 octets), emitter.rs discovery_disable_caps_ipv6_flows_at_1280_and_refuses_probes and ingress.rs echo_replies_on_a_discovery_disabled_ipv6_route_are_at_most_1280; the integration/rfc_host admin and native-admin cases capture every IPv6 packet of tun_echo and the native runtime (existing and new TCP connections, control segments and UDP source fragments) at most 1280 octets after ntcp-pathctl disables discovery on a path or route, with stream and datagram hashes intact, while a neighbor destination keeps 1500-octet packets.
//# The former can be accomplished by associating a flag with the path; when a packet is sent on a path with this flag set, the IP layer does not send packets larger than the IPv6 minimum link MTU.
fn ipv6_discovery_disable_caps_existing_and_future_tcp_at_1280() {
    let cfg = config(3);
    let (local, remote) = addresses(true);
    let mut a = managed(local, 9960, cfg.clone());
    let mut b = managed(remote, 9961, cfg.clone());
    let listener = b.1.listen(remote, 3).unwrap();
    let tcp = a
        .1
        .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
        .unwrap();
    let mut now = 0;
    pump(&mut a, &mut b, &mut now);
    b.1.accept(listener).unwrap();
    a.1.write(tcp, &[1; 500]).unwrap();
    pump(&mut a, &mut b, &mut now);
    a.1.write(tcp, &[2; 30000]).unwrap();
    // A full-size segment leaves and is lost.
    now += 10;
    let lost = emit(&mut a.0, &mut a.1, now).unwrap();
    assert!(lost.len() > 1280);
    let capability = a.0.administration();
    let route = a.0.binding(tcp).unwrap().snapshot.key().route();
    let path = a.0.binding(tcp).unwrap().snapshot.path();
    let set = |a: &mut Side, disabled: bool, now: u64| {
        let expected = a
            .0
            .admin_routes(&capability)
            .unwrap()
            .find(|r| r.route == route)
            .unwrap()
            .generation;
        let candidate = a
            .0
            .admin_validate(
                &capability,
                now,
                AdminChange {
                    target: AdminTarget::Route(route),
                    expected,
                    policy: AdminPolicy {
                        discovery_disabled: disabled,
                        estimate: None,
                    },
                },
            )
            .unwrap();
        a.0.admin_apply(&capability, &mut a.1, candidate).unwrap();
    };
    set(&mut a, true, now);
    assert_eq!(a.1.managed_path(tcp).unwrap().ordinary_ip_budget, 1280);
    // Every packet, the retransmission of the lost range included, is at
    // most 1280 octets; all data is delivered.
    for _ in 0..8 {
        pump_within(&mut a, &mut b, &mut now, 1280);
        expire(&mut a, now);
    }
    pump_within(&mut a, &mut b, &mut now, 1280);
    let progress = a.1.send_progress(tcp).unwrap();
    assert_eq!(progress.acknowledged, progress.queued_end);
    let info = a.1.path_mtu_info(tcp).unwrap().unwrap();
    assert!(info.current_mtu <= 1280 || info.search_low <= 1280);
    // A future connection is created under the ceiling.
    let second = a
        .1
        .connect_with_path_provider(now, SocketAddr::new(local.ip(), local.port() + 1), remote, options(&cfg, 0), &mut a.0)
        .unwrap();
    pump_within(&mut a, &mut b, &mut now, 1280);
    b.1.accept(listener).unwrap();
    assert!(a.1.managed_path(second).unwrap().ordinary_ip_budget <= 1280);
    a.1.write(second, &[3; 20000]).unwrap();
    for _ in 0..4 {
        pump_within(&mut a, &mut b, &mut now, 1280);
        expire(&mut a, now);
    }
    let progress = a.1.send_progress(second).unwrap();
    assert_eq!(progress.acknowledged, progress.queued_end);
    assert_eq!(a.0.service_changes(&mut a.1, now).unwrap().raised, 0);
    // Re-enable: the budget returns to the unlearned first hop, nothing
    // learned or raised while disabled.
    set(&mut a, false, now);
    let snapshot = a.0.paths().path_snapshot(path).unwrap();
    assert_eq!(snapshot.learned_mtu(), None);
    assert_eq!(snapshot.ip_packet_budget().unwrap(), 1500);
    assert_eq!(a.1.managed_path(tcp).unwrap().ordinary_ip_budget, 1500);
    assert_eq!(a.0.service_changes(&mut a.1, now).unwrap().raised, 0);
}

// Atomic transaction: a route restriction to the IPv4 minimum (68 octets)
// is validated against every client of the route before anything is
// stored. A plain connection and a UDP flow accept it, but a connection
// whose complete IP header carries 32 octets of Record Route option cannot
// carry its headers and one payload octet in 68 octets, so the change fails
// with nothing changed: no policy, generation, revision, estimate, hold,
// negative revision, notification or client state. A representable value
// then commits and reaches every client in the same transaction.
#[test]
fn unrepresentable_restriction_fails_after_inspecting_several_clients_with_nothing_changed() {
    let mut cfg = config(3);
    cfg.ipv4_options_enabled = true;
    let (local, remote) = addresses(false);
    let mut a = udp_side(local, 9970, &cfg);
    let mut b = managed(remote, 9971, cfg.clone());
    let listener = b.1.listen(remote, 3).unwrap();
    let plain = a
        .1
        .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
        .unwrap();
    let mut now = 0;
    pump(&mut a, &mut b, &mut now);
    b.1.accept(listener).unwrap();
    let flow = a
        .0
        .udp_open(&a.1, SocketAddr::new(local.ip(), 5000), Some(SocketAddr::new(remote.ip(), 7)), UdpOptions { dscp: 0, hop_limit: 64 })
        .unwrap();
    a.0.udp_path_limits(&a.1, flow, None).unwrap();
    let mut recorded = options(&cfg, 0);
    // An empty (direct) source route admits a Record Route request.
    recorded.ipv4_options.source_route = Some(ntcp::SourceRoute::new(&[], false).unwrap());
    recorded.ipv4_options.record_route_slots = Some(7);
    // The direct path registers the origin and the destination.
    recorded.registration = Some(
        ntcp::Ipv4RegistrationPlan::new(
            local.ip(),
            remote.ip(),
            recorded.ipv4_options,
            &ExpectedRegistrations {
                record_route: Some(2),
                timestamp: None,
            },
        )
        .unwrap(),
    );
    let routed = a
        .1
        .connect_with_path_provider(now, SocketAddr::new(local.ip(), local.port() + 1), remote, recorded, &mut a.0)
        .unwrap();
    // 20 + 32 option octets: 52 + 20 + 1 > 68.
    assert_eq!(a.1.managed_path(routed).unwrap().ip_header_len, 52);
    let capability = a.0.administration();
    let route = a.0.binding(plain).unwrap().snapshot.key().route();
    let path = a.0.binding(plain).unwrap().snapshot.path();
    assert_eq!(a.0.binding(routed).unwrap().snapshot.path(), path);
    let change = |estimate| AdminChange {
        target: AdminTarget::Route(route),
        expected: 0,
        policy: AdminPolicy {
            discovery_disabled: false,
            estimate: Some(estimate),
        },
    };
    let state = |a: &Side| {
        (
            a.0.paths().revision(),
            a.0.paths().admin_revision(),
            a.0.paths().path_snapshot(path).unwrap(),
            a.0.admin_routes(&capability).unwrap().find(|r| r.route == route).unwrap(),
            a.0.binding(plain).unwrap(),
            a.0.binding(routed).unwrap(),
            a.1.managed_path(plain).unwrap().ordinary_ip_budget,
            a.1.managed_path(routed).unwrap().ordinary_ip_budget,
        )
    };
    let before = state(&a);
    let candidate = a.0.admin_validate(&capability, now, change(68)).unwrap();
    assert!(before.2.pmtu_estimate().unwrap() > 68);
    assert_eq!(
        a.0.admin_apply(&capability, &mut a.1, candidate),
        Err(Error::Endpoint(EndpointError::Connection(ntcp::Error::InvalidArgument)))
    );
    assert_eq!(state(&a), before);
    assert!(!a.0.paths().is_dirty(a.0.binding(plain).unwrap().client).unwrap());
    assert_eq!(a.0.udp_path_change(flow).unwrap(), None);
    // A value every client can carry commits and is applied at once.
    let candidate = a.0.admin_validate(&capability, now, change(576)).unwrap();
    assert_eq!(a.0.admin_apply(&capability, &mut a.1, candidate), Ok(1));
    for tcp in [plain, routed] {
        assert!(a.1.managed_path(tcp).unwrap().ordinary_ip_budget <= 576);
        assert!(!a.0.paths().is_dirty(a.0.binding(tcp).unwrap().client).unwrap());
    }
    assert_eq!(a.0.udp_path_change(flow).unwrap().unwrap().max_payload, 576 - 28);
    pump_within(&mut a, &mut b, &mut now, 576);
}

// Host-wide administrative operations through the capability: the IPv4
// plateau table (validated PathService replacement) reaches every binding
// in the same transaction; search aging below 300 seconds is refused with
// nothing changed, a valid value applies to the existing connection at once
// and to a connection created later at its first service pass, without
// touching the path's hold. A foreign capability is refused.
#[test]
fn plateau_and_search_aging_operations_reach_existing_and_future_users() {
    use ntcp::SearchAging;
    let cfg = config(3);
    let (local, remote) = addresses(false);
    let mut a = managed(local, 9980, cfg.clone());
    let mut b = managed(remote, 9981, cfg.clone());
    let listener = b.1.listen(remote, 3).unwrap();
    let tcp = a
        .1
        .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
        .unwrap();
    let mut now = 0;
    pump(&mut a, &mut b, &mut now);
    b.1.accept(listener).unwrap();
    let capability = a.0.administration();
    let foreign = b.0.administration();
    let table = path::Ipv4Plateaus::new(&[1400, 1000, 576, 68]).unwrap();
    assert_eq!(
        a.0.admin_set_ipv4_plateaus(&foreign, &mut a.1, table),
        Err(Error::Unauthorized)
    );
    a.0.admin_set_ipv4_plateaus(&capability, &mut a.1, table).unwrap();
    assert_eq!(a.0.admin_ipv4_plateaus(&capability), Ok(table));
    assert_eq!(a.0.binding(tcp).unwrap().snapshot.ipv4_plateaus(), Some(table));
    assert!(!a.0.paths().is_dirty(a.0.binding(tcp).unwrap().client).unwrap());

    let path = a.0.binding(tcp).unwrap().snapshot.path();
    let hold = a.0.paths().path_snapshot(path).unwrap().retry_not_before();
    let aging = |a: &Side, id| a.1.pmtud_policy(id).unwrap().unwrap().search_aging;
    let original = aging(&a, tcp);
    assert_eq!(a.0.admin_search_aging(&capability), Ok(None));
    assert!(
        a.0.admin_set_search_aging(&capability, &mut a.1, now, SearchAging::Seconds(299))
            .is_err()
    );
    assert_eq!(a.0.admin_search_aging(&capability), Ok(None));
    assert_eq!(aging(&a, tcp), original);
    let value = SearchAging::Seconds(1800);
    assert_ne!(original, value);
    a.0.admin_set_search_aging(&capability, &mut a.1, now, value).unwrap();
    assert_eq!(a.0.admin_search_aging(&capability), Ok(Some(value)));
    assert_eq!(aging(&a, tcp), value);
    let second = a
        .1
        .connect_with_path_provider(now, SocketAddr::new(local.ip(), local.port() + 1), remote, options(&cfg, 0), &mut a.0)
        .unwrap();
    assert_eq!(aging(&a, second), original);
    a.0.service_changes(&mut a.1, now).unwrap();
    assert_eq!(aging(&a, second), value);
    a.0.admin_set_search_aging(&capability, &mut a.1, now, SearchAging::Infinity).unwrap();
    assert_eq!((aging(&a, tcp), aging(&a, second)), (SearchAging::Infinity, SearchAging::Infinity));
    assert_eq!(a.0.paths().path_snapshot(path).unwrap().retry_not_before(), hold);
    pump(&mut a, &mut b, &mut now);
}

// Parent decision D17 / SEMANTICS 7: a held stateless output lease never
// blocks an administrative change. Another host's SYN to a closed port
// leaves a stateless reset held (selected, authorized, ticketed) while the
// owner restricts the route that carries it and the live connection. The
// change applies at once and updates the connection in the same call; the
// held reset, authorized under the path as it was, is refused at its
// submission exactly as after a trusted PTB decrease, released as certified
// unsent, and nothing of it stays in the ledger. (On IPv4 the reset answers
// a source-routed SYN, so its reversed route also makes it larger than the
// restricted estimate.)
#[test]
fn held_stateless_lease_never_blocks_a_restriction_and_is_refused_at_submission() {
    for v6 in [false, true] {
        let mut cfg = config(3);
        cfg.ipv4_options_enabled = true;
        let (local, remote) = addresses(v6);
        let identity = 9990 + 2 * u64::from(v6);
        let mut a = if v6 {
            managed(local, identity, cfg.clone())
        } else {
            super::source_routes::routed(local, identity, cfg.clone())
        };
        let mut b = managed(remote, identity + 1, cfg.clone());
        let listener = b.1.listen(remote, 3).unwrap();
        let tcp = a
            .1
            .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        b.1.accept(listener).unwrap();
        // A SYN to a port of `a` without a listener.
        let closed = SocketAddr::new(local.ip(), 4444);
        now += 10;
        b.1.connect_with_path_provider(now, SocketAddr::new(remote.ip(), 9000), closed, options(&cfg, 0), &mut b.0)
            .unwrap();
        now += 10;
        let syn = emit(&mut b.0, &mut b.1, now).unwrap();
        if v6 {
            input(&mut a.0, &mut a.1, a.2, now + 1, &syn, 0);
        } else {
            super::source_routes::receive(&mut a, now + 1, &syn, &[1, 2, 3, 4, 5, 6, 7, 8]);
        }
        let (attempt, packet, frame) = selected(&mut a.1, now + 2).unwrap();
        assert!(packet.connection.is_none());
        let header = if v6 { 40 } else { usize::from(frame[0] & 0xf) * 4 };
        assert_ne!(frame[header + 13] & 0x04, 0, "a reset");
        let context = a.0.egress_context(&mut a.1, attempt).unwrap();
        let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
        let capability = a.0.administration();
        let lease_path = context.binding.snapshot.path();
        assert!(
            a.0.admin_clients(&capability, &a.1, lease_path)
                .unwrap()
                .any(|c| c.client == AdminClient::OutputLease(attempt))
        );
        let route = a.0.binding(tcp).unwrap().snapshot.key().route();
        assert_eq!(context.binding.snapshot.key().route(), route);
        let path = a.0.binding(tcp).unwrap().snapshot.path();
        // IPv4: just below the reset; IPv6: a downward set, then a disable.
        let changes: &[AdminPolicy] = if v6 {
            &[
                AdminPolicy { discovery_disabled: false, estimate: Some(1300) },
                AdminPolicy { discovery_disabled: true, estimate: Some(1300) },
            ]
        } else {
            assert!(frame.len() > 69, "{}", frame.len());
            &[AdminPolicy { discovery_disabled: false, estimate: Some(frame.len() as u32 - 1) }]
        };
        for &policy in changes {
            let expected = a.0.admin_routes(&capability).unwrap().find(|r| r.route == route).unwrap().generation;
            let candidate = a
                .0
                .admin_validate(&capability, now + 3, AdminChange { target: AdminTarget::Route(route), expected, policy })
                .unwrap();
            assert_eq!(a.0.admin_apply(&capability, &mut a.1, candidate), Ok(expected + 1));
            // Every other client is updated in the same call.
            let snapshot = a.0.paths().path_snapshot(path).unwrap();
            assert_eq!(a.0.binding(tcp).unwrap().snapshot, snapshot);
            assert!(!a.0.paths().is_dirty(a.0.binding(tcp).unwrap().client).unwrap());
            let budget = snapshot.ip_packet_budget().unwrap();
            let cap = if policy.discovery_disabled { 1280 } else { u32::MAX };
            assert_eq!(budget, policy.estimate.unwrap().min(cap));
            assert!(a.1.managed_path(tcp).unwrap().ordinary_ip_budget <= budget);
        }
        let result = a.0.submit(&mut a.1, now + 4, ticket, context, &frame, 0, |_| {
            panic!("a reset authorized under the old path reached the backend")
        });
        let refused = result.err().unwrap();
        assert_eq!(refused.error, Error::Obsolete);
        assert!(a.1.reject_unsubmitted(attempt).unwrap());
        a.0.cancel_submission(refused.ticket);
        a.0.collect(&a.1).unwrap();
        assert_eq!(a.0.ledger.pending_count(), 0);
        // The connection keeps working within the restricted budget.
        a.1.write(tcp, &[5; 300]).unwrap();
        let limit = a.0.paths().path_snapshot(path).unwrap().ip_packet_budget().unwrap() as usize;
        pump_within(&mut a, &mut b, &mut now, limit);
        let progress = a.1.send_progress(tcp).unwrap();
        assert_eq!(progress.acknowledged, progress.queued_end);
    }
}

// SEMANTICS 3 and 6 at the Host, caller time: a TCP probe definitely
// submitted (its real receipt reaches the connection through Host::submit)
// before the owner disables discovery on its route, and acknowledged after
// it, publishes nothing: no PathService change (revision, accepted
// estimate, learned value, hold), the same administration query and no
// search_low growth; its ACK still advances the stream and the delivery,
// loss and congestion accounting. Re-enabling afterwards does not revive
// it.
#[test]
fn probe_submitted_before_a_disable_and_acknowledged_after_it_publishes_nothing() {
    for v6 in [false, true] {
        let (mut a, mut b, tcp, mut now) = lowered_by_ptb(v6, 9760 + 2 * u64::from(v6));
        let capability = a.0.administration();
        let path = a.0.binding(tcp).unwrap().snapshot.path();
        let route = a.0.binding(tcp).unwrap().snapshot.key().route();
        set_estimate(&mut a, &capability, now, path, Some(UP)).unwrap();
        now = a.0.paths().path_snapshot(path).unwrap().retry_not_before();
        expire(&mut a, now);
        a.0.service_changes(&mut a.1, now).unwrap();
        a.1.write(tcp, &[3; 20000]).unwrap();
        let (probe, intent) = submit_next(&mut a, now);
        assert_eq!((probe.len() as u32, intent.expect("a probe").ip_packet_len()), (UP, UP));
        let set_disabled = |a: &mut Side, disabled: bool, now: u64| {
            let expected = a.0.admin_routes(&capability).unwrap().find(|r| r.route == route).unwrap().generation;
            let candidate = a
                .0
                .admin_validate(
                    &capability,
                    now,
                    AdminChange {
                        target: AdminTarget::Route(route),
                        expected,
                        policy: AdminPolicy { discovery_disabled: disabled, estimate: None },
                    },
                )
                .unwrap();
            a.0.admin_apply(&capability, &mut a.1, candidate).unwrap();
        };
        now += 1;
        set_disabled(&mut a, true, now);
        let before = network(&a, &capability, tcp);
        let revision = a.0.paths().revision();
        let query = |a: &Side| {
            let admin = a.0.admin_path(&capability, path).unwrap();
            let clients: Vec<_> = a.0.admin_clients(&capability, &a.1, path).unwrap().collect();
            (admin.accepted, admin.effective, admin.snapshot, admin.generation, clients)
        };
        let queried = query(&a);
        let info = a.1.transport_info(tcp).unwrap();
        let progress = a.1.send_progress(tcp).unwrap();
        // The probe arrives; its ACK returns after the disable.
        input(&mut b.0, &mut b.1, b.2, now + 1, &probe, 0);
        let ack = emit(&mut b.0, &mut b.1, now + 2).unwrap();
        input(&mut a.0, &mut a.1, a.2, now + 3, &ack, 0);
        now += 4;
        assert_eq!(a.0.service_changes(&mut a.1, now).unwrap().raised, 0);
        assert_eq!(network(&a, &capability, tcp), before, "v6={v6}");
        assert_eq!(a.0.paths().revision(), revision);
        assert_eq!(query(&a), queried);
        // Delivery, loss and congestion accounting advance as usual.
        let acked = a.1.transport_info(tcp).unwrap();
        assert!(a.1.send_progress(tcp).unwrap().acknowledged > progress.acknowledged);
        assert!(acked.delivered_segments > info.delivered_segments);
        assert!(acked.unacked < info.unacked);
        assert_eq!(acked.lost, 0);
        assert!(acked.cwnd >= info.cwnd);
        // Re-enabling does not revive the probe's result.
        set_disabled(&mut a, false, now);
        assert_eq!(a.0.service_changes(&mut a.1, now).unwrap().raised, 0);
        let after = network(&a, &capability, tcp);
        assert_eq!(
            (after.accepted, after.learned, after.hold, after.negative, after.search_low),
            (before.accepted, before.learned, before.hold, before.negative, before.search_low)
        );
        assert_eq!(after.learned, Some(low(v6)));
        pump(&mut a, &mut b, &mut now);
        let progress = a.1.send_progress(tcp).unwrap();
        assert_eq!(progress.acknowledged, progress.queued_end);
    }
}

// ---- IPv6 1280 evidence on a discovery-disabled path (RFC 8201 5.6) ----

fn disable_route(a: &mut Side, capability: &Administration, route: path::RouteId, now: u64) {
    let expected = a.0.admin_routes(capability).unwrap().find(|r| r.route == route).unwrap().generation;
    let candidate = a
        .0
        .admin_validate(
            capability,
            now,
            AdminChange {
                target: AdminTarget::Route(route),
                expected,
                policy: AdminPolicy { discovery_disabled: true, estimate: None },
            },
        )
        .unwrap();
    a.0.admin_apply(capability, &mut a.1, candidate).unwrap();
}

// `pump_within(.., 1280)` that also returns the TCP flags of every frame `a`
// emits (IPv6, no extension headers).
fn exchange_flags(a: &mut Side, b: &mut Side, now: &mut u64) -> Vec<u8> {
    let mut flags = Vec::new();
    for _ in 0..512 {
        *now += 10;
        let mut work = false;
        if let Some(frame) = emit(&mut a.0, &mut a.1, *now) {
            assert!(frame.len() <= 1280, "{}", frame.len());
            flags.push(frame[40 + 13]);
            input(&mut b.0, &mut b.1, b.2, *now + 1, &frame, 0);
            work = true;
        }
        if let Some(frame) = emit(&mut b.0, &mut b.1, *now + 2) {
            input(&mut a.0, &mut a.1, a.2, *now + 3, &frame, 0);
            work = true;
        }
        if !work {
            return flags;
        }
    }
    panic!("wire exchange did not quiesce");
}

// Control segments on a disabled IPv6 route, from a connection that existed
// before the disable and from ones created after it: FIN and RST of the
// existing connection, the SYN, RST of a new active connection, the
// SYN-ACK of a new passive one and a stateless RST for a closed port. Each
// leaves and each is at most 1280 octets.
#[test]
fn ipv6_disabled_path_control_segments_are_at_most_1280() {
    const SYN: u8 = 0x02;
    const RST: u8 = 0x04;
    const ACK: u8 = 0x10;
    const FIN: u8 = 0x01;
    let cfg = config(6);
    let (local, remote) = addresses(true);
    let mut a = managed(local, 9800, cfg.clone());
    let mut b = managed(remote, 9801, cfg.clone());
    let listener = b.1.listen(remote, 4).unwrap();
    let served = SocketAddr::new(local.ip(), 2000);
    a.1.listen(served, 4).unwrap();
    let existing = a
        .1
        .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
        .unwrap();
    let mut now = 0;
    pump(&mut a, &mut b, &mut now);
    let peer = b.1.accept(listener).unwrap();
    let aborted = a
        .1
        .connect_with_path_provider(now, SocketAddr::new(local.ip(), 1001), remote, options(&cfg, 0), &mut a.0)
        .unwrap();
    pump(&mut a, &mut b, &mut now);
    b.1.accept(listener).unwrap();
    let capability = a.0.administration();
    let route = a.0.binding(existing).unwrap().snapshot.key().route();
    disable_route(&mut a, &capability, route, now);
    assert_eq!(a.1.managed_path(existing).unwrap().ordinary_ip_budget, 1280);
    // Existing connections: FIN, then RST.
    a.1.close(existing).unwrap();
    b.1.close(peer).unwrap();
    let flags = exchange_flags(&mut a, &mut b, &mut now);
    assert!(flags.iter().any(|f| f & FIN != 0), "{flags:x?}");
    a.1.abort(aborted).unwrap();
    let flags = exchange_flags(&mut a, &mut b, &mut now);
    assert!(flags.iter().any(|f| f & RST != 0), "{flags:x?}");
    // New active connection: SYN, then RST.
    let fresh = a
        .1
        .connect_with_path_provider(now, SocketAddr::new(local.ip(), 1002), remote, options(&cfg, 0), &mut a.0)
        .unwrap();
    let flags = exchange_flags(&mut a, &mut b, &mut now);
    assert!(flags.iter().any(|&f| f & (SYN | ACK) == SYN), "{flags:x?}");
    b.1.accept(listener).unwrap();
    assert!(a.1.managed_path(fresh).unwrap().ordinary_ip_budget <= 1280);
    a.1.abort(fresh).unwrap();
    let flags = exchange_flags(&mut a, &mut b, &mut now);
    assert!(flags.iter().any(|f| f & RST != 0), "{flags:x?}");
    // New passive connection: SYN-ACK.
    now += 10;
    b.1.connect_with_path_provider(now, SocketAddr::new(remote.ip(), 9000), served, options(&cfg, 0), &mut b.0)
        .unwrap();
    let flags = exchange_flags(&mut a, &mut b, &mut now);
    assert!(flags.iter().any(|&f| f & (SYN | ACK) == SYN | ACK), "{flags:x?}");
    // Stateless: a reset for a SYN to a port without a listener.
    now += 10;
    b.1.connect_with_path_provider(now, SocketAddr::new(remote.ip(), 9001), SocketAddr::new(local.ip(), 4444), options(&cfg, 0), &mut b.0)
        .unwrap();
    now += 10;
    let syn = emit(&mut b.0, &mut b.1, now).unwrap();
    input(&mut a.0, &mut a.1, a.2, now + 1, &syn, 0);
    let (attempt, packet, frame) = selected(&mut a.1, now + 2).unwrap();
    assert!(packet.connection.is_none());
    assert_ne!(frame[40 + 13] & RST, 0);
    assert!(frame.len() <= 1280);
    let context = a.0.egress_context(&mut a.1, attempt).unwrap();
    assert_eq!(context.binding.snapshot.ip_packet_budget().unwrap(), 1280);
    let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
    let submitted = a.0.submit(&mut a.1, now + 3, ticket, context, &frame, 0, |_| BackendOutcome::Submitted);
    assert!(submitted.unwrap() == Submission::Submitted);
}

// Software GSO on a disabled IPv6 route: an aggregate reserved before the
// disable at the 1500-octet budget has its first physical segment
// submitted; the next held segment is refused by the submission barrier
// and the rest of the aggregate is rebuilt, every physical segment at most
// 1280 octets; new GSO output after the disable is an aggregate of several
// segments, each at most 1280. The stream is delivered intact.
#[test]
fn ipv6_disabled_path_caps_every_physical_gso_segment_at_1280() {
    let mut cfg = config(4);
    cfg.connection.pmtud.as_mut().unwrap().initial_search_low = Some(1500);
    let (local, remote) = addresses(true);
    let mut a = managed_configured(local, 9810, cfg.clone(), true, None);
    let mut b = managed(remote, 9811, cfg.clone());
    let listener = b.1.listen(remote, 1).unwrap();
    let tcp = a
        .1
        .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
        .unwrap();
    let mut now = 0;
    pump(&mut a, &mut b, &mut now);
    let child = b.1.accept(listener).unwrap();
    let payload: Vec<u8> = (0..12000).map(|i| (i * 7) as u8).collect();
    a.1.write(tcp, &payload[..6000]).unwrap();
    now += 10;
    let (first, _) = submit_next(&mut a, now);
    assert!(first.len() > 1280);
    assert!(a.1.is_output_reserved(tcp), "a GSO aggregate continues");
    input(&mut b.0, &mut b.1, b.2, now + 1, &first, 0);
    // The next physical segment of the held aggregate is authorized...
    let (held, _, frame) = selected(&mut a.1, now + 2).unwrap();
    assert!(frame.len() > 1280);
    let context = a.0.egress_context(&mut a.1, held).unwrap();
    let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
    // ... when the owner disables discovery on the route.
    let capability = a.0.administration();
    let route = a.0.binding(tcp).unwrap().snapshot.key().route();
    disable_route(&mut a, &capability, route, now + 3);
    assert_eq!(a.1.managed_path(tcp).unwrap().ordinary_ip_budget, 1280);
    let refused = a
        .0
        .submit(&mut a.1, now + 4, ticket, context, &frame, 0, |_| {
            panic!("an oversized segment reached the backend")
        })
        .unwrap_err();
    assert_eq!(refused.error, Error::Obsolete);
    assert!(a.1.reject_unsubmitted(held).unwrap());
    a.0.cancel_submission(refused.ticket);
    now += 10;
    while a.1.is_output_reserved(tcp) {
        let (frame, _) = submit_next(&mut a, now);
        assert!(frame.len() <= 1280, "{}", frame.len());
        input(&mut b.0, &mut b.1, b.2, now + 1, &frame, 0);
    }
    pump_within(&mut a, &mut b, &mut now, 1280);
    // New GSO output after the disable.
    a.1.write(tcp, &payload[6000..]).unwrap();
    now += 10;
    let mut segments = 0;
    let (frame, _) = submit_next(&mut a, now);
    assert!(frame.len() <= 1280);
    input(&mut b.0, &mut b.1, b.2, now + 1, &frame, 0);
    segments += 1;
    while a.1.is_output_reserved(tcp) {
        let (frame, _) = submit_next(&mut a, now);
        assert!(frame.len() <= 1280, "{}", frame.len());
        input(&mut b.0, &mut b.1, b.2, now + 1, &frame, 0);
        segments += 1;
    }
    assert!(segments > 1, "one aggregate of several physical segments");
    pump_within(&mut a, &mut b, &mut now, 1280);
    let mut bytes = vec![0; payload.len() + 1];
    assert_eq!(b.1.read(child, &mut bytes).unwrap(), payload.len());
    assert_eq!(&bytes[..payload.len()], &payload[..]);
}
