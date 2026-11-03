// UDP probe receipts and outcome reporting (RFC 4821 sections 7.6 and 9):
// receipt capacity, expiry and reclamation, every rejection, the flow-local
// effect of each outcome on sizing and reported limits, and owner-granted
// shared publication with its separate result.
use super::*;
use path::{AdminChange, AdminPolicy, AdminTarget, DeliveryConfirmation, EstimateProvenance};
use std::boxed::Box;
use std::sync::{Arc, Mutex};

type Side = (Host, Endpoint, IngressContext);

const SECOND: u64 = 1_000_000;
// The Host's 600-second decrease hold in caller time.
const HOLD: u64 = 600 * SECOND;

const UDP: UdpLimits = UdpLimits {
    flows: 2,
    receive_datagrams: 1,
    max_payload: 4000,
    events: 1,
    evicted_signatures: 1,
    probe_receipts: 2,
};

fn side(local: SocketAddr, identity: u128) -> Side {
    let mut side = managed_limited(local, identity, config(2), false, None, None, |p, mut l| {
        l.datagrams = DatagramLimits {
            max_fragments: 8,
            identifiers: IdentifierLimits {
                lifetime_seconds: 120,
                ipv4_tuples: 2,
                ipv6_leases: 16,
            },
            ..Default::default()
        };
        let (p, l) = managed_udp_limits(p, l, UDP).unwrap();
        (p, l, 1)
    });
    let counter = Arc::new(Mutex::new(1u32));
    side.0.set_entropy(Box::new(move |out: &mut [u8]| {
        let mut n = counter.lock().unwrap();
        for b in out.iter_mut() {
            *b = *n as u8;
            *n = n.wrapping_add(1);
        }
        Ok(())
    }));
    side.0
        .start_identifiers(Continuity::QuietFor {
            at: 0,
            seconds: u64::MAX,
        })
        .unwrap();
    side
}

fn options() -> UdpOptions {
    UdpOptions {
        dscp: 0,
        hop_limit: 64,
    }
}

fn mode(mode: UdpSendMode) -> UdpSend {
    UdpSend {
        mode,
        peer_capability: Some(4000),
    }
}

fn overhead(v6: bool) -> usize {
    if v6 { 48 } else { 28 }
}

// One send of `ip_len` complete IP octets (whole) or of `ip_len - overhead`
// payload octets; returns the result and every physical packet.
fn send(
    a: &mut Side,
    now: u64,
    flow: UdpFlowId,
    send: UdpSendMode,
    payload: usize,
    outcome: BackendOutcome,
) -> (Result<DatagramReport, DatagramError>, Vec<Vec<u8>>) {
    let mut packet = vec![0; 8192];
    let mut sent = Vec::new();
    let result = a.0.udp_send_datagram(
        &a.1,
        now,
        flow,
        None,
        Some(mode(send)),
        &vec![0x42; payload],
        &mut packet,
        |_, bytes| {
            sent.push(bytes.to_vec());
            outcome
        },
    );
    (result, sent)
}

// A definite probe of `ip_len` complete IP octets and its receipt.
fn probe(a: &mut Side, now: u64, flow: UdpFlowId, ip_len: usize, v6: bool) -> ProbeReceipt {
    let (result, sent) = send(
        a,
        now,
        flow,
        UdpSendMode::Probe,
        ip_len - overhead(v6),
        BackendOutcome::Submitted,
    );
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].len(), ip_len);
    let receipt = result.unwrap().probe.unwrap().receipt.unwrap();
    assert_eq!(receipt.size() as usize, ip_len);
    receipt
}

fn report(
    a: &mut Side,
    now: u64,
    flow: UdpFlowId,
    receipt: ProbeReceipt,
    outcome: UdpProbeOutcome,
) -> Result<UdpProbeReport, ProbeReportError> {
    a.0.udp_report_probe(now, flow, receipt, outcome, None)
}

fn fragment_sizes(a: &mut Side, now: u64, flow: UdpFlowId) -> Vec<usize> {
    let (result, sent) = send(
        a,
        now,
        flow,
        UdpSendMode::Fragment,
        3000,
        BackendOutcome::Submitted,
    );
    assert!(result.unwrap().fragments > 1);
    sent.iter().map(Vec::len).collect()
}

fn set_discovery(a: &mut Side, now: u64, path: path::PathId, disabled: bool) {
    let capability = a.0.administration();
    let expected = a.0.admin_path(&capability, path).unwrap().generation;
    let candidate =
        a.0.admin_validate(
            &capability,
            now,
            AdminChange {
                target: AdminTarget::Path(path),
                expected,
                policy: AdminPolicy {
                    discovery_disabled: disabled,
                    estimate: None,
                },
            },
        )
        .unwrap();
    a.0.admin_apply(&capability, &mut a.1, candidate).unwrap();
}

#[test]
fn receipts_are_reserved_issued_once_expire_and_are_reclaimed() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let mut a = side(local, 9700 + u128::from(v6));
        let flow = a.0.udp_open(&a.1, local, Some(remote), options()).unwrap();
        let t = 10 * SECOND;
        // An uncertain submission yields no receipt and holds no capacity;
        // a certain non-submission records nothing.
        let (result, _) = send(
            &mut a,
            t,
            flow,
            UdpSendMode::Probe,
            1000,
            BackendOutcome::Unknown,
        );
        let record = result.unwrap().probe.unwrap();
        assert!(!record.definite);
        assert_eq!(record.receipt, None);
        let (result, _) = send(
            &mut a,
            t,
            flow,
            UdpSendMode::Probe,
            1000,
            BackendOutcome::NotSubmitted,
        );
        assert_eq!(
            result.err(),
            Some(DatagramError::NotSubmitted(BackendOutcome::NotSubmitted))
        );
        // Two receipts per flow; a third Probe-mode send is refused before
        // anything is submitted.
        let first = probe(&mut a, t, flow, 1400, v6);
        let second = probe(&mut a, t + 1, flow, 1450, v6);
        let (result, sent) = send(
            &mut a,
            t + 2,
            flow,
            UdpSendMode::Probe,
            1000,
            BackendOutcome::Submitted,
        );
        assert_eq!(result.err(), Some(DatagramError::ReceiptsExhausted));
        assert!(sent.is_empty());
        // Ordinary modes need no receipt.
        let (result, _) = send(
            &mut a,
            t + 2,
            flow,
            UdpSendMode::Refuse,
            100,
            BackendOutcome::Submitted,
        );
        assert!(result.is_ok());
        // Expiry is the feedback horizon after submission.
        assert_eq!(first.expires_at, t + a.0.ledger.feedback_horizon());
        // Consumed exactly once; the replay is rejected.
        assert!(report(&mut a, t + 3, flow, first, UdpProbeOutcome::Inconclusive).is_ok());
        assert_eq!(
            report(&mut a, t + 3, flow, first, UdpProbeOutcome::Success).err(),
            Some(ProbeReportError::Consumed)
        );
        // The freed entry takes the next probe.
        let third = probe(&mut a, t + 4, flow, 1400, v6);
        // A report at the expiry instant is rejected and reclaims it.
        assert_eq!(
            report(
                &mut a,
                second.expires_at,
                flow,
                second,
                UdpProbeOutcome::Success
            )
            .err(),
            Some(ProbeReportError::Expired)
        );
        assert_eq!(
            report(
                &mut a,
                second.expires_at,
                flow,
                second,
                UdpProbeOutcome::Success
            )
            .err(),
            Some(ProbeReportError::Consumed)
        );
        // Unreported receipts never exhaust the flow: once `third` expired
        // both entries are available again.
        let later = third.expires_at;
        let fourth = probe(&mut a, later, flow, 1400, v6);
        let fifth = probe(&mut a, later, flow, 1400, v6);
        assert_eq!(
            report(&mut a, later, flow, third, UdpProbeOutcome::Success).err(),
            Some(ProbeReportError::Consumed)
        );
        // Altered copies are rejected and leave the real receipt usable.
        let mut resized = fourth;
        resized.size -= 1;
        assert_eq!(
            report(&mut a, later, flow, resized, UdpProbeOutcome::Success).err(),
            Some(ProbeReportError::Foreign)
        );
        let mut forged = fourth;
        forged.serial += 100;
        assert_eq!(
            report(&mut a, later, flow, forged, UdpProbeOutcome::Success).err(),
            Some(ProbeReportError::Consumed)
        );
        // A receipt is bound to its flow generation and Host instance.
        let other_local = SocketAddr::new(local.ip(), local.port() + 1);
        let other =
            a.0.udp_open(&a.1, other_local, Some(remote), options())
                .unwrap();
        assert_eq!(
            report(&mut a, later, other, fourth, UdpProbeOutcome::Success).err(),
            Some(ProbeReportError::Foreign)
        );
        let mut b = side(local, 9800 + u128::from(v6));
        let flow_b = b.0.udp_open(&b.1, local, Some(remote), options()).unwrap();
        assert_eq!(flow_b, flow, "same slot and generation in another Host");
        assert_eq!(
            report(&mut b, later, flow_b, fourth, UdpProbeOutcome::Success).err(),
            Some(ProbeReportError::Foreign)
        );
        assert!(report(&mut a, later, flow, fourth, UdpProbeOutcome::Success).is_ok());
        // A replaced flow: the old generation is gone and its successor in
        // the same slot does not accept the old receipt.
        a.0.udp_close(flow).unwrap();
        let reopened = a.0.udp_open(&a.1, local, Some(remote), options()).unwrap();
        assert_ne!(reopened, flow);
        assert_eq!(
            report(&mut a, later, flow, fifth, UdpProbeOutcome::Success).err(),
            Some(ProbeReportError::Host(Error::Obsolete))
        );
        assert_eq!(
            report(&mut a, later, reopened, fifth, UdpProbeOutcome::Success).err(),
            Some(ProbeReportError::Foreign)
        );
    }
}

#[test]
fn stale_receipts_after_rebind_decrease_or_discovery_change_are_rejected() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let mut a = side(local, 9710 + u128::from(v6));
        let flow = a.0.udp_open(&a.1, local, Some(remote), options()).unwrap();
        let path = a.0.udp_path_limits(&a.1, flow, None).unwrap().path;
        let t = 10 * SECOND;
        // A decrease after submission: stale negative revision.
        let receipt = probe(&mut a, t, flow, 1400, v6);
        a.0.trusted_decrease(t + 1, path, 1300).unwrap();
        a.0.service_changes(&mut a.1, t + 1).unwrap();
        assert_eq!(
            report(&mut a, t + 2, flow, receipt, UdpProbeOutcome::Success).err(),
            Some(ProbeReportError::StaleRevision)
        );
        // Disable then re-enable discovery: a delayed success from before
        // the transition revives nothing, locally or shared.
        let receipt = probe(&mut a, t + 3, flow, 1400, v6);
        set_discovery(&mut a, t + 4, path, true);
        set_discovery(&mut a, t + 5, path, false);
        assert_eq!(
            report(&mut a, t + 6, flow, receipt, UdpProbeOutcome::Success).err(),
            Some(ProbeReportError::StaleRevision)
        );
        let limits = a.0.udp_datagram_limits(&a.1, flow, None, None).unwrap();
        assert_eq!(limits.probe, UdpProbeBounds::default());
        // A rebound path: a more specific route invalidates the incarnation.
        let receipt = probe(&mut a, t + 7, flow, 1200, v6);
        let link = a.0.paths().path_snapshot(path).unwrap().key().link();
        a.0.add_route(path::Route {
            destination: path::IpPrefix::new(remote.ip(), if v6 { 128 } else { 32 }).unwrap(),
            source: None,
            dscp: None,
            link,
            next_hop: path::NextHop::Forwarder(path::ForwarderId(9)),
            metric: 0,
        })
        .unwrap();
        assert_eq!(
            report(&mut a, t + 8, flow, receipt, UdpProbeOutcome::Success).err(),
            Some(ProbeReportError::PathChanged)
        );
        // The rebound flow probes and reports on its new incarnation.
        let receipt = probe(&mut a, t + 9, flow, 1200, v6);
        assert!(report(&mut a, t + 10, flow, receipt, UdpProbeOutcome::Success).is_ok());
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-9
//= type=test
//= reason=Host::udp_report_probe (crates/stacks/ntcp-host/src/udp/receipts.rs) lets an application inform the Host of the outcome of each probe it sent with T13's Probe mode (Host::udp_send_datagram with UdpSendMode::Probe, 4821-158) in the Section 7.6 categories Success, IsolatedLoss, TimeoutFailure and Inconclusive. Receipt capacity (UdpLimits::probe_receipts: the per-flow outstanding-receipt limit, configured once in the Host's UDP configuration under which every flow is opened, without a per-flow override) is reserved before a Probe-mode submission, which is refused with ReceiptsExhausted when none is free; a definite submission yields exactly one opaque single-use ProbeReceipt in its ProbeRecord, bound to Host-retained state (Host instance, flow slot and generation, path incarnation and key, negative and discovery-policy revisions, exact size, submission time), and an uncertain one yields none. A receipt expires at the Host's feedback horizon after submission (twice the configured MSL: the probe and any answer to it are gone from the network by then, the same bound as ICMP correlation), and expired or stale receipts are reclaimed when the flow reserves one, so unreported receipts never exhaust a flow. Replayed, foreign-Host, foreign-flow, replaced-flow, altered, expired, rebound-path and stale-revision (a later decrease or discovery-policy change) reports are rejected. An outcome changes only the reporting flow's own bounds for that path incarnation: Success raises its confirmed size (search_low, eff_pmtu), IsolatedLoss sets its upper bound (search_high) to the probe size minus one (never below the family minimum) and lowers its effective size to it, TimeoutFailure infers no isolation and suppresses that flow's Probe-mode sends at or above the failed size until the failed probe's receipt would have expired, and Inconclusive preserves every bound and permits a same-sized retry. The bounds size that flow's Fragment-mode fragments, min(shared budget, upper bound, max(connectionless initial, adjunct-confirmed, flow-confirmed)), and Host::udp_datagram_limits reports them; Refuse keeps shared-budget admission, and silence and losses never lower shared state. A write to the shared PathService cache requires authority granted by the Host owner (4821-195): only a Success reported with the flow-scoped UdpSharedWriter the owner grants through Host::udp_grant_shared_writer is additionally offered to PathService::confirm_delivery_as under its incarnation, negative-revision, hold and first-hop rules and recorded as owner-trusted application evidence, reported separately from the local effect. Dual-family Host tests (crates/stacks/ntcp-host/src/tests/probe_receipts.rs) cover receipt capacity, expiry, reclamation and every rejection, each outcome's flow-only effect on sizing and reported limits, and owner-authorized publication with its separate result. The integration/rfc_host probe-report case (both families) reports outcomes the application learned from a real Linux receiver: a delivered probe's Success raises only that flow's confirmed size, which then cuts its fragments on the wire, with no shared change; a replayed receipt is refused as Consumed; and a probe a router dropped with a PTB is refused as StaleRevision because the PTB's shared decrease followed the submission.
//# Implementing PLPMTUD in an application also requires a mechanism where the application can inform the operating system about the outcome of the probe as described in Section 7.6, or directly update search_low, search_high, and eff_pmtu, described in Section 7.1.
fn each_outcome_changes_only_the_reporting_flows_bounds_and_sizing() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let mut a = side(local, 9720 + u128::from(v6));
        let flow = a.0.udp_open(&a.1, local, Some(remote), options()).unwrap();
        let neighbor_local = SocketAddr::new(local.ip(), local.port() + 1);
        let neighbor =
            a.0.udp_open(&a.1, neighbor_local, Some(remote), options())
                .unwrap();
        let shared = a.0.udp_path_limits(&a.1, flow, None).unwrap();
        let path = shared.path;
        let initial = if v6 { 1280 } else { 1024 };
        let t = 10 * SECOND;
        let limits = |a: &mut Side, flow| a.0.udp_datagram_limits(&a.1, flow, None, None).unwrap();
        assert_eq!(limits(&mut a, flow).effective_size, initial);
        // Success raises search_low and the flow's fragment size, up to the
        // shared budget (1500 here), and nothing else.
        let receipt = probe(&mut a, t, flow, 1400, v6);
        let result = report(&mut a, t + 1, flow, receipt, UdpProbeOutcome::Success).unwrap();
        assert_eq!(result.shared, SharedOffer::NotOffered);
        assert_eq!(result.bounds.confirmed, Some(1400));
        assert_eq!(result.bounds.path, Some(path));
        assert_eq!(limits(&mut a, flow).effective_size, 1400);
        assert_eq!(limits(&mut a, flow).probe, result.bounds);
        assert!(
            fragment_sizes(&mut a, t + 2, flow)
                .iter()
                .all(|&l| l <= 1400)
        );
        // Every fragment but the last carries a multiple of 8 data octets.
        let header = if v6 { 48 } else { 20 };
        assert_eq!(
            fragment_sizes(&mut a, t + 2, flow)[0],
            header + ((1400 - header) & !7)
        );
        // The neighbor and the shared estimate are unchanged.
        assert_eq!(limits(&mut a, neighbor).effective_size, initial);
        assert!(
            fragment_sizes(&mut a, t + 3, neighbor)
                .iter()
                .all(|&l| l <= initial as usize)
        );
        assert_eq!(a.0.udp_path_limits(&a.1, neighbor, None).unwrap(), shared);
        assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), None);
        assert_eq!(a.0.udp_path_change(neighbor).unwrap(), None);
        // Refuse keeps shared-budget admission.
        assert_eq!(
            limits(&mut a, flow).unfragmented_payload,
            shared.max_payload
        );
        // IsolatedLoss: search_high = size - 1, and the effective size that
        // exceeded it drops to it.
        let receipt = probe(&mut a, t + 4, flow, 1350, v6);
        let result = report(&mut a, t + 5, flow, receipt, UdpProbeOutcome::IsolatedLoss).unwrap();
        assert_eq!(result.bounds.upper, Some(1349));
        assert_eq!(result.bounds.confirmed, Some(1349));
        assert_eq!(limits(&mut a, flow).effective_size, 1349);
        assert!(
            fragment_sizes(&mut a, t + 6, flow)
                .iter()
                .all(|&l| l <= 1349)
        );
        // TimeoutFailure: no bound inferred; probes at or above the size are
        // suppressed until the failed probe's receipt would have expired.
        let receipt = probe(&mut a, t + 7, flow, 1450, v6);
        let until = receipt.expires_at;
        let result = report(
            &mut a,
            t + 8,
            flow,
            receipt,
            UdpProbeOutcome::TimeoutFailure,
        )
        .unwrap();
        assert_eq!(
            (result.bounds.upper, result.bounds.confirmed),
            (Some(1349), Some(1349))
        );
        assert_eq!(
            result.bounds.suppressed,
            Some(RetrySuppression { size: 1450, until })
        );
        assert_eq!(limits(&mut a, flow).effective_size, 1349);
        let (refused, sent) = send(
            &mut a,
            t + 9,
            flow,
            UdpSendMode::Probe,
            1450 - overhead(v6),
            BackendOutcome::Submitted,
        );
        assert_eq!(
            refused.err(),
            Some(DatagramError::RetrySuppressed { size: 1450, until })
        );
        assert!(sent.is_empty());
        // Smaller probes, and other flows, are not suppressed.
        let smaller = probe(&mut a, t + 9, flow, 1440, v6);
        let other = probe(&mut a, t + 9, neighbor, 1450, v6);
        // Inconclusive preserves every bound and allows a same-sized retry.
        let before = limits(&mut a, flow).probe;
        let result = report(&mut a, t + 10, flow, smaller, UdpProbeOutcome::Inconclusive).unwrap();
        assert_eq!(result.bounds, before);
        let _retry = probe(&mut a, t + 11, flow, 1440, v6);
        // The suppression ends at its deadline.
        let receipt = probe(&mut a, until, flow, 1450, v6);
        assert_eq!(limits(&mut a, neighbor).probe, UdpProbeBounds::default());
        // Silence and losses never lower shared state.
        assert!(
            report(
                &mut a,
                until,
                neighbor,
                other,
                UdpProbeOutcome::IsolatedLoss
            )
            .is_ok()
        );
        assert!(
            report(
                &mut a,
                until,
                flow,
                receipt,
                UdpProbeOutcome::TimeoutFailure
            )
            .is_ok()
        );
        assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), None);
        assert_eq!(
            a.0.udp_path_limits(&a.1, flow, None).unwrap().max_payload,
            shared.max_payload
        );
        // The administration query reports each flow's own usable size.
        let capability = a.0.administration();
        let usable: Vec<_> =
            a.0.admin_clients(&capability, &a.1, path)
                .unwrap()
                .filter_map(|c| match c.client {
                    AdminClient::Udp(id) => Some((id, c.usable_ip_packet)),
                    _ => None,
                })
                .collect();
        assert!(usable.contains(&(flow, Some(1349))));
        assert!(usable.contains(&(neighbor, Some(initial))));
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-2
//= type=test
//= reason=PathService is the IP-layer path information cache shared by the Host's packetization protocols. TCP runs its own PLPMTUD, reads the cache through Host::service_changes budget application and updates it with correlated PTBs and with probe-confirmed sizes (a definitely submitted, unfragmented probe selected after the hold whose span the peer acknowledged, published through PathService::confirm_delivery). A correlated TCP report about the connection's current path at or above its proven delivery lowers the cache at once when lower and otherwise restarts its hold; one below proven delivery is deferred whatever the connection's loss-inferred estimate and changes nothing shared until that exact report's quoted-data timeout applies it, when the larger of the Host estimate and the report's own policy-derived size is published; cumulative progress past the quoted data refutes it. The report's derived size never depends on the connection's estimate: a legacy IPv4 report without a Next-Hop MTU is corrected against the Host's shared path estimate, RFC 1191 section 5's current PMTU estimate, never the connection's estimate. Loss-inferred decreases stay connection-local. Host UDP flows read MMS_S and the payload limit (Host::udp_path_limits, Host::udp_path_change), and their source fragments are sized from the shared ordinary budget; they lower the cache only through correlated PTBs quoting their datagrams or fragments. The Host-owned ICMP Echo adjunct is a Host-trusted writer: the forward delivery an exact, timely Echo Reply certifies for a definitely submitted, unfragmented probe is offered to PathService::confirm_delivery under its revision, hold and first-hop rules (4821-183). T13's Probe mode (Host::udp_send_datagram with UdpSendMode::Probe) lets a datagram application send its own probes above the estimate up to the first-hop MTU, unfragmented with IPv4 DF; a probe submission writes nothing shared. Host::udp_report_probe takes the application's outcome for each definitely submitted probe (4821-160): an ordinary flow's report changes only its own search state, whose bounds size that flow's fragments, and an application updates the shared cache only with authority granted by the Host owner (4821-195): a Success reported with the owner-granted, flow-scoped UdpSharedWriter is offered to PathService::confirm_delivery_as under the same revision, hold and first-hop rules and recorded as owner-trusted application evidence. The integration/rfc_host probe-report case reports outcomes observed by a real receiver (4821-160). Each packetization protocol therefore has its own PLPMTUD and the means to access and update the shared cache: TCP directly, a datagram application through Host UDP Probe mode and Host::udp_report_probe (shared writes only with the owner's grant) and the Host's IP fragmentation through its Echo adjunct; dual-family Host tests in crates/stacks/ntcp-host/src/tests/probe_receipts.rs show an ordinary flow's report changing only its own bounds and an owner-granted Success reaching PathService with its separately reported result.
//# Most of the difficulty in implementing PLPMTUD arises because it needs to be implemented in several different places within a single node. In general, each Packetization Protocol needs to have its own implementation of PLPMTUD. Furthermore, the natural mechanism to share Path MTU information between concurrent or subsequent connections is a path information cache in the IP layer. The various Packetization Protocols need to have the means to access and update the shared cache in the IP layer. This memo describes PLPMTUD in terms of its primary subsystems without fully describing how they are assembled into a complete implementation.
fn owner_granted_writer_offers_success_to_the_shared_estimate_separately() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let mut a = side(local, 9730 + u128::from(v6));
        let flow = a.0.udp_open(&a.1, local, Some(remote), options()).unwrap();
        let neighbor_local = SocketAddr::new(local.ip(), local.port() + 1);
        let neighbor =
            a.0.udp_open(&a.1, neighbor_local, Some(remote), options())
                .unwrap();
        let path = a.0.udp_path_limits(&a.1, flow, None).unwrap().path;
        let capability = a.0.administration();
        // A router-taught 1280 with its hold.
        let t = 10 * SECOND;
        a.0.trusted_decrease(t, path, 1280).unwrap();
        a.0.service_changes(&mut a.1, t).unwrap();
        let open = t + HOLD;
        // Only the owner's capability grants a writer, per flow generation.
        let foreign = side(local, 9740 + u128::from(v6)).0.administration();
        assert_eq!(
            a.0.udp_grant_shared_writer(&foreign, flow).err(),
            Some(Error::Unauthorized)
        );
        let writer = a.0.udp_grant_shared_writer(&capability, flow).unwrap();
        let neighbor_writer = a.0.udp_grant_shared_writer(&capability, neighbor).unwrap();
        // Selected one second before the hold expires (reported below).
        let held = probe(&mut a, open - SECOND, flow, 1450, v6);
        // Without the capability a Success stays flow-local.
        let receipt = probe(&mut a, open, flow, 1400, v6);
        let result = report(&mut a, open + 1, flow, receipt, UdpProbeOutcome::Success).unwrap();
        assert_eq!(result.shared, SharedOffer::NotOffered);
        assert_eq!(
            a.0.paths().path_snapshot(path).unwrap().learned_mtu(),
            Some(1280)
        );
        // Another flow's capability is refused and changes nothing; the
        // receipt stays usable.
        let receipt = held;
        let bounds =
            a.0.udp_datagram_limits(&a.1, flow, None, None)
                .unwrap()
                .probe;
        assert_eq!(
            a.0.udp_report_probe(
                open + 2,
                flow,
                receipt,
                UdpProbeOutcome::Success,
                Some(&neighbor_writer)
            )
            .err(),
            Some(ProbeReportError::Unauthorized)
        );
        assert_eq!(
            a.0.udp_datagram_limits(&a.1, flow, None, None)
                .unwrap()
                .probe,
            bounds
        );
        // Selected before the hold expired: the local effect applies and
        // the shared offer is Held, reported separately.
        let result =
            a.0.udp_report_probe(
                open + 2,
                flow,
                receipt,
                UdpProbeOutcome::Success,
                Some(&writer),
            )
            .unwrap();
        assert_eq!(result.bounds.confirmed, Some(1450));
        assert_eq!(
            result.shared,
            SharedOffer::Offered(DeliveryConfirmation::Held)
        );
        assert_eq!(
            a.0.paths().path_snapshot(path).unwrap().learned_mtu(),
            Some(1280)
        );
        // Losses with the capability are never offered.
        let receipt = probe(&mut a, open + 3, flow, 1500, v6);
        let result =
            a.0.udp_report_probe(
                open + 4,
                flow,
                receipt,
                UdpProbeOutcome::TimeoutFailure,
                Some(&writer),
            )
            .unwrap();
        assert_eq!(result.shared, SharedOffer::NotOffered);
        // After the hold: Raised, with owner-trusted application provenance;
        // every other client gets ordinary permission at once.
        let receipt = probe(&mut a, open + 5, flow, 1440, v6);
        let result =
            a.0.udp_report_probe(
                open + 6,
                flow,
                receipt,
                UdpProbeOutcome::Success,
                Some(&writer),
            )
            .unwrap();
        assert_eq!(
            result.shared,
            SharedOffer::Offered(DeliveryConfirmation::Raised)
        );
        assert_eq!(
            a.0.paths().path_snapshot(path).unwrap().learned_mtu(),
            Some(1440)
        );
        let accepted = a.0.admin_path(&capability, path).unwrap().accepted.unwrap();
        assert_eq!(
            (accepted.value, accepted.provenance),
            (1440, EstimateProvenance::OwnerTrustedApplication)
        );
        a.0.service_changes(&mut a.1, open + 6).unwrap();
        let change = a.0.udp_path_change(neighbor).unwrap().unwrap();
        assert_eq!(change.max_payload, 1440 - overhead(v6));
        assert_eq!(
            a.0.udp_datagram_limits(&a.1, neighbor, None, None)
                .unwrap()
                .probe,
            UdpProbeBounds::default()
        );
        // A smaller success is NotLarger; a path-service refusal (an IPv6
        // size below the minimum MTU is no network fact) leaves the local
        // effect standing.
        let small = if v6 { 200 } else { 1300 };
        let receipt = probe(&mut a, open + 7, flow, small, v6);
        let result =
            a.0.udp_report_probe(
                open + 8,
                flow,
                receipt,
                UdpProbeOutcome::Success,
                Some(&writer),
            )
            .unwrap();
        assert_eq!(
            result.shared,
            if v6 {
                SharedOffer::Refused(path::Error::InvalidArgument)
            } else {
                SharedOffer::Offered(DeliveryConfirmation::NotLarger)
            }
        );
        assert_eq!(result.bounds.confirmed, Some(1450));
        // A later trusted decrease is Host-observed again.
        a.0.trusted_decrease(open + 9, path, 1300).unwrap();
        let accepted = a.0.admin_path(&capability, path).unwrap().accepted.unwrap();
        assert_eq!(accepted.provenance, EstimateProvenance::Learned);
        a.0.service_changes(&mut a.1, open + 9).unwrap();
        // Revocation ends the grant (only for the owner's capability); the
        // refused report changes nothing shared and keeps its receipt
        // usable; a reopened flow starts without a grant.
        assert_eq!(
            a.0.udp_revoke_shared_writer(&foreign, flow).err(),
            Some(Error::Unauthorized)
        );
        a.0.udp_revoke_shared_writer(&capability, flow).unwrap();
        let receipt = probe(&mut a, open + 10, flow, 1400, v6);
        let before = a.0.paths().path_snapshot(path).unwrap();
        assert_eq!(
            a.0.udp_report_probe(
                open + 11,
                flow,
                receipt,
                UdpProbeOutcome::Success,
                Some(&writer)
            )
            .err(),
            Some(ProbeReportError::Unauthorized)
        );
        assert_eq!(a.0.paths().path_snapshot(path).unwrap(), before);
        assert_eq!(
            a.0.admin_path(&capability, path).unwrap().accepted.unwrap().provenance,
            EstimateProvenance::Learned
        );
        let flow_only =
            a.0.udp_report_probe(open + 11, flow, receipt, UdpProbeOutcome::Success, None)
                .unwrap();
        assert_eq!(flow_only.shared, SharedOffer::NotOffered);
        assert_eq!(a.0.paths().path_snapshot(path).unwrap(), before);
        a.0.udp_close(flow).unwrap();
        let reopened = a.0.udp_open(&a.1, local, Some(remote), options()).unwrap();
        let receipt = probe(&mut a, open + 12, reopened, 1400, v6);
        assert_eq!(
            a.0.udp_report_probe(
                open + 13,
                reopened,
                receipt,
                UdpProbeOutcome::Success,
                Some(&writer)
            )
            .err(),
            Some(ProbeReportError::Unauthorized)
        );
    }
}
