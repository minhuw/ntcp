// Redirect reception through real Host dispatch: IPv4 Host, Network and
// type-of-service Redirects from the current gateway, ICMPv6 Redirects on an
// ND-capable port (with and without a Target Link-Layer Address, to a
// router or to the destination itself), every rejection, the events that
// end an override, notification of TCP and UDP clients by
// `service_changes`, administrative restrictions kept across the change
// and held output revalidated by the submission barrier.
use super::*;
use alloc::boxed::Box;
use core::net::Ipv6Addr;
use ntcp_icmp::{NeighborAdvertisement, NeighborSolicitation};
use path::{AdminChange, AdminPolicy, AdminTarget};

type Side = (Host, Endpoint, IngressContext);

const SECOND: u64 = 1_000_000;
const UDP: UdpLimits = UdpLimits {
    flows: 1,
    receive_datagrams: 1,
    max_payload: 1500,
    events: 1,
    evicted_signatures: 1,
    probe_receipts: 2,
};

fn v4(address: &str) -> IpAddr {
    address.parse().unwrap()
}
fn unscoped(address: IpAddr) -> ScopedAddress {
    ScopedAddress::new(address, None).unwrap()
}
fn next_hop(side: &Side, id: ConnectionId) -> ResolvedNextHop {
    side.0.binding(id).unwrap().snapshot.key().next_hop()
}
fn endpoint(cfg: &EndpointConfig, identity: u64, owned: IpAddr) -> Endpoint {
    Endpoint::new(cfg.clone(), [identity as u8; 32], 0, move |request| match request {
        ntcp::AddressValidation::Bind { local } | ntcp::AddressValidation::Open { local, .. } => {
            local == owned
        }
        ntcp::AddressValidation::Incoming { destination, .. } => destination == owned,
        ntcp::AddressValidation::Route { source, .. } => source == owned,
    })
    .unwrap()
}

// IPv4: 192.0.2.1 on a link whose embedding resolves IP next hops, with a
// default route through gateway 192.0.2.254 and the connected
// 192.0.2.0/24.
fn gateway_side(identity: u64, cfg: &EndpointConfig, gso: bool) -> Side {
    let local = v4("192.0.2.1");
    let (paths, limits) = managed_limits(cfg, 1, 1, 1, 4, 1).unwrap();
    let (paths, limits) = managed_udp_limits(paths, limits, UDP).unwrap();
    let mut host = Host::new(
        ContextId::new(identity),
        paths,
        limits,
        cfg.connection.timebase,
        [1; 16],
    )
    .unwrap();
    let context = host
        .register_link(
            InterfaceKey(1),
            1500,
            ReceiveCapabilities {
                max_ip_packet: 65575,
                ipv4: Ipv4Receive::Enabled {
                    interpretation: true,
                    source_routes: false,
                },
                ipv6: Ipv6Receive::BaseHeader,
                gro: true,
            },
            Forwarding::IpNextHop,
        )
        .unwrap();
    host.register_source(unscoped(local), context.link()).unwrap();
    for (prefix, length, next_hop) in [
        ("0.0.0.0", 0, path::NextHop::Gateway(unscoped(v4("192.0.2.254")))),
        ("192.0.2.0", 24, path::NextHop::OnLink),
    ] {
        host.add_route(path::Route {
            destination: path::IpPrefix::new(v4(prefix), length).unwrap(),
            source: None,
            dscp: None,
            link: context.link(),
            next_hop,
            metric: 0,
        })
        .unwrap();
    }
    let mut endpoint = endpoint(cfg, identity, local);
    host.attach(&mut endpoint).unwrap();
    if gso {
        endpoint
            .enable_output_reservations_with_gso(
                1,
                ntcp::GsoLimits {
                    max_bytes: 8192,
                    max_segments: 8,
                },
            )
            .unwrap();
    } else {
        endpoint
            .enable_output_reservations_with_capacity(1)
            .unwrap();
    }
    (host, endpoint, context)
}

fn local4() -> SocketAddr {
    "192.0.2.1:1000".parse().unwrap()
}
fn remote4() -> SocketAddr {
    "198.51.100.2:8080".parse().unwrap()
}

// An established connection from the gateway side, with one full data
// segment submitted and lost (outstanding, so the ledger still holds it).
fn ipv4_connection(identity: u64, cfg: &EndpointConfig, dscp: u8) -> (Side, Side, ConnectionId, Vec<u8>) {
    let mut a = gateway_side(identity, cfg, false);
    let mut b = managed(remote4(), identity + 1, cfg.clone());
    let listener = b.1.listen(remote4(), 2).unwrap();
    let id =
        a.1.connect_with_path_provider(0, local4(), remote4(), options(cfg, dscp), &mut a.0)
            .unwrap();
    let mut now = 0;
    pump(&mut a, &mut b, &mut now);
    b.1.accept(listener).unwrap();
    assert_eq!(next_hop(&a, id), ResolvedNextHop::Address(unscoped(v4("192.0.2.254"))));
    a.1.write(id, &[7; 1000]).unwrap();
    let data = emit(&mut a.0, &mut a.1, now + 10).unwrap();
    (a, b, id, data)
}

// An IPv4 Redirect from 192.0.2.254 (the gateway) quoting `frame`.
fn redirect4(frame: &[u8], code: u8, gateway: &str) -> Vec<u8> {
    let IpAddr::V4(gateway) = v4(gateway) else {
        panic!()
    };
    super::dispatch::icmp(frame, (5, code), u32::from(gateway))
}
fn from(mut report: Vec<u8>, source: [u8; 4]) -> Vec<u8> {
    report[12..16].copy_from_slice(&source);
    super::dispatch::seal_ipv4(&mut report);
    report
}
fn dispatch(side: &mut Side, now: u64, report: &[u8]) -> RedirectOutcome {
    match side.0.input_icmp(&mut side.1, side.2, now, report, None).unwrap() {
        IcmpDispatch::Completed(IcmpOutcome::Redirect(outcome)) => outcome,
        other => panic!("{other:?}"),
    }
}

// RFC 1122 section 3.2.2.2 (a host MUST update its routing information on
// a Redirect from its current gateway) and RFC 1191 section 6.3 (the
// packetization layer is notified of the route change): a Host Redirect
// moves the destination, and the next service pass rebinds the TCP
// connection and changes the UDP flow on the same path. A Network Redirect
// updates the same destination only, never a mask's worth of others.
#[test]
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.3
//= type=test
//= reason=T7 PathService invalidates bound paths on route/source/link changes, including shadowing routes, route removal and a source address or egress link that moves to or leaves another interface (ntcp-path tests/lifecycle.rs every_route_mutation_reconsiders_pinned_paths_including_live_shadowed_routes, source_ownership_and_link_deletion_only_revoke_lost_authority, egress_link_removal_and_recreation_never_reuses_a_bound_path). T8 Host rebinds actual native/TUN TCP owners, and T10 Host::service_changes notifies every TCP binding and Host UDP flow of the replacement on the next service pass (a failed rebind stays dirty with bounded backpressure, then converges once the bad route is deleted: failed_client_stays_dirty_while_others_are_served) while the submission barrier refuses held packets the current path no longer carries (dual-family Host and native reservation-race tests). T9 correlation never lets a stale or invalidated path incarnation change an estimate. T18 receives IPv4 and ICMPv6 Redirects, validated against the destination's current first hop, the arrival link and the quoted traffic (the live connection its addresses and ports name, for an IPv4 Redirect only with the quoted sequence in that connection's send window as Linux checks it, or an exact committed submission of a stateless reply or datagram), as bounded overrides beneath the selected administrative route (PathService::redirect); installing or replacing one and each event that ends one (route replacement or removal, link removal, neighbor unreachability, loss of the IPv6 Router flag, eviction) invalidates the affected paths, and Host::service_changes then notifies their TCP and UDP clients (ntcp-path tests/redirect.rs, ntcp-host src/tests/redirect.rs). Namespace evidence (T19, integration/rfc_host redirect cases, IPv4 and IPv6): after a Linux router R1's route to the destination moves to R2 on the shared link, R1's kernel answers the native runtime's next captured submission with a Redirect (its OutRedirects or Icmp6OutRedirects counter rising by the Redirects captured) naming R2 and quoting that submission; the native runtime accepts it, both established TCP flows and a later connection then leave with R2's Ethernet address, ntcp-pathctl shows the replacement path identity, next hop and client membership, a destination outside the Redirect keeps R1, and every stream completes with exact hashes.
//# PMTU estimates may disappear from the routing table if the per-host routes are removed; this can happen in response to an ICMP Redirect message, or because certain routing-table daemons delete old routes after several minutes. Also, on a multi-homed host a topology change may result in the use of a different source interface. When this happens, if the packetization layer is not notified then it may continue to use a cached PMTU value that is now too small. One solution is to notify the packetization layer of a possible PMTU change whenever a Redirect message causes a route change, and whenever a route is simply deleted from the routing table.
fn ipv4_redirects_move_the_destination_and_notify_tcp_and_udp() {
    for code in [1, 0] {
        let cfg = config(2);
        let (mut a, _b, id, data) = ipv4_connection(600 + u64::from(code) * 2, &cfg, 0);
        let flow = a
            .0
            .udp_open(
                &a.1,
                SocketAddr::new(local4().ip(), 5000),
                Some(SocketAddr::new(remote4().ip(), 7)),
                UdpOptions {
                    dscp: 0,
                    hop_limit: 64,
                },
            )
            .unwrap();
        let before = a.0.udp_path_limits(&a.1, flow, None).unwrap();
        assert_eq!(a.0.udp_path_change(flow).unwrap(), None);
        let now = 100 * SECOND;
        // The connection's egress decision holds until the Redirect.
        a.0.refresh(&mut a.1, id).unwrap();
        assert!(a.0.dst_held(&a.1, id));
        assert_eq!(
            dispatch(&mut a, now, &redirect4(&data, code, "192.0.2.253")),
            RedirectOutcome::Installed
        );
        assert!(!a.0.dst_held(&a.1, id));
        let report = a.0.service_changes(&mut a.1, now).unwrap();
        assert_eq!((report.applied, report.failed), (2, 0));
        let moved = ResolvedNextHop::Address(unscoped(v4("192.0.2.253")));
        assert_eq!(next_hop(&a, id), moved);
        let change = a.0.udp_path_change(flow).unwrap().expect("a UDP change");
        assert_ne!(change.path, before.path);
        assert_eq!(
            a.0.paths().path_snapshot(change.path).unwrap().key().next_hop(),
            moved
        );
        // The same destination with another DSCP moves too; another
        // destination of the same route does not.
        let dscp = |host: &Host, remote: &str, dscp: u8| {
            let request = host
                .request(local4().ip(), v4(remote), None, Dscp::new(dscp).unwrap())
                .unwrap();
            host.paths().resolve(request).unwrap().key().next_hop()
        };
        assert_eq!(dscp(&a.0, "198.51.100.2", 46), moved);
        assert_eq!(
            dscp(&a.0, "198.51.100.3", 0),
            ResolvedNextHop::Address(unscoped(v4("192.0.2.254")))
        );
        // The lost segment's retransmission leaves on the new path.
        a.1.on_timeout(now + 5 * SECOND, 32).unwrap();
        let next = emit(&mut a.0, &mut a.1, now + 5 * SECOND).unwrap();
        assert_eq!(next[16..20], data[16..20]);
        assert_eq!(
            a.0.binding(id).unwrap().snapshot.key().next_hop(),
            moved
        );
    }
}

// The type-of-service forms apply to the DSCP the quoted segment was
// submitted with, not to other traffic to the destination.
#[test]
fn ipv4_type_of_service_redirects_use_the_submission_dscp() {
    let cfg = config(2);
    let (mut a, _b, id, data) = ipv4_connection(610, &cfg, 24);
    // A router rewriting the quoted DSCP does not change which traffic
    // moves: the submission's own DSCP is used.
    let mut remarked = data.clone();
    remarked[1] = 46 << 2;
    super::dispatch::seal_ipv4(&mut remarked);
    assert_eq!(
        dispatch(&mut a, SECOND, &redirect4(&remarked, 3, "192.0.2.253")),
        RedirectOutcome::Installed
    );
    a.0.service_changes(&mut a.1, SECOND).unwrap();
    let moved = ResolvedNextHop::Address(unscoped(v4("192.0.2.253")));
    assert_eq!(next_hop(&a, id), moved);
    let resolve = |host: &Host, dscp: u8| {
        let request = host
            .request(local4().ip(), remote4().ip(), None, Dscp::new(dscp).unwrap())
            .unwrap();
        host.paths().resolve(request).unwrap().key().next_hop()
    };
    assert_eq!(resolve(&a.0, 24), moved);
    for other in [0, 46] {
        assert_eq!(
            resolve(&a.0, other),
            ResolvedNextHop::Address(unscoped(v4("192.0.2.254")))
        );
    }
}

// The run's strict reading of RFC 1122 section 3.2.2.2: a forged sender,
// a quote naming no connection of this Host, a new gateway not reached
// directly over the arrival link, a stale route generation and a
// destination reached directly are all refused, changing nothing.
#[test]
fn ipv4_redirect_rejections_change_nothing() {
    use RedirectRejection::*;
    let cfg = config(2);
    let (mut a, _b, id, data) = ipv4_connection(620, &cfg, 0);
    let gateway = ResolvedNextHop::Address(unscoped(v4("192.0.2.254")));
    let revision = a.0.paths().revision();
    let forged = from(redirect4(&data, 1, "192.0.2.253"), [192, 0, 2, 250]);
    assert_eq!(dispatch(&mut a, SECOND, &forged), RedirectOutcome::Rejected(NotFirstHop));
    // Another source port: no connection's traffic.
    let unknown = {
        let mut copy = data.clone();
        copy[20] ^= 0xff;
        redirect4(&copy, 1, "192.0.2.253")
    };
    assert_eq!(
        dispatch(&mut a, SECOND, &unknown),
        RedirectOutcome::Rejected(Uncorrelated)
    );
    // The connection's traffic, but a sequence outside its send window: an
    // off-link forger that guessed the ports (RFC 5927 section 4.1).
    let outside = {
        let mut copy = data.clone();
        copy[24] ^= 0x80;
        redirect4(&copy, 1, "192.0.2.253")
    };
    assert_eq!(
        dispatch(&mut a, SECOND, &outside),
        RedirectOutcome::Rejected(Uncorrelated)
    );
    for off_link in ["203.0.113.1", "192.0.2.1", "255.255.255.255"] {
        assert_eq!(
            dispatch(&mut a, SECOND, &redirect4(&data, 1, off_link)),
            RedirectOutcome::Rejected(Target),
            "{off_link}"
        );
    }
    assert_eq!(a.0.paths().revision(), revision);
    assert_eq!(next_hop(&a, id), gateway);
    // An unknown code is invalid on the wire.
    assert!(
        a.0.input_icmp(&mut a.1, a.2, SECOND, &redirect4(&data, 4, "192.0.2.253"), None)
            .is_err()
    );
    // A replaced route generation: the quoted submission's path is stale.
    let route = a.0.binding(id).unwrap().snapshot.key().route();
    let definition = a.0.paths().route(route).unwrap();
    a.0.replace_route(route, definition).unwrap();
    assert_eq!(
        dispatch(&mut a, SECOND, &redirect4(&data, 1, "192.0.2.253")),
        RedirectOutcome::Rejected(Stale)
    );
    // A connected destination is reached directly: nobody redirects it.
    let direct: SocketAddr = "192.0.2.7:8080".parse().unwrap();
    let other =
        a.1.connect_with_path_provider(2 * SECOND, local4(), direct, options(&cfg, 0), &mut a.0)
            .unwrap();
    a.0.service_changes(&mut a.1, 2 * SECOND).unwrap();
    let syn = loop {
        let frame = emit(&mut a.0, &mut a.1, 2 * SECOND + 1).unwrap();
        if frame[16..20] == [192, 0, 2, 7] {
            break frame;
        }
    };
    assert_eq!(
        next_hop(&a, other),
        ResolvedNextHop::Address(unscoped(direct.ip()))
    );
    for sender in [[192, 0, 2, 254], [192, 0, 2, 7]] {
        assert_eq!(
            dispatch(&mut a, 3 * SECOND, &from(redirect4(&syn, 1, "192.0.2.253"), sender)),
            RedirectOutcome::Rejected(NotFirstHop)
        );
    }
}

// Route and exact-path administrative restrictions hold across the
// forwarding change, and a frame held across it meets the submission
// barrier: the scalar, shared-payload and software-GSO output selected
// before the Redirect is refused and sent again through the new gateway.
#[test]
fn ipv4_redirect_keeps_restrictions_and_revalidates_held_output() {
    let cfg = config(2);
    let (mut a, _b, id, data) = ipv4_connection(630, &cfg, 0);
    let capability = a.0.administration();
    let path = a.0.binding(id).unwrap().snapshot.path();
    let route = a.0.binding(id).unwrap().snapshot.key().route();
    for (target, policy) in [
        (
            AdminTarget::Route(route),
            AdminPolicy {
                discovery_disabled: false,
                estimate: Some(1300),
            },
        ),
        (
            AdminTarget::Path(path),
            AdminPolicy {
                discovery_disabled: false,
                estimate: Some(1200),
            },
        ),
    ] {
        let change = AdminChange {
            target,
            expected: 0,
            policy,
        };
        let candidate = a.0.admin_validate(&capability, SECOND, change).unwrap();
        a.0.admin_apply(&capability, &mut a.1, candidate).unwrap();
    }
    let restricted = a.0.binding(id).unwrap().snapshot;
    assert_eq!(restricted.administrative_estimate(), Some(1200));
    assert_eq!(restricted.pmtu_estimate(), Ok(1200));
    // A retransmission selected and held before the Redirect.
    a.1.on_timeout(5 * SECOND, 32).unwrap();
    let (attempt, _, frame) = selected(&mut a.1, 5 * SECOND).unwrap();
    let held = a.0.egress_context(&mut a.1, attempt).unwrap();
    assert_eq!(
        dispatch(&mut a, 5 * SECOND, &redirect4(&data, 1, "192.0.2.253")),
        RedirectOutcome::Installed
    );
    assert_eq!(
        a.0.validate_egress(&mut a.1, held, &frame, 0),
        Err(Error::Obsolete)
    );
    let current = a.0.egress_context(&mut a.1, attempt).unwrap();
    let snapshot = current.binding.snapshot;
    assert_eq!(
        snapshot.key().next_hop(),
        ResolvedNextHop::Address(unscoped(v4("192.0.2.253")))
    );
    assert_eq!(snapshot.key().route(), route);
    assert_eq!(snapshot.administrative_estimate(), Some(1200));
    assert_eq!(snapshot.pmtu_estimate(), restricted.pmtu_estimate());
    // Renewed forwarding fabricates no delivery proof.
    assert!(snapshot.learned_mtu() <= restricted.learned_mtu());
    let owner = a.0.admin_path(&capability, snapshot.path()).unwrap();
    assert_eq!(owner.policy.estimate, Some(1200));
    assert_eq!(owner.route_policy.unwrap().estimate, Some(1300));
    // The rebound connection starts the new incarnation from its own
    // conservative budget (no delivery proof carries over), so the held
    // segment is refused there too and re-segmented within it.
    assert!(a.1.managed_path(id).unwrap().ordinary_ip_budget < frame.len() as u32);
    assert_eq!(
        a.0.validate_egress(&mut a.1, current, &frame, 0),
        Err(Error::Obsolete)
    );
    a.1.reject_unsubmitted(attempt).unwrap();
    a.1.on_timeout(10 * SECOND, 32).unwrap();
    let frame = emit(&mut a.0, &mut a.1, 10 * SECOND).unwrap();
    assert!(frame.len() <= 1200);
    assert_eq!(next_hop(&a, id), snapshot.key().next_hop());
}

#[test]
fn ipv4_redirect_revalidates_held_shared_and_gso_output() {
    let mut cfg = config(4);
    cfg.connection.pmtud.as_mut().unwrap().initial_search_low = Some(1500);
    // Shared payload.
    let mut a = gateway_side(640, &cfg, false);
    let mut b = managed(remote4(), 641, cfg.clone());
    b.1.listen(remote4(), 2).unwrap();
    let id =
        a.1.connect_with_path_provider(0, local4(), remote4(), options(&cfg, 0), &mut a.0)
            .unwrap();
    let mut now = 0;
    pump(&mut a, &mut b, &mut now);
    a.1.enable_shared_output(4).unwrap();
    a.1.write_shared(id, ntcp::Payload::from_vec(vec![7; 4000]), false, true, None)
        .unwrap();
    let mut parts = Vec::with_capacity(4);
    let mut tcp = [0; 2048];
    let (poll, attempt) =
        a.1.poll_reserved_transmit_shared_for(now + 10, id, &mut tcp, &mut parts, 32)
            .unwrap();
    let packet = poll.packet.unwrap();
    let attempt = attempt.unwrap();
    let payload: usize = parts.iter().map(ntcp::Payload::len).sum();
    let header = packet.len - payload;
    let mut frame = vec![0; 2108];
    frame[20..20 + header].copy_from_slice(&tcp[..header]);
    let n = ntcp_ip::encode_shared_header(&mut frame, packet, 123, header).unwrap();
    frame.truncate(n);
    let held = a.0.egress_context(&mut a.1, attempt).unwrap();
    let mut whole = frame.clone();
    for part in &parts {
        whole.extend_from_slice(part.as_slice());
    }
    // An earlier committed segment is the Redirect's evidence.
    let ticket = a.0.submission_ticket(&mut a.1, held).unwrap();
    assert!(
        a.0.submit(&mut a.1, now + 10, ticket, held, &frame, payload, |_| {
            BackendOutcome::Submitted
        })
        .unwrap()
            == Submission::Submitted
    );
    a.0.collect(&a.1).unwrap();
    let (poll, attempt) =
        a.1.poll_reserved_transmit_shared_for(now + 11, id, &mut tcp, &mut parts, 32)
            .unwrap();
    let packet = poll.packet.unwrap();
    let attempt = attempt.unwrap();
    let payload: usize = parts.iter().map(ntcp::Payload::len).sum();
    let header = packet.len - payload;
    let mut frame = vec![0; 2108];
    frame[20..20 + header].copy_from_slice(&tcp[..header]);
    let n = ntcp_ip::encode_shared_header(&mut frame, packet, 123, header).unwrap();
    frame.truncate(n);
    let held = a.0.egress_context(&mut a.1, attempt).unwrap();
    a.0.validate_egress(&mut a.1, held, &frame, payload).unwrap();
    assert_eq!(
        dispatch(&mut a, now + 12, &redirect4(&whole, 1, "192.0.2.253")),
        RedirectOutcome::Installed
    );
    assert_eq!(
        a.0.validate_egress(&mut a.1, held, &frame, payload),
        Err(Error::Obsolete)
    );
    let current = a.0.egress_context(&mut a.1, attempt).unwrap();
    assert_eq!(
        current.binding.snapshot.key().next_hop(),
        ResolvedNextHop::Address(unscoped(v4("192.0.2.253")))
    );
    a.0.validate_egress(&mut a.1, current, &frame, payload).unwrap();

    // Software GSO: a partial aggregate held across the Redirect.
    let mut a = gateway_side(650, &cfg, true);
    let mut b = managed(remote4(), 651, cfg.clone());
    b.1.listen(remote4(), 2).unwrap();
    let id =
        a.1.connect_with_path_provider(0, local4(), remote4(), options(&cfg, 0), &mut a.0)
            .unwrap();
    let mut now = 0;
    pump(&mut a, &mut b, &mut now);
    a.1.write(id, &[9; 6000]).unwrap();
    let (first, _, frame) = selected(&mut a.1, now + 10).unwrap();
    let group = a.1.transmit_segmentation(first).expect("a GSO reservation");
    assert!(group.payload_len > group.segment_payload_len);
    let context = a.0.egress_context(&mut a.1, first).unwrap();
    let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
    assert!(
        a.0.submit(&mut a.1, now + 10, ticket, context, &frame, 0, |_| {
            BackendOutcome::Submitted
        })
        .unwrap()
            == Submission::Submitted
    );
    a.0.collect(&a.1).unwrap();
    let (held_attempt, _, held_frame) = selected(&mut a.1, now + 12).unwrap();
    let held = a.0.egress_context(&mut a.1, held_attempt).unwrap();
    assert_eq!(
        dispatch(&mut a, now + 13, &redirect4(&frame, 1, "192.0.2.253")),
        RedirectOutcome::Installed
    );
    assert_eq!(
        a.0.validate_egress(&mut a.1, held, &held_frame, 0),
        Err(Error::Obsolete)
    );
    let current = a.0.egress_context(&mut a.1, held_attempt).unwrap();
    assert_eq!(
        current.binding.snapshot.key().next_hop(),
        ResolvedNextHop::Address(unscoped(v4("192.0.2.253")))
    );
    a.0.validate_egress(&mut a.1, current, &held_frame, 0).unwrap();
}

// IPv6 on an ND-capable port: 2001:db8::10 with a default route through
// the link-local router fe80::1.
const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];
const R1: [u8; 6] = [2, 0, 0, 0, 0, 0x11];
const R2: [u8; 6] = [2, 0, 0, 0, 0, 0x12];
const PEER: [u8; 6] = [2, 0, 0, 0, 0, 0x0d];

fn v6(address: &str) -> Ipv6Addr {
    address.parse().unwrap()
}
fn local6() -> SocketAddr {
    "[2001:db8::10]:1000".parse().unwrap()
}
fn remote6() -> SocketAddr {
    "[2001:db8:1::7]:8080".parse().unwrap()
}
fn nd_receive() -> ReceiveCapabilities {
    ReceiveCapabilities {
        max_ip_packet: 65575,
        ipv4: Ipv4Receive::Disabled,
        ipv6: Ipv6Receive::Extensions,
        gro: false,
    }
}

fn nd_side(identity: u64, cfg: &EndpointConfig) -> Side {
    nd_side_with(identity, cfg, IcmpOutputLimits::default())
}
fn nd_side_with(identity: u64, cfg: &EndpointConfig, output: IcmpOutputLimits) -> Side {
    let (paths, mut limits) = managed_limits(cfg, 2, 2, 2, 2, 0).unwrap();
    limits.neighbors = NeighborLimits {
        entries: 4,
        pending_packets: 4,
        addresses: 2,
        answers: 2,
    };
    let (paths, limits) = managed_udp_limits(paths, limits, UDP).unwrap();
    let (paths, limits) = managed_icmp_output_limits(paths, limits, output).unwrap();
    let mut host = Host::new(
        ContextId::new(identity),
        paths,
        limits,
        cfg.connection.timebase,
        [1; 16],
    )
    .unwrap();
    host.set_entropy(Box::new(|out: &mut [u8]| {
        out.fill(0);
        out[0] = 0x80;
        Ok(())
    }));
    let port = NdPort {
        dad_transmits: 0,
        ..NdPort::new(OWN)
    };
    let context = host
        .register_neighbor_port(InterfaceKey(1), 1500, nd_receive(), port)
        .unwrap();
    let link = context.link();
    assert_eq!(
        host.add_neighbor_address(link, v6("2001:db8::10")),
        Ok(AddressState::Assigned)
    );
    let router = ScopedAddress::new(IpAddr::V6(v6("fe80::1")), Some(link)).unwrap();
    host.add_route(path::Route {
        destination: path::IpPrefix::new("::".parse().unwrap(), 0).unwrap(),
        source: None,
        dscp: None,
        link,
        next_hop: path::NextHop::Gateway(router),
        metric: 0,
    })
    .unwrap();
    let mut endpoint = endpoint(cfg, identity, local6().ip());
    host.attach(&mut endpoint).unwrap();
    endpoint
        .enable_output_reservations_with_capacity(1)
        .unwrap();
    (host, endpoint, context)
}

// One ICMPv6 packet as it arrives with Hop Limit 255.
fn arriving(source: Ipv6Addr, destination: Ipv6Addr, message: &[u8]) -> Vec<u8> {
    let header = ntcp_ip6::Header {
        ip: IpMetadata {
            source: IpAddr::V6(source),
            destination: IpAddr::V6(destination),
        },
        hop_limit: 255,
        dscp: 0,
        ecn: 0,
    };
    let mut out = vec![0; 40 + message.len()];
    out[40..].copy_from_slice(message);
    ntcp_ip6::encode_datagram(&mut out, header, 58, message.len()).unwrap();
    out
}
fn receive(side: &mut Side, now: u64, frame: &[u8]) -> Result<bool, Error> {
    let mut out = [0; 2048];
    side.0
        .receive(side.2, now, frame, false, &mut out)
        .map(|r| matches!(r, Received::Neighbor))
}
// A Redirect's outcome through physical input.
fn redirected(side: &mut Side, now: u64, frame: &[u8]) -> Result<RedirectOutcome, Error> {
    let mut out = [0; 2048];
    match side.0.receive(side.2, now, frame, false, &mut out)? {
        Received::Redirect(outcome) => Ok(outcome),
        _ => panic!("not consumed as a Redirect"),
    }
}
// The router learns its mapping by soliciting this host's address.
fn learn_router(side: &mut Side, router: Ipv6Addr, mac: [u8; 6], now: u64) {
    let target = v6("2001:db8::10");
    let group = ntcp_ethernet::solicited_node(target);
    let ip = IpMetadata {
        source: IpAddr::V6(router),
        destination: IpAddr::V6(group),
    };
    let mut message = [0; 32];
    let ns = NeighborSolicitation {
        target,
        source_link_layer: Some(mac),
    };
    let len = ntcp_icmp::encode_solicitation(ip, ns, &mut message).unwrap();
    assert_eq!(receive(side, now, &arriving(router, group, &message[..len])), Ok(true));
}
// Submit the next segment (after its timers at `now`) through its
// resolved neighbor; None while that neighbor is resolved.
fn send6(side: &mut Side, now: u64) -> Option<([u8; 6], Vec<u8>)> {
    side.1.on_timeout(now, 32).unwrap();
    let (attempt, packet, frame) = selected(&mut side.1, now).expect("a segment");
    let context = side.0.egress_context(&mut side.1, attempt).unwrap();
    let owner = Owner::Tcp(packet.connection.unwrap());
    let NeighborHop::Resolved(mac) = side.0.resolve_neighbor(context, owner, now).unwrap() else {
        side.1.reject_unsubmitted(attempt).unwrap();
        return None;
    };
    let ticket = side.0.submission_ticket(&mut side.1, context).unwrap();
    let submitted = side
        .0
        .submit(&mut side.1, now, ticket, context, &frame, 0, |_| {
            BackendOutcome::Submitted
        })
        .unwrap();
    assert!(submitted == Submission::Submitted);
    side.0.collect(&side.1).unwrap();
    Some((mac, frame))
}
// An ICMPv6 Redirect from `router` to this host: `target` for
// `destination`, with a Target Link-Layer Address and a Redirected Header
// quoting `quoted` when given.
fn redirect6(
    router: Ipv6Addr,
    target: Ipv6Addr,
    destination: Ipv6Addr,
    mac: Option<[u8; 6]>,
    quoted: Option<&[u8]>,
) -> Vec<u8> {
    let own = v6("2001:db8::10");
    let mut m = vec![137, 0, 0, 0, 0, 0, 0, 0];
    m.extend_from_slice(&target.octets());
    m.extend_from_slice(&destination.octets());
    if let Some(mac) = mac {
        m.extend_from_slice(&[2, 1]);
        m.extend_from_slice(&mac);
    }
    if let Some(quoted) = quoted {
        let len = quoted.len() / 8 * 8;
        m.extend_from_slice(&[4, (1 + len / 8) as u8, 0, 0, 0, 0, 0, 0]);
        m.extend_from_slice(&quoted[..len]);
    }
    let ip = IpMetadata {
        source: IpAddr::V6(router),
        destination: IpAddr::V6(own),
    };
    let sum = ntcp_icmp::icmpv6_checksum(ip, &m).unwrap();
    m[2..4].copy_from_slice(&sum.to_be_bytes());
    arriving(router, own, &m)
}
fn scoped(side: &Side, address: &str) -> ResolvedNextHop {
    ResolvedNextHop::Address(
        ScopedAddress::new(IpAddr::V6(v6(address)), Some(side.2.link())).unwrap(),
    )
}

// A connection through fe80::1 whose SYN was submitted to its mapping.
fn ipv6_connection(identity: u64) -> (Side, ConnectionId, Vec<u8>) {
    let cfg = config(2);
    let mut a = nd_side(identity, &cfg);
    learn_router(&mut a, v6("fe80::1"), R1, 0);
    let id =
        a.1.connect_with_path_provider(0, local6(), remote6(), options(&cfg, 0), &mut a.0)
            .unwrap();
    let (mac, syn) = send6(&mut a, 1).unwrap();
    assert_eq!(mac, R1);
    assert_eq!(next_hop(&a, id), scoped(&a, "fe80::1"));
    (a, id, syn)
}

// A Redirect's Target Link-Layer Address that resolves a neighbor holding
// Host ICMP output settles it at once, as an advertisement does: the
// bounded pending slot is free again and the message leaves to the
// learned address.
#[test]
fn ipv6_redirect_mapping_settles_held_icmp_output() {
    let cfg = config(2);
    let output = IcmpOutputLimits {
        messages: 2,
        message_bytes: 1280,
        hop_limit: 64,
    };
    let mut a = nd_side_with(730, &cfg, output);
    let link = a.2.link();
    learn_router(&mut a, v6("fe80::1"), R1, 0);
    let second = ScopedAddress::new(IpAddr::V6(v6("fe80::2")), Some(link)).unwrap();
    a.0.add_route(path::Route {
        destination: path::IpPrefix::new("2001:db8:2::".parse().unwrap(), 64).unwrap(),
        source: None,
        dscp: None,
        link,
        next_hop: path::NextHop::Gateway(second),
        metric: 0,
    })
    .unwrap();
    a.1.connect_with_path_provider(0, local6(), remote6(), options(&cfg, 0), &mut a.0)
        .unwrap();
    let (_, syn) = send6(&mut a, 1).unwrap();
    // An Echo Reply through fe80::2 waits for its resolution.
    let peer = v6("2001:db8:2::5");
    let ip = IpMetadata {
        source: IpAddr::V6(peer),
        destination: IpAddr::V6(v6("2001:db8::10")),
    };
    let mut message = [0; 16];
    let n =
        ntcp_icmp::encode_echo(ip, ntcp_icmp::EchoKind::Request, 7, 1, &mut message, 8).unwrap();
    let frame = arriving(peer, v6("2001:db8::10"), &message[..n]);
    a.0.input_ip(
        &mut a.1,
        a.2,
        2,
        &frame,
        RxPacketMetadata::default(),
        0,
        None,
    )
    .unwrap();
    let mut sent = None;
    let mut drain = |a: &mut Side, now| {
        let mut packet = vec![0; 2048];
        let _ = a.0.icmp_output(now, &mut packet, |egress, bytes| {
            let ip = ntcp_ip6::parse(bytes).unwrap().ip;
            sent = Some((egress.link_layer, ip.destination));
            BackendOutcome::Submitted
        });
        sent.take()
    };
    assert_eq!(drain(&mut a, 2), None);
    assert_eq!(a.0.icmp_output_pending(), 1);
    assert_eq!(
        a.0.neighbor(link, v6("fe80::2")),
        Some((NeighborState::Incomplete, None, false))
    );
    let held = |a: &Side| {
        (0..a.0.neighbors.pending_slots())
            .filter(|&slot| a.0.neighbors.pending_at(slot).is_some())
            .count()
    };
    assert_eq!(held(&a), 1);
    let redirect = redirect6(
        v6("fe80::1"),
        v6("fe80::2"),
        v6("2001:db8:1::7"),
        Some(R2),
        Some(&syn),
    );
    assert_eq!(
        redirected(&mut a, 3, &redirect),
        Ok(RedirectOutcome::Installed)
    );
    assert_eq!(
        a.0.neighbor(link, v6("fe80::2")),
        Some((NeighborState::Stale, Some(R2), true))
    );
    assert_eq!(held(&a), 0);
    assert_eq!(drain(&mut a, 4), Some((Some(R2), IpAddr::V6(peer))));
    assert_eq!(a.0.icmp_output_counters().unsent, 0);
}

// RFC 4861 section 8.3: a Redirect to a better router with its Target
// Link-Layer Address moves the destination, installs the router STALE
// with IsRouter set, and the retransmitted SYN leaves at its mapping.
#[test]
fn ipv6_redirect_to_a_router_with_its_link_layer_address() {
    let (mut a, id, syn) = ipv6_connection(700);
    let destination = v6("2001:db8:1::7");
    let flow = a
        .0
        .udp_open(
            &a.1,
            SocketAddr::new(local6().ip(), 5000),
            Some(SocketAddr::new(remote6().ip(), 7)),
            UdpOptions {
                dscp: 0,
                hop_limit: 64,
            },
        )
        .unwrap();
    let redirect = redirect6(v6("fe80::1"), v6("fe80::2"), destination, Some(R2), Some(&syn));
    assert_eq!(
        redirected(&mut a, 2, &redirect),
        Ok(RedirectOutcome::Installed)
    );
    let link = a.2.link();
    assert_eq!(
        a.0.neighbor(link, v6("fe80::2")),
        Some((NeighborState::Stale, Some(R2), true))
    );
    let report = a.0.service_changes(&mut a.1, 3).unwrap();
    assert_eq!((report.applied, report.failed), (2, 0));
    assert_eq!(next_hop(&a, id), scoped(&a, "fe80::2"));
    let change = a.0.udp_path_change(flow).unwrap().expect("a UDP change");
    assert_eq!(
        a.0.paths().path_snapshot(change.path).unwrap().key().next_hop(),
        scoped(&a, "fe80::2")
    );
    // The SYN's retransmission goes to the new router.
    let (mac, again) = send6(&mut a, 2 * SECOND).unwrap();
    assert_eq!(mac, R2);
    assert_eq!(again[24..40], syn[24..40]);
    // An advertisement clearing its Router flag ends the override: the
    // destination returns to the configured router.
    let na = NeighborAdvertisement {
        router: false,
        solicited: false,
        override_: true,
        target: v6("fe80::2"),
        target_link_layer: Some(R2),
    };
    let ip = IpMetadata {
        source: IpAddr::V6(v6("fe80::2")),
        destination: IpAddr::V6(v6("2001:db8::10")),
    };
    let mut message = [0; 32];
    let len = ntcp_icmp::encode_advertisement(ip, na, &mut message).unwrap();
    let frame = arriving(v6("fe80::2"), v6("2001:db8::10"), &message[..len]);
    assert_eq!(receive(&mut a, 3 * SECOND, &frame), Ok(true));
    a.0.service_changes(&mut a.1, 3 * SECOND).unwrap();
    assert_eq!(next_hop(&a, id), scoped(&a, "fe80::1"));
}

// Without a Target Link-Layer Address the router target is still a
// router (section 8.3 MUST) once resolution creates its entry; when its
// resolution fails, the override ends with it. A target equal to the
// destination makes the destination on-link (a non-router entry, created
// STALE from its link-layer address).
#[test]
fn ipv6_redirect_without_a_mapping_and_to_the_destination() {
    let (mut a, id, syn) = ipv6_connection(710);
    let destination = v6("2001:db8:1::7");
    let link = a.2.link();
    let redirect = redirect6(v6("fe80::1"), v6("fe80::2"), destination, None, Some(&syn));
    assert_eq!(
        redirected(&mut a, 2, &redirect),
        Ok(RedirectOutcome::Installed)
    );
    assert_eq!(a.0.neighbor(link, v6("fe80::2")), None);
    a.0.service_changes(&mut a.1, 3).unwrap();
    assert_eq!(next_hop(&a, id), scoped(&a, "fe80::2"));
    // Resolution of the new router: held, its entry a router.
    assert!(send6(&mut a, 2 * SECOND).is_none());
    assert_eq!(
        a.0.neighbor(link, v6("fe80::2")),
        Some((NeighborState::Incomplete, None, true))
    );
    // Its three solicitations (after the answer to the first router's
    // solicitation), then failure a RetransTimer after the last.
    let mut now = 2 * SECOND;
    let mut out = [0; 128];
    for _ in 0..3 {
        while let Some(transmit) = a.0.neighbor_output(link, now, &mut out).unwrap() {
            a.0.complete_neighbor_output(transmit.ticket, BackendOutcome::Submitted, now)
                .unwrap();
        }
        now += SECOND;
    }
    a.0.service_neighbors(now);
    assert_eq!(a.0.neighbor(link, v6("fe80::2")), None);
    // Its failure ends the override.
    a.0.service_changes(&mut a.1, now).unwrap();
    assert_eq!(next_hop(&a, id), scoped(&a, "fe80::1"));
    while a.0.neighbor_wake().is_some() {}

    // The destination itself as target.
    let (mut a, id, syn) = ipv6_connection(720);
    let redirect = redirect6(v6("fe80::1"), destination, destination, Some(PEER), Some(&syn));
    assert_eq!(
        redirected(&mut a, 2, &redirect),
        Ok(RedirectOutcome::Installed)
    );
    let link = a.2.link();
    assert_eq!(
        a.0.neighbor(link, destination),
        Some((NeighborState::Stale, Some(PEER), false))
    );
    a.0.service_changes(&mut a.1, 3).unwrap();
    assert_eq!(
        next_hop(&a, id),
        ResolvedNextHop::Address(unscoped(IpAddr::V6(destination)))
    );
    let (mac, _) = send6(&mut a, 2 * SECOND).unwrap();
    assert_eq!(mac, PEER);
}

// Every rejection, with the decoder's result handed to the Host's
// validator: no Redirected Header (this Host's evidence policy), a quote
// naming no connection, a Destination other than the quoted packet's,
// a sender other than the current router, another arrival link, and a
// replaced route generation. None changes forwarding or the cache.
#[test]
fn ipv6_redirect_rejections_change_nothing() {
    use RedirectRejection::*;
    let (mut a, id, syn) = ipv6_connection(730);
    let destination = v6("2001:db8:1::7");
    let second = a
        .0
        .register_neighbor_port(
            InterfaceKey(2),
            1500,
            nd_receive(),
            NdPort {
                dad_transmits: 0,
                ..NdPort::new([2, 0, 0, 0, 0, 2])
            },
        )
        .unwrap();
    // Another source port: no connection's traffic.
    let mut unknown = syn.clone();
    unknown[40] ^= 0xff;
    let revision = a.0.paths().revision();
    for (router, target, dest, quoted, context, rejection) in [
        ("fe80::1", "fe80::2", destination, None, a.2, NoEvidence),
        ("fe80::1", "fe80::2", destination, Some(&unknown[..]), a.2, Uncorrelated),
        ("fe80::1", "fe80::2", v6("2001:db8:1::8"), Some(&syn[..]), a.2, Destination),
        ("fe80::9", "fe80::2", destination, Some(&syn[..]), a.2, NotFirstHop),
        ("fe80::1", "fe80::2", destination, Some(&syn[..]), second, WrongLink),
    ] {
        let frame = redirect6(v6(router), v6(target), dest, Some(R2), quoted);
        let packet = ntcp_ip6::parse(&frame).unwrap();
        let decoded = ntcp_icmp::decode_ipv6_redirect(packet.ip, 255, packet.payload).unwrap();
        assert_eq!(
            a.0.redirect_ipv6(context, 2, v6(router), decoded),
            Ok(RedirectOutcome::Rejected(rejection)),
            "{rejection:?}"
        );
        // Through physical input too.
        if context == a.2 {
            assert_eq!(
                redirected(&mut a, 2, &frame),
                Ok(RedirectOutcome::Rejected(rejection))
            );
        }
    }
    assert_eq!(a.0.paths().revision(), revision);
    assert_eq!(a.0.neighbor(a.2.link(), v6("fe80::2")), None);
    // A forwarded Redirect is invalid on the wire.
    let mut forwarded = redirect6(v6("fe80::1"), v6("fe80::2"), destination, None, Some(&syn));
    forwarded[7] = 254;
    assert!(receive(&mut a, 2, &forwarded).is_err());
    // A replaced route generation.
    let route = a.0.binding(id).unwrap().snapshot.key().route();
    let definition = a.0.paths().route(route).unwrap();
    a.0.replace_route(route, definition).unwrap();
    let frame = redirect6(v6("fe80::1"), v6("fe80::2"), destination, Some(R2), Some(&syn));
    let packet = ntcp_ip6::parse(&frame).unwrap();
    let decoded = ntcp_icmp::decode_ipv6_redirect(packet.ip, 255, packet.payload).unwrap();
    assert_eq!(
        a.0.redirect_ipv6(a.2, 3, v6("fe80::1"), decoded),
        Ok(RedirectOutcome::Rejected(Stale))
    );
}

// Two connections to one destination submitted with DSCP 0 and DSCP 24,
// each with one full data segment submitted and lost; returns their
// identifiers and those segments.
fn ipv4_dscp_pair(
    identity: u64,
    cfg: &EndpointConfig,
    dscp: u8,
) -> (Side, Side, [(ConnectionId, Vec<u8>); 2]) {
    let mut a = gateway_side(identity, cfg, false);
    let mut b = managed(remote4(), identity + 1, cfg.clone());
    let listener = b.1.listen(remote4(), 2).unwrap();
    let plain =
        a.1.connect_with_path_provider(0, local4(), remote4(), options(cfg, 0), &mut a.0)
            .unwrap();
    let marked =
        a.1.connect_with_path_provider(
            0,
            "192.0.2.1:1001".parse().unwrap(),
            remote4(),
            options(cfg, dscp),
            &mut a.0,
        )
        .unwrap();
    let mut now = 0;
    pump(&mut a, &mut b, &mut now);
    b.1.accept(listener).unwrap();
    b.1.accept(listener).unwrap();
    a.1.write(plain, &[7; 1000]).unwrap();
    a.1.write(marked, &[8; 1000]).unwrap();
    let mut frames = [None, None];
    while let Some(frame) = emit(&mut a.0, &mut a.1, now + 10) {
        let index = usize::from(frame[1] >> 2 == dscp);
        frames[index] = Some(frame);
    }
    let [Some(p), Some(m)] = frames else {
        panic!("both segments")
    };
    (a, b, [(plain, p), (marked, m)])
}
// The next retransmission of each connection, after its RTO at `now`.
fn retransmissions(a: &mut Side, now: u64, dscp: u8) -> [Vec<u8>; 2] {
    a.1.on_timeout(now, 32).unwrap();
    let mut frames = [None, None];
    while let Some(frame) = emit(&mut a.0, &mut a.1, now) {
        let index = usize::from(frame[1] >> 2 == dscp);
        frames[index].get_or_insert(frame);
    }
    frames.map(|frame| frame.expect("a retransmission"))
}

// RFC 1122 section 3.2.2.2 over a sequence of Redirects: the
// type-of-service forms (codes 2 and 3) move only the DSCP the quoted
// segment was submitted with; the forms for every type of service (codes 0
// and 1) move every DSCP whose first hop is the sender, whether that first
// hop is the configured gateway or the target of an earlier override.
// A Redirect is about the connection its quote names, which keeps no record
// of the first hop each segment left through: the connection's current
// first hop may quote a segment sent through the replaced one, while the
// replaced first hop is refused.
#[test]
fn ipv4_redirect_sequences_follow_each_dscp_first_hop() {
    for (specific, general) in [(2, 1), (3, 0)] {
        let cfg = config(2);
        let (mut a, _b, [(plain, data0), (marked, data24)]) =
            ipv4_dscp_pair(660 + u64::from(specific) * 2, &cfg, 24);
        let gateway = ResolvedNextHop::Address(unscoped(v4("192.0.2.254")));
        let hop = |address| ResolvedNextHop::Address(unscoped(v4(address)));
        let other = |a: &Side| {
            let request =
                a.0.request(local4().ip(), remote4().ip(), None, Dscp::new(46).unwrap())
                    .unwrap();
            a.0.paths().resolve(request).unwrap().key().next_hop()
        };
        let state = |a: &Side| (next_hop(a, plain), next_hop(a, marked), other(a));
        assert_eq!(state(&a), (gateway, gateway, gateway));

        // The gateway moves DSCP 24 alone to 192.0.2.253.
        let mut now = SECOND;
        assert_eq!(
            dispatch(&mut a, now, &redirect4(&data24, specific, "192.0.2.253")),
            RedirectOutcome::Installed
        );
        a.0.service_changes(&mut a.1, now).unwrap();
        assert_eq!(state(&a), (gateway, hop("192.0.2.253"), gateway));
        // The gateway is no first hop of DSCP 24 any more.
        let revision = a.0.paths().revision();
        assert!(matches!(
            dispatch(&mut a, now, &redirect4(&data24, general, "192.0.2.252")),
            RedirectOutcome::Rejected(_)
        ));
        assert_eq!(a.0.paths().revision(), revision);
        assert_eq!(state(&a), (gateway, hop("192.0.2.253"), gateway));

        // 192.0.2.253's Redirect for every type of service moves only
        // DSCP 24: it is the first hop of nothing else. It quotes the
        // segment sent through the gateway, which names the connection now
        // leaving through 192.0.2.253 as well as its retransmission would.
        now += 10 * SECOND;
        let [_, again24] = retransmissions(&mut a, now, 24);
        assert_eq!(again24[1] >> 2, 24);
        let report = from(redirect4(&data24, general, "192.0.2.252"), [192, 0, 2, 253]);
        assert_eq!(dispatch(&mut a, now, &report), RedirectOutcome::Installed);
        a.0.service_changes(&mut a.1, now).unwrap();
        assert_eq!(state(&a), (gateway, hop("192.0.2.252"), gateway));

        // The gateway's Redirect for every type of service, quoting the
        // DSCP 0 segment, moves DSCP 0 and every other DSCP still leaving
        // through it, but not DSCP 24.
        assert_eq!(
            dispatch(&mut a, now, &redirect4(&data0, general, "192.0.2.251")),
            RedirectOutcome::Installed
        );
        a.0.service_changes(&mut a.1, now).unwrap();
        assert_eq!(
            state(&a),
            (hop("192.0.2.251"), hop("192.0.2.252"), hop("192.0.2.251"))
        );
    }
}

// Codes 0 and 1 move the destination across DSCP values: a connection
// with another DSCP to the same destination, leaving through the same
// gateway, is notified and rebound with the quoted one.
#[test]
fn ipv4_general_redirect_rebinds_connections_of_every_dscp() {
    for code in [0, 1] {
        let cfg = config(2);
        let (mut a, _b, [(plain, data0), (marked, _)]) =
            ipv4_dscp_pair(680 + u64::from(code) * 2, &cfg, 46);
        assert_eq!(
            dispatch(&mut a, SECOND, &redirect4(&data0, code, "192.0.2.253")),
            RedirectOutcome::Installed
        );
        let report = a.0.service_changes(&mut a.1, SECOND).unwrap();
        assert_eq!((report.applied, report.failed), (2, 0));
        let moved = ResolvedNextHop::Address(unscoped(v4("192.0.2.253")));
        assert_eq!(next_hop(&a, plain), moved);
        assert_eq!(next_hop(&a, marked), moved);
        // The marked connection's retransmission leaves on the new path.
        let [_, again] = retransmissions(&mut a, 10 * SECOND, 46);
        assert_eq!(again[1] >> 2, 46);
        assert_eq!(next_hop(&a, marked), moved);
    }
}

// RFC 4861 section 8.3 with T17's Segment Routing routes: a router on the
// link sees, and redirects, the packet's forwarding destination (the first
// segment in the base header), so the ICMPv6 Destination of a valid
// Redirect is that destination, never the final destination the Segment
// Routing Header carries; the override then moves the route's flows to it.
#[test]
fn ipv6_redirect_destination_is_the_segment_route_forwarding_destination() {
    let cfg = config(2);
    let (paths, mut limits) = managed_limits(&cfg, 2, 2, 2, 3, 0).unwrap();
    limits.neighbors = NeighborLimits {
        entries: 4,
        pending_packets: 4,
        addresses: 2,
        answers: 2,
    };
    let (paths, limits) = managed_udp_limits(paths, limits, UDP).unwrap();
    let mut host = Host::new(
        ContextId::new(740),
        paths,
        limits,
        cfg.connection.timebase,
        [1; 16],
    )
    .unwrap();
    host.set_entropy(Box::new(|out: &mut [u8]| {
        out.fill(0);
        out[0] = 0x80;
        Ok(())
    }));
    let port = NdPort {
        dad_transmits: 0,
        ..NdPort::new(OWN)
    };
    let context = host
        .register_neighbor_port(InterfaceKey(1), 1500, nd_receive(), port)
        .unwrap();
    let link = context.link();
    host.add_neighbor_address(link, v6("2001:db8::10")).unwrap();
    let router = ScopedAddress::new(IpAddr::V6(v6("fe80::1")), Some(link)).unwrap();
    let segments = [v6("2001:db8:5::1"), v6("2001:db8:6::1")];
    host.add_segment_route(
        path::Route {
            destination: path::IpPrefix::new(remote6().ip(), 128).unwrap(),
            source: None,
            dscp: None,
            link,
            next_hop: path::NextHop::Gateway(router),
            metric: 0,
        },
        &segments,
    )
    .unwrap();
    let mut endpoint = endpoint(&cfg, 740, local6().ip());
    host.attach(&mut endpoint).unwrap();
    endpoint
        .enable_output_reservations_with_capacity(1)
        .unwrap();
    let mut a = (host, endpoint, context);
    learn_router(&mut a, v6("fe80::1"), R1, 0);
    let id =
        a.1.connect_with_path_provider(0, local6(), remote6(), options(&cfg, 0), &mut a.0)
            .unwrap();
    let (mac, syn) = send_routed(&mut a, 1).unwrap();
    assert_eq!(mac, R1);
    // The SYN leaves for the first segment through fe80::1.
    assert_eq!(syn[24..40], segments[0].octets());
    assert_eq!(next_hop(&a, id), scoped(&a, "fe80::1"));
    // The final destination is not what fe80::1 forwarded the SYN to.
    let revision = a.0.paths().revision();
    let wrong = redirect6(
        v6("fe80::1"),
        v6("fe80::2"),
        v6("2001:db8:1::7"),
        Some(R2),
        Some(&syn),
    );
    assert_eq!(
        redirected(&mut a, 2, &wrong),
        Ok(RedirectOutcome::Rejected(RedirectRejection::Destination))
    );
    assert_eq!(a.0.paths().revision(), revision);
    let redirect = redirect6(
        v6("fe80::1"),
        v6("fe80::2"),
        segments[0],
        Some(R2),
        Some(&syn),
    );
    assert_eq!(
        redirected(&mut a, 3, &redirect),
        Ok(RedirectOutcome::Installed)
    );
    a.0.service_changes(&mut a.1, 4).unwrap();
    assert_eq!(next_hop(&a, id), scoped(&a, "fe80::2"));
    let (mac, again) = send_routed(&mut a, 2 * SECOND).unwrap();
    assert_eq!(mac, R2);
    assert_eq!(again[24..40], segments[0].octets());
}
// As `send6`, the segment after the complete header chain of its path.
fn send_routed(side: &mut Side, now: u64) -> Option<([u8; 6], Vec<u8>)> {
    side.1.on_timeout(now, 32).unwrap();
    let mut tcp = [0; 2048];
    let (poll, attempt) = side
        .1
        .poll_reserved_transmit_with_path_provider(now, &mut tcp, 32, &mut side.0)
        .unwrap();
    let packet = poll.packet.expect("a segment");
    let attempt = attempt.unwrap();
    let context = side.0.egress_context(&mut side.1, attempt).unwrap();
    let plan = side.0.header_plan(context.binding.snapshot.key()).unwrap();
    let mut frame = vec![0; plan.len + packet.len];
    frame[plan.len..].copy_from_slice(&tcp[..packet.len]);
    ntcp_ip6::encode_tcp_routed(&mut frame, packet, plan.segments, packet.len).unwrap();
    let owner = Owner::Tcp(packet.connection.unwrap());
    let NeighborHop::Resolved(mac) = side.0.resolve_neighbor(context, owner, now).unwrap() else {
        side.1.reject_unsubmitted(attempt).unwrap();
        return None;
    };
    let ticket = side.0.submission_ticket(&mut side.1, context).unwrap();
    let submitted = side
        .0
        .submit(&mut side.1, now, ticket, context, &frame, 0, |_| {
            BackendOutcome::Submitted
        })
        .unwrap();
    assert!(submitted == Submission::Submitted);
    side.0.collect(&side.1).unwrap();
    Some((mac, frame))
}

// RFC 4861 section 8.3 over a sequence: the new router may redirect the
// destination again, while the replaced router no longer may. A Redirect is
// about the connection its quote names, which keeps no record of the
// router each packet left through, so the new router may quote even a
// packet sent through the replaced one.
#[test]
fn ipv6_redirects_follow_the_current_first_hop() {
    use RedirectRejection::*;
    let (mut a, id, syn) = ipv6_connection(750);
    let destination = v6("2001:db8:1::7");
    let redirect = redirect6(
        v6("fe80::1"),
        v6("fe80::2"),
        destination,
        Some(R2),
        Some(&syn),
    );
    assert_eq!(
        redirected(&mut a, 2, &redirect),
        Ok(RedirectOutcome::Installed)
    );
    a.0.service_changes(&mut a.1, 3).unwrap();
    let (mac, again) = send6(&mut a, 2 * SECOND).unwrap();
    assert_eq!(mac, R2);
    // A second connection to the destination, opened through fe80::2.
    let cfg = config(2);
    let second =
        a.1.connect_with_path_provider(
            2 * SECOND,
            "[2001:db8::10]:1001".parse().unwrap(),
            remote6(),
            options(&cfg, 0),
            &mut a.0,
        )
        .unwrap();
    let (mac, fresh) = send6(&mut a, 2 * SECOND).unwrap();
    assert_eq!(mac, R2);
    assert_eq!(fresh[40..42], 1001u16.to_be_bytes());
    assert_eq!(next_hop(&a, second), scoped(&a, "fe80::2"));
    let revision = a.0.paths().revision();
    for (router, quoted) in [("fe80::1", &fresh), ("fe80::1", &again), ("fe80::1", &syn)] {
        let frame = redirect6(v6(router), v6("fe80::3"), destination, None, Some(quoted));
        let outcome = redirected(&mut a, 2 * SECOND + 1, &frame).unwrap();
        assert!(
            matches!(outcome, RedirectOutcome::Rejected(NotFirstHop)),
            "{router}: {outcome:?}"
        );
    }
    assert_eq!(a.0.paths().revision(), revision);
    // The SYN left through fe80::1.
    let frame = redirect6(v6("fe80::2"), v6("fe80::3"), destination, None, Some(&syn));
    assert_eq!(
        redirected(&mut a, 2 * SECOND + 2, &frame),
        Ok(RedirectOutcome::Installed)
    );
    let report = a.0.service_changes(&mut a.1, 2 * SECOND + 3).unwrap();
    assert_eq!((report.applied, report.failed), (2, 0));
    assert_eq!(next_hop(&a, id), scoped(&a, "fe80::3"));
    assert_eq!(next_hop(&a, second), scoped(&a, "fe80::3"));
    // fe80::3 is a router even before its mapping is known.
    let ResolvedNextHop::Address(third) = scoped(&a, "fe80::3") else {
        unreachable!()
    };
    assert!(a.0.paths().redirect_router(a.2.link(), third));
}

// A Redirect to this host's own address on the arrival link is refused and
// its Target Link-Layer Address changes no cache entry. A link-local
// address is unique only on its link (RFC 4007): the same address this
// host owns on another port is another node on the arrival link, and a
// valid router target there (RFC 4861 section 8.1 requires only that it
// be link-local).
#[test]
fn ipv6_redirect_target_ownership_is_per_link() {
    let destination = v6("2001:db8:1::7");
    // Own on the arrival link.
    let (mut a, id, syn) = ipv6_connection(760);
    let link = a.2.link();
    assert_eq!(
        a.0.add_neighbor_address(link, v6("fe80::10")),
        Ok(AddressState::Assigned)
    );
    let frame = redirect6(
        v6("fe80::1"),
        v6("fe80::10"),
        destination,
        Some(R2),
        Some(&syn),
    );
    assert_eq!(
        redirected(&mut a, 2, &frame),
        Ok(RedirectOutcome::Rejected(RedirectRejection::Target))
    );
    assert_eq!(a.0.neighbor(link, v6("fe80::10")), None);
    assert_eq!(next_hop(&a, id), scoped(&a, "fe80::1"));

    // Own only on another port.
    let (mut a, id, syn) = ipv6_connection(770);
    let other =
        a.0.register_neighbor_port(
            InterfaceKey(2),
            1500,
            nd_receive(),
            NdPort {
                dad_transmits: 0,
                ..NdPort::new([2, 0, 0, 0, 0, 2])
            },
        )
        .unwrap();
    assert_eq!(
        a.0.add_neighbor_address(other.link(), v6("fe80::10")),
        Ok(AddressState::Assigned)
    );
    let frame = redirect6(
        v6("fe80::1"),
        v6("fe80::10"),
        destination,
        Some(R2),
        Some(&syn),
    );
    assert_eq!(
        redirected(&mut a, 2, &frame),
        Ok(RedirectOutcome::Installed)
    );
    a.0.service_changes(&mut a.1, 3).unwrap();
    assert_eq!(next_hop(&a, id), scoped(&a, "fe80::10"));
    assert_eq!(
        a.0.neighbor(a.2.link(), v6("fe80::10")),
        Some((NeighborState::Stale, Some(R2), true))
    );
}

// RFC 4861 section 7.3.3 and D5: an override also ends when the router
// that sent it is found unreachable. The SYN that left through fe80::1
// moved it to DELAY; without any answer its probes run out, and the
// override fe80::1 sent ends with it, returning the flow to the route.
#[test]
fn ipv6_redirect_ends_when_its_sender_is_unreachable() {
    let (mut a, id, syn) = ipv6_connection(780);
    let link = a.2.link();
    let destination = v6("2001:db8:1::7");
    let redirect = redirect6(
        v6("fe80::1"),
        v6("fe80::2"),
        destination,
        Some(R2),
        Some(&syn),
    );
    assert_eq!(
        redirected(&mut a, 2, &redirect),
        Ok(RedirectOutcome::Installed)
    );
    a.0.service_changes(&mut a.1, 3).unwrap();
    assert_eq!(next_hop(&a, id), scoped(&a, "fe80::2"));
    a.0.refresh(&mut a.1, id).unwrap();
    assert!(a.0.dst_held(&a.1, id));
    let mut out = [0; 128];
    let mut now = 3;
    while a.0.neighbor(link, v6("fe80::1")).is_some() && now < 30 * SECOND {
        a.0.service_neighbors(now);
        while let Some(transmit) = a.0.neighbor_output(link, now, &mut out).unwrap() {
            a.0.complete_neighbor_output(transmit.ticket, BackendOutcome::Submitted, now)
                .unwrap();
        }
        now += SECOND / 4;
    }
    assert_eq!(a.0.neighbor(link, v6("fe80::1")), None);
    // The override's end drops the egress decision checked under it.
    assert!(!a.0.dst_held(&a.1, id));
    // fe80::2 itself is untouched.
    assert_eq!(
        a.0.neighbor(link, v6("fe80::2")),
        Some((NeighborState::Stale, Some(R2), true))
    );
    a.0.service_changes(&mut a.1, now).unwrap();
    assert_eq!(next_hop(&a, id), scoped(&a, "fe80::1"));
}

// An administrative downward estimate reaches a binding moved by a
// Redirect within `admin_apply`, as it reaches any other binding: the
// fan-out recognizes the override's selection as the binding's current
// path.
#[test]
fn admin_estimate_lowers_a_redirected_binding_at_once() {
    let cfg = config(2);
    let (mut a, _b, id, data) = ipv4_connection(790, &cfg, 0);
    assert_eq!(
        dispatch(&mut a, SECOND, &redirect4(&data, 1, "192.0.2.253")),
        RedirectOutcome::Installed
    );
    a.0.service_changes(&mut a.1, SECOND).unwrap();
    let moved = a.0.binding(id).unwrap();
    assert_eq!(
        moved.snapshot.key().next_hop(),
        ResolvedNextHop::Address(unscoped(v4("192.0.2.253")))
    );
    a.0.refresh(&mut a.1, id).unwrap();
    assert!(a.0.dst_held(&a.1, id));
    let before = a.1.transport_ceilings(id).unwrap().effective_mss;
    // Below the connection's current packets.
    let estimate = before as u32 + 40 - 100;
    let capability = a.0.administration();
    super::admin::set_estimate(
        &mut a,
        &capability,
        2 * SECOND,
        moved.snapshot.path(),
        Some(estimate),
    )
    .unwrap();
    let binding = a.0.binding(id).unwrap();
    assert!(!a.0.paths().is_dirty(binding.client).unwrap());
    assert!(!a.0.dst_held(&a.1, id));
    assert_eq!(binding.snapshot.ip_packet_budget(), Ok(estimate));
    assert!(a.1.transport_ceilings(id).unwrap().effective_mss <= before - 100);
}
