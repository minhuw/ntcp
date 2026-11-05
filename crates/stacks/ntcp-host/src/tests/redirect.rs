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
fn endpoint(cfg: &EndpointConfig, identity: u128, owned: IpAddr) -> Endpoint {
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
fn gateway_side(identity: u128, cfg: &EndpointConfig, gso: bool) -> Side {
    let local = v4("192.0.2.1");
    let (paths, limits) = managed_limits(cfg, 1, 1, 1, 4, 1).unwrap();
    let (paths, limits) = managed_udp_limits(paths, limits, UDP).unwrap();
    let mut host = Host::new(
        ContextId::new(identity),
        paths,
        limits,
        cfg.connection.timebase,
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
fn ipv4_connection(identity: u128, cfg: &EndpointConfig, dscp: u8) -> (Side, Side, ConnectionId, Vec<u8>) {
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
fn ipv4_redirects_move_the_destination_and_notify_tcp_and_udp() {
    for code in [1, 0] {
        let cfg = config(2);
        let (mut a, _b, id, data) = ipv4_connection(600 + u128::from(code) * 2, &cfg, 0);
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
        assert_eq!(
            dispatch(&mut a, now, &redirect4(&data, code, "192.0.2.253")),
            RedirectOutcome::Installed
        );
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
// a quote of nothing this Host committed, a new gateway not reached
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
    let unknown = {
        let mut copy = data.clone();
        copy[24] ^= 0xff;
        redirect4(&copy, 1, "192.0.2.253")
    };
    assert_eq!(dispatch(&mut a, SECOND, &unknown), RedirectOutcome::Rejected(Uncorrelated));
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

fn nd_side(identity: u128, cfg: &EndpointConfig) -> Side {
    let (paths, mut limits) = managed_limits(cfg, 2, 2, 2, 2, 0).unwrap();
    limits.neighbors = NeighborLimits {
        entries: 4,
        pending_packets: 4,
        addresses: 2,
        answers: 2,
    };
    let (paths, limits) = managed_udp_limits(paths, limits, UDP).unwrap();
    let mut host = Host::new(
        ContextId::new(identity),
        paths,
        limits,
        cfg.connection.timebase,
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
fn ipv6_connection(identity: u128) -> (Side, ConnectionId, Vec<u8>) {
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
    assert_eq!(receive(&mut a, 2, &redirect), Ok(true));
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
    assert_eq!(receive(&mut a, 2, &redirect), Ok(true));
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
        while let Some(transmit) = a.0.neighbor_output(now, &mut out).unwrap() {
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
    assert_eq!(receive(&mut a, 2, &redirect), Ok(true));
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
// of nothing it committed, a Destination other than the quoted packet's,
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
    let mut unknown = syn.clone();
    unknown[47] ^= 0xff;
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
            assert_eq!(receive(&mut a, 2, &frame), Ok(true));
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
