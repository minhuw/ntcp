extern crate std;
mod adjunct;
mod arp;
mod admin;
mod admission;
mod black_hole_reset;
mod correlation;
mod destination;
mod discovery;
mod dispatch;
mod emitter;
mod extensions;
mod fanout;
mod fragment_icmp;
mod ingress;
mod ipv4_policy;
mod neighbor;
mod probe_receipts;
mod reassembly;
mod redirect;
mod scoped;
mod segment_routes;
mod receive_capability;
mod registration;
mod repair;
mod source_routes;
mod submission;
use super::*;
use core::net::SocketAddr;
use ntcp::{
    ActiveOpenOptions, ConnectionConfig, FastOpenClientPolicy, FastOpenEarlyDataPolicy,
    InitialWindow, ManagedOpenOptions, OutgoingIpv4Options, PmtudConfig, State, Tuple,
};
use std::{vec, vec::Vec};

fn config(count: usize) -> EndpointConfig {
    EndpointConfig {
        max_connections: count,
        max_listeners: 2,
        connection: ConnectionConfig {
            mss: 1460,
            send_capacity: 65536,
            receive_capacity: 65536,
            initial_window: InitialWindow::Iw10,
            nagle: false,
            delayed_ack_us: 0,
            timestamps: true,
            pmtud: Some(PmtudConfig::new(1500)),
            ..ConnectionConfig::default()
        },
        ..EndpointConfig::default()
    }
}
fn addresses(v6: bool) -> (SocketAddr, SocketAddr) {
    if v6 {
        (
            "[2001:db8::1]:1000".parse().unwrap(),
            "[2001:db8::2]:8080".parse().unwrap(),
        )
    } else {
        (
            "192.0.2.1:1000".parse().unwrap(),
            "192.0.2.2:8080".parse().unwrap(),
        )
    }
}
fn managed(
    local: SocketAddr,
    identity: u128,
    cfg: EndpointConfig,
) -> (Host, Endpoint, IngressContext) {
    managed_configured(local, identity, cfg, false, None)
}
// A managed Host whose identifier allocator runs (no earlier emission from
// these sources), so DF-clear IPv4 output of a discovery-disabled route can
// lease Identifications.
fn managed_identified(
    local: SocketAddr,
    identity: u128,
    cfg: EndpointConfig,
) -> (Host, Endpoint, IngressContext) {
    let mut side = managed_limited(local, identity, cfg, false, None, None, |p, mut l| {
        l.datagrams.identifiers = IdentifierLimits {
            lifetime_seconds: DEFAULT_LIFETIME_SECONDS,
            ipv4_tuples: 2,
            ipv6_leases: 2,
        };
        (p, l, 1)
    });
    side.0.set_entropy(std::boxed::Box::new(|out: &mut [u8]| {
        out.fill(0x5a);
        Ok(())
    }));
    side.0.start_identifiers(Continuity::Fresh).unwrap();
    side
}
fn managed_configured(
    local: SocketAddr,
    identity: u128,
    cfg: EndpointConfig,
    gso: bool,
    path_capacity: Option<usize>,
) -> (Host, Endpoint, IngressContext) {
    managed_route_policy(local, identity, cfg, gso, path_capacity, None)
}
// `denied_hop` is an embedding route policy the Endpoint must enforce.
fn managed_route_policy(
    local: SocketAddr,
    identity: u128,
    cfg: EndpointConfig,
    gso: bool,
    path_capacity: Option<usize>,
    denied_hop: Option<IpAddr>,
) -> (Host, Endpoint, IngressContext) {
    managed_with(local, identity, cfg, gso, path_capacity, denied_hop, |_| 1)
}
fn managed_with(
    local: SocketAddr,
    identity: u128,
    cfg: EndpointConfig,
    gso: bool,
    path_capacity: Option<usize>,
    denied_hop: Option<IpAddr>,
    // Adjusts ledger budgets; returns the Endpoint output pool size.
    ledger: impl FnOnce(&mut LedgerLimits) -> usize,
) -> (Host, Endpoint, IngressContext) {
    managed_limited(
        local,
        identity,
        cfg,
        gso,
        path_capacity,
        denied_hop,
        |paths, mut limits| {
            let reservations = ledger(&mut limits.ledger);
            (paths, limits, reservations)
        },
    )
}
// Like `managed_with`, but adjusts every Host limit (e.g. adds UDP flows).
fn managed_limited(
    local: SocketAddr,
    identity: u128,
    cfg: EndpointConfig,
    gso: bool,
    path_capacity: Option<usize>,
    denied_hop: Option<IpAddr>,
    adjust: impl FnOnce(path::Limits, Limits) -> (path::Limits, Limits, usize),
) -> (Host, Endpoint, IngressContext) {
    let (paths, limits) = managed_limits(&cfg, 1, 1, 1, 4, 1).unwrap();
    let (mut paths, limits, reservations) = adjust(paths, limits);
    if let Some(capacity) = path_capacity {
        paths.paths = capacity;
    }
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
            Forwarding::Forwarder(ForwarderId(9)),
        )
        .unwrap();
    host.register_source(
        ScopedAddress::new(local.ip(), None).unwrap(),
        context.link(),
    )
    .unwrap();
    host.add_route(path::Route {
        destination: path::IpPrefix::new(
            if local.is_ipv4() { "0.0.0.0" } else { "::" }
                .parse()
                .unwrap(),
            0,
        )
        .unwrap(),
        source: None,
        dscp: None,
        link: context.link(),
        next_hop: path::NextHop::Forwarder(ForwarderId(9)),
        metric: 0,
    })
    .unwrap();
    let mut endpoint = Endpoint::new(cfg, [identity as u8; 32], 0, move |request| match request {
        ntcp::AddressValidation::Bind { local: address }
        | ntcp::AddressValidation::Open { local: address, .. } => address == local.ip(),
        ntcp::AddressValidation::Incoming { destination, .. } => destination == local.ip(),
        ntcp::AddressValidation::Route { source, hop, .. } => {
            source == local.ip() && Some(hop) != denied_hop
        }
    })
    .unwrap();
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
            .enable_output_reservations_with_capacity(reservations)
            .unwrap();
    }
    (host, endpoint, context)
}
fn options(cfg: &EndpointConfig, dscp: u8) -> ManagedOpenOptions {
    ManagedOpenOptions {
        transport: ActiveOpenOptions::from(&cfg.connection),
        dscp,
        ipv4_options: OutgoingIpv4Options::default(),
        registration: None,
        receive_authority: None,
    }
}
fn learn(
    host: &mut Host,
    local: SocketAddr,
    remote: SocketAddr,
    dscp: u8,
    mtu: u32,
) -> PathSnapshot {
    let request = host
        .request(local.ip(), remote.ip(), None, Dscp::new(dscp).unwrap())
        .unwrap();
    let (client, snapshot) = host.paths.acquire(request).unwrap();
    host.trusted_decrease(0, snapshot.path(), mtu).unwrap();
    let snapshot = host.paths().snapshot(client).unwrap();
    host.paths.release(client).unwrap();
    snapshot
}
fn selected(endpoint: &mut Endpoint, now: u64) -> Option<(TransmitAttempt, Transmit, Vec<u8>)> {
    let mut tcp = [0; 2048];
    let (poll, token) = endpoint.poll_reserved_transmit(now, &mut tcp, 32).unwrap();
    let packet = poll.packet?;
    let base = if packet.ip.source.is_ipv4() { 20 } else { 40 };
    let mut frame = vec![0; 2108];
    frame[base..base + packet.len].copy_from_slice(&tcp[..packet.len]);
    let n = if packet.ip.source.is_ipv4() {
        ntcp_ip::encode(&mut frame, packet, 123).unwrap()
    } else {
        ntcp_ip6::encode(&mut frame, packet).unwrap()
    };
    frame.truncate(n);
    Some((token.unwrap(), packet, frame))
}
fn emit(host: &mut Host, endpoint: &mut Endpoint, now: u64) -> Option<Vec<u8>> {
    let (attempt, _, mut frame) = selected(endpoint, now)?;
    let context = host.egress_context(endpoint, attempt).unwrap();
    // As the embeddings do: DF clear on a discovery-disabled IPv4 path.
    if host.clears_dont_fragment(context) {
        host.lease_df_clear(now, &mut frame).unwrap();
    }
    let ticket = host.submission_ticket(endpoint, context).unwrap();
    let submitted = host
        .submit(endpoint, now, ticket, context, &frame, 0, |_| {
            BackendOutcome::Submitted
        })
        .unwrap();
    assert!(submitted == Submission::Submitted);
    host.collect(endpoint).unwrap();
    Some(frame)
}
fn input(
    host: &mut Host,
    endpoint: &mut Endpoint,
    context: IngressContext,
    now: u64,
    frame: &[u8],
    dscp: u8,
) {
    host.input_ip(
        endpoint,
        context,
        now,
        frame,
        RxPacketMetadata::default(),
        dscp,
        None,
    )
    .unwrap();
}
fn pump(
    a: &mut (Host, Endpoint, IngressContext),
    b: &mut (Host, Endpoint, IngressContext),
    now: &mut u64,
) {
    for _ in 0..256 {
        *now += 10;
        let mut work = false;
        if let Some(frame) = emit(&mut a.0, &mut a.1, *now) {
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
    panic!("wire exchange did not quiesce");
}

#[test]
fn first_syn_and_hidden_synack_use_outgoing_path_before_construction_both_families() {
    for v6 in [false, true] {
        for tfo in [false, true] {
            let cfg = config(4);
            let (local, remote) = addresses(v6);
            let mut a = managed(local, 11, cfg.clone());
            let mut b = managed(remote, 12, cfg.clone());
            let mtu = if v6 { 1280 } else { 1100 };
            learn(&mut a.0, local, remote, 24, mtu);
            learn(&mut b.0, remote, local, 12, mtu);
            let listener = b.1.listen(remote, 4).unwrap();
            if tfo {
                a.1.enable_fast_open().unwrap();
                b.1.enable_fast_open().unwrap();
                b.1.set_listener_fast_open(listener, 4).unwrap();
                b.1.set_listener_fast_open_early_data_policy(
                    listener,
                    FastOpenEarlyDataPolicy::ApplicationProtected,
                )
                .unwrap();
            }
            let id = if tfo {
                let (id, admitted) =
                    a.1.connect_fast_open_with_path_provider(
                        0,
                        local,
                        remote,
                        &[7; 2000],
                        options(&cfg, 24),
                        None,
                        FastOpenClientPolicy::ApplicationProtected,
                        &mut a.0,
                    )
                    .unwrap();
                assert!(admitted <= 536);
                id
            } else {
                a.1.connect_with_path_provider(0, local, remote, options(&cfg, 24), &mut a.0)
                    .unwrap()
            };
            let info = a.1.transport_info(id).unwrap();
            assert_eq!(info.mss, mtu - if v6 { 60 } else { 40 });
            assert_eq!(info.cwnd, 10 * info.mss);
            let syn = emit(&mut a.0, &mut a.1, 1).unwrap();
            assert!(syn.len() <= mtu as usize);
            input(&mut b.0, &mut b.1, b.2, 2, &syn, 12);
            let child =
                b.1.connection_id(Tuple {
                    local: remote,
                    remote: local,
                })
                .unwrap();
            assert_eq!(b.1.state(child).unwrap(), State::SynReceived);
            assert_eq!(
                b.0.binding(child).unwrap().snapshot.key().dscp().value(),
                12
            );
            assert_eq!(b.1.received_dscp(child).unwrap(), Some(24));
            let info = b.1.transport_info(child).unwrap();
            assert_eq!(info.mss, mtu - if v6 { 72 } else { 52 });
            let expected = if tfo {
                info.mss
                    * if info.mss > 2190 {
                        2
                    } else if info.mss > 1095 {
                        3
                    } else {
                        4
                    }
            } else {
                10 * info.mss
            };
            assert_eq!(info.cwnd, expected);
            let synack = emit(&mut b.0, &mut b.1, 3).unwrap();
            assert!(synack.len() <= mtu as usize);
            input(&mut a.0, &mut a.1, a.2, 4, &synack, 24);
            let mut now = 10;
            pump(&mut a, &mut b, &mut now);
            let accepted = b.1.accept(listener).unwrap();
            assert_eq!(accepted, child);
            assert_eq!(a.1.state(id).unwrap(), State::Established);
            if tfo {
                let mut bytes = [0; 2000];
                assert!(b.1.read(child, &mut bytes).unwrap() > 0);
            }
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc1191#section-3.1
//= type=test
//= reason=Host acquires canonical IP path authority before TCP construction, and native/TUN factories use that budget before first output. Physical submission validates current path authority and complete IP size; transport MSS, buffers and local discovery remain independent. Dual-family first-SYN/hidden-SYNACK and framed-stream tests exercise the handoff. Generic validated ICMP publication and cross-protocol fanout are separate T9/T10 obligations.
//# Some TCP implementations send an MSS option only if the destination host is on a non-connected network. However, in general the TCP layer may not have the appropriate information to make this decision, so it is preferable to leave to the IP layer the task of determining a suitable MTU for the Internet path.
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
//= type=test
//= reason=Managed factories acquire per-host records from configured network/default routes before TCP construction, initializing unlearned budgets from the physical first hop. Trusted decreases change only per-host learned estimates, preserving forwarding routes and independent first-hop facts. Dual-family two-Endpoint tests exercise both route selections, first SYN/hidden child and later decreases without forwarding-route mutation. Generic ICMP publication remains the separate 1191-057 obligation.
//# When the first packet is sent to a host for which no per-host route exists, a route is chosen either from the set of per-network routes, or from the set of default routes. The PMTU fields in these route entries should be initialized to be the MTU of the associated first-hop data link, and must never be changed by the PMTU Discovery process. (PMTU Discovery only creates or changes entries for per-host routes). Until a Datagram Too Big message is received, the PMTU associated with the initially-chosen route is presumed to be accurate.
#[test]
fn first_packet_uses_network_or_default_first_hop_without_mutating_forwarding_routes() {
    for v6 in [false, true] {
        for network_route in [false, true] {
            let cfg = config(2);
            let (local, remote) = addresses(v6);
            let mut a = managed(local, 901, cfg.clone());
            let mut b = managed(remote, 902, cfg.clone());
            let explicit = network_route.then(|| {
                a.0.add_route(path::Route {
                    destination: path::IpPrefix::new(
                        if v6 { "2001:db8::" } else { "192.0.2.0" }.parse().unwrap(),
                        if v6 { 64 } else { 24 },
                    )
                    .unwrap(),
                    source: None,
                    dscp: None,
                    link: a.2.link(),
                    next_hop: path::NextHop::Forwarder(ForwarderId(9)),
                    metric: 0,
                })
                .unwrap()
            });
            let listener = b.1.listen(remote, 2).unwrap();
            let id =
                a.1.connect_with_path_provider(0, local, remote, options(&cfg, 24), &mut a.0)
                    .unwrap();
            let initial = a.0.binding(id).unwrap().snapshot;
            assert_eq!(initial.learned_mtu(), None);
            assert_eq!(initial.first_hop_mtu(), 1500);
            assert_eq!(initial.ip_packet_budget(), Ok(1500));
            let route_id = initial.key().route();
            if let Some(explicit) = explicit {
                assert_eq!(route_id, explicit);
            }
            let route = a.0.paths().route(route_id).unwrap();
            assert_eq!(
                route.destination.length(),
                if network_route {
                    if v6 { 64 } else { 24 }
                } else {
                    0
                }
            );
            let syn = emit(&mut a.0, &mut a.1, 1).unwrap();
            input(&mut b.0, &mut b.1, b.2, 2, &syn, 12);
            let child =
                b.1.connection_id(Tuple {
                    local: remote,
                    remote: local,
                })
                .unwrap();
            assert_eq!(b.0.binding(child).unwrap().snapshot.first_hop_mtu(), 1500);
            assert_eq!(b.0.binding(child).unwrap().snapshot.learned_mtu(), None);
            let decrease = if v6 { 1280 } else { 1100 };
            a.0.trusted_decrease(3, initial.path(), decrease).unwrap();
            a.0.refresh(&mut a.1, id).unwrap();
            let latest = a.0.binding(id).unwrap().snapshot;
            assert_eq!(latest.learned_mtu(), Some(decrease));
            assert_eq!(latest.first_hop_mtu(), 1500);
            assert_eq!(a.0.paths().route(route_id).unwrap(), route);
            let synack = emit(&mut b.0, &mut b.1, 4).unwrap();
            input(&mut a.0, &mut a.1, a.2, 5, &synack, 24);
            let mut now = 10;
            pump(&mut a, &mut b, &mut now);
            assert_eq!(b.1.accept(listener).unwrap(), child);
            assert_eq!(a.1.state(id).unwrap(), State::Established);
        }
    }
}

#[test]
fn shared_decrease_two_real_flows_no_phantom_repair_and_held_frame_barrier() {
    for v6 in [false, true] {
        let cfg = config(4);
        let (local, remote) = addresses(v6);
        let mut a = managed(local, 21, cfg.clone());
        let mut b = managed(remote, 22, cfg.clone());
        let listener = b.1.listen(remote, 4).unwrap();
        let first =
            a.1.connect_with_path_provider(0, local, remote, options(&cfg, 24), &mut a.0)
                .unwrap();
        let second_local = SocketAddr::new(local.ip(), local.port() + 1);
        let second =
            a.1.connect_with_path_provider(0, second_local, remote, options(&cfg, 24), &mut a.0)
                .unwrap();
        assert_eq!(
            a.0.binding(first).unwrap().snapshot.path(),
            a.0.binding(second).unwrap().snapshot.path()
        );
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        let children = [b.1.accept(listener).unwrap(), b.1.accept(listener).unwrap()];
        a.1.write(first, &[1; 1400]).unwrap();
        let (held, _, bytes) = selected(&mut a.1, now + 10).unwrap();
        let held_context = a.0.egress_context(&mut a.1, held).unwrap();
        let before = a.1.transport_info(second).unwrap();
        let path = a.0.binding(first).unwrap().snapshot.path();
        let mtu = if v6 { 1280 } else { 1100 };
        a.0.trusted_decrease(now + 11, path, mtu).unwrap();
        a.0.refresh_all(&mut a.1).unwrap();
        assert_eq!(
            a.1.transport_info(second).unwrap().mss,
            mtu - if v6 { 72 } else { 52 }
        );
        assert_eq!(a.1.transport_info(second).unwrap().lost, before.lost);
        assert_eq!(
            a.0.validate_egress(&mut a.1, held_context, &bytes, 0),
            Err(Error::Obsolete)
        );
        assert!(a.1.reject_unsubmitted(held).unwrap());
        now += 20;
        // Serialized ingress is retained until all selected suffixes leave.
        // The later native/example phases supply their bounded receive queues.
        while a.1.is_output_reserved(first) {
            let frame = emit(&mut a.0, &mut a.1, now).unwrap();
            assert!(frame.len() <= mtu as usize);
            input(&mut b.0, &mut b.1, b.2, now + 1, &frame, 12);
        }
        now += 10;
        pump(&mut a, &mut b, &mut now);
        a.1.write(second, &[2; 1400]).unwrap();
        pump(&mut a, &mut b, &mut now);
        for child in children {
            let mut bytes = [0; 2000];
            assert_eq!(b.1.read(child, &mut bytes).unwrap(), 1400);
        }
        let snapshot = a.0.paths().path_snapshot(path).unwrap();
        assert_eq!(
            a.0.trusted_decrease(now, path, mtu).unwrap(),
            path::EstimateChange::Unchanged
        );
        // A fresh unchanged report keeps the estimate and its decrease
        // identity, but restarts the hold for growth selected before it.
        let unchanged = a.0.paths().path_snapshot(path).unwrap();
        assert_eq!(unchanged.learned_mtu(), snapshot.learned_mtu());
        assert_eq!(unchanged.negative_revision(), snapshot.negative_revision());
        assert!(unchanged.retry_not_before() > snapshot.retry_not_before());
        a.0.set_link_mtu(a.2.link(), 1600).unwrap();
        a.0.refresh_all(&mut a.1).unwrap();
        assert_eq!(
            a.0.binding(first).unwrap().snapshot.learned_mtu(),
            Some(mtu)
        );
    }
}

#[test]
fn factory_rollbacks_and_raw_managed_bypass_are_bounded() {
    let cfg = config(1);
    let (local, remote) = addresses(false);
    let (mut host, mut endpoint, _) = managed(local, 31, cfg.clone());
    assert!(endpoint.connect(0, local, remote).is_err());
    for _ in 0..32 {
        let mut invalid = options(&cfg, 0);
        invalid.transport.send_capacity = 0;
        assert!(
            endpoint
                .connect_with_path_provider(0, local, remote, invalid, &mut host)
                .is_err()
        );
        assert_eq!(host.binding_count(), 0);
        assert_eq!(host.paths().usage().clients, 0);
    }
    let id = endpoint
        .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut host)
        .unwrap();
    for port in 1001..1033 {
        assert!(
            endpoint
                .connect_with_path_provider(
                    0,
                    SocketAddr::new(local.ip(), port),
                    remote,
                    options(&cfg, 0),
                    &mut host
                )
                .is_err()
        );
        assert_eq!(host.binding_count(), 1);
        assert_eq!(host.paths().usage().clients, 1);
    }
    endpoint.abort(id).unwrap();
    while emit(&mut host, &mut endpoint, 1).is_some() {}
    endpoint.release(id).unwrap();
    for now in 2..10 {
        endpoint.poll_transmit(now, &mut [0; 2048], 32).unwrap();
        host.collect(&endpoint).unwrap();
    }
    assert_eq!(host.binding_count(), 0);
    assert_eq!(host.paths().usage().clients, 0);
}

#[test]
fn ingress_requires_live_local_owner_and_supported_current_framing() {
    let cfg = config(2);
    let (local, remote) = addresses(false);
    let (mut host, mut endpoint, context) = managed(local, 41, cfg.clone());
    let (mut peer_host, mut peer, _) = managed(remote, 42, cfg.clone());
    peer.connect_with_path_provider(0, remote, local, options(&cfg, 0), &mut peer_host)
        .unwrap();
    let frame = emit(&mut peer_host, &mut peer, 1).unwrap();
    assert!(host.decode_ingress(context, &frame).is_ok());
    let source = host
        .paths()
        .local_source(
            ScopedAddress::new(local.ip(), None).unwrap(),
            context.link(),
        )
        .unwrap();
    host.remove_source_owner(source, context.link()).unwrap();
    assert!(
        host.input_ip(
            &mut endpoint,
            context,
            2,
            &frame,
            RxPacketMetadata::default(),
            0,
            None
        )
        .is_err()
    );
    host.remove_link(context).unwrap();
    assert!(host.decode_ingress(context, &frame).is_err());
    assert_eq!(host.binding_count(), 0);
}

#[test]
fn exact_probe_attempt_and_negative_revision_gate_actual_submission() {
    for v6 in [false, true] {
        let cfg = config(4);
        let (local, remote) = addresses(v6);
        let mut a = managed(local, 51, cfg.clone());
        let mut b = managed(remote, 52, cfg.clone());
        b.1.listen(remote, 4).unwrap();
        let id =
            a.1.connect_with_path_provider(0, local, remote, options(&cfg, 24), &mut a.0)
                .unwrap();
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        let path = a.0.binding(id).unwrap().snapshot.path();
        let mtu = if v6 { 1350 } else { 1100 };
        a.0.trusted_decrease(now, path, mtu).unwrap();
        a.0.refresh_all(&mut a.1).unwrap();
        let hold = a.0.binding(id).unwrap().snapshot.retry_not_before();
        a.1.write(id, &[7; 20000]).unwrap();
        let (attempt, packet, frame) = selected(&mut a.1, hold).unwrap();
        let intent =
            a.1.transmit_discovery_intent(attempt)
                .expect("selected real-data discovery");
        assert_eq!(intent.ip_packet_len() as usize, frame.len());
        assert!(frame.len() > mtu as usize);
        let context = a.0.egress_context(&mut a.1, attempt).unwrap();
        a.0.validate_egress(&mut a.1, context, &frame, 0).unwrap();
        let local = a.1.transport_info(id).unwrap();
        a.0.trusted_decrease(hold + 1, path, if v6 { 1280 } else { 1050 })
            .unwrap();
        let mut submitted = false;
        let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
        let refused =
            a.0.submit(&mut a.1, hold + 1, ticket, context, &frame, 0, |_| {
                submitted = true;
                BackendOutcome::Submitted
            })
            .unwrap_err();
        assert_eq!(refused.error, Error::Obsolete);
        assert!(!submitted);
        assert_eq!(
            a.1.transport_info(id).unwrap().rto_backoff,
            local.rto_backoff
        );
        assert_eq!(a.1.transmit_attempt_packet(attempt), Some(packet));
        assert!(a.1.reject_unsubmitted(attempt).unwrap());
        assert!(a.1.transmit_discovery_intent(attempt).is_none());
        let (next, _, smaller) = selected(&mut a.1, hold + 2).unwrap();
        assert!(a.1.transmit_discovery_intent(next).is_none());
        // The retained ticket follows the replacement attempt.
        let context = a.0.egress_context(&mut a.1, next).unwrap();
        a.0.validate_egress(&mut a.1, context, &smaller, 0).unwrap();
        let submitted =
            a.0.submit(&mut a.1, hold + 2, refused.ticket, context, &smaller, 0, |_| {
                BackendOutcome::Submitted
            })
            .unwrap();
        assert!(submitted == Submission::Submitted);
        assert!(smaller.len() <= if v6 { 1280 } else { 1050 });
    }
}

// A stateless reply's lease grants authority under its path as it is. A
// reply held across a change of that path (a route replacement, or a link
// MTU change that leaves the reply fitting) is refused without reaching the
// backend and without rebinding its lease; rejecting it as unsent releases
// the lease and its pin.
#[test]
fn stateless_reply_held_across_a_path_change_is_refused() {
    for replace_route in [true, false] {
        let cfg = config(2);
        let (local, remote) = addresses(false);
        let mut a = managed(local, 61, cfg.clone());
        let mut b = managed(remote, 62, cfg.clone());
        a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
        let syn = emit(&mut a.0, &mut a.1, 1).unwrap();
        input(&mut b.0, &mut b.1, b.2, 2, &syn, 0);
        let (attempt, packet, frame) = selected(&mut b.1, 3).unwrap();
        assert!(packet.connection.is_none());
        assert_eq!(b.0.binding_count(), 0);
        let held = b.0.egress_context(&mut b.1, attempt).unwrap();
        let old = held.binding;
        assert_eq!(b.0.lease_count(), 1);
        let ticket = b.0.submission_ticket(&mut b.1, held).unwrap();
        if replace_route {
            let route = b.0.paths().route(old.snapshot.key().route()).unwrap();
            b.0.replace_route(old.snapshot.key().route(), route).unwrap();
        } else {
            b.0.set_link_mtu(b.2.link(), 1600).unwrap();
        }
        let usage = b.0.paths().usage();
        let refused = b
            .0
            .submit(&mut b.1, 4, ticket, held, &frame, 0, |_| {
                panic!("a reply authorized under the old path reached the backend")
            })
            .unwrap_err();
        assert_eq!(refused.error, Error::Obsolete);
        assert_eq!(b.0.paths().usage(), usage);
        assert_eq!(b.0.leases[0].unwrap().prepared, old);
        assert_eq!(b.0.paths().path_pins(old.snapshot.path()).unwrap(), 1);
        assert!(b.1.reject_unsubmitted(attempt).unwrap());
        b.0.cancel_submission(refused.ticket);
        b.0.collect(&b.1).unwrap();
        assert_eq!(b.0.lease_count(), 0);
        assert_eq!(b.0.paths().usage().clients, 0);
        assert_eq!(b.0.ledger.pending_count(), 0);
    }
}

#[test]
fn full_path_capacity_class_rebind_is_atomic_and_other_class_is_isolated() {
    let cfg = config(4);
    let (local, remote) = addresses(false);
    let (mut host, mut endpoint, _) = managed_configured(local, 71, cfg.clone(), false, Some(1));
    let id = endpoint
        .connect_with_path_provider(0, local, remote, options(&cfg, 24), &mut host)
        .unwrap();
    let before = host.binding(id).unwrap();
    let info = endpoint.managed_path(id).unwrap();
    assert_eq!(
        host.rebind_dscp(&mut endpoint, id, 12),
        Err(Error::Path(path::Error::Capacity))
    );
    assert_eq!(host.binding(id).unwrap(), before);
    assert_eq!(endpoint.managed_path(id).unwrap(), info);
    assert!(endpoint.set_dscp(id, 12).is_err());

    let (mut host, mut endpoint, _) = managed(local, 72, cfg.clone());
    let first = endpoint
        .connect_with_path_provider(0, local, remote, options(&cfg, 24), &mut host)
        .unwrap();
    let second = endpoint
        .connect_with_path_provider(
            0,
            SocketAddr::new(local.ip(), 1001),
            remote,
            options(&cfg, 12),
            &mut host,
        )
        .unwrap();
    let other = endpoint.managed_path(second).unwrap();
    let path = host.binding(first).unwrap().snapshot.path();
    host.trusted_decrease(0, path, 1100).unwrap();
    host.refresh_all(&mut endpoint).unwrap();
    assert_eq!(endpoint.managed_path(second).unwrap(), other);
    host.rebind_dscp(&mut endpoint, first, 12).unwrap();
    assert_eq!(
        host.binding(first).unwrap().snapshot.path(),
        host.binding(second).unwrap().snapshot.path()
    );
    assert_eq!(host.paths().usage().clients, 2);
}

#[test]
fn software_gso_physical_segments_preserve_submitted_prefix_through_decrease() {
    for v6 in [false, true] {
        let mut cfg = config(4);
        cfg.connection.pmtud.as_mut().unwrap().initial_search_low = Some(1500);
        let (local, remote) = addresses(v6);
        let mut a = managed_configured(local, 81, cfg.clone(), true, None);
        let mut b = managed(remote, 82, cfg.clone());
        let listener = b.1.listen(remote, 4).unwrap();
        let id =
            a.1.connect_with_path_provider(0, local, remote, options(&cfg, 24), &mut a.0)
                .unwrap();
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        let child = b.1.accept(listener).unwrap();
        let payload: Vec<u8> = (0..6000).map(|i| i as u8).collect();
        a.1.write(id, &payload).unwrap();
        let (first, _, frame) = selected(&mut a.1, now + 10).unwrap();
        let group =
            a.1.transmit_segmentation(first)
                .expect("actual software GSO reservation");
        assert!(group.payload_len > group.segment_payload_len);
        let context = a.0.egress_context(&mut a.1, first).unwrap();
        a.0.validate_egress(&mut a.1, context, &frame, 0).unwrap();
        assert!(a.1.accept_transmit(now + 10, first).unwrap());
        input(&mut b.0, &mut b.1, b.2, now + 11, &frame, 12);
        let progress = a.1.send_progress(id).unwrap();
        let (held, _, frame) = selected(&mut a.1, now + 12).unwrap();
        let context = a.0.egress_context(&mut a.1, held).unwrap();
        let mtu = if v6 { 1280 } else { 1100 };
        let path = a.0.binding(id).unwrap().snapshot.path();
        a.0.trusted_decrease(now + 13, path, mtu).unwrap();
        assert_eq!(
            a.0.validate_egress(&mut a.1, context, &frame, 0),
            Err(Error::Obsolete)
        );
        assert_eq!(a.1.send_progress(id).unwrap(), progress);
        a.1.reject_unsubmitted(held).unwrap();
        now += 20;
        while a.1.is_output_reserved(id) {
            let frame = emit(&mut a.0, &mut a.1, now).unwrap();
            assert!(frame.len() <= mtu as usize);
            input(&mut b.0, &mut b.1, b.2, now + 1, &frame, 12);
        }
        now += 10;
        pump(&mut a, &mut b, &mut now);
        let mut bytes = vec![0; payload.len()];
        assert_eq!(b.1.read(child, &mut bytes).unwrap(), payload.len());
        assert_eq!(bytes, payload);
    }
}

#[test]
fn shared_payload_barrier_adds_external_bytes_once_and_splits_obsolete_output() {
    for v6 in [false, true] {
        let mut cfg = config(4);
        cfg.connection.pmtud.as_mut().unwrap().initial_search_low = Some(1500);
        let (local, remote) = addresses(v6);
        let mut a = managed(local, 91, cfg.clone());
        let mut b = managed(remote, 92, cfg.clone());
        let listener = b.1.listen(remote, 4).unwrap();
        let id =
            a.1.connect_with_path_provider(0, local, remote, options(&cfg, 24), &mut a.0)
                .unwrap();
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        let child = b.1.accept(listener).unwrap();
        a.1.enable_shared_output(4).unwrap();
        a.1.write_shared(
            id,
            ntcp::Payload::from_vec(vec![7; 4000]),
            false,
            true,
            None,
        )
        .unwrap();
        let mut parts = Vec::with_capacity(4);
        let mut tcp = [0; 2048];
        let (poll, attempt) =
            a.1.poll_reserved_transmit_shared_for(now + 10, id, &mut tcp, &mut parts, 32)
                .unwrap();
        let packet = poll.packet.unwrap();
        let attempt = attempt.unwrap();
        let payload: usize = parts.iter().map(ntcp::Payload::len).sum();
        assert!(payload > 0);
        let header = packet.len - payload;
        let base = if v6 { 40 } else { 20 };
        let mut frame = vec![0; 2108];
        frame[base..base + header].copy_from_slice(&tcp[..header]);
        let n = if v6 {
            ntcp_ip6::encode_shared_header(&mut frame, packet, header).unwrap()
        } else {
            ntcp_ip::encode_shared_header(&mut frame, packet, 123, header).unwrap()
        };
        frame.truncate(n);
        let context = a.0.egress_context(&mut a.1, attempt).unwrap();
        a.0.validate_egress(&mut a.1, context, &frame, payload)
            .unwrap();
        assert_eq!(
            a.0.validate_egress(&mut a.1, context, &frame, payload * 2),
            Err(Error::Obsolete)
        );
        let mtu = if v6 { 1280 } else { 1100 };
        let path = a.0.binding(id).unwrap().snapshot.path();
        a.0.trusted_decrease(now + 11, path, mtu).unwrap();
        assert_eq!(
            a.0.validate_egress(&mut a.1, context, &frame, payload),
            Err(Error::Obsolete)
        );
        a.1.reject_unsubmitted(attempt).unwrap();
        now += 20;
        while a.1.is_output_reserved(id) {
            let (poll, attempt) =
                a.1.poll_reserved_transmit_shared_for(now, id, &mut tcp, &mut parts, 32)
                    .unwrap();
            let packet = poll.packet.unwrap();
            let attempt = attempt.unwrap();
            let payload: usize = parts.iter().map(ntcp::Payload::len).sum();
            let header = packet.len - payload;
            let mut frame = vec![0; 2108];
            frame[base..base + header].copy_from_slice(&tcp[..header]);
            let n = if v6 {
                ntcp_ip6::encode_shared_header(&mut frame, packet, header).unwrap()
            } else {
                ntcp_ip::encode_shared_header(&mut frame, packet, 123, header).unwrap()
            };
            frame.truncate(n);
            let context = a.0.egress_context(&mut a.1, attempt).unwrap();
            a.0.validate_egress(&mut a.1, context, &frame, payload)
                .unwrap();
            assert!(frame.len() + payload <= mtu as usize);
            for part in &parts {
                frame.extend_from_slice(part.as_slice());
            }
            assert!(a.1.accept_transmit(now, attempt).unwrap());
            input(&mut b.0, &mut b.1, b.2, now + 1, &frame, 12);
        }
        now += 10;
        pump(&mut a, &mut b, &mut now);
        let mut bytes = [0; 4000];
        assert_eq!(b.1.read(child, &mut bytes).unwrap(), bytes.len());
        assert_eq!(bytes, [7; 4000]);
    }
}

#[test]
fn released_time_wait_binding_survives_factory_capacity_rollback_and_success() {
    for capacity in [1, 2] {
        let mut cfg = config(capacity);
        cfg.reuse_time_wait = true;
        cfg.connection.timestamps = false;
        let (local, remote) = addresses(false);
        let mut a = managed(local, 111, cfg.clone());
        let mut b = managed(remote, 112, cfg.clone());
        let listener = a.1.listen(local, capacity).unwrap();
        let peer =
            b.1.connect_with_path_provider(0, remote, local, options(&cfg, 12), &mut b.0)
                .unwrap();
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        let old = a.1.accept(listener).unwrap();
        a.1.shutdown(old).unwrap();
        pump(&mut a, &mut b, &mut now);
        b.1.shutdown(peer).unwrap();
        pump(&mut a, &mut b, &mut now);
        assert_eq!(a.1.state(old).unwrap(), State::TimeWait);
        assert_eq!(b.1.state(peer).unwrap(), State::Closed);
        a.1.release(old).unwrap();
        b.1.release(peer).unwrap();
        a.0.collect(&a.1).unwrap();
        b.0.collect(&b.1).unwrap();
        assert!(a.1.connection_exists(old));
        assert_eq!(a.1.retained_tuple(old).unwrap(), Tuple { local, remote });
        let retained = a.0.binding(old).unwrap();
        now += 1_000_000;
        b.1.connect_with_path_provider(now, remote, local, options(&cfg, 12), &mut b.0)
            .unwrap();
        let syn = emit(&mut b.0, &mut b.1, now + 1).unwrap();
        input(&mut a.0, &mut a.1, a.2, now + 2, &syn, 24);
        assert_eq!(a.0.binding(old).unwrap(), retained);
        let current = a.1.connection_id(Tuple { local, remote }).unwrap();
        if capacity == 1 {
            assert_eq!(current, old);
            assert_eq!(a.0.binding_count(), 1);
            assert_eq!(a.0.paths().usage().clients, 1);
        } else {
            assert_ne!(current, old);
            assert_eq!(a.0.binding_count(), 2);
            assert_eq!(
                a.1.managed_path(current).unwrap().binding.client,
                a.0.binding(current).unwrap().client
            );
            now += 10;
            pump(&mut a, &mut b, &mut now);
            assert_eq!(a.1.accept(listener).unwrap(), current);
            assert_eq!(a.1.state(current).unwrap(), State::Established);
        }
    }
}

#[test]
fn originating_source_route_retains_final_peer_and_actual_forwarding_hop() {
    let mut cfg = config(2);
    cfg.ipv4_options_enabled = true;
    let (local, remote) = addresses(false);
    let (mut host, mut endpoint, _) = managed(local, 121, cfg.clone());
    let hop = "192.0.2.254".parse().unwrap();
    let mut selected_options = options(&cfg, 24);
    selected_options.ipv4_options.source_route =
        Some(ntcp::SourceRoute::new(&[hop], false).unwrap());
    let id = endpoint
        .connect_with_path_provider(0, local, remote, selected_options, &mut host)
        .unwrap();
    let binding = host.binding(id).unwrap();
    assert_eq!(binding.snapshot.key().destination().address(), remote.ip());
    assert_eq!(
        binding.snapshot.key().forwarding_destination().address(),
        IpAddr::V4(hop)
    );
    let (attempt, _, frame) = selected(&mut endpoint, 1).unwrap();
    let (ip, header, _, _) = ntcp_ip::quote_header(&frame).unwrap();
    assert_eq!(ip.destination, remote.ip());
    assert_eq!(&frame[16..20], &hop.octets());
    assert_eq!(
        endpoint.managed_path(id).unwrap().ip_header_len as usize,
        header
    );
    let context = host.egress_context(&mut endpoint, attempt).unwrap();
    host.validate_egress(&mut endpoint, context, &frame, 0)
        .unwrap();
}

#[test]
fn revoked_source_pauses_held_output_and_only_live_registered_generation_can_resume() {
    let cfg = config(2);
    let (local, remote) = addresses(false);
    let (mut host, mut endpoint, ingress) = managed(local, 131, cfg.clone());
    let id = endpoint
        .connect_with_path_provider(0, local, remote, options(&cfg, 24), &mut host)
        .unwrap();
    let (attempt, _, frame) = selected(&mut endpoint, 1).unwrap();
    let context = host.egress_context(&mut endpoint, attempt).unwrap();
    let source = context.binding.snapshot.key().source();
    host.remove_source_owner(source, ingress.link()).unwrap();
    assert!(
        host.validate_egress(&mut endpoint, context, &frame, 0)
            .is_err()
    );
    assert!(host.paths().is_dirty(context.binding.client).unwrap());
    let replacement = host
        .register_source(
            ScopedAddress::new(local.ip(), None).unwrap(),
            ingress.link(),
        )
        .unwrap();
    assert_ne!(replacement, source);
    let current = host.egress_context(&mut endpoint, attempt).unwrap();
    assert_ne!(current.binding.client, context.binding.client);
    assert_ne!(
        current.binding.snapshot.path(),
        context.binding.snapshot.path()
    );
    assert_eq!(current.binding.snapshot.key().source(), replacement);
    assert_eq!(endpoint.managed_path(id).unwrap().binding, current.binding);
    assert_eq!(current.binding.snapshot.learned_mtu(), None);
    assert_eq!(
        host.validate_egress(&mut endpoint, context, &frame, 0),
        Err(Error::Obsolete)
    );
    host.validate_egress(&mut endpoint, current, &frame, 0)
        .unwrap();
    assert!(endpoint.accept_transmit(2, attempt).unwrap());
    assert_eq!(
        host.paths()
            .path_pins(context.binding.snapshot.path())
            .unwrap(),
        0
    );
}
