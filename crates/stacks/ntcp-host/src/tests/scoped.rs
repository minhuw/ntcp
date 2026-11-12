// Scoped identity through Host factories: one Host and Endpoint serving two
// links on which identical link-local address and port pairs coexist.
use super::*;
use super::dispatch::{ptb, tcp_report};
use ntcp::ScopedTuple;

type Peer = (Host, Endpoint, Vec<IngressContext>);

const LOCAL: &str = "[fe80::1]:1000";
const REMOTE: &str = "[fe80::2]:8080";

// A Host with `links` links, each owning `address` (scoped to it) and
// routing fe80::/64 on-link-scope through its own forwarder.
fn scoped_side(address: &str, links: usize, identity: u64, cfg: &EndpointConfig) -> Peer {
    scoped_side_with(address, links, identity, cfg, 0)
}

// `scoped_side` with capacity for `flows` Host UDP flows.
fn scoped_side_with(
    address: &str,
    links: usize,
    identity: u64,
    cfg: &EndpointConfig,
    flows: usize,
) -> Peer {
    let (paths, limits) = managed_limits(cfg, links, links, links, 4, 1).unwrap();
    let (paths, limits) = managed_udp_limits(
        paths,
        limits,
        UdpLimits {
            flows,
            receive_datagrams: 2,
            max_payload: 2000,
            events: 2,
            evicted_signatures: 1,
            probe_receipts: 1,
        },
    )
    .unwrap();
    let mut host = Host::new(
        ContextId::new(identity),
        paths,
        limits,
        cfg.connection.timebase,
        [1; 16],
    )
    .unwrap();
    let address: SocketAddr = address.parse().unwrap();
    let mut contexts = Vec::new();
    for index in 0..links {
        let forwarder = ForwarderId(9 + index as u64);
        let context = host
            .register_link(
                InterfaceKey(1 + index as u64),
                1500,
                ReceiveCapabilities {
                    max_ip_packet: 65575,
                    ipv4: Ipv4Receive::Disabled,
                    ipv6: Ipv6Receive::BaseHeader,
                    gro: false,
                },
                Forwarding::Forwarder(forwarder),
            )
            .unwrap();
        host.register_source(
            ScopedAddress::new(address.ip(), Some(context.link())).unwrap(),
            context.link(),
        )
        .unwrap();
        host.add_route(path::Route {
            destination: path::IpPrefix::new("fe80::".parse().unwrap(), 64).unwrap(),
            source: None,
            dscp: None,
            link: context.link(),
            next_hop: path::NextHop::Forwarder(forwarder),
            metric: 0,
        })
        .unwrap();
        contexts.push(context);
    }
    let mut endpoint = Endpoint::new(cfg.clone(), [identity as u8; 32], 0, |_| true).unwrap();
    host.attach(&mut endpoint).unwrap();
    endpoint
        .enable_output_reservations_with_capacity(1)
        .unwrap();
    (host, endpoint, contexts)
}

// Emit one packet and report the link it was submitted on.
fn emit_on(side: &mut Peer, now: u64) -> Option<(LinkId, Vec<u8>)> {
    let (attempt, _, frame) = selected(&mut side.1, now)?;
    let context = side.0.egress_context(&mut side.1, attempt).unwrap();
    let ticket = side.0.submission_ticket(&mut side.1, context).unwrap();
    let submitted = side
        .0
        .submit(&mut side.1, now, ticket, context, &frame, 0, |_| {
            BackendOutcome::Submitted
        })
        .unwrap();
    assert!(submitted == Submission::Submitted);
    side.0.collect(&side.1).unwrap();
    Some((context.link, frame))
}

fn deliver(side: &mut Peer, context: IngressContext, now: u64, frame: &[u8]) {
    side.0
        .input_ip(
            &mut side.1,
            context,
            now,
            frame,
            RxPacketMetadata::default(),
            0,
            None,
        )
        .unwrap();
}

// Exchange until quiet: `a` link i is wired to peer i's only link.
fn pump_links(a: &mut Peer, peers: &mut [Peer], now: &mut u64) {
    pump_recorded(a, peers, now, &mut Vec::new());
}

// `pump_links`, recording each of `a`'s packets with its link and time.
fn pump_recorded(
    a: &mut Peer,
    peers: &mut [Peer],
    now: &mut u64,
    sent: &mut Vec<(LinkId, u64, Vec<u8>)>,
) {
    for _ in 0..256 {
        *now += 10;
        let mut work = false;
        if let Some((link, frame)) = emit_on(a, *now) {
            let index = a.2.iter().position(|c| c.link() == link).unwrap();
            let peer = &mut peers[index];
            let context = peer.2[0];
            deliver(peer, context, *now + 1, &frame);
            sent.push((link, *now, frame));
            work = true;
        }
        for (index, peer) in peers.iter_mut().enumerate() {
            if let Some((_, frame)) = emit_on(peer, *now + 2) {
                let context = a.2[index];
                deliver(a, context, *now + 3, &frame);
                work = true;
            }
        }
        if !work {
            return;
        }
    }
    panic!("wire exchange did not quiesce");
}

fn tuple() -> Tuple {
    Tuple {
        local: LOCAL.parse().unwrap(),
        remote: REMOTE.parse().unwrap(),
    }
}

fn peers(cfg: &EndpointConfig, identity: u64) -> Vec<Peer> {
    (0..2)
        .map(|index| {
            let mut peer = scoped_side(REMOTE, 1, identity + index, cfg);
            let zone = peer.2[0].link();
            peer.1
                .listen_scoped(REMOTE.parse().unwrap(), Some(zone), 1)
                .unwrap();
            peer
        })
        .collect()
}

// Both links carry the same fe80::1:1000 -> fe80::2:8080 connection.
fn two_scoped_connections(cfg: &EndpointConfig, identity: u64) -> (Peer, Vec<Peer>, [ConnectionId; 2], u64) {
    let mut a = scoped_side(LOCAL, 2, identity, cfg);
    let mut b = peers(cfg, identity + 10);
    let mut ids = [None; 2];
    for (index, id) in ids.iter_mut().enumerate() {
        let scoped = ScopedTuple::new(tuple(), Some(a.2[index].link())).unwrap();
        *id = Some(
            a.1.connect_scoped_with_path_provider(0, scoped, options(cfg, 0), &mut a.0)
                .unwrap(),
        );
    }
    let mut now = 0;
    pump_links(&mut a, &mut b, &mut now);
    (a, b, ids.map(Option::unwrap), now)
}

#[test]
fn identical_link_local_pairs_on_two_links_are_separate_connections() {
    let cfg = config(4);
    let (a, b, ids, _) = two_scoped_connections(&cfg, 7100);
    assert_ne!(ids[0], ids[1]);
    for (index, id) in ids.into_iter().enumerate() {
        let zone = a.2[index].link();
        assert_eq!(a.1.state(id), Ok(State::Established));
        assert_eq!(
            a.1.scoped_connection_id(ScopedTuple::new(tuple(), Some(zone)).unwrap()),
            Some(id)
        );
        assert_eq!(a.1.retained_scoped_tuple(id).unwrap().zone(), Some(zone));
        // Each path lies on its own link, to that link's peer.
        let key = a.0.binding(id).unwrap().snapshot.key();
        assert_eq!(key.link(), zone);
        assert_eq!(key.destination().zone(), Some(zone));
        // The peer's child carries its arrival link's scope.
        let peer = &b[index];
        let reverse = Tuple {
            local: REMOTE.parse().unwrap(),
            remote: LOCAL.parse().unwrap(),
        };
        let child = peer
            .1
            .scoped_connection_id(ScopedTuple::new(reverse, Some(peer.2[0].link())).unwrap())
            .unwrap();
        assert_eq!(peer.1.state(child), Ok(State::Established));
    }
    // The two scoped paths are distinct PMTU records.
    assert_ne!(
        a.0.binding(ids[0]).unwrap().snapshot.path(),
        a.0.binding(ids[1]).unwrap().snapshot.path()
    );
    // The unscoped legacy identity names neither.
    assert_eq!(a.1.connection_id(tuple()), None);
    // A third open of an existing scoped identity is refused.
    let mut a = a;
    let scoped = ScopedTuple::new(tuple(), Some(a.2[0].link())).unwrap();
    assert_eq!(
        a.1.connect_scoped_with_path_provider(1_000, scoped, options(&cfg, 0), &mut a.0),
        Err(ManagedError::Endpoint(EndpointError::AddressInUse))
    );
    // A link-local tuple needs its zone, and a zone is only for one.
    assert!(ScopedTuple::new(tuple(), None).is_none());
    let (local, remote) = addresses(true);
    assert!(ScopedTuple::new(Tuple { local, remote }, Some(a.2[0].link())).is_none());
    std::println!("two links: {ids:?} established on the same link-local tuple");
}

//= https://www.rfc-editor.org/rfc/rfc8201#section-5.2
//= type=test
//= reason=Each IPv6 link keeps its own Path MTU information. PathService keys learned estimates by context, source, destination with its zone, routing DSCP, link, next hop and route generation, and a link-local destination carries an authoritative LinkId zone (context, slot, generation) with which Host::prepare selects and acquires the path on exactly that link before TCP construction. T18 carries this scoped tuple through Endpoint and Host factories, listeners (an exact address and zone beats the wildcard; wildcard children carry the arrival link), TIME-WAIT, digests, Fast Open and MSS caches, Host UDP flows and zone-constrained ICMP correlation; the native runtime resolves sin6_scope_id through its interface-index-to-live-link map over a bounded collection of configured ports, each with its own link, addresses and routes, and IPv6 Ethernet ports resolve next hops by bounded host Neighbor Discovery. Host tests (ntcp-host src/tests/scoped.rs) keep identical link-local pairs on two links as separate connections and UDP flows, and a PTB correlated with one link's submission lowers only that link's estimate; the native two-port test neighbor_discovery_ports_keep_path_mtu_per_link probes each connection up to its own link MTU (1500 and 1400), and a checksummed PTB quoting a packet definitely submitted on one port lowers only that port's estimate and packet sizes while the other port's estimate and both first-hop MTUs stay unchanged; the integration/rfc_host scoped two-link case (one native runtime owning two veth links of MTU 1500 and 1400 to one Linux peer namespace, identical link-local pairs, captured DAD and NS/NA, hashed TCP streams on both links) shows a checksummed, harness-injected PTB quoting a captured packet on link A lowering only A's learned PMTU and packet sizes while link B keeps 1400-octet packets and both first-hop MTUs stay unchanged, and later connections start at their own link's value.
//# Ideally, a PMTU value should be associated with a specific path traversed by packets exchanged between the source and destination nodes. However, in most cases a node will not have enough information to completely and accurately identify such a path. Rather, a node must associate a PMTU value with some local representation of a path. It is left to the implementation to select the local representation of a path. For nodes with multiple interfaces, Path MTU information should be maintained for each IPv6 link.
#[test]
fn ptb_lowers_only_the_link_whose_submission_it_quotes() {
    let cfg = config(4);
    let (mut a, _b, ids, now) = two_scoped_connections(&cfg, 7200);
    for id in ids {
        a.1.write(id, &[7; 1400]).unwrap();
    }
    let (link, first) = emit_on(&mut a, now + 10).unwrap();
    let (other, _) = emit_on(&mut a, now + 11).unwrap();
    assert_ne!(link, other);
    let (owner, sibling) = if link == a.2[0].link() {
        (ids[0], ids[1])
    } else {
        (ids[1], ids[0])
    };
    let arrival = a.0.ingress_context(link).unwrap();
    let wrong = a.0.ingress_context(other).unwrap();
    let report = ptb(&first, 1280);
    // The same link-local address on the other link did not send it.
    assert_eq!(
        a.0.input_icmp(&mut a.1, wrong, now + 12, &report, None),
        Ok(IcmpDispatch::Completed(IcmpOutcome::Discarded(
            IcmpDiscard::Uncorrelated
        )))
    );
    let learned = |a: &Peer, id| {
        let path = a.0.binding(id).unwrap().snapshot.path();
        a.0.paths().path_snapshot(path).unwrap().learned_mtu()
    };
    assert_eq!(learned(&a, owner), None);
    let (report, published) =
        tcp_report(a.0.input_icmp(&mut a.1, arrival, now + 13, &report, None).unwrap());
    assert!(matches!(
        report,
        TcpReport::PacketTooBig(PmtuFeedback::Decreased { .. })
    ));
    assert_eq!(published, Some(path::EstimateChange::Decreased));
    assert_eq!(learned(&a, owner), Some(1280));
    assert_eq!(learned(&a, sibling), None);
    // Both links keep their 1500 first-hop facts.
    for id in ids {
        assert_eq!(a.0.binding(id).unwrap().snapshot.first_hop_mtu(), 1500);
    }
    std::println!("PTB on {link:?} lowered only {owner:?}; {sibling:?} keeps its estimate");
}

// Lossy history is scoped like exact records: the discarded summary of a
// released flow on link 1 denies attribution only within that zone, so the
// identical link-local four-tuple on link 0 keeps its PTB attributable.
#[test]
fn discarded_history_of_one_link_leaves_the_other_links_ptb_attributable() {
    let cfg = config(4);
    // Discarded summaries shadow hash classes of flow keys. The case needs
    // the four-tuple's keys on the two links in different classes, so it
    // takes the first context identity that gives them.
    let local: SocketAddr = LOCAL.parse().unwrap();
    let remote: SocketAddr = REMOTE.parse().unwrap();
    let mut a = (7250..)
        .step_by(20)
        .take(64)
        .map(|identity| scoped_side_with(LOCAL, 2, identity, &cfg, 2))
        .find(|a| {
            let class = |link| a.0.ledger.discard_class(local, remote, Some(link));
            class(a.2[0].link()) != class(a.2[1].link())
        })
        .expect("an identity separating the links' classes");
    let (kept, other) = (a.2[0], a.2[1]);
    let open = |a: &mut Peer, port: u16, zone| {
        let bind = SocketAddr::new(local.ip(), port);
        a.0.udp_open_scoped(&a.1, bind, Some(remote), Some(zone), UDP_OPTIONS)
            .unwrap()
    };
    // Closed flows on link 1, each after one datagram: first the same
    // four-tuple, then others until the summaries overflow and the first,
    // the oldest, is discarded.
    let mut now = 0;
    let mut sent = Vec::new();
    for port in core::iter::once(1000).chain(3000..3100) {
        if a.0.ledger.discards() != 0 {
            break;
        }
        now += 10;
        let flow = open(&mut a, port, other.link());
        let (link, frame) = udp_out(&mut a, now, flow, &[5; 1400]);
        assert_eq!(link, other.link());
        sent.push(frame);
        a.0.udp_close(flow).unwrap();
    }
    assert_eq!(a.0.ledger.discards(), 1);
    let forgotten = super::correlation::quoted_key(&sent[0]);
    assert_eq!(
        a.0.ledger
            .correlate_in(now, &forgotten, Some(other.link()))
            .matches,
        0
    );
    now += 10;
    let flow = open(&mut a, 1000, kept.link());
    let (link, frame) = udp_out(&mut a, now, flow, &[5; 1400]);
    assert_eq!(link, kept.link());
    assert_eq!(frame, sent[0], "identical datagrams on both links");
    let key = super::correlation::quoted_key(&frame);
    let correlation = a.0.ledger.correlate_in(now, &key, Some(kept.link()));
    assert!(!correlation.summarized);
    let owner = correlation.owner.map(|r| r.evidence.owner);
    assert!(owner.is_some());
    assert!(matches!(
        a.0.input_icmp(&mut a.1, kept, now + 1, &ptb(&frame, 1280), None),
        Ok(IcmpDispatch::Completed(IcmpOutcome::Advice {
            owner: advised,
            published: Some(path::EstimateChange::Decreased),
            ..
        })) if advised == owner
    ));
    assert!(matches!(
        a.0.udp_event(flow).unwrap(),
        Some(UdpEvent::PacketTooBig { .. })
    ));
    // The discarded history still denies in its own zone: a new flow on
    // link 1's four-tuple is not attributable until its horizon.
    a.0.udp_close(flow).unwrap();
    now += 10;
    let again = open(&mut a, 1000, other.link());
    let (link, frame) = udp_out(&mut a, now, again, &[5; 1400]);
    assert_eq!(link, other.link());
    let key = super::correlation::quoted_key(&frame);
    let correlation = a.0.ledger.correlate_in(now, &key, Some(other.link()));
    assert_eq!(correlation.matches, 1);
    assert_eq!(correlation.owner, None, "blinded by its own zone's discard");
    // The forgotten datagram left at 10; the new one is still live then.
    let horizon = a.0.ledger.limits().feedback_horizon;
    assert!(
        a.0.ledger
            .correlate_in(10 + horizon, &key, Some(other.link()))
            .owner
            .is_some()
    );
    std::println!(
        "link 1 summary discarded after {} closed flows; link 0 PTB still attributable",
        sent.len()
    );
}

#[test]
fn wildcard_listener_children_carry_their_arrival_link_and_exact_scope_wins() {
    let cfg = config(4);
    let mut server = scoped_side(REMOTE, 2, 7300, &cfg);
    let wildcard = server.1.listen("[::]:8080".parse().unwrap(), 2).unwrap();
    // An exact listener on the second link only.
    let exact = server
        .1
        .listen_scoped(REMOTE.parse().unwrap(), Some(server.2[1].link()), 2)
        .unwrap();
    // A zone is required for, and only for, a link-local listener.
    assert_eq!(
        server.1.listen_scoped(REMOTE.parse().unwrap(), None, 1),
        Err(EndpointError::InvalidAddress)
    );
    assert_eq!(
        server
            .1
            .listen_scoped("[::]:9090".parse().unwrap(), Some(server.2[0].link()), 1),
        Err(EndpointError::InvalidAddress)
    );
    let mut clients: Vec<Peer> = (0..2).map(|i| scoped_side(LOCAL, 1, 7310 + i, &cfg)).collect();
    for client in &mut clients {
        let zone = client.2[0].link();
        client
            .1
            .connect_scoped_with_path_provider(
                0,
                ScopedTuple::new(tuple(), Some(zone)).unwrap(),
                options(&cfg, 0),
                &mut client.0,
            )
            .unwrap();
    }
    let mut now = 0;
    pump_links(&mut server, &mut clients, &mut now);
    let reverse = Tuple {
        local: REMOTE.parse().unwrap(),
        remote: LOCAL.parse().unwrap(),
    };
    let first = server.1.accept(wildcard).unwrap();
    let second = server.1.accept(exact).unwrap();
    assert_eq!(
        server.1.accept(wildcard),
        Err(EndpointError::Connection(ntcp::Error::WouldBlock))
    );
    for (child, index) in [(first, 0), (second, 1)] {
        let zone = server.2[index].link();
        assert_eq!(
            server.1.retained_scoped_tuple(child).unwrap(),
            ScopedTuple::new(reverse, Some(zone)).unwrap()
        );
        assert_eq!(server.0.binding(child).unwrap().snapshot.key().link(), zone);
    }
    std::println!("wildcard child {first:?} on link 0; exact child {second:?} on link 1");
}

// Identical exact link-local listeners on two links coexist in one
// Endpoint (RFC 4007 section 6); a second one in the same zone is refused,
// and each accepts only its own link's connection.
#[test]
fn identical_exact_link_local_listeners_on_two_links_accept_their_own_children() {
    let cfg = config(4);
    let mut server = scoped_side(REMOTE, 2, 7330, &cfg);
    let listeners: Vec<_> = (0..2)
        .map(|i| {
            server
                .1
                .listen_scoped(REMOTE.parse().unwrap(), Some(server.2[i].link()), 2)
                .unwrap()
        })
        .collect();
    assert_eq!(
        server
            .1
            .listen_scoped(REMOTE.parse().unwrap(), Some(server.2[1].link()), 2),
        Err(EndpointError::AddressInUse)
    );
    let mut clients: Vec<Peer> = (0..2)
        .map(|i| scoped_side(LOCAL, 1, 7340 + i, &cfg))
        .collect();
    for client in &mut clients {
        let zone = client.2[0].link();
        client
            .1
            .connect_scoped_with_path_provider(
                0,
                ScopedTuple::new(tuple(), Some(zone)).unwrap(),
                options(&cfg, 0),
                &mut client.0,
            )
            .unwrap();
    }
    let mut now = 0;
    pump_links(&mut server, &mut clients, &mut now);
    let reverse = Tuple {
        local: REMOTE.parse().unwrap(),
        remote: LOCAL.parse().unwrap(),
    };
    for (index, &listener) in listeners.iter().enumerate() {
        let child = server.1.accept(listener).unwrap();
        let zone = server.2[index].link();
        assert_eq!(
            server.1.retained_scoped_tuple(child).unwrap(),
            ScopedTuple::new(reverse, Some(zone)).unwrap()
        );
        assert_eq!(server.0.binding(child).unwrap().snapshot.key().link(), zone);
        assert_eq!(
            server.1.accept(listener),
            Err(EndpointError::Connection(ntcp::Error::WouldBlock))
        );
    }
}

#[test]
fn removed_and_replaced_links_reject_stale_ingress_feedback_and_opens() {
    let cfg = config(4);
    let (mut a, mut b, ids, now) = two_scoped_connections(&cfg, 7400);
    a.1.write(ids[0], &[3; 100]).unwrap();
    let (link, sent) = emit_on(&mut a, now + 10).unwrap();
    assert_eq!(link, a.2[0].link());
    let stale = a.2[0];
    // The peer's next segment for the first connection.
    let reverse = Tuple {
        local: REMOTE.parse().unwrap(),
        remote: LOCAL.parse().unwrap(),
    };
    let peer_id = b[0]
        .1
        .scoped_connection_id(ScopedTuple::new(reverse, Some(b[0].2[0].link())).unwrap())
        .unwrap();
    b[0].1.write(peer_id, &[4; 10]).unwrap();
    let (_, data) = emit_on(&mut b[0], now + 11).unwrap();
    a.0.remove_link(stale).unwrap();
    // Output of the removed zone's connection, reserved after removal, is
    // refused at egress; it has no path.
    a.1.write(ids[0], &[6; 10]).unwrap();
    let (attempt, packet, _) = selected(&mut a.1, now + 11).unwrap();
    assert_eq!(packet.connection, Some(ids[0]));
    assert!(a.0.egress_context(&mut a.1, attempt).is_err());
    // The removed link's generation admits nothing.
    assert!(a.0.input_ip(&mut a.1, stale, now + 12, &data, RxPacketMetadata::default(), 0, None).is_err());
    assert!(a.0.input_icmp(&mut a.1, stale, now + 12, &ptb(&sent, 1280), None).is_err());
    // A replacement link reusing the interface is a new zone: the old
    // connection's packets arriving there name no connection of it.
    let replacement = a
        .0
        .register_link(
            InterfaceKey(1),
            1500,
            ReceiveCapabilities {
                max_ip_packet: 65575,
                ipv4: Ipv4Receive::Disabled,
                ipv6: Ipv6Receive::BaseHeader,
                gro: false,
            },
            Forwarding::Forwarder(ForwarderId(9)),
        )
        .unwrap();
    assert_ne!(replacement.link(), stale.link());
    a.0.register_source(
        ScopedAddress::new("fe80::1".parse().unwrap(), Some(replacement.link())).unwrap(),
        replacement.link(),
    )
    .unwrap();
    assert_eq!(
        a.0.input_icmp(&mut a.1, replacement, now + 13, &ptb(&sent, 1280), None),
        Ok(IcmpDispatch::Completed(IcmpOutcome::Discarded(
            IcmpDiscard::Uncorrelated
        )))
    );
    let before = a.1.state(ids[0]);
    let result = a.0.input_ip(
        &mut a.1,
        replacement,
        now + 14,
        &data,
        RxPacketMetadata::default(),
        0,
        None,
    );
    std::println!("old-zone data on the replacement link: {result:?}");
    assert_eq!(a.1.state(ids[0]), before);
    assert_eq!(
        a.1.scoped_connection_id(ScopedTuple::new(tuple(), Some(replacement.link())).unwrap()),
        None
    );
    // A stale zone opens nothing: there is no path on a removed link.
    let scoped = ScopedTuple::new(tuple(), Some(stale.link())).unwrap();
    let local: SocketAddr = "[fe80::1]:1001".parse().unwrap();
    let stale_open = ScopedTuple::new(
        Tuple {
            local,
            remote: scoped.tuple().remote,
        },
        scoped.zone(),
    )
    .unwrap();
    assert!(a
        .1
        .connect_scoped_with_path_provider(now + 15, stale_open, options(&cfg, 0), &mut a.0)
        .is_err());
    assert!(a.0.refresh(&mut a.1, ids[0]).is_err());
    let live = a.0.refresh(&mut a.1, ids[1]).unwrap();
    assert_eq!(live.snapshot.key().link(), a.2[1].link());
}

// Withdrawing one link's scoped source while the link stays up retires
// only that zone's connection: its binding, ingress and new opens are
// refused, the identical address owned on the other link is untouched, and
// a re-registered source is a new owner to which bindings resolve afresh.
#[test]
fn scoped_source_replacement_on_a_live_link_rejects_the_old_binding() {
    let cfg = config(4);
    let (mut a, mut b, ids, now) = two_scoped_connections(&cfg, 7450);
    let (kept, other) = (a.2[0], a.2[1]);
    let reverse = Tuple {
        local: REMOTE.parse().unwrap(),
        remote: LOCAL.parse().unwrap(),
    };
    let mut data = Vec::new();
    for peer in &mut b {
        let zone = peer.2[0].link();
        let id = peer
            .1
            .scoped_connection_id(ScopedTuple::new(reverse, Some(zone)).unwrap())
            .unwrap();
        peer.1.write(id, &[4; 10]).unwrap();
        data.push(emit_on(peer, now + 10).unwrap().1);
    }
    let scoped = |link: LinkId| ScopedAddress::new("fe80::1".parse().unwrap(), Some(link)).unwrap();
    let old = a.0.paths().local_source(scoped(kept.link()), kept.link()).unwrap();
    assert_eq!(a.0.binding(ids[0]).unwrap().snapshot.key().source(), old);
    a.0.remove_source_owner(old, kept.link()).unwrap();
    // The withdrawn zone's connection has no binding, receives nothing and
    // its output reserved now is refused at egress.
    assert_eq!(
        a.0.refresh(&mut a.1, ids[0]).map(|_| ()),
        Err(Error::Path(path::Error::SourceNotOwned))
    );
    assert!(
        a.0.input_ip(&mut a.1, kept, now + 11, &data[0], RxPacketMetadata::default(), 0, None)
            .is_err()
    );
    a.1.write(ids[0], &[6; 10]).unwrap();
    let (attempt, packet, _) = selected(&mut a.1, now + 12).unwrap();
    assert_eq!(packet.connection, Some(ids[0]));
    assert!(a.0.egress_context(&mut a.1, attempt).is_err());
    assert!(a.1.reject_unsubmitted(attempt).unwrap());
    let open = |a: &mut Peer, port: u16, now: u64| {
        let tuple = Tuple {
            local: SocketAddr::new("fe80::1".parse().unwrap(), port),
            remote: REMOTE.parse().unwrap(),
        };
        let scoped = ScopedTuple::new(tuple, Some(kept.link())).unwrap();
        a.1.connect_scoped_with_path_provider(now, scoped, options(&cfg, 0), &mut a.0)
    };
    // The identical address owned on the other link opens nothing here.
    assert_eq!(
        open(&mut a, 1001, now + 13),
        Err(ManagedError::Provider(Error::Path(path::Error::SourceNotOwned)))
    );
    // The other zone is untouched.
    let live = a.0.refresh(&mut a.1, ids[1]).unwrap();
    assert_eq!(live.snapshot.key().link(), other.link());
    assert_eq!(
        a.0.input_ip(&mut a.1, other, now + 14, &data[1], RxPacketMetadata::default(), 0, None),
        Ok(ntcp::InputDisposition::Processed)
    );
    // The re-registered source is a new owner: the connection is bound to
    // it afresh, never through the withdrawn one.
    let new = a.0.register_source(scoped(kept.link()), kept.link()).unwrap();
    assert_ne!(new, old);
    let rebound = a.0.refresh(&mut a.1, ids[0]).unwrap();
    assert_eq!(rebound.snapshot.key().source(), new);
    assert_eq!(rebound.snapshot.key().link(), kept.link());
    let id = open(&mut a, 1002, now + 15).unwrap();
    assert_eq!(a.0.binding(id).unwrap().snapshot.key().source(), new);
    assert_eq!(a.0.binding(ids[1]).unwrap().snapshot.key().link(), other.link());
}

#[test]
fn fast_open_cookies_and_peer_mss_are_learned_per_link() {
    let cfg = config(6);
    let mut a = scoped_side(LOCAL, 2, 7500, &cfg);
    a.1.enable_fast_open().unwrap();
    let mut b = peers(&cfg, 7510);
    for peer in &mut b {
        peer.1.enable_fast_open().unwrap();
        let listener = peer
            .1
            .matching_scoped_listener(REMOTE.parse().unwrap(), Some(peer.2[0].link()))
            .unwrap();
        peer.1.set_listener_fast_open(listener, 4).unwrap();
    }
    let open = |a: &mut Peer, port: u16, index: usize, now: u64| {
        let tuple = Tuple {
            local: SocketAddr::new("fe80::1".parse().unwrap(), port),
            remote: REMOTE.parse().unwrap(),
        };
        let zone = a.2[index].link();
        a.1.connect_fast_open_scoped_with_path_provider(
            now,
            ScopedTuple::new(tuple, Some(zone)).unwrap(),
            &[9; 100],
            options(&cfg, 0),
            None,
            FastOpenClientPolicy::RequireCookie,
            &mut a.0,
        )
        .unwrap()
    };
    // A cookie request on the first link only.
    let (_, admitted) = open(&mut a, 1000, 0, 0);
    assert_eq!(admitted, 0);
    let mut now = 0;
    pump_links(&mut a, &mut b, &mut now);
    // The first link's server cookie (and its MSS) authorizes early data
    // there; the same address pair on the second link has learned nothing.
    let (_, first) = open(&mut a, 1001, 0, now + 10);
    let (_, second) = open(&mut a, 1001, 1, now + 10);
    assert_eq!(first, 100);
    assert_eq!(second, 0);
    // The unscoped identity of the same addresses has no cookie either.
    assert!(
        !a.1
            .has_fast_open_cookie(now + 10, "fe80::1".parse().unwrap(), "fe80::2".parse().unwrap())
            .unwrap()
    );
    std::println!("early data with the learned cookie: link 0 {first}, link 1 {second}");
}

#[test]
fn time_wait_reuse_stays_within_its_scoped_identity() {
    let mut cfg = config(6);
    cfg.reuse_time_wait = true;
    let mut server = scoped_side(REMOTE, 2, 7600, &cfg);
    let wildcard = server.1.listen("[::]:8080".parse().unwrap(), 4).unwrap();
    let client = |identity| {
        let mut client = scoped_side(LOCAL, 1, identity, &cfg);
        let zone = client.2[0].link();
        client
            .1
            .connect_scoped_with_path_provider(
                0,
                ScopedTuple::new(tuple(), Some(zone)).unwrap(),
                options(&cfg, 0),
                &mut client.0,
            )
            .unwrap();
        client
    };
    let reverse = Tuple {
        local: REMOTE.parse().unwrap(),
        remote: LOCAL.parse().unwrap(),
    };
    let zoned = |server: &Peer, index: usize| {
        ScopedTuple::new(reverse, Some(server.2[index].link())).unwrap()
    };
    // The server's virtual timestamp clock of each packet: TSval less the
    // caller time in TSval units (milliseconds of a microsecond timebase).
    let offsets = |sent: &[(LinkId, u64, Vec<u8>)], link: LinkId| -> Vec<u32> {
        sent.iter()
            .filter(|(l, ..)| *l == link)
            .map(|(_, now, frame)| {
                let ip = IpMetadata {
                    source: REMOTE.parse::<SocketAddr>().unwrap().ip(),
                    destination: LOCAL.parse::<SocketAddr>().unwrap().ip(),
                };
                let segment = ntcp::wire::parse(ip, &frame[40..]).unwrap();
                segment.options.timestamps.unwrap().0.wrapping_sub((now / 1000) as u32)
            })
            .collect()
    };
    // The server closes first on link 0 and holds TIME-WAIT there.
    let mut clients = vec![client(7610), scoped_side(LOCAL, 1, 7611, &cfg)];
    let mut now = 0;
    let mut sent = Vec::new();
    pump_recorded(&mut server, &mut clients, &mut now, &mut sent);
    let old = server.1.accept(wildcard).unwrap();
    let client_id = clients[0].1.scoped_connection_id(ScopedTuple::new(tuple(), Some(clients[0].2[0].link())).unwrap()).unwrap();
    server.1.close(old).unwrap();
    pump_recorded(&mut server, &mut clients, &mut now, &mut sent);
    clients[0].1.close(client_id).unwrap();
    pump_recorded(&mut server, &mut clients, &mut now, &mut sent);
    assert_eq!(server.1.state(old), Ok(State::TimeWait));
    let first = offsets(&sent, server.2[0].link());
    assert!(first.len() >= 3 && first.iter().all(|&o| o == first[0]));
    // The same address pair on link 1 opens a new connection beside it,
    // with its own timestamp clock (the offset digest includes the zone).
    clients[1] = client(7612);
    let mut sent = Vec::new();
    pump_recorded(&mut server, &mut clients, &mut now, &mut sent);
    let beside = server.1.accept(wildcard).unwrap();
    let second = offsets(&sent, server.2[1].link());
    assert!(!second.is_empty() && second.iter().all(|&o| o == second[0]));
    assert_ne!(second[0], first[0]);
    assert_eq!(server.1.retained_scoped_tuple(beside).unwrap(), zoned(&server, 1));
    assert_eq!(server.1.state(old), Ok(State::TimeWait));
    assert_eq!(server.1.scoped_connection_id(zoned(&server, 0)), Some(old));
    // A new SYN on link 0 replaces the TIME-WAIT record of that zone and
    // continues its timestamp clock (RFC 6191 4: the peer's PAWS sees no
    // jump). It comes from the same client, whose secret and link are the
    // first one's: its tuple's TSval offset is the first incarnation's, so
    // the SYN's timestamp is newer than any the TIME-WAIT saw.
    clients[0] = client(7610);
    now += 1_000_000;
    let mut sent = Vec::new();
    pump_recorded(&mut server, &mut clients, &mut now, &mut sent);
    let reused = server.1.accept(wildcard).unwrap();
    let third = offsets(&sent, server.2[0].link());
    assert!(!third.is_empty() && third.iter().all(|&o| o == first[0]));
    assert_ne!(reused, old);
    assert_eq!(server.1.scoped_connection_id(zoned(&server, 0)), Some(reused));
    assert_eq!(server.1.scoped_connection_id(zoned(&server, 1)), Some(beside));
    std::println!("TIME-WAIT {old:?} replaced by {reused:?}; link 1 connection {beside:?} kept");
}

// A client's first SYN for the shared link-local tuple.
fn link_local_syn(cfg: &EndpointConfig, identity: u64) -> Vec<u8> {
    let mut client = scoped_side(LOCAL, 1, identity, cfg);
    let zone = client.2[0].link();
    client
        .1
        .connect_scoped_with_path_provider(
            0,
            ScopedTuple::new(tuple(), Some(zone)).unwrap(),
            options(cfg, 0),
            &mut client.0,
        )
        .unwrap();
    emit_on(&mut client, 1).unwrap().1
}

// The RST answering `syn` (RFC 9293 3.10.7.1, no ACK: <SEQ=0><ACK=SEG.SEQ+1>).
fn assert_reset_for(syn: &[u8], frame: &[u8]) {
    let word = |b: &[u8], at: usize| u32::from_be_bytes(b[at..at + 4].try_into().unwrap());
    assert_eq!(frame[6], 6);
    assert_eq!(&frame[8..24], &syn[24..40]);
    assert_eq!(&frame[24..40], &syn[8..24]);
    assert_eq!(&frame[40..42], &syn[42..44]);
    assert_eq!(&frame[42..44], &syn[40..42]);
    assert_eq!(frame[40 + 13], ntcp::wire::RST | ntcp::wire::ACK);
    assert_eq!(word(frame, 44), 0);
    assert_eq!(word(frame, 48), word(syn, 44).wrapping_add(1));
}

#[test]
fn stateless_resets_to_link_local_peers_leave_on_their_arrival_link() {
    let cfg = config(4);
    let syn = link_local_syn(&cfg, 7700);
    // No listener: both identical SYNs reach a closed port.
    let mut server = scoped_side(REMOTE, 2, 7710, &cfg);
    for (index, now) in [(1, 10), (0, 20)] {
        let arrival = server.2[index];
        deliver(&mut server, arrival, now, &syn);
        let (attempt, packet, _) = selected(&mut server.1, now + 1).unwrap();
        assert_eq!(packet.connection, None);
        assert_eq!(
            server.1.transmit_attempt_zone(attempt),
            Some(Some(arrival.link()))
        );
        server.1.reject_unsubmitted(attempt).unwrap();
        // Queue it again (the reply was discarded) and send it.
        deliver(&mut server, arrival, now + 2, &syn);
        let (link, frame) = emit_on(&mut server, now + 3).unwrap();
        assert_eq!(link, arrival.link());
        assert_reset_for(&syn, &frame);
        assert!(emit_on(&mut server, now + 4).is_none());
    }
    assert_eq!(server.1.undeliverable_control_replies(), 0);
    std::println!("RSTs for identical link-local SYNs left on their arrival links");
}

#[test]
fn stateless_reset_queued_before_its_link_is_replaced_is_dropped_and_counted() {
    let cfg = config(4);
    let syn = link_local_syn(&cfg, 7800);
    let mut server = scoped_side(REMOTE, 2, 7810, &cfg);
    let stale = server.2[1];
    deliver(&mut server, stale, 10, &syn);
    // The arrival link is replaced (same interface, same link-local source
    // and route) before the queued reply drains.
    server.0.remove_link(stale).unwrap();
    let replacement = server
        .0
        .register_link(
            InterfaceKey(2),
            1500,
            ReceiveCapabilities {
                max_ip_packet: 65575,
                ipv4: Ipv4Receive::Disabled,
                ipv6: Ipv6Receive::BaseHeader,
                gro: false,
            },
            Forwarding::Forwarder(ForwarderId(10)),
        )
        .unwrap();
    assert_ne!(replacement.link(), stale.link());
    server
        .0
        .register_source(
            ScopedAddress::new("fe80::2".parse().unwrap(), Some(replacement.link())).unwrap(),
            replacement.link(),
        )
        .unwrap();
    server
        .0
        .add_route(path::Route {
            destination: path::IpPrefix::new("fe80::".parse().unwrap(), 64).unwrap(),
            source: None,
            dscp: None,
            link: replacement.link(),
            next_hop: path::NextHop::Forwarder(ForwarderId(10)),
            metric: 0,
        })
        .unwrap();
    let (attempt, packet, _) = selected(&mut server.1, 11).unwrap();
    assert_eq!(packet.connection, None);
    assert_eq!(server.1.transmit_attempt_zone(attempt), Some(Some(stale.link())));
    // Refused (never placed on the replacement or the other link) and
    // counted once however often it is asked for.
    for _ in 0..2 {
        assert_eq!(
            server.0.egress_context(&mut server.1, attempt).map(|c| c.link),
            Err(Error::Obsolete)
        );
    }
    assert_eq!(server.1.undeliverable_control_replies(), 1);
    assert_eq!(server.1.oversized_control_replies(), 0);
    // The embedding discards the certainly unsubmitted reply: nothing is
    // retried.
    assert!(server.1.reject_unsubmitted(attempt).unwrap());
    assert!(selected(&mut server.1, 12).is_none());
    server.0.collect(&server.1).unwrap();
    assert_eq!(server.0.lease_count(), 0);
    assert_eq!(server.1.undeliverable_control_replies(), 1);
    // The same SYN arriving on the replacement draws its reset there.
    deliver(&mut server, replacement, 13, &syn);
    let (link, frame) = emit_on(&mut server, 14).unwrap();
    assert_eq!(link, replacement.link());
    assert_reset_for(&syn, &frame);
    std::println!("reply for the replaced link dropped once; replacement link answered");
}

#[test]
fn unscoped_stateless_reset_keeps_its_bytes() {
    let cfg = config(4);
    let (local, remote) = addresses(true);
    let mut a = managed(local, 7900, cfg.clone());
    let mut b = managed(remote, 7901, cfg.clone());
    a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
        .unwrap();
    let syn = emit(&mut a.0, &mut a.1, 1).unwrap();
    input(&mut b.0, &mut b.1, b.2, 2, &syn, 0);
    let (attempt, _, _) = selected(&mut b.1, 3).unwrap();
    assert_eq!(b.1.transmit_attempt_zone(attempt), Some(None));
    b.1.reject_unsubmitted(attempt).unwrap();
    input(&mut b.0, &mut b.1, b.2, 4, &syn, 0);
    let frame = emit(&mut b.0, &mut b.1, 5).unwrap();
    assert_reset_for(&syn, &frame);
    // The same reply an unmanaged Endpoint emits for this SYN.
    let mut raw = Endpoint::new(cfg.clone(), [1; 32], 0, |_| true).unwrap();
    let ip = IpMetadata {
        source: local.ip(),
        destination: remote.ip(),
    };
    raw.input(4, ip, &syn[40..]).unwrap();
    let mut tcp = [0; 256];
    let packet = raw.poll_transmit(5, &mut tcp, 16).unwrap().packet.unwrap();
    assert_eq!(&frame[40..], &tcp[..packet.len]);
    assert_eq!(b.1.undeliverable_control_replies(), 0);
}

// An administrative downward estimate on one link's scoped path reaches
// its binding within `admin_apply` (the fan-out compares the zoned
// forwarding destination); the identical tuple on the other link keeps
// its budget.
#[test]
fn admin_estimate_lowers_a_scoped_binding_at_once() {
    let cfg = config(4);
    let (mut a, _b, ids, now) = two_scoped_connections(&cfg, 7950);
    let budget = |a: &Peer, id| a.0.binding(id).unwrap().snapshot.ip_packet_budget();
    let before = ids.map(|id| a.1.transport_ceilings(id).unwrap().effective_mss);
    assert_eq!(budget(&a, ids[0]), Ok(1500));
    let capability = a.0.administration();
    let path = a.0.binding(ids[0]).unwrap().snapshot.path();
    let expected = a.0.admin_path(&capability, path).unwrap().generation;
    let candidate = a
        .0
        .admin_validate(
            &capability,
            now,
            path::AdminChange {
                target: path::AdminTarget::Path(path),
                expected,
                policy: path::AdminPolicy {
                    discovery_disabled: false,
                    estimate: Some(1400),
                },
            },
        )
        .unwrap();
    a.0.admin_apply(&capability, &mut a.1, candidate).unwrap();
    assert!(!a.0.paths().is_dirty(a.0.binding(ids[0]).unwrap().client).unwrap());
    assert_eq!(budget(&a, ids[0]), Ok(1400));
    assert_eq!(a.1.transport_ceilings(ids[0]).unwrap().effective_mss, before[0] - 100);
    assert_eq!(budget(&a, ids[1]), Ok(1500));
    assert_eq!(a.1.transport_ceilings(ids[1]).unwrap().effective_mss, before[1]);
}

const UDP_OPTIONS: UdpOptions = UdpOptions {
    dscp: 0,
    hop_limit: 64,
};

// Send `payload` on `flow` and report the link it left on with its bytes.
fn udp_out(side: &mut Peer, now: u64, flow: UdpFlowId, payload: &[u8]) -> (LinkId, Vec<u8>) {
    let mut packet = vec![0; 2048];
    let mut sent = None;
    let result = side.0.udp_send(&side.1, now, flow, None, payload, &mut packet, |egress, bytes| {
        sent = Some((egress.link, bytes.to_vec()));
        BackendOutcome::Submitted
    });
    assert!(matches!(result, Ok(UdpSent::Submitted(_))), "{result:?}");
    sent.unwrap()
}

// One peer per link, each with a fe80::2:8080 flow connected to
// fe80::1:1000 on its only link.
fn udp_peers(cfg: &EndpointConfig, identity: u64) -> Vec<(Peer, UdpFlowId)> {
    (0..2)
        .map(|index| {
            let mut peer = scoped_side_with(REMOTE, 1, identity + index, cfg, 1);
            let zone = peer.2[0].link();
            let flow = peer
                .0
                .udp_open_scoped(
                    &peer.1,
                    REMOTE.parse().unwrap(),
                    Some(LOCAL.parse().unwrap()),
                    Some(zone),
                    UDP_OPTIONS,
                )
                .unwrap();
            (peer, flow)
        })
        .collect()
}

#[test]
fn identical_link_local_udp_bindings_on_two_links_are_separate_flows() {
    let cfg = config(4);
    let mut a = scoped_side_with(LOCAL, 2, 8100, &cfg, 3);
    let local: SocketAddr = LOCAL.parse().unwrap();
    let remote: SocketAddr = REMOTE.parse().unwrap();
    let zones = [a.2[0].link(), a.2[1].link()];
    // A link-local binding needs its zone, and a zone is only for one.
    assert_eq!(
        a.0.udp_open(&a.1, local, Some(remote), UDP_OPTIONS),
        Err(Error::Endpoint(EndpointError::InvalidAddress))
    );
    let (global, peer) = addresses(true);
    assert_eq!(
        a.0.udp_open_scoped(&a.1, global, Some(peer), Some(zones[0]), UDP_OPTIONS),
        Err(Error::Endpoint(EndpointError::InvalidAddress))
    );
    let flows = zones.map(|zone| {
        a.0.udp_open_scoped(&a.1, local, Some(remote), Some(zone), UDP_OPTIONS)
            .unwrap()
    });
    assert_ne!(flows[0], flows[1]);
    assert_eq!(
        a.0.udp_open_scoped(&a.1, local, Some(remote), Some(zones[0]), UDP_OPTIONS),
        Err(Error::Endpoint(EndpointError::AddressInUse))
    );
    let mut peers = udp_peers(&cfg, 8110);
    // Each flow's path, and every datagram it sends, is its own link's.
    for (index, flow) in flows.into_iter().enumerate() {
        let limits = a.0.udp_path_limits(&a.1, flow, None).unwrap();
        let key = a.0.paths().path_snapshot(limits.path).unwrap().key();
        assert_eq!(key.link(), zones[index]);
        assert_eq!(key.destination().zone(), Some(zones[index]));
        let (link, frame) = udp_out(&mut a, 10, flow, &[index as u8; 8]);
        assert_eq!(link, zones[index]);
        // The peer of that link receives it on its own flow.
        let (peer, peer_flow) = &mut peers[index];
        let context = peer.2[0];
        deliver(peer, context, 11, &frame);
        let mut buffer = [0; 64];
        assert_eq!(
            peer.0.udp_receive(*peer_flow, &mut buffer).unwrap(),
            Some((local, 8))
        );
        assert_eq!(&buffer[..8], &[index as u8; 8]);
    }
    assert_ne!(
        a.0.udp_path_limits(&a.1, flows[0], None).unwrap().path,
        a.0.udp_path_limits(&a.1, flows[1], None).unwrap().path
    );
    // The identical datagram from each link's peer reaches only the flow of
    // its arrival link.
    let mut buffer = [0; 64];
    for index in [1, 0] {
        let (peer, peer_flow) = &mut peers[index];
        let (_, frame) = udp_out(peer, 20, *peer_flow, b"same bytes");
        let arrival = a.2[index];
        deliver(&mut a, arrival, 21, &frame);
        assert_eq!(a.0.udp_receive(flows[1 - index], &mut buffer).unwrap(), None);
        assert_eq!(
            a.0.udp_receive(flows[index], &mut buffer).unwrap(),
            Some((remote, 10))
        );
    }
    // An unconnected flow on the link-local address of link 0 receives
    // only link 0's datagrams for its port.
    let (peer, peer_flow) = &mut peers[1];
    peer.0.udp_close(*peer_flow).unwrap();
    let service: SocketAddr = "[fe80::1]:1001".parse().unwrap();
    let wildcard = a
        .0
        .udp_open_scoped(&a.1, service, None, Some(zones[0]), UDP_OPTIONS)
        .unwrap();
    let to_service = peer
        .0
        .udp_open_scoped(&peer.1, remote, Some(service), Some(peer.2[0].link()), UDP_OPTIONS)
        .unwrap();
    let (_, frame) = udp_out(peer, 30, to_service, b"other link");
    let other = a.2[1];
    deliver(&mut a, other, 31, &frame);
    assert_eq!(a.0.udp_receive(wildcard, &mut buffer).unwrap(), None);
    let on_link = a.2[0];
    deliver(&mut a, on_link, 32, &frame);
    assert_eq!(
        a.0.udp_receive(wildcard, &mut buffer).unwrap(),
        Some((remote, 10))
    );
    // It answers on its link.
    let mut packet = vec![0; 256];
    let mut link = None;
    a.0.udp_send(&a.1, 33, wildcard, Some(remote), b"reply", &mut packet, |egress, _| {
        link = Some(egress.link);
        BackendOutcome::Submitted
    })
    .unwrap();
    assert_eq!(link, Some(zones[0]));
}

#[test]
fn ptb_for_a_link_local_udp_datagram_reaches_only_its_links_flow() {
    let cfg = config(4);
    let mut a = scoped_side_with(LOCAL, 2, 8200, &cfg, 2);
    let local: SocketAddr = LOCAL.parse().unwrap();
    let remote: SocketAddr = REMOTE.parse().unwrap();
    let zones = [a.2[0].link(), a.2[1].link()];
    let flows = zones.map(|zone| {
        a.0.udp_open_scoped(&a.1, local, Some(remote), Some(zone), UDP_OPTIONS)
            .unwrap()
    });
    let frames = flows.map(|flow| udp_out(&mut a, 10, flow, &[7; 1400]).1);
    assert_eq!(frames[0], frames[1], "identical datagrams on both links");
    let report = ptb(&frames[0], 1280);
    let learned = |a: &mut Peer, flow| {
        let path = a.0.udp_path_limits(&a.1, flow, None).unwrap().path;
        a.0.paths().path_snapshot(path).unwrap().learned_mtu()
    };
    // Link 0's report lowers link 0's path and advises its flow only.
    let arrival = a.2[0];
    a.0.input_icmp(&mut a.1, arrival, 20, &report, None).unwrap();
    assert_eq!(learned(&mut a, flows[0]), Some(1280));
    assert_eq!(learned(&mut a, flows[1]), None);
    assert_eq!(
        a.0.udp_event(flows[0]).unwrap(),
        Some(UdpEvent::PacketTooBig {
            remote,
            mtu: Some(1280),
            dropped_len: 1448,
        })
    );
    assert_eq!(a.0.udp_event(flows[1]).unwrap(), None);
    assert_eq!(a.0.udp_path_limits(&a.1, flows[1], None).unwrap().max_payload, 1500 - 48);
    // Link 1's flow, its datagram never reported, keeps sending 1400 octets.
    assert_eq!(udp_out(&mut a, 30, flows[1], &[7; 1400]).0, zones[1]);
}

#[test]
fn udp_flows_of_a_removed_or_replaced_link_are_refused() {
    let cfg = config(4);
    let mut a = scoped_side_with(LOCAL, 2, 8300, &cfg, 2);
    let local: SocketAddr = LOCAL.parse().unwrap();
    let remote: SocketAddr = REMOTE.parse().unwrap();
    let stale = a.2[1];
    let flow = a
        .0
        .udp_open_scoped(&a.1, local, None, Some(stale.link()), UDP_OPTIONS)
        .unwrap();
    a.0.remove_link(stale).unwrap();
    let replacement = a
        .0
        .register_link(
            InterfaceKey(2),
            1500,
            ReceiveCapabilities {
                max_ip_packet: 65575,
                ipv4: Ipv4Receive::Disabled,
                ipv6: Ipv6Receive::BaseHeader,
                gro: false,
            },
            Forwarding::Forwarder(ForwarderId(10)),
        )
        .unwrap();
    a.0.register_source(
        ScopedAddress::new(local.ip(), Some(replacement.link())).unwrap(),
        replacement.link(),
    )
    .unwrap();
    a.0.add_route(path::Route {
        destination: path::IpPrefix::new("fe80::".parse().unwrap(), 64).unwrap(),
        source: None,
        dscp: None,
        link: replacement.link(),
        next_hop: path::NextHop::Forwarder(ForwarderId(10)),
        metric: 0,
    })
    .unwrap();
    // The old flow never moves to the replacement link.
    let mut packet = vec![0; 256];
    let result = a.0.udp_send(&a.1, 10, flow, Some(remote), b"x", &mut packet, |_, _| {
        panic!("a stale flow submits nothing")
    });
    assert!(result.is_err());
    assert_eq!(
        a.0.udp_open_scoped(&a.1, local, Some(remote), Some(stale.link()), UDP_OPTIONS),
        Err(Error::Path(path::Error::SourceNotOwned))
    );
    let fresh = a
        .0
        .udp_open_scoped(&a.1, local, Some(remote), Some(replacement.link()), UDP_OPTIONS)
        .unwrap();
    assert_eq!(udp_out(&mut a, 11, fresh, b"x").0, replacement.link());
}
