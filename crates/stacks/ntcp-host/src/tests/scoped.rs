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
fn scoped_side(address: &str, links: usize, identity: u128, cfg: &EndpointConfig) -> Peer {
    let (paths, limits) = managed_limits(cfg, links, links, links, 4, 1).unwrap();
    let mut host = Host::new(
        ContextId::new(identity),
        paths,
        limits,
        cfg.connection.timebase,
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
    for _ in 0..256 {
        *now += 10;
        let mut work = false;
        if let Some((link, frame)) = emit_on(a, *now) {
            let index = a.2.iter().position(|c| c.link() == link).unwrap();
            let peer = &mut peers[index];
            let context = peer.2[0];
            deliver(peer, context, *now + 1, &frame);
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

fn peers(cfg: &EndpointConfig, identity: u128) -> Vec<Peer> {
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
fn two_scoped_connections(cfg: &EndpointConfig, identity: u128) -> (Peer, Vec<Peer>, [ConnectionId; 2], u64) {
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
// released generation on link 1 denies attribution only within that zone,
// so the identical link-local four-tuple on link 0 keeps its PTB
// attributable.
#[test]
fn discarded_history_of_one_link_leaves_the_other_links_ptb_attributable() {
    let cfg = config(4);
    let mut a = scoped_side(LOCAL, 2, 7250, &cfg);
    let mut b = peers(&cfg, 7260);
    let (kept, other) = (a.2[0], a.2[1]);
    let scoped = ScopedTuple::new(tuple(), Some(kept.link())).unwrap();
    let id =
        a.1.connect_scoped_with_path_provider(0, scoped, options(&cfg, 0), &mut a.0)
            .unwrap();
    let mut now = 0;
    pump_links(&mut a, &mut b, &mut now);
    assert_eq!(a.1.state(id), Ok(State::Established));
    // Unanswered generations on link 1, each released after its SYN: first
    // the same four-tuple, then enough others to overflow the summaries so
    // that the first, the oldest, is discarded.
    let slots = 2 * a.0.ledger.limits().owners;
    let mut syns = Vec::new();
    for port in core::iter::once(1000).chain(3000..3000 + slots as u16) {
        now += 10;
        let tuple = Tuple {
            local: SocketAddr::new("fe80::1".parse().unwrap(), port),
            remote: REMOTE.parse().unwrap(),
        };
        let scoped = ScopedTuple::new(tuple, Some(other.link())).unwrap();
        let churn =
            a.1.connect_scoped_with_path_provider(now, scoped, options(&cfg, 0), &mut a.0)
                .unwrap();
        let (link, syn) = emit_on(&mut a, now).unwrap();
        assert_eq!(link, other.link());
        syns.push(syn);
        a.1.abort(churn).unwrap();
        a.1.release(churn).unwrap();
        assert!(emit_on(&mut a, now).is_none());
        // After the poll that found its output drained.
        a.0.collect(&a.1).unwrap();
    }
    assert_eq!(a.0.ledger.discards(), 1);
    let forgotten = super::dispatch::quote_key(&syns[0]);
    assert_eq!(
        a.0.ledger
            .correlate_in(now, &forgotten, Some(other.link()))
            .matches,
        0
    );
    now += 10;
    a.1.write(id, &[5; 1400]).unwrap();
    let (link, sent) = emit_on(&mut a, now).unwrap();
    assert_eq!(link, kept.link());
    let key = super::dispatch::quote_key(&sent);
    let correlation = a.0.ledger.correlate_in(now, &key, Some(kept.link()));
    assert!(!correlation.summarized);
    assert_eq!(
        correlation.owner.map(|r| r.evidence.owner),
        Some(Owner::Tcp(id))
    );
    let (report, published) = tcp_report(
        a.0.input_icmp(&mut a.1, kept, now + 1, &ptb(&sent, 1280), None)
            .unwrap(),
    );
    assert!(matches!(
        report,
        TcpReport::PacketTooBig(PmtuFeedback::Decreased { .. })
    ));
    assert_eq!(published, Some(path::EstimateChange::Decreased));
    // The discarded history still denies in its own zone: a new generation
    // of link 1's four-tuple is not attributable until its horizon.
    now += 10;
    let scoped = ScopedTuple::new(tuple(), Some(other.link())).unwrap();
    let again =
        a.1.connect_scoped_with_path_provider(now, scoped, options(&cfg, 0), &mut a.0)
            .unwrap();
    // Link 0's repair of the dropped segment may leave first.
    let syn = loop {
        let (link, frame) = emit_on(&mut a, now).unwrap();
        if link == other.link() {
            break frame;
        }
    };
    let key = super::dispatch::quote_key(&syn);
    let correlation = a.0.ledger.correlate_in(now, &key, Some(other.link()));
    assert_eq!(correlation.matches, 1);
    assert_eq!(correlation.owner, None, "blinded by its own zone's discard");
    let horizon = a.0.ledger.limits().feedback_horizon;
    assert_eq!(
        a.0.ledger
            .correlate_in(now + horizon, &key, Some(other.link()))
            .owner
            .map(|r| r.evidence.owner),
        Some(Owner::Tcp(again))
    );
    std::println!("link 1 summary discarded among {slots}; link 0 PTB still Decreased");
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
    // The server closes first on link 0 and holds TIME-WAIT there.
    let mut clients = vec![client(7610), scoped_side(LOCAL, 1, 7611, &cfg)];
    let mut now = 0;
    pump_links(&mut server, &mut clients, &mut now);
    let old = server.1.accept(wildcard).unwrap();
    let client_id = clients[0].1.scoped_connection_id(ScopedTuple::new(tuple(), Some(clients[0].2[0].link())).unwrap()).unwrap();
    server.1.close(old).unwrap();
    pump_links(&mut server, &mut clients, &mut now);
    clients[0].1.close(client_id).unwrap();
    pump_links(&mut server, &mut clients, &mut now);
    assert_eq!(server.1.state(old), Ok(State::TimeWait));
    // The same address pair on link 1 opens a new connection beside it.
    clients[1] = client(7612);
    pump_links(&mut server, &mut clients, &mut now);
    let beside = server.1.accept(wildcard).unwrap();
    assert_eq!(server.1.retained_scoped_tuple(beside).unwrap(), zoned(&server, 1));
    assert_eq!(server.1.state(old), Ok(State::TimeWait));
    assert_eq!(server.1.scoped_connection_id(zoned(&server, 0)), Some(old));
    // A new SYN on link 0 replaces the TIME-WAIT record of that zone.
    clients[0] = client(7613);
    now += 1_000_000;
    pump_links(&mut server, &mut clients, &mut now);
    let reused = server.1.accept(wildcard).unwrap();
    assert_ne!(reused, old);
    assert_eq!(server.1.scoped_connection_id(zoned(&server, 0)), Some(reused));
    assert_eq!(server.1.scoped_connection_id(zoned(&server, 1)), Some(beside));
    std::println!("TIME-WAIT {old:?} replaced by {reused:?}; link 1 connection {beside:?} kept");
}

// A client's first SYN for the shared link-local tuple.
fn link_local_syn(cfg: &EndpointConfig, identity: u128) -> Vec<u8> {
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
