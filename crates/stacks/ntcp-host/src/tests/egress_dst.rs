// A connection's egress decision (`Dst`, as Linux's sk_dst_cache): held
// while nothing it was checked for changes, dropped by every event that can
// change what `refresh` decides, and checked against the full revalidation
// on each use in debug builds (`Host::refresh_route`), so each test here
// also compares the two.
use super::*;

type Side = (Host, Endpoint, IngressContext);

fn connected(v6: bool, cfg: &EndpointConfig, identity: u64) -> (Side, Side, ConnectionId) {
    let (local, remote) = addresses(v6);
    // Room for another link and source.
    let mut a = managed_limited(
        local,
        identity,
        cfg.clone(),
        false,
        None,
        None,
        |mut p, l| {
            p.links = 2;
            p.sources = 2;
            p.source_owners = 2;
            (p, l, 1)
        },
    );
    let mut b = managed(remote, identity + 1, cfg.clone());
    let listener = b.1.listen(remote, 1).unwrap();
    let id =
        a.1.connect_with_path_provider(0, local, remote, options(cfg, 0), &mut a.0)
            .unwrap();
    let mut now = 0;
    pump(&mut a, &mut b, &mut now);
    b.1.accept(listener).unwrap();
    (a, b, id)
}
fn route(side: &Side, destination: &str, length: u8) -> path::Route {
    path::Route {
        destination: path::IpPrefix::new(destination.parse().unwrap(), length).unwrap(),
        source: None,
        dscp: None,
        link: side.2.link(),
        next_hop: path::NextHop::Forwarder(ForwarderId(9)),
        metric: 0,
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Event {
    // A more specific route to the destination.
    ShadowRoute,
    // A route to other destinations.
    UnrelatedRoute,
    ReplaceRoute,
    RemoveRoute,
    // A trusted PMTU decrease on the path.
    Decrease,
    LinkMtu,
    Plateaus,
    // The connection's class.
    Dscp,
    // The source address leaves the link.
    Source,
    // Another link registers, another source on the link.
    OtherLink,
    OtherSource,
    RemoveLink,
}

#[test]
fn every_change_of_the_decision_drops_it_and_nothing_else_does() {
    use Event::*;
    for v6 in [false, true] {
        for event in [
            ShadowRoute,
            UnrelatedRoute,
            ReplaceRoute,
            RemoveRoute,
            Decrease,
            LinkMtu,
            Plateaus,
            Dscp,
            Source,
            OtherLink,
            OtherSource,
            RemoveLink,
        ] {
            if v6 && event == Plateaus {
                continue;
            }
            let cfg = config(2);
            let (mut a, mut b, id) = connected(v6, &cfg, 40);
            // Filled by the full checks, then held.
            a.0.refresh(&mut a.1, id).unwrap();
            assert!(a.0.dst_held(&a.1, id));
            let before = a.0.binding(id).unwrap();
            let key = before.snapshot.key();
            match event {
                ShadowRoute => {
                    let prefix = if v6 { "2001:db8::" } else { "192.0.2.0" };
                    a.0.add_route(route(&a, prefix, if v6 { 64 } else { 24 }))
                        .unwrap();
                }
                UnrelatedRoute => {
                    let prefix = if v6 { "2001:db8:ffff::" } else { "203.0.113.0" };
                    a.0.add_route(route(&a, prefix, if v6 { 48 } else { 24 }))
                        .unwrap();
                }
                ReplaceRoute => {
                    let prefix = if v6 { "::" } else { "0.0.0.0" };
                    a.0.replace_route(key.route(), route(&a, prefix, 0))
                        .unwrap();
                }
                RemoveRoute => a.0.remove_route(key.route()).unwrap(),
                Decrease => {
                    let mtu = if v6 { 1280 } else { 1200 };
                    a.0.trusted_decrease(1, before.snapshot.path(), mtu)
                        .unwrap();
                }
                LinkMtu => a.0.set_link_mtu(key.link(), 1400).unwrap(),
                Plateaus => {
                    let plateaus = path::Ipv4Plateaus::new(&[1400, 1006, 508, 68]).unwrap();
                    a.0.set_ipv4_plateaus(plateaus).unwrap();
                }
                Dscp => a.0.rebind_dscp(&mut a.1, id, 10).unwrap(),
                Source => a.0.remove_source_owner(key.source(), key.link()).unwrap(),
                OtherLink => {
                    let receive = a.0.ports[0].unwrap().receive;
                    a.0.register_link(InterfaceKey(2), 1500, receive, Forwarding::IpNextHop)
                        .unwrap();
                }
                OtherSource => {
                    let other = if v6 { "2001:db8::99" } else { "192.0.2.99" };
                    let other = ScopedAddress::new(other.parse().unwrap(), None).unwrap();
                    a.0.register_source(other, key.link()).unwrap();
                }
                RemoveLink => a.0.remove_link(a.2).unwrap(),
            }
            let keeps = matches!(event, UnrelatedRoute | OtherLink | OtherSource);
            assert_eq!(a.0.dst_held(&a.1, id), keeps, "v6 {v6} {event:?}");
            let refreshed = a.0.refresh(&mut a.1, id);
            if matches!(event, RemoveRoute | Source | RemoveLink) {
                assert!(refreshed.is_err(), "v6 {v6} {event:?}");
                assert!(!a.0.dst_held(&a.1, id));
                continue;
            }
            let refreshed = refreshed.unwrap();
            assert_eq!(refreshed == before, keeps, "v6 {v6} {event:?}");
            // The changed binding, checked in full once more, is held again.
            if !keeps {
                assert_eq!(a.0.refresh(&mut a.1, id), Ok(refreshed));
            }
            assert!(a.0.dst_held(&a.1, id));
            // And the connection's output leaves under it.
            a.1.write(id, &[5; 3000]).unwrap();
            let mut now = 1000;
            pump(&mut a, &mut b, &mut now);
            let child = b.1.connection_id(Tuple {
                local: addresses(v6).1,
                remote: addresses(v6).0,
            });
            let mut bytes = [0; 4000];
            assert_eq!(b.1.read(child.unwrap(), &mut bytes), Ok(3000));
        }
    }
}

// The submission contract ("Egress validation" in the crate
// documentation): `egress_context` validates a packet against the
// connection's checked decision when it is built, and `submit` checks only
// the context's path stamp and the first hop at each physical attempt. A
// change of the path gives it a new stamp, so a frame built and authorized
// before the change is refused at its next attempt (none leaves stale
// here), and the packet built after it leaves under the new state: the new
// route, a smaller PMTU or link MTU, the new class, or nothing at all once
// the source or link is gone. (An IPv4 Redirect:
// `redirect::the_packet_built_after_a_redirect_uses_its_gateway`.)
#[test]
fn after_each_change_the_next_packet_built_uses_the_new_state() {
    use Event::*;
    for v6 in [false, true] {
        for event in [
            ShadowRoute,
            ReplaceRoute,
            Decrease,
            LinkMtu,
            Dscp,
            Source,
            RemoveLink,
        ] {
            let cfg = config(2);
            let (mut a, mut b, id) = connected(v6, &cfg, 60);
            let mut now = 1000;
            a.1.write(id, &[5; 3000]).unwrap();
            // A class rebind needs the connection's output withdrawn first
            // (`rebind_dscp`): no frame of it is held across one.
            let held = (event != Dscp).then(|| {
                let (attempt, _, frame) = selected(&mut a.1, now).unwrap();
                let context = a.0.egress_context(&mut a.1, attempt).unwrap();
                (attempt, frame, context)
            });
            let before = a.0.binding(id).unwrap().snapshot;
            let key = before.key();
            let mtu = if v6 { 1280 } else { 1200 };
            let mut route_id = None;
            match event {
                ShadowRoute => {
                    let prefix = if v6 { "2001:db8::" } else { "192.0.2.0" };
                    route_id = Some(
                        a.0.add_route(route(&a, prefix, if v6 { 64 } else { 24 }))
                            .unwrap(),
                    );
                }
                ReplaceRoute => {
                    let prefix = if v6 { "::" } else { "0.0.0.0" };
                    route_id = Some(
                        a.0.replace_route(key.route(), route(&a, prefix, 0))
                            .unwrap(),
                    );
                }
                Decrease => {
                    a.0.trusted_decrease(1, before.path(), mtu).unwrap();
                }
                LinkMtu => a.0.set_link_mtu(key.link(), mtu).unwrap(),
                Dscp => a.0.rebind_dscp(&mut a.1, id, 10).unwrap(),
                Source => a.0.remove_source_owner(key.source(), key.link()).unwrap(),
                RemoveLink => a.0.remove_link(a.2).unwrap(),
                _ => unreachable!(),
            }
            let mut stale = 0;
            if let Some((attempt, frame, context)) = held {
                let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
                match a.0.submit(&mut a.1, now, ticket, context, &frame, 0, |_| {
                    BackendOutcome::Submitted
                }) {
                    Ok(Submission::Submitted) => stale += 1,
                    Ok(other) => panic!("v6 {v6} {event:?}: {other:?}"),
                    Err(refused) => {
                        a.0.cancel_submission(refused.ticket);
                        assert!(a.1.reject_unsubmitted(attempt).unwrap());
                    }
                }
            }
            assert_eq!(stale, 0, "v6 {v6} {event:?}");
            now += 10;
            let (attempt, packet, mut frame) = selected(&mut a.1, now).unwrap();
            let context = a.0.egress_context(&mut a.1, attempt);
            if matches!(event, Source | RemoveLink) {
                assert!(context.is_err(), "v6 {v6} {event:?}");
                continue;
            }
            let context = context.unwrap();
            match event {
                ShadowRoute | ReplaceRoute => {
                    assert_eq!(
                        Some(a.0.egress_snapshot(&context).unwrap().key().route()),
                        route_id
                    )
                }
                Decrease | LinkMtu => assert!(frame.len() <= mtu as usize, "v6 {v6} {event:?}"),
                Dscp => {
                    let class = if v6 {
                        (frame[0] << 4) | (frame[1] >> 4)
                    } else {
                        frame[1]
                    };
                    assert_eq!((packet.dscp, class >> 2), (10, 10));
                }
                _ => unreachable!(),
            }
            if a.0.clears_dont_fragment(context) {
                a.0.lease_df_clear(now, &mut frame).unwrap();
            }
            let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
            let submitted = a.0.submit(&mut a.1, now, ticket, context, &frame, 0, |_| {
                BackendOutcome::Submitted
            });
            assert!(submitted == Ok(Submission::Submitted), "v6 {v6} {event:?}");
            input(&mut b.0, &mut b.1, b.2, now + 1, &frame, 0);
            pump(&mut a, &mut b, &mut now);
            let child = b.1.connection_id(Tuple {
                local: addresses(v6).1,
                remote: addresses(v6).0,
            });
            let mut bytes = [0; 4000];
            assert_eq!(b.1.read(child.unwrap(), &mut bytes), Ok(3000));
        }
    }
}

#[test]
fn register_link_reused_slot_rejects_stale_handle_and_guards_occupancy_and_capacity() {
    let cfg = config(1);
    let (paths, limits) = managed_limits(&cfg, 2, 2, 2, 2, 0).unwrap();
    let mut host = Host::new(
        ContextId::new(88),
        paths,
        limits,
        cfg.connection.timebase,
        [8; 16],
    )
    .unwrap();
    let recv = ReceiveCapabilities {
        max_ip_packet: 1500,
        ipv4: Ipv4Receive::Enabled {
            interpretation: false,
            source_routes: false,
        },
        ipv6: Ipv6Receive::Disabled,
        gro: false,
    };

    let ctx0 = host
        .register_link(InterfaceKey(1), 1500, recv, Forwarding::IpNextHop)
        .unwrap();
    let ctx1 = host
        .register_link(InterfaceKey(2), 1500, recv, Forwarding::IpNextHop)
        .unwrap();
    assert_eq!(ctx0.link().index(), 0);
    assert_eq!(ctx1.link().index(), 1);
    assert_eq!(host.port_slot(ctx0.link()), Ok(0));
    assert_eq!(host.port_slot(ctx1.link()), Ok(1));

    // Capacity bound rejects a third link without mutating PathService.
    assert_eq!(
        host.register_link(InterfaceKey(3), 1500, recv, Forwarding::IpNextHop),
        Err(Error::Capacity)
    );
    assert_eq!(host.paths().usage().links, 2);

    // Removing link 0 and re-adding reuses slot 0 with a new generation; the old handle is stale.
    host.remove_link(ctx0).unwrap();
    let ctx2 = host
        .register_link(InterfaceKey(3), 1500, recv, Forwarding::IpNextHop)
        .unwrap();
    assert_eq!(ctx2.link().index(), ctx0.link().index());
    assert_ne!(ctx2.link(), ctx0.link());
    assert_eq!(
        host.receive_capabilities(ctx0),
        Err(Error::Path(path::Error::StaleHandle))
    );
    assert_eq!(
        host.ingress_context(ctx0.link()),
        Err(Error::Path(path::Error::StaleHandle))
    );
    assert_eq!(
        host.port_slot(ctx0.link()),
        Err(Error::Path(path::Error::StaleHandle))
    );
    assert_eq!(
        host.remove_link(ctx0),
        Err(Error::Path(path::Error::StaleHandle))
    );
    assert_eq!(host.port_slot(ctx2.link()), Ok(ctx2.link().index()));
    assert_eq!(host.receive_capabilities(ctx2), Ok(recv));

    // R4 release occupancy check: if a port slot is already occupied when PathService allocates
    // that index, register_link refuses it, rolls back the path link, and preserves the live port.
    let slot = ctx2.link().index();
    let sentinel = Port {
        link: ctx1.link(),
        receive: recv,
        forwarding: Forwarding::IpNextHop,
    };
    host.remove_link(ctx2).unwrap();
    assert_eq!(host.paths().usage().links, 1);
    let saved_port1 = host.ports[1].take();
    host.ports[slot] = Some(sentinel);
    assert_eq!(
        host.register_link(InterfaceKey(4), 1500, recv, Forwarding::IpNextHop),
        Err(Error::InvalidContext)
    );
    assert_eq!(host.ports[slot].unwrap().link, sentinel.link);
    assert_eq!(host.paths().usage().links, 1);
    // Restore host state cleanly and verify normal registration succeeds again.
    host.ports[slot] = None;
    host.ports[1] = saved_port1;
    let ctx3 = host
        .register_link(InterfaceKey(4), 1500, recv, Forwarding::IpNextHop)
        .unwrap();
    assert_eq!(ctx3.link().index(), slot);
}
