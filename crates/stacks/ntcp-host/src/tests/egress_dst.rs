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
