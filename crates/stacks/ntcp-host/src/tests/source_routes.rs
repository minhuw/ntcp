use super::*;
use core::net::Ipv4Addr;

type Peer = (Host, Endpoint, IngressContext);
const FIRST: [u8; 2] = [8, 9];
const LATER: [u8; 2] = [10, 11];

fn hop(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, last)
}
pub(super) fn routed(local: SocketAddr, identity: u128, cfg: EndpointConfig) -> Peer {
    let mut peer = managed(local, identity, cfg);
    peer.0.ports[0].as_mut().unwrap().receive.ipv4 = Ipv4Receive::Options {
        source_routes: true,
    };
    peer
}

// Model a completed received IP route, as in the codec/core option tests.
// Recorded router interface addresses need not equal their forward addresses.
// TCP bytes come from an actual managed peer; no TCP metadata is fabricated.
fn received(frame: &[u8], recorded: &[u8]) -> Vec<u8> {
    let (ip, old_header, _, _) = ntcp_ip::quote_header(frame).unwrap();
    let IpAddr::V4(destination) = ip.destination else {
        panic!()
    };
    let option_len = 3 + recorded.len() * 4;
    let header = 20 + ((option_len + 3) & !3);
    let mut result = vec![0; header + frame.len() - old_header];
    result[..20].copy_from_slice(&frame[..20]);
    result[0] = 0x40 | (header / 4) as u8;
    let total = result.len() as u16;
    result[2..4].copy_from_slice(&total.to_be_bytes());
    result[16..20].copy_from_slice(&destination.octets());
    result[20..23].copy_from_slice(&[131, option_len as u8, (option_len + 1) as u8]);
    for (i, &address) in recorded.iter().enumerate() {
        result[23 + 4 * i..27 + 4 * i].copy_from_slice(&hop(address).octets());
    }
    result[header..].copy_from_slice(&frame[old_header..]);
    result[10..12].fill(0);
    let sum = ntcp_ip::checksum(&result[..header]);
    result[10..12].copy_from_slice(&sum.to_be_bytes());
    let packet = ntcp_ip::parse(&result, true).unwrap();
    ntcp::wire::parse(packet.ip, packet.payload).unwrap();
    result
}
pub(super) fn receive(peer: &mut Peer, now: u64, frame: &[u8], recorded: &[u8]) {
    input(
        &mut peer.0,
        &mut peer.1,
        peer.2,
        now,
        &received(frame, recorded),
        24,
    );
}
fn assert_wire(frame: &[u8], final_peer: SocketAddr, hops: &[u8]) {
    let (ip, header, _, _) = ntcp_ip::quote_header(frame).unwrap();
    assert_eq!(ip.destination, final_peer.ip());
    assert_eq!(ntcp_ip::checksum(&frame[..header]), 0);
    ntcp::wire::parse(ip, &frame[header..]).unwrap();
    if let Some(&first) = hops.first() {
        assert_eq!(&frame[16..20], &hop(first).octets());
        assert_eq!(&frame[20..23], &[131, (3 + hops.len() * 4) as u8, 4]);
        for (i, &next) in hops[1..].iter().enumerate() {
            assert_eq!(&frame[23 + i * 4..27 + i * 4], &hop(next).octets());
        }
        let IpAddr::V4(final_ip) = final_peer.ip() else {
            panic!()
        };
        let offset = 23 + (hops.len() - 1) * 4;
        assert_eq!(&frame[offset..offset + 4], &final_ip.octets());
        assert!(
            ntcp::wire::parse(
                IpMetadata {
                    destination: hop(first).into(),
                    ..ip
                },
                &frame[header..],
            )
            .is_err()
        );
    } else {
        assert_eq!(header, 20);
        let IpAddr::V4(final_ip) = final_peer.ip() else {
            panic!()
        };
        assert_eq!(&frame[16..20], &final_ip.octets());
    }
}
fn passive_pair(
    cfg: &EndpointConfig,
) -> (Peer, Peer, ConnectionId, ConnectionId, ntcp::ListenerId) {
    let (local, remote) = addresses(false);
    let mut a = routed(local, 151, cfg.clone());
    let mut b = routed(remote, 152, cfg.clone());
    let listener = b.1.listen(remote, cfg.max_connections).unwrap();
    let mut active = options(cfg, 24);
    active.ipv4_options.source_route = Some(ntcp::SourceRoute::new(&[], false).unwrap());
    let client =
        a.1.connect_with_path_provider(0, local, remote, active, &mut a.0)
            .unwrap();
    let syn = emit(&mut a.0, &mut a.1, 1).unwrap();
    receive(&mut b, 2, &syn, &FIRST);
    let synack = emit(&mut b.0, &mut b.1, 3).unwrap();
    assert_wire(&synack, local, &[9, 8]);
    receive(&mut a, 4, &synack, &FIRST);
    let ack = emit(&mut a.0, &mut a.1, 5).unwrap();
    receive(&mut b, 6, &ack, &FIRST);
    let server = b.1.accept(listener).unwrap();
    assert_eq!(b.1.state(server).unwrap(), State::Established);
    (a, b, client, server, listener)
}
fn routed_pump(a: &mut Peer, b: &mut Peer, now: &mut u64, incoming_b: &[u8]) {
    for _ in 0..256 {
        *now += 10;
        let mut work = false;
        if let Some(frame) = emit(&mut a.0, &mut a.1, *now) {
            receive(b, *now + 1, &frame, incoming_b);
            work = true;
        }
        if let Some(frame) = emit(&mut b.0, &mut b.1, *now + 2) {
            receive(a, *now + 3, &frame, &FIRST);
            work = true;
        }
        if !work {
            return;
        }
    }
    panic!("routed stream did not quiesce");
}

#[test]
fn passive_later_completed_route_changes_actual_wire_output_and_host_key() {
    let mut cfg = config(2);
    cfg.ipv4_options_enabled = true;
    let (mut a, mut b, client, server, _) = passive_pair(&cfg);
    a.1.write(client, b"first").unwrap();
    let first = emit(&mut a.0, &mut a.1, 10).unwrap();
    receive(&mut b, 11, &first, &FIRST);
    let ack = emit(&mut b.0, &mut b.1, 12).unwrap();
    assert_wire(&ack, addresses(false).0, &[9, 8]);
    receive(&mut a, 13, &ack, &FIRST);
    let mut bytes = [0; 5];
    assert_eq!(b.1.read(server, &mut bytes).unwrap(), 5);
    assert_eq!(&bytes, b"first");
    a.1.write(client, b"later").unwrap();
    let later = emit(&mut a.0, &mut a.1, 14).unwrap();
    receive(&mut b, 15, &later, &LATER);
    b.1.write(server, b"reply").unwrap();
    let (attempt, _, frame) = selected(&mut b.1, 16).unwrap();
    // Check core's actual encoded selection before asking Host for authority.
    // The peer's later definition must replace the earlier reverse route.
    assert_wire(&frame, addresses(false).0, &[11, 10]);
    let context = b.0.egress_context(&mut b.1, attempt).unwrap();
    assert_eq!(
        context
            .binding
            .snapshot
            .key()
            .forwarding_destination()
            .address(),
        IpAddr::V4(hop(11))
    );
    b.0.validate_egress(&mut b.1, context, &frame, 0).unwrap();
    b.1.accept_transmit(16, attempt).unwrap();
    receive(&mut a, 17, &frame, &FIRST);
    assert_eq!(a.1.read(client, &mut bytes).unwrap(), 5);
    assert_eq!(&bytes, b"reply");
    assert_eq!(
        a.1.read(client, &mut bytes),
        Err(EndpointError::Connection(ntcp::Error::WouldBlock))
    );
}

#[test]
fn passive_route_update_uses_current_hop_even_before_dscp_rebind_and_revokes_old_proof() {
    for change_class in [false, true] {
        let mut cfg = config(3);
        cfg.ipv4_options_enabled = true;
        cfg.connection.timestamps = false;
        let (mut a, mut b, client, server, _) = passive_pair(&cfg);
        let mut now = 10;
        b.1.write(server, &[3; 1400]).unwrap();
        routed_pump(&mut a, &mut b, &mut now, &FIRST);
        assert!(b.1.path_mtu_info(server).unwrap().unwrap().search_low > 1024);
        let old = b.0.binding(server).unwrap();
        b.0.trusted_decrease(now, old.snapshot.path(), 1100)
            .unwrap();
        b.0.refresh(&mut b.1, server).unwrap();
        let old = b.0.binding(server).unwrap();
        let hold = old.snapshot.retry_not_before();
        b.1.write(server, &[7; 20000]).unwrap();
        let (attempt, _, probe) = selected(&mut b.1, hold).unwrap();
        assert!(b.1.transmit_discovery_intent(attempt).is_some());
        let context = b.0.egress_context(&mut b.1, attempt).unwrap();
        b.0.validate_egress(&mut b.1, context, &probe, 0).unwrap();
        b.1.accept_transmit(hold, attempt).unwrap();
        receive(&mut a, hold + 1, &probe, &FIRST);
        let ack = emit(&mut a.0, &mut a.1, hold + 2).unwrap();
        // This real probe ACK also carries a valid changed return route.
        receive(&mut b, hold + 3, &ack, &LATER);
        let before = b.1.transport_info(server).unwrap();
        let usage = b.0.paths().usage();
        assert_eq!(
            b.0.paths().snapshot(old.client).unwrap().status(),
            PathStatus::Valid
        );
        if change_class {
            b.0.rebind_dscp(&mut b.1, server, 32).unwrap();
        } else {
            b.0.refresh(&mut b.1, server).unwrap();
        }
        let current = b.0.binding(server).unwrap();
        // A class change preflights the new hop directly: one fresh path,
        // with no transient binding for the obsolete hop and new class.
        assert_eq!(b.0.paths().usage().paths, usage.paths + 1);
        assert_eq!(b.0.paths().usage().clients, usage.clients);
        assert_ne!(current.client, old.client);
        assert_ne!(current.snapshot.path(), old.snapshot.path());
        assert_eq!(
            current.snapshot.key().forwarding_destination().address(),
            IpAddr::V4(hop(11))
        );
        assert_eq!(
            current.snapshot.key().destination().address(),
            a.1.retained_tuple(client).unwrap().local.ip()
        );
        assert_eq!(
            current.snapshot.key().dscp().value(),
            if change_class { 32 } else { 24 }
        );
        assert_eq!(current.snapshot.learned_mtu(), None);
        assert_eq!(current.snapshot.negative_revision(), 0);
        assert_eq!(current.snapshot.retry_not_before(), 0);
        let info = b.1.path_mtu_info(server).unwrap().unwrap();
        assert_eq!(info.search_low, 1024);
        assert_eq!(info.current_mtu, 1024);
        assert_eq!(b.1.transport_info(server).unwrap().lost, before.lost);
        assert_eq!(b.0.paths().path_pins(old.snapshot.path()).unwrap(), 0);
        let (attempt, _, frame) = selected(&mut b.1, hold + 4).unwrap();
        assert_wire(&frame, addresses(false).0, &[11, 10]);
        let context = b.0.egress_context(&mut b.1, attempt).unwrap();
        b.0.validate_egress(&mut b.1, context, &frame, 0).unwrap();
        b.1.accept_transmit(hold + 4, attempt).unwrap();
        receive(&mut a, hold + 5, &frame, &FIRST);
        now = hold + 10;
        routed_pump(&mut a, &mut b, &mut now, &LATER);
        let mut bytes = vec![0; 21400];
        assert_eq!(a.1.read(client, &mut bytes).unwrap(), bytes.len());
        assert_eq!(&bytes[..1400], &[3; 1400]);
        assert_eq!(&bytes[1400..], &[7; 20000]);
        assert_eq!(
            a.1.read(client, &mut [0; 1]),
            Err(EndpointError::Connection(ntcp::Error::WouldBlock))
        );
        assert_eq!(
            b.1.retained_tuple(server).unwrap().remote,
            addresses(false).0
        );
    }
}

#[test]
fn active_selected_route_including_empty_direct_keeps_precedence_on_wire() {
    for direct in [false, true] {
        let mut cfg = config(2);
        cfg.ipv4_options_enabled = true;
        let (local, remote) = addresses(false);
        let mut a = routed(local, 161, cfg.clone());
        let mut b = routed(remote, 162, cfg.clone());
        b.1.listen(remote, 2).unwrap();
        let mut chosen = options(&cfg, 24);
        let hops = if direct { vec![] } else { vec![hop(7)] };
        chosen.ipv4_options.source_route = Some(ntcp::SourceRoute::new(&hops, false).unwrap());
        let client =
            a.1.connect_with_path_provider(0, local, remote, chosen, &mut a.0)
                .unwrap();
        let syn = emit(&mut a.0, &mut a.1, 1).unwrap();
        assert_wire(&syn, remote, if direct { &[] } else { &[7] });
        receive(&mut b, 2, &syn, &FIRST);
        let synack = emit(&mut b.0, &mut b.1, 3).unwrap();
        receive(&mut a, 4, &synack, &LATER);
        let ack = emit(&mut a.0, &mut a.1, 5).unwrap();
        assert_wire(&ack, remote, if direct { &[] } else { &[7] });
        receive(&mut b, 6, &ack, &FIRST);
        a.1.write(client, b"explicit route").unwrap();
        let frame = emit(&mut a.0, &mut a.1, 7).unwrap();
        assert_wire(&frame, remote, if direct { &[] } else { &[7] });
        assert_eq!(
            a.0.binding(client)
                .unwrap()
                .snapshot
                .key()
                .forwarding_destination()
                .address(),
            if direct { remote.ip() } else { hop(7).into() }
        );
    }
}

#[test]
fn time_wait_replacement_learns_later_route_and_failed_candidate_keeps_retained_owner() {
    for capacity in [1, 2] {
        let mut cfg = config(capacity);
        cfg.reuse_time_wait = true;
        cfg.ipv4_options_enabled = true;
        cfg.connection.timestamps = false;
        let (mut a, mut b, client, old, listener) = passive_pair(&cfg);
        let mut now = 10;
        b.1.shutdown(old).unwrap();
        routed_pump(&mut a, &mut b, &mut now, &FIRST);
        a.1.shutdown(client).unwrap();
        routed_pump(&mut a, &mut b, &mut now, &FIRST);
        assert_eq!(b.1.state(old).unwrap(), State::TimeWait);
        assert_eq!(a.1.state(client).unwrap(), State::Closed);
        let binding = b.0.binding(old).unwrap();
        b.0.trusted_decrease(now, binding.snapshot.path(), 1100)
            .unwrap();
        b.0.refresh(&mut b.1, old).unwrap();
        a.1.release(client).unwrap();
        b.1.release(old).unwrap();
        a.0.collect(&a.1).unwrap();
        b.0.collect(&b.1).unwrap();
        let retained = b.1.managed_path(old).unwrap();
        assert_eq!(retained.forwarding_destination, IpAddr::V4(hop(9)));
        let pins =
            b.0.paths()
                .path_pins(retained.binding.snapshot.path())
                .unwrap();
        now += 1_000_000;
        let (local, remote) = addresses(false);
        let mut active = options(&cfg, 24);
        active.ipv4_options.source_route = Some(ntcp::SourceRoute::new(&[], false).unwrap());
        let new_client =
            a.1.connect_with_path_provider(now, local, remote, active, &mut a.0)
                .unwrap();
        let syn = emit(&mut a.0, &mut a.1, now + 1).unwrap();
        receive(&mut b, now + 2, &syn, &LATER);
        assert_eq!(b.1.managed_path(old).unwrap(), retained);
        assert_eq!(b.0.binding(old).unwrap(), retained.binding);
        assert_eq!(
            b.0.paths()
                .path_pins(retained.binding.snapshot.path())
                .unwrap(),
            pins
        );
        let current =
            b.1.connection_id(Tuple {
                local: remote,
                remote: local,
            })
            .unwrap();
        if capacity == 1 {
            assert_eq!(current, old);
            assert_eq!(b.0.binding_count(), 1);
            assert_eq!(b.0.paths().usage().clients, 1);
            assert!(selected(&mut b.1, now + 3).is_none());
        } else {
            assert_ne!(current, old);
            let synack = emit(&mut b.0, &mut b.1, now + 3).unwrap();
            assert_wire(&synack, local, &[11, 10]);
            assert_eq!(b.0.binding(current).unwrap().snapshot.learned_mtu(), None);
            receive(&mut a, now + 4, &synack, &FIRST);
            let ack = emit(&mut a.0, &mut a.1, now + 5).unwrap();
            receive(&mut b, now + 6, &ack, &[12, 13]);
            assert_eq!(b.1.accept(listener).unwrap(), current);
            b.1.write(current, b"replacement").unwrap();
            let frame = emit(&mut b.0, &mut b.1, now + 7).unwrap();
            assert_wire(&frame, local, &[13, 12]);
            receive(&mut a, now + 8, &frame, &FIRST);
            let mut bytes = [0; 11];
            assert_eq!(a.1.read(new_client, &mut bytes).unwrap(), 11);
            assert_eq!(&bytes, b"replacement");
            assert_eq!(
                b.0.binding(current)
                    .unwrap()
                    .snapshot
                    .key()
                    .forwarding_destination()
                    .address(),
                IpAddr::V4(hop(13))
            );
            assert_eq!(b.1.managed_path(old).unwrap(), retained);
        }
    }
}

#[test]
fn changed_return_route_failed_refresh_and_class_rebind_preserve_authority_and_retry() {
    for failure in [
        Error::Path(path::Error::NoRoute),
        Error::Path(path::Error::Capacity),
        Error::Unsupported,
    ] {
        let mut cfg = config(3);
        cfg.ipv4_options_enabled = true;
        cfg.connection.timestamps = false;
        let (mut a, mut b, client, server, _) = passive_pair(&cfg);
        let initial = b.0.binding(server).unwrap();
        let mut route = b.0.paths().route(initial.snapshot.key().route()).unwrap();
        if failure == Error::Path(path::Error::NoRoute) {
            route.destination = path::IpPrefix::new(hop(9).into(), 32).unwrap();
            b.0.replace_route(initial.snapshot.key().route(), route)
                .unwrap();
            b.0.refresh(&mut b.1, server).unwrap();
        }
        let blocker = if failure == Error::Path(path::Error::Capacity) {
            // Occupy every other path slot with pinned canonical clients.
            let mut clients = Vec::new();
            for suffix in 100.. {
                let request =
                    b.0.request(
                        addresses(false).1.ip(),
                        hop(suffix).into(),
                        Dscp::new(24).unwrap(),
                    )
                    .unwrap();
                match b.0.paths.acquire(request) {
                    Ok((client, _)) => clients.push(client),
                    Err(path::Error::Capacity) => break,
                    Err(error) => panic!("{error:?}"),
                }
            }
            clients
        } else {
            vec![]
        };
        let unsupported = if failure == Error::Unsupported {
            route.destination = path::IpPrefix::new(hop(11).into(), 32).unwrap();
            route.next_hop = path::NextHop::Forwarder(ForwarderId(99));
            Some(b.0.add_route(route).unwrap())
        } else {
            None
        };
        let old = b.0.binding(server).unwrap();
        b.0.trusted_decrease(10, old.snapshot.path(), 1100).unwrap();
        let notification = b.0.paths().snapshot(old.client).unwrap();
        let usage = b.0.paths().usage();
        let pins = b.0.paths().path_pins(old.snapshot.path()).unwrap();
        a.1.write(client, b"new route").unwrap();
        let update = emit(&mut a.0, &mut a.1, 11).unwrap();
        receive(&mut b, 12, &update, &LATER);
        let expected = failure;
        assert_eq!(b.0.rebind_dscp(&mut b.1, server, 32), Err(expected));
        assert_eq!(b.0.binding(server).unwrap(), old);
        assert_eq!(b.1.managed_path(server).unwrap().binding, old);
        assert_eq!(b.0.paths().snapshot(old.client).unwrap(), notification);
        assert!(b.0.paths().is_dirty(old.client).unwrap());
        assert_eq!(b.0.paths().usage(), usage);
        assert_eq!(b.0.paths().path_pins(old.snapshot.path()).unwrap(), pins);
        let (attempt, _, frame) = selected(&mut b.1, 13).unwrap();
        assert_wire(&frame, addresses(false).0, &[11, 10]);
        let mut submissions = 0;
        let result = b.0.egress_context(&mut b.1, attempt).and_then(|context| {
            let ticket = b.0.submission_ticket(&mut b.1, context)?;
            b.0.submit(&mut b.1, 13, ticket, context, &frame, 0, |_| {
                submissions += 1;
                BackendOutcome::Submitted
            })
            .map_err(|refused| {
                b.0.cancel_submission(refused.ticket);
                refused.error
            })
        });
        assert_eq!(result.map(|_| ()), Err(expected));
        assert_eq!(submissions, 0);
        assert_eq!(b.0.binding(server).unwrap(), old);
        assert_eq!(b.0.paths().snapshot(old.client).unwrap(), notification);
        assert!(b.0.paths().is_dirty(old.client).unwrap());
        assert!(b.1.transmit_attempt_packet(attempt).is_some());
        assert_eq!(b.0.paths().usage(), usage);
        assert_eq!(b.0.paths().path_pins(old.snapshot.path()).unwrap(), pins);
        for client in blocker {
            b.0.paths.release(client).unwrap();
        }
        if let Some(route) = unsupported {
            b.0.remove_route(route).unwrap();
        }
        if failure == Error::Path(path::Error::NoRoute) {
            route.destination = path::IpPrefix::new(hop(11).into(), 32).unwrap();
            b.0.add_route(route).unwrap();
        }
        let context = b.0.egress_context(&mut b.1, attempt).unwrap();
        assert_eq!(
            context
                .binding
                .snapshot
                .key()
                .forwarding_destination()
                .address(),
            IpAddr::V4(hop(11))
        );
        assert_eq!(context.binding.snapshot.key().dscp().value(), 24);
        let ticket = b.0.submission_ticket(&mut b.1, context).unwrap();
        let submitted = b.0.submit(&mut b.1, 14, ticket, context, &frame, 0, |_| {
            submissions += 1;
            BackendOutcome::Submitted
        });
        assert!(submitted == Ok(Submission::Submitted));
        assert_eq!(submissions, 1);
        receive(&mut a, 15, &frame, &FIRST);
        b.0.rebind_dscp(&mut b.1, server, 32).unwrap();
        assert_eq!(
            b.0.binding(server)
                .unwrap()
                .snapshot
                .key()
                .forwarding_destination()
                .address(),
            IpAddr::V4(hop(11))
        );
    }
}

#[test]
fn rejected_received_return_route_is_dropped_before_path_preparation() {
    let mut cfg = config(3);
    cfg.ipv4_options_enabled = true;
    cfg.connection.timestamps = false;
    let (local, remote) = addresses(false);
    let mut a = routed(local, 161, cfg.clone());
    // The embedding's route policy rejects one otherwise well-formed hop.
    let mut b = managed_route_policy(remote, 162, cfg.clone(), false, None, Some(hop(66).into()));
    b.0.ports[0].as_mut().unwrap().receive.ipv4 = Ipv4Receive::Options {
        source_routes: true,
    };
    let listener = b.1.listen(remote, cfg.max_connections).unwrap();
    let mut active = options(&cfg, 24);
    active.ipv4_options.source_route = Some(ntcp::SourceRoute::new(&[], false).unwrap());
    let client =
        a.1.connect_with_path_provider(0, local, remote, active, &mut a.0)
            .unwrap();
    let syn = emit(&mut a.0, &mut a.1, 1).unwrap();
    // A completed route through the denied hop: the ordinary path drops it.
    let rejected = received(&syn, &[8, 66]);
    let before = (b.0.binding_count(), b.0.paths().usage().clients);
    let result = b.0.input_ip(
        &mut b.1,
        b.2,
        2,
        &rejected,
        RxPacketMetadata::default(),
        24,
        None,
    );
    std::println!("rejected received route: {result:?}");
    assert_eq!(result, Ok(ntcp::InputDisposition::Dropped));
    assert_eq!((b.0.binding_count(), b.0.paths().usage().clients), before);
    assert!(emit(&mut b.0, &mut b.1, 3).is_none(), "no SYN-ACK or RST");
    receive(&mut b, 4, &syn, &FIRST);
    let synack = emit(&mut b.0, &mut b.1, 5).unwrap();
    assert_wire(&synack, local, &[9, 8]);
    receive(&mut a, 6, &synack, &FIRST);
    let ack = emit(&mut a.0, &mut a.1, 7).unwrap();
    receive(&mut b, 8, &ack, &FIRST);
    let server = b.1.accept(listener).unwrap();
    assert_eq!(b.1.state(server).unwrap(), State::Established);
    assert_eq!(a.1.state(client).unwrap(), State::Established);
}
