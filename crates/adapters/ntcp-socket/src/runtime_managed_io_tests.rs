// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

type Wire = Arc<Mutex<State>>;
fn pair_output(v6: bool, gso: bool, shared: bool) -> (Owner, Owner, u64, u64, Wire, Wire) {
    let (mut a, wa) = native_output(v6, 2, 4, 1500, gso, shared);
    let (mut b, wb) = native_output(v6, 3, 4, 1500, false, false);
    let listen = listener(&mut b);
    let client = new(&mut a, SOCK_NONBLOCK);
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    assert_eq!(
        a.execute(client, Op::Connect(SocketAddr::new(b.local, 8080)))
            .unwrap_err(),
        EINPROGRESS
    );
    for _ in 0..4 {
        tick(&mut a);
        tick(&mut b);
        flush(&mut a, &mut b, &wa);
        tick(&mut a);
        tick(&mut b);
        flush(&mut b, &mut a, &wb);
    }
    let server = b.execute(listen, Op::Accept(SOCK_NONBLOCK)).unwrap().value as u64;
    wa.lock().unwrap().offered.clear();
    (a, b, client, server, wa, wb)
}
fn tick(owner: &mut Owner) {
    owner.test_now = Some(owner.now() + 2000);
}
fn transfer(from: &Wire, to: &mut Owner, input: &Wire) -> Vec<Vec<u8>> {
    let packets: Vec<_> = from.lock().unwrap().sent.drain(..).collect();
    input
        .lock()
        .unwrap()
        .incoming
        .extend(packets.iter().cloned().map(Ok));
    to.receive_batch(&mut [0; 65549]).unwrap();
    to.events();
    packets
}
fn complete(a: &mut Owner, b: &mut Owner, wa: &Wire, wb: &Wire, cid: ConnectionId, len: usize) {
    for _ in 0..256 {
        tick(a);
        tick(b);
        a.service_egress().unwrap();
        transfer(wa, b, wb);
        b.service_egress().unwrap();
        transfer(wb, a, wa);
        // Drain retained exact-generation feedback after the final suffix.
        a.receive_batch(&mut [0; 65549]).unwrap();
        if a.endpoint.acknowledged(cid).unwrap() == len as u64 {
            return;
        }
    }
    panic!(
        "actual receiver did not acknowledge complete stream: {:?}",
        a.endpoint.transport_info(cid)
    );
}
fn ip_size(frame: &[u8]) -> usize {
    let p = crate::ip::parse(ntcp_ethernet::parse_ethernet(frame).unwrap().payload).unwrap();
    crate::ip::header_len(p.ip.source) + p.payload.len()
}
fn budget(a: &mut Owner, cid: ConnectionId, mtu: u32, physical: bool) {
    if physical {
        let (refresh, _, results) = super::super::super::output::MtuRefresh::fixture();
        a.mtu_refresh = Some(refresh);
        results.send(Ok(Some(mtu))).unwrap();
        a.poll_mtu_refresh();
        assert_eq!(
            a.host
                .as_ref()
                .unwrap()
                .paths()
                .link(a.ingress.unwrap().link())
                .unwrap()
                .mtu,
            mtu
        );
    } else {
        let path = a
            .host
            .as_ref()
            .unwrap()
            .binding(cid)
            .unwrap()
            .snapshot
            .path();
        let now = a.now();
        a.host
            .as_mut()
            .unwrap()
            .trusted_decrease(now, path, mtu)
            .unwrap();
    }
}

#[test]
fn managed_scheduled_held_physical_and_shared_decreases_preserve_submitted_prefix_and_stream() {
    for v6 in [false, true] {
        for (gso, shared) in [(false, false), (true, false), (true, true)] {
            for physical in [false, true] {
                let (mut a, mut b, client, server, wa, wb) = pair_output(v6, gso, shared);
                let cid = connection(&a, client);
                let data: Vec<_> = (0..7000).map(|n| (n % 251) as u8).collect();
                if shared {
                    a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
                        .unwrap();
                }
                let registration =
                    crate::RegisteredPayload::register(ntcp_io::Payload::from_vec(data.clone()))
                        .unwrap();
                if shared {
                    let pointer = registration.as_slice().as_ptr() as usize;
                    assert_eq!(
                        a.execute(client, Op::Send(vec![(pointer, data.len())], MSG_ZEROCOPY))
                            .unwrap()
                            .value,
                        data.len() as i32
                    );
                } else {
                    a.execute(client, Op::Write(data.clone())).unwrap();
                }
                wa.lock().unwrap().block = true;
                a.service_egress().unwrap();
                assert!(a.endpoint.is_output_reserved(cid));
                assert!(wa.lock().unwrap().sent.is_empty());
                let first = wa.lock().unwrap().offered.last().unwrap().clone();
                let context = a.egress.as_ref().unwrap().context(cid).unwrap();
                assert_eq!(context.attempt, a.egress.as_ref().unwrap().attempt(cid));
                // Accept exactly one physical packet, leaving an immutable
                // prefix and a blocked suffix before the network update.
                let port = a.endpoint.tuple(cid).unwrap().local.port();
                {
                    let mut wire = wa.lock().unwrap();
                    wire.block = false;
                    wire.block_after = Some((port, 1));
                }
                tick(&mut a);
                a.service_egress().unwrap();
                assert_eq!(wa.lock().unwrap().sent.len(), 1);
                assert_eq!(wa.lock().unwrap().sent[0], first);
                assert!(a.endpoint.is_output_reserved(cid));
                let prefix = transfer(&wa, &mut b, &wb);
                let mtu = if v6 { 1280 } else { 700 };
                let offered = wa.lock().unwrap().offered.len();
                budget(&mut a, cid, mtu, physical);
                wa.lock().unwrap().block_after = None;
                complete(&mut a, &mut b, &wa, &wb, cid, data.len());
                assert_eq!(b.execute(server, Op::Read(BYTES)).unwrap().bytes, data);
                assert_eq!(b.execute(server, Op::Read(1)).unwrap_err(), EAGAIN);
                assert_eq!(a.endpoint.acknowledged(cid), Ok(7000));
                let wire = wa.lock().unwrap();
                assert!(
                    wire.offered[offered..]
                        .iter()
                        .all(|p| ip_size(p) <= mtu as usize)
                );
                assert!(wire.offered.len() > offered);
                assert_eq!(prefix[0], first);
                if shared {
                    assert!(wire.shared_offered.iter().any(|(_, payload)| *payload > 0));
                    for (&(header, payload), frame) in wire.shared_offered.iter().zip(&wire.offered)
                    {
                        assert_eq!(header + payload, frame.len());
                        assert_eq!(header + payload - 14, ip_size(frame));
                    }
                }
                eprintln!(
                    "NATIVE_BARRIER family={} gso={gso} shared={shared} physical={physical} prefix_ip={} new_budget={mtu} offered={} acknowledged=7000 receiver_once=true",
                    if v6 { 6 } else { 4 },
                    ip_size(&first),
                    wire.offered.len()
                );
            }
        }
    }
}

#[test]
fn managed_scheduled_harmless_stamp_preserves_held_attempt_and_real_rto_work() {
    let (mut a, mut b, client, server, wa, wb) = pair_output(false, false, false);
    let cid = connection(&a, client);
    a.execute(client, Op::Write(vec![9; 300])).unwrap();
    a.service_egress().unwrap();
    let original = wa.lock().unwrap().sent.pop_front().unwrap(); // Real submitted loss.
    let deadline = a.endpoint.next_deadline().unwrap();
    a.test_now = Some(deadline);
    a.endpoint.on_timeout(deadline, BUDGET).unwrap();
    wa.lock().unwrap().block = true;
    a.service_egress().unwrap();
    let attempt = a.egress.as_ref().unwrap().attempt(cid);
    let held = wa.lock().unwrap().offered.last().unwrap().clone();
    let state = a.endpoint.transport_info(cid).unwrap();
    let timer = a.endpoint.next_deadline();
    let context = a.egress.as_ref().unwrap().context(cid).unwrap();
    // Plateau replacement changes the stamp without invalidating these bytes.
    a.host
        .as_mut()
        .unwrap()
        .set_ipv4_plateaus(path::Ipv4Plateaus::RFC1191)
        .unwrap();
    for _ in 0..3 {
        tick(&mut a);
        a.service_egress().unwrap();
        assert_eq!(a.egress.as_ref().unwrap().attempt(cid), attempt);
        assert_eq!(wa.lock().unwrap().offered.last(), Some(&held));
        let mut live = a.endpoint.transport_info(cid).unwrap();
        // These observations intentionally measure elapsed caller time.
        live.last_data_recv_ms = state.last_data_recv_ms;
        live.busy_time_us = state.busy_time_us;
        assert_eq!(live, state);
        assert_eq!(a.endpoint.next_deadline(), timer);
    }
    assert_ne!(
        a.egress
            .as_ref()
            .unwrap()
            .context(cid)
            .unwrap()
            .binding
            .snapshot
            .stamp(),
        context.binding.snapshot.stamp()
    );
    wa.lock().unwrap().block = false;
    complete(&mut a, &mut b, &wa, &wb, cid, 300);
    assert_eq!(
        b.execute(server, Op::Read(400)).unwrap().bytes,
        vec![9; 300]
    );
    assert_eq!(ip_size(&original), ip_size(&held));
}

#[test]
fn managed_scheduled_genuine_probe_submits_but_new_negative_revision_rejects_held_intent() {
    for v6 in [false, true] {
        for stale in [false, true] {
            let (mut a, mut b, client, server, wa, wb) = pair_output(v6, false, false);
            let cid = connection(&a, client);
            let mtu = if v6 { 1350 } else { 1100 };
            budget(&mut a, cid, mtu, false);
            a.service_egress().unwrap();
            let hold = a
                .host
                .as_ref()
                .unwrap()
                .binding(cid)
                .unwrap()
                .snapshot
                .retry_not_before();
            a.test_now = Some(hold);
            b.test_now = Some(hold);
            // Receiver-driven ordinary progress supplies enough congestion
            // credit for the probe plus its three required trailing segments.
            a.execute(client, Op::Write(vec![6; 4000])).unwrap();
            complete(&mut a, &mut b, &wa, &wb, cid, 4000);
            assert_eq!(
                b.execute(server, Op::Read(BYTES)).unwrap().bytes,
                vec![6; 4000]
            );
            wa.lock().unwrap().offered.clear();
            a.execute(client, Op::Write(vec![7; 20000])).unwrap();
            wa.lock().unwrap().block = true;
            a.service_egress().unwrap();
            let attempt = a.egress.as_ref().unwrap().attempt(cid);
            let intent = a
                .endpoint
                .transmit_discovery_intent(attempt)
                .expect("actual native selected upward probe");
            let selected = wa.lock().unwrap().offered.last().unwrap().clone();
            assert_eq!(intent.ip_packet_len() as usize, ip_size(&selected));
            assert!(ip_size(&selected) > mtu as usize);
            let limit = if stale {
                let limit = if v6 { 1280 } else { 1050 };
                budget(&mut a, cid, limit, false);
                limit
            } else {
                let prior = a.egress.as_ref().unwrap().context(cid).unwrap();
                let deadline = a.endpoint.next_deadline();
                budget(&mut a, cid, mtu, false); // Equal evidence cannot restart holdoff.
                a.host
                    .as_mut()
                    .unwrap()
                    .set_link_mtu(prior.link, 1600)
                    .unwrap();
                tick(&mut a);
                a.service_egress().unwrap(); // Still WouldBlock, same real probe.
                assert_eq!(a.egress.as_ref().unwrap().attempt(cid), attempt);
                assert_eq!(
                    a.endpoint
                        .transmit_discovery_intent(attempt)
                        .unwrap()
                        .ip_packet_len(),
                    intent.ip_packet_len()
                );
                assert_eq!(a.endpoint.next_deadline(), deadline);
                let current = a.host.as_ref().unwrap().binding(cid).unwrap().snapshot;
                assert_eq!(current.learned_mtu(), Some(mtu));
                assert_eq!(current.retry_not_before(), hold);
                assert_eq!(wa.lock().unwrap().offered.last(), Some(&selected));
                mtu
            };
            let offers = wa.lock().unwrap().offered.len();
            wa.lock().unwrap().block = false;
            tick(&mut a);
            a.service_egress().unwrap();
            if stale {
                assert!(a.endpoint.transmit_discovery_intent(attempt).is_none());
                assert!(
                    wa.lock().unwrap().offered[offers..]
                        .iter()
                        .all(|p| ip_size(p) <= limit as usize)
                );
            } else {
                assert_eq!(wa.lock().unwrap().sent.front(), Some(&selected));
            }
            transfer(&wa, &mut b, &wb);
            b.service_egress().unwrap();
            transfer(&wb, &mut a, &wa);
            complete(&mut a, &mut b, &wa, &wb, cid, 24000);
            assert_eq!(
                b.execute(server, Op::Read(BYTES)).unwrap().bytes,
                vec![7; 20000]
            );
            assert!(a.endpoint.managed_path(cid).unwrap().ordinary_ip_budget <= limit);
            eprintln!(
                "NATIVE_PROBE family={} stale={stale} selected_ip={} ordinary={limit} acknowledged=24000",
                if v6 { 6 } else { 4 },
                ip_size(&selected)
            );
        }
    }
}

#[test]
fn managed_scheduled_no_route_preserves_sibling_progress_and_budget_update_adds_no_phantom_repair()
{
    let (mut a, mut b, client, server, wa, wb) = pair_output(false, false, false);
    let cid = connection(&a, client);
    let old = a.host.as_ref().unwrap().binding(cid).unwrap();
    let route = a
        .host
        .as_ref()
        .unwrap()
        .paths()
        .route(old.snapshot.key().route())
        .unwrap();
    let mut isolated = route;
    isolated.dscp = Some(path::Dscp::new(12).unwrap());
    let second = new(&mut a, SOCK_NONBLOCK);
    class(&mut a, second, 48).unwrap();
    assert_eq!(
        a.execute(second, Op::Connect(SocketAddr::new(b.local, 8080)))
            .unwrap_err(),
        EINPROGRESS
    );
    exchange(&mut a, &mut b, &wa, &wb);
    let listen = b
        .sockets
        .iter()
        .find(|(_, s)| matches!(s.handle, Handle::Listener(_)))
        .map(|(id, _)| *id)
        .unwrap();
    let received = b.execute(listen, Op::Accept(SOCK_NONBLOCK)).unwrap().value as u64;
    let sibling = connection(&a, second);
    let port = a.endpoint.tuple(cid).unwrap().local.port();
    wa.lock().unwrap().block_port = Some(port);
    a.execute(client, Op::Write(vec![4; 500])).unwrap();
    a.service_egress().unwrap();
    let isolated_id = a
        .host
        .as_mut()
        .unwrap()
        .replace_route(old.snapshot.key().route(), isolated)
        .unwrap();
    a.execute(second, Op::Write(b"unrelated".to_vec())).unwrap();
    tick(&mut a);
    a.service_egress().unwrap();
    assert_eq!(
        a.egress.as_ref().unwrap().blocked(cid),
        Some(ntcp_host::Error::Path(path::Error::NoRoute))
    );
    assert_eq!(wa.lock().unwrap().sent.len(), 1);
    let healthy = a.endpoint.transport_info(sibling).unwrap();
    transfer(&wa, &mut b, &wb);
    b.service_egress().unwrap();
    transfer(&wb, &mut a, &wa);
    assert_eq!(
        b.execute(received, Op::Read(99)).unwrap().bytes,
        b"unrelated"
    );
    a.host
        .as_mut()
        .unwrap()
        .replace_route(isolated_id, route)
        .unwrap();
    a.host
        .as_mut()
        .unwrap()
        .refresh(&mut a.endpoint, cid)
        .unwrap();
    wa.lock().unwrap().block_port = None;
    budget(&mut a, cid, 700, false);
    let offered = wa.lock().unwrap().offered.len();
    complete(&mut a, &mut b, &wa, &wb, cid, 500);
    assert_eq!(
        b.execute(server, Op::Read(600)).unwrap().bytes,
        vec![4; 500]
    );
    let wire = wa.lock().unwrap();
    let sibling_port = a
        .endpoint
        .tuple(sibling)
        .unwrap()
        .local
        .port()
        .to_be_bytes();
    assert!(
        wire.offered[offered..]
            .iter()
            .all(|p| frame_port(p) != Some(sibling_port))
    );
    let live = a.endpoint.transport_info(sibling).unwrap();
    assert_eq!(live.rto_backoff, healthy.rto_backoff);
    assert_eq!(live.lost, 0);
    assert_eq!(live.retransmitted, 0);
}

#[test]
fn managed_scheduled_stateless_and_released_final_reset_leases_end_after_real_submission() {
    for released in [false, true] {
        let (mut a, wa) = native(false, 2, 2);
        let (mut b, wb) = native(false, 3, 2);
        let client = new(&mut a, SOCK_NONBLOCK);
        if released {
            listener(&mut b);
        }
        assert_eq!(
            a.execute(client, Op::Connect(SocketAddr::new(b.local, 8080)))
                .unwrap_err(),
            EINPROGRESS
        );
        let cid = connection(&a, client);
        let (sender, wire) = if released {
            exchange(&mut a, &mut b, &wa, &wb);
            a.endpoint.abort(cid).unwrap();
            a.endpoint.release(cid).unwrap();
            a.sockets.remove(&client);
            (&mut a, &wa)
        } else {
            flush(&mut a, &mut b, &wa);
            (&mut b, &wb)
        };
        wire.lock().unwrap().block = true;
        sender.service_egress().unwrap();
        assert!(wire.lock().unwrap().sent.is_empty());
        assert_eq!(
            sender.host.as_ref().unwrap().binding_count(),
            usize::from(released)
        );
        assert_eq!(
            sender.host.as_ref().unwrap().lease_count(),
            usize::from(!released)
        );
        let held = wire.lock().unwrap().offered.last().unwrap().clone();
        let ip = crate::ip::parse(ntcp_ethernet::parse_ethernet(&held).unwrap().payload).unwrap();
        assert!(ntcp::wire::parse(ip.ip, ip.payload).unwrap().header.flags & ntcp::wire::RST != 0);
        let link = sender.ingress.unwrap().link();
        sender
            .host
            .as_mut()
            .unwrap()
            .set_link_mtu(link, 1400)
            .unwrap();
        wire.lock().unwrap().block = false;
        tick(sender);
        sender.service_egress().unwrap();
        assert_eq!(wire.lock().unwrap().sent.len(), 1);
        assert_eq!(wire.lock().unwrap().sent.front(), Some(&held));
        assert_eq!(sender.host.as_ref().unwrap().lease_count(), 0);
        if released {
            sender.test_now = Some(sender.now() + sender.defaults.connection.time_wait_us + 1);
            sender.endpoint.on_timeout(sender.now(), BUDGET).unwrap();
            sender.collect_paths().unwrap();
        }
        assert_eq!(sender.host.as_ref().unwrap().binding_count(), 0);
        assert_eq!(sender.host.as_ref().unwrap().paths().usage().clients, 0);
    }
}

#[test]
fn managed_scheduled_unattached_generation_and_ip_neighbor_mapping_never_use_global_mac() {
    for new_link in [false, true] {
        let (mut a, mut b, client, server, wa, wb) = pair_output(false, false, false);
        let cid = connection(&a, client);
        a.execute(client, Op::Write(vec![5; 300])).unwrap();
        wa.lock().unwrap().block = true;
        a.service_egress().unwrap();
        let old = a.host.as_ref().unwrap().binding(cid).unwrap();
        let mut route = a
            .host
            .as_ref()
            .unwrap()
            .paths()
            .route(old.snapshot.key().route())
            .unwrap();
        let ingress = a.ingress.unwrap();
        if new_link {
            let caps = a
                .host
                .as_ref()
                .unwrap()
                .receive_capabilities(ingress)
                .unwrap();
            let host = a.host.as_mut().unwrap();
            host.remove_link(ingress).unwrap();
            let replacement = host
                .register_link(
                    path::InterfaceKey(2),
                    1500,
                    caps,
                    ntcp_host::Forwarding::Forwarder(path::ForwarderId(1)),
                )
                .unwrap();
            host.register_source(
                path::ScopedAddress::new(a.local, None).unwrap(),
                replacement.link(),
            )
            .unwrap();
            route.link = replacement.link();
        } else {
            route.next_hop = path::NextHop::OnLink;
        }
        let replacement_route = if new_link {
            a.host.as_mut().unwrap().add_route(route).unwrap()
        } else {
            a.host
                .as_mut()
                .unwrap()
                .replace_route(old.snapshot.key().route(), route)
                .unwrap()
        };
        let offers = wa.lock().unwrap().offered.len();
        wa.lock().unwrap().block = false;
        for _ in 0..3 {
            tick(&mut a);
            a.service_egress().unwrap();
        }
        assert_eq!(wa.lock().unwrap().offered.len(), offers);
        assert_eq!(
            a.egress.as_ref().unwrap().blocked(cid),
            Some(ntcp_host::Error::Unsupported)
        );
        assert_eq!(a.endpoint.state(cid), Ok(ntcp::State::Established));
        if !new_link {
            route.next_hop = path::NextHop::Forwarder(path::ForwarderId(1));
            a.host
                .as_mut()
                .unwrap()
                .replace_route(replacement_route, route)
                .unwrap();
            complete(&mut a, &mut b, &wa, &wb, cid, 300);
            assert_eq!(
                b.execute(server, Op::Read(400)).unwrap().bytes,
                vec![5; 300]
            );
        }
    }
}

#[test]
fn managed_scheduled_shared_budget_has_no_phantom_repair_on_innocent_same_path_sibling() {
    let (mut a, mut b, client, server, wa, wb) = pair_output(false, false, false);
    let second = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(second, Op::Connect(SocketAddr::new(b.local, 8080)))
            .unwrap_err(),
        EINPROGRESS
    );
    exchange(&mut a, &mut b, &wa, &wb);
    let listen = b
        .sockets
        .iter()
        .find(|(_, s)| matches!(s.handle, Handle::Listener(_)))
        .map(|(id, _)| *id)
        .unwrap();
    let receiver = b.execute(listen, Op::Accept(SOCK_NONBLOCK)).unwrap().value as u64;
    let cid = connection(&a, client);
    let sibling = connection(&a, second);
    assert_eq!(
        a.host
            .as_ref()
            .unwrap()
            .binding(cid)
            .unwrap()
            .snapshot
            .path(),
        a.host
            .as_ref()
            .unwrap()
            .binding(sibling)
            .unwrap()
            .snapshot
            .path()
    );
    a.execute(second, Op::Write(vec![8; 300])).unwrap();
    a.service_egress().unwrap();
    let sibling_frame = wa.lock().unwrap().sent.pop_front().unwrap();
    let before = a.endpoint.transport_info(sibling).unwrap();
    assert_eq!(before.unacked, 1);
    let port = a.endpoint.tuple(cid).unwrap().local.port();
    wa.lock().unwrap().block_port = Some(port);
    a.execute(client, Op::Write(vec![5; 2000])).unwrap();
    a.service_egress().unwrap();
    budget(&mut a, cid, 700, false);
    let offers = wa.lock().unwrap().offered.len();
    tick(&mut a);
    a.service_egress().unwrap();
    let sibling_port = a
        .endpoint
        .tuple(sibling)
        .unwrap()
        .local
        .port()
        .to_be_bytes();
    assert!(
        wa.lock().unwrap().offered[offers..]
            .iter()
            .all(|p| frame_port(p) != Some(sibling_port))
    );
    let after = a.endpoint.transport_info(sibling).unwrap();
    assert_eq!(after.unacked, before.unacked);
    assert_eq!(after.lost, before.lost);
    assert_eq!(after.retransmitted, before.retransmitted);
    assert_eq!(after.rto_backoff, before.rto_backoff);
    assert_eq!(after.rto_us, before.rto_us);
    assert!(after.mss <= 660);
    assert_eq!(after.advertised_mss, before.advertised_mss);
    let sibling_path = a.endpoint.managed_path(sibling).unwrap();
    assert_eq!(sibling_path.binding.snapshot.learned_mtu(), Some(700));
    assert!(
        !a.host
            .as_ref()
            .unwrap()
            .paths()
            .is_dirty(sibling_path.binding.client)
            .unwrap()
    );
    // The original submitted evidence still delivers exactly once; no repair
    // was manufactured for the unquoted sibling when its MSS decreased.
    wb.lock().unwrap().incoming.push_back(Ok(sibling_frame));
    b.receive_batch(&mut [0; 65549]).unwrap();
    assert_eq!(
        b.execute(receiver, Op::Read(400)).unwrap().bytes,
        vec![8; 300]
    );
    b.service_egress().unwrap();
    transfer(&wb, &mut a, &wa);
    assert_eq!(a.endpoint.acknowledged(sibling), Ok(300));
    wa.lock().unwrap().block_port = None;
    complete(&mut a, &mut b, &wa, &wb, cid, 2000);
    assert_eq!(
        b.execute(server, Op::Read(3000)).unwrap().bytes,
        vec![5; 2000]
    );
}

#[test]
fn managed_scheduled_ingress_checks_local_authority_and_retains_reserved_feedback() {
    let (mut a, mut b, client, server, wa, wb) = pair_output(false, false, false);
    let cid = connection(&a, client);
    a.execute(client, Op::Write(vec![1; 800])).unwrap();
    wa.lock().unwrap().block = true;
    a.service_egress().unwrap();
    b.execute(server, Op::Write(vec![2; 100])).unwrap();
    b.service_egress().unwrap();
    let packets = transfer(&wb, &mut a, &wa);
    assert_eq!(packets.len(), 1);
    assert!(a.egress.as_ref().unwrap().retained_rx(cid));
    assert_eq!(a.endpoint.transport_info(cid).unwrap().receive_used, 0);
    // The deferred packet is validated at dispatch too; revoked local source
    // ownership cannot slip through an earlier tuple/retention observation.
    let binding = a.host.as_ref().unwrap().binding(cid).unwrap();
    let link = binding.snapshot.key().link();
    a.host
        .as_mut()
        .unwrap()
        .remove_source_owner(binding.snapshot.key().source(), link)
        .unwrap();
    a.host
        .as_mut()
        .unwrap()
        .register_source(path::ScopedAddress::new(a.local, None).unwrap(), link)
        .unwrap();
    wa.lock().unwrap().block = false;
    tick(&mut a);
    a.service_egress().unwrap();
    a.receive_batch(&mut [0; 65549]).unwrap();
    assert!(!a.egress.as_ref().unwrap().retained_rx(cid));
    assert_eq!(
        a.execute(client, Op::Read(200)).unwrap().bytes,
        vec![2; 100]
    );
    let bcid = connection(&b, server);
    let binding = b.host.as_ref().unwrap().binding(bcid).unwrap();
    b.host
        .as_mut()
        .unwrap()
        .remove_source_owner(
            binding.snapshot.key().source(),
            binding.snapshot.key().link(),
        )
        .unwrap();
    let frames = transfer(&wa, &mut b, &wb);
    assert!(!frames.is_empty());
    assert_eq!(b.endpoint.transport_info(bcid).unwrap().receive_used, 0);
    b.host
        .as_mut()
        .unwrap()
        .register_source(
            path::ScopedAddress::new(b.local, None).unwrap(),
            binding.snapshot.key().link(),
        )
        .unwrap();
    wb.lock()
        .unwrap()
        .incoming
        .extend(frames.into_iter().map(Ok));
    b.receive_batch(&mut [0; 65549]).unwrap();
    assert_eq!(
        b.execute(server, Op::Read(900)).unwrap().bytes,
        vec![1; 800]
    );
    b.service_egress().unwrap();
    transfer(&wb, &mut a, &wa);
    assert_eq!(a.endpoint.acknowledged(cid), Ok(800));
}

#[test]
fn managed_scheduled_indivisible_held_tfo_reports_no_submission_and_only_fails_its_owner() {
    let (mut a, wa) = native_output(false, 2, 3, 1500, false, false);
    let (mut b, wb) = native_output(false, 3, 3, 1500, false, false);
    let listen = listener(&mut b);
    b.execute(
        listen,
        Op::SetListenerFastOpenEarlyDataPolicy(FastOpenEarlyDataPolicy::ApplicationProtected),
    )
    .unwrap();
    let client = new(&mut a, SOCK_NONBLOCK);
    let remote = SocketAddr::new(b.local, 8080);
    a.execute(
        client,
        Op::SetFastOpenClientPolicy(Some((remote, FastOpenClientPolicy::ApplicationProtected))),
    )
    .unwrap();
    let data = [7; 300];
    a.execute(
        client,
        Op::SendTo(
            vec![(data.as_ptr() as usize, data.len())],
            MSG_FASTOPEN,
            Some(remote),
            None,
        ),
    )
    .unwrap();
    let cid = connection(&a, client);
    wa.lock().unwrap().block = true;
    a.service_egress().unwrap();
    assert!(a.endpoint.is_output_reserved(cid));
    assert!(ip_size(wa.lock().unwrap().offered.last().unwrap()) > 68);
    budget(&mut a, cid, 68, false);
    let offers = wa.lock().unwrap().offered.len();
    wa.lock().unwrap().block = false;
    tick(&mut a);
    a.service_egress().unwrap();
    assert_eq!(wa.lock().unwrap().offered.len(), offers);
    assert!(wa.lock().unwrap().sent.is_empty());
    assert_eq!(a.endpoint.state(cid), Ok(ntcp::State::Closed));
    assert!(!a.endpoint.is_output_reserved(cid));
    let sibling = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(sibling, Op::Connect(remote)).unwrap_err(),
        EINPROGRESS
    );
    exchange(&mut a, &mut b, &wa, &wb);
    assert_eq!(
        a.endpoint.state(connection(&a, sibling)),
        Ok(ntcp::State::Established)
    );
    assert!(
        wa.lock().unwrap().offered[offers..]
            .iter()
            .all(|p| ip_size(p) <= 68)
    );
}

#[test]
fn managed_scheduled_no_route_and_invalid_source_park_only_affected_lane_then_recover() {
    for remove_source in [false, true] {
        let (mut a, mut b, client, server, wa, wb) = pair_output(false, false, false);
        let cid = connection(&a, client);
        a.execute(client, Op::Write(vec![4; 500])).unwrap();
        wa.lock().unwrap().block = true;
        a.service_egress().unwrap();
        let old = a.host.as_ref().unwrap().binding(cid).unwrap();
        let link = old.snapshot.key().link();
        let route = a
            .host
            .as_ref()
            .unwrap()
            .paths()
            .route(old.snapshot.key().route())
            .unwrap();
        if remove_source {
            a.host
                .as_mut()
                .unwrap()
                .remove_source_owner(old.snapshot.key().source(), link)
                .unwrap();
        } else {
            a.host
                .as_mut()
                .unwrap()
                .remove_route(old.snapshot.key().route())
                .unwrap();
        }
        let calls = wa.lock().unwrap().offered.len();
        wa.lock().unwrap().block = false;
        tick(&mut a);
        a.service_egress().unwrap();
        assert_eq!(wa.lock().unwrap().offered.len(), calls);
        assert!(a.egress.as_ref().unwrap().blocked(cid).is_some());
        assert_eq!(a.endpoint.state(cid), Ok(ntcp::State::Established));
        assert!(
            a.host
                .as_ref()
                .unwrap()
                .paths()
                .is_dirty(old.client)
                .unwrap()
        );
        if remove_source {
            a.host
                .as_mut()
                .unwrap()
                .register_source(path::ScopedAddress::new(a.local, None).unwrap(), link)
                .unwrap();
        } else {
            a.host.as_mut().unwrap().add_route(route).unwrap();
        }
        complete(&mut a, &mut b, &wa, &wb, cid, 500);
        assert_eq!(
            b.execute(server, Op::Read(600)).unwrap().bytes,
            vec![4; 500]
        );
        assert!(a.egress.as_ref().unwrap().blocked(cid).is_none());
    }
}
