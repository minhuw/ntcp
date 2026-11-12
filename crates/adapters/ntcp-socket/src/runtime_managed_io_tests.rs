// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;
#[path = "runtime_path_mtu_tests.rs"]
mod path_mtu;

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
        a.ports[0].mtu_refresh = Some(refresh);
        results.send(Ok(Some(mtu))).unwrap();
        a.poll_mtu_refresh();
        assert_eq!(
            a.host
                .as_ref()
                .unwrap()
                .paths()
                .link(a.ports[0].ingress.unwrap().link())
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

// Successive network decreases (two shared estimates, then a physical
// first-hop decrease) arrive while the native owner keeps a partially
// submitted reservation whose retries the backend blocks or rejects; a
// first-hop increase then restores the learned estimate. Every offered retry
// fits the budget current at that pass, nothing beyond the accepted prefix
// is charged, and the receiver reads exactly the written stream once.
#[test]
fn managed_scheduled_successive_decreases_with_refused_retries_then_increase() {
    for v6 in [false, true] {
        for (gso, shared) in [(false, false), (true, false), (true, true)] {
            let (mut a, mut b, client, server, wa, wb) = pair_output(v6, gso, shared);
            let cid = connection(&a, client);
            let data: Vec<_> = (0..7000).map(|n| (n % 251) as u8).collect();
            let registration =
                crate::RegisteredPayload::register(ntcp_io::Payload::from_vec(data.clone()))
                    .unwrap();
            if shared {
                a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
                    .unwrap();
                let pointer = registration.as_slice().as_ptr() as usize;
                a.execute(client, Op::Send(vec![(pointer, data.len())], MSG_ZEROCOPY))
                    .unwrap();
            } else {
                a.execute(client, Op::Write(data.clone())).unwrap();
            }
            let port = a.endpoint.tuple(cid).unwrap().local.port();
            wa.lock().unwrap().block_after = Some((port, 1));
            a.service_egress().unwrap();
            assert_eq!(wa.lock().unwrap().sent.len(), 1);
            assert!(a.endpoint.is_output_reserved(cid));
            let first = wa.lock().unwrap().sent[0].clone();
            {
                let mut wire = wa.lock().unwrap();
                wire.block_after = None;
                wire.block_port = Some(port);
            }
            let before = a.endpoint.transport_info(cid).unwrap();
            let progress = a.endpoint.send_progress(cid).unwrap();
            let (m1, m2, l3) = if v6 {
                (1420, 1350, 1280)
            } else {
                (1300, 1100, 1000)
            };
            let mut retries = 0;
            for (limit, physical, reject) in
                [(m1, false, false), (m2, false, true), (l3, true, false)]
            {
                wa.lock().unwrap().reject = reject;
                let mark = wa.lock().unwrap().offered.len();
                budget(&mut a, cid, limit, physical);
                tick(&mut a);
                a.service_egress().unwrap();
                assert_eq!(
                    a.endpoint.managed_path(cid).unwrap().ordinary_ip_budget,
                    limit
                );
                let wire = wa.lock().unwrap();
                assert_eq!(wire.sent.len(), 1, "only the accepted prefix left");
                assert!(wire.offered.len() > mark, "a retry reached the backend");
                assert!(
                    wire.offered[mark..]
                        .iter()
                        .all(|p| ip_size(p) <= limit as usize)
                );
                retries += wire.offered.len() - mark;
                drop(wire);
                let info = a.endpoint.transport_info(cid).unwrap();
                assert_eq!(
                    (
                        info.unacked,
                        info.lost,
                        info.retransmitted,
                        info.ssthresh,
                        info.recovery
                    ),
                    (
                        before.unacked,
                        before.lost,
                        before.retransmitted,
                        before.ssthresh,
                        false
                    )
                );
                assert_eq!(a.endpoint.send_progress(cid).unwrap(), progress);
            }
            budget(&mut a, cid, 1500, true);
            assert_eq!(a.endpoint.managed_path(cid).unwrap().ordinary_ip_budget, m2);
            let mark = {
                let mut wire = wa.lock().unwrap();
                wire.reject = false;
                wire.block_port = None;
                wire.offered.len()
            };
            complete(&mut a, &mut b, &wa, &wb, cid, data.len());
            assert_eq!(b.execute(server, Op::Read(BYTES)).unwrap().bytes, data);
            assert_eq!(b.execute(server, Op::Read(1)).unwrap_err(), EAGAIN);
            let wire = wa.lock().unwrap();
            assert!(
                wire.offered[mark..]
                    .iter()
                    .all(|p| ip_size(p) <= m2 as usize)
            );
            let after = a.endpoint.transport_info(cid).unwrap();
            assert_eq!(
                (after.lost, after.retransmitted, after.recovery),
                (0, 0, false)
            );
            eprintln!(
                "NATIVE_RACE family={} gso={gso} shared={shared} prefix_ip={} budgets={m1}->{m2}->{l3}->{m2} refused_retries={retries} later_offered={} acknowledged=7000",
                if v6 { 6 } else { 4 },
                ip_size(&first),
                wire.offered.len() - mark
            );
        }
    }
}

// A held RTO retransmission was authorized under its path as it was. A
// plateau replacement changes the path's stamp without changing what the
// bytes may be, yet the held attempt is refused at its next submission and
// selected again: this costs a repacketization, never phantom loss,
// retransmission or RTO work.
#[test]
fn managed_scheduled_path_change_refuses_held_attempt_without_phantom_rto_work() {
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
    a.host
        .as_mut()
        .unwrap()
        .set_ipv4_plateaus(path::Ipv4Plateaus::RFC1191)
        .unwrap();
    let mut replacement = None;
    for _ in 0..3 {
        tick(&mut a);
        a.service_egress().unwrap();
        let current = a.egress.as_ref().unwrap().attempt(cid);
        assert_ne!(current, attempt);
        assert_eq!(*replacement.get_or_insert(current), current);
        assert_eq!(
            ip_size(wa.lock().unwrap().offered.last().unwrap()),
            ip_size(&held)
        );
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

// A held probe was authorized under its path as it was, so any change of
// that path refuses it, and the connection selects ordinary output in its
// place. Harmless: only a link increase changes the path version; the hold
// is not restarted, so the search probes again during the transfer and
// confirms a larger ceiling. Unchanged: a fresh equal report keeps the
// estimate but restarts the hold. Lower: a new negative revision. In both
// stale cases the refused probe proves nothing and the restarted hold
// outlasts the transfer.
#[test]
fn managed_scheduled_held_probe_is_refused_by_any_path_change() {
    for v6 in [false, true] {
        for (stale, unchanged) in [(false, false), (true, true), (true, false)] {
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
            let limit = if unchanged {
                let prior = a.host.as_ref().unwrap().binding(cid).unwrap().snapshot;
                budget(&mut a, cid, mtu, false);
                let current = a
                    .host
                    .as_ref()
                    .unwrap()
                    .paths()
                    .path_snapshot(prior.path())
                    .unwrap();
                assert_eq!(current.learned_mtu(), Some(mtu));
                assert_eq!(current.negative_revision(), prior.negative_revision());
                assert!(current.retry_not_before() > prior.retry_not_before());
                mtu
            } else if stale {
                let limit = if v6 { 1280 } else { 1050 };
                budget(&mut a, cid, limit, false);
                limit
            } else {
                let prior = a.egress.as_ref().unwrap().context(cid).unwrap();
                let deadline = a.endpoint.next_deadline();
                a.host
                    .as_mut()
                    .unwrap()
                    .set_link_mtu(prior.link, 1600)
                    .unwrap();
                tick(&mut a);
                a.service_egress().unwrap(); // Still WouldBlock: refused, selected again.
                let replacement = a.egress.as_ref().unwrap().attempt(cid);
                assert_ne!(replacement, attempt);
                assert!(a.endpoint.transmit_discovery_intent(attempt).is_none());
                assert!(a.endpoint.transmit_discovery_intent(replacement).is_none());
                assert_eq!(a.endpoint.next_deadline(), deadline);
                let current = a.host.as_ref().unwrap().binding(cid).unwrap().snapshot;
                assert_eq!(current.learned_mtu(), Some(mtu));
                assert_eq!(current.retry_not_before(), hold);
                assert!(ip_size(wa.lock().unwrap().offered.last().unwrap()) <= mtu as usize);
                mtu
            };
            let offers = wa.lock().unwrap().offered.len();
            wa.lock().unwrap().block = false;
            tick(&mut a);
            a.service_egress().unwrap();
            assert!(a.endpoint.transmit_discovery_intent(attempt).is_none());
            assert_ne!(wa.lock().unwrap().sent.front(), Some(&selected));
            if stale {
                assert!(
                    wa.lock().unwrap().offered[offers..]
                        .iter()
                        .all(|p| ip_size(p) <= limit as usize)
                );
            }
            transfer(&wa, &mut b, &wb);
            b.service_egress().unwrap();
            transfer(&wb, &mut a, &wa);
            complete(&mut a, &mut b, &wa, &wb, cid, 24000);
            assert_eq!(
                b.execute(server, Op::Read(BYTES)).unwrap().bytes,
                vec![7; 20000]
            );
            // The runtime's change service publishes a delivered probe,
            // selected after the hold and definitely submitted, as the new
            // shared ceiling: in the harmless case a later one of the transfer.
            let ordinary = a.endpoint.managed_path(cid).unwrap().ordinary_ip_budget;
            let learned = a
                .host
                .as_ref()
                .unwrap()
                .binding(cid)
                .unwrap()
                .snapshot
                .learned_mtu();
            if stale {
                assert!(ordinary <= limit);
                assert_eq!(learned, Some(limit));
            } else {
                let learned = learned.unwrap();
                assert!(learned > limit);
                assert!(ordinary > limit && ordinary <= learned);
            }
            eprintln!(
                "NATIVE_PROBE family={} stale={stale} unchanged={unchanged} selected_ip={} ordinary={ordinary} learned={learned:?} acknowledged=24000",
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

// A reset held by a blocked backend across a change of its path (here a link
// MTU decrease that it still fits) is refused at its next submission. A
// stateless reset is dropped, as the peer's next segment draws another; a
// released connection's final reset is selected again and leaves. Either
// way its lease or binding ends with it.
#[test]
fn managed_scheduled_held_reset_across_a_path_change_ends_its_lease() {
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
            a.remove_socket(client);
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
        let link = sender.ports[0].ingress.unwrap().link();
        sender
            .host
            .as_mut()
            .unwrap()
            .set_link_mtu(link, 1400)
            .unwrap();
        wire.lock().unwrap().block = false;
        tick(sender);
        sender.service_egress().unwrap();
        if released {
            assert_eq!(wire.lock().unwrap().sent.len(), 1);
            assert_eq!(
                ip_size(wire.lock().unwrap().sent.front().unwrap()),
                ip_size(&held)
            );
        } else {
            assert!(wire.lock().unwrap().sent.is_empty());
        }
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
        let ingress = a.ports[0].ingress.unwrap();
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

// An administrative budget reduction is never refused as busy: an owner
// value below a held TFO SYN, set alone or together with a discovery
// disable (whose IPv4 sending limit is then that value), is applied like a
// trusted PTB decrease. The indivisible SYN fails only its owner, exactly
// as in the test above, with nothing submitted, and another connection on
// the route connects within the value.
#[test]
fn managed_scheduled_held_tfo_above_an_owner_value_fails_its_owner_with_or_without_disable() {
    use ntcp_host::path::{AdminChange, AdminPolicy, AdminTarget};
    const VALUE: u32 = 200;
    for disable in [false, true] {
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
        assert!(ip_size(wa.lock().unwrap().offered.last().unwrap()) > VALUE as usize);
        let route = a.host.as_ref().unwrap().binding(cid).unwrap().snapshot.key().route();
        let now = a.now();
        let host = a.host.as_mut().unwrap();
        let capability = host.administration();
        let expected = host
            .admin_routes(&capability)
            .unwrap()
            .find(|r| r.route == route)
            .unwrap()
            .generation;
        let candidate = host
            .admin_validate(
                &capability,
                now,
                AdminChange {
                    target: AdminTarget::Route(route),
                    expected,
                    policy: AdminPolicy {
                        discovery_disabled: disable,
                        estimate: Some(VALUE),
                    },
                },
            )
            .unwrap();
        host.admin_apply(&capability, &mut a.endpoint, candidate)
            .unwrap();
        let offers = wa.lock().unwrap().offered.len();
        wa.lock().unwrap().block = false;
        tick(&mut a);
        a.service_egress().unwrap();
        assert_eq!(wa.lock().unwrap().offered.len(), offers, "disable={disable}");
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
            Ok(ntcp::State::Established),
            "disable={disable}"
        );
        let offered = wa.lock().unwrap().offered[offers..].to_vec();
        assert!(!offered.is_empty());
        for frame in &offered {
            assert!(ip_size(frame) <= VALUE as usize);
            let ip = ntcp_ethernet::parse_ethernet(frame).unwrap().payload;
            assert_eq!(ip[6] & 0x40 == 0, disable, "DF follows the policy");
        }
    }
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

// The validated quote a router would return for this exact physical frame.
fn quote(frame: &[u8]) -> ntcp_host::QuoteKey {
    let p = crate::ip::parse(ntcp_ethernet::parse_ethernet(frame).unwrap().payload).unwrap();
    let header = crate::ip::header_len(p.ip.source);
    ntcp_host::QuoteKey {
        source: p.ip.source,
        destination: p.ip.destination,
        header_len: header as u32,
        packet_len: (header + p.payload.len()) as u32,
        protocol: p.protocol,
        transport: ntcp_host::QuotedSelector::Tcp {
            source_port: u16::from_be_bytes([p.payload[0], p.payload[1]]),
            destination_port: u16::from_be_bytes([p.payload[2], p.payload[3]]),
            sequence: u32::from_be_bytes(p.payload[4..8].try_into().unwrap()),
        },
    }
}
fn correlate(owner: &Owner, frame: &[u8]) -> ntcp_host::Correlation {
    owner
        .host
        .as_ref()
        .unwrap()
        .correlate(owner.now(), &quote(frame))
}
// A router-originated Packet Too Big (the source is neither endpoint) quoting
// the actual frame, as an Ethernet frame for the native receive path.
fn router_ptb(frame: &[u8], mtu: u32) -> Vec<u8> {
    let p = crate::ip::parse(ntcp_ethernet::parse_ethernet(frame).unwrap().payload).unwrap();
    let header = crate::ip::header_len(p.ip.source);
    let packet = &ntcp_ethernet::parse_ethernet(frame).unwrap().payload[..header + p.payload.len()];
    // Addressed to the quoted packet's source: this host.
    let (ip, ether_type) = match (p.ip.destination, p.ip.source) {
        (IpAddr::V4(_), IpAddr::V4(destination)) => {
            let quoted = &packet[..header + 8];
            let mut ip = vec![0; 28 + quoted.len()];
            ip[0] = 0x45;
            let total = ip.len() as u16;
            ip[2..4].copy_from_slice(&total.to_be_bytes());
            ip[8] = 64;
            ip[9] = 1;
            ip[12..16].copy_from_slice(&[10, 73, 0, 1]);
            ip[16..20].copy_from_slice(&destination.octets());
            ip[20] = 3;
            ip[21] = 4;
            ip[26..28].copy_from_slice(&(mtu as u16).to_be_bytes());
            ip[28..].copy_from_slice(quoted);
            let checksum = ntcp_ip_common::checksum(&ip[20..]);
            ip[22..24].copy_from_slice(&checksum.to_be_bytes());
            let checksum = ntcp_ip_common::checksum(&ip[..20]);
            ip[10..12].copy_from_slice(&checksum.to_be_bytes());
            (ip, ntcp_ethernet::ETHERTYPE_IPV4)
        }
        (IpAddr::V6(_), IpAddr::V6(destination)) => {
            let router: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
            let quoted = &packet[..packet.len().min(1280 - 48)];
            let mut ip = vec![0; 48 + quoted.len()];
            ip[0] = 0x60;
            ip[4..6].copy_from_slice(&((8 + quoted.len()) as u16).to_be_bytes());
            ip[6] = 58;
            ip[7] = 64;
            ip[8..24].copy_from_slice(&router.octets());
            ip[24..40].copy_from_slice(&destination.octets());
            ip[40] = 2;
            ip[44..48].copy_from_slice(&mtu.to_be_bytes());
            ip[48..].copy_from_slice(quoted);
            let checksum = ntcp_icmp::icmpv6_checksum(
                ntcp::IpMetadata {
                    source: IpAddr::V6(router),
                    destination: IpAddr::V6(destination),
                },
                &ip[40..],
            )
            .unwrap();
            ip[42..44].copy_from_slice(&checksum.to_be_bytes());
            (ip, ntcp_ethernet::ETHERTYPE_IPV6)
        }
        _ => unreachable!(),
    };
    let mut frame = vec![0; (14 + ip.len()).max(60)];
    ntcp_ethernet::encode_ethernet(&mut frame, [2; 6], [4; 6], ether_type, &ip).unwrap();
    frame
}

// The native transaction calls the backend for exactly the accepted
// physical segments (blocked calls and a blocked GSO suffix are offered
// again) and records no ledger evidence for them: ICMP errors about a
// connection are checked against its own sequence space.
#[test]
fn managed_native_transaction_submits_the_accepted_physical_segments_without_evidence() {
    for v6 in [false, true] {
        for (gso, shared) in [(false, false), (true, false), (true, true)] {
            let (mut a, mut b, client, server, wa, wb) = pair_output(v6, gso, shared);
            let cid = connection(&a, client);
            let data: Vec<_> = (0..7000).map(|n| (n % 251) as u8).collect();
            let registration =
                crate::RegisteredPayload::register(ntcp_io::Payload::from_vec(data.clone()))
                    .unwrap();
            if shared {
                a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
                    .unwrap();
                let pointer = registration.as_slice().as_ptr() as usize;
                a.execute(client, Op::Send(vec![(pointer, data.len())], MSG_ZEROCOPY))
                    .unwrap();
            } else {
                a.execute(client, Op::Write(data.clone())).unwrap();
            }
            // Three WouldBlock calls of the same attempt send nothing.
            wa.lock().unwrap().block = true;
            for _ in 0..3 {
                a.service_egress().unwrap();
                tick(&mut a);
            }
            let blocked = wa.lock().unwrap().offered.last().unwrap().clone();
            assert!(wa.lock().unwrap().sent.is_empty());
            assert_eq!(correlate(&a, &blocked).matches, 0);
            // The first physical segment is accepted, the next one blocks.
            let port = a.endpoint.tuple(cid).unwrap().local.port();
            {
                let mut wire = wa.lock().unwrap();
                wire.block = false;
                wire.block_after = Some((port, 1));
            }
            a.service_egress().unwrap();
            assert!(a.endpoint.is_output_reserved(cid));
            let first = wa.lock().unwrap().sent[0].clone();
            assert_eq!(first, blocked);
            let suffix = wa.lock().unwrap().offered.last().unwrap().clone();
            assert_ne!(suffix, first);
            assert_eq!(correlate(&a, &suffix).matches, 0);
            wa.lock().unwrap().block_after = None;
            tick(&mut a);
            a.service_egress().unwrap();
            let sent: Vec<_> = wa.lock().unwrap().sent.iter().cloned().collect();
            assert!(sent.len() >= 3);
            // None of it is ledger evidence.
            for frame in &sent {
                assert_eq!(correlate(&a, frame).matches, 0);
            }
            complete(&mut a, &mut b, &wa, &wb, cid, data.len());
            assert_eq!(b.execute(server, Op::Read(BYTES)).unwrap().bytes, data);
            eprintln!(
                "NATIVE_SUBMITTED family={} gso={gso} shared={shared} blocked_calls=3 accepted={} acknowledged={}",
                if v6 { 6 } else { 4 },
                sent.len(),
                data.len()
            );
        }
    }
}

#[test]
fn managed_native_unknown_outcome_is_quarantined_without_retry() {
    let (mut a, _, client, _, wa, _) = pair_output(false, false, false);
    let cid = connection(&a, client);
    a.execute(client, Op::Write(vec![1; 100])).unwrap();
    wa.lock().unwrap().output_error = Some(io::ErrorKind::Interrupted);
    assert_eq!(a.service_egress(), Err(EIO));
    let offered = wa.lock().unwrap().offered.clone();
    assert_eq!(offered.len(), 1);
    assert!(wa.lock().unwrap().sent.is_empty());
    // Never success, never unsent: the reservation stays quarantined, and
    // a connection's output leaves no ledger evidence.
    assert!(a.endpoint.is_output_reserved(cid));
    assert_eq!(correlate(&a, &offered[0]).matches, 0);
}

#[test]
fn managed_native_reserved_owner_ptb_is_retained_by_host_dispatch_then_replayed() {
    for v6 in [false, true] {
        let (mut a, mut b, client, server, wa, wb) = pair_output(v6, true, false);
        let cid = connection(&a, client);
        let data: Vec<_> = (0..7000).map(|n| (n % 241) as u8).collect();
        a.execute(client, Op::Write(data.clone())).unwrap();
        let port = a.endpoint.tuple(cid).unwrap().local.port();
        wa.lock().unwrap().block_after = Some((port, 1));
        a.service_egress().unwrap();
        assert!(a.endpoint.is_output_reserved(cid));
        let first = wa.lock().unwrap().sent[0].clone();
        assert!(ip_size(&first) > 1300);
        let mtu = if v6 { 1280 } else { 1000 };
        let path = a
            .host
            .as_ref()
            .unwrap()
            .binding(cid)
            .unwrap()
            .snapshot
            .path();
        // A forged control quoting a sequence outside the connection's send
        // window names no connection, so it is discarded before any owner
        // is consulted and not retained.
        let mut forged = first.clone();
        let offset = 14 + crate::ip::header_len(a.local) + 4;
        forged[offset] ^= 0x80;
        wa.lock()
            .unwrap()
            .incoming
            .push_back(Ok(router_ptb(&forged, mtu)));
        a.receive_batch(&mut [0; 65549]).unwrap();
        assert!(!a.egress.as_ref().unwrap().retained_rx(cid));
        // The genuine router report names the connection, then is deferred
        // unapplied for this exact reserved generation.
        wa.lock()
            .unwrap()
            .incoming
            .push_back(Ok(router_ptb(&first, mtu)));
        a.receive_batch(&mut [0; 65549]).unwrap();
        assert!(a.egress.as_ref().unwrap().retained_rx(cid));
        let host = a.host.as_ref().unwrap();
        assert_eq!(host.binding(cid).unwrap().snapshot.path(), path);
        assert!(
            host.binding(cid)
                .unwrap()
                .snapshot
                .ip_packet_budget()
                .unwrap()
                > mtu
        );
        // The held suffix completes at the old size: nothing was applied.
        wa.lock().unwrap().block_after = None;
        tick(&mut a);
        a.service_egress().unwrap();
        assert!(!a.endpoint.is_output_reserved(cid));
        let held: Vec<_> = wa.lock().unwrap().sent.drain(..).collect();
        assert!(held.iter().any(|f| ip_size(f) > mtu as usize));
        input_frames(&mut b, &held);
        let offered = wa.lock().unwrap().offered.len();
        // Replay revalidates for that generation; TCP accepts the immediate
        // decrease, and the Host publishes it on the submission's path.
        a.receive_batch(&mut [0; 65549]).unwrap();
        assert!(!a.egress.as_ref().unwrap().retained_rx(cid));
        let host = a.host.as_mut().unwrap();
        host.refresh(&mut a.endpoint, cid).unwrap();
        assert_eq!(
            host.binding(cid).unwrap().snapshot.ip_packet_budget(),
            Ok(mtu)
        );
        complete(&mut a, &mut b, &wa, &wb, cid, data.len());
        assert_eq!(b.execute(server, Op::Read(BYTES)).unwrap().bytes, data);
        let wire = wa.lock().unwrap();
        assert!(wire.offered.len() > offered);
        assert!(
            wire.offered[offered..]
                .iter()
                .all(|f| ip_size(f) <= mtu as usize)
        );
        eprintln!(
            "NATIVE_RETAINED_PTB family={} quoted_ip={} router_mtu={mtu} retained=true replay_published={mtu} later_offered={} acknowledged={}",
            if v6 { 6 } else { 4 },
            ip_size(&first),
            wire.offered.len() - offered,
            data.len()
        );
    }
}
fn input_frames(to: &mut Owner, frames: &[Vec<u8>]) {
    for frame in frames {
        let eth = ntcp_ethernet::parse_ethernet(frame).unwrap();
        to.input_ip_metadata(eth.payload, Default::default(), None);
    }
    to.events();
}

// Every option native IPv4 input admits: Record Route and Timestamp (flag 1)
// with two free slots each, an opaque copied and a non-copied option.
fn admitted_ipv4_options() -> Vec<u8> {
    let mut raw = vec![30, 2, 158, 3, 0, 7, 11, 4, 0, 0, 0, 0, 0, 0, 0, 0];
    raw.extend_from_slice(&[68, 20, 5, 1]);
    raw.extend_from_slice(&[0; 16]);
    raw
}
// The frame's IPv4 datagram with `options` inserted, as an Ethernet frame to
// this host.
fn with_ipv4_options(frame: &[u8], options: &[u8]) -> Vec<u8> {
    let payload = ntcp_ethernet::parse_ethernet(frame).unwrap().payload;
    let total = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
    let mut ip = payload[..total].to_vec();
    ip.splice(20..20, options.iter().copied());
    ip[0] = 0x45 + (options.len() / 4) as u8;
    let len = ip.len() as u16;
    ip[2..4].copy_from_slice(&len.to_be_bytes());
    ip[10..12].fill(0);
    let checksum = ntcp_ip_common::checksum(&ip[..20 + options.len()]);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    let mut out = vec![0; (14 + ip.len()).max(60)];
    ntcp_ethernet::encode_ethernet(&mut out, [2; 6], [4; 6], ntcp_ethernet::ETHERTYPE_IPV4, &ip)
        .unwrap();
    out
}
// The frame `owner` sent carrying `data`.
fn data_frame(owner: &mut Owner, wire: &Wire, server: u64, data: &[u8]) -> Vec<u8> {
    owner.execute(server, Op::Write(data.to_vec())).unwrap();
    tick(owner);
    owner.service_egress().unwrap();
    let sent: Vec<_> = wire.lock().unwrap().sent.drain(..).collect();
    sent.into_iter()
        .find(|f| f.windows(data.len()).any(|w| w == data))
        .unwrap()
}
// Destination processing of `admitted_ipv4_options` at 10.73.0.2 recording
// `time` once, leaving the second slots free.
fn recorded_once(time: u32) -> ntcp::Ipv4Options {
    let local = Ipv4Addr::new(10, 73, 0, 2);
    let raw = admitted_ipv4_options();
    let recorded = ntcp::Ipv4Options::parse(&raw, false)
        .unwrap()
        .record(local, time)
        .unwrap();
    let out = recorded.as_bytes();
    assert_eq!(&out[..5], &raw[..5]);
    assert_eq!(&out[5..16], &[7, 11, 8, 10, 73, 0, 2, 0, 0, 0, 0]);
    assert_eq!(&out[16..20], &[68, 20, 13, 1]);
    assert_eq!(&out[20..24], &local.octets());
    assert_eq!(&out[24..28], &time.to_be_bytes());
    assert_eq!(&out[28..], &[0; 8]);
    recorded
}
// The time `options` recorded for a datagram processed at `arrival` between
// the `before` and `after` kernel clock reads: a standard value within their
// UTC window, or the owner clock's elapsed milliseconds at arrival marked
// nonstandard (RFC 791 section 3.1).
fn arrival_time(
    options: Option<ntcp::Ipv4Options>,
    arrival: u64,
    before: Option<i128>,
    after: Option<i128>,
) -> u32 {
    let options = options.unwrap();
    let time = u32::from_be_bytes(options.as_bytes()[24..28].try_into().unwrap());
    if !super::standard_time(time, before, after) {
        assert_eq!(time, 0x8000_0000 | (arrival / 1000) as u32);
    }
    time
}

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
//= type=test
//# A timestamp value MUST follow the rules given in Section 3.2.2.8 for
//# the ICMP Timestamp message.
#[test]
fn managed_native_scalar_input_records_once_with_one_utc_source_sample() {
    let (mut a, mut b, client, server, _, wb) = pair_output(false, false, false);
    let cid = connection(&a, client);
    let frame = data_frame(&mut b, &wb, server, b"scalar options");
    let frame = with_ipv4_options(&frame, &admitted_ipv4_options());
    tick(&mut a);
    // Handshake output, its header sizing included, sampled no time.
    assert_eq!(a.ipv4_clock.acquisitions, 0);
    let arrival = a.now();
    let before = super::utc_read();
    input_frames(&mut a, &[frame]);
    let after = super::utc_read();
    assert_eq!(a.ipv4_clock.acquisitions, 1);
    let received = a.endpoint.received_ipv4_options(cid).unwrap();
    let time = arrival_time(received, arrival, before, after);
    assert_eq!(received, Some(recorded_once(time)));
    assert_eq!(
        a.execute(client, Op::Read(BYTES)).unwrap().bytes,
        b"scalar options"
    );
}

// Native TCP originates no IPv4 options, so its egress samples no time.
// Its provider under the one core origin recording
// (OutgoingIpv4Options::encode_with) is sampled once, and only for a
// Timestamp slot the origin writes (RFC 1122 section 3.2.1.8); the value it
// writes is standard within the test's own kernel clock window or the owner
// clock's elapsed milliseconds marked nonstandard.
//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
//= type=test
//# A timestamp value MUST follow the rules given in Section 3.2.2.8 for
//# the ICMP Timestamp message.
#[test]
fn native_origin_timestamp_samples_only_for_a_written_slot() {
    use ntcp::{OutgoingIpv4Options, TimestampRequest};
    let source = Ipv4Addr::new(10, 73, 0, 2);
    let other = Ipv4Addr::new(10, 73, 0, 9);
    let destination = Ipv4Addr::new(10, 73, 0, 1);
    let now = 5_000_000;
    let mut clock = backend::Ipv4Clock::default();
    for (timestamp, writes) in [
        (None, false),
        (Some(TimestampRequest::Times(1)), true),
        (Some(TimestampRequest::AddressTimes(2)), true),
        (
            Some(TimestampRequest::Prespecified {
                addresses: [source, other, source, other],
                len: 2,
            }),
            true,
        ),
        (
            Some(TimestampRequest::Prespecified {
                addresses: [other, source, other, source],
                len: 2,
            }),
            false,
        ),
    ] {
        let options = OutgoingIpv4Options {
            record_route_slots: Some(2),
            timestamp,
            ..Default::default()
        };
        let sampled = clock.acquisitions;
        let mut out = [0; 40];
        let before = super::utc_read();
        let (_, len) = options
            .encode_with(
                source,
                destination,
                &mut backend::Recording {
                    clock: &mut clock,
                    now,
                },
                &mut out,
            )
            .unwrap();
        let after = super::utc_read();
        assert_eq!(clock.acquisitions - sampled, usize::from(writes));
        // Record Route (11 octets) precedes the Timestamp option.
        assert_eq!(&out[..7], &[7, 11, 8, 10, 73, 0, 2]);
        let Some(request) = timestamp else {
            assert_eq!(len, 12);
            continue;
        };
        let ts = &out[11..len];
        let time = match request {
            TimestampRequest::Times(_) => &ts[4..8],
            _ => &ts[8..12],
        };
        let time = u32::from_be_bytes(time.try_into().unwrap());
        if !writes {
            assert_eq!(ts[2], 5, "no slot written");
            assert_eq!(time, 0);
        } else if !super::standard_time(time, before, after) {
            assert_eq!(time, 0x8000_0000 | 5_000);
        }
    }
}

// Native managed input keeps source routes refused (its TCP has IPv4
// options disabled, so no return route could be used): a routed copy of a
// segment is dropped by scalar and scheduled input alike, nothing recorded
// or delivered; the segment itself is then accepted.
#[test]
fn managed_native_input_refuses_source_routed_segments() {
    for scheduled in [false, true] {
        let (mut a, mut b, client, server, wa, wb) = pair_output(false, false, false);
        let cid = connection(&a, client);
        let frame = data_frame(&mut b, &wb, server, b"routed");
        // A completed loose source route ahead of Record Route.
        let mut options = vec![131, 7, 8, 10, 73, 0, 9, 7, 11, 4];
        options.resize(20, 0);
        let routed = with_ipv4_options(&frame, &options);
        let before = a.endpoint.received_ipv4_options(cid).unwrap();
        tick(&mut a);
        if scheduled {
            wa.lock().unwrap().incoming.push_back(Ok(routed));
            a.receive_batch(&mut [0; 65549]).unwrap();
        } else {
            input_frames(&mut a, &[routed]);
        }
        assert_eq!(a.endpoint.received_ipv4_options(cid).unwrap(), before);
        assert_eq!(a.execute(client, Op::Read(BYTES)).unwrap_err(), EAGAIN);
        input_frames(&mut a, &[frame]);
        assert_eq!(a.execute(client, Op::Read(BYTES)).unwrap().bytes, b"routed");
    }
}

// A segment for a reserved owner is retained after destination processing;
// passes that defer it again and its final dispatch record nothing more, and
// a stale owner generation never receives it.
#[test]
fn managed_native_retained_segment_keeps_its_processing_through_replay() {
    for stale in [false, true] {
        let (mut a, mut b, client, server, wa, wb) = pair_output(false, true, false);
        let cid = connection(&a, client);
        let tuple = a.endpoint.tuple(cid).unwrap();
        a.execute(client, Op::Write(vec![5; 7000])).unwrap();
        wa.lock().unwrap().block_after = Some((tuple.local.port(), 1));
        a.service_egress().unwrap();
        assert!(a.endpoint.is_output_reserved(cid));
        let before = a.endpoint.received_ipv4_options(cid).unwrap();
        let frame = data_frame(&mut b, &wb, server, b"retained options");
        let frame = with_ipv4_options(&frame, &admitted_ipv4_options());
        let arrival = a.now();
        wa.lock().unwrap().incoming.push_back(Ok(frame));
        let utc_before = super::utc_read();
        a.receive_batch(&mut [0; 65549]).unwrap();
        let utc_after = super::utc_read();
        assert!(a.egress.as_ref().unwrap().retained_rx(cid));
        assert_eq!(a.ipv4_clock.acquisitions, 1);
        // Later passes, at later times, defer it again unchanged.
        for _ in 0..3 {
            tick(&mut a);
            a.receive_batch(&mut [0; 65549]).unwrap();
            assert!(a.egress.as_ref().unwrap().retained_rx(cid));
            assert_eq!(a.endpoint.received_ipv4_options(cid).unwrap(), before);
        }
        wa.lock().unwrap().block_after = None;
        tick(&mut a);
        a.service_egress().unwrap();
        assert!(!a.endpoint.is_output_reserved(cid));
        let replacement = stale.then(|| {
            // The tuple's next generation must not inherit the retained input.
            // A hard error about its unacknowledged data ends it without a
            // reset, so the tuple is free at once.
            let sent = wa.lock().unwrap().sent[0].clone();
            let ip = crate::ip::parse(ntcp_ethernet::parse_ethernet(&sent).unwrap().payload);
            let ip = ip.unwrap();
            let sequence = ntcp::wire::parse(ip.ip, ip.payload)
                .unwrap()
                .header
                .sequence;
            let error = ntcp::NetworkError::HardUnreachable;
            assert!(
                a.endpoint
                    .network_error(a.now(), tuple, sequence, error)
                    .unwrap()
            );
            a.endpoint.release(cid).unwrap();
            a.remove_socket(client);
            let replacement = new(&mut a, SOCK_NONBLOCK);
            a.execute(replacement, Op::Bind(tuple.local)).unwrap();
            assert_eq!(
                a.execute(replacement, Op::Connect(tuple.remote))
                    .unwrap_err(),
                EINPROGRESS
            );
            let id = connection(&a, replacement);
            assert_ne!(id, cid);
            assert_eq!(a.endpoint.connection_id(tuple), Some(id));
            id
        });
        tick(&mut a);
        a.receive_batch(&mut [0; 65549]).unwrap();
        assert!(!a.egress.as_ref().unwrap().retained_rx(cid));
        if let Some(id) = replacement {
            assert_eq!(a.endpoint.state(id).unwrap(), ntcp::State::SynSent);
            assert_eq!(a.endpoint.received_ipv4_options(id).unwrap(), None);
        } else {
            // Recorded at arrival, not at any later pass: the replay
            // sampled no time and kept the value recorded then.
            let received = a.endpoint.received_ipv4_options(cid).unwrap();
            let time = arrival_time(received, arrival, utc_before, utc_after);
            assert_eq!(received, Some(recorded_once(time)));
            assert_eq!(a.ipv4_clock.acquisitions, 1);
            assert_eq!(
                a.execute(client, Op::Read(BYTES)).unwrap().bytes,
                b"retained options"
            );
        }
    }
}

#[test]
fn managed_native_timestamp_fallback_and_msgsize_rejection_reuse_the_attempt_ticket() {
    let (mut a, mut b, client, server, wa, wb) = pair_output(false, false, false);
    let cid = connection(&a, client);
    // Zero completion capacity: the requested timestamps fall back to a
    // plain transmission inside the same physical call.
    flags(
        &mut a,
        client,
        ts::TX_SOFTWARE | ts::TX_HARDWARE | ts::TX_ACK | ts::TX_SCHED,
    );
    let data: Vec<_> = (0..4000).map(|n| (n % 239) as u8).collect();
    a.execute(client, Op::Write(data.clone())).unwrap();
    {
        let mut wire = wa.lock().unwrap();
        wire.enforce_mtu = true;
        wire.mtu = Some(1000);
    }
    // EMSGSIZE certainly did not submit: the Endpoint retains the
    // reservation and its replacement attempt reuses the ticket.
    a.service_egress().unwrap();
    let rejected = wa.lock().unwrap().offered.clone();
    assert_eq!(rejected.len(), 1);
    assert!(wa.lock().unwrap().sent.is_empty());
    assert!(wa.lock().unwrap().requests.is_empty());
    assert_eq!(correlate(&a, &rejected[0]).matches, 0);
    assert!(a.endpoint.is_output_reserved(cid));
    budget(&mut a, cid, 1000, true);
    tick(&mut a);
    a.service_egress().unwrap();
    let sent: Vec<_> = wa.lock().unwrap().sent.iter().cloned().collect();
    assert!(!sent.is_empty());
    assert!(wa.lock().unwrap().requests.is_empty());
    // Within the refreshed budget, and leaving no ledger evidence.
    for frame in &sent {
        assert!(ip_size(frame) <= 1000);
        assert_eq!(correlate(&a, frame).matches, 0);
    }
    complete(&mut a, &mut b, &wa, &wb, cid, data.len());
    assert_eq!(b.execute(server, Op::Read(BYTES)).unwrap().bytes, data);
    eprintln!(
        "NATIVE_FALLBACK_MSGSIZE rejected_ip={} sent_after_refresh={} acknowledged={}",
        ip_size(&rejected[0]),
        sent.len(),
        data.len()
    );
}

// IP_PMTUDISC_DONT through production egress: every ordinary IPv4 packet is
// DF-clear with its own leased Identification, a PLPMTUD probe of the same
// connection keeps DF, and identifier backpressure (the per-tuple MDL
// ceiling) holds the reservation unsubmitted until an identifier can be
// issued.
#[test]
fn managed_dont_leases_identifiers_keeps_df_on_probes_and_holds_at_the_ceiling() {
    fn fields(frame: &[u8]) -> (bool, u16) {
        let ip = &ntcp_ethernet::parse_ethernet(frame).unwrap().payload[..20];
        (ip[6] & 0x40 != 0, u16::from_be_bytes([ip[4], ip[5]]))
    }
    let (mut a, mut b, client, server, wa, wb) = pair_output(false, false, false);
    let cid = connection(&a, client);
    let (source, destination) = (a.local, b.local);
    let lease = |a: &mut Owner| {
        let now = a.now();
        a.host
            .as_mut()
            .unwrap()
            .lease_identification(now, source, destination, 6)
    };
    let at = |a: &mut Owner, b: &mut Owner, time: u64| {
        a.test_now = Some(time);
        b.test_now = Some(time);
    };
    a.execute(client, Op::Set(IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT))
        .unwrap();
    a.execute(client, Op::Write(vec![1; 100])).unwrap();
    complete(&mut a, &mut b, &wa, &wb, cid, 100);
    assert_eq!(b.execute(server, Op::Read(400)).unwrap().bytes, vec![1; 100]);

    // A probe above a learned 1100 estimate keeps DF; ordinary packets
    // around it are DF-clear with distinct identifiers.
    budget(&mut a, cid, 1100, false);
    a.service_egress().unwrap();
    let hold = a
        .host
        .as_ref()
        .unwrap()
        .binding(cid)
        .unwrap()
        .snapshot
        .retry_not_before();
    let resume = hold.max(a.now());
    at(&mut a, &mut b, resume);
    a.execute(client, Op::Write(vec![6; 4000])).unwrap();
    complete(&mut a, &mut b, &wa, &wb, cid, 4100);
    b.execute(server, Op::Read(BYTES)).unwrap();
    a.execute(client, Op::Write(vec![7; 20000])).unwrap();
    wa.lock().unwrap().block = true;
    a.service_egress().unwrap();
    let attempt = a.egress.as_ref().unwrap().attempt(cid);
    a.endpoint
        .transmit_discovery_intent(attempt)
        .expect("actual native selected upward probe");
    let probe = wa.lock().unwrap().offered.last().unwrap().clone();
    assert!(ip_size(&probe) > 1100);
    assert_eq!(fields(&probe), (true, 0), "the probe is atomic: DF, Identification 0");
    wa.lock().unwrap().block = false;
    tick(&mut a);
    a.service_egress().unwrap();
    assert_eq!(wa.lock().unwrap().sent.front(), Some(&probe));
    transfer(&wa, &mut b, &wb);
    b.service_egress().unwrap();
    transfer(&wb, &mut a, &wa);
    complete(&mut a, &mut b, &wa, &wb, cid, 24100);
    assert_eq!(
        b.execute(server, Op::Read(BYTES)).unwrap().bytes,
        vec![7; 20000]
    );
    // Later probes of the same search are atomic too; everything else,
    // including every packet within the 1100 estimate, is DF-clear with its
    // own Identification.
    let mut identifiers = std::collections::HashSet::new();
    let mut ordinary = 0;
    for frame in wa.lock().unwrap().offered.iter() {
        let (df, identification) = fields(frame);
        if df {
            assert_eq!(identification, 0);
            assert!(ip_size(frame) > 1100, "only probes above the estimate keep DF");
            continue;
        }
        assert_ne!(identification, 0);
        assert!(identifiers.insert(identification), "one Identification per datagram");
        ordinary += 1;
    }
    assert!(ordinary > 3);

    // The ceiling: every value of the tuple is leased within the MDL.
    let retry_at = loop {
        match lease(&mut a) {
            Ok(_) => {}
            Err(ntcp_host::IdentifierBackpressure::Exhausted { retry_at }) => break retry_at,
            Err(other) => panic!("{other:?}"),
        }
    };
    wa.lock().unwrap().offered.clear();
    a.execute(client, Op::Write(vec![8; 100])).unwrap();
    tick(&mut a);
    a.service_egress().unwrap();
    assert!(wa.lock().unwrap().offered.is_empty(), "never a reused Identification");
    assert_eq!(
        a.egress.as_ref().unwrap().blocked(cid),
        Some(ntcp_host::Error::Capacity)
    );
    at(&mut a, &mut b, retry_at);
    complete(&mut a, &mut b, &wa, &wb, cid, 24200);
    assert_eq!(b.execute(server, Op::Read(400)).unwrap().bytes, vec![8; 100]);
    let (df, identification) = fields(&wa.lock().unwrap().offered[0]);
    assert!(!df && identification != 0);
}

// RFC 1191 section 6.6 through the native egress: after the owner disables
// discovery on the IPv4 route, every packet of a connection that never asked
// for IP_PMTUDISC_DONT (and then one that asks for IP_PMTUDISC_DO) leaves
// without DF, with its own leased Identification and a recomputed header
// checksum, within the 576-octet sending limit of the forwarder next hop.
#[test]
fn route_disable_clears_df_on_native_output_whatever_the_socket_requests() {
    use ntcp_host::path::{AdminChange, AdminPolicy, AdminTarget};
    let (mut a, mut b, client, server, wa, wb) = pair_output(false, false, false);
    let cid = connection(&a, client);
    let route = a.host.as_ref().unwrap().binding(cid).unwrap().snapshot.key().route();
    let host = a.host.as_mut().unwrap();
    let capability = host.administration();
    let expected = host
        .admin_routes(&capability)
        .unwrap()
        .find(|r| r.route == route)
        .unwrap()
        .generation;
    let now = a.now();
    let host = a.host.as_mut().unwrap();
    let candidate = host
        .admin_validate(
            &capability,
            now,
            AdminChange {
                target: AdminTarget::Route(route),
                expected,
                policy: AdminPolicy {
                    discovery_disabled: true,
                    estimate: None,
                },
            },
        )
        .unwrap();
    host.admin_apply(&capability, &mut a.endpoint, candidate).unwrap();
    a.execute(client, Op::Write(vec![1; 3000])).unwrap();
    complete(&mut a, &mut b, &wa, &wb, cid, 3000);
    a.execute(client, Op::Set(IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO))
        .unwrap();
    a.execute(client, Op::Write(vec![2; 3000])).unwrap();
    complete(&mut a, &mut b, &wa, &wb, cid, 6000);
    let mut received = b.execute(server, Op::Read(BYTES)).unwrap().bytes;
    while received.len() < 6000 {
        let more = b.execute(server, Op::Read(BYTES)).unwrap().bytes;
        assert!(!more.is_empty());
        received.extend(more);
    }
    assert_eq!(&received[..3000], &[1; 3000][..]);
    assert_eq!(&received[3000..], &[2; 3000][..]);
    let mut identifiers = std::collections::HashSet::new();
    let offered = wa.lock().unwrap().offered.clone();
    assert!(offered.len() > 10);
    for frame in &offered {
        let ip = ntcp_ethernet::parse_ethernet(frame).unwrap().payload;
        assert!(ip_size(frame) <= 576, "{}", ip_size(frame));
        assert_eq!(ip[6] & 0x40, 0, "DF clear");
        let header = usize::from(ip[0] & 0x0f) * 4;
        assert_eq!(ntcp_ip_common::checksum(&ip[..header]), 0);
        let identification = u16::from_be_bytes([ip[4], ip[5]]);
        assert_ne!(identification, 0);
        assert!(identifiers.insert(identification), "one Identification per packet");
    }
}

// The final bytes follow the decision current at each submission: a packet
// rewritten DF clear (with a leased Identification) while the route was
// disabled, whose submission the backend refused with WouldBlock, leaves
// after the owner re-enables discovery with the atomic header (DF set,
// Identification 0, valid checksum). A connection that asked for
// IP_PMTUDISC_DONT keeps DF clear across the same sequence.
#[test]
fn held_df_clear_packet_follows_a_reenable_unless_the_socket_asks_for_dont() {
    use ntcp_host::path::{AdminChange, AdminPolicy, AdminTarget};
    fn set_route(a: &mut Owner, cid: ConnectionId, discovery_disabled: bool) {
        let route = a.host.as_ref().unwrap().binding(cid).unwrap().snapshot.key().route();
        let now = a.now();
        let host = a.host.as_mut().unwrap();
        let capability = host.administration();
        let expected = host
            .admin_routes(&capability)
            .unwrap()
            .find(|r| r.route == route)
            .unwrap()
            .generation;
        let candidate = host
            .admin_validate(
                &capability,
                now,
                AdminChange {
                    target: AdminTarget::Route(route),
                    expected,
                    policy: AdminPolicy {
                        discovery_disabled,
                        estimate: None,
                    },
                },
            )
            .unwrap();
        host.admin_apply(&capability, &mut a.endpoint, candidate)
            .unwrap();
    }
    fn header(frame: &[u8]) -> Vec<u8> {
        let ip = ntcp_ethernet::parse_ethernet(frame).unwrap().payload;
        ip[..usize::from(ip[0] & 0x0f) * 4].to_vec()
    }
    for dont in [false, true] {
        let (mut a, mut b, client, server, wa, wb) = pair_output(false, false, false);
        let cid = connection(&a, client);
        if dont {
            a.execute(client, Op::Set(IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT))
                .unwrap();
        }
        set_route(&mut a, cid, true);
        wa.lock().unwrap().block = true;
        a.execute(client, Op::Write(vec![3; 400])).unwrap();
        a.service_egress().unwrap();
        assert!(wa.lock().unwrap().sent.is_empty());
        let blocked = header(wa.lock().unwrap().offered.last().unwrap());
        let identification = u16::from_be_bytes([blocked[4], blocked[5]]);
        assert_eq!(blocked[6] & 0x40, 0, "offered DF clear while disabled");
        assert_ne!(identification, 0);
        assert!(a.endpoint.is_output_reserved(cid));
        set_route(&mut a, cid, false);
        wa.lock().unwrap().block = false;
        tick(&mut a);
        a.service_egress().unwrap();
        let sent = header(wa.lock().unwrap().sent.front().unwrap());
        assert_eq!(ntcp_ip_common::checksum(&sent), 0, "valid header checksum");
        if dont {
            assert_eq!(sent[6] & 0x40, 0, "IP_PMTUDISC_DONT keeps DF clear");
            assert_ne!(u16::from_be_bytes([sent[4], sent[5]]), 0);
        } else {
            assert_ne!(sent[6] & 0x40, 0, "DF set on the enabled route");
            assert_eq!(u16::from_be_bytes([sent[4], sent[5]]), 0, "atomic Identification");
        }
        complete(&mut a, &mut b, &wa, &wb, cid, 400);
        assert_eq!(b.execute(server, Op::Read(1000)).unwrap().bytes, vec![3; 400]);
    }
}
