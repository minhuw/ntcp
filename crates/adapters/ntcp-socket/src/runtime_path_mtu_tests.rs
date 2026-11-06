// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// IP_MTU and IPV6_MTU on managed native sockets report the bound path's
// shared estimate (PathSnapshot::pmtu_estimate), as Linux reports dst_mtu.
use super::*;
use ntcp_host::path::{AdminChange, AdminPolicy, AdminTarget};

fn ip_mtu(owner: &mut Owner, socket: u64) -> Result<i32> {
    let option = if owner.local.is_ipv4() {
        (IPPROTO_IP, IP_MTU)
    } else {
        (IPPROTO_IPV6, IPV6_MTU)
    };
    owner
        .execute(socket, Op::Get(option.0, option.1))
        .map(|reply| reply.value)
}
fn maxseg(owner: &mut Owner, socket: u64) -> i32 {
    owner
        .execute(socket, Op::Get(IPPROTO_TCP, TCP_MAXSEG))
        .unwrap()
        .value
}
fn estimate(owner: &Owner, cid: ConnectionId) -> u32 {
    let host = owner.host.as_ref().unwrap();
    let path = host.binding(cid).unwrap().snapshot.path();
    host.paths()
        .path_snapshot(path)
        .unwrap()
        .pmtu_estimate()
        .unwrap()
}
// Transport state, apart from the elapsed time since data last arrived,
// which every operation's clock reading advances.
fn transport(owner: &Owner, cid: ConnectionId) -> ntcp::TransportInfo {
    let mut info = owner.endpoint.transport_info(cid).unwrap();
    info.last_data_recv_ms = 0;
    info
}
// A query changes no transport, binding or notification state.
fn query_is_pure(owner: &mut Owner, socket: u64) -> i32 {
    let cid = connection(owner, socket);
    let host = owner.host.as_ref().unwrap();
    let binding = host.binding(cid).unwrap();
    let before = (
        transport(owner, cid),
        owner.endpoint.path_mtu_info(cid).unwrap(),
        binding.client,
        binding.snapshot,
        host.paths().is_dirty(binding.client).unwrap(),
    );
    let value = ip_mtu(owner, socket).unwrap();
    let host = owner.host.as_ref().unwrap();
    let binding = host.binding(cid).unwrap();
    let after = (
        transport(owner, cid),
        owner.endpoint.path_mtu_info(cid).unwrap(),
        binding.client,
        binding.snapshot,
        host.paths().is_dirty(binding.client).unwrap(),
    );
    assert_eq!(before, after);
    value
}
// A further connection from `a` to `b`'s listener, connecting: it is
// bound to its path from connect.
fn connecting(a: &mut Owner, b: &Owner, options: &[(i32, i32, i32)]) -> u64 {
    let client = new(a, SOCK_NONBLOCK);
    for &(level, name, value) in options {
        a.execute(client, Op::Set(level, name, value)).unwrap();
    }
    assert_eq!(
        a.execute(client, Op::Connect(SocketAddr::new(b.local, 8080)))
            .unwrap_err(),
        EINPROGRESS
    );
    client
}
// The same, established.
fn another(a: &mut Owner, b: &mut Owner, wa: &Wire, wb: &Wire) -> u64 {
    let client = connecting(a, b, &[]);
    client_established(a, b, wa, wb, client);
    client
}
fn client_established(a: &mut Owner, b: &mut Owner, wa: &Wire, wb: &Wire, client: u64) {
    for _ in 0..4 {
        tick(a);
        tick(b);
        flush(a, b, wa);
        tick(a);
        tick(b);
        flush(b, a, wb);
    }
    assert_eq!(
        a.endpoint.state(connection(a, client)),
        Ok(ntcp::State::Established)
    );
}
fn route_policy(a: &mut Owner, cid: ConnectionId, policy: AdminPolicy) {
    let route = a
        .host
        .as_ref()
        .unwrap()
        .binding(cid)
        .unwrap()
        .snapshot
        .key()
        .route();
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
                policy,
            },
        )
        .unwrap();
    host.admin_apply(&capability, &mut a.endpoint, candidate)
        .unwrap();
}

// A router's correlated Packet Too Big lowers the shared estimate: the
// quoted connection reports it at once, before any change service, and a
// later connection to the same destination reports it from its first query,
// whatever its own discovery state starts at. TCP_MAXSEG stays the
// connection's segment size, below the estimate by the headers.
#[test]
fn ip_mtu_reports_the_shared_estimate_a_correlated_ptb_lowered() {
    for v6 in [false, true] {
        let (mut a, mut b, client, server, wa, wb) = pair_output(v6, false, false);
        let cid = connection(&a, client);
        assert_eq!(query_is_pure(&mut a, client), 1500);
        assert_eq!(ip_mtu(&mut b, server).unwrap(), 1500);
        let data: Vec<_> = (0..7000).map(|n| (n % 241) as u8).collect();
        a.execute(client, Op::Write(data.clone())).unwrap();
        tick(&mut a);
        a.service_egress().unwrap();
        let first = wa.lock().unwrap().sent[0].clone();
        assert!(ip_size(&first) > 1300);
        let mtu = if v6 { 1280 } else { 1000 };
        wa.lock()
            .unwrap()
            .incoming
            .push_back(Ok(router_ptb(&first, mtu)));
        a.receive_batch(&mut [0; 65549]).unwrap();
        assert_eq!(estimate(&a, cid), mtu);
        assert_eq!(query_is_pure(&mut a, client), mtu as i32);
        let mss = maxseg(&mut a, client);
        assert!(mss <= mtu as i32 - if v6 { 60 } else { 40 });
        // The peer's own path is not this host's.
        assert_eq!(ip_mtu(&mut b, server).unwrap(), 1500);
        // A new connection on the same path: its first query, before any
        // output or change service, and once established.
        let later = connecting(&mut a, &b, &[]);
        let later_cid = connection(&a, later);
        assert_eq!(
            a.host
                .as_ref()
                .unwrap()
                .binding(later_cid)
                .unwrap()
                .snapshot
                .path(),
            a.host
                .as_ref()
                .unwrap()
                .binding(cid)
                .unwrap()
                .snapshot
                .path()
        );
        assert_eq!(query_is_pure(&mut a, later), mtu as i32);
        client_established(&mut a, &mut b, &wa, &wb, later);
        assert_eq!(query_is_pure(&mut a, later), mtu as i32);
        assert!(maxseg(&mut a, later) < mtu as i32);
        complete(&mut a, &mut b, &wa, &wb, cid, data.len());
        assert_eq!(b.execute(server, Op::Read(BYTES)).unwrap().bytes, data);
        assert_eq!(ip_mtu(&mut a, client).unwrap(), mtu as i32);
    }
}

// An owner's administrative estimate below the network estimate is the
// path's estimate for existing and new sockets alike.
#[test]
fn ip_mtu_reports_an_administrative_decrease_to_existing_and_new_sockets() {
    for v6 in [false, true] {
        let (mut a, mut b, client, _, wa, wb) = pair_output(v6, false, false);
        let cid = connection(&a, client);
        let value = if v6 { 1300 } else { 1200 };
        route_policy(
            &mut a,
            cid,
            AdminPolicy {
                discovery_disabled: false,
                estimate: Some(value),
            },
        );
        assert_eq!(estimate(&a, cid), value);
        assert_eq!(query_is_pure(&mut a, client), value as i32);
        let later = another(&mut a, &mut b, &wa, &wb);
        assert_eq!(query_is_pure(&mut a, later), value as i32);
        assert!(maxseg(&mut a, later) < value as i32);
    }
}

// Disabling discovery on the route changes the sending budget (IPv6: 1280
// octets), not the path's estimate, and a socket that asks for
// IP_PMTUDISC_DONT or IPV6_PMTUDISC_DONT still reports the path's estimate,
// including a shared decrease.
#[test]
fn ip_mtu_of_discovery_disabled_sockets_and_routes_is_the_estimate_not_the_budget() {
    for v6 in [false, true] {
        let (mut a, b, client, _, _, _) = pair_output(v6, false, false);
        let cid = connection(&a, client);
        route_policy(
            &mut a,
            cid,
            AdminPolicy {
                discovery_disabled: true,
                estimate: None,
            },
        );
        let snapshot = a.host.as_ref().unwrap().binding(cid).unwrap().snapshot;
        assert!(snapshot.discovery_disabled());
        // IPv4 through the fixture's forwarder sends at most 576 octets,
        // IPv6 at most 1280.
        assert_eq!(snapshot.ip_packet_budget(), Ok(if v6 { 1280 } else { 576 }));
        assert_eq!(query_is_pure(&mut a, client), 1500);
        // Connecting already binds the path (an IPv4 DF-clear SYN may still
        // wait for the identifier quiet period).
        let later = connecting(&mut a, &b, &[]);
        assert_eq!(query_is_pure(&mut a, later), 1500);
        route_policy(
            &mut a,
            cid,
            AdminPolicy {
                discovery_disabled: false,
                estimate: None,
            },
        );
        let (level, option) = if v6 {
            (IPPROTO_IPV6, IPV6_MTU_DISCOVER)
        } else {
            (IPPROTO_IP, IP_MTU_DISCOVER)
        };
        let dont = connecting(&mut a, &b, &[(level, option, IP_PMTUDISC_DONT)]);
        assert_eq!(query_is_pure(&mut a, dont), 1500);
        let dont_cid = connection(&a, dont);
        budget(&mut a, dont_cid, 1280, false);
        assert_eq!(query_is_pure(&mut a, dont), 1280);
        assert_eq!(query_is_pure(&mut a, client), 1280);
    }
}

// A binding the next refresh moves reads the path that selection names,
// without being refreshed; with no incarnation of that selection yet it
// reads the path it is still bound to.
#[test]
fn ip_mtu_of_a_stale_binding_reads_the_selection_refresh_would_use() {
    for v6 in [false, true] {
        let (mut a, mut b, client, _, wa, wb) = pair_output(v6, false, false);
        let sibling = another(&mut a, &mut b, &wa, &wb);
        let (cid, sibling_cid) = (connection(&a, client), connection(&a, sibling));
        let old = a.host.as_ref().unwrap().binding(cid).unwrap();
        let route = old.snapshot.key().route();
        let host = a.host.as_mut().unwrap();
        let definition = host.paths().route(route).unwrap();
        host.replace_route(route, definition).unwrap();
        // No incarnation of the new selection exists yet.
        assert_eq!(query_is_pure(&mut a, client), 1500);
        let host = a.host.as_mut().unwrap();
        let moved = host.refresh(&mut a.endpoint, sibling_cid).unwrap();
        assert_ne!(moved.snapshot.path(), old.snapshot.path());
        let now = a.now();
        let host = a.host.as_mut().unwrap();
        host.trusted_decrease(now, moved.snapshot.path(), 1280)
            .unwrap();
        // The client is still bound to the replaced path.
        assert_eq!(
            a.host
                .as_ref()
                .unwrap()
                .binding(cid)
                .unwrap()
                .snapshot
                .path(),
            old.snapshot.path()
        );
        assert_eq!(query_is_pure(&mut a, client), 1280);
        assert_eq!(query_is_pure(&mut a, sibling), 1280);
    }
}

// Only a connected socket has a path.
#[test]
fn ip_mtu_of_an_unconnected_managed_socket_is_enotconn() {
    for v6 in [false, true] {
        let (mut a, _) = native_output(v6, 2, 4, 1500, false, false);
        let fresh = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(ip_mtu(&mut a, fresh).unwrap_err(), ENOTCONN);
        let listen = listener(&mut a);
        assert_eq!(ip_mtu(&mut a, listen).unwrap_err(), ENOTCONN);
    }
}

// The connection's own PLPMTUD black-hole fallback (repeated timeouts, no
// ICMP) lowers only its packet size: the path's estimate, and so IP_MTU and
// IPV6_MTU of this and a later socket, stay where no evidence moved them.
#[test]
fn ip_mtu_never_reports_connection_local_black_hole_fallback() {
    for v6 in [false, true] {
        let (mut a, b, client, _, wa, _) = pair_output(v6, false, false);
        let cid = connection(&a, client);
        let data: Vec<_> = (0..7000).map(|n| (n % 239) as u8).collect();
        a.execute(client, Op::Write(data)).unwrap();
        tick(&mut a);
        a.service_egress().unwrap();
        assert!(!wa.lock().unwrap().sent.is_empty());
        // Every transmission is lost without any ICMP.
        for _ in 0..12 {
            wa.lock().unwrap().sent.clear();
            if a.endpoint.path_mtu_info(cid).unwrap().unwrap().current_mtu < 1500 {
                break;
            }
            let deadline = a.endpoint.next_deadline().unwrap();
            a.test_now = Some(deadline);
            a.endpoint.on_timeout(deadline, BUDGET).unwrap();
            a.service_egress().unwrap();
        }
        let local = a.endpoint.path_mtu_info(cid).unwrap().unwrap().current_mtu;
        assert!(local < 1500, "no black-hole fallback: {local}");
        assert_eq!(estimate(&a, cid), 1500);
        assert_eq!(query_is_pure(&mut a, client), 1500);
        let later = connecting(&mut a, &b, &[]);
        assert_eq!(query_is_pure(&mut a, later), 1500);
    }
}

// A Packet Too Big that quotes no packet this host submitted (a forged
// sequence) changes neither the path's estimate nor the readback.
#[test]
fn ip_mtu_ignores_a_packet_too_big_quoting_no_submission() {
    for v6 in [false, true] {
        let (mut a, _, client, _, wa, _) = pair_output(v6, false, false);
        let cid = connection(&a, client);
        let data: Vec<_> = (0..7000).map(|n| (n % 233) as u8).collect();
        a.execute(client, Op::Write(data)).unwrap();
        tick(&mut a);
        a.service_egress().unwrap();
        let mut forged = wa.lock().unwrap().sent[0].clone();
        assert!(ip_size(&forged) > 1300);
        // TCP sequence number, well outside anything sent.
        let seq = 14 + if v6 { 40 } else { 20 } + 4;
        let value = u32::from_be_bytes(forged[seq..seq + 4].try_into().unwrap());
        forged[seq..seq + 4].copy_from_slice(&value.wrapping_add(0x4000_0000).to_be_bytes());
        let mtu = if v6 { 1280 } else { 1000 };
        wa.lock()
            .unwrap()
            .incoming
            .push_back(Ok(router_ptb(&forged, mtu)));
        a.receive_batch(&mut [0; 65549]).unwrap();
        assert_eq!(estimate(&a, cid), 1500);
        assert_eq!(query_is_pure(&mut a, client), 1500);
    }
}

// A lower first-hop link MTU is part of the path's estimate (Linux's
// dst_mtu follows the device), for existing and new sockets.
#[test]
fn ip_mtu_reports_a_lower_first_hop_link_mtu() {
    for v6 in [false, true] {
        let (mut a, mut b, client, _, wa, wb) = pair_output(v6, false, false);
        let cid = connection(&a, client);
        let mtu = if v6 { 1280 } else { 1100 };
        budget(&mut a, cid, mtu, true);
        tick(&mut a);
        a.service_egress().unwrap();
        assert_eq!(query_is_pure(&mut a, client), mtu as i32);
        let later = another(&mut a, &mut b, &wa, &wb);
        assert_eq!(query_is_pure(&mut a, later), mtu as i32);
    }
}

// With its route removed and no other route to the destination, the
// connection is still bound to its last applied path: it reports that
// path's estimate (Linux's cached route), the router's decrease included,
// without being refreshed.
#[test]
fn ip_mtu_of_a_binding_whose_route_was_removed_reads_its_bound_path() {
    for v6 in [false, true] {
        let (mut a, _, client, _, wa, _) = pair_output(v6, false, false);
        let cid = connection(&a, client);
        let data: Vec<_> = (0..7000).map(|n| (n % 229) as u8).collect();
        a.execute(client, Op::Write(data)).unwrap();
        tick(&mut a);
        a.service_egress().unwrap();
        let first = wa.lock().unwrap().sent[0].clone();
        let mtu = if v6 { 1280 } else { 1000 };
        wa.lock()
            .unwrap()
            .incoming
            .push_back(Ok(router_ptb(&first, mtu)));
        a.receive_batch(&mut [0; 65549]).unwrap();
        assert_eq!(query_is_pure(&mut a, client), mtu as i32);
        let old = a.host.as_ref().unwrap().binding(cid).unwrap();
        let route = old.snapshot.key().route();
        a.host.as_mut().unwrap().remove_route(route).unwrap();
        assert_eq!(query_is_pure(&mut a, client), mtu as i32);
        assert_eq!(
            a.host
                .as_ref()
                .unwrap()
                .binding(cid)
                .unwrap()
                .snapshot
                .path(),
            old.snapshot.path()
        );
    }
}
