// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;
use crate::runtime::tests::{new, pair, pump};
use std::sync::{Arc, Mutex};

#[test]
fn entropy_completion_interrupt_short_failure_and_zero_progress() {
    let mut bytes = [0xa5; 32];
    let mut calls = 0;
    fill_with(&mut bytes, |out| {
        calls += 1;
        match calls {
            1 | 3 => Err(EINTR),
            2 => {
                assert_eq!(out.len(), 32);
                out[..3].copy_from_slice(&[1, 2, 3]);
                Ok(3)
            }
            4 => {
                assert_eq!(out.len(), 29);
                out.fill(4);
                Ok(out.len())
            }
            _ => panic!("read after completion"),
        }
    })
    .unwrap();
    assert_eq!(&bytes[..3], &[1, 2, 3]);
    assert_eq!(&bytes[3..], &[4; 29]);
    assert_eq!(calls, 4);
    for result in [Err(EPERM), Err(ENOSYS), Ok(0), Ok(33)] {
        let mut calls = 0;
        assert_eq!(
            fill_with(&mut bytes, |_| {
                calls += 1;
                if calls == 1 { Ok(1) } else { result }
            }),
            Err(result.err().unwrap_or(EIO))
        );
        assert_eq!(calls, 2);
    }
    fill_with(&mut [], |_| panic!("empty read")).unwrap();
    // Smoke the real syscall and startup wrapper, without a probabilistic claim.
    fill(&mut bytes).unwrap();
    random_secret().unwrap();
}

#[derive(Default)]
struct Wire(VecDeque<Vec<u8>>);
struct Io(Arc<Mutex<Wire>>);
impl PacketIo for Io {
    fn layer(&self) -> ntcp_io::PacketLayer {
        ntcp_io::PacketLayer::Ethernet
    }
    fn local_ip_mtu(&self) -> std::io::Result<Option<u32>> {
        Ok(Some(1500))
    }
    fn max_packet_len(&self) -> Option<usize> {
        Some(2048)
    }
    fn receive(&mut self, _: &mut [u8]) -> std::io::Result<Option<usize>> {
        Ok(None)
    }
    fn transmit(&mut self, bytes: &[u8]) -> std::io::Result<TxOutcome> {
        self.0.lock().unwrap().0.push_back(bytes.to_vec());
        Ok(TxOutcome::Submitted)
    }
}
fn external(v6: bool, last: u8) -> (Owner, Arc<Mutex<Wire>>) {
    let local: IpAddr = if v6 {
        format!("2001:db8::{last}")
    } else {
        format!("10.73.0.{last}")
    }
    .parse()
    .unwrap();
    let mut config = SocketConfig::new("external", local);
    config.io.prefix = Some(if v6 { 64 } else { 24 });
    config.tcp.connection.timestamps = false;
    config.tcp.connection.delayed_ack_us = 0;
    let wire = Arc::new(Mutex::new(Wire::default()));
    let mut owner = Owner::external_backend(
        &config,
        crate::EthernetPacketIo {
            io: Box::new(Io(wire.clone())),
            local_mac: [2; 6],
            next_hop_mac: Some([4; 6]),
        },
    )
    .unwrap();
    owner.test_now = Some(0);
    (owner, wire)
}
fn deliver(
    from: &mut Owner,
    to: &mut Owner,
    wire: &Arc<Mutex<Wire>>,
) -> Vec<(SocketAddr, SocketAddr, Vec<u8>)> {
    from.service_egress().unwrap();
    let mut seen = Vec::new();
    while let Some(frame) = wire.lock().unwrap().0.pop_front() {
        let eth = ntcp_ethernet::parse_ethernet(&frame).unwrap();
        let ip = crate::ip::parse(eth.payload).unwrap();
        let tcp = ntcp::wire::parse(ip.ip, ip.payload).unwrap();
        seen.push((
            SocketAddr::new(ip.ip.source, tcp.header.source_port),
            SocketAddr::new(ip.ip.destination, tcp.header.destination_port),
            tcp.payload.to_vec(),
        ));
        to.input_ip_metadata(eth.payload, Default::default(), None);
    }
    from.events();
    to.events();
    seen
}
fn exchange(a: &mut Owner, b: &mut Owner, wa: &Arc<Mutex<Wire>>, wb: &Arc<Mutex<Wire>>) {
    for _ in 0..16 {
        let x = deliver(a, b, wa);
        let y = deliver(b, a, wb);
        if x.is_empty() && y.is_empty() {
            return;
        }
    }
    panic!("wire did not quiesce");
}
fn name(o: &mut Owner, id: u64) -> SocketAddr {
    o.execute(id, Op::Name(false)).unwrap().addr.unwrap()
}
fn connection(o: &Owner, id: u64) -> ConnectionId {
    let Handle::Connection(cid) = o.sockets[&id].handle else {
        panic!()
    };
    cid
}

// The users `port_index` counts, from a pass over the sockets and the
// connections' options: what each lookup stands for.
fn check_index(owner: &Owner) {
    let mut ports: Vec<u16> = owner
        .sockets
        .values()
        .filter_map(|s| s.local.map(|l| l.port()))
        .chain(owner.connection_options.iter().map(|p| p.4.port()))
        .collect();
    ports.extend([owner.ephemeral_ports.start(), owner.ephemeral_ports.end()].map(|p| *p));
    for port in ports {
        let mut users = [0u16; 4];
        for s in owner.sockets.values() {
            if s.local.is_some_and(|l| l.port() == port) {
                users[s.binding as usize] += 1;
            }
        }
        for p in &owner.connection_options {
            if p.4.port() == port {
                users[2 + p.5 as usize] += 1;
            }
        }
        assert_eq!(owner.port_index.users(port), users, "port {port}");
    }
    let deferred = owner
        .sockets
        .values()
        .filter(|s| s.deferred_peer.is_some())
        .count();
    assert_eq!(owner.port_index.deferred_tuples(), deferred);
}
fn remote(v6: bool, last: u8, port: u16) -> SocketAddr {
    SocketAddr::new(
        if v6 {
            format!("2001:db8::{last}")
        } else {
            format!("10.73.0.{last}")
        }
        .parse()
        .unwrap(),
        port,
    )
}
fn connect(o: &mut Owner, to: SocketAddr) -> Result<u64> {
    let id = new(o, SOCK_NONBLOCK);
    match o.execute(id, Op::Connect(to)) {
        Err(EINPROGRESS) => Ok(id),
        Err(e) => {
            o.execute(id, Op::Close).unwrap();
            Err(e)
        }
        Ok(_) => panic!("a nonblocking connect completed at once"),
    }
}
// A client in TIME-WAIT, its connection a record of the endpoint's, the
// socket closed: the record holds (local, the server's listener). `reuse`
// sets the client's SO_REUSEADDR first.
fn time_wait_record(reuse: bool) -> (Owner, Owner, SocketAddr, SocketAddr) {
    let (mut a, mut b, client, server, _) = pair();
    a.test_now = Some(a.now());
    b.test_now = Some(b.now());
    a.execute(client, Op::Set(SOL_SOCKET, SO_REUSEADDR, reuse as i32))
        .unwrap();
    let cid = connection(&a, client);
    let local = name(&mut a, client);
    let peer = a.endpoint.tuple(cid).unwrap().remote;
    a.execute(client, Op::Close).unwrap();
    pump(&mut a, &mut b);
    b.execute(server, Op::Close).unwrap();
    pump(&mut a, &mut b);
    assert_eq!(a.endpoint.state(cid), Ok(State::TimeWait));
    // The owner loop releases a detached connection once in TIME-WAIT.
    a.endpoint.release(cid).unwrap();
    a.collect_connection_options();
    assert!(!a.endpoint.connection_exists(cid));
    assert!(a.endpoint.time_wait_holds_port(local.port()));
    check_index(&a);
    (a, b, local, peer)
}

// These full Informational recommendations are evidenced by the keyed
// Algorithm 4 selection (ntcp::EphemeralPorts) and the live socket paths.
// No distribution test is used as evidence of cryptographic unpredictability.
//= https://www.rfc-editor.org/rfc/rfc5927#section-4.2
//= type=test
//# As discussed in the previous sections, in order to perform any of the attacks described in this document, an attacker would need to guess (or know) the four-tuple that identifies the connection to be attacked. Increasing the port number range used for outgoing TCP connections, and randomizing the port number chosen for each outgoing TCP connection, would make it harder for an attacker to perform any of the attacks discussed in this document.
//= https://www.rfc-editor.org/rfc/rfc5927#section-4.2
//= type=test
//# [PORT-RANDOM] recommends that transport protocols randomize the ephemeral ports used by clients, and proposes a number of randomization algorithms.
// bind(0), an implicit listen, connect and a deferred Fast Open connect
// take ports of Linux's range, on the wire as named; a connect skips the
// ports bind() took, and the deferred connect holds its tuple before it
// sends a SYN.
#[test]
fn native_auto_ports_bind_listen_connect_and_deferred_fast_open() {
    for v6 in [false, true] {
        let (mut a, wa) = external(v6, 2);
        let (mut b, wb) = external(v6, 3);
        let bound = new(&mut a, SOCK_NONBLOCK);
        let bind_ip = a.local;
        a.execute(bound, Op::Bind(SocketAddr::new(bind_ip, 0)))
            .unwrap();
        let bound_port = name(&mut a, bound).port();
        assert!(ports::RANGE.contains(&bound_port));
        let listener_a = new(&mut a, SOCK_NONBLOCK);
        a.execute(listener_a, Op::Listen(4)).unwrap();
        let listen_port = name(&mut a, listener_a).port();
        assert!(ports::RANGE.contains(&listen_port) && listen_port != bound_port);
        let listener_b = new(&mut b, SOCK_NONBLOCK);
        b.execute(listener_b, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 4))
            .unwrap();
        b.execute(listener_b, Op::Listen(4)).unwrap();
        let remote = SocketAddr::new(b.local, name(&mut b, listener_b).port());
        // Neither the bound port nor the listener's is a connect's.
        for port in [bound_port, listen_port] {
            a.ephemeral_ports = port..=port;
            assert_eq!(connect(&mut a, remote), Err(EADDRNOTAVAIL));
        }
        a.ephemeral_ports = ports::RANGE;
        let client = connect(&mut a, remote).unwrap();
        let local = name(&mut a, client);
        assert!(ports::RANGE.contains(&local.port()));
        assert!(![bound_port, listen_port].contains(&local.port()));
        assert_eq!(
            a.endpoint.tuple(connection(&a, client)).unwrap().local,
            local
        );
        let syn = deliver(&mut a, &mut b, &wa);
        assert_eq!((syn[0].0, syn[0].1), (local, remote));
        exchange(&mut a, &mut b, &wa, &wb);
        a.execute(client, Op::FinishConnect).unwrap();
        let server = b
            .execute(listener_b, Op::Accept(SOCK_NONBLOCK))
            .unwrap()
            .value as u64;
        assert_eq!(
            b.execute(server, Op::Name(true)).unwrap().addr.unwrap(),
            local
        );
        a.execute(client, Op::Write(b"native request".to_vec()))
            .unwrap();
        exchange(&mut a, &mut b, &wa, &wb);
        assert_eq!(
            b.execute(server, Op::Read(32)).unwrap().bytes,
            b"native request"
        );
        // bind(0) skips the connected socket's port, as every used one.
        a.ephemeral_ports = local.port()..=local.port() + 1;
        let second = new(&mut a, SOCK_NONBLOCK);
        a.execute(second, Op::Bind(SocketAddr::new(bind_ip, 0)))
            .unwrap();
        assert_eq!(name(&mut a, second).port(), local.port() + 1);
        let third = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(third, Op::Bind(SocketAddr::new(bind_ip, 0)))
                .unwrap_err(),
            EADDRINUSE
        );
        a.ephemeral_ports = ports::RANGE;
        let warm = new(&mut a, SOCK_NONBLOCK);
        a.execute(warm, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
            .unwrap();
        assert_eq!(
            a.execute(warm, Op::Connect(remote)).unwrap_err(),
            EINPROGRESS
        );
        exchange(&mut a, &mut b, &wa, &wb);
        b.execute(listener_b, Op::Accept(SOCK_NONBLOCK)).unwrap();
        assert!(
            a.endpoint
                .has_fast_open_cookie(a.now(), a.local, b.local)
                .unwrap()
        );
        let deferred = new(&mut a, SOCK_NONBLOCK);
        a.execute(deferred, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
            .unwrap();
        a.execute(deferred, Op::Connect(remote)).unwrap();
        let deferred_local = name(&mut a, deferred);
        assert!(ports::RANGE.contains(&deferred_local.port()));
        assert!(matches!(a.sockets[&deferred].handle, Handle::Fresh));
        assert!(deliver(&mut a, &mut b, &wa).is_empty());
        check_index(&a);
        // The deferred connect's tuple is taken: no other connect to the
        // destination gets its port, though one elsewhere may.
        a.ephemeral_ports = deferred_local.port()..=deferred_local.port();
        assert_eq!(connect(&mut a, remote), Err(EADDRNOTAVAIL));
        let elsewhere = connect(&mut a, SocketAddr::new(b.local, remote.port() + 1)).unwrap();
        assert_eq!(name(&mut a, elsewhere).port(), deferred_local.port());
        a.execute(elsewhere, Op::Close).unwrap();
        a.ephemeral_ports = ports::RANGE;
        let early = b"fast open";
        a.execute(
            deferred,
            Op::Send(vec![(early.as_ptr() as usize, early.len())], 0),
        )
        .unwrap();
        let syn = deliver(&mut a, &mut b, &wa);
        assert_eq!((syn[0].0, syn[0].1), (deferred_local, remote));
        assert_eq!(syn[0].2, b"fast open");
        exchange(&mut a, &mut b, &wa, &wb);
        let child = b
            .execute(listener_b, Op::Accept(SOCK_NONBLOCK))
            .unwrap()
            .value as u64;
        assert_eq!(b.execute(child, Op::Read(32)).unwrap().bytes, b"fast open");
        check_index(&a);
        check_index(&b);
    }
}

// RFC 6056 Algorithm 4 as Linux's __inet_hash_connect: a port is shared by
// connects to distinct destinations, never twice to one, and runs out per
// destination only.
//= https://www.rfc-editor.org/rfc/rfc6056#section-3.3.4
//= type=test
//# The array "table[]" assures that successive transport-protocol
//# instances with the same remote endpoint will use increasing ephemeral
//# port numbers.
#[test]
fn connects_share_ports_across_destinations_and_exhaust_per_destination() {
    for v6 in [false, true] {
        let (mut a, _) = external(v6, 2);
        a.ephemeral_ports = 40000..=40003;
        let first = remote(v6, 3, 80);
        let mut taken: Vec<u16> = (0..4)
            .map(|_| {
                let id = connect(&mut a, first).unwrap();
                name(&mut a, id).port()
            })
            .collect();
        // One destination takes each port once, then has none.
        assert_eq!(connect(&mut a, first), Err(EADDRNOTAVAIL));
        taken.sort_unstable();
        assert_eq!(taken, [40000, 40001, 40002, 40003]);
        // Other destinations, another address or another port, share them.
        for other in [remote(v6, 4, 80), remote(v6, 3, 81)] {
            for _ in 0..4 {
                connect(&mut a, other).unwrap();
            }
            assert_eq!(connect(&mut a, other), Err(EADDRNOTAVAIL));
        }
        assert_eq!(a.connection_options.len(), 12);
        check_index(&a);
    }
}

// A connect does not take a port bind() or listen took, for any
// destination, nor a 4-tuple a connection already has.
#[test]
fn connects_skip_bound_and_listening_ports() {
    let (mut a, _) = external(false, 2);
    a.ephemeral_ports = 40000..=40001;
    let bound = new(&mut a, SOCK_NONBLOCK);
    a.execute(bound, Op::Bind(SocketAddr::new(a.local, 40000)))
        .unwrap();
    let listener = new(&mut a, SOCK_NONBLOCK);
    a.execute(listener, Op::Bind(SocketAddr::new(a.local, 40001)))
        .unwrap();
    a.execute(listener, Op::Listen(4)).unwrap();
    assert_eq!(connect(&mut a, remote(false, 3, 80)), Err(EADDRNOTAVAIL));
    a.execute(bound, Op::Close).unwrap();
    let id = connect(&mut a, remote(false, 3, 80)).unwrap();
    assert_eq!(name(&mut a, id).port(), 40000);
    assert_eq!(connect(&mut a, remote(false, 3, 80)), Err(EADDRNOTAVAIL));
    // bind() cannot take a port a connect holds (no SO_REUSEADDR).
    let rebind = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(rebind, Op::Bind(SocketAddr::new(a.local, 40000)))
            .unwrap_err(),
        EADDRINUSE
    );
    check_index(&a);
}

// Each destination starts at an offset of its own, a keyed hash of the
// endpoint's secret: another secret gives other ports.
//= https://www.rfc-editor.org/rfc/rfc6056#section-3.3.3
//= type=test
//# The function should use both IP addresses, the remote
//# port, and a secret key value to compute the offset.
#[test]
fn each_destination_starts_at_its_own_secret_offset() {
    let firsts = |secret: u8| -> Vec<u16> {
        let mut config = SocketConfig::new("test", Ipv4Addr::new(10, 73, 0, 2)).tcp;
        config.max_connections = 64;
        let mut owner = Owner::with_config(
            Ipv4Addr::new(10, 73, 0, 2),
            (Ipv4Addr::new(10, 73, 0, 1), 24),
            [secret; 32],
            None,
            config,
        )
        .unwrap();
        owner.test_now = Some(0);
        (3..19)
            .map(|last| {
                let id = connect(&mut owner, remote(false, last, 80)).unwrap();
                name(&mut owner, id).port()
            })
            .collect()
    };
    let a = firsts(1);
    assert!(a.iter().all(|port| ports::RANGE.contains(port)));
    // 16 destinations start at no one sequence: neither all on one port
    // nor each a port after the last, as one global counter would give.
    assert!(a.windows(2).any(|w| w[0] != w[1]));
    assert!(!a.windows(2).all(|w| w[1] == w[0] + 2 || w[1] == w[0] + 1));
    assert_eq!(a, firsts(1));
    let b = firsts(2);
    assert!(
        a.iter().zip(&b).filter(|(x, y)| x == y).count() < 4,
        "{a:?} {b:?}"
    );
}

// A TIME-WAIT record keeps its 4-tuple: a connect to its destination does
// not take the port while it lasts, one to another destination does.
// bind(0) takes no port a record holds.
#[test]
fn time_wait_records_keep_their_tuple_and_port() {
    let (mut a, _b, local, peer) = time_wait_record(false);
    a.ephemeral_ports = local.port()..=local.port();
    assert_eq!(connect(&mut a, peer), Err(EADDRNOTAVAIL));
    let id = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(id, Op::Bind(SocketAddr::new(a.local, 0)))
            .unwrap_err(),
        EADDRINUSE
    );
    a.execute(id, Op::Close).unwrap();
    let elsewhere = connect(&mut a, SocketAddr::new(peer.ip(), peer.port() + 1)).unwrap();
    assert_eq!(name(&mut a, elsewhere).port(), local.port());
    a.test_now = Some(500_000_000);
    a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
    assert!(!a.endpoint.time_wait_holds_port(local.port()));
    let again = connect(&mut a, peer).unwrap();
    assert_eq!(name(&mut a, again).port(), local.port());
    check_index(&a);
}

// bind() to the port of a TIME-WAIT record, or of a connection whose
// descriptor is closed, is refused unless both it and the bind have
// SO_REUSEADDR, as Linux's inet_bind_conflict judges a timewait socket's
// tw_reuse.
#[test]
fn bind_to_a_time_wait_port_needs_both_sides_reuse() {
    for (tw_reuse, reuse) in [(false, false), (false, true), (true, false), (true, true)] {
        let (mut a, _b, local, _) = time_wait_record(tw_reuse);
        let id = new(&mut a, SOCK_NONBLOCK);
        a.execute(id, Op::Set(SOL_SOCKET, SO_REUSEADDR, reuse as i32))
            .unwrap();
        let wildcard = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), local.port());
        for address in [local, wildcard] {
            assert_eq!(
                a.execute(id, Op::Bind(address)).err(),
                (!(tw_reuse && reuse)).then_some(EADDRINUSE),
                "{tw_reuse} {reuse} {address}"
            );
            if tw_reuse && reuse {
                break;
            }
        }
        if tw_reuse && reuse {
            a.execute(id, Op::Listen(4)).unwrap();
        }
        // Another port is free whatever the reuse.
        let other = new(&mut a, SOCK_NONBLOCK);
        a.execute(other, Op::Bind(SocketAddr::new(a.local, local.port() + 1)))
            .unwrap();
        check_index(&a);
    }
    // A connection whose descriptor is closed, before its TIME-WAIT.
    for (old_reuse, reuse) in [(false, true), (true, true)] {
        let (mut a, _b, client, _, _) = pair();
        a.execute(client, Op::Set(SOL_SOCKET, SO_REUSEADDR, old_reuse as i32))
            .unwrap();
        let local = name(&mut a, client);
        a.execute(client, Op::Close).unwrap();
        let id = new(&mut a, SOCK_NONBLOCK);
        a.execute(id, Op::Set(SOL_SOCKET, SO_REUSEADDR, reuse as i32))
            .unwrap();
        assert_eq!(
            a.execute(id, Op::Bind(local)).err(),
            (!old_reuse).then_some(EADDRINUSE)
        );
        check_index(&a);
    }
}

#[test]
fn detached_and_released_time_wait_ports_stay_owned_until_collection() {
    let (mut a, mut b, client, server, _) = pair();
    a.test_now = Some(a.now());
    b.test_now = Some(b.now());
    let cid = connection(&a, client);
    let local = name(&mut a, client);
    a.execute(client, Op::Close).unwrap();
    assert!(a.port_index.used(local.port()));
    pump(&mut a, &mut b);
    b.execute(server, Op::Close).unwrap();
    pump(&mut a, &mut b);
    assert_eq!(a.endpoint.state(cid), Ok(State::TimeWait));
    a.endpoint.release(cid).unwrap();
    assert!(a.endpoint.tuple(cid).is_err());
    // Released, only its TIME-WAIT record remains, and holds the port.
    assert!(!a.endpoint.connection_exists(cid));
    assert!(a.endpoint.time_wait_holds_port(local.port()));
    a.ephemeral_ports = local.port()..=local.port() + 1;
    assert_eq!(a.bind_port(false), Ok(local.port() + 1));
    a.test_now = Some(500_000_000);
    a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
    pump(&mut a, &mut b);
    assert!(!a.endpoint.connection_exists(cid));
    // Stale generation metadata does not keep a collected port reserved.
    a.ephemeral_ports = local.port()..=local.port();
    assert_eq!(a.bind_port(false), Ok(local.port()));
    check_index(&a);
}

#[test]
fn ordinary_backendless_owner_takes_ports_of_the_linux_range() {
    let (mut owner, _) = external(false, 2);
    owner.ports[0].ethernet = None;
    for _ in 0..4 {
        let id = new(&mut owner, SOCK_NONBLOCK);
        let local = owner.local;
        owner
            .execute(id, Op::Bind(SocketAddr::new(local, 0)))
            .unwrap();
        assert!(ports::RANGE.contains(&name(&mut owner, id).port()));
    }
    check_index(&owner);
}
