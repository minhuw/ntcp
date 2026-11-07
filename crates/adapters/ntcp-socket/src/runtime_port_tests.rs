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

fn at(port: u16) -> [u8; 8] {
    assert!(port >= FIRST);
    u64::from(port - FIRST).to_ne_bytes()
}
fn controlled(owner: &mut Owner, ports: &[u16]) {
    owner.port_entropy = Some(ports.iter().map(|&p| Ok(at(p))).collect());
}
fn choose(start: u16, available: impl FnMut(u16) -> bool) -> Result<u16> {
    allocate(
        |bytes| {
            bytes.copy_from_slice(&at(start));
            Ok(())
        },
        available,
    )
}

#[test]
fn complete_range_wrap_single_available_and_finite_exhaustion() {
    for start in [FIRST, 40000, u16::MAX] {
        for only in [FIRST, 23456, u16::MAX] {
            let mut visits = vec![false; 65536];
            assert_eq!(
                choose(start, |port| {
                    assert!(port >= FIRST);
                    assert!(!visits[usize::from(port)], "candidate revisited");
                    visits[usize::from(port)] = true;
                    port == only
                }),
                Ok(only)
            );
            assert!(visits[usize::from(only)]);
        }
        let mut visits = vec![0; 65536];
        assert_eq!(
            choose(start, |port| {
                visits[usize::from(port)] += 1;
                false
            }),
            Err(EADDRNOTAVAIL)
        );
        assert!(visits[..1024].iter().all(|&n| n == 0));
        assert!(visits[1024..].iter().all(|&n| n == 1));
    }
    let mut visits = Vec::new();
    assert_eq!(
        choose(65535, |p| {
            visits.push(p);
            p == 1025
        }),
        Ok(1025)
    );
    assert_eq!(visits, [65535, 1024, 1025]);
    assert_eq!(
        allocate(|_| Err(EIO), |_| panic!("scanned after entropy failure")),
        Err(EIO)
    );
    assert!(
        allocate(
            |out| {
                out.fill(255);
                Ok(())
            },
            |p| p >= FIRST
        )
        .unwrap()
            >= FIRST
    );
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
    config.io.source_quiet = crate::SourceQuiet::Never;
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

// These full Informational recommendations are evidenced by the native OS
// source above, the exhaustive production-helper tests, and live socket paths.
// No distribution test is used as evidence of cryptographic unpredictability.
//= https://www.rfc-editor.org/rfc/rfc5927#section-4.2
//= type=test
//# As discussed in the previous sections, in order to perform any of the attacks described in this document, an attacker would need to guess (or know) the four-tuple that identifies the connection to be attacked. Increasing the port number range used for outgoing TCP connections, and randomizing the port number chosen for each outgoing TCP connection, would make it harder for an attacker to perform any of the attacks discussed in this document.
//= https://www.rfc-editor.org/rfc/rfc5927#section-4.2
//= type=test
//# [PORT-RANDOM] recommends that transport protocols randomize the ephemeral ports used by clients, and proposes a number of randomization algorithms.
#[test]
fn native_auto_ports_bind_listen_connect_and_deferred_fast_open() {
    for v6 in [false, true] {
        let (mut a, wa) = external(v6, 2);
        let (mut b, wb) = external(v6, 3);
        // Bind(0) and implicit Listen use fresh selection. Distinct controlled
        // values choose independently of descriptor order or the previous port.
        controlled(&mut a, &[65535, 1024, 65535, 1024, 50000, 60000]);
        let bound = new(&mut a, SOCK_NONBLOCK);
        let bind_ip = a.local;
        a.execute(bound, Op::Bind(SocketAddr::new(bind_ip, 0)))
            .unwrap();
        assert_eq!(name(&mut a, bound).port(), 65535);
        let listener_a = new(&mut a, SOCK_NONBLOCK);
        a.execute(listener_a, Op::Listen(4)).unwrap();
        assert_eq!(name(&mut a, listener_a).port(), 1024);
        let client = new(&mut a, SOCK_NONBLOCK);
        controlled(&mut b, &[8080]);
        let listener_b = new(&mut b, SOCK_NONBLOCK);
        b.execute(listener_b, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 4))
            .unwrap();
        b.execute(listener_b, Op::Listen(4)).unwrap();
        let remote = SocketAddr::new(b.local, name(&mut b, listener_b).port());
        // Starting at 65535 skips the bound port, wraps, skips the listener.
        assert_eq!(
            a.execute(client, Op::Connect(remote)).unwrap_err(),
            EINPROGRESS
        );
        let local = name(&mut a, client);
        assert_eq!(local.port(), 1025);
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
        b.execute(server, Op::Write(b"native response".to_vec()))
            .unwrap();
        exchange(&mut a, &mut b, &wa, &wb);
        assert_eq!(
            a.execute(client, Op::Read(32)).unwrap().bytes,
            b"native response"
        );
        // The connected socket is skipped as well as bound/listening sockets.
        let second = new(&mut a, SOCK_NONBLOCK);
        a.execute(second, Op::Bind(SocketAddr::new(bind_ip, 0)))
            .unwrap();
        assert_eq!(name(&mut a, second).port(), 1026);
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
        assert_eq!(deferred_local.port(), 60000);
        assert!(matches!(a.sockets[&deferred].handle, Handle::Fresh));
        assert!(deliver(&mut a, &mut b, &wa).is_empty());
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
        assert!(a.port_entropy.as_ref().unwrap().is_empty());
    }
}

#[test]
fn native_entropy_errors_are_transactional_and_explicit_bind_uses_none() {
    for v6 in [false, true] {
        for operation in 0..4 {
            let (mut owner, wire) = external(v6, 2);
            let id = new(&mut owner, SOCK_NONBLOCK);
            let local = owner.local;
            let remote = SocketAddr::new(
                if v6 { "2001:db8::3" } else { "10.73.0.3" }
                    .parse()
                    .unwrap(),
                8080,
            );
            if operation == 3 {
                owner
                    .execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                    .unwrap();
            }
            owner.port_entropy = Some(VecDeque::from([Err(EPERM)]));
            let options = owner.connection_options.clone();
            let bytes = owner.endpoint.buffer_bytes();
            let op = match operation {
                0 => Op::Bind(SocketAddr::new(local, 0)),
                1 => Op::Listen(4),
                _ => Op::Connect(remote),
            };
            assert_eq!(owner.execute(id, op).unwrap_err(), EPERM);
            let socket = &owner.sockets[&id];
            assert!(matches!(socket.handle, Handle::Fresh));
            assert!(
                socket.local.is_none()
                    && socket.bound_addr.is_none()
                    && socket.deferred_peer.is_none()
            );
            assert_eq!(owner.connection_options, options);
            assert_eq!(owner.endpoint.buffer_bytes(), bytes);
            assert!(owner.detached.is_empty());
            assert!(wire.lock().unwrap().0.is_empty());
            // Empty seam would panic if a nonzero bind consumed entropy.
            owner
                .execute(id, Op::Bind(SocketAddr::new(local, 12345)))
                .unwrap();
            assert_eq!(name(&mut owner, id).port(), 12345);
            owner.execute(id, Op::Listen(1)).unwrap();
        }
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
    assert!(!a.port_available(local.port()));
    pump(&mut a, &mut b);
    b.execute(server, Op::Close).unwrap();
    pump(&mut a, &mut b);
    assert_eq!(a.endpoint.state(cid), Ok(State::TimeWait));
    a.endpoint.release(cid).unwrap();
    assert!(a.endpoint.tuple(cid).is_err());
    assert!(a.endpoint.connection_exists(cid));
    controlled(&mut a, &[local.port(), local.port()]);
    assert_ne!(a.port().unwrap(), local.port());
    a.test_now = Some(500_000_000);
    a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
    pump(&mut a, &mut b);
    assert!(!a.endpoint.connection_exists(cid));
    // Stale generation metadata does not keep a collected port reserved.
    assert_eq!(a.port().unwrap(), local.port());
}

#[test]
fn native_choices_follow_fresh_entropy_even_when_descriptor_is_reused() {
    let (mut owner, _) = external(false, 2);
    controlled(&mut owner, &[2000, 60000, 3000]);
    for expected in [2000, 60000, 3000] {
        owner.next_id = 1; // Reuse the logical descriptor after close.
        let id = new(&mut owner, SOCK_NONBLOCK);
        assert_eq!(id, 1);
        let local = owner.local;
        owner
            .execute(id, Op::Bind(SocketAddr::new(local, 0)))
            .unwrap();
        assert_eq!(name(&mut owner, id).port(), expected);
        owner.execute(id, Op::Close).unwrap();
    }
    assert!(owner.port_entropy.as_ref().unwrap().is_empty());
}

#[test]
fn ordinary_backendless_owner_uses_os_entropy_without_packet_policy() {
    let (mut owner, _) = external(false, 2);
    owner.ports[0].ethernet = None;
    for _ in 0..4 {
        let id = new(&mut owner, SOCK_NONBLOCK);
        let local = owner.local;
        owner
            .execute(id, Op::Bind(SocketAddr::new(local, 0)))
            .unwrap();
        assert!(name(&mut owner, id).port() >= FIRST);
    }
}

// One allocator serves the runtime, each owned address after its own fact.
#[test]
fn every_port_address_keeps_its_own_identifier_fact() {
    let backend = |wire: &Arc<Mutex<Wire>>| crate::EthernetPacketIo {
        io: Box::new(Io(wire.clone())),
        local_mac: [2; 6],
        next_hop_mac: Some([4; 6]),
    };
    let first: IpAddr = "10.73.0.2".parse().unwrap();
    let second: IpAddr = "10.73.1.2".parse().unwrap();
    let config = SocketConfig::parse(
        "io.backend=af-packet\nio.interface=external\nio.address=10.73.0.2\nio.prefix=24\n\
         io.next_hop_mac=04:04:04:04:04:04\nio.source_quiet=never\n\
         port.b.interface=second\nport.b.address=10.73.1.2\nport.b.prefix=24\n\
         port.b.next_hop_mac=04:04:04:04:04:04\nport.b.source_quiet=20\n",
    )
    .unwrap();
    let wire = Arc::new(Mutex::new(Wire::default()));
    let mut owner =
        Owner::external_backends(&config, vec![backend(&wire), backend(&wire)]).unwrap();
    let peer: IpAddr = "10.73.0.9".parse().unwrap();
    let now = owner.now();
    let host = owner.host.as_mut().unwrap();
    assert!(host.lease_identification(now, first, peer, 6).is_ok());
    assert!(matches!(
        host.lease_identification(now, second, peer, 6),
        Err(ntcp_host::IdentifierBackpressure::Unavailable { until: Some(_) })
    ));
}

// A port without its own fact states nothing about its address: its
// identifiers wait the whole MDL, whatever `io.*` asserts about its own
// address.
#[test]
fn a_port_without_a_fact_keeps_its_identifier_quiet_period_whole() {
    let backend = |wire: &Arc<Mutex<Wire>>| crate::EthernetPacketIo {
        io: Box::new(Io(wire.clone())),
        local_mac: [2; 6],
        next_hop_mac: Some([4; 6]),
    };
    let first: IpAddr = "10.73.0.2".parse().unwrap();
    let second: IpAddr = "10.73.1.2".parse().unwrap();
    let config = SocketConfig::parse(
        "io.backend=af-packet\nio.interface=external\nio.address=10.73.0.2\nio.prefix=24\n\
         io.next_hop_mac=04:04:04:04:04:04\nio.source_quiet=never\n\
         port.b.interface=second\nport.b.address=10.73.1.2\nport.b.prefix=24\n\
         port.b.next_hop_mac=04:04:04:04:04:04\n",
    )
    .unwrap();
    let wire = Arc::new(Mutex::new(Wire::default()));
    let mut owner =
        Owner::external_backends(&config, vec![backend(&wire), backend(&wire)]).unwrap();
    let peer: IpAddr = "10.73.0.9".parse().unwrap();
    let now = owner.now();
    let host = owner.host.as_mut().unwrap();
    assert!(host.lease_identification(now, first, peer, 6).is_ok());
    let mdl = u64::from(ntcp_host::DEFAULT_LIFETIME_SECONDS) * 1_000_000;
    match host.lease_identification(now, second, peer, 6) {
        Err(ntcp_host::IdentifierBackpressure::Unavailable { until: Some(until) }) => {
            assert!(until >= owner.started + mdl, "{until}")
        }
        other => panic!("{other:?}"),
    }
}
