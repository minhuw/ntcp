// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;
use ntcp_host::path;
#[path = "runtime_ingress_tests.rs"]
mod ingress;
#[path = "runtime_managed_io_tests.rs"]
mod scheduled;
#[path = "runtime_control_tests.rs"]
mod control;

fn native(v6: bool, last: u8, slots: usize) -> (Owner, Arc<Mutex<State>>) {
    native_output(v6, last, slots, if v6 { 1280 } else { 1100 }, false, false)
}
fn native_output(
    v6: bool,
    last: u8,
    slots: usize,
    mtu: u32,
    gso: bool,
    shared: bool,
) -> (Owner, Arc<Mutex<State>>) {
    let local: IpAddr = if v6 {
        format!("2001:db8::{last}")
    } else {
        format!("10.73.0.{last}")
    }
    .parse()
    .unwrap();
    let mut config = SocketConfig::new("external", local);
    config.io.prefix = Some(if v6 { 64 } else { 24 });
    config.tcp.max_connections = slots;
    config.tcp.reuse_time_wait = true;
    config.io.egress_capacity = slots.min(2);
    config.io.gso = gso.then_some(ntcp::GsoLimits {
        max_bytes: 8192,
        max_segments: 8,
    });
    config.tcp.connection.timestamps = false;
    config.tcp.connection.delayed_ack_us = 0;
    let state = Arc::new(Mutex::new(State {
        mtu: Some(mtu),
        shared,
        max_packet_len: Some(2048),
        ..Default::default()
    }));
    let mut owner = Owner::external_backend(
        &config,
        crate::EthernetPacketIo {
            io: Box::new(Fixture(state.clone())),
            local_mac: [2; 6],
            next_hop_mac: [4; 6],
        },
    )
    .unwrap();
    owner.test_now = Some(1000);
    assert!(state.lock().unwrap().mtu_queries >= 2);
    assert_eq!(
        owner.endpoint.managed_context(),
        Some(owner.host.as_ref().unwrap().paths().context())
    );
    let usage = owner.host.as_ref().unwrap().paths().usage();
    assert_eq!(
        (
            usage.links,
            usage.sources,
            usage.source_owners,
            usage.routes
        ),
        (1, 1, 1, 1)
    );
    assert_eq!(
        owner
            .host
            .as_ref()
            .unwrap()
            .paths()
            .link(owner.ingress.unwrap().link())
            .unwrap()
            .mtu,
        mtu
    );
    (owner, state)
}
fn connection(owner: &Owner, socket: u64) -> ConnectionId {
    let Handle::Connection(cid) = owner.sockets[&socket].handle else {
        panic!()
    };
    cid
}
fn flush(from: &mut Owner, to: &mut Owner, wire: &Arc<Mutex<State>>) -> Vec<Vec<u8>> {
    from.service_egress().unwrap();
    let packets: Vec<_> = wire.lock().unwrap().sent.drain(..).collect();
    for packet in &packets {
        let eth = ntcp_ethernet::parse_ethernet(packet).unwrap();
        to.input_ip_metadata(eth.payload, Default::default(), None);
    }
    from.events();
    to.events();
    packets
}
fn exchange(a: &mut Owner, b: &mut Owner, wa: &Arc<Mutex<State>>, wb: &Arc<Mutex<State>>) {
    for _ in 0..32 {
        let first = flush(a, b, wa);
        let second = flush(b, a, wb);
        if first.is_empty() && second.is_empty() {
            return;
        }
    }
    panic!("native wire did not quiesce");
}
fn class(owner: &mut Owner, socket: u64, value: i32) -> Result<Reply> {
    let (level, option) = if owner.local.is_ipv4() {
        (IPPROTO_IP, IP_TOS)
    } else {
        (IPPROTO_IPV6, IPV6_TCLASS)
    };
    owner.execute(socket, Op::Set(level, option, value))
}
fn listener(owner: &mut Owner) -> u64 {
    let socket = new(owner, SOCK_NONBLOCK);
    class(owner, socket, 48).unwrap();
    owner
        .execute(socket, Op::Bind(SocketAddr::new(owner.local, 8080)))
        .unwrap();
    let backlog = owner.defaults.max_connections.min(4) as i32;
    owner
        .execute(socket, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, backlog))
        .unwrap();
    owner.execute(socket, Op::Listen(backlog)).unwrap();
    socket
}

// The test's own read-only adjtimex read of the kernel clock the UTC source
// samples: its time in nanoseconds since the epoch when the read satisfies
// that source's per-sample conditions (1) and (2) (no kernel error predicate,
// neither TIME_ERROR nor TIME_OOP, maximum error within 0..=16 s).
fn utc_read() -> Option<i128> {
    // SAFETY: timex is plain data; all-zero sets modes 0, a read-only call.
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    // SAFETY: `tx` is a valid, writable timex for the call.
    let state = unsafe { libc::adjtimex(&mut tx) };
    let status = tx.status;
    let error = status & (libc::STA_UNSYNC | libc::STA_CLOCKERR) != 0
        || status & (libc::STA_PPSFREQ | libc::STA_PPSTIME) != 0
            && status & libc::STA_PPSSIGNAL == 0
        || status & (libc::STA_PPSTIME | libc::STA_PPSJITTER)
            == libc::STA_PPSTIME | libc::STA_PPSJITTER
        || status & libc::STA_PPSFREQ != 0
            && status & (libc::STA_PPSWANDER | libc::STA_PPSERROR) != 0;
    if state == -1
        || error
        || matches!(state, libc::TIME_ERROR | libc::TIME_OOP)
        || !(0..=16_000_000).contains(&tx.maxerror)
    {
        return None;
    }
    let unit = if status & libc::STA_NANO != 0 {
        1
    } else {
        1000
    };
    Some(i128::from(tx.time.tv_sec) * 1_000_000_000 + i128::from(tx.time.tv_usec) * unit)
}
// An IPv4 Timestamp value recorded between the `before` and `after` reads:
// true for a standard value, which both reads must accept and which must lie
// within their window in milliseconds since midnight UT (across midnight
// too); false for a value marked nonstandard by the high-order bit.
fn standard_time(value: u32, before: Option<i128>, after: Option<i128>) -> bool {
    const DAY: i128 = 86_400_000;
    if value & 0x8000_0000 != 0 {
        return false;
    }
    let (Some(before), Some(after)) = (before, after) else {
        panic!("unmarked time {value} without a healthy kernel clock bracket");
    };
    let (first, last) = (before.div_euclid(1_000_000), after.div_euclid(1_000_000));
    let offset = (i128::from(value) - first).rem_euclid(DAY);
    assert!(
        i128::from(value) < DAY && offset <= last - first,
        "unmarked time {value} outside the UTC window {first}..={last}"
    );
    true
}

#[test]
fn managed_native_startup_refuses_missing_or_failed_physical_facts() {
    let mut config = SocketConfig::new("external", Ipv4Addr::new(10, 73, 0, 2));
    config.io.prefix = Some(24);
    for (mtu, error, expected) in [
        (None, None, EOPNOTSUPP),
        (Some(1500), Some(ENODEV), ENODEV),
        (Some(67), None, EINVAL),
    ] {
        let state = Arc::new(Mutex::new(State {
            mtu,
            mtu_error: error,
            ..Default::default()
        }));
        let result = Owner::external_backend(
            &config,
            crate::EthernetPacketIo {
                io: Box::new(Fixture(state.clone())),
                local_mac: [2; 6],
                next_hop_mac: [4; 6],
            },
        );
        assert_eq!(result.err(), Some(expected));
        assert!(state.lock().unwrap().sent.is_empty());
    }
}

#[test]
fn managed_native_factory_cancel_rejects_reserved_and_submitted_syns() {
    let (mut owner, _) = native(false, 2, 1);
    let socket = new(&mut owner, SOCK_NONBLOCK);
    assert_eq!(
        owner
            .execute(socket, Op::Connect("10.73.0.3:8080".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    let cid = connection(&owner, socket);
    let binding = owner.host.as_ref().unwrap().binding(cid).unwrap();
    let mut bytes = [0; 2048];
    let (_, attempt) = owner
        .endpoint
        .poll_reserved_transmit(owner.now(), &mut bytes, BUDGET)
        .unwrap();
    assert_eq!(
        owner.endpoint.cancel_unsubmitted_open(cid),
        Err(EndpointError::OutputReserved)
    );
    owner
        .endpoint
        .accept_transmit(owner.now(), attempt.unwrap())
        .unwrap();
    assert!(owner.endpoint.cancel_unsubmitted_open(cid).is_err());
    assert!(owner.endpoint.connection_exists(cid));
    assert_eq!(owner.host.as_ref().unwrap().binding(cid).unwrap(), binding);
}

#[test]
fn managed_native_first_ordinary_tfo_deferred_and_hidden_child_use_selected_outgoing_path() {
    for v6 in [false, true] {
        for mode in 0..3 {
            let (mut a, wa) = native(v6, 2, 4);
            let (mut b, wb) = native(v6, 3, 4);
            assert_ne!(a.endpoint.managed_context(), b.endpoint.managed_context());
            let listen = listener(&mut b);
            let remote = SocketAddr::new(b.local, 8080);
            if mode == 2 {
                let warm = new(&mut a, SOCK_NONBLOCK);
                a.execute(warm, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                    .unwrap();
                assert_eq!(
                    a.execute(warm, Op::Connect(remote)).unwrap_err(),
                    EINPROGRESS
                );
                exchange(&mut a, &mut b, &wa, &wb);
                b.execute(listen, Op::Accept(SOCK_NONBLOCK)).unwrap();
                assert!(
                    a.endpoint
                        .has_fast_open_cookie(a.now(), a.local, b.local)
                        .unwrap()
                );
            }
            let client = new(&mut a, SOCK_NONBLOCK);
            class(&mut a, client, 96).unwrap();
            if mode == 0 {
                assert_eq!(
                    a.execute(client, Op::Connect(remote)).unwrap_err(),
                    EINPROGRESS
                );
            } else if mode == 1 {
                b.execute(
                    listen,
                    Op::SetListenerFastOpenEarlyDataPolicy(
                        FastOpenEarlyDataPolicy::ApplicationProtected,
                    ),
                )
                .unwrap();
                a.execute(
                    client,
                    Op::SetFastOpenClientPolicy(Some((
                        remote,
                        FastOpenClientPolicy::ApplicationProtected,
                    ))),
                )
                .unwrap();
                let data = [7; 2000];
                let result = a.execute(
                    client,
                    Op::SendTo(
                        vec![(data.as_ptr() as usize, data.len())],
                        MSG_FASTOPEN,
                        Some(remote),
                        None,
                    ),
                );
                assert!(result.is_ok() || result.unwrap_err() == EINPROGRESS);
            } else {
                a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                    .unwrap();
                a.execute(client, Op::Connect(remote)).unwrap();
                assert!(matches!(a.sockets[&client].handle, Handle::Fresh));
                let before = a.host.as_ref().unwrap().binding_count();
                assert_eq!(before, 1);
                let data = [7; 2000];
                a.execute(
                    client,
                    Op::Send(vec![(data.as_ptr() as usize, data.len())], 0),
                )
                .unwrap();
            }
            let cid = connection(&a, client);
            let binding = a.host.as_ref().unwrap().binding(cid).unwrap();
            assert_eq!(a.endpoint.managed_path(cid).unwrap().binding, binding);
            assert_eq!(binding.snapshot.key().dscp().value(), 24);
            assert_eq!(
                binding.snapshot.key().next_hop(),
                path::ResolvedNextHop::Forwarder(path::ForwarderId(1))
            );
            let mtu = if v6 { 1280 } else { 1100 };
            assert_eq!(binding.snapshot.first_hop_mtu(), mtu);
            let info = a.endpoint.transport_info(cid).unwrap();
            assert!(info.mss <= mtu - if v6 { 60 } else { 40 });
            let segments = if info.mss > 2190 {
                2
            } else if info.mss > 1095 {
                3
            } else {
                4
            };
            assert_eq!(info.cwnd, segments * info.mss);
            let syns = flush(&mut a, &mut b, &wa);
            assert_eq!(syns.len(), 1);
            let ip = crate::ip::parse(&syns[0][14..]).unwrap();
            assert_eq!(ip.traffic_class >> 2, 24);
            assert!(ip.payload.len() + crate::ip::header_len(a.local) <= mtu as usize);
            let syn = ntcp::wire::parse(ip.ip, ip.payload).unwrap();
            if mode != 0 {
                assert!(!syn.payload.is_empty());
            }
            let tuple = ntcp::Tuple {
                local: remote,
                remote: a.endpoint.tuple(cid).unwrap().local,
            };
            let child = b.endpoint.connection_id(tuple).unwrap();
            assert_eq!(b.endpoint.state(child), Ok(ntcp::State::SynReceived));
            assert_eq!(b.endpoint.received_dscp(child).unwrap(), Some(24));
            let child_binding = b.host.as_ref().unwrap().binding(child).unwrap();
            assert_eq!(child_binding.snapshot.key().dscp().value(), 12);
            assert_eq!(
                b.endpoint.managed_path(child).unwrap().binding,
                child_binding
            );
            let synacks = flush(&mut b, &mut a, &wb);
            assert_eq!(
                crate::ip::parse(&synacks[0][14..]).unwrap().traffic_class >> 2,
                12
            );
            exchange(&mut a, &mut b, &wa, &wb);
            let server = b.execute(listen, Op::Accept(SOCK_NONBLOCK)).unwrap().value as u64;
            assert_eq!(connection(&b, server), child);
            assert_eq!(
                b.host.as_ref().unwrap().binding(child).unwrap().client,
                child_binding.client
            );
        }
    }
}

#[test]
fn managed_native_shared_identity_and_live_class_commit_keep_transport_policy_separate() {
    for v6 in [false, true] {
        let (mut owner, _) = native(v6, 2, 2);
        let remote = SocketAddr::new(
            if v6 { "2001:db8::3" } else { "10.73.0.3" }
                .parse()
                .unwrap(),
            8080,
        );
        let sockets = [
            new(&mut owner, SOCK_NONBLOCK),
            new(&mut owner, SOCK_NONBLOCK),
        ];
        for socket in sockets {
            class(&mut owner, socket, 96).unwrap();
            assert_eq!(
                owner.execute(socket, Op::Connect(remote)).unwrap_err(),
                EINPROGRESS
            );
        }
        let first = connection(&owner, sockets[0]);
        let second = connection(&owner, sockets[1]);
        let a = owner.host.as_ref().unwrap().binding(first).unwrap();
        let b = owner.host.as_ref().unwrap().binding(second).unwrap();
        assert_eq!(a.snapshot.path(), b.snapshot.path());
        assert_ne!(a.client, b.client);
        assert_eq!(
            owner
                .host
                .as_ref()
                .unwrap()
                .paths()
                .path_pins(a.snapshot.path()),
            Ok(2)
        );
        class(&mut owner, sockets[0], 100).unwrap();
        let rebound = owner.host.as_ref().unwrap().binding(first).unwrap();
        assert_ne!(rebound.snapshot.path(), b.snapshot.path());
        assert_eq!(owner.endpoint.managed_path(first).unwrap().binding, rebound);
        assert_eq!(owner.host.as_ref().unwrap().binding(second).unwrap(), b);
        let options = owner.connection_options.clone();
        // Remove configured forwarding authority; class changes fail atomically
        // through the ordinary socket error channel and preserve the old client.
        owner
            .host
            .as_mut()
            .unwrap()
            .remove_route(rebound.snapshot.key().route())
            .unwrap();
        assert_eq!(class(&mut owner, sockets[0], 104).unwrap_err(), ENETUNREACH);
        assert_eq!(
            owner.host.as_ref().unwrap().binding(first).unwrap(),
            rebound
        );
        assert_eq!(owner.endpoint.managed_path(first).unwrap().binding, rebound);
        assert_eq!(owner.connection_options, options);
        assert_eq!(owner.sockets[&sockets[0]].wire_tos(owner.local), 100);
        assert_eq!(owner.host.as_ref().unwrap().paths().usage().clients, 2);
    }
}

#[test]
fn managed_native_repeated_constructor_and_option_failures_reuse_exact_generation_without_leaks() {
    let (mut owner, _) = native(false, 2, 1);
    let socket = new(&mut owner, SOCK_NONBLOCK);
    let local: SocketAddr = "10.73.0.2:40000".parse().unwrap();
    let remote: SocketAddr = "10.73.0.3:8080".parse().unwrap();
    for _ in 0..16 {
        owner.sockets.get_mut(&socket).unwrap().send_capacity = 0;
        assert!(owner.start_connection(socket, local, remote, None).is_err());
        assert_eq!(owner.host.as_ref().unwrap().binding_count(), 0);
        assert_eq!(owner.host.as_ref().unwrap().paths().usage().clients, 0);
        owner.sockets.get_mut(&socket).unwrap().send_capacity = 65536;
        owner.sockets.get_mut(&socket).unwrap().user_timeout_ms = -1;
        assert_eq!(
            owner.start_connection(socket, local, remote, None),
            Err(EINVAL)
        );
        assert_eq!(owner.host.as_ref().unwrap().binding_count(), 0);
        assert_eq!(owner.host.as_ref().unwrap().paths().usage().clients, 0);
        assert!(matches!(owner.sockets[&socket].handle, Handle::Fresh));
        owner.sockets.get_mut(&socket).unwrap().user_timeout_ms = 0;
    }
    owner.start_connection(socket, local, remote, None).unwrap();
    let cid = connection(&owner, socket);
    let prepared = owner.host.as_ref().unwrap().binding(cid).unwrap();
    for _ in 0..16 {
        let other = new(&mut owner, SOCK_NONBLOCK);
        assert_eq!(
            owner.start_connection(other, SocketAddr::new(owner.local, 40001), remote, None),
            Err(ENOBUFS)
        );
        owner.execute(other, Op::Close).unwrap();
        assert_eq!(owner.host.as_ref().unwrap().binding(cid).unwrap(), prepared);
        assert_eq!(owner.host.as_ref().unwrap().paths().usage().clients, 1);
    }
}

#[test]
fn managed_native_live_class_capacity_failure_preserves_socket_core_client_and_dirty_stamp() {
    let (mut owner, _) = native(false, 2, 1);
    // Exercise resource backpressure at the native transaction boundary with
    // explicitly constrained Host storage. Keep the actual registered backend,
    // source and forwarding contract; normal startup includes migration space.
    let previous = owner.host.as_ref().unwrap();
    let ingress = owner.ingress.unwrap();
    let receive = previous.receive_capabilities(ingress).unwrap();
    let link = previous.paths().link(ingress.link()).unwrap();
    let (mut paths, limits) = ntcp_host::managed_limits(&owner.defaults, 1, 1, 1, 1, 1).unwrap();
    paths.paths = 1;
    let mut identity = [0; 16];
    ports::fill(&mut identity).unwrap();
    let mut host = ntcp_host::Host::new(
        path::ContextId::new(u128::from_ne_bytes(identity)),
        paths,
        limits,
        owner.endpoint.caller_timebase(),
    )
    .unwrap();
    let ingress = host
        .register_link(
            link.interface,
            link.mtu,
            receive,
            ntcp_host::Forwarding::Forwarder(path::ForwarderId(1)),
        )
        .unwrap();
    host.register_source(
        path::ScopedAddress::new(owner.local, None).unwrap(),
        ingress.link(),
    )
    .unwrap();
    host.add_route(path::Route {
        destination: path::IpPrefix::new(Ipv4Addr::UNSPECIFIED.into(), 0).unwrap(),
        source: None,
        dscp: None,
        link: ingress.link(),
        next_hop: path::NextHop::Forwarder(path::ForwarderId(1)),
        metric: 0,
    })
    .unwrap();
    owner.endpoint = Endpoint::new(owner.defaults.clone(), [42; 32], 0, |_| true).unwrap();
    host.attach(&mut owner.endpoint).unwrap();
    owner.host = Some(host);
    owner.ingress = Some(ingress);
    let socket = new(&mut owner, SOCK_NONBLOCK);
    class(&mut owner, socket, 96).unwrap();
    assert_eq!(
        owner
            .execute(socket, Op::Connect("10.73.0.3:8080".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    let cid = connection(&owner, socket);
    let before = owner.host.as_ref().unwrap().binding(cid).unwrap();
    owner
        .host
        .as_mut()
        .unwrap()
        .trusted_decrease(1000, before.snapshot.path(), 1000)
        .unwrap();
    let dirty = owner
        .host
        .as_ref()
        .unwrap()
        .paths()
        .snapshot(before.client)
        .unwrap();
    let options = owner.connection_options.clone();
    let transport = owner.endpoint.transport_info(cid).unwrap();
    for _ in 0..16 {
        assert_eq!(class(&mut owner, socket, 100).unwrap_err(), ENOBUFS);
        assert_eq!(owner.sockets[&socket].wire_tos(owner.local), 96);
        assert_eq!(owner.connection_options, options);
        assert_eq!(owner.host.as_ref().unwrap().binding(cid).unwrap(), before);
        assert_eq!(owner.endpoint.managed_path(cid).unwrap().binding, before);
        assert_eq!(owner.endpoint.transport_info(cid).unwrap(), transport);
        assert_eq!(
            owner
                .host
                .as_ref()
                .unwrap()
                .paths()
                .snapshot(before.client)
                .unwrap(),
            dirty
        );
        assert_eq!(
            owner.host.as_ref().unwrap().paths().is_dirty(before.client),
            Ok(true)
        );
        assert_eq!(owner.host.as_ref().unwrap().paths().usage().clients, 1);
    }
}

#[cfg(feature = "linux")]
#[test]
fn managed_native_public_rust_fast_open_helper_and_fd_alias_use_production_attach() {
    const CHILD: &str = "NTCP_MANAGED_FACTORY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "runtime::backend::tests::managed::managed_native_public_rust_fast_open_helper_and_fd_alias_use_production_attach", "--test-threads=1"])
            .env(CHILD, "1").status().unwrap().success());
        return;
    }
    let local = Ipv4Addr::new(10, 73, 0, 2);
    let mut config = SocketConfig::new("external", local);
    config.io.prefix = Some(24);
    let state = Arc::new(Mutex::new(State {
        mtu: Some(1100),
        max_packet_len: Some(2048),
        ..Default::default()
    }));
    let factory_state = state.clone();
    crate::configure_with_packet_io(config, move || {
        Ok(crate::EthernetPacketIo {
            io: Box::new(Fixture(factory_state)),
            local_mac: [2; 6],
            next_hop_mac: [4; 6],
        })
    })
    .unwrap();
    let remote: SocketAddr = "10.73.0.3:8080".parse().unwrap();
    unsafe {
        let fd = crate::ntcp_managed_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
        assert!(fd >= 0);
        let alias = crate::dup(fd);
        assert!(alias >= 0);
        assert_eq!(crate::close(fd), 0);
        crate::set_fast_open_client_policy(
            alias,
            Some((remote, FastOpenClientPolicy::ApplicationProtected)),
        )
        .unwrap();
        let tos = 96i32;
        assert_eq!(
            crate::setsockopt(alias, IPPROTO_IP, IP_TOS, (&tos as *const i32).cast(), 4),
            0
        );
        let address = sockaddr_in {
            sin_family: AF_INET as _,
            sin_port: 8080u16.to_be(),
            sin_addr: in_addr {
                s_addr: u32::from_ne_bytes([10, 73, 0, 3]),
            },
            sin_zero: [0; 8],
        };
        let data = [7; 2000];
        let sent = crate::ntcp_managed_sendto(
            alias,
            data.as_ptr().cast(),
            data.len(),
            MSG_FASTOPEN | MSG_DONTWAIT,
            (&address as *const sockaddr_in).cast(),
            16,
        );
        assert!(sent > 0 || sent == -1 && errno() == EINPROGRESS);
        for _ in 0..200 {
            if !state.lock().unwrap().sent.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let mut wire = state.lock().unwrap();
        assert!(wire.mtu_queries >= 2);
        let packet = wire.sent.pop_front().expect("first production SYN");
        let eth = ntcp_ethernet::parse_ethernet(&packet).unwrap();
        assert_eq!(eth.destination, [4; 6]);
        let ip = crate::ip::parse(eth.payload).unwrap();
        assert_eq!(ip.traffic_class >> 2, 24);
        assert!(eth.payload.len() <= 1100);
        let tcp = ntcp::wire::parse(ip.ip, ip.payload).unwrap();
        assert_eq!(tcp.header.flags & ntcp::wire::SYN, ntcp::wire::SYN);
        assert!(!tcp.payload.is_empty() && tcp.payload.len() <= 536);
        drop(wire);
        assert_eq!(crate::close(alias), 0);
    }
}

#[test]
fn managed_native_time_wait_replacement_capacity_keeps_old_binding_and_cancels_provisional() {
    for capacity in [1, 2] {
        let (mut a, wa) = native(false, 2, capacity);
        let (mut b, wb) = native(false, 3, capacity);
        let listen = listener(&mut b);
        let client = new(&mut a, SOCK_NONBLOCK);
        let remote = SocketAddr::new(b.local, 8080);
        assert_eq!(
            a.execute(client, Op::Connect(remote)).unwrap_err(),
            EINPROGRESS
        );
        exchange(&mut a, &mut b, &wa, &wb);
        let server = b.execute(listen, Op::Accept(SOCK_NONBLOCK)).unwrap().value as u64;
        let old = connection(&b, server);
        let peer = connection(&a, client);
        let local = a.endpoint.tuple(peer).unwrap().local;
        b.execute(server, Op::Shutdown(SHUT_WR)).unwrap();
        exchange(&mut a, &mut b, &wa, &wb);
        a.execute(client, Op::Shutdown(SHUT_WR)).unwrap();
        exchange(&mut a, &mut b, &wa, &wb);
        assert_eq!(b.endpoint.state(old), Ok(ntcp::State::TimeWait));
        b.endpoint.release(old).unwrap();
        b.sockets.remove(&server);
        a.endpoint.release(peer).unwrap();
        a.sockets.remove(&client);
        a.service_egress().unwrap();
        a.collect_paths().unwrap();
        b.collect_paths().unwrap();
        let retained = b.host.as_ref().unwrap().binding(old).unwrap();
        a.test_now = Some(1_001_000);
        b.test_now = Some(1_001_000);
        let next = new(&mut a, SOCK_NONBLOCK);
        a.start_connection(next, local, remote, None).unwrap();
        flush(&mut a, &mut b, &wa);
        assert_eq!(b.host.as_ref().unwrap().binding(old).unwrap(), retained);
        let current = b
            .endpoint
            .connection_id(ntcp::Tuple {
                local: remote,
                remote: local,
            })
            .unwrap();
        if capacity == 1 {
            assert_eq!(current, old);
            assert_eq!(b.host.as_ref().unwrap().binding_count(), 1);
            assert_eq!(b.host.as_ref().unwrap().paths().usage().clients, 1);
        } else {
            assert_ne!(current, old);
            assert_eq!(b.host.as_ref().unwrap().binding_count(), 2);
            exchange(&mut a, &mut b, &wa, &wb);
            let accepted = b.execute(listen, Op::Accept(SOCK_NONBLOCK)).unwrap().value as u64;
            assert_eq!(connection(&b, accepted), current);
        }
    }
}

#[test]
fn managed_native_released_final_output_pins_binding_until_exact_owner_disappears() {
    let (mut a, wa) = native(false, 2, 1);
    let (mut b, wb) = native(false, 3, 1);
    let _listen = listener(&mut b);
    let client = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(client, Op::Connect(SocketAddr::new(b.local, 8080)))
            .unwrap_err(),
        EINPROGRESS
    );
    exchange(&mut a, &mut b, &wa, &wb);
    let cid = connection(&a, client);
    let binding = a.host.as_ref().unwrap().binding(cid).unwrap();
    assert!(a.endpoint.cancel_unsubmitted_open(cid).is_err());
    a.endpoint.abort(cid).unwrap();
    a.endpoint.release(cid).unwrap();
    a.sockets.remove(&client);
    a.collect_paths().unwrap();
    assert!(a.endpoint.connection_exists(cid));
    assert_eq!(a.host.as_ref().unwrap().binding(cid).unwrap(), binding);
    let mut bytes = [0; 2048];
    let (poll, attempt) = a
        .endpoint
        .poll_reserved_transmit(a.now(), &mut bytes, BUDGET)
        .unwrap();
    let packet = poll.packet.unwrap();
    assert_eq!(packet.connection, Some(cid));
    assert_ne!(
        ntcp::wire::parse(packet.ip, &bytes[..packet.len])
            .unwrap()
            .header
            .flags
            & ntcp::wire::RST,
        0
    );
    a.collect_paths().unwrap();
    assert_eq!(a.host.as_ref().unwrap().binding_count(), 1);
    a.endpoint
        .accept_transmit(a.now(), attempt.unwrap())
        .unwrap();
    a.endpoint
        .on_timeout(a.now() + a.defaults.connection.time_wait_us + 1, BUDGET)
        .unwrap();
    assert!(!a.endpoint.connection_exists(cid));
    a.collect_paths().unwrap();
    assert_eq!(a.host.as_ref().unwrap().binding_count(), 0);
    assert_eq!(a.host.as_ref().unwrap().paths().usage().clients, 0);
}

#[test]
fn managed_native_nonlocal_freebind_opens_keep_einval_and_unrouted_source_is_enetunreach() {
    let remote: SocketAddr = "10.73.0.3:18000".parse().unwrap();
    let nonlocal: SocketAddr = "198.51.100.17:18000".parse().unwrap();
    for mode in 0..3 {
        let (mut a, wire) = native(false, 2, 4);
        let id = new(&mut a, SOCK_NONBLOCK);
        a.execute(id, Op::Set(IPPROTO_IP, IP_FREEBIND, 1)).unwrap();
        a.execute(id, Op::Bind(nonlocal)).unwrap();
        let data = [7; 100];
        let result = match mode {
            0 => a.execute(id, Op::Connect(remote)),
            1 => a.execute(
                id,
                Op::SendTo(
                    vec![(data.as_ptr() as usize, data.len())],
                    MSG_FASTOPEN,
                    Some(remote),
                    None,
                ),
            ),
            _ => {
                // Protected-service authority defers the open to first write.
                a.execute(
                    id,
                    Op::SetFastOpenClientPolicy(Some((
                        remote,
                        FastOpenClientPolicy::ApplicationProtected,
                    ))),
                )
                .unwrap();
                a.execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                    .unwrap();
                a.execute(id, Op::Connect(remote)).unwrap();
                assert!(a.sockets[&id].deferred_peer.is_some());
                a.execute(id, Op::Send(vec![(data.as_ptr() as usize, data.len())], 0))
            }
        };
        let errno = result.map(|_| 0).unwrap_or_else(|errno| errno);
        println!("nonlocal FREEBIND open mode {mode}: errno {errno}");
        assert_eq!(errno, EINVAL);
        assert_eq!(a.host.as_ref().unwrap().binding_count(), 0);
        a.service_egress().unwrap();
        assert!(wire.lock().unwrap().sent.is_empty());
    }
    // A registered, authorized source whose forwarding table has no route.
    let (mut a, wire) = native(false, 2, 4);
    let host = a.host.as_mut().unwrap();
    let source = host.paths().sources().next().unwrap().0;
    let request = path::PathRequest {
        source,
        destination: path::ScopedAddress::new(remote.ip(), None).unwrap(),
        dscp: path::Dscp::new(0).unwrap(),
    };
    let route = host.paths().resolve(request).unwrap().key().route();
    host.remove_route(route).unwrap();
    let id = new(&mut a, SOCK_NONBLOCK);
    let errno = a.execute(id, Op::Connect(remote)).unwrap_err();
    println!("owned source without route: errno {errno}");
    assert_eq!(errno, ENETUNREACH);
    assert_eq!(a.host.as_ref().unwrap().binding_count(), 0);
    assert!(wire.lock().unwrap().sent.is_empty());
}
