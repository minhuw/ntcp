// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;
fn owner4(last: u8) -> (Owner, Arc<Mutex<State>>) {
    let mut config = SocketConfig::new("external", Ipv4Addr::new(192, 0, 2, last));
    config.io.prefix = Some(24);
    config.tcp.connection.timestamps = false;
    config.tcp.connection.delayed_ack_us = 0;
    config.tcp.connection.send_ip_payload_limit = 65515;
    let state = Arc::new(Mutex::new(State::default()));
    let mut owner = Owner::external_backend(
        &config,
        crate::EthernetPacketIo {
            io: Box::new(Io(state.clone())),
            local_mac: [2; 6],
            next_hop_mac: [4; 6],
        },
    )
    .unwrap();
    owner.test_now = Some(0);
    (owner, state)
}
fn socket(o: &mut Owner, domain: i32) -> u64 {
    o.execute(0, Op::NewDomain(domain, SOCK_NONBLOCK))
        .unwrap()
        .value as u64
}
fn mapped(ip: IpAddr, port: u16) -> SocketAddr {
    let IpAddr::V4(ip) = ip else { panic!() };
    SocketAddr::new(ip.to_ipv6_mapped().into(), port)
}
fn exchange4(a: &mut Owner, b: &mut Owner, sa: &Arc<Mutex<State>>, sb: &Arc<Mutex<State>>) {
    for _ in 0..32 {
        let mut progress = false;
        for reverse in [false, true] {
            let (from, to, state) = if reverse {
                (&mut *b, &mut *a, sb)
            } else {
                (&mut *a, &mut *b, sa)
            };
            from.service_egress().unwrap();
            while let Some(frame) = state.lock().unwrap().sent.pop_front() {
                let eth = ntcp_ethernet::parse_ethernet(&frame).unwrap();
                assert_eq!(eth.ether_type, ntcp_ethernet::ETHERTYPE_IPV4);
                let ip = ntcp_ip::parse(eth.payload, false).unwrap();
                ntcp::wire::parse(ip.ip, ip.payload).unwrap();
                to.input_ip_metadata(eth.payload, Default::default(), None);
                progress = true;
            }
            from.events();
            to.events();
        }
        if !progress {
            return;
        }
    }
    panic!("mapped output did not quiesce");
}
type MappedPair = (Owner, Owner, u64, u64, Arc<Mutex<State>>, Arc<Mutex<State>>);
fn pair4(server_domain: i32) -> MappedPair {
    let (mut a, sa) = owner4(1);
    let (mut b, sb) = owner4(2);
    let listener = socket(&mut b, server_domain);
    let addr = if server_domain == AF_INET6 {
        "[::]:8080"
    } else {
        "0.0.0.0:8080"
    };
    b.execute(listener, Op::Bind(addr.parse().unwrap()))
        .unwrap();
    b.execute(listener, Op::Listen(2)).unwrap();
    let client = socket(&mut a, AF_INET6);
    assert_eq!(
        a.execute(client, Op::Connect(mapped(b.local, 8080)))
            .unwrap_err(),
        EINPROGRESS
    );
    exchange4(&mut a, &mut b, &sa, &sb);
    let accepted = b.execute(listener, Op::Accept(SOCK_NONBLOCK)).unwrap();
    if server_domain == AF_INET6 {
        assert_eq!(accepted.addr.unwrap().ip(), mapped(a.local, 0).ip());
    } else {
        assert_eq!(accepted.addr.unwrap().ip(), a.local);
    }
    (a, b, client, accepted.value as u64, sa, sb)
}
#[test]
fn mapped_stream_keeps_api_domain_and_ipv4_transport_and_half_close() {
    let (mut a, mut b, client, server, sa, sb) = pair4(AF_INET6);
    for (o, id) in [(&mut a, client), (&mut b, server)] {
        assert_eq!(
            o.execute(id, Op::Get(SOL_SOCKET, SO_DOMAIN)).unwrap().value,
            AF_INET6
        );
        assert_eq!(
            o.execute(id, Op::Get(IPPROTO_IPV6, IPV6_V6ONLY))
                .unwrap()
                .value,
            0
        );
        let tuple = o.endpoint.tuple(cid(o, id)).unwrap();
        assert!(tuple.local.is_ipv4() && tuple.remote.is_ipv4());
        assert_eq!(
            o.execute(id, Op::Name(false)).unwrap().addr,
            Some(mapped(tuple.local.ip(), tuple.local.port()))
        );
        assert_eq!(
            o.execute(id, Op::Name(true)).unwrap().addr,
            Some(mapped(tuple.remote.ip(), tuple.remote.port()))
        );
    }
    a.execute(client, Op::Write(vec![7; 1000])).unwrap();
    b.execute(server, Op::Write(vec![8; 500])).unwrap();
    exchange4(&mut a, &mut b, &sa, &sb);
    assert_eq!(
        b.execute(server, Op::Read(1000)).unwrap().bytes,
        vec![7; 1000]
    );
    assert_eq!(
        a.execute(client, Op::Read(500)).unwrap().bytes,
        vec![8; 500]
    );
    a.execute(client, Op::Shutdown(SHUT_WR)).unwrap();
    exchange4(&mut a, &mut b, &sa, &sb);
    assert_eq!(b.execute(server, Op::Read(1)).unwrap().value, 0);
    b.execute(server, Op::Shutdown(SHUT_WR)).unwrap();
    exchange4(&mut a, &mut b, &sa, &sb);
    assert_eq!(a.execute(client, Op::Read(1)).unwrap().value, 0);
}
#[test]
fn mapped_v6only_bind_overlap_and_listener_family_are_enforced() {
    let (mut a, sa) = owner4(1);
    let (mut b, sb) = owner4(2);
    let only = socket(&mut b, AF_INET6);
    b.execute(only, Op::Set(IPPROTO_IPV6, IPV6_V6ONLY, 1))
        .unwrap();
    b.execute(only, Op::Bind("[::]:18000".parse().unwrap()))
        .unwrap();
    b.execute(only, Op::Listen(1)).unwrap();
    assert_eq!(
        b.execute(only, Op::Name(false)).unwrap().addr,
        Some("[::]:18000".parse().unwrap())
    );
    let v4 = socket(&mut b, AF_INET);
    b.execute(v4, Op::Bind("0.0.0.0:18000".parse().unwrap()))
        .unwrap();
    b.execute(v4, Op::Listen(1)).unwrap();
    let dual = socket(&mut b, AF_INET6);
    b.execute(dual, Op::Bind("[::]:18001".parse().unwrap()))
        .unwrap();
    b.execute(dual, Op::Listen(1)).unwrap();
    let conflict = socket(&mut b, AF_INET);
    assert_eq!(
        b.execute(conflict, Op::Bind("0.0.0.0:18001".parse().unwrap()))
            .unwrap_err(),
        EADDRINUSE
    );
    assert_eq!(
        b.execute(dual, Op::Set(IPPROTO_IPV6, IPV6_V6ONLY, 1))
            .unwrap_err(),
        EINVAL
    );
    let only6 = socket(&mut b, AF_INET6);
    b.execute(only6, Op::Set(IPPROTO_IPV6, IPV6_V6ONLY, 1))
        .unwrap();
    b.execute(only6, Op::Bind("[::]:18003".parse().unwrap()))
        .unwrap();
    let blocked_dual = socket(&mut b, AF_INET6);
    assert_eq!(
        b.execute(blocked_dual, Op::Bind("[::]:18003".parse().unwrap()))
            .unwrap_err(),
        EADDRINUSE
    );
    let blocked6 = socket(&mut b, AF_INET6);
    b.execute(blocked6, Op::Set(IPPROTO_IPV6, IPV6_V6ONLY, 1))
        .unwrap();
    assert_eq!(
        b.execute(blocked6, Op::Bind("[::]:18001".parse().unwrap()))
            .unwrap_err(),
        EADDRINUSE
    );
    let restricted = socket(&mut a, AF_INET6);
    a.execute(restricted, Op::Set(IPPROTO_IPV6, IPV6_V6ONLY, 1))
        .unwrap();
    assert_eq!(
        a.execute(restricted, Op::Bind(mapped(a.local, 18002)))
            .unwrap_err(),
        EINVAL
    );
    assert_eq!(
        a.execute(restricted, Op::Connect(mapped(b.local, 18000)))
            .unwrap_err(),
        ENETUNREACH
    );
    let client = socket(&mut a, AF_INET);
    assert_eq!(
        a.execute(client, Op::Connect(SocketAddr::new(b.local, 18000)))
            .unwrap_err(),
        EINPROGRESS
    );
    exchange4(&mut a, &mut b, &sa, &sb);
    b.execute(v4, Op::Accept(SOCK_NONBLOCK)).unwrap();
    assert_eq!(
        b.execute(only, Op::Accept(SOCK_NONBLOCK)).unwrap_err(),
        EAGAIN
    );
}
#[test]
fn mapped_options_keep_independent_ip_classes_and_pmtu_settings() {
    let (mut a, mut b, client, server, sa, sb) = pair4(AF_INET);
    a.execute(client, Op::Set(IPPROTO_IPV6, IPV6_TCLASS, 43))
        .unwrap();
    a.execute(client, Op::Set(IPPROTO_IP, IP_TOS, 16)).unwrap();
    a.execute(
        client,
        Op::Set(IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT),
    )
    .unwrap();
    a.execute(
        client,
        Op::Set(IPPROTO_IPV6, IPV6_MTU_DISCOVER, IP_PMTUDISC_DO),
    )
    .unwrap();
    assert_eq!(
        a.execute(client, Op::Get(IPPROTO_IPV6, IPV6_TCLASS))
            .unwrap()
            .value,
        43
    );
    assert_eq!(
        a.execute(client, Op::Get(IPPROTO_IP, IP_TOS))
            .unwrap()
            .value,
        16
    );
    assert_eq!(
        a.execute(client, Op::Get(IPPROTO_IP, IP_MTU_DISCOVER))
            .unwrap()
            .value,
        0
    );
    assert_eq!(
        a.execute(client, Op::Get(IPPROTO_IPV6, IPV6_MTU_DISCOVER))
            .unwrap()
            .value,
        2
    );
    // An inactive-family reset cannot change the active IPv4 class.
    a.execute(client, Op::Set(IPPROTO_IPV6, IPV6_TCLASS, -1))
        .unwrap();
    assert_eq!(
        a.execute(client, Op::Get(IPPROTO_IPV6, IPV6_TCLASS))
            .unwrap()
            .value,
        0
    );
    assert_eq!(
        a.execute(client, Op::Get(IPPROTO_IP, IP_TOS))
            .unwrap()
            .value,
        16
    );
    a.execute(client, Op::Write(vec![3; 100])).unwrap();
    // A DF-clear IPv4 packet needs a leased Identification; none is issued
    // until one maximum datagram lifetime after this Host started, because
    // an earlier process may have emitted from the same address.
    a.service_egress().unwrap();
    assert!(sa.lock().unwrap().sent.is_empty());
    a.test_now = Some(121_000_000);
    a.service_egress().unwrap();
    let frame = sa.lock().unwrap().sent.pop_front().unwrap();
    let ip = ntcp_ip::parse(&frame[14..], false).unwrap();
    assert_eq!(ip.traffic_class >> 2, 4);
    assert_eq!(ip.traffic_class & 3, 2);
    assert_eq!(u16::from_be_bytes([frame[20], frame[21]]) & 0x4000, 0);
    assert_ne!(u16::from_be_bytes([frame[18], frame[19]]), 0);
    b.input_ip_metadata(&frame[14..], Default::default(), None);
    exchange4(&mut a, &mut b, &sa, &sb);
    assert_eq!(
        b.execute(server, Op::Read(100)).unwrap().bytes,
        vec![3; 100]
    );
}
#[test]
fn mapped_child_inherits_both_family_settings_at_handshake() {
    let (mut a, sa) = owner4(1);
    let (mut b, sb) = owner4(2);
    let listener = socket(&mut b, AF_INET6);
    b.execute(listener, Op::Set(IPPROTO_IP, IP_TOS, 16))
        .unwrap();
    b.execute(listener, Op::Set(IPPROTO_IPV6, IPV6_TCLASS, 43))
        .unwrap();
    b.execute(listener, Op::Bind("[::]:8080".parse().unwrap()))
        .unwrap();
    b.execute(listener, Op::Listen(1)).unwrap();
    let client = socket(&mut a, AF_INET6);
    assert_eq!(
        a.execute(client, Op::Connect(mapped(b.local, 8080)))
            .unwrap_err(),
        EINPROGRESS
    );
    exchange4(&mut a, &mut b, &sa, &sb);
    b.execute(listener, Op::Set(IPPROTO_IPV6, IPV6_TCLASS, 83))
        .unwrap();
    b.execute(listener, Op::Set(IPPROTO_IP, IP_TOS, 32))
        .unwrap();
    let child = b
        .execute(listener, Op::Accept(SOCK_NONBLOCK))
        .unwrap()
        .value as u64;
    assert_eq!(
        b.execute(child, Op::Get(IPPROTO_IP, IP_TOS)).unwrap().value,
        16
    );
    assert_eq!(
        b.execute(child, Op::Get(IPPROTO_IPV6, IPV6_TCLASS))
            .unwrap()
            .value,
        43
    );
    b.execute(child, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    for (tos, tclass) in [(16, 43), (16, 171), (48, 171)] {
        b.execute(child, Op::Set(IPPROTO_IPV6, IPV6_TCLASS, tclass))
            .unwrap();
        b.execute(child, Op::Set(IPPROTO_IP, IP_TOS, tos)).unwrap();
        assert_eq!(
            b.execute(child, Op::Get(IPPROTO_IPV6, IPV6_TCLASS))
                .unwrap()
                .value,
            tclass
        );
        assert_eq!(
            b.execute(child, Op::Get(IPPROTO_IP, IP_TOS)).unwrap().value,
            tos
        );
        assert_eq!(
            b.execute(listener, Op::Get(IPPROTO_IPV6, IPV6_TCLASS))
                .unwrap()
                .value,
            83
        );
        assert_eq!(
            b.execute(listener, Op::Get(IPPROTO_IP, IP_TOS))
                .unwrap()
                .value,
            32
        );
        b.execute(child, Op::Write(vec![9; 100])).unwrap();
        b.service_egress().unwrap();
        let frame = sb.lock().unwrap().sent.pop_front().unwrap();
        let ip = ntcp_ip::parse(&frame[14..], false).unwrap();
        assert_eq!(ip.traffic_class >> 2, (tos >> 2) as u8);
        assert_eq!(ip.traffic_class & 3, 2);
        assert_eq!(
            ntcp::wire::parse(ip.ip, ip.payload).unwrap().payload,
            [9; 100]
        );
        a.input_ip_metadata(&frame[14..], Default::default(), None);
        exchange4(&mut a, &mut b, &sa, &sb);
        assert_eq!(
            a.execute(client, Op::Read(100)).unwrap().bytes,
            vec![9; 100]
        );
    }
}
#[test]
fn mapped_registered_zero_copy_keeps_ipv4_wire_and_ipv6_completion() {
    let (mut a, mut b, client, server, sa, sb) = pair4(AF_INET);
    a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    let data = vec![9; 1777];
    let registration = crate::RegisteredPayload::register(Payload::from_vec(data.clone())).unwrap();
    let pointer = registration.as_slice().as_ptr();
    let (reply, rx) = mpsc::sync_channel(1);
    let mut request = Request {
        id: client,
        op: Op::Send(vec![(pointer as usize, data.len())], MSG_ZEROCOPY),
        reply,
        deadline: None,
        send: None,
        closing: None,
    };
    assert!(a.service(&mut request));
    assert_eq!(rx.recv().unwrap().unwrap().value, 1777);
    sa.lock().unwrap().block = true;
    a.service_egress().unwrap();
    assert!(sa.lock().unwrap().held.is_empty());
    sa.lock().unwrap().block = false;
    a.test_now = Some(2000);
    a.service_egress().unwrap();
    {
        let state = sa.lock().unwrap();
        let mut offset = 0;
        for packet in &state.held {
            let mut frame = packet.header.clone();
            for part in &packet.payload {
                assert_eq!(part.as_slice().as_ptr(), pointer.wrapping_add(offset));
                offset += part.len();
                frame.extend_from_slice(part.as_slice());
            }
            let eth = ntcp_ethernet::parse_ethernet(&frame).unwrap();
            assert_eq!(eth.ether_type, ntcp_ethernet::ETHERTYPE_IPV4);
            let ip = ntcp_ip::parse(eth.payload, false).unwrap();
            ntcp::wire::parse(ip.ip, ip.payload).unwrap();
            b.input_ip_metadata(eth.payload, Default::default(), None);
        }
        assert_eq!(offset, data.len());
    }
    drop(registration);
    exchange4(&mut a, &mut b, &sa, &sb);
    assert_eq!(b.execute(server, Op::Read(2000)).unwrap().bytes, data);
    a.collect_zero_copy();
    assert!(a.sockets[&client].completions.is_empty());
    sa.lock().unwrap().held.clear();
    a.collect_zero_copy();
    let mut control = [0u8; 128];
    let mut msg: msghdr = unsafe { std::mem::zeroed() };
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len();
    a.execute(client, Op::ErrorQueueTo(&mut msg as *mut _ as usize))
        .unwrap();
    let cmsg = unsafe { ptr::read_unaligned(control.as_ptr().cast::<cmsghdr>()) };
    assert_eq!((cmsg.cmsg_level, cmsg.cmsg_type), (SOL_IPV6, IPV6_RECVERR));
    assert_eq!(control[std::mem::size_of::<cmsghdr>() + 6], 0);
}
#[cfg(feature = "linux")]
#[test]
fn mapped_native_socket_abi_preserves_domain_bind_names_and_fd_alias() {
    const CHILD: &str = "NTCP_MAPPED_ABI_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","runtime::ipv6_tests::mapped_tests::mapped_native_socket_abi_preserves_domain_bind_names_and_fd_alias","--test-threads=1"]).env(CHILD,"1").status().unwrap().success());
        return;
    }
    let mut config = SocketConfig::new("external", Ipv4Addr::new(192, 0, 2, 1));
    config.io.prefix = Some(24);
    let state = Arc::new(Mutex::new(State::default()));
    crate::configure_with_packet_io(config, move || {
        Ok(crate::EthernetPacketIo {
            io: Box::new(Io(state.clone())),
            local_mac: [2; 6],
            next_hop_mac: [4; 6],
        })
    })
    .unwrap();
    unsafe {
        let fd = ntcp_managed_socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
        assert!(fd >= 0);
        let alias = dup(fd);
        assert!(alias >= 0);
        let mut out = -1i32;
        let mut len = 4;
        assert_eq!(
            getsockopt(
                alias,
                SOL_SOCKET,
                SO_DOMAIN,
                (&mut out as *mut i32).cast(),
                &mut len
            ),
            0
        );
        assert_eq!(out, AF_INET6);
        let addr = sockaddr_in6 {
            sin6_family: AF_INET6 as _,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: in6_addr {
                s6_addr: Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped().octets(),
            },
            sin6_scope_id: 0,
        };
        assert_eq!(
            ntcp_managed_bind(fd, (&addr as *const sockaddr_in6).cast(), 28),
            0
        );
        let mut raw = [0u8; 32];
        let mut len = 32;
        assert_eq!(
            ntcp_managed_getsockname(alias, raw.as_mut_ptr().cast(), &mut len),
            0
        );
        assert_eq!(len, 28);
        let actual = address(raw.as_ptr().cast(), len).unwrap();
        assert_eq!(
            actual.ip(),
            mapped(Ipv4Addr::new(192, 0, 2, 1).into(), 0).ip()
        );
        assert_ne!(actual.port(), 0);
        let on = 1i32;
        assert_eq!(
            setsockopt(
                alias,
                IPPROTO_IPV6,
                IPV6_V6ONLY,
                (&on as *const i32).cast(),
                4
            ),
            -1
        );
        assert_eq!(errno(), EINVAL);
        assert_eq!(close(alias), 0);
        assert_eq!(close(fd), 0);
    }
}
