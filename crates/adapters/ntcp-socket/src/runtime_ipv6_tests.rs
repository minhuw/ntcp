// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;
use ntcp_io::{OwnedPacket, Payload, ZeroCopyCapabilities};
use std::sync::{Arc, Mutex};
#[derive(Default)]
struct State {
    sent: VecDeque<Vec<u8>>,
    held: Vec<OwnedPacket>,
    block: bool,
}
struct Io(Arc<Mutex<State>>);
impl PacketIo for Io {
    fn layer(&self) -> ntcp_io::PacketLayer {
        ntcp_io::PacketLayer::Ethernet
    }
    fn local_ip_mtu(&self) -> std::io::Result<Option<u32>> {
        Ok(Some(1520))
    }
    fn max_packet_len(&self) -> Option<usize> {
        Some(2048)
    }
    fn receive(&mut self, _: &mut [u8]) -> std::io::Result<Option<usize>> {
        Ok(None)
    }
    fn transmit(&mut self, p: &[u8]) -> std::io::Result<TxOutcome> {
        let mut s = self.0.lock().unwrap();
        if s.block {
            return Ok(TxOutcome::WouldBlock);
        }
        s.sent.push_back(p.to_vec());
        Ok(TxOutcome::Submitted)
    }
    fn zero_copy_capabilities(&self) -> Option<ZeroCopyCapabilities> {
        Some(ZeroCopyCapabilities {
            max_payload_segments: 4,
            max_packet_len: 2048,
        })
    }
    fn zero_copy_payload_supported(&self, p: &Payload) -> bool {
        p.storage::<Vec<u8>>().is_some()
    }
    fn transmit_zero_copy(&mut self, p: &OwnedPacket) -> std::io::Result<TxOutcome> {
        let mut s = self.0.lock().unwrap();
        if s.block {
            return Ok(TxOutcome::WouldBlock);
        }
        s.held.push(OwnedPacket {
            header: p.header.clone(),
            payload: p.payload.clone(),
        });
        Ok(TxOutcome::Submitted)
    }
}
fn owner(last: u16) -> (Owner, Arc<Mutex<State>>) {
    owner_with_policy(last, false, 0)
}
fn owner_with_policy(last: u16, ecn: bool, dscp: u8) -> (Owner, Arc<Mutex<State>>) {
    owner_with_routes(last, ecn, dscp, Vec::new())
}
fn owner_with_routes(
    last: u16,
    ecn: bool,
    dscp: u8,
    segment_routes: Vec<crate::SegmentRoute>,
) -> (Owner, Arc<Mutex<State>>) {
    let local: IpAddr = format!("2001:db8::{last}").parse().unwrap();
    let mut config = SocketConfig::new("external", local);
    config.segment_routes = segment_routes;
    config.io.prefix = Some(64);
    config.tcp.dscp = dscp;
    let c = &mut config.tcp.connection;
    c.ecn = ecn;
    c.timestamps = false;
    c.delayed_ack_us = 0;
    c.mss = 1460;
    c.send_ip_payload_limit = 65515;
    c.rto_min_us = 200000;
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
fn new(o: &mut Owner) -> u64 {
    o.execute(0, Op::New(SOCK_NONBLOCK)).unwrap().value as u64
}
fn exchange(a: &mut Owner, b: &mut Owner, sa: &Arc<Mutex<State>>, sb: &Arc<Mutex<State>>) {
    for _ in 0..16 {
        let mut progress = false;
        for reverse in [false, true] {
            let (from, to, state) = if reverse {
                (&mut *b, &mut *a, sb)
            } else {
                (&mut *a, &mut *b, sa)
            };
            from.service_egress().unwrap();
            let mut state = state.lock().unwrap();
            while let Some(frame) = state.sent.pop_front() {
                let eth = ntcp_ethernet::parse_ethernet(&frame).unwrap();
                assert_eq!(eth.ether_type, ntcp_ethernet::ETHERTYPE_IPV6);
                let ip = ntcp_ip6::parse(eth.payload).unwrap();
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
    panic!("output did not quiesce");
}
type Pair = (Owner, Owner, u64, u64, Arc<Mutex<State>>, Arc<Mutex<State>>);
fn pair() -> Pair {
    pair_with_ecn(false)
}
fn pair_with_ecn(ecn: bool) -> Pair {
    let (mut a, sa) = owner_with_policy(1, ecn, 0);
    let (mut b, sb) = owner_with_policy(2, ecn, 0);
    let l = new(&mut b);
    b.execute(l, Op::Bind("[::]:8080".parse().unwrap()))
        .unwrap();
    b.execute(l, Op::Listen(2)).unwrap();
    let client = new(&mut a);
    assert_eq!(
        a.execute(client, Op::Connect("[2001:db8::2]:8080".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    exchange(&mut a, &mut b, &sa, &sb);
    let server = b.execute(l, Op::Accept(0)).unwrap().value as u64;
    (a, b, client, server, sa, sb)
}
fn cid(o: &Owner, id: u64) -> ConnectionId {
    let Handle::Connection(c) = o.sockets[&id].handle else {
        panic!()
    };
    c
}
#[test]
fn native_ipv6_handshake_data_half_close_and_family_policy() {
    let (mut a, mut b, client, server, sa, sb) = pair();
    assert_eq!(
        a.execute(client, Op::Get(SOL_SOCKET, SO_DOMAIN))
            .unwrap()
            .value,
        AF_INET6
    );
    assert_eq!(
        a.execute(client, Op::Get(IPPROTO_IPV6, IPV6_V6ONLY))
            .unwrap()
            .value,
        1
    );
    assert_eq!(
        a.execute(client, Op::Get(IPPROTO_IP, IP_TOS)).unwrap_err(),
        ENOPROTOOPT
    );
    a.execute(client, Op::Set(IPPROTO_IPV6, IPV6_TCLASS, 40))
        .unwrap();
    let initial = a
        .host
        .as_ref()
        .unwrap()
        .binding(cid(&a, client))
        .unwrap()
        .snapshot;
    assert_eq!(initial.first_hop_mtu(), 1520);
    assert_eq!(initial.ip_packet_budget(), Ok(1520));
    assert_eq!(
        a.endpoint
            .path_mtu_info(cid(&a, client))
            .unwrap()
            .unwrap()
            .current_mtu,
        1280
    );
    assert_eq!(
        a.endpoint.transport_info(cid(&a, client)).unwrap().mss,
        1220 // Selected initial IPv6 PMTU, with complete base/TCP headers.
    );
    a.execute(client, Op::Write(vec![3; 1800])).unwrap();
    b.execute(server, Op::Write(vec![4; 100])).unwrap();
    exchange(&mut a, &mut b, &sa, &sb);
    assert_eq!(
        b.execute(server, Op::Read(2000)).unwrap().bytes,
        vec![3; 1800]
    );
    assert_eq!(
        a.execute(client, Op::Read(200)).unwrap().bytes,
        vec![4; 100]
    );
    a.execute(client, Op::Shutdown(SHUT_WR)).unwrap();
    exchange(&mut a, &mut b, &sa, &sb);
    assert_eq!(b.execute(server, Op::Read(1)).unwrap().value, 0);
    b.execute(server, Op::Shutdown(SHUT_WR)).unwrap();
    exchange(&mut a, &mut b, &sa, &sb);
    assert_eq!(a.execute(client, Op::Read(1)).unwrap().value, 0);
    let fresh = new(&mut a);
    assert_eq!(
        a.execute(fresh, Op::Connect("192.0.2.1:80".parse().unwrap()))
            .unwrap_err(),
        EAFNOSUPPORT
    );
    assert_eq!(
        a.execute(fresh, Op::Connect("[::ffff:192.0.2.1]:80".parse().unwrap()))
            .unwrap_err(),
        ENETUNREACH
    );
    a.execute(fresh, Op::Set(IPPROTO_IPV6, IPV6_V6ONLY, 0))
        .unwrap();
    assert_eq!(
        a.execute(fresh, Op::Connect("[::ffff:192.0.2.1]:80".parse().unwrap()))
            .unwrap_err(),
        ENETUNREACH
    );
}
#[test]
fn native_ipv6_retransmits_at_core_deadline() {
    let (mut a, mut b, client, server, sa, sb) = pair();
    a.execute(client, Op::Write(vec![7; 1000])).unwrap();
    a.service_egress().unwrap();
    let original = sa.lock().unwrap().sent.pop_front().unwrap();
    let ip = ntcp_ip6::parse(&original[14..]).unwrap();
    let original_tcp = ntcp::wire::parse(ip.ip, ip.payload).unwrap();
    let deadline = a.endpoint.next_deadline().unwrap();
    a.test_now = Some(deadline);
    a.endpoint.on_timeout(deadline, BUDGET).unwrap();
    a.service_egress().unwrap();
    let retransmission = sa.lock().unwrap().sent.pop_front().unwrap();
    let ip = ntcp_ip6::parse(&retransmission[14..]).unwrap();
    let tcp = ntcp::wire::parse(ip.ip, ip.payload).unwrap();
    assert_eq!(tcp.header.sequence, original_tcp.header.sequence);
    assert_eq!(tcp.payload, original_tcp.payload);
    b.input_ip_metadata(&retransmission[14..], Default::default(), None);
    exchange(&mut a, &mut b, &sa, &sb);
    assert_eq!(
        b.execute(server, Op::Read(1000)).unwrap().bytes,
        vec![7; 1000]
    );
}
fn feedback(packet: &[u8], kind: u8, code: u8, mtu: u32) -> Vec<u8> {
    let q = ntcp_ip6::parse(packet).unwrap();
    let ip = ntcp::IpMetadata {
        source: q.ip.destination,
        destination: q.ip.source,
    };
    let mut out = vec![0; 48 + packet.len()];
    out[0] = 0x60;
    let n = (out.len() - 40) as u16;
    out[4..6].copy_from_slice(&n.to_be_bytes());
    out[6] = 58;
    out[7] = 64;
    let (IpAddr::V6(source), IpAddr::V6(destination)) = (ip.source, ip.destination) else {
        panic!()
    };
    out[8..24].copy_from_slice(&source.octets());
    out[24..40].copy_from_slice(&destination.octets());
    out[40] = kind;
    out[41] = code;
    out[44..48].copy_from_slice(&mtu.to_be_bytes());
    out[48..].copy_from_slice(packet);
    let sum = ntcp_icmp::icmpv6_checksum(ip, &out[40..]).unwrap();
    out[42..44].copy_from_slice(&sum.to_be_bytes());
    out
}
#[test]
fn native_ipv6_icmp_errors_correlate_and_pmtu_obeys_floor() {
    for (kind, code, error) in [
        (1, 0, Some(ntcp::NetworkError::SoftUnreachable)),
        (1, 3, Some(ntcp::NetworkError::SoftUnreachable)),
        (3, 0, Some(ntcp::NetworkError::TimeExceeded)),
        (4, 0, Some(ntcp::NetworkError::ParameterProblem)),
        (1, 2, Some(ntcp::NetworkError::HardUnreachable)),
        (1, 4, Some(ntcp::NetworkError::HardUnreachable)),
        (2, 0, None),
    ] {
        let (mut a, _, client, _, sa, _) = pair();
        let id = cid(&a, client);
        a.execute(client, Op::Write(vec![7; 1460])).unwrap();
        a.service_egress().unwrap();
        let packet = sa.lock().unwrap().sent.pop_front().unwrap();
        let f = feedback(&packet[14..], kind, code, 1280);
        assert_eq!(
            ntcp_icmp::decode_icmp(&f).unwrap().ipv6_network_error(),
            error
        );
        let before = a.endpoint.transport_info(id).unwrap();
        let mut bad = f.clone();
        bad[42] ^= 1;
        a.input_ip_metadata(&bad, Default::default(), None);
        assert_eq!(a.endpoint.transport_info(id).unwrap(), before);
        a.input_ip_metadata(&f, Default::default(), None);
        if kind == 2 {
            assert_eq!(
                a.endpoint.path_mtu_info(id).unwrap().unwrap().current_mtu,
                1280
            );
            a.service_egress().unwrap();
            let repair = sa.lock().unwrap().sent.pop_front().unwrap();
            assert!(repair.len() <= 1280 + 14);
        } else if error == Some(ntcp::NetworkError::HardUnreachable) {
            assert_eq!(a.endpoint.state(id).unwrap(), ntcp::State::Closed);
        } else {
            assert_eq!(a.endpoint.state(id).unwrap(), ntcp::State::Established);
            a.events();
            assert_ne!(
                a.execute(client, Op::Get(SOL_SOCKET, SO_ERROR))
                    .unwrap()
                    .value,
                0
            );
        }
    }
}
#[test]
fn native_ipv6_shared_payload_survives_backpressure_ack_and_async_reclaim() {
    let (mut a, mut b, client, server, sa, sb) = pair();
    a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    let data = vec![9; 1777];
    let registered = crate::RegisteredPayload::register(Payload::from_vec(data.clone())).unwrap();
    let pointer = registered.as_slice().as_ptr();
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
    let mut wire = Vec::new();
    {
        let s = sa.lock().unwrap();
        let mut offset = 0;
        for p in &s.held {
            let mut frame = p.header.clone();
            for part in &p.payload {
                assert_eq!(part.as_slice().as_ptr(), pointer.wrapping_add(offset));
                offset += part.len();
                frame.extend_from_slice(part.as_slice());
            }
            let eth = ntcp_ethernet::parse_ethernet(&frame).unwrap();
            assert_eq!(eth.ether_type, ntcp_ethernet::ETHERTYPE_IPV6);
            let ip = ntcp_ip6::parse(eth.payload).unwrap();
            ntcp::wire::parse(ip.ip, ip.payload).unwrap();
            wire.push(frame);
        }
        assert_eq!(offset, data.len());
    }
    drop(registered);
    for frame in wire {
        b.input_ip_metadata(&frame[14..], Default::default(), None);
    }
    exchange(&mut a, &mut b, &sa, &sb);
    assert_eq!(b.execute(server, Op::Read(2000)).unwrap().bytes, data);
    a.collect_zero_copy();
    assert!(a.sockets[&client].completions.is_empty());
    sa.lock().unwrap().held.clear();
    a.collect_zero_copy();
    assert_eq!(
        a.sockets[&client].completions.front(),
        Some(&Completion::SharedZeroCopy(0, 0, false))
    );
    let mut control = [0u8; 128];
    let mut msg: msghdr = unsafe { std::mem::zeroed() };
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len();
    a.execute(client, Op::ErrorQueueTo(&mut msg as *mut _ as usize))
        .unwrap();
    let header = unsafe { ptr::read_unaligned(control.as_ptr().cast::<cmsghdr>()) };
    assert_eq!(header.cmsg_level, SOL_IPV6);
    assert_eq!(header.cmsg_type, IPV6_RECVERR);
    assert_eq!(control[std::mem::size_of::<cmsghdr>() + 6], 0);
}
#[test]
fn ipv6_sockaddr_roundtrip_and_bounded_output() {
    let addr: SocketAddr = "[2001:db8::1234]:54321".parse().unwrap();
    let mut raw: [u8; 32] = [0xa5; 32];
    let mut n = 28;
    unsafe {
        output_addr(addr, raw.as_mut_ptr().cast(), &mut n).unwrap();
        assert_eq!(address(raw.as_ptr().cast(), n).unwrap(), addr);
    }
    assert_eq!(n, 28);
    assert_eq!(&raw[28..], &[0xa5; 4]);
    raw.fill(0xa5);
    n = 7;
    unsafe {
        output_addr(addr, raw.as_mut_ptr().cast(), &mut n).unwrap();
    }
    assert_eq!(n, 28);
    assert!(raw[7..].iter().all(|&b| b == 0xa5));
}

#[test]
fn native_ipv6_configuration_routes_and_runtime_family_are_real() {
    let config=SocketConfig::parse("io.interface=ntcp0\nio.address=2001:db8::1\nio.prefix=64\nroute.2001:db8::2.mtu=1280\nroute.2001:db8::2.advertised_mss=1220\n").unwrap();
    assert_eq!(config.io.address, "2001:db8::1".parse::<IpAddr>().unwrap());
    assert_eq!(config.routes[0].0, "2001:db8::2".parse::<IpAddr>().unwrap());
    assert!(
        SocketConfig::new("ntcp0", "2001:db8::1".parse::<IpAddr>().unwrap())
            .validate()
            .is_ok()
    );
    assert!(
        SocketConfig::parse("io.interface=ntcp0\nio.address=2001:db8::1\nio.prefix=129\n").is_err()
    );
    let runtime = Runtime::spawn(|| Ok(owner(1).0), false).unwrap();
    assert_eq!(runtime.family, AF_INET6);
    let id = runtime.call(0, Op::New(SOCK_NONBLOCK)).unwrap().value as u64;
    assert_eq!(
        runtime
            .call(id, Op::Get(SOL_SOCKET, SO_DOMAIN))
            .unwrap()
            .value,
        AF_INET6
    );
    runtime.stop();
}

#[test]
fn ipv6_freebind_aliases_share_nonlocal_bind_permission() {
    let (mut a, _) = owner(1);
    let nonlocal: SocketAddr = "[2001:db8:1::7]:18000".parse().unwrap();
    let id = new(&mut a);
    for (level, name) in [(IPPROTO_IP, IP_FREEBIND), (IPPROTO_IPV6, IPV6_FREEBIND)] {
        assert_eq!(a.execute(id, Op::Get(level, name)).unwrap().value, 0);
    }
    assert_eq!(
        a.execute(id, Op::Bind(nonlocal)).unwrap_err(),
        EADDRNOTAVAIL
    );
    a.execute(id, Op::Set(IPPROTO_IP, IP_FREEBIND, 1)).unwrap();
    assert_eq!(
        a.execute(id, Op::Get(IPPROTO_IPV6, IPV6_FREEBIND))
            .unwrap()
            .value,
        1
    );
    a.execute(id, Op::Set(IPPROTO_IPV6, IPV6_FREEBIND, 0))
        .unwrap();
    assert_eq!(
        a.execute(id, Op::Get(IPPROTO_IP, IP_FREEBIND))
            .unwrap()
            .value,
        0
    );
    assert_eq!(
        a.execute(id, Op::Bind(nonlocal)).unwrap_err(),
        EADDRNOTAVAIL
    );
    a.execute(id, Op::Set(IPPROTO_IPV6, IPV6_FREEBIND, 1))
        .unwrap();
    assert_eq!(
        a.execute(id, Op::Get(IPPROTO_IP, IP_FREEBIND))
            .unwrap()
            .value,
        1
    );
    a.execute(id, Op::Bind(nonlocal)).unwrap();
    assert_eq!(a.execute(id, Op::Name(false)).unwrap().addr, Some(nonlocal));
    // Bind permission does not assign a new backend source address.
    assert!(
        a.execute(id, Op::Connect("[2001:db8::2]:8080".parse().unwrap()))
            .is_err()
    );
    a.execute(id, Op::Listen(1)).unwrap();
    let fresh = new(&mut a);
    assert_eq!(
        a.execute(fresh, Op::Get(IPPROTO_IP, IP_FREEBIND))
            .unwrap()
            .value,
        0
    );
    a.execute(fresh, Op::Set(IPPROTO_IP, IP_FREEBIND, 1))
        .unwrap();
    assert_eq!(
        a.execute(fresh, Op::Bind("192.0.2.1:80".parse().unwrap()))
            .unwrap_err(),
        EAFNOSUPPORT
    );
    assert_eq!(
        a.execute(fresh, Op::Bind("[::ffff:192.0.2.1]:80".parse().unwrap()))
            .unwrap_err(),
        EINVAL
    );
    assert_eq!(
        a.execute(fresh, Op::Get(IPPROTO_IPV6, IPV6_V6ONLY))
            .unwrap()
            .value,
        1
    );
    for name in [IP_TOS, IP_MTU_DISCOVER, IP_MTU] {
        assert_eq!(
            a.execute(fresh, Op::Set(IPPROTO_IP, name, 1)).unwrap_err(),
            ENOPROTOOPT
        );
        assert_eq!(
            a.execute(fresh, Op::Get(IPPROTO_IP, name)).unwrap_err(),
            ENOPROTOOPT
        );
    }
}

#[test]
fn ipv6_freebind_listener_child_keeps_handshake_snapshot_across_alias_change() {
    let (mut a, sa) = owner(1);
    let (mut b, sb) = owner(2);
    let listener = new(&mut b);
    b.execute(listener, Op::Set(IPPROTO_IP, IP_FREEBIND, 1))
        .unwrap();
    b.execute(listener, Op::Bind("[::]:18001".parse().unwrap()))
        .unwrap();
    b.execute(listener, Op::Listen(1)).unwrap();
    let client = new(&mut a);
    assert_eq!(
        a.execute(client, Op::Connect("[2001:db8::2]:18001".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    exchange(&mut a, &mut b, &sa, &sb);
    b.execute(listener, Op::Set(IPPROTO_IPV6, IPV6_FREEBIND, 0))
        .unwrap();
    let accepted = b.execute(listener, Op::Accept(0)).unwrap();
    assert_eq!(accepted.addr.unwrap().ip(), a.local);
    let child = accepted.value as u64;
    for (level, name) in [(IPPROTO_IP, IP_FREEBIND), (IPPROTO_IPV6, IPV6_FREEBIND)] {
        assert_eq!(b.execute(child, Op::Get(level, name)).unwrap().value, 1);
        assert_eq!(b.execute(listener, Op::Get(level, name)).unwrap().value, 0);
    }
    b.execute(child, Op::Write(vec![7; 100])).unwrap();
    exchange(&mut a, &mut b, &sa, &sb);
    assert_eq!(
        a.execute(client, Op::Read(100)).unwrap().bytes,
        vec![7; 100]
    );
}

#[cfg(feature = "linux")]
#[test]
fn ipv6_freebind_native_abi_aliases_keep_option_widths_and_fd_aliases() {
    const CHILD: &str = "NTCP_IPV6_FREEBIND_ABI_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "runtime::ipv6_tests::ipv6_freebind_native_abi_aliases_keep_option_widths_and_fd_aliases", "--test-threads=1"])
            .env(CHILD,"1").status().unwrap().success());
        return;
    }
    assert!(
        RUNTIME
            .set(Ok(Runtime::spawn(|| Ok(owner(1).0), false).unwrap()))
            .is_ok()
    );
    let id = call(0, Op::New(SOCK_NONBLOCK)).unwrap().value as u64;
    let (fd, t) = token(SOCK_CLOEXEC).unwrap();
    install(fd, t, id).unwrap();
    unsafe {
        let alias = dup(fd);
        assert!(alias >= 0);
        let one = 1u8;
        assert_eq!(
            setsockopt(fd, IPPROTO_IP, IP_FREEBIND, (&one as *const u8).cast(), 1),
            0
        );
        for (level, name) in [(IPPROTO_IP, IP_FREEBIND), (IPPROTO_IPV6, IPV6_FREEBIND)] {
            let mut value = -1i32;
            let mut len = 4;
            assert_eq!(
                getsockopt(
                    alias,
                    level,
                    name,
                    (&mut value as *mut i32).cast(),
                    &mut len
                ),
                0
            );
            assert_eq!((value, len), (1, 4));
        }
        assert_eq!(
            setsockopt(
                alias,
                IPPROTO_IPV6,
                IPV6_FREEBIND,
                (&one as *const u8).cast(),
                1
            ),
            -1
        );
        assert_eq!(errno(), EINVAL);
        assert_eq!(setsockopt(fd, IPPROTO_IP, IP_FREEBIND, ptr::null(), 4), -1);
        assert_eq!(errno(), EFAULT);
        let zero = 0i32;
        assert_eq!(
            setsockopt(
                alias,
                IPPROTO_IPV6,
                IPV6_FREEBIND,
                (&zero as *const i32).cast(),
                4
            ),
            0
        );
        let mut value = -1i32;
        let mut len = 4;
        assert_eq!(
            getsockopt(
                fd,
                IPPROTO_IP,
                IP_FREEBIND,
                (&mut value as *mut i32).cast(),
                &mut len
            ),
            0
        );
        assert_eq!((value, len), (0, 4));
        assert_eq!(close(alias), 0);
        assert_eq!(close(fd), 0);
    }
}

#[path = "runtime_tclass_tests.rs"]
mod tclass_tests;

#[path = "runtime_mapped_tests.rs"]
mod mapped_tests;

#[test]
fn native_ipv6_administrative_small_packet_route_updates_keep_real_link_mtu() {
    let (mut a, sa) = owner(1);
    let (mut b, sb) = owner(2);
    let remote = "2001:db8::2".parse().unwrap();
    let policy = ntcp::RoutePolicy {
        mtu: Some(660),
        advertised_mss: Some(600),
        initial_search_low: Some(572),
        ..Default::default()
    };
    a.execute(0, Op::SetDestinationRoute(remote, Some(policy)))
        .unwrap();
    let listener = new(&mut b);
    b.execute(listener, Op::Bind("[::]:8080".parse().unwrap()))
        .unwrap();
    b.execute(listener, Op::Listen(2)).unwrap();
    let client = new(&mut a);
    assert_eq!(
        a.execute(client, Op::Connect("[2001:db8::2]:8080".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    exchange(&mut a, &mut b, &sa, &sb);
    let server = b.execute(listener, Op::Accept(0)).unwrap().value as u64;
    let id = cid(&a, client);
    let before = a.endpoint.path_mtu_info(id).unwrap().unwrap();
    assert_eq!(before.first_hop_mtu, 1520);
    assert_eq!(before.current_mtu, 660);
    a.execute(
        0,
        Op::SetDestinationRoute(
            remote,
            Some(ntcp::RoutePolicy {
                mtu: Some(1520),
                ..policy
            }),
        ),
    )
    .unwrap();
    assert_eq!(
        a.endpoint.path_mtu_info(id).unwrap().unwrap().current_mtu,
        660
    );
    a.execute(client, Op::Write(vec![7; 20_000])).unwrap();
    exchange(&mut a, &mut b, &sa, &sb);
    assert_eq!(
        b.execute(server, Op::Read(20_000)).unwrap().bytes,
        vec![7; 20_000]
    );
    let info = a.endpoint.path_mtu_info(id).unwrap().unwrap();
    assert_eq!(info.first_hop_mtu, 1520);
    assert!(info.current_mtu > 660);
    assert!(info.current_mtu <= 1520);
}

// The configured SR route is installed with the Host over the interface's
// link and forwarder. A connection selecting it places each segment after
// the route's Segment Routing Header (base Destination Address S1, Segment
// List[0] the peer, a checksum over the peer), sizes it with the complete
// header, and progresses once the final segment endpoint has processed it
// (Segments Left 0, Destination Address the peer).
#[test]
fn configured_segment_route_carries_tcp_after_its_srh() {
    let destination: ntcp_host::path::IpPrefix = "2001:db8::2/128".parse().unwrap();
    let s1: std::net::Ipv6Addr = "2001:db8:5::1".parse().unwrap();
    let peer: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
    let (mut a, sa) = owner_with_routes(
        1,
        false,
        0,
        vec![crate::SegmentRoute {
            destination,
            segments: vec![s1],
        }],
    );
    let host = a.host.as_ref().unwrap();
    let route = host.paths().select_route(destination).unwrap();
    assert_eq!(host.paths().route_segments(route).unwrap(), &[s1]);
    let default = host.paths().select_route("::/0".parse().unwrap()).unwrap();
    assert_eq!(
        host.paths().route(route).unwrap().next_hop,
        host.paths().route(default).unwrap().next_hop
    );
    let (mut b, sb) = owner(2);
    let l = new(&mut b);
    b.execute(l, Op::Bind("[::]:8080".parse().unwrap()))
        .unwrap();
    b.execute(l, Op::Listen(2)).unwrap();
    let client = new(&mut a);
    assert_eq!(
        a.execute(client, Op::Connect("[2001:db8::2]:8080".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    // The SRH of one segment: H = 40 + 8 + 16 * 2.
    assert_eq!(a.endpoint.managed_path(cid(&a, client)).unwrap().ip_header_len, 80);
    let mut largest = 0;
    let mut exchange = |a: &mut Owner, b: &mut Owner| {
        for _ in 0..32 {
            let mut progress = false;
            a.service_egress().unwrap();
            while let Some(frame) = sa.lock().unwrap().sent.pop_front() {
                // Link framing only: the chain is checked below.
                assert_eq!(&frame[12..14], &ntcp_ethernet::ETHERTYPE_IPV6.to_be_bytes());
                let len = ntcp_ip6::ipv6_fragment_bounds(&frame[14..]).unwrap();
                let ip = &frame[14..14 + len];
                assert_eq!((ip[6], &ip[24..40]), (43, &s1.octets()[..]));
                assert_eq!(&ip[40..48], &[6, 4, 4, 1, 1, 0, 0, 0]);
                assert_eq!(&ip[48..64], &peer.octets());
                assert_eq!(&ip[64..80], &s1.octets());
                let (meta, header, total, _) = ntcp_ip6::quote_header(ip).unwrap();
                assert_eq!(total, ip.len());
                ntcp::wire::parse(meta, &ip[header..]).unwrap();
                largest = largest.max(ip.len());
                let mut arrived = ip.to_vec();
                arrived[43] = 0;
                arrived[24..40].copy_from_slice(&peer.octets());
                b.input_ip_metadata(&arrived, Default::default(), None);
                progress = true;
            }
            b.service_egress().unwrap();
            while let Some(frame) = sb.lock().unwrap().sent.pop_front() {
                let ip = ntcp_ethernet::parse_ethernet(&frame).unwrap().payload;
                assert_eq!(ip[6], 6);
                a.input_ip_metadata(ip, Default::default(), None);
                progress = true;
            }
            a.events();
            b.events();
            if !progress {
                return;
            }
        }
        panic!("output did not quiesce");
    };
    exchange(&mut a, &mut b);
    let server = b.execute(l, Op::Accept(0)).unwrap().value as u64;
    // The current packet size less H and the TCP header.
    let mtu = a
        .endpoint
        .path_mtu_info(cid(&a, client))
        .unwrap()
        .unwrap()
        .current_mtu as usize;
    assert_eq!(
        a.endpoint.transport_info(cid(&a, client)).unwrap().mss as usize,
        mtu - 80 - 20
    );
    let payload: Vec<u8> = (0..6000).map(|i| (i % 241) as u8).collect();
    a.execute(client, Op::Write(payload.clone())).unwrap();
    exchange(&mut a, &mut b);
    assert_eq!(b.execute(server, Op::Read(8000)).unwrap().bytes, payload);
    // Full segments fill the current packet size with H.
    assert_eq!(largest, mtu);
}

// A stateless reply (the reset for a SYN to a closed port) to a peer the SR
// route covers is selected before its path is known: once its authority
// names the path, the segment is moved after the route's Segment Routing
// Header and leaves toward S1 with a checksum over the peer.
#[test]
fn stateless_reply_on_a_segment_route_is_placed_after_its_srh() {
    let s1: std::net::Ipv6Addr = "2001:db8:5::1".parse().unwrap();
    let peer: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
    let (mut a, sa) = owner_with_routes(
        1,
        false,
        0,
        vec![crate::SegmentRoute {
            destination: "2001:db8::2/128".parse().unwrap(),
            segments: vec![s1],
        }],
    );
    let ip = ntcp::IpMetadata {
        source: peer.into(),
        destination: "2001:db8::1".parse().unwrap(),
    };
    let mut packet = [0; 100];
    let tcp_len = ntcp::wire::encode(
        ip,
        ntcp::wire::Header {
            source_port: 40000,
            destination_port: 9,
            sequence: 1,
            acknowledgment: 0,
            flags: ntcp::wire::SYN,
            window: 1024,
            urgent_pointer: 0,
        },
        &[],
        &[],
        &mut packet[40..],
    )
    .unwrap();
    let header = ntcp_ip6::Header {
        ip,
        hop_limit: 64,
        dscp: 0,
        ecn: 0,
    };
    let len = ntcp_ip6::encode_datagram(&mut packet, header, 6, tcp_len).unwrap();
    a.input_ip_metadata(&packet[..len], Default::default(), None);
    a.service_egress().unwrap();
    let frame = sa.lock().unwrap().sent.pop_front().unwrap();
    assert!(sa.lock().unwrap().sent.is_empty());
    let len = ntcp_ip6::ipv6_fragment_bounds(&frame[14..]).unwrap();
    let ip = &frame[14..14 + len];
    assert_eq!((ip[6], &ip[24..40]), (43, &s1.octets()[..]));
    assert_eq!(&ip[40..48], &[6, 4, 4, 1, 1, 0, 0, 0]);
    assert_eq!(&ip[48..64], &peer.octets());
    assert_eq!(&ip[64..80], &s1.octets());
    let (meta, header, total, _) = ntcp_ip6::quote_header(ip).unwrap();
    assert_eq!((meta.destination, header, total), (peer.into(), 80, ip.len()));
    let reset = ntcp::wire::parse(meta, &ip[header..]).unwrap();
    assert_ne!(reset.header.flags & ntcp::wire::RST, 0);
}

// Shared (zero-copy) output on a two-segment SR route. The header buffer
// built ahead of the caller's payload holds the Ethernet header, the base
// header, the Segment Routing Header (H = 40 + 8 + 16 * 3) and the TCP
// header with timestamps, more than the base-header reservation; the
// payload parts are the caller's registered bytes, and the stream reaches
// the peer once the final segment endpoint has processed it.
#[test]
fn shared_payload_on_a_segment_route_carries_the_srh() {
    let s1: std::net::Ipv6Addr = "2001:db8:5::1".parse().unwrap();
    let s2: std::net::Ipv6Addr = "2001:db8:6::1".parse().unwrap();
    let peer: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
    let owner_ts = |last: u16, segment_routes: Vec<crate::SegmentRoute>| {
        let local: IpAddr = format!("2001:db8::{last}").parse().unwrap();
        let mut config = SocketConfig::new("external", local);
        config.segment_routes = segment_routes;
        config.io.prefix = Some(64);
        let c = &mut config.tcp.connection;
        c.timestamps = true;
        c.delayed_ack_us = 0;
        c.mss = 1460;
        c.send_ip_payload_limit = 65515;
        c.rto_min_us = 200000;
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
    };
    let (mut a, sa) = owner_ts(
        1,
        vec![crate::SegmentRoute {
            destination: "2001:db8::2/128".parse().unwrap(),
            segments: vec![s1, s2],
        }],
    );
    let (mut b, sb) = owner_ts(2, Vec::new());
    let l = new(&mut b);
    b.execute(l, Op::Bind("[::]:8080".parse().unwrap()))
        .unwrap();
    b.execute(l, Op::Listen(2)).unwrap();
    let client = new(&mut a);
    assert_eq!(
        a.execute(client, Op::Connect("[2001:db8::2]:8080".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    assert_eq!(a.endpoint.managed_path(cid(&a, client)).unwrap().ip_header_len, 96);
    // A's frames, copied or shared, as the final segment endpoint forwards
    // them to B; B's replies reach A directly. Returns A's shared headers.
    let exchange = |a: &mut Owner, b: &mut Owner, pointer: Option<*const u8>| {
        let mut shared = Vec::new();
        let mut offset = 0;
        for _ in 0..32 {
            let mut progress = false;
            a.service_egress().unwrap();
            let frames: Vec<Vec<u8>> = {
                let mut s = sa.lock().unwrap();
                let mut frames: Vec<Vec<u8>> = s.sent.drain(..).collect();
                for p in s.held.drain(..) {
                    shared.push(p.header.len());
                    let mut frame = p.header.clone();
                    for part in &p.payload {
                        assert_eq!(Some(part.as_slice().as_ptr()), pointer.map(|p| p.wrapping_add(offset)));
                        offset += part.len();
                        frame.extend_from_slice(part.as_slice());
                    }
                    frames.push(frame);
                }
                frames
            };
            for frame in frames {
                let len = ntcp_ip6::ipv6_fragment_bounds(&frame[14..]).unwrap();
                let ip = &frame[14..14 + len];
                assert_eq!((ip[6], &ip[24..40]), (43, &s1.octets()[..]));
                assert_eq!(&ip[40..48], &[6, 6, 4, 2, 2, 0, 0, 0]);
                assert_eq!(&ip[48..64], &peer.octets());
                assert_eq!(&ip[64..80], &s2.octets());
                assert_eq!(&ip[80..96], &s1.octets());
                let (meta, header, total, _) = ntcp_ip6::quote_header(ip).unwrap();
                assert_eq!((meta.destination, header, total), (peer.into(), 96, ip.len()));
                ntcp::wire::parse(meta, &ip[header..]).unwrap();
                let mut arrived = ip.to_vec();
                arrived[43] = 0;
                arrived[24..40].copy_from_slice(&peer.octets());
                b.input_ip_metadata(&arrived, Default::default(), None);
                progress = true;
            }
            b.service_egress().unwrap();
            while let Some(frame) = sb.lock().unwrap().sent.pop_front() {
                let ip = ntcp_ethernet::parse_ethernet(&frame).unwrap().payload;
                a.input_ip_metadata(ip, Default::default(), None);
                progress = true;
            }
            a.events();
            b.events();
            if !progress {
                return shared;
            }
        }
        panic!("output did not quiesce");
    };
    assert!(exchange(&mut a, &mut b, None).is_empty());
    let server = b.execute(l, Op::Accept(0)).unwrap().value as u64;
    a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    let data: Vec<u8> = (0..1777).map(|i| (i % 239) as u8).collect();
    let registered = crate::RegisteredPayload::register(Payload::from_vec(data.clone())).unwrap();
    let pointer = registered.as_slice().as_ptr();
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
    let shared = exchange(&mut a, &mut b, Some(pointer));
    // Ethernet, H and the TCP header with timestamps lead every payload.
    assert!(!shared.is_empty());
    assert!(shared.iter().all(|&len| len == 14 + 96 + 32), "{shared:?}");
    assert_eq!(b.execute(server, Op::Read(2000)).unwrap().bytes, data);
    drop(registered);
}
