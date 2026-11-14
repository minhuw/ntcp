// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;
use ntcp_io::{OwnedPacket, Payload, ZeroCopyCapabilities};
use std::sync::{Arc, Mutex};
#[derive(Default)]
struct State {
    sent: VecDeque<Vec<u8>>,
    held: Vec<OwnedPacket>,
    block: bool,
    // This port's link MTU, 1520 unless set.
    mtu: Option<u32>,
    // When set, the number of further packets accepted before WouldBlock.
    allow: Option<usize>,
    // A copying backend, without zero-copy output.
    copying: bool,
}
impl State {
    fn admits(&mut self) -> bool {
        if self.block || self.allow == Some(0) {
            return false;
        }
        if let Some(allow) = &mut self.allow {
            *allow -= 1;
        }
        true
    }
}
struct Io(Arc<Mutex<State>>);
impl PacketIo for Io {
    fn layer(&self) -> ntcp_io::PacketLayer {
        ntcp_io::PacketLayer::Ethernet
    }
    fn local_ip_mtu(&self) -> std::io::Result<Option<u32>> {
        Ok(Some(self.0.lock().unwrap().mtu.unwrap_or(1520)))
    }
    fn max_packet_len(&self) -> Option<usize> {
        Some(2048)
    }
    fn receive(&mut self, _: &mut [u8]) -> std::io::Result<Option<usize>> {
        Ok(None)
    }
    fn transmit(&mut self, p: &[u8]) -> std::io::Result<TxOutcome> {
        let mut s = self.0.lock().unwrap();
        if !s.admits() {
            return Ok(TxOutcome::WouldBlock);
        }
        s.sent.push_back(p.to_vec());
        Ok(TxOutcome::Submitted)
    }
    fn zero_copy_capabilities(&self) -> Option<ZeroCopyCapabilities> {
        if self.0.lock().unwrap().copying {
            return None;
        }
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
        if !s.admits() {
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
    owner_at(
        format!("2001:db8::{last}").parse().unwrap(),
        ecn,
        dscp,
        segment_routes,
    )
}
// A legacy fixed-next-hop external port (interface index 1) owning `local`.
fn owner_at(
    local: IpAddr,
    ecn: bool,
    dscp: u8,
    segment_routes: Vec<crate::SegmentRoute>,
) -> (Owner, Arc<Mutex<State>>) {
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
            next_hop_mac: Some([4; 6]),
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
            .env(CHILD,"1").child_passed());
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
                next_hop_mac: Some([4; 6]),
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

fn v6(ip: &str, port: u16, scope: u32) -> SocketAddr {
    std::net::SocketAddrV6::new(ip.parse().unwrap(), port, 0, scope).into()
}
// Each port owns its own link-local address, scoped by that port's link.
fn link_local_owner(last: u16) -> (Owner, Arc<Mutex<State>>) {
    owner_at(format!("fe80::{last}").parse().unwrap(), false, 0, Vec::new())
}
fn link_local_listener(b: &mut Owner, bind: SocketAddr, v6only: Option<i32>) -> u64 {
    let l = new(b);
    if let Some(v6only) = v6only {
        b.execute(l, Op::Set(IPPROTO_IPV6, IPV6_V6ONLY, v6only))
            .unwrap();
    }
    b.execute(l, Op::Bind(bind)).unwrap();
    b.execute(l, Op::Listen(4)).unwrap();
    l
}

#[test]
fn scoped_sockaddr_round_trips_raw_scope_and_still_rejects_flowinfo() {
    let addr = v6("fe80::1234", 54321, 3);
    let mut raw = [0u8; 28];
    let mut n = 28;
    unsafe {
        output_addr(addr, raw.as_mut_ptr().cast(), &mut n).unwrap();
        // The raw index reaches the runtime, which resolves it to a link.
        assert_eq!(address(raw.as_ptr().cast(), n).unwrap(), addr);
        output_addr(
            std::net::SocketAddrV6::new("fe80::1".parse().unwrap(), 1, 7, 3).into(),
            raw.as_mut_ptr().cast(),
            &mut n,
        )
        .unwrap();
        assert_eq!(address(raw.as_ptr().cast(), n).unwrap_err(), EOPNOTSUPP);
    }
}

#[test]
fn link_local_scope_round_trips_through_bind_connect_accept_and_names() {
    let (mut a, sa) = link_local_owner(1);
    let (mut b, sb) = link_local_owner(2);
    let l = new(&mut b);
    // Absent and foreign scope, and another node's address on this link.
    assert_eq!(b.execute(l, Op::Bind(v6("fe80::2", 8080, 0))).unwrap_err(), EINVAL);
    assert_eq!(b.execute(l, Op::Bind(v6("fe80::2", 8080, 7))).unwrap_err(), ENODEV);
    assert_eq!(
        b.execute(l, Op::Bind(v6("fe80::9", 8080, 1))).unwrap_err(),
        EADDRNOTAVAIL
    );
    b.execute(l, Op::Bind(v6("fe80::2", 8080, 1))).unwrap();
    assert_eq!(b.execute(l, Op::Name(false)).unwrap().addr, Some(v6("fe80::2", 8080, 1)));
    // One link-local binding per link and port.
    let again = new(&mut b);
    assert_eq!(
        b.execute(again, Op::Bind(v6("fe80::2", 8080, 1))).unwrap_err(),
        EADDRINUSE
    );
    b.execute(l, Op::Listen(2)).unwrap();
    let client = new(&mut a);
    assert_eq!(
        a.execute(client, Op::Connect(v6("fe80::2", 8080, 0))).unwrap_err(),
        EINVAL
    );
    assert_eq!(
        a.execute(client, Op::Connect(v6("fe80::2", 8080, 7))).unwrap_err(),
        ENODEV
    );
    assert_eq!(
        a.execute(client, Op::Connect(v6("fe80::2", 8080, 1))).unwrap_err(),
        EINPROGRESS
    );
    exchange(&mut a, &mut b, &sa, &sb);
    let accepted = b.execute(l, Op::Accept(0)).unwrap();
    let server = accepted.value as u64;
    let port = a.execute(client, Op::Name(false)).unwrap().addr.unwrap().port();
    assert_eq!(a.execute(client, Op::Name(false)).unwrap().addr, Some(v6("fe80::1", port, 1)));
    assert_eq!(a.execute(client, Op::Name(true)).unwrap().addr, Some(v6("fe80::2", 8080, 1)));
    assert_eq!(accepted.addr, Some(v6("fe80::1", port, 1)));
    assert_eq!(b.execute(server, Op::Name(false)).unwrap().addr, Some(v6("fe80::2", 8080, 1)));
    assert_eq!(b.execute(server, Op::Name(true)).unwrap().addr, Some(v6("fe80::1", port, 1)));
    // Both ends carry their port's live link as the connection's zone.
    for (owner, id) in [(&a, client), (&b, server)] {
        assert_eq!(
            owner
                .endpoint
                .retained_scoped_tuple(cid(owner, id))
                .unwrap()
                .zone(),
            Some(owner.ports[0].ingress.unwrap().link())
        );
    }
    a.execute(client, Op::Write(vec![5; 1500])).unwrap();
    exchange(&mut a, &mut b, &sa, &sb);
    assert_eq!(b.execute(server, Op::Read(2000)).unwrap().bytes, vec![5; 1500]);
    // A connected socket's link is fixed: another scope contradicts it.
    let other = new(&mut a);
    a.execute(other, Op::Bind(v6("fe80::1", 0, 1))).unwrap();
    assert_eq!(
        a.execute(other, Op::Connect(v6("fe80::2", 8080, 7))).unwrap_err(),
        EINVAL
    );
    // A bound link supplies the zone of a scope-less link-local peer.
    assert_eq!(
        a.execute(other, Op::Connect(v6("fe80::2", 8080, 0))).unwrap_err(),
        EINPROGRESS
    );
}

#[test]
fn unscoped_wildcard_listeners_accept_link_local_children_with_the_arrival_scope() {
    let (mut a, sa) = link_local_owner(1);
    let (mut b, sb) = link_local_owner(2);
    for (port, v6only) in [(8081, 0), (8082, 1)] {
        let l = link_local_listener(&mut b, v6("::", port, 0), Some(v6only));
        let client = new(&mut a);
        assert_eq!(
            a.execute(client, Op::Connect(v6("fe80::2", port, 1))).unwrap_err(),
            EINPROGRESS
        );
        exchange(&mut a, &mut b, &sa, &sb);
        let accepted = b.execute(l, Op::Accept(0)).unwrap();
        let client_port = a.execute(client, Op::Name(false)).unwrap().addr.unwrap().port();
        assert_eq!(accepted.addr, Some(v6("fe80::1", client_port, 1)));
        let child = accepted.value as u64;
        assert_eq!(b.execute(child, Op::Name(false)).unwrap().addr, Some(v6("fe80::2", port, 1)));
        // The listener itself stays on every link.
        assert_eq!(b.execute(l, Op::Name(false)).unwrap().addr, Some(v6("::", port, 0)));
    }
}

#[test]
fn link_local_fast_open_keeps_the_resolved_scope_for_sendto_and_deferred_opens() {
    let (mut a, sa) = link_local_owner(1);
    let (mut b, sb) = link_local_owner(2);
    // Opens need no cookie, so the deferred connect is eligible at once.
    a.socket_policy.fast_open_client_policy = ntcp::FastOpenClientPolicy::ApplicationProtected;
    let l = link_local_listener(&mut b, v6("fe80::2", 8080, 1), None);
    b.execute(l, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 4)).unwrap();
    let data = [9u8; 10];
    let send = |to| Op::SendTo(vec![(data.as_ptr() as usize, data.len())], MSG_FASTOPEN, Some(to), None);
    let implicit = new(&mut a);
    assert_eq!(a.execute(implicit, send(v6("fe80::2", 8080, 0))).unwrap_err(), EINVAL);
    assert_eq!(a.execute(implicit, send(v6("fe80::2", 8080, 7))).unwrap_err(), ENODEV);
    a.execute(implicit, send(v6("fe80::2", 8080, 1))).unwrap();
    let deferred = new(&mut a);
    a.execute(deferred, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
        .unwrap();
    a.execute(deferred, Op::Connect(v6("fe80::2", 8080, 1))).unwrap();
    assert!(a.sockets[&deferred].deferred_peer.is_some());
    assert_eq!(a.execute(deferred, Op::Name(true)).unwrap().addr, Some(v6("fe80::2", 8080, 1)));
    // The first send carries the SYN on the link the connect resolved.
    a.execute(deferred, Op::Send(vec![(data.as_ptr() as usize, data.len())], 0))
        .unwrap();
    assert!(a.sockets[&deferred].deferred_peer.is_none());
    exchange(&mut a, &mut b, &sa, &sb);
    for id in [implicit, deferred] {
        let port = a.execute(id, Op::Name(false)).unwrap().addr.unwrap().port();
        assert_eq!(a.execute(id, Op::Name(false)).unwrap().addr, Some(v6("fe80::1", port, 1)));
        assert_eq!(a.execute(id, Op::Name(true)).unwrap().addr, Some(v6("fe80::2", 8080, 1)));
        assert_eq!(
            a.endpoint.retained_scoped_tuple(cid(&a, id)).unwrap().zone(),
            Some(a.ports[0].ingress.unwrap().link())
        );
        let accepted = b.execute(l, Op::Accept(0)).unwrap();
        assert_eq!(accepted.addr.unwrap().ip(), "fe80::1".parse::<IpAddr>().unwrap());
        assert_eq!(accepted.addr, Some(v6("fe80::1", accepted.addr.unwrap().port(), 1)));
    }
}

#[test]
fn a_reused_interface_index_never_retargets_a_scoped_socket() {
    let (mut a, sa) = link_local_owner(1);
    let (mut b, sb) = link_local_owner(2);
    let l = link_local_listener(&mut b, v6("fe80::2", 8080, 1), None);
    let stale = new(&mut a);
    a.execute(stale, Op::Bind(v6("fe80::1", 9000, 1))).unwrap();
    // The OS gives index 1 to a new interface: a new link (generation)
    // replaces the old one in the Host and in the interface map.
    let old = a.ports[0].ingress.unwrap();
    let host = a.host.as_mut().unwrap();
    let receive = host.receive_capabilities(old).unwrap();
    host.remove_link(old).unwrap();
    use ntcp_host::path;
    let forwarder = path::ForwarderId(1);
    let ingress = host
        .register_link(
            path::InterfaceKey(1),
            1520,
            receive,
            ntcp_host::Forwarding::Forwarder(forwarder),
        )
        .unwrap();
    assert_ne!(ingress.link(), old.link());
    host.register_source(
        path::ScopedAddress::new(a.local, Some(ingress.link())).unwrap(),
        ingress.link(),
    )
    .unwrap();
    host.add_route(path::Route {
        destination: path::IpPrefix::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0).unwrap(),
        source: None,
        dscp: None,
        link: ingress.link(),
        next_hop: path::NextHop::Forwarder(forwarder),
        metric: 0,
    })
    .unwrap();
    a.ports[0].ingress = Some(ingress);
    // The bound socket keeps its old link: the index now names another one.
    assert_eq!(
        a.execute(stale, Op::Connect(v6("fe80::2", 8080, 1))).unwrap_err(),
        EINVAL
    );
    assert_eq!(
        a.execute(stale, Op::Connect(v6("fe80::2", 8080, 0))).unwrap_err(),
        ENODEV
    );
    assert_eq!(a.execute(stale, Op::Name(false)).unwrap().addr, Some(v6("fe80::1", 9000, 1)));
    // The same address and port on the new link is a distinct binding.
    let fresh = new(&mut a);
    a.execute(fresh, Op::Bind(v6("fe80::1", 9000, 1))).unwrap();
    assert_eq!(
        a.execute(fresh, Op::Connect(v6("fe80::2", 8080, 1))).unwrap_err(),
        EINPROGRESS
    );
    exchange(&mut a, &mut b, &sa, &sb);
    assert_eq!(
        b.execute(l, Op::Accept(0)).unwrap().addr,
        Some(v6("fe80::1", 9000, 1))
    );
    assert_eq!(
        a.endpoint.retained_scoped_tuple(cid(&a, fresh)).unwrap().zone(),
        Some(ingress.link())
    );
}

// An external owner with the `io.*` port at `first` (interface index 1) and
// one `port.b` at `second` (index 2), each a legacy fixed-next-hop port
// with its own frame queue.
fn two_port_owner(first: &str, second: &str) -> (Owner, [Arc<Mutex<State>>; 2]) {
    let mut config = SocketConfig::new("external", first.parse::<IpAddr>().unwrap());
    config.io.prefix = Some(64);
    config.ports.push(crate::PortConfig {
        name: "b".into(),
        interface: "external-b".into(),
        address: second.parse().unwrap(),
        prefix: Some(64),
        next_hop_mac: None,
        gateways: Vec::new(),
        neighbors: Vec::new(),
    });
    let c = &mut config.tcp.connection;
    c.timestamps = false;
    c.delayed_ack_us = 0;
    c.mss = 1460;
    c.send_ip_payload_limit = 65515;
    let states = [(); 2].map(|_| Arc::new(Mutex::new(State::default())));
    let backends = states
        .iter()
        .enumerate()
        .map(|(i, state)| crate::EthernetPacketIo {
            io: Box::new(Io(state.clone())),
            local_mac: [2 + i as u8; 6],
            next_hop_mac: Some([8 + i as u8; 6]),
        })
        .collect();
    let mut owner = Owner::external_backends(&config, backends).unwrap();
    owner.test_now = Some(0);
    (owner, states)
}
// Frames between port `i` of the two-port owner and peer `i`'s only port.
fn exchange_ports(
    a: &mut Owner,
    sa: &[Arc<Mutex<State>>; 2],
    peers: &mut [(Owner, Arc<Mutex<State>>); 2],
) {
    for _ in 0..16 {
        let mut progress = false;
        a.service_egress().unwrap();
        for (i, (peer, sp)) in peers.iter_mut().enumerate() {
            while let Some(frame) = sa[i].lock().unwrap().sent.pop_front() {
                let eth = ntcp_ethernet::parse_ethernet(&frame).unwrap();
                // The leaving port's own frame header.
                assert_eq!(eth.source, [2 + i as u8; 6]);
                assert_eq!(eth.destination, [8 + i as u8; 6]);
                peer.input_ip_metadata(eth.payload, Default::default(), None);
                progress = true;
            }
            peer.events();
            peer.service_egress().unwrap();
            while let Some(frame) = sp.lock().unwrap().sent.pop_front() {
                let eth = ntcp_ethernet::parse_ethernet(&frame).unwrap();
                a.input_link(i, eth.payload, Default::default(), None, false);
                progress = true;
            }
            peer.events();
        }
        a.events();
        if !progress {
            return;
        }
    }
    panic!("output did not quiesce");
}
fn link_local_peers() -> [(Owner, Arc<Mutex<State>>); 2] {
    [link_local_owner(2), link_local_owner(2)]
}

#[test]
fn identical_link_local_binds_and_connections_coexist_on_two_ports() {
    let (mut a, sa) = two_port_owner("fe80::1", "fe80::1");
    let mut peers = link_local_peers();
    for (peer, _) in &mut peers {
        link_local_listener(peer, v6("fe80::2", 8080, 1), None);
    }
    // The same address and port, once on each link.
    let sockets = [1, 2].map(|scope| {
        let s = new(&mut a);
        a.execute(s, Op::Bind(v6("fe80::1", 9000, scope))).unwrap();
        s
    });
    let again = new(&mut a);
    assert_eq!(
        a.execute(again, Op::Bind(v6("fe80::1", 9000, 2))).unwrap_err(),
        EADDRINUSE
    );
    // A socket on one link rejects the other link's scope.
    assert_eq!(
        a.execute(sockets[0], Op::Connect(v6("fe80::2", 8080, 2))).unwrap_err(),
        EINVAL
    );
    for (i, &s) in sockets.iter().enumerate() {
        assert_eq!(
            a.execute(s, Op::Connect(v6("fe80::2", 8080, i as u32 + 1))).unwrap_err(),
            EINPROGRESS
        );
    }
    exchange_ports(&mut a, &sa, &mut peers);
    for (i, &s) in sockets.iter().enumerate() {
        let scope = i as u32 + 1;
        assert_eq!(a.execute(s, Op::Name(false)).unwrap().addr, Some(v6("fe80::1", 9000, scope)));
        assert_eq!(a.execute(s, Op::Name(true)).unwrap().addr, Some(v6("fe80::2", 8080, scope)));
        assert_eq!(
            a.endpoint.retained_scoped_tuple(cid(&a, s)).unwrap().zone(),
            a.ports[i].link()
        );
        a.execute(s, Op::Write(vec![0x40 + i as u8; 1000])).unwrap();
    }
    exchange_ports(&mut a, &sa, &mut peers);
    // Each link's peer accepted exactly its own connection and data.
    for (i, (peer, _)) in peers.iter_mut().enumerate() {
        let l = *peer
            .sockets
            .iter()
            .find(|(_, s)| matches!(s.handle, Handle::Listener(_)))
            .unwrap()
            .0;
        let accepted = peer.execute(l, Op::Accept(0)).unwrap();
        assert_eq!(accepted.addr, Some(v6("fe80::1", 9000, 1)));
        let child = accepted.value as u64;
        assert_eq!(peer.execute(child, Op::Read(2000)).unwrap().bytes, vec![0x40 + i as u8; 1000]);
        assert_eq!(peer.execute(l, Op::Accept(0)).unwrap_err(), EAGAIN);
    }
}

// MSG_FASTOPEN and a deferred TCP_FASTOPEN_CONNECT open to scope 2 leave
// through the second port, beside an identical address on the first.
#[test]
fn fast_open_scopes_select_their_port_on_a_two_port_owner() {
    let (mut a, sa) = two_port_owner("fe80::1", "fe80::1");
    let mut peers = link_local_peers();
    a.socket_policy.fast_open_client_policy = ntcp::FastOpenClientPolicy::ApplicationProtected;
    let listeners = peers.each_mut().map(|(peer, _)| {
        let l = link_local_listener(peer, v6("fe80::2", 8080, 1), None);
        peer.execute(l, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 4)).unwrap();
        l
    });
    let data = [9u8; 10];
    let implicit = new(&mut a);
    a.execute(
        implicit,
        Op::SendTo(
            vec![(data.as_ptr() as usize, data.len())],
            MSG_FASTOPEN,
            Some(v6("fe80::2", 8080, 2)),
            None,
        ),
    )
    .unwrap();
    let deferred = new(&mut a);
    a.execute(deferred, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
        .unwrap();
    a.execute(deferred, Op::Connect(v6("fe80::2", 8080, 2))).unwrap();
    assert_eq!(a.execute(deferred, Op::Name(true)).unwrap().addr, Some(v6("fe80::2", 8080, 2)));
    a.execute(deferred, Op::Send(vec![(data.as_ptr() as usize, data.len())], 0))
        .unwrap();
    // Both SYNs leave the second port's frame queue only.
    a.service_egress().unwrap();
    assert!(sa[0].lock().unwrap().sent.is_empty());
    let syns = sa[1].lock().unwrap().sent.len();
    assert_eq!(syns, 2);
    exchange_ports(&mut a, &sa, &mut peers);
    for id in [implicit, deferred] {
        let port = a.execute(id, Op::Name(false)).unwrap().addr.unwrap().port();
        assert_eq!(a.execute(id, Op::Name(false)).unwrap().addr, Some(v6("fe80::1", port, 2)));
        assert_eq!(a.execute(id, Op::Name(true)).unwrap().addr, Some(v6("fe80::2", 8080, 2)));
        assert_eq!(
            a.endpoint.retained_scoped_tuple(cid(&a, id)).unwrap().zone(),
            a.ports[1].link()
        );
        let accepted = peers[1].0.execute(listeners[1], Op::Accept(0)).unwrap();
        assert_eq!(peers[1].0.execute(accepted.value as u64, Op::Read(100)).unwrap().bytes, data);
    }
    assert_eq!(peers[0].0.execute(listeners[0], Op::Accept(0)).unwrap_err(), EAGAIN);
}

// The OS reusing the second port's interface index for a new interface
// gives that port a new link: a socket bound to the old link is never
// retargeted, and the first port's connection is untouched.
#[test]
fn a_reused_index_on_one_port_never_retargets_its_sockets_or_the_other_port() {
    let (mut a, sa) = two_port_owner("fe80::1", "fe80::1");
    let mut peers = link_local_peers();
    let listeners = peers
        .each_mut()
        .map(|(peer, _)| link_local_listener(peer, v6("fe80::2", 8080, 1), None));
    let first = new(&mut a);
    a.execute(first, Op::Bind(v6("fe80::1", 9000, 1))).unwrap();
    assert_eq!(
        a.execute(first, Op::Connect(v6("fe80::2", 8080, 1))).unwrap_err(),
        EINPROGRESS
    );
    let stale = new(&mut a);
    a.execute(stale, Op::Bind(v6("fe80::1", 9000, 2))).unwrap();
    exchange_ports(&mut a, &sa, &mut peers);
    let child = peers[0].0.execute(listeners[0], Op::Accept(0)).unwrap().value as u64;
    let zone = a.ports[0].link();
    let old = a.ports[1].ingress.unwrap();
    let host = a.host.as_mut().unwrap();
    let receive = host.receive_capabilities(old).unwrap();
    host.remove_link(old).unwrap();
    use ntcp_host::path;
    let forwarder = path::ForwarderId(1);
    let ingress = host
        .register_link(
            path::InterfaceKey(2),
            1500,
            receive,
            ntcp_host::Forwarding::Forwarder(forwarder),
        )
        .unwrap();
    assert_ne!(ingress.link(), old.link());
    host.register_source(
        path::ScopedAddress::new("fe80::1".parse().unwrap(), Some(ingress.link())).unwrap(),
        ingress.link(),
    )
    .unwrap();
    host.add_route(path::Route {
        destination: path::IpPrefix::new("fe80::".parse().unwrap(), 64).unwrap(),
        source: None,
        dscp: None,
        link: ingress.link(),
        next_hop: path::NextHop::Forwarder(forwarder),
        metric: 0,
    })
    .unwrap();
    a.ports[1].ingress = Some(ingress);
    // The bound socket keeps its old link: index 2 now names another one,
    // and the first port's link is not a substitute.
    assert_eq!(
        a.execute(stale, Op::Connect(v6("fe80::2", 8080, 2))).unwrap_err(),
        EINVAL
    );
    assert_eq!(
        a.execute(stale, Op::Connect(v6("fe80::2", 8080, 1))).unwrap_err(),
        EINVAL
    );
    assert_eq!(a.execute(stale, Op::Name(false)).unwrap().addr, Some(v6("fe80::1", 9000, 2)));
    // The same address and port on the new link is a distinct binding.
    let fresh = new(&mut a);
    a.execute(fresh, Op::Bind(v6("fe80::1", 9000, 2))).unwrap();
    assert_eq!(
        a.execute(fresh, Op::Connect(v6("fe80::2", 8080, 2))).unwrap_err(),
        EINPROGRESS
    );
    a.execute(first, Op::Write(vec![0x61; 100])).unwrap();
    exchange_ports(&mut a, &sa, &mut peers);
    assert_eq!(
        peers[1].0.execute(listeners[1], Op::Accept(0)).unwrap().addr,
        Some(v6("fe80::1", 9000, 1))
    );
    assert_eq!(
        a.endpoint.retained_scoped_tuple(cid(&a, fresh)).unwrap().zone(),
        Some(ingress.link())
    );
    assert_eq!(a.endpoint.retained_scoped_tuple(cid(&a, first)).unwrap().zone(), zone);
    assert_eq!(peers[0].0.execute(child, Op::Read(200)).unwrap().bytes, vec![0x61; 100]);
    assert_eq!(peers[0].0.execute(listeners[0], Op::Accept(0)).unwrap_err(), EAGAIN);
}

#[test]
fn a_wildcard_listener_accepts_on_both_ports_with_each_arrival_scope() {
    for v6only in [0, 1] {
        let (mut a, sa) = two_port_owner("fe80::1", "fe80::1");
        let mut peers = link_local_peers();
        let l = link_local_listener(&mut a, v6("::", 8080, 0), Some(v6only));
        let clients: Vec<u64> = peers
            .iter_mut()
            .map(|(peer, _)| {
                let c = new(peer);
                assert_eq!(
                    peer.execute(c, Op::Connect(v6("fe80::1", 8080, 1))).unwrap_err(),
                    EINPROGRESS
                );
                c
            })
            .collect();
        exchange_ports(&mut a, &sa, &mut peers);
        let mut scopes = Vec::new();
        for _ in 0..2 {
            let accepted = a.execute(l, Op::Accept(0)).unwrap();
            let SocketAddr::V6(peer) = accepted.addr.unwrap() else {
                panic!()
            };
            assert_eq!(*peer.ip(), "fe80::2".parse::<std::net::Ipv6Addr>().unwrap());
            let child = accepted.value as u64;
            assert_eq!(
                a.execute(child, Op::Name(false)).unwrap().addr,
                Some(v6("fe80::1", 8080, peer.scope_id()))
            );
            let port = peer.scope_id() as usize - 1;
            assert_eq!(
                a.endpoint.retained_scoped_tuple(cid(&a, child)).unwrap().zone(),
                a.ports[port].link()
            );
            // A reply leaves through the arrival port to that link's peer.
            a.execute(child, Op::Write(vec![0x50 + port as u8; 100])).unwrap();
            scopes.push(peer.scope_id());
        }
        scopes.sort();
        assert_eq!(scopes, [1, 2]);
        exchange_ports(&mut a, &sa, &mut peers);
        for (i, (peer, _)) in peers.iter_mut().enumerate() {
            assert_eq!(peer.execute(clients[i], Op::Read(200)).unwrap().bytes, vec![0x50 + i as u8; 100]);
        }
        assert_eq!(a.execute(l, Op::Name(false)).unwrap().addr, Some(v6("::", 8080, 0)));
    }
}

#[test]
fn global_ports_send_through_their_own_link() {
    let (mut a, sa) = two_port_owner("2001:db8::1", "2001:db8:1::1");
    let mut peers = [
        owner_at("2001:db8::2".parse().unwrap(), false, 0, Vec::new()),
        owner_at("2001:db8:1::2".parse().unwrap(), false, 0, Vec::new()),
    ];
    let listeners = [("2001:db8::2", 0), ("2001:db8:1::2", 1)].map(|(ip, i)| {
        let l = new(&mut peers[i].0);
        let addr = SocketAddr::new(ip.parse().unwrap(), 8080);
        peers[i].0.execute(l, Op::Bind(addr)).unwrap();
        peers[i].0.execute(l, Op::Listen(2)).unwrap();
        l
    });
    // Unbound sockets take the address of the port whose prefix holds the
    // peer; everything else uses the `io.*` port and its default route.
    let clients = ["2001:db8::2", "2001:db8:1::2"].map(|ip| {
        let c = new(&mut a);
        assert_eq!(
            a.execute(c, Op::Connect(SocketAddr::new(ip.parse().unwrap(), 8080))).unwrap_err(),
            EINPROGRESS
        );
        c
    });
    exchange_ports(&mut a, &sa, &mut peers);
    for (i, &c) in clients.iter().enumerate() {
        let local = a.execute(c, Op::Name(false)).unwrap().addr.unwrap();
        assert_eq!(local.ip(), a.ports[i].address);
        a.execute(c, Op::Write(vec![0x60 + i as u8; 1200])).unwrap();
    }
    exchange_ports(&mut a, &sa, &mut peers);
    for (i, (peer, _)) in peers.iter_mut().enumerate() {
        let child = peer.execute(listeners[i], Op::Accept(0)).unwrap().value as u64;
        assert_eq!(peer.execute(child, Op::Read(2000)).unwrap().bytes, vec![0x60 + i as u8; 1200]);
    }
    // A destination outside both prefixes leaves through the `io.*` port.
    let routed = new(&mut a);
    assert_eq!(
        a.execute(routed, Op::Connect(SocketAddr::new("2001:db8:5::9".parse().unwrap(), 8080)))
            .unwrap_err(),
        EINPROGRESS
    );
    a.service_egress().unwrap();
    assert!(sa[1].lock().unwrap().sent.is_empty());
    let syn = sa[0].lock().unwrap().sent.pop_front().unwrap();
    let eth = ntcp_ethernet::parse_ethernet(&syn).unwrap();
    assert_eq!(eth.payload[24..40], "2001:db8:5::9".parse::<std::net::Ipv6Addr>().unwrap().octets());
}

// An owner whose ports b and c (interface indexes 2 and 3) resolve their
// next hops by Neighbor Discovery, both with fe80::1, beside the fixed
// `io.*` port.
fn nd_owner() -> (Owner, [Arc<Mutex<State>>; 3]) {
    nd_owner_with([None; 2])
}
// `nd_owner` with link MTUs for ports b and c.
fn nd_owner_with(mtus: [Option<u32>; 2]) -> (Owner, [Arc<Mutex<State>>; 3]) {
    nd_owner_gso(mtus, None)
}
// `nd_owner_with`, with software GSO limits. Native software GSO
// aggregates copied output only, so these ports' backends copy.
fn nd_owner_gso(
    mtus: [Option<u32>; 2],
    gso: Option<ntcp::GsoLimits>,
) -> (Owner, [Arc<Mutex<State>>; 3]) {
    let mut config = SocketConfig::new("external", "fe80::9".parse::<IpAddr>().unwrap());
    config.io.prefix = Some(64);
    config.io.gso = gso;
    for name in ["b", "c"] {
        config.ports.push(crate::PortConfig {
            name: name.into(),
            interface: format!("external-{name}"),
            address: "fe80::1".parse().unwrap(),
            prefix: Some(64),
            next_hop_mac: None,
            gateways: Vec::new(),
            neighbors: Vec::new(),
        });
    }
    let c = &mut config.tcp.connection;
    c.timestamps = false;
    c.delayed_ack_us = 0;
    let states = [(); 3].map(|_| Arc::new(Mutex::new(State::default())));
    for (state, mtu) in states[1..].iter().zip(mtus) {
        state.lock().unwrap().mtu = mtu;
    }
    for state in &states {
        state.lock().unwrap().copying = gso.is_some();
    }
    let backends = states
        .iter()
        .enumerate()
        .map(|(i, state)| crate::EthernetPacketIo {
            io: Box::new(Io(state.clone())),
            local_mac: [2, 0, 0, 0, 0, 1 + i as u8],
            next_hop_mac: (i == 0).then_some([8; 6]),
        })
        .collect();
    let mut owner = Owner::external_backends(&config, backends).unwrap();
    owner.test_now = Some(0);
    (owner, states)
}
const ND_PEER: [[u8; 6]; 2] = [[2, 0, 0, 0, 0, 0xa], [2, 0, 0, 0, 0, 0xb]];
// The Neighbor Solicitation a frame carries, with its IPv6 source.
fn solicitation(frame: &[u8]) -> Option<(std::net::Ipv6Addr, ntcp_icmp::NeighborSolicitation)> {
    let eth = ntcp_ethernet::parse_ethernet(frame).ok()?;
    let packet = ntcp_ip6::parse(eth.payload).ok()?;
    if packet.protocol != 58 {
        return None;
    }
    match ntcp_icmp::decode_neighbor(packet.ip, 255, packet.payload).ok()? {
        ntcp_icmp::NeighborMessage::Solicitation(ns) => match packet.ip.source {
            IpAddr::V6(source) => Some((source, ns)),
            IpAddr::V4(_) => None,
        },
        ntcp_icmp::NeighborMessage::Advertisement(_) => None,
    }
}
// Frames between ND port `i + 1` of `a` and peer `i`. Each solicitation is
// recorded and a resolution solicitation answered by a solicited NA from
// fe80::2 with peer `i`'s MAC; everything else must be addressed to that
// MAC and reaches the peer.
fn exchange_nd(
    a: &mut Owner,
    sa: &[Arc<Mutex<State>>; 3],
    peers: &mut [(Owner, Arc<Mutex<State>>); 2],
    seen: &mut [Vec<(std::net::Ipv6Addr, [u8; 6])>; 2],
) {
    exchange_nd_lengths(a, sa, peers, seen, &mut [Vec::new(), Vec::new()]);
}
// `exchange_nd`, also recording the IPv6 packet length of every TCP
// packet each ND port sent.
fn exchange_nd_lengths(
    a: &mut Owner,
    sa: &[Arc<Mutex<State>>; 3],
    peers: &mut [(Owner, Arc<Mutex<State>>); 2],
    seen: &mut [Vec<(std::net::Ipv6Addr, [u8; 6])>; 2],
    lengths: &mut [Vec<usize>; 2],
) {
    for _ in 0..32 {
        let mut progress = false;
        // Held output is polled again at the owner's 1 ms cadence.
        a.test_now = a.test_now.map(|now| now + 1000);
        a.service_discovery();
        a.service_egress().unwrap();
        for (i, (peer, sp)) in peers.iter_mut().enumerate() {
            while let Some(frame) = sa[i + 1].lock().unwrap().sent.pop_front() {
                progress = true;
                let eth = ntcp_ethernet::parse_ethernet(&frame).unwrap();
                assert_eq!(eth.source, [2, 0, 0, 0, 0, 2 + i as u8]);
                if let Some((source, ns)) = solicitation(&frame) {
                    seen[i].push((source, eth.destination));
                    if source.is_unspecified() {
                        continue;
                    }
                    assert_eq!(ns.source_link_layer, Some([2, 0, 0, 0, 0, 2 + i as u8]));
                    let ip = ntcp::IpMetadata {
                        source: "fe80::2".parse().unwrap(),
                        destination: IpAddr::V6(source),
                    };
                    let na = ntcp_icmp::NeighborAdvertisement {
                        router: false,
                        solicited: true,
                        override_: true,
                        target: ns.target,
                        target_link_layer: Some(ND_PEER[i]),
                    };
                    let mut packet = vec![0; 40 + 32];
                    let len = ntcp_icmp::encode_advertisement(ip, na, &mut packet[40..]).unwrap();
                    let header = ntcp_ip6::Header { ip, hop_limit: 255, dscp: 0, ecn: 0 };
                    let len = ntcp_ip6::encode_datagram(&mut packet, header, 58, len).unwrap();
                    a.input_link(i + 1, &packet[..len], Default::default(), None, false);
                    continue;
                }
                assert_eq!(eth.destination, ND_PEER[i]);
                let packet = ntcp_ip6::parse(eth.payload).unwrap();
                if packet.protocol == 6 {
                    lengths[i].push(40 + packet.payload.len());
                }
                peer.input_ip_metadata(eth.payload, Default::default(), None);
            }
            peer.events();
            peer.service_egress().unwrap();
            while let Some(frame) = sp.lock().unwrap().sent.pop_front() {
                let eth = ntcp_ethernet::parse_ethernet(&frame).unwrap();
                a.input_link(i + 1, eth.payload, Default::default(), None, false);
                progress = true;
            }
            peer.events();
        }
        a.events();
        if !progress && !a.egress.as_ref().unwrap().has_held() {
            return;
        }
    }
}

// Two ND-capable ports with the same link-local address: each defends it
// by DAD before using it, resolves the identical peer address fe80::2 by
// its own NS/NA, holds its SYN meanwhile (no transmission), then carries
// its own connection and data to the MAC its link advertised.
#[test]
fn neighbor_discovery_ports_resolve_identical_link_local_peers_independently() {
    let (mut a, sa) = nd_owner();
    let mut peers = link_local_peers();
    for (peer, _) in &mut peers {
        link_local_listener(peer, v6("fe80::2", 8080, 1), None);
    }
    let mut seen = [Vec::new(), Vec::new()];
    // DAD: the delayed probe, then one RetransTimer.
    for step in 0..=30 {
        a.test_now = Some(step * 100_000);
        exchange_nd(&mut a, &sa, &mut peers, &mut seen);
    }
    let group = ntcp_ethernet::solicited_node("fe80::1".parse().unwrap());
    let group_mac = ntcp_ethernet::ipv6_multicast_mac(group).unwrap();
    for (i, probes) in seen.iter().enumerate() {
        assert_eq!(probes, &vec![(std::net::Ipv6Addr::UNSPECIFIED, group_mac)], "port {i}");
        let link = a.ports[i + 1].link().unwrap();
        assert_eq!(
            a.host.as_ref().unwrap().neighbor_address_state(link, "fe80::1".parse().unwrap()),
            Some(ntcp_host::AddressState::Assigned)
        );
    }
    let sockets = [2, 3].map(|scope| {
        let s = new(&mut a);
        a.execute(s, Op::Bind(v6("fe80::1", 9000, scope))).unwrap();
        assert_eq!(
            a.execute(s, Op::Connect(v6("fe80::2", 8080, scope))).unwrap_err(),
            EINPROGRESS
        );
        s
    });
    // The SYNs are held for resolution: nothing but solicitations leaves.
    a.service_egress().unwrap();
    for state in &sa[1..] {
        assert!(state.lock().unwrap().sent.is_empty());
    }
    exchange_nd(&mut a, &sa, &mut peers, &mut seen);
    let peer_group = ntcp_ethernet::solicited_node("fe80::2".parse().unwrap());
    for (i, &s) in sockets.iter().enumerate() {
        assert_eq!(
            seen[i][1..],
            [(
                "fe80::1".parse().unwrap(),
                ntcp_ethernet::ipv6_multicast_mac(peer_group).unwrap()
            )]
        );
        let link = a.ports[i + 1].link().unwrap();
        let (state, mac, _) =
            a.host.as_ref().unwrap().neighbor(link, "fe80::2".parse().unwrap()).unwrap();
        assert_eq!(mac, Some(ND_PEER[i]));
        assert_eq!(state, ntcp_host::NeighborState::Reachable);
        assert_eq!(a.execute(s, Op::Name(true)).unwrap().addr, Some(v6("fe80::2", 8080, i as u32 + 2)));
        a.execute(s, Op::Write(vec![0x50 + i as u8; 3000])).unwrap();
    }
    exchange_nd(&mut a, &sa, &mut peers, &mut seen);
    for (i, (peer, _)) in peers.iter_mut().enumerate() {
        let l = *peer
            .sockets
            .iter()
            .find(|(_, s)| matches!(s.handle, Handle::Listener(_)))
            .unwrap()
            .0;
        let accepted = peer.execute(l, Op::Accept(0)).unwrap();
        let child = accepted.value as u64;
        assert_eq!(peer.execute(child, Op::Read(4000)).unwrap().bytes, vec![0x50 + i as u8; 3000]);
    }
    // One resolution per link: no further solicitation was needed.
    assert_eq!(seen.map(|s| s.len()), [2, 2]);
}

// IPv4 gateway mode without ARP: a port without a fixed next hop sends a
// gateway route's packets to its operator-configured static neighbor's MAC,
// and an on-link destination to its own static neighbor; a destination
// with no mapping leaves nothing (there is no ARP to resolve it).
#[test]
fn ipv4_gateway_routes_leave_through_static_neighbors() {
    let mut config = SocketConfig::new("external", "10.73.0.2".parse::<IpAddr>().unwrap());
    config.io.prefix = Some(24);
    config.ports.push(crate::PortConfig {
        name: "b".into(),
        interface: "external-b".into(),
        address: "10.73.1.2".parse().unwrap(),
        prefix: Some(24),
        next_hop_mac: None,
        gateways: vec![("10.80.0.0/16".parse().unwrap(), "10.73.1.1".parse().unwrap())],
        neighbors: vec![
            ("10.73.1.1".parse().unwrap(), [2, 0, 0, 0, 0, 0xa]),
            ("10.73.1.7".parse().unwrap(), [2, 0, 0, 0, 0, 0xb]),
        ],
    });
    // A valid configuration of AF_PACKET ports.
    let mut checked = config.clone();
    checked.io.backend = crate::Backend::AfPacket;
    checked.io.next_hop_mac = Some([8; 6]);
    checked.validate().unwrap();
    let states = [(); 2].map(|_| Arc::new(Mutex::new(State::default())));
    let backends = states
        .iter()
        .enumerate()
        .map(|(i, state)| crate::EthernetPacketIo {
            io: Box::new(Io(state.clone())),
            local_mac: [2, 0, 0, 0, 0, 1 + i as u8],
            next_hop_mac: (i == 0).then_some([8; 6]),
        })
        .collect();
    let mut a = Owner::external_backends(&config, backends).unwrap();
    a.test_now = Some(0);
    let v4 = |address: &str, port: u16| SocketAddr::new(address.parse().unwrap(), port);
    for (destination, mac) in [
        ("10.80.0.5", [2, 0, 0, 0, 0, 0xa]),
        ("10.73.1.7", [2, 0, 0, 0, 0, 0xb]),
    ] {
        let s = new(&mut a);
        assert_eq!(a.execute(s, Op::Connect(v4(destination, 80))).unwrap_err(), EINPROGRESS);
        a.service_egress().unwrap();
        let frame = states[1].lock().unwrap().sent.pop_front().expect("a SYN on port b");
        let eth = ntcp_ethernet::parse_ethernet(&frame).unwrap();
        assert_eq!((eth.destination, eth.source), (mac, [2, 0, 0, 0, 0, 2]));
        let ip = ntcp_ip::parse(eth.payload, false).unwrap();
        assert_eq!(ip.ip.destination, destination.parse::<IpAddr>().unwrap());
        assert_eq!(ip.ip.source, "10.73.1.2".parse::<IpAddr>().unwrap());
        assert!(states[0].lock().unwrap().sent.is_empty());
    }
    let s = new(&mut a);
    assert_eq!(a.execute(s, Op::Connect(v4("10.73.1.9", 80))).unwrap_err(), EINPROGRESS);
    a.service_egress().unwrap();
    assert!(states.iter().all(|state| state.lock().unwrap().sent.is_empty()));
}

// RFC 1122 section 3.2.2.2 in the native runtime: an IPv4 Redirect from
// the current gateway quoting a submitted SYN moves the destination to the
// new gateway's static neighbor, while one naming a gateway the port has
// no static neighbor for is discarded before the Host acts on it (there is
// no ARP to reach it).
#[test]
fn ipv4_redirects_follow_only_statically_mapped_gateways() {
    let mut config = SocketConfig::new("external", "10.73.0.2".parse::<IpAddr>().unwrap());
    config.io.prefix = Some(24);
    config.ports.push(crate::PortConfig {
        name: "b".into(),
        interface: "external-b".into(),
        address: "10.73.1.2".parse().unwrap(),
        prefix: Some(24),
        next_hop_mac: None,
        gateways: vec![("10.80.0.0/16".parse().unwrap(), "10.73.1.1".parse().unwrap())],
        neighbors: vec![
            ("10.73.1.1".parse().unwrap(), [2, 0, 0, 0, 0, 0xa]),
            ("10.73.1.7".parse().unwrap(), [2, 0, 0, 0, 0, 0xb]),
        ],
    });
    let states = [(); 2].map(|_| Arc::new(Mutex::new(State::default())));
    let backends = states
        .iter()
        .enumerate()
        .map(|(i, state)| crate::EthernetPacketIo {
            io: Box::new(Io(state.clone())),
            local_mac: [2, 0, 0, 0, 0, 1 + i as u8],
            next_hop_mac: (i == 0).then_some([8; 6]),
        })
        .collect();
    let mut a = Owner::external_backends(&config, backends).unwrap();
    a.test_now = Some(0);
    let s = new(&mut a);
    let destination = SocketAddr::new("10.80.0.5".parse().unwrap(), 80);
    assert_eq!(a.execute(s, Op::Connect(destination)).unwrap_err(), EINPROGRESS);
    a.service_egress().unwrap();
    let frame = states[1].lock().unwrap().sent.pop_front().expect("a SYN on port b");
    let syn = ntcp_ethernet::parse_ethernet(&frame).unwrap().payload.to_vec();
    // A Host Redirect from 10.73.1.1 to this port quoting the SYN.
    let redirect = |gateway: [u8; 4]| {
        let mut icmp = vec![5, 1, 0, 0];
        icmp.extend_from_slice(&gateway);
        icmp.extend_from_slice(&syn[..28]);
        let sum = ntcp_icmp::checksum(&icmp);
        icmp[2..4].copy_from_slice(&sum.to_be_bytes());
        let mut packet = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 1, 0, 0];
        packet.extend_from_slice(&[10, 73, 1, 1, 10, 73, 1, 2]);
        let len = (20 + icmp.len()) as u16;
        packet[2..4].copy_from_slice(&len.to_be_bytes());
        let sum = ntcp_icmp::checksum(&packet);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
        packet.extend_from_slice(&icmp);
        packet
    };
    let retransmitted = |a: &mut Owner, at: u64| {
        a.test_now = Some(at);
        a.endpoint.on_timeout(at, 32).unwrap();
        a.service_egress().unwrap();
        let frame = states[1].lock().unwrap().sent.pop_front().expect("a retransmitted SYN");
        let eth = ntcp_ethernet::parse_ethernet(&frame).unwrap();
        assert_eq!(&eth.payload[16..20], &syn[16..20]);
        eth.destination
    };
    a.input_link(1, &redirect([10, 73, 1, 8]), Default::default(), None, false);
    assert_eq!(retransmitted(&mut a, 1_500_000), [2, 0, 0, 0, 0, 0xa]);
    a.input_link(1, &redirect([10, 73, 1, 7]), Default::default(), None, false);
    assert_eq!(retransmitted(&mut a, 5_000_000), [2, 0, 0, 0, 0, 0xb]);
}

// One IPv6 packet as it arrives from `source` to `destination`.
fn nd_packet(source: &str, destination: std::net::Ipv6Addr, hop_limit: u8, message: &[u8]) -> Vec<u8> {
    let ip = ntcp::IpMetadata {
        source: source.parse().unwrap(),
        destination: IpAddr::V6(destination),
    };
    let mut packet = vec![0; 40 + message.len()];
    packet[40..].copy_from_slice(message);
    let header = ntcp_ip6::Header { ip, hop_limit, dscp: 0, ecn: 0 };
    let len = ntcp_ip6::encode_datagram(&mut packet, header, 58, message.len()).unwrap();
    packet.truncate(len);
    packet
}
// An Echo Request from `source` to fe80::1.
fn echo_to_own(source: &str) -> Vec<u8> {
    let own: std::net::Ipv6Addr = "fe80::1".parse().unwrap();
    let ip = ntcp::IpMetadata {
        source: source.parse().unwrap(),
        destination: IpAddr::V6(own),
    };
    let mut message = [0; 16];
    let n = ntcp_icmp::encode_echo(ip, ntcp_icmp::EchoKind::Request, 5, 1, &mut message, 8).unwrap();
    nd_packet(source, own, 64, &message[..n])
}
// The ICMPv6 type and Ethernet destination of every frame a port sent.
fn sent_icmp(state: &Arc<Mutex<State>>) -> Vec<(u8, [u8; 6], IpAddr)> {
    let mut sent = Vec::new();
    while let Some(frame) = state.lock().unwrap().sent.pop_front() {
        let eth = ntcp_ethernet::parse_ethernet(&frame).unwrap();
        let packet = ntcp_ip6::parse(eth.payload).unwrap();
        assert_eq!(packet.protocol, 58);
        sent.push((packet.payload[0], eth.destination, packet.ip.destination));
    }
    sent
}
// The owner of `nd_owner` with fe80::1 assigned on both ND ports.
fn nd_owner_assigned() -> (Owner, [Arc<Mutex<State>>; 3]) {
    nd_owner_assigned_with([None; 2])
}
fn nd_owner_assigned_with(mtus: [Option<u32>; 2]) -> (Owner, [Arc<Mutex<State>>; 3]) {
    nd_owner_assigned_gso(mtus, None)
}
fn nd_owner_assigned_gso(
    mtus: [Option<u32>; 2],
    gso: Option<ntcp::GsoLimits>,
) -> (Owner, [Arc<Mutex<State>>; 3]) {
    let (mut a, sa) = nd_owner_gso(mtus, gso);
    let mut peers = link_local_peers();
    let mut seen = [Vec::new(), Vec::new()];
    for step in 0..=30 {
        a.test_now = Some(step * 100_000);
        exchange_nd(&mut a, &sa, &mut peers, &mut seen);
    }
    for i in 1..3 {
        let link = a.ports[i].link().unwrap();
        assert_eq!(
            a.host.as_ref().unwrap().neighbor_address_state(link, "fe80::1".parse().unwrap()),
            Some(ntcp_host::AddressState::Assigned)
        );
    }
    (a, sa)
}

// Host ICMP output on ND ports (RFC 4443 section 4.2's Echo responder):
// on port b an Echo Request from a peer whose solicitation created a STALE
// entry is answered at once to that MAC; on port c the reply to an
// unresolved peer is held while its NS goes out, and leaves for the MAC
// its NA gave.
#[test]
fn echo_replies_on_neighbor_discovery_ports_resolve_their_next_hop() {
    let (mut a, sa) = nd_owner_assigned();
    let own: std::net::Ipv6Addr = "fe80::1".parse().unwrap();
    let group = ntcp_ethernet::solicited_node(own);
    let ns = ntcp_icmp::NeighborSolicitation {
        target: own,
        source_link_layer: Some(ND_PEER[0]),
    };
    let mut message = [0; 32];
    let ip = ntcp::IpMetadata {
        source: "fe80::2".parse().unwrap(),
        destination: IpAddr::V6(group),
    };
    let n = ntcp_icmp::encode_solicitation(ip, ns, &mut message).unwrap();
    a.input_link(1, &nd_packet("fe80::2", group, 255, &message[..n]), Default::default(), None, true);
    a.input_link(1, &echo_to_own("fe80::2"), Default::default(), None, false);
    a.input_link(2, &echo_to_own("fe80::3"), Default::default(), None, false);
    a.service_discovery();
    a.service_egress().unwrap();
    a.service_discovery();
    let peer2 = IpAddr::V6("fe80::2".parse().unwrap());
    let peer3: std::net::Ipv6Addr = "fe80::3".parse().unwrap();
    // The NA answering the solicitation, and the Echo Reply.
    let sent = sent_icmp(&sa[1]);
    assert!(sent.contains(&(136, ND_PEER[0], peer2)), "{sent:?}");
    assert!(sent.contains(&(129, ND_PEER[0], peer2)), "{sent:?}");
    let link = a.ports[1].link().unwrap();
    assert_eq!(
        a.host.as_ref().unwrap().neighbor(link, "fe80::2".parse().unwrap()).map(|n| n.0),
        Some(ntcp_host::NeighborState::Delay)
    );
    // Port c: only the resolution solicitation; the reply is held.
    let solicited = ntcp_ethernet::solicited_node(peer3);
    assert_eq!(
        sent_icmp(&sa[2]),
        [(135, ntcp_ethernet::ipv6_multicast_mac(solicited).unwrap(), IpAddr::V6(solicited))]
    );
    a.service_egress().unwrap();
    assert!(sa[2].lock().unwrap().sent.is_empty());
    let na = ntcp_icmp::NeighborAdvertisement {
        router: false,
        solicited: true,
        override_: true,
        target: peer3,
        target_link_layer: Some(ND_PEER[1]),
    };
    let ip = ntcp::IpMetadata {
        source: IpAddr::V6(peer3),
        destination: IpAddr::V6(own),
    };
    let n = ntcp_icmp::encode_advertisement(ip, na, &mut message).unwrap();
    a.input_link(2, &nd_packet("fe80::3", own, 255, &message[..n]), Default::default(), None, false);
    a.service_egress().unwrap();
    assert_eq!(sent_icmp(&sa[2]), [(129, ND_PEER[1], IpAddr::V6(peer3))]);
}

// The Neighbor Advertisements a port sent, with their Ethernet and IPv6
// destinations.
fn sent_advertisements(
    state: &Arc<Mutex<State>>,
) -> Vec<([u8; 6], IpAddr, ntcp_icmp::NeighborAdvertisement)> {
    let mut sent = Vec::new();
    while let Some(frame) = state.lock().unwrap().sent.pop_front() {
        let eth = ntcp_ethernet::parse_ethernet(&frame).unwrap();
        let packet = ntcp_ip6::parse(eth.payload).unwrap();
        if let Ok(ntcp_icmp::NeighborMessage::Advertisement(na)) =
            ntcp_icmp::decode_neighbor(packet.ip, 255, packet.payload)
        {
            sent.push((eth.destination, packet.ip.destination, na));
        }
    }
    sent
}

// Solicitations from other nodes for an assigned native address are
// answered by the owner loop's next pass, with no ND timer of this node
// due (RFC 4861 sections 7.2.4 and 7.3.1; RFC 4862 section 5.4.3): a
// resolution NS on port b at its Source Link-Layer Address, a DAD probe on
// port c to all-nodes, and a unicast NUD probe without SLLAO at the mapping
// the first solicitation left cached.
#[test]
fn peer_solicitations_are_answered_without_a_pending_neighbor_timer() {
    let (mut a, sa) = nd_owner_assigned();
    let own: std::net::Ipv6Addr = "fe80::1".parse().unwrap();
    let group = ntcp_ethernet::solicited_node(own);
    let peer: std::net::Ipv6Addr = "fe80::2".parse().unwrap();
    let all_nodes: std::net::Ipv6Addr = "ff02::1".parse().unwrap();
    let deadline = |a: &Owner| a.host.as_ref().unwrap().next_neighbor_deadline();
    let solicit = |a: &mut Owner, port: usize, source: &str, destination, sllao| {
        // Nothing of this node's own is due: only the answer opens the pass.
        assert_eq!(deadline(a), None);
        let ns = ntcp_icmp::NeighborSolicitation {
            target: own,
            source_link_layer: sllao,
        };
        let ip = ntcp::IpMetadata {
            source: source.parse().unwrap(),
            destination: IpAddr::V6(destination),
        };
        let mut message = [0; 32];
        let n = ntcp_icmp::encode_solicitation(ip, ns, &mut message).unwrap();
        let multicast = destination.is_multicast();
        let packet = nd_packet(source, destination, 255, &message[..n]);
        a.input_link(port, &packet, Default::default(), None, multicast);
        a.test_now = a.test_now.map(|now| now + 1000);
        a.service_discovery();
        assert_eq!(deadline(a), None);
    };
    let answer = |solicited| ntcp_icmp::NeighborAdvertisement {
        router: false,
        solicited,
        override_: true,
        target: own,
        target_link_layer: Some([2, 0, 0, 0, 0, 2]),
    };
    solicit(&mut a, 1, "fe80::2", group, Some(ND_PEER[0]));
    assert_eq!(sent_advertisements(&sa[1]), [(ND_PEER[0], IpAddr::V6(peer), answer(true))]);
    let link = a.ports[1].link().unwrap();
    assert_eq!(
        a.host.as_ref().unwrap().neighbor(link, peer).map(|n| n.0),
        Some(ntcp_host::NeighborState::Stale)
    );
    solicit(&mut a, 2, "::", group, None);
    let all_nodes_mac = ntcp_ethernet::ipv6_multicast_mac(all_nodes).unwrap();
    let mut dad_answer = answer(false);
    dad_answer.target_link_layer = Some([2, 0, 0, 0, 0, 3]);
    assert_eq!(
        sent_advertisements(&sa[2]),
        [(all_nodes_mac, IpAddr::V6(all_nodes), dad_answer)]
    );
    solicit(&mut a, 1, "fe80::2", own, None);
    assert_eq!(sent_advertisements(&sa[1]), [(ND_PEER[0], IpAddr::V6(peer), answer(true))]);
    assert!(sa[2].lock().unwrap().sent.is_empty());
}

// An `io.*` port without a fixed next hop resolves like a named port: its
// gateway route leaves through the static neighbor `io.neighbor` gives, an
// on-link destination through its own mapping, and with no implicit
// default route an off-link destination without a gateway leaves nothing.
#[test]
fn resolving_io_port_routes_through_static_neighbors_without_a_default_route() {
    let mut config = SocketConfig::new("external", "10.73.1.2".parse::<IpAddr>().unwrap());
    config.io.prefix = Some(24);
    config.io.gateways = vec![("10.80.0.0/16".parse().unwrap(), "10.73.1.1".parse().unwrap())];
    config.io.neighbors = vec![
        ("10.73.1.1".parse().unwrap(), [2, 0, 0, 0, 0, 0xa]),
        ("10.73.1.7".parse().unwrap(), [2, 0, 0, 0, 0, 0xb]),
    ];
    let mut checked = config.clone();
    checked.io.backend = crate::Backend::AfPacket;
    checked.validate().unwrap();
    let state = Arc::new(Mutex::new(State::default()));
    let backend = crate::EthernetPacketIo {
        io: Box::new(Io(state.clone())),
        local_mac: [2, 0, 0, 0, 0, 1],
        next_hop_mac: None,
    };
    let mut a = Owner::external_backends(&config, vec![backend]).unwrap();
    a.test_now = Some(0);
    let v4 = |address: &str, port: u16| SocketAddr::new(address.parse().unwrap(), port);
    for (destination, mac) in [
        ("10.80.0.5", [2, 0, 0, 0, 0, 0xa]),
        ("10.73.1.7", [2, 0, 0, 0, 0, 0xb]),
    ] {
        let s = new(&mut a);
        assert_eq!(a.execute(s, Op::Connect(v4(destination, 80))).unwrap_err(), EINPROGRESS);
        a.service_egress().unwrap();
        let frame = state.lock().unwrap().sent.pop_front().expect("a SYN");
        let eth = ntcp_ethernet::parse_ethernet(&frame).unwrap();
        assert_eq!(eth.destination, mac);
        let ip = ntcp_ip::parse(eth.payload, false).unwrap();
        assert_eq!(ip.ip.destination, destination.parse::<IpAddr>().unwrap());
    }
    let s = new(&mut a);
    let _ = a.execute(s, Op::Connect(v4("10.99.0.1", 80)));
    a.service_egress().unwrap();
    assert!(state.lock().unwrap().sent.is_empty());
}

// DAD failure on a native ND port (RFC 4862 section 5.4.3): another node's
// DAD solicitation for the tentative fe80::1 on port b makes it a
// duplicate that stays unusable there (no bind, no answer), while port c
// assigns the same address on its own link.
#[test]
fn dad_failure_on_one_neighbor_discovery_port_leaves_the_other_usable() {
    let (mut a, sa) = nd_owner();
    let own: std::net::Ipv6Addr = "fe80::1".parse().unwrap();
    let group = ntcp_ethernet::solicited_node(own);
    let ns = ntcp_icmp::NeighborSolicitation {
        target: own,
        source_link_layer: None,
    };
    let mut message = [0; 32];
    let ip = ntcp::IpMetadata {
        source: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        destination: IpAddr::V6(group),
    };
    let n = ntcp_icmp::encode_solicitation(ip, ns, &mut message).unwrap();
    a.input_link(1, &nd_packet("::", group, 255, &message[..n]), Default::default(), None, true);
    let mut peers = link_local_peers();
    let mut seen = [Vec::new(), Vec::new()];
    for step in 0..=30 {
        a.test_now = Some(step * 100_000);
        exchange_nd(&mut a, &sa, &mut peers, &mut seen);
    }
    let state = |a: &Owner, i: usize| {
        let link = a.ports[i].link().unwrap();
        a.host.as_ref().unwrap().neighbor_address_state(link, own)
    };
    assert_eq!(state(&a, 1), Some(ntcp_host::AddressState::Duplicate));
    assert_eq!(state(&a, 2), Some(ntcp_host::AddressState::Assigned));
    // Port b sent no probe after the failure; port c its one probe.
    assert!(seen[0].is_empty(), "{:?}", seen[0]);
    assert_eq!(seen[1].len(), 1);
    // Nothing originates from the duplicate: a connection on port b
    // sends nothing (not even a solicitation), one on port c resolves.
    // The duplicate is not an address to bind (D16, as Linux).
    let blocked = new(&mut a);
    assert_eq!(a.execute(blocked, Op::Bind(v6("fe80::1", 9000, 2))).unwrap_err(), EADDRNOTAVAIL);
    // Nor does a wildcard socket select it as its source.
    assert_eq!(a.execute(blocked, Op::Connect(v6("fe80::2", 8080, 2))).unwrap_err(), EADDRNOTAVAIL);
    let s = new(&mut a);
    a.execute(s, Op::Bind(v6("fe80::1", 9000, 3))).unwrap();
    assert_eq!(a.execute(s, Op::Connect(v6("fe80::2", 8080, 3))).unwrap_err(), EINPROGRESS);
    for _ in 0..3 {
        a.test_now = a.test_now.map(|now| now + 1000);
        a.service_discovery();
        a.service_egress().unwrap();
    }
    assert!(sa[1].lock().unwrap().sent.is_empty());
    let sent = sent_icmp(&sa[2]);
    assert!(sent.iter().any(|&(kind, ..)| kind == 135), "{sent:?}");
}

// Resolution failure for a held SYN (RFC 4861 section 7.2.2): a connect to
// an on-link link-local peer that never answers sends at most
// MAX_MULTICAST_SOLICIT solicitations per attempt and nothing else (no
// frame to a guessed MAC). The failed attempt is withdrawn unsubmitted, its
// Address Unreachable advice becomes the socket's soft error (RFC 1122
// section 4.2.3.9), the next attempt waits one RTO after the failure and
// resolves again, and the connection ends at its deadline.
#[test]
fn unresolved_syn_is_retried_at_the_rto_and_ends_at_its_deadline() {
    let (mut a, sa) = nd_owner_assigned();
    let start = a.test_now.unwrap();
    let s = new(&mut a);
    a.execute(s, Op::Bind(v6("fe80::1", 9000, 2))).unwrap();
    assert_eq!(a.execute(s, Op::Connect(v6("fe80::5", 8080, 2))).unwrap_err(), EINPROGRESS);
    let group = ntcp_ethernet::solicited_node("fe80::5".parse().unwrap());
    let group_mac = ntcp_ethernet::ipv6_multicast_mac(group).unwrap();
    let mut solicitations = Vec::new();
    let mut soft_error = false;
    let step = |a: &mut Owner, now: u64, solicitations: &mut Vec<u64>| {
        a.test_now = Some(now);
        a.endpoint.on_timeout(now, BUDGET).unwrap();
        a.service_discovery();
        a.service_egress().unwrap();
        a.events();
        while let Some(frame) = sa[1].lock().unwrap().sent.pop_front() {
            let (source, ns) = solicitation(&frame).expect("only solicitations leave");
            assert_eq!((source, ns.target), ("fe80::1".parse().unwrap(), "fe80::5".parse().unwrap()));
            assert_eq!(ntcp_ethernet::parse_ethernet(&frame).unwrap().destination, group_mac);
            solicitations.push(now - start);
        }
        assert!(sa[2].lock().unwrap().sent.is_empty());
    };
    let mut now = start;
    while now < start + 20_000_000 {
        now += 10_000;
        step(&mut a, now, &mut solicitations);
        // Socket calls wait while its SYN is held (EAGAIN).
        let error = a.execute(s, Op::Get(SOL_SOCKET, SO_ERROR)).map_or_else(|e| e, |r| r.value);
        assert!([0, EAGAIN, EHOSTUNREACH].contains(&error), "{error}");
        soft_error |= error == EHOSTUNREACH;
    }
    assert!(soft_error);
    // Attempts: solicitations one RetransTimer apart; failure one
    // RetransTimer after the last, and the next attempt one RTO (1 s, not
    // backed off) after that.
    let mut attempts: Vec<Vec<u64>> = Vec::new();
    for &at in &solicitations {
        match attempts.last_mut() {
            Some(attempt) if at - attempt.last().unwrap() < 1_500_000 => attempt.push(at),
            _ => attempts.push(vec![at]),
        }
    }
    assert!(attempts.len() >= 4, "{solicitations:?}");
    for pair in attempts.windows(2) {
        assert_eq!(pair[0].len(), 3, "{solicitations:?}");
        assert!(pair[1][0] - pair[0][2] >= 2_000_000, "{solicitations:?}");
        assert!(pair[1][0] - pair[0][2] < 2_100_000, "{solicitations:?}");
    }
    assert!(a.endpoint.transport_info(cid(&a, s)).unwrap().retransmitted == 0);
    // The SYN's R2 deadline (at least three minutes) ends it TimedOut.
    while a.execute(s, Op::Get(SOL_SOCKET, SO_ERROR)).map_or_else(|e| e, |r| r.value) != ETIMEDOUT {
        now += 500_000;
        assert!(now < start + 400_000_000);
        step(&mut a, now, &mut solicitations);
    }
    let config = SocketConfig::new("external", "fe80::9".parse::<IpAddr>().unwrap());
    let deadline = config.tcp.connection.user_timeout_us.max(180_000_000);
    assert!(now - start >= deadline, "{}", now - start);
    assert!(now - start < deadline + 4_000_000, "{}", now - start);
}

// A held attempt the Endpoint cannot roll back (D15): the peer of an
// established connection leaves with data in flight. Neighbor
// Unreachability Detection removes its entry (RFC 4861 section 7.3.3), and
// the next retransmission, selected behind the outstanding flight, is held
// for address resolution, which fails. It is released as unsent output:
// the Address Unreachable advice becomes the socket's soft error (RFC 1122
// section 4.2.3.9), the owner's reservation deadline never abandons the
// connection, and once the neighbor answers again TCP's own retransmission
// resolves it and delivers the data.
#[test]
fn unrestorable_held_output_survives_resolution_failure_and_is_delivered() {
    let (mut a, sa) = nd_owner_assigned();
    let mut peers = link_local_peers();
    let l = link_local_listener(&mut peers[0].0, v6("fe80::2", 8080, 1), None);
    let mut seen = [Vec::new(), Vec::new()];
    let s = new(&mut a);
    a.execute(s, Op::Bind(v6("fe80::1", 9000, 2))).unwrap();
    assert_eq!(a.execute(s, Op::Connect(v6("fe80::2", 8080, 2))).unwrap_err(), EINPROGRESS);
    exchange_nd(&mut a, &sa, &mut peers, &mut seen);
    a.execute(s, Op::Write(vec![0x61; 1000])).unwrap();
    exchange_nd(&mut a, &sa, &mut peers, &mut seen);
    let child = peers[0].0.execute(l, Op::Accept(0)).unwrap().value as u64;
    assert_eq!(peers[0].0.execute(child, Op::Read(4000)).unwrap().bytes, vec![0x61; 1000]);
    // The peer leaves: every frame to it is lost and nothing answers.
    a.execute(s, Op::Write(vec![0x62; 1000])).unwrap();
    let link = a.ports[1].link().unwrap();
    let peer: std::net::Ipv6Addr = "fe80::2".parse().unwrap();
    let id = cid(&a, s);
    let start = a.test_now.unwrap();
    let mut now = start;
    let step = |a: &mut Owner, now: u64| {
        a.test_now = Some(now);
        a.expire_egress(now).unwrap();
        a.endpoint.on_timeout(now, BUDGET).unwrap();
        a.service_discovery();
        a.service_egress().unwrap();
        a.events();
        sa[1].lock().unwrap().sent.clear();
        a.execute(s, Op::Get(SOL_SOCKET, SO_ERROR)).map_or_else(|e| e, |r| r.value)
    };
    let mut removed = false;
    loop {
        now += 50_000;
        assert!(now < start + 250_000_000);
        let error = step(&mut a, now);
        assert!([0, EAGAIN, EHOSTUNREACH].contains(&error), "{error}");
        removed |= a.host.as_ref().unwrap().neighbor(link, peer).is_none();
        if error == EHOSTUNREACH {
            break;
        }
    }
    assert!(removed);
    // Well past the owner's reservation deadline: still established.
    let failed = now;
    while now < failed + 3_000_000 {
        now += 50_000;
        step(&mut a, now);
    }
    assert_eq!(a.endpoint.close_reason(id).unwrap(), None);
    assert_eq!(a.endpoint.state(id).unwrap(), ntcp::State::Established);
    // The neighbor answers again.
    let mut delivered = Vec::new();
    while delivered.len() < 1000 {
        now += 50_000;
        assert!(now < start + 290_000_000);
        a.test_now = Some(now);
        a.endpoint.on_timeout(now, BUDGET).unwrap();
        exchange_nd(&mut a, &sa, &mut peers, &mut seen);
        now = a.test_now.unwrap();
        if let Ok(read) = peers[0].0.execute(child, Op::Read(4000)) {
            delivered.extend(read.bytes);
        }
    }
    assert_eq!(delivered, vec![0x62; 1000]);
    assert_eq!(a.endpoint.close_reason(id).unwrap(), None);
}

// Path MTU per IPv6 link (RFC 8201 section 5.2) on two ND ports with
// identical link-local pairs and link MTUs 1500 and 1400: each connection
// probes up to its own link, and a checksummed PTB quoting a packet
// definitely submitted on port b lowers only b's estimate and packet
// sizes; port c's estimate and both first-hop MTUs stay unchanged.
//= https://www.rfc-editor.org/rfc/rfc8201#section-5.2
//= type=test
//= reason=Each IPv6 link keeps its own Path MTU information. PathService keys learned estimates by context, source, destination with its zone, routing DSCP, link, next hop and route generation, and a link-local destination carries an authoritative LinkId zone (context, slot, generation) with which Host::prepare selects and acquires the path on exactly that link before TCP construction. T18 carries this scoped tuple through Endpoint and Host factories, listeners (an exact address and zone beats the wildcard; wildcard children carry the arrival link), TIME-WAIT, digests, Fast Open and MSS caches, Host UDP flows and zone-constrained ICMP correlation; the native runtime resolves sin6_scope_id through its interface-index-to-live-link map over a bounded collection of configured ports, each with its own link, addresses and routes, and IPv6 Ethernet ports resolve next hops by bounded host Neighbor Discovery. Host tests (ntcp-host src/tests/scoped.rs) keep identical link-local pairs on two links as separate connections and UDP flows, and a PTB correlated with one link's submission lowers only that link's estimate; the native two-port test neighbor_discovery_ports_keep_path_mtu_per_link probes each connection up to its own link MTU (1500 and 1400), and a checksummed PTB quoting a packet definitely submitted on one port lowers only that port's estimate and packet sizes while the other port's estimate and both first-hop MTUs stay unchanged; the integration/rfc_host scoped two-link case (one native runtime owning two veth links of MTU 1500 and 1400 to one Linux peer namespace, identical link-local pairs, captured DAD and NS/NA, hashed TCP streams on both links) shows a checksummed, harness-injected PTB quoting a captured packet on link A lowering only A's learned PMTU and packet sizes while link B keeps 1400-octet packets and both first-hop MTUs stay unchanged, and later connections start at their own link's value.
//# Ideally, a PMTU value should be associated with a specific path traversed by packets exchanged between the source and destination nodes. However, in most cases a node will not have enough information to completely and accurately identify such a path. Rather, a node must associate a PMTU value with some local representation of a path. It is left to the implementation to select the local representation of a path. For nodes with multiple interfaces, Path MTU information should be maintained for each IPv6 link.
#[test]
fn neighbor_discovery_ports_keep_path_mtu_per_link() {
    let (mut a, sa) = nd_owner_assigned_with([Some(1500), Some(1400)]);
    let mut peers = link_local_peers();
    let listeners: Vec<u64> = peers
        .iter_mut()
        .map(|(peer, _)| link_local_listener(peer, v6("fe80::2", 8080, 1), None))
        .collect();
    let mut seen = [Vec::new(), Vec::new()];
    let sockets = [2, 3].map(|scope| {
        let s = new(&mut a);
        a.execute(s, Op::Bind(v6("fe80::1", 9000, scope))).unwrap();
        assert_eq!(a.execute(s, Op::Connect(v6("fe80::2", 8080, scope))).unwrap_err(), EINPROGRESS);
        s
    });
    exchange_nd(&mut a, &sa, &mut peers, &mut seen);
    let children: Vec<u64> = peers
        .iter_mut()
        .zip(&listeners)
        .map(|((peer, _), &l)| peer.execute(l, Op::Accept(0)).unwrap().value as u64)
        .collect();
    let mtu = |a: &Owner, s: u64| a.endpoint.path_mtu_info(cid(a, s)).unwrap().unwrap().current_mtu;
    let first_hop = |a: &Owner, s: u64| {
        a.host.as_ref().unwrap().binding(cid(a, s)).unwrap().snapshot.first_hop_mtu()
    };
    assert_eq!([first_hop(&a, sockets[0]), first_hop(&a, sockets[1])], [1500, 1400]);
    let mut transfer = |a: &mut Owner, peers: &mut [(Owner, Arc<Mutex<State>>); 2], rounds: usize| {
        let mut lengths = [Vec::new(), Vec::new()];
        for _ in 0..rounds {
            for &s in &sockets {
                a.execute(s, Op::Write(vec![7; 20_000])).unwrap();
            }
            for _ in 0..8 {
                a.test_now = a.test_now.map(|now| now + 50_000);
                a.endpoint.on_timeout(a.test_now.unwrap(), BUDGET).unwrap();
                exchange_nd_lengths(a, &sa, peers, &mut seen, &mut lengths);
            }
            for (i, (peer, _)) in peers.iter_mut().enumerate() {
                while peer.execute(children[i], Op::Read(65536)).is_ok_and(|r| !r.bytes.is_empty()) {}
            }
        }
        lengths
    };
    // Packetization-layer probing raises each estimate to its own link.
    let lengths = transfer(&mut a, &mut peers, 40);
    assert_eq!([mtu(&a, sockets[0]), mtu(&a, sockets[1])], [1500, 1400]);
    assert!(lengths[0].iter().all(|&n| n <= 1500) && lengths[0].contains(&1500), "{:?}", lengths[0]);
    assert!(lengths[1].iter().all(|&n| n <= 1400) && lengths[1].contains(&1400), "{:?}", lengths[1]);
    // A correlated PTB on port b quoting one of its submitted packets.
    a.execute(sockets[0], Op::Write(vec![9; 1440])).unwrap();
    a.test_now = a.test_now.map(|now| now + 1000);
    a.service_egress().unwrap();
    let frame = sa[1].lock().unwrap().sent.pop_front().expect("a data packet on port b");
    let eth = ntcp_ethernet::parse_ethernet(&frame).unwrap();
    assert_eq!(eth.destination, ND_PEER[0]);
    let quoted = &eth.payload[..ntcp_ip6::parse(eth.payload).map(|p| 40 + p.payload.len()).unwrap()];
    assert_eq!(quoted.len(), 1500);
    let ptb = feedback(quoted, 2, 0, 1300);
    a.input_link(1, &ptb, Default::default(), None, false);
    // Below the 1500 already proven delivered, the decrease waits for the
    // quoted data's timeout (RFC 5927 policy); the dropped packet never
    // reached the peer, so its retransmission timer applies it.
    assert_eq!([mtu(&a, sockets[0]), mtu(&a, sockets[1])], [1500, 1400]);
    for _ in 0..4 {
        if mtu(&a, sockets[0]) == 1300 {
            break;
        }
        let deadline = a.endpoint.next_deadline().unwrap();
        a.test_now = Some(deadline.max(a.test_now.unwrap()));
        a.endpoint.on_timeout(a.test_now.unwrap(), BUDGET).unwrap();
    }
    assert_eq!([mtu(&a, sockets[0]), mtu(&a, sockets[1])], [1300, 1400]);
    let lengths = transfer(&mut a, &mut peers, 4);
    assert!(lengths[0].iter().all(|&n| n <= 1300) && lengths[0].contains(&1300), "{:?}", lengths[0]);
    assert!(lengths[1].contains(&1400), "{:?}", lengths[1]);
    assert_eq!([first_hop(&a, sockets[0]), first_hop(&a, sockets[1])], [1500, 1400]);
}

// A tentative ND-port address is not available to bind (RFC 4862 section
// 5.4; Linux inet6_bind's EADDRNOTAVAIL) until DAD assigns it.
#[test]
fn bind_to_a_tentative_address_fails_until_dad_assigns_it() {
    let (mut a, sa) = nd_owner();
    let s = new(&mut a);
    assert_eq!(a.execute(s, Op::Bind(v6("fe80::1", 9000, 2))).unwrap_err(), EADDRNOTAVAIL);
    let mut peers = link_local_peers();
    let mut seen = [Vec::new(), Vec::new()];
    for step in 0..=30 {
        a.test_now = Some(step * 100_000);
        exchange_nd(&mut a, &sa, &mut peers, &mut seen);
    }
    a.execute(s, Op::Bind(v6("fe80::1", 9000, 2))).unwrap();
}

// Blocked resolution with partial software GSO and a shared send on an ND
// port (RFC 4861 sections 7.2.2 and 7.3.3). The established peer stops
// answering: its mapping goes STALE, an Echo Reply's use starts DELAY and
// the unanswered unicast probes remove it. A GSO aggregate (copied, or a
// MSG_ZEROCOPY send's shared payload) is then held while fe80::2 is
// resolved again: only the solicitation leaves, nothing is in flight and
// no zero-copy completion is reported. After the NA (a new MAC) the
// backend accepts one segment and then blocks; once it drains, every
// segment has left exactly once, in order, to the new MAC, the peer has
// the complete stream and the shared buffer is completed once.
#[test]
fn blocked_resolution_holds_partial_gso_and_shared_output_until_the_advertisement() {
    const GSO: ntcp::GsoLimits = ntcp::GsoLimits {
        max_bytes: 65536,
        max_segments: 4,
    };
    const MOVED: [u8; 6] = [2, 0, 0, 0, 0, 0x1a];
    let held_segmentation = |a: &Owner, id: ConnectionId| {
        a.endpoint.transmit_segmentation(a.egress.as_ref().unwrap().attempt(id))
    };
    for zero_copy in [false, true] {
        let (mut a, sa) = nd_owner_assigned_gso([None; 2], (!zero_copy).then_some(GSO));
        let mut peers = link_local_peers();
        let l = link_local_listener(&mut peers[0].0, v6("fe80::2", 8080, 1), None);
        let mut seen = [Vec::new(), Vec::new()];
        let s = new(&mut a);
        a.execute(s, Op::Bind(v6("fe80::1", 9000, 2))).unwrap();
        a.execute(s, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1)).unwrap();
        if zero_copy {
            a.execute(s, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1)).unwrap();
        }
        assert_eq!(a.execute(s, Op::Connect(v6("fe80::2", 8080, 2))).unwrap_err(), EINPROGRESS);
        exchange_nd(&mut a, &sa, &mut peers, &mut seen);
        let child = peers[0].0.execute(l, Op::Accept(0)).unwrap().value as u64;
        let id = cid(&a, s);
        let link = a.ports[1].link().unwrap();
        let peer: std::net::Ipv6Addr = "fe80::2".parse().unwrap();
        let state = |a: &Owner| a.host.as_ref().unwrap().neighbor(link, peer).map(|n| n.0);
        assert_eq!(state(&a), Some(ntcp_host::NeighborState::Reachable));
        let mut now = a.test_now.unwrap();
        let mut tick = |a: &mut Owner, step: u64| {
            now += step;
            a.test_now = Some(now);
            a.endpoint.on_timeout(now, BUDGET).unwrap();
            a.service_discovery();
            a.service_egress().unwrap();
            a.events();
        };
        // ReachableTime is at most 1.5 x 30 s.
        for _ in 0..50 {
            tick(&mut a, 1_000_000);
        }
        assert_eq!(state(&a), Some(ntcp_host::NeighborState::Stale));
        a.input_link(1, &echo_to_own("fe80::2"), Default::default(), None, false);
        let mut probes = 0;
        for _ in 0..100 {
            tick(&mut a, 100_000);
            while let Some(frame) = sa[1].lock().unwrap().sent.pop_front() {
                let eth = ntcp_ethernet::parse_ethernet(&frame).unwrap();
                assert_eq!(eth.destination, ND_PEER[0]);
                if let Some((_, ns)) = solicitation(&frame) {
                    assert_eq!(ns.target, peer);
                    probes += 1;
                }
            }
        }
        assert_eq!((probes, state(&a)), (3, None));
        // The aggregate, held for the new resolution: three full segments,
        // the restart window after the idle period.
        let mss = a.endpoint.transport_info(id).unwrap().mss as usize;
        assert_eq!(a.endpoint.transport_info(id).unwrap().cwnd as usize, 3 * mss);
        let data: Vec<u8> = (0..3 * mss).map(|i| (i % 251) as u8).collect();
        let registered = crate::RegisteredPayload::register(Payload::from_vec(data.clone())).unwrap();
        let pointer = registered.as_slice().as_ptr();
        if zero_copy {
            let (reply, rx) = mpsc::sync_channel(1);
            let mut request = Request {
                id: s,
                op: Op::Send(vec![(pointer as usize, data.len())], MSG_ZEROCOPY),
                reply,
                deadline: None,
                send: None,
                closing: None,
            };
            assert!(a.service(&mut request));
            assert_eq!(rx.recv().unwrap().unwrap().value, data.len() as i32);
        } else {
            a.execute(s, Op::Write(data.clone())).unwrap();
        }
        let progress = a.endpoint.send_progress(id).unwrap();
        let group = ntcp_ethernet::solicited_node(peer);
        let mut solicited = Vec::new();
        for _ in 0..5 {
            tick(&mut a, 1000);
            while let Some(frame) = sa[1].lock().unwrap().sent.pop_front() {
                let (_, ns) = solicitation(&frame).expect("only the solicitation leaves");
                solicited.push((ns.target, ntcp_ethernet::parse_ethernet(&frame).unwrap().destination));
            }
        }
        assert_eq!(solicited, [(peer, ntcp_ethernet::ipv6_multicast_mac(group).unwrap())]);
        assert!(sa[1].lock().unwrap().held.is_empty());
        // Not a departure: nothing in flight, no completion.
        let info = a.endpoint.transport_info(id).unwrap();
        assert_eq!((info.unacked, info.retransmitted, info.rto_backoff), (0, 0, 0));
        assert_eq!(a.endpoint.send_progress(id).unwrap(), progress);
        a.collect_zero_copy();
        assert!(a.sockets[&s].completions.is_empty());
        assert!(a.endpoint.is_output_reserved(id));
        let segmentation = held_segmentation(&a, id);
        if !zero_copy {
            let segmentation = segmentation.expect("a held GSO aggregate");
            assert!(segmentation.payload_len >= 2 * segmentation.segment_payload_len, "{segmentation:?}");
        }
        // The NA; the backend takes one segment, then blocks.
        let na = ntcp_icmp::NeighborAdvertisement {
            router: false,
            solicited: true,
            override_: true,
            target: peer,
            target_link_layer: Some(MOVED),
        };
        let own: std::net::Ipv6Addr = "fe80::1".parse().unwrap();
        let ip = ntcp::IpMetadata {
            source: IpAddr::V6(peer),
            destination: IpAddr::V6(own),
        };
        let mut message = [0; 32];
        let n = ntcp_icmp::encode_advertisement(ip, na, &mut message).unwrap();
        a.input_link(1, &nd_packet("fe80::2", own, 255, &message[..n]), Default::default(), None, false);
        sa[1].lock().unwrap().allow = Some(1);
        tick(&mut a, 1000);
        let count = |state: &Arc<Mutex<State>>| {
            let state = state.lock().unwrap();
            state.sent.len() + state.held.len()
        };
        assert_eq!(count(&sa[1]), 1);
        // A GSO aggregate's remaining suffix stays reserved.
        assert_eq!(held_segmentation(&a, id).is_some(), !zero_copy);
        tick(&mut a, 1000);
        assert_eq!(count(&sa[1]), 1);
        sa[1].lock().unwrap().allow = None;
        for _ in 0..4 {
            tick(&mut a, 1000);
        }
        // Every frame, scalar or shared, in submission order.
        let frames: Vec<Vec<u8>> = {
            let mut state = sa[1].lock().unwrap();
            let mut frames: Vec<Vec<u8>> = state.sent.drain(..).collect();
            let mut offset = 0;
            for p in &state.held {
                let mut frame = p.header.clone();
                for part in &p.payload {
                    assert_eq!(part.as_slice().as_ptr(), pointer.wrapping_add(offset));
                    offset += part.len();
                    frame.extend_from_slice(part.as_slice());
                }
                frames.push(frame);
            }
            assert_eq!(offset, if zero_copy { data.len() } else { 0 });
            frames
        };
        let mut next = progress.unacknowledged_sequence;
        let mut carried = 0;
        for frame in &frames {
            let eth = ntcp_ethernet::parse_ethernet(frame).unwrap();
            assert_eq!(eth.destination, MOVED);
            let packet = ntcp_ip6::parse(eth.payload).unwrap();
            let tcp = ntcp::wire::parse(packet.ip, packet.payload).unwrap();
            assert_eq!(tcp.header.sequence, next);
            next = next.wrapping_add(tcp.payload.len() as u32);
            carried += tcp.payload.len();
            peers[0].0.input_ip_metadata(eth.payload, Default::default(), None);
        }
        assert_eq!(carried, data.len());
        assert_eq!(frames.len(), 3);
        drop(registered);
        peers[0].0.events();
        assert_eq!(peers[0].0.execute(child, Op::Read(8000)).unwrap().bytes, data);
        peers[0].0.service_egress().unwrap();
        while let Some(frame) = peers[0].1.lock().unwrap().sent.pop_front() {
            let eth = ntcp_ethernet::parse_ethernet(&frame).unwrap();
            a.input_link(1, eth.payload, Default::default(), None, false);
        }
        a.events();
        let info = a.endpoint.transport_info(id).unwrap();
        assert_eq!((info.unacked, info.retransmitted), (0, 0));
        sa[1].lock().unwrap().held.clear();
        a.collect_zero_copy();
        let completions: Vec<_> = a.sockets[&s].completions.iter().cloned().collect();
        if zero_copy {
            assert_eq!(completions, [Completion::SharedZeroCopy(0, 0, false)]);
        } else {
            assert!(completions.is_empty());
        }
    }
}
