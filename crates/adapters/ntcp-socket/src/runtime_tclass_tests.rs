// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

#[test]
fn ipv6_tclass_reset_invalid_input_and_live_wire_preserve_ecn() {
    for ecn in [false, true] {
        let (mut a, mut b, client, server, sa, sb) = pair_with_ecn(ecn);
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
            .unwrap();
        let connection = cid(&a, client);
        for (value, expected) in [(43, 40), (-1, 0), (255, 252), (3, 0)] {
            a.execute(client, Op::Set(IPPROTO_IPV6, IPV6_TCLASS, value))
                .unwrap();
            assert_eq!(
                a.execute(client, Op::Get(IPPROTO_IPV6, IPV6_TCLASS))
                    .unwrap()
                    .value,
                expected
            );
            let before = a.endpoint.transport_info(connection).unwrap();
            // Invalid values must not reset the class or disturb live TCP state.
            for invalid in [-2, 256, i32::MIN, i32::MAX] {
                assert_eq!(
                    a.execute(client, Op::Set(IPPROTO_IPV6, IPV6_TCLASS, invalid))
                        .unwrap_err(),
                    EINVAL
                );
                assert_eq!(
                    a.execute(client, Op::Get(IPPROTO_IPV6, IPV6_TCLASS))
                        .unwrap()
                        .value,
                    expected
                );
                assert_eq!(a.endpoint.transport_info(connection).unwrap(), before);
            }
            a.execute(client, Op::Write(vec![7; 100])).unwrap();
            a.service_egress().unwrap();
            let frame = sa.lock().unwrap().sent.pop_front().unwrap();
            let ip = ntcp_ip6::parse(&frame[14..]).unwrap();
            let tcp = ntcp::wire::parse(ip.ip, ip.payload).unwrap();
            assert_eq!(tcp.payload, [7; 100]);
            assert_eq!(ip.traffic_class >> 2, (expected >> 2) as u8);
            assert_eq!(ip.traffic_class & 3, if ecn { 2 } else { 0 });
            b.input_ip_metadata(&frame[14..], Default::default(), None);
            exchange(&mut a, &mut b, &sa, &sb);
            assert_eq!(
                b.execute(server, Op::Read(100)).unwrap().bytes,
                vec![7; 100]
            );
        }
    }
}

#[test]
fn ipv6_tclass_fresh_syn_reset_and_ipv4_tos_remain_distinct() {
    // An explicit reset clears a previous class, including configured initial DSCP.
    for (value, expected) in [(-1, 0), (0, 0), (43, 40), (255, 252)] {
        let (mut a, state) = owner_with_policy(1, false, 11);
        let id = new(&mut a);
        assert_eq!(
            a.execute(id, Op::Get(IPPROTO_IPV6, IPV6_TCLASS))
                .unwrap()
                .value,
            44
        );
        a.execute(id, Op::Set(IPPROTO_IPV6, IPV6_TCLASS, value))
            .unwrap();
        assert_eq!(
            a.execute(id, Op::Get(IPPROTO_IPV6, IPV6_TCLASS))
                .unwrap()
                .value,
            expected
        );
        assert_eq!(
            a.execute(id, Op::Connect("[2001:db8::2]:8080".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        a.service_egress().unwrap();
        let frame = state.lock().unwrap().sent.pop_front().unwrap();
        let ip = ntcp_ip6::parse(&frame[14..]).unwrap();
        assert_eq!(ip.traffic_class, expected as u8);
        assert_ne!(
            ntcp::wire::parse(ip.ip, ip.payload).unwrap().header.flags & ntcp::wire::SYN,
            0
        );
    }
    // Linux IPv4 IP_TOS still uses byte truncation; IPv6 validation is not shared.
    for (value, expected) in [(-1, 252), (-2, 252), (256, 0), (259, 0)] {
        let mut config = SocketConfig::new("external", Ipv4Addr::new(192, 0, 2, 1));
        config.io.prefix = Some(24);
        let state = Arc::new(Mutex::new(State::default()));
        let mut a = Owner::external_backend(
            &config,
            crate::EthernetPacketIo {
                io: Box::new(Io(state.clone())),
                local_mac: [2; 6],
                next_hop_mac: [4; 6],
            },
        )
        .unwrap();
        a.test_now = Some(0);
        let id = new(&mut a);
        a.execute(id, Op::Set(IPPROTO_IP, IP_TOS, value)).unwrap();
        assert_eq!(
            a.execute(id, Op::Get(IPPROTO_IP, IP_TOS)).unwrap().value,
            expected
        );
        assert_eq!(
            a.execute(id, Op::Set(IPPROTO_IPV6, IPV6_TCLASS, 40))
                .unwrap_err(),
            ENOPROTOOPT
        );
        assert_eq!(
            a.execute(id, Op::Connect("192.0.2.2:8080".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        a.service_egress().unwrap();
        let frame = state.lock().unwrap().sent.pop_front().unwrap();
        let ip = ntcp_ip::parse(&frame[14..], false).unwrap();
        assert_eq!(ip.traffic_class, expected as u8);
    }
}

#[test]
fn ipv6_tclass_native_abi_signed_values_and_faults_are_atomic() {
    const CHILD: &str = "NTCP_IPV6_TCLASS_ABI_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "runtime::ipv6_tests::tclass_tests::ipv6_tclass_native_abi_signed_values_and_faults_are_atomic", "--test-threads=1"])
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
        for (value, expected) in [(43i32, 40), (-1, 0), (255, 252)] {
            assert_eq!(
                setsockopt(
                    fd,
                    IPPROTO_IPV6,
                    IPV6_TCLASS,
                    (&value as *const i32).cast(),
                    4
                ),
                0
            );
            for invalid in [-2i32, 256, i32::MIN, i32::MAX] {
                assert_eq!(
                    setsockopt(
                        alias,
                        IPPROTO_IPV6,
                        IPV6_TCLASS,
                        (&invalid as *const i32).cast(),
                        4
                    ),
                    -1
                );
                assert_eq!(errno(), EINVAL);
                let mut out = -1i32;
                let mut len = 4;
                assert_eq!(
                    getsockopt(
                        fd,
                        IPPROTO_IPV6,
                        IPV6_TCLASS,
                        (&mut out as *mut i32).cast(),
                        &mut len
                    ),
                    0
                );
                assert_eq!((out, len), (expected, 4));
            }
        }
        let zero = 0i32;
        assert_eq!(
            setsockopt(
                alias,
                IPPROTO_IPV6,
                IPV6_TCLASS,
                (&zero as *const i32).cast(),
                1
            ),
            -1
        );
        assert_eq!(errno(), EINVAL);
        assert_eq!(
            setsockopt(alias, IPPROTO_IPV6, IPV6_TCLASS, ptr::null(), 4),
            -1
        );
        assert_eq!(errno(), EFAULT);
        let mut out = -1i32;
        let mut len = 4;
        assert_eq!(
            getsockopt(
                fd,
                IPPROTO_IPV6,
                IPV6_TCLASS,
                (&mut out as *mut i32).cast(),
                &mut len
            ),
            0
        );
        assert_eq!((out, len), (252, 4));
        assert_eq!(close(alias), 0);
        assert_eq!(close(fd), 0);
    }
}
