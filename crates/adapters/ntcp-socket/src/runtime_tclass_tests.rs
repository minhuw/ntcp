// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

//= https://www.rfc-editor.org/rfc/rfc3542#section-6.5
//= type=test
//# In order to clear a sticky IPV6_TCLASS option the application can
//# specify -1 as the value.
//= https://www.rfc-editor.org/rfc/rfc3542#section-6.5
//= type=test
//# There are cases where the kernel needs to control the traffic class
//# value and conflicts with the user-specified value on the outgoing
//# traffic. An example is an implementation of ECN in the kernel,
//# setting 2 bits of the traffic class value. In such cases, the kernel
//# should override the user-specified value.
//= https://www.rfc-editor.org/rfc/rfc3542#section-4.1
//= type=test
//# When the application uses setsockopt to specify the above options it
//# is expected that TCP will start using the new information when
//# sending segments. However, TCP may or may not use the new information
//# when retransmitting segments that were originally sent when the old
//# sticky options were in effect.
#[test]
fn ipv6_tclass_reset_invalid_input_and_live_wire_preserve_ecn() {
    for ecn in [false, true] {
        let (mut a, mut b, client, server, sa, sb) = pair_with_ecn(ecn);
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
            .unwrap();
        let connection = cid(&a, client);
        assert_eq!(
            a.execute(client, Op::Get(IPPROTO_IPV6, IPV6_TCLASS))
                .unwrap()
                .value,
            0
        );
        for (value, expected) in [(43, 43), (-1, 0), (255, 255), (0, 0), (3, 3)] {
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
            // A second segment without another setsockopt proves persistence.
            for _ in 0..2 {
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
}

#[test]
fn ipv6_tclass_fresh_syn_reset_and_ipv4_tos_remain_distinct() {
    // An explicit reset clears a previous class, including configured initial DSCP.
    for (value, expected) in [(-1, 0), (0, 0), (43, 43), (255, 255)] {
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
        assert_eq!(ip.traffic_class, (expected & !3) as u8);
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
                next_hop_mac: Some([4; 6]),
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
            a.execute(id, Op::Get(IPPROTO_IPV6, IPV6_TCLASS))
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

//= https://www.rfc-editor.org/rfc/rfc3542#section-6.5
//= type=test
//# The outgoing traffic class is normally set to 0.
//= https://www.rfc-editor.org/rfc/rfc3542#section-6.5
//= type=test
//# To specify the outgoing traffic class value, just specify the control
//# information as ancillary data for sendmsg() or using setsockopt().
//# Just like the hop limit value, the interpretation of the integer
//# traffic class value is
//# x < -1: return an error of EINVAL
//# x == -1: use kernel default
//# 0 <= x <= 255: use x
//# x >= 256: return an error of EINVAL
//= https://www.rfc-editor.org/rfc/rfc3542#section-4
//= type=test
//# Issuing getsockopt() for the above options will return the sticky
//# option value i.e., the value set with setsockopt().
//= https://www.rfc-editor.org/rfc/rfc3542#section-4
//= type=test
//# For the IPV6_TCLASS option, it will return the kernel default value.
#[test]
fn ipv6_tclass_default_zero_and_all_sticky_values() {
    // Include a socket that never sets the option to observe the normal default
    // on the wire, then exercise the entire valid integer range and reset.
    for value in std::iter::once(None).chain((-1..=255).map(Some)) {
        let (mut a, state) = owner(1);
        let id = new(&mut a);
        assert_eq!(
            a.execute(id, Op::Get(IPPROTO_IPV6, IPV6_TCLASS))
                .unwrap()
                .value,
            0
        );
        if let Some(value) = value {
            a.execute(id, Op::Set(IPPROTO_IPV6, IPV6_TCLASS, value))
                .unwrap();
        }
        let expected = value.unwrap_or(0).max(0);
        assert_eq!(
            a.execute(id, Op::Get(IPPROTO_IPV6, IPV6_TCLASS))
                .unwrap()
                .value,
            expected
        );
        for invalid in [-2, 256, i32::MIN, i32::MAX] {
            assert_eq!(
                a.execute(id, Op::Set(IPPROTO_IPV6, IPV6_TCLASS, invalid))
                    .unwrap_err(),
                EINVAL
            );
            assert_eq!(
                a.execute(id, Op::Get(IPPROTO_IPV6, IPV6_TCLASS))
                    .unwrap()
                    .value,
                expected
            );
        }
        assert_eq!(
            a.execute(id, Op::Connect("[2001:db8::2]:8080".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        a.service_egress().unwrap();
        let frame = state.lock().unwrap().sent.pop_front().unwrap();
        let ip = ntcp_ip6::parse(&frame[14..]).unwrap();
        assert_eq!(ip.traffic_class, (expected & !3) as u8);
        assert_ne!(
            ntcp::wire::parse(ip.ip, ip.payload).unwrap().header.flags & ntcp::wire::SYN,
            0
        );
    }
}

#[test]
fn ipv6_tclass_native_abi_signed_values_and_faults_are_atomic() {
    const CHILD: &str = "NTCP_IPV6_TCLASS_ABI_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "runtime::ipv6_tests::tclass_tests::ipv6_tclass_native_abi_signed_values_and_faults_are_atomic", "--test-threads=1"])
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
        for (writer, value, expected) in [(fd, 43i32, 43), (alias, -1, 0), (alias, 255, 255)] {
            assert_eq!(
                setsockopt(
                    writer,
                    IPPROTO_IPV6,
                    IPV6_TCLASS,
                    (&value as *const i32).cast(),
                    4
                ),
                0
            );
            for reader in [fd, alias] {
                let mut out = -1i32;
                let mut len = 4;
                assert_eq!(
                    getsockopt(
                        reader,
                        IPPROTO_IPV6,
                        IPV6_TCLASS,
                        (&mut out as *mut i32).cast(),
                        &mut len
                    ),
                    0
                );
                assert_eq!((out, len), (expected, 4));
            }
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
            getsockopt(alias, IPPROTO_IPV6, IPV6_TCLASS, ptr::null_mut(), &mut len),
            -1
        );
        assert_eq!(errno(), EFAULT);
        assert_eq!(
            getsockopt(
                alias,
                IPPROTO_IPV6,
                IPV6_TCLASS,
                (&mut out as *mut i32).cast(),
                ptr::null_mut()
            ),
            -1
        );
        assert_eq!(errno(), EFAULT);
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
        assert_eq!((out, len), (255, 4));
        assert_eq!(close(alias), 0);
        assert_eq!(close(fd), 0);
    }
}

#[test]
fn ipv6_tclass_child_keeps_creation_snapshot_and_independent_live_policy() {
    for ecn in [false, true] {
        let (mut a, sa) = owner_with_policy(1, ecn, 0);
        let (mut b, sb) = owner_with_policy(2, ecn, 0);
        let listener = new(&mut b);
        b.execute(listener, Op::Set(IPPROTO_IPV6, IPV6_TCLASS, 43))
            .unwrap();
        b.execute(listener, Op::Bind("[::]:8080".parse().unwrap()))
            .unwrap();
        b.execute(listener, Op::Listen(1)).unwrap();
        let client = new(&mut a);
        assert_eq!(
            a.execute(client, Op::Connect("[2001:db8::2]:8080".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        a.service_egress().unwrap();
        let syn = sa.lock().unwrap().sent.pop_front().unwrap();
        b.input_ip_metadata(&syn[14..], Default::default(), None);
        b.service_egress().unwrap();
        let syn_ack = sb.lock().unwrap().sent.pop_front().unwrap();
        let ip = ntcp_ip6::parse(&syn_ack[14..]).unwrap();
        let tcp = ntcp::wire::parse(ip.ip, ip.payload).unwrap();
        assert_eq!(
            tcp.header.flags & (ntcp::wire::SYN | ntcp::wire::ACK),
            ntcp::wire::SYN | ntcp::wire::ACK
        );
        assert_eq!(ip.traffic_class, 40); // SYN-ACK remains Not-ECT.
        // The child already exists. Change the listener before handshake completion
        // and accept, so neither event can replace the creation-time class.
        b.execute(listener, Op::Set(IPPROTO_IPV6, IPV6_TCLASS, 83))
            .unwrap();
        a.input_ip_metadata(&syn_ack[14..], Default::default(), None);
        exchange(&mut a, &mut b, &sa, &sb);
        let child = b
            .execute(listener, Op::Accept(SOCK_NONBLOCK))
            .unwrap()
            .value as u64;
        b.execute(child, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
            .unwrap();
        for (change, expected) in [(None, 43), (Some(171), 171)] {
            if let Some(value) = change {
                b.execute(child, Op::Set(IPPROTO_IPV6, IPV6_TCLASS, value))
                    .unwrap();
            }
            assert_eq!(
                b.execute(child, Op::Get(IPPROTO_IPV6, IPV6_TCLASS))
                    .unwrap()
                    .value,
                expected
            );
            assert_eq!(
                b.execute(listener, Op::Get(IPPROTO_IPV6, IPV6_TCLASS))
                    .unwrap()
                    .value,
                83
            );
            for _ in 0..2 {
                b.execute(child, Op::Write(vec![9; 100])).unwrap();
                b.service_egress().unwrap();
                let frame = sb.lock().unwrap().sent.pop_front().unwrap();
                let ip = ntcp_ip6::parse(&frame[14..]).unwrap();
                assert_eq!(ip.traffic_class >> 2, (expected >> 2) as u8);
                assert_eq!(ip.traffic_class & 3, if ecn { 2 } else { 0 });
                assert_eq!(
                    ntcp::wire::parse(ip.ip, ip.payload).unwrap().payload,
                    [9; 100]
                );
                a.input_ip_metadata(&frame[14..], Default::default(), None);
                exchange(&mut a, &mut b, &sa, &sb);
                assert_eq!(
                    a.execute(client, Op::Read(100)).unwrap().bytes,
                    vec![9; 100]
                );
            }
        }
    }
}

#[test]
fn ipv6_tclass_failed_transactions_keep_exact_sticky_and_wire_policy() {
    let (mut a, mut b, client, server, sa, sb) = pair_with_ecn(true);
    a.execute(client, Op::Set(IPPROTO_IPV6, IPV6_TCLASS, 43))
        .unwrap();
    let connection = cid(&a, client);
    let before = a.endpoint.transport_info(connection).unwrap();
    let options = a.connection_options.clone();
    // Retained completion capacity consumes the actual global transaction budget.
    let pressure = new(&mut a);
    a.sockets.get_mut(&pressure).unwrap().completions =
        VecDeque::with_capacity(timestamps::RUNTIME_BYTES / std::mem::size_of::<Completion>() + 1);
    a.recount_timestamp_charge(pressure);
    for value in [-1, 171, -2, 256] {
        assert_eq!(
            a.execute(client, Op::Set(IPPROTO_IPV6, IPV6_TCLASS, value))
                .unwrap_err(),
            if (-1..=255).contains(&value) {
                ENOBUFS
            } else {
                EINVAL
            }
        );
        assert_eq!(
            a.execute(client, Op::Get(IPPROTO_IPV6, IPV6_TCLASS))
                .unwrap()
                .value,
            43
        );
        assert_eq!(a.connection_options, options);
        assert_eq!(a.endpoint.transport_info(connection).unwrap(), before);
    }
    a.sockets.get_mut(&pressure).unwrap().completions = VecDeque::new();
    a.recount_timestamp_charge(pressure);
    a.execute(client, Op::Write(vec![7; 100])).unwrap();
    let mut bytes = [0; 2048];
    let (output, attempt) = a
        .endpoint
        .poll_reserved_transmit_for(a.now(), connection, &mut bytes, BUDGET)
        .unwrap();
    let tx = output.packet.unwrap();
    assert_eq!(tx.dscp, 43 >> 2);
    let mut packet = vec![0; 40 + tx.len];
    packet[40..].copy_from_slice(&bytes[..tx.len]);
    crate::ip::encode(&mut packet, tx, &[], 0, tx.len).unwrap();
    let attempt = attempt.unwrap();
    assert_eq!(
        a.execute(client, Op::Set(IPPROTO_IPV6, IPV6_TCLASS, 171))
            .unwrap_err(),
        EAGAIN
    );
    // Direct dispatch must also respect the endpoint's held-output barrier.
    assert_eq!(
        a.dispatch(client, Op::Set(IPPROTO_IPV6, IPV6_TCLASS, 171))
            .unwrap_err(),
        EAGAIN
    );
    assert_eq!(a.sockets[&client].ipv6_tclass, 43);
    assert_eq!(a.connection_options, options);
    assert!(a.endpoint.accept_transmit(a.now(), attempt).unwrap());
    assert_eq!(
        a.execute(client, Op::Get(IPPROTO_IPV6, IPV6_TCLASS))
            .unwrap()
            .value,
        43
    );
    // Failed transactions leave the previous exact value and actual egress intact.
    let ip = ntcp_ip6::parse(&packet).unwrap();
    assert_eq!(ip.traffic_class, 42); // DSCP 10 plus TCP-selected ECT(0).
    b.input_ip_metadata(&packet, Default::default(), None);
    exchange(&mut a, &mut b, &sa, &sb);
    assert_eq!(
        b.execute(server, Op::Read(100)).unwrap().bytes,
        vec![7; 100]
    );
    a.execute(client, Op::Set(IPPROTO_IPV6, IPV6_TCLASS, 171))
        .unwrap();
    assert_eq!(
        a.execute(client, Op::Get(IPPROTO_IPV6, IPV6_TCLASS))
            .unwrap()
            .value,
        171
    );
    // A stale core handle rejects the candidate without losing the saved byte.
    a.endpoint.abort(connection).unwrap();
    a.endpoint.release(connection).unwrap();
    a.service_egress().unwrap();
    // Its reset sent, the released connection is reclaimed.
    assert!(!a.endpoint.connection_exists(connection));
    assert_eq!(
        a.execute(client, Op::Set(IPPROTO_IPV6, IPV6_TCLASS, -1))
            .unwrap_err(),
        EBADF
    );
    assert_eq!(
        a.execute(client, Op::Get(IPPROTO_IPV6, IPV6_TCLASS))
            .unwrap()
            .value,
        171
    );
}
