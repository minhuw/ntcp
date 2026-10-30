use super::packets::{capture, segment, socket};
use super::*;

fn emit_core(e: &mut ntcp::Endpoint) -> Vec<u8> {
    let mut tcp = [0; 4096];
    let tx = e.poll_transmit(0, &mut tcp, 128).unwrap().packet.unwrap();
    let mut bytes = vec![0; 20 + tx.len];
    bytes[20..].copy_from_slice(&tcp[..tx.len]);
    ntcp_ip::encode(&mut bytes, tx, 0).unwrap();
    bytes
}
fn input_core(e: &mut ntcp::Endpoint, bytes: &[u8]) {
    let p = ntcp_ip::parse(bytes, false).unwrap();
    e.input(0, p.ip, p.payload).unwrap();
}
fn address(last: u8, port: u16) -> sockaddr_in {
    sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: in_addr {
            s_addr: u32::from_ne_bytes([192, 0, 2, last]),
        },
        sin_zero: [0; 8],
    }
}
unsafe fn send_open(fd: i32, peer: &sockaddr_in, data: &[u8]) -> isize {
    unsafe {
        sendto(
            fd,
            data.as_ptr().cast(),
            data.len(),
            MSG_FASTOPEN,
            (peer as *const sockaddr_in).cast(),
            16,
        )
    }
}

#[test]
fn public_authority_packet_io_early_read_peek_fionread_poll_epoll() {
    if !child(
        "fast_open_abi_tests::simultaneous::public_authority_packet_io_early_read_peek_fionread_poll_epoll",
        "NTCP_T4_PACKET_ABI_CHILD",
    ) {
        return;
    }
    packet_test::start((
        Ipv4Addr::new(192, 0, 2, 1),
        packet_profile::Profile::Pipeline,
    ))
    .unwrap();
    let cfg = ntcp::EndpointConfig {
        connection: ntcp::ConnectionConfig {
            nagle: false,
            delayed_ack_us: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    let options = ntcp::ActiveOpenOptions::from(&cfg.connection);
    let mut b = ntcp::Endpoint::new(cfg, [29; 32], 0, |_| true).unwrap();
    b.enable_fast_open().unwrap();
    let lb = b.listen("192.0.2.2:8080".parse().unwrap(), 4).unwrap();
    b.set_listener_fast_open(lb, 4).unwrap();
    unsafe {
        // Learn B's credential at the native endpoint through an actual request.
        let warm_a = socket();
        let target = address(2, 8080);
        assert_eq!(send_open(warm_a, &target, &[]), -1);
        assert_eq!(errno(), EINPROGRESS);
        input_core(&mut b, &capture());
        let reply_b = emit_core(&mut b);
        let cb = segment(&reply_b).options.fast_open.unwrap();
        packet_test::inject(reply_b).unwrap();
        input_core(&mut b, &capture());
        b.accept(lb).unwrap();

        let authority = socket();
        let local = address(1, 9000);
        assert_eq!(set(authority, TCP_FASTOPEN, 4), 0);
        assert_eq!(
            bind(authority, (&local as *const sockaddr_in).cast(), 16),
            0
        );
        assert_eq!(listen(authority, 4), 0);
        // Learn A's independently issued credential at B through another real
        // request, with A as listener. No self-issued cookie copies are used.
        b.connect_fast_open(
            0,
            "192.0.2.2:41001".parse().unwrap(),
            "192.0.2.1:9000".parse().unwrap(),
            &[],
        )
        .unwrap();
        packet_test::inject(emit_core(&mut b)).unwrap();
        let reply_a = capture();
        let ca = segment(&reply_a).options.fast_open.unwrap();
        assert_ne!(ca, cb);
        input_core(&mut b, &reply_a);
        packet_test::inject(emit_core(&mut b)).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let warm_b = loop {
            let fd = accept4(
                authority,
                ptr::null_mut(),
                ptr::null_mut(),
                SOCK_NONBLOCK | SOCK_CLOEXEC,
            );
            if fd >= 0 {
                break fd;
            }
            assert_eq!(errno(), EAGAIN);
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        };

        for (i, mode) in ["msg", "deferred", "reset", "fin-only", "fin-data"].into_iter().enumerate() {
            let deferred = mode == "deferred";
            let active = socket();
            let alias = dup(active);
            let local = address(1, 42000 + i as u16 * 2);
            let peer = address(2, 42001 + i as u16 * 2);
            assert_eq!(bind(active, (&local as *const sockaddr_in).cast(), 16), 0);
            set_fast_open_receive_authority(alias, Some(authority)).unwrap();
            if deferred {
                assert_eq!(set(active, TCP_FASTOPEN_CONNECT, 1), 0);
                assert_eq!(connect(active, (&peer as *const sockaddr_in).cast(), 16), 0);
                assert_eq!(
                    set_fast_open_receive_authority(alias, None)
                        .unwrap_err()
                        .raw_os_error(),
                    Some(EINVAL)
                );
                assert_eq!(write(active, b"from-A".as_ptr().cast(), 6), 6);
            } else {
                assert_eq!(send_open(active, &peer, b"from-A"), 6);
            }
            let aa = format!("192.0.2.1:{}", 42000 + i * 2).parse().unwrap();
            let ba = format!("192.0.2.2:{}", 42001 + i * 2).parse().unwrap();
            let (id_b, n) = b
                .connect_fast_open_with_receive_authority(
                    0,
                    ba,
                    aa,
                    if mode == "fin-only" { b"" } else { b"from-B" },
                    options,
                    None,
                    ntcp::FastOpenClientPolicy::RequireCookie,
                    Some(lb),
                )
                .unwrap();
            assert_eq!(n, if mode == "fin-only" { 0 } else { 6 });
            let sa = capture();
            let mut sb = emit_core(&mut b);
            if mode.starts_with("fin-") {
                let s = segment(&sb);
                let header = ntcp::wire::Header {
                    flags: s.header.flags | ntcp::wire::FIN,
                    ..s.header
                };
                let options = s.raw_options.to_vec();
                let payload = s.payload.to_vec();
                let ip = ntcp_ip::parse(&sb, false).unwrap().ip;
                ntcp::wire::encode(ip, header, &options, &payload, &mut sb[20..]).unwrap();
            }
            assert_eq!(segment(&sa).options.fast_open, Some(cb));
            assert_eq!(segment(&sb).options.fast_open, Some(ca));
            input_core(&mut b, &sa);
            packet_test::inject(sb).unwrap();
            let ra = capture();
            let rb = emit_core(&mut b);
            assert_eq!(segment(&ra).options.fast_open, Some(ca));
            assert_eq!(segment(&rb).options.fast_open, Some(cb));
            assert!(segment(&ra).payload.is_empty() && segment(&rb).payload.is_empty());
            assert_eq!(b.state(id_b), Ok(ntcp::State::SynReceived));
            if mode.starts_with("fin-") {
                let expected = if mode == "fin-only" { 0 } else { 6 };
                let mut count = -1i32;
                assert_eq!(libc::ioctl(alias, FIONREAD as _, &mut count), 0);
                assert_eq!(count, expected);
                let ep = epoll_create1(EPOLL_CLOEXEC);
                let mut event = epoll_event {
                    events: (EPOLLIN | EPOLLOUT | EPOLLRDHUP) as u32,
                    u64: 7,
                };
                assert_eq!(epoll_ctl(ep, EPOLL_CTL_ADD, alias, &mut event), 0);
                for drained in [false, true] {
                    let mut p = pollfd { fd: alias, events: POLLIN | POLLOUT, revents: 0 };
                    assert_eq!(poll(&mut p, 1, 0), 1);
                    assert_eq!(p.revents & (POLLIN | POLLOUT), POLLIN);
                    assert_eq!(epoll_wait(ep, &mut event, 1, 0), 1);
                    assert_eq!(event.events & (EPOLLIN | EPOLLOUT | EPOLLRDHUP) as u32,
                        (EPOLLIN | EPOLLRDHUP) as u32);
                    let mut bytes = [0; 16];
                    let n = if drained { 0 } else { expected as isize };
                    assert_eq!(recv(alias, bytes.as_mut_ptr().cast(), 16, MSG_PEEK), n);
                    assert_eq!(read(active, bytes.as_mut_ptr().cast(), 16), n);
                    if n != 0 { assert_eq!(&bytes[..n as usize], b"from-B"); }
                    assert_eq!(connect(active, (&peer as *const sockaddr_in).cast(), 16), -1);
                    assert_eq!(errno(), EALREADY);
                }
                assert_eq!(libc::ioctl(alias, FIONREAD as _, &mut count), 0);
                assert_eq!(count, 0);
                println!("T4_ABI_EOF {{\"payload\":{expected},\"pending_connect\":true,\"poll_and_epoll_after_drain\":true}}");
                close(ep);
                continue;
            }
            let mut count = 0i32;
            assert_eq!(libc::ioctl(alias, FIONREAD as _, &mut count), 0);
            assert_eq!(count, 6);
            let mut p = pollfd {
                fd: alias,
                events: POLLIN | POLLOUT,
                revents: 0,
            };
            assert_eq!(poll(&mut p, 1, 0), 1);
            assert_eq!(p.revents & (POLLIN | POLLOUT), POLLIN);
            let ep = epoll_create1(EPOLL_CLOEXEC);
            let mut event = epoll_event {
                events: (EPOLLIN | EPOLLOUT | EPOLLET) as u32,
                u64: 7,
            };
            assert_eq!(epoll_ctl(ep, EPOLL_CTL_ADD, alias, &mut event), 0);
            assert_eq!(epoll_wait(ep, &mut event, 1, 0), 1);
            assert_eq!(event.events & (EPOLLIN | EPOLLOUT) as u32, EPOLLIN as u32);
            let mut bytes = [0u8; 16];
            if mode == "reset" {
                b.abort(id_b).unwrap();
                let reset = emit_core(&mut b);
                assert_ne!(segment(&reset).header.flags & ntcp::wire::RST, 0);
                packet_test::inject(reset).unwrap();
                // This invokes FinishConnect before the application consumes
                // any of its authorized early bytes.
                assert_eq!(connect(active, (&peer as *const sockaddr_in).cast(), 16), -1);
                assert_eq!(errno(), ECONNREFUSED);
                assert_eq!(libc::ioctl(alias, FIONREAD as _, &mut count), 0);
                assert_eq!(count, 6);
                assert_eq!(recv(alias, bytes.as_mut_ptr().cast(), 16, MSG_PEEK), 6);
                assert_eq!(&bytes[..6], b"from-B");
                assert_eq!(read(active, bytes.as_mut_ptr().cast(), 2), 2);
                assert_eq!(&bytes[..2], b"fr");
                assert_eq!(read(alias, bytes.as_mut_ptr().cast(), 16), 4);
                assert_eq!(&bytes[..4], b"om-B");
                assert_eq!(libc::ioctl(alias, FIONREAD as _, &mut count), 0);
                assert_eq!(count, 0);
                assert_eq!(read(alias, bytes.as_mut_ptr().cast(), 16), -1);
                assert_eq!(errno(), ENOTCONN);
                let mut info = [0u8; 280];
                let mut len = info.len() as u32;
                assert_eq!(getsockopt(alias, IPPROTO_TCP, TCP_INFO, info.as_mut_ptr().cast(), &mut len), 0);
                assert_eq!(info[0], 7); // TCP_CLOSE, retained after final drain.
                let mut error = -1i32;
                len = 4;
                assert_eq!(getsockopt(alias, SOL_SOCKET, SO_ERROR, (&mut error as *mut i32).cast(), &mut len), 0);
                assert_eq!(error, 0); // Connect consumed the refusal exactly once.
                println!("T4_ABI_RESET {{\"finish_connect_errno\":{ECONNREFUSED},\"fionread_after_finish\":6,\"drained\":6,\"tcp_state\":7,\"so_error\":0}}");
                close(ep);
                continue;
            }
            assert_eq!(recv(alias, bytes.as_mut_ptr().cast(), 6, MSG_PEEK), 6);
            assert_eq!(&bytes[..6], b"from-B");
            assert_eq!(read(active, bytes.as_mut_ptr().cast(), 2), 2);
            assert_eq!(&bytes[..2], b"fr");
            let mut early_b = [0; 3];
            assert_eq!(b.read(id_b, &mut early_b), Ok(3));
            assert_eq!(&early_b, b"fro");
            assert_eq!(
                connect(active, (&peer as *const sockaddr_in).cast(), 16),
                -1
            );
            assert_eq!(errno(), EALREADY);
            input_core(&mut b, &ra);
            packet_test::inject(rb).unwrap();
            input_core(&mut b, &capture());
            packet_test::inject(emit_core(&mut b)).unwrap();
            assert_eq!(read(alias, bytes.as_mut_ptr().cast(), 16), 4);
            assert_eq!(&bytes[..4], b"om-B");
            assert_eq!(b.read(id_b, &mut bytes), Ok(3));
            assert_eq!(&bytes[..3], b"m-A");
            assert_eq!(b.state(id_b), Ok(ntcp::State::Established));
            // The same native fd finishes its pending connect and acquires
            // ordinary writable readiness only after actual handshake progress.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                if connect(active, (&peer as *const sockaddr_in).cast(), 16) == 0 {
                    break;
                }
                assert_eq!(errno(), EALREADY);
                assert!(std::time::Instant::now() < deadline);
                std::thread::yield_now();
            }
            assert_eq!(libc::ioctl(alias, FIONREAD as _, &mut count), 0);
            assert_eq!(count, 0);
            println!(
                "T4_ABI {{\"deferred\":{deferred},\"early_read\":2,\"peek\":6,\"fionread\":6,\"poll_in_only\":true,\"epoll_in_only\":true,\"complete_each\":6}}"
            );
            // Keep streams live until process exit so cleanup FINs cannot be
            // mistaken for the next exchange's SYN.
            close(ep);
        }
        let _ = (warm_a, warm_b);
    }
}
