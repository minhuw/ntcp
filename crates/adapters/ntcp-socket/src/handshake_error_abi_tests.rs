// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::packets::{capture, reply, segment, socket};
use super::*;

fn address() -> sockaddr_in {
    sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: 8080u16.to_be(),
        sin_addr: in_addr {
            s_addr: u32::from_ne_bytes([192, 0, 2, 2]),
        },
        sin_zero: [0; 8],
    }
}
unsafe fn start(fd: i32, mode: &str, addr: &sockaddr_in) -> isize {
    unsafe {
        if mode == "connect" || mode == "deferred-cold" {
            connect(fd, (addr as *const sockaddr_in).cast(), 16) as isize
        } else if mode == "deferred-warm" {
            write(fd, b"hello".as_ptr().cast(), 5)
        } else {
            sendto(
                fd,
                b"hello".as_ptr().cast(),
                5,
                MSG_FASTOPEN,
                (addr as *const sockaddr_in).cast(),
                16,
            )
        }
    }
}
unsafe fn so_error(fd: i32) -> i32 {
    unsafe {
        let mut error = -1i32;
        let mut len = 4;
        assert_eq!(
            getsockopt(
                fd,
                SOL_SOCKET,
                SO_ERROR,
                (&mut error as *mut i32).cast(),
                &mut len
            ),
            0
        );
        assert_eq!(len, 4);
        error
    }
}
unsafe fn info(fd: i32) -> [u8; 280] {
    unsafe {
        let mut bytes = [0; 280];
        let mut len = 280;
        assert_eq!(
            getsockopt(
                fd,
                IPPROTO_TCP,
                TCP_INFO,
                bytes.as_mut_ptr().cast(),
                &mut len
            ),
            0
        );
        assert_eq!(len, 280);
        bytes
    }
}
fn hard_unreachable(syn: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; 28 + syn.len()];
    frame[0] = 0x45;
    let n = frame.len() as u16;
    frame[2..4].copy_from_slice(&n.to_be_bytes());
    frame[8] = 64;
    frame[9] = 1;
    frame[12..16].copy_from_slice(&[192, 0, 2, 2]);
    frame[16..20].copy_from_slice(&[192, 0, 2, 1]);
    frame[20] = 3;
    frame[21] = 3; // Port unreachable is hard; host unreachable is soft.
    frame[28..].copy_from_slice(syn);
    let sum = ntcp_ip::checksum(&frame[20..]);
    frame[22..24].copy_from_slice(&sum.to_be_bytes());
    let sum = ntcp_ip::checksum(&frame[..20]);
    frame[10..12].copy_from_slice(&sum.to_be_bytes());
    assert_eq!(
        ntcp_icmp::decode_icmp(&frame).unwrap().ipv4_network_error(),
        Some(ntcp::NetworkError::HardUnreachable)
    );
    frame
}
fn reset_learning(ack: &[u8]) -> Vec<u8> {
    let p = ntcp_ip::parse(ack, false).unwrap();
    let s = segment(ack);
    let ip = ntcp::IpMetadata {
        source: p.ip.destination,
        destination: p.ip.source,
    };
    let mut frame = vec![0; 40];
    let len = ntcp::wire::encode(
        ip,
        ntcp::wire::Header {
            source_port: s.header.destination_port,
            destination_port: s.header.source_port,
            sequence: s.header.acknowledgment,
            acknowledgment: 0,
            flags: ntcp::wire::RST,
            window: 0,
            urgent_pointer: 0,
        },
        &[],
        &[],
        &mut frame[20..],
    )
    .unwrap();
    ntcp_ip::encode(
        &mut frame,
        ntcp::Transmit {
            tx_timestamp: None,
            connection: None,
            ip,
            len,
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
            ipv4_options: Default::default(),
        },
        0,
    )
    .unwrap();
    frame
}
fn refusal(syn: &[u8]) -> Vec<u8> {
    let mut peer = ntcp::Endpoint::new(Default::default(), [19; 32], 0, |_| true).unwrap();
    let p = ntcp_ip::parse(syn, false).unwrap();
    peer.input(0, p.ip, p.payload).unwrap();
    let mut bytes = [0; 2048];
    let tx = peer
        .poll_transmit(0, &mut bytes, 32)
        .unwrap()
        .packet
        .unwrap();
    let mut frame = vec![0; 20 + tx.len];
    frame[20..].copy_from_slice(&bytes[..tx.len]);
    ntcp_ip::encode(&mut frame, tx, 0).unwrap();
    assert_ne!(segment(&frame).header.flags & ntcp::wire::RST, 0);
    frame
}

#[test]
fn public_paired_handshake_errors_alias_poll_epoll_and_consumption() {
    if !child(
        "fast_open_abi_tests::handshake_errors::public_paired_handshake_errors_alias_poll_epoll_and_consumption",
        "NTCP_T5_ERROR_ABI_CHILD",
    ) {
        return;
    }
    packet_test::start((
        Ipv4Addr::new(192, 0, 2, 1),
        packet_profile::Profile::Pipeline,
    ))
    .unwrap();
    let addr = address();
    unsafe {
        for hard in [false, true] {
            for (blocking, consumed) in [(false, false), (false, true), (true, false)] {
                let mut baseline = None;
                for mode in [
                    "connect",
                    "msg-cold",
                    "msg-warm",
                    "deferred-cold",
                    "deferred-warm",
                ] {
                    packet_test::clear_fast_open_client_cache().unwrap();
                    let warm = mode.ends_with("warm");
                    eprintln!(
                        "T5_ERROR_ABI_STAGE {{\"open\":\"{mode}\",\"hard\":{hard},\"blocking\":{blocking},\"consumed\":{consumed},\"stage\":\"warm\"}}"
                    );
                    if warm {
                        let fd = socket();
                        assert_eq!(
                            sendto(
                                fd,
                                ptr::null(),
                                0,
                                MSG_FASTOPEN,
                                (&addr as *const sockaddr_in).cast(),
                                16
                            ),
                            -1
                        );
                        assert_eq!(errno(), EINPROGRESS);
                        let ack = reply(&segment(&capture()));
                        packet_test::inject(reset_learning(&ack)).unwrap();
                        let mut p = pollfd {
                            fd,
                            events: POLLIN,
                            revents: 0,
                        };
                        assert_eq!(poll(&mut p, 1, 2000), 1);
                        assert_eq!(so_error(fd), ECONNRESET);
                        assert_eq!(close(fd), 0);
                    }
                    let fd = socket();
                    let alias = dup(fd);
                    assert!(alias >= 0);
                    if mode.starts_with("deferred") {
                        assert_eq!(set(fd, TCP_FASTOPEN_CONNECT, 1), 0);
                        if warm {
                            assert_eq!(connect(alias, (&addr as *const sockaddr_in).cast(), 16), 0);
                        }
                    }
                    let ep = epoll_create1(EPOLL_CLOEXEC);
                    assert!(ep >= 0);
                    let mut registration = epoll_event {
                        events: (EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET) as u32,
                        u64: 71,
                    };
                    assert_eq!(epoll_ctl(ep, EPOLL_CTL_ADD, alias, &mut registration), 0);
                    // Drain deferred-connect's intentional initial writable edge.
                    let mut event: epoll_event = std::mem::zeroed();
                    epoll_wait(ep, &mut event, 1, 0);
                    let join = if blocking {
                        call(owned(fd).unwrap().unwrap(), Op::Flags(F_SETFL, 0)).unwrap();
                        Some(std::thread::spawn(move || {
                            let result = start(alias, mode, &address());
                            let error = errno();
                            eprintln!(
                                "T5_ERROR_ABI_RETURN {{\"open\":\"{mode}\",\"return\":{result},\"errno\":{error}}}"
                            );
                            (result, error)
                        }))
                    } else {
                        let result = start(alias, mode, &addr);
                        if warm {
                            assert_eq!(result, 5);
                        } else {
                            assert_eq!(result, -1);
                            assert_eq!(errno(), EINPROGRESS);
                        }
                        None
                    };
                    eprintln!("T5_ERROR_ABI_STAGE {{\"open\":\"{mode}\",\"stage\":\"syn\"}}");
                    let syn = capture();
                    assert_eq!(
                        segment(&syn).payload,
                        if warm { &b"hello"[..] } else { &[][..] }
                    );
                    let expected = if hard { EHOSTUNREACH } else { ECONNREFUSED };
                    packet_test::inject(if hard {
                        hard_unreachable(&syn)
                    } else {
                        refusal(&syn)
                    })
                    .unwrap();
                    if let Some(join) = join {
                        assert_eq!(join.join().unwrap(), (-1, expected));
                    }
                    // SO_ERROR remains consumable for nonblocking completion.
                    // For blocking calls it was already consumed by that call.
                    if !blocking {
                        let mut p = pollfd {
                            fd,
                            events: POLLIN | POLLOUT | POLLRDHUP,
                            revents: 0,
                        };
                        assert_eq!(poll(&mut p, 1, 2000), 1);
                        assert_eq!(
                            p.revents as i32 & (POLLIN | POLLOUT | POLLERR | POLLHUP) as i32,
                            (POLLIN | POLLOUT | POLLERR | POLLHUP) as i32
                        );
                        assert_eq!(epoll_wait(ep, &mut event, 1, 2000), 1);
                        let bits = event.events as i32;
                        assert_eq!(
                            bits & (EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDHUP),
                            EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDHUP
                        );
                        assert_eq!(epoll_wait(ep, &mut event, 1, 0), 0);
                        // LT poll still reports the terminal condition.
                        assert_eq!(poll(&mut p, 1, 0), 1);
                        if consumed {
                            assert_eq!(so_error(fd), expected);
                            assert_eq!(so_error(alias), 0);
                        }
                        assert_eq!(connect(alias, (&addr as *const sockaddr_in).cast(), 16), -1);
                        let completion = errno();
                        assert_eq!(completion, if consumed { ECONNABORTED } else { expected });
                        if let Some(b) = baseline {
                            assert_eq!((completion, bits), b);
                        } else {
                            baseline = Some((completion, bits));
                        }
                    }
                    let terminal = info(fd);
                    assert_eq!(terminal[0], 7);
                    assert_eq!(terminal[5] & 32, 0);
                    assert_eq!(so_error(alias), 0);
                    let mut p = pollfd {
                        fd: alias,
                        events: POLLIN | POLLOUT,
                        revents: 0,
                    };
                    assert_eq!(poll(&mut p, 1, 0), 0);
                    for size in [0u32, 1, 7, 24, 192, 193, 280, 300] {
                        let mut bytes = [0xa5; 300];
                        let mut n = size;
                        assert_eq!(
                            getsockopt(
                                alias,
                                IPPROTO_TCP,
                                TCP_INFO,
                                bytes.as_mut_ptr().cast(),
                                &mut n
                            ),
                            0
                        );
                        assert_eq!(n, size.min(280));
                        assert_eq!(&bytes[..n as usize], &terminal[..n as usize]);
                        assert!(bytes[n as usize..].iter().all(|b| *b == 0xa5));
                    }
                    assert_eq!(close(fd), 0);
                    assert_eq!(info(alias), terminal);
                    assert_eq!(close(alias), 0);
                    assert_eq!(close(ep), 0);
                    eprintln!(
                        "T5_ERROR_ABI {{\"open\":\"{mode}\",\"hard_icmp\":{hard},\"blocking\":{blocking},\"consumed\":{consumed},\"fatal_errno\":{expected},\"terminal_prefix\":true,\"alias\":true,\"poll\":true,\"epoll_et\":{}}}",
                        !blocking
                    );
                }
            }
        }
    }
}
