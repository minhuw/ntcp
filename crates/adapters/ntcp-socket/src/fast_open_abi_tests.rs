// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

fn child(test: &str, variable: &str) -> bool {
    if std::env::var_os(variable).is_some() {
        return true;
    }
    assert!(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--test-threads=1"])
            .env(variable, "1")
            .status()
            .unwrap()
            .success()
    );
    false
}
fn set(fd: i32, option: i32, value: i32) -> i32 {
    unsafe { setsockopt(fd, IPPROTO_TCP, option, (&value as *const i32).cast(), 4) }
}

#[test]
fn fast_open_raw_options_and_aliases() {
    if !child(
        "fast_open_abi_tests::fast_open_raw_options_and_aliases",
        "NTCP_TFO_OPTIONS_CHILD",
    ) {
        return;
    }
    assert!(RUNTIME.set(Ok(Runtime::in_memory_test())).is_ok());
    let id = call(0, Op::New(SOCK_NONBLOCK)).unwrap().value as u64;
    let (fd, token) = token(SOCK_CLOEXEC).unwrap();
    install(fd, token, id).unwrap();
    unsafe {
        let alias = dup(fd);
        assert!(alias >= 0);
        for option in [TCP_FASTOPEN, TCP_FASTOPEN_CONNECT] {
            for value in [0i32, 1, 0, 1] {
                assert_eq!(set(fd, option, value), 0);
                for size in 0..=6u32 {
                    let mut len = size;
                    let mut bytes = [0xa5u8; 6];
                    assert_eq!(
                        getsockopt(
                            alias,
                            IPPROTO_TCP,
                            option,
                            bytes.as_mut_ptr().cast(),
                            &mut len
                        ),
                        0
                    );
                    assert_eq!(len, size.min(4));
                    assert_eq!(&bytes[..len as usize], &value.to_ne_bytes()[..len as usize]);
                    assert!(bytes[len as usize..].iter().all(|b| *b == 0xa5));
                }
                for len in [0, 1, 3, u32::MAX] {
                    assert_eq!(
                        setsockopt(fd, IPPROTO_TCP, option, (&value as *const i32).cast(), len),
                        -1
                    );
                    assert_eq!(errno(), EINVAL);
                }
                assert_eq!(setsockopt(fd, IPPROTO_TCP, option, ptr::null(), 4), -1);
                assert_eq!(errno(), EFAULT);
                let mut len = u32::MAX;
                assert_eq!(
                    getsockopt(fd, IPPROTO_TCP, option, ptr::null_mut(), &mut len),
                    -1
                );
                assert_eq!(errno(), EINVAL);
                len = 0;
                assert_eq!(
                    getsockopt(fd, IPPROTO_TCP, option, ptr::null_mut(), &mut len),
                    0
                );
                assert_eq!(set(fd, option, -1), -1);
                assert_eq!(errno(), EINVAL);
                assert_eq!(call(id, Op::Get(IPPROTO_TCP, option)).unwrap().value, value);
            }
        }
        assert_eq!(close(fd), 0);
        assert_eq!(owned(alias).unwrap(), Some(id));
        assert_eq!(
            call(id, Op::Get(IPPROTO_TCP, TCP_FASTOPEN_CONNECT))
                .unwrap()
                .value,
            1
        );
        assert_eq!(close(alias), 0);
        assert_eq!(
            call(id, Op::Get(IPPROTO_TCP, TCP_FASTOPEN_CONNECT)).unwrap_err(),
            EBADF
        );
    }
}

#[cfg(feature = "packet-test")]
mod packets {
    use super::*;
    use ntcp::wire::{ACK, SYN};
    fn capture() -> Vec<u8> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match packet_test::try_capture(65535) {
                Ok((packet, _)) => return packet,
                Err(EAGAIN) if std::time::Instant::now() < deadline => std::thread::yield_now(),
                other => panic!("capture: {other:?}"),
            }
        }
    }
    fn segment(bytes: &[u8]) -> ntcp::wire::Segment<'_> {
        let p = ntcp_ip::parse(bytes, false).unwrap();
        ntcp::wire::parse(p.ip, p.payload).unwrap()
    }
    fn reply(syn: &ntcp::wire::Segment<'_>) {
        let ip = ntcp::IpMetadata {
            source: Ipv4Addr::new(192, 0, 2, 2).into(),
            destination: Ipv4Addr::new(192, 0, 2, 1).into(),
        };
        let header = ntcp::wire::Header {
            source_port: 8080,
            destination_port: syn.header.source_port,
            sequence: 100,
            acknowledgment: syn
                .header
                .sequence
                .wrapping_add(1 + syn.payload.len() as u32),
            flags: SYN | ACK,
            window: 65535,
            urgent_pointer: 0,
        };
        let mut bytes = vec![0; 80];
        let len = ntcp::wire::encode(
            ip,
            header,
            &[2, 4, 5, 180, 34, 6, 1, 2, 3, 4, 0, 0],
            &[],
            &mut bytes[20..],
        )
        .unwrap();
        ntcp_ip::encode(
            &mut bytes,
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
        bytes.truncate(20 + len);
        packet_test::inject(bytes).unwrap();
        assert_eq!(segment(&capture()).header.flags & SYN, 0);
    }
    fn socket() -> i32 {
        let fd = unsafe {
            packet_test::packet_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP)
        };
        assert!(fd >= 0);
        fd
    }
    #[test]
    fn fast_open_sendto_sendmsg_deferred_alias_and_fault_abi() {
        if !child(
            "fast_open_abi_tests::packets::fast_open_sendto_sendmsg_deferred_alias_and_fault_abi",
            "NTCP_TFO_PACKET_CHILD",
        ) {
            return;
        }
        packet_test::start_with_options(
            (
                Ipv4Addr::new(192, 0, 2, 1),
                packet_profile::Profile::Pipeline,
            ),
            packet_test::Options {
                queue_capacity: 8,
                egress_capacity: 2,
            },
        )
        .unwrap();
        let addr = sockaddr_in {
            sin_family: AF_INET as u16,
            sin_port: 8080u16.to_be(),
            sin_addr: in_addr {
                s_addr: u32::from_ne_bytes([192, 0, 2, 2]),
            },
            sin_zero: [0; 8],
        };
        let destination = (&addr as *const sockaddr_in).cast();
        unsafe {
            let warm = socket();
            assert_eq!(
                sendto(warm, ptr::null(), 1, MSG_FASTOPEN, destination, 16),
                -1
            );
            assert_eq!(errno(), EFAULT);
            assert_eq!(packet_test::try_capture(65535).unwrap_err(), EAGAIN);
            let unspec = sockaddr_in {
                sin_family: AF_UNSPEC as u16,
                ..addr
            };
            assert_eq!(
                sendto(
                    warm,
                    c"hi".as_ptr().cast(),
                    2,
                    MSG_FASTOPEN,
                    (&unspec as *const sockaddr_in).cast(),
                    16
                ),
                -1
            );
            assert_eq!(errno(), EOPNOTSUPP);
            assert_eq!(send(warm, c"hi".as_ptr().cast(), 2, MSG_FASTOPEN), -1);
            assert_eq!(errno(), EINVAL);
            assert_eq!(
                sendto(
                    warm,
                    c"hi".as_ptr().cast(),
                    2,
                    MSG_FASTOPEN,
                    destination,
                    16
                ),
                -1
            );
            assert_eq!(errno(), EINPROGRESS);
            let syn = capture();
            assert_eq!(segment(&syn).header.destination_port, 8080);
            assert!(
                segment(&syn)
                    .options
                    .fast_open
                    .unwrap()
                    .as_bytes()
                    .is_empty()
            );
            assert!(segment(&syn).payload.is_empty());
            reply(&segment(&syn));
            assert_eq!(close(warm), 0);
            let fin = capture();
            assert_ne!(segment(&fin).header.flags & ntcp::wire::FIN, 0);

            // Cookie survives last close; sendmsg preserves both destination and iovec cursor.
            let fd = socket();
            call(owned(fd).unwrap().unwrap(), Op::Flags(F_SETFL, 0)).unwrap();
            let mut iov = [
                iovec {
                    iov_base: c"ab".as_ptr().cast_mut().cast(),
                    iov_len: 2,
                },
                iovec {
                    iov_base: c"cde".as_ptr().cast_mut().cast(),
                    iov_len: 3,
                },
            ];
            let mut msg: msghdr = std::mem::zeroed();
            msg.msg_name = destination.cast_mut().cast();
            msg.msg_namelen = 16;
            msg.msg_iov = iov.as_mut_ptr();
            msg.msg_iovlen = 2;
            assert_eq!(
                sendmsg(fd, &msg, MSG_FASTOPEN | MSG_DONTWAIT),
                5,
                "errno {}",
                errno()
            );
            let syn = capture();
            assert_eq!(segment(&syn).payload, b"abcde");
            assert_eq!(
                segment(&syn).options.fast_open.unwrap().as_bytes(),
                &[1, 2, 3, 4]
            );
            reply(&segment(&syn));
            assert_eq!(close(fd), 0);
            let _fin = capture();

            let fd = socket();
            assert_eq!(set(fd, TCP_FASTOPEN, 1), 0);
            assert_eq!(set(fd, TCP_FASTOPEN_CONNECT, 1), 0);
            assert_eq!(connect(fd, destination, 16), 0);
            let id = owned(fd).unwrap().unwrap();
            let alias = dup(fd);
            assert!(alias >= 0);
            assert_eq!(close(fd), 0);
            assert_eq!(packet_test::try_capture(65535).unwrap_err(), EAGAIN);
            assert_eq!(write(alias, ptr::null(), 1), -1);
            assert_eq!(errno(), EFAULT);
            assert_eq!(packet_test::try_capture(65535).unwrap_err(), EAGAIN);
            assert_eq!(send(alias, c"xyz".as_ptr().cast(), 3, MSG_FASTOPEN), 3);
            assert_eq!(segment(&capture()).payload, b"xyz");
            assert_eq!(close(alias), 0);
            assert_eq!(call(id, Op::Ready).unwrap_err(), EBADF);
            // A never-written deferred socket leaves no connection on last close.
            let idle = socket();
            assert_eq!(set(idle, TCP_FASTOPEN_CONNECT, 1), 0);
            assert_eq!(connect(idle, destination, 16), 0);
            assert_eq!(close(idle), 0);
        }
        packet_test::stop();
    }
}
