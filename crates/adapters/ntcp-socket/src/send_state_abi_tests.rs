// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

#[test]
fn unconnected_stream_send_errno_payload_and_sigpipe_match_native() {
    const NAME: &str =
        "send_state_abi_tests::unconnected_stream_send_errno_payload_and_sigpipe_match_native";
    const CHILD: &str = "NTCP_UNCONNECTED_SEND_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--test-threads=1"])
                .env(CHILD, "1")
                .status()
                .unwrap()
                .success()
        );
        return;
    }
    // Isolate disposition/runtime globals in a subprocess. Block SIGPIPE on
    // this caller so each send's signal can be consumed and checked directly.
    unsafe {
        assert_ne!(libc::signal(SIGPIPE, SIG_DFL), SIG_ERR);
        let mut mask: sigset_t = std::mem::zeroed();
        sigemptyset(&mut mask);
        sigaddset(&mut mask, SIGPIPE);
        assert_eq!(pthread_sigmask(SIG_BLOCK, &mask, ptr::null_mut()), 0);
        assert!(RUNTIME.set(Ok(Runtime::in_memory_test())).is_ok());
        for managed in [false, true] {
            for state in 0..3 {
                let (fd, id) = if managed {
                    let id = call(0, Op::New(SOCK_NONBLOCK)).unwrap().value as u64;
                    let (fd, token) = token(SOCK_CLOEXEC).unwrap();
                    install(fd, token, id).unwrap();
                    (fd, id)
                } else {
                    let fd = syscall(SYS_socket, AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0) as i32;
                    assert!(fd >= 0);
                    (fd, 0)
                };
                if state != 0 {
                    if managed {
                        call(id, Op::Bind("10.73.0.2:0".parse().unwrap())).unwrap();
                    } else {
                        let address = sockaddr_in {
                            sin_family: AF_INET as _,
                            sin_port: 0,
                            sin_addr: in_addr {
                                s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
                            },
                            sin_zero: [0; 8],
                        };
                        assert_eq!(
                            syscall(SYS_bind, fd, &address, std::mem::size_of_val(&address)),
                            0
                        );
                    }
                }
                if state == 2 {
                    assert_eq!(listen(fd, 1), 0);
                }
                for zerocopy in [false, true] {
                    let enabled = i32::from(zerocopy);
                    assert_eq!(
                        setsockopt(
                            fd,
                            SOL_SOCKET,
                            SO_ZEROCOPY,
                            (&enabled as *const i32).cast(),
                            4
                        ),
                        0
                    );
                    for no_signal in [false, true] {
                        let flags = if zerocopy { MSG_ZEROCOPY } else { 0 }
                            | if no_signal { MSG_NOSIGNAL } else { 0 };
                        for (payload, len) in [
                            (ptr::null(), 0),
                            (b"x".as_ptr().cast(), 1),
                            (ptr::null(), 1),
                            (ptr::dangling::<c_void>(), 1),
                        ] {
                            for operation in 0..3 {
                                if operation == 2 && no_signal {
                                    continue; // write has no MSG_NOSIGNAL argument.
                                }
                                let result = if operation == 1 {
                                    let mut iov = iovec {
                                        iov_base: payload.cast_mut(),
                                        iov_len: len,
                                    };
                                    let mut message: msghdr = std::mem::zeroed();
                                    message.msg_iov = &mut iov;
                                    message.msg_iovlen = 1;
                                    sendmsg(fd, &message, flags)
                                } else if operation == 2 {
                                    write(fd, payload, len)
                                } else {
                                    send(fd, payload, len, flags)
                                };
                                assert_eq!(result, -1, "managed={managed} state={state}");
                                assert_eq!(
                                    errno(),
                                    EPIPE,
                                    "managed={managed} state={state} operation={operation}"
                                );
                                let timeout = timespec {
                                    tv_sec: 0,
                                    tv_nsec: 0,
                                };
                                let signal = sigtimedwait(&mask, ptr::null_mut(), &timeout);
                                assert_eq!(signal, if no_signal { -1 } else { SIGPIPE });
                                if no_signal {
                                    assert_eq!(errno(), EAGAIN);
                                }
                            }
                        }
                    }
                    let mut message: msghdr = std::mem::zeroed();
                    assert_eq!(recvmsg(fd, &mut message, MSG_ERRQUEUE | MSG_DONTWAIT), -1);
                    assert_eq!(errno(), EAGAIN);
                }
                assert_eq!(close(fd), 0);
            }
        }
        assert_eq!(send(-1, ptr::null(), 0, MSG_NOSIGNAL), -1);
        assert_eq!(errno(), EBADF);
    }
}
