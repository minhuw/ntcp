// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

#[test]
fn disabled_linux_options_preserve_native_and_posix_abi() {
    const CHILD: &str = "NTCP_DISABLED_LINUX_ABI_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "linux_option_abi_tests::disabled_linux_options_preserve_native_and_posix_abi",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap()
                .success()
        );
        return;
    }
    assert!(RUNTIME.set(Ok(Runtime::in_memory_test())).is_ok());
    let id = call(0, Op::New(SOCK_NONBLOCK)).unwrap().value as u64;
    let (fd, token) = token(SOCK_CLOEXEC).unwrap();
    install(fd, token, id).unwrap();
    unsafe {
        for (level, names) in [
            (
                IPPROTO_TCP,
                &[
                    TCP_CORK,
                    TCP_INFO,
                    TCP_CC_INFO,
                    TCP_USER_TIMEOUT,
                    TCP_NOTSENT_LOWAT,
                    TCP_INQ,
                    TCP_KEEPIDLE,
                    TCP_KEEPINTVL,
                    TCP_KEEPCNT,
                    TCP_FASTOPEN,
                    TCP_FASTOPEN_CONNECT,
                    TCP_FASTOPEN_KEY,
                    TCP_SYNCNT,
                ][..],
            ),
            (
                SOL_SOCKET,
                &[SO_ZEROCOPY, SO_DOMAIN, SO_PROTOCOL, 37, 65][..],
            ),
            (IPPROTO_IP, &[IP_FREEBIND, IP_MTU_DISCOVER, IP_MTU][..]),
        ] {
            for &name in names {
                let mut bytes = [0xa5u8; 32];
                for p in [
                    bytes.as_mut_ptr().cast(),
                    ptr::null_mut(),
                    ptr::dangling_mut::<c_void>(),
                ] {
                    for requested in [0, 1, 4, 8, 16, 32, u32::MAX] {
                        assert_eq!(setsockopt(fd, level, name, p, requested), -1);
                        assert_eq!(errno(), ENOPROTOOPT, "set ({level}, {name})");
                        let mut len = requested;
                        assert_eq!(getsockopt(fd, level, name, p, &mut len), -1);
                        assert_eq!(errno(), ENOPROTOOPT, "get ({level}, {name})");
                        assert_eq!(len, requested);
                    }
                    for len in [ptr::null_mut(), ptr::dangling_mut::<socklen_t>()] {
                        assert_eq!(getsockopt(fd, level, name, p, len), -1);
                        assert_eq!(errno(), ENOPROTOOPT);
                    }
                }
                assert_eq!(bytes, [0xa5; 32]);
            }
        }

        // Internal typed operations do not depend on the exported ABI feature.
        call(id, Op::Set(IPPROTO_TCP, TCP_CORK, 1)).unwrap();
        assert_eq!(call(id, Op::Get(IPPROTO_TCP, TCP_CORK)).unwrap().value, 1);

        // These option numbers overlap Linux options at other levels.
        for (level, name, value) in [
            (IPPROTO_TCP, TCP_NODELAY, 1i32),
            (SOL_SOCKET, SO_REUSEADDR, 1),
            (SOL_SOCKET, SO_KEEPALIVE, 1),
            (IPPROTO_IP, IP_TOS, 40),
        ] {
            assert_eq!(
                setsockopt(fd, level, name, (&value as *const i32).cast(), 4),
                0
            );
            let mut out = -1i32;
            let mut len = 4;
            assert_eq!(
                getsockopt(fd, level, name, (&mut out as *mut i32).cast(), &mut len),
                0
            );
            assert_eq!((out, len), (value, 4));
        }
        for name in [SO_TYPE, SO_ERROR, SO_ACCEPTCONN, SO_SNDBUF, SO_RCVBUF] {
            let mut out = -1i32;
            let mut len = 4;
            assert_eq!(
                getsockopt(
                    fd,
                    SOL_SOCKET,
                    name,
                    (&mut out as *mut i32).cast(),
                    &mut len
                ),
                0
            );
            assert_eq!(len, 4);
        }
        for (old, new) in [(SO_RCVTIMEO, 66), (SO_SNDTIMEO, 67)] {
            for name in [old, new] {
                let value = [2i64, 345];
                assert_eq!(
                    setsockopt(fd, SOL_SOCKET, name, value.as_ptr().cast(), 16),
                    0
                );
                for alias in [old, new] {
                    let mut out = [0i64; 2];
                    let mut len = 16;
                    assert_eq!(
                        getsockopt(fd, SOL_SOCKET, alias, out.as_mut_ptr().cast(), &mut len),
                        0
                    );
                    assert_eq!((out, len), (value, 16));
                }
            }
        }
        assert_eq!(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, ptr::null(), 4), -1);
        assert_eq!(errno(), EFAULT);
        assert_eq!(
            getsockopt(fd, SOL_SOCKET, SO_TYPE, ptr::null_mut(), ptr::null_mut()),
            -1
        );
        assert_eq!(errno(), EFAULT);
        assert_eq!(close(fd), 0);

        // Raw creation avoids managed registration; the exported wrappers must
        // still forward Linux extensions (including kernel validation errors).
        let native = syscall(SYS_socket, AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP) as i32;
        assert!(native >= 0);
        assert_eq!(owned(native).unwrap(), None);
        let one = 1i32;
        assert_eq!(
            setsockopt(
                native,
                IPPROTO_TCP,
                TCP_CORK,
                (&one as *const i32).cast(),
                4
            ),
            0
        );
        for (level, name, expected) in
            [(IPPROTO_TCP, TCP_CORK, 1), (SOL_SOCKET, SO_DOMAIN, AF_INET)]
        {
            let mut out = -1i32;
            let mut len = 4;
            assert_eq!(
                getsockopt(native, level, name, (&mut out as *mut i32).cast(), &mut len),
                0
            );
            assert_eq!(out, expected);
        }
        assert_eq!(
            setsockopt(native, IPPROTO_TCP, TCP_CORK, ptr::null(), 4),
            -1
        );
        assert_eq!(errno(), EFAULT);
        assert_eq!(
            getsockopt(
                native,
                SOL_SOCKET,
                SO_DOMAIN,
                ptr::null_mut(),
                ptr::null_mut()
            ),
            -1
        );
        assert_eq!(errno(), EFAULT);
        assert_eq!(close(native), 0);
    }
}
