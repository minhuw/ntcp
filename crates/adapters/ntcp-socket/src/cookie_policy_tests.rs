// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

#[test]
fn config_cookie_policy_is_explicit_and_redacted() {
    let base = "io.interface=ntcp0\nio.address=192.168.0.1\n";
    let default = SocketConfig::parse(base).unwrap();
    assert!(matches!(
        default.fast_open_cookie_policy,
        FastOpenCookiePolicy::HmacSha256
    ));
    assert_eq!(default.socket, SocketPolicy::default());
    for suffix in [
        "socket.fast_open_cookie=linux-siphash24",
        "socket.fast_open_cookie=aes",
        "socket.fast_open_key=00112233445566778899aabbccddeeff",
        "socket.fast_open_cookie=hmac-sha256\nsocket.fast_open_key=00112233445566778899aabbccddeeff",
        "socket.fast_open_cookie=hmac-sha256\nsocket.fast_open_cookie=hmac-sha256",
        "socket.fast_open_cookie=linux-siphash24\nsocket.fast_open_key=short",
        "socket.fast_open_cookie=linux-siphash24\nsocket.fast_open_key=00112233445566778899aabbccddeefg",
        "socket.fast_open_cookie=linux-siphash24\nsocket.fast_open_key=00112233445566778899aabbccddeeff00",
        "socket.fast_open_cookie=linux-siphash24\nsocket.fast_open_key=00112233445566778899aabbccddeeff\nsocket.fast_open_key=00112233445566778899aabbccddeeff",
    ] {
        let error = SocketConfig::parse(&format!("{base}{suffix}")).unwrap_err();
        assert_eq!(error.to_string(), "invalid socket configuration");
    }
    let mut clock = ntcp_clock::TransportClock::new().unwrap();
    let now = clock.sample().unwrap().ticks;
    let lease = format!(
        "socket.fast_open_key_boot_id={}\nsocket.fast_open_key_not_before_us={now}\nsocket.fast_open_key_issue_until_us={until}\nsocket.fast_open_key_accept_until_us={until}",
        clock.characterization().boot_id,
        until = now + 3_600_000_000,
    );
    let text = format!(
        "{base}socket.fast_open_key=00112233445566778899AABBCCDDEEFF\nsocket.fast_open_cookie=linux-siphash24\n{lease}"
    );
    let result = SocketConfig::parse(&text);
    #[cfg(not(feature = "tfo-linux-cookie"))]
    assert!(result.is_err());
    #[cfg(feature = "tfo-linux-cookie")]
    {
        let config = result.unwrap();
        assert!(matches!(
            config.fast_open_cookie_policy,
            FastOpenCookiePolicy::LinuxSipHash24(_)
        ));
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("00112233"));
    }
}

#[test]
fn binary_key_public_abi_faults_lengths_aliases_and_unsupported_get() {
    const CHILD: &str = "NTCP_COOKIE_ABI_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "cookie_policy_tests::binary_key_public_abi_faults_lengths_aliases_and_unsupported_get", "--test-threads=1"])
            .env(CHILD, "1").status().unwrap().success());
        return;
    }
    assert!(RUNTIME.set(Ok(Runtime::in_memory_test())).is_ok());
    let id = call(0, Op::New(SOCK_NONBLOCK)).unwrap().value as u64;
    let (fd, token) = token(SOCK_CLOEXEC).unwrap();
    install(fd, token, id).unwrap();
    unsafe {
        let alias = dup(fd);
        assert!(alias >= 0);
        let key = [0xabu8; 32];
        let set = |fd, p, len| setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_KEY, p, len);
        #[cfg(all(feature = "linux", feature = "tfo-linux-cookie"))]
        {
            assert_eq!(set(fd, key.as_ptr().cast(), 16), 0);
            // A key configured nowhere; the configured one above still applies.
            let other = [0xcdu8; 16];
            assert_eq!(set(alias, other.as_ptr().cast(), 16), -1);
            assert_eq!(errno(), EINVAL);
            for len in [0, 4, 15, 17, 32, u32::MAX] {
                assert_eq!(set(alias, key.as_ptr().cast(), len), -1);
                assert_eq!(errno(), EINVAL);
            }
            for p in [ptr::null(), ptr::dangling::<c_void>()] {
                assert_eq!(set(alias, p, 16), -1);
                assert_eq!(errno(), EFAULT);
            }
            // The first word is readable, but the complete binary key is not.
            let page = sysconf(_SC_PAGESIZE) as usize;
            let map = mmap(
                ptr::null_mut(),
                page * 2,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            );
            assert_ne!(map, MAP_FAILED);
            assert_eq!(mprotect(map.add(page), page, PROT_NONE), 0);
            assert_eq!(set(alias, map.add(page - 8), 16), -1);
            assert_eq!(errno(), EFAULT);
            assert_eq!(munmap(map, page * 2), 0);
            assert_eq!(
                call(id, Op::Get(IPPROTO_TCP, TCP_FASTOPEN)).unwrap().value,
                0
            );
            call(id, Op::Listen(4)).unwrap();
            assert_eq!(set(alias, key.as_ptr().cast(), 16), 0);
        }
        #[cfg(not(all(feature = "linux", feature = "tfo-linux-cookie")))]
        {
            assert_eq!(set(fd, key.as_ptr().cast(), 16), -1);
            assert_eq!(errno(), ENOPROTOOPT);
            assert_eq!(set(fd, ptr::null(), 16), -1);
            assert_eq!(errno(), ENOPROTOOPT);
        }
        let mut bytes = [0xa5u8; 32];
        let mut len = 32;
        assert_eq!(
            getsockopt(
                alias,
                IPPROTO_TCP,
                TCP_FASTOPEN_KEY,
                bytes.as_mut_ptr().cast(),
                &mut len
            ),
            -1
        );
        assert_eq!(errno(), ENOPROTOOPT);
        assert_eq!(bytes, [0xa5; 32]);
        assert_eq!(len, 32);
        assert_eq!(close(fd), 0);
        assert_eq!(owned(alias).unwrap(), Some(id));
        #[cfg(all(feature = "linux", feature = "tfo-linux-cookie"))]
        assert_eq!(set(alias, key.as_ptr().cast(), 16), 0);
        assert_eq!(close(alias), 0);
        assert_eq!(call(id, Op::Ready).unwrap_err(), EBADF);
        assert_eq!(set(alias, key.as_ptr().cast(), 16), -1);
        assert_eq!(errno(), EBADF);
    }
}
