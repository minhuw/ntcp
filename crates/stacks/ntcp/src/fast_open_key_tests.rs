use super::*;

#[test]
fn hmac_cookie_key_is_independent_of_tcp_identity_and_deferred_policy_selection() {
    for v6 in [false, true] {
        let mut endpoint = Endpoint::new(EndpointConfig::default(), [42; 32], 0, |_| true).unwrap();
        let tuple = Tuple {
            local: if v6 {
                "[2001:db8::1]:8080"
            } else {
                "192.0.2.1:8080"
            }
            .parse()
            .unwrap(),
            remote: if v6 {
                "[2001:db8::2]:40000"
            } else {
                "192.0.2.2:40000"
            }
            .parse()
            .unwrap(),
        };
        let identity = endpoint.digest(b"ntcp initial sequence", tuple);
        let hash = endpoint.hash(tuple);
        let mut domain = *b"ntcp timestamp offset\0\0\0\0";
        let len = domain.len();
        domain[len - 4..].copy_from_slice(&123u32.to_be_bytes());
        let timestamp = endpoint.digest(&domain, tuple);
        let isn = endpoint.isn(tuple);
        let before = endpoint.buffer_bytes();
        crate::allocation_tests::fail_after(0, || endpoint.set_fast_open_hmac_key([9; 32]));
        assert_eq!(endpoint.buffer_bytes(), before);
        assert!(endpoint.fast_open.is_none());
        assert_eq!(endpoint.secret, [42; 32]);
        assert_eq!(endpoint.digest(b"ntcp initial sequence", tuple), identity);
        assert_eq!(endpoint.hash(tuple), hash);
        assert_eq!(endpoint.digest(&domain, tuple), timestamp);
        assert_eq!(endpoint.isn(tuple), isn.wrapping_add(1));
        #[cfg(feature = "tfo-linux-cookie")]
        {
            let policy =
                FastOpenCookiePolicy::LinuxSipHash24(crate::LinuxSipHash24Key::new([7; 16]));
            endpoint.set_fast_open_cookie_policy(policy.clone());
            let before = policy.issue(&[42; 32], tuple.local.ip(), tuple.remote.ip(), 0);
            endpoint.set_fast_open_hmac_key([10; 32]);
            assert_eq!(
                endpoint.fast_open_cookie_policy.issue(
                    &endpoint.fast_open_hmac_key,
                    tuple.local.ip(),
                    tuple.remote.ip(),
                    u64::MAX
                ),
                before
            );
            assert!(matches!(
                endpoint.fast_open_cookie_policy,
                FastOpenCookiePolicy::LinuxSipHash24(_)
            ));
        }
        endpoint.set_fast_open_cookie_policy(FastOpenCookiePolicy::HmacSha256);
        assert_eq!(
            endpoint.fast_open_hmac_key,
            if cfg!(feature = "tfo-linux-cookie") {
                [10; 32]
            } else {
                [9; 32]
            }
        );
    }
}
