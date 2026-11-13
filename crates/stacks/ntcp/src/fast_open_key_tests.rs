use super::*;
use crate::CallerTimebase;
use alloc::vec;

#[test]
fn administrative_sequences_preserve_authoritative_identity_and_nonincreasing_bounds() {
    use crate::{FastOpenCookieLifetime, FastOpenKeyLease, FastOpenServerKey};
    for seed in 0..16u64 {
        let mut config = EndpointConfig::default();
        config.connection.timestamps = false;
        let mut endpoint = Endpoint::new(config, [42; 32], 0, |_| true).unwrap();
        let address = "192.0.2.1:8080".parse().unwrap();
        let mut listener = endpoint.listen(address, 8).unwrap();
        let keys = [
            FastOpenServerKey::HmacSha256([7; 32]),
            FastOpenServerKey::HmacSha256([8; 32]),
            #[cfg(feature = "tfo-linux-cookie")]
            FastOpenServerKey::LinuxSipHash24(crate::LinuxSipHash24Key::new([7; 16])),
            #[cfg(feature = "tfo-linux-cookie")]
            FastOpenServerKey::LinuxSipHash24(crate::LinuxSipHash24Key::new([8; 16])),
        ];
        let mut seen: Vec<Option<(u64, Instant, Option<FastOpenKeyLease>)>> =
            vec![None; keys.len()];
        let mut random = seed + 1;
        for now in 0..128u64 {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            let index = (random >> 32) as usize % keys.len();
            let key = keys[index].clone();
            let lifetime = FastOpenCookieLifetime::from_micros(100 + now).unwrap();
            endpoint.set_fast_open_cookie_lifetime(lifetime);
            let lease =
                FastOpenKeyLease::for_lifetime(now, lifetime, CallerTimebase::default(), false)
                    .unwrap();
            match random % 7 {
                0 => endpoint
                    .install_fast_open_key(now, key, lease, false)
                    .unwrap(),
                1 => endpoint
                    .install_listener_fast_open_key(now, listener, key, lease, false)
                    .unwrap(),
                2 => endpoint.register_fast_open_key(now, key, lease).unwrap(),
                3 => {
                    endpoint
                        .set_listener_fast_open_cookie_policy(listener, None)
                        .unwrap();
                }
                4 => {
                    endpoint.close_listener(listener).unwrap();
                    endpoint.cleanup_one();
                    listener = endpoint.listen(address, 8).unwrap();
                }
                5 => endpoint.clear_fast_open_client_cache(),
                _ => {
                    // Every invalid administrative attempt must leave all
                    // users' facts and the clock untouched, including known keys.
                    let before = endpoint.fast_open_key_registry_usage();
                    let clock = endpoint.now;
                    let facts: Vec<_> = keys
                        .iter()
                        .map(|key| endpoint.fast_open_credentials.constraints(key))
                        .collect();
                    let invalid = FastOpenKeyLease {
                        units_per_second: 123,
                        ..lease
                    };
                    assert!(
                        endpoint
                            .install_fast_open_key(now, key, invalid, false)
                            .is_err()
                    );
                    assert_eq!(endpoint.fast_open_key_registry_usage(), before);
                    assert_eq!(endpoint.now, clock);
                    assert_eq!(
                        keys.iter()
                            .map(|key| endpoint.fast_open_credentials.constraints(key))
                            .collect::<Vec<_>>(),
                        facts
                    );
                }
            }
            for (index, key) in keys.iter().enumerate() {
                let facts = endpoint.fast_open_credentials.constraints(key);
                if let Some((epoch, registered, Some(lease))) = facts {
                    if let Some((old_epoch, old_registered, Some(old))) = seen[index] {
                        assert_eq!(epoch, old_epoch, "epoch mapping changed");
                        assert_eq!(registered, old_registered, "identity clock changed");
                        assert!(lease.issue_until <= old.issue_until);
                        assert!(lease.accept_until <= old.accept_until);
                        assert!(lease.not_before >= old.not_before);
                    }
                    seen[index] = Some((epoch, registered, Some(lease)));
                } else {
                    assert!(seen[index].is_none(), "administration erased an identity");
                }
            }
            assert_eq!(
                endpoint.fast_open_key_registry_usage().0,
                1 + seen.iter().filter(|entry| entry.is_some()).count()
            );
            assert_eq!(
                endpoint.buffer_bytes(),
                endpoint.fast_open_key_registry_usage().1
            );
            assert!(endpoint.buffer_bytes() <= endpoint.config.max_buffer_bytes);
        }
    }
}

#[test]
fn registry_capacity_and_allocation_failure_are_atomic_and_legacy_revocation_blocks() {
    use crate::{FastOpenCookieLifetime, FastOpenKeyLease, FastOpenServerKey};
    let mut config = EndpointConfig::default();
    config.connection.timestamps = false;
    let mut endpoint = Endpoint::new(config, [42; 32], 0, |_| true).unwrap();
    let address = "192.0.2.1:8080".parse().unwrap();
    let listener = endpoint.listen(address, 8).unwrap();
    endpoint
        .set_listener_fast_open_cookie_lifetime(listener, FastOpenCookieLifetime::default())
        .unwrap();
    let old = FastOpenServerKey::HmacSha256([42; 32]);
    let facts = endpoint.fast_open_credentials.constraints(&old);
    let lease = FastOpenKeyLease::for_lifetime(
        1,
        FastOpenCookieLifetime::from_micros(100).unwrap(),
        CallerTimebase::default(),
        false,
    )
    .unwrap();
    crate::allocation_tests::fail_after(0, || {
        assert_eq!(
            endpoint.install_fast_open_key(1, FastOpenServerKey::HmacSha256([7; 32]), lease, true),
            Err(Error::NoMemory.into())
        );
    });
    assert_eq!(endpoint.now, 0);
    assert_eq!(endpoint.fast_open_key_registry_usage(), (1, 0));
    assert_eq!(endpoint.fast_open_credentials.constraints(&old), facts);
    endpoint.config.max_buffer_bytes = 0;
    assert_eq!(
        endpoint.try_set_fast_open_hmac_key([7; 32]),
        Err(Error::NoMemory.into())
    );
    assert_eq!(endpoint.fast_open_hmac_key, [42; 32]);
    assert_eq!(endpoint.fast_open_cookie_error(), None);
    endpoint.set_fast_open_hmac_key([7; 32]);
    assert_eq!(endpoint.fast_open_cookie_error(), Some(Error::NoMemory));
    assert_eq!(
        endpoint.listener_fast_open_cookie_error(listener).unwrap(),
        Some(Error::NoMemory)
    );
    assert!(
        endpoint.listeners[listener.slot]
            .as_ref()
            .unwrap()
            .fast_open_cookie_policy
            .is_some()
    );
    let local = address.ip();
    let remote = "192.0.2.2".parse().unwrap();
    let cookie = crate::fast_open::issue(&[42; 32], local, remote, 0);
    let context = endpoint.listeners[listener.slot]
        .as_ref()
        .unwrap()
        .fast_open_cookie_policy
        .as_ref()
        .unwrap();
    assert!(!context.valid(&endpoint.fast_open_credentials, 1, local, remote, cookie));
    assert_eq!(
        context.issue(&endpoint.fast_open_credentials, 1, local, remote),
        None
    );
    // Unknown listener selection is fallible and cannot clear a blocked override.
    assert_eq!(
        endpoint
            .set_listener_fast_open_cookie_policy(listener, Some(FastOpenCookiePolicy::HmacSha256)),
        Err(Error::NoMemory.into())
    );
    assert_eq!(
        endpoint.listener_fast_open_cookie_error(listener).unwrap(),
        Some(Error::NoMemory)
    );
    crate::allocation_tests::fail_after(0, || {
        endpoint.try_set_fast_open_hmac_key([42; 32]).unwrap();
    });
    assert_eq!(endpoint.fast_open_key_registry_usage(), (1, 0));
    assert_eq!(endpoint.fast_open_cookie_error(), None);
    // Charge actual growth, then freeze the configured budget at that charge.
    endpoint.config.max_buffer_bytes = usize::MAX;
    endpoint
        .install_fast_open_key(1, FastOpenServerKey::HmacSha256([7; 32]), lease, false)
        .unwrap();
    endpoint.config.max_buffer_bytes = endpoint.buffer_bytes();
    let before = endpoint.fast_open_key_registry_usage();
    let facts = endpoint
        .fast_open_credentials
        .constraints(&FastOpenServerKey::HmacSha256([7; 32]));
    let invalid = ListenerId {
        slot: listener.slot,
        generation: listener.generation + 1,
    };
    assert_eq!(
        endpoint.install_listener_fast_open_key(
            2,
            invalid,
            old.clone(),
            FastOpenKeyLease {
                issue_until: 2,
                accept_until: 2,
                ..lease
            },
            false
        ),
        Err(EndpointError::InvalidHandle)
    );
    assert_eq!(
        endpoint.install_fast_open_key(2, FastOpenServerKey::HmacSha256([8; 32]), lease, true),
        Err(Error::NoMemory.into())
    );
    assert_eq!(endpoint.fast_open_key_registry_usage(), before);
    assert_eq!(endpoint.now, 1);
    assert_eq!(
        endpoint
            .fast_open_credentials
            .constraints(&FastOpenServerKey::HmacSha256([7; 32])),
        facts
    );
    endpoint
        .install_fast_open_key(2, old, lease, false)
        .unwrap();
    assert_eq!(endpoint.fast_open_key_registry_usage(), before);
    assert!(endpoint.buffer_bytes() <= endpoint.config.max_buffer_bytes);
}

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
        let scoped = crate::ScopedTuple::unscoped(tuple);
        let identity = endpoint.digest(b"ntcp initial sequence", scoped);
        let hash = endpoint.hash(scoped);
        let timestamp = endpoint.timestamp_offset(scoped);
        let isn = endpoint.isn(scoped);
        let before = endpoint.buffer_bytes();
        endpoint.try_set_fast_open_hmac_key([9; 32]).unwrap();
        endpoint
            .install_fast_open_key(
                0,
                crate::FastOpenServerKey::HmacSha256([99; 32]),
                crate::FastOpenKeyLease::for_lifetime(
                    0,
                    Default::default(),
                    crate::CallerTimebase::default(),
                    true,
                )
                .unwrap(),
                true,
            )
            .unwrap();
        assert_eq!(
            endpoint.buffer_bytes(),
            before + endpoint.fast_open_key_registry_usage().1
        );
        let usage = endpoint.fast_open_key_registry_usage();
        crate::allocation_tests::fail_after(0, || {
            endpoint.try_set_fast_open_hmac_key([99; 32]).unwrap();
        });
        assert_eq!(endpoint.fast_open_key_registry_usage(), usage);
        assert!(endpoint.fast_open.is_none());
        // The identity key is still the endpoint's secret.
        let mut mac = Hmac::<Sha256>::new_from_slice(&[42; 32]).unwrap();
        mac.update(b"ntcp initial sequence");
        encode_tuple(scoped, |bytes| mac.update(bytes));
        assert_eq!(<[u8; 32]>::from(mac.finalize().into_bytes()), identity);
        assert_eq!(endpoint.digest(b"ntcp initial sequence", scoped), identity);
        assert_eq!(endpoint.hash(scoped), hash);
        assert_eq!(endpoint.timestamp_offset(scoped), timestamp);
        assert_eq!(endpoint.isn(scoped), isn.wrapping_add(1));
        #[cfg(feature = "tfo-linux-cookie")]
        {
            let policy =
                FastOpenCookiePolicy::LinuxSipHash24(crate::LinuxSipHash24Key::new([7; 16]));
            endpoint.set_fast_open_cookie_policy(policy.clone());
            let before = policy.issue(&[42; 32], tuple.local.ip(), tuple.remote.ip(), 0);
            endpoint.set_fast_open_hmac_key([10; 32]);
            assert_eq!(
                endpoint.fast_open_cookie_policy.issue(
                    &endpoint.fast_open_credentials,
                    0,
                    tuple.local.ip(),
                    tuple.remote.ip()
                ),
                before
            );
            assert!(matches!(
                endpoint.fast_open_cookie_policy.policy(),
                FastOpenCookiePolicy::LinuxSipHash24(_)
            ));
        }
        endpoint.set_fast_open_cookie_policy(FastOpenCookiePolicy::HmacSha256);
        assert_eq!(
            endpoint.fast_open_hmac_key,
            if cfg!(feature = "tfo-linux-cookie") {
                [10; 32]
            } else {
                [99; 32]
            }
        );
    }
}

// The tuple digests (ISN and timestamp-offset domains) keep their unscoped
// bytes and separate zones, including a recycled link slot. The lookup hash
// reads the same tuple encoding and separates the zones too.
#[test]
fn scoped_tuple_digests_separate_zones_and_keep_unscoped_bytes() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let endpoint = Endpoint::new(EndpointConfig::default(), [5; 32], 0, |_| true).unwrap();
    let tuple = Tuple {
        local: "[fe80::1]:1000".parse().unwrap(),
        remote: "[fe80::2]:8080".parse().unwrap(),
    };
    let mut legacy = Hmac::<Sha256>::new_from_slice(&[5; 32]).unwrap();
    legacy.update(b"ntcp initial sequence");
    for address in [tuple.local, tuple.remote] {
        legacy.update(&[6]);
        if let SocketAddr::V6(v6) = address {
            legacy.update(&v6.ip().octets());
        }
        legacy.update(&address.port().to_be_bytes());
    }
    let legacy: [u8; 32] = legacy.finalize().into_bytes().into();
    let unscoped = crate::ScopedTuple::unscoped(tuple);
    assert_eq!(endpoint.digest(b"ntcp initial sequence", unscoped), legacy);
    let digests = crate::fast_open_policy_tests::zones().map(|zone| {
        endpoint.digest(
            b"ntcp initial sequence",
            crate::ScopedTuple::new(tuple, Some(zone)).unwrap(),
        )
    });
    assert!(digests.iter().all(|digest| *digest != legacy));
    assert_ne!(digests[0], digests[1]);
    assert_ne!(digests[0], digests[2]);
    assert_ne!(digests[1], digests[2]);
    let hashes = crate::fast_open_policy_tests::zones()
        .map(|zone| endpoint.hash(crate::ScopedTuple::new(tuple, Some(zone)).unwrap()));
    assert!(hashes.iter().all(|hash| *hash != endpoint.hash(unscoped)));
    assert_ne!(hashes[0], hashes[1]);
    assert_ne!(hashes[0], hashes[2]);
    assert_ne!(hashes[1], hashes[2]);
}

// The lookup hash writes the tuple encoding once; SipHash streams, so it is
// the hash of a write per encoded field, for either family, mixed families'
// ports and every zone.
#[test]
fn lookup_hash_equals_a_write_per_encoded_field() {
    use core::hash::Hasher;
    let endpoint = Endpoint::new(EndpointConfig::default(), [9; 32], 0, |_| true).unwrap();
    let per_field = |scoped: crate::ScopedTuple| {
        let mut hash = siphasher::sip::SipHasher13::new_with_key(&endpoint.lookup_key);
        encode_tuple(scoped, |bytes| hash.write(bytes));
        hash.finish() as usize
    };
    let mut state = 0x9e37_79b9_u32;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state
    };
    let mut checked = 0;
    for round in 0..3000 {
        let (a, b, c, d) = (next(), next(), next(), next());
        let port = |x: u32| (x >> 16) as u16;
        let tuple = if round % 2 == 0 {
            Tuple {
                local: SocketAddr::new(IpAddr::V4(a.into()), port(c)),
                remote: SocketAddr::new(IpAddr::V4(b.into()), port(d)),
            }
        } else {
            let v6 = |x: u32, y: u32| {
                let mut octets = [0; 16];
                octets[..4].copy_from_slice(&x.to_be_bytes());
                octets[12..].copy_from_slice(&y.to_be_bytes());
                IpAddr::V6(octets.into())
            };
            Tuple {
                local: SocketAddr::new(v6(a, b), port(c)),
                remote: SocketAddr::new(v6(b, a), port(d)),
            }
        };
        let scoped = crate::ScopedTuple::unscoped(tuple);
        assert_eq!(endpoint.hash(scoped), per_field(scoped));
        checked += 1;
    }
    let tuple = Tuple {
        local: "[fe80::1]:1000".parse().unwrap(),
        remote: "[fe80::2]:8080".parse().unwrap(),
    };
    for zone in crate::fast_open_policy_tests::zones() {
        let scoped = crate::ScopedTuple::new(tuple, Some(zone)).unwrap();
        assert_eq!(endpoint.hash(scoped), per_field(scoped));
        checked += 1;
    }
    assert_eq!(checked, 3003);
}
