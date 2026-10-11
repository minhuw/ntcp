extern crate std;

use crate::{wire::FastOpenCookie, *};
use core::net::SocketAddr;

#[test]
fn default_policy_preserves_hmac_epochs_and_addresses() {
    let policy = FastOpenCookiePolicy::default();
    assert!(matches!(policy, FastOpenCookiePolicy::HmacSha256));
    for (local, remote) in [
        ("192.168.0.1", "192.0.2.1"),
        ("fd3d:0a0b:17d6::1", "fd3d:fa7b:d17d::1"),
    ] {
        let local = local.parse().unwrap();
        let remote = remote.parse().unwrap();
        let cookie = crate::fast_open::issue(&[42; 32], local, remote, 7);
        assert_eq!(policy.issue(&[42; 32], local, remote, 7), Some(cookie));
        for epoch in [6, 7, 8, 9] {
            assert_eq!(
                policy.valid(&[42; 32], local, remote, epoch, cookie),
                matches!(epoch, 7 | 8)
            );
        }
        assert!(!policy.valid(&[43; 32], local, remote, 7, cookie));
        assert!(!policy.valid(&[42; 32], remote, local, 7, cookie));
    }
}

fn endpoint() -> Endpoint {
    Endpoint::new(
        EndpointConfig {
            max_connections: 16,
            max_listeners: 2,
            ..EndpointConfig::default()
        },
        [42; 32],
        0,
        |_| true,
    )
    .unwrap()
}

fn addresses(port: u16) -> (SocketAddr, SocketAddr) {
    (
        SocketAddr::new("192.168.0.1".parse().unwrap(), port),
        "192.0.2.1:40000".parse().unwrap(),
    )
}

fn syn(endpoint: &mut Endpoint, port: u16, client_port: u16, cookie: FastOpenCookie) {
    let (local, remote) = addresses(port);
    send_syn(
        endpoint,
        local,
        SocketAddr::new(remote.ip(), client_port),
        Some(cookie),
        b"early",
    );
}

fn send_syn(
    endpoint: &mut Endpoint,
    local: SocketAddr,
    remote: SocketAddr,
    cookie: Option<FastOpenCookie>,
    payload: &[u8],
) {
    let ip = IpMetadata {
        source: remote.ip(),
        destination: local.ip(),
    };
    let mut options = [1; 20];
    let option_len = if let Some(cookie) = cookie {
        let n = cookie.as_bytes().len();
        options[..2].copy_from_slice(&[34, (n + 2) as u8]);
        options[2..2 + n].copy_from_slice(cookie.as_bytes());
        (n + 2).next_multiple_of(4)
    } else {
        0
    };
    let mut bytes = [0; 128];
    let n = wire::encode(
        ip,
        wire::Header {
            source_port: remote.port(),
            destination_port: local.port(),
            sequence: 100,
            acknowledgment: 0,
            flags: wire::SYN,
            window: 8192,
            urgent_pointer: 0,
        },
        &options[..option_len],
        payload,
        &mut bytes,
    )
    .unwrap();
    endpoint.input(0, ip, &bytes[..n]).unwrap();
}

fn response(endpoint: &mut Endpoint) -> (ConnectionId, Option<FastOpenCookie>, u32) {
    let mut bytes = [0; 2048];
    let tx = endpoint
        .poll_transmit(0, &mut bytes, 64)
        .unwrap()
        .packet
        .unwrap();
    let segment = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
    (
        tx.connection.unwrap(),
        segment.options.fast_open,
        segment.header.acknowledgment,
    )
}

#[test]
fn setters_do_not_enable_service_or_listeners_and_reject_stale_handles() {
    for policy in [
        FastOpenCookiePolicy::HmacSha256,
        #[cfg(feature = "tfo-linux-cookie")]
        FastOpenCookiePolicy::LinuxSipHash24(LinuxSipHash24Key::new([1; 16])),
    ] {
        let mut endpoint = endpoint();
        let (local, remote) = addresses(8080);
        let listener = endpoint.listen(local, 8).unwrap();
        let before = endpoint.buffer_bytes();
        crate::allocation_tests::fail_after(0, || {
            endpoint.set_fast_open_cookie_policy(policy.clone());
            endpoint
                .set_listener_fast_open_cookie_policy(listener, Some(policy.clone()))
                .unwrap();
        });
        assert_eq!(endpoint.buffer_bytes(), before);
        assert!(endpoint.set_listener_fast_open(listener, 1).is_err());
        assert!(endpoint.connect_fast_open(0, local, remote, b"x").is_err());
        endpoint.enable_fast_open().unwrap();
        syn(&mut endpoint, 8080, 40000, FastOpenCookie::request());
        assert_eq!(response(&mut endpoint).1, None);
        endpoint.close_listener(listener).unwrap();
        assert_eq!(
            endpoint.set_listener_fast_open_cookie_policy(listener, None),
            Err(EndpointError::InvalidHandle)
        );
        for _ in 0..32 {
            endpoint.poll_transmit(0, &mut [0; 2048], 64).unwrap();
        }
        let replacement = endpoint.listen(local, 8).unwrap();
        assert_ne!(replacement, listener);
        assert_eq!(
            endpoint.set_listener_fast_open_cookie_policy(listener, Some(policy.clone())),
            Err(EndpointError::InvalidHandle)
        );
        endpoint
            .set_listener_fast_open_cookie_policy(replacement, None)
            .unwrap();
    }
}

#[test]
fn response_cookie_does_not_change_authentication_or_quota() {
    for (policy, refresh_valid) in [
        (FastOpenCookiePolicy::HmacSha256, true),
        #[cfg(feature = "tfo-linux-cookie")]
        (linux::policy(), false),
    ] {
        for (local, remote) in [
            ("192.168.0.1:8080", "192.0.2.1:40000"),
            ("[fd3d:0a0b:17d6::1]:8080", "[fd3d:fa7b:d17d::1]:40000"),
        ] {
            let local: SocketAddr = local.parse().unwrap();
            let remote: SocketAddr = remote.parse().unwrap();
            let issued = policy.issue(&[42; 32], local.ip(), remote.ip(), 0).unwrap();
            let mut bad = [0; 8];
            bad.copy_from_slice(issued.as_bytes());
            bad[0] ^= 1;
            for incoming in [
                None,
                Some(FastOpenCookie::request()),
                Some(FastOpenCookie::new(&bad).unwrap()),
                Some(issued),
            ] {
                for payload in [b"".as_slice(), b"early"] {
                    for full in [false, true] {
                        let mut endpoint = endpoint();
                        endpoint.enable_fast_open().unwrap();
                        endpoint.set_fast_open_cookie_policy(policy.clone());
                        let listener = endpoint.listen(local, 8).unwrap();
                        endpoint.set_listener_fast_open(listener, 1).unwrap();
                        if full {
                            let mut other = remote;
                            other.set_port(40001);
                            send_syn(&mut endpoint, local, other, Some(issued), b"early");
                            let (child, _, ack) = response(&mut endpoint);
                            assert_eq!(ack, 106);
                            assert_eq!(endpoint.accept(listener).unwrap(), child);
                            // Accept/read does not release the unacknowledged TFO quota.
                            assert_eq!(endpoint.read(child, &mut [0; 5]).unwrap(), 5);
                        }
                        send_syn(&mut endpoint, local, remote, incoming, payload);
                        let (child, cookie, ack) = response(&mut endpoint);
                        let valid = incoming == Some(issued);
                        let early = valid && !full && !payload.is_empty();
                        let expected = if incoming.is_some() && (!valid || refresh_valid) {
                            Some(issued)
                        } else {
                            None
                        };
                        assert_eq!(cookie, expected);
                        assert_eq!(ack, if early { 106 } else { 101 });
                        assert_eq!(
                            endpoint.readable_bytes(child).unwrap(),
                            if early { 5 } else { 0 }
                        );
                        if early {
                            assert_eq!(endpoint.accept(listener).unwrap(), child);
                            let mut data = [0; 5];
                            assert_eq!(endpoint.read(child, &mut data).unwrap(), 5);
                            assert_eq!(&data, b"early");
                        } else {
                            assert!(endpoint.accept(listener).is_err());
                        }
                    }
                }
            }
        }
    }
}

#[cfg(feature = "tfo-linux-cookie")]
mod linux {
    use super::*;
    use core::net::IpAddr;
    use std::format;

    fn key() -> LinuxSipHash24Key {
        LinuxSipHash24Key::new([
            0xa1, 0xa1, 0xa1, 0xa1, 0xb2, 0xb2, 0xb2, 0xb2, 0xc3, 0xc3, 0xc3, 0xc3, 0xd4, 0xd4,
            0xd4, 0xd4,
        ])
    }

    pub(super) fn policy() -> FastOpenCookiePolicy {
        FastOpenCookiePolicy::LinuxSipHash24(key())
    }

    fn cookie(policy: &FastOpenCookiePolicy) -> FastOpenCookie {
        let (local, remote) = addresses(8080);
        policy.issue(&[42; 32], local.ip(), remote.ip(), 0).unwrap()
    }

    #[test]
    fn openssl_linux_vectors_and_validation_boundaries() {
        // Independently reproduced with openssl mac -macopt hexkey:KEY
        // -macopt size:8 SIPHASH over remote.octets() || local.octets().
        for (key, remote, local, expected) in [
            (
                key(),
                "192.0.2.1",
                "192.168.0.1",
                [0x30, 0x21, 0xb9, 0xd8, 0x89, 0x01, 0x7e, 0xeb],
            ),
            (
                key(),
                "fd3d:fa7b:d17d::1",
                "fd3d:0a0b:17d6::1",
                [0xc1, 0xd1, 0xe9, 0x74, 0x2a, 0x47, 0xa9, 0xbc],
            ),
            (
                LinuxSipHash24Key::from_slice(&[
                    0xf7, 0x63, 0xbf, 0xa0, 0x81, 0x3d, 0x80, 0xed, 0x30, 0x1d, 0x64, 0xcd, 0x90,
                    0x4a, 0xbc, 0xce,
                ])
                .unwrap(),
                "10.248.0.2",
                "192.168.0.2",
                [0x00, 0xab, 0xaa, 0xab, 0xe8, 0xe9, 0x54, 0xc2],
            ),
        ] {
            let policy = FastOpenCookiePolicy::LinuxSipHash24(key);
            let local: IpAddr = local.parse().unwrap();
            let remote: IpAddr = remote.parse().unwrap();
            let cookie = FastOpenCookie::new(&expected).unwrap();
            assert_eq!(policy.issue(&[0; 32], local, remote, 0), Some(cookie));
            assert_eq!(
                policy.issue(&[1; 32], local, remote, u64::MAX),
                Some(cookie)
            );
            assert!(policy.valid(&[1; 32], local, remote, u64::MAX, cookie));
            let other = if local.is_ipv4() {
                "192.0.2.99"
            } else {
                "fd3d::99"
            }
            .parse()
            .unwrap();
            assert!(!policy.valid(&[0; 32], other, remote, 0, cookie));
            assert!(!policy.valid(&[0; 32], local, other, 0, cookie));
            assert!(!policy.valid(&[0; 32], remote, local, 0, cookie));
            let other_family = if local.is_ipv4() {
                "::ffff:192.168.0.1"
            } else {
                "192.168.0.1"
            }
            .parse()
            .unwrap();
            assert_eq!(policy.issue(&[0; 32], other_family, remote, 0), None);
            assert!(!policy.valid(&[0; 32], local, other_family, 0, cookie));
            assert!(!policy.valid(&[0; 32], other_family, other_family, 0, cookie));
            let wrong_key = FastOpenCookiePolicy::LinuxSipHash24(LinuxSipHash24Key::new([0; 16]));
            assert!(!wrong_key.valid(&[0; 32], local, remote, 0, cookie));
            for n in [0, 4, 6, 10, 12, 14, 16] {
                assert!(!policy.valid(
                    &[0; 32],
                    local,
                    remote,
                    0,
                    FastOpenCookie::new(&[0; 16][..n]).unwrap()
                ));
            }
            for i in 0..8 {
                let mut corrupted = expected;
                corrupted[i] ^= 1;
                assert!(!policy.valid(
                    &[0; 32],
                    local,
                    remote,
                    0,
                    FastOpenCookie::new(&corrupted).unwrap()
                ));
            }
        }
        for n in [0, 15, 17, 32] {
            assert!(matches!(
                LinuxSipHash24Key::from_slice(&[1; 32][..n]),
                Err(Error::InvalidArgument)
            ));
        }
        assert_eq!(format!("{:?}", key()), "LinuxSipHash24Key([REDACTED])");
        assert_eq!(
            format!("{:?}", policy()),
            "LinuxSipHash24(LinuxSipHash24Key([REDACTED]))"
        );
    }

    #[test]
    fn global_listener_policy_isolation_fallback_and_generation_reset() {
        let mut endpoint = endpoint();
        endpoint.enable_fast_open().unwrap();
        let a = endpoint.listen(addresses(8080).0, 8).unwrap();
        let b = endpoint.listen(addresses(8081).0, 8).unwrap();
        endpoint.set_listener_fast_open(a, 4).unwrap();
        endpoint.set_listener_fast_open(b, 4).unwrap();
        endpoint.set_fast_open_cookie_policy(policy());
        endpoint
            .set_listener_fast_open_cookie_policy(b, Some(FastOpenCookiePolicy::HmacSha256))
            .unwrap();
        let linux = cookie(&policy());
        let hmac = cookie(&FastOpenCookiePolicy::HmacSha256);
        syn(&mut endpoint, 8080, 40000, linux);
        assert!(endpoint.accept(a).is_ok());
        assert_eq!(response(&mut endpoint).1, None);
        syn(&mut endpoint, 8081, 40000, linux);
        assert!(endpoint.accept(b).is_err());
        let (_, issued, ack) = response(&mut endpoint);
        assert_eq!((issued, ack), (Some(hmac), 101));
        syn(&mut endpoint, 8081, 40001, hmac);
        assert!(endpoint.accept(b).is_ok());
        assert_eq!(response(&mut endpoint).1, Some(hmac));
        endpoint
            .set_listener_fast_open_cookie_policy(b, None)
            .unwrap();
        syn(&mut endpoint, 8081, 40002, linux);
        assert!(endpoint.accept(b).is_ok());
        assert_eq!(response(&mut endpoint).1, None);
        endpoint
            .set_listener_fast_open_cookie_policy(a, Some(policy()))
            .unwrap();
        endpoint.set_fast_open_cookie_policy(FastOpenCookiePolicy::HmacSha256);
        syn(&mut endpoint, 8080, 40003, linux);
        assert!(endpoint.accept(a).is_ok());
        assert_eq!(response(&mut endpoint).1, None);
        syn(&mut endpoint, 8081, 40003, linux);
        assert!(endpoint.accept(b).is_err());
        assert_eq!(response(&mut endpoint).1, Some(hmac));
        endpoint.close_listener(a).unwrap();
        for _ in 0..32 {
            endpoint.poll_transmit(0, &mut [0; 2048], 64).unwrap();
        }
        let replacement = endpoint.listen(addresses(8080).0, 8).unwrap();
        assert_ne!(replacement, a);
        assert_eq!(
            endpoint.set_listener_fast_open_cookie_policy(a, Some(policy())),
            Err(EndpointError::InvalidHandle)
        );
        endpoint.set_listener_fast_open(replacement, 4).unwrap();
        syn(&mut endpoint, 8080, 40004, linux);
        assert!(endpoint.accept(replacement).is_err());
        assert_eq!(response(&mut endpoint).1, Some(hmac));
        // Another endpoint retains its default despite the first endpoint's policies.
        let mut other = super::endpoint();
        other.enable_fast_open().unwrap();
        let listener = other.listen(addresses(8080).0, 8).unwrap();
        other.set_listener_fast_open(listener, 4).unwrap();
        syn(&mut other, 8080, 40000, linux);
        assert!(other.accept(listener).is_err());
        assert_eq!(response(&mut other).1, Some(hmac));
    }

    #[test]
    fn rotation_preserves_issued_responses_and_retransmission_omission() {
        let old = cookie(&policy());
        for incoming in [
            FastOpenCookie::request(),
            FastOpenCookie::new(&[0; 8]).unwrap(),
            old,
        ] {
            let mut endpoint = endpoint();
            endpoint.enable_fast_open().unwrap();
            endpoint.enable_output_reservations().unwrap();
            let listener = endpoint.listen(addresses(8080).0, 8).unwrap();
            endpoint.set_listener_fast_open(listener, 1).unwrap();
            endpoint.set_fast_open_cookie_policy(policy());
            syn(&mut endpoint, 8080, 40000, incoming);
            endpoint.set_fast_open_cookie_policy(FastOpenCookiePolicy::HmacSha256);
            let mut bytes = [0; 2048];
            let (output, attempt) = endpoint.poll_reserved_transmit(0, &mut bytes, 64).unwrap();
            let tx = output.packet.unwrap();
            let child = tx.connection.unwrap();
            let first = bytes[..tx.len].to_vec();
            let segment = wire::parse(tx.ip, &first).unwrap();
            assert_eq!(
                segment.options.fast_open,
                if incoming == old { None } else { Some(old) }
            );
            assert_eq!(
                segment.header.acknowledgment,
                if incoming == old { 106 } else { 101 }
            );
            endpoint.set_fast_open_cookie_policy(FastOpenCookiePolicy::LinuxSipHash24(
                LinuxSipHash24Key::new([9; 16]),
            ));
            assert_eq!(&bytes[..tx.len], first.as_slice());
            assert!(endpoint.reject_unsubmitted(attempt.unwrap()).unwrap());
            let (output, attempt) = endpoint
                .poll_reserved_transmit_for(0, child, &mut bytes, 64)
                .unwrap();
            let tx = output.packet.unwrap();
            let retry = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
            assert_eq!(retry.header, segment.header);
            assert_eq!(retry.options, segment.options);
            assert_eq!(retry.payload, segment.payload);
            assert!(endpoint.accept_transmit(0, attempt.unwrap()).unwrap());
            // Existing children do not reauthenticate or issue under the new policy.
            // Retransmitted SYN-ACKs omit FO under the existing RFC 7413 fallback.
            syn(&mut endpoint, 8080, 40000, incoming);
            let (retry_child, cookie, ack) = response(&mut endpoint);
            assert_eq!(retry_child, child);
            assert_eq!(cookie, None);
            assert_eq!(ack, segment.header.acknowledgment);
            let deadline = endpoint.next_deadline().unwrap();
            endpoint.on_timeout(deadline, 64).unwrap();
            let tx = endpoint
                .poll_transmit(deadline, &mut bytes, 64)
                .unwrap()
                .packet
                .unwrap();
            let retry = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
            assert_eq!(tx.connection, Some(child));
            assert_eq!(retry.options.fast_open, None);
            assert_eq!(retry.header.acknowledgment, segment.header.acknowledgment);
            assert_eq!(
                endpoint.readable_bytes(child).unwrap(),
                if incoming == old { 5 } else { 0 }
            );
        }
    }

    #[test]
    fn rotation_preserves_created_child_reserved_bytes_budget_and_owner_barriers() {
        for listener_override in [false, true] {
            let mut endpoint = endpoint();
            endpoint.enable_fast_open().unwrap();
            endpoint.enable_output_reservations().unwrap();
            let listener = endpoint.listen(addresses(8080).0, 8).unwrap();
            endpoint.set_listener_fast_open(listener, 1).unwrap();
            if listener_override {
                endpoint
                    .set_listener_fast_open_cookie_policy(listener, Some(policy()))
                    .unwrap();
            } else {
                endpoint.set_fast_open_cookie_policy(policy());
            }
            let old = cookie(&policy());
            syn(&mut endpoint, 8080, 40000, old);
            let before = endpoint.buffer_bytes();
            let replacement = FastOpenCookiePolicy::LinuxSipHash24(LinuxSipHash24Key::new([9; 16]));
            // The child snapshots the response before its first output poll.
            crate::allocation_tests::fail_after(0, || {
                if listener_override {
                    endpoint
                        .set_listener_fast_open_cookie_policy(listener, Some(replacement))
                        .unwrap();
                } else {
                    endpoint.set_fast_open_cookie_policy(replacement);
                }
            });
            assert_eq!(endpoint.buffer_bytes(), before);
            let mut bytes = [0; 2048];
            let (output, attempt) = endpoint.poll_reserved_transmit(0, &mut bytes, 64).unwrap();
            let tx = output.packet.unwrap();
            let child = tx.connection.unwrap();
            let attempt = attempt.unwrap();
            assert_eq!(
                wire::parse(tx.ip, &bytes[..tx.len])
                    .unwrap()
                    .options
                    .fast_open,
                None
            );
            let original = bytes[..tx.len].to_vec();
            assert_eq!(
                endpoint.accept(listener),
                Err(EndpointError::OutputReserved)
            );
            assert_eq!(
                endpoint.close_listener(listener),
                Err(EndpointError::OutputReserved)
            );
            // Rotate the selected policy again while the child's output is held.
            let replacement =
                FastOpenCookiePolicy::LinuxSipHash24(LinuxSipHash24Key::new([10; 16]));
            let new = cookie(&replacement);
            if listener_override {
                endpoint
                    .set_listener_fast_open_cookie_policy(listener, Some(replacement))
                    .unwrap();
            } else {
                endpoint.set_fast_open_cookie_policy(replacement);
            }
            assert_eq!(endpoint.buffer_bytes(), before);
            assert_eq!(&bytes[..tx.len], original.as_slice());
            assert!(endpoint.reject_unsubmitted(attempt).unwrap());
            let (output, next) = endpoint
                .poll_reserved_transmit_for(0, child, &mut bytes, 64)
                .unwrap();
            let tx = output.packet.unwrap();
            // Reservation repair repacks option padding; compare decoded content.
            let first = wire::parse(tx.ip, &original).unwrap();
            let retry = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
            assert_eq!(retry.header, first.header);
            assert_eq!(retry.options, first.options);
            assert_eq!(retry.payload, first.payload);
            assert!(!endpoint.accept_transmit(0, attempt).unwrap());
            assert!(endpoint.accept_transmit(0, next.unwrap()).unwrap());
            assert_eq!(endpoint.accept(listener).unwrap(), child);
            assert_eq!(endpoint.readable_bytes(child).unwrap(), 5);
            // Rotation rejects the old cookie, and issuance uses the new key.
            syn(&mut endpoint, 8080, 40001, old);
            assert_eq!(response(&mut endpoint).1, Some(new));
            assert!(endpoint.accept(listener).is_err());
            // The accepted old child still occupies the one-child quota.
            syn(&mut endpoint, 8080, 40002, new);
            let (_, issued, ack) = response(&mut endpoint);
            assert_eq!((issued, ack), (None, 101));
            assert!(endpoint.accept(listener).is_err());
            endpoint.abort(child).unwrap();
            response(&mut endpoint); // Reset releases quota, not key replacement.
            syn(&mut endpoint, 8080, 40003, old);
            assert_eq!(response(&mut endpoint).2, 101);
            assert!(endpoint.accept(listener).is_err());
            syn(&mut endpoint, 8080, 40004, new);
            assert!(endpoint.accept(listener).is_ok());
            assert_eq!(response(&mut endpoint).2, 106);
        }
    }
}
