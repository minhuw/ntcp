extern crate std;
use crate::*;
use core::net::SocketAddr;
use std::{vec, vec::Vec};

fn addresses(v6: bool, port: u16) -> (SocketAddr, SocketAddr) {
    (
        SocketAddr::new(
            if v6 { "2001:db8::1" } else { "192.0.2.1" }
                .parse()
                .unwrap(),
            port,
        ),
        SocketAddr::new(
            if v6 { "2001:db8::2" } else { "192.0.2.2" }
                .parse()
                .unwrap(),
            8080,
        ),
    )
}
fn endpoint(key: u8, v6: bool) -> Endpoint {
    let config = EndpointConfig {
        max_connections: 16,
        max_listeners: 2,
        connection: ConnectionConfig {
            mss: if v6 { 1220 } else { 536 },
            nagle: false,
            send_capacity: 8192,
            receive_capacity: 8192,
            ..ConnectionConfig::default()
        },
        ..EndpointConfig::default()
    };
    Endpoint::new(config, [key; 32], 0, |_| true).unwrap()
}
fn packet(endpoint: &mut Endpoint, now: u64) -> (IpMetadata, Vec<u8>) {
    for _ in 0..32 {
        let mut bytes = [0; 2048];
        let output = endpoint.poll_transmit(now, &mut bytes, 16).unwrap();
        if let Some(tx) = output.packet {
            return (tx.ip, bytes[..tx.len].to_vec());
        }
    }
    panic!("no packet");
}
fn deliver(endpoint: &mut Endpoint, now: u64, p: &(IpMetadata, Vec<u8>)) {
    endpoint.input(now, p.0, &p.1).unwrap();
}
fn warm(v6: bool) -> (Endpoint, Endpoint, ListenerId) {
    let (local, remote) = addresses(v6, 40000);
    let mut a = endpoint(1, v6);
    let mut b = endpoint(2, v6);
    a.enable_fast_open().unwrap();
    b.enable_fast_open().unwrap();
    let listener = b.listen(remote, 8).unwrap();
    b.set_listener_fast_open(listener, 1).unwrap();
    let (id, accepted) = a
        .connect_fast_open(0, local, remote, b"not accepted on miss")
        .unwrap();
    assert_eq!(accepted, 0);
    let p = packet(&mut a, 0);
    let syn = wire::parse(p.0, &p.1).unwrap();
    assert_eq!(syn.options.fast_open, Some(wire::FastOpenCookie::request()));
    assert!(syn.payload.is_empty());
    deliver(&mut b, 10, &p);
    assert!(b.accept(listener).is_err());
    let p = packet(&mut b, 20);
    assert_eq!(
        wire::parse(p.0, &p.1)
            .unwrap()
            .options
            .fast_open
            .unwrap()
            .as_bytes()
            .len(),
        8
    );
    deliver(&mut a, 30, &p);
    assert!(a.has_fast_open_cookie(30, local.ip(), remote.ip()).unwrap());
    deliver(&mut b, 40, &packet(&mut a, 30));
    let child = b.accept(listener).unwrap();
    a.abort(id).unwrap();
    deliver(&mut b, 50, &packet(&mut a, 40));
    a.release(id).unwrap();
    b.release(child).unwrap();
    (a, b, listener)
}

#[test]
fn fast_open_positive_early_read_delayed_write_quota_survives_accept() {
    for v6 in [false, true] {
        let (mut a, mut b, listener) = warm(v6);
        let (local, remote) = addresses(v6, 40001); // Cache and auth are port independent.
        let (client, n) = a.connect_fast_open(100, local, remote, b"hello").unwrap();
        assert_eq!(n, 5);
        let syn = packet(&mut a, 100);
        deliver(&mut b, 110, &syn);
        let child = b.accept(listener).unwrap();
        assert_eq!(b.state(child).unwrap(), State::SynReceived);
        let mut out = [0; 2048];
        assert_eq!(b.readable_bytes(child).unwrap(), 5);
        assert_eq!(b.read(child, &mut out).unwrap(), 5);
        assert_eq!(&out[..5], b"hello");
        assert_eq!(b.write(child, b"reply").unwrap(), 5);
        let response = packet(&mut b, 120);
        let synack = wire::parse(response.0, &response.1).unwrap();
        assert!(synack.payload.is_empty());
        assert_eq!(
            synack.header.acknowledgment,
            wire::parse(syn.0, &syn.1)
                .unwrap()
                .header
                .sequence
                .wrapping_add(6)
        );
        let (local2, _) = addresses(v6, 40002);
        let (_, n) = a.connect_fast_open(130, local2, remote, b"quota").unwrap();
        assert_eq!(n, 5);
        let second = packet(&mut a, 130);
        deliver(&mut b, 140, &second);
        let fallback = packet(&mut b, 140);
        assert_eq!(
            wire::parse(fallback.0, &fallback.1)
                .unwrap()
                .header
                .acknowledgment,
            wire::parse(second.0, &second.1)
                .unwrap()
                .header
                .sequence
                .wrapping_add(1)
        );
        assert!(b.accept(listener).is_err());
        deliver(&mut a, 150, &response);
        assert_eq!(a.acknowledged(client).unwrap(), 5);
        deliver(&mut b, 160, &packet(&mut a, 150));
        assert_eq!(b.state(child).unwrap(), State::Established);
        deliver(&mut a, 170, &packet(&mut b, 160));
        assert_eq!(a.read(client, &mut out).unwrap(), 5);
        assert_eq!(&out[..5], b"reply");
        // The final ACK, not accept(), released quota.
        let (local3, _) = addresses(v6, 40003);
        a.connect_fast_open(180, local3, remote, b"next").unwrap();
        deliver(&mut b, 190, &packet(&mut a, 180));
        assert!(b.accept(listener).is_ok());
    }
}

#[test]
fn fast_open_default_off_invalid_cookie_and_endpoint_opt_in() {
    for (service, enabled) in [(false, false), (true, false), (true, true)] {
        let (local, remote) = addresses(false, 40000);
        let mut b = endpoint(2, false);
        let listener = b.listen(remote, 8).unwrap();
        assert!(b.set_listener_fast_open(listener, 1).is_err());
        assert!(b.connect_fast_open(0, remote, local, b"x").is_err());
        if service {
            b.enable_fast_open().unwrap();
        }
        if enabled {
            b.set_listener_fast_open(listener, 1).unwrap();
        }
        let ip = IpMetadata {
            source: local.ip(),
            destination: remote.ip(),
        };
        let header = wire::Header {
            source_port: local.port(),
            destination_port: remote.port(),
            sequence: 100,
            acknowledgment: 0,
            flags: wire::SYN,
            window: 8192,
            urgent_pointer: 0,
        };
        let mut bytes = [0; 128];
        let n = wire::encode(
            ip,
            header,
            &[34, 10, 1, 2, 3, 4, 5, 6, 7, 8, 1, 1],
            b"abc",
            &mut bytes,
        )
        .unwrap();
        b.input(0, ip, &bytes[..n]).unwrap();
        assert!(b.accept(listener).is_err());
        let p = packet(&mut b, 10);
        let synack = wire::parse(p.0, &p.1).unwrap();
        // RFC 7413 §4.2.2 step 5: without FastOpened, ACK only the SYN.
        assert_eq!(synack.header.acknowledgment, 101);
        assert_eq!(synack.options.fast_open.is_some(), enabled);
        let ack = wire::Header {
            sequence: 101,
            acknowledgment: synack.header.sequence.wrapping_add(1),
            flags: wire::ACK,
            ..header
        };
        let options = synack.options.timestamps.map(|(ts, _)| {
            let mut options = [1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0];
            options[8..].copy_from_slice(&ts.to_be_bytes());
            options
        });
        let n = wire::encode(
            ip,
            ack,
            options.as_ref().map_or(&[], |o| &o[..]),
            &[],
            &mut bytes,
        )
        .unwrap();
        b.input(20, ip, &bytes[..n]).unwrap();
        let child = b.accept(listener).unwrap();
        assert_eq!(b.readable_bytes(child).unwrap(), 0);
        assert_eq!(b.read(child, &mut bytes), Err(Error::WouldBlock.into()));
        let n = wire::encode(ip, ack, &[], b"abc", &mut bytes).unwrap();
        let retry = bytes[..n].to_vec();
        b.input(30, ip, &retry).unwrap();
        assert_eq!(b.read(child, &mut bytes).unwrap(), 3);
        assert_eq!(&bytes[..3], b"abc");
        b.input(40, ip, &retry).unwrap();
        assert_eq!(b.read(child, &mut bytes), Err(Error::WouldBlock.into()));
    }
}

#[test]
fn fast_open_reserved_rejected_and_blocked_output() {
    for reject in [false, true] {
        let (mut a, mut b, listener) = warm(false);
        a.enable_output_reservations_with_gso(
            2,
            GsoLimits {
                max_bytes: 4096,
                max_segments: 8,
            },
        )
        .unwrap();
        let (local, remote) = addresses(false, 40001);
        let (client, n) = a.connect_fast_open(100, local, remote, &[9; 100]).unwrap();
        assert_eq!(n, 100);
        let mut bytes = [0; 2048];
        let (output, attempt) = a
            .poll_reserved_transmit_for(100, client, &mut bytes, 16)
            .unwrap();
        let tx = output.packet.unwrap();
        let attempt = attempt.unwrap();
        assert!(a.transmit_segmentation(attempt).is_none());
        assert!(
            a.poll_reserved_transmit_for(110, client, &mut bytes, 16)
                .is_err()
        );
        assert_eq!(a.abort(client), Err(EndpointError::OutputReserved));
        let original = bytes[..tx.len].to_vec();
        let (tx, attempt) = if reject {
            assert!(a.reject_unsubmitted(attempt).unwrap());
            assert!(!a.accept_transmit(120, attempt).unwrap());
            let (output, attempt) = a
                .poll_reserved_transmit_for(120, client, &mut bytes, 16)
                .unwrap();
            let tx = output.packet.unwrap();
            let segment = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
            assert_eq!(segment.payload, &[9; 100]);
            (tx, attempt.unwrap())
        } else {
            assert_eq!(&bytes[..tx.len], &original);
            (tx, attempt)
        };
        assert!(a.accept_transmit(10_000, attempt).unwrap());
        b.input(10_010, tx.ip, &bytes[..tx.len]).unwrap();
        let child = b.accept(listener).unwrap();
        assert_eq!(b.readable_bytes(child).unwrap(), 100);
        let synack = packet(&mut b, 10_020);
        deliver(&mut a, 30_000, &synack);
        assert_eq!(a.acknowledged(client).unwrap(), 100);
        assert_eq!(a.transport_info(client).unwrap().rtt_us, Some(20_000));
    }
}

#[test]
fn fast_open_mss_budget_cache_expiry_and_failed_setup() {
    for v6 in [false, true] {
        let (mut a, mut b, listener) = warm(v6);
        let (local, remote) = addresses(v6, 40001);
        let (client, n) = a
            .connect_fast_open(100, local, remote, &vec![1; 4096])
            .unwrap();
        assert_eq!(n, if v6 { 1180 } else { 496 });
        let syn = packet(&mut a, 100);
        let segment = wire::parse(syn.0, &syn.1).unwrap();
        assert_eq!(segment.payload.len(), n);
        assert!(segment.raw_options.len() + n <= if v6 { 1220 } else { 536 });
        assert!(
            a.connect_fast_open(100, local, remote, b"duplicate")
                .is_err()
        );
        deliver(&mut b, 110, &syn);
        let child = b.accept(listener).unwrap();
        b.close_listener(listener).unwrap(); // Early-accepted child is independent.
        b.on_timeout(120, 64).unwrap();
        assert_eq!(b.state(child).unwrap(), State::SynReceived);
        b.abort(child).unwrap();
        deliver(&mut a, 130, &packet(&mut b, 120));
        assert_eq!(a.state(client).unwrap(), State::Closed);
        let expired = 3_600_000_100;
        assert!(
            !a.has_fast_open_cookie(expired, local.ip(), remote.ip())
                .unwrap()
        );
        let (local, _) = addresses(v6, 40002);
        let (_, n) = a
            .connect_fast_open(expired, local, remote, b"stale")
            .unwrap();
        assert_eq!(n, 0);
    }
}

#[test]
fn fast_open_duplicate_syn_timeout_reset_and_generation_quota() {
    let (mut a, mut b, listener) = warm(false);
    let (local, remote) = addresses(false, 40001);
    a.connect_fast_open(100, local, remote, b"once").unwrap();
    let syn = packet(&mut a, 100);
    deliver(&mut b, 110, &syn);
    let child = b.accept(listener).unwrap();
    let first = packet(&mut b, 120);
    deliver(&mut b, 130, &syn);
    let retry = packet(&mut b, 140);
    let first = wire::parse(first.0, &first.1).unwrap();
    let retry = wire::parse(retry.0, &retry.1).unwrap();
    assert_eq!(first.header.acknowledgment, retry.header.acknowledgment);
    assert!(first.options.fast_open.is_some());
    assert!(retry.options.fast_open.is_none());
    assert!(retry.payload.is_empty());
    assert_eq!(b.readable_bytes(child).unwrap(), 4);
    assert!(b.accept(listener).is_err());
    let deadline = b.next_deadline().unwrap();
    b.on_timeout(deadline, 64).unwrap();
    let retry = packet(&mut b, deadline);
    assert!(
        wire::parse(retry.0, &retry.1)
            .unwrap()
            .options
            .fast_open
            .is_none()
    );
    b.abort(child).unwrap(); // Reset releases pending quota even before reclaim.
    let (local2, _) = addresses(false, 40002);
    a.connect_fast_open(deadline, local2, remote, b"next")
        .unwrap();
    deliver(&mut b, deadline, &packet(&mut a, deadline));
    let next = b.accept(listener).unwrap();
    assert_eq!(b.readable_bytes(next).unwrap(), 4);
    b.close_listener(listener).unwrap();
    // Output polling owns deferred listener reclamation.
    for _ in 0..32 {
        if !b
            .poll_transmit(deadline, &mut [0; 2048], 64)
            .unwrap()
            .more_work
        {
            break;
        }
    }
    let replacement = b.listen(remote, 8).unwrap();
    assert_ne!(replacement, listener);
    b.set_listener_fast_open(replacement, 1).unwrap();
    let (local3, _) = addresses(false, 40003);
    a.connect_fast_open(deadline, local3, remote, b"new generation")
        .unwrap();
    deliver(&mut b, deadline, &packet(&mut a, deadline));
    assert!(b.accept(replacement).is_ok());
    assert_eq!(b.state(next).unwrap(), State::SynReceived);
}

#[test]
fn fast_open_fallible_setup_is_transactional() {
    use crate::allocation_tests::fail_after;
    let (local, remote) = addresses(false, 40001);
    let mut fresh = endpoint(1, false);
    assert_eq!(
        fail_after(0, || fresh.enable_fast_open()),
        Err(EndpointError::Connection(Error::NoMemory))
    );
    assert!(fresh.connect_fast_open(0, local, remote, b"x").is_err());
    let mut successful = false;
    for failure in 0..32 {
        let (mut a, _, _) = warm(false);
        let result = fail_after(failure, || {
            a.connect_fast_open(100, local, remote, b"copied before publish")
        });
        if let Ok((_, n)) = result {
            assert_eq!(n, 21);
            successful = true;
            break;
        }
        assert!(
            a.poll_transmit(100, &mut [0; 2048], 64)
                .unwrap()
                .packet
                .is_none()
        );
        let (_, n) = a.connect_fast_open(100, local, remote, b"retry").unwrap();
        assert_eq!(n, 5); // Failed construction left no tuple/slot/buffer charge behind.
    }
    assert!(successful);
}

#[test]
fn fast_open_service_does_not_enable_ordinary_connect_or_listener() {
    let (mut a, mut b, listener) = warm(false);
    b.set_listener_fast_open(listener, 0).unwrap();
    let (local, remote) = addresses(false, 40001);
    a.connect(100, local, remote).unwrap();
    let syn = packet(&mut a, 100);
    assert!(
        wire::parse(syn.0, &syn.1)
            .unwrap()
            .options
            .fast_open
            .is_none()
    );
    deliver(&mut b, 110, &syn);
    let reply = packet(&mut b, 120);
    assert!(
        wire::parse(reply.0, &reply.1)
            .unwrap()
            .options
            .fast_open
            .is_none()
    );
}

#[test]
fn fast_open_reserved_syn_is_indivisible_after_path_shrink() {
    let (mut a, _, _) = warm(false);
    let (local, remote) = addresses(false, 40001);
    let (id, _) = a
        .connect_fast_open(100, local, remote, b"one handshake")
        .unwrap();
    let mut bytes = [0; 2048];
    let tx = a
        .poll_transmit(100, &mut bytes, 64)
        .unwrap()
        .packet
        .unwrap();
    let mut reservation = crate::output_reservation::OutputReservation::new();
    reservation.bytes = vec![0; 2048];
    let attempt = reservation.token(Some(id)).unwrap();
    reservation.capture(tx, &bytes, attempt);
    assert_eq!(
        reservation.fragment(tx.len - 1, &mut bytes),
        Err(EndpointError::ReservationMtuTooSmall)
    );
    assert_eq!(reservation.current.as_ref().unwrap().offset, 0);
    let retry = reservation.fragment(tx.len, &mut bytes).unwrap();
    let syn = wire::parse(retry.ip, &bytes[..retry.len]).unwrap();
    assert_eq!(syn.payload, b"one handshake");
    assert_eq!(syn.header.flags & wire::SYN, wire::SYN);
}

#[test]
fn fast_open_early_child_reservation_protects_accept_and_listener_close() {
    let (mut a, mut b, listener) = warm(false);
    b.enable_output_reservations().unwrap();
    let (local, remote) = addresses(false, 40001);
    a.connect_fast_open(100, local, remote, b"early").unwrap();
    deliver(&mut b, 110, &packet(&mut a, 100));
    let mut bytes = [0; 2048];
    let (output, attempt) = b.poll_reserved_transmit(120, &mut bytes, 64).unwrap();
    let child = output.packet.unwrap().connection.unwrap();
    let attempt = attempt.unwrap();
    assert_eq!(b.accept(listener), Err(EndpointError::OutputReserved));
    assert_eq!(
        b.close_listener(listener),
        Err(EndpointError::OutputReserved)
    );
    assert!(b.reject_unsubmitted(attempt).unwrap());
    assert_eq!(b.accept(listener), Err(EndpointError::OutputReserved));
    let (_, next) = b
        .poll_reserved_transmit_for(130, child, &mut bytes, 64)
        .unwrap();
    assert!(!b.accept_transmit(140, attempt).unwrap());
    assert!(b.accept_transmit(140, next.unwrap()).unwrap());
    assert_eq!(b.accept(listener).unwrap(), child);
    assert_eq!(b.read(child, &mut bytes).unwrap(), 5);
    b.close_listener(listener).unwrap();
    assert_eq!(b.state(child).unwrap(), State::SynReceived);
}

#[test]
fn fast_open_explicit_capacities_bound_initial_data_before_publication() {
    for v6 in [false, true] {
        for send in [17, 2048] {
            let (mut a, mut b, listener) = warm(v6);
            let (local, remote) = addresses(v6, 40001);
            let (id, accepted) = a
                .connect_fast_open_with_buffer_capacities(100, local, remote, &[7; 4096], send, 257)
                .unwrap();
            assert_eq!(accepted, send.min(if v6 { 1180 } else { 496 }));
            assert_eq!(a.buffer_capacities(id).unwrap(), (send, 257));
            assert_eq!(a.transport_info(id).unwrap().send_used, accepted);
            if send == 17 {
                assert_eq!(
                    a.write(id, b"full"),
                    Err(EndpointError::Connection(Error::WouldBlock))
                );
            }
            let p = packet(&mut a, 100);
            let syn = wire::parse(p.0, &p.1).unwrap();
            assert_eq!(syn.header.window, 257);
            assert_eq!(syn.payload, &[7; 4096][..accepted]);
            assert!(syn.raw_options.len() + accepted <= if v6 { 1220 } else { 536 });
            deliver(&mut b, 110, &p);
            let child = b.accept(listener).unwrap();
            assert_eq!(b.readable_bytes(child).unwrap(), accepted);
        }
    }
}

#[test]
fn fast_open_explicit_capacity_admission_failure_preserves_tuple_and_budget() {
    for (send, receive, error) in [
        (0, 257, EndpointError::Connection(Error::InvalidArgument)),
        (31, 0, EndpointError::Connection(Error::InvalidArgument)),
        (
            1 << 30,
            257,
            EndpointError::Connection(Error::InvalidArgument),
        ),
        (
            31,
            (65535 << 14) + 1,
            EndpointError::Connection(Error::InvalidArgument),
        ),
        (1 << 29, 257, EndpointError::LimitReached),
    ] {
        let (mut a, _, _) = warm(false);
        let (local, remote) = addresses(false, 40001);
        let before = a.buffer_bytes();
        assert_eq!(
            a.connect_fast_open_with_buffer_capacities(
                100, local, remote, &[7; 128], send, receive,
            ),
            Err(error)
        );
        assert_eq!(a.buffer_bytes(), before);
        assert!(
            a.poll_transmit(100, &mut [0; 2048], 64)
                .unwrap()
                .packet
                .is_none()
        );
        let (id, accepted) = a
            .connect_fast_open_with_buffer_capacities(100, local, remote, &[7; 128], 31, 257)
            .unwrap();
        assert_eq!(accepted, 31);
        assert_eq!(a.buffer_capacities(id).unwrap(), (31, 257));
    }
}

#[test]
fn fast_open_explicit_capacity_allocation_rollback_preserves_receive_pool() {
    use crate::allocation_tests::fail_after;
    let (local, remote) = addresses(false, 40001);
    for preallocate in [0, 1] {
        let mut completed = false;
        for failure in 0..32 {
            let mut cfg = EndpointConfig::default();
            cfg.connection.send_capacity = 64;
            cfg.connection.receive_capacity = 257;
            cfg.connection.mss = 536;
            cfg.preallocate_connections = preallocate;
            // Preserve the exact connection allowance, plus the optional cache.
            cfg.max_buffer_bytes = crate::connection::Connection::allocation_bytes(64, 257, 536)
                .unwrap()
                + crate::fast_open::FastOpen::allocation_bytes();
            let mut a = Endpoint::new(cfg, [1; 32], 0, |_| true).unwrap();
            a.enable_fast_open().unwrap();
            let before = a.buffer_bytes();
            let result = fail_after(failure, || {
                a.connect_fast_open_with_buffer_capacities(0, local, remote, b"cache miss", 31, 257)
            });
            if let Ok((id, accepted)) = result {
                assert_eq!(accepted, 0);
                assert_eq!(a.buffer_capacities(id).unwrap(), (31, 257));
                completed = true;
                break;
            }
            assert_eq!(result, Err(EndpointError::Connection(Error::NoMemory)));
            assert_eq!(a.buffer_bytes(), before);
            assert!(
                a.poll_transmit(0, &mut [0; 2048], 64)
                    .unwrap()
                    .packet
                    .is_none()
            );
            let (id, accepted) = a
                .connect_fast_open_with_buffer_capacities(
                    0,
                    local,
                    remote,
                    b"cache miss retry",
                    31,
                    257,
                )
                .unwrap();
            assert_eq!(accepted, 0);
            assert_eq!(a.buffer_capacities(id).unwrap(), (31, 257));
        }
        assert!(completed);
    }
    // Cached-cookie setup also rolls back before accepting/publishing payload.
    let mut completed = false;
    for failure in 0..32 {
        let (mut a, _, _) = warm(false);
        let before = a.buffer_bytes();
        let result = fail_after(failure, || {
            a.connect_fast_open_with_buffer_capacities(100, local, remote, &[7; 128], 31, 257)
        });
        if let Ok((id, accepted)) = result {
            assert_eq!(accepted, 31);
            assert_eq!(a.buffer_capacities(id).unwrap(), (31, 257));
            completed = true;
            break;
        }
        assert_eq!(a.buffer_bytes(), before);
        assert!(
            a.poll_transmit(100, &mut [0; 2048], 64)
                .unwrap()
                .packet
                .is_none()
        );
        let (_, accepted) = a
            .connect_fast_open_with_buffer_capacities(100, local, remote, &[7; 128], 31, 257)
            .unwrap();
        assert_eq!(accepted, 31);
    }
    assert!(completed);
}

#[test]
fn fast_open_cache_enable_budget_exact_fit_and_idempotence() {
    use crate::fast_open::FastOpen;
    let charge = FastOpen::allocation_bytes();
    assert_eq!(
        charge,
        64 * (core::mem::size_of::<crate::fast_open::CachedCookie>()
            + core::mem::size_of::<crate::fast_open::NegativeService>())
    );
    let (local, remote) = addresses(false, 40001);
    for budget in [0, charge - 1, charge] {
        let cfg = EndpointConfig {
            max_buffer_bytes: budget,
            ..EndpointConfig::default()
        };
        let mut a = Endpoint::new(cfg, [1; 32], 0, |_| true).unwrap();
        if budget < charge {
            assert_eq!(
                a.enable_fast_open(),
                Err(EndpointError::Connection(Error::NoMemory))
            );
            assert_eq!(a.buffer_bytes(), 0);
            assert_eq!(
                a.connect_fast_open(0, local, remote, b"disabled"),
                Err(EndpointError::Connection(Error::InvalidState))
            );
        } else {
            a.enable_fast_open().unwrap();
            assert_eq!(a.buffer_bytes(), charge);
            // A repeated enable neither allocates nor charges again.
            crate::allocation_tests::fail_after(0, || a.enable_fast_open()).unwrap();
            assert_eq!(a.buffer_bytes(), charge);
            assert_eq!(
                a.connect(0, local, remote),
                Err(EndpointError::LimitReached)
            );
        }
        assert!(
            a.poll_transmit(0, &mut [0; 2048], 64)
                .unwrap()
                .packet
                .is_none()
        );
    }
}

#[test]
fn fast_open_cache_allocation_failure_does_not_publish_or_charge() {
    let charge = crate::fast_open::FastOpen::allocation_bytes();
    let cfg = EndpointConfig {
        max_buffer_bytes: charge,
        ..EndpointConfig::default()
    };
    let mut a = Endpoint::new(cfg, [1; 32], 0, |_| true).unwrap();
    let (local, remote) = addresses(false, 40001);
    for failure in 0..2 {
        assert_eq!(
            crate::allocation_tests::fail_after(failure, || a.enable_fast_open()),
            Err(EndpointError::Connection(Error::NoMemory))
        );
        assert_eq!(a.buffer_bytes(), 0);
        assert_eq!(
            a.connect_fast_open(0, local, remote, b"disabled"),
            Err(EndpointError::Connection(Error::InvalidState))
        );
    }
    a.enable_fast_open().unwrap();
    assert_eq!(a.buffer_bytes(), charge);
    assert!(
        a.poll_transmit(0, &mut [0; 2048], 64)
            .unwrap()
            .packet
            .is_none()
    );
}

#[test]
fn fast_open_cache_charge_constrains_subsequent_admission_with_pool_credit() {
    let cache = crate::fast_open::FastOpen::allocation_bytes();
    let connection = crate::connection::Connection::allocation_bytes(64, 257, 536).unwrap();
    let (local, remote) = addresses(false, 40001);
    for preallocate in [0, 1] {
        for budget in [connection + cache - 1, connection + cache] {
            let mut cfg = EndpointConfig::default();
            cfg.connection.send_capacity = 64;
            cfg.connection.receive_capacity = 257;
            cfg.connection.mss = 536;
            cfg.preallocate_connections = preallocate;
            cfg.max_buffer_bytes = budget;
            let mut a = Endpoint::new(cfg, [1; 32], 0, |_| true).unwrap();
            assert_eq!(a.buffer_bytes(), preallocate * connection);
            if preallocate == 1 && budget < connection + cache {
                assert_eq!(
                    a.enable_fast_open(),
                    Err(EndpointError::Connection(Error::NoMemory))
                );
                assert_eq!(a.buffer_bytes(), connection);
                // The failed optional reservation did not spend pooled credit.
                a.connect(0, local, remote).unwrap();
                assert_eq!(a.buffer_bytes(), connection);
                continue;
            }
            a.enable_fast_open().unwrap();
            assert_eq!(a.buffer_bytes(), preallocate * connection + cache);
            let result =
                a.connect_fast_open_with_buffer_capacities(0, local, remote, b"miss", 64, 257);
            if budget < connection + cache {
                assert_eq!(result, Err(EndpointError::LimitReached));
                assert_eq!(a.buffer_bytes(), cache);
                assert!(
                    a.poll_transmit(0, &mut [0; 2048], 64)
                        .unwrap()
                        .packet
                        .is_none()
                );
            } else {
                let (id, accepted) = result.unwrap();
                assert_eq!(accepted, 0);
                assert_eq!(a.buffer_capacities(id).unwrap(), (64, 257));
                assert_eq!(a.buffer_bytes(), connection + cache);
                let (other, _) = addresses(false, 40002);
                assert_eq!(
                    a.connect(0, other, remote),
                    Err(EndpointError::LimitReached)
                );
                assert_eq!(a.buffer_bytes(), connection + cache);
            }
        }
    }
}

fn rejected_syn_data_duplicate(quota: bool) {
    let (local, remote) = addresses(false, 40001);
    let mut b = endpoint(2, false);
    b.enable_fast_open().unwrap();
    let listener = b.listen(remote, 8).unwrap();
    b.set_listener_fast_open(listener, 1).unwrap();
    let cookie = if quota {
        crate::fast_open::issue(&[2; 32], remote.ip(), local.ip(), 0)
    } else {
        wire::FastOpenCookie::new(&[7; 8]).unwrap()
    };
    let mut options = [1; 12];
    options[..2].copy_from_slice(&[34, 10]);
    options[2..10].copy_from_slice(cookie.as_bytes());
    let ip = IpMetadata {
        source: local.ip(),
        destination: remote.ip(),
    };
    let header = wire::Header {
        source_port: local.port(),
        destination_port: remote.port(),
        sequence: 100,
        acknowledgment: 0,
        flags: wire::SYN,
        window: 8192,
        urgent_pointer: 0,
    };
    let mut bytes = [0; 2048];
    if quota {
        let holder = wire::Header {
            source_port: 39999,
            sequence: 50,
            ..header
        };
        let n = wire::encode(ip, holder, &options, b"hold", &mut bytes).unwrap();
        b.input(0, ip, &bytes[..n]).unwrap();
        let held = b.accept(listener).unwrap();
        assert_eq!(b.state(held).unwrap(), State::SynReceived);
        packet(&mut b, 0);
    }
    let n = wire::encode(ip, header, &options, b"abc", &mut bytes).unwrap();
    let syn = bytes[..n].to_vec();
    b.input(10, ip, &syn).unwrap();
    let first = b.poll_transmit(20, &mut bytes, 64).unwrap().packet.unwrap();
    let child = first.connection.unwrap();
    let response = wire::parse(first.ip, &bytes[..first.len]).unwrap();
    assert_eq!(response.header.acknowledgment, 101);
    let server_sequence = response.header.sequence;
    assert_eq!(b.readable_bytes(child).unwrap(), 0);
    b.input(30, ip, &syn).unwrap();
    assert_eq!(b.state(child).unwrap(), State::SynReceived);
    let second = b.poll_transmit(40, &mut bytes, 64).unwrap().packet.unwrap();
    assert_eq!(second.connection, Some(child));
    let response = wire::parse(second.ip, &bytes[..second.len]).unwrap();
    assert_eq!(
        response.header.flags & (wire::SYN | wire::ACK | wire::RST),
        wire::SYN | wire::ACK
    );
    assert_eq!(response.header.sequence, server_sequence);
    assert_eq!(response.header.acknowledgment, 101);
    assert_eq!(b.readable_bytes(child).unwrap(), 0);
    assert!(b.accept(listener).is_err());
    let ack = wire::Header {
        sequence: 101,
        acknowledgment: server_sequence.wrapping_add(1),
        flags: wire::ACK,
        ..header
    };
    let n = wire::encode(ip, ack, &[], b"abc", &mut bytes).unwrap();
    b.input(50, ip, &bytes[..n]).unwrap();
    assert_eq!(b.accept(listener).unwrap(), child);
    assert_eq!(b.state(child).unwrap(), State::Established);
    assert_eq!(b.read(child, &mut bytes).unwrap(), 3);
    assert_eq!(&bytes[..3], b"abc");
}

#[test]
fn fast_open_invalid_cookie_duplicate_syn_data_keeps_child() {
    rejected_syn_data_duplicate(false);
}

#[test]
fn fast_open_quota_rejected_duplicate_syn_data_keeps_child() {
    rejected_syn_data_duplicate(true);
}

fn early_terminal_child(
    payload: &[u8],
) -> (Endpoint, ListenerId, ConnectionId, IpMetadata, wire::Header) {
    let (local, remote) = addresses(false, 40001);
    let mut b = endpoint(2, false);
    b.enable_fast_open().unwrap();
    let listener = b.listen(remote, 8).unwrap();
    b.set_listener_fast_open(listener, 1).unwrap();
    let cookie = crate::fast_open::issue(&[2; 32], remote.ip(), local.ip(), 0);
    let mut options = [1; 12];
    options[..2].copy_from_slice(&[34, 10]);
    options[2..10].copy_from_slice(cookie.as_bytes());
    let ip = IpMetadata {
        source: local.ip(),
        destination: remote.ip(),
    };
    let header = wire::Header {
        source_port: local.port(),
        destination_port: remote.port(),
        sequence: 100,
        acknowledgment: 0,
        flags: wire::SYN,
        window: 8192,
        urgent_pointer: 0,
    };
    let mut bytes = [0; 128];
    let n = wire::encode(ip, header, &options, payload, &mut bytes).unwrap();
    b.input(0, ip, &bytes[..n]).unwrap();
    let child = b.accept(listener).unwrap();
    assert_eq!(b.state(child).unwrap(), State::SynReceived);
    (b, listener, child, ip, header)
}

#[test]
fn fast_open_early_terminal_reset_event_and_quota() {
    for flags in [wire::RST, wire::SYN] {
        let (mut b, listener, child, ip, header) = early_terminal_child(b"hello");
        let mut bytes = [0; 128];
        assert_eq!(b.read(child, &mut bytes).unwrap(), 5);
        assert_eq!(&bytes[..5], b"hello");
        while b.next_event().is_some() {}
        let response = packet(&mut b, 10);
        assert_eq!(
            wire::parse(response.0, &response.1)
                .unwrap()
                .header
                .acknowledgment,
            106
        );
        // An in-window, nonexact RST still challenges instead of terminating.
        let n = wire::encode(
            ip,
            wire::Header {
                sequence: 107,
                flags: wire::RST,
                ..header
            },
            &[],
            &[],
            &mut bytes,
        )
        .unwrap();
        b.input(20, ip, &bytes[..n]).unwrap();
        assert_eq!(b.state(child).unwrap(), State::SynReceived);
        assert!(b.next_event().is_none());
        let challenge = packet(&mut b, 20);
        assert_eq!(
            wire::parse(challenge.0, &challenge.1).unwrap().header.flags,
            wire::ACK
        );
        let n = wire::encode(
            ip,
            wire::Header {
                sequence: 106,
                flags,
                ..header
            },
            &[],
            &[],
            &mut bytes,
        )
        .unwrap();
        b.input(30, ip, &bytes[..n]).unwrap();
        assert_eq!(b.state(child).unwrap(), State::Closed);
        assert!(
            matches!(b.next_event(), Some(Event::Connection(id, events)) if id == child && events.closed == Some(CloseReason::Reset))
        );
        assert!(b.next_event().is_none());
        // Only a validated remote RST retains quota as cooldown debt.
        let cookie = crate::fast_open::issue(&[2; 32], ip.destination, ip.source, 0);
        let mut options = [1; 12];
        options[..2].copy_from_slice(&[34, 10]);
        options[2..10].copy_from_slice(cookie.as_bytes());
        let n = wire::encode(
            ip,
            wire::Header {
                source_port: 40002,
                ..header
            },
            &options,
            b"next",
            &mut bytes,
        )
        .unwrap();
        b.input(40, ip, &bytes[..n]).unwrap();
        if flags == wire::RST {
            assert!(b.accept(listener).is_err());
            let fallback = packet(&mut b, 40);
            assert_eq!(
                wire::parse(fallback.0, &fallback.1)
                    .unwrap()
                    .header
                    .acknowledgment,
                101
            );
            // A new tuple can deliver early data again at the cooldown boundary.
            bytes[0..2].copy_from_slice(&40003u16.to_be_bytes());
            repair_cache_checksum(ip, &mut bytes[..n]);
            b.input(60_000_030, ip, &bytes[..n]).unwrap();
        }
        let next = b.accept(listener).unwrap();
        assert_ne!(next, child);
        assert_eq!(b.read(next, &mut bytes).unwrap(), 4);
    }
}

#[test]
fn fast_open_early_terminal_drains_authenticated_prefix_after_reset_and_timeout() {
    for timeout in [true, false] {
        let (mut b, _, child, ip, header) = early_terminal_child(b"abc");
        let mut bytes = [0; 128];
        assert_eq!(b.read(child, &mut bytes[..1]).unwrap(), 1);
        assert_eq!(bytes[0], b'a');
        packet(&mut b, 10);
        while b.next_event().is_some() {}
        let reason = if timeout {
            b.on_timeout(400_000_000, 64).unwrap();
            CloseReason::TimedOut
        } else {
            let n = wire::encode(
                ip,
                wire::Header {
                    sequence: 104,
                    flags: wire::RST,
                    ..header
                },
                &[],
                &[],
                &mut bytes,
            )
            .unwrap();
            b.input(20, ip, &bytes[..n]).unwrap();
            CloseReason::Reset
        };
        assert_eq!(b.state(child).unwrap(), State::Closed);
        assert_eq!(
            b.read(child, &mut bytes),
            Err(EndpointError::Connection(Error::InvalidState))
        );
        assert_eq!(b.terminal_readable_bytes(child).unwrap(), 2);
        for _ in 0..2 {
            assert_eq!(b.peek_terminal(child, &mut bytes).unwrap(), 2);
            assert_eq!(&bytes[..2], b"bc");
        }
        assert_eq!(b.read_terminal(child, &mut bytes[..1]).unwrap(), 1);
        assert_eq!(bytes[0], b'b');
        assert_eq!(b.read_terminal(child, &mut bytes).unwrap(), 1);
        assert_eq!(bytes[0], b'c');
        assert_eq!(b.read_terminal(child, &mut bytes).unwrap(), 0);
        assert!(
            matches!(b.next_event(), Some(Event::Connection(id, events)) if id == child && events.closed == Some(reason))
        );
        assert!(
            b.poll_transmit(if timeout { 400_000_000 } else { 30 }, &mut bytes, 64)
                .unwrap()
                .packet
                .is_none()
        );
    }
}

#[test]
fn fast_open_early_terminal_read_close_discards_data_and_preserves_abort() {
    let (mut b, _, child, _, _) = early_terminal_child(b"abc");
    packet(&mut b, 10);
    while b.next_event().is_some() {}
    b.close(child).unwrap();
    assert_eq!(b.state(child).unwrap(), State::Closed);
    assert_eq!(b.terminal_readable_bytes(child).unwrap(), 0);
    assert_eq!(b.peek_terminal(child, &mut [0; 3]).unwrap(), 0);
    assert_eq!(b.read_terminal(child, &mut [0; 3]).unwrap(), 0);
    assert!(
        matches!(b.next_event(), Some(Event::Connection(id, events)) if id == child && events.closed == Some(CloseReason::Aborted))
    );
    let reset = packet(&mut b, 20);
    let reset = wire::parse(reset.0, &reset.1).unwrap();
    assert_eq!(
        reset.header.flags & (wire::RST | wire::ACK),
        wire::RST | wire::ACK
    );
    assert_eq!(reset.header.acknowledgment, 104);
}

#[test]
fn fast_open_syn_push_is_explicit_for_both_families_and_output_paths() {
    for v6 in [false, true] {
        for reserved in [false, true] {
            // No mark, explicit PUSH, PUSH+EOR, EOR alone, explicit SEND PUSH.
            for mark in 0..5 {
                let (mut a, _, _) = warm(v6);
                let (local, remote) = addresses(v6, 40001);
                let (id, n) = a.connect_fast_open(100, local, remote, b"hello").unwrap();
                assert_eq!(n, 5);
                match mark {
                    1..=3 => a.finish_send(id, 5, mark == 3, mark != 1, false).unwrap(),
                    4 => assert_eq!(a.write_with_push(id, b"", true).unwrap(), 0),
                    _ => {}
                }
                let (ip, bytes) = if reserved {
                    a.enable_output_reservations().unwrap();
                    let mut bytes = [0; 2048];
                    let (output, attempt) = a
                        .poll_reserved_transmit_for(100, id, &mut bytes, 16)
                        .unwrap();
                    let tx = output.packet.unwrap();
                    assert!(a.accept_transmit(110, attempt.unwrap()).unwrap());
                    (tx.ip, bytes[..tx.len].to_vec())
                } else {
                    packet(&mut a, 100)
                };
                let syn = wire::parse(ip, &bytes).unwrap();
                assert_ne!(syn.header.flags & wire::SYN, 0);
                assert_eq!(syn.payload, b"hello");
                assert_eq!(syn.header.flags & wire::PSH != 0, matches!(mark, 1 | 2 | 4));
            }
        }
    }
}

// Build ingress bytes directly: the output encoder rightly rejects invalid FO lengths.
fn cache_reply(
    syn: &(IpMetadata, Vec<u8>),
    mss: u16,
    cookie: Option<&[u8]>,
) -> (IpMetadata, Vec<u8>) {
    let sent = wire::parse(syn.0, &syn.1).unwrap();
    let ip = IpMetadata {
        source: syn.0.destination,
        destination: syn.0.source,
    };
    let mut options = vec![2, 4, (mss >> 8) as u8, mss as u8];
    if let Some(cookie) = cookie {
        options.extend_from_slice(&[34, (cookie.len() + 2) as u8]);
        options.extend_from_slice(cookie);
    }
    let mut bytes = vec![0; 64];
    let len = wire::encode(
        ip,
        wire::Header {
            source_port: sent.header.destination_port,
            destination_port: sent.header.source_port,
            sequence: 123,
            acknowledgment: sent
                .header
                .sequence
                .wrapping_add(1 + sent.payload.len() as u32),
            flags: wire::SYN | wire::ACK,
            window: 8192,
            urgent_pointer: 0,
        },
        &vec![1; options.len()],
        &[],
        &mut bytes,
    )
    .unwrap();
    bytes.truncate(len);
    bytes[20..20 + options.len()].copy_from_slice(&options);
    repair_cache_checksum(ip, &mut bytes);
    (ip, bytes)
}

fn repair_cache_checksum(ip: IpMetadata, bytes: &mut [u8]) {
    bytes[16..18].fill(0);
    let sum = wire::checksum(ip, bytes).unwrap();
    bytes[16..18].copy_from_slice(&sum.to_be_bytes());
}

#[test]
fn fast_open_validated_mss_without_cookie_replacement() {
    for v6 in [false, true] {
        for explicit in [false, true] {
            for cookie in [
                Some(&[0x11, 0x22][..]),
                None,
                Some(&[][..]),
                Some(&[1; 3][..]),
                Some(&[1; 18][..]),
                Some(&[2; 16][..]),
            ] {
                let mut cfg = EndpointConfig::default();
                cfg.connection.mss = 1460;
                let mut a = Endpoint::new(cfg, [1; 32], 0, |_| true).unwrap();
                a.enable_fast_open().unwrap();
                let mut expected_cookie = wire::FastOpenCookie::new(&[0; 4]).unwrap();
                for (round, expected) in [(0, 0), (1, 1000), (2, 900)] {
                    let now = round * 10;
                    let (local, remote) = addresses(v6, 40000 + round as u16);
                    let (id, accepted) = if explicit {
                        a.connect_fast_open_with_buffer_capacities(
                            now, local, remote, &[7; 1000], 8192, 8192,
                        )
                    } else {
                        a.connect_fast_open(now, local, remote, &[7; 1000])
                    }
                    .unwrap();
                    assert_eq!(accepted, expected, "round {round}, cookie {cookie:?}");
                    assert_eq!(a.transport_info(id).unwrap().send_used, expected);
                    let syn = packet(&mut a, now);
                    let parsed = wire::parse(syn.0, &syn.1).unwrap();
                    assert_eq!(parsed.payload, &[7; 1000][..expected]);
                    if round != 0 {
                        assert_eq!(parsed.options.fast_open, Some(expected_cookie));
                    }
                    let response = cache_reply(
                        &syn,
                        if round == 1 { 940 } else { 1460 },
                        if round == 1 { cookie } else { Some(&[0; 4]) },
                    );
                    if round == 1 {
                        assert_eq!(
                            wire::parse(response.0, &response.1)
                                .unwrap()
                                .options
                                .fast_open,
                            cookie.and_then(|c| wire::FastOpenCookie::new(c).ok())
                        );
                        if let Some(c) = cookie
                            .and_then(|c| wire::FastOpenCookie::new(c).ok())
                            .filter(|c| !c.as_bytes().is_empty())
                        {
                            expected_cookie = c;
                        }
                    }
                    deliver(&mut a, now + 1, &response);
                    assert_eq!(a.transport_info(id).unwrap().send_used, 0);
                    let ack = packet(&mut a, now + 1);
                    assert!(wire::parse(ack.0, &ack.1).unwrap().payload.is_empty());
                    assert!(
                        a.poll_transmit(now + 1, &mut [0; 2048], 64)
                            .unwrap()
                            .packet
                            .is_none()
                    );
                }
            }
        }
    }
}

#[test]
fn fast_open_cache_learning_requires_valid_synack() {
    for mode in 0..4 {
        let mut cfg = EndpointConfig::default();
        cfg.connection.mss = 1460;
        let mut a = Endpoint::new(cfg, [1; 32], 0, |_| true).unwrap();
        a.enable_fast_open().unwrap();
        let (local, remote) = addresses(false, 40000);
        a.connect_fast_open(0, local, remote, &[]).unwrap();
        let syn = packet(&mut a, 0);
        deliver(&mut a, 1, &cache_reply(&syn, 1460, Some(&[0; 4])));
        packet(&mut a, 1);
        let (local, _) = addresses(false, 40001);
        let (id, n) = a.connect_fast_open(2, local, remote, &[7; 1000]).unwrap();
        assert_eq!(n, 1000);
        let syn = packet(&mut a, 2);
        let mut reply = cache_reply(&syn, 940, Some(&[2; 8]));
        match mode {
            0 => {
                // ACK beyond everything actually sent.
                let ack = wire::parse(reply.0, &reply.1)
                    .unwrap()
                    .header
                    .acknowledgment;
                reply.1[8..12].copy_from_slice(&ack.wrapping_add(1).to_be_bytes());
            }
            1 => reply.1[13] = wire::ACK, // Valid ACK, but not a SYN-ACK.
            2 => reply.1[13] = wire::SYN, // No validated ACK.
            _ => {
                // Established non-SYN must not learn either cookie or MSS.
                deliver(&mut a, 3, &cache_reply(&syn, 1460, None));
                packet(&mut a, 3);
                reply.1[13] = wire::ACK;
                reply.1[4..8].copy_from_slice(&124u32.to_be_bytes());
            }
        }
        repair_cache_checksum(reply.0, &mut reply.1);
        deliver(&mut a, 4, &reply);
        if mode == 0 || mode == 1 {
            assert_eq!(a.state(id).unwrap(), State::SynSent);
        }
        // Drain any reset, ACK or simultaneous-open response first.
        while a
            .poll_transmit(4, &mut [0; 2048], 64)
            .unwrap()
            .packet
            .is_some()
        {}
        let (local, _) = addresses(false, 40002);
        let (_, n) = a.connect_fast_open(5, local, remote, &[7; 1000]).unwrap();
        assert_eq!(n, 1000);
        let syn = packet(&mut a, 5);
        assert_eq!(
            wire::parse(syn.0, &syn.1).unwrap().options.fast_open,
            Some(wire::FastOpenCookie::new(&[0; 4]).unwrap())
        );
    }
}

#[test]
fn fast_open_mss_only_wire_learning_does_not_create_or_extend_credentials() {
    for units_per_second in [1_000_000, 1_000_000_000] {
        for warm_cache in [false, true] {
            for at_expiry in [false, true] {
                for cookie in [None, Some(&[1, 2][..]), Some(&[][..])] {
                    let mut cfg = EndpointConfig::default();
                    cfg.connection.timestamps = false;
                    cfg.connection.timebase.units_per_second = units_per_second;
                    let lifetime = cfg
                        .connection
                        .timebase
                        .ticks_from_us(crate::fast_open::LIFETIME_US);
                    let mut a = Endpoint::new(cfg, [1; 32], 0, |_| true).unwrap();
                    a.enable_fast_open().unwrap();
                    let (local, remote) = addresses(false, 40000);
                    if warm_cache {
                        a.connect_fast_open(0, local, remote, &[]).unwrap();
                        let syn = packet(&mut a, 0);
                        deliver(&mut a, 1, &cache_reply(&syn, 1460, Some(&[0; 4])));
                        packet(&mut a, 1);
                    }
                    let expiry = lifetime + 1;
                    let now = if at_expiry { expiry } else { expiry - 1 };
                    let (local, _) = addresses(false, 40001);
                    a.connect_fast_open(now - 1, local, remote, &[]).unwrap();
                    let syn = packet(&mut a, now - 1);
                    deliver(&mut a, now, &cache_reply(&syn, 940, cookie));
                    packet(&mut a, now);
                    assert_eq!(
                        a.has_fast_open_cookie(now, local.ip(), remote.ip())
                            .unwrap(),
                        warm_cache && !at_expiry
                    );
                    assert!(
                        !a.has_fast_open_cookie(expiry, local.ip(), remote.ip())
                            .unwrap()
                    );
                    let (local, _) = addresses(false, 40002);
                    let (id, accepted) = a
                        .connect_fast_open(expiry, local, remote, &[7; 1000])
                        .unwrap();
                    assert_eq!(accepted, 0);
                    assert_eq!(a.transport_info(id).unwrap().send_used, 0);
                    let syn = packet(&mut a, expiry);
                    let syn = wire::parse(syn.0, &syn.1).unwrap();
                    assert!(syn.payload.is_empty());
                    assert_eq!(syn.options.fast_open, Some(wire::FastOpenCookie::request()));
                }
            }
        }
    }
}

#[test]
fn fast_open_disabled_listener_recognized_options_only_fallback() {
    for v6 in [false, true] {
        for service in [false, true] {
            for sequence in [0, u32::MAX] {
                let (local, remote) = addresses(v6, 40000);
                let cookie = crate::fast_open::issue(&[2; 32], remote.ip(), local.ip(), 0);
                let mut valid = vec![34, 10];
                valid.extend_from_slice(cookie.as_bytes());
                valid.extend_from_slice(&[1, 1]);
                for (fo, recognized) in [
                    (valid.as_slice(), true),
                    (&[34, 2, 1, 1][..], true), // Cookie request is recognized too.
                    (&[][..], false),
                    (&[254, 4, 0xf9, 0x89][..], false), // FOEXP is not implemented.
                    (&[34, 3, 0, 1][..], false),        // Bounded invalid option.
                    (&[34, 2, 34, 2][..], false),       // Duplicate option ignored by wire.
                ] {
                    let config = EndpointConfig {
                        max_connections: 16,
                        max_listeners: 2,
                        connection: ConnectionConfig {
                            sack: true,
                            timestamps: true,
                            ..ConnectionConfig::default()
                        },
                        ..EndpointConfig::default()
                    };
                    let mut b = Endpoint::new(config, [2; 32], 0, |_| true).unwrap();
                    let listener = b.listen(remote, 8).unwrap();
                    if service {
                        b.enable_fast_open().unwrap(); // Limit remains zero.
                    }
                    let ip = IpMetadata {
                        source: local.ip(),
                        destination: remote.ip(),
                    };
                    // Keep ordinary SYN-data controls out of this policy regression.
                    let controls = if recognized {
                        wire::FIN | wire::PSH | wire::URG
                    } else {
                        0
                    };
                    let header = wire::Header {
                        source_port: local.port(),
                        destination_port: remote.port(),
                        sequence,
                        acknowledgment: 0,
                        flags: wire::SYN | controls,
                        window: 8192,
                        urgent_pointer: if recognized { 3 } else { 0 },
                    };
                    let mut options = vec![
                        2, 4, 2, 24, 3, 3, 2, 1, 4, 2, 1, 1, 8, 10, 0, 0, 0, 7, 0, 0, 0, 0, 1, 1,
                    ];
                    // Encode padding first: output rightly rejects malformed/duplicate TFO.
                    let fo_start = 20 + options.len();
                    options.resize(options.len() + fo.len(), 1);
                    let mut bytes = [0; 2048];
                    let n = wire::encode(ip, header, &options, b"abc", &mut bytes).unwrap();
                    bytes[fo_start..fo_start + fo.len()].copy_from_slice(fo);
                    bytes[16..18].fill(0);
                    let checksum = wire::checksum(ip, &bytes[..n]).unwrap();
                    bytes[16..18].copy_from_slice(&checksum.to_be_bytes());
                    assert_eq!(
                        wire::parse(ip, &bytes[..n])
                            .unwrap()
                            .options
                            .fast_open
                            .is_some(),
                        recognized
                    );
                    b.input(0, ip, &bytes[..n]).unwrap();
                    assert!(b.accept(listener).is_err());
                    let tx = b.poll_transmit(10, &mut bytes, 64).unwrap().packet.unwrap();
                    let child = tx.connection.unwrap();
                    let reply = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
                    let next = sequence.wrapping_add(1);
                    assert_eq!(reply.header.acknowledgment, next);
                    assert!(reply.options.fast_open.is_none()); // Disabled listeners issue no cookies.
                    assert!(reply.options.sack_permitted);
                    assert!(reply.options.window_scale.is_some());
                    let (ts, echo) = reply.options.timestamps.unwrap();
                    assert_eq!(echo, 7);
                    assert_eq!(b.read(child, &mut [0; 8]), Err(Error::WouldBlock.into()));
                    assert_eq!(b.readable_bytes(child).unwrap(), 0);
                    assert_eq!(b.urgent_remaining(child).unwrap(), 0);
                    let ack = wire::Header {
                        sequence: next,
                        acknowledgment: reply.header.sequence.wrapping_add(1),
                        flags: wire::ACK,
                        urgent_pointer: 0,
                        ..header
                    };
                    let mut timestamps = [1, 1, 8, 10, 0, 0, 0, 8, 0, 0, 0, 0];
                    timestamps[8..].copy_from_slice(&ts.to_be_bytes());
                    let n = wire::encode(ip, ack, &timestamps, &[], &mut bytes).unwrap();
                    b.input(20, ip, &bytes[..n]).unwrap();
                    assert_eq!(b.accept(listener).unwrap(), child);
                    assert_eq!(b.state(child).unwrap(), State::Established); // No rejected FIN.
                    if recognized {
                        assert_eq!(b.read(child, &mut bytes), Err(Error::WouldBlock.into()));
                        let n = wire::encode(ip, ack, &timestamps, b"abc", &mut bytes).unwrap();
                        let retry = bytes[..n].to_vec();
                        b.input(30, ip, &retry).unwrap();
                        assert_eq!(b.read(child, &mut bytes), Ok(3));
                        assert_eq!(&bytes[..3], b"abc");
                        b.input(40, ip, &retry).unwrap();
                        assert_eq!(b.read(child, &mut bytes), Err(Error::WouldBlock.into()));
                    } else {
                        assert_eq!(b.read(child, &mut bytes), Ok(3));
                        assert_eq!(&bytes[..3], b"abc");
                    }
                }
            }
        }
    }
}

#[test]
fn ordinary_and_foexp_syn_text_ack_only_syn_then_deliver_once() {
    for v6 in [false, true] {
        for reserved in [false, true] {
            for options in [&[][..], &[254, 4, 0xf9, 0x89][..]] {
                for retransmit in [false, true] {
                    let (local, remote) = addresses(v6, 40000);
                    let mut endpoint =
                        Endpoint::new(EndpointConfig::default(), [2; 32], 0, |_| true).unwrap();
                    if reserved {
                        endpoint.enable_output_reservations().unwrap();
                    }
                    let listener = endpoint.listen(remote, 4).unwrap();
                    let ip = IpMetadata {
                        source: local.ip(),
                        destination: remote.ip(),
                    };
                    let header = wire::Header {
                        source_port: local.port(),
                        destination_port: remote.port(),
                        sequence: 0,
                        acknowledgment: 0,
                        flags: wire::SYN,
                        window: 8192,
                        urgent_pointer: 0,
                    };
                    let mut bytes = [0; 2048];
                    let n = wire::encode(ip, header, options, b"0123456789", &mut bytes).unwrap();
                    endpoint.input(0, ip, &bytes[..n]).unwrap();
                    assert!(endpoint.accept(listener).is_err());
                    let tx = if reserved {
                        let (output, attempt) =
                            endpoint.poll_reserved_transmit(1, &mut bytes, 64).unwrap();
                        let tx = output.packet.unwrap();
                        let original = bytes[..tx.len].to_vec();
                        let attempt = attempt.unwrap();
                        assert_eq!(
                            wire::parse(tx.ip, &original).unwrap().header.acknowledgment,
                            1
                        );
                        assert!(endpoint.reject_unsubmitted(attempt).unwrap());
                        let (output, retry) =
                            endpoint.poll_reserved_transmit(1, &mut bytes, 64).unwrap();
                        let retry_tx = output.packet.unwrap();
                        assert_eq!(&bytes[..retry_tx.len], original.as_slice());
                        assert!(endpoint.accept_transmit(1, retry.unwrap()).unwrap());
                        retry_tx
                    } else {
                        endpoint
                            .poll_transmit(1, &mut bytes, 64)
                            .unwrap()
                            .packet
                            .unwrap()
                    };
                    let child = tx.connection.unwrap();
                    let reply = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
                    assert_eq!(reply.header.acknowledgment, 1); // Both original ordinary server fixtures.
                    assert!(reply.options.fast_open.is_none()); // FOEXP is not receive authorization.
                    assert_eq!(endpoint.readable_bytes(child).unwrap(), 0);
                    let ack = wire::Header {
                        sequence: 1,
                        acknowledgment: reply.header.sequence.wrapping_add(1),
                        flags: wire::ACK,
                        ..header
                    };
                    let n = wire::encode(
                        ip,
                        ack,
                        &[],
                        if retransmit { b"XXXXXXXXXX" } else { b"" },
                        &mut bytes,
                    )
                    .unwrap();
                    let final_ack = bytes[..n].to_vec();
                    endpoint.input(2, ip, &final_ack).unwrap();
                    assert_eq!(endpoint.accept(listener).unwrap(), child);
                    endpoint.input(3, ip, &final_ack).unwrap();
                    assert_eq!(endpoint.read(child, &mut bytes), Ok(10));
                    assert_eq!(&bytes[..10], b"0123456789");
                    assert_eq!(
                        endpoint.read(child, &mut bytes),
                        Err(Error::WouldBlock.into())
                    );
                }
            }
        }
    }
}

mod cookie_timeout_study {
    include!("fast_open_cookie_timeout_tests.rs");
}

mod partial_synack_study {
    include!("fast_open_partial_synack_tests.rs");
}

#[test]
fn fast_open_negative_synack_suppresses_next_service_attempt() {
    let (mut a, _, _) = warm(false);
    let (local, remote) = addresses(false, 40001);
    a.connect_fast_open(100, local, remote, b"hello").unwrap();
    let syn = packet(&mut a, 100);
    let mut response = cache_reply(&syn, 536, Some(&[9; 8]));
    let seq = wire::parse(syn.0, &syn.1).unwrap().header.sequence;
    response.1[8..12].copy_from_slice(&seq.wrapping_add(1).to_be_bytes());
    repair_cache_checksum(response.0, &mut response.1);
    deliver(&mut a, 110, &response);
    packet(&mut a, 110);
    assert!(
        a.has_fast_open_cookie(110, local.ip(), remote.ip())
            .unwrap()
    );
    let (local, _) = addresses(false, 40002);
    let (_, accepted) = a.connect_fast_open(120, local, remote, b"retry").unwrap();
    assert_eq!(accepted, 0);
    let syn = packet(&mut a, 120);
    let syn = wire::parse(syn.0, &syn.1).unwrap();
    assert!(syn.options.fast_open.is_none());
    assert!(syn.payload.is_empty());
}

#[test]
fn fast_open_negative_endpoint_clock_expiry_and_repeated_errors() {
    for units in [1_000_000, 1_000_000_000] {
        for v6 in [false, true] {
            let mut cfg = EndpointConfig::default();
            cfg.connection.timebase.units_per_second = units;
            let cooldown = cfg
                .connection
                .timebase
                .ticks_from_us(crate::fast_open::NEGATIVE_LIFETIME_US);
            let mut a = Endpoint::new(cfg, [1; 32], 0, |_| true).unwrap();
            a.enable_fast_open().unwrap();
            let (local, remote) = addresses(v6, 40000);
            a.connect_fast_open(0, local, remote, &[]).unwrap();
            let syn = packet(&mut a, 0);
            deliver(&mut a, 1, &cache_reply(&syn, 536, Some(&[7; 8])));
            packet(&mut a, 1);
            let (local, _) = addresses(v6, 40001);
            let (id, _) = a.connect_fast_open(2, local, remote, b"hello").unwrap();
            let syn = packet(&mut a, 2);
            let seq = wire::parse(syn.0, &syn.1).unwrap().header.sequence;
            let tuple = Tuple { local, remote };
            assert!(
                !a.network_error(3, tuple, seq.wrapping_sub(1), NetworkError::SoftUnreachable)
                    .unwrap()
            );
            assert!(a.can_defer_fast_open(3, local.ip(), remote).unwrap());
            assert!(
                a.network_error(10, tuple, seq, NetworkError::SoftUnreachable)
                    .unwrap()
            );
            assert!(!a.can_defer_fast_open(10, local.ip(), remote).unwrap());
            assert!(
                a.network_error(20, tuple, seq, NetworkError::TimeExceeded)
                    .unwrap()
            );
            // Valid replacement learning must not remove the independent negative entry.
            deliver(&mut a, 30, &cache_reply(&syn, 940, Some(&[9; 8])));
            packet(&mut a, 30);
            assert!(a.has_fast_open_cookie(30, local.ip(), remote.ip()).unwrap());
            assert!(!a.can_defer_fast_open(30, local.ip(), remote).unwrap());
            let other_port = SocketAddr::new(remote.ip(), remote.port() + 1);
            assert!(a.can_defer_fast_open(30, local.ip(), other_port).unwrap());
            let (other_local, _) = addresses(v6, 40002);
            let (_, n) = a
                .connect_fast_open(31, other_local, other_port, b"hello")
                .unwrap();
            assert_eq!(n, 5);
            let other_syn = packet(&mut a, 31);
            assert!(
                wire::parse(other_syn.0, &other_syn.1)
                    .unwrap()
                    .options
                    .fast_open
                    .is_some()
            );
            // A suppressed attempt neither stores initial bytes nor refreshes cooldown.
            let (other_local, _) = addresses(v6, 40003);
            let (ordinary, n) = a
                .connect_fast_open(32, other_local, remote, b"hello")
                .unwrap();
            assert_eq!(n, 0);
            assert_eq!(a.transport_info(ordinary).unwrap().send_used, 0);
            let ordinary_syn = packet(&mut a, 32);
            let parsed = wire::parse(ordinary_syn.0, &ordinary_syn.1).unwrap();
            assert!(parsed.options.fast_open.is_none());
            assert!(
                a.network_error(
                    33,
                    Tuple {
                        local: other_local,
                        remote
                    },
                    parsed.header.sequence,
                    NetworkError::HardUnreachable
                )
                .unwrap()
            );
            a.release(ordinary).unwrap();
            assert_eq!(a.abort(ordinary), Err(EndpointError::InvalidHandle));
            assert!(
                !a.can_defer_fast_open(10 + cooldown - 1, local.ip(), remote)
                    .unwrap()
            );
            assert!(
                a.can_defer_fast_open(10 + cooldown, local.ip(), remote)
                    .unwrap()
            );
            let (local, _) = addresses(v6, 40004);
            let (_, n) = a
                .connect_fast_open(10 + cooldown, local, remote, b"again")
                .unwrap();
            assert_eq!(n, 5);
            let syn = packet(&mut a, 10 + cooldown);
            assert_eq!(
                wire::parse(syn.0, &syn.1).unwrap().options.fast_open,
                Some(wire::FastOpenCookie::new(&[9; 8]).unwrap())
            );
            assert!(a.can_defer_fast_open(9, local.ip(), remote).is_err());
            assert_eq!(a.state(id).unwrap(), State::Established);
        }
    }
}

#[test]
fn fast_open_negative_reserved_timeout_starts_at_acceptance() {
    let (mut a, _, _) = warm(false);
    a.enable_output_reservations().unwrap();
    let (local, remote) = addresses(false, 40001);
    let (id, _) = a.connect_fast_open(100, local, remote, b"hello").unwrap();
    let mut bytes = [0; 2048];
    let (_, attempt) = a
        .poll_reserved_transmit_for(100, id, &mut bytes, 16)
        .unwrap();
    let attempt = attempt.unwrap();
    assert!(a.reject_unsubmitted(attempt).unwrap());
    a.on_timeout(2_000_000, 64).unwrap();
    assert!(
        a.can_defer_fast_open(2_000_000, local.ip(), remote)
            .unwrap()
    );
    let (_, retry) = a
        .poll_reserved_transmit_for(2_000_000, id, &mut bytes, 16)
        .unwrap();
    assert!(!a.accept_transmit(3_000_000, attempt).unwrap());
    assert!(a.accept_transmit(3_000_000, retry.unwrap()).unwrap());
    let deadline = a.next_deadline().unwrap();
    a.on_timeout(deadline - 1, 64).unwrap();
    assert!(
        a.can_defer_fast_open(deadline - 1, local.ip(), remote)
            .unwrap()
    );
    a.on_timeout(deadline, 64).unwrap();
    assert!(!a.can_defer_fast_open(deadline, local.ip(), remote).unwrap());
    assert!(
        a.has_fast_open_cookie(deadline, local.ip(), remote.ip())
            .unwrap()
    );
}

#[test]
fn fast_open_negative_local_deadline_does_not_suppress_when_serviced_late() {
    for units in [1_000_000, 1_000_000_000] {
        for (application_us, service_us, suppressed) in [
            (100_000, 100_000, false),
            (100_000, 2_000_000, false),
            (1_500_000, 2_000_000, true),
        ] {
            let mut cfg = EndpointConfig::default();
            cfg.connection.timebase.units_per_second = units;
            let timebase = cfg.connection.timebase;
            let mut a = Endpoint::new(cfg, [1; 32], 0, |_| true).unwrap();
            a.enable_fast_open().unwrap();
            let (local, remote) = addresses(false, 40000);
            a.connect_fast_open(0, local, remote, &[]).unwrap();
            let syn = packet(&mut a, 0);
            deliver(&mut a, 1, &cache_reply(&syn, 536, Some(&[7; 8])));
            packet(&mut a, 1);
            let (local, _) = addresses(false, 40001);
            let (id, accepted) = a.connect_fast_open(2, local, remote, b"hello").unwrap();
            assert_eq!(accepted, 5);
            a.set_application_timeout(id, Some(application_us)).unwrap();
            packet(&mut a, 2);
            let now = 2 + timebase.ticks_from_us(service_us);
            a.on_timeout(now, 64).unwrap();
            assert_eq!(a.state(id).unwrap(), State::Closed);
            assert_eq!(
                a.can_defer_fast_open(now, local.ip(), remote).unwrap(),
                !suppressed
            );
            let (local, _) = addresses(false, 40002);
            let (_, accepted) = a.connect_fast_open(now, local, remote, b"retry").unwrap();
            assert_eq!(accepted, if suppressed { 0 } else { 5 });
        }
    }
}

#[test]
fn inventory_tfo_syn_only_rejection_keeps_cookie_but_suppresses_after_data_ack() {
    for v6 in [false, true] {
        let config = EndpointConfig {
            max_connections: 16,
            connection: ConnectionConfig {
                mss: 1460,
                timestamps: false,
                send_capacity: 8192,
                receive_capacity: 8192,
                ..ConnectionConfig::default()
            },
            ..EndpointConfig::default()
        };
        let mut a = Endpoint::new(config, [1; 32], 0, |_| true).unwrap();
        a.enable_fast_open().unwrap();
        let (local, remote) = addresses(v6, 40000);
        a.connect_fast_open(0, local, remote, &[]).unwrap();
        let syn = packet(&mut a, 0);
        deliver(&mut a, 10_000, &cache_reply(&syn, 1460, Some(&[7; 8])));
        packet(&mut a, 10_000);
        let (local, _) = addresses(v6, 40001);
        let (id, accepted) = a
            .connect_fast_open(20_000, local, remote, &[42; 700])
            .unwrap();
        assert_eq!(accepted, 700);
        let syn = packet(&mut a, 20_000);
        let iss = wire::parse(syn.0, &syn.1).unwrap().header.sequence;
        let mut response = cache_reply(&syn, 1040, Some(&[8; 8]));
        response.1[8..12].copy_from_slice(&iss.wrapping_add(1).to_be_bytes());
        repair_cache_checksum(response.0, &mut response.1);
        deliver(&mut a, 40_000, &response);
        let retry = packet(&mut a, 40_000);
        let parsed = wire::parse(retry.0, &retry.1).unwrap();
        assert_eq!(parsed.header.sequence, iss.wrapping_add(1));
        assert_eq!(parsed.payload.len(), 700);
        let ip = IpMetadata {
            source: remote.ip(),
            destination: local.ip(),
        };
        let mut ack = [0; 64];
        let length = wire::encode(
            ip,
            wire::Header {
                source_port: remote.port(),
                destination_port: local.port(),
                sequence: 124,
                acknowledgment: iss.wrapping_add(701),
                flags: wire::ACK,
                window: 8192,
                urgent_pointer: 0,
            },
            &[],
            &[],
            &mut ack,
        )
        .unwrap();
        deliver(&mut a, 41_000, &(ip, ack[..length].to_vec()));
        assert_eq!(a.acknowledged(id).unwrap(), 700);
        assert!(
            a.has_fast_open_cookie(41_000, local.ip(), remote.ip())
                .unwrap()
        );
        assert!(!a.can_defer_fast_open(41_000, local.ip(), remote).unwrap());
        let (next, _) = addresses(v6, 40002);
        let (_, same_accepted) = a
            .connect_fast_open(42_000, next, remote, &[42; 5000])
            .unwrap();
        assert_eq!(same_accepted, 0);
        assert!(!a.can_defer_fast_open(42_000, local.ip(), remote).unwrap());
        let mut other = remote;
        other.set_port(remote.port() + 1);
        let (next, _) = addresses(v6, 40003);
        let (_, other_accepted) = a
            .connect_fast_open(43_000, next, other, &[42; 5000])
            .unwrap();
        assert_eq!(other_accepted, 1000);
        assert!(
            a.can_defer_fast_open(60_040_001, local.ip(), remote)
                .unwrap()
        );
        std::eprintln!(
            "TFO_INVENTORY {{\"probe\":\"syn_only_cache\",\"v6\":{v6},\"original_bytes\":700,\"repaired_bytes\":700,\"ordinary_data_acked\":700,\"cookie_retained\":true,\"next_same_service_accepted\":{same_accepted},\"other_service_accepted\":{other_accepted},\"eligible_after_60s\":true}}"
        );
    }
}

mod active_open_options {
    include!("fast_open_active_options_tests.rs");
}
