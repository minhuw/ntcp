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
    for enabled in [false, true] {
        let (local, remote) = addresses(false, 40000);
        let mut b = endpoint(2, false);
        let listener = b.listen(remote, 8).unwrap();
        assert!(b.set_listener_fast_open(listener, 1).is_err());
        assert!(b.connect_fast_open(0, remote, local, b"x").is_err());
        if enabled {
            b.enable_fast_open().unwrap();
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
        assert_eq!(
            synack.header.acknowledgment,
            if enabled { 101 } else { 104 }
        );
        assert_eq!(synack.options.fast_open.is_some(), enabled);
        let ack = wire::Header {
            sequence: if enabled { 101 } else { 104 },
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
        assert_eq!(
            b.readable_bytes(child).unwrap(),
            if enabled { 0 } else { 3 }
        );
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
