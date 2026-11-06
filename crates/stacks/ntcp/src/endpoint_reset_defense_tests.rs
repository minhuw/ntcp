use super::*;

fn endpoint(v6: bool, units: u64) -> (Endpoint, ListenerId, Tuple) {
    let mut config = EndpointConfig {
        max_connections: 16,
        max_listeners: 2,
        ..EndpointConfig::default()
    };
    config.connection.timebase.units_per_second = units;
    let mut e = Endpoint::new(config, [42; 32], 0, crate::SETTLED, |_| true).unwrap();
    e.enable_fast_open().unwrap();
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
    let listener = e.listen(tuple.local, 16).unwrap();
    e.set_listener_fast_open(listener, 1).unwrap();
    (e, listener, tuple)
}

fn input(
    e: &mut Endpoint,
    now: u64,
    tuple: Tuple,
    seq: u32,
    ack: u32,
    flags: u8,
    authenticated: bool,
) {
    let ip = IpMetadata {
        source: tuple.remote.ip(),
        destination: tuple.local.ip(),
    };
    let mut options = [1; 12];
    options[..2].copy_from_slice(&[34, 10]);
    options[2..10].copy_from_slice(
        crate::fast_open::issue(
            &[42; 32],
            tuple.local.ip(),
            tuple.remote.ip(),
            now / e.fast_open_lifetime(),
        )
        .as_bytes(),
    );
    let mut bytes = [0; 128];
    let len = wire::encode(
        ip,
        wire::Header {
            source_port: tuple.remote.port(),
            destination_port: tuple.local.port(),
            sequence: seq,
            acknowledgment: ack,
            flags,
            window: 8192,
            urgent_pointer: 0,
        },
        if authenticated { &options } else { &[] },
        if flags == wire::SYN { b"early" } else { b"" },
        &mut bytes,
    )
    .unwrap();
    e.input(now, ip, &bytes[..len]).unwrap();
}

fn syn(e: &mut Endpoint, now: u64, tuple: Tuple) -> ConnectionId {
    input(e, now, tuple, 100, 0, wire::SYN, true);
    let index = e
        .slots
        .iter()
        .position(|s| {
            s.as_ref().is_some_and(|s| {
                s.connection.tuple() == tuple && s.connection.state() != State::Closed
            })
        })
        .unwrap();
    e.id(index)
}

fn next_tuple(mut tuple: Tuple) -> Tuple {
    tuple.remote.set_port(tuple.remote.port() + 1);
    tuple
}

fn debt(e: &mut Endpoint, listener: ListenerId) -> usize {
    e.listeners[listener.slot]
        .as_mut()
        .unwrap()
        .reset_debt(e.now)
}

#[test]
fn recent_reset_fallback_boundary_and_terminal_ownership() {
    for v6 in [false, true] {
        for units in [1_000_000, 1_000_000_000] {
            for accept_first in [false, true] {
                let (mut e, listener, tuple) = endpoint(v6, units);
                let baseline = e.buffer_bytes();
                let child = syn(&mut e, 0, tuple);
                if accept_first {
                    assert_eq!(e.accept(listener).unwrap(), child);
                }
                input(&mut e, 10, tuple, 106, 0, wire::RST, false);
                assert_eq!(debt(&mut e, listener), 1);
                assert!(
                    e.slots[child.slot]
                        .as_ref()
                        .unwrap()
                        .fast_open_owner
                        .is_none()
                );
                // Duplicate remote input and repeated refresh cannot add debt.
                input(&mut e, 11, tuple, 106, 0, wire::RST, false);
                e.refresh(child.slot);
                assert_eq!(debt(&mut e, listener), 1);
                if !accept_first {
                    assert_eq!(e.accept(listener).unwrap(), child);
                }
                let mut bytes = [0; 8];
                assert_eq!(e.read_terminal(child, &mut bytes).unwrap(), 5);
                assert_eq!(&bytes[..5], b"early");
                assert_eq!(e.read(child, &mut bytes), Err(Error::InvalidState.into()));
                e.release(child).unwrap();
                let expiry = 10 + 60 * units;
                for (now, port) in [(12, 40001), (expiry - 1, 40002), (expiry, 40003)] {
                    e.set_listener_fast_open(listener, 0).unwrap();
                    e.set_listener_fast_open(listener, 2).unwrap();
                    e.set_listener_fast_open(listener, 1).unwrap();
                    let mut tuple = tuple;
                    tuple.remote.set_port(port);
                    let id = syn(&mut e, now, tuple);
                    assert_eq!(
                        e.slots[id.slot]
                            .as_ref()
                            .unwrap()
                            .connection
                            .fast_open_early,
                        now == expiry
                    );
                    if now < expiry {
                        assert!(e.accept(listener).is_err());
                        assert_eq!(e.readable_bytes(id).unwrap(), 0);
                    } else {
                        assert_eq!(e.accept(listener).unwrap(), id);
                        assert_eq!(e.readable_bytes(id).unwrap(), 5);
                    }
                }
                assert_eq!(debt(&mut e, listener), 0);
                assert!(e.buffer_bytes() >= baseline);
                assert!(e.buffer_bytes() <= e.config.max_buffer_bytes);
            }
        }
    }
}

#[test]
fn only_valid_pending_remote_reset_charges_and_success_preserves_prior_debt() {
    for cause in 0..5 {
        let (mut e, listener, tuple) = endpoint(false, 1_000_000);
        e.set_listener_fast_open(listener, 2).unwrap();
        let first = syn(&mut e, 0, tuple);
        input(&mut e, 1, tuple, 106, 0, wire::RST, false);
        assert_eq!(debt(&mut e, listener), 1);
        let other = next_tuple(tuple);
        let second = if cause == 4 {
            input(&mut e, 2, other, 100, 0, wire::SYN, false);
            e.id(e
                .slots
                .iter()
                .position(|s| s.as_ref().is_some_and(|s| s.connection.tuple() == other))
                .unwrap())
        } else {
            syn(&mut e, 2, other)
        };
        match cause {
            0 => {
                input(&mut e, 3, other, 107, 0, wire::RST, false); // challenge
                input(&mut e, 4, other, 999_999, 0, wire::RST, false); // out of window
                assert_eq!(e.state(second).unwrap(), State::SynReceived);
                e.abort(second).unwrap();
            }
            1 => {
                e.abort(second).unwrap();
            }
            2 => {
                e.close(second).unwrap();
                e.abort(second).unwrap();
                e.release(second).unwrap();
            }
            3 => {
                // Physically emit SYNACK before accepting the final ACK.
                let mut ack = None;
                for _ in 0..8 {
                    let mut bytes = [0; 2048];
                    if let Some(tx) = e.poll_transmit(2, &mut bytes, 16).unwrap().packet
                        && tx.connection == Some(second)
                    {
                        ack = Some(
                            wire::parse(tx.ip, &bytes[..tx.len])
                                .unwrap()
                                .header
                                .sequence
                                .wrapping_add(1),
                        );
                    }
                }
                let ack = ack.unwrap();
                input(&mut e, 3, other, 106, ack, wire::ACK, false);
                assert_eq!(e.state(second).unwrap(), State::Established);
                input(&mut e, 4, other, 106, 0, wire::RST, false);
            }
            _ => {
                input(&mut e, 3, other, 101, 0, wire::RST, false);
            }
        }
        assert_eq!(debt(&mut e, listener), 1);
        assert!(
            e.slots[first.slot]
                .as_ref()
                .unwrap()
                .fast_open_owner
                .is_none()
        );
        let third = syn(&mut e, 5, next_tuple(other));
        assert!(
            e.slots[third.slot]
                .as_ref()
                .unwrap()
                .connection
                .fast_open_early
        );
    }
}

#[test]
fn reset_batch_extension_isolation_generation_and_saturation() {
    let (mut e, listener, tuple) = endpoint(false, 1_000_000);
    e.set_listener_fast_open(listener, 2).unwrap();
    let first = syn(&mut e, 0, tuple);
    assert_eq!(e.accept(listener).unwrap(), first);
    let other = next_tuple(tuple);
    syn(&mut e, 0, other);
    input(&mut e, 10, tuple, 106, 0, wire::RST, false);
    input(&mut e, 20, other, 106, 0, wire::RST, false);
    assert_eq!(debt(&mut e, listener), 2);
    assert_eq!(
        e.listeners[listener.slot]
            .as_ref()
            .unwrap()
            .reset_debt_expiry,
        Some(60_000_020)
    );
    let fallback = syn(&mut e, 60_000_010, next_tuple(other));
    assert!(
        !e.slots[fallback.slot]
            .as_ref()
            .unwrap()
            .connection
            .fast_open_early
    );
    let mut isolated = tuple;
    isolated.local.set_port(8081);
    let separate = e.listen(isolated.local, 8).unwrap();
    e.set_listener_fast_open(separate, 1).unwrap();
    let old = syn(&mut e, 60_000_011, isolated);
    assert_eq!(e.accept(separate).unwrap(), old);
    e.close_listener(separate).unwrap();
    e.cleanup_one();
    let replacement = e.listen(isolated.local, 8).unwrap();
    assert_eq!(replacement.slot, separate.slot);
    assert_ne!(replacement.generation, separate.generation);
    e.set_listener_fast_open(replacement, 1).unwrap();
    input(&mut e, 60_000_012, isolated, 106, 0, wire::RST, false);
    assert_eq!(debt(&mut e, replacement), 0);
    let fresh = syn(&mut e, 60_000_013, next_tuple(isolated));
    assert!(
        e.slots[fresh.slot]
            .as_ref()
            .unwrap()
            .connection
            .fast_open_early
    );
    // Scalar saturation is independent of retained terminal handles and limits.
    e.listeners[replacement.slot].as_mut().unwrap().reset_debt = e.config.max_connections;
    e.listeners[replacement.slot]
        .as_mut()
        .unwrap()
        .reset_debt_expiry = Some(120_000_000);
    input(
        &mut e,
        60_000_014,
        next_tuple(isolated),
        106,
        0,
        wire::RST,
        false,
    );
    assert_eq!(debt(&mut e, replacement), e.config.max_connections);
    assert_eq!(
        e.set_listener_fast_open(replacement, e.config.max_connections + 1),
        Err(Error::InvalidArgument.into())
    );
    assert_eq!(debt(&mut e, listener), 2);
}

#[test]
fn local_termination_and_stale_attempt_never_charge_reset_debt() {
    for cause in 0..3 {
        let (mut e, listener, tuple) = endpoint(false, 1_000_000);
        e.enable_output_reservations().unwrap();
        let child = syn(&mut e, 0, tuple);
        match cause {
            0 => {
                e.set_application_timeout(child, Some(100_000)).unwrap();
                e.on_timeout(100_000, 64).unwrap();
            }
            1 => {
                e.abort(child).unwrap();
            }
            _ => {
                let (_, attempt) = e.poll_reserved_transmit(0, &mut [0; 2048], 64).unwrap();
                let attempt = attempt.unwrap();
                assert!(e.abandon_transmit(attempt).unwrap());
                assert!(!e.abandon_transmit(attempt).unwrap());
            }
        }
        assert_eq!(debt(&mut e, listener), 0);
        let now = e.now;
        let next = syn(&mut e, now, next_tuple(tuple));
        assert!(
            e.slots[next.slot]
                .as_ref()
                .unwrap()
                .connection
                .fast_open_early
        );
    }
}

#[test]
fn reset_debt_does_not_prevent_cookie_issuance_or_ordinary_handshake() {
    let (mut e, listener, tuple) = endpoint(false, 1_000_000);
    syn(&mut e, 0, tuple);
    input(&mut e, 1, tuple, 106, 0, wire::RST, false);
    let tuple = next_tuple(tuple);
    let ip = IpMetadata {
        source: tuple.remote.ip(),
        destination: tuple.local.ip(),
    };
    let mut bytes = [0; 2048];
    let len = wire::encode(
        ip,
        wire::Header {
            source_port: tuple.remote.port(),
            destination_port: tuple.local.port(),
            sequence: 100,
            acknowledgment: 0,
            flags: wire::SYN,
            window: 8192,
            urgent_pointer: 0,
        },
        &[34, 2, 1, 1],
        b"early",
        &mut bytes,
    )
    .unwrap();
    e.input(2, ip, &bytes[..len]).unwrap();
    let mut response = None;
    for _ in 0..8 {
        if let Some(tx) = e.poll_transmit(2, &mut bytes, 16).unwrap().packet {
            let packet = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
            if packet.header.destination_port == tuple.remote.port() {
                assert_eq!(packet.header.acknowledgment, 101);
                assert!(!packet.options.fast_open.unwrap().as_bytes().is_empty());
                response = Some(packet.header.sequence.wrapping_add(1));
            }
        }
    }
    input(&mut e, 3, tuple, 101, response.unwrap(), wire::ACK, false);
    let first = e.accept(listener).unwrap();
    assert_eq!(e.state(first).unwrap(), State::Closed);
    let ordinary = e.accept(listener).unwrap();
    assert_eq!(e.state(ordinary).unwrap(), State::Established);
    assert_eq!(e.readable_bytes(ordinary).unwrap(), 0);
    assert_eq!(debt(&mut e, listener), 1);
}
