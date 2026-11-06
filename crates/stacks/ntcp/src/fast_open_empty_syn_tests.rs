// SPDX-License-Identifier: MIT
use super::*;

fn server(v6: bool, response: bool) -> (Endpoint, ListenerId, IpMetadata, wire::Header) {
    server_with_service(v6, response, true)
}

fn server_with_service(
    v6: bool,
    response: bool,
    service: bool,
) -> (Endpoint, ListenerId, IpMetadata, wire::Header) {
    let (local, remote) = addresses(v6, 40001);
    let config = EndpointConfig {
        max_connections: 16,
        max_listeners: 2,
        connection: ConnectionConfig {
            timestamps: false,
            mss: 1460,
            nagle: false,
            send_capacity: 8192,
            receive_capacity: 8192,
            fast_open_early_response: response,
            ..ConnectionConfig::default()
        },
        ..EndpointConfig::default()
    };
    let mut endpoint = Endpoint::new(config, [2; 32], 0, crate::SETTLED, |_| true).unwrap();
    if service {
        endpoint.enable_fast_open().unwrap();
    }
    let listener = endpoint.listen(remote, 8).unwrap();
    if service {
        endpoint.set_listener_fast_open(listener, 1).unwrap();
    }
    (
        endpoint,
        listener,
        IpMetadata {
            source: local.ip(),
            destination: remote.ip(),
        },
        wire::Header {
            source_port: local.port(),
            destination_port: remote.port(),
            sequence: 100,
            acknowledgment: 0,
            flags: wire::SYN,
            window: 8192,
            urgent_pointer: 0,
        },
    )
}

fn cookie(ip: IpMetadata, now: u64) -> Vec<u8> {
    let cookie = crate::fast_open::issue(
        &[2; 32],
        ip.destination,
        ip.source,
        now / crate::fast_open::LIFETIME_US,
    );
    let mut options = vec![34, (cookie.as_bytes().len() + 2) as u8];
    options.extend_from_slice(cookie.as_bytes());
    options.resize(options.len().next_multiple_of(4), 1);
    options
}

fn input(
    endpoint: &mut Endpoint,
    now: u64,
    ip: IpMetadata,
    header: wire::Header,
    options: &[u8],
    data: &[u8],
) {
    let mut bytes = [0; 256];
    let n = wire::encode(ip, header, options, data, &mut bytes).unwrap();
    endpoint.input(now, ip, &bytes[..n]).unwrap();
}

#[test]
fn authenticated_empty_syn_exposes_no_data_and_preserves_early_response_policy() {
    for v6 in [false, true] {
        for response in [false, true] {
            let (mut endpoint, listener, ip, header) = server(v6, response);
            input(&mut endpoint, 0, ip, header, &cookie(ip, 0), &[]);
            let child = endpoint.accept(listener).unwrap();
            assert_eq!(endpoint.state(child).unwrap(), State::SynReceived);
            assert_eq!(endpoint.readable_bytes(child).unwrap(), 0);
            assert_eq!(
                endpoint.read(child, &mut [0; 32]),
                Err(Error::WouldBlock.into())
            );
            let synack = packet(&mut endpoint, 1);
            let synack = wire::parse(synack.0, &synack.1).unwrap();
            assert_eq!(synack.header.acknowledgment, header.sequence + 1);
            assert!(!endpoint.transport_info(child).unwrap().syn_data_fully_acked);
            assert_eq!(endpoint.write(child, &[9; 100]).unwrap(), 100);
            if response {
                let sent = packet(&mut endpoint, 2);
                assert_eq!(wire::parse(sent.0, &sent.1).unwrap().payload, &[9; 100]);
            } else {
                assert!(
                    endpoint
                        .poll_transmit(2, &mut [0; 2048], 32)
                        .unwrap()
                        .packet
                        .is_none()
                );
            }
            input(
                &mut endpoint,
                3,
                ip,
                wire::Header {
                    sequence: header.sequence + 1,
                    acknowledgment: synack.header.sequence.wrapping_add(1),
                    flags: wire::ACK | wire::PSH,
                    ..header
                },
                &[],
                b"peer data",
            );
            assert_eq!(endpoint.state(child).unwrap(), State::Established);
            let mut bytes = [0; 32];
            assert_eq!(endpoint.read(child, &mut bytes).unwrap(), 9);
            assert_eq!(&bytes[..9], b"peer data");
            assert!(!endpoint.transport_info(child).unwrap().syn_data_fully_acked);
        }
    }
}

#[test]
fn empty_syn_requires_cookie_authorization_and_enabled_listener() {
    for v6 in [false, true] {
        for mode in 0..5 {
            let (mut endpoint, listener, ip, header) = server_with_service(v6, true, mode != 4);
            let options = match mode {
                0 => vec![],
                1 => vec![34, 2, 1, 1],
                2 => {
                    let mut options = cookie(ip, 0);
                    options[2] ^= 1;
                    options
                }
                _ => {
                    endpoint.set_listener_fast_open(listener, 0).unwrap();
                    cookie(ip, 0)
                }
            };
            input(&mut endpoint, 0, ip, header, &options, &[]);
            let synack = packet(&mut endpoint, 1);
            assert_eq!(endpoint.accept(listener), Err(Error::WouldBlock.into()));
            let synack = wire::parse(synack.0, &synack.1).unwrap();
            assert_eq!(synack.header.acknowledgment, 101);
            input(
                &mut endpoint,
                2,
                ip,
                wire::Header {
                    sequence: 101,
                    acknowledgment: synack.header.sequence.wrapping_add(1),
                    flags: wire::ACK,
                    ..header
                },
                &[],
                &[],
            );
            let child = endpoint.accept(listener).unwrap();
            assert_eq!(endpoint.state(child).unwrap(), State::Established);
            assert!(!endpoint.transport_info(child).unwrap().syn_data_fully_acked);
        }
    }
}

#[test]
fn empty_syn_accept_and_duplicates_do_not_release_pending_quota() {
    for v6 in [false, true] {
        let (mut endpoint, listener, ip, header) = server(v6, false);
        let options = cookie(ip, 0);
        input(&mut endpoint, 0, ip, header, &options, &[]);
        let synack = packet(&mut endpoint, 1);
        let first_sequence = wire::parse(synack.0, &synack.1).unwrap().header.sequence;
        input(&mut endpoint, 2, ip, header, &options, &[]);
        packet(&mut endpoint, 2);
        assert_eq!(endpoint.listener_queue_info(listener).unwrap().0, 1);
        let first = endpoint.accept(listener).unwrap();
        assert!(endpoint.accept(listener).is_err());
        input(
            &mut endpoint,
            3,
            ip,
            wire::Header {
                source_port: 40002,
                ..header
            },
            &options,
            &[],
        );
        packet(&mut endpoint, 3);
        assert!(endpoint.accept(listener).is_err());
        input(
            &mut endpoint,
            4,
            ip,
            wire::Header {
                sequence: 101,
                acknowledgment: first_sequence.wrapping_add(1),
                flags: wire::ACK,
                ..header
            },
            &[],
            &[],
        );
        assert_eq!(endpoint.state(first).unwrap(), State::Established);
        input(
            &mut endpoint,
            5,
            ip,
            wire::Header {
                source_port: 40003,
                ..header
            },
            &options,
            &[],
        );
        let next = endpoint.accept(listener).unwrap();
        assert_ne!(next, first);
        assert_eq!(endpoint.state(next).unwrap(), State::SynReceived);
    }
}

#[test]
fn empty_syn_terminal_paths_preserve_reset_debt_and_release_other_quota() {
    for v6 in [false, true] {
        for mode in 0..3 {
            let (mut endpoint, listener, ip, header) = server(v6, false);
            input(&mut endpoint, 0, ip, header, &cookie(ip, 0), &[]);
            let child = endpoint.accept(listener).unwrap();
            packet(&mut endpoint, 1);
            let now = match mode {
                0 => {
                    input(
                        &mut endpoint,
                        2,
                        ip,
                        wire::Header {
                            sequence: 102,
                            flags: wire::RST,
                            ..header
                        },
                        &[],
                        &[],
                    );
                    assert_eq!(endpoint.state(child).unwrap(), State::SynReceived);
                    packet(&mut endpoint, 2); // Nonexact reset is challenged.
                    input(
                        &mut endpoint,
                        3,
                        ip,
                        wire::Header {
                            sequence: 101,
                            flags: wire::RST,
                            ..header
                        },
                        &[],
                        &[],
                    );
                    4
                }
                1 => {
                    endpoint.abort(child).unwrap();
                    packet(&mut endpoint, 3);
                    4
                }
                _ => {
                    endpoint.on_timeout(400_000_000, 64).unwrap();
                    400_000_001
                }
            };
            assert_eq!(endpoint.state(child).unwrap(), State::Closed);
            assert_eq!(endpoint.terminal_readable_bytes(child).unwrap(), 0);
            assert_eq!(endpoint.read_terminal(child, &mut [0; 8]).unwrap(), 0);
            input(
                &mut endpoint,
                now,
                ip,
                wire::Header {
                    source_port: 40002,
                    ..header
                },
                &cookie(ip, now),
                &[],
            );
            if mode == 0 {
                assert!(endpoint.accept(listener).is_err());
                packet(&mut endpoint, now);
                let expiry = 60_000_003;
                input(
                    &mut endpoint,
                    expiry,
                    ip,
                    wire::Header {
                        source_port: 40003,
                        ..header
                    },
                    &cookie(ip, expiry),
                    &[],
                );
            }
            assert_ne!(endpoint.accept(listener).unwrap(), child);
        }
    }
}

#[test]
fn empty_syn_listener_close_preserves_accepted_ownership_and_reuses_generation() {
    for v6 in [false, true] {
        for accepted in [false, true] {
            let (mut endpoint, listener, ip, header) = server(v6, false);
            input(&mut endpoint, 0, ip, header, &cookie(ip, 0), &[]);
            let child = endpoint
                .connection_id(Tuple {
                    local: SocketAddr::new(ip.destination, header.destination_port),
                    remote: SocketAddr::new(ip.source, header.source_port),
                })
                .unwrap();
            packet(&mut endpoint, 1);
            if accepted {
                assert_eq!(endpoint.accept(listener).unwrap(), child);
            }
            endpoint.close_listener(listener).unwrap();
            for _ in 0..32 {
                if !endpoint
                    .poll_transmit(2, &mut [0; 2048], 32)
                    .unwrap()
                    .more_work
                {
                    break;
                }
            }
            if accepted {
                assert_eq!(endpoint.state(child).unwrap(), State::SynReceived);
            } else {
                // Released children may retain a bounded reset record; the
                // application handle is invalid while that record drains.
                assert_eq!(endpoint.state(child), Err(EndpointError::InvalidHandle));
            }
            let replacement = endpoint
                .listen(SocketAddr::new(ip.destination, header.destination_port), 8)
                .unwrap();
            assert_ne!(replacement, listener);
            endpoint.set_listener_fast_open(replacement, 1).unwrap();
            input(
                &mut endpoint,
                3,
                ip,
                wire::Header {
                    source_port: 40002,
                    ..header
                },
                &cookie(ip, 3),
                &[],
            );
            assert_ne!(endpoint.accept(replacement).unwrap(), child);
        }
    }
}
