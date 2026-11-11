// SPDX-License-Identifier: MIT
use super::*;

fn sender(timestamps: bool, user_mss: Option<u16>) -> (Endpoint, EndpointConfig) {
    let config = EndpointConfig {
        connection: ConnectionConfig {
            mss: 1460,
            user_mss,
            timestamps,
            sack: true,
            send_capacity: 8192,
            receive_capacity: 8192,
            pmtud: Some(PmtudConfig::new(1500)),
            ..ConnectionConfig::default()
        },
        ..EndpointConfig::default()
    };
    let mut endpoint = Endpoint::new(config.clone(), [3; 32], 0, |_| true).unwrap();
    endpoint.enable_fast_open().unwrap();
    (endpoint, config)
}

fn learn_cookie(endpoint: &mut Endpoint, v6: bool) {
    let (local, remote) = addresses(v6, 49000);
    let (_, accepted) = endpoint
        .connect_fast_open(0, local, remote, b"miss")
        .unwrap();
    assert_eq!(accepted, 0);
    let syn = packet(endpoint, 0);
    deliver(
        endpoint,
        1,
        &cache_reply(&syn, 1460, Some(&[0xab, 0xcd, 0x12, 0x34])),
    );
    packet(endpoint, 1);
}

#[test]
fn invalid_active_options_preserve_tuple_budget_clock_and_defaults() {
    for v6 in [false, true] {
        for fast_open in [false, true] {
            let (mut endpoint, config) = sender(false, Some(400));
            let (local, remote) = addresses(v6, 49000);
            let defaults = ActiveOpenOptions::from(&config.connection);
            let charge = endpoint.buffer_bytes();
            for invalid in [
                ActiveOpenOptions {
                    user_mss: Some(0),
                    ..defaults
                },
                ActiveOpenOptions {
                    send_capacity: 0,
                    ..defaults
                },
                ActiveOpenOptions {
                    receive_capacity: 0,
                    ..defaults
                },
            ] {
                let result = if fast_open {
                    endpoint
                        .connect_fast_open_with_options(100, local, remote, b"x", invalid)
                        .map(|p| p.0)
                } else {
                    endpoint.connect_with_options(100, local, remote, invalid)
                };
                assert_eq!(
                    result,
                    Err(EndpointError::Connection(Error::InvalidArgument))
                );
                assert_eq!(endpoint.buffer_bytes(), charge);
                assert!(endpoint.connection_id(Tuple { local, remote }).is_none());
            }
            // A failed request at100 did not advance the endpoint's clock or
            // publish the tuple. Legacy opens retain endpoint defaults.
            let id = if fast_open {
                endpoint
                    .connect_fast_open(0, local, remote, b"x")
                    .unwrap()
                    .0
            } else {
                endpoint.connect(0, local, remote).unwrap()
            };
            assert_eq!(endpoint.transport_info(id).unwrap().advertised_mss, 400);
            let syn = packet(&mut endpoint, 0);
            assert_eq!(wire::parse(syn.0, &syn.1).unwrap().options.mss, Some(400));

            let (local, remote) = addresses(v6, 49001);
            let explicit = ActiveOpenOptions {
                user_mss: None,
                ..defaults
            };
            let id = if fast_open {
                endpoint
                    .connect_fast_open_with_options(0, local, remote, b"x", explicit)
                    .unwrap()
                    .0
            } else {
                endpoint
                    .connect_with_options(0, local, remote, explicit)
                    .unwrap()
            };
            assert_eq!(endpoint.transport_info(id).unwrap().advertised_mss, 1460);
        }
    }
}

#[test]
fn fast_open_active_options_bound_copy_and_preserve_raw_peer_mss() {
    for v6 in [false, true] {
        for timestamps in [false, true] {
            let (mut endpoint, config) = sender(timestamps, None);
            learn_cookie(&mut endpoint, v6);
            let (local, remote) = addresses(v6, 49001);
            let options = ActiveOpenOptions {
                user_mss: Some(1040),
                ..ActiveOpenOptions::from(&config.connection)
            };
            let expected: Vec<u8> = (0..2000).map(|n| (n % 251) as u8).collect();
            let mut source = expected.clone();
            let (id, accepted) = endpoint
                .connect_fast_open_with_options(2, local, remote, &source, options)
                .unwrap();
            assert_eq!(accepted, 1000);
            source.fill(0); // Admission owns its copy before publishing the ID.
            let syn = packet(&mut endpoint, 2);
            let segment = wire::parse(syn.0, &syn.1).unwrap();
            assert_eq!(segment.options.mss, Some(1040));
            assert_eq!(segment.payload, &expected[..accepted]);
            assert!(segment.raw_options.len() + accepted <= 1040);
            let info = endpoint.transport_info(id).unwrap();
            assert_eq!((info.send_used, info.notsent_bytes), (accepted, 0));
            deliver(&mut endpoint, 3, &cache_reply(&syn, 1340, None));
            let ack = packet(&mut endpoint, 3);
            assert!(wire::parse(ack.0, &ack.1).unwrap().payload.is_empty());
            assert_eq!(endpoint.transport_info(id).unwrap().send_used, 0);
            assert_eq!(endpoint.transport_info(id).unwrap().advertised_mss, 1040);

            // Per-open user MSS does not overwrite the raw peer-MSS cache.
            let (local, remote) = addresses(v6, 49002);
            let (_, accepted) = endpoint
                .connect_fast_open_with_options(
                    4,
                    local,
                    remote,
                    &expected,
                    ActiveOpenOptions::from(&config.connection),
                )
                .unwrap();
            assert_eq!(accepted, 1300);
            let syn = packet(&mut endpoint, 4);
            let segment = wire::parse(syn.0, &syn.1).unwrap();
            assert_eq!(segment.options.mss, Some(1460));
            assert_eq!(segment.payload, &expected[..1300]);
        }
    }
}

#[test]
fn fast_open_active_options_retain_owned_tail_after_later_mtu_reduction() {
    for v6 in [false, true] {
        let (mut endpoint, config) = sender(false, None);
        learn_cookie(&mut endpoint, v6);
        let (local, remote) = addresses(v6, 49001);
        let options = ActiveOpenOptions {
            user_mss: Some(1440),
            ..ActiveOpenOptions::from(&config.connection)
        };
        let data: Vec<u8> = (0..2000).map(|n| (n % 251) as u8).collect();
        let (id, accepted) = endpoint
            .connect_fast_open_with_options(2, local, remote, &data, options)
            .unwrap();
        assert_eq!(accepted, 1400);
        let mtu = if v6 { 1280 } else { 800 };
        endpoint.set_first_hop_mtu(3, id, mtu).unwrap();
        let syn = packet(&mut endpoint, 3);
        let parsed = wire::parse(syn.0, &syn.1).unwrap();
        let sent = parsed.payload.len();
        assert!(sent > 0 && sent < accepted);
        assert_eq!(parsed.payload, &data[..sent]);
        assert_eq!(parsed.options.mss, Some(1440));
        assert!(syn.1.len() + if v6 { 40 } else { 20 } <= mtu as usize);
        let info = endpoint.transport_info(id).unwrap();
        assert_eq!(
            (info.send_used, info.notsent_bytes),
            (accepted, accepted - sent)
        );
        deliver(&mut endpoint, 4, &cache_reply(&syn, 1460, None));
        let mut tail = Vec::new();
        for _ in 0..16 {
            let mut bytes = [0; 2048];
            let Some(tx) = endpoint.poll_transmit(4, &mut bytes, 16).unwrap().packet else {
                break;
            };
            let parsed = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
            tail.extend_from_slice(parsed.payload);
        }
        assert_eq!(tail, data[sent..accepted]);
        assert_eq!(endpoint.transport_info(id).unwrap().notsent_bytes, 0);
    }
}

#[cfg(feature = "packet-test-controls")]
#[test]
fn packet_test_timestamp_default_preserves_established_state_and_cached_mss() {
    for v6 in [false, true] {
        let (mut endpoint, _) = sender(true, None);
        let (local, remote) = addresses(v6, 49200);
        let (old, _) = endpoint.connect_fast_open(0, local, remote, b"").unwrap();
        let syn = packet(&mut endpoint, 0);
        let sent = wire::parse(syn.0, &syn.1).unwrap();
        assert!(sent.options.timestamps.is_some());
        let mut reply = cache_reply(&syn, 940, Some(&[0xab, 0xcd, 0x12, 0x34]));
        let mut bytes = reply.1[..30].to_vec();
        let mut ts = vec![1, 1, 8, 10];
        ts.extend_from_slice(&2000u32.to_be_bytes());
        ts.extend_from_slice(&sent.options.timestamps.unwrap().0.to_be_bytes());
        bytes.extend_from_slice(&ts);
        bytes.extend_from_slice(&[1, 1]);
        bytes[12] = ((bytes.len() / 4) as u8) << 4;
        repair_cache_checksum(reply.0, &mut bytes);
        reply.1 = bytes;
        deliver(&mut endpoint, 1000, &reply);
        let ack = packet(&mut endpoint, 1000);
        assert!(
            wire::parse(ack.0, &ack.1)
                .unwrap()
                .options
                .timestamps
                .is_some()
        );
        endpoint.packet_test_timestamp_default(false);
        endpoint.write(old, b"old").unwrap();
        let old_data = packet(&mut endpoint, 1001);
        assert!(
            wire::parse(old_data.0, &old_data.1)
                .unwrap()
                .options
                .timestamps
                .is_some()
        );
        let (local2, _) = addresses(v6, 49201);
        let (_, accepted) = endpoint
            .connect_fast_open(1002, local2, remote, &[7; 2000])
            .unwrap();
        assert_eq!(accepted, 900);
        let syn = packet(&mut endpoint, 1002);
        let syn = wire::parse(syn.0, &syn.1).unwrap();
        assert!(syn.options.timestamps.is_none());
        assert_eq!(syn.payload.len(), 900);
        assert_eq!(
            syn.options.fast_open.unwrap().as_bytes(),
            &[0xab, 0xcd, 0x12, 0x34]
        );
        endpoint.packet_test_timestamp_default(true);
        let (local3, _) = addresses(v6, 49202);
        endpoint.connect(1003, local3, remote).unwrap();
        let syn = packet(&mut endpoint, 1003);
        assert!(
            wire::parse(syn.0, &syn.1)
                .unwrap()
                .options
                .timestamps
                .is_some()
        );
    }
}

#[cfg(feature = "packet-test-controls")]
#[test]
fn packet_test_timestamp_default_applies_to_new_passive_connections() {
    for v6 in [false, true] {
        let (mut client, _) = sender(true, None);
        let (mut server, _) = sender(true, None);
        let (local, remote) = addresses(v6, 49300);
        let listener = server.listen(remote, 8).unwrap();
        server.packet_test_timestamp_default(false);
        client.connect(0, local, remote).unwrap();
        let syn = packet(&mut client, 0);
        assert!(
            wire::parse(syn.0, &syn.1)
                .unwrap()
                .options
                .timestamps
                .is_some()
        );
        deliver(&mut server, 1, &syn);
        let reply = packet(&mut server, 1);
        assert!(
            wire::parse(reply.0, &reply.1)
                .unwrap()
                .options
                .timestamps
                .is_none()
        );
        deliver(&mut client, 2, &reply);
        deliver(&mut server, 3, &packet(&mut client, 2));
        let first = server.accept(listener).unwrap();
        server.packet_test_timestamp_default(true);
        server.write(first, b"first").unwrap();
        let data = packet(&mut server, 4);
        assert!(
            wire::parse(data.0, &data.1)
                .unwrap()
                .options
                .timestamps
                .is_none()
        );
        let (local2, _) = addresses(v6, 49301);
        client.connect(5, local2, remote).unwrap();
        let syn = packet(&mut client, 5);
        deliver(&mut server, 6, &syn);
        let reply = packet(&mut server, 6);
        assert!(
            wire::parse(reply.0, &reply.1)
                .unwrap()
                .options
                .timestamps
                .is_some()
        );
    }
}

#[cfg(feature = "packet-test-controls")]
#[test]
fn packet_test_timestamp_default_controls_time_wait_reuse_without_changing_old_state() {
    for v6 in [false, true] {
        let (mut client, config) = sender(true, None);
        let mut config = config;
        config.reuse_time_wait = true;
        let mut server = Endpoint::new(config, [4; 32], 0, |_| true).unwrap();
        let (local, remote) = addresses(v6, 49400);
        let listener = server.listen(remote, 8).unwrap();
        let client_id = client.connect(0, local, remote).unwrap();
        let first_syn = packet(&mut client, 0);
        let first = wire::parse(first_syn.0, &first_syn.1).unwrap();
        let original_sequence = first.header.sequence;
        let newer_timestamp = first.options.timestamps.unwrap().0.wrapping_add(1000);
        deliver(&mut server, 10, &first_syn);
        deliver(&mut client, 20, &packet(&mut server, 10));
        deliver(&mut server, 30, &packet(&mut client, 20));
        let child = server.accept(listener).unwrap();
        server.shutdown(child).unwrap();
        deliver(&mut client, 100, &packet(&mut server, 100));
        deliver(&mut server, 110, &packet(&mut client, 100));
        client.shutdown(client_id).unwrap();
        deliver(&mut server, 200, &packet(&mut client, 200));
        deliver(&mut client, 210, &packet(&mut server, 200));
        assert_eq!(server.state(child), Ok(State::TimeWait));
        server.release(child).unwrap();
        // Released with its last ACK sent, only its TIME-WAIT record holds
        // the tuple.
        assert!(!server.connection_exists(child));
        assert_eq!(server.time_wait_connections(), 1);
        let old_expiry = server.next_deadline();
        let tuple = Tuple {
            local: remote,
            remote: local,
        };
        let mut options = vec![1, 1, 8, 10];
        options.extend_from_slice(&newer_timestamp.to_be_bytes());
        options.extend_from_slice(&0u32.to_be_bytes());
        let mut syn = vec![0; 64];
        let n = wire::encode(
            first_syn.0,
            wire::Header {
                source_port: local.port(),
                destination_port: remote.port(),
                sequence: original_sequence,
                acknowledgment: 0,
                flags: wire::SYN,
                window: 8192,
                urgent_pointer: 0,
            },
            &options,
            &[],
            &mut syn,
        )
        .unwrap();
        syn.truncate(n);
        server.packet_test_timestamp_default(false);
        assert_eq!(
            server.input(300, first_syn.0, &syn),
            Ok(InputDisposition::Dropped)
        );
        // The record is untouched: still in TIME-WAIT, its timer unchanged,
        // nothing sent and no connection opened.
        assert_eq!(server.time_wait_connections(), 1);
        assert_eq!(server.connection_id(tuple), None);
        assert_eq!(server.next_deadline(), old_expiry);
        assert!(
            server
                .poll_transmit(300, &mut [0; 2000], 8)
                .unwrap()
                .packet
                .is_none()
        );
        server.packet_test_timestamp_default(true);
        assert_eq!(
            server.input(301, first_syn.0, &syn),
            Ok(InputDisposition::Processed)
        );
        let reopened = server.connection_id(tuple).unwrap();
        assert_ne!(reopened, child);
        assert_eq!(server.state(reopened), Ok(State::SynReceived));
        // The new connection's tuple ends the record's TIME-WAIT.
        assert_eq!(server.time_wait_connections(), 0);
        let reply = packet(&mut server, 301);
        let reply = wire::parse(reply.0, &reply.1).unwrap();
        assert_eq!(
            reply.header.flags & (wire::SYN | wire::ACK),
            wire::SYN | wire::ACK
        );
        assert!(reply.options.timestamps.is_some());
    }
}
