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
    let (_, accepted) = endpoint.connect_fast_open(0, local, remote, b"miss").unwrap();
    assert_eq!(accepted, 0);
    let syn = packet(endpoint, 0);
    deliver(endpoint, 1, &cache_reply(&syn, 1460, Some(&[0xab, 0xcd, 0x12, 0x34])));
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
                ActiveOpenOptions { user_mss: Some(0), ..defaults },
                ActiveOpenOptions { send_capacity: 0, ..defaults },
                ActiveOpenOptions { receive_capacity: 0, ..defaults },
            ] {
                let result = if fast_open {
                    endpoint.connect_fast_open_with_options(100, local, remote, b"x", invalid).map(|p| p.0)
                } else {
                    endpoint.connect_with_options(100, local, remote, invalid)
                };
                assert_eq!(result, Err(EndpointError::Connection(Error::InvalidArgument)));
                assert_eq!(endpoint.buffer_bytes(), charge);
                assert!(endpoint.connection_id(Tuple { local, remote }).is_none());
            }
            // A failed request at100 did not advance the endpoint's clock or
            // publish the tuple. Legacy opens retain endpoint defaults.
            let id = if fast_open {
                endpoint.connect_fast_open(0, local, remote, b"x").unwrap().0
            } else {
                endpoint.connect(0, local, remote).unwrap()
            };
            assert_eq!(endpoint.transport_info(id).unwrap().advertised_mss, 400);
            let syn = packet(&mut endpoint, 0);
            assert_eq!(wire::parse(syn.0, &syn.1).unwrap().options.mss, Some(400));

            let (local, remote) = addresses(v6, 49001);
            let explicit = ActiveOpenOptions { user_mss: None, ..defaults };
            let id = if fast_open {
                endpoint.connect_fast_open_with_options(0, local, remote, b"x", explicit).unwrap().0
            } else {
                endpoint.connect_with_options(0, local, remote, explicit).unwrap()
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
            let options = ActiveOpenOptions { user_mss: Some(1040), ..ActiveOpenOptions::from(&config.connection) };
            let expected: Vec<u8> = (0..2000).map(|n| (n % 251) as u8).collect();
            let mut source = expected.clone();
            let (id, accepted) = endpoint.connect_fast_open_with_options(2, local, remote, &source, options).unwrap();
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
            let (_, accepted) = endpoint.connect_fast_open_with_options(4, local, remote, &expected, ActiveOpenOptions::from(&config.connection)).unwrap();
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
        let options = ActiveOpenOptions { user_mss: Some(1440), ..ActiveOpenOptions::from(&config.connection) };
        let data: Vec<u8> = (0..2000).map(|n| (n % 251) as u8).collect();
        let (id, accepted) = endpoint.connect_fast_open_with_options(2, local, remote, &data, options).unwrap();
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
        assert_eq!((info.send_used, info.notsent_bytes), (accepted, accepted - sent));
        deliver(&mut endpoint, 4, &cache_reply(&syn, 1460, None));
        let mut tail = Vec::new();
        for _ in 0..16 {
            let mut bytes = [0; 2048];
            let Some(tx) = endpoint.poll_transmit(4, &mut bytes, 16).unwrap().packet else { break };
            let parsed = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
            tail.extend_from_slice(parsed.payload);
        }
        assert_eq!(tail, data[sent..accepted]);
        assert_eq!(endpoint.transport_info(id).unwrap().notsent_bytes, 0);
    }
}
