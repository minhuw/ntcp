use super::*;

//= https://www.rfc-editor.org/rfc/rfc7413#section-3
//= type=test
//= reason=Small rejected/partial SYN payloads are repaired in the first ACK. public_first_ack_capacity_conflicts_and_receiver_driven_completion validates 400 SYN bytes against newly learned MSS64/cwnd256, a 32-byte offered window, partial acceptance128 with zero window, and an IPv4 effective path MSS28/cwnd112; first ACK payloads are 64/32/0/28 and real receiver ACK/window progress completes each stream once. Native PacketIo/Egress independently emits 88 bytes first and 352 before ACK for 400 rejected SYN bytes with MSS88. Existing wrap/scalar/reserved evidence remains. Literal all-data-in-first-ACK wording remains TODO pending explicit AC27/T23 user disposition; no interpretation or standards deviation is approved.
//# 4. The client sends an ACK acknowledging the SYN and the server data. If the client's data is not acknowledged, the client retransmits the data in the ACK packet.
//= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
//= type=test
//= reason=Small rejected/partial SYN payloads are repaired in the first ACK. public_first_ack_capacity_conflicts_and_receiver_driven_completion validates 400 SYN bytes against newly learned MSS64/cwnd256, a 32-byte offered window, partial acceptance128 with zero window, and an IPv4 effective path MSS28/cwnd112; first ACK payloads are 64/32/0/28 and real receiver ACK/window progress completes each stream once. Native PacketIo/Egress independently emits 88 bytes first and 352 before ACK for 400 rejected SYN bytes with MSS88. Existing wrap/scalar/reserved evidence remains. Literal all-data-in-first-ACK wording remains TODO pending explicit AC27/T23 user disposition; no interpretation or standards deviation is approved.
//# The client SHOULD retransmit any unacknowledged data in the first ACK packet in step 2.
#[test]
fn public_first_ack_capacity_conflicts_and_receiver_driven_completion() {
    for v6 in [false, true] {
        for reserved in [false, true] {
            // The small/zero windows are backed by actual receiver storage.
            // Only the IPv4 path case lowers a path ceiling below the peer MSS.
            for (partial, capacity, path) in [
                (false, 8192, false),
                (false, 32, false),
                (true, 128, false),
                (false, 8192, true),
            ] {
                if path && v6 {
                    continue;
                }
                let config = EndpointConfig {
                    max_connections: 16,
                    connection: ConnectionConfig {
                        mss: 1460,
                        nagle: false,
                        timestamps: false,
                        send_capacity: 8192,
                        receive_capacity: 8192,
                        initial_window: InitialWindow::Rfc5681,
                        pmtud: Some(PmtudConfig::new(1500)),
                        ..ConnectionConfig::default()
                    },
                    ..EndpointConfig::default()
                };
                let a = Endpoint::new(config.clone(), [1; 32], 0, crate::SETTLED, |_| true).unwrap();
                let b = Endpoint::new(config, [2; 32], 0, crate::SETTLED, |_| true).unwrap();
                let (mut a, mut b, listener) = warm_pair(v6, a, b);
                b.set_listener_buffer_capacities(listener, 8192, capacity)
                    .unwrap();
                b.set_listener_user_mss(listener, Some(if path { 1460 } else { 64 }))
                    .unwrap();
                if !partial {
                    b.set_fast_open_hmac_key([77; 32]); // A genuinely rejected old cookie.
                }
                if reserved {
                    a.enable_output_reservations_with_gso(
                        2,
                        GsoLimits {
                            max_bytes: 8192,
                            max_segments: 16,
                        },
                    )
                    .unwrap();
                }
                let (local, remote) = addresses(v6, 40001);
                let data: Vec<u8> = (0..400).map(|n| (n % 251) as u8).collect();
                let (client, n) = a.connect_fast_open(100, local, remote, &data).unwrap();
                assert_eq!(n, 400);
                let syn = emit(&mut a, 100, client, reserved);
                let original = wire::parse(syn.0, &syn.1).unwrap();
                assert_eq!(original.payload, data);
                deliver(&mut b, 110, &syn);
                let child = b
                    .connection_id(Tuple {
                        local: remote,
                        remote: local,
                    })
                    .unwrap();
                let synack = packet(&mut b, 120);
                let validated = wire::parse(synack.0, &synack.1).unwrap();
                let accepted = if partial { capacity as u32 } else { 0 };
                assert_eq!(
                    validated.header.flags & (wire::SYN | wire::ACK),
                    wire::SYN | wire::ACK
                );
                assert_eq!(validated.options.mss, Some(if path { 1460 } else { 64 }));
                assert_eq!(
                    validated.header.acknowledgment,
                    original.header.sequence.wrapping_add(1 + accepted)
                );
                assert_eq!(
                    u32::from(validated.header.window),
                    if partial { 0 } else { capacity as u32 }
                );
                if path {
                    a.set_route_mtu(115, client, Some(68)).unwrap();
                }
                deliver(&mut a, 120, &synack);
                let info = a.transport_info(client).unwrap();
                let effective = if path { 28 } else { 64 };
                assert_eq!((info.mss, info.cwnd), (effective, 4 * effective));
                assert_eq!(a.acknowledged(client).unwrap(), u64::from(accepted));
                let mut bytes = [0; 2048];
                // Encoding failure must leave the first repair available.
                if reserved {
                    assert!(
                        a.poll_reserved_transmit_for(121, client, &mut [0; 19], 64)
                            .is_err()
                    );
                } else {
                    assert!(a.poll_transmit(121, &mut [0; 19], 64).is_err());
                }
                assert_eq!(
                    a.transport_info(client).unwrap().send_used,
                    (400 - accepted) as usize
                );
                let first = if reserved {
                    let (out, token) = a
                        .poll_reserved_transmit_for(122, client, &mut bytes, 64)
                        .unwrap();
                    let tx = out.packet.unwrap();
                    let selected = bytes[..tx.len].to_vec();
                    let token = token.unwrap();
                    assert!(a.reject_unsubmitted(token).unwrap());
                    let (out, next) = a
                        .poll_reserved_transmit_for(123, client, &mut bytes, 64)
                        .unwrap();
                    let tx = out.packet.unwrap();
                    assert_eq!(&bytes[..tx.len], &selected);
                    assert!(!a.accept_transmit(123, token).unwrap());
                    assert!(a.accept_transmit(123, next.unwrap()).unwrap());
                    (tx.ip, selected)
                } else {
                    emit(&mut a, 123, client, false)
                };
                let first_segment = wire::parse(first.0, &first.1).unwrap();
                let offered = u32::from(validated.header.window);
                let lawful_first = effective.min(info.cwnd).min(offered).min(400 - accepted);
                assert_eq!(first_segment.payload.len(), lawful_first as usize);
                assert_eq!(
                    first_segment.header.flags & (wire::SYN | wire::ACK),
                    wire::ACK
                );
                assert_eq!(
                    first_segment.header.acknowledgment,
                    validated.header.sequence.wrapping_add(1)
                );
                if lawful_first != 0 {
                    assert_eq!(
                        first_segment.header.sequence,
                        original.header.sequence.wrapping_add(1 + accepted)
                    );
                }
                let mut pending = vec![first];
                let mut before_ack = lawful_first;
                for _ in 0..32 {
                    let packet = if reserved {
                        let (out, token) = a
                            .poll_reserved_transmit_for(124, client, &mut bytes, 64)
                            .unwrap();
                        if let Some(token) = token {
                            a.accept_transmit(124, token).unwrap();
                        }
                        out.packet
                    } else {
                        a.poll_transmit(124, &mut bytes, 64).unwrap().packet
                    };
                    let Some(tx) = packet else { break };
                    let segment = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
                    assert!(segment.payload.len() <= effective as usize);
                    before_ack += segment.payload.len() as u32;
                    pending.push((tx.ip, bytes[..tx.len].to_vec()));
                }
                assert_eq!(before_ack, info.cwnd.min(offered).min(400 - accepted));
                let mut received = Vec::new();
                if partial {
                    let mut got = [0; 512];
                    let n = b.read(child, &mut got).unwrap();
                    received.extend_from_slice(&got[..n]);
                }
                for p in &pending {
                    deliver(&mut b, 130, p);
                }
                // Actual receiver ACK/window updates, including reopening after
                // application reads, drive every subsequent repair and new byte.
                for now in (1000..900_000).step_by(1000) {
                    b.on_timeout(now, 64).unwrap();
                    a.on_timeout(now, 64).unwrap();
                    if let Ok(n) = b.read(child, &mut bytes) {
                        received.extend_from_slice(&bytes[..n]);
                    }
                    if let Some(tx) = b.poll_transmit(now, &mut bytes, 64).unwrap().packet {
                        a.input(now, tx.ip, &bytes[..tx.len]).unwrap();
                    }
                    let out = if reserved {
                        let (out, token) = a
                            .poll_reserved_transmit_for(now, client, &mut bytes, 64)
                            .unwrap();
                        if let Some(token) = token {
                            a.accept_transmit(now, token).unwrap();
                        }
                        out
                    } else {
                        a.poll_transmit(now, &mut bytes, 64).unwrap()
                    };
                    if let Some(tx) = out.packet {
                        assert!(
                            wire::parse(tx.ip, &bytes[..tx.len]).unwrap().payload.len()
                                <= effective as usize
                        );
                        b.input(now, tx.ip, &bytes[..tx.len]).unwrap();
                    }
                    if received.len() == data.len() && a.acknowledged(client).unwrap() == 400 {
                        break;
                    }
                }
                assert_eq!(received, data);
                assert_eq!(a.acknowledged(client).unwrap(), 400);
                // Late copies of the original SYN and repair must not redeliver.
                deliver(&mut b, 900_000, &syn);
                deliver(&mut b, 900_000, &pending[0]);
                assert_eq!(
                    b.read(child, &mut bytes),
                    Err(EndpointError::Connection(Error::WouldBlock))
                );
                std::eprintln!(
                    "T3_FIRST_ACK {{\"v6\":{v6},\"reserved\":{reserved},\"syn_bytes\":400,\"accepted\":{accepted},\"advertised_mss\":{},\"effective_mss\":{effective},\"cwnd\":{},\"offered_window\":{offered},\"first_ack_bytes\":{lawful_first},\"before_data_ack\":{before_ack},\"delivered_once\":400}}",
                    validated.options.mss.unwrap(),
                    info.cwnd
                );
            }
        }
    }
}

fn response(syn: &(IpMetadata, Vec<u8>), acknowledged_data: u32) -> (IpMetadata, Vec<u8>) {
    let mut result = cache_reply(syn, 1460, Some(&[0x12, 0x34, 0xab, 0xcd]));
    let iss = wire::parse(syn.0, &syn.1).unwrap().header.sequence;
    result.1[8..12].copy_from_slice(&iss.wrapping_add(1 + acknowledged_data).to_be_bytes());
    repair_cache_checksum(result.0, &mut result.1);
    result
}

#[test]
fn partial_synack_rtt_repair_and_next_service_admission() {
    for v6 in [false, true] {
        for scale in [1, 1000] {
            for reserved in [false, true] {
                for acknowledged in [0, 1, 699, 700] {
                    let config = EndpointConfig {
                        max_connections: 16,
                        connection: ConnectionConfig {
                            mss: 1460,
                            timestamps: false,
                            sack: true,
                            rack: true,
                            prr: true,
                            prr_pacing: false,
                            pacing: None,
                            congestion_algorithm: CongestionAlgorithm::Cubic,
                            initial_window: InitialWindow::Iw10,
                            rto_min_us: 200_000,
                            timebase: CallerTimebase {
                                units_per_second: 1_000_000 * scale,
                                ..CallerTimebase::default()
                            },
                            ..ConnectionConfig::default()
                        },
                        ..EndpointConfig::default()
                    };
                    let mut a = Endpoint::new(config, [1; 32], 0, crate::SETTLED, |_| true).unwrap();
                    a.enable_fast_open().unwrap();
                    if reserved {
                        a.enable_output_reservations().unwrap();
                    }
                    let (local, remote) = addresses(v6, 40000);
                    let (warm, n) = a.connect_fast_open(0, local, remote, &[]).unwrap();
                    assert_eq!(n, 0);
                    let warm_syn = emit(&mut a, 0, warm, reserved);
                    deliver(&mut a, 1000 * scale, &response(&warm_syn, 0));
                    emit(&mut a, 1000 * scale, warm, reserved);
                    let (local, _) = addresses(v6, 40001);
                    let sent_at = 10_000 * scale;
                    let (id, accepted) = a
                        .connect_fast_open(sent_at, local, remote, &[0x55; 700])
                        .unwrap();
                    assert_eq!(accepted, 700);
                    let syn = emit(&mut a, sent_at, id, reserved);
                    let original = wire::parse(syn.0, &syn.1).unwrap();
                    assert_eq!(original.payload.len(), 700);
                    let replied_at = sent_at + 20_000 * scale;
                    deliver(&mut a, replied_at, &response(&syn, acknowledged));
                    assert_eq!(a.state(id).unwrap(), State::Established);
                    let before = a.transport_info(id).unwrap();
                    assert_eq!(before.rtt_us, Some(20_000));
                    assert_eq!(before.syn_data_acked, acknowledged != 0);
                    assert_eq!(before.send_used, (700 - acknowledged) as usize);
                    assert_eq!(a.acknowledged(id).unwrap(), u64::from(acknowledged));
                    assert!(
                        a.has_fast_open_cookie(replied_at, local.ip(), remote.ip())
                            .unwrap()
                    );
                    assert_eq!(
                        a.can_defer_fast_open(replied_at, local.ip(), remote)
                            .unwrap(),
                        acknowledged != 0
                    );
                    let repair = emit(&mut a, replied_at, id, reserved);
                    let repair = wire::parse(repair.0, &repair.1).unwrap();
                    assert_eq!(
                        repair.header.sequence,
                        original.header.sequence.wrapping_add(1 + acknowledged)
                    );
                    assert_eq!(repair.payload.len(), (700 - acknowledged) as usize);
                    assert_eq!(repair.header.flags & (wire::SYN | wire::ACK), wire::ACK);
                    let after = a.transport_info(id).unwrap();
                    assert_eq!(after.rtt_us, Some(20_000));
                    assert_eq!(after.send_used, before.send_used);
                    assert_eq!(a.acknowledged(id).unwrap(), u64::from(acknowledged));
                    let (next_local, _) = addresses(v6, 40002);
                    let (next, n) = a
                        .connect_fast_open(replied_at + scale, next_local, remote, &[0x66; 700])
                        .unwrap();
                    assert_eq!(n, if acknowledged != 0 { 700 } else { 0 });
                    let next = emit(&mut a, replied_at + scale, next, reserved);
                    let next = wire::parse(next.0, &next.1).unwrap();
                    assert_eq!(next.options.fast_open.is_some(), acknowledged != 0);
                    // A different service isolates the second RTT assertion from
                    // the first service's negative cache, using the same cookie.
                    let other_remote = SocketAddr::new(remote.ip(), remote.port() + 1);
                    let (other_local, _) = addresses(v6, 40003);
                    let other_at = replied_at + 2 * scale;
                    let (other, other_n) = a
                        .connect_fast_open(other_at, other_local, other_remote, &[0x77; 700])
                        .unwrap();
                    assert_eq!(other_n, 700);
                    let other_syn = emit(&mut a, other_at, other, reserved);
                    let other_reply_at = other_at + 30_000 * scale;
                    deliver(&mut a, other_reply_at, &response(&other_syn, 0));
                    let other_info = a.transport_info(other).unwrap();
                    assert_eq!(other_info.rtt_us, Some(30_000));
                    assert!(!other_info.syn_data_acked);
                    assert_eq!(other_info.send_used, 700);
                    let other_repair = emit(&mut a, other_reply_at, other, reserved);
                    assert_eq!(
                        wire::parse(other_repair.0, &other_repair.1)
                            .unwrap()
                            .payload
                            .len(),
                        700
                    );
                }
            }
        }
    }
}

#[test]
fn partial_synack_preserves_prior_icmp_and_rto_suppression() {
    for v6 in [false, true] {
        for reserved in [false, true] {
            for timed_out in [false, true] {
                let (mut a, _, _) = warm(v6);
                if reserved {
                    a.enable_output_reservations().unwrap();
                }
                let (local, remote) = addresses(v6, 40001);
                let (id, accepted) = a
                    .connect_fast_open(100, local, remote, &[0x55; 12])
                    .unwrap();
                assert_eq!(accepted, 12);
                let syn = emit(&mut a, 100, id, reserved);
                let failure_at = if timed_out {
                    let deadline = a.next_deadline().unwrap();
                    a.on_timeout(deadline, 64).unwrap();
                    deadline
                } else {
                    let seq = wire::parse(syn.0, &syn.1).unwrap().header.sequence;
                    assert!(
                        a.network_error(
                            110,
                            Tuple { local, remote },
                            seq,
                            NetworkError::SoftUnreachable
                        )
                        .unwrap()
                    );
                    110
                };
                assert!(
                    !a.can_defer_fast_open(failure_at, local.ip(), remote)
                        .unwrap()
                );
                let replied_at = failure_at + 100;
                deliver(&mut a, replied_at, &response(&syn, 3));
                assert!(a.transport_info(id).unwrap().syn_data_acked);
                assert_eq!(a.acknowledged(id).unwrap(), 3);
                let repair = emit(&mut a, replied_at, id, reserved);
                assert_eq!(wire::parse(repair.0, &repair.1).unwrap().payload.len(), 9);
                assert!(
                    a.has_fast_open_cookie(replied_at, local.ip(), remote.ip())
                        .unwrap()
                );
                assert!(
                    !a.can_defer_fast_open(replied_at, local.ip(), remote)
                        .unwrap()
                );
                let (next_local, _) = addresses(v6, 40002);
                let (next, accepted) = a
                    .connect_fast_open(replied_at + 1, next_local, remote, &[0x66; 12])
                    .unwrap();
                assert_eq!(accepted, 0);
                let next = emit(&mut a, replied_at + 1, next, reserved);
                assert!(
                    wire::parse(next.0, &next.1)
                        .unwrap()
                        .options
                        .fast_open
                        .is_none()
                );
            }
        }
    }
}
