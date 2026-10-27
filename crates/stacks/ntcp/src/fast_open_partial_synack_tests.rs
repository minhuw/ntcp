use super::*;

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
                    let mut a = Endpoint::new(config, [1; 32], 0, |_| true).unwrap();
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
