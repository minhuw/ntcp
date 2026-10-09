extern crate std;
use super::*;

fn endpoint() -> Endpoint {
    Endpoint::new(
        EndpointConfig {
            max_connections: 4,
            max_listeners: 2,
            connection: ConnectionConfig {
                pmtud: Some(crate::PmtudConfig::new(1500)),
                mss: 1000,
                nagle: false,
                sack: true,
                ..ConnectionConfig::default()
            },
            ..EndpointConfig::default()
        },
        [1; 32],
        0,
        |_| true,
    )
    .unwrap()
}

fn pair() -> (Endpoint, Endpoint, ConnectionId, ConnectionId) {
    let mut a = endpoint();
    let mut b = endpoint();
    let local = "192.0.2.1:40000".parse().unwrap();
    let remote = "192.0.2.2:8080".parse().unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let client = a.connect(0, local, remote).unwrap();
    let mut bytes = [0; 2048];
    for i in 0..3 {
        let (src, dst) = if i == 1 {
            (&mut b, &mut a)
        } else {
            (&mut a, &mut b)
        };
        let p = src
            .poll_transmit(1, &mut bytes, 16)
            .unwrap()
            .packet
            .unwrap();
        dst.input(1, p.ip, &bytes[..p.len]).unwrap();
    }
    let server = b.accept(listener).unwrap();
    a.enable_output_reservations().unwrap();
    (a, b, client, server)
}

#[test]
fn reserved_data_fin_partial_acceptance_and_mutation_barrier() {
    let (mut a, mut b, id, peer) = pair();
    let mut bytes = [0; 2048];
    a.write(id, &[7; 300]).unwrap();
    a.shutdown(id).unwrap();
    let (output, attempt) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
    let original = output.packet.unwrap();
    let attempt = attempt.unwrap();
    let parsed = wire::parse(original.ip, &bytes[..original.len]).unwrap();
    let start = parsed.header.sequence;
    assert_eq!(parsed.payload.len(), 300);
    assert_ne!(parsed.header.flags & wire::FIN, 0);
    assert_eq!(a.write(id, b"x"), Err(EndpointError::OutputReserved));
    assert_eq!(a.abort(id), Err(EndpointError::OutputReserved));
    assert_eq!(a.release(id), Err(EndpointError::OutputReserved));
    assert_eq!(a.on_timeout(3, 16), Err(EndpointError::OutputReserved));
    assert_eq!(
        a.input(3, original.ip, &bytes[..original.len]),
        Err(EndpointError::OutputReserved)
    );
    assert_eq!(
        a.poll_transmit(3, &mut bytes, 16),
        Err(EndpointError::OutputReserved)
    );
    assert_eq!(
        a.poll_reserved_transmit(3, &mut bytes, 16),
        Err(EndpointError::OutputReserved)
    );
    let progress = a.send_progress(id).unwrap();
    crate::allocation_tests::fail_after(0, || {
        a.set_endpoint_first_hop_mtu(3, 100).unwrap();
        assert!(a.reject_unsubmitted(attempt).unwrap());
        assert!(!a.reject_unsubmitted(attempt).unwrap());
        assert!(!a.accept_transmit(attempt).unwrap());
        let mut total = 0;
        let mut n = 0;
        while a.reservation.current.is_some() {
            let (out, token) = a.poll_reserved_transmit(3, &mut bytes, 16).unwrap();
            let p = out.packet.unwrap();
            let token = token.unwrap();
            let segment = wire::parse(p.ip, &bytes[..p.len]).unwrap();
            assert!(p.len + 20 <= 100);
            assert_eq!(segment.header.sequence, start.wrapping_add(total));
            assert!(segment.payload.iter().all(|&x| x == 7));
            let count = segment.payload.len() as u32;
            assert_eq!(segment.header.flags & wire::FIN != 0, total + count == 300);
            if n == 1 {
                // Reject a later fragment after an accepted prefix, then lower again.
                a.set_first_hop_mtu(3, id, 68).unwrap();
                assert!(a.reject_unsubmitted(token).unwrap());
                assert!(!a.accept_transmit(token).unwrap());
            } else {
                b.input(3, p.ip, &bytes[..p.len]).unwrap();
                assert!(a.accept_transmit(token).unwrap());
                assert!(!a.accept_transmit(token).unwrap());
                total += count;
            }
            n += 1;
            assert!(n < 30);
        }
        assert_eq!(total, 300);
    });
    assert_eq!(a.send_progress(id).unwrap(), progress);
    assert_eq!(b.readable_bytes(peer).unwrap(), 300);
    assert!(a.poll_transmit(3, &mut bytes, 16).unwrap().packet.is_none());
}

#[test]
fn reserved_syn_reset_and_timestamp_cancellation() {
    let mut a = endpoint();
    a.enable_output_reservations().unwrap();
    let id = a
        .connect(
            0,
            "192.0.2.1:1".parse().unwrap(),
            "192.0.2.2:2".parse().unwrap(),
        )
        .unwrap();
    let mut bytes = [0; 2048];
    let (_, token) = a.poll_reserved_transmit(0, &mut bytes, 16).unwrap();
    a.set_first_hop_mtu(0, id, 68).unwrap();
    a.reject_unsubmitted(token.unwrap()).unwrap();
    let (out, token) = a.poll_reserved_transmit(0, &mut bytes, 16).unwrap();
    let p = out.packet.unwrap();
    assert_ne!(
        wire::parse(p.ip, &bytes[..p.len]).unwrap().header.flags & SYN,
        0
    );
    assert_eq!(
        wire::parse(p.ip, &bytes[..p.len]).unwrap().header.flags & (wire::ECE | wire::CWR),
        wire::ECE | wire::CWR,
    );
    a.accept_transmit(token.unwrap()).unwrap();
    assert!(a.poll_transmit(0, &mut bytes, 16).unwrap().packet.is_none());

    let (mut a, _, id, _) = pair();
    a.set_tx_timestamp_capacity(id, 4).unwrap();
    a.write_with_timestamp(
        id,
        b"timestamp",
        false,
        false,
        None,
        crate::TxTimestampRequest {
            cookie: 9,
            scheduled: true,
            software_transmit: true,
            hardware_transmit: true,
            acknowledged: true,
        },
    )
    .unwrap();
    let (_, token) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
    assert_eq!(
        a.next_tx_timestamp(id).unwrap().unwrap().stage,
        TxTimestampStage::Scheduled
    );
    a.reject_unsubmitted(token.unwrap()).unwrap();
    for source in [TxTimestampSource::Software, TxTimestampSource::Hardware] {
        let event = a.next_tx_timestamp(id).unwrap().unwrap();
        assert_eq!(event.stage, TxTimestampStage::Transmit);
        assert_eq!(event.source, source);
        assert_eq!(event.outcome, crate::TxTimestampOutcome::Cancelled);
    }
    let (out, token) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
    assert!(out.packet.unwrap().tx_timestamp.is_none());
    a.accept_transmit(token.unwrap()).unwrap();
    a.abort(id).unwrap();
    let (_, token) = a.poll_reserved_transmit(3, &mut bytes, 16).unwrap();
    a.reject_unsubmitted(token.unwrap()).unwrap();
    assert_eq!(a.release(id), Err(EndpointError::OutputReserved));
    let (out, token) = a.poll_reserved_transmit(4, &mut bytes, 16).unwrap();
    let p = out.packet.unwrap();
    assert_eq!(p.connection, Some(id));
    assert_ne!(
        wire::parse(p.ip, &bytes[..p.len]).unwrap().header.flags & RST,
        0
    );
    a.accept_transmit(token.unwrap()).unwrap();
}

#[test]
fn reserved_ack_dsack_option_splitting_wrap_and_ordinal_exhaustion() {
    let (mut a, _, id, _) = pair();
    let ip = IpMetadata {
        source: a.tuple(id).unwrap().local.ip(),
        destination: a.tuple(id).unwrap().remote.ip(),
    };
    let header = Header {
        source_port: 1,
        destination_port: 2,
        sequence: u32::MAX - 4,
        acknowledgment: 100,
        flags: ACK | wire::FIN | wire::URG,
        window: 512,
        urgent_pointer: 9,
    };
    let mut options = [0; 36];
    options[..4].copy_from_slice(&[1, 1, 5, 34]);
    for i in 0..4 {
        options[4 + i * 8..8 + i * 8].copy_from_slice(&(10 + i as u32 * 10).to_be_bytes());
        options[8 + i * 8..12 + i * 8].copy_from_slice(&(15 + i as u32 * 10).to_be_bytes());
    }
    let mut bytes = [0; 200];
    let len = wire::encode(ip, header, &options, &[3; 20], &mut bytes).unwrap();
    let packet = Transmit {
        connection: Some(id),
        tx_timestamp: None,
        ipv4_options: Default::default(),
        ecn: 0,
        ip,
        len,
        hop_limit: 64,
        dscp: 0,
    };
    let token = a.reservation.token(Some(id)).unwrap();
    a.reservation.capture(packet, &bytes, token);
    a.set_first_hop_mtu(2, id, 68).unwrap();
    a.reject_unsubmitted(token).unwrap();
    let mut blocks = std::vec::Vec::new();
    let mut total = 0;
    while a.reservation.current.is_some() {
        let (out, token) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
        let p = out.packet.unwrap();
        let s = wire::parse(ip, &bytes[..p.len]).unwrap();
        assert!(p.len <= 48);
        assert_eq!(s.header.sequence, header.sequence.wrapping_add(total));
        assert_eq!(s.header.urgent_pointer, 9u16.saturating_sub(total as u16));
        blocks.extend(s.options.sack_blocks.into_iter().flatten());
        total += s.payload.len() as u32;
        assert_eq!(s.header.flags & wire::FIN != 0, total == 20);
        a.accept_transmit(token.unwrap()).unwrap();
    }
    assert_eq!(blocks, [(10, 15), (20, 25), (30, 35), (40, 45)]);
    assert_eq!(total, 20);
    a.reservation.ordinal = u64::MAX;
    a.write(id, b"x").unwrap();
    assert!(a.poll_reserved_transmit(2, &mut bytes, 16).is_err());
    assert!(a.poll_transmit(2, &mut bytes, 16).unwrap().packet.is_some());
}

#[test]
fn reserved_real_ack_keeps_consumed_dsack() {
    let (mut a, mut b, id, peer) = pair();
    // Negotiate SACK in this dedicated pair via the same wire handshake.
    assert!(a.slot(id).unwrap().connection.state() == State::Established);
    let mut bytes = [0; 2048];
    b.write(peer, b"duplicate").unwrap();
    let p = b.poll_transmit(2, &mut bytes, 16).unwrap().packet.unwrap();
    a.input(2, p.ip, &bytes[..p.len]).unwrap();
    a.input(2, p.ip, &bytes[..p.len]).unwrap();
    let (out, token) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
    let p = out.packet.unwrap();
    let s = wire::parse(p.ip, &bytes[..p.len]).unwrap();
    assert!(s.payload.is_empty());
    let blocks = s.options.sack_blocks;
    assert!(blocks[0].is_some());
    a.set_first_hop_mtu(2, id, 68).unwrap();
    a.reject_unsubmitted(token.unwrap()).unwrap();
    let (out, token) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
    let p = out.packet.unwrap();
    assert_eq!(
        wire::parse(p.ip, &bytes[..p.len])
            .unwrap()
            .options
            .sack_blocks,
        blocks
    );
    a.accept_transmit(token.unwrap()).unwrap();
}

#[test]
fn reserved_above_ack_dsack_pair_packs_without_padding_at_ipv4_floor() {
    let (mut a, _, id, _) = pair();
    let ip = IpMetadata {
        source: a.tuple(id).unwrap().local.ip(),
        destination: a.tuple(id).unwrap().remote.ip(),
    };
    let header = Header {
        source_port: 1,
        destination_port: 2,
        sequence: 100,
        acknowledgment: 100,
        flags: ACK,
        window: 512,
        urgent_pointer: 0,
    };
    let mut options = [0; 32];
    options[..12].copy_from_slice(&[1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 1]);
    options[12..16].copy_from_slice(&[1, 1, 5, 18]);
    for (i, seq) in [110u32, 120, 105, 130].into_iter().enumerate() {
        options[16 + i * 4..20 + i * 4].copy_from_slice(&seq.to_be_bytes());
    }
    let mut bytes = [0; 200];
    let len = wire::encode(ip, header, &options, &[], &mut bytes).unwrap();
    let packet = Transmit {
        connection: Some(id),
        tx_timestamp: None,
        ipv4_options: Default::default(),
        ecn: 0,
        ip,
        len,
        hop_limit: 64,
        dscp: 0,
    };
    let token = a.reservation.token(Some(id)).unwrap();
    a.reservation.capture(packet, &bytes, token);
    a.set_first_hop_mtu(2, id, 68).unwrap();
    a.reject_unsubmitted(token).unwrap();
    // Too little space for the pair must not silently change its meaning.
    assert_eq!(
        a.reservation.fragment(44, &mut bytes),
        Err(EndpointError::ReservationMtuTooSmall)
    );
    assert_eq!(a.reservation.current.as_ref().unwrap().sacks, 0);
    let (out, token) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
    let p = out.packet.unwrap();
    assert_eq!(p.len, 48);
    let s = wire::parse(ip, &bytes[..p.len]).unwrap();
    assert_eq!(s.options.timestamps, Some((1, 1)));
    assert_eq!(
        s.options.sack_blocks[..2],
        [Some((110, 120)), Some((105, 130))]
    );
    a.accept_transmit(token.unwrap()).unwrap();
}

#[test]
fn reserved_options_only_fragment_defers_ecn_and_cwr_until_actual_data() {
    let (mut a, _, id, _) = pair();
    let tuple = a.tuple(id).unwrap();
    let ip = IpMetadata {
        source: tuple.local.ip(),
        destination: tuple.remote.ip(),
    };
    let header = Header {
        source_port: tuple.local.port(),
        destination_port: tuple.remote.port(),
        sequence: u32::MAX - 4,
        acknowledgment: 100,
        flags: ACK | wire::CWR,
        window: 512,
        urgent_pointer: 0,
    };
    let mut options = [0; 32];
    options[..12].copy_from_slice(&[1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 1]);
    options[12..16].copy_from_slice(&[1, 1, 5, 18]);
    for (i, seq) in [110u32, 120, 105, 130].into_iter().enumerate() {
        options[16 + i * 4..20 + i * 4].copy_from_slice(&seq.to_be_bytes());
    }
    let mut bytes = [0; 200];
    let len = wire::encode(ip, header, &options, &[7; 40], &mut bytes).unwrap();
    let token = a.reservation.token(Some(id)).unwrap();
    a.reservation.capture(
        Transmit {
            connection: Some(id),
            tx_timestamp: None,
            ipv4_options: Default::default(),
            ecn: 2,
            ip,
            len,
            hop_limit: 64,
            dscp: 0,
        },
        &bytes,
        token,
    );
    a.set_first_hop_mtu(2, id, 68).unwrap();
    a.reject_unsubmitted(token).unwrap();
    let mut total = 0;
    let mut pure_acks = 0;
    let mut cwr_packets = 0;
    let mut rejected_data = false;
    while a.reservation.current.is_some() {
        let (out, token) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
        let p = out.packet.unwrap();
        let token = token.unwrap();
        let s = wire::parse(ip, &bytes[..p.len]).unwrap();
        assert!(p.len + 20 <= 68);
        assert_eq!(s.header.sequence, header.sequence.wrapping_add(total));
        if s.payload.is_empty() {
            assert_eq!(p.ecn, 0);
            assert_eq!(s.header.flags & wire::CWR, 0);
            assert_eq!(
                s.options.sack_blocks[..2],
                [Some((110, 120)), Some((105, 130))]
            );
            pure_acks += 1;
        } else {
            assert_eq!(p.ecn, 2);
            assert_eq!(s.header.flags & wire::CWR != 0, total == 0);
            // Rejection of the first data attempt cannot consume its CWR obligation.
            if !rejected_data {
                a.reject_unsubmitted(token).unwrap();
                rejected_data = true;
                continue;
            }
            cwr_packets += usize::from(s.header.flags & wire::CWR != 0);
            total += s.payload.len() as u32;
        }
        a.accept_transmit(token).unwrap();
    }
    assert_eq!((pure_acks, cwr_packets, total), (1, 1, 40));
}

#[test]
fn reserved_released_reset_owner_and_listener_cleanup_can_repair() {
    let (mut a, _, id, _) = pair();
    a.abort(id).unwrap();
    a.release(id).unwrap();
    let mut bytes = [0; 2048];
    let (_, token) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
    assert!(a.reject_unsubmitted(token.unwrap()).unwrap());
    let (out, token) = a.poll_reserved_transmit(3, &mut bytes, 16).unwrap();
    let p = out.packet.unwrap();
    assert_eq!(p.connection, Some(id));
    assert_ne!(
        wire::parse(p.ip, &bytes[..p.len]).unwrap().header.flags & RST,
        0
    );
    assert!(a.accept_transmit(token.unwrap()).unwrap());
    assert!(a.connection_exists(id)); // Retained for reset tuple protection.

    let mut a = endpoint();
    let mut b = endpoint();
    b.enable_output_reservations().unwrap();
    let local = "192.0.2.1:40000".parse().unwrap();
    let remote = "192.0.2.2:8080".parse().unwrap();
    let listener = b.listen(remote, 4).unwrap();
    a.connect(0, local, remote).unwrap();
    let p = a.poll_transmit(1, &mut bytes, 16).unwrap().packet.unwrap();
    b.input(1, p.ip, &bytes[..p.len]).unwrap();
    let child = b
        .connection_id(Tuple {
            local: remote,
            remote: local,
        })
        .unwrap();
    b.close_listener(listener).unwrap();
    let (out, token) = b.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
    assert_eq!(out.packet.unwrap().connection, Some(child));
    assert!(b.retained_slot(child).unwrap().released);
    b.reject_unsubmitted(token.unwrap()).unwrap();
    let (out, token) = b.poll_reserved_transmit(3, &mut bytes, 16).unwrap();
    let p = out.packet.unwrap();
    assert_ne!(
        wire::parse(p.ip, &bytes[..p.len]).unwrap().header.flags & RST,
        0
    );
    b.accept_transmit(token.unwrap()).unwrap();
}

#[test]
fn reserved_abandon_after_impossible_headers_fails_only_owner_and_reclaims() {
    let (mut a, mut b, healthy, peer) = pair();
    a.config.ipv4_options_enabled = true;
    a.enable_output_reservations().unwrap();
    let allocation = a.buffer_bytes();
    let id = a
        .connect_with_ipv4_options(
            1,
            "192.0.2.1:40001".parse().unwrap(),
            "192.0.2.2:8080".parse().unwrap(),
            OutgoingIpv4Options {
                source_route: Some(
                    SourceRoute::new(&["192.0.2.3".parse().unwrap(); 9], false).unwrap(),
                ),
                ..Default::default()
            },
        )
        .unwrap();
    let mut bytes = [0; 2048];
    let (out, token) = a.poll_reserved_transmit(1, &mut bytes, 16).unwrap();
    assert_eq!(out.packet.unwrap().connection, Some(id));
    let token = token.unwrap();
    a.set_first_hop_mtu(2, id, 68).unwrap();
    a.reject_unsubmitted(token).unwrap();
    assert_eq!(
        a.poll_reserved_transmit(2, &mut bytes, 16),
        Err(EndpointError::ReservationMtuTooSmall)
    );
    assert!(a.abandon_transmit(token).unwrap());
    assert!(!a.abandon_transmit(token).unwrap());
    assert_eq!(
        a.close_reason(id).unwrap(),
        Some(crate::CloseReason::Aborted)
    );
    assert_eq!(a.state(healthy).unwrap(), State::Established);
    a.release(id).unwrap();
    assert!(!a.connection_exists(id));
    assert_eq!(a.buffer_bytes(), allocation);
    a.write(healthy, b"healthy").unwrap();
    let p = a.poll_transmit(2, &mut bytes, 16).unwrap().packet.unwrap();
    assert_eq!(p.connection, Some(healthy));
    assert_eq!(
        wire::parse(p.ip, &bytes[..p.len]).unwrap().header.flags & RST,
        0
    );
    b.input(2, p.ip, &bytes[..p.len]).unwrap();
    assert_eq!(b.readable_bytes(peer).unwrap(), 7);
}

#[test]
fn reserved_abandon_wouldblock_and_stale_handles_and_admission_barrier() {
    let (mut a, _, id, _) = pair();
    a.write(id, &[1; 100]).unwrap();
    let mut bytes = [0; 2048];
    let (_, first) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
    let first = first.unwrap();
    let mut consumed = false;
    let admission = a
        .check_write_admission(id, None, TxTimestampRequest::default())
        .map(|_| {
            consumed = true;
        });
    assert_eq!(admission, Err(EndpointError::OutputReserved));
    assert!(!consumed);
    assert_eq!(
        a.send_admission_room(id, None),
        Err(EndpointError::OutputReserved)
    );
    a.reject_unsubmitted(first).unwrap();
    let (_, second) = a.poll_reserved_transmit(3, &mut bytes, 16).unwrap();
    let second = second.unwrap();
    assert!(!a.abandon_transmit(first).unwrap());
    // Adapter's own bounded WouldBlock deadline: no timeout/input call is needed.
    assert!(a.abandon_transmit(second).unwrap());
    assert!(!a.abandon_transmit(second).unwrap());
    assert!(a.poll_transmit(4, &mut bytes, 16).unwrap().packet.is_none());
    assert_eq!(
        a.close_reason(id).unwrap(),
        Some(crate::CloseReason::Aborted)
    );
}

#[test]
fn reserved_abandon_accepted_prefix_encode_error_and_stateless_discard() {
    let (mut a, mut b, id, peer) = pair();
    a.write(id, &[1; 100]).unwrap();
    let mut bytes = [0; 2048];
    let (_, first) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
    let first = first.unwrap();
    a.set_first_hop_mtu(2, id, 68).unwrap();
    a.reject_unsubmitted(first).unwrap();
    let (out, prefix) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
    let p = out.packet.unwrap();
    let prefix = prefix.unwrap();
    b.input(2, p.ip, &bytes[..p.len]).unwrap();
    a.accept_transmit(prefix).unwrap();
    assert_eq!(b.readable_bytes(peer).unwrap(), 28);
    assert!(a.poll_reserved_transmit(2, &mut [], 16).is_err());
    assert!(!a.abandon_transmit(first).unwrap());
    crate::allocation_tests::fail_after(0, || {
        assert!(a.abandon_transmit(prefix).unwrap());
        a.release(id).unwrap();
    });
    assert!(!a.connection_exists(id));
    assert!(a.poll_transmit(2, &mut bytes, 16).unwrap().packet.is_none());

    let mut a = endpoint();
    let mut b = endpoint();
    b.enable_output_reservations().unwrap();
    a.connect(
        0,
        "192.0.2.1:1".parse().unwrap(),
        "192.0.2.2:2".parse().unwrap(),
    )
    .unwrap();
    let p = a.poll_transmit(1, &mut bytes, 16).unwrap().packet.unwrap();
    b.input(1, p.ip, &bytes[..p.len]).unwrap();
    let (out, token) = b.poll_reserved_transmit(1, &mut bytes, 16).unwrap();
    let token = token.unwrap();
    assert_eq!(out.packet.unwrap().connection, None);
    assert!(b.abandon_transmit(token).unwrap());
    assert!(!b.abandon_transmit(token).unwrap());
    assert!(!b.has_pending_output());
}
