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
