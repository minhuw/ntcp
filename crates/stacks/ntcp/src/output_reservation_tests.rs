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
    paced_pair(None)
}

fn paced_pair(pacing: Option<bool>) -> (Endpoint, Endpoint, ConnectionId, ConnectionId) {
    configured_pair(pacing, None)
}

fn configured_pair(
    pacing: Option<bool>,
    granularity: Option<crate::TimestampGranularity>,
) -> (Endpoint, Endpoint, ConnectionId, ConnectionId) {
    let mut a = endpoint();
    let mut b = endpoint();
    if let Some(granularity) = granularity {
        a.config.connection.timestamps = true;
        b.config.connection.timestamps = true;
        a.config.connection.timestamp_granularity = granularity;
        b.config.connection.timestamp_granularity = granularity;
    }
    if let Some(general) = pacing {
        a.config.connection.prr = !general;
        a.config.connection.prr_algorithm = crate::PrrAlgorithm::Rfc9937;
        if general {
            a.config.connection.pacing = Some(crate::PacingConfig {
                max_burst_segments: 1,
                ..Default::default()
            });
        }
    }
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
    // Timers and output now skip only the held owner. Ingress is routed before
    // exclusion: this outbound packet is unknown-tuple input, not input to id.
    assert_eq!(a.on_timeout(3, 16), Ok(false));
    assert_eq!(
        a.input(3, original.ip, &bytes[..original.len]),
        Ok(InputDisposition::Dropped)
    );
    let stateless = a.poll_transmit(3, &mut bytes, 16).unwrap().packet.unwrap();
    assert_eq!(stateless.connection, None);
    assert_eq!(
        a.poll_reserved_transmit(3, &mut bytes, 16),
        Err(EndpointError::OutputReserved)
    );
    let progress = a.send_progress(id).unwrap();
    crate::allocation_tests::fail_after(0, || {
        a.set_endpoint_first_hop_mtu(3, 100).unwrap();
        assert!(a.reject_unsubmitted(attempt).unwrap());
        assert!(!a.reject_unsubmitted(attempt).unwrap());
        assert!(!a.accept_transmit(a.now, attempt).unwrap());
        let mut total = 0;
        let mut n = 0;
        while a.reservations[0].current.is_some() {
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
                assert!(!a.accept_transmit(a.now, token).unwrap());
            } else {
                b.input(3, p.ip, &bytes[..p.len]).unwrap();
                assert!(a.accept_transmit(a.now, token).unwrap());
                assert!(!a.accept_transmit(a.now, token).unwrap());
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
    a.accept_transmit(a.now, token.unwrap()).unwrap();
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
    a.accept_transmit(a.now, token.unwrap()).unwrap();
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
    a.accept_transmit(a.now, token.unwrap()).unwrap();
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
    let token = a.reservations[0].token(Some(id)).unwrap();
    a.reservations[0].capture(packet, &bytes, token);
    a.set_first_hop_mtu(2, id, 68).unwrap();
    a.reject_unsubmitted(token).unwrap();
    let mut blocks = std::vec::Vec::new();
    let mut total = 0;
    while a.reservations[0].current.is_some() {
        let (out, token) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
        let p = out.packet.unwrap();
        let s = wire::parse(ip, &bytes[..p.len]).unwrap();
        assert!(p.len <= 48);
        assert_eq!(s.header.sequence, header.sequence.wrapping_add(total));
        assert_eq!(s.header.urgent_pointer, 9u16.saturating_sub(total as u16));
        blocks.extend(s.options.sack_blocks.into_iter().flatten());
        total += s.payload.len() as u32;
        assert_eq!(s.header.flags & wire::FIN != 0, total == 20);
        a.accept_transmit(a.now, token.unwrap()).unwrap();
    }
    assert_eq!(blocks, [(10, 15), (20, 25), (30, 35), (40, 45)]);
    assert_eq!(total, 20);
    a.reservations[0].ordinal = u64::MAX;
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
    a.accept_transmit(a.now, token.unwrap()).unwrap();
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
    let token = a.reservations[0].token(Some(id)).unwrap();
    a.reservations[0].capture(packet, &bytes, token);
    a.set_first_hop_mtu(2, id, 68).unwrap();
    a.reject_unsubmitted(token).unwrap();
    // Too little space for the pair must not silently change its meaning.
    assert_eq!(
        a.reservations[0].fragment(44, &mut bytes),
        Err(EndpointError::ReservationMtuTooSmall)
    );
    assert_eq!(a.reservations[0].current.as_ref().unwrap().sacks, 0);
    let (out, token) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
    let p = out.packet.unwrap();
    assert_eq!(p.len, 48);
    let s = wire::parse(ip, &bytes[..p.len]).unwrap();
    assert_eq!(s.options.timestamps, Some((1, 1)));
    assert_eq!(
        s.options.sack_blocks[..2],
        [Some((110, 120)), Some((105, 130))]
    );
    a.accept_transmit(a.now, token.unwrap()).unwrap();
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
    let token = a.reservations[0].token(Some(id)).unwrap();
    a.reservations[0].capture(
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
    while a.reservations[0].current.is_some() {
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
        a.accept_transmit(a.now, token).unwrap();
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
    assert!(a.accept_transmit(a.now, token.unwrap()).unwrap());
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
    b.accept_transmit(b.now, token.unwrap()).unwrap();
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
    a.accept_transmit(a.now, prefix).unwrap();
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

#[test]
fn review_repro_delayed_acceptance_must_not_timeout() {
    let (mut a, _, id, _) = pair();
    a.write(id, &[1; 100]).unwrap();
    let mut bytes = [0; 2048];
    let (_, token) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
    a.reject_unsubmitted(token.unwrap()).unwrap();
    let (_, token) = a.poll_reserved_transmit(2_000_002, &mut bytes, 16).unwrap();
    a.accept_transmit(2_000_002, token.unwrap()).unwrap();
    let cwnd = a.transport_info(id).unwrap().cwnd;
    a.on_timeout(2_000_002, 16).unwrap();
    assert_eq!(
        a.transport_info(id).unwrap().cwnd,
        cwnd,
        "local wait must not cause congestion response"
    );
    assert!(
        a.poll_transmit(2_000_002, &mut bytes, 16)
            .unwrap()
            .packet
            .is_none()
    );
}

#[test]
fn review_repro_delayed_acceptance_must_charge_actual_departure() {
    for general in [false, true] {
        let (mut a, _, id, _) = paced_pair(Some(general));
        let mut bytes = [0; 2048];
        a.write(id, &[1; 2000]).unwrap();
        let (_, token) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
        a.reject_unsubmitted(token.unwrap()).unwrap();
        let (_, token) = a.poll_reserved_transmit(2_000_002, &mut bytes, 16).unwrap();
        a.accept_transmit(2_000_002, token.unwrap()).unwrap();
        assert!(
            a.poll_transmit(2_000_002, &mut bytes, 16)
                .unwrap()
                .packet
                .is_none(),
            "general={general}: local repair must leave departure pacing debt"
        );
    }
}

#[test]
fn reserved_acceptance_time_validation_is_atomic_and_tokens_are_single_use() {
    for late in [2, 2_000_002] {
        let (mut a, _, id, _) = pair();
        a.write(id, &[1; 100]).unwrap();
        let mut bytes = [0; 2048];
        let (_, token) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
        let token = token.unwrap();
        let progress = a.send_progress(id).unwrap();
        assert_eq!(
            a.accept_transmit(1, token),
            Err(Error::TimeWentBackwards.into())
        );
        assert_eq!(a.now, 2);
        assert_eq!(a.send_progress(id).unwrap(), progress);
        assert_eq!(
            a.reservations[0].current.as_ref().unwrap().attempt,
            Some(token)
        );
        a.config.connection.timestamps = true;
        assert_eq!(
            a.accept_transmit(u64::MAX, token),
            Err(Error::AmbiguousTimeJump.into())
        );
        assert_eq!(a.now, 2);
        assert_eq!(
            a.reservations[0].current.as_ref().unwrap().attempt,
            Some(token)
        );
        assert!(a.accept_transmit(late, token).unwrap());
        assert!(!a.accept_transmit(u64::MAX, token).unwrap());
        assert!(!a.reject_unsubmitted(token).unwrap());
        assert_eq!(a.now, late);
        let cwnd = a.transport_info(id).unwrap().cwnd;
        a.on_timeout(late, 16).unwrap();
        assert_eq!(a.transport_info(id).unwrap().cwnd, cwnd);
        assert!(
            a.poll_transmit(late, &mut bytes, 16)
                .unwrap()
                .packet
                .is_none()
        );
    }
}

#[test]
fn reserved_pacing_gates_each_fragment_and_late_acceptance_has_no_catchup() {
    for general in [false, true] {
        let (mut a, _, id, _) = paced_pair(Some(general));
        a.write(id, &[1; 2000]).unwrap();
        let mut bytes = [0; 2048];
        let (_, token) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
        a.set_first_hop_mtu(3, id, 200).unwrap();
        a.reject_unsubmitted(token.unwrap()).unwrap();
        let mut now = 2_000_002;
        let mut total = 0;
        while a.reservations[0].current.is_some() {
            let (out, token) = a.poll_reserved_transmit(now, &mut bytes, 16).unwrap();
            let p = out.packet.unwrap();
            let n = wire::parse(p.ip, &bytes[..p.len]).unwrap().payload.len();
            assert!(n > 0 && n <= 160);
            total += n;
            // Backend wait is not idle pacing credit for the accepted bytes.
            now += 2_000_000;
            a.accept_transmit(now, token.unwrap()).unwrap();
            if a.reservations[0].current.is_some() {
                let (out, token) = a.poll_reserved_transmit(now, &mut bytes, 16).unwrap();
                assert!(out.packet.is_none() && token.is_none(), "general={general}");
                let deadline = a.next_deadline().unwrap();
                assert!(deadline > now);
                assert!(
                    a.poll_reserved_transmit(deadline - 1, &mut bytes, 16)
                        .unwrap()
                        .0
                        .packet
                        .is_none()
                );
                now = deadline;
            }
        }
        assert_eq!(total, 1000);
        assert!(
            a.poll_transmit(now, &mut bytes, 16)
                .unwrap()
                .packet
                .is_none(),
            "general={general}"
        );
    }
}

#[test]
fn reserved_acceptance_survives_successive_mtu_clock_advances() {
    for endpoint_wide in [false, true] {
        for repair in [false, true] {
            let (mut a, _, id, _) =
                configured_pair(None, Some(crate::TimestampGranularity::Microseconds));
            a.set_user_timeout(id, 10_000_000_000).unwrap();
            a.write(id, &[1; 100]).unwrap();
            let mut bytes = [0; 2048];
            let (_, token) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
            let mut token = token.unwrap();
            let progress = a.send_progress(id).unwrap();
            for step in 1..=2 {
                let now = 2 + step * (1 << 30);
                if endpoint_wide {
                    a.set_endpoint_first_hop_mtu(now, 100).unwrap();
                } else {
                    a.set_first_hop_mtu(now, id, 100).unwrap();
                }
                assert_eq!(a.now, now);
                assert_eq!(
                    a.reservations[0].current.as_ref().unwrap().attempt,
                    Some(token)
                );
            }
            let now = a.now;
            let invalid_mtu = if endpoint_wide {
                a.set_endpoint_first_hop_mtu(now + 1, 67)
            } else {
                a.set_first_hop_mtu(now + 1, id, 67)
            };
            assert_eq!(invalid_mtu, Err(Error::InvalidArgument.into()));
            assert_eq!(a.now, now);
            assert_eq!(
                a.accept_transmit(now - 1, token),
                Err(Error::TimeWentBackwards.into())
            );
            assert_eq!(a.now, now);
            if repair {
                a.reject_unsubmitted(token).unwrap();
                token = a
                    .poll_reserved_transmit(now, &mut bytes, 16)
                    .unwrap()
                    .1
                    .unwrap();
            }
            assert!(a.accept_transmit(now, token).unwrap());
            while a.reservations[0].current.is_some() {
                let token = a
                    .poll_reserved_transmit(now, &mut bytes, 16)
                    .unwrap()
                    .1
                    .unwrap();
                assert!(a.accept_transmit(now, token).unwrap());
            }
            assert_eq!(a.send_progress(id).unwrap(), progress);
            let cwnd = a.transport_info(id).unwrap().cwnd;
            a.on_timeout(now, 16).unwrap();
            assert_eq!(a.state(id).unwrap(), State::Established);
            assert_eq!(a.transport_info(id).unwrap().cwnd, cwnd);
            assert!(!a.accept_transmit(u64::MAX, token).unwrap());
            assert_eq!(a.now, now);
        }
    }
}

#[test]
fn reserved_departure_preflight_failure_does_not_advance_endpoint_clock() {
    let (mut a, _, id, _) = pair();
    a.write(id, &[1; 100]).unwrap();
    let mut bytes = [0; 2048];
    let (_, token) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
    let token = token.unwrap();
    let progress = a.send_progress(id).unwrap();
    // Corrupt only the private departure range to exercise a ledger validation
    // failure, distinct from the public time/token checks.
    let d = a.reservations[0]
        .current
        .as_mut()
        .unwrap()
        .departure
        .as_mut()
        .unwrap();
    let start = d.start;
    d.start = start.wrapping_add(1);
    assert_eq!(
        a.accept_transmit(100, token),
        Err(Error::InvalidArgument.into())
    );
    assert_eq!(a.now, 2);
    assert_eq!(a.send_progress(id).unwrap(), progress);
    assert_eq!(
        a.reservations[0].current.as_ref().unwrap().attempt,
        Some(token)
    );
    a.reservations[0]
        .current
        .as_mut()
        .unwrap()
        .departure
        .as_mut()
        .unwrap()
        .start = start;
    // An earlier valid accept proves neither connection nor endpoint clock moved.
    assert!(a.accept_transmit(3, token).unwrap());
}

fn two_flows() -> (Endpoint, Endpoint, [ConnectionId; 2], [ConnectionId; 2]) {
    let mut a = endpoint();
    let mut b = endpoint();
    let remote = "192.0.2.2:8080".parse().unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let mut clients = std::vec::Vec::new();
    let mut peers = std::vec::Vec::new();
    let mut bytes = [0; 2048];
    for port in [40000, 40001] {
        let local = SocketAddr::new("192.0.2.1".parse().unwrap(), port);
        clients.push(a.connect(0, local, remote).unwrap());
        for step in 0..3 {
            let (src, dst) = if step == 1 {
                (&mut b, &mut a)
            } else {
                (&mut a, &mut b)
            };
            let p = src
                .poll_transmit(0, &mut bytes, 16)
                .unwrap()
                .packet
                .unwrap();
            dst.input(0, p.ip, &bytes[..p.len]).unwrap();
        }
        peers.push(b.accept(listener).unwrap());
    }
    a.enable_output_reservations_with_capacity(2).unwrap();
    (a, b, clients.try_into().unwrap(), peers.try_into().unwrap())
}

#[test]
fn pool_two_active_flows_progress_while_one_backend_would_block() {
    let (mut a, mut b, [held, other], [held_peer, other_peer]) = two_flows();
    let mut bytes = [0; 2048];
    a.write(held, b"backend blocked").unwrap();
    let (_, held_attempt) = a
        .poll_reserved_transmit_for(1, held, &mut bytes, 1)
        .unwrap();
    let held_attempt = held_attempt.unwrap();
    let progress = a.send_progress(held).unwrap();
    let owner_info = a.slot(held).unwrap().connection.transport_info();
    assert!(a.is_output_reserved(held));
    assert!(!a.ready_connections().any(|id| id == held));

    b.write(held_peer, b"deferred input").unwrap();
    let p = b.poll_transmit(2, &mut bytes, 16).unwrap().packet.unwrap();
    let mut held_input = [0; 2048];
    held_input[..p.len].copy_from_slice(&bytes[..p.len]);
    assert_eq!(
        a.input(2, p.ip, &held_input[..p.len]),
        Err(EndpointError::OutputReserved)
    );
    assert_eq!(a.now, 1);
    assert_eq!(a.readable_bytes(held).unwrap(), 0);
    // Invalid packets are parsed/dropped, not spuriously deferred.
    assert_eq!(a.input(2, p.ip, &[0; 10]), Ok(InputDisposition::Dropped));

    b.write(other_peer, b"independent input").unwrap();
    let q = b.poll_transmit(2, &mut bytes, 16).unwrap().packet.unwrap();
    assert_eq!(q.connection, Some(other_peer));
    assert_eq!(
        a.input(2, q.ip, &bytes[..q.len]),
        Ok(InputDisposition::Processed)
    );
    assert_eq!(a.readable_bytes(other).unwrap(), 17);
    a.write(other, b"independent output").unwrap();
    assert!(a.ready_connections().any(|id| id == other));
    crate::allocation_tests::fail_after(0, || {
        let (q, attempt) = a
            .poll_reserved_transmit_for(3, other, &mut bytes, 1)
            .unwrap();
        assert_eq!(q.packet.unwrap().connection, Some(other));
        let attempt = attempt.unwrap();
        assert_ne!(attempt, held_attempt); // Both slots' first ordinal is one.
        assert!(a.accept_transmit(4, attempt).unwrap());
        assert!(!a.reject_unsubmitted(attempt).unwrap());
        assert!(!a.abandon_transmit(attempt).unwrap());
        assert!(a.is_output_reserved(held));
        let deadline = a.next_deadline().unwrap();
        assert!(deadline > 4);
        assert!(!a.on_timeout(deadline, 16).unwrap());
        let (q, attempt) = a.poll_reserved_transmit(deadline, &mut bytes, 16).unwrap();
        assert_eq!(q.packet.unwrap().connection, Some(other));
        assert!(a.accept_transmit(deadline, attempt.unwrap()).unwrap());
    });
    assert_eq!(a.send_progress(held).unwrap(), progress);
    assert_eq!(
        a.slot(held).unwrap().connection.transport_info(),
        owner_info
    );
    // An older observed time cannot move the endpoint backwards or consume A.
    assert_eq!(
        a.accept_transmit(3, held_attempt),
        Err(Error::TimeWentBackwards.into())
    );
    assert!(a.is_output_reserved(held));
    assert!(a.accept_transmit(a.now, held_attempt).unwrap());
    assert_eq!(
        a.input(a.now, p.ip, &held_input[..p.len]),
        Ok(InputDisposition::Processed)
    );
    assert_eq!(a.readable_bytes(held).unwrap(), 14);
}

#[test]
fn pool_full_and_selected_budget_leave_ready_and_tcp_unchanged() {
    let (mut a, _, [one, two], _) = two_flows();
    let third = a
        .connect(
            1,
            "192.0.2.1:40002".parse().unwrap(),
            "192.0.2.2:8080".parse().unwrap(),
        )
        .unwrap();
    a.write(one, b"one").unwrap();
    a.write(two, b"two").unwrap();
    let mut bytes = [0; 2048];
    let zero = a.send_progress(one).unwrap();
    assert!(
        a.poll_reserved_transmit_for(1, one, &mut bytes, 0)
            .unwrap()
            .0
            .packet
            .is_none()
    );
    assert_eq!(a.send_progress(one).unwrap(), zero);
    let (_, first) = a.poll_reserved_transmit_for(1, one, &mut bytes, 1).unwrap();
    let (_, second) = a.poll_reserved_transmit_for(1, two, &mut bytes, 1).unwrap();
    let before = a.send_progress(third).unwrap();
    let queue: std::vec::Vec<_> = a.output.iter().collect();
    let deadline = a.next_deadline();
    assert_eq!(
        a.poll_reserved_transmit_for(9, third, &mut bytes, 16),
        Err(EndpointError::OutputReserved)
    );
    assert_eq!(
        a.poll_reserved_transmit(9, &mut bytes, 16),
        Err(EndpointError::OutputReserved)
    );
    assert_eq!(
        a.poll_reserved_stateless_transmit(9, &mut bytes, 16),
        Err(EndpointError::OutputReserved)
    );
    assert_eq!(a.now, 1);
    assert_eq!(a.send_progress(third).unwrap(), before);
    assert_eq!(a.output.iter().collect::<std::vec::Vec<_>>(), queue);
    assert_eq!(a.next_deadline(), deadline);
    assert_eq!(a.write(one, b"no"), Err(EndpointError::OutputReserved));
    assert_eq!(a.read(two, &mut bytes), Err(EndpointError::OutputReserved));
    assert_eq!(a.set_nagle(two, true), Err(EndpointError::OutputReserved));
    assert_eq!(
        a.check_write_admission(two, None, Default::default()),
        Err(EndpointError::OutputReserved)
    );
    a.accept_transmit(9, second.unwrap()).unwrap();
    let (out, third_attempt) = a
        .poll_reserved_transmit_for(9, third, &mut bytes, 1)
        .unwrap();
    assert_eq!(out.packet.unwrap().connection, Some(third));
    assert!(!a.accept_transmit(9, second.unwrap()).unwrap());
    a.abandon_transmit(third_attempt.unwrap()).unwrap();
    a.release(third).unwrap();
    let recycled = a
        .connect(
            9,
            "192.0.2.1:40003".parse().unwrap(),
            "192.0.2.2:8080".parse().unwrap(),
        )
        .unwrap();
    assert_eq!(recycled.slot, third.slot);
    assert_ne!(recycled, third);
    assert_eq!(
        a.poll_reserved_transmit_for(9, third, &mut bytes, 1),
        Err(EndpointError::InvalidHandle)
    );
    assert!(!a.abandon_transmit(third_attempt.unwrap()).unwrap());
    assert!(a.is_output_reserved(one));
    a.accept_transmit(9, first.unwrap()).unwrap();
}

#[test]
fn pool_allocation_budget_and_failure_are_atomic() {
    let mut a = endpoint();
    let before = a.buffer_bytes();
    let charge = 2
        * (a.config.connection.send_ip_payload_limit as usize
            + core::mem::size_of::<crate::output_reservation::OutputReservation>());
    a.config.max_buffer_bytes = before + charge - 1;
    assert_eq!(
        a.enable_output_reservations_with_capacity(2),
        Err(Error::NoMemory.into())
    );
    assert_eq!(a.buffer_bytes(), before);
    assert!(a.reservations.is_empty());
    a.config.max_buffer_bytes += 1;
    for fail in 0..3 {
        // Metadata allocation, first packet buffer, second buffer.
        assert_eq!(
            crate::allocation_tests::fail_after(fail, || a
                .enable_output_reservations_with_capacity(2)),
            Err(Error::NoMemory.into())
        );
        assert_eq!(a.buffer_bytes(), before);
        assert!(a.reservations.is_empty());
    }
    assert_eq!(
        a.enable_output_reservations_with_capacity(0),
        Err(Error::InvalidArgument.into())
    );
    assert_eq!(
        a.enable_output_reservations_with_capacity(usize::MAX),
        Err(Error::InvalidArgument.into())
    );
    a.enable_output_reservations_with_capacity(2).unwrap();
    assert_eq!(a.buffer_bytes(), before + charge);
    a.enable_output_reservations_with_capacity(2).unwrap();
    assert_eq!(a.buffer_bytes(), before + charge);
}

#[test]
fn pool_held_old_timer_is_removed_and_restored_without_blocking_other_due_timer() {
    let (mut a, _, [held, other], _) = two_flows();
    let mut bytes = [0; 2048];
    a.write(held, b"older flight").unwrap();
    let (_, first) = a
        .poll_reserved_transmit_for(1, held, &mut bytes, 1)
        .unwrap();
    a.accept_transmit(1, first.unwrap()).unwrap();
    let held_deadline = a.next_deadline().unwrap();
    a.write(held, b"blocked flight").unwrap();
    let (_, pending) = a
        .poll_reserved_transmit_for(2, held, &mut bytes, 1)
        .unwrap();
    assert_eq!(a.next_deadline(), None);
    a.write(other, b"other flight").unwrap();
    let (_, sent) = a
        .poll_reserved_transmit_for(3, other, &mut bytes, 1)
        .unwrap();
    a.accept_transmit(3, sent.unwrap()).unwrap();
    let other_deadline = a.next_deadline().unwrap();
    assert!(other_deadline > held_deadline);
    assert!(!a.on_timeout(other_deadline, 1).unwrap());
    assert_eq!(
        a.slot(held).unwrap().connection.next_deadline(),
        Some(held_deadline)
    );
    let (out, retry) = a
        .poll_reserved_transmit_for(other_deadline, other, &mut bytes, 1)
        .unwrap();
    assert_eq!(out.packet.unwrap().connection, Some(other));
    a.accept_transmit(other_deadline, retry.unwrap()).unwrap();
    a.accept_transmit(other_deadline, pending.unwrap()).unwrap();
    assert_eq!(a.next_deadline(), Some(held_deadline));
    assert!(!a.on_timeout(other_deadline, 1).unwrap());
}

#[test]
fn pool_fragment_repair_timestamp_cancellation_and_pacing_are_owner_local() {
    let (mut a, _, [one, two], _) = two_flows();
    let mut bytes = [0; 2048];
    a.set_tx_timestamp_capacity(one, 4).unwrap();
    a.write_with_timestamp(
        one,
        &[7; 300],
        false,
        false,
        None,
        TxTimestampRequest {
            cookie: 42,
            software_transmit: true,
            ..Default::default()
        },
    )
    .unwrap();
    a.write(two, &[8; 300]).unwrap();
    let (_, first) = a.poll_reserved_transmit_for(1, one, &mut bytes, 1).unwrap();
    let (_, second) = a.poll_reserved_transmit_for(1, two, &mut bytes, 1).unwrap();
    let first = first.unwrap();
    let second = second.unwrap();
    crate::allocation_tests::fail_after(0, || {
        a.set_endpoint_first_hop_mtu(2, 100).unwrap();
        a.reject_unsubmitted(first).unwrap();
        // Rejection and timestamp cancellation cannot touch the other pool slot.
        assert!(!a.accept_transmit(2, first).unwrap());
        assert!(a.is_output_reserved(two));
        assert!(a.next_tx_timestamp(one).unwrap().is_some());
        let (out, prefix) = a.poll_reserved_transmit_for(2, one, &mut bytes, 1).unwrap();
        assert!(out.packet.unwrap().len <= 80);
        let prefix = prefix.unwrap();
        assert!(a.accept_transmit(2, prefix).unwrap());
        assert!(a.is_output_reserved(one));
        assert!(!a.accept_transmit(2, prefix).unwrap());
        a.reject_unsubmitted(second).unwrap();
        let (out, retry) = a.poll_reserved_transmit(2, &mut bytes, 1).unwrap();
        assert_eq!(out.packet.unwrap().connection, Some(two));
        assert!(a.abandon_transmit(retry.unwrap()).unwrap());
        assert!(a.is_output_reserved(one));
        assert!(!a.abandon_transmit(first).unwrap());
        // Latest accepted prefix remains the cancellation authority until retry.
        assert!(a.abandon_transmit(prefix).unwrap());
    });
}

#[test]
fn pool_stateless_lane_and_released_terminal_owner_keep_separate_tickets() {
    let (mut a, mut b, [one, two], [peer, _]) = two_flows();
    let mut bytes = [0; 2048];
    a.abort(one).unwrap();
    a.release(one).unwrap();
    let (out, terminal) = a.poll_reserved_transmit_for(1, one, &mut bytes, 1).unwrap();
    let p = out.packet.unwrap();
    assert_eq!(p.connection, Some(one));
    // A late peer packet to the retained reset owner is deferred before mutation.
    b.write(peer, b"late").unwrap();
    let late = b.poll_transmit(1, &mut bytes, 16).unwrap().packet.unwrap();
    assert_eq!(
        a.input(1, late.ip, &bytes[..late.len]),
        Err(EndpointError::OutputReserved)
    );
    // Same valid segment in the opposite direction has no owner at this endpoint.
    a.input(
        1,
        IpMetadata {
            source: late.ip.destination,
            destination: late.ip.source,
        },
        &[0; 20],
    )
    .unwrap();
    let ip = IpMetadata {
        source: "192.0.2.3".parse().unwrap(),
        destination: "192.0.2.1".parse().unwrap(),
    };
    let len = wire::encode(
        ip,
        Header {
            source_port: 999,
            destination_port: 999,
            sequence: 1,
            acknowledgment: 2,
            flags: ACK,
            window: 100,
            urgent_pointer: 0,
        },
        &[],
        &[],
        &mut bytes,
    )
    .unwrap();
    assert_eq!(a.input(2, ip, &bytes[..len]), Ok(InputDisposition::Dropped));
    let (out, stateless) = a
        .poll_reserved_stateless_transmit(2, &mut bytes, 1)
        .unwrap();
    assert_eq!(out.packet.unwrap().connection, None);
    assert!(a.connection_exists(one));
    assert_eq!(
        a.poll_reserved_stateless_transmit(2, &mut bytes, 1),
        Err(EndpointError::OutputReserved)
    );
    a.write(two, b"healthy").unwrap();
    assert!(a.abandon_transmit(stateless.unwrap()).unwrap());
    assert!(!a.accept_transmit(2, stateless.unwrap()).unwrap());
    assert!(a.is_output_reserved(one));
    a.on_timeout(100_000_000, 16).unwrap();
    assert!(a.connection_exists(one));
    assert!(a.abandon_transmit(terminal.unwrap()).unwrap());
    assert!(!a.connection_exists(one));
    let (out, token) = a
        .poll_reserved_transmit_for(a.now, two, &mut bytes, 1)
        .unwrap();
    assert_eq!(out.packet.unwrap().connection, Some(two));
    assert!(a.accept_transmit(a.now, token.unwrap()).unwrap());
}

#[test]
fn pool_listener_events_and_accept_skip_held_children_without_losing_readiness() {
    check_listener_reservation_readiness(false, false);
}

#[test]
fn pool_listener_consumed_event_requeued_after_acceptance() {
    check_listener_reservation_readiness(true, false);
}

#[test]
fn pool_listener_consumed_event_requeued_after_repair() {
    check_listener_reservation_readiness(true, true);
}

fn check_listener_reservation_readiness(consume_event: bool, repair: bool) {
    let mut a = endpoint();
    let mut b = endpoint();
    let remote = "192.0.2.2:8080".parse().unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let mut bytes = [0; 2048];
    let mut children = std::vec::Vec::new();
    for port in [40000, 40001] {
        let local = SocketAddr::new("192.0.2.1".parse().unwrap(), port);
        a.connect(0, local, remote).unwrap();
        for step in 0..3 {
            let (src, dst) = if step == 1 {
                (&mut b, &mut a)
            } else {
                (&mut a, &mut b)
            };
            let packet = src
                .poll_transmit(0, &mut bytes, 16)
                .unwrap()
                .packet
                .unwrap();
            dst.input(0, packet.ip, &bytes[..packet.len]).unwrap();
        }
        children.push(
            b.connection_id(Tuple {
                local: remote,
                remote: local,
            })
            .unwrap(),
        );
    }
    b.enable_output_reservations_with_capacity(2).unwrap();
    let held = children[0];
    b.write(held, &[7; 120]).unwrap();
    let (_, token) = b
        .poll_reserved_transmit_for(1, held, &mut bytes, 1)
        .unwrap();
    assert_eq!(
        b.close_listener(listener),
        Err(EndpointError::OutputReserved)
    );
    b.set_listener_application_timeout(listener, Some(123))
        .unwrap();
    if consume_event {
        assert!(matches!(b.next_event(), Some(Event::Acceptable(id)) if id == listener));
    }
    // The second child can be accepted without modifying or popping the first.
    assert_eq!(b.accept(listener).unwrap(), children[1]);
    assert_eq!(b.accept(listener), Err(EndpointError::OutputReserved));
    while let Some(event) = b.next_event() {
        assert!(!matches!(event, Event::Acceptable(_)));
    }
    let mut token = token.unwrap();
    if repair {
        b.set_first_hop_mtu(2, held, 100).unwrap();
        assert!(b.reject_unsubmitted(token).unwrap());
        assert_eq!(b.accept(listener), Err(EndpointError::OutputReserved));
        assert_eq!(b.next_event(), None);
        let (_, prefix) = b.poll_reserved_transmit_for(2, held, &mut bytes, 1).unwrap();
        assert!(b.accept_transmit(2, prefix.unwrap()).unwrap());
        assert!(b.is_output_reserved(held));
        assert_eq!(b.accept(listener), Err(EndpointError::OutputReserved));
        assert_eq!(b.next_event(), None);
        assert_eq!(b.next_event(), None);
        let (_, final_fragment) = b.poll_reserved_transmit_for(2, held, &mut bytes, 1).unwrap();
        token = final_fragment.unwrap();
    }
    assert!(b.accept_transmit(2, token).unwrap());
    assert!(!b.is_output_reserved(held));
    assert!(matches!(b.next_event(), Some(Event::Acceptable(id)) if id == listener));
    assert!(!b.accept_transmit(2, token).unwrap());
    assert_eq!(b.next_event(), None);
    assert_eq!(b.accept(listener).unwrap(), held);
}
