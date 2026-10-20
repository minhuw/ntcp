// SPDX-License-Identifier: MIT
// Endpoint contract checks for a real RACK-timer repair and local rejection.
use alloc::vec;
fn local_failure_input(
    a: &mut Endpoint,
    now: u64,
    ack: u32,
    flags: u8,
    options: &[u8],
    payload: &[u8],
) -> Result<InputDisposition, EndpointError> {
    let ip = IpMetadata {
        source: "192.0.2.2".parse().unwrap(),
        destination: "192.0.2.1".parse().unwrap(),
    };
    let mut bytes = vec![0; 60 + payload.len()];
    let n = wire::encode(
        ip,
        wire::Header {
            source_port: 2000,
            destination_port: 1000,
            sequence: if flags & SYN != 0 { 0 } else { 1 },
            acknowledgment: ack,
            flags,
            window: if flags & SYN != 0 { 32792 } else { 320 },
            urgent_pointer: 0,
        },
        options,
        payload,
        &mut bytes,
    )
    .unwrap();
    a.input(now, ip, &bytes[..n])
}

fn local_failure_endpoint() -> (Endpoint, ConnectionId, u32) {
    let mut a = Endpoint::new(
        EndpointConfig {
            max_connections: 1,
            max_listeners: 1,
            max_buffer_bytes: 32 * 1024 * 1024,
            connection: ConnectionConfig {
                receive_capacity: 8 * 1024 * 1024,
                mss: 1460,
                receive_ip_payload_limit: 65515,
                send_ip_payload_limit: 65515,
                initial_window: crate::InitialWindow::Iw10,
                congestion_algorithm: crate::CongestionAlgorithm::Cubic,
                cubic_hystart: true,
                cubic_fast_convergence: true,
                timestamps: true,
                sack: true,
                rack: true,
                tlp: true,
                prr: true,
                prr_algorithm: crate::PrrAlgorithm::Rfc9937,
                prr_pacing: false,
                pacing: None,
                rto_min_us: 200_000,
                adaptive_ack: true,
                delayed_ack_us: 200_000,
                coalesce_read_window_updates: true,
                abort_with_ack: true,
                output_push_batch_segments: 2,
                output_push_batch_retransmissions: false,
                ..ConnectionConfig::default()
            },
            ..EndpointConfig::default()
        },
        [1; 32],
        0,
        |_| true,
    )
    .unwrap();
    let listener = a.listen("192.0.2.1:1000".parse().unwrap(), 1).unwrap();
    local_failure_input(
        &mut a,
        0,
        0,
        SYN,
        &[2, 4, 3, 232, 4, 2, 1, 1, 1, 3, 3, 7],
        &[],
    )
    .unwrap();
    let mut out = [0; 2048];
    let p = a.poll_transmit(0, &mut out, 16).unwrap().packet.unwrap();
    let base = wire::parse(p.ip, &out[..p.len])
        .unwrap()
        .header
        .sequence
        .wrapping_add(1);
    local_failure_input(&mut a, 20_000, base, wire::ACK, &[], &[]).unwrap();
    let id = a.accept(listener).unwrap();
    a.write(id, &[7; 10_000]).unwrap();
    for offset in (0..10_000).step_by(1000) {
        let p = a
            .poll_transmit(20_000, &mut out, 16)
            .unwrap()
            .packet
            .unwrap();
        let s = wire::parse(p.ip, &out[..p.len]).unwrap();
        assert_eq!(
            (s.header.sequence, s.payload.len()),
            (base.wrapping_add(offset), 1000)
        );
    }
    for blocks in [
        &[(9000u32, 10000u32)][..],
        &[(3000u32, 4000u32), (9000, 10000)][..],
    ] {
        let mut options = vec![1, 1, 5, (2 + 8 * blocks.len()) as u8];
        for (lo, hi) in blocks {
            options.extend_from_slice(&base.wrapping_add(*lo).to_be_bytes());
            options.extend_from_slice(&base.wrapping_add(*hi).to_be_bytes());
        }
        local_failure_input(&mut a, 40_000, base, wire::ACK, &options, &[]).unwrap();
    }
    local_failure_input(
        &mut a,
        40_000,
        base.wrapping_add(10000),
        wire::ACK,
        &[],
        &[],
    )
    .unwrap();
    assert_eq!(a.transport_info(id).unwrap().cwnd, 18_000);
    assert_eq!(a.transport_info(id).unwrap().reordering, 10);
    a.write(id, &[8; 2000]).unwrap();
    for offset in [10000, 11000] {
        let p = a
            .poll_transmit(65_000, &mut out, 16)
            .unwrap()
            .packet
            .unwrap();
        let s = wire::parse(p.ip, &out[..p.len]).unwrap();
        assert_eq!(
            (s.header.sequence, s.payload.len()),
            (base.wrapping_add(offset), 1000)
        );
    }
    let mut options = vec![1, 1, 5, 10];
    options.extend_from_slice(&base.wrapping_add(11000).to_be_bytes());
    options.extend_from_slice(&base.wrapping_add(12000).to_be_bytes());
    local_failure_input(
        &mut a,
        85_000,
        base.wrapping_add(10000),
        wire::ACK,
        &options,
        &[],
    )
    .unwrap();
    assert_eq!(a.next_deadline(), Some(90_000));
    a.on_timeout(90_000, 16).unwrap();
    assert!(a.transport_info(id).unwrap().recovery);
    assert_eq!(a.transport_info(id).unwrap().retransmitted, 0);
    a.enable_output_reservations().unwrap();
    (a, id, base)
}

#[test]
fn local_rack_failure_endpoint_rejection_retains_owner_until_accept_or_abort() {
    for abandon in [false, true] {
        let (mut a, id, base) = local_failure_endpoint();
        let mut bytes = [0; 2048];
        let (out, token) = a
            .poll_reserved_transmit_for(90_000, id, &mut bytes, 16)
            .unwrap();
        let p = out.packet.unwrap();
        let s = wire::parse(p.ip, &bytes[..p.len]).unwrap();
        assert_eq!(
            (s.header.sequence, s.payload.len()),
            (base.wrapping_add(10000), 1000)
        );
        let token = token.unwrap();
        assert!(a.is_output_reserved(id));
        assert_eq!(a.transport_info(id).unwrap().retransmitted, 0);
        // No successful backend submission has occurred.
        assert_eq!(
            local_failure_input(
                &mut a,
                95_000,
                base.wrapping_add(10000),
                wire::ACK,
                &[],
                &[9; 1000]
            ),
            Err(EndpointError::OutputReserved)
        );
        assert_eq!(a.readable_bytes(id).unwrap(), 0);
        assert!(a.reject_unsubmitted(token).unwrap());
        assert!(!a.reject_unsubmitted(token).unwrap());
        assert!(a.is_output_reserved(id));
        assert_eq!(
            local_failure_input(
                &mut a,
                96_000,
                base.wrapping_add(10000),
                wire::ACK,
                &[],
                &[9; 1000]
            ),
            Err(EndpointError::OutputReserved)
        );
        if abandon {
            assert!(a.abandon_transmit(token).unwrap());
            assert!(!a.is_output_reserved(id));
            assert_eq!(a.state(id).unwrap(), State::Closed);
        } else {
            let (out, retry) = a
                .poll_reserved_transmit_for(100_000, id, &mut bytes, 16)
                .unwrap();
            let p = out.packet.unwrap();
            let s = wire::parse(p.ip, &bytes[..p.len]).unwrap();
            assert_eq!(
                (s.header.sequence, s.payload.len()),
                (base.wrapping_add(10000), 1000)
            );
            assert_ne!(retry, Some(token));
            assert!(a.accept_transmit(110_000, retry.unwrap()).unwrap());
            assert!(!a.is_output_reserved(id));
            local_failure_input(
                &mut a,
                115_000,
                base.wrapping_add(10000),
                wire::ACK,
                &[],
                &[9; 1000],
            )
            .unwrap();
            assert_eq!(a.readable_bytes(id).unwrap(), 1000);
            assert!(a.transport_info(id).unwrap().recovery);
            assert_eq!(a.transport_info(id).unwrap().retransmitted, 1);
        }
    }
}

#[test]
fn cancelled_local_rack_repair_releases_input_without_credit_or_stale_tokens() {
    let (mut a, id, base) = local_failure_endpoint();
    let before = a.transport_info(id).unwrap();
    let mut bytes = [0; 2048];
    // Repeated certified failures leave the same lost data eligible, not sent.
    for at in [90_000, 91_000, 92_000] {
        let (out, token) = a
            .poll_reserved_transmit_for(at, id, &mut bytes, 16)
            .unwrap();
        let p = out.packet.unwrap();
        let seg = wire::parse(p.ip, &bytes[..p.len]).unwrap();
        assert_eq!(
            (seg.header.sequence, seg.payload.len()),
            (base.wrapping_add(10000), 1000)
        );
        let token = token.unwrap();
        assert_eq!(a.transport_info(id).unwrap().retransmitted, 0);
        crate::allocation_tests::fail_after(0, || {
            assert!(a.cancel_unsubmitted_repair(token).unwrap());
        });
        assert!(!a.is_output_reserved(id));
        assert!(!a.cancel_unsubmitted_repair(token).unwrap());
        assert!(!a.accept_transmit(at, token).unwrap());
        assert!(!a.reject_unsubmitted(token).unwrap());
        let info = a.transport_info(id).unwrap();
        assert_eq!(
            (info.cwnd, info.lost, info.retransmitted),
            (before.cwnd, 1, 0)
        );
        assert_eq!(a.state(id).unwrap(), State::Established);
    }
    local_failure_input(
        &mut a,
        95_000,
        base.wrapping_add(10000),
        wire::ACK,
        &[],
        &[9; 1000],
    )
    .unwrap();
    assert_eq!(a.readable_bytes(id).unwrap(), 1000);
    let (out, token) = a
        .poll_reserved_transmit_for(96_000, id, &mut bytes, 16)
        .unwrap();
    let p = out.packet.unwrap();
    let seg = wire::parse(p.ip, &bytes[..p.len]).unwrap();
    assert_eq!(
        (
            seg.header.sequence,
            seg.header.acknowledgment,
            seg.payload.len()
        ),
        (base.wrapping_add(10000), 1001, 1000)
    );
    assert_eq!(a.transport_info(id).unwrap().retransmitted, 0);
    assert!(a.accept_transmit(97_000, token.unwrap()).unwrap());
    assert_eq!(a.transport_info(id).unwrap().retransmitted, 1);
    assert!(a.transport_info(id).unwrap().recovery);
}

#[test]
fn local_repair_cancellation_declines_changed_mss_without_restoring_old_units() {
    let (mut a, id, _) = local_failure_endpoint();
    let mut out = [0; 2048];
    let (_, token) = a
        .poll_reserved_transmit_for(90_000, id, &mut out, 16)
        .unwrap();
    let token = token.unwrap();
    a.slot_mut(id).unwrap().connection.lower_mss(500).unwrap();
    assert!(!a.cancel_unsubmitted_repair(token).unwrap());
    assert_eq!(a.transport_info(id).unwrap().mss, 500);
    assert!(a.is_output_reserved(id));
}

#[test]
fn local_repair_cancel_then_covering_ack_cannot_resurrect_old_retransmission() {
    let (mut a, id, base) = local_failure_endpoint();
    let mut out = [0; 2048];
    let token = crate::allocation_tests::fail_after(0, || {
        a.poll_reserved_transmit_for(90_000, id, &mut out, 16)
            .unwrap()
            .1
            .unwrap()
    });
    assert!(a.cancel_unsubmitted_repair(token).unwrap());
    assert_eq!(a.next_deadline(), Some(265_000));
    local_failure_input(
        &mut a,
        95_000,
        base.wrapping_add(12000),
        wire::ACK,
        &[],
        &[9; 1000],
    )
    .unwrap();
    assert!(!a.transport_info(id).unwrap().recovery);
    assert_eq!(a.transport_info(id).unwrap().unacked, 0);
    assert_eq!(a.transport_info(id).unwrap().retransmitted, 0);
    assert_eq!(a.readable_bytes(id).unwrap(), 1000);
    let (p, token) = a
        .poll_reserved_transmit_for(96_000, id, &mut out, 16)
        .unwrap();
    if let Some(p) = p.packet {
        assert!(wire::parse(p.ip, &out[..p.len]).unwrap().payload.is_empty());
        a.accept_transmit(96_000, token.unwrap()).unwrap();
    }
}

#[test]
fn fresh_local_rejection_invalidates_old_tokens_and_preserves_accepted_prefixes() {
    for ipv6 in [false, true] {
        let (mut a, _, id, _) = gso_pair(ipv6, true);
        a.write(id, &[7; 3500]).unwrap();
        let mut bytes = [0; 2048];
        let (p, token) = a.poll_reserved_transmit_for(2, id, &mut bytes, 1).unwrap();
        let packet = p.packet.unwrap();
        let first = wire::parse(packet.ip, &bytes[..packet.len])
            .unwrap()
            .header
            .sequence;
        let old = token.unwrap();
        assert!(a.reject_local_output(3, old).unwrap());
        assert!(!a.accept_transmit(3, old).unwrap());
        assert!(!a.reject_local_output(3, old).unwrap());
        assert!(!a.is_output_reserved(id));
        assert_eq!(a.transport_info(id).unwrap().notsent_bytes, 3500);
        assert_eq!(a.transport_info(id).unwrap().unacked, 0);
        a.write(id, b"appended").unwrap();
        let mut selected = None;
        for _ in 0..8 {
            let at = a.next_deadline().unwrap();
            a.on_timeout(at, 16).unwrap();
            let (p, token) = a.poll_reserved_transmit_for(at, id, &mut bytes, 1).unwrap();
            if let Some(packet) = p.packet {
                selected = Some((at, packet, token.unwrap()));
                break;
            }
        }
        let (at, packet, token) = selected.unwrap();
        assert_eq!(
            wire::parse(packet.ip, &bytes[..packet.len])
                .unwrap()
                .header
                .sequence,
            first
        );
        let accepted = token;
        assert!(a.accept_transmit(at, accepted).unwrap());
        let (p, token) = a.poll_reserved_transmit_for(at, id, &mut bytes, 1).unwrap();
        assert!(p.packet.is_some());
        let suffix = token.unwrap();
        assert!(!a.reject_local_output(at, suffix).unwrap());
        assert!(a.is_output_reserved(id));
        assert!(a.accept_transmit(at, suffix).unwrap());
    }
}
