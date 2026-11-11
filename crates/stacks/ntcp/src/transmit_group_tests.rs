extern crate std;
use super::*;
use crate::connection::test_support::departure_snapshot;
use std::vec::Vec;

// A connected pair whose client polls through one GSO reservation. The
// peer's receive buffer bounds the client's send window.
fn pair(
    ipv6: bool,
    timestamps: bool,
    peer_receive: usize,
) -> (Endpoint, Endpoint, ConnectionId, ConnectionId) {
    let config = |receive| ConnectionConfig {
        pmtud: Some(crate::PmtudConfig {
            initial_search_low: Some(if ipv6 { 1280 } else { 1040 }),
            ..crate::PmtudConfig::new(1500)
        }),
        mss: 1000,
        nagle: false,
        sack: true,
        timestamps,
        prr_pacing: false,
        initial_window: crate::InitialWindow::Iw10,
        send_capacity: 16_384,
        receive_capacity: receive,
        ..ConnectionConfig::default()
    };
    let endpoint = |receive| {
        Endpoint::new(
            EndpointConfig {
                max_connections: 4,
                max_listeners: 2,
                connection: config(receive),
                ..EndpointConfig::default()
            },
            [1; 32],
            0,
            |_| true,
        )
        .unwrap()
    };
    let mut a = endpoint(16_384);
    let mut b = endpoint(peer_receive);
    let (local, remote) = if ipv6 {
        ("[2001:db8::1]:40000", "[2001:db8::2]:8080")
    } else {
        ("192.0.2.1:40000", "192.0.2.2:8080")
    };
    let listener = b.listen(remote.parse().unwrap(), 4).unwrap();
    let client = a
        .connect(0, local.parse().unwrap(), remote.parse().unwrap())
        .unwrap();
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
    a.enable_output_reservations_with_gso(
        1,
        crate::GsoLimits {
            max_bytes: 8000,
            max_segments: 8,
        },
    )
    .unwrap();
    (a, b, client, server)
}

fn limits() -> crate::TransmitGroupLimits {
    crate::TransmitGroupLimits {
        max_bytes: usize::MAX,
        max_segments: usize::MAX,
        allow_psh: true,
        allow_cwr: true,
        allow_options: true,
    }
}

fn snapshot(e: &Endpoint, id: ConnectionId) -> std::string::String {
    departure_snapshot(&e.retained_slot(id).unwrap().connection)
}

// The physical segments a backend cuts from the aggregate, as Linux
// tcp_gso_segment does: PSH on the last, CWR on the first only.
fn cut(view: &crate::TransmitGroupView<'_>) -> Vec<Vec<u8>> {
    let size = view.segment_payload_len;
    (0..view.segment_count)
        .map(|n| {
            let mut header = view.header;
            header.sequence = header.sequence.wrapping_add((n * size) as u32);
            if n + 1 != view.segment_count {
                header.flags &= !wire::PSH;
            }
            if n != 0 {
                header.flags &= !wire::CWR;
            }
            let mut out = [0; 2048];
            let len = wire::encode(
                view.packet.ip,
                header,
                view.options,
                &view.payload[n * size..(n + 1) * size],
                &mut out,
            )
            .unwrap();
            out[..len].to_vec()
        })
        .collect()
}

// Everything `e` sends at `now` (it holds no reservations).
fn sent(e: &mut Endpoint, now: Instant) -> Vec<(crate::IpMetadata, Vec<u8>)> {
    let mut out = [0; 2048];
    let mut packets = Vec::new();
    while let Some(p) = e.poll_transmit(now, &mut out, 16).unwrap().packet {
        packets.push((p.ip, out[..p.len].to_vec()));
    }
    packets
}

// Polls and accepts `id`'s output one scalar segment at a time, at `now`.
fn scalar(e: &mut Endpoint, id: ConnectionId, now: Instant) -> Vec<Vec<u8>> {
    let mut out = [0; 2048];
    let mut packets = Vec::new();
    loop {
        let (poll, attempt) = e.poll_reserved_transmit_for(now, id, &mut out, 16).unwrap();
        let Some(p) = poll.packet else {
            return packets;
        };
        assert!(e.accept_transmit(now, attempt.unwrap()).unwrap());
        packets.push(out[..p.len].to_vec());
    }
}

fn receipt(view: &crate::TransmitGroupView<'_>) -> crate::PhysicalReceipt {
    let ip = if view.packet.ip.source.is_ipv4() {
        20
    } else {
        40
    };
    crate::PhysicalReceipt {
        ip_packet_len: (ip + view.packet.len - view.payload.len() + view.segment_payload_len)
            as u32,
        dont_fragment: true,
    }
}

#[test]
fn group_acceptance_records_what_scalar_acceptance_at_its_instant_records() {
    for ipv6 in [false, true] {
        for timestamps in [false, true] {
            for submitted in [false, true] {
                let (mut a, mut peer, id, server) = pair(ipv6, timestamps, 16_384);
                let (mut b, _, bid, _) = pair(ipv6, timestamps, 16_384);
                let data: Vec<u8> = (0..7000).map(|i| (i * 7) as u8).collect();
                a.write(id, &data).unwrap();
                b.write(bid, &data).unwrap();
                let mut out = [0; 2048];
                let mut expected = [0; 2048];
                let (_, attempt) = a.poll_reserved_transmit_for(2, id, &mut out, 1).unwrap();
                let attempt = attempt.unwrap();
                let (poll, mut b_attempt) = b
                    .poll_reserved_transmit_for(2, bid, &mut expected, 1)
                    .unwrap();
                let mut packet = poll.packet.unwrap();
                let s = a.transmit_segmentation(attempt).unwrap();
                let group = a
                    .prepare_transmit_group(attempt, limits())
                    .unwrap()
                    .unwrap();
                let view = a.transmit_group(group).unwrap();
                assert_eq!(view.segment_count, s.payload_len / s.segment_payload_len);
                assert!(view.segment_count >= 6, "{}", view.segment_count);
                assert_eq!(view.options.len(), if timestamps { 12 } else { 0 });
                assert_eq!(view.packet.len, s.tcp_header_len + view.payload.len());
                assert!(view.packet.tx_timestamp.is_none());
                assert_eq!(view.payload, &data[..view.payload.len()]);
                let segments = cut(&view);
                let ip = view.packet.ip;
                let each = receipt(&view);
                // Group preparation records nothing.
                assert_eq!(snapshot(&a, id), snapshot(&b, bid));
                // Scalar polling emits exactly the segments the backend cuts.
                for (n, segment) in segments.iter().enumerate() {
                    if n != 0 {
                        let (poll, next) = b
                            .poll_reserved_transmit_for(3, bid, &mut expected, 1)
                            .unwrap();
                        (packet, b_attempt) = (poll.packet.unwrap(), next);
                    }
                    assert_eq!(&expected[..packet.len], &segment[..]);
                    let attempt = b_attempt.unwrap();
                    assert!(if submitted {
                        b.accept_transmit_submitted(3, attempt, each).unwrap()
                    } else {
                        b.accept_transmit(3, attempt).unwrap()
                    });
                }
                assert!(if submitted {
                    a.accept_transmit_group_submitted(3, group, each).unwrap()
                } else {
                    a.accept_transmit_group(3, group).unwrap()
                });
                assert_eq!(snapshot(&a, id), snapshot(&b, bid));
                assert_eq!(a.is_output_reserved(id), b.is_output_reserved(bid));
                assert_eq!(a.now, b.now);
                // The token is spent.
                assert!(a.transmit_group(group).is_none());
                assert!(!a.validate_transmit_group(3, group).unwrap());
                assert!(!a.accept_transmit_group(3, group).unwrap());
                assert!(!a.reject_unsubmitted_group(group).unwrap());
                // Both learn the same from the peer and send the same after.
                let mut acks = Vec::new();
                for segment in &segments {
                    peer.input(4, ip, segment).unwrap();
                    acks.extend(sent(&mut peer, 4));
                }
                assert!(!acks.is_empty());
                for (ip, ack) in &acks {
                    a.input(5, *ip, ack).unwrap();
                    b.input(5, *ip, ack).unwrap();
                }
                assert_eq!(snapshot(&a, id), snapshot(&b, bid));
                assert_eq!(scalar(&mut a, id, 6), scalar(&mut b, bid, 6));
                assert_eq!(snapshot(&a, id), snapshot(&b, bid));
                let mut received = [0; 7000];
                let n = peer.read(server, &mut received).unwrap();
                assert_eq!(&received[..n], &data[..n]);
            }
        }
    }
}

#[test]
fn group_validation_rejection_and_abandonment_leave_tcp_state_unchanged() {
    let (mut a, _, id, _) = pair(false, true, 16_384);
    a.write(id, &[1; 7000]).unwrap();
    let mut out = [0; 2048];
    let (poll, attempt) = a.poll_reserved_transmit_for(2, id, &mut out, 1).unwrap();
    let first = out[..poll.packet.unwrap().len].to_vec();
    let attempt = attempt.unwrap();
    let before = snapshot(&a, id);
    let group = a
        .prepare_transmit_group(attempt, limits())
        .unwrap()
        .unwrap();
    assert_eq!(snapshot(&a, id), before);
    // The group replaced the scalar attempt.
    assert_eq!(a.transmit_segmentation(attempt), None);
    assert!(!a.preflight_accept_transmit(3, attempt).unwrap());
    assert!(!a.accept_transmit(3, attempt).unwrap());
    assert!(!a.reject_unsubmitted(attempt).unwrap());
    assert!(!a.abandon_transmit(attempt).unwrap());
    assert_eq!(a.prepare_transmit_group(attempt, limits()).unwrap(), None);
    // WouldBlock retries validate without allocating or advancing anything.
    crate::allocation_tests::fail_after(0, || {
        for now in [2, 3, 50] {
            assert!(a.validate_transmit_group(now, group).unwrap());
        }
    });
    assert_eq!(a.now, 2);
    assert_eq!(snapshot(&a, id), before);
    // A held group bars the owner like any held output.
    assert_eq!(
        a.poll_reserved_transmit_for(4, id, &mut out, 1),
        Err(EndpointError::OutputReserved)
    );
    assert_eq!(a.write(id, b"held"), Err(EndpointError::OutputReserved));
    for now in [0, 1] {
        assert_eq!(
            a.validate_transmit_group(now, group),
            Err(Error::TimeWentBackwards.into())
        );
        assert_eq!(
            a.accept_transmit_group(now, group),
            Err(Error::TimeWentBackwards.into())
        );
    }
    assert_eq!(snapshot(&a, id), before);
    assert!(a.reject_unsubmitted_group(group).unwrap());
    assert!(!a.reject_unsubmitted_group(group).unwrap());
    assert!(!a.validate_transmit_group(5, group).unwrap());
    assert!(!a.accept_transmit_group(5, group).unwrap());
    assert!(a.transmit_group(group).is_none());
    assert_eq!(snapshot(&a, id), before);
    // Nothing departed: the reservation emits the same first segment again.
    let (poll, again) = a.poll_reserved_transmit_for(5, id, &mut out, 1).unwrap();
    assert_eq!(&out[..poll.packet.unwrap().len], &first[..]);
    let second = a
        .prepare_transmit_group(again.unwrap(), limits())
        .unwrap()
        .unwrap();
    assert_ne!(second, group);
    assert!(!a.accept_transmit_group(5, group).unwrap());
    assert!(a.accept_transmit_group(5, second).unwrap());

    // Abandonment, also after a rejection, fails only the owner.
    let (mut a, _, id, _) = pair(false, true, 16_384);
    a.write(id, &[1; 7000]).unwrap();
    let (_, attempt) = a.poll_reserved_transmit_for(2, id, &mut out, 1).unwrap();
    let group = a
        .prepare_transmit_group(attempt.unwrap(), limits())
        .unwrap()
        .unwrap();
    assert!(a.reject_unsubmitted_group(group).unwrap());
    assert!(a.abandon_transmit_group(group).unwrap());
    assert!(!a.abandon_transmit_group(group).unwrap());
    assert!(!a.is_output_reserved(id));
    assert_eq!(
        a.close_reason(id).unwrap(),
        Some(crate::CloseReason::Aborted)
    );
}

#[test]
fn group_limits_bound_segments_and_decline_psh_cwr_and_options() {
    for timestamps in [false, true] {
        let (mut a, _, id, _) = pair(false, timestamps, 16_384);
        let mut out = [0; 2048];
        // Exactly four segments: the write's automatic PUSH ends the range.
        let size = if timestamps { 988 } else { 1000 };
        a.write(id, &std::vec![1; 4 * size]).unwrap();
        let (_, attempt) = a.poll_reserved_transmit_for(2, id, &mut out, 1).unwrap();
        let mut attempt = attempt.unwrap();
        let s = a.transmit_segmentation(attempt).unwrap();
        assert_eq!((s.segment_payload_len, s.payload_len), (size, 4 * size));
        assert_ne!(s.terminal_flags & wire::PSH, 0);
        for declined in [
            crate::TransmitGroupLimits {
                max_segments: 1,
                ..limits()
            },
            crate::TransmitGroupLimits {
                max_bytes: 2 * size - 1,
                ..limits()
            },
            crate::TransmitGroupLimits {
                max_segments: 2,
                max_bytes: 0,
                ..limits()
            },
        ] {
            assert_eq!(a.prepare_transmit_group(attempt, declined).unwrap(), None);
            assert_eq!(a.transmit_segmentation(attempt), Some(s));
        }
        let no_options = crate::TransmitGroupLimits {
            allow_options: false,
            ..limits()
        };
        let group = a.prepare_transmit_group(attempt, no_options).unwrap();
        assert_eq!(group.is_none(), timestamps);
        if let Some(group) = group {
            assert!(a.reject_unsubmitted_group(group).unwrap());
            let (_, again) = a.poll_reserved_transmit_for(2, id, &mut out, 1).unwrap();
            attempt = again.unwrap();
            // Bounds shorten the group to a prefix.
            let group = a
                .prepare_transmit_group(
                    attempt,
                    crate::TransmitGroupLimits {
                        max_bytes: 3 * size - 1,
                        ..no_options
                    },
                )
                .unwrap()
                .unwrap();
            let view = a.transmit_group(group).unwrap();
            assert_eq!(view.segment_count, 2);
            assert_eq!(view.header.flags & wire::PSH, 0);
            assert!(a.reject_unsubmitted_group(group).unwrap());
            let (_, again) = a.poll_reserved_transmit_for(2, id, &mut out, 1).unwrap();
            let group = a
                .prepare_transmit_group(
                    again.unwrap(),
                    crate::TransmitGroupLimits {
                        max_segments: 3,
                        ..no_options
                    },
                )
                .unwrap()
                .unwrap();
            assert_eq!(a.transmit_group(group).unwrap().segment_count, 3);
            assert!(a.reject_unsubmitted_group(group).unwrap());
            let (_, again) = a.poll_reserved_transmit_for(2, id, &mut out, 1).unwrap();
            attempt = again.unwrap();
        }
        // A first-segment CWR obligation (the ECN selection that sets it is
        // covered by the connection tests); the backend declines it.
        add_cwr(&mut a);
        let no_cwr = crate::TransmitGroupLimits {
            allow_cwr: false,
            ..limits()
        };
        assert_eq!(a.prepare_transmit_group(attempt, no_cwr).unwrap(), None);
        // Without PSH support the PSH segment stays scalar.
        let group = a
            .prepare_transmit_group(
                attempt,
                crate::TransmitGroupLimits {
                    allow_psh: false,
                    ..limits()
                },
            )
            .unwrap()
            .unwrap();
        let view = a.transmit_group(group).unwrap();
        assert_eq!(view.segment_count, 3);
        assert_eq!(view.header.flags & (wire::CWR | wire::PSH), wire::CWR);
        assert!(a.accept_transmit_group(3, group).unwrap());
        let (poll, last) = a.poll_reserved_transmit_for(3, id, &mut out, 1).unwrap();
        let p = poll.packet.unwrap();
        let segment = wire::parse(p.ip, &out[..p.len]).unwrap();
        assert_eq!(segment.header.flags & (wire::CWR | wire::PSH), wire::PSH);
        assert_eq!(segment.payload.len(), size);
        // One segment is no group, whatever the limits.
        assert_eq!(
            a.prepare_transmit_group(last.unwrap(), limits()).unwrap(),
            None
        );
        assert!(a.accept_transmit(3, last.unwrap()).unwrap());
        assert!(!a.is_output_reserved(id));
        cwr_suffix(&mut a, id, size);
    }
}

// A group after an accepted prefix starts past the first segment: it never
// carries CWR, so a backend without CWR support still takes it.
fn cwr_suffix(a: &mut Endpoint, id: ConnectionId, size: usize) {
    let mut out = [0; 2048];
    a.write(id, &std::vec![2; 4 * size]).unwrap();
    let (_, attempt) = a.poll_reserved_transmit_for(4, id, &mut out, 1).unwrap();
    add_cwr(a);
    assert!(a.accept_transmit(4, attempt.unwrap()).unwrap());
    let (_, attempt) = a.poll_reserved_transmit_for(4, id, &mut out, 1).unwrap();
    let group = a
        .prepare_transmit_group(
            attempt.unwrap(),
            crate::TransmitGroupLimits {
                allow_cwr: false,
                ..limits()
            },
        )
        .unwrap()
        .unwrap();
    let view = a.transmit_group(group).unwrap();
    assert_eq!(view.segment_count, 3);
    assert_eq!(view.header.flags & wire::CWR, 0);
    assert!(a.accept_transmit_group(4, group).unwrap());
}

fn add_cwr(a: &mut Endpoint) {
    a.reservations[0]
        .current
        .as_mut()
        .unwrap()
        .departure
        .as_mut()
        .unwrap()
        .segmentation
        .as_mut()
        .unwrap()
        .terminal_flags |= wire::CWR;
}

// `scalar` that also checks no attempt it accepts can become a group.
fn ungroupable(e: &mut Endpoint, id: ConnectionId, now: Instant) -> Vec<Vec<u8>> {
    let mut out = [0; 2048];
    let mut packets = Vec::new();
    loop {
        let (poll, attempt) = e.poll_reserved_transmit_for(now, id, &mut out, 16).unwrap();
        let Some(p) = poll.packet else {
            return packets;
        };
        let attempt = attempt.unwrap();
        assert_eq!(e.prepare_transmit_group(attempt, limits()).unwrap(), None);
        assert!(e.accept_transmit(now, attempt).unwrap());
        packets.push(out[..p.len].to_vec());
    }
}

// Polls one reservation and sends its whole group at `now`.
fn group(e: &mut Endpoint, id: ConnectionId, now: Instant) -> Vec<Vec<u8>> {
    let (_, attempt) = e
        .poll_reserved_transmit_for(now, id, &mut [0; 2048], 1)
        .unwrap();
    let group = e
        .prepare_transmit_group(attempt.unwrap(), limits())
        .unwrap()
        .unwrap();
    let segments = cut(&e.transmit_group(group).unwrap());
    assert!(e.accept_transmit_group(now, group).unwrap());
    segments
}

#[test]
fn group_loss_is_detected_and_repaired_like_scalar_loss_and_repairs_stay_scalar() {
    let (mut a, mut peer, id, server) = pair(false, true, 16_384);
    let (mut b, _, bid, _) = pair(false, true, 16_384);
    let data: Vec<u8> = (0..7000).map(|i| (i * 3) as u8).collect();
    a.write(id, &data).unwrap();
    b.write(bid, &data).unwrap();
    let mut wire = group(&mut a, id, 2);
    assert_eq!(wire.len(), 7);
    wire.extend(scalar(&mut a, id, 2));
    assert_eq!(wire, scalar(&mut b, bid, 2));
    assert_eq!(snapshot(&a, id), snapshot(&b, bid));
    let ip = crate::IpMetadata {
        source: "192.0.2.1".parse().unwrap(),
        destination: "192.0.2.2".parse().unwrap(),
    };
    // The first segment of the group is lost; SACKs report the rest.
    let mut acks = Vec::new();
    for segment in &wire[1..] {
        peer.input(3, ip, segment).unwrap();
        acks.extend(sent(&mut peer, 3));
    }
    assert!(acks.len() >= 3);
    for (ip, ack) in &acks {
        a.input(4, *ip, ack).unwrap();
        b.input(4, *ip, ack).unwrap();
    }
    assert_eq!(snapshot(&a, id), snapshot(&b, bid));
    let mut repairs = ungroupable(&mut a, id, 4);
    assert_eq!(repairs, ungroupable(&mut b, bid, 4));
    if repairs.is_empty() {
        // Not yet repaired at the ACK: the loss timer finds it.
        let deadline = a.next_deadline().unwrap();
        assert_eq!(b.next_deadline(), Some(deadline));
        a.on_timeout(deadline, 16).unwrap();
        b.on_timeout(deadline, 16).unwrap();
        repairs = ungroupable(&mut a, id, deadline);
        assert_eq!(repairs, ungroupable(&mut b, bid, deadline));
    }
    assert_eq!(snapshot(&a, id), snapshot(&b, bid));
    let first = wire::parse(ip, &wire[0]).unwrap();
    let repair = wire::parse(ip, &repairs[0]).unwrap();
    assert_eq!(repair.header.sequence, first.header.sequence);
    assert_eq!(repair.payload, first.payload);
    peer.input(5, ip, &repairs[0]).unwrap();
    let mut received = [0; 7000];
    assert_eq!(peer.read(server, &mut received).unwrap(), 7000);
    assert_eq!(&received[..], &data[..]);
}

#[test]
fn group_output_carrying_sack_options_or_fin_stays_scalar() {
    // A data segment reporting SACK blocks: GSO selection leaves it scalar.
    let (mut a, mut peer, id, server) = pair(false, true, 16_384);
    peer.write(server, &[9; 2000]).unwrap();
    let from_peer = sent(&mut peer, 2);
    assert!(from_peer.len() >= 2);
    // The first is lost: the rest arrive out of order.
    for (ip, segment) in &from_peer[1..] {
        a.input(2, *ip, segment).unwrap();
    }
    a.write(id, &[1; 7000]).unwrap();
    let mut out = [0; 2048];
    let (poll, attempt) = a.poll_reserved_transmit_for(3, id, &mut out, 1).unwrap();
    let p = poll.packet.unwrap();
    assert!(
        wire::parse(p.ip, &out[..p.len])
            .unwrap()
            .options
            .sack_blocks[0]
            .is_some()
    );
    let attempt = attempt.unwrap();
    assert_eq!(a.transmit_segmentation(attempt), None);
    assert_eq!(a.prepare_transmit_group(attempt, limits()).unwrap(), None);
    assert!(a.accept_transmit(3, attempt).unwrap());

    // FIN after a group goes out with the scalar tail; a queued FIN keeps
    // the whole flight scalar.
    let (mut a, mut peer, id, server) = pair(false, true, 16_384);
    a.write(id, &[1; 7000]).unwrap();
    let mut wire = group(&mut a, id, 2);
    a.close(id).unwrap();
    let tail = ungroupable(&mut a, id, 2);
    let last = wire::parse(p.ip, tail.last().unwrap()).unwrap();
    assert_ne!(last.header.flags & wire::FIN, 0);
    wire.extend(tail);
    for segment in &wire {
        peer.input(3, p.ip, segment).unwrap();
    }
    assert_eq!(peer.read(server, &mut [0; 8000]).unwrap(), 7000);
    assert_eq!(peer.state(server).unwrap(), State::CloseWait);
    let (mut a, _, id, _) = pair(false, true, 16_384);
    a.write(id, &[1; 7000]).unwrap();
    a.close(id).unwrap();
    let flight = ungroupable(&mut a, id, 2);
    assert!(flight.len() >= 7);
}

#[test]
fn group_stays_within_the_peer_window() {
    let (mut a, _, id, _) = pair(false, true, 2500);
    let window = a.transport_info(id).unwrap().max_send_window as usize;
    assert!(window < 3 * 988, "{window}");
    a.write(id, &[1; 7000]).unwrap();
    let mut sent = group(&mut a, id, 2);
    assert_eq!(sent.len(), window / 988);
    sent.extend(ungroupable(&mut a, id, 2));
    let ip = crate::IpMetadata {
        source: "192.0.2.1".parse().unwrap(),
        destination: "192.0.2.2".parse().unwrap(),
    };
    let bytes: usize = sent
        .iter()
        .map(|s| wire::parse(ip, s).unwrap().payload.len())
        .sum();
    assert!(bytes <= window, "{bytes} > {window}");
}

#[test]
fn shared_payload_output_is_never_grouped() {
    let (mut a, _, id, _) = pair(false, true, 16_384);
    a.enable_shared_output(8).unwrap();
    a.write_shared(
        id,
        crate::Payload::from_vec(std::vec![5; 7000]),
        false,
        false,
        None,
    )
    .unwrap();
    let mut header = [0; 2048];
    let mut payload = Vec::with_capacity(8);
    let (poll, attempt) = a
        .poll_reserved_transmit_shared_for(2, id, &mut header, &mut payload, 1)
        .unwrap();
    assert!(poll.packet.is_some() && !payload.is_empty());
    let attempt = attempt.unwrap();
    assert_eq!(a.transmit_segmentation(attempt), None);
    assert_eq!(a.prepare_transmit_group(attempt, limits()).unwrap(), None);
    assert!(a.accept_transmit(2, attempt).unwrap());
}

#[test]
fn group_prepared_before_a_path_decrease_is_refused_and_resplit() {
    let (mut a, _, id, _) = pair(false, true, 16_384);
    a.write(id, &[1; 7000]).unwrap();
    let mut out = [0; 2048];
    let (_, attempt) = a.poll_reserved_transmit_for(2, id, &mut out, 1).unwrap();
    let group = a
        .prepare_transmit_group(attempt.unwrap(), limits())
        .unwrap()
        .unwrap();
    a.set_first_hop_mtu(3, id, 552).unwrap();
    let before = snapshot(&a, id);
    for _ in 0..2 {
        assert_eq!(
            a.validate_transmit_group(3, group),
            Err(EndpointError::ReservationMtuTooSmall)
        );
        assert_eq!(
            a.accept_transmit_group(3, group),
            Err(EndpointError::ReservationMtuTooSmall)
        );
    }
    assert_eq!(snapshot(&a, id), before);
    assert!(a.reject_unsubmitted_group(group).unwrap());
    let mut total = 0;
    while a.is_output_reserved(id) {
        let (poll, attempt) = a.poll_reserved_transmit_for(3, id, &mut out, 1).unwrap();
        let p = poll.packet.unwrap();
        assert!(p.len + 20 <= 552);
        total += wire::parse(p.ip, &out[..p.len]).unwrap().payload.len();
        let attempt = attempt.unwrap();
        assert_eq!(a.prepare_transmit_group(attempt, limits()).unwrap(), None);
        assert!(a.accept_transmit(3, attempt).unwrap());
    }
    assert_eq!(total, 7 * 988);
}
