extern crate std;
use super::*;
use crate::connection::test_support::{
    departure_snapshot, probe_size, recovering, timer_recovering,
};
use std::vec::Vec;

// A connected pair whose client polls through one GSO reservation. The
// peer's receive buffer bounds the client's send window.
fn pair(
    ipv6: bool,
    timestamps: bool,
    peer_receive: usize,
) -> (Endpoint, Endpoint, ConnectionId, ConnectionId) {
    let (mut a, b, client, server) = connected(ipv6, timestamps, peer_receive);
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

fn connected(
    ipv6: bool,
    timestamps: bool,
    peer_receive: usize,
) -> (Endpoint, Endpoint, ConnectionId, ConnectionId) {
    connected_with(ipv6, timestamps, peer_receive, |_| {})
}

// `connected` with `adjust` applied to both sides' configuration.
fn connected_with(
    ipv6: bool,
    timestamps: bool,
    peer_receive: usize,
    adjust: impl Fn(&mut ConnectionConfig),
) -> (Endpoint, Endpoint, ConnectionId, ConnectionId) {
    let config = |receive| {
        let mut config = ConnectionConfig {
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
        adjust(&mut config);
        config
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
// tcp_gso_segment does: full segments and the remainder, PSH and FIN on the
// last, CWR on the first only.
fn cut(view: &crate::TransmitGroupView<'_>) -> Vec<Vec<u8>> {
    let size = view.segment_payload_len;
    (0..view.segment_count)
        .map(|n| {
            let mut header = view.header;
            header.sequence = header.sequence.wrapping_add((n * size) as u32);
            if n + 1 != view.segment_count {
                header.flags &= !(wire::PSH | wire::FIN);
            }
            if n != 0 {
                header.flags &= !wire::CWR;
            }
            let mut out = [0; 2048];
            let len = wire::encode(
                view.packet.ip,
                header,
                view.options,
                &view.payload[n * size..((n + 1) * size).min(view.payload.len())],
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
                assert_eq!(
                    view.segment_count,
                    s.payload_len.div_ceil(s.segment_payload_len)
                );
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
                        // Each physical segment's own size, the short last
                        // one included.
                        let ip_header = if ipv6 { 40 } else { 20 };
                        let actual = crate::PhysicalReceipt {
                            ip_packet_len: (ip_header + segment.len()) as u32,
                            ..each
                        };
                        b.accept_transmit_submitted(3, attempt, actual).unwrap()
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
    // Seven full segments and the short last one.
    let mut wire = group(&mut a, id, 2);
    assert_eq!(wire.len(), 8);
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

// The SACK blocks of each sender's data, segment by segment.
fn sack_blocks(wire: &[Vec<u8>]) -> Vec<[Option<(u32, u32)>; 4]> {
    wire.iter()
        .map(|s| wire::parse(ip(), s).unwrap().options.sack_blocks)
        .collect()
}

// Data reporting ordinary SACK blocks goes as a group that repeats them on
// every segment, as Linux TSO repeats the skb's options and as scalar
// output repeats them while the hole stays. A D-SACK is reported once
// (RFC 2883 section 4): its segment stays scalar, and the rest groups.
#[test]
fn sack_blocks_repeat_in_a_group_but_a_dsack_stays_scalar() {
    for dsack in [false, true] {
        let (mut a, mut peer, id, server) = pair(false, true, 16_384);
        let (mut b, _, bid, _) = pair(false, true, 16_384);
        let (mut c, _, cid, _) = connected(false, true, 16_384);
        c.enable_output_reservations().unwrap();
        peer.write(server, &[9; 3000]).unwrap();
        let from_peer = sent(&mut peer, 2);
        assert!(from_peer.len() >= 3);
        // The second is lost: the third arrives out of order. A repeated
        // first is a duplicate below the hole.
        let mut arriving = std::vec![from_peer[0].clone(), from_peer[2].clone()];
        if dsack {
            arriving.push(from_peer[0].clone());
        }
        for (e, id) in [(&mut a, id), (&mut b, bid), (&mut c, cid)] {
            for (ip, segment) in &arriving {
                e.input(2, *ip, segment).unwrap();
            }
            e.write(id, &[1; 7000]).unwrap();
        }
        let (wire, groups) = drain(&mut a, id, 3);
        assert_eq!(wire, scalar(&mut b, bid, 3));
        assert_eq!(wire, scalar(&mut c, cid, 3));
        assert_eq!(snapshot(&a, id), snapshot(&b, bid));
        assert!(!groups.is_empty());
        let blocks = sack_blocks(&wire);
        // One duplicate block, on the first segment only, then the hole's.
        let ordinary = if dsack { &blocks[1] } else { &blocks[0] };
        assert!(ordinary[0].is_some());
        if dsack {
            assert_ne!(blocks[0], *ordinary);
            assert_eq!(groups[0], wire.len() - 1);
        } else {
            assert_eq!(groups[0], wire.len());
        }
        let skip = usize::from(dsack);
        assert!(blocks[skip..].iter().all(|b| b == ordinary));
        // The peer, missing nothing it will not be repaired, reads it all.
        for segment in &wire {
            peer.input(4, ip(), segment).unwrap();
        }
        assert_eq!(peer.read(server, &mut [0; 8000]).unwrap(), 7000);
    }
}

// A FIN queued behind the data ends the group on its last segment, as
// tcp_gso_segment keeps FIN on the last segment of a TSO skb; a backend
// without PSH/FIN support leaves that segment scalar.
#[test]
fn queued_fin_ends_a_group_on_its_last_segment() {
    for (length, allow_psh) in [(7000, true), (7 * 988, true), (7000, false)] {
        for nagle in [false, true] {
            let (mut a, mut peer, id, server) = pair(false, true, 16_384);
            let (mut b, _, bid, _) = pair(false, true, 16_384);
            let (mut c, _, cid, _) = connected(false, true, 16_384);
            c.enable_output_reservations().unwrap();
            let data: Vec<u8> = (0..length).map(|i| (i * 5) as u8).collect();
            for (e, id) in [(&mut a, id), (&mut b, bid), (&mut c, cid)] {
                e.set_nagle(id, nagle).unwrap();
                e.write(id, &data).unwrap();
                e.close(id).unwrap();
            }
            let mut out = [0; 2048];
            let (_, attempt) = a.poll_reserved_transmit_for(2, id, &mut out, 1).unwrap();
            let s = a.transmit_segmentation(attempt.unwrap()).unwrap();
            assert_eq!(s.payload_len, length);
            assert_ne!(s.terminal_flags & wire::FIN, 0);
            // The first scalar segment never carries the range's FIN.
            let first = wire::parse(ip(), &out[..32 + s.segment_payload_len]).unwrap();
            assert_eq!(first.header.flags & (wire::FIN | wire::PSH), 0);
            let group = a
                .prepare_transmit_group(
                    attempt.unwrap(),
                    crate::TransmitGroupLimits {
                        allow_psh,
                        ..limits()
                    },
                )
                .unwrap()
                .unwrap();
            let view = a.transmit_group(group).unwrap();
            let segments = length.div_ceil(988);
            assert_eq!(view.segment_count, segments - usize::from(!allow_psh));
            assert_eq!(view.header.flags & wire::FIN != 0, allow_psh);
            let mut wire = cut(&view);
            // Scalar acceptance of the same segments records the same.
            let scalar_b = scalar(&mut b, bid, 2);
            for (n, segment) in wire.iter().enumerate() {
                assert_eq!(segment, &scalar_b[n]);
            }
            assert!(a.accept_transmit_group(2, group).unwrap());
            wire.extend(ungroupable(&mut a, id, 2));
            assert_eq!(wire, scalar_b);
            assert_eq!(snapshot(&a, id), snapshot(&b, bid));
            // And selection without GSO sends the same wire.
            assert_eq!(wire, scalar(&mut c, cid, 2));
            let last = wire::parse(ip(), wire.last().unwrap()).unwrap();
            assert_eq!(last.header.flags & wire::FIN, wire::FIN);
            for segment in &wire[..wire.len() - 1] {
                let flags = wire::parse(ip(), segment).unwrap().header.flags;
                assert_eq!(flags & (wire::FIN | wire::PSH), 0);
            }
            for segment in &wire {
                peer.input(3, ip(), segment).unwrap();
            }
            assert_eq!(peer.read(server, &mut [0; 8000]).unwrap(), length);
            assert_eq!(peer.state(server).unwrap(), State::CloseWait);
            // The peer's ACK of data and FIN completes both alike.
            let acks = sent(&mut peer, 3);
            for (ip, ack) in &acks {
                a.input(4, *ip, ack).unwrap();
                b.input(4, *ip, ack).unwrap();
            }
            assert_eq!(snapshot(&a, id), snapshot(&b, bid));
            assert_eq!(a.state(id).unwrap(), State::FinWait2);
        }
    }
}

fn ip() -> crate::IpMetadata {
    crate::IpMetadata {
        source: "192.0.2.1".parse().unwrap(),
        destination: "192.0.2.2".parse().unwrap(),
    }
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
    assert_eq!(total, 7000);
}

// Polls `id` at `now` until it holds nothing, sending every attempt that
// can become a group as one and the rest as scalar segments. Returns the
// wire and the segment count of each group.
fn drain(e: &mut Endpoint, id: ConnectionId, now: Instant) -> (Vec<Vec<u8>>, Vec<usize>) {
    let mut out = [0; 2048];
    let (mut wire, mut groups) = (Vec::new(), Vec::new());
    loop {
        let (poll, attempt) = e.poll_reserved_transmit_for(now, id, &mut out, 16).unwrap();
        let Some(p) = poll.packet else {
            return (wire, groups);
        };
        let attempt = attempt.unwrap();
        if let Some(group) = e.prepare_transmit_group(attempt, limits()).unwrap() {
            let segments = cut(&e.transmit_group(group).unwrap());
            groups.push(segments.len());
            wire.extend(segments);
            assert!(e.accept_transmit_group(now, group).unwrap());
        } else {
            wire.push(out[..p.len].to_vec());
            assert!(e.accept_transmit(now, attempt).unwrap());
        }
    }
}

#[test]
fn short_last_segment_joins_a_group_exactly_when_scalar_selection_sends_it() {
    type Write = fn(&mut Endpoint, ConnectionId);
    // (Nagle, writes, segments of each group); 988-byte segments.
    let cases: [(bool, Write, &[usize]); 6] = [
        // The response's last bytes go at once: 7 x 988 + 84.
        (
            false,
            |e, id| {
                e.write(id, &[1; 7000]).unwrap();
            },
            &[8],
        ),
        // Nagle holds them while the full segments are unacknowledged.
        (
            true,
            |e, id| {
                e.write(id, &[1; 7000]).unwrap();
            },
            &[7],
        ),
        // A completed record ends its group with its last bytes, even under
        // Nagle; the next record is a group of its own.
        (
            true,
            |e, id| {
                e.write_with_options(id, &[1; 2500], false, true).unwrap();
                e.write(id, &[2; 3000]).unwrap();
            },
            &[3, 3],
        ),
        // More data is promised (MSG_MORE) or not pushed: held, as in
        // scalar selection.
        (
            false,
            |e, id| {
                e.write_with_options(id, &[1; 7000], true, false).unwrap();
            },
            &[7],
        ),
        (
            false,
            |e, id| {
                e.write_with_push(id, &[1; 7000], false).unwrap();
            },
            &[7],
        ),
        // Exactly full segments: no short one.
        (
            false,
            |e, id| {
                e.write(id, &[1; 4 * 988]).unwrap();
            },
            &[4],
        ),
    ];
    for (nagle, write, groups) in cases {
        let (mut a, _, id, _) = pair(false, true, 16_384);
        let (mut b, _, bid, _) = connected(false, true, 16_384);
        b.enable_output_reservations().unwrap();
        a.set_nagle(id, nagle).unwrap();
        b.set_nagle(bid, nagle).unwrap();
        write(&mut a, id);
        write(&mut b, bid);
        let (wire, sizes) = drain(&mut a, id, 2);
        assert_eq!(sizes, groups);
        // The wire is what selection without GSO sends at that instant.
        assert_eq!(wire, scalar(&mut b, bid, 2));
    }
}

// Delivers `wire` to `peer` at `now` and returns its ACKs.
fn deliver(
    peer: &mut Endpoint,
    wire: &[Vec<u8>],
    now: Instant,
) -> Vec<(crate::IpMetadata, Vec<u8>)> {
    let mut acks = Vec::new();
    for segment in wire {
        peer.input(now, ip(), segment).unwrap();
        acks.extend(sent(peer, now));
    }
    acks
}

// New data in loss recovery: the recovery credit (PRR's, or RFC 6675's
// cwnd - pipe) admits groups, which send what scalar selection sends after
// the repair, as Linux sends TSO skbs within PRR's quota.
#[test]
fn recovery_groups_new_data_within_its_credit() {
    for prr in [false, true] {
        assert_ne!(lossy_transfer(prr, 1, recovering), 0, "prr {prr}");
    }
}

// Sends 16000 bytes from three senders alike: one that sends every
// groupable attempt as a group, one polling the same GSO reservations
// scalar, and one without GSO. The first `lost` segments of the first
// flight are lost. Checks they send the same wire and the first two
// record the same throughout; returns the groups sent while `during`.
fn lossy_transfer(prr: bool, lost: usize, during: fn(&crate::connection::Connection) -> bool) -> usize {
    let gso = |(mut e, peer, id, server): (Endpoint, Endpoint, ConnectionId, ConnectionId)| {
        e.enable_output_reservations_with_gso(
            1,
            crate::GsoLimits {
                max_bytes: 8000,
                max_segments: 8,
            },
        )
        .unwrap();
        (e, peer, id, server)
    };
    let (mut a, mut peer, id, server) = gso(connected_with(false, true, 65_535, |c| c.prr = prr));
    let (mut b, _, bid, _) = gso(connected_with(false, true, 65_535, |c| c.prr = prr));
    let (mut c, _, cid, _) = connected_with(false, true, 65_535, |c| c.prr = prr);
    c.enable_output_reservations().unwrap();
    let data: Vec<u8> = (0..16_000).map(|i| (i * 11) as u8).collect();
    for (e, id) in [(&mut a, id), (&mut b, bid), (&mut c, cid)] {
        assert_eq!(e.write(id, &data).unwrap(), data.len());
    }
    let mut now = 2;
    let (wire, _) = drain(&mut a, id, now);
    assert_eq!(wire, scalar(&mut b, bid, now));
    assert_eq!(wire, scalar(&mut c, cid, now));
    let mut acks = deliver(&mut peer, &wire[lost.min(wire.len())..], 3);
    let mut groups_during = 0;
    for _ in 0..64 {
        now += 1;
        for (ip, ack) in &acks {
            a.input(now, *ip, ack).unwrap();
            b.input(now, *ip, ack).unwrap();
            c.input(now, *ip, ack).unwrap();
        }
        assert_eq!(snapshot(&a, id), snapshot(&b, bid));
        let counted = during(&a.retained_slot(id).unwrap().connection);
        let (wire, groups) = drain(&mut a, id, now);
        if counted {
            groups_during += groups.len();
        }
        assert_eq!(wire, scalar(&mut b, bid, now));
        assert_eq!(wire, scalar(&mut c, cid, now));
        assert_eq!(snapshot(&a, id), snapshot(&b, bid));
        if wire.is_empty() {
            if a.send_progress(id).unwrap().acknowledged == data.len() as u64 {
                break;
            }
            // Nothing to send until a timer: the peer's (a delayed ACK) or
            // the senders', run on all three alike.
            let deadline = a.next_deadline().unwrap();
            assert_eq!(b.next_deadline(), Some(deadline));
            acks.clear();
            if let Some(ack_at) = peer.next_deadline().filter(|&t| t < deadline) {
                now = ack_at;
                peer.on_timeout(now, 16).unwrap();
                acks = sent(&mut peer, now);
            } else {
                now = deadline;
                for e in [&mut a, &mut b, &mut c] {
                    e.on_timeout(now, 16).unwrap();
                }
            }
            continue;
        }
        acks = deliver(&mut peer, &wire, now);
    }
    assert_eq!(
        a.send_progress(id).unwrap().acknowledged,
        data.len() as u64
    );
    let mut received = std::vec![0; 16_000];
    let mut n = 0;
    while n < received.len() {
        let read = peer.read(server, &mut received[n..]).unwrap();
        assert_ne!(read, 0);
        n += read;
    }
    assert_eq!(received, data);
    groups_during
}

// After a retransmission timeout, while its repairs are under way (RFC
// 6675 section 5.1 / go-back-N to the timeout's boundary), new data that
// cwnd admits is grouped too, as Linux sends TSO skbs in the Loss state.
#[test]
fn groups_follow_a_retransmission_timeout() {
    for prr in [false, true] {
        assert_ne!(
            lossy_transfer(prr, usize::MAX, timer_recovering),
            0,
            "prr {prr}"
        );
    }
}

// With a PMTU probe out, the trailing segments behind it go as a group and
// leave what their scalar acceptance leaves, the probe's PMTU state
// included; the peer's ACKs then confirm the probe alike.
#[test]
fn group_after_a_pmtu_probe_records_what_scalar_acceptance_records() {
    // A peer MSS above the 1040-byte search floor allows an upward probe.
    let gso = |(mut e, peer, id, server): (Endpoint, Endpoint, ConnectionId, ConnectionId)| {
        e.enable_output_reservations_with_gso(
            1,
            crate::GsoLimits {
                max_bytes: 8000,
                max_segments: 8,
            },
        )
        .unwrap();
        (e, peer, id, server)
    };
    let (mut a, mut peer, id, _) = gso(connected_with(false, true, 65_535, |c| c.mss = 1460));
    let (mut b, _, bid, _) = gso(connected_with(false, true, 65_535, |c| c.mss = 1460));
    let data: Vec<u8> = (0..12_000).map(|i| (i * 13) as u8).collect();
    a.write(id, &data).unwrap();
    b.write(bid, &data).unwrap();
    let probe = |e: &Endpoint, id| probe_size(&e.retained_slot(id).unwrap().connection);
    let search_low = |e: &Endpoint, id| e.path_mtu_info(id).unwrap().unwrap().search_low;
    let before = search_low(&a, id);
    // The probe: one scalar segment above the search floor.
    let mut out = [0; 2048];
    let mut wire = Vec::new();
    for (e, id) in [(&mut a, id), (&mut b, bid)] {
        let (poll, attempt) = e.poll_reserved_transmit_for(2, id, &mut out, 1).unwrap();
        let p = poll.packet.unwrap();
        let attempt = attempt.unwrap();
        assert_eq!(e.transmit_segmentation(attempt), None);
        assert!(e.accept_transmit(2, attempt).unwrap());
        assert_eq!(probe(e, id), Some(p.len as u32 + 20));
        assert!(p.len as u32 + 20 > before);
        if wire.is_empty() {
            wire.push(out[..p.len].to_vec());
        }
    }
    assert_eq!(snapshot(&a, id), snapshot(&b, bid));
    let (rest, groups) = drain(&mut a, id, 2);
    assert!(!groups.is_empty());
    assert!(probe(&a, id).is_some());
    assert_eq!(rest, scalar(&mut b, bid, 2));
    assert_eq!(snapshot(&a, id), snapshot(&b, bid));
    wire.extend(rest);
    let acks = deliver(&mut peer, &wire, 3);
    for (ip, ack) in &acks {
        a.input(4, *ip, ack).unwrap();
        b.input(4, *ip, ack).unwrap();
    }
    assert_eq!(snapshot(&a, id), snapshot(&b, bid));
    // The probe succeeded behind the group.
    assert_eq!(probe(&a, id), None);
    assert!(search_low(&a, id) > before);
}

// Bulk output keeps forming groups while PLPMTUD searches from its default
// start (card 3 saw none over 600 KB): probes go out alone, the segments
// around them in groups, as Linux keeps TSO output during MTU probing.
#[test]
fn groups_form_while_plpmtud_searches() {
    let gso = |(mut e, peer, id, server): (Endpoint, Endpoint, ConnectionId, ConnectionId)| {
        e.enable_output_reservations_with_gso(
            1,
            crate::GsoLimits {
                max_bytes: 16_000,
                max_segments: 16,
            },
        )
        .unwrap();
        (e, peer, id, server)
    };
    let adjust = |c: &mut ConnectionConfig| {
        c.mss = 1460;
        c.pmtud = Some(crate::PmtudConfig::new(1500));
    };
    let (mut a, mut peer, id, server) = gso(connected_with(false, true, 65_535, adjust));
    let (mut c, _, cid, _) = connected_with(false, true, 65_535, adjust);
    c.enable_output_reservations().unwrap();
    let total = 600_000;
    let (mut written, mut received, mut grouped, mut probes) = (0, 0, 0, 0);
    let mut now = 2;
    while received < total {
        let chunk: Vec<u8> = (written..(written + 16_384).min(total))
            .map(|i| (i * 7) as u8)
            .collect();
        let n = a.write(id, &chunk).unwrap();
        assert_eq!(c.write(cid, &chunk).unwrap(), n);
        written += n;
        let (wire, groups) = drain(&mut a, id, now);
        assert_eq!(wire, scalar(&mut c, cid, now));
        grouped += groups.iter().sum::<usize>();
        probes += usize::from(probe_size(&a.retained_slot(id).unwrap().connection).is_some());
        let mut acks = deliver(&mut peer, &wire, now);
        if acks.is_empty() {
            now = peer.next_deadline().unwrap();
            peer.on_timeout(now, 16).unwrap();
            acks = sent(&mut peer, now);
        }
        now += 1;
        for (ip, ack) in &acks {
            a.input(now, *ip, ack).unwrap();
            c.input(now, *ip, ack).unwrap();
        }
        let mut buffer = [0; 65_536];
        while let Ok(n) = peer.read(server, &mut buffer) {
            if n == 0 {
                break;
            }
            received += n;
        }
    }
    let info = a.path_mtu_info(id).unwrap().unwrap();
    assert_eq!(info.search_low, 1500, "{info:?}");
    assert!(probes != 0);
    // Most of the transfer leaves in groups.
    let segments = total.div_ceil(1448);
    assert!(grouped > segments / 2, "{grouped} of {segments}");
}
