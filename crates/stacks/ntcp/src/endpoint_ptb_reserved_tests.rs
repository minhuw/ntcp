// Reserved exact-range PTB repair through the public reservation API: a
// racing path decrease that splits a reserved repair yields one accepted
// physical packet during Restart (the unsubmitted suffix returns to pending
// work, uncharged), and ordinary fragment acceptance outside it. Scalar and
// zero-copy (shared payload) output, both families, real peer receiver.
extern crate std;
use super::*;
use crate::{InitialWindow, Payload, TransmitAttempt};
use alloc::vec;

fn endpoint() -> Endpoint {
    Endpoint::new(
        EndpointConfig {
            max_connections: 4,
            max_listeners: 2,
            connection: ConnectionConfig {
                pmtud: Some(crate::PmtudConfig {
                    initial_search_low: Some(1500),
                    ..crate::PmtudConfig::new(1500)
                }),
                initial_window: InitialWindow::Iw10,
                nagle: false,
                sack: true,
                timestamps: false,
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

fn pair(ipv4: bool) -> (Endpoint, Endpoint, ConnectionId, ConnectionId, Tuple) {
    pair_with(ipv4, |a| {
        a.enable_output_reservations().unwrap();
        a.enable_shared_output(8).unwrap();
    })
}

fn pair_with(
    ipv4: bool,
    output: impl FnOnce(&mut Endpoint),
) -> (Endpoint, Endpoint, ConnectionId, ConnectionId, Tuple) {
    let mut a = endpoint();
    let mut b = endpoint();
    let (local, remote) = if ipv4 {
        ("192.0.2.1:40000", "192.0.2.2:8080")
    } else {
        ("[2001:db8::1]:40000", "[2001:db8::2]:8080")
    };
    let (local, remote) = (local.parse().unwrap(), remote.parse().unwrap());
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
    output(&mut a);
    (a, b, client, server, Tuple { local, remote })
}

// One reserved poll: wire bytes (header plus any loaned payload) and token.
fn reserve(
    a: &mut Endpoint,
    now: Instant,
    id: ConnectionId,
    shared: bool,
) -> Option<(Transmit, Vec<u8>, TransmitAttempt)> {
    let mut out = vec![0; 2048];
    let (poll, token) = if shared {
        let mut parts = Vec::with_capacity(8);
        let r = a
            .poll_reserved_transmit_shared_for(now, id, &mut out, &mut parts, 16)
            .unwrap();
        let loaned: usize = parts.iter().map(Payload::len).sum();
        if let Some(p) = r.0.packet {
            out.truncate(p.len - loaned);
            for part in &parts {
                out.extend_from_slice(part.as_slice());
            }
        }
        r
    } else {
        let r = a.poll_reserved_transmit_for(now, id, &mut out, 16).unwrap();
        if let Some(p) = r.0.packet {
            out.truncate(p.len);
        }
        r
    };
    let p = poll.packet?;
    Some((p, out, token.unwrap()))
}

fn segment(p: &Transmit, bytes: &[u8]) -> (Seq, usize) {
    let s = wire::parse(p.ip, bytes).unwrap();
    (Seq(s.header.sequence), s.payload.len())
}

// Every packet b emits now, fed straight into a.
fn feed(b: &mut Endpoint, a: &mut Endpoint, now: Instant) {
    let mut bytes = [0; 2048];
    while let Some(p) = b.poll_transmit(now, &mut bytes, 16).unwrap().packet {
        a.input(now, p.ip, &bytes[..p.len]).unwrap();
    }
}

#[test]
fn reserved_ptb_repair_split_by_racing_decrease_is_one_packet_in_restart() {
    for ipv4 in [true, false] {
        for shared in [false, true] {
            racing_decrease(ipv4, shared);
        }
    }
}

fn racing_decrease(ipv4: bool, shared: bool) {
    let (mut a, mut b, id, peer, tuple) = pair(ipv4);
    let header = if ipv4 { 20u16 } else { 40 };
    let mss = 1500 - usize::from(header) - 20;
    let data: Vec<u8> = (0..3 * mss).map(|i| (i % 251) as u8).collect();
    if shared {
        let n = a
            .write_shared(id, Payload::from_vec(data.clone()), false, false, None)
            .unwrap();
        assert_eq!(n, data.len());
    } else {
        assert_eq!(a.write(id, &data).unwrap(), data.len());
    }
    // Three full-sized originals; the middle one is dropped by the path.
    let mut originals = Vec::new();
    let mut out = [0; 2048];
    let mut now = 10;
    for _ in 0..3 {
        let (p, bytes, token) = reserve(&mut a, now, id, shared).unwrap();
        assert!(a.accept_transmit(now, token).unwrap());
        assert_eq!(p.len + usize::from(header), 1500);
        originals.push((segment(&p, &bytes), p, bytes));
    }
    let middle = originals[1].0;
    let base = originals[0].0.0;
    for k in [0, 2] {
        let (_, p, bytes) = &originals[k];
        b.input(now, p.ip, bytes).unwrap();
    }
    // The peer's SACKing ACKs are delayed on the return path.
    let mut held = Vec::new();
    while let Some(p) = b.poll_transmit(now, &mut out, 16).unwrap().packet {
        held.push((p, out[..p.len].to_vec()));
    }
    assert!(!held.is_empty());
    now += 1;
    // Non-head drop notification: Restart admits one repair packet.
    assert!(
        a.pmtu_feedback(now, tuple, middle.0.0, 1500, header, 1400)
            .unwrap()
    );
    let (p, bytes, token) = reserve(&mut a, now, id, shared).unwrap();
    let selected = segment(&p, &bytes);
    assert_eq!(selected.0, middle.0);
    assert_eq!(selected.1, 1400 - usize::from(header) - 20);
    // A decrease races the held reservation; the barrier refuses it unsent.
    let smaller = if ipv4 { 600 } else { 1300 };
    a.set_first_hop_mtu(now, id, smaller).unwrap();
    assert!(a.reject_unsubmitted(token).unwrap());
    let (p, bytes, token) = reserve(&mut a, now, id, shared).unwrap();
    assert!(p.len + usize::from(header) <= smaller as usize);
    let prefix = segment(&p, &bytes);
    assert_eq!(prefix.0, middle.0);
    assert!(prefix.1 < selected.1);
    assert!(a.accept_transmit(now, token).unwrap());
    // One accepted physical packet: the reservation ends there and the
    // suffix waits, uncharged, for useful ACK progress.
    assert!(!a.is_output_reserved(id));
    assert!(reserve(&mut a, now, id, shared).is_none());
    assert!(a.poll_transmit(now, &mut out, 16).unwrap().packet.is_none());
    b.input(now, p.ip, &bytes).unwrap();
    now += 1;
    for (p, bytes) in &held {
        a.input(now, p.ip, bytes).unwrap();
    }
    feed(&mut b, &mut a, now);
    // Useful progress ended Restart. The returned suffix is admitted under
    // ordinary congestion admission; another racing decrease now uses the
    // existing fragment acceptance, every fragment a physical packet.
    let suffix = middle.0.wrapping_add(prefix.1 as u32);
    let (p, bytes, token) = reserve(&mut a, now, id, shared).unwrap();
    let (seq, selected) = segment(&p, &bytes);
    assert_eq!(seq, suffix);
    let end = middle.0.wrapping_add(middle.1 as u32);
    let split = suffix.wrapping_add(selected as u32);
    assert_eq!(
        selected,
        (end.distance_from(suffix) as usize).min(smaller as usize - usize::from(header) - 20)
    );
    let smallest = if ipv4 { 400 } else { 1280 };
    a.set_first_hop_mtu(now, id, smallest).unwrap();
    assert!(a.reject_unsubmitted(token).unwrap());
    let mut at = suffix;
    let mut fragments = 0;
    while at != split {
        let (p, bytes, token) = reserve(&mut a, now, id, shared).unwrap();
        let (seq, len) = segment(&p, &bytes);
        assert!(p.len + usize::from(header) <= smallest as usize);
        assert_eq!(seq, at);
        assert!(a.accept_transmit(now, token).unwrap());
        b.input(now, p.ip, &bytes).unwrap();
        at = at.wrapping_add(len as u32);
        fragments += 1;
        assert_eq!(a.is_output_reserved(id), at != split);
    }
    // IPv6's 1280-octet floor leaves this 1500-octet path's suffix whole.
    assert_eq!(fragments > 1, ipv4);
    while at != end {
        let (p, bytes, token) = reserve(&mut a, now, id, shared).unwrap();
        let (seq, len) = segment(&p, &bytes);
        assert_eq!(seq, at);
        assert!(a.accept_transmit(now, token).unwrap());
        b.input(now, p.ip, &bytes).unwrap();
        at = at.wrapping_add(len as u32);
    }
    // Nothing was repaired twice and nothing else was retransmitted.
    assert!(reserve(&mut a, now, id, shared).is_none());
    feed(&mut b, &mut a, now);
    let progress = a.send_progress(id).unwrap();
    assert_eq!(
        progress.unacknowledged_sequence,
        base.wrapping_add(data.len() as u32).0
    );
    let mut got = vec![0; data.len()];
    assert_eq!(b.read(peer, &mut got).unwrap(), data.len());
    assert_eq!(got, data);
}

// Data plus FIN in one dropped packet, partially acknowledged through a
// reserved Restart repair at the reduced size: the reserved repair of the
// rest carries the FIN only when the quote covered the outstanding FIN (a
// separately sent FIN is not part of the dropped range).
#[test]
fn reserved_repair_after_partial_ack_carries_fin_only_if_quoted() {
    for ipv4 in [true, false] {
        for quoted in [true, false] {
            data_and_fin(ipv4, quoted);
        }
    }
}

fn fin_of(p: &Transmit, bytes: &[u8]) -> bool {
    wire::parse(p.ip, bytes).unwrap().header.flags & wire::FIN != 0
}

fn data_and_fin(ipv4: bool, quoted: bool) {
    let (mut a, mut b, id, peer, tuple) = pair(ipv4);
    let header = if ipv4 { 20u16 } else { 40 };
    let mss = 1500 - usize::from(header) - 20;
    let data: Vec<u8> = (0..2 * mss).map(|i| (i % 241) as u8).collect();
    assert_eq!(a.write(id, &data).unwrap(), data.len());
    if quoted {
        a.shutdown(id).unwrap();
    }
    let now = 10;
    let mut sent = Vec::new();
    for _ in 0..2 {
        let (p, bytes, token) = reserve(&mut a, now, id, false).unwrap();
        assert!(a.accept_transmit(now, token).unwrap());
        sent.push((segment(&p, &bytes), p, bytes));
    }
    assert_eq!(fin_of(&sent[1].1, &sent[1].2), quoted);
    let fin_only = if quoted {
        None
    } else {
        a.shutdown(id).unwrap();
        let (p, bytes, token) = reserve(&mut a, now, id, false).unwrap();
        assert!(a.accept_transmit(now, token).unwrap());
        assert!(fin_of(&p, &bytes) && segment(&p, &bytes).1 == 0);
        Some((p, bytes))
    };
    // s0 arrives (its ACK is still on the way); s1 was too big.
    b.input(now, sent[0].1.ip, &sent[0].2).unwrap();
    let ((start, len), _, _) = sent[1];
    assert!(
        a.pmtu_feedback(now + 1, tuple, start.0, 1500, header, 1280)
            .unwrap()
    );
    // The Restart repair: a prefix at the reduced size, without the FIN.
    let (p, bytes, token) = reserve(&mut a, now + 1, id, false).unwrap();
    let (seq, prefix) = segment(&p, &bytes);
    assert_eq!((seq, prefix), (start, 1280 - usize::from(header) - 20));
    assert!(!fin_of(&p, &bytes));
    assert!(a.accept_transmit(now + 1, token).unwrap());
    assert!(reserve(&mut a, now + 1, id, false).is_none());
    // The receiver acknowledges the prefix: a partial ACK of the quote.
    b.input(now + 2, p.ip, &bytes).unwrap();
    feed(&mut b, &mut a, now + 2);
    assert_eq!(
        a.send_progress(id).unwrap().unacknowledged_sequence,
        start.wrapping_add(prefix as u32).0
    );
    // The rest of the quoted data, plus the FIN only if it was quoted.
    let (p, bytes, token) = reserve(&mut a, now + 2, id, false).unwrap();
    let (seq, rest) = segment(&p, &bytes);
    assert_eq!(
        (seq, rest),
        (start.wrapping_add(prefix as u32), len - prefix)
    );
    assert_eq!(fin_of(&p, &bytes), quoted);
    assert!(a.accept_transmit(now + 2, token).unwrap());
    assert!(reserve(&mut a, now + 2, id, false).is_none());
    b.input(now + 3, p.ip, &bytes).unwrap();
    if let Some((p, bytes)) = &fin_only {
        b.input(now + 3, p.ip, bytes).unwrap();
    }
    feed(&mut b, &mut a, now + 3);
    // Everything, FIN included, is acknowledged without any other output.
    assert_eq!(
        a.send_progress(id).unwrap().unacknowledged_sequence,
        start.wrapping_add(len as u32 + 1).0
    );
    let mut got = vec![0; data.len() + 1];
    assert_eq!(b.read(peer, &mut got).unwrap(), data.len());
    assert_eq!(&got[..data.len()], &data[..]);
    assert_eq!(b.read(peer, &mut got).unwrap(), 0);
}

// A held PTB repair reservation and the owner's end: abort, close and
// release wait for the reservation; abandoning it ends the owner with no
// repair output, the generation is retired, and the connection that reuses
// the slot starts with no PTB work or history: only its own reports create
// repair work.
#[test]
fn held_ptb_reservation_owner_end_and_generation_reuse() {
    for ipv4 in [true, false] {
        held_reservation_end(ipv4);
    }
}

fn held_reservation_end(ipv4: bool) {
    let (mut a, mut b, id, _, tuple) = pair(ipv4);
    let header = if ipv4 { 20u16 } else { 40 };
    let mss = 1500 - usize::from(header) - 20;
    a.write(id, &vec![3; 3 * mss]).unwrap();
    let now = 10;
    let mut sent = Vec::new();
    for _ in 0..3 {
        let (p, bytes, token) = reserve(&mut a, now, id, false).unwrap();
        assert!(a.accept_transmit(now, token).unwrap());
        sent.push(segment(&p, &bytes));
    }
    assert!(
        a.pmtu_feedback(now, tuple, sent[1].0.0, 1500, header, 1280)
            .unwrap()
    );
    let (p, bytes, token) = reserve(&mut a, now, id, false).unwrap();
    assert_eq!(segment(&p, &bytes).0, sent[1].0);
    // The held reservation owns the connection.
    assert_eq!(a.abort(id), Err(EndpointError::OutputReserved));
    assert_eq!(a.close(id), Err(EndpointError::OutputReserved));
    assert_eq!(a.release(id), Err(EndpointError::OutputReserved));
    // Abandoning the certainly-unsubmitted repair ends the owner.
    assert!(a.abandon_transmit(token).unwrap());
    assert!(!a.is_output_reserved(id));
    assert!(!a.accept_transmit(now, token).unwrap());
    assert_eq!(a.state(id).unwrap(), State::Closed);
    // No repair (or other stream) output for the dead connection, and a
    // later report about it is no drop notification.
    let mut out = [0; 2048];
    while let Some(p) = a.poll_transmit(now + 1, &mut out, 16).unwrap().packet {
        let s = wire::parse(p.ip, &out[..p.len]).unwrap();
        assert!(s.payload.is_empty() && s.header.flags & wire::RST != 0);
    }
    assert!(
        !a.pmtu_feedback(now + 1, tuple, sent[2].0.0, 1500, header, 1280)
            .unwrap_or(false)
    );
    a.release(id).unwrap();
    while a
        .poll_transmit(now + 1, &mut out, 16)
        .unwrap()
        .packet
        .is_some()
    {}
    assert!(!a.connection_exists(id));
    // A new connection reuses the slot under a new generation.
    let local = if ipv4 {
        "192.0.2.1:40001"
    } else {
        "[2001:db8::1]:40001"
    };
    let next = a
        .connect(now + 2, local.parse().unwrap(), tuple.remote)
        .unwrap();
    assert_eq!(next.slot, id.slot);
    assert_ne!(next.generation, id.generation);
    assert!(!a.accept_transmit(now + 2, token).unwrap());
    for i in 0..3 {
        let (src, dst) = if i == 1 {
            (&mut b, &mut a)
        } else {
            (&mut a, &mut b)
        };
        let p = src
            .poll_transmit(now + 2, &mut out, 16)
            .unwrap()
            .packet
            .unwrap();
        dst.input(now + 2, p.ip, &out[..p.len]).unwrap();
    }
    let new_tuple = a.tuple(next).unwrap();
    a.write(next, &vec![4; 3 * mss]).unwrap();
    let mut fresh = Vec::new();
    for _ in 0..3 {
        let (p, bytes, token) = reserve(&mut a, now + 3, next, false).unwrap();
        assert!(a.accept_transmit(now + 3, token).unwrap());
        fresh.push(segment(&p, &bytes));
    }
    // Every output was an original: nothing carried over.
    for w in fresh.windows(2) {
        assert_eq!(w[0].0.wrapping_add(w[0].1 as u32), w[1].0);
    }
    assert!(reserve(&mut a, now + 3, next, false).is_none());
    // Its own report repairs exactly its own quoted packet.
    assert!(
        a.pmtu_feedback(now + 4, new_tuple, fresh[2].0.0, 1500, header, 1280)
            .unwrap()
    );
    let (p, bytes, token) = reserve(&mut a, now + 4, next, false).unwrap();
    assert_eq!(segment(&p, &bytes).0, fresh[2].0);
    assert!(a.accept_transmit(now + 4, token).unwrap());
    assert!(reserve(&mut a, now + 4, next, false).is_none());
}

// Partial software GSO at the reservation level: an aggregate's first
// segment is accepted (and dropped by the path), a racing decrease splits the
// rest into smaller physical packets, and a PTB then quotes the accepted
// segment. Only its bytes are repaired, from the immutable submitted data,
// and each accepted segment was charged once: the aggregate itself is never
// a transmission, and the rejected selection charges nothing.
#[test]
fn partial_gso_aggregate_then_ptb_repairs_only_the_quoted_accepted_segment() {
    for ipv4 in [true, false] {
        partial_gso(ipv4);
    }
}

fn partial_gso(ipv4: bool) {
    let (mut a, mut b, id, peer, tuple) = pair_with(ipv4, |a| {
        a.enable_output_reservations_with_gso(
            1,
            crate::GsoLimits {
                max_bytes: 5000,
                max_segments: 4,
            },
        )
        .unwrap();
    });
    let header = if ipv4 { 20u16 } else { 40 };
    let mss = 1500 - usize::from(header) - 20;
    let data: Vec<u8> = (0..4 * mss).map(|i| (i % 239) as u8).collect();
    a.write(id, &data).unwrap();
    let now = 10;
    let mut out = vec![0; 2048];
    let (poll, token) = a.poll_reserved_transmit_for(now, id, &mut out, 16).unwrap();
    let (p, token) = (poll.packet.unwrap(), token.unwrap());
    let gso = a.transmit_segmentation(token).expect("GSO aggregate");
    assert_eq!(gso.segment_payload_len, mss);
    assert!(gso.payload_len > mss);
    let first = segment(&p, &out[..p.len]);
    assert_eq!(first.1, mss);
    let cwnd = a.transport_info(id).unwrap().cwnd;
    // Only the first segment is accepted; the path drops it.
    assert!(a.accept_transmit(now, token).unwrap());
    assert!(a.is_output_reserved(id));
    assert_eq!(
        a.send_progress(id).unwrap().unacknowledged_sequence,
        first.0.0
    );
    // The next segment's selection is refused unsent by a racing decrease.
    let (_, token) = a.poll_reserved_transmit_for(now, id, &mut out, 16).unwrap();
    let smaller = if ipv4 { 1000 } else { 1280 };
    a.set_first_hop_mtu(now, id, smaller).unwrap();
    assert!(a.reject_unsubmitted(token.unwrap()).unwrap());
    assert_eq!(a.transport_info(id).unwrap().retransmitted, 0);
    // The rest of the aggregate leaves as smaller physical packets, each in
    // sequence after the immutable accepted prefix. They are delayed on the
    // path (arriving after the repair), so no SACK loss inference competes.
    let mut delayed = Vec::new();
    let mut at = first.0.wrapping_add(mss as u32);
    let end = first.0.wrapping_add(gso.payload_len as u32);
    while a.is_output_reserved(id) {
        let (poll, token) = a.poll_reserved_transmit_for(now, id, &mut out, 16).unwrap();
        let p = poll.packet.unwrap();
        assert!(p.len + usize::from(header) <= smaller as usize);
        let (seq, len) = segment(&p, &out[..p.len]);
        assert_eq!(seq, at);
        at = at.wrapping_add(len as u32);
        assert!(a.accept_transmit(now, token.unwrap()).unwrap());
        delayed.push((p, out[..p.len].to_vec()));
    }
    assert_eq!(at, end);
    assert_eq!(a.transport_info(id).unwrap().retransmitted, 0);
    // The PTB quotes the accepted 1500-octet segment. The local estimate is
    // already lower, so this is a nondecreasing drop notification.
    let estimate = a.path_mtu_info(id).unwrap().unwrap().current_mtu;
    assert!(
        a.pmtu_feedback(now + 1, tuple, first.0.0, 1500, header, 1280.min(smaller))
            .unwrap()
    );
    assert_eq!(a.path_mtu_info(id).unwrap().unwrap().current_mtu, estimate);
    // No congestion response beyond the link decrease's MSS rescaling.
    let info = a.transport_info(id).unwrap();
    let (rescaled, ssthresh) = (info.cwnd, info.ssthresh);
    assert!(rescaled <= cwnd && !info.recovery);
    // Exactly the quoted segment is repaired: one Restart packet, then the
    // rest after useful ACK progress, never beyond the quoted bytes.
    let mut repaired = first.0;
    let quoted_end = first.0.wrapping_add(mss as u32);
    let mut t = now + 1;
    let mut restart = true;
    while repaired != quoted_end {
        assert!(t < now + 20);
        let mut sent = 0;
        while let Some((p, bytes, token)) = reserve(&mut a, t, id, false) {
            let (seq, len) = segment(&p, &bytes);
            assert!(a.accept_transmit(t, token).unwrap());
            if seq.after(quoted_end) || seq == quoted_end {
                // Fresh data after the aggregate.
                assert!(seq.at_or_after(end));
            } else {
                assert_eq!(seq, repaired);
                assert!(!seq.wrapping_add(len as u32).after(quoted_end));
                repaired = seq.wrapping_add(len as u32);
                sent += 1;
            }
            b.input(t, p.ip, &bytes).unwrap();
        }
        if restart {
            assert_eq!(sent, 1);
            restart = false;
        }
        let info = a.transport_info(id).unwrap();
        assert!(info.cwnd >= rescaled && info.ssthresh == ssthresh && !info.recovery);
        feed(&mut b, &mut a, t);
        t += 1;
    }
    for (p, bytes) in &delayed {
        b.input(t, p.ip, bytes).unwrap();
    }
    feed(&mut b, &mut a, t);
    while let Some((p, bytes, token)) = reserve(&mut a, t, id, false) {
        assert!(segment(&p, &bytes).0.at_or_after(end));
        assert!(a.accept_transmit(t, token).unwrap());
        b.input(t, p.ip, &bytes).unwrap();
        feed(&mut b, &mut a, t);
    }
    let progress = a.send_progress(id).unwrap();
    assert_eq!(
        progress.unacknowledged_sequence,
        first.0.wrapping_add(data.len() as u32).0
    );
    let mut got = vec![0; data.len()];
    assert_eq!(b.read(peer, &mut got).unwrap(), data.len());
    assert_eq!(got, data);
}
