// Managed send-space ceiling C: logical capacity B rounded down to whole
// segments of the size in use Q (RFC 1191 section 6.4), B itself below one
// segment. Raw Endpoint connections keep B.
use super::*;

fn no_discovery(cfg: &mut ConnectionConfig) {
    cfg.pmtud = None;
}

fn set_link_mtu(a: &mut Connection, service: &mut PathService, mtu: u32) {
    let mut prepared = a.managed_path.unwrap();
    service
        .set_link_mtu(prepared.snapshot.key().link(), mtu)
        .unwrap();
    prepared.snapshot = service.snapshot(prepared.client).unwrap();
    a.apply_managed_budget(prepared).unwrap();
}

fn write_all(a: &mut Connection, data: &[u8]) -> usize {
    match a.write(data) {
        Ok(n) => n,
        Err(Error::WouldBlock) => 0,
        Err(error) => panic!("{error:?}"),
    }
}

fn read_all(b: &mut Connection, received: &mut Vec<u8>) {
    let mut buf = vec![0; 65536];
    while let Ok(n) = b.read(&mut buf) {
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }
}

// Writes `total` bytes as admission allows, delivering every segment and
// ACK, until the receiver has all of them. Queued plus unacknowledged
// payload never exceeds the fixed C.
fn transfer(a: &mut Connection, b: &mut Connection, total: usize, mut now: Instant) -> Instant {
    let data: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    let space = a.send_space();
    let (mut written, mut received) = (0, Vec::new());
    let mut out = vec![0; 65535];
    for _ in 0..20_000 {
        if written < total {
            written += write_all(a, &data[written..]);
        }
        assert!(a.send.len() <= space);
        while let Some(n) = a.transmit(now, &mut out).unwrap() {
            b.input(now, &wire::parse(ip(a.tuple), &out[..n]).unwrap()).unwrap();
        }
        assert!(a.data_flight() as usize <= space);
        read_all(b, &mut received);
        while let Some(n) = b.transmit(now, &mut out).unwrap() {
            a.input(now, &wire::parse(ip(b.tuple), &out[..n]).unwrap()).unwrap();
        }
        if received.len() == total {
            assert_eq!(received, data);
            assert_eq!(a.send.len(), 0);
            return now;
        }
        now = a.next_deadline().map_or(now + 1, |deadline| deadline.max(now + 1));
        a.timeout(now).unwrap();
    }
    panic!("{} of {total} bytes delivered", received.len());
}

//= https://www.rfc-editor.org/rfc/rfc1191#section-6.4
//= type=test
//= reason=Managed connections bound unacknowledged plus queued payload by a send-space ceiling C: the logical send-buffer capacity B rounded down to the greatest multiple of Q, the segment size in use under the current PMTU. User disposition (decision A, 2026-11-04, recorded): Q, the ordinary effective data payload segments actually carry (the PMTU less the fixed IP and TCP headers and negotiated timestamps, within the peer, user and local send ceilings), is this paragraph's segment size (PMTU - 40), because the literal PMTU - 40 would reintroduce the partial segment the rule avoids; the two agree only for option-free IPv4 without a lower transport ceiling (IPv4 PMTU 1500 with timestamps: Q = 1448 and B = 20000 give C = 18824, the literal formula 18980). User disposition (decision A, 2026-11-04, recorded): for a legal buffer below one segment C = B, because the literal greatest multiple, zero, would deadlock it; the peer and congestion windows still bound what is outstanding, so no credit is invented. C is derived on demand, so every PMTU decrease and increase, MSS negotiation, user-cap, header and buffer change applies before the next admission or output. Write admission and readiness use C, and every fresh-output branch (ordinary, Limited Transmit, PRR, RFC 6675 recovery, TLP, Fast Open and early-response data, reserved, shared and GSO totals, PLPMTUD probes) sends at most C less the unacknowledged payload, repairing instead when none is left; retransmission, exact-range repair, FIN, persist and keepalive take none of it, data admitted above a smaller C drains through ACKs, snd_wnd, max_snd_wnd and cwnd are unchanged and reported capacity stays B. Core tests (connection_send_space_tests.rs) cover B = 1, Q-1, Q, Q+1, 2Q-1 and multiples through receiver completion and the largest legal capacity arithmetically, peer windows 0, 1, Q-1, Q and Q+1, cwnd below and above C, PMTU and buffer changes below the flight, partial ACK, SACK and sequence wrap; native tests re-round SO_SNDBUF on PTB feedback with truthful getsockopt and writable edges, tun_echo admits whole segments across a PMTU change, and the integration/rfc_host mss send-space case captures distinct outstanding bytes reaching exactly C for a non-multiple B below the peer window and cwnd before any ACK advancement, then complete delivery verified by length and hash. Raw Endpoints keep B as their legacy contract.
//# TCP performance can be reduced if the sender's maximum window size is not an exact
//# multiple of the segment size in use (this is not the congestion window size, which is
//# always a multiple of the segment size). In many system (such as those derived from
//# 4.2BSD), the segment size is often set to 1024 octets, and the maximum window size (the
//# "send space") is usually a multiple of 1024 octets, so the proper relationship holds by
//# default. If PMTU Discovery is used, however, the segment size may not be a submultiple
//# of the send space, and it may change during a connection; this means that the TCP layer
//# may need to change the transmission window size when PMTU Discovery changes the PMTU
//# value. The maximum window size should be set to the greatest multiple of the segment
//# size (PMTU - 40) that is less than or equal to the sender's buffer space size.
#[test]
fn rounded_send_space_arithmetic_covers_every_boundary() {
    for q in [1, 536, 988, 1448, 1460, 65495] {
        let mut cases = vec![q, q + 1, 2 * q - 1, 2 * q, 7 * q, (1 << 30) - 1];
        if q > 1 {
            cases.extend([1, q - 1]);
        }
        for b in cases {
            let c = rounded_send_space(b, q);
            assert!(c != 0 && c <= b);
            if b < q {
                assert_eq!(c, b);
            } else {
                assert_eq!(c % q, 0);
                assert!(b - c < q);
            }
        }
    }
    // The largest legal capacity, arithmetic only.
    assert_eq!(rounded_send_space((1 << 30) - 1, 1448), 1_073_741_232);
    assert_eq!(rounded_send_space((1 << 30) - 1, 65495), 1_073_725_030);
    assert_eq!(rounded_send_space(1, 1448), 1);
    assert_eq!(rounded_send_space(1447, 1448), 1447);
    assert_eq!(rounded_send_space(1449, 1448), 1448);
    assert_eq!(rounded_send_space(2895, 1448), 1448);
    assert_eq!(rounded_send_space(2896, 1448), 2896);
}

//= https://www.rfc-editor.org/rfc/rfc1191#section-6.4
//= type=test
//= reason=Managed connections bound unacknowledged plus queued payload by a send-space ceiling C: the logical send-buffer capacity B rounded down to the greatest multiple of Q, the segment size in use under the current PMTU. User disposition (decision A, 2026-11-04, recorded): Q, the ordinary effective data payload segments actually carry (the PMTU less the fixed IP and TCP headers and negotiated timestamps, within the peer, user and local send ceilings), is this paragraph's segment size (PMTU - 40), because the literal PMTU - 40 would reintroduce the partial segment the rule avoids; the two agree only for option-free IPv4 without a lower transport ceiling (IPv4 PMTU 1500 with timestamps: Q = 1448 and B = 20000 give C = 18824, the literal formula 18980). User disposition (decision A, 2026-11-04, recorded): for a legal buffer below one segment C = B, because the literal greatest multiple, zero, would deadlock it; the peer and congestion windows still bound what is outstanding, so no credit is invented. C is derived on demand, so every PMTU decrease and increase, MSS negotiation, user-cap, header and buffer change applies before the next admission or output. Write admission and readiness use C, and every fresh-output branch (ordinary, Limited Transmit, PRR, RFC 6675 recovery, TLP, Fast Open and early-response data, reserved, shared and GSO totals, PLPMTUD probes) sends at most C less the unacknowledged payload, repairing instead when none is left; retransmission, exact-range repair, FIN, persist and keepalive take none of it, data admitted above a smaller C drains through ACKs, snd_wnd, max_snd_wnd and cwnd are unchanged and reported capacity stays B. Core tests (connection_send_space_tests.rs) cover B = 1, Q-1, Q, Q+1, 2Q-1 and multiples through receiver completion and the largest legal capacity arithmetically, peer windows 0, 1, Q-1, Q and Q+1, cwnd below and above C, PMTU and buffer changes below the flight, partial ACK, SACK and sequence wrap; native tests re-round SO_SNDBUF on PTB feedback with truthful getsockopt and writable edges, tun_echo admits whole segments across a PMTU change, and the integration/rfc_host mss send-space case captures distinct outstanding bytes reaching exactly C for a non-multiple B below the peer window and cwnd before any ACK advancement, then complete delivery verified by length and hash. Raw Endpoints keep B as their legacy contract.
//# TCP performance can be reduced if the sender's maximum window size is not an exact
//# multiple of the segment size in use (this is not the congestion window size, which is
//# always a multiple of the segment size). In many system (such as those derived from
//# 4.2BSD), the segment size is often set to 1024 octets, and the maximum window size (the
//# "send space") is usually a multiple of 1024 octets, so the proper relationship holds by
//# default. If PMTU Discovery is used, however, the segment size may not be a submultiple
//# of the send space, and it may change during a connection; this means that the TCP layer
//# may need to change the transmission window size when PMTU Discovery changes the PMTU
//# value. The maximum window size should be set to the greatest multiple of the segment
//# size (PMTU - 40) that is less than or equal to the sender's buffer space size.
// Q is the payload segments carry: with timestamps at IPv4 PMTU 1500 it is
// 1448, not the literal PMTU - 40.
#[test]
fn managed_admission_uses_timestamp_segment_not_literal_pmtu_minus_40() {
    for ipv4 in [true, false] {
        let (mut a, _b, _, _) = managed_pair_configured(ipv4, 1_000_000, |cfg| {
            cfg.timestamps = true;
            cfg.send_capacity = 20000;
        });
        let q = if ipv4 { 1448 } else { 1428 };
        assert_eq!(a.mss, q);
        let c = 20000 / q * q;
        assert_eq!(a.write(&[1; 30000]).unwrap(), c);
        assert_eq!(a.write(&[1]), Err(Error::WouldBlock));
        assert_eq!(a.send_admission_room(None), 0);
        let info = a.transport_info();
        assert_eq!((info.send_used, info.send_capacity, info.send_space), (c, 20000, c));
        assert_eq!(a.buffer_capacities().0, 20000);
        if ipv4 {
            assert_eq!(c, 18824);
            assert_ne!(c, 20000 / 1460 * 1460);
        }
    }
    // A raw Endpoint connection keeps its legacy whole-buffer admission.
    let (mut a, _) = pair(
        ConnectionConfig {
            timestamps: true,
            ..config(20000, 1460)
        },
        100,
    );
    assert_eq!(a.write(&[1; 30000]).unwrap(), 20000);
    assert_eq!(a.transport_info().send_space, 20000);
}

#[test]
fn managed_admission_uses_a_peer_mss_below_pmtu_minus_40() {
    let (mut a, _b, _, _) = managed_pair_with_peer(
        true,
        1_000_000,
        |cfg| cfg.send_capacity = 4500,
        |peer| peer.mss = 1000,
    );
    assert_eq!(a.mss, 1000);
    assert_eq!(a.write(&[1; 9000]).unwrap(), 4000);
    assert_eq!(a.transport_info().send_space, 4000);
}

//= https://www.rfc-editor.org/rfc/rfc1191#section-6.4
//= type=test
//= reason=Managed connections bound unacknowledged plus queued payload by a send-space ceiling C: the logical send-buffer capacity B rounded down to the greatest multiple of Q, the segment size in use under the current PMTU. User disposition (decision A, 2026-11-04, recorded): Q, the ordinary effective data payload segments actually carry (the PMTU less the fixed IP and TCP headers and negotiated timestamps, within the peer, user and local send ceilings), is this paragraph's segment size (PMTU - 40), because the literal PMTU - 40 would reintroduce the partial segment the rule avoids; the two agree only for option-free IPv4 without a lower transport ceiling (IPv4 PMTU 1500 with timestamps: Q = 1448 and B = 20000 give C = 18824, the literal formula 18980). User disposition (decision A, 2026-11-04, recorded): for a legal buffer below one segment C = B, because the literal greatest multiple, zero, would deadlock it; the peer and congestion windows still bound what is outstanding, so no credit is invented. C is derived on demand, so every PMTU decrease and increase, MSS negotiation, user-cap, header and buffer change applies before the next admission or output. Write admission and readiness use C, and every fresh-output branch (ordinary, Limited Transmit, PRR, RFC 6675 recovery, TLP, Fast Open and early-response data, reserved, shared and GSO totals, PLPMTUD probes) sends at most C less the unacknowledged payload, repairing instead when none is left; retransmission, exact-range repair, FIN, persist and keepalive take none of it, data admitted above a smaller C drains through ACKs, snd_wnd, max_snd_wnd and cwnd are unchanged and reported capacity stays B. Core tests (connection_send_space_tests.rs) cover B = 1, Q-1, Q, Q+1, 2Q-1 and multiples through receiver completion and the largest legal capacity arithmetically, peer windows 0, 1, Q-1, Q and Q+1, cwnd below and above C, PMTU and buffer changes below the flight, partial ACK, SACK and sequence wrap; native tests re-round SO_SNDBUF on PTB feedback with truthful getsockopt and writable edges, tun_echo admits whole segments across a PMTU change, and the integration/rfc_host mss send-space case captures distinct outstanding bytes reaching exactly C for a non-multiple B below the peer window and cwnd before any ACK advancement, then complete delivery verified by length and hash. Raw Endpoints keep B as their legacy contract.
//# TCP performance can be reduced if the sender's maximum window size is not an exact
//# multiple of the segment size in use (this is not the congestion window size, which is
//# always a multiple of the segment size). In many system (such as those derived from
//# 4.2BSD), the segment size is often set to 1024 octets, and the maximum window size (the
//# "send space") is usually a multiple of 1024 octets, so the proper relationship holds by
//# default. If PMTU Discovery is used, however, the segment size may not be a submultiple
//# of the send space, and it may change during a connection; this means that the TCP layer
//# may need to change the transmission window size when PMTU Discovery changes the PMTU
//# value. The maximum window size should be set to the greatest multiple of the segment
//# size (PMTU - 40) that is less than or equal to the sender's buffer space size.
#[test]
fn managed_boundary_buffers_admit_c_and_deliver_to_completion() {
    const Q: usize = 1460;
    for b in [1, Q - 1, Q, Q + 1, 2 * Q - 1, 3 * Q, 3 * Q + 1] {
        let (mut a, mut peer, _, _) = managed_pair_configured(true, 1_000_000, |cfg| {
            no_discovery(cfg);
            cfg.send_capacity = b;
        });
        assert_eq!(a.mss, Q);
        let c = if b < Q { b } else { b / Q * Q };
        assert_eq!(a.send_space(), c, "B = {b}");
        assert_eq!(a.send_admission_room(None), c);
        transfer(&mut a, &mut peer, 3 * Q + 123, 10);
    }
}

//= https://www.rfc-editor.org/rfc/rfc1191#section-6.4
//= type=test
//= reason=Managed connections bound unacknowledged plus queued payload by a send-space ceiling C: the logical send-buffer capacity B rounded down to the greatest multiple of Q, the segment size in use under the current PMTU. User disposition (decision A, 2026-11-04, recorded): Q, the ordinary effective data payload segments actually carry (the PMTU less the fixed IP and TCP headers and negotiated timestamps, within the peer, user and local send ceilings), is this paragraph's segment size (PMTU - 40), because the literal PMTU - 40 would reintroduce the partial segment the rule avoids; the two agree only for option-free IPv4 without a lower transport ceiling (IPv4 PMTU 1500 with timestamps: Q = 1448 and B = 20000 give C = 18824, the literal formula 18980). User disposition (decision A, 2026-11-04, recorded): for a legal buffer below one segment C = B, because the literal greatest multiple, zero, would deadlock it; the peer and congestion windows still bound what is outstanding, so no credit is invented. C is derived on demand, so every PMTU decrease and increase, MSS negotiation, user-cap, header and buffer change applies before the next admission or output. Write admission and readiness use C, and every fresh-output branch (ordinary, Limited Transmit, PRR, RFC 6675 recovery, TLP, Fast Open and early-response data, reserved, shared and GSO totals, PLPMTUD probes) sends at most C less the unacknowledged payload, repairing instead when none is left; retransmission, exact-range repair, FIN, persist and keepalive take none of it, data admitted above a smaller C drains through ACKs, snd_wnd, max_snd_wnd and cwnd are unchanged and reported capacity stays B. Core tests (connection_send_space_tests.rs) cover B = 1, Q-1, Q, Q+1, 2Q-1 and multiples through receiver completion and the largest legal capacity arithmetically, peer windows 0, 1, Q-1, Q and Q+1, cwnd below and above C, PMTU and buffer changes below the flight, partial ACK, SACK and sequence wrap; native tests re-round SO_SNDBUF on PTB feedback with truthful getsockopt and writable edges, tun_echo admits whole segments across a PMTU change, and the integration/rfc_host mss send-space case captures distinct outstanding bytes reaching exactly C for a non-multiple B below the peer window and cwnd before any ACK advancement, then complete delivery verified by length and hash. Raw Endpoints keep B as their legacy contract.
//# TCP performance can be reduced if the sender's maximum window size is not an exact
//# multiple of the segment size in use (this is not the congestion window size, which is
//# always a multiple of the segment size). In many system (such as those derived from
//# 4.2BSD), the segment size is often set to 1024 octets, and the maximum window size (the
//# "send space") is usually a multiple of 1024 octets, so the proper relationship holds by
//# default. If PMTU Discovery is used, however, the segment size may not be a submultiple
//# of the send space, and it may change during a connection; this means that the TCP layer
//# may need to change the transmission window size when PMTU Discovery changes the PMTU
//# value. The maximum window size should be set to the greatest multiple of the segment
//# size (PMTU - 40) that is less than or equal to the sender's buffer space size.
#[test]
fn pmtu_changes_move_c_and_keep_admitted_data_above_it() {
    let (mut a, mut b, mut service, _) = managed_pair_configured(true, 1_000_000, |cfg| {
        no_discovery(cfg);
        cfg.send_capacity = 2000;
    });
    a.take_events();
    assert_eq!(a.write(&[1; 5000]).unwrap(), 1460);
    assert_eq!(a.write(&[1]), Err(Error::WouldBlock));
    // A smaller segment leaves less unused space: C grows to 2 * 860.
    set_link_mtu(&mut a, &mut service, 900);
    assert_eq!((a.mss, a.send_space()), (860, 1720));
    assert!(a.take_events().writable);
    assert_eq!(a.write(&[2; 5000]).unwrap(), 260);
    // Back at 1500, C = 1460 is below the 1720 admitted bytes: they stay.
    set_link_mtu(&mut a, &mut service, 1500);
    assert_eq!((a.mss, a.send_space(), a.send.len()), (1460, 1460, 1720));
    let info = a.transport_info();
    assert!(info.send_used > info.send_space);
    assert_eq!(a.write(&[3]), Err(Error::WouldBlock));
    assert!(!a.take_events().writable);
    // Only C leaves before an ACK; the rest drains as ACKs reopen it.
    let mut received = Vec::new();
    exchange(&mut a, &mut b, 10);
    read_all(&mut b, &mut received);
    assert_eq!(received.len(), 1460);
    exchange(&mut a, &mut b, 11);
    read_all(&mut b, &mut received);
    assert_eq!(received.len(), 1720);
    assert_eq!(a.send.len(), 0);
    assert!(a.take_events().writable);
    assert_eq!(a.send_admission_room(None), 1460);
}

#[test]
fn pmtu_decrease_below_queue_reopens_on_partial_ack() {
    let (mut a, mut b, mut service, _) = managed_pair_configured(true, 1_000_000, |cfg| {
        no_discovery(cfg);
        cfg.send_capacity = 4400;
    });
    assert_eq!(a.write(&[1; 9000]).unwrap(), 4380);
    set_link_mtu(&mut a, &mut service, 1000);
    assert_eq!((a.mss, a.send_space(), a.send.len()), (960, 3840, 4380));
    assert_eq!(a.send_admission_room(None), 0);
    a.take_events();
    // One 960-octet segment acknowledged: 3420 queued, 420 octets of room.
    deliver(&mut a, &mut b, 10);
    deliver(&mut b, &mut a, 11);
    assert_eq!(a.send.len(), 3420);
    assert!(a.take_events().writable);
    assert_eq!(a.send_admission_room(None), 420);
    assert_eq!(a.write(&[2; 9000]).unwrap(), 420);
}

#[test]
fn resize_with_unchanged_mss_recomputes_c_and_reports_b() {
    let (mut a, _b, _, _) = managed_pair_configured(true, 1_000_000, |cfg| {
        no_discovery(cfg);
        cfg.send_capacity = 4400;
    });
    assert_eq!(a.write(&[1; 9000]).unwrap(), 4380);
    a.set_buffer_capacities(3000, 65536, usize::MAX).unwrap();
    assert_eq!(a.buffer_capacities().0, 3000);
    assert_eq!((a.send_space(), a.send.len()), (2920, 4380));
    assert_eq!(a.write(&[2]), Err(Error::WouldBlock));
    a.take_events();
    a.set_buffer_capacities(6000, 65536, usize::MAX).unwrap();
    let info = a.transport_info();
    assert_eq!((info.send_capacity, info.send_space), (6000, 5840));
    assert!(a.take_events().writable);
    // Shared payload takes the same admission as copied bytes.
    let shared = crate::Payload::from_vec(vec![3; 9000]);
    a.prepare_shared_storage(&shared, usize::MAX).unwrap();
    assert_eq!(a.write_shared(shared, false, false, None).unwrap(), 1460);
    assert_eq!(a.send_admission_room(None), 0);
}

// Fast Open installs the cached or default peer MSS before the SYN-ACK
// updates the segment size; C follows it from the first admission.
#[test]
fn fast_open_peer_mss_installation_sets_c_before_admission() {
    for (cached, q) in [(Some(500), 500), (None, 536)] {
        let cfg = ConnectionConfig {
            pmtud: None,
            ..config(1200, 1460)
        };
        let tuple = tuple();
        let (_service, prepared, _) = authority(tuple, cfg.timebase);
        let mut a = Connection::active_with_receive_path(
            tuple,
            cfg,
            100,
            0,
            &mut None,
            Some(prepared),
            crate::ReceiveIpCapability::new(ContextId::new(101), false, 1500),
            None,
        )
        .unwrap();
        assert_eq!(a.send_space(), 1200);
        let early = a
            .prepare_fast_open_without_cookie(cached, &[1; 2000], usize::MAX)
            .unwrap();
        assert!(early != 0);
        assert_eq!(a.send_space(), 1200 / q * q);
        assert_eq!(early + a.write(&[2; 2000]).unwrap(), 1200 / q * q);
    }
}

// Every packet `a` has ready at `now`, undelivered.
fn segments(a: &mut Connection, now: Instant) -> Vec<Vec<u8>> {
    let mut out = vec![0; 65535];
    let mut sent = Vec::new();
    while let Some(n) = a.transmit(now, &mut out).unwrap() {
        sent.push(out[..n].to_vec());
    }
    sent
}

fn payload(a: &Connection, bytes: &[u8]) -> (u32, usize) {
    let segment = wire::parse(ip(a.tuple), bytes).unwrap();
    (segment.header.sequence, segment.payload.len())
}

fn input_all(from: &Connection, to: &mut Connection, sent: &[Vec<u8>], now: Instant) {
    for bytes in sent {
        to.input(now, &wire::parse(ip(from.tuple), bytes).unwrap()).unwrap();
    }
}

// Runs both sides, timers included, until `b` has read `total` bytes and
// `a` holds nothing; output never carries unacknowledged payload above C.
fn complete(
    a: &mut Connection,
    b: &mut Connection,
    received: &mut Vec<u8>,
    total: usize,
    mut now: Instant,
) {
    let mut out = vec![0; 65535];
    for _ in 0..20_000 {
        let before = a.data_flight();
        while let Some(n) = a.transmit(now, &mut out).unwrap() {
            b.input(now, &wire::parse(ip(a.tuple), &out[..n]).unwrap()).unwrap();
        }
        // New payload only fills C; a flight already above it never grows.
        assert!(a.data_flight() <= before || a.data_flight() as usize <= a.send_space());
        read_all(b, received);
        while let Some(n) = b.transmit(now, &mut out).unwrap() {
            a.input(now, &wire::parse(ip(b.tuple), &out[..n]).unwrap()).unwrap();
        }
        if received.len() == total && a.send.len() == 0 {
            return;
        }
        now = [a.next_deadline(), b.next_deadline()]
            .into_iter()
            .flatten()
            .min()
            .map_or(now + 1, |deadline| deadline.max(now + 1));
        a.timeout(now).unwrap();
        b.timeout(now).unwrap();
    }
    panic!("{} of {total} bytes delivered", received.len());
}

// Queues 3Q, sends it, queues 3Q more, then shrinks B so C = 2Q lies below
// the 3Q flight. Returns the original segments, undelivered.
fn flight_above_c(a: &mut Connection, q: usize, now: Instant) -> Vec<Vec<u8>> {
    assert_eq!(a.write(&vec![1; 3 * q]).unwrap(), 3 * q);
    let first = segments(a, now);
    assert_eq!((first.len(), a.data_flight() as usize), (3, 3 * q));
    assert_eq!(a.write(&vec![2; 3 * q]).unwrap(), 3 * q);
    a.set_buffer_capacities(2 * q + 700, 65536, usize::MAX).unwrap();
    assert_eq!(a.send_space(), 2 * q);
    first
}

// After C falls below the flight, no new payload leaves until ACKs bring the
// flight below C; the RTO head retransmission still leaves, and partial ACKs
// release exactly the reopened allowance. Sequence numbers wrap on the way.
#[test]
fn flight_above_reduced_c_blocks_fresh_output_but_not_retransmission() {
    const Q: usize = 1460;
    let (mut a, mut b, _, _) = managed_pair_configured(true, 1_000_000, |cfg| {
        no_discovery(cfg);
        cfg.send_capacity = 6 * Q;
    });
    let first = flight_above_c(&mut a, Q, 10);
    let (cwnd, nxt) = (a.congestion.cwnd(), a.snd_nxt);
    assert!(cwnd as usize > 6 * Q && a.snd_wnd as usize > 6 * Q);
    assert!(segments(&mut a, 11).is_empty());
    assert_eq!(a.snd_nxt, nxt);
    // One segment acknowledged: the 2Q flight equals C, still no new payload.
    input_all(&a, &mut b, &first[..1], 12);
    let ack = segments(&mut b, 12);
    input_all(&b, &mut a, &ack, 12);
    assert_eq!(a.data_flight() as usize, 2 * Q);
    assert!(segments(&mut a, 13).is_empty());
    // A second acknowledged segment reopens exactly one segment of allowance.
    input_all(&a, &mut b, &first[1..2], 14);
    let ack = segments(&mut b, 14);
    input_all(&b, &mut a, &ack, 14);
    let fresh = segments(&mut a, 15);
    assert_eq!(fresh.len(), 1);
    assert_eq!(payload(&a, &fresh[0]), (nxt.0, Q));
    assert_eq!(a.data_flight() as usize, 2 * Q);
    // The RTO repairs the head without advancing fresh output.
    let nxt = a.snd_nxt;
    let deadline = a.rto_deadline.unwrap();
    a.timeout(deadline).unwrap();
    let retry = segments(&mut a, deadline);
    assert_eq!(retry.len(), 1);
    assert_eq!(payload(&a, &retry[0]), (a.snd_una.0, Q));
    assert_eq!(a.snd_nxt, nxt);
    let mut received = Vec::new();
    read_all(&mut b, &mut received);
    complete(&mut a, &mut b, &mut received, 6 * Q, deadline);
    assert_eq!(&received[..3 * Q], &[1; 3 * Q][..]);
    assert_eq!(&received[3 * Q..], &[2; 3 * Q][..]);
}

// C only removes credit: whichever of the peer window, cwnd and C - flight
// is smallest bounds new payload, and neither window is altered by C.
#[test]
fn fresh_output_is_the_minimum_of_peer_window_cwnd_and_c() {
    const Q: usize = 1460;
    // cwnd (IW10) above C: C bounds the first flight.
    for window in [None, Some(0), Some(1), Some(Q - 1), Some(Q), Some(Q + 1)] {
        let (mut a, mut b, _, _) = managed_pair_configured(true, 1_000_000, |cfg| {
            no_discovery(cfg);
            cfg.send_capacity = 6 * Q;
        });
        assert_eq!(a.write(&[1; 6 * Q]).unwrap(), 6 * Q);
        a.set_buffer_capacities(2 * Q + 700, 65536, usize::MAX).unwrap();
        if let Some(window) = window {
            a.snd_wnd = window as u32;
            a.arm_work();
        }
        let (cwnd, wnd) = (a.congestion.cwnd(), a.snd_wnd);
        assert!(cwnd as usize > 2 * Q);
        let sent = segments(&mut a, 10);
        let bytes: usize = sent.iter().map(|s| payload(&a, s).1).sum();
        let bound = (wnd as usize).min(2 * Q);
        assert!(bytes <= bound, "window {window:?}: {bytes}");
        if window.is_none_or(|w| w >= Q) {
            assert_eq!(bytes, bound / Q * Q, "window {window:?}");
        }
        assert_eq!((a.congestion.cwnd(), a.snd_wnd), (cwnd, wnd));
        assert_eq!(a.data_flight() as usize, bytes);
        input_all(&a, &mut b, &sent, 10);
        let mut received = Vec::new();
        complete(&mut a, &mut b, &mut received, 6 * Q, 11);
        assert_eq!(received, vec![1; 6 * Q]);
    }
    // cwnd below C: the congestion window bounds the flight, unchanged.
    let (mut a, mut b, _, _) = managed_pair_configured(true, 1_000_000, |cfg| {
        no_discovery(cfg);
        cfg.send_capacity = 30_000;
    });
    let c = 30_000 / Q * Q;
    assert_eq!(a.write(&[3; 30_000]).unwrap(), c);
    let cwnd = a.congestion.cwnd() as usize;
    assert!(cwnd < c);
    let sent = segments(&mut a, 10);
    assert_eq!(a.data_flight() as usize, cwnd);
    assert_eq!(a.congestion.cwnd() as usize, cwnd);
    input_all(&a, &mut b, &sent, 10);
    let mut received = Vec::new();
    complete(&mut a, &mut b, &mut received, c, 11);
    assert_eq!(received, vec![3; c]);
}

// TLP chooses new data only with fresh credit; without it, it probes with
// the highest outstanding segment instead.
#[test]
fn tlp_sends_new_data_only_with_fresh_allowance() {
    const Q: usize = 1460;
    for shrink in [false, true] {
        let (mut a, mut b, _, _) = managed_pair_configured(true, 1_000_000, |cfg| {
            no_discovery(cfg);
            cfg.sack = true;
            cfg.rack = true;
            cfg.tlp = true;
            cfg.send_capacity = 6 * Q;
        });
        // One round trip gives TLP its RTT sample.
        a.write(&[9; Q]).unwrap();
        exchange(&mut a, &mut b, 10);
        assert_eq!(a.send.len(), 0);
        assert_eq!(a.write(&[1; 3 * Q]).unwrap(), 3 * Q);
        let first = segments(&mut a, 20);
        assert_eq!(first.len(), 3);
        assert_eq!(a.write(&[2; 3 * Q]).unwrap(), 3 * Q);
        let nxt = a.snd_nxt;
        if shrink {
            a.set_buffer_capacities(2 * Q + 700, 65536, usize::MAX).unwrap();
            assert!(segments(&mut a, 21).is_empty());
        } else {
            // Peer-window credit keeps the rest of the queue unsent here;
            // once it reopens, the probe leads with new data.
            a.snd_wnd = (3 * Q) as u32;
            assert!(segments(&mut a, 21).is_empty());
            a.snd_wnd = (6 * Q) as u32;
        }
        let Some((LossTimer::Pto, pto)) = a.loss_timer else {
            panic!("{:?}", a.loss_timer);
        };
        a.timeout(pto).unwrap();
        let probe = segments(&mut a, pto);
        let (seq, len) = payload(&a, &probe[0]);
        if shrink {
            assert_eq!(probe.len(), 1);
            assert_eq!((seq, len), (payload(&a, &first[2]).0, Q));
            assert_eq!(a.snd_nxt, nxt);
        } else {
            assert_eq!((seq, len), (nxt.0, Q));
        }
        input_all(&a, &mut b, &first, pto);
        input_all(&a, &mut b, &probe, pto);
        let mut received = Vec::new();
        complete(&mut a, &mut b, &mut received, 7 * Q, pto);
        assert_eq!(received.len(), 7 * Q);
    }
}

// FIN takes sequence space, not send space: it still leaves with the flight
// above the reduced C, and C never bounds a zero-window persist probe.
#[test]
fn fin_and_persist_probe_do_not_consume_send_space() {
    const Q: usize = 1460;
    let (mut a, mut b, _, _) = managed_pair_configured(true, 1_000_000, |cfg| {
        no_discovery(cfg);
        cfg.send_capacity = 3 * Q;
    });
    assert_eq!(a.write(&[1; 3 * Q]).unwrap(), 3 * Q);
    let first = segments(&mut a, 10);
    a.set_buffer_capacities(Q + 1, 65536, usize::MAX).unwrap();
    assert_eq!(a.send_space(), Q);
    a.shutdown().unwrap();
    let fin = segments(&mut a, 11);
    assert_eq!(fin.len(), 1);
    let segment = wire::parse(ip(a.tuple), &fin[0]).unwrap();
    assert!(segment.header.flags & FIN != 0 && segment.payload.is_empty());
    input_all(&a, &mut b, &first, 12);
    input_all(&a, &mut b, &fin, 12);
    let mut received = Vec::new();
    read_all(&mut b, &mut received);
    assert_eq!(received.len(), 3 * Q);

    let (mut a, _b, _, _) = managed_pair_configured(true, 1_000_000, |cfg| {
        no_discovery(cfg);
        cfg.send_capacity = 3 * Q;
    });
    a.write(&[1; 3 * Q]).unwrap();
    a.set_buffer_capacities(1, 65536, usize::MAX).unwrap();
    a.snd_wnd = 0;
    a.arm_work();
    assert!(segments(&mut a, 10).is_empty());
    let deadline = a.next_deadline().unwrap();
    a.timeout(deadline).unwrap();
    let probe = segments(&mut a, deadline);
    assert_eq!(probe.len(), 1);
    assert_eq!(a.data_flight(), 0);
}

// Data admitted above a C below one segment drains on ACK progress: each
// segment of C octets leaves when the ACK arrives, with no sender SWS hold
// until the override timer.
#[test]
fn data_above_sub_segment_c_drains_on_ack_progress() {
    const Q: usize = 1460;
    for b in [1, Q - 1] {
        let (mut a, mut peer, _, _) = managed_pair_configured(true, 1_000_000, |cfg| {
            no_discovery(cfg);
            cfg.send_capacity = 3 * Q;
        });
        let data: Vec<u8> = (0..3 * Q).map(|i| (i % 251) as u8).collect();
        assert_eq!(a.write(&data).unwrap(), 3 * Q);
        a.set_buffer_capacities(b, 65536, usize::MAX).unwrap();
        assert_eq!(a.send_space(), b);
        let (mut now, mut received) = (10, Vec::new());
        while received.len() < 3 * Q {
            // The sender is serviced only by the ACK, never by its timers.
            let sent = segments(&mut a, now);
            assert_eq!(sent.len(), 1, "B = {b}, {} received", received.len());
            assert_eq!(payload(&a, &sent[0]).1, b.min(3 * Q - received.len()));
            input_all(&a, &mut peer, &sent, now);
            read_all(&mut peer, &mut received);
            let mut ack = segments(&mut peer, now);
            if ack.is_empty() {
                now = peer.next_deadline().unwrap();
                assert!(a.sws_deadline.is_none_or(|deadline| now < deadline));
                peer.timeout(now).unwrap();
                ack = segments(&mut peer, now);
            }
            input_all(&peer, &mut a, &ack, now);
        }
        assert_eq!(received, data);
        assert_eq!((a.send.len(), a.data_flight()), (0, 0));
    }
}

// RFC 6675 NextSeg prefers new data only with fresh send space. Without it
// Limited Transmit sends nothing new and, after a partial ACK, recovery
// takes its rescue retransmission instead of new data.
#[test]
fn rfc6675_recovery_repairs_instead_of_sending_new_data_without_allowance() {
    const Q: usize = 1460;
    let (mut a, mut b, _, _) = managed_pair_configured(true, 1_000_000, |cfg| {
        no_discovery(cfg);
        cfg.sack = true;
        cfg.send_capacity = 9 * Q;
    });
    assert!(a.sack_recovery_enabled() && !a.rack_enabled());
    assert_eq!(a.write(&[1; 9 * Q]).unwrap(), 9 * Q);
    a.snd_wnd = (8 * Q) as u32;
    let first = segments(&mut a, 10);
    assert_eq!(first.len(), 8);
    a.set_buffer_capacities(Q + 700, 65536, usize::MAX).unwrap();
    assert_eq!(a.send_space(), Q);
    let nxt = a.snd_nxt;
    // Segment 1 is lost; 2..7 arrive and are SACKed.
    let mut repairs = Vec::new();
    for segment in &first[1..7] {
        input_all(&a, &mut b, core::slice::from_ref(segment), 11);
        let acks = segments(&mut b, 11);
        input_all(&b, &mut a, &acks, 11);
        repairs.extend(segments(&mut a, 11));
    }
    assert!(a.sack_recovery.is_some());
    assert_eq!(a.snd_nxt, nxt);
    assert_eq!(repairs.len(), 1);
    assert_eq!(payload(&a, &repairs[0]), payload(&a, &first[0]));
    // The repair's partial ACK leaves segment 8 (one C) outstanding.
    input_all(&a, &mut b, &repairs, 12);
    let acks = segments(&mut b, 12);
    input_all(&b, &mut a, &acks, 12);
    assert!(a.sack_recovery.is_some());
    assert_eq!(a.data_flight() as usize, Q);
    let rescue = segments(&mut a, 12);
    assert_eq!(rescue.len(), 1);
    assert_eq!(payload(&a, &rescue[0]), payload(&a, &first[7]));
    assert_eq!(a.snd_nxt, nxt);
    let mut received = Vec::new();
    read_all(&mut b, &mut received);
    complete(&mut a, &mut b, &mut received, 9 * Q, 13);
    assert_eq!(received, vec![1; 9 * Q]);
}

// Reserved, GSO and shared selections share the scalar fresh allowance.
#[test]
fn reserved_gso_and_shared_totals_stay_within_c() {
    const Q: usize = 1460;
    for shared in [false, true] {
        let (mut a, _b, _, _) = managed_pair_configured(true, 1_000_000, |cfg| {
            no_discovery(cfg);
            cfg.send_capacity = 6 * Q;
        });
        if shared {
            let data = crate::Payload::from_vec(vec![5; 6 * Q]);
            a.prepare_shared_storage(&data, usize::MAX).unwrap();
            assert_eq!(a.write_shared(data, false, false, None).unwrap(), 6 * Q);
        } else {
            assert_eq!(a.write(&[5; 6 * Q]).unwrap(), 6 * Q);
        }
        a.set_buffer_capacities(2 * Q + 700, 65536, usize::MAX).unwrap();
        let mut bytes = vec![0; 65535];
        let mut total = 0;
        if shared {
            let mut parts = Vec::with_capacity(4);
            while a
                .transmit_shared_selected(10, &mut bytes, &mut parts)
                .unwrap()
                .is_some()
            {
                total += a.last_departure.unwrap().payload;
                test_support::commit_reserved(&mut a, 10);
            }
        } else {
            let mut gso = vec![0; 8 * Q];
            let n = a
                .transmit_selected_with_gso(
                    10,
                    &mut bytes,
                    true,
                    Some(crate::output_reservation::GsoBuffer {
                        limits: crate::GsoLimits {
                            max_bytes: 8 * Q,
                            max_segments: 8,
                        },
                        payload: &mut gso,
                    }),
                )
                .unwrap();
            assert!(n.is_some());
            let d = a.last_departure.unwrap();
            assert_eq!(d.segmentation.map(|s| s.payload_len), Some(2 * Q));
            total += d.payload;
            test_support::commit_reserved(&mut a, 10);
            assert!(a.transmit_selected(11, &mut bytes, true).unwrap().is_none());
        }
        assert_eq!((total, a.data_flight() as usize), (2 * Q, 2 * Q), "shared {shared}");
    }
}

// Fast Open initial data is fresh payload: it leaves within C even when a
// resize after admission lowers C below the queued bytes.
#[test]
fn fast_open_syn_data_stays_within_c() {
    for cached in [Some(500), None] {
        let cfg = ConnectionConfig {
            pmtud: None,
            ..config(1200, 1460)
        };
        let tuple = tuple();
        let (_service, prepared, _) = authority(tuple, cfg.timebase);
        let mut a = Connection::active_with_receive_path(
            tuple,
            cfg,
            100,
            0,
            &mut None,
            Some(prepared),
            crate::ReceiveIpCapability::new(ContextId::new(101), false, 1500),
            None,
        )
        .unwrap();
        let early = a
            .prepare_fast_open_without_cookie(cached, &[1; 2000], usize::MAX)
            .unwrap();
        assert!(early > 300);
        a.set_buffer_capacities(300, 65536, usize::MAX).unwrap();
        assert_eq!(a.send_space(), 300);
        let syn = segments(&mut a, 1);
        let segment = wire::parse(ip(tuple), &syn[0]).unwrap();
        assert!(segment.header.flags & SYN != 0);
        assert_eq!(segment.payload.len(), 300, "cached {cached:?}");
    }
}

// An upward PLPMTUD probe and its trailing segments must fit the fresh send
// space; a small C defers probing while ordinary data still progresses.
#[test]
fn plpmtud_probe_must_fit_fresh_send_space() {
    const Q: usize = 1460;
    for limited in [false, true] {
        let (mut a, mut b, _, _) = managed_pair_configured(true, 1_000_000, |cfg| {
            cfg.send_capacity = 30_000;
        });
        a.write(b"x").unwrap();
        deliver(&mut a, &mut b, 32);
        deliver(&mut b, &mut a, 33);
        assert_eq!(a.write(&[7; 20000]).unwrap(), 20000);
        if limited {
            a.set_buffer_capacities(3 * Q + 1, 65536, usize::MAX).unwrap();
            assert_eq!(a.send_space(), 3 * Q);
        }
        let sent = segments(&mut a, 40);
        let probe = a.pmtud.as_ref().unwrap().probe;
        if limited {
            assert!(probe.is_none());
            assert_eq!((sent.len(), a.data_flight() as usize), (3, 3 * Q));
        } else {
            assert!(probe.is_some());
        }
        input_all(&a, &mut b, &sent, 41);
        let mut received = Vec::new();
        read_all(&mut b, &mut received);
        complete(&mut a, &mut b, &mut received, 20001, 42);
        assert_eq!(received[1..], [7; 20000][..]);
    }
}

// Exact-range PTB repair resends outstanding bytes: it needs no fresh send
// space, even with the flight above the C its own decrease lowers.
#[test]
fn exact_range_repair_proceeds_without_fresh_allowance() {
    const Q: usize = 1460;
    let (mut a, mut b, _, _) = managed_pair_configured(true, 1_000_000, |cfg| {
        cfg.pmtud = Some(crate::PmtudConfig {
            initial_search_low: Some(1500),
            ..crate::PmtudConfig::new(1500)
        });
        cfg.sack = true;
        cfg.send_capacity = 6 * Q;
    });
    let first = flight_above_c(&mut a, Q, 20);
    let nxt = a.snd_nxt;
    let quoted = wire::parse(ip(a.tuple), &first[1]).unwrap();
    let len = first[1].len() as u32 + 20;
    let start = quoted.header.sequence;
    let report = crate::CorrelatedPmtu {
        segment: crate::CorrelatedSegment {
            start,
            end: start.wrapping_add(Q as u32),
            ip_packet_len: len,
            ip_header_len: 20,
        },
        quoted_packet_len: len,
        candidate_mtu: 1000,
        current_path: true,
        path_estimate: a.managed_path.unwrap().snapshot.pmtu_estimate().ok(),
    };
    let result = a.correlated_pmtu_feedback(21, report, None).unwrap();
    assert_eq!(result.feedback, crate::PmtuFeedback::Decreased { mtu: 1000 });
    assert_eq!((a.mss, a.send_space()), (960, 2880));
    assert_eq!(a.fresh_send_allowance(), 0);
    let repairs = segments(&mut a, 22);
    let ranges: Vec<_> = repairs.iter().map(|s| payload(&a, s)).collect();
    // The repair's first packet leaves at once; no new payload follows it.
    assert_eq!(ranges, [(start, 960)]);
    assert_eq!(a.snd_nxt, nxt);
    input_all(&a, &mut b, &first, 23);
    input_all(&a, &mut b, &repairs, 23);
    let mut received = Vec::new();
    read_all(&mut b, &mut received);
    complete(&mut a, &mut b, &mut received, 6 * Q, 24);
    assert_eq!(received.len(), 6 * Q);
}

// A keepalive garbage octet is not stream payload: it reuses an
// acknowledged sequence number, adds no flight, takes no send space and
// leaves the whole C to the next write.
#[test]
fn keepalive_garbage_octet_does_not_consume_send_space() {
    const Q: usize = 1460;
    let (mut a, _b, _, _) = managed_pair_configured(true, 1_000_000, |cfg| {
        no_discovery(cfg);
        cfg.send_capacity = 2 * Q + 700;
        cfg.keepalive = Some(KeepaliveConfig {
            idle_us: 100_000,
            interval_us: 100_000,
            probes: 3,
            send_garbage: true,
        });
    });
    let (space, nxt) = (a.send_space(), a.snd_nxt);
    assert_eq!(space, 2 * Q);
    let deadline = a.keepalive_deadline.unwrap();
    a.timeout(deadline).unwrap();
    assert!(a.keepalive_pending);
    let probe = segments(&mut a, deadline);
    assert_eq!(probe.len(), 1);
    assert_eq!(payload(&a, &probe[0]), (nxt.0.wrapping_sub(1), 1));
    assert_eq!((a.snd_nxt, a.data_flight(), a.send_space()), (nxt, 0, space));
    assert_eq!(a.fresh_send_allowance(), space);
    assert_eq!(a.write(&[3; 3 * Q]).unwrap(), space);
    assert_eq!(segments(&mut a, deadline + 1).len(), 2);
    assert_eq!(a.data_flight() as usize, space);
}

// A PMTU decrease while a GSO selection is reserved lowers C below the
// reserved flight: the whole selection still commits, nothing is discarded,
// and no new payload is admitted or sent while the flight stays above C.
#[test]
fn reserved_gso_selection_across_pmtu_decrease_blocks_fresh_output() {
    const Q: usize = 1460;
    let (mut a, _b, mut service, _) = managed_pair_configured(true, 1_000_000, |cfg| {
        no_discovery(cfg);
        cfg.send_capacity = 2 * Q + 700;
    });
    assert_eq!(a.write(&[5; 4 * Q]).unwrap(), 2 * Q);
    let mut bytes = vec![0; 65535];
    let mut gso = vec![0; 8 * Q];
    fn gso_buffer(payload: &mut [u8]) -> crate::output_reservation::GsoBuffer<'_> {
        crate::output_reservation::GsoBuffer {
            limits: crate::GsoLimits {
                max_bytes: payload.len(),
                max_segments: 8,
            },
            payload,
        }
    }
    assert!(a
        .transmit_selected_with_gso(10, &mut bytes, true, Some(gso_buffer(&mut gso)))
        .unwrap()
        .is_some());
    assert_eq!(a.last_departure.unwrap().payload, 2 * Q);
    let nxt = a.snd_nxt;
    // Permitted while the selection is reserved: C = 2 * 1250 < the 2Q flight.
    set_link_mtu(&mut a, &mut service, 1290);
    assert_eq!((a.mss, a.send_space()), (1250, 2500));
    test_support::commit_reserved(&mut a, 10);
    assert_eq!((a.snd_nxt, a.data_flight() as usize, a.send.len()), (nxt, 2 * Q, 2 * Q));
    assert_eq!((a.fresh_send_allowance(), a.send_admission_room(None)), (0, 0));
    assert_eq!(a.write(&[6]), Err(Error::WouldBlock));
    assert!(a.transmit_selected(11, &mut bytes, true).unwrap().is_none());
    assert!(a
        .transmit_selected_with_gso(11, &mut bytes, true, Some(gso_buffer(&mut gso)))
        .unwrap()
        .is_none());
    assert_eq!(a.snd_nxt, nxt);
}
