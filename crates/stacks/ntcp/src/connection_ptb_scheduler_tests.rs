// Exact-range PTB repair scheduling against a real peer receiver: the
// Restart allowance (one accepted repair packet until useful ACK progress),
// ordinary admission afterwards, the PTB estimator, precedence over fresh
// data and the RFC 6298 timer rules.
use super::*;
use crate::{CongestionAlgorithm, CorrelatedPmtu, CorrelatedSegment, PmtuFeedback, PmtudConfig};

// (start, end, complete IP length) of one emitted segment.
pub(super) type Span = (Seq, Seq, u32);

pub(super) fn cfg(sack: bool, algorithm: CongestionAlgorithm) -> ConnectionConfig {
    ConnectionConfig {
        pmtud: Some(PmtudConfig {
            initial_search_low: Some(1500),
            ..PmtudConfig::new(1500)
        }),
        initial_window: InitialWindow::Iw10,
        nagle: false,
        timestamps: false,
        sack,
        congestion_algorithm: algorithm,
        ..config(65_536, 1460)
    }
}

pub(super) fn header(a: &Connection) -> u16 {
    if a.tuple().local.is_ipv4() { 20 } else { 40 }
}

pub(super) fn span(a: &Connection, bytes: &[u8]) -> Span {
    let s = wire::parse(ip(a.tuple()), bytes).unwrap();
    let start = Seq(s.header.sequence);
    let len = s.payload.len() as u32 + u32::from(s.header.flags & FIN != 0);
    (
        start,
        start.wrapping_add(len),
        bytes.len() as u32 + u32::from(header(a)),
    )
}

// What a Host supplies with a correlated report: its shared estimate of the
// current path incarnation (here, the estimate every applied decrease
// lowered), and none for an older incarnation.
pub(super) fn host_estimate(a: &Connection, current: bool) -> Option<u32> {
    current.then(|| a.path_mtu_info().unwrap().current_mtu)
}

pub(super) fn report(a: &mut Connection, now: Instant, s: Span, candidate: u32) -> PmtuFeedback {
    let header = header(a);
    a.correlated_pmtu_feedback(
        now,
        CorrelatedPmtu {
            segment: CorrelatedSegment {
                start: s.0.0,
                end: s.1.0,
                ip_packet_len: s.2,
                ip_header_len: header,
            },
            quoted_packet_len: s.2,
            candidate_mtu: candidate,
            current_path: true,
            path_estimate: host_estimate(a, true),
        },
        None,
    )
    .unwrap()
    .feedback
}

pub(super) fn input(to: &mut Connection, bytes: &[u8], now: Instant) {
    let segment = wire::parse(ip(reverse(to.tuple())), bytes).unwrap();
    to.input(now, &segment).unwrap();
}

// Every packet the connection is willing to emit now, up to `limit`.
pub(super) fn poll(a: &mut Connection, now: Instant, limit: usize) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    let mut out = vec![0; 65_535];
    while packets.len() < limit {
        match a.transmit(now, &mut out).unwrap() {
            Some(n) => packets.push(out[..n].to_vec()),
            None => break,
        }
    }
    packets
}

// The real receiver's pending ACKs, delivered to the sender.
pub(super) fn drain(b: &mut Connection, a: &mut Connection, now: Instant) {
    for bytes in poll(b, now, 16) {
        input(a, &bytes, now);
    }
}

pub(super) fn payload_matches(a: &Connection, bytes: &[u8], data: &[u8]) {
    let s = wire::parse(ip(a.tuple()), bytes).unwrap();
    let offset = Seq(s.header.sequence).distance_from(a.iss.wrapping_add(1)) as usize;
    assert_eq!(s.payload, &data[offset..offset + s.payload.len()]);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
//= type=test
//= reason=Every accepted correlated report is a drop notification separate from the estimate policy (Connection::accept_pmtu_report): Host-correlated Unchanged reports about the current or an older path incarnation, Deferred and Decreased reports, and a ring-matched legacy pmtu_feedback report below the recorded submitted size whether or not the estimate falls, all add the quoted span's eligible outstanding, unSACKed, never-retransmitted bytes as exact repair work, which TCP retransmits at the currently authorized size; a Deferred report's suspicious size waits for authorization, its dropped range does not. The dual-family real-receiver scheduler test repairs the ranges of four successively smaller PTBs that, below proven delivery, leave the estimate unchanged; Host tests repair a deferred report replayed after ledger eviction and, as advice only, after path replacement; the isolated namespace tcp-burst case repairs every range named by real router PTBs, including those that left the estimate unchanged. A Host UDP flow receives the same advice as UdpEvent::PacketTooBig.
//# Also, the instance that sent the datagram that elicited the Datagram Too Big message should be notified that its datagram has been dropped, even if the PMTU estimate has not changed, so that it may retransmit the dropped datagram.
//= https://www.rfc-editor.org/rfc/rfc8201#section-5.2
//= type=test
//= reason=Every accepted correlated report is a drop notification separate from the estimate policy (Connection::accept_pmtu_report): Host-correlated Unchanged reports (at or above the IPv6 minimum and below the packet size) about the current or an older path incarnation, Deferred and Decreased reports, and a ring-matched legacy pmtu_feedback report below the recorded submitted size whether or not the estimate falls, all add the quoted span's eligible outstanding, unSACKed, never-retransmitted bytes as exact repair work, which TCP retransmits at the currently authorized size; a Deferred report's suspicious size waits for authorization, its dropped data does not. The dual-family real-receiver scheduler test repairs the ranges of four successively smaller PTBs that, below proven delivery, leave the estimate unchanged; Host tests repair a deferred report replayed after ledger eviction and, as advice only, after path replacement; the isolated namespace tcp-burst case repairs every range named by real router PTBs, including those that left the estimate unchanged. A Host UDP flow receives the same advice as UdpEvent::PacketTooBig.
//# Also, the instance that sent the packet that elicited the Packet Too Big message should be notified that its packet has been dropped, even if the PMTU estimate has not changed, so that it may retransmit the dropped data.
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.4
//= type=test
//= reason=A PTB never causes a retransmission by itself: it only adds eligible bytes to the connection's pending repair set, which duplicate, repair-copy, path-incarnation and size variants and reports about a flight an RTO took over never enlarge, and each pending byte is repaired at most once. A notification that adds new work enters Restart, which admits one accepted physical repair packet until useful ACK progress (a cumulative advance or newly SACKed bytes; DSACK-only, duplicate and window-only ACKs do not count); remaining work then follows ordinary congestion admission. The dual-family real-receiver scheduler test sends four successively decreasing PTBs, one per oversized original, across many output polls without an ACK and observes exactly one repair packet, then every remaining byte resent exactly once without a timeout; Host reservation tests keep one physical packet when a racing decrease splits the repair; the isolated namespace tcp-burst case shows one repair packet, within a quoted range, before the first useful ACK for three real router PTBs, and no range resent twice between ACK progress.
//# Note: One MUST not retransmit in response to every Datagram Too Big message, since a burst of several oversized segments will give rise to several such messages and hence several retransmissions of the same data. If the new estimated PMTU is still wrong, the process repeats, and there is an exponential growth in the number of superfluous segments sent!
fn successive_ptbs_admit_one_repair_until_useful_ack_then_ordinary_admission() {
    for ipv4 in [true, false] {
        for iss in [0, u32::MAX - 3000] {
            for sack in [true, false] {
                for algorithm in [CongestionAlgorithm::Reno, CongestionAlgorithm::Cubic] {
                    one_restart_then_ordinary(ipv4, iss, sack, algorithm);
                }
            }
        }
    }
}

fn one_restart_then_ordinary(ipv4: bool, iss: u32, sack: bool, algorithm: CongestionAlgorithm) {
    let (mut a, mut b) = super::pmtud_policy::family_pair(cfg(sack, algorithm), ipv4, iss);
    let data: Vec<u8> = (0..8 * a.mss).map(|i| (i * 7 + 3) as u8).collect();
    // Only the six-segment original flight is queued at first.
    a.write(&data[..6 * a.mss]).unwrap();
    let sent: Vec<(Span, Vec<u8>)> = (0..6)
        .map(|_| {
            let bytes = packet(&mut a, 40);
            (span(&a, &bytes), bytes)
        })
        .collect();
    let high = sent[5].0.1;
    // The first and last originals arrive; the middle four were too big for
    // a smaller link, which reports each of them.
    input(&mut b, &sent[0].1, 41);
    input(&mut b, &sent[5].1, 41);
    drain(&mut b, &mut a, 42);
    assert_eq!(a.snd_una, sent[0].0.1);
    let (cwnd, ssthresh, mss) = (a.congestion.cwnd(), a.congestion.ssthresh(), a.mss);
    let segments = cwnd / mss as u32;
    // Successive decreasing PTBs (one per oversized original), interleaved
    // with many output opportunities and no ACK: exactly one repair packet.
    let mut repairs = Vec::new();
    for (k, candidate) in [(1, 1400), (2, 1350), (3, 1300), (4, 1280)] {
        let now = 42 + k as u64;
        let before = a.rto_deadline;
        assert_ne!(
            report(&mut a, now, sent[k].0, candidate),
            PmtuFeedback::Rejected
        );
        // PTB receipt alone never restarts the RTO.
        assert_eq!(a.rto_deadline, before);
        for bytes in poll(&mut a, now, 8) {
            // Anything else is fresh data beyond the original flight.
            if !span(&a, &bytes).0.at_or_after(high) {
                repairs.push(bytes);
            }
        }
    }
    assert_eq!(repairs.len(), 1);
    let first = span(&a, &repairs[0]);
    // The quoted non-head range, at the reduced size, from its first byte.
    assert_eq!(first.0, sent[1].0.0);
    // Emitted at the first output opportunity. s0's acknowledged 1500-octet
    // delivery makes every smaller report Deferred: the dropped range is
    // repaired at the currently authorized size.
    assert_eq!(first.2, 1500);
    assert_eq!(first.1, first.0.wrapping_add(a.mss as u32));
    payload_matches(&a, &repairs[0], &data);
    // The repair began at SND.UNA (s0 was acknowledged): RFC 6298 restarts
    // the timer from that transmission, and later PTBs leave it alone.
    assert_eq!(a.rto_deadline, Some(43 + a.rto()));
    // No congestion response: only the RFC 5681 MSS rescaling of cwnd.
    assert_eq!(a.congestion.cwnd(), segments * a.mss as u32);
    assert_eq!(a.congestion.ssthresh(), ssthresh);
    assert!(!a.congestion.in_recovery());
    assert!(a.sack_recovery.is_none() && a.prr.is_none());
    assert_eq!(a.consecutive_timeouts, 0);
    // PTB estimator: FlightSize minus only the pending dropped originals; the
    // committed replacement counts again.
    let pending = a.ptb.pending as u32;
    assert_eq!(pending, sent[4].0.1.distance_from(first.1));
    assert_eq!(a.ptb_estimate(), a.flight() - pending);
    // A duplicate original yields a duplicate (DSACK) ACK from the receiver:
    // no new delivery, so no further repair.
    input(&mut b, &sent[5].1, 50);
    drain(&mut b, &mut a, 50);
    assert!(
        poll(&mut a, 50, 8)
            .iter()
            .all(|p| span(&a, p).0.at_or_after(high))
    );
    assert_eq!(a.ptb.pending as u32, pending);
    // Useful progress: the receiver acknowledges the repair. Remaining work is
    // admitted by ordinary congestion admission ahead of fresh data, each
    // byte retransmitted exactly once, until all data is delivered without
    // any timeout.
    // Fresh data queued now competes with the remaining PTB work.
    a.write(&data[6 * a.mss..]).unwrap();
    input(&mut b, &repairs[0], 60);
    drain(&mut b, &mut a, 60);
    let mut covered = first.1;
    let mut now = 61;
    while a.snd_una != a.snd_nxt || a.send.len() > a.snd_nxt.distance_from(a.send_base) as usize {
        assert!(now < 200, "repair must not wait for a timeout");
        assert!(a.consecutive_timeouts == 0);
        let estimate = a.ptb_estimate();
        let pending_before = !a.ptb_idle();
        let burst = poll(&mut a, now, 32);
        let mut bytes_sent = 0;
        let mut fresh_seen = false;
        for bytes in &burst {
            let s = span(&a, bytes);
            if s.0.at_or_after(high) {
                fresh_seen = true;
            } else {
                // Repairs precede fresh data and never repeat a byte.
                assert!(!fresh_seen);
                assert_eq!(s.0, covered);
                covered = s.1;
                bytes_sent += s.1.distance_from(s.0);
                payload_matches(&a, bytes, &data);
            }
            input(&mut b, bytes, now);
        }
        if pending_before && a.consecutive_timeouts == 0 && !a.congestion.in_recovery() {
            // Ordinary admission: cwnd against the PTB estimator.
            assert!(bytes_sent <= a.congestion.cwnd().saturating_sub(estimate));
        }
        drain(&mut b, &mut a, now);
        now += 1;
    }
    assert_eq!(covered, sent[4].0.1);
    let mut received = vec![0; data.len()];
    let n = b.read(&mut received).unwrap();
    assert_eq!(&received[..n], &data[..n]);
    assert_eq!(n, data.len());
}

#[test]
fn non_head_then_head_repair_timers_and_rto_takeover() {
    for ipv4 in [true, false] {
        for iss in [0, u32::MAX - 3000] {
            let (mut a, mut b) =
                super::pmtud_policy::family_pair(cfg(true, CongestionAlgorithm::Reno), ipv4, iss);
            let data: Vec<u8> = (0..3 * 1460).map(|i| i as u8).collect();
            a.write(&data).unwrap();
            let sent: Vec<Span> = (0..3)
                .map(|_| {
                    let bytes = packet(&mut a, 40);
                    span(&a, &bytes)
                })
                .collect();
            let high = sent[2].1;
            let deadline = a.rto_deadline;
            // All three were dropped; only the middle one is reported first.
            assert_ne!(report(&mut a, 45, sent[1], 1280), PmtuFeedback::Rejected);
            // No head retry from the decrease: repair is exact PTB work.
            assert!(!a.retx_pending);
            // Trailing unsent bytes may follow as fresh data.
            let repairs: Vec<Vec<u8>> = poll(&mut a, 46, 8)
                .into_iter()
                .filter(|p| !span(&a, p).0.at_or_after(high))
                .collect();
            assert_eq!(repairs.len(), 1);
            let r = span(&a, &repairs[0]);
            assert_eq!(r.0, sent[1].0);
            payload_matches(&a, &repairs[0], &data);
            // A non-head repair cannot postpone the older head's deadline.
            assert_eq!(a.rto_deadline, deadline);
            // Reports of the head and tail during Restart grant nothing more.
            assert_ne!(report(&mut a, 47, sent[0], 1280), PmtuFeedback::Rejected);
            assert_ne!(report(&mut a, 47, sent[2], 1280), PmtuFeedback::Rejected);
            assert!(
                poll(&mut a, 47, 8)
                    .iter()
                    .all(|p| span(&a, p).0.at_or_after(high))
            );
            // The receiver SACKs the repair: newly SACKed bytes are useful
            // progress, and ordinary admission repairs the head first.
            input(&mut b, &repairs[0], 48);
            drain(&mut b, &mut a, 48);
            assert_eq!(a.snd_una, sent[0].0);
            let next = poll(&mut a, 49, 1);
            let h = span(&a, &next[0]);
            assert_eq!(h.0, sent[0].0);
            assert!(h.1.distance_from(h.0) as usize == a.mss);
            payload_matches(&a, &next[0], &data);
            // RFC 6298: the committed head repair restarts the timer so no
            // timer-driven retransmission follows it within one RTO.
            assert_eq!(a.rto_deadline, Some(49 + a.rto()));
            // RTO with work still pending: ordinary timeout recovery takes the
            // whole flight; pending PTB work is discarded, and a report about
            // that old flight adds none.
            assert!(!a.ptb_idle());
            rto(&mut a);
            assert!(a.ptb_idle());
            assert!(
                !a.send
                    .retransmitted(high.distance_from(a.send_base) as usize - 1)
            );
            let now = a.now;
            assert_ne!(report(&mut a, now, sent[2], 1280), PmtuFeedback::Rejected);
            assert!(a.ptb_idle());
        }
    }
}

pub(super) fn rto(a: &mut Connection) {
    while a.consecutive_timeouts == 0 {
        let (_, deadline) = a.loss_timer.unwrap();
        a.timeout(deadline).unwrap();
    }
}

#[test]
fn failed_encode_leaves_work_pending_and_allowance_unconsumed() {
    for ipv4 in [true, false] {
        let (mut a, _b) =
            super::pmtud_policy::family_pair(cfg(true, CongestionAlgorithm::Reno), ipv4, 0);
        a.write(&[5; 3 * 1460]).unwrap();
        let sent: Vec<Span> = (0..3)
            .map(|_| {
                let bytes = packet(&mut a, 40);
                span(&a, &bytes)
            })
            .collect();
        let deadline = a.rto_deadline;
        assert_ne!(report(&mut a, 45, sent[1], 1280), PmtuFeedback::Rejected);
        let pending = a.ptb.pending;
        // Too small an output buffer: nothing is committed.
        let mut small = [0; 40];
        assert_eq!(a.transmit(46, &mut small), Err(Error::OutputTooSmall));
        assert_eq!(a.ptb.pending, pending);
        assert_eq!(a.rto_deadline, deadline);
        assert!(
            !a.send
                .retransmitted(sent[1].0.distance_from(a.send_base) as usize)
        );
        // The allowance is still available: the next poll repairs once.
        let high = sent[2].1;
        let repairs: Vec<Vec<u8>> = poll(&mut a, 47, 8)
            .into_iter()
            .chain(poll(&mut a, 48, 8))
            .filter(|p| !span(&a, p).0.at_or_after(high))
            .collect();
        assert_eq!(repairs.len(), 1);
        assert_eq!(span(&a, &repairs[0]).0, sent[1].0);
    }
}

#[test]
fn restart_segment_is_the_slow_start_allowance_even_with_cwnd_full() {
    for ipv4 in [true, false] {
        for algorithm in [CongestionAlgorithm::Reno, CongestionAlgorithm::Cubic] {
            let (mut a, _b) = super::pmtud_policy::family_pair(cfg(true, algorithm), ipv4, 7);
            let data: Vec<u8> = (0..10 * a.mss).map(|i| (i * 3) as u8).collect();
            a.write(&data).unwrap();
            let sent: Vec<Span> = (0..10)
                .map(|_| {
                    let bytes = packet(&mut a, 40);
                    span(&a, &bytes)
                })
                .collect();
            assert_eq!(a.flight(), a.congestion.cwnd());
            // Only the last packet was too big; the other nine still fill the
            // rescaled cwnd under the PTB estimator.
            assert!(matches!(
                report(&mut a, 45, sent[9], 1280),
                PmtuFeedback::Decreased { mtu: 1280 }
            ));
            assert!(a.ptb_estimate() >= a.congestion.cwnd());
            let repairs = poll(&mut a, 46, 8);
            assert_eq!(repairs.len(), 1);
            let r = span(&a, &repairs[0]);
            assert_eq!(r.0, sent[9].0);
            assert!(r.2 <= 1280);
            payload_matches(&a, &repairs[0], &data);
            // After the Restart packet, ordinary admission waits for ACKs.
            assert!(!a.ptb_idle());
            assert!(poll(&mut a, 47, 8).is_empty());
        }
    }
}

// Grow cwnd with fully delivered flights until it holds `segments` MSS.
pub(super) fn warm(a: &mut Connection, b: &mut Connection, segments: u32, now: &mut Instant) {
    while a.congestion.cwnd() < segments * a.mss as u32 || a.send.len() != 0 {
        if a.send.len() == 0 {
            a.write(&vec![1; a.congestion.cwnd() as usize]).unwrap();
        }
        for bytes in poll(a, *now, 64) {
            input(b, &bytes, *now);
        }
        drain(b, a, *now);
        let mut sink = vec![0; 65_536];
        while b.read(&mut sink).is_ok_and(|n| n != 0) {}
        *now += 1;
    }
    assert_eq!(a.snd_una, a.snd_nxt);
}

pub(super) fn offset(a: &Connection, seq: Seq) -> usize {
    seq.distance_from(a.send_base) as usize
}

#[test]
fn rfc6675_ptb_copy_above_high_rxt_counts_once_and_is_never_resent() {
    for ipv4 in [true, false] {
        for algorithm in [CongestionAlgorithm::Reno, CongestionAlgorithm::Cubic] {
            for rto_release in [false, true] {
                rfc6675_ptb_copy(ipv4, algorithm, rto_release);
            }
        }
    }
}

fn rfc6675_ptb_copy(ipv4: bool, algorithm: CongestionAlgorithm, rto_release: bool) {
    let cfg = ConnectionConfig {
        delayed_ack_us: 0,
        ..cfg(true, algorithm)
    };
    let (mut a, mut b) = super::pmtud_policy::family_pair(cfg, ipv4, 11);
    let mut now = 40;
    warm(&mut a, &mut b, 30, &mut now);
    let n = (a.congestion.cwnd() / a.mss as u32) as usize;
    a.write(&vec![9; n * a.mss]).unwrap();
    let sent: Vec<(Span, Vec<u8>)> = poll(&mut a, now, 64)
        .into_iter()
        .map(|bytes| (span(&a, &bytes), bytes))
        .collect();
    // The peer's receive window may bound the flight below cwnd.
    let n = sent.len();
    assert!(n >= 16);
    // s1 and s2 are lost, s6 is dropped by a smaller link; s0 and s3..s5
    // arrive, s7.. are still in flight.
    for k in [0, 3, 4, 5] {
        input(&mut b, &sent[k].1, now + 1);
    }
    drain(&mut b, &mut a, now + 1);
    let recovery = a.sack_recovery.expect("RFC 6675 recovery");
    assert!(!a.rack_enabled() && a.prr.is_none());
    assert!(recovery.entry_pending);
    // Entry retransmission of s1; the still-counted flight leaves no credit
    // for NextSeg.
    let entry = poll(&mut a, now + 2, 8);
    assert_eq!(entry.len(), 1);
    assert_eq!(span(&a, &entry[0]).0, sent[1].0.0);
    let high_rxt = a.sack_recovery.unwrap().high_rxt;
    assert_eq!(high_rxt, sent[1].0.1);
    // The PTB names s6: one Restart repair, above HighRxt and not
    // contiguous with it (s2 is an unretransmitted hole between).
    assert_ne!(
        report(&mut a, now + 3, sent[6].0, 1280),
        PmtuFeedback::Rejected
    );
    let repairs = poll(&mut a, now + 3, 8);
    assert_eq!(repairs.len(), 1);
    let r = span(&a, &repairs[0]);
    assert_eq!(r.0, sent[6].0.0);
    let copy = r.1.distance_from(r.0);
    assert_eq!(a.sack_recovery.unwrap().high_rxt, high_rxt);
    assert_eq!(a.ptb.copies, copy as usize);
    assert!(a.send.ptb_copy(offset(&a, r.0)));
    if rto_release {
        rto(&mut a);
        assert_eq!(a.ptb.copies, 0);
        assert!(!a.send.ptb_copy(offset(&a, r.0)));
        return;
    }
    // A SACK for s7 recomputes pipe at ACK time: SetPipe does not see the copy
    // above HighRxt, so it is added exactly once.
    input(&mut b, &sent[7].1, now + 4);
    drain(&mut b, &mut a, now + 4);
    let recovery = a.sack_recovery.unwrap();
    let setpipe = a
        .scoreboard
        .pipe(a.snd_una, a.data_high(), recovery.high_rxt, a.mss as u32);
    assert_eq!(recovery.pipe, setpipe + copy);
    // The rest of the flight is SACKed: s6 is now IsLost and credit opens,
    // yet NextSeg repairs only s2 and never the bytes whose copy is in flight.
    for k in 8..n {
        input(&mut b, &sent[k].1, now + 5);
    }
    drain(&mut b, &mut a, now + 5);
    assert!(a.scoreboard.is_lost(r.0, a.mss as u32));
    let recovery = a.sack_recovery.unwrap();
    assert_eq!(
        recovery.pipe,
        a.scoreboard
            .pipe(a.snd_una, a.data_high(), recovery.high_rxt, a.mss as u32)
            + copy
    );
    let mut retransmitted = Vec::new();
    for t in 6..12 {
        for bytes in poll(&mut a, now + t, 8) {
            let s = span(&a, &bytes);
            assert!(
                !s.1.after(r.0) || !r.1.after(s.0),
                "{s:?} repeats the outstanding PTB copy {r:?}"
            );
            retransmitted.push(s.0);
        }
    }
    assert!(retransmitted.contains(&sent[2].0.0));
    assert_eq!(a.ptb.copies, copy as usize);
    // Delivery of the copy (a SACK) releases it.
    input(&mut b, &repairs[0], now + 12);
    drain(&mut b, &mut a, now + 12);
    assert_eq!(a.ptb.copies, 0);
    assert!(!a.send.ptb_copy(offset(&a, r.0)));
}

// NextSeg skips an outstanding PTB copy and repairs a lost hole above it:
// HighRxt then passes the copy, SetPipe's retransmission term counts it, and
// it is no longer added separately, so pipe counts that replacement once.
#[test]
fn rfc6675_high_rxt_passing_a_ptb_copy_counts_it_once() {
    for ipv4 in [true, false] {
        for algorithm in [CongestionAlgorithm::Reno, CongestionAlgorithm::Cubic] {
            high_rxt_passes_ptb_copy(ipv4, algorithm);
        }
    }
}

fn high_rxt_passes_ptb_copy(ipv4: bool, algorithm: CongestionAlgorithm) {
    let cfg = ConnectionConfig {
        delayed_ack_us: 0,
        ..cfg(true, algorithm)
    };
    let (mut a, mut b) = super::pmtud_policy::family_pair(cfg, ipv4, 11);
    let mut now = 40;
    warm(&mut a, &mut b, 30, &mut now);
    let n = (a.congestion.cwnd() / a.mss as u32) as usize;
    a.write(&vec![9; n * a.mss]).unwrap();
    let sent: Vec<(Span, Vec<u8>)> = poll(&mut a, now, 64)
        .into_iter()
        .map(|bytes| (span(&a, &bytes), bytes))
        .collect();
    let n = sent.len();
    assert!(n >= 16);
    // s1, s2 and s7 are lost, s6 is dropped by a smaller link; s0 and
    // s3..s5 arrive.
    for k in [0, 3, 4, 5] {
        input(&mut b, &sent[k].1, now + 1);
    }
    drain(&mut b, &mut a, now + 1);
    assert!(a.sack_recovery.is_some() && !a.rack_enabled() && a.prr.is_none());
    let entry = poll(&mut a, now + 2, 8);
    assert_eq!(entry.len(), 1);
    assert_eq!(span(&a, &entry[0]).0, sent[1].0.0);
    // Below proven delivery the size waits, the whole of s6 is one repair.
    assert_eq!(
        report(&mut a, now + 3, sent[6].0, 1280),
        PmtuFeedback::Deferred
    );
    let repairs = poll(&mut a, now + 3, 8);
    assert_eq!(repairs.len(), 1);
    let r = span(&a, &repairs[0]);
    assert_eq!((r.0, r.1), (sent[6].0.0, sent[6].0.1));
    let copy = r.1.distance_from(r.0) as usize;
    assert_eq!(a.ptb.copies, copy);
    // s8.. are SACKed: s2, s6 and s7 are IsLost. NextSeg repairs s2, skips
    // the outstanding s6 copy and repairs s7, moving HighRxt past the copy.
    for (_, bytes) in &sent[8..] {
        input(&mut b, bytes, now + 4);
    }
    drain(&mut b, &mut a, now + 4);
    let mut s2 = None;
    for t in 5..12 {
        for bytes in poll(&mut a, now + t, 8) {
            let s = span(&a, &bytes);
            assert!(
                !s.1.after(r.0) || !r.1.after(s.0),
                "{s:?} repeats the outstanding PTB copy {r:?}"
            );
            if s.0 == sent[2].0.0 {
                s2 = Some(bytes);
            }
        }
        if a.sack_recovery.unwrap().high_rxt.after(r.1) {
            break;
        }
    }
    let recovery = a.sack_recovery.unwrap();
    assert_eq!(recovery.high_rxt, sent[7].0.1);
    assert_eq!(a.ptb.copies, 0);
    assert!(!a.send.ptb_copy(offset(&a, r.0)));
    assert_eq!(
        recovery.pipe,
        a.scoreboard
            .pipe(a.snd_una, a.data_high(), recovery.high_rxt, a.mss as u32)
    );
    // Delivering the s1 and s2 repairs advances SND.UNA to the copy and
    // recomputes pipe at ACK time: SetPipe alone counts the copy below HighRxt.
    input(&mut b, &entry[0], now + 12);
    input(&mut b, &s2.expect("s2 repaired"), now + 12);
    drain(&mut b, &mut a, now + 12);
    assert_eq!(a.snd_una, r.0);
    let recovery = a.sack_recovery.expect("still in recovery");
    let setpipe = a
        .scoreboard
        .pipe(a.snd_una, a.data_high(), recovery.high_rxt, a.mss as u32);
    assert_eq!(recovery.pipe, setpipe);
    assert_eq!(a.recovery_pipe(recovery.high_rxt), setpipe);
    // The copy, the s7 repair and any fresh data are each counted once.
    let fresh = a.data_high().distance_from(sent[n - 1].0.1);
    assert_eq!(
        setpipe,
        copy as u32 + sent[7].0.1.distance_from(sent[7].0.0) + fresh
    );
}

pub(super) fn report_on(
    a: &mut Connection,
    now: Instant,
    s: Span,
    candidate: u32,
    current: bool,
) -> PmtuFeedback {
    let header = header(a);
    a.correlated_pmtu_feedback(
        now,
        CorrelatedPmtu {
            segment: CorrelatedSegment {
                start: s.0.0,
                end: s.1.0,
                ip_packet_len: s.2,
                ip_header_len: header,
            },
            quoted_packet_len: s.2,
            candidate_mtu: candidate,
            current_path: current,
            path_estimate: host_estimate(a, current),
        },
        None,
    )
    .unwrap()
    .feedback
}

// Probe attribution and exact repair are independent of the accepted class:
// a PTB quoting the original upward probe invalidates its size result and the
// probe's dropped range is repaired once, at the currently authorized size,
// before useful ACK progress.
#[test]
fn probe_attribution_with_repair_in_every_accepted_class() {
    for ipv4 in [true, false] {
        // 0 Unchanged, 1 Deferred, 2 Decreased, 3 older incarnation.
        for class in 0..4 {
            probe_attribution_with_repair(ipv4, class);
        }
    }
}

fn probe_attribution_with_repair(ipv4: bool, class: u8) {
    let low: u32 = if ipv4 { 1200 } else { 1400 };
    let mut cfg = ConnectionConfig {
        delayed_ack_us: 0,
        ..cfg(true, CongestionAlgorithm::Reno)
    };
    cfg.pmtud = Some(PmtudConfig {
        initial_mtu: Some(low),
        initial_search_low: Some(low),
        ..PmtudConfig::new(1500)
    });
    let (mut a, mut b) = super::pmtud_policy::family_pair(cfg, ipv4, 21);
    let ip_header = u32::from(header(&a));
    let mut now = 40;
    if class == 1 {
        // One full packet at the current size is delivered first: proven
        // delivery makes a smaller report Deferred.
        a.write(&vec![3; (low - ip_header - 20) as usize]).unwrap();
        let bytes = packet(&mut a, now);
        assert_eq!(bytes.len() as u32 + ip_header, low);
        assert!(a.pmtud.as_ref().unwrap().probe.is_none());
        input(&mut b, &bytes, now);
        drain(&mut b, &mut a, now);
        now += 1;
    } else {
        a.write(b"x").unwrap();
        let bytes = packet(&mut a, now);
        input(&mut b, &bytes, now);
        drain(&mut b, &mut a, now);
        now += 1;
    }
    let data: Vec<u8> = (0..20_000).map(|i| (i * 13) as u8).collect();
    a.write(&data).unwrap();
    let first = packet(&mut a, now);
    let probe = a.pmtud.as_ref().unwrap().probe.expect("original probe");
    let p = span(&a, &first);
    assert_eq!(p.2, probe.size);
    assert!(probe.size > low);
    let mut trailing = Vec::new();
    while let Some(bytes) = poll(&mut a, now, 1).pop() {
        trailing.push(span(&a, &bytes));
    }
    assert!(!trailing.is_empty());
    assert!(a.pmtud.as_ref().unwrap().provable_probe().is_some());
    let (candidate, current, expected) = match class {
        0 => (low + 20, true, PmtuFeedback::Unchanged),
        1 => (low - 100, true, PmtuFeedback::Deferred),
        2 => (low - 100, true, PmtuFeedback::Decreased { mtu: low - 100 }),
        _ => (low - 100, false, PmtuFeedback::Unchanged),
    };
    let (cwnd, ssthresh, mss) = (a.congestion.cwnd(), a.congestion.ssthresh(), a.mss);
    assert_eq!(
        report_on(&mut a, now + 1, p, candidate, current),
        expected,
        "{ipv4} {class} {p:?} {:?}",
        a.path_mtu_info()
    );
    // Attribution: the size result is invalid in every class.
    assert!(a.pmtud.as_ref().unwrap().provable_probe().is_none());
    assert_eq!(a.ptb.pending as u32, p.1.distance_from(p.0));
    // Exact repair: one packet from the probe's first byte, no larger than
    // the size authorized now, and nothing else before ACK progress.
    let mut repairs = Vec::new();
    for t in 0..4 {
        for bytes in poll(&mut a, now + 1 + t, 8) {
            repairs.push(span(&a, &bytes));
        }
    }
    assert_eq!(repairs.len(), 1, "{repairs:?}");
    let r = repairs[0];
    assert_eq!(r.0, p.0);
    let authorized = a.path_mtu_info().unwrap().current_mtu;
    assert!(r.2 <= authorized);
    assert_eq!(authorized, if class == 2 { low - 100 } else { low });
    // No congestion response (only Decreased rescales by the MSS).
    if a.mss == mss {
        assert_eq!(
            (a.congestion.cwnd(), a.congestion.ssthresh()),
            (cwnd, ssthresh)
        );
    } else {
        assert_eq!(class, 2);
    }
    assert!(!a.congestion.in_recovery() && a.sack_recovery.is_none());
}

// A loss probe never bypasses PTB admission: an expiring PTO sends nothing
// while PTB work is pending (the control without PTB work probes at the same
// point), and loss probing resumes once the work has drained.
#[test]
fn tlp_is_suppressed_while_ptb_work_is_pending_and_resumes_after_it_drains() {
    for ipv4 in [true, false] {
        for ptb in [true, false] {
            tlp_with_ptb_work(ipv4, ptb);
        }
    }
}

fn tlp_with_ptb_work(ipv4: bool, ptb: bool) {
    let cfg = ConnectionConfig {
        rack: true,
        tlp: true,
        delayed_ack_us: 0,
        ..cfg(true, CongestionAlgorithm::Reno)
    };
    let (mut a, mut b) = super::pmtud_policy::family_pair(cfg, ipv4, 31);
    let mut now = 40;
    warm(&mut a, &mut b, 12, &mut now);
    a.write(&vec![4; 4 * a.mss]).unwrap();
    let sent: Vec<(Span, Vec<u8>)> = poll(&mut a, now, 8)
        .into_iter()
        .map(|bytes| (span(&a, &bytes), bytes))
        .collect();
    assert_eq!(sent.len(), 4);
    let pto = a.tlp_deadline.expect("new data arms the PTO");
    if ptb {
        // s1 and s2 were too big: one Restart repair, s2 stays pending.
        assert_ne!(report(&mut a, now, sent[1].0, 1280), PmtuFeedback::Rejected);
        assert_ne!(report(&mut a, now, sent[2].0, 1280), PmtuFeedback::Rejected);
        let repairs = poll(&mut a, now, 8);
        assert_eq!(repairs.len(), 1);
        assert_eq!(span(&a, &repairs[0]).0, sent[1].0.0);
        assert!(!a.ptb_idle());
        // The PTO is disarmed while PTB work is pending.
        assert!(a.tlp_deadline.is_none());
        assert_ne!(a.loss_timer.unwrap().0, LossTimer::Pto);
    } else {
        assert_eq!(a.loss_timer, Some((LossTimer::Pto, pto)));
    }
    a.timeout(pto).unwrap();
    if !ptb {
        // Control: the same expiry sends a loss probe.
        assert!(a.tlp_pending);
        assert_eq!(poll(&mut a, pto, 8).len(), 1);
        assert!(a.tlp_end.is_some());
        return;
    }
    assert!(!a.tlp_pending);
    assert!(poll(&mut a, pto, 8).is_empty());
    assert!(a.tlp_end.is_none());
    let deadline = pto;
    // Deliver everything the sender emits (s1 and s3 originals stay lost
    // but are repaired by PTB or ordinary recovery) until the flight drains;
    // no loss probe is sent while PTB work remains.
    now = deadline;
    for k in [0, 3] {
        input(&mut b, &sent[k].1, now);
    }
    drain(&mut b, &mut a, now);
    let mut out = Vec::new();
    while a.snd_una != a.snd_nxt {
        assert!(now < deadline + 10 * a.rto(), "flight must drain");
        if !a.ptb_idle() {
            assert!(a.tlp_deadline.is_none() && !a.tlp_pending);
        }
        out.clear();
        out.extend(poll(&mut a, now, 8));
        for bytes in &out {
            input(&mut b, bytes, now);
        }
        drain(&mut b, &mut a, now);
        if out.is_empty() {
            now = a.next_deadline().unwrap().max(now + 1);
            a.timeout(now).unwrap();
        }
    }
    assert!(a.ptb_idle());
    assert_eq!(a.ptb.copies, 0);
    // Loss probing resumes: new data arms the PTO, whose expiry probes.
    a.write(&vec![6; 2 * a.mss]).unwrap();
    assert_eq!(poll(&mut a, now, 8).len(), 2);
    let (timer, deadline) = a.loss_timer.unwrap();
    assert_eq!(timer, LossTimer::Pto);
    a.timeout(deadline).unwrap();
    assert!(a.tlp_pending);
    assert_eq!(poll(&mut a, deadline, 8).len(), 1);
    assert!(a.tlp_end.is_some());
}

pub(super) fn payload_len(a: &Connection, bytes: &[u8]) -> u32 {
    wire::parse(ip(a.tuple()), bytes).unwrap().payload.len() as u32
}

// PTB work during SACK recovery (RFC 6675 SetPipe or RACK's estimator, with
// and without PRR): the PTB estimator subtracts only the original-copy
// contribution the selected estimator still counts, ordinary recovery keeps
// precedence, PRR's prr_out grows by exactly the bytes emitted (each repair
// consumes its actual bytes once), and no byte is sent twice before delivery.
#[test]
fn ptb_work_coexists_with_sack_rack_recovery_and_prr() {
    for ipv4 in [true, false] {
        for rack in [false, true] {
            for prr in [false, true] {
                for algorithm in [CongestionAlgorithm::Reno, CongestionAlgorithm::Cubic] {
                    sack_recovery_coexistence(ipv4, rack, prr, algorithm);
                }
            }
        }
    }
}

fn sack_recovery_coexistence(ipv4: bool, rack: bool, prr: bool, algorithm: CongestionAlgorithm) {
    let cfg = ConnectionConfig {
        rack,
        prr,
        delayed_ack_us: 0,
        ..cfg(true, algorithm)
    };
    let (mut a, mut b) = super::pmtud_policy::family_pair(cfg, ipv4, u32::MAX - 9000);
    let mut now = 40;
    warm(&mut a, &mut b, 30, &mut now);
    let data_start = a.snd_nxt;
    a.write(&vec![8; 40 * a.mss]).unwrap();
    let sent: Vec<(Span, Vec<u8>)> = poll(&mut a, now, 64)
        .into_iter()
        .map(|bytes| (span(&a, &bytes), bytes))
        .collect();
    let n = sent.len();
    assert!(n >= 16);
    let high = sent[n - 1].0.1;
    for k in [0, 3, 4, 5] {
        input(&mut b, &sent[k].1, now + 1);
    }
    drain(&mut b, &mut a, now + 1);
    now += 1;
    if a.sack_recovery.is_none() {
        // RACK marks s1/s2 lost after its reordering window.
        now = a.rack.deadline.expect("RACK reordering timer");
        a.timeout(now).unwrap();
    }
    let recovery = a.sack_recovery.expect("SACK recovery");
    assert_eq!(a.rack_enabled(), rack);
    assert_eq!(a.prr.is_some(), prr);
    let (cwnd, ssthresh) = (a.congestion.cwnd(), a.congestion.ssthresh());
    // s6 was too big. Its original is still counted by either estimator (no
    // later byte is SACKed), so the PTB estimator subtracts exactly s6.
    let s6 = sent[6].0;
    let len6 = s6.1.distance_from(s6.0);
    assert_ne!(report(&mut a, now, s6, 1280), PmtuFeedback::Rejected);
    assert_eq!(a.ptb.pending as u32, len6);
    let estimator = if rack { a.rack.pipe() } else { recovery.pipe };
    assert_eq!(a.sack_recovery.unwrap().pipe, estimator);
    assert_eq!(a.ptb_estimate(), estimator - len6);
    // PTB receipt is no congestion signal.
    assert_eq!(
        (a.congestion.cwnd(), a.congestion.ssthresh()),
        (cwnd, ssthresh)
    );
    let mut covered: Vec<(Seq, Seq)> = Vec::new();
    let mut ptb_repairs = 0;
    let mut acked = 7;
    let mut t = now;
    while !a.ptb_idle() || a.ptb.copies != 0 || a.sack_recovery.is_some() {
        assert!(t < now + 100, "recovery must finish without a timeout");
        assert_eq!(a.consecutive_timeouts, 0);
        let out_before = a.prr.map(|p| p.counters().2);
        let burst = poll(&mut a, t, 32);
        let mut bytes_out = 0;
        for bytes in &burst {
            let s = span(&a, bytes);
            bytes_out += payload_len(&a, bytes) as u64;
            if s.0.after(high) || s.0 == high {
                continue;
            }
            // No byte is retransmitted twice: every first copy repairs a
            // distinct range.
            for &(l, r) in &covered {
                assert!(!s.1.after(l) || !r.after(s.0), "{s:?} repeats {l:?}..{r:?}");
            }
            covered.push((s.0, s.1));
            if s.0 == s6.0 {
                ptb_repairs += 1;
            }
        }
        if let (Some(before), Some(p)) = (out_before, a.prr) {
            // prr_out counts each emitted byte exactly once.
            assert_eq!(p.counters().2 - before, bytes_out);
        }
        // The receiver gets every repair; the held originals arrive in order.
        for bytes in &burst {
            input(&mut b, bytes, t);
        }
        if acked < n {
            input(&mut b, &sent[acked].1, t);
            acked += 1;
        }
        drain(&mut b, &mut a, t);
        t += 1;
    }
    assert_eq!(ptb_repairs, 1);
    assert!(covered.iter().any(|&(l, _)| l == sent[1].0.0));
    assert!(covered.iter().any(|&(l, _)| l == sent[2].0.0));
    // Everything arrives without a timeout.
    while acked < n {
        input(&mut b, &sent[acked].1, t);
        acked += 1;
    }
    drain(&mut b, &mut a, t);
    for bytes in poll(&mut a, t, 64) {
        input(&mut b, &bytes, t);
    }
    drain(&mut b, &mut a, t);
    assert!(a.snd_una.at_or_after(high));
    assert!(a.snd_una.after(data_start));
}

// NewReno (no SACK): the partial-ACK head retransmission keeps precedence
// when it names bytes that also carry PTB work. Those bytes leave the pending
// set with that single copy, so FlightSize is never reduced for them twice.
#[test]
fn newreno_partial_ack_head_and_ptb_name_the_same_bytes_once() {
    for ipv4 in [true, false] {
        for algorithm in [CongestionAlgorithm::Reno, CongestionAlgorithm::Cubic] {
            newreno_partial_ack(ipv4, algorithm);
        }
    }
}

fn newreno_partial_ack(ipv4: bool, algorithm: CongestionAlgorithm) {
    let cfg = ConnectionConfig {
        delayed_ack_us: 0,
        ..cfg(false, algorithm)
    };
    let (mut a, mut b) = super::pmtud_policy::family_pair(cfg, ipv4, 77);
    let mut now = 40;
    warm(&mut a, &mut b, 12, &mut now);
    a.write(&vec![2; 10 * a.mss]).unwrap();
    let sent: Vec<(Span, Vec<u8>)> = poll(&mut a, now, 16)
        .into_iter()
        .map(|bytes| (span(&a, &bytes), bytes))
        .collect();
    assert_eq!(sent.len(), 10);
    // s0 is lost, s1 and s2 were too big; s3.. arrive as duplicate ACKs.
    for k in 3..10 {
        // One duplicate ACK per arriving segment.
        input(&mut b, &sent[k].1, now + 1);
        drain(&mut b, &mut a, now + 1);
    }
    assert!(a.congestion.in_recovery());
    let fast = poll(&mut a, now + 1, 1);
    assert_eq!(span(&a, &fast[0]).0, sent[0].0.0);
    let (cwnd, ssthresh) = (a.congestion.cwnd(), a.congestion.ssthresh());
    for k in [1, 2] {
        assert_ne!(
            report(&mut a, now + 2, sent[k].0, 1280),
            PmtuFeedback::Rejected
        );
    }
    let pending = sent[2].0.1.distance_from(sent[1].0.0);
    assert_eq!(a.ptb.pending as u32, pending);
    // Non-SACK accounting: FlightSize minus the pending originals.
    assert_eq!(a.ptb_estimate(), a.flight() - pending);
    // One Restart repair: s1.
    let repairs = poll(&mut a, now + 2, 8);
    assert_eq!(repairs.len(), 1);
    assert_eq!(span(&a, &repairs[0]).0, sent[1].0.0);
    let len2 = sent[2].0.1.distance_from(sent[2].0.0);
    assert_eq!(a.ptb.pending as u32, len2);
    assert_eq!(a.ptb_estimate(), a.flight() - len2);
    // The fast retransmission and the repair arrive: a partial ACK at s2.
    input(&mut b, &fast[0], now + 3);
    input(&mut b, &repairs[0], now + 3);
    drain(&mut b, &mut a, now + 3);
    assert_eq!(a.snd_una, sent[2].0.0);
    assert!(a.congestion.in_recovery());
    assert!(a.retx_pending);
    // NewReno's head retransmission names s2, which still carries PTB work:
    // exactly one copy is sent and the work leaves the pending set with it.
    let mut copies = 0;
    for t in 3..8 {
        for bytes in poll(&mut a, now + t, 8) {
            let s = span(&a, &bytes);
            if s.0 == sent[2].0.0 {
                copies += 1;
                input(&mut b, &bytes, now + t);
            }
        }
    }
    assert_eq!(copies, 1);
    assert!(a.ptb_idle());
    assert_eq!(a.ptb_estimate(), a.flight());
    // No congestion response came from the PTBs: only NewReno's own.
    assert_eq!(a.congestion.ssthresh(), ssthresh);
    assert!(a.congestion.cwnd() <= cwnd.max(ssthresh));
    drain(&mut b, &mut a, now + 8);
    assert_eq!(a.snd_una, sent[9].0.1);
}

// Pacing bounds PTB repairs: the Restart repair and later ordinary repairs
// never leave before the pacing deadline.
#[test]
fn ptb_repairs_are_paced() {
    for ipv4 in [true, false] {
        for algorithm in [CongestionAlgorithm::Reno, CongestionAlgorithm::Cubic] {
            paced_repairs(ipv4, algorithm);
        }
    }
}

fn paced_repairs(ipv4: bool, algorithm: CongestionAlgorithm) {
    let cfg = ConnectionConfig {
        pacing: Some(PacingConfig {
            initial_window_burst: false,
            ..PacingConfig::default()
        }),
        delayed_ack_us: 0,
        ..cfg(true, algorithm)
    };
    let (mut a, mut b) = super::pmtud_policy::family_pair(cfg, ipv4, 5);
    let mut now = 1_000;
    a.write(&vec![3; 4 * a.mss]).unwrap();
    let mut sent = Vec::new();
    while sent.len() < 4 {
        match poll(&mut a, now, 1).pop() {
            Some(bytes) => sent.push((span(&a, &bytes), bytes)),
            None => {
                now = a.pacing_deadline.expect("paced, not blocked");
                a.timeout(now).unwrap();
            }
        }
    }
    // s1 and s2 were too big.
    for k in [1, 2] {
        assert_ne!(report(&mut a, now, sent[k].0, 1280), PmtuFeedback::Rejected);
    }
    let mut repairs = Vec::new();
    let mut times = Vec::new();
    let mut acked = false;
    let mut waited = 0;
    for _ in 0..64 {
        if let Some(deadline) = a.pacing_deadline.filter(|&d| d > now) {
            // Nothing leaves before the pacing deadline.
            assert!(poll(&mut a, now, 8).is_empty());
            waited += 1;
            now = deadline;
            a.timeout(now).unwrap();
        }
        for bytes in poll(&mut a, now, 1) {
            repairs.push(span(&a, &bytes));
            times.push(now);
            if !acked {
                // The Restart repair arrives: useful progress (a SACK).
                input(&mut b, &bytes, now);
                drain(&mut b, &mut a, now);
                acked = true;
            }
        }
        if a.ptb_idle() {
            break;
        }
        now += 1;
    }
    // The Restart repair covers the reduced-size prefix of s1; ordinary
    // admission then repairs the rest of s1 and s2, each paced.
    assert!(repairs.len() >= 2);
    let mut covered = repairs[0].0;
    for r in &repairs {
        assert_eq!(r.0, covered);
        covered = r.1;
    }
    assert_eq!(covered, sent[2].0.1);
    assert_eq!(repairs[0].0, sent[1].0.0);
    assert!(times.windows(2).all(|w| w[1] >= w[0]));
    assert!(times[times.len() - 1] > times[0]);
    assert!(waited != 0);
}

// The kept counts of lost PTB work against the scanning form they replace:
// two equal connection pairs see the same drops, Packet Too Big reports
// (some quoting a few bytes of the next segment), reordering and timeouts;
// one estimates and selects by scanning the marks. Every segment either
// side emits must be identical, and at every step both kept counts equal
// their scans.
#[test]
fn kept_ptb_counts_emit_what_scanning_did() {
    let (mut ptbs, mut timeouts) = (0, 0);
    for seed in 1..=40u64 {
        let rack = seed % 2 == 0;
        let prr = seed % 4 < 2;
        let ipv4 = seed % 3 != 0;
        let algorithm = if seed % 5 < 3 {
            CongestionAlgorithm::Cubic
        } else {
            CongestionAlgorithm::Reno
        };
        let (p, t) = kept_ptb_counts(seed, ipv4, rack, prr, algorithm);
        ptbs += p;
        timeouts += t;
    }
    // Both repair paths and RTO takeover were exercised.
    assert!(
        ptbs > 400 && timeouts > 10,
        "ptbs={ptbs} timeouts={timeouts}"
    );
}

// Returns the reports and timeouts it made.
fn kept_ptb_counts(
    seed: u64,
    ipv4: bool,
    rack: bool,
    prr: bool,
    algorithm: CongestionAlgorithm,
) -> (u32, u32) {
    let mut rng = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut next = move |n: u64| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng % n
    };
    let cfg = ConnectionConfig {
        rack,
        prr,
        delayed_ack_us: 0,
        ..cfg(true, algorithm)
    };
    let iss = [7, u32::MAX - 20_000][seed as usize % 2];
    let mut pairs = [
        super::pmtud_policy::family_pair(cfg.clone(), ipv4, iss),
        super::pmtud_policy::family_pair(cfg, ipv4, iss),
    ];
    pairs[1].0.ptb.scan = true;
    let mut now = 40;
    let mut held: Vec<Vec<u8>> = Vec::new();
    let mut sink = vec![0; 1 << 17];
    let (mut ptbs, mut timeouts) = (0, 0);
    for step in 0..400 {
        let chunk = vec![step as u8; next(20_000) as usize];
        let mut outputs = Vec::new();
        for (a, b) in &mut pairs {
            // A full send buffer takes nothing.
            assert!(matches!(a.write(&chunk), Ok(_) | Err(Error::WouldBlock)));
            if a.next_deadline().is_some_and(|deadline| deadline <= now) {
                timeouts += u32::from(a.rto_deadline.is_some_and(|d| d <= now));
                a.timeout(now).unwrap();
            }
            outputs.push(poll(a, now, 24));
            while b.read(&mut sink).is_ok_and(|n| n != 0) {}
        }
        assert_eq!(outputs[0], outputs[1], "seed={seed} step={step}");
        for bytes in &outputs[0] {
            let s = span(&pairs[0].0, bytes);
            match next(20) {
                0 | 1 if s.1.after(s.0) => {
                    // Too big: a quote may run a little into the next segment.
                    let extra = [0, 0, 1, 12][next(4) as usize];
                    let quote = (s.0, s.1.wrapping_add(extra), s.2);
                    for (a, _) in &mut pairs {
                        report(a, now, quote, 1280);
                    }
                    ptbs += 1;
                }
                2 => {}
                3 | 4 => held.push(bytes.clone()),
                _ => {
                    for (_, b) in &mut pairs {
                        input(b, bytes, now);
                    }
                }
            }
        }
        if !held.is_empty() && next(3) == 0 {
            let late = held.remove(next(held.len() as u64) as usize);
            for (_, b) in &mut pairs {
                input(b, &late, now);
            }
        }
        let acks: Vec<_> = pairs.iter_mut().map(|(_, b)| poll(b, now, 16)).collect();
        assert_eq!(acks[0], acks[1], "seed={seed} step={step}");
        for (a, _) in &mut pairs {
            for bytes in &acks[0] {
                input(a, bytes, now);
            }
        }
        let a = &pairs[0].0;
        for rack in [true, false] {
            assert_eq!(
                a.ptb_still_counted(rack),
                a.ptb_still_counted_scan(rack),
                "seed={seed} step={step} rack={rack}"
            );
        }
        // Mostly back-to-back rounds; now and then a gap past RTO.
        now += match next(12) {
            0 => 1_000_000 + next(1_000_000),
            _ => 1 + next(3) * next(60),
        };
    }
    (ptbs, timeouts / 2)
}
