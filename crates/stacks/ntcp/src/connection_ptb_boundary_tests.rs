// Boundary cases of exact-range PTB repair against a real peer receiver:
// zero-window persist and reopening, receive-window shrink, timestamps and
// Karn, ECN, termination, a reserved repair split during SACK/RACK recovery
// with PRR, and the lowest-pending hint and bounds of the PTB state.
use super::ptb_scheduler::{
    Span, cfg, drain, header, input, offset, payload_len, poll, report, report_on, span, warm,
};
use super::*;
use crate::{CongestionAlgorithm, PmtuFeedback};

// (data, first data sequence, segments) of an original flight.
type Flight = (Vec<u8>, Seq, Vec<(Span, Vec<u8>)>);

// `n` full-sized originals of distinct bytes, sent at `now`. Returns the data
// and the first data sequence number.
fn originals(a: &mut Connection, now: Instant, n: usize) -> Flight {
    let start = a.snd_nxt;
    let data: Vec<u8> = (0..n * a.mss).map(|i| (i * 11 + 5) as u8).collect();
    a.write(&data).unwrap();
    let sent = (0..n)
        .map(|_| {
            let bytes = packet(a, now);
            (span(a, &bytes), bytes)
        })
        .collect();
    (data, start, sent)
}

fn payload_of(a: &Connection, bytes: &[u8], data: &[u8], start: Seq) {
    let s = wire::parse(ip(a.tuple()), bytes).unwrap();
    let at = Seq(s.header.sequence).distance_from(start) as usize;
    assert_eq!(s.payload, &data[at..at + s.payload.len()]);
}

// The receiver's real ACKs with the advertised window field replaced: a
// receiver that closed or shrank its window (or the update reopening it).
fn drain_window(b: &mut Connection, a: &mut Connection, now: Instant, window: u16) {
    for bytes in poll(b, now, 16) {
        let mut segment = wire::parse(ip(reverse(a.tuple())), &bytes).unwrap();
        segment.header.window = window;
        a.input(now, &segment).unwrap();
    }
}

fn tuple_for(ipv4: bool) -> Tuple {
    if ipv4 {
        tuple()
    } else {
        Tuple {
            local: "[2001:db8::1]:1000".parse().unwrap(),
            remote: "[2001:db8::2]:2000".parse().unwrap(),
        }
    }
}

// Without window scaling: the receiver never sees the option in the SYN, so
// neither side scales.
fn unscaled_pair(cfg: ConnectionConfig, ipv4: bool, iss: u32) -> (Connection, Connection) {
    let tuple = tuple_for(ipv4);
    let mut a = Connection::active(tuple, cfg.clone(), iss, 0).unwrap();
    let bytes = packet(&mut a, 0);
    let mut syn = wire::parse(ip(tuple), &bytes).unwrap();
    syn.options.window_scale = None;
    let mut cfg = cfg;
    cfg.pmtud = None;
    let mut b = Connection::passive(reverse(tuple), cfg, 900, 10, &syn).unwrap();
    deliver(&mut b, &mut a, 20);
    deliver(&mut a, &mut b, 30);
    assert!(!a.scaling && !b.scaling);
    (a, b)
}

// Deliver everything each side emits (and service timers when idle) until
// the sender's queue is acknowledged. Returns every stream retransmission
// below `high` as (start, end).
fn complete(
    a: &mut Connection,
    b: &mut Connection,
    mut now: Instant,
    high: Seq,
) -> (Instant, Vec<(Seq, Seq)>) {
    let mut repairs = Vec::new();
    let limit = now + 100 * a.rto();
    while a.snd_una != a.snd_nxt || a.send.len() > a.snd_nxt.distance_from(a.send_base) as usize {
        assert!(now < limit, "transfer must complete");
        let out = poll(a, now, 32);
        for bytes in &out {
            let s = span(a, bytes);
            if s.0.after(s.1) || s.0 == s.1 {
                continue;
            }
            if !s.0.at_or_after(high) {
                repairs.push((s.0, earlier(s.1, high)));
            }
            input(b, bytes, now);
        }
        drain(b, a, now);
        if out.is_empty() {
            now = a.next_deadline().map_or(now + 1, |d| d.max(now + 1));
            a.timeout(now).unwrap();
        }
    }
    (now, repairs)
}

fn earlier(x: Seq, y: Seq) -> Seq {
    if x.after(y) { y } else { x }
}

// Each byte of [low, high) is covered by exactly `times` of the ranges.
fn covered(ranges: &[(Seq, Seq)], low: Seq, high: Seq, times: usize) {
    let mut seq = low;
    while seq != high {
        let n = ranges
            .iter()
            .filter(|&&(l, r)| seq.at_or_after(l) && r.after(seq))
            .count();
        assert_eq!(n, times, "{seq:?} in {ranges:?}");
        seq = seq.wrapping_add(1);
    }
}

fn read_all(b: &mut Connection) -> Vec<u8> {
    let mut out = vec![0; 1 << 20];
    let mut n = 0;
    while let Ok(m) = b.read(&mut out[n..]) {
        if m == 0 {
            break;
        }
        n += m;
    }
    out.truncate(n);
    out
}

// A zero window is flow control, not loss: the RTO under it probes the
// window (persist) without taking over PTB work and independently of the
// Restart allowance, spent or not. Reopening is no useful ACK progress: it
// grants the Restart packet only if none was sent, never a second one.
#[test]
fn zero_window_persist_is_independent_of_restart_and_repair_resumes_after_reopening() {
    for ipv4 in [true, false] {
        for spent in [false, true] {
            zero_window(ipv4, spent);
        }
    }
}

fn zero_window(ipv4: bool, spent: bool) {
    let cfg = ConnectionConfig {
        delayed_ack_us: 0,
        ..cfg(true, CongestionAlgorithm::Reno)
    };
    let (mut a, mut b) = super::pmtud_policy::family_pair(cfg, ipv4, 13);
    let (data, start, sent) = originals(&mut a, 40, 5);
    let high = sent[4].0.1;
    let (s1, s2) = (sent[1].0, sent[2].0);
    // s1 and s2 were too big for a smaller link; the others arrive.
    for k in [0, 3, 4] {
        input(&mut b, &sent[k].1, 41);
    }
    // The Restart packet, whenever it is sent.
    let mut restart = None;
    if spent {
        drain(&mut b, &mut a, 42);
        for s in [s1, s2] {
            assert_ne!(report(&mut a, 43, s, 1280), PmtuFeedback::Rejected);
        }
        let out = poll(&mut a, 43, 8);
        assert_eq!(out.len(), 1);
        restart = Some(out[0].clone());
        // The window closes on a duplicate ACK (no new delivery).
        input(&mut b, &sent[3].1, 44);
        drain_window(&mut b, &mut a, 44, 0);
    } else {
        // The closed window is announced first: no repair passes it.
        drain_window(&mut b, &mut a, 42, 0);
        for s in [s1, s2] {
            assert_ne!(report(&mut a, 43, s, 1280), PmtuFeedback::Rejected);
        }
        assert!(poll(&mut a, 43, 8).is_empty());
    }
    assert_eq!(a.snd_wnd, 0);
    assert!(a.ptb_in_restart());
    let pending = a.ptb.pending;
    assert_ne!(pending, 0);
    // Persist: the RTO under the closed window probes it with one byte.
    let (timer, deadline) = a.loss_timer.unwrap();
    assert_eq!(timer, LossTimer::Rto);
    a.timeout(deadline).unwrap();
    let probe = poll(&mut a, deadline, 8);
    assert_eq!(probe.len(), 1);
    let p = span(&a, &probe[0]);
    assert_eq!((p.0, p.1.distance_from(p.0)), (s1.0, 1));
    // No timeout takeover: the work survives and Restart is unchanged. A
    // probe of a still pending byte is a later copy of it.
    assert_eq!(a.consecutive_timeouts, 0);
    assert_eq!(a.ptb.rto_flight_end, None);
    assert!(a.ptb_in_restart());
    assert_eq!(a.ptb.pending, if spent { pending } else { pending - 1 });
    // The closed receiver discards the probe. Its window reopens on a
    // duplicate ACK: a window update without new delivery.
    let now = deadline + 1;
    input(&mut b, &sent[4].1, now);
    drain(&mut b, &mut a, now);
    assert_ne!(a.snd_wnd, 0);
    let out = poll(&mut a, now, 8);
    if spent {
        // Reopening grants no second Restart packet.
        assert!(out.is_empty());
    } else {
        // The allowance the closed window held back: one packet.
        assert_eq!(out.len(), 1);
        assert_eq!(span(&a, &out[0]).0, s1.0.wrapping_add(1));
        restart = Some(out[0].clone());
    }
    let restart = restart.unwrap();
    let r = span(&a, &restart);
    assert!(r.2 <= a.path_mtu_info().unwrap().current_mtu);
    payload_of(&a, &restart, &data, start);
    // The Restart packet arrives (useful progress); ordinary admission and
    // recovery finish the transfer. The discarded probe's byte is ordinary
    // recovery's to repair; no other byte of the dropped range is sent twice.
    input(&mut b, &restart, now);
    drain(&mut b, &mut a, now);
    let (_, rest) = complete(&mut a, &mut b, now + 1, high);
    let mut all = vec![(r.0, r.1)];
    all.extend(rest);
    covered(&all, s1.0, s2.1, 1);
    assert_eq!(read_all(&mut b), data);
}

// A receive window shrunk into the dropped range clips the PTB repair through
// the existing retry-window policy: unscaled, the repair stops at the
// current right edge; scaled, RFC 7323's permission for a first retry of
// originally in-window data applies. Each repaired byte is sent once.
#[test]
fn receive_window_shrink_clips_ptb_repair_through_the_retry_window_policy() {
    for ipv4 in [true, false] {
        for scaled in [false, true] {
            shrink(ipv4, scaled);
        }
    }
}

fn shrink(ipv4: bool, scaled: bool) {
    let cfg = ConnectionConfig {
        delayed_ack_us: 0,
        ..cfg(true, CongestionAlgorithm::Reno)
    };
    let (mut a, mut b) = if scaled {
        super::pmtud_policy::family_pair(cfg, ipv4, 17)
    } else {
        unscaled_pair(cfg, ipv4, 17)
    };
    assert_eq!(a.scaling, scaled);
    let (data, start, sent) = originals(&mut a, 40, 4);
    let high = sent[3].0.1;
    let s1 = sent[1].0;
    for k in [0, 2, 3] {
        input(&mut b, &sent[k].1, 41);
    }
    // The receiver shrinks its window so that its right edge lies inside s1.
    let allowed = 400u32;
    let shift = if scaled { a.peer_scale } else { 0 };
    drain_window(&mut b, &mut a, 42, (allowed >> shift) as u16);
    assert_eq!((a.snd_una, a.snd_wnd), (s1.0, allowed));
    assert_ne!(report(&mut a, 43, s1, 1280), PmtuFeedback::Rejected);
    let out = poll(&mut a, 43, 8);
    assert_eq!(out.len(), 1);
    let r = span(&a, &out[0]);
    assert_eq!(r.0, s1.0);
    payload_of(&a, &out[0], &data, start);
    let len = s1.1.distance_from(s1.0);
    assert_eq!(
        r.1.distance_from(r.0),
        if scaled {
            len.min(a.mss as u32)
        } else {
            allowed
        }
    );
    let mut repairs = vec![(r.0, r.1)];
    let mut now = 44;
    input(&mut b, &out[0], now);
    if !scaled {
        // While the window stays shrunk, every repair stays inside it.
        for _ in 0..2 {
            drain_window(&mut b, &mut a, now, allowed as u16);
            now += 1;
            for bytes in poll(&mut a, now, 8) {
                let s = span(&a, &bytes);
                assert!(!s.1.after(a.snd_una.wrapping_add(a.snd_wnd)));
                if !s.0.at_or_after(high) {
                    repairs.push((s.0, s.1));
                }
                input(&mut b, &bytes, now);
            }
        }
    }
    drain(&mut b, &mut a, now);
    let (_, rest) = complete(&mut a, &mut b, now + 1, high);
    repairs.extend(rest);
    covered(&repairs, s1.0, s1.1, 1);
    assert_eq!(a.consecutive_timeouts, 0);
    assert_eq!(read_all(&mut b), data);
}

// Karn: the ACK of a PTB repair copy is ambiguous and yields no RTT sample,
// with or without timestamps (whose echo of the copy's TSval is not used to
// sample retransmitted data) and with or without RACK. A later original is
// sampled under the existing rules.
#[test]
fn ptb_repair_copies_never_yield_rtt_samples_and_later_originals_do() {
    for ipv4 in [true, false] {
        for timestamps in [false, true] {
            for rack in [false, true] {
                karn(ipv4, timestamps, rack);
            }
        }
    }
}

fn karn(ipv4: bool, timestamps: bool, rack: bool) {
    let cfg = ConnectionConfig {
        delayed_ack_us: 0,
        timestamps,
        rack,
        ..cfg(true, CongestionAlgorithm::Reno)
    };
    let (mut a, mut b) = super::pmtud_policy::family_pair(cfg, ipv4, 23);
    assert_eq!(a.timestamps, timestamps);
    // One 100-tick round trip.
    a.write(&vec![1; a.mss]).unwrap();
    let bytes = packet(&mut a, 1_000);
    input(&mut b, &bytes, 1_050);
    drain(&mut b, &mut a, 1_100);
    let _ = read_all(&mut b);
    let (data, _, sent) = originals(&mut a, 2_000, 3);
    let high = sent[2].0.1;
    // s1 was too big; s0 and s2 arrive after the same 100-tick round trip.
    input(&mut b, &sent[0].1, 2_050);
    input(&mut b, &sent[2].1, 2_050);
    drain(&mut b, &mut a, 2_100);
    assert_eq!(a.snd_una, sent[1].0.0);
    let srtt = a.rtt.srtt();
    assert!(srtt.is_some());
    assert_ne!(
        report(&mut a, 2_100, sent[1].0, 1280),
        PmtuFeedback::Rejected
    );
    let out = poll(&mut a, 2_100, 8);
    assert_eq!(out.len(), 1);
    let r = span(&a, &out[0]);
    assert_eq!(r.0, sent[1].0.0);
    assert!(a.sample.is_none());
    // The repair arrives much later; the ACKs of it and of the rest of s1
    // are ambiguous (original or copy) and must not be sampled.
    input(&mut b, &out[0], 9_000);
    drain(&mut b, &mut a, 9_000);
    assert!(a.snd_una.at_or_after(r.1));
    assert_eq!(a.rtt.srtt(), srtt);
    let mut now = 9_000;
    while a.snd_una != high {
        now += 500;
        assert!(now < 20_000);
        for bytes in poll(&mut a, now, 8) {
            input(&mut b, &bytes, now);
        }
        drain(&mut b, &mut a, now);
    }
    assert_eq!(a.consecutive_timeouts, 0);
    assert_eq!(a.rtt.srtt(), srtt);
    assert_eq!(read_all(&mut b), data);
    // A fresh original after the repair is sampled again (400 ticks).
    a.write(&vec![2; a.mss]).unwrap();
    let bytes = packet(&mut a, 30_000);
    input(&mut b, &bytes, 30_200);
    drain(&mut b, &mut a, 30_400);
    assert_ne!(a.rtt.srtt(), srtt);
}

// ECN feedback arriving while PTB work is pending gets the ordinary ECN
// response, exactly as without the PTB (one reduction per window, CWR on new
// data); PTB work and the Restart rule are unaffected, PTB repairs carry no
// CWR, and the PTB adds no reduction of its own.
#[test]
fn ecn_feedback_during_ptb_work_keeps_the_ordinary_response() {
    for ipv4 in [true, false] {
        let control = ecn_during_ptb(ipv4, false);
        let ptb = ecn_during_ptb(ipv4, true);
        assert_eq!(control, ptb);
    }
}

// Congestion state after the first and after a second ECE-carrying flight.
fn ecn_during_ptb(ipv4: bool, ptb: bool) -> [(u32, u32, bool); 2] {
    let cfg = ConnectionConfig {
        delayed_ack_us: 0,
        ecn: true,
        ..cfg(true, CongestionAlgorithm::Reno)
    };
    let (mut a, mut b) = super::pmtud_policy::family_pair(cfg, ipv4, 29);
    assert!(a.transport_info().ecn_negotiated);
    let mut now = 40;
    warm(&mut a, &mut b, 16, &mut now);
    let (cwnd, ssthresh) = (a.congestion.cwnd(), a.congestion.ssthresh());
    let (data, start, sent) = originals(&mut a, now, 6);
    let high = sent[5].0.1;
    let tuple = reverse(a.tuple());
    let mut repaired = Vec::new();
    if ptb {
        // s1 and s3 were too big. Full-sized packets were delivered before,
        // so the reports are Deferred: no MSS change, and s1 is repaired at
        // the authorized size by the one Restart packet.
        for k in [1, 3] {
            assert_eq!(report(&mut a, now, sent[k].0, 1280), PmtuFeedback::Deferred);
        }
        let out = poll(&mut a, now, 8);
        assert_eq!(out.len(), 1);
        let r = span(&a, &out[0]);
        assert_eq!((r.0, r.1), (sent[1].0.0, sent[1].0.1));
        let s = wire::parse(ip(a.tuple()), &out[0]).unwrap();
        assert_eq!(s.header.flags & CWR, 0);
        payload_of(&a, &out[0], &data, start);
        repaired.push(out[0].clone());
    }
    // s0 arrives CE-marked, s2 normally: the receiver echoes ECE.
    let s0 = wire::parse(ip(a.tuple()), &sent[0].1).unwrap();
    b.input_with_traffic_class(now + 1, 3, &s0).unwrap();
    input(&mut b, &sent[2].1, now + 1);
    let acks = poll(&mut b, now + 1, 16);
    assert!(
        acks.iter()
            .all(|p| wire::parse(ip(tuple), p).unwrap().header.flags & ECE != 0)
    );
    for bytes in &acks {
        input(&mut a, bytes, now + 1);
    }
    // One ECN reduction, no loss recovery.
    assert!(a.congestion.ssthresh() < ssthresh.max(cwnd));
    assert!(a.ecn_cwr_pending);
    let first = (
        a.congestion.cwnd(),
        a.congestion.ssthresh(),
        a.ecn_cwr_pending,
    );
    if ptb {
        // Cumulative progress ended Restart; the s3 work is untouched.
        assert!(!a.ptb_in_restart());
        assert_eq!(a.ptb.pending as u32, sent[3].0.1.distance_from(sent[3].0.0));
    }
    // More ECE in the same window: no second reduction.
    input(&mut b, &sent[4].1, now + 2);
    drain(&mut b, &mut a, now + 2);
    let second = (
        a.congestion.cwnd(),
        a.congestion.ssthresh(),
        a.ecn_cwr_pending,
    );
    assert_eq!(second.1, first.1);
    if ptb {
        // The s1 repair and s5 arrive.
        input(&mut b, &repaired[0], now + 2);
        input(&mut b, &sent[5].1, now + 2);
        drain(&mut b, &mut a, now + 2);
        // The remaining PTB repair carries no CWR; new data does.
        let mut now = now + 3;
        while !a.ptb_idle() {
            assert!(now < 200);
            for bytes in poll(&mut a, now, 8) {
                let s = wire::parse(ip(a.tuple()), &bytes).unwrap();
                let seq = Seq(s.header.sequence);
                if !seq.at_or_after(high) {
                    assert_eq!(s.header.flags & CWR, 0);
                    repaired.push(bytes.clone());
                }
                input(&mut b, &bytes, now);
            }
            drain(&mut b, &mut a, now);
            now += 1;
        }
        let spans: Vec<(Seq, Seq)> = repaired
            .iter()
            .map(|p| {
                let s = span(&a, p);
                (s.0, s.1)
            })
            .collect();
        covered(&spans, sent[3].0.0, sent[3].0.1, 1);
        covered(&spans, sent[1].0.0, sent[1].0.1, 1);
    }
    [first, second]
}

// Termination with PTB work pending: abort sends only the RST and abandons
// all per-byte work; a graceful close keeps repairing the dropped range
// before its FIN is acknowledged.
#[test]
fn abort_and_close_with_ptb_work_pending() {
    for ipv4 in [true, false] {
        for abort in [true, false] {
            terminate(ipv4, abort);
        }
    }
}

fn terminate(ipv4: bool, abort: bool) {
    let cfg = ConnectionConfig {
        delayed_ack_us: 0,
        ..cfg(true, CongestionAlgorithm::Reno)
    };
    let (mut a, mut b) = super::pmtud_policy::family_pair(cfg, ipv4, 31);
    let (data, _, sent) = originals(&mut a, 40, 3);
    let high = sent[2].0.1;
    for k in [0, 2] {
        input(&mut b, &sent[k].1, 41);
    }
    drain(&mut b, &mut a, 41);
    assert_ne!(report(&mut a, 42, sent[1].0, 1280), PmtuFeedback::Rejected);
    assert_ne!(a.ptb.pending, 0);
    if abort {
        a.abort();
        assert_eq!(a.state(), State::Closed);
        assert!(a.ptb_idle());
        assert_eq!(a.ptb.copies, 0);
        assert_eq!(a.ptb_bounds(), (None, None));
        for i in 0..a.send.len() {
            assert!(!a.send.ptb_pending(i) && !a.send.ptb_copy(i));
        }
        let out = poll(&mut a, 43, 8);
        assert_eq!(out.len(), 1);
        let s = wire::parse(ip(a.tuple()), &out[0]).unwrap();
        assert_ne!(s.header.flags & RST, 0);
        assert!(s.payload.is_empty());
        // A later report about the dead connection repairs nothing.
        assert_eq!(report(&mut a, 44, sent[1].0, 1280), PmtuFeedback::Rejected);
        assert!(poll(&mut a, 44, 8).is_empty());
        return;
    }
    a.close().unwrap();
    let out = poll(&mut a, 43, 8);
    // One Restart repair; anything else is the new FIN.
    for bytes in &out[1..] {
        let s = span(&a, bytes);
        assert_eq!((s.0, s.1), (high, high.wrapping_add(1)));
    }
    let r = span(&a, &out[0]);
    assert_eq!(r.0, sent[1].0.0);
    // The FIN follows the data it closes; it is not part of the repair.
    let s = wire::parse(ip(a.tuple()), &out[0]).unwrap();
    assert_eq!(s.header.flags & FIN, 0);
    for bytes in &out {
        input(&mut b, bytes, 43);
    }
    drain(&mut b, &mut a, 43);
    let (_, rest) = complete(&mut a, &mut b, 44, high);
    let mut all = vec![(r.0, r.1)];
    all.extend(rest);
    covered(&all, sent[1].0.0, sent[1].0.1, 1);
    assert_eq!(a.consecutive_timeouts, 0);
    assert_eq!(read_all(&mut b), data);
    assert!(a.fin_sequence.is_some_and(|fin| a.snd_una.after(fin)));
}

// A reserved PTB repair split by a racing decrease during Restart while SACK
// recovery and PRR are active (RFC 6675 SetPipe or RACK): PRR's prr_out, the
// pipe and HighRxt (or the RACK record) are charged once, for the accepted
// fragment only; the withdrawn suffix is never charged and is repaired later
// exactly once, after useful ACK progress.
#[test]
fn reserved_repair_split_in_restart_during_prr_sack_and_rack_recovery() {
    for ipv4 in [true, false] {
        for rack in [false, true] {
            split_in_recovery(ipv4, rack);
        }
    }
}

fn split_in_recovery(ipv4: bool, rack: bool) {
    let cfg = ConnectionConfig {
        rack,
        prr: true,
        tlp: false,
        delayed_ack_us: 0,
        ..cfg(true, CongestionAlgorithm::Reno)
    };
    let (mut a, mut b) = super::pmtud_policy::family_pair(cfg, ipv4, u32::MAX - 7000);
    let mut now = 40;
    warm(&mut a, &mut b, 30, &mut now);
    let (_, _, sent) = originals(&mut a, now, 16);
    // Unsent data keeps RFC 6675 NextSeg at rule 2 (new data) rather than
    // the rule 3 speculative retransmission of an unSACKed, not-lost hole.
    a.write(&vec![7; 8 * a.mss]).unwrap();
    // s1 and s2 are lost; s0 and s3..s5 arrive.
    for k in [0, 3, 4, 5] {
        input(&mut b, &sent[k].1, now + 1);
    }
    drain(&mut b, &mut a, now + 1);
    now += 1;
    if a.sack_recovery.is_none() {
        now = a.rack.deadline.expect("RACK reordering timer");
        a.timeout(now).unwrap();
    }
    assert!(a.sack_recovery.is_some() && a.prr.is_some());
    // Ordinary recovery keeps precedence: s1 and s2 first, then new data
    // once delivered originals give PRR credit. The receiver gets none of
    // these transmissions yet.
    let mut fresh = None;
    let mut k = 6;
    while fresh.is_none() {
        assert!(k < 12);
        for bytes in poll(&mut a, now, 8) {
            let s = span(&a, &bytes);
            if s.0.at_or_after(sent[15].0.1) {
                fresh.get_or_insert(s);
            } else {
                // PRR may clip these repairs.
                assert!(s.0.at_or_after(sent[1].0.0) && !s.1.after(sent[2].0.1));
            }
        }
        input(&mut b, &sent[k].1, now);
        drain(&mut b, &mut a, now);
        k += 1;
    }
    // The first new segment f was too big. The remaining originals arrive,
    // sent before f and below it: f is lost to neither estimator, and their
    // delivery gives PRR credit.
    let f = fresh.unwrap();
    now += 1;
    for (_, bytes) in &sent[k..] {
        input(&mut b, bytes, now);
    }
    drain(&mut b, &mut a, now);
    assert!(a.sack_recovery.is_some() && a.prr.is_some());
    assert!(!a.scoreboard.is_lost(f.0, a.mss as u32));
    assert_ne!(report(&mut a, now, f, 1400), PmtuFeedback::Rejected);
    assert!(a.ptb_in_restart());
    let mut out = vec![0; 4096];
    let n = a
        .transmit_selected(now, &mut out, true)
        .unwrap()
        .expect("reserved PTB repair");
    let selected = span(&a, &out[..n]);
    assert_eq!(selected.0, f.0);
    let mut d = a.last_departure.unwrap();
    assert!(d.ptb_repair);
    // Selection charges nothing.
    let prr_before = a.prr.unwrap().counters().2;
    let recovery = a.sack_recovery.unwrap();
    let rack_before = a.rack.head_transmission(f.0).unwrap();
    // A racing decrease splits the held repair: one fragment is accepted.
    a.set_reserved_first_hop_mtu(now, 1280).unwrap();
    let fragment = 1280 - usize::from(header(&a)) - 20;
    assert!(fragment < d.payload);
    assert!(
        a.accept_reserved_output(now, &mut d, 0, fragment, false)
            .unwrap()
    );
    let end = f.0.wrapping_add(fragment as u32);
    // PRR: prr_out grew by exactly the accepted fragment.
    assert_eq!(a.prr.unwrap().counters().2 - prr_before, fragment as u64);
    let after = a.sack_recovery.unwrap();
    // The accepted fragment is a new transmission record; the suffix keeps
    // its original record.
    assert_eq!(a.rack.head_transmission(f.0).unwrap(), (end, now));
    assert_eq!(a.rack.head_transmission(end).unwrap(), rack_before);
    if rack {
        // RACK's estimator is the pipe.
        assert_eq!(after.pipe, a.rack.pipe());
        assert_eq!(after.high_rxt, recovery.high_rxt);
    } else {
        // RFC 6675: pipe counts the accepted fragment once. Every byte from
        // HighRxt to f is SACKed, so HighRxt moves over the fragment only.
        assert_eq!(after.pipe, recovery.pipe + fragment as u32);
        assert_eq!(after.high_rxt, end);
        assert_eq!(a.ptb.copies, 0);
    }
    assert!(a.send.retransmitted(offset(&a, end) - 1));
    assert!(!a.send.retransmitted(offset(&a, end)));
    assert_eq!(a.ptb.pending, f.1.distance_from(end) as usize);
    // The suffix waits for useful ACK progress.
    assert!(a.ptb_segment(a.mss).is_none());
    // A late original s1 arrives: cumulative progress ends Restart.
    input(&mut b, &sent[1].1, now + 1);
    drain(&mut b, &mut a, now + 1);
    assert!(!a.ptb_in_restart());
    // The suffix is repaired exactly once and charged once.
    let mut suffix = Vec::new();
    for t in 2..12 {
        let before = a.prr.map(|p| p.counters().2);
        let mut bytes_out = 0;
        for bytes in poll(&mut a, now + t, 8) {
            let s = span(&a, &bytes);
            if s.0.at_or_after(end) && f.1.after(s.0) {
                suffix.push((s.0, s.1));
            }
            bytes_out += u64::from(payload_len(&a, &bytes));
            input(&mut b, &bytes, now + t);
        }
        if let (Some(before), Some(p)) = (before, a.prr) {
            // Every emitted byte is charged to prr_out exactly once.
            assert_eq!(p.counters().2 - before, bytes_out);
        }
        drain(&mut b, &mut a, now + t);
        if a.ptb_idle() {
            break;
        }
    }
    assert!(a.ptb_idle());
    covered(&suffix, end, f.1, 1);
}

// The selection hint never lies past the lowest pending byte, so selection
// never skips work; the bounds always contain every pending byte and shrink
// as cumulative ACKs, SACKs and repairs release their ends.
#[test]
fn ptb_selection_hint_and_bounds_track_pending_work() {
    for ipv4 in [true, false] {
        for iss in [0, u32::MAX - 5000] {
            hint_and_bounds(ipv4, iss);
        }
    }
}

// Invariants: every pending byte lies at or after the hint and inside the
// bounds; returns the lowest pending byte.
fn check_bounds(a: &Connection) -> Option<Seq> {
    let (span, next) = a.ptb_bounds();
    let mut lowest = None;
    let mut count = 0;
    for i in 0..a.send.len() {
        let seq = a.send_base.wrapping_add(i as u32);
        let marked = a.send.ptb_pending(i) || a.send.ptb_copy(i);
        if a.send.ptb_pending(i) {
            count += 1;
            lowest.get_or_insert(seq);
            assert!(seq.at_or_after(next.expect("hint while work is pending")));
        }
        if marked {
            let (low, high) = span.expect("bounds while bytes are marked");
            assert!(seq.at_or_after(low) && high.after(seq));
        }
    }
    assert_eq!(count, a.ptb.pending);
    if a.ptb.pending == 0 {
        assert_eq!(next, None);
    }
    lowest
}

fn hint_and_bounds(ipv4: bool, iss: u32) {
    let cfg = ConnectionConfig {
        delayed_ack_us: 0,
        ..cfg(true, CongestionAlgorithm::Reno)
    };
    let (mut a, mut b) = super::pmtud_policy::family_pair(cfg, ipv4, iss);
    let (_, _, sent) = originals(&mut a, 40, 8);
    let s = |k: usize| sent[k].0;
    assert_eq!(a.ptb_bounds(), (None, None));
    // Reports out of order: the hint follows the lowest reported byte.
    assert_ne!(
        report_on(&mut a, 41, s(5), 1400, false),
        PmtuFeedback::Rejected
    );
    assert_eq!(a.ptb_bounds(), (Some((s(5).0, s(5).1)), Some(s(5).0)));
    assert_ne!(
        report_on(&mut a, 41, s(2), 1400, false),
        PmtuFeedback::Rejected
    );
    assert_ne!(
        report_on(&mut a, 41, s(6), 1400, false),
        PmtuFeedback::Rejected
    );
    assert_eq!(a.ptb_bounds(), (Some((s(2).0, s(6).1)), Some(s(2).0)));
    assert_eq!(check_bounds(&a), Some(s(2).0));
    // Selection starts at the hint: the lowest pending run (Restart packet).
    let (seq, count, _) = a.ptb_segment(a.mss).unwrap();
    assert_eq!((seq, count), (s(2).0, a.mss));
    let out = poll(&mut a, 42, 8);
    assert_eq!(out.len(), 1);
    assert_eq!(span(&a, &out[0]).0, s(2).0);
    // The repaired run left the pending set; the hint stays below the next
    // pending byte and the next selection resumes there.
    assert_eq!(check_bounds(&a), Some(s(5).0));
    // s0, s1, the repair of s2, s3 and s7 arrive; s4 is still missing.
    for k in [0, 1, 3, 7] {
        input(&mut b, &sent[k].1, 43);
    }
    input(&mut b, &out[0], 43);
    drain(&mut b, &mut a, 43);
    assert_eq!(a.snd_una, s(4).0);
    // The cumulative ACK released the low end of the bounds.
    let (bounds, _) = a.ptb_bounds();
    assert!(bounds.unwrap().0.at_or_after(a.snd_una));
    assert_eq!(check_bounds(&a), Some(s(5).0));
    let (seq, _, _) = a.ptb_segment(a.mss).unwrap();
    assert_eq!(seq, s(5).0);
    assert!(a.ptb_bounds().1.unwrap().at_or_after(s(5).0));
    // A SACK of s6 (the top of the bounds) withdraws its work and trims it.
    input(&mut b, &sent[6].1, 44);
    drain(&mut b, &mut a, 44);
    let (low, high) = a.ptb_bounds().0.unwrap();
    assert_eq!(high, s(5).1);
    assert!(low.at_or_after(a.snd_una) && !low.after(s(5).0));
    assert_eq!(check_bounds(&a), Some(s(5).0));
    // Ordinary admission repairs s5; then the work and the bounds are gone.
    let mut now = 45;
    while !a.ptb_idle() {
        assert!(now < 60);
        for bytes in poll(&mut a, now, 8) {
            input(&mut b, &bytes, now);
            check_bounds(&a);
        }
        drain(&mut b, &mut a, now);
        check_bounds(&a);
        now += 1;
    }
    input(&mut b, &sent[4].1, now);
    drain(&mut b, &mut a, now);
    assert_eq!(a.ptb_bounds(), (None, None));
    assert_eq!(a.snd_una, s(7).1);
}
