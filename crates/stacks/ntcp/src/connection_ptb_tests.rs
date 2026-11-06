// Exact-range PTB drop bookkeeping: which outstanding bytes an accepted
// report records as dropped, and how delivery, SACK, retransmission, RTO,
// resize and termination change that per-byte state.
use super::*;
use crate::{CorrelatedPmtu, CorrelatedSegment, PmtuFeedback::*, PmtuReport, PmtudConfig};

// (start, end, complete IP length) of one emitted segment.
type Span = (Seq, Seq, u32);

// The search starts converged, so ordinary output carries no upward probe.
fn cfg() -> ConnectionConfig {
    ConnectionConfig {
        pmtud: Some(PmtudConfig {
            initial_search_low: Some(1500),
            ..PmtudConfig::new(1500)
        }),
        initial_window: InitialWindow::Iw10,
        nagle: false,
        timestamps: false,
        sack: true,
        ..config(65_536, 1460)
    }
}

fn header(a: &Connection) -> u16 {
    if a.tuple().local.is_ipv4() { 20 } else { 40 }
}

fn span(a: &Connection, bytes: &[u8]) -> Span {
    let s = wire::parse(ip(a.tuple()), bytes).unwrap();
    let start = Seq(s.header.sequence);
    let len = s.payload.len() as u32 + u32::from(s.header.flags & FIN != 0);
    (
        start,
        start.wrapping_add(len),
        bytes.len() as u32 + u32::from(header(a)),
    )
}

// `n` full-sized original segments of distinct bytes, none acknowledged.
fn flight(ipv4: bool, iss: u32, n: usize) -> (Connection, Connection, Vec<Span>) {
    let (mut a, b) = super::pmtud_policy::family_pair(cfg(), ipv4, iss);
    let data: Vec<u8> = (0..(n + 1) * 1460).map(|i| i as u8).collect();
    a.write(&data).unwrap();
    let spans: Vec<Span> = (0..n)
        .map(|k| {
            let bytes = packet(&mut a, 40 + k as u64);
            span(&a, &bytes)
        })
        .collect();
    for s in &spans {
        assert_eq!(s.2, 1500);
    }
    (a, b, spans)
}

fn report(a: &mut Connection, now: Instant, s: Span, candidate: u32, current: bool) -> PmtuReport {
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
            path_estimate: super::ptb_scheduler::host_estimate(a, current),
        },
        None,
    )
    .unwrap()
}

// Pending stream ranges, read back from the per-byte flags; also checks the
// constant-time count against them.
fn pending(a: &Connection) -> Vec<(Seq, Seq)> {
    let mut out = Vec::new();
    let mut run = None;
    for i in 0..=a.send.len() {
        match (i < a.send.len() && a.send.ptb_pending(i), run) {
            (true, None) => run = Some(i),
            (false, Some(start)) => {
                out.push((
                    a.send_base.wrapping_add(start as u32),
                    a.send_base.wrapping_add(i as u32),
                ));
                run = None;
            }
            _ => {}
        }
    }
    let total: u32 = out.iter().map(|&(l, r)| r.distance_from(l)).sum();
    assert_eq!(total as usize, a.ptb.pending);
    assert_eq!(a.ptb_idle(), total == 0 && !a.ptb.fin_pending);
    out
}

fn retransmitted(a: &Connection, seq: Seq) -> bool {
    a.send
        .retransmitted(seq.distance_from(a.send_base) as usize)
}

// Synthetic peer ACK, with at most one SACK block.
fn ack(a: &mut Connection, now: Instant, ack: Seq, sack: Option<(Seq, Seq)>) {
    let tuple = reverse(a.tuple());
    let mut options = Vec::new();
    if let Some((left, right)) = sack {
        options.extend([1, 1, 5, 10]);
        options.extend(left.0.to_be_bytes());
        options.extend(right.0.to_be_bytes());
    }
    let mut out = [0; 96];
    let n = wire::encode(
        ip(tuple),
        Header {
            source_port: tuple.local.port(),
            destination_port: tuple.remote.port(),
            sequence: a.receive.next().0,
            acknowledgment: ack.0,
            flags: ACK,
            window: (65_535u32 >> a.peer_scale) as u16,
            urgent_pointer: 0,
        },
        &options,
        &[],
        &mut out,
    )
    .unwrap();
    a.input(now, &wire::parse(ip(tuple), &out[..n]).unwrap())
        .unwrap();
}

fn rto(a: &mut Connection) {
    while a.consecutive_timeouts == 0 {
        let (_, deadline) = a.loss_timer.unwrap();
        a.timeout(deadline).unwrap();
    }
}

#[test]
fn every_accepted_class_records_exact_quoted_outstanding_bytes() {
    for ipv4 in [true, false] {
        for iss in [0, u32::MAX - 3000] {
            let (mut a, _b, s) = flight(ipv4, iss, 4);
            assert!(pending(&a).is_empty());
            if ipv4 {
                // A pure ACK quote inside the flight is accepted but carries
                // no stream work.
                let bare = (s[2].0, s[2].0, 100);
                assert_eq!(report(&mut a, 49, bare, 68, false).feedback, Unchanged);
                assert!(pending(&a).is_empty());
            }
            // Decreased, about the non-head second packet only.
            assert_eq!(
                report(&mut a, 50, s[1], 1400, true),
                PmtuReport {
                    feedback: Decreased { mtu: 1400 },
                    derived_mtu: Some(1400)
                }
            );
            assert_eq!(pending(&a), [(s[1].0, s[1].1)]);
            // Duplicates, older incarnations and other sizes add nothing.
            for (candidate, current) in [(1400, true), (1300, false), (1450, true)] {
                assert_eq!(
                    report(&mut a, 51, s[1], candidate, current).feedback,
                    Unchanged
                );
                assert_eq!(pending(&a), [(s[1].0, s[1].1)]);
            }
            // Unchanged on the current path and on an older incarnation are
            // drop notifications too; neither moves the local estimate.
            assert_eq!(
                report(&mut a, 52, s[2], 1450, true),
                PmtuReport {
                    feedback: Unchanged,
                    derived_mtu: Some(1450)
                }
            );
            assert_eq!(report(&mut a, 53, s[3], 1300, false).feedback, Unchanged);
            assert_eq!(a.path_mtu_info().unwrap().current_mtu, 1400);
            assert_eq!(pending(&a), [(s[1].0, s[3].1)]);
            assert!(!retransmitted(&a, s[0].0));
            // Delivery releases work: a cumulative ACK, then a partial one.
            ack(&mut a, 54, s[1].1, None);
            assert_eq!(pending(&a), [(s[2].0, s[3].1)]);
            let partial = s[2].0.wrapping_add(100);
            ack(&mut a, 55, partial, None);
            assert_eq!(pending(&a), [(partial, s[3].1)]);
            // A partially acknowledged quote is accepted; it adds nothing new.
            assert_eq!(report(&mut a, 56, s[2], 1450, false).feedback, Unchanged);
            assert_eq!(pending(&a), [(partial, s[3].1)]);
            // A wholly acknowledged quote is no notification at all.
            assert_eq!(report(&mut a, 57, s[0], 1300, false).feedback, Rejected);
            ack(&mut a, 58, s[3].1, None);
            assert!(pending(&a).is_empty());
        }
    }
}

#[test]
fn legacy_nondecreasing_ring_matched_report_is_a_drop_notification() {
    for ipv4 in [true, false] {
        for iss in [0, u32::MAX - 3000] {
            let (mut a, _b, s) = flight(ipv4, iss, 3);
            let h = header(&a);
            // Invalid quotes: unrecorded start, wrong size, impossible candidate.
            assert!(!a.pmtu_feedback(49, s[1].0.0 + 1, 1500, h, 1400).unwrap());
            assert!(!a.pmtu_feedback(49, s[1].0.0, 1499, h, 1400).unwrap());
            assert!(!a.pmtu_feedback(49, s[1].0.0, 1500, h, 1500).unwrap());
            assert!(pending(&a).is_empty());
            assert!(a.pmtu_feedback(50, s[1].0.0, 1500, h, 1400).unwrap());
            assert_eq!(a.path_mtu_info().unwrap().current_mtu, 1400);
            assert_eq!(pending(&a), [(s[1].0, s[1].1)]);
            // A PTB-caused decrease is budget-only: no head retry from SND.UNA.
            assert!(!a.retx_pending);
            ack(&mut a, 51, s[0].1, None);
            assert!(!a.retx_pending);
            let info = a.path_mtu_info().unwrap();
            // A nondecreasing report of a recorded, still outstanding packet
            // is accepted: its bytes become repair work, while the estimate
            // neither rises nor schedules a head retry.
            assert!(a.pmtu_feedback(52, s[2].0.0, 1500, h, 1450).unwrap());
            assert_eq!(a.path_mtu_info().unwrap(), info);
            assert!(!a.retx_pending);
            assert_eq!(pending(&a), [(s[1].0, s[2].1)]);
            // Repeating it adds nothing; an acknowledged packet is rejected.
            assert!(a.pmtu_feedback(53, s[2].0.0, 1500, h, 1450).unwrap());
            assert_eq!(pending(&a), [(s[1].0, s[2].1)]);
            assert!(!a.pmtu_feedback(54, s[0].0.0, 1500, h, 1300).unwrap());
        }
    }
}

#[test]
fn sack_split_newly_sacked_release_and_rto_takeover() {
    for ipv4 in [true, false] {
        for iss in [0, u32::MAX - 3000] {
            let (mut a, _b, s) = flight(ipv4, iss, 4);
            let at = |k: usize, n: u32| s[k].0.wrapping_add(n);
            ack(&mut a, 50, s[0].0, Some((at(1, 200), at(1, 600))));
            assert_eq!(report(&mut a, 51, s[1], 1400, false).feedback, Unchanged);
            assert_eq!(pending(&a), [(s[1].0, at(1, 200)), (at(1, 600), s[1].1)]);
            // Newly SACKed pending bytes are delivered: they leave the set.
            ack(&mut a, 52, s[0].0, Some((s[1].0, at(1, 100))));
            let split = [(at(1, 100), at(1, 200)), (at(1, 600), s[1].1)];
            assert_eq!(pending(&a), split);
            // A repeated block and a SACK of unreported bytes change nothing.
            ack(&mut a, 53, s[0].0, Some((s[1].0, at(1, 100))));
            ack(&mut a, 53, s[0].0, Some((at(3, 0), at(3, 100))));
            assert_eq!(pending(&a), split);
            // Only bytes the scoreboard does not cover yet are release
            // candidates: a repeated block has none, a grown block only its
            // new edge, a covering block the hull of the holes it fills.
            let block = |l: Seq, r: Seq| [Some((l.0, r.0)), None, None, None];
            assert_eq!(a.ptb_sack_candidates(&block(s[1].0, at(1, 100))), [None; 4]);
            assert_eq!(
                a.ptb_sack_candidates(&block(s[1].0, at(1, 150)))[0],
                Some((at(1, 100), at(1, 150)))
            );
            assert_eq!(
                a.ptb_sack_candidates(&block(s[1].0, s[1].1))[0],
                Some((at(1, 100), s[1].1))
            );
            ack(&mut a, 53, s[0].0, Some((at(1, 150), at(1, 300))));
            assert_eq!(pending(&a), [(at(1, 100), at(1, 150)), (at(1, 600), s[1].1)]);
            ack(&mut a, 53, s[0].0, Some((s[1].0, s[1].1)));
            assert!(pending(&a).is_empty());
            assert_eq!(report(&mut a, 54, s[2], 1400, false).feedback, Unchanged);
            // RTO takes over the whole flight: work is discarded and the
            // reneged scoreboard does not resurrect it.
            rto(&mut a);
            assert!(pending(&a).is_empty());
            assert_eq!(a.ptb.rto_flight_end, Some(s[3].1));
            let t = a.now;
            for &quote in &s {
                assert_ne!(report(&mut a, t, quote, 1400, false).feedback, Rejected);
            }
            assert!(pending(&a).is_empty());
            // The timeout retransmission is recorded as a later copy.
            let retry = packet(&mut a, t);
            assert_eq!(span(&a, &retry).0, s[0].0);
            assert!(retransmitted(&a, s[0].0));
            assert!(!retransmitted(&a, s[1].0));
            // Partial cumulative progress inside that flight keeps it owned
            // by ordinary recovery.
            ack(&mut a, t + 1, s[1].1, None);
            assert_eq!(report(&mut a, t + 2, s[2], 1400, false).feedback, Unchanged);
            assert!(pending(&a).is_empty());
            // No SACK reports a hole: the rest of the timed-out flight is
            // resent in order under slow start before fresh data.
            let mut out = [0; 2048];
            for k in 2..4 {
                let len = a.transmit(t + 3, &mut out).unwrap().unwrap();
                assert_eq!(span(&a, &out[..len]), s[k]);
            }
            ack(&mut a, t + 4, s[2].1, None);
            // Bytes first sent after the RTO remain eligible.
            let fresh = (0..8).find_map(|n| {
                let mut out = [0; 2048];
                let len = a.transmit(t + 5 + n, &mut out).unwrap()?;
                let sent = span(&a, &out[..len]);
                (sent.0 == s[3].1).then_some(sent)
            });
            let fresh = fresh.expect("fresh data after the RTO");
            assert_eq!(
                report(&mut a, t + 20, fresh, 1400, false).feedback,
                Unchanged
            );
            assert_eq!(pending(&a), [(fresh.0, fresh.1)]);
            // Cumulative ACK past the old flight ends the takeover.
            ack(&mut a, t + 21, s[3].1, None);
            assert_eq!(a.ptb.rto_flight_end, None);
            assert_eq!(pending(&a), [(fresh.0, fresh.1)]);
        }
    }
}

#[test]
fn retransmitted_copies_are_never_eligible_and_history_survives_resize() {
    for ipv4 in [true, false] {
        for iss in [0, u32::MAX - 3000] {
            let (mut a, _b, s) = flight(ipv4, iss, 3);
            assert_eq!(
                report(&mut a, 50, s[0], 1400, true).feedback,
                Decreased { mtu: 1400 }
            );
            assert_eq!(pending(&a), [(s[0].0, s[0].1)]);
            // The Restart repair: a committed smaller copy of the head. Its
            // bytes leave the pending set for good.
            let bytes = packet(&mut a, 51);
            let copy = span(&a, &bytes);
            assert_eq!((copy.0, copy.2), (s[0].0, 1400));
            assert!(retransmitted(&a, s[0].0));
            assert_eq!(pending(&a), [(copy.1, s[0].1)]);
            // Reports about the repair copy or the original again add nothing.
            assert_ne!(report(&mut a, 52, copy, 1300, false).feedback, Rejected);
            assert_ne!(report(&mut a, 53, s[0], 1300, false).feedback, Rejected);
            assert_eq!(pending(&a), [(copy.1, s[0].1)]);
            // History and pending work move with the bytes on resize.
            let (send, receive) = a.buffer_capacities();
            a.set_buffer_capacities(send * 2, receive, usize::MAX)
                .unwrap();
            assert!(retransmitted(&a, s[0].0));
            assert_eq!(pending(&a), [(copy.1, s[0].1)]);
            assert_eq!(report(&mut a, 54, s[2], 1300, false).feedback, Unchanged);
            assert_eq!(pending(&a), [(copy.1, s[0].1), (s[2].0, s[2].1)]);
            // Abort abandons all work.
            a.abort();
            assert!(pending(&a).is_empty());
        }
    }
}

#[test]
fn reserved_copy_records_history_only_for_accepted_coverage() {
    for ipv4 in [true, false] {
        let (mut a, _b, s) = flight(ipv4, 0, 2);
        assert_eq!(
            report(&mut a, 50, s[0], 1400, true).feedback,
            Decreased { mtu: 1400 }
        );
        let mut out = [0; 2048];
        let n = a.transmit_selected(51, &mut out, true).unwrap().unwrap();
        let copy = span(&a, &out[..n]);
        assert_eq!(copy.0, s[0].0);
        // Selection alone is not submission.
        assert!(!retransmitted(&a, s[0].0));
        assert_eq!(pending(&a), [(s[0].0, s[0].1)]);
        let mut d = a.last_departure.unwrap();
        // Restart: a split repair ends at its first accepted fragment and
        // its unsubmitted suffix stays pending.
        assert!(a.accept_reserved_output(52, &mut d, 0, 500, false).unwrap());
        assert!(retransmitted(&a, s[0].0.wrapping_add(499)));
        assert!(!retransmitted(&a, s[0].0.wrapping_add(500)));
        assert_eq!(pending(&a), [(s[0].0.wrapping_add(500), s[0].1)]);
        assert!(a.ptb_segment(a.mss).is_none());
        // Useful progress (s[1] SACKed) ends Restart; a later split outside
        // it keeps the existing fragment acceptance.
        ack(&mut a, 54, s[0].0, Some((s[1].0, s[1].1)));
        let n = a.transmit_selected(55, &mut out, true).unwrap().unwrap();
        let copy = span(&a, &out[..n]);
        assert_eq!(copy.0, s[0].0.wrapping_add(500));
        let mut d = a.last_departure.unwrap();
        assert!(!a.accept_reserved_output(56, &mut d, 0, 300, false).unwrap());
        let rest = d.payload - 300;
        assert!(!a.accept_reserved_output(57, &mut d, 300, rest, true).unwrap());
        assert_eq!(copy.1, s[0].1);
        assert!(pending(&a).is_empty());
    }
}

// A reserved PTB repair charges PRR, RACK, the SACK pipe, the retransmitted
// edge and the RTO only for accepted coverage, at acceptance: a racing
// decrease that ends it in Restart leaves the suffix exactly as before.
#[test]
fn reserved_repair_charges_only_accepted_coverage_at_acceptance() {
    for ipv4 in [true, false] {
        for head in [true, false] {
            let (mut a, _b, s) = flight(ipv4, u32::MAX - 2000, 3);
            let target = if head { s[0] } else { s[1] };
            let deadline = a.rto_deadline;
            let original = a.rack.head_transmission(target.0).unwrap();
            let suffix = target.0.wrapping_add(400);
            let suffix_original = a.rack.head_transmission(suffix).unwrap();
            report(&mut a, 50, target, 1400, true);
            let mut out = [0; 2048];
            a.transmit_selected(51, &mut out, true).unwrap().unwrap();
            // Selection alone charges nothing per byte and restarts no timer.
            assert_eq!(a.rto_deadline, deadline);
            assert_eq!(a.rack.head_transmission(target.0).unwrap(), original);
            let mut d = a.last_departure.unwrap();
            assert!(a.accept_reserved_output(900, &mut d, 0, 400, false).unwrap());
            // RFC 6298: a head repair restarts the timer from its delayed
            // acceptance; a non-head repair never postpones the head's.
            if head {
                assert_eq!(a.rto_deadline, Some(900 + a.rto()));
            } else {
                assert_eq!(a.rto_deadline, deadline);
            }
            assert_eq!(a.rack.head_transmission(target.0).unwrap(), (suffix, 900));
            assert_eq!(a.rack.head_transmission(suffix).unwrap(), suffix_original);
            assert_eq!(pending(&a)[0], (suffix, target.1));
        }
    }
}

#[test]
fn data_and_fin_quote_marks_fin_until_acknowledged() {
    for ipv4 in [true, false] {
        let (mut a, _b) = super::pmtud_policy::family_pair(cfg(), ipv4, 7);
        let payload = if ipv4 { 1460 } else { 1440 };
        a.write(&vec![5; payload]).unwrap();
        a.shutdown().unwrap();
        let bytes = packet(&mut a, 40);
        let s = span(&a, &bytes);
        assert_eq!((s.1.distance_from(s.0), s.2), (payload as u32 + 1, 1500));
        assert_eq!(a.fin_sequence, Some(s.1.wrapping_add(u32::MAX)));
        let candidate = if ipv4 { 1006 } else { 1280 };
        assert_ne!(report(&mut a, 41, s, candidate, false).feedback, Rejected);
        assert!(a.ptb.fin_pending);
        let fin = a.fin_sequence.unwrap();
        // Data delivered, FIN still outstanding: only the FIN remains.
        ack(&mut a, 42, fin, None);
        assert!(pending(&a).is_empty() && a.ptb.fin_pending && !a.ptb_idle());
        ack(&mut a, 43, s.1, None);
        assert!(a.ptb_idle());
    }
}

// The local label only says whether this connection's estimate fell: the
// same legacy IPv4 report derives the same size and records the same
// dropped bytes whether it lowers the estimate (C) or finds it already
// lower (L, after another report lowered it).
#[test]
fn local_label_has_no_repair_or_derived_size_consequence() {
    let mut outcomes = Vec::new();
    for lowered in [false, true] {
        let mut config = cfg();
        config.pmtud.as_mut().unwrap().policy.ipv4_plateaus = crate::Ipv4Plateaus::RFC1191;
        let (mut a, _b) = super::pmtud_policy::family_pair(config, true, 9);
        a.write(&[1; 3 * 1460]).unwrap();
        let s: Vec<Span> = (0..2)
            .map(|k| {
                let bytes = packet(&mut a, 40 + k);
                span(&a, &bytes)
            })
            .collect();
        if lowered {
            assert_eq!(
                report(&mut a, 50, s[0], 576, true).feedback,
                Decreased { mtu: 576 }
            );
        }
        let outcome = report(&mut a, 51, s[1], 0, true);
        assert_eq!(outcome.derived_mtu, Some(1006));
        assert_eq!(
            outcome.feedback,
            if lowered {
                Unchanged
            } else {
                Decreased { mtu: 1006 }
            }
        );
        // L's earlier report also recorded its own packet.
        let first = if lowered { s[0].0 } else { s[1].0 };
        assert_eq!(pending(&a), [(first, s[1].1)]);
        outcomes.push(outcome.derived_mtu);
    }
    assert_eq!(outcomes[0], outcomes[1]);
}
