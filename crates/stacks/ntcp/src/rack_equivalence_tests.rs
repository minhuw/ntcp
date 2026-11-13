// Randomized operation sequences over Rack and the walk-based reference
// ledger (rack_reference.rs, which holds an interval per entry as master
// did): every result, every interval and every scalar must stay identical
// while the ledger is not constrained. Rack gets SPARE more entries than
// the reference, so it refuses a SACK split exactly where the reference
// would overflow; a seed is compared until the reference abandons its
// ledger. Operations follow the connection's use: fresh data only at the
// high edge, repairs inside the flight, selections resolved (or abandoned
// with an unsubmitted suffix) before input.
use super::reference::Reference;
use super::*;
use crate::connection::TimestampGranularity;
use alloc::{format, string::String, vec::Vec};
extern crate std;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

struct Pending {
    selection: DepartureSelection,
    start: Seq,
    end: Seq,
    offset: u32,
    retransmit: bool,
    undo: Option<(RetryUndo, RetryUndo)>,
}

struct Model {
    rack: Rack,
    reference: Reference,
    scoreboard: Scoreboard,
    rng: Rng,
    una: Seq,
    nxt: Seq,
    now: u64,
    mss: u32,
    timestamps: Option<TimestampGranularity>,
    pending: Option<Pending>,
    // Receiver-like ACKs: in order, SACK blocks reaching the high edge.
    orderly: bool,
    // SACK negotiated: otherwise the scoreboard stays empty.
    sack: bool,
    // Request/response: one selection at a time, committed whole and
    // mostly acknowledged whole, so the ledger holds an entry or two.
    exchange: bool,
    // The reference overflowed its ledger and abandoned it, where Rack,
    // with SPARE more entries, refuses a split instead.
    constrained: bool,
    trace: Vec<String>,
}

fn snapshot_rack(r: &Rack) -> String {
    format!(
        "{:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}",
        r.capacity - SPARE,
        r.selection_generation,
        r.departure_selection,
        r.sample_floor,
        r.fallback,
        r.latest,
        r.fack,
        r.min_rtt,
        r.min_rtt_buckets,
        r.rtt,
        r.reordering_seen,
        r.reordering,
        r.reordering_events,
        r.multiplier,
        r.persist,
        r.reo_grew,
        r.dsack_round,
        r.deadline,
        r.ack_sample,
        r.delivered_segments,
        r.delivered_segments_valid,
    )
}

fn snapshot_reference(r: &Reference) -> String {
    format!(
        "{:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}",
        r.capacity,
        r.selection_generation,
        r.departure_selection,
        r.sample_floor,
        r.fallback,
        r.latest,
        r.fack,
        r.min_rtt,
        r.min_rtt_buckets,
        r.rtt,
        r.reordering_seen,
        r.reordering,
        r.reordering_events,
        r.multiplier,
        r.persist,
        r.reo_grew,
        r.dsack_round,
        r.deadline,
        r.ack_sample,
        r.delivered_segments,
        r.delivered_segments_valid,
    )
}

impl Model {
    fn exchanging(seed: u64) -> Self {
        Self {
            exchange: true,
            ..Self::new(seed)
        }
    }

    fn new(seed: u64) -> Self {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let capacity = match rng.below(4) {
            0 => 8 + rng.below(24) as usize,
            1 => 64 + rng.below(64) as usize,
            _ => 4096,
        };
        let base = match rng.below(3) {
            0 => Seq(u32::MAX - rng.below(3000) as u32),
            1 => Seq(rng.next() as u32),
            _ => Seq(1000),
        };
        let mss = [1, 7, 100, 536][rng.below(4) as usize];
        let timestamps = match rng.below(3) {
            0 => None,
            1 => Some(TimestampGranularity::Milliseconds),
            _ => Some(TimestampGranularity::Microseconds),
        };
        let now = 1 + rng.below(1000);
        let orderly = rng.chance(50);
        let sack = rng.chance(85);
        let mut scoreboard = Scoreboard::with_capacity(capacity).unwrap();
        scoreboard.update(base, base, &[None; 4]);
        Self {
            rack: Rack::with_capacity(capacity + SPARE).unwrap(),
            reference: Reference::with_capacity(capacity).unwrap(),
            scoreboard,
            rng,
            una: base,
            nxt: base,
            now,
            mss,
            timestamps,
            pending: None,
            orderly,
            sack,
            exchange: false,
            constrained: false,
            trace: Vec::new(),
        }
    }

    fn note(&mut self, op: String) {
        self.trace.push(op);
    }

    fn context(&self) -> String {
        format!("{:?}", &self.trace[self.trace.len().saturating_sub(40)..])
    }

    fn check(&mut self) {
        assert_eq!(self.rack.split_refusals, 0, "{}", self.context());
        let a: Vec<Interval> = self.rack.intervals.iter().copied().collect();
        let b: Vec<Interval> = self.reference.intervals.iter().copied().collect();
        if a != b || snapshot_rack(&self.rack) != snapshot_reference(&self.reference) {
            panic!(
                "diverged after {}\nrack {a:?}\n{}\nreference {b:?}\n{}",
                self.context(),
                snapshot_rack(&self.rack),
                snapshot_reference(&self.reference)
            );
        }
        let mss = self.mss;
        let trace = self.context();
        let context = || trace.clone();
        let r = &mut self.rack;
        let o = &self.reference;
        assert_eq!(r.pipe(), o.pipe(), "{}", context());
        assert_eq!(
            format!("{:?}", r.packet_counts()),
            format!("{:?}", o.packet_counts()),
            "{}",
            context()
        );
        assert_eq!(
            format!("{:?}", r.diagnostic_packet_counts()),
            format!("{:?}", o.diagnostic_packet_counts()),
            "{}",
            context()
        );
        assert_eq!(
            format!("{:?}", r.counts()),
            format!("{:?}", o.counts()),
            "{}",
            context()
        );
        for m in [mss, mss + 1, 1, 536] {
            assert_eq!(
                r.has_short_transmission(m),
                o.has_short_transmission(m),
                "{}",
                context()
            );
            assert_eq!(r.lowest_lost(m), o.lowest_lost(m), "{}", context());
            assert_eq!(r.tail_segment(m), o.tail_segment(m), "{}", context());
        }
        assert_eq!(r.latest_delivered(), o.latest_delivered());
        assert_eq!(r.min_rtt(), o.min_rtt());
        assert_eq!(r.adaptation(), o.adaptation());
        assert_eq!(r.valid(), o.valid());
        assert_eq!(r.empty_valid(), o.empty_valid());
        assert_eq!(r.departure_selection(), o.departure_selection());
        let span = self.nxt.distance_from(self.una);
        for _ in 0..4 {
            let seq = self
                .una
                .wrapping_add(self.rng.below(u64::from(span) + 2) as u32)
                .wrapping_add(0u32.wrapping_sub(1));
            let end = seq.wrapping_add(1 + self.rng.below(2 * u64::from(mss)) as u32);
            let r = &mut self.rack;
            let o = &self.reference;
            assert_eq!(r.head_transmission(seq), o.head_transmission(seq));
            assert_eq!(
                r.original_retry_span(seq, end),
                o.original_retry_span(seq, end)
            );
            assert_eq!(
                format!("{:?}", r.retry_undo(seq, end)),
                format!("{:?}", o.retry_undo(seq, end))
            );
            assert_eq!(
                r.lost_ranges(seq, end).collect::<Vec<_>>(),
                o.lost_ranges(seq, end).collect::<Vec<_>>()
            );
        }
    }

    fn advance(&mut self) {
        if self.orderly {
            self.now += self.rng.below(300);
            return;
        }
        self.now += match self.rng.below(4) {
            0 => 0,
            1 => 1 + self.rng.below(10),
            2 => 1 + self.rng.below(2_000),
            _ => 1 + self.rng.below(200_000),
        };
    }

    // One interval edge of the flight, or any byte inside it.
    fn edge(&mut self) -> Seq {
        let span = self.nxt.distance_from(self.una);
        if span == 0 {
            return self.una;
        }
        let edges: Vec<Seq> = self.reference.intervals.iter().map(|r| r.end).collect();
        if !edges.is_empty() && self.rng.chance(75) {
            edges[self.rng.below(edges.len() as u64) as usize]
        } else {
            self.una
                .wrapping_add(self.rng.below(u64::from(span) + 1) as u32)
        }
    }

    fn fresh(&mut self) {
        let len = match self.rng.below(4) {
            0 => 1 + self.rng.below(u64::from(self.mss)) as u32,
            1 => self.mss,
            _ => 1 + self.rng.below(4 * u64::from(self.mss)) as u32,
        };
        let (start, end) = (self.nxt, self.nxt.wrapping_add(len));
        let now = self.now;
        self.note(format!("fresh {start:?}..{end:?} @{now}"));
        let valid = self.reference.valid();
        self.rack.transmit(start, end, now, false);
        self.reference.transmit(start, end, now, false);
        if valid && !self.reference.valid() {
            self.constrained = true;
            return;
        }
        let in_window = self.rng.chance(50);
        self.rack.commit_original_window(start, end, in_window);
        self.reference.commit_original_window(start, end, in_window);
        self.nxt = end;
        self.select(start, end, false, None);
    }

    fn select(
        &mut self,
        start: Seq,
        end: Seq,
        retransmit: bool,
        undo: Option<(RetryUndo, RetryUndo)>,
    ) {
        let selection = self.rack.departure_selection();
        assert_eq!(selection, self.reference.departure_selection());
        let Some(selection) = selection else {
            return;
        };
        if self.exchange || self.rng.chance(40) {
            // Scalar output: committed whole at once.
            if self.rng.chance(30) {
                self.advance();
            }
            let now = self.now;
            self.note(format!("commit whole @{now}"));
            assert_eq!(
                self.rack.commit_departure(selection, start, end, now),
                self.reference.commit_departure(selection, start, end, now)
            );
        } else {
            self.pending = Some(Pending {
                selection,
                start,
                end,
                offset: 0,
                retransmit,
                undo,
            });
        }
    }

    fn repair(&mut self) {
        if self.una == self.nxt {
            return;
        }
        let mss = self.mss;
        let (start, end) = match self.rng.below(4) {
            0 | 1 => match self.reference.lowest_lost(mss) {
                Some(range) => range,
                None => return,
            },
            2 => match self.reference.tail_segment(mss) {
                Some(range) => range,
                None => return,
            },
            _ => {
                let a = self.edge();
                let b = self.edge();
                let (a, b) = if b.after(a) { (a, b) } else { (b, a) };
                if a == b {
                    return;
                }
                (a, b)
            }
        };
        let undo = match (
            self.rack.retry_undo(start, end),
            self.reference.retry_undo(start, end),
        ) {
            (Some(a), Some(b)) => Some((a, b)),
            (None, None) => None,
            (a, b) => panic!("retry_undo {a:?} {b:?}"),
        };
        let probe = self.rng.chance(20);
        let now = self.now;
        self.note(format!("repair {start:?}..{end:?} probe={probe} @{now}"));
        let valid = self.reference.valid();
        self.rack.transmit(start, end, now, true);
        self.reference.transmit(start, end, now, true);
        if !probe {
            self.rack.commit_retry_span(start, end);
            self.reference.commit_retry_span(start, end);
        }
        if valid && !self.reference.valid() {
            self.constrained = true;
            return;
        }
        self.select(start, end, true, undo);
    }

    fn continue_pending(&mut self) {
        let Some(mut p) = self.pending.take() else {
            return;
        };
        let total = p.end.distance_from(p.start);
        let rest = total - p.offset;
        if self.rng.chance(20) {
            self.advance();
        }
        let now = self.now;
        let size = 1 + self.rng.below(u64::from(self.mss.min(rest).max(1))) as u32;
        let piece = rest.min(if self.rng.chance(50) { self.mss } else { size });
        let start = p.start.wrapping_add(p.offset);
        if self.rng.chance(25) {
            // A GSO group of whole segments from here.
            let segments = 1 + self.rng.below(4) as u32;
            let bytes = rest.min(segments * self.mss) as usize;
            let segment = self.mss;
            self.note(format!("group {start:?} +{bytes} by {segment} @{now}"));
            let valid = self
                .rack
                .validate_departure_group(p.selection, start, segment, bytes, now);
            let expected =
                self.reference
                    .validate_departure_group(p.selection, start, segment, bytes, now);
            if valid != expected && self.short_of_entries() {
                self.constrained = true;
                return;
            }
            assert_eq!(valid, expected);
            if valid && self.rng.chance(50) {
                // Accepted whole: what committing each segment in turn leaves,
                // dirty ranges and storage layout included.
                self.note(format!("commit group @{now}"));
                let mut whole = self.rack.grown(self.rack.capacity).unwrap();
                let mut each = self.rack.grown(self.rack.capacity).unwrap();
                for k in 0..bytes.div_ceil(segment as usize) {
                    let a = start.wrapping_add(k as u32 * segment);
                    let b = start.wrapping_add(((k + 1) * segment as usize).min(bytes) as u32);
                    each.commit_validated_departure(p.selection, a, b, now);
                    self.reference
                        .commit_validated_departure(p.selection, a, b, now);
                }
                whole.commit_validated_group(p.selection, start, segment, bytes, now);
                self.rack
                    .commit_validated_group(p.selection, start, segment, bytes, now);
                let (a, b) = (format!("{whole:?}"), format!("{each:?}"));
                assert_eq!(a, b, "{}", self.context());
                p.offset += bytes as u32;
                if p.offset < total {
                    self.pending = Some(p);
                }
                return;
            }
        }
        let end = start.wrapping_add(piece);
        self.note(format!("depart {start:?}..{end:?} @{now}"));
        let valid = self.rack.validate_departure(p.selection, start, end, now);
        let expected = self
            .reference
            .validate_departure(p.selection, start, end, now);
        if valid != expected && self.short_of_entries() {
            self.constrained = true;
            return;
        }
        assert_eq!(valid, expected);
        if valid {
            self.rack
                .commit_validated_departure(p.selection, start, end, now);
            self.reference
                .commit_validated_departure(p.selection, start, end, now);
            p.offset += piece;
        }
        if valid && p.offset < total && !self.rng.chance(10) {
            self.pending = Some(p);
        }
    }

    // Whether a departure's splits may need the entries Rack holds beyond
    // the reference's: a group splits at most at each of its edges.
    fn short_of_entries(&self) -> bool {
        self.reference.intervals.len() + 5 > self.reference.capacity
    }

    fn cancel(&mut self) {
        let Some(p) = self.pending.take() else {
            return;
        };
        if p.retransmit {
            if let Some((a, b)) = p.undo {
                self.note(format!("cancel retry {:?}", p.selection));
                assert_eq!(
                    self.rack.cancel_retry(p.selection, a),
                    self.reference.cancel_retry(p.selection, b)
                );
            }
        } else {
            self.note(format!("cancel fresh {:?}", p.selection));
            let cancelled = self.rack.cancel_unsubmitted_fresh(p.selection);
            assert_eq!(
                cancelled,
                self.reference.cancel_unsubmitted_fresh(p.selection)
            );
            if cancelled {
                self.nxt = p.start;
            }
        }
    }

    fn ack(&mut self) {
        let span = self.nxt.distance_from(self.una);
        let ack = if self.exchange && self.rng.chance(70) {
            // Everything sent, as a response acknowledges its request.
            self.nxt
        } else if self.rng.chance(40) || span == 0 {
            self.una
        } else {
            let edge = self.edge();
            if edge.after(self.una) { edge } else { self.una }
        };
        let mut blocks = [None; 4];
        let count = self.rng.below(5) as usize;
        if self.orderly {
            let a = self.edge();
            if a.after(ack) && self.nxt.after(a) {
                blocks[0] = Some((a.0, self.nxt.0));
            }
        }
        for slot in blocks
            .iter_mut()
            .take(count)
            .skip(usize::from(self.orderly))
        {
            let a = self.edge();
            let b = self.edge();
            let (a, b) = if b.after(a) { (a, b) } else { (b, a) };
            if a != b {
                *slot = Some((a.0, b.0));
            }
        }
        if self.rng.chance(5) && span != 0 {
            // A DSACK of the acknowledged prefix, or below it.
            let left = self
                .una
                .wrapping_add(0u32.wrapping_sub(1 + self.rng.below(50) as u32));
            blocks[0] = Some((left.0, ack.0));
        }
        let high = self.nxt;
        let now = self.now;
        let echo = match (self.timestamps, self.rng.below(3)) {
            (None, _) => None,
            (Some(_), 0) => None,
            (Some(g), _) => {
                // Echo some transmission's tick, often the latest one.
                let sent: Vec<u64> = self.reference.intervals.iter().map(|r| r.sent).collect();
                let pick = if sent.is_empty() {
                    now
                } else {
                    sent[self.rng.below(sent.len() as u64) as usize]
                };
                Some(g.tick_in(pick, CallerTimebase::default()) as u32)
            }
        };
        let sack = self.sack;
        self.note(format!(
            "ack {ack:?} sack={sack} {blocks:?} echo={echo:?} @{now}"
        ));
        let valid = self.reference.valid();
        if sack {
            let update = self.scoreboard.update(ack, high, &blocks);
            let mss = self.mss;
            let expected = self.reference.acknowledge(
                ack,
                high,
                &self.scoreboard,
                now,
                echo,
                self.timestamps,
                mss,
                update.dsack,
            );
            let got = self.rack.acknowledge(
                ack,
                high,
                &mut self.scoreboard,
                now,
                echo,
                self.timestamps,
                mss,
                update.dsack,
            );
            if valid && !self.reference.valid() {
                self.constrained = true;
                return;
            }
            assert_eq!(got, expected, "{}", self.context());
        } else {
            let mss = self.mss;
            let expected = self.reference.acknowledge(
                ack,
                high,
                &self.scoreboard,
                now,
                echo,
                self.timestamps,
                mss,
                false,
            );
            let got = self.rack.acknowledge(
                ack,
                high,
                &mut self.scoreboard,
                now,
                echo,
                self.timestamps,
                mss,
                false,
            );
            assert_eq!(got, expected, "{}", self.context());
        }
        self.rack.trim_cumulative(ack);
        self.reference.trim_cumulative(ack);
        self.una = ack;
    }

    fn step(&mut self) {
        if self.exchange && self.pending.is_none() && self.rng.chance(70) {
            if self.una == self.nxt || self.rng.chance(20) {
                self.fresh();
            } else {
                self.ack();
            }
            return;
        }
        let op = self.rng.below(100);
        let busy = self.pending.is_some();
        match op {
            0..=24 if !busy => self.fresh(),
            25..=34 if !busy => self.repair(),
            0..=44 if busy => self.continue_pending(),
            45..=47 => self.cancel(),
            48..=49 if busy => {
                // A partially accepted reservation leaves its suffix unsubmitted.
                self.note("drop pending".into());
                self.pending = None;
            }
            50..=69 if !busy => self.ack(),
            70..=77 if !busy => {
                let recovery = self.rng.chance(50);
                let srtt = (!self.rng.chance(10)).then(|| self.rng.below(100_000));
                let now = self.now;
                self.note(format!("detect @{now} recovery={recovery} srtt={srtt:?}"));
                assert_eq!(
                    self.rack.detect(now, recovery, srtt),
                    self.reference.detect(now, recovery, srtt)
                );
            }
            78 if !busy => {
                let srtt = (!self.rng.chance(10)).then(|| self.rng.below(100_000));
                let (now, una) = (self.now, self.una);
                self.note(format!("rto @{now}"));
                self.rack.rto(now, una, srtt);
                self.reference.rto(now, una, srtt);
                self.scoreboard.clear();
            }
            79..=80 if !busy => {
                self.note("mark head".into());
                self.rack.mark_head_lost();
                self.reference.mark_head_lost();
            }
            81..=82 if !busy => {
                let mss = self.mss;
                self.note("mark scoreboard".into());
                assert_eq!(
                    self.rack.mark_scoreboard_losses(&self.scoreboard, mss),
                    self.reference.mark_scoreboard_losses(&self.scoreboard, mss)
                );
            }
            83..=84 => {
                let rtt = self.rng.below(50_000);
                let now = self.now;
                self.note(format!("sample {rtt} @{now}"));
                self.rack.sample(rtt, now);
                self.reference.sample(rtt, now);
            }
            85 => {
                let grew = self.rng.chance(50);
                self.rack.recovery_exit(grew);
                self.reference.recovery_exit(grew);
            }
            86 if !busy => {
                let now = self.now;
                self.rack.discard_samples_before(now);
                self.reference.discard_samples_before(now);
            }
            87..=88 => {
                let a = self.edge();
                let b = self.edge();
                let (a, b) = if b.after(a) { (a, b) } else { (b, a) };
                if self.rng.chance(50) {
                    self.note(format!("fin payload {a:?}..{b:?}"));
                    assert_eq!(
                        self.rack.record_fin_payload(a, b),
                        self.reference.record_fin_payload(a, b)
                    );
                } else {
                    self.note(format!("syn payload {a:?}..{b:?}"));
                    self.rack.record_syn_payload(a, b);
                    self.reference.record_syn_payload(a, b);
                }
            }
            _ => self.advance(),
        }
    }
}

// Steps compared and seeds whose reference never overflowed, of 400
// seeds of 500 steps.
fn compare(model: impl Fn(u64) -> Model) -> (usize, usize) {
    let (mut compared, mut unconstrained) = (0, 0);
    for seed in 1..=400u64 {
        let mut model = model(seed);
        let mut whole = true;
        for _ in 0..500 {
            let outcome = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
                model.step();
                if model.constrained {
                    return false;
                }
                model.check();
                true
            }));
            match outcome {
                Ok(true) => compared += 1,
                Ok(false) => {
                    whole = false;
                    break;
                }
                Err(panic) => {
                    std::eprintln!("seed {seed}: {}", model.context());
                    std::panic::resume_unwind(panic);
                }
            }
        }
        unconstrained += usize::from(whole);
    }
    (compared, unconstrained)
}

#[test]
fn randomized_operations_match_the_walking_ledger() {
    let (compared, unconstrained) = compare(Model::new);
    // Most seeds (every 4096-entry one) never constrain the ledger: 342 of
    // 400 seeds and 181,351 of 200,000 steps when written.
    assert!(compared > 400 * 500 * 85 / 100, "{compared}");
    assert!(unconstrained > 300, "{unconstrained}");
}

#[test]
fn randomized_exchanges_match_the_walking_ledger() {
    let (compared, unconstrained) = compare(Model::exchanging);
    assert!(compared > 400 * 500 * 85 / 100, "{compared}");
    assert!(unconstrained > 300, "{unconstrained}");
}
