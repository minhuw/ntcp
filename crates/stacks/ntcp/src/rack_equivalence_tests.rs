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

#[test]
fn submitting_an_original_directly_matches_record_then_commit() {
    for generation in [0, u64::MAX - 2] {
        let mut recorded = Rack::with_timebase(16, CallerTimebase::default()).unwrap();
        let mut submitted = Rack::with_timebase(16, CallerTimebase::default()).unwrap();
        recorded.selection_generation = generation;
        submitted.selection_generation = generation;
        let mut start = Seq(u32::MAX - 1100);
        for i in 0..20 {
            if i == 3 {
                start = start.wrapping_add(1);
            }
            let end = start.wrapping_add(if i % 3 == 0 { 1200 } else { i + 1 });
            let now = u64::from(i.saturating_sub(u32::from(i == 6)));
            let in_window = i % 7 != 0;
            recorded.record_transmission(start, end, now, false, in_window);
            let whole = recorded.departure_selection().is_none_or(|selection| {
                recorded.commit_validated_departure(selection, start, end, now)
            });
            assert_eq!(
                submitted.record_submitted_original(start, end, now, in_window),
                whole
            );
            assert_eq!(format!("{submitted:?}"), format!("{recorded:?}"));
            start = end;
        }
    }
}

#[test]
fn fast_commit_record_and_remove_prefix_match_slow_path() {
    let mut fast_record_hits = 0usize;
    let mut fast_commit_hits = 0usize;
    let mut fast_remove_prefix_single = 0usize;
    let mut fast_remove_prefix_multi = 0usize;
    let mut fallback_hits = 0usize;
    let mut retransmit_hits = 0usize;
    let mut same_packet_boundary_hits = 0usize;

    for seed in 1..=100u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let cap = [6, 12, 32][rng.below(3) as usize];
        let mut fast = Rack::with_capacity(cap + SPARE).unwrap();
        let mut slow = Rack::with_capacity(cap + SPARE).unwrap();
        let mut reference = Reference::with_capacity(cap).unwrap();
        let mut sb_fast = Scoreboard::with_capacity(cap).unwrap();
        let mut sb_slow = Scoreboard::with_capacity(cap).unwrap();
        let mut sb_ref = Scoreboard::with_capacity(cap).unwrap();
        let base = if rng.chance(40) {
            Seq(u32::MAX - 2000)
        } else {
            Seq(1000)
        };
        sb_fast.update(base, base, &[None; 4]);
        sb_slow.update(base, base, &[None; 4]);
        sb_ref.update(base, base, &[None; 4]);
        let mss = [100, 536, 1200][rng.below(3) as usize];
        let mut una = base;
        let mut nxt = base;
        let mut now = 10u64;
        let mut ref_valid = true;

        for _ in 0..90 {
            if rng.chance(60) {
                now += rng.below(20);
            }
            match rng.below(100) {
                // Fresh original via record_submitted_original or record_transmission + commit_new_packet.
                0..=49 => {
                    let len = match rng.below(3) {
                        0 => 1 + rng.below(u64::from(mss)) as u32,
                        1 => mss,
                        _ => mss + 1 + rng.below(u64::from(mss)) as u32,
                    };
                    let (start, end) = (nxt, nxt.wrapping_add(len));
                    let in_window = rng.chance(50);
                    let use_direct = rng.chance(50);
                    if fast.fallback.is_some() {
                        fallback_hits += 1;
                    }
                    if use_direct {
                        if fast.fallback.is_none()
                            && fast.intervals.len() < fast.intervals.capacity()
                            && fast.intervals.originals == fast.intervals.len()
                        {
                            fast_record_hits += 1;
                        }
                        let got = fast.record_submitted_original(start, end, now, in_window);
                        slow.record_transmission(start, end, now, false, in_window);
                        let expected = slow.departure_selection().is_none_or(|sel| {
                            slow.commit_validated_departure(sel, start, end, now)
                        });
                        assert_eq!(got, expected, "seed {seed}: record_submitted_original bool");
                    } else {
                        fast.record_transmission(start, end, now, false, in_window);
                        slow.record_transmission(start, end, now, false, in_window);
                        if let Some(sel) = fast.departure_selection() {
                            if fast.intervals.originals + 1 == fast.intervals.len() {
                                fast_commit_hits += 1;
                            }
                            let got = fast.commit_new_packet(sel);
                            let expected = slow.commit_validated_departure(sel, start, end, now);
                            assert_eq!(got, expected, "seed {seed}: commit_new_packet bool");
                        }
                    }
                    if ref_valid {
                        reference.transmit(start, end, now, false);
                        reference.commit_original_window(start, end, in_window);
                        if !reference.valid() {
                            ref_valid = false;
                        } else if let Some(sel) = reference.departure_selection()
                            && !reference.commit_departure(sel, start, end, now)
                        {
                            ref_valid = false;
                        }
                    }
                    nxt = end;
                }
                // Partial departure of a fresh packet to create split intervals sharing the same packet.
                50..=59 => {
                    let len = 40 + rng.below(200) as u32;
                    let (start, end) = (nxt, nxt.wrapping_add(len));
                    let mid = start.wrapping_add(len / 2);
                    fast.record_transmission(start, end, now, false, true);
                    slow.record_transmission(start, end, now, false, true);
                    if let Some(sel) = fast.departure_selection() {
                        fast.commit_validated_departure(sel, start, mid, now);
                        slow.commit_validated_departure(sel, start, mid, now);
                        fast.commit_validated_departure(sel, mid, end, now + 1);
                        slow.commit_validated_departure(sel, mid, end, now + 1);
                    }
                    if ref_valid {
                        reference.transmit(start, end, now, false);
                        reference.commit_original_window(start, end, true);
                        if !reference.valid() {
                            ref_valid = false;
                        } else if let Some(sel) = reference.departure_selection()
                            && (!reference.commit_departure(sel, start, mid, now)
                                || !reference.commit_departure(sel, mid, end, now + 1))
                        {
                            ref_valid = false;
                        }
                    }
                    nxt = end;
                    now += 1;
                }
                // Retransmit an in-flight interval.
                60..=71 if nxt.after(una) => {
                    let span = nxt.distance_from(una);
                    let off = rng.below(u64::from(span)) as u32;
                    let len = 1 + rng.below(u64::from((span - off).min(mss))) as u32;
                    let start = una.wrapping_add(off);
                    let end = start.wrapping_add(len);
                    retransmit_hits += 1;
                    fast.transmit(start, end, now, true);
                    slow.transmit(start, end, now, true);
                    if let Some(sel) = fast.departure_selection() {
                        fast.commit_departure(sel, start, end, now);
                        slow.commit_departure(sel, start, end, now);
                    }
                    if ref_valid {
                        reference.transmit(start, end, now, true);
                        if !reference.valid() {
                            ref_valid = false;
                        } else if let Some(sel) = reference.departure_selection()
                            && !reference.commit_departure(sel, start, end, now)
                        {
                            ref_valid = false;
                        }
                    }
                }
                // Cumulative ACK (optionally with SACK blocks) driving remove_prefix.
                _ if nxt.after(una) => {
                    let edges: Vec<Seq> = fast.intervals.iter().map(|r| r.end).collect();
                    let ack = if !edges.is_empty() && rng.chance(70) {
                        edges[rng.below(edges.len() as u64) as usize]
                    } else if rng.chance(50) {
                        nxt
                    } else {
                        let span = nxt.distance_from(una);
                        una.wrapping_add(1 + rng.below(u64::from(span)) as u32)
                    };
                    let mut blocks = [None; 4];
                    if rng.chance(30) && nxt.after(ack) {
                        let rem = nxt.distance_from(ack);
                        let a = ack.wrapping_add(1 + rng.below(u64::from(rem)) as u32);
                        if nxt.after(a) {
                            let b = a.wrapping_add(
                                1 + rng.below(u64::from(nxt.distance_from(a))) as u32,
                            );
                            blocks[0] = Some((a.0, b.0));
                        }
                    }
                    // Track remove_prefix fast-path and same_packet(count - 1, count) boundary hits.
                    if fast.valid() && !fast.intervals.is_empty() {
                        let count = fast.locate(ack);
                        let len = fast.intervals.len();
                        if count > 0 && count < len {
                            if fast.same_packet(count - 1, count) {
                                same_packet_boundary_hits += 1;
                            } else if fast.intervals.originals >= count {
                                if count == 1 {
                                    fast_remove_prefix_single += 1;
                                } else {
                                    fast_remove_prefix_multi += 1;
                                }
                            }
                        }
                    }
                    let u_fast = sb_fast.update(ack, nxt, &blocks);
                    let u_slow = sb_slow.update(ack, nxt, &blocks);
                    let d_fast = fast.acknowledge(
                        ack,
                        nxt,
                        &mut sb_fast,
                        now,
                        None,
                        None,
                        mss,
                        u_fast.dsack,
                    );
                    let d_slow = slow.acknowledge(
                        ack,
                        nxt,
                        &mut sb_slow,
                        now,
                        None,
                        None,
                        mss,
                        u_slow.dsack,
                    );
                    assert_eq!(d_fast, d_slow, "seed {seed}: delivered mismatch");
                    fast.trim_cumulative(ack);
                    slow.trim_cumulative(ack);
                    if ref_valid {
                        let u_ref = sb_ref.update(ack, nxt, &blocks);
                        let d_ref = reference.acknowledge(
                            ack,
                            nxt,
                            &sb_ref,
                            now,
                            None,
                            None,
                            mss,
                            u_ref.dsack,
                        );
                        if !reference.valid() {
                            ref_valid = false;
                        } else {
                            assert_eq!(d_fast, d_ref, "seed {seed}: ref delivered mismatch");
                            reference.trim_cumulative(ack);
                        }
                    }
                    una = ack;
                }
                _ => {}
            }

            assert_eq!(
                format!("{fast:?}"),
                format!("{slow:?}"),
                "seed {seed}: fast vs slow Rack Debug mismatch"
            );
            assert_eq!(fast.pipe(), slow.pipe());
            assert_eq!(
                format!("{:?}", fast.packet_counts()),
                format!("{:?}", slow.packet_counts())
            );
            assert_eq!(
                format!("{:?}", fast.diagnostic_packet_counts()),
                format!("{:?}", slow.diagnostic_packet_counts())
            );
            if ref_valid && fast.split_refusals == 0 {
                let a: Vec<Interval> = fast.intervals.iter().copied().collect();
                let b: Vec<Interval> = reference.intervals.iter().copied().collect();
                assert_eq!(a, b, "seed {seed}: fast vs reference intervals mismatch");
                assert_eq!(
                    snapshot_rack(&fast),
                    snapshot_reference(&reference),
                    "seed {seed}: fast vs reference snapshot mismatch"
                );
                assert_eq!(fast.pipe(), reference.pipe());
                assert_eq!(
                    format!("{:?}", fast.packet_counts()),
                    format!("{:?}", reference.packet_counts())
                );
                assert_eq!(
                    format!("{:?}", fast.diagnostic_packet_counts()),
                    format!("{:?}", reference.diagnostic_packet_counts())
                );
            }
        }
    }

    // Explicit capacity-exhaustion test for record_submitted_original -> fallback.
    {
        let mut fast = Rack::with_capacity(4).unwrap();
        let mut slow = Rack::with_capacity(4).unwrap();
        for i in 0..6u32 {
            let start = Seq(100 + i * 100);
            let end = Seq(200 + i * 100);
            let got = fast.record_submitted_original(start, end, u64::from(i + 1), true);
            slow.record_transmission(start, end, u64::from(i + 1), false, true);
            let expected = slow.departure_selection().is_none_or(|sel| {
                slow.commit_validated_departure(sel, start, end, u64::from(i + 1))
            });
            assert_eq!(got, expected);
            assert_eq!(format!("{fast:?}"), format!("{slow:?}"));
        }
        assert!(!fast.valid());
        assert_eq!(fast.fallback, Some(Seq(700)));
    }

    assert!(fast_record_hits > 100, "{fast_record_hits}");
    assert!(fast_commit_hits > 100, "{fast_commit_hits}");
    assert!(
        fast_remove_prefix_single > 20,
        "{fast_remove_prefix_single}"
    );
    assert!(fast_remove_prefix_multi > 20, "{fast_remove_prefix_multi}");
    assert!(fallback_hits > 10, "{fallback_hits}");
    assert!(retransmit_hits > 100, "{retransmit_hits}");
    assert!(
        same_packet_boundary_hits > 10,
        "{same_packet_boundary_hits}"
    );
}

#[test]
fn in_order_ack_matches_general_acknowledge_across_loss_free_and_sack_mixed_runs() {
    let mut drained_fast_hits = 0usize;
    let mut partial_fast_hits = 0usize;
    let mut unchanged_hits = 0usize;
    let mut prefix_originals_fast_hits = 0usize;
    let mut drained_non_originals_hits = 0usize;
    let mut sack_then_in_order_hits = 0usize;

    for seed in 1..=160u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let sack_mixed = seed % 2 == 0;
        let cap = 64;
        let mut fast = Rack::with_capacity(cap + SPARE).unwrap();
        let mut general = Rack::with_capacity(cap + SPARE).unwrap();
        let mut reference = Reference::with_capacity(cap).unwrap();
        let mut sb_fast = Scoreboard::with_capacity(cap).unwrap();
        let mut sb_general = Scoreboard::with_capacity(cap).unwrap();
        let mut sb_ref = Scoreboard::with_capacity(cap).unwrap();

        let base = if rng.chance(40) {
            Seq(u32::MAX - 3000)
        } else {
            Seq(5000)
        };
        sb_fast.update(base, base, &[None; 4]);
        sb_general.update(base, base, &[None; 4]);
        sb_ref.update(base, base, &[None; 4]);

        let mss = [100, 536, 1200][rng.below(3) as usize];
        let mut una = base;
        let mut nxt = base;
        let mut now = 100u64;
        let mut saw_sack_this_seed = false;

        for _ in 0..120 {
            if rng.chance(70) {
                now += rng.below(50);
            }
            let op = rng.below(100);
            if op < 48 || (una == nxt && op < 80) {
                // Send a fresh original packet.
                if fast.intervals.len() + 8 < cap {
                    let len = 1 + rng.below(u64::from(mss)) as u32;
                    let (start, end) = (nxt, nxt.wrapping_add(len));
                    let in_window = rng.chance(50);
                    fast.record_submitted_original(start, end, now, in_window);
                    general.record_transmission(start, end, now, false, in_window);
                    if let Some(sel) = general.departure_selection() {
                        general.commit_validated_departure(sel, start, end, now);
                    }
                    reference.transmit(start, end, now, false);
                    reference.commit_original_window(start, end, in_window);
                    if let Some(sel) = reference.departure_selection() {
                        reference.commit_validated_departure(sel, start, end, now);
                    }
                    nxt = end;
                }
            } else if sack_mixed && op < 62 && nxt.after(una) && fast.intervals.len() + 8 < cap {
                // Retransmit an existing interval to mix non-originals with originals.
                let idx = rng.below(fast.intervals.len() as u64) as usize;
                let (start, end) = (fast.intervals[idx].start, fast.intervals[idx].end);
                fast.transmit(start, end, now, true);
                general.transmit(start, end, now, true);
                reference.transmit(start, end, now, true);
                if let Some(sel) = fast.departure_selection() {
                    fast.commit_departure(sel, start, end, now);
                    general.commit_departure(sel, start, end, now);
                    reference.commit_departure(sel, start, end, now);
                }
            } else {
                // Incoming ACK (either pure in-order or with SACK blocks in sack_mixed runs).
                let edges: Vec<Seq> = fast.intervals.iter().map(|r| r.end).collect();
                let ack = if edges.is_empty() || rng.chance(20) {
                    una
                } else if rng.chance(40) {
                    nxt
                } else {
                    edges[rng.below(edges.len() as u64) as usize]
                };
                let advancing = ack.after(una);
                let carries_data = rng.chance(50);
                let mut blocks = [None; 4];
                if sack_mixed && rng.chance(30) && nxt.after(ack) && fast.intervals.len() + 8 < cap
                {
                    let rem = nxt.distance_from(ack);
                    let a = ack.wrapping_add(1 + rng.below(u64::from(rem)) as u32);
                    if nxt.after(a) {
                        let b =
                            a.wrapping_add(1 + rng.below(u64::from(nxt.distance_from(a))) as u32);
                        blocks[0] = Some((a.0, b.0));
                        saw_sack_this_seed = true;
                    }
                }
                let has_sack_blocks = blocks.iter().any(Option::is_some);

                let u_gen = sb_general.update(ack, nxt, &blocks);
                let d_gen = general.acknowledge(
                    ack,
                    nxt,
                    &mut sb_general,
                    now,
                    None,
                    None,
                    mss,
                    u_gen.dsack,
                );
                general.trim_cumulative(ack);

                let u_ref = sb_ref.update(ack, nxt, &blocks);
                let d_ref =
                    reference.acknowledge(ack, nxt, &sb_ref, now, None, None, mss, u_ref.dsack);
                reference.trim_cumulative(ack);

                if sb_fast.is_empty() && !has_sack_blocks {
                    if let Some(count) = fast.in_order_ack(una, ack, nxt, advancing, carries_data) {
                        if saw_sack_this_seed {
                            sack_then_in_order_hits += 1;
                        }
                        sb_fast.acknowledge_empty(ack);
                        let d_fast = if advancing {
                            if ack == nxt {
                                drained_fast_hits += 1;
                                if count > fast.intervals.originals {
                                    drained_non_originals_hits += 1;
                                }
                            } else {
                                partial_fast_hits += 1;
                            }
                            if count > 0 && count <= fast.intervals.originals {
                                prefix_originals_fast_hits += 1;
                            }
                            fast.acknowledge_in_order(
                                count,
                                ack,
                                nxt,
                                &mut sb_fast,
                                now,
                                None,
                                None,
                                mss,
                                false,
                            )
                        } else {
                            assert_eq!(count, 0);
                            unchanged_hits += 1;
                            fast.acknowledge_unchanged(ack, &mut sb_fast);
                            0
                        };
                        assert_eq!(d_fast, d_gen, "seed {seed}: in_order vs general delivered");
                        assert_eq!(d_fast, d_ref, "seed {seed}: in_order vs ref delivered");

                        // Invariant I5: in_order_ack implies no RACK loss candidate and no deadline.
                        for recovery in [false, true] {
                            let mut probe = fast.grown(fast.capacity).unwrap();
                            let before = format!("{probe:?}");
                            let retx_lost = probe.detect(now + 1_000_000, recovery, Some(100));
                            assert!(
                                !retx_lost,
                                "seed {seed}: unexpected retx loss after in_order_ack"
                            );
                            assert_eq!(probe.deadline, None, "seed {seed}: unexpected deadline");
                            assert_eq!(
                                format!("{probe:?}"),
                                before,
                                "seed {seed}: detect mutated intervals"
                            );
                        }
                    } else {
                        let u_fast = sb_fast.update(ack, nxt, &blocks);
                        let d_fast = fast.acknowledge(
                            ack,
                            nxt,
                            &mut sb_fast,
                            now,
                            None,
                            None,
                            mss,
                            u_fast.dsack,
                        );
                        fast.trim_cumulative(ack);
                        assert_eq!(d_fast, d_gen);
                        assert_eq!(d_fast, d_ref);
                    }
                } else {
                    let u_fast = sb_fast.update(ack, nxt, &blocks);
                    let d_fast = fast.acknowledge(
                        ack,
                        nxt,
                        &mut sb_fast,
                        now,
                        None,
                        None,
                        mss,
                        u_fast.dsack,
                    );
                    fast.trim_cumulative(ack);
                    assert_eq!(d_fast, d_gen);
                    assert_eq!(d_fast, d_ref);
                }

                una = ack;
            }

            assert_eq!(
                format!("{fast:?}"),
                format!("{general:?}"),
                "seed {seed}: fast vs general Rack mismatch"
            );
            assert_eq!(sb_fast.ranges(), sb_general.ranges());
            let a: Vec<Interval> = fast.intervals.iter().copied().collect();
            let b: Vec<Interval> = reference.intervals.iter().copied().collect();
            assert_eq!(a, b, "seed {seed}: fast vs reference intervals");
            assert_eq!(
                snapshot_rack(&fast),
                snapshot_reference(&reference),
                "seed {seed}: fast vs reference snapshot"
            );
        }
    }

    assert!(drained_fast_hits > 200, "{drained_fast_hits}");
    assert!(partial_fast_hits > 200, "{partial_fast_hits}");
    assert!(unchanged_hits > 100, "{unchanged_hits}");
    assert!(
        prefix_originals_fast_hits > 200,
        "{prefix_originals_fast_hits}"
    );
    assert!(
        drained_non_originals_hits > 20,
        "{drained_non_originals_hits}"
    );
    assert!(sack_then_in_order_hits > 100, "{sack_then_in_order_hits}");
}

#[test]
fn in_order_prefix_latest_boundary_conditions() {
    for base in [Seq(1000), Seq(u32::MAX - 250)] {
        let p0 = (base, base.wrapping_add(100));
        let p1 = (p0.1, p0.1.wrapping_add(100));
        let p2 = (p1.1, p1.1.wrapping_add(100));
        let mut r = Rack::with_capacity(16).unwrap();
        assert!(r.record_submitted_original(p0.0, p0.1, 10, true));
        assert!(r.record_submitted_original(p1.0, p1.1, 20, true));
        assert!(r.record_submitted_original(p2.0, p2.1, 20, true));

        // Partial ACK retiring p0, leaving next = p1 (sent=20, end=p1.1), tail = p2 (sent=20, end=p2.1).
        r.latest = None;
        assert_eq!(r.in_order_ack(p0.0, p1.0, p2.1, true, false), Some(1));

        // latest.sent < next.sent: always safe regardless of latest.end.
        r.latest = Some((19, p2.1.wrapping_add(500)));
        assert_eq!(r.in_order_ack(p0.0, p1.0, p2.1, true, false), Some(1));

        // latest.sent > next.sent: p1 would be a RACK loss candidate -> must reject.
        r.latest = Some((21, p0.1));
        assert_eq!(r.in_order_ack(p0.0, p1.0, p2.1, true, false), None);

        // Equal sent (20), edge < next.end: safe.
        r.latest = Some((20, p0.1));
        assert_eq!(r.in_order_ack(p0.0, p1.0, p2.1, true, false), Some(1));

        // Equal sent (20), equal ends (edge == next.end): safe (sent_after is strict).
        r.latest = Some((20, p1.1));
        assert_eq!(r.in_order_ack(p0.0, p1.0, p2.1, true, false), Some(1));
        let mut probe = r.grown(r.capacity).unwrap();
        let mut sb = Scoreboard::new();
        sb.acknowledge_empty(p1.0);
        probe.acknowledge_in_order(1, p1.0, p2.1, &mut sb, 30, None, None, 100, false);
        assert!(!probe.detect(1_000_000, false, Some(10)));
        assert_eq!(probe.deadline, None);

        // Equal sent (20), edge > next.end (e.g. edge == p2.1): sent_after((20, p2.1), (20, p1.1)) is true -> must reject!
        r.latest = Some((20, p2.1));
        assert_eq!(r.in_order_ack(p0.0, p1.0, p2.1, true, false), None);

        // Non-advancing ACK at low: accepted only when carrying data (and respecting latest).
        r.latest = Some((10, p0.1));
        assert_eq!(r.in_order_ack(p0.0, p0.0, p2.1, false, false), None);
        assert_eq!(r.in_order_ack(p0.0, p0.0, p2.1, false, true), Some(0));
        r.latest = Some((10, p1.1));
        assert_eq!(r.in_order_ack(p0.0, p0.0, p2.1, false, true), None);

        // Unaligned ACK inside p1 rejects in_order_prefix.
        r.latest = None;
        assert_eq!(
            r.in_order_ack(p0.0, p1.0.wrapping_add(1), p2.1, true, false),
            None
        );
    }
}

#[test]
fn sample_rtt_bucket_early_return_matches_window_min_with_epoch_rollover() {
    let mut early_returns = 0usize;
    let mut epoch_rollovers = 0usize;

    for latest_present in [false, true] {
        let mut fast = Rack::with_capacity(16).unwrap();
        let mut reference = Reference::with_capacity(16).unwrap();
        if latest_present {
            fast.latest = Some((10, Seq(100)));
            reference.latest = Some((10, Seq(100)));
            fast.rtt = 777;
            reference.rtt = 777;
        }
        let mut rng = Rng(if latest_present {
            0xCAFE_BABE
        } else {
            0xDEAD_BEEF
        });
        let mut now = 0u64;
        let mut last_epoch = 0u64;

        for step in 0..500 {
            // Mix same-epoch samples, 1..6 epoch jumps (rollover past 4 buckets),
            // and occasional backward/stale-epoch timestamps.
            match step % 15 {
                0 => {
                    let jump = 1 + rng.below(6);
                    now = now.saturating_add(jump * MIN_RTT_BUCKET);
                }
                7 if now >= 2 * MIN_RTT_BUCKET => {
                    // Temporarily sample an older epoch without advancing `now` permanently.
                    let stale_now = now - MIN_RTT_BUCKET;
                    let rtt = 100 + rng.below(50_000);
                    fast.sample(rtt, stale_now);
                    reference.sample(rtt, stale_now);
                    assert_eq!(fast.min_rtt, reference.min_rtt, "step {step} stale");
                    assert_eq!(
                        fast.min_rtt_buckets, reference.min_rtt_buckets,
                        "step {step} stale"
                    );
                    assert_eq!(fast.rtt, reference.rtt, "step {step} stale rtt");
                    continue;
                }
                _ => {
                    now = now.saturating_add(rng.below(MIN_RTT_BUCKET / 4));
                }
            }
            let epoch = fast.timebase.us_from_ticks(now) / MIN_RTT_BUCKET;
            if epoch > last_epoch {
                epoch_rollovers += 1;
                last_epoch = epoch;
            }
            // Bias toward slower RTTs in the same epoch to hit the early return often.
            let rtt = match rng.below(4) {
                0 => 50 + rng.below(500),
                1 => 500 + rng.below(5_000),
                _ => 5_000 + rng.below(50_000),
            };
            let bucket = fast.min_rtt_buckets[(epoch % 4) as usize];
            if let Some((time, best)) = bucket
                && time == epoch
                && rtt >= best
                && epoch == fast.min_rtt_epoch
            {
                early_returns += 1;
            }

            fast.sample(rtt, now);
            reference.sample(rtt, now);

            assert_eq!(fast.min_rtt, reference.min_rtt, "step {step}");
            assert_eq!(
                fast.min_rtt_buckets, reference.min_rtt_buckets,
                "step {step}"
            );
            assert_eq!(
                fast.rtt, reference.rtt,
                "step {step} latest={latest_present}"
            );
        }
    }

    // Also verify trim_cumulative is a clean no-op when ack <= first.start.
    {
        let mut r = Rack::with_capacity(16).unwrap();
        r.record_submitted_original(Seq(200), Seq(300), 10, true);
        let before = format!("{r:?}");
        r.trim_cumulative(Seq(150));
        r.trim_cumulative(Seq(200));
        assert_eq!(format!("{r:?}"), before);
    }

    assert!(
        early_returns > 200,
        "early return rarely hit: {early_returns}"
    );
    assert!(
        epoch_rollovers > 40,
        "epoch rollovers rarely hit: {epoch_rollovers}"
    );
}
