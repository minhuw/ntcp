// The receive queue's differential harness: one operation trait, the
// per-byte ring of b0d2988 (receive_reference) as the oracle, and random
// operation sequences whose every observable is compared after each step.
// RxQueue runs it (rx_queue.rs tests); until stage 1 C3 the receive ring
// did too.
//
// Payload bytes are a function of their stream offset, except in a quarter
// of the arrivals, whose bytes are random: a byte held twice must keep its
// first copy, as the oracle does. A queue's limit is the oracle's right
// edge, passed to every insertion; the oracle's growth raises it.
extern crate std;

use super::receive_reference::{ReceiveOutputUndo, ReferenceReceiveBuffer as Reference};
use crate::{rx_queue::ReceiveOutcome, seq::Seq};
use alloc::vec::Vec;
use ntcp_buffer::RxFrame;

// Everything a queue answers outside the per-offset queries.
#[derive(Debug, PartialEq)]
pub(crate) struct Snapshot {
    pub next: Seq,
    pub readable: usize,
    pub eof: bool,
    pub has_data: bool,
    pub out_of_order_end: Option<Seq>,
    pub has_sack_blocks: bool,
    pub dsack_pending: bool,
    pub has_pending_report: bool,
    pub read_base: Seq,
    pub occupied: usize,
    pub fin_sequence: Option<Seq>,
    pub latest: Option<Seq>,
    pub reported: [Option<Seq>; 4],
    pub report_debt: usize,
    pub pending_first: Option<Seq>,
    pub dsack: Option<(Seq, Seq)>,
    pub pushed: bool,
    // Bytes, FIN and PUSH of the SYN prefix not yet admitted.
    pub deferred_syn: Option<(usize, bool, bool)>,
}

pub(crate) trait ReceiveQueue {
    type Undo;
    fn create(start: Seq, capacity: usize) -> Self;
    fn defer_syn(&mut self, frame: RxFrame, fin: bool, push: bool);
    fn promote_syn(&mut self) -> Option<usize>;
    // Takes `frame`, whose bytes are the stream from `sequence`, within the
    // right edge `limit`.
    fn insert(
        &mut self,
        sequence: Seq,
        frame: RxFrame,
        fin: bool,
        push: bool,
        limit: Seq,
        accepted: &mut dyn FnMut(usize, usize),
    ) -> ReceiveOutcome;
    fn record_duplicate(&mut self, sequence: Seq, len: usize);
    fn read(&mut self, out: &mut [u8]) -> usize;
    fn peek(&self, out: &mut [u8]) -> usize;
    fn sack_blocks(&self, max_blocks: usize) -> [Option<(u32, u32)>; 4];
    fn output_undo(&self) -> Self::Undo;
    fn commit_sack(&mut self, first: (u32, u32));
    fn commit_report(&mut self);
    fn restore_output(&mut self, undo: Self::Undo);
    fn take_push(&mut self) -> bool;
    fn clear(&mut self);
    fn reset_start(&mut self, start: Seq) -> Result<(), ()>;
    fn clear_dsack(&mut self);
    // The oracle's ring growth. A queue without a ring takes the larger
    // limit at its next insertion.
    fn grow(&mut self, capacity: usize) -> Result<(), ()>;
    fn snapshot(&self) -> Snapshot;
    // The byte held at `seq`, in order or beyond a gap.
    fn byte_at(&self, seq: Seq) -> Option<u8>;
    fn pending(&self, seq: Seq) -> bool;
    fn block_at(&self, seq: Seq) -> Option<(Seq, Seq)>;
    // The runs held beyond the in-order data, in order, each with whether
    // a PUSH mark lies in it.
    fn runs(&self) -> Vec<(Seq, Seq, bool)>;
    // The implementation's own invariants (accounting recounts).
    fn check(&self) {}
}

// Runs and per-byte state of a ring: `present(offset)`, `push(offset)` for
// offsets past the contiguous prefix.
fn ring_runs(
    read_base: Seq,
    contiguous: usize,
    capacity: usize,
    find: impl Fn(usize, bool) -> usize,
    push: impl Fn(usize) -> bool,
) -> Vec<(Seq, Seq, bool)> {
    let mut runs = Vec::new();
    let mut offset = contiguous;
    loop {
        let left = find(offset, true).max(contiguous);
        if left >= capacity {
            return runs;
        }
        let right = find(left, false);
        runs.push((
            read_base.wrapping_add(left as u32),
            read_base.wrapping_add(right as u32),
            (left..right).any(&push),
        ));
        offset = right;
    }
}

impl ReceiveQueue for Reference {
    type Undo = ReceiveOutputUndo;
    fn create(start: Seq, capacity: usize) -> Self {
        Self::new(start, capacity).unwrap()
    }
    fn defer_syn(&mut self, frame: RxFrame, fin: bool, push: bool) {
        Reference::defer_syn(self, &frame, fin, push)
    }
    fn promote_syn(&mut self) -> Option<usize> {
        Reference::promote_syn(self)
    }
    fn insert(
        &mut self,
        sequence: Seq,
        frame: RxFrame,
        fin: bool,
        push: bool,
        limit: Seq,
        accepted: &mut dyn FnMut(usize, usize),
    ) -> ReceiveOutcome {
        assert_eq!(limit, self.right_edge());
        self.insert_observed(sequence, &frame, fin, push, accepted)
    }
    fn record_duplicate(&mut self, sequence: Seq, len: usize) {
        Reference::record_duplicate(self, sequence, len)
    }
    fn read(&mut self, out: &mut [u8]) -> usize {
        Reference::read(self, out)
    }
    fn peek(&self, out: &mut [u8]) -> usize {
        Reference::peek(self, out)
    }
    fn sack_blocks(&self, max_blocks: usize) -> [Option<(u32, u32)>; 4] {
        Reference::sack_blocks(self, max_blocks)
    }
    fn output_undo(&self) -> ReceiveOutputUndo {
        Reference::output_undo(self)
    }
    fn commit_sack(&mut self, first: (u32, u32)) {
        Reference::commit_sack(self, first)
    }
    fn commit_report(&mut self) {
        Reference::commit_report(self)
    }
    fn restore_output(&mut self, undo: ReceiveOutputUndo) {
        Reference::restore_output(self, undo)
    }
    fn take_push(&mut self) -> bool {
        Reference::take_push(self)
    }
    fn clear(&mut self) {
        Reference::clear(self)
    }
    fn reset_start(&mut self, start: Seq) -> Result<(), ()> {
        Reference::reset_start(self, start)
    }
    fn clear_dsack(&mut self) {
        Reference::clear_dsack(self)
    }
    fn grow(&mut self, capacity: usize) -> Result<(), ()> {
        Reference::grow(self, capacity)
    }
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            next: self.next(),
            readable: self.readable(),
            eof: self.eof(),
            has_data: self.has_data(),
            out_of_order_end: self.out_of_order_end(),
            has_sack_blocks: self.has_sack_blocks(),
            dsack_pending: self.dsack_pending(),
            has_pending_report: self.has_pending_report(),
            read_base: self.read_base,
            occupied: self.occupied,
            fin_sequence: self.fin_sequence,
            latest: self.latest,
            reported: self.reported,
            report_debt: self.report_debt,
            pending_first: self.pending_first,
            dsack: self.dsack,
            pushed: self.pushed,
            deferred_syn: self.deferred_syn,
        }
    }
    fn byte_at(&self, seq: Seq) -> Option<u8> {
        let offset = seq.distance_from(self.read_base) as usize;
        if offset >= self.capacity() {
            return None;
        }
        let index = self.index(offset);
        // Presence implies an initialized byte.
        self.is_present(index)
            .then(|| unsafe { self.data[index].assume_init() })
    }
    fn pending(&self, seq: Seq) -> bool {
        Reference::pending(self, seq)
    }
    fn block_at(&self, seq: Seq) -> Option<(Seq, Seq)> {
        Reference::block_at(self, seq)
    }
    fn runs(&self) -> Vec<(Seq, Seq, bool)> {
        ring_runs(
            self.read_base,
            self.contiguous_len,
            self.capacity(),
            |offset, present| self.find_presence(offset, present),
            |offset| self.is_push(self.index(offset)),
        )
    }
}

pub(crate) struct Rng(u32);

impl Rng {
    pub(crate) fn new(seed: u32) -> Self {
        Self(seed | 1)
    }
    pub(crate) fn below(&mut self, bound: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 5;
        self.0 as usize % bound.max(1)
    }
}

// The byte at stream offset `offset` of stream `epoch`.
pub(crate) fn stream_byte(epoch: u32, offset: i64) -> u8 {
    let x = (offset as u64 ^ (u64::from(epoch) << 40)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    (x >> 56) as u8 ^ (x >> 23) as u8
}

// A heap frame holding `bytes`, with `spare` bytes of capacity beyond them.
pub(crate) fn heap_frame(bytes: &[u8], spare: usize) -> RxFrame {
    let mut vec = Vec::with_capacity(bytes.len() + spare);
    vec.extend_from_slice(bytes);
    RxFrame::from_vec(vec)
}

pub(crate) fn same<Q: ReceiveQueue>(q: &Q, r: &Reference) {
    assert_eq!(q.snapshot(), ReceiveQueue::snapshot(r));
    for limit in 0..=5 {
        assert_eq!(
            ReceiveQueue::sack_blocks(q, limit),
            r.sack_blocks(limit),
            "{limit}"
        );
    }
    assert_eq!(q.runs(), ReceiveQueue::runs(r));
    // Every offset of the window, and one past it.
    for offset in 0..=r.capacity() {
        let seq = r.read_base.wrapping_add(offset as u32);
        assert_eq!(q.byte_at(seq), ReceiveQueue::byte_at(r, seq), "{offset}");
        assert_eq!(q.pending(seq), ReceiveQueue::pending(r, seq), "{offset}");
        assert_eq!(q.block_at(seq), ReceiveQueue::block_at(r, seq), "{offset}");
    }
    q.check();
}

// What a run exercised: steps, steps whose insertion took held bytes into
// the in-order data, and insertions that met held data on both sides.
#[derive(Debug, Default)]
pub(crate) struct Coverage {
    pub steps: usize,
    pub absorbed: usize,
    pub spanning: usize,
    pub out_of_order: usize,
    pub wrapped: usize,
}

// `rounds` rounds of `steps` random operations each on a fresh queue `Q`
// and the oracle, compared after every step.
pub(crate) fn run<Q: ReceiveQueue>(rounds: usize, steps: usize, seed: u32) -> Coverage {
    let mut rng = Rng::new(seed);
    let mut coverage = Coverage::default();
    for round in 0..rounds {
        let capacity = 1 + rng.below(if round % 4 == 0 { 5000 } else { 600 });
        // A quarter of the rounds start just below the wrap.
        let start = if round % 4 == 1 {
            Seq(u32::MAX - rng.below(2 * capacity) as u32)
        } else {
            Seq(rng.below(1 << 31) as u32 * 2 + rng.below(2) as u32)
        };
        let mut q = Q::create(start, capacity);
        let mut r = Reference::new(start, capacity).unwrap();
        // The stream offset of r.read_base, and the stream's identity,
        // which a clear changes.
        let mut base = 0i64;
        let mut epoch = round as u32 * 1000;
        let bytes = |epoch: u32, base: i64, r: &Reference, sequence: Seq, len: usize| {
            let at = base + i64::from(sequence.distance_from(r.read_base) as i32);
            (0..len)
                .map(|i| stream_byte(epoch, at + i as i64))
                .collect::<Vec<u8>>()
        };
        // The next end of a run of arrivals in reverse order.
        let mut descending: Option<Seq> = None;
        if rng.below(3) == 0 {
            let len = rng.below(capacity.min(64) + 1).min(capacity - 1);
            let payload = bytes(epoch, base, &r, start, len);
            let (fin, push) = (rng.below(4) == 0, rng.below(2) == 0);
            let spare = rng.below(3) * rng.below(64);
            q.defer_syn(heap_frame(&payload, spare), fin, push);
            r.defer_syn(&payload, fin, push);
            same(&q, &r);
            assert_eq!(q.promote_syn(), r.promote_syn());
        }
        same(&q, &r);
        for _ in 0..steps {
            coverage.steps += 1;
            let capacity = r.capacity();
            let next = r.next();
            let runs = ReceiveQueue::runs(&r);
            match rng.below(16) {
                0..=6 => {
                    let mut fin = rng.below(10) == 0;
                    let (sequence, len) = match rng.below(10) {
                        // Near the frontier, beyond it, or a duplicate.
                        0..=3 => {
                            let distance = match rng.below(4) {
                                0 => 0,
                                1 => rng.below(capacity + 40),
                                _ => rng.below(64),
                            } as i64
                                - if rng.below(5) == 0 {
                                    rng.below(40) as i64
                                } else {
                                    0
                                };
                            (
                                next.wrapping_add(distance as u32),
                                rng.below(capacity.min(300) + 1),
                            )
                        }
                        // One byte in every other position.
                        4 => (
                            next.wrapping_add(1 + 2 * rng.below(capacity.min(64)) as u32),
                            1,
                        ),
                        // Arrivals in reverse order, each ending where the
                        // previous one began.
                        5 => {
                            let end =
                                descending.filter(|end| end.after(next)).unwrap_or_else(|| {
                                    next.wrapping_add(1 + rng.below(capacity) as u32)
                                });
                            let len = (1 + rng.below(16)).min(end.distance_from(next) as usize);
                            let sequence = end.wrapping_add((len as u32).wrapping_neg());
                            descending = Some(sequence);
                            (sequence, len)
                        }
                        // From before one held run to past a later one.
                        6 if !runs.is_empty() => {
                            let first = rng.below(runs.len());
                            let last = first + rng.below(runs.len() - first);
                            let sequence = runs[first]
                                .0
                                .wrapping_add((rng.below(4) as u32).wrapping_neg());
                            let end = runs[last].1.wrapping_add(rng.below(4) as u32);
                            (sequence, end.distance_from(sequence) as usize)
                        }
                        // Starting or ending inside a held run.
                        7 if !runs.is_empty() => {
                            let (left, right, _) = runs[rng.below(runs.len())];
                            let inside = left
                                .wrapping_add(rng.below(right.distance_from(left) as usize) as u32);
                            let len = 1 + rng.below(40);
                            if rng.below(2) == 0 {
                                (inside, len)
                            } else {
                                let sequence = inside.wrapping_add((len as u32).wrapping_neg());
                                (sequence, len)
                            }
                        }
                        // A FIN before held text.
                        8 if !runs.is_empty() => {
                            fin = true;
                            let gap = runs[0].0.distance_from(next) as usize;
                            let len = rng.below(gap);
                            (next.wrapping_add(rng.below(gap - len) as u32), len)
                        }
                        // In order.
                        _ => (next, rng.below(capacity.min(300) + 1)),
                    };
                    let payload = if rng.below(4) == 0 {
                        (0..len).map(|_| rng.below(256) as u8).collect()
                    } else {
                        bytes(epoch, base, &r, sequence, len)
                    };
                    let push = rng.below(3) == 0;
                    if rng.below(2) == 0 {
                        q.record_duplicate(sequence, len);
                        r.record_duplicate(sequence, len);
                    }
                    let spare = if rng.below(3) == 0 {
                        rng.below(2304)
                    } else {
                        0
                    };
                    let before = r.readable();
                    let held = runs.len();
                    let (mut a, mut b) = (Vec::new(), Vec::new());
                    let limit = r.right_edge();
                    let x = q.insert(
                        sequence,
                        heap_frame(&payload, spare),
                        fin,
                        push,
                        limit,
                        &mut |s, e| a.push((s, e)),
                    );
                    let y = r.insert_observed(sequence, &payload, fin, push, |s, e| b.push((s, e)));
                    assert_eq!(
                        (
                            x.new_bytes,
                            x.sack_overflow,
                            x.advanced,
                            x.fin,
                            x.out_of_order
                        ),
                        (
                            y.new_bytes,
                            y.sack_overflow,
                            y.advanced,
                            y.fin,
                            y.out_of_order
                        ),
                        "{sequence:?}+{len}"
                    );
                    assert_eq!(a, b);
                    coverage.absorbed += usize::from(r.readable() > before + y.new_bytes);
                    coverage.spanning += usize::from(a.len() > 1);
                    coverage.out_of_order += usize::from(held != 0 || y.out_of_order);
                    coverage.wrapped +=
                        usize::from(sequence.0 > sequence.0.wrapping_add(len as u32));
                }
                7..=9 => {
                    let len = rng.below(capacity + 1);
                    let (mut a, mut b) = (alloc::vec![0; len], alloc::vec![0; len]);
                    let count = r.read(&mut b);
                    assert_eq!(q.read(&mut a), count);
                    assert_eq!(a, b);
                    base += count as i64;
                }
                10 => {
                    let len = rng.below(capacity + 1);
                    let (mut a, mut b) = (alloc::vec![0; len], alloc::vec![0; len]);
                    assert_eq!(q.peek(&mut a), r.peek(&mut b));
                    assert_eq!(a, b);
                }
                11 | 12 => {
                    let limit = 1 + rng.below(4);
                    let blocks = q.sack_blocks(limit);
                    assert_eq!(blocks, r.sack_blocks(limit));
                    let (u, v) = (q.output_undo(), r.output_undo());
                    if let Some(first) = blocks[0] {
                        q.commit_sack(first);
                        r.commit_sack(first);
                    }
                    q.commit_report();
                    r.commit_report();
                    if rng.below(4) == 0 {
                        same(&q, &r);
                        q.restore_output(u);
                        r.restore_output(v);
                    }
                }
                13 => assert_eq!(q.take_push(), r.take_push()),
                14 if capacity < 6000 => {
                    let grown = capacity + 1 + rng.below(800);
                    assert_eq!(q.grow(grown), r.grow(grown));
                }
                15 if rng.below(8) == 0 => {
                    q.clear();
                    r.clear();
                    let start = Seq(rng.below(1 << 31) as u32 * 2 + rng.below(2) as u32);
                    assert_eq!(q.reset_start(start), r.reset_start(start));
                    base = 0;
                    epoch += 1;
                    descending = None;
                }
                _ => {
                    q.clear_dsack();
                    r.clear_dsack();
                }
            }
            same(&q, &r);
        }
    }
    coverage
}

// Debug-test coverage floor for `run(200, 120, _)`.
pub(crate) fn assert_covered(coverage: &Coverage) {
    assert!(
        coverage.absorbed > 300
            && coverage.spanning > 200
            && coverage.out_of_order > 5000
            && coverage.wrapped > 10,
        "{coverage:?}"
    );
}
