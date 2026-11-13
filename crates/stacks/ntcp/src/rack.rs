// Bounded transmission intervals shared by RACK selection and diagnostics.
// Sequence ranges are exclusive and always smaller than half the sequence space.
use crate::{
    connection::{CallerTimebase, TimestampGranularity},
    sack::{FRESH, Scoreboard},
    seq::Seq,
};
#[cfg(test)]
use alloc::vec::Vec;

#[cfg(test)]
const CAPACITY: usize = 256;

// Linux Documentation/networking/ip-sysctl.rst: tcp_min_rtt_wlen defaults
// to 300 seconds, balancing path migration against transient RTT inflation.
const MIN_RTT_WINDOW: u64 = 300_000_000;
const MIN_RTT_BUCKET: u64 = MIN_RTT_WINDOW / 3;
// Even a one-caller-tick minimum can reach any u64 SRTT with this multiplier.
const MAX_MULTIPLIER: u128 = 4 * u64::MAX as u128;

// Entries that fresh output and peer-forced SACK splits leave free, for
// the splits a cumulative ACK and a retransmission make.
pub(crate) const SPARE: usize = 2;

// What one entry costs in send usage: its interval and half a scoreboard
// range (the scoreboard holds a range per two entries), as Linux counts
// each skb's truesize in sk_wmem_queued.
pub(crate) const ENTRY_BYTES: usize =
    core::mem::size_of::<Interval>() + core::mem::size_of::<(Seq, Seq)>() / 2;

// Linux's tcp_fragment allowance above the send buffer for splits of
// entries in the middle of the flight: 2 * SKB_TRUESIZE(GSO_LEGACY_MAX_SIZE).
const SPLIT_ALLOWANCE: usize = 128 * 1024;

// Send usage (queued payload plus ENTRY_BYTES per entry) and the send
// limit an ACK's SACK splits are held to.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SplitBound {
    pub queued: usize,
    pub limit: usize,
}

impl SplitBound {
    #[cfg(test)]
    pub(crate) const NONE: Self = Self {
        queued: 0,
        limit: usize::MAX / 4,
    };

    // The entries at which, with nothing queued, `refuses` starts: more
    // than a write ever needs under a `limit`-byte send limit.
    pub(crate) fn entries(limit: usize) -> usize {
        limit
            .saturating_add(SPLIT_ALLOWANCE)
            .saturating_mul(2)
            .saturating_add(2)
            .div_ceil(ENTRY_BYTES)
    }

    // Linux's tcp_fragment refuses to split an skb other than the first or
    // last of the retransmission queue once sk_wmem_queued / 2 exceeds
    // sk_sndbuf + 2 * SKB_TRUESIZE(64 KiB).
    fn refuses(&self, entries: usize) -> bool {
        let usage = self
            .queued
            .saturating_add(entries.saturating_mul(ENTRY_BYTES));
        usage / 2 > self.limit.saturating_add(SPLIT_ALLOWANCE)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Interval {
    start: Seq,
    end: Seq,
    // Splits retain the original logical admission/window identity.
    original_start: Seq,
    original_end: Seq,
    // Physical originals may be smaller than the logical admission/window span.
    original_wire_start: Seq,
    original_wire_end: Seq,
    original_sent: u64,
    originally_in_window: bool,
    successful_retries: u32,
    transmission_start: Seq,
    transmission_end: Seq,
    sent: u64,
    // Retained wire TSval must still name this copy's departure time.
    timestamp_eligible: bool,
    retransmitted: bool,
    departure_committed: bool,
    // Any retransmission of the original packet makes its untouched pieces
    // ambiguous too; their ACK may have been solicited by that retransmission.
    original_retransmitted: bool,
    // One-shot byte delivery attribution is independent of transmission state.
    delivered: bool,
    // Compact statistics only; leave byte delivery and recovery independent.
    stats_flags: u8,
    sacked: bool,
    original_lost: bool,
    needs_retransmit: bool,
    // This committed retransmission copy has not shared an extra loss response.
    // Splits copy the marker; only successful retransmit commits renew it.
    loss_response_pending: bool,
    // Which bytes carry PTB repair work (the send buffer's marks).
    ptb: Ptb,
}

// Whether no byte of an interval, all or only some carry PTB work. The
// ledger's interval budget leaves one byte for it, not a count: the bytes
// of Some intervals are counted in the send buffer when asked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ptb {
    None,
    All,
    Some,
}

// Ranges holding every Ptb::Some interval.
const PTB_SOME_SPANS: usize = 8;

// Independent of byte/PRR delivery: survives RTO SACK reneging.
const PACKET_DELIVERED: u8 = 1 << 0;
// Current accepted packet carries FIN; once credited, retain whether that
// credit already represented FIN even when a later copy replaces it.
const PACKET_INCLUDES_FIN: u8 = 1 << 1;
const SYN_PAYLOAD: u8 = 1 << 2;
// Independent delivery-unit boundary: latest RACK transmissions can overlap
// only part of a queued packet. Byte/SACK splits preserve this endpoint.
const DELIVERY_END: u8 = 1 << 3;
const DIAGNOSTIC_RETRY: u8 = 1 << 4;
const DIAGNOSTIC_LOST: u8 = 1 << 5;

impl Interval {
    fn stats_flag(&self, bit: u8) -> bool {
        self.stats_flags & bit != 0
    }

    fn set_stats_flag(&mut self, bit: u8, value: bool) {
        if value {
            self.stats_flags |= bit;
        } else {
            self.stats_flags &= !bit;
        }
    }
}

// Scoped to one Rack instance by the owning connection's generation. Never
// compare only sequence/time: two selections may have exactly the same values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DepartureSelection {
    generation: u64,
    start: Seq,
    end: Seq,
    selected: u64,
    retransmit: bool,
}

// Constant-size undo for one homogeneous original wire packet. Arbitrarily
// split intervals remain in place; no packet-path allocation or ledger clone.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RetryUndo {
    start: Seq,
    end: Seq,
    prior: Interval,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OriginalRetrySpan {
    pub original_start: Seq,
    pub original_end: Seq,
    pub originally_in_window: bool,
    pub successful_retries: u32,
    // A retry-coverage split may precede the immutable original boundary.
    pub retry_end: Seq,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Counts {
    pub unacked: u32,
    pub sacked: u32,
    pub lost: u32,
    pub retransmitted: u32,
}

impl Counts {
    fn apply(&mut self, before: Self, after: Self) {
        self.unacked = self.unacked - before.unacked + after.unacked;
        self.sacked = self.sacked - before.sacked + after.sacked;
        self.lost = self.lost - before.lost + after.lost;
        self.retransmitted = self.retransmitted - before.retransmitted + after.retransmitted;
    }
}

// Sums over the ledger that ACK and output paths read, kept current by
// every change instead of a walk per query.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Tally {
    // Payload of intervals neither SACKed nor awaiting retransmission.
    pipe: u32,
    // Intervals whose transmission is shorter than Rack::short_mss.
    short: u32,
    // Intervals awaiting retransmission and not SACKed.
    lost: u32,
    // Bytes of those intervals wholly carrying PTB work.
    ptb_lost: u32,
    // By original wire packet (packet_counts) and by delivery unit
    // (diagnostic_packet_counts).
    packets: Counts,
    units: Counts,
}

impl Tally {
    fn apply(&mut self, before: Self, after: Self) {
        self.pipe = self.pipe - before.pipe + after.pipe;
        self.short = self.short - before.short + after.short;
        self.lost = self.lost - before.lost + after.lost;
        self.ptb_lost = self.ptb_lost - before.ptb_lost + after.ptb_lost;
        self.packets.apply(before.packets, after.packets);
        self.units.apply(before.units, after.units);
    }
}

// Index ranges whose contribution to the tally is recomputed around a
// change: changed intervals, and whole packets and delivery units.
#[derive(Clone, Copy)]
struct Hull {
    items: (usize, usize),
    packets: (usize, usize),
    units: (usize, usize),
}

// Ranges changed between ACKs in ways ACK processing reads.
const DIRTY: usize = 4;
// What one ACK visits: its cumulative prefix, dirty and fresh ranges.
const SPANS: usize = 1 + DIRTY + FRESH;

struct AckInput<'a> {
    ack: Seq,
    scoreboard: &'a Scoreboard,
    now: u64,
    echo: Option<u32>,
    timestamps: Option<TimestampGranularity>,
    mss: u32,
}

struct AckWalk {
    delivered: u32,
    newest: Option<(u64, Seq, u64, bool)>,
    prior_fack: Option<Seq>,
    sack_reordered: bool,
    cumulative_reordered: bool,
}

#[derive(Debug)]
pub(crate) struct Rack {
    // No Clone/snapshot on packet paths: split copies one Interval and all
    // pushes/inserts stay inside the entries allocated at write.
    intervals: storage::Intervals,
    capacity: usize,
    // SACK splits refused at the SplitBound (Linux's TCPWqueueTooBig), for
    // the connection to take.
    pub(crate) split_refusals: u64,
    selection_generation: u64,
    departure_selection: Option<DepartureSelection>,
    timebase: CallerTimebase,
    // Transmissions before this tick give no RTT sample.
    sample_floor: u64,
    fallback: Option<Seq>,
    latest: Option<(u64, Seq)>,
    fack: Option<Seq>,
    min_rtt: Option<u64>,
    min_rtt_buckets: [Option<(u64, u64)>; 4],
    rtt: u64,
    reordering_seen: bool,
    pub(crate) reordering: u32,
    pub(crate) reordering_events: u64,
    multiplier: u128,
    persist: u8,
    pub(crate) reo_grew: bool,
    dsack_round: Option<Seq>,
    pub(crate) deadline: Option<u64>,
    pub(crate) ack_sample: Option<u64>,
    pub(crate) delivered_segments: u64,
    pub(crate) delivered_segments_valid: bool,
    tally: Tally,
    short_mss: u32,
    // Every interval the scoreboard covers is marked SACKed, except in
    // these ranges (or anywhere, with rescan): ACKs visit only them, their
    // cumulative prefix and the scoreboard's fresh ranges.
    dirty: [(Seq, Seq); DIRTY],
    dirty_len: usize,
    rescan: bool,
    // Every Ptb::Some interval lies in one of these disjoint ranges, or
    // anywhere with ptb_some_all.
    ptb_some: [(Seq, Seq); PTB_SOME_SPANS],
    ptb_some_len: usize,
    ptb_some_all: bool,
}

fn sent_after(a: (u64, Seq), b: (u64, Seq)) -> bool {
    a.0 > b.0 || a.0 == b.0 && a.1.after(b.1)
}

#[path = "rack_storage.rs"]
mod storage;

impl Rack {
    #[cfg(test)]
    fn new() -> Result<Self, ()> {
        Self::with_capacity(CAPACITY)
    }

    // The ledger holds one entry per transmitted segment and per piece an
    // ACK, SACK or retransmission split off, in entries the connection
    // allocates at write.
    pub(crate) fn allocation_bytes(&self) -> usize {
        self.intervals.allocation_bytes()
    }

    // Entries held now: what send usage charges ENTRY_BYTES for.
    pub(crate) fn len(&self) -> usize {
        self.intervals.len()
    }

    // Entries allocated.
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    // Frees every entry of an empty ledger, as Linux frees the skbs of an
    // emptied retransmission queue; the next write allocates again.
    pub(crate) fn release(&mut self) {
        debug_assert!(self.intervals.is_empty());
        self.intervals.release();
        self.capacity = 0;
    }

    // Entries fresh output may still take, leaving SPARE; unbounded while
    // the ledger is abandoned, which records no transmission.
    pub(crate) fn fresh_room(&self) -> usize {
        if !self.valid() {
            return usize::MAX;
        }
        self.capacity
            .saturating_sub(self.intervals.len())
            .saturating_sub(SPARE)
    }

    #[cfg(test)]
    pub(crate) fn grown(&self, capacity: usize) -> Result<Self, ()> {
        let mut intervals = storage::Intervals::new(capacity)?;
        for interval in self.intervals.iter() {
            intervals.push(*interval);
        }
        Ok(Self {
            intervals,
            capacity,
            ..*self
        })
    }

    pub(crate) fn growth_bytes(&self, entries: usize) -> Option<usize> {
        self.intervals.growth_bytes(entries)
    }

    pub(crate) fn prepare_growth(&self, entries: usize) -> Result<storage::Growth, ()> {
        self.intervals.prepare_growth(entries)
    }

    pub(crate) fn commit_growth(&mut self, growth: storage::Growth, entries: usize) {
        self.intervals.commit_growth(growth);
        self.capacity = entries;
    }

    pub(crate) fn storage_bytes(entries: usize) -> Option<usize> {
        storage::Intervals::storage_bytes(entries)
    }

    #[cfg(test)]
    pub(crate) fn with_capacity(capacity: usize) -> Result<Self, ()> {
        Self::with_timebase(capacity, CallerTimebase::default())
    }

    pub(crate) fn with_timebase(capacity: usize, timebase: CallerTimebase) -> Result<Self, ()> {
        let intervals = storage::Intervals::new(capacity)?;
        Ok(Self {
            intervals,
            capacity,
            split_refusals: 0,
            selection_generation: 0,
            departure_selection: None,
            timebase,
            sample_floor: 0,
            fallback: None,
            latest: None,
            fack: None,
            min_rtt: None,
            min_rtt_buckets: [None; 4],
            rtt: 0,
            reordering_seen: false,
            reordering: 3,
            reordering_events: 0,
            multiplier: 1,
            persist: 0,
            reo_grew: false,
            dsack_round: None,
            deadline: None,
            ack_sample: None,
            delivered_segments: 0,
            delivered_segments_valid: true,
            tally: Tally::default(),
            short_mss: 0,
            dirty: [(Seq(0), Seq(0)); DIRTY],
            dirty_len: 0,
            rescan: false,
            ptb_some: [(Seq(0), Seq(0)); PTB_SOME_SPANS],
            ptb_some_len: 0,
            ptb_some_all: false,
        })
    }

    pub(crate) fn original_retry_span(
        &self,
        seq: Seq,
        proposed_end: Seq,
    ) -> Option<OriginalRetrySpan> {
        if !self.valid() || !proposed_end.after(seq) {
            return None;
        }
        let index = self.locate(seq);
        if index == self.intervals.len() || self.intervals[index].start.after(seq) {
            return None;
        }
        let head = self.intervals[index];
        let end = self
            .intervals
            .range(index, self.intervals.len())
            .take_while(|r| {
                r.original_start == head.original_start
                    && r.original_end == head.original_end
                    && r.successful_retries == head.successful_retries
            })
            .last()?
            .end;
        Some(OriginalRetrySpan {
            original_start: head.original_start,
            original_end: head.original_end,
            originally_in_window: head.originally_in_window,
            successful_retries: head.successful_retries,
            retry_end: if end.after(proposed_end) {
                proposed_end
            } else {
                end
            },
        })
    }

    // These two commits are called only after successful wire encoding. Window
    // validity belongs to the complete original, not its surviving ACK suffix.
    pub(crate) fn commit_original_window(&mut self, start: Seq, end: Seq, in_window: bool) {
        // Pieces of an original never leave its own sequence range.
        let (first, last) = self.overlapping(start, end);
        for r in self.intervals.range_mut(first, last) {
            if r.original_start == start && r.original_end == end {
                r.originally_in_window = in_window;
            }
        }
    }

    pub(crate) fn commit_retry_span(&mut self, start: Seq, end: Seq) {
        if !end.after(start) || !self.valid() {
            return;
        }
        if !self.split(start) || !self.split(end) {
            let boundary = self.intervals.last().map_or(end, |r| r.end);
            self.abandon(boundary);
            return;
        }
        let (first, last) = self.overlapping(start, end);
        for r in self.intervals.range_mut(first, last) {
            if !start.after(r.start) && !r.end.after(end) {
                r.successful_retries = r.successful_retries.saturating_add(1);
            }
        }
        self.verify();
    }

    // Preserve the last successful wire packet boundary, including partial ACKs.
    pub(crate) fn head_transmission(&self, start: Seq) -> Option<(Seq, u64)> {
        let first = self.locate(start);
        if first == self.intervals.len() || self.intervals[first].start.after(start) {
            return None;
        }
        let head = self.intervals[first];
        let end = self
            .intervals
            .range(first, self.intervals.len())
            .take_while(|r| {
                r.sent == head.sent
                    && r.transmission_start == head.transmission_start
                    && r.transmission_end == head.transmission_end
            })
            .last()?
            .end;
        Some((end, head.sent))
    }

    // RACK.xmit_ts: the latest transmission time among delivered segments.
    pub(crate) fn latest_delivered(&self) -> Option<u64> {
        self.latest.map(|(sent, _)| sent)
    }

    pub(crate) fn valid(&self) -> bool {
        self.fallback.is_none()
    }

    pub(crate) fn min_rtt(&self) -> Option<u64> {
        self.min_rtt
    }

    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Four fixed buckets conservatively estimate a recent 300-second minimum; acknowledge contributes only eligible non-retransmitted full-transmission samples.
    //# Use the RTT measurements obtained via [RFC6298] or [RFC7323] to
    //# update the estimated minimum RTT in RACK.min_RTT.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Retains all minima within the window and at most one extra bucket; longer paths replace old minima without allocation.
    //# The sender SHOULD
    //# track a windowed min-filtered estimate of recent RTT measurements
    //# that can adapt when migrating to significantly longer paths rather
    //# than tracking a simple global minimum of all RTT measurements.
    pub(crate) fn sample(&mut self, rtt: u64, now: u64) {
        // now and RTT are caller-supplied ticks, as for acknowledge.
        // ponytail: bucket minima retain samples for 300..400 seconds, giving
        // a conservative (never higher) estimate of the exact 300-second min;
        // use a full sample deque only if exact expiration becomes necessary.
        // Like Linux tcp_update_rtt_min, aging happens on accepted samples,
        // not on timers: idle time alone does not erase the ambiguity guard.
        let epoch = now / self.timebase.ticks_from_us(MIN_RTT_BUCKET);
        let bucket = &mut self.min_rtt_buckets[(epoch % 4) as usize];
        *bucket = Some((
            epoch,
            bucket
                .filter(|old| old.0 == epoch)
                .map_or(rtt, |old| old.1.min(rtt)),
        ));
        self.min_rtt = self
            .min_rtt_buckets
            .iter()
            .flatten()
            .filter(|&&(time, _)| time <= epoch && epoch - time < 4)
            .map(|&(_, value)| value)
            .min();
        if self.latest.is_none() {
            self.rtt = rtt;
        }
    }

    pub(crate) fn discard_samples_before(&mut self, now: u64) {
        self.sample_floor = now;
    }

    // Reclaim cumulative bytes without consulting SACK advice or creating
    // delivery/RTT evidence. Trim in place: a full ledger needs no split slot.
    pub(crate) fn trim_cumulative(&mut self, ack: Seq) {
        let count = self.locate(ack);
        self.acknowledge_units(ack, None, &[(0, count)]);
        for r in self.intervals.range(0, count) {
            if !r.stats_flag(PACKET_DELIVERED)
                && r.end == r.transmission_end
                && !r.stats_flag(SYN_PAYLOAD)
            {
                self.delivered_segments_valid = false;
            }
        }
        self.remove_prefix(count);
        if self.intervals.first().is_some_and(|r| ack.after(r.start)) {
            self.retally(0, 1, |s| s.intervals[0].start = ack);
        }
        if self.fallback.is_some_and(|boundary| !boundary.after(ack)) {
            self.fallback = None;
            self.fack = Some(ack);
            // Advice from before the fallback was never marked.
            self.rescan = true;
        }
        self.verify();
    }

    pub(crate) fn abandon(&mut self, boundary: Seq) {
        self.intervals.clear();
        self.tally = Tally::default();
        self.dirty_len = 0;
        self.ptb_some_len = 0;
        self.ptb_some_all = false;
        self.delivered_segments_valid = false;
        self.departure_selection = None;
        self.fallback = Some(boundary);
        self.latest = None;
        self.deadline = None;
    }

    fn split(&mut self, edge: Seq) -> bool {
        let Some(i) = self.inside(edge) else {
            return true;
        };
        if self.intervals.len() == self.capacity {
            return false;
        }
        let hull = self.hull(i, i + 1);
        let before = self.contribution(hull);
        self.divide(i, edge);
        // Both pieces keep the packet and delivery unit of the original.
        let after = self.contribution(Hull {
            items: (i, i + 2),
            packets: (hull.packets.0, hull.packets.1 + 1),
            units: (hull.units.0, hull.units.1 + 1),
        });
        self.tally.apply(before, after);
        true
    }

    // Splits interval i at edge, strictly inside it, leaving the tally to
    // the caller.
    fn divide(&mut self, i: usize, edge: Seq) {
        let mut right = self.intervals[i];
        right.start = edge;
        // Pieces of a Some interval stay inside its noted range.
        self.intervals[i].end = edge;
        self.intervals[i].set_stats_flag(DELIVERY_END, false);
        self.intervals.insert(i + 1, right);
    }

    // Index of the first interval ending after seq: the one holding seq, or
    // the first above it. The ledger is ordered and spans less than half the
    // sequence space, so offsets from its first start order it.
    fn locate(&self, seq: Seq) -> usize {
        let Some(base) = self.intervals.first().map(|r| r.start) else {
            return 0;
        };
        let target = seq.distance_from(base);
        if target >= 1 << 31 {
            return 0;
        }
        let (mut low, mut high) = (0, self.intervals.len());
        while low < high {
            let mid = (low + high) / 2;
            if self.intervals[mid].end.distance_from(base) <= target {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        low
    }

    // Indices of the intervals overlapping [start, end).
    fn overlapping(&self, start: Seq, end: Seq) -> (usize, usize) {
        let first = self.locate(start);
        let mut last = self.locate(end);
        if last < self.intervals.len() && end.after(self.intervals[last].start) {
            last += 1;
        }
        (first, last.max(first))
    }

    // The interval that edge falls strictly inside, which a split divides.
    fn inside(&self, edge: Seq) -> Option<usize> {
        let i = self.locate(edge);
        (i < self.intervals.len() && edge.after(self.intervals[i].start)).then_some(i)
    }

    fn same_packet(&self, a: usize, b: usize) -> bool {
        let (a, b) = (&self.intervals[a], &self.intervals[b]);
        a.original_wire_start == b.original_wire_start && a.original_wire_end == b.original_wire_end
    }

    // First index of the original packet holding index i.
    fn packet_start(&self, mut i: usize) -> usize {
        while i > 0 && self.same_packet(i - 1, i) {
            i -= 1;
        }
        i
    }

    // End of the original packet holding index i - 1.
    fn packet_end(&self, mut i: usize) -> usize {
        while i > 0 && i < self.intervals.len() && self.same_packet(i - 1, i) {
            i += 1;
        }
        i
    }

    // First index of the delivery unit holding index i.
    fn unit_start(&self, mut i: usize) -> usize {
        while i > 0 && !self.intervals[i - 1].stats_flag(DELIVERY_END) {
            i -= 1;
        }
        i
    }

    // First unit boundary at or after i: just past a DELIVERY_END, or the end.
    fn unit_end(&self, mut i: usize) -> usize {
        while i < self.intervals.len()
            && (i == 0 || !self.intervals[i - 1].stats_flag(DELIVERY_END))
        {
            i += 1;
        }
        i
    }

    // What a change to the fields of intervals [a, b) can alter: those
    // intervals, and every original packet and delivery unit holding one of
    // them or a neighbour (a change can join or part them). The boundaries
    // at the hull's edges depend on unchanged intervals only.
    fn hull(&self, a: usize, b: usize) -> Hull {
        let len = self.intervals.len();
        Hull {
            items: (a, b),
            packets: (
                self.packet_start(a.saturating_sub(1)),
                if b < len { self.packet_end(b + 1) } else { len },
            ),
            units: (
                self.unit_start(a),
                if b < len { self.unit_end(b + 1) } else { len },
            ),
        }
    }

    fn contribution(&self, hull: Hull) -> Tally {
        let mut tally = Tally::default();
        for r in self.intervals.range(hull.items.0, hull.items.1) {
            if !r.sacked && !r.needs_retransmit {
                tally.pipe += r.end.distance_from(r.start);
            }
            tally.short +=
                u32::from(r.transmission_end.distance_from(r.transmission_start) < self.short_mss);
            tally.lost += u32::from(!r.sacked && r.needs_retransmit);
            if !r.sacked && r.needs_retransmit && r.ptb == Ptb::All {
                tally.ptb_lost += r.end.distance_from(r.start);
            }
        }
        let (mut i, end) = hull.packets;
        while i < end {
            let first = i;
            let (mut sacked, mut lost, mut retransmitted) = (true, false, false);
            while i < end && (i == first || self.same_packet(i - 1, i)) {
                let r = &self.intervals[i];
                sacked &= r.sacked;
                lost |= r.original_lost && !r.sacked;
                retransmitted |= r.retransmitted && !r.sacked && !r.needs_retransmit;
                i += 1;
            }
            tally.packets.unacked += 1;
            tally.packets.sacked += u32::from(sacked);
            tally.packets.lost += u32::from(lost);
            tally.packets.retransmitted += u32::from(retransmitted);
        }
        let (mut sacked, mut lost, mut retransmitted) = (true, false, false);
        for r in self.intervals.range(hull.units.0, hull.units.1) {
            sacked &= r.sacked;
            lost |= r.original_lost && !r.sacked;
            retransmitted |=
                r.stats_flag(DIAGNOSTIC_RETRY) && !r.stats_flag(DIAGNOSTIC_LOST) && !r.sacked;
            // Intervals after the last DELIVERY_END form no unit yet.
            if r.stats_flag(DELIVERY_END) {
                tally.units.unacked += 1;
                tally.units.sacked += u32::from(sacked);
                tally.units.lost += u32::from(lost);
                tally.units.retransmitted += u32::from(retransmitted);
                (sacked, lost, retransmitted) = (true, false, false);
            }
        }
        tally
    }

    // Applies change, which alters only fields of intervals [a, b), and its
    // effect on the tally.
    fn retally<R>(&mut self, a: usize, b: usize, change: impl FnOnce(&mut Self) -> R) -> R {
        let hull = self.hull(a, b);
        let before = self.contribution(hull);
        let result = change(self);
        let after = self.contribution(hull);
        self.tally.apply(before, after);
        result
    }

    fn push(&mut self, interval: Interval) {
        let from = self.intervals.len().saturating_sub(1);
        let tail = |s: &Self| {
            let len = s.intervals.len();
            s.contribution(Hull {
                items: (from, len),
                packets: (s.packet_start(from), len),
                units: (s.unit_start(from), len),
            })
        };
        let before = tail(self);
        self.intervals.push(interval);
        let after = tail(self);
        self.tally.apply(before, after);
    }

    fn remove_prefix(&mut self, count: usize) {
        if count == 0 {
            return;
        }
        let len = self.intervals.len();
        let packets = if count < len {
            self.packet_end(count + 1)
        } else {
            len
        };
        let units = if count < len {
            self.unit_end(count + 1)
        } else {
            len
        };
        let before = self.contribution(Hull {
            items: (0, count),
            packets: (0, packets),
            units: (0, units),
        });
        self.intervals.remove_prefix(count);
        let after = self.contribution(Hull {
            items: (0, 0),
            packets: (0, packets - count),
            units: (0, units - count),
        });
        self.tally.apply(before, after);
        // Losing an incomplete prefix can complete the unit it cut.
        if let Some(&Interval { start, end, .. }) = self.intervals.first() {
            self.mark_dirty(start, end);
        }
    }

    // Remembers a range whose intervals the next ACK must look at again
    // although the scoreboard did not change there.
    fn mark_dirty(&mut self, start: Seq, end: Seq) {
        if !end.after(start) {
            return;
        }
        for span in &mut self.dirty[..self.dirty_len] {
            if !start.after(span.1) && !span.0.after(end) {
                if span.0.after(start) {
                    span.0 = start;
                }
                if end.after(span.1) {
                    span.1 = end;
                }
                return;
            }
        }
        if self.dirty_len < DIRTY {
            self.dirty[self.dirty_len] = (start, end);
            self.dirty_len += 1;
            return;
        }
        // Full: widen the nearest range over this one.
        let gap = |&(left, right): &(Seq, Seq)| {
            if left.after(end) {
                left.distance_from(end)
            } else {
                start.distance_from(right)
            }
        };
        let nearest = (0..DIRTY).min_by_key(|&i| gap(&self.dirty[i])).unwrap();
        let span = &mut self.dirty[nearest];
        if span.0.after(start) {
            span.0 = start;
        }
        if end.after(span.1) {
            span.1 = end;
        }
    }

    // Index ranges, ordered and disjoint, of the intervals overlapping spans.
    fn index_ranges(&self, spans: &[(Seq, Seq)]) -> ([(usize, usize); SPANS], usize) {
        let mut ranges = [(0, 0); SPANS];
        let mut len = 0;
        for &(start, end) in spans {
            let (first, last) = self.overlapping(start, end);
            if first < last {
                ranges[len] = (first, last);
                len += 1;
            }
        }
        ranges[..len].sort_unstable();
        let mut merged = 0;
        for i in 0..len {
            if merged > 0 && ranges[i].0 <= ranges[merged - 1].1 {
                ranges[merged - 1].1 = ranges[merged - 1].1.max(ranges[i].1);
            } else {
                ranges[merged] = ranges[i];
                merged += 1;
            }
        }
        (ranges, merged)
    }

    // For tests that edit intervals directly.
    #[cfg(test)]
    pub(crate) fn recount(&mut self) {
        let len = self.intervals.len();
        self.tally = self.contribution(Hull {
            items: (0, len),
            packets: (0, len),
            units: (0, len),
        });
    }

    #[cfg(debug_assertions)]
    fn verify(&self) {
        let len = self.intervals.len();
        let all = Hull {
            items: (0, len),
            packets: (0, len),
            units: (0, len),
        };
        debug_assert_eq!(self.tally, self.contribution(all));
        let mut previous: Option<Seq> = None;
        for r in self.intervals.iter() {
            debug_assert!(r.end.after(r.start));
            debug_assert!(previous.is_none_or(|end| !end.after(r.start)));
            previous = Some(r.end);
        }
    }

    #[cfg(not(debug_assertions))]
    fn verify(&self) {}

    pub(crate) fn retry_undo(&self, start: Seq, end: Seq) -> Option<RetryUndo> {
        if !self.valid() || !end.after(start) {
            return None;
        }
        let (first, last) = self.overlapping(start, end);
        let prior = *self
            .intervals
            .range(first, last)
            .next()
            .filter(|r| r.start == start)?;
        if prior.sacked || !prior.needs_retransmit || prior.successful_retries == u32::MAX {
            return None;
        }
        let mut covered = start;
        for r in self.intervals.range(first, last) {
            if r.start != covered
                || r.original_wire_start != prior.original_wire_start
                || r.original_wire_end != prior.original_wire_end
                || r.transmission_start != prior.transmission_start
                || r.transmission_end != prior.transmission_end
                || r.sent != prior.sent
                || r.timestamp_eligible != prior.timestamp_eligible
                || r.retransmitted != prior.retransmitted
                || r.departure_committed != prior.departure_committed
                || r.original_retransmitted != prior.original_retransmitted
                || r.loss_response_pending != prior.loss_response_pending
                || r.successful_retries != prior.successful_retries
                || r.sacked
                || !r.needs_retransmit
                || r.stats_flag(SYN_PAYLOAD) != prior.stats_flag(SYN_PAYLOAD)
            {
                return None;
            }
            covered = if r.end.after(end) { end } else { r.end };
        }
        (covered == end).then_some(RetryUndo { start, end, prior })
    }

    pub(crate) fn cancel_retry(&mut self, selection: DepartureSelection, undo: RetryUndo) -> bool {
        let (first, last) = self.overlapping(undo.start, undo.end);
        if self.departure_selection != Some(selection)
            || !self.valid()
            || !selection.retransmit
            || selection.start != undo.start
            || selection.end != undo.end
            || self
                .intervals
                .range(first, last)
                .any(|r| r.departure_committed)
        {
            return false;
        }
        // The prior packet's pieces lie within its own wire range.
        let (wire_first, wire_last) =
            self.overlapping(undo.prior.original_wire_start, undo.prior.original_wire_end);
        let (a, b) = (first.min(wire_first), last.max(wire_last));
        if a < b {
            self.retally(a, b, |s| {
                for r in s.intervals.range_mut(a, b) {
                    if r.original_wire_start == undo.prior.original_wire_start
                        && r.original_wire_end == undo.prior.original_wire_end
                    {
                        r.original_retransmitted = undo.prior.original_retransmitted;
                    }
                    if !undo.start.after(r.start) && !r.end.after(undo.end) {
                        r.transmission_start = undo.prior.transmission_start;
                        r.transmission_end = undo.prior.transmission_end;
                        r.sent = undo.prior.sent;
                        r.timestamp_eligible = undo.prior.timestamp_eligible;
                        r.retransmitted = undo.prior.retransmitted;
                        r.departure_committed = undo.prior.departure_committed;
                        r.loss_response_pending = undo.prior.loss_response_pending;
                        r.successful_retries = undo.prior.successful_retries;
                        r.needs_retransmit = undo.prior.needs_retransmit;
                        r.sacked = undo.prior.sacked;
                        r.set_stats_flag(SYN_PAYLOAD, undo.prior.stats_flag(SYN_PAYLOAD));
                    }
                }
            });
            // Restored commitment can complete a delivery unit.
            let (start, end) = (self.intervals[a].start, self.intervals[b - 1].end);
            self.mark_dirty(start, end);
        }
        self.departure_selection = None; // Generations are never rolled back.
        self.verify();
        true
    }

    // Capture only when this output actually called transmit, not for pure ACKs.
    // The caller binds the token to its connection generation and freezes input
    // and timeout processing until the reserved output has been resolved.
    pub(crate) fn departure_selection(&self) -> Option<DepartureSelection> {
        self.departure_selection.filter(|_| self.valid())
    }

    // Shared read-only preflight lets the endpoint reject invalid departures
    // before advancing its clock. Commit uses the same edge/coverage checks.
    pub(crate) fn validate_departure(
        &self,
        selection: DepartureSelection,
        start: Seq,
        end: Seq,
        now: u64,
    ) -> bool {
        if !self.valid()
            || self.departure_selection != Some(selection)
            || !end.after(start)
            || start.distance_from(selection.start) >= selection.end.distance_from(selection.start)
            || end.distance_from(selection.start) > selection.end.distance_from(selection.start)
            || now < selection.selected
        {
            return false;
        }
        let mut covered = start;
        let (first, last) = self.overlapping(start, end);
        for r in self.intervals.range(first, last) {
            if r.start.after(covered)
                || r.departure_committed
                || r.sent != selection.selected
                || r.transmission_start != selection.start
                || r.transmission_end != selection.end
                || r.retransmitted != selection.retransmit
            {
                return false;
            }
            covered = if r.end.after(end) { end } else { r.end };
        }
        // Splits that find no free entry coalesce instead
        // (commit_validated_departure).
        covered == end
    }

    // `validate_departure` of the consecutive departures of `bytes` from
    // `start` in `size`-byte segments (the last may be shorter), all
    // committed at `now` one after another: each segment becomes its own
    // physical transmission, so every inner edge may split an interval.
    // Count those splits before an indivisible submission.
    // Unlike a scalar departure, a group needs a free entry for every
    // split: fresh output, which alone forms groups, clips them to the
    // entries it has (Rack::fresh_room).
    pub(crate) fn validate_departure_group(
        &self,
        selection: DepartureSelection,
        start: Seq,
        size: u32,
        bytes: usize,
        now: u64,
    ) -> bool {
        if size == 0 || bytes == 0 || bytes >= 1 << 31 {
            return false;
        }
        if !self.validate_departure(selection, start, start.wrapping_add(bytes as u32), now) {
            return false;
        }
        let segments = bytes.div_ceil(size as usize);
        let splits = (0..=segments)
            .filter(|&i| {
                let edge = start.wrapping_add((i * size as usize).min(bytes) as u32);
                self.inside(edge).is_some()
            })
            .count();
        splits <= self.capacity.saturating_sub(self.intervals.len())
    }

    pub(crate) fn commit_departure(
        &mut self,
        selection: DepartureSelection,
        start: Seq,
        end: Seq,
        now: u64,
    ) -> bool {
        if !self.validate_departure(selection, start, end, now) {
            return false;
        }
        self.commit_validated_departure(selection, start, end, now);
        true
    }

    // `commit_departure` of a departure `validate_departure` accepted, with
    // the intervals unchanged since. Each departure of a selection accepted
    // in parts (an MTU repair's frames) becomes its own entry, split off at
    // its edges. An edge that finds no free entry leaves its entry whole:
    // the entry is committed once the part reaching its end departs, at that
    // part's time and as one transmission, as Linux keeps one skb with one
    // timestamp for the segments of a GSO skb it could not fragment. That is
    // RACK's conservative side: a later transmission time detects loss
    // later, and the whole entry must be acknowledged.
    pub(crate) fn commit_validated_departure(
        &mut self,
        selection: DepartureSelection,
        start: Seq,
        end: Seq,
        now: u64,
    ) {
        debug_assert!(self.validate_departure(selection, start, end, now));
        // Nothing allocates; a split that would take a SPARE entry, which
        // retransmissions and cumulative ACKs need, coalesces.
        for edge in [start, end] {
            if self.intervals.len() + SPARE < self.capacity {
                self.split(edge);
            }
        }
        let (first, last) = self.overlapping(start, end);
        let previous = first
            .checked_sub(1)
            .filter(|&i| self.intervals[i].end == start);
        let from = previous.unwrap_or(first);
        self.retally(from, last, |s| {
            // Repacketize delivery units only after actual acceptance. Keep the
            // untouched prefix/suffix as separate queued units; do not tie their
            // completion to an overwritten latest-transmission sequence range.
            if let Some(previous) = previous {
                s.intervals[previous].set_stats_flag(DELIVERY_END, true);
            }
            // An entry starting before `start` holds earlier parts of the
            // same selection, which departed already.
            for r in s.intervals.range_mut(first, last) {
                if !r.end.after(end) {
                    let from = if start.after(r.start) { r.start } else { start };
                    Self::depart(r, selection, from, end, now);
                }
            }
        });
        // Commitment and the new unit edges at both ends can complete a
        // delivery unit the scoreboard already covers.
        let dirty_start = self.intervals[from].start;
        let dirty_end = self
            .intervals
            .range(last, self.intervals.len())
            .next()
            .map_or(end, |r| r.end);
        self.mark_dirty(dirty_start, dirty_end);
        self.verify();
    }

    // Records r, inside the departure [start, end), as departed at now.
    fn depart(r: &mut Interval, selection: DepartureSelection, start: Seq, end: Seq, now: u64) {
        r.set_stats_flag(DELIVERY_END, r.end == end);
        if selection.retransmit {
            r.set_stats_flag(SYN_PAYLOAD, false);
        }
        r.set_stats_flag(DIAGNOSTIC_RETRY, selection.retransmit);
        r.set_stats_flag(DIAGNOSTIC_LOST, false);
        if !r.stats_flag(PACKET_DELIVERED) {
            r.set_stats_flag(PACKET_INCLUDES_FIN, false);
        }
        r.sent = now;
        // Even a sub-TS-tick delay separates encoding from departure.
        r.timestamp_eligible &= now == selection.selected;
        r.transmission_start = start;
        r.transmission_end = end;
        r.departure_committed = true;
        if !selection.retransmit {
            r.original_wire_start = start;
            r.original_wire_end = end;
            r.original_sent = now;
        }
    }

    // `commit_validated_departure` of each departure of a group
    // `validate_departure_group` accepted, in order, with the intervals
    // unchanged since: the same splits, interval fields, dirty ranges and
    // storage moves, in one pass and with one tally change for the whole
    // group instead of a split, overlap search and retally per segment.
    pub(crate) fn commit_validated_group(
        &mut self,
        selection: DepartureSelection,
        start: Seq,
        size: u32,
        bytes: usize,
        now: u64,
    ) {
        debug_assert!(self.validate_departure_group(selection, start, size, bytes, now));
        let end = start.wrapping_add(bytes as u32);
        let edge = |k: usize| start.wrapping_add((k * size as usize).min(bytes) as u32);
        // Everything the commits change lies in [from, last) and its
        // pieces; the hull's packet and unit edges are unchanged intervals,
        // which the splits only shift.
        let (mut first, last) = self.overlapping(start, end);
        let from = first
            .checked_sub(1)
            .filter(|&i| self.intervals[i].end == start)
            .unwrap_or(first);
        let hull = self.hull(from, last);
        let before = self.contribution(hull);
        let len = self.intervals.len();
        if start.after(self.intervals[first].start) {
            self.divide(first, start);
            first += 1;
        }
        // The first commit's previous unit ends at start.
        let mut previous = first
            .checked_sub(1)
            .filter(|&i| self.intervals[i].end == start);
        if let Some(previous) = previous {
            self.intervals[previous].set_stats_flag(DELIVERY_END, true);
        }
        let mut i = first;
        for k in 0..bytes.div_ceil(size as usize) {
            let (a, b) = (edge(k), edge(k + 1));
            // Segment k's commit splits only at b: a is the last one's end.
            let dirty_start = self.intervals[previous.unwrap_or(i)].start;
            while i < self.intervals.len() && !self.intervals[i].end.after(b) {
                Self::depart(&mut self.intervals[i], selection, a, b, now);
                i += 1;
            }
            if i < self.intervals.len() && b.after(self.intervals[i].start) {
                self.divide(i, b);
                Self::depart(&mut self.intervals[i], selection, a, b, now);
                i += 1;
            }
            // As that commit marks: through the interval after the segment,
            // which later segments' splits have not divided yet.
            let dirty_end = self
                .intervals
                .range(i, self.intervals.len())
                .next()
                .map_or(b, |r| r.end);
            self.mark_dirty(dirty_start, dirty_end);
            previous = Some(i - 1);
        }
        let added = self.intervals.len() - len;
        let after = self.contribution(Hull {
            items: (from, last + added),
            packets: (hull.packets.0, hull.packets.1 + added),
            units: (hull.units.0, hull.units.1 + added),
        });
        self.tally.apply(before, after);
        self.verify();
    }

    // Called only after encoding succeeds. Fresh output takes an entry only
    // from Rack::fresh_room, which the write that queued its bytes grew;
    // a retransmission split past the allocated entries keeps the
    // defensive fallback (abandon).
    //= https://www.rfc-editor.org/rfc/rfc8985#section-4
    //= reason=Each transmitted segment gets its own entry, allocated at write and charged in send usage; entries retain every committed original/retransmission timestamp, including the pieces ACK, SACK and retransmission splits make, in caller ticks without microsecond truncation. A SACK split refused at the send-usage bound or past the allocated entries leaves its entry whole, with one transmission time (duvet exception in rfc8985-todos.toml). Physical precision finer than min_RTT/4 is a caller precondition, never measured or runtime-gated; violation leaves protocol timing guarantees unspecified, not Rust UB or memory-safety violations.
    //# For each data segment sent, the sender MUST store its most recent
    //# transmission time with a timestamp whose granularity is finer
    //# than 1/4 of the minimum RTT of the connection.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.1
    //= reason=Original commit stores timestamp and clear pending loss; retransmit changes timestamp, sets retransmitted, clears needs_retransmit. original_lost is historical diagnostic state, not Segment.lost.
    //# Upon transmitting a new segment or retransmitting an old segment,
    //# record the time in Segment.xmit_ts and set Segment.lost to FALSE.
    //# Upon retransmitting a segment, set Segment.retransmitted to TRUE.
    pub(crate) fn transmit(&mut self, start: Seq, end: Seq, now: u64, retransmit: bool) {
        self.departure_selection = self.selection_generation.checked_add(1).map(|generation| {
            self.selection_generation = generation;
            DepartureSelection {
                generation,
                start,
                end,
                selected: now,
                retransmit,
            }
        });
        if let Some(boundary) = self.fallback {
            self.departure_selection = None;
            if end.after(boundary) {
                self.fallback = Some(end);
            }
            return;
        }
        if retransmit {
            if !self.split(start) || !self.split(end) {
                let boundary = self.intervals.last().map_or(end, |r| r.end);
                self.abandon(boundary);
                return;
            }
            let (first, last) = self.overlapping(start, end);
            if first < last {
                let (a, b) = (self.packet_start(first), self.packet_end(last));
                let unsacked = self.retally(a, b, |s| {
                    for r in s.intervals.range_mut(a, b) {
                        r.original_retransmitted = true;
                    }
                    let mut unsacked = false;
                    for r in s.intervals.range_mut(first, last) {
                        if !start.after(r.start) && !r.end.after(end) {
                            unsacked |= r.sacked;
                            r.set_stats_flag(SYN_PAYLOAD, false);
                            r.transmission_start = start;
                            r.transmission_end = end;
                            r.sent = now;
                            r.timestamp_eligible = true;
                            r.departure_committed = false;
                            r.retransmitted = true;
                            r.loss_response_pending = true;
                            r.needs_retransmit = false;
                            r.sacked = false;
                        }
                    }
                    unsacked
                });
                // The scoreboard still covers these: the next ACK marks them again.
                if unsacked {
                    self.mark_dirty(start, end);
                }
            }
        } else if self.intervals.len() < self.capacity {
            self.push(Interval {
                start,
                end,
                original_start: start,
                original_end: end,
                original_wire_start: start,
                original_wire_end: end,
                original_sent: now,
                originally_in_window: false,
                successful_retries: 0,
                transmission_start: start,
                transmission_end: end,
                sent: now,
                timestamp_eligible: true,
                retransmitted: false,
                departure_committed: false,
                original_retransmitted: false,
                delivered: false,
                stats_flags: 0,
                sacked: false,
                original_lost: false,
                needs_retransmit: false,
                loss_response_pending: false,
                ptb: Ptb::None,
            });
        } else {
            self.abandon(end);
        }
        self.verify();
    }

    // Returns whether an already-delivered data-only unit cannot also supply
    // the new FIN's delivery credit. Keep that control credit in Connection.
    pub(crate) fn record_fin_payload(&mut self, start: Seq, end: Seq) -> bool {
        let mut all_credited = true;
        let mut fin_credited = false;
        let (first, last) = self.overlapping(start, end);
        for r in self.intervals.range_mut(first, last) {
            if !start.after(r.start) && !r.end.after(end) {
                all_credited &= r.stats_flag(PACKET_DELIVERED);
                fin_credited |= r.stats_flag(PACKET_DELIVERED) && r.stats_flag(PACKET_INCLUDES_FIN);
                if !r.stats_flag(PACKET_DELIVERED) {
                    r.set_stats_flag(PACKET_INCLUDES_FIN, true);
                }
            }
        }
        self.mark_dirty(start, end);
        all_credited && !fin_credited
    }

    // Statistics use queued packetization units, as opposed to unknowable
    // physical-copy attribution. Resegmentation changes their boundaries;
    // per-byte credit survives SACK reneging and prevents repeated delivery.
    fn acknowledge_units(
        &mut self,
        ack: Seq,
        scoreboard: Option<&Scoreboard>,
        ranges: &[(usize, usize)],
    ) {
        // Whole units only: widen each range to the units it touches.
        let mut done = 0;
        for &(a, b) in ranges {
            if a >= b {
                continue;
            }
            let (a, b) = (self.unit_start(a).max(done), self.unit_end(b));
            let mut start = a;
            for end in a..b {
                if self.intervals[end].stats_flag(DELIVERY_END) {
                    self.acknowledge_unit(ack, scoreboard, start, end);
                    start = end + 1;
                }
            }
            done = done.max(b);
        }
    }

    fn acknowledge_unit(
        &mut self,
        ack: Seq,
        scoreboard: Option<&Scoreboard>,
        start: usize,
        end: usize,
    ) {
        let complete = self.intervals.range(start, end + 1).all(|r| {
            r.departure_committed
                && (!r.end.after(ack)
                    || scoreboard.is_some_and(|s| {
                        s.unsacked_bytes(if r.start.after(ack) { r.start } else { ack }, r.end) == 0
                    }))
        });
        if complete {
            let newly_delivered = self
                .intervals
                .range(start, end + 1)
                .any(|r| !r.stats_flag(PACKET_DELIVERED) && !r.stats_flag(SYN_PAYLOAD));
            let includes_fin = self
                .intervals
                .range(start, end + 1)
                .any(|r| r.stats_flag(PACKET_INCLUDES_FIN));
            if newly_delivered && self.delivered_segments_valid {
                self.delivered_segments = self.delivered_segments.saturating_add(1);
            }
            for r in self.intervals.range_mut(start, end + 1) {
                r.set_stats_flag(PACKET_DELIVERED, true);
                if includes_fin && newly_delivered {
                    r.set_stats_flag(PACKET_INCLUDES_FIN, true);
                }
            }
        }
    }

    // SYN and its payload share one wire packet, counted by Connection when
    // the SYN is acknowledged. A subsequent data repair is a distinct packet.
    pub(crate) fn record_syn_payload(&mut self, start: Seq, end: Seq) {
        let (first, last) = self.overlapping(start, end);
        for r in self.intervals.range_mut(first, last) {
            if !start.after(r.start) && !r.end.after(end) {
                r.set_stats_flag(SYN_PAYLOAD, true);
            }
        }
        self.mark_dirty(start, end);
    }

    // Scoreboard is authoritative. Split at its byte edges, never scan send-buffer bytes.
    // Return newly delivered bytes, counting SACK-to-cumulative transitions only once.
    #[allow(clippy::too_many_arguments)]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-3.3.2
    //= reason=DSACK grows the multiplier at most once per cumulative flight boundary.
    //# The RACK reordering window SHOULD adaptively increase (using the
    //# algorithm in "Step 4: Update RACK reordering window" below) if
    //# the sender receives a Duplicate Selective Acknowledgment (DSACK)
    //# option [RFC2883].
    //= https://www.rfc-editor.org/rfc/rfc8985#section-4
    //= reason=DSACK adaptation is implemented even though optional in section 4.
    //# RACK DSACK-based reordering window adaptation is RECOMMENDED but
    //# is not required.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-5.1
    //= reason=Full transmission coverage is required for latest timestamp/RTT qualification; byte delivery accounting is separately one-shot.
    //# Denotes the time when the full sequence range of RACK.segment was
    //# selectively or cumulatively acknowledged.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Scoreboard byte coverage marks delivered/SACKed intervals, cumulative transitions do not double count delivery.
    //# Given the information provided in an ACK, each segment
    //# cumulatively ACKed or SACKed is marked as delivered in the
    //# scoreboard.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Ambiguous original pieces cannot qualify; retransmitted range requires full coverage, RTT >= minimum and matching normalized local-tick TSecr when timestamps negotiated. Equality check is stricter than merely rejecting old echoes.
    //# To avoid spurious inferences, ignore a segment as invalid if any of
    //# its sequence range has been retransmitted before and if either of two
    //# conditions is true:
    //#
    //# 1.  The Timestamp Echo Reply field (TSecr) of the ACK's timestamp
    //# option [RFC7323], if available, indicates the ACK was not
    //# acknowledging the last retransmission of the segment.
    //#
    //# 2.  The segment was last retransmitted less than RACK.min_rtt ago.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Chooses most recently sent eligible full transmission for current ACK RTT; latest reference advances only by timestamp and serial end-sequence tie break.
    //# Among all the segments newly ACKed or SACKed by this ACK that pass
    //# the checks above, update the RACK.rtt to be the RTT sample calculated
    //# using this ACK.  Furthermore, record the most recent Segment.xmit_ts
    //# in RACK.xmit_ts if it is ahead of RACK.xmit_ts.  If Segment.xmit_ts
    //# equals RACK.xmit_ts (e.g., due to clock granularity limits), then
    //# compare Segment.end_seq and RACK.end_seq to break the tie when
    //# deciding whether to update the RACK.segment's associated state.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Original non-retransmitted intervals acknowledged below fack set reordering_seen; retransmitted originals are excluded.
    //# If a never-retransmitted segment
    //# that's below RACK.fack is (selectively or cumulatively) acknowledged,
    //# it has been delivered out of order.  The sender sets
    //# RACK.reordering_seen to TRUE if such a segment is identified.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Cumulative ACK covers round boundary before a new DSACK can grow multiplier and reset 16-recovery persistence.
    //# If RACK.dsack_round is not None AND
    //# SND.UNA >= RACK.dsack_round:
    //# RACK.dsack_round = None
    //# /* Grow the reordering window per round that sees DSACK.
    //# Reset the window after 16 DSACK-free recoveries */
    //# If RACK.dsack_round is None AND
    //# any DSACK option is present on latest received ACK:
    //# RACK.dsack_round = SND.NXT
    //# RACK.reo_wnd_mult += 1
    //# RACK.reo_wnd_persist = 16
    //= https://www.rfc-editor.org/rfc/rfc6298#section-3
    //= reason=RACK may advance its loss-detection RTT on retransmission; ack_sample supplied to ordinary RTO estimator is restricted to non-retransmitted, complete, unambiguous original intervals.
    //# TCP MUST use Karn's algorithm [KP87] for taking RTT samples.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-3
    //= reason=RACK may advance its loss-detection RTT on retransmission; ack_sample supplied to ordinary RTO estimator is restricted to non-retransmitted, complete, unambiguous original intervals.
    //# That is, RTT samples MUST NOT be made using segments that were retransmitted (and thus
    //# for which it is ambiguous whether the reply was for the first instance of the packet
    //# or a later instance).
    //= https://www.rfc-editor.org/rfc/rfc6298#section-3
    //= reason=Partial evidence only; TODO remains. RACK may advance its loss-detection RTT on retransmission; ack_sample supplied to ordinary RTO estimator is restricted to non-retransmitted, complete, unambiguous original intervals.
    //# A TCP implementation MUST take at least one RTT measurement per RTT (unless that is
    //# not possible per Karn's algorithm).
    //= https://www.rfc-editor.org/rfc/rfc6298#section-3
    //= reason=Partial evidence only; TODO remains. RACK may advance its loss-detection RTT on retransmission; ack_sample supplied to ordinary RTO estimator is restricted to non-retransmitted, complete, unambiguous original intervals.
    //# However, when using the timestamp option, each ACK can be used as an RTT sample. RFC
    //# 1323 [JBB92] suggests that TCP connections utilizing large congestion windows should
    //# take many RTT samples per window of data to avoid aliasing effects in the estimated
    //# RTT.
    pub(crate) fn acknowledge_within(
        &mut self,
        ack: Seq,
        high: Seq,
        scoreboard: &mut Scoreboard,
        now: u64,
        echo: Option<u32>,
        timestamps: Option<TimestampGranularity>,
        mss: u32,
        dsack: bool,
        bound: SplitBound,
    ) -> u32 {
        self.ack_sample = None;
        self.reo_grew = false;
        // Earlier ACKs marked every interval the scoreboard then covered.
        // Only the cumulative prefix, newly SACKed ranges and ranges changed
        // here since can hold work; without a record, visit everything.
        let fresh = scoreboard.take_fresh();
        let scoreboard = &*scoreboard;
        let mut spans = [(Seq(0), Seq(0)); SPANS];
        let mut count = 0;
        let mut fresh_from = 0;
        let everything = self.rescan || fresh.is_none();
        if let Some(base) = self.intervals.first().map(|r| r.start) {
            if everything {
                spans[0] = (base, self.intervals.last().unwrap().end);
                count = 1;
            } else {
                spans[0] = (base, ack);
                count = 1;
                for &span in &self.dirty[..self.dirty_len] {
                    spans[count] = span;
                    count += 1;
                }
                fresh_from = count;
                let (fresh, len) = fresh.unwrap();
                for &span in &fresh[..len] {
                    spans[count] = span;
                    count += 1;
                }
            }
        }
        self.dirty_len = 0;
        self.rescan = false;
        let (ranges, len) = self.index_ranges(&spans[..count]);
        self.acknowledge_units(ack, Some(scoreboard), &ranges[..len]);
        if self.fallback.is_some() {
            self.trim_cumulative(ack);
            return 0;
        }
        if !self.split(ack) {
            self.abandon(high);
            return 0;
        }
        // Edges of ranges that existed at the last ACK were split then,
        // or refused.
        let advice = scoreboard.ranges();
        let (mut first, mut last) = (0, advice.len());
        if !everything && let Some(&(base, _)) = advice.first() {
            // Offsets from the lowest range; a span reaching below it counts from 0.
            let offset = |seq: Seq| {
                Some(seq.distance_from(base))
                    .filter(|&d| d < 1 << 31)
                    .unwrap_or(0)
            };
            let fresh = &spans[fresh_from..count];
            // Only ranges touching a fresh span.
            if fresh.is_empty() {
                last = 0;
            } else {
                let low = fresh.iter().map(|&(l, _)| offset(l)).min().unwrap();
                let high = fresh.iter().map(|&(_, r)| offset(r)).max().unwrap();
                first = advice.partition_point(|&(_, right)| offset(right) < low);
                last = advice.partition_point(|&(left, _)| offset(left) <= high);
            }
        }
        for &(left, right) in &advice[first..last.max(first)] {
            self.sack_split(left, ack, bound);
            self.sack_split(right, ack, bound);
        }
        let mut walk = AckWalk {
            delivered: 0,
            newest: None,
            prior_fack: self.fack,
            sack_reordered: false,
            cumulative_reordered: false,
        };
        let input = AckInput {
            ack,
            scoreboard,
            now,
            echo,
            timestamps,
            mss,
        };
        // After the splits, every interval lies wholly in or out of a range.
        let (ranges, len) = self.index_ranges(&spans[..count]);
        for &(a, b) in &ranges[..len] {
            let mut i = a;
            while i < b {
                if !self.newly_covered(i, &input) {
                    i += 1;
                    continue;
                }
                let mut j = i + 1;
                while j < b && self.newly_covered(j, &input) {
                    j += 1;
                }
                self.retally(i, j, |s| {
                    for k in i..j {
                        s.deliver(k, &input, &mut walk);
                    }
                });
                i = j;
            }
        }
        #[cfg(debug_assertions)]
        for i in 0..self.intervals.len() {
            debug_assert!(!self.newly_covered(i, &input));
        }
        let delivered = walk.delivered;
        self.reordering_events = self
            .reordering_events
            .saturating_add(u64::from(walk.sack_reordered) + u64::from(walk.cumulative_reordered));
        if let Some((sent, end, rtt, retransmitted)) = walk.newest {
            if !retransmitted {
                self.ack_sample = Some(rtt);
                self.sample(rtt, now);
            }
            self.rtt = rtt;
            if self.latest.is_none_or(|old| sent_after((sent, end), old)) {
                self.latest = Some((sent, end));
            }
            // Karn: retransmissions can advance RACK, not the ordinary RTT estimator.
        }
        let acked = self.locate(ack);
        self.remove_prefix(acked);
        if self.dsack_round.is_some_and(|end| !end.after(ack)) {
            self.dsack_round = None;
        }
        if dsack && self.dsack_round.is_none() {
            self.dsack_round = Some(high);
            self.multiplier = self.multiplier.saturating_add(1).min(MAX_MULTIPLIER);
            self.persist = 16;
            self.reo_grew = true;
            self.reordering_seen = true;
        }
        self.verify();
        delivered
    }

    // `acknowledge_within` with no bound on SACK splits but the entries.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn acknowledge(
        &mut self,
        ack: Seq,
        high: Seq,
        scoreboard: &mut Scoreboard,
        now: u64,
        echo: Option<u32>,
        timestamps: Option<TimestampGranularity>,
        mss: u32,
        dsack: bool,
    ) -> u32 {
        self.acknowledge_within(
            ack,
            high,
            scoreboard,
            now,
            echo,
            timestamps,
            mss,
            dsack,
            SplitBound::NONE,
        )
    }

    // Splits the entry a SACK block's edge falls inside, unless the split
    // would take one of the SPARE entries, or the entry is neither the
    // first one above the cumulative ACK nor the last one and send usage
    // passed the bound: Linux's tcp_fragment refusing (TCPWqueueTooBig),
    // after which tcp_sacktag_walk leaves the skb untagged. A refused entry
    // stays whole and unmarked: the block yields no inference about it, and
    // it is marked once blocks or the cumulative ACK cover all of it
    // (duvet exception to RFC 8985 section 4, rfc8985-todos.toml).
    fn sack_split(&mut self, edge: Seq, ack: Seq, bound: SplitBound) {
        let Some(i) = self.inside(edge) else {
            return;
        };
        let len = self.intervals.len();
        let end = i == self.locate(ack) || i + 1 == len;
        if len + SPARE >= self.capacity || !end && bound.refuses(len) {
            self.split_refusals = self.split_refusals.saturating_add(1);
            return;
        }
        self.split(edge);
    }

    // Covered by this ACK or its scoreboard but not marked yet.
    fn newly_covered(&self, i: usize, input: &AckInput) -> bool {
        let r = &self.intervals[i];
        !r.sacked
            && (!r.end.after(input.ack) || input.scoreboard.unsacked_bytes(r.start, r.end) == 0)
    }

    // Marks one newly covered interval delivered, in sequence order.
    fn deliver(&mut self, i: usize, input: &AckInput, walk: &mut AckWalk) {
        let (ack, scoreboard) = (input.ack, input.scoreboard);
        let r = &mut self.intervals[i];
        let cumulative = !r.end.after(ack);
        let packet_complete = !r.transmission_end.after(ack)
            || scoreboard.unsacked_bytes(
                if r.transmission_start.after(ack) {
                    r.transmission_start
                } else {
                    ack
                },
                r.transmission_end,
            ) == 0;
        if !r.delivered {
            walk.delivered += r.end.distance_from(r.start);
            r.delivered = true;
        }
        if !r.original_retransmitted
            && let Some(fack) = self.fack
            && fack.after(r.end)
        {
            self.reordering_seen = true;
            self.reordering = self
                .reordering
                .max(fack.distance_from(r.start).div_ceil(input.mss));
            // Preserve loss detection's existing proof. Diagnostics
            // aggregate each evidence stage, not its split intervals;
            // cumulative filling refers to the pre-ACK frontier.
            if cumulative {
                walk.cumulative_reordered |= walk.prior_fack.is_some_and(|old| old.after(r.end));
            } else {
                walk.sack_reordered = true;
            }
        }
        if self.fack.is_none_or(|old| r.end.after(old)) {
            self.fack = Some(r.end);
        }
        let rtt = input.now.saturating_sub(r.sent);
        let eligible = packet_complete
            && r.sent >= self.sample_floor
            && (r.retransmitted || !r.original_retransmitted)
            && (!r.retransmitted
                || (rtt >= self.min_rtt.unwrap_or(u64::MAX)
                    && input.timestamps.is_none_or(|granularity| {
                        r.timestamp_eligible
                            && input.echo == Some(granularity.tick_in(r.sent, self.timebase) as u32)
                    })));
        if eligible
            && walk
                .newest
                .is_none_or(|old| sent_after((r.sent, r.transmission_end), (old.0, old.1)))
        {
            walk.newest = Some((r.sent, r.transmission_end, rtt, r.retransmitted));
        }
        r.sacked = true;
        r.original_lost = false;
        r.needs_retransmit = false;
    }

    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Fast/RTO exit decrements persistence unless this same ACK grew the window; resets multiplier on zero.
    //# Else if exiting Fast or RTO recovery:
    //# RACK.reo_wnd_persist -= 1
    //# If RACK.reo_wnd_persist <= 0:
    //# RACK.reo_wnd_mult = 1
    pub(crate) fn recovery_exit(&mut self, grew: bool) {
        if grew {
            return;
        }
        self.persist = self.persist.saturating_sub(1);
        if self.persist == 0 {
            self.multiplier = 1;
        }
    }

    #[cfg(test)]
    pub(crate) fn adaptation(&self) -> (u128, u8) {
        (self.multiplier, self.persist)
    }

    //= https://www.rfc-editor.org/rfc/rfc8985#section-3.3.2
    //= reason=Zero window without observed reordering in recovery or after three complete SACKed logical segments.
    //# The reordering window SHOULD be set to zero if no reordering has
    //# been observed on the connection so far, and either (a) three
    //# segments have been SACKed since the last recovery or (b) the
    //# sender is already in fast or RTO recovery.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-3.3.2
    //= reason=Starts at min_RTT/4 with zero for missing estimates; SRTT bound applies.
    //# Otherwise, the
    //# reordering window SHOULD start from a small fraction of the
    //# round-trip time or zero if no round-trip time estimate is
    //# available.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-3.3.2
    //= reason=u128 bounded multiplier/product allows every positive u64 minimum to reach SRTT; effective window is capped at SRTT (zero if unavailable).
    //# The RACK reordering window MUST be bounded, and this bound SHOULD
    //# be SRTT.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Observed reordering preserves nonzero settling window regardless of complete SACK count/recovery.
    //# Otherwise, if some reordering has been observed, then RACK does not
    //# trigger fast recovery based on DupThresh.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Implements zeroing after three complete SACKed original wire packets or in recovery only without observed reordering; otherwise multiplies before integer division by four and caps at SRTT. Missing estimates yield zero.
    //# If RACK.reordering_seen is FALSE:
    //# If in Fast or RTO recovery:
    //# Return 0
    //# Else if RACK.segs_sacked >= DupThresh:
    //# Return 0
    //# Return min(RACK.reo_wnd_mult * RACK.min_RTT / 4, SRTT)
    fn reo_window(&self, recovery: bool, srtt: Option<u64>) -> u64 {
        if !self.reordering_seen && (recovery || self.packet_counts().sacked >= 3) {
            return 0;
        }
        // Divide after multiplication, including minima below four caller ticks.
        // An overflowing u128 product / 4 still exceeds every u64 SRTT.
        ((u128::from(self.min_rtt.unwrap_or(0)).saturating_mul(self.multiplier) / 4)
            .min(u128::from(srtt.unwrap_or(0)))) as u64
    }

    // RFC 8985 §6.2: maximum remaining eligible interval, not minimum.
    // Return whether newly lost retransmission copies require another response.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Computes maximum remaining eligible deadline so all eligible intervals have expired when serviced; loss marking is one-shot until retransmit.
    //# For timely loss detection, it is RECOMMENDED that the
    //# sender install a reordering timer.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Uses serial tie-break, RTT+window deadline and maximum remaining deadline. needs_retransmit excludes lost intervals from pipe/repeated detection, equivalent to invalid in-flight timestamp; stored timestamp retained for diagnostics.
    //# RACK_detect_loss():
    //# timeout = 0
    //# RACK.reo_wnd = RACK_update_reo_wnd()
    //# For each segment, Segment, not acknowledged yet:
    //# If RACK_sent_after(RACK.xmit_ts, RACK.end_seq,
    //# Segment.xmit_ts, Segment.end_seq):
    //# remaining = Segment.xmit_ts + RACK.rtt +
    //# RACK.reo_wnd - Now()
    //# If remaining <= 0:
    //# Segment.lost = TRUE
    //# Segment.xmit_ts = INFINITE_TS
    //# Else:
    //# timeout = max(remaining, timeout)
    //# Return timeout
    pub(crate) fn detect(&mut self, now: u64, recovery: bool, srtt: Option<u64>) -> bool {
        self.deadline = None;
        let window = self.reo_window(recovery, srtt);
        let Some(latest) = self.latest else {
            return false;
        };
        let mut retransmission_lost = false;
        for i in 0..self.intervals.len() {
            let r = &self.intervals[i];
            if r.sacked || r.needs_retransmit || !sent_after(latest, (r.sent, r.end)) {
                continue;
            }
            let deadline = r.sent.saturating_add(self.rtt).saturating_add(window);
            if now >= deadline {
                retransmission_lost |= r.retransmitted && r.loss_response_pending;
                self.retally(i, i + 1, |s| {
                    let r = &mut s.intervals[i];
                    r.original_lost = true;
                    r.needs_retransmit = true;
                    r.set_stats_flag(DIAGNOSTIC_LOST, true);
                });
            } else {
                self.deadline = Some(self.deadline.map_or(deadline, |old| old.max(deadline)));
            }
        }
        if retransmission_lost {
            // Snapshot the currently committed transmission window. Later ACKs
            // losing older copies share this response, but replacements sent
            // after it renew their marker even with identical time/sequence.
            for r in self.intervals.iter_mut() {
                r.loss_response_pending = false;
            }
        }
        self.verify();
        retransmission_lost
    }

    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.3
    //= reason=First unacknowledged interval is lost regardless of age, others only at recent RTT+window; clears SACK advice for possible reneging.
    //# Upon RTO timer expiration, RACK marks the first outstanding segment
    //# as lost (since it was sent an RTO ago); for all the other segments,
    //# RACK only marks the segment as lost if the time elapsed since the
    //# segment was transmitted is at least the sum of the recent RTT and the
    //# reordering window.
    pub(crate) fn rto(&mut self, now: u64, ack: Seq, srtt: Option<u64>) {
        let window = self.reo_window(true, srtt);
        self.deadline = None;
        for r in self.intervals.iter_mut() {
            // RTO discards prior SACK advice (possible receiver reneging).
            r.sacked = false;
            r.delivered = false;
            if r.start == ack || now >= r.sent.saturating_add(self.rtt).saturating_add(window) {
                r.original_lost = true;
                r.needs_retransmit = true;
                r.set_stats_flag(DIAGNOSTIC_LOST, true);
            }
        }
        let len = self.intervals.len();
        self.tally = self.contribution(Hull {
            items: (0, len),
            packets: (0, len),
            units: (0, len),
        });
        // Any advice still held must be marked again.
        self.rescan = true;
        self.verify();
    }

    // Ordinary fast retransmit / NewReno partial ACK marks the missing head.
    // Retain the original packet edge across short retries and ledger splits.
    pub(crate) fn mark_head_lost(&mut self) {
        if let Some(end) = self.intervals.first().map(|r| r.original_wire_end) {
            let count = self
                .intervals
                .iter()
                .take_while(|r| r.original_wire_end == end)
                .count();
            self.retally(0, count, |s| {
                for r in s.intervals.range_mut(0, count) {
                    if !r.sacked {
                        r.original_lost = true;
                        r.needs_retransmit = true;
                        r.set_stats_flag(DIAGNOSTIC_LOST, true);
                    }
                }
            });
        }
        self.verify();
    }

    pub(crate) fn mark_scoreboard_losses(&mut self, scoreboard: &Scoreboard, mss: u32) -> bool {
        let mut newly_lost = false;
        for i in 0..self.intervals.len() {
            let r = &self.intervals[i];
            if !r.sacked && !r.retransmitted && scoreboard.is_lost(r.start, mss) {
                newly_lost |= !r.needs_retransmit;
                self.retally(i, i + 1, |s| {
                    let r = &mut s.intervals[i];
                    r.original_lost = true;
                    r.needs_retransmit = true;
                    r.set_stats_flag(DIAGNOSTIC_LOST, true);
                });
            }
        }
        self.verify();
        newly_lost
    }

    // SACK splits are byte accounting, not packet boundaries. Include even the
    // SACKed pieces of the highest original segment (RFC 8985 section 7.3).
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= reason=Finds highest original segment, including its SACKed pieces; MSS may clip a suffix but never select an earlier packet.
    //# If such an unsent segment is not available, then the sender SHOULD
    //# retransmit the highest-sequence segment sent so far and set
    //# TLP.is_retrans to true.
    pub(crate) fn tail_segment(&self, mss: u32) -> Option<(Seq, Seq)> {
        if !self.valid() {
            return None;
        }
        let tail = self.intervals.last()?;
        let first = self
            .intervals
            .iter()
            .rev()
            .take_while(|r| r.original_wire_end == tail.original_wire_end)
            .last()?;
        let size = tail.end.distance_from(first.start).min(mss);
        Some((tail.end.wrapping_add(0u32.wrapping_sub(size)), tail.end))
    }

    pub(crate) fn lowest_lost(&self, mss: u32) -> Option<(Seq, Seq)> {
        if self.tally.lost == 0 {
            return None;
        }
        let first = self
            .intervals
            .iter()
            .find(|r| !r.sacked && r.needs_retransmit)?;
        // RFC 6675 §4 starts at the lowest unSACKed byte, up to SMSS;
        // §5.1 leaves post-RTO packetization unspecified. Keep RACK's original
        // packet boundary: SACK splits account bytes, not new packets (RFC 2018 §5).
        // A redundant suffix is allowed, but never include the next packet.
        let size = first.original_wire_end.distance_from(first.start).min(mss);
        Some((first.start, first.start.wrapping_add(size)))
    }

    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
    //= reason=Valid payload ledger: unsacked and not-needs_retransmit intervals count once; successful retransmission clears needs_retransmit for only emitted bytes. Exact reordered original, lost-copy and replacement pipe values are asserted. SYN/FIN sequence space is not payload data.
    //# SACK-enabled connections using RACK-TLP loss detection
    //# [RFC8985] or other loss detection algorithms MUST calculate inflight
    //# by starting with SND.NXT - SND.UNA, subtracting out bytes SACKed in
    //# the scoreboard, subtracting out bytes marked lost in the scoreboard,
    //# and adding bytes in the scoreboard that have been retransmitted since
    //# they were last marked lost.
    pub(crate) fn pipe(&self) -> u32 {
        self.tally.pipe
    }

    // Ranges inside [start, end) that pipe() no longer counts because they
    // await retransmission. The ledger is ordered by sequence, so a binary
    // search finds the first interval; cost follows the intervals visited.
    pub(crate) fn lost_ranges(
        &self,
        start: Seq,
        end: Seq,
    ) -> impl Iterator<Item = (Seq, Seq)> + '_ {
        let len = self.intervals.len();
        let first = if let Some(base) = self.intervals.first().map(|r| r.start) {
            let target = start.distance_from(base);
            let (mut low, mut high) = (0, len);
            if target < 1 << 31 {
                while low < high {
                    let mid = (low + high) / 2;
                    if self.intervals[mid].end.distance_from(base) <= target {
                        low = mid + 1;
                    } else {
                        high = mid;
                    }
                }
            }
            low
        } else {
            0
        };
        self.intervals
            .range(first, len)
            .take_while(move |r| end.after(r.start))
            .filter(|r| !r.sacked && r.needs_retransmit)
            .map(move |r| {
                (
                    if r.start.after(start) { r.start } else { start },
                    if end.after(r.end) { r.end } else { end },
                )
            })
    }

    // PTB repair bytes in intervals awaiting retransmission and not SACKed:
    // those pipe() no longer counts. count returns the marked bytes of a
    // range; only Some intervals are counted. None when they are too
    // scattered to be found but by a walk.
    pub(crate) fn ptb_lost(&self, mut count: impl FnMut(Seq, Seq) -> u32) -> Option<u32> {
        if self.ptb_some_all {
            return None;
        }
        let mut lost = self.tally.ptb_lost;
        for &(start, end) in &self.ptb_some[..self.ptb_some_len] {
            let (first, last) = self.overlapping(start, end);
            for r in self.intervals.range(first, last) {
                if r.ptb == Ptb::Some && !r.sacked && r.needs_retransmit {
                    lost += count(r.start, r.end);
                }
            }
        }
        Some(lost)
    }

    // The PTB marks of [start, end) changed: restate every interval
    // overlapping it from count (the marked bytes of a range). Cost follows
    // those intervals and their bytes.
    pub(crate) fn restate_ptb(
        &mut self,
        start: Seq,
        end: Seq,
        mut count: impl FnMut(Seq, Seq) -> u32,
    ) {
        if !end.after(start) {
            return;
        }
        let (first, last) = self.overlapping(start, end);
        for i in first..last {
            self.restate_one(i, &mut count);
        }
        self.verify();
    }

    fn restate_one(&mut self, i: usize, count: &mut impl FnMut(Seq, Seq) -> u32) {
        let r = &self.intervals[i];
        let len = r.end.distance_from(r.start);
        let ptb = match count(r.start, r.end) {
            0 => Ptb::None,
            n if n == len => Ptb::All,
            _ => Ptb::Some,
        };
        if ptb == Ptb::Some {
            self.note_ptb_some(r.start, r.end);
        }
        let r = &mut self.intervals[i];
        if !r.sacked && r.needs_retransmit {
            if r.ptb == Ptb::All {
                self.tally.ptb_lost -= len;
            }
            if ptb == Ptb::All {
                self.tally.ptb_lost += len;
            }
        }
        r.ptb = ptb;
    }

    // Restate the Some intervals, so that the noted ranges hold only those
    // still partly carrying PTB work.
    pub(crate) fn settle_ptb(&mut self, mut count: impl FnMut(Seq, Seq) -> u32) {
        let (mut spans, mut len) = (self.ptb_some, self.ptb_some_len);
        if self.ptb_some_all {
            len = 0;
            if let (Some(first), Some(last)) = (self.intervals.first(), self.intervals.last()) {
                spans[0] = (first.start, last.end);
                len = 1;
            }
        }
        self.ptb_some_len = 0;
        self.ptb_some_all = false;
        for &(start, end) in &spans[..len] {
            let (first, last) = self.overlapping(start, end);
            for i in first..last {
                if self.intervals[i].ptb == Ptb::Some {
                    self.restate_one(i, &mut count);
                }
            }
        }
        self.verify();
    }

    fn note_ptb_some(&mut self, start: Seq, end: Seq) {
        if self.ptb_some_all {
            return;
        }
        let (mut start, mut end) = (start, end);
        // Join every noted range touching it, keeping the ranges disjoint.
        let mut kept = 0;
        for k in 0..self.ptb_some_len {
            let span = self.ptb_some[k];
            if !start.after(span.1) && !span.0.after(end) {
                if start.after(span.0) {
                    start = span.0;
                }
                if span.1.after(end) {
                    end = span.1;
                }
            } else {
                self.ptb_some[kept] = span;
                kept += 1;
            }
        }
        if kept < PTB_SOME_SPANS {
            self.ptb_some[kept] = (start, end);
            self.ptb_some_len = kept + 1;
        } else {
            self.ptb_some_all = true;
        }
    }

    // SACK/ACK splits are not short wire packets: use the committed span.
    pub(crate) fn has_short_transmission(&mut self, mss: u32) -> bool {
        if mss != self.short_mss {
            self.short_mss = mss;
            self.tally.short = self
                .intervals
                .iter()
                .filter(|r| r.transmission_end.distance_from(r.transmission_start) < mss)
                .count() as u32;
        }
        self.tally.short != 0
    }

    // Diagnostic/accounting identity remains the logical selection, not local
    // repair packetization (which must not manufacture new loss/retry counts).
    pub(crate) fn empty_valid(&self) -> bool {
        self.valid() && self.intervals.is_empty()
    }

    // Only a whole fresh selection with no physical acceptance or feedback.
    // Generations never roll back, so a cancelled token cannot be replayed.
    pub(crate) fn cancel_unsubmitted_fresh(&mut self, selection: DepartureSelection) -> bool {
        if !self.valid()
            || self.departure_selection != Some(selection)
            || selection.retransmit
            || self.intervals.is_empty()
            || self.intervals.iter().any(|r| {
                r.departure_committed
                    || r.retransmitted
                    || r.sacked
                    || r.original_start != selection.start
                    || r.original_end != selection.end
            })
        {
            return false;
        }
        self.intervals.clear();
        self.tally = Tally::default();
        self.dirty_len = 0;
        self.ptb_some_len = 0;
        self.ptb_some_all = false;
        self.departure_selection = None;
        true
    }

    pub(crate) fn counts(&self) -> Counts {
        self.count_by_original(false)
    }

    // Packet-unit consumers must distinguish the original wire segments of a
    // single logical admission. ACK/SACK splits preserve these boundaries;
    // later retry repacketization must not create extra original packets.
    // Linux-style queued packetization statistics are independent of the
    // original-wire identities consumed by RACK/TLP. Commit, not selection,
    // supplies boundaries and retry status; ACK/SACK splits retain them.
    pub(crate) fn diagnostic_packet_counts(&self) -> Counts {
        self.tally.units
    }

    pub(crate) fn packet_counts(&self) -> Counts {
        self.tally.packets
    }

    fn count_by_original(&self, physical: bool) -> Counts {
        let mut counts = Counts::default();
        let mut intervals = self.intervals.iter().peekable();
        while let Some(first) = intervals.next() {
            let mut sacked = first.sacked;
            let mut lost = first.original_lost && !first.sacked;
            let mut retransmitted = first.retransmitted && !first.sacked && !first.needs_retransmit;
            while let Some(next) = intervals.peek() {
                let same = if physical {
                    first.original_wire_start == next.original_wire_start
                        && first.original_wire_end == next.original_wire_end
                } else {
                    first.original_end == next.original_end
                };
                if !same {
                    break;
                }
                let next = intervals.next().unwrap();
                sacked &= next.sacked;
                lost |= next.original_lost && !next.sacked;
                retransmitted |= next.retransmitted && !next.sacked && !next.needs_retransmit;
            }
            counts.unacked += 1;
            counts.sacked += u32::from(sacked);
            counts.lost += u32::from(lost);
            counts.retransmitted += u32::from(retransmitted);
        }
        counts
    }
}

#[cfg(test)]
#[path = "rack_tests.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "rack_reference.rs"]
mod reference;

#[cfg(test)]
#[path = "rack_equivalence_tests.rs"]
mod equivalence_tests;

#[cfg(test)]
mod diagnostic_packetization_tests {
    use super::*;
    #[test]
    fn committed_resegmentation_preserves_recovery_identity_and_rejection_snapshot() {
        let mut r = Rack::with_capacity(16).unwrap();
        r.transmit(Seq(100), Seq(1420), 0, false);
        let original = r.departure_selection().unwrap();
        assert!(r.commit_departure(original, Seq(100), Seq(1420), 0));
        assert_eq!(r.diagnostic_packet_counts().unacked, 1);
        r.mark_head_lost();
        r.transmit(Seq(100), Seq(1420), 1, true);
        let retry = r.departure_selection().unwrap();
        assert_eq!(r.diagnostic_packet_counts().unacked, 1);
        assert_eq!(r.diagnostic_packet_counts().retransmitted, 0);
        assert!(r.commit_departure(retry, Seq(100), Seq(1100), 2));
        assert_eq!(r.diagnostic_packet_counts().unacked, 2);
        assert_eq!(r.diagnostic_packet_counts().retransmitted, 1);
        assert_eq!(r.packet_counts().unacked, 1);
        assert!(r.commit_departure(retry, Seq(1100), Seq(1420), 3));
        assert_eq!(r.diagnostic_packet_counts().unacked, 2);
        assert_eq!(r.diagnostic_packet_counts().retransmitted, 2);
        assert_eq!(r.packet_counts().unacked, 1);
        assert_eq!(r.pipe(), 1320);
    }
}
