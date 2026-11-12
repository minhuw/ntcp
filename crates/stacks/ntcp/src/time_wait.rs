//! TIME-WAIT without a connection. Once a connection in TIME-WAIT has no
//! application owner, the Endpoint keeps only what TIME-WAIT still needs
//! (Linux's inet_timewait_sock): the tuple, both sequence frontiers, the
//! timestamp state, the challenge-ACK budget and the timer. The connection,
//! its buffers and its slot are freed.
extern crate alloc;

use alloc::{boxed::Box, vec::Vec};

use crate::{
    OutgoingIpv4Options,
    connection::{
        ConnectionConfig, Instant, PAWS_RECENT_EXPIRY_US, PEER_TS_RECENT_IDLE_US, ScopedTuple,
    },
    seq::Seq,
    wire::{ACK, FIN, Header, RST, SYN, Segment, URG},
};

const NONE: u32 = u32::MAX;

// What the connection leaves to its TIME-WAIT record, taken when it has no
// output left (`Connection::time_wait_record`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Record {
    pub(crate) tuple: ScopedTuple,
    pub(crate) snd_nxt: Seq,
    pub(crate) rcv_nxt: Seq,
    // SND.UNA - MAX.SND.WND, the oldest acceptable SEG.ACK (RFC 5961 5.2).
    pub(crate) ack_floor: Seq,
    pub(crate) timestamps: bool,
    pub(crate) timestamp_offset: u32,
    pub(crate) ts_recent: u32,
    pub(crate) ts_latest: u32,
    pub(crate) ts_recent_at: Instant,
    pub(crate) last_timestamp_sent_at: Option<Instant>,
    pub(crate) deadline: Instant,
    pub(crate) challenge_start: Option<Instant>,
    pub(crate) challenge_sent: u32,
    pub(crate) ack_pending: bool,
    pub(crate) challenge_pending: bool,
    pub(crate) hop_limit: u8,
    pub(crate) dscp: u8,
    // The connection's mark when it entered TIME-WAIT (Linux's tw_mark).
    pub(crate) mark: u32,
    // The connection's SO_REUSEADDR when it entered TIME-WAIT (tw_reuse).
    pub(crate) reuse_address: bool,
    pub(crate) ipv4_options: OutgoingIpv4Options,
    // The complete IP header length of the path a managed reply leaves on,
    // as a managed input stated it (see the Endpoint's control replies).
    pub(crate) reply_header: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Input {
    Kept,
    // An acceptable RST ended TIME-WAIT.
    Reset,
}

impl Record {
    fn timestamp_value(&self, now: Instant, config: &ConnectionConfig) -> u32 {
        (config.timestamp_granularity.tick_in(now, config.timebase) as u32)
            .wrapping_add(self.timestamp_offset)
    }

    fn refresh_challenge_budget(&mut self, now: Instant, config: &ConnectionConfig) {
        if self.challenge_start.is_none_or(|start| {
            now.saturating_sub(start)
                >= config
                    .timebase
                    .ticks_from_us(config.challenge_ack_interval_us)
        }) {
            self.challenge_start = Some(now);
            self.challenge_sent = 0;
        }
    }

    fn challenge(&mut self, now: Instant, config: &ConnectionConfig) {
        self.refresh_challenge_budget(now, config);
        if self.challenge_sent < config.challenge_ack_limit {
            self.challenge_pending = true;
        }
    }

    pub(crate) fn valid(&self, now: Instant) -> bool {
        now < self.deadline
    }

    pub(crate) fn owes_output(&self) -> bool {
        self.ack_pending || self.challenge_pending
    }

    // The TIME-WAIT branch of `Connection::input_authorized`, step for step:
    // a TIME-WAIT connection is neither synchronized nor in a handshake, so
    // only PAWS, the SYN challenge, the FIN retransmission, acceptability,
    // RST and the ACK range check apply, and none of them admits data.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= reason=The restarted timeout is the configured TIME-WAIT duration, not 2xMSL; the section 3.6.1 exception records that deviation.
    //# The only thing that can arrive in this state is a retransmission of the
    //# remote FIN. Acknowledge it, and restart the 2 MSL timeout.
    pub(crate) fn input(
        &mut self,
        now: Instant,
        segment: &Segment<'_>,
        config: &ConnectionConfig,
    ) -> Input {
        let granularity = config.timestamp_granularity;
        if self.last_timestamp_sent_at.is_some_and(|sent| {
            granularity
                .tick_in(now, config.timebase)
                .saturating_sub(granularity.tick_in(sent, config.timebase))
                >= 1 << 31
        }) {
            self.last_timestamp_sent_at = None;
        }
        let h = segment.header;
        let seq = Seq(h.sequence);
        let ack = Seq(h.acknowledgment);
        let recent_valid = now.saturating_sub(self.ts_recent_at)
            < config.timebase.ticks_from_us(PAWS_RECENT_EXPIRY_US);
        //= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
        //= reason=Negotiated PAWS/missing TS gate precedes receive-window, RST-exempt, ACK and metadata processing. R1 drop schedules ACK; regular R2/R4/R5 follows for accepted TS.
        //# If the PAWS algorithm is used, the following processing MUST be
        //# performed on all incoming segments for a synchronized connection.
        if self.timestamps && h.flags & RST == 0 {
            let Some((value, _)) = segment.options.timestamps else {
                if h.flags & SYN != 0 {
                    self.challenge(now, config);
                }
                return Input::Kept;
            };
            if recent_valid && !Seq(value).at_or_after(Seq(self.ts_recent)) {
                if h.flags & SYN != 0 {
                    self.challenge(now, config);
                } else {
                    self.ack_pending = true;
                }
                return Input::Kept;
            }
        }
        //= https://www.rfc-editor.org/rfc/rfc5961#section-4.2
        //= reason=Selected RFC5961 mitigation challenges and drops synchronized non-handshake SYN regardless of TS presence/sequence, under the existing bounded challenge budget. Narrow RFC7323 missing-TS SHOULD departure accepts no data/ACK/metadata/TS updates; valid/stale TS still traverse PAWS and RST remains exempt. Precedence/output rollback matrix covers all three TS cases.
        //# 1) If the SYN bit is set, irrespective of the sequence number, TCP
        //# MUST send an ACK (also referred to as challenge ACK) to the remote
        //# peer:
        if h.flags & (SYN | RST) == SYN {
            self.challenge(now, config);
            return Input::Kept;
        }
        // A duplicate FIN falls just below RCV.NXT after its first receipt.
        if h.flags & (FIN | ACK | RST | SYN) == (FIN | ACK)
            && seq
                .wrapping_add(segment.payload.len() as u32)
                .wrapping_add(1)
                == self.rcv_nxt
        {
            if self.timestamps
                && let Some((value, _)) = segment.options.timestamps
                && (!recent_valid || Seq(value).after(Seq(self.ts_latest)))
            {
                self.ts_latest = value;
            }
            self.ack_pending = true;
            self.deadline = now.saturating_add(config.timebase.ticks_from_us(config.time_wait_us));
            return Input::Kept;
        }
        let len = segment.payload.len() as u64
            + u64::from(h.flags & SYN != 0)
            + u64::from(h.flags & FIN != 0);
        // RCV.WND is zero: the ACK of the peer's FIN, sent before the record
        // was made, offered no window past it.
        let next = self.rcv_nxt;
        let acceptable = if h.flags & RST != 0 {
            seq == next
        } else {
            seq == next && (len == 0 || h.flags & (ACK | URG) != 0)
        };
        if !acceptable {
            if h.flags & RST == 0 {
                self.ack_pending = true;
            }
            return Input::Kept;
        }
        //= https://www.rfc-editor.org/rfc/rfc5961#section-3.2
        //= reason=Selected RST/SYN defenses: existing state/sequence matrix asserts exact reset termination, outside reset silence, nonexact in-window challenge and SYN challenge fields/drop. Matrix exercises sequence wrap and rejects appended text/URG/FIN/ACK effects.
        //# 2) If the RST bit is set and the sequence number exactly matches the
        //# next expected sequence number (RCV.NXT), then TCP MUST reset the
        //# connection.
        // Without a window, only RCV.NXT is acceptable: no RST is challenged.
        if h.flags & RST != 0 {
            return Input::Reset;
        }
        if h.flags & ACK == 0 {
            return Input::Kept;
        }
        //= https://www.rfc-editor.org/rfc/rfc5961#section-5.2
        //= reason=Inclusive lower/upper bounds, adjacent invalid values and modular wrap are explicitly asserted.
        //# The ACK value is considered acceptable only if it is in the range of ((SND.UNA - MAX.SND.WND) <= SEG.ACK <= SND.NXT).
        if !self.snd_nxt.at_or_after(ack) || !ack.at_or_after(self.ack_floor) {
            self.ack_pending = true;
            return Input::Kept;
        }
        if self.timestamps
            && let Some((value, _)) = segment.options.timestamps
        {
            if !recent_valid || Seq(value).after(Seq(self.ts_latest)) {
                self.ts_latest = value;
            }
            //= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
            //= reason=Accepted synchronized non-RST traffic uses serial nondecrease and last successful ACK gate; expired baseline is separate section5.5 path.
            //# R3)  If an arriving segment satisfies SEG.TSval >= TS.Recent and
            //# SEG.SEQ <= Last.ACK.sent (see Section 4.3), then record its
            //# timestamp in TS.Recent.
            // Last.ACK.sent is RCV.NXT, for the same reason.
            if self.rcv_nxt.at_or_after(seq)
                && (!recent_valid || Seq(value).at_or_after(Seq(self.ts_recent)))
            {
                self.ts_recent = value;
                self.ts_recent_at = now;
            }
        }
        Input::Kept
    }

    // The pure ACK a TIME-WAIT connection sends: SND.NXT, RCV.NXT, a zero
    // window (the peer's FIN ends the receive stream) and, when negotiated,
    // TSval and TS.Recent. Returns the header and its options.
    pub(crate) fn ack(&self, now: Instant, config: &ConnectionConfig) -> (Header, [u8; 12], usize) {
        let header = Header {
            source_port: self.tuple.tuple.local.port(),
            destination_port: self.tuple.tuple.remote.port(),
            sequence: self.snd_nxt.0,
            acknowledgment: self.rcv_nxt.0,
            flags: ACK,
            window: 0,
            urgent_pointer: 0,
        };
        let mut options = [1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0];
        if !self.timestamps {
            return (header, options, 0);
        }
        options[4..8].copy_from_slice(&self.timestamp_value(now, config).to_be_bytes());
        options[8..].copy_from_slice(&self.ts_recent.to_be_bytes());
        (header, options, 12)
    }

    // Commits the ACK `ack` built, once it is encoded.
    pub(crate) fn sent(&mut self, now: Instant, config: &ConnectionConfig) {
        if self.challenge_pending {
            self.refresh_challenge_budget(now, config);
            self.challenge_sent += 1;
        }
        self.challenge_pending = false;
        self.ack_pending = false;
        if self.timestamps {
            self.last_timestamp_sent_at = Some(now);
        }
    }

    // `Connection::next_timestamp_appears_older`: across a suspend, a TSval
    // the peer could still compare with its TS.Recent would look older.
    pub(crate) fn timestamp_appears_older(&self, now: Instant, config: &ConnectionConfig) -> bool {
        let Some(sent) = self.last_timestamp_sent_at.filter(|_| self.timestamps) else {
            return false;
        };
        let tick = |at| config.timestamp_granularity.tick_in(at, config.timebase);
        (tick(now) - tick(sent)) as u32 >= 1 << 31
            && now - sent <= config.timebase.ticks_from_us(PEER_TS_RECENT_IDLE_US)
    }

    pub(crate) fn reuse_syn(&self, now: Instant, syn: &Segment<'_>, timestamps: bool) -> bool {
        self.valid(now)
            && fresh_syn(
                self.timestamps,
                self.ts_latest,
                self.rcv_nxt,
                syn,
                timestamps,
            )
    }

    pub(crate) fn reuse_iss(&self, candidate: u32) -> u32 {
        reincarnation_iss(self.snd_nxt, candidate)
    }
}

// RFC 6191 freshness of a SYN for a new incarnation of a TIME-WAIT
// connection (`Connection::reuse_syn`) or record: `timestamps` tells whether
// the new incarnation would use them. RCV.NXT acknowledges the peer FIN.
// Compare strictly after FIN itself so FIN+1 is fresh and the exact serial
// half-space from FIN remains unordered.
pub(crate) fn fresh_syn(
    old_timestamps: bool,
    ts_latest: u32,
    rcv_nxt: Seq,
    syn: &Segment<'_>,
    timestamps: bool,
) -> bool {
    let peer_fin = rcv_nxt.wrapping_add(u32::MAX);
    let newer_sequence = Seq(syn.header.sequence).after(peer_fin);
    match (
        old_timestamps,
        timestamps.then_some(syn.options.timestamps).flatten(),
    ) {
        (true, Some((value, _))) => {
            Seq(value).after(Seq(ts_latest)) || value == ts_latest && newer_sequence
        }
        (false, Some(_)) => true,
        (_, None) => newer_sequence,
    }
}

// The new incarnation's ISS: the candidate, preserving its secret-derived
// entropy, projected into the forward serial half-space from SND.NXT only
// when necessary. Pure ACKs at SND.NXT count in the old frontier: offsets
// 1..2^31-1 are strictly serially greater.
pub(crate) fn reincarnation_iss(snd_nxt: Seq, candidate: u32) -> u32 {
    if Seq(candidate).after(snd_nxt) {
        candidate
    } else {
        snd_nxt.wrapping_add(1 + candidate % 0x7fff_ffff).0
    }
}

#[derive(Clone, Copy)]
struct Links {
    previous: u32,
    next: u32,
}
const UNLINKED: Links = Links {
    previous: NONE,
    next: NONE,
};

struct Entry {
    record: Record,
    hash: u64,
    // The next record in its bucket's chain.
    next: u32,
    // Position in the timer heap.
    timer: u32,
    output: Links,
    queued: bool,
}

// A record's own allocation, as Linux allocates an inet_timewait_sock per
// TIME-WAIT. `Box::new` cannot fail, so the box comes from a vector.
type Stored = Option<Box<[Entry; 1]>>;

fn allocate(entry: Entry) -> Stored {
    let mut storage = Vec::new();
    storage.try_reserve_exact(1).ok()?;
    storage.push(entry);
    storage.into_boxed_slice().try_into().ok()
}

fn at(entries: &mut [Stored], index: u32) -> &mut Entry {
    &mut entries[index as usize].as_mut().unwrap()[0]
}

#[derive(Clone, Copy, Default)]
struct Ends {
    first: Option<u32>,
    last: Option<u32>,
}

// A doubly linked FIFO through one Links field of the entries.
fn link(entries: &mut [Stored], ends: &mut Ends, index: u32, field: fn(&mut Entry) -> &mut Links) {
    *field(at(entries, index)) = Links {
        previous: ends.last.unwrap_or(NONE),
        next: NONE,
    };
    match ends.last {
        Some(last) => field(at(entries, last)).next = index,
        None => ends.first = Some(index),
    }
    ends.last = Some(index);
}

fn unlink(
    entries: &mut [Stored],
    ends: &mut Ends,
    index: u32,
    field: fn(&mut Entry) -> &mut Links,
) {
    let links = core::mem::replace(field(at(entries, index)), UNLINKED);
    if links.previous == NONE {
        ends.first = (links.next != NONE).then_some(links.next);
    } else {
        field(at(entries, links.previous)).next = links.next;
    }
    if links.next == NONE {
        ends.last = (links.previous != NONE).then_some(links.previous);
    } else {
        field(at(entries, links.next)).previous = links.previous;
    }
}

fn output(entry: &mut Entry) -> &mut Links {
    &mut entry.output
}

/// The TIME-WAIT records, at most `limit` (Linux's tcp_max_tw_buckets),
/// each allocated when it is stored, as Linux allocates an
/// inet_timewait_sock. They are found through chains from buckets of the
/// Endpoint's keyed hash (Linux's ehash): one bucket per record, doubled as
/// records grow, up to `limit` rounded to a power of two. No insert rehashes
/// them all: after a doubling, inserts move the earlier buckets' chains two
/// buckets at a time, and first the one they fall in. Per-port counts are
/// paged in as ports are used. Nothing is allocated before a record is
/// stored, and only storing one allocates.
///
/// Every record has the same duration, but not every one starts it when it
/// is stored: a connection whose application released it late joins with an
/// older deadline than records stored before it. The timers are therefore a
/// heap of records, not a FIFO.
pub(crate) struct TimeWaitTable {
    entries: Vec<Stored>,
    free: Vec<u32>,
    buckets: Vec<u32>,
    // The buckets before the last doubling, each NONE once its chain moved
    // to `buckets`; empty once all have.
    previous: Vec<u32>,
    // The next bucket of `previous` to move.
    moving: usize,
    timers: Vec<u32>,
    // Records per local port, as Linux keeps TIME-WAIT in a port's bind
    // bucket: a port stays bound while one of its tuples is in TIME-WAIT.
    // Pages of PORT_PAGE ports, empty until a record uses one of them.
    ports: Vec<Box<[u32]>>,
    output: Ends,
    len: usize,
    limit: usize,
}

const MIN_BUCKETS: usize = 16;
// Records an insert lets a chain hold. The keyed hash gives a bucket about
// one record, so the bound only stops chains built to collide, keeping
// hostile lookup work fixed.
const CHAIN: usize = 64;
const PORT_PAGE: usize = 256;

impl TimeWaitTable {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            entries: Vec::new(),
            free: Vec::new(),
            buckets: Vec::new(),
            previous: Vec::new(),
            moving: 0,
            timers: Vec::new(),
            ports: Vec::new(),
            output: Ends::default(),
            len: 0,
            limit,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    fn entry(&self, index: u32) -> &Entry {
        &self.entries[index as usize].as_ref().unwrap()[0]
    }

    // The chain `hash` falls in: its bucket of `previous` until that one
    // moved, else its bucket of `buckets`. An insert moves its bucket first,
    // so a chain is never split between the two.
    fn chain(&self, hash: u64) -> (bool, usize) {
        if !self.previous.is_empty() {
            let bucket = hash as usize & (self.previous.len() - 1);
            if self.previous[bucket] != NONE {
                return (true, bucket);
            }
        }
        (false, hash as usize & (self.buckets.len() - 1))
    }

    pub(crate) fn find(&self, hash: u64, tuple: ScopedTuple) -> Option<u32> {
        if self.buckets.is_empty() {
            return None;
        }
        let mut index = match self.chain(hash) {
            (true, bucket) => self.previous[bucket],
            (false, bucket) => self.buckets[bucket],
        };
        while index != NONE {
            let entry = self.entry(index);
            if entry.hash == hash && entry.record.tuple == tuple {
                return Some(index);
            }
            index = entry.next;
        }
        None
    }

    fn unmap(&mut self, index: u32) {
        let entry = self.entry(index);
        let next = entry.next;
        let heads = match self.chain(entry.hash) {
            (true, bucket) => &mut self.previous[bucket],
            (false, bucket) => &mut self.buckets[bucket],
        };
        if *heads == index {
            *heads = next;
            return;
        }
        let mut before = *heads;
        loop {
            let entry = at(&mut self.entries, before);
            if entry.next == index {
                entry.next = next;
                return;
            }
            before = entry.next;
        }
    }

    // Moves the chain of `previous[bucket]` into `buckets`. A chain of
    // `buckets` only ever takes records of one chain of `previous`, so
    // CHAIN still bounds it.
    fn move_bucket(&mut self, bucket: usize) {
        let mut index = core::mem::replace(&mut self.previous[bucket], NONE);
        let mask = self.buckets.len() - 1;
        while index != NONE {
            let entry = at(&mut self.entries, index);
            let head = &mut self.buckets[entry.hash as usize & mask];
            let next = core::mem::replace(&mut entry.next, *head);
            *head = index;
            index = next;
        }
    }

    fn migrate(&mut self) {
        for _ in 0..2 {
            if self.moving == self.previous.len() {
                break;
            }
            self.move_bucket(self.moving);
            self.moving += 1;
        }
        if self.moving == self.previous.len() {
            self.previous = Vec::new();
            self.moving = 0;
        }
    }

    // Doubles the buckets when records would outnumber them, up to the
    // bound. False if the allocation failed.
    fn grow(&mut self) -> bool {
        let count = self.buckets.len();
        let most = self.limit.next_power_of_two();
        if self.len < count || count == most {
            return true;
        }
        // The last doubling came at `count / 2` records, and each of the
        // `count / 2` or more inserts since moved two of the `count / 2`
        // buckets before it.
        assert!(self.previous.is_empty());
        let count = (count * 2).clamp(MIN_BUCKETS.min(most), most);
        let mut buckets = Vec::new();
        if buckets.try_reserve_exact(count).is_err() {
            return false;
        }
        buckets.resize(count, NONE);
        self.previous = core::mem::replace(&mut self.buckets, buckets);
        self.moving = 0;
        true
    }

    // Allocates the page counting `port`. False if that failed.
    fn page(&mut self, port: u16) -> bool {
        if self.ports.is_empty() {
            let pages = (usize::from(u16::MAX) + 1) / PORT_PAGE;
            if self.ports.try_reserve_exact(pages).is_err() {
                return false;
            }
            self.ports.resize_with(pages, Box::default);
        }
        let page = &mut self.ports[usize::from(port) / PORT_PAGE];
        if page.is_empty() {
            let mut counts = Vec::new();
            if counts.try_reserve_exact(PORT_PAGE).is_err() {
                return false;
            }
            counts.resize(PORT_PAGE, 0);
            *page = counts.into_boxed_slice();
        }
        true
    }

    fn port(&mut self, port: u16) -> &mut u32 {
        let port = usize::from(port);
        &mut self.ports[port / PORT_PAGE][port % PORT_PAGE]
    }

    /// Store `record` mapped under `hash`. False at the bound, when storage
    /// cannot grow, or when its chain is full.
    pub(crate) fn insert(&mut self, hash: u64, record: Record) -> bool {
        let port = record.tuple.tuple.local.port();
        if self.len >= self.limit || !self.grow() || !self.page(port) {
            return false;
        }
        self.migrate();
        if !self.previous.is_empty() {
            self.move_bucket(hash as usize & (self.previous.len() - 1));
        }
        let bucket = hash as usize & (self.buckets.len() - 1);
        let (mut chained, mut length) = (self.buckets[bucket], 0);
        while chained != NONE && length < CHAIN {
            chained = self.entry(chained).next;
            length += 1;
        }
        if length == CHAIN
            || self.free.is_empty()
                && (self.entries.try_reserve(1).is_err()
                    || self.timers.try_reserve(1).is_err()
                    || self.free.try_reserve(self.entries.len() + 1).is_err())
        {
            return false;
        }
        let Some(stored) = allocate(Entry {
            record,
            hash,
            next: self.buckets[bucket],
            timer: NONE,
            output: UNLINKED,
            queued: false,
        }) else {
            return false;
        };
        let index = self.free.pop().unwrap_or_else(|| {
            self.entries.push(None);
            (self.entries.len() - 1) as u32
        });
        self.entries[index as usize] = Some(stored);
        self.buckets[bucket] = index;
        self.push_timer(index);
        *self.port(port) += 1;
        self.len += 1;
        true
    }

    pub(crate) fn remove(&mut self, index: u32) -> Record {
        self.unmap(index);
        self.dequeue(index);
        self.remove_timer(index);
        let [entry] = *self.entries[index as usize].take().unwrap();
        *self.port(entry.record.tuple.tuple.local.port()) -= 1;
        self.free.push(index);
        self.len -= 1;
        entry.record
    }

    // Whether a record is stored at `index`.
    pub(crate) fn contains(&self, index: u32) -> bool {
        self.entries
            .get(index as usize)
            .is_some_and(Option::is_some)
    }

    pub(crate) fn record(&self, index: u32) -> &Record {
        &self.entry(index).record
    }

    pub(crate) fn record_mut(&mut self, index: u32) -> &mut Record {
        &mut at(&mut self.entries, index).record
    }

    // After `record_mut` changed the timer or owed output.
    pub(crate) fn update(&mut self, index: u32, restarted: bool) {
        if restarted {
            let position = self.entry(index).timer as usize;
            self.sift_down(position);
        }
        let entry = at(&mut self.entries, index);
        if entry.record.owes_output() && !entry.queued {
            entry.queued = true;
            link(&mut self.entries, &mut self.output, index, output);
        } else if !entry.record.owes_output() {
            self.dequeue(index);
        }
    }

    fn dequeue(&mut self, index: u32) {
        let entry = at(&mut self.entries, index);
        if core::mem::take(&mut entry.queued) {
            unlink(&mut self.entries, &mut self.output, index, output);
        }
    }

    pub(crate) fn first_expiry(&self) -> Option<(Instant, u32)> {
        let index = *self.timers.first()?;
        Some((self.record(index).deadline, index))
    }

    fn key(&self, position: usize) -> (Instant, u32) {
        let index = self.timers[position];
        (self.record(index).deadline, index)
    }

    fn place(&mut self, position: usize, index: u32) {
        self.timers[position] = index;
        at(&mut self.entries, index).timer = position as u32;
    }

    fn swap_timers(&mut self, a: usize, b: usize) {
        let (first, second) = (self.timers[a], self.timers[b]);
        self.place(a, second);
        self.place(b, first);
    }

    fn sift_up(&mut self, mut position: usize) -> usize {
        while position != 0 {
            let parent = (position - 1) / 2;
            if self.key(parent) <= self.key(position) {
                break;
            }
            self.swap_timers(parent, position);
            position = parent;
        }
        position
    }

    fn sift_down(&mut self, mut position: usize) {
        loop {
            let left = position * 2 + 1;
            if left >= self.timers.len() {
                return;
            }
            let right = left + 1;
            let child = if right < self.timers.len() && self.key(right) < self.key(left) {
                right
            } else {
                left
            };
            if self.key(position) <= self.key(child) {
                return;
            }
            self.swap_timers(position, child);
            position = child;
        }
    }

    fn push_timer(&mut self, index: u32) {
        let position = self.timers.len();
        self.timers.push(index);
        self.place(position, index);
        self.sift_up(position);
    }

    fn remove_timer(&mut self, index: u32) {
        let position = self.entry(index).timer as usize;
        let last = self.timers.len() - 1;
        self.swap_timers(position, last);
        self.timers.pop();
        if position < self.timers.len() {
            let position = self.sift_up(position);
            self.sift_down(position);
        }
    }

    pub(crate) fn first_output(&self) -> Option<u32> {
        self.output.first
    }

    pub(crate) fn has_output(&self) -> bool {
        self.output.first.is_some()
    }

    pub(crate) fn holds_port(&self, port: u16) -> bool {
        let port = usize::from(port);
        self.ports
            .get(port / PORT_PAGE)
            .and_then(|page| page.get(port % PORT_PAGE))
            .is_some_and(|&count| count != 0)
    }

    // Every record; for rare whole-endpoint events only.
    pub(crate) fn indices(&self) -> impl Iterator<Item = u32> + '_ {
        self.timers.iter().copied()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::connection::Tuple;
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::collections::BTreeMap;

    fn record(peer: u32, local_port: u16, deadline: Instant) -> Record {
        let address = |ip: u32, port| SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port);
        Record {
            tuple: ScopedTuple {
                tuple: Tuple {
                    local: address(0x0a00_0001, local_port),
                    remote: address(0x0b00_0000 | peer, 40_000),
                },
                zone: None,
            },
            snd_nxt: Seq(1),
            rcv_nxt: Seq(1),
            ack_floor: Seq(1),
            timestamps: false,
            timestamp_offset: 0,
            ts_recent: 0,
            ts_latest: 0,
            ts_recent_at: 0,
            last_timestamp_sent_at: None,
            deadline,
            challenge_start: None,
            challenge_sent: 0,
            ack_pending: false,
            challenge_pending: false,
            hop_limit: 64,
            dscp: 0,
            mark: 0,
            reuse_address: false,
            ipv4_options: OutgoingIpv4Options::default(),
            reply_header: None,
        }
    }

    fn mix(mut x: u64) -> u64 {
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        x ^ (x >> 31)
    }

    // Every stored record is found, in one chain, and the counts agree.
    fn check(table: &TimeWaitTable, model: &BTreeMap<u32, (u64, u32)>) {
        assert_eq!(table.len(), model.len());
        assert_eq!(table.timers.len(), model.len());
        for (&peer, &(hash, index)) in model {
            let tuple = table.record(index).tuple;
            assert_eq!(
                tuple.tuple.remote.ip(),
                record(peer, 0, 0).tuple.tuple.remote.ip()
            );
            assert_eq!(table.find(hash, tuple), Some(index));
        }
        let chained: usize = table
            .buckets
            .iter()
            .chain(&table.previous)
            .map(|&head| {
                let mut count = 0;
                let mut index = head;
                while index != NONE {
                    count += 1;
                    index = table.entry(index).next;
                }
                assert!(count <= CHAIN);
                count
            })
            .sum();
        assert_eq!(chained, model.len());
        assert!(table.buckets.len() <= table.limit.next_power_of_two());
        let mut ports = [0u32; 8];
        for &(_, index) in model.values() {
            ports[usize::from(table.record(index).tuple.tuple.local.port() - 1000)] += 1;
        }
        for (offset, &count) in ports.iter().enumerate() {
            assert_eq!(table.holds_port(1000 + offset as u16), count != 0);
        }
        if let Some((deadline, _)) = table.first_expiry() {
            assert!(
                model
                    .values()
                    .all(|&(_, index)| table.record(index).deadline >= deadline)
            );
        }
    }

    #[test]
    fn nothing_is_allocated_before_a_record_is_stored() {
        let table = TimeWaitTable::new(1 << 30);
        assert_eq!(table.buckets.capacity(), 0);
        assert_eq!(table.ports.capacity(), 0);
        assert_eq!(table.entries.capacity(), 0);
        assert_eq!(table.find(7, record(1, 1000, 5).tuple), None);
        assert!(!table.holds_port(1000));
    }

    // Records stored and removed in any order are found through every
    // doubling, while the earlier buckets move, and the buckets follow the
    // records up to the bound.
    #[test]
    fn records_are_found_while_the_buckets_double() {
        for limit in [1, 5, 16, 100, 3000] {
            let mut table = TimeWaitTable::new(limit);
            let mut model = BTreeMap::new();
            let mut colliding = 0;
            let mut peak = 0;
            for step in 0..20_000u64 {
                let roll = mix(step ^ (limit as u64) << 32);
                let peer = (roll % (limit as u64 * 2)) as u32;
                if let Some((hash, index)) = model.remove(&peer) {
                    colliding -= usize::from(hash & 0xf_ffff == 5);
                    let removed = table.remove(index);
                    assert_eq!(
                        removed.tuple,
                        record(peer, removed.tuple.tuple.local.port(), 0).tuple
                    );
                } else {
                    // Some hashes share their low bits, as a chain of
                    // every size has them all.
                    let hash = if roll & 3 == 0 && colliding < 32 {
                        colliding += 1;
                        (roll >> 40) << 20 | 5
                    } else {
                        mix(u64::from(peer)) | 0x8_0000
                    };
                    let record = record(peer, 1000 + (peer % 8) as u16, roll >> 48);
                    assert_eq!(
                        table.insert(hash, record),
                        model.len() < limit,
                        "limit {limit} step {step}"
                    );
                    match table.find(hash, record.tuple) {
                        Some(index) => {
                            model.insert(peer, (hash, index));
                        }
                        None => colliding -= usize::from(hash & 0xf_ffff == 5),
                    }
                }
                peak = peak.max(model.len());
                assert!(table.buckets.len() <= (2 * peak).max(MIN_BUCKETS));
                if limit <= 100 || step % 101 == 0 {
                    check(&table, &model);
                }
            }
            check(&table, &model);
        }
    }

    // A chain holds at most CHAIN records; a record in another chain is
    // still stored.
    #[test]
    fn a_full_chain_refuses_a_record() {
        let mut table = TimeWaitTable::new(1000);
        let mut model = BTreeMap::new();
        for peer in 0..CHAIN as u32 {
            assert!(table.insert(9, record(peer, 1000, 1)));
            model.insert(
                peer,
                (9, table.find(9, record(peer, 1000, 1).tuple).unwrap()),
            );
        }
        assert!(!table.insert(9, record(500, 1000, 1)));
        assert!(table.insert(10, record(501, 1001, 1)));
        model.insert(
            501,
            (10, table.find(10, record(501, 1001, 1).tuple).unwrap()),
        );
        check(&table, &model);
        let (_, index) = model.remove(&3).unwrap();
        table.remove(index);
        assert!(table.insert(9, record(500, 1000, 1)));
        model.insert(500, (9, table.find(9, record(500, 1000, 1).tuple).unwrap()));
        check(&table, &model);
    }

    // A record whose storage cannot be allocated is not stored, and the
    // table stays as it was.
    #[test]
    fn a_failed_allocation_stores_nothing() {
        let mut table = TimeWaitTable::new(1000);
        let mut model = BTreeMap::new();
        for peer in 0..200u32 {
            let hash = mix(u64::from(peer));
            let record = record(peer, 1000 + (peer % 8) as u16, u64::from(peer));
            let mut failure = 0;
            while !crate::allocation_tests::fail_after(failure, || table.insert(hash, record)) {
                check(&table, &model);
                failure += 1;
            }
            model.insert(peer, (hash, table.find(hash, record.tuple).unwrap()));
            check(&table, &model);
        }
    }
}
