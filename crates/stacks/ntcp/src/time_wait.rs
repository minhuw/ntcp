//! TIME-WAIT without a connection. Once a connection in TIME-WAIT has no
//! application owner, the Endpoint keeps only what TIME-WAIT still needs
//! (Linux's inet_timewait_sock): the tuple, both sequence frontiers, the
//! timestamp state, the challenge-ACK budget and the timer. The connection,
//! its buffers and its slot are freed.
extern crate alloc;

use alloc::vec::Vec;

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
    // Position in the timer heap.
    timer: u32,
    output: Links,
    queued: bool,
}

#[derive(Clone, Copy, Default)]
struct Ends {
    first: Option<u32>,
    last: Option<u32>,
}

// A doubly linked FIFO through one Links field of the entries.
fn link(
    entries: &mut [Option<Entry>],
    ends: &mut Ends,
    index: u32,
    field: fn(&mut Entry) -> &mut Links,
) {
    *field(entries[index as usize].as_mut().unwrap()) = Links {
        previous: ends.last.unwrap_or(NONE),
        next: NONE,
    };
    match ends.last {
        Some(last) => field(entries[last as usize].as_mut().unwrap()).next = index,
        None => ends.first = Some(index),
    }
    ends.last = Some(index);
}

fn unlink(
    entries: &mut [Option<Entry>],
    ends: &mut Ends,
    index: u32,
    field: fn(&mut Entry) -> &mut Links,
) {
    let links = core::mem::replace(field(entries[index as usize].as_mut().unwrap()), UNLINKED);
    if links.previous == NONE {
        ends.first = (links.next != NONE).then_some(links.next);
    } else {
        field(entries[links.previous as usize].as_mut().unwrap()).next = links.next;
    }
    if links.next == NONE {
        ends.last = (links.previous != NONE).then_some(links.previous);
    } else {
        field(entries[links.next as usize].as_mut().unwrap()).previous = links.previous;
    }
}

fn output(entry: &mut Entry) -> &mut Links {
    &mut entry.output
}

/// The TIME-WAIT records, at most `limit` (Linux's tcp_max_tw_buckets).
/// Records are allocated as TIME-WAIT grows; the lookup index (two slots per
/// record allowed, linear probing within a fixed budget under the Endpoint's
/// keyed hash) and the per-port counts are allocated whole. Every record has
/// the same duration, but not every one starts it when it is stored: a
/// connection whose application released it late joins with an older
/// deadline than records stored before it. The timers are therefore a heap
/// of records, not a FIFO.
pub(crate) struct TimeWaitTable {
    entries: Vec<Option<Entry>>,
    free: Vec<u32>,
    index: Vec<u32>,
    timers: Vec<u32>,
    // Records per local port, as Linux keeps TIME-WAIT in a port's bind
    // bucket: a port stays bound while one of its tuples is in TIME-WAIT.
    ports: Vec<u32>,
    output: Ends,
    len: usize,
    limit: usize,
}

const PROBES: usize = 64;

impl TimeWaitTable {
    pub(crate) fn new(limit: usize) -> Result<Self, ()> {
        let (index_len, ports_len) = if limit == 0 {
            (0, 0)
        } else {
            (
                limit
                    .checked_mul(2)
                    .and_then(usize::checked_next_power_of_two)
                    .ok_or(())?,
                usize::from(u16::MAX) + 1,
            )
        };
        let mut index = Vec::new();
        index.try_reserve_exact(index_len).map_err(|_| ())?;
        index.resize(index_len, NONE);
        let mut ports = Vec::new();
        ports.try_reserve_exact(ports_len).map_err(|_| ())?;
        ports.resize(ports_len, 0);
        Ok(Self {
            entries: Vec::new(),
            free: Vec::new(),
            index,
            ports,
            timers: Vec::new(),
            output: Ends::default(),
            len: 0,
            limit,
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    fn position(&self, hash: u64, probe: usize) -> usize {
        (hash as usize).wrapping_add(probe) & (self.index.len() - 1)
    }

    pub(crate) fn find(&self, hash: u64, tuple: ScopedTuple) -> Option<u32> {
        if self.index.is_empty() {
            return None;
        }
        for probe in 0..self.index.len().min(PROBES) {
            match self.index[self.position(hash, probe)] {
                NONE => return None,
                index => {
                    let entry = self.entries[index as usize].as_ref().unwrap();
                    if entry.hash == hash && entry.record.tuple == tuple {
                        return Some(index);
                    }
                }
            }
        }
        None
    }

    fn map(&mut self, index: u32) -> bool {
        let hash = self.entries[index as usize].as_ref().unwrap().hash;
        for probe in 0..self.index.len().min(PROBES) {
            let position = self.position(hash, probe);
            if self.index[position] == NONE {
                self.index[position] = index;
                return true;
            }
        }
        false
    }

    // Backward-shift deletion: no tombstones, so a miss ends at the first
    // empty position however long the table has churned.
    fn unmap(&mut self, index: u32) {
        let hash = self.entries[index as usize].as_ref().unwrap().hash;
        let mask = self.index.len() - 1;
        let mut hole = (0..PROBES)
            .map(|probe| self.position(hash, probe))
            .find(|&position| self.index[position] == index)
            .expect("a mapped record is within its probe budget");
        let mut next = (hole + 1) & mask;
        while self.index[next] != NONE {
            let home = self.entries[self.index[next] as usize]
                .as_ref()
                .unwrap()
                .hash as usize
                & mask;
            // Move it back when the hole lies on its probe path.
            if next.wrapping_sub(home) & mask >= next.wrapping_sub(hole) & mask {
                self.index[hole] = self.index[next];
                hole = next;
            }
            next = (next + 1) & mask;
        }
        self.index[hole] = NONE;
    }

    /// Store `record` mapped under `hash`. False at the bound, when storage
    /// cannot grow, or when its probe budget is exhausted.
    pub(crate) fn insert(&mut self, hash: u64, record: Record) -> bool {
        if self.len >= self.limit {
            return false;
        }
        let index = match self.free.pop() {
            Some(index) => index,
            None => {
                let index = self.entries.len();
                if self.entries.try_reserve(1).is_err()
                    || self.timers.try_reserve(1).is_err()
                    || self.free.try_reserve(index + 1).is_err()
                {
                    return false;
                }
                self.entries.push(None);
                index as u32
            }
        };
        let port = record.tuple.tuple.local.port();
        self.entries[index as usize] = Some(Entry {
            record,
            hash,
            timer: NONE,
            output: UNLINKED,
            queued: false,
        });
        if !self.map(index) {
            self.entries[index as usize] = None;
            self.free.push(index);
            return false;
        }
        self.push_timer(index);
        self.ports[usize::from(port)] += 1;
        self.len += 1;
        true
    }

    pub(crate) fn remove(&mut self, index: u32) -> Record {
        self.unmap(index);
        self.dequeue(index);
        self.remove_timer(index);
        let entry = self.entries[index as usize].take().unwrap();
        self.ports[usize::from(entry.record.tuple.tuple.local.port())] -= 1;
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
        &self.entries[index as usize].as_ref().unwrap().record
    }

    pub(crate) fn record_mut(&mut self, index: u32) -> &mut Record {
        &mut self.entries[index as usize].as_mut().unwrap().record
    }

    // After `record_mut` changed the timer or owed output.
    pub(crate) fn update(&mut self, index: u32, restarted: bool) {
        if restarted {
            let position = self.entries[index as usize].as_ref().unwrap().timer as usize;
            self.sift_down(position);
        }
        let entry = self.entries[index as usize].as_mut().unwrap();
        if entry.record.owes_output() && !entry.queued {
            entry.queued = true;
            link(&mut self.entries, &mut self.output, index, output);
        } else if !entry.record.owes_output() {
            self.dequeue(index);
        }
    }

    fn dequeue(&mut self, index: u32) {
        let entry = self.entries[index as usize].as_mut().unwrap();
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
        self.entries[index as usize].as_mut().unwrap().timer = position as u32;
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
        let position = self.entries[index as usize].as_ref().unwrap().timer as usize;
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
        self.ports
            .get(usize::from(port))
            .is_some_and(|&count| count != 0)
    }

    // Every record; for rare whole-endpoint events only.
    pub(crate) fn indices(&self) -> impl Iterator<Item = u32> + '_ {
        self.timers.iter().copied()
    }
}
