// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;
use crate::timestamping::*;
use ntcp::{
    TxTimestampClock as Clock, TxTimestampOutcome as Outcome, TxTimestampSource as Source,
    TxTimestampStage as Stage,
};
use std::sync::Arc;

pub(super) const PHASES: usize = 128;
const RECORD: usize = 256;
const PACKET_HANDLE: usize = 2 * std::mem::size_of::<usize>() + std::mem::size_of::<Vec<u8>>();
pub(super) const RUNTIME_BYTES: usize = 32 * 1024 * 1024;

// Empty queued TSONLY records own no packet allocation. Pending packets use a
// fallibly grown Vec behind an Arc, so completion only clones the shared handle.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct PacketPayload(Option<Arc<Vec<u8>>>);
impl PacketPayload {
    // Conservatively charge each shared reference as a full packet. Sharing
    // saves real memory but never lets fanout escape either socket's budget.
    fn charge(&self) -> usize {
        self.0.as_ref().map_or(0, |p| PACKET_HANDLE + p.capacity())
    }
}
impl std::ops::Deref for PacketPayload {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0.as_deref().map_or(&[], Vec::as_slice)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Completion {
    ZeroCopy(u32, u32),
    SharedZeroCopy(u32, u32, bool),
    Timestamp {
        stamp: [u8; 48],
        error: [u8; 32],
        payload: PacketPayload,
    },
}
impl Completion {
    pub(super) fn range(&self) -> Option<(u32, u32)> {
        match *self {
            Self::ZeroCopy(a, b) => Some((a, b)),
            _ => None,
        }
    }
    pub(super) fn charge(&self) -> usize {
        match self {
            Self::ZeroCopy(..) | Self::SharedZeroCopy(..) => 0,
            Self::Timestamp { payload, .. } => RECORD + payload.charge(),
        }
    }
}
pub(super) type Observation = (ntcp::TxTimestampEvent, ClockPair, Options, u32);

#[derive(Clone)]
struct Pending {
    cookie: u64,
    target: u64,
    sequence: u32,
    phases: usize,
    software: bool,
    hardware: bool,
    payload: PacketPayload,
    observed: Option<Vec<Observation>>,
}
impl Pending {
    fn charge(&self) -> usize {
        self.phases * RECORD
            + self.payload.charge()
            + self
                .observed
                .as_ref()
                .map_or(0, |v| v.capacity() * std::mem::size_of::<Observation>())
    }
}
#[derive(Clone, Default)]
pub(super) struct TimestampState {
    pub(super) options: Options,
    pub(super) base: u32,
    pending: Vec<Pending>,
    // Sum of Pending::charge, kept at each change of a pending record.
    pending_charge: usize,
}
impl TimestampState {
    fn push(&mut self, pending: Pending) {
        self.pending_charge += pending.charge();
        self.pending.push(pending);
    }
    // Applies a change to one record and carries its charge difference.
    fn update<T>(&mut self, index: usize, change: impl FnOnce(&mut Pending) -> T) -> T {
        let pending = &mut self.pending[index];
        let before = pending.charge();
        let result = change(pending);
        self.pending_charge = self.pending_charge - before + pending.charge();
        result
    }
    fn remove(&mut self, index: usize) {
        self.pending_charge -= self.pending.swap_remove(index).charge();
    }
    pub(super) fn reserved(&self) -> usize {
        self.pending.iter().map(|p| p.phases).sum()
    }
    pub(super) fn staging_charge(&self) -> usize {
        // Clone storage plus replacement observation storage can coexist.
        self.pending.len() * std::mem::size_of::<Pending>()
            + self
                .pending
                .iter()
                .map(|p| {
                    p.observed
                        .as_ref()
                        .map_or(0, |v| (v.len() + 4) * std::mem::size_of::<Observation>())
                })
                .sum::<usize>()
    }
    pub(super) fn restore_reservations(&mut self) -> Result<()> {
        let mut result = Ok(());
        for pending in &mut self.pending {
            if let Some(observed) = &mut pending.observed
                && observed.try_reserve_exact(4 - observed.len()).is_err()
            {
                result = Err(ENOBUFS);
                break;
            }
        }
        // A clone's observation storage has its own capacity: count it anew.
        self.pending_charge = self.pending.iter().map(Pending::charge).sum();
        result
    }
    fn charge(&self) -> usize {
        self.pending.capacity() * std::mem::size_of::<Pending>() + self.pending_charge
    }
}
impl Socket {
    // Retained capacities plus the record sums kept as records are queued and
    // dequeued, as Linux charges each error-queue skb to sk_rmem_alloc in
    // sock_queue_err_skb and releases it in sock_rfree.
    fn timestamp_charge(&self) -> usize {
        self.timestamps.charge()
            + self.zc_leases.capacity() * std::mem::size_of::<crate::zerocopy::Pending>()
            + self.zc_leases.len() * std::mem::size_of::<crate::zerocopy::LeaseState>()
            + self.completions.capacity() * std::mem::size_of::<Completion>()
            + self.completion_charge
    }
    // The full sum the kept totals replace, for debug checks.
    fn recount_timestamp_charge(&self) -> usize {
        self.timestamps.pending.capacity() * std::mem::size_of::<Pending>()
            + self
                .timestamps
                .pending
                .iter()
                .map(Pending::charge)
                .sum::<usize>()
            + self.zc_leases.capacity() * std::mem::size_of::<crate::zerocopy::Pending>()
            + self.zc_leases.len() * std::mem::size_of::<crate::zerocopy::LeaseState>()
            + self.completions.capacity() * std::mem::size_of::<Completion>()
            + self
                .completions
                .iter()
                .map(Completion::charge)
                .sum::<usize>()
    }
    // Moves the owner's total by this socket's change since it last settled.
    // Call after every change to the socket's timestamp or completion storage.
    pub(super) fn settle_timestamp_charge(&mut self, total: &mut usize) {
        let charge = self.timestamp_charge();
        debug_assert_eq!(charge, self.recount_timestamp_charge());
        *total = *total - self.timestamp_charged + charge;
        self.timestamp_charged = charge;
    }
    pub(super) fn push_completion(&mut self, completion: Completion) {
        self.completion_charge += completion.charge();
        self.completions.push_back(completion);
    }
    pub(super) fn pop_completion(&mut self) {
        if let Some(completion) = self.completions.pop_front() {
            self.completion_charge -= completion.charge();
        }
    }
}
pub(super) fn realtime() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u64::MAX as u128) as u64
}
// A fresh bracket at each owner input/output boundary, never a lifetime offset.
#[derive(Clone, Copy)]
pub(super) struct ClockPair {
    ticks: u64,
    realtime: u64,
}
impl ClockPair {
    pub(super) fn sample(owner: &mut Owner) -> Result<Self> {
        let before = owner.clock()?;
        let realtime = realtime();
        let after = owner.clock()?;
        Ok(Self {
            ticks: before + (after - before) / 2,
            realtime,
        })
    }
    fn convert(self, value: u64, clock: Clock) -> Option<u64> {
        match clock {
            Clock::RealtimeNanoseconds => Some(value),
            Clock::CallerTicks(timebase) if timebase.units_per_second == 1_000_000 => {
                let value =
                    i128::from(self.realtime) + (i128::from(value) - i128::from(self.ticks)) * 1000;
                u64::try_from(value).ok()
            }
            Clock::DeviceTicks {
                units_per_second: Some(1_000_000_000),
                ..
            } => Some(value),
            _ => None,
        }
    }
}
impl Owner {
    pub(super) fn software_rx_enabled(&self) -> bool {
        debug_assert_eq!(
            self.rx_software,
            self.sockets
                .values()
                .filter(|s| s.timestamps.options.flags & RX_SOFTWARE != 0)
                .count()
        );
        debug_assert_eq!(
            self.rx_software_children,
            self.child_timestamps
                .iter()
                .filter(|p| p.1.flags & RX_SOFTWARE != 0)
                .count()
        );
        self.rx_software != 0 || self.rx_software_children != 0
    }
    pub(super) fn backend_sources(&self, token: ntcp::TxTimestampToken) -> (bool, bool) {
        let range = token.stream_range();
        self.connection_socket(token.connection())
            .map(|id| &self.sockets[&id])
            .into_iter()
            .flat_map(|s| &s.timestamps.pending)
            .filter(|p| (range.start..range.end).contains(&p.target))
            .fold((false, false), |(sw, hw), p| {
                (sw || p.software, hw || p.hardware)
            })
    }
    // Kept as sockets settle, never summed per operation.
    pub(super) fn timestamp_charge(&self) -> usize {
        debug_assert_eq!(
            self.timestamp_total,
            self.sockets
                .values()
                .map(Socket::recount_timestamp_charge)
                .sum::<usize>()
        );
        self.timestamp_total
    }
    pub(super) fn settle_timestamp_charge(&mut self, id: u64) {
        if let Some(s) = self.sockets.get_mut(&id) {
            s.settle_timestamp_charge(&mut self.timestamp_total);
        }
    }
    pub(super) fn remove_socket(&mut self, id: u64) -> Option<Socket> {
        for list in 0..LISTS {
            unlink(&mut self.sockets, &mut self.lists, list, id);
        }
        let s = self.sockets.remove(&id)?;
        self.rx_software -= usize::from(s.timestamps.options.flags & RX_SOFTWARE != 0);
        if let Some(local) = s.local {
            self.port_sockets.remove(&(local.port(), id));
        }
        self.hold(id, s.handle, false);
        self.timestamp_total -= s.timestamp_charged;
        Some(s)
    }
    // For tests that replace a socket's storage outright.
    #[cfg(test)]
    pub(super) fn recount_timestamp_charge(&mut self, id: u64) {
        let s = self.sockets.get_mut(&id).unwrap();
        s.timestamps.pending_charge = s.timestamps.pending.iter().map(Pending::charge).sum();
        s.completion_charge = s.completions.iter().map(Completion::charge).sum();
        s.settle_timestamp_charge(&mut self.timestamp_total);
        self.touch(id);
    }
    pub(super) fn timestamp_options(&mut self, id: u64, name: i32, flags: u32) -> Result<()> {
        let s = self.sockets.get(&id).ok_or(EBADF)?;
        let cid = if let Handle::Connection(cid) = s.handle {
            Some(cid)
        } else {
            None
        };
        let active =
            cid.is_some_and(|cid| !matches!(self.endpoint.state(cid), Ok(State::Closed) | Err(_)));
        let next = s.timestamps.options.updated(name, flags, active)?;
        if flags & (TX_SOFTWARE | TX_HARDWARE) == TX_SOFTWARE | TX_HARDWARE
            && flags & OPT_TX_SWHW == 0
        {
            return Err(libc::EOPNOTSUPP);
        }
        let listener = if let Handle::Listener(listener) = s.handle {
            Some(listener)
        } else {
            None
        };
        let mut base = s.timestamps.base;
        if s.timestamps.options.resets_id(next) {
            let progress = self
                .endpoint
                .send_progress(cid.ok_or(libc::EINVAL)?)
                .map_err(engine)?;
            base = if flags & OPT_ID_TCP != 0 {
                progress.next_write_sequence
            } else {
                progress.unacknowledged_sequence
            };
        }
        if let Some(cid) = cid {
            // Allocate before committing the visible option. Native retained memory
            // is additionally charged to Endpoint's aggregate buffer budget.
            self.endpoint
                .set_tx_timestamp_capacity(cid, PHASES)
                .map_err(engine)?;
            self.endpoint
                .set_rx_timestamp_capacity(cid, PHASES)
                .map_err(engine)?;
        }
        if let Some(listener) = listener {
            self.endpoint
                .set_listener_rx_timestamp_capacity(listener, PHASES)
                .map_err(engine)?;
        }
        let s = self.sockets.get_mut(&id).unwrap();
        self.rx_software = self.rx_software + usize::from(next.flags & RX_SOFTWARE != 0)
            - usize::from(s.timestamps.options.flags & RX_SOFTWARE != 0);
        s.timestamps.options = next;
        s.timestamps.base = base;
        Ok(())
    }
    // One joint reservation: queued records + every outstanding native phase +
    // this send's phases + a non-coalescing zero-copy record. No completion push
    // may allocate after native acceptance.
    #[cfg(test)]
    pub(super) fn reserve_completion(
        &mut self,
        id: u64,
        nonempty: bool,
        flags: i32,
        override_flags: Option<u32>,
    ) -> Result<bool> {
        let s = self.sockets.get(&id).ok_or(EBADF)?;
        let bits = override_flags
            .map(|f| s.timestamps.options.per_send(f))
            .transpose()?
            .unwrap_or(s.timestamps.options.flags);
        self.reserve_send_completion(
            id,
            nonempty,
            s.zerocopy && flags & MSG_ZEROCOPY != 0,
            bits,
            false,
        )
    }
    pub(super) fn reserve_send_completion(
        &mut self,
        id: u64,
        nonempty: bool,
        completion: bool,
        bits: u32,
        deferred: bool,
    ) -> Result<bool> {
        let s = self.sockets.get(&id).ok_or(EBADF)?;
        if bits & (TX_SOFTWARE | TX_HARDWARE) == TX_SOFTWARE | TX_HARDWARE
            && bits & OPT_TX_SWHW == 0
        {
            return Err(libc::EOPNOTSUPP);
        }
        if !nonempty {
            return Ok(false);
        }
        let phases = (bits & TX_RECORD).count_ones() as usize;
        if phases == 0 && !completion {
            return Ok(false);
        }
        let new_zc = usize::from(
            completion
                && (deferred
                    || !s
                        .completions
                        .back()
                        .and_then(Completion::range)
                        .is_some_and(|p| extends_completion(p, s.zc_next))),
        );
        let additional = s.timestamps.reserved() + phases + new_zc + s.zc_reserved;
        let total = s.completions.len() + additional;
        let pending_bytes = if phases == 0 {
            0
        } else {
            (s.timestamps.pending.len() + 1) * 2 * std::mem::size_of::<Pending>() + PACKET_HANDLE
        };
        let pending_bytes = pending_bytes
            + if deferred && phases != 0 {
                4 * std::mem::size_of::<Observation>()
            } else {
                0
            };
        let queue_bytes = total * 2 * std::mem::size_of::<Completion>();
        if (phases != 0
            && (self.timestamp_cookie == u64::MAX || s.timestamps.pending.len() >= PHASES))
            || (phases != 0 || s.timestamps.reserved() != 0) && total > PHASES
            || new_zc != 0 && total > self.request_limit()
            || phases != 0
                && s.timestamp_charge() + phases * RECORD + pending_bytes + queue_bytes
                    > s.receive_capacity
            || self.timestamp_charge() + phases * RECORD + pending_bytes + queue_bytes
                > RUNTIME_BYTES
        {
            return Err(ENOBUFS);
        }
        let s = self.sockets.get_mut(&id).unwrap();
        let reserved = if phases != 0 {
            s.timestamps.pending.try_reserve_exact(1)
        } else {
            Ok(())
        }
        .and_then(|()| s.completions.try_reserve_exact(additional));
        s.settle_timestamp_charge(&mut self.timestamp_total);
        reserved.map_err(|_| ENOBUFS)?;
        Ok(completion)
    }
    #[cfg(test)]
    pub(super) fn timestamp_write(
        &mut self,
        id: u64,
        cid: ConnectionId,
        bytes: &[u8],
        flags: i32,
        override_flags: Option<u32>,
    ) -> Result<usize> {
        let s = &self.sockets[&id];
        let options = s.timestamps.options;
        let bits = override_flags
            .map(|f| options.per_send(f))
            .transpose()?
            .unwrap_or(options.flags);
        self.timestamp_write_bits(id, cid, bytes, flags, bits)
    }
    pub(super) fn timestamp_write_bits(
        &mut self,
        id: u64,
        cid: ConnectionId,
        bytes: &[u8],
        flags: i32,
        bits: u32,
    ) -> Result<usize> {
        self.timestamp_write_from(id, cid, bytes.len(), flags, bits, |room| Ok(&bytes[..room]))
    }
    // All admission/metadata allocation precedes the producer. Its own storage
    // must be allocated before consumption, and the owner must not yield until
    // exact-prefix TCP admission. Ordinary sends can borrow their existing copy.
    pub(super) fn timestamp_write_from<B: AsRef<[u8]>>(
        &mut self,
        id: u64,
        cid: ConnectionId,
        capacity: usize,
        flags: i32,
        bits: u32,
        produce: impl FnOnce(usize) -> Result<B>,
    ) -> Result<usize> {
        let request = ntcp::TxTimestampRequest {
            cookie: self.timestamp_cookie,
            scheduled: bits & TX_SCHED != 0,
            software_transmit: bits & TX_SOFTWARE != 0,
            hardware_transmit: bits & TX_HARDWARE != 0,
            acknowledged: bits & TX_ACK != 0,
        };
        if bits & (TX_SOFTWARE | TX_HARDWARE) == TX_SOFTWARE | TX_HARDWARE
            && bits & OPT_TX_SWHW == 0
        {
            return Err(libc::EOPNOTSUPP);
        }
        let phases = (bits & TX_RECORD).count_ones() as usize;
        // Allocate the shared handle before native acceptance; packet storage is
        // reserved fallibly at output, before copying any bytes.
        let payload = (phases != 0).then(|| PacketPayload(Some(Arc::new(Vec::new()))));
        if phases != 0 {
            self.endpoint
                .set_tx_timestamp_capacity(cid, PHASES)
                .map_err(engine)?;
        }
        let progress = self.endpoint.send_progress(cid).map_err(engine)?;
        let goal = send::batch_goal(&self.endpoint.transport_info(cid).map_err(engine)?);
        let lowat = None; // Socket lowat gates batches; core still enforces hard capacity.
        let (batch_room, batch_start) = self.send_batch_admission(id, cid)?;
        let room = if capacity == 0 {
            0
        } else {
            let room = self
                .endpoint
                .check_write_admission(cid, lowat, request)
                .map_err(engine)?;
            let room = room.min(batch_room);
            if room == 0 {
                return Err(EAGAIN);
            }
            room
        };
        // Reserve fallible sender metadata before a pipe/file producer can
        // consume bytes. The owner keeps this admission transaction exclusive.
        let room = if capacity == 0 {
            0
        } else {
            self.endpoint
                .prepare_write_admission(cid, capacity.min(room), lowat, request)
                .map_err(engine)?
        };
        let produced = produce(capacity.min(room))?;
        let bytes = produced.as_ref();
        assert!(bytes.len() <= capacity.min(room));
        let n = self
            .endpoint
            .write_with_timestamp(
                cid,
                bytes,
                flags & MSG_MORE != 0,
                flags & MSG_EOR != 0,
                lowat,
                request,
            )
            .map_err(engine)?;
        assert_eq!(n, bytes.len());
        if n != 0 {
            let end = progress.queued_end + n as u64;
            self.sockets.get_mut(&id).unwrap().send_batch = if flags & MSG_EOR == 0 && goal != 0 {
                Some(send::SendBatch {
                    connection: cid,
                    start: batch_start + ((end - batch_start - 1) / goal as u64) * goal as u64,
                    end,
                })
            } else {
                None
            };
        }
        if n != 0 && phases != 0 {
            let s = self.sockets.get_mut(&id).unwrap();
            s.timestamps.push(Pending {
                cookie: self.timestamp_cookie,
                target: progress.queued_end + n as u64 - 1,
                sequence: progress.next_write_sequence.wrapping_add(n as u32 - 1),
                phases,
                software: request.software_transmit,
                hardware: request.hardware_transmit,
                payload: payload.unwrap(),
                observed: None,
            });
            s.settle_timestamp_charge(&mut self.timestamp_total);
            link(&mut self.sockets, &mut self.lists, STAMPING, id);
            self.timestamp_cookie += 1;
        }
        Ok(n)
    }
    // Called on encoded packet output, before draining SCHED. Retain the actual
    // packet, not a copy of the write (writes and output segments need not align).
    pub(super) fn timestamp_packet(&mut self, token: Option<ntcp::TxTimestampToken>, bytes: &[u8]) {
        let Some(token) = token else { return };
        let range = token.stream_range();
        let mut retained: Option<PacketPayload> = None;
        let mut global = self.timestamp_charge();
        if let Some(s) = self
            .connection_socket(token.connection())
            .and_then(|id| self.sockets.get_mut(&id))
        {
            let mut charge = s.timestamp_charge();
            for index in 0..s.timestamps.pending.len() {
                let pending = &s.timestamps.pending[index];
                if !pending.payload.is_empty()
                    || !(range.start..range.end).contains(&pending.target)
                {
                    continue;
                }
                // Linux drops timestamp notifications under receive-memory pressure.
                // Never retain an uncharged packet or substitute invented bytes.
                if charge + bytes.len() <= s.receive_capacity
                    && global + bytes.len() <= RUNTIME_BYTES
                {
                    let stored = s.timestamps.update(index, |pending| {
                        if let Some(packet) = &retained {
                            pending.payload = packet.clone();
                        } else {
                            let packet = Arc::get_mut(pending.payload.0.as_mut().unwrap()).unwrap();
                            if packet.try_reserve_exact(bytes.len()).is_err() {
                                return false;
                            }
                            packet.extend_from_slice(bytes);
                            retained = Some(pending.payload.clone());
                        }
                        true
                    });
                    if !stored {
                        continue;
                    }
                    charge += bytes.len();
                    global += bytes.len();
                }
            }
            s.settle_timestamp_charge(&mut self.timestamp_total);
        }
    }
    pub(super) fn drain_timestamps(&mut self, pair: ClockPair) {
        // Records exist at a connection only for its socket's requests,
        // or reported ready: only those sockets are visited (`STAMPING`).
        self.check_list(
            STAMPING,
            |s| matches!(s.handle, Handle::Connection(_)) && !s.timestamps.pending.is_empty(),
            false,
        );
        let mut global = self.timestamp_charge();
        let mut next = self.lists[STAMPING];
        while let Some(id) = next {
            let s = self.sockets.get_mut(&id).unwrap();
            next = s.lists[STAMPING].next;
            let mut drained = false;
            let mut exhausted = true;
            if let Handle::Connection(cid) = s.handle {
                exhausted = false;
                for _ in 0..PHASES {
                    let Ok(Some(event)) = self.endpoint.next_tx_timestamp(cid) else {
                        exhausted = true;
                        break;
                    };
                    Self::timestamp_event(s, event, pair, None, &mut global);
                    drained = true;
                }
            }
            if drained {
                s.settle_timestamp_charge(&mut self.timestamp_total);
            }
            if exhausted && s.timestamps.pending.is_empty() {
                unlink(&mut self.sockets, &mut self.lists, STAMPING, id);
            }
            if drained {
                self.touch(id);
            }
        }
    }
    fn timestamp_event(
        s: &mut Socket,
        event: ntcp::TxTimestampEvent,
        pair: ClockPair,
        options: Option<(Options, u32)>,
        global: &mut usize,
    ) {
        let Some(index) = s
            .timestamps
            .pending
            .iter()
            .position(|p| p.cookie == event.cookie)
        else {
            return;
        };
        let current = (s.timestamps.options, s.timestamps.base);
        let deferred = s.timestamps.update(index, |pending| {
            if event.stage == Stage::Transmit {
                match event.source {
                    Source::Software => pending.software = false,
                    Source::Hardware => pending.hardware = false,
                }
            }
            let Some(observed) = &mut pending.observed else {
                return false;
            };
            debug_assert!(observed.len() < 4);
            observed.push((event, pair, current.0, current.1));
            true
        });
        if deferred {
            return;
        }
        let (options, base) = options.unwrap_or((s.timestamps.options, s.timestamps.base));
        let flags = options.flags;
        let pending = &s.timestamps.pending[index];
        let tsonly = flags & OPT_TSONLY != 0;
        let payload_charge = if tsonly { 0 } else { pending.payload.charge() };
        let value = match event.outcome {
            Outcome::Recorded { value, clock } => pair.convert(value, clock),
            Outcome::Cancelled => None,
        };
        let charge = s.timestamp_charge();
        if let Some(value) = value.filter(|_| tsonly || !pending.payload.is_empty())
            && charge + payload_charge <= s.receive_capacity
            && *global + payload_charge <= RUNTIME_BYTES
        {
            let (sw, hw) = match event.source {
                Source::Software => (Some(value), None),
                Source::Hardware => (None, Some(value)),
            };
            let stage = match event.stage {
                Stage::Scheduled => 1,
                Stage::Transmit => 0,
                Stage::Acknowledged => 2,
            };
            let completion = Completion::Timestamp {
                stamp: timestamps(sw, hw),
                error: extended_error(stage, options.completion_id(pending.sequence, base)),
                payload: if tsonly {
                    PacketPayload::default()
                } else {
                    pending.payload.clone()
                },
            };
            s.push_completion(completion);
            *global += payload_charge;
            s.readiness_generations[2] = s.readiness_generations[2].wrapping_add(1);
        } else {
            *global = global.saturating_sub(RECORD);
        }
        let finished = s.timestamps.update(index, |pending| {
            pending.phases -= 1;
            pending.phases == 0
        });
        if finished {
            *global = global.saturating_sub(s.timestamps.pending[index].payload.charge());
            s.timestamps.remove(index);
        }
    }
    fn pending_index(s: &Socket, cookie: u64) -> Option<usize> {
        s.timestamps.pending.iter().position(|p| p.cookie == cookie)
    }
    pub(super) fn defer_timestamp(&mut self, id: u64, cookie: u64, observed: Vec<Observation>) {
        if let Some(s) = self.sockets.get_mut(&id)
            && let Some(index) = Self::pending_index(s, cookie)
        {
            s.timestamps.update(index, |p| p.observed = Some(observed));
            s.settle_timestamp_charge(&mut self.timestamp_total);
        }
    }
    pub(super) fn discard_timestamp(&mut self, id: u64, cid: ConnectionId, cookie: u64) {
        let _ = self.endpoint.discard_tx_timestamp_request(cid, cookie);
        if let Some(s) = self.sockets.get_mut(&id) {
            let state = &mut s.timestamps;
            state.pending.retain(|p| {
                let keep = p.cookie != cookie;
                if !keep {
                    state.pending_charge -= p.charge();
                }
                keep
            });
            s.settle_timestamp_charge(&mut self.timestamp_total);
        }
    }
    pub(super) fn finish_timestamp(&mut self, id: u64, cookie: u64) {
        let mut global = self.timestamp_charge();
        let Some(s) = self.sockets.get_mut(&id) else {
            return;
        };
        let Some(index) = Self::pending_index(s, cookie) else {
            return;
        };
        let observed = s
            .timestamps
            .update(index, |p| p.observed.take())
            .unwrap_or_default();
        for (event, pair, options, base) in observed {
            Self::timestamp_event(s, event, pair, Some((options, base)), &mut global);
        }
        s.settle_timestamp_charge(&mut self.timestamp_total);
        self.touch(id);
    }
    pub(super) fn software_transmitted(
        &mut self,
        token: Option<ntcp::TxTimestampToken>,
        value: u64,
    ) {
        if let Some(token) = token {
            let _ = self.endpoint.report_tx_timestamp(
                token,
                Source::Software,
                value,
                Clock::RealtimeNanoseconds,
            );
        }
        // Without time the owner loop ends at its next turn.
        if let Ok(pair) = ClockPair::sample(self) {
            self.drain_timestamps(pair);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clock_pairs_do_not_reinterpret_old_records_or_unknown_device_ticks() {
        let old = ClockPair {
            ticks: 100,
            realtime: 1_000_000,
        };
        let clock = Clock::CallerTicks(ntcp::CallerTimebase::default());
        let recorded = old.convert(90, clock).unwrap();
        let jumped = ClockPair {
            ticks: 200,
            realtime: 9_000_000,
        };
        assert_eq!(recorded, 990_000);
        assert_eq!(jumped.convert(190, clock), Some(8_990_000));
        assert_eq!(
            old.convert(
                77,
                Clock::DeviceTicks {
                    identity: 1,
                    units_per_second: None
                }
            ),
            None
        );
        assert_eq!(
            old.convert(
                77,
                Clock::DeviceTicks {
                    identity: 1,
                    units_per_second: Some(1000)
                }
            ),
            None
        );
        assert_eq!(
            old.convert(
                77,
                Clock::DeviceTicks {
                    identity: 1,
                    units_per_second: Some(1_000_000_000)
                }
            ),
            Some(77)
        );
    }
}
