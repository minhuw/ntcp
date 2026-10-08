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
pub(super) const RUNTIME_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Completion {
    ZeroCopy(u32, u32),
    Timestamp {
        stamp: [u8; 48],
        error: [u8; 32],
        payload: Arc<[u8]>,
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
            Self::ZeroCopy(..) => 0,
            Self::Timestamp { payload, .. } => RECORD + payload.len(),
        }
    }
}
#[derive(Clone)]
struct Pending {
    cookie: u64,
    target: u64,
    id: u32,
    phases: usize,
    software: bool,
    hardware: bool,
    payload: Arc<[u8]>,
}
#[derive(Clone, Default)]
pub(super) struct TimestampState {
    pub(super) options: Options,
    pub(super) base: u32,
    pending: Vec<Pending>,
}
impl TimestampState {
    pub(super) fn reserved(&self) -> usize {
        self.pending.iter().map(|p| p.phases).sum()
    }
    pub(super) fn staging_charge(&self) -> usize {
        self.pending.len() * std::mem::size_of::<Pending>()
    }
    fn charge(&self) -> usize {
        self.pending.capacity() * std::mem::size_of::<Pending>()
            + self
                .pending
                .iter()
                .map(|p| p.phases * RECORD + p.payload.len())
                .sum::<usize>()
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
    pub(super) fn sample(owner: &Owner) -> Self {
        let before = owner.now();
        let realtime = realtime();
        let after = owner.now();
        Self {
            ticks: before + (after - before) / 2,
            realtime,
        }
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
        self.sockets
            .values()
            .any(|s| s.timestamps.options.flags & RX_SOFTWARE != 0)
            || self
                .child_timestamps
                .iter()
                .any(|p| p.1.flags & RX_SOFTWARE != 0)
    }
    pub(super) fn backend_sources(&self, token: ntcp::TxTimestampToken) -> (bool, bool) {
        let range = token.stream_range();
        self.sockets
            .values()
            .filter(|s| matches!(s.handle, Handle::Connection(cid) if cid == token.connection()))
            .flat_map(|s| &s.timestamps.pending)
            .filter(|p| (range.start..range.end).contains(&p.target))
            .fold((false, false), |(sw, hw), p| {
                (sw || p.software, hw || p.hardware)
            })
    }
    pub(super) fn timestamp_charge(&self) -> usize {
        self.sockets
            .values()
            .map(|s| {
                s.timestamps.charge()
                    + s.completions.capacity() * std::mem::size_of::<Completion>()
                    + s.completions.iter().map(Completion::charge).sum::<usize>()
            })
            .sum()
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
        s.timestamps.options = next;
        s.timestamps.base = base;
        Ok(())
    }
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
        let reserve = s.timestamps.reserved() + phases;
        if phases != 0 {
            if self.timestamp_cookie == u64::MAX
                || s.timestamps.pending.len() >= PHASES
                || s.completions.len()
                    + s.timestamps.pending.iter().map(|p| p.phases).sum::<usize>()
                    + phases
                    > PHASES
                || s.timestamps.charge()
                    + s.completions.iter().map(Completion::charge).sum::<usize>()
                    + phases * RECORD
                    + (s.timestamps.pending.len() + 1) * 2 * std::mem::size_of::<Pending>()
                    > s.receive_capacity
                || self.timestamp_charge()
                    + phases * RECORD
                    + (s.timestamps.pending.len() + 1) * 2 * std::mem::size_of::<Pending>()
                    + (s.completions.len() + reserve) * 2 * std::mem::size_of::<Completion>()
                    > RUNTIME_BYTES
            {
                return Err(ENOBUFS);
            }
            self.endpoint
                .set_tx_timestamp_capacity(cid, PHASES)
                .map_err(engine)?;
            self.sockets
                .get_mut(&id)
                .unwrap()
                .timestamps
                .pending
                .try_reserve(1)
                .map_err(|_| ENOBUFS)?;
            self.sockets
                .get_mut(&id)
                .unwrap()
                .completions
                .try_reserve(reserve)
                .map_err(|_| ENOBUFS)?;
        }
        let progress = self.endpoint.send_progress(cid).map_err(engine)?;
        let lowat = self.sockets[&id].notsent_lowat;
        let n = self
            .endpoint
            .write_with_timestamp(
                cid,
                bytes,
                flags & MSG_MORE != 0,
                flags & MSG_EOR != 0,
                Some(effective_notsent_lowat(lowat)),
                request,
            )
            .map_err(engine)?;
        if n != 0 && phases != 0 {
            let s = self.sockets.get_mut(&id).unwrap();
            s.timestamps.pending.push(Pending {
                cookie: self.timestamp_cookie,
                target: progress.queued_end + n as u64 - 1,
                id: if bits & OPT_ID != 0 {
                    progress
                        .next_write_sequence
                        .wrapping_add(n as u32 - 1)
                        .wrapping_sub(s.timestamps.base)
                } else {
                    0
                },
                phases,
                software: request.software_transmit,
                hardware: request.hardware_transmit,
                payload: Arc::from([]),
            });
            self.timestamp_cookie += 1;
        }
        Ok(n)
    }
    // Called on encoded packet output, before draining SCHED. Retain the actual
    // packet, not a copy of the write (writes and output segments need not align).
    pub(super) fn timestamp_packet(&mut self, token: Option<ntcp::TxTimestampToken>, bytes: &[u8]) {
        let Some(token) = token else { return };
        let range = token.stream_range();
        let mut global = self.timestamp_charge();
        for s in self
            .sockets
            .values_mut()
            .filter(|s| matches!(s.handle, Handle::Connection(cid) if cid == token.connection()))
        {
            let mut charge =
                s.timestamps.charge() + s.completions.iter().map(Completion::charge).sum::<usize>();
            for pending in &mut s.timestamps.pending {
                if s.timestamps.options.flags & OPT_TSONLY != 0
                    || !pending.payload.is_empty()
                    || !(range.start..range.end).contains(&pending.target)
                {
                    continue;
                }
                // Linux drops timestamp notifications under receive-memory pressure.
                // Never retain an uncharged packet or substitute invented bytes.
                if charge + bytes.len() <= s.receive_capacity
                    && global + bytes.len() <= RUNTIME_BYTES
                {
                    pending.payload = Arc::from(bytes);
                    charge += bytes.len();
                    global += bytes.len();
                }
            }
        }
    }
    pub(super) fn drain_timestamps(&mut self, pair: ClockPair) {
        let ids: Vec<_> = self
            .sockets
            .iter()
            .filter_map(|(&id, s)| match s.handle {
                Handle::Connection(cid) => Some((id, cid)),
                _ => None,
            })
            .collect();
        let mut global = self.timestamp_charge();
        for (id, cid) in ids {
            for _ in 0..PHASES {
                let Ok(Some(event)) = self.endpoint.next_tx_timestamp(cid) else {
                    break;
                };
                let s = self.sockets.get_mut(&id).unwrap();
                let Some(index) = s
                    .timestamps
                    .pending
                    .iter()
                    .position(|p| p.cookie == event.cookie)
                else {
                    continue;
                };
                let flags = s.timestamps.options.flags;
                let pending = &s.timestamps.pending[index];
                let tsonly = flags & OPT_TSONLY != 0;
                let payload_len = if tsonly { 0 } else { pending.payload.len() };
                let value = match event.outcome {
                    Outcome::Recorded { value, clock } => pair.convert(value, clock),
                    Outcome::Cancelled => None,
                };
                let charge = s.timestamps.charge()
                    + s.completions.iter().map(Completion::charge).sum::<usize>();
                if let Some(value) = value.filter(|_| tsonly || !pending.payload.is_empty())
                    && charge + payload_len <= s.receive_capacity
                    && global + payload_len <= RUNTIME_BYTES
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
                    s.completions.push_back(Completion::Timestamp {
                        stamp: timestamps(sw, hw),
                        error: extended_error(stage, pending.id),
                        payload: if tsonly {
                            Arc::from([])
                        } else {
                            pending.payload.clone()
                        },
                    });
                    global += payload_len;
                    s.readiness_generations[2] = s.readiness_generations[2].wrapping_add(1);
                } else {
                    global = global.saturating_sub(RECORD);
                }
                let pending = &mut s.timestamps.pending[index];
                if event.stage == Stage::Transmit {
                    match event.source {
                        Source::Software => pending.software = false,
                        Source::Hardware => pending.hardware = false,
                    }
                }
                pending.phases -= 1;
                if pending.phases == 0 {
                    global = global.saturating_sub(pending.payload.len());
                    s.timestamps.pending.swap_remove(index);
                }
            }
        }
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
        self.drain_timestamps(ClockPair::sample(self));
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
