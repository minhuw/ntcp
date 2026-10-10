extern crate alloc;

use alloc::vec::Vec;

use crate::{CallerTimebase, ConnectionId, Error};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TxTimestampRequest {
    pub cookie: u64,
    pub scheduled: bool,
    pub software_transmit: bool,
    pub hardware_transmit: bool,
    pub acknowledged: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxTimestampStage {
    Scheduled,
    Transmit,
    Acknowledged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxTimestampSource {
    Software,
    Hardware,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxTimestampClock {
    CallerTicks(CallerTimebase),
    RealtimeNanoseconds,
    DeviceTicks {
        identity: u64,
        units_per_second: Option<u64>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxTimestampOutcome {
    Recorded { value: u64, clock: TxTimestampClock },
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxTimestampEvent {
    pub cookie: u64,
    // Zero-based TCP-stream position, not an accepted-write counter: FLUSH
    // cancels discarded unsent targets, whose positions may then be reused.
    pub target: u64,
    pub stage: TxTimestampStage,
    pub source: TxTimestampSource,
    pub outcome: TxTimestampOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxStreamRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxTimestampToken {
    connection: ConnectionId,
    range: TxStreamRange,
}

impl TxTimestampToken {
    pub fn connection(self) -> ConnectionId {
        self.connection
    }

    pub fn stream_range(self) -> TxStreamRange {
        self.range
    }

    pub(crate) fn new(connection: ConnectionId, range: TxStreamRange) -> Self {
        Self { connection, range }
    }
}

#[derive(Clone, Copy)]
struct Record {
    event: TxTimestampEvent,
    ready: bool,
}

// Pending phases become events in place. No allocation on admission/completion;
// ready events keep their reservations until drained. A fixed phase budget
// bounds requests, events, duplicates, and missing hardware completions together.
#[derive(Default)]
pub(crate) struct TxTimestamps {
    records: Vec<Record>,
    limit: usize,
}

impl TxTimestampRequest {
    fn phases(self) -> [(bool, TxTimestampStage, TxTimestampSource); 4] {
        use TxTimestampSource::{Hardware, Software};
        use TxTimestampStage::{Acknowledged, Scheduled, Transmit};
        [
            (self.scheduled, Scheduled, Software),
            (self.software_transmit, Transmit, Software),
            (self.hardware_transmit, Transmit, Hardware),
            (self.acknowledged, Acknowledged, Software),
        ]
    }
}

impl TxTimestamps {
    pub(crate) fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub(crate) fn storage_bytes(&self) -> usize {
        self.records.capacity() * core::mem::size_of::<Record>()
    }

    pub(crate) fn resize(&mut self, limit: usize, spare_bytes: usize) -> Result<(), Error> {
        if limit < self.records.len() {
            return Err(Error::WouldBlock);
        }
        if limit == self.limit {
            return Ok(());
        }
        let bytes = limit
            .checked_mul(core::mem::size_of::<Record>())
            .ok_or(Error::NoMemory)?;
        if bytes > spare_bytes {
            return Err(Error::NoMemory);
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(limit)
            .map_err(|_| Error::NoMemory)?;
        if records.capacity() * core::mem::size_of::<Record>() > spare_bytes {
            return Err(Error::NoMemory);
        }
        records.extend_from_slice(&self.records);
        self.records = records;
        self.limit = limit;
        Ok(())
    }

    pub(crate) fn admit(&self, request: TxTimestampRequest) -> Result<(), Error> {
        let phases = request.phases().iter().filter(|phase| phase.0).count();
        if phases > self.limit - self.records.len() {
            return Err(Error::WouldBlock);
        }
        Ok(())
    }

    pub(crate) fn insert(&mut self, request: TxTimestampRequest, target: u64) {
        for (enabled, stage, source) in request.phases() {
            if enabled {
                debug_assert!(self.records.len() < self.limit);
                self.records.push(Record {
                    event: TxTimestampEvent {
                        cookie: request.cookie,
                        target,
                        stage,
                        source,
                        outcome: TxTimestampOutcome::Cancelled,
                    },
                    ready: false,
                });
            }
        }
    }

    pub(crate) fn observe(
        &mut self,
        range: TxStreamRange,
        stage: TxTimestampStage,
        source: TxTimestampSource,
        value: u64,
        clock: TxTimestampClock,
    ) {
        // ponytail: bounded linear phase scan; index targets if large opted-in
        // capacities measurably dominate output/ACK processing.
        for record in &mut self.records {
            if !record.ready
                && record.event.stage == stage
                && record.event.source == source
                && range.start <= record.event.target
                && record.event.target < range.end
            {
                record.event.outcome = TxTimestampOutcome::Recorded { value, clock };
                record.ready = true;
            }
        }
    }

    pub(crate) fn cancel_transmit(&mut self, range: TxStreamRange, source: TxTimestampSource) {
        for record in &mut self.records {
            if !record.ready
                && record.event.stage == TxTimestampStage::Transmit
                && record.event.source == source
                && (range.start..range.end).contains(&record.event.target)
            {
                record.event.outcome = TxTimestampOutcome::Cancelled;
                record.ready = true;
            }
        }
    }

    pub(crate) fn cancel_from(&mut self, start: u64) {
        for record in &mut self.records {
            if !record.ready && record.event.target >= start {
                record.event.outcome = TxTimestampOutcome::Cancelled;
                record.ready = true;
            }
        }
    }

    pub(crate) fn discard_request(&mut self, cookie: u64) {
        self.records.retain(|record| record.event.cookie != cookie);
    }

    pub(crate) fn next(&mut self) -> Option<TxTimestampEvent> {
        let index = self.records.iter().position(|record| record.ready)?;
        Some(self.records.remove(index).event)
    }
}
