extern crate alloc;

use crate::{CallerTimebase, Error, TxTimestampClock};
use alloc::vec::Vec;

pub type TimestampClock = TxTimestampClock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendProgress {
    // Payload cursors exclude SYN/FIN; FLUSH may lower queued_end.
    pub acknowledged: u64,
    pub queued_end: u64,
    // Wire SND.UNA includes control sequence space.
    pub unacknowledged_sequence: u32,
    // Payload end: includes the initial SYN offset, never a queued FIN.
    pub next_write_sequence: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RxTimestamp {
    pub value: u64,
    pub clock: TimestampClock,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RxPacketTimestamps {
    pub software: Option<RxTimestamp>,
    pub hardware: Option<RxTimestamp>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RxReadTimestamps {
    pub start: u64,
    pub end: u64,
    // Query result describes the LAST byte of [start, end), not every byte.
    pub timestamps: RxPacketTimestamps,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RxTimestampStatus {
    pub capacity: usize,
    pub retained_ranges: usize,
    pub lost_bytes: u64,
}

impl RxPacketTimestamps {
    pub(crate) fn validate(self, timebase: CallerTimebase) -> Result<(), Error> {
        for (stamp, hardware) in [(self.software, false), (self.hardware, true)] {
            if let Some(stamp) = stamp {
                match stamp.clock {
                    TimestampClock::CallerTicks(base) if hardware || base != timebase => {
                        return Err(Error::InvalidArgument);
                    }
                    TimestampClock::DeviceTicks {
                        units_per_second: Some(0),
                        ..
                    } => return Err(Error::InvalidArgument),
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct RxTimestamps {
    ranges: Vec<RxReadTimestamps>,
    limit: usize,
    lost_bytes: u64,
}

impl RxTimestamps {
    pub(crate) fn status(&self) -> RxTimestampStatus {
        RxTimestampStatus {
            capacity: self.limit,
            retained_ranges: self.ranges.len(),
            lost_bytes: self.lost_bytes,
        }
    }

    pub(crate) fn allocation_bytes(limit: usize) -> Option<usize> {
        core::alloc::Layout::array::<RxReadTimestamps>(limit)
            .ok()
            .map(|layout| layout.size())
    }

    pub(crate) fn storage_bytes(&self) -> usize {
        self.ranges.capacity() * core::mem::size_of::<RxReadTimestamps>()
    }

    pub(crate) fn resize(&mut self, limit: usize, spare: usize) -> Result<(), Error> {
        if limit < self.ranges.len() {
            return Err(Error::WouldBlock);
        }
        if limit == self.limit {
            return Ok(());
        }
        if Self::allocation_bytes(limit).is_none_or(|bytes| bytes > spare) {
            return Err(Error::NoMemory);
        }
        let mut ranges = Vec::new();
        ranges
            .try_reserve_exact(limit)
            .map_err(|_| Error::NoMemory)?;
        if ranges.capacity() * core::mem::size_of::<RxReadTimestamps>() > spare {
            return Err(Error::NoMemory);
        }
        ranges.extend_from_slice(&self.ranges);
        self.ranges = ranges;
        self.limit = limit;
        Ok(())
    }

    pub(crate) fn enabled(&self) -> bool {
        self.limit != 0
    }

    pub(crate) fn insert(&mut self, start: u64, end: u64, timestamps: RxPacketTimestamps) {
        if !self.enabled() || timestamps == RxPacketTimestamps::default() {
            return;
        }
        // ponytail: bounded linear range scan; index ranges if large enabled
        // capacities dominate input. Only bitmap-confirmed new runs enter here.
        if let Some(index) = self.ranges.iter().position(|range| {
            range.timestamps == timestamps && (range.end == start || range.start == end)
        }) {
            self.ranges[index].start = self.ranges[index].start.min(start);
            self.ranges[index].end = self.ranges[index].end.max(end);
            if let Some(other) = self.ranges.iter().enumerate().position(|(i, range)| {
                i != index
                    && range.timestamps == timestamps
                    && (range.end == self.ranges[index].start
                        || range.start == self.ranges[index].end)
            }) {
                self.ranges[index].start = self.ranges[index].start.min(self.ranges[other].start);
                self.ranges[index].end = self.ranges[index].end.max(self.ranges[other].end);
                self.ranges.swap_remove(other);
            }
        } else if self.ranges.len() < self.limit {
            self.ranges.push(RxReadTimestamps {
                start,
                end,
                timestamps,
            });
        } else {
            self.lost_bytes = self.lost_bytes.saturating_add(end - start);
        }
    }

    pub(crate) fn at(&self, offset: u64) -> RxPacketTimestamps {
        self.ranges
            .iter()
            .find(|range| range.start <= offset && offset < range.end)
            .map_or(RxPacketTimestamps::default(), |range| range.timestamps)
    }

    pub(crate) fn consumed(&mut self, end: u64) {
        self.ranges.retain_mut(|range| {
            range.start = range.start.max(end);
            range.start < range.end
        });
    }

    pub(crate) fn lost(&mut self, bytes: u64) {
        self.lost_bytes = self.lost_bytes.saturating_add(bytes);
    }

    pub(crate) fn clear(&mut self) {
        self.ranges.clear();
    }
}
