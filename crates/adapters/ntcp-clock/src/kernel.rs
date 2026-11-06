//! The private kernel-query boundary. [`Linux`] is the production query; the
//! crate's unit tests supply recorded facts through the same [`Query`].

use crate::{Clock, Facts, KernelTime, Timespec};

pub(crate) trait Query {
    fn clock(&mut self, clock: Clock) -> Result<Timespec, i32>;
    /// One read-only `adjtimex` call (modes 0).
    fn adjtimex(&mut self) -> Result<KernelTime, i32>;
}

/// One acquisition, in the order the classification relies on: the BOOTTIME
/// and MONOTONIC pair measures the sleep offset, the call and the following
/// REALTIME read sit inside the BOOTTIME bracket.
pub(crate) fn acquire(query: &mut impl Query) -> Facts {
    let boottime_before = query.clock(Clock::Boottime);
    let monotonic_before = query.clock(Clock::Monotonic);
    let adjtimex = query.adjtimex();
    let realtime_after = query.clock(Clock::Realtime);
    let boottime_after = query.clock(Clock::Boottime);
    Facts {
        boottime_before,
        monotonic_before,
        adjtimex,
        realtime_after,
        boottime_after,
    }
}

/// What the transport provider reads, all of it read-only.
pub(crate) trait TransportQuery {
    fn clock(&mut self, clock: Clock) -> Result<Timespec, i32>;
    fn resolution(&mut self, clock: Clock) -> Result<Timespec, i32>;
    /// The bytes of a `/proc` file.
    fn read(&mut self, path: &str) -> Result<Vec<u8>, i32>;
}

pub(crate) struct Linux;

fn clock_id(clock: Clock) -> libc::clockid_t {
    match clock {
        Clock::Boottime => libc::CLOCK_BOOTTIME,
        Clock::Monotonic => libc::CLOCK_MONOTONIC,
        Clock::Realtime => libc::CLOCK_REALTIME,
    }
}

fn timespec(ts: libc::timespec) -> Timespec {
    Timespec {
        seconds: i64::from(ts.tv_sec),
        nanoseconds: i64::from(ts.tv_nsec),
    }
}

fn clock_gettime(clock: Clock) -> Result<Timespec, i32> {
    // SAFETY: timespec is plain data; all-zero is a valid value.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: `ts` is a valid, writable timespec for the call.
    if unsafe { libc::clock_gettime(clock_id(clock), &mut ts) } != 0 {
        return Err(errno());
    }
    Ok(timespec(ts))
}

impl Query for Linux {
    fn clock(&mut self, clock: Clock) -> Result<Timespec, i32> {
        clock_gettime(clock)
    }

    fn adjtimex(&mut self) -> Result<KernelTime, i32> {
        // SAFETY: timex is plain data; all-zero is a valid value and sets
        // modes to 0, so the call only reads kernel state.
        let mut tx: libc::timex = unsafe { std::mem::zeroed() };
        // SAFETY: `tx` is a valid, writable timex for the call.
        let state = unsafe { libc::adjtimex(&mut tx) };
        if state == -1 {
            return Err(errno());
        }
        Ok(KernelTime {
            state,
            status: tx.status,
            maxerror: i64::from(tx.maxerror),
            seconds: i64::from(tx.time.tv_sec),
            fraction: i64::from(tx.time.tv_usec),
        })
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

impl TransportQuery for Linux {
    fn clock(&mut self, clock: Clock) -> Result<Timespec, i32> {
        clock_gettime(clock)
    }

    fn resolution(&mut self, clock: Clock) -> Result<Timespec, i32> {
        // SAFETY: timespec is plain data; all-zero is a valid value.
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        // SAFETY: `ts` is a valid, writable timespec for the call.
        if unsafe { libc::clock_getres(clock_id(clock), &mut ts) } != 0 {
            return Err(errno());
        }
        Ok(timespec(ts))
    }

    fn read(&mut self, path: &str) -> Result<Vec<u8>, i32> {
        std::fs::read(path).map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))
    }
}
