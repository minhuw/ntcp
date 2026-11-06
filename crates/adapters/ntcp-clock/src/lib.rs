//! Characterized Linux UTC source for IPv4 Timestamp values (RFC 791
//! section 3.1; RFC 1122 sections 3.2.1.8 and 3.2.2.8).
//!
//! [`UtcClock::sample`] makes one read-only acquisition and returns a
//! [`Sample`]: the raw [`Facts`], the [`Classification`] with its [`Reason`]
//! and the emitted 32-bit value. The value is a standard value, UTC
//! milliseconds since midnight UT, only when all of the conditions below
//! hold; otherwise it is the embedding's monotonic elapsed milliseconds with
//! the RFC 791 high-order bit set, never an unmarked guess.
//!
//! # Acquisition
//!
//! `CLOCK_BOOTTIME` and `CLOCK_MONOTONIC`, one `adjtimex` call with modes 0,
//! `CLOCK_REALTIME`, `CLOCK_BOOTTIME`. There is no status cache: callers
//! sample only when a Timestamp slot will actually be written.
//!
//! # Standard value conditions (kernel references are Linux v6.6)
//!
//! 1. The call succeeded and the status shows none of the kernel's error
//!    predicates (`kernel/time/ntp.c` `is_error_status`: `STA_UNSYNC` or
//!    `STA_CLOCKERR`; `STA_PPSFREQ` or `STA_PPSTIME` without
//!    `STA_PPSSIGNAL`; `STA_PPSTIME` with `STA_PPSJITTER`; `STA_PPSFREQ` with
//!    `STA_PPSWANDER` or `STA_PPSERROR`). The status bits are checked
//!    whatever state is returned, because `__do_adjtimex`'s leap handling can
//!    replace `TIME_ERROR` with `TIME_OOP` or `TIME_WAIT`. The returned state
//!    is `TIME_OK`, `TIME_INS`, `TIME_DEL` or `TIME_WAIT`: `TIME_ERROR` is
//!    excluded, and so is `TIME_OOP`, the inserted leap second during which
//!    Linux repeats a second.
//! 2. The maximum error is within 0..=16 000 000 us, Linux's
//!    `NTP_PHASE_LIMIT` (`include/linux/timex.h`). While the system is awake
//!    and no time daemon writes, `second_overflow` grows the maximum error by
//!    `MAXFREQ` (500 us) per second and declares the clock unsynchronized
//!    beyond that limit. An `ADJ_MAXERROR` write can exceed the limit until
//!    the next clamp, so such a sample is rejected. The threshold comes from
//!    the kernel, not from the RFC: 16 s is within RFC 1122's "correct within
//!    a few minutes", conditional on the time daemon's bound and the kernel
//!    drift model being truthful. It does not certify how recently the daemon
//!    synchronized.
//! 3. Acquisition consistency. The BOOTTIME bracket width `w` is at most
//!    64 ms (RFC 1122 3.2.2.8(a): at most the six low-order millisecond bits
//!    undefined), and `CLOCK_REALTIME` read after the call exceeds the time
//!    the call returned (nanoseconds with `STA_NANO`, else truncated
//!    microseconds, with the kernel's leap adjustment) by between 0 and `w`
//!    plus the truncation. `do_adjtimex` (`kernel/time/timekeeping.c`) reads
//!    its time before taking the timekeeper lock, so time and status are not
//!    atomic; a step anywhere in the bracket larger than `w` fails this
//!    check, including a step followed by daemon resynchronization.
//! 4. Suspend continuity. Generic resume neither clears synchronization nor
//!    accounts the sleep in the maximum error (`timekeeping_resume` updates
//!    with `TK_MIRROR | TK_CLOCK_WAS_SET`, without `TK_CLEAR_NTP`; only the
//!    RTC fallback `timekeeping_inject_sleeptime64` clears it). When the
//!    sleep offset (`CLOCK_BOOTTIME` minus `CLOCK_MONOTONIC`, zero at boot)
//!    grew beyond its measurement uncertainty since the provider's previous
//!    sample, or at the provider's first sample when it is nonzero, standard
//!    output needs a later sample whose maximum error is lower than the
//!    previous sample's. Only a time-daemon write can cause such a
//!    decrease: the kernel itself only grows the error or clamps it down to
//!    the limit from above. A sample whose offset cannot be measured within
//!    the bracket limit keeps the previous measurement as the reference:
//!    the offset only grows through a sleep, so a suspend in that interval
//!    shows at the next measurable sample. The previous sleep offset, the previous maximum error and whether such
//!    a write was seen are the only state [`UtcClock`] keeps; it never makes
//!    a failing sample standard.
//!
//! # Cadence
//!
//! `do_adjtimex` takes its time from `ktime_get_real_ts64`, which reads the
//! selected clocksource on demand (non-coarse `timekeeping_get_ns`), so each
//! write samples it. The crate's tests characterize the progression on the
//! tested system over a bounded interval; that does not prove future
//! hardware behaviour. `clock_getres` and the numeric range of a value are
//! not evidence of either cadence or accuracy.
//!
//! The transport time source, [`TransportClock`], is separate: it serves TCP
//! timing, not IPv4 Timestamp values (see the `transport` module).

mod kernel;
#[cfg(test)]
mod tests;
mod transport;

pub use transport::{
    BootId, Characterization, NamespaceOffsets, TransportClock, TransportError, TransportSample,
};

/// RFC 791 section 3.1: a time that is not standard UTC milliseconds since
/// midnight is marked by setting the high-order bit.
const NONSTANDARD: u32 = 0x8000_0000;
/// `NTP_PHASE_LIMIT` in microseconds: `(MAXPHASE / NSEC_PER_USEC) << 5`.
const MAX_ERROR_LIMIT_US: i64 = 16_000_000;
/// 2^6 ms, the RFC 1122 3.2.2.8(a) allowance of undefined low-order bits.
const ACQUISITION_LIMIT_NS: i128 = 64_000_000;
const NANOS_PER_SECOND: i128 = 1_000_000_000;
const SECONDS_PER_DAY: i64 = 86_400;

/// A clock read by the acquisition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Clock {
    Boottime,
    Monotonic,
    Realtime,
}

/// One `clock_gettime` reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timespec {
    pub seconds: i64,
    pub nanoseconds: i64,
}

impl Timespec {
    pub(crate) fn nanos(self) -> i128 {
        i128::from(self.seconds) * NANOS_PER_SECOND + i128::from(self.nanoseconds)
    }
}

/// What a successful read-only `adjtimex` call returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelTime {
    /// The call's return value, the clock state (`TIME_OK`..`TIME_ERROR`).
    pub state: i32,
    pub status: i32,
    /// Maximum error in microseconds.
    pub maxerror: i64,
    /// `time.tv_sec` as returned, leap adjustment included.
    pub seconds: i64,
    /// `time.tv_usec`: nanoseconds with `STA_NANO`, else microseconds.
    pub fraction: i64,
}

/// The raw facts of one acquisition, in acquisition order; errors are errno
/// values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Facts {
    pub boottime_before: Result<Timespec, i32>,
    pub monotonic_before: Result<Timespec, i32>,
    pub adjtimex: Result<KernelTime, i32>,
    pub realtime_after: Result<Timespec, i32>,
    pub boottime_after: Result<Timespec, i32>,
}

/// Why a sample is not standard: the first failing condition, in the order
/// of the crate documentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The `adjtimex` call failed.
    Adjtimex { errno: i32 },
    /// The status shows one of the kernel's error predicates.
    ErrorStatus { status: i32 },
    /// The returned state is `TIME_ERROR`, `TIME_OOP` or unknown.
    State { state: i32 },
    /// The maximum error lies outside 0..=`NTP_PHASE_LIMIT`.
    MaxError { maxerror: i64 },
    /// The returned fraction is outside its unit's range.
    InvalidTime { fraction: i64 },
    /// A clock read of the acquisition failed.
    ClockRead { clock: Clock, errno: i32 },
    /// The BOOTTIME bracket is negative or wider than 64 ms.
    BracketWidth { width_ns: i128 },
    /// `CLOCK_REALTIME` after the call is not within the bracket of the
    /// returned time.
    Inconsistent {
        realtime_minus_returned_ns: i128,
        width_ns: i128,
    },
    /// A suspend may have occurred and no later time-daemon write was seen.
    Suspend,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Classification {
    Standard,
    Nonstandard(Reason),
}

/// One acquisition with its classification and the emitted value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    pub facts: Facts,
    pub classification: Classification,
    pub value: u32,
}

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
//# A timestamp value MUST follow the rules given in Section 3.2.2.8 for
//# the ICMP Timestamp message.
/// The provider. Holds only the suspend-continuity state.
#[derive(Debug, Default)]
pub struct UtcClock {
    continuity: Continuity,
}

impl UtcClock {
    pub fn new() -> Self {
        Self::default()
    }

    /// One acquisition. `elapsed_ms` is the embedding's monotonic elapsed
    /// time, emitted with the high-order bit set when the sample is not
    /// standard.
    pub fn sample(&mut self, elapsed_ms: u64) -> Sample {
        self.sample_from(&mut kernel::Linux, elapsed_ms)
    }

    fn sample_from(&mut self, query: &mut impl kernel::Query, elapsed_ms: u64) -> Sample {
        let facts = kernel::acquire(query);
        let (classification, value) = match self.continuity.classify(&facts) {
            Ok(value) => (Classification::Standard, value),
            // Truncation keeps the low 31 bits, like any wrapping clock.
            Err(reason) => (
                Classification::Nonstandard(reason),
                elapsed_ms as u32 | NONSTANDARD,
            ),
        };
        Sample {
            facts,
            classification,
            value,
        }
    }
}

#[derive(Debug, Default)]
struct Continuity {
    /// Upper bound of the sleep offset at the previous measurable sample;
    /// zero at boot.
    sleep_offset_bound_ns: i128,
    /// Maximum error of the previous sample, if its call succeeded.
    previous_maxerror: Option<i64>,
    /// A possible suspend was seen and no later daemon write yet.
    awaiting_write: bool,
}

impl Continuity {
    fn classify(&mut self, facts: &Facts) -> Result<u32, Reason> {
        self.observe(facts);
        let kernel = facts.adjtimex.map_err(|errno| Reason::Adjtimex { errno })?;
        if is_error_status(kernel.status) {
            return Err(Reason::ErrorStatus {
                status: kernel.status,
            });
        }
        if !matches!(
            kernel.state,
            libc::TIME_OK | libc::TIME_INS | libc::TIME_DEL | libc::TIME_WAIT
        ) {
            return Err(Reason::State {
                state: kernel.state,
            });
        }
        if !(0..=MAX_ERROR_LIMIT_US).contains(&kernel.maxerror) {
            return Err(Reason::MaxError {
                maxerror: kernel.maxerror,
            });
        }
        let unit_ns = fraction_unit_ns(kernel.status);
        let returned_ns = returned_nanos(&kernel).ok_or(Reason::InvalidTime {
            fraction: kernel.fraction,
        })?;
        let before = read(facts.boottime_before, Clock::Boottime)?;
        read(facts.monotonic_before, Clock::Monotonic)?;
        let realtime = read(facts.realtime_after, Clock::Realtime)?;
        let after = read(facts.boottime_after, Clock::Boottime)?;
        let width_ns = after.nanos() - before.nanos();
        if !(0..=ACQUISITION_LIMIT_NS).contains(&width_ns) {
            return Err(Reason::BracketWidth { width_ns });
        }
        // Microsecond decoding truncates by less than one unit.
        let lag_ns = realtime.nanos() - returned_ns;
        if !(0..=width_ns + unit_ns - 1).contains(&lag_ns) {
            return Err(Reason::Inconsistent {
                realtime_minus_returned_ns: lag_ns,
                width_ns,
            });
        }
        if self.awaiting_write {
            return Err(Reason::Suspend);
        }
        milliseconds_since_midnight(&kernel).ok_or(Reason::InvalidTime {
            fraction: kernel.fraction,
        })
    }

    /// Suspend continuity (condition 4), updated by every sample.
    fn observe(&mut self, facts: &Facts) {
        let maxerror = facts.adjtimex.ok().map(|kernel| kernel.maxerror);
        // From a value within the limit the kernel only grows the error; a
        // decrease from above is the kernel's clamp, not a daemon write.
        let daemon_wrote = matches!(
            (self.previous_maxerror, maxerror),
            (Some(previous), Some(current))
                if (0..=MAX_ERROR_LIMIT_US).contains(&previous) && current < previous
        );
        let slept = match sleep_offset(facts) {
            // The measured offset B - M is at most the true offset, and at
            // least the true offset minus the bracket width.
            Some((offset_ns, width_ns)) if (0..=ACQUISITION_LIMIT_NS).contains(&width_ns) => {
                let slept = offset_ns > self.sleep_offset_bound_ns;
                self.sleep_offset_bound_ns = offset_ns + width_ns;
                slept
            }
            // Without a bounded measurement the previous bound stays the
            // reference: B - M only grows through a sleep, so a suspend in
            // this interval shows at the next measurable sample.
            _ => false,
        };
        if slept {
            self.awaiting_write = true;
        } else if daemon_wrote {
            self.awaiting_write = false;
        }
        self.previous_maxerror = maxerror;
    }
}

fn read(reading: Result<Timespec, i32>, clock: Clock) -> Result<Timespec, Reason> {
    reading.map_err(|errno| Reason::ClockRead { clock, errno })
}

fn sleep_offset(facts: &Facts) -> Option<(i128, i128)> {
    let before = facts.boottime_before.ok()?.nanos();
    let monotonic = facts.monotonic_before.ok()?.nanos();
    let after = facts.boottime_after.ok()?.nanos();
    Some((before - monotonic, after - before))
}

/// `kernel/time/ntp.c` `is_error_status`.
fn is_error_status(status: i32) -> bool {
    status & (libc::STA_UNSYNC | libc::STA_CLOCKERR) != 0
        || status & (libc::STA_PPSFREQ | libc::STA_PPSTIME) != 0
            && status & libc::STA_PPSSIGNAL == 0
        || status & (libc::STA_PPSTIME | libc::STA_PPSJITTER)
            == libc::STA_PPSTIME | libc::STA_PPSJITTER
        || status & libc::STA_PPSFREQ != 0
            && status & (libc::STA_PPSWANDER | libc::STA_PPSERROR) != 0
}

fn fraction_unit_ns(status: i32) -> i128 {
    if status & libc::STA_NANO != 0 { 1 } else { 1_000 }
}

fn returned_nanos(kernel: &KernelTime) -> Option<i128> {
    let unit_ns = fraction_unit_ns(kernel.status);
    let fraction = i128::from(kernel.fraction);
    if !(0..NANOS_PER_SECOND / unit_ns).contains(&fraction) {
        return None;
    }
    Some(i128::from(kernel.seconds) * NANOS_PER_SECOND + fraction * unit_ns)
}

fn milliseconds_since_midnight(kernel: &KernelTime) -> Option<u32> {
    let per_ms = if kernel.status & libc::STA_NANO != 0 { 1_000_000 } else { 1_000 };
    let ms = kernel
        .seconds
        .rem_euclid(SECONDS_PER_DAY)
        .checked_mul(1_000)?
        .checked_add(kernel.fraction.checked_div(per_ms)?)?;
    u32::try_from(ms).ok()
}
