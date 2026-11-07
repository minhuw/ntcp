//! Characterized Linux transport time: non-coarse `CLOCK_BOOTTIME` in
//! microseconds, the elapsed real time including suspend, so that MSL,
//! TIME-WAIT and key lifetimes are real durations. Linux TCP itself
//! uses `CLOCK_MONOTONIC` (`include/net/tcp.h`).
//!
//! [`TransportClock::new`] records the clock identity, the `clock_getres`
//! value, the boot id and the time namespace offsets; the reported resolution
//! is a kernel constant (`kernel/time/posix-timers.c`), never evidence of
//! resolution or accuracy. [`TransportClock::sample`] returns the ticks with
//! the suspended time measured since the previous sample.
//!
//! # Suspend
//!
//! `CLOCK_BOOTTIME` minus `CLOCK_MONOTONIC` is the sleep offset, which grows
//! only through a suspend. One sample reads MONOTONIC, BOOTTIME, MONOTONIC:
//! MONOTONIC never advances during a suspend, so the offset at the BOOTTIME
//! read lies between the two differences whenever the suspend happened. The
//! measured suspend is the current lower bound minus the previous upper
//! bound: it is never more than the real suspend, and the ticks that carry a
//! suspend always arrive in the sample that reports it, because both come
//! from the same BOOTTIME read.
//!
//! # Failures
//!
//! Every failure is explicit: a clock call error, a sample outside the
//! microsecond range, a decreasing sample, an unreadable or malformed boot
//! id. A rejected sample leaves the previous reference in place. There is no
//! frozen-time or fallback clock.

use std::fmt;

use crate::kernel::{self, TransportQuery};
use crate::{Clock, NANOS_PER_SECOND, Timespec};

const NANOS_PER_MICROSECOND: i128 = 1_000;
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const OFFSETS_PATH: &str = "/proc/self/timens_offsets";
/// `time_namespaces(7)`: reading gives the clock name, writing also accepts
/// the clock id, which older kernels showed.
const MONOTONIC_ID: &str = "1";
const BOOTTIME_ID: &str = "7";

/// The kernel's boot identifier, a random UUID fixed for one boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootId([u8; 16]);

impl BootId {
    /// The canonical form the kernel prints: 36 characters of lowercase
    /// hexadecimal, hyphens at 8, 13, 18 and 23.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.as_bytes();
        if text.len() != 36 {
            return None;
        }
        let mut digits = text.iter().enumerate().filter_map(|(index, &byte)| {
            let hyphen = matches!(index, 8 | 13 | 18 | 23);
            match (hyphen, byte) {
                (true, b'-') => None,
                (false, b'0'..=b'9') => Some(Some(byte - b'0')),
                (false, b'a'..=b'f') => Some(Some(byte - b'a' + 10)),
                _ => Some(None),
            }
        });
        let mut id = [0; 16];
        for byte in &mut id {
            *byte = digits.next()?? << 4 | digits.next()??;
        }
        (text.iter().filter(|&&byte| byte == b'-').count() == 4).then_some(Self(id))
    }
}

impl fmt::Display for BootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The time namespace's clock offsets, nanoseconds added to the host clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NamespaceOffsets {
    pub monotonic_ns: i128,
    pub boottime_ns: i128,
}

/// What the provider recorded about its clock when it was created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Characterization {
    pub clock: Clock,
    /// `clock_getres`: reported, not a resolution or accuracy claim.
    pub reported_resolution: Timespec,
    pub boot_id: BootId,
    pub offsets: NamespaceOffsets,
}

/// One transport time sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportSample {
    /// `CLOCK_BOOTTIME` in microseconds.
    pub ticks: u64,
    /// Microseconds of the growth since the previous sample that the sleep
    /// offset substantiates as suspended; zero for the provider's first.
    pub suspended: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// `clock_gettime` failed.
    ClockRead { clock: Clock, errno: i32 },
    /// `clock_getres` failed.
    ResolutionRead { errno: i32 },
    /// A reading outside the range of microsecond ticks.
    OutOfRange { clock: Clock, reading: Timespec },
    /// A reading below an earlier one of the same clock.
    Decreased {
        clock: Clock,
        previous_ns: i128,
        current_ns: i128,
    },
    /// The boot id file could not be read.
    BootIdRead { errno: i32 },
    /// The boot id file does not hold one canonical boot id.
    BootIdMalformed,
    /// The time namespace offsets could not be read.
    OffsetsRead { errno: i32 },
    /// The time namespace offsets are not the two clocks' offsets.
    OffsetsMalformed,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::ClockRead { clock, errno } => write!(f, "reading {clock:?}: errno {errno}"),
            Self::ResolutionRead { errno } => write!(f, "clock_getres: errno {errno}"),
            Self::OutOfRange { clock, reading } => {
                write!(f, "{clock:?} reading out of range: {reading:?}")
            }
            Self::Decreased {
                clock,
                previous_ns,
                current_ns,
            } => write!(
                f,
                "{clock:?} decreased from {previous_ns} to {current_ns} ns"
            ),
            Self::BootIdRead { errno } => write!(f, "reading {BOOT_ID_PATH}: errno {errno}"),
            Self::BootIdMalformed => write!(f, "malformed {BOOT_ID_PATH}"),
            Self::OffsetsRead { errno } => write!(f, "reading {OFFSETS_PATH}: errno {errno}"),
            Self::OffsetsMalformed => write!(f, "malformed {OFFSETS_PATH}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// The three reads of one sample, in acquisition order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Readings {
    monotonic_before: Timespec,
    boottime: Timespec,
    monotonic_after: Timespec,
}

/// The accepted sample the next one is measured against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Reference {
    boottime_ns: i128,
    monotonic_ns: i128,
    /// Upper bound of the sleep offset at the BOOTTIME read.
    offset_ns: i128,
}

/// The provider. Holds its characterization and the previous sample.
#[derive(Debug)]
pub struct TransportClock {
    characterization: Characterization,
    reference: Option<Reference>,
}

impl TransportClock {
    pub fn new() -> Result<Self, TransportError> {
        Self::new_from(&mut kernel::Linux)
    }

    fn new_from(query: &mut impl TransportQuery) -> Result<Self, TransportError> {
        let reported_resolution = query
            .resolution(Clock::Boottime)
            .map_err(|errno| TransportError::ResolutionRead { errno })?;
        let boot_id = query
            .read(BOOT_ID_PATH)
            .map_err(|errno| TransportError::BootIdRead { errno })?;
        let boot_id = parse_boot_id(&boot_id).ok_or(TransportError::BootIdMalformed)?;
        let offsets = match query.read(OFFSETS_PATH) {
            Ok(text) => parse_offsets(&text).ok_or(TransportError::OffsetsMalformed)?,
            // A kernel without CONFIG_TIME_NS has no such file and no offset:
            // the boot id above already showed that /proc is there.
            Err(libc::ENOENT) => NamespaceOffsets::default(),
            Err(errno) => return Err(TransportError::OffsetsRead { errno }),
        };
        Ok(Self {
            characterization: Characterization {
                clock: Clock::Boottime,
                reported_resolution,
                boot_id,
                offsets,
            },
            reference: None,
        })
    }

    pub fn characterization(&self) -> &Characterization {
        &self.characterization
    }

    //= https://www.rfc-editor.org/rfc/rfc6191#section-1
    //= reason=Native transport ticks come from the characterized CLOCK_BOOTTIME provider, which rejects decreasing samples. Endpoint::check_clock refuses earlier input and timestamp half-range jumps, every TSval is the selected tick plus one constant per-connection offset, and TIME-WAIT reuse inherits the old incarnation's offset, so a reincarnation continues its predecessor's timestamp clock. Embedders supplying their own clock own its monotonicity.
    //# For the purpose of PAWS, the timestamps sent on a connection are
    //# required to be monotonically increasing.
    /// One acquisition.
    pub fn sample(&mut self) -> Result<TransportSample, TransportError> {
        self.sample_from(&mut kernel::Linux)
    }

    fn sample_from(
        &mut self,
        query: &mut impl TransportQuery,
    ) -> Result<TransportSample, TransportError> {
        let mut read = |clock| {
            query
                .clock(clock)
                .map_err(|errno| TransportError::ClockRead { clock, errno })
        };
        let readings = Readings {
            monotonic_before: read(Clock::Monotonic)?,
            boottime: read(Clock::Boottime)?,
            monotonic_after: read(Clock::Monotonic)?,
        };
        let (sample, reference) = advance(self.reference, readings)?;
        self.reference = Some(reference);
        Ok(sample)
    }
}

fn nanos(clock: Clock, reading: Timespec) -> Result<i128, TransportError> {
    if reading.seconds < 0 || !(0..NANOS_PER_SECOND).contains(&i128::from(reading.nanoseconds)) {
        return Err(TransportError::OutOfRange { clock, reading });
    }
    Ok(reading.nanos())
}

fn not_below(clock: Clock, previous_ns: i128, current_ns: i128) -> Result<(), TransportError> {
    if current_ns < previous_ns {
        return Err(TransportError::Decreased {
            clock,
            previous_ns,
            current_ns,
        });
    }
    Ok(())
}

fn advance(
    previous: Option<Reference>,
    readings: Readings,
) -> Result<(TransportSample, Reference), TransportError> {
    let before = nanos(Clock::Monotonic, readings.monotonic_before)?;
    let boottime = nanos(Clock::Boottime, readings.boottime)?;
    let after = nanos(Clock::Monotonic, readings.monotonic_after)?;
    not_below(Clock::Monotonic, before, after)?;
    let ticks = u64::try_from(boottime / NANOS_PER_MICROSECOND).map_err(|_| {
        TransportError::OutOfRange {
            clock: Clock::Boottime,
            reading: readings.boottime,
        }
    })?;
    let mut suspended = 0;
    if let Some(previous) = previous {
        not_below(Clock::Boottime, previous.boottime_ns, boottime)?;
        not_below(Clock::Monotonic, previous.monotonic_ns, before)?;
        // Below by the read durations of both samples, never above: a
        // negative growth is those durations, not a clock going back.
        let growth = (boottime - after - previous.offset_ns).max(0);
        // At most the BOOTTIME growth, which fits the ticks' range.
        suspended = (growth / NANOS_PER_MICROSECOND) as u64;
    }
    Ok((
        TransportSample { ticks, suspended },
        Reference {
            boottime_ns: boottime,
            monotonic_ns: after,
            offset_ns: boottime - before,
        },
    ))
}

fn parse_boot_id(text: &[u8]) -> Option<BootId> {
    BootId::parse(std::str::from_utf8(text).ok()?.strip_suffix('\n')?)
}

fn parse_offsets(text: &[u8]) -> Option<NamespaceOffsets> {
    let (mut monotonic, mut boottime) = (None, None);
    for line in std::str::from_utf8(text).ok()?.lines() {
        let mut fields = line.split_ascii_whitespace();
        let (clock, seconds, nanoseconds) = (fields.next()?, fields.next()?, fields.next()?);
        let seconds: i64 = seconds.parse().ok()?;
        let nanoseconds: i64 = nanoseconds.parse().ok()?;
        if fields.next().is_some() || !(0..NANOS_PER_SECOND).contains(&i128::from(nanoseconds)) {
            return None;
        }
        let offset = Timespec {
            seconds,
            nanoseconds,
        }
        .nanos();
        let slot = match clock {
            "monotonic" | MONOTONIC_ID => &mut monotonic,
            "boottime" | BOOTTIME_ID => &mut boottime,
            _ => return None,
        };
        if slot.replace(offset).is_some() {
            return None;
        }
    }
    Some(NamespaceOffsets {
        monotonic_ns: monotonic?,
        boottime_ns: boottime?,
    })
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
