use super::*;
use kernel::Query;
use libc::{
    STA_CLOCKERR, STA_DEL, STA_INS, STA_NANO, STA_PLL, STA_PPSERROR, STA_PPSFREQ, STA_PPSJITTER,
    STA_PPSSIGNAL, STA_PPSTIME, STA_PPSWANDER, STA_UNSYNC, TIME_DEL, TIME_ERROR, TIME_INS,
    TIME_OK, TIME_OOP, TIME_WAIT,
};

const NS: i128 = 1_000_000_000;
const DAY: i64 = 86_400;
/// 12:34:56 UT on some day after 2023.
const NOON_ISH: i64 = 19_700 * DAY + 45_296;
const READ_DELAY_NS: i128 = 1_000;

fn ts(ns: i128) -> Timespec {
    Timespec {
        seconds: ns.div_euclid(NS) as i64,
        nanoseconds: ns.rem_euclid(NS) as i64,
    }
}

/// Recorded facts of one acquisition, described by the quantities the rule
/// uses: the BOOTTIME bracket, the true sleep offset and the lag of
/// CLOCK_REALTIME behind the returned time.
#[derive(Clone, Copy)]
struct Recorded {
    kernel: Result<KernelTime, i32>,
    boot_ns: i128,
    sleep_ns: i128,
    width_ns: i128,
    lag_ns: i128,
}

impl Recorded {
    fn healthy() -> Self {
        Self {
            kernel: Ok(KernelTime {
                state: TIME_OK,
                status: STA_PLL | STA_NANO,
                maxerror: 250_000,
                seconds: NOON_ISH,
                fraction: 789_123_456,
            }),
            boot_ns: 5_000 * NS,
            sleep_ns: 0,
            width_ns: 40_000,
            lag_ns: 20_000,
        }
    }

    fn kernel(mut self, edit: impl FnOnce(&mut KernelTime)) -> Self {
        let mut kernel = self.kernel.unwrap();
        edit(&mut kernel);
        self.kernel = Ok(kernel);
        self
    }

    /// The same system `seconds` later while awake: the error grows by
    /// MAXFREQ per second as the kernel's second_overflow does.
    fn later(mut self, seconds: i64) -> Self {
        self.boot_ns += i128::from(seconds) * NS;
        self.kernel(|k| {
            k.seconds += seconds;
            k.maxerror += 500 * seconds;
        })
    }

    fn facts(self) -> Facts {
        let returned = match self.kernel {
            Ok(kernel) => returned_nanos(&kernel).unwrap_or(0),
            Err(_) => i128::from(NOON_ISH) * NS,
        };
        Facts {
            boottime_before: Ok(ts(self.boot_ns)),
            // MONOTONIC is read just after BOOTTIME.
            monotonic_before: Ok(ts(self.boot_ns - self.sleep_ns + READ_DELAY_NS)),
            adjtimex: self.kernel,
            realtime_after: Ok(ts(returned + self.lag_ns)),
            boottime_after: Ok(ts(self.boot_ns + self.width_ns)),
        }
    }
}

fn first(recorded: Recorded) -> Result<u32, Reason> {
    Continuity::default().classify(&recorded.facts())
}

const STANDARD: Result<u32, Reason> = Ok(45_296_789);

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
//= type=test
//# A timestamp value MUST follow the rules given in Section 3.2.2.8 for
//# the ICMP Timestamp message.
#[test]
fn clock_states() {
    let healthy = Recorded::healthy();
    assert_eq!(first(healthy), STANDARD);
    // A pending leap (state and status bit), and the state after a leap.
    for (state, bits) in [(TIME_INS, STA_INS), (TIME_DEL, STA_DEL), (TIME_WAIT, 0)] {
        let sample = healthy.kernel(|k| {
            k.state = state;
            k.status |= bits;
        });
        assert_eq!(first(sample), STANDARD, "state {state}");
    }
    // The inserted leap second repeats a second; TIME_ERROR and any state
    // the kernel does not define are not characterized.
    for state in [TIME_OOP, TIME_ERROR, 6, -2] {
        let sample = healthy.kernel(|k| k.state = state);
        assert_eq!(first(sample), Err(Reason::State { state }));
    }
}

#[test]
fn kernel_error_predicates_on_the_status_bits() {
    let faults = [
        STA_UNSYNC,
        STA_CLOCKERR,
        STA_PPSFREQ,
        STA_PPSTIME,
        STA_PPSFREQ | STA_PPSTIME,
        STA_PPSTIME | STA_PPSJITTER | STA_PPSSIGNAL,
        STA_PPSFREQ | STA_PPSWANDER | STA_PPSSIGNAL,
        STA_PPSFREQ | STA_PPSERROR | STA_PPSSIGNAL,
    ];
    // Leap handling can return TIME_OOP or TIME_WAIT instead of TIME_ERROR,
    // so the predicates decide whatever state is returned.
    let states = [
        (TIME_OK, 0),
        (TIME_ERROR, 0),
        (TIME_WAIT, 0),
        (TIME_INS, STA_INS),
        (TIME_DEL, STA_DEL),
        (TIME_OOP, STA_INS),
    ];
    for fault in faults {
        for (state, leap) in states {
            let status = STA_PLL | STA_NANO | leap | fault;
            let sample = Recorded::healthy().kernel(|k| {
                k.state = state;
                k.status = status;
            });
            assert_eq!(first(sample), Err(Reason::ErrorStatus { status }));
        }
    }
    // PPS bits that no predicate covers.
    for healthy in [
        STA_PPSFREQ | STA_PPSTIME | STA_PPSSIGNAL,
        STA_PPSFREQ | STA_PPSJITTER | STA_PPSSIGNAL,
        STA_PPSTIME | STA_PPSWANDER | STA_PPSERROR | STA_PPSSIGNAL,
        STA_PPSJITTER | STA_PPSWANDER | STA_PPSERROR,
    ] {
        let sample = Recorded::healthy().kernel(|k| k.status |= healthy);
        assert_eq!(first(sample), STANDARD, "status {healthy:#x}");
    }
}

#[test]
fn maximum_error_limit() {
    for maxerror in [0, 16_000_000] {
        assert_eq!(
            first(Recorded::healthy().kernel(|k| k.maxerror = maxerror)),
            STANDARD
        );
    }
    // Just beyond, negative, and an ADJ_MAXERROR write above the limit with
    // synchronization still reported (before the next second_overflow clamp).
    for maxerror in [16_000_001, -1, 20_000_000] {
        let sample = Recorded::healthy().kernel(|k| k.maxerror = maxerror);
        assert_eq!(first(sample), Err(Reason::MaxError { maxerror }));
    }
}

#[test]
fn failed_calls_and_reads() {
    let mut denied = Recorded::healthy();
    denied.kernel = Err(libc::EPERM);
    assert_eq!(first(denied), Err(Reason::Adjtimex { errno: libc::EPERM }));

    let reads: [(fn(&mut Facts) -> &mut Result<Timespec, i32>, Clock); 4] = [
        (|f| &mut f.boottime_before, Clock::Boottime),
        (|f| &mut f.monotonic_before, Clock::Monotonic),
        (|f| &mut f.realtime_after, Clock::Realtime),
        (|f| &mut f.boottime_after, Clock::Boottime),
    ];
    for (field, clock) in reads {
        let mut facts = Recorded::healthy().facts();
        *field(&mut facts) = Err(libc::EINVAL);
        assert_eq!(
            Continuity::default().classify(&facts),
            Err(Reason::ClockRead {
                clock,
                errno: libc::EINVAL
            })
        );
    }
}

#[test]
fn nanosecond_and_microsecond_decoding() {
    let nano = Recorded::healthy();
    let micro = nano.kernel(|k| {
        k.status &= !STA_NANO;
        k.fraction = 789_123;
    });
    assert_eq!(first(micro), STANDARD);
    // Nanoseconds are exact; microseconds truncate by less than 1000 ns.
    for (sample, allowance) in [(nano, 0), (micro, 999)] {
        let mut fits = sample;
        fits.lag_ns = fits.width_ns + allowance;
        assert_eq!(first(fits), STANDARD);
        let mut beyond = sample;
        beyond.lag_ns = beyond.width_ns + allowance + 1;
        assert_eq!(
            first(beyond),
            Err(Reason::Inconsistent {
                realtime_minus_returned_ns: beyond.lag_ns,
                width_ns: beyond.width_ns
            })
        );
    }
    // A fraction outside its unit (a nanosecond value without STA_NANO).
    for (status, fraction) in [
        (STA_PLL | STA_NANO, 1_000_000_000),
        (STA_PLL, 1_000_000),
        (STA_PLL, -1),
    ] {
        let sample = nano.kernel(|k| {
            k.status = status;
            k.fraction = fraction;
        });
        assert_eq!(first(sample), Err(Reason::InvalidTime { fraction }));
    }
}

#[test]
fn day_rollover() {
    let last = Recorded::healthy().kernel(|k| {
        k.seconds = 19_700 * DAY + DAY - 1;
        k.fraction = 999_999_999;
    });
    assert_eq!(first(last), Ok(86_399_999));
    let last_micro = last.kernel(|k| {
        k.status &= !STA_NANO;
        k.fraction = 999_999;
    });
    assert_eq!(first(last_micro), Ok(86_399_999));
    let next = last.kernel(|k| {
        k.seconds += 1;
        k.fraction = 0;
    });
    assert_eq!(first(next), Ok(0));
}

#[test]
fn step_inside_the_bracket() {
    // do_adjtimex reads its time, then the status under the lock: a step and
    // a daemon resynchronization between them leave a healthy status beside a
    // time that CLOCK_REALTIME no longer matches.
    for lag_ns in [2 * NS, -NS, -1] {
        let mut stepped = Recorded::healthy();
        stepped.lag_ns = lag_ns;
        assert_eq!(
            first(stepped),
            Err(Reason::Inconsistent {
                realtime_minus_returned_ns: lag_ns,
                width_ns: stepped.width_ns
            })
        );
    }
}

#[test]
fn bracket_width() {
    let mut exact = Recorded::healthy();
    exact.width_ns = 64_000_000;
    assert_eq!(first(exact), STANDARD);
    for width_ns in [64_000_001, -1] {
        let mut delayed = Recorded::healthy();
        delayed.width_ns = width_ns;
        delayed.lag_ns = 0;
        assert_eq!(first(delayed), Err(Reason::BracketWidth { width_ns }));
    }
}

#[test]
fn suspend_waits_for_a_later_daemon_write() {
    let mut clock = Continuity::default();
    let awake = Recorded::healthy();
    assert_eq!(clock.classify(&awake.facts()), STANDARD);
    // Generic resume: status and maximum error unchanged, sleep offset grown.
    let mut resumed = awake.kernel(|k| k.seconds += 3_600);
    resumed.boot_ns += 3_600 * NS;
    resumed.sleep_ns = 3_590 * NS;
    assert_eq!(clock.classify(&resumed.facts()), Err(Reason::Suspend));
    // The kernel's own growth is no write.
    let grown = resumed.later(1);
    assert_eq!(clock.classify(&grown.facts()), Err(Reason::Suspend));
    let decreased = grown.later(1).kernel(|k| k.maxerror = 40_000);
    assert_eq!(
        clock.classify(&decreased.facts()),
        Ok(45_296_789 + 3_602_000)
    );
    assert_eq!(
        clock.classify(&decreased.later(1).facts()),
        Ok(45_296_789 + 3_603_000)
    );
}

#[test]
fn suspend_decrease_needs_a_later_sample() {
    let mut clock = Continuity::default();
    let awake = Recorded::healthy();
    assert_eq!(clock.classify(&awake.facts()), STANDARD);
    // A write before the suspend can lower the error seen at the sample that
    // detects it; only a decrease after that sample follows the suspend.
    let mut resumed = awake.later(60).kernel(|k| k.maxerror = 10_000);
    resumed.sleep_ns = 50 * NS;
    assert_eq!(clock.classify(&resumed.facts()), Err(Reason::Suspend));
    // A decrease seen by a failing sample counts, but that sample fails.
    let unsynced = resumed.later(1).kernel(|k| {
        k.maxerror = 5_000;
        k.status |= STA_UNSYNC;
    });
    let status = unsynced.kernel.unwrap().status;
    assert_eq!(
        clock.classify(&unsynced.facts()),
        Err(Reason::ErrorStatus { status })
    );
    let healthy = unsynced.later(1).kernel(|k| k.status &= !STA_UNSYNC);
    assert_eq!(clock.classify(&healthy.facts()), Ok(45_296_789 + 62_000));
}

#[test]
fn clamp_from_above_the_limit_is_no_write() {
    let mut clock = Continuity::default();
    let mut resumed = Recorded::healthy().kernel(|k| k.maxerror = 16_400_000);
    resumed.sleep_ns = 10 * NS;
    assert_eq!(
        clock.classify(&resumed.facts()),
        Err(Reason::MaxError {
            maxerror: 16_400_000
        })
    );
    // second_overflow clamps to NTP_PHASE_LIMIT and sets STA_UNSYNC; a
    // daemon then clears STA_UNSYNC without writing the error.
    let clamped = resumed.later(1).kernel(|k| k.maxerror = 16_000_000);
    assert_eq!(clock.classify(&clamped.facts()), Err(Reason::Suspend));
    let held = clamped.later(1).kernel(|k| k.maxerror = 16_000_000);
    assert_eq!(clock.classify(&held.facts()), Err(Reason::Suspend));
}

#[test]
fn sleep_offset_at_the_first_sample() {
    let mut suspended_before = Recorded::healthy();
    suspended_before.sleep_ns = 120 * NS;
    let mut clock = Continuity::default();
    assert_eq!(clock.classify(&suspended_before.facts()), Err(Reason::Suspend));
    let written = suspended_before.later(2).kernel(|k| k.maxerror = 1_000);
    assert_eq!(clock.classify(&written.facts()), Ok(45_296_789 + 2_000));
    // Never suspended: the measured offset is the read delay below zero.
    assert_eq!(first(Recorded::healthy()), STANDARD);
}

#[test]
fn sleep_offset_within_measurement_uncertainty() {
    let mut clock = Continuity::default();
    let mut previous = Recorded::healthy();
    previous.sleep_ns = 30 * NS;
    clock.classify(&previous.facts()).unwrap_err();
    let written = previous.later(1).kernel(|k| k.maxerror = 1_000);
    assert!(clock.classify(&written.facts()).is_ok());
    // The bound is the previous measurement plus its bracket width.
    let mut within = written.later(1);
    within.sleep_ns += written.width_ns;
    assert!(clock.classify(&within.facts()).is_ok());
    let mut beyond = within.later(1);
    beyond.sleep_ns += within.width_ns + 1;
    assert_eq!(clock.classify(&beyond.facts()), Err(Reason::Suspend));
}

#[test]
fn unmeasurable_sleep_offset_keeps_the_previous_reference() {
    let mut clock = Continuity::default();
    let awake = Recorded::healthy();
    assert_eq!(clock.classify(&awake.facts()), STANDARD);
    // A slow acquisition fails itself but is no evidence of a suspend.
    let mut delayed = awake.later(1);
    delayed.width_ns = 5 * NS;
    assert_eq!(
        clock.classify(&delayed.facts()),
        Err(Reason::BracketWidth { width_ns: 5 * NS })
    );
    let mut healthy = delayed.later(1);
    healthy.width_ns = awake.width_ns;
    assert_eq!(clock.classify(&healthy.facts()), Ok(45_296_789 + 2_000));
    // Neither is a failed MONOTONIC read.
    let mut facts = healthy.later(1).facts();
    facts.monotonic_before = Err(libc::EINVAL);
    clock.classify(&facts).unwrap_err();
    assert_eq!(
        clock.classify(&healthy.later(2).facts()),
        Ok(45_296_789 + 4_000)
    );
    // A suspend during an unmeasurable sample shows at the next measurable
    // one against the retained reference.
    let mut slept = healthy.later(3);
    slept.width_ns = 5 * NS;
    slept.sleep_ns = 60 * NS;
    clock.classify(&slept.facts()).unwrap_err();
    let mut resumed = slept.later(1);
    resumed.width_ns = awake.width_ns;
    assert_eq!(clock.classify(&resumed.facts()), Err(Reason::Suspend));
    // A later write seen by an unmeasurable sample still follows the
    // suspend detected before it.
    let mut written = resumed.later(1).kernel(|k| k.maxerror = 1_000);
    written.width_ns = 5 * NS;
    clock.classify(&written.facts()).unwrap_err();
    let mut after = written.later(1);
    after.width_ns = awake.width_ns;
    assert_eq!(clock.classify(&after.facts()), Ok(45_296_789 + 8_000));
}

/// Replays recorded facts through the production query boundary.
struct Replay {
    facts: Facts,
    calls: Vec<&'static str>,
    boottime_reads: usize,
}

impl Query for Replay {
    fn clock(&mut self, clock: Clock) -> Result<Timespec, i32> {
        self.calls.push(match clock {
            Clock::Boottime => "boottime",
            Clock::Monotonic => "monotonic",
            Clock::Realtime => "realtime",
        });
        match clock {
            Clock::Boottime => {
                self.boottime_reads += 1;
                if self.boottime_reads % 2 == 1 {
                    self.facts.boottime_before
                } else {
                    self.facts.boottime_after
                }
            }
            Clock::Monotonic => self.facts.monotonic_before,
            Clock::Realtime => self.facts.realtime_after,
        }
    }

    fn adjtimex(&mut self) -> Result<KernelTime, i32> {
        self.calls.push("adjtimex");
        self.facts.adjtimex
    }
}

#[test]
fn one_acquisition_per_sample() {
    let facts = Recorded::healthy().facts();
    let mut replay = Replay {
        facts,
        calls: Vec::new(),
        boottime_reads: 0,
    };
    let mut clock = UtcClock::new();
    let sample = clock.sample_from(&mut replay, 7);
    let order = ["boottime", "monotonic", "adjtimex", "realtime", "boottime"];
    assert_eq!(replay.calls, order);
    assert_eq!(
        sample,
        Sample {
            facts,
            classification: Classification::Standard,
            value: 45_296_789
        }
    );
    // No status cache: the next sample queries the kernel again.
    clock.sample_from(&mut replay, 8);
    assert_eq!(replay.calls, [order, order].concat());
}

#[test]
fn nonstandard_value_is_marked_elapsed_time() {
    let mut replay = Replay {
        facts: Recorded::healthy().facts(),
        calls: Vec::new(),
        boottime_reads: 0,
    };
    replay.facts.adjtimex = Err(libc::EPERM);
    for (elapsed, value) in [
        (0, 0x8000_0000),
        (1_234, 0x8000_04d2),
        (0x1_8765_4321, 0x8765_4321),
    ] {
        let sample = UtcClock::new().sample_from(&mut replay, elapsed);
        assert_eq!(
            sample.classification,
            Classification::Nonstandard(Reason::Adjtimex { errno: libc::EPERM })
        );
        assert_eq!(sample.value, value);
    }
}

mod actual {
    use super::*;
    use std::time::{Duration, Instant};

    /// Test oracle, written independently of the classification: the
    /// standard value conditions 1-3 evaluated on the recorded facts.
    fn per_sample_value(facts: &Facts) -> Option<u32> {
        let kernel = facts.adjtimex.ok()?;
        let status = kernel.status;
        let has = |bits: i32| status & bits == bits;
        let any = |bits: i32| status & bits != 0;
        let kernel_error = any(STA_UNSYNC)
            || any(STA_CLOCKERR)
            || (has(STA_PPSFREQ) || has(STA_PPSTIME)) && !has(STA_PPSSIGNAL)
            || has(STA_PPSTIME) && has(STA_PPSJITTER)
            || has(STA_PPSFREQ) && (has(STA_PPSWANDER) || has(STA_PPSERROR));
        if kernel_error
            || ![TIME_OK, TIME_INS, TIME_DEL, TIME_WAIT].contains(&kernel.state)
            || kernel.maxerror < 0
            || kernel.maxerror > 16_000_000
        {
            return None;
        }
        let nano = has(STA_NANO);
        let (scale, limit) = if nano { (1, NS) } else { (1_000, 1_000_000) };
        let fraction = i128::from(kernel.fraction);
        if fraction < 0 || fraction >= limit {
            return None;
        }
        let nanos = |t: Timespec| i128::from(t.seconds) * NS + i128::from(t.nanoseconds);
        let before = nanos(facts.boottime_before.ok()?);
        facts.monotonic_before.ok()?;
        let realtime = nanos(facts.realtime_after.ok()?);
        let after = nanos(facts.boottime_after.ok()?);
        let width = after - before;
        let lag = realtime - (i128::from(kernel.seconds) * NS + fraction * scale);
        if !(0..=64_000_000).contains(&width) || lag < 0 || lag > width + scale - 1 {
            return None;
        }
        let ms = i128::from(kernel.seconds.rem_euclid(DAY)) * 1_000 + fraction * scale / 1_000_000;
        Some(u32::try_from(ms).unwrap())
    }

    fn check(sample: &Sample, elapsed: u64) {
        let facts = &sample.facts;
        let expected = per_sample_value(facts);
        match sample.classification {
            Classification::Standard => {
                assert_eq!(Some(sample.value), expected, "{sample:?}");
                assert!(sample.value < 86_400_000);
                return;
            }
            Classification::Nonstandard(Reason::Suspend) => {
                assert!(expected.is_some(), "{sample:?}")
            }
            Classification::Nonstandard(reason) => {
                assert_eq!(expected, None, "{sample:?}");
                let kernel = facts.adjtimex.ok();
                match reason {
                    Reason::Adjtimex { errno } => assert_eq!(facts.adjtimex, Err(errno)),
                    Reason::ErrorStatus { status } => assert_eq!(kernel.unwrap().status, status),
                    Reason::State { state } => assert_eq!(kernel.unwrap().state, state),
                    Reason::MaxError { maxerror } => {
                        assert_eq!(kernel.unwrap().maxerror, maxerror)
                    }
                    Reason::InvalidTime { fraction } => {
                        assert_eq!(kernel.unwrap().fraction, fraction)
                    }
                    Reason::ClockRead { errno, .. } => assert!(
                        [
                            facts.boottime_before,
                            facts.monotonic_before,
                            facts.realtime_after,
                            facts.boottime_after
                        ]
                        .contains(&Err(errno))
                    ),
                    Reason::BracketWidth { width_ns } => assert_eq!(
                        width_ns,
                        facts.boottime_after.unwrap().nanos()
                            - facts.boottime_before.unwrap().nanos()
                    ),
                    Reason::Inconsistent {
                        realtime_minus_returned_ns,
                        ..
                    } => assert_eq!(
                        realtime_minus_returned_ns,
                        facts.realtime_after.unwrap().nanos()
                            - returned_nanos(&kernel.unwrap()).unwrap()
                    ),
                    Reason::Suspend => unreachable!(),
                }
            }
        }
        assert_eq!(sample.value, elapsed as u32 | 0x8000_0000);
    }

    //= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
    //= type=test
    //# A timestamp value MUST follow the rules given in Section 3.2.2.8 for
    //# the ICMP Timestamp message.
    /// Consistency of each actual sample with its own facts; whether this
    /// machine is synchronized is not asserted.
    #[test]
    fn actual_samples_match_their_facts() {
        let mut clock = UtcClock::new();
        let start = Instant::now();
        let first = clock.sample(0);
        check(&first, 0);
        if first.classification == Classification::Nonstandard(Reason::Suspend) {
            // Only an observed sleep offset or an unbounded measurement.
            let offset = first.facts.boottime_before.unwrap().nanos()
                - first.facts.monotonic_before.unwrap().nanos();
            assert!(offset > 0, "{first:?}");
        }
        for _ in 0..20 {
            let elapsed = start.elapsed().as_millis() as u64;
            check(&clock.sample(elapsed), elapsed);
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[derive(Debug, PartialEq)]
    enum Cadence {
        /// An unbroken chain of changes, each within less than 1/15 s,
        /// covering at least one second of BOOTTIME.
        Shown { links: usize, span_ns: i128 },
        /// Too few usable observations: no evidence either way.
        Inconclusive { usable: usize, best_span_ns: i128 },
        /// The returned time stayed unchanged for at least 1/15 s.
        Stalled { stall_ns: i128 },
    }

    /// Bracket and returned time of a usable observation.
    fn observation(facts: &Facts) -> Option<(i128, i128, i128, i128)> {
        let kernel = facts.adjtimex.ok()?;
        let before = facts.boottime_before.ok()?.nanos();
        let after = facts.boottime_after.ok()?.nanos();
        let returned = returned_nanos(&kernel)?;
        (0..=64_000_000)
            .contains(&(after - before))
            .then_some((before, after, returned, fraction_unit_ns(kernel.status) - 1))
    }

    fn characterize(samples: &[Facts]) -> Cadence {
        let observations: Vec<_> = samples.iter().map(observation).collect();
        let usable = observations.iter().flatten().count();
        let (mut links, mut chain_start, mut best_span_ns) = (0, None, 0);
        // End of the bracket of the first observation of the current
        // unchanged returned time.
        let mut unchanged_since = None;
        for pair in observations.windows(2) {
            let (Some(a), Some(b)) = (pair[0], pair[1]) else {
                chain_start = None;
                unchanged_since = None;
                continue;
            };
            let (upper, change) = (b.1 - a.0, b.2 - a.2);
            if change == 0 {
                let stall_ns = b.0 - *unchanged_since.get_or_insert(a.1);
                if stall_ns * 15 >= NS {
                    return Cadence::Stalled { stall_ns };
                }
            } else {
                unchanged_since = None;
            }
            // A change within less than 1/15 s that no step explains.
            if change <= 0 || upper * 15 >= NS || change > upper + b.3 {
                chain_start = None;
                continue;
            }
            let start = *chain_start.get_or_insert_with(|| {
                links = 0;
                a.1
            });
            links += 1;
            let span_ns = b.0 - start;
            best_span_ns = best_span_ns.max(span_ns);
            if span_ns >= NS {
                return Cadence::Shown { links, span_ns };
            }
        }
        Cadence::Inconclusive {
            usable,
            best_span_ns,
        }
    }

    #[test]
    fn characterization_is_never_positive_without_observations() {
        let healthy = |boot_s: i128, returned_ms: i64| {
            let mut recorded = Recorded::healthy().kernel(|k| {
                k.seconds = NOON_ISH + returned_ms / 1_000;
                k.fraction = returned_ms % 1_000 * 1_000_000;
            });
            recorded.boot_ns = boot_s;
            recorded.facts()
        };
        assert!(matches!(
            characterize(&[]),
            Cadence::Inconclusive { usable: 0, .. }
        ));
        // Denied calls observe nothing.
        let mut denied = Recorded::healthy().facts();
        denied.adjtimex = Err(libc::EPERM);
        assert!(matches!(
            characterize(&[denied; 100]),
            Cadence::Inconclusive { usable: 0, .. }
        ));
        // 10 ms progression for half a second is not yet one second.
        let short: Vec<_> = (0..50).map(|i| healthy(i * 10_000_000, i as i64 * 10)).collect();
        assert!(matches!(characterize(&short), Cadence::Inconclusive { .. }));
        let long: Vec<_> = (0..120).map(|i| healthy(i * 10_000_000, i as i64 * 10)).collect();
        assert!(matches!(characterize(&long), Cadence::Shown { .. }));
        // A clock updated ten times per second stalls for 100 ms.
        let coarse: Vec<_> = (0..120)
            .map(|i| healthy(i * 10_000_000, i as i64 / 10 * 100))
            .collect();
        assert!(matches!(characterize(&coarse), Cadence::Stalled { .. }));
    }

    //= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
    //= type=test
    //# A timestamp value MUST follow the rules given in Section 3.2.2.8 for
    //# the ICMP Timestamp message.
    /// Bounded characterization of the returned time's progression on the
    /// tested system. A finite run does not prove future behaviour, and an
    /// inconclusive run is reported as a failure, never as evidence.
    #[test]
    fn actual_cadence_characterization() {
        let mut clock = UtcClock::new();
        let start = Instant::now();
        let mut samples = Vec::new();
        let outcome = loop {
            samples.push(clock.sample(start.elapsed().as_millis() as u64).facts);
            let outcome = characterize(&samples);
            if !matches!(outcome, Cadence::Inconclusive { .. })
                || start.elapsed() >= Duration::from_secs(10)
            {
                break outcome;
            }
            std::thread::sleep(Duration::from_millis(2));
        };
        eprintln!("cadence after {} acquisitions: {outcome:?}", samples.len());
        assert!(matches!(outcome, Cadence::Shown { .. }), "{outcome:?}");
    }
}
