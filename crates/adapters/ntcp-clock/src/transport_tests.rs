use super::*;

const BOOT_ID: &str = "0f1e2d3c-4b5a-4978-8695-a4b3c2d1e0ff";
const OFFSETS: &str = "monotonic           0         0\nboottime            0         0\n";
const NS: i128 = 1_000_000_000;

fn ts(ns: i128) -> Timespec {
    Timespec {
        seconds: ns.div_euclid(NS) as i64,
        nanoseconds: ns.rem_euclid(NS) as i64,
    }
}

/// `clock_gettime` readings scripted in acquisition order, with the file and
/// `clock_getres` results of the provider's creation.
struct Script {
    readings: Vec<(Clock, Result<Timespec, i32>)>,
    resolution: Result<Timespec, i32>,
    boot_id: Result<Vec<u8>, i32>,
    offsets: Result<Vec<u8>, i32>,
}

impl Script {
    fn healthy() -> Self {
        Self {
            readings: Vec::new(),
            resolution: Ok(ts(1)),
            boot_id: Ok(format!("{BOOT_ID}\n").into_bytes()),
            offsets: Ok(OFFSETS.into()),
        }
    }

    /// One sample's reads, as nanoseconds.
    fn sample(mut self, before: i128, boottime: i128, after: i128) -> Self {
        self.readings.extend([
            (Clock::Monotonic, Ok(ts(before))),
            (Clock::Boottime, Ok(ts(boottime))),
            (Clock::Monotonic, Ok(ts(after))),
        ]);
        self
    }

    fn clock(self) -> (TransportClock, Self) {
        let mut script = self;
        (TransportClock::new_from(&mut script).unwrap(), script)
    }
}

impl TransportQuery for Script {
    fn clock(&mut self, clock: Clock) -> Result<Timespec, i32> {
        let (expected, reading) = self.readings.remove(0);
        assert_eq!(expected, clock);
        reading
    }

    fn resolution(&mut self, clock: Clock) -> Result<Timespec, i32> {
        assert_eq!(clock, Clock::Boottime);
        self.resolution
    }

    fn read(&mut self, path: &str) -> Result<Vec<u8>, i32> {
        match path {
            "/proc/sys/kernel/random/boot_id" => self.boot_id.clone(),
            "/proc/self/timens_offsets" => self.offsets.clone(),
            _ => panic!("unexpected read of {path}"),
        }
    }
}

fn created(script: Script) -> Result<Characterization, TransportError> {
    let mut script = script;
    TransportClock::new_from(&mut script).map(|clock| clock.characterization)
}

#[test]
fn creation_records_the_characterization() {
    let mut script = Script::healthy();
    script.resolution = Ok(ts(4_000_000));
    script.offsets = Ok(b"monotonic 10 5\nboottime -3 999999999\n".to_vec());
    assert_eq!(
        created(script),
        Ok(Characterization {
            clock: Clock::Boottime,
            reported_resolution: ts(4_000_000),
            boot_id: BootId::parse(BOOT_ID).unwrap(),
            offsets: NamespaceOffsets {
                monotonic_ns: 10 * NS + 5,
                boottime_ns: -3 * NS + 999_999_999,
            },
        })
    );
}

#[test]
fn creation_errors_are_explicit() {
    let mut script = Script::healthy();
    script.resolution = Err(libc::EINVAL);
    assert_eq!(
        created(script),
        Err(TransportError::ResolutionRead {
            errno: libc::EINVAL
        })
    );
    let mut script = Script::healthy();
    script.boot_id = Err(libc::EACCES);
    assert_eq!(
        created(script),
        Err(TransportError::BootIdRead {
            errno: libc::EACCES
        })
    );
    // An absent boot id is a failure too, unlike absent offsets.
    let mut script = Script::healthy();
    script.boot_id = Err(libc::ENOENT);
    assert_eq!(
        created(script),
        Err(TransportError::BootIdRead {
            errno: libc::ENOENT
        })
    );
    let mut script = Script::healthy();
    script.boot_id = Ok(b"not a boot id\n".to_vec());
    assert_eq!(created(script), Err(TransportError::BootIdMalformed));
    let mut script = Script::healthy();
    script.offsets = Err(libc::EACCES);
    assert_eq!(
        created(script),
        Err(TransportError::OffsetsRead {
            errno: libc::EACCES
        })
    );
    let mut script = Script::healthy();
    script.offsets = Ok(b"boottime 1 0\n".to_vec());
    assert_eq!(created(script), Err(TransportError::OffsetsMalformed));
}

#[test]
fn kernel_without_time_namespaces_has_no_offsets() {
    let mut script = Script::healthy();
    script.offsets = Err(libc::ENOENT);
    assert_eq!(
        created(script).unwrap().offsets,
        NamespaceOffsets::default()
    );
}

#[test]
fn boot_id_text() {
    let id = |text: &[u8]| parse_boot_id(text).map(|id| id.to_string());
    let canonical = format!("{BOOT_ID}\n");
    assert_eq!(id(canonical.as_bytes()).as_deref(), Some(BOOT_ID));
    // Without its line end, with another, or with anything around it.
    assert_eq!(id(BOOT_ID.as_bytes()), None);
    assert_eq!(id(format!("{BOOT_ID}\n\n").as_bytes()), None);
    assert_eq!(id(format!(" {BOOT_ID}\n").as_bytes()), None);
    // Length, case, digit and hyphen positions.
    for text in [
        "",
        "\n",
        "0f1e2d3c-4b5a-4978-8695-a4b3c2d1e0f\n",
        "0f1e2d3c-4b5a-4978-8695-a4b3c2d1e0ff0\n",
        "0F1E2D3C-4B5A-4978-8695-A4B3C2D1E0FF\n",
        "0f1e2d3c-4b5a-4978-8695-a4b3c2d1e0fg\n",
        "0f1e2d3c04b5a-4978-8695-a4b3c2d1e0ff\n",
        "0f1e2d3c-4b5a-49788-695-a4b3c2d1e0ff\n",
        "0f1e2d3c-4b5a-4978-8695-a4b3c2d1e-ff\n",
    ] {
        assert_eq!(id(text.as_bytes()), None, "{text:?}");
    }
    assert_eq!(parse_boot_id(&[0xff; 37]), None);
}

#[test]
fn timens_offsets_text() {
    let offsets = |text: &str| parse_offsets(text.as_bytes());
    assert_eq!(offsets(OFFSETS), Some(NamespaceOffsets::default()));
    // Either order, and the clock ids of time_namespaces(7).
    assert_eq!(
        offsets("7 100 0\n1 -2 500000000\n"),
        Some(NamespaceOffsets {
            monotonic_ns: -2 * NS + 500_000_000,
            boottime_ns: 100 * NS,
        })
    );
    for text in [
        "",
        "boottime 0 0\n",
        "monotonic 0 0\n",
        "monotonic 0 0\nmonotonic 0 0\nboottime 0 0\n",
        "monotonic 0 0\nboottime 0 0\nboottime 0 0\n",
        "monotonic 0 0\nrealtime 0 0\n",
        "monotonic 0\nboottime 0 0\n",
        "monotonic 0 0 0\nboottime 0 0\n",
        "monotonic x 0\nboottime 0 0\n",
        "monotonic 0 1000000000\nboottime 0 0\n",
        "monotonic 0 -1\nboottime 0 0\n",
        "monotonic 9223372036854775808 0\nboottime 0 0\n",
    ] {
        assert_eq!(offsets(text), None, "{text:?}");
    }
    assert_eq!(parse_offsets(&[0xff, b' ', b'0']), None);
}

#[test]
fn ticks_are_truncated_microseconds_in_acquisition_order() {
    let (mut clock, mut script) = Script::healthy().sample(90, 5 * NS + 1_999, 100).clock();
    assert_eq!(
        clock.sample_from(&mut script),
        Ok(TransportSample {
            ticks: 5_000_001,
            suspended: 0,
        })
    );
    assert!(script.readings.is_empty());
}

#[test]
fn suspend_is_the_growth_of_boottime_minus_monotonic() {
    let (mut clock, mut script) = Script::healthy()
        // Offset 100 s, already there at the first sample: no interval.
        .sample(5 * NS, 105 * NS, 5 * NS + 300)
        // One second awake, then 60 s asleep between the samples.
        .sample(6 * NS, 166 * NS, 6 * NS + 300)
        // Awake again: nothing further, whatever the offset's absolute value.
        .sample(7 * NS, 167 * NS, 7 * NS + 300)
        .clock();
    assert_eq!(clock.sample_from(&mut script).unwrap().suspended, 0);
    // Read durations (300 ns) keep the measure just below the real 60 s.
    let resumed = clock.sample_from(&mut script).unwrap();
    assert_eq!(resumed.ticks, 166_000_000);
    assert_eq!(resumed.suspended, 59_999_999);
    assert_eq!(clock.sample_from(&mut script).unwrap().suspended, 0);
}

#[test]
fn a_suspend_between_the_reads_of_one_sample_is_measured_with_its_ticks() {
    // Asleep between the first MONOTONIC read and BOOTTIME, then between
    // BOOTTIME and the last MONOTONIC read: only the first moves the BOOTTIME
    // read, which is the sample that reports it.
    let (mut clock, mut script) = Script::healthy()
        .sample(5 * NS, 5 * NS + 100, 5 * NS + 200)
        .sample(6 * NS, 106 * NS, 6 * NS + 100)
        .sample(6 * NS + 200, 106 * NS + 300, 6 * NS + 400)
        .sample(7 * NS, 207 * NS, 7 * NS + 100)
        .clock();
    clock.sample_from(&mut script).unwrap();
    let first = clock.sample_from(&mut script).unwrap();
    assert_eq!(first.ticks, 106_000_000);
    assert_eq!(first.suspended, 99_999_999);
    assert_eq!(clock.sample_from(&mut script).unwrap().suspended, 0);
    assert_eq!(
        clock.sample_from(&mut script).unwrap().suspended,
        99_999_999
    );
}

#[test]
fn a_slow_acquisition_is_not_a_suspend() {
    let (mut clock, mut script) = Script::healthy()
        .sample(5 * NS, 105 * NS, 5 * NS + 100)
        // Preempted for half a second before the BOOTTIME read: the reading
        // of the offset alone would grow, the bound does not.
        .sample(6 * NS, 106 * NS + 500_000_000, 6 * NS + 500_000_100)
        // And after it, which alone would shrink it.
        .sample(7 * NS, 107 * NS, 7 * NS + 500_000_000)
        .sample(8 * NS, 108 * NS, 8 * NS + 100)
        .clock();
    for _ in 0..4 {
        assert_eq!(clock.sample_from(&mut script).unwrap().suspended, 0);
    }
}

#[test]
fn suspend_never_exceeds_the_tick_advance() {
    // Exactly at microsecond boundaries the truncations meet.
    let (mut clock, mut script) = Script::healthy()
        .sample(0, 999, 0)
        .sample(0, 2 * NS + 2_000, 0)
        .clock();
    let first = clock.sample_from(&mut script).unwrap();
    let second = clock.sample_from(&mut script).unwrap();
    assert!(second.suspended <= second.ticks - first.ticks);
    assert_eq!(second.suspended, 2_000_001);
}

//= https://www.rfc-editor.org/rfc/rfc6191#section-1
//= type=test
//= reason=Native transport ticks come from the characterized CLOCK_BOOTTIME provider, which rejects decreasing samples. Endpoint::check_clock refuses earlier input and timestamp half-range jumps, every TSval is the selected tick plus one constant per-connection offset, and TIME-WAIT reuse inherits the old incarnation's offset, so a reincarnation continues its predecessor's timestamp clock. Embedders supplying their own clock own its monotonicity.
//# For the purpose of PAWS, the timestamps sent on a connection are
//# required to be monotonically increasing.
#[test]
fn decreasing_samples_are_rejected_and_the_reference_stays() {
    let (mut clock, mut script) = Script::healthy()
        .sample(5 * NS, 10 * NS, 5 * NS)
        // BOOTTIME back.
        .sample(6 * NS, 10 * NS - 1, 6 * NS)
        // MONOTONIC back against the previous sample.
        .sample(5 * NS - 1, 11 * NS, 5 * NS - 1)
        // MONOTONIC back within the sample.
        .sample(6 * NS, 11 * NS, 6 * NS - 1)
        // The next acceptable sample measures from the first.
        .sample(6 * NS, 11 * NS, 6 * NS)
        .clock();
    clock.sample_from(&mut script).unwrap();
    assert_eq!(
        clock.sample_from(&mut script),
        Err(TransportError::Decreased {
            clock: Clock::Boottime,
            previous_ns: 10 * NS,
            current_ns: 10 * NS - 1,
        })
    );
    assert_eq!(
        clock.sample_from(&mut script),
        Err(TransportError::Decreased {
            clock: Clock::Monotonic,
            previous_ns: 5 * NS,
            current_ns: 5 * NS - 1,
        })
    );
    assert_eq!(
        clock.sample_from(&mut script),
        Err(TransportError::Decreased {
            clock: Clock::Monotonic,
            previous_ns: 6 * NS,
            current_ns: 6 * NS - 1,
        })
    );
    assert_eq!(
        clock.sample_from(&mut script),
        Ok(TransportSample {
            ticks: 11_000_000,
            suspended: 0,
        })
    );
}

#[test]
fn equal_samples_are_accepted() {
    let (mut clock, mut script) = Script::healthy()
        .sample(5 * NS, 10 * NS, 5 * NS)
        .sample(5 * NS, 10 * NS, 5 * NS)
        .clock();
    let first = clock.sample_from(&mut script).unwrap();
    assert_eq!(clock.sample_from(&mut script), Ok(first));
}

#[test]
fn out_of_range_readings_are_rejected() {
    let reject = |clock_name: Clock, reading: Timespec, readings: [Timespec; 3]| {
        let mut script = Script::healthy();
        script.readings = [Clock::Monotonic, Clock::Boottime, Clock::Monotonic]
            .into_iter()
            .zip(readings.map(Ok))
            .collect();
        let (mut clock, mut script) = script.clock();
        assert_eq!(
            clock.sample_from(&mut script),
            Err(TransportError::OutOfRange {
                clock: clock_name,
                reading,
            })
        );
    };
    let zero = ts(0);
    let negative = Timespec {
        seconds: -1,
        nanoseconds: 0,
    };
    let fraction = Timespec {
        seconds: 1,
        nanoseconds: 1_000_000_000,
    };
    let below = Timespec {
        seconds: 1,
        nanoseconds: -1,
    };
    for reading in [negative, fraction, below] {
        reject(Clock::Boottime, reading, [zero, reading, zero]);
        reject(Clock::Monotonic, reading, [reading, zero, zero]);
        reject(Clock::Monotonic, reading, [zero, zero, reading]);
    }
    // Representable as a timespec, not as microsecond ticks.
    let overflowing = Timespec {
        seconds: i64::MAX,
        nanoseconds: 0,
    };
    reject(Clock::Boottime, overflowing, [zero, overflowing, zero]);
}

#[test]
fn largest_ticks_are_accepted() {
    let seconds = u64::MAX / 1_000_000;
    let boottime = i128::from(seconds) * NS;
    let (mut clock, mut script) = Script::healthy().sample(0, boottime, 0).clock();
    assert_eq!(
        clock.sample_from(&mut script).unwrap().ticks,
        seconds * 1_000_000
    );
}

#[test]
fn clock_read_errors_name_the_clock() {
    for failing in 0..3 {
        let mut script = Script::healthy().sample(0, 0, 0);
        script.readings[failing].1 = Err(libc::EINVAL);
        let clock = script.readings[failing].0;
        let (mut provider, mut script) = script.clock();
        assert_eq!(
            provider.sample_from(&mut script),
            Err(TransportError::ClockRead {
                clock,
                errno: libc::EINVAL,
            })
        );
    }
}

#[test]
fn host_boot_age_removes_the_namespace_offset() {
    // A namespace that presents a host booted ten days earlier.
    let ten_days = 864_000 * NS;
    assert_eq!(boot_age(864_000_000_000 + 5, ten_days), Ok(5));
    assert_eq!(boot_age(5, 0), Ok(5));
    // One behind the host's clock: the host is older than the reading.
    assert_eq!(boot_age(5, -NS), Ok(1_000_005));
    // A fraction of a microsecond of offset rounds the age down.
    assert_eq!(boot_age(5, 1), Ok(4));
    for (ticks, offset) in [(5, ten_days), (5, 5_000), (0, 0)] {
        assert_eq!(
            boot_age(ticks, offset),
            Err(TransportError::BootAge {
                ticks,
                boottime_offset_ns: offset,
            })
        );
    }
    // More than the ticks' range.
    assert_eq!(
        boot_age(u64::MAX, -NS),
        Err(TransportError::BootAge {
            ticks: u64::MAX,
            boottime_offset_ns: -NS,
        })
    );
}

/// Observations of the clocks of the host running this test. They show what
/// this kernel did during the test, nothing about other hardware or about
/// the clock's accuracy; everything above tests parsing and arithmetic.
mod host_observations {
    use super::*;

    fn read(clock: Clock) -> i128 {
        kernel::TransportQuery::clock(&mut kernel::Linux, clock)
            .unwrap()
            .nanos()
    }

    #[test]
    fn samples_do_not_decrease() {
        let mut clock = TransportClock::new().unwrap();
        let mut previous = clock.sample().unwrap();
        for _ in 0..1_000 {
            let sample = clock.sample().unwrap();
            assert!(sample.ticks >= previous.ticks, "{previous:?} {sample:?}");
            previous = sample;
        }
    }

    #[test]
    fn ticks_track_the_boottime_clock() {
        let mut clock = TransportClock::new().unwrap();
        let before = read(Clock::Boottime) / NANOS_PER_MICROSECOND;
        let ticks = clock.sample().unwrap().ticks;
        let after = read(Clock::Boottime) / NANOS_PER_MICROSECOND;
        assert!((before..=after).contains(&i128::from(ticks)));
    }

    #[test]
    fn boottime_is_at_least_monotonic() {
        let monotonic = read(Clock::Monotonic);
        assert!(read(Clock::Boottime) >= monotonic);
    }

    #[test]
    fn boot_id_is_the_kernel_text() {
        let clock = TransportClock::new().unwrap();
        let text = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
        assert_eq!(
            clock.characterization().boot_id.to_string(),
            text.trim_end()
        );
        // A second reader within the same boot finds the same id.
        assert_eq!(
            TransportClock::new().unwrap().characterization().boot_id,
            clock.characterization().boot_id
        );
    }

    #[test]
    fn boot_age_is_positive() {
        let mut clock = TransportClock::new().unwrap();
        let ticks = clock.sample().unwrap().ticks;
        eprintln!(
            "observed: {:?}, boot age {} us",
            clock.characterization(),
            clock.boot_age(ticks).unwrap()
        );
        assert!(clock.boot_age(ticks).unwrap() > 0);
    }

    const NAMESPACED: &str = "NTCP_CLOCK_TIME_NAMESPACE_CHILD";

    // The provider inside a time namespace: its offsets, ticks and boot age.
    fn report() {
        let mut clock = TransportClock::new().unwrap();
        let ticks = clock.sample().unwrap().ticks;
        let offsets = clock.characterization().offsets;
        println!(
            "NAMESPACED {} {} {ticks} {}",
            offsets.monotonic_ns,
            offsets.boottime_ns,
            clock.boot_age(ticks).unwrap()
        );
    }

    /// A real time namespace (`unshare --time`, a user namespace for the
    /// privilege) whose boottime offset presents a host booted a day earlier:
    /// the provider inside reads the offset and reports the host's own boot
    /// age, bracketed by readings outside. The host's clock is not touched.
    /// Without namespace support this fails, it never skips.
    #[test]
    fn a_time_namespace_offset_leaves_the_host_boot_age() {
        if std::env::var_os(NAMESPACED).is_some() {
            return report();
        }
        let name =
            "transport::tests::host_observations::a_time_namespace_offset_leaves_the_host_boot_age";
        let offset_s: i64 = 86_400;
        let before = read(Clock::Boottime) / NANOS_PER_MICROSECOND;
        let output = std::process::Command::new("unshare")
            .args(["--user", "--map-root-user", "--time", "--boottime"])
            .arg(offset_s.to_string())
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env(NAMESPACED, "1")
            .output()
            .expect("unshare must run: a missing namespace capability is a failure");
        let after = read(Clock::Boottime) / NANOS_PER_MICROSECOND;
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "time namespace child failed: {stdout} {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report = stdout
            .lines()
            .find_map(|line| line.split_once("NAMESPACED ").map(|(_, report)| report))
            .unwrap_or_else(|| panic!("no report from the namespace: {stdout}"));
        let fields: Vec<i128> = report
            .split(' ')
            .take(4)
            .map(|f| f.parse().unwrap())
            .collect();
        let (monotonic_ns, boottime_ns, ticks, age) = (fields[0], fields[1], fields[2], fields[3]);
        eprintln!(
            "observed in a time namespace: offset {offset_s} s, boot id {}, ticks {ticks} us, \
             boot age {age} us, host {before}..{after} us",
            TransportClock::new().unwrap().characterization().boot_id
        );
        let offset_us = i128::from(offset_s) * 1_000_000;
        assert_eq!((monotonic_ns, boottime_ns), (0, offset_us * 1_000));
        // The namespace's clock carries the offset; the boot age does not.
        assert!((before + offset_us..=after + offset_us).contains(&ticks));
        assert!(
            (before..=after).contains(&age),
            "boot age {age} outside {before}..{after}"
        );
    }
}
