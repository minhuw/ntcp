use super::*;
use ntcp_clock::TransportSample;

const PEER: &str = "10.73.0.3:8080";
const HALF_RANGE_US: u64 = (1 << 31) * 1_000;

// Timestamps make the half-range an ambiguity at all.
fn timestamped_owner() -> Owner {
    let mut config = SocketConfig::new("test", Ipv4Addr::new(10, 73, 0, 2)).tcp;
    config.connection.timestamps = true;
    owner_with_config(2, config)
}

fn boottime_us() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) },
        0
    );
    time.tv_sec as u64 * 1_000_000 + time.tv_nsec as u64 / 1_000
}

/// Observation of this host: without the fixtures' origin, the owner's
/// samples are the provider's ticks, CLOCK_BOOTTIME in microseconds.
#[test]
fn transport_ticks_are_boottime_microseconds() {
    let mut a = owner(2);
    a.test_origin = 0;
    let before = boottime_us();
    let ticks = a.clock().unwrap();
    assert!((before..=boottime_us()).contains(&ticks));
}

#[test]
fn time_dependent_operations_fail_with_eio_when_the_clock_fails() {
    let mut a = owner(2);
    let fd = new(&mut a, SOCK_NONBLOCK);
    a.test_clock_failure = true;
    assert_eq!(a.clock(), Err(EIO));
    assert_eq!(
        a.execute(fd, Op::Connect(PEER.parse().unwrap())).err(),
        Some(EIO)
    );
    assert!(!a.endpoint.has_pending_output());
    // Time returns with the provider: nothing kept a stale value.
    a.test_clock_failure = false;
    a.test_now = Some(5_000);
    assert_eq!(a.clock(), Ok(5_000));
}

#[test]
fn the_owner_loop_ends_with_eio_when_the_clock_fails() {
    let runtime = Runtime::spawn(
        || {
            let mut a = owner(2);
            a.test_clock_failure = true;
            Ok(a)
        },
        false,
    )
    .unwrap();
    // The owner stopped at its first turn, it did not freeze.
    for _ in 0..2 {
        assert_eq!(runtime.call(0, Op::New(SOCK_NONBLOCK)).err(), Some(EIO));
    }
}

// Logic only: the sample is constructed, not a physical suspend.
#[test]
fn a_measured_suspend_reaches_the_endpoint_with_its_sample() {
    let mut a = timestamped_owner();
    let start = a.clock().unwrap();
    a.test_now = Some(start);
    a.endpoint.on_timeout(start, BUDGET).unwrap();
    let ticks = start + HALF_RANGE_US;
    assert_eq!(
        a.accept_sample(TransportSample {
            ticks,
            suspended: HALF_RANGE_US,
        }),
        Ok(ticks)
    );
    // The jump is accepted, so the owner's next turn is not wedged.
    a.endpoint.on_timeout(ticks, BUDGET).unwrap();
}

#[test]
fn a_rejected_sample_is_eio_and_leaves_no_time_behind() {
    let mut a = timestamped_owner();
    let start = a.clock().unwrap();
    a.test_now = Some(start);
    a.endpoint.on_timeout(start, BUDGET).unwrap();
    assert_eq!(
        a.accept_sample(TransportSample {
            ticks: start + 2 * HALF_RANGE_US,
            suspended: 1,
        }),
        Err(EIO)
    );
    a.endpoint.on_timeout(start, BUDGET).unwrap();
}
