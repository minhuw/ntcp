use ntcp_io::{ClockDescriptor, ClockDomain, TimestampUnit, TransmitTime, TxSchedulingError};
use std::io;

// Linux include/uapi/linux/errqueue.h; not yet exported by libc.
const SO_EE_ORIGIN_TXTIME: u8 = 6;

pub(crate) const CLOCK: ClockDescriptor = ClockDescriptor {
    domain: ClockDomain::Monotonic,
    unit: TimestampUnit::Nanoseconds,
};

#[derive(Clone, Copy, Debug)]
pub struct TxSchedulingConfig {
    // Attests that caller installed fq on this interface, keeps it installed,
    // and configured horizon >= max_future_ns with horizon_drop (not cap),
    // offload_horizon=0 (no early dequeue to a presumed hardware scheduler).
    // setsockopt alone cannot guarantee pacing. No qdisc/NIC mutation here.
    pub caller_owned_fq: bool,
    pub max_future_ns: u64,
}

impl TxSchedulingConfig {
    pub(crate) fn validate(self, when: TransmitTime, now: u64) -> io::Result<()> {
        if when.clock != CLOCK
            || when.value > i64::MAX as u64
            || when
                .value
                .checked_sub(now)
                .is_none_or(|delta| delta > self.max_future_ns)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TX time clock or horizon invalid",
            ));
        }
        Ok(())
    }
}

pub(crate) fn now() -> io::Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: writable timespec and supported explicit clock.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64)
}

pub(crate) fn error(error: libc::sock_extended_err) -> Option<TxSchedulingError> {
    (error.ee_origin == SO_EE_ORIGIN_TXTIME).then_some(TxSchedulingError {
        when: TransmitTime {
            value: (u64::from(error.ee_data) << 32) | u64::from(error.ee_info),
            clock: CLOCK,
        },
        errno: error.ee_errno,
        code: error.ee_code,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clock_horizon_and_native_error() {
        let config = TxSchedulingConfig {
            caller_owned_fq: true,
            max_future_ns: 100,
        };
        let mut when = TransmitTime {
            value: 200,
            clock: CLOCK,
        };
        assert!(config.validate(when, 100).is_ok());
        for now in [99, 201] {
            assert!(config.validate(when, now).is_err());
        }
        when.clock.domain = ClockDomain::Realtime;
        assert!(config.validate(when, 100).is_err());
        when.clock = ClockDescriptor {
            domain: ClockDomain::Monotonic,
            unit: TimestampUnit::RawTicks { identity: 1 },
        };
        assert!(config.validate(when, 100).is_err());
        let mut native: libc::sock_extended_err = unsafe { std::mem::zeroed() };
        native.ee_origin = SO_EE_ORIGIN_TXTIME;
        native.ee_data = 7;
        native.ee_info = 9;
        native.ee_code = 2;
        native.ee_errno = libc::ECANCELED as u32;
        let parsed = error(native).unwrap();
        assert_eq!(parsed.when.value, (7u64 << 32) | 9);
        assert_eq!(parsed.code, 2);
        assert_eq!(parsed.errno, libc::ECANCELED as u32);
        native.ee_origin = libc::SO_EE_ORIGIN_TIMESTAMPING;
        assert!(error(native).is_none());
    }
}
