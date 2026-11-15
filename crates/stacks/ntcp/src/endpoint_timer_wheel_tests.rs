use super::*;
use crate::{KeepaliveConfig, TimerWheel};

// A custom wheel reaching (64 - 1) << 3·8 µs, about 1057 s: beyond the
// default user timeout (300 s), the TIME-WAIT (120 s) and the handshake's
// 180 s, short of Linux's longest TCP_USER_TIMEOUT.
const SHORT: TimerWheel = TimerWheel::Custom {
    tick_ns: 1_000,
    slots: 64,
    levels: 9,
};

#[test]
fn both_presets_reach_every_default_timer() {
    for wheel in [TimerWheel::Datacenter, TimerWheel::Internet] {
        for units_per_second in [1_000_000, 1_000_000_000] {
            let mut cfg = config();
            cfg.timer_wheel = wheel;
            cfg.connection.timebase.units_per_second = units_per_second;
            // Linux's longest settings: TCP_USER_TIMEOUT INT_MAX ms,
            // TCP_KEEPIDLE 32767 s.
            cfg.connection.user_timeout_us = i32::MAX as u64 * 1_000;
            cfg.connection.keepalive = Some(KeepaliveConfig {
                idle_us: 32_767_000_000,
                ..KeepaliveConfig::default()
            });
            assert!(
                Endpoint::new(cfg, [1; 32], 0, test_policy).is_ok(),
                "{wheel:?}"
            );
        }
    }
    assert_eq!(EndpointConfig::default().timer_wheel, TimerWheel::Internet);
}

// An endpoint whose wheel cannot reach a timer its configuration allows is
// refused at creation, loudly, rather than keeping that timer late.
#[test]
fn a_wheel_short_of_a_configured_timer_refuses_the_endpoint() {
    let refused = |change: &dyn Fn(&mut EndpointConfig)| {
        let mut cfg = config();
        cfg.timer_wheel = SHORT;
        change(&mut cfg);
        Endpoint::new(cfg, [1; 32], 0, test_policy).err()
    };
    assert_eq!(refused(&|_| {}), None);
    let invalid = Some(EndpointError::Connection(Error::InvalidArgument));
    assert_eq!(
        refused(&|c| c.connection.user_timeout_us = 1_100_000_000),
        invalid
    );
    assert_eq!(
        refused(&|c| c.connection.time_wait_us = 1_100_000_000),
        invalid
    );
    assert_eq!(
        refused(&|c| c.connection.keepalive = Some(KeepaliveConfig::default())),
        invalid
    );
    // Below the 60 s retransmission backoff and the 180 s handshake.
    for levels in [6, 7] {
        assert_eq!(
            refused(&|c| c.timer_wheel = TimerWheel::Custom {
                tick_ns: 1_000,
                slots: 64,
                levels,
            }),
            invalid
        );
    }
    assert_eq!(
        refused(&|c| c.timer_wheel = TimerWheel::Custom {
            tick_ns: 1_000,
            slots: 48,
            levels: 9,
        }),
        invalid
    );
}

// A timer set on a connection or listener beyond the wheel's reach is
// refused, and the connection keeps what it had.
#[test]
fn a_timer_set_beyond_the_wheel_is_refused() {
    let mut cfg = config();
    cfg.timer_wheel = SHORT;
    let reach = cfg.timer_wheel_geometry().unwrap().coverage;
    assert_eq!(reach, 63 << 24);
    let (local, remote) = addresses();
    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let id = a.connect(0, local, remote).unwrap();
    pump(&mut a, &mut b, 0);
    let invalid = Err(EndpointError::Connection(Error::InvalidArgument));
    assert_eq!(a.timer_wheel().coverage, reach);
    assert_eq!(a.set_user_timeout(id, reach + 1), invalid);
    assert_eq!(a.set_user_timeout(id, reach), Ok(()));
    assert_eq!(a.set_application_timeout(id, Some(reach + 1)), invalid);
    assert_eq!(a.application_timeout(id), Ok(None));
    assert_eq!(a.set_application_timeout(id, Some(reach)), Ok(()));
    let keepalive = KeepaliveConfig {
        idle_us: reach + 1,
        ..KeepaliveConfig::default()
    };
    assert_eq!(a.set_keepalive(id, Some(keepalive)), invalid);
    let keepalive = KeepaliveConfig {
        idle_us: reach,
        interval_us: reach + 1,
        ..KeepaliveConfig::default()
    };
    assert_eq!(a.set_keepalive(id, Some(keepalive)), invalid);
    assert_eq!(
        b.set_listener_application_timeout(listener, Some(reach + 1)),
        invalid
    );
    assert_eq!(
        b.set_listener_application_timeout(listener, Some(reach)),
        Ok(())
    );
}

// PLPMTUD search aging beyond the wheel is refused as well, and the
// read-only check says so first.
#[test]
fn search_aging_beyond_the_wheel_is_refused() {
    let mut cfg = config();
    cfg.timer_wheel = SHORT;
    cfg.connection.pmtud = Some(crate::PmtudConfig::new(1500));
    let reach_s = cfg.timer_wheel_geometry().unwrap().coverage / 1_000_000;
    let (local, remote) = addresses();
    let mut a = Endpoint::new(cfg, [1; 32], 0, test_policy).unwrap();
    let id = a.connect(0, local, remote).unwrap();
    let invalid = Err(EndpointError::Connection(Error::InvalidArgument));
    let far = crate::SearchAging::Seconds(reach_s + 1);
    assert_eq!(a.validate_search_aging(0, id, far), invalid);
    assert_eq!(a.set_search_aging(0, id, far), invalid);
    let near = crate::SearchAging::Seconds(reach_s);
    assert_eq!(a.validate_search_aging(0, id, near), Ok(()));
    assert_eq!(a.set_search_aging(0, id, near), Ok(()));
    assert_eq!(
        a.set_search_aging(0, id, crate::SearchAging::Infinity),
        Ok(())
    );
}
