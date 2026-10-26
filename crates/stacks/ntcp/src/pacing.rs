use crate::Instant;

const FRACTION: u128 = 1 << 32;
const SQUARED: u128 = FRACTION * FRACTION;

// Byte debt with 32 fractional bits; interval is ticks/byte with 32 bits.
// This is a bounded leaky bucket, equivalent to a virtual departure clock.
// No negative debt: idle/lateness can recover only the configured burst.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Pacer {
    debt: u128,
    at: Instant,
    interval: u128,
}

impl Pacer {
    pub(crate) fn interval(rtt: u64, cwnd: u32, gain: u16, cap: Option<u64>, units: u64) -> u128 {
        let interval = (rtt as u128 * 100 * FRACTION).div_ceil(cwnd.max(1) as u128 * gain as u128);
        interval.max(cap.map_or(1, |cap| (units as u128 * FRACTION).div_ceil(cap as u128)))
    }

    fn debt_at(self, now: Instant) -> u128 {
        let drained = (now.saturating_sub(self.at) as u128 * SQUARED) / self.interval.max(1);
        self.debt.saturating_sub(drained)
    }

    // Reserve a full effective MSS before selecting data. Short output charges
    // only its actual bytes, but cannot use the final fractional-MSS headroom.
    pub(crate) fn deadline(self, now: Instant, burst: u32, mss: usize) -> Option<Instant> {
        let excess = self
            .debt_at(now)
            .saturating_sub((burst as u128 - mss as u128) * FRACTION);
        (excess != 0).then(|| {
            let ticks = excess.saturating_mul(self.interval).div_ceil(SQUARED);
            now.saturating_add(ticks.min(u64::MAX as u128) as u64)
        })
    }

    // The one-time startup exemption consumes initial-window credit instead
    // of accumulating a whole flight of rate debt. Keep the ordinary bucket
    // charged, so crossing the startup boundary cannot grant another burst.
    pub(crate) fn startup_sent(&mut self, now: Instant, bytes: usize, interval: u128, burst: u32) {
        self.sent(now, bytes, interval);
        self.debt = self.debt.min(u128::from(burst) * FRACTION);
    }

    pub(crate) fn sent(&mut self, now: Instant, bytes: usize, interval: u128) {
        self.debt = self.debt_at(now).saturating_add(bytes as u128 * FRACTION);
        self.at = now;
        // Sample rate on successful output, without resetting outstanding debt.
        self.interval = interval;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_exemption_leaves_only_normal_bucket_debt_without_extra_credit() {
        let mut p = Pacer::default();
        let interval = Pacer::interval(100000, 10000, 125, None, 1000000);
        for _ in 0..10 {
            p.startup_sent(0, 1000, interval, 2000);
        }
        assert_eq!(p.deadline(0, 2000, 1000), Some(8000));
        assert_eq!(p.deadline(7999, 2000, 1000), Some(8000));
        assert_eq!(p.deadline(8000, 2000, 1000), None);
        p.sent(8000, 1000, interval);
        assert_eq!(p.deadline(8000, 2000, 1000), Some(16000));
    }

    #[test]
    fn general_pacing_fractional_rate_debt_and_saturation() {
        // Half-tick packets: no per-packet ceil to one tick, but at most two
        // packets at any one caller instant, even after arbitrarily late polls.
        let mut p = Pacer::default();
        let interval = Pacer::interval(1, 2, 100, None, 1_000_000);
        assert_eq!(interval, FRACTION / 2);
        for now in [0, 1, 2, 1_000_000] {
            assert_eq!(p.deadline(now, 2, 1), None);
            p.sent(now, 1, interval);
            assert_eq!(p.deadline(now, 2, 1), None);
            p.sent(now, 1, interval);
            assert_eq!(p.deadline(now, 2, 1), Some(now + 1));
        }
        // A changed rate changes drainage, not accumulated byte debt.
        let debt = p.debt;
        p.sent(p.at, 1, 10 * FRACTION); // protocol probe bypass
        assert_eq!(p.debt, debt + FRACTION);
        assert_eq!(p.deadline(p.at, 2, 1), Some(p.at + 20));
        p.sent(p.at, 1, FRACTION);
        assert_eq!(p.debt, debt + 2 * FRACTION);
        assert_eq!(p.deadline(p.at, 2, 1), Some(p.at + 3));

        // Gain and bytes/second cap use caller units; widened inputs saturate
        // deadlines without wrap, including non-advancing Instant::MAX.
        assert_eq!(
            Pacer::interval(100, 100, 125, None, 1_000_000),
            (4 * FRACTION).div_ceil(5)
        );
        for units in [1_000_000, 1_000_000_000] {
            assert_eq!(
                Pacer::interval(1, u32::MAX, u16::MAX, Some(1), units),
                units as u128 * FRACTION
            );
        }
        let slow = Pacer::interval(u64::MAX, 1, 1, Some(1), 1_000_000_000);
        p.sent(u64::MAX, u32::MAX as usize, slow);
        assert_eq!(p.deadline(u64::MAX, 2, 1), Some(u64::MAX));
        assert_eq!(p.deadline(u64::MAX, 2, 1), Some(u64::MAX));
        assert!(Pacer::interval(1, u32::MAX, u16::MAX, Some(u64::MAX), 1_000_000) >= 1);
    }
}
