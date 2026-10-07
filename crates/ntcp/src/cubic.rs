//! Private CUBIC arithmetic/state (RFC 9438 sections 4.2-4.8, 5.8).
//! Recovery, ECN epochs and PRR remain owned by Congestion/Connection.
//! Source: https://www.rfc-editor.org/rfc/rfc9438 (published text).

use core::cmp::Ordering;

use crate::{connection::CallerTimebase, seq::Seq};

const WINDOW_SCALE: u128 = 1 << 32;
const TIME_SCALE: u128 = 1 << 31;
const MAX_WINDOW: u32 = 0x7fff_ffff;

#[derive(Clone, Debug)]
pub(crate) struct Cubic {
    // Windows are bytes; estimates and fractional growth use Q32 bytes.
    w_max: u32,
    cwnd_prior: u32,
    w_est: u128,
    fraction: u128,
    k: i64, // signed Q31 seconds (fast convergence can put W_max below cwnd_epoch)
    epoch: bool,
    elapsed: u64, // caller ticks, excluding application-limited intervals
    last_clock: Option<u64>,
    active: bool,
    // Successful output that filled cwnd validates ACKs for that flight, even
    // as the flight drains (including caller-validated sender SWS slack).
    // Neither queued data alone nor failed output validates it.
    limited_end: Option<Seq>,
    acked: u32,
    rtt: u64,
    timebase: CallerTimebase,
}

impl Cubic {
    pub(crate) fn new(timebase: CallerTimebase) -> Self {
        Self {
            w_max: 0,
            cwnd_prior: 0,
            w_est: 0,
            fraction: 0,
            k: 0,
            epoch: false,
            elapsed: 0,
            last_clock: None,
            active: false,
            limited_end: None,
            acked: 0,
            rtt: 0,
            timebase,
        }
    }

    fn clock(&mut self, now: u64) {
        if let Some(last) = self.last_clock
            && self.active
            && self.epoch
        {
            self.elapsed = self.elapsed.saturating_add(now.saturating_sub(last));
        }
        self.last_clock = Some(now);
    }

    pub(crate) fn sent(
        &mut self,
        now: u64,
        flight: u32,
        cwnd: u32,
        end: Seq,
        recovery: bool,
        cwnd_limited: bool,
    ) {
        self.clock(now);
        if !recovery && (flight >= cwnd || cwnd_limited) && cwnd != 0 {
            self.limited_end = Some(end);
            self.active = true;
        }
    }

    pub(crate) fn prepare_ack(
        &mut self,
        now: u64,
        rtt: Option<u64>,
        ack: Seq,
        acked: u32,
        growth_allowed: bool,
    ) {
        self.clock(now);
        self.rtt = rtt.unwrap_or(0);
        let start = ack.wrapping_add(0u32.wrapping_sub(acked));
        self.acked = self.limited_end.map_or(0, |end| {
            if end.serial_cmp(start) == Some(Ordering::Greater) {
                acked.min(end.distance_from(start))
            } else {
                0
            }
        });
        if self.limited_end.is_some_and(|end| {
            matches!(
                ack.serial_cmp(end),
                Some(Ordering::Equal | Ordering::Greater)
            )
        }) {
            self.limited_end = None;
            self.active = false;
        }
        if !growth_allowed {
            // Receiver-limited periods must not inflate cwnd or age the curve.
            self.pause();
        }
    }

    fn pause(&mut self) {
        self.limited_end = None;
        self.active = false;
        self.acked = 0;
    }

    pub(crate) fn receiver_limited(&mut self, now: u64) {
        self.clock(now);
        self.pause();
    }

    pub(crate) fn can_grow(&self) -> bool {
        self.acked != 0
    }

    fn reset_epoch(&mut self) {
        self.epoch = false;
        self.elapsed = 0;
        self.fraction = 0;
    }

    pub(crate) fn congestion(&mut self, cwnd: u32) {
        // RFC 9438 section 4.7: fast convergence, beta=0.7.
        self.w_max = if cwnd < self.w_max {
            (u64::from(cwnd) * 17 / 20) as u32
        } else {
            cwnd
        };
        // Keep the published cwnd_prior definition; rejected erratum 7806
        // does not replace it with FlightSize.
        self.cwnd_prior = cwnd;
        self.reset_epoch();
        self.pause();
    }

    pub(crate) fn timeout(&mut self) {
        // Section 4.8: first CA epoch after RTO uses K=0, W_max=cwnd_epoch.
        self.w_max = 0;
        self.reset_epoch();
        self.pause();
    }

    pub(crate) fn mss_changed(&mut self, old: u32, new: u32) {
        if new < old {
            self.w_max = (u64::from(self.w_max) * u64::from(new) / u64::from(old)) as u32;
            self.cwnd_prior = (u64::from(self.cwnd_prior) * u64::from(new) / u64::from(old)) as u32;
        }
        // Recompute K with the new segment unit on the next eligible CA ACK.
        self.reset_epoch();
        self.pause();
    }

    pub(crate) fn restart(&mut self) {
        self.reset_epoch();
        self.pause();
    }

    fn seconds(&self, ticks: u64) -> u64 {
        (u128::from(ticks) * TIME_SCALE / u128::from(self.timebase.units_per_second))
            .min(u128::from(u64::MAX)) as u64
    }

    fn start_epoch(&mut self, cwnd: u32, mss: u32) {
        if self.w_max == 0 {
            self.w_max = cwnd;
            self.k = 0;
        } else {
            let cube = u128::from(self.w_max.abs_diff(cwnd)) * 5 * TIME_SCALE.pow(3)
                / (2 * u128::from(mss));
            let root = cube_root(cube) as i64;
            self.k = if self.w_max < cwnd { -root } else { root };
        }
        self.w_est = u128::from(cwnd) * WINDOW_SCALE;
        self.fraction = 0;
        self.elapsed = 0;
        self.epoch = true;
    }

    // C=0.4 segments/s^3. Saturation is only relevant far beyond the TCP
    // byte-window cap; all numerators below that cap fit exactly in u128.
    fn window(&self, time: u64, mss: u32) -> u128 {
        let delta = i128::from(time) - i128::from(self.k);
        let magnitude = delta
            .unsigned_abs()
            .saturating_pow(3)
            .saturating_mul(2 * u128::from(mss))
            / (5 * (TIME_SCALE.pow(3) / WINDOW_SCALE));
        let origin = u128::from(self.w_max) * WINDOW_SCALE;
        if delta < 0 {
            origin.saturating_sub(magnitude)
        } else {
            origin
                .saturating_add(magnitude)
                .min(u128::from(MAX_WINDOW) * WINDOW_SCALE)
        }
    }

    pub(crate) fn grow(&mut self, cwnd: u32, mss: u32) -> u32 {
        if !self.can_grow() || cwnd == 0 {
            return cwnd;
        }
        if !self.epoch {
            self.start_epoch(cwnd, mss);
        }
        let current = u128::from(cwnd) * WINDOW_SCALE;
        // RFC 9438 section 4.3, Figure 4: alpha=9/17, then 1 after
        // W_est reaches cwnd_prior. Unlike the cubic branch, byte-counted.
        let (alpha, denominator) = if self.w_est >= u128::from(self.cwnd_prior) * WINDOW_SCALE {
            (1, 1)
        } else {
            (9, 17)
        };
        self.w_est = self
            .w_est
            .saturating_add(
                u128::from(self.acked) * u128::from(mss) * WINDOW_SCALE * alpha
                    / (u128::from(cwnd) * denominator),
            )
            .min(u128::from(MAX_WINDOW) * WINDOW_SCALE);
        let time = self.seconds(self.elapsed);
        if self.window(time, mss) < self.w_est {
            let next = self.w_est.max(current);
            self.fraction = 0;
            return (next / WINDOW_SCALE).min(u128::from(MAX_WINDOW)) as u32;
        }
        let target = self
            .window(time.saturating_add(self.seconds(self.rtt)), mss)
            .clamp(current, current * 3 / 2);
        // Published RFC 9438 sections 4.4/4.5 specify one increment per new
        // ACK, not per segment acknowledged. Reported erratum 9186 is not
        // normative (https://www.rfc-editor.org/eid9186/) and is NOT applied.
        // W_est above still uses
        // segments_acked. Sub-MSS ACKs also use this published per-ACK rule.
        self.fraction += (target - current) * u128::from(mss) / u128::from(cwnd);
        let increase = self.fraction / WINDOW_SCALE;
        self.fraction %= WINDOW_SCALE;
        (u128::from(cwnd) + increase).min(u128::from(MAX_WINDOW)) as u32
    }
}

fn cube_root(value: u128) -> u64 {
    let (mut low, mut high) = (0u128, 1u128 << 43);
    while low + 1 < high {
        let mid = (low + high) / 2;
        if mid <= value / mid / mid {
            low = mid;
        } else {
            high = mid;
        }
    }
    low as u64
}

#[cfg(test)]
mod tests;
