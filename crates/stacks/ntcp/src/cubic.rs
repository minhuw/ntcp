//! Private CUBIC arithmetic/state (RFC 9438 sections 4.2-4.8, 5.8).
//! Recovery, ECN epochs and PRR remain owned by Congestion/Connection.
//! Source: https://www.rfc-editor.org/rfc/rfc9438 (published text).

use core::cmp::Ordering;

use crate::{connection::CallerTimebase, seq::Seq};

const WINDOW_SCALE: u128 = 1 << 32;
const TIME_SCALE: u128 = 1 << 31;
const MAX_WINDOW: u32 = 0x7fff_ffff;

#[derive(Clone, Debug)]
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.1
//= reason=State is byte-scaled Q32; per-ACK segment arithmetic factors SMSS, caller ticks convert to seconds.
//# The unit of all window sizes in this document is segments of the
//# SMSS, and the unit of all times is seconds.  Implementations can use
//# bytes to express window sizes, which would require factoring in the
//# SMSS wherever necessary and replacing _segments_acked_ (Figure 4)
//# with the number of acknowledged bytes.
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
//= reason=State is byte-scaled Q32; per-ACK segment arithmetic factors SMSS, caller ticks convert to seconds.
//# *  _cwnd_: Current congestion window in segments.
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
//= reason=State is byte-scaled Q32; per-ACK segment arithmetic factors SMSS, caller ticks convert to seconds.
//# *  _W_est_: An estimate for the congestion window in segments in the
//# Reno-friendly region -- that is, an estimate for the congestion
//# window of Reno.
pub(crate) struct Cubic {
    // Windows are bytes; estimates and fractional growth use Q32 bytes.
    w_max: u32,
    pub(crate) fast_convergence: bool,
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
            fast_convergence: true,
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

    //= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
    //= reason=Caller clock accumulates only active CA intervals; idle/application-limited intervals are excluded.
    //# *  _t_current_: Current time of the system in seconds.
    fn clock(&mut self, now: u64) {
        if let Some(last) = self.last_clock
            && self.active
            && self.epoch
        {
            self.elapsed = self.elapsed.saturating_add(now.saturating_sub(last));
        }
        self.last_clock = Some(now);
    }

    //= https://www.rfc-editor.org/rfc/rfc9438#section-5.8
    //= reason=Committed underfilled output or ACK-drained flight pauses curve time while historical full-flight ACK credit survives; receiver limitation revokes credit through prepare_ack/receiver_limited.
    //# A flow is application limited if it is currently sending less than
    //# what is allowed by the congestion window.  This can happen if the
    //# flow is limited by either the sender application or the receiver
    //# application (via the receiver's advertised window) and thus sends
    //# less data than what is allowed by the sender's congestion window.
    //= https://www.rfc-editor.org/rfc/rfc9438#section-5.8
    //= reason=Committed underfilled output or ACK-drained flight pauses curve time while historical full-flight ACK credit survives; receiver limitation revokes credit through prepare_ack/receiver_limited.
    //# CUBIC does not increase its congestion window if a flow is
    //# application limited.  Per Section 4.2, it is required that _t_ in
    //# Figure 1 not include application-limited periods, such as idle
    //# periods; otherwise, W_cubic(_t_) might be very high after restarting
    //# from these periods.
    //= https://www.rfc-editor.org/rfc/rfc9438#section-4.6
    //= reason=Committed underfilled output or ACK-drained flight pauses curve time while historical full-flight ACK credit survives; receiver limitation revokes credit through prepare_ack/receiver_limited.
    //# Implementations
    //# that use _cwnd_ MUST use other measures to prevent _cwnd_ from
    //# growing when the volume of bytes in flight is smaller than
    //# _cwnd_.
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
        self.active = !recovery && (flight >= cwnd || cwnd_limited) && cwnd != 0;
        if self.active {
            self.limited_end = Some(end);
        }
        // A short application suffix stops the curve clock, but does not
        // discard historical full-flight ACK eligibility.
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

    //= https://www.rfc-editor.org/rfc/rfc9438#section-4.2
    //= reason=Post-growth ACK flight below current cwnd freezes clock immediately, without discarding historical committed-flight ACK eligibility. Committed full-window refill reactivates it; receiver limitation independently revokes growth credit.
    //# The elapsed time _t_ in Figure 1 MUST NOT include periods during
    //# which _cwnd_ has not been updated due to application-limited behavior
    //# (see Section 5.8).
    pub(crate) fn ack_flight(&mut self, flight: u32, cwnd: u32) {
        // Current underfill pauses time, not historical full-flight ACK credit.
        self.active &= cwnd != 0 && flight >= cwnd;
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

    pub(crate) fn slow_start_acked(&self) -> u32 {
        self.acked
    }

    pub(crate) fn timebase(&self) -> CallerTimebase {
        self.timebase
    }

    //= https://www.rfc-editor.org/rfc/rfc9438#section-4.10
    //= reason=Lossless exit saves cwnd_prior=W_max=current cwnd, K=0 and W_est=cwnd_epoch; epoch starts at exiting ACK.
    //# When CUBIC uses HyStart++ [RFC9406], it may exit the first slow start
    //# without incurring any packet loss and thus _W_max_ is undefined.  In
    //# this special case, CUBIC sets _cwnd_prior = cwnd_ and switches to
    //# congestion avoidance.  It then increases its congestion window size
    //# using Figure 1, where _t_ is the elapsed time since the beginning of
    //# the current congestion avoidance stage, _K_ is set to 0, and _W_max_
    //# is set to the congestion window size at the beginning of the current
    //# congestion avoidance stage.
    pub(crate) fn startup_exit(&mut self, cwnd: u32, mss: u32) {
        // RFC 9438 section 4.10: no loss, no fast convergence.
        self.cwnd_prior = cwnd;
        self.w_max = cwnd;
        self.start_epoch(cwnd, mss);
    }

    fn reset_epoch(&mut self) {
        self.epoch = false;
        self.elapsed = 0;
        self.fraction = 0;
    }

    //= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
    //= reason=Save actual pre-reduction cwnd; enabled fast convergence applies 17/20 only below old W_max, before beta reduction. Rejected erratum7806 is not applied.
    //# *  _cwnd_prior_: Size of _cwnd_ in segments at the time of setting
    //# _ssthresh_ most recently, either upon exiting the first slow start
    //# or just before _cwnd_ was reduced in the last congestion event.
    //= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
    //= reason=Save actual pre-reduction cwnd; enabled fast convergence applies 17/20 only below old W_max, before beta reduction. Rejected erratum7806 is not applied.
    //# *  _W_max_: Size of _cwnd_ in segments just before _cwnd_ was reduced
    //# in the last congestion event when fast convergence is disabled
    //# (same as _cwnd_prior_ on a congestion event).  However, if fast
    //# convergence is enabled, _W_max_ may be further reduced based on
    //# the current saturation point.
    //= https://www.rfc-editor.org/rfc/rfc9438#section-4.7
    //= reason=Save actual pre-reduction cwnd; enabled fast convergence applies 17/20 only below old W_max, before beta reduction. Rejected erratum7806 is not applied.
    //# With fast convergence, when a congestion event occurs, _W_max_ is
    //# updated as follows, before the window reduction described in
    //# Section 4.6.
    //#
    //# ⎧       1 + β
    //# ⎪            cubic
    //# ⎪cwnd * ────────── if  cwnd < W     and fast convergence enabled,
    //# W    = ⎨           2                  max
    //# max   ⎪                  further reduce  W
    //# ⎪                                   max
    //# ⎩cwnd             otherwise, remember cwnd before reduction
    //= https://www.rfc-editor.org/rfc/rfc9438#section-4.7
    //= reason=Save actual pre-reduction cwnd; enabled fast convergence applies 17/20 only below old W_max, before beta reduction. Rejected erratum7806 is not applied.
    //# To speed up this
    //# bandwidth release by existing flows, the following fast convergence
    //# mechanism SHOULD be implemented.
    pub(crate) fn congestion(&mut self, cwnd: u32) {
        // RFC 9438 section 4.7: fast convergence, beta=0.7.
        self.w_max = if self.fast_convergence && cwnd < self.w_max {
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

    //= https://www.rfc-editor.org/rfc/rfc9438#section-4.8
    //= reason=Reset origin sentinel forces next CA epoch W_max=cwnd_epoch and K=0; standard post-RTO SS is controller-owned.
    //# During the first congestion avoidance stage after a timeout, CUBIC
    //# increases its congestion window size using Figure 1, where _t_ is the
    //# elapsed time since the beginning of the current congestion avoidance
    //# stage, _K_ is set to 0, and _W_max_ is set to the congestion window
    //# size at the beginning of the current congestion avoidance stage.
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

    //= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
    //= reason=Start stores W_est=cwnd_epoch and zero elapsed time; signed cube root uses byte-scaled C=0.4, including W_max below epoch origin.
    //# *  _K_: The time period in seconds it takes to increase the
    //# congestion window size at the beginning of the current congestion
    //# avoidance stage to _W_max_.
    //= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
    //= reason=Start stores W_est=cwnd_epoch and zero elapsed time; signed cube root uses byte-scaled C=0.4, including W_max below epoch origin.
    //# *  _t_epoch_: The time in seconds at which the current congestion
    //# avoidance stage started.
    //= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
    //= reason=Start stores W_est=cwnd_epoch and zero elapsed time; signed cube root uses byte-scaled C=0.4, including W_max below epoch origin.
    //# *  _cwnd_epoch_: The _cwnd_ at the beginning of the current
    //# congestion avoidance stage, i.e., at time _t_epoch_.
    //= https://www.rfc-editor.org/rfc/rfc9438#section-4.8
    //= reason=Start stores W_est=cwnd_epoch and zero elapsed time; signed cube root uses byte-scaled C=0.4, including W_max below epoch origin.
    //# In
    //# addition, for the Reno-friendly region, _W_est_ SHOULD be set to the
    //# congestion window size at the beginning of the current congestion
    //# avoidance stage.
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
    //= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.1
    //= reason=Q31 seconds/Q32 bytes implement C=2/5 segments/s^3 and signed cubic offset; no low-C profile.
    //# *  _C_: Constant that determines the aggressiveness of CUBIC in
    //# competing with other congestion control algorithms in high-BDP
    //# networks.  Please see Section 5 for more explanation on how it is
    //# set.  The unit for _C_ is
    //#
    //# segment
    //# ───────
    //# 3
    //# second
    //= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
    //= reason=Q31 seconds/Q32 bytes implement C=2/5 segments/s^3 and signed cubic offset; no low-C profile.
    //# *  W_cubic(_t_): The congestion window in segments at time _t_ in
    //# seconds based on the cubic increase function, as described in
    //# Section 4.2.
    //= https://www.rfc-editor.org/rfc/rfc9438#section-4.2
    //= reason=Q31 seconds/Q32 bytes implement C=2/5 segments/s^3 and signed cubic offset; no low-C profile.
    //# CUBIC uses the following window increase function:
    //#
    //# 3
    //# W     (t) = C * (t - K)  + W
    //# cubic                      max
    //#
    //# Figure 1
    //#
    //# where _t_ is the elapsed time in seconds from the beginning of the
    //# current congestion avoidance stage -- that is,
    //#
    //# t = t        - t
    //# current    epoch
    //#
    //# and where _t_epoch_ is the time at which the current congestion
    //# avoidance stage starts.  _K_ is the time period that the above
    //# function takes to increase the congestion window size at the
    //# beginning of the current congestion avoidance stage to _W_max_ if
    //# there are no further congestion events.  _K_ is calculated using the
    //# following equation:
    //#
    //# ┌────────────────┐
    //# 3  │W    - cwnd
    //# ╲  │ max       epoch
    //# K =  ╲ │────────────────
    //# ╲│       C
    //#
    //# Figure 2
    //#
    //# where _cwnd_epoch_ is the congestion window at the beginning of the
    //# current congestion avoidance stage.
    //= https://www.rfc-editor.org/rfc/rfc9438#section-5.1
    //= reason=Q31 seconds/Q32 bytes implement C=2/5 segments/s^3 and signed cubic offset; no low-C profile.
    //# However, it is NOT
    //# RECOMMENDED to set _C_ to a very low value like 0.04, since CUBIC
    //# with a low _C_ cannot efficiently use the bandwidth in fast and long-
    //# distance networks.
    //= https://www.rfc-editor.org/rfc/rfc9438#section-5.1
    //= reason=Q31 seconds/Q32 bytes implement C=2/5 segments/s^3 and signed cubic offset; no low-C profile.
    //# Therefore, _C_ SHOULD be set to 0.4.
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
        //= https://www.rfc-editor.org/rfc/rfc9438#section-4.3
        //= reason=Beta=0.7 yields alpha=9/17; switches to one at W_est >= saved cwnd_prior.
        //# Thus, CUBIC uses Figure 4 to estimate the window size _W_est_ in the
        //# Reno-friendly region with
        //#
        //# 1 - β
        //# cubic
        //# α      = 3 * ──────────
        //# cubic       1 + β
        //# cubic
        //= https://www.rfc-editor.org/rfc/rfc9438#section-4.3
        //= reason=Beta=0.7 yields alpha=9/17; switches to one at W_est >= saved cwnd_prior.
        //# Once _W_est_ has grown to reach the _cwnd_ at the time of most
        //# recently setting _ssthresh_ -- that is, _W_est_ >= _cwnd_prior_ --
        //# the sender SHOULD set α__cubic_ to 1 to ensure that it can achieve
        //# the same congestion window increment rate as Reno, which uses AIMD(1,
        //# 0.5).
        let (alpha, denominator) = if self.w_est >= u128::from(self.cwnd_prior) * WINDOW_SCALE {
            (1, 1)
        } else {
            (9, 17)
        };
        //= https://www.rfc-editor.org/rfc/rfc9438#section-4.3
        //= reason=W_est begins at epoch cwnd; Figure4 is byte-counted with acknowledged bytes times SMSS divided by byte cwnd.
        //# _W_est_ is set equal to _cwnd_epoch_ at the start of the congestion
        //# avoidance stage.  After that, on every new ACK, _W_est_ is updated
        //# using Figure 4.  Note that this equation uses _segments_acked_ and
        //# _cwnd_ is measured in segments.  An implementation that measures
        //# _cwnd_ in bytes should adjust the equation accordingly using the
        //# number of acknowledged bytes and the SMSS.  Also note that this
        //# equation works for connections with enabled or disabled delayed ACKs
        //# [RFC5681], as _segments_acked_ will be different based on the
        //# segments actually acknowledged by a new ACK.
        //#
        //# segments_acked
        //# W    = W    + α      * ──────────────
        //# est    est    cubic        cwnd
        //#
        //# Figure 4
        //= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
        //= reason=W_est begins at epoch cwnd; Figure4 is byte-counted with acknowledged bytes times SMSS divided by byte cwnd.
        //# *  _segments_acked_: Number of SMSS-sized segments acked when a "new
        //# ACK" is received, i.e., an ACK that cumulatively acknowledges the
        //# delivery of previously unacknowledged data.  This number will be a
        //# decimal value when a new ACK acknowledges an amount of data that
        //# is not SMSS-sized.  Specifically, it can be less than 1 when a new
        //# ACK acknowledges a segment smaller than the SMSS.
        self.w_est = self
            .w_est
            .saturating_add(
                u128::from(self.acked) * u128::from(mss) * WINDOW_SCALE * alpha
                    / (u128::from(cwnd) * denominator),
            )
            .min(u128::from(MAX_WINDOW) * WINDOW_SCALE);
        let time = self.seconds(self.elapsed);
        //= https://www.rfc-editor.org/rfc/rfc9438#section-4.2
        //= reason=Compare the cubic curve to the independently updated Reno estimate; Reno-friendly ACK selects W_est without lowering cwnd.
        //# To summarize, CUBIC computes both W_cubic(_t_) and _W_est_ (see
        //# Section 4.3) on receiving a new ACK in congestion avoidance and
        //# chooses the larger of the two values.
        //= https://www.rfc-editor.org/rfc/rfc9438#section-4.3
        //= reason=Compare the cubic curve to the independently updated Reno estimate; Reno-friendly ACK selects W_est without lowering cwnd.
        //# If so, CUBIC is in the
        //# Reno-friendly region and _cwnd_ SHOULD be set to _W_est_ at each
        //# reception of a new ACK.
        if self.window(time, mss) < self.w_est {
            let next = self.w_est.max(current);
            self.fraction = 0;
            return (next / WINDOW_SCALE).min(u128::from(MAX_WINDOW)) as u32;
        }
        //= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
        //= reason=Target is next-SRTT curve value clamped between current cwnd and 1.5*cwnd, in Q32 bytes.
        //# *  _target_: Target value of the congestion window in segments after
        //# the next RTT -- that is, W_cubic(_t_ + _RTT_), as described in
        //# Section 4.2.
        //= https://www.rfc-editor.org/rfc/rfc9438#section-4.2
        //= reason=Target is next-SRTT curve value clamped between current cwnd and 1.5*cwnd, in Q32 bytes.
        //# Upon receiving a new ACK during congestion avoidance, CUBIC computes
        //# the _target_ congestion window size after the next _RTT_ using
        //# Figure 1 as follows, where _RTT_ is the smoothed round-trip time.
        //# The lower and upper bounds below ensure that CUBIC's congestion
        //# window increase rate is non-decreasing and is less than the increase
        //# rate of slow start [SXEZ19].
        //#
        //# ⎧
        //# ⎪cwnd            if  W     (t + RTT) < cwnd
        //# ⎪                     cubic
        //# ⎨1.5 * cwnd      if  W     (t + RTT) > 1.5 * cwnd
        //# target = ⎪                     cubic
        //# ⎪W     (t + RTT) otherwise
        //# ⎩ cubic
        let target = self
            .window(time.saturating_add(self.seconds(self.rtt)), mss)
            .clamp(current, current * 3 / 2);
        // Published RFC 9438 sections 4.4/4.5 specify one increment per new
        // ACK, not per segment acknowledged. Reported erratum 9186 is not
        // normative (https://www.rfc-editor.org/eid9186/) and is NOT applied.
        // W_est above still uses
        // segments_acked. Sub-MSS ACKs also use this published per-ACK rule.
        //= https://www.rfc-editor.org/rfc/rfc9438#section-4.4
        //= reason=Same published per-new-ACK increment in concave and convex/equality regions, with fractional bytes retained; reported erratum9186 is not adopted.
        //# When receiving a new ACK in congestion avoidance, if CUBIC is not in
        //# the Reno-friendly region and _cwnd_ is less than _W_max_, then CUBIC
        //# is in the concave region.  In this region, _cwnd_ MUST be incremented
        //# by
        //#
        //# target - cwnd
        //# ─────────────
        //# cwnd
        //#
        //# for each received new ACK, where _target_ is calculated as described
        //# in Section 4.2.
        //= https://www.rfc-editor.org/rfc/rfc9438#section-4.5
        //= reason=Same published per-new-ACK increment in concave and convex/equality regions, with fractional bytes retained; reported erratum9186 is not adopted.
        //# In this region, _cwnd_ MUST be
        //# incremented by
        //#
        //# target - cwnd
        //# ─────────────
        //# cwnd
        //#
        //# for each received new ACK, where _target_ is calculated as described
        //# in Section 4.2.
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
