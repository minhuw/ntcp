//! Device-to-caller clock conversion fitted from paired samples. Pure Rust,
//! no DPDK: the host pairs its own clock reading with a device clock read
//! (e.g. `Port::read_clock`) and feeds both here. No nominal device frequency
//! is assumed; rate and offset both come from the samples.

use std::{collections::VecDeque, fmt};

/// Largest accepted window. Each sample re-fits over all pairs in the window
/// (Theil-Sen is quadratic), so this bounds the per-sample cost.
pub const MAX_CALIBRATION_WINDOW: usize = 128;

// Two points always fit exactly: they give no residual and cannot expose an
// outlier, so a fit needs a third.
const MIN_FIT_SAMPLES: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationError {
    /// Window outside `3..=MAX_CALIBRATION_WINDOW`.
    InvalidWindow,
    /// The device ticks did not increase, or the caller clock went backwards,
    /// relative to the newest accepted sample. The sample was not recorded.
    /// A counter wrap or device reset also lands here; `reset()` to restart.
    NonMonotonic,
}

impl fmt::Display for CalibrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidWindow => "calibration window outside 3..=128 samples",
            Self::NonMonotonic => "non-monotonic clock calibration sample",
        })
    }
}

impl std::error::Error for CalibrationError {}

/// Linear model `caller = anchor_caller + offset + rate * (device - anchor_device)`,
/// anchored at the newest sample so window-local deltas keep f64 precision.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ClockFit {
    rate: f64,
    offset: f64,
    anchor_device: u64,
    anchor_caller: u64,
    residual_rms: f64,
    max_residual: f64,
    rate_stderr: f64,
    inliers: usize,
    outliers: usize,
}

impl ClockFit {
    /// Caller ticks per device tick.
    pub fn rate(&self) -> f64 {
        self.rate
    }
    /// RMS residual of the samples used by the fit, in caller ticks.
    pub fn residual_rms(&self) -> f64 {
        self.residual_rms
    }
    /// Largest absolute residual of the samples used by the fit, in caller ticks.
    pub fn max_residual(&self) -> f64 {
        self.max_residual
    }
    /// Standard error of `rate()`.
    pub fn rate_stderr(&self) -> f64 {
        self.rate_stderr
    }
    pub fn inliers(&self) -> usize {
        self.inliers
    }
    /// Samples in the window excluded as outliers.
    pub fn outliers(&self) -> usize {
        self.outliers
    }
    /// Newest sample's device ticks; conversion error grows with distance from it.
    pub fn anchor_device(&self) -> u64 {
        self.anchor_device
    }

    /// None when the result is outside u64 (e.g. before the caller epoch).
    pub fn to_caller(&self, device_ticks: u64) -> Option<u64> {
        let delta = (i128::from(device_ticks) - i128::from(self.anchor_device)) as f64;
        let caller = (self.offset + self.rate * delta).round();
        if !caller.is_finite() || caller.abs() > u64::MAX as f64 {
            return None;
        }
        u64::try_from(i128::from(self.anchor_caller) + caller as i128).ok()
    }
}

/// Fits rate and offset over a sliding window of `(caller_now, device_ticks)`
/// pairs and re-fits on every accepted sample, so the model follows drift.
/// Robust: a Theil-Sen estimate classifies outliers (beyond 3 robust standard
/// deviations, at least one caller tick), then least squares refines over the
/// inliers. Degenerate windows (too few samples or inliers, non-positive
/// rate) have no fit, so `to_caller` returns None rather than a guess.
#[derive(Clone, Debug)]
pub struct ClockCalibration {
    window: usize,
    samples: VecDeque<(u64, u64)>,
    fit: Option<ClockFit>,
}

impl ClockCalibration {
    pub fn new(window: usize) -> Result<Self, CalibrationError> {
        if !(MIN_FIT_SAMPLES..=MAX_CALIBRATION_WINDOW).contains(&window) {
            return Err(CalibrationError::InvalidWindow);
        }
        Ok(Self {
            window,
            samples: VecDeque::with_capacity(window),
            fit: None,
        })
    }

    pub fn window(&self) -> usize {
        self.window
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn reset(&mut self) {
        self.samples.clear();
        self.fit = None;
    }

    /// Record one paired sample (taken as close together as possible) and
    /// re-fit. Rejected samples leave the window and fit unchanged.
    pub fn push(&mut self, caller_now: u64, device_ticks: u64) -> Result<(), CalibrationError> {
        if let Some(&(caller, device)) = self.samples.back()
            && (device_ticks <= device || caller_now < caller)
        {
            return Err(CalibrationError::NonMonotonic);
        }
        if self.samples.len() == self.window {
            self.samples.pop_front();
        }
        self.samples.push_back((caller_now, device_ticks));
        self.fit = fit(&self.samples);
        Ok(())
    }

    pub fn fit(&self) -> Option<&ClockFit> {
        self.fit.as_ref()
    }

    pub fn to_caller(&self, device_ticks: u64) -> Option<u64> {
        self.fit.as_ref()?.to_caller(device_ticks)
    }
}

fn median(values: &mut [f64]) -> f64 {
    let middle = values.len() / 2;
    let (_, upper, _) = values.select_nth_unstable_by(middle, f64::total_cmp);
    let upper = *upper;
    if values.len() % 2 == 1 {
        return upper;
    }
    let lower = values[..middle]
        .iter()
        .copied()
        .max_by(f64::total_cmp)
        .unwrap();
    (lower + upper) / 2.0
}

fn fit(samples: &VecDeque<(u64, u64)>) -> Option<ClockFit> {
    if samples.len() < MIN_FIT_SAMPLES {
        return None;
    }
    let &(anchor_caller, anchor_device) = samples.back()?;
    let points: Vec<(f64, f64)> = samples
        .iter()
        .map(|&(caller, device)| {
            (
                (i128::from(device) - i128::from(anchor_device)) as f64,
                (i128::from(caller) - i128::from(anchor_caller)) as f64,
            )
        })
        .collect();
    let mut slopes = Vec::with_capacity(points.len() * (points.len() - 1) / 2);
    for (i, &(xi, yi)) in points.iter().enumerate() {
        for &(xj, yj) in &points[i + 1..] {
            // Device ticks strictly increase, so xj > xi.
            slopes.push((yj - yi) / (xj - xi));
        }
    }
    let robust_rate = median(&mut slopes);
    let mut intercepts: Vec<f64> = points.iter().map(|&(x, y)| y - robust_rate * x).collect();
    let robust_offset = median(&mut intercepts);
    let deviations: Vec<f64> = points
        .iter()
        .map(|&(x, y)| (y - robust_offset - robust_rate * x).abs())
        .collect();
    // 1.4826 * MAD estimates a normal standard deviation. Integer caller ticks
    // make anything below one tick quantization, not evidence of an outlier.
    let threshold = (3.0 * 1.4826 * median(&mut deviations.clone())).max(1.0);
    let inliers: Vec<(f64, f64)> = points
        .iter()
        .zip(&deviations)
        .filter(|&(_, &deviation)| deviation <= threshold)
        .map(|(&point, _)| point)
        .collect();
    let count = inliers.len();
    if count < MIN_FIT_SAMPLES {
        return None;
    }
    let n = count as f64;
    let mean_x = inliers.iter().map(|p| p.0).sum::<f64>() / n;
    let mean_y = inliers.iter().map(|p| p.1).sum::<f64>() / n;
    let (sxx, sxy) = inliers.iter().fold((0.0, 0.0), |(sxx, sxy), &(x, y)| {
        let dx = x - mean_x;
        (sxx + dx * dx, sxy + dx * (y - mean_y))
    });
    let rate = sxy / sxx;
    if !(sxx > 0.0 && rate.is_finite() && rate > 0.0) {
        return None;
    }
    let offset = mean_y - rate * mean_x;
    let (squares, max_residual) = inliers.iter().fold((0.0, 0.0f64), |(sum, max), &(x, y)| {
        let residual = y - offset - rate * x;
        (sum + residual * residual, max.max(residual.abs()))
    });
    let residual_rms = (squares / (n - 2.0)).sqrt();
    Some(ClockFit {
        rate,
        offset,
        anchor_device,
        anchor_caller,
        residual_rms,
        max_residual,
        rate_stderr: residual_rms / sxx.sqrt(),
        inliers: count,
        outliers: points.len() - count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deterministic noise in [-amplitude, amplitude] (SplitMix64).
    fn noise(state: &mut u64, amplitude: f64) -> f64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        ((z >> 11) as f64 / (1u64 << 53) as f64 * 2.0 - 1.0) * amplitude
    }

    // caller = caller0 + rate * (device - device0) + noise
    fn feed(
        calibration: &mut ClockCalibration,
        (caller0, device0): (u64, u64),
        rate: f64,
        step: u64,
        range: std::ops::Range<u64>,
        amplitude: f64,
        state: &mut u64,
    ) {
        for i in range {
            let device = device0 + i * step;
            let caller = caller0 as f64 + rate * (i * step) as f64 + noise(state, amplitude);
            calibration.push(caller.round() as u64, device).unwrap();
        }
    }

    #[test]
    fn recovers_rate_and_offset_under_noise() {
        // A 156.25 MHz device counter against a nanosecond caller clock: 6.4 ns/tick.
        let mut calibration = ClockCalibration::new(32).unwrap();
        let mut state = 1;
        let (caller0, device0) = (5_000_000_000, 1_234_567_890_123);
        feed(
            &mut calibration,
            (caller0, device0),
            6.4,
            1_562_500,
            0..32,
            50.0,
            &mut state,
        );
        let fit = *calibration.fit().unwrap();
        assert!((fit.rate() - 6.4).abs() < 3e-6, "{}", fit.rate());
        assert_eq!(fit.outliers(), 0);
        assert!(fit.residual_rms() > 0.0 && fit.residual_rms() < 50.0);
        assert!(fit.max_residual() <= 60.0);
        assert!(fit.rate_stderr() > 0.0 && fit.rate_stderr() < 1e-6);
        // A device timestamp between samples maps within the noise bound.
        let device = device0 + 10 * 1_562_500 + 777;
        let expected = caller0 as f64 + 6.4 * (device - device0) as f64;
        let caller = calibration.to_caller(device).unwrap() as f64;
        assert!((caller - expected).abs() < 50.0, "{caller} vs {expected}");
    }

    #[test]
    fn exact_samples_convert_exactly() {
        let mut calibration = ClockCalibration::new(3).unwrap();
        for i in 0..3 {
            calibration.push(1_000 + 3 * i, 10 + i).unwrap();
        }
        let fit = calibration.fit().unwrap();
        assert_eq!(fit.rate(), 3.0);
        assert_eq!(fit.residual_rms(), 0.0);
        assert_eq!(calibration.to_caller(20), Some(1_030));
        assert_eq!(calibration.to_caller(10), Some(1_000));
    }

    #[test]
    fn rejects_an_outlier_sample() {
        let mut calibration = ClockCalibration::new(16).unwrap();
        let mut state = 7;
        let origin = (1_000_000, 1_000);
        feed(
            &mut calibration,
            origin,
            2.5,
            1_000_000,
            0..8,
            2.0,
            &mut state,
        );
        // Preemption between the device read and the caller read: the caller
        // reading is late (still earlier than the next sample's).
        calibration
            .push(1_000_000 + 20_000_000 + 400_000, 1_000 + 8_000_000)
            .unwrap();
        feed(
            &mut calibration,
            origin,
            2.5,
            1_000_000,
            9..16,
            2.0,
            &mut state,
        );
        let fit = calibration.fit().unwrap();
        assert_eq!(fit.outliers(), 1);
        assert_eq!(fit.inliers(), 15);
        assert!((fit.rate() - 2.5).abs() < 1e-6, "{}", fit.rate());
        assert!(fit.max_residual() < 3.0);
        let caller = calibration.to_caller(1_000 + 8_000_000).unwrap();
        assert!(caller.abs_diff(21_000_000) <= 3, "{caller}");
    }

    #[test]
    fn refits_after_drift() {
        let mut calibration = ClockCalibration::new(8).unwrap();
        let mut state = 3;
        let step = 1_000_000_000;
        feed(&mut calibration, (0, 0), 1.0, step, 0..8, 0.0, &mut state);
        assert!((calibration.fit().unwrap().rate() - 1.0).abs() < 1e-12);
        // The device oscillator drifts +100 ppm (rate seen by the caller drops).
        let rate = 1.0 / 1.0001;
        let anchor = (7 * step, 7 * step);
        feed(&mut calibration, anchor, rate, step, 1..9, 0.0, &mut state);
        let fit = calibration.fit().unwrap();
        assert_eq!(fit.inliers(), 8); // Old samples have left the window.
        assert!((fit.rate() - rate).abs() < 1e-9, "{}", fit.rate());
        let device = 7 * step + 8 * step + step / 2;
        let expected = (7 * step) as f64 + rate * (8 * step + step / 2) as f64;
        let caller = calibration.to_caller(device).unwrap() as f64;
        assert!((caller - expected).abs() <= 2.0, "{caller} vs {expected}");
    }

    #[test]
    fn rejects_non_monotonic_samples() {
        let mut calibration = ClockCalibration::new(4).unwrap();
        calibration.push(100, 1_000).unwrap();
        calibration.push(200, 2_000).unwrap();
        calibration.push(300, 3_000).unwrap();
        let before = *calibration.fit().unwrap();
        for (caller, device) in [(400, 3_000), (400, 2_999), (299, 4_000), (400, 0)] {
            assert_eq!(
                calibration.push(caller, device),
                Err(CalibrationError::NonMonotonic)
            );
        }
        assert_eq!(calibration.len(), 3);
        assert_eq!(calibration.fit(), Some(&before));
        // Equal caller readings are permitted (coarse caller clock).
        calibration.push(300, 3_001).unwrap();
    }

    #[test]
    fn degenerate_input_has_no_fit() {
        assert_eq!(
            ClockCalibration::new(2).unwrap_err(),
            CalibrationError::InvalidWindow
        );
        assert_eq!(
            ClockCalibration::new(MAX_CALIBRATION_WINDOW + 1).unwrap_err(),
            CalibrationError::InvalidWindow
        );
        let mut calibration = ClockCalibration::new(MAX_CALIBRATION_WINDOW).unwrap();
        assert!(calibration.is_empty());
        assert_eq!(calibration.to_caller(0), None);
        calibration.push(10, 10).unwrap();
        calibration.push(20, 20).unwrap();
        assert_eq!(calibration.fit(), None); // Two points: no residual estimate.
        assert_eq!(calibration.to_caller(15), None);
        // Caller clock stuck while the device advances: zero rate.
        let mut stuck = ClockCalibration::new(4).unwrap();
        for device in 1..=4 {
            stuck.push(500, device).unwrap();
        }
        assert_eq!(stuck.fit(), None);
        assert_eq!(stuck.to_caller(2), None);
        stuck.reset();
        assert!(stuck.is_empty());
        assert_eq!(stuck.fit(), None);
    }

    #[test]
    fn u64_edges() {
        // Device counter near u64::MAX, caller clock near zero.
        let mut calibration = ClockCalibration::new(4).unwrap();
        let top = u64::MAX - 4_000;
        for i in 0..4 {
            calibration
                .push(10 + 2 * i * 1_000, top + i * 1_000)
                .unwrap();
        }
        assert_eq!(calibration.fit().unwrap().rate(), 2.0);
        assert_eq!(calibration.to_caller(top), Some(10));
        assert_eq!(calibration.to_caller(top + 3_000), Some(6_010));
        assert_eq!(calibration.to_caller(u64::MAX), Some(8_010));
        assert_eq!(calibration.to_caller(top - 5), Some(0));
        assert_eq!(calibration.to_caller(top - 6), None); // Before caller zero.
        assert_eq!(calibration.to_caller(0), None);
        // A wrapping counter is non-monotonic, not a huge forward step.
        assert_eq!(
            calibration.push(9_000, 5),
            Err(CalibrationError::NonMonotonic)
        );

        // Caller clock near u64::MAX: conversion past it does not wrap.
        let mut high = ClockCalibration::new(3).unwrap();
        let caller_top = u64::MAX - 300;
        for i in 0..3 {
            high.push(caller_top + 100 * i, 7 + i).unwrap();
        }
        assert_eq!(high.to_caller(9), Some(u64::MAX - 100));
        assert_eq!(high.to_caller(10), Some(u64::MAX));
        assert_eq!(high.to_caller(11), None);
        assert_eq!(high.to_caller(u64::MAX), None);

        // Device ticks spanning the whole u64 range in one window.
        let mut wide = ClockCalibration::new(3).unwrap();
        wide.push(0, 0).unwrap();
        wide.push(1, u64::MAX / 2).unwrap();
        wide.push(2, u64::MAX - 1).unwrap();
        let fit = wide.fit().unwrap();
        assert!(fit.rate() > 0.0 && fit.rate().is_finite());
        assert_eq!(wide.to_caller(u64::MAX - 1), Some(2));
        assert_eq!(wide.to_caller(0), Some(0));
    }
}
