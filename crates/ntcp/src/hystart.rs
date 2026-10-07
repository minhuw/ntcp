//! RFC 9406 initial slow start. Times are unsmoothed caller-clock ticks.
use core::cmp::Ordering;

use crate::{connection::CallerTimebase, seq::Seq};

#[derive(Clone, Copy, Debug)]
pub(crate) struct StartupAck {
    pub(crate) rtt: Option<u64>,
    pub(crate) snd_nxt: Seq,
    pub(crate) paced: bool,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct HyStart {
    window_end: Option<Seq>,
    unpaced_end: Option<Seq>,
    last_min: Option<u64>,
    current_min: Option<u64>,
    samples: u8,
    baseline: Option<u64>,
    css_rounds: u8,
    fraction: u8,
}

impl HyStart {
    #[cfg(test)]
    pub(crate) fn test_state(&self) -> (u8, Option<u64>, u8, Option<Seq>) {
        (
            self.samples,
            self.baseline,
            self.css_rounds,
            self.window_end,
        )
    }

    pub(crate) fn sent(&mut self, end: Seq, paced: bool) {
        if !paced {
            self.unpaced_end = Some(end);
        }
    }

    // Called once per fresh delivery ACK, even when cwnd growth is disallowed.
    // The boundary ACK belongs to the round it completes. An empty-flight
    // boundary is armed from committed SND.NXT on the next arriving ACK.
    pub(crate) fn ack(
        &mut self,
        ack: Seq,
        context: StartupAck,
        eligible_bytes: u32,
        mss: u32,
        timebase: CallerTimebase,
    ) -> (u32, bool) {
        let end = *self.window_end.get_or_insert(context.snd_nxt);
        let bytes = if context.paced && self.unpaced_end.is_none() {
            eligible_bytes
        } else {
            eligible_bytes.min(mss.saturating_mul(8))
        };
        if self.unpaced_end.is_some_and(|end| {
            matches!(
                ack.serial_cmp(end),
                Some(Ordering::Equal | Ordering::Greater)
            )
        }) {
            self.unpaced_end = None;
        }
        // Entry ACK grows in standard SS; fallback ACK still grows in CSS.
        let increase = if self.baseline.is_some() {
            let credit = u64::from(bytes) + u64::from(self.fraction);
            self.fraction = (credit % 4) as u8;
            (credit / 4) as u32
        } else {
            bytes
        };
        if let Some(rtt) = context.rtt {
            self.current_min = Some(self.current_min.map_or(rtt, |min| min.min(rtt)));
            self.samples = self.samples.saturating_add(1);
            if self.samples >= 8 {
                let current = self.current_min.unwrap();
                if let Some(baseline) = self.baseline {
                    if current < baseline {
                        self.baseline = None;
                        self.css_rounds = 0;
                        self.fraction = 0;
                    }
                } else if let Some(last) = self.last_min {
                    let units = u128::from(timebase.units_per_second);
                    let lower = (units * 4).div_ceil(1000) as u64;
                    let upper = (units * 16).div_ceil(1000) as u64;
                    let threshold = (last / 8).clamp(lower, upper);
                    if current.saturating_sub(last) >= threshold {
                        self.baseline = Some(current);
                        self.css_rounds = 0;
                    }
                }
            }
        }
        if matches!(
            ack.serial_cmp(end),
            Some(Ordering::Equal | Ordering::Greater)
        ) {
            if self.baseline.is_some() {
                self.css_rounds += 1; // The entry partial round counts.
                if self.css_rounds == 5 {
                    return (increase, true);
                }
            }
            self.last_min = self.current_min;
            self.current_min = None;
            self.samples = 0;
            self.window_end = (context.snd_nxt.serial_cmp(ack) == Some(Ordering::Greater))
                .then_some(context.snd_nxt);
        }
        (increase, false)
    }
}

#[cfg(test)]
mod tests;
