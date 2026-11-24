use crate::{CloseReason, ConnectionEvents, NetworkError};

// Scheduling needs a single "any event" test. Materialize the public
// flags and optional values when an application actually takes them.
#[derive(Clone, Copy)]
#[repr(u16)]
pub(crate) enum Signal {
    Connected = 1,
    Readable = 1 << 1,
    Pushed = 1 << 2,
    Writable = 1 << 3,
    Acknowledged = 1 << 4,
    HalfClosed = 1 << 5,
    Closed = 1 << 6,
    Urgent = 1 << 7,
    RetransmissionWarning = 1 << 8,
    NetworkError = 1 << 9,
    InvalidScale = 1 << 10,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PendingEvents {
    bits: u16,
    urgent: u64,
    closed: Option<CloseReason>,
    network_error: Option<NetworkError>,
    invalid_scale: u8,
}

impl PendingEvents {
    pub(crate) fn is_empty(&self) -> bool {
        self.bits == 0
    }

    pub(crate) fn clear(&mut self) {
        self.bits = 0;
    }

    pub(crate) fn raise(&mut self, signal: Signal) {
        self.bits |= signal as u16;
    }

    pub(crate) fn raise_if(&mut self, signal: Signal, enabled: bool) {
        if enabled {
            self.raise(signal);
        }
    }

    pub(crate) fn set(&mut self, signal: Signal, enabled: bool) {
        if enabled {
            self.raise(signal);
        } else {
            self.bits &= !(signal as u16);
        }
    }

    pub(crate) fn urgent(&mut self, value: Option<u64>) {
        self.set(Signal::Urgent, value.is_some());
        if let Some(value) = value {
            self.urgent = value;
        }
    }

    pub(crate) fn closed(&mut self, reason: CloseReason) {
        self.closed = Some(reason);
        self.raise(Signal::Closed);
    }

    pub(crate) fn network_error(&mut self, error: NetworkError) {
        self.network_error = Some(error);
        self.raise(Signal::NetworkError);
    }

    pub(crate) fn invalid_scale(&mut self, scale: u8) {
        self.invalid_scale = scale;
        self.raise(Signal::InvalidScale);
    }

    #[inline]
    pub(crate) fn take(
        &mut self,
        acknowledged: u64,
        tx_timestamps: bool,
        errors: bool,
    ) -> Option<ConnectionEvents> {
        let mut bits = core::mem::take(&mut self.bits);
        if !errors {
            bits &= !(Signal::NetworkError as u16
                | Signal::RetransmissionWarning as u16
                | Signal::Urgent as u16);
        }
        if bits == 0 && !tx_timestamps {
            return None;
        }
        let has = |signal: Signal| bits & signal as u16 != 0;
        Some(ConnectionEvents {
            connected: has(Signal::Connected),
            readable: has(Signal::Readable),
            pushed: has(Signal::Pushed),
            writable: has(Signal::Writable),
            // Every advance of the cursor raises Acknowledged. Coalescing
            // these changes always reports the current cursor.
            acknowledged: has(Signal::Acknowledged).then_some(acknowledged),
            half_closed: has(Signal::HalfClosed),
            closed: self.closed.filter(|_| has(Signal::Closed)),
            urgent: has(Signal::Urgent).then_some(self.urgent),
            retransmission_warning: has(Signal::RetransmissionWarning),
            network_error: self.network_error.filter(|_| has(Signal::NetworkError)),
            invalid_window_scale: has(Signal::InvalidScale).then_some(self.invalid_scale),
            tx_timestamps,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_take(
        oracle: &mut ConnectionEvents,
        tx_timestamps: bool,
        errors: bool,
    ) -> Option<ConnectionEvents> {
        let mut events = core::mem::take(oracle);
        events.tx_timestamps = tx_timestamps;
        if !errors {
            events.network_error = None;
            events.retransmission_warning = false;
            events.urgent = None;
        }
        (!events.is_empty()).then_some(events)
    }

    #[test]
    fn exhaustive_flag_combinations_and_error_masking_match_oracle() {
        let ack_cursor = 123_456u64;
        let urgent_val = 789u64;
        let close_reason = CloseReason::Reset;
        let net_err = NetworkError::SoftUnreachable;
        let bad_scale = 15u8;

        for mask in 0u16..(1 << 11) {
            for tx_timestamps in [false, true] {
                for error_reports in [false, true] {
                    let mut pending = PendingEvents::default();
                    let mut oracle = ConnectionEvents::default();

                    if mask & (Signal::Connected as u16) != 0 {
                        pending.raise(Signal::Connected);
                        oracle.connected = true;
                    }
                    if mask & (Signal::Readable as u16) != 0 {
                        pending.raise(Signal::Readable);
                        oracle.readable = true;
                    }
                    if mask & (Signal::Pushed as u16) != 0 {
                        pending.raise(Signal::Pushed);
                        oracle.pushed = true;
                    }
                    if mask & (Signal::Writable as u16) != 0 {
                        pending.raise(Signal::Writable);
                        oracle.writable = true;
                    }
                    if mask & (Signal::Acknowledged as u16) != 0 {
                        pending.raise(Signal::Acknowledged);
                        oracle.acknowledged = Some(ack_cursor);
                    }
                    if mask & (Signal::HalfClosed as u16) != 0 {
                        pending.raise(Signal::HalfClosed);
                        oracle.half_closed = true;
                    }
                    if mask & (Signal::Closed as u16) != 0 {
                        pending.closed(close_reason);
                        oracle.closed = Some(close_reason);
                    }
                    if mask & (Signal::Urgent as u16) != 0 {
                        pending.urgent(Some(urgent_val));
                        oracle.urgent = Some(urgent_val);
                    }
                    if mask & (Signal::RetransmissionWarning as u16) != 0 {
                        pending.raise(Signal::RetransmissionWarning);
                        oracle.retransmission_warning = true;
                    }
                    if mask & (Signal::NetworkError as u16) != 0 {
                        pending.network_error(net_err);
                        oracle.network_error = Some(net_err);
                    }
                    if mask & (Signal::InvalidScale as u16) != 0 {
                        pending.invalid_scale(bad_scale);
                        oracle.invalid_window_scale = Some(bad_scale);
                    }

                    assert_eq!(pending.is_empty(), oracle.is_empty(), "mask={mask:#x}");
                    let got = pending.take(ack_cursor, tx_timestamps, error_reports);
                    let expected = reference_take(&mut oracle, tx_timestamps, error_reports);
                    assert_eq!(
                        got, expected,
                        "mask={mask:#x} tx_ts={tx_timestamps} errors={error_reports}"
                    );
                    assert!(pending.is_empty());
                    assert_eq!(pending.take(ack_cursor, false, true), None);
                }
            }
        }
    }

    #[test]
    fn randomized_last_writer_wins_transitions_match_oracle() {
        const CLOSE_REASONS: [CloseReason; 5] = [
            CloseReason::Normal,
            CloseReason::Reset,
            CloseReason::Aborted,
            CloseReason::TimedOut,
            CloseReason::NetworkError,
        ];
        const NET_ERRORS: [NetworkError; 5] = [
            NetworkError::SoftUnreachable,
            NetworkError::HardUnreachable,
            NetworkError::TimeExceeded,
            NetworkError::ParameterProblem,
            NetworkError::SourceQuench,
        ];

        let mut pending = PendingEvents::default();
        let mut oracle = ConnectionEvents::default();
        let mut ack_cursor = 0u64;
        let mut seed = 0x5eed_cafe_1234_5678u64;
        let mut next = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            seed
        };

        for step in 0..5000 {
            match next() % 18 {
                0 => {
                    pending.raise(Signal::Connected);
                    oracle.connected = true;
                }
                1 => {
                    let v = next() & 1 != 0;
                    pending.set(Signal::Readable, v);
                    oracle.readable = v;
                }
                2 => {
                    let v = next() & 1 != 0;
                    pending.raise_if(Signal::Pushed, v);
                    oracle.pushed |= v;
                }
                3 => {
                    let v = next() & 1 != 0;
                    pending.set(Signal::Pushed, v);
                    oracle.pushed = v;
                }
                4 => {
                    let v = next() & 1 != 0;
                    pending.set(Signal::Writable, v);
                    oracle.writable = v;
                }
                5 => {
                    let v = next() & 1 != 0;
                    pending.raise_if(Signal::Writable, v);
                    oracle.writable |= v;
                }
                6 => {
                    ack_cursor += 1 + (next() % 100);
                    pending.raise(Signal::Acknowledged);
                    oracle.acknowledged = Some(ack_cursor);
                }
                7 => {
                    pending.raise(Signal::HalfClosed);
                    oracle.half_closed = true;
                }
                8 => {
                    let v = next() & 1 != 0;
                    pending.set(Signal::HalfClosed, v);
                    oracle.half_closed = v;
                }
                9 => {
                    let reason = CLOSE_REASONS[(next() as usize) % CLOSE_REASONS.len()];
                    pending.closed(reason);
                    oracle.closed = Some(reason);
                }
                10 => {
                    let value = if next() & 3 == 0 {
                        None
                    } else {
                        Some(next() % 10_000)
                    };
                    pending.urgent(value);
                    oracle.urgent = value;
                }
                11 => {
                    pending.raise(Signal::RetransmissionWarning);
                    oracle.retransmission_warning = true;
                }
                12 => {
                    let err = NET_ERRORS[(next() as usize) % NET_ERRORS.len()];
                    pending.network_error(err);
                    oracle.network_error = Some(err);
                }
                13 => {
                    let scale = 15 + (next() % 200) as u8;
                    pending.invalid_scale(scale);
                    oracle.invalid_window_scale = Some(scale);
                }
                14 => {
                    pending.clear();
                    oracle = ConnectionEvents::default();
                }
                _ => {
                    let tx_timestamps = next() & 3 == 0;
                    let error_reports = next() & 1 != 0;
                    assert_eq!(pending.is_empty(), oracle.is_empty(), "step={step}");
                    assert_eq!(
                        pending.take(ack_cursor, tx_timestamps, error_reports),
                        reference_take(&mut oracle, tx_timestamps, error_reports),
                        "step={step}"
                    );
                }
            }
            assert_eq!(pending.is_empty(), oracle.is_empty(), "after step={step}");
        }
    }

    #[test]
    fn error_reports_false_masks_only_soft_error_signals_and_clears_stale_payloads() {
        let mut pending = PendingEvents::default();
        pending.network_error(NetworkError::SoftUnreachable);
        pending.raise(Signal::RetransmissionWarning);
        pending.urgent(Some(42));
        // With error_reports = false and no other signals, take returns None and drains bits.
        assert_eq!(pending.take(10, false, false), None);
        assert!(pending.is_empty());
        // A later take with error_reports = true must NOT resurrect stale payloads.
        pending.raise(Signal::Readable);
        let taken = pending.take(10, false, true).unwrap();
        assert_eq!(
            taken,
            ConnectionEvents {
                readable: true,
                ..ConnectionEvents::default()
            }
        );
    }
}
