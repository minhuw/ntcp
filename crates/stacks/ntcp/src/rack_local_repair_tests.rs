// SPDX-License-Identifier: MIT
use super::*;

#[test]
fn local_repair_rack_cancel_preserves_split_loss_and_wrap_and_invalidates_token() {
    for base in [Seq(1), Seq(u32::MAX - 499)] {
        let mut rack = Rack::with_capacity(2048).unwrap();
        let end = base.wrapping_add(1000);
        rack.transmit(base, end, 10, false);
        let original = rack.departure_selection().unwrap();
        rack.commit_departure(original, base, end, 10);
        // A real detector's lost state, split at existing byte-ledger edges.
        rack.intervals[0].needs_retransmit = true;
        rack.intervals[0].original_lost = true;
        rack.recount();
        rack.split(base.wrapping_add(333));
        let undo = rack.retry_undo(base, end).unwrap();
        let prior: Vec<_> = rack.intervals.iter().copied().collect();
        rack.transmit(base, end, 30, true);
        rack.commit_retry_span(base, end);
        let selected = rack.departure_selection().unwrap();
        assert!(rack.cancel_retry(selected, undo));
        assert_eq!(rack.intervals.iter().copied().collect::<Vec<_>>(), prior);
        assert_eq!(rack.pipe(), 0);
        assert_eq!(rack.counts().retransmitted, 0);
        assert!(!rack.commit_departure(selected, base, end, 40));
        assert!(!rack.cancel_retry(selected, undo));
        rack.transmit(base, end, 50, true);
        assert_ne!(rack.departure_selection(), Some(selected));
    }
}

#[test]
fn local_repair_rack_declines_mixed_transmission_history() {
    let mut rack = Rack::with_capacity(2048).unwrap();
    rack.transmit(Seq(1), Seq(1001), 10, false);
    let token = rack.departure_selection().unwrap();
    rack.commit_departure(token, Seq(1), Seq(1001), 10);
    rack.split(Seq(501));
    rack.intervals[0].needs_retransmit = true;
    rack.intervals[1].needs_retransmit = true;
    rack.intervals[1].sent = 11;
    rack.recount();
    assert!(rack.retry_undo(Seq(1), Seq(1001)).is_none());
}
