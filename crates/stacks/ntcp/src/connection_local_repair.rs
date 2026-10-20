// SPDX-License-Identifier: MIT
// A retained first RACK repair can be synchronously cancelled before any bytes
// are submitted. All snapshots are fixed-size; payload and receive buffers are
// never cloned. Unsupported outputs keep their existing immutable reservation.
use super::*;

pub(super) struct RepairUndo {
    rack: crate::rack::RetryUndo,
    mss: usize,
    receive: crate::buffer::ReceiveOutputUndo,
    congestion: Congestion,
    prr: Option<Prr>,
    sack_recovery: Option<SackRecovery>,
    sample: Option<(Seq, Instant)>,
    sample_departure: Option<Instant>,
    rto_deadline: Option<Instant>,
    loss_timer: Option<(LossTimer, Instant)>,
    last_sent: Instant,
    last_ack_sent: Seq,
    ack_pending: bool,
    ack_deadline: Option<Instant>,
    unacked_segments: u8,
    unacked_bytes: u32,
    advertised_edge: Seq,
    advertised_snd_up: Option<Seq>,
    timestamp_tick: u64,
    timestamp_bytes: u32,
    last_timestamp_sent_at: Option<Instant>,
    retransmit_burst: Option<(Seq, u32)>,
    output_push_batch: Option<(Seq, bool, u16)>,
    sws_deadline: Option<Instant>,
    sws_override: bool,
    retx_pending: bool,
    shrink_unanswered_since: Option<Instant>,
    fast_open_retry: Option<(Seq, Seq)>,
    sack_omit: bool,
    sack_data_turn: bool,
}

impl RepairUndo {
    pub(super) fn capture(a: &Connection, start: Seq, count: usize) -> Option<Self> {
        let rack = a.rack.retry_undo(start, start.wrapping_add(count as u32))?;
        Some(Self {
            rack,
            mss: a.mss,
            receive: a.receive.output_undo(),
            congestion: a.congestion.clone(),
            prr: a.prr,
            sack_recovery: a.sack_recovery,
            sample: a.sample,
            sample_departure: a.sample_departure,
            rto_deadline: a.rto_deadline,
            loss_timer: a.loss_timer,
            last_sent: a.last_sent,
            last_ack_sent: a.last_ack_sent,
            ack_pending: a.ack_pending,
            ack_deadline: a.ack_deadline,
            unacked_segments: a.unacked_segments,
            unacked_bytes: a.unacked_bytes,
            advertised_edge: a.advertised_edge,
            advertised_snd_up: a.advertised_snd_up,
            timestamp_tick: a.timestamp_tick,
            timestamp_bytes: a.timestamp_bytes,
            last_timestamp_sent_at: a.last_timestamp_sent_at,
            retransmit_burst: a.retransmit_burst,
            output_push_batch: a.output_push_batch,
            sws_deadline: a.sws_deadline,
            sws_override: a.sws_override,
            retx_pending: a.retx_pending,
            shrink_unanswered_since: a.shrink_unanswered_since,
            fast_open_retry: a.fast_open_retry,
            sack_omit: a.sack_omit,
            sack_data_turn: a.sack_data_turn,
        })
    }
}

impl Connection {
    pub(crate) fn cancel_reserved_repair(&mut self) -> bool {
        let Some(undo) = &self.repair_undo else {
            return false;
        };
        let Some(selection) = self.reserved_ledger else {
            return false;
        };
        // A concurrent path-MSS update must not be undone with old CC units.
        if self.mss != undo.mss || !self.rack.cancel_retry(selection, undo.rack) {
            return false;
        }
        self.reject_reserved_output();
        let undo = self.repair_undo.take().unwrap();
        self.receive.restore_output(undo.receive);
        self.congestion = undo.congestion;
        self.prr = undo.prr;
        self.sack_recovery = undo.sack_recovery;
        self.sample = undo.sample;
        self.sample_departure = undo.sample_departure;
        self.rto_deadline = undo.rto_deadline;
        self.loss_timer = undo.loss_timer;
        self.last_sent = undo.last_sent;
        self.last_ack_sent = undo.last_ack_sent;
        self.ack_pending = undo.ack_pending;
        self.ack_deadline = undo.ack_deadline;
        self.unacked_segments = undo.unacked_segments;
        self.unacked_bytes = undo.unacked_bytes;
        self.advertised_edge = undo.advertised_edge;
        self.advertised_snd_up = undo.advertised_snd_up;
        self.timestamp_tick = undo.timestamp_tick;
        self.timestamp_bytes = undo.timestamp_bytes;
        self.last_timestamp_sent_at = undo.last_timestamp_sent_at;
        self.retransmit_burst = undo.retransmit_burst;
        self.output_push_batch = undo.output_push_batch;
        self.sws_deadline = undo.sws_deadline;
        self.sws_override = undo.sws_override;
        self.retx_pending = undo.retx_pending;
        self.shrink_unanswered_since = undo.shrink_unanswered_since;
        self.fast_open_retry = undo.fast_open_retry;
        self.sack_omit = undo.sack_omit;
        self.sack_data_turn = undo.sack_data_turn;
        self.reserved_retransmit_counts = None;
        self.last_departure = None;
        self.reserved_ledger = None;
        self.last_output_range = None;
        self.select_loss_timer();
        true
    }
}
