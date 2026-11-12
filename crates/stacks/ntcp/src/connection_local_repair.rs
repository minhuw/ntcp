// SPDX-License-Identifier: MIT
// A retained first RACK repair or a clean fresh flight can be cancelled before
// any physical bytes are submitted. All snapshots are fixed-size; payload and receive buffers are
// never cloned. Unsupported outputs keep their existing immutable reservation.
use super::*;

pub(super) struct RepairUndo {
    rack: Option<crate::rack::RetryUndo>,
    fresh: Option<FreshState>,
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
    sws_deadline: Option<Instant>,
    sws_override: bool,
    retx_pending: bool,
    shrink_unanswered_since: Option<Instant>,
    fast_open_retry: Option<(Seq, Seq)>,
    sack_omit: bool,
    sack_data_turn: bool,
}

#[derive(Clone, Copy)]
struct FreshState {
    snd_nxt: Seq,
    iw_epoch: Option<IwEpoch>,
    iw_started: bool,
    iw_fallback: bool,
    tlp_deadline: Option<Instant>,
    tlp_end: Option<(Seq, Seq, bool)>,
    tlp_flight: Option<Seq>,
    tlp_fresh_rtt: bool,
    last_output_ecn: u8,
    last_pmtu_output: Option<(Seq, Seq)>,
    cork_flush: Option<Seq>,
    cork_deadline: Option<Instant>,
    keepalive_deadline: Option<Instant>,
}

// The selection-time state of a reserved sequence-bearing control without
// payload (SYN, SYN-ACK or FIN): selection advanced SND.NXT, armed the RTO,
// started the Karn sample and moved the setup or close state, none of
// which may survive an attempt certified never submitted.
pub(super) struct ControlUndo {
    state: RepairUndo,
    connection_state: State,
    syn_pending: bool,
    syn_retransmissions: u32,
    syn_loss_detected: bool,
    sack_receive: bool,
    ecn_sent_setup: bool,
    ecn_sent_plain: bool,
    ecn_cwr_pending: bool,
    initial_pacing_open: bool,
    fin_sequence: Option<Seq>,
    fin_standalone: bool,
    fin_sent_at: Option<Instant>,
}

impl ControlUndo {
    pub(super) fn capture(a: &Connection) -> Self {
        Self {
            state: RepairUndo::capture_state(a, None, Some(FreshState::capture(a))),
            connection_state: a.state,
            syn_pending: a.syn_pending,
            syn_retransmissions: a.syn_retransmissions,
            syn_loss_detected: a.syn_loss_detected,
            sack_receive: a.sack_receive,
            ecn_sent_setup: a.ecn_sent_setup,
            ecn_sent_plain: a.ecn_sent_plain,
            ecn_cwr_pending: a.ecn_cwr_pending,
            initial_pacing_open: a.initial_pacing_open,
            fin_sequence: a.fin_sequence,
            fin_standalone: a.fin_standalone,
            fin_sent_at: a.fin_sent_at,
        }
    }
}

impl FreshState {
    fn capture(a: &Connection) -> Self {
        Self {
            snd_nxt: a.snd_nxt,
            iw_epoch: a.iw_epoch,
            iw_started: a.iw_started,
            iw_fallback: a.iw_fallback,
            tlp_deadline: a.tlp_deadline,
            tlp_end: a.tlp_end,
            tlp_flight: a.tlp_flight,
            tlp_fresh_rtt: a.tlp_fresh_rtt,
            last_output_ecn: a.last_output_ecn,
            last_pmtu_output: a.last_pmtu_output,
            cork_flush: a.cork_flush,
            cork_deadline: a.cork_deadline,
            keepalive_deadline: a.keepalive_deadline,
        }
    }
}

impl RepairUndo {
    pub(super) fn is_fresh(&self) -> bool {
        self.fresh.is_some()
    }
    pub(super) fn capture(a: &Connection, start: Seq, count: usize) -> Option<Self> {
        let rack = a.rack.retry_undo(start, start.wrapping_add(count as u32))?;
        Some(Self::capture_state(a, Some(rack), None))
    }

    pub(super) fn capture_fresh(a: &Connection) -> Option<Self> {
        if a.flight() != 0
            || !a.rack.empty_valid()
            || a.prr.is_some()
            || a.congestion.in_recovery()
            || a.congestion.ecn_prr_end().is_some()
            || a.sack_recovery.is_some()
            || a.sack_post_rto.is_some()
            || a.sack_fallback.is_some()
            || a.limited_pending
            || a.pacing_enabled()
            || !a.tx_timestamps.is_empty()
            || a.fast_open_retry.is_some()
            || a.pmtud.as_ref().is_some_and(|p| p.probe.is_some())
        {
            return None;
        }
        Some(Self::capture_state(a, None, Some(FreshState::capture(a))))
    }

    fn capture_state(
        a: &Connection,
        rack: Option<crate::rack::RetryUndo>,
        fresh: Option<FreshState>,
    ) -> Self {
        Self {
            rack,
            fresh,
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
            sws_deadline: a.sws_deadline,
            sws_override: a.sws_override,
            retx_pending: a.retx_pending,
            shrink_unanswered_since: a.shrink_unanswered_since,
            fast_open_retry: a.fast_open_retry,
            sack_omit: a.sack_omit,
            sack_data_turn: a.sack_data_turn,
        }
    }
}

impl Connection {
    pub(crate) fn cancel_reserved_repair(&mut self) -> bool {
        self.repair_undo.as_ref().is_some_and(|u| u.fresh.is_none()) && self.cancel_reserved_local()
    }

    pub(crate) fn cancel_reserved_resource(&mut self, now: Instant) -> Result<bool, Error> {
        self.check_time(now)?;
        let expired = due(self.application_deadline(), now);
        if self.repair_undo.as_ref().is_none_or(|u| u.fresh.is_none())
            || !self.cancel_reserved_local()
        {
            return Ok(false);
        }
        self.update_time(now)?;
        // A late failure callback cannot replace an already-expired application
        // clock with a new resource-probe epoch. Roll back only the certified
        // unsubmitted selection, then retain truthful terminal diagnostics.
        if expired {
            self.terminal(CloseReason::TimedOut);
            return Ok(true);
        }
        let retry_at =
            if self.local_resource.is_some() {
                now.saturating_add(self.config.timebase.ticks_from_us(500_000))
            } else {
                // Resource retry has a separate startup clock; this does not change
                // the transport RTO or its backoff. Match the conservative RTT plus
                // minimum-RTO allowance used before the first resource probe.
                now.saturating_add(
                    self.rto().max(self.rtt.srtt().unwrap_or(0).saturating_add(
                        self.config.timebase.ticks_from_us(self.config.rto_min_us),
                    )),
                )
            };
        let epoch = self.local_resource.and_then(|r| r.epoch);
        self.local_resource = Some(LocalResource {
            retry_at: Some(retry_at),
            epoch,
        });
        self.select_loss_timer();
        Ok(true)
    }

    /// Withdraw a reserved selection certified never submitted because its
    /// next hop could not be resolved (RFC 4861 section 7.2.2): restored as
    /// if never selected, so it records no departure (no RTT sample,
    /// retransmission count, RTO backoff, RACK or ledger commit). Its
    /// retransmittable state waits on the local-failure retry clock: the
    /// next attempt is no earlier than the current RTO, unbacked off, and
    /// an expired application deadline ends the connection TimedOut. False
    /// leaves a selection that cannot be restored wholly unchanged.
    pub(crate) fn cancel_reserved_unsubmitted(&mut self, now: Instant) -> Result<bool, Error> {
        self.check_time(now)?;
        let expired = due(self.application_deadline(), now);
        if !self.cancel_reserved_local() && !self.cancel_reserved_control() {
            return Ok(false);
        }
        self.update_time(now)?;
        if expired {
            self.terminal(CloseReason::TimedOut);
            return Ok(true);
        }
        self.unsubmitted_retry(now);
        Ok(true)
    }

    /// Release a reserved selection certified never submitted because its
    /// next hop could not be resolved (RFC 4861 section 7.2.2) when its
    /// selection-time state cannot be restored exactly (selected behind an
    /// outstanding flight, in recovery, paced, after an accepted prefix,
    /// ...): it becomes an unsent transmission. Its sequence space stays
    /// outstanding without a departure (no RACK commit, PMTU observation,
    /// pacing charge, retransmission count or RTT sample), so the
    /// connection's own loss recovery (RACK, or the retransmission timer
    /// armed when it was selected) sends it again, no earlier than the
    /// local-failure retry clock of a restored selection; an expired
    /// application deadline ends the connection TimedOut.
    pub(crate) fn release_reserved_unsubmitted(
        &mut self,
        now: Instant,
        departure: Option<&crate::output_reservation::Departure>,
    ) -> Result<(), Error> {
        self.check_time(now)?;
        let expired = due(self.application_deadline(), now);
        self.update_time(now)?;
        self.reject_reserved_output();
        self.repair_undo = None;
        self.control_undo = None;
        self.reserved_retransmit_counts = None;
        self.last_departure = None;
        self.last_discovery = None;
        self.reserved_ledger = None;
        self.last_output_range = None;
        // A never-departed copy times nothing (RFC 6298 section 3, Karn).
        if let Some(d) = departure {
            let end = Seq(d.start).wrapping_add(if d.syn {
                1
            } else {
                d.payload as u32 + u32::from(d.fin)
            });
            if self.sample.is_some_and(|(edge, _)| edge == end) {
                self.sample = None;
                self.sample_departure = None;
            }
        }
        if expired {
            self.terminal(CloseReason::TimedOut);
            return Ok(());
        }
        // Outstanding sequence space always has a retransmission timer.
        if self.flight() != 0 && self.rto_deadline.is_none() && self.persist_deadline.is_none() {
            self.rto_deadline = Some(now.saturating_add(self.rto()));
        }
        self.unsubmitted_retry(now);
        Ok(())
    }

    // Unlike a resource probe's fixed cadence, every failed resolution
    // already spent its solicitation timeouts, and the next attempt is TCP's
    // own retry: the same RTO-or-RTT bound as the first resource retry,
    // without a backoff step.
    fn unsubmitted_retry(&mut self, now: Instant) {
        let retry_at = now.saturating_add(
            self.rto().max(
                self.rtt
                    .srtt()
                    .unwrap_or(0)
                    .saturating_add(self.config.timebase.ticks_from_us(self.config.rto_min_us)),
            ),
        );
        let epoch = self.local_resource.and_then(|r| r.epoch);
        self.local_resource = Some(LocalResource {
            retry_at: Some(retry_at),
            epoch,
        });
        self.select_loss_timer();
    }

    fn cancel_reserved_control(&mut self) -> bool {
        let Some(undo) = &self.control_undo else {
            return false;
        };
        // A concurrent path-MSS update must not be undone with old units.
        if self.mss != undo.state.mss {
            return false;
        }
        let undo = self.control_undo.take().unwrap();
        self.reject_reserved_output();
        self.restore_selection(undo.state);
        self.state = undo.connection_state;
        self.syn_pending = undo.syn_pending;
        self.syn_retransmissions = undo.syn_retransmissions;
        self.syn_loss_detected = undo.syn_loss_detected;
        self.sack_receive = undo.sack_receive;
        self.ecn_sent_setup = undo.ecn_sent_setup;
        self.ecn_sent_plain = undo.ecn_sent_plain;
        self.ecn_cwr_pending = undo.ecn_cwr_pending;
        self.initial_pacing_open = undo.initial_pacing_open;
        self.fin_sequence = undo.fin_sequence;
        self.fin_standalone = undo.fin_standalone;
        self.fin_sent_at = undo.fin_sent_at;
        self.reserved_retransmit_counts = None;
        self.last_departure = None;
        self.last_discovery = None;
        self.reserved_ledger = None;
        self.last_output_range = None;
        self.resolve_probe_response();
        self.select_loss_timer();
        true
    }

    fn cancel_reserved_local(&mut self) -> bool {
        let Some(undo) = &self.repair_undo else {
            return false;
        };
        let Some(selection) = self.reserved_ledger else {
            return false;
        };
        // A concurrent path-MSS update must not be undone with old CC units.
        if self.mss != undo.mss {
            return false;
        }
        let cancelled = match undo.rack {
            Some(rack) => self.rack.cancel_retry(selection, rack),
            None => undo.fresh.is_some() && self.rack.cancel_unsubmitted_fresh(selection),
        };
        if !cancelled {
            return false;
        }
        self.reject_reserved_output();
        let undo = self.repair_undo.take().unwrap();
        self.restore_selection(undo);
        self.reserved_retransmit_counts = None;
        self.last_departure = None;
        self.last_discovery = None;
        self.reserved_ledger = None;
        self.last_output_range = None;
        // Withdrawing the PMTU attempt cancels its classification. Restoring
        // admission/PRR must not resurrect a provisional congestion exemption
        // whose evidence was discarded by reject_reserved_output().
        self.resolve_probe_response();
        self.select_loss_timer();
        true
    }

    fn restore_selection(&mut self, undo: RepairUndo) {
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
        self.sws_deadline = undo.sws_deadline;
        self.sws_override = undo.sws_override;
        self.retx_pending = undo.retx_pending;
        self.shrink_unanswered_since = undo.shrink_unanswered_since;
        self.fast_open_retry = undo.fast_open_retry;
        self.sack_omit = undo.sack_omit;
        self.sack_data_turn = undo.sack_data_turn;
        if let Some(fresh) = undo.fresh {
            self.snd_nxt = fresh.snd_nxt;
            self.iw_epoch = fresh.iw_epoch;
            self.iw_started = fresh.iw_started;
            self.iw_fallback = fresh.iw_fallback;
            self.tlp_deadline = fresh.tlp_deadline;
            self.tlp_end = fresh.tlp_end;
            self.tlp_flight = fresh.tlp_flight;
            self.tlp_fresh_rtt = fresh.tlp_fresh_rtt;
            self.last_output_ecn = fresh.last_output_ecn;
            self.last_pmtu_output = fresh.last_pmtu_output;
            self.cork_flush = fresh.cork_flush;
            self.cork_deadline = fresh.cork_deadline;
            self.keepalive_deadline = fresh.keepalive_deadline;
        }
    }
}
