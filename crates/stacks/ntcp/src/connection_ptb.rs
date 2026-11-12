// SPDX-License-Identifier: MIT
// Exact-range repair work from accepted Packet Too Big drop notifications.
// Stream bytes keep their pending and retransmitted history in the send
// buffer's existing per-byte metadata, beside an outstanding-PTB-copy bit for
// the RFC 6675 pipe; only the FIN control position, pending and copy counts
// (constant-time "no work" test), the bounds of marked bytes with a selection
// hint, and the RTO takeover boundary live here. Every change of the pending
// marks also keeps the counts the estimator reads: per RACK interval (summed
// over those awaiting retransmission) and below the RFC 6675 lost edge.
// No packet-path allocation.
use super::*;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PtbRepair {
    // Send-buffer bytes currently carrying PTB work.
    pub(super) pending: usize,
    // Send-buffer bytes whose PTB replacement copy is outstanding and was
    // committed at or above RFC 6675 HighRxt, where SetPipe's retransmission
    // term does not count it: the SACK pipe adds them until delivery,
    // abandonment or HighRxt passing them, and NextSeg never selects them.
    pub(super) copies: usize,
    // Every byte carrying PTB work or an outstanding PTB copy lies in this
    // range: delivery, abandonment and estimator work stay inside it.
    span: Option<(Seq, Seq)>,
    // No pending byte lies below this selection hint. Selection moves it past
    // bytes that left the pending set, so its scan is amortized over them.
    next: Option<Seq>,
    // The quote covered the outstanding, never-retransmitted FIN.
    pub(super) fin_pending: bool,
    // FIN was (possibly) submitted again after its original transmission.
    fin_retransmitted: bool,
    // End of the flight outstanding at the latest RTO. Until a cumulative
    // ACK passes it, that flight belongs to ordinary timeout recovery.
    pub(super) rto_flight_end: Option<Seq>,
    // RFC 1191 section 6.4 slow-start trigger: a notification that added new
    // work admits one accepted physical repair packet until useful ACK
    // progress (cumulative advance or newly SACKed bytes).
    restart: bool,
    restart_spent: bool,
    // RFC 6675 SetPipe treats as lost exactly the unsacked bytes below
    // Scoreboard::lost_edge: an edge and the pending bytes below it, kept by
    // every change of the marks and moved before output reads it.
    lost_edge: Option<(Seq, usize)>,
    // Tests: estimate and select by scanning the marks, as before the kept
    // counts, to compare every emitted segment with them.
    #[cfg(test)]
    pub(super) scan: bool,
}

impl Connection {
    /// Intersection of a quoted sequence span with the outstanding window
    /// [SND.UNA, SND.NXT), in half-space-safe sequence arithmetic. A
    /// partially acknowledged quote is valid; an empty span (pure ACK/RST)
    /// or one wholly outside the window has none.
    pub(super) fn quoted_outstanding(&self, start: Seq, end: Seq) -> Option<(Seq, Seq)> {
        let flight = self.flight();
        let len = end.distance_from(start);
        if flight == 0 || len == 0 || len >= 1 << 31 {
            return None;
        }
        let low = if start.in_window(self.snd_una, flight) == Some(true) {
            start
        } else if self.snd_una.in_window(start, len) == Some(true) {
            self.snd_una
        } else {
            return None;
        };
        let count = end.distance_from(low).min(self.snd_nxt.distance_from(low));
        Some((low, low.wrapping_add(count)))
    }

    /// RFC 5927 section 4.1's acceptance of a TCP sequence quoted by an ICMP
    /// error, as Linux's tcp_v4_err and tcp_v6_err make it: within the sent
    /// sequence space [SND.UNA, SND.NXT], or the start of a quoted segment
    /// still partly outstanding. The span the quoted segment consumed is
    /// `ip_payload` octets (after the IP header) less this connection's
    /// data-segment TCP header. A quote carries only eight TCP octets, so
    /// options beyond the timestamps (SACK blocks) make the span end a
    /// little late, and a quoted FIN is not part of it.
    pub(crate) fn quoted_span(&self, sequence: u32, ip_payload: u32) -> Option<(u32, u32)> {
        let header = 20 + if self.timestamps { 12 } else { 0 };
        let (start, end) = (
            Seq(sequence),
            Seq(sequence).wrapping_add(ip_payload.saturating_sub(header)),
        );
        if start.distance_from(self.snd_una) > self.snd_nxt.distance_from(self.snd_una)
            && self.quoted_outstanding(start, end).is_none()
        {
            return None;
        }
        Some((start.0, end.0))
    }

    /// The latest transmission time among what the peer acknowledged: the
    /// SYN once delivered, and the payload RACK qualified (RFC 8985
    /// RACK.xmit_ts).
    pub(crate) fn delivered_sent_at(&self) -> Option<Instant> {
        let syn = self.syn_sent_at.filter(|_| self.syn_delivered);
        self.rack.latest_delivered().max(syn)
    }

    /// The quote overlaps the outstanding window at the still unacknowledged
    /// SYN.
    pub(super) fn quote_covers_syn(&self, start: Seq, end: Seq) -> bool {
        self.handshake_pending()
            && self
                .quoted_outstanding(start, end)
                .is_some_and(|(low, high)| {
                    self.iss.in_window(low, high.distance_from(low)) == Some(true)
                })
    }

    /// Add the eligible surviving coverage of one accepted drop notification
    /// as repair work: outstanding, not SACKed, never retransmitted since
    /// its original transmission, and outside a flight an RTO took over.
    /// Repeated, path-incarnation or size variants add nothing new. Returns
    /// whether any byte or the FIN became pending.
    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
    //= reason=Drop notification is distinct from path-change notification: Host::input_icmp correlates a validated PTB with committed submission evidence and hands it to the quoting connection at once (a report for an owner whose output is reserved is deferred with its normalized evidence and replayed when the reservation ends, without the possibly evicted ledger record), while the PMTU change reaches other users of the path only through Host::service_changes before their next output. Only bytes a PTB names are retransmitted: repair work is the quoted span's intersection with outstanding, unSACKed, never-retransmitted bytes, reclipped at selection, including non-head, partially acknowledged, wrapped and SACK-split ranges, and a PTB-caused MSS decrease no longer schedules a head retry. Dual-family Host tests repair exactly the quoted range of the quoted connection while an unquoted connection on the same path only adopts the budget and never retransmits; the isolated namespace tcp-staged case shows from captured packets that the first PTB-driven retransmission lies inside the quoted non-head range milliseconds after the real router PTB, while the head is unacknowledged.
    //# It is important to understand that the notification of the packetization layer instances using the path about the change in the PMTU is distinct from the notification of a specific instance that a packet has been dropped. The latter should be done as soon as practical (i.e., asynchronously from the point of view of the packetization layer instance), while the former may be delayed until a packetization layer instance wants to create a packet. Retransmission should be done for only for those packets that are known to be dropped, as indicated by a Datagram Too Big message.
    pub(super) fn note_ptb_drop(&mut self, start: Seq, end: Seq) -> bool {
        let Some((mut low, high)) = self.quoted_outstanding(start, end) else {
            return false;
        };
        if let Some(boundary) = self.ptb.rto_flight_end {
            if !boundary.after(low) {
                // Bytes first sent after that RTO remain eligible.
            } else if boundary.at_or_after(high) {
                return false;
            } else {
                low = boundary;
            }
        }
        // SYN is a control position: its own handshake retry repairs a
        // quoted SYN (including any SYN data), never stream PTB work.
        if self.quote_covers_syn(low, high) {
            return false;
        }
        let mut added = false;
        if let Some(fin) = self.fin_sequence
            && !self.ptb.fin_retransmitted
            && !self.ptb.fin_pending
            && fin.in_window(low, high.distance_from(low)) == Some(true)
        {
            self.ptb.fin_pending = true;
            added = true;
        }
        let data_end = self.send_base.wrapping_add(self.send.len() as u32);
        let high = if data_end.in_window(low, high.distance_from(low)) == Some(true) {
            data_end
        } else {
            high
        };
        if !low.at_or_after(self.send_base) || !high.after(low) {
            return added;
        }
        let base = self.send_base;
        for (left, right) in self.scoreboard.unsacked(low, high) {
            let marked = change_marks(
                &mut self.rack,
                &mut self.send,
                base,
                &mut self.ptb.lost_edge,
                (left, right),
                |send, offset, count| send.mark_ptb(offset, count) as isize,
            ) as usize;
            if marked != 0 {
                self.ptb.next = Some(match self.ptb.next {
                    Some(next) if self.ptb.pending != 0 => earlier(next, left),
                    _ => left,
                });
                widen(&mut self.ptb.span, left, right);
            }
            self.ptb.pending += marked;
            added |= marked != 0;
        }
        if added && !self.ptb.restart {
            // Later notifications during Restart never grant another packet.
            self.ptb.restart = true;
            self.ptb.restart_spent = false;
        }
        added
    }

    /// Useful ACK progress ends Restart: remaining work is admitted under
    /// ordinary congestion admission.
    fn ptb_progress(&mut self) {
        self.ptb.restart = false;
        self.ptb.restart_spent = false;
    }

    /// A PTB repair copy was accepted (direct encode or accepted reserved
    /// fragment): it consumes the Restart allowance.
    pub(super) fn ptb_repair_committed(&mut self) {
        if self.ptb.restart {
            self.ptb.restart_spent = true;
        }
    }

    /// Restart admits one accepted physical repair packet until useful ACK
    /// progress.
    pub(super) fn ptb_in_restart(&self) -> bool {
        self.ptb.restart
    }

    /// Per-coverage charges of one accepted fragment of a reserved PTB repair,
    /// made exactly once, after its retransmission history was recorded (as
    /// direct output records it before advancing HighRxt): PRR credit, the
    /// RACK replacement copy (its TSval names the selection time), the SACK
    /// pipe and contiguous HighRxt or post-RTO frontier, and the retransmitted
    /// edge. Unaccepted coverage was never charged, so a suffix withdrawn in
    /// Restart needs no undo.
    pub(super) fn commit_ptb_copy(
        &mut self,
        now: Instant,
        selected_at: Instant,
        start: Seq,
        count: usize,
        fin: bool,
        last: bool,
    ) {
        let end = start.wrapping_add(count as u32);
        if count != 0 {
            if let Some(prr) = &mut self.prr {
                prr.sent(count as u32);
                if last {
                    prr.finish_timer_repair();
                }
            }
            self.rack.transmit(start, end, selected_at, true);
            self.rack.commit_retry_span(start, end);
            if let Some(selection) = self.rack.departure_selection() {
                let committed = self.rack.commit_departure(selection, start, end, now);
                debug_assert!(committed);
            }
            if !self.rack.valid() {
                self.congestion.end_ecn_prr();
                self.prr = None;
            }
            if let Some(mut recovery) = self.sack_recovery {
                if !self.rack_enabled() && self.ptb_extends_frontier(recovery.high_rxt, start) {
                    recovery.high_rxt = end;
                }
                recovery.pipe = if self.rack_enabled() {
                    self.rack.pipe()
                } else {
                    recovery.pipe.saturating_add(count as u32)
                };
                self.sack_recovery = Some(recovery);
            }
            if let Some((old, boundary)) = self.sack_post_rto
                && self.ptb_extends_frontier(old, start)
                && end.after(old)
            {
                self.sack_post_rto = Some((end, boundary));
            }
        }
        if count != 0 || fin {
            self.congestion
                .on_retransmit(end.wrapping_add(u32::from(fin)));
        }
    }

    /// Sequence-space estimator for PTB admission: the selected estimator
    /// minus only the original-copy contribution of PTB-known-lost bytes that
    /// it still counts. Replacement copies are no longer pending, so the
    /// estimator counts them again until delivery or independent loss.
    pub(super) fn ptb_estimate(&self) -> u32 {
        let rack = self.rack_enabled();
        let (estimate, counted) = if let Some(recovery) = self.sack_recovery {
            (recovery.pipe, self.ptb_still_counted(rack))
        } else if self.sack_post_rto.is_some() && self.sack_fallback.is_none() {
            // Old-flight bytes cannot carry work; later bytes count as
            // unsacked data in the post-RTO pipe (or RACK's estimator).
            (
                self.post_rto_pipe(),
                if rack {
                    self.ptb_still_counted(true)
                } else {
                    self.ptb.pending as u32
                },
            )
        } else {
            // Cumulative FlightSize counts every pending original once.
            (self.flight(), self.ptb.pending as u32)
        };
        estimate.saturating_sub(counted)
    }

    // Pending bytes the recovery estimator still counts as in flight: those
    // RACK has not marked lost, or that RFC 6675 SetPipe does not treat as
    // lost (never subtract bytes already excluded by loss inference). Both
    // counts of lost pending bytes are kept as the marks change.
    pub(super) fn ptb_still_counted(&self, rack: bool) -> u32 {
        if self.ptb.pending == 0 {
            return 0;
        }
        #[cfg(test)]
        if self.ptb.scan {
            return self.ptb_still_counted_scan(rack);
        }
        let lost = if rack {
            let (base, send) = (self.send_base, &self.send);
            match self
                .rack
                .ptb_lost(|left, right| marked(send, base, left, right))
            {
                Some(lost) => lost as usize,
                // Partly marked intervals too scattered to find.
                None => return self.ptb_still_counted_scan(true),
            }
        } else {
            self.ptb_below(self.scoreboard.lost_edge(self.mss as u32))
        };
        let counted = self.ptb.pending.saturating_sub(lost) as u32;
        debug_assert_eq!(counted, self.ptb_still_counted_scan(rack));
        counted
    }

    // ptb_still_counted by visiting the lost ranges inside the pending
    // bounds and counting their marks.
    pub(super) fn ptb_still_counted_scan(&self, rack: bool) -> u32 {
        let Some((low, high)) = self.ptb.span.filter(|_| self.ptb.pending != 0) else {
            return 0;
        };
        let base = self.send_base;
        let start = later(
            later(
                self.ptb.next.map_or(low, |next| later(next, low)),
                self.snd_una,
            ),
            base,
        );
        let end = earlier(high, self.snd_nxt);
        if !end.after(start) {
            return self.ptb.pending as u32;
        }
        let mut lost = 0;
        let mut count = |left: Seq, right: Seq| {
            if right.after(left) {
                lost += self.send.count_ptb(
                    left.distance_from(base) as usize,
                    right.distance_from(left) as usize,
                );
            }
        };
        if rack {
            self.rack
                .lost_ranges(start, end)
                .for_each(|(l, r)| count(l, r));
        } else {
            self.scoreboard
                .lost_holes(start, end, self.mss as u32)
                .for_each(|(l, r)| count(l, r));
        }
        self.ptb.pending.saturating_sub(lost) as u32
    }

    // Pending bytes below `edge`: the kept count, moved by the marks between
    // its edge and this one.
    fn ptb_below(&self, edge: Seq) -> usize {
        match self.ptb.lost_edge {
            Some((old, below)) if edge.after(old) => below + self.ptb_count(old, edge),
            Some((old, below)) => below - self.ptb_count(edge, old),
            None => self
                .ptb
                .span
                .map_or(0, |(low, _)| self.ptb_count(low, edge)),
        }
    }

    // Pending bytes in [left, right).
    fn ptb_count(&self, left: Seq, right: Seq) -> usize {
        self.ptb_window(left, right)
            .map_or(0, |(offset, count)| self.send.count_ptb(offset, count))
    }

    // Before output reads the estimator: restate the RACK intervals only
    // partly marked, and move the RFC 6675 lost edge to the scoreboard's
    // (each byte the edge passes is counted once). Outside that recovery
    // the edge is dropped, so it never trails the flight; entering it again
    // counts the pending bytes below the edge once.
    fn ptb_sync(&mut self) {
        if self.ptb.pending == 0 {
            return;
        }
        let (base, send) = (self.send_base, &self.send);
        self.rack
            .settle_ptb(|left, right| marked(send, base, left, right));
        self.ptb.lost_edge = if self.sack_recovery.is_some() && !self.rack_enabled() {
            let edge = self.scoreboard.lost_edge(self.mss as u32);
            Some((edge, self.ptb_below(edge)))
        } else {
            None
        };
    }

    // Change the marks of [left, right) by op, which returns the change in
    // pending bytes of the range it is given.
    fn change_ptb(
        &mut self,
        left: Seq,
        right: Seq,
        op: impl FnMut(&mut SendBuffer, usize, usize) -> isize,
    ) -> isize {
        change_marks(
            &mut self.rack,
            &mut self.send,
            self.send_base,
            &mut self.ptb.lost_edge,
            (left, right),
            op,
        )
    }

    /// A PTB repair at `seq` may advance a HighRxt-style frontier at `from`
    /// only when no unretransmitted, unsacked byte lies between them.
    pub(super) fn ptb_extends_frontier(&self, from: Seq, seq: Seq) -> bool {
        let from = if from.after(self.snd_una) {
            from
        } else {
            self.snd_una
        };
        seq.at_or_after(from) && self.scoreboard.unsacked_bytes(from, seq) == 0
    }

    /// RFC 6675 NextSeg rules 1 and 3: the lowest (lost, for rule 1) hole
    /// above HighRxt, skipping bytes whose PTB replacement copy is still
    /// outstanding (that copy is counted in pipe and not yet known lost).
    pub(super) fn next_seg_hole(
        &self,
        after: Seq,
        mss: u32,
        lost_only: bool,
    ) -> Option<(Seq, Seq)> {
        let mut after = after;
        loop {
            let (left, right) =
                self.scoreboard
                    .lowest_hole(after, self.data_high(), mss, lost_only)?;
            let (Some((_, high)), true) = (self.ptb.span, self.ptb.copies != 0) else {
                return Some((left, right));
            };
            let Some((offset, count)) = self.ptb_window(left, right) else {
                return Some((left, right));
            };
            let Some((first, _)) = self.send.next_ptb_copy(offset, offset + count) else {
                return Some((left, right));
            };
            let first_seq = self.send_base.wrapping_add(first as u32);
            if first_seq.after(left) {
                return Some((left, first_seq));
            }
            // Skip the whole copy run (it may extend past this candidate).
            let end = high.distance_from(self.send_base) as usize;
            let run = self
                .send
                .next_ptb_copy(first, end)
                .map_or(1, |(_, run)| run);
            after = first_seq.wrapping_add(run as u32);
        }
    }

    /// Next PTB repair, reclipped at selection: the lowest pending run (or the
    /// pending FIN), bounded by the packet budget, the shared retry window
    /// policy, pacing (at the caller) and PRR credit when PRR is active.
    /// During Restart the RFC 1191 section 6.4 slow-start trigger itself is the
    /// congestion allowance: exactly one accepted packet, even when other
    /// outstanding data fills cwnd. Afterwards ordinary admission compares
    /// cwnd with the PTB estimator. Returns (start, payload, FIN).
    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.4
    //= reason=A PTB never causes a retransmission by itself: it only adds eligible bytes to the connection's pending repair set, which duplicate, repair-copy, path-incarnation and size variants and reports about a flight an RTO took over never enlarge, and each pending byte is repaired at most once. A notification that adds new work enters Restart, which admits one accepted physical repair packet until useful ACK progress (a cumulative advance or newly SACKed bytes; DSACK-only, duplicate and window-only ACKs do not count); remaining work then follows ordinary congestion admission. The dual-family real-receiver scheduler test sends four successively decreasing PTBs, one per oversized original, across many output polls without an ACK and observes exactly one repair packet, then every remaining byte resent exactly once without a timeout; Host reservation tests keep one physical packet when a racing decrease splits the repair; the isolated namespace tcp-burst case shows one repair packet, within a quoted range, before the first useful ACK for three real router PTBs, and no range resent twice between ACK progress.
    //# Note: One MUST not retransmit in response to every Datagram Too Big message, since a burst of several oversized segments will give rise to several such messages and hence several retransmissions of the same data. If the new estimated PMTU is still wrong, the process repeats, and there is an exponential growth in the number of superfluous segments sent!
    pub(super) fn ptb_segment(&mut self, packet_mss: usize) -> Option<(Seq, usize, bool)> {
        if self.ptb_idle() || self.ptb.restart && self.ptb.restart_spent || self.snd_wnd == 0 {
            return None;
        }
        let base = self.send_base;
        let run = if self.ptb.pending != 0 {
            let sent = if self.snd_nxt.after(base) {
                (self.snd_nxt.distance_from(base) as usize).min(self.send.len())
            } else {
                0
            };
            let from = later(self.ptb.next.unwrap_or(base), base).distance_from(base) as usize;
            #[cfg(test)]
            let limit = if self.ptb.scan {
                usize::MAX
            } else {
                packet_mss
            };
            #[cfg(not(test))]
            let limit = packet_mss;
            let run = self.send.next_ptb(from, sent, limit);
            // Everything skipped has left the pending set for good.
            if let Some((offset, _)) = run {
                self.ptb.next = Some(base.wrapping_add(offset as u32));
            }
            run
        } else {
            None
        };
        self.ptb_sync();
        let credit = match self.prr {
            Some(prr) => prr.credit(),
            None if self.ptb.restart => u32::MAX,
            None => self.congestion.cwnd().saturating_sub(self.ptb_estimate()),
        } as usize;
        if let Some((offset, run)) = run {
            let left = base.wrapping_add(offset as u32);
            let len = run.min(packet_mss);
            // The retry policy may end the repair at an original packet or
            // window edge; congestion credit must cover what remains of it.
            let limit = self.retry_limit(left, len as u32) as usize;
            let count = limit.min(credit);
            // PRR may clip a repair; otherwise wait for a full segment's
            // credit (or the whole permitted run) rather than dribble bytes.
            if count == 0 || self.prr.is_none() && credit < limit.min(self.mss) {
                return None;
            }
            let end = left.wrapping_add(count as u32);
            let fin = self.ptb.fin_pending
                && self.fin_sequence == Some(end)
                && end.distance_from(self.snd_una) < self.snd_wnd;
            return Some((left, count, fin));
        }
        // Only the quoted FIN remains: it needs peer-window room, not cwnd.
        let fin = self.fin_sequence.filter(|_| self.ptb.fin_pending)?;
        (fin.distance_from(self.snd_una) < self.snd_wnd).then_some((fin, 0, true))
    }

    /// Constant-time test: no PTB repair work exists.
    pub(super) fn ptb_idle(&self) -> bool {
        self.ptb.pending == 0 && !self.ptb.fin_pending
    }

    /// RFC 6675 pipe contribution of outstanding PTB copies that SetPipe's
    /// HighRxt term does not count.
    pub(super) fn ptb_copy_pipe(&self) -> u32 {
        self.ptb.copies as u32
    }

    /// An ordinary RFC 6675 retransmission at `seq` moves HighRxt from `from`
    /// past the PTB copies NextSeg skipped in [from, seq): SetPipe's
    /// retransmission term counts them from now on, so they stop being added
    /// separately. Copies inside the new retransmission itself stay (that
    /// byte has two replacement copies outstanding).
    pub(super) fn ptb_high_rxt_crossed(&mut self, from: Seq, seq: Seq) {
        if self.ptb.copies == 0 {
            return;
        }
        let from = later(from, self.snd_una);
        if let Some((offset, count)) = self.ptb_window(from, seq) {
            self.ptb.copies -= self.send.clear_ptb_copy(offset, count);
            self.ptb_settle();
        }
    }

    /// Record a (possibly) submitted retransmitted copy of `count` stream
    /// bytes from `start`, and of the FIN when `fin`. Never called for failed
    /// encoding or certified non-submission. A PTB repair copy (`ptb`) that
    /// will not lie below HighRxt is remembered for the RFC 6675 pipe.
    pub(super) fn record_retransmission(&mut self, start: Seq, count: usize, fin: bool, ptb: bool) {
        if fin {
            self.ptb.fin_retransmitted = true;
            self.ptb.fin_pending = false;
        }
        if count == 0 {
            return;
        }
        let end = start.wrapping_add(count as u32);
        let start = later(start, self.send_base);
        if !end.after(start) {
            return;
        }
        let base = self.send_base;
        let cleared = if self.ptb.pending == 0 {
            self.send.mark_retransmitted(
                start.distance_from(base) as usize,
                end.distance_from(start) as usize,
            )
        } else {
            -self.change_ptb(start, end, |send, offset, count| {
                -(send.mark_retransmitted(offset, count) as isize)
            }) as usize
        };
        self.ptb.pending -= cleared;
        if ptb && self.sack_recovery_enabled() {
            // Bytes below HighRxt are already counted by SetPipe's
            // retransmission term, as is a repair contiguous with it (the
            // commit advances HighRxt over it).
            let low = match self.sack_recovery {
                Some(r) if !self.rack_enabled() && self.ptb_extends_frontier(r.high_rxt, start) => {
                    end
                }
                Some(r) => later(start, r.high_rxt),
                None => start,
            };
            if end.after(low) {
                let marked = self.send.mark_ptb_copy(
                    low.distance_from(base) as usize,
                    end.distance_from(low) as usize,
                );
                if marked != 0 {
                    self.ptb.copies += marked;
                    widen(&mut self.ptb.span, low, end);
                }
            }
        }
        self.ptb_settle();
    }

    /// Cumulative delivery of `bytes` stream bytes up to `ack`, before the send
    /// buffer releases them: delivered bytes leave the pending set and release
    /// their outstanding PTB copies.
    pub(super) fn ptb_acknowledged(&mut self, ack: Seq, bytes: usize) {
        self.ptb_progress();
        if bytes != 0 {
            self.ptb_release(self.send_base, self.send_base.wrapping_add(bytes as u32));
        }
        if self.fin_sequence.is_some_and(|fin| ack.after(fin)) {
            self.ptb.fin_pending = false;
        }
        if self
            .ptb
            .rto_flight_end
            .is_some_and(|end| ack.at_or_after(end))
        {
            self.ptb.rto_flight_end = None;
        }
    }

    /// Before a SACK update: per incoming block, the hull of the bytes inside
    /// the PTB bounds that it covers and the scoreboard does not yet. Only
    /// these can become newly SACKed, so a repeated block yields nothing and
    /// a growing one only its new edge. Cost follows the scoreboard ranges.
    pub(super) fn ptb_sack_candidates(
        &self,
        blocks: &[Option<(u32, u32)>; 4],
    ) -> [Option<(Seq, Seq)>; 4] {
        let mut hulls = [None; 4];
        let Some((low, high)) = self.ptb.span else {
            return hulls;
        };
        let low = later(low, self.snd_una);
        for (hull, block) in hulls.iter_mut().zip(blocks) {
            let Some((left, right)) = *block else {
                continue;
            };
            let (left, right) = (later(Seq(left), low), earlier(Seq(right), high));
            if !right.after(left) {
                continue;
            }
            let mut holes = self.scoreboard.unsacked(left, right);
            if let Some((first, end)) = holes.next() {
                *hull = Some((first, holes.last().map_or(end, |(_, end)| end)));
            }
        }
        hulls
    }

    /// Newly SACKed bytes were delivered: withdraw any PTB work and copies
    /// they carry. `hulls` come from ptb_sack_candidates before the update;
    /// only their parts the updated scoreboard now covers are released.
    pub(super) fn ptb_sacked(&mut self, hulls: &[Option<(Seq, Seq)>; 4]) {
        self.ptb_progress();
        for &(left, right) in hulls.iter().flatten() {
            let mut cursor = left;
            while right.after(cursor) {
                let hole = self.scoreboard.unsacked(cursor, right).next();
                let (sacked_end, next) = hole.unwrap_or((right, right));
                if sacked_end.after(cursor) {
                    self.ptb_release(cursor, sacked_end);
                }
                cursor = next;
            }
        }
    }

    /// RTO takeover: the timeout's ordinary recovery owns the whole flight
    /// outstanding now. Pending work is discarded, and reports about that
    /// flight add none until a cumulative ACK passes its end.
    pub(super) fn ptb_timeout(&mut self) {
        self.abandon_ptb();
        self.ptb_progress();
        self.ptb.rto_flight_end = Some(self.snd_nxt);
    }

    /// Discard all pending work and outstanding-copy accounting (RTO takeover
    /// or abandonment of the bytes).
    pub(super) fn abandon_ptb(&mut self) {
        if let Some((low, high)) = self.ptb.span {
            self.ptb_release(low, high);
        }
        debug_assert!(self.ptb.pending == 0 && self.ptb.copies == 0);
        self.ptb.fin_pending = false;
    }

    // Withdraw PTB work and outstanding copies from [left, right). A release
    // at either end of the bounds trims them, so later estimator, selection
    // and abandonment work stays within the remaining marked bytes.
    fn ptb_release(&mut self, left: Seq, right: Seq) {
        if let Some((offset, count)) = self.ptb_window(left, right) {
            let left = self.send_base.wrapping_add(offset as u32);
            let right = left.wrapping_add(count as u32);
            let mut copies = 0;
            let pending = -self.change_ptb(left, right, |send, offset, count| {
                let (pending, released) = send.release_ptb(offset, count);
                copies += released;
                -(pending as isize)
            }) as usize;
            self.ptb.pending -= pending;
            self.ptb.copies -= copies;
            if let Some((low, high)) = &mut self.ptb.span {
                if *low == left {
                    *low = right;
                }
                if *high == right {
                    *high = left;
                }
                if !high.after(*low) {
                    self.ptb.span = None;
                }
            }
        }
        self.ptb_settle();
    }

    /// (span, selection hint) of the PTB bounds, for invariant checks.
    #[cfg(test)]
    pub(super) fn ptb_bounds(&self) -> (Option<(Seq, Seq)>, Option<Seq>) {
        (self.ptb.span, self.ptb.next)
    }

    // Forget the bounds once no byte carries PTB state.
    fn ptb_settle(&mut self) {
        if self.ptb.pending == 0 {
            self.ptb.next = None;
            self.ptb.lost_edge = None;
            if self.ptb.copies == 0 {
                self.ptb.span = None;
            }
        }
    }

    // Send-buffer (offset, count) of [left, right) inside the PTB bounds.
    fn ptb_window(&self, left: Seq, right: Seq) -> Option<(usize, usize)> {
        let (low, high) = self.ptb.span?;
        let base = self.send_base;
        let left = later(later(left, low), base);
        let right = earlier(
            earlier(right, high),
            base.wrapping_add(self.send.len() as u32),
        );
        right.after(left).then(|| {
            (
                left.distance_from(base) as usize,
                right.distance_from(left) as usize,
            )
        })
    }
}

fn later(a: Seq, b: Seq) -> Seq {
    if a.after(b) { a } else { b }
}

fn earlier(a: Seq, b: Seq) -> Seq {
    if a.after(b) { b } else { a }
}

fn widen(span: &mut Option<(Seq, Seq)>, left: Seq, right: Seq) {
    *span = Some(match *span {
        Some((low, high)) => (earlier(low, left), later(high, right)),
        None => (left, right),
    });
}

// Applies op to the send-buffer marks of `range` (inside the buffer from
// `base`), then restates the RACK intervals overlapping it and the pending
// bytes below the lost edge. op returns the change in pending bytes of the
// range it is given; the total is returned.
fn change_marks(
    rack: &mut Rack,
    send: &mut SendBuffer,
    base: Seq,
    lost_edge: &mut Option<(Seq, usize)>,
    (left, right): (Seq, Seq),
    mut op: impl FnMut(&mut SendBuffer, usize, usize) -> isize,
) -> isize {
    if !right.after(left) {
        return 0;
    }
    let mut apply = |send: &mut SendBuffer, left: Seq, right: Seq| {
        if right.after(left) {
            op(
                send,
                left.distance_from(base) as usize,
                right.distance_from(left) as usize,
            )
        } else {
            0
        }
    };
    let total = match lost_edge {
        Some((edge, below)) if edge.after(left) => {
            let cut = earlier(*edge, right);
            let low = apply(send, left, cut);
            *below = below.wrapping_add_signed(low);
            low + apply(send, cut, right)
        }
        _ => apply(send, left, right),
    };
    if total != 0 {
        let send = &*send;
        rack.restate_ptb(left, right, |left, right| marked(send, base, left, right));
    }
    total
}

// Pending bytes of [left, right) in the send buffer from `base`.
fn marked(send: &SendBuffer, base: Seq, left: Seq, right: Seq) -> u32 {
    let len = send.len();
    let offset = (later(left, base).distance_from(base) as usize).min(len);
    let end = (later(right, base).distance_from(base) as usize).min(len);
    send.count_ptb(offset, end.saturating_sub(offset)) as u32
}
