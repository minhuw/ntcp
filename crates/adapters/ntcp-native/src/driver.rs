use super::*;
use ntcp_host::{
    Advice, BackendOutcome, Datagram, DeferredIcmp, EgressContext, IcmpDispatch, NeighborHop,
    NeighborWake, Owner, Processed, ProcessedEnvelope, Received, Submission, SubmissionTicket,
};
use ntcp_io::{
    ClockDomain, PacketLayer, PacketTimestamp, ReceivedPacket, TcpSegmentationError,
    TcpSegmentationRequest, TimestampUnit, TxOutcome,
};

pub(super) struct PendingFrame {
    attempt: ntcp::TransmitAttempt,
    owner: Option<ntcp::ConnectionId>,
    context: Option<EgressContext>,
    ticket: Option<SubmissionTicket>,
    ip_len: usize,
    // Waiting while ARP resolves its next hop: not retried before the
    // Host's wake, and no backend backpressure.
    held: bool,
    // The aggregate prepared from `attempt`, which preparation retired,
    // kept for a retry while the backend blocks.
    group: Option<ntcp::TransmitGroup>,
    // Polled again after the backend refused its aggregate: sent a segment
    // at a time.
    scalar: bool,
}
pub(super) struct TxSlot {
    pub bytes: Vec<u8>,
    pub pending: Option<PendingFrame>,
}
pub(super) struct RetainedInput {
    bytes: Vec<u8>,
    len: usize,
    owner: ntcp::ConnectionId,
    envelope: Option<ProcessedEnvelope>,
    icmp: Option<DeferredIcmp>,
    metadata: ntcp::RxPacketMetadata,
}

impl<P: PacketIo> Network<P> {
    fn stop_with_error(&mut self, error: io::Error) -> Error {
        self.stopped = true;
        self.stopped_event = true;
        for (index, slot) in self.connections.iter_mut().enumerate() {
            if let Some(c) = &mut slot.value {
                // Observation cancellation does not certify non-submission.
                let _ = self.endpoint.cancel_tx_timestamps(c.core);
                c.closed_event = true;
                c.connected_event = false;
                c.readable_event = false;
                c.read_waiting = false;
                c.write_waiting = None;
                self.ready.push(index);
                self.stamped.push(index);
            }
        }
        let returned = io::Error::new(error.kind(), error.to_string());
        self.failure = Some(error);
        Error::Backend(returned)
    }
    pub fn stop(&mut self) {
        if !self.stopped {
            let _ = self.stop_with_error(io::Error::new(
                io::ErrorKind::Interrupted,
                "network stopped by its owner",
            ));
        }
    }
    pub fn drive(&mut self, now: Instant, budget: WorkBudget) -> Result<DriveReport> {
        // The drive's look at the inbox of a member of shared flows begins
        // before anything that can fail: every handoff from here on wakes
        // the member again, whatever becomes of this drive, so a drive that
        // fails early cannot leave the wake taken and later handoffs
        // silent. What already waits is this drive's to take or report.
        if let Some(inlet) = &self.inlet {
            inlet.begin();
        }
        self.advance_time(now)?;
        let mut report = DriveReport::default();
        // Take reusable scratch out of the owner while processed datagrams
        // borrow it. They never survive a call unless copied into the bounded
        // retained-input pool with their exact Host envelope.
        let mut rx = std::mem::take(&mut self.rx);
        let mut completed = std::mem::take(&mut self.completed);
        let result = self.drive_inner(now, budget, &mut rx, &mut completed, &mut report);
        self.rx = rx;
        self.completed = completed;
        self.counters.received += report.received as u64;
        self.counters.transmitted += report.transmitted as u64;
        self.counters.discarded += report.discarded as u64;
        if let Err(error) = result {
            return Err(match error {
                Error::Backend(error) => self.stop_with_error(error),
                other => other,
            });
        }
        Ok(report)
    }
    fn drive_inner(
        &mut self,
        now: Instant,
        budget: WorkBudget,
        rx: &mut [u8],
        completed: &mut [u8],
        report: &mut DriveReport,
    ) -> Result<()> {
        if let Some(member) = super::shared::member(&mut self.host) {
            member.begin();
        }
        self.maintain_connections()?;
        report.more_work |= self.endpoint.on_timeout(now, budget.timers)?;
        let changes = self.host.service_changes(&mut self.endpoint, now)?;
        if let Some(error) = changes.first_error {
            return Err(error.into());
        }
        let mut receive_work = 0;
        let retained = self.retained.len().min(budget.receive);
        for _ in 0..retained {
            receive_work += 1;
            let mut item = self.retained.pop_front().unwrap();
            if self.endpoint.is_output_reserved(item.owner) {
                self.retained.push_back(item);
                continue;
            }
            if let Some(icmp) = item.icmp {
                if let Ok(IcmpDispatch::Deferred(again)) =
                    self.host.replay_icmp(&mut self.endpoint, icmp, now)
                {
                    item.icmp = Some(again);
                    self.retained.push_back(item);
                    continue;
                }
            } else if self.endpoint.connection_exists(item.owner)
                && let Some(processed) = item
                    .envelope
                    .and_then(|e| e.datagram(&item.bytes[..item.len]))
            {
                let _ = self.host.input_datagram(
                    &mut self.endpoint,
                    now,
                    processed,
                    item.metadata,
                    self.config.tcp.dscp,
                );
            }
            self.receive_free.push(item.bytes);
        }
        // Packets other members of shared flows handed over, within the
        // same budget as this queue's own. Other members can keep the inbox
        // full however fast it drains, and this queue holds packets that
        // may be theirs, so the inbox takes at most half of what is left,
        // rounded up, before the queue is polled, as control frames take at
        // most half of the transmit budget, and after it what the queue
        // leaves: neither starves the other, and neither's share idles
        // while the other has packets. The inbox is looked at once, and its
        // drains tell whether more waits: a packet handed over after they
        // looked is the next drive's, and wakes a member that blocks
        // (`Wake`).
        let mut handoffs = false;
        if self.inlet.as_ref().is_some_and(|i| i.pending()) {
            let share = (budget.receive - receive_work).div_ceil(2);
            let (taken, more) = self.take_handoffs(share, completed, report);
            receive_work += taken;
            handoffs = more;
        }
        while receive_work < budget.receive && !self.receive_free.is_empty() {
            let packet = match self.io.receive_with_metadata(rx) {
                Ok(Some(packet)) => packet,
                Ok(None) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::InvalidData | io::ErrorKind::Unsupported
                    ) =>
                {
                    report.discarded += 1;
                    receive_work += 1;
                    continue;
                }
                Err(e) => return Err(Error::Backend(e)),
            };
            receive_work += 1;
            report.received += 1;
            if packet.len > rx.len() {
                return Err(Error::Backend(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "backend returned an invalid packet length",
                )));
            }
            let frame = if self.io.layer() == PacketLayer::Ethernet {
                match ntcp_ethernet::parse_ethernet_fragment(&rx[..packet.len]) {
                    Ok(frame) => {
                        let Link::Ethernet { local_mac, .. } = self.config.link else {
                            unreachable!()
                        };
                        if frame.destination != local_mac {
                            report.discarded += 1;
                            continue;
                        }
                        frame.payload
                    }
                    Err(_) => {
                        // ARP rides its own EtherType, which the IP parser
                        // refuses.
                        if self.control.is_empty() || !self.arp_input(&rx[..packet.len]) {
                            report.discarded += 1;
                        }
                        continue;
                    }
                }
            } else {
                &rx[..packet.len]
            };
            // A member of shared flows hands a packet of another member's
            // flow, or a fragment another member reassembles, to it as it
            // arrived.
            let mut fragment = false;
            if let Some(flows) = &self.flows {
                let key = flows::key(frame);
                fragment = matches!(key, flows::Key::Fragment { .. });
                if let Some(owner) = flows.elsewhere(key) {
                    let handoff = flows::Handoff {
                        timestamps: packet.timestamps,
                        tcp_segment_size: packet.tcp_segment_size,
                        fragment,
                        reassembled: None,
                    };
                    self.hand_off(owner, frame, handoff);
                    continue;
                }
            }
            if self.input(frame, packet, fragment, completed).is_err() {
                report.discarded += 1;
            }
        }
        if handoffs && receive_work < budget.receive {
            let (taken, more) =
                self.take_handoffs(budget.receive - receive_work, completed, report);
            receive_work += taken;
            handoffs = more;
        }
        if receive_work == budget.receive && budget.receive != 0 {
            report.more_work = true;
        }
        if !self.retained.is_empty() || handoffs {
            report.more_work = true;
        }
        // Control frames due now take at most half the transmit budget,
        // rounded up, before data, so data cannot starve them nor they data.
        let mut control = 0;
        if self.shared_neighbors {
            control = self.shared_output(now, budget.transmit.div_ceil(2), true, report)?;
            self.settle_member(now)?;
        } else if !self.control.is_empty() {
            self.service_neighbors(now)?;
            control = self.control_output(now, budget.transmit.div_ceil(2), report)?;
        }
        let mut data = 0;
        // Once the endpoint offers nothing and no slot holds a frame to retry,
        // further polls at this instant cannot transmit anything. A held
        // frame is not retried before its wake.
        let mut exhausted = false;
        for _ in control..budget.transmit {
            if exhausted && self.tx_pending == 0 || self.tx_held == self.tx.len() {
                break;
            }
            data += 1;
            let index = self.tx_cursor;
            self.tx_cursor = (index + 1) % self.tx.len();
            // The table is set aside while one slot is served in place: a
            // slot carries its frame's egress context, too large to move out
            // and back for every frame.
            let mut tx = std::mem::take(&mut self.tx);
            let slot = &mut tx[index];
            let was_pending = slot.pending.is_some();
            let was_held = slot.pending.as_ref().is_some_and(|p| p.held);
            let owner = slot.pending.as_ref().and_then(|p| p.owner);
            let result = self.transmit_slot(slot, report);
            let still_pending = slot.pending.is_some();
            let still_held = slot.pending.as_ref().is_some_and(|p| p.held);
            self.tx = tx;
            match (was_pending, still_pending) {
                (false, true) => occupy(&mut self.tx_frames, index),
                (true, false) => {
                    vacate(&mut self.tx_frames, index);
                    self.reservation_released(owner);
                }
                _ => {}
            }
            // Only frames to retry count as pending.
            self.tx_pending += usize::from(still_pending && !still_held);
            self.tx_pending -= usize::from(was_pending && !was_held);
            self.tx_held += usize::from(still_held);
            self.tx_held -= usize::from(was_held);
            // A settled retry may release output, so poll again after it.
            let idle = result?;
            exhausted = idle || exhausted && was_pending && still_pending;
        }
        // Requests for next hops data output just began resolving, within
        // what is left.
        if self.shared_neighbors {
            self.shared_output(now, budget.transmit - control - data, false, report)?;
        } else if !self.control.is_empty() {
            self.control_output(now, budget.transmit - control - data, report)?;
        }
        if budget.reclaim != 0 {
            report.reclaimed = self
                .io
                .reclaim_transmit(budget.reclaim)
                .map_err(Error::Backend)?;
        }
        self.collect_core_events();
        self.maintain_connections()?;
        self.host.collect(&self.endpoint)?;
        report.next_deadline = self
            .endpoint
            .next_deadline()
            .into_iter()
            .chain(self.host.next_reassembly_deadline())
            .min();
        if !self.control.is_empty()
            && let Some(at) = self.host.next_neighbor_deadline()
        {
            report.next_deadline = Some(report.next_deadline.map_or(at, |d| d.min(at)));
        }
        self.check_live();
        debug_assert_eq!(
            self.tx_pending,
            self.tx
                .iter()
                .filter(|s| s.pending.as_ref().is_some_and(|p| !p.held))
                .count()
        );
        debug_assert_eq!(
            self.tx_held,
            self.tx
                .iter()
                .filter(|s| s.pending.as_ref().is_some_and(|p| p.held))
                .count()
        );
        report.tx_blocked |= self.tx_pending != 0;
        // A held frame's reservation waits for its wake, not for a poll.
        if if self.tx_held == 0 {
            self.endpoint.has_pending_output()
        } else {
            self.tx_pending != 0 || self.endpoint.has_queued_output()
        } {
            report.more_work = true;
        }
        Ok(())
    }
    // An ARP frame addressed to this port or to broadcast, for the Host's
    // ARP; frames to other stations are not this port's to learn from.
    fn arp_input(&mut self, bytes: &[u8]) -> bool {
        let Link::Ethernet { local_mac, .. } = self.config.link else {
            return false;
        };
        let Ok(frame) = ntcp_ethernet::parse_ethernet_arp(bytes) else {
            return false;
        };
        if frame.destination != local_mac && frame.destination != ntcp_ethernet::BROADCAST {
            return false;
        }
        self.counters.arp_received += 1;
        let taken = self
            .host
            .receive_arp(self.ingress, self.now, frame.payload)
            .is_ok();
        self.arp_input |= taken;
        taken
    }
    // ARP's due timers, then held frames whose resolution ended.
    fn service_neighbors(&mut self, now: Instant) -> Result<()> {
        let due = self
            .host
            .next_neighbor_deadline()
            .is_some_and(|at| at <= now);
        if due {
            self.host.service_neighbors(now);
        }
        // A resolution ends only on ARP input or a timer. Its wakes are
        // taken then even when no frame is held: the held records of
        // frames given up meanwhile must not keep their slots in the held
        // table, which would refuse every later resolution.
        if self.tx_held == 0 && !due && !std::mem::take(&mut self.arp_input) {
            return Ok(());
        }
        self.arp_input = false;
        self.release_resolved()
    }
    // A member's share of its port's housekeeping: when the shared table has
    // work due and no other member holds it, the port's timers (`timers`)
    // and up to `limit` due ARP frames, sent on this queue through the
    // control slot as `control_output` sends them; returns how many were
    // tried. A member that finds the table held skips it: the holder is
    // doing the work, or the next drive of any member will.
    fn shared_output(
        &mut self,
        now: Instant,
        limit: usize,
        timers: bool,
        report: &mut DriveReport,
    ) -> Result<usize> {
        let Self {
            host,
            io,
            control,
            counters,
            ..
        } = self;
        let Some(member) = super::shared::member(host) else {
            return Ok(0);
        };
        let (mut sent, mut blocked, mut failure) = (0, false, None);
        let used = member.housekeep(now, limit, timers, |frame| {
            use ntcp_arp::ControlOutcome;
            if frame.encode(control).is_err() {
                return ControlOutcome::Failed;
            }
            match io.transmit(control) {
                Ok(TxOutcome::Submitted) => {
                    sent += 1;
                    ControlOutcome::Submitted
                }
                Ok(TxOutcome::WouldBlock | TxOutcome::Rejected) => {
                    blocked = true;
                    ControlOutcome::Blocked
                }
                Err(error) => {
                    failure = Some(error);
                    ControlOutcome::Uncertain
                }
            }
        });
        report.transmitted += sent;
        counters.arp_sent += sent as u64;
        if blocked {
            report.tx_blocked = true;
            counters.backend_backpressure += 1;
        }
        if let Some(error) = failure {
            return Err(Error::Backend(error));
        }
        Ok(used.unwrap_or(0))
    }
    // A member's wakes: the neighbors the port lost are reported to its
    // Host, and its held frames whose resolution ended are released.
    fn settle_member(&mut self, now: Instant) -> Result<()> {
        if !super::shared::member(&mut self.host).is_some_and(|m| m.woken()) {
            return Ok(());
        }
        self.host.service_neighbors(now);
        self.release_resolved()?;
        if let Some(member) = super::shared::member(&mut self.host) {
            member.settled();
        }
        Ok(())
    }
    // Up to `limit` due ARP control frames (replies, requests, probes)
    // through their own slot; returns how many were tried.
    //= https://www.rfc-editor.org/rfc/rfc826#name-abstract
    //# ?Is the opcode ares_op$REQUEST?  (NOW look at the opcode!!)
    //# Yes:
    //# Swap hardware and protocol fields, putting the local
    //# hardware and protocol addresses in the sender fields.
    //# Set the ar$op field to ares_op$REPLY
    //# Send the packet to the (new) target hardware address on
    //# the same hardware on which the request was received.
    //
    // A reply leaves through this port, the one its request arrived on, to
    // the requester's hardware address.
    //= https://www.rfc-editor.org/rfc/rfc826#name-abstract
    //# It then causes
    //# this packet to be broadcast to all stations on the Ethernet cable
    //# originally determined by the routing mechanism.
    //
    // A request for a next hop this port resolves leaves through it to the
    // broadcast address.
    //= https://www.rfc-editor.org/rfc/rfc826#name-abstract
    //# After a suitable time, the daemon considers removing an entry.
    //# It first sends (with a small number of retransmissions if needed)
    //# an address resolution packet with opcode REQUEST directly to the
    //# Ethernet address in the table.  If a REPLY is not seen in a short
    //# amount of time, the entry is deleted.  The request is sent
    //# directly so as not to bother every station on the Ethernet.
    //
    // The Host's unicast probes of an unconfirmed entry leave through this
    // port; the entry is deleted when none is answered.
    fn control_output(
        &mut self,
        now: Instant,
        limit: usize,
        report: &mut DriveReport,
    ) -> Result<usize> {
        let Link::Ethernet { local_mac, .. } = self.config.link else {
            return Ok(0);
        };
        let link = self.ingress.link();
        let mut used = 0;
        while used < limit {
            let Some(transmit) = self
                .host
                .neighbor_output(link, now, &mut self.control[14..])?
            else {
                break;
            };
            used += 1;
            let end = 14 + transmit.len;
            self.control[..6].copy_from_slice(&transmit.destination);
            self.control[6..12].copy_from_slice(&local_mac);
            self.control[12..14].copy_from_slice(&transmit.ethertype.to_be_bytes());
            self.control[end..].fill(0);
            let mut failure = None;
            let outcome = match self.io.transmit(&self.control) {
                Ok(TxOutcome::Submitted) => BackendOutcome::Submitted,
                Ok(TxOutcome::WouldBlock | TxOutcome::Rejected) => BackendOutcome::WouldBlock,
                Err(error) => {
                    failure = Some(error);
                    BackendOutcome::Unknown
                }
            };
            self.host
                .complete_neighbor_output(transmit.ticket, outcome, now)?;
            match outcome {
                BackendOutcome::Submitted => {
                    report.transmitted += 1;
                    self.counters.arp_sent += 1;
                }
                BackendOutcome::WouldBlock => {
                    report.tx_blocked = true;
                    self.counters.backend_backpressure += 1;
                    break;
                }
                _ => return Err(Error::Backend(failure.unwrap())),
            }
        }
        Ok(used)
    }
    // Held frames whose resolution ended. A resolved one is retried by the
    // transmit loop, which resolves it again. A failed one was certainly
    // never submitted: as ntcp-socket does for Neighbor Discovery, the
    // Endpoint withdraws it without a departure, records the Address
    // Unreachable advice as the connection's soft error and retries
    // retransmittable output on its own clock, no earlier than the RTO.
    fn release_resolved(&mut self) -> Result<()> {
        while let Some(wake) = self.host.neighbor_wake() {
            let (attempt, advice) = match wake {
                NeighborWake::Retry { attempt, .. } => (attempt, None),
                NeighborWake::Unreachable {
                    attempt, advice, ..
                } => (attempt, Some(advice)),
            };
            // A frame given up meanwhile (its connection aborted) is gone.
            let Some(index) = self.tx_frames.iter().copied().find(|&i| {
                self.tx[i]
                    .pending
                    .as_ref()
                    .is_some_and(|p| p.held && p.attempt == attempt)
            }) else {
                continue;
            };
            self.tx_held -= 1;
            let slot = &mut self.tx[index];
            match advice {
                None => {
                    slot.pending.as_mut().unwrap().held = false;
                    self.tx_pending += 1;
                }
                Some(advice) => {
                    let owner = slot.pending.take().unwrap().owner;
                    vacate(&mut self.tx_frames, index);
                    self.reservation_released(owner);
                    let error = match advice {
                        Advice::NetworkError(error) => Some(error),
                        Advice::PacketTooBig { .. } => None,
                    };
                    self.endpoint
                        .discard_unsubmitted(self.now, attempt, error)?;
                }
            }
        }
        Ok(())
    }
    fn receive_metadata(&mut self, packet: ReceivedPacket) -> ntcp::RxPacketMetadata {
        if self.config.rx_timestamp_ranges == 0 {
            return ntcp::RxPacketMetadata {
                tcp_segment_size: packet.tcp_segment_size,
                ..Default::default()
            };
        }
        ntcp::RxPacketMetadata {
            timestamps: ntcp::RxPacketTimestamps {
                software: packet
                    .timestamps
                    .software
                    .and_then(|stamp| self.receive_stamp(stamp)),
                hardware: packet
                    .timestamps
                    .hardware
                    .and_then(|stamp| self.receive_stamp(stamp)),
            },
            tcp_segment_size: packet.tcp_segment_size,
        }
    }
    fn receive_stamp(&mut self, packet: PacketTimestamp) -> Option<ntcp::RxTimestamp> {
        let clock = match (packet.clock.domain, packet.clock.unit) {
            (ClockDomain::Realtime, TimestampUnit::Nanoseconds) => {
                TimestampClock::RealtimeNanoseconds
            }
            (ClockDomain::Device(_), unit) => {
                let identity = if let Some((id, _)) =
                    self.backend_clocks.iter().find(|(_, c)| *c == packet.clock)
                {
                    *id
                } else {
                    if self.backend_clocks.len() == self.config.timestamp_clock_capacity {
                        self.counters.timestamp_metadata_lost += 1;
                        return None;
                    }
                    let Ok(id) =
                        NEXT_INSTANCE
                            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                    else {
                        self.counters.timestamp_metadata_lost += 1;
                        return None;
                    };
                    self.backend_clocks.push((id, packet.clock));
                    id
                };
                TimestampClock::DeviceTicks {
                    identity,
                    units_per_second: match unit {
                        TimestampUnit::Nanoseconds => Some(1_000_000_000),
                        TimestampUnit::RawTicks { .. } => None,
                    },
                }
            }
            _ => {
                self.counters.timestamp_metadata_lost += 1;
                return None;
            }
        };
        Some(ntcp::RxTimestamp {
            value: packet.value,
            clock,
        })
    }
    // `fragment`: a member of shared flows keyed the packet as a fragment.
    fn input(
        &mut self,
        frame: &[u8],
        packet: ReceivedPacket,
        fragment: bool,
        completed: &mut [u8],
    ) -> Result<()> {
        let metadata = self.receive_metadata(packet);
        let received = self
            .host
            .receive(self.ingress, self.now, frame, false, completed)?;
        let Received::Datagram(datagram) = received else {
            return Ok(());
        };
        // A member of shared flows that completes a datagram on a fragment
        // hands it to the member that owns its flow. Its fragments were
        // keyed by their addresses alone; it is keyed once, here.
        if fragment
            && let Some(flows) = &self.flows
            && let Some(owner) = flows.elsewhere(flows::key(datagram.bytes()))
        {
            let handoff = flows::Handoff {
                timestamps: packet.timestamps,
                tcp_segment_size: packet.tcp_segment_size,
                fragment: false,
                reassembled: Some(datagram.envelope()),
            };
            self.hand_off(owner, datagram.bytes(), handoff);
            return Ok(());
        }
        self.dispatch(datagram, metadata)
    }
    // A packet another member of shared flows handed over, taken in as one
    // this queue received: as it arrived, through `input` (a fragment is
    // reassembled here), or as the datagram the sender reassembled, which
    // the Host adopts and processes as if it had reassembled it. Only a
    // datagram completed here is keyed again.
    fn take_handoff(
        &mut self,
        bytes: &[u8],
        handoff: flows::Handoff,
        completed: &mut [u8],
    ) -> Result<()> {
        let packet = ReceivedPacket {
            len: bytes.len(),
            timestamps: handoff.timestamps,
            tcp_segment_size: handoff.tcp_segment_size,
        };
        let Some(envelope) = handoff.reassembled else {
            return self.input(bytes, packet, handoff.fragment, completed);
        };
        let metadata = self.receive_metadata(packet);
        let datagram = envelope.datagram(bytes).ok_or(Error::Unsupported(
            "a handed-over datagram of another length",
        ))?;
        let datagram = self.host.adopt_datagram(self.ingress, datagram)?;
        self.dispatch(datagram, metadata)
    }
    // Up to `limit` packets from this member's inbox, no more than there are
    // receive buffers free to retain them; returns how many it took, and
    // whether that was all it could take (none, without a buffer), so that
    // more may wait. A drain that stops short found the inbox empty, or
    // its next packet still being copied in, whose handoff wakes the
    // member then.
    fn take_handoffs(
        &mut self,
        limit: usize,
        completed: &mut [u8],
        report: &mut DriveReport,
    ) -> (usize, bool) {
        let Some(inlet) = self.inlet.take() else {
            return (0, false);
        };
        let limit = limit.min(self.receive_free.len());
        let mut discarded = 0;
        let taken = inlet.drain(limit, |packet, handoff| {
            if self.take_handoff(packet, handoff, completed).is_err() {
                discarded += 1;
            }
        });
        self.inlet = Some(inlet);
        report.discarded += discarded;
        self.counters.handoffs_received += taken as u64;
        (taken, taken == limit)
    }
    // Copies a packet into member `owner`'s inbox, counted either way.
    fn hand_off(&mut self, owner: usize, packet: &[u8], handoff: flows::Handoff) {
        let flows = self.flows.as_ref().expect("a member of shared flows");
        if flows.hand_off(owner, packet, handoff) {
            self.counters.handed_off += 1;
        } else {
            self.counters.handoffs_dropped += 1;
        }
    }
    // Destination processing and dispatch of one complete datagram.
    fn dispatch(&mut self, datagram: Datagram<'_>, metadata: ntcp::RxPacketMetadata) -> Result<()> {
        let processed = self.host.process(datagram, None)?;
        let packet = self.host.decode_datagram(processed)?;
        if packet.protocol == 1 || packet.protocol == 58 {
            if let IcmpDispatch::Deferred(icmp) =
                self.host
                    .input_icmp_datagram(&mut self.endpoint, self.now, processed)?
            {
                self.retain(icmp.owner(), None, Some(icmp), metadata)?;
            }
            return Ok(());
        }
        match self.host.input_datagram(
            &mut self.endpoint,
            self.now,
            processed,
            metadata,
            self.config.tcp.dscp,
        ) {
            Ok(ntcp::InputDisposition::Processed) => Ok(()),
            // Not taken in (malformed, or refused by the endpoint): counted
            // as discarded.
            Ok(ntcp::InputDisposition::Dropped) => Err(Error::Unsupported("datagram dropped")),
            // The endpoint refuses a segment for a connection whose output is
            // reserved before taking anything in. It waits, with its exact
            // envelope, until the reservation ends.
            Err(ntcp_host::Error::Endpoint(EndpointError::OutputReserved))
                if packet.protocol == 6 =>
            {
                let tcp = ntcp::wire::parse(packet.ip, packet.payload)
                    .map_err(|_| Error::Unsupported("malformed TCP packet"))?;
                let tuple = Tuple {
                    local: SocketAddr::new(packet.ip.destination, tcp.header.destination_port),
                    remote: SocketAddr::new(packet.ip.source, tcp.header.source_port),
                };
                let owner = self
                    .endpoint
                    .scoped_connection_id(self.scoped(tuple))
                    .ok_or(Error::InvalidHandle)?;
                self.retain(owner, Some(processed), None, metadata)
            }
            Err(error) => Err(error.into()),
        }
    }
    fn retain(
        &mut self,
        owner: ntcp::ConnectionId,
        processed: Option<Processed<'_>>,
        icmp: Option<DeferredIcmp>,
        metadata: ntcp::RxPacketMetadata,
    ) -> Result<()> {
        let mut bytes = self.receive_free.pop().ok_or(Error::Capacity)?;
        let mut len = 0;
        if let Some(processed) = processed {
            len = processed.bytes().len();
            if len > bytes.len() {
                self.receive_free.push(bytes);
                return Err(Error::Capacity);
            }
            bytes[..len].copy_from_slice(processed.bytes());
        }
        self.retained.push_back(RetainedInput {
            bytes,
            len,
            owner,
            envelope: processed.map(|p| p.envelope()),
            icmp,
            metadata,
        });
        Ok(())
    }
    // Ok(true): the endpoint was polled and has nothing left to offer at this
    // instant. A poll that skipped an idle ready-queue entry still reports
    // more work, and the next connection may have a packet.
    fn transmit_slot(&mut self, slot: &mut TxSlot, report: &mut DriveReport) -> Result<bool> {
        if slot.pending.is_none()
            && let Some(idle) = self.fill(slot, None, report)?
        {
            return Ok(idle);
        }
        loop {
            match self.send(slot, report)? {
                // The backend refused the aggregate, which the endpoint
                // took back: its first segment goes out alone, in this turn.
                Some(owner) => {
                    if let Some(idle) = self.fill(slot, Some(owner), report)? {
                        return Ok(idle);
                    }
                }
                None => return Ok(false),
            }
        }
    }
    // Polls the endpoint's next packet into empty `slot`, or that of
    // `owner`'s reservation; Some ends the slot's turn, Some(true) when the
    // endpoint has nothing left to offer.
    fn fill(
        &mut self,
        slot: &mut TxSlot,
        owner: Option<ntcp::ConnectionId>,
        report: &mut DriveReport,
    ) -> Result<Option<bool>> {
        let offset = self.config.link.offset();
        {
            let header = if self.config.local_address.is_ipv4() {
                20
            } else {
                40
            };
            let out = &mut slot.bytes[offset + header..];
            let polled = match owner {
                None => self.endpoint.poll_reserved_transmit(self.now, out, 1),
                Some(id) => self
                    .endpoint
                    .poll_reserved_transmit_for(self.now, id, out, 1),
            };
            let (poll, attempt) = match polled {
                Ok(result) => result,
                Err(EndpointError::OutputReserved) => {
                    report.tx_blocked = true;
                    return Ok(Some(true));
                }
                Err(e) => return Err(e.into()),
            };
            // Held frames' reservations are not output to poll for. On a
            // resolving link the poll's view, taken before its packet may
            // be held, is left to the drive's final account.
            let more_work = if self.tx_held == 0 {
                poll.more_work
            } else {
                self.tx_pending != 0 || self.endpoint.has_queued_output()
            };
            if poll.packet.is_none() || self.control.is_empty() {
                report.more_work |= more_work;
            }
            let Some(packet) = poll.packet else {
                return Ok(Some(owner.is_none() && !more_work));
            };
            let attempt = attempt.ok_or(Error::InvalidHandle)?;
            let ip_len = if packet.ip.source.is_ipv4() {
                ntcp_ip::encode(&mut slot.bytes[offset..], packet, 0)
            } else {
                ntcp_ip6::encode(&mut slot.bytes[offset..], packet)
            }
            .map_err(|e| Error::Host(e.into()))?;
            if let Link::Ethernet {
                local_mac,
                next_hop,
            } = self.config.link
            {
                // An ARP-resolved destination is written once resolved.
                if let EthernetNextHop::Fixed(next_hop_mac) = next_hop {
                    slot.bytes[..6].copy_from_slice(&next_hop_mac);
                }
                slot.bytes[6..12].copy_from_slice(&local_mac);
                slot.bytes[12..14].copy_from_slice(
                    &(if packet.ip.source.is_ipv4() {
                        0x0800u16
                    } else {
                        0x86ddu16
                    })
                    .to_be_bytes(),
                );
                let end = offset + ip_len;
                if end < 60 {
                    slot.bytes[end..60].fill(0);
                }
            }
            slot.pending = Some(PendingFrame {
                attempt,
                owner: packet.connection,
                context: None,
                ticket: None,
                ip_len,
                held: false,
                group: None,
                scalar: owner.is_some(),
            });
        }
        Ok(None)
    }
    // One physical attempt of `slot`'s frame. Some(owner): the backend
    // refused the aggregate prepared from it, and the endpoint took its
    // reservation back unattempted.
    fn send(
        &mut self,
        slot: &mut TxSlot,
        report: &mut DriveReport,
    ) -> Result<Option<ntcp::ConnectionId>> {
        let offset = self.config.link.offset();
        let pending = slot.pending.as_mut().unwrap();
        if pending.held {
            return Ok(None);
        }
        let context = match pending.context {
            Some(context) => context,
            None => match self
                .host
                .egress_context(&mut self.endpoint, pending.attempt)
            {
                Ok(context) => {
                    pending.context = Some(context);
                    context
                }
                Err(ntcp_host::Error::Capacity | ntcp_host::Error::Allocation) => {
                    report.tx_blocked = true;
                    return Ok(None);
                }
                Err(ntcp_host::Error::Obsolete) => {
                    self.endpoint.reject_unsubmitted(pending.attempt)?;
                    slot.pending = None;
                    report.more_work = true;
                    return Ok(None);
                }
                Err(error) => return Err(error.into()),
            },
        };
        // The next hop is resolved before each new ticket; a blocked frame
        // keeps its ticket and the destination resolved for it.
        if pending.ticket.is_none() && !self.control.is_empty() {
            let owner = pending.owner.map_or(Owner::Stateless, Owner::Tcp);
            match self.host.resolve_neighbor(context, owner, self.now) {
                Ok(NeighborHop::Resolved(mac)) => slot.bytes[..6].copy_from_slice(&mac),
                // The frame stays in its owner's slot, the latest of that
                // owner's output, and is sent once its wake retries it.
                //= https://www.rfc-editor.org/rfc/rfc1122#section-2.3.2.2
                //# The link layer SHOULD save (rather than discard) at least
                //# one (the latest) packet of each set of packets destined to
                //# the same unresolved IP address, and transmit the saved
                //# packet when the address has been resolved.
                Ok(NeighborHop::Held) => {
                    pending.held = true;
                    return Ok(None);
                }
                // No neighbor entry or held record is free: the attempt is
                // withdrawn unsubmitted, retried on TCP's own clock.
                Err(ntcp_host::Error::Capacity) => {
                    self.endpoint
                        .discard_unsubmitted(self.now, pending.attempt, None)?;
                    slot.pending = None;
                    return Ok(None);
                }
                Err(error) => return Err(error.into()),
            }
        }
        let ticket = match pending.ticket.take() {
            Some(ticket) => ticket,
            None => self.host.submission_ticket(&mut self.endpoint, context)?,
        };
        if pending.group.is_none()
            && !pending.scalar
            && pending.owner.is_some()
            && let Some(capabilities) = self.segmentation
        {
            let ecn = if self.config.local_address.is_ipv4() {
                slot.bytes[offset + 1] & 3
            } else {
                (slot.bytes[offset + 1] >> 4) & 3
            };
            let attempt = pending.attempt;
            let group = self.prepare_group(capabilities, attempt, ecn)?;
            slot.pending.as_mut().unwrap().group = group;
        }
        let pending = slot.pending.as_mut().unwrap();
        if let Some(group) = pending.group {
            return self.send_group(slot, context, ticket, group, report);
        }
        let packet = &slot.bytes[offset..offset + pending.ip_len];
        let wire_len = (offset + pending.ip_len).max(if offset == 0 { 0 } else { 60 });
        let wire = &slot.bytes[..wire_len];
        let io = &mut self.io;
        let mut failure = None;
        let result = self.host.submit(
            &mut self.endpoint,
            self.now,
            ticket,
            context,
            packet,
            0,
            |_| match io.transmit(wire) {
                Ok(TxOutcome::Submitted) => BackendOutcome::Submitted,
                Ok(TxOutcome::WouldBlock | TxOutcome::Rejected) => BackendOutcome::WouldBlock,
                Err(error) => {
                    failure = Some(error);
                    BackendOutcome::Unknown
                }
            },
        );
        match result {
            Ok(Submission::Submitted) => {
                slot.pending = None;
                report.transmitted += 1;
            }
            Ok(Submission::Blocked(ticket) | Submission::Rejected(ticket)) => {
                pending.ticket = Some(ticket);
                report.tx_blocked = true;
                self.counters.backend_backpressure += 1;
            }
            Ok(Submission::PossiblySubmitted) => {
                return Err(Error::Backend(failure.unwrap_or_else(|| {
                    io::Error::other("unknown packet submission outcome")
                })));
            }
            Ok(Submission::Cancelled) => {
                slot.pending = None;
            }
            Err(refused) if refused.error == ntcp_host::Error::Obsolete => {
                self.host.cancel_submission(refused.ticket);
                self.endpoint.reject_unsubmitted(pending.attempt)?;
                slot.pending = None;
                report.more_work = true;
            }
            Err(refused) => {
                pending.ticket = Some(refused.ticket);
                return Err(refused.error.into());
            }
        }
        Ok(None)
    }
    // The aggregate of `attempt`'s reservation the backend can segment: as
    // many of its full segments as the aggregate's frame holds, the backend
    // cuts and their frames take on the wire, each at most the device's
    // MTU. The segments of a reservation of fewer, its last one with PSH
    // while the backend cannot place PSH, and every segment marked ECT or
    // CE go out one at a time: no backend copies an IP ECN codepoint into
    // the segments it cuts (DPDK refuses it), so such an aggregate would
    // only be built to be refused. `ecn`: the attempt's codepoint.
    fn prepare_group(
        &mut self,
        capabilities: ntcp_io::TcpSegmentationCapabilities,
        attempt: ntcp::TransmitAttempt,
        ecn: u8,
    ) -> Result<Option<ntcp::TransmitGroup>> {
        let Some(s) = self.endpoint.transmit_segmentation(attempt) else {
            return Ok(None);
        };
        let offset = self.config.link.offset();
        let ip = if self.config.local_address.is_ipv4() {
            20
        } else {
            40
        };
        let packet = ip + s.tcp_header_len + s.segment_payload_len;
        if ecn != 0 || packet > capabilities.local_ip_mtu as usize {
            return Ok(None);
        }
        let frame = (offset + packet).max(if offset == 0 { 0 } else { 60 });
        let limits = ntcp::TransmitGroupLimits {
            max_bytes: self
                .aggregate
                .len()
                .saturating_sub(offset + ip + s.tcp_header_len),
            max_segments: capabilities
                .max_segments
                .min(capabilities.max_wire_bytes / frame),
            allow_psh: capabilities.allow_psh,
            allow_cwr: capabilities.allow_cwr,
            // Data segments carry timestamps and SACK blocks, which stay
            // valid repeated in every segment, as Linux's TSO repeats them;
            // a backend that cannot copy them refuses the aggregate.
            allow_options: true,
        };
        match self.endpoint.prepare_transmit_group(attempt, limits) {
            Ok(group) => Ok(group),
            // Departure records cannot take this group's segments at once
            // (RACK's interval storage); one at a time they may.
            Err(EndpointError::Connection(ntcp::Error::InvalidArgument)) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
    // One physical attempt of the aggregate `group`, prepared from `slot`'s
    // frame, whose Ethernet header (its next hop resolved) it shares, and
    // whose context and ticket it keeps for a retry while the backend
    // blocks. The frame is built again for each attempt: the group's TCP
    // header and one IP header around the whole aggregate, their checksum
    // fields zero, which the backend fills for every segment it cuts.
    // Some(owner) as for `send`.
    fn send_group(
        &mut self,
        slot: &mut TxSlot,
        context: EgressContext,
        ticket: SubmissionTicket,
        group: ntcp::TransmitGroup,
        report: &mut DriveReport,
    ) -> Result<Option<ntcp::ConnectionId>> {
        let offset = self.config.link.offset();
        let header = if self.config.local_address.is_ipv4() {
            20
        } else {
            40
        };
        let mut request = TcpSegmentationRequest {
            segment_payload_len: 0,
        };
        let (mut ip_len, mut segments) = (0, 0);
        // A stale group is refused by the Host before any backend call.
        if let Some(view) = self.endpoint.transmit_group(group) {
            let tcp = &mut self.aggregate[offset + header..];
            let tcp_len = ntcp::wire::encode(view.packet.ip, view.header, view.options, &[], tcp)
                .map_err(|_| Error::Unsupported("TCP aggregate header"))?;
            tcp[16..18].fill(0);
            tcp[tcp_len..tcp_len + view.payload.len()].copy_from_slice(view.payload);
            ip_len = if view.packet.ip.source.is_ipv4() {
                ntcp_ip::encode(&mut self.aggregate[offset..], view.packet, 0)
            } else {
                ntcp_ip6::encode(&mut self.aggregate[offset..], view.packet)
            }
            .map_err(|e| Error::Host(e.into()))?;
            if view.packet.ip.source.is_ipv4() {
                self.aggregate[offset + 10..offset + 12].fill(0);
            }
            self.aggregate[..offset].copy_from_slice(&slot.bytes[..offset]);
            request.segment_payload_len = view.segment_payload_len;
            segments = view.segment_count;
        }
        let packet = &self.aggregate[offset..offset + ip_len];
        let wire = &self.aggregate[..offset + ip_len];
        let io = &mut self.io;
        let mut failure = None;
        let result =
            self.host
                .submit_group(&mut self.endpoint, self.now, context, group, packet, |_| {
                    match io.transmit_segmented(wire, request) {
                        Ok(TxOutcome::Submitted) => BackendOutcome::Submitted,
                        Ok(TxOutcome::WouldBlock | TxOutcome::Rejected) => {
                            BackendOutcome::WouldBlock
                        }
                        // Both certify that nothing was submitted.
                        Err(
                            TcpSegmentationError::Unsupported | TcpSegmentationError::InvalidInput,
                        ) => BackendOutcome::NotSubmitted,
                        Err(TcpSegmentationError::Other(error)) => {
                            failure = Some(error);
                            BackendOutcome::Unknown
                        }
                    }
                });
        let pending = slot.pending.as_mut().unwrap();
        let owner = pending.owner.ok_or(Error::InvalidHandle)?;
        match result {
            Ok(Submission::Submitted) => {
                slot.pending = None;
                report.transmitted += segments;
                self.counters.segmented += 1;
            }
            Ok(Submission::Blocked(_) | Submission::Rejected(_)) => {
                pending.ticket = Some(ticket);
                report.tx_blocked = true;
                self.counters.backend_backpressure += 1;
            }
            Ok(Submission::PossiblySubmitted) => {
                return Err(Error::Backend(failure.unwrap_or_else(|| {
                    io::Error::other("unknown aggregate submission outcome")
                })));
            }
            // The backend, or the Host for a path that clears DF, cannot
            // send this aggregate: its segments go out one at a time.
            Ok(Submission::Cancelled) | Err(ntcp_host::Error::Unsupported) => {
                self.host.cancel_submission(ticket);
                slot.pending = None;
                self.counters.segmentation_refused += 1;
                if self.endpoint.reject_unsubmitted_group(group)? {
                    return Ok(Some(owner));
                }
                report.more_work = true;
            }
            // The path changed since the group was prepared: polled again,
            // the reservation is cut for the new path.
            Err(
                ntcp_host::Error::Obsolete
                | ntcp_host::Error::Endpoint(EndpointError::ReservationMtuTooSmall),
            ) => {
                self.host.cancel_submission(ticket);
                slot.pending = None;
                self.endpoint.reject_unsubmitted_group(group)?;
                report.more_work = true;
            }
            Err(error) => {
                pending.ticket = Some(ticket);
                return Err(error.into());
            }
        }
        Ok(None)
    }
    // A frame of `owner` left its transmit slot, ending the reservation that
    // kept the connection's events, and its close, from being acted on.
    fn reservation_released(&mut self, owner: Option<ntcp::ConnectionId>) {
        if let Some(slot) = owner.and_then(|core| self.connection_map.get(&core).copied()) {
            self.touch(slot);
        }
    }
    // Carries on the closes and aborts some change may have advanced, then
    // frees the slots of released connections the endpoint has reclaimed.
    fn maintain_connections(&mut self) -> Result<()> {
        let connections = self.connections.len();
        // A close blocked by a reservation is queued again, for the next
        // pass: reservations end within a few drives.
        for _ in 0..self.maintain.len() {
            let index = self.maintain.pop().unwrap();
            if index >= connections {
                let index = index - connections;
                let Some(listener) = self.listeners[index].value.as_ref() else {
                    continue;
                };
                let (core, port) = (listener.core, listener.port);
                match self.endpoint.close_listener(core) {
                    Ok(()) => {
                        self.listener_map.remove(&core);
                        self.listeners[index].value = None;
                        vacate(&mut self.live_listeners, index);
                        give_back(&mut self.free_listeners, &self.listeners, index);
                        self.ports.give(port);
                        if let Some(flows) = &mut self.flows {
                            flows.unlisten(port);
                        }
                    }
                    Err(EndpointError::OutputReserved) => self.maintain.push(connections + index),
                    Err(e) => return Err(e.into()),
                }
                continue;
            }
            let Some(c) = self.connections[index].value.as_ref() else {
                continue;
            };
            let (core, abort, close) = (c.core, c.abort_requested, c.close_requested);
            if c.released || !(abort || close) {
                continue;
            }
            if self.endpoint.is_output_reserved(core) {
                self.maintain.push(index);
            }
            if abort {
                if self.tx_pending != 0 || self.tx_held != 0 {
                    let mut next = 0;
                    while let Some(frame) = next_live(&self.tx_frames, next) {
                        next = frame + 1;
                        let slot = &mut self.tx[frame];
                        if slot.pending.as_ref().is_some_and(|p| p.owner == Some(core)) {
                            let pending = slot.pending.take().unwrap();
                            vacate(&mut self.tx_frames, frame);
                            if pending.held {
                                self.tx_held -= 1;
                            } else {
                                self.tx_pending -= 1;
                            }
                            if let Some(ticket) = pending.ticket {
                                self.host.cancel_submission(ticket);
                            }
                            // An aggregate's reservation, taken back, is
                            // polled again for the attempt to withdraw.
                            let attempt = match pending.group {
                                None => Some(pending.attempt),
                                Some(group) => {
                                    self.endpoint.reject_unsubmitted_group(group)?;
                                    self.endpoint
                                        .poll_reserved_transmit_for(
                                            self.now,
                                            core,
                                            &mut slot.bytes,
                                            1,
                                        )?
                                        .1
                                }
                            };
                            // Every retained frame is certified unsubmitted. The
                            // explicit abort below supersedes its restored work.
                            if let Some(attempt) = attempt {
                                self.endpoint.discard_unsubmitted(self.now, attempt, None)?;
                            }
                        }
                    }
                }
                if !self.endpoint.is_output_reserved(core) {
                    self.endpoint.abort(core)?;
                }
            } else if close
                && !self.endpoint.is_output_reserved(core)
                && !matches!(self.endpoint.state(core)?, State::Closed | State::TimeWait)
            {
                match self.endpoint.close(core) {
                    Ok(()) => {}
                    Err(EndpointError::Connection(ntcp::Error::InvalidState)) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            // Release reads the state its Closed event was derived from:
            // every change to Closed or TIME-WAIT raises an event, whose
            // drain refreshes the connection and queues it here again.
            let c = self.connections[index].value.as_mut().unwrap();
            if matches!(c.state, State::Closed | State::TimeWait)
                && !c.connected_event
                && !c.closed_event
                && c.trace_count == 0
                && !self.endpoint.is_output_reserved(core)
            {
                self.endpoint.release(core)?;
                c.released = true;
                self.releasing.push(index);
            }
        }
        let reclaimed = self.endpoint.reclaimed();
        if reclaimed != self.reclaimed {
            self.reclaimed = reclaimed;
            let mut k = 0;
            while k < self.releasing.len() {
                let index = self.releasing[k];
                let c = self.connections[index].value.as_ref().unwrap();
                let (core, port) = (c.core, c.local.port());
                if self.endpoint.connection_exists(core) {
                    k += 1;
                    continue;
                }
                self.releasing.swap_remove(k);
                self.connection_map.remove(&core);
                self.connections[index].value = None;
                vacate(&mut self.live_connections, index);
                give_back(&mut self.free_connections, &self.connections, index);
                self.ports.give(port);
            }
        }
        Ok(())
    }
}
