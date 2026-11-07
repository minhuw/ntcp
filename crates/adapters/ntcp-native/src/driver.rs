use super::*;
use ntcp_host::{
    BackendOutcome, DeferredIcmp, EgressContext, IcmpDispatch, Processed, ProcessedEnvelope,
    Received, Submission, SubmissionTicket,
};
use ntcp_io::{
    ClockDomain, PacketLayer, PacketTimestamp, ReceivedPacket, TimestampUnit, TxOutcome,
};

pub(super) struct PendingFrame {
    attempt: ntcp::TransmitAttempt,
    owner: Option<ntcp::ConnectionId>,
    context: Option<EgressContext>,
    ticket: Option<SubmissionTicket>,
    ip_len: usize,
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
        for slot in &mut self.connections {
            if let Some(c) = &mut slot.value {
                // Observation cancellation does not certify non-submission.
                let _ = self.endpoint.cancel_tx_timestamps(c.core);
                c.closed_event = true;
                c.connected_event = false;
                c.readable_event = false;
                c.read_waiting = false;
                c.write_waiting = None;
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
                        report.discarded += 1;
                        continue;
                    }
                }
            } else {
                &rx[..packet.len]
            };
            let metadata = self.receive_metadata(packet);
            if self.input(frame, metadata, completed).is_err() {
                report.discarded += 1;
            }
        }
        if receive_work == budget.receive && budget.receive != 0 {
            report.more_work = true;
        }
        if !self.retained.is_empty() {
            report.more_work = true;
        }
        for _ in 0..budget.transmit {
            let index = self.tx_cursor;
            self.tx_cursor = (index + 1) % self.tx.len();
            let mut slot = std::mem::replace(
                &mut self.tx[index],
                TxSlot {
                    bytes: Vec::new(),
                    pending: None,
                },
            );
            let result = self.transmit_slot(&mut slot, report);
            self.tx[index] = slot;
            result?;
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
        report.tx_blocked |= self.tx.iter().any(|s| s.pending.is_some());
        if self.endpoint.has_pending_output() {
            report.more_work = true;
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
    fn input(
        &mut self,
        frame: &[u8],
        metadata: ntcp::RxPacketMetadata,
        completed: &mut [u8],
    ) -> Result<()> {
        let received = self
            .host
            .receive(self.ingress, self.now, frame, false, completed)?;
        let Received::Datagram(datagram) = received else {
            return Ok(());
        };
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
        if packet.protocol == 6 {
            let tcp = ntcp::wire::parse(packet.ip, packet.payload)
                .map_err(|_| Error::Unsupported("malformed TCP packet"))?;
            let tuple = Tuple {
                local: SocketAddr::new(packet.ip.destination, tcp.header.destination_port),
                remote: SocketAddr::new(packet.ip.source, tcp.header.source_port),
            };
            if let Some(owner) = self.endpoint.scoped_connection_id(self.scoped(tuple))
                && self.endpoint.is_output_reserved(owner)
            {
                return self.retain(owner, Some(processed), None, metadata);
            }
        }
        self.host.input_datagram(
            &mut self.endpoint,
            self.now,
            processed,
            metadata,
            self.config.tcp.dscp,
        )?;
        Ok(())
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
    fn transmit_slot(&mut self, slot: &mut TxSlot, report: &mut DriveReport) -> Result<()> {
        let offset = self.config.link.offset();
        if slot.pending.is_none() {
            let header = if self.config.local_address.is_ipv4() {
                20
            } else {
                40
            };
            let (poll, attempt) = match self.endpoint.poll_reserved_transmit(
                self.now,
                &mut slot.bytes[offset + header..],
                1,
            ) {
                Ok(result) => result,
                Err(EndpointError::OutputReserved) => {
                    report.tx_blocked = true;
                    return Ok(());
                }
                Err(e) => return Err(e.into()),
            };
            report.more_work |= poll.more_work;
            let Some(packet) = poll.packet else {
                return Ok(());
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
                next_hop_mac,
            } = self.config.link
            {
                slot.bytes[..6].copy_from_slice(&next_hop_mac);
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
            });
        }
        let pending = slot.pending.as_mut().unwrap();
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
                    return Ok(());
                }
                Err(ntcp_host::Error::Obsolete) => {
                    self.endpoint.reject_unsubmitted(pending.attempt)?;
                    slot.pending = None;
                    report.more_work = true;
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            },
        };
        let ticket = match pending.ticket.take() {
            Some(ticket) => ticket,
            None => self.host.submission_ticket(&mut self.endpoint, context)?,
        };
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
        Ok(())
    }
    fn maintain_connections(&mut self) -> Result<()> {
        for index in 0..self.listeners.len() {
            let Some(listener) = &self.listeners[index].value else {
                continue;
            };
            if listener.closing {
                let core = listener.core;
                match self.endpoint.close_listener(core) {
                    Ok(()) => {
                        self.listener_map.remove(&core);
                        self.listeners[index].value = None;
                    }
                    Err(EndpointError::OutputReserved) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        for index in 0..self.connections.len() {
            let Some(c) = &self.connections[index].value else {
                continue;
            };
            let (core, abort, close, released) =
                (c.core, c.abort_requested, c.close_requested, c.released);
            if released {
                if !self.endpoint.connection_exists(core) {
                    self.connection_map.remove(&core);
                    self.connections[index].value = None;
                }
                continue;
            }
            if abort {
                for slot in &mut self.tx {
                    if slot.pending.as_ref().is_some_and(|p| p.owner == Some(core)) {
                        let pending = slot.pending.take().unwrap();
                        if let Some(ticket) = pending.ticket {
                            self.host.cancel_submission(ticket);
                        }
                        // Every retained frame is certified unsubmitted. The
                        // explicit abort below supersedes its restored work.
                        self.endpoint
                            .discard_unsubmitted(self.now, pending.attempt, None)?;
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
            self.refresh_connection(index);
            let c = self.connections[index].value.as_mut().unwrap();
            if (close || abort)
                && matches!(c.state, State::Closed | State::TimeWait)
                && !c.connected_event
                && !c.closed_event
                && c.trace_count == 0
                && !self.endpoint.is_output_reserved(core)
            {
                self.endpoint.release(core)?;
                c.released = true;
            }
        }
        Ok(())
    }
}
