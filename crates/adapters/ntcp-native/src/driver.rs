use super::*;
use crate::inbox::Handed;
use ntcp::DropReason;
use ntcp::RxFrame;
use ntcp_host::{
    Advice, BackendOutcome, Datagram, DeferredIcmp, EgressContext, IcmpDispatch, NeighborHop,
    NeighborWake, Owner, Processed, ProcessedEnvelope, Received, Submission, SubmissionTicket,
};
use ntcp_io::{
    ClockDomain, PacketLayer, PacketTimestamp, ReceivedPacket, RxChecksum, TcpSegmentationError,
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
    // The segment carries payload: once submitted it is in the device for
    // autocorking (`Network::push`).
    data: bool,
}
pub(super) struct TxSlot {
    pub bytes: Vec<u8>,
    pub pending: Option<PendingFrame>,
}
// A SYN a member takes in itself (`take_syn`): its flow, whether the member
// holds that for its owner, and what a handoff of it carries.
struct Syn {
    local: SocketAddrV4,
    remote: SocketAddrV4,
    held: bool,
    packet: ReceivedPacket,
    reassembled: Option<ntcp_host::Envelope>,
}
pub(super) struct RetainedInput {
    // A receive buffer, holding the datagram's copy unless `frame` holds it.
    bytes: Vec<u8>,
    len: usize,
    // The frame the datagram arrived in, kept in place of a copy, and where
    // the datagram's `len` bytes start in its memory: the frame is trimmed
    // to the TCP segment (`Host::input_datagram_frame`), and trimming
    // releases nothing, so they stay valid while it lives.
    frame: Option<(RxFrame, *const u8)>,
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
    // Stops the network for `cause`, an error no drive can get past, and
    // gives `cause` back for the drive to return; `failure` tells it again.
    #[cold]
    fn stop_with_cause(&mut self, cause: Error) -> Error {
        let _ = self.stop_with_error(io::Error::other(cause.to_string()));
        cause
    }
    pub fn stop(&mut self) {
        if !self.stopped {
            let _ = self.stop_with_error(io::Error::new(
                io::ErrorKind::Interrupted,
                "network stopped by its owner",
            ));
        }
    }
    /// Advances the stack: receives, runs timers and transmits. A Network has
    /// no thread of its own, so protocol work happens only inside the caller's
    /// `drive`, unlike Linux, whose softirq and timers run whatever the
    /// application does. An embedding that busy-polls to keep latency low
    /// therefore pays for every wakeup of another thread sharing its CPU: the
    /// preempted owner stops receiving and acknowledging until it runs again
    /// (for example an application timer thread that wakes once per request).
    ///
    /// Output a write queues leaves in its `push`, Linux's tcp_push at the
    /// end of sendmsg, or in the next drive; every other output (timers,
    /// ACKs of input, other connections') leaves in drives.
    ///
    /// A drive with `budget.receive` 0 receives nothing
    /// (`WorkBudget::receive`): run between a `try_read` and the next
    /// `drain_events`, it adds no arrival to what the read left.
    ///
    /// A drive that reports `more_work` wants another drive before the
    /// embedding sleeps; otherwise the embedding may sleep until
    /// `next_deadline`, which it asks for after its last drive or push,
    /// as it is about to sleep. A drive does not compute it.
    ///
    /// A drive never fails for what passes: a backend without TX room, a
    /// connection's output held for it (its calls take effect meanwhile), an
    /// unresolved or unreachable next hop, a full neighbor or path table,
    /// a peer's Packet Too Big below what a held packet needs (its
    /// connection alone ends, `Aborted`). Each is retried within the
    /// network, on TCP's own clocks. The errors it returns:
    /// - `Stopped`: the network had stopped; nothing was done.
    /// - `TimeWentBackwards`: `now` is before the network's time; nothing
    ///   was done and the network runs on, for a drive with a valid `now`.
    /// - Any other error stops the network first, as `stop` does (every
    ///   connection Closed, then `NetworkStopped`), with `failure` telling
    ///   the cause: `Backend`, the backend's own failure (a receive or
    ///   transmit error, or a submission whose outcome is unknown); a time
    ///   step so large that the TCP timestamp clock cannot tell it from a
    ///   wrap (`Tcp(Connection(AmbiguousTimeJump))`); otherwise a broken
    ///   invariant of the stack, which debug builds assert.
    pub fn drive(&mut self, now: Instant, budget: WorkBudget) -> Result<DriveReport> {
        // A NextPoll device has completed what was submitted before this
        // drive (autocorking, `Network::push`).
        self.tx_epoch += 1;
        // The drive's look at the inbox of a member of shared flows begins
        // before anything that can fail: every handoff from here on wakes
        // the member again, whatever becomes of this drive, so a drive that
        // fails early cannot leave the wake taken and later handoffs
        // silent. What already waits is this drive's to take or report.
        if let Some(inlet) = &self.inlet {
            inlet.begin();
        }
        // After the wake is taken: memory another member returned since
        // wakes this member's waiting writers.
        self.endpoint.poll_shared_memory();
        match self.advance_time(now) {
            Ok(()) => {}
            Err(error @ Error::Tcp(EndpointError::Connection(ntcp::Error::AmbiguousTimeJump))) => {
                return Err(self.stop_with_cause(error));
            }
            Err(error) => return Err(error),
        }
        let mut report = DriveReport::default();
        // Take reusable scratch out of the owner while processed datagrams
        // borrow it. They never survive a call unless copied into the bounded
        // retained-input pool with their exact Host envelope.
        let mut rx = std::mem::take(&mut self.rx);
        let mut completed = std::mem::take(&mut self.completed);
        let discarded = self.drop_total();
        let result = self.drive_inner(now, budget, &mut rx, &mut completed, &mut report);
        report.discarded = (self.drop_total() - discarded) as usize;
        self.rx = rx;
        self.completed = completed;
        self.wake_members_for_memory();
        self.counters.received += report.received as u64;
        self.counters.transmitted += report.transmitted as u64;
        if let Err(error) = result {
            return Err(match error {
                Error::Backend(error) => self.stop_with_error(error),
                // What passes is retried within the drive, so what reaches
                // here is a broken invariant (c151, every site classified).
                other => {
                    if cfg!(debug_assertions) {
                        panic!("drive: broken invariant: {other}");
                    }
                    self.stop_with_cause(other)
                }
            });
        }
        report.events_pending = self.events_pending();
        Ok(report)
    }
    /// Linux's tcp_push for connection `id` alone, at `now`: its output is
    /// selected and handed to the backend until it has nothing selectable
    /// (nothing queued, or what is queued held by the windows, Nagle or
    /// pacing), a frame waits for backend room, its frame waits for its
    /// next hop's resolution, or `PUSH_FRAMES` frames went out
    /// (`PushReport::more`). What one write left past a TSO aggregate, the
    /// rest of a reservation and the segments of an aggregate the backend
    /// refused all leave in the same push. Call it where Linux's sendmsg
    /// ends: after the writes of one application write (one
    /// `try_write_vectored`, or the `try_write`s of one iovec), and after
    /// `set_nodelay(true)` and `shutdown_write`, which Linux pushes inside
    /// the call. What is written and not pushed is sent by the next drive.
    ///
    /// Everything else stays with `drive`: timers (one due now runs in the
    /// next drive, as Linux runs a timer that fired during sendmsg at
    /// release_sock), input, other connections' output and stateless
    /// replies, ARP timers and replies, closes, reclaim and event
    /// collection. A push that finds any frame waiting for backend room
    /// sends nothing (`tx_blocked`): the next drive retries those first, as
    /// a qdisc queues a new skb behind older ones. A connection whose
    /// output is reserved (its own frame waiting for room or for its next
    /// hop) gets nothing sent either, with `tx_blocked`; the drive that
    /// ends the reservation sends what its calls released meanwhile. The
    /// first frame to an unresolved next hop starts its resolution here:
    /// the frame is held, and the request leaves in this push.
    ///
    /// Autocorking (Linux's tcp_should_autocork, `tcp.autocorking`, on by
    /// default): on a backend whose device completes frames later
    /// (`PacketIo::tx_completion` NextPoll or Counter), a push holds the
    /// connection's output while a data frame it submitted earlier is still
    /// in the device, data is in flight, and what waits unsent is less than
    /// the size goal, the device's largest aggregate (`Endpoint::
    /// should_autocork`). The held output stays queued and the next drive
    /// sends it, together with what later writes add, whatever the device's
    /// completion state: so a push that holds sends nothing and reports
    /// `more_work`, and the caller drives before it sleeps. The first push
    /// after `set_nodelay(true)` does not hold, as Linux pushes inside
    /// setsockopt(TCP_NODELAY), nor does one after `shutdown_write`, whose
    /// FIN Linux pushes at once. `Counters::autocorked` counts holds.
    ///
    /// A push can arm timers (its connection's retransmission, loss probe,
    /// persist and pacing; on a link that resolves next hops, its next
    /// hop's: the first use of a STALE entry starts DELAY, as Linux's
    /// neigh_event_send, and resolving a new one schedules its requests).
    /// It does not report them: `next_deadline`, asked after the push,
    /// covers them with every other deadline of the network.
    ///
    /// Errors as `drive`'s: `Stopped`, nothing done; `TimeWentBackwards`,
    /// nothing done and the network runs on; `InvalidHandle` for a
    /// connection released, closed or aborted, nothing done; any other
    /// stops the network first.
    pub fn push(&mut self, id: ConnId, now: Instant) -> Result<PushReport> {
        self.running()?;
        let c = self.conn(id)?;
        if c.close_requested || c.abort_requested || c.released {
            return Err(Error::InvalidHandle);
        }
        let core = c.core;
        match self.advance_time(now) {
            Ok(()) => {}
            Err(error @ Error::Tcp(EndpointError::Connection(ntcp::Error::AmbiguousTimeJump))) => {
                return Err(self.stop_with_cause(error));
            }
            Err(error) => return Err(error),
        }
        let mut report = DriveReport::default();
        let changes = self.host.output_changes_pending();
        let result = match self.autocork(id, core) {
            Ok(Some(held)) => return Ok(held),
            Ok(None) => self.push_inner(core, now, changes, &mut report),
            Err(error) => Err(error),
        };
        self.wake_members_for_memory();
        self.counters.transmitted += report.transmitted as u64;
        let more = match result {
            Ok(more) => more,
            Err(Error::Backend(error)) => return Err(self.stop_with_error(error)),
            Err(other) => {
                if cfg!(debug_assertions) {
                    panic!("push: broken invariant: {other}");
                }
                return Err(self.stop_with_cause(other));
            }
        };
        Ok(PushReport {
            transmitted: report.transmitted,
            tx_blocked: report.tx_blocked || self.tx_pending != 0,
            more,
            more_work: more || self.tx_pending != 0,
        })
    }
    /// The instant by which the network next has work for a drive, for an
    /// embedding about to sleep: the earliest of the endpoint's timers
    /// (its deadline heap and TIME-WAIT wheel, which hold every
    /// connection timer and the retry of a wait for memory, and the pacing
    /// of each reservation not yet attempted), reassembly expiry, the
    /// TIME-WAIT records of flows this member of shared flows holds, and,
    /// on a link that resolves next hops, the neighbor tables' next timer
    /// or queued reply (on a member of a shared table, the table's, or at
    /// once when the member has a wake it has not settled). When a drive
    /// now would transmit, the network's current time instead: output
    /// queued and not sent (writes not pushed, output autocorking held), a
    /// frame waiting for backend room, or input retained while its
    /// connection's output was reserved. None: nothing is due, and only
    /// input, the member's wake or a call can give the network work.
    ///
    /// Ask after the last drive or push, before sleeping: the value holds
    /// until the next input, drive, push or other call on the network (a
    /// write, a connect, a close), and on a member of shared flows or of
    /// a shared neighbor table until another member hands it work, which
    /// wakes it. After a drive that reported no `more_work` it is the
    /// deadline that drive found. It does not replace `more_work`: a drive
    /// that used its whole receive budget, or left ICMP messages for want
    /// of transmit budget, reports `more_work` and wants another drive
    /// whatever this says. It reads the deadlines the network keeps (a
    /// heap's first entry, the wheel's next slot, cached table deadlines)
    /// and walks only the reservations not yet attempted, so it is cheap
    /// enough to ask before every sleep, but not free: an embedding that
    /// busy-polls and never sleeps need not ask. A stopped network has
    /// none.
    pub fn next_deadline(&self) -> Option<Instant> {
        if self.stopped {
            return None;
        }
        if self.work_pending() {
            return Some(self.now);
        }
        self.timer_deadline()
    }
    // Whether a drive at the network's time would have work its state
    // shows: output to poll or a frame to retry (as each drive's end
    // tells it in `more_work`; a frame held for its next hop waits for
    // the resolution's wake, not a poll), or retained input to replay.
    fn work_pending(&self) -> bool {
        !self.retained.is_empty()
            || if self.tx_held == 0 {
                self.endpoint.has_pending_output()
            } else {
                self.tx_pending != 0 || self.endpoint.has_queued_output()
            }
    }
    // Where the backend's transmission stands, for a frame submitted now
    // (`Connection::tx_mark`): the drive epoch for a NextPoll device, the
    // submissions so far, this one's included, for a Counter one.
    fn tx_position(&self) -> u64 {
        match self.tx_completion {
            ntcp_io::TxCompletion::Counter => self.tx_submitted,
            _ => self.tx_epoch,
        }
    }
    // A data frame of `owner` was submitted: it is in the device until the
    // device completes it.
    fn mark_in_device(&mut self, owner: ntcp::ConnectionId) {
        if self.tx_completion == ntcp_io::TxCompletion::Synchronous {
            return;
        }
        let position = self.tx_position();
        if let Some(slot) = self.connection_slot(owner)
            && let Some(c) = self.connections[slot].value.as_mut()
        {
            c.tx_mark = position;
            c.nodelay_push = false;
        }
    }
    // A push of `id` held by autocorking, Linux's tcp_should_autocork: the
    // device still has a data frame of the connection (its sk_wmem_alloc
    // test), and TCP's half holds (`Endpoint::should_autocork`). The hold
    // counts once, until the connection's next data frame is submitted.
    fn autocork(&mut self, id: ConnId, core: ntcp::ConnectionId) -> Result<Option<PushReport>> {
        let completion = self.tx_completion;
        if completion == ntcp_io::TxCompletion::Synchronous {
            return Ok(None);
        }
        let c = self.conn_mut(id)?;
        let nodelay = std::mem::take(&mut c.nodelay_push);
        let mark = c.tx_mark & !HELD;
        let in_device = match completion {
            ntcp_io::TxCompletion::Counter => mark > self.io.tx_submissions_completed(),
            _ => mark == self.tx_epoch,
        };
        if nodelay || !in_device {
            return Ok(None);
        }
        // tcp_xmit_size_goal's GSO size: the aggregate, less the headers
        // (Linux's sk_gso_max_size less MAX_TCP_HEADER).
        let (gso_bytes, gso_segments) = match self.segmentation {
            Some(capabilities) => {
                let ip = if self.config.local_address.is_ipv4() {
                    20
                } else {
                    40
                };
                let headers = self.config.link.offset() + ip + 60;
                (
                    self.aggregate.len().saturating_sub(headers),
                    capabilities.max_segments,
                )
            }
            None => (0, 0),
        };
        if !self
            .endpoint
            .should_autocork(core, gso_bytes, gso_segments)?
        {
            return Ok(None);
        }
        let c = self.conn_mut(id)?;
        if c.tx_mark & HELD == 0 {
            c.tx_mark |= HELD;
            self.counters.autocorked += 1;
        }
        Ok(Some(PushReport {
            transmitted: 0,
            tx_blocked: self.tx_pending != 0,
            more: false,
            more_work: true,
        }))
    }
    // The push's transmit loop for `core`; true when it ended at the frame
    // limit with the connection's output still selectable.
    // `changes`: `Host::output_changes_pending`, as the push began.
    fn push_inner(
        &mut self,
        core: ntcp::ConnectionId,
        now: Instant,
        changes: bool,
        report: &mut DriveReport,
    ) -> Result<bool> {
        self.begin_member();
        // A path change an earlier drive queued reaches the connection
        // before its selection, as in the drive.
        if changes {
            let changes = self.host.service_changes(&mut self.endpoint, now)?;
            if let Some(error) = changes.first_error {
                return Err(error.into());
            }
        }
        let held = self.tx_held;
        let mut frames = 0;
        let mut more = false;
        // Frames waiting for backend room go first, in the drive.
        while self.tx_pending == 0 {
            if frames == PUSH_FRAMES {
                more = self.endpoint.output_selectable(core);
                break;
            }
            // No frame waits for room, so every slot is free but those
            // held for their next hop.
            let index = if self.tx_held == 0 {
                self.tx_cursor
            } else {
                match (0..self.tx.len()).find(|&i| self.tx[i].pending.is_none()) {
                    Some(index) => index,
                    None => break,
                }
            };
            frames += 1;
            let mut tx = std::mem::take(&mut self.tx);
            let slot = &mut tx[index];
            let result = self.push_slot(slot, core, report);
            let waiting = slot.pending.as_ref().map(|p| p.held);
            self.tx = tx;
            if let Some(held) = waiting {
                occupy(&mut self.tx_frames, index);
                if held {
                    self.tx_held += 1;
                } else {
                    self.tx_pending += 1;
                }
            }
            if result? || waiting.is_some() {
                break;
            }
        }
        // The request for a next hop the push began resolving.
        if self.tx_held != held {
            if self.shared_neighbors {
                self.shared_output(now, PUSH_FRAMES, false, report)?;
            } else if !self.control.is_empty() {
                self.control_output(now, PUSH_FRAMES, report)?;
            }
        }
        Ok(more)
    }
    // The start of a drive or a push on a member of a shared neighbor
    // table: the table's mapping epoch, which egress resolution checks its
    // front cache against, and the member's wake. The member begins only
    // when either moved since it last began, which is what beginning it
    // would find (`shared::Probe`); debug builds check the member's epoch
    // when it does not.
    fn begin_member(&mut self) {
        if self.member_probe.as_ref().is_some_and(|p| !p.current())
            && let Some(member) = super::shared::member(&mut self.host)
        {
            member.begin();
            let epoch = member.epoch();
            if let Some(probe) = &mut self.member_probe {
                probe.began(epoch);
            }
        } else if cfg!(debug_assertions)
            && let Some(probe) = &self.member_probe
            && let Some(member) = super::shared::member(&mut self.host)
        {
            debug_assert_eq!(member.epoch(), probe.epoch());
        }
    }
    // One frame of `core`'s output polled into empty `slot` and tried, and
    // the segments polled again, one at a time, of an aggregate the backend
    // refused; true when the connection had nothing to select.
    fn push_slot(
        &mut self,
        slot: &mut TxSlot,
        core: ntcp::ConnectionId,
        report: &mut DriveReport,
    ) -> Result<bool> {
        if self.fill(slot, Some(core), false, report)?.is_some() {
            return Ok(true);
        }
        loop {
            match self.send(slot, report)? {
                Some(owner) => {
                    if self.fill(slot, Some(owner), true, report)?.is_some() {
                        return Ok(true);
                    }
                }
                None => return Ok(false),
            }
        }
    }
    // The earliest instant the network has timed work: the endpoint's
    // timers, reassembly expiry, held TIME-WAIT flows and, on a resolving
    // link, its neighbor timers.
    fn timer_deadline(&self) -> Option<Instant> {
        let deadline = self
            .endpoint
            .next_deadline()
            .into_iter()
            .chain(self.host.next_reassembly_deadline())
            .chain(self.time_wait_flows.next_due())
            .min();
        if !self.control.is_empty()
            && let Some(at) = self.host.next_neighbor_deadline()
        {
            return Some(deadline.map_or(at, |d| d.min(at)));
        }
        deadline
    }
    // Whether drain_events would give anything now: its queues, and the
    // endpoint's events it collects first. When it would not, no live
    // connection or listener holds an event left unqueued (a full scan in
    // debug builds).
    fn events_pending(&self) -> bool {
        let pending = !self.events.is_empty()
            || self.stopped_event
            || !self.ready.is_empty()
            || self.endpoint.has_events();
        if !pending {
            self.check_ready();
        }
        pending
    }
    // Memory this member returned to the group since the last look wakes
    // the members whose writers wait for it: as each drive ends, and as a
    // call outside drive that returned memory ends.
    pub(crate) fn wake_members_for_memory(&mut self) {
        if self.endpoint.take_memory_returned()
            && let Some(flows) = &self.flows
        {
            flows.wake_memory_waiters();
        }
    }
    fn drive_inner(
        &mut self,
        now: Instant,
        budget: WorkBudget,
        rx: &mut [u8],
        completed: &mut [u8],
        report: &mut DriveReport,
    ) -> Result<()> {
        self.begin_member();
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
                match self.host.replay_icmp(&mut self.endpoint, icmp, now) {
                    Ok(IcmpDispatch::Deferred(again)) => {
                        item.icmp = Some(again);
                        self.retained.push_back(item);
                        continue;
                    }
                    Ok(IcmpDispatch::Completed(_)) => {}
                    Err(error) => self.input_failed(&Error::Host(error), &[]),
                }
            } else {
                let (mut held, datagram) = match item.frame.take() {
                    Some((frame, datagram)) => (Some(frame), Some(datagram)),
                    None => (None, None),
                };
                #[allow(unsafe_code)]
                let bytes: &[u8] = match (&held, datagram) {
                    // SAFETY: `datagram` points at `len` bytes of the held
                    // frame's memory (`retain`), which stay valid and
                    // unchanged while it lives: it is dropped only after the
                    // last use of `bytes` below, or held by a receive queue,
                    // which lets it go only in a later input, read or clear.
                    (Some(_), Some(datagram)) => unsafe {
                        core::slice::from_raw_parts(datagram, item.len)
                    },
                    _ => &item.bytes[..item.len],
                };
                if let Some(processed) = item.envelope.and_then(|e| e.datagram(bytes)) {
                    // Its connection went away while it waited.
                    if !self.endpoint.connection_exists(item.owner) {
                        self.drop_ip(DropReason::NoSocket, processed.bytes());
                    } else if let Err(error) =
                        self.input_datagram(processed, item.metadata, &mut held)
                    {
                        self.input_failed(&Error::Host(error), processed.bytes());
                    }
                }
                drop(held);
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
            let (taken, more) = self.take_handoffs(share, completed);
            receive_work += taken;
            handoffs = more;
        }
        while receive_work < budget.receive && !self.receive_free.is_empty() {
            let mut arrival = None;
            let packet = match self.receive_packet(rx, &mut arrival) {
                Ok(Some(packet)) => packet,
                Ok(None) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::InvalidData | io::ErrorKind::Unsupported
                    ) =>
                {
                    self.drop_received(DropReason::DevHdr, &[]);
                    receive_work += 1;
                    continue;
                }
                Err(e) => return Err(Error::Backend(e)),
            };
            receive_work += 1;
            report.received += 1;
            #[allow(unsafe_code)]
            let bytes: &[u8] = match &arrival {
                // SAFETY: an RxFrame's bytes stay valid and unchanged until
                // it is dropped, and neither moving nor trimming it moves or
                // releases them. This one is dropped at the end of this
                // iteration, after the last use of `bytes`; before that it
                // moves only into the Host, which gives it back unless a
                // receive queue holds it (and a queue lets it go only in a
                // later input, read or clear), into `retain`, which keeps it,
                // or into another member's inbox (`hand_off_frame`), after
                // which this iteration reads nothing more. No function this
                // loop calls keeps the slice.
                Some(frame) => unsafe { core::slice::from_raw_parts(frame.as_ptr(), frame.len()) },
                None => {
                    if packet.len > rx.len() {
                        return Err(Error::Backend(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "backend returned an invalid packet length",
                        )));
                    }
                    &rx[..packet.len]
                }
            };
            let frame = if self.io.layer() == PacketLayer::Ethernet {
                match ntcp_ethernet::parse_ethernet_fragment(bytes) {
                    Ok(frame) => {
                        let Link::Ethernet { local_mac, .. } = self.config.link else {
                            unreachable!()
                        };
                        if frame.destination != local_mac {
                            self.drop_received(DropReason::OtherHost, bytes);
                            continue;
                        }
                        frame.payload
                    }
                    Err(error) => {
                        // ARP rides its own EtherType, which the IP parser
                        // refuses.
                        let arp = bytes.get(12..14) == Some(&[0x08, 0x06]);
                        let result = match (arp, self.control.is_empty()) {
                            (true, false) => self.arp_input(bytes),
                            (true, true) => Err(DropReason::ArpInvalid),
                            (false, _) => Err(ntcp_host::ip_drop_reason(error)),
                        };
                        if let Err(reason) = result {
                            self.drop_received(reason, bytes);
                        }
                        continue;
                    }
                }
            } else {
                bytes
            };
            // A member of shared flows hands a packet of another member's
            // flow, or a fragment another member reassembles, to it as it
            // arrived.
            let mut fragment = false;
            let mut syn = None;
            if self.inlet.is_some()
                && let Some(flows) = &self.flows
            {
                let key = flows::key(frame);
                fragment = matches!(key, flows::Key::Fragment { .. });
                let route = flows.elsewhere(key);
                if let Some(owner) = route.to {
                    let handoff = flows::Handoff {
                        timestamps: packet.timestamps,
                        tcp_segment_size: packet.tcp_segment_size,
                        fragment,
                        reassembled: None,
                        syn: matches!(key, flows::Key::Flow { syn: true, .. }),
                        held: route.held,
                    };
                    match arrival.take() {
                        // The frame itself, trimmed to the IP packet.
                        Some(mut moved) => {
                            moved.advance(frame.as_ptr() as usize - moved.as_ptr() as usize);
                            moved.truncate(frame.len());
                            self.hand_off_frame(owner, moved, handoff);
                        }
                        None => self.hand_off(owner, frame, handoff),
                    }
                    continue;
                }
                if let flows::Key::Flow {
                    local,
                    remote,
                    syn: true,
                } = key
                {
                    syn = Some((local, remote, route.held));
                }
            }
            let result = match syn {
                Some((local, remote, held)) => {
                    let syn = Syn {
                        local,
                        remote,
                        held,
                        packet,
                        reassembled: None,
                    };
                    self.take_syn(syn, frame, |network| {
                        network.input(frame, packet, false, completed, &mut arrival)
                    })
                }
                None => self.input(frame, packet, fragment, completed, &mut arrival),
            };
            if let Err(error) = result {
                self.input_failed(&error, frame);
            }
            drop(arrival);
        }
        if handoffs && receive_work < budget.receive {
            let (taken, more) = self.take_handoffs(budget.receive - receive_work, completed);
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
            let woken;
            (control, woken) =
                self.shared_output(now, budget.transmit.div_ceil(2), true, report)?;
            if woken {
                self.settle_member(now)?;
            }
        } else if !self.control.is_empty() {
            self.service_neighbors(now)?;
            control = self.control_output(now, budget.transmit.div_ceil(2), report)?;
        }
        // The Host's ICMP messages, queued by this drive's input or by
        // reassembly expiry, take at most half of what is left, so that
        // neither they nor data starve the other.
        // Only messages this pass leaves behind are sent after data:
        // nothing in between queues one.
        let mut icmp_left = false;
        if self.icmp_due() {
            control += self.drain_icmp_output(
                now,
                (budget.transmit - control).div_ceil(2),
                false,
                report,
            )?;
            icmp_left = self.host.icmp_output_pending() != 0;
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
            // An endpoint with nothing pending (every reservation free, so no
            // slot holds a frame; no output queued, no stateless reply, no
            // listener cleanup) gives a poll at its clock, `now`, nothing to
            // select or change, and no more work to report: the loop ends as
            // after such a poll.
            if !self.endpoint.has_pending_output() {
                debug_assert!(self.tx_pending == 0 && self.tx_held == 0);
                exhausted = true;
                continue;
            }
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
            // Rotate among outstanding frames for retry fairness. With every
            // slot free, reuse the hot frame buffer until a send blocks.
            if self.tx_pending != 0 || self.tx_held != 0 {
                self.tx_cursor = if index + 1 == self.tx.len() {
                    0
                } else {
                    index + 1
                };
            }
            // A settled retry may release output, so poll again after it.
            let idle = result?;
            exhausted = idle || exhausted && was_pending && still_pending;
        }
        // ICMP messages within what data left, then requests for next hops
        // data or ICMP output just began resolving, within what is left.
        if icmp_left {
            control +=
                self.drain_icmp_output(now, budget.transmit - control - data, true, report)?;
        }
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
        // `next_deadline` is the deadline drives reported until it was
        // asked for instead (`timer_deadline`, which this drive found)
        // whenever the drive reports no more work: work it would report
        // at once is more work. The deadline of a member of a shared
        // neighbor table can move meanwhile (another member's wake).
        if cfg!(debug_assertions) && !report.more_work {
            debug_assert!(!self.work_pending());
            if !self.shared_neighbors {
                debug_assert_eq!(self.next_deadline(), self.timer_deadline());
            }
        }
        Ok(())
    }
    // An ARP frame addressed to this port or to broadcast, for the Host's
    // ARP; frames to other stations are not this port's to learn from.
    fn arp_input(&mut self, bytes: &[u8]) -> core::result::Result<(), DropReason> {
        let Link::Ethernet { local_mac, .. } = self.config.link else {
            return Err(DropReason::UnhandledProto);
        };
        let frame = ntcp_ethernet::parse_ethernet_arp(bytes).map_err(|_| DropReason::ArpInvalid)?;
        if frame.destination != local_mac && frame.destination != ntcp_ethernet::BROADCAST {
            return Err(DropReason::OtherHost);
        }
        self.counters.arp_received += 1;
        let taken = self
            .host
            .receive_arp(self.ingress, self.now, frame.payload)
            .is_ok();
        self.arp_input |= taken;
        if taken {
            Ok(())
        } else {
            Err(DropReason::ArpInvalid)
        }
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
    // tried, and whether the member has wakes to settle (`settle_member`),
    // read through the same lookup of the member. A member that finds the
    // table held skips it: the holder is doing the work, or the next drive
    // of any member will.
    #[inline]
    fn shared_output(
        &mut self,
        now: Instant,
        limit: usize,
        timers: bool,
        report: &mut DriveReport,
    ) -> Result<(usize, bool)> {
        // Nothing due on the table: no frame to try, only the member's time
        // to move and its wake to read, which its probe does without the
        // Host.
        if let Some(woken) = self.member_probe.as_ref().and_then(|p| p.idle(now)) {
            return Ok((0, woken));
        }
        self.shared_housekeeping(now, limit, timers, report)
    }

    #[inline(never)]
    fn shared_housekeeping(
        &mut self,
        now: Instant,
        limit: usize,
        timers: bool,
        report: &mut DriveReport,
    ) -> Result<(usize, bool)> {
        let Self {
            host,
            io,
            control,
            counters,
            tx_submitted,
            ..
        } = self;
        let Some(member) = super::shared::member(host) else {
            return Ok((0, false));
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
        *tx_submitted += sent as u64;
        if blocked {
            report.tx_blocked = true;
            counters.backend_backpressure += 1;
        }
        if let Some(error) = failure {
            return Err(Error::Backend(error));
        }
        Ok((used.unwrap_or(0), member.woken()))
    }
    // A woken member's wakes: the neighbors the port lost are reported to
    // its Host, and its held frames whose resolution ended are released.
    fn settle_member(&mut self, now: Instant) -> Result<()> {
        self.host.service_neighbors(now);
        self.release_resolved()?;
        if let Some(member) = super::shared::member(&mut self.host) {
            member.settled();
        }
        Ok(())
    }
    // Whether the Host's ICMP output has work: messages queued, or storage
    // charged other than it holds. On every drive of a TCP-only network it
    // has none, and this is two loads and compares, inline.
    #[inline(always)]
    fn icmp_due(&self) -> bool {
        self.host.icmp_output_pending() != 0 || self.host.icmp_memory() != self.icmp_charge
    }
    // Up to `limit` of the Host's queued ICMP messages, each through the
    // backend as one frame per packet (a message beyond the path's size is
    // fragmented by the Host); returns how many messages were tried. A
    // message the backend has no room for stays queued for the next drive;
    // one with no route or path left, or refused, is consumed unsent and
    // counted by the Host. In the drive's `last` pass, messages left for
    // want of budget are more work. Then the Host's ICMP storage is charged
    // again, as it changed with this drive's input and output.
    #[inline(never)]
    fn drain_icmp_output(
        &mut self,
        now: Instant,
        limit: usize,
        last: bool,
        report: &mut DriveReport,
    ) -> Result<usize> {
        let mut used = 0;
        while used < limit && self.host.icmp_output_pending() != 0 {
            used += 1;
            let Self {
                host,
                io,
                config,
                icmp_packet,
                icmp_frame,
                ..
            } = self;
            let (mut sent, mut blocked, mut failure) = (0, false, None);
            let result = host.icmp_output(now, icmp_packet, |egress, packet| {
                // An Ethernet frame is padded to its 60-octet minimum.
                let len = match config.link {
                    Link::Ip => packet.len(),
                    Link::Ethernet { .. } => (14 + packet.len()).max(60),
                };
                let Some(frame) = icmp_frame.get_mut(..len) else {
                    return BackendOutcome::NotSubmitted;
                };
                let frame = if let Link::Ethernet {
                    local_mac,
                    next_hop,
                } = config.link
                {
                    // An ARP-resolved next hop's MAC, which the Host
                    // resolved before submitting, or the fixed one.
                    let destination = match (egress.link_layer, next_hop) {
                        (Some(mac), _) | (None, EthernetNextHop::Fixed(mac)) => mac,
                        (None, EthernetNextHop::Arp { .. }) => {
                            return BackendOutcome::NotSubmitted;
                        }
                    };
                    frame[..6].copy_from_slice(&destination);
                    frame[6..12].copy_from_slice(&local_mac);
                    let ethertype: u16 = if packet[0] >> 4 == 4 { 0x0800 } else { 0x86dd };
                    frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
                    frame[14..14 + packet.len()].copy_from_slice(packet);
                    frame[14 + packet.len()..].fill(0);
                    &*frame
                } else {
                    frame.copy_from_slice(packet);
                    &*frame
                };
                match io.transmit(frame) {
                    Ok(TxOutcome::Submitted) => {
                        sent += 1;
                        BackendOutcome::Submitted
                    }
                    Ok(TxOutcome::WouldBlock | TxOutcome::Rejected) => {
                        blocked = true;
                        BackendOutcome::WouldBlock
                    }
                    Err(error) => {
                        failure = Some(error);
                        BackendOutcome::Unknown
                    }
                }
            });
            report.transmitted += sent;
            self.tx_submitted += sent as u64;
            if let Some(error) = failure {
                return Err(Error::Backend(error));
            }
            if blocked {
                report.tx_blocked = true;
                self.counters.backend_backpressure += 1;
                break;
            }
            // Every queued message waits for its next hop's resolution,
            // which ARP's wake brings to a later drive. Otherwise it was
            // sent, or consumed unsent (counted by the Host).
            if let Ok(None | Some(BackendOutcome::WouldBlock)) = result {
                break;
            }
        }
        if last && used == limit && self.host.icmp_output_pending() != 0 {
            report.more_work = true;
        }
        let charge = self.host.icmp_memory();
        if charge != self.icmp_charge {
            self.icmp_charge = charge;
            self.endpoint.set_embedding_charge(charge);
        }
        Ok(used)
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
        // The tables' next deadline is the earliest time `neighbor_output`
        // has work: a reply queued, or a request or probe due. Reading it
        // costs less than polling them for nothing, which is what every
        // drive finds on a resolved link.
        if self.host.next_neighbor_deadline().is_none_or(|at| at > now) {
            return Ok(0);
        }
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
                    self.tx_submitted += 1;
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
    // Endpoint records the Address Unreachable advice as the connection's
    // soft error, accounts a fresh data segment as sent and lost (Linux's
    // neighbour queue drop, NEIGH_FAILED), for TLP, RACK or the RTO to
    // repair, and withdraws other retransmittable output without a
    // departure, retried on its own clock no earlier than the RTO
    // (`Endpoint::discard_unsubmitted`).
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
                    self.endpoint.discard_unsubmitted(
                        self.now,
                        attempt,
                        error,
                        DropReason::NeighFailed,
                    )?;
                }
            }
        }
        Ok(())
    }
    fn receive_metadata(&mut self, packet: ReceivedPacket) -> ntcp::RxPacketMetadata {
        // Only the device's Good is trusted (Linux's CHECKSUM_UNNECESSARY);
        // Bad and Unknown are verified in software. The Host takes it back
        // from a datagram that is not the packet as it arrived.
        let tcp_checksum_verified = packet.l4_checksum == RxChecksum::Good;
        if self.config.rx_timestamp_ranges == 0 {
            return ntcp::RxPacketMetadata {
                tcp_segment_size: packet.tcp_segment_size,
                tcp_checksum_verified,
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
            tcp_checksum_verified,
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
    // The next received packet, and in `arrival` the frame it is in on a
    // backend whose frames are held by reference (`PacketIo::
    // rx_frame_budget`); a copying backend's receive is called as it was,
    // with nothing else on its path.
    #[inline]
    fn receive_packet(
        &mut self,
        rx: &mut [u8],
        arrival: &mut Option<RxFrame>,
    ) -> io::Result<Option<ReceivedPacket>> {
        match self.frame_threshold {
            None => self.io.receive_with_metadata(rx),
            Some(threshold) => self.receive_held(rx, threshold, arrival),
        }
    }
    // The next received frame of a backend whose frames are held by
    // reference: its own frame while fewer than ¾ of its budget
    // (`threshold`) are out, a heap copy past that, so that a reader that
    // stops cannot take the pool the device receives into (Linux's
    // page_pool falls back to the page allocator).
    fn receive_held(
        &mut self,
        rx: &mut [u8],
        threshold: usize,
        arrival: &mut Option<RxFrame>,
    ) -> io::Result<Option<ReceivedPacket>> {
        // Matched in place: `?` would first move the whole result (the
        // metadata is over 128 bytes, so a memcpy call), on every receive,
        // the empty ones included. The frame is put in `arrival` itself.
        let metadata = match self.io.receive_frame(rx, arrival) {
            Ok(Some(metadata)) => metadata,
            Ok(None) => return Ok(None),
            Err(error) => return Err(error),
        };
        let Some(frame) = arrival else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "backend returned no frame",
            ));
        };
        // The backend copied it already (a scatter chain, an attached
        // external buffer), or the budget is spent. Then the connections'
        // backend frames are copied into heap frames until half the budget
        // is out (`Endpoint::collapse_device_frames`), so that readers that
        // stop do not keep every later arrival from being held; what it
        // cannot bring below ¾ is copied on arrival.
        // The count is read only once the frames received since its last
        // read could have taken it past ¾: each receive hands out at most
        // one frame (`PacketIo::rx_frames_outstanding`), so until then it
        // is known to be within.
        if frame.is_heap() {
            self.counters.rx_frames_copied += 1;
        } else if self.frame_slack != 0 {
            self.frame_slack -= 1;
        } else if let Some(mut out) = self.io.rx_frames_outstanding() {
            if out > threshold {
                let collapsed = self
                    .endpoint
                    .collapse_device_frames(out - self.frame_target);
                self.counters.rx_frames_collapsed += collapsed as u64;
                out = self.io.rx_frames_outstanding().unwrap_or(0);
                if out > threshold {
                    *frame = RxFrame::copy_from_slice(frame);
                    self.counters.rx_frames_copied += 1;
                }
            }
            self.frame_slack = threshold.saturating_sub(out);
        }
        Ok(Some(metadata))
    }
    // `fragment`: a member of shared flows keyed the packet as a fragment.
    // `held`: the frame `frame` lies in, if the backend handed one over.
    fn input(
        &mut self,
        frame: &[u8],
        packet: ReceivedPacket,
        fragment: bool,
        completed: &mut [u8],
        held: &mut Option<RxFrame>,
    ) -> Result<()> {
        let metadata = self.receive_metadata(packet);
        if !fragment {
            if let Some(processed) = self.host.receive_processed(
                self.ingress,
                self.now,
                frame,
                false,
                completed,
                None,
            )? {
                self.dispatch_processed(processed, metadata, held)?;
            }
            return Ok(());
        }
        let received = self
            .host
            .receive(self.ingress, self.now, frame, false, completed)?;
        let Received::Datagram(datagram) = received else {
            return Ok(());
        };
        // A member of shared flows that completes a datagram on a fragment
        // hands it to the member that owns its flow. Its fragments were
        // keyed by their addresses alone; it is keyed once, here.
        if let Some(flows) = &self.flows {
            let key = flows::key(datagram.bytes());
            let route = flows.elsewhere(key);
            if let Some(owner) = route.to {
                let handoff = flows::Handoff {
                    timestamps: packet.timestamps,
                    tcp_segment_size: packet.tcp_segment_size,
                    fragment: false,
                    reassembled: Some(datagram.envelope()),
                    syn: matches!(key, flows::Key::Flow { syn: true, .. }),
                    held: route.held,
                };
                self.hand_off(owner, datagram.bytes(), handoff);
                return Ok(());
            }
            if let flows::Key::Flow {
                local,
                remote,
                syn: true,
            } = key
            {
                let syn = Syn {
                    local,
                    remote,
                    held: route.held,
                    packet,
                    reassembled: Some(datagram.envelope()),
                };
                return self.take_syn(syn, datagram.bytes(), |network| {
                    network.dispatch(datagram, metadata, held)
                });
            }
        }
        self.dispatch(datagram, metadata, held)
    }
    // A SYN of a flow this member takes in, `bytes` as it arrived (or the
    // datagram reassembled), which `take` takes in. A member of shared flows hands one it
    // owns, whose port it does not listen on while another member does, to
    // a listening member (`Member::redirect`) unless it has a connection
    // for it, which then takes it as any segment of its own: Linux's
    // reuseport group gives a SYN only to a socket that listens, and its
    // established table goes first. The member that takes a SYN of a flow
    // it holds for its owner keeps track of a connection it opens, so that
    // the flow is its owner's again once the connection is reclaimed, or at
    // once if none opened (`maintain_connections`).
    fn take_syn(
        &mut self,
        syn: Syn,
        bytes: &[u8],
        take: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<()> {
        let Syn { local, remote, .. } = syn;
        let flows = self.flows.as_ref().expect("a member of shared flows");
        if !syn.held && !flows.unheard(local.port()) {
            return take(self);
        }
        let tuple = self.scoped(Tuple {
            local: local.into(),
            remote: remote.into(),
        });
        if !syn.held {
            if self.endpoint.scoped_connection_id(tuple).is_some() {
                return take(self);
            }
            return match flows.redirect(local, remote) {
                flows::Redirect::To(member) => {
                    let handoff = flows::Handoff {
                        timestamps: syn.packet.timestamps,
                        tcp_segment_size: syn.packet.tcp_segment_size,
                        fragment: false,
                        reassembled: syn.reassembled,
                        syn: true,
                        held: true,
                    };
                    self.counters.redirected += 1;
                    self.hand_off(member, bytes, handoff);
                    Ok(())
                }
                flows::Redirect::Full => {
                    self.counters.redirects_dropped += 1;
                    self.drop_ip(DropReason::RedirectTableFull, bytes);
                    self.rx_recorded = true;
                    Err(Error::Capacity)
                }
                flows::Redirect::Nobody => take(self),
            };
        }
        let before = self.endpoint.scoped_connection_id(tuple);
        let result = take(self);
        let after = self.endpoint.scoped_connection_id(tuple);
        let flows = self.flows.as_ref().expect("a member of shared flows");
        // A flow a TIME-WAIT record holds stays the record's until it is
        // due, when a connection that reopened the tuple takes it over
        // (`maintain_time_wait_flows`).
        if let Some(held) = flows.held(local, remote)
            && !self.time_wait_flows.holds(held)
        {
            match (before, after) {
                (None, Some(core)) => self.hold(core, held),
                // A TIME-WAIT connection not yet released gave its tuple to
                // the one this SYN reopened, which holds the flow now.
                (Some(old), Some(core)) if old != core => {
                    if let Some(entry) = self.held_flows.get_mut(old.index())
                        && entry.is_some_and(|(id, _)| id == old)
                    {
                        *entry = None;
                        self.holding -= 1;
                    }
                    self.hold(core, held);
                }
                (None, None) => flows.release(held),
                _ => {}
            }
        }
        result
    }
    // Connection `core` of the endpoint holds `held`, until it is reclaimed.
    fn hold(&mut self, core: ntcp::ConnectionId, held: flows::Held) {
        // An earlier connection of the endpoint's slot, reclaimed in this
        // drive, is not yet looked at: unless `core` reopened its tuple and
        // holds its flow now.
        match self.held_flows[core.index()].replace((core, held)) {
            Some((_, earlier)) if earlier != held => self.reclaimed_flow(earlier),
            Some(_) => {}
            None => self.holding += 1,
        }
    }
    // The flow a reclaimed connection held is its owner's again, unless the
    // connection left a TIME-WAIT record, which holds it while it lasts, so
    // that the flow's later segments still reach it: Linux's timewait socket
    // takes its connection's place in the established hash
    // (inet_twsk_hashdance), and answers the retransmitted FIN its final
    // ACK was lost for. Without room to note it, the record is left to
    // segments that reach this member, as when TIME-WAIT overflows.
    fn reclaimed_flow(&mut self, held: flows::Held) {
        let tuple = self.held_tuple(held);
        if !self
            .time_wait_flows
            .reclaimed(&self.endpoint, self.now, tuple, held)
        {
            self.flows.as_ref().unwrap().release(held);
        }
    }
    fn held_tuple(&self, held: flows::Held) -> ntcp::ScopedTuple {
        let (local, remote) = self.flows.as_ref().unwrap().tuple(held);
        self.scoped(Tuple {
            local: local.into(),
            remote: remote.into(),
        })
    }
    // The flows of TIME-WAIT records that are due. One whose record's timer
    // restarted is due again at the new deadline; one whose tuple a
    // connection reopened is that connection's; any other, its record over
    // (expired, or ended by a RST), is its owner's again.
    fn maintain_time_wait_flows(&mut self) {
        while let Some(due) = self.time_wait_flows.next_due()
            && due <= self.now
        {
            let Reverse((_, key)) = self.time_wait_flows.due.pop().unwrap();
            let held = self.time_wait_flows.held[&key];
            let tuple = self.held_tuple(held);
            if let Some(deadline) = self.endpoint.time_wait_deadline(tuple)
                && deadline > self.now
            {
                self.time_wait_flows.due.push(Reverse((deadline, key)));
                continue;
            }
            self.time_wait_flows.held.remove(&key);
            match self.endpoint.scoped_connection_id(tuple) {
                Some(core) => self.hold(core, held),
                None => self.flows.as_ref().unwrap().release(held),
            }
        }
    }
    // A packet another member of shared flows handed over, taken in as one
    // this queue received: as it arrived, through `input` (a fragment is
    // reassembled here), or as the datagram the sender reassembled, which
    // the Host adopts and processes as if it had reassembled it. Only a
    // datagram completed here is keyed again.
    // `held`: the frame `bytes` lies in, when the sender moved it in.
    fn take_handoff(
        &mut self,
        bytes: &[u8],
        handoff: flows::Handoff,
        completed: &mut [u8],
        held: &mut Option<RxFrame>,
    ) -> Result<()> {
        // The device's checksum verdict stays with the queue that received
        // the packet: what it hands over is verified here in software.
        let packet = ReceivedPacket {
            len: bytes.len(),
            timestamps: handoff.timestamps,
            tcp_segment_size: handoff.tcp_segment_size,
            l4_checksum: RxChecksum::Unknown,
        };
        let syn = match handoff.syn.then(|| flows::key(bytes)) {
            Some(flows::Key::Flow { local, remote, .. }) => Some((local, remote)),
            _ => None,
        };
        let syn = syn.map(|(local, remote)| Syn {
            local,
            remote,
            held: handoff.held,
            packet,
            reassembled: handoff.reassembled,
        });
        let Some(envelope) = handoff.reassembled else {
            return match syn {
                Some(syn) => self.take_syn(syn, bytes, |network| {
                    network.input(bytes, packet, false, completed, held)
                }),
                None => self.input(bytes, packet, handoff.fragment, completed, held),
            };
        };
        let metadata = self.receive_metadata(packet);
        let datagram = envelope.datagram(bytes).ok_or(Error::Unsupported(
            "a handed-over datagram of another length",
        ))?;
        let datagram = self.host.adopt_datagram(self.ingress, datagram)?;
        match syn {
            Some(syn) => self.take_syn(syn, bytes, |network| {
                network.dispatch(datagram, metadata, held)
            }),
            None => self.dispatch(datagram, metadata, held),
        }
    }
    // Up to `limit` packets from this member's inbox, no more than there are
    // receive buffers free to retain them; returns how many it took, and
    // whether that was all it could take (none, without a buffer), so that
    // more may wait. A drain that stops short found the inbox empty, or
    // its next packet still being copied in, whose handoff wakes the
    // member then.
    fn take_handoffs(&mut self, limit: usize, completed: &mut [u8]) -> (usize, bool) {
        let Some(inlet) = self.inlet.take() else {
            return (0, false);
        };
        let limit = limit.min(self.receive_free.len());
        let taken = inlet.drain(limit, |packet, handoff| match packet {
            Handed::Bytes(packet) => {
                if let Err(error) = self.take_handoff(packet, handoff, completed, &mut None) {
                    self.input_failed(&error, packet);
                }
            }
            Handed::Frame(frame) => {
                let mut held = Some(frame);
                // SAFETY: as for a frame received here (`drive_inner`): the
                // frame is dropped after the last use of `bytes`, or held
                // by a receive queue or `retain`.
                #[allow(unsafe_code)]
                let packet = unsafe {
                    let frame = held.as_ref().unwrap();
                    core::slice::from_raw_parts(frame.as_ptr(), frame.len())
                };
                if let Err(error) = self.take_handoff(packet, handoff, completed, &mut held) {
                    self.input_failed(&error, packet);
                }
                drop(held);
            }
        });
        self.inlet = Some(inlet);
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
            self.drop_ip(DropReason::CpuBacklog, packet);
        }
    }
    // Moves a received frame, trimmed to its IP packet, into member
    // `owner`'s inbox, counted either way. It takes no slice of the frame:
    // once in the inbox, the owner may release it at any time.
    fn hand_off_frame(&mut self, owner: usize, frame: RxFrame, handoff: flows::Handoff) {
        let flows = self.flows.as_ref().expect("a member of shared flows");
        match flows.hand_off_frame(owner, frame, handoff) {
            Ok(()) => self.counters.handed_off += 1,
            Err(frame) => {
                self.counters.handoffs_dropped += 1;
                self.drop_ip(DropReason::CpuBacklog, &frame);
            }
        }
    }
    // Every discard this Network recorded.
    fn drop_total(&self) -> u64 {
        self.endpoint.drops().total() + self.host.drops().total() + self.drops.total()
    }
    // Record the discard of a received frame as the backend delivered it.
    #[cold]
    #[inline(never)]
    fn drop_received(&mut self, reason: DropReason, frame: &[u8]) {
        let ethernet = self.io.layer() == PacketLayer::Ethernet;
        self.drops.record(reason, self.now, frame.len(), || {
            if ethernet {
                ntcp::DropSubject::of_ethernet_frame(frame)
            } else {
                ntcp::DropSubject::of_ip_packet(frame)
            }
        });
    }
    // Record the discard of IP packet `packet`.
    #[cold]
    #[inline(never)]
    fn drop_ip(&mut self, reason: DropReason, packet: &[u8]) {
        self.drops.record(reason, self.now, packet.len(), || {
            ntcp::DropSubject::of_ip_packet(packet)
        });
    }
    // A received IP packet whose input failed with `error`: recorded with the
    // reason the error stands for, unless the layer that refused it recorded
    // it already.
    #[cold]
    #[inline(never)]
    fn input_failed(&mut self, error: &Error, packet: &[u8]) {
        let recorded = core::mem::take(&mut self.rx_recorded)
            | self.endpoint.drops_mut().take_error_recorded()
            | self.host.drops_mut().take_error_recorded();
        if recorded {
            return;
        }
        let icmp = match packet.first().map(|b| b >> 4) {
            Some(4) => packet.get(9) == Some(&1),
            Some(6) => packet.get(6) == Some(&58),
            _ => false,
        };
        let reason = match error {
            Error::Host(error) if icmp => ntcp_host::icmp_drop_reason(error),
            Error::Host(error) => ntcp_host::drop_reason(error),
            Error::Tcp(_) => DropReason::InvalidMetadata,
            Error::Capacity => DropReason::SocketBacklog,
            Error::Unsupported(_) => DropReason::UnhandledProto,
            _ => DropReason::NotSpecified,
        };
        self.drop_ip(reason, packet);
    }
    // Destination processing and dispatch of one complete datagram. `held`:
    // the frame it arrived in, if the backend handed one over.
    fn dispatch(
        &mut self,
        datagram: Datagram<'_>,
        metadata: ntcp::RxPacketMetadata,
        held: &mut Option<RxFrame>,
    ) -> Result<()> {
        let processed = self.host.process(datagram, None)?;
        self.dispatch_processed(processed, metadata, held)
    }

    fn dispatch_processed(
        &mut self,
        processed: Processed<'_>,
        metadata: ntcp::RxPacketMetadata,
        held: &mut Option<RxFrame>,
    ) -> Result<()> {
        // `process` found the destination owned on the Host's one link,
        // which is what `decode_datagram` would check again.
        debug_assert!(self.host.decode_datagram(processed).is_ok());
        let packet = processed.packet();
        if packet.protocol == 1 || packet.protocol == 58 {
            if let IcmpDispatch::Deferred(icmp) =
                self.host
                    .input_icmp_datagram(&mut self.endpoint, self.now, processed)?
            {
                self.retain(icmp.owner(), None, Some(icmp), metadata, &mut None)?;
            }
            return Ok(());
        }
        match self.input_datagram(processed, metadata, held) {
            // Not taken in (malformed, or refused by the endpoint): the
            // Endpoint or Host recorded why.
            Ok(ntcp::InputDisposition::Processed | ntcp::InputDisposition::Dropped) => Ok(()),
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
                self.retain(owner, Some(processed), None, metadata, held)
            }
            Err(error) => Err(error.into()),
        }
    }
    // The Host's input of a processed datagram, from `held`, the frame it
    // arrived in, when there is one (which comes back unless a receive
    // queue holds it).
    fn input_datagram(
        &mut self,
        processed: Processed<'_>,
        metadata: ntcp::RxPacketMetadata,
        held: &mut Option<RxFrame>,
    ) -> core::result::Result<ntcp::InputDisposition, ntcp_host::Error> {
        self.host.input_datagram_frame(
            &mut self.endpoint,
            self.now,
            processed,
            held,
            metadata,
            self.config.tcp.dscp,
        )
    }
    // Keeps a datagram whose connection's output is reserved, or a deferred
    // ICMP message, for a retry. The datagram stays in `held`, the frame it
    // arrived in, when it lies there; otherwise it is copied into a receive
    // buffer, which bounds what is retained either way.
    fn retain(
        &mut self,
        owner: ntcp::ConnectionId,
        processed: Option<Processed<'_>>,
        icmp: Option<DeferredIcmp>,
        metadata: ntcp::RxPacketMetadata,
        held: &mut Option<RxFrame>,
    ) -> Result<()> {
        let mut bytes = self.receive_free.pop().ok_or(Error::Capacity)?;
        let mut len = 0;
        let mut frame = None;
        if let Some(processed) = processed {
            let datagram = processed.bytes();
            len = datagram.len();
            // The frame Host gave back is the datagram's TCP segment or a
            // part of it: the datagram lies in that frame's memory.
            let start = datagram.as_ptr() as usize;
            if let Some(held) = held.take_if(|held| {
                let at = held.as_ptr() as usize;
                start <= at && at + held.len() <= start + len
            }) {
                frame = Some((held, datagram.as_ptr()));
            } else {
                if len > bytes.len() {
                    self.receive_free.push(bytes);
                    return Err(Error::Capacity);
                }
                bytes[..len].copy_from_slice(datagram);
            }
        }
        self.retained.push_back(RetainedInput {
            bytes,
            len,
            frame,
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
            && let Some(idle) = self.fill(slot, None, false, report)?
        {
            return Ok(idle);
        }
        loop {
            match self.send(slot, report)? {
                // The backend refused the aggregate, which the endpoint
                // took back: its first segment goes out alone, in this turn.
                Some(owner) => {
                    if let Some(idle) = self.fill(slot, Some(owner), true, report)? {
                        return Ok(idle);
                    }
                }
                None => return Ok(false),
            }
        }
    }
    // Polls the endpoint's next packet into empty `slot`, or that of
    // `owner`'s reservation; Some ends the slot's turn, Some(true) when the
    // endpoint has nothing left to offer. `scalar`: the packet goes out
    // alone, never prepared as an aggregate (a re-poll after the backend
    // refused one).
    fn fill(
        &mut self,
        slot: &mut TxSlot,
        owner: Option<ntcp::ConnectionId>,
        scalar: bool,
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
            let polled = self.endpoint.poll_transmit_attempt(self.now, out, 1, owner);
            let (more_work, attempt) = match polled {
                Ok(result) => result,
                Err(EndpointError::OutputReserved) => {
                    report.tx_blocked = true;
                    return Ok(Some(true));
                }
                // A held packet that cannot be cut for its path's budget,
                // which a Packet Too Big lowered: the poll failed its owner
                // alone, whose Closed event the drive collects.
                Err(EndpointError::ReservationMtuTooSmall) => {
                    report.more_work = true;
                    return Ok(Some(false));
                }
                Err(e) => return Err(e.into()),
            };
            // Held frames' reservations are not output to poll for. On a
            // resolving link the poll's view, taken before its packet may
            // be held, is left to the drive's final account.
            let more_work = if self.tx_held == 0 {
                more_work
            } else {
                self.tx_pending != 0 || self.endpoint.has_queued_output()
            };
            if attempt.is_none() || self.control.is_empty() {
                report.more_work |= more_work;
            }
            let Some(attempt) = attempt else {
                return Ok(Some(owner.is_none() && !more_work));
            };
            let packet = self
                .endpoint
                .transmit_attempt_packet_ref(attempt)
                .ok_or(Error::InvalidHandle)?;
            // Read before the IP header is written around the segment.
            let data = packet.len > usize::from(out[12] >> 4) * 4;
            let ip_len = if packet.ip.source.is_ipv4() {
                ntcp_ip::encode(&mut slot.bytes[offset..], *packet, 0)
            } else {
                ntcp_ip6::encode(&mut slot.bytes[offset..], *packet)
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
                scalar,
                data,
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
                // No path lease is free for a stateless reply's destination
                // (a full path table, `Path(Capacity)` as the Host's own
                // Capacity): it waits, as for TX room.
                Err(
                    ntcp_host::Error::Capacity
                    | ntcp_host::Error::Allocation
                    | ntcp_host::Error::Path(path::Error::Capacity),
                ) => {
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
                // No neighbor entry or held record is free, or none could
                // be allocated: the attempt is withdrawn unsubmitted,
                // retried on TCP's own clock.
                Err(ntcp_host::Error::Capacity | ntcp_host::Error::Allocation) => {
                    self.endpoint.discard_unsubmitted(
                        self.now,
                        pending.attempt,
                        None,
                        DropReason::NeighQueueFull,
                    )?;
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
        let offload = self.config.tcp.connection.tcp_checksum_offload;
        let mut failure = None;
        let result = self.host.submit(
            &mut self.endpoint,
            self.now,
            ticket,
            context,
            packet,
            0,
            |_| match if offload {
                io.transmit_tcp_checksum_offload(wire)
            } else {
                io.transmit(wire)
            } {
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
                let (owner, data) = (pending.owner, pending.data);
                slot.pending = None;
                report.transmitted += 1;
                self.tcp_segments += 1;
                self.tx_submitted += 1;
                if data && let Some(owner) = owner {
                    self.mark_in_device(owner);
                }
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
                self.tcp_segments += segments as u64;
                self.tx_submitted += 1;
                self.mark_in_device(owner);
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
        if let Some(slot) = owner.and_then(|core| self.connection_slot(core)) {
            self.touch(slot);
        }
    }
    // Carries on the closes and aborts some change may have advanced, then
    // frees the slots of released connections the endpoint has reclaimed.
    // With no close, abort or shutdown queued, no connection reclaimed since
    // the last pass and no TIME-WAIT flow due, a pass changes nothing.
    #[inline]
    fn maintain_connections(&mut self) -> Result<()> {
        if self.maintain.is_empty()
            && self.endpoint.reclaimed() == self.reclaimed
            && self.time_wait_flows.due.is_empty()
        {
            return Ok(());
        }
        self.maintain_pass()
    }
    #[inline(never)]
    fn maintain_pass(&mut self) -> Result<()> {
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
                        self.ports.give(port, Binding::Bound);
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
            if c.shutdown_requested && !(c.released || abort || close) {
                if self.endpoint.is_output_reserved(core) {
                    self.maintain.push(index);
                    continue;
                }
                self.connections[index]
                    .value
                    .as_mut()
                    .unwrap()
                    .shutdown_requested = false;
                match self.endpoint.shutdown(core) {
                    // A connection that ended meanwhile has nothing to shut.
                    Ok(()) | Err(EndpointError::Connection(ntcp::Error::InvalidState)) => {}
                    Err(e) => return Err(e.into()),
                }
                self.ready.push(index);
                continue;
            }
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
                                    match self.endpoint.poll_reserved_transmit_for(
                                        self.now,
                                        core,
                                        &mut slot.bytes,
                                        1,
                                    ) {
                                        Ok((_, attempt)) => attempt,
                                        // Unfit for a path a Packet Too Big
                                        // lowered: the poll failed the owner
                                        // and freed its reservation.
                                        Err(EndpointError::ReservationMtuTooSmall) => None,
                                        Err(e) => return Err(e.into()),
                                    }
                                }
                            };
                            // Every retained frame is certified unsubmitted. The
                            // explicit abort below supersedes its restored work.
                            if let Some(attempt) = attempt {
                                self.endpoint.discard_unsubmitted(
                                    self.now,
                                    attempt,
                                    None,
                                    DropReason::SocketClose,
                                )?;
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
            }
        }
        // The released connections the endpoint reclaimed since the last
        // pass or, past what it keeps of them, every one gone. A flow held
        // for another member's share is its owner's again once its
        // connection is reclaimed, accepted or not.
        let reclaimed = self.endpoint.reclaimed();
        if let Some(gone) = self.endpoint.reclaimed_since(self.reclaimed) {
            for core in gone {
                if self.holding != 0
                    && let Some(entry) = self.held_flows.get_mut(core.index())
                    && entry.is_some_and(|(id, _)| id == core)
                {
                    let (_, held) = entry.take().unwrap();
                    self.holding -= 1;
                    // `reclaimed_flow`, on the fields it reads: `gone`
                    // borrows the endpoint.
                    let flows = self.flows.as_ref().unwrap();
                    let (local, remote) = flows.tuple(held);
                    let tuple = scoped_tuple(
                        Tuple {
                            local: local.into(),
                            remote: remote.into(),
                        },
                        self.ingress.link(),
                    );
                    if !self
                        .time_wait_flows
                        .reclaimed(&self.endpoint, self.now, tuple, held)
                    {
                        flows.release(held);
                    }
                }
                if let Some(index) =
                    self.core_slots
                        .forget(core, &self.live_connections, &self.connections)
                {
                    let c = self.connections[index].value.take().unwrap();
                    debug_assert!(c.released);
                    vacate(&mut self.live_connections, index);
                    give_back(&mut self.free_connections, &self.connections, index);
                    self.ports.give(c.local.port(), c.binding);
                }
            }
        } else {
            let mut next = 0;
            while let Some(index) = next_live(&self.live_connections, next) {
                next = index + 1;
                let c = self.connections[index].value.as_ref().unwrap();
                let (core, port, binding) = (c.core, c.local.port(), c.binding);
                if !c.released || self.endpoint.connection_exists(core) {
                    continue;
                }
                self.core_slots
                    .forget(core, &self.live_connections, &self.connections);
                self.connections[index].value = None;
                vacate(&mut self.live_connections, index);
                give_back(&mut self.free_connections, &self.connections, index);
                self.ports.give(port, binding);
            }
            if self.holding != 0 {
                for index in 0..self.held_flows.len() {
                    if let Some((id, held)) = self.held_flows[index]
                        && !self.endpoint.connection_exists(id)
                    {
                        self.held_flows[index] = None;
                        self.holding -= 1;
                        self.reclaimed_flow(held);
                    }
                }
            }
        }
        self.reclaimed = reclaimed;
        if !self.time_wait_flows.due.is_empty() {
            self.maintain_time_wait_flows();
        }
        Ok(())
    }
}
