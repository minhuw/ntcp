// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

// Linux caps each logical transfer, not each owner work item.
pub(super) fn max_rw_count() -> usize {
    static LIMIT: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *LIMIT.get_or_init(|| {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page = usize::try_from(page)
            .ok()
            .filter(|p| p.is_power_of_two())
            .unwrap_or(4096);
        (i32::MAX as usize) & !(page - 1)
    })
}

#[derive(Clone, Copy)]
pub(super) struct SendBatch {
    pub connection: ConnectionId,
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Copy)]
pub(super) struct SendFinish {
    pub connection: ConnectionId,
    pub end: u64,
    pub more: bool,
    pub end_of_record: bool,
    pub force: bool,
}

pub(super) fn batch_goal(info: &ntcp::TransportInfo) -> usize {
    let mss = (info.mss as usize).max(1);
    ((info.max_send_window as usize / 2 / mss) * mss)
        .max(mss)
        .min((BYTES / mss).max(1) * mss)
        .min(info.send_capacity)
}

impl Owner {
    // A nonblocking caller may return while output owns an immutable plan.
    // Apply only its boundary metadata once that generation is mutable again.
    pub(super) fn finish_retained_sends(&mut self) {
        for socket in self.sockets.values_mut() {
            if let Some(finish) = socket.send_finish
                && !self.endpoint.is_output_reserved(finish.connection)
            {
                if matches!(socket.handle, Handle::Connection(cid) if cid == finish.connection) {
                    let _ = self.endpoint.finish_send(
                        finish.connection,
                        finish.end,
                        finish.more,
                        finish.end_of_record,
                        finish.force,
                    );
                }
                socket.send_finish = None;
            }
        }
    }

    // Host coalescing batches are separate from TCP's exact byte-quota API.
    // Filling an existing tail may cross lowat; opening another batch may not.
    pub(super) fn send_batch_admission(&self, id: u64, cid: ConnectionId) -> Result<(usize, u64)> {
        let s = self.sockets.get(&id).ok_or(EBADF)?;
        let info = self.endpoint.transport_info(cid).map_err(engine)?;
        let progress = self.endpoint.send_progress(cid).map_err(engine)?;
        let room = self
            .endpoint
            .send_admission_room(cid, None)
            .map_err(engine)?;
        let lowat = effective_notsent_lowat(s.notsent_lowat, self.socket_policy.notsent_lowat);
        let goal = batch_goal(&info);
        let transmitted = progress
            .queued_end
            .saturating_sub(info.notsent_bytes as u64);
        let tail_start = s
            .send_batch
            .filter(|b| b.connection == cid && b.end == progress.queued_end && b.start <= b.end)
            .map(|b| b.start.max(transmitted))
            .filter(|&start| progress.queued_end - start < goal as u64);
        if lowat == u32::MAX {
            return Ok((room, tail_start.unwrap_or(progress.queued_end)));
        }
        if lowat == 0 {
            return Ok((0, progress.queued_end));
        }
        if let Some(start) = tail_start {
            return Ok((
                room.min(goal - (progress.queued_end - start) as usize),
                start,
            ));
        }
        Ok((
            if info.notsent_bytes < lowat as usize {
                room.min(goal)
            } else {
                0
            },
            progress.queued_end,
        ))
    }

    pub(super) fn socket_send_room(&self, id: u64, cid: ConnectionId) -> Result<usize> {
        self.send_batch_admission(id, cid).map(|(room, _)| room)
    }

    fn batched_send(&self, id: u64) -> bool {
        self.sockets.get(&id).is_some_and(|s| {
            effective_notsent_lowat(s.notsent_lowat, self.socket_policy.notsent_lowat) != u32::MAX
        })
    }
}

pub(super) struct LogicalSend {
    sources: Vec<(usize, usize)>,
    total: usize,
    pub(super) accepted: usize,
    index: usize,
    offset: usize,
    flags: i32,
    bits: u32,
    cid: Option<ConnectionId>,
    end: u64,
    cookie: Option<u64>,
    zc: Option<u32>,
    lease: Option<std::sync::Arc<crate::zerocopy::LeaseState>>,
    // Owns one notification slot, without an ID, during provisional TFO copy.
    zc_pending: bool,
    zerocopy: bool,
    destination: Option<SocketAddr>,
    fast_open_started: bool,
    wait_handshake: bool,
    pending_fast_open: Option<ConnectionId>,
    batch_turns: usize,
}
impl LogicalSend {
    pub(super) fn new(
        owner: &Owner,
        id: u64,
        sources: Vec<(usize, usize)>,
        flags: i32,
        stamp: Option<u32>,
        destination: Option<SocketAddr>,
    ) -> Result<Self> {
        let total = sources
            .iter()
            .try_fold(0usize, |n, p| {
                n.checked_add(p.1)
                    .filter(|n| *n <= isize::MAX as usize)
                    .ok_or(EINVAL)
            })?
            .min(max_rw_count());
        let socket = owner.sockets.get(&id).ok_or(EBADF)?;
        let options = socket.timestamps.options;
        let bits = stamp
            .map(|stamp| options.per_send(stamp))
            .transpose()?
            .unwrap_or(options.flags);
        Ok(Self {
            sources,
            total,
            accepted: 0,
            index: 0,
            offset: 0,
            flags,
            bits,
            cid: None,
            end: 0,
            cookie: None,
            zc: None,
            lease: None,
            zc_pending: false,
            zerocopy: socket.zerocopy && flags & MSG_ZEROCOPY != 0,
            destination,
            fast_open_started: false,
            wait_handshake: false,
            pending_fast_open: None,
            batch_turns: 0,
        })
    }
    #[cfg(test)]
    pub(super) fn total_for_test(&self) -> usize {
        self.total
    }
    pub(super) fn waiting_fast_open(&self) -> bool {
        self.wait_handshake
    }
    pub(super) fn continuing_nonblocking(&self) -> bool {
        self.batch_turns != 0 && self.accepted != 0 && !self.wait_handshake
    }
    fn done(&self) -> bool {
        self.accepted == self.total && !self.wait_handshake
    }
    fn copy_chunk(&self, count: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0; count];
        let mut copied = 0;
        let mut index = self.index;
        let mut offset = self.offset;
        while copied < count {
            let (address, len) = self.sources[index];
            let len = (len - offset).min(count - copied);
            if len == 0 {
                index += 1;
                offset = 0;
                continue;
            }
            let address = address.checked_add(offset).ok_or(EFAULT)?;
            // A fault anywhere in this bounded chunk admits none of it.
            memory(bytes[copied..].as_mut_ptr(), address as *mut u8, len, false)?;
            copied += len;
            offset += len;
            if offset == self.sources[index].1 {
                index += 1;
                offset = 0;
            }
        }
        Ok(bytes)
    }
    fn advance(&mut self, mut count: usize) {
        self.accepted += count;
        while count != 0 {
            let n = count.min(self.sources[self.index].1 - self.offset);
            self.offset += n;
            count -= n;
            if self.offset == self.sources[self.index].1 {
                self.index += 1;
                self.offset = 0;
            }
        }
    }
}
impl Owner {
    pub(super) fn collect_zero_copy(&mut self) {
        for socket in self.sockets.values_mut() {
            let mut index = 0;
            while index < socket.zc_leases.len() {
                let Some(copied) = socket.zc_leases[index].state.complete() else {
                    index += 1;
                    continue;
                };
                let pending = socket.zc_leases.remove(index).unwrap();
                socket.zc_reserved -= 1;
                if let Some(Completion::SharedZeroCopy(lo, hi, old_copied)) =
                    socket.completions.back_mut()
                    && *old_copied == copied
                    && extends_completion((*lo, *hi), pending.id)
                {
                    *hi = pending.id;
                } else {
                    socket
                        .completions
                        .push_back(Completion::SharedZeroCopy(pending.id, pending.id, copied));
                }
                socket.readiness_generations[2] = socket.readiness_generations[2].wrapping_add(1);
            }
        }
    }
    // One bounded copy/admission per service turn. No foreign data survives a
    // turn except bytes already owned by TCP; the cursor advances only on write.
    //= https://www.rfc-editor.org/rfc/rfc7413#appendix-A.1
    //# MSG_FASTOPEN marks the attempt to send data in the SYN like a combination of connect() and sendto(),
    //# by performing an implicit connect() operation.
    //= https://www.rfc-editor.org/rfc/rfc7413#appendix-A.1
    //# It blocks until the handshake has completed and the data is buffered.
    //= https://www.rfc-editor.org/rfc/rfc7413#appendix-A.1
    //# For a non-blocking socket, it returns the number of bytes buffered and sent in the SYN packet.
    //= https://www.rfc-editor.org/rfc/rfc7413#appendix-A.1
    //# If the cookie is not available locally, it returns -1 with errno EINPROGRESS, and sends a SYN with a
    //# TFO cookie request automatically. The caller needs to write the data again when the socket is
    //# connected.
    fn send_step(&mut self, id: u64, send: &mut LogicalSend, blocking: bool) -> Result<()> {
        // An open held for the lifecycle deadline is a connection attempt.
        if self.sockets.get(&id).ok_or(EBADF)?.quiet_open.is_some() {
            return Err(if send.flags & MSG_FASTOPEN != 0 && !send.fast_open_started {
                EALREADY
            } else {
                EAGAIN
            });
        }
        let deferred = self.sockets.get(&id).ok_or(EBADF)?.deferred_peer.is_some();
        // Permission belongs to the logical call. A call already admitted
        // before a policy change keeps its handshake/tail and completion ownership.
        if !send.fast_open_started
            && (send.flags & MSG_FASTOPEN != 0 || deferred)
            && !self.socket_policy.fast_open_client_enabled
        {
            return Err(EOPNOTSUPP);
        }
        if !send.fast_open_started && send.flags & MSG_FASTOPEN != 0 && !deferred {
            // Completing SS_CONNECTING is an ordinary send, not another SYN
            // copy: retain normal timestamp/zerocopy admission on this retry.
            send.fast_open_started = !self.check_connect(id)?;
        }
        if !send.fast_open_started && (send.flags & MSG_FASTOPEN != 0 || deferred) {
            let socket = &self.sockets[&id];
            // A deferred open keeps the zone its connect resolved; sendto
            // with MSG_FASTOPEN resolves the destination's scope now.
            let (remote, zone) = if let Some(remote) = socket.deferred_peer {
                (remote, socket.zone)
            } else {
                let destination = send.destination.ok_or(EINVAL)?;
                let remote = socket.normalize_address(destination, self.local, false)?;
                (remote, self.connect_zone(id, destination)?)
            };
            let socket = &self.sockets[&id];
            if remote.port() == 0 {
                return Err(EINVAL);
            }
            // Native TX timestamps need a real initial-copy range and events.
            // Copied notifications instead rely on ownership of admitted bytes.
            if send.bits & crate::timestamping::TX_RECORD != 0 {
                return Err(EOPNOTSUPP);
            }
            let lowat =
                effective_notsent_lowat(socket.notsent_lowat, self.socket_policy.notsent_lowat);
            let count = send.total.min(BYTES).min(socket.send_capacity);
            if lowat == 0 && send.total != 0 {
                return Err(EAGAIN);
            }
            // A blocking implicit connect waits here for the lifecycle
            // deadline, owning nothing and interruptible like any waiter.
            if blocking {
                let now = self.clock()?;
                if self.endpoint.quiet_until(now).is_some() {
                    return Err(EAGAIN);
                }
            }
            // Crucially precedes local-port allocation, core connection, and
            // clearing the deferred peer. EFAULT leaves the socket retryable.
            let completion =
                self.reserve_send_completion(id, count != 0, send.zerocopy, 0, true)?;
            let bytes = send.copy_chunk(count)?;
            let local = self.connect_local(id, remote, zone)?;
            let n = self.start_connection(id, local, remote, zone, Some(&bytes))?;
            send.fast_open_started = true;
            send.advance(n);
            if n != 0 && completion {
                let socket = self.sockets.get_mut(&id).unwrap();
                // A blocking implicit open owns only provisional SYN bytes.
                // Hold notification capacity until the handshake makes the
                // positive return irrevocable; failed calls consume no ID.
                if blocking {
                    send.zc_pending = true;
                } else {
                    send.zc = Some(socket.zc_next);
                    socket.zc_next = socket.zc_next.wrapping_add(1);
                }
                socket.zc_reserved += 1;
            }
            send.wait_handshake = blocking;
            if blocking {
                let Handle::Connection(cid) = self.sockets[&id].handle else {
                    unreachable!()
                };
                self.endpoint
                    .set_fast_open_write_pending(cid, send.total != 0)
                    .map_err(engine)?;
                send.pending_fast_open = Some(cid);
            }
            if n == 0 && !blocking {
                return Err(EINPROGRESS);
            }
            return Ok(());
        }
        if send.wait_handshake {
            if !self.sockets.get(&id).is_some_and(|s| {
                matches!(s.handle, Handle::Connection(cid) if Some(cid) == send.pending_fast_open)
            }) {
                return Err(EBADF);
            }
            self.complete_connect(id)?;
            send.wait_handshake = false;
            if core::mem::take(&mut send.zc_pending) {
                let socket = self.sockets.get_mut(&id).unwrap();
                send.zc = Some(socket.zc_next);
                socket.zc_next = socket.zc_next.wrapping_add(1);
            }
        }
        // Ordinary stream sends validate state before accessing payload or
        // reserving completions. Fast Open's implicit connect is handled above.
        let cid = self.send_state(id)?;
        let remaining = send.total - send.accepted;
        if remaining == 0 {
            return Ok(());
        }
        let room = self.socket_send_room(id, cid)?;
        if room == 0 {
            self.endpoint
                .record_send_backpressure(cid)
                .map_err(engine)?;
            return Err(EAGAIN);
        }
        let deferred = blocking || self.batched_send(id);
        let completion = self.reserve_send_completion(
            id,
            true,
            send.zerocopy && send.zc.is_none(),
            send.bits,
            deferred,
        )?;
        let mut observed = Vec::new();
        if deferred && send.bits & crate::timestamping::TX_RECORD != 0 {
            observed.try_reserve_exact(4).map_err(|_| ENOBUFS)?;
        }
        let count = remaining.min(BYTES).min(room);
        // Registered immutable input is eligible only when the selected backend
        // explicitly accepts its storage. Arbitrary pointers stay on fault-safe
        // copied admission; timestamp packet capture is also a copied contract.
        let shared = if send.zerocopy
            && send.bits & crate::timestamping::TX_RECORD == 0
            && self.egress.as_ref().is_some_and(|e| e.shared_enabled())
        {
            let mut index = send.index;
            let mut offset = send.offset;
            while index < send.sources.len() && send.sources[index].1 == offset {
                index += 1;
                offset = 0;
            }
            let (address, len) = send.sources[index];
            let address = address.checked_add(offset).ok_or(EFAULT)?;
            // Its port is chosen later: every port must be able to send it.
            crate::zerocopy::lookup(address, count.min(len - offset))?.filter(|p| {
                self.ports.iter().all(|port| {
                    port.ethernet
                        .as_ref()
                        .is_some_and(|b| b.io.zero_copy_payload_supported(p))
                })
            })
        } else {
            None
        };
        let admitted = shared.as_ref().map_or(count, ntcp_io::Payload::len);
        let flags = if deferred && admitted < remaining {
            (send.flags | MSG_MORE) & !MSG_EOR
        } else {
            send.flags
        };
        let cookie = self.timestamp_cookie;
        let n = if let Some(payload) = shared {
            let socket = self.sockets.get_mut(&id).unwrap();
            let pending = socket.zc_reserved + usize::from(send.zc.is_none());
            socket
                .zc_leases
                .try_reserve_exact(pending.saturating_sub(socket.zc_leases.len()))
                .map_err(|_| ENOBUFS)?;
            let state = send.lease.get_or_insert_with(|| {
                let state = crate::zerocopy::LeaseState::new();
                if send.accepted != 0 {
                    state.copied();
                }
                state
            });
            let progress = self.endpoint.send_progress(cid).map_err(engine)?;
            let goal = batch_goal(&self.endpoint.transport_info(cid).map_err(engine)?);
            let (_, batch_start) = self.send_batch_admission(id, cid)?;
            let n = self
                .endpoint
                .write_shared(
                    cid,
                    state.borrow(payload),
                    flags & MSG_MORE != 0,
                    flags & MSG_EOR != 0,
                    None,
                )
                .map_err(engine)?;
            if n != 0 {
                let end = progress.queued_end + n as u64;
                self.sockets.get_mut(&id).unwrap().send_batch = if flags & MSG_EOR == 0 && goal != 0
                {
                    Some(SendBatch {
                        connection: cid,
                        start: batch_start + ((end - batch_start - 1) / goal as u64) * goal as u64,
                        end,
                    })
                } else {
                    None
                };
            }
            n
        } else {
            let bytes = send.copy_chunk(count)?;
            let n = self.timestamp_write_bits(id, cid, &bytes, flags, send.bits)?;
            if n != 0
                && let Some(state) = &send.lease
            {
                state.copied();
            }
            debug_assert_eq!(n, bytes.len());
            n
        };
        send.advance(n);
        send.cid = Some(cid);
        send.end = self.endpoint.send_progress(cid).map_err(engine)?.queued_end;
        if let Some(old) = send.cookie.take() {
            self.discard_timestamp(id, cid, old);
        }
        if self.timestamp_cookie != cookie {
            if deferred {
                self.defer_timestamp(id, cookie, observed);
            }
            send.cookie = Some(cookie);
        }
        if completion && send.zc.is_none() {
            let s = self.sockets.get_mut(&id).unwrap();
            send.zc = Some(s.zc_next);
            s.zc_next = s.zc_next.wrapping_add(1);
            s.zc_reserved += 1;
        }
        Ok(())
    }
    pub(super) fn finish_send(
        &mut self,
        id: u64,
        send: &mut LogicalSend,
        result: Result<()>,
    ) -> Result<Reply> {
        if core::mem::take(&mut send.zc_pending)
            && let Some(socket) = self.sockets.get_mut(&id)
        {
            socket.zc_reserved -= 1;
        }
        if let Some(cid) = send.pending_fast_open.take() {
            let _ = self.endpoint.set_fast_open_write_pending(cid, false);
        }
        if let Some(cid) = send.cid {
            let full = !send.done() && self.endpoint.send_admission_room(cid, None) == Ok(0);
            let finish = SendFinish {
                connection: cid,
                end: send.end,
                more: send.flags & MSG_MORE != 0,
                end_of_record: send.flags & MSG_EOR != 0,
                force: full,
            };
            let result = self.endpoint.finish_send(
                cid,
                finish.end,
                finish.more,
                finish.end_of_record,
                finish.force,
            );
            if let Some(socket) = self.sockets.get_mut(&id) {
                if result == Err(ntcp::EndpointError::OutputReserved) {
                    debug_assert!(socket.send_finish.is_none());
                    socket.send_finish = Some(finish);
                }
                if finish.end_of_record {
                    socket.send_batch = None;
                }
            }
        }
        if let Some(cookie) = send.cookie.take() {
            self.finish_timestamp(id, cookie);
        }
        let lease = send.lease.take();
        if let Some(state) = &lease {
            state.finish();
        }
        if let Some(next) = send.zc.take()
            && let Some(s) = self.sockets.get_mut(&id)
        {
            if let Some(state) = lease {
                // Reservation transfers to a release observation, not immediate
                // submission completion. TCP, held plans and backend all count.
                s.zc_leases
                    .push_back(crate::zerocopy::Pending { id: next, state });
            } else {
                s.zc_reserved -= 1;
                if let Some(Completion::ZeroCopy(lo, hi)) = s.completions.back_mut()
                    && extends_completion((*lo, *hi), next)
                {
                    *hi = next;
                } else {
                    s.completions.push_back(Completion::ZeroCopy(next, next));
                }
                s.readiness_generations[2] = s.readiness_generations[2].wrapping_add(1);
            }
        }
        self.collect_zero_copy();
        // A blocking implicit connect has only provisionally copied SYN data.
        // Its failure is not an ordinary post-handshake partial send success.
        if send.accepted == 0 || send.wait_handshake {
            result?;
        }
        Ok(Reply {
            value: send.accepted as i32,
            ..Reply::default()
        })
    }
    pub(super) fn service_send(&mut self, request: &mut Request, wait: bool) -> bool {
        let mut send = request.send.take().unwrap();
        let blocking = wait
            && send.flags & MSG_DONTWAIT == 0
            && self
                .sockets
                .get(&request.id)
                .is_some_and(|s| s.flags & SOCK_NONBLOCK == 0);
        let expired = request.deadline.is_some_and(|d| Instant::now() >= d);
        let result = if expired {
            Err(EAGAIN)
        } else {
            self.send_step(request.id, &mut send, blocking)
        };
        let continuing = !blocking
            && !expired
            && !send.done()
            && send.cid.is_some()
            && !send.wait_handshake
            && result.is_ok()
            && (self.batched_send(request.id) || send.lease.is_some())
            && send.batch_turns < BUDGET;
        if (blocking || continuing)
            && !expired
            && !send.done()
            && (result.is_ok() || matches!(result, Err(EAGAIN)))
        {
            // A blocked syscall must release the queued prefix even under MORE
            // or CORK. RFC FLUSH is deliberately not used: it discards bytes.
            if let Some(s) = self.sockets.get(&request.id)
                && let Handle::Connection(cid) = s.handle
            {
                let room = self.socket_send_room(request.id, cid).unwrap_or(0);
                if room == 0 || matches!(result, Err(EAGAIN)) {
                    let more = !self.batched_send(request.id) || send.flags & MSG_MORE != 0;
                    let _ = self.endpoint.finish_send(cid, send.end, more, false, true);
                }
            }
            if continuing {
                send.batch_turns += 1;
            }
            let _ = self.refresh_readiness(request.id);
            request.send = Some(send);
            return false;
        }
        let result = self.finish_send(request.id, &mut send, result);
        let _ = self.refresh_readiness(request.id);
        let _ = request.reply.send(result);
        true
    }
    pub(super) fn send_once(
        &mut self,
        id: u64,
        sources: Vec<(usize, usize)>,
        flags: i32,
        stamp: Option<u32>,
        destination: Option<SocketAddr>,
    ) -> Result<Reply> {
        let mut send = LogicalSend::new(self, id, sources, flags, stamp, destination)?;
        let result = self.send_step(id, &mut send, false);
        self.finish_send(id, &mut send, result)
    }
}

impl Owner {
    pub(super) fn transfer_once(
        &mut self,
        id: u64,
        source: i32,
        staging: [i32; 2],
        offset: Option<usize>,
        count: usize,
        flags: i32,
    ) -> Result<i32> {
        let socket = self.sockets.get(&id).ok_or(EBADF)?;
        if socket.quiet_open.is_some() {
            return Err(EAGAIN);
        }
        if socket.deferred_peer.is_some() {
            return Err(EOPNOTSUPP);
        }
        if count == 0 {
            return match offset {
                Some(offset) => raw(unsafe {
                    syscall(SYS_sendfile, staging[1], source, offset as *mut off_t, 0)
                })
                .map(|n| n as i32),
                None => Ok(0),
            };
        }
        let cid = self.send_state(id)?;
        let bits = self.sockets[&id].timestamps.options.flags;
        self.reserve_send_completion(id, true, false, bits, false)?;
        let mut source_error = None;
        let transferred = self.timestamp_write_from(
            id,
            cid,
            count.min(BYTES).min(max_rw_count()),
            flags,
            bits,
            |room| {
                let mut bytes = Vec::new();
                bytes.try_reserve_exact(room).map_err(|_| ENOBUFS)?;
                bytes.resize(room, 0);
                let result = raw(unsafe {
                    match offset {
                        Some(offset) => syscall(
                            SYS_sendfile,
                            staging[1],
                            source,
                            offset as *mut off_t,
                            bytes.len(),
                        ),
                        None => syscall(
                            SYS_splice,
                            source,
                            ptr::null_mut::<loff_t>(),
                            staging[1],
                            ptr::null_mut::<loff_t>(),
                            bytes.len(),
                            SPLICE_F_NONBLOCK,
                        ),
                    }
                });
                // sendfile may have moved bytes before an offset copyout EFAULT.
                // Admit those bytes too, while preserving the native error result.
                let mut available = 0i32;
                raw(unsafe { syscall(SYS_ioctl, staging[0], FIONREAD, &mut available) })?;
                if available == 0 {
                    source_error = result.as_ref().err().copied();
                    result?;
                    return Ok(Vec::new());
                }
                source_error = result.err();
                let n = raw(unsafe {
                    syscall(SYS_read, staging[0], bytes.as_mut_ptr(), available as usize)
                })?;
                assert_eq!(n, available as i64); // Private pipe: no competing reader.
                bytes.truncate(n as usize);
                Ok(bytes)
            },
        );
        // Distinguish empty native input from TCP admission backpressure. A
        // nonblocking socket must not turn a blocking input pipe nonblocking.
        if source_error == Some(EAGAIN) {
            return Ok(-EAGAIN);
        }
        let n = transferred?;
        let end = self.endpoint.send_progress(cid).map_err(engine)?.queued_end;
        self.endpoint
            .finish_send(cid, end, flags & MSG_MORE != 0, false, false)
            .map_err(engine)?;
        self.refresh_readiness(id)?;
        if let Some(error) = source_error {
            Err(error)
        } else {
            Ok(n as i32)
        }
    }
}
