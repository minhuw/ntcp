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
    zerocopy: bool,
}
impl LogicalSend {
    pub(super) fn new(
        owner: &Owner,
        id: u64,
        sources: Vec<(usize, usize)>,
        flags: i32,
        stamp: Option<u32>,
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
            zerocopy: socket.zerocopy && flags & MSG_ZEROCOPY != 0,
        })
    }
    #[cfg(test)]
    pub(super) fn total_for_test(&self) -> usize {
        self.total
    }
    fn done(&self) -> bool {
        self.accepted == self.total
    }
}
impl Owner {
    // One bounded copy/admission per service turn. No foreign data survives a
    // turn except bytes already owned by TCP; the cursor advances only on write.
    fn send_step(&mut self, id: u64, send: &mut LogicalSend, blocking: bool) -> Result<()> {
        let connected = matches!(
            self.sockets.get(&id).ok_or(EBADF)?.handle,
            Handle::Connection(_)
        );
        let cid = if connected {
            Some(self.send_state(id)?)
        } else {
            None
        };
        let remaining = send.total - send.accepted;
        if remaining == 0 {
            self.send_state(id)?;
            return Ok(());
        }
        let room = if let Some(cid) = cid {
            self.endpoint
                .send_admission_room(
                    cid,
                    Some(effective_notsent_lowat(self.sockets[&id].notsent_lowat)),
                )
                .map_err(engine)?
        } else {
            BYTES
        };
        if room == 0 {
            return Err(EAGAIN);
        }
        let completion = if cid.is_some() {
            self.reserve_send_completion(
                id,
                true,
                send.zerocopy && send.zc.is_none(),
                send.bits,
                blocking,
            )?
        } else {
            false
        };
        let mut observed = Vec::new();
        if blocking && send.bits & crate::timestamping::TX_RECORD != 0 {
            observed.try_reserve_exact(4).map_err(|_| ENOBUFS)?;
        }
        let count = remaining.min(BYTES).min(room);
        let mut bytes = vec![0; count];
        let mut copied = 0;
        let mut index = send.index;
        let mut offset = send.offset;
        while copied < count {
            let (address, len) = send.sources[index];
            let len = (len - offset).min(count - copied);
            if len == 0 {
                index += 1;
                offset = 0;
                continue;
            }
            let address = address.checked_add(offset).ok_or(EFAULT)?;
            // The temporary chunk is one copy transaction: a fault in any
            // page/iovec admits none of it. Earlier owner turns remain accepted.
            memory(bytes[copied..].as_mut_ptr(), address as *mut u8, len, false)?;
            copied += len;
            offset += len;
            if offset == send.sources[index].1 {
                index += 1;
                offset = 0;
            }
        }
        let cid = cid.ok_or(ENOTCONN)?;
        let flags = if blocking && copied < remaining {
            (send.flags | MSG_MORE) & !MSG_EOR
        } else {
            send.flags
        };
        let cookie = self.timestamp_cookie;
        let n = self.timestamp_write_bits(id, cid, &bytes[..copied], flags, send.bits)?;
        debug_assert_eq!(n, copied); // Exclusive owner: admission cannot change during copy.
        send.accepted += n;
        send.index = index;
        send.offset = offset;
        send.cid = Some(cid);
        send.end = self.endpoint.send_progress(cid).map_err(engine)?.queued_end;
        if let Some(old) = send.cookie.take() {
            self.discard_timestamp(id, cid, old);
        }
        if self.timestamp_cookie != cookie {
            if blocking {
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
        if let Some(cid) = send.cid {
            let full = !send.done() && self.endpoint.send_admission_room(cid, None) == Ok(0);
            let _ = self.endpoint.finish_send(
                cid,
                send.end,
                send.flags & MSG_MORE != 0,
                send.flags & MSG_EOR != 0,
                full,
            );
        }
        if let Some(cookie) = send.cookie.take() {
            self.finish_timestamp(id, cookie);
        }
        if let Some(next) = send.zc.take()
            && let Some(s) = self.sockets.get_mut(&id)
        {
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
        if send.accepted == 0 {
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
        if blocking && !expired && !send.done() && (result.is_ok() || matches!(result, Err(EAGAIN)))
        {
            // A blocked syscall must release the queued prefix even under MORE
            // or CORK. RFC FLUSH is deliberately not used: it discards bytes.
            if let Some(s) = self.sockets.get(&request.id)
                && let Handle::Connection(cid) = s.handle
            {
                let room = self
                    .endpoint
                    .send_admission_room(cid, Some(effective_notsent_lowat(s.notsent_lowat)))
                    .unwrap_or(0);
                if room == 0 || matches!(result, Err(EAGAIN)) {
                    let _ = self.endpoint.finish_send(cid, send.end, true, false, true);
                }
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
    ) -> Result<Reply> {
        let mut send = LogicalSend::new(self, id, sources, flags, stamp)?;
        let result = self.send_step(id, &mut send, false);
        self.finish_send(id, &mut send, result)
    }
}
