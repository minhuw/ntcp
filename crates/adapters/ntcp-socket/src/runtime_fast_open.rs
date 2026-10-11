// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

impl Owner {
    // True starts a new open; false completes Linux SS_CONNECTING on the
    // existing transport. TCP establishment alone must not imply SS_CONNECTED.
    pub(super) fn check_connect(&mut self, id: u64) -> Result<bool> {
        let s = self.sockets.get(&id).ok_or(EBADF)?;
        if s.deferred_peer.is_some() {
            return Err(EISCONN);
        }
        match s.handle {
            Handle::Fresh => Ok(true),
            Handle::Listener(_) => Err(EINVAL),
            Handle::Connection(_) if !s.connect_pending => Err(EISCONN),
            Handle::Connection(_) => self
                .complete_connect(id)
                .map(|()| false)
                .map_err(|e| if e == EAGAIN { EALREADY } else { e }),
        }
    }

    pub(super) fn complete_connect(&mut self, id: u64) -> Result<()> {
        let s = self.sockets.get_mut(&id).ok_or(EBADF)?;
        let Handle::Connection(cid) = s.handle else {
            return Err(ENOTCONN);
        };
        match self.endpoint.state(cid).map_err(engine)? {
            State::SynSent | State::SynReceived => return Err(EAGAIN),
            State::Closed => {
                // __inet_stream_connect's sock_error path returns to
                // SS_UNCONNECTED; do not leave a failed implicit open pending.
                let error = if s.error != 0 { s.error } else { ECONNABORTED };
                s.error = 0;
                s.handle = Handle::Fresh;
                s.connect_pending = false;
                s.connected = false;
                s.peer_fin = false;
                s.write_shutdown = false;
                s.read_shutdown = false;
                let options = s.timestamps.options;
                s.timestamps = TimestampState::default();
                s.timestamps.options = options;
                self.rollback_connection(cid);
                return Err(error);
            }
            _ => (),
        }
        s.connect_pending = false;
        Ok(())
    }

    pub(super) fn connect_local(&mut self, id: u64) -> Result<SocketAddr> {
        self.connection_options
            .retain(|p| self.endpoint.connection_exists(p.0));
        if self.connection_options.len() == self.socket_limit() {
            return Err(ENOBUFS);
        }
        let mut local = match self.sockets[&id].local {
            Some(local) => local,
            None => SocketAddr::new(self.local.into(), self.port()?),
        };
        if local.ip().is_unspecified() {
            local.set_ip(self.local.into());
        }
        Ok(local)
    }

    // All active opens share admission, pre-output options, and rollback. The
    // caller must copy foreign initial data before entering this transaction.
    pub(super) fn start_connection(
        &mut self,
        id: u64,
        local: SocketAddr,
        remote: SocketAddr,
        initial: Option<&[u8]>,
    ) -> Result<usize> {
        if remote.port() == 0 {
            return Err(EINVAL);
        }
        let options = self.sockets[&id].clone();
        let (cid, accepted) = if let Some(initial) = initial {
            self.endpoint.enable_fast_open().map_err(engine)?;
            self.endpoint
                .connect_fast_open_with_buffer_capacities(
                    self.now(),
                    local,
                    remote,
                    initial,
                    options.send_capacity,
                    options.receive_capacity,
                )
                .map_err(engine)?
        } else {
            (
                self.endpoint
                    .connect_with_buffer_capacities(
                        self.now(),
                        local,
                        remote,
                        options.send_capacity,
                        options.receive_capacity,
                    )
                    .map_err(engine)?,
                0,
            )
        };
        if let Err(e) = self.apply_options(cid, &options) {
            self.rollback_connection(cid);
            return Err(e);
        }
        self.connection_options
            .push((cid, options.tos, options.discover, Some(options.zerocopy)));
        let s = self.sockets.get_mut(&id).unwrap();
        s.handle = Handle::Connection(cid);
        s.connect_pending = true;
        s.local = Some(local);
        s.deferred_peer = None;
        Ok(accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fast_open_enable_budget_failure_is_atomic_on_fresh_and_listener() {
        let local = Ipv4Addr::new(192, 0, 2, 1);
        let config = EndpointConfig {
            max_buffer_bytes: 0,
            ..EndpointConfig::default()
        };
        let mut owner = Owner::with_config(local, (local, 32), [1; 32], None, config).unwrap();
        let id = owner.execute(0, Op::New(SOCK_NONBLOCK)).unwrap().value as u64;
        for listening in [false, true] {
            if listening {
                owner.execute(id, Op::Listen(1)).unwrap();
            }
            assert_eq!(
                owner
                    .execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 1))
                    .unwrap_err(),
                ENOMEM
            );
            assert_eq!(
                owner
                    .execute(id, Op::Get(IPPROTO_TCP, TCP_FASTOPEN))
                    .unwrap()
                    .value,
                0
            );
            assert_eq!(owner.endpoint.buffer_bytes(), 0);
            owner
                .execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 0))
                .unwrap();
        }
    }
}
