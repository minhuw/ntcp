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
                // Snapshot before timestamp cleanup/release can invalidate the
                // core view. Queries must retain its validity bits and errors.
                s.terminal_transport = Some(self.endpoint.transport_info(cid).map_err(engine));
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
            None => SocketAddr::new(self.local, self.port()?),
        };
        if local.ip().is_unspecified() {
            local.set_ip(self.local);
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
        self.check_address(remote)?;
        if remote.port() == 0 {
            return Err(EINVAL);
        }
        let options = self.sockets[&id].clone();
        let open = ntcp::ActiveOpenOptions {
            send_capacity: options.send_capacity,
            receive_capacity: options.receive_capacity,
            user_mss: options.user_mss,
        };
        let (cid, accepted) = if let Some(initial) = initial {
            self.endpoint.enable_fast_open().map_err(engine)?;
            if let Some(cookie) = options.server_cookie_for(remote) {
                self.endpoint.connect_fast_open_with_server_cookie(
                    self.now(),
                    local,
                    remote,
                    initial,
                    open,
                    Some(cookie),
                )
            } else {
                self.endpoint.connect_fast_open_with_policy(
                    self.now(),
                    local,
                    remote,
                    initial,
                    open,
                    options.client_policy_for(remote, self.socket_policy.fast_open_client_policy),
                )
            }
            .map_err(engine)?
        } else {
            (
                self.endpoint
                    .connect_with_options(self.now(), local, remote, open)
                    .map_err(engine)?,
                0,
            )
        };
        // Core admission begins the next transport attempt. Invalid requests,
        // failed admission, and deferred peer selection retain the old view.
        self.sockets.get_mut(&id).unwrap().terminal_transport = None;
        self.sockets.get_mut(&id).unwrap().soft_error = 0;
        if let Err(e) = self.apply_options(cid, &options) {
            self.rollback_connection(cid);
            return Err(e);
        }
        self.connection_options.push((
            cid,
            options.wire_tos(self.local),
            options.wire_discover(self.local),
            Some(options.zerocopy),
            options.mark,
            local,
        ));
        let s = self.sockets.get_mut(&id).unwrap();
        s.handle = Handle::Connection(cid);
        s.connect_pending = true;
        s.local = Some(local);
        s.deferred_peer = None;
        s.deferred_client_policy = None;
        Ok(accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_transport_queries_preserve_validity_and_unavailability() {
        let (mut owner, _peer, client, _, _) = crate::runtime::tests::pair();
        let Handle::Connection(cid) = owner.sockets[&client].handle else {
            panic!()
        };
        owner.endpoint.abort(cid).unwrap();
        owner.events();
        assert_eq!(owner.complete_connect(client), Err(ECONNABORTED));
        let info = owner.sockets[&client].terminal_transport.unwrap().unwrap();
        assert_eq!(info.state, State::Closed);
        let actual = owner.execute(client, Op::Transport(1)).unwrap().bytes;
        assert_eq!(
            &actual[148..152],
            &(info
                .min_rtt_us
                .unwrap_or(u32::MAX as u64)
                .min(u32::MAX as u64) as u32)
                .to_ne_bytes()
        );
        assert_eq!(
            &actual[220..224],
            &(info.reordering_events.min(u32::MAX as u64) as u32).to_ne_bytes()
        );
        let unsupported = unsupported_option("test");
        for ledger_valid in [false, true] {
            for delivered_segments_valid in [false, true] {
                owner.sockets.get_mut(&client).unwrap().terminal_transport =
                    Some(Ok(ntcp::TransportInfo {
                        ledger_valid,
                        delivered_segments_valid,
                        min_rtt_us: Some(12_000),
                        reordering_events: 7,
                        ..info
                    }));
                for requested in [0, 1, 7, 148, 151, 152, 192, 193, 220, 223, 224, 280, 512] {
                    let result = owner.execute(client, Op::TransportPrefix(1, requested));
                    let bytes = result.unwrap().bytes;
                    let available = if !ledger_valid {
                        24
                    } else if !delivered_segments_valid {
                        192
                    } else {
                        280
                    };
                    assert_eq!(bytes.len(), requested.min(available));
                    if requested > 0 {
                        assert_eq!(bytes[0], 7);
                    }
                    if bytes.len() >= 152 {
                        assert_eq!(&bytes[148..152], &12_000u32.to_ne_bytes());
                    }
                    if bytes.len() >= 224 {
                        assert_eq!(&bytes[220..224], &7u32.to_ne_bytes());
                    }
                }
                assert!(owner.execute(client, Op::Transport(1)).is_ok());
                assert!(
                    owner
                        .execute(client, Op::Transport(2))
                        .unwrap()
                        .bytes
                        .is_empty()
                );
                assert_eq!(
                    owner.execute(client, Op::Transport(99)).unwrap_err(),
                    unsupported
                );
            }
        }
        owner.sockets.get_mut(&client).unwrap().terminal_transport = Some(Err(EIO));
        for op in [
            Op::Transport(1),
            Op::TransportPrefix(1, 0),
            Op::TransportPrefix(1, 192),
        ] {
            assert_eq!(owner.execute(client, op).unwrap_err(), EIO);
        }
        let fresh = owner.execute(0, Op::New(0)).unwrap().value as u64;
        let snapshot = owner.execute(fresh, Op::Transport(1)).unwrap().bytes;
        assert_eq!(snapshot.len(), 280);
        assert_eq!(snapshot[0], 7);
        assert_eq!(&snapshot[148..152], &u32::MAX.to_ne_bytes());
        assert_eq!(&snapshot[220..224], &0u32.to_ne_bytes());
        owner
            .execute(fresh, Op::Bind("10.73.0.2:10090".parse().unwrap()))
            .unwrap();
        assert_eq!(
            owner.execute(fresh, Op::Transport(1)).unwrap().bytes,
            snapshot
        );
        owner.execute(fresh, Op::Listen(1)).unwrap();
        let listening = owner.execute(fresh, Op::Transport(1)).unwrap().bytes;
        assert_eq!(listening[0], 10);
        assert_eq!(&listening[148..152], &0u32.to_ne_bytes());
        assert_eq!(&listening[220..224], &0u32.to_ne_bytes());
    }

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
