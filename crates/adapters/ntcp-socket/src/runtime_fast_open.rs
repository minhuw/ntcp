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

    //= https://www.rfc-editor.org/rfc/rfc7413#appendix-A.1
    //= reason=Shared active startup and consumable completion preserve ordinary connect errno semantics for MSG_FASTOPEN and deferred first writes. Paired IPv4/IPv6 packet and Owner tests cover validated refusal, R2/application/SYN-budget timeout, local abort, unsubmitted reservation abandonment, normal cancellation and every supported hard ICMP code; all soft/time/parameter/quench codes remain notifications through successful completion and stream delivery. Blocking/nonblocking completion, consumed SO_ERROR fallback, readiness generations, public descriptor aliases/poll/epoll, retry, terminal TCP_INFO prefixes and authorized receive drain retain their distinct channels. Initial admission returns and pre-start address/copy/resource/allocation/entropy rejections are separate stages, not universal send-buffer errno claims or Linux-kernel equivalence.
    //# On errors, it returns the same errno as connect() if the handshake fails.
    pub(super) fn complete_connect(&mut self, id: u64) -> Result<()> {
        let s = self.sockets.get_mut(&id).ok_or(EBADF)?;
        let Handle::Connection(cid) = s.handle else {
            return Err(ENOTCONN);
        };
        match self.endpoint.state(cid).map_err(engine)? {
            State::SynSent | State::SynReceived => return Err(EAGAIN),
            State::Closed => {
                // Match SS_UNCONNECTED while retaining any independently
                // authorized receive prefix until the application drains it.
                // Snapshot before cleanup/release can invalidate the core view.
                s.terminal_transport = Some(self.endpoint.transport_info(cid).map_err(engine));
                let error = if s.error != 0 { s.error } else { ECONNABORTED };
                s.error = 0;
                s.connect_pending = false;
                s.connected = false;
                if self.endpoint.terminal_readable_bytes(cid).map_err(engine)? == 0 {
                    self.release_failed_connect(id, cid);
                }
                return Err(error);
            }
            _ => (),
        }
        s.connect_pending = false;
        Ok(())
    }

    // Called after failed completion, immediately if there is no accepted data
    // or after the final read. Keep the terminal transport snapshot for queries.
    pub(super) fn release_failed_connect(&mut self, id: u64, cid: ConnectionId) {
        self.set_handle(id, Handle::Fresh);
        let s = self.sockets.get_mut(&id).unwrap();
        s.peer_fin = false;
        s.write_shutdown = false;
        s.read_shutdown = false;
        let options = s.timestamps.options;
        s.timestamps = TimestampState::default();
        s.timestamps.options = options;
        s.settle_timestamp_charge(&mut self.timestamp_total);
        self.rollback_connection(cid);
    }

    pub(super) fn connect_local(
        &mut self,
        id: u64,
        remote: SocketAddr,
        zone: Option<address_policy::Zone>,
    ) -> Result<(SocketAddr, ports::Binding)> {
        self.collect_paths()?;
        self.collect_connection_options();
        if self.connection_options.len() == self.socket_limit() {
            return Err(ENOBUFS);
        }
        let source = self.source_for(remote, zone);
        let socket = &self.sockets[&id];
        let (mut local, binding) = match socket.local {
            Some(local) => (local, socket.binding),
            None => (
                SocketAddr::new(source, self.connect_port(source, remote, zone)?),
                ports::Binding::Ephemeral,
            ),
        };
        if local.ip().is_unspecified() {
            local.set_ip(source);
        }
        Ok((local, binding))
    }
    // The source address of an unbound or wildcard-bound connection to
    // `remote`: the address of the port whose link the connection is scoped
    // to, else of the port whose prefix or gateway route holds the peer (the
    // longest, as route selection prefers; that route leaves through the
    // port), else the `io.*` port's, whose default route carries everything
    // else.
    fn source_for(&self, remote: SocketAddr, zone: Option<address_policy::Zone>) -> IpAddr {
        let port = match zone {
            Some(zone) => self.ports.iter().find(|p| p.link() == Some(zone.link)),
            None => self
                .ports
                .iter()
                .filter_map(|p| {
                    let own = (!crate::ip::link_local(p.address)
                        && crate::ip::network(remote.ip(), p.subnet.1)
                            == crate::ip::network(p.subnet.0, p.subnet.1))
                    .then_some(p.subnet.1);
                    let gateway = p
                        .gateways
                        .iter()
                        .filter(|(prefix, _)| prefix.contains(remote.ip()))
                        .map(|(prefix, _)| prefix.length())
                        .max();
                    Some((own.max(gateway)?, p))
                })
                .max_by_key(|&(length, _)| length)
                .map(|(_, p)| p),
        };
        port.map_or(self.local, |p| p.address)
    }

    // All active opens share admission, pre-output options, and rollback. The
    // caller must copy foreign initial data before entering this transaction.
    pub(super) fn start_connection(
        &mut self,
        id: u64,
        local: SocketAddr,
        binding: ports::Binding,
        remote: SocketAddr,
        zone: Option<address_policy::Zone>,
        initial: Option<&[u8]>,
    ) -> Result<usize> {
        self.check_address(remote)?;
        if remote.port() == 0 {
            return Err(EINVAL);
        }
        // A deferred open's link may have gone since its connect resolved it.
        if zone.is_some_and(|zone| !self.zones().any(|live| live == zone)) {
            return Err(ENODEV);
        }
        // A link-local local or peer address leaves only on its zone's link.
        let scoped = ntcp::ScopedTuple::new(ntcp::Tuple { local, remote }, zone.map(|z| z.link))
            .ok_or(EINVAL)?;
        let options = self.sockets[&id].clone();
        if let Some(authority) = options.receive_authority {
            self.endpoint
                .validate_fast_open_receive_authority(authority, local.ip())
                .map_err(engine)?;
        }
        let open = ntcp::ActiveOpenOptions {
            send_capacity: options.send_capacity,
            receive_capacity: options.receive_capacity,
            user_mss: options.user_mss,
        };
        self.collect_paths()?;
        let now = self.clock()?;
        let managed = ntcp::ManagedOpenOptions {
            transport: open,
            dscp: options.wire_tos(self.local) >> 2,
            ipv4_options: ntcp::OutgoingIpv4Options::default(),
            registration: None,
            receive_authority: options.receive_authority,
        };
        let cookie = options.server_cookie_for(remote);
        let policy = options.client_policy_for(remote, self.socket_policy.fast_open_client_policy);
        let (cid, accepted) = if let Some(initial) = initial {
            self.endpoint.enable_fast_open().map_err(engine)?;
            if let Some(host) = &mut self.host {
                self.endpoint
                    .connect_fast_open_scoped_with_path_provider(
                        now, scoped, initial, managed, cookie, policy, host,
                    )
                    .map_err(managed_error)?
            } else {
                self.endpoint
                    .connect_fast_open_with_receive_authority(
                        now,
                        local,
                        remote,
                        initial,
                        open,
                        cookie,
                        policy,
                        options.receive_authority,
                    )
                    .map_err(engine)?
            }
        } else {
            let cid = if let Some(host) = &mut self.host {
                self.endpoint
                    .connect_scoped_with_path_provider(now, scoped, managed, host)
                    .map_err(managed_error)?
            } else {
                self.endpoint
                    .connect_with_receive_authority(
                        now,
                        local,
                        remote,
                        open,
                        options.receive_authority,
                    )
                    .map_err(engine)?
            };
            (cid, 0)
        };
        if let Err(e) = self.apply_options(cid, &options) {
            // Serialized factory: no input or output can have observed this
            // active generation. Cancel it without leaving a retained slot.
            self.endpoint.cancel_unsubmitted_open(cid).map_err(engine)?;
            self.collect_paths()?;
            return Err(e);
        }
        // Publish the new attempt only after all pre-output options succeeded.
        self.sockets.get_mut(&id).unwrap().terminal_transport = None;
        self.sockets.get_mut(&id).unwrap().soft_error = 0;
        self.push_connection_options((
            cid,
            options.wire_tos(self.local),
            options.wire_discover(self.local),
            Some(options.zerocopy),
            local,
            binding,
        ));
        if let (Some(deferred), Some(peer)) = (options.local, options.deferred_peer) {
            self.port_index.defer((deferred, peer), false);
        }
        self.set_local(id, local, binding);
        self.set_handle(id, Handle::Connection(cid));
        let s = self.sockets.get_mut(&id).unwrap();
        s.connect_pending = true;
        s.deferred_peer = None;
        s.deferred_client_policy = None;
        s.zone = zone;
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
