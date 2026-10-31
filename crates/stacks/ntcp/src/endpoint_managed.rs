use super::*;
use crate::{
    FactoryRole, ManagedError, ManagedOpenOptions, ManagedPathInfo, PathFactoryRequest,
    PathProvider, PreparedPath,
};

/// What a managed Host proved about one physically submitted TCP segment of
/// an exact connection generation: the sequence span it consumed and the
/// complete IP packet and header lengths it was submitted with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorrelatedSegment {
    pub start: u32,
    pub end: u32,
    pub ip_packet_len: u32,
    pub ip_header_len: u16,
}

/// A Packet Too Big report correlated by the Host with `segment`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorrelatedPmtu {
    pub segment: CorrelatedSegment,
    /// Complete length as quoted; an IPv4 report without next-hop MTU may
    /// carry RFC 1191's legacy header-length inflation.
    pub quoted_packet_len: u32,
    /// Zero only for an IPv4 report without a next-hop MTU.
    pub candidate_mtu: u32,
    /// Whether the segment's path incarnation is still the connection's
    /// current one. Feedback about an older one is drop advice only.
    pub current_path: bool,
}

impl Endpoint {
    /// Host-correlated Packet Too Big for an exact connection generation.
    /// The Host's submission ledger is the authenticity check; this applies
    /// TCP policy (state/window, deferral, probe semantics, IPv6 floor,
    /// impossible candidates) without a second lookup in the connection's
    /// bounded sent ring, which cannot establish Host provenance and whose
    /// eviction must not negate a valid Host match. Managed endpoints only;
    /// unmanaged callers keep `pmtu_feedback`.
    pub fn correlated_pmtu_feedback(
        &mut self,
        now: Instant,
        id: ConnectionId,
        report: CorrelatedPmtu,
    ) -> Result<crate::PmtuFeedback, EndpointError> {
        if self.managed_context.is_none() {
            return Err(Error::InvalidState.into());
        }
        self.slot(id)?;
        self.reject_if_output_reserved(id)?;
        self.clock(now)?;
        let outcome = self.slots[id.slot]
            .as_mut()
            .unwrap()
            .connection
            .correlated_pmtu_feedback(now, report)?;
        self.refresh(id.slot);
        Ok(outcome)
    }

    /// Host-correlated hard/soft error for an exact connection generation,
    /// with the same TCP semantics as `network_error`. Source Quench is
    /// discarded (RFC 6633).
    pub fn correlated_network_error(
        &mut self,
        now: Instant,
        id: ConnectionId,
        segment: CorrelatedSegment,
        error: crate::NetworkError,
    ) -> Result<bool, EndpointError> {
        if self.managed_context.is_none() {
            return Err(Error::InvalidState.into());
        }
        self.slot(id)?;
        self.reject_if_output_reserved(id)?;
        self.clock(now)?;
        if error == crate::NetworkError::SourceQuench {
            return Ok(false);
        }
        self.deliver_network_error(id.slot, now, segment.start, error)
    }

    /// Enable once, before any transport is constructed. Raw constructors then
    /// fail closed; existing-owner input and independently usable raw endpoints
    /// retain their lower-level contract.
    pub fn enable_managed_paths(
        &mut self,
        context: ntcp_path::ContextId,
    ) -> Result<(), EndpointError> {
        if self.managed_context.is_some() || self.slots.iter().any(Option::is_some) {
            return Err(Error::InvalidState.into());
        }
        self.managed_context = Some(context);
        Ok(())
    }

    pub fn caller_timebase(&self) -> crate::CallerTimebase {
        self.config.connection.timebase
    }

    pub fn managed_context(&self) -> Option<ntcp_path::ContextId> {
        self.managed_context
    }

    /// Address admission for a managed Host's datagram users: the same base
    /// unicast/family checks and caller policy TCP applies to binds, opens and
    /// received packets, so a datagram flow binds, sends and receives only
    /// where a TCP connection in this network context could. Route requests
    /// are TCP source-route policy and are never admitted here.
    pub fn admits_datagram(&self, check: AddressValidation) -> bool {
        let unicast = |address| valid_address(address) && !unzoned_link_local(address);
        self.managed_context.is_some()
            && match check {
                AddressValidation::Bind { local } => unicast(local),
                AddressValidation::Open { local, remote } => {
                    unicast(local) && unicast(remote) && local.is_ipv4() == remote.is_ipv4()
                }
                AddressValidation::Incoming {
                    source,
                    destination,
                } => {
                    unicast(source)
                        && unicast(destination)
                        && source.is_ipv4() == destination.is_ipv4()
                }
                AddressValidation::Route { .. } => false,
            }
            && (self.address_policy)(check)
    }

    fn path_factory<P: PathProvider, T>(
        &mut self,
        provider: &mut P,
        request: PathFactoryRequest,
        operation: impl FnOnce(&mut Self) -> Result<T, EndpointError>,
    ) -> Result<T, ManagedError<P::Error>> {
        let context = self
            .managed_context
            .ok_or(EndpointError::Connection(Error::InvalidState))?;
        if self.factory_transaction.is_some() {
            return Err(EndpointError::Connection(Error::InvalidState).into());
        }
        self.validate_ipv4_options(
            IpMetadata {
                source: request.tuple.local.ip(),
                destination: request.tuple.remote.ip(),
            },
            request.ipv4_options,
        )?;
        let prepared = provider.prepare(request).map_err(ManagedError::Provider)?;
        if !crate::managed_path::valid_prepared(context, request, prepared) {
            provider.cancel(prepared);
            return Err(EndpointError::InvalidAddress.into());
        }
        self.factory_transaction = Some(crate::managed_path::FactoryTransaction {
            request,
            prepared,
            inserted: None,
        });
        let result = operation(self);
        let transaction = self.factory_transaction.take().unwrap();
        match transaction.inserted {
            Some(id) => provider.commit(prepared, id),
            None => provider.cancel(prepared),
        }
        result.map_err(ManagedError::Endpoint)
    }

    pub fn connect_with_path_provider<P: PathProvider>(
        &mut self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
        options: ManagedOpenOptions,
        provider: &mut P,
    ) -> Result<ConnectionId, ManagedError<P::Error>> {
        let tuple = Tuple { local, remote };
        self.active_admission(
            now,
            tuple,
            &options.transport,
            options.receive_authority,
            false,
        )?;
        let dscp = ntcp_path::Dscp::new(options.dscp)
            .map_err(|_| EndpointError::Connection(Error::InvalidArgument))?;
        let request = PathFactoryRequest {
            tuple,
            role: FactoryRole::Active,
            listener: None,
            dscp,
            ipv4_options: options.ipv4_options,
        };
        self.path_factory(provider, request, |endpoint| {
            endpoint.connect_with_receive_authority(
                now,
                local,
                remote,
                options.transport,
                options.receive_authority,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn connect_fast_open_with_path_provider<P: PathProvider>(
        &mut self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
        initial: &[u8],
        options: ManagedOpenOptions,
        cookie: Option<wire::FastOpenCookie>,
        policy: crate::FastOpenClientPolicy,
        provider: &mut P,
    ) -> Result<(ConnectionId, usize), ManagedError<P::Error>> {
        let tuple = Tuple { local, remote };
        self.active_admission(
            now,
            tuple,
            &options.transport,
            options.receive_authority,
            true,
        )?;
        let dscp = ntcp_path::Dscp::new(options.dscp)
            .map_err(|_| EndpointError::Connection(Error::InvalidArgument))?;
        let request = PathFactoryRequest {
            tuple,
            role: FactoryRole::Active,
            listener: None,
            dscp,
            ipv4_options: options.ipv4_options,
        };
        self.path_factory(provider, request, |endpoint| {
            endpoint.connect_fast_open_authorized(
                now,
                local,
                remote,
                initial,
                options.transport,
                cookie,
                policy,
                options.receive_authority,
            )
        })
    }

    /// `outgoing_dscp` is socket/listener policy, never received DSCP. Incoming
    /// TFO receive authority is still the independent local ListenerId policy.
    #[allow(clippy::too_many_arguments)]
    pub fn input_with_path_provider<P: PathProvider>(
        &mut self,
        now: Instant,
        ip: IpMetadata,
        traffic_class: u8,
        options: Ipv4Options,
        bytes: &[u8],
        metadata: crate::RxPacketMetadata,
        outgoing_dscp: u8,
        provider: &mut P,
    ) -> Result<InputDisposition, ManagedError<P::Error>> {
        if self.managed_context.is_none() {
            return Err(EndpointError::Connection(Error::InvalidState).into());
        }
        // Input the Endpoint discards (invalid/broadcast/multicast source or
        // destination, rejected received route, ...) prepares no path.
        let Some((route, segment)) = self.ingress_admission(ip, options, bytes, metadata)? else {
            return Ok(InputDisposition::Dropped);
        };
        let tuple = Tuple {
            local: SocketAddr::new(ip.destination, segment.header.destination_port),
            remote: SocketAddr::new(ip.source, segment.header.source_port),
        };
        let target = self.tuples.find(self.hash(tuple), tuple);
        let replacement = target.is_some_and(|index| {
            self.config.reuse_time_wait
                && self.slots[index].as_ref().unwrap().connection.state() == State::TimeWait
        });
        let listener = self.match_listener(tuple.local);
        if let Some(id) = listener
            && (target.is_none() || replacement)
            && segment.header.flags & (SYN | ACK | RST) == SYN
            // A full backlog/Endpoint or stale TIME-WAIT reuse is dropped by
            // the ordinary factory below without any path transaction.
            && self.passive_room(now, target.filter(|_| replacement), id, tuple, &segment)
        {
            let request = PathFactoryRequest {
                tuple,
                role: if replacement {
                    FactoryRole::TimeWaitReplacement
                } else {
                    FactoryRole::Passive
                },
                listener,
                dscp: ntcp_path::Dscp::new(outgoing_dscp)
                    .map_err(|_| EndpointError::Connection(Error::InvalidArgument))?,
                ipv4_options: OutgoingIpv4Options {
                    source_route: route,
                    ..OutgoingIpv4Options::default()
                },
            };
            self.path_factory(provider, request, |endpoint| {
                endpoint.input_with_metadata(now, ip, traffic_class, options, bytes, metadata)
            })
        } else {
            self.input_with_metadata(now, ip, traffic_class, options, bytes, metadata)
                .map_err(ManagedError::Endpoint)
        }
    }

    /// Use the Endpoint's own wildcard/exact listener precedence when selecting
    /// outbound listener policy before a managed passive factory transaction.
    pub fn matching_listener(&self, local: SocketAddr) -> Option<ListenerId> {
        self.match_listener(local)
    }

    /// Roll back an active factory before any SYN was submitted. A reservation
    /// or any committed SYN makes this unavailable: those owners must retain
    /// their ordinary final-output/TIME-WAIT lifetime instead. This permits
    /// embeddings to cancel fallible pre-output socket options without needing
    /// an output poll, another reservation lane, or a fabricated transmission.
    pub fn cancel_unsubmitted_open(&mut self, id: ConnectionId) -> Result<(), EndpointError> {
        self.reject_if_output_reserved(id)?;
        if !self.slot(id)?.connection.unsubmitted_active_open() {
            return Err(Error::InvalidState.into());
        }
        self.reclaim(id.slot);
        Ok(())
    }

    pub fn retained_tuple(&self, id: ConnectionId) -> Result<Tuple, EndpointError> {
        Ok(self.retained_slot(id)?.connection.tuple())
    }

    pub fn managed_path(&self, id: ConnectionId) -> Result<ManagedPathInfo, EndpointError> {
        let slot = self.retained_slot(id)?;
        let connection = &slot.connection;
        Ok(ManagedPathInfo {
            binding: connection.managed_path.ok_or(Error::InvalidState)?,
            tuple: connection.tuple(),
            forwarding_destination: slot
                .ipv4_options
                .source_route
                .and_then(|route| route.hops().first().copied())
                .map(IpAddr::V4)
                .unwrap_or(connection.tuple().remote.ip()),
            ip_header_len: connection.ip_header_len(),
            ordinary_ip_budget: connection.path_payload_limit() as u32
                + u32::from(connection.ip_header_len()),
        })
    }

    /// Apply without refreshing local PMTU search or creating repair work.
    /// Notification acknowledgement belongs to the provider only after success.
    pub fn apply_path_budget(
        &mut self,
        id: ConnectionId,
        path: PreparedPath,
    ) -> Result<(), EndpointError> {
        let dscp = path.snapshot.key().dscp().value();
        let slot = self.retained_slot_mut(id)?;
        slot.connection.apply_managed_budget(path)?;
        slot.dscp = dscp;
        // Only future suffix selection uses this metadata. Already returned
        // attempt bytes retain their old metadata and fail the host barrier.
        for reservation in &mut self.reservations {
            if let Some(r) = &mut reservation.current
                && r.packet.connection == Some(id)
            {
                r.packet.dscp = dscp;
            }
        }
        self.refresh(id.slot);
        Ok(())
    }

    /// Metadata for exactly the currently selected physical segment, including
    /// software-GSO and repaired suffixes, rather than aggregate byte length.
    pub fn transmit_attempt_packet(&self, attempt: crate::TransmitAttempt) -> Option<Transmit> {
        let r = self
            .reservations
            .get(attempt.reservation)?
            .current
            .as_ref()?;
        (r.attempt == Some(attempt)).then_some(r.emitted_packet)
    }

    pub fn transmit_discovery_intent(
        &self,
        attempt: crate::TransmitAttempt,
    ) -> Option<crate::DiscoveryIntent> {
        let r = self
            .reservations
            .get(attempt.reservation)?
            .current
            .as_ref()?;
        if r.attempt != Some(attempt) || r.repaired {
            return None;
        }
        r.departure?.discovery
    }
}
