use super::*;
use crate::{
    FactoryRole, ManagedError, ManagedOpenOptions, ManagedPathInfo, ManagedRoute,
    PathFactoryRequest, PathProvider, PreparedPath,
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
    /// The Host's shared estimate (complete IP packet budget) of that current,
    /// valid path incarnation when the report is applied: RFC 1191 section
    /// 5's "current PMTU estimate", against which a legacy IPv4 quote is
    /// corrected, never the connection's own estimate. `None` for an older
    /// incarnation; TCP then compares with the submitted length. A report
    /// with `current_path` and no estimate is rejected as invalid input.
    pub path_estimate: Option<u32>,
}

/// The Host's certification, made only for a backend outcome of definitely
/// Submitted (never a possible or unknown submission), of the exact complete
/// IP length and IPv4 Don't Fragment bit of the physical packet it submitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalReceipt {
    pub ip_packet_len: u32,
    /// IPv6 sources never fragment in transit; Host reports `true` for them.
    pub dont_fragment: bool,
}

/// A deferred report below proven delivery that the connection applied at
/// the quoted data's timeout, with the provenance of exactly that report.
/// Not network authority by itself: the Host publishes it only for the same
/// live owner, client and valid path incarnation, and only while it still
/// reduces the shared estimate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingPmtuApplied {
    pub(crate) binding: PreparedPath,
    pub(crate) report: CorrelatedPmtu,
    pub(crate) host_estimate: u32,
    pub(crate) applied_mtu: u32,
}
impl PendingPmtuApplied {
    /// Client and path incarnation the report was accepted under.
    pub const fn binding(self) -> PreparedPath {
        self.binding
    }
    pub const fn report(self) -> CorrelatedPmtu {
        self.report
    }
    /// The Host's normalized estimate supplied with the report.
    pub const fn host_estimate(self) -> u32 {
        self.host_estimate
    }
    /// The size the applied report derived under the connection's policy
    /// (its plateau table for a legacy IPv4 report), never the connection's
    /// estimate: a lower loss-inferred estimate stays connection-local.
    pub const fn applied_mtu(self) -> u32 {
        self.applied_mtu
    }
}

/// Delivery of an authenticated probe proved its exact size: the selected
/// departure's intent, the Host's definitely-submitted receipt retained with
/// the active probe, and no retry, timeout or invalidated size result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfirmedProbe {
    pub(crate) intent: crate::DiscoveryIntent,
    pub(crate) receipt: PhysicalReceipt,
}
impl ConfirmedProbe {
    /// Binding, exact IP length and selection time from the departure.
    pub const fn intent(self) -> crate::DiscoveryIntent {
        self.intent
    }
    pub const fn receipt(self) -> PhysicalReceipt {
        self.receipt
    }
}

/// Connection-local publication state: one pending provenance and one
/// unpublished result of each kind. Newer results replace older ones; this is
/// never a queue.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ManagedResults {
    pub(crate) pending: Option<(u64, PendingPmtuApplied)>,
    pub(crate) applied: Option<PendingPmtuApplied>,
    pub(crate) receipt: Option<((Seq, Seq, u32), crate::DiscoveryIntent, PhysicalReceipt)>,
    pub(crate) confirmed: Option<ConfirmedProbe>,
}
impl ManagedResults {
    pub(crate) fn unpublished(&self) -> bool {
        self.applied.is_some() || self.confirmed.is_some()
    }
}

impl Endpoint {
    /// Host-correlated Packet Too Big for an exact connection generation.
    /// The Host's submission ledger is the authenticity check; this applies
    /// TCP policy (state/window, deferral, probe semantics, IPv6 floor,
    /// impossible candidates) without a second lookup in the connection's
    /// bounded sent ring, which cannot establish Host provenance and whose
    /// eviction must not negate a valid Host match. Managed endpoints only;
    /// unmanaged callers keep `pmtu_feedback`. The result pairs the local
    /// class (whether this connection's estimate fell) with the size the
    /// report itself derives under the connection's configured policy,
    /// which never depends on that estimate. Every accepted class records
    /// the quoted outstanding bytes as dropped.
    pub fn correlated_pmtu_feedback(
        &mut self,
        now: Instant,
        id: ConnectionId,
        report: CorrelatedPmtu,
    ) -> Result<crate::PmtuReport, EndpointError> {
        if self.managed_context.is_none() {
            return Err(Error::InvalidState.into());
        }
        self.correlated_pmtu_report(now, id, report, None)
    }

    /// `correlated_pmtu_feedback` with the Host's normalized estimate for the
    /// report. A Deferred outcome attaches this provenance to exactly that
    /// pending report; applying it at the quoted data's timeout yields one
    /// `take_pending_pmtu_applied` result. Replacement, cumulative progress
    /// and path replacement discard the provenance.
    pub fn correlated_pmtu_feedback_with_estimate(
        &mut self,
        now: Instant,
        id: ConnectionId,
        report: CorrelatedPmtu,
        host_estimate: u32,
    ) -> Result<crate::PmtuReport, EndpointError> {
        self.correlated_pmtu_report(now, id, report, Some(host_estimate))
    }

    fn correlated_pmtu_report(
        &mut self,
        now: Instant,
        id: ConnectionId,
        report: CorrelatedPmtu,
        host_estimate: Option<u32>,
    ) -> Result<crate::PmtuReport, EndpointError> {
        if self.managed_context.is_none() {
            return Err(Error::InvalidState.into());
        }
        // Rejected before any clock or connection change.
        if report.current_path && report.path_estimate.is_none() {
            return Err(Error::InvalidArgument.into());
        }
        self.slot(id)?;
        self.reject_if_output_reserved(id)?;
        self.clock(now)?;
        let outcome = self.slots[id.slot]
            .as_mut()
            .unwrap()
            .connection
            .correlated_pmtu_feedback(now, report, host_estimate)?;
        self.refresh(id.slot);
        Ok(outcome)
    }

    /// Take the unpublished applied-pending result of a live owner generation.
    pub fn take_pending_pmtu_applied(
        &mut self,
        id: ConnectionId,
    ) -> Result<Option<PendingPmtuApplied>, EndpointError> {
        self.slot(id)?;
        Ok(self.slots[id.slot]
            .as_mut()
            .unwrap()
            .connection
            .managed_results
            .applied
            .take())
    }

    /// Whether a live owner generation holds a result to take
    /// (`take_pending_pmtu_applied` or `take_confirmed_probe`); a connection
    /// that comes to hold one is reported by `next_progress`.
    pub fn has_unpublished_results(&self, id: ConnectionId) -> Result<bool, EndpointError> {
        Ok(self.slot(id)?.connection.managed_results.unpublished())
    }

    /// The next live connection whose SND.UNA moved, or that came to hold
    /// a result to take, since this last gave it: what a provider learns
    /// from acknowledgments and results without polling every owner. When
    /// its SND.UNA moved, with the latest transmission time among the data
    /// the peer acknowledged (RFC 8985 RACK.xmit_ts), if any qualified: the
    /// forward progress RFC 4861 section 7.3.1 confirms a neighbor by. A
    /// connection is given once per change, however many came before the
    /// call.
    pub fn next_progress(&mut self) -> Option<(ConnectionId, Option<Instant>)> {
        let index = self.progress.pop()?;
        let connection = &self.slots[index].as_ref().unwrap().connection;
        let una = connection.unacknowledged();
        let delivered = if una != self.progress_una[index] {
            connection.delivered_sent_at()
        } else {
            None
        };
        self.progress_una[index] = una;
        Some((self.id(index), delivered))
    }

    /// The live connection an ICMP error quoting `tuple` and `sequence` is
    /// about, with the segment it quotes, as RFC 5927 section 4.1 and Linux
    /// accept one: the scoped tuple's connection, whose sent sequence space
    /// [SND.UNA, SND.NXT] holds the sequence. The segment's span runs from
    /// the sequence over the payload the quoted lengths leave after this
    /// connection's data-segment TCP header (`Connection::quoted_span`).
    pub fn quoted_segment(
        &self,
        tuple: ScopedTuple,
        sequence: u32,
        ip_packet_len: u32,
        ip_header_len: u16,
    ) -> Option<(ConnectionId, CorrelatedSegment)> {
        let id = self.scoped_connection_id(tuple)?;
        let payload = ip_packet_len.checked_sub(u32::from(ip_header_len))?;
        let (start, end) = self.slot(id).ok()?.connection.quoted_span(sequence, payload)?;
        Some((
            id,
            CorrelatedSegment {
                start,
                end,
                ip_packet_len,
                ip_header_len,
            },
        ))
    }

    /// Take the unpublished confirmed-probe result of a live owner generation.
    pub fn take_confirmed_probe(
        &mut self,
        id: ConnectionId,
    ) -> Result<Option<ConfirmedProbe>, EndpointError> {
        self.slot(id)?;
        Ok(self.slots[id.slot]
            .as_mut()
            .unwrap()
            .connection
            .managed_results
            .confirmed
            .take())
    }

    /// `accept_transmit` for a backend outcome of definitely Submitted. The
    /// receipt is the final-byte provenance of the physical packet: only an
    /// unfragmentable one (IPv4 DF, or IPv6) becomes size evidence for the
    /// connection's search; plain `accept_transmit` (an uncertain outcome)
    /// proves no size on a managed connection. When
    /// the attempt is a whole authenticated probe and `receipt` matches its
    /// intent (exact IP length, IPv4 DF, unchanged binding and negative
    /// revision), the receipt is retained with the active probe so that the
    /// probe's own delivery can later confirm its size.
    pub fn accept_transmit_submitted(
        &mut self,
        now: Instant,
        attempt: crate::TransmitAttempt,
        receipt: PhysicalReceipt,
    ) -> Result<bool, EndpointError> {
        let probe = self.discovery_intent(attempt).and_then(|intent| {
            let r = self.reservations[attempt.reservation].current.as_ref()?;
            (r.offset == 0).then_some((r.packet.connection?, r.departure?.start, *intent))
        });
        // The exact physical packet this attempt submits, read before
        // acceptance advances or clears the reservation.
        let physical = self.reservations[attempt.reservation]
            .current
            .as_ref()
            .filter(|r| r.attempt == Some(attempt))
            .and_then(|r| {
                let d = r.departure?;
                let count = if r.repaired { r.emitted_bytes } else { d.payload };
                Some((r.packet.connection?, d, r.offset, count))
            });
        if !self.accept_transmit(now, attempt)? {
            return Ok(false);
        }
        if let Some((id, departure, offset, count)) = physical
            && let Ok(slot) = self.retained_slot_mut(id)
        {
            slot.connection
                .certify_submission(&departure, offset, count, receipt);
        }
        if let Some((id, start, intent)) = probe
            && let Ok(slot) = self.retained_slot_mut(id)
        {
            slot.connection
                .retain_probe_receipt(Seq(start), intent, receipt);
        }
        Ok(true)
    }

    /// `accept_transmit_group` for a backend outcome of definitely
    /// Submitted. `receipt` is the provenance of each full-sized physical
    /// segment the backend cut from the aggregate; a short last segment is
    /// that packet less its missing payload. Like `accept_transmit_submitted`,
    /// it certifies every segment's size evidence. A group never carries a
    /// PMTU probe.
    pub fn accept_transmit_group_submitted(
        &mut self,
        now: Instant,
        token: crate::TransmitGroup,
        receipt: PhysicalReceipt,
    ) -> Result<bool, EndpointError> {
        let physical = self
            .reservations
            .get(token.0.reservation)
            .and_then(|slot| slot.current.as_ref())
            .and_then(|r| {
                let group = r.group.filter(|g| g.token == token)?;
                Some((r.packet.connection?, r.departure?, r.offset, group))
            });
        if !self.accept_transmit_group(now, token)? {
            return Ok(false);
        }
        if let Some((id, departure, offset, group)) = physical
            && let Some(s) = departure.segmentation
            && let Ok(slot) = self.retained_slot_mut(id)
        {
            let size = s.segment_payload_len;
            for n in 0..group.segments {
                let count = size.min(group.bytes - n * size);
                slot.connection.certify_submission(
                    &departure,
                    offset + n * size,
                    count,
                    PhysicalReceipt {
                        ip_packet_len: receipt.ip_packet_len.saturating_sub((size - count) as u32),
                        ..receipt
                    },
                );
            }
        }
        Ok(true)
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

    pub fn max_connections(&self) -> usize {
        self.config.max_connections
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
        self.admits_scoped_datagram(check, None)
    }

    /// `admits_datagram` for a scoped datagram flow: an IPv6 link-local
    /// address is admitted only with `zone`, a link of this managed context
    /// (RFC 4007: the address names an interface of that link only), and a
    /// zone only when one of the checked addresses is link-local, as for a
    /// `ScopedTuple`. None keeps the unscoped admission.
    pub fn admits_scoped_datagram(
        &self,
        check: AddressValidation,
        zone: Option<ntcp_path::LinkId>,
    ) -> bool {
        let scoped = |a: IpAddr, b: Option<IpAddr>| {
            let link_local = unzoned_link_local(a) || b.is_some_and(unzoned_link_local);
            link_local == zone.is_some()
                && zone.is_none_or(|zone| Some(zone.context()) == self.managed_context)
        };
        let unicast = |address| valid_address(address);
        self.managed_context.is_some()
            && match check {
                AddressValidation::Bind { local } => scoped(local, None),
                AddressValidation::Open { local, remote } => scoped(local, Some(remote)),
                AddressValidation::Incoming {
                    source,
                    destination,
                } => scoped(source, Some(destination)),
                AddressValidation::Route { .. } => false,
            }
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
        crate::managed_path::check_registration(&request).map_err(EndpointError::from)?;
        let scoped = ScopedTuple::new(request.tuple, request.zone)
            .ok_or(EndpointError::InvalidAddress)?;
        if !self.admits_zone(scoped) {
            return Err(EndpointError::InvalidAddress.into());
        }
        self.validate_ipv4_options(
            IpMetadata {
                source: request.tuple.local.ip(),
                destination: request.tuple.remote.ip(),
            },
            request.ipv4_options,
        )?;
        let crate::PreparedFactory {
            path: prepared,
            receive,
        } = provider.prepare(request).map_err(ManagedError::Provider)?;
        if !crate::managed_path::valid_prepared(context, request, prepared) {
            provider.cancel(prepared);
            return Err(EndpointError::InvalidAddress.into());
        }
        if !crate::managed_path::valid_receive(context, request, receive) {
            provider.cancel(prepared);
            return Err(EndpointError::Connection(Error::InvalidArgument).into());
        }
        self.factory_transaction = Some(crate::managed_path::FactoryTransaction {
            request,
            prepared,
            receive,
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
        self.connect_scoped_with_path_provider(
            now,
            ScopedTuple::unscoped(Tuple { local, remote }),
            options,
            provider,
        )
    }

    /// `connect_with_path_provider` for a scoped identity: a link-local
    /// open names the link it runs on, and its path is selected there.
    pub fn connect_scoped_with_path_provider<P: PathProvider>(
        &mut self,
        now: Instant,
        scoped: ScopedTuple,
        options: ManagedOpenOptions,
        provider: &mut P,
    ) -> Result<ConnectionId, ManagedError<P::Error>> {
        let tuple = scoped.tuple();
        let (local, remote) = (tuple.local, tuple.remote);
        let admission = self.active_admission(
            now,
            scoped,
            &options.transport,
            options.receive_authority,
            false,
        );
        self.admit_open(admission)?;
        let dscp = ntcp_path::Dscp::new(options.dscp)
            .map_err(|_| EndpointError::Connection(Error::InvalidArgument))?;
        let request = PathFactoryRequest {
            tuple,
            zone: scoped.zone(),
            role: FactoryRole::Active,
            listener: None,
            dscp,
            ipv4_options: options.ipv4_options,
            registration: options.registration,
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
        self.connect_fast_open_scoped_with_path_provider(
            now,
            ScopedTuple::unscoped(Tuple { local, remote }),
            initial,
            options,
            cookie,
            policy,
            provider,
        )
    }

    /// `connect_fast_open_with_path_provider` for a scoped identity.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_fast_open_scoped_with_path_provider<P: PathProvider>(
        &mut self,
        now: Instant,
        scoped: ScopedTuple,
        initial: &[u8],
        options: ManagedOpenOptions,
        cookie: Option<wire::FastOpenCookie>,
        policy: crate::FastOpenClientPolicy,
        provider: &mut P,
    ) -> Result<(ConnectionId, usize), ManagedError<P::Error>> {
        let tuple = scoped.tuple();
        let (local, remote) = (tuple.local, tuple.remote);
        let admission = self.active_admission(
            now,
            scoped,
            &options.transport,
            options.receive_authority,
            true,
        );
        self.admit_open(admission)?;
        let dscp = ntcp_path::Dscp::new(options.dscp)
            .map_err(|_| EndpointError::Connection(Error::InvalidArgument))?;
        let request = PathFactoryRequest {
            tuple,
            zone: scoped.zone(),
            role: FactoryRole::Active,
            listener: None,
            dscp,
            ipv4_options: options.ipv4_options,
            registration: options.registration,
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
    /// `arrival` is the link the packet arrived on: it scopes a tuple with
    /// an IPv6 link-local address and is otherwise not part of its identity.
    #[allow(clippy::too_many_arguments)]
    pub fn input_with_path_provider<P: PathProvider>(
        &mut self,
        now: Instant,
        arrival: ntcp_path::LinkId,
        ip: IpMetadata,
        traffic_class: u8,
        options: Ipv4Options,
        bytes: &[u8],
        metadata: crate::RxPacketMetadata,
        outgoing_dscp: u8,
        provider: &mut P,
    ) -> Result<InputDisposition, ManagedError<P::Error>> {
        if self.managed_context != Some(arrival.context()) {
            return Err(EndpointError::Connection(Error::InvalidState).into());
        }
        let tuple = Tuple {
            local: SocketAddr::new(ip.destination, 0),
            remote: SocketAddr::new(ip.source, 0),
        };
        let zone = crate::connection::needs_zone(tuple).then_some(arrival);
        // Input the Endpoint discards (invalid/broadcast/multicast source or
        // destination, rejected received route, ...) prepares no path.
        let Some((route, segment)) = self.ingress_admission(ip, zone, options, bytes, metadata)?
        else {
            return Ok(InputDisposition::Dropped);
        };
        let tuple = Tuple {
            local: SocketAddr::new(ip.destination, segment.header.destination_port),
            remote: SocketAddr::new(ip.source, segment.header.source_port),
        };
        let scoped = ScopedTuple { tuple, zone };
        let target = self.lookup(scoped);
        let replacement = self.config.reuse_time_wait
            && match target {
                Some(super::Target::Connection(index)) => {
                    self.slots[index].as_ref().unwrap().connection.state() == State::TimeWait
                }
                Some(super::Target::TimeWait(_)) => true,
                None => false,
            };
        // Only a connection request can open through a listener.
        let listener = ((target.is_none() || replacement)
            && segment.header.flags & (SYN | ACK | RST) == SYN)
            .then(|| self.match_listener(tuple.local, zone))
            .flatten();
        let queued = self.control.len();
        let result = if let Some(id) = listener
            // A SYN a full SYN or accept queue or Endpoint refuses is
            // dropped, and a stale TIME-WAIT reuse answered by its
            // TIME-WAIT, by the ordinary input below without any path
            // transaction.
            && self.passive_room(now, target.filter(|_| replacement), id, scoped, &segment)
        {
            let request = PathFactoryRequest {
                tuple,
                zone,
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
                registration: None,
            };
            let result = self.path_factory(provider, request, |endpoint| {
                endpoint.input_scoped(now, ip, zone, traffic_class, options, bytes, metadata)
            });
            // The provider has no path to answer on (no route, or no path
            // capacity): the listener drops the SYN, as Linux's does one it
            // finds no route for.
            if matches!(result, Err(ManagedError::Provider(_))) {
                self.count_listen_drop(false);
            }
            result
        } else {
            // Admitted and looked up above; nothing since changed either.
            self.input_admitted(
                now,
                ip,
                scoped,
                target,
                traffic_class,
                options,
                route,
                &segment,
                metadata,
            )
            .map_err(ManagedError::Endpoint)
        };
        // A stateless IPv6 reply this input queued is sized with the complete
        // header of the path the provider will place it on (on its zone's
        // link when it carries one).
        let dscp = self.config.dscp;
        for entry in self.control.iter_mut().skip(queued) {
            if entry.0.destination.is_ipv6() {
                entry.4 = provider.reply_header_len(entry.0, entry.5, dscp);
            }
        }
        // So is a TIME-WAIT record's ACK.
        if let Some(super::Target::TimeWait(index)) = target
            && ip.destination.is_ipv6()
            && self.time_wait.contains(index)
            && self.time_wait.record(index).tuple == scoped
            && self.time_wait.record(index).owes_output()
        {
            let record = self.time_wait.record(index);
            let reply = IpMetadata {
                source: ip.destination,
                destination: ip.source,
            };
            let header = provider.reply_header_len(reply, zone, record.dscp);
            self.time_wait.record_mut(index).reply_header = header;
        }
        result
    }

    /// Use the Endpoint's own wildcard/exact listener precedence when selecting
    /// outbound listener policy before a managed passive factory transaction.
    pub fn matching_listener(&self, local: SocketAddr) -> Option<ListenerId> {
        self.match_listener(local, None)
    }

    /// `matching_listener` for a scoped local address.
    pub fn matching_scoped_listener(
        &self,
        local: SocketAddr,
        zone: Option<ntcp_path::LinkId>,
    ) -> Option<ListenerId> {
        self.match_listener(local, zone)
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

    /// Transport ceilings of a retained connection, for administrative
    /// reporting. A pure read.
    pub fn transport_ceilings(
        &self,
        id: ConnectionId,
    ) -> Result<crate::TransportCeilings, EndpointError> {
        Ok(self.retained_slot(id)?.connection.transport_ceilings())
    }

    /// The connection's administrative search transition (the targeted
    /// attempt, its deferral reason or clipping bound), for administrative
    /// reporting. A pure read.
    pub fn administrative_search(
        &self,
        id: ConnectionId,
    ) -> Result<Option<crate::AdministrativeSearch>, EndpointError> {
        Ok(self.retained_slot(id)?.connection.administrative_search())
    }

    pub fn retained_tuple(&self, id: ConnectionId) -> Result<Tuple, EndpointError> {
        Ok(self.retained_slot(id)?.connection.tuple())
    }

    pub fn retained_scoped_tuple(&self, id: ConnectionId) -> Result<ScopedTuple, EndpointError> {
        Ok(self.retained_slot(id)?.connection.scoped_tuple())
    }

    // The state of a connection, released or not, until it is reclaimed.
    pub fn retained_state(&self, id: ConnectionId) -> Result<crate::State, EndpointError> {
        Ok(self.retained_slot(id)?.connection.state())
    }

    pub fn managed_path(&self, id: ConnectionId) -> Result<ManagedPathInfo, EndpointError> {
        let slot = self.retained_slot(id)?;
        let connection = &slot.connection;
        let route = self.managed_route(id)?;
        Ok(ManagedPathInfo {
            binding: connection.managed_path.ok_or(Error::InvalidState)?,
            tuple: connection.tuple(),
            zone: route.zone,
            forwarding_destination: route.forwarding_destination,
            ip_header_len: connection.ip_header_len(),
            ordinary_ip_budget: route.ordinary_ip_budget,
        })
    }

    /// The route-selecting part of `managed_path`, for providers that check
    /// it on every packet.
    pub fn managed_route(&self, id: ConnectionId) -> Result<ManagedRoute, EndpointError> {
        let slot = self.retained_slot(id)?;
        let connection = &slot.connection;
        let binding = connection
            .managed_path
            .as_ref()
            .ok_or(Error::InvalidState)?;
        Ok(ManagedRoute {
            client: binding.client,
            stamp: binding.snapshot.stamp(),
            dscp: slot.dscp,
            zone: connection.scoped_tuple().zone(),
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

    /// Read-only: whether `apply_path_budget(id, path)` would succeed now
    /// (binding authority and a budget that carries the connection's
    /// complete headers and one payload octet). Changes nothing, so a
    /// provider can validate every client before committing a change.
    pub fn validate_path_budget(&self, id: ConnectionId, path: &PreparedPath) -> Result<(), EndpointError> {
        let connection = &self.retained_slot(id)?.connection;
        connection.check_managed_budget(path)?;
        if !connection.represents_budget(path) {
            return Err(crate::Error::InvalidArgument.into());
        }
        Ok(())
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
        // The binding already applied, under the same class: nothing changes,
        // so nothing needs rescheduling. Path providers apply the current
        // binding again on every packet they authorize.
        if !slot.connection.apply_managed_budget(path)? && slot.dscp == dscp {
            return Ok(());
        }
        slot.dscp = dscp;
        // Only future suffix selection uses this metadata. Already returned
        // attempt bytes retain their old metadata and fail the host barrier.
        if let Some(index) = self.reservation_of(Some(id)) {
            self.reservations[index]
                .current
                .as_mut()
                .unwrap()
                .packet
                .dscp = dscp;
        }
        self.refresh(id.slot);
        Ok(())
    }

    /// `poll_reserved_transmit` for a managed Endpoint: a stateless IPv6
    /// reply selected now is sized with the complete IP header of the path
    /// `provider` selects for it now (`PathProvider::reply_header_len`), not
    /// the one sampled when it was queued, so a route replaced in between
    /// neither refuses a reply that fits its new path nor sizes it for the
    /// old one. A reply that cannot fit even the new path is still dropped
    /// and counted (`oversized_control_replies`).
    pub fn poll_reserved_transmit_with_path_provider<P: PathProvider>(
        &mut self,
        now: Instant,
        out: &mut [u8],
        budget: usize,
        provider: &mut P,
    ) -> Result<(PollTransmit, Option<crate::TransmitAttempt>), EndpointError> {
        let dscp = self.config.dscp;
        let mut reply = |ip, zone| provider.reply_header_len(ip, zone, dscp);
        self.poll_reserved_any(now, out, budget, Some(&mut reply))
    }

    /// `poll_reserved_stateless_transmit` with drain-time reply sizing
    /// (`poll_reserved_transmit_with_path_provider`).
    pub fn poll_reserved_stateless_transmit_with_path_provider<P: PathProvider>(
        &mut self,
        now: Instant,
        out: &mut [u8],
        budget: usize,
        provider: &mut P,
    ) -> Result<(PollTransmit, Option<crate::TransmitAttempt>), EndpointError> {
        let dscp = self.config.dscp;
        let mut reply = |ip, zone| provider.reply_header_len(ip, zone, dscp);
        self.poll_reserved_selected(now, out, budget, None, None, Some(&mut reply))
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

    /// The link scoping exactly the currently selected attempt's packet,
    /// present only when one of its addresses is IPv6 link-local: its
    /// connection's zone, or for a stateless reply the arrival link of the
    /// input that caused it. Such a packet leaves only on that link. None
    /// when `attempt` is not current.
    pub fn transmit_attempt_zone(
        &self,
        attempt: crate::TransmitAttempt,
    ) -> Option<Option<ntcp_path::LinkId>> {
        let r = self
            .reservations
            .get(attempt.reservation)?
            .current
            .as_ref()?;
        (r.attempt == Some(attempt)).then_some(r.zone)
    }

    /// Count the current stateless reply `attempt` as undeliverable: the
    /// link of its zone was removed or replaced, so it can leave on no link.
    /// Counts each reservation once however often its provider refuses it;
    /// the embedding then discards the certainly unsubmitted attempt
    /// (`reject_unsubmitted`). False, counting nothing, for a connection's
    /// packet, an unscoped reply or an attempt that is not current.
    pub fn count_undeliverable_reply(&mut self, attempt: crate::TransmitAttempt) -> bool {
        let Some(r) = self
            .reservations
            .get_mut(attempt.reservation)
            .and_then(|slot| slot.current.as_mut())
        else {
            return false;
        };
        if r.attempt != Some(attempt) || r.packet.connection.is_some() || r.zone.is_none() {
            return false;
        }
        if !r.undeliverable {
            r.undeliverable = true;
            self.undeliverable_control += 1;
        }
        true
    }

    pub fn transmit_discovery_intent(
        &self,
        attempt: crate::TransmitAttempt,
    ) -> Option<crate::DiscoveryIntent> {
        self.discovery_intent(attempt).copied()
    }

    // The intent in place: only a probe's is copied out.
    fn discovery_intent(&self, attempt: crate::TransmitAttempt) -> Option<&crate::DiscoveryIntent> {
        let r = self
            .reservations
            .get(attempt.reservation)?
            .current
            .as_ref()?;
        if r.attempt != Some(attempt) || r.repaired {
            return None;
        }
        r.departure.as_ref()?;
        r.discovery.as_ref()
    }
}
