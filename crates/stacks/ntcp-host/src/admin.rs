//! Owner-authorized path administration (RFC 1191 section 6.6, RFC 8201
//! section 5.6). Mutable Host access is owner authority: the owner issues an
//! `Administration` capability bound to this Host instance and hands it to a
//! delegated administrator (the local control server) instead of the Host.
//! Route and path identifiers are provenance, never authority.
//!
//! Scope. Per-route and per-path policy (discovery disable, administrative
//! estimate) is stored by `PathService`; Host-wide administration covers the
//! IPv4 plateau table (the validated `PathService` replacement every user
//! reads) and RFC 4821 search aging (each connection's `SearchAging`, at
//! least 300 seconds or infinity); both apply to every existing and future
//! user through the serialized transaction. Validation here is read-only.
//! `admin_apply` is the serialized transaction: it validates every client
//! of every affected path read-only, then stores policy, applies its
//! estimate operation (see `ntcp_path` administration) and brings every
//! client to the new snapshot in the same call: a downward estimate lowers
//! each affected path's accepted estimate with a fresh negative revision
//! and the Host's 600-second hold; an equal estimate is a no-op; an
//! upward estimate changes no accepted estimate, hold or confirmed bound and
//! is delivered to clients only as a search cap and a once-per-value
//! targeted attempt (TCP PLPMTUD and the Echo adjunct), whose deferral or
//! clip `admin_clients` reports. A discovery disable (RFC 1191 6.6, RFC
//! 8201 5.6) stops every probe on the path (TCP, the adjunct, UDP Probe
//! mode, and at the submission barrier) and TCP size-search changes, and
//! on IPv6 caps the path's packet budget, hence every physical packet, at
//! the 1280-octet minimum link MTU. No change is refused for output in
//! flight: a TCP reservation is always withdrawable (the submission barrier
//! refuses an oversized or probe attempt and the connection rebuilds the
//! unsent suffix), and best-effort stateless and ICMP output is revalidated
//! where it leaves, exactly as after a trusted PTB decrease, so a remote
//! peer cannot hold the owner's restriction off.

use crate::udp::UdpFlowId;
use crate::{Error, Host, path};
use core::sync::atomic::{AtomicU64, Ordering};
use ntcp::{ConnectionId, Endpoint, Instant, SearchAging, TransmitAttempt, TransportCeilings};
use ntcp::PreparedPath;
use path::{
    AdminChange, AdminPlan, AdminTarget, EffectivePolicy, IpPrefix, Ipv4Plateaus, PathAdministration,
    PathId, PathSnapshot, PathStatus, RouteAdministration, RouteId,
};

// Process-wide Host instance identities: a capability names the Host that
// issued it, not a caller-chosen ContextId (two Hosts may share one).
static INSTANCES: AtomicU64 = AtomicU64::new(0);

pub(crate) fn next_instance() -> Result<u64, Error> {
    INSTANCES
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        .map(|n| n + 1)
        .map_err(|_| Error::Capacity)
}

/// Opaque administration capability bound to the Host instance that issued
/// it. It cannot be constructed outside this crate; another Host rejects it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Administration {
    instance: u64,
}

/// An administrative client of a path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminClient {
    Tcp(ConnectionId),
    Udp(UdpFlowId),
    /// A stateless output lease (reset, challenge ACK or reply).
    OutputLease(TransmitAttempt),
    /// The Host's ICMP Echo adjunct, while it keeps sizing state (demand,
    /// search and confirmed lower bound) for the path.
    Adjunct,
    /// The Host's Echo service and ICMP output (configured ICMP output):
    /// replies and errors to the path's destination are sized at drain by
    /// the path's connectionless size and budget. `queued` messages are
    /// routed over the path now. Its report's `usable_ip_packet` is the
    /// smallest size the drain uses for any of them: while one carries a
    /// source route, the size that is never raised by the adjunct-confirmed
    /// bound, which understates an option-free message's size on a path
    /// with such a bound; otherwise the connectionless size.
    Echo { queued: usize },
}

/// One client's usable size and transport ceilings, reported separately
/// from the path's accepted shared estimate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientReport {
    pub client: AdminClient,
    /// Complete IP packet octets this client uses after its local
    /// validation (TCP: its ordinary packet budget; UDP and the adjunct: the
    /// connectionless datagram size; leases: the shared budget).
    pub usable_ip_packet: Option<u32>,
    /// TCP connections only.
    pub transport: Option<TransportCeilings>,
    /// TCP connections and the adjunct: deferred or clipped growth toward
    /// the path's administrative estimate and its reason.
    pub search: Option<ntcp::AdministrativeSearch>,
}

/// A change validated read-only against this Host instance. Stage-specific
/// client validation reads it through `admin_affected`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdminCandidate {
    instance: u64,
    plan: AdminPlan,
}

impl AdminCandidate {
    // Tests inspect the validated plan (e.g. that an identical set is a
    // no-op); production reads the field.
    #[cfg(test)]
    pub(crate) const fn plan(self) -> AdminPlan {
        self.plan
    }
}

/// One path a candidate would affect, with its current and candidate
/// combined policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AffectedPath {
    pub path: PathId,
    pub current: EffectivePolicy,
    pub candidate: EffectivePolicy,
}

impl Host {
    /// Owner entrypoint: issue the administration capability of this Host.
    pub fn administration(&mut self) -> Administration {
        Administration {
            instance: self.instance,
        }
    }

    pub(crate) fn authorize(&self, capability: &Administration) -> Result<(), Error> {
        if capability.instance != self.instance {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    pub fn admin_routes<'a>(
        &'a self,
        capability: &Administration,
    ) -> Result<impl Iterator<Item = RouteAdministration> + 'a, Error> {
        self.authorize(capability)?;
        Ok(self.paths.route_administrations())
    }

    /// The single live route with exactly this destination prefix.
    pub fn admin_select_route(
        &self,
        capability: &Administration,
        destination: IpPrefix,
    ) -> Result<RouteId, Error> {
        self.authorize(capability)?;
        Ok(self.paths.select_route(destination)?)
    }

    pub fn admin_paths<'a>(
        &'a self,
        capability: &Administration,
    ) -> Result<impl Iterator<Item = PathAdministration> + 'a, Error> {
        self.authorize(capability)?;
        Ok(self.paths.path_administrations())
    }

    pub fn admin_path(
        &self,
        capability: &Administration,
        path: PathId,
    ) -> Result<PathAdministration, Error> {
        self.authorize(capability)?;
        Ok(self.paths.path_administration(path)?)
    }

    /// Clients bound to `path`: TCP bindings, UDP flows, output leases, the
    /// Echo adjunct and the Echo service.
    pub fn admin_clients<'a>(
        &'a self,
        capability: &Administration,
        endpoint: &'a Endpoint,
        path: PathId,
    ) -> Result<impl Iterator<Item = ClientReport> + 'a, Error> {
        self.authorize(capability)?;
        self.check_endpoint(endpoint)?;
        self.paths.path_administration(path)?;
        let tcp = self.bindings.iter().flatten().filter_map(move |binding| {
            let owner = binding.owner?;
            (binding.prepared.snapshot.path() == path).then(|| ClientReport {
                client: AdminClient::Tcp(owner),
                usable_ip_packet: endpoint
                    .managed_path(owner)
                    .ok()
                    .map(|info| info.ordinary_ip_budget),
                transport: endpoint.transport_ceilings(owner).ok(),
                search: endpoint.administrative_search(owner).ok().flatten(),
            })
        });
        let udp = self.udp.flows_on(path).map(|(flow, prepared)| ClientReport {
            client: AdminClient::Udp(flow),
            usable_ip_packet: self.udp_flow_size(flow, prepared.snapshot).ok(),
            transport: None,
            search: None,
        });
        let leases = self.leases.iter().flatten().filter_map(move |lease| {
            (lease.prepared.snapshot.path() == path).then(|| ClientReport {
                client: AdminClient::OutputLease(lease.attempt),
                usable_ip_packet: lease.prepared.snapshot.ip_packet_budget().ok(),
                transport: None,
                search: None,
            })
        });
        let adjunct = self.adjunct.administrative_search(path).map(|search| ClientReport {
            client: AdminClient::Adjunct,
            usable_ip_packet: self
                .paths
                .path_snapshot(path)
                .ok()
                .and_then(|snapshot| self.connectionless_size(snapshot).ok()),
            transport: None,
            search,
        });
        let key = self.paths.path_snapshot(path)?.key();
        let echo = self.icmp_output_on(key).map(|queued| ClientReport {
            client: AdminClient::Echo { queued },
            // The smallest size the drain uses for a queued message: a
            // source-routed one is never sized by the adjunct-confirmed
            // bound of the direct path, an option-free one may be.
            usable_ip_packet: self.paths.path_snapshot(path).ok().and_then(|snapshot| {
                if self.icmp_source_routed_on(key) {
                    self.connectionless_unconfirmed_size(snapshot).ok()
                } else {
                    self.connectionless_size(snapshot).ok()
                }
            }),
            transport: None,
            search: None,
        });
        Ok(tcp.chain(udp).chain(leases).chain(adjunct).chain(echo))
    }

    pub fn admin_ipv4_plateaus(&self, capability: &Administration) -> Result<Ipv4Plateaus, Error> {
        self.authorize(capability)?;
        Ok(self.paths.ipv4_plateaus())
    }

    /// Read-only candidate validation at caller time `now`: authority, exact
    /// target, expected generation, value bounds, counters and the hold
    /// arithmetic of a downward restriction (now + the Host's 600-second
    /// decrease hold). Nothing changes on any outcome.
    pub fn admin_validate(
        &self,
        capability: &Administration,
        now: ntcp::Instant,
        change: AdminChange,
    ) -> Result<AdminCandidate, Error> {
        self.authorize(capability)?;
        Ok(AdminCandidate {
            instance: self.instance,
            plan: self.paths.prepare_admin(change, now, self.decrease_hold()?)?,
        })
    }

    /// Valid paths the candidate would affect: every current path resolved
    /// through a route target, or the exact path target.
    pub fn admin_affected<'a>(
        &'a self,
        capability: &Administration,
        candidate: &AdminCandidate,
    ) -> Result<impl Iterator<Item = AffectedPath> + 'a, Error> {
        self.authorize(capability)?;
        if candidate.instance != self.instance {
            return Err(Error::Unauthorized);
        }
        let change = candidate.plan.change();
        Ok(self.paths.path_administrations().filter_map(move |admin| {
            if admin.snapshot.status() != PathStatus::Valid {
                return None;
            }
            let path = admin.snapshot.path();
            let (route, exact) = match change.target {
                AdminTarget::Route(route) if admin.snapshot.key().route() == route => {
                    (change.policy, admin.policy)
                }
                AdminTarget::Path(target) if target == path => {
                    (admin.route_policy.unwrap_or_default(), change.policy)
                }
                _ => return None,
            };
            Some(AffectedPath {
                path,
                current: admin.effective,
                candidate: EffectivePolicy::of(route, exact),
            })
        }))
    }

    /// The serialized administration transaction for a validated candidate.
    ///
    /// Validation (read-only, nothing changes on failure): the capability
    /// and candidate belong to this Host and the service is unchanged since
    /// `admin_validate`; then every affected path's candidate snapshot is
    /// checked against every client on it: each live TCP binding must accept
    /// the snapshot (`Endpoint::validate_path_budget`: binding authority and
    /// a complete-header budget carrying its IP and TCP headers with options
    /// and one payload octet) and still forward over the path.
    ///
    /// Best-effort output never blocks a change (budget-only reductions keep
    /// the reservation-safe application a trusted PTB decrease uses): a held
    /// stateless output lease (reset, challenge ACK) is revalidated at its
    /// submission and refused by the barrier when its final bytes no longer
    /// fit, and a queued ICMP message (Echo Reply or error) is sized at
    /// emission by `icmp_output`, which discards and counts unsent one that
    /// can no longer leave. An administrative budget reduction (a downward
    /// estimate, and the sending limit a discovery disable applies: on IPv4
    /// 576 octets through a gateway or forwarder or the owner's value, on
    /// IPv6 1280 octets) is never refused as busy either: it keeps the
    /// reservation-safe budget application of a trusted PTB decrease, so an
    /// indivisible held reservation larger than the new budget (a SYN
    /// carrying TFO data, a D-SACK pair) fails its owner exactly as after
    /// that decrease (the native runtime abandons the transmission on
    /// `ReservationMtuTooSmall`), while other connections on the path
    /// continue. A SYN sized without a peer MSS already fits 576 (IPv4) or
    /// 1280 (IPv6) octets, so only an owner value below its size affects it.
    ///
    /// Apply (after validation, nothing fallible is left): store the policy
    /// and estimate operation, bring each TCP binding on an affected path to
    /// its new snapshot by budget-only application (reserved output keeps
    /// its submitted prefix; oversized unsent bytes fail the submission
    /// barrier and are rebuilt) and acknowledge exactly that stamp, update
    /// each UDP flow's coalesced change notification, and deliver the policy
    /// to the Echo adjunct (a disable voids its outstanding probe's size
    /// result, so a late reply publishes nothing while a correlated PTB for
    /// it is still a trusted decrease). A binding left dirty by an earlier
    /// deferred topology change keeps that notification for
    /// `service_changes`. Returns the target's new policy generation.
    pub fn admin_apply(
        &mut self,
        capability: &Administration,
        endpoint: &mut Endpoint,
        candidate: AdminCandidate,
    ) -> Result<u64, Error> {
        self.authorize(capability)?;
        if candidate.instance != self.instance {
            return Err(Error::Unauthorized);
        }
        self.check_endpoint(endpoint)?;
        for (current, next) in self.paths.preview_admin(candidate.plan)? {
            if current != next {
                self.admin_check_clients(endpoint, next)?;
            }
        }
        // Infallible from here: the plan is current (checked by
        // preview_admin) and every client accepted its snapshot.
        let since = self.paths.revision();
        self.paths.commit_admin(candidate.plan)?;
        self.admin_fanout(endpoint, since);
        Ok(candidate.plan.generation())
    }

    /// Replace the Host-wide IPv4 plateau table (RFC 1191 section 7) every
    /// user reads, through the serialized transaction: the validated
    /// `PathService` replacement (nothing changes when it fails), then every
    /// TCP binding and UDP flow is brought to its new snapshot at once. An
    /// identical table is a no-op.
    pub fn admin_set_ipv4_plateaus(
        &mut self,
        capability: &Administration,
        endpoint: &mut Endpoint,
        plateaus: Ipv4Plateaus,
    ) -> Result<(), Error> {
        self.authorize(capability)?;
        self.check_endpoint(endpoint)?;
        let since = self.paths.revision();
        self.paths.set_ipv4_plateaus(plateaus)?;
        self.admin_fanout(endpoint, since);
        Ok(())
    }

    /// The owner search aging every TCP connection with PLPMTUD uses, once
    /// set (None: each connection keeps its creation policy).
    pub fn admin_search_aging(&self, capability: &Administration) -> Result<Option<SearchAging>, Error> {
        self.authorize(capability)?;
        Ok(self.search_aging)
    }

    /// Set the search aging (RFC 4821 section 7.3: at least 300 seconds, or
    /// infinity) of every existing TCP connection with PLPMTUD and of every
    /// future one (adopted by `service_changes` before its first output).
    /// Every existing connection is validated read-only first; on failure
    /// nothing changes. Mandatory PTB holds and failure cooldowns are
    /// separate timers and are never shortened. An identical value is a
    /// no-op.
    pub fn admin_set_search_aging(
        &mut self,
        capability: &Administration,
        endpoint: &mut Endpoint,
        now: Instant,
        aging: SearchAging,
    ) -> Result<(), Error> {
        self.authorize(capability)?;
        self.check_endpoint(endpoint)?;
        let units = endpoint.caller_timebase().units_per_second;
        if let SearchAging::Seconds(seconds) = aging
            && (seconds < 300 || seconds.checked_mul(units).is_none())
        {
            return Err(Error::Endpoint(ntcp::Error::InvalidArgument.into()));
        }
        for owner in self.bindings.iter().flatten().filter_map(|b| b.owner) {
            // Released connections (no live handle) have no search left.
            if endpoint.pmtud_policy(owner).is_ok_and(|p| p.is_some()) {
                endpoint.validate_search_aging(now, owner, aging)?;
            }
        }
        self.search_aging = Some(aging);
        for index in 0..self.bindings.len() {
            if let Some(owner) = self.bindings[index].and_then(|b| b.owner) {
                // Validated above.
                let _ = self.apply_search_aging(endpoint, now, owner);
            }
        }
        Ok(())
    }

    // Apply the owner search aging to one live connection with PLPMTUD
    // whose policy differs from it.
    pub(crate) fn apply_search_aging(
        &mut self,
        endpoint: &mut Endpoint,
        now: Instant,
        owner: ConnectionId,
    ) -> Result<(), Error> {
        let Some(aging) = self.search_aging else {
            return Ok(());
        };
        match endpoint.pmtud_policy(owner) {
            Ok(Some(policy)) if policy.search_aging != aging => {
                Ok(endpoint.set_search_aging(now, owner, aging)?)
            }
            _ => Ok(()),
        }
    }

    // Bring each live TCP binding whose path this change produced a new
    // snapshot for (stamped with the service revision the change committed,
    // when it advanced past `since`) to that snapshot by budget-only
    // application, and every UDP flow and the adjunct to its newest
    // snapshot. Any other dirty binding (an earlier deferred topology
    // change) keeps its notification for `service_changes`, whose refresh
    // performs the forwarding and rebind checks; so does an affected
    // binding whose outgoing selection changed or that fails to apply.
    fn admin_fanout(&mut self, endpoint: &mut Endpoint, since: u64) {
        let revision = self.paths.revision();
        for index in 0..self.bindings.len() {
            if revision == since {
                break;
            }
            let Some(binding) = self.bindings[index] else {
                continue;
            };
            let Some(owner) = binding.owner else {
                continue;
            };
            if !endpoint.connection_exists(owner) && !endpoint.is_output_reserved(owner) {
                // Released by the next `collect`.
                continue;
            }
            if !self.paths.is_dirty(binding.prepared.client).unwrap_or(false) {
                continue;
            }
            let Ok(snapshot) = self.paths.snapshot(binding.prepared.client) else {
                continue;
            };
            if snapshot.version() != revision
                || snapshot.status() != PathStatus::Valid
                || !endpoint.managed_path(owner).is_ok_and(|current| {
                    current.binding.client == binding.prepared.client
                        && crate::scoped(current.forwarding_destination, current.zone)
                            .is_ok_and(|via| self.forwards_via(snapshot.key(), via))
                })
                || self.forwarding(&snapshot).is_err()
            {
                continue;
            }
            let prepared = PreparedPath {
                client: binding.prepared.client,
                snapshot,
            };
            if endpoint.apply_path_budget(owner, prepared).is_ok() {
                self.bindings[index].as_mut().unwrap().prepared = prepared;
                let _ = self.paths.acknowledge(prepared.client, snapshot.stamp());
            }
        }
        for slot in 0..self.udp.limits.flows {
            let _ = self.udp_service(slot);
        }
        self.adjunct_observe();
    }

    // Read-only validation of every TCP binding of one affected path at its
    // candidate snapshot. Stateless and ICMP output is revalidated where it
    // leaves and never fails a change.
    fn admin_check_clients(&self, endpoint: &Endpoint, next: PathSnapshot) -> Result<(), Error> {
        let path = next.path();
        for binding in self.bindings.iter().flatten() {
            let Some(owner) = binding.owner else {
                continue;
            };
            if !endpoint.connection_exists(owner) && !endpoint.is_output_reserved(owner) {
                continue;
            }
            if self.paths.snapshot(binding.prepared.client)?.path() != path {
                continue;
            }
            endpoint.validate_path_budget(
                owner,
                PreparedPath {
                    client: binding.prepared.client,
                    snapshot: next,
                },
            )?;
            self.forwarding(&next)?;
        }
        Ok(())
    }
}
