//! Owner administrative policy of forwarding routes and resolved paths
//! (RFC 1191 section 6.6, RFC 8201 section 5.6). This module stores,
//! validates and reports policy and applies its estimate operations, which
//! compare the combined administrative estimate of each affected path with
//! that path's accepted network estimate (learned or unlearned), never with
//! an earlier administrative request or a transport-clipped size:
//! - below it (downward): a trusted administrative restriction that lowers
//!   the accepted estimate at once, advances the negative revision, extends
//!   the hold to max(old, now + hold) and dirties every client of the path;
//!   while set, the value also caps `confirm_delivery`;
//! - at or above it (equal or upward): stored as the cached administrative
//!   estimate; no accepted estimate, hold or negative revision changes.
//!   Growth needs real delivery evidence through `confirm_delivery`;
//! - clear: removes the constraint without cancelling holds or restoring an
//!   older larger accepted value.
//!
//! Every change of a path's effective administrative estimate or discovery
//! policy is delivered to its clients in its snapshot (a new version, dirty
//! clients), so packetization layers can cap their size search with it.
//! A route keeps its policy and conservative admission state in its
//! preallocated record: the outstanding administrative hold and the lowest
//! administrative value its estimate actually imposed on a path through it
//! (a downward set on a live path, or a path installed under the value).
//! An upward set raises neither; clearing the route's estimate drops the
//! retained restriction (the owner withdrew the value) and keeps the hold.
//! A path installed through the route later (after idle eviction or for
//! another destination) starts from its unlearned first-hop estimate capped
//! by the smaller of that retained restriction and the current
//! administrative value, as a restriction with administrative provenance
//! (never as learned state), and with the outstanding hold, so
//! reacquisition never promotes a deferred upward request. A live
//! incarnation's restriction is kept through later upward sets and clears
//! and relaxes only through confirmed delivery on that incarnation, so a
//! clear never restores an older larger accepted value on a live path.

use super::*;

/// Owner policy attached to one forwarding route or one exact resolved path.
/// The empty policy (`Default`) means "no administrative constraint".
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AdminPolicy {
    /// The RFC 1191 6.6 / RFC 8201 5.6 route flag: PMTU discovery is not
    /// done on paths through this target.
    pub discovery_disabled: bool,
    /// The owner's cached administrative PMTU estimate, in complete IP packet
    /// octets. It is never learned delivery proof and is reported separately
    /// from the accepted network estimate.
    pub estimate: Option<u32>,
}

impl AdminPolicy {
    pub const fn is_empty(self) -> bool {
        !self.discovery_disabled && self.estimate.is_none()
    }
}

/// Which administered object a constraint comes from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicySource {
    Route,
    Path,
    /// Both carry the constraint; for an estimate the values are equal.
    RouteAndPath,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdministrativeEstimate {
    pub value: u32,
    pub source: PolicySource,
}

/// Route and exact-path policy combined. Administrative restrictions
/// intersect: a disable on either object disables discovery (a route disable
/// dominates a path without one), and the smaller estimate governs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EffectivePolicy {
    pub discovery_disabled: Option<PolicySource>,
    pub estimate: Option<AdministrativeEstimate>,
}

impl EffectivePolicy {
    /// Combine a route policy with an exact-path overlay.
    pub fn of(route: AdminPolicy, path: AdminPolicy) -> Self {
        let source = |r: bool, p: bool| match (r, p) {
            (true, true) => Some(PolicySource::RouteAndPath),
            (true, false) => Some(PolicySource::Route),
            (false, true) => Some(PolicySource::Path),
            (false, false) => None,
        };
        let estimate = match (route.estimate, path.estimate) {
            (Some(r), Some(p)) => Some(AdministrativeEstimate {
                value: r.min(p),
                source: source(r <= p, p <= r).unwrap(),
            }),
            (Some(value), None) => Some(AdministrativeEstimate {
                value,
                source: PolicySource::Route,
            }),
            (None, Some(value)) => Some(AdministrativeEstimate {
                value,
                source: PolicySource::Path,
            }),
            (None, None) => None,
        };
        Self {
            discovery_disabled: source(route.discovery_disabled, path.discovery_disabled),
            estimate,
        }
    }
}

/// Where the accepted network estimate of a path comes from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EstimateProvenance {
    /// Nothing learned: the largest first-hop budget this path incarnation
    /// has exposed (RFC 1191 6.2's presumed initial value).
    Unlearned,
    /// A trusted decrease (validated PTB or an administrative restriction
    /// applied to the live path) or a confirmed delivery recorded a learned
    /// ceiling.
    Learned,
    /// The learned ceiling was last raised by a successful probe an
    /// application flow holding the owner-granted shared-writer capability
    /// reported: owner-trusted application evidence, not Host-observed proof.
    OwnerTrustedApplication,
    /// The route's retained administrative restriction caps the unlearned
    /// or learned network estimate of a path installed after it was set: an
    /// owner value, never learned delivery proof.
    Administrative,
}

/// The network estimate an administrative set is compared with: never a
/// previous administrative request or a transport-clipped size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedEstimate {
    pub value: u32,
    pub provenance: EstimateProvenance,
}

/// An administered object, named by its opaque identifier. Route
/// identifiers carry the route generation and path identifiers the path
/// incarnation, so a replaced route or an evicted path is a stale target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminTarget {
    Route(RouteId),
    Path(PathId),
}

/// Compare-and-set request replacing the complete policy of one target.
/// `expected` is the target's current policy generation (0 when it never
/// carried policy); clearing is the empty policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdminChange {
    pub target: AdminTarget,
    pub expected: u64,
    pub policy: AdminPolicy,
}

/// A change validated read-only by `prepare_admin`. Only `commit_admin`
/// consumes it, and only while the service is unchanged since validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdminPlan {
    change: AdminChange,
    revision: u64,
    admin_revision: u64,
    generation: u64,
    // Absolute hold deadline when the change restricts some path below its
    // accepted estimate (checked at validation), else None.
    restriction: Option<u64>,
}

impl AdminPlan {
    pub const fn change(self) -> AdminChange {
        self.change
    }
    /// True when the target already carries exactly this policy: committing
    /// changes nothing (no generation advance).
    pub const fn is_noop(self) -> bool {
        self.generation == self.change.expected
    }
    /// The target's policy generation after commit.
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteAdministration {
    pub route: RouteId,
    pub definition: Route,
    pub policy: AdminPolicy,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathAdministration {
    pub snapshot: PathSnapshot,
    /// Client pins; the administrative pin is `policy` being nonempty.
    pub pins: usize,
    pub policy: AdminPolicy,
    pub generation: u64,
    /// The policy of the route the path was resolved through, while that
    /// exact route generation is live.
    pub route_policy: Option<AdminPolicy>,
    pub effective: EffectivePolicy,
    /// None once the path is invalidated.
    pub accepted: Option<AcceptedEstimate>,
}

// Per route slot. Policy belongs to exactly one route generation; a record
// whose generation does not match the live route is empty, so a removal
// followed by an unrelated addition inherits nothing.
#[derive(Clone, Copy, Default)]
pub(in crate::service) struct RouteAdmin {
    route_generation: u64,
    pub(super) policy: AdminPolicy,
    generation: u64,
    // Outstanding administrative hold (absolute, caller timebase) of the
    // latest downward restriction through this route: future paths start
    // with retry_not_before at least this. Clearing the policy keeps it; a
    // past deadline has no effect.
    pub(super) hold: u64,
    // The lowest value the route's administrative estimate imposed on a
    // path through it (a downward set on a live path or the installation of
    // a path under the value): future paths start capped by it. A lower
    // imposed value lowers it and upward sets keep it, since only confirmed
    // delivery on a path incarnation relaxes a restriction and that
    // evidence is the incarnation's own, never route-wide; clearing the
    // route's estimate drops it (the owner withdrew the value).
    pub(super) restriction: Option<u32>,
    // Preallocated staging for mapped bulk replacement (no allocation).
    staged: Option<(AdminPolicy, u64, u64, Option<u32>)>,
}

#[derive(Clone, Copy, Default)]
pub(in crate::service) struct PathAdmin {
    pub(super) policy: AdminPolicy,
    pub(super) generation: u64,
}

impl PathService {
    pub(in crate::service) fn route_admin(&self, route: RouteId) -> Option<RouteAdmin> {
        let record = *self.route_admin.get(route.0.slot)?;
        (route.0.context == self.context
            && record.route_generation == route.0.generation
            && self.route(route).is_ok())
        .then_some(record)
    }

    pub fn route_administration(&self, route: RouteId) -> Result<RouteAdministration, Error> {
        let definition = self.route(route)?;
        let record = self.route_admin(route).unwrap_or_default();
        Ok(RouteAdministration {
            route,
            definition,
            policy: record.policy,
            generation: record.generation,
        })
    }

    /// Every live route in slot order. Bounded, allocation-free.
    pub fn route_administrations(&self) -> impl Iterator<Item = RouteAdministration> + '_ {
        self.routes
            .slots
            .iter()
            .enumerate()
            .filter_map(|(slot, record)| {
                record.value.map(|_| RouteId(Handle {
                    context: self.context,
                    slot,
                    generation: record.generation,
                }))
            })
            .map(|route| self.route_administration(route).unwrap())
    }

    /// A destination-prefix selector names a route only when exactly one live
    /// route has that destination prefix; never an implicit broadcast.
    pub fn select_route(&self, destination: IpPrefix) -> Result<RouteId, Error> {
        let mut found = None;
        for route in self.route_administrations() {
            if route.definition.destination == destination {
                if found.is_some() {
                    return Err(Error::Ambiguous);
                }
                found = Some(route.route);
            }
        }
        found.ok_or(Error::NoRoute)
    }

    pub fn path_administration(&self, path: PathId) -> Result<PathAdministration, Error> {
        let cached = self.paths.get(self.context, path.0)?;
        let snapshot = cached.snapshot;
        let route_policy = self.route_admin(snapshot.key.route).map(|r| r.policy);
        let valid = snapshot.status == PathStatus::Valid;
        Ok(PathAdministration {
            snapshot,
            pins: cached.pins,
            policy: cached.admin.policy,
            generation: cached.admin.generation,
            route_policy,
            effective: EffectivePolicy::of(
                route_policy.unwrap_or_default(),
                cached.admin.policy,
            ),
            accepted: valid.then(|| AcceptedEstimate {
                value: cached.accepted_estimate(),
                provenance: if cached.accepted_estimate() < cached.network_estimate() {
                    EstimateProvenance::Administrative
                } else if snapshot.learned_mtu.is_some()
                    && snapshot.learned_mtu == cached.application_mtu
                {
                    EstimateProvenance::OwnerTrustedApplication
                } else if snapshot.learned_mtu.is_some() {
                    EstimateProvenance::Learned
                } else {
                    EstimateProvenance::Unlearned
                },
            }),
        })
    }

    /// Every cached path incarnation (pinned, idle or invalidated but still
    /// pinned) in slot order. Bounded, allocation-free.
    pub fn path_administrations(&self) -> impl Iterator<Item = PathAdministration> + '_ {
        self.paths
            .slots
            .iter()
            .filter_map(|record| record.value)
            .map(|cached| self.path_administration(cached.snapshot.path()).unwrap())
    }

    /// Service-wide nonwrapping administrative clock: the source of policy
    /// generations. Independent of `revision`, so storing policy never
    /// dirties a client.
    pub const fn admin_revision(&self) -> u64 {
        self.admin_revision
    }

    // The snapshot of the cached path in slot `index` with `change`
    // applied, when the change affects it, and whether the change restricts
    // it below its accepted estimate (the caller then records the negative
    // revision). `generation` is the change's policy generation and
    // `not_before` the restriction's hold deadline.
    fn admin_refresh(
        &self,
        change: AdminChange,
        index: usize,
        generation: u64,
        not_before: u64,
    ) -> Option<(PathSnapshot, bool)> {
        let cached = self.paths.slots[index].value?;
        let mut snapshot = cached.snapshot;
        if snapshot.status != PathStatus::Valid {
            return None;
        }
        let route_policy = self
            .route_admin(snapshot.key.route)
            .map(|r| r.policy)
            .unwrap_or_default();
        let (route, exact) = match change.target {
            AdminTarget::Route(route) if snapshot.key.route == route => {
                (change.policy, cached.admin.policy)
            }
            AdminTarget::Path(target) if target == snapshot.path() => {
                (route_policy, change.policy)
            }
            _ => return None,
        };
        let effective = EffectivePolicy::of(route, exact);
        let estimate = effective.estimate.map(|e| e.value);
        let disabled = effective.discovery_disabled.is_some();
        // A retained restriction stays through upward sets and clears (no
        // learned state is fabricated from it): only confirmed delivery on
        // this incarnation relaxes it.
        snapshot.admin_estimate = estimate;
        if disabled != snapshot.discovery_disabled {
            snapshot.discovery_disabled = disabled;
            snapshot.discovery_revision = generation;
        }
        let restricted = estimate.filter(|&e| e < cached.accepted_estimate());
        if let Some(estimate) = restricted {
            snapshot.learned_mtu = Some(estimate);
            snapshot.retry_not_before = snapshot.retry_not_before.max(not_before);
        }
        Some((snapshot, restricted.is_some()))
    }

    /// Combined administrative estimate currently capping `path`.
    pub(in crate::service) fn admin_cap(&self, path: PathId) -> Option<u32> {
        self.path_administration(path)
            .ok()?
            .effective
            .estimate
            .map(|e| e.value)
    }

    /// Read-only validation: target authority, expected generation, value
    /// bounds and counter and hold arithmetic (`now + hold`, in the caller
    /// timebase of path deadlines, when the change restricts any affected
    /// path). Nothing changes on any outcome.
    pub fn prepare_admin(&self, change: AdminChange, now: u64, hold: u64) -> Result<AdminPlan, Error> {
        let (current, generation, ipv4, first_hop) = match change.target {
            AdminTarget::Route(route) => {
                let admin = self.route_administration(route)?;
                let link = self.link(admin.definition.link)?;
                (
                    admin.policy,
                    admin.generation,
                    admin.definition.destination.network.is_ipv4(),
                    link.mtu,
                )
            }
            AdminTarget::Path(path) => {
                let admin = self.path_administration(path)?;
                if admin.snapshot.status != PathStatus::Valid {
                    return Err(Error::Invalidated);
                }
                self.validate_selection(admin.snapshot.key)?;
                (
                    admin.policy,
                    admin.generation,
                    admin.snapshot.key.destination.address.is_ipv4(),
                    admin.snapshot.first_hop_mtu,
                )
            }
        };
        if change.expected != generation {
            return Err(Error::StaleGeneration);
        }
        if let Some(value) = change.policy.estimate {
            // Family minimum and wire maximum, bounded by the first hop.
            let (floor, ceiling) = if ipv4 { (68, 65535) } else { (1280, 65575) };
            if value < floor || value > ceiling.min(first_hop) {
                return Err(Error::InvalidArgument);
            }
        }
        if current == change.policy {
            // Identical: no generation, revision, hold or estimate change.
            return Ok(AdminPlan {
                change,
                revision: self.revision,
                admin_revision: self.admin_revision,
                generation,
                restriction: None,
            });
        }
        let generation = self.admin_revision.checked_add(1).ok_or(Error::Exhausted)?;
        let (mut restricts, mut delivers) = (false, false);
        for index in 0..self.paths.slots.len() {
            if let Some((snapshot, restricted)) = self.admin_refresh(change, index, generation, 0) {
                restricts |= restricted;
                delivers |= snapshot != self.paths.slots[index].value.unwrap().snapshot;
            }
        }
        if restricts || delivers {
            self.next_revision()?;
        }
        let restriction = if restricts {
            Some(now.checked_add(hold).ok_or(Error::Exhausted)?)
        } else {
            None
        };
        Ok(AdminPlan {
            change,
            revision: self.revision,
            admin_revision: self.admin_revision,
            generation,
            restriction,
        })
    }

    /// Infallible store of a plan validated against this exact service
    /// state; any intervening topology or policy change makes it stale.
    pub fn commit_admin(&mut self, plan: AdminPlan) -> Result<(), Error> {
        if plan.revision != self.revision || plan.admin_revision != self.admin_revision {
            return Err(Error::StaleGeneration);
        }
        if plan.is_noop() {
            return Ok(());
        }
        let policy = plan.change.policy;
        match plan.change.target {
            AdminTarget::Route(route) => {
                let old = self.route_admin(route).unwrap_or_default();
                // A downward set imposed the route's value on a live path:
                // future paths through the route start no higher. The
                // retained restriction lasts while the route carries an
                // administrative estimate (an upward set keeps it, so a
                // reacquired path never starts from the deferred value);
                // clearing the estimate withdraws it for future paths and
                // keeps only the outstanding hold.
                let imposed = plan.restriction.and(policy.estimate);
                let retained = policy.estimate.and(lower(old.restriction, imposed));
                self.route_admin[route.0.slot] = RouteAdmin {
                    route_generation: route.0.generation,
                    policy,
                    generation: plan.generation,
                    hold: old.hold.max(plan.restriction.unwrap_or(0)),
                    restriction: retained,
                    staged: None,
                };
            }
            AdminTarget::Path(path) => {
                self.paths.slots[path.0.slot].value.as_mut().unwrap().admin = PathAdmin {
                    policy,
                    generation: plan.generation,
                };
            }
        }
        self.admin_revision = plan.generation;
        // One revision (and, for a restriction, one negative revision) for
        // the whole change. The plan's service revision is current and was
        // checked whenever a snapshot changes, so this cannot overflow.
        let revision = self.revision.wrapping_add(1);
        let mut changed = false;
        for index in 0..self.paths.slots.len() {
            let Some(snapshot) = self.admin_candidate(plan, index) else {
                continue;
            };
            let cached = self.paths.slots[index].value.as_mut().unwrap();
            if snapshot != cached.snapshot {
                cached.snapshot = snapshot;
                changed = true;
                self.mark_dirty(snapshot.path());
            }
        }
        if changed {
            self.revision = revision;
        }
        Ok(())
    }

    // The snapshot slot `index` would carry after committing `plan` (the
    // policy stored before refresh, as `commit_admin` does), or None when
    // the plan does not affect it. Read-only.
    fn admin_candidate(&self, plan: AdminPlan, index: usize) -> Option<PathSnapshot> {
        let (mut snapshot, restricted) = self.admin_refresh(
            plan.change,
            index,
            plan.generation,
            plan.restriction.unwrap_or(0),
        )?;
        let revision = plan.revision.wrapping_add(1);
        if restricted {
            snapshot.negative_revision = revision;
        }
        if snapshot != self.paths.slots[index].value?.snapshot {
            snapshot.stamp.version = revision;
        }
        Some(snapshot)
    }

    /// Read-only preview of a plan still current for this service: each
    /// valid path it affects, as (current snapshot, snapshot after commit).
    /// Clients validate the candidate snapshots before anything is stored;
    /// `commit_admin` then installs exactly these snapshots.
    pub fn preview_admin(
        &self,
        plan: AdminPlan,
    ) -> Result<impl Iterator<Item = (PathSnapshot, PathSnapshot)> + '_, Error> {
        if plan.revision != self.revision || plan.admin_revision != self.admin_revision {
            return Err(Error::StaleGeneration);
        }
        let noop = plan.is_noop();
        Ok((0..self.paths.slots.len()).filter_map(move |index| {
            if noop {
                return None;
            }
            let current = self.paths.slots[index].value?.snapshot;
            Some((current, self.admin_candidate(plan, index)?))
        }))
    }

    // Explicit single replacement carries owner policy to the fresh route
    // generation; learned path state is never carried (paths re-resolve).
    // A replacement whose destination family differs is an unrelated route
    // for administration (like a removal followed by an addition): the
    // record's values are in the old family's terms, so nothing is carried.
    // Call before the old generation is overwritten.
    pub(in crate::service) fn transfer_route_admin(
        &mut self,
        old: RouteId,
        generation: u64,
        route: Route,
    ) {
        let same_family = self.route(old).is_ok_and(|r| {
            r.destination.network.is_ipv4() == route.destination.network.is_ipv4()
        });
        self.route_admin[old.0.slot] = match self.route_admin(old) {
            Some(record) if same_family => RouteAdmin {
                route_generation: generation,
                ..record
            },
            _ => RouteAdmin::default(),
        };
    }

    // Validate a bulk mapping read-only: old routes live and distinct,
    // new indices in range and distinct, and each new route of the old
    // route's destination family (a cross-family carry is invalid input:
    // that replacement is an unrelated route). Allocation-free.
    pub(in crate::service) fn check_route_mapping(
        &self,
        routes: &[Route],
        carry: &[(RouteId, usize)],
    ) -> Result<(), Error> {
        for (i, &(old, new)) in carry.iter().enumerate() {
            let previous = self.route(old)?;
            if routes.get(new).is_none_or(|route| {
                route.destination.network.is_ipv4() != previous.destination.network.is_ipv4()
            })
                || carry[..i]
                    .iter()
                    .any(|&(o, n)| o.0.slot == old.0.slot || n == new)
            {
                return Err(Error::InvalidArgument);
            }
        }
        Ok(())
    }

    // Stage mapped policies before the route table is rewritten, then
    // install them on the new generations; every unmapped record is dropped.
    pub(in crate::service) fn stage_route_mapping(&mut self, carry: &[(RouteId, usize)]) {
        for &(old, new) in carry {
            let record = self.route_admin(old).unwrap_or_default();
            self.route_admin[new].staged = Some((
                record.policy,
                record.generation,
                record.hold,
                record.restriction,
            ));
        }
    }

    // Record that a path was installed through `route` under the restriction
    // `imposed` (preallocated record, infallible).
    pub(in crate::service) fn retain_route_restriction(&mut self, route: RouteId, imposed: u32) {
        if let Some(mut record) = self.route_admin(route) {
            record.restriction = lower(record.restriction, Some(imposed));
            self.route_admin[route.0.slot] = record;
        }
    }
    pub(in crate::service) fn install_route_mapping(&mut self) {
        for (slot, record) in self.route_admin.iter_mut().enumerate() {
            let staged = record.staged.take();
            *record = match (staged, self.routes.slots[slot].value) {
                (Some((policy, generation, hold, restriction)), Some(_)) => RouteAdmin {
                    route_generation: self.routes.slots[slot].generation,
                    policy,
                    generation,
                    hold,
                    restriction,
                    staged: None,
                },
                _ => RouteAdmin::default(),
            };
        }
    }
}

// The smaller of two optional restrictions.
pub(super) fn lower(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}
