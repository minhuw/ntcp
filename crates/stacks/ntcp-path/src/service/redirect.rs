//! Redirect overrides (RFC 1122 section 3.2.2.2; RFC 4861 sections 8.3 and
//! 7.3.3). A validated Redirect changes the first hop of one destination
//! beneath the administrative route that selects it: the override is
//! attached to that exact route generation and never becomes a route of
//! its own, so route selection, route policy and its retained restriction
//! are unchanged and the override cannot outlive the route. Each override
//! carries a forwarding generation from the service's nonwrapping domain,
//! which every path key resolved through it holds, so an override that is
//! replaced, or ends and is installed again, never names an earlier path
//! incarnation. An override ends only by an event: its route replaced or
//! removed, its link removed, its target or the router that sent it found
//! unreachable, its router target no longer a router, or eviction from the
//! bounded population (one slot per cached path); neither RFC defines a
//! lifetime for it. Every change invalidates the paths whose selection it
//! changes, which notifies their clients.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Redirect {
    route: RouteId,
    link: LinkId,
    // The forwarding destination: the destination of the packets the
    // Redirect is about, as forwarded.
    destination: ScopedAddress,
    // Present for a Redirect specific to one type of service (IPv4 codes 2
    // and 3).
    dscp: Option<Dscp>,
    sender: ScopedAddress,
    target: ScopedAddress,
    generation: u64,
}

/// Why overrides through a neighbor end (`PathService::end_redirects`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NeighborLoss {
    /// Neighbor Unreachability Detection failed, or the owner withdrew the
    /// neighbor's mapping: overrides that use it as their target or were
    /// sent by it end.
    Unreachable,
    /// It is no longer a router (RFC 4861 section 7.2.5): overrides that use
    /// it as a router target end; one whose target is its own destination
    /// does not use it as a router.
    NotRouter,
}

impl Redirect {
    pub(super) const fn target(self) -> ScopedAddress {
        self.target
    }
    pub(super) const fn generation(self) -> u64 {
        self.generation
    }
}

impl PathService {
    /// The override selecting the first hop of `destination` through route
    /// `route` for `dscp`: one specific to the type of service wins over one
    /// for every type of service.
    pub(super) fn redirect_for(
        &self,
        route: RouteId,
        destination: ScopedAddress,
        dscp: Dscp,
    ) -> Option<Redirect> {
        let mut found = None;
        for r in self.redirects.iter().flatten() {
            if r.route != route || r.destination != destination {
                continue;
            }
            match r.dscp {
                Some(d) if d == dscp => return Some(*r),
                None => found = Some(*r),
                Some(_) => {}
            }
        }
        found
    }

    /// Install a Redirect for the forwarding destination of `key` received
    /// from `sender`: from now on that destination's packets through the
    /// same route leave for `target`, for every type of service, or only
    /// for the key's when `type_of_service` is set. A Redirect for every
    /// type of service moves every type of service whose first hop is the
    /// sender: each override of the destination leaving for the sender,
    /// and the selection for every type of service only when the sender is
    /// its first hop (the target of the override for every type of service,
    /// else the route's own next hop). `key` must still be the
    /// authoritative selection (a stale route generation or link is
    /// refused), `sender` its current first hop, which is a router (a
    /// destination reached directly is never redirected), and `target` a
    /// unicast address of the key's link other than this host's own there
    /// (a link-local address is compared with its zone, RFC 4007). The
    /// caller validates the Redirect's evidence and family rules first. The
    /// paths it moves are invalidated and their clients dirty.
    pub fn redirect(
        &mut self,
        key: PathKey,
        sender: ScopedAddress,
        target: ScopedAddress,
        type_of_service: bool,
    ) -> Result<(), Error> {
        self.validate_selection(key)?;
        let destination = key.forwarding_destination;
        if key.next_hop != ResolvedNextHop::Address(sender)
            || sender == destination
            || target.address.is_ipv4() != destination.address.is_ipv4()
            || target.zone.is_some_and(|zone| zone != key.link)
            || target == sender
            || self.sources().any(|(_, own)| own == target)
        {
            return Err(Error::InvalidArgument);
        }
        let dscp = type_of_service.then_some(key.dscp);
        let existing = self.redirects.iter().position(|r| {
            r.is_some_and(|r| {
                r.route == key.route && r.destination == destination && r.dscp == dscp
            })
        });
        let installs = dscp.is_some() || {
            let first_hop = match existing.and_then(|i| self.redirects[i]) {
                Some(general) => ResolvedNextHop::Address(general.target),
                None => match self.route(key.route)?.next_hop {
                    NextHop::OnLink => ResolvedNextHop::Address(destination),
                    NextHop::Gateway(g) => ResolvedNextHop::Address(g),
                    NextHop::Forwarder(id) => ResolvedNextHop::Forwarder(id),
                },
            };
            first_hop == ResolvedNextHop::Address(sender)
        };
        // Replace this destination's override, else take a free slot, else
        // evict the oldest.
        let index = if installs {
            Some(
                existing
                    .or_else(|| self.redirects.iter().position(Option::is_none))
                    .or_else(|| {
                        self.redirects
                            .iter()
                            .enumerate()
                            .filter_map(|(i, r)| Some((i, (*r)?.generation)))
                            .min_by_key(|(_, generation)| *generation)
                            .map(|(i, _)| i)
                    })
                    .ok_or(Error::Capacity)?,
            )
        } else {
            None
        };
        // The type-of-service overrides of this destination that leave for
        // the sender move with a Redirect for every type of service.
        let moves = |i: usize, r: Option<Redirect>| {
            dscp.is_none()
                && Some(i) != index
                && r.is_some_and(|r| {
                    r.route == key.route
                        && r.destination == destination
                        && r.dscp.is_some()
                        && r.target == sender
                })
        };
        let moved = (0..self.redirects.len())
            .filter(|&i| moves(i, self.redirects[i]))
            .count();
        // Each changed override takes its own forwarding generation.
        let changed =
            u64::try_from(moved + usize::from(index.is_some())).map_err(|_| Error::Exhausted)?;
        self.generation
            .checked_add(changed)
            .ok_or(Error::Exhausted)?;
        let revision = self.next_revision()?;
        for i in 0..self.redirects.len() {
            let dscp = if Some(i) == index {
                dscp
            } else if moves(i, self.redirects[i]) {
                self.redirects[i].and_then(|r| r.dscp)
            } else {
                continue;
            };
            let generation = self.next_generation()?;
            self.redirects[i] = Some(Redirect {
                route: key.route,
                link: key.link,
                destination,
                dscp,
                sender,
                target,
                generation,
            });
            self.generation = generation;
        }
        self.commit_revision(revision);
        Ok(())
    }

    /// End the overrides that `loss` of `neighbor` on `link` affects,
    /// returning how many ended; their paths are invalidated and their
    /// clients dirty.
    pub fn end_redirects(
        &mut self,
        link: LinkId,
        neighbor: ScopedAddress,
        loss: NeighborLoss,
    ) -> Result<usize, Error> {
        let affected = |r: &Redirect| {
            r.link == link
                && match loss {
                    NeighborLoss::Unreachable => r.target == neighbor || r.sender == neighbor,
                    NeighborLoss::NotRouter => r.target == neighbor && r.target != r.destination,
                }
        };
        let ended = self
            .redirects
            .iter()
            .flatten()
            .filter(|r| affected(r))
            .count();
        if ended == 0 {
            return Ok(0);
        }
        let revision = self.next_revision()?;
        for slot in &mut self.redirects {
            if slot.is_some_and(|r| affected(&r)) {
                *slot = None;
            }
        }
        self.commit_revision(revision);
        Ok(ended)
    }

    /// Whether a live override uses `neighbor` on `link` as a router: a
    /// target other than its destination (RFC 4861 section 8.3 makes it a
    /// router even before its link-layer address is known).
    pub fn redirect_router(&self, link: LinkId, neighbor: ScopedAddress) -> bool {
        self.redirects
            .iter()
            .flatten()
            .any(|r| r.link == link && r.target == neighbor && r.target != r.destination)
    }

    // Whether the selection replacing `key` keeps its flow and route and
    // changes only the first hop an override chose.
    pub(super) fn forwarding_transition(&self, key: PathKey) -> bool {
        let current = if self.route_segments(key.route).is_ok_and(<[_]>::is_empty) {
            self.resolve_via(key.request(), key.forwarding_destination)
        } else {
            self.resolve(key.request())
        };
        current.is_ok_and(|current| current.key != key && same_flow(current.key, key))
    }

    // Overrides whose route generation or link is gone end with them.
    pub(super) fn prune_redirects(&mut self) {
        for slot in 0..self.redirects.len() {
            let Some(r) = self.redirects[slot] else {
                continue;
            };
            if !self.route(r.route).is_ok_and(|route| route.link == r.link)
                || self.link(r.link).is_err()
            {
                self.redirects[slot] = None;
            }
        }
    }
}

// The same flow through the same route generation, whatever first hop.
pub(super) fn same_flow(a: PathKey, b: PathKey) -> bool {
    PathKey {
        next_hop: b.next_hop,
        forwarding: b.forwarding,
        ..a
    } == b
}
