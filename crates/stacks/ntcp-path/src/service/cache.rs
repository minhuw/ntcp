use super::*;

#[cfg(test)]
mod tests;

handle!(PathId);
handle!(ClientId);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidationReason {
    SourceRemoved,
    LinkRemoved,
    RouteRemoved,
    SelectionChanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathStatus {
    Valid,
    Invalidated(InvalidationReason),
}

/// Acknowledgement provenance for one path incarnation and change version.
/// Reading a snapshot never acknowledges it. Tokens from another path (including
/// a prior binding) and future versions are rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChangeStamp {
    path: PathId,
    version: u64,
}

/// A detached observation, not perpetual output authorization. Embeddings must
/// compare its stamp with the live binding before physical submission (T8/T10).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathSnapshot {
    stamp: ChangeStamp,
    key: PathKey,
    status: PathStatus,
    first_hop_mtu: u32,
    link_version: u64,
    learned_mtu: Option<u32>,
    negative_revision: u64,
    retry_not_before: u64,
    ipv4_plateaus: Option<Ipv4Plateaus>,
}

impl PathSnapshot {
    pub const fn path(self) -> PathId {
        self.stamp.path
    }
    pub const fn stamp(self) -> ChangeStamp {
        self.stamp
    }
    pub const fn version(self) -> u64 {
        self.stamp.version
    }
    pub const fn key(self) -> PathKey {
        self.key
    }
    pub const fn status(self) -> PathStatus {
        self.status
    }
    pub const fn first_hop_mtu(self) -> u32 {
        self.first_hop_mtu
    }
    pub const fn link_version(self) -> u64 {
        self.link_version
    }
    pub const fn learned_mtu(self) -> Option<u32> {
        self.learned_mtu
    }
    /// Revision of the last actual learned decrease, independent of harmless
    /// link/policy updates. The deadline uses the producer's caller timebase.
    pub const fn negative_revision(self) -> u64 {
        self.negative_revision
    }
    pub const fn retry_not_before(self) -> u64 {
        self.retry_not_before
    }
    pub const fn ipv4_plateaus(self) -> Option<Ipv4Plateaus> {
        self.ipv4_plateaus
    }

    /// Ordinary wire lengths only: IPv6's 65535 payload octets plus40 base
    /// header octets. Physical jumbo MTUs remain separately observable.
    pub fn ip_packet_budget(self) -> Result<u32, Error> {
        if self.status != PathStatus::Valid {
            return Err(Error::Invalidated);
        }
        let ceiling = if self.key.destination.address.is_ipv4() {
            65535
        } else {
            65575
        };
        Ok(self
            .first_hop_mtu
            .min(self.learned_mtu.unwrap_or(u32::MAX))
            .min(ceiling))
    }

    /// Maximum send transport-message size uses the MINIMUM family IP header,
    /// not the actual complete header or TCP payload size.
    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.1
    //= reason=T7 PathService exposes minimum-header MMS_S, complete-header budgets and versioned notifications with exact acknowledgements. T8 Host applies snapshots to actual native/TUN TCP owners and gates every reserved physical submission. Independent-reader/coalescing tests preserve readN/update/ackN; validated cross-protocol publication remains T9/T10.
    //# A way to learn of changes in the value of MMS_S, the "maximum send transport-message size", which is derived from the Path MTU by subtracting the minimum IP header size.
    pub fn mms_s(self) -> Result<u32, Error> {
        self.ip_packet_budget()?
            .checked_sub(self.minimum_header())
            .ok_or(Error::InvalidArgument)
    }

    fn minimum_header(self) -> u32 {
        if self.key.destination.address.is_ipv4() {
            20
        } else {
            40
        }
    }

    /// Caller supplies validated complete IP/transport header lengths. This
    /// checks size arithmetic, not extension/option semantics. The optional
    /// ceiling is a transport PAYLOAD ceiling, intersected only for this query.
    pub fn payload_budget(
        self,
        ip_header: u32,
        transport_header: u32,
        transport_ceiling: Option<u32>,
    ) -> Result<u32, Error> {
        let ipv4 = self.key.destination.address.is_ipv4();
        if (ipv4 && (!(20..=60).contains(&ip_header) || !ip_header.is_multiple_of(4)))
            || (!ipv4 && (ip_header < 40 || !(ip_header - 40).is_multiple_of(8)))
        {
            return Err(Error::InvalidArgument);
        }
        let headers = ip_header
            .checked_add(transport_header)
            .ok_or(Error::InvalidArgument)?;
        let payload = self
            .ip_packet_budget()?
            .checked_sub(headers)
            .ok_or(Error::InvalidArgument)?;
        Ok(payload.min(transport_ceiling.unwrap_or(u32::MAX)))
    }
}

#[derive(Clone, Copy)]
pub(super) struct CachedPath {
    snapshot: PathSnapshot,
    // Greatest unlearned packet budget exposed on this live path. Retain it
    // across physical reductions because feedback for older submissions remains
    // useful. Once learned, the separate learned ceiling governs decreases.
    unlearned_mtu: u32,
    pins: usize,
}

#[derive(Clone, Copy)]
pub(super) struct Client {
    path: PathId,
    dirty: bool,
}

/// Estimate changes and packet-drop actions are independent. Even Unchanged
/// feedback can describe a dropped packet; a later dispatcher owns that action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EstimateChange {
    /// A learned network ceiling was recorded or lowered. A smaller physical
    /// MTU can mask this change in the effective packet budget.
    Decreased,
    Unchanged,
}

/// Disposition of probe-confirmed delivery offered to `confirm_delivery`.
/// Only `Raised` changes shared state; every other outcome is stale or
/// non-informative evidence, never an error in the trusted producer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryConfirmation {
    /// The learned ceiling rose to the confirmed length; clients are dirty.
    Raised,
    /// A decrease was learned after the probe was selected.
    StaleNegativeRevision,
    /// Selected or offered before the current conservative hold expired.
    Held,
    /// Larger than the current first-hop MTU or the family wire ceiling.
    ExceedsFirstHop,
    /// No larger than the current learned ceiling, or nothing was learned.
    NotLarger,
}

impl PathService {
    /// Commit after the authority operation has preflighted its revision and
    /// generations. Re-resolve ALL valid paths, including still-live routes
    /// shadowed by additions or metric changes. No allocation or fallible work
    /// remains here. Invalidations are sticky until rebind/release; later table
    /// changes can never revive an old path, even if its key resolves again.
    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.3
    //= reason=T7 PathService invalidates bound paths on route/source/link changes, including shadowing routes. T8 Host rebinds actual native/TUN TCP owners, and T10 Host::service_changes notifies every TCP binding and Host UDP flow of the replacement on the next service pass (a failed rebind stays dirty with bounded backpressure) while the submission barrier refuses held packets the current path no longer carries (dual-family Host and native reservation-race tests). T9 correlation never lets a stale or invalidated path incarnation change an estimate. Remaining T18: ICMP Redirect is decoded as unsupported because no production backend has an IP gateway route; Redirect-driven route changes and their notification arrive with the first real Gateway forwarding in T18, with topology evidence in T19.
    //# PMTU estimates may disappear from the routing table if the per-host routes are removed; this can happen in response to an ICMP Redirect message, or because certain routing-table daemons delete old routes after several minutes. Also, on a multi-homed host a topology change may result in the use of a different source interface. When this happens, if the packetization layer is not notified then it may continue to use a cached PMTU value that is now too small. One solution is to notify the packetization layer of a possible PMTU change whenever a Redirect message causes a route change, and whenever a route is simply deleted from the routing table.
    pub(super) fn commit_revision(&mut self, revision: u64) {
        self.revision = revision;
        for index in 0..self.paths.slots.len() {
            let Some(mut path) = self.paths.slots[index].value else {
                continue;
            };
            if path.snapshot.status != PathStatus::Valid {
                continue;
            }
            let old = path.snapshot;
            match self.validate_selection(old.key) {
                Ok(resolved) => {
                    path.snapshot.first_hop_mtu = resolved.first_hop_mtu;
                    path.snapshot.link_version = resolved.link_version;
                    if path.snapshot.learned_mtu.is_none() {
                        path.unlearned_mtu = path
                            .unlearned_mtu
                            .max(path.snapshot.ip_packet_budget().unwrap());
                    }
                    path.snapshot.ipv4_plateaus = old
                        .key
                        .destination
                        .address
                        .is_ipv4()
                        .then_some(self.plateaus);
                }
                Err(_) => {
                    let key = old.key;
                    let reason = if self.source_address(key.source).is_err() {
                        InvalidationReason::SourceRemoved
                    } else if self.link(key.link).is_err() {
                        InvalidationReason::LinkRemoved
                    } else if self.route(key.route).is_err() {
                        InvalidationReason::RouteRemoved
                    } else {
                        InvalidationReason::SelectionChanged
                    };
                    path.snapshot.status = PathStatus::Invalidated(reason);
                }
            }
            if path.snapshot != old {
                path.snapshot.stamp.version = revision;
                self.paths.slots[index].value = Some(path);
                self.mark_dirty(old.path());
            }
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
    //= reason=PathService marks every client of a path dirty on each trusted decrease and on link MTU, route, source, link or plateau changes. Host::service_changes, run on every native service_egress and MTU-refresh pass and every tun_echo transmit pass, brings each dirty TCP binding (reserved owners included, budget only, no repair) and each Host UDP flow (a coalesced per-flow change slot carrying MMS_S and the payload limit) to the newest snapshot and acknowledges exactly that version; a failing client stays dirty without stopping the others, and stateless leases and every physical submission revalidate against the current version. Dual-family Host tests (two TCP flows plus a UDP flow, held scalar, zero-copy and partial software GSO reservations, a randomized multi-client model), native reservation-race tests and the isolated namespace shared-fanout case, in which a real router PTB quotes only TCP flow A, verify it.
    //# The packetization layers must be notified about decreases in the PMTU. Any packetization layer instance (for example, a TCP connection) that is actively using the path must be notified if the PMTU estimate is decreased.
    fn mark_dirty(&mut self, path: PathId) {
        for slot in &mut self.clients.slots {
            if let Some(client) = &mut slot.value {
                if client.path == path {
                    client.dirty = true;
                }
            }
        }
    }

    /// Deterministic bounded cache policy: reuse a matching valid path, then a
    /// free slot, then the lowest-index idle slot. Live clients pin paths even
    /// after invalidation. Eviction is resource reclamation, never delivery or
    /// permission to grow a live estimate.
    fn path_slot(&self, key: PathKey) -> Result<(usize, bool), Error> {
        if let Some(index) = self.paths.slots.iter().position(|s| {
            s.value
                .is_some_and(|p| p.snapshot.key == key && p.snapshot.status == PathStatus::Valid)
        }) {
            return Ok((index, false));
        }
        let index = self.paths.free().or_else(|_| {
            self.paths
                .slots
                .iter()
                .position(|s| s.value.is_some_and(|p| p.pins == 0))
                .ok_or(Error::Capacity)
        })?;
        Ok((index, true))
    }

    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
    //= reason=Managed factories acquire per-host records from configured network/default routes before TCP construction, initializing unlearned budgets from the physical first hop. Trusted decreases change only per-host learned estimates, preserving forwarding routes and independent first-hop facts. Dual-family two-Endpoint tests exercise both route selections, first SYN/hidden child and later decreases without forwarding-route mutation. Generic ICMP publication remains the separate 1191-057 obligation.
    //# When the first packet is sent to a host for which no per-host route exists, a route is chosen either from the set of per-network routes, or from the set of default routes. The PMTU fields in these route entries should be initialized to be the MTU of the associated first-hop data link, and must never be changed by the PMTU Discovery process. (PMTU Discovery only creates or changes entries for per-host routes). Until a Datagram Too Big message is received, the PMTU associated with the initially-chosen route is presumed to be accurate.
    fn install_path(
        &mut self,
        index: usize,
        generation: u64,
        resolved: ResolvedPath,
        revision: u64,
    ) -> PathId {
        let id = PathId(Handle {
            context: self.context,
            slot: index,
            generation,
        });
        let snapshot = PathSnapshot {
            stamp: ChangeStamp {
                path: id,
                version: revision,
            },
            key: resolved.key,
            status: PathStatus::Valid,
            first_hop_mtu: resolved.first_hop_mtu,
            link_version: resolved.link_version,
            learned_mtu: None,
            negative_revision: 0,
            retry_not_before: 0,
            ipv4_plateaus: resolved
                .key
                .destination
                .address
                .is_ipv4()
                .then_some(self.plateaus),
        };
        self.paths.insert(
            self.context,
            index,
            generation,
            CachedPath {
                snapshot,
                unlearned_mtu: snapshot.ip_packet_budget().unwrap(),
                pins: 0,
            },
        );
        id
    }

    fn pin(&mut self, path: PathId) {
        // Every client occupies one preallocated slot; this count was checked
        // before mutation, and cannot exceed the checked client allocation.
        self.paths.slots[path.0.slot].value.as_mut().unwrap().pins += 1;
    }
    fn unpin(&mut self, path: PathId) {
        self.paths.slots[path.0.slot].value.as_mut().unwrap().pins -= 1;
    }

    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
    //= reason=T7 PathService maintains bounded per-host resolved routing records with independent learned estimates and exact first-hop authority. Every acquired active destination is pinned by its clients; capacity exhaustion preserves active records, and deterministic idle eviction uses fresh generations. Public tests exercise shared pinning, full-cache backpressure, idle reuse and repeated release cycles. ICMP Redirect processing remains a separate T9 producer obligation.
    //# The obvious place to store this association is as a field in the routing table entries. A host will not have a route for every possible destination, but it should be able to cache a per-host route for every active destination. (This requirement is already imposed by the need to process ICMP Redirect messages.)
    pub fn acquire(&mut self, request: PathRequest) -> Result<(ClientId, PathSnapshot), Error> {
        self.acquire_via(request, request.destination)
    }
    pub fn acquire_via(&mut self, request: PathRequest, forwarding_destination: ScopedAddress) -> Result<(ClientId, PathSnapshot), Error> {
        let resolved = self.resolve_via(request, forwarding_destination)?;
        let client_slot = self.clients.free()?;
        let (index, new) = self.path_slot(resolved.key)?;
        let needed = if new { 2 } else { 1 };
        let generation = self
            .generation
            .checked_add(needed)
            .ok_or(Error::Exhausted)?;
        let revision = if new {
            self.next_revision()?
        } else {
            self.revision
        };
        let path = if new {
            self.install_path(index, generation - 1, resolved, revision)
        } else {
            self.paths.slots[index].value.unwrap().snapshot.path()
        };
        self.pin(path);
        let client = ClientId(self.clients.insert(
            self.context,
            client_slot,
            generation,
            Client { path, dirty: true },
        ));
        self.generation = generation;
        self.revision = revision;
        Ok((client, self.snapshot(client)?))
    }

    /// Rebind in place with fresh client authority. On ANY error, old binding,
    /// pinning, pending invalidation, counters and cache are unchanged. A full
    /// pinned cache reports Capacity even if releasing this client could free a
    /// slot: the owner must pause/retry or explicitly release authority first.
    pub fn rebind(
        &mut self,
        client: ClientId,
        request: PathRequest,
    ) -> Result<(ClientId, PathSnapshot), Error> {
        self.rebind_via(client, request, request.destination)
    }
    pub fn rebind_via(
        &mut self,
        client: ClientId,
        request: PathRequest,
        forwarding_destination: ScopedAddress,
    ) -> Result<(ClientId, PathSnapshot), Error> {
        let old = self.clients.get(self.context, client.0)?;
        let resolved = self.resolve_via(request, forwarding_destination)?;
        let (index, new) = self.path_slot(resolved.key)?;
        if !new && self.paths.slots[index].value.unwrap().snapshot.path() == old.path {
            return Ok((client, self.snapshot(client)?));
        }
        let generation = self
            .generation
            .checked_add(if new { 2 } else { 1 })
            .ok_or(Error::Exhausted)?;
        let revision = if new {
            self.next_revision()?
        } else {
            self.revision
        };
        let path = if new {
            self.install_path(index, generation - 1, resolved, revision)
        } else {
            self.paths.slots[index].value.unwrap().snapshot.path()
        };
        self.unpin(old.path);
        self.pin(path);
        let client = ClientId(self.clients.insert(
            self.context,
            client.0.slot,
            generation,
            Client { path, dirty: true },
        ));
        self.generation = generation;
        self.revision = revision;
        Ok((client, self.snapshot(client)?))
    }

    pub fn release(&mut self, client: ClientId) -> Result<(), Error> {
        let old = self.clients.get(self.context, client.0)?;
        self.unpin(old.path);
        self.clients.slots[client.0.slot].value = None;
        Ok(())
    }

    /// Pure read; invalidated snapshots stay readable, but budget methods reject
    /// them. Acknowledging invalidation clears dirty only, never restores output
    /// authority. A new binding is required before output may resume.
    pub fn snapshot(&self, client: ClientId) -> Result<PathSnapshot, Error> {
        let client = self.clients.get(self.context, client.0)?;
        self.path_snapshot(client.path)
    }
    pub fn path_snapshot(&self, path: PathId) -> Result<PathSnapshot, Error> {
        Ok(self.paths.get(self.context, path.0)?.snapshot)
    }
    pub fn path_pins(&self, path: PathId) -> Result<usize, Error> {
        Ok(self.paths.get(self.context, path.0)?.pins)
    }
    pub fn is_dirty(&self, client: ClientId) -> Result<bool, Error> {
        Ok(self.clients.get(self.context, client.0)?.dirty)
    }

    /// Callback-free, allocation-free bounded scan. Reading does not consume.
    pub fn dirty_clients(&self) -> impl Iterator<Item = ClientId> + '_ {
        self.clients
            .slots
            .iter()
            .enumerate()
            .filter_map(|(slot, record)| {
                record.value.filter(|c| c.dirty).map(|_| {
                    ClientId(Handle {
                        context: self.context,
                        slot,
                        generation: record.generation,
                    })
                })
            })
    }

    pub fn acknowledge(&mut self, client: ClientId, stamp: ChangeStamp) -> Result<(), Error> {
        let current = self.snapshot(client)?;
        if stamp.path != current.path() || stamp.version > current.version() {
            return Err(Error::InvalidArgument);
        }
        if stamp.version == current.version() {
            self.clients.slots[client.0.slot]
                .value
                .as_mut()
                .unwrap()
                .dirty = false;
        }
        Ok(())
    }

    /// Trusted NETWORK fact producer only. The later host must validate the
    /// actually submitted quote and owner/key before calling. A path generation
    /// is stable across budget versions: useful older submissions can decrease
    /// it again. No packetization version equality, ACK, timer or TCP state is
    /// treated as network provenance here. No remote-address route creation.
    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
    //= reason=T7 PathService keys learned estimates by canonical context, source, destination/scope, routing DSCP, link, next-hop and route generation, excluding ECN and ports. T8 Host binds actual native/TUN TCP owners to these records; public tests preserve source/destination/DSCP/scoped-link isolation. Generic validated ICMP publication remains T9.
    //# In general, the IP layer should associate each PMTU value that it has learned with a specific path. A path is identified by a source address, a destination address and an IP type-of-service. (Some implementations do not record the source address of paths; this is acceptable for single-homed hosts, which have only one possible source address.)
    pub fn trusted_decrease(
        &mut self,
        path: PathId,
        candidate: u32,
    ) -> Result<EstimateChange, Error> {
        self.trusted_decrease_with_hold(path, candidate, 0)
    }

    /// Trusted producer supplies an absolute conservative discovery deadline.
    /// Equal/larger observations preserve the learned estimate and negative
    /// revision, but a later deadline still restarts the hold: growth selected
    /// before this fresh report must not be confirmed or submitted.
    pub fn trusted_decrease_with_hold(
        &mut self,
        path: PathId,
        candidate: u32,
        retry_not_before: u64,
    ) -> Result<EstimateChange, Error> {
        let mut cached = self.paths.get(self.context, path.0)?;
        if cached.snapshot.status != PathStatus::Valid {
            return Err(Error::Invalidated);
        }
        self.validate_selection(cached.snapshot.key)?;
        let ipv4 = cached.snapshot.key.destination.address.is_ipv4();
        let (floor, ceiling) = if ipv4 { (68, 65535) } else { (1280, 65575) };
        if !(floor..=ceiling).contains(&candidate) {
            return Err(Error::InvalidArgument);
        }
        // Compare against the pre-feedback network estimate, independently of
        // a temporary physical limit that can mask older-submission feedback.
        let estimate = cached.snapshot.learned_mtu.unwrap_or(cached.unlearned_mtu);
        if candidate >= estimate {
            if retry_not_before > cached.snapshot.retry_not_before {
                let revision = self.next_revision()?;
                cached.snapshot.retry_not_before = retry_not_before;
                cached.snapshot.stamp.version = revision;
                self.paths.slots[path.0.slot].value = Some(cached);
                self.revision = revision;
                self.mark_dirty(path);
            }
            return Ok(EstimateChange::Unchanged);
        }
        let revision = self.next_revision()?;
        cached.snapshot.learned_mtu = Some(candidate);
        cached.snapshot.negative_revision = revision;
        cached.snapshot.retry_not_before = cached.snapshot.retry_not_before.max(retry_not_before);
        cached.snapshot.stamp.version = revision;
        self.paths.slots[path.0.slot].value = Some(cached);
        self.revision = revision;
        self.mark_dirty(path);
        Ok(EstimateChange::Decreased)
    }

    /// Trusted positive NETWORK fact: an unfragmented packet of exactly
    /// `ip_len` complete IP octets, selected at `selected_at` under
    /// `negative_revision` and definitely submitted on this path incarnation,
    /// was delivered. The host proves that provenance; this checks it is
    /// still current at `now` (caller timebase of the hold deadline). Raising
    /// records `Some(ip_len)`, never the historical unlearned value, so a
    /// later physical increase cannot lift past what was proven.
    //= https://www.rfc-editor.org/rfc/rfc4821#section-5.2
    //= reason=PathService is the IP-layer store of per-path state, keyed by context, source, destination/scope, routing DSCP, link, next hop and route generation. Host stores correlated ICMP PTB MTUs there (TCP reports at or above the connection's proven delivery at once; reports below it only when that exact report's quoted-data timeout applies it, never because of loss inference; UDP and path-level reports) with a 600-second hold, and Host::service_changes publishes TCP's PLPMTUD-confirmed size through PathService::confirm_delivery only for a definitely submitted, unfragmented probe selected after the hold under an unchanged negative revision, raising other flows' ordinary ceiling without local delivery proof. Loss-inferred decreases and probe state stay connection-local. Dual-family Host tests with real probes across the 600-second deadline verify it.
    //# The IP layer SHOULD be used to store the cached PMTU value and other shared state such as MTU values reported by ICMP PTB messages. Ideally, this shared state should be associated with a specific path traversed by packets exchanged between the source and destination nodes. However, in most cases a node will not have enough information to completely and accurately identify such a path. Rather, a node must associate a PMTU value with some local representation of a path. It is left to the implementation to select the local representation of a path.
    pub fn confirm_delivery(
        &mut self,
        path: PathId,
        ip_len: u32,
        negative_revision: u64,
        selected_at: u64,
        now: u64,
    ) -> Result<DeliveryConfirmation, Error> {
        let mut cached = self.paths.get(self.context, path.0)?;
        if cached.snapshot.status != PathStatus::Valid {
            return Err(Error::Invalidated);
        }
        self.validate_selection(cached.snapshot.key)?;
        let ipv4 = cached.snapshot.key.destination.address.is_ipv4();
        let (floor, ceiling) = if ipv4 { (68, 65535) } else { (1280, 65575) };
        if ip_len < floor {
            return Err(Error::InvalidArgument);
        }
        let snapshot = cached.snapshot;
        if negative_revision != snapshot.negative_revision {
            return Ok(DeliveryConfirmation::StaleNegativeRevision);
        }
        if selected_at < snapshot.retry_not_before || now < snapshot.retry_not_before {
            return Ok(DeliveryConfirmation::Held);
        }
        if ip_len > snapshot.first_hop_mtu.min(ceiling) {
            return Ok(DeliveryConfirmation::ExceedsFirstHop);
        }
        if snapshot.learned_mtu.is_none_or(|learned| ip_len <= learned) {
            return Ok(DeliveryConfirmation::NotLarger);
        }
        let revision = self.next_revision()?;
        cached.snapshot.learned_mtu = Some(ip_len);
        cached.snapshot.stamp.version = revision;
        self.paths.slots[path.0.slot].value = Some(cached);
        self.revision = revision;
        self.mark_dirty(path);
        Ok(DeliveryConfirmation::Raised)
    }

    /// Apply the selected live fallback policy to checked caller evidence.
    /// Like trusted_decrease, this does not establish physical quote provenance.
    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
    //= reason=PathService keeps per-host learned estimates keyed by the path, created on first use with the current route's first hop, and never changes forwarding routes. Host ICMP dispatch derives the estimate from a nonzero Next-Hop MTU or the RFC1191 section 5 plateau below the corrected quoted length, requires correlation with committed submission evidence and lowers the per-host record only when lower. A correlated TCP report about the connection's current path at or above its proven delivery lowers the record at once (the larger of the Host and TCP estimates) and otherwise restarts its hold. One below proven delivery is deferred whatever the connection's loss-inferred estimate and changes nothing shared (no decrease, hold restart or notification) until the connection applies exactly that report at the quoted data's timeout; Host::service_changes then publishes the larger of the Host estimate and the report's own policy-derived size, so a loss-inferred value never leaks. Cumulative progress past the quoted data refutes it, and released owners, rebound paths and subsumed results publish nothing. Stale or evicted path incarnations are never resurrected or changed. Dual-family Host tests and real router PTBs in the isolated namespace gate verify it.
    //# When a Datagram Too Big message is received, the ICMP layer determines a new estimate for the Path MTU (either from a non-zero Next-Hop MTU value in the packet, or using the method described in section 5). If a per-host route for this path does not exist, then one is created (almost as if a per-host ICMP Redirect is being processed; the new route uses the same first-hop router as the current route). If the PMTU estimate associated with the per-host route is higher than the new estimate, then the value in the routing entry is changed.
    pub fn trusted_ipv4_fallback(
        &mut self,
        path: PathId,
        quoted_total: u32,
        header_bytes: u32,
        exact_sent_size: u32,
    ) -> Result<EstimateChange, Error> {
        let snapshot = self.path_snapshot(path)?;
        let table = snapshot.ipv4_plateaus.ok_or(Error::InvalidArgument)?;
        let candidate = table.legacy_fallback(
            snapshot.ip_packet_budget()?,
            quoted_total,
            header_bytes,
            exact_sent_size,
        )?;
        self.trusted_decrease(path, candidate)
    }
}
