use alloc::vec::Vec;
use core::{cmp::Reverse, mem::size_of, net::IpAddr};

use crate::{Error, Ipv4Plateaus};

/// Supplied by the authoritative embedding. A value must identify exactly one
/// service for its entire lifetime, including restarts with retained handles.
/// Embeddings must allocate distinct values for independent network contexts;
/// addresses and interface indices do not establish context identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ContextId(u128);

impl ContextId {
    pub const fn new(value: u128) -> Self {
        Self(value)
    }
    pub const fn value(self) -> u128 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
struct Handle {
    context: ContextId,
    slot: usize,
    generation: u64,
}

macro_rules! handle {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
        pub struct $name(Handle);
        impl $name {
            pub const fn context(self) -> ContextId {
                self.0.context
            }
        }
    };
}
handle!(LinkId);
handle!(SourceId);
handle!(RouteId);

mod cache;
pub use cache::*;

/// Authoritative embedding interface key, independent of a source IP address.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct InterfaceKey(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Dscp(u8);

impl Dscp {
    pub fn new(value: u8) -> Result<Self, Error> {
        if value <= 63 {
            Ok(Self(value))
        } else {
            Err(Error::InvalidArgument)
        }
    }
    /// IP traffic class, with the mutable ECN low two bits excluded.
    pub const fn from_traffic_class(value: u8) -> Self {
        Self(value >> 2)
    }
    pub const fn value(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ScopedAddress {
    address: IpAddr,
    zone: Option<LinkId>,
}

impl ScopedAddress {
    /// Link-local IPv6 requires an explicit zone. Other supported unicast
    /// addresses must not carry one. The service checks zone liveness on use.
    pub fn new(address: IpAddr, zone: Option<LinkId>) -> Result<Self, Error> {
        if address.is_unspecified()
            || address.is_multicast()
            || (is_link_local(address) != zone.is_some())
            || address == IpAddr::V4(core::net::Ipv4Addr::BROADCAST)
        {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { address, zone })
    }
    pub const fn address(self) -> IpAddr {
        self.address
    }
    pub const fn zone(self) -> Option<LinkId> {
        self.zone
    }
}

fn is_link_local(address: IpAddr) -> bool {
    matches!(address, IpAddr::V6(v) if v.is_unicast_link_local())
}

/// A canonical network prefix; host bits must be zero, including /0.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpPrefix {
    network: IpAddr,
    length: u8,
}

impl IpPrefix {
    pub fn new(network: IpAddr, length: u8) -> Result<Self, Error> {
        let valid = match network {
            IpAddr::V4(a) => length <= 32 && (u32::from(a) & mask4(length)) == u32::from(a),
            IpAddr::V6(a) => length <= 128 && (u128::from(a) & mask6(length)) == u128::from(a),
        };
        if !valid {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { network, length })
    }
    pub const fn network(self) -> IpAddr {
        self.network
    }
    pub const fn length(self) -> u8 {
        self.length
    }
    pub fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(n), IpAddr::V4(a)) => u32::from(a) & mask4(self.length) == u32::from(n),
            (IpAddr::V6(n), IpAddr::V6(a)) => u128::from(a) & mask6(self.length) == u128::from(n),
            _ => false,
        }
    }
    fn scoped(self) -> bool {
        self.length >= 10 && is_link_local(self.network)
    }
}

fn mask4(length: u8) -> u32 {
    if length == 0 {
        0
    } else {
        u32::MAX.checked_shl(u32::from(32 - length)).unwrap_or(0)
    }
}
fn mask6(length: u8) -> u128 {
    if length == 0 {
        0
    } else {
        u128::MAX.checked_shl(u32::from(128 - length)).unwrap_or(0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ForwarderId(pub u64);

/// Explicit embedding assignment, scoped by the canonical link. This does
/// not assert that a peer is on-link or that an IP neighbor has been resolved.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ResolvedNextHop {
    Address(ScopedAddress),
    Forwarder(ForwarderId),
}

impl PartialEq<ScopedAddress> for ResolvedNextHop {
    fn eq(&self, other: &ScopedAddress) -> bool {
        *self == Self::Address(*other)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NextHop {
    OnLink,
    Gateway(ScopedAddress),
    Forwarder(ForwarderId),
}

/// Forwarding policy only. No transport ceilings, ports or peer MSS participate.
/// Precedence: longest destination prefix, longest source prefix (Some /0 beats
/// None), exact DSCP, then lowest metric. Equal-priority definitions are rejected
/// even if they would choose the same hop. Link-local prefixes on distinct links
/// are disjoint zones and may coexist. Allocation order never breaks a tie.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Route {
    pub destination: IpPrefix,
    pub source: Option<IpPrefix>,
    pub dscp: Option<Dscp>,
    pub link: LinkId,
    pub next_hop: NextHop,
    pub metric: u32,
}

impl Route {
    fn priority(self) -> (u8, Option<u8>, bool, Reverse<u32>) {
        (
            self.destination.length,
            self.source.map(|s| s.length),
            self.dscp.is_some(),
            Reverse(self.metric),
        )
    }
    fn ambiguous(self, other: Self) -> bool {
        self.destination == other.destination
            && self.source == other.source
            && self.dscp == other.dscp
            && self.metric == other.metric
            && !(self.destination.scoped() && self.link != other.link)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub links: usize,
    pub sources: usize,
    pub source_owners: usize,
    pub routes: usize,
    pub paths: usize,
    pub clients: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    pub links: usize,
    pub sources: usize,
    pub source_owners: usize,
    pub routes: usize,
    pub paths: usize,
    pub clients: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkInfo {
    pub interface: InterfaceKey,
    /// Physical fact, permitted to exceed ordinary IP wire representability.
    pub mtu: u32,
    pub version: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathRequest {
    pub source: SourceId,
    pub destination: ScopedAddress,
    pub dscp: Dscp,
}

/// Canonical immutable identity, minted only by authoritative route resolution.
/// A key is provenance, not a perpetual output authorization: validate_selection
/// must be checked at use. Link MTU and mutable ECN do not change identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PathKey {
    context: ContextId,
    source: SourceId,
    source_address: ScopedAddress,
    destination: ScopedAddress,
    forwarding_destination: ScopedAddress,
    dscp: Dscp,
    link: LinkId,
    next_hop: ResolvedNextHop,
    route: RouteId,
}

impl PathKey {
    pub const fn context(self) -> ContextId {
        self.context
    }
    pub const fn source(self) -> SourceId {
        self.source
    }
    pub const fn source_address(self) -> ScopedAddress {
        self.source_address
    }
    pub const fn destination(self) -> ScopedAddress {
        self.destination
    }
    /// Actual destination used for forwarding (the first source-route hop
    /// when explicitly supplied), distinct from the transport destination.
    pub const fn forwarding_destination(self) -> ScopedAddress {
        self.forwarding_destination
    }
    pub const fn dscp(self) -> Dscp {
        self.dscp
    }
    pub const fn link(self) -> LinkId {
        self.link
    }
    pub const fn next_hop(self) -> ResolvedNextHop {
        self.next_hop
    }
    pub const fn route(self) -> RouteId {
        self.route
    }
    pub const fn request(self) -> PathRequest {
        PathRequest {
            source: self.source,
            destination: self.destination,
            dscp: self.dscp,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedPath {
    key: PathKey,
    first_hop_mtu: u32,
    link_version: u64,
}

impl ResolvedPath {
    pub const fn key(self) -> PathKey {
        self.key
    }
    pub const fn first_hop_mtu(self) -> u32 {
        self.first_hop_mtu
    }
    pub const fn link_version(self) -> u64 {
        self.link_version
    }
}

#[derive(Clone, Copy)]
struct Slot<T> {
    generation: u64,
    value: Option<T>,
}

struct Table<T> {
    slots: Vec<Slot<T>>,
}

impl<T: Copy> Table<T> {
    fn new(limit: usize) -> Result<Self, Error> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(limit)
            .map_err(|_| Error::Allocation)?;
        slots.resize(
            limit,
            Slot {
                generation: 0,
                value: None,
            },
        );
        Ok(Self { slots })
    }
    fn free(&self) -> Result<usize, Error> {
        self.slots
            .iter()
            .position(|s| s.value.is_none())
            .ok_or(Error::Capacity)
    }
    fn get(&self, context: ContextId, handle: Handle) -> Result<T, Error> {
        if handle.context != context {
            return Err(Error::ForeignContext);
        }
        self.slots
            .get(handle.slot)
            .filter(|s| s.generation == handle.generation)
            .and_then(|s| s.value)
            .ok_or(Error::StaleHandle)
    }
    fn insert(&mut self, context: ContextId, slot: usize, generation: u64, value: T) -> Handle {
        self.slots[slot] = Slot {
            generation,
            value: Some(value),
        };
        Handle {
            context,
            slot,
            generation,
        }
    }
    fn used(&self) -> usize {
        self.slots.iter().filter(|s| s.value.is_some()).count()
    }
}

#[derive(Clone, Copy)]
struct Source {
    address: ScopedAddress,
}
#[derive(Clone, Copy)]
struct Owner {
    source: SourceId,
    link: LinkId,
}

/// Trusted serialized IP authority. All storage is bounded and allocated
/// fallibly at construction. Resolution and mutations allocate nothing.
/// There is no transport or discovery state in route selection.
pub struct PathService {
    context: ContextId,
    links: Table<LinkInfo>,
    sources: Table<Source>,
    owners: Table<Owner>,
    routes: Table<Route>,
    paths: Table<CachedPath>,
    clients: Table<Client>,
    // A shared nonwrapping generation domain prevents reuse after deletion.
    generation: u64,
    revision: u64,
    plateaus: Ipv4Plateaus,
}

impl PathService {
    pub fn new(context: ContextId, limits: Limits) -> Result<Self, Error> {
        // Validate total accounting before attempting any allocation, including
        // Vec's isize bound. Later operations only fill already reserved slots.
        let mut bytes = 0usize;
        for (count, size) in [
            (limits.links, size_of::<Slot<LinkInfo>>()),
            (limits.sources, size_of::<Slot<Source>>()),
            (limits.source_owners, size_of::<Slot<Owner>>()),
            (limits.routes, size_of::<Slot<Route>>()),
            (limits.paths, size_of::<Slot<CachedPath>>()),
            (limits.clients, size_of::<Slot<Client>>()),
        ] {
            bytes = bytes
                .checked_add(count.checked_mul(size).ok_or(Error::Capacity)?)
                .filter(|v| *v <= isize::MAX as usize)
                .ok_or(Error::Capacity)?;
        }
        Ok(Self {
            context,
            links: Table::new(limits.links)?,
            sources: Table::new(limits.sources)?,
            owners: Table::new(limits.source_owners)?,
            routes: Table::new(limits.routes)?,
            paths: Table::new(limits.paths)?,
            clients: Table::new(limits.clients)?,
            generation: 0,
            revision: 0,
            plateaus: Ipv4Plateaus::CONTEMPORARY,
        })
    }

    pub const fn context(&self) -> ContextId {
        self.context
    }
    /// Service-wide nonwrapping change clock. Each snapshot retains its last
    /// relevant value; unrelated changes can advance this without dirtying it.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub fn usage(&self) -> Usage {
        Usage {
            links: self.links.used(),
            sources: self.sources.used(),
            source_owners: self.owners.used(),
            routes: self.routes.used(),
            paths: self.paths.used(),
            clients: self.clients.used(),
        }
    }
    fn next_revision(&self) -> Result<u64, Error> {
        self.revision.checked_add(1).ok_or(Error::Exhausted)
    }
    fn next_generation(&self) -> Result<u64, Error> {
        self.generation.checked_add(1).ok_or(Error::Exhausted)
    }

    pub fn register_link(&mut self, interface: InterfaceKey, mtu: u32) -> Result<LinkId, Error> {
        if mtu < 68 {
            return Err(Error::InvalidArgument);
        }
        if self
            .links
            .slots
            .iter()
            .any(|s| s.value.is_some_and(|l| l.interface == interface))
        {
            return Err(Error::Duplicate);
        }
        let slot = self.links.free()?;
        let generation = self.next_generation()?;
        let revision = self.next_revision()?;
        let handle = self.links.insert(
            self.context,
            slot,
            generation,
            LinkInfo {
                interface,
                mtu,
                version: revision,
            },
        );
        self.generation = generation;
        self.commit_revision(revision);
        Ok(LinkId(handle))
    }

    pub fn link(&self, link: LinkId) -> Result<LinkInfo, Error> {
        self.links.get(self.context, link.0)
    }

    /// Administrative physical MTU change retains link identity. IPv6 users
    /// require at least1280; reject a change that would strand such authority.
    pub fn set_link_mtu(&mut self, link: LinkId, mtu: u32) -> Result<(), Error> {
        let old = self.link(link)?;
        if mtu < 68 || (mtu < 1280 && self.link_uses_ipv6(link)) {
            return Err(Error::InvalidArgument);
        }
        if old.mtu == mtu {
            return Ok(());
        }
        let revision = self.next_revision()?;
        self.links.slots[link.0.slot].value = Some(LinkInfo {
            mtu,
            version: revision,
            ..old
        });
        self.commit_revision(revision);
        Ok(())
    }

    fn link_uses_ipv6(&self, link: LinkId) -> bool {
        self.owners.slots.iter().filter_map(|s| s.value).any(|o| {
            o.link == link
                && self
                    .source_address(o.source)
                    .is_ok_and(|s| s.address.is_ipv6())
        }) || self
            .routes
            .slots
            .iter()
            .filter_map(|s| s.value)
            .any(|r| r.link == link && r.destination.network.is_ipv6())
    }

    /// Cascades route and ownership revocation. A globally scoped source with
    /// another live owner retains its identity and authority.
    pub fn remove_link(&mut self, link: LinkId) -> Result<(), Error> {
        self.link(link)?;
        let revision = self.next_revision()?;
        self.links.slots[link.0.slot].value = None;
        for slot in &mut self.routes.slots {
            if slot.value.is_some_and(|r| r.link == link) {
                slot.value = None;
            }
        }
        for slot in &mut self.owners.slots {
            if slot.value.is_some_and(|o| o.link == link) {
                slot.value = None;
            }
        }
        self.prune_sources();
        self.commit_revision(revision);
        Ok(())
    }

    fn check_address(&self, address: ScopedAddress) -> Result<(), Error> {
        if let Some(link) = address.zone {
            self.link(link)?;
        }
        Ok(())
    }

    /// Adds an owner claim; a global address registered on another link returns
    /// the same source identity. Repeating the same claim is idempotent.
    pub fn register_source(
        &mut self,
        address: ScopedAddress,
        link: LinkId,
    ) -> Result<SourceId, Error> {
        let info = self.link(link)?;
        self.check_address(address)?;
        if address.zone.is_some_and(|zone| zone != link)
            || (address.address.is_ipv6() && info.mtu < 1280)
        {
            return Err(Error::InvalidArgument);
        }
        let existing = self.sources.slots.iter().enumerate().find_map(|(slot, s)| {
            s.value.filter(|s| s.address == address).map(|_| {
                SourceId(Handle {
                    context: self.context,
                    slot,
                    generation: s.generation,
                })
            })
        });
        if let Some(source) = existing {
            if self.owners.slots.iter().any(|s| {
                s.value
                    .is_some_and(|o| o.source == source && o.link == link)
            }) {
                return Ok(source);
            }
        }
        let owner_slot = self.owners.free()?;
        let source_slot = if existing.is_none() {
            Some(self.sources.free()?)
        } else {
            None
        };
        let generation = if source_slot.is_some() {
            self.next_generation()?
        } else {
            self.generation
        };
        let revision = self.next_revision()?;
        let source = match (existing, source_slot) {
            (Some(source), _) => source,
            (_, Some(slot)) => {
                SourceId(
                    self.sources
                        .insert(self.context, slot, generation, Source { address }),
                )
            }
            _ => unreachable!(),
        };
        self.owners
            .insert(self.context, owner_slot, generation, Owner { source, link });
        self.generation = generation;
        self.commit_revision(revision);
        Ok(source)
    }

    /// Canonical source lookup; ownership is checked against the live link.
    /// No separate address registry is needed by the serialized host.
    pub fn local_source(&self, address: ScopedAddress, link: LinkId) -> Result<SourceId, Error> {
        self.link(link)?;
        self.sources.slots.iter().enumerate().find_map(|(slot, record)| {
            let source = record.value?;
            if source.address != address {
                return None;
            }
            let id = SourceId(Handle { context: self.context, slot, generation: record.generation });
            self.owns_source(id, link).ok().filter(|owned| *owned).map(|_| id)
        }).ok_or(Error::NoRoute)
    }

    pub fn sources(&self) -> impl Iterator<Item = (SourceId, ScopedAddress)> + '_ {
        self.sources.slots.iter().enumerate().filter_map(|(slot, record)| {
            record.value.map(|source| (SourceId(Handle {
                context: self.context, slot, generation: record.generation,
            }), source.address))
        })
    }

    pub fn source_address(&self, source: SourceId) -> Result<ScopedAddress, Error> {
        Ok(self.sources.get(self.context, source.0)?.address)
    }

    pub fn owns_source(&self, source: SourceId, link: LinkId) -> Result<bool, Error> {
        self.source_address(source)?;
        self.link(link)?;
        Ok(self.owners.slots.iter().any(|s| {
            s.value
                .is_some_and(|o| o.source == source && o.link == link)
        }))
    }

    pub fn remove_source_owner(&mut self, source: SourceId, link: LinkId) -> Result<(), Error> {
        if !self.owns_source(source, link)? {
            return Err(Error::SourceNotOwned);
        }
        let revision = self.next_revision()?;
        for slot in &mut self.owners.slots {
            if slot
                .value
                .is_some_and(|o| o.source == source && o.link == link)
            {
                slot.value = None;
            }
        }
        self.prune_sources();
        self.commit_revision(revision);
        Ok(())
    }

    fn prune_sources(&mut self) {
        for (slot, record) in self.sources.slots.iter_mut().enumerate() {
            let source = SourceId(Handle {
                context: self.context,
                slot,
                generation: record.generation,
            });
            if !self
                .owners
                .slots
                .iter()
                .any(|s| s.value.is_some_and(|o| o.source == source))
            {
                record.value = None;
            }
        }
    }

    fn validate_route(&self, route: Route) -> Result<(), Error> {
        let link = self.link(route.link)?;
        if route
            .source
            .is_some_and(|s| s.network.is_ipv4() != route.destination.network.is_ipv4())
            || (route.destination.network.is_ipv6() && link.mtu < 1280)
        {
            return Err(Error::InvalidArgument);
        }
        if let NextHop::Gateway(gateway) = route.next_hop {
            self.check_address(gateway)?;
            if gateway.address.is_ipv4() != route.destination.network.is_ipv4()
                || gateway.zone.is_some_and(|zone| zone != route.link)
            {
                return Err(Error::InvalidArgument);
            }
        }
        Ok(())
    }

    fn check_duplicate(&self, route: Route, except: Option<RouteId>) -> Result<(), Error> {
        for (slot, record) in self.routes.slots.iter().enumerate() {
            if except.is_some_and(|id| id.0.slot == slot) {
                continue;
            }
            if record.value.is_some_and(|r| r.ambiguous(route)) {
                return Err(Error::Duplicate);
            }
        }
        Ok(())
    }

    pub fn add_route(&mut self, route: Route) -> Result<RouteId, Error> {
        self.validate_route(route)?;
        self.check_duplicate(route, None)?;
        let slot = self.routes.free()?;
        let generation = self.next_generation()?;
        let revision = self.next_revision()?;
        let id = RouteId(self.routes.insert(self.context, slot, generation, route));
        self.generation = generation;
        self.commit_revision(revision);
        Ok(id)
    }

    pub fn route(&self, route: RouteId) -> Result<Route, Error> {
        self.routes.get(self.context, route.0)
    }

    /// Replacement always creates fresh authority, even for identical text.
    /// The occupied slot is reused, so replacement works at route capacity.
    pub fn replace_route(&mut self, old: RouteId, route: Route) -> Result<RouteId, Error> {
        self.route(old)?;
        self.validate_route(route)?;
        self.check_duplicate(route, Some(old))?;
        let generation = self.next_generation()?;
        let revision = self.next_revision()?;
        let id = RouteId(
            self.routes
                .insert(self.context, old.0.slot, generation, route),
        );
        self.generation = generation;
        self.commit_revision(revision);
        Ok(id)
    }

    pub fn remove_route(&mut self, route: RouteId) -> Result<(), Error> {
        self.route(route)?;
        let revision = self.next_revision()?;
        self.routes.slots[route.0.slot].value = None;
        self.commit_revision(revision);
        Ok(())
    }

    /// Atomic full replacement. Caller-owned input is validated completely
    /// before changing any slot, generation or revision. No temporary allocation.
    pub fn replace_routes(&mut self, routes: &[Route]) -> Result<(), Error> {
        if routes.len() > self.routes.slots.len() {
            return Err(Error::Capacity);
        }
        for (i, &route) in routes.iter().enumerate() {
            self.validate_route(route)?;
            if routes[..i].iter().any(|r| r.ambiguous(route)) {
                return Err(Error::Duplicate);
            }
        }
        let count = u64::try_from(routes.len()).map_err(|_| Error::Exhausted)?;
        let generation = self.generation.checked_add(count).ok_or(Error::Exhausted)?;
        let revision = self.next_revision()?;
        for slot in &mut self.routes.slots {
            slot.value = None;
        }
        for (i, &route) in routes.iter().enumerate() {
            self.routes
                .insert(self.context, i, self.generation + i as u64 + 1, route);
        }
        self.generation = generation;
        self.commit_revision(revision);
        Ok(())
    }

    pub fn resolve(&self, request: PathRequest) -> Result<ResolvedPath, Error> {
        self.resolve_via(request, request.destination)
    }

    /// Explicit originating source-route context, never inferred from ingress.
    /// Both final and forwarding destinations participate in canonical identity.
    pub fn resolve_via(&self, request: PathRequest, forwarding_destination: ScopedAddress) -> Result<ResolvedPath, Error> {
        let source = self.source_address(request.source)?;
        self.check_address(forwarding_destination)?;
        if forwarding_destination.address.is_ipv4() != request.destination.address.is_ipv4() {
            return Err(Error::InvalidArgument);
        }
        self.check_address(source)?;
        self.check_address(request.destination)?;
        if source.address.is_ipv4() != request.destination.address.is_ipv4()
            || (source.zone.is_some()
                && request.destination.zone.is_some()
                && source.zone != request.destination.zone)
        {
            return Err(Error::InvalidArgument);
        }
        // Owner records only reference live links and are pruned on deletion.
        if !self
            .owners
            .slots
            .iter()
            .any(|s| s.value.is_some_and(|o| o.source == request.source))
        {
            return Err(Error::SourceNotOwned);
        }
        let mut selected: Option<(RouteId, Route)> = None;
        for (slot, record) in self.routes.slots.iter().enumerate() {
            let Some(route) = record.value else {
                continue;
            };
            if !route.destination.contains(forwarding_destination.address)
                || route.source.is_some_and(|p| !p.contains(source.address))
                || route.dscp.is_some_and(|d| d != request.dscp)
                // A scoped source may reach an unscoped destination, but only
                // through its authoritative link, irrespective of precedence.
                || source.zone.is_some_and(|zone| zone != route.link)
                || forwarding_destination.zone.is_some_and(|zone| zone != route.link)
                || request
                    .destination
                    .zone
                    .is_some_and(|zone| zone != route.link)
            {
                continue;
            }
            if selected.is_none_or(|(_, old)| route.priority() > old.priority()) {
                selected = Some((
                    RouteId(Handle {
                        context: self.context,
                        slot,
                        generation: record.generation,
                    }),
                    route,
                ));
            }
        }
        let (id, route) = selected.ok_or(Error::NoRoute)?;
        let link = self.link(route.link)?;
        Ok(ResolvedPath {
            key: PathKey {
                context: self.context,
                source: request.source,
                source_address: source,
                destination: request.destination,
                forwarding_destination,
                dscp: request.dscp,
                link: route.link,
                next_hop: match route.next_hop {
                    NextHop::OnLink => ResolvedNextHop::Address(forwarding_destination),
                    NextHop::Gateway(g) => ResolvedNextHop::Address(g),
                    NextHop::Forwarder(id) => ResolvedNextHop::Forwarder(id),
                },
                route: id,
            },
            first_hop_mtu: link.mtu,
            link_version: link.version,
        })
    }

    /// Reconsider the entire route table, including newly shadowing entries.
    /// Returns current physical facts only if the exact original selection is
    /// still authoritative. A superseded key never silently migrates.
    pub fn validate_selection(&self, key: PathKey) -> Result<ResolvedPath, Error> {
        if key.context != self.context {
            return Err(Error::ForeignContext);
        }
        self.link(key.link)?;
        self.route(key.route)?;
        let current = self.resolve_via(key.request(), key.forwarding_destination)?;
        if current.key != key {
            return Err(Error::SelectionChanged);
        }
        Ok(current)
    }

    pub const fn ipv4_plateaus(&self) -> Ipv4Plateaus {
        self.plateaus
    }

    /// Source-free live policy update, independent of forwarding identity.
    //= https://www.rfc-editor.org/rfc/rfc1191#section-7
    //= reason=T7 canonical bounded16 IPv4 policy selects nine contemporary values from AWS EC2 and Google VPC MTU documentation, RFC2516 PPPoE and RFC791 wire/fallback/floor limits. PathService defaults to this compact policy and atomically replaces validated tables at runtime without source changes; public tests exercise historical/custom/contemporary replacement and fallback. The low-level ntcp adapter preserves historical defaults and Error compatibility. Owner-authorized utility integration is independently T12, not a prerequisite imposed by this example ioctl advice.
    //# We do not expect that the values in the table, especially for higher MTU levels, are going to be valid forever. The values given here are an implementation suggestion, NOT a specification or requirement. Implementors should use up-to-date references to pick a set of plateaus; it is important that the table not contain too many entries or the process of searching for a PMTU might waste Internet resources. Implementors should also make it convenient for customers without source code to update the table values in their systems (for example, the table in a BSD-derived Unix kernel could be changed using a new "ioctl" command).
    pub fn set_ipv4_plateaus(&mut self, table: Ipv4Plateaus) -> Result<(), Error> {
        if self.plateaus == table {
            return Ok(());
        }
        let revision = self.next_revision()?;
        self.plateaus = table;
        self.commit_revision(revision);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> PathService {
        PathService::new(
            ContextId::new(1),
            Limits {
                links: 1,
                sources: 1,
                source_owners: 1,
                routes: 1,
                paths: 2,
                clients: 2,
            },
        )
        .unwrap()
    }

    #[test]
    fn exhausted_counters_fail_before_mutation() {
        let mut service = service();
        service.generation = u64::MAX;
        assert_eq!(
            service.register_link(InterfaceKey(1), 1500),
            Err(Error::Exhausted)
        );
        assert_eq!(service.usage().links, 0);
        assert_eq!(service.revision(), 0);
        service.generation = 0;
        let link = service.register_link(InterfaceKey(1), 1500).unwrap();
        service.revision = u64::MAX;
        assert_eq!(service.set_link_mtu(link, 1492), Err(Error::Exhausted));
        assert_eq!(service.remove_link(link), Err(Error::Exhausted));
        assert_eq!(service.link(link).unwrap().mtu, 1500);
        let policy = service.ipv4_plateaus();
        assert_eq!(
            service.set_ipv4_plateaus(Ipv4Plateaus::RFC1191),
            Err(Error::Exhausted)
        );
        assert_eq!(service.ipv4_plateaus(), policy);
        assert_eq!(service.revision(), u64::MAX);
    }

    #[test]
    fn batch_generation_exhaustion_preserves_old_routes() {
        let mut service = service();
        let link = service.register_link(InterfaceKey(1), 1500).unwrap();
        let route = Route {
            destination: IpPrefix::new("0.0.0.0".parse().unwrap(), 0).unwrap(),
            source: None,
            dscp: None,
            link,
            next_hop: NextHop::OnLink,
            metric: 0,
        };
        let id = service.add_route(route).unwrap();
        let revision = service.revision();
        service.generation = u64::MAX;
        assert_eq!(service.replace_routes(&[route]), Err(Error::Exhausted));
        assert_eq!(service.replace_route(id, route), Err(Error::Exhausted));
        assert_eq!(service.route(id), Ok(route));
        assert_eq!(service.revision(), revision);
    }
}
