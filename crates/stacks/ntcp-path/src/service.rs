use alloc::{boxed::Box, vec::Vec};
use core::{
    cmp::Reverse,
    mem::size_of,
    net::{IpAddr, Ipv6Addr},
};

use crate::{Error, Ipv4Plateaus};

/// Supplied by the authoritative embedding. A value must identify exactly one
/// service for its entire lifetime, including restarts with retained handles.
/// Embeddings must allocate distinct values for independent network contexts;
/// addresses and interface indices do not establish context identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ContextId(u64);

impl ContextId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
    pub const fn value(self) -> u64 {
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

impl LinkId {
    /// The complete identity (context, slot, generation) as fixed-width
    /// big-endian octets: keyed digests of scoped identities include it, so
    /// a recycled slot never names the same zone.
    pub fn to_bytes(self) -> [u8; 24] {
        let mut bytes = [0; 24];
        bytes[..8].copy_from_slice(&self.0.context.0.to_be_bytes());
        bytes[8..16].copy_from_slice(&(self.0.slot as u64).to_be_bytes());
        bytes[16..].copy_from_slice(&self.0.generation.to_be_bytes());
        bytes
    }
}
handle!(RouteId);

mod cache;
mod redirect;
#[cfg(test)]
mod segment_route_tests;
pub use cache::*;
pub use redirect::NeighborLoss;

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

/// Largest SR segment list: the Segment Routing Header carries the n
/// segments and the final destination as 16-octet entries, and its 8-bit
/// Hdr Ext Len counts 8-octet units after the first 8 (RFC 8200 4.4), so
/// 2(n + 1) <= 255.
pub(crate) const MAX_SEGMENTS: usize = 126;

/// Whether `segments` S1..Sn may be configured for SR routes to
/// `destination` (`PathService::add_segment_route`): an IPv6 prefix of
/// final destinations beyond the link, and 1..=`MAX_SEGMENTS` segments
/// each forwarded to beyond this link, so no scoped, multicast, loopback or
/// unspecified address names an SR node. Embeddings check configuration
/// with it before installation.
pub fn check_segment_route(destination: IpPrefix, segments: &[Ipv6Addr]) -> Result<(), Error> {
    if segments.is_empty()
        || segments.len() > MAX_SEGMENTS
        || !destination.network.is_ipv6()
        || destination.scoped()
        || segments.iter().any(|s| {
            s.is_unspecified() || s.is_multicast() || s.is_loopback() || s.is_unicast_link_local()
        })
    {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// Validated and fallibly allocated before any route mutation.
fn segment_list(route: Route, segments: &[Ipv6Addr]) -> Result<Box<[Ipv6Addr]>, Error> {
    if segments.is_empty() {
        return Ok(Box::default());
    }
    check_segment_route(route.destination, segments)?;
    let mut list = Vec::new();
    list.try_reserve_exact(segments.len())
        .map_err(|_| Error::Allocation)?;
    list.extend_from_slice(segments);
    Ok(list.into_boxed_slice())
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

/// `address/length` with a canonical network, as `IpPrefix::new`.
impl core::str::FromStr for IpPrefix {
    type Err = Error;
    fn from_str(text: &str) -> Result<Self, Error> {
        let (network, length) = text.split_once('/').ok_or(Error::InvalidArgument)?;
        if length.is_empty() || !length.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::InvalidArgument);
        }
        Self::new(
            network.parse().map_err(|_| Error::InvalidArgument)?,
            length.parse().map_err(|_| Error::InvalidArgument)?,
        )
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
    // The forwarding generation of the Redirect override that chose
    // `next_hop`; 0 for the route's own next hop.
    forwarding: u64,
}

impl PathKey {
    pub const fn context(&self) -> ContextId {
        self.context
    }
    pub const fn source(&self) -> SourceId {
        self.source
    }
    pub const fn source_address(&self) -> ScopedAddress {
        self.source_address
    }
    pub const fn destination(&self) -> ScopedAddress {
        self.destination
    }
    /// Actual destination used for forwarding (the first source-route hop
    /// when explicitly supplied), distinct from the transport destination.
    pub const fn forwarding_destination(&self) -> ScopedAddress {
        self.forwarding_destination
    }
    pub const fn dscp(&self) -> Dscp {
        self.dscp
    }
    pub const fn link(&self) -> LinkId {
        self.link
    }
    pub const fn next_hop(&self) -> ResolvedNextHop {
        self.next_hop
    }
    pub const fn route(&self) -> RouteId {
        self.route
    }
    pub const fn request(&self) -> PathRequest {
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
    pub const fn key(&self) -> PathKey {
        self.key
    }
    pub const fn first_hop_mtu(&self) -> u32 {
        self.first_hop_mtu
    }
    pub const fn link_version(&self) -> u64 {
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
        self.get_ref(context, handle).copied()
    }
    // Readers of one field of a large record (a cached path) borrow it.
    fn get_ref(&self, context: ContextId, handle: Handle) -> Result<&T, Error> {
        if handle.context != context {
            return Err(Error::ForeignContext);
        }
        self.slots
            .get(handle.slot)
            .filter(|s| s.generation == handle.generation)
            .and_then(|s| s.value.as_ref())
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
    // Owner policy per route slot, preallocated beside the route table.
    route_admin: Vec<RouteAdmin>,
    // Immutable SR segment list S1..Sn of the route in the same slot and
    // generation; empty for an ordinary route. Cleared with the route.
    route_segments: Vec<Box<[Ipv6Addr]>>,
    // Redirect overrides, one slot per cached path: the population of
    // destinations whose first hop a Redirect can change.
    redirects: Vec<Option<redirect::Redirect>>,
    // Slots of `redirects` holding an override, ascending: what every
    // selection consults (`set_redirect`).
    installed: Vec<usize>,
    // A shared nonwrapping generation domain prevents reuse after deletion.
    generation: u64,
    revision: u64,
    admin_revision: u64,
    // Counts the changes that may have made a client dirty (`dirtied`).
    dirtied: u64,
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
            (limits.routes, size_of::<RouteAdmin>()),
            (limits.routes, size_of::<Box<[Ipv6Addr]>>()),
            (limits.paths, size_of::<Option<redirect::Redirect>>()),
            (limits.paths, size_of::<usize>()),
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
            route_admin: {
                let mut records = Vec::new();
                records
                    .try_reserve_exact(limits.routes)
                    .map_err(|_| Error::Allocation)?;
                records.resize(limits.routes, RouteAdmin::default());
                records
            },
            route_segments: {
                let mut records = Vec::new();
                records
                    .try_reserve_exact(limits.routes)
                    .map_err(|_| Error::Allocation)?;
                // Empty boxed slices do not allocate.
                records.resize_with(limits.routes, Box::default);
                records
            },
            redirects: {
                let mut records = Vec::new();
                records
                    .try_reserve_exact(limits.paths)
                    .map_err(|_| Error::Allocation)?;
                records.resize(limits.paths, None);
                records
            },
            installed: {
                let mut slots = Vec::new();
                slots
                    .try_reserve_exact(limits.paths)
                    .map_err(|_| Error::Allocation)?;
                slots
            },
            generation: 0,
            revision: 0,
            admin_revision: 0,
            dirtied: 0,
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
        for (slot, record) in self.routes.slots.iter_mut().enumerate() {
            if record.value.is_some_and(|r| r.link == link) {
                record.value = None;
                self.route_segments[slot] = Box::default();
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
        self.add_segment_route(route, &[])
    }

    /// A Segment Routing route (RFC 8754 4.1, an SR source node, as Linux
    /// seg6 inline encapsulation): a packet whose final destination D the
    /// route selects carries a Segment Routing Header listing `segments`
    /// S1..Sn and D, and is forwarded towards S1 over the route's link and
    /// next hop. The list is immutable for the route generation; an empty
    /// list is an ordinary route. IPv6 only, at most `MAX_SEGMENTS` unscoped
    /// unicast segments; the list is allocated before anything changes.
    pub fn add_segment_route(
        &mut self,
        route: Route,
        segments: &[Ipv6Addr],
    ) -> Result<RouteId, Error> {
        self.validate_route(route)?;
        let list = segment_list(route, segments)?;
        self.check_duplicate(route, None)?;
        let slot = self.routes.free()?;
        let generation = self.next_generation()?;
        let revision = self.next_revision()?;
        let id = RouteId(self.routes.insert(self.context, slot, generation, route));
        self.route_segments[slot] = list;
        self.generation = generation;
        self.commit_revision(revision);
        Ok(id)
    }

    pub fn route(&self, route: RouteId) -> Result<Route, Error> {
        self.routes.get(self.context, route.0)
    }

    /// The segment list S1..Sn of a live route generation; empty for an
    /// ordinary route.
    pub fn route_segments(&self, route: RouteId) -> Result<&[Ipv6Addr], Error> {
        self.route(route)?;
        Ok(&self.route_segments[route.0.slot])
    }

    /// Replacement always creates fresh authority, even for identical text.
    /// The occupied slot is reused, so replacement works at route capacity.
    /// Owner administrative policy moves to the replacement; learned path
    /// state does not (paths through the old generation are invalidated).
    /// A replacement whose destination family differs from the old route's
    /// is an unrelated route for administration, like a removal followed by
    /// an addition: it inherits no policy, hold or restriction. A
    /// same-family replacement keeps the record, also onto a link of
    /// another MTU; a carried estimate above the new first hop then means
    /// exactly what a stored estimate means after `set_link_mtu` lowers its
    /// link: it caps nothing above the first hop, and search targets are
    /// clipped by the first hop.
    /// The replacement is an ordinary route: an SR route's segment list ends
    /// with its generation. A failed replacement changes no route,
    /// generation, segment list or administrative policy.
    pub fn replace_route(&mut self, old: RouteId, route: Route) -> Result<RouteId, Error> {
        self.route(old)?;
        self.validate_route(route)?;
        let list = segment_list(route, &[])?;
        self.check_duplicate(route, Some(old))?;
        let generation = self.next_generation()?;
        let revision = self.next_revision()?;
        self.transfer_route_admin(old, generation, route);
        let id = RouteId(
            self.routes
                .insert(self.context, old.0.slot, generation, route),
        );
        self.route_segments[old.0.slot] = list;
        self.generation = generation;
        self.commit_revision(revision);
        Ok(id)
    }

    pub fn remove_route(&mut self, route: RouteId) -> Result<(), Error> {
        self.route(route)?;
        let revision = self.next_revision()?;
        self.routes.slots[route.0.slot].value = None;
        self.route_segments[route.0.slot] = Box::default();
        self.commit_revision(revision);
        Ok(())
    }

    /// Atomic full replacement. Caller-owned input is validated completely
    /// before changing any slot, generation or revision. No temporary allocation.
    /// Administrative policy is dropped; see `replace_routes_mapped`.
    pub fn replace_routes(&mut self, routes: &[Route]) -> Result<(), Error> {
        self.replace_routes_mapped(routes, &[])
    }

    /// Full replacement that carries owner policy only along explicit
    /// `(old route, index into routes)` mappings; every unmapped route's
    /// policy is dropped. New routes occupy slots `0..routes.len()`, so the
    /// replacement of `routes[i]` is the live route in slot `i`. A mapping
    /// onto a route of the other destination family is invalid input
    /// (`InvalidArgument`, nothing changed): that replacement is an
    /// unrelated route. A carried estimate above a smaller new first hop
    /// has the meaning described for `replace_route`.
    pub fn replace_routes_mapped(
        &mut self,
        routes: &[Route],
        carry: &[(RouteId, usize)],
    ) -> Result<(), Error> {
        if routes.len() > self.routes.slots.len() {
            return Err(Error::Capacity);
        }
        self.check_route_mapping(routes, carry)?;
        for (i, &route) in routes.iter().enumerate() {
            self.validate_route(route)?;
            if routes[..i].iter().any(|r| r.ambiguous(route)) {
                return Err(Error::Duplicate);
            }
        }
        let count = u64::try_from(routes.len()).map_err(|_| Error::Exhausted)?;
        let generation = self.generation.checked_add(count).ok_or(Error::Exhausted)?;
        let revision = self.next_revision()?;
        self.stage_route_mapping(carry);
        for slot in &mut self.routes.slots {
            slot.value = None;
        }
        for segments in &mut self.route_segments {
            *segments = Box::default();
        }
        for (i, &route) in routes.iter().enumerate() {
            self.routes
                .insert(self.context, i, self.generation + i as u64 + 1, route);
        }
        self.install_route_mapping();
        self.generation = generation;
        self.commit_revision(revision);
        Ok(())
    }

    /// Selects by the final destination. A selected SR route derives the
    /// forwarding destination S1 from its segment list.
    pub fn resolve(&self, request: PathRequest) -> Result<ResolvedPath, Error> {
        self.select(request, None)
    }

    /// Explicit originating source-route context, never inferred from ingress.
    /// Both final and forwarding destinations participate in canonical identity.
    /// A forwarding destination equal to the final destination is `resolve`;
    /// any other selects by the forwarding destination among ordinary routes
    /// only, since an SR route's prefix describes final destinations.
    pub fn resolve_via(&self, request: PathRequest, forwarding_destination: ScopedAddress) -> Result<ResolvedPath, Error> {
        self.select(
            request,
            (forwarding_destination != request.destination).then_some(forwarding_destination),
        )
    }

    //= https://www.rfc-editor.org/rfc/rfc8201#section-3
    //= reason=No same-link bypass: PathService::select resolves an on-link route's next hop to the destination itself and keys, estimates and correlates that path exactly as a gateway path, so on-link destinations get the same shared estimate, Packet Too Big processing and PLPMTUD; the Host resolves the next hop by bounded host Neighbor Discovery (Host::resolve_neighbor holds output until an NS/NA exchange maps it), which changes no Path MTU state. Host test on_link_route_resolves_by_neighbor_discovery_and_keeps_pmtud: an on-link route is resolved by NS/NA before the SYN leaves and a downstream PTB correlated with a definitely submitted data segment lowers the path estimate to 1280 while the 1500 first-hop fact stays; core wire test ipv6_same_prefix_proxy_wire_path_does_not_bypass_downstream_ptb: 1500-to-1280 feedback, bounded repair and real receiver progress for a same-/64 peer. Namespace evidence (T19, AC-22; integration/rfc_host nd-proxy cases): the native runtime selects a destination inside its /64 through its on-link route, and a Linux router answers its Neighbor Solicitation for that destination, which lies behind it, as an NDP proxy (proxy_ndp with ip -6 neigh add proxy); no native segment precedes the solicited proxy NA and every segment carries the router's MAC with the destination's IPv6 address. After the router's downstream link falls from 1500 to 1280 its kernel-generated PTB (MTU 1280, valid checksum, Icmp6OutPktTooBigs rising by the PTBs captured) quotes a captured native packet larger than 1280, the dropped range is repaired in packets of at most 1280 octets, complete bidirectional hashed streams reach EOF with the native runtime as client and as server, the 1500-octet first-hop MTU stays, and existing and new sockets report 1280 through IPV6_MTU. The black-hole variant (the router's outgoing PTBs dropped by an owned nft rule) still delivers the stream through connection-local PLPMTUD fallback without a shared-estimate change, and the gateway variant shows the same PTB processing through an io.gateway route resolved by NS/NA.
    //# Note that Path MTU Discovery must be performed even in cases where a node "thinks" a destination is attached to the same link as itself, as it might have a PMTU lower than the link MTU. In a situation such as when a neighboring router acts as proxy [ND] for some destination, the destination can appear to be directly connected, but it is in fact more than one hop away.
    fn select(&self, request: PathRequest, explicit: Option<ScopedAddress>) -> Result<ResolvedPath, Error> {
        let matched = explicit.unwrap_or(request.destination);
        let source = self.source_address(request.source)?;
        self.check_address(matched)?;
        if matched.address.is_ipv4() != request.destination.address.is_ipv4() {
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
            let segment_route = !self.route_segments[slot].is_empty();
            if !route.destination.contains(matched.address)
                // An SR route carries final destinations of its prefix; a
                // scoped destination's scope ends at its own link.
                || (segment_route && (explicit.is_some() || request.destination.zone.is_some()))
                || route.source.is_some_and(|p| !p.contains(source.address))
                || route.dscp.is_some_and(|d| d != request.dscp)
                // A scoped source may reach an unscoped destination, but only
                // through its authoritative link, irrespective of precedence.
                || source.zone.is_some_and(|zone| zone != route.link)
                || matched.zone.is_some_and(|zone| zone != route.link)
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
        let forwarding_destination = match self.route_segments[id.0.slot].first() {
            // Segments are unscoped unicast (`segment_list`).
            Some(&first) => ScopedAddress {
                address: IpAddr::V6(first),
                zone: None,
            },
            None => matched,
        };
        let (next_hop, forwarding) =
            match self.redirect_for(id, forwarding_destination, request.dscp) {
                Some(redirect) => (
                    ResolvedNextHop::Address(redirect.target()),
                    redirect.generation(),
                ),
                None => (
                    match route.next_hop {
                        NextHop::OnLink => ResolvedNextHop::Address(forwarding_destination),
                        NextHop::Gateway(g) => ResolvedNextHop::Address(g),
                        NextHop::Forwarder(id) => ResolvedNextHop::Forwarder(id),
                    },
                    0,
                ),
            };
        Ok(ResolvedPath {
            key: PathKey {
                context: self.context,
                source: request.source,
                source_address: source,
                destination: request.destination,
                forwarding_destination,
                dscp: request.dscp,
                link: route.link,
                next_hop,
                route: id,
                forwarding,
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
        // An SR route generation's segments are immutable: reselect by the
        // final destination and compare the derived S1 with the rest of the
        // key, never matching S1 against the route's destination prefix.
        let current = if self.route_segments(key.route)?.is_empty() {
            self.resolve_via(key.request(), key.forwarding_destination)?
        } else {
            self.resolve(key.request())?
        };
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
    //= reason=T7 canonical bounded16 IPv4 policy selects nine contemporary values from AWS EC2 and Google VPC MTU documentation, RFC2516 PPPoE and RFC791 wire/fallback/floor limits. PathService defaults to this compact policy and atomically replaces validated tables at runtime without source changes; public tests exercise historical/custom/contemporary replacement and fallback. The low-level ntcp adapter preserves historical defaults and Error compatibility. The Host owner also replaces the table at runtime through Host::admin_set_ipv4_plateaus (the Administration capability, the same validated PathService replacement), which the ntcp-pathctl utility's plateaus command reaches through the opt-in local control socket of the native runtime and tun_echo, the counterpart of the suggested ioctl (ntcp-path-control tests/control.rs).
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
    fn exhausted_admin_revision_fails_before_change() {
        let mut service = service();
        let link = service.register_link(InterfaceKey(1), 1500).unwrap();
        let id = service
            .add_route(Route {
                destination: IpPrefix::new("0.0.0.0".parse().unwrap(), 0).unwrap(),
                source: None,
                dscp: None,
                link,
                next_hop: NextHop::OnLink,
                metric: 0,
            })
            .unwrap();
        service.admin_revision = u64::MAX;
        let change = AdminChange {
            target: AdminTarget::Route(id),
            expected: 0,
            policy: AdminPolicy {
                discovery_disabled: true,
                estimate: None,
            },
        };
        assert_eq!(service.prepare_admin(change, 0, 600), Err(Error::Exhausted));
        assert_eq!(service.route_administration(id).unwrap().policy, AdminPolicy::default());
        // An identical (empty) policy needs no generation and still succeeds.
        let noop = service
            .prepare_admin(AdminChange {
                policy: AdminPolicy::default(),
                ..change
            }, 0, 600)
            .unwrap();
        assert!(noop.is_noop());
        service.commit_admin(noop).unwrap();
        assert_eq!(service.admin_revision(), u64::MAX);
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
