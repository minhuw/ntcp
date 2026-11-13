// The Host's IPv4 neighbor backend: ARP (RFC 826) resolution of IPv4 next
// hops on neighbor ports. Every IPv4 neighbor access of the Host goes
// through the `Ipv4NeighborTable` calls, served by the Host's own cache
// (`Limits::ipv4_neighbors`; the default, nothing, registers no link) or by
// a table the embedding installs, such as one port's table shared by the
// Hosts of its queues.
use alloc::boxed::Box;
use core::any::Any;
use core::cell::Cell;
use core::net::Ipv4Addr;
use ntcp::Instant;
use ntcp_arp::{
    AddressKind, Arp, ArpCache, ArpCounters, ArpLimits, ArpState, ArpTimers, ControlOutcome,
    ControlToken, Event, Resolution, Wake,
};
use ntcp_path::LinkId;

use crate::discovery::HeldOutput;
use crate::{Entropy, Error, NeighborLimits};

/// The identity of one output attempt a table holds while its next hop
/// resolves: one record however often the attempt is retried. Opaque; a
/// table only stores, compares and returns it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NeighborHold(pub(crate) HeldOutput);

/// The IPv4 neighbor (ARP) state behind a Host's neighbor calls
/// (`Host::set_ipv4_neighbor_table`). Times are the Host's caller time; a
/// table clamps them never to move backwards. Every call is made by the
/// Host's owner, so a table shared beyond one Host synchronizes itself.
/// The embedding reaches its own table type again through `Any`.
pub trait Ipv4NeighborTable: Any + Send {
    /// Whether `link`'s IPv4 next hops are resolved here.
    fn has_link(&self, link: LinkId) -> bool;
    /// Resolve `link`'s IPv4 next hops here, its requests sent from `mac`;
    /// the link's ReachableTime is drawn from `entropy`.
    fn add_link(
        &mut self,
        link: LinkId,
        mac: [u8; 6],
        entropy: Option<&mut Entropy>,
    ) -> Result<(), Error>;
    /// Forget `link` with its entries, addresses and held output.
    fn remove_link(&mut self, link: LinkId);
    /// One of the node's own addresses on `link`: answered, and a source of
    /// the link's requests.
    fn add_local(&mut self, link: LinkId, address: Ipv4Addr) -> Result<(), Error>;
    fn remove_local(&mut self, link: LinkId, address: Ipv4Addr);
    /// A configured mapping: never expires, never replaced by learning.
    fn add_permanent(
        &mut self,
        link: LinkId,
        address: Ipv4Addr,
        mac: [u8; 6],
        now: Instant,
    ) -> Result<(), Error>;
    /// The MAC of `address` on `link` for output `held`, or None while it is
    /// held (once, however often retried) until `next_wake` reports its end.
    /// Exhausted storage is backpressure (`Error::Capacity`).
    fn resolve(
        &mut self,
        link: LinkId,
        address: Ipv4Addr,
        now: Instant,
        held: NeighborHold,
    ) -> Result<Option<[u8; 6]>, Error>;
    /// The next held output accepted by `filter` whose resolution ended,
    /// removed from the held set: resolved (true) or failed.
    fn next_wake(&mut self, filter: &dyn Fn(&NeighborHold) -> bool)
    -> Option<(NeighborHold, bool)>;
    /// A parsed ARP packet received on `link`; a reply answering this
    /// node's request draws a ReachableTime from `entropy`.
    fn receive(
        &mut self,
        link: LinkId,
        arp: &Arp,
        now: Instant,
        entropy: Option<&mut Entropy>,
    ) -> Result<(), Error>;
    /// Write `link`'s next due ARP body into `out`: its Ethernet
    /// destination, length and completion token. A table whose control
    /// output leaves by other means has none.
    fn output(
        &mut self,
        link: LinkId,
        now: Instant,
        out: &mut [u8],
    ) -> Result<Option<([u8; 6], usize, ControlToken)>, Error>;
    /// The backend's outcome for one message `output` wrote.
    fn complete(&mut self, token: ControlToken, outcome: ControlOutcome, now: Instant);
    /// Apply the timers due at `now`, reporting every neighbor found
    /// unreachable since the last call.
    fn service(&mut self, now: Instant, unreachable: &mut dyn FnMut(LinkId, Ipv4Addr));
    /// The earliest time `service` or `output` has work.
    fn next_deadline(&self) -> Option<Instant>;
    /// An upper-layer reachability confirmation of `address` by a packet
    /// submitted at `carried_at`; true when the entry stands confirmed.
    fn confirm(
        &mut self,
        link: LinkId,
        address: Ipv4Addr,
        carried_at: Instant,
        now: Instant,
        entropy: Option<&mut Entropy>,
    ) -> Result<bool, Error>;
    /// Cumulative counters of the table.
    fn counters(&self) -> ArpCounters;
    /// Inspection: the entry for `address` on `link`, its state and MAC.
    fn entry(&self, _link: LinkId, _address: Ipv4Addr) -> Option<(ArpState, Option<[u8; 6]>)> {
        None
    }
    /// The neighbour-state generation (`ArpCache::neighbor_generation`):
    /// it changes whenever a REACHABLE or PERMANENT entry leaves that
    /// state, changes its MAC or is removed. While it is unchanged, a MAC
    /// `connected` returned is what `resolve` returns, and the Host sends a
    /// connection's output to it without calling `resolve`. None (the
    /// default): every output resolves.
    fn generation(&self) -> Option<u64> {
        None
    }
    /// The MAC `resolve` would return for `address` on `link` while its
    /// entry is REACHABLE or PERMANENT, changing nothing; None otherwise.
    fn connected(&self, _link: LinkId, _address: Ipv4Addr) -> Option<[u8; 6]> {
        None
    }
}

// The Host's own cache.
pub(crate) struct Ipv4Neighbors {
    cache: ArpCache<LinkId, NeighborHold>,
    // The latest caller time seen. The cache starts its timers from the
    // time it is given, so time taken from out-of-order callers is clamped
    // to never move backwards.
    latest: Instant,
}

// Where the Host's IPv4 next hops resolve: an installed table, else its own
// cache, which ports use when storage was provided.
pub(crate) struct Ipv4Backend {
    own: Ipv4Neighbors,
    // The own cache's next deadline, kept between changes, which reach the
    // cache only through `table_mut`; None while not known.
    next: Cell<Option<Option<Instant>>>,
    enabled: bool,
    installed: Option<Box<dyn Ipv4NeighborTable>>,
}

impl Ipv4Backend {
    pub(crate) fn new(
        limits: NeighborLimits,
        links: usize,
        units_per_second: u64,
    ) -> Result<Self, Error> {
        let enabled = limits.entries != 0;
        let limits = ArpLimits {
            links: if enabled { links } else { 0 },
            entries: limits.entries,
            held: limits.pending_packets,
            replies: limits.answers,
            addresses: limits.addresses,
        };
        Ok(Self {
            own: Ipv4Neighbors {
                cache: ArpCache::new(limits, ArpTimers::default(), units_per_second)?,
                latest: 0,
            },
            next: Cell::new(None),
            enabled,
            installed: None,
        })
    }
    // Ports that receive IPv4 resolve it here.
    pub(crate) fn enabled(&self) -> bool {
        self.enabled || self.installed.is_some()
    }
    pub(crate) fn install(&mut self, table: Box<dyn Ipv4NeighborTable>) {
        self.installed = Some(table);
    }
    pub(crate) fn installed(&mut self) -> Option<&mut (dyn Ipv4NeighborTable + 'static)> {
        self.installed.as_deref_mut()
    }
    // The table's next deadline (`Ipv4NeighborTable::next_deadline`). The
    // own cache's is found once per change, not on every look; an
    // installed table's, which other owners may change, on every look.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        if let Some(table) = &self.installed {
            return table.next_deadline();
        }
        let next = self.next.get().unwrap_or_else(|| {
            let next = self.own.next_deadline();
            self.next.set(Some(next));
            next
        });
        debug_assert_eq!(next, self.own.next_deadline());
        next
    }
    pub(crate) fn table(&self) -> &dyn Ipv4NeighborTable {
        match &self.installed {
            Some(table) => &**table,
            None => &self.own,
        }
    }
    pub(crate) fn table_mut(&mut self) -> &mut dyn Ipv4NeighborTable {
        self.next.set(None);
        match &mut self.installed {
            Some(table) => &mut **table,
            None => &mut self.own,
        }
    }
}

// The cache's draws: four octets of the Host's entropy, or None when it is
// absent or fails.
fn draw(entropy: Option<&mut Entropy>) -> impl FnMut() -> Option<u32> {
    let mut entropy = entropy;
    move || {
        let entropy = entropy.as_mut()?;
        let mut bytes = [0; 4];
        entropy(&mut bytes).ok().map(|_| u32::from_be_bytes(bytes))
    }
}

impl From<ntcp_arp::Error> for Error {
    fn from(error: ntcp_arp::Error) -> Self {
        use ntcp_arp::Error as Arp;
        match error {
            Arp::Capacity => Error::Capacity,
            Arp::Allocation => Error::Allocation,
            Arp::Entropy => Error::Entropy,
            Arp::UnknownLink => Error::InvalidContext,
            Arp::Duplicate => Error::Path(ntcp_path::Error::Duplicate),
            Arp::NoSource => Error::Path(ntcp_path::Error::SourceNotOwned),
            Arp::Truncated => Error::Codec(ntcp_ip::Error::Truncated),
            // Not resolvable by ARP (broadcast, multicast, unspecified or an
            // own address), or a packet of another hardware or protocol space.
            _ => Error::Unsupported,
        }
    }
}

impl Ipv4Neighbors {
    fn now(&mut self, now: Instant) -> Instant {
        self.latest = self.latest.max(now);
        self.latest
    }
}

impl Ipv4NeighborTable for Ipv4Neighbors {
    fn has_link(&self, link: LinkId) -> bool {
        self.cache.has_link(link)
    }
    fn add_link(
        &mut self,
        link: LinkId,
        mac: [u8; 6],
        entropy: Option<&mut Entropy>,
    ) -> Result<(), Error> {
        Ok(self.cache.add_link(link, mac, &mut draw(entropy))?)
    }
    fn remove_link(&mut self, link: LinkId) {
        self.cache.remove_link(link);
    }
    fn add_local(&mut self, link: LinkId, address: Ipv4Addr) -> Result<(), Error> {
        Ok(self.cache.add_address(link, address, AddressKind::Local)?)
    }
    fn remove_local(&mut self, link: LinkId, address: Ipv4Addr) {
        self.cache.remove_address(link, address);
    }
    fn add_permanent(
        &mut self,
        link: LinkId,
        address: Ipv4Addr,
        mac: [u8; 6],
        now: Instant,
    ) -> Result<(), Error> {
        let now = self.now(now);
        Ok(self.cache.add_permanent(link, address, mac, now)?)
    }
    fn resolve(
        &mut self,
        link: LinkId,
        address: Ipv4Addr,
        now: Instant,
        held: NeighborHold,
    ) -> Result<Option<[u8; 6]>, Error> {
        let now = self.now(now);
        Ok(match self.cache.resolve(link, address, now, held)? {
            Resolution::Ready(mac) => Some(mac),
            Resolution::Held => None,
        })
    }
    fn next_wake(
        &mut self,
        filter: &dyn Fn(&NeighborHold) -> bool,
    ) -> Option<(NeighborHold, bool)> {
        Some(match self.cache.next_wake(filter)? {
            Wake::Retry(held) => (held, true),
            Wake::Unreachable(held) => (held, false),
        })
    }
    fn receive(
        &mut self,
        link: LinkId,
        arp: &Arp,
        now: Instant,
        entropy: Option<&mut Entropy>,
    ) -> Result<(), Error> {
        let now = self.now(now);
        Ok(self.cache.receive(link, arp, now, &mut draw(entropy))?)
    }
    fn output(
        &mut self,
        link: LinkId,
        now: Instant,
        out: &mut [u8],
    ) -> Result<Option<([u8; 6], usize, ControlToken)>, Error> {
        let now = self.now(now);
        let Some((control, token)) = self.cache.next_control(link, now) else {
            return Ok(None);
        };
        // An unwritten message is polled again: polling changed nothing.
        let len = ntcp_arp::encode(out, &control.arp).map_err(|_| Error::Capacity)?;
        Ok(Some((control.destination, len, token)))
    }
    fn complete(&mut self, token: ControlToken, outcome: ControlOutcome, now: Instant) {
        let now = self.now(now);
        self.cache.complete(token, outcome, now);
    }
    fn service(&mut self, now: Instant, unreachable: &mut dyn FnMut(LinkId, Ipv4Addr)) {
        let now = self.now(now);
        self.cache.service(now, &mut |event| match event {
            Event::Unreachable { link, address } => unreachable(link, address),
        });
    }
    fn next_deadline(&self) -> Option<Instant> {
        self.cache.next_deadline()
    }
    fn confirm(
        &mut self,
        link: LinkId,
        address: Ipv4Addr,
        carried_at: Instant,
        now: Instant,
        entropy: Option<&mut Entropy>,
    ) -> Result<bool, Error> {
        let now = self.now(now);
        Ok(self
            .cache
            .confirm(link, address, carried_at, now, &mut draw(entropy))?)
    }
    fn counters(&self) -> ArpCounters {
        self.cache.counters()
    }
    fn entry(&self, link: LinkId, address: Ipv4Addr) -> Option<(ArpState, Option<[u8; 6]>)> {
        self.cache.entry(link, address)
    }
    fn generation(&self) -> Option<u64> {
        Some(self.cache.neighbor_generation())
    }
    fn connected(&self, link: LinkId, address: Ipv4Addr) -> Option<[u8; 6]> {
        self.cache.connected(link, address)
    }
}
