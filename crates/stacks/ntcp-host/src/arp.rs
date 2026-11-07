// The Host's IPv4 neighbor backend: ARP (RFC 826) resolution of IPv4 next
// hops on neighbor ports. Every ArpCache access of the Host goes through
// this one struct, so that another backing (a table shared by several
// Hosts) can replace it behind the same calls. Its storage comes from
// `Limits::ipv4_neighbors`; the default (nothing) registers no link.
use core::net::Ipv4Addr;
use ntcp::Instant;
use ntcp_arp::{
    AddressKind, ArpCache, ArpCounters, ArpLimits, ArpTimers, ControlOutcome, Event, Resolution,
    Wake,
};
use ntcp_path::LinkId;

use crate::discovery::HeldOutput;
use crate::{Entropy, Error, NeighborLimits};

pub(crate) use ntcp_arp::ControlToken;

pub(crate) struct Ipv4Neighbors {
    cache: ArpCache<LinkId, HeldOutput>,
    // Storage was provided: ports that receive IPv4 resolve it here.
    enabled: bool,
    // The latest caller time seen. The cache starts its timers from the
    // time it is given, so time taken from out-of-order callers is clamped
    // to never move backwards.
    latest: Instant,
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

fn error(error: ntcp_arp::Error) -> Error {
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

impl Ipv4Neighbors {
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
            cache: ArpCache::new(limits, ArpTimers::default(), units_per_second).map_err(error)?,
            enabled,
            latest: 0,
        })
    }
    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }
    fn now(&mut self, now: Instant) -> Instant {
        self.latest = self.latest.max(now);
        self.latest
    }
    pub(crate) fn has_link(&self, link: LinkId) -> bool {
        self.cache.has_link(link)
    }
    pub(crate) fn add_link(
        &mut self,
        link: LinkId,
        mac: [u8; 6],
        entropy: Option<&mut Entropy>,
    ) -> Result<(), Error> {
        self.cache
            .add_link(link, mac, &mut draw(entropy))
            .map_err(error)
    }
    pub(crate) fn remove_link(&mut self, link: LinkId) {
        self.cache.remove_link(link);
    }
    // One of the node's own addresses on `link`: answered, and the source
    // of the link's requests (its first one).
    pub(crate) fn add_local(&mut self, link: LinkId, address: Ipv4Addr) -> Result<(), Error> {
        self.cache
            .add_address(link, address, AddressKind::Local)
            .map_err(error)
    }
    pub(crate) fn remove_local(&mut self, link: LinkId, address: Ipv4Addr) {
        self.cache.remove_address(link, address);
    }
    // A configured mapping: never expires, never replaced by learning.
    pub(crate) fn add_permanent(
        &mut self,
        link: LinkId,
        address: Ipv4Addr,
        mac: [u8; 6],
        now: Instant,
    ) -> Result<(), Error> {
        let now = self.now(now);
        self.cache
            .add_permanent(link, address, mac, now)
            .map_err(error)
    }
    pub(crate) fn resolve(
        &mut self,
        link: LinkId,
        address: Ipv4Addr,
        now: Instant,
        held: HeldOutput,
    ) -> Result<Option<[u8; 6]>, Error> {
        let now = self.now(now);
        Ok(
            match self
                .cache
                .resolve(link, address, now, held)
                .map_err(error)?
            {
                Resolution::Ready(mac) => Some(mac),
                Resolution::Held => None,
            },
        )
    }
    // The next held output accepted by `filter` whose resolution ended,
    // removed from the held set: resolved (true) or failed.
    pub(crate) fn next_wake(
        &mut self,
        filter: impl Fn(&HeldOutput) -> bool,
    ) -> Option<(HeldOutput, bool)> {
        Some(match self.cache.next_wake(filter)? {
            Wake::Retry(held) => (held, true),
            Wake::Unreachable(held) => (held, false),
        })
    }
    // A received ARP body (Ethernet padding may follow it).
    pub(crate) fn receive(
        &mut self,
        link: LinkId,
        body: &[u8],
        now: Instant,
        entropy: Option<&mut Entropy>,
    ) -> Result<(), Error> {
        let arp = ntcp_arp::parse(body).map_err(error)?;
        let now = self.now(now);
        self.cache
            .receive(link, &arp, now, &mut draw(entropy))
            .map_err(error)
    }
    // Write `link`'s next due ARP body into `out`: its Ethernet
    // destination, length and completion token.
    pub(crate) fn output(
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
    pub(crate) fn complete(&mut self, token: ControlToken, outcome: ControlOutcome, now: Instant) {
        let now = self.now(now);
        self.cache.complete(token, outcome, now);
    }
    // Apply every timer due at `now`; each failed entry is reported.
    pub(crate) fn service(&mut self, now: Instant, unreachable: &mut impl FnMut(LinkId, Ipv4Addr)) {
        let now = self.now(now);
        self.cache.service(now, &mut |event| match event {
            Event::Unreachable { link, address } => unreachable(link, address),
        });
    }
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.cache.next_deadline()
    }
    // An upper-layer reachability confirmation by a packet submitted at
    // `carried_at`.
    pub(crate) fn confirm(
        &mut self,
        link: LinkId,
        address: Ipv4Addr,
        carried_at: Instant,
        now: Instant,
        entropy: Option<&mut Entropy>,
    ) -> Result<bool, Error> {
        let now = self.now(now);
        self.cache
            .confirm(link, address, carried_at, now, &mut draw(entropy))
            .map_err(error)
    }
    pub(crate) fn counters(&self) -> ArpCounters {
        self.cache.counters()
    }
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn entry(
        &self,
        link: LinkId,
        address: Ipv4Addr,
    ) -> Option<(ntcp_arp::ArpState, Option<[u8; 6]>)> {
        self.cache.entry(link, address)
    }
}
