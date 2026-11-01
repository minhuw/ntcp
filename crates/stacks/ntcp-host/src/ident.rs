//! Identification allocation for the non-atomic datagrams this Host
//! originates, and the entropy dependency it draws on.
//!
//! RFC 6864 section 4.3: the IPv4 Identification of a non-atomic datagram
//! MUST NOT be repeated for the same (source, destination, protocol) within
//! the maximum datagram lifetime (MDL), whatever flow, route or DSCP carried
//! it; a source that cannot meet this MUST NOT send. RFC 6864 sections 1 and
//! 3.2 treat the MDL as an operational estimate (120 seconds is the default
//! here, RFC 6864 section 1's figure, not a guaranteed network maximum): no
//! finite lifetime protects against a packet the network delays without
//! bound, which is why every lease is held for the whole configured MDL and
//! never evicted. RFC 8200 section 4.5 requires an IPv6 Identification that
//! differs from every other recently fragmented packet with the same source
//! and destination; RFC 7739 section 5 recommends making it unpredictable,
//! so IPv6 values come from the entropy supply with an exact check against
//! every outstanding lease of the pair.
//!
//! Continuity: a lease outlives addresses, links, routes and the Host
//! context itself. A replacement Host either receives this allocator, with
//! the same timebase (`Host::take_identifiers`, `Continuity::Transfer`), or
//! issues nothing until a full MDL after the previous context stopped
//! emitting (`Continuity::QuietSince`). Hosts that use one source address at
//! the same time must share one allocator; a Host never issues from an
//! allocator another Host owns, because transfer moves it.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ntcp::Instant;

use crate::Error;

/// The entropy supply could not deliver unpredictable octets. There is no
/// weaker fallback: what needed them is not issued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntropyError;

/// A fallible cryptographically secure random source supplied by the
/// embedding (the operating system's CSPRNG).
pub type Entropy = Box<dyn FnMut(&mut [u8]) -> Result<(), EntropyError> + Send>;

/// Allocator storage and the MDL. The default (no tuples, no IPv6 leases)
/// issues no identifier, so the Host originates no non-atomic datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentifierLimits {
    /// The maximum datagram lifetime every lease is held for, in seconds.
    pub lifetime_seconds: u32,
    /// Concurrent IPv4 (source, destination, protocol) tuples with live
    /// leases; each holds a counter and per-block expiry times.
    pub ipv4_tuples: usize,
    /// Concurrent IPv6 leases, one per non-atomic datagram within the MDL.
    pub ipv6_leases: usize,
}

impl Default for IdentifierLimits {
    fn default() -> Self {
        Self {
            lifetime_seconds: DEFAULT_LIFETIME_SECONDS,
            ipv4_tuples: 0,
            ipv6_leases: 0,
        }
    }
}

/// RFC 6864 section 1 (and RFC 791's TTL upper bound of 255 seconds is not
/// used: RFC 6864 section 3.2 treats 120 seconds as the operational MDL).
pub const DEFAULT_LIFETIME_SECONDS: u32 = 120;

/// Bounded retries for an IPv6 value that collides with a live lease of the
/// same pair. With 2^32 values a single retry already makes repeated
/// collision negligible unless the table is close to the whole space, which
/// no realistic `ipv6_leases` is; exhausting the retries is backpressure.
const IPV6_RETRIES: usize = 4;

/// IPv4 identifiers are tracked in 256 blocks of 256 values per tuple: a
/// block may be re-entered only once every value issued from it has
/// expired. This bounds the state per tuple (2 KiB) at the cost of up to
/// 255 values of granularity below the RFC 6864 ceiling of 65536 per MDL.
const BLOCKS: usize = 256;

/// Why no identifier was issued: explicit backpressure, never a reused
/// value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentifierBackpressure {
    /// No allocator is started (or the configured storage is zero), or the
    /// quiet period of `Continuity::QuietSince` lasts until `until`.
    Unavailable { until: Option<Instant> },
    /// Every value that may be issued next is still leased (the RFC 6864
    /// ceiling of 65536 non-atomic datagrams per tuple per MDL, or a full
    /// lease table); retry at `retry_at`.
    Exhausted { retry_at: Instant },
    /// The entropy supply failed.
    Entropy,
}

/// How a newly started allocator relates to earlier Host contexts that used
/// the same sources.
pub enum Continuity {
    /// The previous context, if any, stopped emitting at this instant of
    /// this Host's timebase; nothing is issued until a full MDL later.
    QuietSince(Instant),
    /// Deployment knowledge stated at `at`: no earlier context had emitted
    /// from these sources for at least `seconds` before it (`u64::MAX`: no
    /// earlier emission at all, for example addresses or a link that did
    /// not exist before this Host). Nothing is issued until a full MDL after
    /// that emission ceased. This asserts a fact about the deployment; it
    /// does not shorten the MDL.
    QuietFor { at: Instant, seconds: u64 },
    /// Exclusive ownership of the previous context's allocator.
    Transfer(IdentifierAllocator),
}

#[derive(Clone, Copy)]
struct Tuple {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    next: u16,
    fresh: bool,
}

#[derive(Clone, Copy)]
struct Lease6 {
    source: Ipv6Addr,
    destination: Ipv6Addr,
    identification: u32,
    expires: Instant,
}

/// The allocator. Moves between Host contexts only as a whole.
pub struct IdentifierAllocator {
    limits: IdentifierLimits,
    units_per_second: u64,
    lifetime: Instant,
    running: bool,
    not_before: Instant,
    tuples: Vec<Option<Tuple>>,
    blocks: Vec<Instant>,
    leases: Vec<Option<Lease6>>,
}

impl IdentifierAllocator {
    /// Storage is allocated once; the lifetime must be nonzero when any
    /// storage is configured.
    pub fn new(limits: IdentifierLimits, units_per_second: u64) -> Result<Self, Error> {
        if (limits.ipv4_tuples != 0 || limits.ipv6_leases != 0) && limits.lifetime_seconds == 0 {
            return Err(Error::Capacity);
        }
        let lifetime = u64::from(limits.lifetime_seconds)
            .checked_mul(units_per_second)
            .ok_or(Error::Capacity)?;
        Ok(Self {
            limits,
            units_per_second,
            lifetime,
            running: false,
            not_before: 0,
            tuples: crate::table(limits.ipv4_tuples, None)?,
            blocks: crate::table(
                limits
                    .ipv4_tuples
                    .checked_mul(BLOCKS)
                    .ok_or(Error::Capacity)?,
                0,
            )?,
            leases: crate::table(limits.ipv6_leases, None)?,
        })
    }
    pub fn limits(&self) -> IdentifierLimits {
        self.limits
    }
    pub(crate) fn units_per_second(&self) -> u64 {
        self.units_per_second
    }
    pub(crate) fn start_quiet(&mut self, stopped: Instant) {
        self.running = true;
        self.not_before = stopped.saturating_add(self.lifetime);
    }
    // Emission ceased `seconds` before `at`: the part of the MDL that has
    // not yet elapsed remains.
    pub(crate) fn start_quiet_for(&mut self, at: Instant, seconds: u64) {
        let elapsed = seconds.saturating_mul(self.units_per_second);
        self.running = true;
        self.not_before = at.saturating_add(self.lifetime.saturating_sub(elapsed));
    }
    // A transferred allocator keeps its own quiet period; one that was
    // never started carries no continuity and cannot be transferred.
    pub(crate) fn running(&self) -> bool {
        self.running
    }

    fn available(&self, now: Instant) -> Result<(), IdentifierBackpressure> {
        if !self.running {
            return Err(IdentifierBackpressure::Unavailable { until: None });
        }
        if now < self.not_before {
            return Err(IdentifierBackpressure::Unavailable {
                until: Some(self.not_before),
            });
        }
        Ok(())
    }

    /// Issue the Identification of one non-atomic datagram whose last
    /// possible physical submission happens at `now`; its lease ends a full
    /// MDL later.
    pub(crate) fn issue(
        &mut self,
        now: Instant,
        source: IpAddr,
        destination: IpAddr,
        protocol: u8,
        entropy: Option<&mut Entropy>,
    ) -> Result<u32, IdentifierBackpressure> {
        self.available(now)?;
        match (source, destination) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => self
                .issue_v4(now, source, destination, protocol, entropy)
                .map(u32::from),
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                self.issue_v6(now, source, destination, entropy)
            }
            _ => Err(IdentifierBackpressure::Unavailable { until: None }),
        }
    }

    fn issue_v4(
        &mut self,
        now: Instant,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: u8,
        entropy: Option<&mut Entropy>,
    ) -> Result<u16, IdentifierBackpressure> {
        let matches =
            |t: &Tuple| t.source == source && t.destination == destination && t.protocol == protocol;
        let index = match self.tuples.iter().position(|t| t.as_ref().is_some_and(matches)) {
            Some(index) => index,
            None => {
                // A tuple whose every lease expired is reclaimed; a live one
                // never is.
                let blocks = &self.blocks;
                let reusable = |i: usize| blocks[i * BLOCKS..][..BLOCKS].iter().all(|e| *e <= now);
                let Some(index) = (0..self.tuples.len())
                    .find(|&i| self.tuples[i].is_none() || reusable(i))
                else {
                    let retry_at = (0..self.tuples.len())
                        .filter_map(|i| self.blocks[i * BLOCKS..][..BLOCKS].iter().copied().max())
                        .min();
                    return Err(match retry_at {
                        Some(retry_at) => IdentifierBackpressure::Exhausted { retry_at },
                        None => IdentifierBackpressure::Unavailable { until: None },
                    });
                };
                // RFC 7739 section 5.1: a per-destination counter starting
                // at a random value keeps the sequence of one tuple from
                // revealing another's. The start is a random block boundary
                // so that the full 65536 values are usable within one MDL.
                let mut start = [0; 2];
                entropy
                    .ok_or(IdentifierBackpressure::Entropy)?(&mut start)
                    .map_err(|_| IdentifierBackpressure::Entropy)?;
                self.tuples[index] = Some(Tuple {
                    source,
                    destination,
                    protocol,
                    next: u16::from_be_bytes([start[0], 0]),
                    fresh: true,
                });
                self.blocks[index * BLOCKS..][..BLOCKS].fill(0);
                index
            }
        };
        let tuple = self.tuples[index].as_mut().unwrap();
        let id = tuple.next;
        let block = &mut self.blocks[index * BLOCKS + usize::from(id >> 8)];
        // Entering a block (or starting a tuple) requires every value issued
        // from that block in the previous cycle to have expired.
        if (tuple.fresh || id & 0xff == 0) && *block > now {
            return Err(IdentifierBackpressure::Exhausted { retry_at: *block });
        }
        *block = (*block).max(now.saturating_add(self.lifetime));
        tuple.next = id.wrapping_add(1);
        tuple.fresh = false;
        Ok(id)
    }

    fn issue_v6(
        &mut self,
        now: Instant,
        source: Ipv6Addr,
        destination: Ipv6Addr,
        entropy: Option<&mut Entropy>,
    ) -> Result<u32, IdentifierBackpressure> {
        let Some(slot) = self
            .leases
            .iter()
            .position(|l| l.is_none_or(|l| l.expires <= now))
        else {
            return Err(match self.leases.iter().flatten().map(|l| l.expires).min() {
                Some(retry_at) => IdentifierBackpressure::Exhausted { retry_at },
                None => IdentifierBackpressure::Unavailable { until: None },
            });
        };
        let entropy = entropy.ok_or(IdentifierBackpressure::Entropy)?;
        for _ in 0..IPV6_RETRIES {
            let mut value = [0; 4];
            entropy(&mut value).map_err(|_| IdentifierBackpressure::Entropy)?;
            let identification = u32::from_be_bytes(value);
            let collides = self.leases.iter().flatten().any(|l| {
                l.expires > now
                    && l.source == source
                    && l.destination == destination
                    && l.identification == identification
            });
            if !collides {
                self.leases[slot] = Some(Lease6 {
                    source,
                    destination,
                    identification,
                    expires: now.saturating_add(self.lifetime),
                });
                return Ok(identification);
            }
        }
        Err(IdentifierBackpressure::Exhausted {
            retry_at: now.saturating_add(1),
        })
    }
}
