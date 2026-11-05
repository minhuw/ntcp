//! Connectionless sizing and the ICMP Echo adjunct prober (RFC 4821 section
//! 10.3).
//!
//! Datagrams the Host source-fragments (Host UDP in Fragment mode, Echo
//! Replies) are cut to the connectionless effective size E = min(shared
//! ordinary budget, max(connectionless initial, confirmed lower bound)). The
//! confirmed lower bound is this module's: per path incarnation, the largest
//! unfragmented Echo Request whose matching Echo Reply proved forward
//! delivery. It is Host-certified state about one path, separate from the
//! shared learned ceilings: it is never written to shared state as a negative
//! observation and never lowers another client's budget. Where the path has a
//! learned ceiling below a confirmed size, the confirmation is offered to
//! `PathService::confirm_delivery`, which applies its own revision, hold and
//! first-hop rules (an unlearned path answers NotLarger: nothing is
//! manufactured).
//!
//! RFC 4821 section 10.3 recommends that IP fragmentation used as a
//! packetization layer rely on shared path state plus an adjunct protocol to
//! probe the Path MTU, naming ICMP Echo among the candidates while preferring
//! forward-only methods. Echo is used here because every host must implement
//! the responder (RFC 1122 section 3.2.2.6, RFC 4443 section 4.1), the Host
//! can verify the reply against an unpredictable identifier, sequence and
//! data nonce it chose, and a matching reply proves forward delivery of the
//! unfragmented request. Forward-only methods need the destination's
//! cooperation in a protocol of its choosing, which raw IP datagrams do not
//! have. The return path's MTU never enters the result: a reply that was
//! fragmented on its way back still proves only forward delivery of the
//! request.
//!
//! Probing is driven by demand: a path on which the Host sent a fragmented
//! datagram keeps that demand until a search has serviced it (after the
//! path's conservative hold), with no further sends needed and no
//! datagram-count threshold. At most one probe per path is outstanding and
//! the number of paths with state is bounded by `AdjunctLimits::paths`; a
//! full table replaces the least recently used path without an outstanding
//! probe (the bounded counterpart of RFC 4821 section 10.3's illustrative LRU
//! cache), and demand that finds every entry probing is dropped and counted.
//! Silence and ICMP errors other than a Packet Too Big lower only the
//! search's upper bound, never E or a shared ceiling; a correlated Packet Too
//! Big for a probe is an ordinary trusted decrease of the probe's path.
//!
//! The owner's administrative estimate of the path (RFC 1191 section 6.6,
//! RFC 8201 section 5.6: actual knowledge of its PMTU) replaces the largest
//! fragmented datagram as the search's upper bound, intersected with the
//! first hop and the search's negative evidence. It is never delivery
//! evidence: it changes neither E nor the confirmed lower bound. Once per
//! administrative value, the first probe the existing demand, hold,
//! outstanding-probe, retry and restart rules allow targets the value
//! (within those bounds) instead of the midpoint; a failure lowers the
//! search's upper bound as any other, and a later value is clipped by that
//! negative evidence until the search restarts. The latest value's attempt
//! (deferred, or sent and possibly clipped) is reported with the TCP
//! diagnostic vocabulary through the administration query. A discovery
//! disable makes the outstanding probe ineligible for size results in the
//! administration transaction itself (a later re-enable does not revive it)
//! and no probe leaves while it holds: a reply to a probe sent before a
//! disable proves no size and narrows nothing, while a correlated Packet Too
//! Big for it is still the ordinary trusted shared decrease (the router's
//! report is a network fact about a packet definitely sent). The ineligible
//! probe stays correlatable until its reply deadline, then lapses without
//! loss evidence.

use alloc::vec::Vec;
use ntcp::{
    AdministrativeClip, AdministrativeDeferral, AdministrativeSearch, Instant, IpMetadata,
    NetworkError,
};
use ntcp_icmp::EchoKind;
use ntcp_path::{
    DeliveryConfirmation, Dscp, EstimateChange, PathId, PathSnapshot, PathStatus, ScopedAddress,
};

use crate::emitter::{DatagramError, Plan};
use crate::{BackendOutcome, Error, Host, IngressPacket, UdpEgress};

/// Octets of the unpredictable data nonce that opens every probe's data; the
/// rest of the data repeats it, so the complete echoed data is checked.
const NONCE: usize = 16;

/// RFC 4821 section 7.3: "The value for this timer MUST NOT be less than 5
/// minutes and is recommended to be 10 minutes, per RFC 1981."
pub const MIN_RESTART_SECONDS: u64 = 300;
pub const DEFAULT_RESTART_SECONDS: u64 = 600;

/// Configuration of the Echo adjunct. Probes leave through the Host ICMP
/// output drain (`Host::icmp_output`), so the adjunct needs that queue
/// enabled and uses its path client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdjunctLimits {
    /// Paths with connectionless sizing state (demand, search and confirmed
    /// lower bound), each with at most one outstanding probe. Zero (the
    /// default) disables the adjunct: E is then the configured initial value.
    pub paths: usize,
    /// How long a probe waits for its Echo Reply before it counts as lost,
    /// in milliseconds. There is no round-trip sample for a connectionless
    /// path; the default of 3 seconds is the conservative initial
    /// retransmission timeout RFC 6298 section 2 keeps as its fallback and
    /// RFC 1122 section 4.2.3.1 used, so an ordinary reply is not mistaken
    /// for a loss. A late reply only makes the search stop lower (benign,
    /// RFC 4821 section 10.3); the next restart probes again.
    pub reply_timeout_ms: u32,
    /// RFC 4821 section 7.3's timer after convergence before the search
    /// restarts from its initial upper bound; at least 300 seconds.
    pub restart_seconds: u64,
}

impl Default for AdjunctLimits {
    fn default() -> Self {
        Self {
            paths: 0,
            reply_timeout_ms: 3_000,
            restart_seconds: DEFAULT_RESTART_SECONDS,
        }
    }
}

impl AdjunctLimits {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.paths != 0
            && (self.reply_timeout_ms == 0 || self.restart_seconds < MIN_RESTART_SECONDS)
        {
            return Err(Error::Capacity);
        }
        Ok(())
    }
}

/// What the adjunct did, cumulatively.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AdjunctCounters {
    /// Echo Requests submitted (definitely or possibly).
    pub probes: u64,
    /// Matching replies: forward delivery certified.
    pub confirmed: u64,
    /// Probes that drew no matching reply within the timeout, or a matching
    /// ICMP error other than Packet Too Big.
    pub lost: u64,
    /// Probes a correlated Packet Too Big reported dropped.
    pub too_big: u64,
    /// Echo Replies that matched no outstanding probe exactly (forged,
    /// late, altered or for an uncertain submission).
    pub unmatched_replies: u64,
    /// Searches that converged.
    pub converged: u64,
    /// Demand dropped because every entry had a probe outstanding.
    pub demand_dropped: u64,
    /// Probes not sent: no entropy, or the backend refused before submission.
    pub not_sent: u64,
}

/// The adjunct's view of an ICMP message about one of its probes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeOutcome {
    /// A matching Echo Reply: forward delivery of `size` complete IP octets
    /// is certified and the path's confirmed lower bound is at least `size`.
    /// `published` is `confirm_delivery`'s disposition (None when the path
    /// incarnation is no longer valid).
    Confirmed {
        size: u32,
        published: Option<DeliveryConfirmation>,
    },
    /// A correlated Packet Too Big for a probe of `size` octets: an ordinary
    /// trusted decrease of the probe's path.
    TooBig {
        size: u32,
        mtu: Option<u32>,
        published: Option<EstimateChange>,
    },
    /// Another ICMP error about a probe: the search's upper bound falls
    /// below it, nothing else changes.
    Failed { size: u32, error: NetworkError },
    /// An Echo Reply matching no outstanding probe exactly; nothing changes.
    Unmatched,
}

#[derive(Clone, Copy, Debug)]
enum Search {
    /// Demand waits for the first probe.
    Pending,
    /// Probing between `low` (exclusive, delivered or the effective size)
    /// and `high` (inclusive).
    Active { low: u32, high: u32 },
    /// Converged at this instant; restarts with fresh demand after the
    /// restart interval.
    Converged(Instant),
}

#[derive(Clone, Copy, Debug)]
struct Probe {
    size: u32,
    // The probe's complete IP header length: the base header and, on an SR
    // path, its Segment Routing Header. A reply may omit extension headers,
    // so only the rest of `size` is compared with it.
    header: u32,
    identifier: u16,
    sequence: u16,
    nonce: [u8; NONCE],
    sent_at: Instant,
    // Only a definitely submitted probe is certified by its reply.
    definite: bool,
    negative_revision: u64,
    // False once the path's discovery policy changed after submission: the
    // probe's reply or loss is no size result (RFC 1191 6.6 / RFC 8201
    // 5.6); a PTB for it is still a trusted shared decrease.
    eligible: bool,
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    path: PathId,
    ip: IpMetadata,
    dscp: u8,
    // Host-confirmed lower bound, complete IP octets (0: none).
    confirmed: u32,
    // Largest fragmented datagram (complete IP octets) and when demand last
    // arrived.
    demand: u32,
    demand_at: Instant,
    used_at: Instant,
    search: Search,
    probe: Option<Probe>,
    // Local retry deadline: no probe before it. Silence never touches the
    // shared hold.
    not_before: Instant,
    // Negative evidence of the current search: the largest size not yet
    // shown undeliverable (a lost or too-big probe minus one). Cleared when
    // a search (re)starts from its initial upper bound.
    negative: Option<u32>,
    // The path's effective administrative estimate as last observed, the
    // armed once-per-value target and the latest value's diagnostic.
    admin: Option<u32>,
    admin_target: Option<u32>,
    admin_search: Option<AdministrativeSearch>,
    // The path's owner disabled discovery: no probe leaves for it.
    disabled: bool,
}

impl Entry {
    // The search's initial upper bound: the first hop, capped by the
    // administrative estimate when one is set and otherwise by the largest
    // fragmented datagram (no larger size is needed without other
    // knowledge of the path).
    fn ceiling(&self, first_hop: u32) -> u32 {
        first_hop.min(self.admin.unwrap_or(self.demand))
    }

    // Take in the path's current administrative estimate: a new value caps
    // an active search afresh (with its negative evidence kept) and arms
    // one targeted attempt; an unchanged value changes nothing.
    fn observe(&mut self, snapshot: PathSnapshot) {
        self.disabled = snapshot.discovery_disabled();
        if self.disabled
            && let Some(probe) = &mut self.probe
        {
            // RFC 1191 6.6 / RFC 8201 5.6: discovery is not done on this
            // path. The outstanding probe loses size-result eligibility
            // (its reply publishes nothing and its loss narrows nothing)
            // but stays correlatable until its reply deadline, so a PTB for
            // it still lowers the shared estimate. Demand and the confirmed
            // bound are kept.
            probe.eligible = false;
        }
        let value = snapshot.administrative_estimate();
        if value == self.admin {
            return;
        }
        self.admin = value;
        self.admin_target = value;
        self.admin_search = value.map(|target| AdministrativeSearch::Pending {
            target,
            deferred: None,
        });
        if let Search::Active { low, .. } = self.search {
            self.search = Search::Active {
                low,
                high: self
                    .ceiling(snapshot.first_hop_mtu())
                    .min(self.negative.unwrap_or(u32::MAX)),
            };
        }
    }

    fn defer(&mut self, reason: AdministrativeDeferral) {
        if self.admin_target.is_some()
            && let Some(AdministrativeSearch::Pending { deferred, .. }) = &mut self.admin_search
        {
            *deferred = Some(reason);
        }
    }

    // The armed target was attempted at `size` (`low` when nothing above
    // the search's lower bound remained), below the reachable `high`.
    fn attempted(&mut self, size: u32, low: u32, high: u32) {
        let Some(target) = self.admin_target.take() else {
            return;
        };
        let clipped = if size >= target {
            None
        } else if target <= low || high >= target {
            Some(AdministrativeClip::SearchLow)
        } else {
            Some(AdministrativeClip::SearchHigh)
        };
        self.admin_search = Some(AdministrativeSearch::Attempted {
            target,
            size,
            clipped,
        });
    }
}

pub(crate) struct Adjunct {
    limits: AdjunctLimits,
    entries: Vec<Option<Entry>>,
    timeout: u64,
    restart: u64,
    counters: AdjunctCounters,
}

impl Adjunct {
    pub fn new(limits: AdjunctLimits, units_per_second: u64) -> Result<Self, Error> {
        limits.validate()?;
        let timeout = u64::from(limits.reply_timeout_ms)
            .checked_mul(units_per_second / 1000)
            .ok_or(Error::Capacity)?;
        let restart = limits
            .restart_seconds
            .checked_mul(units_per_second)
            .ok_or(Error::Capacity)?;
        Ok(Self {
            limits,
            entries: crate::table(limits.paths, None)?,
            timeout,
            restart,
            counters: AdjunctCounters::default(),
        })
    }
    pub fn enabled(&self) -> bool {
        self.limits.paths != 0
    }
    pub fn confirmed(&self, path: PathId) -> u32 {
        self.entries
            .iter()
            .flatten()
            .find(|e| e.path == path)
            .map_or(0, |e| e.confirmed)
    }
    /// Whether the adjunct keeps state for `path`, and the diagnostic of its
    /// latest administrative target.
    pub fn administrative_search(&self, path: PathId) -> Option<Option<AdministrativeSearch>> {
        self.entries
            .iter()
            .flatten()
            .find(|e| e.path == path)
            .map(|e| e.admin_search)
    }
    fn deadline(&self, probe: &Probe) -> Instant {
        probe.sent_at.saturating_add(self.timeout)
    }
    // What keeps `entry` from probing at `now`, if anything: the path's
    // hold, an outstanding probe, the local retry deadline or the restart
    // interval (Cooldown), or no demand since convergence (nothing to send).
    fn deferral(
        &self,
        entry: &Entry,
        snapshot: PathSnapshot,
        now: Instant,
    ) -> Option<AdministrativeDeferral> {
        if entry.disabled {
            return Some(AdministrativeDeferral::DiscoveryDisabled);
        }
        if entry.probe.is_some() {
            return Some(AdministrativeDeferral::Cooldown);
        }
        if now < snapshot.retry_not_before() {
            return Some(AdministrativeDeferral::Hold);
        }
        match entry.search {
            Search::Converged(at) if entry.demand_at <= at => {
                Some(AdministrativeDeferral::DataOrWindow)
            }
            Search::Converged(at) if now < at.saturating_add(self.restart) => {
                Some(AdministrativeDeferral::Cooldown)
            }
            _ => (now < entry.not_before).then_some(AdministrativeDeferral::Cooldown),
        }
    }
    // Earliest instant at which `entry` may send its next probe, ignoring the
    // shared hold; None while nothing is to be done.
    fn ready_at(&self, entry: &Entry) -> Option<Instant> {
        // An outstanding probe (even an ineligible one on a disabled path)
        // is settled at its reply deadline.
        if let Some(probe) = &entry.probe {
            return Some(self.deadline(probe));
        }
        if entry.disabled {
            return None;
        }
        match entry.search {
            Search::Pending | Search::Active { .. } => Some(entry.not_before),
            Search::Converged(at) => (entry.demand_at > at)
                .then(|| at.saturating_add(self.restart).max(entry.not_before)),
        }
    }
}

impl Host {
    pub fn adjunct_counters(&self) -> AdjunctCounters {
        self.adjunct.counters
    }

    /// The connectionless effective size for `snapshot`'s path (complete IP
    /// octets): min(shared ordinary budget, max(connectionless initial,
    /// Host-confirmed lower bound)).
    pub(crate) fn connectionless_size(&self, snapshot: PathSnapshot) -> Result<u32, Error> {
        let floor = self
            .connectionless_initial(snapshot)
            .max(self.adjunct.confirmed(snapshot.path()));
        Ok(snapshot.ip_packet_budget()?.min(floor))
    }

    /// The connectionless effective size for a datagram that leaves over
    /// `snapshot`'s path but does not follow the direct route the adjunct
    /// probes (a source-routed one): min(shared ordinary budget,
    /// connectionless initial), never raised by a Host-confirmed bound.
    pub(crate) fn connectionless_unconfirmed_size(
        &self,
        snapshot: PathSnapshot,
    ) -> Result<u32, Error> {
        Ok(snapshot
            .ip_packet_budget()?
            .min(self.connectionless_initial(snapshot)))
    }

    fn connectionless_initial(&self, snapshot: PathSnapshot) -> u32 {
        if snapshot.key().destination().address().is_ipv4() {
            self.datagram_limits.connectionless.ipv4
        } else {
            self.datagram_limits.connectionless.ipv6
        }
    }

    /// Record that a datagram of `ip_len` complete IP octets was
    /// source-fragmented on `snapshot`'s path: demand the adjunct keeps until
    /// a search services it.
    pub(crate) fn adjunct_demand(
        &mut self,
        now: Instant,
        snapshot: PathSnapshot,
        ip: IpMetadata,
        dscp: u8,
        ip_len: u32,
    ) {
        if !self.adjunct.enabled() {
            return;
        }
        let path = snapshot.path();
        let adjunct = &mut self.adjunct;
        let index = match adjunct
            .entries
            .iter()
            .position(|e| e.is_some_and(|e| e.path == path))
        {
            Some(index) => index,
            None => {
                // A free entry, else the least recently used one without an
                // outstanding probe.
                let slot = adjunct
                    .entries
                    .iter()
                    .position(Option::is_none)
                    .or_else(|| {
                        adjunct
                            .entries
                            .iter()
                            .enumerate()
                            .filter(|(_, e)| e.is_some_and(|e| e.probe.is_none()))
                            .min_by_key(|(_, e)| e.map_or(0, |e| e.used_at))
                            .map(|(i, _)| i)
                    });
                let Some(slot) = slot else {
                    adjunct.counters.demand_dropped += 1;
                    return;
                };
                adjunct.entries[slot] = Some(Entry {
                    path,
                    ip,
                    dscp,
                    confirmed: 0,
                    demand: 0,
                    demand_at: now,
                    used_at: now,
                    search: Search::Pending,
                    probe: None,
                    not_before: now,
                    negative: None,
                    admin: None,
                    admin_target: None,
                    admin_search: None,
                    disabled: false,
                });
                slot
            }
        };
        let entry = adjunct.entries[index].as_mut().unwrap();
        entry.observe(snapshot);
        entry.demand = entry.demand.max(ip_len);
        entry.demand_at = entry.demand_at.max(now);
        entry.used_at = entry.used_at.max(now);
    }

    /// Whether `icmp_output` has a probe to send at `now` (besides queued
    /// messages), so that an embedding drains it even with an empty queue.
    pub fn adjunct_due(&self, now: Instant) -> bool {
        self.adjunct.entries.iter().flatten().any(|e| {
            self.adjunct.ready_at(e).is_some_and(|at| at <= now)
                && self
                    .paths
                    .path_snapshot(e.path)
                    .map_or(true, |s| e.probe.is_some() || s.retry_not_before() <= now)
        })
    }

    /// The earliest instant at which the adjunct has work: a probe's reply
    /// deadline, a retry deadline, a hold or restart expiring for retained
    /// demand. `service_changes` and `icmp_output` act on it.
    pub fn next_adjunct_deadline(&self) -> Option<Instant> {
        self.adjunct
            .entries
            .iter()
            .flatten()
            .filter_map(|e| {
                let at = self.adjunct.ready_at(e)?;
                Some(match (&e.probe, self.paths.path_snapshot(e.path)) {
                    (None, Ok(s)) => at.max(s.retry_not_before()),
                    _ => at,
                })
            })
            .min()
    }

    /// Drop the state of paths that are no longer valid incarnations, take
    /// in each path's administrative estimate and count every probe whose
    /// reply deadline passed as lost: RFC 4821 section 7.6.2 sets
    /// search_high to the probe size minus one. Neither lowers E or any
    /// shared value. An armed administrative target that cannot be probed
    /// at `now` records the precondition blocking it.
    // Deliver each tracked path's current snapshot (administrative estimate
    // and discovery policy) to its entry at once, without a time step.
    pub(crate) fn adjunct_observe(&mut self) {
        for index in 0..self.adjunct.entries.len() {
            let Some(mut entry) = self.adjunct.entries[index] else {
                continue;
            };
            if let Ok(snapshot) = self.paths.path_snapshot(entry.path)
                && snapshot.status() == PathStatus::Valid
            {
                entry.observe(snapshot);
                self.adjunct.entries[index] = Some(entry);
            }
        }
    }

    pub(crate) fn service_adjunct(&mut self, now: Instant) {
        for index in 0..self.adjunct.entries.len() {
            let Some(mut entry) = self.adjunct.entries[index] else {
                continue;
            };
            let snapshot = match self.paths.path_snapshot(entry.path) {
                Ok(snapshot) if snapshot.status() == PathStatus::Valid => snapshot,
                _ => {
                    self.adjunct.entries[index] = None;
                    continue;
                }
            };
            entry.observe(snapshot);
            if let Some(probe) = entry.probe
                && now >= self.adjunct.deadline(&probe)
            {
                // An ineligible probe lapses without loss evidence.
                if probe.eligible {
                    self.adjunct.counters.lost += 1;
                    lower(&mut entry, probe.size);
                }
                entry.probe = None;
                // The reply deadline was the local retry deadline.
                entry.not_before = now;
            }
            if let Some(reason) = self.adjunct.deferral(&entry, snapshot, now) {
                entry.defer(reason);
            }
            self.adjunct.entries[index] = Some(entry);
        }
    }

    /// Send the next due probe, if any, through `submit` (one unfragmented
    /// packet, IPv4 with DF). None when no probe is due.
    pub(crate) fn adjunct_probe(
        &mut self,
        now: Instant,
        packet: &mut [u8],
        submit: impl FnMut(UdpEgress, &[u8]) -> BackendOutcome,
    ) -> Result<Option<BackendOutcome>, Error> {
        if !self.adjunct.enabled() {
            return Ok(None);
        }
        self.service_adjunct(now);
        let mut submit = submit;
        // Each pass either sends, defers or settles one entry.
        for _ in 0..self.adjunct.entries.len() {
            let Some(index) = self
                .adjunct
                .entries
                .iter()
                .enumerate()
                .filter_map(|(i, e)| {
                    let e = e.as_ref()?;
                    let at = self.adjunct.ready_at(e)?;
                    (e.probe.is_none() && at <= now).then_some((i, at))
                })
                .min_by_key(|(_, at)| *at)
                .map(|(i, _)| i)
            else {
                return Ok(None);
            };
            if let Some(outcome) = self.probe_entry(now, index, packet, &mut submit)? {
                return Ok(Some(outcome));
            }
        }
        Ok(None)
    }

    // Select and send one probe for entry `index`; None when the entry was
    // settled without sending (converged, held, or its path changed).
    fn probe_entry(
        &mut self,
        now: Instant,
        index: usize,
        packet: &mut [u8],
        submit: &mut impl FnMut(UdpEgress, &[u8]) -> BackendOutcome,
    ) -> Result<Option<BackendOutcome>, Error> {
        let mut entry = self.adjunct.entries[index].unwrap();
        // The probe follows the demand's own path: same source, destination
        // and DSCP, and the same live incarnation.
        let snapshot = match self.probe_path(&entry) {
            Ok(snapshot) if snapshot.path() == entry.path => snapshot,
            _ => {
                self.adjunct.entries[index] = None;
                return Ok(None);
            }
        };
        // Demand is serviced after the shared hold (RFC 1191 section 6.3,
        // RFC 8201 section 4: no attempt to increase within it).
        entry.observe(snapshot);
        if now < snapshot.retry_not_before() {
            entry.not_before = snapshot.retry_not_before();
            entry.defer(AdministrativeDeferral::Hold);
            self.adjunct.entries[index] = Some(entry);
            return Ok(None);
        }
        let ipv4 = entry.ip.source.is_ipv4();
        let effective = self.connectionless_size(snapshot)?;
        let ceiling = entry.ceiling(snapshot.first_hop_mtu());
        let (low, high) = match entry.search {
            Search::Pending => {
                entry.negative = None;
                (effective, ceiling)
            }
            // RFC 4821 section 7.3: when the timer expires, search_high is
            // reset to its initial value so probing can resume.
            Search::Converged(at)
                if entry.demand_at > at && now >= at.saturating_add(self.adjunct.restart) =>
            {
                entry.negative = None;
                (effective, ceiling)
            }
            Search::Converged(at) => {
                entry.defer(if entry.demand_at > at {
                    AdministrativeDeferral::Cooldown
                } else {
                    AdministrativeDeferral::DataOrWindow
                });
                entry.not_before = now;
                self.adjunct.entries[index] = Some(entry);
                return Ok(None);
            }
            Search::Active { low, high } => (
                low.max(effective),
                high.min(snapshot.first_hop_mtu())
                    .min(entry.admin.unwrap_or(u32::MAX)),
            ),
        };
        // RFC 4821 section 7.3: each packetization layer MUST determine when
        // probing has converged. Fragments carry their data in multiples of
        // 8 octets (RFC 791 section 3.2, RFC 8200 section 4.5), so a range
        // narrower than 8 octets cannot enlarge any fragment.
        if high < low.saturating_add(8) {
            entry.search = Search::Converged(now);
            entry.not_before = now;
            entry.attempted(low, low, high);
            self.adjunct.counters.converged += 1;
            self.adjunct.entries[index] = Some(entry);
            return Ok(None);
        }
        // Halve the range (RFC 4821 section 7.3's binary search): a lost
        // Echo costs one packet, never retransmitted data. Integer progress:
        // low < size <= high. An armed administrative target is probed
        // instead, within the same bounds (high carries the first hop, the
        // value itself and negative evidence).
        let size = match entry.admin_target {
            Some(target) => target.min(high),
            None => low + (high - low).div_ceil(2),
        };
        entry.search = Search::Active { low, high };
        // The header H of the route the path selected (an SR route's
        // Segment Routing Header included) is indivisible: a probe of
        // `size` complete octets must hold it, the Echo header and the
        // whole nonce, or it is not sent; it is never truncated, sent over
        // another route or credited with data it cannot carry.
        let header = self.header_plan(snapshot.key())?.len;
        let Some(data_len) = (size as usize)
            .checked_sub(header + 8)
            .filter(|data| *data >= NONCE)
        else {
            self.adjunct.counters.not_sent += 1;
            entry.not_before = now.saturating_add(self.adjunct.timeout);
            self.adjunct.entries[index] = Some(entry);
            return Err(Error::Unsupported);
        };
        // On an ND-capable port the probe's next hop is resolved first; an
        // unresolved one holds the probe, which is due again once resolved
        // (`adjunct_settle`).
        let held = crate::discovery::HeldOutput::Probe(entry.path);
        let link_layer = match self.host_output_neighbor(snapshot.key(), now, held) {
            Ok(None) => None,
            Ok(Some(crate::NeighborHop::Resolved(mac))) => Some(mac),
            Ok(Some(crate::NeighborHop::Held)) => {
                entry.not_before = Instant::MAX;
                self.adjunct.entries[index] = Some(entry);
                return Ok(None);
            }
            Err(error) => {
                self.adjunct.counters.not_sent += 1;
                entry.not_before = now.saturating_add(self.adjunct.timeout);
                self.adjunct.entries[index] = Some(entry);
                return Err(error);
            }
        };
        let mut nonce = [0u8; NONCE + 4];
        let drawn = self
            .entropy
            .as_mut()
            .is_some_and(|fill| fill(&mut nonce).is_ok());
        if !drawn {
            // No weaker source: the probe waits a timeout and tries again.
            self.adjunct.counters.not_sent += 1;
            entry.not_before = now.saturating_add(self.adjunct.timeout);
            self.adjunct.entries[index] = Some(entry);
            return Ok(Some(BackendOutcome::NotSubmitted));
        }
        let identifier = u16::from_be_bytes([nonce[0], nonce[1]]);
        let sequence = u16::from_be_bytes([nonce[2], nonce[3]]);
        let nonce: [u8; NONCE] = nonce[4..].try_into().unwrap();
        let len = size as usize;
        let Some(packet) = packet.get_mut(..len) else {
            self.adjunct.entries[index] = Some(entry);
            return Err(Error::Capacity);
        };
        fill_probe(&nonce, &mut packet[header + 8..]);
        let ip = entry.ip;
        let message = ntcp_icmp::encode_echo(
            ip,
            EchoKind::Request,
            identifier,
            sequence,
            &mut packet[header..],
            data_len,
        )?;
        let hop_limit = self.icmp_output.hop_limit();
        let protocol = if ipv4 { 1 } else { 58 };
        // Unfragmented; the atomic IPv4 encoder sets DF.
        let encoded = if ipv4 {
            ntcp_ip::encode_datagram(
                packet,
                ntcp_ip::Header {
                    ip,
                    hop_limit,
                    dscp: entry.dscp,
                    ecn: 0,
                    ipv4_options: Default::default(),
                },
                protocol,
                message,
                0,
            )?
        } else {
            // On an SR path the probe carries the route's Segment Routing
            // Header, so it measures the path its datagrams take.
            ntcp_ip6::encode_routed(
                packet,
                ntcp_ip6::Header {
                    ip,
                    hop_limit,
                    dscp: entry.dscp,
                    ecn: 0,
                },
                self.header_plan(snapshot.key())?.segments,
                protocol,
                message,
            )?
        };
        if encoded != len {
            return Err(Error::Obsolete);
        }
        let plan = Plan {
            ip,
            protocol,
            dscp: entry.dscp,
            hop_limit,
            data_len: message,
            fragment_size: None,
            snapshot,
            client: None,
            options: None,
        };
        let mut resolved = |egress: UdpEgress, bytes: &[u8]| {
            submit(
                UdpEgress {
                    link_layer,
                    ..egress
                },
                bytes,
            )
        };
        let result = self.transmit(now, plan, packet, |_, _| None, None, None, &mut resolved);
        let outcome = match result {
            Ok(report) => {
                self.adjunct.counters.probes += 1;
                entry.probe = Some(Probe {
                    size,
                    header: header as u32,
                    identifier,
                    sequence,
                    nonce,
                    sent_at: now,
                    definite: report.submitted == 1,
                    negative_revision: snapshot.negative_revision(),
                    eligible: true,
                });
                entry.attempted(size, low, high);
                report.terminal.unwrap_or(BackendOutcome::Submitted)
            }
            Err(DatagramError::NotSubmitted(outcome)) => {
                // A blocked backend keeps the probe due; any other refusal
                // waits for the local retry deadline.
                if outcome != BackendOutcome::WouldBlock {
                    self.adjunct.counters.not_sent += 1;
                    entry.not_before = now.saturating_add(self.adjunct.timeout);
                }
                outcome
            }
            Err(error) => {
                self.adjunct.counters.not_sent += 1;
                entry.not_before = now.saturating_add(self.adjunct.timeout);
                self.adjunct.entries[index] = Some(entry);
                return Err(match error {
                    DatagramError::Host(error) => error,
                    _ => Error::Capacity,
                });
            }
        };
        entry.used_at = now;
        self.adjunct.entries[index] = Some(entry);
        Ok(Some(outcome))
    }

    // The probe of `path` held for its neighbor's resolution, which ended
    // (`resolved`) or is still waiting (None): due at once when resolved;
    // after a failure counted unsent and retried after the probe timeout,
    // as for other probes not sent. False when no entry holds a probe.
    pub(crate) fn adjunct_settle(
        &mut self,
        path: ntcp_path::PathId,
        resolved: Option<bool>,
        now: Instant,
    ) -> bool {
        let timeout = self.adjunct.timeout;
        let Some(entry) = self
            .adjunct
            .entries
            .iter_mut()
            .flatten()
            .find(|e| e.path == path && e.not_before == Instant::MAX)
        else {
            return false;
        };
        match resolved {
            None => {}
            Some(true) => entry.not_before = now,
            Some(false) => {
                entry.not_before = now.saturating_add(timeout);
                self.adjunct.counters.not_sent += 1;
            }
        }
        true
    }

    fn probe_path(&mut self, entry: &Entry) -> Result<PathSnapshot, Error> {
        let request = self.request(
            entry.ip.source,
            entry.ip.destination,
            None,
            Dscp::new(entry.dscp)?,
        )?;
        let via = ScopedAddress::new(entry.ip.destination, None)?;
        let resolved = self.paths.resolve_via(request, via)?;
        self.forwarding_resolved(resolved.key())?;
        let (client, snapshot) = self.paths.acquire_via(request, via)?;
        self.paths.release(client)?;
        if snapshot.status() != PathStatus::Valid {
            return Err(Error::Obsolete);
        }
        Ok(snapshot)
    }

    /// An Echo Reply addressed to this Host: certified forward delivery when
    /// it matches an outstanding, definitely submitted probe exactly (reply
    /// addresses reversed, identifier, sequence and every data octet of the
    /// nonce pattern) within its timeout on the probe's still-valid path
    /// incarnation. A reply reassembled from fragments proves the same
    /// forward delivery; its return path is not measured.
    //= https://www.rfc-editor.org/rfc/rfc4821#section-10.3
    //= reason=IP fragmentation is a packetization layer under unmodified applications here (Host UDP Fragment mode, Echo Replies (a reply to an IPv4 source-routed Echo Request takes the reversed, policy-authorized return route, registers no adjunct demand and is never sized by an adjunct-confirmed bound, while IPv6 Echo Replies use only owner-configured routes)), and it relies on Path MTU sharing plus an adjunct: fragments are cut to E, bounded by the shared PathService ordinary budget, which correlated PTBs about fragments and probes lower for every client; the Host-owned ICMP Echo adjunct (crates/stacks/ntcp-host/src/adjunct.rs) probes each path with fragmentation demand using unfragmented Echo Requests (DF on IPv4) carrying an unpredictable identifier, sequence and data nonce, sized by an RFC 4821 section 7.3 search between E (exclusive) and min(first-hop MTU, largest fragmented datagram). Only an exact, timely Echo Reply to a definitely submitted probe raises the path's confirmed lower bound and, under a learned ceiling below it, is offered to PathService::confirm_delivery (NotLarger on an unlearned path); silence and other errors lower only the search's upper bound, and a correlated PTB for a probe is an ordinary trusted decrease. Echo is used despite the preference for forward-only methods because every host implements the responder, the Host verifies its own nonce, and an exact reply proves forward delivery of the unfragmented request; a reply reassembled from fragments proves the same, so the return path limits the result only where the responder cannot deliver its reply at all (the search then stops lower, which is safe). Host tests cover the converging search, silence, forged, stale, mismatched and reassembled replies, a PTB for a probe and publication only under PathService rules; the integration/rfc_host fragment case raises IPv4 E only after a real Echo Reply and draws a real router PTB for a probe above 1280, and adjunct-silence shows that unanswered probes lower nothing.
    //# To support IP fragmentation as a Packetization Layer under an unmodified application, an implementation SHOULD rely on the Path MTU sharing described in Section 5.2 plus an adjunct protocol to probe the Path MTU. There are a number of protocols that might be used for the purpose, such as ICMP ECHO and ECHO REPLY, or "traceroute" style UDP datagrams that trigger ICMP messages. Use of ICMP ECHO and ECHO REPLY will probe both forward and return paths, so the sender will only be able to take advantage of the minimum of the two. Other methods that probe only the forward path are preferred if available.
    pub(crate) fn adjunct_reply(
        &mut self,
        now: Instant,
        packet: &IngressPacket,
    ) -> Result<ProbeOutcome, Error> {
        let reply = ntcp_icmp::decode_echo(packet.ip, packet.payload)?;
        if reply.kind != EchoKind::Reply {
            return Err(ntcp_ip::Error::Invalid.into());
        }
        let found = self.adjunct.entries.iter().position(|e| {
            e.and_then(|e| e.probe.map(|p| (e, p)))
                .is_some_and(|(e, p)| {
                    e.ip.source == packet.ip.destination
                        && e.ip.destination == packet.ip.source
                        && p.identifier == reply.identifier
                        && p.sequence == reply.sequence
                })
        });
        let Some(index) = found else {
            self.adjunct.counters.unmatched_replies += 1;
            return Ok(ProbeOutcome::Unmatched);
        };
        let mut entry = self.adjunct.entries[index].unwrap();
        let probe = entry.probe.unwrap();
        // The reply may omit the request's extension headers: its Echo
        // message must be the request's exactly, which certifies the
        // recorded request size on the probe's own path.
        let exact = probe.header + 8 + reply.data.len() as u32 == probe.size
            && matches_probe(&probe.nonce, reply.data);
        // An altered or late reply, or one for an uncertain submission,
        // certifies nothing; a forged one leaves the real probe outstanding.
        if !exact || !probe.definite || now >= self.adjunct.deadline(&probe) {
            self.adjunct.counters.unmatched_replies += 1;
            return Ok(ProbeOutcome::Unmatched);
        }
        if !probe.eligible {
            // Sent before a discovery-policy change: its exact reply settles
            // the probe and proves no size.
            entry.probe = None;
            entry.not_before = now;
            self.adjunct.entries[index] = Some(entry);
            self.adjunct.counters.unmatched_replies += 1;
            return Ok(ProbeOutcome::Unmatched);
        }
        if !self
            .paths
            .path_snapshot(entry.path)
            .is_ok_and(|snapshot| snapshot.status() == PathStatus::Valid)
        {
            self.adjunct.entries[index] = None;
            self.adjunct.counters.unmatched_replies += 1;
            return Ok(ProbeOutcome::Unmatched);
        }
        // RFC 4821 section 7.6.1: set search_low to the probe size; raise
        // eff_pmtu when the probe was larger.
        self.adjunct.counters.confirmed += 1;
        entry.confirmed = entry.confirmed.max(probe.size);
        if let Search::Active { low, high } = entry.search {
            entry.search = Search::Active {
                low: low.max(probe.size),
                high,
            };
        }
        entry.probe = None;
        entry.not_before = now;
        entry.used_at = now;
        self.adjunct.entries[index] = Some(entry);
        // A network fact other packetization layers may share (RFC 4821
        // section 5.2), under PathService's revision, hold and first-hop
        // rules; NotLarger on a path with no learned ceiling below it.
        let published = match self.paths.confirm_delivery(
            entry.path,
            probe.size,
            probe.negative_revision,
            probe.sent_at,
            now,
        ) {
            Ok(outcome) => Some(outcome),
            Err(
                ntcp_path::Error::Invalidated
                | ntcp_path::Error::StaleHandle
                | ntcp_path::Error::NoRoute
                | ntcp_path::Error::SelectionChanged,
            ) => None,
            Err(error) => return Err(error.into()),
        };
        Ok(ProbeOutcome::Confirmed {
            size: probe.size,
            published,
        })
    }

    /// An ICMP error whose quote is an unfragmented Echo Request: matched
    /// against outstanding probes by addresses, the quoted packet length
    /// (or RFC 1191 section 5's inflated reading from a legacy IPv4 router),
    /// identifier and sequence. None when it quotes no probe. `message` is
    /// the error's ICMP message, the payload of its processed datagram.
    pub(crate) fn adjunct_error(
        &mut self,
        now: Instant,
        message: &[u8],
        feedback: &ntcp_icmp::Feedback<ntcp_icmp::Quote>,
    ) -> Result<Option<ProbeOutcome>, Error> {
        let quote = feedback.quoted;
        let ipv4 = quote.ip.source.is_ipv4();
        if !self.adjunct.enabled()
            || quote.fragment.is_some()
            || quote.protocol != if ipv4 { 1 } else { 58 }
        {
            return Ok(None);
        }
        // The quoted Echo header follows the 8-octet ICMP error header and
        // the quoted IP header (every IPv4 error quotes at least 8 data
        // octets, RFC 1122 section 3.2.2).
        let Some(echo) = message
            .get(8 + usize::from(quote.ip_header_len)..)
            .and_then(|b| b.get(..8))
        else {
            return Ok(None);
        };
        if echo[0] != if ipv4 { 8 } else { 128 } {
            return Ok(None);
        }
        let (identifier, sequence) = (
            u16::from_be_bytes([echo[4], echo[5]]),
            u16::from_be_bytes([echo[6], echo[7]]),
        );
        let ptb = feedback.kind == ntcp_icmp::FeedbackKind::PacketTooBig;
        let header = u32::from(quote.ip_header_len);
        let found = self.adjunct.entries.iter().position(|e| {
            e.and_then(|e| e.probe.map(|p| (e, p)))
                .is_some_and(|(e, p)| {
                    e.ip == quote.ip
                        && self.quote_authorized(e.path, message)
                        && p.identifier == identifier
                        && p.sequence == sequence
                        && (quote.ip_packet_len == p.size
                            || (ptb
                                && ipv4
                                && feedback.candidate_mtu.is_none()
                                && quote.ip_packet_len.checked_sub(header) == Some(p.size)))
                })
        });
        let Some(index) = found else {
            return Ok(None);
        };
        let mut entry = self.adjunct.entries[index].unwrap();
        let probe = entry.probe.unwrap();
        let mtu = crate::report_mtu(ipv4, probe.size, feedback.candidate_mtu);
        if ptb && mtu.is_none() {
            // An implausible report (an IPv6 MTU below 1280, or one not
            // below the probe) changes nothing; the probe stays outstanding.
            return Ok(Some(ProbeOutcome::Unmatched));
        }
        entry.probe = None;
        entry.not_before = now;
        let outcome = if let Some(mtu) = mtu.filter(|_| ptb) {
            self.adjunct.counters.too_big += 1;
            // RFC 4821 section 7.6.2: search_high and eff_pmtu MAY be set
            // from the indicated MTU; the shared decrease is the ordinary
            // trusted one, which E follows through the shared budget.
            let estimate = self.host_estimate(
                entry.path,
                ipv4,
                (quote.ip_packet_len, u32::from(quote.ip_header_len)),
                probe.size,
                feedback.candidate_mtu,
            );
            // An ineligible probe's search result is void: only the shared
            // trusted decrease applies.
            if probe.eligible {
                lower(
                    &mut entry,
                    estimate.map_or(probe.size, |e| e.saturating_add(1)),
                );
            }
            self.adjunct.entries[index] = Some(entry);
            let published = self.publish(
                now,
                entry.path,
                ipv4,
                (quote.ip_packet_len, u32::from(quote.ip_header_len)),
                probe.size,
                feedback.candidate_mtu,
                None,
            )?;
            ProbeOutcome::TooBig {
                size: probe.size,
                mtu,
                published,
            }
        } else {
            let error = feedback
                .ipv4_network_error()
                .or_else(|| feedback.ipv6_network_error())
                .unwrap_or(NetworkError::ParameterProblem);
            if probe.eligible {
                self.adjunct.counters.lost += 1;
                lower(&mut entry, probe.size);
            }
            self.adjunct.entries[index] = Some(entry);
            ProbeOutcome::Failed {
                size: probe.size,
                error,
            }
        };
        Ok(Some(outcome))
    }

    #[cfg(test)]
    pub(crate) fn adjunct_confirmed(&self, path: PathId) -> u32 {
        self.adjunct.confirmed(path)
    }
    #[cfg(test)]
    pub(crate) fn adjunct_outstanding(&self) -> usize {
        self.adjunct
            .entries
            .iter()
            .flatten()
            .filter(|e| e.probe.is_some())
            .count()
    }
    #[cfg(test)]
    pub(crate) fn adjunct_paths(&self) -> usize {
        self.adjunct.entries.iter().flatten().count()
    }
}

// RFC 4821 section 7.6.2: the probe of `size` octets was not delivered, so
// search_high becomes at most size - 1. The effective size is untouched:
// silence and errors are never a decrease.
fn lower(entry: &mut Entry, size: u32) {
    if let Search::Active { low, high } = entry.search {
        let bound = size.saturating_sub(1);
        entry.negative = Some(entry.negative.map_or(bound, |n| n.min(bound)));
        entry.search = Search::Active {
            low,
            high: high.min(bound),
        };
    }
}

fn fill_probe(nonce: &[u8; NONCE], data: &mut [u8]) {
    for (i, b) in data.iter_mut().enumerate() {
        *b = nonce[i % NONCE];
    }
}

fn matches_probe(nonce: &[u8; NONCE], data: &[u8]) -> bool {
    data.len() >= NONCE && data.iter().enumerate().all(|(i, b)| *b == nonce[i % NONCE])
}
