use crate::{
    Error, Instant, Ipv4Plateaus, PmtudConfig, PmtudPolicy,
    pmtud_config::{default_search_low, min_mtu},
    seq::Seq,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathMtuInfo {
    pub first_hop_mtu: u32,
    pub route_mtu: Option<u32>,
    pub current_mtu: u32,
    pub search_low: u32,
    pub search_high: u32,
}

/// TCP policy's disposition of one correlated Packet Too Big report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PmtuFeedback {
    /// Not acted on: wrong state/window, PMTUD disabled, malformed or
    /// impossible candidate (no smaller than the dropped packet, or below
    /// the IPv6 minimum).
    Rejected,
    /// A plausible drop that leaves the estimate unchanged; consumed as drop
    /// advice only.
    Unchanged,
    /// Below previously proven delivery: held until the quoted data times out.
    Deferred,
    /// Applied immediately to this connection's estimate, which is now `mtu`
    /// (under this connection's own plateau policy for an IPv4 report
    /// without a next-hop MTU).
    Decreased { mtu: u32 },
}

/// One Host-correlated report: the local class together with the size the
/// report itself derives under this connection's configured policy (next-hop
/// MTU with family floor, or the plateau below an IPv4 quoted length
/// corrected per RFC 1191 section 5 against the Host's shared path estimate,
/// the IP layer's current PMTU estimate). The derived size is independent of
/// the connection's current, possibly loss-inferred, estimate; `feedback`
/// only says whether that local estimate fell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PmtuReport {
    pub feedback: PmtuFeedback,
    /// `None` exactly when `feedback` is `Rejected`.
    pub derived_mtu: Option<u32>,
}

impl PmtuReport {
    const REJECTED: Self = Self {
        feedback: PmtuFeedback::Rejected,
        derived_mtu: None,
    };
}

#[derive(Clone, Copy, Debug)]
struct Sent {
    start: Seq,
    end: Seq,
    size: u32,
    header: u16,
    ambiguous: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Probe {
    pub start: Seq,
    pub end: Seq,
    pub trailing_end: Seq,
    pub size: u32,
    // Matching PTB invalidates size inference, but not finite loss classification.
    size_result_valid: bool,
    retried: bool,
    loss_reported: bool,
    other_loss: bool,
    timeout: bool,
    repair_end: Seq,
}

/// One deferred report below proven delivery. Its identity changes exactly
/// when the size that a later timeout would apply changes, so provenance
/// attached to one report never describes a replacement. `live..end` is the
/// quoted data still outstanding: a partial ACK into it neither clears the
/// report nor moves its authorization to unrelated data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Pending {
    seq: Seq,
    live: Seq,
    end: Seq,
    mtu: u32,
    id: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProbeOutcome {
    pub start: Seq,
    end: Seq,
    pub isolated: bool,
}

#[derive(Debug)]
pub(crate) struct Pmtud {
    pub info: PathMtuInfo,
    pub bound: u32,
    ipv4: bool,
    initial_low: u32,
    // Fixed 600-second PTB hold in caller ticks, independent of periodic aging.
    hold: u64,
    aging: Option<u64>,
    periodic_deadline: Option<Instant>,
    high_limit: Option<u32>,
    // Negative network evidence survives temporary administrative clipping.
    discovered_high: Option<u32>,
    low_limit: Option<u32>,
    plateaus: Ipv4Plateaus,
    // PTB hold / failed-probe suppression; Infinity never disables this timer.
    pub deadline: Option<Instant>,
    reset_search: bool,
    pub probe: Option<Probe>,
    outcome: Option<ProbeOutcome>,
    // Packetization boundary survives cancellation of the probe's search result.
    repair_range: Option<(Seq, Seq)>,
    pending: Option<Pending>,
    pending_ids: u64,
    // Exactly the pending report a quoted-data timeout applied, never inferred
    // from current_mtu (loss inference changes that too).
    applied_pending: Option<(u64, u32)>,
    // Exact span and size of the latest probe whose delivery proved its size.
    success: Option<(Seq, Seq, u32)>,
    icmp_since_progress: bool,
    max_sent: u32,
    max_acked: u32,
    // ponytail: 64 recent exact packets; evicted quotes are ignored, never
    // guessed from a sequence range. Increase this bound if feedback coverage
    // on very large flights matters. No allocation on the packet path.
    sent: [Option<Sent>; 64],
    next: usize,
    verification: Option<(u32, Instant, u64, u64)>,
}

fn overlaps(a: Seq, b: Seq, c: Seq, d: Seq) -> bool {
    a.in_window(c, d.distance_from(c)) == Some(true)
        || c.in_window(a, b.distance_from(a)) == Some(true)
}

impl Pmtud {
    //= https://www.rfc-editor.org/rfc/rfc1191#section-2
    //= reason=Core starts at the caller's actual first-hop bound, further constrained by peer and allocation ceilings. DF encoding belongs to the IP layer.
    //# The basic idea is that a source host initially assumes that the PMTU
    //# of a path is the (known) MTU of its first hop, and sends all
    //# datagrams on that path with the DF bit set.
    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.1
    //= reason=By default Pmtud::new initializes search_low to min(bound,1024) for IPv4 or min(bound,1280) for IPv6. The full-stop test checks both family starting lows through the first fallback; independent creation-time configurability is covered at 113.
    //# For initial conditions when there is no information about the path, eff_pmtu may
    //# be greater than search_low. The initial value of search_low SHOULD be
    //# conservatively low, but performance may be better if eff_pmtu starts at a higher,
    //# less conservative, value. See Section 7.2.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-2
    //= reason=Enabled PMTUD initializes from the supplied first-hop MTU, capped by independent peer/allocation ceilings; native startup/jumbo tests establish those bounds. This does not assert a router implementation.
    //# The basic idea is that a source host initially assumes that the PMTU of a path
    //# is the (known) MTU of its first hop,

    //= https://www.rfc-editor.org/rfc/rfc8201#section-1
    //= reason=Enabled IPv6 core implements PTB decrease, full packet budgets and ACK-confirmed upward discovery; the dual-family test performs a real probe after PTB holdoff. Optional minimal implementations are not required to omit discovery. No native IPv6 socket claim.
    //# IPv6 nodes should implement Path MTU Discovery in order to discover and take
    //# advantage of paths with PMTU greater than the IPv6 minimum link MTU [RFC8200]. A
    //# minimal IPv6 implementation (e.g., in a boot ROM) may choose to omit
    //# implementation of Path MTU Discovery.

    //= https://www.rfc-editor.org/rfc/rfc8201#section-3
    //= reason=Enabled IPv6 state starts at the caller first-hop bound (subject to peer/allocation caps); family-floor test asserts the initial 1500-byte estimate before rejecting subminimum feedback.
    //# The basic idea is that a source node initially assumes that the PMTU of a path
    //# is the (known) MTU of the first hop in the path.

    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.2
    //= reason=Enabled IPv6 PMTU starts at the supplied first-hop bound, with separate allocation/peer ceilings. The dual-family floor test asserts 1500 initially; the small-allocation test covers independent limiting.
    //# Initially, the PMTU value for a path is assumed to be the (known) MTU of the
    //# first-hop link.

    pub fn new(config: PmtudConfig, bound: u32, ipv4: bool, hold: u64) -> Result<Self, Error> {
        let (mtu, low, high) = config.initial_values(bound, ipv4)?;
        Ok(Self {
            info: PathMtuInfo {
                first_hop_mtu: config.first_hop_mtu,
                route_mtu: config.route_mtu,
                current_mtu: mtu,
                search_low: low,
                search_high: high,
            },
            bound,
            ipv4,
            initial_low: low,
            hold,
            aging: config.policy.search_aging.ticks(hold / 600)?,
            periodic_deadline: None,
            high_limit: config.initial_search_high,
            discovered_high: None,
            low_limit: config.initial_search_low,
            plateaus: config.policy.ipv4_plateaus,
            deadline: None,
            reset_search: false,
            probe: None,
            outcome: None,
            repair_range: None,
            pending: None,
            pending_ids: 0,
            applied_pending: None,
            success: None,
            icmp_since_progress: false,
            max_sent: 0,
            max_acked: 0,
            sent: [None; 64],
            next: 0,
            verification: None,
        })
    }

    pub fn constrain(&mut self, bound: u32) {
        self.constrain_inner(bound, false);
    }

    /// Managed physical selection bounds cannot cancel the finite loss
    /// classification of a probe that was already submitted. All subsequent
    /// ACK/MSS refreshes must retain that distinction as well as the update.
    pub(crate) fn constrain_network(&mut self, bound: u32) {
        self.constrain_inner(bound, true);
    }

    fn constrain_inner(&mut self, bound: u32, preserve_probe_loss: bool) {
        self.bound = bound;
        let bound = self.route_bound();
        self.initial_low = bound.min(self.low_limit.unwrap_or(default_search_low(self.ipv4)));
        if self.info.current_mtu > bound {
            // A local limit decrease is not failure of the previously verified
            // larger size; its loss ratio cannot classify this smaller MTU.
            self.verification = None;
        }
        self.info.current_mtu = self.info.current_mtu.min(bound);
        self.info.search_low = self.info.search_low.min(bound);
        self.info.search_high = self.info.search_high.min(self.search_ceiling());
        if self.probe.is_some_and(|p| p.size > bound) {
            if preserve_probe_loss {
                self.invalidate_probe_size_result();
            } else {
                self.probe = None;
            }
        }
    }

    pub fn link(&mut self, mtu: u32, bound: u32, now: Instant) {
        self.info.first_hop_mtu = mtu;
        self.constrain(bound);
        // A local link increase is a new search bound, not proof about the path.
        if self.info.search_high < self.search_ceiling() {
            self.schedule_aging(now);
        }
    }

    // Same path only: this is permission to probe, never delivery evidence.
    pub fn set_route_mtu(&mut self, mtu: Option<u32>) {
        if mtu == self.info.route_mtu {
            return;
        }
        let old_ceiling = self.search_ceiling();
        self.info.route_mtu = mtu;
        self.constrain(self.bound);
        if self.search_ceiling() > old_ceiling {
            let high = self
                .search_ceiling()
                .min(self.discovered_high.unwrap_or(u32::MAX));
            if high > self.info.search_high {
                self.info.search_high = high;
                if self.info.search_low < high {
                    // New admissible space, not a periodic reset of negative
                    // evidence. PTB/probe/RTO cooldown stays in `deadline`.
                    self.periodic_deadline = None;
                }
            }
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.3
    //= reason=One-byte convergence schedules600s reset; link growth cannot increase eff without an ACK; before/at-deadline targets and bounded reset asserted.
    //# Each Packetization Layer MUST determine when probing has converged, that is, when
    //# the probe size range is small enough that further probing is no longer worth its
    //# cost. When probing has converged, a timer SHOULD be set. When the timer expires,
    //# search_high should be reset to its initial value (described above) so that probing
    //# can resume. Thus, if the path changes, increasing the Path MTU, then the flow will
    //# eventually take advantage of it. The value for this timer MUST NOT be less than 5
    //# minutes and is recommended to be 10 minutes, per RFC 1981.

    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.3
    //= reason=Enabled IPv6 core holds PTB for 600 seconds and defaults converged-search aging to 600 seconds, reopens the upper search bound on expiry, and emits an ACK-confirmed larger probe. The dual-family real-probe test exercises periodic retry; configurable periodic aging is separately covered at 8201-069.
    //# If the stale PMTU value is too large, this will be discovered almost immediately
    //# once a large enough packet is sent on the path. No such mechanism exists for
    //# realizing that a stale PMTU value is too small, so an implementation should
    //# "age" cached values. When a PMTU value has not been decreased for a while (on
    //# the order of 10 minutes), it should probe to find if a larger PMTU is supported.

    pub fn tick(&mut self, now: Instant) {
        if self.deadline.is_some_and(|d| d <= now) {
            self.deadline = None;
            if self.reset_search {
                self.discovered_high = None;
                self.info.search_high = self.search_ceiling();
            }
            self.reset_search = false;
            if self.info.search_low >= self.info.search_high {
                self.schedule_aging(now);
            }
        }
        if self.periodic_deadline.is_some_and(|d| d <= now) {
            self.periodic_deadline = None;
            self.discovered_high = None;
            self.info.search_high = self.search_ceiling();
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.1
    //= reason=Binary target is strictly above search_low and <=search_high; actual IP probe size checked for IPv4/IPv6 and constrained by peer/allocation ceilings.
    //# When transmitting probes, the Packetization Layer MUST select a probe size that is
    //# larger than search_low and smaller than or equal to search_high.

    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.4
    //# o If the last probe failed or was inconclusive, then the probe timeout has expired (see Section 7.6.2).
    pub fn target(&self) -> Option<u32> {
        if self.deadline.is_some()
            || self.periodic_deadline.is_some()
            || self.probe.is_some()
            || self.repair_range.is_some()
            || self.info.search_low >= self.info.search_high
        {
            return None;
        }
        Some(self.info.search_low + (self.info.search_high - self.info.search_low).div_ceil(2))
    }

    /// A shared decrease revokes permission to publish this probe's size;
    /// its independent loss-classification evidence remains intact.
    pub(crate) fn invalidate_probe_size_result(&mut self) {
        if let Some(probe) = &mut self.probe {
            probe.size_result_valid = false;
        }
    }

    pub(crate) fn set_plateaus(&mut self, plateaus: Ipv4Plateaus) {
        self.plateaus = plateaus;
    }

    pub(crate) fn network_link_bound(&mut self, mtu: u32, bound: u32) {
        if self.info.first_hop_mtu == mtu && self.bound == bound { return; }
        self.info.first_hop_mtu = mtu;
        self.bound = bound;
        // Authority to select a future size is separate from the outstanding
        // probe's loss-classification record. Retain local negative evidence
        // until its existing cooldown/aging rules authorize forgetting it.
        self.info.search_high = self
            .search_ceiling()
            .min(self.discovered_high.unwrap_or(u32::MAX));
        if self.probe.is_some_and(|p| p.size > self.route_bound()) {
            self.invalidate_probe_size_result();
        }
    }

    pub(crate) fn replace_network_authority(&mut self) {
        self.invalidate_probe_size_result();
        self.verification = None;
        self.sent.fill(None);
        self.max_sent = 0;
        self.max_acked = 0;
        self.pending = None;
        self.applied_pending = None;
        self.success = None;
        self.discovered_high = None;
        self.info.search_low = self.initial_low.min(self.route_bound());
        self.info.search_high = self.search_ceiling();
        self.info.current_mtu = self.info.search_low;
    }

    /// Challenge a shared ordinary ceiling with real TCP data. Existing local
    /// probe/loss/cooldown admission still applies, even if prior local proof
    /// is larger than the shared estimate. Positive publication is separate.
    pub(crate) fn target_for_network(&self, ordinary: u32) -> Option<u32> {
        self.target().or_else(|| {
            (self.deadline.is_none() && self.periodic_deadline.is_none()
                && self.probe.is_none() && self.repair_range.is_none()
                && self.info.current_mtu > ordinary)
                .then_some(self.info.current_mtu)
        })
    }

    /// Identity of the report a quoted-data timeout would apply.
    pub(crate) fn pending_id(&self) -> Option<u64> {
        self.pending.map(|p| p.id)
    }

    /// The pending report identity and the size that report derived under
    /// this connection's policy, which the last timeout applied.
    pub(crate) fn take_applied_pending(&mut self) -> Option<(u64, u32)> {
        self.applied_pending.take()
    }

    /// Exact span and size of a probe whose delivery the latest ACK proved.
    pub(crate) fn take_probe_success(&mut self) -> Option<(Seq, Seq, u32)> {
        self.success.take()
    }

    /// The outstanding probe while delivery could still prove its size.
    pub(crate) fn provable_probe(&self) -> Option<(Seq, Seq, u32)> {
        self.probe
            .filter(|p| p.size_result_valid && !p.retried && !p.timeout)
            .map(|p| (p.start, p.end, p.size))
    }

    pub fn start_probe(&mut self, start: Seq, payload: u32, trailing: u32, size: u32) {
        self.repair_range = Some((start, start.wrapping_add(payload)));
        self.outcome = None;
        self.probe = Some(Probe {
            start,
            end: start.wrapping_add(payload),
            trailing_end: start.wrapping_add(payload + trailing),
            size,
            size_result_valid: true,
            retried: false,
            loss_reported: false,
            other_loss: false,
            timeout: false,
            repair_end: start,
        });
    }

    //= https://www.rfc-editor.org/rfc/rfc4821#section-6.1
    //= reason=Real receiver NewReno/SACK/RACK traces in both families across serial wrap contrast leading-original delivery before DupThresh/RACK settling, actual leading-plus-probe loss, late leading delivery after detection, and reorder without probe loss. Finite tail/recovery proof gates isolation; other detected loss commits congestion response with unchanged MTU bounds and eventual stream progress. Existing trailing-hole, repair-copy, ECN, matching-PTB and inconclusive-RTO controls remain complementary. Full timing/reordering robustness beyond these detector conditions remains unestablished; sufficiently late leading originals are conservatively treated as other loss, not magically identified as reorder. Retain the whole timely/robust loss-reporting advice as TODO for that evidence/interpretation boundary.
    //# It is important that the Packetization Layer has a timely and robust mechanism for detecting and reporting losses. PLPMTUD makes MTU adjustments on the basis of detected losses. Any delays or inaccuracy in loss notification is likely to result in incorrect MTU decisions or slow convergence. It is important that the mechanism can robustly distinguish between the isolated loss of just a probe and other losses in the probe's leading and trailing windows.

    //= https://www.rfc-editor.org/rfc/rfc4821#section-4
    //= reason=TCP duplicate-ACK recovery reports probe loss; real receiver ACKs distinguish an isolated loss from a second hole beyond the minimum trailing window. This covers a loss-reporting mechanism, not suppression of congestion control.
    //# To use PLPMTUD, a Packetization Layer MUST have a loss reporting mechanism that
    //# provides the sender with timely and accurate indications of which packets were
    //# lost in the network.

    //= https://www.rfc-editor.org/rfc/rfc4821#section-6.1
    //= reason=The allowed implicit TCP duplicate-ACK mechanism is used in this non-SACK fixture: actual receiver ACKs trigger repairs and distinguish the second hole. SACK is not mandatory in this paragraph.
    //# It is best if Packetization Protocols use an explicit loss detection mechanism
    //# such as a Selective Acknowledgment (SACK) scoreboard [RFC3517] or ACK Vector
    //# [RFC4340] to distinguish real losses from reordered data, although implicit
    //# mechanisms such as TCP Reno style duplicate acknowledgments counting are
    //# sufficient.

    //= https://www.rfc-editor.org/rfc/rfc4821#section-6.1
    //= reason=Timeout is not the primary loss detector: real receiver duplicate ACKs trigger probe repair before any timeout in the non-SACK lifecycle test.
    //# PLPMTUD can also be implemented in protocols that rely on timeouts as their
    //# primary mechanism for loss recovery; however, timeouts SHOULD NOT be used as the
    //# primary mechanism for loss indication unless there are no other alternatives.

    pub fn eligible_probe_loss(&self) -> Option<Seq> {
        self.probe
            .filter(|p| !p.other_loss && !p.timeout)
            .map(|p| p.start)
            .or_else(|| self.outcome.filter(|o| o.isolated).map(|o| o.start))
    }

    pub fn take_probe_outcome(&mut self, ack: Seq) -> Option<ProbeOutcome> {
        if self.outcome.is_some_and(|o| ack.at_or_after(o.end)) {
            self.outcome.take()
        } else {
            None
        }
    }

    pub fn loss(&mut self, start: Seq, multiple: bool) {
        if let Some(outcome) = &mut self.outcome {
            // Cumulative proof can finish before this ACK's loss detection.
            // Any remaining loss is outside that delivered flight and must
            // invalidate isolation before another recovery can reuse its identity.
            outcome.isolated = false;
        }
        if let Some(p) = &mut self.probe {
            // Freeze before recovery can emit fresh data, not on its ending ACK.
            p.loss_reported = true;
            if multiple || start.in_window(p.start, p.end.distance_from(p.start)) != Some(true) {
                p.other_loss = true;
            }
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc5927#section-7.4
    //= reason=Selected max-sent update is implemented exactly as max_sent.max(size) in sent(). Exact-evidence tests send real sizes and exercise acceptance/rejection against their recorded upper bound; initialization/reset choices are separate clauses.
    //# if (packet_size > maxsizesent) maxsizesent = packet_size;

    pub fn sent(&mut self, start: Seq, end: Seq, size: u32, header: u16, retry: bool) {
        self.max_sent = self.max_sent.max(size);
        if let Some(p) = &mut self.probe
            && !retry
            && !p.loss_reported
            && !p.retried
            && !p.timeout
            && end.at_or_after(p.trailing_end)
        {
            // Retain the minimum trailing requirement and all flight emitted
            // before loss. Recovery/replenishment must not move proof forever.
            p.trailing_end = end;
        }
        if retry {
            for packet in self.sent.iter_mut().flatten() {
                if overlaps(start, end, packet.start, packet.end) {
                    packet.ambiguous = true;
                }
            }
            if let Some(p) = &mut self.probe {
                if overlaps(start, end, p.start, p.end) {
                    p.retried = true;
                    // A second copy of already repaired gap bytes is another
                    // loss, unlike the next smaller segment of a split repair.
                    if start != p.repair_end && p.repair_end.at_or_after(start) {
                        p.other_loss = true;
                    }
                    if end.at_or_after(p.repair_end) {
                        p.repair_end = end;
                    }
                }
                // Overlap past the gap is not evidence of another lost packet.
                if start.in_window(p.start, p.end.distance_from(p.start)) != Some(true) {
                    p.other_loss = true;
                }
            }
        }
        if let Some((_, _, sent, lost)) = &mut self.verification {
            if retry {
                *lost = lost.saturating_add(1);
            } else {
                *sent = sent.saturating_add(1);
            }
        }
        self.sent[self.next] = Some(Sent {
            start,
            end,
            size,
            header,
            ambiguous: retry,
        });
        self.next = (self.next + 1) % self.sent.len();
    }

    // Known synchronous nonsubmission only: the caller validates output identity
    // and rearms transport work before any intervening output/input.
    pub fn reject_latest(&mut self, start: Seq, end: Seq) -> bool {
        let index = (self.next + self.sent.len() - 1) % self.sent.len();
        let Some(packet) = self.sent[index].filter(|p| p.start == start && p.end == end) else {
            return false;
        };
        self.sent[index] = None;
        // A local probe/trailing rejection is inconclusive, not network loss.
        self.probe = None;
        if let Some((_, _, sent, lost)) = &mut self.verification {
            let counter = if packet.ambiguous { lost } else { sent };
            *counter = counter.saturating_sub(1);
        }
        // Earlier retry ambiguity stays conservative; no whole-state rollback.
        true
    }

    // Core also checks tuple and that the quoted span overlaps [SND.UNA, SND.NXT).
    //= https://www.rfc-editor.org/rfc/rfc1191#section-3
    //= reason=Enabled IPv4 PMTUD: exact sent evidence and legal floor; only a candidate below the current estimate reduces it, and repeated/nondecreasing accepted reports are drop notifications that neither raise the estimate nor rearm the hold. Security-selected deferred updates are tested separately from immediate initial discovery.
    //# When a host receives a Datagram Too Big message, it MUST reduce its estimate of the
    //# PMTU for the relevant path, based on the value of the Next-Hop MTU field in the
    //# message (see section 4). We do not specify the precise behavior of a host in this
    //# circumstance, since different applications may have different requirements, and
    //# since different implementation architectures may favor different strategies.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-3
    //= reason=Enabled IPv4 PMTUD: exact sent evidence and legal floor; only a candidate below the current estimate reduces it, and repeated/nondecreasing accepted reports are drop notifications that neither raise the estimate nor rearm the hold. Security-selected deferred updates are tested separately from immediate initial discovery.
    //# We do require that after receiving a Datagram Too Big message, a host MUST attempt
    //# to avoid eliciting more such messages in the near future. The host may either reduce
    //# the size of the datagrams it is sending along the path, or cease setting the Don't
    //# Fragment bit in the headers of those datagrams. Clearly, the former strategy may
    //# continue to elicit Datagram Too Big messages for a while, but since each of these
    //# messages (and the dropped datagrams they respond to) consume Internet resources, the
    //# host MUST force the PMTU Discovery process to converge.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-3
    //= reason=Enabled IPv4 PMTUD: exact sent evidence and legal floor; only a candidate below the current estimate reduces it, and repeated/nondecreasing accepted reports are drop notifications that neither raise the estimate nor rearm the hold. Security-selected deferred updates are tested separately from immediate initial discovery.
    //# A host MUST never reduce its estimate of the Path MTU below 68 octets.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-3
    //= reason=Enabled IPv4 PMTUD: exact sent evidence and legal floor; only a candidate below the current estimate reduces it, and repeated/nondecreasing accepted reports are drop notifications that neither raise the estimate nor rearm the hold. Security-selected deferred updates are tested separately from immediate initial discovery.
    //# A host MUST not increase its estimate of the Path MTU in response to the contents of
    //# a Datagram Too Big message. A message purporting to announce an increase in the Path
    //# MTU might be a stale datagram that has been floating around in the Internet, a false
    //# packet injected as part of a denial-of-service attack, or the result of having
    //# multiple paths to the destination.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-5
    //= reason=Zero next-hop MTU uses quoted total length, legacy IHL correction and next lower plateau; exact packet evidence bounds the input and floor68 is retained.
    //# Any search strategy must have some "memory" of previous estimates in order to chose
    //# the next one. One approach is to use the currently-cached estimate of the Path MTU,
    //# but in fact there is better information available in the Datagram Too Big message
    //# itself. All ICMP Destination Unreachable messages, including this one, contain the
    //# IP header of the original datagram, which contains the Total Length of the datagram
    //# that was too big to be forwarded without fragmentation. Since this Total Length may
    //# be less than the current PMTU estimate, but is nonetheless larger than the actual
    //# PMTU, it may be a good input to the method for choosing the next PMTU estimate.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-5
    //= reason=Zero next-hop MTU uses quoted total length, legacy IHL correction and next lower plateau; exact packet evidence bounds the input and floor68 is retained.
    //# Note: routers based on implementations derived from 4.2BSD Unix send an incorrect
    //# value for the Total Length of the original IP datagram. The value sent by these
    //# routers is the sum of the original Total Length and the original Header Length
    //# (expressed in octets). Since it is impossible for the host receiving such a Datagram
    //# Too Big message to know if it sent by one of these routers, the host must be
    //# conservative and assume that it is. If the Total Length field returned is not less
    //# than the current PMTU estimate, it must be reduced by 4 times the value of the
    //# returned Header Length field.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-5
    //= reason=Zero next-hop MTU uses quoted total length, legacy IHL correction and next lower plateau; exact packet evidence bounds the input and floor68 is retained.
    //# The strategy we recommend, then, is to use as the next PMTU estimate the greatest
    //# plateau value that is less than the returned Total Length field (corrected, if
    //# necessary, according to the Note above).

    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.4
    //= reason=Only a report that decreases the connection's estimate reaches packetization refresh; a nondecreasing report changes no estimate or segment size (it is only a drop notification of the quoted bytes), and stale and impossible exact-size quotes are rejected.
    //# This means that the TCP layer must be able to recognize when a Datagram Too Big
    //# notification actually decreases the PMTU that it has already used to send a datagram
    //# on the given connection, and should ignore any other notifications.

    //= https://www.rfc-editor.org/rfc/rfc8201#section-4
    //= reason=IPv6 core rejects1279 without changing1500 estimate and accepts1280; native IPv6 socket transport is not claimed.
    //# If a node receives a Packet Too Big message reporting a next-hop MTU that is less
    //# than the IPv6 minimum link MTU, it must discard it. A node must not reduce its
    //# estimate of the Path MTU below the IPv6 minimum link MTU on receipt of a Packet Too
    //# Big message.

    //= https://www.rfc-editor.org/rfc/rfc5927#section-7.2
    //= reason=Selected plausibility gate rejects a candidate larger than max_sent and also requires it to be smaller than the exact recently sent packet. The security test rejects equal/larger reported sizes; this does not authenticate ICMP.
    //# Upon receipt of an ICMP "Packet Too Big" error message, the Next-Hop MTU claimed by
    //# the ICMP message (henceforth "claimedmtu") is compared with maxsizesent. If
    //# claimedmtu is larger than maxsizesent, then the ICMP error message is silently
    //# discarded. The rationale for this is that the ICMP error message cannot be
    //# legitimate if it claims to have been triggered by a packet larger than the largest
    //# packet we have so far sent for this connection.

    //= https://www.rfc-editor.org/rfc/rfc5927#section-7.2
    //= reason=Selected below-proven-size update policy records a pending report without lowering PMTU; the wire test asserts PMTU remains 1500 until matching-head timeout.
    //# On the other hand, if claimedmtu is smaller than maxsizeacked, TCP is supposed to be
    //# in the Path-MTU Update stage. At this stage, these implementations are more cautious
    //# with the errors being reported by the network, and therefore just record the
    //# received error message, and delay the update of the assumed Path-MTU.

    //= https://www.rfc-editor.org/rfc/rfc5927#section-7.2
    //= reason=Selected policy clears pending once cumulative ACK passes the quoted packet's data; the security test proves a later timeout then does not apply the report. A partial ACK into the quoted packet deliberately does not clear it (its surviving bytes were still dropped) and that data's own timeout applies it, as the same test shows; this is a deliberate deviation, not literal algorithm equivalence.
    //# If, while there is a pending ICMP "Packet Too Big" error message, the TCP SEQ
    //# claimed by the pending message is acknowledged (i.e., an ACK that acknowledges that
    //# sequence number is received), then the "pending error" condition is cleared.

    //= https://www.rfc-editor.org/rfc/rfc5927#section-7.2
    //= reason=Selected cautious-update behavior defers a candidate below proven delivery; existing wire test contrasts progress clearing with quoted-head timeout. Historical variable resets are not claimed.
    //# The Path-MTU Update stage is when TCP tries to send segments that are equal to or
    //# smaller than the ones that have already been sent and acknowledged for this
    //# connection. During the Path-MTU Update stage, TCP already has knowledge of the
    //# estimated Path-MTU for the given connection. Thus, in this case, these
    //# implementations are more cautious with the errors being reported by the network.

    //= https://www.rfc-editor.org/rfc/rfc5927#section-7.4
    //= reason=Selected gate rejects a candidate not smaller than the exact quoted sent size (hence never above max_sent). A candidate >=current_mtu updates nothing but is deliberately kept as a drop notification of the quoted bytes, not dropped. The security wire test rejects equal and larger reports and shows nondecreasing ones never change the estimate.
    //# else { if (claimedmtu > maxsizesent || claimedmtu >= current_mtu) drop_message();

    //= https://www.rfc-editor.org/rfc/rfc1191#section-2
    //= reason=Enabled core applies validated initial PTB decreases and repacketizes to the new budget; feedback below previously proven delivery is deliberately deferred until the quoted head times out. Immediate and deferred cases are separate from upward probing.
    //# Upon receipt of such a message (henceforth called a "Datagram Too Big" message),
    //# the source host reduces its assumed PMTU for the path.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-2
    //= reason=Enabled IPv4 PMTUD retains DF in the codec and reacts to validated lower-MTU feedback; zero-MTU and family-floor tests exercise decrease and bounded repair. This is not a claim about arbitrary external embeddings.
    //# Normally, the host continues to set DF in all datagrams, so that if the route
    //# changes and the new PMTU is lower, it will be discovered.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-2
    //= reason=Enabled core applies validated initial PTB decreases and repacketizes to the new budget; feedback below previously proven delivery is deliberately deferred until the quoted head times out. Immediate and deferred cases are separate from upward probing.
    //# Reductions of the PMTU are detected by Datagram Too Big messages, except on
    //# paths for which the host has stopped setting the DF bit.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-3
    //= reason=Enabled core applies validated initial PTB decreases and repacketizes to the new budget; feedback below previously proven delivery is deliberately deferred until the quoted head times out. Immediate and deferred cases are separate from upward probing.
    //# Hosts using PMTU Discovery MUST detect decreases in Path MTU as fast as
    //# possible.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-3
    //= reason=Accepted PTB inhibits upward probing for 600 seconds, including after ACK progress and local link growth. The core test checks the deadline and subsequent real probe for both IP families.
    //# An attempt to detect an increase (by sending a datagram larger than the current
    //# estimate) MUST NOT be done less than 5 minutes after a Datagram Too Big message
    //# has been received for the given destination,

    //= https://www.rfc-editor.org/rfc/rfc1191#section-3
    //= reason=IPv4 zero Next-Hop MTU selects the next lower plateau using exact sent length and legacy header correction. Connection, direct-state and native socket tests cover zero-MTU processing; the following section5 cross-reference is context, not a missing feature.
    //# Hosts MUST be able to deal with Datagram Too Big messages that do not include
    //# the next-hop MTU, since it is not feasible to upgrade all the routers in the
    //# Internet in any finite time. A Datagram Too Big message from an unmodified
    //# router can be recognized by the presence of a zero in the (newly-defined)
    //# Next-Hop MTU field.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-8
    //= reason=The IPv4 estimate retains the legal 68-byte floor; the core wire test demonstrates bounded payload repair at that floor. This repeats the floor invariant, not a guarantee against an on-path ICMP blocker.
    //# In the first attack, the false message indicates a PMTU much smaller than
    //# reality. This should not entirely stop data flow, since the victim host should
    //# never set its PMTU estimate below the absolute minimum, but at 8 octets of IP
    //# data per datagram, progress could be slow.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-8
    //= reason=IPv4 feedback rejects candidates no smaller than the quoted packet and impossible ones, and an accepted nondecreasing report is only a drop notification; exact-quote tests show none of these raise the estimate. The hypothetical attack narrative is not a separate router round-trip or on-path-blocker obligation.
    //# In the other attack, the false message indicates a PMTU greater than reality. If
    //# believed, this could cause temporary blockage as the victim sends datagrams that
    //# will be dropped by some router. Within one round-trip time, the host would
    //# discover its mistake (receiving Datagram Too Big messages from that router), but
    //# frequent repetition of this attack could cause lots of datagrams to be dropped.
    //# A host, however, should never raise its estimate of the PMTU based on a Datagram
    //# Too Big message, so should not be vulnerable to this attack.

    //= https://www.rfc-editor.org/rfc/rfc8201#section-3
    //= reason=Enabled IPv6 core reduces its estimate from validated PTB; the dual-family floor test checks the new estimate and bounded retry.
    //# Reductions of the PMTU are detected by Packet Too Big messages.

    //= https://www.rfc-editor.org/rfc/rfc8201#section-4
    //= reason=Enabled IPv6 core applies a validated initial PTB decrease; the floor test checks 1500 to 1280 and repacketized retry. Later reports below proven delivery follow the selected deferred security policy, not unconditional trust of every ICMP packet.
    //# When a node receives a Packet Too Big message, it must reduce its estimate of
    //# the PMTU for the relevant path, based on the value of the MTU field in the
    //# message. The precise behavior of a node in this circumstance is not specified,
    //# since different applications may have different requirements, and since
    //# different implementation architectures may favor different strategies.

    //= https://www.rfc-editor.org/rfc/rfc8201#section-6
    //= reason=Same enabled-core floor invariant as 8201-034: sub1280 feedback is discarded and a legal 1280 report is accepted. The dual-family wire test asserts both outcomes; no native IPv6 socket or complete threat-model claim.
    //# In the first attack, the false message indicates a PMTU much smaller than
    //# reality. In response, the victim node should never set its PMTU estimate below
    //# the IPv6 minimum link MTU. A sender that falsely reduces to this MTU would
    //# observe suboptimal performance.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-3
    //= reason=Exact PTB half of the two-timer recommendation in parent 1191-013: accepted PTB holds upward probing for the recommended 600 seconds. The separate 2-minute post-success half is unselected, not covered by this evidence.
    //# 10 minutes

    //= https://www.rfc-editor.org/rfc/rfc8201#section-4
    //= reason=IPv6 base-header wire test from 819b8f2 covers decode_icmp checksum, truncation, impossible quoted payload length and outer-destination rejection, then exact sent-ledger sequence/size validation and stale quotes after real receiver ACKs, idle or with new flight, including wrap. A valid minimal quote is accepted. Plausibility validation is not authentication against a knowledgeable attacker; no native IPv6 socket or extension-header claim.
    //# Nodes should appropriately validate the payload of ICMPv6 PTB messages to ensure
    //# these are received in response to transmitted traffic (i.e., a reported error
    //# condition that corresponds to an IPv6 packet actually sent by the application)
    //# per [ICMPv6].

    //= https://www.rfc-editor.org/rfc/rfc8201#section-4
    //= reason=Enabled IPv6 core applies validated initial decreases and deliberately defers below-proven-delivery reports under the selected security policy. Test from 819b8f2 establishes proof with a real 1500-byte packet/receiver ACK, contrasts progress clearing with quoted-head RTO applying 1280, and verifies bounded wire repair and receiver ACK progress through wrap. No unconditional trust of PTB or native IPv6 socket claim.
    //# the dropped packets they respond to) consume network resources, nodes using Path
    //# MTU Discovery must detect decreases in PMTU as fast as possible.

    //= https://www.rfc-editor.org/rfc/rfc8201#section-4
    //= reason=Pmtud::feedback never raises the estimate: candidates no smaller than the quoted packet are rejected, and an accepted nondecreasing report is only a drop notification. IPv6 base-header wire test from 819b8f2 supplies exact emitted-packet quotes with equal/larger MTUs (1500, 2000, UINT32_MAX), then repeats 1400/1500/2000 after an accepted 1400 decrease; estimates never increase, including wrapped sequence ranges. No native IPv6 socket or extension-header claim.
    //# A node must not increase its estimate of the Path MTU in response to the
    //# contents of a Packet Too Big message. A message purporting to announce an
    //# increase in the Path MTU might be a stale packet that has been floating around
    //# in the network, a false packet injected as part of a denial-of-service (DoS)
    //# attack, or the result of having multiple paths to the destination, each with a
    //# different PMTU.

    //= https://www.rfc-editor.org/rfc/rfc8201#section-6
    //= reason=Feedback never raises the estimate, which prevents the described increase attack. IPv6 base-header wire test from 819b8f2 shows equal/larger MTUs before and after a valid decrease leave the estimate unchanged, including wrap. The hypothetical router round-trip is not claimed as a separate implemented behavior; no native IPv6 socket or extension-header claim.
    //# In the second attack, the false message indicates a PMTU larger than reality. If
    //# believed, this could cause temporary blockage as the victim sends packets that
    //# will be dropped by some router. Within one round-trip time, the node would
    //# discover its mistake (receiving Packet Too Big messages from that router), but
    //# frequent repetition of this attack could cause lots of packets to be dropped. A
    //# node, however, must not raise its estimate of the PMTU based on a Packet Too Big
    //# message, so it should not be vulnerable to this attack.

    /// Legacy ring-matched drop notification. `true` means accepted as a
    /// notification that the exactly recorded transmission was dropped (its
    /// candidate is below the submitted size), whether or not the estimate
    /// decreases; a nondecreasing report never raises the estimate.
    #[cfg(test)]
    pub fn feedback(
        &mut self,
        now: Instant,
        seq: Seq,
        size: u32,
        header: u16,
        candidate: u32,
    ) -> bool {
        self.legacy_report(now, seq, size, header, candidate).derived_mtu.is_some()
    }

    pub(crate) fn legacy_report(
        &mut self,
        now: Instant,
        seq: Seq,
        size: u32,
        header: u16,
        candidate: u32,
    ) -> PmtuReport {
        match self.known(seq, size, header, candidate) {
            Some(known) => {
                let reference = self.info.current_mtu;
                self.report(now, known, size, header, candidate, None, reference)
            }
            None => PmtuReport::REJECTED,
        }
    }

    /// Span of the recorded transmission a legacy quote identifies, if any.
    pub(crate) fn quoted_span(
        &self,
        seq: Seq,
        size: u32,
        header: u16,
        candidate: u32,
    ) -> Option<(Seq, Seq)> {
        self.known(seq, size, header, candidate).map(|p| (p.start, p.end))
    }

    fn known(&self, seq: Seq, size: u32, header: u16, candidate: u32) -> Option<Sent> {
        if !self.plausible_quote(size, header) {
            return None;
        }
        self.sent.iter().flatten().copied().find(|p| {
            p.start == seq
                && p.header == header
                && (p.size == size
                    || self.ipv4
                        && candidate == 0
                        && p.size.checked_add(u32::from(header)) == Some(size))
        })
    }

    fn plausible_quote(&self, size: u32, header: u16) -> bool {
        !((self.ipv4 && (!(20..=60).contains(&header) || !header.is_multiple_of(4)))
            || (!self.ipv4 && header != 40)
            || size < u32::from(header) + 20)
    }

    /// Feedback whose physical submission a managed Host already proved
    /// (exact span, size and header from its ledger), so the bounded `sent`
    /// ring is not consulted a second time: its eviction must not negate a
    /// valid Host match. TCP policy still applies in full. A report that
    /// identifies a dropped packet without decreasing the estimate (equal or
    /// larger than current and not below proven delivery, or about a path
    /// incarnation the connection no longer uses) is consumed as drop advice
    /// only: the black-hole timeout learns an ICMP message explained the
    /// loss and probe attribution applies, but no estimate or hold changes.
    /// A current-path report below proven delivery is Deferred whatever the
    /// current estimate, so a loss-inferred local decrease never changes its
    /// outcome, and the derived size never depends on that estimate either:
    /// RFC 1191 section 5's "current PMTU estimate" for a legacy IPv4 quote
    /// is `path_estimate`, the Host's shared estimate of the current path
    /// incarnation. Without one (an older incarnation, whose report is drop
    /// advice only) the reference is the submitted length: every estimate
    /// the packet could have been sent under was at least that large, so it
    /// reduces every quote any of them would, and it uses no local state.
    #[allow(clippy::too_many_arguments)]
    pub fn correlated_feedback(
        &mut self,
        now: Instant,
        start: Seq,
        end: Seq,
        sent_size: u32,
        header: u16,
        quoted_size: u32,
        candidate: u32,
        current_path: bool,
        path_estimate: Option<u32>,
    ) -> PmtuReport {
        if !self.plausible_quote(quoted_size, header) {
            return PmtuReport::REJECTED;
        }
        let known = Sent {
            start,
            end,
            size: sent_size,
            header,
            ambiguous: false,
        };
        let reference = path_estimate.filter(|_| current_path).unwrap_or(sent_size);
        self.report(
            now,
            known,
            quoted_size,
            header,
            candidate,
            Some(current_path),
            reference,
        )
    }

    // `advice` is None for the legacy ring-matched entrypoint, or whether the
    // Host-proven submission used the connection's current path. `reference`
    // is the PMTU estimate a legacy IPv4 quote is compared with. Every
    // accepted class is a drop notification for `known`.
    #[allow(clippy::too_many_arguments)]
    fn report(
        &mut self,
        now: Instant,
        known: Sent,
        size: u32,
        header: u16,
        candidate: u32,
        advice: Option<bool>,
        reference: u32,
    ) -> PmtuReport {
        let seq = known.start;
        let sent_size = known.size;
        // Only the exact original packet may retain probe classification. A
        // smaller repair or any other live packet is independent loss evidence.
        let original_probe = self
            .probe
            .is_some_and(|p| known.start == p.start && known.end == p.end && known.size == p.size);
        //= https://www.rfc-editor.org/rfc/rfc8201#section-4
        //# If a node receives a Packet Too Big message reporting a next-hop MTU
        //# that is less than the IPv6 minimum link MTU, it must discard it.
        if !self.ipv4 && candidate < 1280 {
            return PmtuReport::REJECTED;
        }
        let mtu = if self.ipv4 && candidate == 0 {
            //= https://www.rfc-editor.org/rfc/rfc1191#section-5
            //# If the Total Length field returned is
            //# not less than the current PMTU estimate, it must be reduced by
            //# 4 times the value of the returned Header Length field.
            // header is in bytes already, not the IHL field's 32-bit words.
            // A Host-correlated report compares with the Host's shared path
            // estimate, the IP layer's current PMTU estimate, so the derived
            // size never depends on connection-local loss inference, and an
            // exact and a header-inflated quote of a packet smaller than that
            // estimate derive the same size. A quote not less than it is
            // reduced as the rule mandates. The uncorrelated legacy
            // entrypoint has no shared estimate and keeps its own.
            let corrected = if size >= reference {
                size.saturating_sub(u32::from(header))
            } else {
                size
            };
            self.plateaus
                .as_slice()
                .iter()
                .copied()
                .find(|&p| p < corrected.min(sent_size))
                .unwrap_or(68)
        } else {
            //= https://www.rfc-editor.org/rfc/rfc1191#section-3
            //# A host MUST never reduce its estimate of the Path MTU below 68
            //# octets.
            candidate.max(min_mtu(self.ipv4))
        };
        //= https://www.rfc-editor.org/rfc/rfc1191#section-3
        //# A host MUST not increase its estimate of the Path MTU in response to
        //# the contents of a Datagram Too Big message.
        //= https://www.rfc-editor.org/rfc/rfc8201#section-4
        //# A node must not increase its estimate of the Path MTU in response to
        //# the contents of a Packet Too Big message.
        // A hop cannot have dropped a packet no larger than its own MTU.
        if mtu >= sent_size {
            return PmtuReport::REJECTED;
        }
        // Probe attribution precedes and is independent of estimate policy.
        // Only the exact original probe may retain its finite loss record,
        // and a PTB about it always invalidates its size result. Any other
        // dropped packet (including a repair copy) is independent loss.
        if original_probe {
            self.invalidate_probe_size_result();
        } else {
            self.probe = None;
            self.outcome = None;
        }
        // RFC 4821 section 7.7: an ICMP message explained this loss.
        self.icmp_since_progress = true;
        let accepted = |feedback| PmtuReport {
            feedback,
            derived_mtu: Some(mtu),
        };
        let unchanged = match advice {
            None => mtu >= self.info.current_mtu,
            // A current-path report below proven delivery is deferred below
            // even when a loss-inferred decrease already took the local
            // estimate under it: what it may change, here or for the Host's
            // shared record, must not depend on connection-local inference.
            Some(current_path) => {
                !current_path || (mtu >= self.info.current_mtu && mtu >= self.max_acked)
            }
        };
        if unchanged {
            // Drop advice only: no estimate increase or hold restart.
            return accepted(PmtuFeedback::Unchanged);
        }
        //= https://www.rfc-editor.org/rfc/rfc5927#section-7.2
        //= reason=Informational mitigation selected as policy, not a TCP MUST. Exact bounded packet evidence strengthens the live-sequence gate; cumulative progress past the quoted data clears a pending report, while a partial ACK into it does not.
        //# A
        //# MAXSEGRTO of 1 provides enough protection for most cases.
        // RFC5927 policy: defer a decrease below previously proven delivery,
        // until the quoted data times out; cumulative progress past the
        // quoted data clears it.
        if mtu < self.max_acked {
            // Even deferred validated PTB feedback inhibits new upward probes.
            self.delay(now, self.hold);
            self.periodic_deadline = None;
            self.reset_search = true;
            if self.pending.is_none_or(|old| old.seq != seq || mtu < old.mtu) {
                self.pending_ids += 1;
                self.pending = Some(Pending {
                    seq,
                    live: seq,
                    end: known.end,
                    mtu,
                    id: self.pending_ids,
                });
            }
            // The deferred size is suspect, the reported drop is not.
            accepted(PmtuFeedback::Deferred)
        } else {
            self.apply_ptb(mtu, now, original_probe);
            accepted(PmtuFeedback::Decreased {
                mtu: self.info.current_mtu,
            })
        }
    }

    pub fn network_error(&mut self) {
        self.icmp_since_progress = true;
    }

    //= https://www.rfc-editor.org/rfc/rfc8201#section-4
    //= reason=Both families retain ten-minute PTB hold through ACK progress and local link growth; only subsequent ACK-confirmed PLPMTUD can raise effective PMTU.
    //# Nodes may detect increases in PMTU, but because doing so requires sending packets
    //# larger than the current estimated PMTU, and because the likelihood is that the PMTU
    //# will not have increased, this must be done at infrequent intervals. An attempt to
    //# detect an increase (by sending a packet larger than the current estimate) must not
    //# be done less than 5 minutes after a Packet Too Big message has been received for the
    //# given path. The recommended setting for this timer is twice its minimum value (10
    //# minutes).

    //= https://www.rfc-editor.org/rfc/rfc4821#section-2
    //= reason=Isolated original-probe loss with or without exact matching PTB suppresses only the logical congestion response after finite cumulative delivery and recovery/PRR exit. Dual-family receiver traces assert conservative split repairs, unchanged threshold, independently MSS-scaled window and mandatory headway; all other loss and timeout responses remain active. Literal unchanged-cwnd conflicts at1191-082/8201-076 remain TODO.
    //# The isolated loss of a probe packet (with or without an ICMP Packet Too Big message) is treated as an indication of an MTU limit, and not as a congestion indicator. In this case alone, the Packetization Protocol is permitted to retransmit any missing data without adjusting the congestion window.
    fn apply_ptb(&mut self, mtu: u32, now: Instant, original_probe: bool) {
        self.icmp_since_progress = true;
        self.info.current_mtu = mtu.min(self.info.current_mtu);
        self.record_upper_limit(mtu);
        self.info.search_low = self.info.search_low.min(mtu);
        if original_probe {
            if let Some(p) = &mut self.probe {
                // PTB establishes a ceiling independently of congestion. Keep
                // the original finite delivery proof, never its size result:
                // even an unexpected original ACK cannot undo this decrease.
                p.size_result_valid = false;
            }
        } else {
            // Other packets (including repairs) cannot prove isolated probe loss.
            self.probe = None;
            self.outcome = None;
        }
        self.verification = None;
        self.delay(now, self.hold);
        self.periodic_deadline = None;
        self.reset_search = true;
    }

    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.1
    //= reason=Unambiguous explicit-probe cumulative ACK raises low and effective MTU; failed encoding cannot create a probe or advance flight.
    //# When the probe is delivered, it is an indication that the Path MTU is at least as
    //# large as the probe size. Set search_low to the probe size. If the probe size is
    //# larger than the eff_pmtu, raise eff_pmtu to the probe size. The probe size might be
    //# smaller than the eff_pmtu if the flow has not been using the full MTU of the path
    //# because it is subject to some other limitation, such as available data in an
    //# interactive session.

    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.2
    //= reason=Real receiver ACKs resolve full trailing flight before isolated classification; upper bound becomes probe-1 and invalid eff falls to low; second hole preserves bounds. No congestion-suppression claim.
    //# In the absence of other indications, set search_high to the probe size minus one.
    //# The eff_pmtu might be larger than the probe size if the flow has not been using the
    //# full MTU of the path because it is subject to some other limitation, such as
    //# available data in an interactive session. If eff_pmtu is larger than the probe size,
    //# eff_pmtu MUST be reduced to no larger than search_high, and SHOULD be reduced to
    //# search_low, as the eff_pmtu has been determined to be invalid, similar to after a
    //# full-stop timeout (see Section 7.7).

    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.8
    //= reason=Selected verification heuristic tracks retry/original ratio >10% across two RTO intervals, preserves prior verified baseline and restores it after repeated increases. Not empirical multipath validation.
    //# Striping in this manner is often operationally undesirable for other reasons (e.g.,
    //# due to packet reordering) and is usually avoided by hashing each flow to a single
    //# path. However, to increase robustness, an implementation SHOULD implement some form
    //# of MTU verification, such that if increasing eff_pmtu results in a sharp increase in
    //# loss rate, it will fall back to using a lower MTU.

    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.8
    //= reason=Selected verification heuristic tracks retry/original ratio >10% across two RTO intervals, preserves prior verified baseline and restores it after repeated increases. Not empirical multipath validation.
    //# A RECOMMENDED strategy would be to save the value of eff_pmtu before raising it.
    //# Then, if loss rate rises above a threshold for a period of time (e.g., loss rate is
    //# higher than 10% over multiple retransmission timeout (RTO) intervals), then the new
    //# MTU is

    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.8
    //= reason=Selected verification heuristic tracks retry/original ratio >10% across two RTO intervals, preserves prior verified baseline and restores it after repeated increases. Not empirical multipath validation.
    //# considered incorrect. The saved value of eff_pmtu SHOULD be restored, and
    //# search_high reduced in the same manner as in a probe failure. PLPMTUD
    //# implementations SHOULD implement MTU verification.

    //= https://www.rfc-editor.org/rfc/rfc4821#section-2
    //= reason=Explicit probe ACK raises effective PMTU and search_low; the wire test checks both families and the next larger probe.
    //# The general strategy is for the Packetization Layer to find an appropriate Path
    //# MTU by probing the path with progressively larger packets. If a probe packet is
    //# successfully delivered, then the effective Path MTU is raised to the probe size.

    //= https://www.rfc-editor.org/rfc/rfc4821#section-2
    //= reason=Selected MTU verification observes retry/original loss ratio and restores the prior baseline after repeated increases; no physical multipath experiment is claimed.
    //# An optional verification process can be used to detect situations where raising
    //# the MTU raises the packet loss rate. For example, if a link is striped across
    //# multiple physical channels with inconsistent MTUs, it is possible that a probe
    //# will be delivered even if it is too large for some of the physical channels. In
    //# such cases, raising the Path MTU to the probe size can cause severe packet loss
    //# and abysmal performance. After raising the MTU, the new MTU size can be verified
    //# by monitoring the loss rate.

    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.1
    //= reason=MTU verification is implemented and the multi-increase lifecycle test restores the original verified baseline after sustained loss; the same evidence supports 150-152. No size-below-eff test is needed for this verification recommendation.
    //# Note that if a flow's packets are routed via multiple paths, or over a path with a
    //# non-deterministic MTU, delivery of a single probe packet does not indicate that
    //# all packets of that size will be delivered. To be robust in such a case, the
    //# Packetization Layer SHOULD conduct MTU verification as described in Section 7.8.

    //= https://www.rfc-editor.org/rfc/rfc4821#section-2
    //= reason=Bound updates are implemented in ack(): explicit success raises low, isolated failure lowers high, and low>=high stops search and schedules reset. The convergence test exercises stop/reset; failure-side executable evidence is separately linked at 140. No single combined trace is required by this overview.
    //# PLPMTUD uses a searching technique to find the Path MTU. Each conclusive probe
    //# narrows the MTU search range, either by raising the lower limit on a successful
    //# probe or lowering the upper limit on a failed probe, converging toward the true
    //# Path MTU. For most transport layers, the search should be stopped once the range
    //# is narrow enough that the benefit of a larger effective Path MTU is smaller than
    //# the search overhead of finding it.

    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.1
    //= reason=State relationship is retained as operative: upward probe success sets low and effective PMTU together; the wire test checks both values and the next upward probe. Initial eff>low is permitted and does not imply an implicit-ACK update here; that distinct SHOULD remains TODO at 111.
    //# When probing upward, eff_pmtu always equals search_low. In other states, such as
    //# initial conditions, after ICMP PTB message processing or following PLPMTUD on
    //# another flow sharing the same path representation, eff_pmtu may be different from
    //# search_low. Normally, eff_pmtu will be greater than or equal to search_low and
    //# less than search_high. It is generally expected but not required that probe size
    //# will be greater than eff_pmtu.

    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.1
    //= reason=Pmtud::ack raises search_low only from fully cumulatively acknowledged, unambiguous ordinary sent packets within effective MTU, search_high and path bounds; explicit-probe overlap retains separate timeout/verification rules. Tests from 742e320 cover real ordinary ACKs in both families/wrap, retry ambiguity, partial ACK, local rejection, PTB/link ceilings, stale quotes, holdoff and probe timeout. Ordinary loss does not enter explicit probe-failure handling; mixed ordinary/explicit success preserves larger ordinary proof.
    //# If eff_pmtu is larger than search_low, it is explicitly permitted to send
    //# non-probe packets larger than search_low. When such a packet is acknowledged, it
    //# is effectively an "implicit probe" and search_low SHOULD be raised to the size
    //# of the acknowledged packet. However, if an "implicit probe" is lost, it MUST NOT
    //# be treated as a probe failure as a true probe would be. If eff_pmtu is too
    //# large, this condition will only be detected with ICMP PTB messages or black hole
    //# discovery (see Section 7.7).

    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.2
    //= reason=Only actual probe repair followed by finite extended-tail cumulative delivery and recovery/PRR exit can suppress the logical congestion response. Dual-family real receiver matrices cover exact matching PTB before/after loss, decreasing ceilings, wrap, PRR, Reno/CUBIC and pacing; other loss, ECE, repair-copy loss and RTO retain normal response. Without PTB the isolated result narrows search_high to probe-1; with matching PTB its invalidated size result cannot undo the accepted ceiling, even on an unexpected original ACK. Independent MSS scaling remains active.
    //# When only the probe is lost, it is treated as an indication that the Path MTU is
    //# smaller than the probe size. In this case alone, the loss SHOULD NOT be
    //# interpreted as congestion signal.

    //= https://www.rfc-editor.org/rfc/rfc4821#section-2
    //# The most likely (and least serious) probe failure is due to the link experiencing congestion-related losses while probing. In this case, it is appropriate to retry a probe of the same size as soon as the Packetization Layer has fully adapted to the congestion and recovered from the losses. In other cases, additional losses or timeouts indicate problems with the link or Packetization Layer. In these situations, it is desirable to use longer delays depending on the severity of the error.
    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.4
    //# The presence of other losses near the loss of the probe may indicate that the probe was lost due to congestion rather than due to an MTU limitation. In this case, the state variables eff_pmtu, search_low, and search_high SHOULD NOT be updated, and the same-sized probe SHOULD be attempted again as soon as the probing preconditions are met (i.e., once the packetization layer has no outstanding unrecovered losses). At this point, it is particularly appropriate to re-probe since the flow's congestion window will be at its lowest point, minimizing the probability of congestive losses.
    //= https://www.rfc-editor.org/rfc/rfc4821#section-2
    //= reason=Timeout/additional-loss completion supplies no failed-size ceiling and marks the outcome non-isolated, retaining normal congestion recovery. Receiver-driven IPv4/IPv6 NewReno/SACK/RACK with PRR on/off assert reduced window/threshold, one-MSS RTO response, unchanged bounds, repair-only output, cooldown exclusion and same-sized re-probing with available credit. Exact deadline tests retain the fivefold timeout hold and longer PTB holds; independent delivery, PTB, verification and black-hole evidence remain operative.
    //# If there is a timeout or additional packets are lost during the probing process,
    //# the probe is considered to be inconclusive (e.g., the lost probe does not
    //# necessarily indicate that the probe exceeded the Path MTU). Furthermore, the
    //# losses are treated like any other congestion indication: window or rate
    //# adjustments are mandatory per the relevant congestion control standards
    //# [RFC2914]. Probing can resume after a delay that is determined by the nature
    //# of the detected failure.
    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.6
    //= reason=Categorized processing retains success/verification evidence at137/138, isolated loss with or without matching PTB at139/142, timeout congestion response and fivefold cooldown at143, and multiple-loss unchanged bounds plus same-sized re-probing at144. The real-probe success/failed-encode test, verification lifecycle, recovery/disqualifier matrices and probe_admission_real_loss_recovery_and_cooldown_output execute these outcomes. Independent PTB ceilings survive original or repair ACKs; timeout alone supplies no failed-size bound.
    //# When a probe has completed, the result SHOULD be processed as follows, categorized by the probe's result type.
    pub fn ack(&mut self, ack: Seq, now: Instant, cooldown: u64, rto: u64) {
        if self
            .repair_range
            .is_some_and(|(_, end)| ack.at_or_after(end))
        {
            self.repair_range = None;
        }
        // Cumulative progress past the quoted data refutes a pending report;
        // a partial ACK leaves its surviving quoted data outstanding.
        if let Some(pending) = &mut self.pending {
            if ack.at_or_after(pending.end) {
                self.pending = None;
            } else if ack.after(pending.live) {
                pending.live = ack;
            }
        }
        self.icmp_since_progress = false;
        for entry in &mut self.sent {
            if let Some(packet) = entry
                && ack.at_or_after(packet.end)
            {
                if !packet.ambiguous {
                    self.max_acked = self.max_acked.max(packet.size);
                    // Ordinary delivery validates only the current non-probe
                    // range. Old larger flight must not undo a PTB/link bound,
                    // and explicit probes retain their own timeout/verification rules.
                    if packet.size
                        <= self
                            .info
                            .current_mtu
                            .min(self.info.search_high)
                            .min(self.bound)
                        && self
                            .probe
                            .is_none_or(|p| !overlaps(packet.start, packet.end, p.start, p.end))
                    {
                        self.info.search_low = self.info.search_low.max(packet.size);
                    }
                }
                *entry = None;
            }
        }
        let verification_expired = self
            .verification
            .is_some_and(|(_, since, _, _)| now.saturating_sub(since) >= rto.saturating_mul(2));
        if let Some(p) = self.probe {
            if !p.retried && !p.timeout && ack.at_or_after(p.end) {
                //= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.1
                //# Set search_low to the probe
                //# size.  If the probe size is larger than the eff_pmtu, raise eff_pmtu
                //# to the probe size.
                if p.size_result_valid {
                    // Recorded even when local proof already exceeds it: the
                    // probe still establishes a network fact for this size.
                    self.success = Some((p.start, p.end, p.size));
                    self.info.search_low = self.info.search_low.max(p.size);
                    if p.size > self.info.current_mtu {
                        // Preserve the baseline across successive verified increases.
                        self.verification
                            .get_or_insert((self.info.current_mtu, now, 0, 0))
                            .1 = now;
                        self.info.current_mtu = p.size;
                    }
                }
                self.probe = None;
            } else if ack.at_or_after(p.trailing_end) {
                self.outcome = Some(ProbeOutcome {
                    start: p.start,
                    end: p.trailing_end,
                    isolated: p.retried && !p.other_loss && !p.timeout,
                });
                if p.size_result_valid && p.retried && !p.other_loss && !p.timeout {
                    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.2
                    //= reason=Wait for cumulative delivery of the trailing window and exclude timeout or nearby loss. Only conclusive size evidence narrows this bound; congestion outcome consumption is separate.
                    //# In the absence of other indications, set search_high to the probe
                    //# size minus one.
                    self.record_upper_limit(p.size - 1);
                    self.info.search_low = self.info.search_low.min(self.info.search_high);
                    if self.info.current_mtu >= p.size {
                        self.info.current_mtu = self.info.search_low;
                    }
                }
                if p.retried && !p.other_loss {
                    // Preserve the conservative finishing-ACK timeout hold even
                    // when the probe supplies no conclusive size evidence.
                    self.delay(now, cooldown.saturating_mul(if p.timeout { 5 } else { 1 }));
                } else if p.other_loss && !p.timeout && !self.reset_search {
                    self.deadline = None;
                }
                // Timeout and multiple/nearby loss are inconclusive; they supply
                // no MTU ceiling. Independent delivery/verification still applies.
                // Only the one-shot non-timeout isolated result may waive CC.
                self.probe = None;
            }
        }
        //= https://www.rfc-editor.org/rfc/rfc4821#section-7.8
        //# PLPMTUD implementations SHOULD implement MTU verification.
        // Two RTO intervals with >10% retry/original packets revert the increase.
        if let Some((previous, since, sent, lost)) = self.verification
            // A new increase must not defer an already-due lossy rollback.
            && (now.saturating_sub(since) >= rto.saturating_mul(2)
                || verification_expired && lost.saturating_mul(10) > sent)
            && sent != 0
        {
            if lost.saturating_mul(10) > sent {
                self.record_upper_limit(self.info.current_mtu - 1);
                self.info.current_mtu = previous.min(self.route_bound());
                self.info.search_low = self.info.search_low.min(self.info.current_mtu);
                self.probe = None;
                self.delay(now, cooldown);
            }
            self.verification = None;
        }
        //= https://www.rfc-editor.org/rfc/rfc4821#section-7.3
        //= reason=One-byte search convergence; caller-timebase ten-minute reset, not a two-minute hold between active successful search steps.
        //# The value for this timer
        //# MUST NOT be less than 5 minutes and is recommended to be 10 minutes,
        //# per RFC 1981.
        if self.info.search_low >= self.info.search_high {
            self.schedule_aging(now);
        }
    }

    fn record_upper_limit(&mut self, mtu: u32) {
        self.discovered_high = Some(self.discovered_high.map_or(mtu, |old| old.min(mtu)));
        self.info.search_high = self.info.search_high.min(mtu);
    }

    fn route_bound(&self) -> u32 {
        self.bound.min(self.info.route_mtu.unwrap_or(self.bound))
    }

    fn search_ceiling(&self) -> u32 {
        self.route_bound()
            .min(self.high_limit.unwrap_or(self.bound))
    }

    fn schedule_aging(&mut self, now: Instant) {
        if self.deadline.is_none() && self.periodic_deadline.is_none() {
            self.periodic_deadline = self
                .aging
                .map(|interval| now.saturating_add(interval))
                .filter(|&d| d > now);
        }
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.deadline
            .into_iter()
            .chain(self.periodic_deadline)
            .min()
    }

    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.3
    //= reason=Reviewed 0030a96: PmtudPolicy exposes SearchAging::Seconds (validated >=300 with checked caller-timebase conversion) and Infinity through creation and live Endpoint::set_pmtud_policy. Tests exercise finite rearming, disabled periodic aging and both families retaining independent mandatory 600-second PTB hold and failure cooldown. No route/cache or socket-parser integration is claimed.
    //# Note: an implementation should provide a means for changing the timeout
    //# duration, including setting it to "infinity". For example, hosts attached to an
    //# FDDI network which is then attached to the rest of the Internet via a slow
    //# serial line are never going to discover a new non-local PMTU, so they should not
    //# have to put up with dropped datagrams every 10 minutes.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.6
    //= reason=Reviewed 0030a96: PmtudPolicy exposes SearchAging::Seconds (validated >=300 with checked caller-timebase conversion) and Infinity through creation and live Endpoint::set_pmtud_policy. Tests exercise finite rearming, disabled periodic aging and both families retaining independent mandatory 600-second PTB hold and failure cooldown. No route/cache or socket-parser integration is claimed.
    //# The implementation should also provide a way to change the timeout period for
    //# aging stale PMTU information.

    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.3
    //= reason=Reviewed 0030a96: PmtudPolicy exposes SearchAging::Seconds (validated >=300 with checked caller-timebase conversion) and Infinity through creation and live Endpoint::set_pmtud_policy. Tests exercise finite rearming, disabled periodic aging and both families retaining independent mandatory 600-second PTB hold and failure cooldown. No route/cache or socket-parser integration is claimed.
    //# Note: an implementation should provide a means for changing the timeout
    //# duration, including setting it to "infinity". For example, nodes attached to a
    //# link with a large MTU that is then attached to the rest of the Internet via a
    //# link with a small MTU are never going to discover a new non-local PMTU, so they
    //# should not have to put up with dropped packets every 10 minutes.

    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.6
    //= reason=Reviewed 0030a96: PmtudPolicy exposes SearchAging::Seconds (validated >=300 with checked caller-timebase conversion) and Infinity through creation and live Endpoint::set_pmtud_policy. Tests exercise finite rearming, disabled periodic aging and both families retaining independent mandatory 600-second PTB hold and failure cooldown. No route/cache or socket-parser integration is claimed.
    //# The implementation should also provide a way to change the timeout period for
    //# aging stale PMTU information.

    pub fn set_policy(&mut self, now: Instant, policy: PmtudPolicy, aging: Option<u64>) {
        self.plateaus = policy.ipv4_plateaus;
        if self.aging != aging {
            self.aging = aging;
            self.periodic_deadline = None;
            if self.info.search_low >= self.info.search_high
                || self.info.search_high < self.search_ceiling()
            {
                self.schedule_aging(now);
            }
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.4
    //= reason=IPv6 lost_probe_repairs uses real receiver ACKs and ntcp-ip6 parsing to assert repairs split within the original probe gap and conservative packet budget, including two decreasing exact original PTBs down to1280 and wrapping sequences. Normal repair admission remains active; finite full-tail proof suppresses only the logical loss response, preserving MSS scaling and the PTB hold. Other-loss, ECN, repair-copy-loss and timeout matrices retain normal retransmission congestion control. Literal unchanged-cwnd and shared-path fanout obligations remain separate.
    //# Note: A packetization layer that determines a probe packet is lost needs to
    //# adapt the segment size of the retransmission. Using the reported size in the
    //# last Packet Too Big message, however, can lead to further losses as there might
    //# be smaller PMTU limits at the routers further along the path. This would lead to
    //# loss of all retransmitted segments and therefore cause unnecessary congestion as
    //# well as additional packets to be sent each time a new router announces a smaller
    //# MTU. Any packetization layer that uses retransmission is therefore also
    //# responsible for congestion control of its retransmissions [RFC8085].

    pub fn repair_limit(&self, seq: Seq, proposed: u32) -> u32 {
        match self.repair_range {
            Some((start, end)) if seq.in_window(start, end.distance_from(start)) == Some(true) => {
                proposed.min(end.distance_from(seq))
            }
            _ => proposed,
        }
    }

    pub fn terminal(&mut self) {
        self.probe = None;
        self.outcome = None;
        self.repair_range = None;
    }

    fn delay(&mut self, now: Instant, interval: u64) {
        self.deadline = Some(self.deadline.unwrap_or(0).max(now.saturating_add(interval)));
    }

    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.7
    //= reason=R1 uses third consecutive data RTO; earlier RTOs preserve PMTU, later ones halve to family floor while cwnd follows normal timeout response.
    //# Under all conditions, a full-stop timeout (also known as a "persistent timeout" in
    //# other documents) SHOULD be taken as an indication of some significantly disruptive
    //# event in the network, such as a router failure or a routing change to a path with a
    //# smaller MTU. For TCP, this occurs when the R1 timeout threshold described by
    //# [RFC1122] expires.

    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.3
    //= reason=Reviewed 76800de: real receiver disqualifier matrix drops a probe repair and fires actual TCP RTO, asserting one-MSS cwnd, reduced threshold and committed response throughout cumulative repair. Non-SACK NewReno as well as SACK/RACK, PRR and Reno/CUBIC are exercised. Pmtud::timeout applies five times cooldown; exact deadline unit test and integrated timeout trace prove later inconclusive retry loss cannot erase it. This is TCP timeout repair, not a new generic go-back-n transport.
    //# If the loss was detected with a timeout and repaired with go-back-n
    //# retransmission, then congestion window reduction will be necessary. The
    //# relatively high price of a failed probe in this case may merit a longer time
    //# interval until the next probe. A time interval that is five times the
    //# non-timeout failure case (Section 7.6.2) is RECOMMENDED.

    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.7
    //# If there is a full-stop timeout and there was not an ICMP message indicating a reason (PTB, Net unreachable, etc., or the ICMP message was ignored for some reason), the RECOMMENDED first recovery action is to treat this as a detected ICMP black hole as defined in [RFC2923].
    pub fn timeout(&mut self, now: Instant, head: Seq, consecutive: u32, cooldown: u64) {
        if let Some(pending) = self.pending.take() {
            // Only the timeout of still-outstanding quoted data authorizes a
            // deferred decrease, never that of unrelated earlier data.
            if head.in_window(pending.live, pending.end.distance_from(pending.live)) == Some(true) {
                // Deferred feedback is applied only on timeout, which cannot
                // qualify for an isolated-loss congestion exemption.
                self.apply_ptb(pending.mtu, now, false);
                // The report's own size, never the estimate now in force: a
                // lower loss-inferred estimate stays connection-local, and the
                // report never raises it.
                self.applied_pending = Some((pending.id, pending.mtu));
            } else {
                self.pending = Some(pending);
            }
        }
        if let Some(p) = &mut self.probe {
            p.timeout = true;
            if head != p.start {
                p.other_loss = true;
            }
            //= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.3
            //# A time interval that is
            //# five times the non-timeout failure case (Section 7.6.2) is
            //# RECOMMENDED.
            self.delay(now, cooldown.saturating_mul(5));
        }
        //= https://www.rfc-editor.org/rfc/rfc4821#section-7.7
        //# For TCP, this occurs when the R1 timeout threshold described by
        //# [RFC1122] expires.
        if consecutive >= 3 && !self.icmp_since_progress {
            // An explicit conservative transport bound is not an undersized
            // physical link or PTB. Recovery must never raise packet size or
            // exceed a current administrative ceiling. Unconfigured IPv6
            // still retains the normal 1280-byte blackhole fallback floor.
            let ceiling = self.route_bound().min(self.info.current_mtu);
            let floor = min_mtu(self.ipv4).min(self.initial_low).min(ceiling);
            let low = if consecutive == 3 {
                if self.info.current_mtu > self.info.search_low {
                    self.info.search_low
                } else {
                    self.initial_low.min(self.info.current_mtu)
                }
            } else {
                self.info.current_mtu / 2
            }
            .max(floor)
            .min(ceiling);
            self.info.current_mtu = low;
            self.info.search_low = self.info.search_low.min(low);
            self.probe = None;
            self.verification = None;
            self.delay(now, cooldown.saturating_mul(5));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(ipv4: bool) -> Pmtud {
        Pmtud::new(PmtudConfig::new(1500), 1500, ipv4, 600_000_000).unwrap()
    }

    // Host-correlated drop advice: consumed by black-hole classification
    // without raising the estimate, restarting the hold or deferring.
    #[test]
    fn correlated_unchanged_report_is_consumed_as_drop_advice_only() {
        for ipv4 in [true, false] {
            let header = if ipv4 { 20 } else { 40 };
            let report = |p: &mut Pmtud, now, mtu, current| {
                p.correlated_feedback(
                    now,
                    Seq(1),
                    Seq(1449),
                    1500,
                    header,
                    1500,
                    mtu,
                    current,
                    None,
                )
                .feedback
            };
            let mut advised = state(ipv4);
            let mut control = state(ipv4);
            for p in [&mut advised, &mut control] {
                // The ring is never consulted: nothing was recorded in it.
                assert!(!p.feedback(1, Seq(1), 1500, header, 1400));
                assert_eq!(report(p, 2, 1500, true), PmtuFeedback::Rejected);
                if !ipv4 {
                    assert_eq!(report(p, 2, 1279, true), PmtuFeedback::Rejected);
                }
                assert_eq!(
                    report(p, 3, 1400, true),
                    PmtuFeedback::Decreased { mtu: 1400 }
                );
                assert_eq!(p.info.current_mtu, 1400);
                // ACK progress clears the ICMP explanation of later loss.
                p.ack(Seq(1), 4, 1000, 1000);
            }
            let (info, deadline) = (advised.info, advised.deadline);
            // Equal, larger-than-current and stale-incarnation reports.
            assert_eq!(report(&mut advised, 5, 1400, true), PmtuFeedback::Unchanged);
            assert_eq!(report(&mut advised, 6, 1450, true), PmtuFeedback::Unchanged);
            assert_eq!(report(&mut advised, 7, 1300, false), PmtuFeedback::Unchanged);
            assert_eq!((advised.info, advised.deadline), (info, deadline));
            assert!(advised.pending.is_none() && advised.icmp_since_progress);
            // The third consecutive RTO is explained by the ICMP drop; the
            // control (no advice) treats it as a black hole.
            advised.timeout(8, Seq(1), 3, 1000);
            control.timeout(8, Seq(1), 3, 1000);
            assert_eq!(advised.info.current_mtu, 1400);
            assert!(control.info.current_mtu < 1400);
        }
    }

    // A current-path report below proven delivery is deferred whether or not
    // black-hole timeouts already lowered the local estimate under it; its
    // timeout never raises that estimate and reports the report's own size,
    // never the loss-inferred one.
    #[test]
    fn below_proven_delivery_report_defers_regardless_of_loss_inferred_estimate() {
        for ipv4 in [true, false] {
            let (header, size, reported) = if ipv4 { (20, 1440, 1100) } else { (40, 1460, 1350) };
            let (first, second, end) = (Seq(1), Seq(1401), Seq(2801));
            let mut outcomes = [None, None];
            for (index, inferred) in [false, true].into_iter().enumerate() {
                for progress in [true, false] {
                    let mut p = state(ipv4);
                    p.sent(first, second, size, header, false);
                    p.ack(second, 1, 1000, 1000);
                    assert_eq!(p.max_acked, size);
                    p.sent(second, end, size, header, false);
                    let mut consecutive = 0;
                    while inferred && p.info.current_mtu >= reported {
                        consecutive += 1;
                        p.timeout(2, second, consecutive, 1000);
                    }
                    assert_eq!(inferred, p.info.current_mtu < reported);
                    let (local, deadline) = (p.info.current_mtu, p.deadline);
                    assert_eq!(
                        p.correlated_feedback(
                            3, second, end, size, header, size, reported, true, None
                        ),
                        PmtuReport {
                            feedback: PmtuFeedback::Deferred,
                            derived_mtu: Some(reported),
                        }
                    );
                    assert_eq!(p.info.current_mtu, local);
                    assert_ne!(p.deadline, deadline);
                    let pending = p.pending_id().unwrap();
                    if progress {
                        // Cumulative progress clears it: nothing is applied.
                        p.ack(end, 4, 1000, 1000);
                        p.timeout(5, end, 1, 1000);
                        assert_eq!((p.pending_id(), p.take_applied_pending()), (None, None));
                        continue;
                    }
                    // The quoted data's timeout applies exactly that report.
                    p.timeout(4, second, consecutive + 1, 1000);
                    assert_eq!(p.info.current_mtu, local.min(reported));
                    assert_eq!(p.take_applied_pending(), Some((pending, reported)));
                    outcomes[index] = Some(p.info.current_mtu);
                }
            }
            assert_eq!(outcomes[0], Some(reported));
            assert!(outcomes[1].unwrap() < reported);
        }
    }

    // An exact original-probe report invalidates the probe's size result,
    // and any other dropped packet (including a repair copy of the probe)
    // removes its isolation, whichever class the estimate policy returns.
    #[test]
    fn probe_attribution_is_independent_of_the_accepted_class() {
        let cases = [
            (1100, true, false, PmtuFeedback::Decreased { mtu: 1100 }),
            (1220, true, false, PmtuFeedback::Unchanged),
            (1100, false, false, PmtuFeedback::Unchanged),
            (1100, true, true, PmtuFeedback::Deferred),
        ];
        for (candidate, current, delivered, class) in cases {
            for target in 0..3 {
                let mut p = state(true);
                if delivered {
                    p.sent(Seq(0), Seq(1160), 1200, 20, false);
                    p.ack(Seq(1160), 1, 1000, 1000);
                    assert_eq!(p.max_acked, 1200);
                }
                p.info.current_mtu = 1200;
                let start = Seq(1160);
                let end = start.wrapping_add(1200);
                p.start_probe(start, 1200, 3000, 1240);
                p.sent(start, end, 1240, 20, false);
                p.sent(end, end.wrapping_add(1200), 1240, 20, false);
                let (s, e, size) = match target {
                    0 => (start, end, 1240),
                    1 => {
                        let copy = start.wrapping_add(1160);
                        p.sent(start, copy, 1200, 20, true);
                        (start, copy, 1200)
                    }
                    _ => (end, end.wrapping_add(1200), 1240),
                };
                if candidate >= size {
                    continue;
                }
                let report =
                    p.correlated_feedback(2, s, e, size, 20, size, candidate, current, None);
                assert_eq!(report.feedback, class);
                assert_eq!(report.derived_mtu, Some(candidate));
                if target == 0 {
                    assert!(p.probe.is_some_and(|q| !q.size_result_valid));
                } else {
                    assert!(p.probe.is_none());
                }
                assert!(p.provable_probe().is_none());
            }
        }
        // The legacy entrypoint attributes a nondecreasing report alike.
        let mut p = state(true);
        p.info.current_mtu = 1200;
        p.start_probe(Seq(1), 1200, 3000, 1240);
        p.sent(Seq(1), Seq(1201), 1240, 20, false);
        assert!(p.feedback(2, Seq(1), 1240, 20, 1220));
        assert_eq!(p.info.current_mtu, 1200);
        assert!(p.probe.is_some_and(|q| !q.size_result_valid));
    }

    // A partial ACK into the quoted data neither clears a deferred report
    // nor lets an unrelated head's timeout authorize it; the timeout of its
    // surviving quoted data does, and progress past that data clears it.
    #[test]
    fn deferred_report_is_authorized_by_its_own_surviving_data_timeout() {
        for ipv4 in [true, false] {
            let (header, reported) = if ipv4 { (20, 1100) } else { (40, 1350) };
            let payload = 1500 - u32::from(header) - 20;
            for clear in [false, true] {
                let mut p = state(ipv4);
                let first = Seq(u32::MAX - 700);
                let second = first.wrapping_add(payload);
                let third = second.wrapping_add(payload);
                let end = third.wrapping_add(payload);
                p.sent(first, second, 1500, header, false);
                p.ack(second, 1, 1000, 1000);
                p.sent(second, third, 1500, header, false);
                p.sent(third, end, 1500, header, false);
                let report =
                    p.correlated_feedback(2, third, end, 1500, header, 1500, reported, true, None);
                assert_eq!(report.feedback, PmtuFeedback::Deferred);
                let id = p.pending_id().unwrap();
                p.timeout(3, second, 1, 1000);
                assert_eq!((p.info.current_mtu, p.pending_id()), (1500, Some(id)));
                let partial = third.wrapping_add(100);
                p.ack(partial, 4, 1000, 1000);
                assert_eq!(p.pending_id(), Some(id));
                if clear {
                    p.ack(end, 5, 1000, 1000);
                    p.timeout(6, end, 1, 1000);
                    assert_eq!((p.pending_id(), p.take_applied_pending()), (None, None));
                    assert_eq!(p.info.current_mtu, 1500);
                } else {
                    p.timeout(5, partial, 2, 1000);
                    assert_eq!(p.info.current_mtu, reported);
                    assert_eq!(p.take_applied_pending(), Some((id, reported)));
                }
            }
        }
    }

    // RFC 1191 section 5 for a Host-correlated legacy IPv4 report compares
    // the quoted length with the Host's shared path estimate, the IP layer's
    // current PMTU estimate, so the derived size never depends on a
    // loss-inferred local estimate. A packet smaller than that estimate
    // derives the same size from an exact and a header-inflated quote; for
    // one not smaller, section 5 mandates reducing both quotes, which the
    // rule then cannot tell apart. An older incarnation's report compares
    // with the submitted length. The uncorrelated entrypoint keeps the
    // current-estimate comparison.
    #[test]
    fn correlated_legacy_correction_is_independent_of_the_local_estimate() {
        let below = |p: &Pmtud, v: u32| p.plateaus.as_slice().iter().copied().find(|&x| x < v).unwrap();
        // (table, shared estimate, submitted, exact-quote and inflated-quote
        // sizes), each the plateau below the quote, reduced by its header
        // when not less than the estimate, and capped by the submitted size.
        let cases = [
            (Ipv4Plateaus::RFC1191, 1500, 1010, 1006, 1006),
            (Ipv4Plateaus::RFC1191, 1500, 1452, 1006, 1006),
            (Ipv4Plateaus::RFC1191, 1500, 1500, 1006, 1492),
            (Ipv4Plateaus::RFC1191, 1000, 1010, 508, 1006),
            (Ipv4Plateaus::CONTEMPORARY, 1500, 1010, 576, 576),
            (Ipv4Plateaus::CONTEMPORARY, 1500, 1495, 1492, 1492),
            (Ipv4Plateaus::CONTEMPORARY, 1500, 1500, 1460, 1492),
            (Ipv4Plateaus::CONTEMPORARY, 1000, 1010, 576, 576),
        ];
        for (table, estimate, sent, exact, inflated) in cases {
            for inferred in [None, Some(1006), Some(576)] {
                let derive = |quoted, current, shared| {
                    let mut p = state(true);
                    p.set_plateaus(table);
                    if let Some(mtu) = inferred {
                        p.info.current_mtu = mtu;
                    }
                    let end = Seq(sent - 39);
                    let report =
                        p.correlated_feedback(1, Seq(1), end, sent, 20, quoted, 0, current, shared);
                    assert_ne!(report.feedback, PmtuFeedback::Rejected);
                    let rule = if quoted >= shared.filter(|_| current).unwrap_or(sent) {
                        quoted - 20
                    } else {
                        quoted
                    };
                    assert_eq!(report.derived_mtu, Some(below(&p, rule.min(sent))));
                    report.derived_mtu.unwrap()
                };
                assert_eq!(derive(sent, true, Some(estimate)), exact);
                assert_eq!(derive(sent + 20, true, Some(estimate)), inflated);
                if sent < estimate {
                    assert_eq!(exact, inflated);
                }
                // Older incarnation: drop advice compared with the submitted
                // length, whatever estimate accompanies it.
                derive(sent, false, Some(estimate));
                derive(sent + 20, false, None);
            }
        }
        // Uncorrelated: the comparison stays with the current estimate.
        for (current, corrected) in [(1500, false), (1006, true)] {
            let mut p = state(true);
            p.sent(Seq(1), Seq(971), 1010, 20, false);
            p.info.current_mtu = current;
            let report = p.legacy_report(1, Seq(1), 1010, 20, 0);
            let expected = below(&p, if corrected { 990 } else { 1010 });
            assert_eq!(report.derived_mtu, Some(expected));
        }
    }

    #[test]
    fn matching_ptb_retains_finite_classification_and_repair_boundary() {
        for start in [Seq(1), Seq(u32::MAX - 499)] {
            let mut p = state(false);
            let end = start.wrapping_add(1330);
            p.start_probe(start, 1330, 3660, 1390);
            p.sent(start, end, 1390, 40, false);
            assert!(p.feedback(10, start, 1390, 40, 1389));
            let partial = start.wrapping_add(1220);
            p.sent(start, partial, 1280, 40, true);
            // Retrying marks the old sent entry ambiguous for ACK size proof,
            // but an exact quote still identifies the original larger probe.
            assert!(p.feedback(11, start, 1390, 40, 1280));
            let info = p.info;
            let deadline = p.deadline;
            assert!(p.probe.is_some());
            assert!(!p.probe.unwrap().size_result_valid);
            // Repeated and nondecreasing reports are still drop notifications
            // for the original probe; they change no estimate or hold.
            assert!(p.feedback(12, start, 1390, 40, 1280));
            assert!(p.feedback(13, start, 1390, 40, 1389));
            assert_eq!((p.info, p.deadline), (info, deadline));
            assert!(p.probe.is_some_and(|p| !p.size_result_valid));
            assert_eq!(p.repair_limit(start, 1220), 1220);
            p.ack(partial, 20, 1000, 1000);
            p.ack(partial, 21, 1000, 1000); // duplicate progress cannot clear the tail
            assert_eq!(p.repair_limit(partial, 1220), 110);
            assert_eq!(p.repair_limit(end, 1220), 1220);
            assert_eq!(p.info, info);
            assert_eq!(p.deadline, deadline);
            p.tick(deadline.unwrap());
            assert!(p.target().is_none()); // no replacement while repair is outstanding
            p.sent(partial, end, 170, 40, true);
            p.ack(end, deadline.unwrap() + 1, 1000, 1000);
            assert!(p.repair_range.is_none());
            assert!(p.probe.is_some()); // Gap delivery is not full-tail proof.
            let tail = end.wrapping_add(3660);
            p.ack(tail, deadline.unwrap() + 2, 1000, 1000);
            assert!(p.take_probe_outcome(tail).unwrap().isolated);
            assert!(p.take_probe_outcome(tail).is_none());
            assert!(p.probe.is_none());
            assert!(p.verification.is_none());
            assert_eq!(p.info.current_mtu, 1280);
            assert_eq!(p.info.search_low, 1280);
            assert_eq!(p.info.search_high, 1500); // Hold expiry alone reopens search.
            let ready = p.deadline.unwrap();
            p.tick(ready);
            let next_size = p.target().unwrap();
            p.start_probe(end, next_size - 60, 3660, next_size);
            assert_eq!(p.repair_limit(end, 2000), next_size - 60);
            let next_end = end.wrapping_add(next_size - 60);
            p.sent(end, next_end, next_size, 40, false);
            p.ack(next_end, ready + 1, 1000, 1000);
            assert_eq!(p.info.current_mtu, next_size); // fresh probe still classifies
            assert!(p.repair_range.is_none());
            assert!(!p.feedback(ready + 2, start, 1390, 40, 1280)); // stale quote
            p.start_probe(next_end, 1330, 3660, 1390);
            p.apply_ptb(1280, ready + 2, false);
            p.terminal();
            assert!(p.repair_range.is_none());
            assert!(p.probe.is_none());
            assert_eq!(p.repair_limit(next_end, 2000), 2000);
        }
    }

    #[test]
    fn probe_repair_overlap_is_not_another_loss() {
        for start in [Seq(1), Seq(u32::MAX - 499)] {
            let mut p = state(false);
            p.start_probe(start, 1330, 3660, 1390);
            let end = start.wrapping_add(1330);
            p.sent(
                start.wrapping_add(1220),
                end.wrapping_add(1110),
                1280,
                40,
                true,
            );
            assert!(p.probe.unwrap().retried);
            assert!(!p.probe.unwrap().other_loss);
            p.sent(end, end.wrapping_add(1220), 1280, 40, true);
            assert!(p.probe.unwrap().other_loss); // a distinct trailing repair is evidence
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc1191#section-5
    //= type=test
    //= reason=Zero next-hop MTU uses quoted total length, legacy IHL correction and next lower plateau; exact packet evidence bounds the input and floor68 is retained.
    //# Any search strategy must have some "memory" of previous estimates in order to chose
    //# the next one. One approach is to use the currently-cached estimate of the Path MTU,
    //# but in fact there is better information available in the Datagram Too Big message
    //# itself. All ICMP Destination Unreachable messages, including this one, contain the
    //# IP header of the original datagram, which contains the Total Length of the datagram
    //# that was too big to be forwarded without fragmentation. Since this Total Length may
    //# be less than the current PMTU estimate, but is nonetheless larger than the actual
    //# PMTU, it may be a good input to the method for choosing the next PMTU estimate.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-5
    //= type=test
    //= reason=Zero next-hop MTU uses quoted total length, legacy IHL correction and next lower plateau; exact packet evidence bounds the input and floor68 is retained.
    //# Note: routers based on implementations derived from 4.2BSD Unix send an incorrect
    //# value for the Total Length of the original IP datagram. The value sent by these
    //# routers is the sum of the original Total Length and the original Header Length
    //# (expressed in octets). Since it is impossible for the host receiving such a Datagram
    //# Too Big message to know if it sent by one of these routers, the host must be
    //# conservative and assume that it is. If the Total Length field returned is not less
    //# than the current PMTU estimate, it must be reduced by 4 times the value of the
    //# returned Header Length field.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-5
    //= type=test
    //= reason=Zero next-hop MTU uses quoted total length, legacy IHL correction and next lower plateau; exact packet evidence bounds the input and floor68 is retained.
    //# The strategy we recommend, then, is to use as the next PMTU estimate the greatest
    //# plateau value that is less than the returned Total Length field (corrected, if
    //# necessary, according to the Note above).

    //= https://www.rfc-editor.org/rfc/rfc5927#section-7.4
    //= type=test
    //= reason=Selected max-sent update is implemented exactly as max_sent.max(size) in sent(). Exact-evidence tests send real sizes and exercise acceptance/rejection against their recorded upper bound; initialization/reset choices are separate clauses.
    //# if (packet_size > maxsizesent) maxsizesent = packet_size;

    //= https://www.rfc-editor.org/rfc/rfc1191#section-3
    //= type=test
    //= reason=IPv4 zero Next-Hop MTU selects the next lower plateau using exact sent length and legacy header correction. Connection, direct-state and native socket tests cover zero-MTU processing; the following section5 cross-reference is context, not a missing feature.
    //# Hosts MUST be able to deal with Datagram Too Big messages that do not include
    //# the next-hop MTU, since it is not feasible to upgrade all the routers in the
    //# Internet in any finite time. A Datagram Too Big message from an unmodified
    //# router can be recognized by the presence of a zero in the (newly-defined)
    //# Next-Hop MTU field.

    fn pmtud_exact_evidence_eviction_legacy_header_correction_and_floor() {
        for (reported, expected) in [(1500, 1006), (1520, 1492)] {
            let mut p = state(true);
            p.sent(Seq(10), Seq(1470), 1500, 20, false);
            assert!(p.feedback(1, Seq(10), reported, 20, 0));
            assert_eq!(p.info.current_mtu, expected);
            // A nondecreasing report of the same packet is a drop notification
            // that never raises the estimate.
            assert!(p.feedback(2, Seq(10), 1500, 20, 1499));
            assert_eq!(p.info.current_mtu, expected);
        }
        let mut p = state(true);
        p.sent(Seq(10), Seq(60), 90, 20, false);
        assert!(p.feedback(1, Seq(10), 90, 20, 0));
        assert_eq!(p.info.current_mtu, 68);
        let mut p = state(true);
        for n in 0..65 {
            p.sent(Seq(n * 1460), Seq((n + 1) * 1460), 1500, 20, false);
        }
        assert!(!p.feedback(1, Seq(0), 1500, 20, 1000));
        assert!(p.feedback(1, Seq(64 * 1460), 1500, 20, 1000));
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.3
    //= type=test
    //= reason=Reviewed 76800de: real receiver disqualifier matrix drops a probe repair and fires actual TCP RTO, asserting one-MSS cwnd, reduced threshold and committed response throughout cumulative repair. Non-SACK NewReno as well as SACK/RACK, PRR and Reno/CUBIC are exercised. Pmtud::timeout applies five times cooldown; exact deadline unit test and integrated timeout trace prove later inconclusive retry loss cannot erase it. This is TCP timeout repair, not a new generic go-back-n transport.
    //# If the loss was detected with a timeout and repaired with go-back-n
    //# retransmission, then congestion window reduction will be necessary. The
    //# relatively high price of a failed probe in this case may merit a longer time
    //# interval until the next probe. A time interval that is five times the
    //# non-timeout failure case (Section 7.6.2) is RECOMMENDED.

    fn pmtud_probe_timeout_cooldown_inconclusive_and_unambiguous_ack() {
        for multiple in [false, true] {
            let mut p = state(true);
            let start = Seq(u32::MAX - 499);
            let end = start.wrapping_add(1200);
            let tail = end.wrapping_add(3000);
            p.start_probe(start, 1200, 3000, 1240);
            p.sent(start, end, 1240, 20, false);
            p.timeout(100, start, 1, 1000);
            assert_eq!(p.deadline, Some(5100));
            p.sent(start, start.wrapping_add(984), 1024, 20, true);
            if multiple {
                p.sent(end, tail, 3040, 20, true);
            }
            let before = p.info;
            p.ack(end, 110, 1000, 1000);
            assert_eq!(p.info, before); // retry ACK cannot prove probe success
            p.ack(tail, 120, 1000, 1000);
            assert_eq!(p.info, before);
            assert!(!p.take_probe_outcome(tail).unwrap().isolated);
            let deadline = if multiple { 5100 } else { 5120 };
            assert_eq!(p.deadline, Some(deadline));
            p.tick(deadline - 1);
            assert!(p.target().is_none());
            p.tick(deadline);
            assert_eq!(p.info, before);
            assert_eq!(p.target(), Some(1262));
            // Independent, unambiguous ordinary delivery can still prove a
            // larger lower bound after the inconclusive probe has completed.
            let delivered = tail.wrapping_add(1360);
            p.sent(tail, delivered, 1400, 20, false);
            p.ack(delivered, deadline + 1, 1000, 1000);
            assert_eq!(p.info.search_low, 1400);
            assert_eq!(p.info.search_high, before.search_high);
            assert_eq!(p.info.current_mtu, before.current_mtu);
        }
    }

    #[test]
    fn pmtud_mtu_verification_reverts_lossy_upward_change() {
        let mut p = state(true);
        p.info.current_mtu = 1024;
        p.start_probe(Seq(0), 1200, 3000, 1240);
        p.sent(Seq(0), Seq(1200), 1240, 20, false);
        p.ack(Seq(1200), 100, 1000, 1000);
        assert_eq!(p.info.current_mtu, 1240);
        for n in 1..=10 {
            let start = Seq(n * 1200);
            let end = start.wrapping_add(1200);
            p.sent(start, end, 1240, 20, false);
            if n <= 2 {
                p.sent(start, end, 1240, 20, true);
            }
        }
        p.ack(Seq(13_200), 2100, 1000, 1000);
        assert_eq!(p.info.current_mtu, 1024);
        assert_eq!(p.info.search_low, 1024);
        assert_eq!(p.info.search_high, 1239);
    }

    #[test]
    fn pmtud_deferred_ptb_hold_survives_probe_loss_and_progress() {
        for multiple in [false, true] {
            let mut p = state(true);
            p.sent(Seq(0), Seq(1460), 1500, 20, false);
            p.ack(Seq(1460), 10, 1000, 1000);
            p.start_probe(Seq(1460), 1200, 3000, 1240);
            p.sent(Seq(1460), Seq(2660), 1240, 20, false);
            p.sent(Seq(2660), Seq(3644), 1024, 20, false);
            assert!(p.feedback(20, Seq(2660), 1024, 20, 508));
            p.timeout(30, Seq(1460), 1, 1000);
            p.sent(Seq(1460), Seq(2444), 1024, 20, true);
            if multiple {
                p.sent(Seq(2660), Seq(3644), 1024, 20, true);
            }
            p.ack(Seq(5660), 40, 1000, 1000);
            assert_eq!(p.deadline, Some(600_000_020));
            assert!(p.pending.is_none());
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.3
    //= type=test
    //= reason=One-byte convergence schedules600s reset; link growth cannot increase eff without an ACK; before/at-deadline targets and bounded reset asserted.
    //# Each Packetization Layer MUST determine when probing has converged, that is, when
    //# the probe size range is small enough that further probing is no longer worth its
    //# cost. When probing has converged, a timer SHOULD be set. When the timer expires,
    //# search_high should be reset to its initial value (described above) so that probing
    //# can resume. Thus, if the path changes, increasing the Path MTU, then the flow will
    //# eventually take advantage of it. The value for this timer MUST NOT be less than 5
    //# minutes and is recommended to be 10 minutes, per RFC 1981.

    //= https://www.rfc-editor.org/rfc/rfc4821#section-2
    //= type=test
    //= reason=Bound updates are implemented in ack(): explicit success raises low, isolated failure lowers high, and low>=high stops search and schedules reset. The convergence test exercises stop/reset; failure-side executable evidence is separately linked at 140. No single combined trace is required by this overview.
    //# PLPMTUD uses a searching technique to find the Path MTU. Each conclusive probe
    //# narrows the MTU search range, either by raising the lower limit on a successful
    //# probe or lowering the upper limit on a failed probe, converging toward the true
    //# Path MTU. For most transport layers, the search should be stopped once the range
    //# is narrow enough that the benefit of a larger effective Path MTU is smaller than
    //# the search overhead of finding it.

    fn pmtud_convergence_hold_and_link_growth_require_ack_proof() {
        let mut p = state(true);
        p.info.search_low = 1500;
        p.ack(Seq(1), 100, 1000, 1000);
        assert_eq!(p.next_deadline(), Some(600_000_100));
        p.link(9000, 2000, 101);
        assert_eq!(p.info.current_mtu, 1500);
        p.tick(600_000_099);
        assert_eq!(p.target(), None);
        p.tick(600_000_100);
        assert_eq!(p.target(), Some(1750));
        assert_eq!(p.info.current_mtu, 1500);
        p.start_probe(Seq(1), 1710, 3000, 1750);
        p.sent(Seq(1), Seq(1711), 1750, 20, false);
        p.ack(Seq(1711), 600_000_200, 1000, 1000);
        assert_eq!(p.info.current_mtu, 1750);
    }
}

#[cfg(test)]
#[path = "pmtud_route_tests.rs"]
mod route_tests;
