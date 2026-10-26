use crate::{Instant, Ipv4Plateaus, PmtudConfig, PmtudPolicy, seq::Seq};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathMtuInfo {
    pub first_hop_mtu: u32,
    pub route_mtu: Option<u32>,
    pub current_mtu: u32,
    pub search_low: u32,
    pub search_high: u32,
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
    retried: bool,
    loss_reported: bool,
    other_loss: bool,
    timeout: bool,
    repair_end: Seq,
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
    floor: u32,
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
    pending: Option<(Seq, u32)>,
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

fn covered(ack: Seq, end: Seq) -> bool {
    ack.distance_from(end) < 1 << 31
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

    pub fn new(config: PmtudConfig, bound: u32, ipv4: bool, hold: u64) -> Self {
        let (mtu, low, high) = config
            .initial_values(bound, ipv4)
            .expect("validated PMTUD bounds");
        Self {
            info: PathMtuInfo {
                first_hop_mtu: config.first_hop_mtu,
                route_mtu: config.route_mtu,
                current_mtu: mtu,
                search_low: low,
                search_high: high,
            },
            bound,
            floor: if ipv4 { 68 } else { 1280 },
            initial_low: low,
            hold,
            aging: config
                .policy
                .search_aging
                .ticks(hold / 600)
                .expect("validated PMTUD aging"),
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
            icmp_since_progress: false,
            max_sent: 0,
            max_acked: 0,
            sent: [None; 64],
            next: 0,
            verification: None,
        }
    }

    pub fn constrain(&mut self, bound: u32) {
        self.bound = bound;
        let bound = self.route_bound();
        self.initial_low =
            bound.min(
                self.low_limit
                    .unwrap_or(if self.floor == 68 { 1024 } else { 1280 }),
            );
        if self.info.current_mtu > bound {
            // A local limit decrease is not failure of the previously verified
            // larger size; its loss ratio cannot classify this smaller MTU.
            self.verification = None;
        }
        self.info.current_mtu = self.info.current_mtu.min(bound);
        self.info.search_low = self.info.search_low.min(bound);
        self.info.search_high = self.info.search_high.min(self.search_ceiling());
        if self.probe.is_some_and(|p| p.size > bound) {
            self.probe = None;
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

    pub fn start_probe(&mut self, start: Seq, payload: u32, trailing: u32, size: u32) {
        self.repair_range = Some((start, start.wrapping_add(payload)));
        self.outcome = None;
        self.probe = Some(Probe {
            start,
            end: start.wrapping_add(payload),
            trailing_end: start.wrapping_add(payload + trailing),
            size,
            retried: false,
            loss_reported: false,
            other_loss: false,
            timeout: false,
            repair_end: start,
        });
    }

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
        if self.outcome.is_some_and(|o| covered(ack, o.end)) {
            self.outcome.take()
        } else {
            None
        }
    }

    pub fn loss(&mut self, start: Seq, multiple: bool) {
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
            && covered(end, p.trailing_end)
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
                    if start != p.repair_end && covered(p.repair_end, start) {
                        p.other_loss = true;
                    }
                    if covered(end, p.repair_end) {
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

    // Core also checks tuple and the live SND.UNA <= SEG.SEQ < SND.NXT window.
    //= https://www.rfc-editor.org/rfc/rfc1191#section-3
    //= reason=Enabled IPv4 PMTUD: exact sent evidence, legal floor and strictly decreasing candidates; repeated/nondecreasing reports do not rearm. Security-selected deferred updates are tested separately from immediate initial discovery.
    //# When a host receives a Datagram Too Big message, it MUST reduce its estimate of the
    //# PMTU for the relevant path, based on the value of the Next-Hop MTU field in the
    //# message (see section 4). We do not specify the precise behavior of a host in this
    //# circumstance, since different applications may have different requirements, and
    //# since different implementation architectures may favor different strategies.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-3
    //= reason=Enabled IPv4 PMTUD: exact sent evidence, legal floor and strictly decreasing candidates; repeated/nondecreasing reports do not rearm. Security-selected deferred updates are tested separately from immediate initial discovery.
    //# We do require that after receiving a Datagram Too Big message, a host MUST attempt
    //# to avoid eliciting more such messages in the near future. The host may either reduce
    //# the size of the datagrams it is sending along the path, or cease setting the Don't
    //# Fragment bit in the headers of those datagrams. Clearly, the former strategy may
    //# continue to elicit Datagram Too Big messages for a while, but since each of these
    //# messages (and the dropped datagrams they respond to) consume Internet resources, the
    //# host MUST force the PMTU Discovery process to converge.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-3
    //= reason=Enabled IPv4 PMTUD: exact sent evidence, legal floor and strictly decreasing candidates; repeated/nondecreasing reports do not rearm. Security-selected deferred updates are tested separately from immediate initial discovery.
    //# A host MUST never reduce its estimate of the Path MTU below 68 octets.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-3
    //= reason=Enabled IPv4 PMTUD: exact sent evidence, legal floor and strictly decreasing candidates; repeated/nondecreasing reports do not rearm. Security-selected deferred updates are tested separately from immediate initial discovery.
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
    //= reason=Nondecreasing, stale and impossible exact-size quotes are rejected; decreasing accepted feedback alone reaches packetization refresh.
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
    //= reason=Selected policy clears pending when the quoted sequence is acknowledged; the security test exercises advancing partial ACK and proves a later timeout does not apply the report. Additional clearing on any other progress is a deliberate deviation, not literal algorithm equivalence.
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
    //= reason=Selected gate rejects candidate>=current_mtu or >=max_sent, and additionally requires a smaller value than the exact quoted sent size. The security wire test rejects equal and larger reports; stricter rejection is not a missing historical branch.
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
    //= reason=IPv4 feedback rejects equal/larger and impossible candidates; exact-quote tests show these do not raise the estimate. The hypothetical attack narrative is not a separate router round-trip or on-path-blocker obligation.
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
    //= reason=Pmtud::feedback rejects nondecreasing candidates. IPv6 base-header wire test from 819b8f2 supplies exact emitted-packet quotes with equal/larger MTUs (1500, 2000, UINT32_MAX), then repeats 1400/1500/2000 after an accepted 1400 decrease; estimates never increase, including wrapped sequence ranges. No native IPv6 socket or extension-header claim.
    //# A node must not increase its estimate of the Path MTU in response to the
    //# contents of a Packet Too Big message. A message purporting to announce an
    //# increase in the Path MTU might be a stale packet that has been floating around
    //# in the network, a false packet injected as part of a denial-of-service (DoS)
    //# attack, or the result of having multiple paths to the destination, each with a
    //# different PMTU.

    //= https://www.rfc-editor.org/rfc/rfc8201#section-6
    //= reason=The strictly-decreasing feedback guard prevents the described increase attack. IPv6 base-header wire test from 819b8f2 rejects equal/larger MTUs before and after a valid decrease, including wrap. The hypothetical router round-trip is not claimed as a separate implemented behavior; no native IPv6 socket or extension-header claim.
    //# In the second attack, the false message indicates a PMTU larger than reality. If
    //# believed, this could cause temporary blockage as the victim sends packets that
    //# will be dropped by some router. Within one round-trip time, the node would
    //# discover its mistake (receiving Packet Too Big messages from that router), but
    //# frequent repetition of this attack could cause lots of packets to be dropped. A
    //# node, however, must not raise its estimate of the PMTU based on a Packet Too Big
    //# message, so it should not be vulnerable to this attack.

    pub fn feedback(
        &mut self,
        now: Instant,
        seq: Seq,
        size: u32,
        header: u16,
        candidate: u32,
    ) -> bool {
        let ipv4 = self.floor == 68;
        if (ipv4 && (!(20..=60).contains(&header) || !header.is_multiple_of(4)))
            || (!ipv4 && header != 40)
            || size < u32::from(header) + 20
        {
            return false;
        }
        let known = self.sent.iter().flatten().find(|p| {
            p.start == seq
                && p.header == header
                && (p.size == size
                    || ipv4
                        && candidate == 0
                        && p.size.checked_add(u32::from(header)) == Some(size))
        });
        let Some(known) = known else {
            return false;
        };
        let sent_size = known.size;
        //= https://www.rfc-editor.org/rfc/rfc8201#section-4
        //# If a node receives a Packet Too Big message reporting a next-hop MTU
        //# that is less than the IPv6 minimum link MTU, it must discard it.
        if !ipv4 && candidate < 1280 {
            return false;
        }
        let mtu = if ipv4 && candidate == 0 {
            //= https://www.rfc-editor.org/rfc/rfc1191#section-5
            //# If the Total Length field returned is
            //# not less than the current PMTU estimate, it must be reduced by
            //# 4 times the value of the returned Header Length field.
            // header is in bytes already, not the IHL field's 32-bit words.
            let corrected = if size >= self.info.current_mtu {
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
            candidate.max(self.floor)
        };
        //= https://www.rfc-editor.org/rfc/rfc1191#section-3
        //# A host MUST not increase its estimate of the Path MTU in response to
        //# the contents of a Datagram Too Big message.
        //= https://www.rfc-editor.org/rfc/rfc8201#section-4
        //# A node must not increase its estimate of the Path MTU in response to
        //# the contents of a Packet Too Big message.
        if mtu >= self.info.current_mtu || mtu >= sent_size || mtu >= self.max_sent {
            return false;
        }
        //= https://www.rfc-editor.org/rfc/rfc5927#section-7.2
        //= reason=Informational mitigation selected as policy, not a TCP MUST. Exact bounded packet evidence strengthens the live-sequence gate; any cumulative progress clears a pending report.
        //# A
        //# MAXSEGRTO of 1 provides enough protection for most cases.
        // RFC5927 policy: defer a decrease below previously proven delivery,
        // until the quoted data times out; any cumulative progress clears it.
        if mtu < self.max_acked {
            // Even deferred validated PTB feedback inhibits new upward probes.
            self.delay(now, self.hold);
            self.periodic_deadline = None;
            self.reset_search = true;
            self.pending = Some((
                seq,
                self.pending
                    .filter(|(old_seq, _)| *old_seq == seq)
                    .map_or(mtu, |(_, old)| old.min(mtu)),
            ));
        } else {
            self.apply_ptb(mtu, now);
        }
        true
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

    fn apply_ptb(&mut self, mtu: u32, now: Instant) {
        self.icmp_since_progress = true;
        self.info.current_mtu = mtu.min(self.info.current_mtu);
        self.record_upper_limit(mtu);
        self.info.search_low = self.info.search_low.min(mtu);
        // Cancel classification, not the outstanding data's repair boundary.
        self.probe = None;
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
    //= reason=Partial no-PTB evidence from 76800de plus a4b9a0c: provisional normal repair admission and PRR remain active; only finite preloss extended-tail cumulative proof followed by recovery/PRR exit suppresses the logical loss response. Real receiver NewReno/SACK/RACK, PRR, Reno/CUBIC and pacing matrices assert isolated suppression and normal response on other loss; disqualifiers cover ECE, RTO and ordinary loss. Replenishment retains nonempty flight and resumes ACK growth. Independent MSS decrease scaling remains, not literal unchanged-cwnd advice. Pmtud::ack narrows search_high to probe size minus one after the finite proof. Partial gap: RFC4821 sections 2, 4 and 7.6.2 cover isolated loss with or without matching PTB. apply_ptb cancels probe classification; resolve_probe_response commits normal congestion response even when only the probe is lost and trailing packets are delivered, as asserted by the IPv6 two-PTB fixture. No-PTB evidence does not close this full span.
    //# When only the probe is lost, it is treated as an indication that the Path MTU is
    //# smaller than the probe size. In this case alone, the loss SHOULD NOT be
    //# interpreted as congestion signal.

    pub fn ack(&mut self, ack: Seq, now: Instant, cooldown: u64, rto: u64) {
        if self.repair_range.is_some_and(|(_, end)| covered(ack, end)) {
            self.repair_range = None;
        }
        self.pending = None;
        self.icmp_since_progress = false;
        for entry in &mut self.sent {
            if let Some(packet) = entry
                && covered(ack, packet.end)
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
            if !p.retried && !p.timeout && covered(ack, p.end) {
                //= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.1
                //# Set search_low to the probe
                //# size.  If the probe size is larger than the eff_pmtu, raise eff_pmtu
                //# to the probe size.
                self.info.search_low = self.info.search_low.max(p.size);
                if p.size > self.info.current_mtu {
                    // Active search can make several increases before verification
                    // finishes. Keep the last verified baseline and all evidence,
                    // but observe each new size for another two RTO intervals.
                    self.verification
                        .get_or_insert((self.info.current_mtu, now, 0, 0))
                        .1 = now;
                    self.info.current_mtu = p.size;
                }
                self.probe = None;
            } else if covered(ack, p.trailing_end) {
                self.outcome = Some(ProbeOutcome {
                    start: p.start,
                    end: p.trailing_end,
                    isolated: p.retried && !p.other_loss && !p.timeout,
                });
                if p.retried && !p.other_loss {
                    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.2
                    //= reason=Wait for cumulative delivery of the trailing window and exclude every observed nearby retransmission. This bound update is independent of the one-shot congestion outcome.
                    //# In the absence of other indications, set search_high to the probe
                    //# size minus one.
                    self.record_upper_limit(p.size - 1);
                    self.info.search_low = self.info.search_low.min(self.info.search_high);
                    if self.info.current_mtu >= p.size {
                        self.info.current_mtu = self.info.search_low;
                    }
                    self.delay(now, cooldown.saturating_mul(if p.timeout { 5 } else { 1 }));
                } else if p.other_loss && !p.timeout && !self.reset_search {
                    self.deadline = None;
                }
                // Multiple/nearby losses are inconclusive; retain search bounds.
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
    //= reason=Reviewed IPv6 lost_probe_repairs wire fixture and 76800de: actual receiver repairs are split within the probe gap and conservative packet budget, including two successively smaller router PTBs down to1280 and wrapping sequences. Normal repair admission remains active; isolated proof retains only MSS-scaled logical cwnd, while PTB cancellation commits normal congestion response. Both PTB repair-boundary tests assert the committed threshold; no unchanged-cwnd or shared-path fanout claim.
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

    pub fn timeout(&mut self, now: Instant, head: Seq, consecutive: u32, cooldown: u64) {
        if let Some((seq, mtu)) = self.pending.take() {
            // Only the quoted data's timeout authorizes a deferred decrease.
            if head == seq {
                self.apply_ptb(mtu, now);
            } else {
                self.pending = Some((seq, mtu));
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
            let floor = self.floor.min(self.initial_low).min(ceiling);
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
        Pmtud::new(PmtudConfig::new(1500), 1500, ipv4, 600_000_000)
    }

    #[test]
    fn ptb_cancelled_probe_retains_only_repair_boundary() {
        for start in [Seq(1), Seq(u32::MAX - 499)] {
            let mut p = state(false);
            let end = start.wrapping_add(1330);
            p.start_probe(start, 1330, 3660, 1390);
            p.sent(start, end, 1390, 40, false);
            assert!(p.feedback(10, start, 1390, 40, 1389));
            assert!(p.feedback(11, start, 1390, 40, 1280));
            let info = p.info;
            let deadline = p.deadline;
            assert!(p.probe.is_none());
            assert!(!p.feedback(12, start, 1390, 40, 1280));
            assert!(!p.feedback(13, start, 1390, 40, 1389));
            assert_eq!(p.deadline, deadline);
            assert_eq!(p.repair_limit(start, 1220), 1220);
            let partial = start.wrapping_add(1220);
            p.sent(start, partial, 1280, 40, true);
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
            assert!(p.probe.is_none());
            assert!(p.verification.is_none());
            assert_eq!(p.info.current_mtu, 1280);
            assert_eq!(p.info.search_low, 1280);
            assert_eq!(p.info.search_high, 1500); // no cancelled-probe loss result
            let next_size = p.target().unwrap();
            p.start_probe(end, next_size - 60, 3660, next_size);
            assert_eq!(p.repair_limit(end, 2000), next_size - 60);
            let next_end = end.wrapping_add(next_size - 60);
            p.sent(end, next_end, next_size, 40, false);
            p.ack(next_end, deadline.unwrap() + 2, 1000, 1000);
            assert_eq!(p.info.current_mtu, next_size); // fresh probe still classifies
            assert!(p.repair_range.is_none());
            assert!(!p.feedback(deadline.unwrap() + 3, start, 1390, 40, 1280)); // stale quote
            p.start_probe(next_end, 1330, 3660, 1390);
            p.apply_ptb(1280, deadline.unwrap() + 3);
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
            assert!(!p.feedback(2, Seq(10), 1500, 20, 1499));
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
            if multiple {
                assert_eq!(p.info, before);
                assert_eq!(p.deadline, Some(5100)); // timeout retains its fivefold hold
            } else {
                assert_eq!(p.info.search_high, 1239);
                assert_eq!(p.deadline, Some(5120));
                p.tick(5120);
                assert_eq!(p.info.search_high, 1239);
                assert!(p.target().unwrap() < 1240);
            }
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
mod route_tests {
    include!("pmtud_route_tests.rs");
}
