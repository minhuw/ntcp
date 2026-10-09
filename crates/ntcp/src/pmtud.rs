use crate::{Instant, seq::Seq};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PmtudConfig {
    pub first_hop_mtu: u32,
}
impl PmtudConfig {
    pub const fn new(first_hop_mtu: u32) -> Self {
        Self { first_hop_mtu }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathMtuInfo {
    pub first_hop_mtu: u32,
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
    other_loss: bool,
    timeout: bool,
}

#[derive(Debug)]
pub(crate) struct Pmtud {
    pub info: PathMtuInfo,
    pub bound: u32,
    floor: u32,
    initial_low: u32,
    hold: u64,
    pub deadline: Option<Instant>,
    reset_search: bool,
    pub probe: Option<Probe>,
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
    //= reason=Pmtud::new initializes search_low to min(bound,1024) for IPv4 or min(bound,1280) for IPv6. The full-stop test checks both family starting lows through the first fallback; independent configurability remains TODO at 113.
    //# For initial conditions when there is no information about the path, eff_pmtu may
    //# be greater than search_low. The initial value of search_low SHOULD be
    //# conservatively low, but performance may be better if eff_pmtu starts at a higher,
    //# less conservative, value. See Section 7.2.

    pub fn new(config: PmtudConfig, bound: u32, ipv4: bool, hold: u64) -> Self {
        let low = bound.min(if ipv4 { 1024 } else { 1280 });
        Self {
            info: PathMtuInfo {
                first_hop_mtu: config.first_hop_mtu,
                current_mtu: bound,
                search_low: low,
                search_high: bound,
            },
            bound,
            floor: if ipv4 { 68 } else { 1280 },
            initial_low: low,
            hold,
            deadline: None,
            reset_search: false,
            probe: None,
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
        self.initial_low = bound.min(if self.floor == 68 { 1024 } else { 1280 });
        self.info.current_mtu = self.info.current_mtu.min(bound);
        self.info.search_low = self.info.search_low.min(bound);
        self.info.search_high = self.info.search_high.min(bound);
        if self.probe.is_some_and(|p| p.size > bound) {
            self.probe = None;
        }
    }

    pub fn link(&mut self, mtu: u32, bound: u32, now: Instant) {
        self.info.first_hop_mtu = mtu;
        self.constrain(bound);
        // A local link increase is a new search bound, not proof about the path.
        if self.info.search_high < bound && self.deadline.is_none() {
            self.deadline = Some(now.saturating_add(self.hold));
            self.reset_search = true;
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

    pub fn tick(&mut self, now: Instant) {
        if self.deadline.is_some_and(|d| d <= now) {
            self.deadline = None;
            if self.reset_search {
                self.info.search_high = self.bound;
            }
            self.reset_search = false;
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.1
    //= reason=Binary target is strictly above search_low and <=search_high; actual IP probe size checked for IPv4/IPv6 and constrained by peer/allocation ceilings.
    //# When transmitting probes, the Packetization Layer MUST select a probe size that is
    //# larger than search_low and smaller than or equal to search_high.

    pub fn target(&self) -> Option<u32> {
        if self.deadline.is_some()
            || self.probe.is_some()
            || self.info.search_low >= self.info.search_high
        {
            return None;
        }
        Some(self.info.search_low + (self.info.search_high - self.info.search_low).div_ceil(2))
    }

    pub fn start_probe(&mut self, start: Seq, payload: u32, trailing: u32, size: u32) {
        self.probe = Some(Probe {
            start,
            end: start.wrapping_add(payload),
            trailing_end: start.wrapping_add(payload + trailing),
            size,
            retried: false,
            other_loss: false,
            timeout: false,
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

    pub fn loss(&mut self, start: Seq, multiple: bool) {
        if let Some(p) = &mut self.probe
            && (multiple || start.in_window(p.start, p.end.distance_from(p.start)) != Some(true))
        {
            p.other_loss = true;
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc5927#section-7.4
    //= reason=Selected max-sent update is implemented exactly as max_sent.max(size) in sent(). Exact-evidence tests send real sizes and exercise acceptance/rejection against their recorded upper bound; initialization/reset choices are separate clauses.
    //# if (packet_size > maxsizesent) maxsizesent = packet_size;

    pub fn sent(&mut self, start: Seq, end: Seq, size: u32, header: u16, retry: bool) {
        self.max_sent = self.max_sent.max(size);
        if let Some(p) = &mut self.probe
            && !retry
            && covered(end, p.trailing_end)
        {
            // Three queued segments are only a minimum: all subsequently sent
            // flight must resolve before a failed probe can be called isolated.
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
                }
                if !covered(start, p.start) || !covered(p.end, end) {
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
            [
                65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68,
            ]
            .into_iter()
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
            self.deadline = Some(now.saturating_add(self.hold));
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
        self.info.search_high = self.info.search_high.min(mtu);
        self.info.search_low = self.info.search_low.min(mtu);
        self.probe = None;
        self.verification = None;
        self.deadline = Some(now.saturating_add(self.hold));
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

    pub fn ack(&mut self, ack: Seq, now: Instant, cooldown: u64, rto: u64) {
        self.pending = None;
        self.icmp_since_progress = false;
        for entry in &mut self.sent {
            if let Some(packet) = entry
                && covered(ack, packet.end)
            {
                if !packet.ambiguous {
                    self.max_acked = self.max_acked.max(packet.size);
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
                self.info.search_low = p.size;
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
                if p.retried && !p.other_loss {
                    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.2
                    //= reason=Wait for cumulative delivery of the trailing window and exclude every observed nearby retransmission. Congestion reduction is conservatively retained, never prematurely waived.
                    //# In the absence of other indications, set search_high to the probe
                    //# size minus one.
                    self.info.search_high = self.info.search_high.min(p.size - 1);
                    self.info.search_low = self.info.search_low.min(self.info.search_high);
                    if self.info.current_mtu >= p.size {
                        self.info.current_mtu = self.info.search_low;
                    }
                    self.delay(now, cooldown.saturating_mul(if p.timeout { 5 } else { 1 }));
                } else if p.other_loss && !self.reset_search {
                    self.deadline = None;
                }
                // Multiple/nearby losses are inconclusive; retain search bounds.
                // Congestion control is never waived, including isolated losses.
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
                self.info.search_high = self.info.search_high.min(self.info.current_mtu - 1);
                self.info.current_mtu = previous.min(self.bound);
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
        if self.info.search_low >= self.info.search_high && self.deadline.is_none() {
            self.deadline = Some(now.saturating_add(self.hold));
            self.reset_search = true;
        }
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
            let floor = self.floor.min(self.bound);
            let low = if consecutive == 3 {
                if self.info.current_mtu > self.info.search_low {
                    self.info.search_low
                } else {
                    self.initial_low.min(self.info.current_mtu)
                }
            } else {
                self.info.current_mtu / 2
            }
            .max(floor);
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
                assert_eq!(p.deadline, None); // recovery alone gates retry
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
        assert_eq!(p.deadline, Some(600_000_100));
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
