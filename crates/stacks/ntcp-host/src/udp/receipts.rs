//! Probe-outcome reporting for Host UDP flows (RFC 4821 section 9: an
//! application implementing PLPMTUD informs the stack about each probe's
//! outcome as described in section 7.6).
//!
//! Receipts. A definite Probe-mode submission yields exactly one opaque
//! `ProbeReceipt`, bound to state the Host retains: the Host instance, the
//! flow slot and generation, the path incarnation and key, its negative and
//! discovery-policy revisions, the exact size and the submission time. The
//! capacity is reserved before the submission (`UdpLimits::probe_receipts`
//! per flow); an uncertain or failed submission issues none. A receipt is
//! usable until the Host's feedback horizon (twice the configured MSL) after
//! its submission: the probe and any answer to it are gone from the network
//! by then, so a later report cannot describe that probe, and the same
//! horizon already bounds ICMP correlation of the submission. Expired and
//! stale receipts (the flow sends on another path incarnation, or a
//! decrease or discovery-policy change followed the submission) are
//! reclaimed when the flow next reserves one, so unreported receipts never
//! exhaust a flow.
//!
//! Outcomes. `Host::udp_report_probe` consumes a valid receipt exactly once
//! and changes only that flow's own bounds for the path (RFC 4821 section
//! 7.6): Success raises its confirmed size (search_low and eff_pmtu);
//! IsolatedLoss sets its upper bound (search_high) to the probe size minus
//! one, never below the family minimum; TimeoutFailure infers no isolation
//! (the application owns its congestion response and recovery) and
//! suppresses the flow's Probe-mode sends at or above that size until the
//! failed probe's receipt would have expired (section 7.6.3 asks for a
//! longer interval after a timeout failure; without a round-trip sample for
//! the flow the Host's only bound on that failure's network consequences is
//! the feedback horizon); Inconclusive preserves every bound and permits a
//! same-sized retry (section 7.6.2). The bounds size the flow's fragments
//! and are reported by `udp_datagram_limits`. Silence and losses never
//! lower shared state: shared decreases come only from correlated PTBs and
//! administrative restrictions.
//!
//! Shared publication (RFC 4821 section 11: an untrusted packetization
//! protocol should not write shared state). Only a Success reported with
//! the flow's owner-granted `UdpSharedWriter` is additionally offered to
//! `PathService::confirm_delivery_as` under its incarnation, negative
//! revision, hold and first-hop rules, recorded as owner-trusted
//! application evidence. The local effect and the shared attempt are
//! reported separately: an invalid receipt or capability changes nothing;
//! a valid one always applies its local effect, and a shared refusal never
//! undoes it.

use super::{Flow, Udp, UdpFlowId};
use crate::{Administration, Error, Host};
use ntcp::Instant;
use ntcp_path::{DeliveryConfirmation, DeliveryEvidence, PathId, PathKey, PathSnapshot};

/// What one flow's application learned from its own probes on one path
/// incarnation (complete IP octets).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UdpProbeBounds {
    /// The path incarnation the bounds describe; None before any outcome.
    pub path: Option<PathId>,
    /// Largest successfully probed size (search_low).
    pub confirmed: Option<u32>,
    /// Upper bound after an isolated probe loss (search_high).
    pub upper: Option<u32>,
    /// Retry suppression after a timeout failure.
    pub suppressed: Option<RetrySuppression>,
}

/// Probe-mode sends at or above `size` are refused before `until`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetrySuppression {
    pub size: u32,
    pub until: Instant,
}

impl UdpProbeBounds {
    /// The bounds when they describe `path`, otherwise none.
    pub(crate) fn on(self, path: PathId) -> Self {
        if self.path == Some(path) {
            self
        } else {
            Self::default()
        }
    }
}

/// RFC 4821 section 7.6 result categories an application reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpProbeOutcome {
    /// The probe was delivered (section 7.6.1).
    Success,
    /// Only the probe was lost, without a timeout (section 7.6.2).
    IsolatedLoss,
    /// The probe was lost and detected by a timeout (section 7.6.3).
    TimeoutFailure,
    /// Other losses near the probe: no size information (section 7.6.2).
    Inconclusive,
}

/// Opaque, single-use handle for one definite Probe-mode submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeReceipt {
    instance: u64,
    flow: UdpFlowId,
    index: usize,
    // Crate-visible so Host tests can present altered copies.
    pub(crate) serial: u64,
    path: PathId,
    pub(crate) size: u32,
    // Crate-visible so Host tests can check the expiry policy.
    pub(crate) expires_at: Instant,
}

impl ProbeReceipt {
    /// Complete IP octets of the probe.
    pub const fn size(&self) -> u32 {
        self.size
    }
}

/// Owner-granted capability letting one flow generation's successful probe
/// reports be offered to the shared path estimate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpSharedWriter {
    instance: u64,
    flow: UdpFlowId,
    serial: u64,
}

/// The shared half of a report, separate from the flow's local effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedOffer {
    /// Not a Success, or reported without the shared-writer capability.
    NotOffered,
    /// `confirm_delivery`'s disposition; only Raised changed shared state,
    /// with provenance owner-trusted application evidence.
    Offered(DeliveryConfirmation),
    /// The path service refused it (the path incarnation is no longer
    /// valid); nothing shared changed.
    Refused(ntcp_path::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpProbeReport {
    /// The flow's bounds after the outcome.
    pub bounds: UdpProbeBounds,
    pub shared: SharedOffer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeReportError {
    /// Not a receipt this Host issued to this flow generation, or altered.
    Foreign,
    /// Already reported, or reclaimed once it became unusable.
    Consumed,
    /// Reported at or after its expiry; reclaimed.
    Expired,
    /// The flow no longer sends on the probe's path incarnation; reclaimed.
    PathChanged,
    /// A decrease or discovery-policy change followed the submission;
    /// reclaimed.
    StaleRevision,
    /// The presented shared-writer capability is not this flow's grant;
    /// nothing changed and the receipt stays usable.
    Unauthorized,
    Host(Error),
}
impl From<Error> for ProbeReportError {
    fn from(error: Error) -> Self {
        Self::Host(error)
    }
}

/// Host-retained state of one issued receipt.
#[derive(Clone, Copy)]
pub(super) struct Receipt {
    serial: u64,
    path: PathId,
    key: PathKey,
    negative_revision: u64,
    discovery_revision: u64,
    size: u32,
    submitted_at: Instant,
    expires_at: Instant,
}

impl Receipt {
    // Whether a report could still be accepted against `live`, the flow's
    // current path at `now`.
    fn usable(&self, now: Instant, live: PathSnapshot) -> bool {
        now < self.expires_at
            && live.path() == self.path
            && live.key() == self.key
            && live.negative_revision() == self.negative_revision
            && live.discovery_revision() == self.discovery_revision
    }
}

impl Udp {
    fn receipt_range(&self, slot: usize) -> core::ops::Range<usize> {
        let depth = self.limits.probe_receipts;
        slot * depth..(slot + 1) * depth
    }
    pub(super) fn clear_receipts(&mut self, slot: usize) {
        let range = self.receipt_range(slot);
        self.receipts[range].fill(None);
    }
}

impl Host {
    /// The flow's connectionless effective size on `snapshot`'s path under
    /// its probe bounds: min(shared ordinary budget, upper bound,
    /// max(connectionless initial, adjunct-confirmed, flow-confirmed)).
    pub(super) fn flow_size(
        &self,
        snapshot: PathSnapshot,
        bounds: UdpProbeBounds,
    ) -> Result<u32, Error> {
        let shared = self.connectionless_size(snapshot)?;
        let budget = snapshot.ip_packet_budget()?;
        let raised = bounds
            .confirmed
            .map_or(shared, |c| shared.max(c.min(budget)));
        Ok(bounds.upper.map_or(raised, |u| raised.min(u)))
    }

    /// One flow's usable datagram size on `snapshot`'s path (administration
    /// reporting).
    pub(crate) fn udp_flow_size(
        &self,
        id: UdpFlowId,
        snapshot: PathSnapshot,
    ) -> Result<u32, Error> {
        let flow = self.udp.flow(id)?;
        self.flow_size(snapshot, flow.bounds.on(snapshot.path()))
    }

    // Reserve one receipt entry for a Probe-mode submission on `live`,
    // reclaiming the flow's expired and stale ones first.
    pub(super) fn reserve_receipt(
        &mut self,
        id: UdpFlowId,
        now: Instant,
        live: PathSnapshot,
    ) -> Result<usize, crate::DatagramError> {
        self.udp
            .receipt_serial
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        let range = self.udp.receipt_range(id.slot);
        let mut free = None;
        for index in range {
            let entry = &mut self.udp.receipts[index];
            if entry.is_some_and(|r| !r.usable(now, live)) {
                *entry = None;
            }
            if entry.is_none() && free.is_none() {
                free = Some(index);
            }
        }
        free.ok_or(crate::DatagramError::ReceiptsExhausted)
    }

    // Record the definite submission in the reserved entry.
    pub(super) fn issue_receipt(
        &mut self,
        id: UdpFlowId,
        index: usize,
        snapshot: PathSnapshot,
        size: u32,
        now: Instant,
    ) -> ProbeReceipt {
        // Checked when the entry was reserved, within the same call.
        self.udp.receipt_serial += 1;
        let serial = self.udp.receipt_serial;
        let expires_at = now.saturating_add(self.ledger.feedback_horizon());
        self.udp.receipts[index] = Some(Receipt {
            serial,
            path: snapshot.path(),
            key: snapshot.key(),
            negative_revision: snapshot.negative_revision(),
            discovery_revision: snapshot.discovery_revision(),
            size,
            submitted_at: now,
            expires_at,
        });
        ProbeReceipt {
            instance: self.instance,
            flow: id,
            index,
            serial,
            path: snapshot.path(),
            size,
            expires_at,
        }
    }

    /// Owner entrypoint: let flow `id` (this generation only) offer its
    /// successful probe reports to the shared path estimate. Replaces any
    /// earlier grant to the flow.
    pub fn udp_grant_shared_writer(
        &mut self,
        capability: &Administration,
        id: UdpFlowId,
    ) -> Result<UdpSharedWriter, Error> {
        self.authorize(capability)?;
        self.udp.flow(id)?;
        let serial = self
            .udp
            .writer_serial
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        self.udp.writer_serial = serial;
        self.udp.slots[id.slot].flow.as_mut().unwrap().writer = Some(serial);
        Ok(UdpSharedWriter {
            instance: self.instance,
            flow: id,
            serial,
        })
    }

    /// Owner entrypoint: withdraw the flow's shared-writer grant; every
    /// capability issued for it stops working.
    pub fn udp_revoke_shared_writer(
        &mut self,
        capability: &Administration,
        id: UdpFlowId,
    ) -> Result<(), Error> {
        self.authorize(capability)?;
        self.udp.flow(id)?;
        self.udp.slots[id.slot].flow.as_mut().unwrap().writer = None;
        Ok(())
    }

    /// Report the outcome of the probe `receipt` names (RFC 4821 sections 7.6
    /// and 9), consuming it. Everything is checked before anything changes:
    /// the receipt must have been issued by this Host to this live flow
    /// generation, unaltered and unreported, before its expiry, while the
    /// flow still sends on the probe's path incarnation under the negative
    /// and discovery-policy revisions it was sized against; `writer`, when
    /// presented, must be the flow's current grant. The outcome then
    /// changes only this flow's bounds; a Success with `writer` is also
    /// offered to the shared estimate, reported separately in `shared`.
    //= https://www.rfc-editor.org/rfc/rfc4821#section-2
    //= reason=PathService is the IP-layer path information cache shared by the Host's packetization protocols. TCP runs its own PLPMTUD, reads the cache through Host::service_changes budget application and updates it with correlated PTBs and with probe-confirmed sizes (a definitely submitted, unfragmented probe selected after the hold whose span the peer acknowledged, published through PathService::confirm_delivery). A correlated TCP report about the connection's current path at or above its proven delivery lowers the cache at once when lower and otherwise restarts its hold; one below proven delivery is deferred whatever the connection's loss-inferred estimate and changes nothing shared until that exact report's quoted-data timeout applies it, when the larger of the Host estimate and the report's own policy-derived size is published; cumulative progress past the quoted data refutes it. The report's derived size never depends on the connection's estimate: a legacy IPv4 report without a Next-Hop MTU is corrected against the Host's shared path estimate, RFC 1191 section 5's current PMTU estimate, never the connection's estimate. Loss-inferred decreases stay connection-local. Host UDP flows read MMS_S and the payload limit (Host::udp_path_limits, Host::udp_path_change), and their source fragments are sized from the shared ordinary budget; they lower the cache only through correlated PTBs quoting their datagrams or fragments. The Host-owned ICMP Echo adjunct is a Host-trusted writer: the forward delivery an exact, timely Echo Reply certifies for a definitely submitted, unfragmented probe is offered to PathService::confirm_delivery under its revision, hold and first-hop rules (4821-183). T13's Probe mode (Host::udp_send_datagram with UdpSendMode::Probe) lets a datagram application send its own probes above the estimate up to the first-hop MTU, unfragmented with IPv4 DF; a probe submission writes nothing shared. Host::udp_report_probe takes the application's outcome for each definitely submitted probe (4821-160): an ordinary flow's report changes only its own search state, whose bounds size that flow's fragments, and an application updates the shared cache only with authority granted by the Host owner (4821-195): a Success reported with the owner-granted, flow-scoped UdpSharedWriter is offered to PathService::confirm_delivery_as under the same revision, hold and first-hop rules and recorded as owner-trusted application evidence. The integration/rfc_host probe-report case reports outcomes observed by a real receiver (4821-160). Each packetization protocol therefore has its own PLPMTUD and the means to access and update the shared cache: TCP directly, a datagram application through Host UDP Probe mode and Host::udp_report_probe (shared writes only with the owner's grant) and the Host's IP fragmentation through its Echo adjunct; dual-family Host tests in crates/stacks/ntcp-host/src/tests/probe_receipts.rs show an ordinary flow's report changing only its own bounds and an owner-granted Success reaching PathService with its separately reported result.
    //# Most of the difficulty in implementing PLPMTUD arises because it needs to be implemented in several different places within a single node. In general, each Packetization Protocol needs to have its own implementation of PLPMTUD. Furthermore, the natural mechanism to share Path MTU information between concurrent or subsequent connections is a path information cache in the IP layer. The various Packetization Protocols need to have the means to access and update the shared cache in the IP layer. This memo describes PLPMTUD in terms of its primary subsystems without fully describing how they are assembled into a complete implementation.
    //= https://www.rfc-editor.org/rfc/rfc4821#section-9
    //= reason=Host::udp_report_probe (crates/stacks/ntcp-host/src/udp/receipts.rs) lets an application inform the Host of the outcome of each probe it sent with T13's Probe mode (Host::udp_send_datagram with UdpSendMode::Probe, 4821-158) in the Section 7.6 categories Success, IsolatedLoss, TimeoutFailure and Inconclusive. Receipt capacity (UdpLimits::probe_receipts: the per-flow outstanding-receipt limit, configured once in the Host's UDP configuration under which every flow is opened, without a per-flow override) is reserved before a Probe-mode submission, which is refused with ReceiptsExhausted when none is free; a definite submission yields exactly one opaque single-use ProbeReceipt in its ProbeRecord, bound to Host-retained state (Host instance, flow slot and generation, path incarnation and key, negative and discovery-policy revisions, exact size, submission time), and an uncertain one yields none. A receipt expires at the Host's feedback horizon after submission (twice the configured MSL: the probe and any answer to it are gone from the network by then, the same bound as ICMP correlation), and expired or stale receipts are reclaimed when the flow reserves one, so unreported receipts never exhaust a flow. Replayed, foreign-Host, foreign-flow, replaced-flow, altered, expired, rebound-path and stale-revision (a later decrease or discovery-policy change) reports are rejected. An outcome changes only the reporting flow's own bounds for that path incarnation: Success raises its confirmed size (search_low, eff_pmtu), IsolatedLoss sets its upper bound (search_high) to the probe size minus one (never below the family minimum) and lowers its effective size to it, TimeoutFailure infers no isolation and suppresses that flow's Probe-mode sends at or above the failed size until the failed probe's receipt would have expired, and Inconclusive preserves every bound and permits a same-sized retry. The bounds size that flow's Fragment-mode fragments, min(shared budget, upper bound, max(connectionless initial, adjunct-confirmed, flow-confirmed)), and Host::udp_datagram_limits reports them; Refuse keeps shared-budget admission, and silence and losses never lower shared state. A write to the shared PathService cache requires authority granted by the Host owner (4821-195): only a Success reported with the flow-scoped UdpSharedWriter the owner grants through Host::udp_grant_shared_writer is additionally offered to PathService::confirm_delivery_as under its incarnation, negative-revision, hold and first-hop rules and recorded as owner-trusted application evidence, reported separately from the local effect. Dual-family Host tests (crates/stacks/ntcp-host/src/tests/probe_receipts.rs) cover receipt capacity, expiry, reclamation and every rejection, each outcome's flow-only effect on sizing and reported limits, and owner-authorized publication with its separate result. The integration/rfc_host probe-report case (both families) reports outcomes the application learned from a real Linux receiver: a delivered probe's Success raises only that flow's confirmed size, which then cuts its fragments on the wire, with no shared change; a replayed receipt is refused as Consumed; and a probe a router dropped with a PTB is refused as StaleRevision because the PTB's shared decrease followed the submission.
    //# Implementing PLPMTUD in an application also requires a mechanism where the application can inform the operating system about the outcome of the probe as described in Section 7.6, or directly update search_low, search_high, and eff_pmtu, described in Section 7.1.
    pub fn udp_report_probe(
        &mut self,
        now: Instant,
        id: UdpFlowId,
        receipt: ProbeReceipt,
        outcome: UdpProbeOutcome,
        writer: Option<&UdpSharedWriter>,
    ) -> Result<UdpProbeReport, ProbeReportError> {
        let flow: Flow = self.udp.flow(id)?;
        if receipt.instance != self.instance
            || receipt.flow != id
            || !self.udp.receipt_range(id.slot).contains(&receipt.index)
        {
            return Err(ProbeReportError::Foreign);
        }
        let Some(retained) =
            self.udp.receipts[receipt.index].filter(|r| r.serial == receipt.serial)
        else {
            return Err(ProbeReportError::Consumed);
        };
        if retained.path != receipt.path
            || retained.size != receipt.size
            || retained.expires_at != receipt.expires_at
        {
            return Err(ProbeReportError::Foreign);
        }
        if writer.is_some_and(|w| {
            w.instance != self.instance || w.flow != id || flow.writer != Some(w.serial)
        }) {
            return Err(ProbeReportError::Unauthorized);
        }
        let live = self.paths.path_snapshot(retained.path).ok();
        let bound = flow
            .path
            .is_some_and(|p| p.snapshot.path() == retained.path)
            && live.is_some_and(|l| l.status() == ntcp_path::PathStatus::Valid);
        let rejection = if now >= retained.expires_at {
            Some(ProbeReportError::Expired)
        } else if !bound || live.is_none_or(|l| l.key() != retained.key) {
            Some(ProbeReportError::PathChanged)
        } else if live.is_none_or(|l| !retained.usable(now, l)) {
            Some(ProbeReportError::StaleRevision)
        } else {
            None
        };
        // Consumed exactly once; an unusable receipt is reclaimed.
        self.udp.receipts[receipt.index] = None;
        if let Some(rejection) = rejection {
            return Err(rejection);
        }
        self.now = self.now.max(now);
        let ipv4 = retained.key.destination().address().is_ipv4();
        let floor = if ipv4 { 68 } else { 1280 };
        let size = retained.size;
        let mut bounds = flow.bounds.on(retained.path);
        bounds.path = Some(retained.path);
        match outcome {
            UdpProbeOutcome::Success => {
                bounds.confirmed = Some(bounds.confirmed.map_or(size, |c| c.max(size)));
                // Newer delivery evidence supersedes a smaller upper bound
                // and any suppression at or below the delivered size.
                bounds.upper = bounds.upper.filter(|&u| u >= size);
                bounds.suppressed = bounds.suppressed.filter(|s| s.size > size);
            }
            UdpProbeOutcome::IsolatedLoss => {
                let upper = (size - 1).max(floor);
                let upper = bounds.upper.map_or(upper, |u| u.min(upper));
                bounds.upper = Some(upper);
                // search_low never exceeds search_high.
                bounds.confirmed = bounds.confirmed.map(|c| c.min(upper));
            }
            UdpProbeOutcome::TimeoutFailure => {
                bounds.suppressed = Some(match bounds.suppressed {
                    Some(s) if now < s.until => RetrySuppression {
                        size: s.size.min(size),
                        until: s.until.max(retained.expires_at),
                    },
                    _ => RetrySuppression {
                        size,
                        until: retained.expires_at,
                    },
                });
            }
            UdpProbeOutcome::Inconclusive => {}
        }
        self.udp.slots[id.slot].flow.as_mut().unwrap().bounds = bounds;
        let shared = match (outcome, writer) {
            (UdpProbeOutcome::Success, Some(_)) => match self.paths.confirm_delivery_as(
                retained.path,
                size,
                retained.negative_revision,
                retained.submitted_at,
                now,
                DeliveryEvidence::OwnerTrustedApplication,
            ) {
                Ok(disposition) => SharedOffer::Offered(disposition),
                Err(error) => SharedOffer::Refused(error),
            },
            _ => SharedOffer::NotOffered,
        };
        Ok(UdpProbeReport { bounds, shared })
    }
}
