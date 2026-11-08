use super::*;

/// IPv6 minimum link MTU (RFC 8200 section 5).
const IPV6_MINIMUM_LINK_MTU: u32 = 1280;
// RFC 1122 section 3.3.3: without actual knowledge of the path's minimum
// MTU, an IPv4 destination that is not on a connected network gets
// EMTU_S <= 576.
const IPV4_OFF_LINK_SEND_LIMIT: u32 = 576;

#[cfg(test)]
mod tests;
mod admin;
pub use admin::*;

handle!(PathId);
handle!(ClientId);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidationReason {
    SourceRemoved,
    LinkRemoved,
    RouteRemoved,
    SelectionChanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathStatus {
    Valid,
    Invalidated(InvalidationReason),
}

/// Acknowledgement provenance for one path incarnation and change version.
/// Reading a snapshot never acknowledges it. Tokens from another path (including
/// a prior binding) and future versions are rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChangeStamp {
    path: PathId,
    version: u64,
}

/// A detached observation, not perpetual output authorization. Embeddings must
/// compare its stamp with the live binding before physical submission (T8/T10).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathSnapshot {
    stamp: ChangeStamp,
    key: PathKey,
    status: PathStatus,
    first_hop_mtu: u32,
    link_version: u64,
    learned_mtu: Option<u32>,
    negative_revision: u64,
    retry_not_before: u64,
    ipv4_plateaus: Option<Ipv4Plateaus>,
    // Administrative restriction of this incarnation's packet budget carried
    // from its route's retained admission state at installation: a cap, not
    // learned network state. Kept through upward sets and clears; only
    // confirmed delivery on this incarnation relaxes it.
    restriction: Option<u32>,
    // The owner's effective administrative estimate and discovery policy,
    // delivered to clients with the snapshot.
    admin_estimate: Option<u32>,
    discovery_disabled: bool,
    discovery_revision: u64,
    // Fixed by the route generation the key selected: the base header, and
    // an SR route's Segment Routing Header of n + 1 16-octet entries after
    // its 8-octet fixed part (the length `ntcp_ip6::header_len` encodes).
    ip_header_len: u32,
}

impl PathSnapshot {
    pub const fn path(self) -> PathId {
        self.stamp.path
    }
    pub const fn stamp(self) -> ChangeStamp {
        self.stamp
    }
    pub const fn version(self) -> u64 {
        self.stamp.version
    }
    pub const fn key(self) -> PathKey {
        self.key
    }
    pub const fn status(self) -> PathStatus {
        self.status
    }
    pub const fn first_hop_mtu(self) -> u32 {
        self.first_hop_mtu
    }
    pub const fn link_version(self) -> u64 {
        self.link_version
    }
    pub const fn learned_mtu(self) -> Option<u32> {
        self.learned_mtu
    }
    /// Revision of the last actual learned decrease, independent of harmless
    /// link/policy updates. The deadline uses the producer's caller timebase.
    pub const fn negative_revision(self) -> u64 {
        self.negative_revision
    }
    pub const fn retry_not_before(self) -> u64 {
        self.retry_not_before
    }
    pub const fn ipv4_plateaus(self) -> Option<Ipv4Plateaus> {
        self.ipv4_plateaus
    }
    /// An administrative cap on this incarnation's packet budget that came
    /// from its route's retained restriction when the path was installed
    /// (after idle eviction or for another destination of the route). It is
    /// never delivery proof and is not learned network state. Upward sets
    /// and clears keep it, so they never restore a larger accepted value;
    /// only confirmed delivery on this incarnation relaxes it.
    pub const fn administrative_restriction(self) -> Option<u32> {
        self.restriction
    }
    /// The effective owner administrative estimate of the path (route and
    /// exact-path policy intersected): a cap on size search, distinct from
    /// the accepted network estimate and from delivery proof.
    pub const fn administrative_estimate(self) -> Option<u32> {
        self.admin_estimate
    }
    /// The effective owner discovery-disable flag of the path.
    pub const fn discovery_disabled(self) -> bool {
        self.discovery_disabled
    }
    /// Advances (to the policy generation of the change) every time the
    /// effective discovery policy of this incarnation changes, so size
    /// evidence selected under an older policy is recognizably stale even
    /// after a disable followed by a re-enable.
    pub const fn discovery_revision(self) -> u64 {
        self.discovery_revision
    }
    /// The complete IP header length H of output on this path before any
    /// IPv4 options its sender adds: the family's base header and, on an SR
    /// route of n segments, the Segment Routing Header listing them and the
    /// final destination (8 + 16(n + 1) octets). Fixed for the path, whose
    /// key names the route generation.
    pub const fn ip_header_len(self) -> u32 {
        self.ip_header_len
    }

    /// Ordinary wire lengths only: IPv6's 65535 payload octets plus40 base
    /// header octets. Physical jumbo MTUs remain separately observable.
    ///
    /// On an IPv6 path whose owner disabled discovery (RFC 8201 section
    /// 5.6) every physical packet is at most the IPv6 minimum link MTU
    /// (1280 octets, RFC 8200 section 5), whatever the network estimate:
    /// the budget every client of the path sizes its output with.
    /// On an IPv4 path whose owner disabled discovery (RFC 1191 section 6.6)
    /// packets go without DF, so the budget is the RFC 1122 section 3.3.3
    /// sending limit used without discovery: the owner's administrative
    /// value when one is set (actual knowledge of the path, never above the
    /// accepted network estimate), otherwise at most 576 octets when the
    /// destination is reached through a gateway or forwarder (not on a
    /// connected network) and the accepted estimate, bounded by the link
    /// MTU, when it is on-link.
    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.6
    //= reason=The owner's discovery-disable flag on a path, or on the route it resolves through, set through Host::administration and by the ntcp-pathctl utility (8201-080), caps that path's IPv6 packet budget at the IPv6 minimum link MTU of 1280 octets (PathSnapshot::ip_packet_budget), counting every IP header and any Fragment header; the uncapped network estimate is still the one compared with administrative values, and an administrative value above 1280 stays cached. Every packet the Host sends on the path obeys it: Host::admin_apply applies the budget to existing TCP connections in the same transaction (reservation-safe budget application keeps submitted prefixes) and future connections are created under it, the submission barrier refuses a larger packet, each physical software-GSO segment is cut to it, UDP Refuse admits only datagrams that fit whole, Fragment mode and Echo replies cut packets to at most 1280 octets, and Host::udp_send's payload limit follows the same budget. Connections created with PMTUD disabled enforce the same ceiling on their own (8201-004); the path flag is the separate administrative control. Tests: ntcp-host src/tests/admin.rs (existing and future TCP output and retransmissions, SYN, SYN-ACK, FIN and RST control segments and stateless resets, and every physical GSO segment of an aggregate held across the disable and of new aggregates, at most 1280 octets), emitter.rs discovery_disable_caps_ipv6_flows_at_1280_and_refuses_probes and ingress.rs echo_replies_on_a_discovery_disabled_ipv6_route_are_at_most_1280; the integration/rfc_host admin and native-admin cases capture every IPv6 packet of tun_echo and the native runtime (existing and new TCP connections, control segments and UDP source fragments) at most 1280 octets after ntcp-pathctl disables discovery on a path or route, with stream and datagram hashes intact, while a neighbor destination keeps 1500-octet packets.
    //# The former can be accomplished by associating a flag with the path; when a packet is sent on a path with this flag set, the IP layer does not send packets larger than the IPv6 minimum link MTU.
    pub fn ip_packet_budget(self) -> Result<u32, Error> {
        let budget = self.pmtu_estimate()?;
        if !self.discovery_disabled {
            return Ok(budget);
        }
        if !self.key.destination.address.is_ipv4() {
            return Ok(budget.min(IPV6_MINIMUM_LINK_MTU));
        }
        Ok(match self.admin_estimate {
            Some(estimate) => budget.min(estimate),
            None if self.next_hop_on_link() => budget,
            None => budget.min(IPV4_OFF_LINK_SEND_LIMIT),
        })
    }

    /// Whether the destination is on a connected network: the resolved next
    /// hop is the forwarding destination itself rather than a gateway or a
    /// forwarder.
    fn next_hop_on_link(self) -> bool {
        self.key.next_hop == ResolvedNextHop::Address(self.key.forwarding_destination)
    }

    /// Whether IPv4 output on this path must leave DF clear whatever the
    /// upper layer requests: the owner disabled discovery on its route or
    /// path (RFC 1191 section 6.6). Never true for IPv6.
    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.6
    //= reason=The suggested route flag is set through Host::administration and by the ntcp-pathctl utility. Outside flagged routes IPv4 packets carry DF (the atomic encoder and every source fragment) except the application-requested IP_PMTUDISC_DONT TCP output, each with an Identification leased from the Host allocator. T13 supplies the mechanisms those controls build on: the Host IdentifierAllocator (every non-atomic IPv4 datagram the Host originates, fragmented or DF-clear, carries a leased Identification), the fragmenting datagram emitter and Host UDP Probe mode; it adds no administrative control. The administrative model exists: PathService stores owner policy (discovery disable and an administrative PMTU estimate) per forwarding route and per exact resolved path under compare-and-set generations and keeps a route's administrative restriction (the lowest value its estimate imposed on a path) across idle path eviction and upward sets until the route's estimate is cleared, and its outstanding administrative hold across clears as well, and installs later paths of the route under them, so reacquisition never promotes a deferred upward value; Host::administration issues a Host-instance-bound capability for query (the administrative estimate, the accepted network estimate with its provenance, each client's usable size, TCP transport ceilings, and the TCP and Echo adjunct search diagnostic), read-only candidate validation and apply. Each estimate operation compares with the path's accepted network estimate: a downward value lowers it at once with a fresh negative revision and a hold of max(old, now + 600 seconds), notifies every client of the path in the same administration transaction and caps the search and confirmed growth while set; an equal value is a no-op; an upward value changes no accepted estimate, hold, search lower bound, current size or confirmed bound and defines a search transition: it caps TCP PLPMTUD and the Host Echo adjunct search, and once per value the first probe the existing hold, cooldown, loss-recovery, data/window and adjunct-demand rules allow targets it (clipped by the first-hop, transport and negative-evidence bounds; the deferral or clip is reported), so the accepted estimate grows only through an acknowledged or echoed unfragmented probe and PathService::confirm_delivery, and a failed targeted probe is not reopened by later revisions; clearing removes the cap for live and later paths and keeps every hold, while a live path incarnation keeps the accepted estimate a restriction lowered (no older larger value is restored), which relaxes only through confirmed delivery there. Size proof follows the final submitted bytes: a TCP record raises max_acked or search_low or reaches confirm_delivery only when its submitted packet was unfragmentable (IPv4 DF set, certified from Host::submit's physical receipt for managed output), so DF-clear IP_PMTUDISC_DONT output proves no size. Every change is one serialized Host::admin_apply transaction: it validates read-only every TCP binding on each affected path (complete option-bearing headers plus one payload octet), failing with nothing changed, then stores the policy and applies each binding's new snapshot, each UDP flow's change notification and the Echo adjunct state at once; best-effort output never blocks a change: a held stateless output lease is revalidated by the submission barrier and a queued ICMP message is sized at emission, exactly as after a trusted PTB decrease (one that no longer fits is refused or counted unsent), so a remote peer cannot hold the owner's restriction off; the IPv4 plateau table and RFC 4821 search aging (existing TCP connections at once, future ones before their first output) are administered through the same capability. The discovery-disable flag is enforced on existing and future users: no TCP PLPMTUD probe, Echo adjunct probe or UDP Probe-mode datagram (refused with DiscoveryDisabled) leaves a flagged path and the submission barrier refuses any packet above its ordinary budget; TCP stops size-search changes (probe success, implicit growth, isolated-loss narrowing, verification and black-hole fallback) while loss recovery continues; each change invalidates outstanding TCP and adjunct size results selected under the previous policy; and on IPv6 the path's packet budget is at most 1280 octets, which every physical packet of existing and newly created users obeys (Host tests: TCP output and retransmissions, SYN, SYN-ACK, FIN and RST control segments and stateless resets, each physical software-GSO segment of an aggregate held across the disable and of new aggregates, UDP Refuse and Fragment, and Echo replies). On IPv4 the flag leaves DF clear on the packets of the route or path whatever the upper layer requests (RFC 1191 section 6.6, the user's recorded decision B): TCP segments including control segments and connections created with PLPMTUD, whole UDP datagrams of Host::udp_send and Host::udp_send_datagram and Host source fragments of UDP Fragment mode and Echo replies (MF, offsets and the datagram's one Identification kept, every rewritten header checksum recomputed), each DF-clear datagram carrying an Identification leased from the Host allocator (the RFC 6864 ceiling holds output instead of reusing a value); its sending limit is the RFC 1122 section 3.3.3 EMTU_S: the owner's administrative value when set (never above the accepted estimate), otherwise at most 576 octets through a gateway or forwarder and the accepted estimate within the link MTU on-link, the packet budget existing and future TCP, UDP Refuse and Fragment, Echo replies and udp_datagram_limits use. The TCP submission barrier (Host::submit) refuses a DF-set IPv4 packet on such a path; Host::clears_dont_fragment and Host::lease_df_clear apply the rewrite at each physical submission in the native runtime (a route disable dominates the socket's IP_MTU_DISCOVER) and tun_echo, and DF-clear deliveries prove no size (Host tests in ntcp-host src/tests/ipv4_policy.rs, PathService tests of the on-link, gateway and forwarder limits). A DF-clear datagram is non-atomic, so such a route needs exactly these leased Identifications (RFC 6864). T12 stage 6 adds the system utility: the ntcp-path-control crate's opt-in local control socket (an absolute pathname Unix stream socket of mode 0600 in a private 0700 directory owned by the owner; every request, queries included, authorized on the accepted descriptor by its kernel SO_PEERCRED uid against an allow-list defaulting to the owner's effective uid, without a root bypass and failing closed; a versioned length-prefixed binary protocol with fixed-width fields, frame and page bounds derived from the largest encoded messages, bounded peer slots, per-pass work, frame-completion, reply-drain and idle deadlines, and explicit statuses for malformed, oversized, unknown-version, unknown-opcode, unauthorized and stale requests, which change nothing), served from the owner loop of the native runtime (control.socket, control.allow_uids, separate from route.*; native descriptors and direct system calls on the owner thread, before the held-output early continue) and of tun_echo (NTCP_CONTROL_SOCKET), through the Host-bound administration capability, and the ntcp-pathctl utility: paginated route and path queries carrying a listing revision (generations, policy, the cached administrative estimate, the accepted estimate with provenance, the shared packet budget, holds and revisions, and per client the usable size, transport ceilings and deferred growth with its reason), discovery disable and enable and administrative estimate set and clear on a route or an exact path under compare-and-set generations, the IPv4 plateau table and search aging (real utility process round trips in ntcp-path-control tests/control.rs, the native runtime and tun_echo tests). Namespace evidence (integration/rfc_host admin and native-admin cases): after ntcp-pathctl disables discovery on an IPv4 route or path of tun_echo or the native runtime, every captured packet, TCP control segments and UDP source fragments included, has DF clear and its own nonzero leased Identification, at most 576 octets through a Forwarder route or at most the administrative value when one is set, while another destination through the same route keeps DF on its packets and fragments. Host::udp_send, the T9 whole-datagram API that tun_echo's Refuse-mode UDP echo replies use, leaves its IPv4 datagrams on such a route DF clear with a leased Identification as well, holding a datagram on identifier backpressure (UdpSendError::Backpressure) and refusing one above the sending limit with its payload limit (ntcp-host test disabled_ipv4_route_clears_df_on_whole_udp_send_datagrams); the integration/rfc_host admin refuse case captures tun_echo's Refuse-mode replies after ntcp-pathctl disables discovery on its IPv4 path: DF clear, distinct nonzero Identifications and at most 576 octets, a larger reply refused locally with the 548-octet payload limit, while the neighbor destination keeps DF and re-enabling restores it. Route isolation of the IPv4 policy is shown in-process: ntcp-host test disabling_one_ipv4_route_leaves_a_neighbor_route_keeping_df_on_fragments disables one of two routes sharing a link and next hop, whose fragments leave DF clear while the other route keeps DF on its fragments; on the wire, the integration/rfc_host icmp route-isolation case gives the datagram_drive Host a second route (the same link and Forwarder next hop, selected by DSCP): after the owner disables discovery on its default route, that route's source fragments leave DF clear with one nonzero leased Identification per datagram and at most 576 octets, while the neighboring enabled route keeps DF on its fragments and the peer reassembles both.
    //# The former can be accomplished by associating a flag with the routing entry; when a packet is sent via a route with this flag set, the IP layer leaves the DF bit clear no matter what the upper layer requests.
    pub fn clears_dont_fragment(self) -> bool {
        self.discovery_disabled && self.key.destination.address.is_ipv4()
    }

    /// RFC 1191 section 5's current PMTU estimate for this path incarnation
    /// (complete IP octets): the accepted network estimate (first hop,
    /// learned value and any retained administrative restriction, within
    /// the family wire ceiling) WITHOUT the discovery-policy sending limit
    /// of `ip_packet_budget` (IPv4 576 through a gateway or forwarder or the
    /// owner's value, IPv6 1280). It is the reference every estimate
    /// comparison uses: correcting a legacy IPv4 Datagram Too Big quote,
    /// deriving a correlated PTB's estimate and lowering a search baseline,
    /// so a validated PTB for an earlier submission learns the same network
    /// value whether or not the owner disabled discovery. It is NOT a
    /// sending limit: packets are sized with `ip_packet_budget`.
    pub fn pmtu_estimate(self) -> Result<u32, Error> {
        if self.status != PathStatus::Valid {
            return Err(Error::Invalidated);
        }
        Ok(self.last_pmtu_estimate())
    }

    /// The `pmtu_estimate` this incarnation held when it was last valid:
    /// invalidation freezes it, so it stays readable after the path's
    /// route, source or link is gone. A report of what the path learned,
    /// never output authority or a sending budget.
    pub fn last_pmtu_estimate(self) -> u32 {
        let ceiling = if self.key.destination.address.is_ipv4() {
            65535
        } else {
            65575
        };
        self.first_hop_mtu
            .min(self.learned_mtu.unwrap_or(u32::MAX))
            .min(self.restriction.unwrap_or(u32::MAX))
            .min(ceiling)
    }

    /// Maximum send transport-message size uses the MINIMUM family IP header,
    /// not the actual complete header or TCP payload size.
    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.1
    //= reason=T7 PathService exposes minimum-header MMS_S, complete-header budgets and versioned notifications with exact acknowledgements. T8 Host applies snapshots to actual native/TUN TCP owners and gates every reserved physical submission. Independent-reader/coalescing tests preserve readN/update/ackN; validated cross-protocol publication remains T9/T10.
    //# A way to learn of changes in the value of MMS_S, the "maximum send transport-message size", which is derived from the Path MTU by subtracting the minimum IP header size.
    pub fn mms_s(self) -> Result<u32, Error> {
        self.ip_packet_budget()?
            .checked_sub(self.minimum_header())
            .ok_or(Error::InvalidArgument)
    }

    fn minimum_header(self) -> u32 {
        if self.key.destination.address.is_ipv4() {
            20
        } else {
            40
        }
    }

    /// Caller supplies validated complete IP/transport header lengths. This
    /// checks size arithmetic, not extension/option semantics. The optional
    /// ceiling is a transport PAYLOAD ceiling, intersected only for this query.
    pub fn payload_budget(
        self,
        ip_header: u32,
        transport_header: u32,
        transport_ceiling: Option<u32>,
    ) -> Result<u32, Error> {
        let ipv4 = self.key.destination.address.is_ipv4();
        if (ipv4 && (!(20..=60).contains(&ip_header) || !ip_header.is_multiple_of(4)))
            || (!ipv4 && (ip_header < 40 || !(ip_header - 40).is_multiple_of(8)))
        {
            return Err(Error::InvalidArgument);
        }
        let headers = ip_header
            .checked_add(transport_header)
            .ok_or(Error::InvalidArgument)?;
        let payload = self
            .ip_packet_budget()?
            .checked_sub(headers)
            .ok_or(Error::InvalidArgument)?;
        Ok(payload.min(transport_ceiling.unwrap_or(u32::MAX)))
    }
}

#[derive(Clone, Copy)]
pub(super) struct CachedPath {
    snapshot: PathSnapshot,
    // Greatest unlearned packet budget exposed on this live path. Retain it
    // across physical reductions because feedback for older submissions remains
    // useful. Once learned, the separate learned ceiling governs decreases.
    pub(super) unlearned_mtu: u32,
    pub(super) pins: usize,
    // Exact-path owner policy: a nonempty policy is an administrative pin
    // that keeps this incarnation out of idle eviction until cleared or
    // invalidated. It migrates only across a forwarding transition (a
    // Redirect override installed or ended beneath the same route): the
    // invalidated incarnation keeps it until the same flow's next
    // incarnation is installed and takes it.
    pub(super) admin: PathAdmin,
    // The learned ceiling owner-trusted application evidence raised, while
    // it is still the learned ceiling: provenance only, never Host proof.
    pub(super) application_mtu: Option<u32>,
}

impl CachedPath {
    fn idle(&self) -> bool {
        self.pins == 0 && (self.admin.policy.is_empty() || self.snapshot.status != PathStatus::Valid)
    }
    // Learned ceiling, else the largest unlearned budget exposed.
    pub(super) fn network_estimate(&self) -> u32 {
        self.snapshot.learned_mtu.unwrap_or(self.unlearned_mtu)
    }
    // The accepted estimate: the network estimate under any retained
    // administrative restriction.
    pub(super) fn accepted_estimate(&self) -> u32 {
        self.network_estimate()
            .min(self.snapshot.restriction.unwrap_or(u32::MAX))
    }
}

#[derive(Clone, Copy)]
pub(super) struct Client {
    path: PathId,
    dirty: bool,
}

/// Estimate changes and packet-drop actions are independent. Even Unchanged
/// feedback can describe a dropped packet; a later dispatcher owns that action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EstimateChange {
    /// A learned network ceiling was recorded or lowered. A smaller physical
    /// MTU can mask this change in the effective packet budget.
    Decreased,
    Unchanged,
}

/// Who certified a delivery offered to `confirm_delivery_as`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryEvidence {
    /// The Host observed it: a TCP probe acknowledgment backed by its own
    /// physical receipt, or an exact Echo Reply to the Host's adjunct probe.
    HostObserved,
    /// An application flow holding the owner-granted shared-writer
    /// capability reported a successful probe the Host definitely submitted.
    /// The Host trusts the owner's grant, not its own observation.
    OwnerTrustedApplication,
}

/// Disposition of probe-confirmed delivery offered to `confirm_delivery`.
/// Only `Raised` changes shared state; every other outcome is stale or
/// non-informative evidence, never an error in the trusted producer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryConfirmation {
    /// The learned ceiling rose to the confirmed length; clients are dirty.
    Raised,
    /// A decrease was learned after the probe was selected.
    StaleNegativeRevision,
    /// Selected or offered before the current conservative hold expired.
    Held,
    /// Larger than the current first-hop MTU or the family wire ceiling.
    ExceedsFirstHop,
    /// Larger than the owner's administrative estimate for the path, which
    /// caps search and the accepted estimate while it is set.
    ExceedsAdministrative,
    /// No larger than the current learned ceiling, or nothing was learned
    /// (no larger than the accepted estimate while an administrative
    /// restriction caps it).
    NotLarger,
}

impl PathService {
    /// Commit after the authority operation has preflighted its revision and
    /// generations. Re-resolve ALL valid paths, including still-live routes
    /// shadowed by additions or metric changes. No allocation or fallible work
    /// remains here. Invalidations are sticky until rebind/release; later table
    /// changes can never revive an old path, even if its key resolves again.
    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.3
    //= reason=T7 PathService invalidates bound paths on route/source/link changes, including shadowing routes, route removal and a source address or egress link that moves to or leaves another interface (ntcp-path tests/lifecycle.rs every_route_mutation_reconsiders_pinned_paths_including_live_shadowed_routes, source_ownership_and_link_deletion_only_revoke_lost_authority, egress_link_removal_and_recreation_never_reuses_a_bound_path). T8 Host rebinds actual native/TUN TCP owners, and T10 Host::service_changes notifies every TCP binding and Host UDP flow of the replacement on the next service pass (a failed rebind stays dirty with bounded backpressure, then converges once the bad route is deleted: failed_client_stays_dirty_while_others_are_served) while the submission barrier refuses held packets the current path no longer carries (dual-family Host and native reservation-race tests). T9 correlation never lets a stale or invalidated path incarnation change an estimate. T18 receives IPv4 and ICMPv6 Redirects, validated against the destination's current first hop, the arrival link and an exact committed submission, as bounded overrides beneath the selected administrative route (PathService::redirect); installing or replacing one and each event that ends one (route replacement or removal, link removal, neighbor unreachability, loss of the IPv6 Router flag, eviction) invalidates the affected paths, and Host::service_changes then notifies their TCP and UDP clients (ntcp-path tests/redirect.rs, ntcp-host src/tests/redirect.rs). Namespace evidence (T19, integration/rfc_host redirect cases, IPv4 and IPv6): after a Linux router R1's route to the destination moves to R2 on the shared link, R1's kernel answers the native runtime's next captured submission with a Redirect (its OutRedirects or Icmp6OutRedirects counter rising by the Redirects captured) naming R2 and quoting that submission; the native runtime accepts it, both established TCP flows and a later connection then leave with R2's Ethernet address, ntcp-pathctl shows the replacement path identity, next hop and client membership, a destination outside the Redirect keeps R1, and every stream completes with exact hashes.
    //# PMTU estimates may disappear from the routing table if the per-host routes are removed; this can happen in response to an ICMP Redirect message, or because certain routing-table daemons delete old routes after several minutes. Also, on a multi-homed host a topology change may result in the use of a different source interface. When this happens, if the packetization layer is not notified then it may continue to use a cached PMTU value that is now too small. One solution is to notify the packetization layer of a possible PMTU change whenever a Redirect message causes a route change, and whenever a route is simply deleted from the routing table.
    pub(super) fn commit_revision(&mut self, revision: u64) {
        self.revision = revision;
        self.prune_redirects();
        for index in 0..self.paths.slots.len() {
            let Some(mut path) = self.paths.slots[index].value else {
                continue;
            };
            if path.snapshot.status != PathStatus::Valid {
                continue;
            }
            let old = path.snapshot;
            match self.validate_selection(old.key) {
                Ok(resolved) => {
                    path.snapshot.first_hop_mtu = resolved.first_hop_mtu;
                    path.snapshot.link_version = resolved.link_version;
                    if path.snapshot.learned_mtu.is_none() {
                        // The network estimate, not the administrative cap.
                        let network = PathSnapshot {
                            restriction: None,
                            ..path.snapshot
                        };
                        path.unlearned_mtu =
                            path.unlearned_mtu.max(network.pmtu_estimate().unwrap());
                    }
                    path.snapshot.ipv4_plateaus = old
                        .key
                        .destination
                        .address
                        .is_ipv4()
                        .then_some(self.plateaus);
                }
                Err(_) => {
                    // Invalidation releases the administrative pin and its
                    // policy: the target no longer exists for the owner.
                    // Across a forwarding transition the same flow goes on
                    // through the same route, and its successor takes it.
                    if !self.forwarding_transition(old.key) {
                        path.admin = PathAdmin::default();
                    }
                    let key = old.key;
                    let reason = if self.source_address(key.source).is_err() {
                        InvalidationReason::SourceRemoved
                    } else if self.link(key.link).is_err() {
                        InvalidationReason::LinkRemoved
                    } else if self.route(key.route).is_err() {
                        InvalidationReason::RouteRemoved
                    } else {
                        InvalidationReason::SelectionChanged
                    };
                    path.snapshot.status = PathStatus::Invalidated(reason);
                }
            }
            if path.snapshot != old {
                path.snapshot.stamp.version = revision;
                self.paths.slots[index].value = Some(path);
                self.mark_dirty(old.path());
            }
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
    //= reason=PathService marks every client of a path dirty on each trusted decrease and on link MTU, route, source, link or plateau changes. Host::service_changes, run on every native service_egress and MTU-refresh pass and every tun_echo transmit pass, brings each dirty TCP binding (reserved owners included, budget only, no repair) and each Host UDP flow (a coalesced per-flow change slot carrying MMS_S and the payload limit) to the newest snapshot and acknowledges exactly that version; a failing client stays dirty without stopping the others, and stateless leases and every physical submission revalidate against the current version. Dual-family Host tests (two TCP flows plus a UDP flow, held scalar, zero-copy and partial software GSO reservations, a randomized multi-client model), native reservation-race tests and the isolated namespace shared-fanout case, in which a real router PTB quotes only TCP flow A, verify it.
    //# The packetization layers must be notified about decreases in the PMTU. Any packetization layer instance (for example, a TCP connection) that is actively using the path must be notified if the PMTU estimate is decreased.
    fn mark_dirty(&mut self, path: PathId) {
        for slot in &mut self.clients.slots {
            if let Some(client) = &mut slot.value {
                if client.path == path {
                    client.dirty = true;
                }
            }
        }
    }

    /// Deterministic bounded cache policy: reuse a matching valid path, then a
    /// free slot, then the lowest-index idle slot. Live clients pin paths even
    /// after invalidation. Eviction is resource reclamation, never delivery or
    /// permission to grow a live estimate.
    fn path_slot(&self, key: PathKey) -> Result<(usize, bool), Error> {
        if let Some(index) = self.paths.slots.iter().position(|s| {
            s.value
                .is_some_and(|p| p.snapshot.key == key && p.snapshot.status == PathStatus::Valid)
        }) {
            return Ok((index, false));
        }
        let index = self.paths.free().or_else(|_| {
            self.paths
                .slots
                .iter()
                .position(|s| s.value.is_some_and(|p| p.idle()))
                .ok_or(Error::Capacity)
        })?;
        Ok((index, true))
    }

    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
    //= reason=Managed factories acquire per-host records from configured network/default routes before TCP construction, initializing unlearned budgets from the physical first hop. Trusted decreases change only per-host learned estimates, preserving forwarding routes and independent first-hop facts. Dual-family two-Endpoint tests exercise both route selections, first SYN/hidden child and later decreases without forwarding-route mutation. Generic ICMP publication remains the separate 1191-057 obligation.
    //# When the first packet is sent to a host for which no per-host route exists, a route is chosen either from the set of per-network routes, or from the set of default routes. The PMTU fields in these route entries should be initialized to be the MTU of the associated first-hop data link, and must never be changed by the PMTU Discovery process. (PMTU Discovery only creates or changes entries for per-host routes). Until a Datagram Too Big message is received, the PMTU associated with the initially-chosen route is presumed to be accurate.
    fn install_path(
        &mut self,
        index: usize,
        generation: u64,
        resolved: ResolvedPath,
        revision: u64,
    ) -> PathId {
        let id = PathId(Handle {
            context: self.context,
            slot: index,
            generation,
        });
        // Route policy and its conservative admission state survive idle
        // eviction; learned network state does not.
        let route = self.route_admin(resolved.key.route).unwrap_or_default();
        let mut snapshot = PathSnapshot {
            stamp: ChangeStamp {
                path: id,
                version: revision,
            },
            key: resolved.key,
            status: PathStatus::Valid,
            first_hop_mtu: resolved.first_hop_mtu,
            link_version: resolved.link_version,
            learned_mtu: None,
            negative_revision: 0,
            retry_not_before: route.hold,
            ipv4_plateaus: resolved
                .key
                .destination
                .address
                .is_ipv4()
                .then_some(self.plateaus),
            restriction: None,
            admin_estimate: route.policy.estimate,
            discovery_disabled: route.policy.discovery_disabled,
            discovery_revision: 0,
            ip_header_len: match self.route_segments(resolved.key.route).map_or(0, <[_]>::len) {
                0 if resolved.key.destination.address.is_ipv4() => 20,
                0 => 40,
                n => 40 + 8 + 16 * (n as u32 + 1),
            },
        };
        let unlearned_mtu = snapshot.pmtu_estimate().unwrap();
        let restriction = match (route.restriction, route.policy.estimate) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        snapshot.restriction = restriction.filter(|&e| e < unlearned_mtu);
        if route.policy.estimate == snapshot.restriction
            && let Some(imposed) = snapshot.restriction
        {
            // The current value restricts this new path: retain it for the
            // route's future paths as a downward set on a live path would.
            self.retain_route_restriction(resolved.key.route, imposed);
        }
        // The same flow's exact-path policy, carried across a forwarding
        // transition, restricts this incarnation as it did the last one,
        // with that incarnation's hold.
        let admin = match self.carried_admin(resolved.key) {
            Some((slot, carried, previous)) => {
                self.paths.slots[slot].value.as_mut().unwrap().admin = PathAdmin::default();
                let effective = EffectivePolicy::of(route.policy, carried.policy);
                snapshot.admin_estimate = effective.estimate.map(|e| e.value);
                if effective.discovery_disabled.is_some() {
                    snapshot.discovery_disabled = true;
                    snapshot.discovery_revision = previous.discovery_revision;
                }
                snapshot.retry_not_before = snapshot.retry_not_before.max(previous.retry_not_before);
                snapshot.restriction = lower(snapshot.restriction, carried.policy.estimate)
                    .filter(|&e| e < unlearned_mtu);
                carried
            }
            None => PathAdmin::default(),
        };
        self.paths.insert(
            self.context,
            index,
            generation,
            CachedPath {
                snapshot,
                unlearned_mtu,
                pins: 0,
                admin,
                application_mtu: None,
            },
        );
        id
    }

    // The exact-path policy an invalidated incarnation of `key`'s flow
    // kept across a forwarding transition: its slot, policy and snapshot.
    fn carried_admin(&self, key: PathKey) -> Option<(usize, PathAdmin, PathSnapshot)> {
        self.paths.slots.iter().enumerate().find_map(|(slot, record)| {
            let path = record.value?;
            (path.snapshot.status == PathStatus::Invalidated(InvalidationReason::SelectionChanged)
                && !path.admin.policy.is_empty()
                && super::redirect::same_flow(path.snapshot.key, key))
            .then_some((slot, path.admin, path.snapshot))
        })
    }

    fn pin(&mut self, path: PathId) {
        // Every client occupies one preallocated slot; this count was checked
        // before mutation, and cannot exceed the checked client allocation.
        self.paths.slots[path.0.slot].value.as_mut().unwrap().pins += 1;
    }
    fn unpin(&mut self, path: PathId) {
        self.paths.slots[path.0.slot].value.as_mut().unwrap().pins -= 1;
    }

    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
    //= reason=T7 PathService maintains bounded per-host resolved routing records with independent learned estimates and exact first-hop authority. Every acquired active destination is pinned by its clients; capacity exhaustion preserves active records, and deterministic idle eviction uses fresh generations. Public tests exercise shared pinning, full-cache backpressure, idle reuse and repeated release cycles. Received ICMP Redirects become bounded destination overrides beneath the selected administrative route, not new owner routes (PathService::redirect, 1191-074).
    //# The obvious place to store this association is as a field in the routing table entries. A host will not have a route for every possible destination, but it should be able to cache a per-host route for every active destination. (This requirement is already imposed by the need to process ICMP Redirect messages.)
    pub fn acquire(&mut self, request: PathRequest) -> Result<(ClientId, PathSnapshot), Error> {
        self.acquire_via(request, request.destination)
    }
    pub fn acquire_via(&mut self, request: PathRequest, forwarding_destination: ScopedAddress) -> Result<(ClientId, PathSnapshot), Error> {
        let resolved = self.resolve_via(request, forwarding_destination)?;
        let client_slot = self.clients.free()?;
        let (index, new) = self.path_slot(resolved.key)?;
        let needed = if new { 2 } else { 1 };
        let generation = self
            .generation
            .checked_add(needed)
            .ok_or(Error::Exhausted)?;
        let revision = if new {
            self.next_revision()?
        } else {
            self.revision
        };
        let path = if new {
            self.install_path(index, generation - 1, resolved, revision)
        } else {
            self.paths.slots[index].value.unwrap().snapshot.path()
        };
        self.pin(path);
        let client = ClientId(self.clients.insert(
            self.context,
            client_slot,
            generation,
            Client { path, dirty: true },
        ));
        self.generation = generation;
        self.revision = revision;
        Ok((client, self.snapshot(client)?))
    }

    /// Rebind in place with fresh client authority. On ANY error, old binding,
    /// pinning, pending invalidation, counters and cache are unchanged. A full
    /// pinned cache reports Capacity even if releasing this client could free a
    /// slot: the owner must pause/retry or explicitly release authority first.
    pub fn rebind(
        &mut self,
        client: ClientId,
        request: PathRequest,
    ) -> Result<(ClientId, PathSnapshot), Error> {
        self.rebind_via(client, request, request.destination)
    }
    pub fn rebind_via(
        &mut self,
        client: ClientId,
        request: PathRequest,
        forwarding_destination: ScopedAddress,
    ) -> Result<(ClientId, PathSnapshot), Error> {
        let old = self.clients.get(self.context, client.0)?;
        let resolved = self.resolve_via(request, forwarding_destination)?;
        let (index, new) = self.path_slot(resolved.key)?;
        if !new && self.paths.slots[index].value.unwrap().snapshot.path() == old.path {
            return Ok((client, self.snapshot(client)?));
        }
        let generation = self
            .generation
            .checked_add(if new { 2 } else { 1 })
            .ok_or(Error::Exhausted)?;
        let revision = if new {
            self.next_revision()?
        } else {
            self.revision
        };
        let path = if new {
            self.install_path(index, generation - 1, resolved, revision)
        } else {
            self.paths.slots[index].value.unwrap().snapshot.path()
        };
        self.unpin(old.path);
        self.pin(path);
        let client = ClientId(self.clients.insert(
            self.context,
            client.0.slot,
            generation,
            Client { path, dirty: true },
        ));
        self.generation = generation;
        self.revision = revision;
        Ok((client, self.snapshot(client)?))
    }

    pub fn release(&mut self, client: ClientId) -> Result<(), Error> {
        let old = self.clients.get(self.context, client.0)?;
        self.unpin(old.path);
        self.clients.slots[client.0.slot].value = None;
        Ok(())
    }

    /// Pure read; invalidated snapshots stay readable, but budget methods reject
    /// them. Acknowledging invalidation clears dirty only, never restores output
    /// authority. A new binding is required before output may resume.
    pub fn snapshot(&self, client: ClientId) -> Result<PathSnapshot, Error> {
        self.client_snapshot(client).copied()
    }
    pub fn path_snapshot(&self, path: PathId) -> Result<PathSnapshot, Error> {
        Ok(self.paths.get_ref(self.context, path.0)?.snapshot)
    }
    /// The observation `snapshot(client)` would return.
    pub fn stamp(&self, client: ClientId) -> Result<ChangeStamp, Error> {
        Ok(self.client_snapshot(client)?.stamp())
    }
    fn client_snapshot(&self, client: ClientId) -> Result<&PathSnapshot, Error> {
        let path = self.clients.get_ref(self.context, client.0)?.path;
        Ok(&self.paths.get_ref(self.context, path.0)?.snapshot)
    }
    /// `validate_selection` of an observed path's key, without selecting a
    /// route again while that path is still valid: every revision re-resolves
    /// every valid path and invalidates, for good, each whose selection
    /// changed (`commit_revision`), and nothing else changes selection, so a
    /// path still valid is still its key's selection. An invalidated or
    /// released path, or one of another incarnation, is checked in full.
    pub fn validate_snapshot(&self, snapshot: &PathSnapshot) -> Result<(), Error> {
        let path = snapshot.path().0;
        if path.context == self.context
            && let Some(Slot {
                generation,
                value: Some(current),
            }) = self.paths.slots.get(path.slot)
            && *generation == path.generation
            && current.snapshot.status == PathStatus::Valid
            && current.snapshot.key == snapshot.key
        {
            debug_assert!(
                self.validate_selection(snapshot.key)
                    .is_ok_and(|resolved| resolved.key == snapshot.key)
            );
            return Ok(());
        }
        self.validate_selection(snapshot.key).map(|_| ())
    }
    pub fn path_pins(&self, path: PathId) -> Result<usize, Error> {
        Ok(self.paths.get_ref(self.context, path.0)?.pins)
    }
    pub fn is_dirty(&self, client: ClientId) -> Result<bool, Error> {
        Ok(self.clients.get_ref(self.context, client.0)?.dirty)
    }

    /// Callback-free, allocation-free bounded scan. Reading does not consume.
    pub fn dirty_clients(&self) -> impl Iterator<Item = ClientId> + '_ {
        self.clients
            .slots
            .iter()
            .enumerate()
            .filter_map(|(slot, record)| {
                record.value.filter(|c| c.dirty).map(|_| {
                    ClientId(Handle {
                        context: self.context,
                        slot,
                        generation: record.generation,
                    })
                })
            })
    }

    pub fn acknowledge(&mut self, client: ClientId, stamp: ChangeStamp) -> Result<(), Error> {
        let current = self.client_snapshot(client)?.stamp();
        if stamp.path != current.path || stamp.version > current.version {
            return Err(Error::InvalidArgument);
        }
        if stamp.version == current.version {
            self.clients.slots[client.0.slot]
                .value
                .as_mut()
                .unwrap()
                .dirty = false;
        }
        Ok(())
    }

    /// Trusted NETWORK fact producer only. The later host must validate the
    /// actually submitted quote and owner/key before calling. A path generation
    /// is stable across budget versions: useful older submissions can decrease
    /// it again. No packetization version equality, ACK, timer or TCP state is
    /// treated as network provenance here. No remote-address route creation.
    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
    //= reason=T7 PathService keys learned estimates by canonical context, source, destination/scope, routing DSCP, link, next-hop and route generation, excluding ECN and ports. T8 Host binds actual native/TUN TCP owners to these records; public tests preserve source/destination/DSCP/scoped-link isolation.
    //# In general, the IP layer should associate each PMTU value that it has learned with a specific path. A path is identified by a source address, a destination address and an IP type-of-service. (Some implementations do not record the source address of paths; this is acceptable for single-homed hosts, which have only one possible source address.)
    pub fn trusted_decrease(
        &mut self,
        path: PathId,
        candidate: u32,
    ) -> Result<EstimateChange, Error> {
        self.trusted_decrease_with_hold(path, candidate, 0)
    }

    /// Trusted producer supplies an absolute conservative discovery deadline.
    /// Equal/larger observations preserve the learned estimate and negative
    /// revision, but a later deadline still restarts the hold: growth selected
    /// before this fresh report must not be confirmed or submitted.
    pub fn trusted_decrease_with_hold(
        &mut self,
        path: PathId,
        candidate: u32,
        retry_not_before: u64,
    ) -> Result<EstimateChange, Error> {
        let mut cached = self.paths.get(self.context, path.0)?;
        if cached.snapshot.status != PathStatus::Valid {
            return Err(Error::Invalidated);
        }
        self.validate_selection(cached.snapshot.key)?;
        let ipv4 = cached.snapshot.key.destination.address.is_ipv4();
        let (floor, ceiling) = if ipv4 { (68, 65535) } else { (1280, 65575) };
        if !(floor..=ceiling).contains(&candidate) {
            return Err(Error::InvalidArgument);
        }
        // Compare against the pre-feedback network estimate, independently of
        // a temporary physical limit that can mask older-submission feedback.
        let estimate = cached.snapshot.learned_mtu.unwrap_or(cached.unlearned_mtu);
        if candidate >= estimate {
            if retry_not_before > cached.snapshot.retry_not_before {
                let revision = self.next_revision()?;
                cached.snapshot.retry_not_before = retry_not_before;
                cached.snapshot.stamp.version = revision;
                self.paths.slots[path.0.slot].value = Some(cached);
                self.revision = revision;
                self.mark_dirty(path);
            }
            return Ok(EstimateChange::Unchanged);
        }
        let revision = self.next_revision()?;
        cached.snapshot.learned_mtu = Some(candidate);
        cached.snapshot.negative_revision = revision;
        cached.snapshot.retry_not_before = cached.snapshot.retry_not_before.max(retry_not_before);
        cached.snapshot.stamp.version = revision;
        self.paths.slots[path.0.slot].value = Some(cached);
        self.revision = revision;
        self.mark_dirty(path);
        Ok(EstimateChange::Decreased)
    }

    /// Trusted positive NETWORK fact: an unfragmented packet of exactly
    /// `ip_len` complete IP octets, selected at `selected_at` under
    /// `negative_revision` and definitely submitted on this path incarnation,
    /// was delivered. The host proves that provenance; this checks it is
    /// still current at `now` (caller timebase of the hold deadline). Raising
    /// records `Some(ip_len)`, never the historical unlearned value, so a
    /// later physical increase cannot lift past what was proven.
    //= https://www.rfc-editor.org/rfc/rfc4821#section-5.2
    //= reason=PathService is the IP-layer store of per-path state, keyed by context, source, destination/scope, routing DSCP, link, next hop and route generation. Host stores correlated ICMP PTB MTUs there (TCP reports at or above the connection's proven delivery at once; reports below it only when that exact report's quoted-data timeout applies it, never because of loss inference, with a derived size that is independent of the connection's estimate because a legacy IPv4 report without a Next-Hop MTU is corrected against the Host's shared path estimate, RFC 1191 section 5's current PMTU estimate, never the connection's estimate; UDP datagram and fragment, Echo adjunct probe and path-level reports) with a 600-second hold, and Host::service_changes publishes TCP's PLPMTUD-confirmed size through PathService::confirm_delivery only for a definitely submitted, unfragmented probe selected after the hold under an unchanged negative revision, raising other flows' ordinary ceiling without local delivery proof; the Host's ICMP Echo adjunct offers the forward delivery an exact Echo Reply certifies through the same confirm_delivery rules. Loss-inferred decreases and probe state stay connection-local. Dual-family Host tests with real probes across the 600-second deadline verify it.
    //# The IP layer SHOULD be used to store the cached PMTU value and other shared state such as MTU values reported by ICMP PTB messages. Ideally, this shared state should be associated with a specific path traversed by packets exchanged between the source and destination nodes. However, in most cases a node will not have enough information to completely and accurately identify such a path. Rather, a node must associate a PMTU value with some local representation of a path. It is left to the implementation to select the local representation of a path.
    pub fn confirm_delivery(
        &mut self,
        path: PathId,
        ip_len: u32,
        negative_revision: u64,
        selected_at: u64,
        now: u64,
    ) -> Result<DeliveryConfirmation, Error> {
        self.confirm_delivery_as(
            path,
            ip_len,
            negative_revision,
            selected_at,
            now,
            DeliveryEvidence::HostObserved,
        )
    }

    /// `confirm_delivery` under exactly the same rules, recording where the
    /// delivery fact came from: a raise by owner-trusted application
    /// evidence is reported with that provenance until the learned ceiling
    /// changes again.
    pub fn confirm_delivery_as(
        &mut self,
        path: PathId,
        ip_len: u32,
        negative_revision: u64,
        selected_at: u64,
        now: u64,
        evidence: DeliveryEvidence,
    ) -> Result<DeliveryConfirmation, Error> {
        let mut cached = self.paths.get(self.context, path.0)?;
        if cached.snapshot.status != PathStatus::Valid {
            return Err(Error::Invalidated);
        }
        self.validate_selection(cached.snapshot.key)?;
        let ipv4 = cached.snapshot.key.destination.address.is_ipv4();
        let (floor, ceiling) = if ipv4 { (68, 65535) } else { (1280, 65575) };
        if ip_len < floor {
            return Err(Error::InvalidArgument);
        }
        let snapshot = cached.snapshot;
        if negative_revision != snapshot.negative_revision {
            return Ok(DeliveryConfirmation::StaleNegativeRevision);
        }
        if selected_at < snapshot.retry_not_before || now < snapshot.retry_not_before {
            return Ok(DeliveryConfirmation::Held);
        }
        if ip_len > snapshot.first_hop_mtu.min(ceiling) {
            return Ok(DeliveryConfirmation::ExceedsFirstHop);
        }
        // A downward administrative estimate stays a persistent cap on the
        // accepted estimate until the owner changes or clears it.
        if self.admin_cap(path).is_some_and(|cap| ip_len > cap) {
            return Ok(DeliveryConfirmation::ExceedsAdministrative);
        }
        match snapshot.restriction {
            // A retained administrative restriction relaxes only through
            // delivery of a packet larger than the accepted estimate it
            // caps; the proven length becomes the learned ceiling.
            Some(_) if ip_len <= cached.accepted_estimate() => {
                return Ok(DeliveryConfirmation::NotLarger);
            }
            Some(_) => {}
            None if snapshot.learned_mtu.is_none_or(|learned| ip_len <= learned) => {
                return Ok(DeliveryConfirmation::NotLarger);
            }
            None => {}
        }
        let revision = self.next_revision()?;
        cached.snapshot.restriction = None;
        cached.snapshot.learned_mtu = Some(ip_len);
        cached.application_mtu =
            (evidence == DeliveryEvidence::OwnerTrustedApplication).then_some(ip_len);
        cached.snapshot.stamp.version = revision;
        self.paths.slots[path.0.slot].value = Some(cached);
        self.revision = revision;
        self.mark_dirty(path);
        Ok(DeliveryConfirmation::Raised)
    }

    /// Apply the selected live fallback policy to checked caller evidence.
    /// Like trusted_decrease, this does not establish physical quote provenance.
    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
    //= reason=PathService keeps per-host learned estimates keyed by the path, created on first use with the current route's first hop, and never changes forwarding routes. Host ICMP dispatch derives the estimate from a nonzero Next-Hop MTU or the RFC1191 section 5 plateau below the quoted length, corrected against the Host's shared path estimate, RFC 1191 section 5's current PMTU estimate, never the connection's estimate, requires correlation with committed submission evidence and lowers the per-host record only when lower. A correlated TCP report about the connection's current path at or above its proven delivery lowers the record at once (the larger of the Host and TCP estimates) and otherwise restarts its hold. One below proven delivery is deferred whatever the connection's loss-inferred estimate and changes nothing shared (no decrease, hold restart or notification) until the connection applies exactly that report at the quoted data's timeout; Host::service_changes then publishes the larger of the Host estimate and the report's own policy-derived size, so a loss-inferred value never leaks. Cumulative progress past the quoted data refutes it, and released owners, rebound paths and subsumed results publish nothing. Stale or evicted path incarnations are never resurrected or changed. Dual-family Host tests (including legacy IPv4 reports without a Next-Hop MTU, compared with and without prior black-hole loss inference: identical derived size, deferral and publication) and real router PTBs in the isolated namespace gate verify it.
    //# When a Datagram Too Big message is received, the ICMP layer determines a new estimate for the Path MTU (either from a non-zero Next-Hop MTU value in the packet, or using the method described in section 5). If a per-host route for this path does not exist, then one is created (almost as if a per-host ICMP Redirect is being processed; the new route uses the same first-hop router as the current route). If the PMTU estimate associated with the per-host route is higher than the new estimate, then the value in the routing entry is changed.
    pub fn trusted_ipv4_fallback(
        &mut self,
        path: PathId,
        quoted_total: u32,
        header_bytes: u32,
        exact_sent_size: u32,
    ) -> Result<EstimateChange, Error> {
        let snapshot = self.path_snapshot(path)?;
        let table = snapshot.ipv4_plateaus.ok_or(Error::InvalidArgument)?;
        let candidate = table.legacy_fallback(
            snapshot.pmtu_estimate()?,
            quoted_total,
            header_bytes,
            exact_sent_size,
        )?;
        self.trusted_decrease(path, candidate)
    }
}
