extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use core::{mem::MaybeUninit, net::SocketAddr, num::NonZeroU8};

use crate::{
    RxPacketTimestamps, RxReadTimestamps, SendProgress, TxStreamRange, TxTimestampClock,
    TxTimestampRequest, TxTimestampSource, TxTimestampStage,
    buffer::{ReceiveBuffer, SendBuffer},
    output_reservation::Departure,
    pacing::Pacer,
    pmtud_config::min_mtu,
    rack::Rack,
    recovery::{
        Congestion, CongestionAlgorithm, InitialWindow, Prr, RecoveryAlgorithm, RttEstimator,
    },
    rx_timestamp::RxTimestamps,
    sack::Scoreboard,
    seq::Seq,
    tx_timestamp::TxTimestamps,
    wire::{self, ACK, CWR, ECE, FIN, Header, IpMetadata, PSH, RST, SYN, Segment, URG},
};

#[path = "connection_local_repair.rs"]
mod local_repair;
use local_repair::{ControlUndo, RepairUndo};
#[path = "connection_ptb.rs"]
mod ptb;
use ptb::PtbRepair;

// Caller-owned ticks in CallerTimebase units; deadlines use the same unit.
// The caller supplies monotonic, consistent-rate time in its real or simulated
// time domain, with precision at least as fine as the wire timestamp tick and
// finer than min_RTT/4 when using RACK.
// Violations leave protocol timing guarantees unspecified, never Rust undefined
// behavior or memory-safety violations. Nondecreasing input and resource bounds are checked.
// No wall/system clock is sampled.
pub type Instant = u64;

// Linux 22430ae5d90ab288b0ee2ad99ae941f4a666b694, include/net/tcp.h:
// TCP_PAWS_WRAP = INT_MAX / USEC_PER_SEC; tcp_paws_check expires at >=2147s.
// Peer units are unknown: support clocks <=1MHz, independent of local ticks.
// 2147s exceeds the configured MSL maximum (255s) and precedes sign-bit wrap.
// Linux compares floor-seconds (up to <1s earlier); we use exact elapsed us,
// retaining the same conservative bound, not identical quantized deadlines.
pub(crate) const PAWS_RECENT_EXPIRY_US: u64 = 2_147_000_000;
// RFC 7323 section 5.5: a peer invalidates TS.Recent only once idle for more
// than 24 days, whatever shorter limit this receiver applies to itself.
pub(crate) const PEER_TS_RECENT_IDLE_US: u64 = 24 * 86_400 * 1_000_000;

// Adaptive ACK timeout floor (Linux TCP_ATO_MIN); a shorter delayed_ack_us lowers it.
const ACK_TIMEOUT_FLOOR_US: u64 = 40_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallerTimebase {
    // Supported caller units: 1_000_000 (microseconds, default) or
    // 1_000_000_000 (nanoseconds). This is a unit, not a resolution declaration.
    pub units_per_second: u64,
    pub max_segment_lifetime_us: u64,
}
impl Default for CallerTimebase {
    fn default() -> Self {
        Self {
            units_per_second: 1_000_000,
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4.2
            //# For this specification the MSL is taken to be 2 minutes.
            max_segment_lifetime_us: 120_000_000,
        }
    }
}
impl CallerTimebase {
    // Config durations are microseconds; internal elapsed times retain caller ticks.
    pub(crate) fn ticks_from_us(self, us: u64) -> u64 {
        us.saturating_mul(self.units_per_second / 1_000_000)
    }

    pub(crate) fn us_from_ticks(self, ticks: u64) -> u64 {
        ticks / (self.units_per_second / 1_000_000)
    }

    pub(crate) fn valid(self) -> bool {
        matches!(self.units_per_second, 1_000_000 | 1_000_000_000)
            && (1..=255_000_000).contains(&self.max_segment_lifetime_us)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TimestampGranularity {
    #[default]
    Milliseconds,
    // Explicit policy exception to RFC7323's chosen 1ms..1s range, like Linux
    // tcp_usec_ts. External legacy 24-day PAWS peers may reject after ~35.8min
    // idle; ntcp receivers expire independently at 2147s in either local mode.
    Microseconds,
}

impl TimestampGranularity {
    pub(crate) const fn tick_us(self) -> u64 {
        match self {
            Self::Milliseconds => 1_000,
            Self::Microseconds => 1,
        }
    }

    pub(crate) fn tick_in(self, now: Instant, timebase: CallerTimebase) -> u64 {
        now / timebase.ticks_from_us(self.tick_us())
    }

    #[cfg(test)]
    pub(crate) fn tick(self, now: Instant) -> u64 {
        self.tick_in(now, CallerTimebase::default())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacingConfig {
    // Percentage of cwnd/SRTT (estimator RTO before the first RTT sample).
    pub rate_gain_percent: u16,
    // Stream bytes, including retransmissions, per second; excludes headers.
    pub max_bytes_per_second: Option<u64>,
    // Maximum rate-paced burst after startup, in effective sender MSS units. Nonzero;
    // the product with configured MSS must fit u32. Probes may exceed it.
    pub max_burst_segments: u32,
    // One initial flight may bypass rate spacing, bounded by its selected IW.
    // Explicit byte-rate caps and pre-data loss keep ordinary pacing instead.
    pub initial_window_burst: bool,
}

impl Default for PacingConfig {
    fn default() -> Self {
        Self {
            rate_gain_percent: 125,
            max_bytes_per_second: None,
            max_burst_segments: 2,
            initial_window_burst: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConnectionConfig {
    pub send_capacity: usize,
    pub receive_capacity: usize,
    // The send limit's floor and ceiling, Linux's tcp_wmem[0] and
    // tcp_wmem[2] (`send_capacity` is tcp_wmem[1]). The direction is tuned
    // while `send_capacity_max` exceeds `send_capacity` and no setter locked
    // it (`Endpoint::set_buffer_capacities`, SOCK_SNDBUF_LOCK): memory
    // pressure refuses its growth and moderates its limit, down to
    // `send_capacity_min` (or `send_capacity`, the lower). By default max
    // is `send_capacity`'s default, so that size is not tuned.
    pub send_capacity_min: usize,
    pub send_capacity_max: usize,
    pub mss: u16,
    // Application maximum segment size; independent of path MTU and storage ceiling.
    pub user_mss: Option<u16>,
    // Receive-only MSS offer cap. Does not constrain outgoing data/probes or
    // reduce actual receive/storage capacity. None retains the normal offer.
    pub advertised_mss: Option<u16>,
    pub pmtud: Option<crate::PmtudConfig>,
    // Maximum TCP segment bytes after IP headers/extensions are subtracted from
    // the reassembly bound; use the smallest bound if it varies.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.3
    //# As a result, when the effective MTU of an interface varies packet-to-
    //# packet, TCP implementations SHOULD use the smallest effective MTU of
    //# the interface to calculate the value to advertise in the MSS Option
    //# (SHLD-6).
    pub receive_ip_payload_limit: u16,
    // Maximum TCP segment bytes after IP headers/extensions are subtracted from
    // the transmission bound; must fit SYN with MSS/WS: 28 bytes, 32 with
    // SACK alone, or 40 with timestamps (with or without SACK).
    pub send_ip_payload_limit: u16,
    pub nagle: bool,
    pub ecn: bool,
    // With ecn: an active open sends an ECN-setup SYN. False only answers a
    // peer's ECN-setup SYN, as Linux does by default (tcp_ecn=2); without
    // ecn nothing is negotiated either way.
    pub ecn_initiate: bool,
    pub recovery_algorithm: RecoveryAlgorithm,
    // Optional growth/backoff policy; does not select loss recovery or PRR.
    pub congestion_algorithm: CongestionAlgorithm,
    // RFC 9406 initial startup for CUBIC; false selects standard Reno slow start.
    // Ignored when congestion_algorithm is Reno.
    pub cubic_hystart: bool,
    // Disable for a known single-flow path without competing traffic (RFC 9438).
    pub cubic_fast_convergence: bool,
    //= https://www.rfc-editor.org/rfc/rfc6928#section-1
    //= reason=Settable Rfc5681/Iw10 selection with default-disabled IW10; deployment monitoring/application interactions remain enabling-actor obligations explicitly excluded from this implementation audit, not satisfied. No evidence for IW>10 is claimed.
    //# We recommend that all TCP implementations have a settable TCP IW parameter, as long as there is a reasonable effort to monitor for possible interactions with other Internet applications and services as described in Section 12. Furthermore, Section 10 details why 10 segments may be an appropriate value, and while that value may continue to rise in the future, this document does not include any supporting evidence for values of IW larger than 10.
    pub initial_window: InitialWindow,
    // Opt-in RST|ACK for local abort after a completed, synchronized handshake.
    // Default retains the bare RST illustrated by RFC 9293 section 3.10.5.
    // Linux tcp_send_active_reset uses RST|ACK; only the flag policy is matched:
    // https://github.com/torvalds/linux/blob/22430ae5d90ab288b0ee2ad99ae941f4a666b694/net/ipv4/tcp_output.c
    pub abort_with_ack: bool,
    // Opt-in authenticated passive response packets after a committed SYN-ACK.
    // Default withholding avoids pre-handshake reflection (RFC 7413 section 5.2).
    pub fast_open_early_response: bool,
    // Optional flush hint on the terminal physical segment of an admitted GSO
    // group covered by pending application PUSH. Group size follows actual
    // backend/queue/window limits and a 1ms window/RTT work target (minimum
    // useful aggregation: two full segments), capped to half the effective cwnd. The hint
    // is transient: it never creates an application PUSH mark for retries.
    // Default false preserves exact scalar/GSO wire-equivalence for callers
    // that use segmentation solely as an encoding optimization.
    pub output_group_flush: bool,
    pub timestamps: bool,
    pub timestamp_granularity: TimestampGranularity,
    pub timebase: CallerTimebase,
    // Successful sequence-space bytes (including copies and SYN/FIN) per local timestamp tick; <2^31.
    pub timestamp_bytes_per_tick: u32,
    pub sack: bool,
    // Opt-in RFC 8985 time-based loss detection (requires negotiated SACK).
    // Physical clock precision is a caller precondition, not a runtime gate.
    pub rack: bool,
    // Opt-in PRR byte-credit control for SACK or non-SACK loss recovery.
    pub prr: bool,
    // RFC9937 data pacing, effective only with prr=true.
    // With pacing=None, false is a nonpaced override for equation tests or
    // caller-managed pacing; it does not implement RFC9937 section 6.4.
    // Ignored by the independent Some(PacingConfig) policy.
    pub prr_pacing: bool,
    // None preserves legacy PRR-only pacing, including its one-tick minimum.
    // Some enables fractional bounded-burst pacing independently of PRR/CC.
    pub pacing: Option<PacingConfig>,
    // Opt-in RFC 8985 tail loss probes; requires rack and sack configuration
    // and negotiated SACK. At most one probe per outstanding flight.
    pub tlp: bool,
    // Extra scheduling/granularity allowance for sampled multi-packet PTOs.
    // Default 2ms reduces spurious probes on very low-RTT paths; 0 selects
    // the RFC8985 section7.2 baseline. Always capped by the existing RTO.
    // Single-packet peer ACK budgets and the no-SRTT fallback are independent.
    pub tlp_timer_margin_us: u64,
    // Peer delayed-ACK budget, independent of our receive ACK policy. Default
    // covers RFC 9293's <500ms bound; tune only with knowledge of the peer.
    pub peer_max_ack_delay_us: u64,
    // RTT-derived RTO floor, 1..=60_000_000 us. Values below one second are an
    // explicit deviation from RFC 6298 section 2.4's SHOULD floor. Initial
    // RTO remains one second; the post-SYN-timeout three-second guard remains.
    pub rto_min_us: u64,
    pub retransmit_beyond_window: bool,
    pub delayed_ack_us: u64,
    // Opt-in receive-spacing policy; delayed_ack_us is its positive maximum.
    pub adaptive_ack: bool,
    // Default Linux-style standalone read updates: double the remaining
    // receive window. Ordinary ACKs and zero/sub-scale reopening retain
    // receiver SWS selection. False opts into eager one-MSS read updates.
    // Boolean policy has no invalid values; existing capacity/MSS validation applies.
    pub coalesce_read_window_updates: bool,
    // Per-connection fixed-window challenge budget, in microseconds.
    // ponytail: permits boundary bursts; use sliding windows if a rolling cap is needed.
    pub challenge_ack_limit: u32,
    pub challenge_ack_interval_us: u64,
    pub user_timeout_us: u64,
    // TIME-WAIT duration after an active close, and the tuple reservation
    // after a locally generated reset. The 120 s default lingers 2xMSL only
    // for a 60 s MSL, not RFC 9293's 2 minutes; Linux fixes 60 s
    // (TCP_TIMEWAIT_LEN), which ntcp-native's Linux defaults and the
    // packetdrill upstream profile configure. Any positive value may be
    // configured, a shorter one for example for benchmarks. RFC 6191
    // timestamp-based reuse applies within whatever duration is configured.
    pub time_wait_us: u64,
    pub keepalive: Option<KeepaliveConfig>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct KeepaliveConfig {
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
    //# This interval MUST be configurable (MUST-27) and MUST default to no less than
    //# two hours (MUST-28).
    pub idle_us: u64,
    pub interval_us: u64,
    pub probes: u32,
    pub send_garbage: bool,
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        Self {
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
            //# This interval MUST be configurable (MUST-27) and MUST default to no less
            //# than two hours (MUST-28).
            idle_us: 7_200_000_000,
            interval_us: 75_000_000,
            probes: 9,
            send_garbage: false,
        }
    }
}

impl ConnectionConfig {
    pub fn validate(&self, ipv4: bool) -> Result<(), Error> {
        if let Some(p) = self.pmtud {
            p.policy
                .search_aging
                .ticks(self.timebase.units_per_second)?;
            p.initial_values(self.initial_path_bound(p.first_hop_mtu, ipv4), ipv4)?;
            if !ipv4
                && [
                    p.route_mtu,
                    p.initial_mtu,
                    p.initial_search_low,
                    p.initial_search_high,
                ]
                .into_iter()
                .flatten()
                .any(|mtu| mtu < self.packetization_mtu_floor(false))
            {
                return Err(Error::InvalidArgument);
            }
        }
        if !self.valid_timestamp_timebase()
            || !self.valid_pacing()
            || self.timestamp_bytes_per_tick == 0
            || self.timestamp_bytes_per_tick >= 1 << 31
            || (self.tlp && (!self.rack || !self.sack))
            || !(1..=60_000_000).contains(&self.rto_min_us)
            || self.send_capacity == 0
            || self.send_capacity >= 1 << 30
            || self.send_capacity_min == 0
            || self.send_capacity_max >= 1 << 30
            || self.receive_capacity == 0
            || self.receive_capacity > (65535usize << 14)
            || self.receive_ip_payload_limit < 21
            || self.send_ip_payload_limit < self.minimum_send_budget()
            || self.user_mss == Some(0)
            || self.advertised_mss == Some(0)
            || self.mss == 0
            || self.mss > if ipv4 { 65495 } else { 65515 }
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.3
            //= reason=Configuration rejects delays of 500 ms or more; the driver must service deadlines.
            //# A TCP endpoint SHOULD implement a delayed ACK (SHLD-18), but an ACK
            //# should not be excessively delayed; in particular, the delay MUST be less
            //# than 0.5 seconds (MUST-40).
            || self.delayed_ack_us >= 500_000
            || (self.adaptive_ack && self.delayed_ack_us == 0)
            || self.challenge_ack_limit == 0
            || self.challenge_ack_interval_us == 0
            || self.user_timeout_us == 0
            // A zero TIME-WAIT would expire at the instant it begins, where
            // time_wait_valid already fails, and a timer serviced at that
            // instant before output would drop the ACK of the peer's FIN.
            // Any positive duration outlives that instant; a large one
            // saturates the deadline in ticks_from_us and saturating_add.
            || self.time_wait_us == 0
            || self
                .keepalive
                .is_some_and(|k| k.idle_us == 0 || k.interval_us == 0 || k.probes < 2)
        {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    //= https://www.rfc-editor.org/rfc/rfc1191#section-3.1
    //= reason=The receive offer is captured without routing-locality input: a managed connection's from its Host's per-family receive capability, a raw Endpoint's from configured receive ceilings, both intersected with user/advertised caps. Public Endpoint tests use authoritative single-address policies and equivalent /24 local/routed topologies, compare actual codec SYN/SYNACK offers above536 under four identical configurations, and retain receive capability after validated lower send-PMTU feedback in both directions. The continuation's host receive sizing and the connected-network note are covered separately at1191-024/025.
    //# Moreover, doing this prevents PMTU Discovery from discovering PMTUs larger than 576, so hosts SHOULD no longer lower the value they send

    //= https://www.rfc-editor.org/rfc/rfc1191#section-3.1
    //= reason=Managed connections send the MSS this paragraph describes. T13 supplies the host capacity: Host::reassembly_capacity states, per family and per Host context, EMTU_R (RFC 1122 section 3.3.2: the largest complete IP datagram, header included, that the configured, storage-backed reassembly engine accepts) and MMS_R (EMTU_R - 20 for IPv4, EMTU_R - 40 for IPv6). This paragraph calls the largest reassemblable datagram MMS_R, so its host MMS_R-40 is EMTU_R - 40, that is RFC 1122's MMS_R less TCP's 20-octet header for IPv4; the TCP payload unit (MSS) differs from both EMTU_R and MMS_R. T16 derives the managed receive MSS inside every Host factory transaction (active, Fast Open, passive child and TIME-WAIT replacement): Host::receive_ip_capability takes the least of EMTU_R (no term while reassembly is disabled), the largest live link enabled for the family at the smaller of its current MTU and physical receive capacity (the permitted maximum connected-link choice: a multi-homed Host counts its largest link, not the selected route's) and the family wire limit, less the IP and TCP base headers, so 65495 is offered exactly when an actual 65535-octet IPv4 link and matching reassembly support it; only user and advertised caps reduce it, a discovered send PMTU never does, and the offer is frozen once committed in its SYN or SYN-ACK. Host factory tests (ntcp-host src/tests/receive_capability.rs) cover both families, unequal links with per-link family enablement, link addition, removal and MTU change, new listener children after a topology change, separate contexts and source replacement, reassembly below and above the links and disabled, physical capacity below a link MTU, the 65535-octet IPv4 link and rejection without a capability. The supplied managed embeddings keep no static receive sizing: native SYN and SYN-ACK offers follow the Host's link (ntcp-socket packet_tests.rs) and tun_echo's equal Host::receive_ip_capability (tun_echo_pmtu_tests.rs). On the wire, the integration/rfc_host mss case's production-factory driver (src/bin/two_link.rs) owns two TUNs of unequal MTU with genuine reassembly and routes over the smaller: in both families the captured SYN-ACK and SYN offers over the smaller link equal the larger link's derivation, also for connections opened after real downstream PTBs lowered the send PMTU. Raw Endpoints keep their documented caller-supplied receive limits as an explicit legacy contract, on which this closure does not rest. The optional link-derived choice is not itself a required feature.
    //# in the MSS option. The MSS option should be 40 octets less than the size of the largest datagram the host is able to reassemble (MMS_R, as defined in [1]); in many cases, this will be the architectural limit of 65495 (65535 - 40) octets. A host MAY send an MSS value derived from the MTU of its connected network (the maximum MTU over its connected networks, for a multi-homed host); this should not cause problems for PMTU Discovery, and may dissuade a broken peer from sending enormous datagrams.
    fn receive_mss_offer(&self, capability: Option<u16>) -> u16 {
        // A managed connection's offer starts from its Host's receive
        // capability (already an MSS); `mss` (the local send and allocation
        // ceiling) and `receive_ip_payload_limit` keep limiting only the raw
        // Endpoint's legacy offer. User and advertised caps apply to both.
        capability
            .unwrap_or_else(|| self.mss.min(self.receive_ip_payload_limit - 20))
            .min(self.user_mss.unwrap_or(u16::MAX))
            .min(self.advertised_mss.unwrap_or(u16::MAX))
    }

    fn ack_timeout_floor(&self) -> u64 {
        self.timebase
            .ticks_from_us(self.delayed_ack_us.min(ACK_TIMEOUT_FLOOR_US))
    }

    fn initial_path_bound(&self, mtu: u32, ipv4: bool) -> u32 {
        let header = if ipv4 { 20 } else { 40 };
        let floor = min_mtu(ipv4);
        mtu.min((u32::from(self.send_ip_payload_limit) + header).max(floor))
            .min((u32::from(self.mss) + header + 20).max(floor))
    }

    pub(crate) fn valid_pacing(&self) -> bool {
        self.pacing.is_none_or(|p| {
            p.rate_gain_percent != 0
                && p.max_bytes_per_second != Some(0)
                && p.max_burst_segments != 0
                && p.max_burst_segments.checked_mul(self.mss as u32).is_some()
        })
    }

    pub(crate) fn valid_timestamp_timebase(&self) -> bool {
        self.timebase.valid()
    }

    pub(crate) fn packetization_mtu_floor(&self, ipv4: bool) -> u32 {
        if ipv4 {
            68
        } else {
            // Administrative limits must still fit the IPv6 header, enabled
            // TCP options and the same minimum data budget as normal output.
            40 + 20 + u32::from(self.timestamps) * 12 + u32::from(self.sack) * 12 + 8
        }
    }

    pub(crate) fn minimum_send_budget(&self) -> u16 {
        if self.timestamps && self.sack {
            44
        } else if self.timestamps {
            40
        } else if self.sack {
            32
        } else {
            28
        }
    }
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            send_capacity: 65536,
            receive_capacity: 65536,
            // Linux's tcp_wmem[0], PAGE_SIZE.
            send_capacity_min: 4096,
            send_capacity_max: 65536,
            mss: 1460,
            user_mss: None,
            advertised_mss: None,
            pmtud: None,
            receive_ip_payload_limit: u16::MAX,
            send_ip_payload_limit: u16::MAX,
            nagle: true,
            ecn: true,
            ecn_initiate: true,
            recovery_algorithm: RecoveryAlgorithm::default(),
            congestion_algorithm: CongestionAlgorithm::default(),
            cubic_hystart: true,
            cubic_fast_convergence: true,
            initial_window: InitialWindow::default(),
            abort_with_ack: false,
            fast_open_early_response: false,
            output_group_flush: false,
            timestamps: false,
            timestamp_granularity: TimestampGranularity::default(),
            timebase: CallerTimebase::default(),
            timestamp_bytes_per_tick: (1 << 30) - 1,
            sack: false,
            rack: false,
            prr: false,
            prr_pacing: true,
            pacing: None,
            tlp: false,
            tlp_timer_margin_us: 2_000,
            peer_max_ack_delay_us: 499_999,
            rto_min_us: 1_000_000,
            retransmit_beyond_window: false,
            delayed_ack_us: 200_000,
            adaptive_ack: false,
            coalesce_read_window_updates: true,
            challenge_ack_limit: 100,
            challenge_ack_interval_us: 1_000_000,
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
            //= reason=Default R2; applications may override the per-connection timeout.
            //# The value of R2 SHOULD correspond to at least 100 seconds (SHLD-11).
            user_timeout_us: 300_000_000,
            time_wait_us: 120_000_000,
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
            //# If keep-alives are included, the application MUST be able to turn them
            //# on or off for each TCP connection (MUST-24), and they MUST default to
            //# off (MUST-25).
            keepalive: None,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Tuple {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

/// A canonical tuple with the link that scopes it. The zone is present
/// exactly when either address is IPv6 link-local, whose identity is only
/// meaningful on one link (RFC 4007 section 6), so identical link-local
/// address and port pairs on two links are two connections. Unscoped tuples
/// carry no zone and keep their exact identity.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ScopedTuple {
    pub(crate) tuple: Tuple,
    pub(crate) zone: Option<ntcp_path::LinkId>,
}
impl ScopedTuple {
    /// `None` unless `zone` is present exactly when an address of `tuple`
    /// is IPv6 link-local.
    pub fn new(tuple: Tuple, zone: Option<ntcp_path::LinkId>) -> Option<Self> {
        (needs_zone(tuple) == zone.is_some()).then_some(Self { tuple, zone })
    }
    pub const fn tuple(self) -> Tuple {
        self.tuple
    }
    pub const fn zone(self) -> Option<ntcp_path::LinkId> {
        self.zone
    }
    // The identity of a raw (unmanaged) tuple, whose addresses have no link
    // authority: never scoped.
    pub(crate) const fn unscoped(tuple: Tuple) -> Self {
        Self { tuple, zone: None }
    }
}

pub(crate) fn link_local(address: core::net::IpAddr) -> bool {
    matches!(address, core::net::IpAddr::V6(ip) if ip.is_unicast_link_local())
}

pub(crate) fn needs_zone(tuple: Tuple) -> bool {
    link_local(tuple.local.ip()) || link_local(tuple.remote.ip())
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum LossTimer {
    Rack,
    Pto,
    Rto,
    Zwp,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum State {
    Closed,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

// Core diagnostics, not a platform TCP_INFO ABI. Windows and queues use bytes;
// times use microseconds. Counts identify original successful data segments:
// split intervals retain their identity. SACK counts require complete delivery;
// loss/retransmission counts include outstanding fragments. SACKed data remains
// unacked until cumulative ACK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportInfo {
    pub state: State,
    pub recovery: bool,
    // Active ECN congestion-response epoch, not negotiation or pending CWR output.
    pub ecn_response: bool,
    pub loss: bool,
    // False only after explicit diagnostic abandonment; capacity-backed production flights retain every byte interval.
    pub ledger_valid: bool,
    pub timestamps_negotiated: bool,
    pub sack_negotiated: bool,
    pub window_scaling_negotiated: bool,
    // Effective peer/local shifts, zero when window scaling was not negotiated.
    pub send_window_scale: u8,
    pub receive_window_scale: u8,
    // Bilateral setup permitting ECN sending, independent of the CWR epoch.
    pub ecn_negotiated: bool,
    // Initial handshake acknowledged a positive prefix actually sent in SYN.
    pub syn_data_acked: bool,
    // Active: initial handshake ACK covers the entire original SYN payload.
    // Passive: authenticated early data has been acknowledged on the wire.
    // Linux TCPI_OPT_SYN_DATA excludes partial active-open progress.
    pub syn_data_fully_acked: bool,
    // Saturating one-shot ACK/SACK delivery of queued packetization units,
    // including SYN/standalone FIN, not bytes or every physical retry copy.
    // Resegmentation updates unit boundaries; repeated SACK/ACK cannot renew credit.
    pub delivered_segments: u64,
    // False only after diagnostic ledger/inference abandonment. Partial
    // retransmission and mixed prior SACK credit keep exact delivery units.
    // Recovery's ledger_valid is independent and can remain true.
    pub delivered_segments_valid: bool,
    pub unacked: u32,
    pub sacked: u32,
    // Original loss attribution persists through retransmission until delivery.
    pub lost: u32,
    // Outstanding, non-lost retransmissions, excluding SACKed retransmissions.
    pub retransmitted: u32,
    // Cumulative over the connection's life: segments sent carrying
    // retransmitted sequence space, as LossCounters::retransmitted_segments
    // counts them: Linux's tcpi_total_retrans.
    pub total_retrans: u64,
    pub reordering: u32,
    // Saturating observed reordering detections for never-retransmitted
    // original data. SACK and cumulative hole filling each count once per
    // ACK; interval splits and repeated advice add no events. Separate DSACK
    // adaptation and non-SACK duplicate-ACK heuristics are not counted.
    pub reordering_events: u64,
    // Local resource timer attempts, independent of wire transmission and RTO.
    pub resource_probes: u32,
    pub rto_backoff: u32,
    pub cwnd: u32,
    pub ssthresh: u32,
    pub mss: u32,
    // Current observed incoming full-segment payload estimate, not the peer MSS offer.
    pub received_mss: u32,
    // Receive MSS offer, without TCP option overhead or the peer's send limit.
    pub advertised_mss: u32,
    // Largest accepted peer window, in bytes; useful for bounded host batching.
    pub max_send_window: u32,
    pub rtt_us: Option<u64>,
    // Windowed minimum of accepted RTT samples, in microseconds. None means
    // no sample; a measured zero remains Some(0). Sampling, not querying,
    // ages the minimum as in the RACK estimator.
    pub min_rtt_us: Option<u64>,
    pub rttvar_us: u64,
    pub rto_us: u64,
    // Queued payload not yet first-transmitted; SYN/FIN and retransmissions excluded.
    pub notsent_bytes: usize,
    // Elapsed caller-clock milliseconds since establishment or last newly accepted
    // payload (including out-of-order bytes); ACKs, FINs and duplicates do not reset it.
    pub last_data_recv_ms: u32,
    // Pending payload/FIN time, including the mutually exclusive limited intervals.
    pub busy_time_us: u64,
    pub rwnd_limited_us: u64,
    // Actual byte-buffer backpressure, not Linux skb memory accounting.
    pub sndbuf_limited_us: u64,
    pub send_used: usize,
    pub send_capacity: usize,
    // Ceiling on unacknowledged plus queued payload: send_capacity rounded
    // down to whole segments for a managed connection. send_used may exceed
    // it after it shrinks; those bytes stay queued.
    pub send_space: usize,
    pub receive_used: usize,
    pub receive_capacity: usize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CloseReason {
    Normal,
    Reset,
    Aborted,
    TimedOut,
    NetworkError,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NetworkError {
    SoftUnreachable,
    HardUnreachable,
    TimeExceeded,
    ParameterProblem,
    SourceQuench,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    WouldBlock,
    InvalidState,
    InvalidArgument,
    NoMemory,
    OutputTooSmall,
    TimeWentBackwards,
    AmbiguousTimeJump,
    TimestampBudgetExceeded,
    Wire(wire::WireError),
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ConnectionEvents {
    pub connected: bool,
    pub readable: bool,
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.3
    //# A TCP receiver MAY pass a received PSH bit to the application layer
    //# via the PUSH flag in the interface (MAY-17), but it is not required
    //# (this was clarified in RFC 1122, Section 4.2.2.2).
    pub pushed: bool,
    pub writable: bool,
    pub acknowledged: Option<u64>,
    pub half_closed: bool,
    pub closed: Option<CloseReason>,
    pub urgent: Option<u64>,
    pub retransmission_warning: bool,
    pub network_error: Option<NetworkError>,
    // One notification per connection, coalesced in the existing bounded event queue.
    pub invalid_window_scale: Option<u8>,
    // A TX timestamp observation became ready to take with next_tx_timestamp.
    pub tx_timestamps: bool,
}

impl ConnectionEvents {
    pub(crate) fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

fn due(deadline: Option<Instant>, now: Instant) -> bool {
    deadline.is_some_and(|deadline| now >= deadline)
}

// RFC 1191 section 6.4: the greatest multiple of the segment size in use
// not above the sender's buffer space, so no partial segment is left over.
// A legal buffer below one segment keeps its whole capacity: the literal
// multiple, zero, would deadlock it, and the peer and congestion windows
// still bound what is outstanding.
fn rounded_send_space(capacity: usize, quantum: usize) -> usize {
    if capacity < quantum {
        capacity
    } else {
        capacity / quantum * quantum
    }
}

// One initial/restart burst, not a duplicate original-transmission ledger.
#[derive(Clone, Copy, Debug)]
struct IwEpoch {
    start: Seq,
    end: Seq,
    // Probe ACKs cannot validate the ordinary restart flight. Its first byte
    // is recorded separately from the complete (possibly probe-led) range.
    fresh_start: Option<Seq>,
    bytes: u32,
    open: bool,
    lost: bool,
}

#[derive(Copy, Clone, Debug)]
struct LocalResource {
    retry_at: Option<Instant>,
    epoch: Option<Instant>,
}

#[derive(Copy, Clone, Debug)]
struct SackRecovery {
    // All sequence markers are exclusive, unlike the RFC's inclusive octets.
    recovery_point: Seq,
    high_rxt: Seq,
    rescue_rxt: Option<Seq>,
    entry_pending: bool,
    pipe: u32,
}

struct DeferredSyn {
    received_at: Instant,
    urgent: Option<u64>,
}

pub(crate) struct Connection {
    pub(crate) managed_path: Option<crate::PreparedPath>,
    pub(crate) managed_results: crate::endpoint::ManagedResults,
    tuple: Tuple,
    // The link scoping `tuple`; set by the Endpoint before insertion.
    zone: Option<ntcp_path::LinkId>,
    config: ConnectionConfig,
    state: State,
    reason: Option<CloseReason>,
    events: ConnectionEvents,
    now: Instant,
    send: SendBuffer,
    receive: ReceiveBuffer,
    scratch: Vec<u8>,
    iss: Seq,
    irs: Option<Seq>,
    passive_open: bool,
    fast_open: Option<wire::FastOpenCookie>,
    // A crossing SYN's locally issued response never replaces our peer cookie.
    fast_open_response: Option<wire::FastOpenCookie>,
    fast_open_response_committed: bool,
    fast_open_client_policy: crate::FastOpenClientPolicy,
    // Physical option provenance is independent of early-send authorization.
    fast_open_option_sent: bool,
    fast_open_initial: usize,
    fast_open_attempt: bool,
    pub(crate) fast_open_negative: bool,
    // Physical SYN acceptance, separate from attempted/queued Fast Open data.
    syn_payload_sent: usize,
    syn_data_acked: bool,
    syn_data_fully_acked: bool,
    // First actually stored authenticated SYN byte, independent of reads and
    // active/passive open role. Its exclusive ACK is sufficient departure proof.
    received_syn_data_start: Option<Seq>,
    syn_delivered: bool,
    fin_delivered: bool,
    fin_needs_separate_credit: bool,
    deferred_tfo_push: bool,
    fast_open_retry: Option<(Seq, Seq)>,
    pub(crate) fast_open_early: bool,
    pub(crate) fast_open_peer_reset: bool,
    pub(crate) fast_open_learned: Option<(Option<wire::FastOpenCookie>, Option<u16>)>,
    snd_una: Seq,
    snd_nxt: Seq,
    send_base: Seq,
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //= reason=Send windows use u32; receive_window derives u32 width from Seq-backed advertised_edge.
    //# It is RECOMMENDED that implementations will reserve 32-bit fields for the send
    //# and receive window sizes in the connection record and do all window computations
    //# with 32 bits (REC- 1).
    snd_wnd: u32,
    max_snd_wnd: u32,
    wl1: Seq,
    wl2: Seq,
    local_scale: u8,
    peer_scale: u8,
    scaling: bool,
    timestamps: bool,
    timestamp_offset: u32,
    // Inclusive wire TSval bounds from accepted active-open SYNs, not selection.
    syn_timestamp_range: Option<(u32, u32)>,
    timestamp_tick: u64,
    timestamp_bytes: u32,
    invalid_scale_reported: bool,
    iw_epoch: Option<IwEpoch>,
    iw_started: bool,
    iw_fallback: bool,
    iw_setup_loss: bool,
    syn_loss_detected: bool,
    syn_retransmissions: u32,
    handshake_retransmission_limit: Option<NonZeroU8>,
    committed_syn_retransmissions: u8,
    // Segments sent carrying retransmitted sequence space, over the
    // connection's life (`TransportInfo::total_retrans`).
    total_retrans: u64,
    // Loss events the endpoint has not yet taken into its LossCounters, at
    // the connection's refresh or reclaim.
    pub(crate) loss_events: crate::LossCounters,
    syn_committed: bool,
    sack_send: bool,
    sack_receive: bool,
    sack_recovery: Option<SackRecovery>,
    sack_guard: Option<Seq>,
    // Retransmitted prefix and fixed data boundary at the most recent timeout.
    // Without SACK recovery the prefix is a go-back-N frontier: the timed-out
    // flight is resent in order under slow start (RFC 6582 section 4).
    sack_post_rto: Option<(Seq, Seq)>,
    sack_fallback: Option<Seq>,
    scoreboard: Scoreboard,
    rack: Rack,
    tlp_deadline: Option<Instant>,
    tlp_pending: bool,
    // Retain a retransmitted probe at equality until DSACK/duplicate ACK or
    // an ACK beyond its end resolves the RFC 8985 section 7.4.2 ambiguity.
    tlp_end: Option<(Seq, Seq, bool)>,
    tlp_flight: Option<Seq>,
    tlp_fresh_rtt: bool,
    prr: Option<Prr>,
    // Legacy eligibility time, or latest general-pacer wakeup. Fractional
    // general-pacing debt lives separately and survives servicing this timer.
    pacing_deadline: Option<Instant>,
    pacer: Pacer,
    initial_pacing_open: bool,
    receive_used: usize,
    deferred_syn: Option<DeferredSyn>,
    sack_omit: bool,
    sack_data_turn: bool,
    ts_recent: u32,
    ts_latest: u32,
    ts_recent_at: Instant, // Last R3/handshake refresh; pending ACKs do not extend PAWS age.
    last_ack_sent: Seq,
    reset_echo: Option<u32>,
    reset_reply: bool,
    last_timestamp_sent_at: Option<Instant>,
    // A substantiated suspend left the next TSval older than what the peer
    // may hold: no further output, and the next timeout service ends this.
    timestamp_ambiguous: bool,
    mss: usize,
    peer_mss: u16,
    receive_mss_offer: u16,
    // Managed only: the MSS of the Host's receive capability derived when
    // this connection was constructed, kept so that a user MSS set before
    // the SYN commits composes with it.
    receive_capability: Option<u16>,
    send_mss_limit: u16,
    ip_header_len: u16,
    //= https://www.rfc-editor.org/rfc/rfc4821#section-5.2
    //= reason=Pmtud is stored on the individual Connection, not indexed by remote network or subnet number. A paired connection test leaves the peer PMTUD-disabled while updating only the sender; no route-mask representation is used.
    //# Network or subnet numbers MUST NOT be used as representations of a path, because
    //# there is not a general mechanism to determine the network mask at the remote host.
    pmtud: Option<crate::pmtud::Pmtud>,
    advertised_edge: Seq,
    syn_window: u16,
    acknowledged: u64,
    pub(crate) tx_timestamps: TxTimestamps,
    pub(crate) last_output_range: Option<TxStreamRange>,
    pub(crate) last_departure: Option<Departure>,
    // The intent of the PLPMTUD probe `last_departure` sends, if it is one.
    pub(crate) last_discovery: Option<crate::DiscoveryIntent>,
    // Optional timing evidence, separate from the retained output obligation.
    reserved_ledger: Option<crate::rack::DepartureSelection>,
    repair_undo: Option<RepairUndo>,
    control_undo: Option<ControlUndo>,
    ptb: PtbRepair,
    local_resource: Option<LocalResource>,
    resource_probes: u32,
    reserved_retransmit_counts: Option<crate::rack::Counts>,
    last_pmtu_output: Option<(Seq, Seq)>,
    pub(crate) rx_timestamps: RxTimestamps,
    input_timestamps: RxPacketTimestamps,
    input_segment_size: Option<core::num::NonZeroU16>,
    received_mss: crate::receive_metadata::ReceiveMss,
    received_read: u64,
    received_total: u64,
    snd_up: Option<Seq>,
    advertised_snd_up: Option<Seq>,
    rcv_up: Option<u64>,
    handshake_complete: bool,
    send_issued: bool,
    shutdown: bool,
    read_closed: bool,
    fin_sequence: Option<Seq>,
    fin_sent_at: Option<Instant>,
    // Distinguish standalone FIN from data+FIN even at the same caller instant.
    fin_standalone: bool,
    syn_pending: bool,
    ack_pending: bool,
    ack_ato: u64,
    // The boolean distinguishes the establishment seed from the first data sample.
    ack_receive: Option<(Instant, bool)>,
    // A waiting Fast Open writer can initialize ATO without stream receive history.
    ack_engine_initialized: bool,
    fast_open_write_pending: bool,
    ack_quick: u8,
    ack_interactive: bool,
    challenge_ack_pending: bool,
    challenge_ack_start: Option<Instant>,
    challenge_ack_sent: u32,
    pending_rst: Option<(Seq, bool)>,
    retx_pending: bool,
    duplicate_acks: u8,
    limited_pending: bool,
    limited_sent: u32,
    limited_end: Option<Seq>,
    // Earlier no-SACK delivery estimates, consumed only by real data ACKs.
    // Independent of Limited Transmit grants and recovery's PRR counters.
    growth_dupack_bytes: u32,
    probe_pending: bool,
    keepalive_pending: bool,
    rtt: RttEstimator,
    congestion: Congestion,
    ecn_sent_setup: bool,
    ecn_sent_plain: bool,
    ecn_peer_setup: bool,
    ecn_peer_plain: bool,
    ecn_echo: bool,
    ecn_ce_end: Option<Seq>,
    ecn_cwr_pending: bool,
    ecn_pause: Option<Instant>,
    // Independent of RTT sampling and loss RTO backoff: (flight end, interval).
    ecn_backoff: Option<(Seq, u64)>,
    last_output_ecn: u8,
    pub(crate) accepted_metadata: bool,
    // Set by the Endpoint for the input of an unaccepted passive child whose
    // listener's accept queue is full: the ACK that would complete the
    // handshake is dropped, `establishment_held` raised, and the child stays
    // in SYN-RECEIVED to retransmit its SYN-ACK.
    pub(crate) hold_establishment: bool,
    pub(crate) establishment_held: bool,
    sample: Option<(Seq, Instant)>,
    // Reserved control RTT uses physical departure; sample's time still names
    // the immutable wire TSval for ordinary RTTM echo validation.
    sample_departure: Option<Instant>,
    rtt_sample_after: Option<Instant>,
    // When the SYN last left: the departure its acknowledgment delivers,
    // which RACK, tracking payload only, does not record.
    syn_sent_at: Option<Instant>,
    syn_timed_out: bool,
    consecutive_timeouts: u32,
    route_advice_pending: bool,
    // Unarmed RFC 6298 reference expiration, retained for PTO cap/fallback.
    rto_deadline: Option<Instant>,
    loss_timer: Option<(LossTimer, Instant)>,
    ack_deadline: Option<Instant>,
    unacked_segments: u8,
    unacked_bytes: u32,
    persist_deadline: Option<Instant>,
    persist_interval: u64,
    persist_unanswered_since: Option<Instant>,
    shrink_unanswered_since: Option<Instant>,
    sws_deadline: Option<Instant>,
    sws_override: bool,
    cork: bool,
    more: bool,
    cork_deadline: Option<Instant>,
    // Explicit flush covers only bytes already queued, not future corked writes.
    cork_flush: Option<Seq>,
    time_wait_deadline: Option<Instant>,
    progress_at: Instant,
    application_timeout_us: Option<u64>,
    application_progress_at: Instant,
    last_received: Instant,
    last_data_received: Instant,
    // Caller ticks retain sub-microsecond fractions across state transitions.
    transport_ticks: [u64; 3],
    send_backpressured: bool,
    // The bytes a write's storage growth needed when the buffer budget or
    // the allocator refused it, as Linux's tcp_sendmsg finds
    // sk_wmem_schedule fail and waits in sk_stream_wait_memory. Until memory
    // comes back (`memory_released`) or a later write's growth succeeds,
    // writes take only what the allocated storage holds, and the connection
    // is not writable beyond it.
    send_memory_wanted: Option<usize>,
    // Whether memory pressure applies to the send direction
    // (`ConnectionConfig::send_capacity_max`), and the floor it moderates
    // the send limit to.
    send_tuned: bool,
    send_min: usize,
    // Successful data output only; ACKs and keepalives do not restart data-idle time.
    last_sent: Instant,
    retransmit_burst: Option<(Seq, u32)>,
    keepalive_deadline: Option<Instant>,
    keepalive_probes: u32,
}

impl Connection {
    #[cfg(test)]
    pub(crate) fn active(
        tuple: Tuple,
        config: ConnectionConfig,
        iss: u32,
        now: Instant,
    ) -> Result<Self, Error> {
        Self::active_with_receive(tuple, config, iss, now, &mut None)
    }

    //= https://www.rfc-editor.org/rfc/rfc8201#section-1
    //= reason=Shared active/passive construction caps only the disabled IPv6 send IP-payload budget at the minimum link MTU minus the supported base header, preserving smaller caller limits, receive capability and configured storage. Actual codec/peer tests cover boundary-sized scalar, reserved, shared and coalesced output, options, RTO repair, Fast Open, live MSS updates and TIME-WAIT reopening; enabled discovery retains larger packets and validated growth. Smaller packets can cost throughput; discovery defaults are unchanged.
    //# Nodes not implementing Path MTU Discovery must use the IPv6 minimum link MTU
    //# defined in [RFC8200] as the maximum packet size. In most cases, this will result
    //# in the use of smaller packets than necessary, because most paths have a PMTU
    //# greater than the IPv6 minimum link MTU. A node sending packets much smaller than
    //# the Path MTU allows is wasting network resources and probably getting
    //# suboptimal throughput.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-4
    //= reason=Constructor rejects TLP unless both RACK and SACK are configured; runtime additionally requires negotiated SACK.
    //# TLP requires RACK.
    #[cfg(test)]
    pub(crate) fn active_with_receive(
        tuple: Tuple,
        config: ConnectionConfig,
        iss: u32,
        now: Instant,
        receive: &mut Option<ReceiveBuffer>,
    ) -> Result<Self, Error> {
        Self::active_with_receive_path(tuple, config, iss, now, receive, None, None, None)
            .map(|connection| *connection)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn active_with_receive_path(
        tuple: Tuple,
        mut config: ConnectionConfig,
        iss: u32,
        now: Instant,
        receive: &mut Option<ReceiveBuffer>,
        managed_path: Option<crate::PreparedPath>,
        receive_capability: Option<crate::ReceiveIpCapability>,
        initial_ip_header_len: Option<u16>,
    ) -> Result<Box<Self>, Error> {
        config.validate(tuple.local.is_ipv4())?;
        if tuple.local.is_ipv4() != tuple.remote.is_ipv4() {
            return Err(Error::InvalidArgument);
        }
        // A managed connection receives under its Host's derived capability
        // for this family; a raw one under its configured legacy limits.
        if managed_path.is_some() != receive_capability.is_some()
            || receive_capability.is_some_and(|c| c.ipv6() == tuple.local.is_ipv4())
        {
            return Err(Error::InvalidState);
        }
        let receive_capability = receive_capability.map(crate::ReceiveIpCapability::mss);
        // Non-jumbo family limits include the TCP header, not the IP header.
        let family_limit = if tuple.local.is_ipv4() { 65515 } else { 65535 };
        config.receive_ip_payload_limit = config.receive_ip_payload_limit.min(family_limit);
        config.send_ip_payload_limit = config.send_ip_payload_limit.min(family_limit);
        if !tuple.local.is_ipv4() && config.pmtud.is_none() {
            // Without discovery, a legal minimum-MTU path must carry every
            // packet. This send budget includes TCP options, but excludes the
            // supported base IPv6 header; receive offers and storage stay independent.
            config.send_ip_payload_limit = config
                .send_ip_payload_limit
                .min((min_mtu(false) - 40) as u16);
        }
        let send = SendBuffer::unallocated(config.send_capacity);
        let send_tuned = config.send_capacity_max > config.send_capacity;
        let send_min = config.send_capacity_min.min(config.send_capacity);
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(config.mss as usize)
            .map_err(|_| Error::NoMemory)?;
        scratch.resize(config.mss as usize, 0);
        //= https://www.rfc-editor.org/rfc/rfc7323#section-2.1
        //= reason=Capacity-derived exponent is frozen after first successful SYN output; maximum negotiated true window bounded by receive allocation.
        //# The maximum receive window, and therefore the scale factor, is
        //# determined by the maximum receive buffer space.
        let local_scale = (0..=14)
            .find(|&shift| config.receive_capacity <= (65535usize << shift))
            .unwrap_or(14);
        let syn_window = config.receive_capacity.min(65535) as u16;
        let ip_header_len = initial_ip_header_len.unwrap_or(if tuple.local.is_ipv4() { 20 } else { 40 });
        let pmtud = config
            .pmtud
            .map(|mut p| {
                p.policy.ipv4_plateaus = p.policy.ipv4_plateaus.for_path(managed_path);
                crate::pmtud::Pmtud::new(
                    p,
                    config.initial_path_bound(p.first_hop_mtu, tuple.local.is_ipv4()),
                    tuple.local.is_ipv4(),
                    config.timebase.ticks_from_us(600_000_000),
                )
                .map(|mut pmtud| {
                    // The binding delivers the path's administrative policy.
                    if let Some(path) = managed_path {
                        pmtud.set_policy_revision(path.snapshot.discovery_revision());
                        pmtud.set_discovery_disabled(path.snapshot.discovery_disabled());
                        pmtud.set_administrative(path.snapshot.administrative_estimate());
                        pmtud.set_shared_estimate(path.snapshot.pmtu_estimate().ok());
                    }
                    pmtud
                })
            })
            .transpose()?;
        let mss = config
            .mss
            .min(config.user_mss.unwrap_or(u16::MAX))
            .min(config.send_ip_payload_limit - 20) as usize;
        let mss = if managed_path.is_some() {
            mss.saturating_sub(usize::from(ip_header_len) - if tuple.local.is_ipv4() { 20 } else { 40 }).max(1)
        } else { mss };
        let mss = pmtud.as_ref().map_or(mss, |p| {
            mss.min(
                p.info
                    .current_mtu
                    .saturating_sub(u32::from(ip_header_len) + 20)
                    .max(1) as usize,
            )
        });
        let mss = managed_path.map_or(mss, |path| {
            mss.min(path.snapshot.ip_packet_budget().unwrap()
                .saturating_sub(u32::from(ip_header_len) + 20).max(1) as usize)
        });
        let congestion = Congestion::new(
            mss as u32,
            config.recovery_algorithm,
            config.initial_window,
            Seq(iss),
        )
        .with_congestion(config.congestion_algorithm, config.timebase)
        .with_cubic_hystart(config.cubic_hystart)
        //= https://www.rfc-editor.org/rfc/rfc9438#section-4.7
        //= reason=Shared active/passive construction forwards caller-selected fast convergence. Known isolated-single-flow policy is supplied by caller; no topology inference.
        //# In network environments with only a single CUBIC flow
        //# and without any other traffic, fast convergence SHOULD be disabled.
        .with_cubic_fast_convergence(config.cubic_fast_convergence);
        //= https://www.rfc-editor.org/rfc/rfc6928#section-2
        //= reason=All initial-window choices share RFC6298 estimator and connection timer/sampling implementation. Default/configured >=1s floors retain the recommended floor; explicit subsecond Linux compatibility is a scoped departure, not universal inherited conformance.
        //# Implementations must also follow RFC 6298 [RFC6298] in order to avoid spurious RTO as described in Section 9.
        let rtt = RttEstimator::with_timebase(config.rto_min_us, config.timebase);
        let rack = Rack::with_timebase(2, config.timebase).map_err(|_| Error::NoMemory)?;
        let scoreboard = Scoreboard::with_capacity(0).map_err(|_| Error::NoMemory)?;
        let storage = Self::storage()?;
        // Take pooled storage only after every fallible allocation has succeeded.
        let receive = match receive.take() {
            Some(receive) => receive,
            None => {
                ReceiveBuffer::new(Seq(0), config.receive_capacity).map_err(|_| Error::NoMemory)?
            }
        };
        let timestamp_tick = config.timestamp_granularity.tick_in(now, config.timebase);
        let ack_ato = config.ack_timeout_floor();
        let connection = Self {
            managed_path,
            managed_results: crate::endpoint::ManagedResults::default(),
            tuple,
            zone: None,
            peer_mss: config.mss,
            receive_mss_offer: config.receive_mss_offer(receive_capability),
            received_mss: crate::receive_metadata::ReceiveMss::new(config.receive_mss_offer(receive_capability)),
            receive_capability,
            send_mss_limit: config.mss,
            ip_header_len,
            pmtud,
            config,
            state: State::SynSent,
            reason: None,
            events: ConnectionEvents::default(),
            now,
            send,
            receive,
            scratch,
            iss: Seq(iss),
            irs: None,
            passive_open: false,
            fast_open: None,
            fast_open_response: None,
            fast_open_response_committed: false,
            fast_open_client_policy: crate::FastOpenClientPolicy::RequireCookie,
            fast_open_option_sent: false,
            fast_open_initial: 0,
            fast_open_attempt: false,
            fast_open_negative: false,
            syn_payload_sent: 0,
            syn_data_acked: false,
            syn_data_fully_acked: false,
            received_syn_data_start: None,
            syn_delivered: false,
            fin_delivered: false,
            fin_needs_separate_credit: false,
            deferred_tfo_push: false,
            fast_open_retry: None,
            fast_open_early: false,
            fast_open_peer_reset: false,
            fast_open_learned: None,
            snd_una: Seq(iss),
            snd_nxt: Seq(iss),
            send_base: Seq(iss).wrapping_add(1),
            snd_wnd: 0,
            max_snd_wnd: 0,
            wl1: Seq(0),
            wl2: Seq(0),
            local_scale,
            peer_scale: 0,
            scaling: false,
            timestamps: false,
            timestamp_offset: 0,
            syn_timestamp_range: None,
            timestamp_tick,
            timestamp_bytes: 0,
            invalid_scale_reported: false,
            iw_epoch: None,
            iw_started: false,
            iw_fallback: false,
            iw_setup_loss: false,
            syn_loss_detected: false,
            syn_retransmissions: 0,
            handshake_retransmission_limit: None,
            committed_syn_retransmissions: 0,
            total_retrans: 0,
            loss_events: crate::LossCounters::default(),
            syn_committed: false,
            sack_send: false,
            sack_receive: false,
            sack_recovery: None,
            sack_guard: None,
            sack_post_rto: None,
            sack_fallback: None,
            scoreboard,
            rack,
            tlp_deadline: None,
            tlp_pending: false,
            tlp_end: None,
            tlp_flight: None,
            tlp_fresh_rtt: false,
            prr: None,
            pacing_deadline: None,
            pacer: Pacer::default(),
            initial_pacing_open: true,
            receive_used: 0,
            deferred_syn: None,
            sack_omit: false,
            sack_data_turn: false,
            ts_recent: 0,
            ts_latest: 0,
            ts_recent_at: now,
            last_ack_sent: Seq(0),
            reset_echo: None,
            reset_reply: false,
            last_timestamp_sent_at: None,
            timestamp_ambiguous: false,
            mss,
            advertised_edge: Seq(0),
            syn_window,
            acknowledged: 0,
            tx_timestamps: TxTimestamps::default(),
            last_output_range: None,
            last_departure: None,
            last_discovery: None,
            reserved_ledger: None,
            repair_undo: None,
            control_undo: None,
            ptb: PtbRepair::default(),
            local_resource: None,
            resource_probes: 0,
            reserved_retransmit_counts: None,
            last_pmtu_output: None,
            rx_timestamps: RxTimestamps::default(),
            input_timestamps: RxPacketTimestamps::default(),
            input_segment_size: None,
            received_read: 0,
            received_total: 0,
            snd_up: None,
            advertised_snd_up: None,
            rcv_up: None,
            handshake_complete: false,
            send_issued: false,
            shutdown: false,
            read_closed: false,
            fin_sequence: None,
            fin_sent_at: None,
            fin_standalone: false,
            syn_pending: true,
            ack_ato,
            ack_receive: None,
            ack_engine_initialized: false,
            fast_open_write_pending: false,
            ack_quick: 0,
            ack_interactive: false,
            ack_pending: false,
            challenge_ack_pending: false,
            challenge_ack_start: None,
            challenge_ack_sent: 0,
            pending_rst: None,
            retx_pending: false,
            duplicate_acks: 0,
            limited_pending: false,
            limited_sent: 0,
            limited_end: None,
            growth_dupack_bytes: 0,
            probe_pending: false,
            keepalive_pending: false,
            rtt,
            congestion,
            ecn_sent_setup: false,
            ecn_sent_plain: false,
            ecn_peer_setup: false,
            ecn_peer_plain: false,
            ecn_echo: false,
            ecn_ce_end: None,
            ecn_cwr_pending: false,
            ecn_pause: None,
            ecn_backoff: None,
            last_output_ecn: 0,
            accepted_metadata: false,
            hold_establishment: false,
            establishment_held: false,
            sample: None,
            sample_departure: None,
            rtt_sample_after: None,
            syn_sent_at: None,
            syn_timed_out: false,
            consecutive_timeouts: 0,
            route_advice_pending: false,
            rto_deadline: None,
            loss_timer: None,
            ack_deadline: None,
            unacked_segments: 0,
            unacked_bytes: 0,
            persist_deadline: None,
            persist_interval: 0,
            persist_unanswered_since: None,
            shrink_unanswered_since: None,
            sws_deadline: None,
            sws_override: false,
            cork: false,
            more: false,
            cork_deadline: None,
            cork_flush: None,
            time_wait_deadline: None,
            progress_at: now,
            application_timeout_us: None,
            application_progress_at: now,
            last_received: now,
            last_data_received: now,
            transport_ticks: [0; 3],
            send_backpressured: false,
            send_memory_wanted: None,
            send_tuned,
            send_min,
            last_sent: now,
            retransmit_burst: None,
            keepalive_deadline: None,
            keepalive_probes: 0,
        };
        Ok(Box::write(storage, connection))
    }

    // A connection's heap home. The ~10 KB value is copied into it once, and
    // from then on only the pointer moves: through the endpoint's
    // constructors into its slot and out at reclaim. Fallible, as every
    // other allocation of a connection is: Box::new aborts when memory runs
    // out.
    fn storage() -> Result<Box<MaybeUninit<Self>>, Error> {
        let layout = core::alloc::Layout::new::<Self>();
        // SAFETY: a Connection is not zero-sized.
        let pointer = unsafe { alloc::alloc::alloc(layout) }.cast::<MaybeUninit<Self>>();
        if pointer.is_null() {
            return Err(Error::NoMemory);
        }
        // SAFETY: allocated by the global allocator with the layout Box uses
        // for this type; a MaybeUninit needs no initialization.
        Ok(unsafe { Box::from_raw(pointer) })
    }

    #[cfg(test)]
    pub(crate) fn passive(
        tuple: Tuple,
        config: ConnectionConfig,
        iss: u32,
        now: Instant,
        syn: &Segment<'_>,
    ) -> Result<Self, Error> {
        Self::passive_with_receive(
            tuple,
            config,
            iss,
            now,
            syn,
            false,
            &mut None,
            RxTimestamps::default(),
            RxPacketTimestamps::default(),
        )
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.2
    //= reason=Passive state is SYN-RECEIVED; transmit commits ISS+1 only after SYN-ACK encoding succeeds.
    //# SND.NXT is set to ISS+1 and SND.UNA to ISS. The connection state should be changed to
    //# SYN-RECEIVED.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
    //= reason=Authorized passive children and explicitly selected active receive contexts select Rfc5681 before controller construction and negotiated effective-MSS recalculation, independently of ordinary IW10 and growth/recovery selection. Controller, public Endpoint and native Egress tests assert piecewise boundaries, physical output limits, authorization, transactional output and complete streams.
    //# If the FastOpened flag is set, the server MUST follow [RFC5681] (based on [RFC3390]) to set the initial congestion window for sending more data packets.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn passive_with_receive(
        tuple: Tuple,
        config: ConnectionConfig,
        iss: u32,
        now: Instant,
        syn: &Segment<'_>,
        early_authorized: bool,
        receive: &mut Option<ReceiveBuffer>,
        rx_timestamps: RxTimestamps,
        timestamps: RxPacketTimestamps,
    ) -> Result<Self, Error> {
        Self::passive_with_receive_path(
            tuple,
            config,
            iss,
            now,
            syn,
            early_authorized,
            receive,
            rx_timestamps,
            timestamps,
            None,
            None,
            None,
        )
        .map(|connection| *connection)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn passive_with_receive_path(
        tuple: Tuple,
        config: ConnectionConfig,
        iss: u32,
        now: Instant,
        syn: &Segment<'_>,
        early_authorized: bool,
        receive: &mut Option<ReceiveBuffer>,
        rx_timestamps: RxTimestamps,
        timestamps: RxPacketTimestamps,
        managed_path: Option<crate::PreparedPath>,
        receive_capability: Option<crate::ReceiveIpCapability>,
        initial_ip_header_len: Option<u16>,
    ) -> Result<Box<Self>, Error> {
        if syn.header.flags & (SYN | ACK | RST) != SYN {
            return Err(Error::InvalidArgument);
        }
        timestamps.validate(config.timebase)?;
        // Before handshake validation, authorized early responses use the
        // conservative RFC5681 startup profile even if ordinary opens opt in
        // to IW10. Select it before constructing the actual controller so MSS
        // negotiation, pacing and every output path share the same authority.
        let mut config = config;
        if early_authorized {
            config.initial_window = InitialWindow::Rfc5681;
        }
        let mut connection = Self::active_with_receive_path(tuple, config, iss, now, receive, managed_path, receive_capability, initial_ip_header_len)?;
        connection.rx_timestamps = rx_timestamps;
        connection.input_timestamps = timestamps;
        connection.passive_open = true;
        // Listener policy authorizes an early child even for a server-first
        // exchange. Payload presence separately controls readable data.
        connection.fast_open_early = early_authorized;
        connection.learn_syn(syn, early_authorized);
        connection.input_timestamps = RxPacketTimestamps::default();
        connection.state = State::SynReceived;
        Ok(connection)
    }

    pub(crate) fn validate_buffer_capacities(send: usize, receive: usize) -> Result<(), Error> {
        if send == 0 || send >= 1 << 30 || receive == 0 || receive > (65535usize << 14) {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    // What a connection with a `receive`-byte ring and an `mss`-byte scratch
    // segment allocates at open, its charge until the first write: the
    // receive ring, which backs every window it advertises, the scratch
    // segment and the sender ledgers' initial entries (two RACK intervals,
    // the scoreboard's four spare ranges). The send ring and the ledgers'
    // growth are allocated, and charged, at write.
    pub(crate) fn open_bytes(receive: usize, mss: usize) -> Option<usize> {
        ReceiveBuffer::allocation_bytes(receive)?
            .checked_add(mss)?
            .checked_add(Rack::storage_bytes(0)?)?
            .checked_add(Scoreboard::allocation_bytes(0)?)
    }

    pub(crate) fn receive_allocation_capacity(&self) -> usize {
        self.receive.capacity()
    }

    // What the connection's buffers and records hold allocated now: its
    // share of the endpoint's max_buffer_bytes.
    pub(crate) fn buffer_charge(&self) -> usize {
        self.send.storage_bytes()
            + self.receive.storage_bytes()
            + self.scoreboard.storage_bytes()
            + self.rack.allocation_bytes()
            + self.scratch.capacity()
            + self.tx_timestamps.storage_bytes()
            + self.rx_timestamps.storage_bytes()
    }

    // The charge at the peak of `set_buffer_capacities(_, receive)`: the
    // original receive ring stays live while its replacement is filled. A
    // send limit allocates nothing; the next write grows the send ring.
    pub(crate) fn resize_peak_charge(&self, receive: usize) -> Option<usize> {
        let receiver = if receive > self.receive.capacity() {
            ReceiveBuffer::allocation_bytes(receive)?
        } else {
            0
        };
        self.buffer_charge().checked_add(receiver)
    }

    pub(crate) fn buffer_capacities(&self) -> (usize, usize) {
        (self.send.capacity(), self.config.receive_capacity)
    }

    pub(crate) fn set_buffer_capacities(
        &mut self,
        send: usize,
        receive: usize,
        max_charge: usize,
    ) -> Result<(), Error> {
        Self::validate_buffer_capacities(send, receive)?;
        // The original remains live until its replacement has been staged.
        if self
            .resize_peak_charge(receive)
            .is_none_or(|peak| peak > max_charge)
        {
            return Err(Error::NoMemory);
        }
        let old_window = self.advertised_window(false);
        // Stage the allocation before changing any quota or live protocol state.
        let receiver = if receive > self.receive.capacity() {
            Some(self.receive.grown(receive).map_err(|_| Error::NoMemory)?)
        } else {
            None
        };
        if self
            .buffer_charge()
            .checked_add(receiver.as_ref().map_or(0, ReceiveBuffer::storage_bytes))
            .is_none_or(|peak| peak > max_charge)
        {
            return Err(Error::NoMemory);
        }
        if let Some(buffer) = receiver {
            self.receive = buffer;
        }
        self.send.set_limit(send);
        self.config.send_capacity = send;
        // As SO_SNDBUF sets SOCK_SNDBUF_LOCK: no longer tuned.
        self.send_tuned = false;
        if self.send_space_remaining() != 0 {
            self.send_backpressured = false;
        }
        self.config.receive_capacity = receive;
        if self.handshake_pending() && self.snd_nxt == self.iss {
            // No local SYN has reached the wire, including after failed output.
            self.local_scale = (0..=14)
                .find(|&shift| receive <= (65535usize << shift))
                .unwrap_or(14);
            self.syn_window = if self.receive.eof() {
                0
            } else {
                receive
                    .min(65535)
                    .saturating_sub(if self.deferred_syn.is_some() {
                        0
                    } else {
                        self.receive_used
                    }) as u16
            };
            if self.irs.is_some() {
                self.advertised_edge = self.receive.next().wrapping_add(self.syn_window as u32);
            }
        }
        // ponytail: retain backing on shrink until reclamation; compaction can
        // reclaim slack later, but must preserve queued bytes and promised edges.
        self.events.writable = !self.shutdown
            && !self.read_closed
            && matches!(self.state, State::Established | State::CloseWait)
            && self.send_space_remaining() != 0;
        if self.synchronized() && self.advertised_window(false) > old_window {
            self.immediate_ack();
        }
        Ok(())
    }

    pub(crate) fn into_receive(self: Box<Self>) -> ReceiveBuffer {
        self.receive
    }

    pub(crate) fn tuple(&self) -> Tuple {
        self.tuple
    }
    pub(crate) fn scoped_tuple(&self) -> ScopedTuple {
        ScopedTuple {
            tuple: self.tuple,
            zone: self.zone,
        }
    }
    pub(crate) fn set_zone(&mut self, zone: Option<ntcp_path::LinkId>) {
        self.zone = zone;
    }
    pub(crate) fn state(&self) -> State {
        self.state
    }
    // Set only by validated handshake ACK processing, never inferred from state.
    pub(crate) fn handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    #[cfg(test)]
    pub(crate) fn prepare_fast_open(
        &mut self,
        cached: Option<crate::fast_open::CachedCookie>,
        initial: &[u8],
    ) -> Result<usize, Error> {
        self.prepare_fast_open_with_budget(cached, initial, usize::MAX)
    }
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
    //= reason=Server policy selection does not change the ordinary active-open path: cold client accepts zero initial data and sends a cookie request.
    //# To open a TFO connection, the client MUST have obtained a cookie from the server:
    pub(crate) fn prepare_fast_open_with_budget(
        &mut self,
        cached: Option<crate::fast_open::CachedCookie>,
        initial: &[u8],
        max_charge: usize,
    ) -> Result<usize, Error> {
        self.fast_open = Some(cached.map_or(wire::FastOpenCookie::request(), |c| c.cookie));
        let Some(cached) = cached else {
            return Ok(0);
        };
        self.prepare_fast_open_with_server_cookie(cached.cookie, cached.mss, initial, max_charge)
    }

    // A supplied cookie is a credential obtained from this server, including
    // an explicitly agreed zero cookie for a protected RFC7413 section7.3 service.
    // It is still serialized as a Fast Open option; no omitted-option bypass.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.3
    //= reason=Cold SYN admission uses a conservative 536-byte ceiling in both families before option, configuration, path and storage limits; true peer defaults remain 536/1220 and validated learned MSS remains usable.
    //# Without a cached server MSS, the amount of data in the SYN packet is limited to the default MSS of 536 bytes for IPv4 [RFC1122] and 1220 bytes for IPv6 [RFC2460].
    pub(crate) fn prepare_fast_open_with_server_cookie(
        &mut self,
        cookie: wire::FastOpenCookie,
        peer_mss: Option<u16>,
        initial: &[u8],
        max_charge: usize,
    ) -> Result<usize, Error> {
        self.fast_open = Some(cookie);
        self.prepare_fast_open_data(peer_mss, initial, max_charge)
    }

    pub(crate) fn prepare_fast_open_without_cookie(
        &mut self,
        peer_mss: Option<u16>,
        initial: &[u8],
        max_charge: usize,
    ) -> Result<usize, Error> {
        self.fast_open_client_policy = crate::FastOpenClientPolicy::ApplicationProtected;
        self.prepare_fast_open_data(peer_mss, initial, max_charge)
    }

    fn prepare_fast_open_data(
        &mut self,
        peer_mss: Option<u16>,
        initial: &[u8],
        max_charge: usize,
    ) -> Result<usize, Error> {
        self.peer_mss = peer_mss.unwrap_or(if self.tuple.remote.is_ipv4() {
            536
        } else {
            1220
        });
        // Unknown peer/path capacity calls for conservative cold SYN admission
        // in both families. Keep the actual peer MSS defaults above independent.
        let admission_mss = peer_mss.unwrap_or(536);
        // Reserve the entire option budget, including cookies up to 16 bytes.
        // A changed path may clip the SYN further; all accepted bytes remain queued.
        let limit = usize::from(
            admission_mss
                .min(self.config.mss)
                .min(self.config.user_mss.unwrap_or(u16::MAX)),
        )
        .saturating_sub(40)
        .min(self.path_payload_limit().saturating_sub(60))
        .min(self.scratch.len());
        let count = initial.len().min(limit).min(self.send_space_remaining());
        if count == 0 {
            return Ok(0);
        }
        // Defer the internal automatic PUSH; explicit application marks still
        // apply to SYN data and are never suppressed by the output path.
        // Storage refused for the data leaves a plain SYN, as Linux's
        // tcp_send_syn_data falls back when it cannot allocate syn_data.
        if self.prepare_send_metadata(count, None, max_charge, None)? {
            self.send_memory_wanted = None;
            self.send_backpressured = false;
            return Ok(0);
        }
        let count = self.write_with_push(&initial[..count], false)?;
        self.fast_open_initial = count;
        self.deferred_tfo_push = true;
        Ok(count)
    }

    pub(crate) fn set_fast_open_write_pending(&mut self, pending: bool) -> Result<(), Error> {
        if pending && self.state != State::SynSent {
            return Err(Error::InvalidState);
        }
        self.fast_open_write_pending = pending;
        Ok(())
    }

    //= https://www.rfc-editor.org/rfc/rfc7413#section-2
    //# To enable applications to exchange data in a TCP handshake, TFO removes the constraint and allows
    //# data in SYN packets to be delivered to the application.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2
    //# The server keeps a FastOpened flag per connection to mark if a connection has successfully performed
    //# a TFO.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
    //# 6. Advance to the SYN-RCVD state.
    pub(crate) fn passive_fast_open(&mut self, cookie: Option<wire::FastOpenCookie>, early: bool) {
        self.fast_open = cookie;
        self.fast_open_early = early;
        if early {
            self.events.readable = self.receive.readable() != 0;
            if self.events.readable {
                self.received_syn_data_start = self.irs.map(|irs| irs.wrapping_add(1));
            }
        }
    }

    pub(crate) fn reset_pending(&self) -> bool {
        self.state == State::Closed && self.pending_rst.is_some()
    }

    fn handshake_pending(&self) -> bool {
        !self.handshake_complete
            && matches!(
                self.state,
                State::SynSent | State::SynReceived | State::FinWait1
            )
    }

    //= https://www.rfc-editor.org/rfc/rfc7413#section-3
    //# If the server accepts the data in the SYN packet, it may send the response data before the handshake
    //# finishes.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-5.2
    //= reason=Selected default withholding defense; explicit early-response opt-in accepts the described security tradeoff. Rejected erratum 6239 is not applied.
    //# The best defense is for the server not to respond with data until the handshake finishes.
    fn early_response_eligible(&self) -> bool {
        self.passive_open
            && self.fast_open_early
            && self.handshake_pending()
            && self.config.fast_open_early_response
            && self.syn_committed
    }

    pub(crate) fn time_wait_valid(&self, now: Instant) -> bool {
        self.state == State::TimeWait && self.time_wait_deadline.is_some_and(|end| now < end)
    }

    //= https://www.rfc-editor.org/rfc/rfc6191#section-2
    //# In the above explanation, the phrase "TCP Timestamps would be enabled
    //# for the new incarnation for the connection" means that the incoming SYN
    //# segment contains a TCP Timestamps option (i.e., the client has enabled
    //# TCP Timestamps), and that the SYN/ACK segment that would be sent in
    //# response to it would also contain a Timestamps option (i.e., the server
    //# has enabled TCP Timestamps). In such a scenario, TCP Timestamps would be
    //# enabled for the new incarnation of the connection.
    //= https://www.rfc-editor.org/rfc/rfc6191#section-2
    //= reason=The receive frontier acknowledges FIN+1; strict serial comparison is against FIN itself, preserving undefined half-space rejection.
    //# The "last sequence number seen on the previous incarnation of the
    //# connection (for the same direction of the data transfer)" refers to the
    //# last sequence number used by the previous incarnation of the connection
    //# (for the same direction of the data transfer), and not to the last
    //# value seen in the Sequence Number field of the corresponding segments.
    //# That is, it refers to the sequence number corresponding to the FIN flag
    //# of the previous incarnation of the connection, for that direction of
    //# the data transfer.
    //= https://www.rfc-editor.org/rfc/rfc6191#section-2
    //# * If TCP Timestamps would be enabled for the new incarnation of the
    //# connection, the timestamp contained in the incoming SYN segment is equal
    //# to the last timestamp seen on the previous incarnation of the connection
    //# (for that direction of the data transfer), and the Sequence Number of
    //# the incoming SYN segment is greater than the last sequence number seen
    //# on the previous incarnation of the connection (for that direction of the
    //# data transfer), honor the connection request (creating a connection in
    //# the SYN-RECEIVED state).
    //= https://www.rfc-editor.org/rfc/rfc6191#section-2
    //# * If TCP Timestamps would not be enabled for the new incarnation of the
    //# connection, but the Sequence Number of the incoming SYN segment is
    //# greater than the last sequence number seen on the previous incarnation
    //# of the connection (for the same direction of the data transfer), honor
    //# the connection request (creating a connection in the SYN-RECEIVED
    //# state).
    //= https://www.rfc-editor.org/rfc/rfc6191#section-2
    //# * If TCP Timestamps would not be enabled for the new incarnation of the
    //# connection, but the Sequence Number of the incoming SYN segment is
    //# greater than the last sequence number seen on the previous incarnation
    //# of the connection (for the same direction of the data transfer), honor
    //# the incoming connection request (creating a connection in the
    //# SYN-RECEIVED state).
    //= https://www.rfc-editor.org/rfc/rfc6191#section-2
    //= reason=Only a SYN without ACK or RST to a TIME-WAIT connection reaches reopen_time_wait, whose reuse_syn freshness uses both the incoming sequence number and its Timestamps option when present. Reuse enabled versus disabled leaves results, state, resources, deadlines and emitted bytes identical in CLOSED, LISTEN, SYN-SENT, SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1/2, CLOSE-WAIT, LAST-ACK and CLOSING across flag, checksum, timestamp and sequence variants.
    //# The following paragraphs summarize the processing of SYN segments
    //# received for connections in the TIME-WAIT state. The processing of SYN
    //# segments received for connections in all other states is unchanged. Both
    //# the ISN (Initial Sequence Number) and the Timestamps option (if present)
    //# of the incoming SYN segment are included in the heuristics performed for
    //# allowing a high connection-establishment rate.
    pub(crate) fn reuse_syn(&self, now: Instant, syn: &Segment<'_>, timestamps: bool) -> bool {
        self.time_wait_valid(now)
            && crate::time_wait::fresh_syn(
                self.timestamps,
                self.ts_latest,
                self.receive.next(),
                syn,
                timestamps,
            )
    }

    // What TIME-WAIT keeps once this connection is gone; None before it is
    // in TIME-WAIT with nothing left to send.
    pub(crate) fn time_wait_record(
        &self,
        hop_limit: u8,
        dscp: u8,
        mark: u32,
        reuse_address: bool,
        ipv4_options: crate::OutgoingIpv4Options,
    ) -> Option<crate::time_wait::Record> {
        if self.state != State::TimeWait || !self.output_idle() {
            return None;
        }
        // The ACK of the peer's FIN has gone out, offering no window past it.
        debug_assert_eq!(self.receive_window(), 0);
        debug_assert_eq!(self.last_ack_sent, self.receive.next());
        Some(crate::time_wait::Record {
            tuple: self.scoped_tuple(),
            snd_nxt: self.snd_nxt,
            rcv_nxt: self.receive.next(),
            ack_floor: self
                .snd_una
                .wrapping_add(0u32.wrapping_sub(self.max_snd_wnd)),
            timestamps: self.timestamps,
            timestamp_offset: self.timestamp_offset,
            ts_recent: self.ts_recent,
            ts_latest: self.ts_latest,
            ts_recent_at: self.ts_recent_at,
            last_timestamp_sent_at: self.last_timestamp_sent_at,
            deadline: self.time_wait_deadline?,
            challenge_start: self.challenge_ack_start,
            challenge_sent: self.challenge_ack_sent,
            ack_pending: false,
            challenge_pending: false,
            hop_limit,
            dscp,
            mark,
            reuse_address,
            ipv4_options,
            reply_header: None,
        })
    }

    pub(crate) fn reuse_iss(&self, candidate: u32) -> u32 {
        crate::time_wait::reincarnation_iss(self.snd_nxt, candidate)
    }

    // TIME-WAIT ends: at its timer, or when a reopening SYN gave the tuple
    // to a new connection.
    pub(crate) fn end_time_wait(&mut self) {
        debug_assert_eq!(self.state, State::TimeWait);
        self.state = State::Closed;
        self.pacing_deadline = None;
        self.pacer = Pacer::default();
        self.time_wait_deadline = None;
        self.ack_pending = false;
    }

    #[cfg(test)]
    pub(crate) fn transport_info(&self) -> TransportInfo {
        self.transport_info_at(self.now)
    }

    // Read-only sampling also covers dormant connections whose clock lags Endpoint.
    pub(crate) fn transport_info_at(&self, now: Instant) -> TransportInfo {
        let counts = self
            .reserved_retransmit_counts
            .unwrap_or_else(|| self.rack.diagnostic_packet_counts());
        let ticks = self.transport_ticks_at(now);
        TransportInfo {
            state: self.state,
            recovery: self.congestion.in_recovery(),
            ecn_response: self.congestion.in_ecn_response(self.snd_una),
            loss: self.sack_post_rto.is_some() || self.consecutive_timeouts != 0,
            ledger_valid: self.rack.valid(),
            timestamps_negotiated: self.timestamps,
            sack_negotiated: self.sack_send,
            window_scaling_negotiated: self.scaling,
            send_window_scale: if self.scaling { self.peer_scale } else { 0 },
            receive_window_scale: if self.scaling { self.local_scale } else { 0 },
            ecn_negotiated: self.ecn_send(),
            syn_data_acked: self.syn_data_acked,
            syn_data_fully_acked: self.syn_data_fully_acked,
            delivered_segments: self
                .rack
                .delivered_segments
                .saturating_add(u64::from(self.syn_delivered) + u64::from(self.fin_delivered)),
            delivered_segments_valid: self.rack.delivered_segments_valid,
            unacked: counts.unacked,
            sacked: counts.sacked,
            lost: counts.lost,
            retransmitted: counts.retransmitted,
            total_retrans: self.total_retrans,
            reordering: self.rack.reordering,
            reordering_events: self.rack.reordering_events,
            resource_probes: self.resource_probes,
            rto_backoff: self.consecutive_timeouts,
            cwnd: self.congestion.cwnd(),
            ssthresh: self.congestion.ssthresh(),
            mss: self.mss as u32,
            received_mss: u32::from(self.received_mss.value(self.receive_mss())),
            advertised_mss: u32::from(self.receive_mss()),
            max_send_window: self.max_snd_wnd,
            rtt_us: self
                .rtt
                .srtt()
                .map(|ticks| self.config.timebase.us_from_ticks(ticks)),
            min_rtt_us: self
                .rack
                .min_rtt()
                .map(|ticks| self.config.timebase.us_from_ticks(ticks)),
            rttvar_us: self.config.timebase.us_from_ticks(self.rtt.variance()),
            rto_us: self.config.timebase.us_from_ticks(self.rto()),
            notsent_bytes: self.notsent_bytes(),
            last_data_recv_ms: (self
                .config
                .timebase
                .us_from_ticks(now.saturating_sub(self.last_data_received))
                / 1000)
                .min(u32::MAX as u64) as u32,
            busy_time_us: self.config.timebase.us_from_ticks(ticks[0]),
            rwnd_limited_us: self.config.timebase.us_from_ticks(ticks[1]),
            sndbuf_limited_us: self.config.timebase.us_from_ticks(ticks[2]),
            send_used: self.send.len(),
            send_capacity: self.config.send_capacity,
            send_space: self.send_space(),
            receive_used: self.receive_used,
            receive_capacity: self.config.receive_capacity,
        }
    }

    fn notsent_bytes(&self) -> usize {
        let sent = if !self.snd_nxt.at_or_after(self.send_base) {
            0
        } else {
            (self.snd_nxt.distance_from(self.send_base) as usize).min(self.send.len())
        };
        self.send.len() - sent
    }

    fn transport_ticks_at(&self, now: Instant) -> [u64; 3] {
        let mut ticks = self.transport_ticks;
        let fin_pending =
            self.shutdown && self.fin_sequence.is_none_or(|fin| !self.snd_una.after(fin));
        if !matches!(self.state, State::Closed | State::TimeWait)
            && (self.send.len() != 0 || fin_pending)
        {
            let elapsed = now.saturating_sub(self.now);
            ticks[0] = ticks[0].saturating_add(elapsed);
            let unsent = self.notsent_bytes();
            let flight = self.flight();
            // Linux chronographs prioritize sndbuf over rwnd. Here NOSPACE means
            // an actual short/blocked core write, and ends at core writable credit.
            let sndbuf = self.send_backpressured
                && self.send_space_remaining() == 0
                && unsent == 0
                && matches!(self.state, State::Established | State::CloseWait)
                && flight < self.congestion.cwnd();
            let next_payload = unsent.min(self.mss) as u32;
            // Standalone FIN needs one peer-window sequence unit, but no
            // payload cwnd credit. Match transmit's PRR/recovery admission.
            let standalone_fin = unsent == 0
                && self.shutdown
                && self.fin_sequence.is_none()
                && matches!(self.state, State::Established | State::CloseWait)
                && self.prr.is_none_or(|prr| {
                    self.sack_recovery.map_or_else(
                        || prr.credit() != 0,
                        |recovery| {
                            !recovery.entry_pending
                                && self.recovery_credit(recovery) >= self.mss as u32
                        },
                    )
                });
            let rwnd = self.synchronized()
                && (next_payload != 0
                    && self.congestion.cwnd().saturating_sub(flight) >= next_payload
                    && self.snd_wnd.saturating_sub(flight) < next_payload
                    || standalone_fin && self.snd_wnd.saturating_sub(flight) == 0);
            if sndbuf {
                ticks[2] = ticks[2].saturating_add(elapsed);
            } else if rwnd {
                ticks[1] = ticks[1].saturating_add(elapsed);
            }
        }
        ticks
    }

    //= https://www.rfc-editor.org/rfc/rfc8985#section-1
    //= reason=Opt-in alternative to DupAck inference only with bidirectional negotiated SACK and a valid ledger.
    //# This document presents RACK-TLP, a TCP loss detection algorithm that
    //# improves upon the widely implemented duplicate acknowledgment
    //# (DupAck) counting approach described in [RFC5681] and [RFC6675]; it
    //# is RECOMMENDED as an alternative to that earlier approach.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-4
    //= reason=Requires negotiated SACK in both directions; connection owns its scoreboard.
    //# The connection MUST use selective acknowledgment (SACK) options
    //# [RFC2018], and the sender MUST keep SACK scoreboard information
    //# on a per-connection basis ("SACK scoreboard" has the same meaning
    //# here as in [RFC6675], Section 3).
    fn rack_enabled(&self) -> bool {
        self.config.rack
            && self.sack_receive
            && self.sack_send
            && self.rack.valid()
            && self.sack_fallback.is_none()
    }

    fn tlp_arm_packets(&self) -> Option<u32> {
        if !(self.config.tlp
            && self.rack_enabled()
            && self.synchronized()
            && self.flight() != 0
            && self.snd_wnd != 0
            && !self.congestion.in_recovery()
            && self.sack_post_rto.is_none()
            && self.consecutive_timeouts == 0
            && !self.retx_pending
            && self.ecn_pause.is_none_or(|deadline| self.now >= deadline)
            && self.rack.deadline.is_none()
            // A loss probe must not bypass the PTB Restart allowance or
            // ordinary admission of known-dropped ranges.
            && self.ptb_idle())
        {
            return None;
        }
        // PTO sizing uses the same original-packet count as eligibility.
        let counts = self.rack.packet_counts();
        (counts.sacked == 0).then_some(counts.unacked)
    }

    fn tlp_eligible(&self) -> bool {
        self.tlp_arm_packets().is_some()
    }

    // Only this value is armed. The protocol-specific deadlines are candidate
    // expirations, not independent timers; RTO remains an unarmed reference.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-8
    //# The RACK reordering timer, the TLP PTO timer, the RTO, and Zero
    //# Window Probe (ZWP) timer [RFC793] are mutually exclusive and are used
    //# in different scenarios.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-8
    //# When arming a RACK reordering timer or TLP
    //# PTO timer, the sender SHOULD cancel any other pending timers.
    fn select_loss_timer(&mut self) {
        self.loss_timer = if let Some(deadline) = self.rack.deadline {
            self.tlp_deadline = None;
            Some((LossTimer::Rack, deadline))
        } else if let Some(deadline) = self.tlp_deadline {
            Some((LossTimer::Pto, deadline))
        } else if let Some(deadline) = self.persist_deadline {
            Some((LossTimer::Zwp, deadline))
        } else {
            self.rto_deadline.map(|deadline| (LossTimer::Rto, deadline))
        };
    }

    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.2
    //= reason=New-data and advancing cumulative ACK events arm PTO outside recovery/SACKed flights. Expiry gates do not constrain arming; closing data and absent-SRTT flights are covered.
    //# The sender SHOULD start or
    //# restart a loss probe PTO timer after transmitting new data (that was
    //# not itself a loss probe) or upon receiving an ACK that cumulatively
    //# acknowledges new data unless it is already in fast recovery, RTO
    //# recovery, or segments have been SACKed (i.e., RACK.segs_sacked is not
    //# zero).
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.2
    //= reason=Absent SRTT arms a one-second PTO capped by the unarmed RTO reference; expiry skips unsampled probes and restores RTO.
    //# Second, when there is no SRTT estimate available, the PTO SHOULD be 1
    //# second.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.2
    //= reason=Single original outstanding packet adds explicit peer_max_ack_delay_us, default499999us for RFC9293 delayed ACK bound, independently of our receiver ACK policy.
    //# Third, when the FlightSize is one segment, the sender MAY inflate the
    //# PTO by TLP.max_ack_delay to accommodate a potentially delayed
    //# acknowledgment and reduce the risk of spurious retransmissions.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.2
    //= reason=One second without SRTT; sampled single-packet flight adds the peer ACK budget, multi-packet flight adds the configurable scheduling margin (default2ms). This is a documented conservative SHOULD departure to reduce low-RTT spurious probes; bounded by the original RTO. pto_margin_ack_loss_and_rto_cap_wire tests default/zero/nonzero margins and real wire feedback.
    //# Summarizing these considerations in pseudocode form, a sender SHOULD
    //# use the following logic to select the duration of a PTO:
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.2
    //= reason=RTO cap, no-SRTT fallback and peer ACK budget are retained. The configurable multi-packet scheduling margin is scoped to the 2*SRTT line by duvet/rfc8985-additions.toml; it does not waive expiry gating, probe bounds or accounting. Short-packet flights retain their section9.4 peer-delay floor.
    //# TLP_calc_PTO():
    //# If SRTT is available:
    //# PTO = 2 * SRTT
    //# If FlightSize is one segment:
    //# PTO += TLP.max_ack_delay
    //# Else:
    //# PTO = 1 sec
    //#
    //# If Now() + PTO > TCP_RTO_expiration():
    //# PTO = TCP_RTO_expiration() - Now()
    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.4
    //= reason=Peer-delay inflation plus a short-packet-flight floor cover delayed and stretched short-packet ACKs; PTO is still capped by the unarmed RTO reference.
    //# To mitigate this
    //# complication, before sending a TLP loss probe retransmission, the
    //# sender should attempt to wait long enough that the receiver has sent
    //# any delayed ACKs that it is withholding.
    fn schedule_tlp(&mut self) {
        if let Some(unacked_packets) = self.tlp_arm_packets() {
            // Preserve a short flight's peer ACK budget without imposing that
            // delay on full-sized flights. A separate scheduling margin covers
            // local timing variance for sampled multi-packet flights.
            let pto =
                self.rtt
                    .srtt()
                    .map_or(self.config.timebase.ticks_from_us(1_000_000), |srtt| {
                        let fin_packet = u32::from(self.fin_sequence.is_some_and(|fin| {
                            fin.at_or_after(self.snd_una)
                                && (self.fin_standalone || fin == self.snd_una)
                        }));
                        let packets = unacked_packets + fin_packet;
                        let delay = if packets == 1 {
                            self.config
                                .timebase
                                .ticks_from_us(self.config.peer_max_ack_delay_us)
                        } else if packets > 1 {
                            // Conservative scheduling allowance, not delivery or
                            // congestion credit. Preserve RTO as the outer cap.
                            self.config
                                .timebase
                                .ticks_from_us(self.config.tlp_timer_margin_us)
                        } else {
                            0
                        };
                        let pto = srtt.saturating_mul(2).saturating_add(delay);
                        if self.rack.has_short_transmission(self.mss as u32) {
                            pto.max(
                                srtt.saturating_add(
                                    self.config
                                        .timebase
                                        .ticks_from_us(self.config.peer_max_ack_delay_us),
                                ),
                            )
                        } else {
                            pto
                        }
                        .max(1)
                    });
            self.tlp_deadline = self
                .rto_deadline
                .map(|rto| self.now.saturating_add(pto).min(rto));
        }
        self.select_loss_timer();
    }

    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.1
    //= reason=Constructor starts unset; fast/RTO recovery call reset_tlp to clear probe history/pending timers without inventing freshness.
    //# Reset TLP.is_retrans and TLP.end_seq when initiating a connection,
    //# fast recovery, or RTO recovery.
    fn reset_tlp(&mut self) {
        self.tlp_deadline = None;
        self.tlp_pending = false;
        self.tlp_end = None;
        self.tlp_flight = None;
        // Do not manufacture the fresh RTT sample required since the last probe.
    }

    // Called only for validated ACKs, before advancing SND.UNA.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.4.2
    //= reason=Without matching DSACK or bare duplicate ACK, ACK strictly beyond probe end reports repaired loss; equality keeps ambiguity pending.
    //# If the TLP
    //# sender does not receive such an indication, then it MUST assume that
    //# the original data segment, the TLP retransmission, or a corresponding
    //# ACK was lost for congestion control purposes.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.4.2
    //= reason=New-data, matching DSACK, ACK beyond and bare DupACK branches clear episode; only retransmitted beyond-end loss reports congestion.
    //# TLP_process_ack(ACK):
    //# If TLP.end_seq is not None AND ACK's ack. number >= TLP.end_seq:
    //# If not TLP.is_retrans:
    //# TLP.end_seq = None    /* TLP of new data delivered */
    //# Else if ACK has a DSACK option matching TLP.end_seq:
    //# TLP.end_seq = None    /* Case 1, above */
    //# Else If ACK's ack. number > TLP.end_seq:
    //# TLP.end_seq = None    /* Repaired the single loss */
    //# (Invoke congestion control to react to
    //# the loss event the probe has repaired)
    //# Else If ACK is a DupAck without any SACK option:
    //# TLP.end_seq = None     /* Case 2, above */
    fn tlp_ack(
        &mut self,
        ack: Seq,
        advancing: bool,
        dsack: bool,
        blocks: &[Option<(u32, u32)>; 4],
        duplicate: bool,
    ) -> bool {
        if self.tlp_flight.is_some_and(|end| ack.at_or_after(end)) {
            self.tlp_flight = None;
        }
        let Some((start, end, retransmit)) = self.tlp_end else {
            return false;
        };
        if !ack.at_or_after(end) {
            return false;
        }
        let matching_dsack = dsack
            && blocks[0]
                .is_some_and(|(left, right)| start.at_or_after(Seq(left)) && Seq(right) == end);
        let repaired = retransmit && !matching_dsack && ack.after(end);
        if !retransmit
            || matching_dsack
            || repaired
            || (!advancing && duplicate && blocks.iter().all(Option::is_none))
        {
            self.tlp_end = None;
        }
        repaired
    }

    //= https://www.rfc-editor.org/rfc/rfc6582#section-1
    //= reason=Directional SACK permission is retained; ACK processing selects SACK recovery from actual retained scoreboard evidence, or ordinary fallback without it. Opt-in RACK still requires peer SACK negotiation; Rfc9937 PRR also supports non-SACK recovery.
    //# This document applies to TCP connections that are unable to use the TCP Selective
    //# Acknowledgment (SACK) option, either because the option is not locally supported or
    //# because the TCP peer did not indicate a willingness to use SACK.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-1
    //= reason=Local receive-SACK permission is directional. Actual ACK scoreboard evidence selects RFC6675; absent evidence ordinary NewReno repairs two holes, for local sack=true/peer sack=false with RACK/PRR on or off. Limited Transmit still requires new SACK if permitted; existing first-flight directional SACK tests remain intact.
    //# This document applies to TCP connections that are unable to use the TCP Selective
    //# Acknowledgment (SACK) option, either because the option is not locally supported or because the
    //# TCP peer did not indicate a willingness to use SACK.
    fn sack_recovery_enabled(&self) -> bool {
        self.sack_receive && (!(self.config.rack || self.config.prr) || self.sack_send)
    }

    //= https://www.rfc-editor.org/rfc/rfc9937#section-5
    //= reason=Selected RFC6675 SACK, RACK and non-SACK NewReno compositions are covered separately by strict_prr_rack_pipe_reordered_originals_and_lost_retransmissions and rfc9937_no_sack_wire_delivery_cap_zero_ack_and_completion; no FACK claim.
    //# Thus, PRR MAY be used in
    //# conjunction with the loss detection algorithms specified or described
    //# in the following documents: Reno [RFC5681], NewReno [RFC6582], SACK
    //# [RFC6675], Forward Acknowledgment (FACK) [FACK], and Recent
    //# Acknowledgment Tail Loss Probe (RACK-TLP) [RFC8985].
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
    //= reason=rack=false, negotiated SACK and valid byte ledger: literal Scoreboard::pipe values and successful committed HighRxt are asserted, independently of the RACK estimator.
    //# To
    //# calculate inflight, connections with SACK enabled and using [RFC6675]
    //# loss detection MAY use the "pipe" algorithm as specified in
    //# [RFC6675].
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
    //= reason=Uses selected estimator, not raw cumulative flight: RACK excludes lost and SACKed bytes and restores committed copies. RFC6675/non-SACK estimators have separate exact tests.
    //# inflight = (estimated volume of in-flight data)
    fn recovery_pipe(&self, high_rxt: Seq) -> u32 {
        if self.rack_enabled() {
            self.rack.pipe()
        } else {
            // Outstanding PTB copies committed above HighRxt are in transit
            // too, though SetPipe's HighRxt term does not see them.
            self.scoreboard
                .pipe(self.snd_una, self.data_high(), high_rxt, self.mss as u32)
                + self.ptb_copy_pipe()
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc9937#section-3
    //= reason=Normal output subtracts flight from cwnd; recovery_credit bounds selected recovery by pipe or strict PRR byte credit, with PRR setting cwnd=inflight+SndCnt. RFC9937 section5 recommends RACK-TLP composition: its sole congestion-control exception is one accounted outstanding probe (RFC8985 sections7.3/9.3), not unrestricted recovery. RFC3042 section2 Limited Transmit is separately bounded to two SMSS without changing cwnd. ordinary_output_policy_matrix, selected_recovery_output_policy_matrix and probe_and_shrink_output_policy_matrix assert these distinct policies.
    //# At any given time, a connection MUST
    //# NOT send data if inflight (see below) matches or exceeds cwnd.
    fn recovery_credit(&self, recovery: SackRecovery) -> u32 {
        self.prr.map_or_else(
            || self.congestion.cwnd().saturating_sub(recovery.pipe),
            |prr| prr.credit(),
        )
    }

    //= https://www.rfc-editor.org/rfc/rfc2018#section-5.1
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Congestion controller halves eligible flight, excludes limited bytes and avoids duplicate ECN reductions. This cites integration, not all congestion-control recommendations.
    //# However, the congestion control algorithms present in the de facto standard
    //# TCP implementations MUST be preserved [Stevens94].
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Entry records fixed data_high boundary; cumulative ACK at exclusive boundary ends recovery.
    //# (4.1) RecoveryPoint = HighData When the TCP sender receives a cumulative ACK
    //# for this data octet, the loss recovery phase is terminated.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Congestion on_sack_recovery sets cwnd=ssthresh=half eligible flight with RFC5681 minimum; outstanding limited bytes excluded even after partial ACK. ECN epoch guards prevent second reduction.
    //# (4.2) ssthresh = cwnd = (FlightSize / 2) The congestion window (cwnd) and
    //# slow start threshold (ssthresh) are reduced to half of FlightSize per
    //# [RFC5681]. Additionally, note that [RFC5681] requires that any segments sent
    //# as part of the Limited Transmit mechanism not be counted in FlightSize for
    //# the purpose of the above equation.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Entry initializes pipe from scoreboard and successful entry retransmission recomputes SetPipe with committed HighRxt, including when advisory SACK covers the head.
    //# (4.4) Run SetPipe () Set a "pipe" variable to the number of outstanding
    //# octets currently "in the pipe"; this is the data which has been sent by the
    //# TCP sender but for which no cumulative or selective acknowledgment has been
    //# received and the data has not been determined to have been dropped in the
    //# network. It is assumed that the data is still traversing the network path.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
    //= reason=Configurable PRR initialized on valid SACK recovery; default PRR is off.
    //# The Proportional Rate
    //# Reduction (PRR) algorithm [RFC6937] is RECOMMENDED for the specific
    //# congestion control actions taken upon the losses detected by RACK-
    //# TLP.
    //= https://www.rfc-editor.org/rfc/rfc9937#section-5
    //= reason=PRR uses the ssthresh target; strict_ack covers loss and cubic_ecn_prr covers eligible ECN and SafeACK credit. Optional ECN PRR is omitted/cancelled if the post-MSS logical target differs from ssthresh, preserving direct CUBIC below the threshold floor.
    //# PRR MAY be used in conjunction with any congestion control algorithm
    //# that intends to make a multiplicative decrease in its sending rate
    //# over approximately the time scale of one round-trip time, as long as
    //# the current volume of in-flight data is limited by a congestion
    //# window (cwnd) and the target volume of in-flight data during that
    //# reduction is a fixed value given by ssthresh.
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.1
    //= reason=Connection selects the congestion target; constructor zeros byte counters. Entry wire traces separately assert the actual target.
    //# ssthresh = CongCtrlAlg()      // Target flight size in recovery
    //# prr_delivered = 0             // Total bytes delivered in recovery
    //# prr_out = 0                   // Total bytes sent in recovery
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.1
    //= reason=Snapshot post-ACK unsacked payload and add current signed delivery, excluding earlier SACKs; exact 9000 RecoverFS/6000 delivery plus wrap and later invariance asserted by independent strict_ack oracle.
    //# RecoverFS = SND.NXT - SND.UNA
    //# // Bytes SACKed before entering recovery will not be
    //# // marked as delivered during recovery:
    //# RecoverFS -= (bytes SACKed in scoreboard)
    //# // Include the (common) case of selectively ACKed bytes:
    //# RecoverFS += (bytes newly SACKed)
    //# // Include the (rare) case of cumulatively ACKed bytes:
    //# RecoverFS += (bytes newly cumulatively acknowledged)
    fn start_sack_recovery(&mut self) -> bool {
        let probe = self.pmtud.as_ref().and_then(|p| p.eligible_probe_loss());
        if self.sack_guard.is_some()
            || self.sack_recovery.is_some()
            || !self.data_high().after(self.snd_una)
            || !self.congestion.on_sack_recovery_with_probe(
                self.snd_una,
                self.data_flight().saturating_sub(self.limited_sent),
                self.data_high(),
                probe,
            )
        {
            return false;
        }
        self.loss_events.sack_recoveries += 1;
        self.note_iw_loss(self.snd_una);
        self.reset_tlp();
        self.sack_recovery = Some(SackRecovery {
            recovery_point: self.data_high(),
            high_rxt: self.snd_una,
            rescue_rxt: None,
            entry_pending: true,
            pipe: self.recovery_pipe(self.snd_una),
        });
        if self.config.prr && self.sack_send && self.rack.valid() {
            self.prr = Some(Prr::new(
                self.scoreboard
                    .unsacked_bytes(self.snd_una, self.data_high()),
                self.mss as u32,
            ));
        }
        self.retx_pending = false;
        self.limited_pending = false;
        self.ecn_cwr_pending |= self.ecn_feedback();
        true
    }

    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.2
    //= reason=Lost retransmissions remain eligible for revised RACK recovery selection; an additional congestion response is required only without active PRR.
    //# Therefore, the algorithm [RFC6675]
    //# MUST NOT be used with RACK-TLP; instead, a modified recovery
    //# algorithm that carefully addresses such a case is needed.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
    //= reason=Without active PRR, lost retransmissions receive one extra congestion response per committed-copy window; configured PRR alone does not imply an active episode.
    //# In the absence of PRR [RFC6937], when RACK-TLP detects a lost
    //# retransmission, the congestion control MUST trigger an additional
    //# congestion response per the aforementioned principle in [RFC5681].
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=RACK recovery entry depends on time-based losses; ACK path gates DupAck/scoreboard loss entry behind !rack_enabled().
    //# Otherwise, if some reordering has been observed, then RACK does not
    //# trigger fast recovery based on DupThresh.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=ACK and timer paths call shared detector and update recovery pipe; zero-window/invalid-ledger profile suppresses detection.
    //# When an ACK
    //# is received or the RACK reordering timer expires, call
    //# RACK_detect_loss_and_arm_timer().
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.4.1
    //= reason=All validated ACK feedback, including tail-probe ACK, goes through RACK detector and loss-triggered recovery.
    //# More specifically, RACK_detect_loss() (Step 5) would mark those
    //# earlier segments as lost.  Then the sender would trigger a fast
    //# recovery to recover those losses.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
    //= reason=Original losses share recovery entry; Rack snapshots committed retransmission copies to group losses across ACKs, while successful replacements can trigger a later response.
    //# If multiple original transmissions or retransmissions were lost in a
    //# window, the congestion control specified in [RFC5681] only reacts
    //# once per window.
    //= https://www.rfc-editor.org/rfc/rfc9937#section-5
    //= reason=Opt-in prr=true/rack=true composes PRR with modified RACK loss recovery; lost-copy ACK and timer detection preserve the active episode and target. Default prr=false is not evidence of enabling PRR by default.
    //# Because of the
    //# performance properties of RACK-TLP, including resilience to tail
    //# loss, reordering, and lost retransmissions, it is RECOMMENDED that
    //# PRR is implemented together with RACK-TLP loss recovery [RFC8985].
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.4
    //= reason=Lost-copy ACK/timer detection alone does not initiate a congestion response or end active PRR; boundary ACK traces separately assert completion and unchanged ending counters.
    //# A PRR episode ends upon either completing fast recovery or before
    //# initiating a new PRR episode due to a new congestion control response
    //# episode.
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.1
    //= reason=Active PRR keeps its flight snapshot and counters on retransmission loss; RACK still updates pipe and the ACK path accounts only current delivery without reinitialization.
    //# Upon entering fast
    //# recovery, PRR initializes RecoverFS, and RecoverFS remains constant
    //# during a given fast recovery episode.
    fn detect_rack(&mut self) -> (bool, bool) {
        if !self.rack_enabled() || self.snd_wnd == 0 {
            self.rack.deadline = None;
            return (false, false);
        }
        let old_pipe = self.rack.pipe();
        let retransmission_lost = self.rack.detect(
            self.now,
            self.sack_recovery.is_some() || self.sack_post_rto.is_some(),
            self.rtt.srtt(),
        );
        // RFC 8985 section 9.3 requires an additional response in the absence
        // of PRR, not merely when PRR is disabled in configuration. Active PRR
        // handles fresh loss through pipe and SafeACK (RFC 9937 section 6.2).
        let new_response = retransmission_lost && self.prr.is_none();
        if retransmission_lost {
            self.note_probe_loss(self.snd_una, true);
        }
        if new_response {
            self.congestion.retransmission_lost(self.data_flight());
        }
        let further_loss = self.rack.pipe() < old_pipe;
        if let Some((start, _)) = self.rack.lowest_lost(self.mss as u32) {
            self.note_probe_loss(start, self.rack.packet_counts().lost > 1);
            self.note_iw_loss(start);
            self.start_sack_recovery();
        }
        if let Some(mut recovery) = self.sack_recovery {
            recovery.pipe = self.rack.pipe();
            self.sack_recovery = Some(recovery);
        }
        (new_response, further_loss)
    }

    fn receive_payload(
        &mut self,
        sequence: Seq,
        payload: &[u8],
        fin: bool,
        push: bool,
    ) -> crate::buffer::ReceiveOutcome {
        if !self.rx_timestamps.enabled() || self.input_timestamps == RxPacketTimestamps::default() {
            return self.receive.insert_with_push(sequence, payload, fin, push);
        }
        let base = self.received_read;
        let timestamps = self.input_timestamps;
        let metadata = &mut self.rx_timestamps;
        self.receive
            .insert_observed(sequence, payload, fin, push, |start, end| {
                if let (Some(start), Some(end)) =
                    (base.checked_add(start as u64), base.checked_add(end as u64))
                {
                    metadata.insert(start, end, timestamps);
                } else {
                    metadata.lost((end - start) as u64);
                }
            })
    }

    pub(crate) fn send_capacity(&self) -> usize {
        self.config.send_capacity
    }

    pub(crate) fn send_progress(&self) -> SendProgress {
        SendProgress {
            acknowledged: self.acknowledged,
            queued_end: self.acknowledged + self.send.len() as u64,
            unacknowledged_sequence: self.snd_una.0,
            next_write_sequence: self.send_base.wrapping_add(self.send.len() as u32).0,
        }
    }

    pub(crate) fn peek_rx_timestamps(
        &self,
        count: usize,
    ) -> Result<Option<RxReadTimestamps>, Error> {
        if count == 0 {
            return Ok(None);
        }
        if count > self.readable_bytes().max(self.terminal_readable_bytes()) {
            return Err(Error::InvalidArgument);
        }
        let end = self
            .received_read
            .checked_add(count as u64)
            .ok_or(Error::InvalidArgument)?;
        Ok(Some(RxReadTimestamps {
            start: self.received_read,
            end,
            timestamps: self.rx_timestamps.at(end - 1),
        }))
    }

    #[cfg(test)]
    pub(crate) fn input_with_timestamps(
        &mut self,
        now: Instant,
        traffic_class: u8,
        segment: &Segment<'_>,
        timestamps: RxPacketTimestamps,
    ) -> Result<(), Error> {
        self.input_with_metadata(
            now,
            traffic_class,
            segment,
            crate::RxPacketMetadata {
                timestamps,
                tcp_segment_size: None,
            },
        )
    }

    pub(crate) fn input_with_metadata(
        &mut self,
        now: Instant,
        traffic_class: u8,
        segment: &Segment<'_>,
        metadata: crate::RxPacketMetadata,
    ) -> Result<(), Error> {
        self.input_with_receive_authorization(now, traffic_class, segment, metadata, None)
            .map(|_| ())
    }

    pub(crate) fn input_with_receive_authorization(
        &mut self,
        now: Instant,
        traffic_class: u8,
        segment: &Segment<'_>,
        metadata: crate::RxPacketMetadata,
        authorization: Option<crate::endpoint::CrossingSynAuthorization>,
    ) -> Result<bool, Error> {
        metadata.timestamps.validate(self.config.timebase)?;
        metadata.validate_segment(segment)?;
        self.input_timestamps = metadata.timestamps;
        self.input_segment_size = metadata.tcp_segment_size;
        let was_early = self.fast_open_early;
        let result = if authorization.is_some() {
            self.input_authorized(now, traffic_class, segment, authorization)
        } else {
            self.input_with_traffic_class(now, traffic_class, segment)
        };
        self.input_timestamps = RxPacketTimestamps::default();
        self.input_segment_size = None;
        result.map(|()| !was_early && self.fast_open_early)
    }

    pub(crate) fn acknowledged(&self) -> u64 {
        self.acknowledged
    }
    pub(crate) fn close_reason(&self) -> Option<CloseReason> {
        self.reason
    }
    pub(crate) fn unacknowledged(&self) -> u32 {
        self.snd_una.0
    }
    pub(crate) fn events_pending(&self) -> bool {
        !self.events.is_empty() || self.tx_timestamps.signalled()
    }
    pub(crate) fn take_events(&mut self) -> ConnectionEvents {
        let mut events = core::mem::take(&mut self.events);
        events.tx_timestamps = self.tx_timestamps.take_signal();
        events
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.5
    //# The TCP implementation MUST (MUST-33) provide a way for the application to learn
    //# how much urgent data remains to be read from the connection, or at least to
    //# determine whether more urgent data remains to be read [19].
    pub(crate) fn urgent_remaining(&self) -> u64 {
        if self.handshake_pending() && !self.fast_open_early
            || self.state == State::Closed && self.reason != Some(CloseReason::Normal)
        {
            return 0;
        }
        self.rcv_up.unwrap_or(0).saturating_sub(self.received_read)
    }

    pub(crate) fn readable_bytes(&self) -> usize {
        if self.read_closed
            || self.handshake_pending() && !self.fast_open_early
            || self.state == State::Closed
                && (self.reason != Some(CloseReason::Normal) || !self.receive.eof())
        {
            return 0;
        }
        self.receive.readable()
    }

    pub(crate) fn terminal_readable_bytes(&self) -> usize {
        if self.state == State::Closed
            && (self.handshake_complete || self.fast_open_early)
            && !self.read_closed
        {
            self.receive.readable()
        } else {
            0
        }
    }

    pub(crate) fn peek_terminal(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self.state != State::Closed {
            return Err(Error::InvalidState);
        }
        Ok(if self.terminal_readable_bytes() != 0 {
            self.receive.peek(out)
        } else {
            0
        })
    }

    pub(crate) fn read_terminal(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        if self.state != State::Closed {
            return Err(Error::InvalidState);
        }
        let count = if self.terminal_readable_bytes() != 0 {
            self.receive.read(out)
        } else {
            0
        };
        self.receive_used -= count;
        self.received_read = self.received_read.saturating_add(count as u64);
        self.rx_timestamps.consumed(self.received_read);
        // Terminal draining never schedules ACKs or window updates.
        Ok(count)
    }

    pub(crate) fn take_route_advice(&mut self) -> bool {
        core::mem::take(&mut self.route_advice_pending)
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
    //# Implementers MAY include "keep-alives" in their TCP implementations (MAY-5),
    //# although this practice is not universally accepted.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
    //# If keep-alives are included, the application MUST be able to turn them on or off
    //# for each TCP connection (MUST-24),
    pub(crate) fn set_keepalive(
        &mut self,
        keepalive: Option<KeepaliveConfig>,
    ) -> Result<(), Error> {
        if keepalive.is_some_and(|k| k.idle_us == 0 || k.interval_us == 0 || k.probes < 2) {
            return Err(Error::InvalidArgument);
        }
        self.config.keepalive = keepalive;
        self.keepalive_probes = 0;
        self.keepalive_pending = false;
        self.keepalive_deadline =
            if self.state == State::Established && self.send.len() == 0 && self.flight() == 0 {
                keepalive.map(|k| {
                    self.now
                        .saturating_add(self.config.timebase.ticks_from_us(k.idle_us))
                })
            } else {
                None
            };
        self.arm_work();
        Ok(())
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
    //# (d) An application MUST (MUST-21) be able to set the value for R2 for a
    //# particular connection.
    pub(crate) fn set_user_timeout(&mut self, timeout_us: u64) -> Result<(), Error> {
        if timeout_us == 0 {
            return Err(Error::InvalidArgument);
        }
        self.config.user_timeout_us = timeout_us;
        Ok(())
    }

    pub(crate) fn set_application_timeout(&mut self, timeout_us: Option<u64>) -> Result<(), Error> {
        if timeout_us == Some(0) {
            return Err(Error::InvalidArgument);
        }
        self.application_timeout_us = timeout_us;
        Ok(())
    }

    pub(crate) fn application_timeout(&self) -> Option<u64> {
        self.application_timeout_us
    }

    pub(crate) fn set_handshake_retransmission_limit(&mut self, limit: Option<NonZeroU8>) {
        self.handshake_retransmission_limit = limit;
    }

    pub(crate) fn handshake_retransmission_limit(&self) -> Option<NonZeroU8> {
        self.handshake_retransmission_limit
    }

    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.3.1
    //# Negative responses include the server not acknowledging the data in the SYN, ICMP error messages,
    //# and (most importantly) no response (SYN-ACK) from the server at all, i.e., connection timeout.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.1
    //= reason=The first RTO of a physically transmitted request trains the existing per-source/service cooldown once. Local output failures and held reservations do not train it; successful fallback and late cookie/MSS learning cannot erase it, and expiry permits future requests.
    //# We also RECOMMEND the client to record the set of servers that failed to respond to cookie requests and only attempt another cookie request after a certain period.
    fn report_fast_open_failure(&mut self) {
        if self.handshake_pending() && core::mem::take(&mut self.fast_open_attempt) {
            self.fast_open_negative = true;
        }
    }

    // Called after SYN-ACK or active handshake ACK validation. Any acknowledged
    // SYN payload is positive TFO progress; repair its residue separately
    // (RFC 7413 4.2.2).
    // Only SYN-only acknowledgment adds rejection evidence here. Independent
    // ICMP/RTO evidence is neither consumed nor cleared by partial progress.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
    //= reason=An emitted regular retry followed by a SYN-only acknowledgment without a cookie realizes the loss heuristic and preserves service suppression with ordinary stream progress. Delayed original, spurious, partial and returned-cookie controls keep independent RTO/rejection evidence authoritative. This is a presumption, not proof of intentional physical middlebox loss.
    //# If the client has timed out and retransmitted only regular SYN packets, it can heuristically detect paths that intentionally drop SYNs with the Fast Open option or data. If the SYN-ACK acknowledges only the initial sequence and does not carry a Fast Open cookie option, presumably it is triggered by a retransmitted (regular) SYN and the original SYN or the corresponding SYN-ACK was lost.
    fn report_fast_open_syn_rejection(&mut self, ack: Seq) {
        if self.syn_payload_sent != 0 && ack == self.iss.wrapping_add(1) {
            self.report_fast_open_failure();
        }
    }

    fn record_syn_departure(&mut self, timestamp: Option<u32>) {
        if !self.passive_open
            && let Some(value) = timestamp
        {
            let first = self.syn_timestamp_range.map_or(value, |(first, _)| first);
            self.syn_timestamp_range = Some((first, value));
        }
        if self.syn_committed {
            self.committed_syn_retransmissions =
                self.committed_syn_retransmissions.saturating_add(1);
        }
        self.syn_committed = true;
    }

    //= https://www.rfc-editor.org/rfc/rfc5927#section-5.2
    //= reason=Selected connection-local policy: network_error mutates only the matched Connection and PMTU feedback has no cross-connection cache. The existing validation test checks live-sequence rejection and error processing on that instance.
    //# Additionally, they do not extrapolate ICMP errors across TCP connections. This
    //# policy is based on the premise that TCP should be as robust as possible. Aborting
    //# the connection would be to ignore the valuable feature of the Internet -- that for
    //# many internal failures, it reconstructs its function without any disruption of the
    //# endpoints [RFC0816].

    pub(crate) fn network_error(
        &mut self,
        now: Instant,
        quoted_sequence: u32,
        error: NetworkError,
    ) -> Result<bool, Error> {
        self.update_time(now)?;
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
        //# Source Quench
        //# TCP implementations MUST silently discard any received ICMP Source
        //# Quench messages (MUST-55).
        if error == NetworkError::SourceQuench
            || matches!(self.state, State::Closed | State::TimeWait)
            || Seq(quoted_sequence).in_window(self.snd_una, self.flight()) != Some(true)
        {
            return Ok(false);
        }
        self.apply_network_error(error);
        Ok(true)
    }

    /// The advice about this connection's own reserved attempt, withdrawn
    /// unsubmitted (`Endpoint::discard_unsubmitted`): the local Host's
    /// authority stands in for the quoted-sequence check, which exists to
    /// reject reports about sequence space never sent.
    pub(crate) fn unsubmitted_network_error(
        &mut self,
        now: Instant,
        error: NetworkError,
    ) -> Result<bool, Error> {
        self.update_time(now)?;
        if error == NetworkError::SourceQuench || matches!(self.state, State::Closed | State::TimeWait)
        {
            return Ok(false);
        }
        self.apply_network_error(error);
        Ok(true)
    }

    fn apply_network_error(&mut self, error: NetworkError) {
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
        //= reason=Acts on adapter-classified errors only; soft errors remain nonterminal.
        //# Since these Unreachable messages indicate soft error conditions, a
        //# TCP implementation MUST NOT abort the connection (MUST-56), and it
        //# SHOULD make the information available to the application (SHLD-25).
        self.report_fast_open_failure();
        self.events.network_error = Some(error);
        if let Some(p) = &mut self.pmtud {
            p.network_error();
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
        //# These are hard error conditions, so TCP implementations SHOULD abort the
        //# connection (SHLD-26).
        if error == NetworkError::HardUnreachable {
            self.terminal(CloseReason::NetworkError);
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc1191#section-3.1
    //= reason=Peer MSS is stored separately from receive capability; missing IPv4 MSS defaults536 and emitted packets remain <=576 even with local MTU9000.
    //# A host doing PMTU Discovery must obey the rule that it not send IP datagrams larger
    //# than 576 octets unless it has permission from the receiver. For TCP connections,
    //# this means that a host must not send datagrams larger than 40 octets plus the
    //# Maximum Segment Size (MSS) sent by its peer.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-3.1
    //= reason=Peer MSS is stored separately from receive capability; missing IPv4 MSS defaults536 and emitted packets remain <=576 even with local MTU9000.
    //# Note: The TCP MSS is defined to be the relevant IP datagram size minus 40 [9]. The
    //# default of 576 octets for the maximum IP datagram size yields a default of 536
    //# octets for the TCP MSS.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.4
    //= reason=Peer MSS is stored separately from receive capability; missing IPv4 MSS defaults536 and emitted packets remain <=576 even with local MTU9000.
    //# A TCP implementation must also store the MSS value received from its peer (which
    //# defaults to 536), and not send any segment larger than this MSS, regardless of the
    //# PMTU. In 4.xBSD-derived implementations, this requires adding an additional field to
    //# the TCP state record.

    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.2
    //= reason=Initial/search bound intersects supplied interface, peer, administrative and allocation limits. Administrative ceilings survive validated growth without changing receive MSS.
    //# The initial value for search_high SHOULD be the largest possible packet that might
    //# be supported by the flow. This may be limited by the local interface MTU, by an
    //# explicit protocol mechanism such as the TCP MSS option, or by an intrinsic limit
    //# such as the size of a protocol length field. In addition, the initial value for
    //# search_high MAY be limited by a configuration option to prevent probing above some
    //# maximum size. Search_high is likely to be the same as the initial Path MTU as
    //# computed by the classical Path MTU Discovery algorithm.

    fn path_bound(&self, link: u32) -> u32 {
        let base = if self.tuple.local.is_ipv4() { 20 } else { 40 };
        let floor = min_mtu(self.tuple.local.is_ipv4());
        // A tiny peer/allocation ceiling limits packetization, not the IP
        // family's minimum legal path estimate. Such flows cannot size-probe.
        link.min(
            (u32::from(self.config.send_ip_payload_limit) + u32::from(self.ip_header_len))
                .max(floor),
        )
        .min((u32::from(self.peer_mss.min(self.send_mss_limit)) + base + 20).max(floor))
        .min((self.scratch.len() as u32 + base + 20).max(floor))
    }

    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.4
    //= reason=Dynamic send path MSS never mutates the receive offer (Host-derived when managed, configured when raw); family-floor wire test asserts unchanged receive capability.
    //# PMTU Discovery does not affect the value sent in the TCP MSS option, because that
    //# value is used by the other end of the connection, which may be using an unrelated
    //# PMTU value.

    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.4
    //= reason=IPv6 core stores peer MSS separately, defaults1220, caps transmit size independently of local link and retains receive MSS1460.
    //# A TCP implementation must also store the Maximum Segment Size (MSS) value received
    //# from its peer, which represents the EMTU_R, the largest packet that can be
    //# reassembled by the receiver, and must not send any segment larger than this MSS,
    //# regardless of the PMTU.

    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.4
    //= reason=IPv6 core stores peer MSS separately, defaults1220, caps transmit size independently of local link and retains receive MSS1460.
    //# The value sent in the TCP MSS option is independent of the PMTU; it is determined by
    //# the receiver reassembly limit EMTU_R. This MSS option value is used by the other end
    //# of the connection, which may be using an unrelated PMTU value. See Section 5,
    //# "Packet Size Issues", and Section 8.3, "Maximum Upper-Layer Payload Size", of
    //# [RFC8200] for information on selecting a value for the TCP MSS option.

    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.4
    //= reason=Connection caches PMTU-derived MSS and bounds packetization by it; family-floor wire tests assert repaired packets within the updated PMTU. GET_MAXSIZES polling is an example, not a required API. Probe behavior is the selected RFC4821 extension.
    //# The TCP layer must track the PMTU for the destination of a connection; it should
    //# not send datagrams that would be larger than this. A simple implementation could
    //# ask the IP layer for this value (using the GET_MAXSIZES interface described in
    //# [1]) each time it created a new segment, but this could be inefficient.
    //# Moreover, TCP implementations that follow the "slow-start" congestion-avoidance
    //# algorithm [4] typically calculate and cache several other values derived from
    //# the PMTU. It may be simpler to receive asynchronous notification when the PMTU
    //# changes, so that these variables may be updated.

    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.1
    //= reason=Enabled TCP limits complete IPv6 packets to the path budget rather than invoking source fragmentation; the family-floor test parses base-header packets and checks resized retry length with timestamp options. Extension headers and shared caches are not prerequisites of this avoidance recommendation.
    //# However, packetization layers are encouraged to avoid sending messages that will
    //# require source fragmentation (for the case against fragmentation, see [FRAG]).

    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.4
    //= reason=Connection uses the PMTU-derived budget for ordinary data/retries and a distinct bounded real-data probe size. Dual-family wire tests check the exact larger probe and unchanged effective PMTU before ACK; base-header IPv6 packets are unfragmented. IP-service polling is an optional implementation example.
    //# A packetization layer (e.g., TCP) must use the PMTU for the path(s) in use by a
    //# connection; it should not send segments that would result in packets larger than
    //# the PMTU, except to probe during PMTU Discovery (this probe packet must not be
    //# fragmented to the PMTU). A simple implementation could ask the IP layer for this
    //# value each time it created a new segment, but this could be inefficient. An
    //# implementation typically caches other values derived from the PMTU. It may be
    //# simpler to receive asynchronous notification when the PMTU changes, so that
    //# these variables may be also updated.

    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.5
    //= reason=TCP packetizes ordinary data to the path budget and provides real-data discovery probes. The dual-family test checks complete probe length and ACK-confirmed increase; this is the transport duty, not an NFS conformance claim.
    //# In this case, the transport is responsible for ensuring that transmitted
    //# segments (except probes) conform to the Path MTU, including supporting PMTU
    //# Discovery probe transmissions as needed.

    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.4
    //= reason=Implemented operative behavior: a PTB indicating a lost PMTU probe is not a congestion notification. Probe attribution invalidates the probe size for Unchanged, Deferred, Decreased and older-incarnation reports alike while finite isolated-probe proof survives, a congestion-loss response is suppressed only after receiver delivery and recovery exit, and neither the PTB nor its exact-range repair reduces cwnd or ssthresh, enters or extends recovery or starts PRR. Accepted lower PMTU still calls refresh_path_mss and Congestion::set_mss, rescaling the byte congestion window when MSS decreases; the dual-family receiver matrix asserts that ratio. Remaining (T23, AC-27): only the standards decision whether that RFC 5681/RFC 4821 MSS-decrease rescaling conflicts with "the congestion window may not change"; required MSS rescaling is preserved.
    //# A loss caused by a PMTU probe indicated by the reception of a Packet Too Big message must not be considered as a congestion notification, and hence the congestion window may not change.
    fn refresh_path_mss(&mut self) {
        self.refresh_path_mss_with(true);
    }

    // `repair` selects whether an MSS decrease schedules the generic head
    // retry (non-PTB causes) or only updates the packet budget.
    fn refresh_path_mss_with(&mut self, repair: bool) {
        let Some(link) = self.pmtud.as_ref().map(|p| p.info.first_hop_mtu) else {
            if self.managed_path.is_some() {
                let base = if self.tuple.local.is_ipv4() { 20 } else { 40 };
                let options = usize::from(self.ip_header_len - base) + if self.timestamps { 12 } else { 0 };
                let effective = usize::from(self.peer_mss.min(self.send_mss_limit)
                    .min(self.config.user_mss.unwrap_or(u16::MAX)))
                    .min(self.scratch.len()).saturating_sub(options).max(1)
                    .min(self.path_payload_limit().saturating_sub(20 + if self.timestamps { 12 } else { 0 }).max(1));
                self.update_path_mss(effective, repair);
            }
            return;
        };
        let bound = self.path_bound(link);
        let p = self.pmtud.as_mut().unwrap();
        if self.managed_path.is_some() {
            p.constrain_network(bound);
        } else {
            p.constrain(bound);
        }
        let mss = p
            .info
            .current_mtu
            .saturating_sub(
                u32::from(self.ip_header_len) + 20 + if self.timestamps { 12 } else { 0 },
            )
            .max(1) as usize;
        let base = if self.tuple.local.is_ipv4() { 20 } else { 40 };
        let options = usize::from(self.ip_header_len - base) + if self.timestamps { 12 } else { 0 };
        let ceiling = usize::from(
            self.peer_mss
                .min(self.send_mss_limit)
                .min(self.config.user_mss.unwrap_or(u16::MAX)),
        )
        .min(self.scratch.len())
        .saturating_sub(options)
        .max(1);
        let budget = (self.config.send_ip_payload_limit as usize)
            .saturating_sub(20 + if self.timestamps { 12 } else { 0 })
            .max(1);
        self.update_path_mss(
            mss.min(ceiling).min(budget).min(self.managed_payload_mss()),
            repair,
        );
        self.resolve_probe_response();
    }

    pub(crate) fn reserved_pacing_deadline(&self, now: Instant, d: &Departure) -> Option<Instant> {
        if d.bypass || d.initial_burst || !d.stream {
            return None;
        }
        if d.interval.is_some() {
            self.general_pacing_deadline(now)
        } else if d.legacy_rate.is_some() {
            self.pacing_deadline.filter(|&deadline| now < deadline)
        } else {
            None
        }
    }

    pub(crate) fn validate_reserved_output(
        &self,
        now: Instant,
        d: &Departure,
        offset: usize,
        count: usize,
    ) -> Result<(), Error> {
        self.check_time(now)?;
        if now < d.selected_at {
            return Err(Error::TimeWentBackwards);
        }
        if offset > d.payload || count > d.payload - offset {
            return Err(Error::InvalidArgument);
        }
        if d.stream
            && count != 0
            && let Some(selection) = self.reserved_ledger
        {
            let start = Seq(d.start).wrapping_add(u32::from(d.syn) + offset as u32);
            if !self.rack.validate_departure(
                selection,
                start,
                start.wrapping_add(count as u32),
                now,
            ) {
                return Err(Error::InvalidArgument);
            }
        }
        Ok(())
    }

    /// `validate_reserved_output` of the segments of a GSO reservation that
    /// cover `bytes` from `offset`, each accepted at `now` in turn: once this
    /// holds, none of those acceptances can fail part way through a group.
    pub(crate) fn validate_reserved_group(
        &self,
        now: Instant,
        d: &Departure,
        offset: usize,
        bytes: usize,
    ) -> Result<(), Error> {
        let s = d.segmentation.ok_or(Error::InvalidArgument)?;
        self.validate_reserved_output(now, d, offset, bytes)?;
        if let Some(selection) = self.reserved_ledger
            && !self.rack.validate_departure_group(
                selection,
                Seq(d.start).wrapping_add(offset as u32),
                s.segment_payload_len as u32,
                bytes,
                now,
            )
        {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    fn record_fin_departure(&mut self, start: Seq, payload: usize) {
        self.fin_needs_separate_credit = payload == 0
            || self
                .rack
                .record_fin_payload(start, start.wrapping_add(payload as u32));
    }

    /// Returns whether the reservation ends at this fragment although its
    /// suffix was not emitted: a PTB repair split during Restart, whose
    /// never-charged suffix stays pending repair work.
    pub(crate) fn accept_reserved_output(
        &mut self,
        now: Instant,
        d: &mut Departure,
        offset: usize,
        count: usize,
        finished: bool,
    ) -> Result<bool, Error> {
        self.validate_reserved_output(now, d, offset, count)?;
        if d.stream
            && count != 0
            && let Some(selection) = self.reserved_ledger
        {
            let start = Seq(d.start).wrapping_add(u32::from(d.syn) + offset as u32);
            // Validated above; nothing since changed the intervals.
            self.rack.commit_validated_departure(
                selection,
                start,
                start.wrapping_add(count as u32),
                now,
            );
        }
        self.accept_departed_output(now, d, offset, count, finished)
    }

    /// `accept_reserved_output` of each segment of a GSO reservation that
    /// covers `bytes` from `offset`, in turn at `now`, after
    /// `validate_reserved_group` held. RACK records the whole group at once:
    /// what the rest of each acceptance reads of it (packet counts, short
    /// transmissions, its timer) is overwritten by the last segment's, which
    /// sees every segment committed either way. Fresh data only; SYN,
    /// retransmission and PTB repair acceptances, which record more in RACK,
    /// take each segment alone.
    pub(crate) fn accept_reserved_group(
        &mut self,
        now: Instant,
        d: &mut Departure,
        offset: usize,
        bytes: usize,
        finished: bool,
    ) {
        let size = d.segmentation.unwrap().segment_payload_len;
        let segments = bytes.div_ceil(size);
        let whole = !(d.syn || d.retransmission || d.ptb_repair);
        debug_assert!(self.validate_reserved_group(now, d, offset, bytes).is_ok());
        if whole
            && d.stream
            && let Some(selection) = self.reserved_ledger
        {
            self.rack.commit_validated_group(
                selection,
                Seq(d.start).wrapping_add(offset as u32),
                size as u32,
                bytes,
                now,
            );
        }
        for n in 0..segments {
            let (at, count) = (offset + n * size, size.min(bytes - n * size));
            let last = finished && n + 1 == segments;
            // The group preflight covers every segment, and nothing else
            // runs between these acceptances.
            let withdrawn = if whole {
                self.accept_departed_output(now, d, at, count, last)
            } else {
                self.accept_reserved_output(now, d, at, count, last)
            }
            .expect("preflighted group departure");
            // Only PTB repairs withdraw a suffix; GSO selects fresh data.
            debug_assert!(!withdrawn);
        }
    }

    // The rest of `accept_reserved_output`, once RACK has the departure.
    fn accept_departed_output(
        &mut self,
        now: Instant,
        d: &mut Departure,
        offset: usize,
        count: usize,
        finished: bool,
    ) -> Result<bool, Error> {
        self.control_undo = None;
        if count != 0 {
            if let Some(resource) = self.local_resource.take() {
                self.application_progress_at = resource.epoch.unwrap_or(now);
            }
            self.repair_undo = None; // Accepted prefixes can never be cancelled.
            self.reserved_retransmit_counts = None;
        }
        if finished && d.defer_push {
            self.send.collapse_push(
                Seq(d.start).distance_from(self.send_base) as usize,
                d.payload,
            );
            d.defer_push = false;
        }
        if count != 0
            && (d.segmentation.is_some() || d.deferred_fresh)
            && let Some(p) = &mut self.pmtud
        {
            // An aggregate is not a physical packet or PMTU observation. Record
            // only the actual accepted segment, including any reduced-MTU split.
            let start = Seq(d.start).wrapping_add(u32::from(d.syn) + offset as u32);
            p.sent(
                start,
                start.wrapping_add(count as u32),
                (count
                    + d.segmentation
                        .map_or(if self.timestamps { 32 } else { 20 }, |s| s.tcp_header_len))
                    as u32
                    + u32::from(self.ip_header_len),
                self.ip_header_len,
                false,
            );
            if self.managed_path.is_some() {
                p.defer_proof_latest();
            }
        }
        if d.deferred_fresh && count != 0 && !finished {
            // The unsubmitted suffix is reserved sequence space, not another
            // physical packet. Keep partial-acceptance diagnostics truthful.
            self.reserved_retransmit_counts = Some(self.rack.diagnostic_packet_counts());
        }
        self.update_time(now)?;
        if d.stream
            && !d.ptb_repair
            && let Some(prr) = &mut self.prr
            && prr.timer_repair()
        {
            prr.sent(count as u32);
            if finished {
                prr.finish_timer_repair();
            }
        }
        self.adaptive_departure(d.data_ack, d.fresh_data && count != 0 && !d.syn);
        d.data_ack = false; // One logical ACK, including SACK-only repair fragments.
        self.syn_data_acked |= d.received_syn_data_acked;
        self.syn_data_fully_acked |= d.received_syn_data_acked;
        // Payload has accepted-departure evidence in RACK. SYN (including
        // SYN+data) and standalone FIN retain their Karn-eligible sample, but
        // measure from acceptance, never from the encoded TSval's selection.
        // A retransmission already invalidated sample during selection; an
        // earlier flight's sample must not acquire this output's departure.
        let end = Seq(d.start).wrapping_add(if d.syn {
            1
        } else {
            d.payload as u32 + u32::from(d.fin)
        });
        if d.syn {
            if finished {
                self.fast_open_attempt |= d.fast_open && !self.syn_committed;
                self.fast_open_option_sent |= d.fast_open_option;
                self.fast_open_response_committed |= d.simultaneous_response;
                self.record_syn_departure(d.syn_timestamp);
                self.syn_sent_at = Some(now);
            }
            self.syn_payload_sent = self.syn_payload_sent.max(count);
            self.rack.record_syn_payload(
                Seq(d.start).wrapping_add(1),
                Seq(d.start).wrapping_add(1 + count as u32),
            );
        }
        if (d.payload != 0 || d.syn || d.fin) && self.sample.is_some_and(|(edge, _)| edge == end) {
            if d.payload != 0 && !d.syn {
                self.sample = None;
            } else if d.syn || (d.fin && finished) {
                self.sample_departure = Some(now);
            }
        }
        let sequence = count != 0 || d.syn || (d.fin && finished);
        if d.stream && count != 0 {
            self.last_sent = now;
            if let Some(interval) = d.interval {
                if d.initial_burst {
                    let burst = self.config.pacing.unwrap().max_burst_segments * self.mss as u32;
                    self.pacer.startup_sent(now, count, interval, burst);
                } else {
                    self.pacer.sent(now, count, interval);
                }
                self.pacing_deadline = self.general_pacing_deadline(now);
            } else if let Some((rtt, cwnd)) = d.legacy_rate {
                let spacing = (count as u128 * rtt as u128)
                    .div_ceil(cwnd as u128)
                    .clamp(1, u64::MAX as u128) as u64;
                // Bypass probes cannot erase debt belonging to earlier output.
                self.pacing_deadline = Some(
                    self.pacing_deadline
                        .unwrap_or(now)
                        .max(now)
                        .saturating_add(spacing),
                );
            }
        }
        if d.fin && finished {
            self.record_fin_departure(Seq(d.start).wrapping_add(offset as u32), count);
            self.fin_sent_at = Some(now);
        }
        // Accepted PTB repair coverage consumes the Restart allowance. In
        // Restart a split repair ends at its first accepted fragment.
        let mut withdrawn = false;
        if d.ptb_repair && (count != 0 || d.fin && finished) {
            withdrawn = !finished && self.ptb_in_restart();
            self.ptb_repair_committed();
        }
        // Only this accepted coverage became a (possibly) submitted copy.
        if d.retransmission {
            self.record_retransmission(
                Seq(d.start).wrapping_add(u32::from(d.syn) + offset as u32),
                if d.stream { count } else { 0 },
                d.fin && finished && d.fin_retransmission,
                d.ptb_repair,
            );
            if sequence {
                self.count_retransmitted_segment(d.timeout_recovery);
            }
        }
        // The probe's first accepted sequence-bearing segment sends it.
        if sequence && d.loss_probe {
            self.loss_events.loss_probes += 1;
            d.loss_probe = false;
        }
        if d.ptb_repair {
            self.commit_ptb_copy(
                now,
                d.selected_at,
                Seq(d.start).wrapping_add(offset as u32),
                count,
                d.fin && finished,
                finished || withdrawn,
            );
        }
        if sequence && d.rto {
            // A non-head retry cannot replace an ACK-restarted timer with
            // head.sent + RTO (nor defer an already overdue older flight).
            self.rto_deadline = if d.rto_head {
                Some(now.saturating_add(self.rto()))
            } else {
                Some(
                    d.prior_rto_deadline
                        .unwrap_or(d.selected_at.saturating_add(self.rto())),
                )
            };
            // The first accepted sequence-bearing fragment owns this restart;
            // later siblings must not defer that prefix's RTO.
            d.rto = false;
        }
        if sequence && d.shrink {
            self.shrink_unanswered_since = Some(now);
            d.shrink = false;
        }
        if d.persist && (sequence || finished) {
            if self.snd_wnd == 0 {
                if d.unanswered {
                    self.persist_unanswered_since = Some(now);
                }
                if self.flight() != 0 {
                    self.rto_deadline = Some(now.saturating_add(self.persist_interval));
                } else {
                    self.persist_deadline = Some(now.saturating_add(self.persist_interval));
                }
            } else if sequence && self.flight() != 0 {
                // A real data retry accepted after reopening rejoins normal
                // RTO management. An empty control cannot create that timer.
                self.rto_deadline = Some(now.saturating_add(self.rto()));
            }
            d.unanswered = false;
            d.persist = false;
        }
        if d.keepalive {
            self.keepalive_deadline = self
                .config
                .keepalive
                .map(|k| now.saturating_add(self.config.timebase.ticks_from_us(k.interval_us)));
            d.keepalive = false;
        }
        if sequence && d.tlp {
            if self.rto_deadline.is_some_and(|deadline| deadline <= now) {
                // Local waiting cannot insert a new PTO ahead of an already
                // expired older flight's RTO (PTO wins capped ties otherwise).
                self.tlp_deadline = None;
            } else {
                self.schedule_tlp();
            }
        }
        if d.syn && finished && self.early_response_eligible() {
            self.arm_work();
        } else {
            self.select_loss_timer();
        }
        if withdrawn {
            self.arm_work();
        }
        Ok(withdrawn)
    }

    // One accepted segment carried retransmitted sequence space.
    fn count_retransmitted_segment(&mut self, timeout_recovery: bool) {
        self.total_retrans += 1;
        self.loss_events.retransmitted_segments += 1;
        self.loss_events.timeout_retransmitted_segments += u64::from(timeout_recovery);
    }

    pub(crate) fn abandon_reserved_output(&mut self) {
        self.reject_reserved_output();
        self.pending_rst = None;
        self.reset_echo = None;
        self.reset_reply = false;
        self.repair_undo = None;
        self.control_undo = None;
        self.reserved_retransmit_counts = None;
        self.terminal(CloseReason::Aborted);
    }

    pub(crate) fn reject_reserved_output(&mut self) {
        if let Some((start, end)) = self.last_pmtu_output.take()
            && let Some(p) = &mut self.pmtud
        {
            p.reject_latest(start, end);
        }
        self.resolve_probe_response();
    }

    pub(crate) fn path_payload_limit(&self) -> usize {
        let local = self.pmtud
            .as_ref()
            .map_or(self.config.send_ip_payload_limit as usize, |p| {
                (self.config.send_ip_payload_limit as usize).min(
                    p.info
                        .current_mtu
                        .saturating_sub(u32::from(self.ip_header_len)) as usize,
                )
            });
        local.min(self.managed_path.as_ref().map_or(usize::MAX, |path| {
            self.managed_ip_budget(path)
                .saturating_sub(u32::from(self.ip_header_len)) as usize
        }))
    }

    fn managed_payload_mss(&self) -> usize {
        self.managed_path.as_ref().map_or(usize::MAX, |path| {
            self.managed_ip_budget(path)
                .saturating_sub(u32::from(self.ip_header_len) + 20 + if self.timestamps { 12 } else { 0 })
                .max(1) as usize
        })
    }

    // The path's packet budget for this connection. Without discovery an
    // IPv6 connection keeps every complete packet within the IPv6 minimum
    // link MTU, whose payload ceiling `send_ip_payload_limit` states only
    // for the base header: an SR route's Segment Routing Header counts too.
    fn managed_ip_budget(&self, path: &crate::PreparedPath) -> u32 {
        let budget = path.snapshot.ip_packet_budget().unwrap_or(0);
        if self.pmtud.is_none() && !self.tuple.local.is_ipv4() {
            budget.min(min_mtu(false))
        } else {
            budget
        }
    }

    // The complete IP header this connection's packets carry on `path`: its
    // IPv4 header with options, or the path's IPv6 header (the base header
    // and an SR route's Segment Routing Header).
    fn path_ip_header_len(&self, path: &crate::PreparedPath) -> u16 {
        if self.tuple.local.is_ipv4() {
            self.ip_header_len
        } else {
            path.snapshot.ip_header_len() as u16
        }
    }

    /// Whether the packet budget of `path` still carries this connection's
    /// complete IP header on it (options and extension headers included),
    /// its TCP header with every option it sends and one payload octet.
    pub(crate) fn represents_budget(&self, path: &crate::PreparedPath) -> bool {
        path.snapshot.ip_packet_budget().is_ok_and(|budget| {
            budget
                >= u32::from(self.path_ip_header_len(path)) + 20 + if self.timestamps { 12 } else { 0 } + 1
        })
    }

    /// Read-only check that `apply_managed_budget(path)` succeeds (the same
    /// binding authority).
    pub(crate) fn check_managed_budget(&self, path: &crate::PreparedPath) -> Result<(), Error> {
        let old = self.managed_path.as_ref().ok_or(Error::InvalidState)?;
        if path.snapshot.status() != ntcp_path::PathStatus::Valid
            || old.snapshot.key().context() != path.snapshot.key().context()
            || old.snapshot.key().source_address() != path.snapshot.key().source_address()
            || old.snapshot.key().destination() != path.snapshot.key().destination()
            || (old.client == path.client && path.snapshot.version() < old.snapshot.version())
        {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Network authority changes packetization, never loss/retry classification.
    /// Safe while a reservation is held: its immutable bytes are checked again
    /// by the serialized submission barrier and split only after nonsubmission.
    /// Returns whether anything changed: false for the binding already applied.
    pub(crate) fn apply_managed_budget(
        &mut self,
        path: crate::PreparedPath,
    ) -> Result<bool, Error> {
        self.check_managed_budget(&path)?;
        let old = self.managed_path.as_ref().unwrap();
        if *old == path {
            return Ok(false);
        }
        let replaced = old.snapshot.path() != path.snapshot.path();
        let rebound = old.client != path.client;
        let negative = old.snapshot.negative_revision() != path.snapshot.negative_revision();
        let bound = self.path_bound(path.snapshot.first_hop_mtu());
        if let Some(p) = &mut self.pmtud {
            p.set_plateaus(self.config.pmtud.unwrap().policy.ipv4_plateaus.for_path(Some(path)));
            p.network_link_bound(path.snapshot.first_hop_mtu(), bound);
            if replaced {
                p.replace_network_authority();
            } else if negative {
                p.invalidate_probe_size_result();
            }
            // Owner policy delivered with the snapshot: stale-policy size
            // results lose eligibility; the administrative value caps the
            // search and arms its targeted attempt; a working baseline at or
            // above it is lowered to a smaller shared network estimate (not
            // the discovery-policy sending limit, which is no estimate).
            p.set_policy_revision(path.snapshot.discovery_revision());
            p.set_discovery_disabled(path.snapshot.discovery_disabled());
            p.set_administrative(path.snapshot.administrative_estimate());
            p.set_shared_estimate(path.snapshot.pmtu_estimate().ok());
            if let Ok(budget) = path.snapshot.pmtu_estimate() {
                p.lower_baseline(budget);
            }
        }
        if replaced || rebound {
            // Results and provenance describe only the binding they arose on.
            self.managed_results = crate::endpoint::ManagedResults::default();
        } else if negative {
            // Newer negative evidence makes earlier delivery proof stale. An
            // applied decrease stays: the Host discards it once subsumed.
            self.managed_results.receipt = None;
            self.managed_results.confirmed = None;
        }
        self.managed_path = Some(path);
        // A replacement route may add, change or drop a Segment Routing
        // Header: every later packet is sized for the new path's header.
        self.ip_header_len = self.path_ip_header_len(&path);
        let base = if self.tuple.local.is_ipv4() { 20 } else { 40 };
        let options = usize::from(self.ip_header_len - base) + if self.timestamps { 12 } else { 0 };
        let local = self.pmtud.as_ref().map_or(usize::MAX, |p| {
            p.info.current_mtu.saturating_sub(u32::from(self.ip_header_len) + 20
                + if self.timestamps { 12 } else { 0 }).max(1) as usize
        });
        let effective = usize::from(self.peer_mss.min(self.send_mss_limit)
            .min(self.config.user_mss.unwrap_or(u16::MAX)))
            .min(self.scratch.len()).saturating_sub(options).max(1)
            .min(self.config.send_ip_payload_limit as usize - 20 - if self.timestamps { 12 } else { 0 })
            .min(local).min(self.managed_payload_mss());
        self.set_path_mss_budget(effective);
        Ok(true)
    }

    pub(crate) fn ip_header_len(&self) -> u16 { self.ip_header_len }

    /// Convert exactly identified Pmtud events into unpublished results and
    /// drop provenance or receipts whose report or probe no longer exists.
    fn observe_pmtud_results(&mut self) {
        let Some(p) = &mut self.pmtud else {
            return;
        };
        let results = &mut self.managed_results;
        if let Some((id, mtu)) = p.take_applied_pending()
            && let Some((pending, mut result)) = results.pending.take()
            && pending == id
        {
            result.applied_mtu = mtu;
            let shared = |r: crate::PendingPmtuApplied| r.host_estimate.max(r.applied_mtu);
            // One slot: an unpublished smaller decrease is never lost.
            if results.applied.is_none_or(|old| shared(result) < shared(old)) {
                results.applied = Some(result);
            }
        }
        if results.pending.is_some_and(|(id, _)| p.pending_id() != Some(id)) {
            results.pending = None;
        }
        if let Some(success) = p.take_probe_success()
            && let Some((probe, intent, receipt)) = results.receipt.take()
            && probe == success
        {
            results.confirmed = Some(crate::ConfirmedProbe { intent, receipt });
        }
        if results
            .receipt
            .is_some_and(|(probe, ..)| p.provable_probe() != Some(probe))
        {
            results.receipt = None;
        }
    }

    /// Final-byte provenance for the physical packet of reserved output that
    /// was definitely submitted as `receipt` (accepted at `offset`, `count`
    /// payload octets): an unfragmentable packet becomes size evidence; a
    /// DF-clear IPv4 packet stays ineligible.
    pub(crate) fn certify_submission(
        &mut self,
        d: &Departure,
        offset: usize,
        count: usize,
        receipt: crate::PhysicalReceipt,
    ) {
        let unfragmented = receipt.dont_fragment || !self.tuple.local.is_ipv4();
        let Some(p) = &mut self.pmtud else {
            return;
        };
        let (start, end) = if d.segmentation.is_some() || d.deferred_fresh {
            let start = Seq(d.start).wrapping_add(u32::from(d.syn) + offset as u32);
            (start, start.wrapping_add(count as u32))
        } else {
            let start = Seq(d.start);
            let length = d.payload as u32 + u32::from(d.syn) + u32::from(d.fin);
            (start, start.wrapping_add(length))
        };
        p.certify(start, end, receipt.ip_packet_len, unfragmented);
    }

    /// Retain a definitely-submitted receipt with the active probe it proves.
    pub(crate) fn retain_probe_receipt(
        &mut self,
        start: Seq,
        intent: crate::DiscoveryIntent,
        receipt: crate::PhysicalReceipt,
    ) {
        let (Some(p), Some(binding)) = (&self.pmtud, self.managed_path) else {
            return;
        };
        let selected = intent.binding.snapshot;
        if let Some(probe) = p.provable_probe()
            && probe.0 == start
            && probe.2 == intent.ip_packet_len
            && receipt.ip_packet_len == intent.ip_packet_len
            && (receipt.dont_fragment || !self.tuple.local.is_ipv4())
            && intent.binding.client == binding.client
            && selected.path() == binding.snapshot.path()
            && selected.negative_revision() == binding.snapshot.negative_revision()
            && intent.selected_at >= binding.snapshot.retry_not_before()
        {
            self.managed_results.receipt = Some((probe, intent, receipt));
        }
    }

    pub(crate) fn set_ip_header_len(&mut self, len: u16) {
        if self.ip_header_len != len {
            self.ip_header_len = len;
            self.refresh_path_mss();
        }
    }

    pub(crate) fn administrative_search(&self) -> Option<crate::AdministrativeSearch> {
        self.pmtud.as_ref().and_then(|p| p.administrative_search())
    }

    pub(crate) fn path_mtu_info(&self) -> Option<crate::PathMtuInfo> {
        self.pmtud.as_ref().map(|p| p.info)
    }

    pub(crate) fn validate_pmtud_policy(
        &self,
        now: Instant,
        policy: crate::PmtudPolicy,
    ) -> Result<(), Error> {
        self.check_time(now)?;
        if self.pmtud.is_none() {
            return Err(Error::InvalidArgument);
        }
        policy
            .search_aging
            .ticks(self.config.timebase.units_per_second)?;
        Ok(())
    }

    /// The connection's creation (or last set) PLPMTUD policy, if enabled.
    pub(crate) fn pmtud_policy(&self) -> Option<crate::PmtudPolicy> {
        self.config.pmtud.map(|p| p.policy)
    }

    pub(crate) fn set_pmtud_policy(
        &mut self,
        now: Instant,
        policy: crate::PmtudPolicy,
    ) -> Result<(), Error> {
        self.validate_pmtud_policy(now, policy)?;
        let aging = policy
            .search_aging
            .ticks(self.config.timebase.units_per_second)?;
        self.update_time(now)?;
        let mut effective = policy;
        effective.ipv4_plateaus = policy.ipv4_plateaus.for_path(self.managed_path);
        self.pmtud.as_mut().unwrap().set_policy(now, effective, aging);
        self.config.pmtud.as_mut().unwrap().policy = policy;
        self.arm_work();
        Ok(())
    }

    pub(crate) fn validate_route_mtu(&self, now: Instant, mtu: Option<u32>) -> Result<(), Error> {
        self.check_time(now)?;
        let ipv4 = self.tuple.local.is_ipv4();
        let range = self.config.packetization_mtu_floor(ipv4)..=if ipv4 { 65535 } else { 65575 };
        if self.pmtud.is_none() || mtu.is_some_and(|mtu| !range.contains(&mtu)) {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    pub(crate) fn set_route_mtu(&mut self, now: Instant, mtu: Option<u32>) -> Result<(), Error> {
        self.validate_route_mtu(now, mtu)?;
        self.update_time(now)?;
        self.pmtud.as_mut().unwrap().set_route_mtu(mtu);
        self.config.pmtud.as_mut().unwrap().route_mtu = mtu;
        self.refresh_path_mss();
        self.arm_work();
        Ok(())
    }

    pub(crate) fn validate_first_hop_mtu(&self, now: Instant, mtu: u32) -> Result<(), Error> {
        self.check_time(now)?;
        let range = if self.tuple.local.is_ipv4() {
            68..=65535
        } else {
            1280..=65575
        };
        if !range.contains(&mtu) || self.pmtud.is_none() {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    pub(crate) fn set_reserved_first_hop_mtu(
        &mut self,
        now: Instant,
        mtu: u32,
    ) -> Result<(), Error> {
        // Local repair owns this output. An MSS change must not schedule an
        // additional SYN/head retransmission for the same unsubmitted bytes.
        let pending = (self.syn_pending, self.retx_pending);
        self.set_first_hop_mtu(now, mtu)?;
        (self.syn_pending, self.retx_pending) = pending;
        self.arm_work();
        Ok(())
    }

    pub(crate) fn set_first_hop_mtu(&mut self, now: Instant, mtu: u32) -> Result<(), Error> {
        self.validate_first_hop_mtu(now, mtu)?;
        let bound = self.path_bound(mtu);
        self.update_time(now)?;
        self.pmtud.as_mut().unwrap().link(mtu, bound, now);
        self.refresh_path_mss();
        self.arm_work();
        Ok(())
    }

    //= https://www.rfc-editor.org/rfc/rfc5927#section-4.1
    //= reason=Informational mitigation selected as policy: live serial send-window validation plus stronger exact recent packet gate; stale/idle and wrapped-sequence quotes tested, not authentication.
    //# Many TCP implementations have incorporated a validation check such that they react
    //# only to those ICMP error messages that appear to relate to segments currently "in
    //# flight" to the destination system. These implementations check that the TCP sequence
    //# number contained in the payload of the ICMP error message is within the range
    //# SND.UNA =< SEG.SEQ < SND.NXT. This means that they require that the sequence number
    //# be within the range of the data already sent but not yet acknowledged. If an ICMP
    //# error message does not pass this check, it is discarded.

    //= https://www.rfc-editor.org/rfc/rfc5927#section-7.4
    //= reason=Informational serial-arithmetic guidance: Seq::in_window and wrapping comparisons, exercised across u32 wrap; exact-match sent evidence is an additional policy gate.
    //# Notes: All comparisons between sequence numbers must be performed using sequence
    //# number arithmetic.

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.2
    //= reason=Enabled core implements validated PTB, real-data ACK-confirmed probes, bounded search and R1 black-hole fallback. Native IPv4 TUN/AF_PACKET ingress and real MTU startup integrate it. This closes the implementation recommendation, not all external RFC clauses: RFC1191/8201/4821 inventories retain exact gaps; native IPv6 sockets remain unsupported.
    //# Instead, implementation of Path MTU Discovery (PMTUD) and Packetization Layer Path
    //# MTU Discovery (PLPMTUD) is strongly recommended in order for TCP to improve
    //# segmentation decisions.
    //= https://www.rfc-editor.org/rfc/rfc5927#section-7.4
    //= reason=Selected live-sequence check uses serial arithmetic for SND.UNA<=seq<SND.NXT; the same stale/idle/wrapped quote test supports 044. Unrelated initialization and reset deviations do not invalidate this branch.
    //# if (claimedtcpseq < SND.UNA || claimedtcpseq >= SND.NXT) drop_message();

    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.4
    //= reason=Accepted feedback repairs only the matched Connection's quoted range at once; the family-floor test verifies the repair's sequence/payload and complete packet size within the new PMTU. Cross-connection dispatch is additionally exercised by native tuple validation; exact dropped-range notification and burst non-amplification are audited in 1191-061, 1191-064 and 1191-080.
    //# Alternatively, the retransmission could be done in immediate response to a
    //# notification that the Path MTU has changed, but only for the specific connection
    //# specified by the Datagram Too Big message. The datagram size used in the
    //# retransmission should, of course, be no larger than the new PMTU.

    //= https://www.rfc-editor.org/rfc/rfc8201#section-3
    //= reason=Enabled IPv6 core consumes validated PTB, reduces the estimate and emits a smaller unfragmented retry. The dual-family floor test checks complete packet length and retry payload; no native IPv6 socket claim.
    //# Upon receipt of such a message, the source node reduces its assumed PMTU for the
    //# path based on the MTU of the constricting hop as reported in the Packet Too Big
    //# message. The decreased PMTU causes the source to send smaller packets or change
    //# EMTU_S to cause the upper layer to reduce the size of IP packets it sends.

    //= https://www.rfc-editor.org/rfc/rfc8201#section-4
    //= reason=Validated initial IPv6 PTB reduces packet size; the dual-family floor test asserts a complete retry no larger than 1280. Smaller successive legal reports decrease it the same way; no source fragmentation is used.
    //# After receiving a Packet Too Big message, a node must attempt to avoid eliciting
    //# more such messages in the near future. The node must reduce the size of the
    //# packets it is sending along the path. Using a PMTU estimate larger than the IPv6
    //# minimum link MTU may continue to elicit Packet Too Big messages. Because each of
    //# these messages (and

    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.4
    //= reason=Validated feedback for the matched Connection immediately repairs its quoted range no larger than the new IPv6 PMTU; the dual-family floor test checks sequence, payload and full packet length. Notification of the dropped data is audited in 8201-064.
    //# Alternatively, the retransmission could be done in immediate response to a
    //# notification that the Path MTU was decreased, but only for the specific
    //# connection specified by the Packet Too Big message. The packet size used in the
    //# retransmission should be no larger than the new PMTU.

    pub(crate) fn pmtu_feedback(
        &mut self,
        now: Instant,
        seq: u32,
        size: u32,
        header: u16,
        mtu: u32,
    ) -> Result<bool, Error> {
        self.update_time(now)?;
        if matches!(self.state, State::Closed | State::TimeWait) {
            return Ok(false);
        }
        let Some(span) = self
            .pmtud
            .as_ref()
            .and_then(|p| p.quoted_span(Seq(seq), size, header, mtu))
            .filter(|&(start, end)| self.quoted_outstanding(start, end).is_some())
        else {
            return Ok(false);
        };
        let outcome = self
            .pmtud
            .as_mut()
            .unwrap()
            .legacy_report(now, Seq(seq), size, header, mtu);
        // `true` means accepted as a drop notification of that recorded
        // transmission, whether or not the estimate decreased.
        Ok(self.accept_pmtu_report(outcome.feedback, span))
    }

    /// Managed counterpart of `pmtu_feedback`: the Host already proved the
    /// physical submission (span and sizes), so only TCP policy runs here.
    /// Every accepted class is a drop notification for the quoted span's
    /// outstanding bytes; Deferred and Decreased keep their estimate effects.
    pub(crate) fn correlated_pmtu_feedback(
        &mut self,
        now: Instant,
        report: crate::CorrelatedPmtu,
        host_estimate: Option<u32>,
    ) -> Result<crate::PmtuReport, Error> {
        // A current-path report is corrected against the Host's shared
        // estimate (RFC 1191 section 5); without one it is malformed input.
        if report.current_path && report.path_estimate.is_none() {
            return Err(Error::InvalidArgument);
        }
        self.update_time(now)?;
        let segment = report.segment;
        let (start, end) = (Seq(segment.start), Seq(segment.end));
        let rejected = crate::PmtuReport {
            feedback: crate::PmtuFeedback::Rejected,
            derived_mtu: None,
        };
        // A sequence-bearing quote must overlap the outstanding window; a pure
        // ACK/RST quote (empty span) keeps the in-flight start test and
        // carries no stream work.
        let live = if start == end {
            start.in_window(self.snd_una, self.flight()) == Some(true)
        } else {
            self.quoted_outstanding(start, end).is_some()
        };
        if matches!(self.state, State::Closed | State::TimeWait) || !live {
            return Ok(rejected);
        }
        let Some(p) = &mut self.pmtud else {
            return Ok(rejected);
        };
        let outcome = p.correlated_feedback(
            now,
            start,
            end,
            segment.ip_packet_len,
            segment.ip_header_len,
            report.quoted_packet_len,
            report.candidate_mtu,
            report.current_path,
            report.path_estimate,
        );
        let id = p.pending_id();
        if id != self.managed_results.pending.map(|(id, _)| id) {
            // This report replaced the pending one (or none is pending): only
            // its own provenance, never the replaced report's, may describe it.
            self.managed_results.pending =
                match (outcome.feedback, id, host_estimate, self.managed_path) {
                    (crate::PmtuFeedback::Deferred, Some(id), Some(host_estimate), Some(binding)) => {
                        Some((
                            id,
                            crate::PendingPmtuApplied {
                                binding,
                                report,
                                host_estimate,
                                applied_mtu: 0,
                            },
                        ))
                    }
                    _ => None,
                };
        }
        self.accept_pmtu_report(outcome.feedback, (start, end));
        Ok(outcome)
    }

    // Local consequences of one report: the drop notification is separate
    // from the estimate policy. Returns whether the report was accepted.
    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
    //= reason=Every accepted correlated report is a drop notification separate from the estimate policy (Connection::accept_pmtu_report): Host-correlated Unchanged reports about the current or an older path incarnation, Deferred and Decreased reports, and a ring-matched legacy pmtu_feedback report below the recorded submitted size whether or not the estimate falls, all add the quoted span's eligible outstanding, unSACKed, never-retransmitted bytes as exact repair work, which TCP retransmits at the currently authorized size; a Deferred report's suspicious size waits for authorization, its dropped range does not. The dual-family real-receiver scheduler test repairs the ranges of four successively smaller PTBs that, below proven delivery, leave the estimate unchanged; Host tests repair a deferred report replayed after ledger eviction and, as advice only, after path replacement; the isolated namespace tcp-burst case repairs every range named by real router PTBs, including those that left the estimate unchanged. A Host UDP flow receives the same advice as UdpEvent::PacketTooBig.
    //# Also, the instance that sent the datagram that elicited the Datagram Too Big message should be notified that its datagram has been dropped, even if the PMTU estimate has not changed, so that it may retransmit the dropped datagram.
    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.2
    //= reason=Every accepted correlated report is a drop notification separate from the estimate policy (Connection::accept_pmtu_report): Host-correlated Unchanged reports (at or above the IPv6 minimum and below the packet size) about the current or an older path incarnation, Deferred and Decreased reports, and a ring-matched legacy pmtu_feedback report below the recorded submitted size whether or not the estimate falls, all add the quoted span's eligible outstanding, unSACKed, never-retransmitted bytes as exact repair work, which TCP retransmits at the currently authorized size; a Deferred report's suspicious size waits for authorization, its dropped data does not. The dual-family real-receiver scheduler test repairs the ranges of four successively smaller PTBs that, below proven delivery, leave the estimate unchanged; Host tests repair a deferred report replayed after ledger eviction and, as advice only, after path replacement; the isolated namespace tcp-burst case repairs every range named by real router PTBs, including those that left the estimate unchanged. A Host UDP flow receives the same advice as UdpEvent::PacketTooBig.
    //# Also, the instance that sent the packet that elicited the Packet Too Big message should be notified that its packet has been dropped, even if the PMTU estimate has not changed, so that it may retransmit the dropped data.
    fn accept_pmtu_report(&mut self, feedback: crate::PmtuFeedback, span: (Seq, Seq)) -> bool {
        match feedback {
            crate::PmtuFeedback::Rejected => return false,
            crate::PmtuFeedback::Unchanged => {
                // Probe attribution may have changed the loss classification.
                self.resolve_probe_response();
            }
            crate::PmtuFeedback::Deferred | crate::PmtuFeedback::Decreased { .. } => {
                self.report_fast_open_failure();
                // Budget only: the exact quoted range below is the repair,
                // not a head retry from SND.UNA.
                self.refresh_path_mss_with(false);
            }
        }
        // SYN is a control position: whatever the estimate did, a dropped
        // outstanding SYN (with any Fast Open data) is repaired by the
        // existing handshake retry, which falls back to a regular SYN. As for
        // stream bytes, only a never-retransmitted SYN is eligible: a minimal
        // quote cannot name the copy, so duplicates never amplify retries.
        if self.quote_covers_syn(span.0, span.1) && self.committed_syn_retransmissions == 0 {
            self.report_fast_open_failure();
            self.syn_pending = true;
        }
        self.note_ptb_drop(span.0, span.1);
        self.arm_work();
        true
    }

    fn note_probe_loss(&mut self, start: Seq, multiple: bool) {
        if let Some(p) = &mut self.pmtud {
            p.loss(start, multiple);
            if self.congestion.pending_probe_response().is_some()
                && self.congestion.pending_probe_response() != p.eligible_probe_loss()
            {
                self.congestion.commit_probe_response();
            }
        }
    }

    // Resolve after recovery/PRR's ending-ACK bookkeeping, not at the earlier
    // PMTU ACK hook: exit deflation must apply only to repair admission.
    //= https://www.rfc-editor.org/rfc/rfc4821#section-4
    //= reason=Finite original-probe proof survives exact matching PTB while its size result is invalidated. Receiver-driven IPv4/IPv6 traces cover PTB before/after loss, decreasing quotes, wrap, split repairs and finite extended-tail delivery followed by recovery/PRR exit. Normal repair admission, MSS rescaling and PRR remain active; additional original loss, ECE, repair-copy loss, timeout and non-probe PTB commit normal congestion response. Replenishment resumes ACK growth; encoding failure and reservation rejection preserve conservative state.
    //# Normal congestion control algorithms MUST remain in effect under all conditions
    //# except when only an isolated probe packet is detected as lost. In this case
    //# alone, the normal congestion (window or data rate) reduction SHOULD be
    //# suppressed. If any other data loss is detected, standard congestion control MUST
    //# take place.

    fn resolve_probe_response(&mut self) {
        if let Some(p) = &mut self.pmtud {
            if !self.congestion.in_recovery()
                && self.sack_recovery.is_none()
                && self.prr.is_none()
                && let Some(outcome) = p.take_probe_outcome(self.snd_una)
            {
                if outcome.isolated {
                    self.congestion.suppress_probe_response(outcome.start);
                } else {
                    self.congestion.commit_probe_response();
                }
            }
            if self.congestion.pending_probe_response().is_some()
                && self.congestion.pending_probe_response() != p.eligible_probe_loss()
            {
                self.congestion.commit_probe_response();
            }
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc4821#section-4
    //= reason=Reviewed 76800de plus a4b9a0c: isolated suppression waits for finite cumulative proof and recovery exit; pmtu_cooldown uses the unsuppressed logical window, not transient PRR admission, with one RTT per packet plus a strict extra interval/tick and an RTO floor. Real receiver matrix checks no target before the deadline and a target at it; dedicated arithmetic test distinguishes logical14600 from admission1000. Mandatory failure cooldown is independent of configurable periodic aging.
    //# Suppressed congestion control MUST be rate limited such that it occurs less
    //# frequently than the worst-case loss rate for TCP congestion control at a
    //# comparable data rate over the same path (i.e., less than the "TCP-friendly" loss
    //# rate [tcp-friendly]). This SHOULD be enforced by requiring a minimum headway
    //# between a suppressed congestion adjustment (due to a failed probe) and the next
    //# attempted probe, which is equal to one round-trip time for each packet permitted
    //# by the congestion window. This is discussed further in Section 7.6.2.

    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.2
    //= reason=Isolated suppression with or without matching PTB waits for finite cumulative proof and recovery/PRR exit. pmtu_cooldown uses the unsuppressed logical window with one RTT per packet, a strict extra interval/tick and an RTO floor; the arithmetic test distinguishes logical14600 from admission1000. Receiver matrices assert exclusion before the deadline and admission at expiry. Matching PTB additionally retains its mandatory600-second hold through original, split-repair and trailing ACKs; periodic aging cannot disable failure headway.
    //# A probe failure event is the one situation under which the Packetization Layer
    //# SHOULD ignore loss as a congestion signal. Because there is some small risk that
    //# suppressing congestion control might have unanticipated consequences (even for
    //# one isolated loss), it is REQUIRED that probe failure events be less frequent
    //# than the normal period for losses under standard congestion control.
    //# Specifically, after a probe failure event and suppressed congestion control,
    //# PLPMTUD MUST NOT probe again until an interval that is larger than the expected
    //# interval between congestion control events. See Section 4 for details. The
    //# simplest estimate of the interval to the next congestion event is the same
    //# number of round trips as the current congestion window in packets.

    fn pmtu_cooldown(&self) -> u64 {
        (u64::from(self.congestion.unsuppressed_cwnd()) / self.mss.max(1) as u64 + 1)
            .saturating_mul(self.rtt.srtt().unwrap_or(1).max(1))
            .max(self.rto())
            .saturating_add(1)
    }

    pub(crate) fn user_mss(&self) -> Option<u16> {
        self.config.user_mss
    }

    pub(crate) fn transport_ceilings(&self) -> crate::TransportCeilings {
        crate::TransportCeilings {
            peer_mss: self.peer_mss,
            user_mss: self.config.user_mss,
            local_mss: self.send_mss_limit,
            allocation: self.scratch.len(),
            send_ip_payload_limit: self.config.send_ip_payload_limit,
            destination_mtu: self.pmtud.as_ref().and_then(|p| p.info.route_mtu),
            effective_mss: self.mss,
        }
    }

    pub(crate) fn set_user_mss(&mut self, mss: Option<u16>) -> Result<(), Error> {
        if mss == Some(0) {
            return Err(Error::InvalidArgument);
        }
        if self.config.user_mss == mss {
            return Ok(());
        }
        self.config.user_mss = mss;
        // An application can limit future sends after establishment, but cannot
        // retroactively change the receive capability advertised in its SYN.
        if !self.syn_committed {
            self.receive_mss_offer = self.config.receive_mss_offer(self.receive_capability);
        }
        if self.pmtud.is_some() {
            self.refresh_path_mss();
        } else {
            let effective = self
                .peer_mss
                .min(self.send_mss_limit)
                .min(mss.unwrap_or(u16::MAX))
                .saturating_sub(if self.timestamps { 12 } else { 0 })
                .max(1)
                .min(self.config.send_ip_payload_limit - 20 - if self.timestamps { 12 } else { 0 });
            self.set_path_mss(usize::from(effective));
        }
        Ok(())
    }

    pub(crate) fn lower_mss(&mut self, mss: u16) -> Result<(), Error> {
        if self.pmtud.is_some() {
            // Administrative reductions are independent of the transient path MSS.
            if mss == 0 || mss > self.send_mss_limit {
                return Err(Error::InvalidArgument);
            }
            self.send_mss_limit = self.send_mss_limit.min(mss);
            self.refresh_path_mss();
            return Ok(());
        }
        let effective = mss
            .saturating_sub(if self.timestamps { 12 } else { 0 })
            .max(1);
        if mss == 0 || effective as usize > self.mss {
            return Err(Error::InvalidArgument);
        }
        if effective as usize == self.mss {
            return Ok(());
        }
        // Legacy explicit MSS override retains its original SYN behavior.
        self.config.mss = self.config.mss.min(mss);
        self.receive_capability = self.receive_capability.map(|c| c.min(mss));
        self.receive_mss_offer = self.receive_mss_offer.min(mss);
        self.send_mss_limit = self.send_mss_limit.min(mss);
        self.set_path_mss(effective as usize);
        Ok(())
    }

    // MSS changes or a new congestion event can separate CUBIC's direct ECN
    // window from ssthresh. Drop only optional PRR admission/credit, never
    // complete it by raising the logical window to the threshold floor.
    fn cancel_divergent_ecn_prr(&mut self) {
        if self.congestion.ecn_prr_end().is_some()
            && self.congestion.unsuppressed_cwnd() != self.congestion.ssthresh()
        {
            self.congestion.end_ecn_prr();
            self.prr = None;
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.3
    //= reason=Connection::set_path_mss creates retx_pending/SYN retry work only on decreases; growth leaves legitimate pending work and timers intact. Tests from 742e320 exercise MSS-only growth with remaining flight and no output, actual RTO retry preservation, SYN work, and real upward-probe ACKs followed by new data rather than trailing-byte retransmission (both families and wrap).
    //# An upper layer MUST not retransmit datagrams in response to an increase in the
    //# PMTU estimate, since this increase never comes in response to an indication of a
    //# dropped datagram.

    fn set_path_mss(&mut self, effective: usize) {
        self.update_path_mss(effective, true);
    }

    fn set_path_mss_budget(&mut self, effective: usize) {
        self.update_path_mss(effective, false);
    }

    fn update_path_mss(&mut self, effective: usize, repair: bool) {
        let effective = effective.min(self.managed_payload_mss());
        if effective == self.mss {
            return;
        }
        let decreased = effective < self.mss;
        let blocked = self.send_space_remaining() == 0;
        self.mss = effective;
        // A new segment size moves C; reopened room is writable as after an ACK.
        if blocked && self.send_space_remaining() != 0 {
            self.send_backpressured = false;
            self.events.writable |=
                !self.shutdown && matches!(self.state, State::Established | State::CloseWait);
        }
        if self.pmtud.is_some() || self.managed_path.is_some() {
            self.congestion.set_path_mss(effective as u32);
        } else {
            self.congestion.set_mss(effective as u32);
        }
        self.cancel_divergent_ecn_prr();
        if let Some(prr) = &mut self.prr {
            prr.set_mss(effective as u32);
        }
        if let Some(mut recovery) = self.sack_recovery {
            recovery.pipe = self.recovery_pipe(recovery.high_rxt);
            self.sack_recovery = Some(recovery);
        }
        // An increase is not evidence of loss. Leave existing retry work alone;
        // only a decrease may require repacketizing outstanding bytes.
        // PTB-caused decreases pass repair=false: their drop notification
        // schedules exact-range repair instead of this head retry.
        if repair && decreased && self.flight() != 0 {
            if self.handshake_pending() {
                self.syn_pending = true;
            } else if self.synchronized() && self.snd_wnd != 0 && self.sack_recovery.is_none() {
                self.retx_pending = true;
            }
        }
        self.arm_work();
    }

    pub(crate) fn update_time(&mut self, now: Instant) -> Result<(), Error> {
        self.check_time(now)?;
        self.transport_ticks = self.transport_ticks_at(now);
        // Endpoint validates caller clock gaps. A dormant connection may lag
        // that serviced clock by more than the timestamp serial half-range.
        let granularity = if self.config.timestamps {
            self.config.timestamp_granularity
        } else {
            TimestampGranularity::Milliseconds
        };
        // Ticks of one period differ by less than 2^31 while fewer than
        // 2^31 - 1 periods separate the samples, so only an older sample
        // needs its ticks divided out.
        let period = self.config.timebase.ticks_from_us(granularity.tick_us());
        let stale = |sent: Instant| {
            now.saturating_sub(sent) >= ((1 << 31) - 1u64).saturating_mul(period)
                && granularity
                    .tick_in(now, self.config.timebase)
                    .saturating_sub(granularity.tick_in(sent, self.config.timebase))
                    >= 1 << 31
        };
        if self.sample.is_some_and(|(_, sent)| stale(sent))
            || self.last_timestamp_sent_at.is_some_and(stale)
        {
            self.sample = None;
            self.last_timestamp_sent_at = None;
            self.tlp_fresh_rtt = false;
            // Discard stale transmission history, not queued bytes or
            // cleanup/retransmission deadlines; ordinary loss recovery remains.
            if self.flight() != 0 {
                self.rack.abandon(self.data_high());
                // The exact reserved bytes/timers survive, but acceptance must
                // not require or recreate this discarded timestamp evidence.
                self.reserved_ledger = None;
                self.congestion.end_ecn_prr();
                self.prr = None;
            }
        }
        self.now = now;
        Ok(())
    }

    //= https://www.rfc-editor.org/rfc/rfc7323#section-4.1
    //= reason=Native and tun_echo time is the characterized CLOCK_BOOTTIME provider, which rejects decreasing samples and measures suspend; other embedders owe physically monotonic, consistent-rate time with sufficient precision for protocol timing; violation leaves timing guarantees unspecified, never Rust UB or memory-safety violations. CallerTimebase accepts microsecond/nanosecond units and MSL <=255s, independently of wire ms/us periods. Nondecreasing input, endpoint timestamp half-range gaps and resource bounds are checked; physical rate/drift/precision and actual network MSL cannot be established here. Peer PAWS expires independently at2147s. Fixed wire cadence and opt-in microsecond frequency remain scoped policy exceptions, not literal conformance.
    //# Values of this
    //# clock MUST be at least approximately proportional to real time, in
    //# order to measure actual RTT.
    //= https://www.rfc-editor.org/rfc/rfc7323#section-5.4
    //= reason=Every input/transmit checks nondecreasing Instant, TSval derived by fixed selected local tick scaling (default milliseconds) modulo2^32; repeated Instant intentionally repeats TSval. Physical rate/precision remain caller obligations; endpoint timestamp half-range gap checks are separate.
    //# The PAWS mechanism also puts a strong monotonicity requirement on the
    //# sender's timestamp clock.
    // `now` carries a suspend the clock provider measured. Nothing measured
    // across it is a path RTT, so in-flight transmissions stop sampling. RFC
    // 7323 section 5.5: beyond 24 days idle the peer must have invalidated
    // TS.Recent and ours has expired by elapsed time; within them, the
    // returned ambiguity ends the connection.
    pub(crate) fn suspended(&mut self, now: Instant) -> Result<bool, Error> {
        self.check_time(now)?;
        self.timestamp_ambiguous |= self.next_timestamp_appears_older(now);
        self.update_time(now)?;
        self.sample = None;
        self.rtt_sample_after = Some(now);
        self.rack.discard_samples_before(now);
        Ok(self.timestamp_ambiguous)
    }

    fn next_timestamp_appears_older(&self, now: Instant) -> bool {
        let Some(sent) = self.last_timestamp_sent_at.filter(|_| self.timestamps) else {
            return false;
        };
        let tick = |at| {
            self.config
                .timestamp_granularity
                .tick_in(at, self.config.timebase)
        };
        (tick(now) - tick(sent)) as u32 >= 1 << 31
            && now - sent <= self.config.timebase.ticks_from_us(PEER_TS_RECENT_IDLE_US)
    }

    pub(crate) fn check_time(&self, now: Instant) -> Result<(), Error> {
        if now < self.now {
            Err(Error::TimeWentBackwards)
        } else {
            Ok(())
        }
    }

    pub(crate) fn timestamp_offset(&self) -> u32 {
        self.timestamp_offset
    }

    pub(crate) fn set_timestamp_offset(&mut self, offset: u32) {
        self.timestamp_offset = offset;
    }

    //= https://www.rfc-editor.org/rfc/rfc7323#section-5.4
    //= reason=Successful TS-bearing sequence-space bytes (including retransmitted copies and SYN/FIN) are transactionally limited by configured nonzero timestamp_bytes_per_tick <2^31. Exhaustion returns TimestampBudgetExceeded with caller time and protocol state unchanged; next tick resets credit. Boundary/wrap/output rollback tests verify the gate. Physical clock truth remains separately external.
    //# It MUST tick at least once for each 2^31 bytes sent.
    fn timestamp_value(&self, now: Instant) -> u32 {
        self.timestamp_value_at(
            self.config
                .timestamp_granularity
                .tick_in(now, self.config.timebase),
        )
    }

    // TSval at timestamp clock tick `tick`.
    fn timestamp_value_at(&self, tick: u64) -> u32 {
        (tick as u32).wrapping_add(self.timestamp_offset)
    }

    // Classic RFC 3168 only: setup offers remain binding for receive feedback even
    // after a local fallback forbids sending ECT data.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.2
    //# A TCP endpoint SHOULD implement ECN as described in RFC 3168 (SHLD-
    //# 8).
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1.1
    //= reason=Optional timeout fallback selected; asserts plain setup after timeout and ECT suppression, retaining earlier receive commitment. No RST-triggered retry claim.
    //# A host that receives no reply to an ECN-setup SYN within the normal
    //# SYN retransmission timeout interval MAY resend the SYN and any
    //# subsequent SYN retransmissions with CWR and ECE cleared.
    // Actor/condition: TCP setup initiator/responder; no setup reply before SYN retransmission timeout.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
    //= reason=Responder ECN setup only after peer setup: endpoint asserts setup SYN yields ECE-only SYN-ACK; opt-out/plain SYN yields plain SYN-ACK. No ECT on handshake output.
    //# * If a host has received an ECN-setup SYN packet, then it MAY send
    //# an ECN-setup SYN-ACK packet.
    // Actor/condition: TCP setup responder; received ECN-setup SYN.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
    //= reason=Responder ECN setup only after peer setup: endpoint asserts setup SYN yields ECE-only SYN-ACK; opt-out/plain SYN yields plain SYN-ACK. No ECT on handshake output.
    //# Otherwise, it MUST NOT send an
    //# ECN-setup SYN-ACK packet.
    // Actor/condition: TCP setup responder; no received ECN-setup SYN.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
    //= reason=Setup/opt-out evidence: exact SYN/SYN-ACK flag interpretation, plain setup forbids ECT, all SYN-ACK ECE/CWR forms are asserted. Earlier receive commitment is separately retained.
    //# * A host MUST NOT set ECT on data packets unless it has sent at
    //# least one ECN-setup SYN or ECN-setup SYN-ACK packet, and has
    //# received at least one ECN-setup SYN or ECN-setup SYN-ACK packet,
    //# and has sent no non-ECN-setup SYN or non-ECN-setup SYN-ACK
    //# packet.
    // Actor/condition: TCP sender; ECT eligibility after bilateral setup with no local plain setup.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
    //= reason=Setup/opt-out evidence: exact SYN/SYN-ACK flag interpretation, plain setup forbids ECT, all SYN-ACK ECE/CWR forms are asserted. Earlier receive commitment is separately retained.
    //# If a host has received at least one non-ECN-setup SYN
    //# or non-ECN-setup SYN-ACK packet, then it SHOULD NOT set ECT on
    //# data packets.
    // Actor/condition: TCP sender; received any plain setup packet.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
    //= reason=Negotiated receive commitment gates CE handling after sequence/control/ACK validation, including exact-sequence zero-window probes without receive credit. Tests cover normal CE, repeated feedback, fallback commitment, invalid packets and ECN-off receive.
    //# * If a host has sent at least one ECN-setup SYN or ECN-setup SYN-
    //# ACK packet, and has received no non-ECN-setup SYN or non-ECN-
    //# setup SYN-ACK packet, then if that host receives TCP data
    //# packets with ECT and CE codepoints set in the IP header, then
    //# that host MUST process these packets as specified for an ECN-
    //# capable connection.
    // Actor/condition: TCP receiver; sent setup and received no plain setup; ECN data received.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
    //= reason=Setup/opt-out evidence: exact SYN/SYN-ACK flag interpretation, plain setup forbids ECT, all SYN-ACK ECE/CWR forms are asserted. Earlier receive commitment is separately retained.
    //# * A host that is not willing to use ECN on a TCP connection SHOULD
    //# clear both the ECE and CWR flags in all non-ECN-setup SYN and/or
    //# SYN-ACK packets that it sends to indicate this unwillingness.
    // Actor/condition: TCP setup sender; unwilling to use ECN.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
    //= reason=Setup/opt-out evidence: exact SYN/SYN-ACK flag interpretation, plain setup forbids ECT, all SYN-ACK ECE/CWR forms are asserted. Earlier receive commitment is separately retained.
    //# Receivers MUST correctly handle all forms of the non-ECN-setup
    //# SYN and SYN-ACK packets.
    // Actor/condition: TCP setup receiver; any non-ECN-setup SYN/SYN-ACK flag combination.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
    //= reason=Explicit receive commitment assertion after delayed setup SYN-ACK and local plain-SYN fallback; sender no longer sets ECT, receiver still latches CE.
    //# However, the commitment to respond appropriately to incoming packets with the CE codepoint set remains even if the TCP sender in a later transmission, within this TCP connection, sends a SYN packet without ECE and CWR set.
    // Actor/condition: TCP endpoint; ECN setup followed by local plain-SYN fallback.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1.1
    //= reason=Setup flags alone establish ECN capability; explicit ECN-off receive tests inject CE and ECT without enabling ECN or ECE, then assert outgoing data remains Not-ECT.
    //# a host is forbidden from using the reception of ECT data packets as an implicit signal that the other host is ECN- capable.
    // Actor/condition: TCP endpoint; ECT packet without bilateral setup.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1.2
    //= reason=Exact flag-combination assertion enables ECN only for ECE-only SYN-ACK, rejecting reflected ECE|CWR.
    //# the sending TCP correctly interprets a receiver's reflection of its own flags in the Reserved field as an indication that the receiver is not ECN-capable.
    // Actor/condition: TCP endpoint; SYN-ACK reflects both ECE/CWR.
    fn learn_ecn(&mut self, flags: u8) {
        let setup = flags & (ECE | CWR) == if flags & ACK != 0 { ECE } else { ECE | CWR };
        self.ecn_peer_setup |= setup;
        self.ecn_peer_plain |= !setup;
    }

    fn ecn_feedback(&self) -> bool {
        self.ecn_sent_setup && self.ecn_peer_setup && !self.ecn_peer_plain
    }

    fn ecn_send(&self) -> bool {
        self.ecn_feedback() && !self.ecn_sent_plain
    }

    fn learn_fast_open_response(&mut self, segment: &Segment<'_>) {
        if self.fast_open_option_sent
            || self.fast_open_client_policy == crate::FastOpenClientPolicy::ApplicationProtected
                && self.syn_payload_sent != 0
        {
            let cookie = self
                .fast_open_option_sent
                .then_some(segment.options.fast_open)
                .flatten()
                .filter(|cookie| !cookie.as_bytes().is_empty());
            // A family default is not an observed MSS. Pure crossing SYNs
            // never reach this path: their credential was issued locally.
            self.fast_open_learned = Some((cookie, segment.options.mss));
        }
    }

    pub(crate) fn last_output_ecn(&self) -> u8 {
        self.last_output_ecn
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.2
    //= reason=Passive constructor consumes SYN sequence, learns peer, and schedules SYN-ACK. SYN text buffering/delivery scope separately cited.
    //# Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ, and any other control or text should be
    //# queued for processing later. ISS should be selected and a SYN segment sent of the form:
    //# <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
    //= https://www.rfc-editor.org/rfc/rfc7323#section-2.2
    //= reason=Active always offers WS; passive enables only after peer offer. Missing peer WS disables effective shifts in both directions, not necessarily the stored capacity-derived exponent.
    //# This option is an offer, not a promise; both sides MUST send Window
    //# Scale options in their <SYN> segments to enable window scaling in
    //# either direction.
    //= https://www.rfc-editor.org/rfc/rfc7323#section-2.3
    //= reason=Effective incoming/outgoing shifts use negotiated scaling; absent peer WS means zero effective shifts even though local_scale retains its configured value.
    //# o  Upon receiving a <SYN> segment with a Window Scale option
    //# containing shift.cnt = S, a TCP MUST set Snd.Wind.Shift to S and
    //# MUST set Rcv.Wind.Shift to R; otherwise, it MUST set both
    //# Snd.Wind.Shift and Rcv.Wind.Shift to zero.
    //= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
    //= reason=Timestamp negotiation is config/peer-SYN gated; SYN TSecr=0, ACK replies echo ts_recent, bool timestamps retains negotiated state.
    //# The TCP SHOULD remember
    //# this state by setting a flag, referred to as Snd.TS.OK, to one.
    //= https://www.rfc-editor.org/rfc/rfc7323#section-5.2
    //= reason=learn_syn copies offered TSval into TS.Recent and ts_latest on both active/passive negotiation.
    //# TSval timestamps sent on <SYN> and <SYN,ACK> segments are used to
    //# initialize PAWS.
    //= https://www.rfc-editor.org/rfc/rfc7323#section-2.3
    //= reason=Invalid SYN Window Scale is clamped to 14 and emits at most one invalid_window_scale event per connection; the existing coalesced bounded endpoint event queue carries the diagnostic. Values 15/255 and repeated negotiation are covered without unbounded logging.
    //# If a
    //# Window Scale option is received with a shift.cnt value larger than
    //# 14, the TCP SHOULD log the error but MUST use 14 instead of the
    //# specified value.
    fn learn_syn(&mut self, syn: &Segment<'_>, early_authorized: bool) {
        self.learn_ecn(syn.header.flags);
        self.sack_send |= self.config.sack && syn.options.sack_permitted;
        self.timestamps = self.config.timestamps && syn.options.timestamps.is_some();
        if self.timestamps {
            self.ts_recent = syn.options.timestamps.unwrap().0;
            self.ts_latest = self.ts_recent;
            self.ts_recent_at = self.now;
        }
        self.irs = Some(Seq(syn.header.sequence));
        let start = Seq(syn.header.sequence).wrapping_add(1);
        self.receive
            .reset_start(start)
            .expect("handshake receive buffer is empty");
        self.advertised_edge = start.wrapping_add(self.syn_window as u32);
        self.last_ack_sent = start;
        self.scaling = syn.options.window_scale.is_some();
        self.peer_scale = syn.options.window_scale.unwrap_or(0);
        if let Some(scale) = syn.options.invalid_window_scale
            && !self.invalid_scale_reported
        {
            self.events.invalid_window_scale = Some(scale);
            self.invalid_scale_reported = true;
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.1
        //# If an MSS Option is not received at connection setup, TCP implementations
        //# MUST assume a default send MSS of 536 (576 - 40) for IPv4 or 1220 (1280 -
        //# 60) for IPv6 (MUST-15).
        let default_mss = if self.tuple.remote.is_ipv4() {
            536
        } else {
            1220
        };
        // The configured MSS remains the scratch/buffer ceiling, independently of
        // the receive offer. IP has already subtracted its actual header overhead.
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.1
        //# The maximum size of a segment that a TCP endpoint really sends, the
        //# "effective send MSS", MUST be the smaller (MUST-16) of the send MSS
        //# (that reflects the available reassembly buffer size at the remote
        //# host, the EMTU_R [19]) and the largest transmission size permitted by
        //# the IP layer (EMTU_S [19]):
        self.peer_mss = syn.options.mss.unwrap_or(default_mss).max(1);
        self.mss = syn
            .options
            .mss
            .unwrap_or(default_mss)
            .max(1)
            .min(self.config.mss)
            .min(self.config.user_mss.unwrap_or(u16::MAX))
            .saturating_sub(if self.timestamps { 12 } else { 0 })
            .max(1)
            .min(self.config.send_ip_payload_limit - 20 - if self.timestamps { 12 } else { 0 })
            as usize;
        self.refresh_path_mss();
        self.congestion
            .set_initial_mss(self.mss as u32, self.syn_loss_detected);
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
        //# The window size MUST be treated as an unsigned number, or else large window
        //# sizes will appear like negative windows and TCP will not work (MUST-1).
        self.snd_wnd = syn.header.window as u32;
        self.max_snd_wnd = self.snd_wnd;
        self.wl1 = Seq(syn.header.sequence);
        self.wl2 = Seq(syn.header.acknowledgment);
        let count = syn.payload.len().min(self.syn_window as usize);
        let fin = syn.header.flags & FIN != 0 && syn.payload.len() < self.syn_window as usize;
        let urgent = (syn.header.flags & URG != 0 && syn.header.urgent_pointer > 1)
            .then(|| (syn.header.urgent_pointer - 1) as u64);
        if !early_authorized {
            if count == 0 && !fin && urgent.is_none() {
                return;
            }
            // Conservative RFC 9293 reference ordering: retain ordinary SYN
            // text, but do not process it until validated establishment. The
            // staged prefix occupies the same window slots, not extra credit.
            self.receive.defer_syn(
                &syn.payload[..count],
                fin,
                syn.header.flags & PSH != 0 && count == syn.payload.len(),
            );
            // Keep first-arrival metadata in its existing bounded store. It is
            // unreadable until promotion, but still constrains metadata resize.
            if count != 0 {
                self.rx_timestamps
                    .insert(0, count as u64, self.input_timestamps);
            }
            self.deferred_syn = Some(DeferredSyn {
                received_at: self.now,
                urgent,
            });
            self.receive_used = count;
            return;
        }
        let outcome = self.receive_payload(
            start,
            &syn.payload[..count],
            fin,
            syn.header.flags & PSH != 0 && count == syn.payload.len(),
        );
        self.received_total = count as u64;
        self.receive_used += outcome.new_bytes;
        if outcome.new_bytes != 0 {
            self.last_data_received = self.now;
        }
        if outcome.fin {
            self.syn_window = 0;
        } else {
            self.syn_window -= count as u16;
        }
        self.rcv_up = urgent;
    }

    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= reason=After SYN acknowledgment, syn_timed_out imposes >=3s until fresh data sample; synack_timeout_roles_first_data_and_fresh_sample_guard asserts passive/simultaneous timeout deadlines and release, active role covered by tlp_small_rto_floor_preserves_initial_and_syn_timeout_guard.
    //# (5.7) If the timer expires awaiting the ACK of a SYN segment and the TCP
    //# implementation is using an RTO less than 3 seconds, the RTO MUST be re-initialized to
    //# 3 seconds when data transmission begins (i.e., after the three-way handshake
    //# completes).
    fn rto(&self) -> u64 {
        self.rtt
            .rto()
            .max(if self.syn_timed_out && self.syn_delivered {
                self.config.timebase.ticks_from_us(3_000_000)
            } else {
                0
            })
    }

    // FlightSize counts payload, not SYN/FIN sequence-space consumption.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-2
    //= reason=Separate payload FlightSize from transport sequence-space flight: SYN0/FIN0 payload accounting, SACK-only preservation, divided cumulative release and unchanged cwnd on FIN-only ACK are directly asserted through wrap. RFC9937 PRR snapshots unsacked payload and includes the triggering ACK delivery.
    //# FLIGHT SIZE: The amount of data that has been sent but not yet cumulatively acknowledged.
    fn data_flight(&self) -> u32 {
        if self.data_high().after(self.send_base) {
            self.data_high()
                .distance_from(self.send_base)
                .min(self.send.len() as u32)
        } else {
            0
        }
    }

    fn flight(&self) -> u32 {
        self.snd_nxt.distance_from(self.snd_una)
    }

    fn synchronized(&self) -> bool {
        !self.handshake_pending()
            && !matches!(
                self.state,
                State::Closed | State::SynSent | State::SynReceived | State::TimeWait
            )
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= reason=Coalesces ACK requests; input never transmits inline.
    //# o In general, the processing of received segments MUST be implemented to
    //# aggregate ACK segments whenever possible (MUST-58).
    fn immediate_ack(&mut self) {
        self.ack_pending = true;
        self.ack_deadline = None;
    }

    // RFC 5961 section 7; held erratum 4772 warns against global counters.
    // Count successful output, not coalesced requests or failed encodes.
    //= https://www.rfc-editor.org/rfc/rfc5961#section-7
    //= reason=Validated nonzero per-connection count/interval tunables; caller-clock fixed windows, bounded successful-output counters, coalescing and transactional encode. No shared challenge counter; held erratum 4772 is considered, not treated as verified normative text.
    //# 2) The values for both the time and number of ACKs SHOULD be tunable
    //# by the system administrator to accommodate different perceived
    //# levels of threat and/or system resources.
    //= https://www.rfc-editor.org/rfc/rfc5961#section-7
    //= reason=Validated nonzero per-connection count/interval tunables; caller-clock fixed windows, bounded successful-output counters, coalescing and transactional encode. No shared challenge counter; held erratum 4772 is considered, not treated as verified normative text.
    //# An implementation SHOULD include an ACK throttling mechanism to be
    //# conservative.
    //= https://www.rfc-editor.org/rfc/rfc5961#section-7
    //= reason=Validated nonzero per-connection count/interval tunables; caller-clock fixed windows, bounded successful-output counters, coalescing and transactional encode. No shared challenge counter; held erratum 4772 is considered, not treated as verified normative text.
    //# The time limit SHOULD be tunable to help timeout brute force attacks
    //# faster than a potential legitimate flood of RSTs.
    //= https://www.rfc-editor.org/rfc/rfc5961#section-7
    //= reason=Validated nonzero per-connection count/interval tunables; caller-clock fixed windows, bounded successful-output counters, coalescing and transactional encode. No shared challenge counter; held erratum 4772 is considered, not treated as verified normative text.
    //# 1) The system administrator can configure the number of challenge ACKs that can be sent out in a given interval. For example, in any 5 second window, no more than 10 challenge ACKs should be sent.
    fn refresh_challenge_budget(&mut self, now: Instant) {
        if self.challenge_ack_start.is_none_or(|start| {
            now.saturating_sub(start)
                >= self
                    .config
                    .timebase
                    .ticks_from_us(self.config.challenge_ack_interval_us)
        }) {
            self.challenge_ack_start = Some(now);
            self.challenge_ack_sent = 0;
        }
    }

    fn challenge_ack(&mut self) {
        self.refresh_challenge_budget(self.now);
        if self.challenge_ack_sent < self.config.challenge_ack_limit {
            self.challenge_ack_pending = true;
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc7413#section-3
    //= reason=Small rejected/partial SYN payloads are repaired in the first ACK. public_first_ack_capacity_conflicts_and_receiver_driven_completion validates 400 SYN bytes against newly learned MSS64/cwnd256, a 32-byte offered window, partial acceptance128 with zero window, and an IPv4 effective path MSS28/cwnd112; first ACK payloads are 64/32/0/28 and real receiver ACK/window progress completes each stream once. Native PacketIo/Egress independently emits 88 bytes first and 352 before ACK for 400 rejected SYN bytes with MSS88. Existing wrap/scalar/reserved evidence remains. Literal all-data-in-first-ACK wording remains TODO pending explicit AC27/T23 user disposition; no interpretation or standards deviation is approved.
    //# 4. The client sends an ACK acknowledging the SYN and the server data. If the client's data is not
    //# acknowledged, the client retransmits the data in the ACK packet.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
    //= reason=Small rejected/partial SYN payloads are repaired in the first ACK. public_first_ack_capacity_conflicts_and_receiver_driven_completion validates 400 SYN bytes against newly learned MSS64/cwnd256, a 32-byte offered window, partial acceptance128 with zero window, and an IPv4 effective path MSS28/cwnd112; first ACK payloads are 64/32/0/28 and real receiver ACK/window progress completes each stream once. Native PacketIo/Egress independently emits 88 bytes first and 352 before ACK for 400 rejected SYN bytes with MSS88. Existing wrap/scalar/reserved evidence remains. Literal all-data-in-first-ACK wording remains TODO pending explicit AC27/T23 user disposition; no interpretation or standards deviation is approved.
    //# The client SHOULD retransmit any unacknowledged data in the first ACK packet in step 2.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
    //# 2. Send an ACK packet. Set acknowledgment number to RCV.NXT and include the data after SND.UNA if
    //# data is available.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
    //# 3. Advance to the ESTABLISHED state.
    fn establish(&mut self) {
        self.fast_open_attempt = false;
        if self.deferred_tfo_push {
            self.deferred_tfo_push = false;
            let end = self.iss.wrapping_add(1 + self.fast_open_initial as u32);
            let remaining = end.distance_from(self.send_base) as usize;
            // ACK processing has already reclaimed accepted SYN data. Promote
            // only its still-buffered original endpoint, not later queued data.
            if end.after(self.send_base) && remaining <= self.send.len() {
                self.send.finish_send(remaining - 1, true, false);
            }
        }
        if self.fast_open_initial != 0 && self.snd_nxt.after(self.snd_una) {
            self.fast_open_retry = Some((self.snd_una, self.snd_nxt));
        }
        self.handshake_complete = true;
        self.ack_engine_initialized = core::mem::take(&mut self.fast_open_write_pending);
        if self.config.adaptive_ack {
            self.ack_receive = Some((self.now, false));
            if self.ack_engine_initialized {
                self.ack_ato = self.config.ack_timeout_floor();
                self.ack_quick = self.adaptive_quick_budget();
            }
        }
        self.last_data_received = self.now;
        if let Some(deferred) = self.deferred_syn.take() {
            let count = self.receive.promote_syn().expect("staged SYN prefix");
            self.received_total = count as u64;
            self.rcv_up = deferred.urgent;
            if count != 0 {
                self.last_data_received = deferred.received_at;
            }
            if count != 0 || self.receive.eof() {
                self.immediate_ack();
            }
        }
        if self.state == State::SynSent || self.state == State::SynReceived {
            self.state = State::Established;
        }
        self.syn_pending = false;
        self.events.connected = true;
        self.events.writable = !self.shutdown && self.send_space_remaining() != 0;
        self.events.readable =
            !self.read_closed && (self.receive.readable() != 0 || self.receive.eof());
        self.events.pushed |= self.receive.take_push();
        // An admitted active opener already published its urgent endpoint with
        // the early receive prefix. Establishment must not notify it again.
        if self.passive_open || !self.fast_open_early {
            self.events.urgent = if self.read_closed { None } else { self.rcv_up };
        }
        if self.receive.eof() {
            self.events.half_closed = true;
            if self.state == State::Established {
                self.state = State::CloseWait;
            } else if self.state == State::FinWait1 {
                self.state = State::Closing;
            } else if self.state == State::FinWait2 {
                self.time_wait();
            }
        }
        self.arm_work();
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.6
    //= reason=Reset produces a terminal reason; receive_text reports FIN through half_closed.
    //# If the local TCP connection is closed by the remote side due to a FIN or RST
    //# received from the remote side, then the local application MUST be informed
    //# whether it closed normally or was aborted (MUST-12).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= reason=Exact-sequence inbound reset terminates, cancels all protocol output/deadlines, reports Reset; explicit release governs terminal handle storage.
    //# If the RST bit is set, then any outstanding RECEIVEs and SEND should receive "reset"
    //# responses. All segment queues should be flushed. Users should also receive an
    //# unsolicited general "connection reset" signal. Enter the CLOSED state, delete the TCB,
    //# and return.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
    //= reason=Terminal entry disables receive/send ECN commitment and clears echo/CWR; TIME-WAIT/CLOSED tests assert ignored negotiation and fresh same-tuple connections require new setup.
    //# When a TCP host enters TIME-WAIT or CLOSED state, it should ignore any previous state about the negotiation of ECN for that connection.
    fn terminal(&mut self, reason: CloseReason) {
        if self.deferred_syn.take().is_some() {
            let next = self.receive.next();
            self.receive.clear();
            self.rx_timestamps.clear();
            self.receive
                .reset_start(next)
                .expect("cleared receive buffer");
            self.receive_used = 0;
        }
        self.state = State::Closed;
        self.local_resource = None;
        self.repair_undo = None;
        self.control_undo = None;
        self.abandon_ptb();
        self.congestion.commit_probe_response();
        if let Some(p) = &mut self.pmtud {
            p.terminal();
        }
        self.tx_timestamps.cancel_from(0);
        self.pacing_deadline = None;
        self.pacer = Pacer::default();
        self.reset_tlp();
        self.rack.deadline = None;
        self.congestion.end_ecn_prr();
        self.prr = None;
        self.sack_recovery = None;
        self.sack_guard = None;
        self.sack_post_rto = None;
        self.sack_fallback = None;
        self.scoreboard.clear();
        self.growth_dupack_bytes = 0;
        self.ecn_echo = false;
        self.ecn_cwr_pending = false;
        self.ecn_pause = None;
        self.ecn_backoff = None;
        self.ecn_sent_setup = false;
        self.fast_open_retry = None;
        self.deferred_tfo_push = false;
        self.reason = Some(reason);
        self.send.release_shared();
        self.events.closed = Some(reason);
        if reason != CloseReason::Aborted {
            self.pending_rst = None;
        }
        self.syn_pending = false;
        self.ack_pending = false;
        self.ack_receive = None;
        self.ack_engine_initialized = false;
        self.fast_open_write_pending = false;
        self.ack_interactive = false;
        self.ack_quick = 0;
        self.ack_ato = self.config.ack_timeout_floor();
        self.challenge_ack_pending = false;
        self.retx_pending = false;
        self.probe_pending = false;
        self.keepalive_pending = false;
        self.rto_deadline = None;
        self.loss_timer = None;
        self.ack_deadline = None;
        self.persist_deadline = None;
        self.shrink_unanswered_since = None;
        self.sws_deadline = None;
        self.cork_deadline = None;
        self.cork_flush = None;
        self.time_wait_deadline = None;
        self.keepalive_deadline = None;
    }

    // Lingers for the configured time_wait_us rather than RFC 9293's 2xMSL
    // (section 3.6.1 MUST-13, recorded as an exception): 120 s by default,
    // and any positive duration when configured.
    fn time_wait(&mut self) {
        self.terminal(CloseReason::Normal);
        self.state = State::TimeWait;
        self.time_wait_deadline = Some(
            self.now
                .saturating_add(self.config.timebase.ticks_from_us(self.config.time_wait_us)),
        );
        self.immediate_ack();
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
    //# In particular, R2 for a SYN segment MUST be set large enough to provide
    //# retransmission of the segment for at least 3 minutes (MUST-23).
    fn user_timeout(&self) -> u64 {
        self.config
            .timebase
            .ticks_from_us(if self.handshake_pending() {
                self.config.user_timeout_us.max(180_000_000)
            } else {
                self.config.user_timeout_us
            })
    }

    fn user_timer_needed(&self) -> bool {
        self.handshake_pending()
            || self.state == State::FinWait2
            || (self.synchronized()
                && (self.send.len() != 0
                    || self.flight() != 0
                    || self.shutdown && self.fin_sequence.is_none()))
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1
    //# As long as the receiving TCP peer continues to send acknowledgments in response
    //# to the probe segments, the sending TCP peer MUST allow the connection to stay
    //# open (MUST-37).
    // Nonzero shrink keeps normal in-window RTO retransmission. Like persist,
    // intentional backoff is not peer failure: only a committed, unanswered
    // retransmission starts the liveness clock. Current ACK/window feedback
    // clears it; reopening starts a fresh ordinary progress timeout.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
    //# but SHOULD NOT
    //# time out the connection if data beyond the right window edge is not
    //# acknowledged (SHLD-17).
    //= https://www.rfc-editor.org/rfc/rfc6429#section-1
    //# As long as the receiving TCP continues to send acknowledgments in
    //# response to the probe segments, the sending TCP MUST allow the
    //# connection to stay open.
    //= https://www.rfc-editor.org/rfc/rfc6429#section-2
    //# Per [RFC1122], as long as the ACKs are being received for window probes,
    //# a connection can continue to stay in the persist condition.
    //= https://www.rfc-editor.org/rfc/rfc6429#section-2
    //# Although this may result in a prolonged ZWP state, it would be premature
    //# for TCP to take action on its own and close the printer connection
    //# merely due to its lack of progress. Once the printer's paper tray is
    //# reloaded (which may be minutes, hours, or days later), the print job
    //# needs to be able to continue uninterrupted over the same TCP connection.
    //= https://www.rfc-editor.org/rfc/rfc6429#section-4
    //# As stated in [RFC1122], a TCP implementation MUST NOT close a connection
    //# merely because it seems to be stuck in the ZWP or persist condition.
    fn user_deadline(&self) -> Option<Instant> {
        if !self.user_timer_needed() {
            return None;
        }
        if self.synchronized()
            && self.snd_wnd == 0
            && (self.send.len() != 0
                || self.flight() != 0
                || self.shutdown && self.fin_sequence.is_none())
        {
            // Persist backoff is not evidence of peer failure. Only start the
            // liveness timeout once a probe has actually gone unanswered.
            return self
                .persist_unanswered_since
                .map(|sent| sent.saturating_add(self.user_timeout()));
        }
        if self.synchronized() && self.snd_wnd != 0 && self.flight() > self.snd_wnd {
            return self
                .shrink_unanswered_since
                .map(|sent| sent.saturating_add(self.user_timeout()));
        }
        Some(self.progress_at.saturating_add(self.user_timeout()))
    }

    // Explicit application resource policy is separate from transport R2 liveness
    // (RFC 6429 section 4). Responsive probes do not constitute output progress.
    fn application_timer_needed(&self) -> bool {
        self.handshake_pending()
            || (self.synchronized()
                && (self.send.len() != 0
                    || self.flight() != 0
                    || self.shutdown && self.fin_sequence.is_none()))
    }

    pub(crate) fn application_deadline(&self) -> Option<Instant> {
        self.application_timeout_us
            .filter(|_| self.application_timer_needed())
            .and_then(|timeout| {
                self.local_resource
                    .map_or(Some(self.application_progress_at), |r| r.epoch)
                    .map(|epoch| epoch.saturating_add(self.config.timebase.ticks_from_us(timeout)))
            })
    }

    pub(crate) fn expire_reserved_application(&mut self, now: Instant) -> Result<bool, Error> {
        self.check_time(now)?;
        if !due(self.application_deadline(), now) {
            return Ok(false);
        }
        self.update_time(now)?;
        self.terminal(CloseReason::TimedOut);
        Ok(true)
    }

    //= https://www.rfc-editor.org/rfc/rfc6429#section-1
    //# Therefore, zero window probing needs to be supported to prevent a
    //# connection from hanging forever if ACK segments that re-open the window
    //# are lost.
    fn arm_work(&mut self) {
        self.resolve_probe_response();
        let early_response = self.early_response_eligible();
        if !self.synchronized() && !early_response {
            self.select_loss_timer();
            return;
        }
        if self.tlp_arm_packets().is_none() {
            self.tlp_deadline = None;
            self.tlp_pending = false;
        }
        let pending = self.send.len() != 0
            || self.flight() != 0
            || self.shutdown && self.fin_sequence.is_none();
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
        //# If the window shrinks to zero, the TCP implementation MUST probe it in the
        //# standard way (described below) (MUST-35).
        // Early response coalescing is live, but loss/persist timing stays SYN-owned.
        if !early_response && self.snd_wnd == 0 && pending {
            if self.prr.is_some() {
                // Complete the PRR episode before zero-window probes.
                self.congestion.complete_prr();
                self.sack_guard = self.sack_recovery.map(|r| r.recovery_point);
                self.sack_recovery = None;
                self.congestion.end_ecn_prr();
                self.prr = None;
                self.congestion.cancel_prr_recovery();
                self.reset_limited_transmit();
            }
            self.rack.deadline = None;
            if self.persist_interval == 0 {
                self.persist_interval = self.rto();
            }
            if self.flight() == 0 {
                if self.persist_deadline.is_none() && !self.probe_pending {
                    self.persist_deadline = Some(self.now.saturating_add(self.persist_interval));
                }
                self.rto_deadline = None;
            } else {
                // Outstanding bytes use RTO, including the required post-PTO
                // fallback. Unsent-only work uses ZWP; both expirations probe
                // a closed window with the same exponential backoff.
                self.persist_deadline = None;
                if self.rto_deadline.is_none() && !self.probe_pending {
                    self.rto_deadline = Some(self.now.saturating_add(self.persist_interval));
                }
            }
        } else if !early_response {
            self.probe_pending = false;
            self.persist_interval = 0;
            self.persist_unanswered_since = None;
            self.persist_deadline = None;
            if self.flight() != 0 && self.rto_deadline.is_none() && !self.retx_pending {
                self.rto_deadline = Some(self.now.saturating_add(self.rto()));
            }
        }
        let unsent = self.send.len() > self.snd_nxt.distance_from(self.send_base) as usize;
        if self.cork_flush.is_some_and(|end| !end.after(self.snd_nxt)) {
            self.cork_flush = None;
        }
        let queued_end = self.send_base.wrapping_add(self.send.len() as u32);
        if unsent
            && (self.cork || self.more)
            && !self.shutdown
            && self.cork_flush.is_none_or(|end| queued_end.after(end))
        {
            // Linux tcp(7): corking has a 200ms ceiling. Like all timers this
            // is caller-clock time, and does not override transport admission.
            if self.cork_deadline.is_none() {
                self.cork_deadline = Some(
                    self.now
                        .saturating_add(self.config.timebase.ticks_from_us(200_000)),
                );
            }
        } else {
            self.cork_deadline = None;
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
        //= reason=SWS override, retransmission and user deadlines require driver servicing.
        //# MUST NOT buffer data indefinitely (MUST-60),
        if unsent && self.snd_wnd != 0 {
            if self.sws_deadline.is_none() && !self.sws_override {
                self.sws_deadline = Some(
                    self.now
                        .saturating_add(self.config.timebase.ticks_from_us(500_000)),
                );
            }
        } else {
            self.sws_deadline = None;
            self.sws_override = false;
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
        //# Keep-alive packets MUST only be sent when no sent data is outstanding, and
        //# no data or acknowledgment packets have been received for the connection
        //# within an interval (MUST-26).
        if self.send.len() == 0 && self.flight() == 0 && self.state == State::Established {
            if let Some(keepalive) = self.config.keepalive
                && self.keepalive_deadline.is_none()
                && !self.keepalive_pending
            {
                self.keepalive_deadline = Some(
                    self.last_received
                        .saturating_add(self.config.timebase.ticks_from_us(keepalive.idle_us)),
                );
            }
        } else {
            self.keepalive_deadline = None;
            self.keepalive_pending = false;
        }
        self.select_loss_timer();
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.2
    //# Queue the data for transmission after entering ESTABLISHED state.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.2
    //# Return "error: connection closing" and do not service request.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
    //= reason=Explicit PUSH is supported by write_with_push; write supplies automatic PUSH, with arm_work deadlines requiring driver servicing.
    //# If
    //# PUSH flags are not implemented, then the sending TCP peer: (1) MUST
    //# NOT buffer data indefinitely (MUST-60), and (2) MUST set the PSH bit
    //# in the last buffered segment (i.e., when there is no more queued data
    //# to be sent) (MUST-61).
    pub(crate) fn write(&mut self, data: &[u8]) -> Result<usize, Error> {
        self.write_with_push(data, true)
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
    //# A TCP endpoint MAY implement PUSH flags on SEND calls (MAY-15).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
    //= reason=Explicit PUSH marks survive packetization and partial acknowledgment; Nagle still applies.
    //# If the PUSH flag is set, the application intends the data to be transmitted promptly to
    //# the receiver, and the PSH bit will be set in the last TCP segment created from the
    //# buffer.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
    //= reason=FIFO byte queue across successive writes, not per-write completion records.
    //# Multiple SENDs are served in first come, first served order, so the TCP endpoint will
    //# queue those it cannot service immediately.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.2
    //= reason=Handshake SEND queue; focused send_state_matrix_preserves_queue_on_rejection additionally tests exhaustion.
    //# Queue the data for transmission after entering ESTABLISHED state. If no space to queue,
    //# respond with "error: insufficient resources".
    pub(crate) fn write_with_push(&mut self, data: &[u8], push: bool) -> Result<usize, Error> {
        self.queue_write(data, push, false, false, None)
    }

    pub(crate) fn write_with_options(
        &mut self,
        data: &[u8],
        more: bool,
        end_of_record: bool,
    ) -> Result<usize, Error> {
        self.write_with_options_and_notsent_lowat(data, more, end_of_record, None)
    }

    pub(crate) fn write_with_options_and_notsent_lowat(
        &mut self,
        data: &[u8],
        more: bool,
        end_of_record: bool,
        lowat: Option<u32>,
    ) -> Result<usize, Error> {
        self.queue_write(data, !more && !data.is_empty(), more, end_of_record, lowat)
    }

    pub(crate) fn write_with_timestamp(
        &mut self,
        data: &[u8],
        more: bool,
        end_of_record: bool,
        lowat: Option<u32>,
        request: TxTimestampRequest,
    ) -> Result<usize, Error> {
        if !data.is_empty() {
            // No fallible operation follows write acceptance: these slots are
            // already allocated, and this exclusive borrow reserves admission.
            self.tx_timestamps.admit(request)?;
        }
        let count = self.write_with_options_and_notsent_lowat(data, more, end_of_record, lowat)?;
        if count != 0 {
            let target = self.acknowledged + self.send.len() as u64 - 1;
            self.tx_timestamps.insert(request, target);
        }
        Ok(count)
    }

    pub(crate) fn check_write_admission(
        &self,
        lowat: Option<u32>,
        request: TxTimestampRequest,
    ) -> Result<usize, Error> {
        self.check_admission(lowat, request, self.send_space_remaining())
    }

    // As check_write_admission, but for a write that tries its storage
    // growth again, as each tcp_sendmsg call retries sk_wmem_schedule: the
    // room a write would take with memory to grow.
    pub(crate) fn check_write_retry(
        &self,
        lowat: Option<u32>,
        request: TxTimestampRequest,
    ) -> Result<usize, Error> {
        let space = self.send_space().saturating_sub(self.send.len());
        self.check_admission(lowat, request, space)
    }

    fn check_admission(
        &self,
        lowat: Option<u32>,
        request: TxTimestampRequest,
        space: usize,
    ) -> Result<usize, Error> {
        if self.shutdown
            || !matches!(
                self.state,
                State::SynSent | State::SynReceived | State::Established | State::CloseWait
            )
        {
            return Err(Error::InvalidState);
        }
        self.tx_timestamps.admit(request)?;
        let room = self.admission_room(lowat, space);
        if room == 0 {
            Err(Error::WouldBlock)
        } else {
            Ok(room)
        }
    }

    pub(crate) fn send_admission_room(&self, lowat: Option<u32>) -> usize {
        self.admission_room(lowat, self.send_space_remaining())
    }

    // The admission room with `space` of send space left.
    fn admission_room(&self, lowat: Option<u32>, space: usize) -> usize {
        // Keep the u64 TCP-stream position representable, including output's
        // exclusive end. Never wrap offsets or admit bytes we cannot identify.
        let cursor_room = u64::MAX - self.acknowledged - self.send.len() as u64;
        self.send
            .admission_room(self.notsent_bytes(), lowat)
            .min(space)
            .min(usize::try_from(cursor_room).unwrap_or(usize::MAX))
    }

    // Bytes the send ring and both sender ledgers, as allocated, hold beyond
    // those queued.
    fn allocated_send_room(&self) -> usize {
        self.send
            .allocation_capacity()
            .min(self.rack.admitted_bytes())
            .min(self.scoreboard.admitted_bytes())
            .saturating_sub(self.send.len())
    }

    pub(crate) fn send_memory_throttled(&self) -> bool {
        self.send_memory_wanted.is_some()
    }

    pub(crate) fn send_memory_wanted(&self) -> Option<usize> {
        self.send_memory_wanted
    }

    // Memory came back to the buffer budget: the next write may grow the
    // storage again, and the connection is writable if it has room
    // (sk_stream_write_space).
    pub(crate) fn memory_released(&mut self) {
        if self.send_memory_wanted.take().is_some() && self.send_space_remaining() != 0 {
            self.send_backpressured = false;
            self.events.writable |=
                !self.shutdown && matches!(self.state, State::Established | State::CloseWait);
        }
    }

    pub(crate) fn send_tuned(&self) -> bool {
        self.send_tuned
    }

    // Queued payload below the send floor: as Linux lets a socket whose
    // sk_wmem_queued is below tcp_wmem[0] allocate under pressure
    // (__sk_mem_raise_allocated), so that RFC 7323 still works.
    pub(crate) fn send_below_min(&self) -> bool {
        self.send.len() < self.send_min
    }

    // A tuned send limit falls to what is queued, but not below its floor:
    // Linux's sk_stream_moderate_sndbuf, applied where an allocation was
    // suppressed. The write being refused still takes what the storage
    // already allocated holds, as Linux then forces the allocation in
    // flight through for a socket at its new sndbuf, so the limit keeps
    // those bytes too. It allocates and frees nothing; the next ACKs that
    // free room let writes in within it.
    pub(crate) fn moderate_send(&mut self) {
        if !self.send_tuned {
            return;
        }
        let limit = (self.send.len() + self.allocated_send_room()).max(self.send_min);
        if limit < self.config.send_capacity {
            self.config.send_capacity = limit;
            self.send.set_limit(limit);
        }
    }

    // A write found its storage growth refused for `wanted` bytes.
    pub(crate) fn throttle_send(&mut self, wanted: usize) {
        self.send_memory_wanted = Some(wanted);
        self.send_backpressured = true;
    }

    // The ordinary effective data-segment size Q under the current PMTU:
    // `mss` already carries the fixed IP and TCP headers, negotiated
    // timestamps and the user, local and path ceilings. Fast Open installs
    // a cached or default peer MSS before the SYN-ACK updates `mss`.
    fn send_quantum(&self) -> usize {
        let base = if self.tuple.local.is_ipv4() { 20 } else { 40 };
        let options = usize::from(self.ip_header_len - base) + if self.timestamps { 12 } else { 0 };
        self.mss
            .min(usize::from(self.peer_mss).saturating_sub(options).max(1))
    }

    //= https://www.rfc-editor.org/rfc/rfc1191#section-6.4
    //= reason=Managed connections bound unacknowledged plus queued payload by a send-space ceiling C: the logical send-buffer capacity B rounded down to the greatest multiple of Q, the segment size in use under the current PMTU. User disposition (decision A, 2026-11-04, recorded): Q, the ordinary effective data payload segments actually carry (the PMTU less the fixed IP and TCP headers and negotiated timestamps, within the peer, user and local send ceilings), is this paragraph's segment size (PMTU - 40), because the literal PMTU - 40 would reintroduce the partial segment the rule avoids; the two agree only for option-free IPv4 without a lower transport ceiling (IPv4 PMTU 1500 with timestamps: Q = 1448 and B = 20000 give C = 18824, the literal formula 18980). User disposition (decision A, 2026-11-04, recorded): for a legal buffer below one segment C = B, because the literal greatest multiple, zero, would deadlock it; the peer and congestion windows still bound what is outstanding, so no credit is invented. C is derived on demand, so every PMTU decrease and increase, MSS negotiation, user-cap, header and buffer change applies before the next admission or output. Write admission and readiness use C, and every fresh-output branch (ordinary, Limited Transmit, PRR, RFC 6675 recovery, TLP, Fast Open and early-response data, reserved, shared and GSO totals, PLPMTUD probes) sends at most C less the unacknowledged payload, repairing instead when none is left; retransmission, exact-range repair, FIN, persist and keepalive take none of it, data admitted above a smaller C drains through ACKs, snd_wnd, max_snd_wnd and cwnd are unchanged and reported capacity stays B. Core tests (connection_send_space_tests.rs) cover B = 1, Q-1, Q, Q+1, 2Q-1 and multiples through receiver completion and the largest legal capacity arithmetically, peer windows 0, 1, Q-1, Q and Q+1, cwnd below and above C, PMTU and buffer changes below the flight, partial ACK, SACK and sequence wrap; native tests re-round SO_SNDBUF on PTB feedback with truthful getsockopt and writable edges, tun_echo admits whole segments across a PMTU change, and the integration/rfc_host mss send-space case captures distinct outstanding bytes reaching exactly C for a non-multiple B below the peer window and cwnd before any ACK advancement, then complete delivery verified by length and hash. Raw Endpoints keep B as their legacy contract.
    //# TCP performance can be reduced if the sender's maximum window size is not an exact
    //# multiple of the segment size in use (this is not the congestion window size, which
    //# is always a multiple of the segment size). In many system (such as those derived
    //# from 4.2BSD), the segment size is often set to 1024 octets, and the maximum window
    //# size (the "send space") is usually a multiple of 1024 octets, so the proper
    //# relationship holds by default. If PMTU Discovery is used, however, the segment size
    //# may not be a submultiple of the send space, and it may change during a connection;
    //# this means that the TCP layer may need to change the transmission window size when
    //# PMTU Discovery changes the PMTU value. The maximum window size should be set to the
    //# greatest multiple of the segment size (PMTU - 40) that is less than or equal to the
    //# sender's buffer space size.
    // The send-space ceiling C bounding unacknowledged plus queued payload.
    // A managed connection rounds its logical capacity B to whole segments;
    // a raw Endpoint keeps B. Derived on demand, so every PMTU, MSS, header
    // and capacity change applies before the next admission.
    pub(crate) fn send_space(&self) -> usize {
        if self.managed_path.is_none() {
            return self.config.send_capacity;
        }
        rounded_send_space(self.config.send_capacity, self.send_quantum())
    }

    // Bytes admitted above a smaller new C stay queued; room reopens only
    // once ordinary ACK progress drains below it.
    // While a write's storage growth stays refused, only what the allocated
    // storage holds: Linux's sk_stream_memory_free.
    fn send_space_remaining(&self) -> usize {
        let room = self.send_space().saturating_sub(self.send.len());
        if self.send_memory_wanted.is_some() {
            room.min(self.allocated_send_room())
        } else {
            room
        }
    }

    // Fresh payload a managed connection may newly transmit: C less the
    // unacknowledged payload. Retransmissions, SYN/FIN sequence units and
    // persist/keepalive probes take none of it. After C falls below the
    // flight, no new payload leaves until ACK progress reopens it. A raw
    // Endpoint keeps its legacy output, bounded by its windows alone.
    fn fresh_send_allowance(&self) -> usize {
        if self.managed_path.is_none() {
            return usize::MAX;
        }
        self.send_space()
            .saturating_sub(self.data_flight() as usize)
    }

    // Allocate the send ring and stage both sender ledgers before accepting
    // any bytes, within `max_charge` for the whole connection. The ring
    // takes the send limit whole once admitted bytes outgrow it: at the
    // first write, and at the first one after a larger limit. The ledgers
    // follow admitted live bytes, with geometric growth. Nothing allocates
    // from ACK, output, SACK or timeout processing. A ring that grew before
    // the other failed keeps its storage, which buffer_charge counts.
    //
    // Growth the budget or the allocator refuses fails no write: as Linux's
    // tcp_sendmsg copies what fits and then waits for memory
    // (sk_wmem_schedule, sk_stream_wait_memory), the write takes what the
    // allocated storage holds, as a partial write or WouldBlock, and the
    // connection is not writable beyond it until memory comes back. Returns
    // whether growth was refused.
    pub(crate) fn prepare_send_metadata(
        &mut self,
        bytes: usize,
        lowat: Option<u32>,
        max_charge: usize,
        timestamp: Option<TxTimestampRequest>,
    ) -> Result<bool, Error> {
        self.prepare_send_storage(bytes, lowat, max_charge, timestamp)
            .map(|refused| refused.is_some())
    }

    // As prepare_send_metadata; a refused growth gives the bytes the whole
    // write's growth would have charged.
    pub(crate) fn prepare_send_storage(
        &mut self,
        bytes: usize,
        lowat: Option<u32>,
        max_charge: usize,
        timestamp: Option<TxTimestampRequest>,
    ) -> Result<Option<usize>, Error> {
        if self.shutdown
            || !matches!(
                self.state,
                State::SynSent | State::SynReceived | State::Established | State::CloseWait
            )
        {
            return Err(Error::InvalidState);
        }
        if bytes == 0 {
            return Ok(None);
        }
        if let Some(request) = timestamp {
            self.tx_timestamps.admit(request)?;
        }
        // What the write would take with memory to grow: a refused write
        // tries again.
        let space = self.send_space().saturating_sub(self.send.len());
        let accepted = bytes.min(self.admission_room(lowat, space));
        if accepted == 0 {
            return Ok(None);
        }
        let live = self.send.len().saturating_add(accepted);
        let Err(wanted) = self.grow_send_storage(live, max_charge) else {
            self.send_memory_wanted = None;
            return Ok(None);
        };
        // As tcp_sendmsg copies skb by skb until sk_wmem_schedule refuses,
        // grow for the longest prefix the budget takes, halving the bytes
        // asked for (costs only, until one fits); the write takes that.
        let held = self.send.len() + self.allocated_send_room();
        let mut part = accepted / 2;
        while self.send.len() + part > held {
            let prefix = self.send.len() + part;
            if self
                .send_growth_cost(prefix)
                .is_some_and(|cost| self.buffer_charge().saturating_add(cost) <= max_charge)
            {
                // The allocator may still refuse it; the write then takes
                // what the storage held before.
                let _ = self.grow_send_storage(prefix, max_charge);
                break;
            }
            part /= 2;
        }
        // What waking it needs is the smallest growth that takes one more
        // byte, not the whole write: as sk_stream_memory_free, any room lets
        // the writer make progress.
        let held = self.send.len() + self.allocated_send_room();
        let next = self.send_growth_cost(held + 1).unwrap_or(wanted);
        self.throttle_send(next.min(wanted));
        Ok(Some(wanted))
    }

    // The peak bytes growing the send ring and both ledgers to hold `live`
    // queued bytes adds to the charge, or None if it overflows.
    fn send_growth_cost(&self, live: usize) -> Option<usize> {
        let grow_ring = live > self.send.allocation_capacity();
        let limit = if grow_ring {
            self.send.capacity()
        } else {
            self.send.allocation_capacity()
        };
        let target = live.checked_next_power_of_two().unwrap_or(limit).min(limit);
        let ring = if grow_ring {
            self.send.growth_bytes(limit)
        } else {
            0
        };
        let rack = if self.rack.admits_bytes(live) {
            0
        } else {
            self.rack.growth_bytes(target)?
        };
        let scoreboard = if self.scoreboard.admits_bytes(live) {
            0
        } else {
            Scoreboard::allocation_bytes(target)?
        };
        ring.checked_add(rack)?.checked_add(scoreboard)
    }

    // Grow the send ring and the ledgers to hold `live` queued bytes, or
    // leave them as they were and give the bytes the growth needed.
    fn grow_send_storage(&mut self, live: usize, max_charge: usize) -> Result<(), usize> {
        let grow_ring = live > self.send.allocation_capacity();
        let grow_rack = !self.rack.admits_bytes(live);
        let grow_scoreboard = !self.scoreboard.admits_bytes(live);
        if !grow_ring && !grow_rack && !grow_scoreboard {
            return Ok(());
        }
        // Admission keeps live bytes within the limit.
        let limit = if grow_ring {
            self.send.capacity()
        } else {
            self.send.allocation_capacity()
        };
        debug_assert!(live <= limit);
        let target = live.checked_next_power_of_two().unwrap_or(limit).min(limit);
        let existing = self.buffer_charge();
        let staged = self.send_growth_cost(live).ok_or(usize::MAX)?;
        if existing
            .checked_add(staged)
            .is_none_or(|peak| peak > max_charge)
        {
            return Err(staged);
        }
        let rack = if grow_rack {
            Some(self.rack.prepare_growth(target).map_err(|_| staged)?)
        } else {
            None
        };
        let scoreboard = if grow_scoreboard {
            Some(self.scoreboard.grown(target).map_err(|_| staged)?)
        } else {
            None
        };
        let ring = if grow_ring {
            self.send.growth_bytes(limit)
        } else {
            0
        };
        let actual = rack.as_ref().map_or(0, |growth| growth.allocation_bytes())
            + scoreboard.as_ref().map_or(0, Scoreboard::storage_bytes)
            + ring;
        if existing
            .checked_add(actual)
            .is_none_or(|peak| peak > max_charge)
        {
            return Err(actual);
        }
        // The ring grows in place, last: a failure leaves the ledgers staged
        // aside to drop, and the queued bytes as they were.
        if grow_ring {
            self.send.grow(limit).map_err(|_| staged)?;
        }
        if let Some(rack) = rack {
            self.rack.commit_growth(rack, target);
        }
        if let Some(scoreboard) = scoreboard {
            self.scoreboard = scoreboard;
        }
        Ok(())
    }

    pub(crate) fn admits_shared(&self, payload: &crate::Payload, max_spans: usize) -> bool {
        self.send.shared_room(payload, max_spans)
    }

    pub(crate) fn prepare_shared_storage(
        &mut self,
        payload: &crate::Payload,
        max_spans: usize,
        peak_room: usize,
    ) -> Result<(), Error> {
        if !self.send.shared_room(payload, max_spans) {
            return Err(Error::InvalidArgument);
        }
        self.send
            .prepare_shared(payload, peak_room)
            .map_err(|_| Error::NoMemory)
    }

    pub(crate) fn write_shared(
        &mut self,
        payload: crate::Payload,
        more: bool,
        end_of_record: bool,
        lowat: Option<u32>,
    ) -> Result<usize, Error> {
        self.queue_write_input(&[], Some(payload), !more, more, end_of_record, lowat)
    }

    fn queue_write(
        &mut self,
        data: &[u8],
        push: bool,
        more: bool,
        end_of_record: bool,
        lowat: Option<u32>,
    ) -> Result<usize, Error> {
        self.queue_write_input(data, None, push, more, end_of_record, lowat)
    }

    fn queue_write_input(
        &mut self,
        data: &[u8],
        shared: Option<crate::Payload>,
        push: bool,
        more: bool,
        end_of_record: bool,
        lowat: Option<u32>,
    ) -> Result<usize, Error> {
        let input_len = shared.as_ref().map_or(data.len(), crate::Payload::len);
        if self.shutdown
            || !matches!(
                self.state,
                State::SynSent | State::SynReceived | State::Established | State::CloseWait
            )
        {
            return Err(Error::InvalidState);
        }
        if input_len == 0 {
            self.send_issued = true;
            if push {
                self.send.mark_push();
            }
            return Ok(0);
        }
        // A write the endpoint found short of memory takes what the storage
        // holds; it grows nothing here.
        if self.send_memory_wanted.is_none() {
            self.prepare_send_metadata(input_len, lowat, usize::MAX, None)?;
        }
        let application_idle = !self.application_timer_needed();
        let idle = !self.user_timer_needed();
        let room = self.send_admission_room(lowat);
        let count = if let Some(payload) = shared {
            self.send
                .write_shared(payload.slice(0..input_len.min(room)).unwrap())
        } else {
            self.send.write(&data[..input_len.min(room)])
        };
        self.send_backpressured |= count < input_len;
        if count == 0 {
            return Err(Error::WouldBlock);
        }
        self.send_issued = true;
        self.more = more;
        if end_of_record {
            self.send.mark_end_of_record();
        }
        if push {
            self.send.mark_push();
        }
        if idle {
            self.progress_at = self.now;
        }
        if application_idle {
            self.application_progress_at = self.now;
        }
        self.arm_work();
        Ok(count)
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.5
    //# However, TCP implementations MUST still include support for the urgent mechanism
    //# (MUST-30).
    pub(crate) fn write_urgent(&mut self, data: &[u8]) -> Result<usize, Error> {
        let count = self.write(data)?;
        if count != 0 {
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.5
            //# The urgent pointer MUST point to the sequence number of the octet
            //# following the urgent data (MUST-62).
            self.snd_up = Some(self.send_base.wrapping_add(self.send.len() as u32));
        }
        Ok(count)
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.7
    //# The FLUSH call MAY be implemented (MAY-14).
    pub(crate) fn flush(&mut self) -> Result<usize, Error> {
        // FIN and SYN occupy sequence space, not buffer slots.
        if self.shutdown
            || !matches!(
                self.state,
                State::SynSent | State::SynReceived | State::Established | State::CloseWait
            )
        {
            return Err(Error::InvalidState);
        }
        let sent = if !self.snd_nxt.at_or_after(self.send_base) {
            0
        } else {
            (self.snd_nxt.distance_from(self.send_base) as usize).min(self.send.len())
        };
        // An on-wire urgent endpoint cannot be retracted: retain even unsent
        // bytes covered by it beyond the offered window.
        let advertised = self
            .advertised_snd_up
            .map_or(0, |end| end.distance_from(self.send_base) as usize);
        // FLUSH discards only to the right of the offered send window, not
        // all unsent data (which may merely be waiting for congestion control).
        let edge = self.snd_una.wrapping_add(self.snd_wnd);
        let window_prefix = if edge.after(self.send_base) {
            (edge.distance_from(self.send_base) as usize).min(self.send.len())
        } else {
            0
        };
        let retained = sent.max(advertised).max(window_prefix).min(self.send.len());
        let discarded = self.send.len() - retained;
        if self.deferred_tfo_push {
            let end = self.iss.wrapping_add(1 + self.fast_open_initial as u32);
            let remaining = end.distance_from(self.send_base) as usize;
            // Discarding the original mark must not let replacement bytes at
            // the same sequence numbers inherit the deferred PUSH.
            if end.after(self.send_base) && remaining > retained && remaining <= self.send.len() {
                self.deferred_tfo_push = false;
            }
        }
        self.tx_timestamps
            .cancel_from(self.acknowledged + retained as u64);
        self.send.truncate(retained);
        let end = self.send_base.wrapping_add(retained as u32);
        if self.cork_flush.is_some_and(|flush| flush.after(end)) {
            self.cork_flush = Some(end);
        }
        if self.snd_up.is_some_and(|up| up.after(end)) {
            self.snd_up = (retained != 0).then_some(end);
        }
        if discarded != 0 && self.send_space_remaining() != 0 {
            self.send_backpressured = false;
            self.events.writable = true;
        }
        self.arm_work();
        Ok(discarded)
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.6.1
    //# A host MAY implement a "half-duplex" TCP close sequence, so that an
    //# application that has called CLOSE cannot continue to read data from
    //# the connection (MAY-1).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.6.1
    //# If such a host issues a CLOSE call while received data is still pending in
    //# the TCP connection, or if new data is received after CLOSE is called, its
    //# TCP implementation SHOULD send a RST to show that data was lost (SHLD-3).
    pub(crate) fn close(&mut self) -> Result<(), Error> {
        if self.read_closed {
            return if self.state == State::Closed && self.reason != Some(CloseReason::Normal) {
                Err(Error::InvalidState)
            } else {
                Ok(())
            };
        }
        if !(matches!(
            self.state,
            State::SynSent | State::SynReceived | State::Established | State::CloseWait
        ) || self.shutdown
            && matches!(
                self.state,
                State::FinWait1 | State::FinWait2 | State::Closing | State::LastAck
            ))
        {
            return Err(Error::InvalidState);
        }
        // Closing the reader after write shutdown must not send a second FIN;
        // unread accepted bytes still take the existing data-loss abort path.
        self.read_closed = true;
        self.events.readable = false;
        self.events.pushed = false;
        self.events.urgent = None;
        self.events.writable = false;
        if self.receive.has_data() {
            self.abort();
            Ok(())
        } else {
            self.shutdown()
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.3
    //= reason=CLOSE-WAIT drains accepted bytes then returns EOF (0), the nonblocking API equivalent of closing notification.
    //# Since the remote side has already sent FIN, RECEIVEs must be satisfied by data already
    //# on hand, but not yet delivered to the user. If no text is awaiting delivery, the RECEIVE
    //# will get an "error: connection closing" response. Otherwise, any remaining data can be
    //# used to satisfy the RECEIVE.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.5
    //= reason=SYN data is buffered internally, not readable nor notified to application before handshake completes.
    //# so long as the receiving TCP endpoint doesn't deliver the data to the user until it is
    //# clear the data is valid (e.g., the data is buffered at the receiver until the connection
    //# reaches the ESTABLISHED state, given that the three-way handshake reduces the
    //# possibility of false connections).
    pub(crate) fn peek(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self.read_closed
            || self.state == State::Closed
                && (self.reason != Some(CloseReason::Normal) || !self.receive.eof())
        {
            return Err(Error::InvalidState);
        }
        if out.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if self.handshake_pending() && !self.fast_open_early {
            return Err(Error::WouldBlock);
        }
        let count = self.receive.peek(out);
        if count == 0 && !self.receive.eof() {
            return Err(Error::WouldBlock);
        }
        Ok(count)
    }

    pub(crate) fn read(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        if self.read_closed {
            return Err(Error::InvalidState);
        }
        if out.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if self.state == State::Closed
            && (self.reason != Some(CloseReason::Normal) || !self.receive.eof())
        {
            return Err(Error::InvalidState);
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
        //# If there are other controls or text in the segment, queue them for
        //# processing after the ESTABLISHED state has been reached, return.
        if self.handshake_pending() && !self.fast_open_early {
            return Err(Error::WouldBlock);
        }
        let count = self.receive.read(out);
        self.receive_used -= count;
        if count == 0 && !self.receive.eof() {
            return Err(Error::WouldBlock);
        }
        self.received_read = self.received_read.saturating_add(count as u64);
        self.rx_timestamps.consumed(self.received_read);
        // Only credit that an ordinary ACK can actually offer is useful:
        // backing storage may exceed the wire cap, or be below a scale unit.
        let shift = if self.scaling { self.local_scale } else { 0 };
        let credit = (u32::from(self.advertised_window(false)) << shift)
            .saturating_sub(self.receive_window());
        if count != 0 && !self.receive.eof() && credit >= self.read_window_threshold() {
            self.immediate_ack();
        }
        Ok(count)
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.6
    //# The user who CLOSEs may continue to RECEIVE until the TCP receiver is told that
    //# the remote peer has CLOSED also.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.4
    //= reason=Unpushed writes flush before FIN; read half remains available.
    //# Close also implies push function.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.4
    //= reason=Repeated shutdown is idempotent and never creates a second FIN.
    //# An "ok" response would be acceptable, too, as long as a second FIN is not emitted (the
    //# first FIN may be retransmitted, though).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.4
    //= reason=CLOSE-WAIT sends final reply data with FIN and enters LAST-ACK only on committed output.
    //# Queue this request until all preceding SENDs have been segmentized; then send a FIN
    //# segment, enter LAST-ACK state.
    pub(crate) fn shutdown(&mut self) -> Result<(), Error> {
        if self.shutdown
            && (self.state != State::Closed || self.reason == Some(CloseReason::Normal))
        {
            return Ok(());
        }
        if !matches!(
            self.state,
            State::SynSent | State::SynReceived | State::Established | State::CloseWait
        ) {
            return Err(Error::InvalidState);
        }
        if !self.user_timer_needed() {
            self.progress_at = self.now;
        }
        if !self.application_timer_needed() {
            self.application_progress_at = self.now;
        }
        self.shutdown = true;
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.4
        //= reason=Cancels protocol work locally; terminal handle storage remains until release.
        //# Delete the TCB and return "error: closing" responses to any queued
        //# SENDs, or RECEIVEs.
        if self.state == State::SynSent {
            self.terminal(CloseReason::Normal);
        } else {
            self.arm_work();
        }
        Ok(())
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.5
    //= reason=Only SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1/2 and CLOSE-WAIT emit reset; default is the illustrated bare RST. Explicit abort_with_ack adds ACK=RCV.NXT only after a completed synchronized handshake; section 3.10 permits detail differences and section 3.5.3 validates synchronized resets by SEQ. Release is endpoint-owned.
    //# Send a reset segment:
    //# <SEQ=SND.NXT><CTL=RST>
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.5
    //= reason=Terminal state cancels queued work; Endpoint defers storage reclamation until the reset is generated.
    //# All queued SENDs and RECEIVEs should be given "connection reset"
    //# notification; all segments queued for transmission (except for the
    //# RST formed above) or retransmission should be flushed. Delete the
    //# TCB, enter CLOSED state, and return.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.5
    //= reason=CLOSING, LAST-ACK and TIME-WAIT terminate without scheduling a reset.
    //# Respond with "ok" and delete the TCB, enter CLOSED state, and return.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.5
    //= reason=Aborted closes the connection and invalidates reads/writes; Endpoint release reclaims storage after reset output drains.
    //# All queued SENDs and RECEIVEs should be given "connection reset"
    //# notification.  Delete the TCB, enter CLOSED state, and return.
    pub(crate) fn abort(&mut self) {
        if self.state != State::Closed {
            self.pending_rst = matches!(
                self.state,
                State::SynReceived
                    | State::Established
                    | State::FinWait1
                    | State::FinWait2
                    | State::CloseWait
            )
            .then_some((
                self.snd_nxt,
                // An early-accepted peer can still be SYN-SENT: its reset
                // validation requires an ACK covering the original SYN.
                self.fast_open_early && self.handshake_pending()
                    || self.config.abort_with_ack && self.handshake_complete && self.synchronized(),
            ));
            // This replaces any reactive reset; its TSval=0 echo override
            // must not escape on the newly scheduled local-abort reset.
            self.reset_echo = None;
            self.reset_reply = false;
            self.terminal(CloseReason::Aborted);
        }
    }

    pub(crate) fn unsubmitted_active_open(&self) -> bool {
        self.state == State::SynSent && !self.syn_committed
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.4
    //# However, there MUST be a way for an application to disable the Nagle algorithm
    //# on an individual connection (MUST-17).
    pub(crate) fn set_nagle(&mut self, enabled: bool) {
        self.config.nagle = enabled;
        // Linux tcp(7): explicitly setting NODELAY flushes currently queued
        // output even under CORK; CORK still applies to subsequent writes.
        if !enabled {
            self.release_corked();
        }
        self.arm_work();
    }

    pub(crate) fn set_cork(&mut self, enabled: bool) {
        self.cork = enabled;
        if !enabled {
            self.release_corked();
        }
        self.arm_work();
    }

    pub(crate) fn record_send_backpressure(&mut self) {
        self.send_backpressured |= self.send_space_remaining() == 0;
    }

    pub(crate) fn finish_send(&mut self, end: u64, more: bool, end_of_record: bool, force: bool) {
        if let Some(offset) = end
            .checked_sub(self.acknowledged)
            .and_then(|n| n.checked_sub(1))
            && let Ok(offset) = usize::try_from(offset)
        {
            self.send.finish_send(offset, !more, end_of_record);
        }
        if end == self.acknowledged + self.send.len() as u64 {
            self.more = more;
        }
        if force {
            self.record_send_backpressure();
            self.release_corked();
        }
        self.arm_work();
    }

    fn release_corked(&mut self) {
        if self.send.len() > self.snd_nxt.distance_from(self.send_base) as usize {
            self.cork_flush = Some(self.send_base.wrapping_add(self.send.len() as u32));
        }
        self.cork_deadline = None;
    }

    #[cfg(test)]
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
    //= reason=Negotiated SACK (non-RACK/non-PRR test profile): empty/repeated SACK grants no Limited Transmit output; new SACK including duplex data grants one packet. No assertion that bare non-SACK DupACKs are SACK delivery.
    //# Note that a sender using SACK [RFC2018] MUST NOT send new data unless the incoming
    //# duplicate acknowledgment contains new SACK information.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
    //= reason=Non-SACK third DupACK threshold uses flight minus limited_sent; wire assertion flight=24, limited=8, ssthresh=8 at MSS4. Negotiated SACK partial advancing ACK trace additionally retains unacknowledged Limited Transmit exclusion. ECN reduction epoch sharing is separately scoped.
    //# When the third duplicate ACK is received, a TCP MUST set ssthresh to no more than the
    //# value given in equation (4).
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
    //= reason=Non-SACK third DupACK threshold uses flight minus limited_sent; wire assertion flight=24, limited=8, ssthresh=8 at MSS4. Negotiated SACK partial advancing ACK trace additionally retains unacknowledged Limited Transmit exclusion. ECN reduction epoch sharing is separately scoped.
    //# When [RFC3042] is in use, additional data sent in limited transmit MUST NOT be included
    //# in this calculation.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-2
    //= reason=Negotiated SACK fresh byte evidence defines duplicate ACK, including duplex input; repeated/no SACK cannot grant new credit. Non-SACK five-predicate definition remains TODO.
    //# Alternatively, a TCP that utilizes selective acknowledgments (SACKs) [RFC2018, RFC2883]
    //# can leverage the SACK information to determine when an incoming ACK is a "duplicate"
    //# (e.g., if the ACK contains previously unknown SACK information).
    pub(crate) fn input(&mut self, now: Instant, segment: &Segment<'_>) -> Result<(), Error> {
        self.input_with_traffic_class(now, 0, segment)
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= reason=Core separates input and transmit; driver-owned batches must be fed before polling output.
    //# For example, if the TCP endpoint is processing a series of queued segments, it
    //# MUST process them all before sending any ACK segments (MUST-59).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
    //= reason=SYN-SENT validates ACK before RST; no response to unacceptable RST. Erratum 8167 remains separate.
    //# If SEG.ACK =< ISS or SEG.ACK > SND.NXT, send a reset (unless the RST bit is set, if so
    //# drop the segment and return) <SEQ=SEG.ACK><CTL=RST>
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
    //= reason=SYN-SENT reset acceptance uses ACK of SYN, not RCV.NXT; terminal reason distinguishes reset.
    //# If the ACK was acceptable, then signal to the user "error: connection reset", drop the
    //# segment, enter CLOSED state, delete TCB, and return. Otherwise (no ACK), drop the
    //# segment and return.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
    //= reason=ACK-only/text without SYN cannot establish a SYN-SENT connection.
    //# Fifth, if neither of the SYN or RST bits is set, then drop the segment and return.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= reason=Rejected input leaves receive state unchanged and replies with current ACK; invalid RST is silent.
    //# If an incoming segment is not acceptable, an acknowledgment should be sent in reply
    //# (unless the RST bit is set, if so drop the segment and return):
    //# <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK> o After sending the acknowledgment, drop the
    //# unacceptable segment and return.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1
    //= reason=Receiver replies to persist probes with current next sequence/window; responsive sender survives.
    //# When the receiving TCP peer has a zero window and a segment arrives, it must still send
    //# an acknowledgment showing its next expected sequence number and current window (zero).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
    //= reason=SYN-ACK establishes active side and schedules ACK, which may carry queued data; no inline output.
    //# If SND.UNA > ISS (our SYN has been ACKed), change the connection state to ESTABLISHED,
    //# form an ACK segment <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= reason=RST in passive child silently releases it while listener survives; active simultaneous opener terminates and reports Reset (refusal equivalent).
    //# If this connection was initiated with a passive OPEN (i.e., came from the LISTEN state),
    //# then return this connection to LISTEN state and return. The user need not be informed.
    //# If this connection was initiated with an active OPEN (i.e., came from SYN-SENT state),
    //# then the connection was refused; signal the user "connection refused". In either case,
    //# the retransmission queue should be flushed. And in the active OPEN case, enter the
    //# CLOSED state and delete the TCB, and return.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Fresh post-RTO SACKs update scoreboard and select missing offset 256 without fast-recovery reentry.
    //# Further, a SACK TCP sender SHOULD utilize all SACK information made
    //# available during the loss recovery following an RTO.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Fresh post-RTO SACKs update scoreboard and select missing offset 256 without fast-recovery reentry.
    //# As described in Sections 4 and 5, Update () SHOULD continue to be used
    //# appropriately upon receipt of ACKs.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Fresh post-RTO SACKs update scoreboard and select missing offset 256 without fast-recovery reentry.
    //# In this case, a TCP sender SHOULD use this SACK information when determining
    //# what data should be sent in each segment following an RTO.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Validated negotiated ACKs, including reordered ACKs, update live in-flight ranges; malformed/future/DSACK-only blocks cannot count as fresh delivery.
    //# Upon the receipt of any ACK containing SACK information, the scoreboard MUST
    //# be updated via the Update () routine.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. New SACK evidence increments once even on duplex/window-changing ACK; repeated blocks do not earn new credit.
    //# If the incoming ACK is a duplicate acknowledgment per the definition in
    //# Section 2 (regardless of its status as a cumulative acknowledgment), and the
    //# TCP is not currently in loss recovery, the TCP MUST increase DupAcks by one
    //# and take the following steps:
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Recovery ACK processing updates scoreboard/pipe and exits on boundary; partial cumulative ACK keeps recovery active without cwnd growth.
    //# Once a TCP is in the loss recovery phase, the following procedure MUST be
    //# used for each arriving ACK:
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Exclusive recovery boundary is cumulatively ACKed; recovery terminates, send storage releases and cwnd is deflated.
    //# (A) An incoming cumulative ACK for a sequence number greater than
    //# RecoveryPoint signals the end of loss recovery, and the loss recovery phase
    //# MUST be terminated.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Exit does not clear scoreboard; Update trims only cumulatively ACKed ranges. sack_recovery_exit_retains_new_data_advice_for_later_recovery checks retained new-data suffix, recomputed pipe and later IsLost entry across wrap.
    //# Any information contained in the scoreboard for sequence numbers greater
    //# than the new value of HighACK SHOULD NOT be cleared when leaving the loss
    //# recovery phase.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. ACK below recovery boundary updates scoreboard and recomputes recovery.pipe; partial ACK remains in recovery.
    //# (B) Upon receipt of an ACK that does not cover RecoveryPoint, the following
    //# actions MUST be taken:
    //= https://www.rfc-editor.org/rfc/rfc6675#section-2
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. snd_una is the exclusive cumulative edge, equivalent to HighACK+1.
    //# "HighACK" is the sequence number of the highest byte of data that has been
    //# cumulatively ACKed at a given point.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-2
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. duplicate_acks resets on cumulative ACK and increments on new delivery evidence.
    //# "DupAcks" is the number of duplicate acknowledgments received since the last
    //# cumulative acknowledgment.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-2
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. New in-flight SACK bytes qualify even when ACK carries duplex data or changes window; advancing-ACK test separately checks reset then increment.
    //# For the purposes of this specification, we define a "duplicate
    //# acknowledgment" as a segment that arrives carrying a SACK block that
    //# identifies previously unacknowledged and un-SACKed octets between HighACK
    //# and HighData. Note that an ACK which carries new SACK data is counted as a
    //# duplicate acknowledgment under this definition even if it carries new data,
    //# changes the advertised window, or moves the cumulative acknowledgment point,
    //# which is different from the definition of duplicate acknowledgment in
    //# [RFC5681].
    //= https://www.rfc-editor.org/rfc/rfc6675#section-2
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Threshold is three fresh-evidence ACKs; recovery starts on third, not repeated SACK blocks.
    //# Per [RFC5681], this threshold is defined to be 3 duplicate acknowledgments.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Three fresh evidence ACKs start recovery; repeated evidence is not counted.
    //# (1) If DupAcks >= DupThresh, go to step (4).
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. A single ACK carrying three one-byte discontiguous SACK ranges starts recovery immediately and emits one SMSS starting at snd_una regardless of advisory SACK edges.
    //# (2) If DupAcks < DupThresh but IsLost (HighACK + 1) returns true --
    //# indicating at least three segments have arrived above the current cumulative
    //# acknowledgment point, which is taken to indicate loss -- go to step (4).
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Event input returns; output is poll-driven and repeated evidence gives no extra credit.
    //# (3.4) Terminate processing of this ACK.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Every valid recovery ACK records SACK union before cumulative ACK and recovery state processing.
    //# (B.1) Use Update () to record the new SACK information conveyed by the
    //# incoming ACK.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. ACK below recovery boundary recomputes pipe; test gains credit after partial ACK then sends new data.
    //# (B.2) Use SetPipe () to re-calculate the number of octets still in the
    //# network.
    pub(crate) fn input_with_traffic_class(
        &mut self,
        now: Instant,
        traffic_class: u8,
        segment: &Segment<'_>,
    ) -> Result<(), Error> {
        self.input_authorized(now, traffic_class, segment, None)
    }

    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
    //= reason=Explicit live local ListenerId selection authorizes only the first acceptable crossing SYN using current finite listener credentials, protected policy and shared pending/reset-debt limits. Active identity, RFC5681 construction, early reads and frozen rejection remain independent of outgoing cookies; local SYN-ACK cookies require actual departure and never train client request provenance. Two actual Endpoint listeners issue asymmetric credentials, and core/native PacketIo and public-fd tests complete both streams through fallback, expiry, wrap, duplicates, loss and reserved output without false connect completion.
    //# A special case is simultaneous open where the SYN receiver is a client in SYN-SENT state. The protocol remains the same because [RFC793] already supports both data in the SYN and simultaneous open.
    fn input_authorized(
        &mut self,
        now: Instant,
        traffic_class: u8,
        segment: &Segment<'_>,
        authorization: Option<crate::endpoint::CrossingSynAuthorization>,
    ) -> Result<(), Error> {
        self.accepted_metadata = false;
        self.check_time(now)?;
        // Supersede the previous packet's D-SACK even when this checked arrival
        // is later dropped. Endpoint rejects checksum-invalid packets before
        // this boundary; output failure alone must not consume the report.
        self.receive.clear_dsack();
        self.update_time(now)?;
        self.retransmit_burst = None;
        if self.state == State::Closed {
            return Ok(());
        }
        let h = segment.header;
        let seq = Seq(h.sequence);
        let ack = Seq(h.acknowledgment);
        if self.state == State::SynSent {
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
            //# If SEG.ACK =< ISS or SEG.ACK > SND.NXT, send a reset (unless the RST bit
            //# is set, if so drop the segment and return)
            //= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
            //= reason=Nonzero forged TSecr on simultaneous SYN and synchronized non-ACK traffic cannot advance ACK state or update RTT; SYN TSval still initializes PAWS and simultaneous SYN deliberately cancels the pending sample.
            //# When the ACK bit is not set, the receiver MUST ignore
            //# the value of the TSecr field.
            //= https://www.rfc-editor.org/rfc/rfc5961#section-3.2
            //= reason=SYN-SENT reset validation assertion matrix includes arbitrary peer sequences, invalid/missing ACK silence and valid reset closure.
            //# In all
            //# other cases the receiver MUST silently discard the segment.
            // Actor/condition: TCP endpoint; SYN-SENT reset validation.
            let valid_ack =
                h.flags & ACK != 0 && ack.after(self.iss) && self.snd_nxt.at_or_after(ack);
            if h.flags & ACK != 0 && !valid_ack {
                if h.flags & RST == 0 {
                    self.pending_rst = Some((ack, false));
                    self.reset_echo = segment.options.timestamps.map(|ts| ts.0);
                    self.reset_reply = true;
                }
                return Ok(());
            }
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
            //# Otherwise (no ACK), drop the segment and return.
            if h.flags & RST != 0 {
                if valid_ack {
                    // A validated refusal ends this connection, but alone is not
                    // evidence that the service cannot accept Fast Open.
                    self.terminal(CloseReason::Reset);
                }
                return Ok(());
            }
            if h.flags & SYN == 0 {
                return Ok(());
            }
            // Active-open hardening: a nonzero echo must lie within the
            // timestamps we actually sent in SYNs. Reject before learning any
            // peer options or data, while leaving this handshake alive. This
            // supplements ACK validation; it is not the negotiated PAWS test.
            if self.config.timestamps
                && valid_ack
                && let Some((_, echo)) = segment.options.timestamps
                && echo != 0
                && self
                    .syn_timestamp_range
                    .is_none_or(|(first, last)| echo.wrapping_sub(first) > last.wrapping_sub(first))
            {
                self.pending_rst = Some((ack, false));
                self.reset_echo = None;
                self.reset_reply = true;
                return Ok(());
            }
            self.accepted_metadata = true;
            // RFC 7413 §4.2.2 also governs simultaneous open. An outgoing
            // cookie is not receive authorization; normal SYN-ACK data is allowed.
            let (early, response) = if !valid_ack {
                authorization.map_or((false, None), |grant| grant.consume())
            } else {
                (false, None)
            };
            if !valid_ack && !early && segment.options.fast_open.is_some() {
                let mut header = segment.header;
                header.flags &= !(FIN | PSH | URG);
                header.urgent_pointer = 0;
                self.learn_syn(
                    &Segment {
                        header,
                        options: segment.options,
                        raw_options: segment.raw_options,
                        payload: &[],
                    },
                    false,
                );
            } else {
                self.learn_syn(segment, early);
            }
            if !valid_ack {
                self.fast_open_response = response;
                self.fast_open_early = early;
                if early {
                    self.events.readable = self.receive.readable() != 0 || self.receive.eof();
                    self.events.pushed |= self.receive.take_push();
                    self.events.half_closed = self.receive.eof();
                    self.events.urgent = if self.read_closed { None } else { self.rcv_up };
                    if self.receive.readable() != 0 {
                        self.received_syn_data_start = self.irs.map(|irs| irs.wrapping_add(1));
                    }
                }
            }
            self.last_received = now;
            if valid_ack {
                self.report_fast_open_syn_rejection(ack);
                self.accept_ack(
                    ack,
                    false,
                    segment.options.timestamps.map(|ts| ts.1),
                    self.snd_wnd,
                    false,
                    0,
                );
                self.learn_fast_open_response(segment);
                self.establish();
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
                //# Data or controls that were queued for transmission MAY be included.
                // Pending ACKs share the output path with queued stream data.
                self.immediate_ack();
            } else {
                self.state = State::SynReceived;
                self.syn_pending = true;
                self.sample = None;
            }
            self.arm_work();
            return Ok(());
        }

        // RFC 7323 sections 3.2 and 5.2: RST bypasses PAWS, and its
        // timestamps never update connection state. Missing TS data/ACK silently drops.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
        //= reason=Negotiated missing-TS data/ACK silently drops without abort; RST exempt. Only synchronized non-handshake SYN is challenged and dropped under selected RFC5961 MUST, never accepted or used to update TS/ACK/payload/metadata. Handshake paths retain TS checks. Narrow justified departure from silent SHOULD, not a blanket waiver.
        //# non-<RST> segment is received without a TSopt, a TCP SHOULD silently
        //# drop the segment.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
        //= reason=Negotiated missing-TS data/ACK silently drops without abort; RST exempt. Only synchronized non-handshake SYN is challenged and dropped under selected RFC5961 MUST, never accepted or used to update TS/ACK/payload/metadata. Handshake paths retain TS checks. Narrow justified departure from silent SHOULD, not a blanket waiver.
        //# A TCP MUST NOT abort a TCP connection because any
        //# segment lacks an expected TSopt.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
        //= reason=TS-bearing ACK/data on an established unnegotiated fallback connection is processed normally: payload/window and local-clock RTT progress, no late TS negotiation, TS.Recent/age/latest mutation, PAWS dependence or outgoing TS.
        //# If a TSopt is received on a connection where TSopt was not negotiated
        //# in the initial three-way handshake, the TSopt MUST be ignored and the
        //# packet processed normally.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-5.2
        //= reason=RST bypasses PAWS and terminates/challenges before TS.Recent/ts_latest updates; no timestamp or stale timestamp cannot veto sequence-valid RST.
        //# When an <RST> segment is
        //# received, it MUST NOT be subjected to the PAWS check by verifying an
        //# acceptable value in SEG.TSval, and information from the Timestamps
        //# option MUST NOT be used to update connection state information.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
        //= reason=Negotiated PAWS/missing TS gate precedes receive-window, RST-exempt, ACK and metadata processing. R1 drop schedules ACK; regular R2/R4/R5 follows for accepted TS.
        //# If the PAWS algorithm is used, the following processing MUST be
        //# performed on all incoming segments for a synchronized connection.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
        //= reason=Negotiated PAWS/missing TS gate precedes receive-window, RST-exempt, ACK and metadata processing. R1 drop schedules ACK; regular R2/R4/R5 follows for accepted TS.
        //# Also, PAWS processing MUST take precedence over the regular TCP
        //# acceptability check (Section 3.3 in [RFC0793]), which is performed
        //# after verification of the received Timestamps option:
        //= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
        //= reason=Older timestamp data queued before a newer hole filler is delivered/read without a second PAWS check; a fresh raw arrival with the same old TS is rejected after the baseline advances.
        //# It is important to note that the timestamp MUST be checked only when
        //# a segment first arrives at the receiver, regardless of whether it is
        //# in sequence or it must be queued for later delivery.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-5.5
        //= reason=Stores ts_recent_at on eligible TS.Recent refresh, not pending ACKs; 2147s expiry boundary tests reject at -1us and accept at equality/+1us in both local modes.
        //# To detect how long the connection has been idle, the TCP MAY update a
        //# clock or timestamp value associated with the connection whenever
        //# TS.Recent is updated, for example.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
        //= reason=R1 stale negotiated non-RST schedules immediate ACK and returns without accepting data; missing TS is silent per section 3.2.
        //# Send an acknowledgment in reply as specified in Section 3.9
        //# of [RFC0793], page 69, and drop the segment.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-5.5
        //= reason=Tracks last TS.Recent refresh and invalidates at 2147s, before the RFC 24-day maximum; peer clocks <=1MHz are supported independent of local ticks, with TCP validation and R3 refresh retained.
        //# We therefore require that an implementation of PAWS include a
        //# mechanism to "invalidate" the TS.Recent value when a connection is
        //# idle for more than 24 days.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-5.2
        //= reason=TS values use same modular serial comparisons as sequence values. Wrap accepted, older values rejected; ambiguous half-space accepted only after baseline expiry.
        //# s < t  if 0 < (t - s) < 2^31,
        //= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
        //= reason=Shared negotiated PAWS gate precedes window and ACK metadata acceptance, with explicit RST and expired-baseline exemptions.
        //# R1)  If there is a Timestamps option in the arriving segment,
        //# SEG.TSval < TS.Recent, TS.Recent is valid (see later
        //# discussion), and if the RST bit is not set, then treat the
        //# arriving segment as not acceptable:
        //= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
        //= reason=PAWS-valid in-sequence text advances receive frontier; later gap fill advances through queued data. Negotiated TS assertion covers this path.
        //# R4)  If an arriving segment is in sequence (i.e., at the left window
        //# edge), then accept it normally.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
        //= reason=Timestamp-validated in-window data uses capacity-backed presence bits, without a range-count admission gate. Alternating-window and timestamp fragmentation tests cover more than 64 intervals, gap filling, retained delivery and wrap.
        //# R5)  Otherwise, treat the segment as a normal in-window,
        //# out-of-sequence TCP segment (e.g., queue it for later delivery
        //# to the user).
        //= https://www.rfc-editor.org/rfc/rfc7323#section-5.5
        //= reason=2147s expired baseline does not reject older/half-space value; sequence/ACK validation still gates R3 refresh and receive frontier advance.
        //# If
        //# TS.Recent is found to be invalid, then the segment is accepted,
        //# regardless of the failure of the timestamp check, and rule R3 updates
        //# TS.Recent with the TSval from the new segment.
        let recent_valid = now.saturating_sub(self.ts_recent_at)
            < self.config.timebase.ticks_from_us(PAWS_RECENT_EXPIRY_US);
        if self.timestamps && h.flags & RST == 0 {
            let Some((value, _)) = segment.options.timestamps else {
                // Narrow SHOULD departure: SYN is never accepted; selected RFC5961
                // MUST challenge wins without admitting data or updating TS state.
                // Handshake SYNs and RST handling retain their original paths.
                if h.flags & SYN != 0 && !self.handshake_pending() {
                    self.challenge_ack();
                }
                return Ok(());
            };
            if recent_valid && !Seq(value).at_or_after(Seq(self.ts_recent)) {
                if h.flags & SYN != 0 && !self.handshake_pending() {
                    self.challenge_ack();
                } else {
                    self.immediate_ack();
                }
                return Ok(());
            }
        }

        // RFC 7323 5.3 R1 is checked above, including SYN: stale SYN is
        // challenged and dropped without timestamp or stream side effects.
        // Missing-TS non-handshake SYN follows the narrow SHOULD departure
        // above; it is challenged, never accepted. Handshake paths below
        // retain their passive/SYN+ACK simultaneous-open handling.
        //= https://www.rfc-editor.org/rfc/rfc5961#section-4.2
        //= reason=Selected RFC5961 mitigation challenges and drops synchronized non-handshake SYN regardless of TS presence/sequence, under the existing bounded challenge budget. Narrow RFC7323 missing-TS SHOULD departure accepts no data/ACK/metadata/TS updates; valid/stale TS still traverse PAWS and RST remains exempt. Precedence/output rollback matrix covers all three TS cases.
        //# Instead, the handling of the SYN in the synchronized state SHOULD be
        //# performed as follows:
        // Actor/condition: TCP endpoint; selected blind-attack mitigation.
        //= https://www.rfc-editor.org/rfc/rfc5961#section-4.2
        //= reason=Selected RFC5961 mitigation challenges and drops synchronized non-handshake SYN regardless of TS presence/sequence, under the existing bounded challenge budget. Narrow RFC7323 missing-TS SHOULD departure accepts no data/ACK/metadata/TS updates; valid/stale TS still traverse PAWS and RST remains exempt. Precedence/output rollback matrix covers all three TS cases.
        //# 1) If the SYN bit is set, irrespective of the sequence number, TCP
        //# MUST send an ACK (also referred to as challenge ACK) to the remote
        //# peer:
        // Actor/condition: TCP endpoint; selected blind-attack mitigation.
        //= https://www.rfc-editor.org/rfc/rfc5961#section-4.2
        //= reason=Selected RFC5961 mitigation challenges and drops synchronized non-handshake SYN regardless of TS presence/sequence, under the existing bounded challenge budget. Narrow RFC7323 missing-TS SHOULD departure accepts no data/ACK/metadata/TS updates; valid/stale TS still traverse PAWS and RST remains exempt. Precedence/output rollback matrix covers all three TS cases.
        //# After sending the acknowledgment, TCP MUST drop the unacceptable
        //# segment and stop processing further.
        // Actor/condition: TCP endpoint; selected blind-attack mitigation.
        if h.flags & (SYN | RST) == SYN && !self.handshake_pending() {
            self.challenge_ack();
            return Ok(());
        }

        // Match the original handshake SYN before payload/window overlap can
        // classify it as a conflicting SYN. Rejected TFO text stays rejected;
        // a retry only repeats our existing SYN-ACK and receive commitment.
        if self.handshake_pending()
            && self.irs == Some(seq)
            && h.flags & (SYN | ACK | RST) == SYN
            && (h.flags & FIN == 0 || self.deferred_syn.is_some() || self.fast_open_early)
        {
            self.learn_ecn(h.flags);
            self.sack_send |= self.config.sack && segment.options.sack_permitted;
            self.syn_pending = true;
            return Ok(());
        }

        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.5
        //# A TCP implementation MUST support simultaneous open attempts (MUST- 10).
        // Simultaneous open: the SYN has already consumed receive sequence
        // space. Only the identical SYN+ACK can finish this handshake here.
        if self.handshake_pending()
            && !self.passive_open
            && self.irs == Some(seq)
            && h.flags & (SYN | ACK | RST | FIN) == (SYN | ACK)
            && (ack == self.iss.wrapping_add(1)
                || self.fast_open_initial != 0 && ack.after(self.iss))
            && self.snd_nxt.at_or_after(ack)
        {
            if self.timestamps
                && let Some((_, echo)) = segment.options.timestamps
                && echo != 0
                && self
                    .syn_timestamp_range
                    .is_none_or(|(first, last)| echo.wrapping_sub(first) > last.wrapping_sub(first))
            {
                return Ok(());
            }
            self.accepted_metadata = true;
            self.learn_ecn(h.flags);
            self.sack_send |= self.config.sack && segment.options.sack_permitted;
            if self.timestamps
                && let Some((value, _)) = segment.options.timestamps
            {
                self.ts_recent = value;
                self.ts_latest = value;
                self.ts_recent_at = now;
            }
            // The SYN-ACK can acknowledge only a prefix and close the peer's
            // window after early admission. Apply its unscaled SYN window
            // before ACK processing creates repair work; do not relearn the
            // SYN or reset the already readable receive frontier.
            self.snd_wnd = h.window as u32;
            self.max_snd_wnd = self.max_snd_wnd.max(self.snd_wnd);
            self.wl1 = seq;
            self.wl2 = ack;
            self.congestion.on_window_update(now, self.snd_wnd);
            self.report_fast_open_syn_rejection(ack);
            self.accept_ack(
                ack,
                false,
                segment.options.timestamps.map(|ts| ts.1),
                self.snd_wnd,
                false,
                0,
            );
            self.learn_fast_open_response(segment);
            self.establish();
            self.last_received = now;
            self.immediate_ack();
            self.receive_text(seq.wrapping_add(1), segment);
            if self.sack_send && segment.payload.is_empty() {
                // Linux-compatible D-SACK of the repeated SYN sequence only,
                // not rejected Fast Open text. Preserve any payload D-SACK.
                self.receive.record_duplicate(seq, 1);
                self.sack_omit = false;
            }
            self.arm_work();
            return Ok(());
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
        //= reason=The restarted timeout is the configured TIME-WAIT duration, not 2xMSL; the section 3.6.1 exception records that deviation.
        //# The only thing that can arrive in this state is a retransmission of the
        //# remote FIN. Acknowledge it, and restart the 2 MSL timeout.
        // A duplicate FIN falls just below RCV.NXT after its first receipt.
        if self.state == State::TimeWait
            && h.flags & (FIN | ACK | RST | SYN) == (FIN | ACK)
            && seq
                .wrapping_add(segment.payload.len() as u32)
                .wrapping_add(1)
                == self.receive.next()
        {
            if self.timestamps
                && let Some((value, _)) = segment.options.timestamps
                && (!recent_valid || Seq(value).after(Seq(self.ts_latest)))
            {
                self.ts_latest = value;
            }
            self.immediate_ack();
            self.time_wait_deadline = Some(
                now.saturating_add(self.config.timebase.ticks_from_us(self.config.time_wait_us)),
            );
            return Ok(());
        }
        let len = segment.payload.len() as u64
            + u64::from(h.flags & SYN != 0)
            + u64::from(h.flags & FIN != 0);
        let next = self.receive.next();
        let window = self.receive_window();
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
        //# A TCP receiver MUST process the RST and URG fields of all incoming segments,
        //# even when the receive window is zero (MUST-66).
        let acceptable = if h.flags & RST != 0 {
            //= https://www.rfc-editor.org/rfc/rfc5961#section-1.1
            //= reason=All three defenses are selected for ordinary endpoint operation; RST/SYN/ACK assertion matrices establish the operative behavior, not cryptographic/on-path protection or administrator threat assessment.
            //# The mitigations suggested in this document
            //# SHOULD be implemented in devices that regularly need to maintain TCP
            //# connections of the kind most vulnerable to the attacks described in
            //# this document.
            // Actor/condition: TCP endpoint; selected blind-attack mitigation.
            //= https://www.rfc-editor.org/rfc/rfc5961#section-1.1
            //= reason=All three defenses are selected for ordinary endpoint operation; RST/SYN/ACK assertion matrices establish the operative behavior, not cryptographic/on-path protection or administrator threat assessment.
            //# These mitigations
            //# MAY be implemented in other cases.
            // Actor/condition: TCP endpoint; selected blind-attack mitigation.
            //= https://www.rfc-editor.org/rfc/rfc5961#section-3.2
            //= reason=Selected RST/SYN defenses: existing state/sequence matrix asserts exact reset termination, outside reset silence, nonexact in-window challenge and SYN challenge fields/drop. Matrix exercises sequence wrap and rejects appended text/URG/FIN/ACK effects.
            //# Instead, implementations SHOULD implement the following steps in
            //# place of those specified in [RFC0793] (as listed above).
            // Actor/condition: TCP endpoint; selected blind-attack mitigation.
            //= https://www.rfc-editor.org/rfc/rfc5961#section-3.2
            //= reason=Selected RST/SYN defenses: existing state/sequence matrix asserts exact reset termination, outside reset silence, nonexact in-window challenge and SYN challenge fields/drop. Matrix exercises sequence wrap and rejects appended text/URG/FIN/ACK effects.
            //# 2) If the RST bit is set and the sequence number exactly matches the
            //# next expected sequence number (RCV.NXT), then TCP MUST reset the
            //# connection.
            // Actor/condition: TCP endpoint; selected blind-attack mitigation.
            //= https://www.rfc-editor.org/rfc/rfc5961#section-3.2
            //= reason=Selected RST/SYN defenses: existing state/sequence matrix asserts exact reset termination, outside reset silence, nonexact in-window challenge and SYN challenge fields/drop. Matrix exercises sequence wrap and rejects appended text/URG/FIN/ACK effects.
            //# 3) If the RST bit is set and the sequence number does not exactly
            //# match the next expected sequence value, yet is within the current
            //# receive window (RCV.NXT < SEG.SEQ < RCV.NXT+RCV.WND), TCP MUST
            //# send an acknowledgment (challenge ACK):
            // Actor/condition: TCP endpoint; selected blind-attack mitigation.
            //= https://www.rfc-editor.org/rfc/rfc5961#section-3.2
            //= reason=Selected RST/SYN defenses: existing state/sequence matrix asserts exact reset termination, outside reset silence, nonexact in-window challenge and SYN challenge fields/drop. Matrix exercises sequence wrap and rejects appended text/URG/FIN/ACK effects.
            //# After sending the challenge ACK, TCP MUST drop the unacceptable
            //# segment and stop processing the incoming packet further.
            // Actor/condition: TCP endpoint; selected blind-attack mitigation.
            //= https://www.rfc-editor.org/rfc/rfc5961#section-3.2
            //= reason=Selected RST/SYN defenses: existing state/sequence matrix asserts exact reset termination, outside reset silence, nonexact in-window challenge and SYN challenge fields/drop. Matrix exercises sequence wrap and rejects appended text/URG/FIN/ACK effects.
            //# In all other cases, where
            //# the SEQ-field does not match and is outside the window, the receiver
            //# MUST silently discard the segment.
            // Actor/condition: TCP endpoint; selected blind-attack mitigation.
            //= https://www.rfc-editor.org/rfc/rfc5961#section-4.2
            //= reason=Selected RST/SYN defenses: existing state/sequence matrix asserts exact reset termination, outside reset silence, nonexact in-window challenge and SYN challenge fields/drop. Matrix exercises sequence wrap and rejects appended text/URG/FIN/ACK effects.
            //# Upon receipt of a valid RST, the local TCP
            //# endpoint MUST terminate its connection.
            // Actor/condition: TCP endpoint; selected blind-attack mitigation.
            //= https://www.rfc-editor.org/rfc/rfc5961#section-3.2
            //= reason=This is the operative replacement list, not the preceding historical RFC793 rule. State matrix asserts outside-window RST does not schedule ACK or mutate state; verified erratum 4845 corrects only the historical list inequality.
            //# 1) If the RST bit is set and the sequence number is outside the current receive window, silently drop the segment.
            // Actor/condition: TCP endpoint; replacement RST mitigation, outside window.
            // RST validation uses SEG.SEQ, never the end of accompanying text.
            seq == next || seq.in_window(next, window) == Some(true)
        } else if window == 0 {
            // Even when accompanying text has no receive credit, exact-sequence
            // ACK/RST/URG controls must still be processed (RFC 9293 MUST-66).
            seq == next && (len == 0 || h.flags & (ACK | RST | URG) != 0)
        } else if len == 0 {
            seq.in_window(next, window) == Some(true)
        } else {
            len < 1 << 31
                && window != 0
                && (seq.in_window(next, window) == Some(true)
                    || seq.wrapping_add(len as u32 - 1).in_window(next, window) == Some(true))
        };
        //= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
        //= reason=Ordinary shared acceptability check follows PAWS; outside-window old-data D-SACK path reports evidence without admitting text or metadata.
        //# R2)  If the segment is outside the window, reject it (normal TCP
        //# processing).
        if !acceptable {
            // Old text is not admitted, but a validated duplicate may be
            // reported without accepting its ACK/window/metadata (RFC 2883).
            if self.sack_send
                && self.synchronized()
                && h.flags & (ACK | RST | SYN) == ACK
                && !segment.payload.is_empty()
                && segment.payload.len() < 1usize << 31
                && next.after(seq)
                && next.at_or_after(seq.wrapping_add(segment.payload.len() as u32))
                && self.snd_nxt.at_or_after(ack)
                && ack.at_or_after(
                    self.snd_una
                        .wrapping_add(0u32.wrapping_sub(self.max_snd_wnd)),
                )
            {
                self.receive.record_duplicate(seq, segment.payload.len());
                self.sack_omit = false;
            }
            if h.flags & RST == 0 {
                if self.handshake_pending() && h.flags & SYN != 0 && self.irs == Some(seq) {
                    self.syn_pending = true;
                } else {
                    self.immediate_ack();
                }
            }
            return Ok(());
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.5.3
        //# TCP implementations SHOULD allow a received RST segment to include data
        //# (SHLD-2).
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
        //# 3) If the RST bit is set and the sequence number does not exactly match the
        //# next expected sequence value, yet is within the current receive window, TCP
        //# endpoints MUST send an acknowledgment (challenge ACK):
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
        //# After sending the challenge ACK, TCP endpoints MUST drop the unacceptable
        //# segment and stop processing the incoming packet further.
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
        //# 2)  If the RST bit is set and the sequence number exactly
        //# matches the next expected sequence number (RCV.NXT), then
        //# TCP endpoints MUST reset the connection in the manner
        //# prescribed below according to the connection state.
        if h.flags & RST != 0 {
            if seq == next {
                self.fast_open_peer_reset = self.handshake_pending() && self.fast_open_early;
                // Preserve earlier path-failure evidence without adding any for RST.
                let passive =
                    self.handshake_pending() && self.passive_open && !self.fast_open_early;
                self.terminal(CloseReason::Reset);
                if passive {
                    self.events = ConnectionEvents::default();
                }
            } else {
                self.challenge_ack();
            }
            return Ok(());
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
        //# RFC 5961 recommends that in
        //# these synchronized states, if the SYN bit is set,
        //# irrespective of the sequence number, TCP endpoints MUST send
        //# a "challenge ACK" to the remote peer:
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
        //# o  After sending the acknowledgment, TCP implementations MUST
        //# drop the unacceptable segment and stop processing further.
        if h.flags & SYN != 0 {
            if self.handshake_pending() && self.passive_open {
                // Ordinary unaccepted children close silently; authenticated
                // early children may already be application-owned.
                self.terminal(CloseReason::Reset);
                if !self.fast_open_early {
                    self.events = ConnectionEvents::default();
                }
            } else {
                self.challenge_ack();
            }
            return Ok(());
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
        //# if the ACK bit is off, drop the segment and return
        if h.flags & ACK == 0 {
            return Ok(());
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
        //# o RFC 5961 [9], Section 5 describes a potential blind data injection attack,
        //# and mitigation that implementations MAY choose to include (MAY-12).
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
        //# TCP stacks that implement RFC 5961 MUST add an input check that the ACK
        //# value is acceptable only if it is in the range of ((SND.UNA - MAX.SND.WND)
        //# =< SEG.ACK =< SND.NXT).
        //= https://www.rfc-editor.org/rfc/rfc5961#section-1.1
        //= reason=All three defenses are selected for ordinary endpoint operation; RST/SYN/ACK assertion matrices establish the operative behavior, not cryptographic/on-path protection or administrator threat assessment.
        //# The mitigations suggested in this document
        //# SHOULD be implemented in devices that regularly need to maintain TCP
        //# connections of the kind most vulnerable to the attacks described in
        //# this document.
        // Actor/condition: TCP endpoint; selected blind-attack mitigation.
        //= https://www.rfc-editor.org/rfc/rfc5961#section-1.1
        //= reason=All three defenses are selected for ordinary endpoint operation; RST/SYN/ACK assertion matrices establish the operative behavior, not cryptographic/on-path protection or administrator threat assessment.
        //# These mitigations
        //# MAY be implemented in other cases.
        // Actor/condition: TCP endpoint; selected blind-attack mitigation.
        //= https://www.rfc-editor.org/rfc/rfc5961#section-5.2
        //= reason=Selected DATA/FIN mitigation: inclusive serial ACK bounds, adjacent rejection, challenge fields and no receive/URG/FIN/window/send/timer effects are asserted. RST/SYN state validation remains prior to ordinary ACK/data handling.
        //# All TCP stacks MAY implement the following mitigation.
        // Actor/condition: TCP endpoint; ACK-bearing segments after state/control validation.
        //= https://www.rfc-editor.org/rfc/rfc5961#section-5.2
        //= reason=Selected DATA/FIN mitigation: inclusive serial ACK bounds, adjacent rejection, challenge fields and no receive/URG/FIN/window/send/timer effects are asserted. RST/SYN state validation remains prior to ordinary ACK/data handling.
        //# TCP stacks
        //# that implement this mitigation MUST add an additional input check to
        //# any incoming segment.
        // Actor/condition: TCP endpoint; ACK-bearing segments after state/control validation.
        //= https://www.rfc-editor.org/rfc/rfc5961#section-5.2
        //= reason=Selected DATA/FIN mitigation: inclusive serial ACK bounds, adjacent rejection, challenge fields and no receive/URG/FIN/window/send/timer effects are asserted. RST/SYN state validation remains prior to ordinary ACK/data handling.
        //# All incoming segments whose ACK value doesn't satisfy the
        //# above condition MUST be discarded and an ACK sent back.
        // Actor/condition: TCP endpoint; ACK-bearing segments after state/control validation.
        //= https://www.rfc-editor.org/rfc/rfc5961#section-5.2
        //= reason=Inclusive lower/upper bounds, adjacent invalid values and modular wrap are explicitly asserted.
        //# The ACK value is considered acceptable only if it is in the range of ((SND.UNA - MAX.SND.WND) <= SEG.ACK <= SND.NXT).
        // Actor/condition: TCP endpoint; selected ACK bound mitigation.
        let oldest_ack = self
            .snd_una
            .wrapping_add(0u32.wrapping_sub(self.max_snd_wnd));
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
        //# All incoming segments
        //# whose ACK value doesn't satisfy the above condition MUST be
        //# discarded and an ACK sent back.
        if !self.snd_nxt.at_or_after(ack) || !ack.at_or_after(oldest_ack) {
            self.immediate_ack();
            return Ok(());
        }
        // As Linux's tcp_check_req with tcp_abort_on_overflow off, after the
        // same sequence, PAWS, RST, SYN and ACK checks: the request stays,
        // marked acked, its SYN-ACK retransmits, and the peer's next ACK
        // completes it once accept() made room. Nothing of the segment is
        // taken, neither its timestamp nor its data.
        if self.hold_establishment && self.handshake_pending() && ack.after(self.snd_una) {
            self.establishment_held = true;
            return Ok(());
        }
        // TCP sequence and ACK validation must precede timestamp refresh.
        if self.timestamps
            && let Some((value, _)) = segment.options.timestamps
            && (!recent_valid || Seq(value).after(Seq(self.ts_latest)))
        {
            self.ts_latest = value;
        }
        if self.timestamps
            //= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
            //= reason=Cross-reference to section 4.3: earliest delayed echo, OOO retained echo and hole-fill replacement use TS.Recent/Last.ACK.sent algorithm.
            //# The exact rules on which TSval MUST be echoed are given in
            //# Section 4.3.
            //= https://www.rfc-editor.org/rfc/rfc7323#section-4.3
            //= reason=TS.Recent updates only for sequence<=Last.ACK.sent and nondecreasing/expired TSval. Existing test asserts delayed earliest echo, unchanged echo across OOO hole, and replacement/frontier advance on hole fill.
            //# Thus,
            //# when delayed ACKs are in use, the receiver SHOULD reply with the
            //# TSval field from the earliest unacknowledged segment.
            //= https://www.rfc-editor.org/rfc/rfc7323#section-4.3
            //= reason=TS.Recent updates only for sequence<=Last.ACK.sent and nondecreasing/expired TSval. Existing test asserts delayed earliest echo, unchanged echo across OOO hole, and replacement/frontier advance on hole fill.
            //# An <ACK> for an out-of-order segment
            //# SHOULD, therefore, contain the timestamp from the most recent
            //# segment that advanced RCV.NXT.
            //= https://www.rfc-editor.org/rfc/rfc7323#section-4.3
            //= reason=TS.Recent updates only for sequence<=Last.ACK.sent and nondecreasing/expired TSval. Existing test asserts delayed earliest echo, unchanged echo across OOO hole, and replacement/frontier advance on hole fill.
            //# Thus, the timestamp from the
            //# latest segment (which filled the hole) MUST be echoed.
            //= https://www.rfc-editor.org/rfc/rfc7323#section-5.2
            //= reason=Valid TS.Recent uses modular serial nondecrease; expiry explicitly invalidates old baseline at 2147s; same SYN initializes it.
            //# The choice of incoming timestamps to be saved for this comparison
            //# MUST guarantee a value that is monotonically non-decreasing.
            //= https://www.rfc-editor.org/rfc/rfc7323#section-4.3
            //= reason=Synchronized valid baseline uses serial timestamp comparison and last ACK sequence gate; expired baseline handled by section5.5 exception to stale test.
            //# SEG.TSval >= TS.Recent and SEG.SEQ <= Last.ACK.sent
            //#
            //# then SEG.TSval is copied to TS.Recent; otherwise, it is ignored.
            //= https://www.rfc-editor.org/rfc/rfc7323#section-5.3
            //= reason=Accepted synchronized non-RST traffic uses serial nondecrease and last successful ACK gate; expired baseline is separate section5.5 path.
            //# R3)  If an arriving segment satisfies SEG.TSval >= TS.Recent and
            //# SEG.SEQ <= Last.ACK.sent (see Section 4.3), then record its
            //# timestamp in TS.Recent.
            && self.last_ack_sent.at_or_after(seq)
            && let Some((value, _)) = segment.options.timestamps
            && (!recent_valid || Seq(value).at_or_after(Seq(self.ts_recent)))
        {
            self.ts_recent = value;
            self.ts_recent_at = now;
        }
        let response_handshake = self.handshake_pending()
            && self.passive_open
            && self.fast_open_early
            && self.data_flight() != 0;
        let split_response_ack = response_handshake && ack.after(self.iss.wrapping_add(1));
        if response_handshake {
            // This wire ACK may be processed as SYN then payload internally.
            // Preserve its actual cumulative advance for RFC6582 section4.1.
            self.congestion.observe_ack_advance(self.snd_una, ack);
        }
        if self.handshake_pending() {
            if !ack.after(self.snd_una) {
                self.pending_rst = Some((ack, false));
                self.reset_echo = segment.options.timestamps.map(|ts| ts.0);
                self.reset_reply = true;
                return Ok(());
            }
            // Active simultaneous open can finish with a plain ACK when the
            // peer receives our SYN-ACK before selecting its own response.
            if !self.passive_open {
                self.report_fast_open_syn_rejection(ack);
            }
            // Leave response delivery for the normal ACK/SACK/PRR snapshot below.
            self.accept_ack(
                if split_response_ack {
                    self.iss.wrapping_add(1)
                } else {
                    ack
                },
                false,
                segment.options.timestamps.map(|ts| ts.1),
                self.snd_wnd,
                split_response_ack,
                0,
            );
            self.establish();
        }
        if self.state == State::TimeWait {
            return Ok(());
        }
        self.accepted_metadata = true;
        self.last_received = now;
        self.keepalive_probes = 0;
        self.keepalive_pending = false;
        self.keepalive_deadline = None;
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
        //= reason=Negotiated receive commitment gates CE handling after sequence/control/ACK validation, including exact-sequence zero-window probes without receive credit. Tests cover normal CE, repeated feedback, fallback commitment, invalid packets and ECN-off receive.
        //# * If a host has sent at least one ECN-setup SYN or ECN-setup SYN-
        //# ACK packet, and has received no non-ECN-setup SYN or non-ECN-
        //# setup SYN-ACK packet, then if that host receives TCP data
        //# packets with ECT and CE codepoints set in the IP header, then
        //# that host MUST process these packets as specified for an ECN-
        //# capable connection.
        // Actor/condition: TCP receiver; sent setup and received no plain setup; ECN data received.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.5
        //= reason=Sender retransmission Not-ECT asserted at endpoint; receiver invalid/out-of-window CE rejection asserted at sequence/ACK boundaries. TCP roles only, no network marking behavior.
        //# This document specifies ECN-capable TCP implementations MUST NOT set
        //# either ECT codepoint (ECT(0) or ECT(1)) in the IP header for
        //# retransmitted data packets, and that the TCP data receiver SHOULD
        //# ignore the ECN field on arriving data packets that are outside of the
        //# receiver's current window.
        // Actor/condition: TCP sender and receiver; retransmitted data output and out-of-window received data.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.5
        //= reason=Sender retransmission Not-ECT asserted at endpoint; receiver invalid/out-of-window CE rejection asserted at sequence/ACK boundaries. TCP roles only, no network marking behavior.
        //# To prevent such a denial-of-service attack, we
        //# specify that a legitimate TCP data sender MUST NOT set an ECT
        //# codepoint on retransmitted data packets, and that the TCP data
        //# receiver SHOULD ignore the CE codepoint on out-of-window packets.
        // Actor/condition: TCP sender and receiver; retransmitted data output and out-of-window received data.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
        //= reason=Explicit receive commitment assertion after delayed setup SYN-ACK and local plain-SYN fallback; sender no longer sets ECT, receiver still latches CE.
        //# However, the commitment to respond appropriately to incoming packets with the CE codepoint set remains even if the TCP sender in a later transmission, within this TCP connection, sends a SYN packet without ECE and CWR set.
        // Actor/condition: TCP endpoint; ECN setup followed by local plain-SYN fallback.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.3
        //= reason=Receive CE latch survives to the next ACK; two-packet aggregate tests mark either first or second segment, assert cumulative coverage of both and ECE, and contrast ECN-off. Immediate ACK scheduling on CE is retained.
        //# When TCP receives a CE data packet at the destination end-system, the TCP data receiver sets the ECN-Echo flag in the TCP header of the subsequent ACK packet. If there is any ACK withholding implemented, as in current "delayed-ACK" TCP implementations where the TCP receiver can send an ACK for two arriving data packets, then the ECN-Echo flag in the ACK packet will be set to '1' if the CE codepoint is set in any of the data packets being acknowledged. That is, if any of the received data packets are CE packets, then the returning ACK has the ECN-Echo flag set.
        // Actor/condition: TCP endpoint; CE data including delayed-ACK aggregation.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.3
        //= reason=Dropped feedback/repeated echo, unmarked CWR clearing, subsequent CE and CE-marked CWR assertions establish latch behavior. Erratum 3639 clarifies CWR-before-CE; reordered older CWR is guarded by CE epoch sequence.
        //# After a TCP receiver sends an ACK packet with the ECN-Echo bit set, that TCP receiver continues to set the ECN-Echo flag in all the ACK packets it sends (whether they acknowledge CE data packets or non-CE data packets) until it receives a CWR packet (a packet with the CWR flag set). After the receipt of the CWR packet, acknowledgments for subsequent non-CE data packets do not have the ECN-Echo flag set.
        // Actor/condition: TCP endpoint; echo persistence until CWR and later CE.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
        //= reason=ECN-off CE/ECT receive tests now prove no implicit enablement or echo; negotiated exact-sequence probes explicitly honor section 6.1.6. Sender Not-ECT outputs are asserted. A receiver cannot recover an overwritten original Not-ECT from CE alone, so universal per-packet ignore applicability is not proven. Rejected errata 3636/3680 do not waive the original text; retain this unresolved interpretation/evidence obligation.
        //# If the TCP connection does not wish to use ECN notification for a particular packet, the sending TCP sets the ECN codepoint to not-ECT, and the TCP receiver ignores the CE codepoint in the received packet.
        // Actor/condition: TCP endpoint; packet not sent as ECN-capable.
        // ECN never bypasses sequence, RST/SYN, or ACK-range validation.
        // Old ACKs cannot signal sender congestion, but their accepted duplex
        // data still carries receive-side CE/CWR (RFC 3168 section 6.1.3).
        let ece = self.ecn_feedback() && ack.at_or_after(self.snd_una) && h.flags & ECE != 0;
        if self.ecn_feedback() {
            if h.flags & CWR != 0 && self.ecn_ce_end.is_none_or(|end| seq.at_or_after(end)) {
                self.ecn_echo = false;
                self.ecn_ce_end = None;
            }
            //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.6
            //= reason=Validated exact-sequence zero-window ACK probes latch CE and return ECE without admitting payload or granting receive credit; boundary tests assert invalid sequence/ACK rejection, ECN-off, failed output and unchanged receive stream. Sender probes remain Not-ECT without CWR.
            //# Therefore, if
            //# a window probe arrives with the CE codepoint set, then the receiver
            //# SHOULD respond to the ECN indications.
            if traffic_class & 3 == 3 && !segment.payload.is_empty() {
                self.ecn_echo = true;
                // Exact-sequence zero-window controls passed validation above;
                // echo CE without accepting the probe's byte or receive credit.
                let end = seq.wrapping_add(if window == 0 {
                    0
                } else {
                    segment.payload.len() as u32
                });
                if self.ecn_ce_end.is_none_or(|old| end.after(old)) {
                    self.ecn_ce_end = Some(end);
                }
                self.immediate_ack();
            }
        }
        self.congestion.observe_ack(ack);
        let old_window = self.snd_wnd;
        // Compute the existing WL1/WL2 admission once. CUBIC needs the
        // accepted receive window before cumulative ACK growth; commit it
        // below at the existing transactional window-update boundary.
        let window_update = ack.at_or_after(self.snd_una)
            && (seq.after(self.wl1) || seq == self.wl1 && ack.at_or_after(self.wl2));
        let was_blocked = old_window == 0 || self.flight() > old_window;
        let prr_window_before = self.prr.map(|_| self.congestion.cwnd());
        let advancing = ack.after(self.snd_una);
        if advancing {
            self.tlp_pending = false;
        }
        let ecn_one = ece
            && self.flight() != 0
            && (if self.congestion.ecn_prr_end().is_some() {
                self.congestion.unsuppressed_cwnd()
            } else {
                self.congestion.cwnd()
            }) <= self.mss as u32
            && self.ecn_backoff.is_none_or(|(end, _)| ack.after(end));
        // A duplicate or reordered no-ECE ACK does not prove congestion ended.
        // Require new cumulative data delivery beyond the last marked flight.
        if advancing
            && !ece
            && self.data_flight() != 0
            && self.ecn_backoff.is_some_and(|(end, _)| ack.after(end))
        {
            self.ecn_backoff = None;
        }
        let ecn_reduced = ece
            && self.flight() != 0
            && self
                .congestion
                .on_ecn(ack, self.data_flight(), self.snd_nxt);
        if ecn_reduced {
            self.ecn_cwr_pending = true;
            self.growth_dupack_bytes = 0;
            self.reset_limited_transmit();
        }
        // Snapshot before ACK removal; start only after old loss recovery exits
        // and this ACK's loss detection runs. ECE never fabricates lost bytes.
        let ecn_prr_entry = (ecn_reduced
            && self.config.congestion_algorithm == CongestionAlgorithm::Cubic
            && self.config.prr
            && self.rack.valid())
        .then(|| {
            (
                self.snd_nxt,
                self.scoreboard
                    .unsacked_bytes(self.snd_una, self.data_high()),
                self.congestion.unsuppressed_cwnd(),
                self.mss as u32,
            )
        });
        let ecn_prr_was_active = self.congestion.ecn_prr_end().is_some();
        // Snapshot before this ACK: if it enters recovery, its entire current
        // delta belongs to the new epoch. Timer entry has no current ACK.
        let prr_was_active = self.prr.is_some();
        let ordinary_prr = prr_was_active && !ecn_prr_was_active && self.sack_recovery.is_none();
        let mut further_loss = false;
        let delivery_una = self.snd_una;
        let sackd_before = self.flight()
            - self
                .scoreboard
                .unsacked_bytes(self.snd_una, self.data_high());
        let mut dsack = false;
        let mut reo_grew = false;
        let tlp_flight = self.data_flight();
        let had_sack_advice = !self.scoreboard.ranges().is_empty();
        //= https://www.rfc-editor.org/rfc/rfc3042#section-2
        //= reason=Scoreboard update must add previously unknown sent bytes without overflow. Empty/repeated SACK grants no new credit; fresh SACK including duplex ACK is asserted by sack_limited_transmit_requires_new_evidence_including_duplex_ack.
        //# Note: If the connection is using selective acknowledgments [RFC2018], the data sender MUST
        //# NOT send new segments in response to duplicate ACKs that contain no new SACK information,
        //# as a misbehaving receiver can generate such ACKs to trigger inappropriate transmission of
        //# data segments.
        // RFC5961 ACK bounds were checked above. A reordered ACK may carry
        // fresh SACK evidence, but cannot move the cumulative edge backwards.
        let live_ack = if advancing { ack } else { self.snd_una };
        let sack_allowed =
            self.sack_receive && self.sack_fallback.is_none_or(|end| ack.at_or_after(end));
        // Snapshot before SACK/cumulative retirement removes earlier delivery.
        // SYN/FIN sequence space never contributes data growth credit.
        let growth_discount = if advancing {
            self.ack_growth_discount(ack, sack_allowed)
        } else {
            0
        };
        // Per-input ledger sample: SACK fallback may skip acknowledge entirely.
        // Never let a prior ACK's candidate leak into startup or RTO sampling.
        self.rack.ack_sample = None;
        let sack_evidence = if sack_allowed {
            let ptb_sack = self.ptb_sack_candidates(&segment.options.sack_blocks);
            let update = self.scoreboard.update_with_packet_ack(
                live_ack,
                ack,
                self.data_high(),
                &segment.options.sack_blocks,
            );
            dsack = update.dsack;
            self.loss_events.dsack_received += u64::from(update.dsack);
            if update.overflow {
                // SACK advice exhaustion disables inference, never timestamp
                // retention: normal RTO still needs each latest wire boundary.
                self.rack.deadline = None;
                self.congestion.end_ecn_prr();
                self.prr = None;
                let boundary = self.data_high();
                self.sack_fallback = Some(boundary);
                self.sack_guard = Some(boundary);
                self.sack_recovery = None;
                self.sack_post_rto = None;
                self.congestion.cancel_sack_recovery();
                self.reset_limited_transmit();
            }
            self.rack.acknowledge(
                live_ack,
                self.data_high(),
                &mut self.scoreboard,
                now,
                segment
                    .options
                    .timestamps
                    .map(|ts| ts.1.wrapping_sub(self.timestamp_offset)),
                self.timestamps.then_some(self.config.timestamp_granularity),
                self.mss as u32,
                update.dsack,
            );
            reo_grew = self.rack.reo_grew;
            if update.newly_sacked != 0 {
                self.ptb_sacked(&ptb_sack);
            }
            // Capacity backing preserves timestamp splits. Advice fallback
            // cannot retain a PRR epoch based on the discarded scoreboard.
            if !self.rack.valid() {
                self.congestion.end_ecn_prr();
                self.prr = None;
            }
            if !self.rack_enabled() {
                further_loss |= self
                    .rack
                    .mark_scoreboard_losses(&self.scoreboard, self.mss as u32);
                if let Some((start, _)) = self.rack.lowest_lost(self.mss as u32) {
                    self.note_probe_loss(start, self.rack.packet_counts().lost > 1);
                }
            }
            if !advancing
                && !response_handshake
                && let Some(sample) = self.rack.ack_sample
            {
                self.congestion.observe_startup_ack(
                    live_ack,
                    crate::hystart::StartupAck {
                        rtt: Some(sample),
                        snd_nxt: self.snd_nxt,
                        paced: self.pacing_enabled(),
                    },
                );
                if self.rack_enabled() {
                    self.update_rtt(sample);
                }
            }
            update.newly_sacked != 0 && !update.overflow
        } else {
            false
        };
        let tlp_loss_start = self.tlp_end.map(|(start, _, _)| start);
        let tlp_repaired = self.tlp_ack(
            ack,
            advancing,
            dsack,
            &segment.options.sack_blocks,
            segment.payload.is_empty()
                && h.flags & FIN == 0
                && ack == self.snd_una
                && old_window
                    == (u32::from(h.window) << if self.scaling { self.peer_scale } else { 0 }),
        );
        // RFC 8985 section 7.4.2: an ACK beyond a retransmitted probe without
        // duplicate-delivery evidence needs the same loss/ECN epoch guards as
        // fast recovery, but no retransmission (the probe repaired the loss).
        self.loss_events.loss_probe_recoveries += u64::from(tlp_repaired);
        let tlp_reduced =
            tlp_repaired && self.congestion.on_tlp_repair(ack, tlp_flight, self.snd_nxt);
        if tlp_reduced {
            if let Some(start) = tlp_loss_start {
                self.note_iw_loss(start);
            }
            self.ecn_cwr_pending |= self.ecn_feedback();
        }
        self.cancel_divergent_ecn_prr();
        let was_rto_recovery = self.sack_post_rto.is_some();
        let mut recovery_exited = false;
        if advancing {
            // Do not grow cwnd on the ACK that just triggered a loss reduction.
            self.accept_ack(
                ack,
                ece || tlp_reduced,
                segment.options.timestamps.map(|ts| ts.1),
                if window_update {
                    u32::from(h.window) << if self.scaling { self.peer_scale } else { 0 }
                } else {
                    old_window
                },
                response_handshake,
                growth_discount,
            );
        }
        if self
            .congestion
            .ecn_prr_end()
            .is_some_and(|end| self.snd_una.at_or_after(end))
        {
            self.congestion.complete_prr();
            self.prr = None;
        }
        if let Some(mut recovery) = self.sack_recovery {
            if self.snd_una.at_or_after(recovery.recovery_point) {
                if self.prr.is_some() {
                    self.congestion.complete_prr();
                }
                self.sack_recovery = None;
                self.congestion.end_ecn_prr();
                self.prr = None;
                recovery_exited = true;
            } else {
                recovery.pipe = self.recovery_pipe(recovery.high_rxt);
                self.sack_recovery = Some(recovery);
            }
        }
        if ordinary_prr && !self.congestion.in_fast_recovery() {
            self.congestion.complete_prr();
            self.congestion.end_ecn_prr();
            self.prr = None;
            recovery_exited = true;
        }
        if recovery_exited || was_rto_recovery && self.sack_post_rto.is_none() {
            self.rack.recovery_exit(reo_grew);
        }
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
        //= reason=One-MSS ECE rate reduction: existing assertion proves no fresh output before RTO-length pause and output at expiry, not merely an MSS cwnd floor.
        //# Therefore, the sending TCP MUST reset the
        //# retransmit timer on receiving the ECN-Echo packet when the congestion
        //# window is one.
        // Actor/condition: TCP sender; accepted ECE at one-MSS cwnd.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
        //= reason=Existing assertion blocks fresh output until RTO-length pause deadline and permits fresh ECT/CWR output at expiry.
        //# The sending TCP will then be able to send a new packet only when the retransmit timer expires.
        // Actor/condition: TCP endpoint; ECE at one-MSS cwnd.
        //= https://www.rfc-editor.org/rfc/rfc9438#section-4.6
        //= reason=Shared ECN rate control retains an independent interval across RTT samples and pause expiry; serial flight boundaries prevent repeated feedback from doubling or postponing the same pause.
        //# If congestion events indicated by ECN-Echo ACKs persist,
        //# a sender with a _cwnd_ of 1 SMSS MUST reduce its sending rate even
        //# further.
        //= https://www.rfc-editor.org/rfc/rfc9438#section-5.5
        //= reason=Successive distinct marked one-MSS flights double the send interval up to the existing 60-second timer cap in caller units. Only advancing no-ECE delivery beyond the marked flight resets persistence; loss backoff remains independent.
        //# CUBIC also satisfies the "full backoff" requirement as described in
        //# [RFC5033].  After reducing the sending rate to one packet per RTT in
        //# response to congestion events detected by ECN-Echo ACKs, CUBIC then
        //# exponentially increases the transmission timer for each packet
        //# retransmission while congestion persists.
        if ecn_one {
            let interval = self
                .ecn_backoff
                .map_or(self.rto(), |(_, interval)| {
                    interval.saturating_mul(2).max(self.rto())
                })
                .min(self.config.timebase.ticks_from_us(60_000_000));
            self.ecn_backoff = Some((self.snd_nxt, interval));
            self.ecn_pause = Some(now.saturating_add(interval));
            // PTO must not clock out another packet during the ECN pause.
            self.reset_tlp();
        }
        // Partial advancing ACKs may restart the ordinary RTO earlier, but
        // cannot shorten the current ECN pause or postpone it on duplicates.
        if let Some(deadline) = self.ecn_pause
            && self.flight() != 0
        {
            self.rto_deadline = Some(self.rto_deadline.map_or(deadline, |rto| rto.max(deadline)));
        }
        if self.state == State::Closed || self.state == State::TimeWait {
            return Ok(());
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
        //# If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK)), set
        //# SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.
        if window_update {
            //= https://www.rfc-editor.org/rfc/rfc7323#section-2.2
            //= reason=Changed WS on established data and ACK is ignored: negotiated shifts and subsequent effective incoming/outgoing windows remain fixed, including zero, nonzero and absent negotiation.
            //# A Window Scale option in a segment
            //# without a SYN bit MUST be ignored.
            //= https://www.rfc-editor.org/rfc/rfc7323#section-2.3
            //= reason=Incoming non-SYN SEG.WND is expanded with fixed negotiated peer_scale; raw SYN values stay unscaled.
            //# o  The window field (SEG.WND) in the header of every incoming
            //# segment, with the exception of <SYN> segments, MUST be left-
            //# shifted by Snd.Wind.Shift bits before updating SND.WND:
            //= https://www.rfc-editor.org/rfc/rfc7323#section-2.3
            //= reason=snd_wnd and receive acceptance credit are 32-bit; internal/congestion bytes are not scaled header values.
            //# The scale factor applies only to the window field as transmitted in
            //# the TCP header; each TCP using extended windows will maintain the
            //# window values locally as 32-bit numbers.
            self.snd_wnd = (h.window as u32) << if self.scaling { self.peer_scale } else { 0 };
            // Also freeze CUBIC on accepted non-advancing window updates;
            // otherwise a zero-window interval could age the cubic curve.
            self.congestion.on_window_update(now, self.snd_wnd);
            //= https://www.rfc-editor.org/rfc/rfc5961#section-5.2
            //= reason=Initial SYN window is unscaled; accepted updates are scaled and monotonically maxed. Scaled growth/shrink/zero history and ACK lower bounds across wrap are asserted.
            //# A new state variable MAX.SND.WND is defined as the largest window that the local sender has ever received from its peer. This window may be scaled to a value larger than 65,535 bytes ([RFC1323]).
            // Actor/condition: TCP endpoint; largest historically received scaled sender window.
            self.max_snd_wnd = self.max_snd_wnd.max(self.snd_wnd);
            self.wl1 = seq;
            self.wl2 = ack;
            self.shrink_unanswered_since = None;
            // Only current, acceptable ACK/window feedback proves responsiveness.
            // Old ACKs, stale window updates and rejected controls cannot prolong
            // persist or shrink liveness. Reopening also gets a fresh timeout.
            if was_blocked || self.flight() > self.snd_wnd {
                self.progress_at = now;
                self.persist_unanswered_since = None;
            }
        }
        // Permission to receive SACK is directional, not proof that this
        // peer supplies it. Retained advice keeps RFC6675 active across ACKs
        // without a SACK option; absent advice use ordinary loss inference.
        let duplicate = !advancing
            && ack == self.snd_una
            && self.data_flight() != 0
            && segment.payload.is_empty()
            && h.flags & FIN == 0
            && self.snd_wnd == old_window
            && self.snd_wnd != 0;
        if duplicate
            && !self.sack_receive
            && !ece
            && !self.congestion.in_recovery()
            && self.prr.is_none()
            && self.config.congestion_algorithm == CongestionAlgorithm::Cubic
        {
            // Duplicate ACKs are only bounded evidence of delivery. They grant
            // no cwnd growth; their estimates discount later cumulative growth.
            self.growth_dupack_bytes = self
                .growth_dupack_bytes
                .saturating_add(self.mss as u32)
                .min(self.data_flight());
        }
        if self.sack_recovery_enabled()
            && (!self.scoreboard.ranges().is_empty()
                || self.sack_recovery.is_some()
                || segment.options.sack_blocks.iter().any(Option::is_some))
            && !self.congestion.in_fast_recovery()
        {
            if sack_evidence && self.sack_recovery.is_none() {
                if !had_sack_advice {
                    // Fresh SACK starts the RFC6675 evidence counter, not an
                    // accumulation of earlier bare duplicate ACKs.
                    self.duplicate_acks = 0;
                    self.congestion.reset_duplicate_acks();
                }
                self.duplicate_acks = self.duplicate_acks.saturating_add(1);
                self.limited_pending = self.duplicate_acks <= 2 && self.sack_guard.is_none();
                if !self.rack_enabled()
                    && (self.duplicate_acks >= 3
                        || self.scoreboard.is_lost(self.snd_una, self.mss as u32))
                {
                    self.rack
                        .mark_scoreboard_losses(&self.scoreboard, self.mss as u32);
                    self.note_probe_loss(self.snd_una, self.rack.packet_counts().lost > 1);
                    self.start_sack_recovery();
                }
            }
        } else if duplicate {
            self.duplicate_acks = self.duplicate_acks.saturating_add(1);
            //= https://www.rfc-editor.org/rfc/rfc3042#section-2
            //= reason=Non-SACK first two consecutive duplicates grant fresh output; advancing/ineligible ACKs reset the epoch. Wire tests assert fresh sequence, one packet per grant, cwnd invariance, and denial with exhausted window or queue. Negotiated SACK uses RFC6675 SetPipe, not a claim of one output packet per SACK ACK.
            //# When a TCP sender has previously unsent data queued for transmission it SHOULD use the
            //# Limited Transmit algorithm, which calls for a TCP sender to transmit new data upon the
            //# arrival of the first two consecutive duplicate ACKs when the following conditions are
            //# satisfied:
            // RFC 5681 limited transmit: one new segment on each of the first
            // two duplicate ACKs, bounded by cwnd + 2 MSS and the peer window.
            self.limited_pending =
                self.duplicate_acks <= 2 && (!self.sack_receive || sack_evidence);
            if self.duplicate_acks == 3 {
                self.note_probe_loss(self.snd_una, false);
            }
            let probe = self.pmtud.as_ref().and_then(|p| p.eligible_probe_loss());
            if self.congestion.on_duplicate_ack_with_probe(
                ack,
                self.data_flight().saturating_sub(self.limited_sent),
                self.data_high(),
                ece,
                probe,
            ) {
                self.loss_events.reno_recoveries += 1;
                if self.config.prr {
                    self.prr = Some(Prr::new(self.data_flight(), self.mss as u32));
                }
                self.note_iw_loss(self.snd_una);
                self.note_probe_loss(self.snd_una, false);
                self.retx_pending = true;
                self.ecn_cwr_pending |= self.ecn_feedback();
                self.limited_pending = false;
            }
        } else if !advancing {
            self.reset_limited_transmit();
            self.congestion.reset_duplicate_acks();
        }
        let (new_response, rack_loss) = self.detect_rack();
        if self.congestion.in_recovery() || self.prr.is_some() || tlp_reduced {
            self.growth_dupack_bytes = 0;
        }
        let ecn_loss_takeover = ecn_prr_was_active
            && self.congestion.ecn_prr_end().is_none()
            && self.congestion.in_recovery();
        let new_response = new_response || ecn_loss_takeover;
        further_loss |= rack_loss;
        let mut started_ecn_prr = false;
        if let Some((end, flight, target, target_mss)) = ecn_prr_entry
            && !self.congestion.in_recovery()
            && self.rack.valid()
            && self.sack_fallback.is_none()
            && self
                .congestion
                .start_ecn_prr(end, self.data_flight(), target, target_mss)
        {
            // The ending ACK is excluded even when it also caused the event.
            if self.snd_una.at_or_after(end) {
                self.congestion.complete_prr();
                self.prr = None;
            } else {
                self.prr = Some(Prr::new(flight, self.mss as u32));
                started_ecn_prr = true;
            }
        }
        // Outside recovery DeliveredData is deltaUNA, not RACK's detection
        // evidence (which can include SACKs). An ACK entering recovery uses
        // the pre-ACK scoreboard baseline; no earlier ACK is replayed.
        //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
        //= reason=Current entry ACK is processed; ending ACK clears PRR without running its per-ACK steps, before ordinary output. No deferred causative ACK replay; timer/default trace asserts that separately.
        //# On every ACK starting or during fast recovery, excluding the ACK that
        //# concludes a PRR episode, PRR executes the following steps.
        //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
        //= reason=Signed scoreboard delta prevents recounting SACKed bytes when cumulative ACK trims them; current advancing entry ACK and wrapped sequence space are asserted. Bare negotiated-SACK duplicates grant no estimates in rfc9937_negotiated_sack_bare_duplicates_do_not_estimate_delivery.
        //# With SACK, DeliveredData can be computed precisely as the
        //# change in SND.UNA, plus the signed change in quantity of data marked
        //# SACKed in the scoreboard.  Thus, in the special case when there are
        //# no SACKed sequence ranges in the scoreboard before or after the ACK,
        //# DeliveredData is the change in SND.UNA.
        //= https://www.rfc-editor.org/rfc/rfc9937#section-11.2
        //= reason=No PRR outside response; wire matrix asserts ordinary slow start and avoidance. strict_prr_default_timer_entry_and_current_ack_epoch asserts no pre-entry PRR/delivery replay; exit traces assert ordinary reduced-cwnd handoff.
        //# PRR does not modify
        //# the congestion control cwnd increase or decrease mechanisms outside
        //# of congestion control response episodes.
        let cumulative_delivery = self.snd_una.distance_from(delivery_una);
        if let Some(mut prr) = self.prr {
            let sackd_after = self.flight()
                - self
                    .scoreboard
                    .unsacked_bytes(self.snd_una, self.data_high());
            let sack_accounting = self.sack_recovery_enabled();
            let delivered = if !sack_accounting {
                prr.non_sack_delivery(cumulative_delivery, duplicate)
            } else {
                // Signed delta includes trimming of previously SACKed bytes.
                let delta = i64::from(cumulative_delivery) + i64::from(sackd_after)
                    - i64::from(sackd_before);
                debug_assert!(delta >= 0);
                delta.max(0) as u32
            };
            if sack_accounting && !started_ecn_prr && (!prr_was_active || new_response) {
                prr.include_entry_delivery(delivered);
            }
            if self.sack_recovery.is_none() && self.retx_pending {
                self.rack.mark_head_lost();
            }
            let pipe = self
                .sack_recovery
                .map_or_else(|| prr.non_sack_pipe(self.rack.pipe()), |r| r.pipe);
            // RFC6675 rescue selection is itself evidence of further loss.
            let rescue_indicated = !self.rack_enabled()
                && self.sack_recovery.is_some_and(|r| {
                    !r.entry_pending
                        && self
                            .next_seg_hole(r.high_rxt, self.mss as u32, false)
                            .is_none()
                        && !(self.send.len() > self.snd_nxt.distance_from(self.send_base) as usize
                            && self.snd_wnd > self.flight()
                            && self.fresh_send_allowance() != 0
                            && self.ecn_pause.is_none_or(|deadline| now >= deadline))
                        && r.rescue_rxt.is_none_or(|end| self.snd_una.after(end))
                        && self
                            .scoreboard
                            .tail_hole(self.snd_una, self.data_high(), self.mss as u32)
                            .is_some()
                });
            //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
            //= reason=strict_ack independently checks per-ACK byte window and credit; shrinking nonzero rwnd clips committed output without consuming unsent credit. Normal supported TCP window range is bounded by MAX_WINDOW.
            //# cwnd = inflight + SndCnt
            //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
            //= reason=Advancing ACKs receive the extra SMSS only when loss detection, pending retransmission and RFC6675 rescue selection indicate no further loss. Real advancing-loss/rescue ACK regressions in connection_output_tests compare the denied bonus against safe advancement and parsed output.
            //# SafeACK = (SND.UNA advances and no further loss indicated)
            let safe_ack = advancing && !further_loss && !self.retx_pending && !rescue_indicated;
            prr.acknowledge(delivered, pipe, self.congestion.recovery_target(), safe_ack);
            if delivered != 0 {
                self.congestion
                    .prr_window(pipe.saturating_add(prr.credit()));
            } else if !new_response
                && !ecn_reduced
                && let Some(window) = prr_window_before
            {
                // Ordinary Reno/NewReno accounting must not inflate/deflate
                // PRR's window on a zero-delivery ACK (including capped estimates).
                self.congestion.prr_window(window);
            }
            self.prr = Some(prr);
        }
        self.receive_text(seq, segment);
        // MSG_MORE is a per-call hint, unlike persistent TCP_CORK. Linux's
        // ACK-driven output uses socket Nagle policy, releasing a MORE tail
        // without inventing PUSH. Retain our existing Nagle flight rule.
        if advancing && self.more && !self.cork && (!self.config.nagle || self.flight() == 0) {
            self.release_corked();
        }
        self.arm_work();
        if advancing {
            self.schedule_tlp();
        }
        Ok(())
    }

    fn data_high(&self) -> Seq {
        self.fin_sequence.unwrap_or(self.snd_nxt)
    }

    fn ack_growth_discount(&mut self, ack: Seq, sack_allowed: bool) -> u32 {
        let start = self.send_base;
        let end = if ack.after(self.data_high()) {
            self.data_high()
        } else {
            ack
        };
        if !end.after(start) {
            return 0;
        }
        let cumulative = end.distance_from(start);
        let eligible = self.congestion.growth_prefix(start, cumulative);
        if sack_allowed {
            // Only advice inside the actual eligible prefix can discount it.
            // A SACKed tail beyond a historical full flight is irrelevant.
            eligible
                - self
                    .scoreboard
                    .unsacked_bytes(start, start.wrapping_add(eligible))
        } else if !self.sack_receive {
            // Consume estimates by bytes, even on divided ACKs or when growth
            // is disallowed. Unknown delivery positions are treated conservatively.
            let estimated = cumulative.min(self.growth_dupack_bytes);
            self.growth_dupack_bytes -= estimated;
            eligible.min(estimated)
        } else {
            0 // SACK fallback does not invent duplicate-ACK delivery estimates.
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
    //= reason=Explicit before-ACK/after-ACK/after-output cwnd invariance for first two ordinary duplicates; sack_limited_transmit_requires_new_evidence_including_duplex_ack asserts SACK invariance and evidence gating separately.
    //# Further, the TCP sender MUST NOT change cwnd to reflect these two segments [RFC3042].
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
    //= reason=Actual fourth eligible duplicate grants one fresh SMSS, with sequence and payload assertions; exhausted cwnd and rwnd independently deny further output.
    //# When previously unsent data is available and the new value of cwnd and the receiver's
    //# advertised window allow, a TCP SHOULD send 1*SMSS bytes of previously unsent data.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-2
    //= reason=Integrated outstanding-data, empty-payload, SYN/FIN, cumulative-equality and unchanged/nonzero-window predicate matrix; advancing and data-bearing ACKs reset duplicate count, and the third eligible duplicate repairs current UNA.
    //# DUPLICATE ACKNOWLEDGMENT: An acknowledgment is considered a "duplicate" in the following
    //# algorithms when (a) the receiver of the ACK has outstanding data, (b) the incoming
    //# acknowledgment carries no data, (c) the SYN and FIN bits are both off, (d) the acknowledgment
    //# number is equal to the greatest acknowledgment received on the given connection (TCP.UNA from
    //# [RFC793]) and (e) the advertised window in the incoming acknowledgment equals the advertised
    //# window in the last incoming acknowledgment.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
    //= reason=Integrated advancing/ineligible ACK reset trace denies premature retransmission and checks repair sequence at the third eligible duplicate after reset. Initial NewReno guard is separately asserted, not waived as a duplicate-eligibility exception.
    //# The fast retransmit algorithm uses the arrival of 3 duplicate ACKs (as defined in section 2,
    //# without any intervening ACKs which move SND.UNA) as an indication that a segment has been lost.
    //# After receiving 3 duplicate ACKs, TCP performs a retransmission of what appears to be the
    //# missing segment, without waiting for the retransmission timer to expire.
    //= https://www.rfc-editor.org/rfc/rfc3042#section-2
    //= reason=Reset consecutive duplicate/grant state on advancing or ineligible ACKs, ECN/RTO and SACK overflow. duplicate_ack_eligibility_and_intervening_advancement_reset asserts no premature third-ACK repair; outstanding limited_sent retention after partial cumulative ACK is separately RFC5681 evidence.
    //# When a TCP sender has previously unsent data queued for transmission it SHOULD use the
    //# Limited Transmit algorithm, which calls for a TCP sender to transmit new data upon the
    //# arrival of the first two consecutive duplicate ACKs when the following conditions are
    //# satisfied:
    fn reset_limited_transmit(&mut self) {
        self.duplicate_acks = 0;
        self.limited_pending = false;
        self.limited_sent = 0;
        self.limited_end = None;
    }

    // ponytail: one update per causal RTT, not per packet. Fixed RFC6298 weights
    // retain round history even under ACK compression or arbitrarily dense SACKs.
    // RFC6298's many-per-window suggestion trades aliasing for history loss here;
    // use rate-adjusted weights only if per-packet RTO sampling becomes necessary.
    // The ledger keeps in-flight candidates, so output need not rearm a timer.
    fn update_rtt(&mut self, sample: u64) -> bool {
        let sent = self.now.saturating_sub(sample);
        if self.rtt_sample_after.is_some_and(|after| sent < after) {
            return false;
        }
        self.rtt.sample(sample);
        self.rtt_sample_after = Some(self.now.saturating_add(u64::from(sample == 0)));
        self.tlp_fresh_rtt = true;
        true
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= reason=Partial cumulative ACK removes only covered bytes and reports progress; future ACK rejection additionally in rfc5961_ack_bounds_are_inclusive_and_reject_all_incoming_side_effects.
    //# If SND.UNA < SEG.ACK =< SND.NXT, then set SND.UNA <- SEG.ACK. Any segments on the
    //# retransmission queue that are thereby entirely acknowledged are removed. Users should
    //# receive positive acknowledgments for buffers that have been SENT and fully acknowledged
    //# (i.e., SEND buffer should be returned with "ok" response). If the ACK is a duplicate
    //# (SEG.ACK =< SND.UNA), it can be ignored. If the ACK acks something not yet sent (SEG.ACK
    //# > SND.NXT), then send an ACK, drop the segment, and return.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-8
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Only validated cumulative ACK calls SendBuffer::acknowledge; test asserts 1024 bytes retained across selective recovery and zero only after full ACK.
    //# Since the data receiver may later discard data reported in a SACK option,
    //# the sender MUST NOT discard data before it is acknowledged by the
    //# Acknowledgment Number field in the TCP header.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. SACK updates never release send bytes; cumulative ACK is the release path and is asserted separately.
    //# Note: SACK information is advisory and therefore SACKed data MUST NOT be
    //# removed from the TCP's retransmission buffer until the data is cumulatively
    //# acknowledged [RFC2018].
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Cumulative ACK resets duplicate counter before new SACK evidence increments it; test explicitly observes count one after advancing ACK.
    //# If the incoming ACK is a cumulative acknowledgment, the TCP MUST reset
    //# DupAcks to zero.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Byte buffer is retained across SACKs and released only by cumulative ACK.
    //# A segment will not be dequeued and its buffer freed until the left window
    //# edge is advanced over it.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Validated advancing ACK sample from ordinary estimator also updates Rack::sample.
    //# Use the RTT measurements obtained via [RFC6298] or [RFC7323] to
    //# update the estimated minimum RTT in RACK.min_RTT.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-1
    //= reason=Default/configured >=1s timing evidence; subsecond compatibility is a scoped departure, not universal MUST conformance. Validated advancing cumulative ACK; updates eligible sample, then disables RTO for zero flight or restarts at now+current RTO. Zero-window arm_work can select persist; SACK/RACK delivery alone is not cumulative ACK progress.
    //# However, a TCP MUST NOT be more aggressive than the following algorithms allow.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-3
    //= reason=Validated advancing cumulative ACK; updates eligible sample, then disables RTO for zero flight or restarts at now+current RTO. Zero-window arm_work can select persist; SACK/RACK delivery alone is not cumulative ACK progress.
    //# TCP MUST use Karn's algorithm [KP87] for taking RTT samples.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-3
    //= reason=Validated advancing cumulative ACK; updates eligible sample, then disables RTO for zero flight or restarts at now+current RTO. Zero-window arm_work can select persist; SACK/RACK delivery alone is not cumulative ACK progress.
    //# That is, RTT samples MUST NOT be made using segments that were retransmitted (and thus
    //# for which it is ambiguous whether the reply was for the first instance of the packet
    //# or a later instance).
    //= https://www.rfc-editor.org/rfc/rfc6298#section-3
    //= reason=Continuous sliding flights use complete unambiguous local ledger candidates even without fresh output; actual update counts cover delayed/stretched ACKs and same-millisecond reuse. All-invalid echo flights with/without RACK assert identical local-clock estimator histories for differing forgeries. RTTM still validates TSecr; independent local timing never uses it, and Karn-ambiguous originals remain excluded.
    //# A TCP implementation MUST take at least one RTT measurement per RTT (unless that is
    //# not possible per Karn's algorithm).
    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= reason=Partial evidence only; TODO remains. Validated advancing cumulative ACK; updates eligible sample, then disables RTO for zero flight or restarts at now+current RTO. Zero-window arm_work can select persist; SACK/RACK delivery alone is not cumulative ACK progress.
    //# An implementation MUST manage the retransmission timer(s) in such a way that a segment
    //# is never retransmitted too early, i.e., less than one RTO after the previous
    //# transmission of that segment.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= reason=Partial evidence only; TODO remains. Validated advancing cumulative ACK; updates eligible sample, then disables RTO for zero flight or restarts at now+current RTO. Zero-window arm_work can select persist; SACK/RACK delivery alone is not cumulative ACK progress.
    //# The following is the RECOMMENDED algorithm for managing the retransmission timer:
    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= reason=Partial evidence only; TODO remains. Validated advancing cumulative ACK; updates eligible sample, then disables RTO for zero flight or restarts at now+current RTO. Zero-window arm_work can select persist; SACK/RACK delivery alone is not cumulative ACK progress.
    //# (5.7) If the timer expires awaiting the ACK of a SYN segment and the TCP
    //# implementation is using an RTO less than 3 seconds, the RTO MUST be re-initialized to
    //# 3 seconds when data transmission begins (i.e., after the three-way handshake
    //# completes).
    //= https://www.rfc-editor.org/rfc/rfc6298#section-3
    //= reason=Conservative one-per-causal-RTT policy intentionally declines suggested many-per-window samples: RFC7323 section4.2 reports limited RTO benefit and fixed-weight history truncation. Large sliding flights and dense SACK delivery count one actual estimator update per round; rate-adjusted weights would be required before increasing rate.
    //# However, when using the timestamp option, each ACK can be used as an RTT sample. RFC
    //# 1323 [JBB92] suggests that TCP connections utilizing large congestion windows should
    //# take many RTT samples per window of data to avoid aliasing effects in the estimated
    //# RTT.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= reason=Validated advancing cumulative ACK; updates eligible sample, then disables RTO for zero flight or restarts at now+current RTO. Zero-window arm_work can select persist; SACK/RACK delivery alone is not cumulative ACK progress.
    //# (5.2) When all outstanding data has been acknowledged, turn off the retransmission
    //# timer.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= reason=Partial evidence only; TODO remains. Validated advancing cumulative ACK; updates eligible sample, then disables RTO for zero flight or restarts at now+current RTO. Zero-window arm_work can select persist; SACK/RACK delivery alone is not cumulative ACK progress.
    //# (5.3) When an ACK is received that acknowledges new data, restart the retransmission
    //# timer so that it will expire after RTO seconds (for the current value of RTO).
    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= reason=Validated advancing cumulative ACK; updates eligible sample, then disables RTO for zero flight or restarts at now+current RTO. Zero-window arm_work can select persist; SACK/RACK delivery alone is not cumulative ACK progress.
    //# Note that after retransmitting, once a new RTT measurement is obtained (which can only
    //# happen when new data has been sent and acknowledged), the computations outlined in
    //# Section 2 are performed, including the computation of RTO, which may result in
    //# "collapsing" RTO back down after it has been subject to exponential back off (rule
    //# 5.5).
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=NewReno partial ACK schedules retx_pending; committed output starts at snd_una. newreno_partial_ack_wire_timer_and_exit_boundaries asserts each missing sequence/payload, continued recovery and failed-output rollback, including wrap.
    //# In this case, retransmit the first unacknowledged segment.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=Selected RFC6298 restart-on-every-advancing-ACK variant, not RFC3782 first-only variant. newreno_partial_ack_wire_timer_and_exit_boundaries asserts first/later partial deadlines=ACKtime+RTO, duplicate nonrestart and committed retransmission rearm.
    //# For the first partial ACK that arrives during fast recovery, also reset the retransmit
    //# timer.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= reason=Both initial-window policies, active and passive handshakes: accept_ack suppresses congestion growth for SYN ACK; test compares unchanged active/passive cwnd after handshake. No claim about IW formula correctness.
    //# As specified in [RFC3390], the SYN/ACK and the acknowledgment of the SYN/ACK MUST NOT
    //# increase the size of the congestion window.
    //= https://www.rfc-editor.org/rfc/rfc6928#section-2
    //= reason=IW10 first data-flight bound and handshake no-growth: negotiation test checks cwnd after active/passive handshake; idle/data-RTO trace emits exactly ten MSS before blocking. IW10 first-retry relaxation and bounded loss fallback are covered separately; no deployment monitoring claim.
    //# This change applies to the initial window of the connection in the first round-trip time
    //# (RTT) of data transmission during or following the TCP three-way handshake. Neither the
    //# SYN/ACK nor its ACK in the three-way handshake should increase the initial window size.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= reason=Connection ACK parsing frees only new cumulative payload bytes, with one-byte division and delayed cumulative ACK byte ledger through wrap; data_flight_excludes_control_and_retains_sacked_payload separately excludes FIN ACK growth and SACK-only release.
    //# where N is the number of previously unacknowledged bytes acknowledged in the incoming ACK.
    //= https://www.rfc-editor.org/rfc/rfc6928#section-9
    //= reason=IW10 divided/delayed new ACKs with outstanding flight restart at ACKtime+current RTO after estimator update; duplicate ACK does not restart, last new ACK cancels. RFC6298 universal timing audit remains separate.
    //# To minimize spurious retransmissions, implementations MUST follow RFC 6298 [RFC6298] to restart the retransmission timer with the current value of RTO for each ACK received that acknowledges new data.
    fn accept_ack(
        &mut self,
        ack: Seq,
        ece: bool,
        echo: Option<u32>,
        send_window: u32,
        response_handshake: bool,
        growth_discount: u32,
    ) {
        if !response_handshake {
            self.congestion.observe_ack_advance(self.snd_una, ack);
        }
        let syn_ack = self.snd_una == self.iss && self.handshake_pending();
        // A split handshake ACK owns one PMTU observation, at its actual full ACK.
        if self.pmtud.is_some() && !(response_handshake && syn_ack) {
            let cooldown = self.pmtu_cooldown();
            let rto = self.rto();
            self.pmtud
                .as_mut()
                .unwrap()
                .ack(ack, self.now, cooldown, rto);
            self.observe_pmtud_results();
            self.refresh_path_mss();
        }
        // When the ledger is available, only its newly delivered complete
        // original qualifies. A scalar RTTM pending across a SACK must not
        // count that same transmission again on its later cumulative ACK.
        let startup_scalar_allowed = !self.rack.valid();
        if syn_ack {
            self.syn_delivered = true;
            self.syn_data_acked |=
                self.syn_payload_sent != 0 && ack.after(self.iss.wrapping_add(1));
            self.syn_data_fully_acked |= self.syn_payload_sent != 0
                && ack.at_or_after(self.iss.wrapping_add(1 + self.syn_payload_sent as u32));
        }
        if self.fin_needs_separate_credit && self.fin_sequence.is_some_and(|fin| ack.after(fin)) {
            self.fin_delivered = true;
        }
        if !self.sack_receive || self.handshake_pending() {
            self.rack.acknowledge(
                ack,
                self.data_high(),
                &mut self.scoreboard,
                self.now,
                echo.map(|value| value.wrapping_sub(self.timestamp_offset)),
                self.timestamps.then_some(self.config.timestamp_granularity),
                self.mss as u32,
                false,
            );
        }
        // Timestamp storage follows cumulative send-buffer reclamation even
        // while SACK inference is suspended below its fallback boundary.
        self.rack.trim_cumulative(ack);
        let limited = self
            .limited_end
            .filter(|&end| self.sack_recovery_enabled() && end.after(ack))
            .map(|end| (end, self.limited_sent.min(end.distance_from(ack))));
        self.reset_limited_transmit();
        if let Some((end, bytes)) = limited {
            self.limited_end = Some(end);
            self.limited_sent = bytes;
        }
        if !syn_ack
            && let Some(epoch) = &mut self.iw_epoch
            && epoch.fresh_start.is_some_and(|start| ack.after(start))
        {
            // Only cumulative progress into ordinary fresh data validates
            // this burst; a probe-only ACK leaves its accounting open.
            epoch.open = false;
        }
        let bytes = ack
            .distance_from(self.send_base)
            .min(self.send.len() as u32);
        let bytes = if ack.at_or_after(self.send_base) {
            bytes
        } else {
            0
        };
        self.ptb_acknowledged(ack, bytes as usize);
        if bytes != 0 {
            self.initial_pacing_open = false;
            self.send
                .acknowledge(bytes as usize)
                .expect("ACK is bounded by sent sequence space");
            if self.send_space_remaining() != 0 {
                self.send_backpressured = false;
            }
            self.send_base = self.send_base.wrapping_add(bytes);
            self.acknowledged = self.acknowledged.saturating_add(bytes as u64);
            self.events.acknowledged = Some(self.acknowledged);
            self.tx_timestamps.observe(
                TxStreamRange {
                    start: 0,
                    end: self.acknowledged,
                },
                TxTimestampStage::Acknowledged,
                TxTimestampSource::Software,
                self.now,
                TxTimestampClock::CallerTicks(self.config.timebase),
            );
            if !self.shutdown && self.send_space_remaining() != 0 {
                self.events.writable = true;
            }
        }
        self.snd_una = ack;
        if let Some((start, end)) = self.fast_open_retry {
            self.fast_open_retry = if ack.at_or_after(end) {
                None
            } else {
                Some((if ack.after(start) { ack } else { start }, end))
            };
        }
        if self.sack_guard.is_some_and(|end| ack.at_or_after(end)) {
            self.sack_guard = None;
            self.sack_post_rto = None;
        }
        if !self.sack_recovery_enabled()
            && self
                .sack_post_rto
                .is_some_and(|(_, boundary)| ack.at_or_after(boundary))
        {
            self.sack_post_rto = None;
        }
        if self.sack_fallback.is_some_and(|end| ack.at_or_after(end)) {
            self.sack_fallback = None;
        }

        if self.snd_up.is_some_and(|end| ack.at_or_after(end)) {
            self.snd_up = None;
        }
        if self
            .advertised_snd_up
            .is_some_and(|end| ack.at_or_after(end))
        {
            self.advertised_snd_up = None;
        }
        self.progress_at = self.now;
        self.application_progress_at = self.now;
        self.resource_probes = 0;
        self.local_resource = None;
        self.consecutive_timeouts = 0;
        self.retx_pending = false;
        let mut startup_rtt = None;
        if let Some((end, sent)) = self.sample
            && ack.at_or_after(end)
        {
            // One bounded sample per flight. Never infer a transmission time
            // from an unvalidated echo, and retain Karn's exclusion on retransmit.
            //= https://www.rfc-editor.org/rfc/rfc7323#section-4.1
            //= reason=Matching TSecr on duplicate and SACK-only ACK cannot consume/update the ordinary pending RTTM sample or advance UNA. Under negotiated TS, original-transmission RACK samples now-minus-local-send-time independently of matching/forged TSecr; only RACK-enabled connections feed that separate sample into RTO.
            //# RTTM Rule: A TSecr value received in a segment MAY be used to update
            //# the averaged RTT measurement only if the segment advances
            //# the left edge of the send window, i.e., SND.UNA is
            //# increased.
            //= https://www.rfc-editor.org/rfc/rfc7323#section-4.2
            //= reason=Ordinary RTTM and local-clock RACK delivery share a causal-round gate: next eligible original must be sent at or after the prior sampling ACK. Continuous sliding, delayed/stretched and same-tick flights count actual updates; dense SACK and mixed cumulative delivery retain exact RFC6298 history. Conservative one-per-RTT sampling avoids fixed-weight history truncation; Appendix G and many-per-window sampling are suggestions, not mandatory formulas.
            //# to update the RTT estimator, an implementation SHOULD try to adhere
            //# to the spirit of the history specified in [RFC6298].
            if (!response_handshake || syn_ack)
                && (!self.timestamps || echo == Some(self.timestamp_value(sent)))
            {
                let sample = self
                    .now
                    .saturating_sub(self.sample_departure.unwrap_or(sent));
                startup_rtt = Some(sample);
                let updated = self.update_rtt(sample);
                self.rack.sample(sample, self.now);
                if updated && !syn_ack {
                    self.syn_timed_out = false;
                }
            }
            self.sample = None;
        }
        // A covered/mismatched pending RTTM must not starve the remaining flight.
        // The ledger candidate is a complete, never-retransmitted original
        // measured on the local clock, regardless of the loss-recovery algorithm.
        // Unlike RTTM above, it uses no peer echo, valid or otherwise.
        // The SYN scalar owns handshake RTT: payload must not sample twice or
        // bypass a rejected echo/Karn gate when that ACK also covers SYN data.
        // The split passive response ACK retains this rule through its data step.
        if let Some(sample) = self.rack.ack_sample
            && !syn_ack
            && !response_handshake
            && self.update_rtt(sample)
        {
            self.syn_timed_out = false;
        }
        if !syn_ack {
            // send_base is the cumulative DATA edge (unlike SEG.ACK it excludes
            // an acknowledged FIN), matching the successful-output data marker.
            //= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
            //= reason=CUBIC receives freshly updated RFC6298 SRTT in caller ticks; raw HyStart RTT is forwarded separately.
            //# *  _RTT_: Smoothed round-trip time in seconds, calculated as
            //# described in [RFC6298].
            self.congestion.prepare_ack(
                self.now,
                self.rtt.srtt(),
                self.send_base,
                bytes,
                send_window,
            );
            self.congestion.discount_ack_growth(growth_discount);
            // Consume at most one fresh raw candidate, independent of the
            // causal-round gate used by the fixed-weight RTO estimator. RACK's
            // ledger excludes incomplete/retransmitted/previously delivered
            // originals even when time-based loss detection is disabled.
            self.congestion
                //= https://www.rfc-editor.org/rfc/rfc9406#section-4.3
                //= reason=At most one fresh original-delivery RTT per ACK, independent of RTO estimator gating; Karn-safe scalar fallback only without original-send ledger coverage. Retransmitted/incomplete/cached candidates are excluded.
                //# While all TCP implementations are REQUIRED to take at least one RTT
                //# sample each round, implementations of HyStart++ are RECOMMENDED to
                //# take at least N_RTT_SAMPLE RTT samples.
                .prepare_startup_ack(crate::hystart::StartupAck {
                    rtt: self
                        .rack
                        .ack_sample
                        .or(startup_rtt.filter(|_| startup_scalar_allowed))
                        .filter(|_| !response_handshake),
                    snd_nxt: self.snd_nxt,
                    paced: self.pacing_enabled(),
                });
        }
        if !syn_ack
            && self
                .congestion
                .on_ack_with_ecn(ack, bytes, self.data_flight(), ece)
        {
            self.note_probe_loss(ack, false);
            self.retx_pending = true;
        }
        self.rto_deadline = if self.flight() == 0 {
            if self.snd_wnd == 0 && self.persist_interval != 0 {
                self.persist_deadline = self.rto_deadline;
            }
            None
        } else {
            Some(self.now.saturating_add(self.rto()))
        };
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
        //# if the FIN segment is now acknowledged, then enter FIN- WAIT-2 and continue
        //# processing in that state.
        if self.fin_sequence.is_some_and(|fin| ack.after(fin)) {
            match self.state {
                State::FinWait1 => self.state = State::FinWait2,
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
                //# if the ACK acknowledges our FIN, then enter the TIME-WAIT state;
                //# otherwise, ignore the segment.
                State::Closing => self.time_wait(),
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
                //= reason=Terminal connection storage is reclaimed by Endpoint release, not by this transition.
                //# If our FIN is now acknowledged, delete the TCB, enter the CLOSED
                //# state, and return.
                State::LastAck => self.terminal(CloseReason::Normal),
                _ => {}
            }
        }
    }

    fn receive_window(&self) -> u32 {
        let width = self.advertised_edge.distance_from(self.receive.next());
        if width < 1 << 31 { width } else { 0 }
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //# This should not occur since a FIN has been received from the remote side. Ignore
    //# the segment text.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= reason=Focused edge test covers duplicate-prefix and out-of-window suffix trimming, wrap and zero-window rejection.
    //# If a segment's contents straddle the boundary between old and new, only the new parts
    //# are processed.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= reason=Closing-state test additionally checks URG after FIN cannot advance the urgent endpoint.
    //# This should not occur since a FIN has been received from the remote side. Ignore the
    //# URG.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= reason=RCV.NXT reflects accepted contiguous bytes and advertised credit; scaled rounding exception scoped in existing SHLD-14 evidence.
    //# Once the TCP endpoint takes responsibility for the data, it advances RCV.NXT over the
    //# data accepted, and adjusts RCV.WND as appropriate to the current buffer availability.
    //# The total of RCV.NXT and RCV.WND should not be reduced.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= reason=FIN advances receive sequence and half_closed event, sends ACK, preserves buffered bytes for subsequent read.
    //# If the FIN bit is set, signal the user "connection closing" and return any pending
    //# RECEIVEs with same message, advance RCV.NXT over the FIN, and send an acknowledgment for
    //# the FIN. Note that FIN implies PUSH for any segment text not yet delivered to the user.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= reason=Unacknowledged local FIN enters CLOSING; fin_half_close_time_wait_and_duplicate_fin_restart covers acknowledged branch and timer cancellation.
    //# If our FIN has been ACKed (perhaps in this segment), then enter TIME-WAIT, start the
    //# time-wait timer, turn off the other timers; otherwise, enter the CLOSING state.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-4
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Ordinary reordered arrivals schedule immediate ACKs, output includes retained ranges; tests parse emitted ACKs.
    //# If the data receiver generates SACK options under any circumstance, it
    //# SHOULD generate them under all permitted circumstances.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-4
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Ordinary reordered arrivals schedule immediate ACKs, output includes retained ranges; tests parse emitted ACKs.
    //# If sent at all, SACK options SHOULD be included in all ACKs which do not ACK
    //# the highest sequence number in the data receiver's queue.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-4
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Ordinary reordered arrivals schedule immediate ACKs, output includes retained ranges; tests parse emitted ACKs.
    //# The receiver SHOULD send an ACK for every valid segment that arrives
    //# containing new data, and each of these "duplicate" ACKs SHOULD bear a SACK
    //# option.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-5
    //= reason=newreno_partial_ack_wire_timer_and_exit_boundaries asserts immediate ACK pending and no delayed deadline for OOO pure data and hole-fill partial ACKs, with other pure-data holes still outstanding.
    //# [RFC5681] specifies that "Out-of-order data segments SHOULD be acknowledged
    //# immediately, in order to accelerate loss recovery".
    //= https://www.rfc-editor.org/rfc/rfc6582#section-5
    //= reason=newreno_partial_ack_wire_timer_and_exit_boundaries receives pure-data hole fills while another hole remains, asserts ack_pending and ack_deadline=None despite delayed ACK enabled, and immediately emits cumulative partial ACKs.
    //# Echoing [RFC5681], our recommendation is that the data receiver send an immediate
    //# acknowledgment for an out-of-order segment, even when that out-of-order segment fills
    //# a hole in the buffer.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
    //= reason=Receiver ACK scheduling applies regardless of sender recovery choice; SACK receive trace polls immediate ACK after reordered data and full gap fill and checks cumulative sequence. Partial-only gap fill is asserted by partial_gap_ack_is_immediate_and_output_is_coalesced.
    //# A TCP receiver SHOULD send an immediate duplicate ACK when an out- of-order segment
    //# arrives.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
    //= reason=Receiver role, all recovery profiles. Default 200ms timer; configuration rejects >=500ms. Existing tests assert no early output, timeout at first packet+200ms, and immediate second full-RMSS ACK; caller must service scheduled timeout/poll. Not a guarantee when host ignores deadlines.
    //# The delayed ACK algorithm specified in [RFC1122] SHOULD be used by a TCP receiver.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
    //= reason=Receiver role, all recovery profiles. Default 200ms timer; configuration rejects >=500ms. Existing tests assert no early output, timeout at first packet+200ms, and immediate second full-RMSS ACK; caller must service scheduled timeout/poll. Not a guarantee when host ignores deadlines.
    //# When using delayed ACKs, a TCP receiver MUST NOT excessively delay acknowledgments.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
    //= reason=Receiver role, all recovery profiles. Default 200ms timer; configuration rejects >=500ms. Existing tests assert no early output, timeout at first packet+200ms, and immediate second full-RMSS ACK; caller must service scheduled timeout/poll. Not a guarantee when host ignores deadlines.
    //# Specifically, an ACK SHOULD be generated for at least every second full-sized segment,
    //# and MUST be generated within 500 ms of the arrival of the first unacknowledged packet.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
    //= reason=Receiver role, all recovery profiles. Default 200ms timer; configuration rejects >=500ms. Existing tests assert no early output, timeout at first packet+200ms, and immediate second full-RMSS ACK; caller must service scheduled timeout/poll. Not a guarantee when host ignores deadlines.
    //# Finally, we repeat that an ACK MUST NOT be delayed for more than 500 ms waiting on a
    //# second full-sized segment to arrive.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
    //= reason=Receiver scheduling after reorder/full gap fill is directly observed in SACK wire trace, with expected cumulative ACK sequence. Applies regardless of local sender recovery profile; partial-only gap fill is asserted by partial_gap_ack_is_immediate_and_output_is_coalesced.
    //# Out-of-order data segments SHOULD be acknowledged immediately, in order to accelerate
    //# loss recovery.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
    //= reason=Receiver scheduling after reorder/full gap fill is directly observed in SACK wire trace, with expected cumulative ACK sequence. Applies regardless of local sender recovery profile; partial-only gap fill is asserted by partial_gap_ack_is_immediate_and_output_is_coalesced.
    //# To trigger the fast retransmit algorithm, the receiver SHOULD send an immediate
    //# duplicate ACK when it receives a data segment above a gap in the sequence space.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
    //= reason=Actual output counts after delayed data, piggyback reply and deadline/second-packet races; partial_gap_ack_is_immediate_and_output_is_coalesced covers gap and partial-fill immediate feedback. No receive-credit update is counted as a data ACK.
    //# A TCP receiver MUST NOT generate more than one ACK for every incoming segment, other than to
    //# update the offered window as the receiving application consumes new data (see [RFC813] and page
    //# 42 of [RFC793]).
    //= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
    //= reason=Newly received small segments now count toward second-segment feedback regardless of RMSS, without changing PMTU or MSS. Both small-segment tests assert immediate second ACK, transactional failed output, piggyback reset and RMSS-sized feedback; operative delayed timer is separately asserted.
    //# In some cases, the sender and receiver may not agree on what constitutes a full-sized segment.
    //# An implementation is deemed to comply with this requirement if it sends at least one
    //# acknowledgment every time it receives 2*RMSS bytes of new data from the sender, where RMSS is
    //# the Maximum Segment Size specified by the receiver to the sender (or the default value of 536
    //# bytes, per [RFC1122], if the receiver does not specify an MSS option during connection
    //# establishment). The sender may be forced to use a segment size less than RMSS due to the
    //# maximum transmission unit (MTU), the path MTU discovery algorithm or other factors. For
    //# instance, consider the case when the receiver announces an RMSS of X bytes but the sender ends
    //# up using a segment size of Y bytes (Y < X) due to path MTU discovery (or the sender's MTU
    //# size). The receiver will generate stretch ACKs if it waits for 2*X bytes to arrive before an
    //# ACK is sent. Clearly this will take more than 2 segments of size Y bytes. Therefore, while a
    //# specific algorithm is not defined, it is desirable for receivers to attempt to prevent this
    //# situation, for example, by acknowledging at least every second segment, regardless of size.
    //# Finally, we repeat that an ACK MUST NOT be delayed for more than 500 ms waiting on a second
    //# full-sized segment to arrive.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
    //= reason=Non-SACK and SACK receivers immediately emit cumulative ACKs after only part of an existing gap is filled, and after full fill; each input produces at most one committed ACK.
    //# In addition, a TCP receiver SHOULD send an immediate ACK when the incoming segment fills in all
    //# or part of a gap in the sequence space.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-4.2
    //= reason=Non-SACK and SACK receivers immediately emit cumulative ACKs after only part of an existing gap is filled, and after full fill; each input produces at most one committed ACK.
    //# To provide feedback to senders recovering from losses, the receiver SHOULD send an immediate
    //# ACK when it receives a data segment that fills in all or part of a gap in the sequence space.
    fn receive_text(&mut self, seq: Seq, segment: &Segment<'_>) {
        let payload = segment.payload;
        let flags = segment.header.flags & !SYN;
        let urgent = segment
            .header
            .urgent_pointer
            .saturating_sub(u16::from(segment.header.flags & SYN != 0));
        if !matches!(
            self.state,
            State::Established | State::FinWait1 | State::FinWait2
        ) {
            return;
        }
        let next = self.receive.next();
        let window = self.receive_window();
        if flags & URG != 0 && !self.read_closed {
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.5
            //# The urgent pointer MUST point to the sequence number of the octet
            //# following the urgent data (MUST-62).
            let end = seq.wrapping_add(urgent as u32);
            let delta = end.distance_from(next);
            // Inline urgent data, not a separate OOB byte. Absolute offsets
            // remain useful after TCP's 32-bit sequence space wraps.
            let absolute = if delta < 1 << 31 {
                Some(self.received_total.saturating_add(delta as u64))
            } else {
                self.received_total
                    .checked_sub(next.distance_from(end) as u64)
            };
            if let Some(end) = absolute
                && end > self.received_read
                && self.rcv_up.is_none_or(|old| end > old)
            {
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.5
                //# A TCP implementation MUST (MUST-32) inform the application layer
                //# asynchronously whenever it receives an urgent pointer and there was
                //# previously no pending urgent data, or whenever the urgent pointer
                //# advances in the data stream.
                self.rcv_up = Some(end);
                self.events.urgent = Some(end);
            }
        }
        let skip = if next.after(seq) {
            (next.distance_from(seq) as usize).min(payload.len())
        } else {
            0
        };
        let start = seq.wrapping_add(skip as u32);
        let offset = start.distance_from(next);
        let count = if offset < window {
            (payload.len() - skip).min((window - offset) as usize)
        } else {
            0
        };
        let fin_position = seq.wrapping_add(payload.len() as u32);
        let fin = flags & FIN != 0 && fin_position.in_window(next, window) == Some(true);
        if self.sack_send && (!payload.is_empty() || fin) {
            // A valid FIN-only arrival supersedes the previous duplicate report;
            // FIN itself is not a byte of data for D-SACK.
            self.receive.record_duplicate(seq, payload.len());
            self.sack_omit = false;
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
        //# Segments with higher beginning sequence numbers SHOULD be held for later
        //# processing (SHLD-31).
        let outcome = self.receive_payload(
            start,
            &payload[skip..skip + count],
            fin && skip + count == payload.len(),
            flags & PSH != 0 && skip + count == payload.len(),
        );
        self.receive_used += outcome.new_bytes;
        if outcome.new_bytes != 0 {
            self.last_data_received = self.now;
            let offer = self.receive_mss();
            let size = self
                .input_segment_size
                .map_or(payload.len(), |s| usize::from(s.get()));
            let terminal = flags & (PSH | FIN) != 0 && size == payload.len();
            self.received_mss.observe(size, terminal, offer);
            if self.input_segment_size.is_some() && payload.len() / size >= 2 {
                self.received_mss.observe(size, false, offer);
            }
        }
        if outcome.sack_overflow && self.sack_send {
            self.sack_omit = true;
            self.receive.clear_dsack();
        }
        if self.read_closed && outcome.new_bytes != 0 {
            self.events.readable = false;
            self.events.pushed = false;
            self.events.urgent = None;
            self.events.writable = false;
            // RFC 9293 3.6.1: new text after half-duplex CLOSE loses data.
            // This is a segment-triggered reset, not the local ABORT of 3.10.5.
            // PAWS, sequence, controls, handshake and ACK bounds were checked
            // before receive_text; use SEG.ACK (3.5.2) rather than SND.NXT so
            // an unacknowledged FIN does not shift the peer's reset sequence.
            self.pending_rst = Some((Seq(segment.header.acknowledgment), false));
            // RFC 7323 5.2: reactive RST uses TSval=0, TSecr=SEG.TSval.
            self.reset_echo = segment.options.timestamps.map(|ts| ts.0);
            self.reset_reply = true;
            self.receive.clear();
            self.rx_timestamps.clear();
            self.receive
                .reset_start(next)
                .expect("cleared receive buffer");
            self.receive_used = 0;
            // Aborted preserves the pending reset until successful output;
            // terminal cancels all ordinary output and timers.
            self.terminal(CloseReason::Aborted);
            return;
        }
        if self.config.adaptive_ack && outcome.new_bytes != 0 && outcome.advanced {
            self.adaptive_receive();
        }
        self.events.pushed |= self.receive.take_push();
        let advanced = self.receive.next().distance_from(next);
        self.received_total = self
            .received_total
            .saturating_add(advanced.saturating_sub(u32::from(outcome.fin)) as u64);
        if outcome.advanced {
            self.events.readable = !self.read_closed;
            if self.state == State::FinWait2 {
                self.progress_at = self.now;
            }
        }
        // A FIN that ends the peer's stream in ESTABLISHED leaves the
        // application to answer it, as a server does that closes on EOF, so
        // the adaptive engine turns interactive and delays its ACK for the
        // reply's FIN to carry, as Linux's tcp_fin enters pingpong mode on
        // the move to CLOSE-WAIT. Linux delays it by the delayed-ACK
        // engine's timeout, which stays zero until data first arrives
        // (tcp_event_data_recv), so a FIN on a connection that received none
        // is acknowledged at once, as is one in FIN-WAIT, which nothing
        // local follows (tcp_fin sends that ACK itself).
        let fin_awaits_reply = self.config.adaptive_ack
            && self.ack_engine_initialized
            && outcome.fin
            && self.state == State::Established;
        if fin_awaits_reply {
            self.ack_interactive = true;
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.3
        //# A TCP endpoint SHOULD implement a delayed ACK (SHLD-18), but an ACK should
        //# not be excessively delayed; in particular, the delay MUST be less than 0.5
        //# seconds (MUST-40).
        if !payload.is_empty() || flags & FIN != 0 {
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.3
            //# An ACK SHOULD be generated for at least every second full-sized segment
            //# or 2*RMSS bytes of new data (where RMSS is the MSS specified by the TCP
            //# endpoint receiving the segments to be acknowledged, or the default value
            //# if not specified) (SHLD-19).
            self.unacked_bytes = self
                .unacked_bytes
                .saturating_add(advanced.saturating_sub(u32::from(outcome.fin)));
            let rmss = self.receive_mss();
            if outcome.new_bytes != 0 {
                let segments = self
                    .input_segment_size
                    .filter(|_| {
                        skip == 0 && count == payload.len() && outcome.new_bytes == payload.len()
                    })
                    .map_or(1, |size| {
                        payload
                            .len()
                            .div_ceil(usize::from(size.get()))
                            .min(usize::from(u8::MAX)) as u8
                    });
                self.unacked_segments = self.unacked_segments.saturating_add(segments);
            }
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
            //# o A TCP implementation MAY send an ACK segment acknowledging RCV.NXT
            //# when a valid segment arrives that is in the window but not at the left
            //# window edge (MAY-13).
            if seq != next
                || outcome.out_of_order
                || self.receive.has_sack_blocks()
                || !outcome.advanced
                || advanced.saturating_sub(u32::from(outcome.fin)) as usize > count
                || (flags & FIN != 0 && !fin_awaits_reply)
                || self.receive_window() == 0
                || self.unacked_segments >= 2
                || self.unacked_bytes >= 2 * u32::from(rmss)
                || self.config.delayed_ack_us == 0
                || (self.config.adaptive_ack && self.ack_quick != 0 && !self.ack_interactive)
            {
                self.immediate_ack();
            } else if !self.ack_pending && self.ack_deadline.is_none() {
                self.ack_deadline = Some(self.now.saturating_add(if self.config.adaptive_ack {
                    self.ack_ato
                } else {
                    self.config
                        .timebase
                        .ticks_from_us(self.config.delayed_ack_us)
                }));
            }
        }
        if outcome.fin {
            self.events.half_closed = true;
            match self.state {
                State::Established => self.state = State::CloseWait,
                State::FinWait1 => self.state = State::Closing,
                State::FinWait2 => self.time_wait(),
                _ => {}
            }
        }
    }

    fn adaptive_receive(&mut self) {
        let min = self.config.ack_timeout_floor();
        let max = self
            .config
            .timebase
            .ticks_from_us(self.config.delayed_ack_us);
        if let Some((last, initialized)) = self.ack_receive
            && (initialized || self.ack_engine_initialized)
        {
            let gap = self.now.saturating_sub(last);
            if gap > self.rto() {
                self.ack_quick = self.adaptive_quick_budget();
                self.ack_interactive = false;
            } else if gap <= min / 2 {
                self.ack_ato = self.ack_ato / 2 + min / 2;
            } else if gap < self.ack_ato {
                self.ack_ato = (self.ack_ato / 2).saturating_add(gap);
            }
        } else {
            self.ack_ato = min;
            self.ack_quick = self.adaptive_quick_budget();
        }
        self.ack_ato = self.ack_ato.clamp(min, max);
        self.ack_receive = Some((self.now, true));
        self.ack_engine_initialized = true;
    }

    fn adaptive_departure(&mut self, data_ack: bool, fresh_data: bool) {
        if !self.config.adaptive_ack || self.reason.is_some() {
            return;
        }
        if data_ack {
            self.ack_quick = self.ack_quick.saturating_sub(1);
        }
        if fresh_data
            && self.ack_receive.is_some_and(|(last, initialized)| {
                (initialized || self.ack_engine_initialized)
                    && self.now.saturating_sub(last) < self.ack_ato
            })
        {
            self.ack_interactive = true;
        }
    }

    fn adaptive_quick_budget(&self) -> u8 {
        // Use the remaining local advertised byte window, not the peer's send credit.
        let budget = self.receive_window() / (2 * u32::from(self.receive_mss()));
        if budget == 0 { 2 } else { budget.min(16) as u8 }
    }

    fn receive_mss(&self) -> u16 {
        self.receive_mss_offer
    }

    fn window_threshold(&self) -> u32 {
        // RFC 9293 section 3.8.6.2.2: min(Fr * RCV.BUFF, Eff.snd.MSS), Fr = 1/2.
        (self.config.receive_capacity / 2).max(1).min(self.mss) as u32
    }

    fn read_window_threshold(&self) -> u32 {
        let shift = if self.scaling { self.local_scale } else { 0 };
        // A retained sub-scale promise can coexist with a zero wire window.
        // Do not make a stalled sender wait for the coalescing threshold.
        if !self.config.coalesce_read_window_updates || self.receive_window() < (1u32 << shift) {
            return self.window_threshold();
        }
        // Linux v6.12 __tcp_cleanup_rbuf: new_window >= 2 * rcv_window_now.
        // read() compares encodable new credit with the remaining window,
        // equivalently doubling without multiplication/overflow. Selection
        // still enforces RFC9293 3.8.6.2.2 / RFC1122 4.2.3.3 receiver SWS;
        // this only gates unsolicited read updates, not data/delayed ACKs.
        self.receive_window().max(1)
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.2.2
    //= reason=Window selection enforces receiver SWS independently of ACK scheduling; standalone read updates default to remaining-window doubling, with SWS-qualified zero/sub-scale reopening.
    //# A TCP implementation MUST include a SWS avoidance algorithm in the receiver
    //# (MUST-39).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1
    //= reason=Receive credit stays occupied until application reads, without a receiver-side reopening timer.
    //# A TCP implementation MAY keep its offered receive window closed indefinitely
    //# (MAY-8).
    //= https://www.rfc-editor.org/rfc/rfc7323#section-2.2
    //= reason=SYN windows are learned raw and advertised_window returns raw syn_window; ordinary ACK scaling is separate.
    //# The window field in a segment where the SYN bit is set (i.e., a <SYN>
    //# or <SYN,ACK>) MUST NOT be scaled.
    //= https://www.rfc-editor.org/rfc/rfc7323#section-2.3
    //= reason=Ordinary outgoing receive window divides by scale unit (floor), SYN is raw; backing and encoded edge tested through sub-scale advances.
    //# o  The window field (SEG.WND) of every outgoing segment, with the
    //# exception of <SYN> segments, MUST be right-shifted by
    //# Rcv.Wind.Shift bits:
    // Scope: Shrinking windows retain payload; original validity and retry coverage implement scaled first/sub-scale permission with conservative overflow fallback and separate persist.
    //= https://www.rfc-editor.org/rfc/rfc7323#section-2.4
    //= reason=Shrinking windows retain payload; capacity-backed original validity and retry coverage implement scaled first/sub-scale retry permission with conservative overflow fallback and separate persist behavior.
    //# Implementations MUST ensure that they handle a shrinking
    //# window, as specified in Section 4.2.2.16 of [RFC1122].
    //= https://www.rfc-editor.org/rfc/rfc7323#section-7
    //= reason=Receive window bounded by explicit configured receive allocation, never rounds beyond backing; no speculative unlimited window growth.
    //# Hence, implementers should take care to not open the TCP window
    //# drastically beyond the requirements of the connection.
    //= https://www.rfc-editor.org/rfc/rfc6928#section-3
    //= reason=Default storage advertises >=10 local RMSS on initial SYN/SYNACK; explicitly configured slow-link storage advertises <10. No bandwidth autodetection or deployment performance claim.
    //# Some implementations advertise a small initial receive window (Table 2 in [Duk10]), effectively limiting how much window a remote host may use. In order to realize the full benefit of the large initial window, implementations are encouraged to advertise an initial receive window of at least 10 segments, except for the circumstances where a larger initial window is deemed harmful. (See Section 8 below.)
    //= https://www.rfc-editor.org/rfc/rfc6928#section-8
    //= reason=Manual receive_capacity=4000 with local RMSS=1000 advertises four segments on both handshake directions; default capacity advertises >=10. Manual mitigation selected, no low-speed autodetection claim.
    //# The negative impact can be mitigated by hosts directly connected to a low-speed link advertising an initial receive window smaller than 10 segments. This can be achieved either through manual configuration by the users or through the host stack auto-detecting the low- bandwidth links.
    //= https://www.rfc-editor.org/rfc/rfc6429#section-1
    //# A TCP MAY keep its offered receive window closed indefinitely.
    fn advertised_window(&self, syn: bool) -> u16 {
        if syn {
            return self.syn_window;
        }
        if self.receive.eof() {
            return 0;
        }
        let shift = if self.scaling { self.local_scale } else { 0 };
        let unit = 1u32 << shift;
        let backing = self.receive.right_edge().distance_from(self.receive.next());
        let quota = self
            .config
            .receive_capacity
            .saturating_sub(self.receive.readable()) as u32;
        // Never retract credit already offered to the peer on shrink.
        let available = backing.min(quota.max(self.receive_window()));
        let old = self.receive_window();
        // Apply both wire limits before SWS avoidance, not just at encoding.
        let candidate = (available / unit).min(u32::from(u16::MAX));
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
        //= reason=Retains prior acceptance credit; RFC 7323 rounding can retract the encoded edge by less than one scale unit.
        //# A TCP receiver SHOULD NOT shrink the window, i.e., move the right window
        //# edge to the left (SHLD-14).
        // RFC 7323 section 2.4: sub-scale advances can require retraction
        // on the wire. Never round beyond backing storage; retain the old
        // promise separately so in-flight bytes remain acceptable.
        let old_field = old.div_ceil(unit).min(candidate);
        if candidate.saturating_mul(unit).saturating_sub(old) >= self.window_threshold() {
            candidate as u16
        } else {
            old_field as u16
        }
    }

    fn post_rto_pipe(&self) -> u32 {
        if self.rack_enabled() {
            return self.rack.pipe();
        }
        let Some((high_rxt, boundary)) = self.sack_post_rto else {
            return 0;
        };
        // RFC 6675 §5.1: fill fresh holes under slow start, not SetPipe.
        // Timeout-era originals do not consume the new congestion window.
        // Count the retransmitted prefix once, plus data first sent after RTO.
        let retransmitted_end = if high_rxt.after(boundary) {
            boundary
        } else {
            high_rxt
        };
        let retransmitted = if retransmitted_end.after(self.snd_una) {
            self.scoreboard
                .unsacked_bytes(self.snd_una, retransmitted_end)
        } else {
            0
        };
        let new_start = if boundary.after(self.snd_una) {
            boundary
        } else {
            self.snd_una
        };
        retransmitted + self.scoreboard.unsacked_bytes(new_start, self.data_high())
    }

    // Pure planning shared by cumulative RTO/Reno, SACK/RACK and TLP data.
    // Persist deliberately bypasses this rule and never consumes retry credit.
    //= https://www.rfc-editor.org/rfc/rfc9937#section-3
    //= reason=Fresh ordinary/PRR/TLP output is bounded by the latest rwnd. Reconcile this inherited definition only with RFC9293 section3.8.6 MAY-7 old-data shrink retries and section3.8.6.1 mandatory zero-window probes; scaled retries additionally obey RFC7323 section2.4 items4/5 (originally in-window, first/sub-scale permission, otherwise current window). retry_limit is shared by RTO/Reno/SACK/RACK/TLP; missing scaled metadata cannot authorize beyond-window retries. Persist is separate and active strict PRR is cancelled before probing. Wire/shrink matrices and scaled retry regressions assert these limits, not a general recovery exemption.
    //# At any given time, a connection MUST
    //# NOT send data with a sequence number higher than the sum of
    //# SND.UNA and rwnd.
    fn retry_limit(&self, seq: Seq, proposed: u32) -> u32 {
        let proposed = proposed.min(self.data_high().distance_from(seq));
        // Keep probe repairs within the original gap even after PTB cancels
        // the probe's search result; trailing bytes may already be delivered.
        let proposed = self
            .pmtud
            .as_ref()
            .map_or(proposed, |p| p.repair_limit(seq, proposed));
        let window = self.snd_wnd.saturating_sub(seq.distance_from(self.snd_una));
        if self.snd_wnd == 0 {
            return 0;
        }
        if self.scaling
            && let Some(span) = self
                .rack
                .original_retry_span(seq, seq.wrapping_add(proposed))
        {
            let limit = span.retry_end.distance_from(seq);
            let edge = self.snd_una.wrapping_add(self.snd_wnd);
            // RFC7323 tests the segment's sequence number (SEG.SEQ), not
            // its last byte; permitted retries still stop at original/coverage edges.
            let near_edge = seq.in_window(self.snd_una, self.snd_wnd) == Some(true)
                || seq.distance_from(edge) < (1u32 << self.peer_scale);
            if span.originally_in_window && (span.successful_retries == 0 || near_edge) {
                return limit;
            }
            return limit.min(window);
        }
        // RFC9293 MAY-7 opt-in cannot override RFC7323 scaled retry rules,
        // including when the original-validity/retry ledger is unavailable.
        if !self.scaling && self.config.retransmit_beyond_window {
            proposed
        } else {
            proposed.min(window)
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //= reason=Output ACK field is the receive frontier; established reply flags and sequence are explicitly checked.
    //# If the ACK control bit is set, this field contains the value of the next sequence number
    //# the sender of the segment is expecting to receive. Once a connection is established,
    //# this is always sent.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
    //= reason=SYN precedes queued data, FIN follows it; sequence numbers checked across wrap, handshake_queues_sends_until_established checks SYN consumes one.
    //# For sequence number purposes, the SYN is considered to occur before the first actual
    //# data octet of the segment in which it occurs, while the FIN is considered to occur after
    //# the last actual data octet in a segment in which it occurs.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.1
    //= reason=ISS/ISS+1 are checked on committed SYN output; active API enqueues SYN and driver polls, rather than emitting inline.
    //# A SYN segment of the form <SEQ=ISS><CTL=SYN> is sent. Set SND.UNA to ISS, SND.NXT to
    //# ISS+1, enter SYN-SENT state, and return.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-4
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Enabled receiver emits kind 5 after SYN permission; reordered data yields SACK and gap fill removes it.
    //# If the data receiver has received a SACK-Permitted option on the SYN for
    //# this connection, the data receiver MAY elect to generate SACK options as
    //# described below.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-4
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Output gates kind 5 on sack_send, set only from SYN permission and local config.
    //# If the data receiver has not received a SACK-Permitted option for a given
    //# connection, it MUST NOT send SACK options on that connection.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-4
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Output uses available TCP/path option budget; tests assert 4 ordinary slots or 3 with timestamps, payload clipping and failed-output rollback.
    //# * The data receiver SHOULD include as many distinct SACK blocks as possible
    //# in the SACK option.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Update/IsLost/SetPipe are byte-range scoreboard functions; NextSeg is in poll-driven output selection, not a literal function. Focused scoreboard reference and priority tests provide behavioral evidence.
    //# For the purposes of the algorithm defined in this document, the scoreboard
    //# SHOULD implement the following functions:
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= reason=Negotiated non-RACK/non-PRR SACK; full-budget and piggybacked-SACK regressions exercise lost/new/speculative/rescue priority. IsLost uses SMSS independently of output clipping; markers commit only after encoding.
    //# NextSeg () MUST return the sequence number range of the next segment that is
    //# to be transmitted, per the following rules:
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= reason=Negotiated non-RACK/non-PRR SACK; lowest_hole uses SMSS for IsLost and output is clipped to the packet budget. Integrated 240/256/257-byte SACK cases verify the strict loss threshold and fresh-data priority with SMSS 128 and budget 116.
    //# (1) If there exists a smallest unSACKed sequence number 'S2' that meets the
    //# following three criteria for determining loss, the sequence range of one
    //# segment of up to SMSS octets starting with S2 MUST be returned.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= reason=Negotiated non-RACK/non-PRR SACK; full-budget and budget-116 tests send fresh data before nonlost holes and keep RecoveryPoint fixed.
    //# (2) If no sequence number 'S2' per rule (1) exists but there exists
    //# available unsent data and the receiver's advertised window allows, the
    //# sequence range of one segment of up to SMSS octets of previously unsent data
    //# starting with sequence number HighData+1 MUST be returned.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. With no new/lost segment, speculative offset 768 is sent before tail rescue, then high_rxt advances.
    //# (3) If the conditions for rules (1) and (2) fail, but there exists an
    //# unSACKed sequence number 'S3' that meets the criteria for detecting loss
    //# given in steps (1.a) and (1.b) above (specifically excluding step (1.c)),
    //# then one segment of up to SMSS octets starting with S3 SHOULD be returned.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Rescue contains the highest outstanding unsacked byte; success sets RescueRxt to fixed recovery boundary, retry does not consume it and a second rescue is denied.
    //# If HighACK is greater than RescueRxt (or RescueRxt is undefined), then one
    //# segment of up to SMSS octets that MUST include the highest outstanding
    //# unSACKed sequence number SHOULD be returned, and RescueRxt set to
    //# RecoveryPoint.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Rescue leaves high_rxt unchanged, explicitly asserted.
    //# HighRxt MUST NOT be updated.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. No remaining permitted candidate yields Ok(None); rescue test separately denies repeated rescue.
    //# (5) If the conditions for each of (1), (2), (3), and (4) are not met, then
    //# NextSeg () MUST indicate failure, and no segment is returned.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated non-RACK/non-PRR SACK; each output poll recomputes SetPipe and sends up to the packet budget while SMSS credit and peer window permit. Integrated tests exhaust two-SMSS credit from one ACK, check window/option limits and failed-output rollback.
    //# (3) The TCP MAY transmit previously unsent data segments as per Limited
    //# Transmit [RFC5681], except that the number of octets which may be sent is
    //# governed by pipe and cwnd as follows:
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated non-RACK/non-PRR SACK; active recovery polls consume pipe/cwnd credit and stop below SMSS; separate limited-transmit regression checks the pre-recovery loop.
    //# (C) If cwnd - pipe >= 1 SMSS, the sender SHOULD transmit one or more
    //# segments as follows:
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Output uses scoreboard lowest/tail-hole selection and fails without a candidate; test checks multiple output ranges then Ok(None).
    //# (C.1) The scoreboard MUST be queried via NextSeg () for the sequence number
    //# range of the next segment to transmit (if any), and the given segment sent.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Successful nonrescue output advances high_rxt; rescue explicitly leaves it unchanged; failed encode does not commit either.
    //# (C.2) If any of the data octets sent in (C.1) are below HighData, HighRxt
    //# MUST be set to the highest sequence number of the retransmitted segment
    //# unless NextSeg () rule (4) was invoked for this retransmission.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-6
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Optional timer variant uses the shared successful-retransmission commit path. sack_multiloss_selective_recovery_and_transactional_entry asserts exact send_time+rto after both retransmissions, failed-output stability and nonadvancing-SACK nonrestart; sack_rto_discards_advice_retransmits_head_and_guards_epoch checks entry and expiry.
    //# Therefore, we give implementers the latitude to use the standard
    //# [RFC6298]-style RTO management or, optionally, a more careful variant that
    //# re-arms the RTO timer on each retransmission that is sent during recovery
    //# MAY be used.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-9
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Section 9 restates rule (3), not a new algorithm; speculative retransmission is selected and asserted before rescue.
    //# Rule (3) of NextSeg() has been changed from MAY to SHOULD, to appropriately
    //# reflect the opinion of the authors and working group that it should be left
    //# in, rather than out, if an implementor does not have a compelling reason to
    //# do otherwise.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-3
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Wire ACK remains cumulative across SACK reports and advances to end only after gap fill.
    //# When missing segments are received, the data receiver acknowledges the data
    //# normally by advancing the left window edge in the Acknowledgement Number
    //# Field of the TCP header. The SACK option does not change the meaning of the
    //# Acknowledgement Number field.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Equivalent byte-range strategy skips SACKed intervals in retransmission selection; test sends only missing offsets 0 and 256. RTO intentionally clears advice.
    //# After the SACKed bit is turned on (as the result of processing a received
    //# SACK option), the data sender will skip that segment during any later
    //# retransmission.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-2
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. data_high is the exclusive transmitted data edge; new output advances snd_nxt but excludes FIN.
    //# "HighData" is the highest sequence number transmitted at a given point.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-2
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. high_rxt is exclusive; only successful nonrescue retransmissions advance it.
    //# "HighRxt" is the highest sequence number which has been retransmitted during
    //# the current loss recovery phase.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-2
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. rescue_rxt grants a single tail retransmission and tracks recovery boundary after success.
    //# "RescueRxt" is the highest sequence number which has been optimistically
    //# retransmitted to prevent stalling of the ACK clock when there is loss at the
    //# end of the window and no new data is available for transmission.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-2
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Recovery pipe bounds output; independent scoreboard per-byte oracle checks computation.
    //# "Pipe" is a sender's estimate of the number of bytes outstanding in the
    //# network. This is used during recovery for limiting the sender's sending
    //# rate. The pipe variable allows TCP to use fundamentally different congestion
    //# control than the algorithm specified in [RFC5681]. The congestion control
    //# algorithm using the pipe estimate is often referred to as the "pipe
    //# algorithm".
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= reason=Negotiated non-RACK/non-PRR SACK; lowest_hole uses SMSS for IsLost and output is clipped to the packet budget. Integrated 240/256/257-byte SACK cases verify the strict loss threshold and fresh-data priority with SMSS 128 and budget 116.
    //# (1.a) S2 is greater than HighRxt.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= reason=Negotiated non-RACK/non-PRR SACK; lowest_hole uses SMSS for IsLost and output is clipped to the packet budget. Integrated 240/256/257-byte SACK cases verify the strict loss threshold and fresh-data priority with SMSS 128 and budget 116.
    //# (1.b) S2 is less than the highest octet covered by any received SACK.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= reason=Negotiated non-RACK/non-PRR SACK; lowest_hole uses SMSS for IsLost and output is clipped to the packet budget. Integrated 240/256/257-byte SACK cases verify the strict loss threshold and fresh-data priority with SMSS 128 and budget 116.
    //# (1.c) IsLost (S2) returns true.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Limited-transmit pipe passes snd_una (exclusive HighACK) as high_rxt.
    //# (3.1) Set HighRxt to HighACK.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated non-RACK/non-PRR SACK; each output poll recomputes SetPipe and sends up to the packet budget while SMSS credit and peer window permit. Integrated tests exhaust two-SMSS credit from one ACK, check window/option limits and failed-output rollback.
    //# (3.2) Run SetPipe ().
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated non-RACK/non-PRR SACK; each output poll recomputes SetPipe and sends up to the packet budget while SMSS credit and peer window permit. Integrated tests exhaust two-SMSS credit from one ACK, check window/option limits and failed-output rollback.
    //# (3.3) If (cwnd - pipe) >= 1 SMSS, there exists previously unsent data, and
    //# the receiver's advertised window allows, transmit up to 1 SMSS of data
    //# starting with the octet HighData+1 and update HighData to reflect this
    //# transmission, then return to (3.2).
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. entry_pending retransmits snd_una regardless of advisory SACK, bounded by real data high, output and peer window; sack_entry_retransmits_sacked_head_transactionally checks committed exclusive HighRxt/RescueRxt and SetPipe after success, not failure.
    //# (4.3) Retransmit the first data segment presumed dropped -- the segment
    //# starting with sequence number HighACK + 1. To prevent repeated
    //# retransmission of the same data or a premature rescue retransmission, set
    //# both HighRxt and RescueRxt to the highest sequence number in the
    //# retransmitted segment.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Poll-driven output continues recovery candidates until cwnd credit exhausted.
    //# (4.5) In order to take advantage of potential additional available cwnd,
    //# proceed to step (C) below.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. No candidate returns no segment; multiloss and rescue tests assert Ok(None).
    //# If NextSeg () returns failure (no data to send), return without sending
    //# anything (i.e., terminate steps C.1 -- C.5).
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Successful new data advances exclusive snd_nxt; test checks one-SMSS advance while recovery point remains fixed.
    //# (C.3) If any of the data octets sent in (C.1) are above HighData, HighData
    //# must be updated to reflect the transmission of previously unsent data.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Non-RACK pipe increments by actual successfully encoded bytes; test fills pipe exactly to cwnd and denies next poll.
    //# (C.4) The estimate of the amount of data outstanding in the network must be
    //# updated by incrementing pipe by the number of octets transmitted in (C.1).
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. One segment per output poll; successive polls select ranges until credit less than SMSS, equivalent to loop.
    //# (C.5) If cwnd - pipe >= 1 SMSS, return to (C.1)
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Post-RTO selection fills fresh holes without the normal fast-recovery NextSeg priorities/rescue and stays guarded until old flight is cumulatively covered.
    //# The exact algorithm for this selection is not specified in this document
    //# (specifically NextSeg () is inappropriate during loss recovery after an
    //# RTO).
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= reason=TLP branch prefers lowest unsent data fitting the receive window, even beyond cwnd; commit advances SND.NXT and charges FlightSize.
    //# If both conditions are met, then the sender SHOULD transmit a
    //# previously unsent data segment, if one exists and the receive window
    //# allows, and increment the FlightSize accordingly.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= reason=Output falls back to the tail segment and commits retransmitted probe state only on successful encode.
    //# If such an unsent segment is not available, then the sender SHOULD
    //# retransmit the highest-sequence segment sent so far and set
    //# TLP.is_retrans to true.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= reason=All successfully encoded non-persist/non-keepalive data, including new/retransmitted TLP, calls Rack::transmit with committed boundaries and now.
    //# The sender MUST follow the RACK transmission procedures in the "Upon
    //# Transmitting a Data Segment" section upon sending either a
    //# retransmission or a new data loss probe.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= reason=Probe commit clears PTO and arms now+RTO; failed encode leaves the expiry-armed fallback intact.
    //# After attempting to send a loss probe, regardless of whether a loss
    //# probe was sent, the sender MUST re-arm the RTO timer, not the PTO
    //# timer, if the FlightSize is not zero.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.2
    //= reason=When RACK is enabled, selection uses Rack::lowest_lost and time-based pipe instead of unchanged RFC6675 NextSeg; the disabled/fallback profile retains RFC6675.
    //# Therefore, the algorithm [RFC6675]
    //# MUST NOT be used with RACK-TLP; instead, a modified recovery
    //# algorithm that carefully addresses such a case is needed.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
    //= reason=RACK loss selection is clipped by recovery credit/PRR, then receive-window limits; timer marking alone does not emit bytes.
    //# A segment marked
    //# as lost by RACK-TLP MUST NOT be retransmitted until congestion
    //# control deems this appropriate.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= reason=Requires fresh RTT at selection and clears it only when nonempty probe commits.
    //# Second, the sender has obtained an RTT measurement since the last
    //# loss probe transmission or the start of the connection, whichever
    //# was later.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
    //= reason=TLP may send one packet past cwnd but within receive window; committed new bytes advance SND.NXT, so flight includes overcommit (not limited-transmit credit).
    //# The only exception -- the only way in which RACK-TLP modulates the
    //# congestion control algorithm -- is that one outstanding loss probe
    //# can be sent even if the congestion window is fully used.  However,
    //# this temporary overcommit is accounted for and credited in the in-
    //# flight data tracked for congestion control, so that congestion
    //# control will erase the overcommit upon the next ACK.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-1
    //= reason=Default/configured >=1s timing evidence; subsecond compatibility is a scoped departure, not universal MUST conformance. Successful encode commit only; ordinary data starts an absent RTO and retransmission re-arms it. SYN/FIN count as sequence space. RACK/TLP loss detection and persist are separate paths, not evidence for literal RTO timing in every profile.
    //# However, a TCP MUST NOT be more aggressive than the following algorithms allow.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-3
    //= reason=Successful encode commit only; ordinary data starts an absent RTO and retransmission re-arms it. SYN/FIN count as sequence space. RACK/TLP loss detection and persist are separate paths, not evidence for literal RTO timing in every profile.
    //# TCP MUST use Karn's algorithm [KP87] for taking RTT samples.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-3
    //= reason=Successful encode commit only; ordinary data starts an absent RTO and retransmission re-arms it. SYN/FIN count as sequence space. RACK/TLP loss detection and persist are separate paths, not evidence for literal RTO timing in every profile.
    //# That is, RTT samples MUST NOT be made using segments that were retransmitted (and thus
    //# for which it is ambiguous whether the reply was for the first instance of the packet
    //# or a later instance).
    //= https://www.rfc-editor.org/rfc/rfc6298#section-3
    //= reason=Partial evidence only; TODO remains. Successful encode commit only; ordinary data starts an absent RTO and retransmission re-arms it. SYN/FIN count as sequence space. RACK/TLP loss detection and persist are separate paths, not evidence for literal RTO timing in every profile.
    //# A TCP implementation MUST take at least one RTT measurement per RTT (unless that is
    //# not possible per Karn's algorithm).
    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= reason=Partial evidence only; TODO remains. Successful encode commit only; ordinary data starts an absent RTO and retransmission re-arms it. SYN/FIN count as sequence space. RACK/TLP loss detection and persist are separate paths, not evidence for literal RTO timing in every profile.
    //# An implementation MUST manage the retransmission timer(s) in such a way that a segment
    //# is never retransmitted too early, i.e., less than one RTO after the previous
    //# transmission of that segment.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= reason=Partial evidence only; TODO remains. Successful encode commit only; ordinary data starts an absent RTO and retransmission re-arms it. SYN/FIN count as sequence space. RACK/TLP loss detection and persist are separate paths, not evidence for literal RTO timing in every profile.
    //# The following is the RECOMMENDED algorithm for managing the retransmission timer:
    //= https://www.rfc-editor.org/rfc/rfc6298#section-3
    //= reason=Partial evidence only; TODO remains. Successful encode commit only; ordinary data starts an absent RTO and retransmission re-arms it. SYN/FIN count as sequence space. RACK/TLP loss detection and persist are separate paths, not evidence for literal RTO timing in every profile.
    //# However, when using the timestamp option, each ACK can be used as an RTT sample. RFC
    //# 1323 [JBB92] suggests that TCP connections utilizing large congestion windows should
    //# take many RTT samples per window of data to avoid aliasing effects in the estimated
    //# RTT.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= reason=Partial evidence only; TODO remains. Successful encode commit only; ordinary data starts an absent RTO and retransmission re-arms it. SYN/FIN count as sequence space. RACK/TLP loss detection and persist are separate paths, not evidence for literal RTO timing in every profile.
    //# (5.1) Every time a packet containing data is sent (including a retransmission), if the
    //# timer is not running, start it running so that it will expire after RTO seconds (for
    //# the current value of RTO).
    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= reason=Successful encode commit only; ordinary data starts an absent RTO and retransmission re-arms it. SYN/FIN count as sequence space. RACK/TLP loss detection and persist are separate paths, not evidence for literal RTO timing in every profile.
    //# (5.4) Retransmit the earliest segment that has not been acknowledged by the TCP
    //# receiver.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= reason=Successful encode commit only; ordinary data starts an absent RTO and retransmission re-arms it. SYN/FIN count as sequence space. RACK/TLP loss detection and persist are separate paths, not evidence for literal RTO timing in every profile.
    //# (5.6) Start the retransmission timer, such that it expires after RTO seconds (for the
    //# value of RTO after the doubling operation outlined in 5.5).
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=Partial evidence only; TODO remains. Successful encode commit only; ordinary data starts an absent RTO and retransmission re-arms it. SYN/FIN count as sequence space. RACK/TLP loss detection and persist are separate paths, not evidence for literal RTO timing in every profile.
    //# The procedures specified in Section 3.2 of [RFC5681] are followed, with the
    //# modifications listed below.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=NewReno partial ACK schedules retx_pending; committed output starts at snd_una. newreno_partial_ack_wire_timer_and_exit_boundaries asserts each missing sequence/payload, continued recovery and failed-output rollback, including wrap.
    //# In this case, retransmit the first unacknowledged segment.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=newreno_partial_ack_wire_timer_and_exit_boundaries asserts no fresh output with flight>=cwnd, one fresh MSS with credit, rwnd/SWS suppression then permission, MSS payload bounds and failed-output rollback.
    //# Send a new segment if permitted by the new value of cwnd.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= reason=Selected full-ACK option1 cwnd=min(ssthresh,max(FlightSize,SMSS)+SMSS). Lost-duplicate-ACK wire trace newreno_partial_ack_wire_timer_and_exit_boundaries polls to exhaustion: two fresh MSS at zero flight, one at residual one-MSS flight.
    //# In Section 3.2, step 3 above, it is noted that implementations should take measures to
    //# avoid a possible burst of data when leaving fast recovery, in case the amount of new
    //# data that the sender is eligible to send due to the new value of the congestion window
    //# is large.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
    //= reason=Non-SACK Limited Transmit: each of first two duplicate ACKs yields one unsent SMSS; output then stops, total extra flight is two MSS, and third ACK threshold excludes those bytes. SACK fresh-evidence gating is tested separately; not a PRR output claim.
    //# On the first and second duplicate ACKs received at a sender, a TCP SHOULD send a segment
    //# of previously unsent data per [RFC3042] provided that the receiver's advertised window
    //# allows, the total FlightSize would remain less than or equal to cwnd plus 2*SMSS, and
    //# that new data is available for transmission.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-2
    //= reason=Ordinary new data uses min(rwnd,cwnd)-flight; section3.2 Limited Transmit extends cwnd by at most two MSS. Negotiated SACK selects RFC6675 pipe, RFC9937 PRR selects exact byte credit, RACK selects RFC8985 modified pipe, and TLP permits one accounted probe. retry_limit restricts old-data receive-window exceptions; zero-window output is only the prescribed probe. output_policy wire matrix tests these choices, not section4.3 half-flight packet counts.
    //# At any given time, a TCP MUST NOT send data with a sequence number higher than the sum of the highest acknowledged sequence number and the minimum of cwnd and rwnd.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= reason=Shared congestion ACK/timeout processing selects slow start or byte-counting avoidance; ordinary output uses their computed cwnd, including reduced-cwnd recovery exit. Selected advanced recovery/probe budgets are tested separately in output_policy.
    //# The slow start and congestion avoidance algorithms MUST be used by a TCP sender to control the amount of outstanding data being injected into the network.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3
    //= reason=Selected algorithm evidence, not a blanket exception: ordinary min windows, controlled Limited Transmit, non-RACK/non-PRR RFC6675 pipe, RFC9937 PRR byte credit, RFC8985 modified RACK recovery and one accounted TLP probe; retry_limit allows only prescribed old-data retry exceptions. output_policy asserts exact output and exhaustion. Section4.3 literal segment-count TODO remains independent.
    //# In some situations, it may be beneficial for a TCP sender to be more conservative than the algorithms allow; however, a TCP MUST NOT be more aggressive than the following algorithms allow (that is, MUST NOT send data when the value of cwnd computed by the following algorithms would not allow the data to be sent).
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
    //= reason=ACK/eligible duplicate ACK/RTO output follows the selected ordinary congestion algorithm or negotiated advanced-recovery budget, with RFC8985 one-probe extension; output_policy and ECN wire traces test those paths. Not whole RFC2581/5681 compliance or a section4.3 half-flight claim.
    //# TCP follows existing algorithms for sending data packets in response to incoming ACKs, multiple duplicate acknowledgments, or retransmit timeouts [RFC2581].
    pub(crate) fn transmit(
        &mut self,
        now: Instant,
        out: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        self.transmit_selected(now, out, false)
    }

    pub(crate) fn transmit_selected(
        &mut self,
        now: Instant,
        out: &mut [u8],
        reserve: bool,
    ) -> Result<Option<usize>, Error> {
        self.transmit_selected_with_gso(now, out, reserve, None)
    }

    pub(crate) fn transmit_shared_selected(
        &mut self,
        now: Instant,
        out: &mut [u8],
        payload: &mut Vec<crate::Payload>,
    ) -> Result<Option<usize>, Error> {
        payload.clear();
        if payload.capacity() == 0 {
            return Err(Error::InvalidArgument);
        }
        self.send.set_shared_output(Some(payload.capacity()));
        let result = self.transmit_selected_payload(now, out, true, None, Some(&mut *payload));
        self.send.set_shared_output(None);
        if result.is_err() {
            payload.clear();
        }
        result
    }

    pub(crate) fn transmit_selected_with_gso(
        &mut self,
        now: Instant,
        out: &mut [u8],
        reserve: bool,
        gso: Option<crate::output_reservation::GsoBuffer<'_>>,
    ) -> Result<Option<usize>, Error> {
        self.transmit_selected_payload(now, out, reserve, gso, None)
    }

    fn transmit_selected_payload(
        &mut self,
        now: Instant,
        out: &mut [u8],
        reserve: bool,
        gso: Option<crate::output_reservation::GsoBuffer<'_>>,
        shared: Option<&mut Vec<crate::Payload>>,
    ) -> Result<Option<usize>, Error> {
        // A connection is offered output after every change, and most changes
        // (input, a read, the send that took its last data) leave it nothing
        // to send. The selection below would find that only after building
        // its options and planning every kind of output; see it at once, as
        // Linux tests the send head before tcp_write_xmit.
        if self.output_idle() {
            let idle = self.check_time(now).map(|()| None);
            // The selection finds nothing either, and changes nothing doing
            // so.
            #[cfg(debug_assertions)]
            debug_assert_eq!(
                self.select_output(now, out, reserve, gso, shared),
                idle,
                "an idle connection selected output"
            );
            return idle;
        }
        self.select_output(now, out, reserve, gso, shared)
    }

    // Whether this connection certainly has nothing to send: no reset,
    // acknowledgment, SYN or probe owed, no retransmission or recovery work,
    // every queued octet and any FIN sent, and no administrative PMTU target
    // whose deferral a selection would record. Each of these is set by a
    // change, never by time alone.
    pub(crate) fn output_idle(&self) -> bool {
        self.pending_rst.is_none()
            && !self.challenge_ack_pending
            && !self.syn_pending
            && !self.ack_pending
            && !self.probe_pending
            && !self.keepalive_pending
            && !self.tlp_pending
            && !self.retx_pending
            && self.fast_open_retry.is_none()
            && self.sack_recovery.is_none()
            && self.prr.is_none()
            && self.sack_post_rto.is_none()
            && self.ptb_idle()
            && self.send.len() <= self.snd_nxt.distance_from(self.send_base) as usize
            && !(self.shutdown && self.fin_sequence.is_none())
            && self
                .pmtud
                .as_ref()
                .is_none_or(|p| p.administrative_target().is_none())
    }

    fn select_output(
        &mut self,
        now: Instant,
        out: &mut [u8],
        reserve: bool,
        mut gso: Option<crate::output_reservation::GsoBuffer<'_>>,
        mut shared: Option<&mut Vec<crate::Payload>>,
    ) -> Result<Option<usize>, Error> {
        self.check_time(now)?;
        if self.local_resource.is_some_and(|r| r.retry_at.is_some()) || self.timestamp_ambiguous {
            return Ok(None); // Owner must service the timer first.
        }
        let mut segmentation = None;
        // Plan entirely before encode. Even timer/clock/accounting changes
        // are committed only once the adapter has sufficient output space.
        let reset = self.pending_rst;
        let challenge = reset.is_none() && self.challenge_ack_pending;
        let syn = reset.is_none() && !challenge && self.syn_pending;
        let live = self.synchronized() && !challenge;
        let early_response = self.early_response_eligible() && !challenge;
        // Control and due protocol probes bypass pacing: SYN/RST/challenge,
        // pure ACK/FIN, RTO head retry outside PRR, TLP, persist and keepalive.
        // Actual stream data on bypasses still schedules spacing (keepalive's
        // garbage octet is not stream data). Fast recovery retries do not
        // bypass. Selection/admission below remains the sole authority to send.
        let pacing_blocked = if self.config.pacing.is_some() {
            // A saturated deadline still blocks at Instant::MAX.
            self.general_pacing_deadline(now).is_some()
        } else {
            self.pacing_enabled() && self.pacing_deadline.is_some_and(|deadline| now < deadline)
        };
        let data_live = live && !pacing_blocked;
        let retransmit = reset.is_none()
            && !syn
            && live
            && (!pacing_blocked || self.consecutive_timeouts != 0 && self.prr.is_none())
            && self.retx_pending
            && self.flight() != 0;
        let probe = reset.is_none() && !syn && live && self.probe_pending;
        // An old-sequence control elicits a window reply, but cannot deliver
        // a new urgent pointer. First notify URG at the acceptable sequence;
        // the unchanged probe obligation then emits the old-sequence control.
        // Compare the encodable pointer edge so long urgent runs stay bounded.
        let urgent_probe = probe
            && self.flight() == 0
            && self.snd_up.is_some_and(|end| {
                let distance = end.distance_from(self.snd_una);
                let edge = self.snd_una.wrapping_add(distance.min(u16::MAX as u32));
                distance != 0
                    && distance < 1 << 31
                    && self.advertised_snd_up.is_none_or(|old| edge.after(old))
            });
        let tlp = reset.is_none()
            && !syn
            && live
            && self.tlp_pending
            && self.tlp_eligible()
            && self.tlp_end.is_none()
            && self.tlp_flight.is_none()
            && self.tlp_fresh_rtt;
        let keepalive = reset.is_none() && !syn && live && self.keepalive_pending;
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.1
        //= reason=Transmit supplies MSS on SYN; learn_syn consumes the decoded peer MSS.
        //# TCP endpoints MUST implement both sending and receiving the MSS Option
        //# (MUST-14).
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.1
        //# where MMS_R is the maximum size for a transport-layer message that
        //# can be received (and reassembled at the IP layer) (MUST-67).
        let mss = self.receive_mss().to_be_bytes();
        // The timestamp clock's tick at `now`: TSval, this tick's TS-bearing
        // credit and its commit all read it, so it is divided out once.
        let tick = self
            .config
            .timestamp_granularity
            .tick_in(now, self.config.timebase);
        let mut options = [0; 40];
        options[..4].copy_from_slice(&[2, 4, mss[0], mss[1]]);
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.1
        //# TCP implementations SHOULD send an MSS Option in every SYN segment when its
        //# receive MSS differs from the default 536 for IPv4 or 1220 for IPv6 (SHLD-5),
        //# and MAY send it always (MAY-3).
        let mut option_len = if syn { 4 } else { 0 };
        //= https://www.rfc-editor.org/rfc/rfc2018#section-2
        //# It MUST NOT be sent on non-SYN segments.
        let sack_offer =
            syn && self.config.sack && (self.state == State::SynSent || self.sack_send);
        //= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
        //= reason=Timestamp negotiation is config/peer-SYN gated; SYN TSecr=0, ACK replies echo ts_recent, bool timestamps retains negotiated state.
        //# If
        //# the ACK bit is not set in the outgoing TCP header, the sender of that
        //# segment SHOULD set the TSecr field to zero.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
        //= reason=Timestamp negotiation is config/peer-SYN gated; SYN TSecr=0, ACK replies echo ts_recent, bool timestamps retains negotiated state.
        //# When the ACK bit is set
        //# in an outgoing segment, the sender MUST echo a recently received
        //# TSval sent by the remote TCP in the TSval field of a Timestamps
        //# option.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
        //= reason=Timestamp negotiation is config/peer-SYN gated; SYN TSecr=0, ACK replies echo ts_recent, bool timestamps retains negotiated state.
        //# A TCP MAY send the TSopt in an initial <SYN> segment (i.e., segment
        //# containing a SYN bit and no ACK bit), and MAY send a TSopt in
        //# <SYN,ACK> only if it received a TSopt in the initial <SYN> segment
        //# for the connection.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
        //= reason=Negotiated non-RST output always allocates TS; timestamp-enabled path budget minimum 40 preserves SYN options, ordinary data/ACK/FIN/probe/keepalive and user-abort RST retain TS. Reactive reset limits audited separately in section 5.2.
        //# Once TSopt has been successfully negotiated, that is both <SYN> and
        //# <SYN,ACK> contain TSopt, the TSopt MUST be sent in every non-<RST>
        //# segment for the duration of the connection, and SHOULD be sent in an
        //# <RST> segment (see Section 5.2 for details).
        //= https://www.rfc-editor.org/rfc/rfc7323#section-5.2
        //= reason=Local user abort on negotiated connection emits TS; not a reactive RST requiring TSval=0.
        //# If an <RST> is being generated
        //# because of a user abort, and Snd.TS.OK is set, then a Timestamps
        //# option SHOULD be included in the <RST>.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-5.4
        //= reason=Successful TS-bearing sequence-space bytes (including retransmitted copies and SYN/FIN) are transactionally limited by configured nonzero timestamp_bytes_per_tick <2^31. Exhaustion returns TimestampBudgetExceeded with caller time and protocol state unchanged; next tick resets credit. Boundary/wrap/output rollback tests verify the gate. Physical clock truth remains separately external.
        //# It MUST tick at least once for each 2^31 bytes sent.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-5.4
        //= reason=Approved fixed-tick SHOULD policy exception: default1ms and opt-in1us clocks preserve network-rate behavior without per-window pacing or synthetic ticks. A1byte/10us path can carry100000B/s instead of the1000B/s imposed by window/1ms pacing. Local Karn-safe RTT sampling preserves estimator cadence independently of TSecr. Separate <2^31-byte per-tick MUST credit remains enforced and tested; this exception does not waive it or physical clock evidence.
        //# In fact,
        //# in order to be useful to the sender for round-trip timing, the
        //# clock SHOULD tick at least once per window's worth of data, and
        //# even with the window extension defined in Section 2.2, 2^31
        //# bytes must be at least two windows.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-5.4
        //= reason=Native and tun_echo time is the characterized CLOCK_BOOTTIME provider, which rejects decreasing samples and measures suspend; other embedders owe physically monotonic, consistent-rate time with sufficient precision for protocol timing; violation leaves timing guarantees unspecified, never Rust UB or memory-safety violations. CallerTimebase accepts microsecond/nanosecond units and MSL <=255s, independently of wire ms/us periods. Nondecreasing input, endpoint timestamp half-range gaps and resource bounds are checked; physical rate/drift/precision and actual network MSL cannot be established here. Peer PAWS expires independently at2147s. Fixed wire cadence and opt-in microsecond frequency remain scoped policy exceptions, not literal conformance.
        //# The recycling time of the timestamp clock MUST be greater than
        //# MSL seconds.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-7.1
        //= reason=Endpoint derives offset using HMAC-SHA256 of the secret and the tuple alone in the separate ntcp timestamp offset domain before first output, the ISN's PRF under another domain (section 5.4) with Linux's inputs (secure_tcp_seq_and_ts_off: addresses and ports). Every incarnation of a tuple shares it, so peer PAWS and TIME-WAIT see no random jump; other tuples' offsets stay unpredictable. Modular addition/subtraction covers wire TS and ordinary/RACK RTT validation. TIME-WAIT reuse inherits the old local offset; failed output/candidate rollback retain the old clock. Unrelated tuple/secret, reincarnation, echo/RTT/wrap and reuse rollback tests cover the policy.
        //# It is therefore RECOMMENDED to generate a random, per-
        //# connection offset to be used with the clock source when generating
        //# the Timestamps option value (see Section 5.4).
        //= https://www.rfc-editor.org/rfc/rfc7323#section-7
        //= reason=Endpoint derives offset using HMAC-SHA256 of the secret and the tuple alone in the separate ntcp timestamp offset domain before first output, the ISN's PRF under another domain (section 5.4) with Linux's inputs (secure_tcp_seq_and_ts_off: addresses and ports). Every incarnation of a tuple shares it, so peer PAWS and TIME-WAIT see no random jump; other tuples' offsets stay unpredictable. Modular addition/subtraction covers wire TS and ordinary/RACK RTT validation. TIME-WAIT reuse inherits the old local offset; failed output/candidate rollback retain the old clock. Unrelated tuple/secret, reincarnation, echo/RTT/wrap and reuse rollback tests cover the policy.
        //# It is therefore
        //# RECOMMENDED to generate a random, per-connection offset to be used
        //# with the clock source when generating the Timestamps option value
        //# (see Section 5.4).
        //= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
        //= reason=Wire TS fields u32 network-order; TSval uses selected local ticks (default milliseconds) modulo 32 bits. Physical rate guarantees separately TODO.
        //# The Timestamps option carries two four-byte timestamp fields.  The
        //# TSval field contains the current value of the timestamp clock of the
        //# TCP sending the option.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-4.3
        //= reason=Negotiated ordinary ACK output echoes single retained TS.Recent; reactive RST overrides follow section 5.2.
        //# (3)  When a TSopt is sent, its TSecr field is set to the current
        //# TS.Recent value.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-5.4
        //= reason=Approved timestamp frequency policy exception: default1ms is within the quoted chosen1ms..1s range; explicit opt-in1us is outside it, like Linux tcp_usec_ts at pinned22430ae5d90ab288b0ee2ad99ae941f4a666b694 include/net/tcp.h. No literal range compliance is claimed for microseconds. Independent2147s peer PAWS expiry remains; native monotonicity comes from the characterized CLOCK_BOOTTIME provider; physical rate/precision and actual network MSL are not measured or declared resolution gates, and other embedders' clocks remain caller obligations.
        //# Based upon these considerations, we choose a timestamp clock
        //# frequency in the range 1 ms to 1 sec per tick.
        let timestamp = if reset.is_some() && self.reset_echo.is_some() {
            self.reset_echo.map(|echo| (0, echo))
        } else if self.timestamps || syn && self.state == State::SynSent && self.config.timestamps {
            Some((
                self.timestamp_value_at(tick),
                if reset.map_or(self.state != State::SynSent, |(_, with_ack)| with_ack) {
                    self.ts_recent
                } else {
                    0
                },
            ))
        } else {
            None
        };
        if let Some((value, echo)) =
            timestamp.filter(|_| reset.is_none() || self.path_payload_limit() >= 32)
        {
            // SACK-permitted replaces timestamp padding on SYN, as in Linux.
            options[option_len..option_len + 4].copy_from_slice(if sack_offer {
                &[4, 2, 8, 10]
            } else {
                &[1, 1, 8, 10]
            });
            options[option_len + 4..option_len + 8].copy_from_slice(&value.to_be_bytes());
            options[option_len + 8..option_len + 12].copy_from_slice(&echo.to_be_bytes());
            option_len += 12;
        }
        if sack_offer && timestamp.is_none() {
            options[option_len..option_len + 4].copy_from_slice(&[1, 1, 4, 2]);
            option_len += 4;
        }
        //= https://www.rfc-editor.org/rfc/rfc7323#section-2.2
        //= reason=Scaling-capable endpoint offers WS in active SYN and echoes only peer-offered WS in passive SYN-ACK; scale fixed for connection.
        //# The three-byte Window Scale option MAY be sent in a <SYN> segment by
        //# a TCP.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-2.2
        //= reason=Scaling-capable endpoint offers WS in active SYN and echoes only peer-offered WS in passive SYN-ACK; scale fixed for connection.
        //# Thus, a TCP that is prepared to scale windows SHOULD send the option,
        //# even if its own scale factor is 1 and the exponent 0.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-2.2
        //= reason=Wire tests assert Some(0) on SYN and SYN-ACK for small receive buffers, distinct from absent negotiation; both use unscaled effective windows.
        //# MAY be zero (offering to scale, while applying a scale factor of 1 to
        //# the receive window).
        //= https://www.rfc-editor.org/rfc/rfc7323#section-2.2
        //= reason=Scaling-capable endpoint offers WS in active SYN and echoes only peer-offered WS in passive SYN-ACK; scale fixed for connection.
        //# This option MAY be sent in an initial <SYN> segment (i.e., a segment
        //# with the SYN bit on and the ACK bit off).
        //= https://www.rfc-editor.org/rfc/rfc7323#section-2.2
        //= reason=Scaling-capable endpoint offers WS in active SYN and echoes only peer-offered WS in passive SYN-ACK; scale fixed for connection.
        //# If a Window Scale option
        //# was received in the initial <SYN> segment, then this option MAY be
        //# sent in the <SYN,ACK> segment.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-2.3
        //= reason=SYN-only WS output sends capacity-derived local_scale, including passive echo after peer offer; selected R=2 is asserted on wire.
        //# o  If a TCP receives a <SYN> segment containing a Window Scale
        //# option, it SHOULD send its own Window Scale option in the
        //# <SYN,ACK> segment.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-2.3
        //= reason=SYN-only WS output sends capacity-derived local_scale, including passive echo after peer offer; selected R=2 is asserted on wire.
        //# o  The Window Scale option MUST be sent with shift.cnt = R, where R
        //# is the value that the TCP would like to use for its receive
        //# window.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-2.1
        //= reason=Wire tests inject changed WS on established data/ACK, including zero/nonzero/absent negotiation, and assert fixed shifts, unchanged effective window expansion and no outgoing non-SYN WS.
        //# This option is sent only in a <SYN> segment (a
        //# segment with the SYN bit on), hence the window scale is fixed in each
        //# direction when a connection is opened.
        //= https://www.rfc-editor.org/rfc/rfc7323#section-2.2
        //= reason=WS wire kind fixed at 3 in SYN layout; independent option parser/clamp assertions use literal kind 3.
        //# Kind: 3
        //= https://www.rfc-editor.org/rfc/rfc7323#section-2.2
        //= reason=WS emits [NOP,3,3,local_scale], parser only accepts option length 3.
        //# Length: 3 bytes
        if syn && (self.state == State::SynSent || self.scaling) {
            options[option_len..option_len + 4].copy_from_slice(&[1, 3, 3, self.local_scale]);
            option_len += 4;
        }
        //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
        //= reason=Supplied cookies use the existing first-SYN-only data/option selection; actual timer retry drops both and preserves service failure evidence.
        //# To deal with network or servers dropping SYN packets with payload or unknown options, when the SYN timer fires, the client SHOULD retransmit a SYN packet without data and Fast Open options.
        // Original Length 0 below is interpreted using verified erratum 4239:
        // the empty request emitted here has Length 2, never Length 0.
        //= https://www.rfc-editor.org/rfc/rfc7413#section-3
        //# 1. The client sends a SYN with a Fast Open option with an empty cookie field to request a cookie.
        //= https://www.rfc-editor.org/rfc/rfc7413#section-3
        //# 1. The client sends a SYN with data and the cookie in the Fast Open option.
        //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.1
        //= reason=Verified erratum 4239 corrects the original published Length 0 to Length 2; corrected wire behavior is cited, not literal Length 0.
        //# 1. The client sends a SYN packet with a Fast Open option with a Length field of 0 (empty cookie
        //# field).
        //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.1
        //# We RECOMMEND both the client and the server to retransmit SYN and SYN-ACK packets without the cookie
        //# options on timeouts.
        //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
        //# 1. Send a SYN packet.
        //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
        //# a. If the SYN packet does not have enough option space for the Fast Open option, abort TFO and fall
        //# back to the regular 3WHS.
        //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
        //# 2. Advance to SYN-SENT state and update SND.NXT to include the data accordingly.
        //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
        //# If the SYN-ACK timer fires, the server SHOULD retransmit a SYN-ACK segment with neither data nor
        //# Fast Open options for compatibility reasons.
        //= https://www.rfc-editor.org/rfc/rfc7413#section-7.1
        //# The TFO protocol deals with this problem by falling back to the regular TCP handshake and
        //# retransmitting the SYN without data or cookie options after the initial SYN timeout.
        //= https://www.rfc-editor.org/rfc/rfc7413#section-9
        //# Current and new implementations SHOULD use option (34).
        let response_syn = syn && !self.passive_open && self.state != State::SynSent;
        let candidate_cookie = if response_syn {
            (!self.fast_open_response_committed)
                .then_some(self.fast_open_response)
                .flatten()
        } else if syn && self.snd_nxt == self.iss && !self.syn_timed_out {
            self.fast_open
        } else {
            None
        };
        let fast_open_option = candidate_cookie.filter(|cookie| {
            let padded = (option_len + cookie.as_bytes().len() + 2 + 3) & !3;
            padded <= 40 && 20 + padded <= self.path_payload_limit()
        });
        //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
        //= reason=The cookie-required branch serializes the selected server cookie and limits SYN data to validated learned MSS or a conservative cold 536 bytes in both families before the full option reserve and other bounds. Explicit ApplicationProtected uses section 7.3 authorization separately. Erratum 8015 remains Held for Document Update and is not needed for this bound.
        //# Otherwise, include the Fast Open option with the cookie of the server. Include any data up to the cached server MSS or default 536 bytes.
        if let Some(cookie) = fast_open_option {
            let bytes = cookie.as_bytes();
            let length = bytes.len() + 2;
            options[option_len] = 34;
            options[option_len + 1] = length as u8;
            options[option_len + 2..option_len + length].copy_from_slice(bytes);
            option_len += length;
            while option_len % 4 != 0 {
                options[option_len] = 1;
                option_len += 1;
            }
        }
        let mut sack_option_len = 0;
        let mut sack_first = None;
        let mut sack_limited = false;
        if reset.is_none() && !syn && live && self.sack_send && !self.sack_omit {
            let control_payload = usize::from(
                probe || keepalive && self.config.keepalive.is_some_and(|k| k.send_garbage),
            );
            let available = (40 - option_len)
                .min((self.path_payload_limit()).saturating_sub(20 + option_len + control_payload))
                // Pure ACK options are independent of MSS. Once reported, limit
                // piggybacked SACKs to leave room for data on the next poll.
                .min(if self.ack_pending && !self.sack_data_turn {
                    40
                } else {
                    self.mss.saturating_sub(1)
                });
            let full_available =
                (40 - option_len).min((self.path_payload_limit()).saturating_sub(20 + option_len));
            let max_blocks = available.saturating_sub(4) / 8;
            let blocks = self.receive.sack_blocks(max_blocks);
            let n = blocks.iter().flatten().count();
            let full_max_blocks = full_available.saturating_sub(4) / 8;
            // Reuse matching budgets; DSACK can change with the slot count.
            sack_limited = max_blocks != full_max_blocks
                && self
                    .receive
                    .sack_blocks(full_max_blocks)
                    .iter()
                    .flatten()
                    .count()
                    > n;
            if n != 0 {
                sack_first = blocks[0];
                options[option_len..option_len + 4].copy_from_slice(&[1, 1, 5, (2 + n * 8) as u8]);
                for (index, &(left, right)) in blocks.iter().flatten().enumerate() {
                    let offset = option_len + 4 + index * 8;
                    options[offset..offset + 4].copy_from_slice(&left.to_be_bytes());
                    options[offset + 4..offset + 8].copy_from_slice(&right.to_be_bytes());
                }
                sack_option_len = 4 + n * 8;
                option_len += sack_option_len;
            }
        }
        let tick_bytes = if tick == self.timestamp_tick {
            self.timestamp_bytes
        } else {
            0
        };
        let timestamp_credit = if timestamp.is_some() {
            self.config
                .timestamp_bytes_per_tick
                .saturating_sub(tick_bytes)
        } else {
            u32::MAX
        };
        // New data accompanying an upward probe retains the current MSS.
        // Repair copies use the smaller search floor so a failed large
        // probe can still be delivered and classified.
        let repair_mss = self
            .pmtud
            .as_ref()
            .filter(|p| p.probe.is_some())
            .map_or(self.mss, |p| {
                self.mss.min(
                    p.info
                        .search_low
                        .saturating_sub(
                            u32::from(self.ip_header_len)
                                + 20
                                + (option_len - sack_option_len) as u32,
                        )
                        .max(1) as usize,
                )
            });
        // Shared output writes only headers, but the caller's complete-packet
        // capacity still bounds the selected wire span. No header-only encoder
        // error may silently bypass a backend's packet-size bound.
        let output_limit = if shared.is_some() {
            out.len()
        } else {
            usize::MAX
        };
        let payload_mss = |mss: usize| {
            mss.saturating_sub(sack_option_len).min(
                self.path_payload_limit()
                    .min(output_limit)
                    .saturating_sub(20 + option_len),
            )
        };
        // A probe below the current estimate is validating an uncertain
        // baseline: keep its surrounding packets at the safe lower bound.
        // Larger ordinary packets could otherwise invalidate an isolated
        // probe-loss inference. Upward probes need no such reduction.
        let ordinary_mss = if self.pmtud.as_ref().is_some_and(|p| {
            p.probe
                .is_some_and(|probe| probe.size <= p.info.current_mtu)
        }) {
            repair_mss
        } else {
            self.mss
        };
        let wire_mss = payload_mss(ordinary_mss);
        // With zero credit, retain a plan so the transactional gate reports
        // exhaustion instead of consuming the pending output obligation.
        let timestamp_limit = if timestamp_credit == 0 {
            usize::MAX
        } else {
            timestamp_credit as usize
        };
        let packet_mss = wire_mss.min(timestamp_limit);
        let repair_packet_mss = payload_mss(repair_mss).min(timestamp_limit);
        let mut burst_push = false;
        //= https://www.rfc-editor.org/rfc/rfc5681#section-4.3
        //= reason=Exact receiver-driven wire observations in half_flight_segment_output_observations: ten originals at SMSS1/13/128; NewReno emits one full-SMSS retry in each of the first two recovery RTTs; non-RACK/non-PRR SACK without duplex SACK output emits five full-SMSS retries. With an out-of-order duplex byte requiring a 12-byte outgoing SACK option, fixed path budget33/SMSS13 emits 53 one-byte retries in one poll burst before any retry RTT completes; budget148/SMSS128 emits nine packets (116-byte prefixes and 12-byte suffixes), while holes remain. RFC6675 section5(C) byte gating (cwnd-pipe>=SMSS) and actual-byte pipe increments prescribe these admissions but do not prove RFC5681 section4.3 literal half-flight packet count. Retain the concrete packetization/algorithm applicability gap: no compliant packet-count limiter is specified by the selected RFC6675 algorithm, and RFC8985 section9.3 does not waive congestion control. Do not infer a strict PRR defect: zero-entry credit and zero-window epoch cancellation are already fixed; historical initial-credit/uncounted-persist compatibility was removed. General small-flight/lost-copy multi-RTT packet-count proof remains unestablished.
        //# Second, until all lost segments in the window of data in question are repaired, the number of segments transmitted in each RTT MUST be no more than half the number of outstanding segments when the loss was detected.
        // Partial evidence: byte credit and packet clipping at recovery admission;
        // the existing wire witness demonstrates the literal packet-count gap.
        let mut sack_segment = None;
        if reset.is_none()
            && !syn
            && data_live
            && !retransmit
            && !probe
            && !keepalive
            && let Some(recovery) = self.sack_recovery
        {
            if self.rack_enabled() {
                let credit = if recovery.entry_pending && self.prr.is_none() {
                    self.mss as u32
                } else {
                    self.recovery_credit(recovery)
                };
                if credit != 0 {
                    sack_segment = self
                        .rack
                        .lowest_lost((repair_packet_mss as u32).min(credit))
                        .map(|(left, right)| (left, right, false, recovery.entry_pending));
                }
            } else if recovery.entry_pending {
                // SACK is advisory: RFC 6675 entry starts at HighACK+1.
                // PRR replaces congestion control, not this selection:
                // strict credit can clip the retransmission below SMSS.
                // RACK uses RFC 8985 section 9.2 modified recovery instead.
                let range = self.data_high().after(self.snd_una).then_some((
                    self.snd_una,
                    self.snd_una.wrapping_add(
                        self.data_high()
                            .distance_from(self.snd_una)
                            .min(repair_packet_mss as u32),
                    ),
                ));
                sack_segment = range.map(|(left, right)| (left, right, false, true));
            } else if self.prr.is_some_and(|prr| prr.credit() != 0)
                || self.prr.is_none() && self.recovery_credit(recovery) >= self.mss as u32
            {
                //= https://www.rfc-editor.org/rfc/rfc6675#section-4
                //= reason=Negotiated non-RACK/non-PRR SACK; full-budget and piggybacked-SACK regressions exercise lost/new/speculative/rescue priority. IsLost uses SMSS independently of output clipping; markers commit only after encoding.
                //# NextSeg () MUST return the sequence number range of the next segment that is to be transmitted, per the following rules:
                // RFC 6675 NextSeg: lost hole, new data, speculative hole,
                // then one tail rescue. New data is selected by the live branch.
                let lost = self.next_seg_hole(recovery.high_rxt, self.mss as u32, true);
                let unsent = self.send.len() > self.snd_nxt.distance_from(self.send_base) as usize;
                let new_allowed = unsent
                    && self.snd_wnd > self.flight()
                    && self.fresh_send_allowance() != 0
                    && self.ecn_pause.is_none_or(|deadline| now >= deadline);
                if let Some((left, right)) = lost {
                    sack_segment = Some((left, right, false, false));
                } else if !new_allowed {
                    if let Some((left, right)) =
                        self.next_seg_hole(recovery.high_rxt, repair_packet_mss as u32, false)
                    {
                        sack_segment = Some((left, right, false, false));
                    } else if recovery
                        .rescue_rxt
                        .is_none_or(|end| self.snd_una.after(end))
                    {
                        sack_segment = self
                            .scoreboard
                            .tail_hole(self.snd_una, self.data_high(), repair_packet_mss as u32)
                            .map(|(left, right)| {
                                let offset = self.send.tail_record_offset(
                                    left.distance_from(self.send_base) as usize,
                                    right.distance_from(left) as usize,
                                );
                                (self.send_base.wrapping_add(offset as u32), right)
                            })
                            // A clipped rescue would not contain the highest
                            // outstanding byte but would consume RescueRxt.
                            .filter(|&(left, right)| {
                                self.retry_limit(left, right.distance_from(left))
                                    == right.distance_from(left)
                            })
                            .map(|(left, right)| (left, right, true, false));
                    }
                }
            }
        }
        // No-SACK PRR uses the same byte loss ledger for short-retry suffixes,
        // without enabling SACK's speculative/rescue selection.
        if reset.is_none()
            && !syn
            && data_live
            && !retransmit
            && !probe
            && !keepalive
            && self.sack_recovery.is_none()
            && let Some(prr) = self.prr
            && prr.credit() != 0
        {
            sack_segment = self
                .rack
                .lowest_lost((repair_packet_mss as u32).min(prr.credit()))
                .map(|(left, right)| (left, right, false, false));
        }
        // RFC 6675 §5.1 recommends filling the newly reported holes after an
        // RTO, but forbids starting another recovery phase before its boundary
        // is covered. The initial RTO retransmission still ignores all SACKs.
        let post_rto_segment = if reset.is_none()
            && !syn
            && data_live
            && !retransmit
            && !probe
            && !keepalive
            && self.sack_fallback.is_none()
            && let Some((high_rxt, boundary)) = self.sack_post_rto
            && self.congestion.cwnd().saturating_sub(self.post_rto_pipe())
                >= (self.mss as u32).min(self.congestion.cwnd())
        {
            // A timeout whose black-hole reset raised the MSS keeps cwnd
            // below one SMSS (limit_loss_window). Then the whole free window
            // is the repair segment: waiting for a full SMSS of credit would
            // leave go-back-N repair to another RTO.
            let credit = self.congestion.cwnd().saturating_sub(self.post_rto_pipe());
            let repair_packet_mss = if self.congestion.cwnd() < self.mss as u32 {
                repair_packet_mss.min(credit as usize)
            } else {
                repair_packet_mss
            };
            if self.rack_enabled() {
                self.rack.lowest_lost(repair_packet_mss as u32)
            } else if !self.sack_recovery_enabled() || self.scoreboard.ranges().is_empty() {
                // Without SACKed data above SND.UNA no hole is reported and
                // every byte below the timeout's boundary is unacknowledged:
                // resend it in order under slow start, as without SACK,
                // instead of one segment per backed-off RTO.
                let left = if high_rxt.after(self.snd_una) {
                    high_rxt
                } else {
                    self.snd_una
                };
                boundary.after(left).then(|| {
                    let count = boundary.distance_from(left).min(repair_packet_mss as u32);
                    (left, left.wrapping_add(count))
                })
            } else {
                self.scoreboard.lowest_hole(
                    high_rxt,
                    self.data_high(),
                    repair_packet_mss as u32,
                    false,
                )
            }
        } else {
            None
        };
        // Exact-range PTB repair: ahead of fresh data, behind control work and
        // due ordinary recovery (RTO/NewReno head, SACK/RACK, post-RTO, TFO).
        let ptb_segment = if reset.is_none()
            && !syn
            && !challenge
            && data_live
            && !retransmit
            && !probe
            && !keepalive
            && sack_segment.is_none()
            && post_rto_segment.is_none()
            && self.fast_open_retry.is_none()
        {
            self.ptb_segment(repair_packet_mss)
        } else {
            None
        };
        let mut seq = self.snd_nxt;
        let mut flags = ACK;
        let mut count = 0usize;
        let mut pmtu_probe = None;
        let mut new_fin = false;
        let mut retransmitted = false;
        let mut ptb_repair = false;
        if let Some((reset_seq, with_ack)) = reset {
            seq = reset_seq;
            flags = RST | if with_ack { ACK } else { 0 };
        } else if syn {
            seq = self.iss;
            flags = SYN | if self.irs.is_some() { ACK } else { 0 };
            retransmitted = self.snd_nxt != self.iss;
            if self.state == State::SynSent
                && !retransmitted
                && (fast_open_option.is_some()
                    || self.fast_open_client_policy
                        == crate::FastOpenClientPolicy::ApplicationProtected)
            {
                let limit = self
                    .fast_open_initial
                    .min(packet_mss)
                    .min(timestamp_credit.saturating_sub(1) as usize)
                    .min(
                        usize::from(
                            self.peer_mss
                                .min(self.send_mss_limit)
                                .min(self.config.user_mss.unwrap_or(u16::MAX)),
                        )
                        .saturating_sub(option_len),
                    )
                    .min(self.fresh_send_allowance());
                count = self.send.copy(0, &mut self.scratch[..limit]);
            }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1
        //# Probing of zero (offered) windows MUST be supported (MUST-36).
        } else if challenge {
            //= https://www.rfc-editor.org/rfc/rfc5961#section-3.2
            //= reason=Dedicated challenge output precedes sender work; SEQ=SND.NXT, ACK=RCV.NXT, no payload/FIN/RST/URG. Negotiated TS and ECE feedback remain; successful encode alone consumes the obligation. Missing-TS SYN challenge selection remains a separate TODO.
            //# <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            //= https://www.rfc-editor.org/rfc/rfc5961#section-4.2
            //= reason=Dedicated challenge output precedes sender work; SEQ=SND.NXT, ACK=RCV.NXT, no payload/FIN/RST/URG. Negotiated TS and ECE feedback remain; successful encode alone consumes the obligation. Missing-TS SYN challenge selection remains a separate TODO.
            //# <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            // Pure ACK at SND.NXT, ahead of all stream/recovery/probe work.
        } else if let Some((left, right)) =
            post_rto_segment.or(sack_segment.map(|(left, right, _, _)| (left, right)))
        {
            seq = left;
            let credit = self.retry_limit(seq, right.distance_from(left));
            let credit = self.prr.map_or(credit, |prr| credit.min(prr.credit()));
            count = self.send.copy(
                seq.distance_from(self.send_base) as usize,
                &mut self.scratch[..(right.distance_from(left) as usize)
                    .min(repair_packet_mss)
                    .min(credit as usize)],
            );
            retransmitted = count != 0;
        } else if let Some((left, payload, fin)) = ptb_segment {
            seq = left;
            count = self.send.copy(
                left.distance_from(self.send_base) as usize,
                &mut self.scratch[..payload],
            );
            if fin {
                flags |= FIN;
            }
            retransmitted = true;
            ptb_repair = true;
        } else if tlp {
            let offset = self.snd_nxt.distance_from(self.send_base) as usize;
            let unsent = self.send.len().saturating_sub(offset);
            //= https://www.rfc-editor.org/rfc/rfc7323#section-2.4
            //= reason=Fresh-data branch saturates latest-window credit after flight subtraction; no new data after shrinking below flight; retransmit policy never sends unsent tail.
            //# 3)  The initial transmission MUST be within the window announced by
            //# the most recent <ACK>.
            // New data needs fresh send space too; otherwise probe the tail.
            let credit = (self.snd_wnd.saturating_sub(self.flight()) as usize)
                .min(self.fresh_send_allowance());
            if unsent != 0 && credit >= unsent.min(packet_mss) {
                count = self
                    .send
                    .copy(offset, &mut self.scratch[..unsent.min(packet_mss)]);
            } else if let Some(fin) = self.fin_sequence.filter(|&fin| {
                fin.at_or_after(self.snd_una) && (self.fin_standalone || fin == self.snd_una)
            }) {
                // RFC8985 section7.3 selects the highest-sequence *segment*,
                // including a standalone FIN (RFC9293 section3.4). Keep FIN
                // out of the payload ledger and require peer-window room.
                if fin.distance_from(self.snd_una) < self.snd_wnd {
                    seq = fin;
                    flags |= FIN;
                    retransmitted = true;
                }
            } else if let Some((left, right)) = self.rack.tail_segment(repair_packet_mss as u32) {
                seq = left;
                let limit = self.retry_limit(left, right.distance_from(left)) as usize;
                count = self.send.copy(
                    seq.distance_from(self.send_base) as usize,
                    &mut self.scratch[..limit],
                );
                retransmitted = count != 0;
                if count != 0
                    && self.fin_sequence == Some(seq.wrapping_add(count as u32))
                    && seq.distance_from(self.snd_una).saturating_add(count as u32) < self.snd_wnd
                {
                    flags |= FIN;
                }
            }
        } else if data_live && self.fast_open_retry.is_some() && !retransmit && !probe {
            let (start, end) = self.fast_open_retry.unwrap();
            seq = start;
            let limit = end.distance_from(start) as usize;
            // The SYN flight may exceed the newly negotiated cwnd. Bound the
            // repair cursor relative to UNA, not the entire original flight:
            // subtracting that flight would prevent even the first repair.
            let mut credit = self
                .snd_wnd
                .min(self.congestion.cwnd())
                .saturating_sub(start.distance_from(self.snd_una));
            if let Some(prr) = self.prr {
                credit = credit.min(prr.credit());
            } else if let Some(recovery) = self.sack_recovery {
                credit = credit.min(self.recovery_credit(recovery));
            }
            count = self.send.copy(
                start.distance_from(self.send_base) as usize,
                &mut self.scratch[..limit.min(repair_packet_mss).min(credit as usize)],
            );
            retransmitted = count != 0;
        } else if probe && self.flight() == 0 {
            // Empty-flight window discovery must not create an unacknowledged
            // stream byte. An old-sequence ACK elicits the peer's current ACK
            // and window, without advancing NXT or entering the loss ledger.
            // This selects Linux-style control probing rather than RFC9293
            // section3.8.6.1's data-octet description; ordinary outstanding
            // data below retains its actual retransmission and RTO history.
            seq = if urgent_probe {
                self.snd_una
            } else {
                self.snd_una.wrapping_add(u32::MAX)
            };
        } else if retransmit || probe {
            seq = self.snd_una;
            let offset = seq.distance_from(self.send_base) as usize;
            let limit = if probe {
                1
            } else {
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
                //= reason=Retransmits the in-window flight by default; the new-data branch saturates usable credit at zero after shrink.
                //# If this happens, the sender SHOULD NOT send new data (SHLD-15), but
                //# SHOULD retransmit normally the old unacknowledged data between
                //# SND.UNA and SND.UNA+SND.WND (SHLD-16).
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
                //= reason=Optional retransmission is bounded by flight; user_deadline excludes responsive shrink/backoff from failure time.
                //# The sender MAY also
                //# retransmit old data beyond SND.UNA+SND.WND (MAY-7), but SHOULD NOT
                //# time out the connection if data beyond the right window edge is not
                //# acknowledged (SHLD-17).
                // Scope: Scaled retry limits cannot be overridden by configuration.
                //= https://www.rfc-editor.org/rfc/rfc7323#section-2.4
                //= reason=Subsequent scaled retries clip to the current window unless original-valid sub-scale permission applies. retransmit_beyond_window applies only without scaling; missing scaled metadata falls back to the current window.
                //# 5)  Subsequent retransmissions MAY only be sent if they are within
                //# the window announced by the most recent <ACK>.
                // Scope: Capacity-backed original identity and per-coverage successful retries implement first/sub-scale permission; normal retries share pure planning and post-encode commit, with persist separate.
                //= https://www.rfc-editor.org/rfc/rfc7323#section-2.4
                //= reason=Capacity-backed original identity and per-coverage successful retries implement first/sub-scale permission; all normal retry paths share pure planning and post-encode commit, while zero-window persist is separate.
                //# 4)  On first retransmission, or if the sequence number is out of
                //# window by less than 2^Rcv.Wind.Shift, then do normal
                //# retransmission(s) without regard to the receiver window as long
                //# as the original segment was in window when it was sent.
                let boundary = if self.consecutive_timeouts != 0 {
                    self.rack
                        .head_transmission(seq)
                        .map_or(self.flight(), |(end, _)| end.distance_from(seq))
                } else {
                    self.flight()
                };
                self.retry_limit(seq, (repair_packet_mss as u32).min(boundary)) as usize
            };
            let limit = if probe {
                limit
            } else {
                self.prr
                    .map_or(limit, |prr| limit.min(prr.credit() as usize))
            };
            count = self.send.copy(offset, &mut self.scratch[..limit]);
            retransmitted = seq != self.snd_nxt;
            if self.fin_sequence == Some(seq.wrapping_add(count as u32))
                && !probe
                && (self.consecutive_timeouts == 0
                    || count == 0
                    || self
                        .rack
                        .head_transmission(seq)
                        .is_some_and(|(_, sent)| self.fin_sent_at.is_some_and(|fin| fin <= sent)))
                && self.snd_wnd > count as u32
            {
                flags |= FIN;
            } else if count == 0 {
                seq = self.snd_nxt.wrapping_add(u32::MAX);
            }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
        //= reason=The default has no payload; send_garbage explicitly selects the initialized compatibility octet.
        //# An implementation SHOULD send a keep-alive segment with no data
        //# (SHLD-12); however, it MAY be configurable to send a keep-alive
        //# segment containing one garbage octet (MAY-6), for compatibility with
        //# erroneous TCP implementations.
        } else if keepalive {
            seq = self.snd_nxt.wrapping_add(u32::MAX);
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
            //# it MAY be configurable to send a keep-alive segment containing one
            //# garbage octet (MAY-6), for compatibility with erroneous TCP implementations.
            if self
                .config
                .keepalive
                .is_some_and(|config| config.send_garbage)
            {
                self.scratch[0] = 0;
                count = 1;
            }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.4
        //= reason=SYN-ACK has output priority; FIN and FIN-WAIT-1 commit only after successful encoding.
        //# If no SENDs have been issued and there is no pending data to send, then form a
        //# FIN segment and send it, and enter FIN-WAIT-1 state; otherwise, queue for
        //# processing after entering ESTABLISHED state.
        } else if self.state == State::SynReceived
            && self.shutdown
            && !self.send_issued
            && self.send.len() == 0
            && self.fin_sequence.is_none()
            && self.snd_wnd.min(self.congestion.cwnd()) > self.flight()
        {
            seq = self.iss.wrapping_add(1);
            flags |= FIN;
            new_fin = true;
        } else if (live || early_response)
            && (!pacing_blocked
                || self.send.len() <= self.snd_nxt.distance_from(self.send_base) as usize)
            && !(pacing_blocked && self.retx_pending)
        {
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
            //= reason=SendBuffer coalesces ordinary writes; explicit EOR constrains local coalescing, not stream framing.
            //# The transmitter SHOULD collapse successive bits when it packetizes data,
            //# to send the largest possible segment (SHLD-27).
            let offset = self.snd_nxt.distance_from(self.send_base) as usize;
            let unsent = self.send.len().saturating_sub(offset);
            let idle_restart =
                self.flight() == 0 && now.saturating_sub(self.last_sent) >= self.rto();
            let cwnd = if idle_restart {
                self.congestion.cwnd().min(self.restart_window())
            } else {
                self.congestion.cwnd()
            };
            //= https://www.rfc-editor.org/rfc/rfc3042#section-2
            //= reason=Local cwnd_limit extends admission, never stored cwnd; before/after ACK and successful output invariance asserted for ordinary and negotiated-SACK Limited Transmit.
            //# The congestion window (cwnd) MUST NOT be changed when these new segments are transmitted.
            //= https://www.rfc-editor.org/rfc/rfc3042#section-2
            //= reason=Ordinary admission uses cwnd+2*SMSS minus flight. RFC6675 SACK pre-recovery admission recomputes pipe; sack_limited_transmit_repeats_setpipe_on_same_ack checks its two-SMSS original-flight headroom, option clipping and window exhaustion.
            //# The amount of outstanding data would remain less than or equal to the congestion window
            //# plus 2 segments. In other words, the sender can only send two segments beyond the
            //# congestion window (cwnd).
            let cwnd_limit = if self.limited_pending {
                cwnd.saturating_add(2 * self.mss as u32)
            } else {
                cwnd
            };
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
            //# If this happens, the sender SHOULD NOT send new data (SHLD-15),
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
            //# However, a sending TCP peer MUST
            //# be robust against window shrinking, which may cause the "usable
            //# window" (see Section 3.8.6.2.1) to become negative (MUST-34).
            //= https://www.rfc-editor.org/rfc/rfc3042#section-2
            //= reason=All fresh-data branches subtract sequence-space flight from peer window. limited_transmit_window_queue_and_failed_output and sack_limited_transmit_repeats_setpipe_on_same_ack assert exhausted and one-segment headroom.
            //# The receiver's advertised window allows the transmission of the segment.
            //= https://www.rfc-editor.org/rfc/rfc9406#section-3
            //= reason=Ordinary SS/CSS/CA uses min(cwnd,rwnd) minus sequence flight. Separately selected RFC3042/RFC6675/RFC8985/RFC9937 recovery/probe policies retain their own admission rules, not an unconditional sequence-edge claim.
            //# At any given time, a TCP MUST NOT
            //# send data with a sequence number higher than the sum of the
            //# highest acknowledged sequence number and the minimum of the cwnd
            //# and rwnd.
            let usable = if early_response {
                // RFC6928 section2 explicitly covers data during the handshake.
                // Honor the endpoint-selected IW policy, including path fallback;
                // current cwnd still bounds loss/retry reductions independently.
                let initial = self.initial_window();
                self.snd_wnd
                    .saturating_sub(self.flight())
                    .min(cwnd.min(initial).saturating_sub(self.data_flight()))
                    as usize
            } else if self.sack_recovery.is_none()
                && let Some(prr) = self.prr
            {
                self.snd_wnd.saturating_sub(self.flight()).min(prr.credit()) as usize
            } else if let Some(recovery) = self.sack_recovery {
                if recovery.entry_pending || self.recovery_credit(recovery) < self.mss as u32 {
                    0
                } else {
                    self.snd_wnd
                        .saturating_sub(self.flight())
                        .min(self.recovery_credit(recovery)) as usize
                }
            } else if self.sack_post_rto.is_some()
                && self.sack_fallback.is_none()
                && self.sack_recovery_enabled()
            {
                let pipe = self.post_rto_pipe();
                if cwnd.saturating_sub(pipe) >= self.mss as u32 {
                    self.snd_wnd
                        .saturating_sub(self.flight())
                        .min(cwnd.saturating_sub(pipe)) as usize
                } else {
                    0
                }
            } else if self.sack_recovery_enabled() && self.limited_pending {
                let pipe = self.recovery_pipe(self.snd_una);
                if cwnd.saturating_sub(pipe) >= self.mss as u32 {
                    self.snd_wnd
                        .saturating_sub(self.flight())
                        .min(cwnd.saturating_sub(pipe)) as usize
                } else {
                    0
                }
            } else {
                self.snd_wnd.min(cwnd_limit).saturating_sub(self.flight()) as usize
            };
            let initial_room = self.initial_pacing_room();
            let usable = if initial_room != 0 {
                usable.min(initial_room as usize)
            } else {
                usable
            };
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
            //# However, a TCP implementation SHOULD send a maximum-sized segment
            //# whenever possible (SHLD-28) to improve performance (see Section
            //# 3.8.6.2.1).
            // Plan FIN admission before Nagle so an admissible final short
            // payload can close immediately, as in Linux's final-FIN exemption.
            // FIN occupies sequence space, not data space (RFC 9293
            // section 3.4). RFC 5681 section 2 and RFC 9937 section 3
            // constrain data: a standalone FIN need not wait for cwnd.
            // Keep peer-window admission and the existing PRR gate.
            let fin_admissible = self.shutdown
                && self.fin_sequence.is_none()
                && self.snd_wnd.saturating_sub(self.flight()) as usize > unsent
                && (usable > unsent || unsent == 0 && self.prr.is_none())
                && matches!(self.state, State::Established | State::CloseWait);
            // FIN consumes no send space; payload, probes and GSO totals do.
            let usable = usable.min(self.fresh_send_allowance());
            //= https://www.rfc-editor.org/rfc/rfc4821#section-7.4
            //# It has no outstanding probes or losses.
            // Leading/trailing retransmissions are tracked through cumulative
            // delivery, so an isolated loss is never inferred prematurely.
            //= https://www.rfc-editor.org/rfc/rfc4821#section-7.4
            //# Before sending a probe, the flow MUST meet at least the following conditions:
            //= https://www.rfc-editor.org/rfc/rfc4821#section-7.4
            //# o It has no outstanding probes or losses.
            // The administrative target (armed once per administrative value)
            // passes every existing admission condition; when it does not
            // leave, the blocking precondition is recorded.
            let admin_target = self.pmtud.as_ref().and_then(|p| p.administrative_target());
            let mut admin_deferral = None;
            let candidate = self.pmtud.as_ref().and_then(|p| {
                let target = if let Some(path) = &self.managed_path {
                    if p.discovery_disabled() {
                        admin_deferral = Some(crate::pmtud::AdministrativeDeferral::DiscoveryDisabled);
                        return None;
                    }
                    if now < path.snapshot.retry_not_before() {
                        admin_deferral = Some(crate::pmtud::AdministrativeDeferral::Hold);
                        return None;
                    }
                    p.target_for_network(path.snapshot.ip_packet_budget().ok()?)
                } else {
                    p.target()
                };
                if target.is_none() {
                    admin_deferral = Some(crate::pmtud::AdministrativeDeferral::Cooldown);
                }
                target
            }).filter(|&size| {
                self.managed_path
                    .as_ref()
                    .is_none_or(|path| size <= path.snapshot.first_hop_mtu())
            }).filter(|_| {
                let recovering = self.congestion.in_recovery()
                    || self.sack_recovery.is_some()
                    || self.sack_post_rto.is_some()
                    || self.prr.is_some()
                    || self.consecutive_timeouts != 0
                    || self.rack.counts().lost != 0
                    || self.retx_pending
                    || self.limited_pending;
                if recovering {
                    admin_deferral = Some(crate::pmtud::AdministrativeDeferral::LossRecovery);
                }
                !early_response
                    && self.rtt.srtt().is_some()
                    && !pacing_blocked
                    && !recovering
                    && !self.shutdown
                    && self.ecn_pause.is_none()
                    && !self.cork
                    && !self.more
            });
            // The targeted size is clipped (not dropped) by transport bounds:
            // peer and user MSS, the configured payload limit, allocation.
            let candidate = candidate.and_then(|size| {
                // Pmtud::target yields the armed administrative target first.
                let targeted = admin_target.is_some()
                    && self.pmtud.as_ref().and_then(|p| p.target()) == Some(size);
                if !targeted {
                    return Some(size);
                }
                let base = if self.tuple.local.is_ipv4() { 20 } else { 40 };
                let transport = (u32::from(
                    self.peer_mss
                        .min(self.send_mss_limit)
                        .min(self.config.user_mss.unwrap_or(u16::MAX)),
                ) + base + 20)
                    .min(u32::from(self.config.send_ip_payload_limit) + u32::from(self.ip_header_len))
                    .min(self.scratch.len() as u32 + u32::from(self.ip_header_len) + 20 + option_len as u32);
                let low = self.pmtud.as_ref().map_or(0, |p| p.info.search_low);
                if size <= transport {
                    Some(size)
                } else {
                    (transport > low).then_some(transport)
                }
            });
            //= https://www.rfc-editor.org/rfc/rfc4821#section-6.2
            //= reason=TCP probes use real queued stream bytes, respecting record boundary and allocation; no synthetic padding or control-only TCP size probe.
            //# These techniques do not work for TCP, because there is not a separate length
            //# field or other mechanism to differentiate between padding and real payload
            //# data. With TCP the only approach is to send additional payload data in an
            //# over-sized segment. There are at least two variants of this approach,
            //# discussed in Section 10.1.

            //= https://www.rfc-editor.org/rfc/rfc4821#section-10.1
            //= reason=TCP probes use real queued stream bytes, respecting record boundary and allocation; no synthetic padding or control-only TCP size probe.
            //# TCP has no mechanism to distinguish in-band data from padding. Therefore,
            //# TCP must generate probes by appropriately segmenting data. There are two
            //# approaches to segmentation: overlapping and non- overlapping.

            //= https://www.rfc-editor.org/rfc/rfc4821#section-7.4
            //= reason=Admission requires probe payload plus three MSS of queued/window credit, measured RTT and timestamp/pacing credit. This test asserts absent probe for insufficient window/queue/RTT and bounded paced output.
            //# o The available window is greater than the probe size.

            //= https://www.rfc-editor.org/rfc/rfc4821#section-7.4
            //= reason=Admission requires probe payload plus three MSS of queued/window credit, measured RTT and timestamp/pacing credit. This test asserts absent probe for insufficient window/queue/RTT and bounded paced output.
            //# o For a protocol using in-band data for probing, enough data is available to
            //# send the probe.

            //= https://www.rfc-editor.org/rfc/rfc4821#section-7.4
            //= reason=Admission requires probe payload plus three MSS of queued/window credit, measured RTT and timestamp/pacing credit. This test asserts absent probe for insufficient window/queue/RTT and bounded paced output.
            //# In addition, the timely loss detection algorithms in most protocols have
            //# pre-conditions that SHOULD be satisfied before sending a probe. For example,
            //# TCP Fast Retransmit is not robust unless there are sufficient segments
            //# following a probe; that is, the sender SHOULD have enough data queued and
            //# sufficient receiver window to send the probe plus at least Tcprexmtthresh
            //# [RFC2760] additional segments. This restriction may inhibit probing in some
            //# protocol states, such as too close to the end of a connection, or when the
            //# window is too small.

            let candidate = candidate.and_then(|size| {
                let payload = size
                    .checked_sub(u32::from(self.ip_header_len) + 20 + option_len as u32)?
                    as usize;
                let trailing = self.mss.checked_mul(3)?;
                let needed = payload.checked_add(trailing)?;
                let paced = self.config.pacing.is_none_or(|p| {
                    let burst = p.max_burst_segments * self.mss as u32;
                    self.pacer
                        .deadline(now, burst, payload.min(burst as usize))
                        .is_none()
                });
                let base = if self.tuple.local.is_ipv4() { 20 } else { 40 };
                let ceiling = u32::from(
                    self.peer_mss
                        .min(self.send_mss_limit)
                        .min(self.config.user_mss.unwrap_or(u16::MAX)),
                ) + base
                    + 20;
                (size <= ceiling
                    && size
                        <= u32::from(self.config.send_ip_payload_limit)
                            + u32::from(self.ip_header_len)
                    && payload > 0
                    && payload <= self.scratch.len()
                    && payload <= output_limit.saturating_sub(20 + option_len)
                    && usable >= needed
                    && paced
                    && unsent >= needed
                    && timestamp_credit as usize >= payload
                    && self.send.selection_len(offset, payload) == payload
                    && self.send.record_len(offset, payload) == payload)
                    .then_some((size, payload, trailing))
            });
            let wire_mss = candidate.map_or(wire_mss, |(_, payload, _)| payload);
            let packet_mss = candidate.map_or(packet_mss, |(_, payload, _)| payload);
            let record = self.send.record_len(offset, unsent.min(wire_mss));
            count = record.min(packet_mss).min(usable);
            let selected = self.send.selection_len(offset, count);
            let descriptor_limited = selected < count;
            count = selected;
            pmtu_probe = candidate.filter(|(_, payload, _)| count == *payload);
            if admin_target.is_some()
                && pmtu_probe.is_none()
                && let Some(p) = &mut self.pmtud
            {
                p.defer_administrative(
                    admin_deferral.unwrap_or(crate::pmtud::AdministrativeDeferral::DataOrWindow),
                );
            }
            let flush_credit = self
                .cork_flush
                .filter(|&end| end.after(self.snd_nxt))
                .map_or(0, |end| end.distance_from(self.snd_nxt) as usize);
            // Linux's non-tail EOR buffers can be emitted independently. This
            // local coalescing constraint does not expose TCP record framing.
            let complete_record = record < unsent && count == record;
            let flushing = flush_credit != 0 || complete_record;
            let urgent = self.snd_up.is_some_and(|end| end.after(seq));
            if count < packet_mss && !urgent && self.sack_recovery.is_none() {
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.4
                //# A TCP implementation SHOULD implement the Nagle algorithm to
                //# coalesce short segments (SHLD-7).
                let final_fin =
                    fin_admissible && count == unsent && (count as u32) < timestamp_credit;
                let nagle_flight = if early_response {
                    self.data_flight()
                } else {
                    self.flight()
                };
                let nagle = !flushing && !final_fin && self.config.nagle && nagle_flight != 0;
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.2.1
                //# A TCP implementation MUST include a SWS avoidance algorithm in the
                //# sender (MUST-38).
                // A managed C below one segment is the largest payload this
                // connection can ever send: a segment it alone shortens is
                // not held, since waiting cannot enlarge it.
                let largest = if self.managed_path.is_some() {
                    record.min(self.send_space())
                } else {
                    record
                };
                let sws = !flushing
                    && !descriptor_limited
                    && !self.sws_override
                    && count < largest
                    && count < (self.max_snd_wnd / 2) as usize;
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
                //# When an application issues a series of SEND calls without setting
                //# the PUSH flag, the TCP implementation MAY aggregate the data
                //# internally without sending it (MAY-16).
                let aggregate = !flushing
                    && !self.shutdown
                    && !self.sws_override
                    && !self.send.pushed(offset, unsent);
                if nagle || sws || aggregate {
                    count = 0;
                }
            }
            // Timestamp/credit clipping does not turn a partial frame into
            // a full-MSS exception to CORK.
            if count < wire_mss
                && (self.cork || self.more)
                && !self.shutdown
                && !urgent
                && !complete_record
            {
                count = count.min(flush_credit);
            }
            if self.ecn_pause.is_some_and(|deadline| now < deadline) {
                count = 0;
            }
            // Startup retains the window-exhaustion flush boundary: ACK
            // progress is needed to release the next flight. After congestion
            // reduction, a singleton is not an extra aggregation group; avoid
            // forcing its flush unless the application requested PUSH.
            let startup_flush = self.prr.is_none()
                && !self.congestion.in_recovery()
                && self.congestion.ecn_prr_end().is_none()
                && cwnd < self.congestion.ssthresh();
            // Extend only an already-admissible full-sized fresh segment.
            // Recovery (PRR, RFC 6675 pipe, RACK losses) admits new data from
            // a byte credit each segment consumes, and sending new data marks
            // no loss for a repair to take first, so a group within the credit
            // is what scalar selection sends: Linux likewise sends TSO skbs
            // within PRR's quota. Repairs retain their separate, immutable
            // reservation/undo policy.
            // Keep protocol scratch/MTU unchanged: only the first segment is
            // encoded here; separately reserved storage retains the whole range.
            // TX timestamp requests stay with their target bytes. Scheduled
            // is recorded at this selection over the whole range, as for its
            // segments selected one by one now, and Acknowledged by the ACK
            // covering the target. A Transmit phase is completed by the
            // backend for the packet whose token names its target, and the
            // aggregate interface carries none (Linux's tcp_gso_tstamp moves
            // the request to the one segment holding the byte instead), so
            // a group ends before that segment, which leaves scalar.
            let position = self.acknowledged + offset as u64;
            let stamp_room = match self.tx_timestamps.pending_transmit_from(position) {
                Some(target) => {
                    let before = usize::try_from(target - position).unwrap_or(usize::MAX);
                    before / wire_mss.max(1) * wire_mss
                }
                None => usize::MAX,
            };
            let group_eligible = count == wire_mss
                && count != 0
                && packet_mss == wire_mss
                && reserve
                && !urgent
                && !self.retx_pending
                && !self.tlp_pending
                && !self.probe_pending
                && candidate.is_none()
                && self.rack.valid()
                && !self.limited_pending
                && !self.pacing_enabled()
                && stamp_room != 0
                //= https://www.rfc-editor.org/rfc/rfc2883#section-4
                //# (2) Each duplicate contiguous sequence of data received is reported
                //# in at most one D-SACK block.
                // Every segment of a range repeats its options, as Linux TSO
                // repeats the skb's: ordinary SACK blocks may repeat, a
                // D-SACK block may not.
                && (sack_option_len == 0 || !self.receive.dsack_pending())
                && gso.is_some();
            if group_eligible {
                let buffer = gso.as_ref().unwrap();
                let bounded = unsent
                    .min(usable)
                    .min(timestamp_credit as usize)
                    .min(buffer.limits.max_bytes)
                    .min(buffer.payload.len())
                    .min(stamp_room);
                let group_limit = if self.config.output_group_flush {
                    // Aim for at most 1ms of estimated send work per group.
                    // Rate estimation sizes batches even when pacing is off;
                    // it never marks this flight as paced or grants credit.
                    // Two full segments are the minimum useful aggregation,
                    // not an instruction to put PSH on every second packet.
                    let rtt_us = self
                        .config
                        .timebase
                        .us_from_ticks(self.rtt.srtt().unwrap_or(self.rtt.rto()))
                        .max(1);
                    let gain = if cwnd < self.congestion.ssthresh() {
                        200u128
                    } else {
                        120
                    };
                    let bytes = u128::from(cwnd.max(self.data_flight())) * gain * 1000
                        / (u128::from(rtt_us) * 100);
                    let target = usize::try_from(bytes / wire_mss as u128)
                        .unwrap_or(usize::MAX)
                        .max(2);
                    target.min((cwnd as usize / wire_mss / 2).max(1))
                } else {
                    buffer.limits.max_segments
                };
                let record = self.send.record_len(offset, bounded);
                let limit = buffer.limits.max_segments.min(group_limit);
                let full = (record / wire_mss).min(limit);
                // A short last segment ends the group, as it may end a Linux
                // TSO skb (tcp_mss_split_point), exactly when scalar selection
                // sends it right after the full ones, which it sees in flight:
                // it completes a record, or it ends the queue and neither
                // Nagle, aggregation nor CORK holds it (SWS cannot: it is all
                // there is). A window- or credit-clipped remainder stays.
                let tail = record - full * wire_mss;
                let sent = full * wire_mss;
                let flush = flush_credit > sent;
                let tail_fin = fin_admissible && ((sent + tail) as u32) < timestamp_credit;
                // SACK-based recovery admits a segment only with a full
                // SMSS of credit left (RFC 6675 section 5, rule C).
                let credit_left = !(self.sack_recovery.is_some()
                    || self.sack_post_rto.is_some()
                    || self.limited_pending)
                    || usable.saturating_sub(sent) >= self.mss;
                let tail_sendable = credit_left
                    && (record < bounded
                        || record == unsent
                            && !(self.config.nagle && !flush && !tail_fin)
                            && (flush
                                || self.shutdown
                                || self.sws_override
                                || self.send.pushed(offset + sent, tail))
                            && (!(self.cork || self.more)
                                || self.shutdown
                                || flush_credit.saturating_sub(sent) >= tail));
                let tail = if full == record / wire_mss && full < limit && tail_sendable {
                    tail
                } else {
                    0
                };
                let mut segments = full + usize::from(tail != 0);
                let mut total = sent + tail;
                // Scalar selection pushes the segment that fills the window
                // or cwnd (burst_push below). PRR admits by its own credit, so
                // that edge can fall inside the group, which then ends there.
                let edge = (self.snd_wnd.min(cwnd).saturating_sub(self.flight())) as usize;
                if (!self.config.output_group_flush || startup_flush)
                    && edge < total
                    && edge >= wire_mss
                    && edge.is_multiple_of(wire_mss)
                    && self
                        .send
                        .pushed(offset + edge - wire_mss, unsent - edge + wire_mss)
                {
                    segments = edge / wire_mss;
                    total = edge;
                }
                let last = if !total.is_multiple_of(wire_mss) {
                    tail
                } else {
                    wire_mss
                };
                // A PUSH in an intermediate physical segment must not migrate.
                // Leave such selections scalar, including successive PUSH writes.
                if segments >= 2 && !self.send.pushed(offset, total - last) {
                    count = total;
                    segmentation = Some(crate::TransmitSegmentation {
                        payload_len: total,
                        segment_payload_len: wire_mss,
                        tcp_header_len: 20 + option_len,
                        terminal_flags: 0,
                    });
                }
            }
            burst_push = (!self.config.output_group_flush || !group_eligible || startup_flush)
                && count != 0
                && self.flight().saturating_add(count as u32) == self.snd_wnd.min(cwnd)
                && self.send.pushed(offset, unsent);
            if segmentation.is_none() {
                count = self.send.copy(offset, &mut self.scratch[..count]);
            } else {
                // The reservation's payload, whose first segment is encoded
                // from it below: copied from the send buffer once.
                let buffer = gso.as_mut().unwrap();
                self.send.copy(offset, &mut buffer.payload[..count]);
            }
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.4
            //# Queue this until all preceding SENDs have been segmentized, then form a
            //# FIN segment and send it.
            if fin_admissible && count == unsent {
                flags |= FIN;
                new_fin = true;
            }
        }
        // A data turn blocked by cwnd/window/SWS is still a full-report ACK,
        // never a budget-reduced empty packet that can perpetuate ACK work.
        if count == 0 && sack_limited && self.ack_pending {
            option_len -= sack_option_len;
            let available =
                (40 - option_len).min((self.path_payload_limit()).saturating_sub(20 + option_len));
            let blocks = self.receive.sack_blocks(available.saturating_sub(4) / 8);
            let n = blocks.iter().flatten().count();
            sack_first = blocks[0];
            sack_option_len = if n == 0 { 0 } else { 4 + n * 8 };
            if n != 0 {
                options[option_len..option_len + 4].copy_from_slice(&[1, 1, 5, (2 + n * 8) as u8]);
                for (index, &(left, right)) in blocks.iter().flatten().enumerate() {
                    let offset = option_len + 4 + index * 8;
                    options[offset..offset + 4].copy_from_slice(&left.to_be_bytes());
                    options[offset + 4..offset + 8].copy_from_slice(&right.to_be_bytes());
                }
                option_len += sack_option_len;
            }
            sack_limited = false;
        }
        // Data can fill the tick without room for FIN. Commit the data now and
        // leave FIN queued (or outstanding on retransmission) for another tick.
        if flags & FIN != 0 && count != 0 && count as u32 >= timestamp_credit {
            flags &= !FIN;
            new_fin = false;
        }
        let retransmit_burst = (retransmitted && count != 0 && !probe && !keepalive).then(|| {
            let previous = self.retransmit_burst.filter(|&(end, _)| end == seq);
            (
                seq.wrapping_add(count as u32),
                previous
                    .map_or(0, |(_, bytes)| bytes)
                    .saturating_add(count as u32),
            )
        });
        if self.sack_receive
            && retransmit_burst.is_some_and(|(_, bytes)| bytes > repair_packet_mss as u32)
        {
            let offset = seq.distance_from(self.send_base) as usize;
            let end = seq.wrapping_add(count as u32);
            let queued_end = self.send_base.wrapping_add(self.send.len() as u32);
            // Flush the final multi-segment recovery burst, analogous to Linux's
            // GSO PUSH policy. Single-segment repairs retain their original marks.
            burst_push = self.scoreboard.unsacked_bytes(end, queued_end) == 0
                && self
                    .send
                    .pushed(offset, self.send.len().saturating_sub(offset));
        }
        let offset = seq
            .wrapping_add(u32::from(syn))
            .distance_from(self.send_base) as usize;
        let application_push = count != 0 && !keepalive && self.send.pushed(offset, count);
        let group_push = self.config.output_group_flush
            && segmentation.is_some()
            && self
                .send
                .pushed(offset, self.send.len().saturating_sub(offset));
        if count != 0 && !keepalive && (burst_push || application_push || group_push) {
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
            // Scope: write supplies automatic PUSH; explicit no-PUSH SENDs are
            // supported separately. Group hints never suppress the final mark.
            //# MUST set the PSH bit in the last buffered segment (i.e., when there is
            //# no more queued data to be sent) (MUST-61).
            flags |= PSH;
        }
        if reset.is_none()
            && !syn
            && count == 0
            && flags & FIN == 0
            && !probe
            && !keepalive
            && !self.ack_pending
            && !challenge
        {
            return Ok(None);
        }
        if self.state == State::Closed && reset.is_none() {
            return Ok(None);
        }
        let mut urgent_pointer = 0;
        if !challenge
            && reset.is_none()
            && !syn
            && let Some(end) = self.snd_up
        {
            let distance = end.distance_from(seq);
            if distance != 0 && distance < 1 << 31 {
                flags |= URG;
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.5
                //= reason=Long urgent runs use an advancing capped wire pointer; absolute receive offsets track consumption.
                //# A TCP implementation MUST support a sequence of urgent data of any
                //# length (MUST-31) [19].
                //= https://www.rfc-editor.org/rfc/rfc7323#appendix-A
                //= reason=Appendix A suggestion implemented as saturating wire offset; retained full urgent endpoint lets later packets advance receiver urgent pointer without leaving urgent mode.
                //# If it does overflow, than a value of 65535
                //# should be inserted into the Urgent Pointer.
                urgent_pointer = distance.min(65535) as u16;
            }
        }
        let setup = syn
            && self.config.ecn
            && !self.syn_timed_out
            && !self.ecn_sent_plain
            && (self.state == State::SynSent && self.config.ecn_initiate
                || self.ecn_peer_setup && !self.ecn_peer_plain);
        let fresh_data = reset.is_none()
            && !syn
            && !retransmitted
            && !retransmit
            && !probe
            && !keepalive
            && count != 0;
        // Only actual stream output can restart an idle data flight. An
        // empty window probe preserves idle age and deferred ECN feedback.
        let idle_restart = !keepalive
            && count != 0
            && self.flight() == 0
            && now.saturating_sub(self.last_sent) >= self.rto();
        let idle_reduction = idle_restart && self.congestion.cwnd() > self.restart_window();
        //= https://www.rfc-editor.org/rfc/rfc3168#section-5.2
        //= reason=Shared fresh-data output predicate excludes setup, pure ACK, reset, FIN-only, keepalive, persist and retransmitted packets. Fresh FIFO bytes (including Limited Transmit, recovery new data, data/FIN and original TLP) advance tracked sequence space and remain subject to loss recovery. Assertions cover special ECT/Not-ECT outputs, original TLP loss RTO and corrupted CE loss congestion response; no router marking claim.
        //# To ensure the reliable delivery of the congestion indication
        //# of the CE codepoint, an ECT codepoint MUST NOT be set in a packet
        //# unless the loss of that packet in the network would be detected by
        //# the end nodes and interpreted as an indication of congestion.
        // Actor/condition: TCP sender and IP adapter; all ECT outputs.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-5.2
        //= reason=TCP output policy evidence: fresh ECT(0), setup and pure ACK Not-ECT are asserted at endpoint metadata boundary; external adapters must preserve that metadata. No router/AQM behavior is claimed.
        //# We believe that this aspect is still
        //# the subject of research, so this document specifies that at this
        //# time, "pure" ACK packets MUST NOT indicate ECN-Capability.
        // Actor/condition: TCP sender; pure ACK output.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-5
        //= reason=TCP output policy evidence: fresh ECT(0), setup and pure ACK Not-ECT are asserted at endpoint metadata boundary; external adapters must preserve that metadata. No router/AQM behavior is claimed.
        //# Protocols and senders that only require a single ECT codepoint SHOULD
        //# use ECT(0).
        // Actor/condition: TCP sender; single ECT codepoint policy.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1.1
        //= reason=Optional timeout fallback selected; asserts plain setup after timeout and ECT suppression, retaining earlier receive commitment. No RST-triggered retry claim.
        //# A host that receives no reply to an ECN-setup SYN within the normal
        //# SYN retransmission timeout interval MAY resend the SYN and any
        //# subsequent SYN retransmissions with CWR and ECE cleared.
        // Actor/condition: TCP setup initiator/responder; no setup reply before SYN retransmission timeout.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
        //= reason=Responder ECN setup only after peer setup: endpoint asserts setup SYN yields ECE-only SYN-ACK; opt-out/plain SYN yields plain SYN-ACK. No ECT on handshake output.
        //# * If a host has received an ECN-setup SYN packet, then it MAY send
        //# an ECN-setup SYN-ACK packet.
        // Actor/condition: TCP setup responder; received ECN-setup SYN.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
        //= reason=Responder ECN setup only after peer setup: endpoint asserts setup SYN yields ECE-only SYN-ACK; opt-out/plain SYN yields plain SYN-ACK. No ECT on handshake output.
        //# Otherwise, it MUST NOT send an
        //# ECN-setup SYN-ACK packet.
        // Actor/condition: TCP setup responder; no received ECN-setup SYN.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
        //= reason=Setup/opt-out evidence: exact SYN/SYN-ACK flag interpretation, plain setup forbids ECT, all SYN-ACK ECE/CWR forms are asserted. Earlier receive commitment is separately retained.
        //# * A host MUST NOT set ECT on data packets unless it has sent at
        //# least one ECN-setup SYN or ECN-setup SYN-ACK packet, and has
        //# received at least one ECN-setup SYN or ECN-setup SYN-ACK packet,
        //# and has sent no non-ECN-setup SYN or non-ECN-setup SYN-ACK
        //# packet.
        // Actor/condition: TCP sender; ECT eligibility after bilateral setup with no local plain setup.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
        //= reason=Setup/opt-out evidence: exact SYN/SYN-ACK flag interpretation, plain setup forbids ECT, all SYN-ACK ECE/CWR forms are asserted. Earlier receive commitment is separately retained.
        //# If a host has received at least one non-ECN-setup SYN
        //# or non-ECN-setup SYN-ACK packet, then it SHOULD NOT set ECT on
        //# data packets.
        // Actor/condition: TCP sender; received any plain setup packet.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
        //= reason=Shared fresh-data-only CWR predicate and transactional commit preserve signaling through failed outputs, pure ACK, persist, keepalive, FIN-only and retransmissions; tests assert first-fresh CWR and clearing after ECN, RTO, Reno/NewReno, SACK, RACK/PRR, TLP repaired loss and idle reduction.
        //# * If a host ever sets the ECT codepoint on a data packet, then
        //# that host MUST correctly set/clear the CWR TCP bit on all
        //# subsequent packets in the connection.
        // Actor/condition: TCP sender; ever transmitted ECT within this connection.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
        //= reason=Setup/opt-out evidence: exact SYN/SYN-ACK flag interpretation, plain setup forbids ECT, all SYN-ACK ECE/CWR forms are asserted. Earlier receive commitment is separately retained.
        //# * A host that is not willing to use ECN on a TCP connection SHOULD
        //# clear both the ECE and CWR flags in all non-ECN-setup SYN and/or
        //# SYN-ACK packets that it sends to indicate this unwillingness.
        // Actor/condition: TCP setup sender; unwilling to use ECN.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
        //= reason=Setup/opt-out evidence: exact SYN/SYN-ACK flag interpretation, plain setup forbids ECT, all SYN-ACK ECE/CWR forms are asserted. Earlier receive commitment is separately retained.
        //# Receivers MUST correctly handle all forms of the non-ECN-setup
        //# SYN and SYN-ACK packets.
        // Actor/condition: TCP setup receiver; any non-ECN-setup SYN/SYN-ACK flag combination.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
        //= reason=TCP output policy evidence: fresh ECT(0), setup and pure ACK Not-ECT are asserted at endpoint metadata boundary; external adapters must preserve that metadata. No router/AQM behavior is claimed.
        //# * A host MUST NOT set ECT on SYN or SYN-ACK packets.
        // Actor/condition: TCP sender; SYN/SYN-ACK output.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
        //= reason=TCP output policy evidence: fresh ECT(0), setup and pure ACK Not-ECT are asserted at endpoint metadata boundary; external adapters must preserve that metadata. No router/AQM behavior is claimed.
        //# When only one ECT codepoint
        //# is needed by a sender for all packets sent on a TCP connection,
        //# ECT(0) SHOULD be used.
        // Actor/condition: TCP sender; one ECT codepoint for fresh data.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
        //= reason=First committed fresh-data CWR; lost CWR data retransmits without CWR; next fresh data after subsequent reduction carries CWR. Failed encoding cannot consume pending signaling.
        //# Thus, the
        //# CWR bit in the TCP header SHOULD NOT be set on retransmitted packets.
        // Actor/condition: TCP sender; retransmitted data output.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
        //= reason=First committed fresh-data CWR; lost CWR data retransmits without CWR; next fresh data after subsequent reduction carries CWR. Failed encoding cannot consume pending signaling.
        //# When the TCP data sender is ready to set the CWR bit after reducing
        //# the congestion window, it SHOULD set the CWR bit only on the first
        //# new data packet that it transmits.
        // Actor/condition: TCP sender; first fresh data after reduction.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.4
        //= reason=TCP output policy evidence: fresh ECT(0), setup and pure ACK Not-ECT are asserted at endpoint metadata boundary; external adapters must preserve that metadata. No router/AQM behavior is claimed.
        //# For the current generation of TCP congestion control algorithms, pure
        //# acknowledgement packets (e.g., packets that do not contain any
        //# accompanying data) MUST be sent with the not-ECT codepoint.
        // Actor/condition: TCP sender; pure ACK output.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.5
        //= reason=Sender retransmission Not-ECT asserted at endpoint; receiver invalid/out-of-window CE rejection asserted at sequence/ACK boundaries. TCP roles only, no network marking behavior.
        //# This document specifies ECN-capable TCP implementations MUST NOT set
        //# either ECT codepoint (ECT(0) or ECT(1)) in the IP header for
        //# retransmitted data packets, and that the TCP data receiver SHOULD
        //# ignore the ECN field on arriving data packets that are outside of the
        //# receiver's current window.
        // Actor/condition: TCP sender and receiver; retransmitted data output and out-of-window received data.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.5
        //= reason=Sender retransmission Not-ECT asserted at endpoint; receiver invalid/out-of-window CE rejection asserted at sequence/ACK boundaries. TCP roles only, no network marking behavior.
        //# To prevent such a denial-of-service attack, we
        //# specify that a legitimate TCP data sender MUST NOT set an ECT
        //# codepoint on retransmitted data packets, and that the TCP data
        //# receiver SHOULD ignore the CE codepoint on out-of-window packets.
        // Actor/condition: TCP sender and receiver; retransmitted data output and out-of-window received data.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.6
        //= reason=Persist probe output explicitly excludes fresh data; assertions prove Not-ECT, no CWR, pending CWR preserved for later eligible data.
        //# Therefore, the TCP data sender MUST NOT set either an ECT codepoint
        //# or the CWR bit on window probe packets.
        // Actor/condition: TCP sender; zero-window probe output.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
        //= reason=First-fresh CWR tests cover RTO, Reno/NewReno fast retransmit, SACK and RACK/PRR reductions; TLP repaired-loss trace asserts CWR only after actual reduction. ECN and idle tests plus shared successful fresh-data commit cover other causes and failed encoding.
        //# When an ECN-Capable TCP sender reduces its congestion window for any reason (because of a retransmit timeout, a Fast Retransmit, or in response to an ECN Notification), the TCP sender sets the CWR flag in the TCP header of the first new data packet sent after the window reduction.
        // Actor/condition: TCP endpoint; any reduction cause including timeout, fast retransmit and ECN.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-21
        //= reason=Output defaults to Not-ECT unless eligible fresh data with bilateral ECN; setup, control ACK, retransmission and opted-out data metadata are asserted.
        //# the not-ECT codepoint should be the default.
        // Actor/condition: TCP endpoint; default IP/TCP output ECN policy.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
        //= reason=ECN-off CE/ECT receive tests now prove no implicit enablement or echo; negotiated exact-sequence probes explicitly honor section 6.1.6. Sender Not-ECT outputs are asserted. A receiver cannot recover an overwritten original Not-ECT from CE alone, so universal per-packet ignore applicability is not proven. Rejected errata 3636/3680 do not waive the original text; retain this unresolved interpretation/evidence obligation.
        //# If the TCP connection does not wish to use ECN notification for a particular packet, the sending TCP sets the ECN codepoint to not-ECT, and the TCP receiver ignores the CE codepoint in the received packet.
        // Actor/condition: TCP endpoint; packet not sent as ECN-capable.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
        //= reason=Bilateral setup gates fresh data ECT(0), with endpoint metadata assertions in both directions; no router marking claim.
        //# For a TCP connection using ECN, new data packets are transmitted with an ECT codepoint set in the IP header.
        // Actor/condition: TCP endpoint; negotiated fresh data.
        let ecn = if fresh_data && self.ecn_send() { 2 } else { 0 };
        if setup {
            flags |= ECE | if flags & ACK == 0 { CWR } else { 0 };
        } else if reset.is_none() && !syn {
            if self.ecn_echo {
                flags |= ECE;
            }
            if fresh_data && (self.ecn_cwr_pending || idle_reduction && self.ecn_feedback()) {
                flags |= CWR;
            }
        }
        // Reactive resets carry no receive credit or unused ACK value;
        // local ABORT retains its existing default/opt-in wire format.
        let reset_reply = reset.is_some() && self.reset_reply;
        let window = if reset_reply {
            0
        } else {
            self.advertised_window(syn)
        };
        let header = Header {
            source_port: self.tuple.local.port(),
            destination_port: self.tuple.remote.port(),
            sequence: seq.0,
            acknowledgment: if reset_reply {
                0
            } else {
                self.receive.next().0
            },
            flags,
            window,
            urgent_pointer,
        };
        let ip = IpMetadata {
            source: self.tuple.local.ip(),
            destination: self.tuple.remote.ip(),
        };
        // Include TCP options on every output path, before committing any state.
        //= https://www.rfc-editor.org/rfc/rfc4821#section-10.1
        //= reason=Selected non-overlapping real-data probes; actual receiver-generated ACKs exercise multiple smaller gap repairs and prevent crossing the probe boundary.
        //# In the non-overlapping method, data is segmented such that the probe and any
        //# subsequent segments contain no overlapping data. If the probe is lost, the
        //# "probe gap" will be a full probe size minus headers. Data in the probe gap will
        //# need to be retransmitted with multiple smaller segments.

        //= https://www.rfc-editor.org/rfc/rfc4821#section-10.1
        //= reason=Non-overlapping segmentation is the selected simple TCP method; the real-receiver lifecycle test already demonstrates bounded multiple gap repairs (164). No additional receiver-evidence gap exists in this choice statement.
        //# The choice of which segmentation method to use should be based on what is simplest
        //# and most efficient for a given TCP implementation.

        let pmtu_probe = pmtu_probe.filter(|&(_, payload, _)| count == payload && !retransmitted);
        //= https://www.rfc-editor.org/rfc/rfc4821#section-7.1
        //= reason=Every non-probe output checks final TCP header/options/data against path payload budget before commit; floor68 retry includes timestamps and SACK within budget.
        //# When transmitting non-probes, the Packetization Layer SHOULD create packets of a
        //# size less than or equal to eff_pmtu.

        //= https://www.rfc-editor.org/rfc/rfc4821#section-5.1
        //= reason=Supported non-probe accounting subtracts actual IP header length and TCP options. The IPv4 options test rejects a mismatched quote header and bounds repair including those headers; unsupported IPsec/IPv6 extension headers are not emitted.
        //# The way in which PLPMTUD operates across multiple layers requires a mechanism for
        //# accounting header sizes at all layers between IP and the Packetization Layer
        //# (inclusive). When transmitting non-probe packets, it is sufficient for the
        //# Packetization Layer to ensure an upper bound on final IP packet size, so as not to
        //# exceed the current

        //= https://www.rfc-editor.org/rfc/rfc4821#section-5.1
        //= reason=The selected probe size includes IP and TCP headers. The wire test asserts final IPv4/IPv6 probe length equals the recorded size and failed encoding cannot commit probe state; no unsupported extension-header emission is claimed.
        //# effective Path MTU. All Packetization Layers participating in classical Path MTU
        //# Discovery have this requirement already. When conducting a probe, the
        //# Packetization Layer MUST determine the probe packet's final size including IP
        //# headers. This requirement is specific to PLPMTUD, and satisfying it may require
        //# additional inter- layer communication in existing implementations.

        //= https://www.rfc-editor.org/rfc/rfc4821#section-7.5
        //= reason=Probe is committed only after successful encoding; final IP length equals the selected size in IPv4 and IPv6. Outcome-specific response requirements are separate, not prerequisites for this size/commit clause.
        //# Once a probe size in the appropriate range has been selected, and the above
        //# preconditions have been met, the Packetization Layer MAY conduct a probe. To do
        //# so, it creates a probe packet such that its size, including the outermost IP
        //# headers, is equal to the probe size. After sending the probe it awaits a response,
        //# which will have one of the following results:

        //= https://www.rfc-editor.org/rfc/rfc4821#section-8
        //= reason=TCP avoids fragmentation by respecting the current complete-IP non-probe budget; the floor/options repair test checks the emitted size. For a UDP application that cannot change its message sizes, Host::udp_send_datagram's Fragment mode source-fragments a datagram larger than the connectionless effective size within the peer reassembly guarantee or a stated capability, with DF on every IPv4 fragment outside owner-disabled routes (4821-155, 1191-093); tun_echo's UDP echo replies use it.
        //# Packetization Layers SHOULD avoid sending messages that will require fragmentation
        //# [Kent87] [frag-errors]. However, entirely preventing fragmentation is not always
        //# possible. Some Packetization Layers, such as a UDP application outside the kernel,
        //# may be unable to change the size of messages it sends, resulting in datagram sizes
        //# that exceed the Path MTU.

        let path_limit = pmtu_probe.map_or(self.path_payload_limit(), |(size, _, _)| {
            size.saturating_sub(u32::from(self.ip_header_len)) as usize
        });
        let wire_count = segmentation.map_or(count, |s| s.segment_payload_len);
        if 20 + option_len + wire_count > path_limit {
            return Err(Error::InvalidArgument);
        }
        let timestamp_cost =
            count as u32 + u32::from(flags & SYN != 0) + u32::from(flags & FIN != 0);
        if timestamp_cost > timestamp_credit {
            return Err(Error::TimestampBudgetExceeded);
        }
        let mut wire_header = header;
        if let Some(s) = &mut segmentation {
            s.terminal_flags = flags;
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.4
            //# Queue this until all preceding SENDs have been segmentized, then form a
            //# FIN segment and send it.
            // FIN, like PSH, belongs to the range's last segment only.
            wire_header.flags &= !(PSH | FIN);
        }
        let shared_payload = if count != 0 && !keepalive {
            shared
                .as_deref_mut()
                .is_some_and(|parts| self.send.shared_slices(offset, wire_count, parts))
        } else {
            false
        };
        let encoded = if shared_payload {
            wire::encode_shared(
                ip,
                wire_header,
                &options[..option_len],
                shared.as_deref().unwrap(),
                out,
            )
            .map(|n| n + wire_count)
        } else {
            wire::encode(
                ip,
                wire_header,
                &options[..option_len],
                match &gso {
                    Some(buffer) if segmentation.is_some() => &buffer.payload[..wire_count],
                    _ => &self.scratch[..wire_count],
                },
                out,
            )
        };
        let size = encoded.map_err(|error| {
            if error == wire::WireError::OutputTooSmall {
                Error::OutputTooSmall
            } else {
                Error::Wire(error)
            }
        })?;
        // Only the first timer-entry repair has not charged PRR at selection.
        // Fixed receive-report metadata is journaled along with sender state.
        // FIN/URG outputs retain the existing immutable reservation contract.
        // A reserved PTB repair charges nothing per byte before acceptance.
        self.repair_undo = if reserve
            && retransmitted
            && !ptb_repair
            && !syn
            && !probe
            && !tlp
            && !keepalive
            && flags & (FIN | URG) == 0
            && self.prr.is_some_and(|p| p.timer_repair())
        {
            RepairUndo::capture(self, seq, count)
        } else if reserve
            && fresh_data
            && !syn
            && !probe
            && !tlp
            && !keepalive
            && flags & (FIN | CWR | URG) == 0
            && pmtu_probe.is_none()
            && sack_option_len == 0
            && self.snd_wnd != 0
        {
            RepairUndo::capture_fresh(self)
        } else {
            None
        };
        // A sequence-bearing control without payload (SYN, SYN-ACK, FIN)
        // keeps its selection-time state, so a held attempt whose next hop
        // never resolves can be withdrawn without a departure.
        // Cleared in place: most outputs keep none, and an empty one built
        // aside would still be copied in whole.
        self.control_undo = None;
        if reserve
            && self.repair_undo.is_none()
            && count == 0
            && flags & (SYN | FIN) != 0
            && flags & RST == 0
            && reset.is_none()
            && !challenge
            && !probe
            && !tlp
            && !keepalive
            && pmtu_probe.is_none()
        {
            self.control_undo = Some(ControlUndo::capture(self));
        }
        let deferred_fresh = self.repair_undo.as_ref().is_some_and(|u| u.is_fresh());
        self.reserved_retransmit_counts =
            (reserve && (retransmitted || deferred_fresh) && !syn && !probe && !keepalive)
                .then(|| self.rack.diagnostic_packet_counts());
        let received_syn_data_acked = flags & ACK != 0
            && self
                .received_syn_data_start
                .is_some_and(|start| Seq(header.acknowledgment).after(start));
        let data_ack = flags & ACK != 0
            && (self.unacked_segments != 0 || (received_syn_data_acked && !self.syn_data_acked));
        if !reserve {
            self.syn_data_acked |= received_syn_data_acked;
            self.syn_data_fully_acked |= received_syn_data_acked;
        }
        self.reserved_ledger = None;
        let initial_burst = fresh_data
            && count != 0
            && pmtu_probe.is_none()
            && self.initial_pacing_room() >= count as u32;
        let timeout_recovery = self.sack_post_rto.is_some() || self.consecutive_timeouts != 0;
        self.last_discovery = pmtu_probe
            .filter(|_| reserve)
            .and_then(|(size, _, _)| {
                self.managed_path.map(|binding| crate::DiscoveryIntent {
                    binding,
                    ip_packet_len: size,
                    selected_at: now,
                })
            });
        self.last_departure = reserve.then_some(Departure {
            initial_burst,
            data_ack,
            defer_push: self.repair_undo.is_some()
                && flags & PSH != 0
                && (application_push || !group_push),
            fresh_data,
            deferred_fresh,
            received_syn_data_acked,
            segmentation,
            selected_at: now,
            start: seq.0,
            payload: count,
            stream: count != 0 && !keepalive,
            syn,
            syn_timestamp: timestamp.map(|(value, _)| value),
            fast_open: syn
                && !response_syn
                && !self.passive_open
                && (fast_open_option.is_some()
                    || self.fast_open_client_policy
                        == crate::FastOpenClientPolicy::ApplicationProtected
                        && count != 0),
            fast_open_option: syn
                && !response_syn
                && fast_open_option.is_some()
                && !self.passive_open,
            simultaneous_response: response_syn,
            fin: flags & FIN != 0,
            rto: !keepalive
                && !probe
                && (count != 0 || syn || flags & FIN != 0)
                && (self.rto_deadline.is_none() || retransmitted || tlp),
            rto_head: seq == self.snd_una,
            prior_rto_deadline: self.rto_deadline.or_else(|| {
                self.rack
                    .head_transmission(self.snd_una)
                    .map(|(_, sent)| sent.saturating_add(self.rto()))
            }),
            tlp: (fresh_data || new_fin) && !tlp,
            loss_probe: tlp,
            timeout_recovery,
            persist: probe && !urgent_probe,
            keepalive,
            shrink: retransmit
                && self.shrink_unanswered_since.is_none()
                && self.snd_wnd != 0
                && self.flight() > self.snd_wnd,
            unanswered: probe && !urgent_probe && self.persist_unanswered_since.is_none(),
            retransmission: retransmitted && !keepalive,
            fin_retransmission: flags & FIN != 0 && !new_fin,
            ptb_repair,
            bypass: probe
                || tlp
                || keepalive
                || syn
                || (retransmit && self.consecutive_timeouts != 0 && self.prr.is_none()),
            ..Departure::default()
        });
        // Protocol payload/probes must not reopen an ordinary startup epoch.
        if count != 0 && (!fresh_data || pmtu_probe.is_some() || !self.handshake_complete()) {
            self.initial_pacing_open = false;
        }
        self.last_pmtu_output = None;
        if let Some(p) = &mut self.pmtud {
            if let Some((size, payload, trailing)) = pmtu_probe {
                p.start_probe(seq, payload as u32, trailing as u32, size);
            }
            let length = count as u32 + u32::from(flags & SYN != 0) + u32::from(flags & FIN != 0);
            if length != 0 && !keepalive && segmentation.is_none() && !deferred_fresh {
                self.last_pmtu_output = Some((seq, seq.wrapping_add(length)));
                p.sent(
                    seq,
                    seq.wrapping_add(length),
                    size as u32 + u32::from(self.ip_header_len),
                    self.ip_header_len,
                    retransmitted,
                );
                // A managed embedding may rewrite reserved bytes (DF) before
                // submission: only the Host's receipt can prove their size.
                if reserve && self.managed_path.is_some() {
                    p.defer_proof_latest();
                }
            }
        }
        self.resolve_probe_response();
        // A retained reservation records its copy only on accepted
        // (Submitted or PossiblySubmitted) coverage; direct output is
        // committed here, after successful encoding.
        if !reserve && retransmitted && !keepalive {
            self.record_retransmission(
                seq.wrapping_add(u32::from(syn)),
                count,
                flags & FIN != 0 && !new_fin,
                ptb_repair,
            );
            if count != 0 || syn || flags & FIN != 0 {
                self.count_retransmitted_segment(timeout_recovery);
            }
        }
        self.last_output_range = if count != 0 && !keepalive {
            let data_seq = seq.wrapping_add(u32::from(syn));
            let start = self.acknowledged + u64::from(data_seq.distance_from(self.send_base));
            let range = TxStreamRange {
                start,
                end: start + count as u64,
            };
            self.tx_timestamps.observe(
                range,
                TxTimestampStage::Scheduled,
                TxTimestampSource::Software,
                now,
                TxTimestampClock::CallerTicks(self.config.timebase),
            );
            Some(range)
        } else {
            None
        };
        if syn && retransmitted {
            self.syn_retransmissions = self.syn_retransmissions.saturating_add(1);
            if self.config.initial_window == InitialWindow::Iw10 && self.syn_retransmissions > 1 {
                self.syn_loss_detected = true;
                self.congestion.limit_restart(self.mss as u32);
            }
        }
        if self.config.initial_window == InitialWindow::Iw10 && fresh_data {
            if !self.iw_started || idle_restart {
                self.iw_epoch = Some(IwEpoch {
                    start: seq,
                    end: seq,
                    fresh_start: None,
                    bytes: 0,
                    open: true,
                    lost: false,
                });
                self.iw_started = true;
            }
            if let Some(epoch) = &mut self.iw_epoch
                && epoch.open
            {
                epoch.end = seq.wrapping_add(count as u32);
                // Only unique new stream bytes contribute to the IW epoch.
                epoch.bytes = epoch.bytes.saturating_add(count as u32);
                if fresh_data {
                    epoch.fresh_start.get_or_insert(seq);
                }
                if epoch.lost && epoch.bytes > 4_096 {
                    self.iw_fallback = true;
                }
            }
        }
        if timestamp.is_some() {
            self.timestamp_tick = tick;
            self.timestamp_bytes = tick_bytes + timestamp_cost;
        }
        if !challenge {
            self.retransmit_burst = retransmit_burst;
        }
        // Commit only the encoded (possibly clamped) urgent coverage, and only
        // after successful output. Retransmissions must not move it backwards.
        if flags & URG != 0 {
            let end = seq.wrapping_add(urgent_pointer as u32);
            if self.advertised_snd_up.is_none_or(|old| end.after(old)) {
                self.advertised_snd_up = Some(end);
            }
        }
        // Commit the on-wire endpoint only after output succeeds. A partial ACK
        // past an earlier collapsed mark must not lose PSH on retransmission.
        // Opt-in batch-only hints are transient, not application PUSH requests.
        if self.repair_undo.is_none() && flags & PSH != 0 && (application_push || !group_push) {
            self.send
                .collapse_push(seq.distance_from(self.send_base) as usize, count);
        }
        self.update_time(now)?;
        if !reserve {
            self.adaptive_departure(data_ack, fresh_data);
        }
        self.last_output_ecn = ecn;
        if syn {
            self.sack_receive |= sack_offer;
            self.ecn_sent_setup |= setup;
            self.ecn_sent_plain |= !setup;
        }
        if idle_reduction {
            // A probe cannot carry CWR. Retain this successful reduction for
            // the next eligible new-data packet, even if the probe is ACKed.
            self.ecn_cwr_pending |= self.ecn_feedback();
        }
        if fresh_data && flags & CWR != 0 {
            self.ecn_cwr_pending = false;
        }
        if reset.is_some() {
            self.pending_rst = None;
            self.reset_echo = None;
            self.reset_reply = false;
            return Ok(Some(size));
        }
        //= https://www.rfc-editor.org/rfc/rfc2883#section-4
        //= reason=Planning/retry does not consume pending report; successful SACK-bearing ACK consumes it once. Second identical report requires fresh duplicate recording.
        //# (2) Each duplicate contiguous sequence of data received is reported
        //# in at most one D-SACK block.  (I.e., the receiver sends two identical
        //# D-SACK blocks in subsequent packets only if the receiver receives two
        //# duplicate segments.)
        if sack_option_len != 0 && flags & ACK != 0 {
            self.receive.commit_sack(sack_first.unwrap());
        }
        if flags & ACK != 0 {
            self.sack_data_turn = count == 0 && sack_option_len >= self.mss;
            if !sack_limited {
                self.receive.commit_report();
            }
            self.sack_omit = false;
        }
        // A reserved PTB repair defers its per-coverage charges (PRR, RACK
        // copy, SACK pipe and HighRxt, post-RTO frontier, retransmission
        // marker and RTO restart) to acceptance: a racing decrease that splits
        // it must charge exactly the accepted fragments.
        let deferred_ptb = reserve && ptb_repair;
        if count != 0 && !keepalive {
            let seq = seq.wrapping_add(u32::from(syn));
            // Strict recovery exits before persist; legacy probes retain their
            // separate policy. Record every real emission in the age ledger.
            if !probe
                && !deferred_ptb
                && let Some(prr) = &mut self.prr
            {
                // Timer-entry credit belongs to this lost-head repair only.
                // Reservations account actual accepted fragments, not selection.
                if !reserve || !prr.timer_repair() {
                    prr.sent(count as u32);
                    prr.finish_timer_repair();
                }
            }
            let end = seq.wrapping_add(count as u32);
            if deferred_ptb {
                self.reserved_ledger = None;
            } else {
                self.rack.transmit(seq, end, now, retransmitted);
                if retransmitted && !probe {
                    self.rack.commit_retry_span(seq, end);
                } else if !retransmitted {
                    self.rack.commit_original_window(
                        seq,
                        end,
                        !probe
                            && seq.distance_from(self.snd_una) < self.snd_wnd
                            && end.distance_from(self.snd_una) <= self.snd_wnd,
                    );
                }
                if reserve {
                    self.reserved_ledger = self.rack.departure_selection();
                } else if let Some(selection) = self.rack.departure_selection() {
                    let committed = self.rack.commit_departure(selection, seq, end, now);
                    debug_assert!(committed);
                }
            }
            if !self.rack.valid() {
                self.congestion.end_ecn_prr();
                self.prr = None;
            }
        }
        if count != 0
            && !deferred_ptb
            && let Some(mut recovery) = self.sack_recovery
        {
            if let Some((_, _, rescue, entry)) = sack_segment {
                let end = seq.wrapping_add(count as u32);
                if !rescue {
                    self.ptb_high_rxt_crossed(recovery.high_rxt, seq);
                    recovery.high_rxt = end;
                }
                if entry {
                    recovery.entry_pending = false;
                    recovery.rescue_rxt = Some(end);
                } else if rescue {
                    recovery.rescue_rxt = Some(recovery.recovery_point);
                }
            } else if ptb_repair
                && !self.rack_enabled()
                && self.ptb_extends_frontier(recovery.high_rxt, seq)
            {
                // Only a repair contiguous with HighRxt may advance it; an
                // arbitrary non-head repair never skips unretransmitted holes.
                recovery.high_rxt = seq.wrapping_add(count as u32);
            }
            recovery.pipe = if self.rack_enabled() {
                self.rack.pipe()
            } else if sack_segment.is_some_and(|(_, _, _, entry)| entry) {
                self.recovery_pipe(recovery.high_rxt)
            } else {
                recovery.pipe.saturating_add(count as u32)
            };
            self.sack_recovery = Some(recovery);
        }
        if retransmitted
            && !syn
            && !probe
            && count != 0
            && !deferred_ptb
            && let Some((old, boundary)) = self.sack_post_rto
            && (!ptb_repair || self.ptb_extends_frontier(old, seq))
        {
            let end = seq.wrapping_add(count as u32);
            if end.after(old) {
                self.sack_post_rto = Some((end, boundary));
            }
        }
        //= https://www.rfc-editor.org/rfc/rfc5681#section-4.1
        //# Therefore, a TCP SHOULD set cwnd to no more than RW before beginning transmission
        //# if the TCP has not sent data in an interval exceeding the retransmission timeout.
        if idle_restart {
            let window = self.restart_window();
            self.congestion.restart_after_idle(window);
        }
        if !challenge {
            if count != 0 && !keepalive {
                self.last_sent = now;
            }
            self.syn_pending = false;
        }
        if flags & ACK != 0 {
            //= https://www.rfc-editor.org/rfc/rfc7323#section-4.3
            //= reason=Retains one pending echo value and last successfully committed ACK; separate ts_latest is TIME-WAIT freshness bookkeeping, not extra unprocessed echo queue.
            //# TS.Recent holds a timestamp to be echoed in TSecr whenever a
            //# segment is sent, and Last.ACK.sent holds the ACK field from the
            //# last segment sent.  Last.ACK.sent will equal RCV.NXT except when
            //# <ACK>s have been delayed.
            self.last_ack_sent = self.receive.next();
            self.ack_pending =
                self.sack_send && (sack_limited || self.receive.has_pending_report());
            self.ack_deadline = None;
            self.unacked_segments = 0;
            self.unacked_bytes = 0;
            let shift = if !syn && self.scaling {
                self.local_scale
            } else {
                0
            };
            let edge = self.receive.next().wrapping_add((window as u32) << shift);
            //= https://www.rfc-editor.org/rfc/rfc7323#section-2.4
            //= reason=Previously committed receive promises remain valid across scaled rounding and wrap. Capacity-backed presence bits accept arbitrary fragmentation without an interval-count limit; tests combine delayed promised bytes, batching and complete retained delivery.
            //# 1)  The receiver MUST honor, as in window, any segment that would
            //# have been in window for any <ACK> sent by the receiver.
            //= https://www.rfc-editor.org/rfc/rfc7323#section-2.4
            //= reason=Tracks maximum successful advertised edge independently of current quantized field; not advanced on failed output.
            //# 2)  When window scaling is in effect, the receiver SHOULD track the
            //# actual maximum window sequence number (which is likely to be
            //# greater than the window announced by the most recent <ACK>, if
            //# more than one segment has arrived since the application consumed
            //# any data in the receive buffer).
            if edge.after(self.advertised_edge) || self.receive.eof() {
                self.advertised_edge = edge;
            }
        }
        if challenge {
            self.refresh_challenge_budget(now);
            self.challenge_ack_sent += 1;
            self.challenge_ack_pending = false;
            if timestamp.is_some() {
                self.last_timestamp_sent_at = Some(now);
            }
            // The ACK satisfies receiver work, but must not re-arm, consume,
            // or otherwise perturb sender work or any protocol timer.
            return Ok(Some(size));
        }
        //= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
        //# 2. Advance to SYN-SENT state and update SND.NXT to include the data accordingly.
        let length = count as u32 + u32::from(flags & SYN != 0) + u32::from(flags & FIN != 0);
        if syn && !reserve {
            self.fast_open_attempt |= !response_syn
                && !self.passive_open
                && !self.syn_committed
                && (fast_open_option.is_some()
                    || self.fast_open_client_policy
                        == crate::FastOpenClientPolicy::ApplicationProtected
                        && count != 0);
            self.fast_open_option_sent |=
                !response_syn && fast_open_option.is_some() && !self.passive_open;
            self.fast_open_response_committed |= response_syn;
            self.record_syn_departure(timestamp.map(|(value, _)| value));
            self.syn_payload_sent = self.syn_payload_sent.max(count);
            self.rack
                .record_syn_payload(seq.wrapping_add(1), seq.wrapping_add(1 + count as u32));
        }
        if length != 0 && !keepalive {
            let end = seq.wrapping_add(length);
            if retransmitted {
                if !syn && !probe && !deferred_ptb {
                    self.congestion.on_retransmit(end);
                }
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.1
                //= reason=Sample invalidation here and accept_ack sampling integrate with recovery.rs RTT estimation.
                //# The RTO MUST be computed according to the algorithm in [10],
                //# including Karn's algorithm for taking RTT samples (MUST-18).
                // Karn: invalidate every pending sample when retransmitting.
                // Fresh sequence space sent afterwards may start a new sample;
                // its ACK cannot predate its first transmission.
                self.sample = None;
            } else if self.sample.is_none() {
                self.sample = Some((if syn { seq.wrapping_add(1) } else { end }, now));
                self.sample_departure = None;
            }
            if end.after(self.snd_nxt) {
                self.snd_nxt = end;
            }
            // A non-head PTB repair cannot postpone an older head's deadline;
            // a head repair keeps RFC 6298's one-RTO protection, measured
            // from acceptance when reserved.
            let restart = retransmitted && !(ptb_repair && (reserve || seq != self.snd_una));
            if (self.rto_deadline.is_none() || restart) && !probe {
                self.rto_deadline = Some(now.saturating_add(self.rto()));
            }
        }
        if ptb_repair && length != 0 && !reserve {
            self.ptb_repair_committed();
        }
        if tlp && length != 0 {
            if !reserve {
                self.loss_events.loss_probes += 1;
            }
            // A probe is not Limited Transmit: it must neither earn its
            // duplicate-ACK credit nor be excluded from congestion FlightSize.
            self.limited_pending = false;
            self.tlp_pending = false;
            self.tlp_end = Some((seq, seq.wrapping_add(length), retransmitted));
            self.tlp_flight = Some(self.snd_nxt);
            self.tlp_fresh_rtt = false;
            self.tlp_deadline = None;
            self.rto_deadline = Some(now.saturating_add(self.rto()));
        }
        if timestamp.is_some() {
            self.last_timestamp_sent_at = Some(now);
        }
        if flags & FIN != 0 {
            if !reserve {
                self.record_fin_departure(seq, count);
            }
            self.fin_sent_at = Some(now);
        }
        if new_fin {
            self.fin_standalone = count == 0;
            self.fin_sequence = Some(seq.wrapping_add(count as u32));
            self.state = if self.state == State::CloseWait {
                State::LastAck
            } else {
                State::FinWait1
            };
        }
        if !syn
            && count != 0
            && let Some((start, end)) = self.fast_open_retry
            && seq == start
        {
            let next = seq.wrapping_add(count as u32);
            self.fast_open_retry = if next.at_or_after(end) {
                None
            } else {
                Some((next, end))
            };
        }
        if retransmit && length != 0 {
            self.retx_pending = false;
            if self.snd_wnd != 0 && self.flight() > self.snd_wnd {
                // Commit only after encode succeeds; retries cannot postpone
                // the deadline for the oldest still-unanswered retransmission.
                self.shrink_unanswered_since.get_or_insert(now);
            }
        }
        if probe && !urgent_probe {
            self.probe_pending = false;
            if !reserve {
                self.persist_unanswered_since.get_or_insert(now);
            }
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1
            //= reason=arm_work starts at the current RTO; each emitted probe doubles the interval up to the timer cap.
            //# The transmitting host SHOULD send the first zero-window probe when a
            //# zero window has existed for the retransmission timeout period (SHLD-
            //# 29) (Section 3.8.1), and SHOULD increase exponentially the interval
            //# between successive probes (SHLD-30).
            self.persist_interval = self
                .persist_interval
                .saturating_mul(2)
                .min(self.config.timebase.ticks_from_us(60_000_000));
            if self.flight() != 0 {
                self.rto_deadline = Some(now.saturating_add(self.persist_interval));
            } else {
                self.persist_deadline = Some(now.saturating_add(self.persist_interval));
            }
        }
        if keepalive {
            self.keepalive_pending = false;
            self.keepalive_probes = self.keepalive_probes.saturating_add(1);
            self.keepalive_deadline = self
                .config
                .keepalive
                .map(|k| now.saturating_add(self.config.timebase.ticks_from_us(k.interval_us)));
        }
        if count != 0 && !keepalive {
            if self.limited_pending && !retransmit && !probe {
                self.limited_sent = self.limited_sent.saturating_add(count as u32);
                self.limited_end = Some(seq.wrapping_add(count as u32));
                // RFC 6675 repeats SetPipe across output polls for this ACK.
                // Reno and the RACK/PRR profiles retain one-packet credit.
                self.limited_pending = self.sack_recovery_enabled()
                    && !self.rack_enabled()
                    && !self.config.prr
                    && self
                        .congestion
                        .cwnd()
                        .saturating_sub(self.recovery_pipe(self.snd_una))
                        >= self.mss as u32
                    && self.send.len() > self.snd_nxt.distance_from(self.send_base) as usize
                    && self.snd_wnd > self.flight();
            }
            self.sws_deadline = None;
            self.sws_override = false;
        }
        if count != 0 && !syn && !keepalive && !probe {
            // Successful encode only: failed polls cannot start/advance CUBIC's
            // clock or validate an application-limited flight for growth.
            let flight = self.data_flight();
            let unsent = self
                .send
                .len()
                .saturating_sub(self.snd_nxt.distance_from(self.send_base) as usize);
            // Sender SWS may leave <MSS credit in a fractional CUBIC window.
            // Validate that case only with queued data and rwnd >= cwnd.
            let cwnd_limited = unsent != 0
                && self.snd_wnd >= self.congestion.cwnd()
                && flight.saturating_add(unsent.min(self.mss) as u32) > self.congestion.cwnd();
            self.congestion
                .on_data_sent(now, flight, self.data_high(), cwnd_limited);
        }
        if count != 0 && !syn && !keepalive {
            self.congestion.on_startup_sent(
                self.snd_nxt,
                self.pacing_enabled() && !initial_burst && !probe && !tlp && !retransmit,
            );
        }
        self.arm_work();
        if (fresh_data || new_fin) && !tlp {
            self.schedule_tlp();
        }
        if count != 0
            && !syn
            && !keepalive
            && let Some(pacing) = self.config.pacing
        {
            let interval = Pacer::interval(
                self.rtt.srtt().unwrap_or(self.rtt.rto()),
                self.congestion.cwnd(),
                pacing.rate_gain_percent,
                pacing.max_bytes_per_second,
                self.config.timebase.units_per_second,
            );
            if let Some(departure) = &mut self.last_departure {
                departure.interval = Some(interval);
            } else {
                if initial_burst {
                    self.pacer.startup_sent(
                        now,
                        count,
                        interval,
                        pacing.max_burst_segments * self.mss as u32,
                    );
                } else {
                    self.pacer.sent(now, count, interval);
                }
                self.pacing_deadline = self.general_pacing_deadline(now);
            }
        } else if count != 0 && !syn && !keepalive && self.pacing_enabled() {
            // Commit after encode and congestion/idle accounting. Schedule from
            // this output, never from an expired deadline (no catch-up bursts).
            let rtt = self.rtt.srtt().unwrap_or(self.rtt.rto());
            let spacing = (count as u128 * rtt as u128)
                .div_ceil(self.congestion.cwnd().max(1) as u128)
                .clamp(1, u64::MAX as u128) as u64;
            if let Some(departure) = &mut self.last_departure {
                departure.legacy_rate = Some((rtt, self.congestion.cwnd().max(1)));
            } else {
                self.pacing_deadline = Some(now.saturating_add(spacing));
            }
        }
        Ok(Some(size))
    }

    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.4
    //= reason=Legacy pacing=None only: Connection::transmit gates ordinary/startup and recovery selection on one caller-clock deadline, commits ceil(data*SRTT/cwnd) after encoding (initial RTO fallback), and preserves spacing through recovery exit/idle. Connection::next_deadline/timeout expose budgeted Endpoint::on_timeout wakeups. src/connection_output_tests.rs pacing_wire_spacing_units_idle_and_failed_output, pacing_recovery_budget_exit_and_control, pacing_selection_gates_protocol_probes_and_widened_rate, pacing_no_sack_retries_with_default_policy and src/endpoint_tests.rs pacing_endpoint_budget_and_halfclose verify wire behavior. Explicit nonpaced override excluded; protocol-control/probe bypasses scoped at transmit.
    //# It is RECOMMENDED that implementations use pacing to reduce the
    //# burstiness of data traffic.
    fn pacing_enabled(&self) -> bool {
        self.config.pacing.is_some() || (self.config.prr && self.config.prr_pacing)
    }

    fn initial_pacing_room(&self) -> u32 {
        if !self.initial_pacing_open
            || !self
                .config
                .pacing
                .is_some_and(|p| p.initial_window_burst && p.max_bytes_per_second.is_none())
            || !self.handshake_complete()
            || !matches!(self.state, State::Established | State::CloseWait)
            || self.congestion.in_recovery()
            || self.congestion.in_ecn_response(self.snd_una)
            || self.congestion.ecn_prr_end().is_some()
            || self.prr.is_some()
            || self.sack_recovery.is_some()
            || self.sack_post_rto.is_some()
            || self.limited_pending
            || self.retx_pending
            || self.probe_pending
            || self.tlp_pending
            || self.consecutive_timeouts != 0
            || self.pmtud.as_ref().is_some_and(|p| p.probe.is_some())
        {
            return 0;
        }
        // Before the first data ACK this serial distance is unique initial
        // payload, including any already selected immutable reservation.
        self.initial_window()
            .min(self.congestion.cwnd())
            .saturating_sub(self.snd_nxt.distance_from(self.iss.wrapping_add(1)))
    }

    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.4
    //= reason=Opt-in PacingConfig gates ordinary/startup and recovery data independently of PRR or Reno/CUBIC. Fractional byte debt bounds ordinary/idle/late-poll bursts to max_burst_segments effective MSS; the one-time configured initial flight is IW/window-bounded and recorded as unpaced; successful output alone consumes bytes. cwnd/SRTT times configured gain (RTO fallback), optional caller-unit-correct byte-rate cap, and retained debt across rate changes drive existing next_deadline/timeout wakeups. Protocol-control/probe exemptions remain scoped at transmit; no future-launch or QUIC compliance is claimed. general_pacing tests cover fractional output, bounds, rates, recovery, rollback and saturation; legacy pacing tests cover None unchanged.
    //# It is RECOMMENDED that implementations use pacing to reduce the
    //# burstiness of data traffic.
    fn general_pacing_deadline(&self, now: Instant) -> Option<Instant> {
        if self.initial_pacing_room() != 0 {
            return None;
        }
        self.config.pacing.and_then(|p| {
            self.pacer
                .deadline(now, p.max_burst_segments * self.mss as u32, self.mss)
        })
    }

    pub(crate) fn iw_setup_loss(&self) -> bool {
        self.iw_setup_loss
    }

    fn note_iw_loss(&mut self, start: Seq) {
        self.initial_pacing_open = false;
        if let Some(epoch) = &mut self.iw_epoch
            && start.at_or_after(epoch.start)
            && epoch.end.after(start)
        {
            epoch.lost = true;
            self.iw_setup_loss = true;
            if epoch.bytes > 4_096 {
                self.iw_fallback = true;
            }
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc6928#section-2
    //= reason=Initial/restart epoch retains original byte range and bytes sent before first advancing data ACK. RTO, Reno/SACK/RACK loss and TLP repair latch inferred loss; >4096 bytes selects future RFC3390 restart bound without increasing cwnd. Wrap, initial/restart, fast/RTO, 4096/4097 and actual future burst tests cover fallback.
    //# Furthermore, to limit any negative effect that a larger initial window may have on links with limited bandwidth or buffer space, implementations SHOULD fall back to RFC 3390 for the restart window (RW) if any packet loss is detected during either the initial window or a restart window, and more than 4 KB of data is sent.
    fn restart_window(&self) -> u32 {
        if self.iw_fallback {
            InitialWindow::Rfc5681.bytes(self.mss as u32)
        } else {
            self.initial_window()
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc6928#section-2
    //= reason=IW10 retains its initial window after a first potentially spurious SYN timeout; only successfully encoded retransmissions count. More than one committed SYN/SYNACK retry reduces to one MSS; failed output and both endpoint roles tested. This is conservative inference, not physical loss proof.
    //# For this reason, it is RECOMMENDED that implementations refrain from resetting the initial window to 1 segment, unless there have been more than one SYN or SYN/ACK retransmissions or true loss detection has been made.
    fn initial_window(&self) -> u32 {
        self.congestion.initial_window()
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        // A successfully filled tick can leave stream/control output queued.
        // Derive its wakeup from committed credit: failed encodes do not arm a
        // timer, and timeout advancing to the next tick removes this deadline.
        let timestamp_wakeup = (self.timestamp_bytes >= self.config.timestamp_bytes_per_tick
            && self.timestamp_tick
                == self
                    .config
                    .timestamp_granularity
                    .tick_in(self.now, self.config.timebase)
            && (self.syn_pending
                || self.retx_pending
                || self.fast_open_retry.is_some()
                || self.probe_pending
                || self.keepalive_pending
                || (self.synchronized() || self.early_response_eligible())
                    && (self.send.len() > self.snd_nxt.distance_from(self.send_base) as usize
                        || self.shutdown && self.fin_sequence.is_none())))
        .then(|| {
            self.timestamp_tick.saturating_add(1).saturating_mul(
                self.config
                    .timebase
                    .ticks_from_us(self.config.timestamp_granularity.tick_us()),
            )
        });
        // At most one extra wakeup even if no data remains: timeout consumes
        // eligibility and refresh rechecks admission, so idle cannot busy-loop.
        [
            if self.config.pacing.is_some() {
                // At Instant::MAX debt still blocks admission, but its saturated
                // deadline cannot be serviced; do not rearm an already-due timer.
                self.general_pacing_deadline(self.now)
                    .filter(|&deadline| deadline > self.now)
            } else {
                self.pacing_deadline
            },
            timestamp_wakeup,
            self.timestamp_ambiguous.then_some(self.now),
            self.pmtud
                .as_ref()
                // Unlike pacing, tick consumes even a saturated due deadline.
                // Input may advance now before Endpoint services that timer.
                .and_then(|p| p.next_deadline()),
            self.loss_timer.map(|(_, deadline)| deadline),
            self.ecn_pause,
            self.ack_deadline,
            self.sws_deadline,
            self.cork_deadline,
            self.time_wait_deadline,
            self.keepalive_deadline,
            self.user_deadline(),
            self.application_deadline(),
            self.local_resource.and_then(|r| r.retry_at),
        ]
        .iter()
        .flatten()
        .min()
        .copied()
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.8
    //= reason=Default SYN/data R2 terminal behavior; storage reclaimed by release, timer servicing belongs to driver; explicit application stall timeout is separate.
    //# For any state if the user timeout expires, flush all queues, signal the user "error:
    //# connection aborted due to user timeout" in general and for any outstanding calls, delete
    //# the TCB, enter the CLOSED state, and return.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-5.1
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Timeout clears scoreboard and RTO sends left edge before acting on fresh SACKs. Implementation satisfies even the original stronger wording; verified erratum 1610 changes MUST to SHOULD, rejected erratum 6602 is not applied.
    //# Because the data receiver is allowed to discard SACKed data, when a
    //# retransmit timeout occurs the data sender MUST ignore prior SACK information
    //# in determining which data to retransmit.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Timeout clears advisory ranges; test observes full pipe after timeout.
    //# After a retransmit timeout the data sender SHOULD turn off all of the SACKed
    //# bits, since the timeout might indicate that the data receiver has reneged.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-5
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. sack_rto_discards_advice_retransmits_head_and_guards_epoch accepts a valid first SACK block covering snd_una through data_high before RTO, then verifies wire head sequence/payload and guard after timeout clears advice.
    //# The data sender MUST retransmit the segment at the left edge of the window
    //# after a retransmit timeout, whether or not the SACKed bit is on for that
    //# segment.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Clears prior advice and sends the head. Erratum 1610 permits a weaker SHOULD but implementation takes conservative clearing path.
    //# As a result, [RFC2018] suggests that a TCP sender SHOULD expunge the SACK
    //# information gathered from a receiver upon a retransmission timeout (RTO)
    //# "since the timeout might indicate that the data receiver has reneged."
    //# Additionally, a TCP sender MUST "ignore prior SACK information in
    //# determining which data to retransmit." However, since the publication of
    //# [RFC2018], this has come to be viewed by some as too strong.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Timeout replaces recovery with sack_guard=data_high; fresh SACKs cannot reenter until cumulative boundary is covered. Exclusive boundary equals RFC highest byte plus one.
    //# If an RTO occurs during loss recovery as specified in this document,
    //# RecoveryPoint MUST be set to HighData.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Timeout replaces recovery with sack_guard=data_high; fresh SACKs cannot reenter until cumulative boundary is covered. Exclusive boundary equals RFC highest byte plus one.
    //# Further, the new value of RecoveryPoint MUST be preserved and the loss
    //# recovery algorithm outlined in this document MUST be terminated.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Timeout replaces recovery with sack_guard=data_high; fresh SACKs cannot reenter until cumulative boundary is covered. Exclusive boundary equals RFC highest byte plus one.
    //# In addition, a new recovery phase (as described in Section 5) MUST NOT be
    //# initiated until HighACK is greater than or equal to the new value of
    //# RecoveryPoint.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Services only the selected RACK timer by re-running detect_rack; the retained RTO expiration is an unarmed fallback reference.
    //# For timely loss detection, it is RECOMMENDED that the
    //# sender install a reordering timer.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= reason=Checks no tlp_end, no tlp_flight, and fresh RTT before making a probe pending; output repeats these checks.
    //# When the PTO timer expires, the sender MUST check whether both of the
    //# following conditions are met before sending a loss probe:
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= reason=At PTO expiration failed send eligibility leaves no pending probe and rearms the selected RTO for every outstanding flight, including a zero window.
    //# If either one of these two conditions is not met, then the sender
    //# MUST skip sending a loss probe and MUST proceed to re-arm the RTO
    //# timer, as specified at the end of this section.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= reason=PTO expiry rearms RTO before attempting output whenever flight is nonzero; successful probe commit rearms again. Zero-window RTO expiration probes flow control without a congestion response.
    //# After attempting to send a loss probe, regardless of whether a loss
    //# probe was sent, the sender MUST re-arm the RTO timer, not the PTO
    //# timer, if the FlightSize is not zero.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= reason=Tracks both unresolved TLP recovery episode and original-flight boundary; at most one committed probe until ACK/recovery reset.
    //# First, there is no other previous loss probe still in flight.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-1
    //= reason=Selected RTO enforces latest wire-span boundary and elapsed age before loss/backoff; output failure preserves pending state, and successful commit rearms. Sampling cadence is separately evidenced; approved subsecond compatibility is a scoped departure, not universal MUST conformance.
    //# However, a TCP MUST NOT be more aggressive than the following algorithms allow.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= reason=Selected RTO enforces latest wire-span boundary and elapsed age before loss/backoff; output failure preserves pending state, and successful commit rearms. Global sampling/floor profile obligations remain separate.
    //# An implementation MUST manage the retransmission timer(s) in such a way that a segment
    //# is never retransmitted too early, i.e., less than one RTO after the previous
    //# transmission of that segment.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= reason=Selected RTO enforces latest wire-span boundary and elapsed age before loss/backoff; output failure preserves pending state, and successful commit rearms. Global sampling/floor profile obligations remain separate.
    //# The following is the RECOMMENDED algorithm for managing the retransmission timer:
    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= reason=Due RTO clears sample and PRR/SACK recovery, backs off, records exclusive snd_nxt recovery epoch, then sets SYN/head retransmission pending. Output commit re-arms; no emission on timeout alone.
    //# (5.5) The host MUST set RTO <- RTO * 2 ("back off the timer").
    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= reason=Selected RTO enforces latest wire-span boundary and elapsed age before loss/backoff; output failure preserves pending state, and successful commit rearms. Global sampling/floor profile obligations remain separate.
    //# (5.7) If the timer expires awaiting the ACK of a SYN segment and the TCP
    //# implementation is using an RTO less than 3 seconds, the RTO MUST be re-initialized to
    //# 3 seconds when data transmission begins (i.e., after the three-way handshake
    //# completes).
    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= reason=Due RTO clears sample and PRR/SACK recovery, backs off, records exclusive snd_nxt recovery epoch, then sets SYN/head retransmission pending. Output commit re-arms; no emission on timeout alone.
    //# (5.4) Retransmit the earliest segment that has not been acknowledged by the TCP
    //# receiver.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= reason=Due RTO clears sample and PRR/SACK recovery, backs off, records exclusive snd_nxt recovery epoch, then sets SYN/head retransmission pending. Output commit re-arms; no emission on timeout alone.
    //# (5.6) Start the retransmission timer, such that it expires after RTO seconds (for the
    //# value of RTO after the doubling operation outlined in 5.5).
    // Due RTO clears sample and PRR/SACK recovery, backs off, records exclusive snd_nxt recovery epoch, then sets SYN/head retransmission pending. Output commit re-arms; no emission on timeout alone.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.1
    //= reason=No-SACK NewReno wire entry, partial-ACK continuation, full-ACK exit and active-recovery RTO exit are asserted by newreno_partial_ack_wire_timer_and_exit_boundaries. timeout_marker_boundaries_and_wrap asserts timeout marker replacement; initial guard and strict admission are asserted by newreno_initial_boundary_and_loss_epoch_are_distinct.
    //# The NewReno modification applies to the fast recovery procedure that begins when three
    //# duplicate ACKs are received and ends when either a retransmission timeout occurs or an
    //# ACK arrives that acknowledges all of the data up to and including the data that was
    //# outstanding when the fast recovery procedure began.
    // Due RTO clears sample and PRR/SACK recovery, backs off, records exclusive snd_nxt recovery epoch, then sets SYN/head retransmission pending. Output commit re-arms; no emission on timeout alone.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=on_timeout stores exclusive highest_sent and clears recovery; timeout_marker_boundaries_and_wrap directly asserts active flag clear and marker replacement. newreno_partial_ack_wire_timer_and_exit_boundaries asserts active wire RTO at exact expiry.
    //# After a retransmit timeout, record the highest sequence number transmitted in the
    //# variable recover, and exit the fast recovery procedure if applicable.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-4
    //= reason=Due RTO clears sample and PRR/SACK recovery, backs off, records exclusive snd_nxt recovery epoch, then sets SYN/head retransmission pending. Output commit re-arms; no emission on timeout alone.
    //# After each retransmit timeout, the highest sequence number transmitted so far is
    //# recorded in the variable recover.
    pub(crate) fn timeout(&mut self, now: Instant) -> Result<(), Error> {
        self.update_time(now)?;
        if let Some(p) = &mut self.pmtud {
            p.tick(now);
        }
        if due(self.pacing_deadline, now) {
            self.pacing_deadline = None;
        }
        self.retransmit_burst = None;
        let expired_loss = self
            .loss_timer
            .filter(|&(_, deadline)| now >= deadline)
            .map(|(timer, _)| timer);
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.8
        //= reason=Closes protocol state here; terminal handle storage is reclaimed on release.
        //# If the time-wait timeout expires on a connection, delete the TCB, enter the
        //# CLOSED state, and return.
        if due(self.time_wait_deadline, now) {
            self.end_time_wait();
            return Ok(());
        }
        if core::mem::take(&mut self.timestamp_ambiguous) {
            self.terminal(CloseReason::TimedOut);
            return Ok(());
        }
        let terminal_deadline = self
            .user_deadline()
            .into_iter()
            .chain(self.application_deadline())
            .min();
        if due(terminal_deadline, now) {
            // Late servicing must not turn an earlier local give-up into SYN loss.
            if self
                .rto_deadline
                .zip(terminal_deadline)
                .is_some_and(|(rto, terminal)| rto <= terminal)
            {
                self.report_fast_open_failure();
            }
            self.terminal(CloseReason::TimedOut);
            return Ok(());
        }
        if let Some(resource) = &mut self.local_resource
            && due(resource.retry_at, now)
        {
            resource.retry_at = None;
            resource.epoch.get_or_insert(now);
            self.resource_probes = self.resource_probes.saturating_add(1);
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
        //= reason=R1 raises route advice at three RTOs; user_deadline implements R2 closure.
        //# The following procedure MUST be used to handle excessive retransmissions of
        //# data segments (MUST-20):
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.8
        //= reason=Schedules retransmission for transmit; output and deadline servicing are driver-owned.
        //# For any state if the retransmission timeout expires on a segment in the
        //# retransmission queue, send the segment at the front of the retransmission
        //# queue again, reinitialize the retransmission timer, and return.
        if due(self.ecn_pause, now) {
            self.ecn_pause = None;
        }
        if expired_loss == Some(LossTimer::Rack) {
            let fresh_episode = self.prr.is_none() && self.sack_recovery.is_none();
            self.detect_rack();
            let fresh_entry = fresh_episode && self.sack_recovery.is_some_and(|r| r.entry_pending);
            if let Some(prr) = &mut self.prr
                && fresh_entry
            {
                prr.admit_timer_repair(self.rack.pipe(), self.congestion.cwnd());
                // Timer entry has its own first-repair grant. Represent that
                // allowance like ACK-driven PRR, without changing its fixed
                // congestion target or inventing delivery. Later timers keep
                // the active episode's window and accounting intact.
                self.congestion
                    .prr_window(self.rack.pipe().saturating_add(prr.credit()));
            }
        }
        // PTO takes precedence at an RTO-capped tie. Attempts do not back off
        // RTO or reduce cwnd; only successfully encoded probes consume state.
        if expired_loss == Some(LossTimer::Pto) {
            self.tlp_deadline = None;
            self.tlp_pending = self.tlp_eligible()
                && self.tlp_fresh_rtt
                && self.tlp_end.is_none()
                && self.tlp_flight.is_none();
            if self.flight() != 0 {
                self.rto_deadline = Some(now.saturating_add(self.rto()));
            }
        }
        let head_sent = self
            .rack
            .head_transmission(self.snd_una)
            .map(|(_, sent)| sent)
            .or_else(|| {
                (self.fin_sequence == Some(self.snd_una))
                    .then_some(self.fin_sent_at)
                    .flatten()
            });
        if expired_loss == Some(LossTimer::Rto) && self.synchronized() && self.snd_wnd == 0 {
            // Unacknowledged flight retains the post-PTO RTO. Its expiration
            // probes the closed window without treating flow control as loss.
            self.rto_deadline = None;
            self.probe_pending = true;
            if self.persist_interval == 0 {
                self.persist_interval = self.rto();
            }
        } else if expired_loss == Some(LossTimer::Rto)
            && head_sent.is_some_and(|sent| now.saturating_sub(sent) < self.rto())
        {
            self.rto_deadline = head_sent.map(|sent| sent.saturating_add(self.rto()));
        } else if expired_loss == Some(LossTimer::Rto) {
            self.loss_events.timeouts += 1;
            self.growth_dupack_bytes = 0;
            self.congestion.disarm_initial_ack_heuristic();
            // A genuinely transmitted TFO request that reaches RTO trains the
            // service cooldown even if its bare retry is locally blocked. The
            // departure gate and one-shot report prevent unsent attempts or
            // subsequent retries from creating/renewing failure evidence.
            self.report_fast_open_failure();
            // Explicit application give-up budget, not the default SYN R2 policy.
            if self.handshake_pending()
                && self
                    .handshake_retransmission_limit
                    .is_some_and(|limit| self.committed_syn_retransmissions >= limit.get())
            {
                self.terminal(CloseReason::TimedOut);
                return Ok(());
            }
            self.reset_tlp();
            self.congestion.end_ecn_prr();
            self.prr = None;
            let early_response = self.early_response_eligible();
            if !early_response {
                self.rack.rto(now, self.snd_una, self.rtt.srtt());
            }
            self.ptb_timeout();
            //= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
            //= reason=Timeout discards advisory ranges and guards a fresh recovery phase until its exclusive data boundary is covered.
            //# RecoveryPoint MUST be set to HighData.
            if !early_response && self.sack_recovery_enabled() {
                self.scoreboard.clear();
                self.sack_recovery = None;
                self.sack_guard = Some(self.data_high());
                self.sack_post_rto = Some((self.snd_una, self.data_high()));
                self.congestion.cancel_sack_recovery();
            } else if !early_response && !self.handshake_pending() {
                // Without SACK the timed-out flight is resent in order from
                // SND.UNA under slow start (go-back-N, RFC 6582 section 4):
                // each cumulative ACK frees cwnd for the next segments below
                // the timeout's data boundary instead of waiting for another
                // backed-off RTO. recover = highest sent keeps the resulting
                // duplicate ACKs from starting fast retransmit.
                self.sack_post_rto = Some((self.snd_una, self.data_high()));
            }
            self.reset_limited_transmit();
            self.rto_deadline = None;
            self.sample = None;
            self.rtt.backoff();
            self.initial_pacing_open = false;
            self.consecutive_timeouts = self.consecutive_timeouts.saturating_add(1);
            let cooldown = self.pmtu_cooldown();
            // Byte window and segment size before this timeout's path step.
            let (window, mss) = (self.congestion.cwnd(), self.mss);
            if let Some(p) = &mut self.pmtud {
                p.timeout(now, self.snd_una, self.consecutive_timeouts, cooldown);
            }
            self.observe_pmtud_results();
            self.refresh_path_mss();
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
            //# (e) TCP implementations SHOULD inform the application of the delivery
            //# problem (unless such information has been disabled by the application;
            //# see the "Asynchronous Reports" section (Section 3.9.1.8)), when R1 is
            //# reached and before R2 (SHLD-9).
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
            //# The value of R1 SHOULD correspond to at least 3 retransmissions, at the
            //# current RTO (SHLD-10).
            if self.consecutive_timeouts == 3 {
                self.events.retransmission_warning = true;
                self.route_advice_pending = true;
            }
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.2
            //= reason=Connection wires timeout/backoff and ACKs into the congestion controller in recovery.rs.
            //# A TCP endpoint MUST implement the basic congestion control algorithms
            //# slow start, congestion avoidance, and exponential backoff of RTO to
            //# avoid creating congestion collapse conditions (MUST-19).
            if self.handshake_pending() {
                // First SYN timeout may be spurious. More than one is the RFC6928
                // conservative trigger, not proof of physical packet loss.
                self.syn_loss_detected = self.config.initial_window != InitialWindow::Iw10
                    || self.syn_retransmissions > 1;
                if self.syn_loss_detected {
                    self.congestion.on_timeout(self.data_flight(), self.snd_nxt);
                }
            } else {
                self.note_iw_loss(self.snd_una);
                self.congestion.on_timeout(self.data_flight(), self.snd_nxt);
            }
            if self.mss > mss {
                // A black-hole reset raised the MSS: the loss window stays
                // within one SMSS and the byte window held before the raise.
                self.congestion.limit_loss_window(window);
            }
            self.ecn_cwr_pending |= self.ecn_feedback();
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
            //# SYN retransmissions MUST be handled in the general way just described
            //# for data retransmissions, including notification of the application
            //# layer.
            if self.handshake_pending() {
                self.syn_timed_out = true;
                self.syn_pending = true;
            } else {
                self.retx_pending = self.flight() != 0;
            }
        }
        if due(self.ack_deadline, now) {
            if self.config.adaptive_ack {
                self.ack_interactive = false;
                self.ack_quick = self.adaptive_quick_budget();
            }
            self.immediate_ack();
        }
        if expired_loss == Some(LossTimer::Zwp) {
            self.persist_deadline = None;
            self.probe_pending = true;
        }
        if due(self.cork_deadline, now) {
            self.release_corked();
            // Automatic flush supplies PUSH independently of EOR. Explicit
            // NODELAY/uncork leave the application's existing PUSH unchanged.
            self.send.mark_push();
        }
        if due(self.sws_deadline, now) {
            self.sws_deadline = None;
            self.sws_override = true;
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
        //# Consequently, if a keep-alive mechanism is implemented it MUST NOT interpret
        //# failure to respond to any specific probe as a dead connection (MUST-29).
        if due(self.keepalive_deadline, now) {
            self.keepalive_deadline = None;
            if self
                .config
                .keepalive
                .is_some_and(|k| self.keepalive_probes >= k.probes)
            {
                self.terminal(CloseReason::TimedOut);
            } else {
                self.keepalive_pending = true;
            }
        }
        self.select_loss_timer();
        Ok(())
    }
}

#[cfg(test)]
#[path = "connection_test_support.rs"]
pub(crate) mod test_support;

#[cfg(test)]
#[path = "connection_tests.rs"]
mod tests;
