extern crate alloc;

use alloc::vec::Vec;
use core::{cmp::Ordering, net::SocketAddr};

use crate::{
    buffer::{ReceiveBuffer, SendBuffer},
    rack::Rack,
    recovery::{Congestion, InitialWindow, Prr, RecoveryAlgorithm, RttEstimator},
    sack::Scoreboard,
    seq::Seq,
    wire::{self, ACK, CWR, ECE, FIN, Header, IpMetadata, PSH, RST, SYN, Segment, URG},
};

pub type Instant = u64;

#[derive(Clone, Debug)]
pub struct ConnectionConfig {
    pub send_capacity: usize,
    pub receive_capacity: usize,
    pub mss: u16,
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
    pub recovery_algorithm: RecoveryAlgorithm,
    pub initial_window: InitialWindow,
    pub timestamps: bool,
    pub sack: bool,
    // Opt-in RFC 8985 time-based loss detection (requires negotiated SACK).
    pub rack: bool,
    // Opt-in RFC 6937 PRR-CRB recovery pacing (requires negotiated SACK).
    pub prr: bool,
    // Opt-in RFC 8985 tail loss probes; requires rack and sack configuration
    // and negotiated SACK. At most one probe per outstanding flight.
    pub tlp: bool,
    // RTT-derived RTO floor, 1..=60_000_000 us. Values below one second are an
    // explicit deviation from RFC 6298 section 2.4's SHOULD floor. Initial
    // RTO remains one second; the post-SYN-timeout three-second guard remains.
    pub rto_min_us: u64,
    pub retransmit_beyond_window: bool,
    pub delayed_ack_us: u64,
    pub user_timeout_us: u64,
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

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            send_capacity: 65536,
            receive_capacity: 65536,
            mss: 1460,
            receive_ip_payload_limit: u16::MAX,
            send_ip_payload_limit: u16::MAX,
            nagle: true,
            ecn: true,
            recovery_algorithm: RecoveryAlgorithm::default(),
            initial_window: InitialWindow::default(),
            timestamps: false,
            sack: false,
            rack: false,
            prr: false,
            tlp: false,
            rto_min_us: 1_000_000,
            retransmit_beyond_window: false,
            delayed_ack_us: 200_000,
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
            //= reason=Default R2; applications may override the per-connection timeout.
            //# The value of R2 SHOULD correspond to at least 100 seconds (SHLD-11).
            user_timeout_us: 300_000_000,
            time_wait_us: 240_000_000,
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
    pub loss: bool,
    // False after bounded ledger overflow; segment counts are unavailable.
    pub ledger_valid: bool,
    pub unacked: u32,
    pub sacked: u32,
    // Original loss attribution persists through retransmission until delivery.
    pub lost: u32,
    // Outstanding, non-lost retransmissions, excluding SACKed retransmissions.
    pub retransmitted: u32,
    pub reordering: u32,
    pub cwnd: u32,
    pub ssthresh: u32,
    pub mss: u32,
    pub rtt_us: Option<u64>,
    pub rttvar_us: u64,
    pub rto_us: u64,
    pub send_used: usize,
    pub send_capacity: usize,
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
}

impl ConnectionEvents {
    pub(crate) fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

fn after(a: Seq, b: Seq) -> bool {
    a.serial_cmp(b) == Some(Ordering::Greater)
}

fn at_or_after(a: Seq, b: Seq) -> bool {
    a == b || after(a, b)
}

fn due(deadline: Option<Instant>, now: Instant) -> bool {
    deadline.is_some_and(|deadline| now >= deadline)
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

pub(crate) struct Connection {
    tuple: Tuple,
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
    sack_send: bool,
    sack_receive: bool,
    sack_recovery: Option<SackRecovery>,
    sack_guard: Option<Seq>,
    // Retransmitted prefix and fixed data boundary at the most recent timeout.
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
    // Real causative delivery, capped at one MSS and bound to its deferred timer.
    rack_entry_delivery: Option<(u64, u32)>,
    receive_used: usize,
    sack_omit: bool,
    ts_recent: u32,
    ts_latest: u32,
    ts_recent_at: Instant,
    last_ack_sent: Seq,
    reset_echo: Option<u32>,
    last_timestamp_sent_at: Option<Instant>,
    mss: usize,
    advertised_edge: Seq,
    syn_window: u16,
    acknowledged: u64,
    received_read: u64,
    received_total: u64,
    snd_up: Option<Seq>,
    advertised_snd_up: Option<Seq>,
    rcv_up: Option<u64>,
    shutdown: bool,
    read_closed: bool,
    fin_sequence: Option<Seq>,
    syn_pending: bool,
    ack_pending: bool,
    pending_rst: Option<(Seq, bool)>,
    retx_pending: bool,
    duplicate_acks: u8,
    limited_pending: bool,
    limited_sent: u32,
    limited_end: Option<Seq>,
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
    last_output_ecn: u8,
    pub(crate) accepted_metadata: bool,
    sample: Option<(Seq, Instant)>,
    syn_timed_out: bool,
    consecutive_timeouts: u32,
    route_advice_pending: bool,
    rto_deadline: Option<Instant>,
    ack_deadline: Option<Instant>,
    full_segments: u8,
    unacked_bytes: u32,
    persist_deadline: Option<Instant>,
    persist_interval: u64,
    persist_unanswered_since: Option<Instant>,
    shrink_unanswered_since: Option<Instant>,
    sws_deadline: Option<Instant>,
    sws_override: bool,
    time_wait_deadline: Option<Instant>,
    progress_at: Instant,
    application_timeout_us: Option<u64>,
    application_progress_at: Instant,
    last_received: Instant,
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

    //= https://www.rfc-editor.org/rfc/rfc8985#section-4
    //= reason=Constructor rejects TLP unless both RACK and SACK are configured; runtime additionally requires negotiated SACK.
    //# TLP requires RACK.
    pub(crate) fn active_with_receive(
        tuple: Tuple,
        mut config: ConnectionConfig,
        iss: u32,
        now: Instant,
        receive: &mut Option<ReceiveBuffer>,
    ) -> Result<Self, Error> {
        if (config.tlp && (!config.rack || !config.sack))
            || !(1..=60_000_000).contains(&config.rto_min_us)
            || config.send_capacity == 0
            || config.send_capacity >= 1 << 30
            || config.receive_capacity == 0
            || config.receive_capacity > (65535usize << 14)
            || config.receive_ip_payload_limit < 21
            || config.send_ip_payload_limit
                < if config.timestamps {
                    40
                } else if config.sack {
                    32
                } else {
                    28
                }
            || config.mss == 0
            || config.mss > if tuple.local.is_ipv4() { 65495 } else { 65515 }
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.3
            //= reason=Configuration rejects delays of 500 ms or more; the driver must service deadlines.
            //# A TCP endpoint SHOULD implement a delayed ACK (SHLD-18), but an ACK
            //# should not be excessively delayed; in particular, the delay MUST be less
            //# than 0.5 seconds (MUST-40).
            || config.delayed_ack_us >= 500_000
            || config.user_timeout_us == 0
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4.2
            //# For this specification the MSL is taken to be 2 minutes.
            || config.time_wait_us < 240_000_000
            || tuple.local.is_ipv4() != tuple.remote.is_ipv4()
            || config
                .keepalive
                .is_some_and(|k| k.idle_us == 0 || k.interval_us == 0 || k.probes < 2)
        {
            return Err(Error::InvalidArgument);
        }
        // Non-jumbo family limits include the TCP header, not the IP header.
        let family_limit = if tuple.local.is_ipv4() { 65515 } else { 65535 };
        config.receive_ip_payload_limit = config.receive_ip_payload_limit.min(family_limit);
        config.send_ip_payload_limit = config.send_ip_payload_limit.min(family_limit);
        let send = SendBuffer::new(config.send_capacity).map_err(|_| Error::NoMemory)?;
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(config.mss as usize)
            .map_err(|_| Error::NoMemory)?;
        scratch.resize(config.mss as usize, 0);
        let local_scale = (0..=14)
            .find(|&shift| config.receive_capacity <= (65535usize << shift))
            .unwrap_or(14);
        let syn_window = config.receive_capacity.min(65535) as u16;
        let mss = config.mss.min(config.send_ip_payload_limit - 20) as usize;
        let congestion =
            Congestion::new(mss as u32, config.recovery_algorithm, config.initial_window);
        let rtt = RttEstimator::new(config.rto_min_us);
        let rack = Rack::new().map_err(|_| Error::NoMemory)?;
        // Take pooled storage only after every fallible allocation has succeeded.
        let receive = match receive.take() {
            Some(receive) => receive,
            None => {
                ReceiveBuffer::new(Seq(0), config.receive_capacity).map_err(|_| Error::NoMemory)?
            }
        };
        Ok(Self {
            tuple,
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
            sack_send: false,
            sack_receive: false,
            sack_recovery: None,
            sack_guard: None,
            sack_post_rto: None,
            sack_fallback: None,
            scoreboard: Scoreboard::new(),
            rack,
            tlp_deadline: None,
            tlp_pending: false,
            tlp_end: None,
            tlp_flight: None,
            tlp_fresh_rtt: false,
            prr: None,
            rack_entry_delivery: None,
            receive_used: 0,
            sack_omit: false,
            ts_recent: 0,
            ts_latest: 0,
            ts_recent_at: now,
            last_ack_sent: Seq(0),
            reset_echo: None,
            last_timestamp_sent_at: None,
            mss,
            advertised_edge: Seq(0),
            syn_window,
            acknowledged: 0,
            received_read: 0,
            received_total: 0,
            snd_up: None,
            advertised_snd_up: None,
            rcv_up: None,
            shutdown: false,
            read_closed: false,
            fin_sequence: None,
            syn_pending: true,
            ack_pending: false,
            pending_rst: None,
            retx_pending: false,
            duplicate_acks: 0,
            limited_pending: false,
            limited_sent: 0,
            limited_end: None,
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
            last_output_ecn: 0,
            accepted_metadata: false,
            sample: None,
            syn_timed_out: false,
            consecutive_timeouts: 0,
            route_advice_pending: false,
            rto_deadline: None,
            ack_deadline: None,
            full_segments: 0,
            unacked_bytes: 0,
            persist_deadline: None,
            persist_interval: 0,
            persist_unanswered_since: None,
            shrink_unanswered_since: None,
            sws_deadline: None,
            sws_override: false,
            time_wait_deadline: None,
            progress_at: now,
            application_timeout_us: None,
            application_progress_at: now,
            last_received: now,
            last_sent: now,
            retransmit_burst: None,
            keepalive_deadline: None,
            keepalive_probes: 0,
        })
    }

    #[cfg(test)]
    pub(crate) fn passive(
        tuple: Tuple,
        config: ConnectionConfig,
        iss: u32,
        now: Instant,
        syn: &Segment<'_>,
    ) -> Result<Self, Error> {
        Self::passive_with_receive(tuple, config, iss, now, syn, &mut None)
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.2
    //= reason=Passive state is SYN-RECEIVED; transmit commits ISS+1 only after SYN-ACK encoding succeeds.
    //# SND.NXT is set to ISS+1 and SND.UNA to ISS. The connection state should be changed to
    //# SYN-RECEIVED.
    pub(crate) fn passive_with_receive(
        tuple: Tuple,
        config: ConnectionConfig,
        iss: u32,
        now: Instant,
        syn: &Segment<'_>,
        receive: &mut Option<ReceiveBuffer>,
    ) -> Result<Self, Error> {
        if syn.header.flags & (SYN | ACK | RST) != SYN {
            return Err(Error::InvalidArgument);
        }
        let mut connection = Self::active_with_receive(tuple, config, iss, now, receive)?;
        connection.passive_open = true;
        connection.learn_syn(syn);
        connection.state = State::SynReceived;
        Ok(connection)
    }

    pub(crate) fn into_receive(self) -> ReceiveBuffer {
        self.receive
    }

    pub(crate) fn tuple(&self) -> Tuple {
        self.tuple
    }
    pub(crate) fn state(&self) -> State {
        self.state
    }
    pub(crate) fn time_wait_valid(&self, now: Instant) -> bool {
        self.state == State::TimeWait && self.time_wait_deadline.is_some_and(|end| now < end)
    }

    pub(crate) fn reuse_syn(&self, now: Instant, syn: &Segment<'_>, timestamps: bool) -> bool {
        if !self.time_wait_valid(now) {
            return false;
        }
        // RFC 6191 section 2: receive.next() is one beyond the peer's FIN.
        // Conservatively require strictly beyond that frontier for sequence reuse.
        let newer_sequence = after(Seq(syn.header.sequence), self.receive.next());
        match (
            self.timestamps,
            timestamps.then_some(syn.options.timestamps).flatten(),
        ) {
            (true, Some((value, _))) => {
                after(Seq(value), Seq(self.ts_latest)) || value == self.ts_latest && newer_sequence
            }
            (false, Some(_)) => true,
            (_, None) => newer_sequence,
        }
    }

    pub(crate) fn reuse_iss(&self, candidate: u32) -> u32 {
        // Preserve secret-derived entropy, projecting into the forward serial
        // half-space only when necessary. Include pure ACKs at snd_nxt in
        // the old frontier: offsets 1..2^31-1 are strictly serially greater.
        if after(Seq(candidate), self.snd_nxt) {
            candidate
        } else {
            self.snd_nxt.wrapping_add(1 + candidate % 0x7fff_ffff).0
        }
    }

    pub(crate) fn transport_info(&self) -> TransportInfo {
        let counts = self.rack.counts();
        TransportInfo {
            state: self.state,
            recovery: self.congestion.in_recovery(),
            loss: self.sack_post_rto.is_some() || self.consecutive_timeouts != 0,
            ledger_valid: self.rack.valid(),
            unacked: counts.unacked,
            sacked: counts.sacked,
            lost: counts.lost,
            retransmitted: counts.retransmitted,
            reordering: self.rack.reordering,
            cwnd: self.congestion.cwnd(),
            ssthresh: self.congestion.ssthresh(),
            mss: self.mss as u32,
            rtt_us: self.rtt.srtt(),
            rttvar_us: self.rtt.variance(),
            rto_us: self.rto(),
            send_used: self.send.len(),
            send_capacity: self.config.send_capacity,
            receive_used: self.receive_used,
            receive_capacity: self.config.receive_capacity,
        }
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
        self.config.rack && self.sack_receive && self.sack_send && self.rack.valid()
    }

    fn tlp_eligible(&self) -> bool {
        self.config.tlp
            && self.rack_enabled()
            && matches!(self.state, State::Established | State::CloseWait)
            && self.fin_sequence.is_none()
            && self.flight() != 0
            && self.snd_wnd >= self.flight()
            && !self.congestion.in_recovery()
            && self.sack_post_rto.is_none()
            && self.consecutive_timeouts == 0
            && !self.retx_pending
            && self.rack.counts().sacked == 0
            && self.rack.deadline.is_none()
    }

    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.2
    //= reason=Conditional evidence: new-data and advancing-ACK callers schedule only outside recovery, complete SACK, zero/shrunken window, FIN and invalid-ledger states, with a fresh RTT and no outstanding probe.
    //# The sender SHOULD start or
    //# restart a loss probe PTO timer after transmitting new data (that was
    //# not itself a loss probe) or upon receiving an ACK that cumulatively
    //# acknowledges new data unless it is already in fast recovery, RTO
    //# recovery, or segments have been SACKed (i.e., RACK.segs_sacked is not
    //# zero).
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.2
    //= reason=Partial arithmetic evidence: missing SRTT uses 500000*2 = one second before the RTO cap. Fresh-sample eligibility normally makes this fallback unreachable.
    //# Second, when there is no SRTT estimate available, the PTO SHOULD be 1
    //# second.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.2
    //= reason=Optional inflation is not selected: PTO remains 2*SRTT even for a single segment; no TLP.max_ack_delay budget is modeled. This is evidence of the permitted non-inflating choice, not delayed-ACK mitigation.
    //# Third, when the FlightSize is one segment, the sender MAY inflate the
    //# PTO by TLP.max_ack_delay to accommodate a potentially delayed
    //# acknowledgment and reduce the risk of spurious retransmissions.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.2
    //= reason=2*SRTT or one second, capped by current RTO; optional single-segment delay inflation omitted.
    //# Summarizing these considerations in pseudocode form, a sender SHOULD
    //# use the following logic to select the duration of a PTO:
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.2
    //= reason=2*SRTT or one second capped by RTO; permitted single-segment inflation not implemented.
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
    fn schedule_tlp(&mut self) {
        if self.tlp_eligible()
            && self.tlp_fresh_rtt
            && self.tlp_end.is_none()
            && self.tlp_flight.is_none()
            && !self.tlp_pending
        {
            self.tlp_deadline = self.rto_deadline.map(|rto| {
                self.now
                    .saturating_add(self.rtt.srtt().unwrap_or(500_000).saturating_mul(2).max(1))
                    .min(rto)
            });
        }
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
        if self.tlp_flight.is_some_and(|end| at_or_after(ack, end)) {
            self.tlp_flight = None;
        }
        let Some((start, end, retransmit)) = self.tlp_end else {
            return false;
        };
        if !at_or_after(ack, end) {
            return false;
        }
        let matching_dsack = dsack
            && blocks[0]
                .is_some_and(|(left, right)| at_or_after(start, Seq(left)) && Seq(right) == end);
        let repaired = retransmit && !matching_dsack && after(ack, end);
        if !retransmit
            || matching_dsack
            || repaired
            || (!advancing && duplicate && blocks.iter().all(Option::is_none))
        {
            self.tlp_end = None;
        }
        repaired
    }

    fn sack_recovery_enabled(&self) -> bool {
        self.sack_receive && (!(self.config.rack || self.config.prr) || self.sack_send)
    }

    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= reason=Uses Scoreboard::pipe without RACK, Rack::pipe with RACK. The latter is not proof of the literal RFC 6675 estimator; TODO remains.
    //# pipe = (RFC 6675 pipe algorithm)
    fn recovery_pipe(&self, high_rxt: Seq) -> u32 {
        if self.rack_enabled() {
            self.rack.pipe()
        } else {
            self.scoreboard
                .pipe(self.snd_una, self.data_high(), high_rxt, self.mss as u32)
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc6937#section-2
    //= reason=Uses byte PRR credit rather than inflated cwnd when PRR is active. Does not prove all output-path or entry behavior.
    //# We introduce a local variable "sndcnt", which indicates exactly how
    //# many bytes should be sent in response to each ACK.
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
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= reason=Scoped entry evidence: threshold selected by Congestion and flight passed to Prr::new. Does not justify the initial-MSS override or delayed-entry delivery policy; tracked TODOs remain.
    //# At the beginning of recovery, initialize PRR state.
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= reason=Scoped entry evidence: threshold selected by Congestion and flight passed to Prr::new. Does not justify the initial-MSS override or delayed-entry delivery policy; tracked TODOs remain.
    //# ssthresh = CongCtrlAlg()  // Target cwnd after recovery
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= reason=Scoped entry evidence: threshold selected by Congestion and flight passed to Prr::new. Does not justify the initial-MSS override or delayed-entry delivery policy; tracked TODOs remain.
    //# RecoverFS = snd.nxt-snd.una // FlightSize at the start of recovery
    fn start_sack_recovery(&mut self) -> bool {
        if self.sack_guard.is_some()
            || self.sack_recovery.is_some()
            || !after(self.data_high(), self.snd_una)
            || !self.congestion.on_sack_recovery(
                self.snd_una,
                self.flight().saturating_sub(self.limited_sent),
                self.data_high(),
            )
        {
            return false;
        }
        self.reset_tlp();
        self.rack_entry_delivery = None;
        self.sack_recovery = Some(SackRecovery {
            recovery_point: self.data_high(),
            high_rxt: self.snd_una,
            rescue_rxt: None,
            entry_pending: true,
            pipe: self.recovery_pipe(self.snd_una),
        });
        if self.config.prr && self.sack_send && self.rack.valid() {
            self.prr = Some(Prr::new(self.flight(), self.mss as u32));
        }
        self.retx_pending = false;
        self.limited_pending = false;
        self.ecn_cwr_pending |= self.ecn_feedback();
        true
    }

    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.2
    //= reason=Lost retransmissions trigger additional congestion response, then revised RACK recovery selection.
    //# Therefore, the algorithm [RFC6675]
    //# MUST NOT be used with RACK-TLP; instead, a modified recovery
    //# algorithm that carefully addresses such a case is needed.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
    //= reason=Every newly detected lost retransmission calls Congestion::retransmission_lost, independently of the PRR option.
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
    //= reason=Original losses share recovery entry; lost retransmissions within one detect call aggregate into one additional response. This does not establish grouping across multiple ACKs in one retransmission window.
    //# If multiple original transmissions or retransmissions were lost in a
    //# window, the congestion control specified in [RFC5681] only reacts
    //# once per window.
    fn detect_rack(&mut self) {
        if !self.rack_enabled() || self.snd_wnd == 0 {
            self.rack.deadline = None;
            return;
        }
        let retransmission_lost = self.rack.detect(
            self.now,
            self.sack_recovery.is_some() || self.sack_post_rto.is_some(),
            self.rtt.srtt(),
        );
        if retransmission_lost {
            self.congestion.retransmission_lost(self.flight());
        }
        if self.rack.lowest_lost(self.mss as u32).is_some() {
            self.start_sack_recovery();
        }
        if let Some(mut recovery) = self.sack_recovery {
            recovery.pipe = self.rack.pipe();
            self.sack_recovery = Some(recovery);
        }
    }

    pub(crate) fn acknowledged(&self) -> u64 {
        self.acknowledged
    }
    pub(crate) fn close_reason(&self) -> Option<CloseReason> {
        self.reason
    }
    pub(crate) fn events_pending(&self) -> bool {
        !self.events.is_empty()
    }
    pub(crate) fn take_events(&mut self) -> ConnectionEvents {
        core::mem::take(&mut self.events)
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.5
    //# The TCP implementation MUST (MUST-33) provide a way for the application to learn
    //# how much urgent data remains to be read from the connection, or at least to
    //# determine whether more urgent data remains to be read [19].
    pub(crate) fn urgent_remaining(&self) -> u64 {
        if matches!(self.state, State::SynSent | State::SynReceived)
            || self.state == State::Closed && self.reason != Some(CloseReason::Normal)
        {
            return 0;
        }
        self.rcv_up.unwrap_or(0).saturating_sub(self.received_read)
    }

    pub(crate) fn readable_bytes(&self) -> usize {
        if self.read_closed
            || matches!(self.state, State::SynSent | State::SynReceived)
            || self.state == State::Closed
                && (self.reason != Some(CloseReason::Normal) || !self.receive.eof())
        {
            return 0;
        }
        self.receive.readable()
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
                keepalive.map(|k| self.now.saturating_add(k.idle_us))
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

    pub(crate) fn network_error(
        &mut self,
        now: Instant,
        quoted_sequence: u32,
        error: NetworkError,
    ) -> Result<bool, Error> {
        self.check_time(now)?;
        self.now = now;
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
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
        //= reason=Acts on adapter-classified errors only; soft errors remain nonterminal.
        //# Since these Unreachable messages indicate soft error conditions, a
        //# TCP implementation MUST NOT abort the connection (MUST-56), and it
        //# SHOULD make the information available to the application (SHLD-25).
        self.events.network_error = Some(error);
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
        //# These are hard error conditions, so TCP implementations SHOULD abort the
        //# connection (SHLD-26).
        if error == NetworkError::HardUnreachable {
            self.terminal(CloseReason::NetworkError);
        }
        Ok(true)
    }

    pub(crate) fn lower_mss(&mut self, mss: u16) -> Result<(), Error> {
        let effective = mss
            .saturating_sub(if self.timestamps { 12 } else { 0 })
            .max(1);
        if mss == 0 || effective as usize > self.mss {
            return Err(Error::InvalidArgument);
        }
        if effective as usize == self.mss {
            return Ok(());
        }
        self.mss = effective as usize;
        // Also constrain future SYN offers and negotiation if this occurs
        // before the peer's SYN; the scratch allocation never changes.
        self.config.mss = self.config.mss.min(mss);
        self.congestion.set_mss(effective as u32);
        if let Some(mut recovery) = self.sack_recovery {
            recovery.pipe = self.recovery_pipe(recovery.high_rxt);
            self.sack_recovery = Some(recovery);
        }
        if self.flight() != 0 {
            if matches!(self.state, State::SynSent | State::SynReceived) {
                self.syn_pending = true;
            } else if self.synchronized() && self.snd_wnd != 0 && self.sack_recovery.is_none() {
                self.retx_pending = true;
            }
        }
        self.arm_work();
        Ok(())
    }

    pub(crate) fn update_time(&mut self, now: Instant) -> Result<(), Error> {
        self.check_time(now)?;
        self.now = now;
        Ok(())
    }

    fn check_time(&self, now: Instant) -> Result<(), Error> {
        if now < self.now {
            Err(Error::TimeWentBackwards)
        } else {
            Ok(())
        }
    }

    // Classic RFC 3168 only: setup offers remain binding for receive feedback even
    // after a local fallback forbids sending ECT data.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.2
    //# A TCP endpoint SHOULD implement ECN as described in RFC 3168 (SHLD-
    //# 8).
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

    pub(crate) fn last_output_ecn(&self) -> u8 {
        self.last_output_ecn
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.2
    //= reason=Passive constructor consumes SYN sequence, learns peer, and schedules SYN-ACK. SYN text buffering/delivery scope separately cited.
    //# Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ, and any other control or text should be
    //# queued for processing later. ISS should be selected and a SYN segment sent of the form:
    //# <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
    fn learn_syn(&mut self, syn: &Segment<'_>) {
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
        self.peer_scale = syn.options.window_scale.unwrap_or(0).min(14);
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
        self.mss = syn
            .options
            .mss
            .unwrap_or(default_mss)
            .max(1)
            .min(self.config.mss)
            .saturating_sub(if self.timestamps { 12 } else { 0 })
            .max(1)
            .min(self.config.send_ip_payload_limit - 20 - if self.timestamps { 12 } else { 0 })
            as usize;
        self.congestion
            .set_initial_mss(self.mss as u32, self.syn_timed_out);
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
        //# The window size MUST be treated as an unsigned number, or else large window
        //# sizes will appear like negative windows and TCP will not work (MUST-1).
        self.snd_wnd = syn.header.window as u32;
        self.max_snd_wnd = self.snd_wnd;
        self.wl1 = Seq(syn.header.sequence);
        self.wl2 = Seq(syn.header.acknowledgment);
        let count = syn.payload.len().min(self.syn_window as usize);
        let fin = syn.header.flags & FIN != 0 && syn.payload.len() < self.syn_window as usize;
        let outcome = self.receive.insert_with_push(
            start,
            &syn.payload[..count],
            fin,
            syn.header.flags & PSH != 0 && count == syn.payload.len(),
        );
        self.received_total = count as u64;
        self.receive_used += outcome.new_bytes;
        if outcome.fin {
            self.syn_window = 0;
        } else {
            self.syn_window -= count as u16;
        }
        if syn.header.flags & URG != 0 && syn.header.urgent_pointer > 1 {
            self.rcv_up = Some((syn.header.urgent_pointer - 1) as u64);
        }
    }

    fn rto(&self) -> u64 {
        self.rtt
            .rto()
            .max(if self.syn_timed_out { 3_000_000 } else { 0 })
    }

    fn flight(&self) -> u32 {
        self.snd_nxt.distance_from(self.snd_una)
    }

    fn synchronized(&self) -> bool {
        !matches!(
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

    fn establish(&mut self) {
        self.state = State::Established;
        self.syn_pending = false;
        self.events.connected = true;
        self.events.writable = !self.shutdown && self.send.remaining() != 0;
        self.events.readable =
            !self.read_closed && (self.receive.readable() != 0 || self.receive.eof());
        self.events.pushed |= self.receive.take_push();
        self.events.urgent = if self.read_closed { None } else { self.rcv_up };
        if self.receive.eof() {
            self.events.half_closed = true;
            self.state = State::CloseWait;
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
    fn terminal(&mut self, reason: CloseReason) {
        self.state = State::Closed;
        self.reset_tlp();
        self.rack.deadline = None;
        self.prr = None;
        self.rack_entry_delivery = None;
        self.sack_recovery = None;
        self.sack_guard = None;
        self.sack_post_rto = None;
        self.sack_fallback = None;
        self.scoreboard.clear();
        self.ecn_echo = false;
        self.ecn_cwr_pending = false;
        self.ecn_pause = None;
        self.ecn_sent_setup = false;
        self.reason = Some(reason);
        self.events.closed = Some(reason);
        if reason != CloseReason::Aborted {
            self.pending_rst = None;
        }
        self.syn_pending = false;
        self.ack_pending = false;
        self.retx_pending = false;
        self.probe_pending = false;
        self.keepalive_pending = false;
        self.rto_deadline = None;
        self.ack_deadline = None;
        self.persist_deadline = None;
        self.shrink_unanswered_since = None;
        self.sws_deadline = None;
        self.time_wait_deadline = None;
        self.keepalive_deadline = None;
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.6.1
    //# When a connection is closed actively, it MUST linger in the TIME-WAIT
    //# state for a time 2xMSL (Maximum Segment Lifetime) (MUST-13).
    // Configuration enforces at least twice RFC 9293's 120-second MSL.
    fn time_wait(&mut self) {
        self.terminal(CloseReason::Normal);
        self.state = State::TimeWait;
        self.time_wait_deadline = Some(self.now.saturating_add(self.config.time_wait_us));
        self.immediate_ack();
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
    //# In particular, R2 for a SYN segment MUST be set large enough to provide
    //# retransmission of the segment for at least 3 minutes (MUST-23).
    fn user_timeout(&self) -> u64 {
        if matches!(self.state, State::SynSent | State::SynReceived) {
            self.config.user_timeout_us.max(180_000_000)
        } else {
            self.config.user_timeout_us
        }
    }

    fn user_timer_needed(&self) -> bool {
        matches!(
            self.state,
            State::SynSent | State::SynReceived | State::FinWait2
        ) || (self.synchronized()
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
        matches!(self.state, State::SynSent | State::SynReceived)
            || (self.synchronized()
                && (self.send.len() != 0
                    || self.flight() != 0
                    || self.shutdown && self.fin_sequence.is_none()))
    }

    fn application_deadline(&self) -> Option<Instant> {
        self.application_timeout_us
            .filter(|_| self.application_timer_needed())
            .map(|timeout| self.application_progress_at.saturating_add(timeout))
    }

    fn arm_work(&mut self) {
        if !self.synchronized() {
            return;
        }
        if !self.tlp_eligible() {
            self.tlp_deadline = None;
            self.tlp_pending = false;
        }
        let pending = self.send.len() != 0
            || self.flight() != 0
            || self.shutdown && self.fin_sequence.is_none();
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
        //# If the window shrinks to zero, the TCP implementation MUST probe it in the
        //# standard way (described below) (MUST-35).
        if self.snd_wnd == 0 && pending {
            if self.persist_deadline.is_none() && !self.probe_pending {
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1
                //# The transmitting host SHOULD send the first zero-window probe when a
                //# zero window has existed for the retransmission timeout period (SHLD-
                //# 29) (Section 3.8.1),
                if self.persist_interval == 0 {
                    self.persist_interval = self.rto();
                }
                self.persist_deadline = Some(self.now.saturating_add(self.persist_interval));
            }
            self.rto_deadline = None;
        } else {
            self.persist_deadline = None;
            self.probe_pending = false;
            self.persist_interval = 0;
            self.persist_unanswered_since = None;
            if self.flight() != 0 && self.rto_deadline.is_none() && !self.retx_pending {
                self.rto_deadline = Some(self.now.saturating_add(self.rto()));
            }
        }
        let unsent = self.send.len() > self.snd_nxt.distance_from(self.send_base) as usize;
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
        //= reason=SWS override, retransmission and user deadlines require driver servicing.
        //# MUST NOT buffer data indefinitely (MUST-60),
        if unsent && self.snd_wnd != 0 {
            if self.sws_deadline.is_none() && !self.sws_override {
                self.sws_deadline = Some(self.now.saturating_add(500_000));
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
                self.keepalive_deadline =
                    Some(self.last_received.saturating_add(keepalive.idle_us));
            }
        } else {
            self.keepalive_deadline = None;
            self.keepalive_pending = false;
        }
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
        if self.shutdown
            || !matches!(
                self.state,
                State::SynSent | State::SynReceived | State::Established | State::CloseWait
            )
        {
            return Err(Error::InvalidState);
        }
        if data.is_empty() {
            if push {
                self.send.mark_push();
            }
            return Ok(0);
        }
        let application_idle = !self.application_timer_needed();
        let idle = !self.user_timer_needed();
        let count = self.send.write(data);
        if count == 0 {
            return Err(Error::WouldBlock);
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
        let sent = if matches!(self.state, State::SynSent | State::SynReceived) {
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
        let window_prefix = if after(edge, self.send_base) {
            (edge.distance_from(self.send_base) as usize).min(self.send.len())
        } else {
            0
        };
        let retained = sent.max(advertised).max(window_prefix).min(self.send.len());
        let discarded = self.send.len() - retained;
        self.send.truncate(retained);
        let end = self.send_base.wrapping_add(retained as u32);
        if self.snd_up.is_some_and(|up| after(up, end)) {
            self.snd_up = (retained != 0).then_some(end);
        }
        if discarded != 0 {
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
        if matches!(self.state, State::SynSent | State::SynReceived) {
            return Err(Error::WouldBlock);
        }
        let count = self.receive.read(out);
        self.receive_used -= count;
        if count == 0 && !self.receive.eof() {
            return Err(Error::WouldBlock);
        }
        self.received_read = self.received_read.saturating_add(count as u64);
        let credit = self
            .receive
            .right_edge()
            .distance_from(self.advertised_edge);
        if count != 0
            && !self.receive.eof()
            && credit < 1 << 31
            && credit >= self.window_threshold()
        {
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
    //= reason=Only SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1/2 and CLOSE-WAIT emit reset; release is endpoint-owned.
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
            .then_some((self.snd_nxt, false));
            self.terminal(CloseReason::Aborted);
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.4
    //# However, there MUST be a way for an application to disable the Nagle algorithm
    //# on an individual connection (MUST-17).
    pub(crate) fn set_nagle(&mut self, enabled: bool) {
        self.config.nagle = enabled;
    }

    #[cfg(test)]
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
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Validated negotiated ACKs update in-flight ranges; stale/future/DSACK-only blocks cannot count as fresh delivery.
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
    //= https://www.rfc-editor.org/rfc/rfc6937#section-2
    //= reason=Partial byte-ledger evidence: acknowledge counts new covered bytes once; feeds PRR on ACKs while active and disables PRR on invalid ledger. Signed-delta equivalence and retained pre-entry interval accounting remain TODOs.
    //# SACKd: The total number of bytes that the scoreboard indicates have
    //# been delivered to the receiver.  This can be computed by scanning
    //# the scoreboard and counting the total number of bytes covered by
    //# all SACK blocks.  If SACK is not in use, SACKd is not defined.
    //= https://www.rfc-editor.org/rfc/rfc6937#section-2
    //= reason=Partial byte-ledger evidence: acknowledge counts new covered bytes once; feeds PRR on ACKs while active and disables PRR on invalid ledger. Signed-delta equivalence and retained pre-entry interval accounting remain TODOs.
    //# With SACK,
    //# DeliveredData can be computed precisely as the change in snd.una,
    //# plus the (signed) change in SACKd.
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= reason=Partial byte-ledger evidence: acknowledge counts new covered bytes once; feeds PRR on ACKs while active and disables PRR on invalid ledger. Signed-delta equivalence and retained pre-entry interval accounting remain TODOs.
    //# On every ACK during recovery compute:
    //#
    //#    DeliveredData = change_in(snd.una) + change_in(SACKd)
    //#    prr_delivered += DeliveredData
    //= https://www.rfc-editor.org/rfc/rfc6937#section-2
    //= reason=Partial byte-ledger evidence: acknowledge counts new covered bytes once; feeds PRR on ACKs while active and disables PRR on invalid ledger. Signed-delta equivalence and retained pre-entry interval accounting remain TODOs.
    //# Furthermore, for any TCP
    //# (with or without SACK), the sum of DeliveredData must agree with the
    //# forward progress over the same time interval.
    //= https://www.rfc-editor.org/rfc/rfc6937#section-2
    //= reason=Delayed timer entry reuses retained pre-entry ACK delivery (capped at MSS) instead of a current ACK; audit interval/epoch semantics rather than treating one-shot evidence as compliance. ACK path ledger counts unique covered bytes; this is partial evidence, not a deferred-entry waiver.
    //# DeliveredData: The total number of bytes that the current ACK
    //# indicates have been delivered to the receiver.
    pub(crate) fn input_with_traffic_class(
        &mut self,
        now: Instant,
        traffic_class: u8,
        segment: &Segment<'_>,
    ) -> Result<(), Error> {
        self.accepted_metadata = false;
        self.check_time(now)?;
        self.now = now;
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
            let valid_ack =
                h.flags & ACK != 0 && after(ack, self.iss) && at_or_after(self.snd_nxt, ack);
            if h.flags & ACK != 0 && !valid_ack {
                if h.flags & RST == 0 {
                    self.pending_rst = Some((ack, false));
                    self.reset_echo = segment
                        .options
                        .timestamps
                        .filter(|_| self.config.timestamps)
                        .map(|ts| ts.0);
                }
                return Ok(());
            }
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
            //# Otherwise (no ACK), drop the segment and return.
            if h.flags & RST != 0 {
                if valid_ack {
                    self.terminal(CloseReason::Reset);
                }
                return Ok(());
            }
            if h.flags & SYN == 0 {
                return Ok(());
            }
            self.accepted_metadata = true;
            self.learn_syn(segment);
            self.last_received = now;
            if valid_ack {
                self.accept_ack(ack, false, segment.options.timestamps.map(|ts| ts.1));
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
        // timestamps never update connection state. Missing TS is silent loss.
        let recent_valid = now.saturating_sub(self.ts_recent_at) <= 24 * 86_400_000_000;
        if self.timestamps && h.flags & RST == 0 {
            let Some((value, _)) = segment.options.timestamps else {
                return Ok(());
            };
            if recent_valid && !at_or_after(Seq(value), Seq(self.ts_recent)) {
                self.immediate_ack();
                return Ok(());
            }
        }

        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.5
        //# A TCP implementation MUST support simultaneous open attempts (MUST- 10).
        // Simultaneous open: the SYN has already consumed receive sequence
        // space. Only the identical SYN+ACK can finish this handshake here.
        if self.state == State::SynReceived
            && !self.passive_open
            && self.irs == Some(seq)
            && h.flags & (SYN | ACK | RST | FIN) == (SYN | ACK)
            && ack == self.iss.wrapping_add(1)
            && ack == self.snd_nxt
        {
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
            self.accept_ack(ack, false, segment.options.timestamps.map(|ts| ts.1));
            self.establish();
            self.last_received = now;
            self.immediate_ack();
            self.receive_text(
                seq.wrapping_add(1),
                segment.payload,
                h.flags & !SYN,
                h.urgent_pointer.saturating_sub(1),
            );
            self.arm_work();
            return Ok(());
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
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
                && (!recent_valid || after(Seq(value), Seq(self.ts_latest)))
            {
                self.ts_latest = value;
            }
            self.immediate_ack();
            self.time_wait_deadline = Some(now.saturating_add(self.config.time_wait_us));
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
        if !acceptable {
            // Old text is not admitted, but a validated duplicate may be
            // reported without accepting its ACK/window/metadata (RFC 2883).
            if self.sack_send
                && self.synchronized()
                && h.flags & (ACK | RST | SYN) == ACK
                && !segment.payload.is_empty()
                && segment.payload.len() < 1usize << 31
                && after(next, seq)
                && at_or_after(next, seq.wrapping_add(segment.payload.len() as u32))
                && at_or_after(self.snd_nxt, ack)
                && at_or_after(
                    ack,
                    self.snd_una
                        .wrapping_add(0u32.wrapping_sub(self.max_snd_wnd)),
                )
            {
                self.receive.record_duplicate(seq, segment.payload.len());
                self.sack_omit = false;
            }
            if h.flags & RST == 0 {
                if self.state == State::SynReceived && h.flags & SYN != 0 && self.irs == Some(seq) {
                    if h.flags & (ACK | FIN) == 0 {
                        self.learn_ecn(h.flags);
                        self.sack_send |= self.config.sack && segment.options.sack_permitted;
                    }
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
                let passive = self.state == State::SynReceived && self.passive_open;
                self.terminal(CloseReason::Reset);
                if passive {
                    self.events = ConnectionEvents::default();
                }
            } else {
                self.immediate_ack();
            }
            return Ok(());
        }
        if self.timestamps
            && let Some((value, _)) = segment.options.timestamps
            && (!recent_valid || after(Seq(value), Seq(self.ts_latest)))
        {
            self.ts_latest = value;
        }
        if self.timestamps
            && at_or_after(self.last_ack_sent, seq)
            && let Some((value, _)) = segment.options.timestamps
            && (!recent_valid || at_or_after(Seq(value), Seq(self.ts_recent)))
        {
            self.ts_recent = value;
            self.ts_recent_at = now;
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
            if self.state == State::SynReceived && self.passive_open {
                // Endpoint owns LISTEN independently; closing this unaccepted
                // child releases its slot without notifying the application.
                self.terminal(CloseReason::Reset);
                self.events = ConnectionEvents::default();
            } else {
                self.immediate_ack();
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
        let oldest_ack = self
            .snd_una
            .wrapping_add(0u32.wrapping_sub(self.max_snd_wnd));
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
        //# All incoming segments
        //# whose ACK value doesn't satisfy the above condition MUST be
        //# discarded and an ACK sent back.
        if !at_or_after(self.snd_nxt, ack) || !at_or_after(ack, oldest_ack) {
            self.immediate_ack();
            return Ok(());
        }
        if self.state == State::SynReceived {
            if !after(ack, self.snd_una) {
                self.pending_rst = Some((ack, false));
                self.reset_echo = segment
                    .options
                    .timestamps
                    .filter(|_| self.config.timestamps)
                    .map(|ts| ts.0);
                return Ok(());
            }
            self.accept_ack(ack, false, segment.options.timestamps.map(|ts| ts.1));
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
        // ECN never bypasses sequence, RST/SYN, or ACK-range validation.
        // Old ACKs cannot signal sender congestion, but their accepted duplex
        // data still carries receive-side CE/CWR (RFC 3168 section 6.1.3).
        let ece = self.ecn_feedback() && at_or_after(ack, self.snd_una) && h.flags & ECE != 0;
        if self.ecn_feedback() {
            if h.flags & CWR != 0 && self.ecn_ce_end.is_none_or(|end| at_or_after(seq, end)) {
                self.ecn_echo = false;
                self.ecn_ce_end = None;
            }
            if traffic_class & 3 == 3 && !segment.payload.is_empty() && window != 0 {
                self.ecn_echo = true;
                let end = seq.wrapping_add(segment.payload.len() as u32);
                if self.ecn_ce_end.is_none_or(|old| after(end, old)) {
                    self.ecn_ce_end = Some(end);
                }
                self.immediate_ack();
            }
        }
        let old_window = self.snd_wnd;
        let was_blocked = old_window == 0 || self.flight() > old_window;
        let advancing = after(ack, self.snd_una);
        if advancing {
            self.rack_entry_delivery = None;
            self.tlp_pending = false;
        }
        let ecn_one = ece && self.flight() != 0 && self.congestion.cwnd() <= self.mss as u32;
        let ecn_reduced =
            ece && self.flight() != 0 && self.congestion.on_ecn(ack, self.flight(), self.snd_nxt);
        if ecn_reduced {
            self.ecn_cwr_pending = true;
            self.reset_limited_transmit();
        }
        let mut delivered = 0;
        let mut dsack = false;
        let tlp_flight = self.flight();
        let sack_evidence = if self.sack_receive
            && at_or_after(ack, self.snd_una)
            && self.sack_fallback.is_none_or(|end| at_or_after(ack, end))
        {
            let cumulative_delivery = if advancing {
                self.scoreboard.unsacked_bytes(self.snd_una, ack)
            } else {
                0
            };
            let update =
                self.scoreboard
                    .update(ack, self.data_high(), &segment.options.sack_blocks);
            dsack = update.dsack;
            if update.overflow {
                self.rack.abandon(self.data_high());
                self.prr = None;
                self.rack_entry_delivery = None;
                let boundary = self.data_high();
                self.sack_fallback = Some(boundary);
                self.sack_guard = Some(boundary);
                self.sack_recovery = None;
                self.sack_post_rto = None;
                self.congestion.cancel_sack_recovery();
                self.reset_limited_transmit();
            }
            let ledger_delivery = self.rack.acknowledge(
                ack,
                self.data_high(),
                &self.scoreboard,
                now,
                segment.options.timestamps.map(|ts| ts.1),
                self.timestamps,
                self.mss as u32,
                update.dsack,
            );
            // Splitting at ACK/SACK edges can exhaust the ledger during this
            // call. Do not use its delivery or retain PRR after that transition.
            delivered = if self.rack.valid() {
                ledger_delivery
            } else {
                self.prr = None;
                self.rack_entry_delivery = None;
                cumulative_delivery.saturating_add(update.newly_sacked)
            };
            if !self.rack_enabled() {
                self.rack
                    .mark_scoreboard_losses(&self.scoreboard, self.mss as u32);
            }
            if self.rack_enabled()
                && !advancing
                && let Some(sample) = self.rack.ack_sample
            {
                self.rtt.sample(sample);
                self.tlp_fresh_rtt = true;
            }
            update.newly_sacked != 0 && !update.overflow
        } else {
            false
        };
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
        let tlp_reduced =
            tlp_repaired && self.congestion.on_tlp_repair(ack, tlp_flight, self.snd_nxt);
        if tlp_reduced {
            self.ecn_cwr_pending |= self.ecn_feedback();
        }
        if advancing {
            // Do not grow cwnd on the ACK that just triggered a loss reduction.
            self.accept_ack(
                ack,
                ece || tlp_reduced,
                segment.options.timestamps.map(|ts| ts.1),
            );
        }
        if at_or_after(ack, self.snd_una)
            && let Some(mut recovery) = self.sack_recovery
        {
            if at_or_after(ack, recovery.recovery_point) {
                self.sack_recovery = None;
                self.prr = None;
                self.rack_entry_delivery = None;
                self.rack.recovery_exit();
            } else {
                recovery.pipe = self.recovery_pipe(recovery.high_rxt);
                self.sack_recovery = Some(recovery);
            }
        }
        if ecn_one {
            let deadline = now.saturating_add(self.rto());
            self.ecn_pause = Some(deadline);
            if self.flight() != 0 {
                self.rto_deadline = Some(deadline);
            }
        }
        if self.state == State::Closed || self.state == State::TimeWait {
            return Ok(());
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
        //# If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK)), set
        //# SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.
        if at_or_after(ack, self.snd_una)
            && (after(seq, self.wl1) || seq == self.wl1 && at_or_after(ack, self.wl2))
        {
            self.snd_wnd = (h.window as u32) << if self.scaling { self.peer_scale } else { 0 };
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
        if self.sack_recovery_enabled() {
            if sack_evidence && self.sack_recovery.is_none() {
                self.duplicate_acks = self.duplicate_acks.saturating_add(1);
                self.limited_pending = self.duplicate_acks <= 2 && self.sack_guard.is_none();
                if !self.rack_enabled()
                    && (self.duplicate_acks >= 3
                        || self.scoreboard.is_lost(self.snd_una, self.mss as u32))
                {
                    self.rack
                        .mark_scoreboard_losses(&self.scoreboard, self.mss as u32);
                    self.start_sack_recovery();
                }
            }
        } else if !advancing
            && ack == self.snd_una
            && self.flight() != 0
            && segment.payload.is_empty()
            && h.flags & FIN == 0
            && self.snd_wnd == old_window
            && self.snd_wnd != 0
        {
            self.duplicate_acks = self.duplicate_acks.saturating_add(1);
            // RFC 5681 limited transmit: one new segment on each of the first
            // two duplicate ACKs, bounded by cwnd + 2 MSS and the peer window.
            self.limited_pending = self.duplicate_acks <= 2;
            if self.congestion.on_duplicate_ack(
                self.flight().saturating_sub(self.limited_sent),
                self.snd_nxt,
            ) {
                self.retx_pending = true;
                self.ecn_cwr_pending |= self.ecn_feedback();
                self.limited_pending = false;
            }
        } else if !advancing {
            self.reset_limited_transmit();
            self.congestion.reset_duplicate_acks();
        }
        self.detect_rack();
        if self.sack_recovery.is_none()
            && !advancing
            && delivered != 0
            && self.rack.ack_sample.is_some()
        {
            self.rack_entry_delivery = self
                .rack
                .deadline
                .map(|deadline| (deadline, delivered.min(self.mss as u32)));
        }
        if self.rack.deadline.is_none() || !self.rack.valid() {
            self.rack_entry_delivery = None;
        }
        if let Some(mut prr) = self.prr {
            let pipe = self.sack_recovery.map_or(0, |r| r.pipe);
            prr.acknowledge(delivered, pipe, self.congestion.ssthresh());
            if self.sack_recovery.is_some_and(|r| r.entry_pending) {
                // The first retransmission is guaranteed, including timer entry.
                prr.guarantee_initial(self.mss as u32);
            }
            self.prr = Some(prr);
        }
        self.receive_text(seq, segment.payload, h.flags, h.urgent_pointer);
        self.arm_work();
        if advancing {
            self.schedule_tlp();
        }
        Ok(())
    }

    fn data_high(&self) -> Seq {
        self.fin_sequence.unwrap_or(self.snd_nxt)
    }

    fn reset_limited_transmit(&mut self) {
        self.duplicate_acks = 0;
        self.limited_pending = false;
        self.limited_sent = 0;
        self.limited_end = None;
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
    fn accept_ack(&mut self, ack: Seq, ece: bool, echo: Option<u32>) {
        if !self.sack_receive {
            self.rack.acknowledge(
                ack,
                self.data_high(),
                &self.scoreboard,
                self.now,
                echo,
                self.timestamps,
                self.mss as u32,
                false,
            );
        }
        let limited = self
            .limited_end
            .filter(|&end| self.sack_recovery_enabled() && after(end, ack))
            .map(|end| (end, self.limited_sent.min(end.distance_from(ack))));
        self.reset_limited_transmit();
        if let Some((end, bytes)) = limited {
            self.limited_end = Some(end);
            self.limited_sent = bytes;
        }
        let syn_ack =
            self.snd_una == self.iss && matches!(self.state, State::SynSent | State::SynReceived);
        let bytes = ack
            .distance_from(self.send_base)
            .min(self.send.len() as u32);
        let bytes = if at_or_after(ack, self.send_base) {
            bytes
        } else {
            0
        };
        if bytes != 0 {
            self.send
                .acknowledge(bytes as usize)
                .expect("ACK is bounded by sent sequence space");
            self.send_base = self.send_base.wrapping_add(bytes);
            self.acknowledged = self.acknowledged.saturating_add(bytes as u64);
            self.events.acknowledged = Some(self.acknowledged);
            if !self.shutdown {
                self.events.writable = true;
            }
        }
        self.snd_una = ack;
        if self.sack_guard.is_some_and(|end| at_or_after(ack, end)) {
            self.sack_guard = None;
            self.sack_post_rto = None;
        }
        if self.sack_fallback.is_some_and(|end| at_or_after(ack, end)) {
            self.sack_fallback = None;
        }

        if self.snd_up.is_some_and(|end| at_or_after(ack, end)) {
            self.snd_up = None;
        }
        if self
            .advertised_snd_up
            .is_some_and(|end| at_or_after(ack, end))
        {
            self.advertised_snd_up = None;
        }
        self.progress_at = self.now;
        self.application_progress_at = self.now;
        self.consecutive_timeouts = 0;
        self.retx_pending = false;
        if let Some((end, sent)) = self.sample
            && at_or_after(ack, end)
        {
            // One bounded sample per flight. Never infer a transmission time
            // from an unvalidated echo, and retain Karn's exclusion on retransmit.
            if !self.timestamps || echo == Some((sent / 1_000) as u32) {
                let sample = self.now.saturating_sub(sent);
                self.rtt.sample(sample);
                self.tlp_fresh_rtt = true;
                self.rack.sample(sample, self.now);
                if !syn_ack {
                    self.syn_timed_out = false;
                }
            }
            self.sample = None;
        }
        if !syn_ack
            && self
                .congestion
                .on_ack_with_ecn(ack, bytes, self.flight(), ece)
        {
            self.retx_pending = true;
        }
        self.rto_deadline = if self.flight() == 0 {
            None
        } else {
            Some(self.now.saturating_add(self.rto()))
        };
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
        //# if the FIN segment is now acknowledged, then enter FIN- WAIT-2 and continue
        //# processing in that state.
        if self.fin_sequence.is_some_and(|fin| after(ack, fin)) {
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
    fn receive_text(&mut self, seq: Seq, payload: &[u8], flags: u8, urgent: u16) {
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
        let skip = if after(next, seq) {
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
        let outcome = self.receive.insert_with_push(
            start,
            &payload[skip..skip + count],
            fin && skip + count == payload.len(),
            flags & PSH != 0 && skip + count == payload.len(),
        );
        self.receive_used += outcome.new_bytes;
        if outcome.sack_overflow && self.sack_send {
            self.sack_omit = true;
            self.receive.clear_dsack();
        }
        if self.read_closed && outcome.new_bytes != 0 {
            self.events.readable = false;
            self.events.pushed = false;
            self.events.urgent = None;
            self.events.writable = false;
            self.abort();
            return;
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
            if payload.len() >= self.mss {
                self.full_segments = self.full_segments.saturating_add(1);
            }
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
            //# o A TCP implementation MAY send an ACK segment acknowledging RCV.NXT
            //# when a valid segment arrives that is in the window but not at the left
            //# window edge (MAY-13).
            if seq != next
                || outcome.out_of_order
                || !outcome.advanced
                || advanced as usize > count
                || flags & FIN != 0
                || self.receive_window() == 0
                || self.full_segments >= 2
                || self.unacked_bytes
                    >= 2 * u32::from(
                        self.config
                            .mss
                            .min(self.config.receive_ip_payload_limit - 20),
                    )
                || self.config.delayed_ack_us == 0
            {
                self.immediate_ack();
            } else if !self.ack_pending && self.ack_deadline.is_none() {
                self.ack_deadline = Some(self.now.saturating_add(self.config.delayed_ack_us));
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

    fn window_threshold(&self) -> u32 {
        (self.config.receive_capacity / 2).max(1).min(self.mss) as u32
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.2.2
    //# A TCP implementation MUST include a SWS avoidance algorithm in the receiver
    //# (MUST-39).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1
    //= reason=Receive credit stays occupied until application reads, without a receiver-side reopening timer.
    //# A TCP implementation MAY keep its offered receive window closed indefinitely
    //# (MAY-8).
    fn advertised_window(&self, syn: bool) -> u16 {
        if syn {
            return self.syn_window;
        }
        if self.receive.eof() {
            return 0;
        }
        let shift = if self.scaling { self.local_scale } else { 0 };
        let unit = 1u32 << shift;
        let available = self.receive.right_edge().distance_from(self.receive.next());
        let old = self.receive_window();
        let candidate = available / unit;
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
        //= reason=Retains prior acceptance credit; RFC 7323 rounding can retract the encoded edge by less than one scale unit.
        //# A TCP receiver SHOULD NOT shrink the window, i.e., move the right window
        //# edge to the left (SHLD-14).
        // RFC 7323 section 2.4: sub-scale advances can require retraction
        // on the wire. Never round beyond backing storage; retain the old
        // promise separately so in-flight bytes remain acceptable.
        let old_field = old.div_ceil(unit).min(candidate);
        if candidate.saturating_mul(unit).saturating_sub(old) >= self.window_threshold() {
            candidate.min(65535) as u16
        } else {
            old_field.min(65535) as u16
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
        let retransmitted_end = if after(high_rxt, boundary) {
            boundary
        } else {
            high_rxt
        };
        let retransmitted = if after(retransmitted_end, self.snd_una) {
            self.scoreboard
                .unsacked_bytes(self.snd_una, retransmitted_end)
        } else {
            0
        };
        let new_start = if after(boundary, self.snd_una) {
            boundary
        } else {
            self.snd_una
        };
        retransmitted + self.scoreboard.unsacked_bytes(new_start, self.data_high())
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
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= reason=Partial output evidence: retransmission payload clipped to PRR credit, new recovery data bounded by recovery_credit, and actual payload counted only after wire::encode succeeds. No universal bound claim for initial override or special output paths.
    //# On any data transmission or retransmission:
    //#
    //#    prr_out += (data sent) // strictly less than or equal to sndcnt
    pub(crate) fn transmit(
        &mut self,
        now: Instant,
        out: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        self.check_time(now)?;
        // Plan entirely before encode. Even timer/clock/accounting changes
        // are committed only once the adapter has sufficient output space.
        let reset = self.pending_rst;
        let syn = reset.is_none() && self.syn_pending;
        let live = self.synchronized();
        let retransmit = reset.is_none() && !syn && live && self.retx_pending && self.flight() != 0;
        let probe = reset.is_none() && !syn && live && self.probe_pending;
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
        let mss = self
            .config
            .mss
            .min(self.config.receive_ip_payload_limit - 20)
            .to_be_bytes();
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
        let timestamp = if reset.is_some() && self.reset_echo.is_some() {
            self.reset_echo.map(|echo| (0, echo))
        } else if self.timestamps || syn && self.state == State::SynSent && self.config.timestamps {
            Some((
                (now / 1_000) as u32,
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
            timestamp.filter(|_| reset.is_none() || self.config.send_ip_payload_limit >= 32)
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
        if syn && (self.state == State::SynSent || self.scaling) {
            options[option_len..option_len + 4].copy_from_slice(&[1, 3, 3, self.local_scale]);
            option_len += 4;
        }
        let mut sack_option_len = 0;
        if reset.is_none() && !syn && live && self.sack_send && !self.sack_omit {
            let control_payload = usize::from(
                probe || keepalive && self.config.keepalive.is_some_and(|k| k.send_garbage),
            );
            let available = (40 - option_len)
                .min(
                    (self.config.send_ip_payload_limit as usize)
                        .saturating_sub(20 + option_len + control_payload),
                )
                // Pure ACK options are independent of MSS. Once reported, limit
                // piggybacked SACKs to leave room for data on the next poll.
                .min(if self.ack_pending {
                    40
                } else {
                    self.mss.saturating_sub(1)
                });
            let max_blocks = available.saturating_sub(4) / 8;
            let blocks = self.receive.sack_blocks(max_blocks);
            let n = blocks.iter().flatten().count();
            if n != 0 {
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
        let packet_mss = self
            .mss
            .saturating_sub(sack_option_len)
            .min((self.config.send_ip_payload_limit as usize).saturating_sub(20 + option_len));
        let mut burst_push = false;
        let mut sack_segment = None;
        if reset.is_none()
            && !syn
            && live
            && !retransmit
            && !probe
            && !keepalive
            && let Some(recovery) = self.sack_recovery
        {
            if self.rack_enabled() {
                let credit = if recovery.entry_pending {
                    self.mss as u32
                } else {
                    self.recovery_credit(recovery)
                };
                if credit != 0 {
                    sack_segment = self
                        .rack
                        .lowest_lost((packet_mss as u32).min(credit))
                        .map(|(left, right)| (left, right, false, recovery.entry_pending));
                }
            } else if recovery.entry_pending {
                // SACK is advisory: RFC 6675 entry always starts at HighACK+1.
                let range = after(self.data_high(), self.snd_una).then_some((
                    self.snd_una,
                    self.snd_una.wrapping_add(
                        self.data_high()
                            .distance_from(self.snd_una)
                            .min(packet_mss as u32),
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
                let lost = self.scoreboard.lowest_hole(
                    recovery.high_rxt,
                    self.data_high(),
                    self.mss as u32,
                    true,
                );
                let unsent = self.send.len() > self.snd_nxt.distance_from(self.send_base) as usize;
                let new_allowed = unsent
                    && self.snd_wnd > self.flight()
                    && self.ecn_pause.is_none_or(|deadline| now >= deadline);
                if let Some((left, right)) = lost {
                    sack_segment = Some((left, right, false, false));
                } else if !new_allowed {
                    if let Some((left, right)) = self.scoreboard.lowest_hole(
                        recovery.high_rxt,
                        self.data_high(),
                        packet_mss as u32,
                        false,
                    ) {
                        sack_segment = Some((left, right, false, false));
                    } else if recovery
                        .rescue_rxt
                        .is_none_or(|end| after(self.snd_una, end))
                    {
                        sack_segment = self
                            .scoreboard
                            .tail_hole(self.snd_una, self.data_high(), packet_mss as u32)
                            // A clipped rescue would not contain the highest
                            // outstanding byte but would consume RescueRxt.
                            .filter(|&(_, right)| right.distance_from(self.snd_una) <= self.snd_wnd)
                            .map(|(left, right)| (left, right, true, false));
                    }
                }
            }
        }
        // RFC 6675 §5.1 recommends filling the newly reported holes after an
        // RTO, but forbids starting another recovery phase before its boundary
        // is covered. The initial RTO retransmission still ignores all SACKs.
        let post_rto_segment = if reset.is_none()
            && !syn
            && live
            && !retransmit
            && !probe
            && !keepalive
            && self.sack_fallback.is_none()
            && let Some((high_rxt, _)) = self.sack_post_rto
            && self.congestion.cwnd().saturating_sub(self.post_rto_pipe()) >= self.mss as u32
        {
            if self.rack_enabled() {
                self.rack.lowest_lost(packet_mss as u32)
            } else {
                self.scoreboard
                    .lowest_hole(high_rxt, self.data_high(), packet_mss as u32, false)
            }
        } else {
            None
        };
        let mut seq = self.snd_nxt;
        let mut flags = ACK;
        let mut count = 0usize;
        let mut new_fin = false;
        let mut retransmitted = false;
        if let Some((reset_seq, with_ack)) = reset {
            seq = reset_seq;
            flags = RST | if with_ack { ACK } else { 0 };
        } else if syn {
            seq = self.iss;
            flags = SYN
                | if self.state == State::SynReceived {
                    ACK
                } else {
                    0
                };
            retransmitted = self.snd_nxt != self.iss;
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1
        //# Probing of zero (offered) windows MUST be supported (MUST-36).
        } else if let Some((left, right)) =
            post_rto_segment.or(sack_segment.map(|(left, right, _, _)| (left, right)))
        {
            seq = left;
            let credit = if self.config.retransmit_beyond_window && self.snd_wnd != 0 {
                self.data_high().distance_from(seq)
            } else {
                self.snd_wnd.saturating_sub(seq.distance_from(self.snd_una))
            };
            let credit = self.prr.map_or(credit, |prr| credit.min(prr.credit()));
            count = self.send.copy(
                seq.distance_from(self.send_base) as usize,
                &mut self.scratch[..(right.distance_from(left) as usize)
                    .min(packet_mss)
                    .min(credit as usize)],
            );
            retransmitted = count != 0;
        } else if tlp {
            let offset = self.snd_nxt.distance_from(self.send_base) as usize;
            let unsent = self.send.len().saturating_sub(offset);
            let credit = self.snd_wnd.saturating_sub(self.flight()) as usize;
            if unsent != 0 && credit >= unsent.min(packet_mss) {
                count = self
                    .send
                    .copy(offset, &mut self.scratch[..unsent.min(packet_mss)]);
            } else if let Some((left, right)) = self.rack.tail_segment(packet_mss as u32) {
                seq = left;
                count = self.send.copy(
                    seq.distance_from(self.send_base) as usize,
                    &mut self.scratch[..right.distance_from(left) as usize],
                );
                retransmitted = count != 0;
            }
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
                let window = if self.config.retransmit_beyond_window && self.snd_wnd != 0 {
                    self.flight()
                } else {
                    self.snd_wnd
                };
                packet_mss.min(window as usize).min(self.flight() as usize)
            };
            count = self.send.copy(offset, &mut self.scratch[..limit]);
            retransmitted = seq != self.snd_nxt;
            if self.fin_sequence == Some(seq.wrapping_add(count as u32))
                && !probe
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
        } else if live {
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
            //= reason=SendBuffer coalesces writes; packetization is independent of application write boundaries.
            //# The transmitter SHOULD collapse successive bits when it packetizes data,
            //# to send the largest possible segment (SHLD-27).
            let offset = self.snd_nxt.distance_from(self.send_base) as usize;
            let unsent = self.send.len().saturating_sub(offset);
            let idle_restart =
                self.flight() == 0 && now.saturating_sub(self.last_sent) >= self.rto();
            let cwnd = if idle_restart {
                self.congestion.cwnd().min(self.initial_window())
            } else {
                self.congestion.cwnd()
            };
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
            let usable = if let Some(recovery) = self.sack_recovery {
                if recovery.entry_pending || self.recovery_credit(recovery) < self.mss as u32 {
                    0
                } else {
                    self.snd_wnd
                        .saturating_sub(self.flight())
                        .min(self.recovery_credit(recovery)) as usize
                }
            } else if self.sack_post_rto.is_some() && self.sack_fallback.is_none() {
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
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
            //# However, a TCP implementation SHOULD send a maximum-sized segment
            //# whenever possible (SHLD-28) to improve performance (see Section
            //# 3.8.6.2.1).
            count = unsent.min(packet_mss).min(usable);
            let urgent = self.snd_up.is_some_and(|end| after(end, seq));
            if count < packet_mss && !urgent && self.sack_recovery.is_none() {
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.4
                //# A TCP implementation SHOULD implement the Nagle algorithm to
                //# coalesce short segments (SHLD-7).
                let nagle = self.config.nagle && self.flight() != 0;
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.2.1
                //# A TCP implementation MUST include a SWS avoidance algorithm in the
                //# sender (MUST-38).
                let sws =
                    !self.sws_override && count < unsent && count < (self.max_snd_wnd / 2) as usize;
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
                //# When an application issues a series of SEND calls without setting
                //# the PUSH flag, the TCP implementation MAY aggregate the data
                //# internally without sending it (MAY-16).
                let aggregate =
                    !self.shutdown && !self.sws_override && !self.send.pushed(offset, unsent);
                if nagle || sws || aggregate {
                    count = 0;
                }
            }
            if self.ecn_pause.is_some_and(|deadline| now < deadline) {
                count = 0;
            }
            burst_push = count != 0
                && self.flight().saturating_add(count as u32) == self.snd_wnd.min(cwnd)
                && self.send.pushed(offset, unsent);
            self.send.copy(offset, &mut self.scratch[..count]);
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.4
            //# Queue this until all preceding SENDs have been segmentized, then form a
            //# FIN segment and send it.
            if self.shutdown
                && self.fin_sequence.is_none()
                && count == unsent
                && usable > count
                && matches!(self.state, State::Established | State::CloseWait)
            {
                flags |= FIN;
                new_fin = true;
            }
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
        if self.sack_receive && retransmit_burst.is_some_and(|(_, bytes)| bytes > packet_mss as u32)
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
        if count != 0
            && !keepalive
            && (burst_push
                || self
                    .send
                    .pushed(seq.distance_from(self.send_base) as usize, count))
        {
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
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
        {
            return Ok(None);
        }
        if self.state == State::Closed && reset.is_none() {
            return Ok(None);
        }
        let mut urgent_pointer = 0;
        if reset.is_none()
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
                urgent_pointer = distance.min(65535) as u16;
            }
        }
        let setup = syn
            && self.config.ecn
            && !self.syn_timed_out
            && !self.ecn_sent_plain
            && (self.state == State::SynSent || self.ecn_peer_setup && !self.ecn_peer_plain);
        let fresh_data = reset.is_none()
            && !syn
            && !retransmitted
            && !retransmit
            && !probe
            && !keepalive
            && count != 0;
        let idle_reduction = fresh_data
            && self.flight() == 0
            && now.saturating_sub(self.last_sent) >= self.rto()
            && self.congestion.cwnd() > self.initial_window();
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
        let window = self.advertised_window(syn);
        let header = Header {
            source_port: self.tuple.local.port(),
            destination_port: self.tuple.remote.port(),
            sequence: seq.0,
            acknowledgment: self.receive.next().0,
            flags,
            window,
            urgent_pointer,
        };
        let ip = IpMetadata {
            source: self.tuple.local.ip(),
            destination: self.tuple.remote.ip(),
        };
        // Include TCP options on every output path, before committing any state.
        if 20 + option_len + count > self.config.send_ip_payload_limit as usize {
            return Err(Error::InvalidArgument);
        }
        let size = wire::encode(
            ip,
            header,
            &options[..option_len],
            &self.scratch[..count],
            out,
        )
        .map_err(|error| {
            if error == wire::WireError::OutputTooSmall {
                Error::OutputTooSmall
            } else {
                Error::Wire(error)
            }
        })?;
        self.retransmit_burst = retransmit_burst;
        // Commit only the encoded (possibly clamped) urgent coverage, and only
        // after successful output. Retransmissions must not move it backwards.
        if flags & URG != 0 {
            let end = seq.wrapping_add(urgent_pointer as u32);
            if self.advertised_snd_up.is_none_or(|old| after(end, old)) {
                self.advertised_snd_up = Some(end);
            }
        }
        // Commit the on-wire endpoint only after output succeeds. A partial ACK
        // past an earlier collapsed mark must not lose PSH on retransmission.
        if flags & PSH != 0 {
            self.send
                .collapse_push(seq.distance_from(self.send_base) as usize, count);
        }
        self.now = now;
        self.last_output_ecn = ecn;
        if syn {
            self.sack_receive |= sack_offer;
            self.ecn_sent_setup |= setup;
            self.ecn_sent_plain |= !setup;
        }
        if fresh_data && flags & CWR != 0 {
            self.ecn_cwr_pending = false;
        }
        if reset.is_some() {
            self.pending_rst = None;
            self.reset_echo = None;
            return Ok(Some(size));
        }
        if sack_option_len != 0 && flags & ACK != 0 {
            self.receive.clear_dsack();
        }
        if flags & ACK != 0 {
            self.sack_omit = false;
        }
        if count != 0 && !syn && !keepalive && !probe {
            self.rack
                .transmit(seq, seq.wrapping_add(count as u32), now, retransmitted);
            if !self.rack.valid() {
                self.prr = None;
                self.rack_entry_delivery = None;
            } else if let Some(prr) = &mut self.prr {
                prr.sent(count as u32);
            }
        }
        if count != 0
            && let Some(mut recovery) = self.sack_recovery
        {
            if let Some((_, _, rescue, entry)) = sack_segment {
                let end = seq.wrapping_add(count as u32);
                if !rescue {
                    recovery.high_rxt = end;
                }
                if entry {
                    recovery.entry_pending = false;
                    recovery.rescue_rxt = Some(end);
                } else if rescue {
                    recovery.rescue_rxt = Some(recovery.recovery_point);
                }
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
            && let Some((old, boundary)) = self.sack_post_rto
        {
            let end = seq.wrapping_add(count as u32);
            if after(end, old) {
                self.sack_post_rto = Some((end, boundary));
            }
        }
        if !keepalive
            && self.flight() == 0
            && now.saturating_sub(self.last_sent) >= self.rto()
            && count != 0
        {
            self.congestion.restart_after_idle();
        }
        self.last_sent = now;
        self.syn_pending = false;
        if flags & ACK != 0 {
            self.last_ack_sent = self.receive.next();
            self.ack_pending = false;
            self.ack_deadline = None;
            self.full_segments = 0;
            self.unacked_bytes = 0;
            let shift = if !syn && self.scaling {
                self.local_scale
            } else {
                0
            };
            let edge = self.receive.next().wrapping_add((window as u32) << shift);
            if after(edge, self.advertised_edge) || self.receive.eof() {
                self.advertised_edge = edge;
            }
        }
        let length = count as u32 + u32::from(flags & SYN != 0) + u32::from(flags & FIN != 0);
        if length != 0 && !keepalive {
            let end = seq.wrapping_add(length);
            if retransmitted {
                if !syn && !probe {
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
            } else if self.sample.is_none()
                && (timestamp.is_none()
                    || self
                        .last_timestamp_sent_at
                        .is_none_or(|sent| sent / 1_000 != now / 1_000))
            {
                self.sample = Some((end, now));
            }
            if after(end, self.snd_nxt) {
                self.snd_nxt = end;
            }
            if (self.rto_deadline.is_none() || retransmitted) && !probe {
                self.rto_deadline = Some(now.saturating_add(self.rto()));
            }
        }
        if tlp && count != 0 {
            // A probe is not Limited Transmit: it must neither earn its
            // duplicate-ACK credit nor be excluded from congestion FlightSize.
            self.limited_pending = false;
            self.tlp_pending = false;
            self.tlp_end = Some((seq, seq.wrapping_add(count as u32), retransmitted));
            self.tlp_flight = Some(self.snd_nxt);
            self.tlp_fresh_rtt = false;
            self.tlp_deadline = None;
            self.rto_deadline = Some(now.saturating_add(self.rto()));
        }
        if timestamp.is_some() {
            self.last_timestamp_sent_at = Some(now);
        }
        if new_fin {
            self.fin_sequence = Some(seq.wrapping_add(count as u32));
            self.state = if self.state == State::CloseWait {
                State::LastAck
            } else {
                State::FinWait1
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
        if probe {
            self.probe_pending = false;
            self.persist_unanswered_since.get_or_insert(now);
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1
            //= reason=arm_work starts at the current RTO; each emitted probe doubles the interval up to the timer cap.
            //# The transmitting host SHOULD send the first zero-window probe when a
            //# zero window has existed for the retransmission timeout period (SHLD-
            //# 29) (Section 3.8.1), and SHOULD increase exponentially the interval
            //# between successive probes (SHLD-30).
            self.persist_interval = self.persist_interval.saturating_mul(2).min(60_000_000);
            self.persist_deadline = Some(now.saturating_add(self.persist_interval));
        }
        if keepalive {
            self.keepalive_pending = false;
            self.keepalive_probes = self.keepalive_probes.saturating_add(1);
            self.keepalive_deadline = self
                .config
                .keepalive
                .map(|k| now.saturating_add(k.interval_us));
        }
        if count != 0 && !keepalive {
            if self.limited_pending && !retransmit && !probe {
                self.limited_sent = self.limited_sent.saturating_add(count as u32);
                self.limited_end = Some(seq.wrapping_add(count as u32));
                // RFC 6675 repeats SetPipe across output polls for this ACK.
                // Reno and the RACK/PRR profiles retain one-packet credit.
                self.limited_pending = self.sack_recovery_enabled()
                    && !self.config.rack
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
        self.arm_work();
        if fresh_data && !tlp {
            self.schedule_tlp();
        }
        Ok(Some(size))
    }

    fn initial_window(&self) -> u32 {
        self.congestion.initial_window()
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        [
            self.rack.deadline,
            self.tlp_deadline,
            self.rto_deadline,
            self.ecn_pause,
            self.ack_deadline,
            self.persist_deadline,
            self.sws_deadline,
            self.time_wait_deadline,
            self.keepalive_deadline,
            self.user_deadline(),
            self.application_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
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
    //= reason=Services the RACK deadline by re-running detect_rack; RTO takes priority if already due.
    //# For timely loss detection, it is RECOMMENDED that the
    //# sender install a reordering timer.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= reason=Checks no tlp_end, no tlp_flight, and fresh RTT before making a probe pending; output repeats these checks.
    //# When the PTO timer expires, the sender MUST check whether both of the
    //# following conditions are met before sending a loss probe:
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= reason=At PTO expiration failed send eligibility leaves no pending probe and rearms RTO for nonzero/nonzero-window flight.
    //# If either one of these two conditions is not met, then the sender
    //# MUST skip sending a loss probe and MUST proceed to re-arm the RTO
    //# timer, as specified at the end of this section.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= reason=PTO expiry rearms RTO before attempting output when flight and window are nonzero; successful probe commit rearms again.
    //# After attempting to send a loss probe, regardless of whether a loss
    //# probe was sent, the sender MUST re-arm the RTO timer, not the PTO
    //# timer, if the FlightSize is not zero.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= reason=Tracks both unresolved TLP recovery episode and original-flight boundary; at most one committed probe until ACK/recovery reset.
    //# First, there is no other previous loss probe still in flight.
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= reason=Consumes matching retained timer evidence once, then acknowledges PRR with real but capped pre-entry delivery. This is not a new ACK or proof of RFC entry-epoch semantics; TODO remains.
    //# On every ACK during recovery compute:
    //#
    //#    DeliveredData = change_in(snd.una) + change_in(SACKd)
    //#    prr_delivered += DeliveredData
    pub(crate) fn timeout(&mut self, now: Instant) -> Result<(), Error> {
        self.check_time(now)?;
        self.now = now;
        self.retransmit_burst = None;
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.8
        //= reason=Closes protocol state here; terminal handle storage is reclaimed on release.
        //# If the time-wait timeout expires on a connection, delete the TCB, enter the
        //# CLOSED state, and return.
        if due(self.time_wait_deadline, now) {
            self.state = State::Closed;
            self.time_wait_deadline = None;
            self.ack_pending = false;
            return Ok(());
        }
        if due(self.user_deadline(), now) || due(self.application_deadline(), now) {
            self.terminal(CloseReason::TimedOut);
            return Ok(());
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
        if due(self.rack.deadline, now) && !due(self.rto_deadline, now) {
            let delivery = self
                .rack_entry_delivery
                .take()
                .filter(|&(deadline, _)| self.rack.deadline == Some(deadline))
                .map_or(0, |(_, bytes)| bytes);
            self.detect_rack();
            if let Some(prr) = &mut self.prr {
                prr.acknowledge(delivery, self.rack.pipe(), self.congestion.ssthresh());
                if self.sack_recovery.is_some_and(|r| r.entry_pending) {
                    prr.guarantee_initial(self.mss as u32);
                }
            }
        }
        // PTO takes precedence at an RTO-capped tie. Attempts do not back off
        // RTO or reduce cwnd; only successfully encoded probes consume state.
        if due(self.tlp_deadline, now) {
            self.tlp_deadline = None;
            self.tlp_pending = self.tlp_eligible()
                && self.tlp_fresh_rtt
                && self.tlp_end.is_none()
                && self.tlp_flight.is_none();
            if self.flight() != 0 && self.snd_wnd != 0 {
                self.rto_deadline = Some(now.saturating_add(self.rto()));
            }
        }
        if due(self.rto_deadline, now) {
            self.reset_tlp();
            self.prr = None;
            self.rack_entry_delivery = None;
            self.rack.rto(now, self.snd_una, self.rtt.srtt());
            //= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
            //= reason=Timeout discards advisory ranges and guards a fresh recovery phase until its exclusive data boundary is covered.
            //# RecoveryPoint MUST be set to HighData.
            if self.sack_recovery_enabled() {
                self.scoreboard.clear();
                self.sack_recovery = None;
                self.sack_guard = Some(self.data_high());
                self.sack_post_rto = Some((self.snd_una, self.data_high()));
                self.congestion.cancel_sack_recovery();
            }
            self.reset_limited_transmit();
            self.rto_deadline = None;
            self.sample = None;
            self.rtt.backoff();
            self.consecutive_timeouts = self.consecutive_timeouts.saturating_add(1);
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
            self.congestion.on_timeout(self.flight(), self.snd_nxt);
            self.ecn_cwr_pending |= self.ecn_feedback();
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
            //# SYN retransmissions MUST be handled in the general way just described
            //# for data retransmissions, including notification of the application
            //# layer.
            if matches!(self.state, State::SynSent | State::SynReceived) {
                self.syn_timed_out = true;
                self.syn_pending = true;
            } else {
                self.retx_pending = self.flight() != 0;
            }
        }
        if due(self.ack_deadline, now) {
            self.immediate_ack();
        }
        if due(self.persist_deadline, now) {
            self.persist_deadline = None;
            self.probe_pending = true;
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    fn config(capacity: usize, mss: u16) -> ConnectionConfig {
        ConnectionConfig {
            send_capacity: capacity,
            receive_capacity: capacity,
            mss,
            ..ConnectionConfig::default()
        }
    }

    fn tuple() -> Tuple {
        Tuple {
            local: "192.0.2.1:1000".parse().unwrap(),
            remote: "192.0.2.2:2000".parse().unwrap(),
        }
    }

    fn reverse(tuple: Tuple) -> Tuple {
        Tuple {
            local: tuple.remote,
            remote: tuple.local,
        }
    }

    fn ip(tuple: Tuple) -> IpMetadata {
        IpMetadata {
            source: tuple.local.ip(),
            destination: tuple.remote.ip(),
        }
    }

    fn packet(connection: &mut Connection, now: Instant) -> Vec<u8> {
        let mut out = vec![0; 65535];
        let length = connection
            .transmit(now, &mut out)
            .unwrap()
            .expect("packet ready");
        out.truncate(length);
        out
    }

    fn deliver(from: &mut Connection, to: &mut Connection, now: Instant) -> Vec<u8> {
        let bytes = packet(from, now);
        let segment = wire::parse(ip(from.tuple()), &bytes).unwrap();
        to.input(now, &segment).unwrap();
        bytes
    }

    fn pair(cfg: ConnectionConfig, iss: u32) -> (Connection, Connection) {
        let mut a = Connection::active(tuple(), cfg.clone(), iss, 0).unwrap();
        let bytes = packet(&mut a, 0);
        let syn = wire::parse(ip(tuple()), &bytes).unwrap();
        let mut b = Connection::passive(reverse(tuple()), cfg, 900, 10, &syn).unwrap();
        deliver(&mut b, &mut a, 20);
        deliver(&mut a, &mut b, 30);
        assert_eq!(a.state(), State::Established);
        assert_eq!(b.state(), State::Established);
        assert!(a.take_events().connected);
        assert!(b.take_events().connected);
        (a, b)
    }

    #[test]
    fn send_state_matrix_preserves_queue_on_rejection() {
        for state in [
            State::Closed,
            State::SynSent,
            State::SynReceived,
            State::Established,
            State::FinWait1,
            State::FinWait2,
            State::CloseWait,
            State::Closing,
            State::LastAck,
            State::TimeWait,
        ] {
            let (mut a, _) = pair(config(4, 4), 100);
            a.state = state;
            let allowed = matches!(
                state,
                State::SynSent | State::SynReceived | State::Established | State::CloseWait
            );
            let before = (a.send.len(), a.snd_una, a.snd_nxt, a.acknowledged());
            if allowed {
                assert_eq!(a.write(b"abc"), Ok(3));
                assert_eq!(a.write(b"de"), Ok(1));
                assert_eq!(a.write(b"f"), Err(Error::WouldBlock));
                let mut queued = [0; 4];
                assert_eq!(a.send.copy(0, &mut queued), 4);
                assert_eq!(&queued, b"abcd");
                assert_eq!(
                    (a.snd_una, a.snd_nxt, a.acknowledged()),
                    (before.1, before.2, before.3)
                );
            } else {
                assert_eq!(a.write(b"late"), Err(Error::InvalidState));
                assert_eq!(
                    (a.send.len(), a.snd_una, a.snd_nxt, a.acknowledged()),
                    before
                );
            }
            assert_eq!(a.state(), state);
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.4
    //= type=test
    //= reason=Unpushed writes flush before FIN; read half remains available.
    //# Close also implies push function.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.3
    //= type=test
    //= reason=CLOSE-WAIT drains accepted bytes then returns EOF (0), the nonblocking API equivalent of closing notification.
    //# Since the remote side has already sent FIN, RECEIVEs must be satisfied by data already
    //# on hand, but not yet delivered to the user. If no text is awaiting delivery, the RECEIVE
    //# will get an "error: connection closing" response. Otherwise, any remaining data can be
    //# used to satisfy the RECEIVE.
    fn shutdown_pushes_unpushed_fifo_and_close_wait_drains_before_eof() {
        let (mut a, mut b) = pair(config(64, 4), u32::MAX - 2);
        a.set_nagle(false);
        a.write_with_push(b"abc", false).unwrap();
        a.write_with_push(b"def", false).unwrap();
        a.shutdown().unwrap();
        let first = deliver(&mut a, &mut b, 40);
        let first = wire::parse(ip(tuple()), &first).unwrap();
        assert_eq!(first.payload, b"abcd");
        assert_eq!(first.header.flags & FIN, 0);
        let last = deliver(&mut a, &mut b, 50);
        let last = wire::parse(ip(tuple()), &last).unwrap();
        assert_eq!(last.payload, b"ef");
        assert_ne!(last.header.flags & FIN, 0);
        assert_eq!(b.state(), State::CloseWait);
        assert!(b.take_events().half_closed);
        for expected in [b"ab", b"cd", b"ef"] {
            let mut out = [0; 2];
            assert_eq!(b.read(&mut out), Ok(2));
            assert_eq!(&out, expected);
        }
        assert_eq!(b.read(&mut [0; 2]), Ok(0));
        assert_eq!(b.write(b"reply"), Ok(5));
        deliver(&mut b, &mut a, 60);
        let mut out = [0; 8];
        assert_eq!(a.read(&mut out), Ok(4));
        assert_eq!(&out[..4], b"repl");
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //= reason=Focused edge test covers duplicate-prefix and out-of-window suffix trimming, wrap and zero-window rejection.
    //# If a segment's contents straddle the boundary between old and new, only the new parts
    //# are processed.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //= reason=Rejected input leaves receive state unchanged and replies with current ACK; invalid RST is silent.
    //# If an incoming segment is not acceptable, an acknowledgment should be sent in reply
    //# (unless the RST bit is set, if so drop the segment and return):
    //# <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK> o After sending the acknowledgment, drop the
    //# unacceptable segment and return.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //= type=test
    //= reason=Output ACK field is the receive frontier; established reply flags and sequence are explicitly checked.
    //# If the ACK control bit is set, this field contains the value of the next sequence number
    //# the sender of the segment is expecting to receive. Once a connection is established,
    //# this is always sent.
    fn receive_acceptability_edges_trim_duplicates_and_wrap() {
        for next in [Seq(901), Seq(u32::MAX - 1)] {
            for (offset, payload, flags, used, readable, reply) in [
                (u32::MAX - 1, b"xxAB".as_slice(), ACK, 2, 2, true),
                (30, b"WXYZ".as_slice(), ACK, 2, 0, true),
                (32, b"bad".as_slice(), ACK, 0, 0, true),
                (u32::MAX - 3, b"old".as_slice(), ACK, 0, 0, true),
                (32, b"bad".as_slice(), RST | ACK, 0, 0, false),
            ] {
                let (mut a, _) = pair(config(32, 8), 100);
                a.receive.reset_start(next).unwrap();
                a.advertised_edge = next.wrapping_add(32);
                let ack = a.snd_una;
                inject(
                    &mut a,
                    40,
                    next.wrapping_add(offset),
                    ack,
                    flags,
                    32,
                    payload,
                );
                assert_eq!(a.state(), State::Established);
                assert_eq!(a.receive_used, used);
                assert_eq!(a.readable_bytes(), readable);
                assert_eq!(a.receive.next(), next.wrapping_add(readable as u32));
                let mut out = [0; 64];
                let packet = a.transmit(40, &mut out).unwrap();
                assert_eq!(packet.is_some(), reply);
                if let Some(len) = packet {
                    let segment = wire::parse(ip(tuple()), &out[..len]).unwrap();
                    assert_eq!(segment.header.flags, ACK);
                    assert_eq!(segment.header.sequence, a.snd_nxt.0);
                    assert_eq!(segment.header.acknowledgment, a.receive.next().0);
                    assert!(segment.payload.is_empty());
                }
                if readable != 0 {
                    let mut out = [0; 8];
                    assert_eq!(a.read(&mut out), Ok(2));
                    assert_eq!(&out[..2], b"AB");
                }
            }
            for (offset, payload, reply) in [
                (0, b"".as_slice(), false),
                (1, b"".as_slice(), true),
                (0, b"bad".as_slice(), true),
            ] {
                let (mut a, _) = pair(config(32, 8), 100);
                a.receive.reset_start(next).unwrap();
                a.advertised_edge = next;
                let ack = a.snd_una;
                inject(&mut a, 40, next.wrapping_add(offset), ack, ACK, 32, payload);
                assert_eq!(a.receive.next(), next);
                assert_eq!(a.receive_used, 0);
                assert_eq!(a.ack_pending, reply);
                assert_eq!(a.state(), State::Established);
            }
        }
    }

    #[test]
    fn initial_window_uses_negotiated_effective_mss() {
        assert_eq!(
            ConnectionConfig::default().initial_window,
            InitialWindow::Rfc5681
        );
        for policy in [InitialWindow::Rfc5681, InitialWindow::Iw10] {
            for (configured, peer, timestamps, path_limit, effective, default_iw, iw10) in [
                (1_000, 1_000, false, 65_515, 1_000, 4_000, 10_000),
                (1_460, 1_460, false, 65_515, 1_460, 4_380, 14_600),
                (3_000, 3_000, false, 65_515, 3_000, 6_000, 14_600),
                (8_000, 8_000, false, 65_515, 8_000, 16_000, 16_000),
                (3_000, 1_000, false, 65_515, 1_000, 4_000, 10_000),
                (3_000, 1_460, false, 65_515, 1_460, 4_380, 14_600),
                (1_000, 3_000, false, 65_515, 1_000, 4_000, 10_000),
                (3_000, 1_460, true, 65_515, 1_448, 4_380, 14_480),
                (3_000, 3_000, true, 1_032, 1_000, 4_000, 10_000),
            ] {
                let mut cfg = config(65_536, configured);
                cfg.initial_window = policy;
                cfg.timestamps = timestamps;
                cfg.send_ip_payload_limit = path_limit;
                let mut peer_cfg = config(65_536, peer);
                peer_cfg.initial_window = policy;
                peer_cfg.timestamps = timestamps;
                let mut a = Connection::active(tuple(), cfg, 100, 0).unwrap();
                let bytes = packet(&mut a, 0);
                let syn = wire::parse(ip(tuple()), &bytes).unwrap();
                let mut b = Connection::passive(reverse(tuple()), peer_cfg, 900, 10, &syn).unwrap();
                let passive_iw = b.congestion.cwnd();
                deliver(&mut b, &mut a, 20);
                deliver(&mut a, &mut b, 30);
                assert_eq!(a.mss, effective);
                assert_eq!(
                    a.congestion.cwnd(),
                    if policy == InitialWindow::Iw10 {
                        iw10
                    } else {
                        default_iw
                    }
                );
                assert_eq!(a.congestion.cwnd(), a.initial_window());
                assert_eq!(b.congestion.cwnd(), passive_iw);
                let before = a.congestion.cwnd();
                let lowered = effective / 2;
                a.lower_mss(lowered as u16 + if timestamps { 12 } else { 0 })
                    .unwrap();
                assert_eq!(a.mss, lowered);
                assert_eq!(
                    a.congestion.cwnd(),
                    (before as u64 * lowered as u64 / effective as u64) as u32
                );
            }
        }
    }

    #[test]
    fn initial_window_syn_loss_and_output_retries_remain_conservative() {
        for policy in [InitialWindow::Rfc5681, InitialWindow::Iw10] {
            for lose_synack in [false, true] {
                let mut cfg = config(65_536, 3_000);
                cfg.initial_window = policy;
                let mut peer_cfg = cfg.clone();
                peer_cfg.mss = 1_000;
                let mut a = Connection::active(tuple(), cfg, 100, 0).unwrap();
                let initial = a.congestion.cwnd();
                assert_eq!(a.transmit(0, &mut [0; 19]), Err(Error::OutputTooSmall));
                assert_eq!(a.congestion.cwnd(), initial);
                assert_eq!(a.rto_deadline, None);
                let bytes = packet(&mut a, 0);
                let syn = wire::parse(ip(tuple()), &bytes).unwrap();
                if !lose_synack {
                    a.timeout(1_000_000).unwrap();
                    assert_eq!(a.congestion.cwnd(), 3_000);
                    assert_eq!(
                        a.transmit(1_000_000, &mut [0; 19]),
                        Err(Error::OutputTooSmall)
                    );
                    packet(&mut a, 1_000_000);
                }
                let mut b =
                    Connection::passive(reverse(tuple()), peer_cfg, 900, 1_000_000, &syn).unwrap();
                if lose_synack {
                    packet(&mut b, 1_000_000);
                    b.timeout(2_000_000).unwrap();
                    assert_eq!(b.congestion.cwnd(), 1_000);
                    assert_eq!(
                        b.transmit(2_000_000, &mut [0; 19]),
                        Err(Error::OutputTooSmall)
                    );
                }
                deliver(&mut b, &mut a, 2_000_010);
                deliver(&mut a, &mut b, 2_000_020);
                let selected = if policy == InitialWindow::Iw10 {
                    10_000
                } else {
                    4_000
                };
                assert_eq!(
                    a.congestion.cwnd(),
                    if lose_synack { selected } else { 1_000 }
                );
                assert_eq!(
                    b.congestion.cwnd(),
                    if lose_synack { 1_000 } else { selected }
                );
            }
        }
    }

    #[test]
    fn iw10_transmit_idle_restart_and_data_rto() {
        for mss in [1_000, 1_460] {
            let mut cfg = config(65_536, mss);
            cfg.initial_window = InitialWindow::Iw10;
            cfg.nagle = false;
            let (mut a, mut b) = pair(cfg, 100);
            let iw = 10 * mss as u32;
            a.write(&vec![1; mss as usize]).unwrap();
            deliver(&mut a, &mut b, 40);
            b.immediate_ack();
            deliver(&mut b, &mut a, 50);
            assert!(a.congestion.cwnd() > iw);
            a.write(&vec![2; 2 * iw as usize]).unwrap();
            let now = 50 + a.rto();
            let grown = a.congestion.cwnd();
            assert_eq!(a.transmit(now, &mut [0; 19]), Err(Error::OutputTooSmall));
            assert_eq!(a.congestion.cwnd(), grown);
            let mut sent = 0;
            let mut out = vec![0; 65_535];
            while let Some(size) = a.transmit(now, &mut out).unwrap() {
                sent += wire::parse(ip(tuple()), &out[..size])
                    .unwrap()
                    .payload
                    .len();
            }
            assert_eq!(sent, iw as usize);
            assert_eq!(a.congestion.cwnd(), iw);
            a.timeout(a.rto_deadline.unwrap()).unwrap();
            assert_eq!(a.congestion.cwnd(), mss as u32);
            let now = a.now;
            let retry = packet(&mut a, now);
            assert_eq!(
                wire::parse(ip(tuple()), &retry).unwrap().payload.len(),
                mss as usize
            );
            assert_eq!(a.congestion.cwnd(), mss as u32);
            assert_eq!(a.transmit(now, &mut out).unwrap(), None);
        }
    }

    fn inject(
        to: &mut Connection,
        now: Instant,
        seq: Seq,
        ack: Seq,
        flags: u8,
        window: u16,
        payload: &[u8],
    ) {
        let mut bytes = vec![0; 20 + payload.len()];
        let metadata = ip(reverse(to.tuple()));
        let header = Header {
            source_port: to.tuple.remote.port(),
            destination_port: to.tuple.local.port(),
            sequence: seq.0,
            acknowledgment: ack.0,
            flags,
            window,
            urgent_pointer: 0,
        };
        let size = wire::encode(metadata, header, &[], payload, &mut bytes).unwrap();
        let segment = wire::parse(metadata, &bytes[..size]).unwrap();
        to.input(now, &segment).unwrap();
    }

    #[allow(clippy::too_many_arguments)]
    fn inject_sack(
        to: &mut Connection,
        now: Instant,
        seq: Seq,
        ack: Seq,
        flags: u8,
        window: u16,
        payload: &[u8],
        blocks: &[(u32, u32)],
    ) {
        let mut options = vec![];
        if to.timestamps {
            options.extend_from_slice(&[1, 1, 8, 10]);
            options.extend_from_slice(&((now / 1_000) as u32).to_be_bytes());
            options.extend_from_slice(&to.ts_recent.to_be_bytes());
        }
        if !blocks.is_empty() {
            options.extend_from_slice(&[1, 1, 5, (2 + 8 * blocks.len()) as u8]);
            for &(left, right) in blocks {
                options.extend_from_slice(&left.to_be_bytes());
                options.extend_from_slice(&right.to_be_bytes());
            }
        }
        let metadata = ip(reverse(to.tuple()));
        let mut bytes = vec![0; 60 + payload.len()];
        let size = wire::encode(
            metadata,
            Header {
                source_port: to.tuple.remote.port(),
                destination_port: to.tuple.local.port(),
                sequence: seq.0,
                acknowledgment: ack.0,
                flags,
                window,
                urgent_pointer: 0,
            },
            &options,
            payload,
            &mut bytes,
        )
        .unwrap();
        to.input(now, &wire::parse(metadata, &bytes[..size]).unwrap())
            .unwrap();
    }

    fn rack_flight(iss: u32) -> Connection {
        let cfg = ConnectionConfig {
            sack: true,
            rack: true,
            prr: true,
            initial_window: InitialWindow::Iw10,
            ..config(65_536, 1000)
        };
        let mut a = Connection::active(tuple(), cfg.clone(), iss, 0).unwrap();
        let bytes = packet(&mut a, 0);
        let syn = wire::parse(ip(tuple()), &bytes).unwrap();
        let mut b = Connection::passive(reverse(tuple()), cfg, 900, 0, &syn).unwrap();
        deliver(&mut b, &mut a, 100_000);
        deliver(&mut a, &mut b, 100_000);
        a.write(&[0x55; 10_000]).unwrap();
        for _ in 0..10 {
            packet(&mut a, 100_000);
        }
        assert_eq!(a.transport_info().unacked, 10);
        a
    }

    fn rack_sack(a: &mut Connection, now: u64, ack_offset: u32, blocks: &[(u32, u32)]) {
        let base = a.iss.wrapping_add(1);
        let blocks: Vec<_> = blocks
            .iter()
            .map(|&(l, r)| (base.wrapping_add(l).0, base.wrapping_add(r).0))
            .collect();
        inject_sack(
            a,
            now,
            a.receive.next(),
            base.wrapping_add(ack_offset),
            ACK,
            65_535,
            &[],
            &blocks,
        );
    }

    fn tlp_pair(iss: u32) -> (Connection, Connection) {
        let cfg = ConnectionConfig {
            sack: true,
            rack: true,
            prr: true,
            tlp: true,
            rto_min_us: 200_000,
            ..config(65_536, 1000)
        };
        let mut a = Connection::active(tuple(), cfg.clone(), iss, 0).unwrap();
        let bytes = packet(&mut a, 0);
        let syn = wire::parse(ip(tuple()), &bytes).unwrap();
        let mut b = Connection::passive(reverse(tuple()), cfg, 900, 0, &syn).unwrap();
        deliver(&mut b, &mut a, 100_000);
        deliver(&mut a, &mut b, 100_000);
        assert_eq!(a.rto(), 300_000);
        assert!(a.tlp_fresh_rtt);
        (a, b)
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
    //= type=test
    //= reason=Partial/repeated SACK does not mint retransmission credit after initial entry output.
    //# A segment marked
    //# as lost by RACK-TLP MUST NOT be retransmitted until congestion
    //# control deems this appropriate.
    //= https://www.rfc-editor.org/rfc/rfc6937#section-2
    //= type=test
    //= reason=Asserts partial SACK then full tail and later head coverage cannot double-count delivery; checks credit=0 and no output. Entry guarantee explicitly not evidence for strict CRB.
    //# With SACK,
    //# DeliveredData can be computed precisely as the change in snd.una,
    //# plus the (signed) change in SACKd.
    fn tlp_partial_sack_then_full_tail_delivery_cannot_inflate_prr_credit() {
        for iss in [0, u32::MAX - 1999] {
            let (mut a, _) = tlp_pair(iss);
            let base = a.send_base;
            a.write(&[0x55; 4000]).unwrap();
            for _ in 0..4 {
                packet(&mut a, 100_000);
            }
            rack_sack(&mut a, 200_000, 0, &[(3500, 4000)]);
            assert!(a.prr.is_none());
            a.timeout(300_000).unwrap();
            let bytes = packet(&mut a, 300_000);
            let p = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(p.header.sequence, base.wrapping_add(3000).0);
            assert_eq!(p.payload.len(), 1000);
            rack_sack(&mut a, 400_000, 0, &[(3000, 4000)]);
            assert!(a.sack_recovery.is_some());
            assert_eq!(a.prr.unwrap().credit(), 1000); // Guaranteed entry, not 1000 delivered.
            packet(&mut a, 400_000);
            assert_eq!(a.prr.unwrap().credit(), 0);
            rack_sack(&mut a, 400_001, 0, &[(0, 500), (3000, 4000)]);
            // Exactly 500 new tail bytes + 500 new head bytes have been
            // delivered since entry; the one emitted MSS consumed that budget.
            assert_eq!(a.prr.unwrap().credit(), 0);
            assert_eq!(a.transmit(400_001, &mut [0; 1500]), Ok(None));
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.4.2
    //= type=test
    //= reason=Asserts TLP reduction and recovery of later original loss without a second same-flight reduction.
    //# The sender then
    //# SHOULD invoke a congestion control response equivalent to a fast
    //# recovery.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
    //= type=test
    //= reason=Later original loss in the already-reduced TLP flight starts recovery without a second reduction.
    //# If multiple original transmissions or retransmissions were lost in a
    //# window, the congestion control specified in [RFC5681] only reacts
    //# once per window.
    fn tlp_repaired_loss_epoch_never_bars_recovery_of_later_original_loss() {
        for iss in [0, u32::MAX - 4999] {
            let cfg = ConnectionConfig {
                sack: true,
                rack: true,
                prr: true,
                tlp: true,
                rto_min_us: 200_000,
                initial_window: InitialWindow::Iw10,
                ..config(65_536, 1000)
            };
            let mut a = Connection::active(tuple(), cfg.clone(), iss, 0).unwrap();
            let bytes = packet(&mut a, 0);
            let syn = wire::parse(ip(tuple()), &bytes).unwrap();
            let mut b = Connection::passive(reverse(tuple()), cfg, 900, 0, &syn).unwrap();
            deliver(&mut b, &mut a, 100_000);
            deliver(&mut a, &mut b, 100_000);
            let base = a.send_base;
            a.write(&[0x55; 4000]).unwrap();
            for _ in 0..4 {
                packet(&mut a, 100_000);
            }
            a.timeout(300_000).unwrap();
            packet(&mut a, 300_000); // Retransmitted tail ends at offset 4000.
            a.write(&[0x66; 6000]).unwrap();
            for _ in 0..6 {
                packet(&mut a, 300_001);
            }
            assert_eq!(a.snd_nxt, base.wrapping_add(10_000));
            rack_sack(&mut a, 400_001, 5000, &[]);
            assert_eq!(a.tlp_end, None);
            assert_eq!((a.congestion.cwnd(), a.congestion.ssthresh()), (5000, 5000));
            assert!(!a.congestion.in_recovery());
            assert!(a.sack_recovery.is_none());
            // Later SACKs prove the original segment at offset 5000 was lost
            // in the already-reduced flight. Recovery must retransmit it now.
            rack_sack(&mut a, 500_001, 5000, &[(6000, 10_000)]);
            assert_eq!(a.rack.counts().lost, 1);
            assert!(a.sack_recovery.is_some());
            assert_eq!(a.congestion.ssthresh(), 5000); // No second original-flight reduction.
            let bytes = packet(&mut a, 500_001);
            let p = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(p.header.sequence, base.wrapping_add(5000).0);
            assert_eq!(p.payload, &[0x66; 1000]);
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= type=test
    //= reason=Immediate SACK of partly retransmitted original cannot replenish freshness.
    //# Second, the sender has obtained an RTT measurement since the last
    //# loss probe transmission or the start of the connection, whichever
    //# was later.
    fn tlp_options_clipped_suffix_full_sack_cannot_grant_fresh_rtt() {
        for iss in [0, u32::MAX - 1999] {
            let (mut a, _) = tlp_pair(iss);
            a.config.send_ip_payload_limit = 1020;
            let base = a.send_base;
            a.write(&[0x55; 4000]).unwrap();
            for _ in 0..4 {
                packet(&mut a, 100_000);
            }
            // Duplex out-of-order data adds a 12-byte SACK report to the probe,
            // shrinking its packet budget, not the identity of the original tail.
            let next = a.receive.next();
            inject_sack(
                &mut a,
                200_000,
                next.wrapping_add(1000),
                base,
                ACK,
                65_535,
                &[0x66; 100],
                &[],
            );
            assert_eq!(a.tlp_deadline, Some(300_000));
            a.timeout(300_000).unwrap();
            let bytes = packet(&mut a, 300_000);
            let p = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(p.header.sequence, base.wrapping_add(3012).0);
            assert_eq!(p.payload.len(), 988);
            assert!(p.options.sack_blocks[0].is_some());
            assert!(!a.tlp_fresh_rtt);
            assert!(a.sample.is_none());
            rack_sack(&mut a, 300_001, 0, &[(3000, 4000)]);
            assert!(a.rack.ack_sample.is_none());
            assert!(!a.tlp_fresh_rtt);
            assert_eq!(a.rtt.srtt(), Some(100_000));
            assert!(a.sack_recovery.is_none());
            assert_eq!(a.rack.deadline, None);
            assert_eq!(a.tlp_deadline, None);
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= type=test
    //= reason=Checks tail retransmission, output retry state, RTO fallback and no repeated probe.
    //# If such an unsent segment is not available, then the sender SHOULD
    //# retransmit the highest-sequence segment sent so far and set
    //# TLP.is_retrans to true.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= type=test
    //= reason=Output-too-small does not change RACK retransmitted counts or probe state; successful output does.
    //# The sender MUST follow the RACK transmission procedures in the "Upon
    //# Transmitting a Data Segment" section upon sending either a
    //# retransmission or a new data loss probe.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.1
    //= type=test
    //= reason=RTO after pending/committed probe clears episode and preserves last-resort recovery.
    //# Reset TLP.is_retrans and TLP.end_seq when initiating a connection,
    //# fast recovery, or RTO recovery.
    fn tlp_four_packets_partial_byte_sack_output_retry_and_rto_sequence() {
        for iss in [0, u32::MAX - 1999] {
            let (mut a, _) = tlp_pair(iss);
            let base = a.send_base;
            a.write(&[0x55; 4000]).unwrap();
            for i in 0..4 {
                let bytes = packet(&mut a, 100_000);
                let p = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(p.header.sequence, base.wrapping_add(i * 1000).0);
                assert_eq!(p.payload, &[0x55; 1000]);
            }
            assert_eq!(a.tlp_deadline, Some(300_000));
            rack_sack(&mut a, 200_000, 0, &[(3999, 4000)]);
            assert_eq!(a.rack.counts().sacked, 0);
            assert_eq!(a.rack.deadline, None);
            assert!(a.sack_recovery.is_none());
            assert_eq!(a.tlp_deadline, Some(300_000));
            a.timeout(300_000).unwrap();
            let before = (
                a.snd_nxt,
                a.sample,
                a.tlp_end,
                a.tlp_flight,
                a.tlp_fresh_rtt,
                a.rto_deadline,
                a.congestion.cwnd(),
                a.rack.counts().retransmitted,
            );
            assert_eq!(
                a.transmit(300_000, &mut [0; 19]),
                Err(Error::OutputTooSmall)
            );
            assert!(a.tlp_pending);
            assert_eq!(
                before,
                (
                    a.snd_nxt,
                    a.sample,
                    a.tlp_end,
                    a.tlp_flight,
                    a.tlp_fresh_rtt,
                    a.rto_deadline,
                    a.congestion.cwnd(),
                    a.rack.counts().retransmitted
                )
            );
            let bytes = packet(&mut a, 300_000);
            let p = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(p.header.sequence, base.wrapping_add(3000).0);
            assert_eq!(p.payload, &[0x55; 1000]); // includes the SACKed last byte
            assert_eq!(a.rto_deadline, Some(600_000));
            assert_eq!(a.congestion.cwnd(), 4000);
            assert_eq!(a.tlp_deadline, None);
            assert!(!a.tlp_fresh_rtt);
            assert_eq!(a.rack.counts().retransmitted, 1);
            assert_eq!(a.limited_sent, 0);
            assert!(!a.limited_pending);
            assert_eq!(a.transmit(300_001, &mut [0; 1500]), Ok(None));
            rack_sack(&mut a, 400_000, 0, &[(3999, 4000)]);
            assert_eq!(a.tlp_deadline, None);
            a.timeout(599_999).unwrap();
            assert_eq!(a.transmit(599_999, &mut [0; 1500]), Ok(None));
            a.timeout(600_000).unwrap();
            assert_eq!(a.tlp_end, None);
            assert_eq!(a.congestion.cwnd(), 1000);
            assert_eq!(a.rto(), 600_000);
            let bytes = packet(&mut a, 600_000);
            let p = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(p.header.sequence, base.0);
            assert_eq!(p.payload.len(), 1000);
            rack_sack(&mut a, 1_100_000, 1000, &[(3999, 4000)]);
            for offset in [1000, 2000] {
                let bytes = packet(&mut a, 1_100_000);
                let p = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(p.header.sequence, base.wrapping_add(offset).0);
                assert_eq!(p.payload.len(), 1000);
            }
            rack_sack(&mut a, 1_200_000, 3000, &[(3999, 4000)]);
            let bytes = packet(&mut a, 1_200_000);
            let p = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(p.header.sequence, base.wrapping_add(3000).0);
            // RACK retains the original packet boundary while the scoreboard
            // still preserves advisory delivery of the final byte.
            assert_eq!(p.payload, &[0x55; 1000]);
            rack_sack(&mut a, 1_300_000, 4000, &[]);
            assert_eq!(a.flight(), 0);
            assert_eq!(a.rto_deadline, None);
            assert_eq!(a.tlp_deadline, None);
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= type=test
    //= reason=At full cwnd one new segment probe increases flight by one MSS and a second output is blocked.
    //# When the PTO timer expires, the sender MUST check whether both of the
    //# following conditions are met before sending a loss probe:
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= type=test
    //= reason=Asserts new-data choice, one MSS cwnd overcommit, flight charge and no loss response for its ACK.
    //# If both conditions are met, then the sender SHOULD transmit a
    //# previously unsent data segment, if one exists and the receive window
    //# allows, and increment the FlightSize accordingly.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= type=test
    //= reason=Blocks a second output while probe is outstanding despite additional unsent data.
    //# First, there is no other previous loss probe still in flight.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.4.2
    //= type=test
    //= reason=New-data probe ACK clears episode without threshold reduction.
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
    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
    //= type=test
    //= reason=Checks full-window overcommit, flight=5000 for cwnd=4000, no second output and cumulative ACK exit.
    //# The only exception -- the only way in which RACK-TLP modulates the
    //# congestion control algorithm -- is that one outstanding loss probe
    //# can be sent even if the congestion window is fully used.  However,
    //# this temporary overcommit is accounted for and credited in the in-
    //# flight data tracked for congestion control, so that congestion
    //# control will erase the overcommit upon the next ACK.
    fn tlp_prefers_new_data_beyond_cwnd_and_ack_is_not_loss() {
        for iss in [0, u32::MAX - 1999] {
            let (mut a, _) = tlp_pair(iss);
            let base = a.send_base;
            a.write(&[0x55; 6000]).unwrap();
            for _ in 0..4 {
                packet(&mut a, 100_000);
            }
            assert_eq!(a.transmit(100_000, &mut [0; 1500]), Ok(None));
            a.timeout(300_000).unwrap();
            let bytes = packet(&mut a, 300_000);
            let p = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(p.header.sequence, base.wrapping_add(4000).0);
            assert_eq!(p.payload.len(), 1000);
            assert_eq!(a.flight(), 5000);
            assert_eq!(
                a.tlp_end,
                Some((base.wrapping_add(4000), base.wrapping_add(5000), false))
            );
            assert_eq!(a.rto_deadline, Some(600_000));
            assert_eq!(a.transmit(300_001, &mut [0; 1500]), Ok(None));
            let threshold = a.congestion.ssthresh();
            rack_sack(&mut a, 400_000, 5000, &[]);
            assert_eq!(a.tlp_end, None);
            assert_eq!(a.congestion.ssthresh(), threshold);
            assert!(!a.congestion.in_recovery());
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= type=test
    //= reason=No fresh RTT after retransmitted probe, no second PTO; a new sampled flight permits another.
    //# When the PTO timer expires, the sender MUST check whether both of the
    //# following conditions are met before sending a loss probe:
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.4.2
    //= type=test
    //= reason=Checks equality, matching and unrelated DSACK, bare DupACK, later ACK loss reduction and fresh-sample gate.
    //# If the TLP
    //# sender does not receive such an indication, then it MUST assume that
    //# the original data segment, the TLP retransmission, or a corresponding
    //# ACK was lost for congestion control purposes.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= type=test
    //= reason=Retransmitted probe does not yield a new ordinary RTT sample; new unambiguous data ACK restores freshness.
    //# Second, the sender has obtained an RTT measurement since the last
    //# loss probe transmission or the start of the connection, whichever
    //# was later.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.4.2
    //= type=test
    //= reason=Checks retransmission equality, DSACK match/unrelated, DupACK and beyond-end loss.
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
    fn tlp_retransmit_ack_equality_dsack_dupack_and_single_loss_response() {
        for iss in [0, u32::MAX - 1999] {
            // 0: ACK beyond probe = loss; 1: matching DSACK; 2: bare DupACK;
            // 3: unrelated DSACK must not suppress the later loss response.
            for case in 0..4 {
                let (mut a, _) = tlp_pair(iss);
                a.write(&[0x55; 4000]).unwrap();
                for _ in 0..4 {
                    packet(&mut a, 100_000);
                }
                a.timeout(300_000).unwrap();
                packet(&mut a, 300_000);
                let threshold = a.congestion.ssthresh();
                rack_sack(
                    &mut a,
                    400_000,
                    4000,
                    match case {
                        1 => &[(3000, 4000)][..],
                        3 => &[(2000, 3000)][..],
                        _ => &[],
                    },
                );
                assert_eq!(a.congestion.ssthresh(), threshold);
                assert_eq!(a.tlp_end.is_none(), case == 1);
                assert!(!a.tlp_fresh_rtt); // Karn: no new measurement from the probe
                if case == 2 {
                    rack_sack(&mut a, 400_001, 4000, &[]);
                    assert_eq!(a.tlp_end, None);
                }
                a.write(&[0x66; 1000]).unwrap();
                packet(&mut a, 400_002);
                assert_eq!(a.tlp_deadline, None); // no fresh RTT, no second probe
                rack_sack(&mut a, 500_002, 5000, &[]);
                assert_eq!(a.tlp_end, None);
                assert_eq!(
                    a.congestion.ssthresh(),
                    if case == 0 || case == 3 {
                        2000
                    } else {
                        threshold
                    }
                );
                assert!(!a.congestion.in_recovery());
                assert!(a.tlp_fresh_rtt);
                assert_eq!(a.tlp_deadline, None);
                a.write(&[0x77; 1000]).unwrap();
                packet(&mut a, 500_003);
                assert!(a.tlp_deadline.is_some()); // a genuinely new sampled flight
            }
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-1
    //= type=test
    //= reason=Opt-in packet-level feedback enters RACK recovery and retransmits earlier losses.
    //# This document presents RACK-TLP, a TCP loss detection algorithm that
    //# improves upon the widely implemented duplicate acknowledgment
    //# (DupAck) counting approach described in [RFC5681] and [RFC6675]; it
    //# is RECOMMENDED as an alternative to that earlier approach.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.1
    //= type=test
    //= reason=Feedback-triggered fast recovery clears probe episode.
    //# Reset TLP.is_retrans and TLP.end_seq when initiating a connection,
    //# fast recovery, or RTO recovery.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.4.1
    //= type=test
    //= reason=Actual packet delivery of tail probe solicits SACK and causes earlier losses, threshold reduction and retransmission.
    //# More specifically, RACK_detect_loss() (Step 5) would mark those
    //# earlier segments as lost.  Then the sender would trigger a fast
    //# recovery to recover those losses.
    fn tlp_packet_feedback_detects_earlier_losses_and_enters_rack_recovery() {
        for iss in [0, u32::MAX - 1999] {
            let (mut a, mut b) = tlp_pair(iss);
            let base = a.send_base;
            a.write(&[0x55; 4000]).unwrap();
            for _ in 0..4 {
                packet(&mut a, 100_000);
            } // drop all original packets
            a.timeout(300_000).unwrap();
            let probe = deliver(&mut a, &mut b, 300_000);
            let p = wire::parse(ip(tuple()), &probe).unwrap();
            assert_eq!(p.header.sequence, base.wrapping_add(3000).0);
            let ack = deliver(&mut b, &mut a, 400_000);
            let feedback = wire::parse(ip(reverse(tuple())), &ack).unwrap();
            assert_eq!(feedback.header.acknowledgment, base.0);
            assert_eq!(
                feedback.options.sack_blocks[0],
                Some((base.wrapping_add(3000).0, base.wrapping_add(4000).0))
            );
            assert!(a.sack_recovery.is_some());
            assert_eq!(a.tlp_end, None);
            assert_eq!(a.tlp_deadline, None);
            assert_eq!(a.congestion.ssthresh(), 2000);
            assert_eq!(a.rack.counts().lost, 3);
            let bytes = packet(&mut a, 400_000);
            let p = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(p.header.sequence, base.0);
            assert_eq!(p.payload, &[0x55; 1000]);
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.2
    //= type=test
    //= reason=Checks advancing ACK reschedule and cancellation for full SACK, zero window and invalid ledger.
    //# The sender SHOULD start or
    //# restart a loss probe PTO timer after transmitting new data (that was
    //# not itself a loss probe) or upon receiving an ACK that cumulatively
    //# acknowledges new data unless it is already in fast recovery, RTO
    //# recovery, or segments have been SACKed (i.e., RACK.segs_sacked is not
    //# zero).
    fn tlp_zero_window_complete_sack_and_recovery_cancel_probe() {
        for mode in 0..4 {
            let (mut a, _) = tlp_pair(0);
            a.write(&[0x55; 4000]).unwrap();
            for _ in 0..4 {
                packet(&mut a, 100_000);
            }
            a.timeout(300_000).unwrap();
            assert!(a.tlp_pending);
            if mode == 0 {
                inject_sack(&mut a, 300_001, Seq(901), Seq(1), ACK, 0, &[], &[]);
                assert!(a.persist_deadline.is_some());
                assert_eq!(a.rto_deadline, None);
            } else if mode == 1 {
                rack_sack(&mut a, 300_001, 0, &[(3000, 4000)]);
                assert_eq!(a.rack.counts().sacked, 1);
                assert_eq!(a.rack.deadline, Some(325_001));
            } else if mode == 2 {
                rack_sack(&mut a, 300_001, 1000, &[]);
                assert_eq!(a.tlp_deadline, Some(525_001));
            } else {
                a.rack.abandon(a.data_high());
                a.arm_work();
            }
            assert!(!a.tlp_pending);
            assert_eq!(a.tlp_end, None);
            if mode != 2 {
                assert_eq!(a.tlp_deadline, None);
            }
        }
    }

    #[test]
    fn tlp_small_rto_floor_preserves_initial_and_syn_timeout_guard() {
        let cfg = ConnectionConfig {
            sack: true,
            rack: true,
            tlp: true,
            rto_min_us: 200_000,
            ..config(65_536, 1000)
        };
        let mut a = Connection::active(tuple(), cfg.clone(), 0, 0).unwrap();
        assert_eq!(a.rto(), 1_000_000);
        packet(&mut a, 0); // lose SYN
        a.timeout(1_000_000).unwrap();
        let bytes = packet(&mut a, 1_000_000);
        let syn = wire::parse(ip(tuple()), &bytes).unwrap();
        let mut b = Connection::passive(reverse(tuple()), cfg, 900, 1_000_000, &syn).unwrap();
        deliver(&mut b, &mut a, 1_100_000);
        deliver(&mut a, &mut b, 1_100_000);
        assert_eq!(a.state(), State::Established);
        assert_eq!(a.rto(), 3_000_000);
        assert!(!a.tlp_fresh_rtt);
        a.write(&[0x55; 1000]).unwrap();
        deliver(&mut a, &mut b, 1_100_000);
        assert_eq!(a.rto_deadline, Some(4_100_000));
        assert_eq!(a.tlp_deadline, None);
        b.timeout(1_300_000).unwrap();
        deliver(&mut b, &mut a, 1_300_000);
        assert!(!a.syn_timed_out);
        assert!(a.tlp_fresh_rtt);
        assert_eq!(a.rto(), 600_000);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= type=test
    //= reason=Failed output preserves sample/probe state and subsequent RTO emits the first outstanding packet.
    //# After attempting to send a loss probe, regardless of whether a loss
    //# probe was sent, the sender MUST re-arm the RTO timer, not the PTO
    //# timer, if the FlightSize is not zero.
    fn tlp_failed_output_falls_back_to_rto_without_consuming_a_probe() {
        let (mut a, _) = tlp_pair(0);
        a.write(&[0x55; 5000]).unwrap();
        for _ in 0..4 {
            packet(&mut a, 100_000);
        }
        a.timeout(300_000).unwrap();
        assert_eq!(
            a.transmit(300_000, &mut [0; 19]),
            Err(Error::OutputTooSmall)
        );
        assert_eq!(a.snd_nxt, Seq(4001));
        assert_eq!(a.flight(), 4000);
        assert_eq!(a.tlp_end, None);
        assert_eq!(a.tlp_flight, None);
        assert!(a.tlp_pending);
        assert!(a.tlp_fresh_rtt);
        a.timeout(600_000).unwrap();
        assert!(!a.tlp_pending);
        assert_eq!(a.tlp_end, None);
        assert_eq!(a.rack.counts().retransmitted, 0);
        assert_eq!(a.rto(), 600_000);
        let bytes = packet(&mut a, 600_000);
        let p = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(p.header.sequence, 1);
        assert_eq!(p.payload, &[0x55; 1000]);
        assert_eq!(a.tlp_deadline, None);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.2
    //= type=test
    //= reason=Asserts capped tie, no RTO backoff and successful probe RTO rearm, not the unestimated RTT branch.
    //# Summarizing these considerations in pseudocode form, a sender SHOULD
    //# use the following logic to select the duration of a PTO:
    //= https://www.rfc-editor.org/rfc/rfc8985#section-4
    //= type=test
    //= reason=Asserts default-off TLP and rejects all TLP/RACK/SACK invalid combinations.
    //# TLP requires RACK.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.2
    //= type=test
    //= reason=Directly asserts cap tie and RTO rearm after successful probe.
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
    fn tlp_opt_in_rto_floor_validation_fresh_rtt_and_capped_pto() {
        assert!(!ConnectionConfig::default().tlp);
        assert_eq!(ConnectionConfig::default().rto_min_us, 1_000_000);
        for (sack, rack) in [(false, false), (true, false), (false, true)] {
            let cfg = ConnectionConfig {
                tlp: true,
                sack,
                rack,
                ..config(4096, 1000)
            };
            assert!(matches!(
                Connection::active(tuple(), cfg, 0, 0),
                Err(Error::InvalidArgument)
            ));
        }
        for floor in [0, 60_000_001, u64::MAX] {
            let cfg = ConnectionConfig {
                rto_min_us: floor,
                ..config(4096, 1000)
            };
            assert!(matches!(
                Connection::active(tuple(), cfg, 0, 0),
                Err(Error::InvalidArgument)
            ));
        }
        let (mut a, _) = tlp_pair(0);
        a.tlp_fresh_rtt = false;
        a.write(&[0x55; 1000]).unwrap();
        packet(&mut a, 100_000);
        assert_eq!(a.tlp_deadline, None);
        a.tlp_fresh_rtt = true;
        a.rto_deadline = Some(150_000);
        a.schedule_tlp();
        assert_eq!(a.tlp_deadline, Some(150_000));
        a.timeout(150_000).unwrap();
        assert!(a.tlp_pending);
        assert!(!a.retx_pending);
        assert_eq!(a.rto(), 300_000); // capped PTO does not back off
        packet(&mut a, 150_000);
        assert_eq!(a.rto_deadline, Some(450_000));
        assert_eq!(a.congestion.cwnd(), 4000);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= type=test
    //= reason=Checks next_deadline, deferred entry and emitted retransmission after timer expiry.
    //# For timely loss detection, it is RECOMMENDED that the
    //# sender install a reordering timer.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
    //= type=test
    //= reason=Exercises RACK timer recovery, unique delivery credit and PRR output gating.
    //# The Proportional Rate
    //# Reduction (PRR) algorithm [RFC6937] is RECOMMENDED for the specific
    //# congestion control actions taken upon the losses detected by RACK-
    //# TLP.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= type=test
    //= reason=Services deadline and confirms deferred recovery and output selection.
    //# When an ACK
    //# is received or the RACK reordering timer expires, call
    //# RACK_detect_loss_and_arm_timer().
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= type=test
    //= reason=Failed output preserves TransportInfo, successful packets increase retransmission count, repeated SACK cannot restore spent credit. No direct prr_out assertion for all output kinds.
    //# On any data transmission or retransmission:
    //#
    //#    prr_out += (data sent) // strictly less than or equal to sndcnt
    fn rack_shift_timer_loss_and_reordered_sack_counts() {
        for iss in [0, u32::MAX - 4999] {
            for low in [3000, 5000] {
                let mut a = rack_flight(iss);
                rack_sack(&mut a, 200_000, 0, &[(7000, 8000)]);
                assert_eq!(a.rack.deadline, Some(225_000));
                assert_eq!(a.next_deadline(), Some(225_000));
                assert!(!a.transport_info().recovery);
                a.timeout(227_000).unwrap();
                let before = a.transport_info();
                assert_eq!(
                    (before.recovery, before.lost, before.reordering),
                    (true, 7, 3)
                );
                assert_eq!(
                    a.transmit(227_000, &mut [0; 20]),
                    Err(Error::OutputTooSmall)
                );
                assert_eq!(a.transport_info(), before);
                let bytes = packet(&mut a, 227_000);
                let h = wire::parse(ip(tuple()), &bytes).unwrap().header;
                assert_eq!(h.sequence, iss.wrapping_add(1));
                assert_eq!(
                    (a.transport_info().lost, a.transport_info().retransmitted),
                    (7, 1)
                );
                rack_sack(&mut a, 229_000, 0, &[(low, low + 1000), (7000, 8000)]);
                assert_eq!(
                    (a.transport_info().lost, a.transport_info().reordering),
                    (6, if low == 3000 { 5 } else { 3 })
                );
                let bytes = packet(&mut a, 229_000);
                assert_eq!(
                    wire::parse(ip(tuple()), &bytes).unwrap().header.sequence,
                    iss.wrapping_add(1001)
                );
                assert_eq!(a.transport_info().retransmitted, 2);
                rack_sack(&mut a, 229_000, 0, &[(low, low + 1000), (7000, 8000)]);
                assert_eq!(a.prr.unwrap().credit(), 0);
                rack_sack(&mut a, 231_000, 0, &[(low, low + 2000), (7000, 8000)]);
                assert_eq!(a.transport_info().lost, 5);
                rack_sack(&mut a, 233_000, 0, &[(low, low + 2000), (7000, 9000)]);
                rack_sack(&mut a, 235_000, 0, &[(low, low + 2000), (7000, 10_000)]);
                rack_sack(&mut a, 335_000, 10_000, &[]);
                let info = a.transport_info();
                assert!(!info.recovery);
                assert_eq!(
                    (info.unacked, info.sacked, info.lost, info.retransmitted),
                    (0, 0, 0, 0)
                );
            }
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6937#section-2
    //= type=test
    //= reason=Retained causative evidence survives duplicate SACK, clears on advancing ACK, reset and scoreboard exhaustion; asserts PRR disabled after exhaustion. Not interval-sum equivalence.
    //# Furthermore, for any TCP
    //# (with or without SACK), the sum of DeliveredData must agree with the
    //# forward progress over the same time interval.
    fn rack_timer_entry_credit_is_unique_and_cleared_on_ack_and_reset() {
        let mut a = rack_flight(0);
        rack_sack(&mut a, 200_000, 0, &[(7000, 8000)]);
        let pending = a.rack_entry_delivery;
        assert_eq!(pending, Some((225_000, 1000)));
        rack_sack(&mut a, 201_000, 0, &[(7000, 8000)]);
        assert_eq!(a.rack_entry_delivery, pending);
        rack_sack(&mut a, 202_000, 1000, &[(7000, 8000)]);
        assert_eq!(a.rack_entry_delivery, None);
        // A stale cumulative ACK cannot revive the consumed evidence.
        rack_sack(&mut a, 203_000, 0, &[(7000, 8000)]);
        assert_eq!(a.rack_entry_delivery, None);
        let mut a = rack_flight(0);
        rack_sack(&mut a, 200_000, 0, &[(7000, 8000)]);
        a.terminal(CloseReason::Reset);
        assert_eq!(a.rack_entry_delivery, None);
        let mut a = rack_flight(0);
        rack_sack(&mut a, 200_000, 0, &[(7000, 8000)]);
        // Disjoint byte advice overflows the scoreboard without minting credit.
        for i in 0..65 {
            rack_sack(&mut a, 200_001 + i as u64, 0, &[(i * 2, i * 2 + 1)]);
        }
        assert!(!a.rack.valid());
        assert_eq!(a.rack_entry_delivery, None);
        assert!(a.prr.is_none());
    }

    #[test]
    fn fresh_burst_push_uses_normal_window_not_limited_credit() {
        for push in [false, true] {
            let mut a = rack_flight(0);
            // Start another flight with a deliberately fixed window.
            rack_sack(&mut a, 200_000, 10_000, &[]);
            a.congestion = Congestion::new(1000, RecoveryAlgorithm::NewReno, InitialWindow::Iw10);
            a.write_with_push(&[0x55; 15_000], push).unwrap();
            for i in 0..10 {
                if i == 9 {
                    assert_eq!(
                        a.transmit(200_000, &mut [0; 20]),
                        Err(Error::OutputTooSmall)
                    );
                }
                let bytes = packet(&mut a, 200_000);
                let segment = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(segment.header.flags & PSH != 0, push && i == 9);
            }
            rack_sack(&mut a, 201_000, 10_000, &[(11_000, 12_000)]);
            let bytes = packet(&mut a, 201_000);
            assert_eq!(
                wire::parse(ip(tuple()), &bytes).unwrap().header.flags & PSH,
                0
            );
            rack_sack(&mut a, 202_000, 10_000, &[(11_000, 13_000)]);
            let bytes = packet(&mut a, 202_000);
            assert_eq!(
                wire::parse(ip(tuple()), &bytes).unwrap().header.flags & PSH,
                0
            );
            rack_sack(&mut a, 203_000, 13_000, &[]);
            for i in 0..2 {
                let bytes = packet(&mut a, 203_000);
                assert_eq!(
                    wire::parse(ip(tuple()), &bytes).unwrap().header.flags & PSH != 0,
                    push && i == 1
                );
            }
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= type=test
    //= reason=Exercises recovery burst across wrap, one/two holes and unsent suffix; failed small output precedes each successful MSS packet. Validates transactional recovery output, not all PRR accounting paths.
    //# On any data transmission or retransmission:
    //#
    //#    prr_out += (data sent) // strictly less than or equal to sndcnt
    fn recovery_burst_push_preserves_explicit_control_and_unsent_suffix() {
        for (iss, holes) in [
            (0, 1),
            (0, 2),
            (u32::MAX - 12_000, 1),
            (u32::MAX - 12_000, 2),
        ] {
            for push in [false, true] {
                for unsent in [false, true] {
                    let mut a = rack_flight(iss);
                    rack_sack(&mut a, 200_000, 10_000, &[]);
                    a.write_with_push(&[0x55; 6000], push).unwrap();
                    for _ in 0..6 {
                        packet(&mut a, 200_000);
                    }
                    if unsent {
                        a.write_with_push(&[0x66; 1000], push).unwrap();
                    }
                    rack_sack(&mut a, 300_000, 10_000, &[(10_000 + holes * 1000, 16_000)]);
                    for i in 0..holes {
                        assert_eq!(
                            a.transmit(300_000, &mut [0; 20]),
                            Err(Error::OutputTooSmall)
                        );
                        let bytes = packet(&mut a, 300_000);
                        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
                        assert_eq!(
                            segment.header.sequence,
                            a.iss.wrapping_add(10_001 + i * 1000).0
                        );
                        assert_eq!(segment.payload.len(), 1000);
                        assert_eq!(
                            segment.header.flags & PSH != 0,
                            push && !unsent && holes > 1 && i + 1 == holes
                        );
                    }
                    assert_eq!(a.send.pushed(5999, 1), push);
                }
            }
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6937#section-2
    //= type=test
    //= reason=Repeated same SACK after output leaves credit zero; cumulative delivery and recovery exit leave no outstanding ledger counts. Not signed reneging proof.
    //# With SACK,
    //# DeliveredData can be computed precisely as the change in snd.una,
    //# plus the (signed) change in SACKd.
    fn rack_shift_three_sacks_nofack_and_cumulative_delivery() {
        for iss in [0, u32::MAX - 4999] {
            let mut a = rack_flight(iss);
            rack_sack(&mut a, 200_000, 0, &[(2000, 3000)]);
            rack_sack(&mut a, 201_000, 0, &[(2000, 3000), (6000, 7000)]);
            rack_sack(
                &mut a,
                202_000,
                0,
                &[(2000, 3000), (6000, 7000), (8000, 9000)],
            );
            assert_eq!(a.transport_info().lost, 6);
            packet(&mut a, 202_000);
            rack_sack(
                &mut a,
                209_000,
                0,
                &[(2000, 4000), (6000, 7000), (8000, 9000)],
            );
            assert_eq!(
                (a.transport_info().lost, a.transport_info().reordering),
                (5, 6)
            );
            packet(&mut a, 209_000);
            assert_eq!(a.prr.unwrap().credit(), 0);
            rack_sack(
                &mut a,
                209_000,
                0,
                &[(2000, 4000), (6000, 7000), (8000, 9000)],
            );
            assert_eq!(a.prr.unwrap().credit(), 0);
            rack_sack(
                &mut a,
                219_000,
                0,
                &[(2000, 4000), (6000, 7000), (8000, 10_000)],
            );
            assert_eq!(a.transport_info().lost, 5);
            rack_sack(
                &mut a,
                302_000,
                1000,
                &[(2000, 4000), (6000, 7000), (8000, 10_000)],
            );
            assert_eq!(a.transport_info().lost, 4);
            rack_sack(&mut a, 319_000, 4000, &[(6000, 7000), (8000, 10_000)]);
            assert_eq!(a.transport_info().lost, 3);
            rack_sack(&mut a, 329_000, 7000, &[(8000, 10_000)]);
            rack_sack(&mut a, 429_000, 10_000, &[]);
            let info = a.transport_info();
            assert_eq!(
                (info.unacked, info.sacked, info.lost, info.retransmitted),
                (0, 0, 0, 0)
            );
            assert!(!info.recovery);
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
    //= type=test
    //= reason=After initial MSS consumes PRR credit, further timer-marked loss cannot emit without new delivery credit.
    //# A segment marked
    //# as lost by RACK-TLP MUST NOT be retransmitted until congestion
    //# control deems this appropriate.
    //= https://www.rfc-editor.org/rfc/rfc6937#section-2
    //= type=test
    //= reason=Immediate entry consumes its MSS; later deferred timer marks another loss without minting delivery credit; asserts zero credit and no transmission. Does not prove pre-entry policy.
    //# Furthermore, for any TCP
    //# (with or without SACK), the sum of DeliveredData must agree with the
    //# forward progress over the same time interval.
    fn rack_mixed_immediate_deferred_loss_timer_cannot_mint_prr_entry_credit() {
        for iss in [0, u32::MAX - 1999] {
            let (mut a, _) = tlp_pair(iss);
            a.config.tlp = false;
            a.write(&[0x55; 4000]).unwrap();
            for now in [100_000, 200_000, 300_000, 300_000] {
                packet(&mut a, now);
            }
            rack_sack(&mut a, 400_000, 0, &[(3000, 4000)]);
            assert_eq!(a.rack.counts().lost, 2);
            assert_eq!(a.rack.deadline, Some(425_000));
            assert!(a.sack_recovery.unwrap().entry_pending);
            assert_eq!(a.prr.unwrap().credit(), 1000);
            packet(&mut a, 400_000);
            assert!(!a.sack_recovery.unwrap().entry_pending);
            assert_eq!(a.prr.unwrap().credit(), 0);
            a.timeout(425_000).unwrap();
            assert_eq!(a.rack.counts().lost, 3);
            assert_eq!(a.prr.unwrap().credit(), 0);
            assert_eq!(a.transmit(425_000, &mut [0; 1500]), Ok(None));
        }
    }

    #[test]
    fn rack_ack_split_overflow_disables_active_prr_and_uses_byte_pipe_fallback() {
        for iss in [0, u32::MAX - 99] {
            let (mut a, _) = tlp_pair(iss);
            a.set_nagle(false);
            let base = a.send_base;
            a.write(&[0x55; 2]).unwrap();
            packet(&mut a, 100_000);
            for _ in 0..255 {
                a.write(&[0x55; 1]).unwrap();
                packet(&mut a, 100_000);
            }
            assert_eq!(a.rack.counts().unacked, 256);
            assert!(a.rack.valid());
            assert!(a.start_sack_recovery());
            assert!(a.prr.is_some());
            assert!(a.rack_entry_delivery.is_none());
            // Cumulative ACK cuts the first actual two-byte segment; the SACK
            // simultaneously supplies one byte of fallback delivery at the tail.
            rack_sack(&mut a, 200_000, 1, &[(256, 257)]);
            assert!(!a.rack.valid());
            assert!(a.prr.is_none());
            assert!(a.rack_entry_delivery.is_none());
            assert_eq!(a.snd_una, base.wrapping_add(1));
            assert_eq!(a.flight(), 256);
            assert_eq!(a.scoreboard.unsacked_bytes(a.snd_una, a.data_high()), 255);
            let recovery = a.sack_recovery.unwrap();
            assert_eq!(
                recovery.pipe,
                a.scoreboard
                    .pipe(a.snd_una, a.data_high(), recovery.high_rxt, a.mss as u32)
            );
            assert_eq!(a.tlp_deadline, None);
            assert_eq!(a.tlp_end, None);
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6937#section-2
    //= type=test
    //= reason=Partial SACK retains byte advice; completing original packet retains only 502 new bytes. Asserts later cumulative credit, RTO removal and no-SACK fallback; no universal entry accounting claim.
    //# SACKd: The total number of bytes that the scoreboard indicates have
    //# been delivered to the receiver.  This can be computed by scanning
    //# the scoreboard and counting the total number of bytes covered by
    //# all SACK blocks.  If SACK is not in use, SACKd is not defined.
    fn rack_partial_sack_credit_rto_ecn_and_peer_fallback() {
        let mut a = rack_flight(0);
        rack_sack(&mut a, 200_000, 0, &[(7501, 7999)]);
        assert_eq!(a.transport_info().sacked, 0);
        assert_eq!(a.rack.deadline, None);
        assert!(a.rack_entry_delivery.is_none());
        a.timeout(225_000).unwrap();
        assert!(!a.transport_info().recovery);
        // Completing the original packet supplies RACK evidence; byte advice
        // still credits only the 502 bytes not already SACKed.
        rack_sack(&mut a, 300_000, 0, &[(7000, 8000)]);
        assert_eq!(a.rack_entry_delivery.unwrap().1, 502);
        a.timeout(a.rack.deadline.unwrap()).unwrap();
        packet(&mut a, 350_000);
        assert_eq!(a.transport_info().sacked, 1);
        rack_sack(&mut a, 400_000, 7999, &[]);
        assert_eq!(a.prr.unwrap().credit(), 3000);
        let mut a = rack_flight(0);
        assert!(a.congestion.on_ecn(a.snd_una, a.flight(), a.data_high()));
        let threshold = a.congestion.ssthresh();
        rack_sack(&mut a, 200_000, 0, &[(7000, 8000)]);
        a.timeout(225_000).unwrap();
        assert_eq!(a.congestion.ssthresh(), threshold);
        packet(&mut a, 225_000);
        let rto = a.rto_deadline.unwrap();
        a.timeout(rto).unwrap();
        assert!(a.prr.is_none());
        assert_eq!(a.transport_info().sacked, 0);
        assert_eq!(a.congestion.cwnd(), 1000);
        packet(&mut a, rto);
        assert!(a.transport_info().lost > 0);
        let cfg = ConnectionConfig {
            sack: false,
            rack: true,
            prr: true,
            ..config(4096, 1000)
        };
        let (mut a, mut b) = pair(cfg, 0);
        assert!(!a.rack_enabled());
        a.write(&[1; 1000]).unwrap();
        deliver(&mut a, &mut b, 100);
        b.immediate_ack();
        deliver(&mut b, &mut a, 200);
        assert_eq!(a.transport_info().unacked, 0);
        assert!(a.prr.is_none());
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-4
    //= type=test
    //= reason=Peer without negotiated SACK uses ordinary fast retransmit, not RACK/PRR.
    //# The connection MUST use selective acknowledgment (SACK) options
    //# [RFC2018], and the sender MUST keep SACK scoreboard information
    //# on a per-connection basis ("SACK scoreboard" has the same meaning
    //# here as in [RFC6675], Section 3).
    //= https://www.rfc-editor.org/rfc/rfc6937#section-2
    //= type=test
    //= reason=Peer lacking SACK negotiates ordinary duplicate-ACK retransmission; asserts prr remains None. Applicability evidence only, not implementation of PRR without SACK.
    //# In recovery without SACK,
    //# DeliveredData is estimated to be 1 SMSS on duplicate
    //# acknowledgements, and on a subsequent partial or full ACK,
    //# DeliveredData is estimated to be the change in snd.una, minus 1
    //# SMSS for each preceding duplicate ACK.
    fn rack_prr_peer_without_sack_uses_ordinary_fast_retransmit() {
        let cfg = ConnectionConfig {
            sack: true,
            rack: true,
            prr: true,
            ..config(65_536, 1000)
        };
        let mut a = Connection::active(tuple(), cfg.clone(), 0, 0).unwrap();
        let bytes = packet(&mut a, 0);
        let syn = wire::parse(ip(tuple()), &bytes).unwrap();
        let mut b = Connection::passive(
            reverse(tuple()),
            ConnectionConfig { sack: false, ..cfg },
            900,
            0,
            &syn,
        )
        .unwrap();
        deliver(&mut b, &mut a, 100_000);
        deliver(&mut a, &mut b, 100_000);
        assert!(a.sack_receive);
        assert!(!a.sack_send);
        a.write(&[1; 4000]).unwrap();
        for _ in 0..4 {
            packet(&mut a, 100_000);
        }
        let ack = a.snd_una;
        inject_sack(&mut a, 199_999, b.snd_nxt, ack, ACK, 32_768, &[], &[]);
        for now in 200_000..200_003 {
            let ack = a.snd_una;
            let window = (a.snd_wnd >> a.peer_scale) as u16;
            inject_sack(&mut a, now, b.snd_nxt, ack, ACK, window, &[], &[]);
        }
        assert!(a.retx_pending);
        assert!(a.prr.is_none());
        let bytes = packet(&mut a, 200_003);
        assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().header.sequence, 1);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc2018#section-2
    //= type=test
    //# It MUST NOT be sent on non-SYN segments.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-4
    //= type=test
    //= reason=All active/passive permission combinations, both directions and timestamp modes inject kind 4 on accepted non-SYN OOO data. ACK wire output retains only SYN-negotiated kind-5 permission; disabled directions retain data but emit no SACK.
    //# If the data receiver has not received a SACK-Permitted option for a given
    //# connection, it MUST NOT send SACK options on that connection.
    fn sack_negotiation_directional_and_disabled_layout() {
        assert!(!ConnectionConfig::default().sack);
        for active in [false, true] {
            for passive in [false, true] {
                for timestamps in [false, true] {
                    let cfg = ConnectionConfig {
                        sack: active,
                        timestamps,
                        ..config(1024, 128)
                    };
                    let mut a = Connection::active(tuple(), cfg.clone(), 100, 0).unwrap();
                    assert_eq!(a.transmit(0, &mut [0; 8]), Err(Error::OutputTooSmall));
                    assert!(!a.sack_receive);
                    let bytes = packet(&mut a, 0);
                    assert_eq!(&bytes[20..24], &[2, 4, 0, 128]);
                    assert_eq!(&bytes[bytes.len() - 4..], &[1, 3, 3, 0]);
                    if active {
                        assert_eq!(
                            &bytes[24..28],
                            if timestamps {
                                &[4, 2, 8, 10]
                            } else {
                                &[1, 1, 4, 2]
                            }
                        );
                    }
                    let syn = wire::parse(ip(tuple()), &bytes).unwrap();
                    assert_eq!(syn.options.sack_permitted, active);
                    assert_eq!(
                        bytes.len(),
                        28 + if timestamps {
                            12
                        } else {
                            4 * usize::from(active)
                        }
                    );
                    let mut b = Connection::passive(
                        reverse(tuple()),
                        ConnectionConfig {
                            sack: passive,
                            ..cfg
                        },
                        900,
                        10,
                        &syn,
                    )
                    .unwrap();
                    let bytes = deliver(&mut b, &mut a, 20);
                    let reply = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
                    assert_eq!(reply.options.sack_permitted, active && passive);
                    let ack = deliver(&mut a, &mut b, 30);
                    let ack = wire::parse(ip(tuple()), &ack).unwrap();
                    assert_eq!(ack.header.flags & SYN, 0);
                    assert!(!ack.options.sack_permitted);
                    a.write(b"data").unwrap();
                    let data = packet(&mut a, 31);
                    let data = wire::parse(ip(tuple()), &data).unwrap();
                    assert_eq!(data.payload, b"data");
                    assert!(!data.options.sack_permitted);
                    assert_eq!((a.sack_receive, a.sack_send), (active, active && passive));
                    assert_eq!(
                        (b.sack_receive, b.sack_send),
                        (active && passive, active && passive)
                    );
                    for receiver in [&mut a, &mut b] {
                        let permission = receiver.sack_send;
                        let next = receiver.receive.next();
                        let metadata = ip(reverse(receiver.tuple()));
                        let mut options = vec![1; 4];
                        if timestamps {
                            options.extend_from_slice(&[1, 1, 8, 10]);
                            options.extend_from_slice(&0u32.to_be_bytes());
                            options.extend_from_slice(&receiver.ts_recent.to_be_bytes());
                        }
                        let mut bytes = [0; 128];
                        let len = wire::encode(
                            metadata,
                            Header {
                                source_port: receiver.tuple.remote.port(),
                                destination_port: receiver.tuple.local.port(),
                                sequence: next.wrapping_add(10).0,
                                acknowledgment: receiver.snd_una.0,
                                flags: ACK,
                                window: 1024,
                                urgent_pointer: 0,
                            },
                            &options,
                            b"ooo",
                            &mut bytes,
                        )
                        .unwrap();
                        // Encoder correctly forbids non-SYN kind 4; inject it as peer input.
                        bytes[20..24].copy_from_slice(&[4, 2, 1, 1]);
                        bytes[16..18].fill(0);
                        let checksum = wire::checksum(metadata, &bytes[..len]).unwrap();
                        bytes[16..18].copy_from_slice(&checksum.to_be_bytes());
                        let injected = wire::parse(metadata, &bytes[..len]).unwrap();
                        assert!(injected.options.sack_permitted);
                        assert_eq!(injected.header.flags & SYN, 0);
                        receiver.input(40, &injected).unwrap();
                        assert!(receiver.accepted_metadata);
                        assert_eq!(receiver.sack_send, permission);
                        assert_eq!(
                            receiver.receive.sack_blocks(4)[0],
                            Some((next.wrapping_add(10).0, next.wrapping_add(13).0))
                        );
                        let bytes = packet(receiver, 41);
                        let ack = wire::parse(ip(receiver.tuple()), &bytes).unwrap();
                        assert_eq!(ack.header.acknowledgment, next.0);
                        assert_eq!(
                            ack.options.sack_blocks[0],
                            permission
                                .then_some((next.wrapping_add(10).0, next.wrapping_add(13).0))
                        );
                        assert!(ack.options.sack_blocks.iter().skip(1).all(Option::is_none));
                    }
                }
            }
        }
    }

    #[test]
    fn sack_passive_without_scale_and_repeated_syn() {
        let cfg = ConnectionConfig {
            sack: true,
            ..config(1024, 128)
        };
        let metadata = ip(tuple());
        let mut bytes = [0; 64];
        let len = wire::encode(
            metadata,
            Header {
                source_port: 1000,
                destination_port: 2000,
                sequence: 100,
                acknowledgment: 0,
                flags: SYN,
                window: 1024,
                urgent_pointer: 0,
            },
            &[2, 4, 0, 128, 1, 1, 4, 2],
            &[],
            &mut bytes,
        )
        .unwrap();
        let syn = wire::parse(metadata, &bytes[..len]).unwrap();
        let mut b = Connection::passive(reverse(tuple()), cfg, 900, 10, &syn).unwrap();
        let reply = packet(&mut b, 20);
        assert_eq!(&reply[20..], &[2, 4, 0, 128, 1, 1, 4, 2]);
        b.input(30, &syn).unwrap();
        assert_eq!(packet(&mut b, 40), reply);
        assert!(b.sack_receive && b.sack_send);
    }

    #[test]
    fn sack_syn_path_budget_validated() {
        for sack in [false, true] {
            for timestamps in [false, true] {
                let bound = if timestamps {
                    40
                } else if sack {
                    32
                } else {
                    28
                };
                let mut cfg = ConnectionConfig {
                    sack,
                    timestamps,
                    nagle: false,
                    send_ip_payload_limit: bound - 1,
                    ..config(1024, 128)
                };
                assert!(matches!(
                    Connection::active(tuple(), cfg.clone(), 100, 0),
                    Err(Error::InvalidArgument)
                ));
                cfg.send_ip_payload_limit = bound;
                let mut a = Connection::active(tuple(), cfg.clone(), 100, 0).unwrap();
                let syn = packet(&mut a, 0);
                assert_eq!(syn.len(), bound as usize);
                let syn = wire::parse(ip(tuple()), &syn).unwrap();
                let mut b = Connection::passive(reverse(tuple()), cfg, 900, 10, &syn).unwrap();
                assert_eq!(deliver(&mut b, &mut a, 20).len(), bound as usize);
                deliver(&mut a, &mut b, 30);
                let payload = usize::from(bound) - 20 - if timestamps { 12 } else { 0 };
                assert_eq!(a.mss, payload);
                a.write(&[7; 32]).unwrap();
                let data = deliver(&mut a, &mut b, 40);
                assert_eq!(data.len(), bound as usize);
                let data = wire::parse(ip(tuple()), &data).unwrap();
                assert_eq!(data.payload, vec![7; payload]);
                assert_eq!(data.raw_options.len(), if timestamps { 12 } else { 0 });
                a.lower_mss(if timestamps { 16 } else { 4 }).unwrap();
                assert_eq!(a.mss, 4);
                assert_eq!(
                    packet(&mut a, 50).len(),
                    24 + if timestamps { 12 } else { 0 }
                );
            }
        }
    }

    #[test]
    fn sack_disabled_ignores_peer_kind5() {
        let (mut a, _) = pair(config(1024, 128), 100);
        a.write(&[1; 512]).unwrap();
        for now in 40..44 {
            packet(&mut a, now);
        }
        let una = a.snd_una;
        let next = a.receive.next();
        let timer = a.rto_deadline;
        for now in 50..53 {
            inject_sack(&mut a, now, next, una, ACK, 1024, &[], &[(229, 613)]);
        }
        assert!(a.retx_pending); // Classic Reno/NewReno duplicate ACK handling.
        assert_eq!(a.rto_deadline, timer);
        assert_eq!(a.send.len(), 512);
        let bytes = packet(&mut a, 60);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.header.sequence, una.0);
        assert!(segment.options.sack_blocks.iter().all(Option::is_none));
    }

    #[test]
    fn sack_simultaneous_open_and_syn_retransmit() {
        for timestamps in [false, true] {
            let cfg = ConnectionConfig {
                sack: true,
                timestamps,
                ..config(1024, 128)
            };
            let mut a = Connection::active(tuple(), cfg.clone(), 100, 0).unwrap();
            let mut b = Connection::active(reverse(tuple()), cfg, 900, 0).unwrap();
            let a_syn = packet(&mut a, 0);
            let b_syn = packet(&mut b, 0);
            let mut expected = vec![2, 4, 0, 128];
            if timestamps {
                expected.extend_from_slice(&[4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0]);
            } else {
                expected.extend_from_slice(&[1, 1, 4, 2]);
            }
            expected.extend_from_slice(&[1, 3, 3, 0]);
            assert_eq!(&a_syn[20..], expected);
            assert_eq!(&b_syn[20..], expected);
            let deadline = a.rto_deadline.unwrap();
            a.timeout(deadline).unwrap();
            let retry = packet(&mut a, deadline);
            let mut retry_options = expected.clone();
            if timestamps {
                retry_options[8..12].copy_from_slice(&((deadline / 1_000) as u32).to_be_bytes());
            }
            assert_eq!(&retry[20..], retry_options);
            a.input(
                deadline + 10,
                &wire::parse(ip(reverse(tuple())), &b_syn).unwrap(),
            )
            .unwrap();
            b.input(deadline + 10, &wire::parse(ip(tuple()), &a_syn).unwrap())
                .unwrap();
            let a_reply = packet(&mut a, deadline + 20);
            let b_reply = packet(&mut b, deadline + 20);
            if timestamps {
                expected[8..12].copy_from_slice(&(((deadline + 20) / 1_000) as u32).to_be_bytes());
            }
            assert_eq!(&a_reply[20..], expected);
            assert_eq!(&b_reply[20..], expected);
            assert!(
                wire::parse(ip(tuple()), &a_reply)
                    .unwrap()
                    .options
                    .sack_permitted
            );
            a.input(
                deadline + 30,
                &wire::parse(ip(reverse(tuple())), &b_reply).unwrap(),
            )
            .unwrap();
            b.input(deadline + 30, &wire::parse(ip(tuple()), &a_reply).unwrap())
                .unwrap();
            assert_eq!((a.state, b.state), (State::Established, State::Established));
            assert!(a.sack_send && a.sack_receive && b.sack_send && b.sack_receive);
            let bytes = deliver(&mut a, &mut b, deadline + 40);
            assert!(
                !wire::parse(ip(tuple()), &bytes)
                    .unwrap()
                    .options
                    .sack_permitted
            );
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= type=test
    //= reason=SMSS 128 remains the loss threshold with a piggybacked-SACK budget of 116; 240 and 256 SACKed bytes do not outrank fresh data, but 257 do. Failed encoding does not advance recovery markers.
    //# (1.c) IsLost (S2) returns true.
    fn sack_nextseg_piggyback_budget_does_not_change_loss_threshold() {
        for covered in [240, 256, 257] {
            let mut a = sack_flight(128, 100, 12);
            let una = a.snd_una;
            let point = a.data_high();
            let tail = (una.wrapping_add(1024).0, una.wrapping_add(1024 + covered).0);
            sack_ack(
                &mut a,
                200,
                una,
                &[(una.wrapping_add(128).0, una.wrapping_add(896).0), tail],
            );
            packet(&mut a, 201); // Entry retransmission.
            a.write(&[9; 128]).unwrap();
            let next = a.receive.next();
            inject_sack(
                &mut a,
                210,
                next.wrapping_add(1),
                una.wrapping_add(896),
                ACK,
                8192,
                &[1], // Retained receive hole adds a 12-byte SACK option.
                &[tail],
            );
            assert_eq!(a.scoreboard.is_lost(a.snd_una, 128), covered > 256);
            let recovery = a.sack_recovery.unwrap();
            let nxt = a.snd_nxt;
            let deadline = a.rto_deadline;
            assert_eq!(a.transmit(211, &mut [0; 8]), Err(Error::OutputTooSmall));
            assert_eq!(a.snd_nxt, nxt);
            assert_eq!(a.rto_deadline, deadline);
            let unchanged = a.sack_recovery.unwrap();
            assert_eq!(unchanged.high_rxt, recovery.high_rxt);
            assert_eq!(unchanged.rescue_rxt, recovery.rescue_rxt);
            assert_eq!(unchanged.pipe, recovery.pipe);
            let bytes = packet(&mut a, 211);
            let segment = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(segment.payload.len(), 116);
            assert!(segment.options.sack_blocks[0].is_some());
            assert_eq!(
                segment.header.sequence,
                if covered > 256 { a.snd_una.0 } else { point.0 }
            );
            assert_eq!(a.sack_recovery.unwrap().recovery_point, point);
            if covered <= 256 {
                assert_eq!(segment.payload, &[9; 116]);
                assert_eq!(a.snd_nxt, point.wrapping_add(116));
                assert_eq!(a.sack_recovery.unwrap().high_rxt, recovery.high_rxt);
            } else {
                assert_eq!(a.snd_nxt, point);
                assert_eq!(
                    a.sack_recovery.unwrap().high_rxt,
                    a.snd_una.wrapping_add(116)
                );
            }
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=One SACK ACK leaves pipe 256 under cwnd 512; successive pulls send two packets and stop at credit or window limits. Options clip packets without lowering SMSS credit; failed output preserves pending work and accounting.
    //# (3.3) If (cwnd - pipe) >= 1 SMSS, there exists previously unsent data, and
    //# the receiver's advertised window allows, transmit up to 1 SMSS of data
    //# starting with the octet HighData+1 and update HighData to reflect this
    //# transmission, then return to (3.2).
    fn sack_limited_transmit_repeats_setpipe_on_same_ack() {
        for (piggyback, window, queued, packets) in [
            (false, 8192, 1024, 2),
            (true, 8192, 1024, 2),
            (false, 640, 1024, 1),
            (false, 8192, 640, 1),
        ] {
            let (mut a, _) = pair(sack_config(128), 100);
            a.write(&vec![1; queued]).unwrap();
            for now in 40..44 {
                packet(&mut a, now);
            }
            let una = a.snd_una;
            let end = a.snd_nxt;
            assert_eq!(a.flight(), 512);
            assert_eq!(a.congestion.cwnd(), 512);
            let next = a.receive.next();
            inject_sack(
                &mut a,
                50,
                if piggyback {
                    next.wrapping_add(1)
                } else {
                    next
                },
                una,
                ACK,
                window,
                if piggyback { &[1] } else { &[] },
                &[(una.wrapping_add(128).0, una.wrapping_add(384).0)],
            );
            assert_eq!(a.recovery_pipe(una), 256);
            assert_eq!(a.duplicate_acks, 1);
            assert!(a.limited_pending);
            let budget = if piggyback { 116 } else { 128 };
            for i in 0..packets {
                let nxt = a.snd_nxt;
                let sent = a.limited_sent;
                let limited_end = a.limited_end;
                let deadline = a.rto_deadline;
                assert_eq!(a.transmit(51, &mut [0; 8]), Err(Error::OutputTooSmall));
                assert_eq!(a.snd_nxt, nxt);
                assert_eq!(a.limited_sent, sent);
                assert_eq!(a.limited_end, limited_end);
                assert_eq!(a.rto_deadline, deadline);
                assert!(a.limited_pending);
                let bytes = packet(&mut a, 51);
                let segment = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(segment.header.sequence, end.wrapping_add(i * budget).0);
                assert_eq!(segment.payload.len(), budget as usize);
                assert_eq!(a.limited_sent, (i + 1) * budget);
                assert_eq!(a.limited_end, Some(a.snd_nxt));
            }
            assert!(!a.limited_pending);
            assert_eq!(a.transmit(52, &mut [0; 1024]), Ok(None));
            assert_eq!(a.duplicate_acks, 1);
            assert!(a.recovery_pipe(una) <= a.congestion.cwnd());
            assert!(a.flight() <= a.snd_wnd);
        }
    }

    fn sack_config(mss: u16) -> ConnectionConfig {
        ConnectionConfig {
            sack: true,
            nagle: false,
            delayed_ack_us: 0,
            ..config(8192, mss)
        }
    }

    fn sack_ack(a: &mut Connection, now: Instant, ack: Seq, blocks: &[(u32, u32)]) {
        inject_sack(a, now, a.receive.next(), ack, ACK, 8192, &[], blocks);
    }

    fn sack_flight(mss: u16, iss: u32, segments: usize) -> Connection {
        let (mut a, mut b) = pair(sack_config(mss), iss);
        // Grow cwnd through real cumulative acknowledgments, not test-only setters.
        for round in 0..segments {
            a.write(&vec![0x55; mss as usize]).unwrap();
            deliver(&mut a, &mut b, 40 + round as u64 * 2);
            deliver(&mut b, &mut a, 41 + round as u64 * 2);
            b.read(&mut vec![0; mss as usize]).unwrap();
        }
        a.write(&vec![0x77; mss as usize * segments]).unwrap();
        for i in 0..segments {
            packet(&mut a, 100 + i as u64);
        }
        a
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc2018#section-4
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Enabled receiver emits kind 5 after SYN permission; reordered data yields SACK and gap fill removes it.
    //# If the data receiver has received a SACK-Permitted option on the SYN for
    //# this connection, the data receiver MAY elect to generate SACK options as
    //# described below.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-4
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Ordinary reordered arrivals schedule immediate ACKs, output includes retained ranges; tests parse emitted ACKs.
    //# If the data receiver generates SACK options under any circumstance, it
    //# SHOULD generate them under all permitted circumstances.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-4
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Ordinary reordered arrivals schedule immediate ACKs, output includes retained ranges; tests parse emitted ACKs.
    //# If sent at all, SACK options SHOULD be included in all ACKs which do not ACK
    //# the highest sequence number in the data receiver's queue.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-4
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Ordinary reordered arrivals schedule immediate ACKs, output includes retained ranges; tests parse emitted ACKs.
    //# The receiver SHOULD send an ACK for every valid segment that arrives
    //# containing new data, and each of these "duplicate" ACKs SHOULD bear a SACK
    //# option.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-3
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Wire ACK remains cumulative across SACK reports and advances to end only after gap fill.
    //# When missing segments are received, the data receiver acknowledges the data
    //# normally by advancing the left window edge in the Acknowledgement Number
    //# Field of the TCP header. The SACK option does not change the meaning of the
    //# Acknowledgement Number field.
    fn sack_receiver_reorder_gap_fill_and_dsack_transaction() {
        for iss in [100, u32::MAX - 20] {
            let (mut a, mut b) = pair(sack_config(128), iss);
            a.write(&[1; 384]).unwrap();
            let first = packet(&mut a, 40);
            let second = packet(&mut a, 41);
            let third = packet(&mut a, 42);
            let start = wire::parse(ip(tuple()), &first).unwrap().header.sequence;
            b.input(50, &wire::parse(ip(tuple()), &second).unwrap())
                .unwrap();
            let ack = packet(&mut b, 51);
            let ack = wire::parse(ip(reverse(tuple())), &ack).unwrap();
            assert_eq!(ack.header.acknowledgment, start);
            assert_eq!(
                ack.options.sack_blocks[0],
                Some((start.wrapping_add(128), start.wrapping_add(256)))
            );
            b.input(52, &wire::parse(ip(tuple()), &third).unwrap())
                .unwrap();
            packet(&mut b, 53);
            b.input(54, &wire::parse(ip(tuple()), &third).unwrap())
                .unwrap();
            assert_eq!(b.transmit(55, &mut [0; 20]), Err(Error::OutputTooSmall));
            let bytes = packet(&mut b, 55);
            let ack = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
            assert_eq!(
                ack.options.sack_blocks[..2],
                [
                    Some((start.wrapping_add(256), start.wrapping_add(384))),
                    Some((start.wrapping_add(128), start.wrapping_add(384)))
                ]
            );
            b.immediate_ack();
            let bytes = packet(&mut b, 56);
            assert_eq!(
                wire::parse(ip(reverse(tuple())), &bytes)
                    .unwrap()
                    .options
                    .sack_blocks[0],
                Some((start.wrapping_add(128), start.wrapping_add(384)))
            );
            b.input(57, &wire::parse(ip(tuple()), &first).unwrap())
                .unwrap();
            let bytes = packet(&mut b, 58);
            let ack = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
            assert_eq!(ack.header.acknowledgment, start.wrapping_add(384));
            assert!(ack.options.sack_blocks.iter().all(Option::is_none));
            b.read(&mut [0; 384]).unwrap();
            b.input(59, &wire::parse(ip(tuple()), &first).unwrap())
                .unwrap();
            assert!(!b.accepted_metadata); // Narrow old-data path accepts no metadata.
            let bytes = packet(&mut b, 60);
            assert_eq!(
                wire::parse(ip(reverse(tuple())), &bytes)
                    .unwrap()
                    .options
                    .sack_blocks[0],
                Some((start, start.wrapping_add(128)))
            );
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc2018#section-4
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Output uses available TCP/path option budget; tests assert 4 ordinary slots or 3 with timestamps, payload clipping and failed-output rollback.
    //# * The data receiver SHOULD include as many distinct SACK blocks as possible
    //# in the SACK option.
    fn sack_options_budget_ts_payload_fin_and_failed_output() {
        for timestamps in [false, true] {
            let cfg = ConnectionConfig {
                timestamps,
                send_ip_payload_limit: 160,
                ..sack_config(128)
            };
            let (mut a, _) = pair(cfg, 100);
            let next = a.receive.next();
            for (i, offset) in [10, 30, 50, 70].into_iter().enumerate() {
                let una = a.snd_una;
                inject_sack(
                    &mut a,
                    1000 + i as u64,
                    next.wrapping_add(offset),
                    una,
                    ACK,
                    8192,
                    &[1; 5],
                    &[],
                );
                packet(&mut a, 1000 + i as u64);
            }
            // Restore a pending option report and send final queued bytes with FIN.
            let una = a.snd_una;
            inject_sack(
                &mut a,
                2000,
                next.wrapping_add(70),
                una,
                ACK,
                8192,
                &[1; 5],
                &[],
            );
            a.write(&[2; 128]).unwrap();
            a.shutdown().unwrap();
            let before = (
                a.snd_nxt,
                a.fin_sequence,
                a.now,
                a.rto_deadline,
                a.last_ack_sent,
            );
            assert_eq!(a.transmit(3000, &mut [0; 20]), Err(Error::OutputTooSmall));
            assert_eq!(
                before,
                (
                    a.snd_nxt,
                    a.fin_sequence,
                    a.now,
                    a.rto_deadline,
                    a.last_ack_sent
                )
            );
            let bytes = packet(&mut a, 3000);
            let segment = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(
                segment.options.sack_blocks.iter().flatten().count(),
                if timestamps { 3 } else { 4 }
            );
            assert_eq!(
                segment.payload.len(),
                a.mss - if timestamps { 28 } else { 36 }
            );
            assert!(bytes.len() <= 160);
            assert_eq!(segment.header.flags & (FIN | PSH), 0);
            let bytes = packet(&mut a, 4000);
            let segment = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(segment.header.flags & (FIN | PSH), FIN | PSH);
            assert_eq!(
                a.fin_sequence,
                Some(Seq(segment.header.sequence).wrapping_add(segment.payload.len() as u32))
            );
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Validated negotiated ACKs update in-flight ranges; stale/future/DSACK-only blocks cannot count as fresh delivery.
    //# Upon the receipt of any ACK containing SACK information, the scoreboard MUST
    //# be updated via the Update () routine.
    fn sack_invalid_future_stale_ack_and_dsack_are_not_delivery() {
        let mut a = sack_flight(128, 100, 6);
        let una = a.snd_una;
        let end = a.data_high();
        let next = a.receive.next();
        let timer = a.rto_deadline;
        for (i, (ack, block)) in [
            (end.wrapping_add(1), (una.wrapping_add(128).0, end.0)),
            (una.wrapping_add(u32::MAX), (una.wrapping_add(128).0, end.0)),
            (una, (una.wrapping_add(128).0, end.wrapping_add(1).0)),
            (una, (end.0, una.0)),
            (una, (una.0, una.0)),
            (una, (una.wrapping_add(1 << 31).0, end.0)),
            (una, (una.wrapping_add(u32::MAX - 9).0, una.0)),
        ]
        .into_iter()
        .enumerate()
        {
            inject_sack(&mut a, 200 + i as u64, next, ack, ACK, 8192, &[], &[block]);
            assert_eq!(a.duplicate_acks, 0);
            assert!(a.sack_recovery.is_none());
            assert_eq!(
                a.scoreboard.pipe(una, end, una, 128),
                end.distance_from(una)
            );
        }
        assert_eq!(a.rto_deadline, timer);
        assert_eq!(a.send.len(), 768);
        let ack = a.snd_una;
        // The second enclosing block is evidence once; the first DSACK is not.
        sack_ack(
            &mut a,
            220,
            ack,
            &[
                (una.wrapping_add(140).0, una.wrapping_add(150).0),
                (una.wrapping_add(128).0, una.wrapping_add(256).0),
            ],
        );
        assert_eq!(a.duplicate_acks, 1);
        sack_ack(
            &mut a,
            221,
            ack,
            &[
                (una.wrapping_add(140).0, una.wrapping_add(150).0),
                (una.wrapping_add(128).0, una.wrapping_add(256).0),
            ],
        );
        assert_eq!(a.duplicate_acks, 1);
        assert_eq!(a.send.len(), 768);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= type=test
    //= reason=Negotiated non-RACK/non-PRR SACK; full-budget and piggybacked-SACK regressions exercise lost/new/speculative/rescue priority. IsLost uses SMSS independently of output clipping; markers commit only after encoding.
    //# NextSeg () MUST return the
    //# sequence number range of the next segment that is to be
    //# transmitted, per the following rules:
    //= https://www.rfc-editor.org/rfc/rfc2018#section-8
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Only validated cumulative ACK calls SendBuffer::acknowledge; test asserts 1024 bytes retained across selective recovery and zero only after full ACK.
    //# Since the data receiver may later discard data reported in a SACK option,
    //# the sender MUST NOT discard data before it is acknowledged by the
    //# Acknowledgment Number field in the TCP header.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Update/IsLost/SetPipe are byte-range scoreboard functions; NextSeg is in poll-driven output selection, not a literal function. Focused scoreboard reference and priority tests provide behavioral evidence.
    //# For the purposes of the algorithm defined in this document, the scoreboard
    //# SHOULD implement the following functions:
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. SACK updates never release send bytes; cumulative ACK is the release path and is asserted separately.
    //# Note: SACK information is advisory and therefore SACKed data MUST NOT be
    //# removed from the TCP's retransmission buffer until the data is cumulatively
    //# acknowledged [RFC2018].
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= type=test
    //= reason=Negotiated non-RACK/non-PRR SACK; lowest_hole uses SMSS for IsLost and output is clipped to the packet budget. Integrated 240/256/257-byte SACK cases verify the strict loss threshold and fresh-data priority with SMSS 128 and budget 116.
    //# (1) If there exists a smallest unSACKed sequence number 'S2' that meets the
    //# following three criteria for determining loss, the sequence range of one
    //# segment of up to SMSS octets starting with S2 MUST be returned.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. No remaining permitted candidate yields Ok(None); rescue test separately denies repeated rescue.
    //# (5) If the conditions for each of (1), (2), (3), and (4) are not met, then
    //# NextSeg () MUST indicate failure, and no segment is returned.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Exclusive recovery boundary is cumulatively ACKed; recovery terminates, send storage releases and cwnd is deflated.
    //# (A) An incoming cumulative ACK for a sequence number greater than
    //# RecoveryPoint signals the end of loss recovery, and the loss recovery phase
    //# MUST be terminated.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Output uses scoreboard lowest/tail-hole selection and fails without a candidate; test checks multiple output ranges then Ok(None).
    //# (C.1) The scoreboard MUST be queried via NextSeg () for the sequence number
    //# range of the next segment to transmit (if any), and the given segment sent.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Equivalent byte-range strategy skips SACKed intervals in retransmission selection; test sends only missing offsets 0 and 256. RTO intentionally clears advice.
    //# After the SACKed bit is turned on (as the result of processing a received
    //# SACK option), the data sender will skip that segment during any later
    //# retransmission.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Byte buffer is retained across SACKs and released only by cumulative ACK.
    //# A segment will not be dequeued and its buffer freed until the left window
    //# edge is advanced over it.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= type=test
    //= reason=Negotiated non-RACK/non-PRR SACK; lowest_hole uses SMSS for IsLost and output is clipped to the packet budget. Integrated 240/256/257-byte SACK cases verify the strict loss threshold and fresh-data priority with SMSS 128 and budget 116.
    //# (1.a) S2 is greater than HighRxt.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= type=test
    //= reason=Negotiated non-RACK/non-PRR SACK; lowest_hole uses SMSS for IsLost and output is clipped to the packet budget. Integrated 240/256/257-byte SACK cases verify the strict loss threshold and fresh-data priority with SMSS 128 and budget 116.
    //# (1.b) S2 is less than the highest octet covered by any received SACK.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= type=test
    //= reason=Negotiated non-RACK/non-PRR SACK; lowest_hole uses SMSS for IsLost and output is clipped to the packet budget. Integrated 240/256/257-byte SACK cases verify the strict loss threshold and fresh-data priority with SMSS 128 and budget 116.
    //# (1.c) IsLost (S2) returns true.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Entry records fixed data_high boundary; cumulative ACK at exclusive boundary ends recovery.
    //# (4.1) RecoveryPoint = HighData When the TCP sender receives a cumulative ACK
    //# for this data octet, the loss recovery phase is terminated.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. entry_pending retransmits snd_una regardless of advisory SACK, bounded by real data high, output and peer window; sack_entry_retransmits_sacked_head_transactionally checks committed exclusive HighRxt/RescueRxt and SetPipe after success, not failure.
    //# (4.3) Retransmit the first data segment presumed dropped -- the segment
    //# starting with sequence number HighACK + 1. To prevent repeated
    //# retransmission of the same data or a premature rescue retransmission, set
    //# both HighRxt and RescueRxt to the highest sequence number in the
    //# retransmitted segment.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Entry initializes pipe from scoreboard and successful entry retransmission recomputes SetPipe with committed HighRxt, including when advisory SACK covers the head.
    //# (4.4) Run SetPipe () Set a "pipe" variable to the number of outstanding
    //# octets currently "in the pipe"; this is the data which has been sent by the
    //# TCP sender but for which no cumulative or selective acknowledgment has been
    //# received and the data has not been determined to have been dropped in the
    //# network. It is assumed that the data is still traversing the network path.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. No candidate returns no segment; multiloss and rescue tests assert Ok(None).
    //# If NextSeg () returns failure (no data to send), return without sending
    //# anything (i.e., terminate steps C.1 -- C.5).
    //= https://www.rfc-editor.org/rfc/rfc6675#section-6
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Optional timer variant uses the shared successful-retransmission commit path. sack_multiloss_selective_recovery_and_transactional_entry asserts exact send_time+rto after both retransmissions, failed-output stability and nonadvancing-SACK nonrestart; sack_rto_discards_advice_retransmits_head_and_guards_epoch checks entry and expiry.
    //# Therefore, we give implementers the latitude to use the standard
    //# [RFC6298]-style RTO management or, optionally, a more careful variant that
    //# re-arms the RTO timer on each retransmission that is sent during recovery
    //# MAY be used.
    fn sack_multiloss_selective_recovery_and_transactional_entry() {
        for iss in [100, u32::MAX - 1000] {
            let mut a = sack_flight(128, iss, 8);
            let una = a.snd_una;
            let point = a.data_high();
            // Losses at 0 and 256; enough new bytes above both to mark both lost.
            sack_ack(
                &mut a,
                200,
                una,
                &[
                    (una.wrapping_add(128).0, una.wrapping_add(256).0),
                    (una.wrapping_add(384).0, point.0),
                ],
            );
            let recovery = a.sack_recovery.unwrap();
            assert!(recovery.entry_pending);
            assert_eq!(recovery.high_rxt, una);
            let original_deadline = a.rto_deadline;
            assert_eq!(a.transmit(201, &mut [0; 8]), Err(Error::OutputTooSmall));
            assert_eq!(a.rto_deadline, original_deadline);
            assert!(a.sack_recovery.unwrap().entry_pending);
            assert_eq!(a.sack_recovery.unwrap().rescue_rxt, None);
            let bytes = packet(&mut a, 201);
            let first = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(first.header.sequence, una.0);
            assert_eq!(first.payload.len(), 128);
            assert_eq!(a.rto_deadline, Some(201 + a.rto()));
            assert_eq!(a.sack_recovery.unwrap().high_rxt, una.wrapping_add(128));
            let first_deadline = a.rto_deadline;
            assert_eq!(a.transmit(202, &mut [0; 8]), Err(Error::OutputTooSmall));
            assert_eq!(a.rto_deadline, first_deadline);
            let bytes = packet(&mut a, 202);
            let second = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(second.header.sequence, una.wrapping_add(256).0);
            assert_eq!(second.payload.len(), 128);
            assert_eq!(a.rto_deadline, Some(202 + a.rto()));
            let second_deadline = a.rto_deadline;
            sack_ack(
                &mut a,
                203,
                una,
                &[
                    (una.wrapping_add(128).0, una.wrapping_add(256).0),
                    (una.wrapping_add(384).0, point.0),
                ],
            );
            assert_eq!(a.snd_una, una);
            assert_eq!(a.rto_deadline, second_deadline);
            assert_eq!(a.transmit(203, &mut [0; 1024]), Ok(None));
            assert_eq!(a.send.len(), 1024); // SACK never frees send bytes.
            assert_eq!(a.acknowledged, 1024); // Only the warmup was ACKed.
            sack_ack(&mut a, 210, point, &[]);
            assert!(a.sack_recovery.is_none());
            assert_eq!(a.send.len(), 0);
            assert_eq!(a.congestion.cwnd(), 256);
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Non-RACK/non-PRR entry with a valid SACKed head retransmits snd_una across wrap, clips to output/peer/data limits, and commits exclusive HighRxt/RescueRxt and recomputed pipe only after successful encoding.
    //# (4.3) Retransmit the first data segment presumed dropped -- the segment
    //# starting with sequence number HighACK + 1. To prevent repeated
    //# retransmission of the same data or a premature rescue retransmission, set
    //# both HighRxt and RescueRxt to the highest sequence number in the
    //# retransmitted segment.
    fn sack_entry_retransmits_sacked_head_transactionally() {
        for iss in [100, u32::MAX - 1000] {
            for (tail, window, ooo, expected) in [
                (1024, 8192, false, 128),
                (1024, 63, false, 63),
                (1024, 8192, true, 116),
                (31, 8192, false, 31),
            ] {
                let mut a = sack_flight(128, iss, 8);
                let una = a.data_high().wrapping_add(0u32.wrapping_sub(tail));
                sack_ack(&mut a, 190, una, &[]);
                if ooo {
                    let seq = a.receive.next().wrapping_add(10);
                    inject_sack(&mut a, 191, seq, una, ACK, window, b"ooo", &[]);
                }
                for (i, size) in [8, 16, 24].into_iter().enumerate() {
                    let seq = a.receive.next();
                    inject_sack(
                        &mut a,
                        200 + i as u64,
                        seq,
                        una,
                        ACK,
                        window,
                        &[],
                        &[(una.0, una.wrapping_add(size).0)],
                    );
                }
                assert_eq!(a.scoreboard.ranges(), &[(una, una.wrapping_add(24))]);
                let before = a.sack_recovery.unwrap();
                assert!(before.entry_pending);
                let deadline = a.rto_deadline;
                assert_eq!(a.transmit(203, &mut [0; 8]), Err(Error::OutputTooSmall));
                let retry = a.sack_recovery.unwrap();
                assert_eq!(
                    (
                        retry.high_rxt,
                        retry.rescue_rxt,
                        retry.pipe,
                        retry.entry_pending
                    ),
                    (
                        before.high_rxt,
                        before.rescue_rxt,
                        before.pipe,
                        before.entry_pending
                    )
                );
                assert_eq!(a.rto_deadline, deadline);
                let bytes = packet(&mut a, 204);
                let segment = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(segment.header.sequence, una.0);
                assert_eq!(segment.payload, &[0x77; 128][..expected]);
                let recovery = a.sack_recovery.unwrap();
                let end = una.wrapping_add(expected as u32);
                assert!(!recovery.entry_pending);
                assert_eq!(recovery.high_rxt, end);
                assert_eq!(recovery.rescue_rxt, Some(end));
                assert_eq!(recovery.pipe, a.recovery_pipe(end));
                assert_eq!(a.scoreboard.ranges(), &[(una, una.wrapping_add(24))]);
            }
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Non-RACK/non-PRR recovery sends new bytes beyond fixed RecoveryPoint, SACKs their suffix, exits with advice retained across wrap, recomputes pipe and uses retained advice to trigger later recovery on one new SACK ACK.
    //# Any information contained in the scoreboard for sequence numbers greater
    //# than the new value of HighACK SHOULD NOT be cleared when leaving the loss
    //# recovery phase.
    fn sack_recovery_exit_retains_new_data_advice_for_later_recovery() {
        for iss in [100, u32::MAX - 1800] {
            let mut a = sack_flight(128, iss, 12);
            let una = a.snd_una;
            let point = a.data_high();
            a.write(&[9; 512]).unwrap();
            sack_ack(&mut a, 200, una, &[(una.wrapping_add(128).0, point.0)]);
            packet(&mut a, 201); // Entry retransmission.
            for i in 0..4 {
                let bytes = packet(&mut a, 202 + i);
                let segment = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(
                    segment.header.sequence,
                    point.wrapping_add(i as u32 * 128).0
                );
                assert_eq!(segment.payload, &[9; 128]);
                assert_eq!(a.sack_recovery.unwrap().recovery_point, point);
            }
            let retained = (point.wrapping_add(128), point.wrapping_add(512));
            sack_ack(&mut a, 210, una, &[(retained.0.0, retained.1.0)]);
            let recovery = a.sack_recovery.unwrap();
            assert_eq!(recovery.pipe, a.recovery_pipe(recovery.high_rxt));
            sack_ack(&mut a, 211, point, &[]);
            assert!(a.sack_recovery.is_none());
            assert!(!a.congestion.in_recovery());
            assert_eq!(a.scoreboard.ranges(), &[retained]);
            assert_eq!(a.send.len(), 512);
            assert_eq!(a.recovery_pipe(point), 0); // 384 retained SACKed bytes mark the head lost.
            a.write(&[8; 128]).unwrap();
            let bytes = packet(&mut a, 212);
            assert_eq!(
                wire::parse(ip(tuple()), &bytes).unwrap().header.sequence,
                retained.1.0
            );
            let high = a.snd_nxt;
            sack_ack(&mut a, 213, point, &[(retained.1.0, high.0)]);
            let recovery = a.sack_recovery.unwrap();
            assert!(recovery.entry_pending); // Only one fresh SACK; retained bytes supply IsLost evidence.
            assert_eq!(recovery.recovery_point, point.wrapping_add(640));
            assert_eq!(recovery.pipe, 0);
            assert_eq!(
                a.scoreboard.ranges(),
                &[(retained.0, point.wrapping_add(640))]
            );
            let bytes = packet(&mut a, 214);
            let segment = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(segment.header.sequence, point.0);
            assert_eq!(segment.payload, &[9; 128]);
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. A single ACK carrying three one-byte discontiguous SACK ranges starts recovery immediately and emits one SMSS starting at snd_una regardless of advisory SACK edges.
    //# (2) If DupAcks < DupThresh but IsLost (HighACK + 1) returns true --
    //# indicating at least three segments have arrived above the current cumulative
    //# acknowledgment point, which is taken to indicate loss -- go to step (4).
    fn sack_discontiguous_evidence_and_unaligned_retransmit() {
        let mut a = sack_flight(128, 100, 8);
        let una = a.snd_una;
        sack_ack(
            &mut a,
            200,
            una,
            &[
                (una.wrapping_add(17).0, una.wrapping_add(18).0),
                (una.wrapping_add(91).0, una.wrapping_add(92).0),
                (una.wrapping_add(201).0, una.wrapping_add(202).0),
            ],
        );
        assert!(a.sack_recovery.is_some()); // Three ranges, not three SMSS.
        let bytes = packet(&mut a, 201);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.header.sequence, una.0);
        assert_eq!(segment.payload.len(), 128); // Entry does not clip at advisory SACK edges.
        // ACK trims arbitrary bytes; a retransmission starts from that offset.
        sack_ack(&mut a, 202, una.wrapping_add(7), &[]);
        assert_eq!(a.snd_una, una.wrapping_add(7));
        assert_eq!(a.send.len(), 1017);
        assert_eq!(
            a.sack_recovery.unwrap().recovery_point,
            una.wrapping_add(1024)
        );
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. New SACK evidence increments once even on duplex/window-changing ACK; repeated blocks do not earn new credit.
    //# If the incoming ACK is a duplicate acknowledgment per the definition in
    //# Section 2 (regardless of its status as a cumulative acknowledgment), and the
    //# TCP is not currently in loss recovery, the TCP MUST increase DupAcks by one
    //# and take the following steps:
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated non-RACK/non-PRR SACK; each output poll recomputes SetPipe and sends up to the packet budget while SMSS credit and peer window permit. Integrated tests exhaust two-SMSS credit from one ACK, check window/option limits and failed-output rollback.
    //# (3) The TCP MAY transmit previously unsent data segments as per Limited
    //# Transmit [RFC5681], except that the number of octets which may be sent is
    //# governed by pipe and cwnd as follows:
    //= https://www.rfc-editor.org/rfc/rfc6675#section-2
    //= type=test
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
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Threshold is three fresh-evidence ACKs; recovery starts on third, not repeated SACK blocks.
    //# Per [RFC5681], this threshold is defined to be 3 duplicate acknowledgments.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Three fresh evidence ACKs start recovery; repeated evidence is not counted.
    //# (1) If DupAcks >= DupThresh, go to step (4).
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Limited-transmit pipe passes snd_una (exclusive HighACK) as high_rxt.
    //# (3.1) Set HighRxt to HighACK.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated non-RACK/non-PRR SACK; each output poll recomputes SetPipe and sends up to the packet budget while SMSS credit and peer window permit. Integrated tests exhaust two-SMSS credit from one ACK, check window/option limits and failed-output rollback.
    //# (3.2) Run SetPipe ().
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated non-RACK/non-PRR SACK; each output poll recomputes SetPipe and sends up to the packet budget while SMSS credit and peer window permit. Integrated tests exhaust two-SMSS credit from one ACK, check window/option limits and failed-output rollback.
    //# (3.3) If (cwnd - pipe) >= 1 SMSS, there exists previously unsent data, and
    //# the receiver's advertised window allows, transmit up to 1 SMSS of data
    //# starting with the octet HighData+1 and update HighData to reflect this
    //# transmission, then return to (3.2).
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Event input returns; output is poll-driven and repeated evidence gives no extra credit.
    //# (3.4) Terminate processing of this ACK.
    fn sack_limited_transmit_requires_new_evidence_including_duplex_ack() {
        let (mut a, _) = pair(sack_config(128), 100);
        a.write(&[1; 1024]).unwrap();
        for now in 40..44 {
            packet(&mut a, now);
        }
        let una = a.snd_una;
        let end = a.snd_nxt;
        sack_ack(&mut a, 50, una, &[]);
        assert_eq!(a.transmit(51, &mut [0; 1024]), Ok(None));
        let next = a.receive.next();
        inject_sack(
            &mut a,
            52,
            next,
            una,
            ACK,
            8000,
            b"duplex",
            &[(una.wrapping_add(128).0, una.wrapping_add(256).0)],
        );
        assert_eq!(a.duplicate_acks, 1);
        let bytes = packet(&mut a, 53);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.sequence,
            end.0
        );
        assert_eq!(a.limited_sent, 128);
        sack_ack(
            &mut a,
            54,
            una,
            &[(una.wrapping_add(128).0, una.wrapping_add(256).0)],
        );
        assert_eq!(a.transmit(55, &mut [0; 1024]), Ok(None));
        sack_ack(
            &mut a,
            56,
            una,
            &[(una.wrapping_add(256).0, una.wrapping_add(384).0)],
        );
        packet(&mut a, 57);
        assert_eq!(a.limited_sent, 256);
        sack_ack(&mut a, 58, una, &[(una.wrapping_add(384).0, end.0)]);
        assert!(a.sack_recovery.is_some());
        assert_eq!(a.congestion.ssthresh(), 256); // Excludes 256 limited bytes.
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc2018#section-5.1
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Congestion controller halves eligible flight, excludes limited bytes and avoids duplicate ECN reductions. This cites integration, not all congestion-control recommendations.
    //# However, the congestion control algorithms present in the de facto standard
    //# TCP implementations MUST be preserved [Stevens94].
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Congestion on_sack_recovery sets cwnd=ssthresh=half eligible flight with RFC5681 minimum; outstanding limited bytes excluded even after partial ACK. ECN epoch guards prevent second reduction.
    //# (4.2) ssthresh = cwnd = (FlightSize / 2) The congestion window (cwnd) and
    //# slow start threshold (ssthresh) are reduced to half of FlightSize per
    //# [RFC5681]. Additionally, note that [RFC5681] requires that any segments sent
    //# as part of the Limited Transmit mechanism not be counted in FlightSize for
    //# the purpose of the above equation.
    fn sack_advancing_ack_keeps_unacked_limited_bytes_out_of_reduction() {
        let (mut a, _) = pair(sack_config(128), 100);
        a.write(&[1; 1024]).unwrap();
        for now in 40..44 {
            packet(&mut a, now);
        }
        let una = a.snd_una;
        sack_ack(
            &mut a,
            50,
            una,
            &[(una.wrapping_add(128).0, una.wrapping_add(256).0)],
        );
        packet(&mut a, 51);
        sack_ack(
            &mut a,
            52,
            una,
            &[(una.wrapping_add(256).0, una.wrapping_add(384).0)],
        );
        packet(&mut a, 53);
        assert_eq!(a.limited_sent, 256);
        let end = a.snd_nxt;
        sack_ack(
            &mut a,
            54,
            una.wrapping_add(64),
            &[(una.wrapping_add(128).0, end.0)],
        );
        assert!(a.sack_recovery.is_some());
        assert_eq!(a.limited_sent, 256);
        assert_eq!(a.congestion.ssthresh(), 256);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
    //= type=test
    //# RecoveryPoint MUST be set to HighData.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-5.1
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Timeout clears scoreboard and RTO sends left edge before acting on fresh SACKs. Implementation satisfies even the original stronger wording; verified erratum 1610 changes MUST to SHOULD, rejected erratum 6602 is not applied.
    //# Because the data receiver is allowed to discard SACKed data, when a
    //# retransmit timeout occurs the data sender MUST ignore prior SACK information
    //# in determining which data to retransmit.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Timeout clears advisory ranges; test observes full pipe after timeout.
    //# After a retransmit timeout the data sender SHOULD turn off all of the SACKed
    //# bits, since the timeout might indicate that the data receiver has reneged.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. sack_rto_discards_advice_retransmits_head_and_guards_epoch accepts a valid first SACK block covering snd_una through data_high before RTO, then verifies wire head sequence/payload and guard after timeout clears advice.
    //# The data sender MUST retransmit the segment at the left edge of the window
    //# after a retransmit timeout, whether or not the SACKed bit is on for that
    //# segment.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Clears prior advice and sends the head. Erratum 1610 permits a weaker SHOULD but implementation takes conservative clearing path.
    //# As a result, [RFC2018] suggests that a TCP sender SHOULD expunge the SACK
    //# information gathered from a receiver upon a retransmission timeout (RTO)
    //# "since the timeout might indicate that the data receiver has reneged."
    //# Additionally, a TCP sender MUST "ignore prior SACK information in
    //# determining which data to retransmit." However, since the publication of
    //# [RFC2018], this has come to be viewed by some as too strong.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Timeout replaces recovery with sack_guard=data_high; fresh SACKs cannot reenter until cumulative boundary is covered. Exclusive boundary equals RFC highest byte plus one.
    //# If an RTO occurs during loss recovery as specified in this document,
    //# RecoveryPoint MUST be set to HighData.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Timeout replaces recovery with sack_guard=data_high; fresh SACKs cannot reenter until cumulative boundary is covered. Exclusive boundary equals RFC highest byte plus one.
    //# Further, the new value of RecoveryPoint MUST be preserved and the loss
    //# recovery algorithm outlined in this document MUST be terminated.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Timeout replaces recovery with sack_guard=data_high; fresh SACKs cannot reenter until cumulative boundary is covered. Exclusive boundary equals RFC highest byte plus one.
    //# In addition, a new recovery phase (as described in Section 5) MUST NOT be
    //# initiated until HighACK is greater than or equal to the new value of
    //# RecoveryPoint.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-6
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Optional timer variant uses the shared successful-retransmission commit path. sack_multiloss_selective_recovery_and_transactional_entry asserts exact send_time+rto after both retransmissions, failed-output stability and nonadvancing-SACK nonrestart; sack_rto_discards_advice_retransmits_head_and_guards_epoch checks entry and expiry.
    //# Therefore, we give implementers the latitude to use the standard
    //# [RFC6298]-style RTO management or, optionally, a more careful variant that
    //# re-arms the RTO timer on each retransmission that is sent during recovery
    //# MAY be used.
    fn sack_rto_discards_advice_retransmits_head_and_guards_epoch() {
        let mut a = sack_flight(128, 100, 8);
        let una = a.snd_una;
        let point = a.data_high();
        sack_ack(&mut a, 200, una, &[(una.wrapping_add(128).0, point.0)]);
        let original_deadline = a.rto_deadline;
        assert_eq!(a.transmit(201, &mut [0; 8]), Err(Error::OutputTooSmall));
        assert_eq!(a.rto_deadline, original_deadline);
        packet(&mut a, 201);
        assert_eq!(a.rto_deadline, Some(201 + a.rto()));
        let deadline = a.rto_deadline.unwrap();
        sack_ack(&mut a, 202, una, &[(una.0, point.0)]);
        assert_eq!(a.scoreboard.ranges(), &[(una, point)]); // Valid first block covers snd_una.
        assert_eq!(a.snd_una, una);
        assert_eq!(a.rto_deadline, Some(deadline));
        a.timeout(deadline).unwrap();
        assert!(a.sack_recovery.is_none());
        assert_eq!(a.sack_guard, Some(point));
        assert_eq!(a.scoreboard.pipe(una, point, una, 128), 1024);
        assert!(a.sample.is_none());
        let bytes = packet(&mut a, deadline);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.header.sequence, una.0);
        assert_eq!(segment.payload, &[0x77; 128]);
        sack_ack(
            &mut a,
            deadline + 1,
            una,
            &[(una.wrapping_add(128).0, point.0)],
        );
        assert!(a.sack_recovery.is_none());
        assert_eq!(a.send.len(), 1024);
        sack_ack(&mut a, deadline + 2, point, &[]);
        assert!(a.sack_guard.is_none());
        assert_eq!(a.send.len(), 0);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Fresh post-RTO SACKs update scoreboard and select missing offset 256 without fast-recovery reentry.
    //# Further, a SACK TCP sender SHOULD utilize all SACK information made
    //# available during the loss recovery following an RTO.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Fresh post-RTO SACKs update scoreboard and select missing offset 256 without fast-recovery reentry.
    //# As described in Sections 4 and 5, Update () SHOULD continue to be used
    //# appropriately upon receipt of ACKs.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Fresh post-RTO SACKs update scoreboard and select missing offset 256 without fast-recovery reentry.
    //# In this case, a TCP sender SHOULD use this SACK information when determining
    //# what data should be sent in each segment following an RTO.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5.1
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Post-RTO selection fills fresh holes without the normal fast-recovery NextSeg priorities/rescue and stays guarded until old flight is cumulatively covered.
    //# The exact algorithm for this selection is not specified in this document
    //# (specifically NextSeg () is inappropriate during loss recovery after an
    //# RTO).
    fn sack_after_rto_uses_fresh_holes_without_reentering_recovery() {
        let mut a = sack_flight(128, 100, 8);
        let una = a.snd_una;
        let point = a.data_high();
        let deadline = a.rto_deadline.unwrap();
        a.timeout(deadline).unwrap();
        let bytes = packet(&mut a, deadline);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.header.sequence, una.0);
        assert_eq!(segment.payload, &[0x77; 128]);
        sack_ack(
            &mut a,
            deadline + 1,
            una.wrapping_add(256),
            &[(una.wrapping_add(384).0, point.0)],
        );
        assert!(a.sack_recovery.is_none());
        assert_eq!(a.sack_guard, Some(point));
        let bytes = packet(&mut a, deadline + 2);
        let seg = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(seg.header.sequence, una.wrapping_add(256).0);
        assert_eq!(seg.payload.len(), 128);
        assert_eq!(a.transmit(deadline + 3, &mut [0; 1024]), Ok(None));
        sack_ack(&mut a, deadline + 4, point, &[]);
        assert!(a.sack_post_rto.is_none());
    }

    #[test]
    fn sack_sender_overflow_cumulative_only_until_flight_covered() {
        let mut a = sack_flight(128, 100, 8);
        let una = a.snd_una;
        let end = a.data_high();
        for i in 0..65 {
            sack_ack(
                &mut a,
                200 + i as u64,
                una,
                &[(una.wrapping_add(2 * i + 1).0, una.wrapping_add(2 * i + 2).0)],
            );
        }
        assert_eq!(a.sack_fallback, Some(end));
        assert!(a.sack_recovery.is_none());
        assert_eq!(a.scoreboard.pipe(una, end, una, 128), 1024);
        for now in 300..305 {
            sack_ack(&mut a, now, una, &[(una.wrapping_add(128).0, end.0)]);
        }
        assert_eq!(a.scoreboard.pipe(una, end, una, 128), 1024);
        assert!(a.sack_recovery.is_none());
        sack_ack(&mut a, 310, end, &[]);
        assert!(a.sack_fallback.is_none());
        assert!(a.sack_guard.is_none());
    }

    #[test]
    fn sack_receiver_cap_rejection_sends_only_cumulative_ack() {
        let (mut a, _) = pair(sack_config(128), 100);
        let next = a.receive.next();
        let una = a.snd_una;
        for i in 0..64 {
            inject_sack(
                &mut a,
                40 + i as u64,
                next.wrapping_add(2 * i + 1),
                una,
                ACK,
                8192,
                &[1],
                &[],
            );
            packet(&mut a, 40 + i as u64);
        }
        inject_sack(
            &mut a,
            110,
            next.wrapping_add(201),
            una,
            ACK,
            8192,
            &[2],
            &[],
        );
        assert!(a.sack_omit);
        assert_eq!(a.transmit(111, &mut [0; 8]), Err(Error::OutputTooSmall));
        assert!(a.sack_omit);
        let bytes = packet(&mut a, 111);
        let ack = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(ack.header.acknowledgment, next.0);
        assert!(ack.options.sack_blocks.iter().all(Option::is_none));
        inject_sack(&mut a, 112, next, una, ACK, 8192, &[3; 128], &[]);
        let bytes = packet(&mut a, 113);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes)
                .unwrap()
                .header
                .acknowledgment,
            next.wrapping_add(128).0
        );
        assert_eq!(a.read(&mut [0; 128]), Ok(128));
        assert_eq!(a.read(&mut [0; 1]), Err(Error::WouldBlock));
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= type=test
    //= reason=Together with multiloss and speculative/rescue tests, checks the selected sequence ranges and NextSeg priorities.
    //# NextSeg () MUST return the
    //# sequence number range of the next segment that is to be
    //# transmitted, per the following rules:
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= type=test
    //= reason=Negotiated non-RACK/non-PRR SACK; full-budget and piggybacked-SACK regressions exercise lost/new/speculative/rescue priority. IsLost uses SMSS independently of output clipping; markers commit only after encoding.
    //# NextSeg () MUST return the sequence number range of the next segment that is
    //# to be transmitted, per the following rules:
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= type=test
    //= reason=Negotiated non-RACK/non-PRR SACK; full-budget and budget-116 tests send fresh data before nonlost holes and keep RecoveryPoint fixed.
    //# (2) If no sequence number 'S2' per rule (1) exists but there exists
    //# available unsent data and the receiver's advertised window allows, the
    //# sequence range of one segment of up to SMSS octets of previously unsent data
    //# starting with sequence number HighData+1 MUST be returned.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated non-RACK/non-PRR SACK; active recovery polls consume pipe/cwnd credit and stop below SMSS; separate limited-transmit regression checks the pre-recovery loop.
    //# (C) If cwnd - pipe >= 1 SMSS, the sender SHOULD transmit one or more
    //# segments as follows:
    //= https://www.rfc-editor.org/rfc/rfc6675#section-2
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. data_high is the exclusive transmitted data edge; new output advances snd_nxt but excludes FIN.
    //# "HighData" is the highest sequence number transmitted at a given point.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-2
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Recovery pipe bounds output; independent scoreboard per-byte oracle checks computation.
    //# "Pipe" is a sender's estimate of the number of bytes outstanding in the
    //# network. This is used during recovery for limiting the sender's sending
    //# rate. The pipe variable allows TCP to use fundamentally different congestion
    //# control than the algorithm specified in [RFC5681]. The congestion control
    //# algorithm using the pipe estimate is often referred to as the "pipe
    //# algorithm".
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Poll-driven output continues recovery candidates until cwnd credit exhausted.
    //# (4.5) In order to take advantage of potential additional available cwnd,
    //# proceed to step (C) below.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. ACK below recovery boundary recomputes pipe; test gains credit after partial ACK then sends new data.
    //# (B.2) Use SetPipe () to re-calculate the number of octets still in the
    //# network.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Successful new data advances exclusive snd_nxt; test checks one-SMSS advance while recovery point remains fixed.
    //# (C.3) If any of the data octets sent in (C.1) are above HighData, HighData
    //# must be updated to reflect the transmission of previously unsent data.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Non-RACK pipe increments by actual successfully encoded bytes; test fills pipe exactly to cwnd and denies next poll.
    //# (C.4) The estimate of the amount of data outstanding in the network must be
    //# updated by incrementing pipe by the number of octets transmitted in (C.1).
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. One segment per output poll; successive polls select ranges until credit less than SMSS, equivalent to loop.
    //# (C.5) If cwnd - pipe >= 1 SMSS, return to (C.1)
    fn sack_nextseg_new_data_precedes_speculative_holes_and_bounds_pipe() {
        let mut a = sack_flight(128, 100, 12);
        let una = a.snd_una;
        let point = a.data_high();
        let ranges = [
            (una.wrapping_add(128).0, una.wrapping_add(256).0),
            (una.wrapping_add(512).0, una.wrapping_add(1152).0),
        ];
        a.write(&[9; 128]).unwrap();
        sack_ack(&mut a, 200, una, &ranges);
        for (now, offset) in [(201, 0), (202, 256), (203, 384)] {
            let bytes = packet(&mut a, now);
            assert_eq!(
                wire::parse(ip(tuple()), &bytes).unwrap().header.sequence,
                una.wrapping_add(offset).0
            );
        }
        assert_eq!(a.sack_recovery.unwrap().pipe, a.congestion.cwnd());
        assert_eq!(a.transmit(204, &mut [0; 1024]), Ok(None));
        sack_ack(&mut a, 210, una.wrapping_add(256), &ranges[1..]);
        let bytes = packet(&mut a, 211);
        let seg = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(seg.header.sequence, point.0); // Rule 2 before rule 3.
        assert_eq!(seg.payload, &[9; 128]);
        assert_eq!(a.sack_recovery.unwrap().recovery_point, point);
        assert_eq!(a.snd_nxt, point.wrapping_add(128));
        assert_eq!(a.transmit(212, &mut [0; 1024]), Ok(None));
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= type=test
    //= reason=Negotiated non-RACK/non-PRR SACK; full-budget and piggybacked-SACK regressions exercise lost/new/speculative/rescue priority. IsLost uses SMSS independently of output clipping; markers commit only after encoding.
    //# NextSeg () MUST return the
    //# sequence number range of the next segment that is to be
    //# transmitted, per the following rules:
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. With no new/lost segment, speculative offset 768 is sent before tail rescue, then high_rxt advances.
    //# (3) If the conditions for rules (1) and (2) fail, but there exists an
    //# unSACKed sequence number 'S3' that meets the criteria for detecting loss
    //# given in steps (1.a) and (1.b) above (specifically excluding step (1.c)),
    //# then one segment of up to SMSS octets starting with S3 SHOULD be returned.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Rescue contains the highest outstanding unsacked byte; success sets RescueRxt to fixed recovery boundary, retry does not consume it and a second rescue is denied.
    //# If HighACK is greater than RescueRxt (or RescueRxt is undefined), then one
    //# segment of up to SMSS octets that MUST include the highest outstanding
    //# unSACKed sequence number SHOULD be returned, and RescueRxt set to
    //# RecoveryPoint.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-4
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Rescue leaves high_rxt unchanged, explicitly asserted.
    //# HighRxt MUST NOT be updated.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Successful nonrescue output advances high_rxt; rescue explicitly leaves it unchanged; failed encode does not commit either.
    //# (C.2) If any of the data octets sent in (C.1) are below HighData, HighRxt
    //# MUST be set to the highest sequence number of the retransmitted segment
    //# unless NextSeg () rule (4) was invoked for this retransmission.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-9
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Section 9 restates rule (3), not a new algorithm; speculative retransmission is selected and asserted before rescue.
    //# Rule (3) of NextSeg() has been changed from MAY to SHOULD, to appropriately
    //# reflect the opinion of the authors and working group that it should be left
    //# in, rather than out, if an implementor does not have a compelling reason to
    //# do otherwise.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-2
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. high_rxt is exclusive; only successful nonrescue retransmissions advance it.
    //# "HighRxt" is the highest sequence number which has been retransmitted during
    //# the current loss recovery phase.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-2
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. rescue_rxt grants a single tail retransmission and tracks recovery boundary after success.
    //# "RescueRxt" is the highest sequence number which has been optimistically
    //# retransmitted to prevent stalling of the ACK clock when there is loss at the
    //# end of the window and no new data is available for transmission.
    fn sack_nextseg_speculative_then_single_transactional_tail_rescue() {
        for speculative in [false, true] {
            let mut a = sack_flight(128, 100, 8);
            let una = a.snd_una;
            let point = a.data_high();
            let ranges = [
                (una.wrapping_add(128).0, una.wrapping_add(256).0),
                (una.wrapping_add(384).0, una.wrapping_add(768).0),
            ];
            sack_ack(&mut a, 200, una, &ranges);
            packet(&mut a, 201);
            packet(&mut a, 202);
            assert_eq!(a.transmit(203, &mut [0; 1024]), Ok(None));
            let blocks = if speculative {
                &[(una.wrapping_add(896).0, point.0)][..]
            } else {
                &[][..]
            };
            sack_ack(&mut a, 210, una.wrapping_add(384), blocks);
            if speculative {
                let bytes = packet(&mut a, 211);
                let seg = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(seg.header.sequence, una.wrapping_add(768).0); // Rule 3.
                assert_eq!(seg.payload.len(), 128);
                assert_eq!(a.sack_recovery.unwrap().high_rxt, una.wrapping_add(896));
            }
            let old = a.sack_recovery.unwrap();
            assert_eq!(a.transmit(212, &mut [0; 8]), Err(Error::OutputTooSmall));
            assert_eq!(a.sack_recovery.unwrap().rescue_rxt, old.rescue_rxt);
            assert_eq!(a.sack_recovery.unwrap().pipe, old.pipe);
            let bytes = packet(&mut a, 212);
            let rescue = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(
                rescue.header.sequence,
                una.wrapping_add(if speculative { 768 } else { 896 }).0
            );
            assert_eq!(rescue.payload.len(), 128);
            assert_eq!(a.sack_recovery.unwrap().high_rxt, old.high_rxt);
            assert_eq!(a.sack_recovery.unwrap().rescue_rxt, Some(point));
            assert_eq!(a.transmit(213, &mut [0; 1024]), Ok(None));
            // More credit and identical SACK cannot grant another rescue.
            sack_ack(&mut a, 214, una.wrapping_add(512), &[]);
            assert_eq!(a.transmit(215, &mut [0; 1024]), Ok(None));
        }
    }

    #[test]
    fn sack_fin_is_not_scoreboard_data_and_remains_rto_retransmittable() {
        let mut a = sack_flight(128, 100, 8);
        a.shutdown().unwrap();
        let bytes = packet(&mut a, 150);
        let fin = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(fin.header.flags & FIN, FIN);
        assert!(fin.payload.is_empty());
        let una = a.snd_una;
        let data_end = a.fin_sequence.unwrap();
        sack_ack(
            &mut a,
            200,
            una,
            &[(una.wrapping_add(128).0, data_end.wrapping_add(1).0)],
        );
        assert!(a.sack_recovery.is_none()); // A block including FIN is invalid.
        sack_ack(&mut a, 201, una, &[(una.wrapping_add(128).0, data_end.0)]);
        assert_eq!(a.sack_recovery.unwrap().recovery_point, data_end);
        let bytes = packet(&mut a, 202);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.flags & FIN,
            0
        );
        sack_ack(&mut a, 203, data_end, &[]);
        assert!(a.sack_recovery.is_none());
        assert_eq!(a.send.len(), 0);
        assert_eq!(a.flight(), 1);
        // FIN-only SACK reports cannot start data recovery.
        for now in 204..208 {
            sack_ack(
                &mut a,
                now,
                data_end,
                &[(data_end.0, data_end.wrapping_add(1).0)],
            );
        }
        assert!(a.sack_recovery.is_none());
        let deadline = a.rto_deadline.unwrap();
        a.timeout(deadline).unwrap();
        let bytes = packet(&mut a, deadline);
        let fin = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(fin.header.sequence, data_end.0);
        assert_eq!(fin.header.flags & FIN, FIN);
        sack_ack(&mut a, deadline + 1, data_end.wrapping_add(1), &[]);
        assert_eq!(a.state, State::FinWait2);
    }

    #[test]
    fn sack_ecn_shares_reduction_but_preserves_loss_retransmit() {
        let mut a = sack_flight(128, 100, 8);
        let una = a.snd_una;
        let point = a.data_high();
        let next = a.receive.next();
        inject_sack(
            &mut a,
            200,
            next,
            una,
            ACK | ECE,
            8192,
            &[],
            &[(una.wrapping_add(128).0, point.0)],
        );
        assert!(a.sack_recovery.is_some());
        assert_eq!(a.congestion.ssthresh(), 512);
        assert_eq!(a.congestion.cwnd(), 512);
        assert!(a.ecn_cwr_pending);
        let bytes = packet(&mut a, 201);
        let seg = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(seg.header.sequence, una.0);
        assert_eq!(seg.header.flags & CWR, 0);
        assert_eq!(a.last_output_ecn(), 0);
        assert!(a.ecn_cwr_pending);
        inject_sack(
            &mut a,
            202,
            next,
            una,
            ACK | ECE,
            8192,
            &[],
            &[(una.wrapping_add(128).0, point.0)],
        );
        assert_eq!(a.congestion.cwnd(), 512);
        assert_eq!(a.transmit(203, &mut [0; 1024]), Ok(None));
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Cumulative ACK resets duplicate counter before new SACK evidence increments it; test explicitly observes count one after advancing ACK.
    //# If the incoming ACK is a cumulative acknowledgment, the TCP MUST reset
    //# DupAcks to zero.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Recovery ACK processing updates scoreboard/pipe and exits on boundary; partial cumulative ACK keeps recovery active without cwnd growth.
    //# Once a TCP is in the loss recovery phase, the following procedure MUST be
    //# used for each arriving ACK:
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. ACK below recovery boundary updates scoreboard and recomputes recovery.pipe; partial ACK remains in recovery.
    //# (B) Upon receipt of an ACK that does not cover RecoveryPoint, the following
    //# actions MUST be taken:
    //= https://www.rfc-editor.org/rfc/rfc6675#section-2
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. snd_una is the exclusive cumulative edge, equivalent to HighACK+1.
    //# "HighACK" is the sequence number of the highest byte of data that has been
    //# cumulatively ACKed at a given point.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-2
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. duplicate_acks resets on cumulative ACK and increments on new delivery evidence.
    //# "DupAcks" is the number of duplicate acknowledgments received since the last
    //# cumulative acknowledgment.
    //= https://www.rfc-editor.org/rfc/rfc6675#section-2
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Advancing ACK with new SACK evidence remains counted as one duplicate after reset.
    //# For the purposes of this specification, we define a "duplicate
    //# acknowledgment" as a segment that arrives carrying a SACK block that
    //# identifies previously unacknowledged and un-SACKed octets between HighACK
    //# and HighData. Note that an ACK which carries new SACK data is counted as a
    //# duplicate acknowledgment under this definition even if it carries new data,
    //# changes the advertised window, or moves the cumulative acknowledgment point,
    //# which is different from the definition of duplicate acknowledgment in
    //# [RFC5681].
    //= https://www.rfc-editor.org/rfc/rfc6675#section-5
    //= type=test
    //= reason=Negotiated SACK; RFC 6675 algorithm evidence is for rack=false, prr=false. Every valid recovery ACK records SACK union before cumulative ACK and recovery state processing.
    //# (B.1) Use Update () to record the new SACK information conveyed by the
    //# incoming ACK.
    fn sack_advancing_ack_resets_count_before_new_evidence_and_partial_cwnd() {
        let mut a = sack_flight(128, 100, 8);
        let una = a.snd_una;
        sack_ack(
            &mut a,
            200,
            una,
            &[(una.wrapping_add(128).0, una.wrapping_add(256).0)],
        );
        assert_eq!(a.duplicate_acks, 1);
        sack_ack(
            &mut a,
            201,
            una.wrapping_add(17),
            &[(una.wrapping_add(256).0, una.wrapping_add(384).0)],
        );
        assert_eq!(a.duplicate_acks, 1);
        sack_ack(
            &mut a,
            202,
            una.wrapping_add(17),
            &[(una.wrapping_add(384).0, una.wrapping_add(512).0)],
        );
        assert!(a.sack_recovery.is_some());
        let cwnd = a.congestion.cwnd();
        packet(&mut a, 203);
        sack_ack(&mut a, 204, una.wrapping_add(30), &[]);
        assert_eq!(a.congestion.cwnd(), cwnd);
        assert!(a.sack_recovery.is_some());
    }

    #[test]
    fn sack_three_blocks_with_timestamps_fit_data_mss_and_path() {
        let cfg = ConnectionConfig {
            timestamps: true,
            send_ip_payload_limit: 148,
            ..sack_config(128)
        };
        let (mut a, _) = pair(cfg, 100);
        let next = a.receive.next();
        let una = a.snd_una;
        for offset in [10, 30, 50] {
            inject_sack(
                &mut a,
                40,
                next.wrapping_add(offset),
                una,
                ACK,
                8192,
                &[2; 5],
                &[],
            );
        }
        a.write(&[7; 128]).unwrap();
        let before = (a.now, a.snd_nxt, a.last_timestamp_sent_at, a.ack_pending);
        assert_eq!(a.transmit(1_000, &mut [0; 147]), Err(Error::OutputTooSmall));
        assert_eq!(
            (a.now, a.snd_nxt, a.last_timestamp_sent_at, a.ack_pending),
            before
        );
        let bytes = packet(&mut a, 1_000);
        let data = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(bytes.len(), 148);
        assert_eq!(data.raw_options.len(), 40);
        assert_eq!(
            &data.raw_options[..12],
            &[1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0]
        );
        assert_eq!(&data.raw_options[12..16], &[1, 1, 5, 26]);
        assert_eq!(
            data.options.sack_blocks[..3],
            [
                Some((next.wrapping_add(50).0, next.wrapping_add(55).0)),
                Some((next.wrapping_add(30).0, next.wrapping_add(35).0)),
                Some((next.wrapping_add(10).0, next.wrapping_add(15).0)),
            ]
        );
        assert_eq!(data.payload, &[7; 88]);
        assert_eq!(data.payload.len() + data.raw_options.len(), 128);
    }

    #[test]
    fn sack_small_mss_ack_report_does_not_starve_data() {
        for (mss, timestamps) in [(8, false), (24, true)] {
            let cfg = ConnectionConfig {
                timestamps,
                ..sack_config(mss)
            };
            let (mut a, _) = pair(cfg, 100);
            let next = a.receive.next();
            let una = a.snd_una;
            inject_sack(
                &mut a,
                40,
                next.wrapping_add(10),
                una,
                ACK,
                8192,
                &[2; 5],
                &[],
            );
            a.write(&[1; 8]).unwrap();
            assert_eq!(a.transmit(41, &mut [0; 20]), Err(Error::OutputTooSmall));
            let bytes = packet(&mut a, 41);
            let seg = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(
                seg.options.sack_blocks[0],
                Some((next.wrapping_add(10).0, next.wrapping_add(15).0))
            );
            assert!(seg.payload.is_empty());
            let bytes = packet(&mut a, 42);
            let seg = wire::parse(ip(tuple()), &bytes).unwrap();
            assert!(!seg.payload.is_empty());
            assert!(seg.payload.len() + seg.raw_options.len() <= mss as usize);
        }
    }

    #[test]
    fn sack_only_ack_preserves_pending_rto_retransmission() {
        for (mss, timestamps) in [(8, false), (24, true)] {
            let cfg = ConnectionConfig {
                timestamps,
                ..sack_config(mss)
            };
            let (mut a, _) = pair(cfg, 100);
            let una = a.snd_una;
            a.write(&[7; 8]).unwrap();
            let sent = packet(&mut a, 40);
            assert_eq!(wire::parse(ip(tuple()), &sent).unwrap().payload, &[7; 8]);
            let timeout = a.rto_deadline.unwrap();
            a.timeout(timeout).unwrap();
            assert!(a.retx_pending);
            let next = a.receive.next();
            inject_sack(
                &mut a,
                timeout,
                next.wrapping_add(10),
                una,
                ACK,
                8192,
                &[2; 5],
                &[],
            );
            assert_eq!(
                a.transmit(timeout, &mut [0; 20]),
                Err(Error::OutputTooSmall)
            );
            assert!(a.retx_pending);
            let bytes = packet(&mut a, timeout);
            let seg = wire::parse(ip(tuple()), &bytes).unwrap();
            assert!(seg.payload.is_empty());
            assert!(seg.options.sack_blocks[0].is_some());
            assert!(a.retx_pending);
            let bytes = packet(&mut a, timeout);
            let seg = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(seg.header.sequence, una.0);
            assert_eq!(seg.payload, &[7; 8]);
            assert!(!a.retx_pending);
        }
    }

    #[test]
    fn sack_options_leave_path_space_for_probe_and_keepalive_octets() {
        for timestamps in [false, true] {
            for probing in [false, true] {
                let limit = if timestamps { 40 } else { 32 };
                let cfg = ConnectionConfig {
                    timestamps,
                    send_ip_payload_limit: limit,
                    keepalive: Some(KeepaliveConfig {
                        idle_us: 100_000,
                        interval_us: 100_000,
                        probes: 3,
                        send_garbage: true,
                    }),
                    ..sack_config(64)
                };
                let (mut a, _) = pair(cfg, 100);
                if probing {
                    a.write(&[7; 3]).unwrap();
                    packet(&mut a, 40);
                }
                let next = a.receive.next();
                let una = a.snd_una;
                inject_sack(
                    &mut a,
                    41,
                    next.wrapping_add(10),
                    una,
                    ACK,
                    if probing { 0 } else { 8192 },
                    &[2; 5],
                    &[],
                );
                let deadline = if probing {
                    a.persist_deadline
                } else {
                    a.keepalive_deadline
                }
                .unwrap();
                a.timeout(deadline).unwrap();
                assert!(if probing {
                    a.probe_pending
                } else {
                    a.keepalive_pending
                });
                let bytes = packet(&mut a, deadline);
                assert!(bytes.len() <= limit as usize);
                assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload.len(), 1);
            }
        }
    }

    #[test]
    fn sack_rescue_waits_for_tail_to_fit_reopened_window() {
        let mut a = sack_flight(128, 100, 8);
        let una = a.snd_una;
        let ranges = [
            (una.wrapping_add(128).0, una.wrapping_add(256).0),
            (una.wrapping_add(384).0, una.wrapping_add(768).0),
        ];
        sack_ack(&mut a, 200, una, &ranges);
        for (now, offset) in [(201, 0), (202, 256)] {
            let bytes = packet(&mut a, now);
            assert_eq!(
                wire::parse(ip(tuple()), &bytes).unwrap().header.sequence,
                una.wrapping_add(offset).0
            );
        }
        let next = a.receive.next();
        inject_sack(&mut a, 210, next, una.wrapping_add(384), ACK, 576, &[], &[]);
        let old = a.sack_recovery.unwrap().rescue_rxt;
        assert_eq!(a.transmit(211, &mut [0; 1024]), Ok(None));
        assert_eq!(a.sack_recovery.unwrap().rescue_rxt, old);
        inject_sack(
            &mut a,
            212,
            next,
            una.wrapping_add(384),
            ACK,
            8192,
            &[],
            &[],
        );
        let bytes = packet(&mut a, 213);
        let seg = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(seg.header.sequence, una.wrapping_add(896).0);
        assert_eq!(seg.payload.len(), 128);
        assert_eq!(
            a.sack_recovery.unwrap().rescue_rxt,
            Some(una.wrapping_add(1024))
        );
    }

    #[test]
    fn sack_post_rto_alternating_losses_fill_cwnd_with_retransmissions() {
        let mut a = sack_flight(128, 100, 8);
        let una = a.snd_una;
        let point = a.data_high();
        let deadline = a.rto_deadline.unwrap();
        a.timeout(deadline).unwrap();
        packet(&mut a, deadline);
        let ranges = [(384, 512), (640, 768), (896, 1024)]
            .map(|(l, r)| (una.wrapping_add(l).0, una.wrapping_add(r).0));
        sack_ack(&mut a, deadline + 1, una.wrapping_add(256), &ranges);
        assert_eq!(a.congestion.cwnd(), 256);
        for (time, offset) in [(2, 256), (3, 512)] {
            let bytes = packet(&mut a, deadline + time);
            let seg = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(seg.header.sequence, una.wrapping_add(offset).0);
            assert_eq!(seg.payload.len(), 128);
        }
        assert_eq!(a.transmit(deadline + 4, &mut [0; 1024]), Ok(None));
        assert_eq!(a.sack_guard, Some(point));
        assert!(a.sack_recovery.is_none());
        assert_eq!(a.send.len(), 768);
        assert!(a.sample.is_none());

        // New data consumes this slow-start window too, using the fixed RTO
        // snapshot rather than the advancing HighData as its lower boundary.
        a.write(&[9; 256]).unwrap();
        sack_ack(&mut a, deadline + 5, una.wrapping_add(768), &ranges[2..]);
        assert_eq!(a.congestion.cwnd(), 384);
        for (time, offset) in [(6, 768), (7, 1024), (8, 1152)] {
            let bytes = packet(&mut a, deadline + time);
            let seg = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(seg.header.sequence, una.wrapping_add(offset).0);
            assert_eq!(seg.payload.len(), 128);
        }
        assert_eq!(a.post_rto_pipe(), 384);
        assert_eq!(a.transmit(deadline + 9, &mut [0; 1024]), Ok(None));
        sack_ack(&mut a, deadline + 10, point, &[]);
        assert!(a.sack_post_rto.is_none());
    }

    #[test]
    fn sack_fin_only_input_clears_previous_batched_dsack() {
        let (mut a, _) = pair(sack_config(128), 100);
        let next = a.receive.next();
        let una = a.snd_una;
        inject_sack(
            &mut a,
            40,
            next.wrapping_add(10),
            una,
            ACK,
            8192,
            &[1; 10],
            &[],
        );
        inject_sack(
            &mut a,
            41,
            next.wrapping_add(12),
            una,
            ACK,
            8192,
            &[1; 3],
            &[],
        );
        inject_sack(
            &mut a,
            42,
            next.wrapping_add(30),
            una,
            ACK | FIN,
            8192,
            &[],
            &[],
        );
        let bytes = packet(&mut a, 43);
        let seg = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(
            seg.options.sack_blocks[0],
            Some((next.wrapping_add(10).0, next.wrapping_add(20).0))
        );
        assert!(seg.options.sack_blocks[1].is_none());
    }

    #[test]
    fn sack_tiny_mss_option_budget_and_shrink_remain_safe() {
        for mss in [1, 4, 12, 13] {
            let (mut a, _) = pair(sack_config(mss), 100);
            let una = a.snd_una;
            let next = a.receive.next();
            inject_sack(&mut a, 40, next.wrapping_add(4), una, ACK, 8192, &[2], &[]);
            a.write(&[1; 20]).unwrap();
            let bytes = packet(&mut a, 41);
            let seg = wire::parse(ip(tuple()), &bytes).unwrap();
            assert!(seg.payload.len() <= mss as usize);
            assert!(seg.options.sack_blocks.iter().flatten().count() <= 1);
        }
        let mut a = sack_flight(128, 100, 8);
        let una = a.snd_una;
        let end = a.data_high();
        sack_ack(&mut a, 200, una, &[(una.wrapping_add(128).0, end.0)]);
        let next = a.receive.next();
        inject_sack(&mut a, 201, next, una, ACK, 7, &[], &[]);
        let bytes = packet(&mut a, 202);
        assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload.len(), 7);
        assert!(!a.sack_recovery.unwrap().entry_pending);
        a.lower_mss(32).unwrap();
        assert_eq!(a.mss, 32);
        assert!(a.rto_deadline.is_some());
    }

    #[test]
    fn sack_future_ack_and_paws_cannot_forge_old_duplicate_evidence() {
        let cfg = ConnectionConfig {
            timestamps: true,
            ..sack_config(128)
        };
        let (mut a, mut b) = pair(cfg, 100);
        a.write(&[1; 20]).unwrap();
        let bytes = deliver(&mut a, &mut b, 2_000);
        deliver(&mut b, &mut a, 3_000);
        b.read(&mut [0; 20]).unwrap();
        let old = wire::parse(ip(tuple()), &bytes).unwrap();
        let next = Seq(old.header.sequence);
        let future = b.snd_nxt.wrapping_add(1);
        inject_sack(&mut b, 4_000, next, future, ACK, 8192, &[1; 20], &[]);
        let bytes = packet(&mut b, 4_000);
        assert!(
            wire::parse(ip(reverse(tuple())), &bytes)
                .unwrap()
                .options
                .sack_blocks
                .iter()
                .all(Option::is_none)
        );
        // Old timestamp is rejected before recording a duplicate.
        b.ts_recent = 100;
        b.ts_recent_at = 4_000;
        b.input(5_000, &old).unwrap();
        let bytes = packet(&mut b, 5_000);
        assert!(
            wire::parse(ip(reverse(tuple())), &bytes)
                .unwrap()
                .options
                .sack_blocks
                .iter()
                .all(Option::is_none)
        );
    }

    #[test]
    fn sack_seeded_lossy_reordered_duplex_delivers_and_closes() {
        for seed in [1u64, 17, 0xdead_beef] {
            let (mut a, mut b) = pair(sack_config(128), u32::MAX - 200);
            let left: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
            let right: Vec<u8> = (0..3072).map(|i| (i % 239) as u8).collect();
            a.write(&left).unwrap();
            b.write(&right).unwrap();
            a.shutdown().unwrap();
            b.shutdown().unwrap();
            let mut a_read = vec![];
            let mut b_read = vec![];
            let mut pending: Vec<(bool, Vec<u8>)> = vec![];
            let mut random = seed;
            let mut scratch = [0; 2048];
            for tick in 1..20_000 {
                let now = 100 + tick * 10_000;
                for (direction, conn) in [(true, &mut a), (false, &mut b)] {
                    if conn.next_deadline().is_some_and(|deadline| now >= deadline) {
                        conn.timeout(now).unwrap();
                    }
                    for _ in 0..8 {
                        if let Some(len) = conn.transmit(now, &mut scratch).unwrap() {
                            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
                            if random % 7 != 0 {
                                pending.push((direction, scratch[..len].to_vec()));
                            }
                        } else {
                            break;
                        }
                    }
                }
                // Retain some packets and select the rest out of order.
                for _ in 0..4 {
                    if pending.is_empty() {
                        break;
                    }
                    random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
                    let index = random as usize % pending.len();
                    let (direction, bytes) = pending.swap_remove(index);
                    let (sender, receiver) = if direction {
                        (tuple(), &mut b)
                    } else {
                        (reverse(tuple()), &mut a)
                    };
                    receiver
                        .input(now, &wire::parse(ip(sender), &bytes).unwrap())
                        .unwrap();
                }
                for (conn, received) in [(&mut a, &mut a_read), (&mut b, &mut b_read)] {
                    while let Ok(count) = conn.read(&mut scratch) {
                        if count == 0 {
                            break;
                        }
                        received.extend_from_slice(&scratch[..count]);
                    }
                }
                if a_read == right && b_read == left && a.flight() == 0 && b.flight() == 0 {
                    break;
                }
            }
            assert_eq!(a_read, right, "seed={seed}");
            assert_eq!(b_read, left, "seed={seed}");
            assert_eq!((a.flight(), b.flight()), (0, 0));
            assert!(matches!(a.state, State::TimeWait | State::Closed));
            assert!(matches!(b.state, State::TimeWait | State::Closed));
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.2
    //= type=test
    //# Queue the data for transmission after entering ESTABLISHED state.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.2
    //= type=test
    //= reason=Handshake SEND queue; focused send_state_matrix_preserves_queue_on_rejection additionally tests exhaustion.
    //# Queue the data for transmission after entering ESTABLISHED state. If no space to queue,
    //# respond with "error: insufficient resources".
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.1
    //= type=test
    //= reason=ISS/ISS+1 are checked on committed SYN output; active API enqueues SYN and driver polls, rather than emitting inline.
    //# A SYN segment of the form <SEQ=ISS><CTL=SYN> is sent. Set SND.UNA to ISS, SND.NXT to
    //# ISS+1, enter SYN-SENT state, and return.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.2
    //= type=test
    //= reason=Passive constructor consumes SYN sequence, learns peer, and schedules SYN-ACK. SYN text buffering/delivery scope separately cited.
    //# Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ, and any other control or text should be
    //# queued for processing later. ISS should be selected and a SYN segment sent of the form:
    //# <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.2
    //= type=test
    //= reason=Passive state is SYN-RECEIVED; transmit commits ISS+1 only after SYN-ACK encoding succeeds.
    //# SND.NXT is set to ISS+1 and SND.UNA to ISS. The connection state should be changed to
    //# SYN-RECEIVED.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
    //= type=test
    //= reason=SYN-ACK establishes active side and schedules ACK, which may carry queued data; no inline output.
    //# If SND.UNA > ISS (our SYN has been ACKed), change the connection state to ESTABLISHED,
    //# form an ACK segment <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
    fn handshake_queues_sends_until_established() {
        let cfg = config(64, 8);
        let mut a = Connection::active(tuple(), cfg.clone(), 100, 0).unwrap();
        assert_eq!(a.write(b"active"), Ok(6));
        let bytes = packet(&mut a, 0);
        let syn = wire::parse(ip(tuple()), &bytes).unwrap();
        assert!(syn.payload.is_empty());
        assert_eq!(a.state(), State::SynSent);
        assert_eq!(a.snd_nxt, Seq(101));
        assert_eq!(a.snd_una, Seq(100));
        assert_eq!(syn.header.flags & (SYN | ACK), SYN);
        assert_eq!(syn.header.sequence, 100);
        assert_eq!(a.transmit(1, &mut [0; 64]), Ok(None));
        let mut b = Connection::passive(reverse(tuple()), cfg, 900, 10, &syn).unwrap();
        assert_eq!(b.write(b"passive"), Ok(7));
        assert_eq!(b.irs, Some(Seq(100)));
        assert_eq!(b.receive.next(), Seq(101));
        assert_eq!(b.snd_una, Seq(900));
        let bytes = deliver(&mut b, &mut a, 20);
        let synack = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
        assert_eq!(synack.header.flags & (SYN | ACK), SYN | ACK);
        assert_eq!(synack.header.sequence, 900);
        assert_eq!(synack.header.acknowledgment, 101);
        assert!(
            wire::parse(ip(reverse(tuple())), &bytes)
                .unwrap()
                .payload
                .is_empty()
        );
        assert_eq!(b.state(), State::SynReceived);
        assert_eq!(b.snd_nxt, Seq(901));
        assert_eq!(b.transmit(21, &mut [0; 64]), Ok(None));
        assert_eq!(a.state(), State::Established);
        assert_eq!(a.snd_una, Seq(101));
        let bytes = deliver(&mut a, &mut b, 30);
        let final_ack = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(final_ack.header.flags & (SYN | ACK), ACK);
        assert_eq!(final_ack.header.sequence, 101);
        assert_eq!(final_ack.header.acknowledgment, 901);
        assert_eq!(final_ack.payload, b"active");
        assert_eq!(b.state(), State::Established);
        let bytes = deliver(&mut b, &mut a, 40);
        assert_eq!(
            wire::parse(ip(reverse(tuple())), &bytes).unwrap().payload,
            b"passive"
        );
        let mut out = [0; 8];
        assert_eq!(b.read(&mut out), Ok(6));
        assert_eq!(&out[..6], b"active");
        assert_eq!(a.read(&mut out), Ok(7));
        assert_eq!(&out[..7], b"passive");
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
    //= type=test
    //# If there are other controls or text in the segment, queue them for
    //# processing after the ESTABLISHED state has been reached, return.
    fn simultaneous_open_defers_syn_text_and_push_until_established() {
        let mut a = Connection::active(tuple(), config(64, 8), 100, 0).unwrap();
        packet(&mut a, 0);
        inject(&mut a, 10, Seq(u32::MAX - 1), Seq(0), SYN | PSH, 64, b"abc");
        assert_eq!(a.state(), State::SynReceived);
        assert_eq!(a.read(&mut [0; 8]), Err(Error::WouldBlock));
        assert!(!a.events_pending());
        let bytes = packet(&mut a, 20);
        let synack = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(synack.header.flags & (SYN | ACK), SYN | ACK);
        assert_eq!(synack.header.acknowledgment, 2);
        inject(&mut a, 30, Seq(2), Seq(101), ACK, 64, b"");
        assert_eq!(a.state(), State::Established);
        let events = a.take_events();
        assert!(events.connected && events.readable && events.pushed);
        let mut out = [0; 8];
        assert_eq!(a.read(&mut out), Ok(3));
        assert_eq!(&out[..3], b"abc");
        assert_eq!(a.read(&mut out), Err(Error::WouldBlock));
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.4
    //= type=test
    //# Queue this until all preceding SENDs have been segmentized, then form a
    //# FIN segment and send it.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
    //= type=test
    //= reason=SYN precedes queued data, FIN follows it; sequence numbers checked across wrap, handshake_queues_sends_until_established checks SYN consumes one.
    //# For sequence number purposes, the SYN is considered to occur before the first actual
    //# data octet of the segment in which it occurs, while the FIN is considered to occur after
    //# the last actual data octet in a segment in which it occurs.
    fn fin_follows_all_queued_sends_across_segments() {
        let (mut a, mut b) = pair(config(64, 4), u32::MAX - 2);
        a.set_nagle(false);
        a.write(b"abcdef").unwrap();
        a.write(b"ghij").unwrap();
        a.shutdown().unwrap();
        for (index, expected) in [b"abcd".as_slice(), b"efgh", b"ij"].into_iter().enumerate() {
            let bytes = deliver(&mut a, &mut b, 40 + index as u64);
            let segment = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(segment.payload, expected);
            assert_eq!(
                segment.header.sequence,
                (u32::MAX - 1).wrapping_add(index as u32 * 4)
            );
            if index < 2 {
                assert_eq!(segment.header.flags & FIN, 0);
                assert_eq!(a.state(), State::Established);
                assert_eq!(b.state(), State::Established);
            } else {
                assert_ne!(segment.header.flags & FIN, 0);
                assert_eq!(a.state(), State::FinWait1);
                assert_eq!(b.state(), State::CloseWait);
            }
        }
        let mut out = [0; 16];
        assert_eq!(b.read(&mut out), Ok(10));
        assert_eq!(&out[..10], b"abcdefghij");
        assert_eq!(b.read(&mut out), Ok(0));
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK)), set
    //# SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.
    fn window_updates_order_by_sequence_then_ack() {
        for iss in [100, u32::MAX - 4] {
            let (mut a, _) = pair(config(64, 8), iss);
            a.write(b"abcdefgh").unwrap();
            packet(&mut a, 40);
            let seq = a.receive.next();
            let ack = a.snd_una;
            // Newer SEQ; equal SEQ with equal, advancing, and stale ACK;
            // older SEQ despite newer ACK; finally newer SEQ with equal ACK.
            for (i, (seq, ack, window, accepted)) in [
                (seq.wrapping_add(1), ack, 40, true),
                (seq.wrapping_add(1), ack, 41, true),
                (seq.wrapping_add(1), ack.wrapping_add(1), 42, true),
                (seq.wrapping_add(1), ack, 43, false),
                (seq, ack.wrapping_add(2), 44, false),
                (seq.wrapping_add(2), ack.wrapping_add(2), 45, true),
            ]
            .into_iter()
            .enumerate()
            {
                let before = (a.snd_wnd, a.wl1, a.wl2);
                inject(&mut a, 50 + i as u64, seq, ack, ACK, window, b"");
                assert_eq!(
                    (a.snd_wnd, a.wl1, a.wl2),
                    if accepted {
                        (u32::from(window), seq, ack)
                    } else {
                        before
                    }
                );
            }
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# This should not occur since a FIN has been received from the remote side. Ignore
    //# the segment text.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //= reason=Closing-state test additionally checks URG after FIN cannot advance the urgent endpoint.
    //# This should not occur since a FIN has been received from the remote side. Ignore the
    //# URG.
    fn text_after_fin_is_ignored_in_closing_states() {
        for closing in [false, true] {
            let (mut a, mut b) = pair(config(64, 8), 100);
            if closing {
                a.shutdown().unwrap();
                packet(&mut a, 40); // Peer has not acknowledged our FIN.
            }
            b.write(b"last").unwrap();
            b.shutdown().unwrap();
            deliver(&mut b, &mut a, 50);
            assert_eq!(
                a.state(),
                if closing {
                    State::Closing
                } else {
                    State::CloseWait
                }
            );
            // Test CLOSE-WAIT (or CLOSING), then LAST-ACK (or TIME-WAIT).
            for step in 0..2 {
                a.take_events();
                let next = a.receive.next();
                let ack = a.snd_una;
                let state = a.state();
                let total = a.received_total;
                let urgent_before = (a.rcv_up, a.urgent_remaining());
                inject(
                    &mut a,
                    60 + step * 20,
                    next,
                    ack,
                    ACK | PSH | URG,
                    64,
                    b"bad",
                );
                assert_eq!((a.rcv_up, a.urgent_remaining()), urgent_before);
                assert_eq!(a.state(), state);
                assert_eq!(a.receive.next(), next);
                assert_eq!(a.received_total, total);
                assert_eq!(a.receive.readable(), if step == 0 { 4 } else { 0 });
                let events = a.take_events();
                assert!(!events.readable && !events.pushed);
                let mut out = [0; 8];
                if step == 0 {
                    assert_eq!(a.read(&mut out), Ok(4));
                    assert_eq!(&out[..4], b"last");
                    if closing {
                        let ack = a.snd_nxt;
                        inject(&mut a, 70, next, ack, ACK, 64, b"");
                        assert_eq!(a.state(), State::TimeWait);
                    } else {
                        a.shutdown().unwrap();
                        packet(&mut a, 70);
                        assert_eq!(a.state(), State::LastAck);
                    }
                }
                assert_eq!(a.read(&mut out), Ok(0));
            }
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.2.2
    //= type=test
    //# A TCP implementation MUST include a SWS avoidance algorithm in the receiver
    //# (MUST-39).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //= reason=RCV.NXT reflects accepted contiguous bytes and advertised credit; scaled rounding exception scoped in existing SHLD-14 evidence.
    //# Once the TCP endpoint takes responsibility for the data, it advances RCV.NXT over the
    //# data accepted, and adjusts RCV.WND as appropriate to the current buffer availability.
    //# The total of RCV.NXT and RCV.WND should not be reduced.
    fn handshake_data_backpressure_partial_reads_and_sequence_wrap() {
        let (mut a, mut b) = pair(config(8, 4), u32::MAX - 2);
        assert_eq!(a.write(b"abcdefghij"), Ok(8));
        assert_eq!(a.write(b"i"), Err(Error::WouldBlock));
        assert_eq!(b.read(&mut [0; 1]), Err(Error::WouldBlock));
        assert_eq!(b.read(&mut []), Err(Error::InvalidArgument));
        deliver(&mut a, &mut b, 40);
        assert!(!b.ack_pending);
        assert_eq!(b.ack_deadline, Some(200_040));
        deliver(&mut a, &mut b, 50);
        assert!(b.ack_pending);
        deliver(&mut b, &mut a, 60);
        assert_eq!(a.acknowledged(), 8);
        assert_eq!(a.take_events().acknowledged, Some(8));
        assert_eq!(a.write(b"ijkl"), Ok(4));
        let mut out = [0; 8];
        assert_eq!(b.read(&mut out[..2]), Ok(2));
        assert_eq!(&out[..2], b"ab");
        assert!(!b.ack_pending); // SWS: wait for four bytes of credit.
        assert_eq!(b.read(&mut out[..2]), Ok(2));
        assert_eq!(&out[..2], b"cd");
        deliver(&mut b, &mut a, 70);
        deliver(&mut a, &mut b, 80);
        assert_eq!(b.read(&mut out), Ok(8));
        assert_eq!(&out, b"efghijkl");
        assert_eq!(b.received_total, 12);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.4
    //= type=test
    //# However, there MUST be a way for an application to disable the Nagle algorithm
    //# on an individual connection (MUST-17).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.4
    //= type=test
    //# A TCP implementation SHOULD implement the Nagle algorithm to coalesce short
    //# segments (SHLD-7).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.2.1
    //= type=test
    //# A TCP implementation MUST include a SWS avoidance algorithm in the sender
    //# (MUST-38).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.3
    //= type=test
    //# A TCP endpoint SHOULD implement a delayed ACK (SHLD-18), but an ACK should not
    //# be excessively delayed; in particular, the delay MUST be less than 0.5 seconds
    //# (MUST-40).
    fn delayed_ack_nagle_and_override_deadlines() {
        let (mut a, mut b) = pair(config(64, 4), 100);
        a.write(b"abcde").unwrap();
        deliver(&mut a, &mut b, 40);
        assert_eq!(a.transmit(50, &mut [0; 64]), Ok(None));
        assert_eq!(b.transmit(50, &mut [0; 64]), Ok(None));
        b.timeout(200_040).unwrap();
        deliver(&mut b, &mut a, 200_040);
        deliver(&mut a, &mut b, 200_050);
        a.write(b"f").unwrap();
        assert_eq!(a.transmit(200_060, &mut [0; 64]), Ok(None));
        a.timeout(700_050).unwrap();
        assert_eq!(a.transmit(700_050, &mut [0; 64]), Ok(None));
        a.set_nagle(false);
        let bytes = packet(&mut a, 700_050);
        assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, b"f");

        let (mut a, _) = pair(config(64, 4), 100);
        a.set_nagle(false);
        let next = a.receive.next();
        let ack = a.snd_nxt;
        inject(&mut a, 40, next, ack, ACK, 2, b"");
        a.write(b"abcdef").unwrap();
        assert_eq!(a.transmit(50, &mut [0; 64]), Ok(None));
        a.timeout(500_040).unwrap();
        let bytes = packet(&mut a, 500_040);
        assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, b"ab");
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.5
    //= type=test
    //# A TCP implementation MUST support simultaneous open attempts (MUST- 10).
    fn simultaneous_open_and_lost_final_ack() {
        let cfg = config(64, 8);
        let mut a = Connection::active(tuple(), cfg.clone(), 10, 0).unwrap();
        let mut b = Connection::active(reverse(tuple()), cfg, 50, 0).unwrap();
        let a_syn = packet(&mut a, 0);
        let b_syn = packet(&mut b, 0);
        a.input(10, &wire::parse(ip(reverse(tuple())), &b_syn).unwrap())
            .unwrap();
        b.input(10, &wire::parse(ip(tuple()), &a_syn).unwrap())
            .unwrap();
        assert_eq!(a.state(), State::SynReceived);
        let a_synack = packet(&mut a, 20);
        let b_synack = packet(&mut b, 20);
        let sa = wire::parse(ip(tuple()), &a_synack).unwrap();
        let sb = wire::parse(ip(reverse(tuple())), &b_synack).unwrap();
        assert_eq!(sa.header.sequence, 10);
        assert_eq!(sb.header.sequence, 50);
        assert_eq!(sa.header.flags, SYN | ACK | ECE);
        assert_eq!(sb.header.flags, SYN | ACK | ECE);
        a.input(30, &sb).unwrap();
        b.input(30, &sa).unwrap();
        assert_eq!(a.state(), State::Established);
        assert_eq!(b.state(), State::Established);
        assert!(a.ecn_send() && b.ecn_send());
        let _lost = packet(&mut a, 40);
        a.input(50, &sb).unwrap();
        let ack = packet(&mut a, 50);
        assert_eq!(wire::parse(ip(tuple()), &ack).unwrap().header.flags, ACK);
        assert_eq!(a.snd_nxt, Seq(11));
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
    //= type=test
    //# The following procedure MUST be used to handle excessive retransmissions of data
    //# segments (MUST-20):
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
    //= type=test
    //# SYN retransmissions MUST be handled in the general way just described for data
    //# retransmissions, including notification of the application layer.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
    //= type=test
    //# (e) TCP implementations SHOULD inform the application of the delivery problem
    //# (unless such information has been disabled by the application; see the
    //# "Asynchronous Reports" section (Section 3.9.1.8)), when R1 is reached and before R2
    //# (SHLD-9).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
    //= type=test
    //# The value of R2 SHOULD correspond to at least 100 seconds (SHLD-11).
    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.8
    //= type=test
    //= reason=Default SYN/data R2 terminal behavior; storage reclaimed by release, timer servicing belongs to driver; explicit application stall timeout is separate.
    //# For any state if the user timeout expires, flush all queues, signal the user "error:
    //# connection aborted due to user timeout" in general and for any outstanding calls, delete
    //# the TCB, enter the CLOSED state, and return.
    fn syn_and_data_failures_warn_before_default_r2_expires() {
        for handshake in [true, false] {
            let cfg = config(64, 8);
            assert!(cfg.user_timeout_us >= 100_000_000);
            let mut a = if handshake {
                Connection::active(tuple(), cfg, 100, 0).unwrap()
            } else {
                pair(cfg, 100).0
            };
            a.take_events();
            if !handshake {
                a.write(b"lost").unwrap();
            }
            let original = packet(&mut a, 40);
            let original = wire::parse(ip(tuple()), &original).unwrap();
            for attempt in 0..3 {
                let deadline = a.rto_deadline.unwrap();
                a.timeout(deadline).unwrap();
                assert_eq!(a.take_events().retransmission_warning, attempt == 2);
                assert_eq!(a.take_route_advice(), attempt == 2);
                assert_ne!(a.state(), State::Closed);
                let retry = packet(&mut a, deadline);
                let retry = wire::parse(ip(tuple()), &retry).unwrap();
                assert_eq!(retry.header.sequence, original.header.sequence);
                assert_eq!(retry.payload, original.payload);
                assert_eq!(retry.header.flags & SYN, original.header.flags & SYN);
            }
            let deadline = a.user_deadline().unwrap();
            a.timeout(deadline - 1).unwrap();
            assert_ne!(a.state(), State::Closed);
            a.timeout(deadline).unwrap();
            assert_eq!(a.take_events().closed, Some(CloseReason::TimedOut));
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
    //= type=test
    //# The transmitter SHOULD collapse successive bits when it packetizes data, to send
    //# the largest possible segment (SHLD-27).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
    //= type=test
    //# However, a TCP implementation SHOULD send a maximum-sized segment whenever
    //# possible (SHLD-28) to improve performance (see Section 3.8.6.2.1).
    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
    //= type=test
    //= reason=FIFO byte queue across successive writes, not per-write completion records.
    //# Multiple SENDs are served in first come, first served order, so the TCP endpoint will
    //# queue those it cannot service immediately.
    fn successive_writes_coalesce_to_mss_and_push_the_final_segment() {
        let (mut a, _) = pair(config(64, 8), 100);
        a.set_nagle(false);
        for bytes in [&b"ab"[..], &b"cdef"[..], &b"ghijk"[..]] {
            assert_eq!(a.write(bytes), Ok(bytes.len()));
        }
        for expected in [&b"abcdefgh"[..], &b"ijk"[..]] {
            let bytes = packet(&mut a, 40);
            let segment = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(segment.payload, expected);
            assert_ne!(segment.header.flags & PSH, 0);
        }
        assert_eq!(a.transmit(40, &mut [0; 64]), Ok(None));
    }

    #[test]
    fn syn_option_layout_and_short_output_are_transactional() {
        for (synack, scaling) in [(false, true), (true, false), (true, true)] {
            for local_ts in [false, true] {
                for peer_ts in [false, true] {
                    if !synack && peer_ts {
                        continue;
                    }
                    for (local_sack, peer_sack) in
                        [(false, false), (false, true), (true, false), (true, true)]
                    {
                        let mut cfg = config(131072, 300);
                        cfg.ecn = false;
                        cfg.receive_ip_payload_limit = 200;
                        cfg.send_ip_payload_limit = if local_ts {
                            40
                        } else if local_sack {
                            32
                        } else {
                            28
                        };
                        cfg.sack = local_sack;
                        cfg.timestamps = local_ts;
                        let mut c = if synack {
                            let mut options = vec![2, 4, 1, 44];
                            if peer_sack {
                                options.extend_from_slice(&[1, 1, 4, 2]);
                            }
                            if scaling {
                                options.extend_from_slice(&[1, 3, 3, 7]);
                            }
                            if peer_ts {
                                options.extend_from_slice(&[1, 1, 8, 10, 0, 0, 0, 2, 0, 0, 0, 0]);
                            }
                            let mut input = [0; 60];
                            let size = wire::encode(
                                ip(reverse(tuple())),
                                Header {
                                    source_port: tuple().remote.port(),
                                    destination_port: tuple().local.port(),
                                    sequence: 900,
                                    acknowledgment: 0,
                                    flags: SYN,
                                    window: 65535,
                                    urgent_pointer: 0,
                                },
                                &options,
                                &[],
                                &mut input,
                            )
                            .unwrap();
                            let syn = wire::parse(ip(reverse(tuple())), &input[..size]).unwrap();
                            Connection::passive(tuple(), cfg, 100, 3_000, &syn).unwrap()
                        } else {
                            Connection::active(tuple(), cfg, 100, 3_000).unwrap()
                        };
                        let timestamps = local_ts && (!synack || peer_ts);
                        let mut expected = vec![2, 4, 0, 180];
                        let sack_offer = local_sack && (!synack || peer_sack);
                        if timestamps {
                            let echo = if synack { 2 } else { 0 };
                            expected.extend_from_slice(if sack_offer {
                                &[4, 2, 8, 10]
                            } else {
                                &[1, 1, 8, 10]
                            });
                            expected.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, echo]);
                        } else if sack_offer {
                            expected.extend_from_slice(&[1, 1, 4, 2]);
                        }
                        if scaling {
                            expected.extend_from_slice(&[1, 3, 3, 2]);
                        }
                        let size = 20 + expected.len();
                        let before = (
                            c.now,
                            c.snd_nxt,
                            c.last_sent,
                            c.last_ack_sent,
                            c.advertised_edge,
                            c.ts_recent,
                            c.last_timestamp_sent_at,
                            c.sample,
                            c.next_deadline(),
                            c.syn_pending,
                            (
                                c.ack_pending,
                                c.sack_receive,
                                c.sack_send,
                                c.timestamps,
                                c.scaling,
                                c.state,
                            ),
                        );
                        for len in 0..size {
                            let mut short = vec![0xa5; len];
                            assert_eq!(c.transmit(4_000, &mut short), Err(Error::OutputTooSmall));
                            assert_eq!(short, vec![0xa5; len]);
                            assert_eq!(
                                (
                                    c.now,
                                    c.snd_nxt,
                                    c.last_sent,
                                    c.last_ack_sent,
                                    c.advertised_edge,
                                    c.ts_recent,
                                    c.last_timestamp_sent_at,
                                    c.sample,
                                    c.next_deadline(),
                                    c.syn_pending,
                                    (
                                        c.ack_pending,
                                        c.sack_receive,
                                        c.sack_send,
                                        c.timestamps,
                                        c.scaling,
                                        c.state
                                    ),
                                ),
                                before
                            );
                        }
                        let mut out = vec![0; size];
                        assert_eq!(c.transmit(4_000, &mut out), Ok(Some(size)));
                        let segment = wire::parse(ip(tuple()), &out).unwrap();
                        assert_eq!(segment.raw_options, expected);
                        assert_eq!(segment.header.flags, SYN | if synack { ACK } else { 0 });
                        assert_eq!(segment.header.window, 65535);
                        assert_eq!(segment.options.mss, Some(180));
                        assert_eq!(segment.options.window_scale, scaling.then_some(2));
                        assert_eq!(
                            segment.options.timestamps,
                            timestamps.then_some((4, if synack { 2 } else { 0 }))
                        );
                        assert_eq!(segment.options.sack_permitted, sack_offer);
                        assert_eq!(c.sack_receive, sack_offer);
                        assert!(segment.payload.is_empty());
                        assert!(!c.syn_pending);
                    }
                }
            }
        }
    }

    #[test]
    fn output_small_and_none_do_not_commit_protocol_state() {
        let mut a = Connection::active(tuple(), config(64, 8), 42, 0).unwrap();
        let before = (a.snd_nxt, a.next_deadline(), a.now, a.advertised_edge);
        assert_eq!(a.transmit(100, &mut [0; 27]), Err(Error::OutputTooSmall));
        assert_eq!(
            (a.snd_nxt, a.next_deadline(), a.now, a.advertised_edge),
            before
        );
        assert!(a.syn_pending);
        assert_eq!(a.write(b"queued"), Ok(6));
        let bytes = packet(&mut a, 100);
        assert!(wire::parse(ip(tuple()), &bytes).unwrap().payload.is_empty());
        let before = (a.snd_nxt, a.next_deadline(), a.now);
        assert_eq!(a.transmit(200, &mut [0; 128]), Ok(None));
        assert_eq!((a.snd_nxt, a.next_deadline(), a.now), before);
        assert_eq!(a.transmit(99, &mut [0; 128]), Err(Error::TimeWentBackwards));
        let (mut a, _) = pair(config(64, 8), 42);
        a.write(b"data").unwrap();
        let before = (a.snd_nxt, a.next_deadline(), a.now, a.advertised_edge);
        assert_eq!(a.transmit(100, &mut [0; 23]), Err(Error::OutputTooSmall));
        assert_eq!(
            (a.snd_nxt, a.next_deadline(), a.now, a.advertised_edge),
            before
        );
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.8
    //= type=test
    //# For any state if the retransmission timeout expires on a segment in the
    //# retransmission queue, send the segment at the front of the retransmission
    //# queue again, reinitialize the retransmission timer, and return.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //= reason=Partial cumulative ACK removes only covered bytes and reports progress; future ACK rejection additionally in rfc5961_ack_bounds_are_inclusive_and_reject_all_incoming_side_effects.
    //# If SND.UNA < SEG.ACK =< SND.NXT, then set SND.UNA <- SEG.ACK. Any segments on the
    //# retransmission queue that are thereby entirely acknowledged are removed. Users should
    //# receive positive acknowledgments for buffers that have been SENT and fully acknowledged
    //# (i.e., SEND buffer should be returned with "ok" response). If the ACK is a duplicate
    //# (SEG.ACK =< SND.UNA), it can be ignored. If the ACK acks something not yet sent (SEG.ACK
    //# > SND.NXT), then send an ACK, drop the segment, and return.
    fn retransmission_uses_partial_ack_base_and_never_sends_unsent_tail() {
        let (mut a, mut b) = pair(config(64, 8), u32::MAX - 4);
        a.set_nagle(false);
        a.write(b"abcdefghijk").unwrap();
        let _lost = packet(&mut a, 40);
        let ack = a.send_base.wrapping_add(3);
        let next = a.receive.next();
        inject(&mut a, 50, next, ack, ACK, 64, b"");
        assert_eq!(a.acknowledged(), 3);
        let high = a.snd_nxt;
        let deadline = a.rto_deadline.unwrap();
        a.timeout(deadline).unwrap();
        assert!(a.retx_pending);
        assert_eq!(a.snd_nxt, high);
        let before = a.next_deadline();
        assert_eq!(
            a.transmit(deadline, &mut [0; 24]),
            Err(Error::OutputTooSmall)
        );
        assert!(a.retx_pending);
        assert_eq!(a.next_deadline(), before);
        let bytes = packet(&mut a, deadline);
        let retransmit = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(retransmit.header.sequence, ack.0);
        assert_eq!(retransmit.payload, b"defgh");
        assert_eq!(a.snd_nxt, high);
        assert!(a.sample.is_none());
        assert!(a.rto() >= 2_000_000);
        assert_eq!(a.rto_deadline, Some(deadline + a.rto()));
        // Separately exercise actual two-peer loss recovery.
        let (mut c, mut d) = pair(config(64, 8), 100);
        c.write(b"lost").unwrap();
        let _lost = packet(&mut c, 40);
        let deadline = c.rto_deadline.unwrap();
        c.timeout(deadline).unwrap();
        deliver(&mut c, &mut d, deadline);
        d.timeout(deadline + 200_000).unwrap();
        deliver(&mut d, &mut c, deadline + 200_000);
        assert_eq!(c.acknowledged(), 4);
        assert_eq!(c.rto_deadline, None);
        assert_eq!(d.read(&mut [0; 4]), Ok(4));
        // Keep this peer alive to ensure the original test never delivered
        // falsely acknowledged bytes into the receiver.
        assert_eq!(b.read(&mut [0; 1]), Err(Error::WouldBlock));
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.6
    //= type=test
    //# The user who CLOSEs may continue to RECEIVE until the TCP receiver is told that
    //# the remote peer has CLOSED also.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# if the FIN segment is now acknowledged, then enter FIN- WAIT-2 and continue
    //# processing in that state.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# The only thing that can arrive in this state is a retransmission of the remote
    //# FIN. Acknowledge it, and restart the 2 MSL timeout.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# If our FIN is now acknowledged, delete the TCB, enter the CLOSED
    //# state, and return.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.2
    //= type=test
    //# Return "error: connection closing" and do not service request.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.4
    //= type=test
    //= reason=CLOSE-WAIT sends final reply data with FIN and enters LAST-ACK only on committed output.
    //# Queue this request until all preceding SENDs have been segmentized; then send a FIN
    //# segment, enter LAST-ACK state.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //= reason=FIN advances receive sequence and half_closed event, sends ACK, preserves buffered bytes for subsequent read.
    //# If the FIN bit is set, signal the user "connection closing" and return any pending
    //# RECEIVEs with same message, advance RCV.NXT over the FIN, and send an acknowledgment for
    //# the FIN. Note that FIN implies PUSH for any segment text not yet delivered to the user.
    fn fin_half_close_time_wait_and_duplicate_fin_restart() {
        let (mut a, mut b) = pair(config(64, 8), 100);
        a.write(b"last").unwrap();
        a.shutdown().unwrap();
        assert_eq!(a.write(b"no"), Err(Error::InvalidState));
        deliver(&mut a, &mut b, 40);
        assert_eq!(a.state(), State::FinWait1);
        assert_eq!(a.write(b"no"), Err(Error::InvalidState));
        assert_eq!(a.send.len(), 4);
        assert_eq!(b.state(), State::CloseWait);
        let events = b.take_events();
        assert!(events.readable && events.half_closed);
        assert_eq!(b.read(&mut [0; 8]), Ok(4));
        assert_eq!(b.read(&mut [0; 8]), Ok(0));
        deliver(&mut b, &mut a, 50);
        assert_eq!(a.state(), State::FinWait2);
        assert_eq!(a.write(b"no"), Err(Error::InvalidState));
        assert_eq!(a.send.len(), 0);
        b.write(b"reply").unwrap();
        b.shutdown().unwrap();
        let fin = deliver(&mut b, &mut a, 60);
        assert_eq!(b.state(), State::LastAck);
        assert_eq!(b.write(b"no"), Err(Error::InvalidState));
        assert_eq!(b.send.len(), 5);
        assert_eq!(a.state(), State::TimeWait);
        assert_eq!(a.write(b"no"), Err(Error::InvalidState));
        assert_eq!(a.send.len(), 0);
        assert_eq!(a.take_events().closed, Some(CloseReason::Normal));
        let deadline = a.next_deadline().unwrap();
        a.input(70, &wire::parse(ip(reverse(tuple())), &fin).unwrap())
            .unwrap();
        assert_eq!(deadline, 60 + 240_000_000);
        assert_eq!(a.next_deadline(), Some(70 + 240_000_000));
        deliver(&mut a, &mut b, 80);
        assert_eq!(b.state(), State::Closed);
        assert_eq!(b.close_reason(), Some(CloseReason::Normal));
        assert_eq!(b.next_deadline(), None);
        assert_eq!(b.transmit(80, &mut [0; 64]), Ok(None));
        assert_eq!(a.read(&mut [0; 8]), Ok(5));
        assert_eq!(a.read(&mut [0; 8]), Ok(0));
        a.timeout(deadline).unwrap();
        assert_eq!(a.state(), State::TimeWait);
        a.timeout(a.next_deadline().unwrap()).unwrap();
        assert_eq!(a.state(), State::Closed);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# if the ACK acknowledges our FIN, then enter the TIME-WAIT state;
    //# otherwise, ignore the segment.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //= reason=Unacknowledged local FIN enters CLOSING; fin_half_close_time_wait_and_duplicate_fin_restart covers acknowledged branch and timer cancellation.
    //# If our FIN has been ACKed (perhaps in this segment), then enter TIME-WAIT, start the
    //# time-wait timer, turn off the other timers; otherwise, enter the CLOSING state.
    fn simultaneous_close_and_fin_retransmission() {
        let (mut a, mut b) = pair(config(64, 8), 100);
        a.shutdown().unwrap();
        b.shutdown().unwrap();
        let af = packet(&mut a, 40);
        let bf = packet(&mut b, 40);
        a.input(50, &wire::parse(ip(reverse(tuple())), &bf).unwrap())
            .unwrap();
        b.input(50, &wire::parse(ip(tuple()), &af).unwrap())
            .unwrap();
        assert_eq!(a.state(), State::Closing);
        assert_eq!(b.state(), State::Closing);
        assert_eq!(a.write(b"no"), Err(Error::InvalidState));
        assert_eq!(a.send.len(), 0);
        let next = a.receive.next();
        let una = a.snd_una;
        inject(&mut a, 55, next, una, ACK, 64, b"");
        assert_eq!(a.state(), State::Closing);
        assert_eq!(a.time_wait_deadline, None);
        let _lost = packet(&mut b, 60);
        deliver(&mut a, &mut b, 60);
        assert_eq!(b.state(), State::TimeWait);
        let deadline = a.rto_deadline.unwrap();
        a.timeout(deadline).unwrap();
        let fin = deliver(&mut a, &mut b, deadline);
        assert_ne!(
            wire::parse(ip(tuple()), &fin).unwrap().header.flags & FIN,
            0
        );
        deliver(&mut b, &mut a, deadline);
        assert_eq!(a.state(), State::TimeWait);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# 3) If the RST bit is set and the sequence number does not exactly match the
    //# next expected sequence value, yet is within the current receive window, TCP
    //# endpoints MUST send an acknowledgment (challenge ACK):
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# After sending the challenge ACK, TCP endpoints MUST drop the unacceptable
    //# segment and stop processing the incoming packet further.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# if the ACK bit is off, drop the segment and return
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
    //= type=test
    //= reason=ACK-only/text without SYN cannot establish a SYN-SENT connection.
    //# Fifth, if neither of the SYN or RST bits is set, then drop the segment and return.
    fn invalid_ack_reset_and_unsynchronized_text_are_not_processed() {
        let (mut a, _) = pair(config(64, 8), 100);
        a.write(b"retained").unwrap();
        packet(&mut a, 40);
        let next = a.receive.next();
        let high = a.snd_nxt;
        inject(&mut a, 50, next, high.wrapping_add(1), ACK, 0, b"bad");
        assert_eq!(a.send.len(), 8);
        assert_eq!(a.receive.readable(), 0);
        assert_eq!(a.snd_wnd, 64);
        packet(&mut a, 55); // Drain the invalid-ACK response before testing silent discard.
        inject(&mut a, 60, next, high, FIN | PSH, 0, b"bad");
        assert_eq!(a.receive.readable(), 0);
        assert_eq!(a.receive.next(), next);
        assert_eq!(a.state(), State::Established);
        assert_eq!(a.send.len(), 8);
        assert_eq!(a.snd_wnd, 64);
        assert!(!a.events_pending());
        assert_eq!(a.transmit(60, &mut [0; 64]), Ok(None));
        inject(&mut a, 70, next.wrapping_add(64), high, RST | ACK, 0, b"");
        assert_eq!(a.state(), State::Established);
        assert!(!a.ack_pending);
        inject(
            &mut a,
            80,
            next.wrapping_add(1),
            high,
            RST | ACK,
            0,
            b"rejected",
        );
        assert_eq!(a.state(), State::Established);
        assert!(a.ack_pending);
        assert_eq!(a.receive.readable(), 0);
        assert_eq!(a.receive.next(), next);
        assert_eq!(a.send.len(), 8);
        let response = packet(&mut a, 80);
        let response = wire::parse(ip(tuple()), &response).unwrap();
        assert_eq!(response.header.flags, ACK);
        assert_eq!(response.header.acknowledgment, next.0);
        // Filling the gap must not expose text from the rejected RST.
        inject(&mut a, 85, next, high, ACK, 64, b"x");
        let mut data = [0; 16];
        assert_eq!(a.read(&mut data), Ok(1));
        assert_eq!(data[0], b'x');
        let next = a.receive.next();
        // RST validation precedes ACK validation, including a bogus ACK.
        inject(&mut a, 90, next, high.wrapping_add(999), RST | ACK, 0, b"");
        assert_eq!(a.close_reason(), Some(CloseReason::Reset));
        assert_eq!(a.state(), State::Closed);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
    //= type=test
    //# Otherwise (no ACK), drop the segment and return.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
    //= type=test
    //# If SEG.ACK =< ISS or SEG.ACK > SND.NXT, send a reset (unless the RST bit
    //# is set, if so drop the segment and return)
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
    //= type=test
    //= reason=SYN-SENT validates ACK before RST; no response to unacceptable RST. Erratum 8167 remains separate.
    //# If SEG.ACK =< ISS or SEG.ACK > SND.NXT, send a reset (unless the RST bit is set, if so
    //# drop the segment and return) <SEQ=SEG.ACK><CTL=RST>
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
    //= type=test
    //= reason=SYN-SENT reset acceptance uses ACK of SYN, not RCV.NXT; terminal reason distinguishes reset.
    //# If the ACK was acceptable, then signal to the user "error: connection reset", drop the
    //# segment, enter CLOSED state, delete TCB, and return. Otherwise (no ACK), drop the
    //# segment and return.
    fn syn_sent_resets_require_ack_and_abort_outputs_once() {
        // Verified erratum 8167 removes the SYN-SENT RCV.NXT check:
        // https://www.rfc-editor.org/errata/eid8167
        // No peer sequence has been learned; only acknowledgment of our SYN matters.
        for iss in [100u32, u32::MAX] {
            for sequence in [0, 0x1234_5678, u32::MAX] {
                let mut a = Connection::active(tuple(), config(64, 8), iss, 0).unwrap();
                packet(&mut a, 0);
                for (flags, ack) in [
                    (RST, iss.wrapping_add(1)),
                    (RST | ACK, iss),
                    (RST | ACK, iss.wrapping_add(2)),
                ] {
                    inject(&mut a, 10, Seq(sequence), Seq(ack), flags, 0, b"");
                    assert_eq!(a.state(), State::SynSent);
                    assert_eq!(a.transmit(10, &mut [0; 64]), Ok(None));
                }
                for ack in [iss.wrapping_sub(1), iss, iss.wrapping_add(2)] {
                    inject(&mut a, 15, Seq(sequence), Seq(ack), SYN | ACK, 64, b"bad");
                    let bytes = packet(&mut a, 15);
                    let reset = wire::parse(ip(tuple()), &bytes).unwrap();
                    assert_eq!(reset.header.flags, RST);
                    assert_eq!(reset.header.sequence, ack);
                    assert!(reset.payload.is_empty());
                    assert_eq!(a.state(), State::SynSent);
                    assert_eq!(a.snd_una, Seq(iss));
                    assert_eq!(a.snd_nxt, Seq(iss.wrapping_add(1)));
                    assert_eq!(a.irs, None);
                    assert_eq!(a.receive.readable(), 0);
                    assert!(!a.events_pending());
                    assert_eq!(a.transmit(15, &mut [0; 64]), Ok(None));
                }
                inject(
                    &mut a,
                    20,
                    Seq(sequence),
                    Seq(iss.wrapping_add(1)),
                    RST | ACK,
                    0,
                    b"",
                );
                assert_eq!(a.state(), State::Closed);
                assert_eq!(a.close_reason(), Some(CloseReason::Reset));
                assert_eq!(a.transmit(20, &mut [0; 64]), Ok(None));
            }
        }
        let (mut a, mut b) = pair(config(64, 8), 100);
        a.abort();
        assert_eq!(a.state(), State::Closed);
        assert_eq!(a.close_reason(), Some(CloseReason::Aborted));
        assert_eq!(a.transmit(40, &mut [0; 1]), Err(Error::OutputTooSmall));
        deliver(&mut a, &mut b, 40);
        assert_eq!(b.close_reason(), Some(CloseReason::Reset));
        assert_eq!(a.transmit(50, &mut [0; 64]), Ok(None));
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1
    //= type=test
    //# Probing of zero (offered) windows MUST be supported (MUST-36).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1
    //= type=test
    //# As long as the receiving TCP peer continues to send acknowledgments in response
    //# to the probe segments, the sending TCP peer MUST allow the connection to stay
    //# open (MUST-37).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1
    //= type=test
    //= reason=Receiver replies to persist probes with current next sequence/window; responsive sender survives.
    //# When the receiving TCP peer has a zero window and a segment arrives, it must still send
    //# an acknowledgment showing its next expected sequence number and current window (zero).
    fn zero_window_probe_recovers_lost_update_and_responsive_peer_survives() {
        let mut cfg = config(4, 4);
        cfg.user_timeout_us = 5_000_000;
        let (mut a, mut b) = pair(cfg, 100);
        a.write(b"abcd").unwrap();
        deliver(&mut a, &mut b, 40);
        deliver(&mut b, &mut a, 50);
        assert_eq!(a.snd_wnd, 0);
        a.write(b"efgh").unwrap();
        for _ in 0..3 {
            let when = a.persist_deadline.unwrap();
            a.timeout(when).unwrap();
            deliver(&mut a, &mut b, when);
            deliver(&mut b, &mut a, when);
            assert_eq!(a.state(), State::Established);
        }
        assert_eq!(b.read(&mut [0; 4]), Ok(4));
        let when = a.now + 10;
        let _lost = packet(&mut b, when);
        let when = a.persist_deadline.unwrap();
        // No timeout while waiting to send a probe, even when persist
        // backoff exceeds the configured data timeout.
        assert_eq!(a.user_deadline(), None);
        a.timeout(when).unwrap();
        deliver(&mut a, &mut b, when);
        b.timeout(when + 200_000).unwrap();
        deliver(&mut b, &mut a, when + 200_000);
        assert!(a.snd_wnd > 0);
        a.set_nagle(false);
        deliver(&mut a, &mut b, when + 200_010);
        assert_eq!(b.read(&mut [0; 4]), Ok(4));
    }

    #[test]
    fn freed_receive_credit_is_not_accepted_until_advertised() {
        let (mut a, mut b) = pair(config(4, 4), 100);
        a.write(b"abcd").unwrap();
        deliver(&mut a, &mut b, 40);
        deliver(&mut b, &mut a, 50);
        assert_eq!(b.read(&mut [0; 4]), Ok(4));
        let next = b.receive.next();
        let ack = b.snd_nxt;
        inject(&mut b, 60, next, ack, ACK, 4, b"X");
        assert_eq!(b.receive.readable(), 0);
        packet(&mut b, 70);
        inject(&mut b, 80, next, ack, ACK, 4, b"X");
        assert_eq!(b.receive.readable(), 1);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# All incoming segments
    //# whose ACK value doesn't satisfy the above condition MUST be
    //# discarded and an ACK sent back.
    fn passive_handshake_applies_blind_ack_check_before_state_specific_reset() {
        let mut active = Connection::active(tuple(), config(64, 8), 100, 0).unwrap();
        let syn = packet(&mut active, 0);
        let syn = wire::parse(ip(tuple()), &syn).unwrap();
        let mut passive =
            Connection::passive(reverse(tuple()), config(64, 8), 200, 0, &syn).unwrap();
        packet(&mut passive, 0);
        inject(&mut passive, 1, Seq(101), Seq(202), ACK, 64, &[]);
        let response = packet(&mut passive, 1);
        let response = wire::parse(ip(reverse(tuple())), &response).unwrap();
        assert_eq!(response.header.flags, ACK);
        assert_eq!(response.header.sequence, 201);
        assert_eq!(passive.state(), State::SynReceived);
        // Within the RFC 5961 range, but not an ACK of our SYN: state-specific RST.
        inject(&mut passive, 2, Seq(101), Seq(200), ACK, 64, &[]);
        let response = packet(&mut passive, 2);
        let response = wire::parse(ip(reverse(tuple())), &response).unwrap();
        assert_eq!(response.header.flags, RST);
        assert_eq!(response.header.sequence, 200);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.5
    //= type=test
    //# The urgent pointer MUST point to the sequence number of the octet following the
    //# urgent data (MUST-62).
    fn zero_urgent_offset_can_advance_the_stream_urgent_mark() {
        let (_, mut receiver) = pair(config(64, 4), 100);
        receiver.take_events();
        let sequence = receiver.receive.next().wrapping_add(2);
        let ack = receiver.snd_nxt;
        inject(&mut receiver, 40, sequence, ack, ACK | URG, 64, &[]);
        assert_eq!(receiver.urgent_remaining(), 2);
        assert_eq!(receiver.take_events().urgent, Some(2));
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.5
    //= type=test
    //# However, TCP implementations MUST still include support for the urgent mechanism
    //# (MUST-30).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# Segments with higher beginning sequence numbers SHOULD be held for later
    //# processing (SHLD-31).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# o A TCP implementation MAY send an ACK segment acknowledging RCV.NXT when a
    //# valid segment arrives that is in the window but not at the left window edge
    //# (MAY-13).
    fn out_of_order_data_fin_and_inline_urgent() {
        let (mut a, mut b) = pair(config(64, 4), u32::MAX - 2);
        a.write_urgent(b"abcdef").unwrap();
        let first = packet(&mut a, 40);
        a.set_nagle(false);
        a.shutdown().unwrap();
        let second = packet(&mut a, 50);
        b.input(60, &wire::parse(ip(tuple()), &second).unwrap())
            .unwrap();
        assert_eq!(b.receive.readable(), 0);
        assert!(!b.receive.eof());
        assert!(b.ack_pending);
        assert_eq!(b.take_events().urgent, Some(6));
        b.input(70, &wire::parse(ip(tuple()), &first).unwrap())
            .unwrap();
        assert_eq!(b.state(), State::CloseWait);
        let mut out = [0; 8];
        assert_eq!(b.read(&mut out), Ok(6));
        assert_eq!(&out[..6], b"abcdef");
        assert_eq!(b.read(&mut out), Ok(0));
        assert_eq!(b.take_events().urgent, None);
    }

    #[test]
    fn readable_bytes_defers_syn_payload_and_matches_inline_reads() {
        let metadata = ip(tuple());
        let header = Header {
            source_port: 1000,
            destination_port: 2000,
            sequence: 100,
            acknowledgment: 0,
            flags: SYN | URG,
            window: 64,
            urgent_pointer: 4,
        };
        let mut bytes = [0; 64];
        let n = wire::encode(metadata, header, &[], b"abc", &mut bytes).unwrap();
        let syn = wire::parse(metadata, &bytes[..n]).unwrap();
        let mut b = Connection::passive(reverse(tuple()), config(64, 8), 900, 0, &syn).unwrap();
        assert_eq!(b.readable_bytes(), 0);
        packet(&mut b, 10);
        inject(&mut b, 20, Seq(104), Seq(901), ACK, 64, b"");
        assert_eq!(b.readable_bytes(), 3);
        assert_eq!(b.read(&mut [0; 1]), Ok(1));
        assert_eq!(b.readable_bytes(), 2);
        b.abort();
        assert_eq!(b.readable_bytes(), 0);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
    //= type=test
    //# Consequently, if a keep-alive mechanism is implemented it MUST NOT interpret
    //# failure to respond to any specific probe as a dead connection (MUST-29).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
    //= type=test
    //# Implementers MAY include "keep-alives" in their TCP implementations (MAY-5),
    //# although this practice is not universally accepted.
    fn syn_timeout_data_rto_user_timeout_and_keepalive() {
        let cfg = config(64, 8);
        let mut a = Connection::active(tuple(), cfg.clone(), 100, 0).unwrap();
        let _lost = packet(&mut a, 0);
        a.timeout(1_000_000).unwrap();
        let bytes = packet(&mut a, 1_000_000);
        let syn = wire::parse(ip(tuple()), &bytes).unwrap();
        let mut b = Connection::passive(reverse(tuple()), cfg, 200, 1_000_000, &syn).unwrap();
        deliver(&mut b, &mut a, 1_000_010);
        deliver(&mut a, &mut b, 1_000_020);
        a.write(b"data").unwrap();
        packet(&mut a, 1_000_030);
        assert!(a.rto_deadline.unwrap() >= 4_000_030);
        a.timeout(a.progress_at + a.config.user_timeout_us).unwrap();
        assert_eq!(a.close_reason(), Some(CloseReason::TimedOut));

        let mut cfg = config(64, 8);
        cfg.keepalive = Some(KeepaliveConfig {
            idle_us: 7_200_000_000,
            interval_us: 1_000_000,
            probes: 2,
            send_garbage: false,
        });
        let (mut a, mut b) = pair(cfg, 100);
        let deadline = a.keepalive_deadline.unwrap();
        a.timeout(deadline).unwrap();
        deliver(&mut a, &mut b, deadline);
        deliver(&mut b, &mut a, deadline);
        assert_eq!(a.keepalive_probes, 0);
        let deadline = a.keepalive_deadline.unwrap();
        a.timeout(deadline).unwrap();
        packet(&mut a, deadline);
        let deadline = a.keepalive_deadline.unwrap();
        a.timeout(deadline).unwrap();
        packet(&mut a, deadline);
        assert_eq!(a.state(), State::Established);
        a.timeout(a.keepalive_deadline.unwrap()).unwrap();
        assert_eq!(a.close_reason(), Some(CloseReason::TimedOut));
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //= type=test
    //# The window size MUST be treated as an unsigned number, or else large window
    //# sizes will appear like negative windows and TCP will not work (MUST-1).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //= type=test
    //# It is RECOMMENDED that implementations will reserve 32-bit fields for the send
    //# and receive window sizes in the connection record and do all window computations
    //# with 32 bits (REC- 1).
    fn window_scaling_is_negotiated_but_syn_windows_are_unscaled() {
        let (mut a, mut b) = pair(config(131072, 1460), 100);
        assert!(a.scaling && b.scaling);
        assert_eq!(a.local_scale, 2);
        assert_eq!(a.peer_scale, 2);
        assert_eq!(a.snd_wnd, 65535); // From SYN+ACK, never scaled.
        assert!(b.snd_wnd > 65535); // Final ACK is scaled.
        b.immediate_ack();
        deliver(&mut b, &mut a, 40);
        assert!(a.snd_wnd > 65535);
        assert!(a.snd_wnd <= 131072);
        assert!(b.receive_window() <= 131072);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.5
    //= type=test
    //# The TCP implementation MUST (MUST-33) provide a way for the application to learn
    //# how much urgent data remains to be read from the connection, or at least to
    //# determine whether more urgent data remains to be read [19].
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.5
    //= type=test
    //= reason=SYN data is buffered internally, not readable nor notified to application before handshake completes.
    //# so long as the receiving TCP endpoint doesn't deliver the data to the user until it is
    //# clear the data is valid (e.g., the data is buffered at the receiver until the connection
    //# reaches the ESTABLISHED state, given that the three-way handshake reduces the
    //# possibility of false connections).
    fn syn_text_is_retained_but_not_readable_before_establishment() {
        let metadata = ip(tuple());
        let header = Header {
            source_port: 1000,
            destination_port: 2000,
            sequence: u32::MAX - 1,
            acknowledgment: 0,
            flags: SYN | URG | PSH,
            window: 64,
            urgent_pointer: 4,
        };
        let mut bytes = [0; 64];
        let size = wire::encode(metadata, header, &[], b"abc", &mut bytes).unwrap();
        let syn = wire::parse(metadata, &bytes[..size]).unwrap();
        let mut b = Connection::passive(reverse(tuple()), config(64, 8), 900, 0, &syn).unwrap();
        assert_eq!(b.receive.next(), Seq(2));
        assert!(!b.events_pending());
        assert_eq!(b.read(&mut [0; 8]), Err(Error::WouldBlock));
        assert_eq!(b.urgent_remaining(), 0);
        let synack_bytes = packet(&mut b, 10);
        let synack = wire::parse(ip(reverse(tuple())), &synack_bytes).unwrap();
        assert_eq!(synack.header.acknowledgment, 2);
        assert_eq!(synack.header.window, 61);
        inject(&mut b, 20, Seq(2), Seq(901), ACK, 64, b"");
        let events = b.take_events();
        assert!(events.connected && events.readable);
        assert_eq!(events.urgent, Some(3));
        assert!(events.pushed);
        assert_eq!(b.urgent_remaining(), 3);
        let mut out = [0; 8];
        assert_eq!(b.read(&mut out[..1]), Ok(1));
        assert_eq!(b.urgent_remaining(), 2);
        assert_eq!(b.read(&mut out[1..]), Ok(2));
        assert_eq!(&out[..3], b"abc");
        assert_eq!(b.urgent_remaining(), 0);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
    //= type=test
    //# A TCP receiver MUST process the RST and URG fields of all incoming segments,
    //# even when the receive window is zero (MUST-66).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.5.3
    //= type=test
    //# TCP implementations SHOULD allow a received RST segment to include data
    //# (SHLD-2).
    fn zero_window_still_processes_reset_and_urgent_controls_with_text() {
        let (mut a, mut b) = pair(config(4, 4), 100);
        a.write(b"abcd").unwrap();
        deliver(&mut a, &mut b, 40);
        deliver(&mut b, &mut a, 50);
        assert_eq!(b.receive_window(), 0);
        let header = Header {
            source_port: 1000,
            destination_port: 2000,
            sequence: b.receive.next().0,
            acknowledgment: b.snd_nxt.0,
            flags: ACK | URG,
            window: 4,
            urgent_pointer: 1,
        };
        let mut bytes = [0; 64];
        let size = wire::encode(ip(tuple()), header, &[], b"x", &mut bytes).unwrap();
        b.input(60, &wire::parse(ip(tuple()), &bytes[..size]).unwrap())
            .unwrap();
        assert_eq!(b.receive.readable(), 4);
        assert_eq!(b.take_events().urgent, Some(5));
        assert_eq!(b.urgent_remaining(), 5);
        let next = b.receive.next();
        let ack = b.snd_nxt.wrapping_add(999);
        inject(&mut b, 70, next, ack, RST | ACK, 4, b"ignored");
        assert_eq!(b.close_reason(), Some(CloseReason::Reset));
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.5
    //= type=test
    //= reason=Exercises a 70000-byte urgent run across sequence wrap, not every possible length.
    //# A TCP implementation MUST support a sequence of urgent data of any length
    //# (MUST-31) [19].
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.5
    //= type=test
    //# A TCP implementation MUST (MUST-32) inform the application layer asynchronously
    //# whenever it receives an urgent pointer and there was previously no pending
    //# urgent data, or whenever the urgent pointer advances in the data stream.
    fn urgent_run_larger_than_pointer_keeps_urg_set_from_first_packet() {
        let (mut a, mut b) = pair(config(131072, 1460), u32::MAX - 100);
        assert_eq!(a.write_urgent(&vec![42; 70000]), Ok(70000));
        let bytes = deliver(&mut a, &mut b, 40);
        let first = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_ne!(first.header.flags & URG, 0);
        assert_eq!(first.header.urgent_pointer, 65535);
        assert_eq!(b.take_events().urgent, Some(65535));
        let bytes = deliver(&mut a, &mut b, 50);
        let second = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_ne!(second.header.flags & URG, 0);
        assert_eq!(b.take_events().urgent, Some(65535 + 1460));
        assert_eq!(b.urgent_remaining(), 65535 + 1460);
    }

    #[test]
    fn configured_recovery_reaches_active_and_passive_connections() {
        assert_eq!(
            ConnectionConfig::default().recovery_algorithm,
            RecoveryAlgorithm::NewReno
        );
        for choice in [
            None,
            Some(RecoveryAlgorithm::Reno),
            Some(RecoveryAlgorithm::NewReno),
        ] {
            let mut cfg = config(64, 4);
            if let Some(algorithm) = choice {
                cfg.recovery_algorithm = algorithm;
            }
            let newreno = cfg.recovery_algorithm == RecoveryAlgorithm::NewReno;
            let (a, b) = pair(cfg, u32::MAX - 7);
            for mut sender in [a, b] {
                sender.write(&[1; 16]).unwrap();
                for _ in 0..4 {
                    packet(&mut sender, 40);
                }
                let seq = sender.receive.next();
                let una = sender.snd_una;
                for _ in 0..3 {
                    inject(&mut sender, 41, seq, una, ACK, 64, b"");
                }
                assert!(sender.retx_pending);
                packet(&mut sender, 42);
                inject(&mut sender, 43, seq, una.wrapping_add(4), ACK, 64, b"");
                assert_eq!(sender.retx_pending, newreno);
                assert_eq!(sender.congestion.cwnd(), if newreno { 20 } else { 8 });
                if newreno {
                    let bytes = packet(&mut sender, 44);
                    let segment = wire::parse(ip(sender.tuple()), &bytes).unwrap();
                    assert_eq!(segment.header.sequence, una.wrapping_add(4).0);
                }
                inject(&mut sender, 45, seq, una.wrapping_add(16), ACK, 64, b"");
                assert!(!sender.retx_pending);
                assert_eq!(sender.flight(), 0);
            }
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.4
    //= type=test
    //= reason=Repeated shutdown is idempotent and never creates a second FIN.
    //# An "ok" response would be acceptable, too, as long as a second FIN is not emitted (the
    //# first FIN may be retransmitted, though).
    fn fast_retransmit_uses_three_duplicate_acks_and_fin_shutdown_is_idempotent() {
        let (mut a, mut b) = pair(config(64, 4), 100);
        a.write(b"abcdefghijklmnop").unwrap();
        let _lost = packet(&mut a, 40);
        for now in [50, 60, 70] {
            deliver(&mut a, &mut b, now);
            deliver(&mut b, &mut a, now);
        }
        assert!(a.retx_pending);
        assert_eq!(a.rtt.rto(), 1_000_000); // Fast retransmit does not back off.
        let bytes = deliver(&mut a, &mut b, 80);
        let retransmit = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(retransmit.payload, b"abcd");
        assert_eq!(retransmit.header.sequence, 101);
        deliver(&mut b, &mut a, 90);
        assert_eq!(a.acknowledged(), 16);
        assert!(!a.retx_pending);
        a.shutdown().unwrap();
        a.shutdown().unwrap();
        deliver(&mut a, &mut b, 100);
        a.shutdown().unwrap();
        deliver(&mut b, &mut a, 110);
        a.shutdown().unwrap();
        b.shutdown().unwrap();
        deliver(&mut b, &mut a, 120);
        b.shutdown().unwrap();
        a.shutdown().unwrap();
        deliver(&mut a, &mut b, 130);
        b.shutdown().unwrap();
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
    //= type=test
    //# In particular, R2 for a SYN segment MUST be set large enough to provide
    //# retransmission of the segment for at least 3 minutes (MUST-23).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
    //= type=test
    //# (d) An application MUST (MUST-21) be able to set the value for R2 for a
    //# particular connection.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
    //= type=test
    //# The value of R1 SHOULD correspond to at least 3 retransmissions, at the current
    //# RTO (SHLD-10).
    fn handshake_minimum_timeout_warning_and_fresh_app_clock() {
        let mut cfg = config(64, 8);
        cfg.user_timeout_us = 1_000;
        let mut a = Connection::active(tuple(), cfg, 100, 0).unwrap();
        assert_eq!(a.user_deadline(), Some(180_000_000));
        packet(&mut a, 0);
        for attempt in 0..3 {
            let deadline = a.rto_deadline.unwrap();
            a.timeout(deadline).unwrap();
            assert_eq!(a.take_events().retransmission_warning, attempt == 2);
            assert_eq!(a.take_route_advice(), attempt == 2);
            assert!(!a.take_route_advice());
            packet(&mut a, deadline);
        }
        a.timeout(179_999_999).unwrap();
        assert_eq!(a.state(), State::SynSent);
        a.timeout(180_000_000).unwrap();
        assert_eq!(a.close_reason(), Some(CloseReason::TimedOut));
        let (mut a, _) = pair(config(64, 8), 100);
        a.set_user_timeout(10_000).unwrap();
        assert_eq!(a.set_user_timeout(0), Err(Error::InvalidArgument));
        a.update_time(10_000_000).unwrap();
        a.write(b"new").unwrap();
        assert_eq!(a.user_deadline(), Some(10_010_000));
        assert_eq!(a.update_time(9_999_999), Err(Error::TimeWentBackwards));
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
    //= type=test
    //# Source Quench
    //# TCP implementations MUST silently discard any received ICMP Source
    //# Quench messages (MUST-55).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
    //= type=test
    //= reason=The soft-error event is observable and the connection remains Established; outer ICMP validation belongs to the adapter.
    //# Since these Unreachable messages indicate soft error conditions, a
    //# TCP implementation MUST NOT abort the connection (MUST-56), and it
    //# SHOULD make the information available to the application (SHLD-25).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
    //= type=test
    //# These are hard error conditions, so TCP implementations SHOULD abort the
    //# connection (SHLD-26).
    fn network_errors_validate_quote_and_mss_reduction_repacketizes() {
        let (mut a, mut b) = pair(config(64, 8), 100);
        a.write(b"abcdefgh").unwrap();
        let original = packet(&mut a, 40);
        assert_eq!(
            a.network_error(50, 100, NetworkError::HardUnreachable),
            Ok(false)
        );
        assert_eq!(
            a.network_error(50, 109, NetworkError::HardUnreachable),
            Ok(false)
        );
        assert_eq!(
            a.network_error(50, 101, NetworkError::SourceQuench),
            Ok(false)
        );
        assert!(!a.events_pending());
        assert_eq!(
            a.network_error(60, 101, NetworkError::SoftUnreachable),
            Ok(true)
        );
        assert_eq!(
            a.take_events().network_error,
            Some(NetworkError::SoftUnreachable)
        );
        assert_eq!(a.state(), State::Established);
        assert_eq!(
            a.network_error(70, 108, NetworkError::TimeExceeded),
            Ok(true)
        );
        assert_eq!(
            a.take_events().network_error,
            Some(NetworkError::TimeExceeded)
        );
        assert_eq!(a.lower_mss(0), Err(Error::InvalidArgument));
        assert_eq!(a.lower_mss(9), Err(Error::InvalidArgument));
        let storage = (a.scratch.as_ptr(), a.scratch.capacity());
        let high = a.snd_nxt;
        a.lower_mss(3).unwrap();
        assert!(a.retx_pending);
        assert_eq!((a.scratch.as_ptr(), a.scratch.capacity()), storage);
        let bytes = packet(&mut a, 80);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.payload, b"abc");
        assert_eq!(a.snd_nxt, high);
        assert!(a.sample.is_none());
        assert_eq!(
            a.network_error(90, 101, NetworkError::ParameterProblem),
            Ok(true)
        );
        assert_eq!(a.close_reason(), None);
        assert_eq!(
            a.take_events().network_error,
            Some(NetworkError::ParameterProblem)
        );
        b.input(100, &wire::parse(ip(tuple()), &original).unwrap())
            .unwrap();
        b.timeout(200_100).unwrap();
        deliver(&mut b, &mut a, 200_100);
        assert_eq!(a.acknowledged(), 8);
        assert_eq!(a.state(), State::Established);
        let mut data = [0; 8];
        assert_eq!(b.read(&mut data), Ok(8));
        assert_eq!(&data, b"abcdefgh");
        a.write(b"new").unwrap();
        deliver(&mut a, &mut b, 200_110);
        assert_eq!(
            a.network_error(200_120, 109, NetworkError::HardUnreachable),
            Ok(true)
        );
        assert_eq!(a.close_reason(), Some(CloseReason::NetworkError));
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.1
    //= type=test
    //# If an MSS Option is not received at connection setup, TCP implementations MUST
    //# assume a default send MSS of 536 (576 - 40) for IPv4 or 1220 (1280 - 60) for
    //# IPv6 (MUST-15).
    fn invalid_configuration_and_unscaled_peer_defaults() {
        assert!(Connection::active(tuple(), config(64, 65495), 100, 0).is_ok());
        assert!(matches!(
            Connection::active(tuple(), config(64, 65496), 100, 0),
            Err(Error::InvalidArgument)
        ));
        let mut cfg = config(64, 8);
        cfg.delayed_ack_us = 500_000;
        assert!(matches!(
            Connection::active(tuple(), cfg, 100, 0),
            Err(Error::InvalidArgument)
        ));
        let header = Header {
            source_port: 1000,
            destination_port: 2000,
            sequence: 100,
            acknowledgment: 0,
            flags: SYN,
            window: 65535,
            urgent_pointer: 0,
        };
        let syn = Segment {
            header,
            options: wire::Options::default(),
            raw_options: &[],
            payload: &[],
        };
        let mut b =
            Connection::passive(reverse(tuple()), ConnectionConfig::default(), 900, 0, &syn)
                .unwrap();
        assert_eq!(b.mss, 536);
        assert!(!b.scaling);
        let bytes = packet(&mut b, 10);
        assert_eq!(
            wire::parse(ip(reverse(tuple())), &bytes)
                .unwrap()
                .options
                .window_scale,
            None
        );
        let v6_tuple = Tuple {
            local: "[2001:db8::1]:1000".parse().unwrap(),
            remote: "[2001:db8::2]:2000".parse().unwrap(),
        };
        let b = Connection::passive(v6_tuple, ConnectionConfig::default(), 900, 0, &syn).unwrap();
        assert_eq!(b.mss, 1220);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
    //= type=test
    //# A TCP receiver SHOULD NOT shrink the window, i.e., move the right
    //# window edge to the left (SHLD-14).
    fn scaled_window_rounding_never_overruns_storage_or_revokes_old_credit() {
        let (mut a, mut b) = pair(config(65536, 1460), 100);
        let backing = b.receive.right_edge();
        for step in 0..32 {
            let now = 40 + step * 10;
            a.write(b"x").unwrap();
            deliver(&mut a, &mut b, now);
            b.immediate_ack();
            let promised = b.advertised_edge;
            let bytes = deliver(&mut b, &mut a, now);
            let ack = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
            let edge = Seq(ack.header.acknowledgment)
                .wrapping_add((ack.header.window as u32) << b.local_scale);
            assert!(at_or_after(backing, edge));
            assert!(at_or_after(backing, b.advertised_edge));
            assert!(at_or_after(b.advertised_edge, promised));
        }
        assert_eq!(b.read(&mut [0; 32]), Ok(32));
    }

    #[test]
    fn eof_reads_do_not_generate_an_unbounded_ack_stream() {
        let (mut a, mut b) = pair(config(64, 8), 100);
        b.shutdown().unwrap();
        deliver(&mut b, &mut a, 40);
        deliver(&mut a, &mut b, 50);
        for now in 60..100 {
            assert_eq!(a.read(&mut [0; 8]), Ok(0));
            assert_eq!(a.transmit(now, &mut [0; 64]), Ok(None));
        }
    }

    #[test]
    fn limited_transmit_is_one_packet_per_duplicate_and_excluded_from_threshold() {
        let (mut a, mut b) = pair(config(64, 4), 100);
        a.write(b"abcdefghijklmnopqrstuvwxyzABCDEF").unwrap();
        let _lost = packet(&mut a, 40);
        let second = packet(&mut a, 40);
        let third = packet(&mut a, 40);
        let fourth = packet(&mut a, 40);
        assert_eq!(a.flight(), 16);
        assert_eq!(a.transmit(40, &mut [0; 64]), Ok(None));
        for (now, bytes) in [(50, second), (60, third)] {
            b.input(now, &wire::parse(ip(tuple()), &bytes).unwrap())
                .unwrap();
            deliver(&mut b, &mut a, now);
            assert!(a.limited_pending);
            let extra = packet(&mut a, now);
            assert_eq!(wire::parse(ip(tuple()), &extra).unwrap().payload.len(), 4);
            assert!(!a.limited_pending);
            assert_eq!(a.transmit(now, &mut [0; 64]), Ok(None));
        }
        assert_eq!(a.flight(), 24);
        assert_eq!(a.limited_sent, 8);
        b.input(70, &wire::parse(ip(tuple()), &fourth).unwrap())
            .unwrap();
        deliver(&mut b, &mut a, 70);
        assert!(a.retx_pending);
        assert_eq!(a.congestion.ssthresh(), 8);
        let bytes = packet(&mut a, 80);
        assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, b"abcd");
    }

    #[test]
    fn karn_discards_retransmission_samples_but_can_time_fresh_sequence_space() {
        let (mut a, _) = pair(config(64, 4), 100);
        a.write(b"abcdefghijkl").unwrap();
        packet(&mut a, 40);
        packet(&mut a, 40);
        let deadline = a.rto_deadline.unwrap();
        a.timeout(deadline).unwrap();
        packet(&mut a, deadline);
        assert!(a.sample.is_none());
        let seq = a.receive.next();
        inject(&mut a, deadline + 10, seq, Seq(105), ACK, 64, b"");
        let fresh = packet(&mut a, deadline + 20);
        assert_eq!(wire::parse(ip(tuple()), &fresh).unwrap().payload, b"ijkl");
        assert_eq!(a.sample, Some((Seq(113), deadline + 20)));
        inject(&mut a, deadline + 30, seq, Seq(113), ACK, 64, b"");
        assert!(a.sample.is_none());
        assert_eq!(a.rto(), 1_000_000);
    }

    #[test]
    fn lost_payload_and_fin_are_retransmitted_together() {
        let (mut a, mut b) = pair(config(64, 8), 100);
        a.write(b"last").unwrap();
        a.shutdown().unwrap();
        let _lost = packet(&mut a, 40);
        let high = a.snd_nxt;
        let deadline = a.rto_deadline.unwrap();
        a.timeout(deadline).unwrap();
        let bytes = deliver(&mut a, &mut b, deadline);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.payload, b"last");
        assert_ne!(segment.header.flags & FIN, 0);
        assert_eq!(a.snd_nxt, high);
        assert_eq!(b.read(&mut [0; 8]), Ok(4));
        assert_eq!(b.read(&mut [0; 8]), Ok(0));
        deliver(&mut b, &mut a, deadline);
        assert_eq!(a.state(), State::FinWait2);
        assert_eq!(a.rto_deadline, None);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
    //= type=test
    //# This interval MUST be configurable (MUST-27) and MUST default to no less than
    //# two hours (MUST-28).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
    //= type=test
    //= reason=Default configuration is off; per-connection enable, override and disable update the timers.
    //# If
    //# keep-alives are included, the application MUST be able to turn them
    //# on or off for each TCP connection (MUST-24), and they MUST default to
    //# off (MUST-25).
    fn keepalive_can_be_disabled_or_overridden_without_reusing_stale_deadlines() {
        assert_eq!(ConnectionConfig::default().keepalive, None);
        assert_eq!(KeepaliveConfig::default().idle_us, 7_200_000_000);
        let (mut a, _) = pair(config(64, 8), 100);
        a.update_time(1_000_000).unwrap();
        let keepalive = KeepaliveConfig {
            idle_us: 100,
            interval_us: 50,
            probes: 2,
            send_garbage: false,
        };
        a.set_keepalive(Some(keepalive)).unwrap();
        assert_eq!(a.next_deadline(), Some(1_000_100));
        a.timeout(1_000_100).unwrap();
        packet(&mut a, 1_000_100);
        assert_eq!(a.keepalive_probes, 1);
        a.update_time(1_000_120).unwrap();
        a.set_keepalive(Some(keepalive)).unwrap();
        assert_eq!(a.keepalive_probes, 0);
        assert_eq!(a.next_deadline(), Some(1_000_220));
        a.timeout(1_000_220).unwrap();
        assert!(a.keepalive_pending);
        a.set_keepalive(None).unwrap();
        assert!(!a.keepalive_pending);
        assert_eq!(a.next_deadline(), None);
        assert_eq!(a.transmit(1_000_220, &mut [0; 64]), Ok(None));
        for invalid in [
            KeepaliveConfig {
                idle_us: 0,
                ..keepalive
            },
            KeepaliveConfig {
                interval_us: 0,
                ..keepalive
            },
            KeepaliveConfig {
                probes: 1,
                ..keepalive
            },
        ] {
            assert_eq!(a.set_keepalive(Some(invalid)), Err(Error::InvalidArgument));
        }
        let mut cfg = config(64, 8);
        cfg.keepalive = Some(keepalive);
        assert!(Connection::active(tuple(), cfg, 100, 0).is_ok());
    }
    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.4
    //= type=test
    //# Delete the TCB and return "error: closing" responses to any queued
    //# SENDs, or RECEIVEs.
    fn syn_sent_shutdown_cancels_unsent_and_sent_open() {
        for sent in [false, true] {
            let mut a = Connection::active(tuple(), config(64, 8), 100, 0).unwrap();
            a.write(b"queued").unwrap();
            if sent {
                packet(&mut a, 0);
                // Even an already queued response must not escape local cancellation.
                inject(&mut a, 10, Seq(0), Seq(999), ACK, 64, b"");
                assert!(a.pending_rst.is_some());
            }
            a.shutdown().unwrap();
            assert_eq!(a.state(), State::Closed);
            assert_eq!(a.close_reason(), Some(CloseReason::Normal));
            assert_eq!(a.take_events().closed, Some(CloseReason::Normal));
            assert_eq!(a.write(b"late"), Err(Error::InvalidState));
            assert_eq!(a.read(&mut [0; 1]), Err(Error::InvalidState));
            assert_eq!(a.next_deadline(), None);
            assert_eq!(a.transmit(20, &mut []), Ok(None));
            a.timeout(180_000_000).unwrap();
            assert_eq!(a.transmit(180_000_000, &mut [0; 64]), Ok(None));
            a.shutdown().unwrap();
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.5
    //= type=test
    //# Send a reset segment:
    //# <SEQ=SND.NXT><CTL=RST>
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.5
    //= type=test
    //# All queued SENDs and RECEIVEs should be given "connection reset"
    //# notification. Delete the TCB, enter CLOSED state, and return.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.5
    //= type=test
    //# Respond with "ok" and delete the TCB, enter CLOSED state, and return.
    fn abort_state_matrix_cancels_work_and_only_resets_required_states() {
        for state in [
            State::SynSent,
            State::SynReceived,
            State::Established,
            State::FinWait1,
            State::FinWait2,
            State::CloseWait,
            State::Closing,
            State::LastAck,
            State::TimeWait,
        ] {
            let (mut a, _) = pair(config(64, 8), 100);
            a.write(b"queued").unwrap();
            a.state = state;
            a.pending_rst = Some((Seq(999), true));
            a.abort();
            assert_eq!(a.state(), State::Closed);
            assert_eq!(a.close_reason(), Some(CloseReason::Aborted));
            assert_eq!(a.take_events().closed, Some(CloseReason::Aborted));
            assert_eq!(a.next_deadline(), None);
            assert_eq!(a.write(b"late"), Err(Error::InvalidState));
            assert_eq!(a.read(&mut [0; 1]), Err(Error::InvalidState));
            a.abort(); // Idempotence must not erase the required reset.
            if matches!(
                state,
                State::SynReceived
                    | State::Established
                    | State::FinWait1
                    | State::FinWait2
                    | State::CloseWait
            ) {
                assert_eq!(a.transmit(40, &mut [0; 19]), Err(Error::OutputTooSmall));
                let bytes = packet(&mut a, 40);
                let reset = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(reset.header.flags, RST);
                assert_eq!(reset.header.sequence, a.snd_nxt.0);
                assert!(reset.payload.is_empty());
            }
            assert_eq!(a.transmit(50, &mut []), Ok(None));
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.3
    //= type=test
    //# An ACK SHOULD be generated for at least every second full-sized segment
    //# or 2*RMSS bytes of new data (where RMSS is the MSS specified by the TCP
    //# endpoint receiving the segments to be acknowledged, or the default value
    //# if not specified) (SHLD-19).
    fn delayed_ack_counts_small_segments_and_commits_only_with_output() {
        let (mut a, _) = pair(config(128, 8), 100);
        // Effective send MSS is not the local receive MSS used for this threshold.
        a.mss = 4;
        let ack = a.snd_nxt;
        for i in 0..8 {
            let next = a.receive.next();
            inject(&mut a, 40 + i, next, ack, ACK, 128, b"ab");
            assert_eq!(a.unacked_bytes, 2 * (i + 1) as u32);
            assert_eq!(a.full_segments, 0);
            assert_eq!(a.ack_pending, i == 7);
        }
        let before = (a.unacked_bytes, a.full_segments, a.ack_pending, a.now);
        assert_eq!(a.transmit(50, &mut [0; 19]), Err(Error::OutputTooSmall));
        assert_eq!(
            (a.unacked_bytes, a.full_segments, a.ack_pending, a.now),
            before
        );
        packet(&mut a, 50);
        assert_eq!(a.unacked_bytes, 0);
        let next = a.receive.next();
        inject(&mut a, 60, next, ack, ACK, 128, b"ab");
        assert!(!a.ack_pending);
        assert_eq!(a.unacked_bytes, 2);
        assert_eq!(a.transmit(70, &mut [0; 64]), Ok(None));
        assert_eq!(a.unacked_bytes, 2);
        // A piggyback ACK also commits the reset.
        a.write(b"reply").unwrap();
        packet(&mut a, 70);
        assert_eq!(a.unacked_bytes, 0);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1
    //= type=test
    //= reason=Asserts the initial RTO deadline and successive doubled intervals, including failed output attempts.
    //# The transmitting host SHOULD send the first zero-window probe when a
    //# zero window has existed for the retransmission timeout period (SHLD-
    //# 29) (Section 3.8.1), and SHOULD increase exponentially the interval
    //# between successive probes (SHLD-30).
    fn persist_uses_updated_rto_once_per_episode() {
        let (mut a, _) = pair(config(64, 4), 100);
        a.write(b"abcdefgh").unwrap();
        packet(&mut a, 40);
        let old_rto = a.rto();
        let next = a.receive.next();
        let ack = a.snd_nxt;
        inject(&mut a, 2_000_040, next, ack, ACK, 0, b"");
        assert!(a.rto() > old_rto);
        let first_rto = a.rto();
        assert_eq!(a.persist_interval, first_rto);
        assert_eq!(a.persist_deadline, Some(a.now + first_rto));
        let deadline = a.persist_deadline.unwrap();
        a.arm_work();
        assert_eq!(a.persist_deadline, Some(deadline));
        a.timeout(deadline).unwrap();
        a.arm_work();
        assert_eq!(a.persist_deadline, None);
        assert!(a.probe_pending);
        assert_eq!(
            a.transmit(deadline, &mut [0; 20]),
            Err(Error::OutputTooSmall)
        );
        assert_eq!(a.persist_interval, first_rto);
        packet(&mut a, deadline);
        assert_eq!(a.persist_interval, 2 * first_rto);
        let second = a.persist_deadline.unwrap();
        // A responsive, still-closed window must not restart the backoff.
        let ack = a.snd_nxt;
        inject(&mut a, deadline + 1, next, ack, ACK, 0, b"");
        a.arm_work();
        assert_eq!(a.persist_deadline, Some(second));
        assert_eq!(a.persist_interval, 2 * first_rto);
        a.timeout(second).unwrap();
        packet(&mut a, second);
        assert_eq!(a.persist_interval, 4 * first_rto);
        let ack = a.snd_nxt;
        inject(&mut a, second + 1, next, ack, ACK, 64, b"");
        assert_eq!(a.persist_interval, 0);
        assert_eq!(a.persist_deadline, None);
        inject(&mut a, second + 2, next, ack, ACK, 0, b"");
        assert_eq!(a.persist_interval, a.rto());
        assert_eq!(a.persist_deadline, Some(second + 2 + a.rto()));
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.6.1
    //= type=test
    //# When a connection is closed actively, it MUST linger in the TIME-WAIT
    //# state for a time 2xMSL (Maximum Segment Lifetime) (MUST-13).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4.2
    //= type=test
    //# For this specification the MSL is taken to be 2 minutes.
    fn time_wait_configuration_enforces_two_msl_minimum() {
        for time_wait_us in [0, 1, 239_999_999, 240_000_000, 240_000_001] {
            let mut cfg = config(64, 8);
            cfg.time_wait_us = time_wait_us;
            let result = Connection::active(tuple(), cfg, 100, 0);
            if time_wait_us < 240_000_000 {
                assert!(matches!(result, Err(Error::InvalidArgument)));
            } else {
                let mut a = result.unwrap();
                a.time_wait();
                assert_eq!(a.time_wait_deadline, Some(time_wait_us));
                a.timeout(time_wait_us - 1).unwrap();
                assert_eq!(a.state(), State::TimeWait);
                a.timeout(time_wait_us).unwrap();
                assert_eq!(a.state(), State::Closed);
            }
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.1
    //= type=test
    //# TCP endpoints MUST implement both sending and receiving the MSS Option
    //# (MUST-14).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.1
    //= type=test
    //# TCP implementations SHOULD send an MSS Option in every SYN segment when its
    //# receive MSS differs from the default 536 for IPv4 or 1220 for IPv6 (SHLD-5),
    //# and MAY send it always (MAY-3).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.1
    //= type=test
    //# The maximum size of a segment that a TCP endpoint really sends, the
    //# "effective send MSS", MUST be the smaller (MUST-16) of the send MSS
    //# (that reflects the available reassembly buffer size at the remote
    //# host, the EMTU_R [19]) and the largest transmission size permitted by
    //# the IP layer (EMTU_S [19]):
    fn mss_offers_and_asymmetric_send_limits_for_both_address_families() {
        let v6 = Tuple {
            local: "[2001:db8::1]:1000".parse().unwrap(),
            remote: "[2001:db8::2]:2000".parse().unwrap(),
        };
        for tuple in [tuple(), v6] {
            let default_mss = if tuple.local.is_ipv4() { 536 } else { 1220 };
            for (local_mss, peer_mss) in [(default_mss, 300), (300, default_mss), (1460, 1460)] {
                let mut a = Connection::active(tuple, config(8192, local_mss), 100, 0).unwrap();
                let bytes = packet(&mut a, 0);
                let syn = wire::parse(ip(tuple), &bytes).unwrap();
                assert_eq!(syn.options.mss, Some(local_mss));
                let mut b =
                    Connection::passive(reverse(tuple), config(8192, peer_mss), 900, 10, &syn)
                        .unwrap();
                let bytes = deliver(&mut b, &mut a, 20);
                let synack = wire::parse(ip(reverse(tuple)), &bytes).unwrap();
                assert_eq!(synack.options.mss, Some(peer_mss));
                deliver(&mut a, &mut b, 30);
                let effective = usize::from(local_mss.min(peer_mss));
                assert_eq!(a.mss, effective);
                assert_eq!(b.mss, effective);
                for sender in [&mut a, &mut b] {
                    sender.write(&vec![42; 4096]).unwrap();
                    let bytes = packet(sender, 40);
                    let data = wire::parse(ip(sender.tuple()), &bytes).unwrap();
                    assert_eq!(data.payload.len(), effective);
                    assert_eq!(data.options.mss, None);
                }
            }
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
    //= type=test
    //# and they MUST default to off (MUST-25).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
    //= type=test
    //# Keep-alive packets MUST only be sent when no sent data is outstanding, and
    //# no data or acknowledgment packets have been received for the connection
    //# within an interval (MUST-26).
    fn keepalive_defaults_off_and_is_suppressed_by_outstanding_data() {
        assert_eq!(ConnectionConfig::default().keepalive, None);
        let (mut a, _) = pair(config(64, 8), 100);
        a.timeout(7_200_000_100).unwrap();
        assert_eq!(a.keepalive_deadline, None);
        assert!(!a.keepalive_pending);
        assert_eq!(a.transmit(7_200_000_100, &mut [0; 64]), Ok(None));

        let (mut a, _) = pair(config(64, 8), 100);
        a.set_keepalive(Some(KeepaliveConfig {
            idle_us: 100,
            interval_us: 50,
            probes: 2,
            send_garbage: false,
        }))
        .unwrap();
        a.timeout(a.keepalive_deadline.unwrap()).unwrap();
        assert!(a.keepalive_pending);
        a.write(b"data").unwrap();
        assert!(!a.keepalive_pending);
        packet(&mut a, 130);
        assert_eq!(a.flight(), 4);
        assert_eq!(a.keepalive_deadline, None);
        a.timeout(230).unwrap();
        assert_eq!(a.transmit(230, &mut [0; 64]), Ok(None));
        let next = a.receive.next();
        let ack = a.snd_nxt;
        inject(&mut a, 240, next, ack, ACK, 64, b"");
        assert_eq!(a.keepalive_deadline, Some(340));
        a.timeout(339).unwrap();
        assert_eq!(a.transmit(339, &mut [0; 64]), Ok(None));
        a.timeout(340).unwrap();
        let bytes = packet(&mut a, 340);
        let probe = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(probe.header.sequence, a.snd_nxt.wrapping_add(u32::MAX).0);
        assert!(probe.payload.is_empty());
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.6
    //= type=test
    //# If the local TCP connection is closed by the remote side due to a FIN or RST
    //# received from the remote side, then the local application MUST be informed
    //# whether it closed normally or was aborted (MUST-12).
    fn remote_fin_and_reset_have_distinct_close_notifications() {
        let (mut a, mut b) = pair(config(64, 8), 100);
        b.shutdown().unwrap();
        deliver(&mut b, &mut a, 40);
        let events = a.take_events();
        assert!(events.half_closed);
        assert_eq!(events.closed, None);
        assert_eq!(a.read(&mut [0; 1]), Ok(0));
        a.shutdown().unwrap();
        deliver(&mut a, &mut b, 50);
        deliver(&mut b, &mut a, 60);
        assert_eq!(a.take_events().closed, Some(CloseReason::Normal));
        assert_eq!(a.close_reason(), Some(CloseReason::Normal));

        let (mut a, _) = pair(config(64, 8), 100);
        let next = a.receive.next();
        let ack = a.snd_nxt;
        inject(&mut a, 40, next, ack, RST, 64, b"");
        let events = a.take_events();
        assert!(!events.half_closed);
        assert_eq!(events.closed, Some(CloseReason::Reset));
        assert_eq!(a.close_reason(), Some(CloseReason::Reset));
        assert_eq!(a.read(&mut [0; 1]), Err(Error::InvalidState));
    }
    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
    //= type=test
    //# However, a sending TCP peer MUST
    //# be robust against window shrinking, which may cause the "usable
    //# window" (see Section 3.8.6.2.1) to become negative (MUST-34).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
    //= type=test
    //# If this happens, the sender SHOULD NOT send new data (SHLD-15), but
    //# SHOULD retransmit normally the old unacknowledged data between
    //# SND.UNA and SND.UNA+SND.WND (SHLD-16).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
    //= type=test
    //# but SHOULD NOT
    //# time out the connection if data beyond the right window edge is not
    //# acknowledged (SHLD-17).
    fn nonzero_shrink_below_flight_retains_bytes_retransmits_inside_and_reopens() {
        for iss in [100, u32::MAX - 4] {
            let mut cfg = config(64, 8);
            cfg.user_timeout_us = 5_000_000;
            let (mut a, _) = pair(cfg, iss);
            a.write(b"abcdefghijkl").unwrap();
            packet(&mut a, 40);
            let next = a.receive.next();
            let una = a.snd_una;
            let high = a.snd_nxt;
            inject(&mut a, 50, next, una, ACK, 3, b"");
            assert_eq!(a.flight(), 8);
            assert_eq!(a.send.len(), 12);
            assert_eq!(a.transmit(60, &mut [0; 64]), Ok(None));
            let when = a.rto_deadline.unwrap();
            a.timeout(when).unwrap();
            let before = (a.snd_nxt, a.rto_deadline, a.now, a.retx_pending);
            assert_eq!(
                a.transmit(when + 1, &mut [0; 22]),
                Err(Error::OutputTooSmall)
            );
            assert_eq!((a.snd_nxt, a.rto_deadline, a.now, a.retx_pending), before);
            let bytes = packet(&mut a, when + 1);
            let seg = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(seg.header.sequence, una.0);
            assert_eq!(seg.payload, b"abc");
            assert_eq!(a.snd_nxt, high);
            // No ACK progress for longer than the user timeout, but validated
            // window feedback proves the shrunken peer is still responsive.
            for now in [4_000_000, 8_000_000, 12_000_000, 16_000_000] {
                inject(&mut a, now, next, una, ACK, 3, b"");
                assert_eq!(a.user_deadline(), None);
                a.timeout(now).unwrap();
                assert_eq!(a.state(), State::Established);
                if a.retx_pending && now != 16_000_000 {
                    let bytes = packet(&mut a, now);
                    assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, b"abc");
                }
                assert_eq!(a.snd_nxt, high);
                assert_eq!(a.send.len(), 12);
            }
            inject(&mut a, 16_000_001, next, una, ACK, 64, b"");
            assert_eq!(a.user_deadline(), Some(21_000_001));
            // Reopening lets the pending retransmission recover the entire flight.
            let bytes = packet(&mut a, 16_000_001);
            assert_eq!(
                wire::parse(ip(tuple()), &bytes).unwrap().payload,
                b"abcdefgh"
            );
            assert_eq!(a.snd_nxt, high);
            // ACK only the original flight; the unsent tail survived the shrink.
            inject(&mut a, 16_000_002, next, high, ACK, 64, b"");
            assert_eq!(a.acknowledged(), 8);
            let bytes = packet(&mut a, 16_000_003);
            assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, b"ijkl");
            let end = a.snd_nxt;
            inject(&mut a, 16_000_004, next, end, ACK, 64, b"");
            assert_eq!(a.acknowledged(), 12);
            assert_eq!(a.send.len(), 0);
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
    //= type=test
    //# but SHOULD NOT
    //# time out the connection if data beyond the right window edge is not
    //# acknowledged (SHLD-17).
    fn shrink_liveness_rejects_stale_feedback_and_keeps_ordinary_boundary_timeout() {
        for iss in [100, u32::MAX - 4] {
            for window in [1, 7, 8, 9] {
                let mut cfg = config(64, 8);
                cfg.user_timeout_us = 5_000_000;
                let (mut a, _) = pair(cfg, iss);
                a.write(b"abcdefgh").unwrap();
                packet(&mut a, 40);
                let seq = a.receive.next().wrapping_add(1);
                let una = a.snd_una;
                inject(&mut a, 50, seq, una, ACK, window, b"");
                let baseline = a.user_deadline();
                inject(&mut a, 100, seq, una, ACK, window, b"");
                if window < 8 {
                    assert_eq!(a.user_deadline(), None);
                    let when = a.rto_deadline.unwrap();
                    a.timeout(when).unwrap();
                    packet(&mut a, when);
                    assert_eq!(a.user_deadline(), Some(when + 5_000_000));
                } else {
                    assert_eq!(a.user_deadline(), baseline);
                }
                let deadline = a.user_deadline().unwrap();
                let feedback_at = a.now + 1;
                // Acceptable old ACK, stale SEQ/window, future ACK, RST and SYN
                // cannot reset the liveness clock or update the send window.
                for (seq, ack, flags) in [
                    (seq, una.wrapping_add(u32::MAX), ACK),
                    (a.receive.next(), una, ACK),
                    (seq, a.snd_nxt.wrapping_add(1), ACK),
                    (seq, una, RST | ACK),
                    (seq, una, SYN | ACK),
                ] {
                    inject(&mut a, feedback_at, seq, ack, flags, 64, b"");
                    assert_eq!(a.user_deadline(), Some(deadline));
                    assert_eq!(a.snd_wnd, window as u32);
                }
                a.timeout(deadline - 1).unwrap();
                assert_eq!(a.state(), State::Established);
                a.timeout(deadline).unwrap();
                assert_eq!(a.close_reason(), Some(CloseReason::TimedOut));
            }
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.1
    //= type=test
    //# The maximum size of a segment that a TCP endpoint really sends, the
    //# "effective send MSS", MUST be the smaller (MUST-16) of the send MSS
    //# (that reflects the available reassembly buffer size at the remote
    //# host, the EMTU_R [19]) and the largest transmission size permitted by
    //# the IP layer (EMTU_S [19]):
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.1
    //= type=test
    //# where MMS_R is the maximum size for a transport-layer message that
    //# can be received (and reassembled at the IP layer) (MUST-67).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.3
    //= type=test
    //# As a result, when the effective MTU of an interface varies packet-to-
    //# packet, TCP implementations SHOULD use the smallest effective MTU of
    //# the interface to calculate the value to advertise in the MSS Option
    //# (SHLD-6).
    fn ip_limits_bound_receive_offer_send_payload_options_and_allocations() {
        let v6 = Tuple {
            local: "[2001:db8::1]:1000".parse().unwrap(),
            remote: "[2001:db8::2]:2000".parse().unwrap(),
        };
        for tuple in [tuple(), v6] {
            let family_limit = if tuple.local.is_ipv4() { 65515 } else { 65535 };
            let max_mss = family_limit - 20;
            for (configured, receive, send, peer) in [
                (64, 25, 40, 64),
                (64, 100, 40, 9),
                (64, 21, 28, 64),
                (8, 100, 100, 64),
                (max_mss, u16::MAX, u16::MAX, max_mss),
            ] {
                let mut cfg = config(131072, configured);
                cfg.receive_ip_payload_limit = receive;
                cfg.send_ip_payload_limit = send;
                let mut a = Connection::active(tuple, cfg, 100, 0).unwrap();
                let storage = (a.scratch.as_ptr(), a.scratch.capacity());
                assert_eq!(a.scratch.len(), configured as usize);
                let before = (a.snd_nxt, a.now, a.next_deadline());
                assert_eq!(a.transmit(1, &mut [0; 27]), Err(Error::OutputTooSmall));
                assert_eq!((a.snd_nxt, a.now, a.next_deadline()), before);
                assert!(a.syn_pending);
                let bytes = packet(&mut a, 1);
                assert_eq!(bytes.len(), 28);
                assert!(bytes.len() <= send as usize);
                let syn = wire::parse(ip(tuple), &bytes).unwrap();
                assert_eq!(
                    syn.options.mss,
                    Some(configured.min(receive.min(family_limit) - 20))
                );
                assert!(syn.options.window_scale.is_some());
                let mut b =
                    Connection::passive(reverse(tuple), config(131072, peer), 900, 10, &syn)
                        .unwrap();
                deliver(&mut b, &mut a, 20);
                let ack = deliver(&mut a, &mut b, 30);
                assert_eq!(ack.len(), 20);
                let effective = configured.min(peer).min(send.min(family_limit) - 20) as usize;
                assert_eq!(a.mss, effective);
                a.write(&vec![42; effective + 1]).unwrap();
                let before = (a.snd_nxt, a.now, a.next_deadline());
                assert_eq!(
                    a.transmit(40, &mut vec![0; 19 + effective]),
                    Err(Error::OutputTooSmall)
                );
                assert_eq!((a.snd_nxt, a.now, a.next_deadline()), before);
                let bytes = packet(&mut a, 40);
                assert_eq!(bytes.len(), 20 + effective);
                assert!(bytes.len() <= send.min(family_limit) as usize);
                assert_eq!(
                    wire::parse(ip(tuple), &bytes).unwrap().payload.len(),
                    effective
                );
                a.lower_mss(1).unwrap();
                assert_eq!((a.scratch.as_ptr(), a.scratch.capacity()), storage);
                assert_eq!(packet(&mut a, 50).len(), 21);
                a.abort();
                assert_eq!(packet(&mut a, 60).len(), 20);
            }
            for (receive, send) in [
                (0, 100),
                (20, 100),
                (100, 0),
                (100, 20),
                (100, 21),
                (100, 27),
            ] {
                let mut cfg = config(64, 8);
                cfg.receive_ip_payload_limit = receive;
                cfg.send_ip_payload_limit = send;
                assert!(matches!(
                    Connection::active(tuple, cfg, 100, 0),
                    Err(Error::InvalidArgument)
                ));
            }
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# o  RFC 5961 [9], Section 5 describes a potential blind data
    //# injection attack, and mitigation that implementations MAY
    //# choose to include (MAY-12).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# TCP stacks that implement RFC
    //# 5961 MUST add an input check that the ACK value is
    //# acceptable only if it is in the range of ((SND.UNA -
    //# MAX.SND.WND) =< SEG.ACK =< SND.NXT).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# All incoming segments
    //# whose ACK value doesn't satisfy the above condition MUST be
    //# discarded and an ACK sent back.
    fn rfc5961_ack_bounds_are_inclusive_and_reject_all_incoming_side_effects() {
        for iss in [100, u32::MAX - 4] {
            for bound in 0..4 {
                let (mut a, _) = pair(config(64, 8), iss);
                a.write(b"retained").unwrap();
                packet(&mut a, 40);
                let oldest = a.snd_una.wrapping_add(0u32.wrapping_sub(a.max_snd_wnd));
                let high = a.snd_nxt;
                let ack = [
                    oldest,
                    high,
                    oldest.wrapping_add(u32::MAX),
                    high.wrapping_add(1),
                ][bound];
                let next = a.receive.next();
                let seq = next.wrapping_add(1); // URG offset zero still advances the mark.
                let before = (
                    a.snd_una,
                    a.snd_wnd,
                    a.wl1,
                    a.wl2,
                    a.progress_at,
                    a.last_received,
                    a.rto_deadline,
                );
                inject(&mut a, 50, seq, ack, ACK | URG | FIN, 1, b"bad");
                if bound < 2 {
                    assert_eq!(a.urgent_remaining(), 1);
                    assert_eq!(a.send.len(), if bound == 0 { 8 } else { 0 });
                    // The accepted out-of-order text and FIN become visible on filling the gap.
                    inject(&mut a, 60, next, high, ACK, 64, b"x");
                    let mut data = [0; 4];
                    assert_eq!(a.read(&mut data), Ok(4));
                    assert_eq!(&data, b"xbad");
                    assert_eq!(a.state(), State::CloseWait);
                } else {
                    assert_eq!(
                        (
                            a.snd_una,
                            a.snd_wnd,
                            a.wl1,
                            a.wl2,
                            a.progress_at,
                            a.last_received,
                            a.rto_deadline
                        ),
                        before
                    );
                    assert_eq!(a.urgent_remaining(), 0);
                    assert_eq!(a.send.len(), 8);
                    assert_eq!(a.receive.next(), next);
                    assert_eq!(a.state(), State::Established);
                    assert!(!a.events_pending());
                    let bytes = packet(&mut a, 50);
                    let response = wire::parse(ip(tuple()), &bytes).unwrap();
                    assert_eq!(response.header.flags, ACK);
                    assert_eq!(response.header.sequence, high.0);
                    assert_eq!(response.header.acknowledgment, next.0);
                    inject(&mut a, 60, next, high, ACK, 64, b"x");
                    assert_eq!(a.read(&mut [0; 8]), Ok(1));
                    assert_eq!(a.state(), State::Established);
                }
            }
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# 2)  If the RST bit is set and the sequence number exactly
    //# matches the next expected sequence number (RCV.NXT), then
    //# TCP endpoints MUST reset the connection in the manner
    //# prescribed below according to the connection state.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# RFC 5961 recommends that in
    //# these synchronized states, if the SYN bit is set,
    //# irrespective of the sequence number, TCP endpoints MUST send
    //# a "challenge ACK" to the remote peer:
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# o  After sending the acknowledgment, TCP implementations MUST
    //# drop the unacceptable segment and stop processing further.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //= reason=Exact-sequence inbound reset terminates, cancels all protocol output/deadlines, reports Reset; explicit release governs terminal handle storage.
    //# If the RST bit is set, then any outstanding RECEIVEs and SEND should receive "reset"
    //# responses. All segment queues should be flushed. Users should also receive an
    //# unsolicited general "connection reset" signal. Enter the CLOSED state, delete the TCB,
    //# and return.
    fn rfc5961_reset_and_syn_state_matrix_drops_text_urgent_fin_and_ack() {
        for state in [
            State::SynReceived,
            State::Established,
            State::FinWait1,
            State::FinWait2,
            State::CloseWait,
            State::Closing,
            State::LastAck,
            State::TimeWait,
        ] {
            for control in [RST, SYN] {
                for offset in [0, 1, 64, u32::MAX] {
                    let (mut a, _) = pair(config(64, 8), u32::MAX - 4);
                    a.write(b"retained").unwrap();
                    packet(&mut a, 40);
                    a.state = state;
                    // Exercise receive wrap as well as send wrap.
                    a.receive = ReceiveBuffer::new(Seq(u32::MAX), 64).unwrap();
                    a.advertised_edge = Seq(63);
                    let next = a.receive.next();
                    let high = a.snd_nxt;
                    let before = (
                        a.snd_una,
                        a.snd_wnd,
                        a.wl1,
                        a.wl2,
                        a.progress_at,
                        a.last_received,
                    );
                    inject(
                        &mut a,
                        50,
                        next.wrapping_add(offset),
                        high,
                        control | ACK | URG | FIN,
                        0,
                        b"bad",
                    );
                    if control == RST && offset == 0 {
                        assert_eq!(a.state(), State::Closed);
                        assert_eq!(a.close_reason(), Some(CloseReason::Reset));
                        assert_eq!(a.next_deadline(), None);
                    } else {
                        assert_eq!(a.state(), state);
                        assert_eq!(
                            (
                                a.snd_una,
                                a.snd_wnd,
                                a.wl1,
                                a.wl2,
                                a.progress_at,
                                a.last_received
                            ),
                            before
                        );
                        assert_eq!(a.ack_pending, control == SYN || offset == 1);
                        if a.ack_pending {
                            let bytes = packet(&mut a, 50);
                            let ack = wire::parse(ip(tuple()), &bytes).unwrap();
                            assert_eq!(ack.header.flags, ACK);
                            assert_eq!(ack.header.sequence, high.0);
                            assert_eq!(ack.header.acknowledgment, next.0);
                        }
                    }
                    assert_eq!(a.receive.next(), next);
                    assert_eq!(a.receive.readable(), 0);
                    assert!(!a.receive.eof());
                    assert_eq!(a.rcv_up, None);
                    assert_eq!(a.send.len(), 8);
                }
            }
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# 2)  If the RST bit is set and the sequence number exactly
    //# matches the next expected sequence number (RCV.NXT), then
    //# TCP endpoints MUST reset the connection in the manner
    //# prescribed below according to the connection state.
    fn passive_syn_received_exception_releases_child_without_user_notification() {
        for control in [RST, SYN] {
            let mut a = Connection::active(tuple(), config(64, 8), 100, 0).unwrap();
            let bytes = packet(&mut a, 0);
            let syn = wire::parse(ip(tuple()), &bytes).unwrap();
            let mut b =
                Connection::passive(reverse(tuple()), config(64, 8), 900, 10, &syn).unwrap();
            packet(&mut b, 20);
            let next = b.receive.next();
            let high = b.snd_nxt;
            inject(
                &mut b,
                30,
                next,
                high,
                control | ACK | URG | FIN,
                0,
                b"ignored",
            );
            assert_eq!(b.state(), State::Closed);
            assert!(!b.events_pending());
            assert_eq!(b.receive.readable(), 0);
            assert_eq!(b.rcv_up, None);
            assert_eq!(b.next_deadline(), None);
            assert_eq!(b.transmit(40, &mut [0; 64]), Ok(None));
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1
    //= type=test
    //# A TCP implementation MAY keep its offered receive window closed
    //# indefinitely (MAY-8).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
    //= type=test
    //# A TCP receiver SHOULD NOT shrink the window, i.e., move the right
    //# window edge to the left (SHLD-14).
    fn receiver_zero_window_persists_without_reads_and_sender_probes_after_shrink() {
        let (mut a, mut b) = pair(config(4, 4), u32::MAX - 2);
        a.write(b"abcd").unwrap();
        let edge = b.advertised_edge;
        deliver(&mut a, &mut b, 40);
        let bytes = deliver(&mut b, &mut a, 50);
        assert_eq!(
            wire::parse(ip(reverse(tuple())), &bytes)
                .unwrap()
                .header
                .window,
            0
        );
        assert_eq!(b.advertised_edge, edge);
        a.write(b"efgh").unwrap();
        for _ in 0..10 {
            let deadline = a.persist_deadline.unwrap();
            a.timeout(deadline).unwrap();
            let bytes = deliver(&mut a, &mut b, deadline);
            assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload.len(), 1);
            b.timeout(deadline).unwrap();
            let bytes = deliver(&mut b, &mut a, deadline);
            assert_eq!(
                wire::parse(ip(reverse(tuple())), &bytes)
                    .unwrap()
                    .header
                    .window,
                0
            );
            assert_eq!(b.receive.readable(), 4);
            assert_eq!(b.advertised_edge, edge);
            assert_eq!(b.user_deadline(), None);
            assert_eq!(a.state(), State::Established);
        }
        // No response to the next probe: retain the resource/liveness bound.
        let when = a.persist_deadline.unwrap();
        a.timeout(when).unwrap();
        packet(&mut a, when);
        let deadline = a.user_deadline().unwrap();
        a.timeout(deadline).unwrap();
        assert_eq!(a.close_reason(), Some(CloseReason::TimedOut));
        b.timeout(deadline).unwrap();
        assert_eq!(b.state(), State::Established);
        assert_eq!(b.advertised_window(false), 0);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
    //= type=test
    //# If the window shrinks to zero, the TCP
    //# implementation MUST probe it in the standard way (described below)
    //# (MUST-35).
    fn shrink_to_zero_with_outstanding_bytes_probes_and_validates_liveness_feedback() {
        for iss in [100, u32::MAX - 4] {
            let (mut a, _) = pair(config(64, 8), iss);
            a.write(b"abcdefgh").unwrap();
            packet(&mut a, 40);
            let seq = a.receive.next();
            let una = a.snd_una;
            let high = a.snd_nxt;
            inject(&mut a, 50, seq, una, ACK, 0, b"");
            assert_eq!(a.rto_deadline, None);
            assert_eq!(a.user_deadline(), None);
            let when = a.persist_deadline.unwrap();
            a.timeout(when).unwrap();
            let bytes = packet(&mut a, when);
            let probe = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(probe.header.sequence, una.0);
            assert_eq!(probe.payload, b"a");
            assert_eq!(a.snd_nxt, high);
            assert_eq!(a.send.len(), 8);
            let deadline = a.user_deadline();
            inject(
                &mut a,
                when + 1,
                seq,
                una.wrapping_add(u32::MAX),
                ACK,
                64,
                b"",
            );
            assert_eq!(a.user_deadline(), deadline);
            assert_eq!(a.snd_wnd, 0);
            inject(&mut a, when + 2, seq, una, ACK, 0, b"");
            assert_eq!(a.user_deadline(), None);
            inject(&mut a, when + 3, seq, una, ACK, 64, b"");
            assert_eq!(a.persist_deadline, None);
            assert_eq!(a.user_deadline(), Some(when + 3 + a.user_timeout()));
            let when = a.rto_deadline.unwrap();
            a.timeout(when).unwrap();
            let bytes = packet(&mut a, when);
            assert_eq!(
                wire::parse(ip(tuple()), &bytes).unwrap().payload,
                b"abcdefgh"
            );
        }
    }
    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
    //= type=test
    //# but SHOULD NOT
    //# time out the connection if data beyond the right window edge is not
    //# acknowledged (SHLD-17).
    fn shrink_peer_replying_only_to_retransmissions_survives_long_backoff() {
        for iss in [100, u32::MAX - 4] {
            let mut cfg = config(64, 8);
            cfg.user_timeout_us = 5_000_000;
            let (mut a, _) = pair(cfg, iss);
            a.write(b"abcdefgh").unwrap();
            packet(&mut a, 40);
            let seq = a.receive.next();
            let una = a.snd_una;
            inject(&mut a, 50, seq, una, ACK, 3, b"");
            for _ in 0..6 {
                assert_eq!(a.user_deadline(), None);
                let when = a.next_deadline().unwrap();
                assert_eq!(Some(when), a.rto_deadline);
                a.timeout(when).unwrap();
                assert_eq!(a.state(), State::Established);
                let bytes = packet(&mut a, when);
                let retransmit = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(retransmit.header.sequence, una.0);
                assert_eq!(retransmit.payload, b"abc");
                assert_eq!(a.user_deadline(), Some(when + 5_000_000));
                // No unsolicited feedback between emitted retransmissions.
                inject(&mut a, when + 1, seq, una, ACK, 3, b"");
                assert_eq!(a.shrink_unanswered_since, None);
                assert_eq!(a.flight(), 8);
                assert_eq!(a.send.len(), 8);
            }
            assert!(a.rto() > a.user_timeout());
            let when = a.next_deadline().unwrap();
            a.timeout(when).unwrap();
            packet(&mut a, when);
            // Reopening to exactly flight restores the ordinary progress timer.
            inject(&mut a, when + 1, seq, una, ACK, 8, b"");
            assert_eq!(a.shrink_unanswered_since, None);
            assert_eq!(a.user_deadline(), Some(when + 1 + 5_000_000));
            a.timeout(a.user_deadline().unwrap()).unwrap();
            assert_eq!(a.close_reason(), Some(CloseReason::TimedOut));
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
    //= type=test
    //= reason=Checks both retransmission policies and survival beyond the user timeout while the shrunken peer answers without ACK progress.
    //# The sender MAY also
    //# retransmit old data beyond SND.UNA+SND.WND (MAY-7), but SHOULD NOT
    //# time out the connection if data beyond the right window edge is not
    //# acknowledged (SHLD-17).
    #[test]
    fn optional_beyond_window_retransmission_never_sends_new_bytes() {
        for iss in [100, u32::MAX - 3] {
            for enabled in [false, true] {
                let mut cfg = config(64, 8);
                cfg.retransmit_beyond_window = enabled;
                cfg.user_timeout_us = 5_000_000;
                let (mut a, _) = pair(cfg, iss);
                a.write(b"abcdefghijklmnop").unwrap();
                packet(&mut a, 40); // Only the first eight bytes have been sent.
                let seq = a.receive.next();
                let una = a.snd_una;
                let next = a.snd_nxt;
                inject(&mut a, 50, seq, una, ACK, 3, b"");
                assert_eq!(a.transmit(60, &mut [0; 64]), Ok(None));
                let deadline = a.rto_deadline.unwrap();
                a.timeout(deadline).unwrap();
                let retry = packet(&mut a, deadline);
                let segment = wire::parse(ip(tuple()), &retry).unwrap();
                assert_eq!(segment.header.sequence, una.0);
                assert_eq!(
                    segment.payload,
                    if enabled { &b"abcdefgh"[..] } else { b"abc" }
                );
                assert_eq!(a.last_output_ecn(), 0);
                assert_eq!(a.snd_nxt, next);
                assert_eq!(a.send.len(), 16);
                let mut last = deadline;
                for _ in 0..6 {
                    inject(&mut a, last + 1, seq, una, ACK, 3, b"");
                    assert_eq!(a.user_deadline(), None);
                    last = a.rto_deadline.unwrap();
                    a.timeout(last).unwrap();
                    assert_eq!(a.state(), State::Established);
                    let retry = packet(&mut a, last);
                    assert_eq!(
                        wire::parse(ip(tuple()), &retry).unwrap().payload,
                        if enabled { &b"abcdefgh"[..] } else { b"abc" }
                    );
                    assert_eq!(a.snd_nxt, next);
                }
                assert!(last - 50 > a.user_timeout());
                inject(&mut a, last + 1, seq, una, ACK, 0, b"");
                let deadline = a.persist_deadline.unwrap();
                a.timeout(deadline).unwrap();
                let probe = packet(&mut a, deadline);
                assert_eq!(wire::parse(ip(tuple()), &probe).unwrap().payload, b"a");
                assert_eq!(a.snd_nxt, next);
            }
        }
    }

    #[test]
    fn ecn_duplex_reordering_old_ack_preserves_receive_feedback() {
        for iss in [100, u32::MAX - 63] {
            let (mut a, mut b) = pair(config(1024, 64), iss);
            a.write(&[1; 192]).unwrap();
            let old_cwr = packet(&mut a, 40);
            let ce = packet(&mut a, 40);
            let new_cwr = packet(&mut a, 40);
            let old_ack = b.snd_una;
            // Reverse-direction data is ACKed while the duplex packets are delayed.
            b.write(&[2; 128]).unwrap();
            deliver(&mut b, &mut a, 41);
            packet(&mut b, 41); // Leave some reverse-direction data in flight.
            a.immediate_ack();
            deliver(&mut a, &mut b, 42);
            assert_eq!(b.snd_una, old_ack.wrapping_add(64));
            assert_eq!(b.flight(), 64);
            let cwnd = b.congestion.cwnd();
            let mut ce = wire::parse(ip(tuple()), &ce).unwrap();
            assert_eq!(Seq(ce.header.acknowledgment), old_ack);
            ce.header.flags |= ECE;
            b.input_with_traffic_class(43, 3, &ce).unwrap();
            assert!(b.ecn_echo);
            assert_eq!(b.congestion.cwnd(), cwnd); // Stale ECE is still ignored.
            assert!(!b.ecn_cwr_pending);
            let echo = packet(&mut b, 43);
            assert_ne!(
                wire::parse(ip(reverse(tuple())), &echo)
                    .unwrap()
                    .header
                    .flags
                    & ECE,
                0
            );
            // The earlier CWR is sequence-valid (fills the hole), but predates CE.
            let mut old_cwr = wire::parse(ip(tuple()), &old_cwr).unwrap();
            old_cwr.header.flags |= CWR;
            b.input(44, &old_cwr).unwrap();
            assert!(b.ecn_echo);
            let echo = packet(&mut b, 44);
            assert_ne!(
                wire::parse(ip(reverse(tuple())), &echo)
                    .unwrap()
                    .header
                    .flags
                    & ECE,
                0
            );
            // A later CWR clears CE even though its duplex ACK is also old.
            let mut new_cwr = wire::parse(ip(tuple()), &new_cwr).unwrap();
            new_cwr.header.flags |= CWR;
            b.input(45, &new_cwr).unwrap();
            assert!(!b.ecn_echo);
            assert_eq!(b.ecn_ce_end, None);
            assert_eq!(b.read(&mut [0; 192]), Ok(192));
        }
    }

    #[test]
    fn ecn_rto_distinguishes_emitted_retransmission_from_pending_original_loss() {
        for iss in [100, u32::MAX - 20_000] {
            for emit_partial_retransmission in [false, true] {
                let (mut a, _) = pair(config(32_000, 1000), iss);
                let seq = a.receive.next();
                // Grow a real send window to sixteen MSS before inducing congestion.
                for _ in 0..12 {
                    a.write(&[1; 1000]).unwrap();
                    packet(&mut a, 40);
                    let ack = a.snd_nxt;
                    inject(&mut a, 40, seq, ack, ACK, 32_000, b"");
                }
                a.write(&[2; 16_000]).unwrap();
                for _ in 0..16 {
                    packet(&mut a, 41);
                }
                assert_eq!(a.flight(), 16_000);
                let una = a.snd_una;
                for _ in 0..3 {
                    inject(&mut a, 42, seq, una, ACK | ECE, 32_000, b"");
                }
                assert_eq!(a.congestion.ssthresh(), 8000);
                assert!(a.retx_pending);
                packet(&mut a, 43); // Fast retransmit is delivered; its ACK is partial.
                inject(&mut a, 44, seq, una.wrapping_add(12_000), ACK, 32_000, b"");
                assert_eq!(a.flight(), 4000);
                assert!(a.retx_pending);
                assert_eq!(a.transmit(45, &mut [0; 20]), Err(Error::OutputTooSmall));
                if emit_partial_retransmission {
                    let bytes = packet(&mut a, 45); // This retransmission is lost.
                    let segment = wire::parse(ip(tuple()), &bytes).unwrap();
                    assert_eq!(segment.header.sequence, a.snd_una.0);
                    assert_eq!(segment.payload.len(), 1000);
                }
                let deadline = a.rto_deadline.unwrap();
                a.timeout(deadline).unwrap();
                let threshold = if emit_partial_retransmission {
                    2000
                } else {
                    8000
                };
                assert_eq!(a.congestion.ssthresh(), threshold);
                assert_eq!(a.congestion.cwnd(), 1000);
                packet(&mut a, deadline);
                a.timeout(a.rto_deadline.unwrap()).unwrap();
                assert_eq!(a.congestion.ssthresh(), threshold); // Repeated RTO.
            }
        }
    }

    #[test]
    fn ecn_validation_wrap_repeated_marks_and_transactional_output() {
        let (mut a, mut b) = pair(config(1024, 64), u32::MAX - 63);
        a.write(&[1; 128]).unwrap();
        let data = packet(&mut a, 40);
        assert_eq!(a.last_output_ecn(), 2);
        let data2 = packet(&mut a, 40);
        let parsed = wire::parse(ip(tuple()), &data).unwrap();
        let mut segment = wire::parse(ip(tuple()), &data).unwrap();
        // Rejected sequence, missing ACK and out-of-range ACKs never latch CE.
        for (seq, ack, flags) in [
            (
                parsed.header.sequence.wrapping_sub(64),
                parsed.header.acknowledgment,
                ACK,
            ),
            (
                parsed.header.sequence.wrapping_add(4096),
                parsed.header.acknowledgment,
                ACK,
            ),
            (parsed.header.sequence, parsed.header.acknowledgment, 0),
            (
                parsed.header.sequence,
                parsed.header.acknowledgment.wrapping_add(1),
                ACK,
            ),
            (
                parsed.header.sequence,
                parsed.header.acknowledgment.wrapping_sub(b.max_snd_wnd + 1),
                ACK,
            ),
        ] {
            segment.header.sequence = seq;
            segment.header.acknowledgment = ack;
            segment.header.flags = flags;
            b.input_with_traffic_class(40, 3, &segment).unwrap();
            assert!(!b.ecn_echo);
        }
        b.input_with_traffic_class(40, 3, &parsed).unwrap();
        assert!(b.ecn_echo);
        let ece = packet(&mut b, 40);
        let mut feedback = wire::parse(ip(reverse(tuple())), &ece).unwrap();
        let cwnd = a.congestion.cwnd();
        // ECE cannot bypass the future ACK check.
        let valid_ack = feedback.header.acknowledgment;
        feedback.header.acknowledgment = a.snd_nxt.wrapping_add(1).0;
        a.input(40, &feedback).unwrap();
        assert_eq!(a.congestion.cwnd(), cwnd);
        assert!(!a.ecn_cwr_pending);
        feedback.header.acknowledgment = valid_ack;
        a.input(40, &feedback).unwrap();
        let reduced = a.congestion.cwnd();
        assert!(reduced < cwnd);
        assert!(!a.retx_pending);
        for _ in 0..2 {
            a.input(40, &feedback).unwrap();
            assert_eq!(a.congestion.cwnd(), reduced);
        }
        // Finish this flight with repeated CE; equality with the epoch end cannot reduce twice.
        let parsed2 = wire::parse(ip(tuple()), &data2).unwrap();
        b.input_with_traffic_class(40, 3, &parsed2).unwrap();
        let ece = packet(&mut b, 40);
        a.input(40, &wire::parse(ip(reverse(tuple())), &ece).unwrap())
            .unwrap();
        assert_eq!(a.congestion.cwnd(), reduced);
        a.write(&[2; 64]).unwrap();
        let before = (a.snd_nxt, a.last_output_ecn(), a.ecn_cwr_pending, a.now);
        assert_eq!(a.transmit(41, &mut [0; 20]), Err(Error::OutputTooSmall));
        assert_eq!(
            (a.snd_nxt, a.last_output_ecn(), a.ecn_cwr_pending, a.now),
            before
        );
        let cwr = packet(&mut a, 41);
        let cwr = wire::parse(ip(tuple()), &cwr).unwrap();
        assert_ne!(cwr.header.flags & CWR, 0);
        // A newly marked CWR packet starts (or preserves) echo, rather than clearing CE.
        b.input_with_traffic_class(41, 3, &cwr).unwrap();
        assert!(b.ecn_echo);
        let ece = packet(&mut b, 41);
        a.input(41, &wire::parse(ip(reverse(tuple())), &ece).unwrap())
            .unwrap();
        assert!(a.ecn_cwr_pending); // Next flight can signal a new congestion episode.
        a.write(&[3; 64]).unwrap();
        let cwr2 = packet(&mut a, 42);
        b.input(42, &wire::parse(ip(tuple()), &cwr2).unwrap())
            .unwrap();
        assert!(!b.ecn_echo);
        assert_eq!(b.ecn_ce_end, None);
        // An old CE/CWR retransmission is outside the receive window.
        b.input_with_traffic_class(42, 3, &cwr).unwrap();
        assert!(!b.ecn_echo);
        a.abort();
        packet(&mut a, 42);
        assert_eq!(a.last_output_ecn(), 0);
    }

    #[test]
    fn ecn_one_mss_waits_rto_and_zero_window_probe_is_not_ect() {
        let (mut a, mut b) = pair(config(1024, 64), 10);
        // Model a previous timeout followed by enough ACK progress to leave recovery.
        a.congestion
            .on_timeout(64, a.snd_una.wrapping_add(u32::MAX));
        a.write(&[1; 128]).unwrap();
        let data = packet(&mut a, 40);
        b.input_with_traffic_class(40, 3, &wire::parse(ip(tuple()), &data).unwrap())
            .unwrap();
        deliver(&mut b, &mut a, 40);
        assert_eq!(a.congestion.cwnd(), 64);
        let pause = a.ecn_pause.unwrap();
        assert_eq!(a.transmit(pause - 1, &mut [0; 2048]), Ok(None));
        a.timeout(pause).unwrap();
        let data = packet(&mut a, pause);
        assert_eq!(a.last_output_ecn(), 2);
        assert_ne!(
            wire::parse(ip(tuple()), &data).unwrap().header.flags & CWR,
            0
        );
        // Closed offered window; persist probes cannot carry ECT or CWR.
        a.snd_wnd = 0;
        a.ecn_cwr_pending = true;
        a.arm_work();
        let deadline = a.persist_deadline.unwrap();
        a.timeout(deadline).unwrap();
        let probe = packet(&mut a, deadline);
        assert_eq!(a.last_output_ecn(), 0);
        assert_eq!(
            wire::parse(ip(tuple()), &probe).unwrap().header.flags & CWR,
            0
        );
        assert!(a.ecn_cwr_pending);
    }

    #[test]
    fn ecn_fallback_retains_receive_commitment() {
        let cfg = config(1024, 64);
        let mut a = Connection::active(tuple(), cfg.clone(), 10, 0).unwrap();
        let syn = packet(&mut a, 0);
        let mut b = Connection::passive(
            reverse(tuple()),
            cfg,
            900,
            0,
            &wire::parse(ip(tuple()), &syn).unwrap(),
        )
        .unwrap();
        let synack = packet(&mut b, 0);
        a.timeout(1_000_000).unwrap();
        packet(&mut a, 1_000_000); // Lost plain SYN, delayed ECN SYN-ACK arrives instead.
        a.input(
            1_000_000,
            &wire::parse(ip(reverse(tuple())), &synack).unwrap(),
        )
        .unwrap();
        deliver(&mut a, &mut b, 1_000_000);
        assert!(!a.ecn_send());
        assert!(a.ecn_feedback());
        b.write(&[0; 64]).unwrap();
        let data = packet(&mut b, 1_000_001);
        assert_eq!(b.last_output_ecn(), 2);
        a.input_with_traffic_class(
            1_000_001,
            3,
            &wire::parse(ip(reverse(tuple())), &data).unwrap(),
        )
        .unwrap();
        assert!(a.ecn_echo);
    }
    #[test]
    fn ecn_setup_output_is_atomic_and_synack_flags_are_not_echoed_reserved_bits() {
        for flags in [0, ECE, CWR, ECE | CWR] {
            let cfg = config(1024, 64);
            let mut a = Connection::active(tuple(), cfg.clone(), 10, 0).unwrap();
            assert_eq!(a.transmit(1, &mut [0; 19]), Err(Error::OutputTooSmall));
            assert!(!a.ecn_sent_setup && !a.ecn_sent_plain);
            assert_eq!(a.last_output_ecn(), 0);
            let syn = packet(&mut a, 1);
            let mut b = Connection::passive(
                reverse(tuple()),
                cfg,
                900,
                1,
                &wire::parse(ip(tuple()), &syn).unwrap(),
            )
            .unwrap();
            let synack = packet(&mut b, 1);
            let mut parsed = wire::parse(ip(reverse(tuple())), &synack).unwrap();
            parsed.header.flags = SYN | ACK | flags;
            a.input(1, &parsed).unwrap();
            assert_eq!(a.ecn_send(), flags == ECE);
            a.write(&[1; 64]).unwrap();
            packet(&mut a, 1);
            assert_eq!(a.last_output_ecn(), if flags == ECE { 2 } else { 0 });
        }
    }

    #[test]
    fn shrink_silence_times_out_from_first_committed_unanswered_retransmission() {
        for iss in [100, u32::MAX - 4] {
            let mut cfg = config(64, 8);
            cfg.user_timeout_us = 5_000_000;
            let (mut a, _) = pair(cfg, iss);
            a.write(b"abcdefgh").unwrap();
            packet(&mut a, 40);
            let seq = a.receive.next().wrapping_add(1);
            let una = a.snd_una;
            inject(&mut a, 50, seq, una, ACK, 3, b"");
            assert_eq!(a.transmit(60, &mut [0; 64]), Ok(None));
            assert_eq!(a.shrink_unanswered_since, None);
            let when = a.next_deadline().unwrap();
            a.timeout(when).unwrap();
            assert_eq!(a.user_deadline(), None);
            let before = (a.now, a.next_deadline(), a.retx_pending);
            assert_eq!(
                a.transmit(when + 1, &mut [0; 22]),
                Err(Error::OutputTooSmall)
            );
            assert_eq!((a.now, a.next_deadline(), a.retx_pending), before);
            assert_eq!(a.shrink_unanswered_since, None);
            // Adapter backpressure is not peer silence either.
            let sent = when + 6_000_000;
            a.timeout(sent).unwrap();
            assert_eq!(a.state(), State::Established);
            packet(&mut a, sent);
            let deadline = sent + 5_000_000;
            assert_eq!(a.shrink_unanswered_since, Some(sent));
            assert_eq!(a.user_deadline(), Some(deadline));
            let when = a.next_deadline().unwrap();
            assert!(when < deadline);
            a.timeout(when).unwrap();
            packet(&mut a, when);
            assert_eq!(a.shrink_unanswered_since, Some(sent));
            assert_eq!(a.user_deadline(), Some(deadline));
            // Both an old ACK and a stale window SEQ must leave the first
            // unanswered timestamp intact, even if they advertise reopening.
            for (seq, ack) in [(seq, una.wrapping_add(u32::MAX)), (a.receive.next(), una)] {
                inject(&mut a, when + 1, seq, ack, ACK, 64, b"");
                assert_eq!(a.shrink_unanswered_since, Some(sent));
                assert_eq!(a.user_deadline(), Some(deadline));
                assert_eq!(a.snd_wnd, 3);
            }
            assert_eq!(a.next_deadline(), Some(deadline));
            a.timeout(deadline - 1).unwrap();
            assert_eq!(a.state(), State::Established);
            a.timeout(deadline).unwrap();
            assert_eq!(a.close_reason(), Some(CloseReason::TimedOut));
            assert_eq!(a.shrink_unanswered_since, None);
        }
    }

    #[test]
    fn ecn_synack_timeout_fallback_and_invalid_handshake_ack() {
        let cfg = config(1024, 64);
        let mut a = Connection::active(tuple(), cfg.clone(), 10, 0).unwrap();
        let syn = packet(&mut a, 0);
        let mut b = Connection::passive(
            reverse(tuple()),
            cfg,
            900,
            0,
            &wire::parse(ip(tuple()), &syn).unwrap(),
        )
        .unwrap();
        packet(&mut b, 0); // Lost setup SYN-ACK.
        let mut invalid = wire::parse(ip(tuple()), &syn).unwrap();
        invalid.header.flags = SYN | ACK;
        invalid.header.acknowledgment = 123;
        b.input(0, &invalid).unwrap();
        assert!(!b.ecn_peer_plain);
        b.timeout(1_000_000).unwrap();
        let fallback = packet(&mut b, 1_000_000);
        assert_eq!(
            wire::parse(ip(reverse(tuple())), &fallback)
                .unwrap()
                .header
                .flags,
            SYN | ACK
        );
        a.input(
            1_000_000,
            &wire::parse(ip(reverse(tuple())), &fallback).unwrap(),
        )
        .unwrap();
        deliver(&mut a, &mut b, 1_000_000);
        assert!(!a.ecn_send() && !b.ecn_send());
        assert!(b.ecn_feedback()); // Original receive promise is retained.
    }

    #[test]
    fn ecn_reordered_cwr_cannot_clear_newer_ce() {
        let (mut a, mut b) = pair(config(1024, 64), u32::MAX - 127);
        a.write(&[1; 192]).unwrap();
        packet(&mut a, 40); // Keep a receive hole so older CWR remains in-window.
        let old = packet(&mut a, 40);
        let marked = packet(&mut a, 40);
        b.input_with_traffic_class(40, 3, &wire::parse(ip(tuple()), &marked).unwrap())
            .unwrap();
        let mut old = wire::parse(ip(tuple()), &old).unwrap();
        old.header.flags |= CWR;
        b.input(40, &old).unwrap();
        assert!(b.ecn_echo);
        let ack = packet(&mut b, 40);
        assert_ne!(
            wire::parse(ip(reverse(tuple())), &ack)
                .unwrap()
                .header
                .flags
                & ECE,
            0
        );
    }
    #[test]
    fn ecn_idle_window_reduction_signals_cwr_on_committed_fresh_data() {
        let (mut a, mut b) = pair(config(1024, 64), 10);
        a.write(&[0; 64]).unwrap();
        deliver(&mut a, &mut b, 40);
        b.timeout(200_040).unwrap();
        deliver(&mut b, &mut a, 200_040);
        assert!(a.congestion.cwnd() > a.initial_window());
        a.write(&[0; 64]).unwrap();
        let now = 200_040 + a.rto();
        let before = a.congestion.cwnd();
        assert_eq!(a.transmit(now, &mut [0; 19]), Err(Error::OutputTooSmall));
        assert_eq!(a.congestion.cwnd(), before);
        let data = packet(&mut a, now);
        assert_eq!(a.congestion.cwnd(), a.initial_window());
        assert_ne!(
            wire::parse(ip(tuple()), &data).unwrap().header.flags & CWR,
            0
        );
        assert_eq!(a.last_output_ecn(), 2);
    }
    #[test]
    fn ecn_valid_cwr_control_clears_echo_but_pure_ack_ce_does_not_set_it() {
        let (mut a, mut b) = pair(config(1024, 64), 10);
        a.write(&[0; 64]).unwrap();
        let data = packet(&mut a, 40);
        let mut control = wire::parse(ip(tuple()), &data).unwrap();
        b.input_with_traffic_class(40, 3, &control).unwrap();
        assert!(b.ecn_echo);
        control.header.sequence = a.snd_nxt.0;
        control.header.flags = ACK | CWR;
        control.payload = &[];
        b.input_with_traffic_class(40, 3, &control).unwrap();
        assert!(!b.ecn_echo);
        assert_eq!(b.ecn_ce_end, None);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
    //= type=test
    //# A TCP endpoint MAY implement PUSH flags on SEND calls (MAY-15).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
    //= type=test
    //# When an application issues a series of SEND calls without setting the PUSH
    //# flag, the TCP implementation MAY aggregate the data internally without
    //# sending it (MAY-16).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
    //= type=test
    //= reason=Explicit PUSH marks survive packetization and partial acknowledgment; Nagle still applies.
    //# If the PUSH flag is set, the application intends the data to be transmitted promptly to
    //# the receiver, and the PSH bit will be set in the last TCP segment created from the
    //# buffer.
    fn explicit_push_aggregates_crosses_marks_and_retransmits_after_partial_ack() {
        let (mut a, _) = pair(config(16, 8), u32::MAX - 3);
        a.set_nagle(false);
        a.write_with_push(b"ab", false).unwrap();
        assert_eq!(a.transmit(40, &mut [0; 64]), Ok(None));
        a.write_with_push(b"cd", true).unwrap();
        a.write_with_push(b"efghij", false).unwrap();
        let before = (a.snd_nxt, a.send.len(), a.next_deadline());
        assert_eq!(a.transmit(40, &mut [0; 27]), Err(Error::OutputTooSmall));
        assert_eq!((a.snd_nxt, a.send.len(), a.next_deadline()), before);
        let bytes = packet(&mut a, 40);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.payload, b"abcdefgh");
        assert_ne!(segment.header.flags & PSH, 0); // Crossed cd, not a record boundary.
        let ack = a.send_base.wrapping_add(2);
        inject(&mut a, 50, Seq(901), ack, ACK, 16, b"");
        a.retx_pending = true;
        let bytes = packet(&mut a, 60);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.payload, b"cdefgh");
        assert_ne!(segment.header.flags & PSH, 0);
        let ack = a.send_base.wrapping_add(4); // Past original PUSH, before wire PSH.
        inject(&mut a, 65, Seq(901), ack, ACK, 16, b"");
        a.retx_pending = true;
        let bytes = packet(&mut a, 66);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.payload, b"gh");
        assert_ne!(segment.header.flags & PSH, 0);
        let ack = a.snd_nxt;
        inject(&mut a, 70, Seq(901), ack, ACK, 16, b"");
        assert_eq!(a.transmit(80, &mut [0; 64]), Ok(None));
        a.write_with_push(b"", true).unwrap();
        let bytes = packet(&mut a, 80);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.payload, b"ij");
        assert_ne!(segment.header.flags & PSH, 0);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
    //= type=test
    //= reason=Tests automatic-PUSH write packetization and deadline-serviced aggregation; explicit PUSH is implemented, so the conditional is not a claim about write_with_push(false).
    //# If
    //# PUSH flags are not implemented, then the sending TCP peer: (1) MUST
    //# NOT buffer data indefinitely (MUST-60), and (2) MUST set the PSH bit
    //# in the last buffered segment (i.e., when there is no more queued data
    //# to be sent) (MUST-61).
    fn automatic_push_final_segment_partial_write_and_bounded_aggregation() {
        let (mut a, _) = pair(config(10, 8), 100);
        a.set_nagle(false);
        assert_eq!(a.write(b"abcdefghijkl"), Ok(10));
        assert_eq!(a.write_with_push(b"x", false), Err(Error::WouldBlock));
        for (expected, pushed) in [(&b"abcdefgh"[..], false), (&b"ij"[..], true)] {
            let bytes = packet(&mut a, 40);
            let segment = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(segment.payload, expected);
            assert_eq!(segment.header.flags & PSH != 0, pushed);
        }
        let (mut a, _) = pair(config(16, 8), 100);
        a.write_with_push(b"abc", false).unwrap();
        assert_eq!(a.transmit(40, &mut [0; 64]), Ok(None));
        let deadline = a.sws_deadline.unwrap();
        a.timeout(deadline).unwrap();
        let bytes = packet(&mut a, deadline);
        assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, b"abc");

        let (mut a, _) = pair(config(16, 8), 100);
        a.write_with_push(b"abc", false).unwrap();
        a.shutdown().unwrap();
        let bytes = packet(&mut a, 40);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.payload, b"abc");
        assert_ne!(segment.header.flags & FIN, 0);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.7
    //= type=test
    //# The FLUSH call MAY be implemented (MAY-14).
    fn flush_retains_advertised_urgency_and_push_after_partial_ack() {
        let (mut a, _) = pair(config(16, 8), u32::MAX - 3);
        a.write_with_push(b"ab", true).unwrap();
        a.write_urgent(b"cdefghijklmnop").unwrap();
        packet(&mut a, 40);
        let ack = a.send_base.wrapping_add(2);
        inject(&mut a, 50, Seq(901), ack, ACK, 6, b"");
        let next = a.snd_nxt;
        let urgent_end = a.send_base.wrapping_add(14);
        assert_eq!(a.flush(), Ok(0));
        assert_eq!(a.send.len(), 14);
        assert_eq!(a.snd_nxt, next);
        assert_eq!(a.snd_up, Some(urgent_end));
        assert_eq!(a.advertised_snd_up, Some(urgent_end));
        assert!(a.take_events().writable);
        a.retx_pending = true;
        let bytes = packet(&mut a, 60);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.payload, b"cdefgh");
        assert_ne!(segment.header.flags & PSH, 0); // Retained on-wire mark survives the partial ACK.
        assert_eq!(segment.header.urgent_pointer, 14);
        inject(&mut a, 70, Seq(901), next, ACK, 16, b"");
        let bytes = packet(&mut a, 71);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().payload,
            b"ijklmnop"
        );
        inject(&mut a, 72, Seq(901), urgent_end, ACK, 16, b"");
        assert_eq!(a.advertised_snd_up, None);
        let next = a.snd_nxt;
        a.write(b"new").unwrap();
        let bytes = packet(&mut a, 80);
        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(segment.header.sequence, next.0);
        assert_eq!(segment.payload, b"new");
        assert_ne!(segment.header.flags & PSH, 0);
        assert_eq!(segment.header.flags & URG, 0);
        a.shutdown().unwrap();
        assert_eq!(a.flush(), Err(Error::InvalidState));
        a.abort();
        assert_eq!(a.flush(), Err(Error::InvalidState));

        let mut a = Connection::active(tuple(), config(16, 8), 100, 0).unwrap();
        a.write_urgent(b"queued").unwrap();
        assert_eq!(a.flush(), Ok(6));
        assert_eq!(a.snd_nxt, Seq(100));
        assert_eq!(a.snd_up, None);
        a.write(b"new").unwrap();
        packet(&mut a, 0); // Flushing SYN-SENT must not discard or advance SYN.
        assert_eq!(a.snd_nxt, Seq(101));
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.7
    //= type=test
    //# The FLUSH call MAY be implemented (MAY-14).
    fn flush_cannot_reclassify_replacement_bytes_as_urgent_at_peer() {
        for iss in [100, u32::MAX - 3] {
            let (mut a, mut b) = pair(config(16, 8), iss);
            a.write_urgent(b"abcdefghijklmnop").unwrap();
            let bytes = deliver(&mut a, &mut b, 40);
            assert_eq!(
                wire::parse(ip(tuple()), &bytes)
                    .unwrap()
                    .header
                    .urgent_pointer,
                16
            );
            assert_eq!(a.flush(), Ok(0));
            assert_eq!(a.write(b"ordinary"), Err(Error::WouldBlock));
            let mut out = [0; 8];
            assert_eq!(b.read(&mut out), Ok(8));
            assert_eq!(&out, b"abcdefgh");
            assert_eq!(b.urgent_remaining(), 8);
            deliver(&mut b, &mut a, 50);
            assert_eq!(a.write(b"ordinary"), Ok(8));
            let bytes = deliver(&mut a, &mut b, 60);
            assert_eq!(
                wire::parse(ip(tuple()), &bytes).unwrap().payload,
                b"ijklmnop"
            );
            assert_eq!(b.read(&mut out), Ok(8));
            assert_eq!(b.urgent_remaining(), 0);
            deliver(&mut b, &mut a, 70);
            let bytes = deliver(&mut a, &mut b, 80);
            let segment = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(segment.payload, b"ordinary");
            assert_eq!(segment.header.flags & URG, 0);
            assert_eq!(b.urgent_remaining(), 0);
            assert_eq!(b.read(&mut out), Ok(8));
            assert_eq!(&out, b"ordinary");
            assert_eq!(a.send.capacity(), 16);
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.7
    //= type=test
    //# The FLUSH call MAY be implemented (MAY-14).
    fn flush_retains_offered_window_not_congestion_window() {
        for (window, discarded) in [(8, 4), (12, 0), (16, 0), (0, 12)] {
            let (mut a, _) = pair(config(16, 2), u32::MAX - 3);
            let base = a.send_base;
            inject(&mut a, 40, Seq(901), base, ACK, window, b"");
            assert_eq!(a.snd_wnd, window as u32);
            assert!(a.congestion.cwnd() < 12);
            a.write(b"abcdefghijkl").unwrap();
            assert_eq!(a.flight(), 0);
            a.take_events();
            assert_eq!(a.flush(), Ok(discarded));
            assert_eq!(a.send.len(), 12 - discarded);
            assert_eq!(a.snd_nxt, base);
            assert_eq!(a.take_events().writable, discarded != 0);
            // Reopening and replacing the suffix must not create a sequence hole.
            inject(&mut a, 50, Seq(901), base, ACK, 16, b"");
            a.write(b"XY").unwrap();
            let bytes = packet(&mut a, 60);
            let segment = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(segment.header.sequence, base.0);
            assert_eq!(segment.payload, if window == 0 { b"XY" } else { b"ab" });
        }
    }

    #[test]
    fn flush_shrunk_window_retains_flight_after_partial_ack_and_wrap() {
        for window in [0, 2, 8] {
            let (mut a, _) = pair(config(16, 8), u32::MAX - 3);
            a.write(b"abcdefgh").unwrap();
            a.write(b"ijklmnop").unwrap();
            packet(&mut a, 40);
            let next = a.snd_nxt;
            let ack = a.send_base.wrapping_add(5);
            assert_eq!(ack, Seq(2));
            inject(&mut a, 50, Seq(901), ack, ACK, window, b"");
            let retained = 3usize.max(window as usize);
            assert_eq!(a.flush(), Ok(11 - retained));
            assert_eq!(a.send.len(), retained);
            assert_eq!(a.snd_nxt, next);
            inject(&mut a, 60, Seq(901), ack, ACK, 16, b"");
            a.retx_pending = true;
            let bytes = packet(&mut a, 61);
            let segment = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(segment.header.sequence, ack.0);
            assert_eq!(segment.payload, b"fgh");
            assert_ne!(segment.header.flags & PSH, 0);
            inject(&mut a, 70, Seq(901), next, ACK, 16, b"");
            a.write(b"XY").unwrap();
            let bytes = packet(&mut a, 71);
            let segment = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(segment.header.sequence, next.0);
            assert_eq!(
                segment.payload,
                if window == 8 { &b"ijklmXY"[..] } else { b"XY" }
            );
        }
    }

    #[test]
    fn flush_handshake_window_accounts_for_syn_sequence_space() {
        for iss in [100, u32::MAX] {
            for sent_syn in [false, true] {
                let mut a = Connection::active(tuple(), config(16, 8), iss, 0).unwrap();
                if sent_syn {
                    packet(&mut a, 0);
                }
                a.write(b"queued").unwrap();
                let next = a.snd_nxt;
                assert_eq!(a.flush(), Ok(6)); // No window offered in SYN-SENT.
                assert_eq!(a.snd_nxt, next);
                assert_eq!(a.send_base, Seq(iss).wrapping_add(1));

                for window in [0, 1, 8] {
                    let mut peer = Connection::active(tuple(), config(16, 8), 900, 0).unwrap();
                    let bytes = packet(&mut peer, 0);
                    let mut syn = wire::parse(ip(tuple()), &bytes).unwrap();
                    syn.header.window = window;
                    let mut b =
                        Connection::passive(reverse(tuple()), config(16, 8), iss, 0, &syn).unwrap();
                    if sent_syn {
                        packet(&mut b, 0);
                    }
                    assert_eq!(b.state(), State::SynReceived);
                    b.write(b"abcdefghijkl").unwrap();
                    let next = b.snd_nxt;
                    let retained = window.saturating_sub(1) as usize;
                    assert_eq!(b.flush(), Ok(12 - retained));
                    assert_eq!(b.send.len(), retained);
                    assert_eq!(b.snd_nxt, next);
                    assert_eq!(b.send_base, Seq(iss).wrapping_add(1));
                }
            }
        }
    }

    #[test]
    fn flush_discards_only_unadvertised_suffix_even_after_failed_output() {
        let (mut a, _) = pair(config(24, 8), u32::MAX - 3);
        a.write_urgent(b"abcdefghijklmnop").unwrap();
        packet(&mut a, 40); // Commits coverage of sixteen bytes, only eight sent.
        let committed = a.advertised_snd_up;
        a.write_urgent(b"qrstuvwx").unwrap();
        assert_eq!(a.transmit(50, &mut [0; 27]), Err(Error::OutputTooSmall));
        assert_eq!(a.advertised_snd_up, committed);
        let ack = a.snd_una;
        inject(&mut a, 51, Seq(901), ack, ACK, 8, b"");
        assert_eq!(a.flush(), Ok(8));
        assert_eq!(a.send.len(), 16);
        assert_eq!(a.snd_up, committed);
        assert_eq!(a.send.capacity(), 24);

        let (mut a, _) = pair(config(16, 8), 100);
        a.write_urgent(b"abcdefghijklmnop").unwrap();
        assert_eq!(a.transmit(40, &mut [0; 27]), Err(Error::OutputTooSmall));
        let ack = a.snd_una;
        inject(&mut a, 41, Seq(901), ack, ACK, 0, b"");
        assert_eq!(a.flush(), Ok(16)); // Outside the window, urgency never committed.
        assert_eq!(a.snd_up, None);
        assert_eq!(a.advertised_snd_up, None);
        inject(&mut a, 42, Seq(901), ack, ACK, 16, b"");
        a.write(b"ordinary").unwrap();
        let bytes = packet(&mut a, 50);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.flags & URG,
            0
        );

        let (mut a, _) = pair(config(131072, 1460), u32::MAX - 100);
        a.write_urgent(&vec![42; 70000]).unwrap();
        packet(&mut a, 40);
        packet(&mut a, 50); // Advances the capped wire endpoint by one MSS.
        a.retx_pending = true;
        packet(&mut a, 60); // Older retransmission cannot retract that endpoint.
        let ack = a.snd_una;
        inject(&mut a, 61, Seq(901), ack, ACK, 0, b"");
        assert_eq!(a.flush(), Ok(70000 - 65535 - 1460));
        assert_eq!(a.send.len(), 65535 + 1460);
        assert_eq!(a.snd_up, a.advertised_snd_up);
        assert_eq!(a.send.capacity(), 131072);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.3
    //= type=test
    //# A TCP receiver MAY pass a received PSH bit to the application layer
    //# via the PUSH flag in the interface (MAY-17), but it is not required
    //# (this was clarified in RFC 1122, Section 4.2.2.2).
    fn receive_push_waits_for_gap_and_ignores_duplicate_empty_and_trimmed_marks() {
        let (_, mut b) = pair(config(16, 8), u32::MAX - 2);
        let start = b.receive.next();
        inject(
            &mut b,
            40,
            start.wrapping_add(2),
            Seq(901),
            ACK | PSH,
            16,
            b"cd",
        );
        assert!(!b.take_events().pushed);
        inject(&mut b, 50, start, Seq(901), ACK, 16, b"ab");
        let events = b.take_events();
        assert!(events.pushed && events.readable);
        inject(
            &mut b,
            60,
            start.wrapping_add(2),
            Seq(901),
            ACK | PSH,
            16,
            b"cd",
        );
        assert!(!b.take_events().pushed);
        let next = b.receive.next();
        inject(&mut b, 70, next, Seq(901), ACK | PSH, 16, b"");
        assert!(!b.take_events().pushed);
        inject(&mut b, 80, next, Seq(901), ACK | PSH, 16, b"efghijklmnopq");
        assert!(!b.take_events().pushed); // PSH endpoint was outside the window.
        assert_eq!(b.read(&mut [0; 16]), Ok(16));
        packet(&mut b, 80); // Advertise the newly freed receive credit.
        let next = b.receive.next();
        inject(&mut b, 90, next, Seq(901), ACK | PSH, 16, b"x");
        inject(
            &mut b,
            100,
            next.wrapping_add(1),
            Seq(901),
            ACK | PSH,
            16,
            b"y",
        );
        assert!(b.take_events().pushed); // Coalesced, not a queue of records.
        assert!(!b.take_events().pushed);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.6.1
    //= type=test
    //# A host MAY implement a "half-duplex" TCP close sequence, so that an
    //# application that has called CLOSE cannot continue to read data from
    //# the connection (MAY-1).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.6.1
    //= type=test
    //# If such a host issues a CLOSE call while received data is still pending in
    //# the TCP connection, or if new data is received after CLOSE is called, its
    //# TCP implementation SHOULD send a RST to show that data was lost (SHLD-3).
    fn optional_close_resets_only_accepted_data_loss_shutdown_still_reads() {
        for offset in [0, 2] {
            let (mut a, _) = pair(config(16, 8), 100);
            inject(&mut a, 40, Seq(901 + offset), Seq(101), ACK | PSH, 16, b"x");
            a.close().unwrap();
            assert_eq!(a.read(&mut [0]), Err(Error::InvalidState));
            let events = a.take_events();
            assert_eq!(events.closed, Some(CloseReason::Aborted));
            assert!(!events.readable && !events.pushed);
            let bytes = packet(&mut a, 50);
            assert_ne!(
                wire::parse(ip(tuple()), &bytes).unwrap().header.flags & RST,
                0
            );
        }
        let (mut a, _) = pair(config(16, 8), 100);
        inject(&mut a, 40, Seq(901), Seq(101), ACK, 16, b"x");
        assert_eq!(a.read(&mut [0]), Ok(1));
        a.take_events();
        a.close().unwrap();
        let bytes = packet(&mut a, 50);
        assert_ne!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.flags & FIN,
            0
        );
        // Old data, out-of-window data, missing ACK, and unacceptable ACK do not reset.
        for (seq, ack, flags) in [
            (901, 102, ACK),
            (950, 102, ACK),
            (902, 102, PSH),
            (902, 999, ACK),
        ] {
            inject(&mut a, 60, Seq(seq), Seq(ack), flags, 16, b"x");
            assert_ne!(a.state(), State::Closed);
        }
        inject(&mut a, 70, Seq(904), Seq(102), ACK | PSH, 16, b"x");
        assert_eq!(a.state(), State::Closed); // Accepted out-of-order bytes also lose data.
        assert_eq!(a.take_events().closed, Some(CloseReason::Aborted));
        let bytes = packet(&mut a, 80);
        assert_ne!(
            wire::parse(ip(tuple()), &bytes).unwrap().header.flags & RST,
            0
        );

        let (mut a, _) = pair(config(16, 8), 100);
        a.shutdown().unwrap();
        packet(&mut a, 40);
        inject(&mut a, 50, Seq(901), Seq(102), ACK | FIN, 16, b"reply");
        let mut out = [0; 8];
        assert_eq!(a.read(&mut out), Ok(5));
        assert_eq!(&out[..5], b"reply");
        assert_eq!(a.read(&mut out), Ok(0));

        let (mut a, _) = pair(config(16, 8), 100);
        a.close().unwrap();
        packet(&mut a, 40);
        inject(&mut a, 50, Seq(901), Seq(102), ACK | FIN, 16, b"");
        assert_eq!(a.state(), State::TimeWait);
        assert!(!a.take_events().readable);
    }

    #[test]
    fn close_after_write_shutdown_preserves_fin_or_resets_unread_data() {
        for passive in [false, true] {
            let (mut a, _) = pair(config(16, 8), 100);
            if passive {
                inject(&mut a, 40, Seq(901), Seq(101), ACK | FIN, 16, b"");
            }
            a.shutdown().unwrap();
            packet(&mut a, 50);
            if !passive {
                inject(&mut a, 60, Seq(901), Seq(101), ACK | FIN, 16, b"");
                packet(&mut a, 60); // Drain the FIN acknowledgment before close.
            }
            let state = if passive {
                State::LastAck
            } else {
                State::Closing
            };
            assert_eq!(a.state(), state);
            a.close().unwrap();
            a.close().unwrap();
            assert_eq!(a.state(), state);
            assert_eq!(a.snd_nxt, Seq(102));
            assert_eq!(a.transmit(70, &mut [0; 128]), Ok(None));
        }
        for phase in 0..3 {
            for unread in [false, true] {
                let (mut a, _) = pair(config(16, 8), 100);
                a.shutdown().unwrap();
                if phase >= 1 {
                    let bytes = packet(&mut a, 40);
                    assert_ne!(
                        wire::parse(ip(tuple()), &bytes).unwrap().header.flags & FIN,
                        0
                    );
                    assert_eq!(a.state(), State::FinWait1);
                }
                if phase == 2 {
                    inject(&mut a, 50, Seq(901), Seq(102), ACK, 16, b"");
                    assert_eq!(a.state(), State::FinWait2);
                }
                if unread {
                    let ack = a.snd_nxt;
                    inject(&mut a, 60, Seq(901), ack, ACK, 16, b"x");
                }
                let state = a.state();
                let next = a.snd_nxt;
                a.close().unwrap();
                assert_eq!(a.read(&mut [0]), Err(Error::InvalidState));
                if unread {
                    assert_eq!(a.state(), State::Closed);
                    assert_eq!(a.close_reason(), Some(CloseReason::Aborted));
                    let bytes = packet(&mut a, 70);
                    assert_ne!(
                        wire::parse(ip(tuple()), &bytes).unwrap().header.flags & RST,
                        0
                    );
                } else {
                    assert_eq!(a.state(), state);
                    assert_eq!(a.snd_nxt, next);
                    a.close().unwrap();
                    if phase == 0 {
                        let bytes = packet(&mut a, 70);
                        assert_ne!(
                            wire::parse(ip(tuple()), &bytes).unwrap().header.flags & FIN,
                            0
                        );
                    }
                    assert_eq!(a.snd_nxt, Seq(102));
                    assert_eq!(a.transmit(70, &mut [0; 128]), Ok(None));
                }
            }
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
    //= type=test
    //= reason=Checks both default empty and configured one-octet payloads, without advancing the stream.
    //# An implementation SHOULD send a keep-alive segment with no data
    //# (SHLD-12); however, it MAY be configurable to send a keep-alive
    //# segment containing one garbage octet (MAY-6), for compatibility with
    //# erroneous TCP implementations.
    fn keepalive_garbage_is_initialized_atomic_and_outside_stream_accounting() {
        assert!(!KeepaliveConfig::default().send_garbage);
        for garbage in [false, true] {
            let (mut a, mut b) = pair(config(16, 8), u32::MAX);
            a.set_keepalive(Some(KeepaliveConfig {
                idle_us: 100,
                interval_us: 50,
                probes: 2,
                send_garbage: garbage,
            }))
            .unwrap();
            let deadline = a.keepalive_deadline.unwrap();
            a.timeout(deadline).unwrap();
            let before = (
                a.snd_nxt,
                a.snd_una,
                a.acknowledged,
                a.sample,
                a.rto_deadline,
                a.keepalive_probes,
                a.next_deadline(),
                a.last_sent,
            );
            assert_eq!(
                a.transmit(deadline, &mut [0; 19]),
                Err(Error::OutputTooSmall)
            );
            if garbage {
                assert_eq!(
                    a.transmit(deadline, &mut [0; 20]),
                    Err(Error::OutputTooSmall)
                );
            }
            assert_eq!(
                (
                    a.snd_nxt,
                    a.snd_una,
                    a.acknowledged,
                    a.sample,
                    a.rto_deadline,
                    a.keepalive_probes,
                    a.next_deadline(),
                    a.last_sent
                ),
                before
            );
            assert!(a.keepalive_pending);
            let bytes = deliver(&mut a, &mut b, deadline);
            let segment = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(segment.header.sequence, u32::MAX);
            assert_eq!(segment.payload, if garbage { &b"\0"[..] } else { &b""[..] });
            assert_eq!(segment.header.flags, ACK);
            assert_eq!(
                (
                    a.snd_nxt,
                    a.snd_una,
                    a.acknowledged,
                    a.sample,
                    a.rto_deadline
                ),
                (before.0, before.1, before.2, before.3, before.4)
            );
            assert_eq!(a.send.len(), 0);
            assert_eq!(a.keepalive_probes, 1);
            assert_eq!(b.read(&mut [0]), Err(Error::WouldBlock));
            assert!(!b.take_events().pushed);
            deliver(&mut b, &mut a, deadline);
            assert_eq!(a.acknowledged, 0);
        }
    }
    fn timestamp_input(
        c: &mut Connection,
        now: u64,
        sequence: Seq,
        acknowledgment: Seq,
        flags: u8,
        ts: Option<(u32, u32)>,
        payload: &[u8],
    ) {
        let mut options = [1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0];
        if let Some((value, echo)) = ts {
            options[4..8].copy_from_slice(&value.to_be_bytes());
            options[8..].copy_from_slice(&echo.to_be_bytes());
        }
        let mut bytes = vec![0; 32 + payload.len()];
        let ip = ip(reverse(c.tuple));
        let n = wire::encode(
            ip,
            Header {
                source_port: c.tuple.remote.port(),
                destination_port: c.tuple.local.port(),
                sequence: sequence.0,
                acknowledgment: acknowledgment.0,
                flags,
                window: 1024,
                urgent_pointer: 0,
            },
            if ts.is_some() { &options } else { &[] },
            payload,
            &mut bytes,
        )
        .unwrap();
        c.input(now, &wire::parse(ip, &bytes[..n]).unwrap())
            .unwrap();
    }

    #[test]
    fn timestamps_negotiate_fallback_and_atomic_output() {
        for active_ts in [false, true] {
            for passive_ts in [false, true] {
                let mut ac = config(1024, 128);
                ac.timestamps = active_ts;
                let mut bc = ac.clone();
                bc.timestamps = passive_ts;
                let mut a = Connection::active(tuple(), ac, 10, 1_000).unwrap();
                let syn = packet(&mut a, 2_000);
                let syn = wire::parse(ip(tuple()), &syn).unwrap();
                assert_eq!(syn.options.timestamps, active_ts.then_some((2, 0)));
                let mut b = Connection::passive(reverse(tuple()), bc, 20, 3_000, &syn).unwrap();
                let old = (
                    b.now,
                    b.snd_nxt,
                    b.last_ack_sent,
                    b.ts_recent,
                    b.sample,
                    b.next_deadline(),
                );
                assert_eq!(b.transmit(4_000, &mut [0; 23]), Err(Error::OutputTooSmall));
                assert_eq!(
                    (
                        b.now,
                        b.snd_nxt,
                        b.last_ack_sent,
                        b.ts_recent,
                        b.sample,
                        b.next_deadline()
                    ),
                    old
                );
                let synack = deliver(&mut b, &mut a, 4_000);
                assert_eq!(
                    wire::parse(ip(reverse(tuple())), &synack)
                        .unwrap()
                        .options
                        .timestamps,
                    (active_ts && passive_ts).then_some((4, 2))
                );
                let ack = deliver(&mut a, &mut b, 5_000);
                assert_eq!(
                    wire::parse(ip(tuple()), &ack).unwrap().options.timestamps,
                    (active_ts && passive_ts).then_some((5, 4))
                );
                assert_eq!(b.state, State::Established);
                assert_eq!(a.timestamps, active_ts && passive_ts);
                assert_eq!(b.timestamps, a.timestamps);
                b.write(b"hello").unwrap();
                let data = deliver(&mut b, &mut a, 6_000);
                assert_eq!(
                    wire::parse(ip(reverse(tuple())), &data)
                        .unwrap()
                        .options
                        .timestamps
                        .is_some(),
                    a.timestamps
                );
            }
        }
        let mut cfg = config(1024, 128);
        cfg.timestamps = true;
        cfg.send_ip_payload_limit = 39;
        assert!(matches!(
            Connection::active(tuple(), cfg, 0, 0),
            Err(Error::InvalidArgument)
        ));
    }

    #[test]
    fn timestamps_paws_echo_order_wrap_idle_and_rst_exemption() {
        let mut cfg = config(1024, 128);
        cfg.timestamps = true;
        let (mut a, _) = pair(cfg.clone(), 10);
        a.ts_recent = u32::MAX - 2;
        a.ts_latest = a.ts_recent;
        let next = a.receive.next();
        let ack = a.snd_nxt;
        timestamp_input(&mut a, 1_000, next, ack, ACK, None, b"missing");
        assert_eq!(a.receive.next(), next);
        assert!(!a.ack_pending);
        timestamp_input(
            &mut a,
            2_000,
            next,
            ack,
            ACK,
            Some((u32::MAX - 3, 0)),
            b"stale",
        );
        assert_eq!(a.receive.next(), next);
        assert!(a.ack_pending);
        packet(&mut a, 2_000);
        timestamp_input(&mut a, 3_000, next, ack, ACK, Some((u32::MAX - 1, 0)), b"a");
        timestamp_input(
            &mut a,
            4_000,
            next.wrapping_add(1),
            ack,
            ACK,
            Some((1, 0)),
            b"b",
        );
        assert_eq!(a.ts_recent, u32::MAX - 1); // Earliest unacknowledged segment.
        a.immediate_ack();
        let bytes = packet(&mut a, 4_000);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes).unwrap().options.timestamps,
            Some((4, u32::MAX - 1))
        );
        assert_eq!(a.last_ack_sent, next.wrapping_add(2));
        timestamp_input(
            &mut a,
            5_000,
            next.wrapping_add(3),
            ack,
            ACK,
            Some((4, 0)),
            b"d",
        );
        assert_eq!(a.ts_recent, u32::MAX - 1); // Hole must not advance echo.
        packet(&mut a, 5_000);
        timestamp_input(
            &mut a,
            6_000,
            next.wrapping_add(2),
            ack,
            ACK,
            Some((3, 0)),
            b"c",
        );
        assert_eq!(a.ts_recent, 3); // Filling the hole replaces the echo.
        assert_eq!(a.receive.next(), next.wrapping_add(4));
        packet(&mut a, 6_000);
        let idle = 6_000 + 24 * 86_400_000_000 + 1;
        timestamp_input(
            &mut a,
            idle,
            next.wrapping_add(4),
            ack,
            ACK,
            Some((0x8000_0003, 0)),
            b"e",
        );
        assert_eq!(a.ts_recent, 0x8000_0003);
        assert_eq!(a.receive.next(), next.wrapping_add(5));
        let recent = a.ts_recent;
        timestamp_input(
            &mut a,
            idle + 1,
            next.wrapping_add(5),
            ack,
            RST,
            Some((0, 0)),
            b"",
        );
        assert_eq!(a.state, State::Closed);
        assert_eq!(a.ts_recent, recent);
        let (mut a, _) = pair(cfg, 10);
        let next = a.receive.next();
        let ack = a.snd_nxt;
        timestamp_input(&mut a, 40, next, ack, RST, None, b"");
        assert_eq!(a.state, State::Closed);
    }

    #[test]
    fn timestamps_rtt_validated_echo_and_karn() {
        let mut cfg = config(1024, 128);
        cfg.timestamps = true;
        cfg.nagle = false;
        for valid in [false, true] {
            let (mut a, _) = pair(cfg.clone(), 10);
            a.rtt = RttEstimator::new(1_000_000);
            a.write(b"sample").unwrap();
            packet(&mut a, 2_000_000);
            assert!(a.sample.is_some());
            let next = a.receive.next();
            let ack = a.snd_nxt;
            timestamp_input(
                &mut a,
                2_600_000,
                next,
                ack,
                ACK,
                Some((5, if valid { 2000 } else { 1999 })),
                b"",
            );
            assert_eq!(a.rtt.rto(), if valid { 1_800_000 } else { 1_000_000 });
            assert!(a.sample.is_none());
        }
        let (mut a, _) = pair(cfg, 10);
        a.write(b"lost").unwrap();
        packet(&mut a, 2_000_000);
        a.timeout(3_000_000).unwrap();
        let bytes = packet(&mut a, 3_000_000);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes)
                .unwrap()
                .options
                .timestamps
                .unwrap()
                .0,
            3000
        );
        assert!(a.sample.is_none());
        let rto = a.rtt.rto();
        let next = a.receive.next();
        let ack = a.snd_nxt;
        timestamp_input(&mut a, 3_600_000, next, ack, ACK, Some((6, 3000)), b"");
        assert_eq!(a.rtt.rto(), rto);
    }

    #[test]
    fn timestamps_ip_budget_data_fin_keepalive_and_clock_wrap() {
        for v6 in [false, true] {
            let mut cfg = config(1024, 128);
            cfg.timestamps = true;
            cfg.send_ip_payload_limit = 40;
            cfg.nagle = false;
            cfg.keepalive = Some(KeepaliveConfig {
                idle_us: 100_000,
                ..KeepaliveConfig::default()
            });
            let t = if v6 {
                Tuple {
                    local: "[2001:db8::1]:1000".parse().unwrap(),
                    remote: "[2001:db8::2]:2000".parse().unwrap(),
                }
            } else {
                tuple()
            };
            let now = (u32::MAX as u64) * 1000;
            let mut a = Connection::active(t, cfg.clone(), 10, now).unwrap();
            let syn = packet(&mut a, now);
            assert_eq!(syn.len(), 40);
            let mut b =
                Connection::passive(reverse(t), cfg, 20, now, &wire::parse(ip(t), &syn).unwrap())
                    .unwrap();
            deliver(&mut b, &mut a, now + 1_000);
            let ack = deliver(&mut a, &mut b, now + 2_000);
            assert_eq!(
                wire::parse(ip(t), &ack)
                    .unwrap()
                    .options
                    .timestamps
                    .unwrap()
                    .0,
                1
            );
            a.write(b"12345678").unwrap();
            let before = (a.now, a.snd_nxt, a.last_ack_sent, a.sample);
            assert_eq!(
                a.transmit(now + 3_000, &mut [0; 39]),
                Err(Error::OutputTooSmall)
            );
            assert_eq!((a.now, a.snd_nxt, a.last_ack_sent, a.sample), before);
            let data = deliver(&mut a, &mut b, now + 3_000);
            assert_eq!(data.len(), 40);
            b.immediate_ack();
            deliver(&mut b, &mut a, now + 4_000);
            a.timeout(now + 104_000).unwrap();
            assert_eq!(packet(&mut a, now + 104_000).len(), 32);
            a.shutdown().unwrap();
            let fin = packet(&mut a, now + 105_000);
            assert_eq!(fin.len(), 32);
            assert_ne!(wire::parse(ip(t), &fin).unwrap().header.flags & FIN, 0);
        }
    }

    #[test]
    fn time_wait_iss_projection_is_strict_serial_and_secret_candidate_dependent() {
        let (mut a, _) = pair(config(1024, 128), 10);
        for frontier in [0, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            a.snd_nxt = Seq(frontier);
            for candidate in [0, 1, 12345, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
                let iss = a.reuse_iss(candidate);
                assert!(after(Seq(iss), Seq(frontier)));
                if after(Seq(candidate), Seq(frontier)) {
                    assert_eq!(iss, candidate);
                }
            }
        }
        a.snd_nxt = Seq(100_000);
        assert_ne!(a.reuse_iss(1), a.reuse_iss(2));
    }
    #[test]
    fn timestamps_lower_mss_probe_garbage_keepalive_abort_and_simultaneous_open() {
        let mut cfg = config(1024, 128);
        cfg.timestamps = true;
        cfg.nagle = false;
        let (mut a, _) = pair(cfg.clone(), 10);
        a.lower_mss(64).unwrap();
        assert_eq!(a.mss, 52);
        a.write(&[1; 100]).unwrap();
        let bytes = packet(&mut a, 1_000);
        assert_eq!(bytes.len(), 84); // 64-byte MSS plus fixed TCP header.
        a.probe_pending = true;
        a.snd_wnd = 0;
        let probe = packet(&mut a, 2_000);
        assert_eq!(probe.len(), 33);
        assert!(
            wire::parse(ip(tuple()), &probe)
                .unwrap()
                .options
                .timestamps
                .is_some()
        );
        let (mut a, _) = pair(cfg.clone(), 10);
        a.config.keepalive = Some(KeepaliveConfig {
            send_garbage: true,
            ..KeepaliveConfig::default()
        });
        a.keepalive_pending = true;
        assert_eq!(packet(&mut a, 1_000).len(), 33);
        a.abort();
        let reset = packet(&mut a, 2_000);
        let reset = wire::parse(ip(tuple()), &reset).unwrap();
        assert_ne!(reset.header.flags & RST, 0);
        assert_eq!(reset.options.timestamps.unwrap().0, 2);

        let mut a = Connection::active(tuple(), cfg.clone(), 10, 0).unwrap();
        let mut b = Connection::active(reverse(tuple()), cfg, 20, 0).unwrap();
        let a_syn = packet(&mut a, 1_000);
        let b_syn = packet(&mut b, 1_000);
        a.input(2_000, &wire::parse(ip(reverse(tuple())), &b_syn).unwrap())
            .unwrap();
        b.input(2_000, &wire::parse(ip(tuple()), &a_syn).unwrap())
            .unwrap();
        let a_synack = packet(&mut a, 3_000);
        let b_synack = packet(&mut b, 3_000);
        a.input(
            4_000,
            &wire::parse(ip(reverse(tuple())), &b_synack).unwrap(),
        )
        .unwrap();
        b.input(4_000, &wire::parse(ip(tuple()), &a_synack).unwrap())
            .unwrap();
        assert_eq!((a.state, b.state), (State::Established, State::Established));
        assert_eq!((a.ts_recent, b.ts_recent), (3, 3));
    }
    #[test]
    fn time_wait_timestamp_freshness_uses_latest_not_echo_and_handles_wrap() {
        let (mut a, _) = pair(config(1024, 128), 10);
        a.time_wait();
        a.timestamps = true;
        a.ts_recent = 1;
        a.ts_latest = 9;
        let mut syn = Segment {
            header: Header {
                source_port: 2000,
                destination_port: 1000,
                sequence: 1,
                acknowledgment: 0,
                flags: SYN,
                window: 1024,
                urgent_pointer: 0,
            },
            options: wire::Options {
                timestamps: Some((8, 0)),
                ..wire::Options::default()
            },
            raw_options: &[],
            payload: &[],
        };
        assert!(!a.reuse_syn(40, &syn, true));
        a.ts_latest = u32::MAX;
        syn.options.timestamps = Some((0, 0));
        assert!(a.reuse_syn(40, &syn, true));
        syn.options.timestamps = Some((0x7fff_ffff, 0));
        assert!(!a.reuse_syn(40, &syn, true));
        a.timestamps = false;
        assert!(a.reuse_syn(40, &syn, true));
        assert!(!a.reuse_syn(40, &syn, false));
        assert!(!a.reuse_syn(240_000_030, &syn, true));
    }
    #[test]
    fn application_stall_bounds_responsive_persist_and_window_shrink() {
        for window in [0, 3] {
            for explicit in [false, true] {
                let (mut a, _) = pair(config(64, 8), 100);
                if explicit {
                    a.set_application_timeout(Some(5_000_000)).unwrap();
                }
                a.write(b"abcdefgh").unwrap();
                packet(&mut a, 40);
                let seq = a.receive.next();
                let una = a.snd_una;
                inject(&mut a, 50, seq, una, ACK, window, b"");
                let deadline = 30 + 5_000_000;
                for now in [1_000_000, 2_000_000, 4_000_000, deadline - 1] {
                    a.timeout(now).unwrap();
                    // Actual retransmission/probe feedback remains responsive.
                    a.transmit(now, &mut [0; 128]).unwrap();
                    inject(&mut a, now, seq, una, ACK, window, b"");
                    assert_eq!(a.user_deadline(), None);
                    assert_eq!(a.application_deadline(), explicit.then_some(deadline));
                    assert_eq!(a.state(), State::Established);
                }
                a.timeout(deadline).unwrap();
                if explicit {
                    assert_eq!(a.close_reason(), Some(CloseReason::TimedOut));
                    assert_eq!(a.take_events().closed, Some(CloseReason::TimedOut));
                } else {
                    assert_eq!(a.state(), State::Established);
                }
            }
        }
    }

    #[test]
    fn application_progress_requires_cumulative_ack_not_output_or_window_feedback() {
        let (mut a, _) = pair(config(64, 8), 100);
        assert_eq!(
            a.set_application_timeout(Some(0)),
            Err(Error::InvalidArgument)
        );
        a.set_application_timeout(Some(1_000)).unwrap();
        a.write(b"abcdefgh").unwrap();
        assert_eq!(a.application_deadline(), Some(1_030));
        assert_eq!(a.transmit(100, &mut [0; 1]), Err(Error::OutputTooSmall));
        assert_eq!(a.application_deadline(), Some(1_030));
        assert_eq!(a.acknowledged, 0);
        packet(&mut a, 100);
        assert_eq!(a.application_deadline(), Some(1_030));
        let seq = a.receive.next();
        let una = a.snd_una;
        inject(&mut a, 200, seq, una.wrapping_add(4), ACK, 64, b"");
        assert_eq!(a.acknowledged, 4);
        assert_eq!(a.application_deadline(), Some(1_200));
        inject(&mut a, 300, seq, una.wrapping_add(4), ACK, 0, b"");
        inject(&mut a, 400, seq, una.wrapping_add(4), ACK, 64, b"");
        assert_eq!(a.application_deadline(), Some(1_200));
        inject(&mut a, 500, seq, una.wrapping_add(8), ACK, 64, b"");
        assert_eq!(a.application_deadline(), None);
        assert_eq!(a.acknowledged, 8);
        a.timeout(2_000).unwrap();
        a.write(b"new").unwrap();
        assert_eq!(a.application_deadline(), Some(3_000));
        a.set_application_timeout(None).unwrap();
        assert_eq!(a.application_deadline(), None);
        assert_eq!(a.user_deadline(), Some(2_000 + a.config.user_timeout_us));
    }
}
