extern crate alloc;

use alloc::vec::Vec;
use core::{cmp::Ordering, net::SocketAddr};

use crate::{
    buffer::{ReceiveBuffer, SendBuffer},
    recovery::{Congestion, RttEstimator},
    seq::Seq,
    wire::{self, ACK, FIN, Header, IpMetadata, PSH, RST, SYN, Segment, URG},
};

pub type Instant = u64;

#[derive(Clone, Debug)]
pub struct ConnectionConfig {
    pub send_capacity: usize,
    pub receive_capacity: usize,
    // RFC 9293 MUST-67 remains partial: this configured offer has no explicit MMS_R
    // input; stream receive capacity is not the IP reassembly limit.
    pub mss: u16,
    pub nagle: bool,
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
        }
    }
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            send_capacity: 65536,
            receive_capacity: 65536,
            mss: 1460,
            nagle: true,
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
    mss: usize,
    advertised_edge: Seq,
    syn_window: u16,
    acknowledged: u64,
    received_read: u64,
    received_total: u64,
    snd_up: Option<Seq>,
    rcv_up: Option<u64>,
    shutdown: bool,
    fin_sequence: Option<Seq>,
    syn_pending: bool,
    ack_pending: bool,
    pending_rst: Option<(Seq, bool)>,
    retx_pending: bool,
    duplicate_acks: u8,
    limited_pending: bool,
    limited_sent: u32,
    probe_pending: bool,
    keepalive_pending: bool,
    rtt: RttEstimator,
    // RFC 9293 SHLD-8 gap: ECN negotiation and congestion responses are absent; IP
    // CE/output ECN metadata is also missing.
    congestion: Congestion,
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
    sws_deadline: Option<Instant>,
    sws_override: bool,
    time_wait_deadline: Option<Instant>,
    progress_at: Instant,
    last_received: Instant,
    last_sent: Instant,
    keepalive_deadline: Option<Instant>,
    keepalive_probes: u32,
}

impl Connection {
    pub(crate) fn active(
        tuple: Tuple,
        config: ConnectionConfig,
        iss: u32,
        now: Instant,
    ) -> Result<Self, Error> {
        if config.send_capacity == 0
            || config.send_capacity >= 1 << 30
            || config.receive_capacity == 0
            || config.receive_capacity > (65535usize << 14)
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
        let send = SendBuffer::new(config.send_capacity).map_err(|_| Error::NoMemory)?;
        let receive =
            ReceiveBuffer::new(Seq(0), config.receive_capacity).map_err(|_| Error::NoMemory)?;
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(config.mss as usize)
            .map_err(|_| Error::NoMemory)?;
        scratch.resize(config.mss as usize, 0);
        let local_scale = (0..=14)
            .find(|&shift| config.receive_capacity <= (65535usize << shift))
            .unwrap_or(14);
        let syn_window = config.receive_capacity.min(65535) as u16;
        let mss = config.mss as usize;
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
            mss,
            advertised_edge: Seq(0),
            syn_window,
            acknowledged: 0,
            received_read: 0,
            received_total: 0,
            snd_up: None,
            rcv_up: None,
            shutdown: false,
            fin_sequence: None,
            syn_pending: true,
            ack_pending: false,
            pending_rst: None,
            retx_pending: false,
            duplicate_acks: 0,
            limited_pending: false,
            limited_sent: 0,
            probe_pending: false,
            keepalive_pending: false,
            rtt: RttEstimator::new(),
            congestion: Congestion::new(mss as u32),
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
            sws_deadline: None,
            sws_override: false,
            time_wait_deadline: None,
            progress_at: now,
            last_received: now,
            last_sent: now,
            keepalive_deadline: None,
            keepalive_probes: 0,
        })
    }

    pub(crate) fn passive(
        tuple: Tuple,
        config: ConnectionConfig,
        iss: u32,
        now: Instant,
        syn: &Segment<'_>,
    ) -> Result<Self, Error> {
        if syn.header.flags & (SYN | ACK | RST) != SYN {
            return Err(Error::InvalidArgument);
        }
        let mut connection = Self::active(tuple, config, iss, now)?;
        connection.learn_syn(syn);
        connection.state = State::SynReceived;
        Ok(connection)
    }

    pub(crate) fn tuple(&self) -> Tuple {
        self.tuple
    }
    pub(crate) fn state(&self) -> State {
        self.state
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

    pub(crate) fn network_error(
        &mut self,
        now: Instant,
        quoted_sequence: u32,
        error: NetworkError,
    ) -> Result<bool, Error> {
        self.check_time(now)?;
        self.now = now;
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
        //# TCP implementations MUST silently discard any received ICMP Source Quench
        //# messages (MUST-55).
        if error == NetworkError::SourceQuench
            || matches!(self.state, State::Closed | State::TimeWait)
            || Seq(quoted_sequence).in_window(self.snd_una, self.flight()) != Some(true)
        {
            return Ok(false);
        }
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
        //= reason=Acts on adapter-classified errors only; soft errors remain nonterminal.
        //# Since these Unreachable messages indicate soft error conditions, a TCP
        //# implementation MUST NOT abort the connection (MUST-56),
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
        if mss == 0 || mss as usize > self.mss {
            return Err(Error::InvalidArgument);
        }
        if mss as usize == self.mss {
            return Ok(());
        }
        self.mss = mss as usize;
        // Also constrain future SYN offers and negotiation if this occurs
        // before the peer's SYN; the scratch allocation never changes.
        self.config.mss = self.config.mss.min(mss);
        self.congestion.set_mss(mss as u32);
        if self.flight() != 0 {
            if matches!(self.state, State::SynSent | State::SynReceived) {
                self.syn_pending = true;
            } else if self.synchronized() && self.snd_wnd != 0 {
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

    fn learn_syn(&mut self, syn: &Segment<'_>) {
        self.irs = Some(Seq(syn.header.sequence));
        let start = Seq(syn.header.sequence).wrapping_add(1);
        self.receive
            .reset_start(start)
            .expect("handshake receive buffer is empty");
        self.advertised_edge = start.wrapping_add(self.syn_window as u32);
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
        // RFC 9293 MUST-16: peer MSS is capped here, but the configured/lowered MSS
        // still depends on adapter IP limits and options overhead.
        self.mss =
            (syn.options.mss.unwrap_or(default_mss).max(1) as usize).min(self.config.mss as usize);
        self.congestion.set_mss(self.mss as u32);
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
        //# The window size MUST be treated as an unsigned number, or else large window
        //# sizes will appear like negative windows and TCP will not work (MUST-1).
        self.snd_wnd = syn.header.window as u32;
        self.max_snd_wnd = self.snd_wnd;
        self.wl1 = Seq(syn.header.sequence);
        self.wl2 = Seq(syn.header.acknowledgment);
        let count = syn.payload.len().min(self.syn_window as usize);
        let fin = syn.header.flags & FIN != 0 && syn.payload.len() < self.syn_window as usize;
        let outcome = self.receive.insert(start, &syn.payload[..count], fin);
        self.received_total = count as u64;
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
        self.rtt.rto().max(if self.syn_timed_out {
            3_000_000
        } else {
            1_000_000
        })
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
        self.events.readable = self.receive.readable() != 0 || self.receive.eof();
        self.events.urgent = self.rcv_up;
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
    fn terminal(&mut self, reason: CloseReason) {
        self.state = State::Closed;
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
    // RFC 9293 MUST-34/SHLD-17 remain partial: responsive zero-window persist is
    // exempt, but nonzero-window shrink recovery is untested and has no dedicated
    // timeout exemption.
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
        Some(self.progress_at.saturating_add(self.user_timeout()))
    }

    fn arm_work(&mut self) {
        if !self.synchronized() {
            return;
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
    pub(crate) fn write(&mut self, data: &[u8]) -> Result<usize, Error> {
        if self.shutdown
            || !matches!(
                self.state,
                State::SynSent | State::SynReceived | State::Established | State::CloseWait
            )
        {
            return Err(Error::InvalidState);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let idle = !self.user_timer_needed();
        let count = self.send.write(data);
        if count == 0 {
            return Err(Error::WouldBlock);
        }
        if idle {
            self.progress_at = self.now;
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

    pub(crate) fn read(&mut self, out: &mut [u8]) -> Result<usize, Error> {
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

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= reason=Core separates input and transmit; driver-owned batches must be fed before polling output.
    //# For example, if the TCP endpoint is processing a series of queued segments, it
    //# MUST process them all before sending any ACK segments (MUST-59).
    pub(crate) fn input(&mut self, now: Instant, segment: &Segment<'_>) -> Result<(), Error> {
        self.check_time(now)?;
        self.now = now;
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
            self.learn_syn(segment);
            self.last_received = now;
            if valid_ack {
                self.accept_ack(ack);
                self.establish();
                self.immediate_ack();
            } else {
                self.state = State::SynReceived;
                self.syn_pending = true;
                self.sample = None;
            }
            self.arm_work();
            return Ok(());
        }

        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.5
        //# A TCP implementation MUST support simultaneous open attempts (MUST- 10).
        // Simultaneous open: the SYN has already consumed receive sequence
        // space. Only the identical SYN+ACK can finish this handshake here.
        if self.state == State::SynReceived
            && self.irs == Some(seq)
            && h.flags & (SYN | ACK | RST | FIN) == (SYN | ACK)
            && ack == self.iss.wrapping_add(1)
            && ack == self.snd_nxt
        {
            self.accept_ack(ack);
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
        let acceptable = if window == 0 {
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
            if h.flags & RST == 0 {
                if self.state == State::SynReceived && h.flags & SYN != 0 && self.irs == Some(seq) {
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
        if h.flags & RST != 0 {
            if seq == next {
                self.terminal(CloseReason::Reset);
            } else {
                self.immediate_ack();
            }
            return Ok(());
        }
        // RFC 9293 section 3.10.7.4 gap: passive SYN-RECEIVED unexpected SYN is
        // challenged without returning the child to LISTEN.
        if h.flags & SYN != 0 {
            self.immediate_ack();
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
        if !at_or_after(self.snd_nxt, ack) || !at_or_after(ack, oldest_ack) {
            if self.state == State::SynReceived {
                self.pending_rst = Some((ack, false));
            } else {
                self.immediate_ack();
            }
            return Ok(());
        }
        if self.state == State::SynReceived {
            if !after(ack, self.snd_una) {
                self.pending_rst = Some((ack, false));
                return Ok(());
            }
            self.accept_ack(ack);
            self.establish();
        }
        if self.state == State::TimeWait {
            return Ok(());
        }
        self.last_received = now;
        self.keepalive_probes = 0;
        self.keepalive_pending = false;
        self.keepalive_deadline = None;
        // A responsive zero-window peer must not be killed for backpressure.
        if self.snd_wnd == 0 {
            self.progress_at = now;
            self.persist_unanswered_since = None;
        }
        let old_window = self.snd_wnd;
        let advancing = after(ack, self.snd_una);
        if advancing {
            self.accept_ack(ack);
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
        }
        if !advancing
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
                self.limited_pending = false;
            }
        } else if !advancing {
            self.reset_limited_transmit();
            self.congestion.reset_duplicate_acks();
        }
        self.receive_text(seq, segment.payload, h.flags, h.urgent_pointer);
        self.arm_work();
        Ok(())
    }

    fn reset_limited_transmit(&mut self) {
        self.duplicate_acks = 0;
        self.limited_pending = false;
        self.limited_sent = 0;
    }

    fn accept_ack(&mut self, ack: Seq) {
        self.reset_limited_transmit();
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
        if self.snd_up.is_some_and(|end| at_or_after(ack, end)) {
            self.snd_up = None;
        }
        self.progress_at = self.now;
        self.consecutive_timeouts = 0;
        self.retx_pending = false;
        if let Some((end, sent)) = self.sample
            && at_or_after(ack, end)
        {
            self.rtt.sample(self.now.saturating_sub(sent));
            self.sample = None;
            if !syn_ack {
                self.syn_timed_out = false;
            }
        }
        if !syn_ack && bytes != 0 && self.congestion.on_ack(ack, bytes, self.flight()) {
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
    fn receive_text(&mut self, seq: Seq, payload: &[u8], flags: u8, urgent: u16) {
        if !matches!(
            self.state,
            State::Established | State::FinWait1 | State::FinWait2
        ) {
            return;
        }
        let next = self.receive.next();
        let window = self.receive_window();
        if flags & URG != 0 {
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
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
        //# Segments with higher beginning sequence numbers SHOULD be held for later
        //# processing (SHLD-31).
        let outcome = self.receive.insert(
            start,
            &payload[skip..skip + count],
            fin && skip + count == payload.len(),
        );
        let advanced = self.receive.next().distance_from(next);
        self.received_total = self
            .received_total
            .saturating_add(advanced.saturating_sub(u32::from(outcome.fin)) as u64);
        if outcome.advanced {
            self.events.readable = true;
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
                || self.unacked_bytes >= 2 * u32::from(self.config.mss)
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
        let keepalive = reset.is_none() && !syn && live && self.keepalive_pending;
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
        } else if retransmit || probe {
            seq = self.snd_una;
            let offset = seq.distance_from(self.send_base) as usize;
            let limit = if probe {
                1
            } else {
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6
                //= reason=Retransmit is bounded by offered window; no direct shrinking-window regression test.
                //# but SHOULD retransmit normally the old unacknowledged data between
                //# SND.UNA and SND.UNA+SND.WND (SHLD-16).
                self.mss
                    .min(self.snd_wnd as usize)
                    .min(self.flight() as usize)
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
        //# An implementation SHOULD send a keep-alive segment with no data (SHLD-12);
        } else if keepalive {
            seq = self.snd_nxt.wrapping_add(u32::MAX);
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
            let usable = self.snd_wnd.min(cwnd_limit).saturating_sub(self.flight()) as usize;
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
            //# However, a TCP implementation SHOULD send a maximum-sized segment
            //# whenever possible (SHLD-28) to improve performance (see Section
            //# 3.8.6.2.1).
            count = unsent.min(self.mss).min(usable);
            let urgent = self.snd_up.is_some_and(|end| after(end, seq));
            if count < self.mss && !urgent {
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.4
                //# A TCP implementation SHOULD implement the Nagle algorithm to
                //# coalesce short segments (SHLD-7).
                let nagle = self.config.nagle && self.flight() != 0;
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.2.1
                //# A TCP implementation MUST include a SWS avoidance algorithm in the
                //# sender (MUST-38).
                let sws =
                    !self.sws_override && count < unsent && count < (self.max_snd_wnd / 2) as usize;
                if nagle || sws {
                    count = 0;
                }
            }
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
        if count != 0 {
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
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.1
        //= reason=Transmit supplies MSS on SYN; learn_syn consumes the decoded peer MSS.
        //# TCP endpoints MUST implement both sending and receiving the MSS Option
        //# (MUST-14).
        let mss = self.config.mss.to_be_bytes();
        let options = [2, 4, mss[0], mss[1], 3, 3, self.local_scale, 0];
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.1
        //# TCP implementations SHOULD send an MSS Option in every SYN segment when its
        //# receive MSS differs from the default 536 for IPv4 or 1220 for IPv6 (SHLD-5),
        //# and MAY send it always (MAY-3).
        let option_len = if syn {
            if self.state == State::SynSent || self.scaling {
                8
            } else {
                4
            }
        } else {
            0
        };
        let ip = IpMetadata {
            source: self.tuple.local.ip(),
            destination: self.tuple.remote.ip(),
        };
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
        self.now = now;
        if reset.is_some() {
            self.pending_rst = None;
            return Ok(Some(size));
        }
        if self.flight() == 0 && now.saturating_sub(self.last_sent) >= self.rto() && count != 0 {
            self.congestion.restart_after_idle();
        }
        self.last_sent = now;
        self.syn_pending = false;
        if flags & ACK != 0 {
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
        if length != 0 {
            let end = seq.wrapping_add(length);
            if retransmitted {
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.1
                //= reason=Sample invalidation here and accept_ack sampling integrate with recovery.rs RTT estimation.
                //# The RTO MUST be computed according to the algorithm in [10],
                //# including Karn's algorithm for taking RTT samples (MUST-18).
                // Karn: invalidate every pending sample when retransmitting.
                // Fresh sequence space sent afterwards may start a new sample;
                // its ACK cannot predate its first transmission.
                self.sample = None;
            } else if self.sample.is_none() {
                self.sample = Some((end, now));
            }
            if after(end, self.snd_nxt) {
                self.snd_nxt = end;
            }
            if (self.rto_deadline.is_none() || retransmitted) && !probe {
                self.rto_deadline = Some(now.saturating_add(self.rto()));
            }
        }
        if new_fin {
            self.fin_sequence = Some(seq.wrapping_add(count as u32));
            self.state = if self.state == State::CloseWait {
                State::LastAck
            } else {
                State::FinWait1
            };
        }
        if retransmit {
            self.retx_pending = false;
        }
        if probe {
            self.probe_pending = false;
            self.persist_unanswered_since.get_or_insert(now);
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1
            //# and SHOULD increase exponentially the interval between successive probes
            //# (SHLD-30).
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
        if count != 0 {
            if self.limited_pending && !retransmit && !probe {
                self.limited_sent = self.limited_sent.saturating_add(count as u32);
                self.limited_pending = false;
            }
            self.sws_deadline = None;
            self.sws_override = false;
        }
        self.arm_work();
        Ok(Some(size))
    }

    fn initial_window(&self) -> u32 {
        let mss = self.mss as u32;
        (4 * mss).min((2 * mss).max(4380))
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        [
            self.rto_deadline,
            self.ack_deadline,
            self.persist_deadline,
            self.sws_deadline,
            self.time_wait_deadline,
            self.keepalive_deadline,
            self.user_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    pub(crate) fn timeout(&mut self, now: Instant) -> Result<(), Error> {
        self.check_time(now)?;
        self.now = now;
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
        if due(self.user_deadline(), now) {
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
        if due(self.rto_deadline, now) {
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

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.2.2
    //= type=test
    //# A TCP implementation MUST include a SWS avoidance algorithm in the receiver
    //# (MUST-39).
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
        a.input(30, &sb).unwrap();
        b.input(30, &sa).unwrap();
        assert_eq!(a.state(), State::Established);
        assert_eq!(b.state(), State::Established);
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
    fn fin_half_close_time_wait_and_duplicate_fin_restart() {
        let (mut a, mut b) = pair(config(64, 8), 100);
        a.write(b"last").unwrap();
        a.shutdown().unwrap();
        assert_eq!(a.write(b"no"), Err(Error::InvalidState));
        deliver(&mut a, &mut b, 40);
        assert_eq!(a.state(), State::FinWait1);
        assert_eq!(b.state(), State::CloseWait);
        let events = b.take_events();
        assert!(events.readable && events.half_closed);
        assert_eq!(b.read(&mut [0; 8]), Ok(4));
        assert_eq!(b.read(&mut [0; 8]), Ok(0));
        deliver(&mut b, &mut a, 50);
        assert_eq!(a.state(), State::FinWait2);
        b.write(b"reply").unwrap();
        b.shutdown().unwrap();
        let fin = deliver(&mut b, &mut a, 60);
        assert_eq!(b.state(), State::LastAck);
        assert_eq!(a.state(), State::TimeWait);
        assert_eq!(a.take_events().closed, Some(CloseReason::Normal));
        let deadline = a.next_deadline().unwrap();
        a.input(70, &wire::parse(ip(reverse(tuple())), &fin).unwrap())
            .unwrap();
        assert_eq!(deadline, 60 + 240_000_000);
        assert_eq!(a.next_deadline(), Some(70 + 240_000_000));
        deliver(&mut a, &mut b, 80);
        assert_eq!(b.state(), State::Closed);
        assert_eq!(a.read(&mut [0; 8]), Ok(5));
        assert_eq!(a.read(&mut [0; 8]), Ok(0));
        a.timeout(deadline).unwrap();
        assert_eq!(a.state(), State::TimeWait);
        a.timeout(a.next_deadline().unwrap()).unwrap();
        assert_eq!(a.state(), State::Closed);
    }

    #[test]
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
        inject(&mut a, 60, next, high, 0, 0, b"bad");
        assert_eq!(a.receive.readable(), 0);
        inject(&mut a, 70, next.wrapping_add(64), high, RST | ACK, 0, b"");
        assert_eq!(a.state(), State::Established);
        packet(&mut a, 75); // Consume the earlier invalid-ACK response.
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
    fn syn_sent_resets_require_ack_and_abort_outputs_once() {
        let mut a = Connection::active(tuple(), config(64, 8), 100, 0).unwrap();
        packet(&mut a, 0);
        inject(&mut a, 10, Seq(0), Seq(101), RST, 0, b"");
        assert_eq!(a.state(), State::SynSent);
        inject(&mut a, 20, Seq(0), Seq(102), RST | ACK, 0, b"");
        assert_eq!(a.state(), State::SynSent);
        inject(&mut a, 30, Seq(0), Seq(101), RST | ACK, 0, b"");
        assert_eq!(a.close_reason(), Some(CloseReason::Reset));
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
    fn future_ack_during_passive_handshake_gets_a_reset_not_an_ack() {
        let mut active = Connection::active(tuple(), config(64, 8), 100, 0).unwrap();
        let syn = packet(&mut active, 0);
        let syn = wire::parse(ip(tuple()), &syn).unwrap();
        let mut passive =
            Connection::passive(reverse(tuple()), config(64, 8), 200, 0, &syn).unwrap();
        packet(&mut passive, 0);
        inject(&mut passive, 1, Seq(101), Seq(202), ACK, 64, &[]);
        let response = packet(&mut passive, 1);
        let response = wire::parse(ip(reverse(tuple())), &response).unwrap();
        assert_eq!(response.header.flags, RST);
        assert_eq!(response.header.sequence, 202);
        assert_eq!(passive.state(), State::SynReceived);
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
    fn syn_text_is_retained_but_not_readable_before_establishment() {
        let metadata = ip(tuple());
        let header = Header {
            source_port: 1000,
            destination_port: 2000,
            sequence: u32::MAX - 1,
            acknowledgment: 0,
            flags: SYN | URG,
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
    //# TCP implementations MUST silently discard any received ICMP Source Quench
    //# messages (MUST-55).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
    //= type=test
    //# Since these Unreachable messages indicate soft error conditions, a TCP
    //# implementation MUST NOT abort the connection (MUST-56),
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
    //# If keep-alives are included, the application MUST be able to turn them on or off
    //# for each TCP connection (MUST-24),
    fn keepalive_can_be_disabled_or_overridden_without_reusing_stale_deadlines() {
        assert_eq!(KeepaliveConfig::default().idle_us, 7_200_000_000);
        let (mut a, _) = pair(config(64, 8), 100);
        a.update_time(1_000_000).unwrap();
        let keepalive = KeepaliveConfig {
            idle_us: 100,
            interval_us: 50,
            probes: 2,
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
    //# The transmitting host SHOULD send the first zero-window probe when a
    //# zero window has existed for the retransmission timeout period (SHLD-
    //# 29) (Section 3.8.1),
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1
    //= type=test
    //# and SHOULD increase exponentially the interval between successive probes
    //# (SHLD-30).
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
    //= reason=Asserts peer versus configured payload ceiling; adapter IP limits and options overhead remain adapter responsibilities.
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
}
