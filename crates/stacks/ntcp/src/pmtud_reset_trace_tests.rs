// RFC 4821 section 7.7 black-hole recovery through a real receiver Endpoint:
// queued wire packets with a one-way delay, every timer at its actual
// deadline. The network drops sender packets above a size, silently (a black
// hole) or with a router's Packet Too Big, and an optional outage drops
// every packet in both directions. Each fallback is a step recorded at the RTO
// that took it: eff_pmtu, search_low, MSS, cwnd and ssthresh.
use super::*;
use crate::{Endpoint, EndpointConfig, PmtudConfig};
use alloc::collections::VecDeque;

const DELAY: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Step {
    count: u32,
    mtu: u32,
    low: u32,
    mss: u32,
    cwnd: u32,
    ssthresh: u32,
    at: u64,
    // Data flight and window just before the timeout.
    flight: u32,
    window: u32,
    // PLPMTUD cooldown armed by the timeout and its backed-off RTO.
    deadline: Option<u64>,
    rto: u64,
}

struct Sent {
    at: u64,
    payload: usize,
    dropped: bool,
}

struct Trace {
    a: Connection,
    b: Endpoint,
    listener: crate::ListenerId,
    child: Option<crate::ConnectionId>,
    now: u64,
    // (arrival, toward the receiver, TCP bytes)
    queue: VecDeque<(u64, bool, Vec<u8>)>,
    // Largest sender IP packet the black hole forwards.
    hole: u32,
    // The hole's router reports each drop in a Packet Too Big instead.
    ptb: bool,
    // (arrival, quoted sequence, quoted IP packet size)
    ptbs: VecDeque<(u64, u32, u32)>,
    outage: bool,
    written: Vec<u8>,
    received: Vec<u8>,
    steps: Vec<Step>,
    sent: Vec<Sent>,
}

fn v6_tuple() -> Tuple {
    Tuple {
        local: "[2001:db8::1]:1000".parse().unwrap(),
        remote: "[2001:db8::2]:2000".parse().unwrap(),
    }
}

impl Trace {
    fn new(ipv4: bool, sack: bool, iss: u32, pmtud: PmtudConfig) -> Self {
        Self::with_rack(ipv4, sack, false, iss, pmtud)
    }

    fn with_rack(ipv4: bool, sack: bool, rack: bool, iss: u32, pmtud: PmtudConfig) -> Self {
        let tuple = if ipv4 { tuple() } else { v6_tuple() };
        let cfg = ConnectionConfig {
            pmtud: Some(pmtud),
            rack,
            initial_window: InitialWindow::Iw10,
            nagle: false,
            timestamps: true,
            sack,
            delayed_ack_us: 0,
            ..config(65_536, 1460)
        };
        let a = Connection::active(tuple, cfg.clone(), iss, 0).unwrap();
        let mut b = Endpoint::new(
            EndpointConfig {
                max_connections: 1,
                max_listeners: 1,
                connection: ConnectionConfig { pmtud: None, ..cfg },
                ..EndpointConfig::default()
            },
            [2; 32],
            0,
            crate::SETTLED,
            |_| true,
        )
        .unwrap();
        let listener = b.listen(tuple.remote, 1).unwrap();
        let mut t = Trace {
            a,
            b,
            listener,
            child: None,
            now: 0,
            queue: VecDeque::new(),
            hole: u32::MAX,
            ptb: false,
            ptbs: VecDeque::new(),
            outage: false,
            written: Vec::new(),
            received: Vec::new(),
            steps: Vec::new(),
            sent: Vec::new(),
        };
        t.run_until(|t| t.child.is_some() && t.a.state() == State::Established);
        t
    }

    fn header(&self) -> u32 {
        if self.a.tuple.local.is_ipv4() { 20 } else { 40 }
    }

    fn info(&self) -> crate::PathMtuInfo {
        self.a.path_mtu_info().unwrap()
    }

    // The expected MSS at `mtu`: IP and TCP headers and the timestamp option.
    fn mss_at(&self, mtu: u32) -> u32 {
        mtu - self.header() - 20 - 12
    }

    fn write(&mut self, len: usize) {
        let start = self.written.len();
        let bytes: Vec<u8> = (start..start + len).map(|i| (i % 251) as u8).collect();
        assert_eq!(self.a.write(&bytes).unwrap(), len);
        self.written.extend_from_slice(&bytes);
    }

    fn drained(&self) -> bool {
        self.a.flight() == 0 && self.a.send.len() == 0 && self.received.len() == self.written.len()
    }

    fn output(&mut self) {
        let mut out = vec![0; 65_575];
        let cooldown = self.a.pmtud.as_ref().unwrap().deadline;
        while let Some(n) = self.a.transmit(self.now, &mut out).unwrap() {
            let size = n as u32 + self.header();
            let segment = wire::parse(ip(self.a.tuple), &out[..n]).unwrap();
            let current = self.info().current_mtu;
            // A larger packet is only ever a probe, never before a fallback's
            // cooldown ends.
            assert!(
                size <= current || cooldown.is_none_or(|d| self.now >= d),
                "{size} > {current} during cooldown"
            );
            // The IPv6 floor is reached by loss inference alone.
            assert!(self.a.tuple.local.is_ipv4() || current >= 1280);
            let dropped = self.outage || size > self.hole;
            if !self.outage && size > self.hole && self.ptb {
                // A real router's report: never below the IPv6 minimum.
                assert!(self.a.tuple.local.is_ipv4() || self.hole >= 1280);
                self.ptbs.push_back((self.now + DELAY / 2, segment.header.sequence, size));
            }
            self.sent.push(Sent {
                at: self.now,
                payload: segment.payload.len(),
                dropped,
            });
            if !dropped {
                self.queue.push_back((self.now + DELAY, true, out[..n].to_vec()));
            }
        }
        let mut bytes = vec![0; 65_575];
        while let Some(p) = self.b.poll_transmit(self.now, &mut bytes, 16).unwrap().packet {
            if !self.outage {
                self.queue.push_back((self.now + DELAY, false, bytes[..p.len].to_vec()));
            }
        }
        if self.child.is_none() {
            self.child = self.b.accept(self.listener).ok();
        }
        if let Some(child) = self.child {
            let mut read = vec![0; 65_536];
            while let Ok(n) = self.b.read(child, &mut read) {
                if n == 0 {
                    break;
                }
                self.received.extend_from_slice(&read[..n]);
            }
        }
    }

    fn advance(&mut self) {
        let next = [
            self.queue.front().map(|q| q.0),
            self.ptbs.front().map(|q| q.0),
            self.a.next_deadline(),
            self.b.next_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
        .expect("a pending event");
        self.now = self.now.max(next);
        while self.ptbs.front().is_some_and(|q| q.0 <= self.now) {
            let (_, seq, size) = self.ptbs.pop_front().unwrap();
            let header = self.header() as u16;
            self.a.pmtu_feedback(self.now, seq, size, header, self.hole).unwrap();
        }
        while self.queue.front().is_some_and(|q| q.0 <= self.now) {
            let (_, toward, bytes) = self.queue.pop_front().unwrap();
            let forward = ip(self.a.tuple);
            if toward {
                self.b.input(self.now, forward, &bytes).unwrap();
            } else {
                let segment = wire::parse(ip(reverse(self.a.tuple)), &bytes).unwrap();
                self.a.input(self.now, &segment).unwrap();
            }
        }
        if self.a.next_deadline().is_some_and(|d| d <= self.now) {
            let (count, flight, window) =
                (self.a.consecutive_timeouts, self.a.data_flight(), self.a.congestion.cwnd());
            self.a.timeout(self.now).unwrap();
            if self.a.consecutive_timeouts > count {
                let info = self.info();
                self.steps.push(Step {
                    count: self.a.consecutive_timeouts,
                    mtu: info.current_mtu,
                    low: info.search_low,
                    mss: self.a.mss as u32,
                    cwnd: self.a.congestion.cwnd(),
                    ssthresh: self.a.congestion.ssthresh(),
                    at: self.now,
                    flight,
                    window,
                    deadline: self.a.pmtud.as_ref().unwrap().deadline,
                    rto: self.a.rto(),
                });
            }
        }
        if self.b.next_deadline().is_some_and(|d| d <= self.now) {
            self.b.on_timeout(self.now, 16).unwrap();
        }
    }

    // Lets every event up to `until` happen, then idles to it.
    fn idle_until(&mut self, until: u64) {
        loop {
            self.output();
            let next = [
                self.queue.front().map(|q| q.0),
                self.ptbs.front().map(|q| q.0),
                self.a.next_deadline(),
                self.b.next_deadline(),
            ]
            .into_iter()
            .flatten()
            .min();
            if next.is_none_or(|n| n > until) {
                break;
            }
            self.advance();
        }
        self.now = self.now.max(until);
    }

    fn run_until(&mut self, done: impl Fn(&Trace) -> bool) {
        for _ in 0..200_000 {
            self.output();
            if done(self) {
                return;
            }
            self.advance();
        }
        panic!("trace did not reach its condition");
    }

    // Timeouts of one full stop until `count` steps of the run are recorded.
    fn timeouts(&mut self, count: usize) -> &[Step] {
        let start = self.steps.len();
        self.run_until(|t| t.steps.len() == start + count);
        &self.steps[start..]
    }

    // Delivered recovery: the stream drains through the receiver without a
    // further RTO, which clears the successive count.
    fn recover(&mut self) {
        let steps = self.steps.len();
        self.run_until(|t| t.drained());
        assert_eq!(self.steps.len(), steps, "recovery waited for another RTO");
        assert_eq!(self.a.consecutive_timeouts, 0);
        assert_eq!(self.received, self.written);
    }

    // Data packets the sender put on the wire after `step` and before the
    // next step, and the payload bytes of those that crossed.
    fn after(&self, step: &Step) -> (usize, usize) {
        let next = self.steps.iter().find(|s| s.at > step.at).map_or(u64::MAX, |s| s.at);
        let packets = self.sent.iter().filter(|s| s.at >= step.at && s.at < next && s.payload > 0);
        let delivered = packets.clone().filter(|s| !s.dropped).map(|s| s.payload).sum();
        (packets.count(), delivered)
    }

    // Successive timeouts of one full stop: the first sets ssthresh from the
    // flight (Reno, RFC 5681 equation 4), repeated ones keep it; cwnd is one
    // current SMSS, unless the timeout's path step raised the SMSS: then it
    // keeps the byte window held before the raise (RFC 4821 section 4).
    // Each timeout of a stop retransmits exactly one segment (bounded wire
    // repair) and every fallback arms the fivefold cooldown.
    fn check_congestion(&self, run: &[Step]) {
        for (i, step) in run.iter().enumerate() {
            assert_eq!(step.mss, self.mss_at(step.mtu), "{step:?}");
            if i == 0 {
                assert_eq!(step.count, 1);
                assert_eq!(step.ssthresh, (step.flight / 2).max(2 * step.mss), "{step:?}");
            } else {
                assert_eq!(step.count, run[i - 1].count + 1);
                assert_eq!(step.ssthresh, run[i - 1].ssthresh, "{step:?}");
            }
            let raised = i > 0 && step.mss > run[i - 1].mss;
            if raised {
                assert_eq!(step.cwnd, step.window, "{step:?}");
                assert!(step.cwnd < step.mss);
            } else {
                assert_eq!(step.cwnd, step.mss, "{step:?}");
            }
            if step.count >= 3 {
                // At least the fivefold cooldown; a running PTB hold may end later.
                let cooldown = step.at + 5 * (step.rto + 1);
                assert!(step.deadline.is_some_and(|d| d >= cooldown), "{step:?}");
            }
            if i + 1 < run.len() {
                // The run continues: its one retransmission was lost.
                assert_eq!(self.after(step), (1, 0), "{step:?}");
            }
        }
    }
}

// The four-step trace of one full stop: the first two keep eff_pmtu, the
// third falls back and the fourth halves.
fn first_stop(t: &mut Trace, hole: u32, len: usize) -> Vec<Step> {
    t.hole = hole;
    t.write(len);
    let run = t.timeouts(4).to_vec();
    t.check_congestion(&run);
    run
}

fn shape(run: &[Step]) -> Vec<(u32, u32, u32)> {
    run.iter().map(|s| (s.count, s.mtu, s.low)).collect()
}

// A renewed full stop after delivered recovery: an outage loses every
// packet through the third timeout (the reset's retransmission included), so
// failure persists and the fourth halves; the outage then ends.
fn renewed_stop(t: &mut Trace, len: usize) -> Vec<Step> {
    t.outage = true;
    t.write(len);
    let mut run = t.timeouts(3).to_vec();
    t.outage = false;
    run.extend_from_slice(t.timeouts(1));
    t.check_congestion(&run);
    run
}

#[test]
// D4 traces, both families, SACK and go-back-N, a stream crossing sequence
// wrap. IPv4 (initial search_low 1024): 1500 -> 1024 (RTO 3) -> 512 (RTO 4)
// -> delivered recovery -> new full stop -> reset to 1024 at RTO 3 (above
// the loss-inferred 512) -> 512 at RTO 4. IPv6 with initial search_low 1400:
// 1500 -> 1400 -> 1280 (the halving floor) -> recovery -> reset 1400 ->
// 1280. Complete stream bytes through the receiver.
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.7
//= type=test
//= reason=User disposition (decision A, 2026-11-06, recorded): the reset is read as bounded by independently validated path ceilings, and the MAY of even lower bounds is not selected. Pmtud::timeout takes the black-hole action at R1, the third successive data RTO without cumulative progress or an explaining ICMP message since progress, with discovery enabled: if eff_pmtu is larger than search_low it sets eff_pmtu to search_low; otherwise it sets both eff_pmtu and search_low to the initial search_low, which may raise packet size above a loss-inferred estimate, bounded by reset_ceiling (first-hop, transport and configured search maximum, route policy and initial_search_high, administrative value, negative search evidence, accepted Packet Too Big authority and the managed shared estimate), never by the connection's current eff_pmtu. Each further successive timeout halves both, with a lower bound of 68 bytes for IPv4 and 1280 bytes for IPv6 (also bounded by the reset ceiling), clears probe and verification state and applies the fivefold cooldown. Accepted Packet Too Big authority outlives its hold and is released only by authorized path replacement or a larger acknowledged probe. A timeout whose reset raises the MSS keeps the byte cwnd held before the raise and its ssthresh (RFC 4821 section 4, RFC 5681 section 3.1); its retransmission and go-back-N repair leave within that window and the stream completes without another RTO; a later decrease takes the one-SMSS response. A loss-only fallback never publishes to or lowers the shared estimate. Real receiver traces in both families, SACK and non-SACK, across sequence wrap: IPv4 1500 to 1024 at RTO 3 and 512 at RTO 4, delivered recovery, then a renewed full stop resets to 1024 and halves to 512; IPv6 with initial search_low 1400: 1500 to 1400 to 1280, recovery, reset to 1400 then 1280. Route policy, first-hop, administrative, Packet Too Big and shared-estimate bounds clip the reset; with discovery disabled no fallback is taken, and re-enabling it during a run takes the run's first action (ntcp pmtud_reset_trace_tests.rs and pmtud_tests.rs, ntcp-host tests/black_hole_reset.rs).
//# The response to a detected black hole depends on the current values for search_low
//# and eff_pmtu. If eff_pmtu is larger than search_low, set eff_pmtu to search_low.
//# Otherwise, set both eff_pmtu and search_low to the initial value for search_low.
//# Upon additional successive timeouts, search_low and eff_pmtu SHOULD be halved, with
//# a lower bound of 68 bytes for IPv4 and 1280 bytes for IPv6. Even lower lower bounds
//# MAY be permitted to support limited operation over links with MTUs that are smaller
//# than permitted by the IP specifications.
fn renewed_full_stop_resets_to_the_initial_low_through_a_real_receiver() {
    for ipv4 in [true, false] {
        for sack in [true, false] {
            for iss in [0x1000, u32::MAX - 20_000] {
                let pmtud = PmtudConfig {
                    initial_search_low: (!ipv4).then_some(1400),
                    ..PmtudConfig::new(1500)
                };
                let (initial, halved, hole) = if ipv4 { (1024, 512, 600) } else { (1400, 1280, 1300) };
                let mut t = Trace::new(ipv4, sack, iss, pmtud);
                let run = first_stop(&mut t, hole, 12_000);
                assert_eq!(
                    shape(&run),
                    [(1, 1500, initial), (2, 1500, initial), (3, initial, initial), (4, halved, halved)]
                );
                t.recover();
                assert_eq!((t.info().current_mtu, t.info().search_low), (halved, halved));
                let run = renewed_stop(&mut t, 24_000);
                assert_eq!(
                    shape(&run),
                    [(1, halved, halved), (2, halved, halved), (3, initial, initial), (4, halved, halved)]
                );
                // The reset's retransmission still left (no stall below one
                // SMSS), within the byte window it kept.
                let retry = t.sent.iter().find(|s| s.at == run[2].at && s.payload > 0).unwrap();
                assert!(retry.payload as u32 <= run[2].cwnd);
                t.recover();
                if iss != 0x1000 {
                    assert!(t.a.snd_una.0 < iss, "the stream crossed sequence wrap");
                }
            }
        }
    }
}

fn family(ipv4: bool) -> (PmtudConfig, u32, u32, u32) {
    // (config, initial search_low, its loss-inferred half, black hole)
    let pmtud = PmtudConfig {
        initial_search_low: (!ipv4).then_some(1400),
        ..PmtudConfig::new(1500)
    };
    if ipv4 { (pmtud, 1024, 512, 600) } else { (pmtud, 1400, 1280, 1300) }
}

fn halve(ipv4: bool, mtu: u32) -> u32 {
    (mtu / 2).max(if ipv4 { 68 } else { 1280 })
}

#[test]
// A route policy MTU or first-hop MTU between the loss-inferred estimate and
// the initial search_low clips the renewed reset; the next timeout halves
// from the clipped value.
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.7
//= type=test
//= reason=User disposition (decision A, 2026-11-06, recorded): the reset is read as bounded by independently validated path ceilings, and the MAY of even lower bounds is not selected. Pmtud::timeout takes the black-hole action at R1, the third successive data RTO without cumulative progress or an explaining ICMP message since progress, with discovery enabled: if eff_pmtu is larger than search_low it sets eff_pmtu to search_low; otherwise it sets both eff_pmtu and search_low to the initial search_low, which may raise packet size above a loss-inferred estimate, bounded by reset_ceiling (first-hop, transport and configured search maximum, route policy and initial_search_high, administrative value, negative search evidence, accepted Packet Too Big authority and the managed shared estimate), never by the connection's current eff_pmtu. Each further successive timeout halves both, with a lower bound of 68 bytes for IPv4 and 1280 bytes for IPv6 (also bounded by the reset ceiling), clears probe and verification state and applies the fivefold cooldown. Accepted Packet Too Big authority outlives its hold and is released only by authorized path replacement or a larger acknowledged probe. A timeout whose reset raises the MSS keeps the byte cwnd held before the raise and its ssthresh (RFC 4821 section 4, RFC 5681 section 3.1); its retransmission and go-back-N repair leave within that window and the stream completes without another RTO; a later decrease takes the one-SMSS response. A loss-only fallback never publishes to or lowers the shared estimate. Real receiver traces in both families, SACK and non-SACK, across sequence wrap: IPv4 1500 to 1024 at RTO 3 and 512 at RTO 4, delivered recovery, then a renewed full stop resets to 1024 and halves to 512; IPv6 with initial search_low 1400: 1500 to 1400 to 1280, recovery, reset to 1400 then 1280. Route policy, first-hop, administrative, Packet Too Big and shared-estimate bounds clip the reset; with discovery disabled no fallback is taken, and re-enabling it during a run takes the run's first action (ntcp pmtud_reset_trace_tests.rs and pmtud_tests.rs, ntcp-host tests/black_hole_reset.rs).
//# The response to a detected black hole depends on the current values for search_low
//# and eff_pmtu. If eff_pmtu is larger than search_low, set eff_pmtu to search_low.
//# Otherwise, set both eff_pmtu and search_low to the initial value for search_low.
//# Upon additional successive timeouts, search_low and eff_pmtu SHOULD be halved, with
//# a lower bound of 68 bytes for IPv4 and 1280 bytes for IPv6. Even lower lower bounds
//# MAY be permitted to support limited operation over links with MTUs that are smaller
//# than permitted by the IP specifications.
fn renewed_reset_is_clipped_by_route_and_first_hop_mtu() {
    for ipv4 in [true, false] {
        for first_hop in [false, true] {
            let (pmtud, initial, halved, hole) = family(ipv4);
            let bound = if ipv4 { 900 } else { 1350 };
            let mut t = Trace::new(ipv4, true, u32::MAX - 30_000, pmtud);
            first_stop(&mut t, hole, 12_000);
            t.recover();
            if first_hop {
                t.a.set_first_hop_mtu(t.now, bound).unwrap();
            } else {
                t.a.set_route_mtu(t.now, Some(bound)).unwrap();
            }
            assert!(bound < initial);
            let run = renewed_stop(&mut t, 24_000);
            let next = halve(ipv4, bound);
            assert_eq!(
                shape(&run),
                [(1, halved, halved), (2, halved, halved), (3, bound, bound), (4, next, next)]
            );
            t.recover();
        }
    }
}

// Grows the estimate through acknowledged probes once the path carries
// 1500-byte packets again, until it exceeds `above`.
fn grow(t: &mut Trace, above: u32) {
    t.hole = u32::MAX;
    for _ in 0..64 {
        if t.info().current_mtu > above {
            return;
        }
        if let Some(deadline) = t.a.pmtud.as_ref().unwrap().next_deadline() {
            t.idle_until(deadline);
        }
        t.write(20_000);
        t.recover();
    }
    panic!("no probe grew the estimate past {above}");
}

#[test]
// An accepted Packet Too Big below the initial search_low bounds the reset:
// the first stop's fallback stays at it, and a renewed stop after its
// 600-second hold expired (the search may grow again) still resets to it,
// not to the initial search_low. A probe acknowledged at a larger size
// releases that authority: the next renewed stop resets to the initial low.
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.7
//= type=test
//= reason=User disposition (decision A, 2026-11-06, recorded): the reset is read as bounded by independently validated path ceilings, and the MAY of even lower bounds is not selected. Pmtud::timeout takes the black-hole action at R1, the third successive data RTO without cumulative progress or an explaining ICMP message since progress, with discovery enabled: if eff_pmtu is larger than search_low it sets eff_pmtu to search_low; otherwise it sets both eff_pmtu and search_low to the initial search_low, which may raise packet size above a loss-inferred estimate, bounded by reset_ceiling (first-hop, transport and configured search maximum, route policy and initial_search_high, administrative value, negative search evidence, accepted Packet Too Big authority and the managed shared estimate), never by the connection's current eff_pmtu. Each further successive timeout halves both, with a lower bound of 68 bytes for IPv4 and 1280 bytes for IPv6 (also bounded by the reset ceiling), clears probe and verification state and applies the fivefold cooldown. Accepted Packet Too Big authority outlives its hold and is released only by authorized path replacement or a larger acknowledged probe. A timeout whose reset raises the MSS keeps the byte cwnd held before the raise and its ssthresh (RFC 4821 section 4, RFC 5681 section 3.1); its retransmission and go-back-N repair leave within that window and the stream completes without another RTO; a later decrease takes the one-SMSS response. A loss-only fallback never publishes to or lowers the shared estimate. Real receiver traces in both families, SACK and non-SACK, across sequence wrap: IPv4 1500 to 1024 at RTO 3 and 512 at RTO 4, delivered recovery, then a renewed full stop resets to 1024 and halves to 512; IPv6 with initial search_low 1400: 1500 to 1400 to 1280, recovery, reset to 1400 then 1280. Route policy, first-hop, administrative, Packet Too Big and shared-estimate bounds clip the reset; with discovery disabled no fallback is taken, and re-enabling it during a run takes the run's first action (ntcp pmtud_reset_trace_tests.rs and pmtud_tests.rs, ntcp-host tests/black_hole_reset.rs).
//# The response to a detected black hole depends on the current values for search_low
//# and eff_pmtu. If eff_pmtu is larger than search_low, set eff_pmtu to search_low.
//# Otherwise, set both eff_pmtu and search_low to the initial value for search_low.
//# Upon additional successive timeouts, search_low and eff_pmtu SHOULD be halved, with
//# a lower bound of 68 bytes for IPv4 and 1280 bytes for IPv6. Even lower lower bounds
//# MAY be permitted to support limited operation over links with MTUs that are smaller
//# than permitted by the IP specifications.
fn renewed_reset_keeps_ptb_authority_past_its_hold_until_a_larger_probe() {
    for ipv4 in [true, false] {
        let (pmtud, initial, halved, hole) = family(ipv4);
        let reported = if ipv4 { 900 } else { 1350 };
        let mut t = Trace::new(ipv4, true, 0x2000, pmtud);
        t.hole = reported;
        t.ptb = true;
        t.write(12_000);
        t.recover();
        assert_eq!((t.info().current_mtu, t.info().search_low), (reported, reported));
        t.ptb = false;
        let ptb_at = t.now;
        let run = first_stop(&mut t, hole, 12_000);
        let next = halve(ipv4, reported);
        assert_eq!(
            shape(&run),
            [(1, reported, reported), (2, reported, reported), (3, reported, reported), (4, next, next)]
        );
        t.recover();
        // The hold ends: its search ceiling is forgotten.
        t.idle_until(ptb_at + 600_000_000 + 1);
        assert!(t.info().search_high > reported);
        let run = renewed_stop(&mut t, 24_000);
        assert_eq!(
            shape(&run),
            [(1, next, next), (2, next, next), (3, reported, reported), (4, next, next)]
        );
        t.recover();
        grow(&mut t, reported);
        let grown = t.info().current_mtu;
        let run = renewed_stop(&mut t, 24_000);
        assert_eq!(
            shape(&run),
            [(1, grown, grown), (2, grown, grown), (3, initial, initial), (4, halved, halved)]
        );
        t.recover();
    }
}

// D3 through a real receiver: a renewed full stop whose outage ends before
// R1, so the reset's own retransmission (cwnd below the raised SMSS) is
// delivered. The raising timeout keeps the byte window and ssthresh, the
// retransmission of SND.UNA leaves within that window and the reset MTU,
// and SACK, RACK and go-back-N repair (Nagle on and off) complete the
// stream across sequence wrap without another RTO.
#[test]
fn renewed_reset_repairs_below_one_smss_without_another_rto() {
    for ipv4 in [true, false] {
        for (sack, rack) in [(true, false), (true, true), (false, false)] {
            for nagle in [false, true] {
                for iss in [0x1000, u32::MAX - 20_000] {
                    let (pmtud, initial, halved, hole) = family(ipv4);
                    let mut t = Trace::with_rack(ipv4, sack, rack, iss, pmtud);
                    t.a.set_nagle(nagle);
                    if rack {
                        // A tail loss probe may take the first reduction
                        // before the RTO: check_congestion's first-timeout
                        // threshold does not apply.
                        t.hole = hole;
                        t.write(12_000);
                        assert_eq!(shape(t.timeouts(4))[3], (4, halved, halved));
                    } else {
                        first_stop(&mut t, hole, 12_000);
                    }
                    t.recover();
                    // The path heals; only the outage stops the flow.
                    t.hole = u32::MAX;
                    t.outage = true;
                    t.write(24_000);
                    let mut run = t.timeouts(2).to_vec();
                    t.outage = false;
                    run.extend_from_slice(t.timeouts(1));
                    let case = (ipv4, sack, rack, nagle, iss);
                    assert_eq!(
                        shape(&run),
                        [(1, halved, halved), (2, halved, halved), (3, initial, initial)],
                        "{case:?}"
                    );
                    if !rack {
                        t.check_congestion(&run);
                    }
                    let reset = run[2];
                    assert_eq!(reset.cwnd, reset.window, "{case:?}");
                    assert!(reset.cwnd < reset.mss, "{case:?}");
                    assert_eq!(reset.ssthresh, run[1].ssthresh, "{case:?}");
                    assert_eq!(reset.mss, t.mss_at(initial), "{case:?}");
                    assert_eq!(reset.window, t.mss_at(halved), "{case:?}");
                    // The mandatory retransmission of SND.UNA (RFC 6298
                    // 5.4) left at the reset and crossed, within the byte
                    // window the raise kept.
                    let retry = t.sent.iter().find(|s| s.at == reset.at && s.payload > 0).unwrap();
                    assert!(!retry.dropped, "{case:?}");
                    assert!(retry.payload as u32 <= reset.cwnd.min(reset.mss), "{case:?}");
                    t.recover();
                    if iss != 0x1000 {
                        assert!(t.a.snd_una.0 < iss, "the stream crossed sequence wrap");
                    }
                }
            }
        }
    }
}

// RFC 4821 section 7.7: an ICMP message explaining the loss since the last
// progress suppresses the black-hole action for the whole renewed run, both
// families, SACK and go-back-N; delivered progress then re-arms it.
#[test]
fn network_error_since_progress_suppresses_the_renewed_reset() {
    for ipv4 in [true, false] {
        for sack in [true, false] {
            let (pmtud, initial, halved, hole) = family(ipv4);
            let mut t = Trace::new(ipv4, sack, u32::MAX - 30_000, pmtud);
            first_stop(&mut t, hole, 12_000);
            t.recover();
            t.outage = true;
            t.write(24_000);
            let mut run = t.timeouts(1).to_vec();
            let una = t.a.snd_una.0;
            assert!(t.a.network_error(t.now, una, NetworkError::SoftUnreachable).unwrap());
            run.extend_from_slice(t.timeouts(2));
            // The outage ends before the fourth timeout: its retransmission
            // (at the unchanged size) recovers.
            t.outage = false;
            run.extend_from_slice(t.timeouts(1));
            assert_eq!(
                shape(&run),
                [(1, halved, halved), (2, halved, halved), (3, halved, halved), (4, halved, halved)],
                "{ipv4} {sack}"
            );
            t.recover();
            // Progress cleared the explanation: the next stop resets, to
            // the initial low within negative search evidence a black-holed
            // probe may have left meanwhile.
            let reset = initial.min(t.info().search_high);
            assert!(reset > halved);
            let run = renewed_stop(&mut t, 24_000);
            let next = halve(ipv4, reset);
            assert_eq!(
                shape(&run),
                [(1, halved, halved), (2, halved, halved), (3, reset, reset), (4, next, next)],
                "{ipv4} {sack}"
            );
            t.recover();
        }
    }
}
