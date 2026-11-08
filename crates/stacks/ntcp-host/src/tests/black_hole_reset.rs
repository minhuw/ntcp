// RFC 4821 section 7.7 black-hole recovery of managed connections through
// the Host: real sender and receiver Endpoints, queued wire frames with a
// one-way delay and every timer at its actual deadline. The network drops
// sender frames above a size, silently (a black hole) or with a router's
// Packet Too Big, and an optional outage drops every frame both ways. The
// reset of a renewed full stop is bounded by the path's shared estimate, an
// administrative estimate and accepted PTB authority (released by path
// replacement); disabled discovery takes no fallback; loss inference never
// publishes to or lowers the shared estimate.
use super::*;
use path::{AdminChange, AdminPolicy, AdminTarget};
use std::collections::VecDeque;

type Side = (Host, Endpoint, IngressContext);

const DELAY: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Step {
    count: u32,
    mtu: u32,
    low: u32,
    mss: u32,
    cwnd: u32,
    ssthresh: u32,
    // Byte window and SMSS just before the timeout.
    window: u32,
    prior_mss: u32,
    // The path's shared estimate after the timeout and the packet budget.
    shared: Option<u32>,
    budget: u32,
}

struct Net {
    a: Side,
    b: Side,
    tcp: ConnectionId,
    child: ConnectionId,
    now: u64,
    // (arrival, toward the receiver, IP frame)
    queue: VecDeque<(u64, bool, Vec<u8>)>,
    hole: u32,
    // The hole's router answers the first dropped frame with a PTB.
    ptb: bool,
    outage: bool,
    written: Vec<u8>,
    received: Vec<u8>,
    steps: Vec<Step>,
}

fn family(v6: bool) -> (u32, u32, u32) {
    // (initial search_low, its loss-inferred half, black hole)
    if v6 { (1400, 1280, 1300) } else { (1024, 512, 600) }
}

impl Net {
    fn new(v6: bool, identity: u64) -> Self {
        let mut cfg = config(2);
        cfg.connection.pmtud = Some(PmtudConfig {
            initial_search_low: v6.then_some(1400),
            ..PmtudConfig::new(1500)
        });
        let (local, remote) = addresses(v6);
        // DF-clear output of a discovery-disabled IPv4 path leases
        // Identifications.
        let mut a = managed_identified(local, identity, cfg.clone());
        let mut b = managed(remote, identity + 1, cfg.clone());
        let listener = b.1.listen(remote, 2).unwrap();
        let tcp = a
            .1
            .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        let child = b.1.accept(listener).unwrap();
        // pump's last input was at now + 3.
        now += 10;
        Net {
            a,
            b,
            tcp,
            child,
            now,
            queue: VecDeque::new(),
            hole: u32::MAX,
            ptb: false,
            outage: false,
            written: Vec::new(),
            received: Vec::new(),
            steps: Vec::new(),
        }
    }

    fn v6(&self) -> bool {
        self.a.1.tuple(self.tcp).unwrap().local.is_ipv6()
    }

    fn info(&self) -> ntcp::PathMtuInfo {
        self.a.1.path_mtu_info(self.tcp).unwrap().unwrap()
    }

    fn path(&self) -> path::PathId {
        self.a.0.binding(self.tcp).unwrap().snapshot.path()
    }

    fn shared(&self) -> Option<u32> {
        self.a.0.paths().path_snapshot(self.path()).unwrap().learned_mtu()
    }

    fn budget(&self) -> u32 {
        self.a.0.binding(self.tcp).unwrap().snapshot.ip_packet_budget().unwrap()
    }

    fn mss_at(&self, mtu: u32) -> u32 {
        mtu - if self.v6() { 40 } else { 20 } - 20 - 12
    }

    fn write(&mut self, len: usize) {
        let start = self.written.len();
        let bytes: Vec<u8> = (start..start + len).map(|i| (i % 251) as u8).collect();
        assert_eq!(self.a.1.write(self.tcp, &bytes).unwrap(), len);
        self.written.extend_from_slice(&bytes);
    }

    fn output(&mut self) {
        while let Some(frame) = emit(&mut self.a.0, &mut self.a.1, self.now) {
            let size = frame.len() as u32;
            if !self.outage && size > self.hole && self.ptb {
                // One real router report quoting the dropped frame; never
                // below the IPv6 minimum.
                assert!(!self.v6() || self.hole >= 1280);
                self.ptb = false;
                let report = super::dispatch::ptb(&frame, self.hole);
                let (_, published) = super::dispatch::tcp_report(
                    self.a.0.input_icmp(&mut self.a.1, self.a.2, self.now, &report, None).unwrap(),
                );
                assert_eq!(published, Some(path::EstimateChange::Decreased));
            } else if !self.outage && size <= self.hole {
                self.queue.push_back((self.now + DELAY, true, frame));
            }
        }
        while let Some(frame) = emit(&mut self.b.0, &mut self.b.1, self.now) {
            if !self.outage {
                self.queue.push_back((self.now + DELAY, false, frame));
            }
        }
        let mut read = vec![0; 65_536];
        while let Ok(n) = self.b.1.read(self.child, &mut read) {
            if n == 0 {
                break;
            }
            self.received.extend_from_slice(&read[..n]);
        }
    }

    fn next(&self) -> Option<u64> {
        [
            self.queue.front().map(|q| q.0),
            self.a.1.next_deadline(),
            self.b.1.next_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    fn advance(&mut self) {
        self.now = self.now.max(self.next().expect("a pending event"));
        while self.queue.front().is_some_and(|q| q.0 <= self.now) {
            let (_, toward, frame) = self.queue.pop_front().unwrap();
            if toward {
                input(&mut self.b.0, &mut self.b.1, self.b.2, self.now, &frame, 0);
            } else {
                input(&mut self.a.0, &mut self.a.1, self.a.2, self.now, &frame, 0);
            }
        }
        if self.a.1.next_deadline().is_some_and(|d| d <= self.now) {
            let before = self.a.1.transport_info(self.tcp).unwrap();
            self.a.1.on_timeout(self.now, 32).unwrap();
            let after = self.a.1.transport_info(self.tcp).unwrap();
            if after.rto_backoff > before.rto_backoff {
                let info = self.info();
                self.steps.push(Step {
                    count: after.rto_backoff,
                    mtu: info.current_mtu,
                    low: info.search_low,
                    mss: after.mss,
                    cwnd: after.cwnd,
                    ssthresh: after.ssthresh,
                    window: before.cwnd,
                    prior_mss: before.mss,
                    shared: self.shared(),
                    budget: self.budget(),
                });
            }
        }
        if self.b.1.next_deadline().is_some_and(|d| d <= self.now) {
            self.b.1.on_timeout(self.now, 32).unwrap();
        }
    }

    fn run_until(&mut self, done: impl Fn(&Net) -> bool) {
        for _ in 0..200_000 {
            self.output();
            if done(self) {
                return;
            }
            self.advance();
        }
        panic!("trace did not reach its condition");
    }

    fn idle_until(&mut self, until: u64) {
        loop {
            self.output();
            if self.next().is_none_or(|n| n > until) {
                break;
            }
            self.advance();
        }
        self.now = self.now.max(until);
    }

    fn timeouts(&mut self, count: usize) -> Vec<Step> {
        let start = self.steps.len();
        self.run_until(|t| t.steps.len() == start + count);
        self.steps[start..].to_vec()
    }

    // Delivered recovery: the stream drains through the receiver without a
    // further RTO, which clears the successive count.
    fn recover(&mut self) {
        let steps = self.steps.len();
        let tcp = self.tcp;
        self.run_until(|t| {
            let progress = t.a.1.send_progress(tcp).unwrap();
            progress.acknowledged == progress.queued_end && t.received.len() == t.written.len()
        });
        assert_eq!(self.steps.len(), steps, "recovery waited for another RTO");
        assert_eq!(self.a.1.transport_info(self.tcp).unwrap().rto_backoff, 0);
        assert_eq!(self.received, self.written);
    }

    // Repeated timeouts of a run keep ssthresh; cwnd is one current SMSS
    // unless the timeout's path step raised the SMSS, when the byte window
    // held before it is kept (RFC 4821 section 4). No timeout changes the
    // shared estimate.
    fn check(&self, run: &[Step], shared: Option<u32>) {
        for (i, step) in run.iter().enumerate() {
            assert_eq!(step.mss, self.mss_at(step.mtu.min(step.budget)), "{step:?}");
            assert_eq!(step.shared, shared, "{step:?}");
            if i > 0 {
                assert_eq!(step.count, run[i - 1].count + 1, "{step:?}");
                assert_eq!(step.ssthresh, run[i - 1].ssthresh, "{step:?}");
            }
            if step.mss > step.prior_mss {
                assert_eq!(step.cwnd, step.window, "{step:?}");
                assert!(step.cwnd < step.mss);
            } else {
                assert_eq!(step.cwnd, step.mss, "{step:?}");
            }
        }
    }

    // A black-hole full stop of four timeouts.
    fn stop(&mut self, hole: u32, len: usize) -> Vec<Step> {
        self.hole = hole;
        self.write(len);
        let run = self.timeouts(4);
        assert_eq!(run[0].count, 1);
        run
    }

    // A renewed full stop: an outage through the third timeout, so failure
    // persists past the reset and the fourth halves.
    fn renewed(&mut self, len: usize) -> Vec<Step> {
        self.outage = true;
        self.write(len);
        let mut run = self.timeouts(3);
        self.outage = false;
        run.extend(self.timeouts(1));
        assert_eq!(run[0].count, 1);
        run
    }
}

fn shape(run: &[Step]) -> Vec<(u32, u32, u32)> {
    run.iter().map(|s| (s.count, s.mtu, s.low)).collect()
}

fn halve(v6: bool, mtu: u32) -> u32 {
    (mtu / 2).max(if v6 { 1280 } else { 68 })
}

fn set_policy(net: &mut Net, disabled: bool, estimate: Option<u32>) {
    let capability = net.a.0.administration();
    let path = net.path();
    let expected = net.a.0.admin_path(&capability, path).unwrap().generation;
    let candidate = net
        .a
        .0
        .admin_validate(
            &capability,
            net.now,
            AdminChange {
                target: AdminTarget::Path(path),
                expected,
                policy: AdminPolicy {
                    discovery_disabled: disabled,
                    estimate,
                },
            },
        )
        .unwrap();
    net.a.0.admin_apply(&capability, &mut net.a.1, candidate).unwrap();
}

#[test]
// Loss-only fallback: 1500 -> initial -> half, recovery, renewed reset to
// the initial search_low and halving again, with the shared estimate
// untouched (None). A shared estimate between the half and the initial low
// (a trusted decrease) clips every reset and stays exactly as published.
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
fn managed_reset_is_bounded_by_the_shared_estimate_which_loss_never_changes() {
    for v6 in [false, true] {
        for decrease in [false, true] {
            let (initial, halved, hole) = family(v6);
            let mut t = Net::new(v6, 7700 + u64::from(v6) * 2 + u64::from(decrease));
            let bound = if v6 { 1350 } else { 900 };
            let shared = decrease.then_some(bound);
            if decrease {
                let path = t.path();
                t.a.0.trusted_decrease(t.now, path, bound).unwrap();
                t.a.0.refresh(&mut t.a.1, t.tcp).unwrap();
            }
            // The shared estimate bounds packets and the reset; eff_pmtu
            // stays connection-local until the fallback.
            let reset = if decrease { bound } else { initial };
            let next = halve(v6, reset);
            let run = t.stop(hole, 12_000);
            t.check(&run, shared);
            assert_eq!(
                shape(&run),
                [(1, 1500, initial), (2, 1500, initial), (3, reset, reset), (4, next, next)]
            );
            t.recover();
            let run = t.renewed(24_000);
            t.check(&run, shared);
            assert_eq!(
                shape(&run),
                [(1, next, next), (2, next, next), (3, reset, reset), (4, next, next)]
            );
            t.recover();
            assert_eq!(t.shared(), shared);
            if !decrease {
                assert_eq!(next, halved);
            }
        }
    }
}

#[test]
// A downward administrative estimate between the loss-inferred half and the
// initial search_low, set after recovery, clips the renewed reset.
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
fn managed_reset_is_bounded_by_an_administrative_estimate() {
    for v6 in [false, true] {
        let (initial, halved, hole) = family(v6);
        let mut t = Net::new(v6, 7720 + u64::from(v6));
        let run = t.stop(hole, 12_000);
        t.check(&run, None);
        assert_eq!(shape(&run)[2..], [(3, initial, initial), (4, halved, halved)]);
        t.recover();
        let bound = if v6 { 1350 } else { 900 };
        set_policy(&mut t, false, Some(bound));
        let shared = t.shared();
        assert!(shared.is_none_or(|s| s >= bound));
        let run = t.renewed(24_000);
        t.check(&run, shared);
        let next = halve(v6, bound);
        assert_eq!(
            shape(&run),
            [(1, halved, halved), (2, halved, halved), (3, bound, bound), (4, next, next)]
        );
        t.recover();
    }
}

#[test]
// Discovery disabled by the owner during an RTO run: the third timeout takes
// no fallback (its packets obey the disabled path's budget, below which
// the black hole still drops). Re-enabled before the fourth, that timeout
// takes the run's first action (eff_pmtu to search_low) and the fifth
// halves, not a second halving.
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
fn managed_disabled_discovery_takes_no_fallback_until_re_enabled_in_the_run() {
    for v6 in [false, true] {
        let (initial, halved, _) = family(v6);
        let mut t = Net::new(v6, 7730 + u64::from(v6));
        // Below every packet the path will carry.
        t.hole = if v6 { 1200 } else { 500 };
        t.write(12_000);
        let mut run = t.timeouts(2);
        set_policy(&mut t, true, None);
        run.extend(t.timeouts(1));
        set_policy(&mut t, false, None);
        run.extend(t.timeouts(1));
        // The path heals after the fourth timeout's packet was lost.
        t.hole = u32::MAX;
        run.extend(t.timeouts(1));
        t.check(&run, None);
        assert_eq!(
            shape(&run),
            [(1, 1500, initial), (2, 1500, initial), (3, 1500, initial), (4, initial, initial), (5, halved, halved)]
        );
        t.recover();
    }
}

#[test]
// A router's PTB below the initial search_low is accepted (published to the
// path, current-path authority): the black-hole fallback stays at it and,
// after its 600-second hold, a renewed reset still goes no higher. An
// authorized path replacement (a DSCP rebind to another path) releases it:
// the next reset goes to the initial search_low.
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
fn managed_ptb_authority_outlives_its_hold_and_path_replacement_releases_it() {
    for v6 in [false, true] {
        let (initial, halved, hole) = family(v6);
        let mut t = Net::new(v6, 7740 + u64::from(v6));
        let reported = if v6 { 1350 } else { 900 };
        t.hole = reported;
        t.ptb = true;
        t.write(12_000);
        t.recover();
        assert!(!t.ptb, "a router reported the drop");
        assert_eq!((t.info().current_mtu, t.info().search_low), (reported, reported));
        let shared = Some(reported);
        assert_eq!(t.shared(), shared);
        let ptb_at = t.now;
        let next = halve(v6, reported);
        let run = t.stop(hole, 12_000);
        t.check(&run, shared);
        assert_eq!(
            shape(&run),
            [(1, reported, reported), (2, reported, reported), (3, reported, reported), (4, next, next)]
        );
        t.recover();
        let hold = 600 * t.a.1.caller_timebase().units_per_second;
        t.idle_until(ptb_at + hold + 1);
        let run = t.renewed(12_000);
        t.check(&run, shared);
        assert_eq!(shape(&run)[2..], [(3, reported, reported), (4, next, next)]);
        t.recover();
        let old = t.path();
        t.a.0.rebind_dscp(&mut t.a.1, t.tcp, 8).unwrap();
        assert_ne!(t.path(), old);
        assert_eq!(t.shared(), None);
        let run = t.renewed(12_000);
        t.check(&run, None);
        assert_eq!(
            shape(&run),
            [(1, initial, initial), (2, initial, initial), (3, initial, initial), (4, halved, halved)]
        );
        t.recover();
    }
}
