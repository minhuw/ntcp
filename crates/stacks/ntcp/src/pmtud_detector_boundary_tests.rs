// RFC 4821 section 6.1 detector-boundary schedules for an original PLPMTUD
// probe, through a real receiver Endpoint in both families and across
// sequence wrap. The sender emits one flight at one tick: a leading original
// L, the probe P (always lost) and trailing originals T0... Each schedule
// then decides, packet by packet, what the receiver gets and which of its
// genuine ACKs reach the sender, and fires sender timers at exact ticks
// around the RACK deadline. The provisional classification is asserted at
// each boundary, before the finite tail proof; a drain phase then repairs
// everything (late originals first), and the final classification is read
// when the probe resolves: isolated (search_high = probe - 1, no congestion
// response), other loss (bounds unchanged, response committed) or timeout.
use super::*;
use crate::{Endpoint, EndpointConfig, PmtudConfig};
use alloc::format;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    NewReno,
    Sack,
    Rack,
}

// The sender's view at a boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    // No loss detected: no recovery, no response, bounds unchanged.
    Undetected,
    // Only the probe is detected lost: recovery with the congestion response
    // held pending the finite tail proof.
    Pending,
    // Other loss detected: the normal congestion response is committed.
    Committed,
}

// Ordered from least to most conservative.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Final {
    Isolated,
    Other,
    Timeout,
}

#[derive(Clone, Copy, Debug)]
enum Step {
    // The receiver gets the packet; its ACK reaches the sender (true) or is lost.
    Deliver(usize, bool),
    // The receiver gets the packets at one tick; their ACKs reach the sender
    // together at that tick (ACK compression).
    Batch(&'static [usize]),
    // Move to the RACK deadline (captured on first use) plus an offset; a
    // delivery that follows happens at that tick.
    AtDeadline(i64),
    // Move to the RACK deadline as currently armed.
    NextDeadline,
    // Service the sender's timers now.
    Timer,
    Expect(Class),
}

const L: usize = 0;
const T0: usize = 2;
const T1: usize = 3;
const T2: usize = 4;
const T3: usize = 5;
const T4: usize = 6;
const T5: usize = 7;

struct Case<'a> {
    name: &'static str,
    mode: Mode,
    // Observe reordering (a SACKed original later cumulatively acknowledged)
    // before the probe flight.
    reordered_history: bool,
    // Full-sized trailing segments beyond the three the probe requires.
    extra: usize,
    // One-byte trailing segments after the full-sized ones.
    small: usize,
    steps: &'a [Step],
    // Originals the network loses for good (besides the probe).
    lost: &'a [usize],
    // The network loses the first repair copy of the probe.
    lose_repair: bool,
    result: Final,
}

const RTT: u64 = 1000;
const FLIGHT: u64 = 5000;

fn v6_tuple() -> Tuple {
    Tuple {
        local: "[2001:db8::1]:1000".parse().unwrap(),
        remote: "[2001:db8::2]:2000".parse().unwrap(),
    }
}

struct Net {
    a: Connection,
    b: Endpoint,
    child: Option<crate::ConnectionId>,
    now: u64,
    written: Vec<u8>,
    received: Vec<u8>,
}

impl Net {
    fn new(ipv4: bool, mode: Mode, prr: bool, iss: u32, low: u32) -> Self {
        let tuple = if ipv4 { tuple() } else { v6_tuple() };
        let cfg = ConnectionConfig {
            pmtud: Some(PmtudConfig {
                initial_mtu: Some(low),
                ..PmtudConfig::new(1500)
            }),
            initial_window: InitialWindow::Iw10,
            sack: mode != Mode::NewReno,
            rack: mode == Mode::Rack,
            prr,
            nagle: false,
            timestamps: false,
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
        let mut net = Net {
            a,
            b,
            child: None,
            now: 0,
            written: Vec::new(),
            received: Vec::new(),
        };
        // A handshake with a real round trip, so RACK's settling window
        // (min_RTT / 4) is not zero.
        let syn = net.send();
        assert_eq!(syn.len(), 1);
        net.now = RTT / 2;
        let synack = net.deliver_forward(&syn[0]);
        net.now = RTT;
        net.deliver_reverse(&synack);
        let ack = net.send();
        net.now = 3 * RTT / 2;
        for bytes in &ack {
            net.deliver_forward(bytes);
        }
        net.child = Some(net.b.accept(listener).unwrap());
        assert_eq!(net.a.state(), State::Established);
        net
    }

    fn header(&self) -> u32 {
        if self.a.tuple.local.is_ipv4() { 20 } else { 40 }
    }

    fn write(&mut self, len: usize) {
        let start = self.written.len();
        let bytes: Vec<u8> = (start..start + len).map(|i| (i % 251) as u8).collect();
        assert_eq!(self.a.write(&bytes).unwrap(), len);
        self.written.extend_from_slice(&bytes);
    }

    fn transmit(&mut self) -> Option<Vec<u8>> {
        let mut out = vec![0; 2000];
        let n = self.a.transmit(self.now, &mut out).unwrap()?;
        out.truncate(n);
        Some(out)
    }

    fn send(&mut self) -> Vec<Vec<u8>> {
        core::iter::from_fn(|| self.transmit()).collect()
    }

    // The receiver's ACKs for one arriving packet.
    fn deliver_forward(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        self.b.input(self.now, ip(self.a.tuple), bytes).unwrap();
        let mut acks = Vec::new();
        let mut out = vec![0; 2000];
        while let Some(p) = self.b.poll_transmit(self.now, &mut out, 16).unwrap().packet {
            acks.push(out[..p.len].to_vec());
        }
        acks
    }

    // The application reads only after the run: a read between ACKs would
    // open the advertised window and disqualify duplicate ACKs (RFC 5681).
    fn read(&mut self) {
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

    fn deliver_reverse(&mut self, acks: &[Vec<u8>]) {
        for ack in acks {
            let segment = wire::parse(ip(reverse(self.a.tuple)), ack).unwrap();
            self.a.input(self.now, &segment).unwrap();
        }
    }

    fn seq(&self, bytes: &[u8]) -> (Seq, usize) {
        let segment = wire::parse(ip(self.a.tuple), bytes).unwrap();
        (Seq(segment.header.sequence), segment.payload.len())
    }
}

#[derive(Debug)]
struct Outcome {
    result: Final,
    // Every original-flight and repair packet stayed within the MTU bound.
    bounded: bool,
}

// Runs one schedule; returns the final classification after asserting the
// boundary expectations, MTU bounds, congestion state and complete delivery.
fn run(case: &Case<'_>, ipv4: bool, iss: u32, prr: bool) -> Outcome {
    let label = format!("{} ipv4={ipv4} iss={iss:#x} prr={prr}", case.name);
    let low = if ipv4 { 1024 } else { 1280 };
    let mut net = Net::new(ipv4, case.mode, prr, iss, low);
    let mss = net.a.mss;
    assert_eq!(mss as u32, low - net.header() - 20);
    // Warm up with one real round trip.
    net.write(mss);
    let warm = net.send();
    net.now += RTT / 2;
    let acks: Vec<_> = warm.iter().flat_map(|w| net.deliver_forward(w)).collect();
    net.now += RTT / 2;
    net.deliver_reverse(&acks);
    if case.reordered_history {
        net.now += 1;
        net.write(100);
        let first = net.transmit().unwrap();
        net.write(100);
        let second = net.transmit().unwrap();
        net.now += RTT;
        let acks = net.deliver_forward(&second);
        net.deliver_reverse(&acks);
        let acks = net.deliver_forward(&first);
        net.deliver_reverse(&acks);
        assert_eq!(net.a.snd_una, net.a.snd_nxt);
    }
    assert!(net.a.pmtud.as_ref().unwrap().probe.is_none());

    // The flight, at one tick.
    net.now = FLIGHT;
    net.write(800);
    let mut packets = vec![net.transmit().unwrap()];
    assert!(net.a.pmtud.as_ref().unwrap().probe.is_none());
    let size = net.a.pmtud.as_ref().unwrap().target().expect("probe due");
    let payload = (size - net.header() - 20) as usize;
    net.write(payload + (3 + case.extra) * mss);
    packets.push(
        net.transmit()
            .unwrap_or_else(|| panic!("{label}: probe admitted")),
    );
    let probe = net.a.pmtud.as_ref().unwrap().probe.expect("original probe");
    assert_eq!((probe.start, probe.size), (net.seq(&packets[1]).0, size));
    for _ in 0..3 + case.extra {
        let bytes = net.transmit().unwrap();
        assert_eq!(net.seq(&bytes).1, mss);
        packets.push(bytes);
    }
    for _ in 0..case.small {
        net.write(1);
        let bytes = net.transmit().unwrap();
        assert_eq!(net.seq(&bytes).1, 1);
        packets.push(bytes);
    }
    assert!(
        net.transmit().is_none(),
        "{label}: the flight is exactly the schedule's"
    );
    let tail_end = net.a.snd_nxt;
    assert!(tail_end.at_or_after(probe.trailing_end));
    if iss > u32::MAX / 2 {
        assert!(
            tail_end.0 < probe.start.0,
            "{label}: the tail crosses sequence wrap"
        );
    }
    let before = net.a.path_mtu_info().unwrap();
    let (window, threshold) = (net.a.congestion.cwnd(), net.a.congestion.ssthresh());
    let mut delivered = vec![false; packets.len()];
    let mut deadline = None;
    let mut timed_out = false;
    let mut pinned = false;

    net.now = FLIGHT + RTT - 1;
    for (i, step) in case.steps.iter().enumerate() {
        let at = format!("{label} step {i} {step:?}");
        match *step {
            Step::Deliver(n, ack) => {
                net.now += u64::from(!core::mem::take(&mut pinned));
                delivered[n] = true;
                let acks = net.deliver_forward(&packets[n]);
                assert!(!acks.is_empty(), "{at}: an immediate receiver ACK");
                if ack {
                    net.deliver_reverse(&acks);
                }
            }
            Step::Batch(list) => {
                net.now += u64::from(!core::mem::take(&mut pinned));
                let mut acks = Vec::new();
                for &n in list {
                    delivered[n] = true;
                    acks.extend(net.deliver_forward(&packets[n]));
                }
                assert_eq!(acks.len(), list.len());
                net.deliver_reverse(&acks);
            }
            Step::AtDeadline(offset) => {
                let d = *deadline
                    .get_or_insert_with(|| net.a.rack.deadline.expect("RACK settling timer armed"));
                let target = d.checked_add_signed(offset).unwrap();
                assert!(target >= net.now, "{at}: the deadline is ahead");
                net.now = target;
                pinned = true;
            }
            Step::NextDeadline => {
                let d = net.a.rack.deadline.expect("RACK settling timer armed");
                assert!(d > net.now, "{at}: the deadline is ahead");
                net.now = d;
                pinned = true;
            }
            Step::Timer => {
                net.a.timeout(net.now).unwrap();
                timed_out |= net.a.consecutive_timeouts > 0;
            }
            Step::Expect(class) => {
                let c = &net.a.congestion;
                let observed = match (c.in_recovery(), c.pending_probe_response()) {
                    (false, None) => Class::Undetected,
                    (true, Some(start)) => {
                        assert_eq!(start, probe.start, "{at}");
                        Class::Pending
                    }
                    (true, None) => Class::Committed,
                    (false, Some(_)) => panic!("{at}: pending response outside recovery"),
                };
                assert_eq!(observed, class, "{at}");
                // Provisional: no MTU decision before the finite tail proof.
                assert_eq!(net.a.path_mtu_info().unwrap(), before, "{at}");
                assert_eq!(
                    net.a.pmtud.as_ref().unwrap().probe.map(|p| p.start),
                    Some(probe.start)
                );
                if class == Class::Committed {
                    assert!(c.ssthresh() < threshold, "{at}");
                } else {
                    assert_eq!(c.ssthresh(), threshold, "{at}");
                }
            }
        }
    }

    // Drain: late originals arrive, then every repair crosses (save a lost
    // repair copy of the probe), ACKs at once; idle ticks go to the next timer.
    let mut resolved = None;
    let mut bounded = true;
    let mut repair_lost = !case.lose_repair;
    let check = |net: &Net, resolved: &mut Option<_>, timed_out: bool| {
        if resolved.is_none()
            && net.a.pmtud.as_ref().unwrap().probe.map(|p| p.start) != Some(probe.start)
        {
            *resolved = Some((
                net.a.path_mtu_info().unwrap(),
                net.a.congestion.ssthresh(),
                net.a.congestion.cwnd(),
                timed_out,
                net.now,
            ));
        }
    };
    net.now += 1;
    for n in 0..packets.len() {
        if n != 1 && !delivered[n] && !case.lost.contains(&n) {
            let acks = net.deliver_forward(&packets[n]);
            net.deliver_reverse(&acks);
            check(&net, &mut resolved, timed_out);
        }
    }
    for _ in 0..400 {
        if resolved.is_some() && net.a.acknowledged() == net.written.len() as u64 {
            break;
        }
        net.now += 1;
        let out = net.send();
        if out.is_empty() {
            net.now = net
                .now
                .max(net.a.next_deadline().expect("unrepaired data has a timer"));
            net.a.timeout(net.now).unwrap();
            if resolved.is_none() {
                timed_out |= net.a.consecutive_timeouts > 0;
            }
            check(&net, &mut resolved, timed_out);
            continue;
        }
        for bytes in out {
            let (seq, len) = net.seq(&bytes);
            let fresh = net
                .a
                .pmtud
                .as_ref()
                .unwrap()
                .probe
                .is_some_and(|p| p.start == seq)
                && seq != probe.start;
            if bytes.len() as u32 + net.header() > low && !fresh {
                bounded = false;
            }
            if !repair_lost
                && seq.in_window(probe.start, probe.end.distance_from(probe.start)) == Some(true)
                && len > 0
            {
                repair_lost = true;
                continue;
            }
            let acks = net.deliver_forward(&bytes);
            net.deliver_reverse(&acks);
            check(&net, &mut resolved, timed_out);
        }
    }
    net.read();
    let (info, ssthresh, cwnd, timed_out, at) =
        resolved.unwrap_or_else(|| panic!("{label}: the probe never resolved"));
    assert_eq!(net.received, net.written, "{label}: complete delivery");
    assert!(repair_lost, "{label}: the schedule lost a repair copy");
    let result = if timed_out {
        Final::Timeout
    } else if info.search_high == probe.size - 1 {
        Final::Isolated
    } else {
        Final::Other
    };
    match result {
        Final::Isolated => {
            // Only the size bound moves; the response stays suppressed.
            assert_eq!(info.current_mtu, before.current_mtu, "{label}");
            assert_eq!(info.search_low, before.search_low, "{label}");
            assert_eq!(ssthresh, threshold, "{label}");
            assert!(cwnd >= window, "{label}: no window reduction");
            // The failure headway holds the next probe.
            assert!(
                net.a
                    .pmtud
                    .as_ref()
                    .unwrap()
                    .deadline
                    .is_some_and(|d| d > at),
                "{label}"
            );
        }
        Final::Other | Final::Timeout => {
            assert_eq!(info, before, "{label}: other loss supplies no MTU bound");
            assert!(
                ssthresh < threshold,
                "{label}: committed congestion response"
            );
            assert!(cwnd < window, "{label}");
        }
    }
    Outcome { result, bounded }
}

// Without PRR every schedule must reach its tabled outcome exactly. With
// RFC 9937 PRR, repair credit is counted in bytes: it can split a repair
// into a sub-MSS segment, and without SACK the partial ACK of that segment
// is no larger than the episode's duplicate-ACK delivery estimate, so it
// grants no credit and recovery of the rest waits for the RTO (NewReno
// tables: timeout instead of isolated or other loss). With SACK the split
// can leave the probe's tail as the RFC 6675 rescue candidate, whose
// selection commits the response (the 2*SMSS + 1 schedule: other loss).
// PRR runs must still never be less conservative than the tabled outcome.
fn run_all(cases: &[Case<'_>]) {
    for case in cases {
        for ipv4 in [true, false] {
            for iss in [0x1000, u32::MAX - 3000] {
                for prr in [false, true] {
                    let outcome = run(case, ipv4, iss, prr);
                    let label = format!("{} ipv4={ipv4} iss={iss:#x} prr={prr}", case.name);
                    assert!(outcome.bounded, "{label}");
                    if prr {
                        assert!(outcome.result >= case.result, "{label}: {outcome:?}");
                    } else {
                        assert_eq!(outcome.result, case.result, "{label}");
                    }
                }
            }
        }
    }
}

use Class::*;
use Step::*;

const fn case(
    name: &'static str,
    mode: Mode,
    steps: &'static [Step],
    result: Final,
) -> Case<'static> {
    Case {
        name,
        mode,
        reordered_history: false,
        extra: 0,
        small: 0,
        steps,
        lost: &[],
        lose_repair: false,
        result,
    }
}

#[test]
// NewReno (no SACK): two versus three eligible duplicate ACKs (RFC 5681
// DupThresh). Cumulative ACKs make a lost leading-progress ACK harmless when
// later ACKs cover it; a lost decisive ACK with no later segment leaves the
// probe to the retransmission timer, which is inconclusive and commits the
// response.
//= https://www.rfc-editor.org/rfc/rfc4821#section-6.1
//= type=test
//= reason=Real receiver NewReno/SACK/RACK traces in both families across serial wrap contrast leading-original delivery before DupThresh/RACK settling, actual leading-plus-probe loss, late leading delivery after detection, and reorder without probe loss. Table-driven detector-boundary schedules through real receiver Endpoints (pmtud_detector_boundary_tests.rs; both families, serial wrap, PRR off and on, reproducible seeds) add NewReno two versus three eligible duplicate ACKs, RFC 6675 IsLost two versus three discontiguous SACKed ranges and exactly 2*SMSS versus one byte more above the candidate, and RACK at the settling deadline - 1, = and + 1 with ACK-before-timer and timer-before-ACK orderings at equality, observed reordering and the three-SACK transition. At each boundary they lose the decisive or leading-progress ACK, batch genuine receiver ACKs at one tick, reorder leading and trailing originals and lose a repair copy, asserting the provisional classification before finite tail proof, the final isolated, other-loss or timeout outcome, MTU bounds, congestion commitment, packets within the MTU bound and complete delivery, including controls where ACK loss leaves insufficient evidence and recovery waits for a timer; seeded schedules never report an isolated probe loss when another original or a repair copy was lost. Finite tail/recovery proof gates isolation; other detected loss commits congestion response with unchanged MTU bounds and eventual stream progress. Existing trailing-hole, repair-copy, ECN, matching-PTB and inconclusive-RTO controls remain complementary. With PRR, byte-granular repair can end a NewReno isolated probe loss at the RTO, or leave the probe's tail as the RFC 6675 rescue retransmission, which commits the response: more conservative outcomes, with packet-aware recovery left to T22. Full timing/reordering robustness beyond these detector conditions remains unestablished: a finite-time ambiguity, not a missing detector function; sufficiently late leading originals are conservatively treated as other loss, not magically identified as reorder. Counterexample, for the T23 disposition: Drop the probe and withhold its leading original until after the selected loss detector fires. Through that decision, the sender's observations are identical to a run in which both packets were lost. Later delivery of the leading original cannot make the earlier decision distinguish those runs. Losing its progress ACK extends the ambiguity. Retain the whole timely/robust loss-reporting advice as TODO for that evidence/interpretation boundary.
//# It is important that the Packetization Layer has a timely and robust mechanism for detecting and reporting losses. PLPMTUD makes MTU adjustments on the basis of detected losses. Any delays or inaccuracy in loss notification is likely to result in incorrect MTU decisions or slow convergence. It is important that the mechanism can robustly distinguish between the isolated loss of just a probe and other losses in the probe's leading and trailing windows.
fn newreno_duplicate_ack_threshold_boundaries() {
    let cases = [
        case(
            "two dupacks, decisive ACK lost: timer",
            Mode::NewReno,
            &[
                Deliver(L, true),
                Deliver(T0, true),
                Deliver(T1, true),
                Deliver(T2, false),
                Expect(Undetected),
            ],
            Final::Timeout,
        ),
        case(
            "three dupacks",
            Mode::NewReno,
            &[
                Deliver(L, true),
                Deliver(T0, true),
                Deliver(T1, true),
                Expect(Undetected),
                Deliver(T2, true),
                Expect(Pending),
            ],
            Final::Isolated,
        ),
        Case {
            extra: 1,
            ..case(
                "decisive ACK lost, a later segment supplies it",
                Mode::NewReno,
                &[
                    Deliver(L, true),
                    Deliver(T0, true),
                    Deliver(T1, true),
                    Deliver(T2, false),
                    Expect(Undetected),
                    Deliver(T3, true),
                    Expect(Pending),
                ],
                Final::Isolated,
            )
        },
        case(
            "ACKs batched at one tick",
            Mode::NewReno,
            &[Deliver(L, true), Batch(&[T0, T1, T2]), Expect(Pending)],
            Final::Isolated,
        ),
        Case {
            extra: 1,
            ..case(
                "trailing reordered",
                Mode::NewReno,
                &[
                    Deliver(L, true),
                    Deliver(T3, true),
                    Deliver(T1, true),
                    Expect(Undetected),
                    Deliver(T0, true),
                    Expect(Pending),
                ],
                Final::Isolated,
            )
        },
        Case {
            extra: 2,
            ..case(
                "leading reordered before the third dupack",
                Mode::NewReno,
                &[
                    Deliver(T0, true),
                    Deliver(T1, true),
                    Expect(Undetected),
                    Deliver(L, true),
                    Deliver(T2, true),
                    Deliver(T3, true),
                    Expect(Undetected),
                    Deliver(T4, true),
                    Expect(Pending),
                ],
                Final::Isolated,
            )
        },
        case(
            "leading reordered after the third dupack",
            Mode::NewReno,
            &[
                Deliver(T0, true),
                Deliver(T1, true),
                Deliver(T2, true),
                Expect(Committed),
                Deliver(L, true),
                Expect(Committed),
            ],
            Final::Other,
        ),
        Case {
            extra: 1,
            ..case(
                "leading-progress ACK lost, covered later",
                Mode::NewReno,
                &[
                    Deliver(L, false),
                    Deliver(T0, true),
                    Deliver(T1, true),
                    Deliver(T2, true),
                    Expect(Undetected),
                    Deliver(T3, true),
                    Expect(Pending),
                ],
                Final::Isolated,
            )
        },
        case(
            "leading-progress ACK lost, two dupacks left: timer",
            Mode::NewReno,
            &[
                Deliver(L, false),
                Deliver(T0, true),
                Deliver(T1, true),
                Deliver(T2, true),
                Expect(Undetected),
            ],
            Final::Timeout,
        ),
        Case {
            lose_repair: true,
            ..case(
                "repair copy lost",
                Mode::NewReno,
                &[
                    Deliver(L, true),
                    Deliver(T0, true),
                    Deliver(T1, true),
                    Deliver(T2, true),
                    Expect(Pending),
                ],
                Final::Timeout,
            )
        },
        Case {
            lost: &[L],
            ..case(
                "leading original lost",
                Mode::NewReno,
                &[
                    Deliver(T0, true),
                    Deliver(T1, true),
                    Deliver(T2, true),
                    Expect(Committed),
                ],
                Final::Other,
            )
        },
    ];
    run_all(&cases);
}

#[test]
// RFC 6675 IsLost (sack.rs is_lost) at its two boundaries, with ACK loss
// keeping DupAcks below three: two versus three discontiguous SACKed ranges
// above the candidate (one-byte segments keep the bytes below 2*SMSS), and
// exactly 2*SMSS versus one byte more SACKed above it.
//= https://www.rfc-editor.org/rfc/rfc4821#section-6.1
//= type=test
//= reason=Real receiver NewReno/SACK/RACK traces in both families across serial wrap contrast leading-original delivery before DupThresh/RACK settling, actual leading-plus-probe loss, late leading delivery after detection, and reorder without probe loss. Table-driven detector-boundary schedules through real receiver Endpoints (pmtud_detector_boundary_tests.rs; both families, serial wrap, PRR off and on, reproducible seeds) add NewReno two versus three eligible duplicate ACKs, RFC 6675 IsLost two versus three discontiguous SACKed ranges and exactly 2*SMSS versus one byte more above the candidate, and RACK at the settling deadline - 1, = and + 1 with ACK-before-timer and timer-before-ACK orderings at equality, observed reordering and the three-SACK transition. At each boundary they lose the decisive or leading-progress ACK, batch genuine receiver ACKs at one tick, reorder leading and trailing originals and lose a repair copy, asserting the provisional classification before finite tail proof, the final isolated, other-loss or timeout outcome, MTU bounds, congestion commitment, packets within the MTU bound and complete delivery, including controls where ACK loss leaves insufficient evidence and recovery waits for a timer; seeded schedules never report an isolated probe loss when another original or a repair copy was lost. Finite tail/recovery proof gates isolation; other detected loss commits congestion response with unchanged MTU bounds and eventual stream progress. Existing trailing-hole, repair-copy, ECN, matching-PTB and inconclusive-RTO controls remain complementary. With PRR, byte-granular repair can end a NewReno isolated probe loss at the RTO, or leave the probe's tail as the RFC 6675 rescue retransmission, which commits the response: more conservative outcomes, with packet-aware recovery left to T22. Full timing/reordering robustness beyond these detector conditions remains unestablished: a finite-time ambiguity, not a missing detector function; sufficiently late leading originals are conservatively treated as other loss, not magically identified as reorder. Counterexample, for the T23 disposition: Drop the probe and withhold its leading original until after the selected loss detector fires. Through that decision, the sender's observations are identical to a run in which both packets were lost. Later delivery of the leading original cannot make the earlier decision distinguish those runs. Losing its progress ACK extends the ambiguity. Retain the whole timely/robust loss-reporting advice as TODO for that evidence/interpretation boundary.
//# It is important that the Packetization Layer has a timely and robust mechanism for detecting and reporting losses. PLPMTUD makes MTU adjustments on the basis of detected losses. Any delays or inaccuracy in loss notification is likely to result in incorrect MTU decisions or slow convergence. It is important that the mechanism can robustly distinguish between the isolated loss of just a probe and other losses in the probe's leading and trailing windows.
fn sack_islost_range_and_byte_boundaries() {
    let cases = [
        case(
            "exactly 2*SMSS, decisive ACK lost: timer",
            Mode::Sack,
            &[
                Deliver(L, true),
                Deliver(T0, false),
                Deliver(T1, true),
                Deliver(T2, false),
                Expect(Undetected),
            ],
            Final::Timeout,
        ),
        Case {
            small: 1,
            ..case(
                "2*SMSS + 1 byte",
                Mode::Sack,
                &[
                    Deliver(L, true),
                    Deliver(T0, false),
                    Deliver(T1, true),
                    Expect(Undetected),
                    Deliver(T3, true),
                    Expect(Pending),
                ],
                Final::Isolated,
            )
        },
        Case {
            small: 3,
            ..case(
                "two versus three discontiguous ranges",
                Mode::Sack,
                &[
                    Deliver(L, true),
                    Deliver(T0, false),
                    Deliver(T3, true),
                    Expect(Undetected),
                    Deliver(T5, true),
                    Expect(Pending),
                ],
                Final::Isolated,
            )
        },
        case(
            "three SACK ACKs",
            Mode::Sack,
            &[
                Deliver(L, true),
                Deliver(T0, true),
                Deliver(T1, true),
                Expect(Undetected),
                Deliver(T2, true),
                Expect(Pending),
            ],
            Final::Isolated,
        ),
        case(
            "ACKs batched at one tick",
            Mode::Sack,
            &[Deliver(L, true), Batch(&[T0, T1, T2]), Expect(Pending)],
            Final::Isolated,
        ),
        case(
            "leading reordered before IsLost",
            Mode::Sack,
            &[
                Deliver(T0, true),
                Deliver(L, true),
                Deliver(T1, true),
                Expect(Undetected),
                Deliver(T2, true),
                Expect(Pending),
            ],
            Final::Isolated,
        ),
        case(
            "leading reordered after IsLost",
            Mode::Sack,
            &[
                Deliver(T0, true),
                Deliver(T1, true),
                Deliver(T2, true),
                Expect(Committed),
                Deliver(L, true),
                Expect(Committed),
            ],
            Final::Other,
        ),
        Case {
            small: 1,
            ..case(
                "trailing reordered",
                Mode::Sack,
                &[
                    Deliver(L, true),
                    Deliver(T3, true),
                    Deliver(T1, true),
                    Expect(Undetected),
                    Deliver(T0, true),
                    Expect(Pending),
                ],
                Final::Isolated,
            )
        },
        Case {
            lose_repair: true,
            ..case(
                "repair copy lost",
                Mode::Sack,
                &[
                    Deliver(L, true),
                    Deliver(T0, true),
                    Deliver(T1, true),
                    Deliver(T2, true),
                    Expect(Pending),
                ],
                Final::Timeout,
            )
        },
    ];
    run_all(&cases);
}

#[test]
// RACK (RFC 8985): the settling deadline - 1, = and + 1, with the leading
// original arriving at each and both ACK-before-timer and timer-before-ACK
// orderings at equality; the three-SACK transition to a zero window and its
// suppression by observed reordering. A leading original delivered in time
// whose ACK is lost is, through the timer's decision, indistinguishable from
// its loss: other loss.
//= https://www.rfc-editor.org/rfc/rfc4821#section-6.1
//= type=test
//= reason=Real receiver NewReno/SACK/RACK traces in both families across serial wrap contrast leading-original delivery before DupThresh/RACK settling, actual leading-plus-probe loss, late leading delivery after detection, and reorder without probe loss. Table-driven detector-boundary schedules through real receiver Endpoints (pmtud_detector_boundary_tests.rs; both families, serial wrap, PRR off and on, reproducible seeds) add NewReno two versus three eligible duplicate ACKs, RFC 6675 IsLost two versus three discontiguous SACKed ranges and exactly 2*SMSS versus one byte more above the candidate, and RACK at the settling deadline - 1, = and + 1 with ACK-before-timer and timer-before-ACK orderings at equality, observed reordering and the three-SACK transition. At each boundary they lose the decisive or leading-progress ACK, batch genuine receiver ACKs at one tick, reorder leading and trailing originals and lose a repair copy, asserting the provisional classification before finite tail proof, the final isolated, other-loss or timeout outcome, MTU bounds, congestion commitment, packets within the MTU bound and complete delivery, including controls where ACK loss leaves insufficient evidence and recovery waits for a timer; seeded schedules never report an isolated probe loss when another original or a repair copy was lost. Finite tail/recovery proof gates isolation; other detected loss commits congestion response with unchanged MTU bounds and eventual stream progress. Existing trailing-hole, repair-copy, ECN, matching-PTB and inconclusive-RTO controls remain complementary. With PRR, byte-granular repair can end a NewReno isolated probe loss at the RTO, or leave the probe's tail as the RFC 6675 rescue retransmission, which commits the response: more conservative outcomes, with packet-aware recovery left to T22. Full timing/reordering robustness beyond these detector conditions remains unestablished: a finite-time ambiguity, not a missing detector function; sufficiently late leading originals are conservatively treated as other loss, not magically identified as reorder. Counterexample, for the T23 disposition: Drop the probe and withhold its leading original until after the selected loss detector fires. Through that decision, the sender's observations are identical to a run in which both packets were lost. Later delivery of the leading original cannot make the earlier decision distinguish those runs. Losing its progress ACK extends the ambiguity. Retain the whole timely/robust loss-reporting advice as TODO for that evidence/interpretation boundary.
//# It is important that the Packetization Layer has a timely and robust mechanism for detecting and reporting losses. PLPMTUD makes MTU adjustments on the basis of detected losses. Any delays or inaccuracy in loss notification is likely to result in incorrect MTU decisions or slow convergence. It is important that the mechanism can robustly distinguish between the isolated loss of just a probe and other losses in the probe's leading and trailing windows.
fn rack_deadline_and_three_sack_boundaries() {
    let cases = [
        case(
            "two SACKs: deadline - 1 then =",
            Mode::Rack,
            &[
                Deliver(L, true),
                Deliver(T0, true),
                Deliver(T1, true),
                Expect(Undetected),
                AtDeadline(-1),
                Timer,
                Expect(Undetected),
                AtDeadline(0),
                Timer,
                Expect(Pending),
            ],
            Final::Isolated,
        ),
        case(
            "three-SACK transition",
            Mode::Rack,
            &[
                Deliver(L, true),
                Deliver(T0, true),
                Deliver(T1, true),
                Expect(Undetected),
                Deliver(T2, true),
                Expect(Pending),
            ],
            Final::Isolated,
        ),
        Case {
            reordered_history: true,
            ..case(
                "three SACKs after observed reordering",
                Mode::Rack,
                &[
                    Deliver(L, true),
                    Deliver(T0, true),
                    Deliver(T1, true),
                    Deliver(T2, true),
                    Expect(Undetected),
                    AtDeadline(-1),
                    Timer,
                    Expect(Undetected),
                    AtDeadline(0),
                    Timer,
                    Expect(Pending),
                ],
                Final::Isolated,
            )
        },
        // The leading original's ACK resets RACK.rtt (RFC 8985 RACK_update)
        // to its longer sample, which moves the probe's deadline later.
        case(
            "leading at deadline - 1",
            Mode::Rack,
            &[
                Deliver(T0, true),
                Deliver(T1, true),
                AtDeadline(-1),
                Deliver(L, true),
                AtDeadline(0),
                Timer,
                Expect(Undetected),
                NextDeadline,
                Timer,
                Expect(Pending),
            ],
            Final::Isolated,
        ),
        case(
            "leading at deadline, ACK before timer",
            Mode::Rack,
            &[
                Deliver(T0, true),
                Deliver(T1, true),
                AtDeadline(0),
                Deliver(L, true),
                Timer,
                Expect(Undetected),
                NextDeadline,
                Timer,
                Expect(Pending),
            ],
            Final::Isolated,
        ),
        case(
            "leading at deadline, timer before ACK",
            Mode::Rack,
            &[
                Deliver(T0, true),
                Deliver(T1, true),
                AtDeadline(0),
                Timer,
                Expect(Committed),
                Deliver(L, true),
                Expect(Committed),
            ],
            Final::Other,
        ),
        case(
            "leading at deadline + 1",
            Mode::Rack,
            &[
                Deliver(T0, true),
                Deliver(T1, true),
                AtDeadline(0),
                Timer,
                AtDeadline(1),
                Deliver(L, true),
                Expect(Committed),
            ],
            Final::Other,
        ),
        case(
            "leading at deadline - 1, its ACK lost",
            Mode::Rack,
            &[
                Deliver(T0, true),
                Deliver(T1, true),
                AtDeadline(-1),
                Deliver(L, false),
                AtDeadline(0),
                Timer,
                Expect(Committed),
            ],
            Final::Other,
        ),
        case(
            "ACKs batched at one tick",
            Mode::Rack,
            &[Deliver(L, true), Batch(&[T0, T1, T2]), Expect(Pending)],
            Final::Isolated,
        ),
        case(
            "trailing reordered",
            Mode::Rack,
            &[
                Deliver(L, true),
                Deliver(T2, true),
                Deliver(T0, true),
                Deliver(T1, true),
                Expect(Undetected),
                AtDeadline(0),
                Timer,
                Expect(Pending),
            ],
            Final::Isolated,
        ),
        case(
            "every trailing ACK lost",
            Mode::Rack,
            &[
                Deliver(L, true),
                Deliver(T0, false),
                Deliver(T1, false),
                Deliver(T2, false),
                Expect(Undetected),
            ],
            Final::Timeout,
        ),
        // Nothing is delivered after the lost repair copy, so no SACK can
        // reveal it: the timer decides.
        Case {
            lose_repair: true,
            ..case(
                "repair copy lost, nothing after it",
                Mode::Rack,
                &[
                    Deliver(L, true),
                    Deliver(T0, true),
                    Deliver(T1, true),
                    Deliver(T2, true),
                    Expect(Pending),
                ],
                Final::Timeout,
            )
        },
    ];
    run_all(&cases);
}

// xorshift64*: reproducible schedules from a printed seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[test]
// Seeded expansion around the same boundaries, every detector: the leading
// and five trailing originals arrive in a random order, some in one-tick
// batches; receiver ACKs are lost at random; some originals are lost for
// good; sometimes the probe's first repair copy too. Whatever the detector
// decides, the schedule never reports an isolated probe loss when another
// original was lost, a non-isolated outcome supplies no MTU bound and
// commits the congestion response, packets stay within the MTU bound and
// the receiver gets the complete stream (asserted by `run`).
//= https://www.rfc-editor.org/rfc/rfc4821#section-6.1
//= type=test
//= reason=Real receiver NewReno/SACK/RACK traces in both families across serial wrap contrast leading-original delivery before DupThresh/RACK settling, actual leading-plus-probe loss, late leading delivery after detection, and reorder without probe loss. Table-driven detector-boundary schedules through real receiver Endpoints (pmtud_detector_boundary_tests.rs; both families, serial wrap, PRR off and on, reproducible seeds) add NewReno two versus three eligible duplicate ACKs, RFC 6675 IsLost two versus three discontiguous SACKed ranges and exactly 2*SMSS versus one byte more above the candidate, and RACK at the settling deadline - 1, = and + 1 with ACK-before-timer and timer-before-ACK orderings at equality, observed reordering and the three-SACK transition. At each boundary they lose the decisive or leading-progress ACK, batch genuine receiver ACKs at one tick, reorder leading and trailing originals and lose a repair copy, asserting the provisional classification before finite tail proof, the final isolated, other-loss or timeout outcome, MTU bounds, congestion commitment, packets within the MTU bound and complete delivery, including controls where ACK loss leaves insufficient evidence and recovery waits for a timer; seeded schedules never report an isolated probe loss when another original or a repair copy was lost. Finite tail/recovery proof gates isolation; other detected loss commits congestion response with unchanged MTU bounds and eventual stream progress. Existing trailing-hole, repair-copy, ECN, matching-PTB and inconclusive-RTO controls remain complementary. With PRR, byte-granular repair can end a NewReno isolated probe loss at the RTO, or leave the probe's tail as the RFC 6675 rescue retransmission, which commits the response: more conservative outcomes, with packet-aware recovery left to T22. Full timing/reordering robustness beyond these detector conditions remains unestablished: a finite-time ambiguity, not a missing detector function; sufficiently late leading originals are conservatively treated as other loss, not magically identified as reorder. Counterexample, for the T23 disposition: Drop the probe and withhold its leading original until after the selected loss detector fires. Through that decision, the sender's observations are identical to a run in which both packets were lost. Later delivery of the leading original cannot make the earlier decision distinguish those runs. Losing its progress ACK extends the ambiguity. Retain the whole timely/robust loss-reporting advice as TODO for that evidence/interpretation boundary.
//# It is important that the Packetization Layer has a timely and robust mechanism for detecting and reporting losses. PLPMTUD makes MTU adjustments on the basis of detected losses. Any delays or inaccuracy in loss notification is likely to result in incorrect MTU decisions or slow convergence. It is important that the mechanism can robustly distinguish between the isolated loss of just a probe and other losses in the probe's leading and trailing windows.
fn seeded_detector_schedules_never_isolate_other_loss() {
    for mode in [Mode::NewReno, Mode::Sack, Mode::Rack] {
        let mut seen = [false; 3];
        for seed in 1..=24u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let mut order = vec![L, T0, T1, T2, T3, T4];
            for i in (1..order.len()).rev() {
                order.swap(i, rng.below(i as u64 + 1) as usize);
            }
            let lost: Vec<usize> = order
                .iter()
                .copied()
                .filter(|_| rng.below(6) == 0)
                .collect();
            let mut steps = Vec::new();
            let mut arriving: Vec<usize> =
                order.into_iter().filter(|n| !lost.contains(n)).collect();
            while !arriving.is_empty() {
                let take = if rng.below(4) == 0 {
                    arriving.len().min(3)
                } else {
                    1
                };
                let group: Vec<usize> = arriving.drain(..take).collect();
                if group.len() > 1 {
                    steps.push(Step::Batch(group.leak()));
                } else {
                    steps.push(Step::Deliver(group[0], rng.below(4) != 0));
                }
            }
            let case = Case {
                name: "seeded",
                mode,
                reordered_history: rng.below(3) == 0,
                extra: 2,
                small: 0,
                steps: &steps,
                lost: &lost,
                lose_repair: rng.below(5) == 0,
                result: Final::Isolated,
            };
            for ipv4 in [true, false] {
                for (iss, prr) in [(0x1000, false), (u32::MAX - 3000, true)] {
                    let outcome = run(&case, ipv4, iss, prr);
                    let label = format!(
                        "{mode:?} seed={seed} ipv4={ipv4} iss={iss:#x} prr={prr} lost={lost:?} steps={steps:?}"
                    );
                    assert!(outcome.bounded, "{label}");
                    seen[outcome.result as usize] = true;
                    if !lost.is_empty() || case.lose_repair {
                        assert_ne!(outcome.result, Final::Isolated, "{label}");
                    }
                }
            }
        }
        // The seeds reach every classification of this detector.
        assert_eq!(seen, [true; 3], "{mode:?}");
    }
}
