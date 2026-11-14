extern crate std;
use super::*;
use crate::LossCounters;
use std::vec::Vec;

// How the client's output leaves: committed as polled, accepted a reserved
// segment at a time, or accepted as backend aggregates (TSO) wherever the
// selection groups, each aggregate's segments cut as a backend cuts them.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Output {
    Direct,
    Reserved,
    Grouped,
}

const OUTPUTS: [Output; 3] = [Output::Direct, Output::Reserved, Output::Grouped];

// One-way delay, in microseconds.
const HOP: Instant = 1_000;

// A full segment's payload: the MSS less the timestamps option.
const SEGMENT: usize = 988;

fn ab() -> crate::IpMetadata {
    crate::IpMetadata {
        source: "192.0.2.1".parse().unwrap(),
        destination: "192.0.2.2".parse().unwrap(),
    }
}

fn ba() -> crate::IpMetadata {
    crate::IpMetadata {
        source: "192.0.2.2".parse().unwrap(),
        destination: "192.0.2.1".parse().unwrap(),
    }
}

fn limits() -> crate::TransmitGroupLimits {
    crate::TransmitGroupLimits {
        max_bytes: usize::MAX,
        max_segments: usize::MAX,
        allow_psh: true,
        allow_cwr: true,
        allow_options: true,
    }
}

// The physical segments a backend cuts from the aggregate, as Linux
// tcp_gso_segment does.
fn cut(view: &crate::TransmitGroupView<'_>) -> Vec<Vec<u8>> {
    let size = view.segment_payload_len;
    (0..view.segment_count)
        .map(|n| {
            let mut header = view.header;
            header.sequence = header.sequence.wrapping_add((n * size) as u32);
            if n + 1 != view.segment_count {
                header.flags &= !(wire::PSH | wire::FIN);
            }
            if n != 0 {
                header.flags &= !wire::CWR;
            }
            let mut out = [0; 2048];
            let len = wire::encode(
                view.packet.ip,
                header,
                view.options,
                &view.payload[n * size..((n + 1) * size).min(view.payload.len())],
                &mut out,
            )
            .unwrap();
            out[..len].to_vec()
        })
        .collect()
}

// A client `a` connecting to a listener on `b` over a wire that loses the
// segments a test chooses.
struct Run {
    a: Endpoint,
    b: Endpoint,
    listener: ListenerId,
    client: ConnectionId,
    server: Option<ConnectionId>,
    output: Output,
    now: Instant,
    // Every segment each side sent, lost or not, in order.
    from_a: Vec<Vec<u8>>,
    from_b: Vec<Vec<u8>>,
    // What the server sent in answer to the client's last segments, each
    // polled as soon as the segment arrived.
    answers: Vec<Vec<u8>>,
    groups: usize,
    received: Vec<u8>,
    // The client's segment, counted as `from_a`, whose reserved attempt is
    // disposed of as never submitted (`discard_unsubmitted`), for this
    // reason, instead of accepted.
    refuse: Option<(usize, crate::DropReason)>,
}

impl Run {
    // SACK, RACK-TLP and PRR on, as Linux runs; `adjust` changes both sides.
    fn new(output: Output, adjust: impl Fn(&mut ConnectionConfig)) -> Self {
        let mut config = ConnectionConfig {
            mss: 1000,
            nagle: false,
            sack: true,
            rack: true,
            tlp: true,
            prr: true,
            prr_pacing: false,
            timestamps: true,
            initial_window: crate::InitialWindow::Iw10,
            send_capacity: 32_768,
            receive_capacity: 32_768,
            ..ConnectionConfig::default()
        };
        adjust(&mut config);
        let endpoint = || {
            Endpoint::new(
                EndpointConfig {
                    max_connections: 4,
                    max_listeners: 2,
                    connection: config.clone(),
                    ..EndpointConfig::default()
                },
                [1; 32],
                0,
                |_| true,
            )
            .unwrap()
        };
        let (mut a, mut b) = (endpoint(), endpoint());
        match output {
            Output::Direct => {}
            Output::Reserved => a.enable_output_reservations().unwrap(),
            Output::Grouped => a
                .enable_output_reservations_with_gso(
                    1,
                    crate::GsoLimits {
                        max_bytes: 8000,
                        max_segments: 8,
                    },
                )
                .unwrap(),
        }
        let listener = b.listen("192.0.2.2:8080".parse().unwrap(), 4).unwrap();
        let client = a
            .connect(
                0,
                "192.0.2.1:40000".parse().unwrap(),
                "192.0.2.2:8080".parse().unwrap(),
            )
            .unwrap();
        Self {
            a,
            b,
            listener,
            client,
            server: None,
            output,
            now: 0,
            from_a: Vec::new(),
            from_b: Vec::new(),
            answers: Vec::new(),
            groups: 0,
            received: Vec::new(),
            refuse: None,
        }
    }

    fn established(output: Output, adjust: impl Fn(&mut ConnectionConfig)) -> Self {
        let mut run = Self::new(output, adjust);
        run.run(
            |_| false,
            |_| false,
            |r| {
                r.server.is_some()
                    && r.a.transport_info(r.client).unwrap().state == State::Established
            },
        );
        run
    }

    fn poll_a(&mut self) -> Vec<Vec<u8>> {
        let mut out = [0; 2048];
        let mut wire = Vec::new();
        loop {
            if self.output == Output::Direct {
                let Some(p) = self.a.poll_transmit(self.now, &mut out, 16).unwrap().packet else {
                    return wire;
                };
                wire.push(out[..p.len].to_vec());
                continue;
            }
            let (poll, attempt) = self
                .a
                .poll_reserved_transmit_for(self.now, self.client, &mut out, 16)
                .unwrap();
            let Some(p) = poll.packet else {
                return wire;
            };
            let attempt = attempt.unwrap();
            if let Some((n, reason)) = self.refuse
                && n == self.from_a.len() + wire.len()
            {
                assert!(
                    self.a
                        .discard_unsubmitted(self.now, attempt, None, reason)
                        .unwrap()
                );
                assert!(!self.a.is_output_reserved(self.client));
                wire.push(out[..p.len].to_vec());
                continue;
            }
            if self.output == Output::Grouped
                && let Some(group) = self.a.prepare_transmit_group(attempt, limits()).unwrap()
            {
                wire.extend(cut(&self.a.transmit_group(group).unwrap()));
                self.groups += 1;
                assert!(self.a.accept_transmit_group(self.now, group).unwrap());
            } else {
                wire.push(out[..p.len].to_vec());
                assert!(self.a.accept_transmit(self.now, attempt).unwrap());
            }
        }
    }

    fn poll_b(&mut self) -> Vec<Vec<u8>> {
        let mut out = [0; 2048];
        let mut wire = Vec::new();
        while let Some(p) = self.b.poll_transmit(self.now, &mut out, 16).unwrap().packet {
            wire.push(out[..p.len].to_vec());
        }
        wire
    }

    // Runs both sides, their timers included, until `done`. The client's
    // `n`th segment, counted from 0 over all it sent, is lost when
    // `lose_a(n)`; the server's when `lose_b(n)`.
    fn run(
        &mut self,
        mut lose_a: impl FnMut(usize) -> bool,
        mut lose_b: impl FnMut(usize) -> bool,
        done: impl Fn(&Self) -> bool,
    ) {
        for _ in 0..10_000 {
            if self.server.is_none() {
                self.server = self.b.accept(self.listener).ok();
            }
            if let Some(server) = self.server {
                let mut buffer = [0; 4096];
                while let Ok(n) = self.b.read(server, &mut buffer)
                    && n != 0
                {
                    self.received.extend_from_slice(&buffer[..n]);
                }
            }
            if done(self) {
                return;
            }
            for e in [&mut self.a, &mut self.b] {
                if e.next_deadline().is_some_and(|at| at <= self.now) {
                    e.on_timeout(self.now, 16).unwrap();
                }
            }
            let from_a = self.poll_a();
            let mut from_b = core::mem::take(&mut self.answers);
            from_b.extend(self.poll_b());
            if from_a.is_empty() && from_b.is_empty() {
                self.now = [self.a.next_deadline(), self.b.next_deadline()]
                    .into_iter()
                    .flatten()
                    .min()
                    .expect("both sides idle before done")
                    .max(self.now);
                continue;
            }
            self.now += HOP;
            for segment in from_a {
                if !lose_a(self.from_a.len()) {
                    self.b.input(self.now, ab(), &segment).unwrap();
                    let answers = self.poll_b();
                    self.answers.extend(answers);
                }
                self.from_a.push(segment);
            }
            for segment in from_b {
                if !lose_b(self.from_b.len()) {
                    self.a.input(self.now, ba(), &segment).unwrap();
                }
                self.from_b.push(segment);
            }
        }
        panic!("not done");
    }

    // Writes `len` bytes and runs until the server has read them.
    fn transfer(
        &mut self,
        len: usize,
        lose_a: impl FnMut(usize) -> bool,
        lose_b: impl FnMut(usize) -> bool,
    ) {
        let data: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
        let start = self.received.len();
        assert_eq!(self.a.write(self.client, &data).unwrap(), len);
        let end = start + len;
        self.run(lose_a, lose_b, |r| {
            r.received.len() == end
                && r.a.send_progress(r.client).unwrap().acknowledged as usize == end
        });
        assert_eq!(self.received[start..], data[..]);
    }

    fn total_retrans(&self) -> u64 {
        self.a.transport_info(self.client).unwrap().total_retrans
    }
}

// Runs `scenario` with each kind of output; every one must send the same
// segments and count the same. Returns the client's and server's counters
// and the client's total_retrans.
fn each_output(
    scenario: impl Fn(&mut Run),
    new: impl Fn(Output) -> Run,
) -> (LossCounters, LossCounters, u64) {
    let mut first: Option<(Vec<Vec<u8>>, LossCounters, LossCounters, u64)> = None;
    for output in OUTPUTS {
        let mut run = new(output);
        scenario(&mut run);
        let result = (
            run.from_a.clone(),
            run.a.loss_counters(),
            run.b.loss_counters(),
            run.total_retrans(),
        );
        // A connection counts what its endpoint counts.
        assert_eq!(result.3, result.1.retransmitted_segments, "{output:?}");
        match &first {
            None => first = Some(result),
            Some(first) => assert_eq!(first, &result, "{output:?}"),
        }
    }
    let (_, a, b, total) = first.unwrap();
    (a, b, total)
}

// A lost SYN and a lost SYN-ACK each time out once and are each resent
// once, from the timeout: Linux's TCPTimeouts and RetransSegs (its SYN-ACK
// timeouts count in TCPTimeouts too).
#[test]
fn handshake_timeouts_count_their_retransmissions() {
    let (a, b, total) = each_output(
        |run| {
            // The client's SYN (its segment 0), then the server's SYN-ACK
            // to the resent one (its segment 0).
            run.run(
                |n| n == 0,
                |n| n == 0,
                |r| {
                    r.server.is_some()
                        && r.a.transport_info(r.client).unwrap().state == State::Established
                },
            );
        },
        |output| Run::new(output, |_| {}),
    );
    let timeout = LossCounters {
        retransmitted_segments: 1,
        timeout_retransmitted_segments: 1,
        timeouts: 1,
        ..LossCounters::default()
    };
    assert_eq!((a, b, total), (timeout, timeout, 1));
}

// A segment lost with its tail loss probe and its first retransmission
// times out twice: each expiry counts, and so does each segment resent, the
// probe outside the timeout's recovery, the two after it inside.
#[test]
fn each_backed_off_timeout_counts() {
    let (a, b, total) = each_output(
        |run| {
            let sent = run.from_a.len();
            // The segment, the probe and the first timeout's resend.
            run.transfer(500, |n| (sent..sent + 3).contains(&n), |_| false);
            assert_eq!(run.from_a.len(), sent + 4);
        },
        |output| Run::established(output, |_| {}),
    );
    assert_eq!(
        a,
        LossCounters {
            retransmitted_segments: 3,
            timeout_retransmitted_segments: 2,
            timeouts: 2,
            loss_probes: 1,
            ..LossCounters::default()
        }
    );
    assert_eq!((b, total), (LossCounters::default(), 3));
}

// A lost tail is repaired by the probe that retransmits it: the probe
// counts, and the next ACK beyond it shows it repaired a loss (Linux's
// TCPLossProbes and TCPLossProbeRecovery). No recovery, no timeout.
#[test]
fn a_loss_probe_repairs_a_lost_tail() {
    let (a, _, total) = each_output(
        |run| {
            let sent = run.from_a.len();
            // The second of two segments.
            run.transfer(2 * SEGMENT, |n| n == sent + 1, |_| false);
            assert_eq!(run.a.loss_counters().loss_probe_recoveries, 0);
            // The ACK that covers the probe alone leaves the repair
            // unproven (RFC 8985 section 7.4.2); one beyond it proves it.
            run.transfer(SEGMENT, |_| false, |_| false);
        },
        |output| Run::established(output, |_| {}),
    );
    assert_eq!(
        a,
        LossCounters {
            retransmitted_segments: 1,
            loss_probes: 1,
            loss_probe_recoveries: 1,
            ..LossCounters::default()
        }
    );
    assert_eq!(total, 1);
}

// Data delivered whose ACK is lost: the probe resends it needlessly, and
// the peer's D-SACK for the duplicate shows it. The probe repaired nothing.
#[test]
fn a_needless_probe_draws_a_dsack() {
    let (a, _, total) = each_output(
        |run| {
            let acks = run.from_b.len();
            // The server's ACK of the segment.
            run.transfer(SEGMENT, |_| false, |n| n == acks);
            run.run(
                |_| false,
                |_| false,
                |r| r.a.loss_counters().dsack_received != 0,
            );
        },
        |output| Run::established(output, |_| {}),
    );
    assert_eq!(
        a,
        LossCounters {
            retransmitted_segments: 1,
            loss_probes: 1,
            dsack_received: 1,
            ..LossCounters::default()
        }
    );
    assert_eq!(total, 1);
}

// The first of six segments lost: the SACKs of the rest start SACK-based
// recovery (RACK), which resends it once (Linux's TCPSackRecovery).
#[test]
fn sack_recovery_counts_its_entry() {
    for rack in [false, true] {
        let (a, _, total) = each_output(
            |run| {
                let sent = run.from_a.len();
                run.transfer(6 * SEGMENT, |n| n == sent, |_| false);
                if run.output == Output::Grouped {
                    assert_ne!(run.groups, 0);
                }
            },
            |output| {
                Run::established(output, |c| {
                    c.rack = rack;
                    c.tlp = rack;
                })
            },
        );
        assert_eq!(
            a,
            LossCounters {
                retransmitted_segments: 1,
                sack_recoveries: 1,
                ..LossCounters::default()
            },
            "rack {rack}"
        );
        assert_eq!(total, 1);
    }
}

// Without SACK the third duplicate ACK starts NewReno fast recovery
// (Linux's TCPRenoRecovery), which resends the lost segment once.
#[test]
fn newreno_recovery_counts_its_entry() {
    let (a, _, total) = each_output(
        |run| {
            let sent = run.from_a.len();
            run.transfer(6 * SEGMENT, |n| n == sent, |_| false);
        },
        |output| {
            Run::established(output, |c| {
                c.sack = false;
                c.rack = false;
                c.tlp = false;
            })
        },
    );
    assert_eq!(
        a,
        LossCounters {
            retransmitted_segments: 1,
            reno_recoveries: 1,
            ..LossCounters::default()
        }
    );
    assert_eq!(total, 1);
}

// The endpoint keeps what a connection counted after the connection is
// gone, and adds every connection's counts.
#[test]
fn counts_outlive_their_connection() {
    let mut run = Run::established(Output::Direct, |_| {});
    let sent = run.from_a.len();
    run.transfer(500, |n| (sent..sent + 3).contains(&n), |_| false);
    let counted = run.a.loss_counters();
    assert_eq!(counted.timeouts, 2);
    run.a.abort(run.client).unwrap();
    run.a.release(run.client).unwrap();
    let now = run.now + HOP;
    run.a.poll_transmit(now, &mut [0; 2048], 16).unwrap();
    assert_eq!(run.a.loss_counters(), counted);
    // A second connection's SYN timeout adds to them.
    let second = run
        .a
        .connect(
            now,
            "192.0.2.1:40001".parse().unwrap(),
            "192.0.2.2:8080".parse().unwrap(),
        )
        .unwrap();
    let mut out = [0; 2048];
    assert!(
        run.a
            .poll_transmit(now, &mut out, 16)
            .unwrap()
            .packet
            .is_some()
    );
    let deadline = run.a.next_deadline().unwrap();
    run.a.on_timeout(deadline, 16).unwrap();
    assert!(
        run.a
            .poll_transmit(deadline, &mut out, 16)
            .unwrap()
            .packet
            .is_some()
    );
    assert_eq!(run.a.transport_info(second).unwrap().total_retrans, 1);
    assert_eq!(
        run.a.loss_counters(),
        LossCounters {
            retransmitted_segments: counted.retransmitted_segments + 1,
            timeout_retransmitted_segments: counted.timeout_retransmitted_segments + 1,
            timeouts: counted.timeouts + 1,
            ..counted
        }
    );
}

// A reserved retransmission counts when the backend took it, not when it
// was selected: one certainly not submitted counts nothing, its resend
// once.
#[test]
fn an_unsubmitted_retransmission_does_not_count() {
    let mut run = Run::established(Output::Reserved, |c| c.tlp = false);
    let mut out = [0; 2048];
    run.a.write(run.client, &[1; 500]).unwrap();
    let (poll, attempt) = run
        .a
        .poll_reserved_transmit_for(run.now, run.client, &mut out, 16)
        .unwrap();
    assert!(poll.packet.is_some());
    assert!(run.a.accept_transmit(run.now, attempt.unwrap()).unwrap());
    while run.a.loss_counters().timeouts == 0 {
        run.now = run.a.next_deadline().unwrap();
        run.a.on_timeout(run.now, 16).unwrap();
    }
    for submitted in [false, true] {
        let (poll, attempt) = run
            .a
            .poll_reserved_transmit_for(run.now, run.client, &mut out, 16)
            .unwrap();
        assert!(poll.packet.is_some());
        assert_eq!(run.a.loss_counters().retransmitted_segments, 0);
        if submitted {
            assert!(run.a.accept_transmit(run.now, attempt.unwrap()).unwrap());
        } else {
            assert!(run.a.reject_unsubmitted(attempt.unwrap()).unwrap());
        }
    }
    assert_eq!(
        run.a.loss_counters(),
        LossCounters {
            retransmitted_segments: 1,
            timeout_retransmitted_segments: 1,
            timeouts: 1,
            ..LossCounters::default()
        }
    );
    assert_eq!(run.total_retrans(), 1);
}

// A fresh segment of `len` octets' transfer, the `nth` the client sends,
// never sent for want of its next hop: the client accounts it as sent and
// lost, as Linux accounts a skb its neighbour queue frees, so every segment
// it sends after, its counters and its state are those of the same segment
// lost on the wire, and the ordinary loss path delivers every octet,
// whether or not the backend can also refuse output synchronously.
// Returns the client's counters.
fn refused_as_lost(
    adjust: impl Fn(&mut ConnectionConfig) + Copy,
    len: usize,
    nth: usize,
) -> LossCounters {
    let mut counters = None;
    for (reason, refusals) in [
        (crate::DropReason::NeighFailed, false),
        (crate::DropReason::NeighQueueFull, false),
        (crate::DropReason::NeighFailed, true),
    ] {
        let mut lost = Run::established(Output::Reserved, adjust);
        let mut refused = Run::established(Output::Reserved, adjust);
        lost.a.set_local_transmit_refusals(refusals);
        refused.a.set_local_transmit_refusals(refusals);
        let sent = lost.from_a.len();
        assert_eq!(refused.from_a, lost.from_a);
        refused.refuse = Some((sent + nth, reason));
        lost.transfer(len, |n| n == sent + nth, |_| false);
        refused.transfer(len, |n| n == sent + nth, |_| false);
        assert_eq!(refused.from_a, lost.from_a, "{reason}");
        assert_eq!(refused.from_b, lost.from_b, "{reason}");
        assert_eq!(refused.now, lost.now, "{reason}");
        assert_eq!(
            refused.a.loss_counters(),
            lost.a.loss_counters(),
            "{reason}"
        );
        assert_eq!(
            std::format!("{:?}", refused.a.transport_info(refused.client).unwrap()),
            std::format!("{:?}", lost.a.transport_info(lost.client).unwrap()),
            "{reason}"
        );
        assert_eq!(refused.a.drop_counts()[reason], 1);
        assert_eq!(refused.a.drop_counts().total(), 1);
        assert_eq!(lost.a.drop_counts().total(), 0);
        let c = lost.a.loss_counters();
        assert!(counters.is_none_or(|first| first == c));
        counters = Some(c);
    }
    counters.unwrap()
}

// The only segment in flight: the tail loss probe resends it.
#[test]
fn a_refused_tail_segment_is_repaired_by_the_loss_probe() {
    let counters = refused_as_lost(|_| {}, SEGMENT, 0);
    assert_eq!(counters.loss_probes, 1);
    assert_eq!(counters.timeouts, 0);
}

// One of a flight: RACK infers its loss from the SACKs of the later ones
// and loss recovery (with its cwnd reduction) resends it.
#[test]
fn a_refused_segment_inside_a_flight_enters_loss_recovery() {
    let counters = refused_as_lost(|_| {}, 10 * SEGMENT, 3);
    assert_eq!(counters.sack_recoveries, 1);
    assert_eq!(counters.timeouts, 0);
    assert!(counters.retransmitted_segments >= 1);
}

// Without TLP, the retransmission timeout repairs it.
#[test]
fn a_refused_tail_segment_without_tlp_times_out() {
    let counters = refused_as_lost(|c| c.tlp = false, SEGMENT, 0);
    assert_eq!(counters.timeouts, 1);
    assert_eq!(counters.loss_probes, 0);
}
