use super::*;
use ntcp::{ConnectionConfig, ConnectionId, EndpointConfig, GsoLimits, InitialWindow};
use ntcp_io::TcpSegmentationCapabilities;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

struct Allocator;
thread_local! { static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) }; }
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| {
            if let Some(v) = n.get() {
                n.set(Some(v + 1));
            }
        });
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) }
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.with(|n| {
            if let Some(v) = n.get() {
                n.set(Some(v + 1));
            }
        });
        unsafe { System.realloc(p, layout, size) }
    }
}

const LINK: Ethernet = Ethernet {
    source: [1; 6],
    destination: [2; 6],
};
const BUDGET: Budget = Budget {
    max_segments: 8,
    max_wire_bytes: 100_000,
};

fn pair(v6: bool, timestamps: bool, pacing: bool, mss: u16) -> (Endpoint, Endpoint, ConnectionId) {
    let mut pmtud = ntcp::PmtudConfig::new(1500);
    pmtud.initial_search_low = Some(if v6 {
        1280.max(u32::from(mss) + 60)
    } else {
        1040.max(u32::from(mss) + 40)
    });
    let config = EndpointConfig {
        max_connections: 4,
        max_listeners: 2,
        connection: ConnectionConfig {
            pmtud: (mss > 1).then_some(pmtud),
            mss,
            timestamps,
            nagle: false,
            ecn: false,
            sack: true,
            prr_pacing: false,
            pacing: pacing.then_some(ntcp::PacingConfig::default()),
            initial_window: InitialWindow::Iw10,
            send_capacity: 16_384,
            receive_capacity: 16_384,
            ..ConnectionConfig::default()
        },
        ..EndpointConfig::default()
    };
    let mut a = Endpoint::new(config.clone(), [1; 32], 0, |_| true).unwrap();
    let mut b = Endpoint::new(config, [1; 32], 0, |_| true).unwrap();
    let local = if v6 {
        "[2001:db8::1]:40000"
    } else {
        "192.0.2.1:40000"
    }
    .parse()
    .unwrap();
    let remote = if v6 {
        "[2001:db8::2]:8080"
    } else {
        "192.0.2.2:8080"
    }
    .parse()
    .unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let id = a.connect(0, local, remote).unwrap();
    let mut bytes = [0; 2048];
    for i in 0..3 {
        let (src, dst) = if i == 1 {
            (&mut b, &mut a)
        } else {
            (&mut a, &mut b)
        };
        let p = src
            .poll_transmit(1, &mut bytes, 16)
            .unwrap()
            .packet
            .unwrap();
        dst.input(1, p.ip, &bytes[..p.len]).unwrap();
    }
    b.accept(listener).unwrap();
    a.enable_output_reservations_with_gso(
        1,
        GsoLimits {
            max_bytes: 12_000,
            max_segments: 10,
        },
    )
    .unwrap();
    (a, b, id)
}

#[derive(Clone, Copy)]
enum Behavior {
    Submit,
    Block,
    Unsupported,
    Invalid,
    Other,
}
struct Recording {
    caps: Option<TcpSegmentationCapabilities>,
    behavior: Behavior,
    calls: usize,
    bytes: [u8; 65_589],
    len: usize,
    request: Option<TcpSegmentationRequest>,
}
impl Recording {
    fn new() -> Self {
        Self {
            caps: Some(TcpSegmentationCapabilities {
                max_aggregate_len: 65_589,
                max_segments: 64,
                max_wire_bytes: 100_000,
                local_ip_mtu: 1500,
            }),
            behavior: Behavior::Submit,
            calls: 0,
            bytes: [0; 65_589],
            len: 0,
            request: None,
        }
    }
}
impl PacketIo for Recording {
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ethernet
    }
    fn receive(&mut self, _: &mut [u8]) -> std::io::Result<Option<usize>> {
        Ok(None)
    }
    fn transmit(&mut self, _: &[u8]) -> std::io::Result<TxOutcome> {
        panic!("aggregate must never use scalar IO")
    }
    fn tcp_segmentation_capabilities(&self) -> Option<TcpSegmentationCapabilities> {
        self.caps
    }
    fn transmit_segmented(
        &mut self,
        p: &[u8],
        request: TcpSegmentationRequest,
    ) -> Result<TxOutcome, TcpSegmentationError> {
        self.calls += 1;
        self.bytes[..p.len()].copy_from_slice(p);
        self.len = p.len();
        self.request = Some(request);
        match self.behavior {
            Behavior::Submit => Ok(TxOutcome::Submitted),
            Behavior::Block => Ok(TxOutcome::WouldBlock),
            Behavior::Unsupported => Err(TcpSegmentationError::Unsupported),
            Behavior::Invalid => Err(TcpSegmentationError::InvalidInput),
            Behavior::Other => Err(TcpSegmentationError::Other(
                std::io::ErrorKind::Other.into(),
            )),
        }
    }
}
fn scalar<'a>(a: &mut Endpoint, id: ConnectionId, out: &'a mut [u8], now: Instant) -> Scalar<'a> {
    let (p, token) = a.poll_reserved_transmit_for(now, id, out, 16).unwrap();
    let packet = p.packet.unwrap();
    Scalar {
        packet,
        attempt: token.unwrap(),
        tcp: &out[..packet.len],
        when: None,
        timestamp: None,
    }
}

// Software segmentation oracle: reconstruct each normal checksummed frame and
// compare with a separate real endpoint's scalar stream, including suffix groups.
fn oracle(
    pending: &Pending<'_>,
    reference: &mut Endpoint,
    id: ConnectionId,
    v6: bool,
    now: Instant,
) {
    let p = pending.bytes();
    let ip_len = if v6 { 40 } else { 20 };
    let headers = 14 + ip_len + 20;
    let tcp = 14 + ip_len;
    assert_eq!(&p[..6], &LINK.destination);
    assert_eq!(&p[6..12], &LINK.source);
    assert_eq!(&p[tcp + 16..tcp + 18], &[0, 0]);
    let word = |i| usize::from(u16::from_be_bytes([p[i], p[i + 1]]));
    if v6 {
        assert_eq!(word(18), p.len() - 54);
    } else {
        assert_eq!(word(16), p.len() - 14);
        assert_eq!(word(24), 0);
    }
    let seq = u32::from_be_bytes(p[tcp + 4..tcp + 8].try_into().unwrap());
    let mss = pending.request().segment_payload_len;
    let mut count = 0;
    let mut wire_bytes = 0;
    for (i, payload) in p[headers..].chunks(mss).enumerate() {
        let mut scratch = [0; 2048];
        let s = scalar(reference, id, &mut scratch, now);
        let parsed = wire::parse(s.packet.ip, s.tcp).unwrap();
        assert_eq!(parsed.payload, payload);
        assert_eq!(parsed.header.sequence, seq.wrapping_add((i * mss) as u32));
        assert_eq!(parsed.header.flags, wire::ACK);
        let mut frame = [0u8; 2048];
        frame[..headers].copy_from_slice(&p[..headers]);
        frame[headers..headers + payload.len()].copy_from_slice(payload);
        let len = headers + payload.len();
        frame[tcp + 4..tcp + 8].copy_from_slice(&parsed.header.sequence.to_be_bytes());
        let sum = wire::checksum(s.packet.ip, &frame[tcp..len]).unwrap();
        frame[tcp + 16..tcp + 18].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(&frame[tcp..len], s.tcp);
        let mut expected = [0u8; 2048];
        expected[ip_len..ip_len + s.tcp.len()].copy_from_slice(s.tcp);
        if v6 {
            frame[18..20].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
            ntcp_ip6::encode(&mut expected, s.packet).unwrap();
            ntcp_ip6::parse(&frame[14..len]).unwrap();
        } else {
            frame[16..18].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
            let sum = ntcp_ip::checksum(&frame[14..34]);
            frame[24..26].copy_from_slice(&sum.to_be_bytes());
            ntcp_ip::encode(&mut expected, s.packet, 0).unwrap();
            ntcp_ip::parse(&frame[14..len], false).unwrap();
        }
        assert_eq!(&frame[14..len], &expected[..len - 14]);
        assert!(reference.accept_transmit(now, s.attempt).unwrap());
        count += 1;
        wire_bytes += len.max(60);
    }
    assert_eq!(
        pending.charge(),
        Charge {
            segments: count,
            wire_bytes
        }
    );
}

#[test]
fn endpoint_bridge_generic_io_oracle_regrouped_suffix_and_psh() {
    for v6 in [false, true] {
        let (mut a, _peer, id) = pair(v6, false, false, 1000);
        let (mut reference, _, rid) = pair(v6, false, false, 1000);
        let payload: Vec<_> = (0..6000).map(|i| (i % 251) as u8).collect();
        a.write(id, &payload).unwrap();
        reference.write(rid, &payload).unwrap();
        let mut io = Recording::new();
        let mut scratch = [0; 2048];
        let mut buffer = [0; 9000];
        for (turn, expected) in [(2, 2), (3, 3)] {
            let s = scalar(&mut a, id, &mut scratch, turn);
            let old = s.attempt;
            let budget = if turn == 2 {
                Budget {
                    max_segments: 2,
                    ..BUDGET
                }
            } else {
                BUDGET
            };
            let pending = prepare(&mut a, &io, s, &mut buffer, LINK, budget)
                .unwrap()
                .unwrap();
            assert_eq!(pending.charge().segments, expected);
            assert!(!a.accept_transmit(turn, old).unwrap());
            oracle(&pending, &mut reference, rid, v6, turn);
            let len = pending.bytes().len();
            let group = pending.group;
            let charge = pending.charge();
            // Trait-object dispatch is the same path an enabled DPDK PacketIo uses.
            let backend: &mut dyn PacketIo = &mut io;
            assert!(
                matches!(pending.submit(&mut a, backend, || turn), Submission::Submitted(c) if c == charge)
            );
            assert_eq!(io.len, len);
            assert!(!a.accept_transmit_group(turn, group).unwrap());
        }
        let s = scalar(&mut a, id, &mut scratch, 4);
        let token = s.attempt;
        assert_eq!(
            wire::parse(s.packet.ip, s.tcp).unwrap().header.flags,
            wire::ACK | wire::PSH
        );
        assert!(
            prepare(&mut a, &io, s, &mut buffer, LINK, BUDGET)
                .unwrap()
                .is_none()
        );
        assert!(a.accept_transmit(4, token).unwrap());
        assert!(!a.is_output_reserved(id));
    }
}

#[test]
fn wouldblock_exact_retry_and_typed_rejection_repoll() {
    for behavior in [Behavior::Submit, Behavior::Unsupported, Behavior::Invalid] {
        let (mut a, _, id) = pair(false, false, false, 1000);
        a.write(id, &[7; 5000]).unwrap();
        let mut io = Recording::new();
        io.behavior = Behavior::Block;
        let mut scratch = [0; 2048];
        let mut buffer = [0; 9000];
        let s = scalar(&mut a, id, &mut scratch, 2);
        let start = wire::parse(s.packet.ip, s.tcp).unwrap().header.sequence;
        let pending = prepare(&mut a, &io, s, &mut buffer, LINK, BUDGET)
            .unwrap()
            .unwrap();
        let group = pending.group;
        let pending = match pending.submit(&mut a, &mut io, || 3) {
            Submission::WouldBlock(p) => p,
            other => panic!("{other:?}"),
        };
        assert_eq!(pending.group, group);
        assert_eq!(pending.bytes(), &io.bytes[..io.len]);
        assert_eq!(Some(pending.request()), io.request);
        assert!(a.transmit_group(group).is_some());
        io.behavior = behavior;
        let result = pending.submit(&mut a, &mut io, || 4);
        assert_eq!(io.calls, 2);
        match behavior {
            Behavior::Submit => assert!(matches!(result, Submission::Submitted(_))),
            _ => {
                assert!(matches!(result, Submission::Rejected(_)));
                assert!(a.transmit_group(group).is_none());
                let s = scalar(&mut a, id, &mut scratch, 4);
                let parsed = wire::parse(s.packet.ip, s.tcp).unwrap();
                assert_eq!(parsed.payload, &[7; 1000]);
                assert_eq!(parsed.header.sequence, start);
                assert!(a.accept_transmit(4, s.attempt).unwrap());
            }
        }
    }
}

#[test]
fn unsupported_metadata_and_budgets_preserve_scalar() {
    for v6 in [false, true] {
        for case in 0..16 {
            let (mut a, _, id) = pair(v6, case == 0, case == 1, 1000);
            if case == 15 {
                a.set_tx_timestamp_capacity(id, 4).unwrap();
                a.write_with_timestamp(
                    id,
                    &[1; 6000],
                    false,
                    false,
                    None,
                    ntcp::TxTimestampRequest {
                        cookie: 1,
                        software_transmit: true,
                        ..Default::default()
                    },
                )
                .unwrap();
            } else {
                a.write(id, &[1; 6000]).unwrap();
            }
            let mut scratch = [0; 2048];
            let mut buffer = [0; 9000];
            let mut io = Recording::new();
            let mut s = scalar(&mut a, id, &mut scratch, 2);
            let token = s.attempt;
            let mut budget = BUDGET;
            let mut capacity = buffer.len();
            match case {
                2 => io.caps = None,
                3 => budget.max_segments = 1,
                4 => budget.max_wire_bytes = 2 * (1054 + if v6 { 20 } else { 0 }) - 1,
                5 => capacity = 100,
                6 => s.packet.ecn = 1,
                7 => s.packet.ipv4_options.record_route_slots = Some(1),
                8 => {
                    s.timestamp = Some(TxTimestampRequest {
                        cookie: 1,
                        software: true,
                        hardware: false,
                    })
                }
                9 => {
                    s.when = Some(TransmitTime {
                        value: 2,
                        clock: ntcp_io::ClockDescriptor {
                            domain: ntcp_io::ClockDomain::Monotonic,
                            unit: ntcp_io::TimestampUnit::Nanoseconds,
                        },
                    })
                }
                10 => io.caps.as_mut().unwrap().local_ip_mtu = 1000,
                11 => io.caps.as_mut().unwrap().max_aggregate_len = 100,
                12 => io.caps.as_mut().unwrap().max_segments = 1,
                13 => {
                    io.caps.as_mut().unwrap().max_wire_bytes =
                        2 * (1054 + if v6 { 20 } else { 0 }) - 1
                }
                14 => s.tcp = &s.tcp[..19],
                _ => {}
            }
            assert!(
                prepare(&mut a, &io, s, &mut buffer[..capacity], LINK, budget)
                    .unwrap()
                    .is_none(),
                "case {case}"
            );
            assert!(a.accept_transmit(2, token).unwrap());
            assert_eq!(io.calls, 0);
        }
    }
}

#[test]
fn budget_exact_padding_and_no_hotpath_allocations() {
    for (v6, mss) in [(false, 1), (false, 1000), (true, 1000)] {
        let (mut a, _, id) = pair(v6, false, false, mss);
        let payload = vec![9; 6 * usize::from(mss)];
        a.write(id, &payload).unwrap();
        let mut io = Recording::new();
        let mut scratch = [0; 2048];
        let mut buffer = [0; 9000];
        let per = (54 + if v6 { 20 } else { 0 } + usize::from(mss)).max(60);
        ALLOCATIONS.with(|n| n.set(Some(0)));
        let s = scalar(&mut a, id, &mut scratch, 2);
        let pending = prepare(
            &mut a,
            &io,
            s,
            &mut buffer,
            LINK,
            Budget {
                max_segments: usize::MAX,
                max_wire_bytes: 2 * per,
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            pending.charge(),
            Charge {
                segments: 2,
                wire_bytes: 2 * per
            }
        );
        io.behavior = Behavior::Block;
        let pending = match pending.submit(&mut a, &mut io, || 2) {
            Submission::WouldBlock(p) => p,
            other => panic!("{other:?}"),
        };
        io.behavior = Behavior::Submit;
        assert!(matches!(
            pending.submit(&mut a, &mut io, || 3),
            Submission::Submitted(_)
        ));
        assert_eq!(ALLOCATIONS.with(|n| n.replace(None)), Some(0));
    }
}

#[test]
fn accepted_prefix_then_reject_mtu_shrink_never_replays_prefix() {
    for v6 in [false, true] {
        let (mut a, _, id) = pair(v6, false, false, 1400);
        let payload: Vec<_> = (0..8400).map(|i| (i % 251) as u8).collect();
        a.write(id, &payload).unwrap();
        let mut io = Recording::new();
        let mut scratch = [0; 2048];
        let mut buffer = [0; 10000];
        let s = scalar(&mut a, id, &mut scratch, 2);
        let start = wire::parse(s.packet.ip, s.tcp).unwrap().header.sequence;
        let pending = prepare(
            &mut a,
            &io,
            s,
            &mut buffer,
            LINK,
            Budget {
                max_segments: 2,
                ..BUDGET
            },
        )
        .unwrap()
        .unwrap();
        let mut offset = pending.request().segment_payload_len * pending.charge().segments;
        assert!(matches!(
            pending.submit(&mut a, &mut io, || 3),
            Submission::Submitted(_)
        ));
        let s = scalar(&mut a, id, &mut scratch, 3);
        let pending = prepare(&mut a, &io, s, &mut buffer, LINK, BUDGET)
            .unwrap()
            .unwrap();
        let mtu = if v6 { 1280 } else { 552 };
        assert_eq!(
            a.set_first_hop_mtu(3, id, mtu),
            Err(EndpointError::OutputReserved)
        );
        pending.reject(&mut a).unwrap();
        a.set_first_hop_mtu(3, id, mtu).unwrap();
        while a.is_output_reserved(id) {
            let s = scalar(&mut a, id, &mut scratch, 3);
            let parsed = wire::parse(s.packet.ip, s.tcp).unwrap();
            assert_eq!(parsed.header.sequence, start.wrapping_add(offset as u32));
            assert_eq!(
                parsed.payload,
                &payload[offset..offset + parsed.payload.len()]
            );
            offset += parsed.payload.len();
            assert!(s.packet.len + if v6 { 40 } else { 20 } <= mtu as usize);
            let token = s.attempt;
            assert!(
                prepare(&mut a, &io, s, &mut buffer, LINK, BUDGET)
                    .unwrap()
                    .is_none()
            );
            assert!(a.accept_transmit(3, token).unwrap());
        }
        assert_eq!(offset, payload.len());
        assert_eq!(io.calls, 1);
    }
}

#[test]
fn uncertain_and_postsubmitted_clock_failure_quarantine_without_resubmission() {
    for behavior in [Behavior::Other, Behavior::Submit] {
        let (mut a, _, id) = pair(false, false, false, 1000);
        a.write(id, &[7; 5000]).unwrap();
        let mut io = Recording::new();
        io.behavior = behavior;
        let mut scratch = [0; 2048];
        let mut buffer = [0; 9000];
        let s = scalar(&mut a, id, &mut scratch, 2);
        let pending = prepare(&mut a, &io, s, &mut buffer, LINK, BUDGET)
            .unwrap()
            .unwrap();
        let group = pending.group;
        let mut times = [3, 0].into_iter();
        let result = pending.submit(&mut a, &mut io, || times.next().unwrap());
        let Submission::Quarantined(q) = result else {
            panic!("{result:?}")
        };
        assert_eq!(q.bytes(), &io.bytes[..io.len]);
        match behavior {
            Behavior::Other => assert!(matches!(q.reason, QuarantineReason::Io(_))),
            _ => assert!(matches!(q.reason, QuarantineReason::Core(_))),
        }
        assert!(a.transmit_group(group).is_some());
        assert_eq!(io.calls, 1);
        // q has no submit/reject/abandon method: no recovery permission inferred.
    }
}

#[test]
fn preflight_stale_clock_history_and_deadline_abandon_do_not_send() {
    for case in 0..4 {
        let (mut a, _, id) = pair(false, false, false, 1000);
        a.write(id, &[7; 5000]).unwrap();
        let mut io = Recording::new();
        let mut scratch = [0; 2048];
        let mut buffer = [0; 9000];
        let s = scalar(&mut a, id, &mut scratch, 2);
        let pending = prepare(&mut a, &io, s, &mut buffer, LINK, BUDGET)
            .unwrap()
            .unwrap();
        let group = pending.group;
        match case {
            0 => {
                // Simulate external misuse of a retained core token.
                a.reject_unsubmitted_group(group).unwrap();
                assert!(matches!(
                    pending.submit(&mut a, &mut io, || 3),
                    Submission::Quarantined(_)
                ));
            }
            1 => {
                assert!(matches!(
                    pending.submit(&mut a, &mut io, || 0),
                    Submission::Rejected(Rejection::Preflight(_))
                ));
                assert!(a.transmit_group(group).is_none());
                let s = scalar(&mut a, id, &mut scratch, 3);
                assert!(a.accept_transmit(3, s.attempt).unwrap());
            }
            2 => {
                io.behavior = Behavior::Block;
                let pending = match pending.submit(&mut a, &mut io, || 3) {
                    Submission::WouldBlock(p) => p,
                    other => panic!("{other:?}"),
                };
                io.behavior = Behavior::Submit;
                // Other owner advances the endpoint clock while this owner is held.
                let now = (1u64 << 31) * 1000 + 3;
                a.connect(
                    now,
                    "192.0.2.1:40001".parse().unwrap(),
                    "192.0.2.3:8080".parse().unwrap(),
                )
                .unwrap();
                assert!(matches!(
                    pending.submit(&mut a, &mut io, || now),
                    Submission::Rejected(Rejection::Preflight(_))
                ));
                assert!(a.transmit_group(group).is_none());
            }
            _ => {
                pending.abandon(&mut a).unwrap();
                assert!(!a.is_output_reserved(id));
            }
        }
        assert_eq!(io.calls, usize::from(case == 2));
    }
}

#[test]
fn flags_options_and_psh_only_two_segment_prefix_fall_back() {
    for case in 0..5 {
        let (mut a, _, id) = pair(false, false, false, 1000);
        a.write(id, &vec![7; if case == 4 { 2000 } else { 5000 }])
            .unwrap();
        let io = Recording::new();
        let mut scratch = [0; 2048];
        let mut changed = [0; 2048];
        let mut buffer = [0; 9000];
        let mut s = scalar(&mut a, id, &mut scratch, 2);
        let token = s.attempt;
        let parsed = wire::parse(s.packet.ip, s.tcp).unwrap();
        let mut header = parsed.header;
        let options: &[u8] = match case {
            0 => {
                header.flags |= wire::CWR;
                &[]
            }
            1 => {
                header.flags |= wire::ECE;
                &[]
            }
            2 => {
                header.urgent_pointer = 1;
                &[]
            }
            3 => &[1, 1, 0, 0],
            _ => &[],
        };
        // Deliberately inconsistent caller metadata exercises boundary rejection;
        // the untouched core scalar remains usable, not the altered test packet.
        s.packet.len =
            wire::encode(s.packet.ip, header, options, parsed.payload, &mut changed).unwrap();
        s.tcp = &changed[..s.packet.len];
        assert!(
            prepare(&mut a, &io, s, &mut buffer, LINK, BUDGET)
                .unwrap()
                .is_none()
        );
        assert!(a.accept_transmit(2, token).unwrap());
    }
}

#[test]
fn failed_core_preparation_leaves_scalar_identity_intact() {
    let (mut a, _, id) = pair(false, false, false, 1000);
    a.write(id, &[7; 5000]).unwrap();
    let io = Recording::new();
    let mut scratch = [0; 2048];
    let mut buffer = [0; 9000];
    let s = scalar(&mut a, id, &mut scratch, 2);
    let token = s.attempt;
    let segmentation = a.transmit_segmentation(token);
    a.on_timeout((1u64 << 31) * 1000 + 3, 0).unwrap();
    assert!(prepare(&mut a, &io, s, &mut buffer, LINK, BUDGET).is_err());
    assert_eq!(a.transmit_segmentation(token), segmentation);
    assert!(a.reject_unsubmitted(token).unwrap());
    assert_eq!(io.calls, 0);
}
