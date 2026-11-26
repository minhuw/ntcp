use super::*;
use std::{cell::RefCell, collections::VecDeque, rc::Rc};

unsafe extern "C" {
    fn ntcp_test_tso_gate();
    fn ntcp_test_check_tso(l3: u32, l4: u32, mss: u32, length: u32);
    fn ntcp_test_init() -> i32;
    fn ntcp_test_pool() -> *mut c_void;
    fn ntcp_test_available() -> u32;
    fn ntcp_test_tx_count() -> u32;
    fn ntcp_test_loopback() -> u32;
    fn ntcp_test_register_tx_timestamp();
    fn ntcp_test_check_scheduled(value: u64, length: u32);
    fn ntcp_test_hold(leave: u32);
    fn ntcp_test_release();
    fn ntcp_test_finish();
    fn ntcp_test_take(out: *mut u8, cap: u32, mss: *mut u32) -> u32;
    fn ntcp_test_inject(frame: *const u8, length: u32) -> i32;
    fn ntcp_test_l4_checksum(kind: u32);
    fn ntcp_test_checksummed() -> u32;
    fn ntcp_test_tx_dequeue(
        info: *mut TestTxInfo,
        segs: *mut TestTxSeg,
        seg_cap: u32,
    ) -> *mut c_void;
    fn ntcp_test_tx_read(mbuf: *const c_void, out: *mut u8, cap: u32) -> u32;
    fn ntcp_test_tx_verify_tso(mbuf: *mut c_void, l3: u32, l4: u32, mss: u32, length: u32);
    fn ntcp_test_tx_verify_checksum(mbuf: *const c_void, out: *mut u8, cap: u32);
    fn ntcp_test_tx_free(mbuf: *mut c_void);
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TestTxSeg {
    data: *const c_void,
    len: u16,
    external: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TestTxInfo {
    pkt_len: u32,
    nb_segs: u16,
    l2_len: u16,
    l3_len: u16,
    l4_len: u16,
    tso_segsz: u16,
    ol_flags: u64,
    timestamp: u64,
    has_timestamp: i32,
}

// The device's RX TCP checksum verdict: reported only once the queue opted
// in (`enable_rx_checksum`), which the ring PMD's capabilities refuse;
// GOOD and BAD as such, UNKNOWN and NONE (a checksum field not final) as
// Unknown. Ring mbufs carry the injected flags, NOT a device's checks.
unsafe fn rx_checksum_verdicts(io: &mut Dpdk) {
    let mut out = [0; 64];
    let mut verdict = |io: &mut Dpdk, kind| {
        unsafe { ntcp_test_l4_checksum(kind) };
        let packet = io.receive_with_metadata(&mut out).unwrap().unwrap();
        assert_eq!((packet.len, out), (64, [0x42; 64]));
        packet.l4_checksum
    };
    for kind in 0..4 {
        assert_eq!(verdict(io, kind), RxChecksum::Unknown);
    }
    assert_eq!(
        io.enable_rx_checksum().unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
    // PRIVATE fixture only: the opt-in the ring PMD cannot grant.
    io.rx_checksum = true;
    let expected = [
        RxChecksum::Unknown,
        RxChecksum::Good,
        RxChecksum::Bad,
        RxChecksum::Unknown,
    ];
    for (kind, expected) in expected.into_iter().enumerate() {
        assert_eq!(verdict(io, kind as u32), expected);
    }
    io.rx_checksum = false;

    // Enabling RX checksum with unread burst leftovers must invalidate their
    // plain views so leftovers fall back cleanly to `receive_meta` and read
    // L4 checksum verdicts; views stay on for later bursts and carry them.
    io.set_rx_frame_budget(Some(100));
    assert!(io.rx_views.is_some());
    for kind in 0..4u32 {
        unsafe { ntcp_test_l4_checksum(kind) };
    }
    let mut scratch = [0xa5; 128];
    let mut frame = None;
    let first = io.receive_frame(&mut scratch, &mut frame).unwrap().unwrap();
    assert_eq!(first.l4_checksum, RxChecksum::Unknown);
    assert_eq!(frame.take().unwrap().as_slice(), &[0x42; 64]);
    // PRIVATE fixture only: `enable_rx_checksum`'s state transition.
    io.mark_rx_checksum_enabled();
    for expected in [RxChecksum::Good, RxChecksum::Bad, RxChecksum::Unknown] {
        let mut frame = None;
        let pkt = io.receive_frame(&mut scratch, &mut frame).unwrap().unwrap();
        assert_eq!(pkt.l4_checksum, expected);
        assert_eq!(frame.take().unwrap().as_slice(), &[0x42; 64]);
    }
    io.set_rx_frame_budget(Some(100));
    assert!(io.rx_views.is_some());
    for (kind, expected) in [
        RxChecksum::Unknown,
        RxChecksum::Good,
        RxChecksum::Bad,
        RxChecksum::Unknown,
    ]
    .into_iter()
    .enumerate()
    {
        unsafe { ntcp_test_l4_checksum(kind as u32) };
        let mut frame = None;
        let pkt = io.receive_frame(&mut scratch, &mut frame).unwrap().unwrap();
        assert_eq!(pkt.l4_checksum, expected);
        assert_eq!(frame.take().unwrap().as_slice(), &[0x42; 64]);
    }
    unsafe { borrowed_checksum_verdicts(io) };
    io.rx_checksum = false;
    io.set_rx_frame_budget(None);
    assert_eq!(unsafe { ntcp_test_available() }, 1023);
}

// `consume_unannotated_frame` with RX checksum offload on (views kept, see
// `rx_checksum_verdicts`): a GOOD or UNKNOWN verdict is lent with the frame,
// a BAD one is deferred to normal receive, which reports it, and a view the
// opt-in invalidated is never lent. Integration coverage without the opt-in
// is in tests/borrowed_frame.rs.
unsafe fn borrowed_checksum_verdicts(io: &mut Dpdk) {
    assert!(io.rx_checksum && io.rx_views.is_some());
    let available = unsafe { ntcp_test_available() };
    // SAFETY: the fixture's EAL, port and pool are live; each call enqueues
    // one 64-byte mbuf of 0x42 on the ring's RX side.
    unsafe {
        for kind in [1, 0, 2, 3] {
            ntcp_test_l4_checksum(kind);
        }
    }
    let mut seen = None;
    let lent = io.consume_unannotated_frame(|bytes, checksum| {
        seen = Some((bytes.to_vec(), checksum));
        true
    });
    assert_eq!(lent, BorrowedFrame::Consumed);
    assert_eq!(seen.take(), Some((vec![0x42; 64], RxChecksum::Good)));
    assert_eq!(
        io.consume_unannotated_frame(|_, checksum| {
            assert_eq!(checksum, RxChecksum::Unknown);
            true
        }),
        BorrowedFrame::Consumed
    );
    // BAD: deferred untouched, then taken normally with its verdict.
    assert_eq!(
        io.consume_unannotated_frame(|_, _| unreachable!("BAD is never lent")),
        BorrowedFrame::Deferred
    );
    let mut scratch = [0xa5; 128];
    let mut frame = None;
    let mut meta = ReceivedPacket::default();
    assert!(io.receive_frame_into(&mut scratch, &mut frame, &mut meta).unwrap());
    assert_eq!(meta.l4_checksum, RxChecksum::Bad);
    assert_eq!(frame.take().unwrap().as_slice(), &[0x42; 64]);
    // NONE (a checksum field not final) is lent as Unknown.
    assert_eq!(
        io.consume_unannotated_frame(|_, checksum| {
            assert_eq!(checksum, RxChecksum::Unknown);
            true
        }),
        BorrowedFrame::Consumed
    );
    // Views prefetched before the opt-in carry no verdict, and the opt-in
    // invalidates them rather than lend them as Unknown.
    io.rx_checksum = false;
    // SAFETY: as above.
    unsafe {
        ntcp_test_l4_checksum(1);
        ntcp_test_l4_checksum(1);
    }
    let mut seen = None;
    assert_eq!(
        io.consume_unannotated_frame(|_, checksum| {
            seen = Some(checksum);
            false
        }),
        BorrowedFrame::Deferred
    );
    assert_eq!(seen, Some(RxChecksum::Unknown));
    io.mark_rx_checksum_enabled();
    assert_eq!(
        io.consume_unannotated_frame(|_, _| unreachable!("an invalidated view is never lent")),
        BorrowedFrame::Deferred
    );
    for _ in 0..2 {
        assert!(io.receive_frame_into(&mut scratch, &mut frame, &mut meta).unwrap());
        assert_eq!(meta.l4_checksum, RxChecksum::Good);
        assert_eq!(frame.take().unwrap().as_slice(), &[0x42; 64]);
    }
    assert_eq!(
        io.consume_unannotated_frame(|_, _| unreachable!("empty queue")),
        BorrowedFrame::Empty
    );
    assert_eq!(io.rx_frames_outstanding(), Some(0));
    assert_eq!(unsafe { ntcp_test_available() }, available);
}

#[test]
fn scheduled_mbuf_encoding_and_rejection_not_live_launch() {
    unsafe {
        let port = ntcp_test_init();
        assert!(port >= 0);
        struct Host;
        impl Drop for Host {
            fn drop(&mut self) {
                unsafe { ntcp_test_finish() }
            }
        }
        let _host = Host;
        let mut io = Dpdk::from_borrowed(port as u16, 0, 0, ntcp_test_pool()).unwrap();
        shared::ring_test(&mut io);
        rx_checksum_verdicts(&mut io);
        ntcp_test_tso_gate();
        assert_eq!(io.tcp_segmentation_capabilities(), None);
        let request = TcpSegmentationRequest {
            segment_payload_len: 100,
        };
        assert!(matches!(
            io.transmit_segmented(&[], request),
            Err(TcpSegmentationError::Unsupported)
        ));
        assert!(io.enable_tcp_segmentation().is_err()); // ring PMD has no TSO.
        assert_eq!(io.tcp_segmentation_capabilities(), None);
        // Inject cached configuration only inside this private fixture. Real
        // ring mbufs exercise encoding/ownership, NOT actual NIC segmentation.
        io.tso = Some(TsoConfig {
            mtu: 1500,
            room: 128,
            max_descriptors: 512,
        });
        let caps = io.tcp_segmentation_capabilities().unwrap();
        assert!(!caps.allow_psh && !caps.allow_cwr);
        // No options, timestamps (data offset 8), and the 60-byte maximum.
        for (v6, l4) in [false, true]
            .into_iter()
            .flat_map(|v6| [20, 32, 60].map(|l4| (v6, l4)))
        {
            let l3 = if v6 { 40 } else { 20 };
            let mut packet = vec![0; 14 + l3 + l4 + 300];
            packet[12..14].copy_from_slice(&(if v6 { 0x86ddu16 } else { 0x0800 }).to_be_bytes());
            if v6 {
                packet[14] = 0x60;
                packet[20] = 6;
                packet[18..20].copy_from_slice(&((l4 + 300) as u16).to_be_bytes());
            } else {
                packet[14] = 0x45;
                packet[23] = 6;
                packet[16..18].copy_from_slice(&((20 + l4 + 300) as u16).to_be_bytes());
            }
            packet[14 + l3 + 12] = (l4 as u8 / 4) << 4;
            packet[14 + l3 + 13] = 0x10;
            packet[14 + l3 + 20..14 + l3 + l4].fill(1); // NOP padding
            for _ in 0..7 {
                assert_eq!(
                    io.transmit_segmented(&packet, request).unwrap(),
                    TxOutcome::Submitted
                );
            }
            let available = ntcp_test_available();
            assert_eq!(
                io.transmit_segmented(&packet, request).unwrap(),
                TxOutcome::WouldBlock
            );
            assert_eq!(ntcp_test_available(), available);
            for _ in 0..7 {
                ntcp_test_check_tso(l3 as u32, l4 as u32, 100, packet.len() as u32);
            }
            assert_eq!(ntcp_test_available(), 1023);
            let full = io.device_counters().tx_nombuf;
            for leave in [0, 1, 2] {
                ntcp_test_hold(leave);
                assert_eq!(
                    io.transmit_segmented(&packet, request).unwrap(),
                    TxOutcome::WouldBlock
                );
                assert_eq!(ntcp_test_available(), leave);
                ntcp_test_release();
            }
            // An aggregate whose chain the pool could not complete.
            assert_eq!(io.device_counters().tx_nombuf, full + 3);
            io.tso.as_mut().unwrap().max_descriptors = 1;
            assert!(matches!(
                io.transmit_segmented(&packet, request),
                Err(TcpSegmentationError::InvalidInput)
            ));
            assert_eq!(ntcp_test_tx_count(), 0);
            assert_eq!(ntcp_test_available(), 1023);
            io.tso.as_mut().unwrap().max_descriptors = 512;
            // Headers must fit the head mbuf; the device cannot take them split.
            io.tso.as_mut().unwrap().room = (14 + l3 + l4 - 1) as u16;
            assert!(matches!(
                io.transmit_segmented(&packet, request),
                Err(TcpSegmentationError::Unsupported)
            ));
            assert_eq!(ntcp_test_available(), 1023);
            io.tso.as_mut().unwrap().room = 128;
            // PSH and FIN only where the driver keeps them on the last
            // segment (mlx5); the shim hands their header to the PMD as given.
            packet[14 + l3 + 13] = 0x19;
            assert!(matches!(
                io.transmit_segmented(&packet, request),
                Err(TcpSegmentationError::Unsupported)
            ));
            io.tso_psh = true;
            assert!(io.tcp_segmentation_capabilities().unwrap().allow_psh);
            assert_eq!(
                io.transmit_segmented(&packet, request).unwrap(),
                TxOutcome::Submitted
            );
            let (mut frame, mut mss) = (vec![0; packet.len()], 0);
            let len = ntcp_test_take(frame.as_mut_ptr(), frame.len() as u32, &mut mss);
            assert_eq!((len as usize, mss), (packet.len(), 100));
            assert_eq!(frame[14 + l3 + 13], 0x19);
            assert_eq!(ntcp_test_available(), 1023);
            io.tso_psh = false;
        }
        io.tso = None;
        let clock = ClockDescriptor {
            domain: ClockDomain::Device(17),
            unit: TimestampUnit::RawTicks { identity: 23 },
        };
        let when = TransmitTime { value: 123, clock };
        assert_eq!(io.tx_scheduling_capabilities(), None);
        assert_eq!(
            io.transmit_at(&[7; 64], when, None).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        for domain in [ClockDomain::Monotonic, ClockDomain::Realtime] {
            assert_eq!(
                io.enable_tx_scheduling(ClockDescriptor { domain, ..clock })
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(
            io.enable_tx_scheduling(clock).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        let (mut offset, mut flag) = (-1, 0);
        assert!(ntcp_dpdk_tx_timestamp_lookup(&mut offset, &mut flag) < 0);
        ntcp_test_register_tx_timestamp();
        assert_eq!(ntcp_dpdk_tx_timestamp_lookup(&mut offset, &mut flag), 0);
        assert!(offset >= 0 && flag.is_power_of_two());
        assert_eq!(
            io.enable_tx_scheduling(clock).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(io.tx_scheduling_capabilities(), None); // Registry is not offload evidence.
        eprintln!(
            "SKIP live launch verification: ring PMD has no SEND_ON_TIMESTAMP hardware offload"
        );

        // PRIVATE unit-test fixture only. Bypass capability discovery solely to
        // inspect real mbufs; no production/test-pmd public enable bypass exists.
        io.tx_scheduling = Some(TimestampConfig {
            clock,
            offset,
            flag,
        });
        assert_eq!(io.tx_scheduling_capabilities().unwrap().clock, clock);
        for bad_clock in [
            ClockDescriptor {
                domain: ClockDomain::Device(18),
                ..clock
            },
            ClockDescriptor {
                domain: ClockDomain::Monotonic,
                ..clock
            },
            ClockDescriptor {
                unit: TimestampUnit::Nanoseconds,
                ..clock
            },
            ClockDescriptor {
                unit: TimestampUnit::RawTicks { identity: 24 },
                ..clock
            },
        ] {
            assert_eq!(
                io.transmit_at(
                    &[7; 64],
                    TransmitTime {
                        clock: bad_clock,
                        ..when
                    },
                    None
                )
                .unwrap_err()
                .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        for (software, hardware) in [(true, false), (false, true), (true, true), (false, false)] {
            let error = io
                .transmit_at(
                    &[7; 64],
                    when,
                    Some(TxTimestampRequest {
                        cookie: 1,
                        software,
                        hardware,
                    }),
                )
                .unwrap_err();
            assert_eq!(
                error.kind(),
                if software || hardware {
                    io::ErrorKind::Unsupported
                } else {
                    io::ErrorKind::InvalidInput
                }
            );
        }
        assert!(io.transmit_at(&[], when, None).is_err());
        assert!(
            io.transmit_at(&vec![7; MAX_PACKET_LEN + 1], when, None)
                .is_err()
        );
        assert_eq!(
            io.poll_tx_scheduling_error().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(ntcp_test_tx_count(), 0);
        assert_eq!(ntcp_test_available(), 1023);

        for value in [0, 123456789, u64::MAX] {
            for length in [64, 129, MAX_PACKET_LEN] {
                assert_eq!(
                    io.transmit_at(&vec![7; length], TransmitTime { value, clock }, None)
                        .unwrap(),
                    TxOutcome::Submitted
                );
                ntcp_test_check_scheduled(value, length as u32);
                assert_eq!(ntcp_test_available(), 1023);
            }
        }
        for _ in 0..7 {
            assert_eq!(
                io.transmit_at(&[7; 64], when, None).unwrap(),
                TxOutcome::Submitted
            );
        }
        let available = ntcp_test_available();
        assert_eq!(
            io.transmit_at(&[7; 129], when, None).unwrap(),
            TxOutcome::WouldBlock
        );
        assert_eq!(ntcp_test_available(), available);
        for _ in 0..7 {
            ntcp_test_check_scheduled(when.value, 64);
        }
        let full = io.device_counters().tx_nombuf;
        for leave in [0, 1] {
            ntcp_test_hold(leave);
            assert_eq!(
                io.transmit_at(&[7; 129], when, None).unwrap(),
                TxOutcome::WouldBlock
            );
            assert_eq!(ntcp_test_available(), leave);
            ntcp_test_release();
        }
        assert_eq!(io.device_counters().tx_nombuf, full + 2);
        // Recycled mbufs do not retain the launch flag for ordinary transmit.
        assert_eq!(io.transmit(&[7; 64]).unwrap(), TxOutcome::Submitted);
        ntcp_test_loopback(); // Asserts every segment has zero offload flags.
        assert_eq!(io.receive(&mut [0; 64]).unwrap(), Some(64));
        assert_eq!(ntcp_test_available(), 1023);
        io.tx_scheduling = None;
        chunk_and_transmit_packet_ring_test(&mut io);
        segmented_network(io);
        assert_eq!(ntcp_test_available(), 1023);
        let io = Dpdk::from_borrowed(port as u16, 0, 0, ntcp_test_pool()).unwrap();
        dpdk_chunk_source_network(io);
        assert_eq!(ntcp_test_available(), 1023);
        assert_eq!(chunk::live_dpdk_chunks(), 0);
        for offload in [true, false] {
            let io = Dpdk::from_borrowed(port as u16, 0, 0, ntcp_test_pool()).unwrap();
            checksummed_network(io, offload);
            assert_eq!(ntcp_test_available(), 1023);
        }
        let io = Dpdk::from_borrowed(port as u16, 0, 0, ntcp_test_pool()).unwrap();
        pool_exhausted_network(io);
        assert_eq!(ntcp_test_available(), 1023);
    }
}

// The software peer of a Network on the ring port.
struct Peer {
    incoming: Rc<RefCell<VecDeque<Vec<u8>>>>,
    outgoing: Rc<RefCell<VecDeque<Vec<u8>>>>,
}
impl PacketIo for Peer {
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ethernet
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        let Some(frame) = self.incoming.borrow_mut().pop_front() else {
            return Ok(None);
        };
        out[..frame.len()].copy_from_slice(&frame);
        Ok(Some(frame.len()))
    }
    fn transmit(&mut self, frame: &[u8]) -> io::Result<TxOutcome> {
        self.outgoing.borrow_mut().push_back(frame.to_vec());
        Ok(TxOutcome::Submitted)
    }
}
fn sum(mut acc: u32, bytes: &[u8]) -> u32 {
    for word in bytes.chunks(2) {
        acc += u32::from(u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]));
    }
    acc
}
fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}
// The segments a device cuts from an IPv4 TSO frame, as Linux
// tcp_gso_segment does, every length and checksum filled.
fn cut(frame: &[u8], mss: usize) -> Vec<Vec<u8>> {
    let tcp = 14 + 20;
    let payload = tcp + usize::from(frame[tcp + 12] >> 4) * 4;
    let data = &frame[payload..];
    let count = data.len().div_ceil(mss);
    let sequence = u32::from_be_bytes(frame[tcp + 4..tcp + 8].try_into().unwrap());
    (0..count)
        .map(|n| {
            let mut s = frame[..payload].to_vec();
            s.extend_from_slice(&data[n * mss..((n + 1) * mss).min(data.len())]);
            let len = (s.len() - 14) as u16;
            s[16..18].copy_from_slice(&len.to_be_bytes());
            s[24..26].fill(0);
            let ip = fold(sum(0, &s[14..tcp]));
            s[24..26].copy_from_slice(&ip.to_be_bytes());
            s[tcp + 4..tcp + 8]
                .copy_from_slice(&sequence.wrapping_add((n * mss) as u32).to_be_bytes());
            if n + 1 != count {
                s[tcp + 13] &= !0x09;
            }
            if n != 0 {
                s[tcp + 13] &= !0x80;
            }
            s[tcp + 16..tcp + 18].fill(0);
            let pseudo = sum(
                sum(sum(0, &s[26..34]), &[0, 6]),
                &((s.len() - tcp) as u16).to_be_bytes(),
            );
            let tcp_sum = fold(sum(pseudo, &s[tcp..]));
            s[tcp + 16..tcp + 18].copy_from_slice(&tcp_sum.to_be_bytes());
            s
        })
        .collect()
}

// ntcp-native over the ring port with TSO: aggregates leave as one TSO mbuf
// chain each (offload metadata checked by the fixture), which the test cuts
// as a device would for a software peer; the pool, held down to room for
// a scalar segment, has none for the next aggregate, which waits until the
// mbufs return. The stream
// arrives whole. Each write of up to 64 KiB asks for Scheduled and
// Acknowledged observations, as dpdk_echo's requests do: aggregates still
// form, and each request's arrive once, for its last byte. Real ring
// mbufs, NOT NIC segmentation.
unsafe fn segmented_network(mut io: Dpdk) {
    use ntcp_native::{
        EthernetNextHop, Link, Network, NetworkConfig, ReadOutcome, TimestampEvent,
        TxTimestampEvent, TxTimestampOutcome, TxTimestampRequest, TxTimestampSource,
        TxTimestampStage, WorkBudget, WriteOptions,
    };
    io.tso = Some(TsoConfig {
        mtu: 1500,
        room: 128,
        max_descriptors: 512,
    });
    let link = |side: u8| Link::Ethernet {
        local_mac: [2, 0, 0, 0, 0, side],
        next_hop: EthernetNextHop::Fixed([2, 0, 0, 0, 0, 3 - side]),
    };
    let config = |address: &str, side: u8| {
        let mut config = NetworkConfig::new(address.parse().unwrap(), 1500);
        config.tcp.max_connections = 2;
        config.tcp.connection.send_capacity = 256 * 1024;
        config.tcp.connection.receive_capacity = 256 * 1024;
        config.link = link(side);
        config
    };
    // buffer_budget admits the connections with no room to write: a writer
    // also allocates its send ring (2 bytes a byte of send_capacity) and its
    // RACK and SACK ledgers (68 bytes a byte held queued, and the replaced
    // ones while they grow).
    let headroom = |config: &NetworkConfig| 2 * (72 * config.tcp.connection.send_capacity + 65536);
    let mut ca = config("10.74.0.1", 1);
    ca.tx_timestamp_phases = 64;
    ca.tcp.max_buffer_bytes = ca.buffer_budget(2, &io).unwrap() + headroom(&ca);
    let incoming = Rc::new(RefCell::new(VecDeque::new()));
    let outgoing = Rc::new(RefCell::new(VecDeque::new()));
    let peer = Peer {
        incoming: incoming.clone(),
        outgoing: outgoing.clone(),
    };
    let mut cb = config("10.74.0.2", 2);
    cb.tcp.max_buffer_bytes = cb.buffer_budget(2, &peer).unwrap() + headroom(&cb);
    let mut a = Network::new(ca, io, [1; 32], 0).unwrap();
    let mut b = Network::new(cb, peer, [2; 32], 0).unwrap();
    let listener = b.listen(9000, 1).unwrap();
    let client = a.connect("10.74.0.2:9000".parse().unwrap()).unwrap();
    let data: Vec<u8> = (0..300_000).map(|i| (i * 7 % 251) as u8).collect();
    let budget = WorkBudget::new(64, 64, 64, 64);
    let (mut server, mut sent, mut received) = (None, 0, Vec::new());
    let (mut frame, mut out) = (vec![0; MAX_PACKET_LEN], vec![0; 65536]);
    let (mut aggregates, mut blocked, mut holding) = (0, 0, false);
    let mut backlog = VecDeque::new();
    let (mut writes, mut targets, mut events) = (0u64, Vec::new(), Vec::new());
    let placeholder = TimestampEvent {
        connection: client,
        observation: TxTimestampEvent {
            cookie: u64::MAX,
            target: 0,
            stage: TxTimestampStage::Scheduled,
            source: TxTimestampSource::Software,
            outcome: TxTimestampOutcome::Cancelled,
        },
    };
    let mut stamps = [placeholder; 16];
    for step in 1..20_000u64 {
        let now = step * 1000;
        let timestamps = TxTimestampRequest {
            cookie: writes,
            scheduled: true,
            acknowledged: true,
            ..TxTimestampRequest::default()
        };
        let request = &data[sent..(sent + 65536).min(data.len())];
        if !request.is_empty()
            && let Ok(receipt) = a.try_write(client, request, WriteOptions { timestamps })
        {
            sent += receipt.accepted;
            targets.push((writes, receipt.range.end - 1));
            writes += 1;
        }
        let pressure = a.counters().backend_backpressure;
        a.drive(now, budget).unwrap();
        blocked += usize::from(a.counters().backend_backpressure > pressure);
        // Mbufs come back once an aggregate waited for them.
        if holding && blocked != 0 {
            unsafe { ntcp_test_release() };
            holding = false;
        }
        loop {
            let report = a.drain_timestamps(&mut stamps);
            events.extend(stamps[..report.written].iter().map(|e| e.observation));
            if !report.more {
                break;
            }
        }
        loop {
            let mut mss = 0;
            let len = unsafe { ntcp_test_take(frame.as_mut_ptr(), frame.len() as u32, &mut mss) };
            if len == 0 {
                break;
            }
            let frame = &frame[..len as usize];
            if mss == 0 {
                incoming.borrow_mut().push_back(frame.to_vec());
            } else {
                aggregates += 1;
                assert!(frame.len() > 1514);
                incoming.borrow_mut().extend(cut(frame, mss as usize));
            }
        }
        // Once aggregates flow, the pool keeps room for a scalar segment
        // (12 mbufs of 128 bytes) but not for the next aggregate, as frames
        // held elsewhere would: that aggregate waits until mbufs return.
        if aggregates != 0 && blocked == 0 && !holding {
            unsafe { ntcp_test_hold(16) };
            holding = true;
        }
        b.drive(now, budget).unwrap();
        backlog.extend(outgoing.borrow_mut().drain(..));
        while let Some(frame) = backlog.front() {
            if unsafe { ntcp_test_inject(frame.as_ptr(), frame.len() as u32) } != 0 {
                break;
            }
            backlog.pop_front();
        }
        if server.is_none() {
            server = b.accept(listener).ok();
        }
        if let Some(server) = server {
            while let Ok(ReadOutcome::Data { len, .. }) = b.try_read(server, &mut out) {
                received.extend_from_slice(&out[..len]);
            }
        }
        if received.len() == data.len() && events.len() == 2 * targets.len() {
            break;
        }
    }
    assert_eq!(received, data);
    assert!(targets.len() > 1);
    assert_eq!(events.len(), 2 * targets.len());
    for &(cookie, target) in &targets {
        for stage in [TxTimestampStage::Scheduled, TxTimestampStage::Acknowledged] {
            let mut matching = events
                .iter()
                .filter(|o| o.cookie == cookie && o.stage == stage);
            let event = matching.next().unwrap();
            assert!(matching.next().is_none(), "{cookie} {stage:?}");
            assert_eq!(event.target, target);
            assert!(matches!(event.outcome, TxTimestampOutcome::Recorded { .. }));
        }
    }
    assert!(!holding);
    // What is left on the rings goes back to the pool.
    for step in 0..4 {
        a.drive(30_000_000 + step, budget).unwrap();
        let mut mss = 0;
        while unsafe { ntcp_test_take(frame.as_mut_ptr(), frame.len() as u32, &mut mss) } != 0 {}
    }
    assert!(aggregates > 0);
    assert_eq!(a.counters().segmented, aggregates as u64);
    assert!(blocked > 0, "no aggregate waited for the pool");
    eprintln!("ring PMD: {aggregates} TSO chains, {blocked} drives blocked, {writes} writes");
    drop(a);
}

// ntcp-native over the ring port, its segments' TCP checksums left to the
// device (`offload`, through the private opt-in the ring PMD cannot grant)
// or computed in software. The fixture checks each offload request's
// metadata and pseudo-header sum and completes the checksum as a device
// would; the software peer verifies every checksum, and the stream
// arrives whole. Without offload every frame carries no offload flags.
// Real ring mbufs, NOT a device's checksum engine.
unsafe fn checksummed_network(mut io: Dpdk, offload: bool) {
    use ntcp_native::{
        EthernetNextHop, Link, Network, NetworkConfig, ReadOutcome, WorkBudget, WriteOptions,
    };
    assert_eq!(
        io.enable_tx_checksum().unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
    assert!(!io.tcp_checksum_offload());
    assert_eq!(
        io.transmit_tcp_checksum_offload(&[0; 64])
            .unwrap_err()
            .kind(),
        io::ErrorKind::Unsupported
    );
    io.tx_checksum = offload;
    assert_eq!(io.tcp_checksum_offload(), offload);
    let config = |address: &str, side: u8| {
        let mut config = NetworkConfig::new(address.parse().unwrap(), 1500);
        config.tcp.max_connections = 2;
        config.link = Link::Ethernet {
            local_mac: [2, 0, 0, 0, 0, side],
            next_hop: EthernetNextHop::Fixed([2, 0, 0, 0, 0, 3 - side]),
        };
        config
    };
    let incoming = Rc::new(RefCell::new(VecDeque::new()));
    let outgoing = Rc::new(RefCell::new(VecDeque::new()));
    let peer = Peer {
        incoming: incoming.clone(),
        outgoing: outgoing.clone(),
    };
    let mut a = Network::new(config("10.75.0.1", 1), io, [1; 32], 0).unwrap();
    let mut b = Network::new(config("10.75.0.2", 2), peer, [2; 32], 0).unwrap();
    assert_eq!(a.config().tcp.connection.tcp_checksum_offload, offload);
    let listener = b.listen(9000, 1).unwrap();
    let client = a.connect("10.75.0.2:9000".parse().unwrap()).unwrap();
    let data: Vec<u8> = (0..100_000).map(|i| (i * 13 % 251) as u8).collect();
    let budget = WorkBudget::new(64, 64, 64, 64);
    let (mut server, mut sent, mut received) = (None, 0, Vec::new());
    let (mut frame, mut out) = (vec![0; MAX_PACKET_LEN], vec![0; 65536]);
    let before = unsafe { ntcp_test_checksummed() };
    let mut frames = 0;
    for step in 1..20_000u64 {
        let now = step * 1000;
        if sent < data.len()
            && let Ok(receipt) = a.try_write(client, &data[sent..], WriteOptions::default())
        {
            sent += receipt.accepted;
        }
        a.drive(now, budget).unwrap();
        loop {
            let mut mss = 0;
            let len = unsafe { ntcp_test_take(frame.as_mut_ptr(), frame.len() as u32, &mut mss) };
            if len == 0 {
                break;
            }
            assert_eq!(mss, 0);
            frames += 1;
            incoming
                .borrow_mut()
                .push_back(frame[..len as usize].to_vec());
        }
        b.drive(now, budget).unwrap();
        for frame in outgoing.borrow_mut().drain(..) {
            assert_eq!(
                unsafe { ntcp_test_inject(frame.as_ptr(), frame.len() as u32) },
                0
            );
        }
        if server.is_none() {
            server = b.accept(listener).ok();
        }
        if let Some(server) = server {
            while let Ok(ReadOutcome::Data { len, .. }) = b.try_read(server, &mut out) {
                received.extend_from_slice(&out[..len]);
            }
        }
        if received.len() == data.len() {
            break;
        }
    }
    assert_eq!(received, data);
    assert_eq!(b.counters().tcp_checksum_errors, 0);
    let checksummed = unsafe { ntcp_test_checksummed() } - before;
    assert_eq!(checksummed, if offload { frames } else { 0 });
    assert!(frames > 70);
    // What is left on the rings goes back to the pool.
    for step in 0..4 {
        a.drive(30_000_000 + step, budget).unwrap();
        let mut mss = 0;
        while unsafe { ntcp_test_take(frame.as_mut_ptr(), frame.len() as u32, &mut mss) } != 0 {}
    }
    drop(a);
}

// ntcp-native over the ring port while its pool is empty: every frame the
// Network tries to send finds no mbuf. The attempt is backpressure, as a
// full TX ring is (TxOutcome::WouldBlock): the frame stays in its slot, is
// neither counted sent nor discarded, and leaves once mbufs come back, with
// no retransmission. Counters::tx_nombuf counts the attempts; drops,
// discarded and transmitted do not move.
unsafe fn pool_exhausted_network(io: Dpdk) {
    use ntcp_native::{
        EthernetNextHop, Link, Network, NetworkConfig, ReadOutcome, WorkBudget, WriteOptions,
    };
    let config = |address: &str, side: u8| {
        let mut config = NetworkConfig::new(address.parse().unwrap(), 1500);
        config.tcp.max_connections = 2;
        config.link = Link::Ethernet {
            local_mac: [2, 0, 0, 0, 0, side],
            next_hop: EthernetNextHop::Fixed([2, 0, 0, 0, 0, 3 - side]),
        };
        config
    };
    let incoming = Rc::new(RefCell::new(VecDeque::new()));
    let outgoing = Rc::new(RefCell::new(VecDeque::new()));
    let peer = Peer {
        incoming: incoming.clone(),
        outgoing: outgoing.clone(),
    };
    let mut a = Network::new(config("10.76.0.1", 1), io, [1; 32], 0).unwrap();
    let mut b = Network::new(config("10.76.0.2", 2), peer, [2; 32], 0).unwrap();
    let listener = b.listen(9000, 1).unwrap();
    let client = a.connect("10.76.0.2:9000".parse().unwrap()).unwrap();
    let budget = WorkBudget::new(64, 64, 64, 64);
    let mut frame = vec![0; MAX_PACKET_LEN];
    // One round trip of the wire: a's frames to b, b's back to a.
    let mut exchange = |a: &mut Network<Dpdk>, b: &mut Network<Peer>, now: u64| {
        a.drive(now, budget).unwrap();
        loop {
            let mut mss = 0;
            let len = unsafe { ntcp_test_take(frame.as_mut_ptr(), frame.len() as u32, &mut mss) };
            if len == 0 {
                break;
            }
            incoming
                .borrow_mut()
                .push_back(frame[..len as usize].to_vec());
        }
        b.drive(now, budget).unwrap();
        for frame in outgoing.borrow_mut().drain(..) {
            assert_eq!(
                unsafe { ntcp_test_inject(frame.as_ptr(), frame.len() as u32) },
                0
            );
        }
    };
    let mut server = None;
    for step in 1..100u64 {
        exchange(&mut a, &mut b, step * 1000);
        server = b.accept(listener).ok();
        if server.is_some() {
            break;
        }
    }
    let server = server.unwrap();
    exchange(&mut a, &mut b, 200_000);
    let before = a.counters();
    assert_eq!(before.tx_nombuf, 0);

    let data: Vec<u8> = (0..3000).map(|i| (i * 11 % 251) as u8).collect();
    assert_eq!(
        a.try_write(client, &data, WriteOptions::default())
            .unwrap()
            .accepted,
        data.len()
    );
    unsafe { ntcp_test_hold(0) };
    for _ in 0..3 {
        a.drive(300_000, budget).unwrap();
    }
    assert_eq!(unsafe { ntcp_test_tx_count() }, 0);
    let held = a.counters();
    // Each drive tried the frame at the head of its slots again.
    assert!(held.tx_nombuf >= 3, "{}", held.tx_nombuf);
    assert_eq!(
        held.backend_backpressure - before.backend_backpressure,
        held.tx_nombuf
    );
    assert_eq!(held.transmitted, before.transmitted);
    assert_eq!(held.drops, before.drops);
    assert_eq!(held.discarded, before.discarded);
    // The ring PMD reports no receive counters.
    assert_eq!((held.rx_nombuf, held.rx_missed), (0, 0));
    unsafe { ntcp_test_release() };

    let mut received = Vec::new();
    let mut out = vec![0; 65536];
    for step in 0..100u64 {
        exchange(&mut a, &mut b, 300_000 + step * 1000);
        while let Ok(ReadOutcome::Data { len, .. }) = b.try_read(server, &mut out) {
            received.extend_from_slice(&out[..len]);
        }
        if received.len() == data.len() {
            break;
        }
    }
    assert_eq!(received, data);
    let after = a.counters();
    assert_eq!(after.tx_nombuf, held.tx_nombuf);
    // Never counted sent while it waited, so nothing was repaired.
    assert_eq!(after.retransmitted_segments, 0);
    assert_eq!(after.loss_probes, 0);
    assert_eq!(after.drops, before.drops);
    // What is left on the rings goes back to the pool.
    for step in 0..4 {
        a.drive(30_000_000 + step, budget).unwrap();
        let mut mss = 0;
        while unsafe { ntcp_test_take(frame.as_mut_ptr(), frame.len() as u32, &mut mss) } != 0 {}
    }
    drop(a);
}

fn build_tcp_header(v6: bool, l4: usize, payload_len: usize, for_tso: bool) -> Vec<u8> {
    let l3 = if v6 { 40 } else { 20 };
    let mut hdr = vec![0u8; 14 + l3 + l4];
    hdr[12..14].copy_from_slice(&(if v6 { 0x86ddu16 } else { 0x0800 }).to_be_bytes());
    if v6 {
        hdr[14] = 0x60;
        hdr[20] = 6;
        hdr[18..20].copy_from_slice(&((l4 + payload_len) as u16).to_be_bytes());
        hdr[22..38].copy_from_slice(&[0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        hdr[38..54].copy_from_slice(&[0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    } else {
        hdr[14] = 0x45;
        hdr[23] = 6;
        hdr[16..18].copy_from_slice(&((20 + l4 + payload_len) as u16).to_be_bytes());
        hdr[26..30].copy_from_slice(&[10, 0, 0, 1]);
        hdr[30..34].copy_from_slice(&[10, 0, 0, 2]);
    }
    let tcp = 14 + l3;
    hdr[tcp..tcp + 2].copy_from_slice(&12345u16.to_be_bytes());
    hdr[tcp + 2..tcp + 4].copy_from_slice(&443u16.to_be_bytes());
    hdr[tcp + 12] = ((l4 / 4) as u8) << 4;
    hdr[tcp + 13] = 0x10; // ACK
    if l4 > 20 {
        hdr[tcp + 20..tcp + l4].fill(1); // NOP options
    }
    if !for_tso {
        // Compute RFC 1071 pseudo-header sum (matching rte_ipv4/ipv6_phdr_cksum).
        let mut sum: u32 = 0;
        if v6 {
            for &pair in hdr[22..54].as_chunks::<2>().0 {
                sum += u32::from(u16::from_be_bytes(pair));
            }
            sum += (l4 + payload_len) as u32;
            sum += 6;
        } else {
            for &pair in hdr[26..34].as_chunks::<2>().0 {
                sum += u32::from(u16::from_be_bytes(pair));
            }
            sum += 6;
            sum += (l4 + payload_len) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        hdr[tcp + 16..tcp + 18].copy_from_slice(&(sum as u16).to_be_bytes());
    }
    hdr
}

unsafe fn chunk_and_transmit_packet_ring_test(io: &mut Dpdk) {
    use ntcp_io::{ChunkSlice, Payload, PayloadSlice};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    // 1. Default copybreak & tx_chunk_source fallback when shared_limit is None.
    assert_eq!(io.tx_copybreak(), DEFAULT_TX_COPYBREAK);
    assert!(io.shared_limit.is_none());
    {
        let mut heap_src = io.tx_chunk_source();
        let heap_chunk = heap_src.allocate().unwrap();
        assert!(!core::ptr::eq(
            heap_chunk.vtable(),
            &chunk::DPDK_CHUNK_VTABLE
        ));
    }

    // 2. DpdkChunkSource lifecycle, alignment, bounded recycler, and drop with live chunks.
    {
        let mut src = chunk::DpdkChunkSource::new(chunk::DEFAULT_DPDK_CHUNK_SIZE);
        assert_eq!(src.chunk_size(), 16 * 1024);
        assert_eq!(src.cached_count(), 0);
        let mut c1 = src.allocate().unwrap();
        assert!(core::ptr::eq(c1.vtable(), &chunk::DPDK_CHUNK_VTABLE));
        assert_eq!(c1.as_ptr() as usize % 64, 0);
        assert_eq!(chunk::chunk_refcnt(&c1), 1);
        assert_eq!(c1.append(b"hello dpdk chunk"), 16);
        let s = ChunkSlice::new(&c1, 6..10).unwrap();
        assert_eq!(s.bytes(), b"dpdk");
        let first_ptr = c1.as_ptr();
        drop(c1);
        assert_eq!(src.cached_count(), 1);
        // Reuses cached chunk without hitting rte_malloc again.
        let c2 = src.allocate().unwrap();
        assert_eq!(c2.as_ptr(), first_ptr);
        assert_eq!(src.cached_count(), 0);
        assert_eq!(chunk::chunk_refcnt(&c2), 1);
        drop(c2);
        assert_eq!(src.cached_count(), 1);

        // Recycler is bounded at CHUNK_RECYCLER_CAP; extras are rte_free'd cleanly.
        let mut batch = Vec::new();
        for _ in 0..(chunk::CHUNK_RECYCLER_CAP + 4) {
            batch.push(src.allocate().unwrap());
        }
        assert_eq!(src.cached_count(), 0);
        drop(batch);
        assert_eq!(src.cached_count(), chunk::CHUNK_RECYCLER_CAP);

        // Dropping source while a chunk is still live keeps the chunk valid;
        // dropping the chunk later (on another thread) frees it cleanly.
        let mut survivor = src.allocate().unwrap();
        survivor.append(&[0xab; 128]);
        drop(src);
        assert_eq!(survivor.bytes(0..128), &[0xab; 128]);
        std::thread::spawn(move || {
            assert_eq!(survivor.bytes(0..128), &[0xab; 128]);
            drop(survivor);
        })
        .join()
        .unwrap();
    }

    // Inject multi-seg limit in private fixture to exercise extbuf TX path.
    io.shared_limit = Some(8);
    {
        let mut dpdk_src = io.tx_chunk_source();
        let dpdk_chunk = dpdk_src.allocate().unwrap();
        assert!(core::ptr::eq(
            dpdk_chunk.vtable(),
            &chunk::DPDK_CHUNK_VTABLE
        ));
        assert_eq!(dpdk_chunk.capacity(), 16 * 1024);
    }

    // 3. Two-level refcount test: drop TxChunk while NIC mbuf still holds extbuf!
    {
        let mut src = chunk::DpdkChunkSource::new(chunk::DEFAULT_DPDK_CHUNK_SIZE);
        let mut c = src.allocate().unwrap();
        let payload_bytes: Vec<u8> = (0..700).map(|i| ((i * 31) % 251) as u8).collect();
        assert_eq!(c.append(&payload_bytes), 700);
        let chunk_base = c.as_ptr();
        let header = [0x42u8; 54];
        let parts = [TxPart::Chunk(ChunkSlice::new(&c, 64..700).unwrap())];
        let pkt = TxPacket {
            header: &header,
            payload: &parts,
        };
        assert_eq!(
            io.transmit_packet(&pkt, TransmitRequest::default()).unwrap(),
            TxOutcome::Submitted
        );
        // Owner ref (1) + attached extbuf mbuf (1) = 2.
        assert_eq!(chunk::chunk_refcnt(&c), 2);
        let mut info = TestTxInfo::default();
        let mut segs = [TestTxSeg::default(); 8];
        let mbuf = unsafe { ntcp_test_tx_dequeue(&mut info, segs.as_mut_ptr(), 8) };
        assert!(!mbuf.is_null());
        assert_eq!(info.nb_segs, 2);
        assert_eq!(info.pkt_len, 54 + 636);
        assert_eq!(segs[0].len, 54);
        assert_eq!(segs[0].external, 0);
        assert_eq!(segs[1].len, 636);
        assert_eq!(segs[1].external, 1);
        assert_eq!(segs[1].data, unsafe { chunk_base.add(64) }.cast());

        // Drop TxChunk while the mbuf is still held (simulating in-flight DMA).
        drop(c);
        assert_eq!(src.cached_count(), 0); // Must stay pinned until mbuf frees!
        let mut wire = vec![0u8; info.pkt_len as usize];
        assert_eq!(
            unsafe { ntcp_test_tx_read(mbuf, wire.as_mut_ptr(), wire.len() as u32) },
            info.pkt_len
        );
        assert_eq!(&wire[..54], &header);
        assert_eq!(&wire[54..], &payload_bytes[64..700]);

        // Freeing the mbuf drops refcnt 1 -> 0 and recycles the chunk!
        unsafe { ntcp_test_tx_free(mbuf) };
        assert_eq!(src.cached_count(), 1);
        let reused = src.allocate().unwrap();
        assert_eq!(reused.as_ptr(), chunk_base);
        assert_eq!(chunk::chunk_refcnt(&reused), 1);

        // Also drop BOTH source AND TxChunk while mbuf is held; freeing mbuf
        // later must rte_free cleanly without UAF.
        let mut c2 = reused;
        c2.append(&payload_bytes);
        let parts2 = [TxPart::Chunk(ChunkSlice::new(&c2, 0..600).unwrap())];
        let pkt2 = TxPacket {
            header: &header,
            payload: &parts2,
        };
        assert_eq!(
            io.transmit_packet(&pkt2, TransmitRequest::default()).unwrap(),
            TxOutcome::Submitted
        );
        let mbuf2 = unsafe { ntcp_test_tx_dequeue(&mut info, segs.as_mut_ptr(), 8) };
        assert!(!mbuf2.is_null());
        drop(c2);
        drop(src);
        let mut wire2 = vec![0u8; info.pkt_len as usize];
        assert_eq!(
            unsafe { ntcp_test_tx_read(mbuf2, wire2.as_mut_ptr(), wire2.len() as u32) },
            info.pkt_len
        );
        assert_eq!(&wire2[54..], &payload_bytes[..600]);
        unsafe { ntcp_test_tx_free(mbuf2) };
        assert_eq!(unsafe { ntcp_test_available() }, 1023);
    }

    // 4. D1 configurable TX copybreak & I9 adjacent chunk merging.
    {
        let mut src = chunk::DpdkChunkSource::new(chunk::DEFAULT_DPDK_CHUNK_SIZE);
        let mut c = src.allocate().unwrap();
        let data: Vec<u8> = (0..1200).map(|i| (i % 239) as u8).collect();
        c.append(&data);
        let header = [0x11u8; 54];

        // Small payload <= pool_room - 54 (64 bytes <= default copybreak 512):
        // copies into 1 direct mbuf (no extbuf).
        let small_parts = [TxPart::Chunk(ChunkSlice::new(&c, 0..64).unwrap())];
        assert_eq!(
            io.transmit_packet(
                &TxPacket {
                    header: &header,
                    payload: &small_parts,
                },
                TransmitRequest::default()
            )
            .unwrap(),
            TxOutcome::Submitted
        );
        assert_eq!(chunk::chunk_refcnt(&c), 1);
        let mut info = TestTxInfo::default();
        let mut segs = [TestTxSeg::default(); 8];
        let m = unsafe { ntcp_test_tx_dequeue(&mut info, segs.as_mut_ptr(), 8) };
        assert_eq!(info.nb_segs, 1);
        assert_eq!(segs[0].external, 0);
        assert_eq!(info.pkt_len, 54 + 64);
        let mut wire = vec![0u8; info.pkt_len as usize];
        unsafe { ntcp_test_tx_read(m, wire.as_mut_ptr(), wire.len() as u32) };
        assert_eq!(&wire[..54], &header);
        assert_eq!(&wire[54..], &data[..64]);
        unsafe { ntcp_test_tx_free(m) };

        // Exact boundary payload == DEFAULT_TX_COPYBREAK (512): still copy path!
        let at_break = [TxPart::Chunk(ChunkSlice::new(&c, 0..512).unwrap())];
        assert_eq!(
            io.transmit_packet(
                &TxPacket {
                    header: &header,
                    payload: &at_break,
                },
                TransmitRequest::default()
            )
            .unwrap(),
            TxOutcome::Submitted
        );
        assert_eq!(chunk::chunk_refcnt(&c), 1);
        let m = unsafe { ntcp_test_tx_dequeue(&mut info, segs.as_mut_ptr(), 8) };
        assert_eq!(info.pkt_len, 54 + 512);
        for seg in &segs[..info.nb_segs as usize] {
            assert_eq!(seg.external, 0);
        }
        unsafe { ntcp_test_tx_free(m) };

        // Just above copybreak (513): extbuf zero-copy path!
        let over_break = [TxPart::Chunk(ChunkSlice::new(&c, 0..513).unwrap())];
        assert_eq!(
            io.transmit_packet(
                &TxPacket {
                    header: &header,
                    payload: &over_break,
                },
                TransmitRequest::default()
            )
            .unwrap(),
            TxOutcome::Submitted
        );
        assert_eq!(chunk::chunk_refcnt(&c), 2);
        let m = unsafe { ntcp_test_tx_dequeue(&mut info, segs.as_mut_ptr(), 8) };
        assert_eq!(info.nb_segs, 2);
        assert_eq!(segs[1].external, 1);
        assert_eq!(segs[1].data, c.as_ptr().cast());
        unsafe { ntcp_test_tx_free(m) };
        assert_eq!(chunk::chunk_refcnt(&c), 1);

        // Raising copybreak to 1024 moves 600-byte payload back to copy path.
        io.set_tx_copybreak(1024);
        assert_eq!(io.tx_copybreak(), 1024);
        let mid = [TxPart::Chunk(ChunkSlice::new(&c, 0..600).unwrap())];
        assert_eq!(
            io.transmit_packet(
                &TxPacket {
                    header: &header,
                    payload: &mid,
                },
                TransmitRequest::default()
            )
            .unwrap(),
            TxOutcome::Submitted
        );
        assert_eq!(chunk::chunk_refcnt(&c), 1);
        let m = unsafe { ntcp_test_tx_dequeue(&mut info, segs.as_mut_ptr(), 8) };
        for seg in &segs[..info.nb_segs as usize] {
            assert_eq!(seg.external, 0);
        }
        unsafe { ntcp_test_tx_free(m) };

        // Copy path also pads short (<60) non-TSO frames with trailing zeros
        // up to 60 bytes, matching the extbuf path.
        io.set_tx_copybreak(DEFAULT_TX_COPYBREAK);
        let short_hdr_only = [0x33u8; 54];
        assert_eq!(
            io.transmit_packet(
                &TxPacket {
                    header: &short_hdr_only,
                    payload: &[],
                },
                TransmitRequest::default()
            )
            .unwrap(),
            TxOutcome::Submitted
        );
        let m = unsafe { ntcp_test_tx_dequeue(&mut info, segs.as_mut_ptr(), 8) };
        assert_eq!(info.nb_segs, 1);
        assert_eq!(info.pkt_len, 60);
        assert_eq!(segs[0].external, 0);
        let mut wire = vec![0u8; 60];
        unsafe { ntcp_test_tx_read(m, wire.as_mut_ptr(), 60) };
        assert_eq!(&wire[..54], &short_hdr_only);
        assert_eq!(&wire[54..60], &[0u8; 6]);
        unsafe { ntcp_test_tx_free(m) };

        let short_hdr = [0x22u8; 34];
        let short_part = [TxPart::Chunk(ChunkSlice::new(&c, 10..20).unwrap())];
        assert_eq!(
            io.transmit_packet(
                &TxPacket {
                    header: &short_hdr,
                    payload: &short_part,
                },
                TransmitRequest::default()
            )
            .unwrap(),
            TxOutcome::Submitted
        );
        let m = unsafe { ntcp_test_tx_dequeue(&mut info, segs.as_mut_ptr(), 8) };
        assert_eq!(info.nb_segs, 1);
        assert_eq!(info.pkt_len, 60);
        assert_eq!(segs[0].external, 0);
        let mut wire = vec![0u8; 60];
        unsafe { ntcp_test_tx_read(m, wire.as_mut_ptr(), 60) };
        assert_eq!(&wire[..34], &short_hdr);
        assert_eq!(&wire[34..44], &data[10..20]);
        assert_eq!(&wire[44..60], &[0u8; 16]);
        unsafe { ntcp_test_tx_free(m) };

        // Lowering copybreak to 0 sends even short (<60) frames via extbuf + pad mbuf.
        io.set_tx_copybreak(0);
        assert_eq!(
            io.transmit_packet(
                &TxPacket {
                    header: &short_hdr,
                    payload: &short_part,
                },
                TransmitRequest::default()
            )
            .unwrap(),
            TxOutcome::Submitted
        );
        let m = unsafe { ntcp_test_tx_dequeue(&mut info, segs.as_mut_ptr(), 8) };
        assert_eq!(info.nb_segs, 3); // head (34) + ext (10) + zero pad (16) = 60
        assert_eq!(info.pkt_len, 60);
        assert_eq!(segs[1].external, 1);
        assert_eq!(segs[1].len, 10);
        assert_eq!(segs[2].external, 0);
        assert_eq!(segs[2].len, 16);
        let mut wire = vec![0u8; 60];
        unsafe { ntcp_test_tx_read(m, wire.as_mut_ptr(), 60) };
        assert_eq!(&wire[..34], &short_hdr);
        assert_eq!(&wire[34..44], &data[10..20]);
        assert_eq!(&wire[44..60], &[0u8; 16]);
        unsafe { ntcp_test_tx_free(m) };

        // I9: adjacent ChunkSlices from the same chunk merge (skipping empty parts).
        let merged_parts = [
            TxPart::Chunk(ChunkSlice::new(&c, 0..300).unwrap()),
            TxPart::Chunk(ChunkSlice::new(&c, 300..300).unwrap()),
            TxPart::Chunk(ChunkSlice::new(&c, 300..700).unwrap()),
            TxPart::Chunk(ChunkSlice::new(&c, 800..900).unwrap()),
        ];
        assert_eq!(
            io.transmit_packet(
                &TxPacket {
                    header: &header,
                    payload: &merged_parts,
                },
                TransmitRequest::default()
            )
            .unwrap(),
            TxOutcome::Submitted
        );
        assert_eq!(chunk::chunk_refcnt(&c), 3); // owner + 2 extbufs (NOT 3!)
        let m = unsafe { ntcp_test_tx_dequeue(&mut info, segs.as_mut_ptr(), 8) };
        assert_eq!(info.nb_segs, 3);
        assert_eq!(segs[1].external, 1);
        assert_eq!(segs[1].data, c.as_ptr().cast());
        assert_eq!(segs[1].len, 700);
        assert_eq!(segs[2].external, 1);
        assert_eq!(segs[2].data, unsafe { c.as_ptr().add(800) }.cast());
        assert_eq!(segs[2].len, 100);
        unsafe { ntcp_test_tx_free(m) };
        assert_eq!(chunk::chunk_refcnt(&c), 1);

        // Mixed DPDK Chunk + DPDK Shared (with sub-slice & release callback).
        let mut buf = unsafe { DpdkBuffer::allocate(2048) }.unwrap();
        for (i, b) in buf.as_mut_slice().iter_mut().enumerate() {
            *b = ((i * 7 + 3) % 251) as u8;
        }
        let buf_ptr = buf.as_ref().as_ptr();
        let released = Arc::new(AtomicUsize::new(0));
        let rel_clone = released.clone();
        let sub_payload = buf
            .freeze()
            .slice(100..900)
            .unwrap()
            .with_release(move || {
                rel_clone.fetch_add(1, Ordering::SeqCst);
            });
        let mixed = [
            TxPart::Chunk(ChunkSlice::new(&c, 0..400).unwrap()),
            TxPart::Shared(PayloadSlice::new(&sub_payload, 50..350).unwrap()),
        ];
        assert_eq!(
            io.transmit_packet(
                &TxPacket {
                    header: &header,
                    payload: &mixed,
                },
                TransmitRequest::default()
            )
            .unwrap(),
            TxOutcome::Submitted
        );
        drop(sub_payload); // Lease still held by TX mbuf!
        assert_eq!(released.load(Ordering::SeqCst), 0);
        let m = unsafe { ntcp_test_tx_dequeue(&mut info, segs.as_mut_ptr(), 8) };
        assert_eq!(info.nb_segs, 3);
        assert_eq!(segs[1].external, 1);
        assert_eq!(segs[1].data, c.as_ptr().cast());
        assert_eq!(segs[1].len, 400);
        assert_eq!(segs[2].external, 1);
        assert_eq!(segs[2].data, unsafe { buf_ptr.add(150) }.cast());
        assert_eq!(segs[2].len, 300);
        unsafe { ntcp_test_tx_free(m) };
        assert_eq!(released.load(Ordering::SeqCst), 1);

        // Non-DPDK part falls back cleanly to copy-into-mbuf path.
        let heap_payload = Payload::from_vec(vec![0x77; 200]);
        let fallback_parts = [
            TxPart::Chunk(ChunkSlice::new(&c, 0..100).unwrap()),
            TxPart::Shared(PayloadSlice::new(&heap_payload, 0..200).unwrap()),
        ];
        assert_eq!(
            io.transmit_packet(
                &TxPacket {
                    header: &header,
                    payload: &fallback_parts,
                },
                TransmitRequest::default()
            )
            .unwrap(),
            TxOutcome::Submitted
        );
        assert_eq!(chunk::chunk_refcnt(&c), 1);
        let m = unsafe { ntcp_test_tx_dequeue(&mut info, segs.as_mut_ptr(), 8) };
        assert_eq!(info.pkt_len, 54 + 300);
        for seg in &segs[..info.nb_segs as usize] {
            assert_eq!(seg.external, 0);
        }
        let mut wire = vec![0u8; info.pkt_len as usize];
        unsafe { ntcp_test_tx_read(m, wire.as_mut_ptr(), wire.len() as u32) };
        assert_eq!(&wire[54..154], &data[..100]);
        assert_eq!(&wire[154..354], &[0x77; 200]);
        unsafe { ntcp_test_tx_free(m) };

        // NOMBUF on extbuf path: returns WouldBlock, bumps tx_nombuf, restores refcnt & releases leases.
        let mut buf2 = unsafe { DpdkBuffer::allocate(1024) }.unwrap();
        buf2.as_mut_slice().fill(0x5c);
        let nombuf_rel = Arc::new(AtomicUsize::new(0));
        let nombuf_rel_c = nombuf_rel.clone();
        let p2 = buf2.freeze().with_release(move || {
            nombuf_rel_c.fetch_add(1, Ordering::SeqCst);
        });
        let nombuf_parts = [
            TxPart::Chunk(ChunkSlice::new(&c, 0..600).unwrap()),
            TxPart::Shared(PayloadSlice::new(&p2, 0..300).unwrap()),
        ];
        for leave in [0u32, 1, 2] {
            let before = io.device_counters().tx_nombuf;
            unsafe { ntcp_test_hold(leave) };
            assert_eq!(
                io.transmit_packet(
                    &TxPacket {
                        header: &header,
                        payload: &nombuf_parts,
                    },
                    TransmitRequest::default()
                )
                .unwrap(),
                TxOutcome::WouldBlock
            );
            assert_eq!(io.device_counters().tx_nombuf, before + 1);
            assert_eq!(chunk::chunk_refcnt(&c), 1);
            assert_eq!(unsafe { ntcp_test_available() }, leave);
            unsafe { ntcp_test_release() };
        }
        drop(p2);
        assert_eq!(nombuf_rel.load(Ordering::SeqCst), 1);

        io.set_tx_copybreak(DEFAULT_TX_COPYBREAK);
    }

    // 5. I8 combination error matrix + TSO / TCP checksum offload / TX scheduling.
    {
        let mut src = chunk::DpdkChunkSource::new(chunk::DEFAULT_DPDK_CHUNK_SIZE);
        let mut c = src.allocate().unwrap();
        let body: Vec<u8> = (0..2048).map(|i| ((i * 13) % 251) as u8).collect();
        c.append(&body);

        let clock = ClockDescriptor {
            domain: ClockDomain::Device(1),
            unit: TimestampUnit::Nanoseconds,
        };
        let when = Some(TransmitTime { value: 999, clock });
        let seg_req = Some(TcpSegmentationRequest {
            segment_payload_len: 500,
        });
        let ts_req = Some(TxTimestampRequest {
            cookie: 1,
            software: true,
            hardware: false,
        });
        let dummy_pkt = TxPacket {
            header: &[0u8; 64],
            payload: &[],
        };
        // Forbidden combinations (I8) all return Unsupported.
        for req in [
            TransmitRequest {
                segmentation: seg_req,
                when,
                ..Default::default()
            },
            TransmitRequest {
                segmentation: seg_req,
                timestamp: ts_req,
                ..Default::default()
            },
            TransmitRequest {
                tcp_checksum_offload: true,
                when,
                ..Default::default()
            },
            TransmitRequest {
                tcp_checksum_offload: true,
                timestamp: ts_req,
                ..Default::default()
            },
            TransmitRequest {
                timestamp: ts_req,
                ..Default::default()
            },
        ] {
            assert!(matches!(
                io.transmit_packet(&dummy_pkt, req),
                Err(TransmitError::Unsupported)
            ));
        }
        // Empty and oversized packets return InvalidInput.
        assert!(matches!(
            io.transmit_packet(
                &TxPacket {
                    header: &[],
                    payload: &[],
                },
                TransmitRequest::default()
            ),
            Err(TransmitError::InvalidInput)
        ));
        let huge = vec![0u8; MAX_PACKET_LEN + 1];
        assert!(matches!(
            io.transmit_packet(
                &TxPacket {
                    header: &huge,
                    payload: &[],
                },
                TransmitRequest::default()
            ),
            Err(TransmitError::InvalidInput)
        ));

        // TSO over extbuf (> copybreak) and copy (<= copybreak), IPv4 and IPv6,
        // both with and without tcp_checksum_offload: true.
        assert!(matches!(
            io.transmit_packet(
                &dummy_pkt,
                TransmitRequest {
                    segmentation: seg_req,
                    ..Default::default()
                }
            ),
            Err(TransmitError::Unsupported)
        ));
        io.tso = Some(TsoConfig {
            mtu: 1500,
            room: 128,
            max_descriptors: 512,
        });
        for v6 in [false, true] {
            let l3 = if v6 { 40u32 } else { 20 };
            let l4 = 32usize;
            for (payload_len, expect_ext, cksum_flag) in
                [(1200usize, true, true), (400usize, false, false)]
            {
                let hdr = build_tcp_header(v6, l4, payload_len, true);
                let parts = [
                    TxPart::Chunk(ChunkSlice::new(&c, 0..payload_len / 2).unwrap()),
                    TxPart::Chunk(ChunkSlice::new(&c, payload_len / 2..payload_len).unwrap()),
                ];
                let pkt = TxPacket {
                    header: &hdr,
                    payload: &parts,
                };
                assert_eq!(
                    io.transmit_packet(
                        &pkt,
                        TransmitRequest {
                            tcp_checksum_offload: cksum_flag,
                            segmentation: Some(TcpSegmentationRequest {
                                segment_payload_len: 300,
                            }),
                            ..Default::default()
                        }
                    )
                    .unwrap(),
                    TxOutcome::Submitted
                );
                let mut info = TestTxInfo::default();
                let mut segs = [TestTxSeg::default(); 8];
                let m = unsafe { ntcp_test_tx_dequeue(&mut info, segs.as_mut_ptr(), 8) };
                assert!(!m.is_null());
                unsafe {
                    ntcp_test_tx_verify_tso(
                        m,
                        l3,
                        l4 as u32,
                        300,
                        (hdr.len() + payload_len) as u32,
                    );
                }
                if expect_ext {
                    // I9 merged the two adjacent halves into 1 extbuf!
                    assert_eq!(info.nb_segs, 2);
                    assert_eq!(segs[1].external, 1);
                    assert_eq!(segs[1].data, c.as_ptr().cast());
                    assert_eq!(segs[1].len, payload_len as u16);
                } else {
                    for seg in &segs[..info.nb_segs as usize] {
                        assert_eq!(seg.external, 0);
                    }
                }
                unsafe { ntcp_test_tx_free(m) };
            }
            // Truncated TSO header is rejected before submitting without copying payload.
            let hdr = build_tcp_header(v6, l4, 1000, true);
            let bad_parts = [TxPart::Chunk(ChunkSlice::new(&c, 0..1000).unwrap())];
            assert!(matches!(
                io.transmit_packet(
                    &TxPacket {
                        header: &hdr[..hdr.len() - 4],
                        payload: &bad_parts,
                    },
                    TransmitRequest {
                        segmentation: Some(TcpSegmentationRequest {
                            segment_payload_len: 300,
                        }),
                        ..Default::default()
                    }
                ),
                Err(TransmitError::InvalidInput)
            ));
        }
        io.tso = None;

        // TX TCP checksum offload on both extbuf (> copybreak) and copy (<= copybreak).
        assert!(matches!(
            io.transmit_packet(
                &dummy_pkt,
                TransmitRequest {
                    tcp_checksum_offload: true,
                    ..Default::default()
                }
            ),
            Err(TransmitError::Unsupported)
        ));
        io.tx_checksum = true;
        for v6 in [false, true] {
            for (payload_len, expect_ext) in [(700usize, true), (200usize, false)] {
                let hdr = build_tcp_header(v6, 20, payload_len, false);
                let parts = [TxPart::Chunk(ChunkSlice::new(&c, 0..payload_len).unwrap())];
                assert_eq!(
                    io.transmit_packet(
                        &TxPacket {
                            header: &hdr,
                            payload: &parts,
                        },
                        TransmitRequest {
                            tcp_checksum_offload: true,
                            ..Default::default()
                        }
                    )
                    .unwrap(),
                    TxOutcome::Submitted
                );
                let mut info = TestTxInfo::default();
                let mut segs = [TestTxSeg::default(); 8];
                let m = unsafe { ntcp_test_tx_dequeue(&mut info, segs.as_mut_ptr(), 8) };
                assert!(!m.is_null());
                if expect_ext {
                    assert_eq!(info.nb_segs, 2);
                    assert_eq!(segs[1].external, 1);
                } else {
                    for seg in &segs[..info.nb_segs as usize] {
                        assert_eq!(seg.external, 0);
                    }
                }
                let mut wire = vec![0u8; info.pkt_len as usize];
                unsafe { ntcp_test_tx_verify_checksum(m, wire.as_mut_ptr(), wire.len() as u32) };
                unsafe { ntcp_test_tx_free(m) };
            }
        }
        io.tx_checksum = false;

        // TX scheduling (`request.when`) on both extbuf and copy paths.
        assert!(matches!(
            io.transmit_packet(
                &dummy_pkt,
                TransmitRequest {
                    when,
                    ..Default::default()
                }
            ),
            Err(TransmitError::Unsupported)
        ));
        // TX timestamp dynfield/flag were already registered above.
        let (mut ts_off, mut ts_flag) = (-1, 0);
        assert_eq!(
            unsafe { ntcp_dpdk_tx_timestamp_lookup(&mut ts_off, &mut ts_flag) },
            0
        );
        io.tx_scheduling = Some(TimestampConfig {
            clock,
            offset: ts_off,
            flag: ts_flag,
        });
        let wrong_clock = ClockDescriptor {
            domain: ClockDomain::Device(99),
            unit: TimestampUnit::Nanoseconds,
        };
        assert!(matches!(
            io.transmit_packet(
                &dummy_pkt,
                TransmitRequest {
                    when: Some(TransmitTime {
                        value: 1,
                        clock: wrong_clock,
                    }),
                    ..Default::default()
                }
            ),
            Err(TransmitError::InvalidInput)
        ));
        for (payload_len, expect_ext) in [(640usize, true), (64usize, false)] {
            let hdr = [0x33u8; 54];
            let parts = [TxPart::Chunk(ChunkSlice::new(&c, 0..payload_len).unwrap())];
            assert_eq!(
                io.transmit_packet(
                    &TxPacket {
                        header: &hdr,
                        payload: &parts,
                    },
                    TransmitRequest {
                        when: Some(TransmitTime {
                            value: 0x1234_5678,
                            clock,
                        }),
                        ..Default::default()
                    }
                )
                .unwrap(),
                TxOutcome::Submitted
            );
            let mut info = TestTxInfo::default();
            let mut segs = [TestTxSeg::default(); 8];
            let m = unsafe { ntcp_test_tx_dequeue(&mut info, segs.as_mut_ptr(), 8) };
            assert!(!m.is_null());
            assert_eq!(info.has_timestamp, 1);
            assert_eq!(info.timestamp, 0x1234_5678);
            assert_eq!(info.nb_segs == 2 && segs[1].external == 1, expect_ext);
            unsafe { ntcp_test_tx_free(m) };
        }
        io.tx_scheduling = None;
    }

    io.shared_limit = None;
    assert_eq!(unsafe { ntcp_test_available() }, 1023);
    assert_eq!(chunk::live_dpdk_chunks(), 0);
}

// End-to-end ntcp-native over Dpdk with DpdkChunkSource + transmit_packet:
// exercises (a) small scalar writes (<= 512 B copybreak path, no extbuf),
// (b) large scalar writes (> 512 B single-MSS extbuf zero-copy path), and
// (c) multi-MSS TSO aggregates over extbuf, verifying bit-exact delivery and
// zero mbuf or EAL chunk leaks.
unsafe fn dpdk_chunk_source_network(mut io: Dpdk) {
    use ntcp_native::{
        EthernetNextHop, Link, Network, NetworkConfig, ReadOutcome, WorkBudget, WriteOptions,
    };
    // Enable multi-seg extbuf + DpdkChunkSource and TSO in this private test
    // fixture (ring PMD does not expose tx_queue_info_get or TSO caps).
    io.shared_limit = Some(8);
    io.tso = Some(TsoConfig {
        mtu: 1500,
        room: 128,
        max_descriptors: 512,
    });
    let link = |side: u8| Link::Ethernet {
        local_mac: [2, 0, 0, 0, 0, side],
        next_hop: EthernetNextHop::Fixed([2, 0, 0, 0, 0, 3 - side]),
    };
    let config = |address: &str, side: u8| {
        let mut config = NetworkConfig::new(address.parse().unwrap(), 1500);
        config.tcp.max_connections = 2;
        config.tcp.connection.send_capacity = 256 * 1024;
        config.tcp.connection.receive_capacity = 256 * 1024;
        config.tcp.connection.nagle = false;
        config.link = link(side);
        config
    };
    let headroom = |config: &NetworkConfig| 2 * (72 * config.tcp.connection.send_capacity + 65536);
    let mut ca = config("10.76.0.1", 1);
    ca.tcp.max_buffer_bytes = ca.buffer_budget(2, &io).unwrap() + headroom(&ca);
    let incoming = Rc::new(RefCell::new(VecDeque::new()));
    let outgoing = Rc::new(RefCell::new(VecDeque::new()));
    let peer = Peer {
        incoming: incoming.clone(),
        outgoing: outgoing.clone(),
    };
    let mut cb = config("10.76.0.2", 2);
    cb.tcp.max_buffer_bytes = cb.buffer_budget(2, &peer).unwrap() + headroom(&cb);

    let mut a = Network::new(ca, io, [3; 32], 0).unwrap();
    let mut b = Network::new(cb, peer, [4; 32], 0).unwrap();
    let listener = b.listen(9100, 1).unwrap();
    let client = a.connect("10.76.0.2:9100".parse().unwrap()).unwrap();

    // Planned writes:
    // - 4 small writes <= 512 B (copybreak path)
    // - 4 large single-MSS writes > 512 B (scalar extbuf zero-copy path)
    // - 1 bulk 48 KiB write (TSO extbuf zero-copy path)
    let write_sizes: &[usize] = &[64, 180, 320, 500, 900, 1100, 1300, 1400, 48 * 1024];
    let total_len: usize = write_sizes.iter().sum();
    let expected: Vec<u8> = (0..total_len).map(|i| ((i * 19 + 5) % 251) as u8).collect();

    // Ring PMD lacks `rte_eth_tx_done_cleanup` (normal `enable_zero_copy`
    // rejects it; this private fixture injects `shared_limit` directly), so
    // drive with `reclaim = 0` while dequeuing/freeing TX mbufs explicitly.
    let budget = WorkBudget::new(64, 64, 64, 0);
    let mut server = None;
    let mut received = Vec::with_capacity(total_len);
    let mut out = vec![0u8; 65536];
    let mut wire = vec![0u8; MAX_PACKET_LEN];
    let mut backlog = VecDeque::new();

    let mut phase = 0usize;
    let mut written_total = 0usize;
    let mut phase_target = 0usize;
    let mut small_copy_segs = 0usize;
    let mut large_ext_scalar_segs = 0usize;
    let mut tso_ext_aggregates = 0usize;

    for step in 1..20_000u64 {
        let now = step * 1000;
        // Start next write once the peer has received the previous phase, so
        // small and large scalar writes are never coalesced across phases.
        if server.is_some() && phase < write_sizes.len() && received.len() == phase_target {
            let chunk_len = write_sizes[phase];
            if let Ok(receipt) = a.try_write(
                client,
                &expected[written_total..written_total + chunk_len],
                WriteOptions::default(),
            ) {
                assert_eq!(receipt.accepted, chunk_len);
                written_total += chunk_len;
                phase_target = written_total;
                phase += 1;
            }
        }
        a.drive(now, budget).unwrap();
        loop {
            let mut info = TestTxInfo::default();
            let mut segs = [TestTxSeg::default(); 16];
            let m = unsafe { ntcp_test_tx_dequeue(&mut info, segs.as_mut_ptr(), 16) };
            if m.is_null() {
                break;
            }
            let pkt_len = info.pkt_len as usize;
            let got = unsafe { ntcp_test_tx_read(m, wire.as_mut_ptr(), pkt_len as u32) };
            assert_eq!(got as usize, pkt_len);
            let frame = &wire[..pkt_len];
            let has_ext = segs[..info.nb_segs as usize]
                .iter()
                .any(|s| s.external != 0);
            if info.tso_segsz > 0 {
                assert!(
                    has_ext,
                    "TSO aggregate ({pkt_len}B) should attach DpdkChunkSource extbufs"
                );
                tso_ext_aggregates += 1;
                incoming
                    .borrow_mut()
                    .extend(cut(frame, info.tso_segsz as usize));
            } else {
                if pkt_len >= 54 && frame[12..14] == [0x08, 0x00] && frame[23] == 6 {
                    let ip_hdr = usize::from(frame[14] & 0x0f) * 4;
                    let ip_total = u16::from_be_bytes([frame[16], frame[17]]) as usize;
                    let tcp_hdr = usize::from(frame[14 + ip_hdr + 12] >> 4) * 4;
                    let tcp_payload = ip_total.saturating_sub(ip_hdr + tcp_hdr);
                    if tcp_payload > 0 && tcp_payload <= DEFAULT_TX_COPYBREAK {
                        assert!(
                            !has_ext,
                            "small scalar ({tcp_payload}B <= copybreak) must use copy path"
                        );
                        small_copy_segs += 1;
                    } else if tcp_payload > DEFAULT_TX_COPYBREAK {
                        assert!(
                            has_ext,
                            "large scalar ({tcp_payload}B > copybreak) must attach DpdkChunkSource extbuf"
                        );
                        large_ext_scalar_segs += 1;
                    }
                }
                incoming.borrow_mut().push_back(frame.to_vec());
            }
            unsafe { ntcp_test_tx_free(m) };
        }
        b.drive(now, budget).unwrap();
        backlog.extend(outgoing.borrow_mut().drain(..));
        while let Some(pkt) = backlog.front() {
            if unsafe { ntcp_test_inject(pkt.as_ptr(), pkt.len() as u32) } != 0 {
                break;
            }
            backlog.pop_front();
        }
        if server.is_none() {
            server = b.accept(listener).ok();
        }
        if let Some(srv) = server {
            while let Ok(ReadOutcome::Data { len, .. }) = b.try_read(srv, &mut out) {
                received.extend_from_slice(&out[..len]);
            }
        }
        if received.len() == total_len {
            break;
        }
    }

    assert_eq!(received, expected);
    assert_eq!(b.counters().tcp_checksum_errors, 0);
    assert!(
        small_copy_segs >= 4,
        "expected >=4 copybreak segments, got {small_copy_segs}"
    );
    assert!(
        large_ext_scalar_segs >= 4,
        "expected >=4 extbuf scalar segments, got {large_ext_scalar_segs}"
    );
    assert!(
        tso_ext_aggregates >= 1,
        "expected >=1 extbuf TSO aggregates, got {tso_ext_aggregates}"
    );

    // Drain any residual frames on the rings before drop.
    for step in 0..4 {
        a.drive(30_000_000 + step, budget).unwrap();
        let mut info = TestTxInfo::default();
        let mut segs = [TestTxSeg::default(); 16];
        loop {
            let m = unsafe { ntcp_test_tx_dequeue(&mut info, segs.as_mut_ptr(), 16) };
            if m.is_null() {
                break;
            }
            unsafe { ntcp_test_tx_free(m) };
        }
    }
    drop(a);
    drop(b);
    assert_eq!(unsafe { ntcp_test_available() }, 1023);
    assert_eq!(chunk::live_dpdk_chunks(), 0);
}
