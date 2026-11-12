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
            for leave in [0, 1, 2] {
                ntcp_test_hold(leave);
                assert_eq!(
                    io.transmit_segmented(&packet, request).unwrap(),
                    TxOutcome::WouldBlock
                );
                assert_eq!(ntcp_test_available(), leave);
                ntcp_test_release();
            }
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
        for leave in [0, 1] {
            ntcp_test_hold(leave);
            assert_eq!(
                io.transmit_at(&[7; 129], when, None).unwrap(),
                TxOutcome::WouldBlock
            );
            assert_eq!(ntcp_test_available(), leave);
            ntcp_test_release();
        }
        // Recycled mbufs do not retain the launch flag for ordinary transmit.
        assert_eq!(io.transmit(&[7; 64]).unwrap(), TxOutcome::Submitted);
        ntcp_test_loopback(); // Asserts every segment has zero offload flags.
        assert_eq!(io.receive(&mut [0; 64]).unwrap(), Some(64));
        assert_eq!(ntcp_test_available(), 1023);
        io.tx_scheduling = None;
        segmented_network(io);
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
// as a device would for a software peer; the pool's room for a whole
// aggregate runs out and blocks it until the ring drains. The stream
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
    let mut ca = config("10.74.0.1", 1);
    ca.tx_timestamp_phases = 64;
    ca.tcp.max_buffer_bytes = ca.buffer_budget(2, &io).unwrap();
    let incoming = Rc::new(RefCell::new(VecDeque::new()));
    let outgoing = Rc::new(RefCell::new(VecDeque::new()));
    let peer = Peer {
        incoming: incoming.clone(),
        outgoing: outgoing.clone(),
    };
    let mut cb = config("10.74.0.2", 2);
    cb.tcp.max_buffer_bytes = cb.buffer_budget(2, &peer).unwrap();
    let mut a = Network::new(ca, io, [1; 32], 0).unwrap();
    let mut b = Network::new(cb, peer, [2; 32], 0).unwrap();
    let listener = b.listen(9000, 1).unwrap();
    let client = a.connect("10.74.0.2:9000".parse().unwrap()).unwrap();
    let data: Vec<u8> = (0..300_000).map(|i| (i * 7 % 251) as u8).collect();
    let budget = WorkBudget::new(64, 64, 64, 64);
    let (mut server, mut sent, mut received) = (None, 0, Vec::new());
    let (mut frame, mut out) = (vec![0; MAX_PACKET_LEN], vec![0; 65536]);
    let (mut aggregates, mut blocked) = (0, 0);
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
