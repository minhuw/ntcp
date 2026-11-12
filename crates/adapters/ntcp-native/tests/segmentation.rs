// A backend that segments TCP aggregates (TSO): the aggregates a Network
// submits, the segments the backend cuts from them, and what falls back to
// one segment at a time.
use ntcp_io::{
    PacketIo, PacketLayer, TcpSegmentationCapabilities, TcpSegmentationError,
    TcpSegmentationRequest, TxOutcome,
};
use ntcp_native::*;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    rc::Rc,
};

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Segment,
    Block,
    Unsupported,
    InvalidInput,
}

// One aggregate as the backend received it.
#[derive(Clone, Debug)]
struct Aggregate {
    frame: Vec<u8>,
    segment_payload_len: usize,
    submitted: bool,
}

#[derive(Clone)]
struct Wire {
    incoming: Queue,
    outgoing: Queue,
    layer: PacketLayer,
    capabilities: Option<TcpSegmentationCapabilities>,
    mode: Rc<Cell<Mode>>,
    aggregates: Rc<RefCell<Vec<Aggregate>>>,
    // Frames handed to the peer: scalar ones and cut segments.
    frames: Rc<Cell<usize>>,
    // Cut segments with payload, and those of them to lose.
    cut: Rc<Cell<usize>>,
    lose: Rc<RefCell<Vec<usize>>>,
    // The sequence number of every data segment sent, lost or not.
    sent: Rc<RefCell<Vec<u32>>>,
}
impl Wire {
    fn record(&self, frame: &[u8]) {
        let (_, tcp, payload) = layout(frame, self.layer);
        let ip = l2(self.layer);
        let end = if frame[ip] >> 4 == 4 {
            ip + usize::from(u16::from_be_bytes([frame[ip + 2], frame[ip + 3]]))
        } else {
            ip + 40 + usize::from(u16::from_be_bytes([frame[ip + 4], frame[ip + 5]]))
        };
        if end > payload {
            let sequence = u32::from_be_bytes(frame[tcp + 4..tcp + 8].try_into().unwrap());
            self.sent.borrow_mut().push(sequence);
        }
    }
    // Data segments sent again.
    fn retransmitted(&self) -> usize {
        let mut sent = self.sent.borrow().clone();
        let all = sent.len();
        sent.sort_unstable();
        sent.dedup();
        all - sent.len()
    }
    fn deliver(&self, frame: Vec<u8>) {
        self.frames.set(self.frames.get() + 1);
        self.outgoing.borrow_mut().push_back(frame);
    }
}
impl PacketIo for Wire {
    fn layer(&self) -> PacketLayer {
        self.layer
    }
    fn max_packet_len(&self) -> Option<usize> {
        Some(65589)
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        let Some(packet) = self.incoming.borrow_mut().pop_front() else {
            return Ok(None);
        };
        out[..packet.len()].copy_from_slice(&packet);
        Ok(Some(packet.len()))
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        assert!(packet.len() <= 1500 + l2(self.layer));
        self.record(packet);
        self.deliver(packet.to_vec());
        Ok(TxOutcome::Submitted)
    }
    fn tcp_segmentation_capabilities(&self) -> Option<TcpSegmentationCapabilities> {
        self.capabilities
    }
    fn transmit_segmented(
        &mut self,
        packet: &[u8],
        request: TcpSegmentationRequest,
    ) -> std::result::Result<TxOutcome, TcpSegmentationError> {
        let capabilities = self.capabilities.expect("only offered with capabilities");
        let mode = self.mode.get();
        self.aggregates.borrow_mut().push(Aggregate {
            frame: packet.to_vec(),
            segment_payload_len: request.segment_payload_len,
            submitted: mode == Mode::Segment,
        });
        match mode {
            Mode::Segment => {}
            Mode::Block => return Ok(TxOutcome::WouldBlock),
            Mode::Unsupported => return Err(TcpSegmentationError::Unsupported),
            Mode::InvalidInput => return Err(TcpSegmentationError::InvalidInput),
        }
        assert!(packet.len() <= capabilities.max_aggregate_len);
        // Both checksums are the backend's, as DPDK requires.
        let (ip, tcp, _) = layout(packet, self.layer);
        assert_eq!(packet[tcp + 16..tcp + 18], [0, 0]);
        if packet[ip] >> 4 == 4 {
            assert_eq!(packet[ip + 10..ip + 12], [0, 0]);
        }
        for segment in cut(packet, self.layer, request.segment_payload_len) {
            let n = self.cut.get();
            self.cut.set(n + 1);
            self.record(&segment);
            if self.lose.borrow().contains(&n) {
                continue;
            }
            self.deliver(segment);
        }
        Ok(TxOutcome::Submitted)
    }
}

fn l2(layer: PacketLayer) -> usize {
    if layer == PacketLayer::Ethernet {
        14
    } else {
        0
    }
}
fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in header.chunks(2) {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
fn addresses(frame: &[u8], ip: usize) -> ntcp::IpMetadata {
    if frame[ip] >> 4 == 4 {
        ntcp::IpMetadata {
            source: IpAddr::from(<[u8; 4]>::try_from(&frame[ip + 12..ip + 16]).unwrap()),
            destination: IpAddr::from(<[u8; 4]>::try_from(&frame[ip + 16..ip + 20]).unwrap()),
        }
    } else {
        ntcp::IpMetadata {
            source: IpAddr::from(<[u8; 16]>::try_from(&frame[ip + 8..ip + 24]).unwrap()),
            destination: IpAddr::from(<[u8; 16]>::try_from(&frame[ip + 24..ip + 40]).unwrap()),
        }
    }
}
// The offsets of the IP header, the TCP header and the payload.
fn layout(frame: &[u8], layer: PacketLayer) -> (usize, usize, usize) {
    let ip = l2(layer);
    let tcp = ip + if frame[ip] >> 4 == 4 { 20 } else { 40 };
    (ip, tcp, tcp + usize::from(frame[tcp + 12] >> 4) * 4)
}
// The segments a device cuts from an aggregate, as Linux tcp_gso_segment
// does: headers repeated, the sequence advanced, PSH and FIN on the last
// segment only, CWR on the first only, every length and checksum filled.
fn cut(frame: &[u8], layer: PacketLayer, mss: usize) -> Vec<Vec<u8>> {
    let (ip, tcp, payload) = layout(frame, layer);
    let data = &frame[payload..];
    let count = data.len().div_ceil(mss);
    let sequence = u32::from_be_bytes(frame[tcp + 4..tcp + 8].try_into().unwrap());
    (0..count)
        .map(|n| {
            let chunk = &data[n * mss..((n + 1) * mss).min(data.len())];
            let mut s = frame[..payload].to_vec();
            s.extend_from_slice(chunk);
            let tcp_len = s.len() - tcp;
            if s[ip] >> 4 == 4 {
                let len = (s.len() - ip) as u16;
                s[ip + 2..ip + 4].copy_from_slice(&len.to_be_bytes());
                s[ip + 10..ip + 12].fill(0);
                let sum = ip_checksum(&s[ip..tcp]);
                s[ip + 10..ip + 12].copy_from_slice(&sum.to_be_bytes());
            } else {
                s[ip + 4..ip + 6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
            }
            s[tcp + 4..tcp + 8]
                .copy_from_slice(&sequence.wrapping_add((n * mss) as u32).to_be_bytes());
            if n + 1 != count {
                s[tcp + 13] &= !0x09;
            }
            if n != 0 {
                s[tcp + 13] &= !0x80;
            }
            let sum = ntcp::wire::checksum(addresses(&s, ip), &s[tcp..]).unwrap();
            s[tcp + 16..tcp + 18].copy_from_slice(&sum.to_be_bytes());
            if layer == PacketLayer::Ethernet && s.len() < 60 {
                s.resize(60, 0);
            }
            s
        })
        .collect()
}

// A DPDK port's: aggregates of up to 64 KiB and 64 segments, no PSH or CWR.
fn dpdk() -> TcpSegmentationCapabilities {
    TcpSegmentationCapabilities {
        max_aggregate_len: 65535,
        max_segments: 64,
        max_wire_bytes: 65535 + 63 * 114,
        local_ip_mtu: 1500,
        allow_psh: false,
        allow_cwr: false,
    }
}
fn wires(layer: PacketLayer, capabilities: Option<TcpSegmentationCapabilities>) -> (Wire, Wire) {
    let a = Rc::new(RefCell::new(VecDeque::new()));
    let b = Rc::new(RefCell::new(VecDeque::new()));
    let make = |incoming, outgoing| Wire {
        incoming,
        outgoing,
        layer,
        capabilities,
        mode: Rc::new(Cell::new(Mode::Segment)),
        aggregates: Rc::new(RefCell::new(Vec::new())),
        frames: Rc::new(Cell::new(0)),
        cut: Rc::new(Cell::new(0)),
        lose: Rc::new(RefCell::new(Vec::new())),
        sent: Rc::new(RefCell::new(Vec::new())),
    };
    (make(a.clone(), b.clone()), make(b, a))
}
fn config(address: IpAddr, ethernet: bool, side: u8) -> NetworkConfig {
    let mut config = NetworkConfig::new(address, 1500);
    config.tcp.max_connections = 4;
    config.tcp.max_listeners = 1;
    config.tcp.connection.send_capacity = 256 * 1024;
    config.tcp.connection.receive_capacity = 256 * 1024;
    if ethernet {
        config.link = Link::Ethernet {
            local_mac: [2, 0, 0, 0, 0, side],
            next_hop: EthernetNextHop::Fixed([2, 0, 0, 0, 0, 3 - side]),
        };
    }
    config
}
const BUDGET: WorkBudget = WorkBudget::new(64, 64, 64, 64);

struct Pair {
    a: Network<Wire>,
    b: Network<Wire>,
    wire: Wire,
    client: ConnId,
    server: ConnId,
    now: u64,
}
impl Pair {
    fn new(ipv6: bool, ethernet: bool, capabilities: Option<TcpSegmentationCapabilities>) -> Self {
        Self::with(ipv6, ethernet, capabilities, |_| {})
    }
    fn with(
        ipv6: bool,
        ethernet: bool,
        capabilities: Option<TcpSegmentationCapabilities>,
        adjust: impl Fn(&mut NetworkConfig),
    ) -> Self {
        let (ip_a, ip_b): (IpAddr, IpAddr) = if ipv6 {
            (
                "2001:db8::1".parse().unwrap(),
                "2001:db8::2".parse().unwrap(),
            )
        } else {
            ("10.73.0.1".parse().unwrap(), "10.73.0.2".parse().unwrap())
        };
        let layer = if ethernet {
            PacketLayer::Ethernet
        } else {
            PacketLayer::Ip
        };
        let (wa, wb) = wires(layer, capabilities);
        let wire = wa.clone();
        let mut ca = config(ip_a, ethernet, 1);
        let mut cb = config(ip_b, ethernet, 2);
        adjust(&mut ca);
        adjust(&mut cb);
        ca.tcp.max_buffer_bytes = ca.buffer_budget(4, &wa).unwrap();
        cb.tcp.max_buffer_bytes = cb.buffer_budget(4, &wb).unwrap();
        let mut a = Network::new(ca, wa, [1; 32], 0).unwrap();
        let mut b = Network::new(cb, wb, [2; 32], 0).unwrap();
        let listener = b.listen(9000, 4).unwrap();
        let client = a.connect(SocketAddr::new(ip_b, 9000)).unwrap();
        for now in 1..1000u64 {
            a.drive(now * 100, BUDGET).unwrap();
            b.drive(now * 100, BUDGET).unwrap();
            if let Ok(server) = b.accept(listener) {
                return Self {
                    a,
                    b,
                    wire,
                    client,
                    server,
                    now: now * 100,
                };
            }
        }
        panic!("handshake did not finish");
    }
    fn step(&mut self) {
        self.now += 10_000;
        self.a.drive(self.now, BUDGET).unwrap();
        self.b.drive(self.now, BUDGET).unwrap();
    }
    // Writes `data` from client to server and reads it back.
    fn transfer(&mut self, data: &[u8]) -> Vec<u8> {
        let (mut sent, mut received) = (0, Vec::new());
        let mut out = vec![0; 65536];
        for _ in 0..20_000 {
            if sent < data.len() {
                match self
                    .a
                    .try_write(self.client, &data[sent..], WriteOptions::default())
                {
                    Ok(receipt) => sent += receipt.accepted,
                    Err(error) if error.is_would_block() => {}
                    Err(error) => panic!("write: {error:?}"),
                }
            }
            self.step();
            loop {
                match self.b.try_read(self.server, &mut out) {
                    Ok(ReadOutcome::Data { len, .. }) => received.extend_from_slice(&out[..len]),
                    Err(error) if error.is_would_block() => break,
                    other => panic!("read: {other:?}"),
                }
            }
            if received.len() == data.len() {
                return received;
            }
        }
        panic!(
            "transfer did not finish: {} of {}",
            received.len(),
            data.len()
        );
    }
}
fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

// Every aggregate is a whole number of full segments of the size the
// backend is asked to cut, at least two and within the backend's bounds;
// its checksum fields (IPv4 header, TCP) are zero, its only flag ACK (this backend places
// neither PSH nor CWR), its IP length covers it all and each segment fits
// the MTU. The stream arrives whole, and the counters count the segments.
#[test]
fn aggregates_carry_full_segments_the_backend_cuts_into_the_stream() {
    for ipv6 in [false, true] {
        for ethernet in [false, true] {
            let mut pair = Pair::new(ipv6, ethernet, Some(dpdk()));
            let layer = pair.wire.layer;
            let frames = pair.wire.frames.get();
            let data = data(600_000);
            assert_eq!(
                pair.transfer(&data),
                data,
                "ipv6={ipv6} ethernet={ethernet}"
            );
            let aggregates = pair.wire.aggregates.borrow();
            assert!(aggregates.len() >= 10, "{}", aggregates.len());
            let mut largest = 0;
            for aggregate in aggregates.iter() {
                let frame = &aggregate.frame;
                let (ip, tcp, payload) = layout(frame, layer);
                let mss = aggregate.segment_payload_len;
                let len = frame.len() - payload;
                assert!(len.is_multiple_of(mss) && len / mss >= 2, "{len} {mss}");
                assert!(len / mss <= 64 && frame.len() <= 65535);
                assert!(payload - ip + mss <= 1500);
                // Timestamps on every segment.
                assert_eq!(payload - tcp, 32);
                assert_eq!(frame[tcp + 13], 0x10);
                assert_eq!(frame[tcp + 16..tcp + 18], [0, 0]);
                let ip_len = if ipv6 {
                    usize::from(u16::from_be_bytes([frame[ip + 4], frame[ip + 5]])) + 40
                } else {
                    assert_eq!(frame[ip + 10..ip + 12], [0, 0]);
                    assert_eq!(frame[ip + 6] & 0x40, 0x40);
                    usize::from(u16::from_be_bytes([frame[ip + 2], frame[ip + 3]]))
                };
                assert_eq!(ip_len, frame.len() - ip);
                largest = largest.max(len / mss);
            }
            assert!(largest > 10, "{largest}");
            let counters = pair.a.counters();
            assert_eq!(counters.segmented as usize, aggregates.len());
            assert_eq!(counters.segmentation_refused, 0);
            assert_eq!(
                counters.transmitted as usize,
                pair.wire.frames.get(),
                "segments, not aggregates"
            );
            assert!(pair.wire.frames.get() - frames > aggregates.len() * 2);
        }
    }
}

// Segments lost from aggregates are recovered like any other: the stream
// still arrives whole, and aggregates keep forming after recovery.
#[test]
fn segments_lost_from_aggregates_are_retransmitted() {
    for ipv6 in [false, true] {
        let mut pair = Pair::new(ipv6, true, Some(dpdk()));
        pair.wire
            .lose
            .borrow_mut()
            .extend([3, 4, 30, 31, 32, 100, 250]);
        let data = data(800_000);
        assert_eq!(pair.transfer(&data), data);
        let lost = pair.wire.lose.borrow().len();
        assert!(pair.wire.cut.get() > 250);
        assert!(pair.wire.retransmitted() >= lost);
        assert!(pair.a.counters().segmented > 20);
    }
}

// A backend that refuses every aggregate certifies that nothing was sent:
// each refused aggregate's segments go out one at a time, and the stream
// arrives whole.
#[test]
fn refused_aggregates_fall_back_to_one_segment_at_a_time() {
    for mode in [Mode::Unsupported, Mode::InvalidInput] {
        let mut pair = Pair::new(false, true, Some(dpdk()));
        pair.wire.mode.set(mode);
        let data = data(200_000);
        assert_eq!(pair.transfer(&data), data);
        let counters = pair.a.counters();
        assert_eq!(counters.segmented, 0);
        assert!(counters.segmentation_refused > 0);
        assert_eq!(
            counters.segmentation_refused as usize,
            pair.wire.aggregates.borrow().len()
        );
        assert_eq!(pair.wire.cut.get(), 0);
        assert!(pair.wire.frames.get() as u64 >= 200_000 / 1448);
    }
}

// While the backend blocks, the same aggregate is offered again on every
// drive, unchanged, and nothing else of its connection goes out; once the
// backend takes it, it is sent once.
#[test]
fn a_blocked_aggregate_is_retried_unchanged() {
    let mut pair = Pair::new(false, true, Some(dpdk()));
    pair.wire.mode.set(Mode::Block);
    let data = data(100_000);
    let accepted = pair
        .a
        .try_write(pair.client, &data, WriteOptions::default())
        .unwrap()
        .accepted;
    let frames = pair.wire.frames.get();
    for _ in 0..5 {
        pair.step();
    }
    let blocked = pair.wire.aggregates.borrow().clone();
    assert!(blocked.len() >= 5);
    assert!(blocked.iter().all(|a| a.frame == blocked[0].frame));
    assert_eq!(pair.wire.frames.get(), frames);
    assert!(pair.a.counters().backend_backpressure >= 5);
    pair.wire.mode.set(Mode::Segment);
    pair.step();
    let aggregates = pair.wire.aggregates.borrow().clone();
    let first = aggregates.iter().find(|a| a.submitted).unwrap();
    assert_eq!(first.frame, blocked[0].frame);
    let mut received = vec![0; accepted];
    let mut read = 0;
    for _ in 0..1000 {
        while let Ok(ReadOutcome::Data { len, .. }) =
            pair.b.try_read(pair.server, &mut received[read..])
        {
            read += len;
        }
        if read == accepted {
            break;
        }
        pair.step();
    }
    assert_eq!(received, data[..accepted]);
    assert_eq!(pair.wire.retransmitted(), 0);
}

// The transmit budget counts frames handed to the backend: one aggregate is
// one, and the drive reports the segments it carried.
#[test]
fn an_aggregate_takes_one_unit_of_the_transmit_budget() {
    let mut pair = Pair::new(false, false, Some(dpdk()));
    let data = data(14_480);
    pair.a
        .try_write(pair.client, &data, WriteOptions::default())
        .unwrap();
    let frames = pair.wire.frames.get();
    pair.now += 10;
    let report = pair
        .a
        .drive(pair.now, WorkBudget::new(64, 1, 64, 64))
        .unwrap();
    let aggregates = pair.wire.aggregates.borrow();
    assert_eq!(aggregates.len(), 1);
    let segments = pair.wire.frames.get() - frames;
    assert!(segments >= 2);
    assert_eq!(report.transmitted, segments);
    assert!(report.more_work);
}

// An ECN-capable connection's segments are marked ECT, which no backend
// copies into the segments it cuts: they go out one at a time, without
// building an aggregate to be refused.
#[test]
fn ecn_capable_segments_are_sent_one_at_a_time() {
    let mut pair = Pair::with(false, true, Some(dpdk()), |config| {
        config.tcp.connection.ecn_initiate = true;
    });
    let data = data(100_000);
    assert_eq!(pair.transfer(&data), data);
    assert!(pair.wire.aggregates.borrow().is_empty());
    assert_eq!(pair.a.counters().segmentation_refused, 0);
}

// Without segmentation the backend is never offered an aggregate, and the
// buffer budget charges no aggregate room; with it, each output
// reservation holds the payload of the largest aggregate. Either budget
// admits exactly its connections.
#[test]
fn the_buffer_budget_follows_the_backends_segmentation() {
    let address = "10.73.0.1".parse().unwrap();
    let peer = SocketAddr::new("10.73.0.2".parse().unwrap(), 9000);
    let plain = config(address, true, 1);
    let without = plain
        .buffer_budget(3, &wires(PacketLayer::Ethernet, None).0)
        .unwrap();
    let with = plain
        .buffer_budget(3, &wires(PacketLayer::Ethernet, Some(dpdk())).0)
        .unwrap();
    // Five reservations: four connection slots and the stateless lane.
    assert_eq!(with - without, 5 * (65535 - 14 - 20 - 20));
    for (capabilities, budget) in [(None, without), (Some(dpdk()), with)] {
        let admitted = |budget: usize| {
            let mut config = config(address, true, 1);
            config.tcp.max_buffer_bytes = budget;
            let (wire, _) = wires(PacketLayer::Ethernet, capabilities);
            let mut network = Network::new(config, wire, [1; 32], 0).unwrap();
            (0..4).take_while(|_| network.connect(peer).is_ok()).count()
        };
        assert_eq!(admitted(budget), 3);
        assert_eq!(admitted(budget - 1), 2);
    }
    let mut pair = Pair::new(false, true, None);
    let data = data(100_000);
    assert_eq!(pair.transfer(&data), data);
    assert!(pair.wire.aggregates.borrow().is_empty());
}

// An abort while the backend blocks an aggregate withdraws it unsent: the
// connection ends, and none of its data reaches the backend later.
#[test]
fn an_abort_withdraws_a_blocked_aggregate() {
    let mut pair = Pair::new(false, true, Some(dpdk()));
    pair.wire.mode.set(Mode::Block);
    pair.a
        .try_write(pair.client, &data(100_000), WriteOptions::default())
        .unwrap();
    pair.step();
    assert!(!pair.wire.aggregates.borrow().is_empty());
    pair.a.abort(pair.client).unwrap();
    pair.wire.mode.set(Mode::Segment);
    let blocked = pair.wire.aggregates.borrow().len();
    for _ in 0..10 {
        pair.step();
    }
    assert_eq!(pair.wire.aggregates.borrow().len(), blocked);
    assert!(pair.wire.sent.borrow().is_empty());
    assert!(matches!(
        pair.a.connection_info(pair.client),
        Err(Error::InvalidHandle)
            | Ok(ConnectionInfo {
                state: State::Closed,
                ..
            })
    ));
    assert!(
        matches!(
            pair.b.try_read(pair.server, &mut [0; 16]),
            Err(Error::ConnectionClosed(_)) | Ok(ReadOutcome::Eof)
        ) || pair.b.connection_info(pair.server).unwrap().state == State::Closed
    );
}

// Writes timestamped as an application timing its requests does (dpdk_echo
// asks Scheduled for every 64 KiB request) still leave in aggregates, and
// every request's Scheduled and Acknowledged observation arrives once, for
// the last byte the write accepted.
#[test]
fn timestamped_writes_leave_in_aggregates() {
    let mut pair = Pair::with(false, true, Some(dpdk()), |config| {
        config.tx_timestamp_phases = 64;
    });
    let data = data(640 * 1024);
    let placeholder = TimestampEvent {
        connection: pair.client,
        observation: TxTimestampEvent {
            cookie: u64::MAX,
            target: 0,
            stage: TxTimestampStage::Scheduled,
            source: TxTimestampSource::Software,
            outcome: TxTimestampOutcome::Cancelled,
        },
    };
    let mut out = [placeholder; 16];
    let (mut sent, mut received, mut targets, mut events) = (0, 0, Vec::new(), Vec::new());
    let mut buffer = vec![0; 65536];
    for _ in 0..20_000 {
        if sent < data.len() {
            let end = (sent + 64 * 1024 - sent % (64 * 1024)).min(data.len());
            let options = WriteOptions {
                timestamps: TxTimestampRequest {
                    cookie: targets.len() as u64,
                    scheduled: true,
                    acknowledged: true,
                    ..TxTimestampRequest::default()
                },
            };
            match pair.a.try_write(pair.client, &data[sent..end], options) {
                Ok(receipt) => {
                    sent += receipt.accepted;
                    targets.push(receipt.range.end - 1);
                }
                Err(error) if error.is_would_block() => {}
                Err(error) => panic!("write: {error:?}"),
            }
        }
        pair.step();
        loop {
            let report = pair.a.drain_timestamps(&mut out);
            events.extend_from_slice(&out[..report.written]);
            if !report.more {
                break;
            }
        }
        while let Ok(ReadOutcome::Data { len, .. }) = pair.b.try_read(pair.server, &mut buffer) {
            received += len;
        }
        if received == data.len() && events.len() == 2 * targets.len() {
            break;
        }
    }
    assert_eq!(received, data.len());
    assert!(targets.len() >= 10, "{}", targets.len());
    assert!(pair.a.counters().segmented >= 10, "{:?}", pair.a.counters());
    assert_eq!(events.len(), 2 * targets.len());
    for (cookie, &target) in targets.iter().enumerate() {
        for stage in [TxTimestampStage::Scheduled, TxTimestampStage::Acknowledged] {
            let matching: Vec<_> = events
                .iter()
                .map(|e| e.observation)
                .filter(|o| o.cookie == cookie as u64 && o.stage == stage)
                .collect();
            assert_eq!(matching.len(), 1, "{cookie} {stage:?}: {matching:?}");
            assert_eq!(matching[0].target, target);
            assert_eq!(matching[0].source, TxTimestampSource::Software);
            assert!(matches!(
                matching[0].outcome,
                TxTimestampOutcome::Recorded { .. }
            ));
        }
    }
}
