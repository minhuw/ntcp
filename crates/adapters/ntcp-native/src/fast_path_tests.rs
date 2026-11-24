// Differential and regression tests for Commit 10 fast paths and fixes:
// - SlotQueue & CoreSlots randomized model tests
// - empty_reader same-clock invalidation tests (shutdown_write, close, abort,
//   release/reclaim + slot reuse, stop, set_receive_buffer, push, and peer
//   data/FIN/RST via drive at the same clock)
// - Events differential tests (collect_events_pass, drain_events fast path,
//   refresh_connection unconditional reason, CloseWait/Closed/abort/idle-reader
//   skip/armed-writer wakeup)
// - Ingress & egress fast-path differential tests (Ethernet plain-TCP fast path
//   vs padded/IPv4-options/IPv6 slow path, offer_fresh/fill_selected/quiet gate,
//   blocked TX retry via reserved path, and scratch restore on mid-drive error)
use super::*;
use ntcp_io::{
    PacketLayer, TcpSegmentationCapabilities, TcpSegmentationError, TcpSegmentationRequest,
    TxOutcome,
};
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    rc::Rc,
};

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

struct MockIo {
    layer: PacketLayer,
    incoming: Queue,
    outgoing: Queue,
    blocked: Rc<Cell<bool>>,
    // Optional IPv4 NOP options injected into transmitted IPv4 TCP packets
    // (IHL=6) to force the general IPv4 parser instead of PlainTcp::parse.
    add_ipv4_nop_options: Rc<Cell<bool>>,
    // When Some(0), receive returns a hard backend I/O error; Some(n) counts down.
    fail_after_receives: Rc<Cell<Option<usize>>>,
    tso: Option<TcpSegmentationCapabilities>,
    scalar_transmits: Rc<Cell<usize>>,
    aggregates: Rc<Cell<usize>>,
}

impl MockIo {
    fn new(layer: PacketLayer, incoming: &Queue, outgoing: &Queue) -> Self {
        Self {
            layer,
            incoming: incoming.clone(),
            outgoing: outgoing.clone(),
            blocked: Rc::new(Cell::new(false)),
            add_ipv4_nop_options: Rc::new(Cell::new(false)),
            fail_after_receives: Rc::new(Cell::new(None)),
            tso: None,
            scalar_transmits: Rc::new(Cell::new(0)),
            aggregates: Rc::new(Cell::new(0)),
        }
    }
}

impl PacketIo for MockIo {
    fn layer(&self) -> PacketLayer {
        self.layer
    }
    fn max_packet_len(&self) -> Option<usize> {
        Some(if self.tso.is_some() { 65535 } else { 1514 })
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        if let Some(remaining) = self.fail_after_receives.get() {
            if remaining == 0 {
                self.fail_after_receives.set(None);
                return Err(io::Error::other("injected backend receive failure"));
            }
            self.fail_after_receives.set(Some(remaining - 1));
        }
        let Some(packet) = self.incoming.borrow_mut().pop_front() else {
            return Ok(None);
        };
        out[..packet.len()].copy_from_slice(&packet);
        Ok(Some(packet.len()))
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        if self.blocked.get() {
            return Ok(TxOutcome::WouldBlock);
        }
        self.scalar_transmits.set(self.scalar_transmits.get() + 1);
        let mut frame = packet.to_vec();
        if self.add_ipv4_nop_options.get() {
            let ip_off = if self.layer == PacketLayer::Ethernet {
                14
            } else {
                0
            };
            if frame.len() >= ip_off + 20 && (frame[ip_off] >> 4) == 4 && (frame[ip_off] & 0x0f) == 5
            {
                frame = inject_ipv4_nop_option(&frame, ip_off);
            }
        }
        self.outgoing.borrow_mut().push_back(frame);
        Ok(TxOutcome::Submitted)
    }
    fn tcp_segmentation_capabilities(&self) -> Option<TcpSegmentationCapabilities> {
        self.tso
    }
    fn transmit_segmented(
        &mut self,
        packet: &[u8],
        request: TcpSegmentationRequest,
    ) -> std::result::Result<TxOutcome, TcpSegmentationError> {
        if self.blocked.get() {
            return Ok(TxOutcome::WouldBlock);
        }
        self.aggregates.set(self.aggregates.get() + 1);
        let ip_off = if self.layer == PacketLayer::Ethernet {
            14
        } else {
            0
        };
        let ip_hdr = usize::from(packet[ip_off] & 0x0f) * 4;
        let tcp = ip_off + ip_hdr;
        let tcp_hdr = usize::from(packet[tcp + 12] >> 4) * 4;
        let payload = tcp + tcp_hdr;
        let data = &packet[payload..];
        let mss = request.segment_payload_len;
        let count = data.len().div_ceil(mss);
        let sequence = u32::from_be_bytes(packet[tcp + 4..tcp + 8].try_into().unwrap());
        let ip = ntcp::IpMetadata {
            source: IpAddr::from(<[u8; 4]>::try_from(&packet[ip_off + 12..ip_off + 16]).unwrap()),
            destination: IpAddr::from(
                <[u8; 4]>::try_from(&packet[ip_off + 16..ip_off + 20]).unwrap(),
            ),
        };
        for n in 0..count {
            let mut seg = packet[..payload].to_vec();
            seg.extend_from_slice(&data[n * mss..((n + 1) * mss).min(data.len())]);
            let ip_len = (seg.len() - ip_off) as u16;
            seg[ip_off + 2..ip_off + 4].copy_from_slice(&ip_len.to_be_bytes());
            seg[ip_off + 10..ip_off + 12].fill(0);
            let sum = ipv4_header_checksum(&seg[ip_off..tcp]);
            seg[ip_off + 10..ip_off + 12].copy_from_slice(&sum.to_be_bytes());
            seg[tcp + 4..tcp + 8]
                .copy_from_slice(&sequence.wrapping_add((n * mss) as u32).to_be_bytes());
            if n + 1 != count {
                seg[tcp + 13] &= !0x09;
            }
            seg[tcp + 16..tcp + 18].fill(0);
            let sum = ntcp::wire::checksum(ip, &seg[tcp..]).unwrap();
            seg[tcp + 16..tcp + 18].copy_from_slice(&sum.to_be_bytes());
            if ip_off != 0 && seg.len() < 60 {
                seg.resize(60, 0);
            }
            self.outgoing.borrow_mut().push_back(seg);
        }
        Ok(TxOutcome::Submitted)
    }
}

fn inject_ipv4_nop_option(frame: &[u8], ip_off: usize) -> Vec<u8> {
    let ip_total = u16::from_be_bytes([frame[ip_off + 2], frame[ip_off + 3]]) as usize;
    let payload_end = ip_off + ip_total;
    let mut out = Vec::with_capacity(frame.len() + 4);
    out.extend_from_slice(&frame[..ip_off + 20]);
    // 4 bytes of NOP options (type 1) to bump IHL from 5 to 6.
    out.extend_from_slice(&[1, 1, 1, 1]);
    out.extend_from_slice(&frame[ip_off + 20..payload_end]);
    out[ip_off] = (4 << 4) | 6;
    let new_total = (ip_total + 4) as u16;
    out[ip_off + 2..ip_off + 4].copy_from_slice(&new_total.to_be_bytes());
    out[ip_off + 10..ip_off + 12].fill(0);
    let csum = ipv4_header_checksum(&out[ip_off..ip_off + 24]);
    out[ip_off + 10..ip_off + 12].copy_from_slice(&csum.to_be_bytes());
    if ip_off == 14 && out.len() < 60 {
        out.resize(60, 0);
    }
    out
}

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.as_chunks::<2>().0 {
        sum += u32::from(u16::from_be_bytes(*chunk));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

const BUDGET: WorkBudget = WorkBudget::new(64, 64, 64, 64);
const PORT: u16 = 9100;
const CLIENT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const SERVER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

fn v4_addr(side: u8) -> IpAddr {
    IpAddr::from([10, 88, 0, side])
}

fn v6_addr(side: u8) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, u16::from(side)))
}

fn drain_all(net: &mut Network<MockIo>) -> Vec<Event> {
    let mut events = Vec::new();
    let mut out = [Event::NetworkStopped; 16];
    loop {
        let report = net.drain_events(&mut out);
        events.extend_from_slice(&out[..report.written]);
        if !report.more {
            return events;
        }
    }
}

struct Pair {
    client: Network<MockIo>,
    server: Network<MockIo>,
    listener: ListenerId,
    client_blocked: Rc<Cell<bool>>,
    to_server: Queue,
    peer_addr: SocketAddr,
    now: u64,
}

impl Pair {
    fn new_ip() -> Self {
        Self::build(PacketLayer::Ip, v4_addr(1), v4_addr(2), false, false)
    }

    fn new_ip_with_options() -> Self {
        Self::build(PacketLayer::Ip, v4_addr(1), v4_addr(2), false, true)
    }

    fn new_ethernet_v4(arp: bool, add_ipv4_nop_options: bool) -> Self {
        Self::build(
            PacketLayer::Ethernet,
            v4_addr(1),
            v4_addr(2),
            arp,
            add_ipv4_nop_options,
        )
    }

    fn new_ethernet_v6() -> Self {
        Self::build(
            PacketLayer::Ethernet,
            v6_addr(1),
            v6_addr(2),
            false,
            false,
        )
    }

    fn build(
        layer: PacketLayer,
        client_ip: IpAddr,
        server_ip: IpAddr,
        arp: bool,
        add_ipv4_nop_options: bool,
    ) -> Self {
        let to_client = Queue::default();
        let to_server = Queue::default();

        let make_cfg = |local: IpAddr, local_mac: [u8; 6], peer_mac: [u8; 6]| {
            let mut cfg = NetworkConfig::new(local, 1500);
            cfg.tcp.max_connections = 4;
            cfg.tcp.max_listeners = 2;
            cfg.tcp.connection.send_capacity = 4096;
            cfg.tcp.connection.send_capacity_max = 0;
            if layer == PacketLayer::Ethernet {
                cfg.link = Link::Ethernet {
                    local_mac,
                    next_hop: if arp {
                        EthernetNextHop::Arp {
                            prefix_len: 24,
                            gateway: None,
                        }
                    } else {
                        EthernetNextHop::Fixed(peer_mac)
                    },
                };
            }
            cfg
        };

        let client_io = MockIo::new(layer, &to_client, &to_server);
        client_io.add_ipv4_nop_options.set(add_ipv4_nop_options);
        let client_blocked = client_io.blocked.clone();

        let server_io = MockIo::new(layer, &to_server, &to_client);
        server_io.add_ipv4_nop_options.set(add_ipv4_nop_options);

        let client = Network::new(
            make_cfg(client_ip, CLIENT_MAC, SERVER_MAC),
            client_io,
            [1; 32],
            0,
        )
        .unwrap();
        let mut server = Network::new(
            make_cfg(server_ip, SERVER_MAC, CLIENT_MAC),
            server_io,
            [2; 32],
            0,
        )
        .unwrap();
        let listener = server.listen(PORT, 4).unwrap();
        Self {
            client,
            server,
            listener,
            client_blocked,
            to_server,
            peer_addr: SocketAddr::new(server_ip, PORT),
            now: 0,
        }
    }

    fn step(&mut self) {
        self.now += 1_000;
        self.client.drive(self.now, BUDGET).unwrap();
        self.server.drive(self.now, BUDGET).unwrap();
    }

    fn connected(&mut self) -> (ConnId, ConnId) {
        let c = self.client.connect(self.peer_addr).unwrap();
        for _ in 0..100 {
            self.step();
            if let Ok(s) = self.server.accept(self.listener) {
                self.client.set_nodelay(c, true).unwrap();
                self.server.set_nodelay(s, true).unwrap();
                self.step();
                self.step();
                drain_all(&mut self.client);
                drain_all(&mut self.server);
                return (c, s);
            }
        }
        panic!("handshake did not complete");
    }
}

// =========================================================================
// 1. SlotQueue & CoreSlots randomized differential model tests
// =========================================================================

struct XorShift64(u64);
impl XorShift64 {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

fn check_slot_queue_invariants(q: &SlotQueue, oracle: &VecDeque<usize>) {
    assert_eq!(q.len(), oracle.len());
    assert_eq!(q.is_empty(), oracle.is_empty());
    if oracle.is_empty() {
        assert_eq!(q.first, usize::MAX);
        assert!(q.rest.is_empty());
        assert!(q.queued.iter().all(|&b| !b));
    } else {
        assert_eq!(q.first, oracle[0]);
        assert!(!q.queued[q.first]);
        assert!(q.rest.iter().copied().eq(oracle.iter().skip(1).copied()));
        for (slot, &flag) in q.queued.iter().enumerate() {
            let expected = oracle.iter().skip(1).any(|&s| s == slot);
            assert_eq!(flag, expected, "queued bit mismatch for slot {slot}");
        }
    }
}

#[test]
fn slot_queue_differential_model() {
    let mut rng = XorShift64(0x9e37_79b9_7f4a_7c15);

    // Edge case: 0 slots.
    let mut empty_q = SlotQueue::new(0).unwrap();
    assert!(empty_q.is_empty());
    assert_eq!(empty_q.len(), 0);
    assert_eq!(empty_q.pop(), None);

    for slots in [1usize, 2, 4, 16, 64] {
        let mut q = SlotQueue::new(slots).unwrap();
        let mut oracle: VecDeque<usize> = VecDeque::new();
        check_slot_queue_invariants(&q, &oracle);

        for step in 0..2_000 {
            match rng.next() % 10 {
                // Push (including duplicate pushes of first, rest, and reused slots)
                0..=5 => {
                    let slot = if !oracle.is_empty() && rng.next().is_multiple_of(4) {
                        // Explicitly hammer duplicate push of `first`
                        oracle[0]
                    } else {
                        (rng.next() as usize) % slots
                    };
                    q.push(slot);
                    if !oracle.contains(&slot) {
                        oracle.push_back(slot);
                    }
                }
                // Pop
                6..=8 => {
                    let got = q.pop();
                    let expected = oracle.pop_front();
                    assert_eq!(got, expected, "pop mismatch at slots={slots} step={step}");
                }
                // Drain completely (clear) then verify reuse
                _ => {
                    while let Some(expected) = oracle.pop_front() {
                        assert_eq!(q.pop(), Some(expected));
                    }
                    assert_eq!(q.pop(), None);
                }
            }
            check_slot_queue_invariants(&q, &oracle);
        }

        // Final full drain
        while let Some(expected) = oracle.pop_front() {
            assert_eq!(q.pop(), Some(expected));
        }
        assert_eq!(q.pop(), None);
        check_slot_queue_invariants(&q, &oracle);
    }
}

#[test]
fn core_slots_generation_reuse_and_displacement() {
    // Exercise CoreSlots via real connection lifecycle with max_connections = 2
    // so slots and core indices wrap and reuse across generations.
    let mut pair = Pair::new_ip();
    for round in 0..6 {
        let (c, s) = pair.connected();
        let old_slot = c.slot();
        let old_gen = c.generation();
        assert_eq!(pair.client.conn_id(old_slot), c);
        pair.client.abort(c).unwrap();
        pair.server.abort(s).unwrap();
        let mut steps = 0;
        while pair.client.connections[old_slot].value.is_some()
            || pair.server.connections[s.slot()].value.is_some()
        {
            pair.step();
            drain_all(&mut pair.client);
            drain_all(&mut pair.server);
            steps += 1;
            assert!(steps < 200, "round {round}: slot was not reclaimed");
        }
        assert_eq!(pair.client.core_slots.displaced, 0);
        // Old handle must be rejected even after slot reuse.
        assert!(matches!(
            pair.client.connection_info(c),
            Err(Error::InvalidHandle)
        ));
        assert!(old_gen >= 1);
    }
}

// =========================================================================
// 2. empty_reader same-clock invalidation regression tests
// =========================================================================

// Prime `empty_reader` for an established connection at the current clock:
// if the connection's internal clock lagged behind `network.now()`, the first
// `try_read` synchronizes its clock and the second hits `read_available() == None`.
fn prime_empty_reader(net: &mut Network<MockIo>, id: ConnId) {
    let mut buf = [0u8; 32];
    for _ in 0..2 {
        assert!(matches!(
            net.try_read(id, &mut buf),
            Err(Error::WouldBlock(BlockReason::Receive))
        ));
        if net.empty_reader == Some(id) {
            return;
        }
    }
    panic!("empty_reader was not populated for {id:?}");
}

#[test]
fn empty_reader_invalidated_by_shutdown_write_same_clock() {
    let mut pair = Pair::new_ip();
    let (_c, s) = pair.connected();
    let mut buf = [0u8; 64];

    // Prime empty_reader via read_available() == None path.
    prime_empty_reader(&mut pair.server, s);
    assert_eq!(pair.server.empty_reader, Some(s));

    // Another same-clock read hits empty_reader cache cleanly.
    assert!(matches!(
        pair.server.try_read(s, &mut buf),
        Err(Error::WouldBlock(BlockReason::Receive))
    ));
    assert_eq!(pair.server.empty_reader, Some(s));

    // shutdown_write clears empty_reader immediately at the same clock.
    pair.server.shutdown_write(s).unwrap();
    assert_eq!(pair.server.empty_reader, None);

    // Re-prime empty_reader while still Established (FIN queued, not yet sent),
    // then send the FIN via same-clock push -> Established -> FinWait1.
    prime_empty_reader(&mut pair.server, s);
    let same_now = pair.now;
    pair.server.push(s, same_now).unwrap();
    assert_eq!(pair.server.now(), same_now);
    assert_eq!(pair.server.empty_reader, None);

    // Same-clock try_read in FinWait1 must NOT hit stale empty_reader cache
    // and must refresh cached connection state to FinWait1.
    assert!(matches!(
        pair.server.try_read(s, &mut buf),
        Err(Error::WouldBlock(BlockReason::Receive))
    ));
    assert_eq!(pair.server.empty_reader, None);
    assert_eq!(
        pair.server.connection_info(s).unwrap().state,
        State::FinWait1
    );
    assert_eq!(
        pair.server.connections[s.slot()]
            .value
            .as_ref()
            .unwrap()
            .state,
        State::FinWait1
    );
}

#[test]
fn empty_reader_invalidated_by_close_abort_stop_and_slot_reuse_same_clock() {
    // (a) close at same clock
    {
        let mut pair = Pair::new_ip();
        let (_c, s) = pair.connected();
        let mut buf = [0u8; 32];
        prime_empty_reader(&mut pair.server, s);
        assert_eq!(pair.server.empty_reader, Some(s));

        pair.server.close(s).unwrap();
        assert_eq!(pair.server.empty_reader, None);
        assert!(matches!(
            pair.server.try_read(s, &mut buf),
            Err(Error::InvalidHandle)
        ));
    }

    // (b) abort at same clock + release/reclaim + slot reuse
    {
        let mut pair = Pair::new_ip();
        let (c, s) = pair.connected();
        let mut buf = [0u8; 32];
        prime_empty_reader(&mut pair.client, c);
        assert_eq!(pair.client.empty_reader, Some(c));

        pair.client.abort(c).unwrap();
        assert_eq!(pair.client.empty_reader, None);
        assert!(matches!(
            pair.client.try_read(c, &mut buf),
            Err(Error::InvalidHandle)
        ));

        // Drive until slot is released and reclaimed, then reuse the same slot.
        let old_slot = c.slot();
        pair.server.abort(s).unwrap();
        for _ in 0..100 {
            if pair.client.connections[old_slot].value.is_none() {
                break;
            }
            pair.step();
            drain_all(&mut pair.client);
            drain_all(&mut pair.server);
        }
        assert!(pair.client.connections[old_slot].value.is_none());
        let (c2, s2) = pair.connected();
        assert_eq!(c2.slot(), old_slot);
        assert_eq!(c2.generation(), c.generation() + 1);
        assert!(matches!(
            pair.client.try_read(c, &mut buf),
            Err(Error::InvalidHandle)
        ));

        // New connection in reused slot receives data cleanly at the same clock.
        pair.server
            .try_write(s2, b"reused", WriteOptions::default())
            .unwrap();
        pair.server.push(s2, pair.now).unwrap();
        pair.client.drive(pair.now, BUDGET).unwrap();
        match pair.client.try_read(c2, &mut buf).unwrap() {
            ReadOutcome::Data { len, .. } => assert_eq!(&buf[..len], b"reused"),
            other => panic!("expected Data on reused slot, got {other:?}"),
        }
    }

    // (c) stop() at same clock
    {
        let mut pair = Pair::new_ip();
        let (_c, s) = pair.connected();
        let mut buf = [0u8; 32];
        prime_empty_reader(&mut pair.server, s);
        assert_eq!(pair.server.empty_reader, Some(s));

        pair.server.stop();
        assert_eq!(pair.server.empty_reader, None);
        assert!(matches!(
            pair.server.try_read(s, &mut buf),
            Err(Error::Stopped)
        ));
    }

    // (d) set_receive_buffer and push at same clock
    {
        let mut pair = Pair::new_ip();
        let (_c, s) = pair.connected();
        prime_empty_reader(&mut pair.server, s);
        assert_eq!(pair.server.empty_reader, Some(s));

        pair.server.set_receive_buffer(s, 32 * 1024).unwrap();
        assert_eq!(pair.server.empty_reader, None);

        prime_empty_reader(&mut pair.server, s);
        assert_eq!(pair.server.empty_reader, Some(s));

        pair.server
            .try_write(s, b"x", WriteOptions::default())
            .unwrap();
        pair.server.push(s, pair.now).unwrap();
        assert_eq!(pair.server.empty_reader, None);
    }
}

#[test]
fn empty_reader_invalidated_by_same_clock_peer_data_fin_and_rst() {
    // (a) Peer data at SAME clock (populates empty_reader via read_with_wait too)
    {
        let mut pair = Pair::new_ip();
        let (c, s) = pair.connected();
        let mut buf = [0u8; 64];

        // First send data and drain it completely so read_with_wait sets waiting=true -> empty_reader=Some(s).
        pair.client
            .try_write(c, b"first", WriteOptions::default())
            .unwrap();
        pair.client.push(c, pair.now).unwrap();
        pair.server.drive(pair.now, BUDGET).unwrap();
        match pair.server.try_read(s, &mut buf).unwrap() {
            ReadOutcome::Data { len, .. } => assert_eq!(&buf[..len], b"first"),
            other => panic!("expected first chunk, got {other:?}"),
        }
        assert_eq!(pair.server.empty_reader, Some(s));

        // Now peer sends more data at the EXACT SAME clock `pair.now`!
        let same_now = pair.now;
        pair.client
            .try_write(c, b"second", WriteOptions::default())
            .unwrap();
        pair.client.push(c, same_now).unwrap();
        pair.server.drive(same_now, BUDGET).unwrap();
        assert_eq!(pair.server.now(), same_now);
        assert_eq!(pair.server.empty_reader, None);

        match pair.server.try_read(s, &mut buf).unwrap() {
            ReadOutcome::Data { len, .. } => assert_eq!(&buf[..len], b"second"),
            other => panic!("expected second chunk at same clock, got {other:?}"),
        }
    }

    // (b) Peer FIN at SAME clock -> immediate Eof (not stale WouldBlock)
    {
        let mut pair = Pair::new_ip();
        let (c, s) = pair.connected();
        let mut buf = [0u8; 64];
        prime_empty_reader(&mut pair.server, s);
        assert_eq!(pair.server.empty_reader, Some(s));

        let same_now = pair.now;
        pair.client.shutdown_write(c).unwrap();
        pair.client.push(c, same_now).unwrap();
        pair.server.drive(same_now, BUDGET).unwrap();
        assert_eq!(pair.server.now(), same_now);
        assert_eq!(pair.server.empty_reader, None);

        assert_eq!(pair.server.try_read(s, &mut buf).unwrap(), ReadOutcome::Eof);
    }

    // (c) Peer RST at SAME clock -> immediate ConnectionClosed(Reset)
    {
        let mut pair = Pair::new_ip();
        let (c, s) = pair.connected();
        let mut buf = [0u8; 64];
        prime_empty_reader(&mut pair.server, s);
        assert_eq!(pair.server.empty_reader, Some(s));

        let same_now = pair.now;
        pair.client.abort(c).unwrap();
        pair.client.drive(same_now, BUDGET).unwrap();
        pair.server.drive(same_now, BUDGET).unwrap();
        assert_eq!(pair.server.now(), same_now);
        assert_eq!(pair.server.empty_reader, None);

        assert!(matches!(
            pair.server.try_read(s, &mut buf),
            Err(Error::ConnectionClosed(Some(CloseReason::Reset)))
        ));
    }
}

// =========================================================================
// 3. Events differential test (collect_events_pass, drain_events, refresh_connection)
// =========================================================================

#[test]
fn events_idle_reader_skip_armed_writer_and_close_reasons() {
    let mut pair = Pair::new_ip();
    let (c, s) = pair.connected();
    let mut buf = [0u8; 128];

    // (a) Empty drain_events fast path
    let mut single = [Event::NetworkStopped; 1];
    let report = pair.client.drain_events(&mut single);
    assert_eq!(report, DrainReport { written: 0, more: false });

    // (b) Idle-reader ready-queue skip: client writes small payload without
    // arming write_waiting, server ACKs it, client receives ACK -> core emits
    // writable/ack event, collect_events_pass skips ready queue because
    // idle_reader && Established && write_waiting.is_none().
    assert!(matches!(
        pair.client.try_read(c, &mut buf),
        Err(Error::WouldBlock(BlockReason::Receive))
    ));
    pair.client
        .try_write(c, b"hello", WriteOptions::default())
        .unwrap();
    pair.step(); // client transmits, server receives + ACKs
    // Drain server's data and Readable event
    assert!(drain_all(&mut pair.server).contains(&Event::Readable(s)));
    match pair.server.try_read(s, &mut buf).unwrap() {
        ReadOutcome::Data { len, .. } => assert_eq!(&buf[..len], b"hello"),
        other => panic!("expected Data, got {other:?}"),
    }
    // Client processes server's pure ACK
    pair.now += 1_000;
    let drive_rep = pair.client.drive(pair.now, BUDGET).unwrap();
    assert!(!drive_rep.events_pending);
    assert!(pair.client.ready.is_empty());
    assert_eq!(
        pair.client.drain_events(&mut single),
        DrainReport {
            written: 0,
            more: false
        }
    );

    // (c) Armed writer wakeup: fill client send buffer until WouldBlock
    // while receive buffer stays empty; peer ACKs -> Writable MUST be raised!
    let chunk = [0xABu8; 512];
    loop {
        match pair.client.try_write(c, &chunk, WriteOptions::default()) {
            Ok(_) => {}
            Err(Error::WouldBlock(BlockReason::SendBuffer)) => break,
            Err(e) => panic!("unexpected write error: {e:?}"),
        }
    }
    let mut got_writable = false;
    for _ in 0..30 {
        pair.step();
        while let Ok(ReadOutcome::Data { .. }) = pair.server.try_read(s, &mut buf) {}
        drain_all(&mut pair.server);
        let events = drain_all(&mut pair.client);
        if events.contains(&Event::Writable(c)) {
            got_writable = true;
            break;
        }
    }
    assert!(got_writable, "armed writer did not receive Event::Writable");

    // (d) CloseWait transition via peer FIN: refresh_connection updates state
    // and raises Readable even when receive queue has 0 bytes.
    assert!(matches!(
        pair.server.try_read(s, &mut buf),
        Err(Error::WouldBlock(BlockReason::Receive))
    ));
    pair.client.shutdown_write(c).unwrap();
    pair.step();
    let server_events = drain_all(&mut pair.server);
    assert_eq!(server_events, vec![Event::Readable(s)]);
    assert_eq!(
        pair.server.connection_info(s).unwrap().state,
        State::CloseWait
    );
    assert_eq!(pair.server.try_read(s, &mut buf).unwrap(), ReadOutcome::Eof);

    // (e) Peer RST -> Event::Closed with Some(CloseReason::Reset) and
    // unconditional reason update in refresh_connection.
    let (c2, s2) = pair.connected();
    pair.client.abort(c2).unwrap();
    pair.step();
    // Drain one event at a time to exercise multi-drain `more` flag.
    let mut server_closed = Vec::new();
    loop {
        let rep = pair.server.drain_events(&mut single);
        if rep.written == 1 {
            server_closed.push(single[0]);
        }
        if !rep.more {
            break;
        }
    }
    assert!(
        server_closed.contains(&Event::Closed {
            connection: s2,
            reason: Some(CloseReason::Reset),
        }),
        "expected Closed(Reset), got {server_closed:?}"
    );
    assert_eq!(
        pair.server.connection_info(s2).unwrap().reason,
        Some(CloseReason::Reset)
    );

    // (f) Normal close -> Event::Closed with Some(CloseReason::Normal)
    let (c3, s3) = pair.connected();
    pair.client.shutdown_write(c3).unwrap();
    pair.step();
    drain_all(&mut pair.server);
    pair.server.shutdown_write(s3).unwrap();
    for _ in 0..10 {
        pair.step();
        let ev = drain_all(&mut pair.server);
        if let Some(Event::Closed { connection, reason }) =
            ev.into_iter().find(|e| matches!(e, Event::Closed { .. }))
        {
            assert_eq!(connection, s3);
            assert_eq!(reason, Some(CloseReason::Normal));
            return;
        }
    }
    panic!("server did not reach Closed(Normal)");
}

// =========================================================================
// 4. Ingress & egress fast-path differential tests
// =========================================================================

fn run_burst_workload(pair: &mut Pair) -> (Vec<u8>, Vec<u8>, Counters, Counters) {
    let (c, s) = pair.connected();
    let mut c_sent = Vec::new();
    let mut s_recv = Vec::new();
    let mut s_sent = Vec::new();
    let mut c_recv = Vec::new();
    let mut buf = [0u8; 256];

    // Send 12 varied-length bursts in both directions (exercises offer_fresh,
    // PlainTcp::parse fast path vs forced slow path, and multi-packet bursts).
    for i in 0..12u8 {
        let msg_c: Vec<u8> = (0..(40 + usize::from(i) * 17))
            .map(|k| i.wrapping_mul(31).wrapping_add(k as u8))
            .collect();
        let msg_s: Vec<u8> = (0..(25 + usize::from(i) * 19))
            .map(|k| i.wrapping_mul(17).wrapping_add(k as u8).wrapping_add(7))
            .collect();

        let wr_c = pair
            .client
            .try_write(c, &msg_c, WriteOptions::default())
            .unwrap();
        c_sent.extend_from_slice(&msg_c[..wr_c.accepted]);
        if i % 2 == 0 {
            pair.client.push(c, pair.now).unwrap();
        }

        let wr_s = pair
            .server
            .try_write(s, &msg_s, WriteOptions::default())
            .unwrap();
        s_sent.extend_from_slice(&msg_s[..wr_s.accepted]);
        if i % 2 == 1 {
            pair.server.push(s, pair.now).unwrap();
        }

        pair.step();
        pair.step();

        while let Ok(ReadOutcome::Data { len, .. }) = pair.server.try_read(s, &mut buf) {
            s_recv.extend_from_slice(&buf[..len]);
        }
        while let Ok(ReadOutcome::Data { len, .. }) = pair.client.try_read(c, &mut buf) {
            c_recv.extend_from_slice(&buf[..len]);
        }
        drain_all(&mut pair.client);
        drain_all(&mut pair.server);
    }

    // Drain any stragglers.
    for _ in 0..6 {
        pair.step();
        while let Ok(ReadOutcome::Data { len, .. }) = pair.server.try_read(s, &mut buf) {
            s_recv.extend_from_slice(&buf[..len]);
        }
        while let Ok(ReadOutcome::Data { len, .. }) = pair.client.try_read(c, &mut buf) {
            c_recv.extend_from_slice(&buf[..len]);
        }
        drain_all(&mut pair.client);
        drain_all(&mut pair.server);
    }

    assert_eq!(s_recv, c_sent);
    assert_eq!(c_recv, s_sent);

    // Idle drive exercises the `quiet` gate: zero packets transmitted, no more_work.
    pair.now += 1_000;
    let quiet_c = pair.client.drive(pair.now, BUDGET).unwrap();
    let quiet_s = pair.server.drive(pair.now, BUDGET).unwrap();
    assert_eq!(quiet_c.transmitted, 0);
    assert_eq!(quiet_s.transmitted, 0);
    assert!(!quiet_c.more_work);
    assert!(!quiet_s.more_work);

    (
        s_recv,
        c_recv,
        pair.client.counters(),
        pair.server.counters(),
    )
}

#[test]
fn ingress_plain_tcp_fast_path_matches_slow_paths() {
    // Fast path 1: exact-length IPv4 Ethernet frames (PlainTcp::parse succeeds).
    let mut eth_fast = Pair::new_ethernet_v4(false, false);
    let (eth_fast_s, eth_fast_c, eth_fast_cc, eth_fast_sc) = run_burst_workload(&mut eth_fast);

    // Forced slow path 1: IPv4 over Ethernet with NOP options (IHL=6 -> PlainTcp::parse returns None).
    let mut eth_opts = Pair::new_ethernet_v4(false, true);
    let (eth_opt_s, eth_opt_c, eth_opt_cc, eth_opt_sc) = run_burst_workload(&mut eth_opts);

    // Fast path 2: IP-layer IPv4 (input -> receive_tcp_frame).
    let mut ip_fast = Pair::new_ip();
    let (ip_fast_s, ip_fast_c, ip_fast_cc, ip_fast_sc) = run_burst_workload(&mut ip_fast);

    // Forced slow path 2: IP-layer IPv4 with NOP options (receive_tcp_frame returns None -> receive_processed).
    let mut ip_opts = Pair::new_ip_with_options();
    let (ip_opt_s, ip_opt_c, ip_opt_cc, ip_opt_sc) = run_burst_workload(&mut ip_opts);

    // Forced slow path 3: IPv6 over Ethernet (non-IPv4 -> general path).
    let mut v6 = Pair::new_ethernet_v6();
    let (v6_s, v6_c, _, _) = run_burst_workload(&mut v6);

    assert_eq!(eth_fast_s, eth_opt_s);
    assert_eq!(eth_fast_c, eth_opt_c);
    assert_eq!(eth_fast_s, ip_fast_s);
    assert_eq!(eth_fast_c, ip_fast_c);
    assert_eq!(eth_fast_s, ip_opt_s);
    assert_eq!(eth_fast_c, ip_opt_c);
    assert_eq!(eth_fast_s, v6_s);
    assert_eq!(eth_fast_c, v6_c);

    // Identical zero-drop counters across fast and forced-slow IPv4 paths.
    assert_eq!(eth_fast_cc.discarded, 0);
    assert_eq!(eth_opt_cc.discarded, 0);
    assert_eq!(eth_fast_sc.discarded, 0);
    assert_eq!(eth_opt_sc.discarded, 0);
    assert_eq!(eth_fast_cc.received, eth_opt_cc.received);
    assert_eq!(eth_fast_sc.received, eth_opt_sc.received);
    assert_eq!(eth_fast_cc.transmitted, eth_opt_cc.transmitted);
    assert_eq!(eth_fast_sc.transmitted, eth_opt_sc.transmitted);

    assert_eq!(ip_fast_cc.discarded, 0);
    assert_eq!(ip_opt_cc.discarded, 0);
    assert_eq!(ip_fast_sc.discarded, 0);
    assert_eq!(ip_opt_sc.discarded, 0);
    assert_eq!(ip_fast_cc.received, ip_opt_cc.received);
    assert_eq!(ip_fast_sc.received, ip_opt_sc.received);
    assert_eq!(ip_fast_cc.transmitted, ip_opt_cc.transmitted);
    assert_eq!(ip_fast_sc.transmitted, ip_opt_sc.transmitted);
}

#[test]
fn ingress_ethernet_fast_path_preserves_drop_reasons() {
    let mut pair = Pair::new_ethernet_v4(false, false);
    pair.server.set_drop_feed(16).unwrap();
    let (_c, _s) = pair.connected();

    // 1. Valid IPv4 header inside an Ethernet frame addressed to another MAC -> DropReason::OtherHost
    let mut other_mac = vec![0u8; 60];
    other_mac[..6].copy_from_slice(&[0x02, 0xde, 0xad, 0xbe, 0xef, 0x00]);
    other_mac[6..12].copy_from_slice(&CLIENT_MAC);
    other_mac[12..14].copy_from_slice(&ntcp_ethernet::ETHERTYPE_IPV4.to_be_bytes());
    other_mac[14] = 0x45;
    other_mac[16..18].copy_from_slice(&40u16.to_be_bytes());
    other_mac[23] = 6;
    other_mac[26..30].copy_from_slice(&[10, 88, 0, 1]);
    other_mac[30..34].copy_from_slice(&[10, 88, 0, 2]);
    let csum = ipv4_header_checksum(&other_mac[14..34]);
    other_mac[24..26].copy_from_slice(&csum.to_be_bytes());
    pair.to_server.borrow_mut().push_back(other_mac);

    // 2. IPv4 TCP frame with bad IP header checksum -> falls out of PlainTcp::parse
    //    and is dropped by the general IPv4 validator.
    let mut bad_csum = vec![0u8; 54];
    bad_csum[..6].copy_from_slice(&SERVER_MAC);
    bad_csum[6..12].copy_from_slice(&CLIENT_MAC);
    bad_csum[12..14].copy_from_slice(&ntcp_ethernet::ETHERTYPE_IPV4.to_be_bytes());
    bad_csum[14] = 0x45;
    bad_csum[16..18].copy_from_slice(&40u16.to_be_bytes());
    bad_csum[23] = 6; // TCP
    bad_csum[24..26].copy_from_slice(&[0xde, 0xad]); // bogus checksum
    bad_csum[26..30].copy_from_slice(&[10, 88, 0, 1]);
    bad_csum[30..34].copy_from_slice(&[10, 88, 0, 2]);
    pair.to_server.borrow_mut().push_back(bad_csum);

    pair.now += 1_000;
    let rep = pair.server.drive(pair.now, BUDGET).unwrap();
    assert_eq!(rep.discarded, 2);
    let mut reasons = Vec::new();
    pair.server
        .drain_drop_events(|ev| reasons.push(ev.reason));
    assert_eq!(reasons.len(), 2);
    assert_eq!(reasons[0], ntcp::DropReason::OtherHost);
    assert_eq!(reasons[1], ntcp::DropReason::IpCsum);
}

#[test]
fn egress_offer_fresh_blocked_retry_and_arp_resolution() {
    // (a) Blocked backend during offer_fresh (both push and drive) retains
    //     frame + egress context and delivers byte-exact on retry.
    let mut pair = Pair::new_ethernet_v4(false, false);
    let (c, s) = pair.connected();

    let payload = b"blocked-offer-fresh-retry-payload-0123456789";
    pair.client
        .try_write(c, payload, WriteOptions::default())
        .unwrap();

    // Block client TX during push -> offer_fresh captures reservation in slot.
    pair.client_blocked.set(true);
    let push_rep = pair.client.push(c, pair.now).unwrap();
    assert_eq!(push_rep.transmitted, 0);
    assert!(push_rep.tx_blocked);
    assert_eq!(pair.client.tx_pending, 1);
    assert!(pair.client.counters().backend_backpressure >= 1);

    // Drive while still blocked -> retries reserved path, stays blocked.
    pair.now += 1_000;
    let blocked_drive = pair.client.drive(pair.now, BUDGET).unwrap();
    assert_eq!(blocked_drive.transmitted, 0);
    assert!(blocked_drive.tx_blocked);
    assert_eq!(pair.client.tx_pending, 1);

    // Unblock and drive -> retained frame transmits and delivers byte-exact.
    pair.client_blocked.set(false);
    pair.step();
    assert_eq!(pair.client.tx_pending, 0);
    let mut buf = [0u8; 128];
    match pair.server.try_read(s, &mut buf).unwrap() {
        ReadOutcome::Data { len, .. } => assert_eq!(&buf[..len], payload),
        other => panic!("expected exact payload after unblock, got {other:?}"),
    }

    // (b) ARP-resolving Ethernet link exercises ethernet_egress_context +
    //     offer_fresh with resolve=true + quiet gate.
    let mut arp_pair = Pair::new_ethernet_v4(true, false);
    let (ac, asrv) = arp_pair.connected();
    let msg = b"arp-resolved-offer-fresh";
    arp_pair
        .client
        .try_write(ac, msg, WriteOptions::default())
        .unwrap();
    arp_pair.client.push(ac, arp_pair.now).unwrap();
    arp_pair.step();
    match arp_pair.server.try_read(asrv, &mut buf).unwrap() {
        ReadOutcome::Data { len, .. } => assert_eq!(&buf[..len], msg),
        other => panic!("expected Data over ARP link, got {other:?}"),
    }
}

#[test]
fn drive_receive_error_restores_lazy_scratch() {
    let mut pair = Pair::new_ip();
    let orig_rx_len = pair.server.rx.len();
    let orig_completed_len = pair.server.completed.len();
    assert!(orig_rx_len > 0);
    assert!(orig_completed_len > 0);

    // Inject one packet followed by a receive error in the SAME burst so
    // `rx` and `completed` are lazily moved out of `self` on packet 1, then
    // packet 2 triggers Err and both scratch vectors must still be restored.
    let (_c, _s) = pair.connected();
    pair.to_server.borrow_mut().push_back(vec![0u8; 20]);
    pair.server.io.fail_after_receives.set(Some(1));
    pair.now += 1_000;
    let err = pair.server.drive(pair.now, BUDGET).unwrap_err();
    assert!(matches!(err, Error::Backend(_)));
    assert_eq!(pair.server.rx.len(), orig_rx_len);
    assert_eq!(pair.server.completed.len(), orig_completed_len);
}

#[test]
fn tso_enabled_network_uses_offer_fresh_for_single_segment_and_tso_for_multi_segment() {
    let caps = TcpSegmentationCapabilities {
        max_aggregate_len: 65535,
        max_segments: 64,
        max_wire_bytes: 65535 + 63 * 114,
        local_ip_mtu: 1500,
        allow_psh: true,
        allow_cwr: false,
    };

    let build_tso_pair = || {
        let to_client = Queue::default();
        let to_server = Queue::default();

        let make_cfg = |local: IpAddr, local_mac: [u8; 6], peer_mac: [u8; 6]| {
            let mut cfg = NetworkConfig::new(local, 1500);
            cfg.tcp.max_connections = 4;
            cfg.tcp.max_listeners = 2;
            cfg.link = Link::Ethernet {
                local_mac,
                next_hop: EthernetNextHop::Fixed(peer_mac),
            };
            cfg
        };

        let mut client_io = MockIo::new(PacketLayer::Ethernet, &to_client, &to_server);
        client_io.tso = Some(caps);
        let client_blocked = client_io.blocked.clone();
        let client_scalars = client_io.scalar_transmits.clone();
        let client_aggregates = client_io.aggregates.clone();

        let server_io = MockIo::new(PacketLayer::Ethernet, &to_server, &to_client);

        let client = Network::new(
            make_cfg(v4_addr(1), CLIENT_MAC, SERVER_MAC),
            client_io,
            [1; 32],
            0,
        )
        .unwrap();
        let mut server = Network::new(
            make_cfg(v4_addr(2), SERVER_MAC, CLIENT_MAC),
            server_io,
            [2; 32],
            0,
        )
        .unwrap();
        let listener = server.listen(PORT, 4).unwrap();
        assert!(client.segmentation.is_some());
        (
            Pair {
                client,
                server,
                listener,
                client_blocked,
                to_server,
                peer_addr: SocketAddr::new(v4_addr(2), PORT),
                now: 0,
            },
            client_scalars,
            client_aggregates,
        )
    };

    let read_all = |pair: &mut Pair, s: ConnId, expected: usize| {
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        for _ in 0..32 {
            pair.step();
            while let Ok(ReadOutcome::Data { len, .. }) = pair.server.try_read(s, &mut buf) {
                out.extend_from_slice(&buf[..len]);
            }
            if out.len() >= expected {
                break;
            }
        }
        out
    };

    // (a) Small <= 1 wire MSS writes take offer_fresh directly under TSO (no
    //     segmentation, no prepare_group), while multi-MSS writes fall back to
    //     fill() + prepare_group() + transmit_segmented().
    {
        let (mut pair, scalars, aggregates) = build_tso_pair();
        let (c, s) = pair.connected();
        pair.client.set_nodelay(c, true).unwrap();

        let before_scalars = scalars.get();
        let before_aggregates = aggregates.get();

        // Small RPC (64 bytes): submitted directly via offer_fresh scalar path.
        let rpc = [0x41u8; 64];
        pair.client
            .try_write(c, &rpc, WriteOptions::default())
            .unwrap();
        let rep = pair.client.push(c, pair.now).unwrap();
        assert_eq!(rep.transmitted, 1);
        assert_eq!(scalars.get(), before_scalars + 1);
        assert_eq!(aggregates.get(), before_aggregates);
        assert_eq!(pair.client.counters().segmented, 0);
        assert_eq!(read_all(&mut pair, s, rpc.len()), rpc);

        // Exact 1 wire MSS (1448 bytes with timestamps): also stays scalar via offer_fresh.
        let one_mss = [0x42u8; 1448];
        let before_scalars = scalars.get();
        pair.client
            .try_write(c, &one_mss, WriteOptions::default())
            .unwrap();
        let rep = pair.client.push(c, pair.now).unwrap();
        assert_eq!(rep.transmitted, 1);
        assert_eq!(scalars.get(), before_scalars + 1);
        assert_eq!(aggregates.get(), before_aggregates);
        assert_eq!(pair.client.counters().segmented, 0);
        assert_eq!(read_all(&mut pair, s, one_mss.len()), one_mss);

        // Multi-MSS bulk write (6 KiB): offer_fresh returns Unavailable and
        // transmit_slot falls back to fill() -> transmit_segmented().
        let bulk: Vec<u8> = (0..6144).map(|i| (i % 251) as u8).collect();
        pair.client
            .try_write(c, &bulk, WriteOptions::default())
            .unwrap();
        let rep = pair.client.push(c, pair.now).unwrap();
        assert!(rep.transmitted >= 2);
        assert!(aggregates.get() > before_aggregates);
        assert!(pair.client.counters().segmented >= 1);
        assert_eq!(read_all(&mut pair, s, bulk.len()), bulk);

        // Follow-up small RPC after a TSO burst returns to scalar offer_fresh.
        let seg_after_bulk = pair.client.counters().segmented;
        let agg_after_bulk = aggregates.get();
        let rpc2 = [0x43u8; 128];
        pair.client
            .try_write(c, &rpc2, WriteOptions::default())
            .unwrap();
        let rep = pair.client.push(c, pair.now).unwrap();
        assert_eq!(rep.transmitted, 1);
        assert_eq!(aggregates.get(), agg_after_bulk);
        assert_eq!(pair.client.counters().segmented, seg_after_bulk);
        assert_eq!(read_all(&mut pair, s, rpc2.len()), rpc2);
    }

    // (b) Blocked-TX proof that transmit_slot actually entered offer_fresh (not
    //     fill()) for <= 1 wire MSS under TSO, and entered fill() + prepare_group()
    //     for > 1 wire MSS under TSO.
    {
        let (mut pair, _, aggregates) = build_tso_pair();
        let (c, s) = pair.connected();
        pair.client.set_nodelay(c, true).unwrap();

        // Small write with backend blocked -> offer_fresh captures PendingFrame
        // with scalar == true, context.is_some(), group.is_none().
        let small = b"blocked-small-under-tso";
        pair.client
            .try_write(c, small, WriteOptions::default())
            .unwrap();
        pair.client_blocked.set(true);
        let rep = pair.client.push(c, pair.now).unwrap();
        assert_eq!(rep.transmitted, 0);
        assert!(rep.tx_blocked);
        let pending = pair
            .client
            .tx
            .iter()
            .find_map(|slot| slot.pending.as_ref())
            .expect("small write must retain pending frame on WouldBlock");
        assert!(
            pending.is_scalar() && pending.has_context() && !pending.has_group(),
            "small write under TSO must take offer_fresh, not fill()"
        );
        pair.client_blocked.set(false);
        assert_eq!(read_all(&mut pair, s, small.len()), small);
        assert_eq!(aggregates.get(), 0);

        // Multi-MSS write with backend blocked -> offer_fresh returns Unavailable,
        // fill() + prepare_group() captures PendingFrame with scalar == false and
        // group.is_some().
        let large: Vec<u8> = (0..4096).map(|i| (i % 199) as u8).collect();
        pair.client
            .try_write(c, &large, WriteOptions::default())
            .unwrap();
        pair.client_blocked.set(true);
        let rep = pair.client.push(c, pair.now).unwrap();
        assert_eq!(rep.transmitted, 0);
        assert!(rep.tx_blocked);
        let pending = pair
            .client
            .tx
            .iter()
            .find_map(|slot| slot.pending.as_ref())
            .expect("multi-MSS write must retain pending aggregate on WouldBlock");
        assert!(
            !pending.is_scalar() && pending.has_group(),
            "multi-MSS write under TSO must bypass offer_fresh and prepare a TransmitGroup"
        );
        pair.client_blocked.set(false);
        assert_eq!(read_all(&mut pair, s, large.len()), large);
        assert!(aggregates.get() >= 1);
        assert!(pair.client.counters().segmented >= 1);
    }
}
