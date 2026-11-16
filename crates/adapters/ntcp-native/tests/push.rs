// Network::push: one connection's output sent where Linux's sendmsg ends
// (tcp_push), everything else left to drive. Two IPv4 Networks over an
// in-memory IP wire; the server's side of it can segment TCP aggregates
// (TSO), refuse them, have no TX room, or lose segments.
use ntcp_io::{
    PacketIo, PacketLayer, TcpSegmentationCapabilities, TcpSegmentationError,
    TcpSegmentationRequest, TxOutcome,
};
use ntcp_native::*;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    rc::Rc,
};

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Mode {
    // Every frame and aggregate is submitted.
    #[default]
    Submit,
    // No TX room: everything WouldBlock.
    Block,
    // Aggregates are refused (Unsupported); scalar frames are submitted.
    Refuse,
}

#[derive(Clone, Default)]
struct Shared {
    mode: Rc<Cell<Mode>>,
    // Every frame the peer is handed, in order: scalar frames and the
    // segments cut from aggregates.
    frames: Rc<RefCell<Vec<Vec<u8>>>>,
    // Aggregates submitted.
    aggregates: Rc<Cell<usize>>,
    // A loss generator's state; 0 loses nothing.
    loss: Rc<Cell<u64>>,
}

struct Wire {
    incoming: Queue,
    outgoing: Queue,
    tso: Option<TcpSegmentationCapabilities>,
    shared: Shared,
}
impl Wire {
    fn deliver(&self, frame: Vec<u8>) {
        self.shared.frames.borrow_mut().push(frame.clone());
        // About one data segment in 16 is lost.
        let state = self.shared.loss.get();
        if state != 0 && payload_len(&frame) != 0 {
            let mut x = state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.shared.loss.set(x);
            if x.is_multiple_of(16) {
                return;
            }
        }
        self.outgoing.borrow_mut().push_back(frame);
    }
}
impl PacketIo for Wire {
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn max_packet_len(&self) -> Option<usize> {
        Some(65535)
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        let Some(packet) = self.incoming.borrow_mut().pop_front() else {
            return Ok(None);
        };
        out[..packet.len()].copy_from_slice(&packet);
        Ok(Some(packet.len()))
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        if self.shared.mode.get() == Mode::Block {
            return Ok(TxOutcome::WouldBlock);
        }
        self.deliver(packet.to_vec());
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
        match self.shared.mode.get() {
            Mode::Block => return Ok(TxOutcome::WouldBlock),
            Mode::Refuse => return Err(TcpSegmentationError::Unsupported),
            Mode::Submit => {}
        }
        self.shared.aggregates.set(self.shared.aggregates.get() + 1);
        for segment in cut(packet, request.segment_payload_len) {
            self.deliver(segment);
        }
        Ok(TxOutcome::Submitted)
    }
}

fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in header.chunks(2) {
        sum += u32::from(u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
// The offsets of the TCP header and the payload of an IPv4 packet.
fn layout(packet: &[u8]) -> (usize, usize) {
    let tcp = usize::from(packet[0] & 15) * 4;
    (tcp, tcp + usize::from(packet[tcp + 12] >> 4) * 4)
}
fn payload_len(packet: &[u8]) -> usize {
    if packet[9] != 6 {
        return 0;
    }
    packet.len() - layout(packet).1
}
fn flags(packet: &[u8]) -> u8 {
    packet[layout(packet).0 + 13]
}
// The local port of the server connection that sent `packet`.
fn source_port(packet: &[u8]) -> u16 {
    let tcp = layout(packet).0;
    u16::from_be_bytes([packet[tcp], packet[tcp + 1]])
}
fn destination_port(packet: &[u8]) -> u16 {
    let tcp = layout(packet).0;
    u16::from_be_bytes([packet[tcp + 2], packet[tcp + 3]])
}
// The segments a device cuts from an aggregate, as Linux tcp_gso_segment:
// PSH and FIN on the last only, lengths and checksums filled.
fn cut(packet: &[u8], mss: usize) -> Vec<Vec<u8>> {
    let (tcp, payload) = layout(packet);
    let data = &packet[payload..];
    let count = data.len().div_ceil(mss);
    let sequence = u32::from_be_bytes(packet[tcp + 4..tcp + 8].try_into().unwrap());
    let ip = ntcp::IpMetadata {
        source: IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).unwrap()),
        destination: IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).unwrap()),
    };
    (0..count)
        .map(|n| {
            let mut s = packet[..payload].to_vec();
            s.extend_from_slice(&data[n * mss..((n + 1) * mss).min(data.len())]);
            let len = s.len() as u16;
            s[2..4].copy_from_slice(&len.to_be_bytes());
            s[10..12].fill(0);
            let sum = ip_checksum(&s[..tcp]);
            s[10..12].copy_from_slice(&sum.to_be_bytes());
            s[tcp + 4..tcp + 8]
                .copy_from_slice(&sequence.wrapping_add((n * mss) as u32).to_be_bytes());
            if n + 1 != count {
                s[tcp + 13] &= !0x09;
            }
            s[tcp + 16..tcp + 18].fill(0);
            let sum = ntcp::wire::checksum(ip, &s[tcp..]).unwrap();
            s[tcp + 16..tcp + 18].copy_from_slice(&sum.to_be_bytes());
            s
        })
        .collect()
}

// An mlx5 port's: 64 KiB aggregates, PSH on the last segment.
fn tso() -> TcpSegmentationCapabilities {
    TcpSegmentationCapabilities {
        max_aggregate_len: 65535,
        max_segments: 64,
        max_wire_bytes: 65535 + 63 * 114,
        local_ip_mtu: 1500,
        allow_psh: true,
        allow_cwr: false,
    }
}

const BUDGET: WorkBudget = WorkBudget::new(64, 64, 64, 64);
// A write's flush, as Stackbench's shim drives one: transmit only.
const FLUSH: WorkBudget = WorkBudget::new(0, 64, 0, 0);
const PORT: u16 = 9000;
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 79, 0, 1);
const SERVER: Ipv4Addr = Ipv4Addr::new(10, 79, 0, 2);

struct Net {
    server: Network<Wire>,
    client: Network<Wire>,
    listener: ListenerId,
    // The (server's, client's) handles of each connection.
    connections: Vec<(ConnId, ConnId)>,
    wire: Shared,
    to_client: Queue,
    to_server: Queue,
    // What each step's drives may do.
    budget: WorkBudget,
    now: u64,
}
impl Net {
    fn new(segmentation: bool) -> Self {
        Self::configured(segmentation, |_| {})
    }
    // Both sides' configurations changed by `configure`.
    fn configured(segmentation: bool, configure: impl Fn(&mut NetworkConfig)) -> Self {
        let (a, b) = (Queue::default(), Queue::default());
        let wire = Shared::default();
        let network = |address: Ipv4Addr, incoming: &Queue, outgoing: &Queue, server: bool| {
            let mut config = NetworkConfig::new(IpAddr::V4(address), 1500);
            config.tcp.max_connections = 8;
            config.tcp.max_listeners = 1;
            configure(&mut config);
            let io = Wire {
                incoming: incoming.clone(),
                outgoing: outgoing.clone(),
                tso: (server && segmentation).then(tso),
                shared: if server {
                    wire.clone()
                } else {
                    Shared::default()
                },
            };
            Network::new(config, io, [address.octets()[3]; 32], 0).unwrap()
        };
        let client = network(CLIENT, &a, &b, false);
        let mut server = network(SERVER, &b, &a, true);
        let listener = server.listen(PORT, 8).unwrap();
        Self {
            server,
            client,
            listener,
            connections: Vec::new(),
            wire,
            to_client: a,
            to_server: b,
            budget: BUDGET,
            now: 0,
        }
    }
    // A new connection, accepted, its handshake done; the server's handle.
    fn connect(&mut self, nodelay: bool) -> ConnId {
        let peer = self
            .client
            .connect(SocketAddr::new(SERVER.into(), PORT))
            .unwrap();
        for _ in 0..100 {
            self.step();
            if let Ok(id) = self.server.accept(self.listener) {
                self.server.set_nodelay(id, nodelay).unwrap();
                self.step();
                self.step();
                self.connections.push((id, peer));
                self.wire.frames.borrow_mut().clear();
                return id;
            }
        }
        panic!("no connection");
    }
    // Both sides driven fully, and the server's frames delivered.
    fn step(&mut self) {
        self.now += 1000;
        self.client.drive(self.now, self.budget).unwrap();
        self.server.drive(self.now, self.budget).unwrap();
    }
    fn write(&mut self, id: ConnId, len: usize) {
        let written = self
            .server
            .try_write(id, &data(len), WriteOptions::default());
        assert_eq!(written.unwrap().accepted, len);
    }
    fn push(&mut self, id: ConnId) -> PushReport {
        self.push_result(id).unwrap()
    }
    fn push_result(&mut self, id: ConnId) -> Result<PushReport> {
        self.now += 10;
        self.server.push(id, self.now)
    }
    // What the server sent since the last look.
    fn sent(&self) -> Vec<Vec<u8>> {
        self.wire.frames.borrow_mut().drain(..).collect()
    }
    // The client's local port of the connection whose server handle is `id`.
    fn client_port(&self, id: ConnId) -> u16 {
        let (_, peer) = *self.connections.iter().find(|(s, _)| *s == id).unwrap();
        self.client.connection_info(peer).unwrap().local.port()
    }
    // Everything the client can read on the connection of server handle `id`.
    fn read(&mut self, id: ConnId) -> Vec<u8> {
        let (_, peer) = *self.connections.iter().find(|(s, _)| *s == id).unwrap();
        let mut out = Vec::new();
        let mut buf = [0; 65536];
        for _ in 0..200 {
            self.step();
            while let Ok(ReadOutcome::Data { len, .. }) = self.client.try_read(peer, &mut buf) {
                out.extend_from_slice(&buf[..len]);
            }
        }
        out
    }
}
fn data(len: usize) -> Vec<u8> {
    (0..len).map(|n| (n % 251) as u8).collect()
}
fn lengths(frames: &[Vec<u8>]) -> Vec<usize> {
    frames.iter().map(|f| payload_len(f)).collect()
}

// A write's push sends all of it that the windows allow, at once, and only
// what the connection has: a second push finds nothing. Its deadline is
// the network's, the one a drive at the same instant reports.
#[test]
fn a_push_sends_the_whole_write_and_a_second_push_nothing() {
    let mut net = Net::new(false);
    let id = net.connect(true);
    net.write(id, 10_000);
    let report = net.push(id);
    let sent = net.sent();
    assert_eq!(lengths(&sent), [1448, 1448, 1448, 1448, 1448, 1448, 1312]);
    assert_eq!(report.transmitted, 7);
    assert!(!report.tx_blocked && !report.more && !report.more_work);
    let deadline = report.next_deadline;
    assert!(deadline.is_some());
    let again = net.push(id);
    assert_eq!(again.transmitted, 0);
    assert!(net.sent().is_empty());
    assert_eq!(again.next_deadline, deadline);
    let drive = net
        .server
        .drive(net.now, WorkBudget::new(0, 0, 0, 0))
        .unwrap();
    assert_eq!(drive.next_deadline, deadline);
    assert_eq!(net.read(id), data(10_000));
}

// Minshall's Nagle (c148): with Nagle on, a write of two full segments and
// a short tail leaves whole in its push, no earlier short segment being
// unacknowledged; a second short write waits for that tail's ACK, which a
// drive takes in and whose transmit loop sends it.
#[test]
fn a_push_sends_what_nagle_allows() {
    let mut net = Net::new(false);
    let id = net.connect(false);
    net.write(id, 3000);
    assert_eq!(net.push(id).transmitted, 3);
    assert_eq!(lengths(&net.sent()), [1448, 1448, 104]);
    net.write(id, 100);
    assert_eq!(net.push(id).transmitted, 0);
    assert!(net.sent().is_empty());
    assert_eq!(net.read(id).len(), 3100);
    assert_eq!(lengths(&net.sent()), [100]);
}

// A pushed write as a TSO aggregate: the remainder past the group's first
// PUSH segment leaves in the same push (n0cc), and a refused aggregate's
// segments leave one at a time, in the same push.
#[test]
fn a_push_sends_aggregates_and_the_segments_of_refused_ones() {
    let mut net = Net::new(true);
    let id = net.connect(true);
    net.write(id, 10_000);
    let report = net.push(id);
    assert_eq!(report.transmitted, 7);
    assert_eq!(net.wire.aggregates.get(), 1);
    assert_eq!(
        lengths(&net.sent()),
        [1448, 1448, 1448, 1448, 1448, 1448, 1312]
    );
    assert_eq!(net.push(id).transmitted, 0);
    assert_eq!(net.read(id).len(), 10_000);

    let refused = net.server.counters().segmentation_refused;
    net.wire.mode.set(Mode::Refuse);
    net.write(id, 5000);
    let report = net.push(id);
    assert_eq!(report.transmitted, 4);
    assert!(!report.more);
    assert_eq!(lengths(&net.sent()), [1448, 1448, 1448, 656]);
    assert!(net.server.counters().segmentation_refused > refused);
    assert_eq!(net.push(id).transmitted, 0);
    net.wire.mode.set(Mode::Submit);
    assert_eq!(net.read(id).len(), 5000);
}

// More than PUSH_FRAMES frames' worth selectable: the push stops there and
// says so; another push sends the rest.
#[test]
fn a_push_stops_at_its_frame_limit() {
    // Small segments, so that the window holds more than the limit.
    let mut net = Net::configured(false, |config| config.mtu = 576);
    // Drives that take a whole window in, so the window can grow.
    net.budget = WorkBudget::new(1024, 1024, 64, 64);
    let id = net.connect(true);
    let (_, peer) = net.connections[0];
    net.client.set_receive_buffer(peer, 4 << 20).unwrap();
    net.server.set_send_buffer(id, 4 << 20).unwrap();
    let mss = net.server.transport_info(id).unwrap().mss as usize;
    let len = mss * (PUSH_FRAMES + 10);
    // The congestion window grown by bulk transfer until it holds it.
    for _ in 0..30 {
        if net.server.transport_info(id).unwrap().cwnd as usize >= len {
            break;
        }
        net.write(id, 8 * len);
        net.push(id);
        net.read(id);
    }
    net.sent();
    let cwnd = net.server.transport_info(id).unwrap().cwnd as usize;
    assert!(cwnd >= len, "cwnd {cwnd}");
    net.write(id, len);
    let report = net.push(id);
    assert_eq!(report.transmitted, PUSH_FRAMES);
    assert!(report.more && report.more_work);
    let report = net.push(id);
    assert_eq!(report.transmitted, 10);
    assert!(!report.more && !report.more_work);
    assert_eq!(net.push(id).transmitted, 0);
}

// No TX room: the push takes the frame, which waits for room, and says so;
// nothing surfaces as an error (c151), later pushes send nothing while it
// waits, and the drive that finds room sends it and the rest of the write.
#[test]
fn a_push_without_tx_room_leaves_its_frame_to_the_drive() {
    let mut net = Net::new(false);
    let id = net.connect(true);
    net.wire.mode.set(Mode::Block);
    net.write(id, 3000);
    let report = net.push(id);
    assert_eq!(report.transmitted, 0);
    assert!(report.tx_blocked && report.more_work);
    assert!(net.sent().is_empty());
    net.write(id, 100);
    let report = net.push(id);
    assert_eq!(report.transmitted, 0);
    assert!(report.tx_blocked);
    net.wire.mode.set(Mode::Submit);
    net.now += 10;
    net.server.drive(net.now, FLUSH).unwrap();
    assert_eq!(lengths(&net.sent()), [1448, 1448, 204]);
    assert_eq!(net.read(id).len(), 3100);
}

// Set while the connection's output is reserved, TCP_NODELAY takes effect
// at once (c151): the push after it sends nothing, the frame still
// waiting, and the drive that ends the reservation sends the tail Nagle
// held, which it would hold without the change.
#[test]
fn nodelay_set_while_reserved_releases_the_tail_in_the_drive_that_ends_it() {
    for nodelay in [false, true] {
        let mut net = Net::new(false);
        let id = net.connect(false);
        net.write(id, 100);
        assert_eq!(net.push(id).transmitted, 1);
        net.wire.mode.set(Mode::Block);
        net.write(id, 1448 + 50);
        let report = net.push(id);
        assert!(report.tx_blocked && report.transmitted == 0);
        if nodelay {
            net.server.set_nodelay(id, true).unwrap();
            let report = net.push(id);
            assert!(report.tx_blocked && report.transmitted == 0);
        }
        net.wire.mode.set(Mode::Submit);
        net.sent();
        net.now += 10;
        net.server.drive(net.now, FLUSH).unwrap();
        let expected: &[usize] = if nodelay { &[1448, 50] } else { &[1448] };
        assert_eq!(lengths(&net.sent()), expected);
    }
}

// A frame of another connection waits for TX room: a push sends nothing,
// as a qdisc queues behind it, and the next drive sends both.
#[test]
fn a_push_queues_behind_frames_waiting_for_tx_room() {
    let mut net = Net::new(false);
    let a = net.connect(true);
    let b = net.connect(true);
    net.wire.mode.set(Mode::Block);
    net.write(b, 500);
    net.now += 10;
    let report = net.server.drive(net.now, FLUSH).unwrap();
    assert!(report.tx_blocked);
    net.wire.mode.set(Mode::Submit);
    net.write(a, 500);
    let report = net.push(a);
    assert_eq!(report.transmitted, 0);
    assert!(report.tx_blocked && report.more_work);
    assert!(net.sent().is_empty());
    net.now += 10;
    net.server.drive(net.now, FLUSH).unwrap();
    let sent = net.sent();
    let mut ports: Vec<u16> = sent.iter().map(|f| destination_port(f)).collect();
    ports.sort_unstable();
    let mut expected = [net.client_port(a), net.client_port(b)];
    expected.sort_unstable();
    assert_eq!(ports, expected);
}

// A push sends its own connection's output alone: another connection's
// queued write and a queued stateless reply (a RST to a SYN for a port
// nobody listens on) leave in the next drive.
#[test]
fn a_push_sends_only_its_connections_output() {
    let mut net = Net::new(false);
    let a = net.connect(true);
    let b = net.connect(true);
    // A SYN to a closed port, taken in by a drive that transmits nothing.
    let stray = net
        .client
        .connect(SocketAddr::new(SERVER.into(), PORT + 1))
        .unwrap();
    net.now += 1000;
    net.client.drive(net.now, BUDGET).unwrap();
    net.server
        .drive(net.now, WorkBudget::new(64, 0, 64, 64))
        .unwrap();
    assert!(net.sent().is_empty());
    net.write(b, 700);
    net.write(a, 600);
    net.push(a);
    let sent = net.sent();
    assert_eq!(lengths(&sent), [600]);
    assert_eq!(destination_port(&sent[0]), net.client_port(a));
    net.now += 10;
    net.server.drive(net.now, FLUSH).unwrap();
    let sent = net.sent();
    let stray_port = net.client.connection_info(stray).unwrap().local.port();
    assert!(
        sent.iter()
            .any(|f| destination_port(f) == net.client_port(b) && payload_len(f) == 700)
    );
    assert!(
        sent.iter()
            .any(|f| destination_port(f) == stray_port && flags(f) & 0x04 != 0)
    );
    assert!(
        sent.iter()
            .all(|f| source_port(f) == PORT || source_port(f) == PORT + 1)
    );
}

// A path MTU decrease an earlier drive took in (a Packet Too Big quoting
// another connection's segment to the same peer, which the path service
// passes on to every connection on the path) reaches the connection
// before its push selects: the push's segments are cut for the new MTU,
// the same wire as a write's flush drive gives.
#[test]
fn a_push_after_a_packet_too_big_cuts_for_the_new_mtu() {
    let run = |push: bool| {
        // Packet Too Big messages acted on (path MTU discovery).
        let mut net = Net::configured(false, |config| {
            config.tcp.connection.pmtud = Some(ntcp::PmtudConfig::new(1500));
        });
        let a = net.connect(true);
        let b = net.connect(true);
        net.write(b, 1448);
        net.push(b);
        let sent = net.sent();
        // B's segment stays unacknowledged: the client never gets it.
        net.to_client.borrow_mut().clear();
        let mut message = vec![3, 4, 0, 0, 0, 0, 0x04, 0xb0];
        message.extend(&sent[0][..28]);
        let sum = ip_checksum(&message);
        message[2..4].copy_from_slice(&sum.to_be_bytes());
        net.to_server.borrow_mut().push_back(ipv4(
            Ipv4Addr::new(10, 79, 0, 9),
            SERVER,
            1,
            &message,
        ));
        net.now += 10;
        net.server
            .drive(net.now, WorkBudget::new(64, 0, 0, 0))
            .unwrap();
        net.write(a, 3000);
        if push {
            net.push(a);
        } else {
            net.now += 10;
            net.server.drive(net.now, FLUSH).unwrap();
        }
        let sent: Vec<_> = net
            .sent()
            .into_iter()
            .filter(|f| destination_port(f) == net.client_port(a))
            .collect();
        assert_eq!(lengths(&sent), [1148, 1148, 704]);
        assert_eq!(net.read(a).len(), 3000);
        sent
    };
    assert_eq!(run(true), run(false));
}

fn ipv4(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x45, 0, 0, 0, 0, 7, 0x40, 0, 64, protocol, 0, 0];
    packet[2..4].copy_from_slice(&(20 + payload.len() as u16).to_be_bytes());
    packet.extend(source.octets());
    packet.extend(destination.octets());
    let sum = ip_checksum(&packet);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet.extend(payload);
    packet
}

// The same script of writes, Nagle changes and a shutdown, over a wire that
// loses data segments, sent by a push after every write call and by a
// flush drive after every write call: the server's frames are the same,
// byte for byte, with or without TSO.
#[test]
fn pushes_send_the_wire_flush_drives_send() {
    for seed in 1..=6u64 {
        for tso in [false, true] {
            let run = |push: bool| {
                let mut net = Net::new(tso);
                let id = net.connect(seed % 2 == 0);
                net.wire
                    .loss
                    .set(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
                let mut rng = seed;
                let mut next = move |n: u64| {
                    rng ^= rng << 13;
                    rng ^= rng >> 7;
                    rng ^= rng << 17;
                    rng % n
                };
                let flush = |net: &mut Net| {
                    if push {
                        net.push(id);
                    } else {
                        net.now += 10;
                        net.server.drive(net.now, FLUSH).unwrap();
                    }
                };
                let (mut written, mut read) = (0, 0);
                let (_, peer) = net.connections[0];
                let mut buf = [0; 65536];
                for _ in 0..60 {
                    match next(10) {
                        0 => {
                            net.server.set_nodelay(id, next(2) == 0).unwrap();
                            flush(&mut net);
                        }
                        1..=6 => {
                            let len = [1, 24, 100, 1448, 3000, 4120, 20_000][next(7) as usize];
                            if let Ok(receipt) =
                                net.server
                                    .try_write(id, &data(len), WriteOptions::default())
                            {
                                written += receipt.accepted;
                            }
                            flush(&mut net);
                        }
                        _ => {
                            for _ in 0..1 + next(3) {
                                net.step();
                            }
                            while let Ok(ReadOutcome::Data { len, .. }) =
                                net.client.try_read(peer, &mut buf)
                            {
                                read += len;
                            }
                        }
                    }
                }
                net.server.shutdown_write(id).unwrap();
                flush(&mut net);
                for _ in 0..3000 {
                    net.step();
                    while let Ok(ReadOutcome::Data { len, .. }) =
                        net.client.try_read(peer, &mut buf)
                    {
                        read += len;
                    }
                    if read == written && net.server.transport_info(id).unwrap().unacked == 0 {
                        break;
                    }
                }
                assert_eq!(read, written, "seed {seed} tso {tso} push {push}");
                net.sent()
            };
            let pushed = run(true);
            let flushed = run(false);
            assert!(pushed.len() > 50);
            assert!(pushed == flushed, "seed {seed} tso {tso}");
        }
    }
}

// The errors a push gives, as a drive's: a closed handle, time going
// backwards (nothing done, the network runs on) and a stopped network.
#[test]
fn a_push_refuses_as_a_drive_does() {
    let mut net = Net::new(false);
    let a = net.connect(true);
    let b = net.connect(true);
    let earlier = net.now - 1;
    assert!(matches!(
        net.server.push(a, earlier),
        Err(Error::TimeWentBackwards)
    ));
    assert!(!net.server.is_stopped());
    net.server.close(b).unwrap();
    assert!(matches!(net.push_result(b), Err(Error::InvalidHandle)));
    net.write(a, 10);
    assert_eq!(net.push(a).transmitted, 1);
    net.server.stop();
    assert!(matches!(net.push_result(a), Err(Error::Stopped)));
}
