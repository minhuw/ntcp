// DriveReport::events_pending: true whenever drain_events has an event to
// give as the drive returns, false after a drive with nothing queued. Every
// drive here checks the guarantee itself: a report saying false is followed
// by a drain that must give nothing. Two Networks over an in-memory IP
// wire, whose packets a test can drop.
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::*;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    rc::Rc,
};

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

struct Wire {
    incoming: Queue,
    outgoing: Queue,
    // Drop what this side transmits.
    lose: Rc<Cell<bool>>,
}
impl PacketIo for Wire {
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn max_packet_len(&self) -> Option<usize> {
        Some(1500)
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        let Some(packet) = self.incoming.borrow_mut().pop_front() else {
            return Ok(None);
        };
        out[..packet.len()].copy_from_slice(&packet);
        Ok(Some(packet.len()))
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        if !self.lose.get() {
            self.outgoing.borrow_mut().push_back(packet.to_vec());
        }
        Ok(TxOutcome::Submitted)
    }
}

const BUDGET: WorkBudget = WorkBudget::new(32, 32, 32, 32);
const PORT: u16 = 9000;
const MS: u64 = 1000;

fn address(side: u8) -> IpAddr {
    IpAddr::from([10, 75, 0, side])
}

fn network(side: u8, incoming: &Queue, outgoing: &Queue, lose: &Rc<Cell<bool>>) -> Network<Wire> {
    let mut config = NetworkConfig::new(address(side), 1500);
    config.tcp.max_connections = 8;
    config.tcp.max_listeners = 2;
    config.tcp.connection.send_capacity = 2048;
    // A send limit the Writable test fills.
    config.tcp.connection.send_capacity_max = 0;
    let wire = Wire {
        incoming: incoming.clone(),
        outgoing: outgoing.clone(),
        lose: lose.clone(),
    };
    Network::new(config, wire, [side; 32], 0).unwrap()
}

fn drain(network: &mut Network<Wire>) -> Vec<Event> {
    let mut result = Vec::new();
    let mut out = [Event::NetworkStopped; 8];
    loop {
        let report = network.drain_events(&mut out);
        result.extend_from_slice(&out[..report.written]);
        if !report.more {
            return result;
        }
    }
}

// One drive of `network`, then a drain. A drive that reports nothing
// pending must leave nothing to drain. Returns the flag and the events.
fn drive(network: &mut Network<Wire>, now: u64, budget: WorkBudget) -> (bool, Vec<Event>) {
    let report = network.drive(now, budget).unwrap();
    let events = drain(network);
    if !report.events_pending {
        assert_eq!(events, [], "a drive reported no events pending");
    }
    (report.events_pending, events)
}

struct Pair {
    client: Network<Wire>,
    server: Network<Wire>,
    listener: ListenerId,
    now: u64,
    // Drops what the client sends.
    lose: Rc<Cell<bool>>,
    // Every event of either side, with the flag of the drive it followed.
    client_events: Vec<(bool, Event)>,
    server_events: Vec<(bool, Event)>,
}
impl Pair {
    fn new() -> Self {
        let (a, b) = (Queue::default(), Queue::default());
        let lose = Rc::new(Cell::new(false));
        let client = network(1, &a, &b, &lose);
        let mut server = network(2, &b, &a, &Rc::new(Cell::new(false)));
        let listener = server.listen(PORT, 4).unwrap();
        Self {
            client,
            server,
            listener,
            now: 0,
            lose,
            client_events: Vec::new(),
            server_events: Vec::new(),
        }
    }
    fn step(&mut self) {
        self.now += MS;
        let (flag, events) = drive(&mut self.client, self.now, BUDGET);
        self.client_events
            .extend(events.into_iter().map(|e| (flag, e)));
        let (flag, events) = drive(&mut self.server, self.now, BUDGET);
        self.server_events
            .extend(events.into_iter().map(|e| (flag, e)));
    }
    fn steps(&mut self, n: usize) {
        for _ in 0..n {
            self.step();
        }
    }
    // Whether `event` arrived, each time after a drive reporting events
    // pending, and forget the events seen so far.
    fn client_saw(&mut self, event: impl Fn(&Event) -> bool) -> bool {
        seen(&mut self.client_events, event)
    }
    fn server_saw(&mut self, event: impl Fn(&Event) -> bool) -> bool {
        seen(&mut self.server_events, event)
    }
    fn connected(&mut self) -> (ConnId, ConnId) {
        let client = self
            .client
            .connect(SocketAddr::new(address(2), PORT))
            .unwrap();
        for _ in 0..100 {
            self.step();
            if let Ok(server) = self.server.accept(self.listener) {
                self.client.set_nodelay(client, true).unwrap();
                self.server.set_nodelay(server, true).unwrap();
                self.steps(2);
                self.client_events.clear();
                self.server_events.clear();
                return (client, server);
            }
        }
        panic!("handshake did not finish");
    }
}

fn seen(events: &mut Vec<(bool, Event)>, event: impl Fn(&Event) -> bool) -> bool {
    let mut found = false;
    for (flag, e) in events.drain(..) {
        if event(&e) {
            assert!(flag, "{e:?} drained after a drive reporting none pending");
            found = true;
        }
    }
    found
}

fn read_all(network: &mut Network<Wire>, id: ConnId) -> usize {
    let mut out = [0; 512];
    let mut total = 0;
    loop {
        match network.try_read(id, &mut out) {
            Ok(ReadOutcome::Data { len, .. }) => total += len,
            Err(error) if error.is_would_block() => return total,
            other => panic!("read: {other:?}"),
        }
    }
}

#[test]
fn an_idle_drive_has_no_events_pending() {
    let mut pair = Pair::new();
    let (client, _) = pair.connected();
    pair.steps(400);
    for budget in [BUDGET, WorkBudget::new(0, 32, 0, 0)] {
        let (flag, events) = drive(&mut pair.client, pair.now, budget);
        assert!(!flag && events.is_empty(), "{events:?}");
    }
    // A write queues no event; the flush drive that sends it raises none.
    pair.client
        .try_write(client, &[1; 100], WriteOptions::default())
        .unwrap();
    let (flag, _) = drive(&mut pair.client, pair.now, WorkBudget::new(0, 32, 0, 0));
    assert!(!flag);
}

#[test]
fn connected_and_acceptable_are_pending() {
    let mut pair = Pair::new();
    let client = pair
        .client
        .connect(SocketAddr::new(address(2), PORT))
        .unwrap();
    pair.steps(5);
    let listener = pair.listener;
    assert!(pair.client_saw(|e| *e == Event::Connected(client)));
    assert!(pair.server_saw(|e| *e == Event::Acceptable(listener)));
}

#[test]
fn readable_and_closed_are_pending() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    pair.client
        .try_write(client, &[7; 600], WriteOptions::default())
        .unwrap();
    pair.steps(3);
    assert!(pair.server_saw(|e| *e == Event::Readable(server)));
    assert_eq!(read_all(&mut pair.server, server), 600);
    pair.server.abort(server).unwrap();
    pair.steps(3);
    assert!(
        pair.client_saw(|e| matches!(e, Event::Closed { connection, .. } if *connection == client))
    );
}

// A refused write arms Writable, which the acknowledgments that free its
// send buffer raise inside a drive.
#[test]
fn writable_is_pending() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    let accepted = pair
        .client
        .try_write(client, &[1; 16384], WriteOptions::default())
        .unwrap()
        .accepted;
    assert!(accepted < 16384);
    assert!(
        pair.client
            .try_write(client, &[1; 16384], WriteOptions::default())
            .is_err_and(|e| e.is_would_block())
    );
    let mut writable = false;
    for _ in 0..400 {
        pair.step();
        read_all(&mut pair.server, server);
        writable |= pair.client_saw(|e| *e == Event::Writable(client));
    }
    assert!(writable);
}

// Retransmissions to a peer that answers nothing pass the threshold at
// which the connection advises the IP layer (RFC 9293 R1).
#[test]
fn route_advice_is_pending() {
    let mut pair = Pair::new();
    let (client, _) = pair.connected();
    pair.lose.set(true);
    pair.client
        .try_write(client, &[3; 100], WriteOptions::default())
        .unwrap();
    let mut advised = false;
    for _ in 0..600 {
        pair.now += 100 * MS;
        let (flag, events) = drive(&mut pair.client, pair.now, BUDGET);
        pair.client_events
            .extend(events.into_iter().map(|e| (flag, e)));
        advised |= pair.client_saw(|e| matches!(e, Event::RouteAdvice { .. }));
        if advised {
            break;
        }
    }
    assert!(advised);
}

// An ICMP error for a connection a listener has not yet given out is the
// listener's to report.
#[test]
fn passive_error_is_pending() {
    let (incoming, outgoing) = (Queue::default(), Queue::default());
    let mut server = network(2, &incoming, &outgoing, &Rc::new(Cell::new(false)));
    let listener = server.listen(PORT, 4).unwrap();
    let peer = Ipv4Addr::new(10, 75, 0, 1);
    let local = Ipv4Addr::new(10, 75, 0, 2);
    // A SYN from the peer, answered by a SYN-ACK that goes nowhere.
    let mut syn = vec![
        0x9c, 0x40, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0x10, 0, 0, 0, 0, 0,
    ];
    syn[2..4].copy_from_slice(&PORT.to_be_bytes());
    let sum = checksum(&pseudo(peer, local, 6, &syn));
    syn[16..18].copy_from_slice(&sum.to_be_bytes());
    incoming.borrow_mut().push_back(ipv4(peer, local, 6, &syn));
    let (_, events) = drive(&mut server, MS, BUDGET);
    assert_eq!(events, []);
    let synack = outgoing.borrow_mut().pop_front().expect("a SYN-ACK");
    assert_eq!(synack[20 + 13], 0x12);
    // Host unreachable, quoting the SYN-ACK.
    let mut message = vec![3, 1, 0, 0, 0, 0, 0, 0];
    message.extend(&synack[..28]);
    let sum = checksum(&message);
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    incoming
        .borrow_mut()
        .push_back(ipv4(peer, local, 1, &message));
    let (flag, events) = drive(&mut server, 2 * MS, BUDGET);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::PassiveError { listener: l, .. } if *l == listener)),
        "{events:?}"
    );
    assert!(flag);
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn pseudo(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, segment: &[u8]) -> Vec<u8> {
    let mut pseudo = source.octets().to_vec();
    pseudo.extend(destination.octets());
    pseudo.extend([0, protocol]);
    pseudo.extend((segment.len() as u16).to_be_bytes());
    pseudo.extend(segment);
    pseudo
}

fn ipv4(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x45, 0, 0, 0, 0, 7, 0x40, 0, 64, protocol, 0, 0];
    packet[2..4].copy_from_slice(&(20 + payload.len() as u16).to_be_bytes());
    packet.extend(source.octets());
    packet.extend(destination.octets());
    let sum = checksum(&packet);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet.extend(payload);
    packet
}
