// A connection whose output is reserved, its packet refused by a backend
// with no TX room, gives no event until the reservation ends: the core
// holds its events, and a read would be refused. The drain after the
// drive that submits the packet gives each held event once. Debug builds
// check, after every drain that leaves nothing queued, that no connection
// has an event the ready queue misses. Two Networks over an in-memory IP
// wire whose transmit a test can refuse (WouldBlock).
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::*;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    rc::Rc,
};

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

struct Wire {
    incoming: Queue,
    outgoing: Queue,
    blocked: Rc<Cell<bool>>,
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
        if self.blocked.get() {
            return Ok(TxOutcome::WouldBlock);
        }
        self.outgoing.borrow_mut().push_back(packet.to_vec());
        Ok(TxOutcome::Submitted)
    }
}

const BUDGET: WorkBudget = WorkBudget::new(32, 32, 32, 32);
const PORT: u16 = 9000;

fn address(side: u8) -> IpAddr {
    IpAddr::from([10, 78, 0, side])
}

fn network(side: u8, incoming: &Queue, outgoing: &Queue) -> Network<Wire> {
    let mut config = NetworkConfig::new(address(side), 1500);
    config.tcp.max_connections = 8;
    config.tcp.max_listeners = 2;
    let wire = Wire {
        incoming: incoming.clone(),
        outgoing: outgoing.clone(),
        blocked: Rc::default(),
    };
    Network::new(config, wire, [side; 32], 0).unwrap()
}

struct Pair {
    client: Network<Wire>,
    server: Network<Wire>,
    listener: ListenerId,
    // What the server sent the client and the client has not received.
    to_client: Queue,
    now: u64,
}
impl Pair {
    fn new() -> Self {
        let (a, b) = (Queue::default(), Queue::default());
        let client = network(1, &a, &b);
        let mut server = network(2, &b, &a);
        let listener = server.listen(PORT, 4).unwrap();
        Self {
            client,
            server,
            listener,
            to_client: a,
            now: 0,
        }
    }
    fn step(&mut self) {
        self.now += 1000;
        self.client.drive(self.now, BUDGET).unwrap();
        self.server.drive(self.now, BUDGET).unwrap();
    }
    // A connection from the client, accepted, with the events of the
    // handshake drained on both sides.
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
                self.step();
                self.step();
                assert_eq!(count(&drain(&mut self.client), Event::Connected(client)), 1);
                drain(&mut self.server);
                return (client, server);
            }
        }
        panic!("handshake did not finish");
    }
}

// Every event, over as many drains as it takes.
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

fn count(events: &[Event], event: Event) -> usize {
    events.iter().filter(|&&e| e == event).count()
}

// The client's ACK of the SYN-ACK refused: the connection is ESTABLISHED
// in the core, but Connected waits for the ACK to leave.
#[test]
fn connected_waits_for_the_refused_ack_of_the_syn_ack() {
    let mut pair = Pair::new();
    let blocked = pair.client.backend().blocked.clone();
    let client = pair
        .client
        .connect(SocketAddr::new(address(2), PORT))
        .unwrap();
    pair.now += 1000;
    pair.client.drive(pair.now, BUDGET).unwrap();
    assert!(drain(&mut pair.client).is_empty());
    pair.server.drive(pair.now, BUDGET).unwrap();
    assert!(!pair.to_client.borrow().is_empty());
    blocked.set(true);
    for _ in 0..3 {
        pair.step();
        assert!(drain(&mut pair.client).is_empty());
        assert!(matches!(
            pair.client.try_write(client, b"x", WriteOptions::default()),
            Err(Error::WouldBlock(BlockReason::OutputReserved))
        ));
    }
    assert!(pair.to_client.borrow().is_empty());
    assert!(pair.server.accept(pair.listener).is_err());
    blocked.set(false);
    pair.step();
    assert_eq!(count(&drain(&mut pair.client), Event::Connected(client)), 1);
    assert!(drain(&mut pair.client).is_empty());
    pair.step();
    let server = pair.server.accept(pair.listener).unwrap();
    assert_eq!(count(&drain(&mut pair.server), Event::Connected(server)), 1);
}

// Data arrived whose ACK is refused: the client's Readable waits for the
// ACK to leave, and a read refused meanwhile (armed) adds no second one.
#[test]
fn readable_waits_for_the_refused_ack_of_the_data() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    let blocked = pair.client.backend().blocked.clone();
    blocked.set(true);
    pair.server
        .try_write(server, &[7; 600], WriteOptions::default())
        .unwrap();
    pair.server.drive(pair.now, BUDGET).unwrap();
    assert!(!pair.to_client.borrow().is_empty());
    for _ in 0..3 {
        pair.step();
        assert!(drain(&mut pair.client).is_empty());
        let read = pair.client.try_read(client, &mut [0; 1024]);
        assert!(
            matches!(read, Err(Error::WouldBlock(BlockReason::OutputReserved))),
            "{read:?}"
        );
        assert!(!pair.client.readiness(client).unwrap().readable);
    }
    assert!(pair.to_client.borrow().is_empty());
    blocked.set(false);
    pair.step();
    assert_eq!(count(&drain(&mut pair.client), Event::Readable(client)), 1);
    assert!(drain(&mut pair.client).is_empty());
    assert!(matches!(
        pair.client.try_read(client, &mut [0; 1024]),
        Ok(ReadOutcome::Data { len: 600, .. })
    ));
}

// The Readable for the data already given, a read refused while the
// client's own write waits for TX room arms Readable, which the drain
// after the drive that submits the write gives once.
#[test]
fn a_read_refused_while_a_write_is_reserved_gets_readable_after_it() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    pair.server
        .try_write(server, &[7; 600], WriteOptions::default())
        .unwrap();
    for _ in 0..3 {
        pair.step();
    }
    assert_eq!(count(&drain(&mut pair.client), Event::Readable(client)), 1);
    let blocked = pair.client.backend().blocked.clone();
    blocked.set(true);
    pair.client
        .try_write(client, b"reserved", WriteOptions::default())
        .unwrap();
    pair.now += 1000;
    pair.client.drive(pair.now, BUDGET).unwrap();
    let read = pair.client.try_read(client, &mut [0; 1024]);
    assert!(
        matches!(read, Err(Error::WouldBlock(BlockReason::OutputReserved))),
        "{read:?}"
    );
    assert!(drain(&mut pair.client).is_empty());
    blocked.set(false);
    // The client alone: the end of the reservation, not the peer's ACK,
    // raises it.
    pair.now += 1000;
    pair.client.drive(pair.now, BUDGET).unwrap();
    assert_eq!(drain(&mut pair.client), [Event::Readable(client)]);
    assert!(drain(&mut pair.client).is_empty());
    assert!(matches!(
        pair.client.try_read(client, &mut [0; 1024]),
        Ok(ReadOutcome::Data { len: 600, .. })
    ));
}
