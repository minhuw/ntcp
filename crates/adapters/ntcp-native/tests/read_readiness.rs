// What a read leaves queued, and what may join it before the next drain:
// an embedding that drains its events after each read, and drives only
// between drains, learns from the drain whether to read again, without a
// readiness call (Stackbench's ntcp shim). Two Networks over an in-memory
// IP wire.
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
const NO_RECEIVE: WorkBudget = WorkBudget::new(0, 32, 32, 32);
const PORT: u16 = 9000;

fn address(side: u8) -> IpAddr {
    IpAddr::from([10, 77, 0, side])
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
    // What the client sent the server and the server has not received.
    to_server: Queue,
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
            to_server: b,
            now: 0,
        }
    }
    fn step(&mut self) {
        self.now += 1000;
        self.client.drive(self.now, BUDGET).unwrap();
        self.server.drive(self.now, BUDGET).unwrap();
    }
    fn steps(&mut self, n: usize) {
        for _ in 0..n {
            self.step();
        }
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
                self.steps(2);
                drain(&mut self.client);
                drain(&mut self.server);
                return (client, server);
            }
        }
        panic!("handshake did not finish");
    }
    // `len` octets from the client, arrived at the server, with the
    // server's events drained.
    fn arrived(&mut self, client: ConnId, len: usize) {
        let receipt = self
            .client
            .try_write(client, &vec![7; len], WriteOptions::default())
            .unwrap();
        assert_eq!(receipt.accepted, len);
        self.steps(3);
        drain(&mut self.server);
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

// One drain, with room for more events than these tests raise.
fn next_drain(network: &mut Network<Wire>) -> Vec<Event> {
    let mut out = [Event::NetworkStopped; 16];
    let report = network.drain_events(&mut out);
    assert!(report.written < out.len());
    out[..report.written].to_vec()
}

fn readables(events: &[Event], id: ConnId) -> usize {
    events.iter().filter(|&&e| e == Event::Readable(id)).count()
}

// Right after a read: whether the connection is readable, after checking
// that the next drain gives its Readable if and only if it is.
fn readable_as_queued(network: &mut Network<Wire>, id: ConnId) -> bool {
    let readable = network.readiness(id).unwrap().readable;
    let events = next_drain(network);
    assert_eq!(readables(&events, id), usize::from(readable), "{events:?}");
    readable
}

fn read(network: &mut Network<Wire>, id: ConnId, len: usize) -> Result<ReadOutcome> {
    network.try_read(id, &mut vec![0; len])
}

#[test]
fn a_read_that_leaves_data_queues_readable() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    pair.arrived(client, 600);
    assert!(matches!(
        read(&mut pair.server, server, 100),
        Ok(ReadOutcome::Data { len: 100, .. })
    ));
    assert!(readable_as_queued(&mut pair.server, server));
    // The Readable was handed out once; the next read decides again.
    assert!(next_drain(&mut pair.server).is_empty());
    assert!(matches!(
        read(&mut pair.server, server, 200),
        Ok(ReadOutcome::Data { len: 200, .. })
    ));
    assert!(readable_as_queued(&mut pair.server, server));
}

#[test]
fn a_read_that_takes_all_data_in_established_queues_nothing() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    pair.arrived(client, 600);
    assert!(matches!(
        read(&mut pair.server, server, 1024),
        Ok(ReadOutcome::Data { len: 600, .. })
    ));
    assert_eq!(
        pair.server.connection_info(server).unwrap().state,
        State::Established
    );
    assert!(!readable_as_queued(&mut pair.server, server));
    assert!(matches!(
        read(&mut pair.server, server, 1024),
        Err(Error::WouldBlock(BlockReason::Receive))
    ));
    assert!(!readable_as_queued(&mut pair.server, server));
}

// A read that takes the last data before the peer's FIN leaves the end of
// the stream to read: the EOF read is still due, so Readable is queued,
// and after it the stream stays at its end, readable, as poll(2) reports a
// socket whose peer finished.
#[test]
fn a_read_that_takes_the_data_before_the_fin_queues_readable_for_the_eof() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    pair.client
        .try_write(client, &[7; 600], WriteOptions::default())
        .unwrap();
    pair.client.shutdown_write(client).unwrap();
    pair.steps(3);
    assert!(readables(&drain(&mut pair.server), server) == 1);
    assert_eq!(
        pair.server.connection_info(server).unwrap().state,
        State::CloseWait
    );
    assert!(matches!(
        read(&mut pair.server, server, 1024),
        Ok(ReadOutcome::Data { len: 600, .. })
    ));
    assert!(readable_as_queued(&mut pair.server, server));
    assert!(matches!(
        read(&mut pair.server, server, 1024),
        Ok(ReadOutcome::Eof)
    ));
    assert!(readable_as_queued(&mut pair.server, server));
}

// A connection the peer reset stays readable: what arrived before the
// reset, then the reset itself, which every read after reports.
#[test]
fn a_read_after_a_reset_queues_readable_while_the_reset_is_pending() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    pair.arrived(client, 600);
    pair.client.abort(client).unwrap();
    pair.steps(3);
    let events = drain(&mut pair.server);
    assert!(
        events.contains(&Event::Closed {
            connection: server,
            reason: Some(CloseReason::Reset)
        }),
        "{events:?}"
    );
    let mut total = 0;
    loop {
        match read(&mut pair.server, server, 100) {
            Ok(ReadOutcome::Data { len, .. }) => total += len,
            Err(Error::ConnectionClosed(Some(CloseReason::Reset))) => break,
            other => panic!("read: {other:?}"),
        }
        assert!(readable_as_queued(&mut pair.server, server));
    }
    assert_eq!(total, 600);
    for _ in 0..2 {
        assert!(readable_as_queued(&mut pair.server, server));
        assert!(matches!(
            read(&mut pair.server, server, 100),
            Err(Error::ConnectionClosed(Some(CloseReason::Reset)))
        ));
    }
    assert!(readable_as_queued(&mut pair.server, server));
}

// With no receive budget a drive takes no frame from the backend, so no
// data arrives and no arrival raises Readable; the next drive with a
// receive budget takes the frame.
#[test]
fn a_drive_with_no_receive_budget_receives_nothing() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    // Nothing left to read, nothing queued.
    pair.arrived(client, 300);
    assert!(matches!(
        read(&mut pair.server, server, 1024),
        Ok(ReadOutcome::Data { len: 300, .. })
    ));
    pair.client
        .try_write(client, &[8; 200], WriteOptions::default())
        .unwrap();
    pair.now += 1000;
    pair.client.drive(pair.now, BUDGET).unwrap();
    let waiting = pair.to_server.borrow().len();
    assert!(waiting != 0);
    let report = pair.server.drive(pair.now, NO_RECEIVE).unwrap();
    assert_eq!(report.received, 0);
    assert_eq!(pair.to_server.borrow().len(), waiting);
    assert!(next_drain(&mut pair.server).is_empty());
    assert!(matches!(
        read(&mut pair.server, server, 1024),
        Err(Error::WouldBlock(BlockReason::Receive))
    ));
    let report = pair.server.drive(pair.now, BUDGET).unwrap();
    assert_eq!(report.received, waiting);
    assert_eq!(readables(&next_drain(&mut pair.server), server), 1);
    assert!(matches!(
        read(&mut pair.server, server, 1024),
        Ok(ReadOutcome::Data { len: 200, .. })
    ));
}

// Between a read that left data and the next drain, a drive with no
// receive budget adds nothing: the drain gives the one Readable the read
// queued, and the data readable is what the read left.
#[test]
fn a_drive_with_no_receive_budget_adds_nothing_to_what_a_read_left() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    pair.arrived(client, 600);
    assert!(matches!(
        read(&mut pair.server, server, 100),
        Ok(ReadOutcome::Data { len: 100, .. })
    ));
    pair.client
        .try_write(client, &[8; 200], WriteOptions::default())
        .unwrap();
    pair.now += 1000;
    pair.client.drive(pair.now, BUDGET).unwrap();
    assert!(!pair.to_server.borrow().is_empty());
    let report = pair.server.drive(pair.now, NO_RECEIVE).unwrap();
    assert_eq!(report.received, 0);
    assert_eq!(next_drain(&mut pair.server), [Event::Readable(server)]);
    assert!(matches!(
        read(&mut pair.server, server, 1024),
        Ok(ReadOutcome::Data { len: 500, .. })
    ));
    assert!(!readable_as_queued(&mut pair.server, server));
}

// Input that arrived for a connection whose output was reserved waits in
// the retained pool; a drive with no receive budget does not replay it,
// even once the reservation ended in that drive.
#[test]
fn a_drive_with_no_receive_budget_leaves_retained_input_retained() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    let blocked = pair.server.backend().blocked.clone();
    blocked.set(true);
    pair.server
        .try_write(server, b"reserved", WriteOptions::default())
        .unwrap();
    pair.server.drive(pair.now, BUDGET).unwrap();
    assert!(matches!(
        pair.server
            .try_write(server, b"more", WriteOptions::default()),
        Err(Error::WouldBlock(BlockReason::OutputReserved))
    ));
    pair.client
        .try_write(client, &[7; 200], WriteOptions::default())
        .unwrap();
    for _ in 0..100 {
        pair.step();
        if pair.server.counters().retained_input != 0 {
            break;
        }
    }
    assert!(pair.server.counters().retained_input != 0);
    drain(&mut pair.server);
    blocked.set(false);
    pair.now += 1000;
    let report = pair.server.drive(pair.now, NO_RECEIVE).unwrap();
    assert_eq!(report.received, 0);
    assert!(report.transmitted != 0);
    assert!(pair.server.counters().retained_input != 0);
    // The reservation over, the next such drive could replay the input,
    // and does not.
    pair.server.drive(pair.now, NO_RECEIVE).unwrap();
    assert!(pair.server.counters().retained_input != 0);
    assert_eq!(readables(&next_drain(&mut pair.server), server), 0);
    assert!(!pair.server.readiness(server).unwrap().readable);
    pair.server.drive(pair.now, BUDGET).unwrap();
    assert_eq!(pair.server.counters().retained_input, 0);
    assert_eq!(readables(&next_drain(&mut pair.server), server), 1);
    assert!(matches!(
        read(&mut pair.server, server, 1024),
        Ok(ReadOutcome::Data { len: 200, .. })
    ));
}

// The Readable a read queued is the connection's one event in the next
// drain, whatever is called in between: writes, readiness and transport
// state of this or other connections, the close of another.
#[test]
fn the_readable_a_read_queued_is_the_next_drains_event_after_other_calls() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    let (other_client, other) = pair.connected();
    pair.arrived(client, 600);
    pair.client
        .try_write(other_client, &[9; 100], WriteOptions::default())
        .unwrap();
    pair.steps(3);
    drain(&mut pair.server);
    assert!(matches!(
        read(&mut pair.server, server, 100),
        Ok(ReadOutcome::Data { len: 100, .. })
    ));
    pair.server
        .try_write(server, b"reply", WriteOptions::default())
        .unwrap();
    assert!(pair.server.readiness(server).unwrap().readable);
    assert!(pair.server.readiness(other).unwrap().readable);
    pair.server.transport_info(server).unwrap();
    pair.server.transport_info(other).unwrap();
    pair.server.send_progress(server).unwrap();
    pair.server.connection_info(server).unwrap();
    pair.server.close(other).unwrap();
    let events = next_drain(&mut pair.server);
    let mine: Vec<_> = events
        .iter()
        .filter(|e| match e {
            Event::Connected(id) | Event::Readable(id) | Event::Writable(id) => *id == server,
            Event::Closed { connection, .. } => *connection == server,
            _ => false,
        })
        .collect();
    assert_eq!(mine, [&Event::Readable(server)], "{events:?}");
    assert!(next_drain(&mut pair.server).is_empty());
}

// A connection's Connected and Closed come before its Readable, one event
// a drain: a read made before the drain that tells of a reset queues
// Readable, which the drain after that one gives.
#[test]
fn a_closed_due_comes_before_the_readable_a_read_queued() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    pair.arrived(client, 600);
    pair.client.abort(client).unwrap();
    pair.steps(3);
    assert!(matches!(
        read(&mut pair.server, server, 100),
        Ok(ReadOutcome::Data { len: 100, .. })
    ));
    assert!(pair.server.readiness(server).unwrap().readable);
    let mut out = [Event::NetworkStopped; 16];
    let report = pair.server.drain_events(&mut out);
    assert_eq!(
        out[..report.written],
        [Event::Closed {
            connection: server,
            reason: Some(CloseReason::Reset)
        }]
    );
    assert!(report.more);
    assert_eq!(next_drain(&mut pair.server), [Event::Readable(server)]);
}
