// Network::readiness and Network::acceptable: the state a level-triggered
// embedding polls, and the events a condition it reports false raises
// once it becomes true. Two Networks over an in-memory IP wire.
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::*;
use std::{
    cell::RefCell,
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    rc::Rc,
};

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

struct Wire {
    incoming: Queue,
    outgoing: Queue,
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
        self.outgoing.borrow_mut().push_back(packet.to_vec());
        Ok(TxOutcome::Submitted)
    }
}

const BUDGET: WorkBudget = WorkBudget::new(32, 32, 32, 32);
const PORT: u16 = 9000;

fn address(side: u8) -> IpAddr {
    IpAddr::from([10, 74, 0, side])
}

fn network(side: u8, incoming: &Queue, outgoing: &Queue) -> Network<Wire> {
    let mut config = NetworkConfig::new(address(side), 1500);
    config.tcp.max_connections = 8;
    config.tcp.max_listeners = 2;
    config.tcp.connection.send_capacity = 2048;
    // A fixed send limit for the tests that fill it, where
    // NetworkConfig::new's limit rises to 4 MiB.
    config.tcp.connection.send_capacity_max = 0;
    config.tcp.connection.receive_capacity = 8192;
    let wire = Wire {
        incoming: incoming.clone(),
        outgoing: outgoing.clone(),
    };
    // buffer_budget admits the connections with no room to write: a writer
    // also allocates its send ring (2 bytes a byte of send_capacity) and its
    // RACK and SACK ledgers (68 bytes a byte held queued, and the replaced
    // ones while they grow).
    config.tcp.max_buffer_bytes = config.buffer_budget(8, &wire).unwrap()
        + 8 * (72 * config.tcp.connection.send_capacity + 65536);
    Network::new(config, wire, [side; 32], 0).unwrap()
}

struct Pair {
    client: Network<Wire>,
    server: Network<Wire>,
    listener: ListenerId,
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

fn write_all(network: &mut Network<Wire>, id: ConnId, data: &[u8]) -> usize {
    match network.try_write(id, data, WriteOptions::default()) {
        Ok(receipt) => receipt.accepted,
        Err(error) if error.is_would_block() => 0,
        Err(error) => panic!("write: {error:?}"),
    }
}

// Reads until the connection would block; returns the octets read.
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

const OPEN: Readiness = Readiness {
    readable: false,
    writable: true,
    read_closed: false,
    closed: false,
};

#[test]
fn readiness_stays_while_data_waits_and_ends_when_it_is_read() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    assert_eq!(pair.server.readiness(server).unwrap(), OPEN);
    assert_eq!(write_all(&mut pair.client, client, &[7; 600]), 600);
    pair.steps(3);
    assert!(drain(&mut pair.server).contains(&Event::Readable(server)));
    // The event told of the change once; the state stays as long as the
    // data does, read in part or not at all.
    for _ in 0..2 {
        assert!(!drain(&mut pair.server).contains(&Event::Readable(server)));
        assert!(pair.server.readiness(server).unwrap().readable);
    }
    let mut out = [0; 100];
    assert!(matches!(
        pair.server.try_read(server, &mut out),
        Ok(ReadOutcome::Data { len: 100, .. })
    ));
    assert!(pair.server.readiness(server).unwrap().readable);
    assert_eq!(read_all(&mut pair.server, server), 500);
    assert_eq!(pair.server.readiness(server).unwrap(), OPEN);
    drain(&mut pair.server);
    // Data after a readiness that found none raises Readable.
    assert_eq!(write_all(&mut pair.client, client, &[8; 10]), 10);
    let mut readable = false;
    for _ in 0..400 {
        pair.step();
        readable |= drain(&mut pair.server).contains(&Event::Readable(server));
    }
    assert!(readable);
    assert!(pair.server.readiness(server).unwrap().readable);
}

fn readable(network: &mut Network<Wire>, id: ConnId) -> usize {
    drain(network)
        .iter()
        .filter(|&&e| e == Event::Readable(id))
        .count()
}

// As Linux wakes a socket for every segment it queues, each arrival of data
// or of the peer's FIN raises Readable, also while earlier data is unread and
// no read armed it; arrivals between two drains give one event, and segments
// that bring nothing to read give none.
#[test]
fn each_arrival_raises_readable_while_earlier_data_is_unread() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    assert_eq!(write_all(&mut pair.client, client, &[1; 10]), 10);
    pair.steps(3);
    assert_eq!(readable(&mut pair.server, server), 1);
    assert_eq!(write_all(&mut pair.client, client, &[2; 10]), 10);
    pair.steps(3);
    assert_eq!(readable(&mut pair.server, server), 1);
    for byte in [3, 4] {
        assert_eq!(write_all(&mut pair.client, client, &[byte; 10]), 10);
        pair.steps(3);
    }
    assert_eq!(readable(&mut pair.server, server), 1);
    // The server's own data, and the client's acknowledgment of it.
    assert_eq!(write_all(&mut pair.server, server, &[5; 100]), 100);
    pair.steps(400);
    assert_eq!(read_all(&mut pair.client, client), 100);
    pair.steps(400);
    assert_eq!(pair.server.send_progress(server).unwrap().acknowledged, 100);
    assert_eq!(readable(&mut pair.server, server), 0);
    pair.client.shutdown_write(client).unwrap();
    pair.steps(3);
    assert_eq!(readable(&mut pair.server, server), 1);
    assert_eq!(read_all_until_eof(&mut pair.server, server), 40);
}

fn read_all_until_eof(network: &mut Network<Wire>, id: ConnId) -> usize {
    let mut out = [0; 512];
    let mut total = 0;
    loop {
        match network.try_read(id, &mut out) {
            Ok(ReadOutcome::Data { len, .. }) => total += len,
            Ok(ReadOutcome::Eof) => return total,
            other => panic!("read: {other:?}"),
        }
    }
}

// A partial write that fills the send buffer arms nothing; a readiness
// that finds it full arms Writable, as a refused write does.
#[test]
fn a_full_send_buffer_found_by_readiness_raises_writable_when_it_drains() {
    for ask in [false, true] {
        let mut pair = Pair::new();
        let (client, server) = pair.connected();
        let accepted = write_all(&mut pair.client, client, &[1; 16384]);
        assert!(accepted > 0 && accepted < 16384, "{accepted}");
        if ask {
            let readiness = pair.client.readiness(client).unwrap();
            assert!(!readiness.writable, "{readiness:?}");
        }
        let mut writable = false;
        for _ in 0..400 {
            pair.step();
            read_all(&mut pair.server, server);
            writable |= drain(&mut pair.client).contains(&Event::Writable(client));
        }
        assert_eq!(writable, ask, "asked {ask}");
        assert!(pair.client.readiness(client).unwrap().writable);
    }
}

#[test]
fn readiness_follows_each_side_of_a_close() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    pair.client.shutdown_write(client).unwrap();
    pair.steps(3);
    let half = Readiness {
        readable: true,
        writable: true,
        read_closed: true,
        closed: false,
    };
    assert_eq!(pair.server.readiness(server).unwrap(), half);
    let readiness = pair.client.readiness(client).unwrap();
    assert!(!readiness.writable && !readiness.read_closed && !readiness.closed);
    pair.server.shutdown_write(server).unwrap();
    pair.steps(3);
    for (network, id) in [(&mut pair.client, client), (&mut pair.server, server)] {
        let readiness = network.readiness(id).unwrap();
        assert!(readiness.readable && readiness.read_closed && readiness.closed);
        assert!(!readiness.writable);
    }
    assert_eq!(
        pair.client.connection_info(client).unwrap().reason,
        Some(CloseReason::Normal)
    );
}

#[test]
fn a_reset_reads_as_closed_with_its_reason() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    pair.client.abort(client).unwrap();
    pair.steps(3);
    let readiness = pair.server.readiness(server).unwrap();
    assert!(readiness.readable && readiness.read_closed && readiness.closed);
    assert!(!readiness.writable);
    assert_eq!(
        pair.server.connection_info(server).unwrap().reason,
        Some(CloseReason::Reset)
    );
    // An application that closed or aborted a connection asks no more.
    assert!(matches!(
        pair.client.readiness(client),
        Err(Error::InvalidHandle)
    ));
    pair.server.close(server).unwrap();
    assert!(matches!(
        pair.server.readiness(server),
        Err(Error::InvalidHandle)
    ));
}

#[test]
fn a_connecting_connection_is_ready_for_nothing_until_connected() {
    let mut pair = Pair::new();
    let client = pair
        .client
        .connect(SocketAddr::new(address(2), PORT))
        .unwrap();
    assert_eq!(pair.client.readiness(client).unwrap(), Readiness::default());
    let mut connected = false;
    for _ in 0..20 {
        pair.step();
        connected |= drain(&mut pair.client).contains(&Event::Connected(client));
    }
    assert!(connected);
    assert_eq!(pair.client.readiness(client).unwrap(), OPEN);
}

#[test]
fn acceptable_tells_whether_accept_would_give_a_connection() {
    let mut pair = Pair::new();
    assert!(!pair.server.acceptable(pair.listener).unwrap());
    for _ in 0..2 {
        pair.client
            .connect(SocketAddr::new(address(2), PORT))
            .unwrap();
    }
    pair.steps(5);
    assert!(pair.server.acceptable(pair.listener).unwrap());
    pair.server.accept(pair.listener).unwrap();
    assert!(pair.server.acceptable(pair.listener).unwrap());
    pair.server.accept(pair.listener).unwrap();
    assert!(!pair.server.acceptable(pair.listener).unwrap());
    pair.server.close_listener(pair.listener).unwrap();
    assert!(matches!(
        pair.server.acceptable(pair.listener),
        Err(Error::InvalidHandle)
    ));
}
