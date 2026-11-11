// The local ports a Network's opens take: an explicit port, or one of the
// ephemeral range, is refused while a connection or listener uses it, and
// taken again once the slot that used it is freed; an open finds no slot
// in a full table until one is freed. Two Networks over an in-memory IP
// wire.
use ntcp::EndpointError;
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::*;
use std::{
    cell::RefCell,
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    ops::RangeInclusive,
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
    IpAddr::from([10, 75, 0, side])
}

fn network(
    side: u8,
    incoming: &Queue,
    outgoing: &Queue,
    ports: RangeInclusive<u16>,
) -> Network<Wire> {
    let mut config = NetworkConfig::new(address(side), 1500);
    config.tcp.max_connections = 8;
    config.tcp.max_listeners = 2;
    config.tcp.connection.send_capacity = 2048;
    config.tcp.connection.receive_capacity = 8192;
    config.tcp.max_buffer_bytes = config.buffer_budget(8).unwrap();
    config.ephemeral_ports = ports;
    let wire = Wire {
        incoming: incoming.clone(),
        outgoing: outgoing.clone(),
    };
    Network::new(config, wire, [side; 32], 0).unwrap()
}

struct Pair {
    client: Network<Wire>,
    server: Network<Wire>,
    listener: ListenerId,
    now: u64,
}
impl Pair {
    fn new(client_ports: RangeInclusive<u16>, server_ports: RangeInclusive<u16>) -> Self {
        let (a, b) = (Queue::default(), Queue::default());
        let client = network(1, &a, &b, client_ports);
        let mut server = network(2, &b, &a, server_ports);
        let listener = server.listen(PORT, 8).unwrap();
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
        drain(&mut self.client);
        drain(&mut self.server);
    }
    fn steps(&mut self, n: usize) {
        for _ in 0..n {
            self.step();
        }
    }
    fn accepted(&mut self) -> ConnId {
        for _ in 0..100 {
            self.step();
            if let Ok(server) = self.server.accept(self.listener) {
                return server;
            }
        }
        panic!("handshake did not finish");
    }
    // Drives past TIME-WAIT until the client's `id` is reclaimed.
    fn reclaim(&mut self, id: ConnId) {
        self.now += self.client.config().tcp.connection.time_wait_us;
        for _ in 0..100 {
            self.step();
            if matches!(self.client.connection_info(id), Err(Error::InvalidHandle)) {
                return;
            }
        }
        panic!("the connection was not reclaimed");
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

fn local_port(network: &Network<Wire>, id: ConnId) -> u16 {
    network.connection_info(id).unwrap().local.port()
}

fn in_use<T: std::fmt::Debug>(result: Result<T>) -> bool {
    matches!(result, Err(Error::Tcp(EndpointError::AddressInUse)))
}

fn exhausted<T: std::fmt::Debug>(result: Result<T>) -> bool {
    matches!(result, Err(Error::Capacity))
}

// A closed connection's port stays taken through TIME-WAIT, after its
// released slot was freed into the endpoint's TIME-WAIT record, and is free
// after.
#[test]
fn a_closed_connections_port_is_taken_until_its_time_wait_ends() {
    let mut pair = Pair::new(40000..=40000, 50000..=50000);
    let server_address = SocketAddr::new(address(2), PORT);
    let client = pair.client.connect(server_address).unwrap();
    assert_eq!(local_port(&pair.client, client), 40000);
    let server = pair.accepted();
    pair.client.close(client).unwrap();
    pair.steps(4);
    assert!(matches!(
        pair.server.try_read(server, &mut [0; 8]),
        Ok(ReadOutcome::Eof)
    ));
    pair.server.close(server).unwrap();
    for _ in 0..100 {
        pair.step();
        if pair.client.counters().time_wait_connections == 1 {
            break;
        }
    }
    pair.steps(4);
    // The application closed it and drained its events: the slot is free.
    assert_eq!(pair.client.counters().time_wait_connections, 1);
    assert!(matches!(
        pair.client.connection_info(client),
        Err(Error::InvalidHandle)
    ));
    assert!(in_use(
        pair.client.connect_from(server_address, Some(40000))
    ));
    assert!(exhausted(pair.client.connect(server_address)));
    pair.reclaim(client);
    assert_eq!(pair.client.counters().time_wait_connections, 0);
    let next = pair.client.connect(server_address).unwrap();
    assert_eq!(local_port(&pair.client, next), 40000);
    pair.accepted();
}

// An aborted connection's port, the first of a wrapping ephemeral range,
// is the one the next open takes once it is reclaimed.
#[test]
fn an_exhausted_ephemeral_range_gives_back_reclaimed_ports_in_turn() {
    let mut pair = Pair::new(40000..=40003, 50000..=50000);
    let server_address = SocketAddr::new(address(2), PORT);
    let mut opened = Vec::new();
    for port in 40000..=40003 {
        let id = pair.client.connect(server_address).unwrap();
        assert_eq!(local_port(&pair.client, id), port);
        opened.push(id);
    }
    // Slots remain; ports do not.
    assert!(exhausted(pair.client.connect(server_address)));
    pair.steps(4);
    pair.client.abort(opened[1]).unwrap();
    pair.steps(4);
    assert!(exhausted(pair.client.connect(server_address)));
    pair.reclaim(opened[1]);
    let next = pair.client.connect(server_address).unwrap();
    assert_eq!(local_port(&pair.client, next), 40001);
    assert!(exhausted(pair.client.connect(server_address)));
}

// A listener's port is skipped by ephemeral opens and refused to explicit
// ones until the listener's slot is freed, as is a port an explicit open
// took, whatever the peer.
#[test]
fn listeners_and_explicit_opens_take_their_ports() {
    let mut pair = Pair::new(40000..=40000, PORT..=PORT + 2);
    let client_address = SocketAddr::new(address(1), 7000);
    let other_client = SocketAddr::new(address(1), 7001);
    assert!(in_use(pair.server.connect_from(client_address, Some(PORT))));
    assert!(matches!(
        pair.server.connect_from(client_address, Some(0)),
        Err(Error::InvalidConfig(_))
    ));
    let explicit = pair
        .server
        .connect_from(client_address, Some(PORT + 1))
        .unwrap();
    assert_eq!(local_port(&pair.server, explicit), PORT + 1);
    assert!(in_use(
        pair.server.connect_from(other_client, Some(PORT + 1))
    ));
    let ephemeral = pair.server.connect(client_address).unwrap();
    assert_eq!(local_port(&pair.server, ephemeral), PORT + 2);
    assert!(exhausted(pair.server.connect(other_client)));
    // A closing listener holds its port until a drive frees its slot.
    pair.server.close_listener(pair.listener).unwrap();
    assert!(in_use(pair.server.connect_from(client_address, Some(PORT))));
    pair.step();
    let reused = pair.server.connect(other_client).unwrap();
    assert_eq!(local_port(&pair.server, reused), PORT);
}

// The connections a listener accepted share its port, and keep it taken
// after the listener is gone.
#[test]
fn accepted_connections_keep_their_listeners_port() {
    let mut pair = Pair::new(40000..=40001, 50000..=50000);
    let server_address = SocketAddr::new(address(2), PORT);
    let client_address = SocketAddr::new(address(1), 7000);
    pair.client.connect(server_address).unwrap();
    let first = pair.accepted();
    pair.client.connect(server_address).unwrap();
    let second = pair.accepted();
    assert_eq!(local_port(&pair.server, first), PORT);
    assert_eq!(local_port(&pair.server, second), PORT);
    pair.server.close_listener(pair.listener).unwrap();
    pair.steps(2);
    assert!(matches!(
        pair.server.acceptable(pair.listener),
        Err(Error::InvalidHandle)
    ));
    assert!(in_use(pair.server.connect_from(client_address, Some(PORT))));
    pair.server.abort(first).unwrap();
    pair.steps(4);
    assert!(in_use(pair.server.connect_from(client_address, Some(PORT))));
}

// A full table of connections or listeners refuses opens until a slot is
// freed, an aborted connection's once it is reclaimed and a closed
// listener's at the next drive, and then gives back that slot only, under a
// handle its old one cannot reach.
#[test]
fn a_full_table_takes_again_only_the_slots_freed() {
    let mut pair = Pair::new(40000..=40015, 50000..=50000);
    let server_address = SocketAddr::new(address(2), PORT);
    let opened: Vec<_> = (0..8)
        .map(|_| pair.client.connect(server_address).unwrap())
        .collect();
    // Ports remain; slots do not.
    assert!(exhausted(pair.client.connect(server_address)));
    pair.steps(4);
    pair.client.abort(opened[3]).unwrap();
    pair.steps(4);
    assert!(exhausted(pair.client.connect(server_address)));
    pair.reclaim(opened[3]);
    let next = pair.client.connect(server_address).unwrap();
    assert!(!opened.contains(&next));
    assert!(matches!(
        pair.client.connection_info(opened[3]),
        Err(Error::InvalidHandle)
    ));
    assert!(exhausted(pair.client.connect(server_address)));

    let second = pair.server.listen(PORT + 1, 8).unwrap();
    assert!(exhausted(pair.server.listen(PORT + 2, 8)));
    pair.server.close_listener(second).unwrap();
    assert!(exhausted(pair.server.listen(PORT + 2, 8)));
    pair.step();
    let third = pair.server.listen(PORT + 2, 8).unwrap();
    assert_ne!(third, second);
    assert!(matches!(
        pair.server.acceptable(second),
        Err(Error::InvalidHandle)
    ));
    assert!(pair.server.acceptable(third).is_ok());
    assert!(exhausted(pair.server.listen(PORT + 3, 8)));
}

// A server that closes first frees each connection's slot once TIME-WAIT
// holds only its tuple: four times its eight slots of short connections
// complete within one TIME-WAIT period.
#[test]
fn server_closed_connections_beyond_the_slots_within_one_time_wait() {
    let mut pair = Pair::new(40000..=40100, 50000..=50000);
    let server_address = SocketAddr::new(address(2), PORT);
    for n in 1..=32 {
        let client = pair.client.connect(server_address).unwrap();
        let server = pair.accepted();
        pair.server.close(server).unwrap();
        for _ in 0..100 {
            pair.step();
            if matches!(
                pair.client.try_read(client, &mut [0; 8]),
                Ok(ReadOutcome::Eof)
            ) {
                break;
            }
        }
        pair.client.close(client).unwrap();
        for _ in 0..100 {
            pair.step();
            if pair.server.counters().time_wait_connections == n
                && matches!(
                    pair.server.connection_info(server),
                    Err(Error::InvalidHandle)
                )
            {
                break;
            }
        }
        assert_eq!(pair.server.counters().time_wait_connections, n);
    }
    assert!(pair.now < pair.server.config().tcp.connection.time_wait_us);
}
