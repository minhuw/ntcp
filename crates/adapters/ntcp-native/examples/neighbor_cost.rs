// Caller-side cost of IPv4 neighbor resolution on an Ethernet port whose
// next hops ARP resolves: an idle drive() plus drain_events(), and a 16-byte
// request/response round trip over four connections' first, for side A
// with its own table and as a member of a shared table of one and of four
// members (the other three idle). Side B keeps its own table. Two Networks
// run back to back over in-memory queues on one thread.
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::{
    ConnId, EthernetNextHop, Event, Link, Network, NetworkConfig, ReadOutcome,
    SharedNeighborLimits, SharedNeighbors, WorkBudget, WriteOptions,
};
use std::{
    cell::RefCell,
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    rc::Rc,
    time::Instant,
};

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;
struct Wire {
    incoming: Queue,
    outgoing: Queue,
}
impl PacketIo for Wire {
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ethernet
    }
    fn max_packet_len(&self) -> Option<usize> {
        Some(1514)
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        Ok(self.incoming.borrow_mut().pop_front().map(|packet| {
            out[..packet.len()].copy_from_slice(&packet);
            packet.len()
        }))
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        self.outgoing.borrow_mut().push_back(packet.to_vec());
        Ok(TxOutcome::Submitted)
    }
}

const BUDGET: WorkBudget = WorkBudget::new(64, 64, 64, 64);
const CONNECTIONS: usize = 4;
const MAX_CONNECTIONS: usize = 16;
const IDLE_ITERATIONS: u32 = 20_000;
const ROUNDS: u32 = 2_000;
const REPETITIONS: usize = 5;
const MAC_A: [u8; 6] = [2, 0, 0, 0, 0, 1];
const MAC_B: [u8; 6] = [2, 0, 0, 0, 0, 2];

struct Pair {
    a: Network<Wire>,
    b: Network<Wire>,
    client: ConnId,
    server: ConnId,
    // The other members of A's table, idle.
    _others: Vec<Network<Wire>>,
}

fn now(start: Instant) -> u64 {
    start.elapsed().as_micros() as u64 + 1
}

fn drain(network: &mut Network<Wire>, events: &mut [Event]) {
    while network.drain_events(events).more {}
}

fn config(address: Ipv4Addr, mac: [u8; 6]) -> NetworkConfig {
    let mut config = NetworkConfig::new(IpAddr::V4(address), 1500);
    config.tcp.max_connections = MAX_CONNECTIONS;
    config.link = Link::Ethernet {
        local_mac: mac,
        next_hop: EthernetNextHop::Arp {
            prefix_len: 24,
            gateway: None,
        },
    };
    config
}

// Side A with its own table (`members` 0) or as the first of `members`.
fn pair(members: usize, start: Instant) -> Pair {
    let (x, y) = (Queue::default(), Queue::default());
    let ip_a = Ipv4Addr::new(10, 73, 0, 1);
    let ip_b = Ipv4Addr::new(10, 73, 0, 100);
    let wire = |incoming: &Queue, outgoing: &Queue| Wire {
        incoming: incoming.clone(),
        outgoing: outgoing.clone(),
    };
    let (mut a, others) = if members == 0 {
        let a = Network::new(config(ip_a, MAC_A), wire(&x, &y), [1; 32], now(start)).unwrap();
        (a, Vec::new())
    } else {
        let limits = SharedNeighborLimits {
            members,
            entries: 16,
            held: members * (MAX_CONNECTIONS + 1),
            replies: 16,
        };
        let table = SharedNeighbors::new(MAC_A, 1_000_000, limits).unwrap();
        let mut networks: Vec<_> = (0..members)
            .map(|k| {
                let address = Ipv4Addr::new(10, 73, 0, 1 + k as u8);
                let (incoming, outgoing) = if k == 0 {
                    (x.clone(), y.clone())
                } else {
                    (Queue::default(), Queue::default())
                };
                Network::with_shared_neighbors(
                    config(address, MAC_A),
                    wire(&incoming, &outgoing),
                    [1 + k as u8; 32],
                    now(start),
                    &table,
                )
                .unwrap()
            })
            .collect();
        let a = networks.remove(0);
        (a, networks)
    };
    let mut b = Network::new(config(ip_b, MAC_B), wire(&y, &x), [2; 32], now(start)).unwrap();
    let listener = b.listen(9000, CONNECTIONS).unwrap();
    let clients: Vec<_> = (0..CONNECTIONS)
        .map(|_| a.connect(SocketAddr::new(ip_b.into(), 9000)).unwrap())
        .collect();
    let mut servers = Vec::new();
    let mut events = [Event::NetworkStopped; 64];
    while servers.len() < CONNECTIONS {
        a.drive(now(start), BUDGET).unwrap();
        b.drive(now(start), BUDGET).unwrap();
        drain(&mut a, &mut events);
        drain(&mut b, &mut events);
        match b.accept(listener) {
            Ok(server) => servers.push(server),
            Err(error) if error.is_would_block() => {}
            Err(error) => panic!("accept: {error}"),
        }
    }
    for (&client, &server) in clients.iter().zip(&servers) {
        a.set_nodelay(client, true).unwrap();
        b.set_nodelay(server, true).unwrap();
    }
    for _ in 0..1000 {
        a.drive(now(start), BUDGET).unwrap();
        b.drive(now(start), BUDGET).unwrap();
        drain(&mut a, &mut events);
        drain(&mut b, &mut events);
    }
    let local = a.connection_info(clients[0]).unwrap().local;
    let server = *servers
        .iter()
        .find(|&&s| b.connection_info(s).unwrap().peer == local)
        .unwrap();
    Pair {
        a,
        b,
        client: clients[0],
        server,
        _others: others,
    }
}

// Mean microseconds of one idle drive() plus drain_events() on side A.
fn idle(pair: &mut Pair, start: Instant) -> f64 {
    let mut events = [Event::NetworkStopped; 64];
    let t = Instant::now();
    for _ in 0..IDLE_ITERATIONS {
        pair.a.drive(now(start), BUDGET).unwrap();
        pair.a.drain_events(&mut events);
    }
    t.elapsed().as_secs_f64() * 1e6 / f64::from(IDLE_ITERATIONS)
}

fn receive(
    network: &mut Network<Wire>,
    peer: &mut Network<Wire>,
    id: ConnId,
    start: Instant,
    events: &mut [Event],
    buffer: &mut [u8],
) {
    let mut received = 0;
    while received < 16 {
        peer.drive(now(start), BUDGET).unwrap();
        peer.drain_events(events);
        network.drive(now(start), BUDGET).unwrap();
        network.drain_events(events);
        if let Ok(ReadOutcome::Data { len, .. }) = network.try_read(id, buffer) {
            received += len;
        }
    }
}

// Mean microseconds of a 16-byte request from A and B's 16-byte response.
fn round_trip(pair: &mut Pair, start: Instant) -> f64 {
    let mut events = [Event::NetworkStopped; 64];
    let mut buffer = [0; 64];
    let t = Instant::now();
    for _ in 0..ROUNDS {
        let written = pair
            .a
            .try_write(pair.client, &[7; 16], WriteOptions::default());
        assert_eq!(written.unwrap().accepted, 16);
        receive(
            &mut pair.b,
            &mut pair.a,
            pair.server,
            start,
            &mut events,
            &mut buffer,
        );
        let written = pair
            .b
            .try_write(pair.server, &[8; 16], WriteOptions::default());
        assert_eq!(written.unwrap().accepted, 16);
        receive(
            &mut pair.a,
            &mut pair.b,
            pair.client,
            start,
            &mut events,
            &mut buffer,
        );
    }
    t.elapsed().as_secs_f64() * 1e6 / f64::from(ROUNDS)
}

fn main() {
    let start = Instant::now();
    let variants = [("private", 0), ("shared1", 1), ("shared4", 4)];
    let mut pairs: Vec<_> = variants
        .iter()
        .map(|&(_, members)| pair(members, start))
        .collect();
    // Repetitions alternate between the variants so that drift in machine
    // load or clock frequency reaches all of them alike; each keeps its
    // minimum.
    let mut idle_us = [f64::INFINITY; 3];
    let mut round_trip_us = [f64::INFINITY; 3];
    for _ in 0..REPETITIONS {
        for (index, pair) in pairs.iter_mut().enumerate() {
            idle_us[index] = idle_us[index].min(idle(pair, start));
            round_trip_us[index] = round_trip_us[index].min(round_trip(pair, start));
        }
    }
    for (index, (name, _)) in variants.iter().enumerate() {
        println!("METRIC idle_drive_drain_us_{name}={:.3}", idle_us[index]);
        println!("METRIC round_trip_us_{name}={:.3}", round_trip_us[index]);
    }
    for index in 1..variants.len() {
        println!(
            "{} over private: idle {:.3}, round trip {:.3}",
            variants[index].0,
            idle_us[index] / idle_us[0],
            round_trip_us[index] / round_trip_us[0]
        );
    }
}
