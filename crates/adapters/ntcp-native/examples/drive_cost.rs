// Caller-side cost of one Network: an idle drive() plus drain_events(), and a
// 16-byte request/response round trip on one connection. Two Networks run
// back to back over in-memory queues. Two series: max_connections grows while
// four connections are live, and then the live connections, all idle but
// the one measured, grow at a fixed max_connections. With --check, exits
// nonzero unless both costs at the largest size of each series stay within
// their bounds of the cost at its smallest.
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::{
    ConnId, Event, Link, Network, NetworkConfig, ReadOutcome, WorkBudget, WriteOptions,
};
use std::{
    cell::RefCell,
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    process::ExitCode,
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
        PacketLayer::Ip
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
const SIZES: [usize; 4] = [16, 64, 256, 1024];
// Live connections, at max_connections of the largest.
const LIVE: [usize; 3] = [CONNECTIONS, 32, 128];
const IDLE_ITERATIONS: u32 = 20_000;
const ROUNDS: u32 = 2_000;
const REPETITIONS: usize = 5;
// --check bounds: the cost at 1024 over the cost at 16.
const IDLE_RATIO: f64 = 2.5;
const ROUND_TRIP_RATIO: f64 = 1.5;
// --check bound: the cost at 32 and 128 live connections over the cost at
// four. A drive does work for connections that have some, not for each live
// one.
const LIVE_RATIO: f64 = 1.25;

struct Pair {
    a: Network<Wire>,
    b: Network<Wire>,
    client: ConnId,
    server: ConnId,
}

fn now(start: Instant) -> u64 {
    start.elapsed().as_micros() as u64 + 1
}

fn drain(network: &mut Network<Wire>, events: &mut [Event]) {
    while network.drain_events(events).more {}
}

fn pair(max_connections: usize, live: usize, start: Instant) -> Pair {
    let (x, y) = (Queue::default(), Queue::default());
    let (ip_a, ip_b): (IpAddr, IpAddr) =
        ("10.73.0.1".parse().unwrap(), "10.73.0.2".parse().unwrap());
    let config = |address| {
        let mut config = NetworkConfig::new(address, 1500);
        config.link = Link::Ip;
        config.tcp.max_connections = max_connections;
        // The endpoint's buffer budget is not under test; the default admits
        // fewer than the largest series' connections.
        config.tcp.max_buffer_bytes = usize::MAX;
        config
    };
    let wire = |incoming: &Queue, outgoing: &Queue| Wire {
        incoming: incoming.clone(),
        outgoing: outgoing.clone(),
    };
    let mut a = Network::new(config(ip_a), wire(&x, &y), [1; 32], now(start)).unwrap();
    let mut b = Network::new(config(ip_b), wire(&y, &x), [2; 32], now(start)).unwrap();
    let listener = b.listen(9000, live).unwrap();
    let clients: Vec<_> = (0..live)
        .map(|_| a.connect(SocketAddr::new(ip_b, 9000)).unwrap())
        .collect();
    let mut servers = Vec::new();
    let mut events = [Event::NetworkStopped; 64];
    while servers.len() < live {
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
    // Settle the handshakes' acknowledgments and events.
    for _ in 0..1000 {
        a.drive(now(start), BUDGET).unwrap();
        b.drive(now(start), BUDGET).unwrap();
        drain(&mut a, &mut events);
        drain(&mut b, &mut events);
    }
    // The request and its response use the first connection.
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
    assert_eq!(received, 16);
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

fn main() -> ExitCode {
    let check = match std::env::args().nth(1).as_deref() {
        None => false,
        Some("--check") => true,
        Some(_) => {
            eprintln!("usage: drive_cost [--check]");
            return ExitCode::FAILURE;
        }
    };
    let start = Instant::now();
    let max = *LIVE.last().unwrap();
    let series: Vec<_> = SIZES
        .iter()
        .map(|&size| (format!("{size}"), size, CONNECTIONS))
        .chain(LIVE.iter().map(|&live| (format!("live{live}"), max, live)))
        .collect();
    let mut pairs: Vec<_> = series
        .iter()
        .map(|&(_, max, live)| pair(max, live, start))
        .collect();
    // Repetitions alternate between the sizes so that drift in machine load
    // or clock frequency reaches all of them alike; each keeps its minimum.
    let mut idle_us = vec![f64::INFINITY; series.len()];
    let mut round_trip_us = vec![f64::INFINITY; series.len()];
    for _ in 0..REPETITIONS {
        for (index, pair) in pairs.iter_mut().enumerate() {
            idle_us[index] = idle_us[index].min(idle(pair, start));
            round_trip_us[index] = round_trip_us[index].min(round_trip(pair, start));
        }
    }
    for (index, (name, ..)) in series.iter().enumerate() {
        println!("METRIC idle_drive_drain_us_{name}={:.3}", idle_us[index]);
        println!("METRIC round_trip_us_{name}={:.3}", round_trip_us[index]);
    }
    let mut failed = false;
    let mut compare = |what: &str, costs: &[f64], names: (&str, &str), bound: f64| {
        let ratio = costs[1] / costs[0];
        println!("{what} {}/{}: {ratio:.3} (bound {bound})", names.1, names.0);
        failed |= ratio > bound;
    };
    let last = SIZES.len() - 1;
    let names = (series[0].0.as_str(), series[last].0.as_str());
    compare(
        "idle drive+drain",
        &[idle_us[0], idle_us[last]],
        names,
        IDLE_RATIO,
    );
    compare(
        "round trip",
        &[round_trip_us[0], round_trip_us[last]],
        names,
        ROUND_TRIP_RATIO,
    );
    let first = SIZES.len();
    for index in first + 1..series.len() {
        let names = (series[first].0.as_str(), series[index].0.as_str());
        compare(
            "idle drive+drain",
            &[idle_us[first], idle_us[index]],
            names,
            LIVE_RATIO,
        );
        compare(
            "round trip",
            &[round_trip_us[first], round_trip_us[index]],
            names,
            LIVE_RATIO,
        );
    }
    if check && failed {
        eprintln!("drive cost grows with configured capacity or idle connections");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
