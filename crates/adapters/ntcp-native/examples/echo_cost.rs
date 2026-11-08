// CPU cost of a closed-loop 16-octet echo between two Networks on one
// thread, over in-memory Ethernet queues: the stack's share of what an
// embedding such as xylem spends per request, without a NIC or system calls.
// Like a DPDK embedding, both sides busy-poll: every iteration drives each
// Network, drains its events and polls every connection. Connections use
// TCP_NODELAY, ARP with permanent neighbors (no ARP traffic) and caller
// time in nanoseconds.
//
//   echo_cost [--connections N] [--requests N] [--repetitions N] [--idle-only]
//
// Prints `METRIC name=value` lines: nanoseconds and Network drives per
// completed request (both sides together), and nanoseconds of one idle drive
// plus event drain of the client with its connections open, each the
// minimum over repetitions. --idle-only measures (and profiles) only that.
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::{
    CallerTimebase, ConnId, EthernetNextHop, Event, Link, Network, NetworkConfig, ReadOutcome,
    WorkBudget, WriteOptions,
};
use std::{
    cell::RefCell,
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::ExitCode,
    rc::Rc,
    time::Instant,
};

const REQUEST_LEN: usize = 16;
const BUDGET: WorkBudget = WorkBudget::new(64, 64, 64, 64);
const MAC_A: [u8; 6] = [2, 0, 0, 0, 0, 1];
const MAC_B: [u8; 6] = [2, 0, 0, 0, 0, 2];
const IP_A: Ipv4Addr = Ipv4Addr::new(10, 73, 0, 1);
const IP_B: Ipv4Addr = Ipv4Addr::new(10, 73, 0, 2);
const PORT: u16 = 9000;

// Frames in flight, with their buffers reused, so the wire allocates nothing
// once warm.
#[derive(Default)]
struct Frames {
    queued: VecDeque<Vec<u8>>,
    spare: Vec<Vec<u8>>,
}
type Queue = Rc<RefCell<Frames>>;

struct Wire {
    incoming: Queue,
    outgoing: Queue,
}

impl PacketIo for Wire {
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ethernet
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        let mut frames = self.incoming.borrow_mut();
        let Some(frame) = frames.queued.pop_front() else {
            return Ok(None);
        };
        let len = frame.len();
        out[..len].copy_from_slice(&frame);
        frames.spare.push(frame);
        Ok(Some(len))
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        let mut frames = self.outgoing.borrow_mut();
        let mut frame = frames.spare.pop().unwrap_or_default();
        frame.clear();
        frame.extend_from_slice(packet);
        frames.queued.push_back(frame);
        Ok(TxOutcome::Submitted)
    }
}

struct Args {
    connections: usize,
    requests: u64,
    repetitions: usize,
    idle_only: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        connections: 4,
        requests: 200_000,
        repetitions: 5,
        idle_only: false,
    };
    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        if flag == "--idle-only" {
            args.idle_only = true;
            continue;
        }
        let value = iter.next().ok_or_else(|| format!("{flag} needs a value"))?;
        let bad = || format!("bad {flag} {value}");
        match flag.as_str() {
            "--connections" => args.connections = value.parse().map_err(|_| bad())?,
            "--requests" => args.requests = value.parse().map_err(|_| bad())?,
            "--repetitions" => args.repetitions = value.parse().map_err(|_| bad())?,
            _ => {
                return Err(
                    "usage: echo_cost [--connections N] [--requests N] [--repetitions N] \\
                     [--idle-only]"
                        .into(),
                );
            }
        }
    }
    if args.connections == 0 || args.requests == 0 || args.repetitions == 0 {
        return Err("counts must be positive".into());
    }
    Ok(args)
}

struct Clock(Instant);

impl Clock {
    fn now(&self) -> u64 {
        self.0.elapsed().as_nanos() as u64 + 1
    }
}

fn network(
    local: Ipv4Addr,
    mac: [u8; 6],
    peer: (Ipv4Addr, [u8; 6]),
    wire: Wire,
    args: &Args,
    now: u64,
) -> Network<Wire> {
    let mut config = NetworkConfig::new(IpAddr::V4(local), 1500);
    config.tcp.max_connections = args.connections;
    config.tcp.connection.timebase = CallerTimebase {
        units_per_second: 1_000_000_000,
        ..CallerTimebase::default()
    };
    config.link = Link::Ethernet {
        local_mac: mac,
        next_hop: EthernetNextHop::Arp {
            prefix_len: 24,
            gateway: None,
        },
    };
    config.static_neighbors = vec![peer];
    let secret = [local.octets()[3]; 32];
    Network::new(config, wire, secret, now).unwrap()
}

struct Bench {
    client: Network<Wire>,
    server: Network<Wire>,
    clients: Vec<ConnId>,
    servers: Vec<ConnId>,
    events: Vec<Event>,
    drives: u64,
}

impl Bench {
    fn new(args: &Args, clock: &Clock) -> Self {
        let (x, y) = (Queue::default(), Queue::default());
        let wire = |incoming: &Queue, outgoing: &Queue| Wire {
            incoming: incoming.clone(),
            outgoing: outgoing.clone(),
        };
        let client = network(IP_A, MAC_A, (IP_B, MAC_B), wire(&x, &y), args, clock.now());
        let server = network(IP_B, MAC_B, (IP_A, MAC_A), wire(&y, &x), args, clock.now());
        let mut bench = Self {
            client,
            server,
            clients: Vec::new(),
            servers: Vec::new(),
            events: vec![Event::NetworkStopped; 64],
            drives: 0,
        };
        let listener = bench.server.listen(PORT, args.connections).unwrap();
        for _ in 0..args.connections {
            let id = bench
                .client
                .connect(SocketAddr::new(IpAddr::V4(IP_B), PORT))
                .unwrap();
            bench.client.set_nodelay(id, true).unwrap();
            bench.clients.push(id);
        }
        while bench.servers.len() < args.connections {
            bench.drive(clock);
            match bench.server.accept(listener) {
                Ok(id) => {
                    bench.server.set_nodelay(id, true).unwrap();
                    bench.servers.push(id);
                }
                Err(error) if error.is_would_block() => {}
                Err(error) => panic!("accept: {error}"),
            }
        }
        bench
    }

    fn drive(&mut self, clock: &Clock) {
        for network in [&mut self.client, &mut self.server] {
            network.drive(clock.now(), BUDGET).unwrap();
            while network.drain_events(&mut self.events).more {}
        }
        self.drives += 2;
    }

    // Run the closed loop until `requests` responses complete; returns the
    // nanoseconds it took.
    fn run(&mut self, clock: &Clock, requests: u64) -> u64 {
        let connections = self.clients.len();
        let mut sent = vec![false; connections];
        let mut received = vec![0usize; connections];
        let mut buffer = [0u8; 64];
        let mut completed = 0;
        let started = clock.now();
        while completed < requests {
            for (index, &id) in self.clients.iter().enumerate() {
                if !sent[index] {
                    let receipt = self
                        .client
                        .try_write(id, &[index as u8; REQUEST_LEN], WriteOptions::default())
                        .unwrap();
                    assert_eq!(receipt.accepted, REQUEST_LEN);
                    sent[index] = true;
                }
            }
            self.drive(clock);
            for &id in &self.servers {
                match self.server.try_read(id, &mut buffer) {
                    Ok(ReadOutcome::Data { len, .. }) => {
                        let receipt = self
                            .server
                            .try_write(id, &buffer[..len], WriteOptions::default())
                            .unwrap();
                        assert_eq!(receipt.accepted, len);
                    }
                    Ok(ReadOutcome::EmptyBuffer) => {}
                    Err(error) if error.is_would_block() => {}
                    other => panic!("server read: {other:?}"),
                }
            }
            for (index, &id) in self.clients.iter().enumerate() {
                match self.client.try_read(id, &mut buffer) {
                    Ok(ReadOutcome::Data { len, .. }) => {
                        assert!(buffer[..len].iter().all(|&b| b == index as u8));
                        received[index] += len;
                        if received[index] == REQUEST_LEN {
                            received[index] = 0;
                            sent[index] = false;
                            completed += 1;
                        }
                    }
                    Ok(ReadOutcome::EmptyBuffer) => {}
                    Err(error) if error.is_would_block() => {}
                    other => panic!("client read: {other:?}"),
                }
            }
        }
        clock.now() - started
    }

    // Nanoseconds of `iterations` idle drives plus drains of the client.
    fn idle(&mut self, clock: &Clock, iterations: u64) -> u64 {
        let started = clock.now();
        for _ in 0..iterations {
            self.client.drive(clock.now(), BUDGET).unwrap();
            self.client.drain_events(&mut self.events);
        }
        clock.now() - started
    }
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(error) => {
            eprintln!("echo_cost: {error}");
            return ExitCode::FAILURE;
        }
    };
    let clock = Clock(Instant::now());
    let mut bench = Bench::new(&args, &clock);
    // Warm the connections' windows, buffers and caches.
    bench.run(&clock, args.requests / 10 + 1);
    // Let the last responses' acknowledgments settle before idling.
    for _ in 0..100 {
        bench.drive(&clock);
    }
    let mut best_ns = f64::INFINITY;
    let mut best_drives = f64::INFINITY;
    let mut best_idle = f64::INFINITY;
    for _ in 0..args.repetitions {
        if !args.idle_only {
            let drives = bench.drives;
            let elapsed = bench.run(&clock, args.requests);
            best_ns = best_ns.min(elapsed as f64 / args.requests as f64);
            best_drives = best_drives.min((bench.drives - drives) as f64 / args.requests as f64);
        }
        let elapsed = bench.idle(&clock, args.requests);
        best_idle = best_idle.min(elapsed as f64 / args.requests as f64);
    }
    println!("METRIC connections={}", args.connections);
    if !args.idle_only {
        println!("METRIC ns_per_request={best_ns:.1}");
        println!("METRIC drives_per_request={best_drives:.2}");
        println!("METRIC requests_per_second={:.0}", 1e9 / best_ns);
    }
    println!("METRIC idle_drive_ns={best_idle:.1}");
    ExitCode::SUCCESS
}
