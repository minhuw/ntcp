// CPU cost of being a member of shared flows, per closed-loop 16-octet
// request and response, all Networks on one thread over in-memory Ethernet
// queues as in echo_cost. The clients are n Networks on the n receive
// queues of one port, each opening its share of the connections to one
// plain server Network, and every iteration drives each of them and the
// server. Three series for each n:
//
//   a<n>  n plain Networks (`Network::new`), each with its own address, its
//         frames steered to it by destination address: the baseline.
//   b<n>  n members of `FlowOwnership::Hash` flows (DEFAULT_FLOW_KEY, a
//         round-robin table) on one shared address, steered by a NIC model
//         that hashes with the members' key and table: no handoffs, so
//         b - a is the classification and Toeplitz hash every member pays
//         per packet it receives.
//   c<n>  the same members behind a NIC with one receive queue: member 0
//         receives every frame and hands those of the other members' flows
//         to their inboxes, so c - b is the cost of a handoff (the copy into
//         the inbox, the drain, the input).
//
// The in-memory port and dispatcher cost the same for a frame in every
// series but for the choice of queue. The NIC model hashes each flow once
// and remembers its queue by destination port, as hardware hashes for free,
// and the cost of moving one frame through the port and dispatcher of each
// series is measured on its own (transmit, steer, receive) and subtracted:
// the `stack_` metrics and the derived per-packet costs exclude it. Members
// join without a shared neighbor table (static neighbors, as the plain
// Networks have), so these costs are the flows' alone; neighbor_cost
// measures the table's.
//
//   flows_cost [--check] [--requests N] [--repetitions N] [--series NAME]
//
// Prints `METRIC name=value` lines: per series the median over repetitions,
// interleaved, of nanoseconds per request (all Networks together), of the
// same less the port and dispatcher, of the packets the clients receive
// and hand off per request, and of an idle drive plus event drain of
// client 0; then the derived costs, from differences within each
// repetition. --series
// runs only one series (to profile it). With --check, exits nonzero unless
// the handoff counters are as the steering dictates and the costs stay
// within the bounds below.
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::{
    CallerTimebase, ConnId, DEFAULT_FLOW_KEY, EthernetNextHop, Event, FlowOwnership, Link, Network,
    NetworkConfig, ReadOutcome, SharedFlowLimits, SharedFlows, WorkBudget, WriteOptions,
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
const PORT_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const PEER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
// The members' shared address, and the first of the plain clients'.
const ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 73, 0, 1);
const PEER: Ipv4Addr = Ipv4Addr::new(10, 73, 0, 100);
const PORT: u16 = 9000;
const SECRET: [u8; 32] = [7; 32];
// Connections over all clients; each of n clients opens CONNECTIONS / n.
const CONNECTIONS: usize = 8;
const GROUPS: [usize; 2] = [2, 4];
const TABLE: usize = 128;
const INBOX: usize = 256;
const WIRE_PACKETS: usize = 200_000;
const IDLE_ITERATIONS: u64 = 20_000;
// --check bound: b over a, the stack cost per request (port and dispatcher
// excluded) of members over that of plain Networks. A member classifies
// each packet it receives and hashes 12 octets with byte tables, some 120
// instructions, measured at 0-60 ns over a round trip of about 9.5 us, a
// ratio within 1.006. The bound leaves room for that run-to-run noise and
// fails when membership costs some 250 ns more per packet, several times
// what classification costs.
const MEMBER_RATIO: f64 = 1.03;
// --check bound: c over b. A handed-off packet costs a copy into an inbox
// slot, the drain and the atomics on both sides besides its input, some
// 330 instructions, measured at a ratio within 1.009 with half and three
// quarters of the packets handed off. This fails when a handoff costs
// some 400 ns, several times what it costs, or a good part of a second
// receive path.
const HANDOFF_RATIO: f64 = 1.04;
// --check bound: b over a, the idle drive plus drain of member 0 over that
// of a plain Network. A member's drive also clears its wake flag and looks
// at its inbox, measured at 7-9 ns over about 295 ns, a ratio within
// 1.035; this fails at some 25 ns more, a lock or a second atomic per drive.
const IDLE_RATIO: f64 = 1.08;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Plain,
    Ideal,
    Queue0,
}

impl Kind {
    fn name(self, members: usize) -> String {
        let letter = match self {
            Self::Plain => 'a',
            Self::Ideal => 'b',
            Self::Queue0 => 'c',
        };
        format!("{letter}{members}")
    }

    // The port's steering of the server's frames to the clients' queues.
    fn steer(self, members: usize) -> Steer {
        match self {
            Self::Plain => Steer::ByDestination,
            Self::Ideal => Steer::rss(members),
            Self::Queue0 => Steer::Queue0,
        }
    }
}

// Frames in flight, with their buffers reused, so the wire allocates nothing
// once warm.
#[derive(Default)]
struct Frames {
    queued: VecDeque<Vec<u8>>,
    spare: Vec<Vec<u8>>,
}
type Queue = Rc<RefCell<Frames>>;

// The port's choice of receive queue for a frame the server sends.
enum Steer {
    // One receive queue: the server's own interface, and a port without
    // receive-side scaling.
    Queue0,
    // The queue numbered by the destination address, counted from ADDRESS:
    // per-address flow rules for plain Networks.
    ByDestination,
    // Receive-side scaling with the members' key and table. The hash of a
    // flow from the server's port is computed once and its queue remembered
    // by destination port, as a NIC hashes in hardware for free.
    Rss { table: Vec<usize>, queues: Vec<u8> },
}

const UNKNOWN: u8 = u8::MAX;

impl Steer {
    fn rss(members: usize) -> Self {
        Self::Rss {
            table: round_robin(members),
            queues: vec![UNKNOWN; 1 << 16],
        }
    }

    fn queue(&mut self, frame: &[u8]) -> usize {
        if frame.len() < 34 || frame[12..14] != [0x08, 0x00] {
            return 0;
        }
        let ip = &frame[14..];
        match self {
            Self::Queue0 => 0,
            Self::ByDestination => usize::from(ip[19] - ADDRESS.octets()[3]),
            Self::Rss { table, queues } => {
                let header = usize::from(ip[0] & 15) * 4;
                let unfragmented = u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff == 0;
                let Some(ports) = ip
                    .get(header..header + 4)
                    .filter(|_| ip[9] == 6 && unfragmented)
                else {
                    return table[toeplitz(&ip[12..20]) as usize & (TABLE - 1)];
                };
                let hash = || {
                    let mut input = [0; 12];
                    input[..8].copy_from_slice(&ip[12..20]);
                    input[8..].copy_from_slice(ports);
                    table[toeplitz(&input) as usize & (TABLE - 1)]
                };
                if ip[12..16] != PEER.octets() || ports[..2] != PORT.to_be_bytes() {
                    return hash();
                }
                let at = usize::from(u16::from_be_bytes([ports[2], ports[3]]));
                if queues[at] == UNKNOWN {
                    queues[at] = hash() as u8;
                }
                usize::from(queues[at])
            }
        }
    }
}

// RSS's Toeplitz hash under DEFAULT_FLOW_KEY, written out here so that the
// NIC model is independent of the crate: every set bit i of the input,
// counted from the most significant bit of its first octet, contributes the
// 32 key bits that start at bit i.
fn toeplitz(input: &[u8]) -> u32 {
    let bit = |bytes: &[u8], i: usize| bytes[i / 8] >> (7 - i % 8) & 1;
    (0..input.len() * 8)
        .filter(|&i| bit(input, i) == 1)
        .map(|i| {
            (0..32).fold(0u32, |w, j| {
                w << 1 | u32::from(bit(&DEFAULT_FLOW_KEY, i + j))
            })
        })
        .fold(0, |hash, window| hash ^ window)
}

fn round_robin(members: usize) -> Vec<usize> {
    (0..TABLE).map(|i| i % members).collect()
}

struct Wire {
    incoming: Queue,
    // The receive queues this side's frames go to, and the choice among them.
    queues: Vec<Queue>,
    steer: Steer,
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
        let queue = self.steer.queue(packet);
        let mut frames = self.queues[queue].borrow_mut();
        let mut frame = frames.spare.pop().unwrap_or_default();
        frame.clear();
        frame.extend_from_slice(packet);
        frames.queued.push_back(frame);
        Ok(TxOutcome::Submitted)
    }
}

struct Args {
    check: bool,
    requests: u64,
    repetitions: usize,
    series: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        check: false,
        requests: 50_000,
        repetitions: 7,
        series: None,
    };
    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        if flag == "--check" {
            args.check = true;
            continue;
        }
        let value = iter.next().ok_or_else(|| format!("{flag} needs a value"))?;
        let bad = || format!("bad {flag} {value}");
        match flag.as_str() {
            "--requests" => args.requests = value.parse().map_err(|_| bad())?,
            "--repetitions" => args.repetitions = value.parse().map_err(|_| bad())?,
            "--series" => args.series = Some(value),
            _ => {
                return Err(
                    "usage: flows_cost [--check] [--requests N] [--repetitions N] \
                     [--series a2|b2|c2|a4|b4|c4]"
                        .into(),
                );
            }
        }
    }
    if args.requests == 0 || args.repetitions == 0 {
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

fn config(local: Ipv4Addr, mac: [u8; 6], neighbors: Vec<(Ipv4Addr, [u8; 6])>) -> NetworkConfig {
    let mut config = NetworkConfig::new(IpAddr::V4(local), 1500);
    config.tcp.max_connections = CONNECTIONS;
    // The endpoint's buffer budget is not under test.
    config.tcp.max_buffer_bytes = usize::MAX;
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
    config.static_neighbors = neighbors;
    config
}

// The packets the clients received from their queues and handed over,
// and those the server received.
#[derive(Clone, Copy, Default)]
struct Totals {
    received: u64,
    handed_off: u64,
    handoffs_received: u64,
    handoffs_dropped: u64,
    server_received: u64,
}

struct Bench {
    kind: Kind,
    clients: Vec<Network<Wire>>,
    server: Network<Wire>,
    // Each connection's client.
    connections: Vec<(usize, ConnId)>,
    servers: Vec<ConnId>,
    events: Vec<Event>,
}

impl Bench {
    fn new(kind: Kind, members: usize, clock: &Clock) -> Self {
        let queues: Vec<Queue> = (0..members).map(|_| Queue::default()).collect();
        let toward_server = Queue::default();
        let client_wire = |k: usize| Wire {
            incoming: queues[k].clone(),
            queues: vec![toward_server.clone()],
            steer: Steer::Queue0,
        };
        let server_neighbors;
        let clients: Vec<_> = match kind {
            Kind::Plain => {
                let addresses: Vec<_> = (0..members)
                    .map(|k| Ipv4Addr::from(u32::from(ADDRESS) + k as u32))
                    .collect();
                server_neighbors = addresses.iter().map(|&a| (a, PORT_MAC)).collect();
                addresses
                    .iter()
                    .enumerate()
                    .map(|(k, &address)| {
                        let config = config(address, PORT_MAC, vec![(PEER, PEER_MAC)]);
                        Network::new(config, client_wire(k), SECRET, clock.now()).unwrap()
                    })
                    .collect()
            }
            Kind::Ideal | Kind::Queue0 => {
                server_neighbors = vec![(ADDRESS, PORT_MAC)];
                let ownership = FlowOwnership::Hash {
                    key: DEFAULT_FLOW_KEY.to_vec(),
                    table: round_robin(members),
                };
                let limits = SharedFlowLimits {
                    members,
                    inbox_packets: INBOX,
                    packet_bytes: 1500,
                };
                let flows = SharedFlows::new(ownership, limits).unwrap();
                (0..members)
                    .map(|k| {
                        let config = config(ADDRESS, PORT_MAC, vec![(PEER, PEER_MAC)]);
                        Network::with_shared_flows(
                            config,
                            client_wire(k),
                            SECRET,
                            clock.now(),
                            None,
                            &flows,
                            k,
                        )
                        .unwrap()
                    })
                    .collect()
            }
        };
        let steer = kind.steer(members);
        let server_wire = Wire {
            incoming: toward_server.clone(),
            queues: queues.clone(),
            steer,
        };
        let config = config(PEER, PEER_MAC, server_neighbors);
        let server = Network::new(config, server_wire, [9; 32], clock.now()).unwrap();
        let mut bench = Self {
            kind,
            clients,
            server,
            connections: Vec::new(),
            servers: Vec::new(),
            events: vec![Event::NetworkStopped; 64],
        };
        let listener = bench.server.listen(PORT, CONNECTIONS).unwrap();
        for i in 0..CONNECTIONS {
            let k = i % members;
            let client = &mut bench.clients[k];
            let id = client
                .connect(SocketAddr::new(IpAddr::V4(PEER), PORT))
                .unwrap();
            client.set_nodelay(id, true).unwrap();
            bench.connections.push((k, id));
        }
        while bench.servers.len() < CONNECTIONS {
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
        for network in self.clients.iter_mut().chain([&mut self.server]) {
            network.drive(clock.now(), BUDGET).unwrap();
            while network.drain_events(&mut self.events).more {}
        }
    }

    // Run the closed loop until `requests` responses complete; returns the
    // nanoseconds it took.
    fn run(&mut self, clock: &Clock, requests: u64) -> u64 {
        let connections = self.connections.len();
        let mut sent = vec![false; connections];
        let mut received = vec![0usize; connections];
        let mut buffer = [0u8; 64];
        let mut completed = 0;
        let started = clock.now();
        while completed < requests {
            for (index, &(k, id)) in self.connections.iter().enumerate() {
                if !sent[index] {
                    let receipt = self.clients[k]
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
            for (index, &(k, id)) in self.connections.iter().enumerate() {
                match self.clients[k].try_read(id, &mut buffer) {
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

    // Mean nanoseconds of an idle drive plus event drain of member (or
    // client) 0, with its connections open.
    fn idle(&mut self, clock: &Clock) -> f64 {
        let started = clock.now();
        for _ in 0..IDLE_ITERATIONS {
            self.clients[0].drive(clock.now(), BUDGET).unwrap();
            self.clients[0].drain_events(&mut self.events);
        }
        (clock.now() - started) as f64 / IDLE_ITERATIONS as f64
    }

    fn totals(&self) -> Totals {
        let mut totals = Totals {
            server_received: self.server.counters().received,
            ..Totals::default()
        };
        for client in &self.clients {
            let counters = client.counters();
            totals.received += counters.received;
            totals.handed_off += counters.handed_off;
            totals.handoffs_received += counters.handoffs_received;
            totals.handoffs_dropped += counters.handoffs_dropped;
        }
        totals
    }

    // Nanoseconds to move one frame through this series' port and
    // dispatcher, each way: (server to clients, clients to server). A frame
    // to each connection's local address and port in turn is transmitted,
    // steered and received from the queue it lands on.
    fn wire_cost(&self) -> (f64, f64) {
        let members = self.clients.len();
        let queues: Vec<Queue> = (0..members).map(|_| Queue::default()).collect();
        let steer = self.kind.steer(members);
        let mut down = Wire {
            incoming: Queue::default(),
            queues: queues.clone(),
            steer,
        };
        let mut steer = self.kind.steer(members);
        let mut receivers: Vec<_> = queues
            .iter()
            .map(|queue| Wire {
                incoming: queue.clone(),
                queues: Vec::new(),
                steer: Steer::Queue0,
            })
            .collect();
        let frames: Vec<_> = self
            .connections
            .iter()
            .map(|&(k, id)| {
                let SocketAddr::V4(local) = self.clients[k].connection_info(id).unwrap().local
                else {
                    unreachable!()
                };
                let frame = frame(PEER, *local.ip(), PORT, local.port());
                // Where it lands, found apart from the timed loop so that
                // the loop polls no empty queue.
                let queue = steer.queue(&frame);
                (frame, queue)
            })
            .collect();
        let mut out = [0u8; 1514];
        let mut once = |down: &mut Wire, receivers: &mut [Wire], frames: &[(Vec<u8>, usize)]| {
            let started = Instant::now();
            for (frame, queue) in frames.iter().cycle().take(WIRE_PACKETS) {
                down.transmit(frame).unwrap();
                let got = receivers[*queue].receive(&mut out).unwrap();
                assert_eq!(got, Some(frame.len()));
            }
            started.elapsed().as_nanos() as f64 / WIRE_PACKETS as f64
        };
        // The first pass hashes the flows and allocates the frames.
        once(&mut down, &mut receivers, &frames);
        let down_ns = once(&mut down, &mut receivers, &frames);
        let frames: Vec<_> = frames.into_iter().map(|(frame, _)| (frame, 0)).collect();
        let queue = Queue::default();
        let mut up = Wire {
            incoming: Queue::default(),
            queues: vec![queue.clone()],
            steer: Steer::Queue0,
        };
        let mut server = [Wire {
            incoming: queue,
            queues: Vec::new(),
            steer: Steer::Queue0,
        }];
        once(&mut up, &mut server, &frames);
        (down_ns, once(&mut up, &mut server, &frames))
    }
}

// A 16-octet TCP segment as the server sends it, checksums aside: the
// port and dispatcher read only addresses and ports.
fn frame(source: Ipv4Addr, destination: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
    let mut frame = PORT_MAC.to_vec();
    frame.extend(PEER_MAC);
    frame.extend([0x08, 0x00]);
    let mut ip = [0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&((20 + 20 + REQUEST_LEN) as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = 6;
    ip[12..16].copy_from_slice(&source.octets());
    ip[16..20].copy_from_slice(&destination.octets());
    frame.extend(ip);
    let mut tcp = [0u8; 20];
    tcp[..2].copy_from_slice(&sport.to_be_bytes());
    tcp[2..4].copy_from_slice(&dport.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = 0x18;
    frame.extend(tcp);
    frame.extend([0u8; REQUEST_LEN]);
    frame
}

// One series' samples over the repetitions.
struct Series {
    name: String,
    bench: Bench,
    ns: Vec<f64>,
    stack_ns: Vec<f64>,
    // Per request: the clients' received and handed-off packets, the
    // server's received packets.
    received: Vec<f64>,
    handed_off: Vec<f64>,
    server_received: Vec<f64>,
    idle_ns: Vec<f64>,
    wire: (f64, f64),
}

fn median(samples: &[f64]) -> f64 {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let middle = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    } else {
        sorted[middle]
    }
}

fn range(samples: &[f64]) -> (f64, f64) {
    samples
        .iter()
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), &s| {
            (lo.min(s), hi.max(s))
        })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(error) => {
            eprintln!("flows_cost: {error}");
            return ExitCode::FAILURE;
        }
    };
    let clock = Clock(Instant::now());
    let mut series: Vec<Series> = GROUPS
        .iter()
        .flat_map(|&n| [Kind::Plain, Kind::Ideal, Kind::Queue0].map(|kind| (kind, n)))
        .filter(|(kind, n)| args.series.as_ref().is_none_or(|s| *s == kind.name(*n)))
        .map(|(kind, n)| {
            let mut bench = Bench::new(kind, n, &clock);
            // Warm the connections' windows, buffers and caches.
            bench.run(&clock, args.requests / 10 + 1);
            let wire = bench.wire_cost();
            Series {
                name: kind.name(n),
                bench,
                ns: Vec::new(),
                stack_ns: Vec::new(),
                received: Vec::new(),
                handed_off: Vec::new(),
                server_received: Vec::new(),
                idle_ns: Vec::new(),
                wire,
            }
        })
        .collect();
    if series.is_empty() {
        eprintln!("flows_cost: no series {}", args.series.unwrap_or_default());
        return ExitCode::FAILURE;
    }
    // Repetitions alternate between the series so that drift in machine
    // load or clock frequency reaches all of them alike.
    let requests = args.requests as f64;
    for _ in 0..args.repetitions {
        for s in &mut series {
            let before = s.bench.totals();
            let elapsed = s.bench.run(&clock, args.requests) as f64 / requests;
            let after = s.bench.totals();
            let received = (after.received - before.received) as f64 / requests;
            let server = (after.server_received - before.server_received) as f64 / requests;
            let wire = received * s.wire.0 + server * s.wire.1;
            s.ns.push(elapsed);
            s.stack_ns.push(elapsed - wire);
            s.received.push(received);
            s.handed_off
                .push((after.handed_off - before.handed_off) as f64 / requests);
            s.server_received.push(server);
            s.idle_ns.push(s.bench.idle(&clock));
        }
    }
    let mut failed = false;
    for s in &series {
        let name = &s.name;
        let (lo, hi) = range(&s.ns);
        let (stack_lo, stack_hi) = range(&s.stack_ns);
        println!("METRIC ns_per_request_{name}={:.1}", median(&s.ns));
        println!(
            "METRIC stack_ns_per_request_{name}={:.1}",
            median(&s.stack_ns)
        );
        println!(
            "METRIC received_per_request_{name}={:.2}",
            median(&s.received)
        );
        println!(
            "METRIC handed_off_per_request_{name}={:.2}",
            median(&s.handed_off)
        );
        println!("METRIC wire_ns_per_packet_{name}={:.1}", s.wire.0);
        println!("METRIC idle_drive_ns_{name}={:.1}", median(&s.idle_ns));
        println!(
            "{name}: {:.1} ns/request [{lo:.1}, {hi:.1}], less port and dispatcher {:.1} \
             [{stack_lo:.1}, {stack_hi:.1}]; port and dispatcher {:.1} ns/packet to the \
             clients, {:.1} to the server; {:.2} packets/request to the clients, {:.2} to the \
             server",
            median(&s.ns),
            median(&s.stack_ns),
            s.wire.0,
            s.wire.1,
            median(&s.received),
            median(&s.server_received),
        );
        // Plain Networks and ideal steering hand nothing off; one queue
        // hands member 0 every packet of members 1.., which it hands over;
        // and every handoff reaches its member's inbox.
        let totals = s.bench.totals();
        let handoffs_right = match s.bench.kind {
            Kind::Plain | Kind::Ideal => totals.handed_off == 0,
            Kind::Queue0 => totals.handed_off > 0,
        } && totals.handoffs_received == totals.handed_off
            && totals.handoffs_dropped == 0;
        println!(
            "{name}: handed off {}, handoffs received {}, dropped {}",
            totals.handed_off, totals.handoffs_received, totals.handoffs_dropped
        );
        failed |= !handoffs_right;
    }
    let find = |name: String| series.iter().find(|s| s.name == name);
    for n in GROUPS {
        let (Some(a), Some(b), Some(c)) = (
            find(Kind::Plain.name(n)),
            find(Kind::Ideal.name(n)),
            find(Kind::Queue0.name(n)),
        ) else {
            continue;
        };
        // Differences within each repetition, whose series ran back to
        // back, so that drift between repetitions cancels.
        let paired =
            |x: &[f64], y: &[f64]| -> Vec<f64> { x.iter().zip(y).map(|(x, y)| y - x).collect() };
        let mut report = |what: &str, diffs: Vec<f64>, per: f64, base: &Series, bound: f64| {
            let (lo, hi) = range(&diffs);
            let diff = median(&diffs);
            let ratio = 1.0 + diff / median(&base.stack_ns);
            println!("METRIC {what}_ns_per_request_{n}={diff:.1}");
            println!("METRIC {what}_ns_per_packet_{n}={:.1}", diff / per);
            println!(
                "{what} ({n} members): {diff:.1} ns/request [{lo:.1}, {hi:.1}], {:.1} ns per \
                 packet of {per:.2}/request; stack cost ratio {ratio:.4} (bound {bound})",
                diff / per
            );
            failed |= ratio > bound;
        };
        // Every packet a member receives from its queue is classified and
        // hashed.
        let member = paired(&a.stack_ns, &b.stack_ns);
        report("member", member, median(&b.received), a, MEMBER_RATIO);
        let handoff = paired(&b.stack_ns, &c.stack_ns);
        report("handoff", handoff, median(&c.handed_off), b, HANDOFF_RATIO);
        // A member's drive also looks at its inbox when nothing arrived.
        let idle = paired(&a.idle_ns, &b.idle_ns);
        let (lo, hi) = range(&idle);
        let idle_ratio = median(&b.idle_ns) / median(&a.idle_ns);
        println!("METRIC member_idle_drive_ns_{n}={:.1}", median(&idle));
        println!(
            "member idle drive ({n} members): {:.1} ns [{lo:.1}, {hi:.1}]; ratio {idle_ratio:.4} \
             (bound {IDLE_RATIO})",
            median(&idle)
        );
        failed |= idle_ratio > IDLE_RATIO;
    }
    if args.check && failed {
        eprintln!("shared flows cost more than their bounds, or handoffs miscounted");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
