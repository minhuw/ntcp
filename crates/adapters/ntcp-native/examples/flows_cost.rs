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
// the `stack_` metrics and the derived per-packet costs exclude it. Every
// Network sends to one MAC, its link's fixed next hop: members of shared
// flows that resolve by ARP share the port's neighbor table, whose cost
// neighbor_cost measures, so with no ARP these costs are the flows' alone.
//
// With --cpus, the series b<n>t and c<n>t run b<n> and c<n> again with every
// Network on its own pinned thread; the `threaded` module below describes
// them. They are left out by default and --check bounds none of their
// costs, only their handoff counters: on a shared host the time of a
// handoff between cores depends on what else runs on those cores' socket.
//
//   flows_cost [--check] [--requests N] [--repetitions N] [--series NAME]
//              [--cpus SERVER,MEMBER0,MEMBER1,...]
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
    // The threaded series' CPUs: the server's, then one per member.
    cpus: Vec<usize>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        check: false,
        requests: 50_000,
        repetitions: 7,
        series: None,
        cpus: Vec::new(),
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
            "--cpus" => {
                args.cpus = value
                    .split(',')
                    .map(|cpu| cpu.parse().map_err(|_| bad()))
                    .collect::<Result<_, _>>()?;
            }
            _ => {
                return Err(
                    "usage: flows_cost [--check] [--requests N] [--repetitions N] \
                     [--series a2|b2|c2|a4|b4|c4|b2t|c2t|b4t|c4t] \
                     [--cpus SERVER,MEMBER0,MEMBER1,...]"
                        .into(),
                );
            }
        }
    }
    if args.requests == 0 || args.repetitions == 0 {
        return Err("counts must be positive".into());
    }
    if !args.cpus.is_empty() && args.cpus.len() < 3 {
        return Err("--cpus names the server's CPU and at least two members'".into());
    }
    Ok(args)
}

#[derive(Clone, Copy)]
struct Clock(Instant);

impl Clock {
    fn now(&self) -> u64 {
        self.0.elapsed().as_nanos() as u64 + 1
    }
}

fn config(local: Ipv4Addr, mac: [u8; 6], next_hop: [u8; 6]) -> NetworkConfig {
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
        next_hop: EthernetNextHop::Fixed(next_hop),
    };
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
        let clients: Vec<_> = match kind {
            Kind::Plain => {
                let addresses: Vec<_> = (0..members)
                    .map(|k| Ipv4Addr::from(u32::from(ADDRESS) + k as u32))
                    .collect();
                addresses
                    .iter()
                    .enumerate()
                    .map(|(k, &address)| {
                        let config = config(address, PORT_MAC, PEER_MAC);
                        Network::new(config, client_wire(k), SECRET, clock.now()).unwrap()
                    })
                    .collect()
            }
            Kind::Ideal | Kind::Queue0 => {
                let ownership = FlowOwnership::Hash {
                    key: DEFAULT_FLOW_KEY.to_vec(),
                    table: round_robin(members),
                };
                let limits = SharedFlowLimits {
                    members,
                    inbox_packets: INBOX,
                    packet_bytes: 1500,
                    redirected_flows: 0,
                    ..SharedFlowLimits::default()
                };
                let flows = SharedFlows::new(ownership, limits).unwrap();
                (0..members)
                    .map(|k| {
                        let config = config(ADDRESS, PORT_MAC, PEER_MAC);
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
        let config = config(PEER, PEER_MAC, PORT_MAC);
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
    let threaded = threaded::selected(&args);
    if series.is_empty() && threaded.is_empty() {
        eprintln!(
            "flows_cost: no series {}{}",
            args.series.unwrap_or_default(),
            if args.cpus.is_empty() {
                " (threaded series need --cpus)"
            } else {
                ""
            }
        );
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
    if !threaded.is_empty() {
        match threaded::run(&args, &threaded, clock) {
            Ok(right) => failed |= !right,
            Err(error) => {
                eprintln!("flows_cost: {error}");
                return ExitCode::FAILURE;
            }
        }
    }
    if args.check && failed {
        eprintln!("shared flows cost more than their bounds, or handoffs miscounted");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

// The series b<n>t and c<n>t: b<n> and c<n> with every Network on its own
// thread, pinned to its own CPU: the server on the first CPU --cpus names,
// member k on the one after. The single-threaded series count what a
// handoff executes, but its packet never leaves one core's cache; here the
// inbox's ring positions, the slot's stamp, lock and buffer, and the wake
// flag move from member 0's core to the owner's with every handoff, as they
// do behind a NIC that cannot steer.
//
// The port's queues become bounded channels of fixed-size frames, and every
// thread polls without blocking. CPU time per request cannot come from the
// clock alone, since a polling thread is never idle, so each thread splits
// its time by turn of its polling loop: a turn that received, transmitted
// or took a handoff, or read or wrote a request, is busy, and any other is
// idle polling. Busy time per request is what the series compare, the
// members' above all, since a handoff changes only their work; each
// thread's CPU time (CLOCK_THREAD_CPUTIME_ID) over the run, which polling
// makes about its wall time, shows that it had its CPU to itself. Each series has a twin, qb<n>t or qc<n>t, that moves the same
// frames (each connection's request to the server and its response back,
// steered as the series steers them) through the same queues on the same
// CPUs without Networks: what the queues cost apart from the stack, two
// frames per request.
//
// A handoff between cores then costs the members' busy time of c<n>t less
// that of b<n>t, less what their queues' frames cost them more in qc<n>t
// than in qb<n>t, per packet handed off; less the single-threaded
// c<n> - b<n>, it is what crossing cores adds.
//
// The members' CPUs should share a socket, so that a handoff crosses cores
// as it does between the queues of one NIC; the server may sit on the other
// socket, whose frames then cross sockets in both series alike. On the
// Xeon Gold 6230R these were measured on, odd CPUs are one socket and even
// ones the other: `--cpus 44,41,43,45,47` puts the server on 44 and members
// on 41, 43, 45 and 47 (the first two of them for two members), CPUs that
// `ps -eLo psr,pcpu,comm` showed idle. Pin the main thread, which runs the
// single-threaded series and then waits, to another idle CPU.
#[cfg(target_os = "linux")]
mod threaded {
    use super::{
        ADDRESS, Args, BUDGET, CONNECTIONS, Clock, GROUPS, INBOX, Kind, PEER, PEER_MAC, PORT,
        PORT_MAC, REQUEST_LEN, SECRET, Steer, Totals, config, frame, median, range, round_robin,
    };
    use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
    use ntcp_native::{
        ConnId, DEFAULT_FLOW_KEY, Event, FlowOwnership, Network, ReadOutcome, SharedFlowLimits,
        SharedFlows, WriteOptions,
    };
    use std::{
        io,
        net::{IpAddr, SocketAddr},
        sync::{
            Arc, Barrier,
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc,
        },
        thread,
    };

    // The bench's frames are at most a SYN's, 14 + 20 + 60 octets, so the
    // queues carry them in fixed buffers and allocate nothing.
    const FRAME: usize = 128;
    // Frames a queue holds: far more than eight connections keep in flight.
    const QUEUE: usize = 1024;
    // How long the threads poll after the last run so that every handoff
    // in flight arrives before the counters are read.
    const SETTLE_NS: u64 = 20_000_000;

    struct Frame {
        len: usize,
        bytes: [u8; FRAME],
    }

    struct Wire {
        incoming: mpsc::Receiver<Frame>,
        queues: Vec<mpsc::SyncSender<Frame>>,
        steer: Steer,
    }

    impl PacketIo for Wire {
        fn layer(&self) -> PacketLayer {
            PacketLayer::Ethernet
        }
        fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
            let Ok(frame) = self.incoming.try_recv() else {
                return Ok(None);
            };
            out[..frame.len].copy_from_slice(&frame.bytes[..frame.len]);
            Ok(Some(frame.len))
        }
        fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
            assert!(packet.len() <= FRAME, "a {}-octet frame", packet.len());
            let mut frame = Frame {
                len: packet.len(),
                bytes: [0; FRAME],
            };
            frame.bytes[..packet.len()].copy_from_slice(packet);
            let queue = self.steer.queue(packet);
            Ok(match self.queues[queue].try_send(frame) {
                Ok(()) => TxOutcome::Submitted,
                Err(_) => TxOutcome::WouldBlock,
            })
        }
    }

    // A rig's wires: the server's, transmitting to the members' queues as
    // `kind` steers, and each member's, transmitting to the server's.
    fn wires(kind: Kind, members: usize) -> (Wire, Vec<Wire>) {
        let (to_server, server_queue) = mpsc::sync_channel(QUEUE);
        let (to_members, member_queues): (Vec<_>, Vec<_>) =
            (0..members).map(|_| mpsc::sync_channel(QUEUE)).unzip();
        let server = Wire {
            incoming: server_queue,
            queues: to_members,
            steer: kind.steer(members),
        };
        let members = member_queues
            .into_iter()
            .map(|incoming| Wire {
                incoming,
                queues: vec![to_server.clone()],
                steer: Steer::Queue0,
            })
            .collect();
        (server, members)
    }

    fn pin(cpu: usize) -> io::Result<()> {
        // SAFETY: an all-zero cpu_set_t is the empty set.
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        // SAFETY: CPU_SET checks the CPU against the set's size.
        unsafe { libc::CPU_SET(cpu, &mut set) };
        // SAFETY: the set is initialized and its size is the one given.
        let pinned = unsafe { libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &set) } == 0;
        if pinned {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn thread_cpu_ns() -> u64 {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: the call writes the timespec it is given.
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time) };
        time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
    }

    #[derive(Clone, Copy)]
    enum Command {
        // Requests per connection.
        Run(u64),
        // Poll for SETTLE_NS whatever is left.
        Settle,
    }

    // One thread's run: its time, and its Network's counters so far.
    #[derive(Clone, Copy, Default)]
    struct Sample {
        thread: usize,
        cpu_ns: u64,
        wall_ns: u64,
        busy_ns: u64,
        idle_ns: u64,
        totals: Totals,
    }

    // A thread's time over a run, split by turn of its polling loop.
    struct Meter {
        clock: Clock,
        cpu: u64,
        started: u64,
        last: u64,
        busy: u64,
        idle: u64,
    }

    impl Meter {
        fn start(clock: Clock) -> Self {
            let cpu = thread_cpu_ns();
            let now = clock.now();
            Self {
                clock,
                cpu,
                started: now,
                last: now,
                busy: 0,
                idle: 0,
            }
        }

        // Ends a turn, busy if it moved a packet or data, and returns the
        // time, which the next turn's drive takes as its own.
        fn turn(&mut self, worked: bool) -> u64 {
            let now = self.clock.now();
            let spent = now - self.last;
            if worked {
                self.busy += spent;
            } else {
                self.idle += spent;
            }
            self.last = now;
            now
        }

        fn polling(&self, command: Command, remaining: &Remaining) -> bool {
            match command {
                Command::Run(_) => remaining.0.load(Ordering::Acquire) != 0,
                Command::Settle => self.last - self.started < SETTLE_NS,
            }
        }

        fn sample(&self, totals: Totals) -> Sample {
            Sample {
                thread: 0,
                cpu_ns: thread_cpu_ns() - self.cpu,
                wall_ns: self.last - self.started,
                busy_ns: self.busy,
                idle_ns: self.idle,
                totals,
            }
        }
    }

    // The members (or connections) whose part of a run is not yet done;
    // every thread polls until none is left. On a line of its own, which
    // the threads only read until the end of the run.
    #[repr(align(128))]
    struct Remaining(AtomicUsize);

    // A thread's setup: its connections' local ports, by connection.
    type Ready = Result<Vec<(usize, u16)>, String>;

    // One series' threads, the server's first, each waiting for commands.
    struct Rig {
        commands: Vec<mpsc::Sender<Command>>,
        samples: mpsc::Receiver<Sample>,
        remaining: Arc<Remaining>,
        finishers: usize,
        threads: Vec<thread::JoinHandle<()>>,
    }

    struct Spawner {
        // The series' name, which names its threads for profiles.
        name: String,
        barrier: Arc<Barrier>,
        remaining: Arc<Remaining>,
        commands: Vec<mpsc::Sender<Command>>,
        samples: mpsc::Sender<Sample>,
        results: mpsc::Receiver<Sample>,
        ready: mpsc::Sender<Ready>,
        readies: mpsc::Receiver<Ready>,
        threads: Vec<thread::JoinHandle<()>>,
    }

    impl Spawner {
        fn new(name: String, threads: usize) -> Self {
            let (samples, results) = mpsc::channel();
            let (ready, readies) = mpsc::channel();
            Self {
                name,
                barrier: Arc::new(Barrier::new(threads)),
                remaining: Arc::new(Remaining(AtomicUsize::new(0))),
                commands: Vec::new(),
                samples,
                results,
                ready,
                readies,
                threads: Vec::new(),
            }
        }

        // A thread pinned to `cpu` that sets itself up with `build` (which
        // may wait on the barrier, as every thread of the rig must), says
        // so, then runs each command once all threads have it.
        fn spawn<R: FnMut(Command, &Remaining) -> Sample>(
            &mut self,
            cpu: usize,
            build: impl FnOnce(&Barrier) -> (R, Vec<(usize, u16)>) + Send + 'static,
        ) {
            let index = self.commands.len();
            let (command, commands) = mpsc::channel();
            self.commands.push(command);
            let (barrier, remaining) = (self.barrier.clone(), self.remaining.clone());
            let (samples, ready) = (self.samples.clone(), self.ready.clone());
            let name = match index {
                0 => format!("{} server", self.name),
                k => format!("{} member{}", self.name, k - 1),
            };
            let spawned = thread::Builder::new().name(name).spawn(move || {
                if let Err(error) = pin(cpu) {
                    let _ = ready.send(Err(format!("cpu {cpu}: {error}")));
                    return;
                }
                let (mut role, ports) = build(&barrier);
                let _ = ready.send(Ok(ports));
                while let Ok(command) = commands.recv() {
                    barrier.wait();
                    let sample = Sample {
                        thread: index,
                        ..role(command, &remaining)
                    };
                    if samples.send(sample).is_err() {
                        break;
                    }
                }
            });
            self.threads.push(spawned.expect("spawn a thread"));
        }

        // Waits for every thread's setup; returns the rig and the
        // connections' local ports, in connection order.
        fn finish(self, finishers: usize) -> Result<(Rig, Vec<u16>), String> {
            let mut ports = vec![0; CONNECTIONS];
            for _ in 0..self.commands.len() {
                let ready = self
                    .readies
                    .recv()
                    .map_err(|_| "a thread failed to set up")?;
                for (index, port) in ready? {
                    ports[index] = port;
                }
            }
            let rig = Rig {
                commands: self.commands,
                samples: self.results,
                remaining: self.remaining,
                finishers,
                threads: self.threads,
            };
            Ok((rig, ports))
        }
    }

    impl Rig {
        // b<n>t or c<n>t: the server and n members on `cpus`, connected.
        fn network(
            kind: Kind,
            members: usize,
            cpus: &[usize],
            clock: Clock,
        ) -> Result<(Self, Vec<u16>), String> {
            let (server_wire, member_wires) = wires(kind, members);
            let mut spawner = Spawner::new(name(kind, members), members + 1);
            let setting_up = Arc::new(AtomicBool::new(true));
            let up = setting_up.clone();
            spawner.spawn(cpus[0], move |barrier| {
                let config = config(PEER, PEER_MAC, PORT_MAC);
                let mut network = Network::new(config, server_wire, [9; 32], clock.now()).unwrap();
                let listener = network.listen(PORT, CONNECTIONS).unwrap();
                barrier.wait();
                let mut events = vec![Event::NetworkStopped; 64];
                let mut servers = Vec::new();
                while servers.len() < CONNECTIONS {
                    network.drive(clock.now(), BUDGET).unwrap();
                    while network.drain_events(&mut events).more {}
                    match network.accept(listener) {
                        Ok(id) => {
                            network.set_nodelay(id, true).unwrap();
                            servers.push(id);
                        }
                        Err(error) if error.is_would_block() => {}
                        Err(error) => panic!("accept: {error}"),
                    }
                }
                up.store(false, Ordering::Release);
                (server_role(network, servers, events, clock), Vec::new())
            });
            let ownership = FlowOwnership::Hash {
                key: DEFAULT_FLOW_KEY.to_vec(),
                table: round_robin(members),
            };
            let limits = SharedFlowLimits {
                members,
                inbox_packets: INBOX,
                packet_bytes: 1500,
                redirected_flows: 0,
                ..SharedFlowLimits::default()
            };
            let flows = SharedFlows::new(ownership, limits).map_err(|e| format!("{e:?}"))?;
            for (k, wire) in member_wires.into_iter().enumerate() {
                let (flows, setting_up) = (flows.clone(), setting_up.clone());
                spawner.spawn(cpus[1 + k], move |barrier| {
                    let config = config(ADDRESS, PORT_MAC, PEER_MAC);
                    let mut network = Network::with_shared_flows(
                        config,
                        wire,
                        SECRET,
                        clock.now(),
                        None,
                        &flows,
                        k,
                    )
                    .unwrap();
                    barrier.wait();
                    let mine: Vec<(usize, ConnId)> = (k..CONNECTIONS)
                        .step_by(members)
                        .map(|index| {
                            let id = network
                                .connect(SocketAddr::new(IpAddr::V4(PEER), PORT))
                                .unwrap();
                            network.set_nodelay(id, true).unwrap();
                            (index, id)
                        })
                        .collect();
                    let mut events = vec![Event::NetworkStopped; 64];
                    while setting_up.load(Ordering::Acquire) {
                        network.drive(clock.now(), BUDGET).unwrap();
                        while network.drain_events(&mut events).more {}
                    }
                    let ports = mine
                        .iter()
                        .map(
                            |&(index, id)| match network.connection_info(id).unwrap().local {
                                SocketAddr::V4(local) => (index, local.port()),
                                SocketAddr::V6(_) => unreachable!(),
                            },
                        )
                        .collect();
                    (member_role(network, mine, events, clock), ports)
                });
            }
            spawner.finish(members)
        }

        // qb<n>t or qc<n>t: the same frames through the same queues on the
        // same CPUs, without Networks, one request in flight on each
        // connection, which whoever receives its response renews.
        fn queues(
            kind: Kind,
            members: usize,
            cpus: &[usize],
            ports: &[u16],
            clock: Clock,
        ) -> Result<Self, String> {
            let (mut server_wire, member_wires) = wires(kind, members);
            let requests: Vec<_> = ports
                .iter()
                .map(|&port| frame(ADDRESS, PEER, port, PORT))
                .collect();
            let responses: Vec<_> = ports
                .iter()
                .map(|&port| frame(PEER, ADDRESS, PORT, port))
                .collect();
            let mut spawner = Spawner::new(format!("q{}", name(kind, members)), members + 1);
            let server_ports = ports.to_vec();
            spawner.spawn(cpus[0], move |_| {
                let mut received = 0;
                let role = move |command: Command, remaining: &Remaining| {
                    let mut meter = Meter::start(clock);
                    let mut out = [0u8; FRAME];
                    while meter.polling(command, remaining) {
                        let mut worked = false;
                        while let Some(len) = server_wire.receive(&mut out).unwrap() {
                            worked = true;
                            received += 1;
                            let port = u16::from_be_bytes([out[34], out[35]]);
                            let index = server_ports.iter().position(|&p| p == port).unwrap();
                            assert_eq!(len, responses[index].len());
                            server_wire.transmit(&responses[index]).unwrap();
                        }
                        meter.turn(worked);
                    }
                    meter.sample(Totals {
                        server_received: received,
                        ..Totals::default()
                    })
                };
                (role, Vec::new())
            });
            for (k, mut wire) in member_wires.into_iter().enumerate() {
                let (requests, ports) = (requests.clone(), ports.to_vec());
                spawner.spawn(cpus[1 + k], move |_| {
                    let mut received = 0;
                    let role = move |command: Command, remaining: &Remaining| {
                        let mut meter = Meter::start(clock);
                        let mut done = [0u64; CONNECTIONS];
                        let mut out = [0u8; FRAME];
                        if let Command::Run(per_connection) = command {
                            for index in (k..CONNECTIONS).step_by(members) {
                                assert!(per_connection > 0);
                                wire.transmit(&requests[index]).unwrap();
                            }
                        }
                        while meter.polling(command, remaining) {
                            let mut worked = false;
                            while wire.receive(&mut out).unwrap().is_some() {
                                worked = true;
                                received += 1;
                                let port = u16::from_be_bytes([out[36], out[37]]);
                                let index = ports.iter().position(|&p| p == port).unwrap();
                                done[index] += 1;
                                match command {
                                    Command::Run(per) if done[index] < per => {
                                        wire.transmit(&requests[index]).unwrap();
                                    }
                                    Command::Run(_) => {
                                        remaining.0.fetch_sub(1, Ordering::AcqRel);
                                    }
                                    Command::Settle => {}
                                }
                            }
                            meter.turn(worked);
                        }
                        meter.sample(Totals {
                            received,
                            ..Totals::default()
                        })
                    };
                    (role, Vec::new())
                });
            }
            spawner.finish(CONNECTIONS).map(|(rig, _)| rig)
        }

        // Runs `command` on every thread; their samples, the server's first.
        fn run(&self, command: Command) -> Vec<Sample> {
            self.remaining.0.store(self.finishers, Ordering::Release);
            for sender in &self.commands {
                sender.send(command).unwrap();
            }
            let mut samples: Vec<_> = self
                .commands
                .iter()
                .map(|_| self.samples.recv().unwrap())
                .collect();
            samples.sort_by_key(|sample| sample.thread);
            samples
        }

        fn stop(self) {
            drop(self.commands);
            for thread in self.threads {
                thread.join().unwrap();
            }
        }
    }

    // The server's turns: drive, then echo whatever each connection read.
    fn server_role(
        mut network: Network<Wire>,
        servers: Vec<ConnId>,
        mut events: Vec<Event>,
        clock: Clock,
    ) -> impl FnMut(Command, &Remaining) -> Sample {
        move |command, remaining| {
            let mut meter = Meter::start(clock);
            let mut now = meter.last;
            let mut buffer = [0u8; 64];
            while meter.polling(command, remaining) {
                let report = network.drive(now, BUDGET).unwrap();
                while network.drain_events(&mut events).more {}
                let mut worked = report.received + report.transmitted != 0;
                for &id in &servers {
                    match network.try_read(id, &mut buffer) {
                        Ok(ReadOutcome::Data { len, .. }) => {
                            let receipt = network
                                .try_write(id, &buffer[..len], WriteOptions::default())
                                .unwrap();
                            assert_eq!(receipt.accepted, len);
                            worked = true;
                        }
                        Ok(ReadOutcome::EmptyBuffer) => {}
                        Err(error) if error.is_would_block() => {}
                        other => panic!("server read: {other:?}"),
                    }
                }
                now = meter.turn(worked);
            }
            meter.sample(Totals {
                server_received: network.counters().received,
                ..Totals::default()
            })
        }
    }

    // A member's turns: a request on each of its connections whose last
    // one was answered, a drive, then the responses. A member whose
    // connections have all their requests answered polls on, as member 0
    // hands the others their packets, until every member's are.
    fn member_role(
        mut network: Network<Wire>,
        mine: Vec<(usize, ConnId)>,
        mut events: Vec<Event>,
        clock: Clock,
    ) -> impl FnMut(Command, &Remaining) -> Sample {
        move |command, remaining| {
            let mut meter = Meter::start(clock);
            let mut now = meter.last;
            let target = match command {
                Command::Run(per_connection) => per_connection,
                Command::Settle => 0,
            };
            let mut done = vec![0; mine.len()];
            let mut sent = vec![false; mine.len()];
            let mut received = vec![0; mine.len()];
            let mut finished = false;
            let mut handoffs = network.counters().handoffs_received;
            let mut buffer = [0u8; 64];
            while meter.polling(command, remaining) {
                let mut worked = false;
                for (j, &(index, id)) in mine.iter().enumerate() {
                    if !sent[j] && done[j] < target {
                        let receipt = network
                            .try_write(id, &[index as u8; REQUEST_LEN], WriteOptions::default())
                            .unwrap();
                        assert_eq!(receipt.accepted, REQUEST_LEN);
                        sent[j] = true;
                        worked = true;
                    }
                }
                let report = network.drive(now, BUDGET).unwrap();
                while network.drain_events(&mut events).more {}
                let taken = network.counters().handoffs_received;
                worked |= report.received + report.transmitted != 0 || taken != handoffs;
                handoffs = taken;
                for (j, &(index, id)) in mine.iter().enumerate() {
                    match network.try_read(id, &mut buffer) {
                        Ok(ReadOutcome::Data { len, .. }) => {
                            assert!(buffer[..len].iter().all(|&b| b == index as u8));
                            worked = true;
                            received[j] += len;
                            if received[j] == REQUEST_LEN {
                                received[j] = 0;
                                sent[j] = false;
                                done[j] += 1;
                            }
                        }
                        Ok(ReadOutcome::EmptyBuffer) => {}
                        Err(error) if error.is_would_block() => {}
                        other => panic!("client read: {other:?}"),
                    }
                }
                if !finished
                    && matches!(command, Command::Run(_))
                    && done.iter().all(|&d| d == target)
                {
                    finished = true;
                    remaining.0.fetch_sub(1, Ordering::AcqRel);
                }
                now = meter.turn(worked);
            }
            let counters = network.counters();
            meter.sample(Totals {
                received: counters.received,
                handed_off: counters.handed_off,
                handoffs_received: counters.handoffs_received,
                handoffs_dropped: counters.handoffs_dropped,
                server_received: 0,
            })
        }
    }

    fn name(kind: Kind, members: usize) -> String {
        format!("{}t", kind.name(members))
    }

    /// The threaded series the arguments ask for: none without --cpus, and
    /// only the groups that have a CPU for every thread.
    pub(super) fn selected(args: &Args) -> Vec<(Kind, usize)> {
        GROUPS
            .iter()
            .filter(|&&n| !args.cpus.is_empty() && n < args.cpus.len())
            .flat_map(|&n| [(Kind::Ideal, n), (Kind::Queue0, n)])
            .filter(|&(kind, n)| args.series.as_ref().is_none_or(|s| *s == name(kind, n)))
            .collect()
    }

    // One run of a rig, per request: the slowest thread's wall time, the
    // threads' CPU, busy and idle time and each thread's busy time; the
    // packets the members received from their queue and handed off, and
    // the server's.
    #[derive(Default)]
    struct Measured {
        wall: f64,
        cpu: f64,
        // The threads' CPU time over their wall time: near 1 when each had
        // its CPU to itself.
        cpu_share: f64,
        busy: f64,
        idle: f64,
        threads: Vec<f64>,
        received: f64,
        handed_off: f64,
        server_received: f64,
    }

    fn add(t: Totals, u: Totals) -> Totals {
        Totals {
            received: t.received + u.received,
            handed_off: t.handed_off + u.handed_off,
            handoffs_received: t.handoffs_received + u.handoffs_received,
            handoffs_dropped: t.handoffs_dropped + u.handoffs_dropped,
            server_received: t.server_received + u.server_received,
        }
    }

    fn sum(samples: &[Sample]) -> Totals {
        samples
            .iter()
            .map(|s| s.totals)
            .fold(Totals::default(), add)
    }

    // One run of `rig` after a warm-up run.
    fn measure(rig: &Rig, per_connection: u64) -> Measured {
        let before = sum(&rig.run(Command::Run(per_connection / 10 + 1)));
        let samples = rig.run(Command::Run(per_connection));
        let requests = (per_connection * CONNECTIONS as u64) as f64;
        let after = sum(&samples);
        let per = |after: u64, before: u64| (after - before) as f64 / requests;
        let total = |f: fn(&Sample) -> u64| samples.iter().map(f).sum::<u64>() as f64;
        Measured {
            wall: samples.iter().map(|s| s.wall_ns).max().unwrap() as f64 / requests,
            cpu: total(|s| s.cpu_ns) / requests,
            cpu_share: total(|s| s.cpu_ns) / total(|s| s.wall_ns),
            busy: total(|s| s.busy_ns) / requests,
            idle: total(|s| s.idle_ns) / requests,
            threads: samples
                .iter()
                .map(|s| s.busy_ns as f64 / requests)
                .collect(),
            received: per(after.received, before.received),
            handed_off: per(after.handed_off, before.handed_off),
            server_received: per(after.server_received, before.server_received),
        }
    }

    // The members' busy time per request.
    fn members(m: &Measured) -> f64 {
        m.threads[1..].iter().sum()
    }

    // A series' runs, one per repetition, and its counters over all.
    struct Series {
        name: String,
        kind: Kind,
        members: usize,
        network: Vec<Measured>,
        queues: Vec<Measured>,
        totals: Totals,
    }

    fn show(samples: &[f64]) -> String {
        let (lo, hi) = range(samples);
        format!("{:.1} [{lo:.1}, {hi:.1}]", median(samples))
    }

    /// Runs the threaded series and reports them; false if their handoff
    /// counters are not as the steering dictates.
    pub(super) fn run(
        args: &Args,
        selected: &[(Kind, usize)],
        clock: Clock,
    ) -> Result<bool, String> {
        let per_connection = (args.requests / CONNECTIONS as u64).max(1);
        let mut series: Vec<_> = selected
            .iter()
            .map(|&(kind, members)| Series {
                name: name(kind, members),
                kind,
                members,
                network: Vec::new(),
                queues: Vec::new(),
                totals: Totals::default(),
            })
            .collect();
        // Every repetition builds each series' threads, Networks and queues
        // anew: how the threads' turns interleave settles differently from
        // one build to the next, by more than the runs of one build differ.
        // Repetitions alternate between the series as the single-threaded
        // ones do.
        for _ in 0..args.repetitions {
            for s in &mut series {
                let (network, ports) = Rig::network(s.kind, s.members, &args.cpus, clock)?;
                let queues = Rig::queues(s.kind, s.members, &args.cpus, &ports, clock)?;
                s.network.push(measure(&network, per_connection));
                s.queues.push(measure(&queues, per_connection));
                // Whatever was in flight when the run ended arrives before
                // the counters are read.
                s.totals = add(s.totals, sum(&network.run(Command::Settle)));
                network.stop();
                queues.stop();
            }
        }
        let mut right = true;
        for s in &series {
            let name = &s.name;
            let net = |f: fn(&Measured) -> f64| s.network.iter().map(f).collect::<Vec<_>>();
            let queue = s.queues.iter().map(|m| m.busy / 2.0).collect::<Vec<_>>();
            let idle_share = net(|m| m.idle / (m.busy + m.idle));
            let throughput = net(|m| 1e9 / m.wall);
            println!(
                "METRIC cpu_ns_per_request_{name}={:.1}",
                median(&net(|m| m.cpu))
            );
            println!(
                "METRIC busy_ns_per_request_{name}={:.1}",
                median(&net(|m| m.busy))
            );
            println!(
                "METRIC member_busy_ns_per_request_{name}={:.1}",
                median(&net(members))
            );
            println!("METRIC idle_share_{name}={:.3}", median(&idle_share));
            println!(
                "METRIC wall_ns_per_request_{name}={:.1}",
                median(&net(|m| m.wall))
            );
            println!(
                "METRIC requests_per_second_{name}={:.0}",
                median(&throughput)
            );
            println!(
                "METRIC handed_off_per_request_{name}={:.2}",
                median(&net(|m| m.handed_off))
            );
            println!(
                "METRIC queue_busy_ns_per_frame_{name}={:.1}",
                median(&queue)
            );
            println!(
                "{name} (cpus {:?}): busy {} ns/request: server {}, members {} (member 0 {}); \
                 CPU {} ns/request ({:.3} of wall time), {:.1}% of it idle polling; wall {} \
                 ns/request, {} requests/s; {:.2} packets/request to the members, {:.2} to the \
                 server, {:.2} handed off",
                &args.cpus[..=s.members],
                show(&net(|m| m.busy)),
                show(&net(|m| m.threads[0])),
                show(&net(members)),
                show(&net(|m| m.threads[1])),
                show(&net(|m| m.cpu)),
                median(&net(|m| m.cpu_share)),
                100.0 * median(&idle_share),
                show(&net(|m| m.wall)),
                show(&throughput),
                median(&net(|m| m.received)),
                median(&net(|m| m.server_received)),
                median(&net(|m| m.handed_off)),
            );
            println!(
                "q{name}: queues alone {} ns/frame busy (members {} ns/request), {} ns/request \
                 CPU with idle polling",
                show(&queue),
                show(&s.queues.iter().map(members).collect::<Vec<_>>()),
                show(&s.queues.iter().map(|m| m.cpu).collect::<Vec<_>>()),
            );
            let totals = s.totals;
            let handoffs_right = match s.kind {
                Kind::Plain | Kind::Ideal => totals.handed_off == 0,
                Kind::Queue0 => totals.handed_off > 0,
            } && totals.handoffs_received == totals.handed_off
                && totals.handoffs_dropped == 0;
            println!(
                "{name}: handed off {}, handoffs received {}, dropped {}",
                totals.handed_off, totals.handoffs_received, totals.handoffs_dropped
            );
            right &= handoffs_right;
        }
        for n in GROUPS {
            let find = |kind| series.iter().find(|s| s.kind == kind && s.members == n);
            let (Some(b), Some(c)) = (find(Kind::Ideal), find(Kind::Queue0)) else {
                continue;
            };
            // Within each repetition, per packet handed off: the busy time
            // c adds over all threads, over the members (whose work alone
            // the handoffs change), and over the members less what their
            // frames cost them in the queues more than b's.
            let mut all = Vec::new();
            let mut handoff = Vec::new();
            let mut cross = Vec::new();
            let mut queues = Vec::new();
            for (((b, c), qb), qc) in b
                .network
                .iter()
                .zip(&c.network)
                .zip(&b.queues)
                .zip(&c.queues)
            {
                let frames = |m: &Measured| (m.received + m.server_received) / 2.0;
                let queue = frames(c) * members(qc) - frames(b) * members(qb);
                all.push((c.busy - b.busy) / c.handed_off);
                handoff.push((members(c) - members(b)) / c.handed_off);
                cross.push((members(c) - members(b) - queue) / c.handed_off);
                queues.push(queue);
            }
            println!(
                "METRIC threaded_handoff_ns_per_packet_{n}={:.1}",
                median(&handoff)
            );
            println!(
                "METRIC threaded_handoff_less_queues_ns_per_packet_{n}={:.1}",
                median(&cross)
            );
            println!(
                "handoff between cores ({n} members): members {} ns per handed-off packet (all \
                 threads {}); the members' queues {} ns/request more; less that, {} ns per \
                 handed-off packet",
                show(&handoff),
                show(&all),
                show(&queues),
                show(&cross),
            );
        }
        Ok(right)
    }
}

#[cfg(not(target_os = "linux"))]
mod threaded {
    use super::{Args, Clock, Kind};

    pub(super) fn selected(_: &Args) -> Vec<(Kind, usize)> {
        Vec::new()
    }

    pub(super) fn run(_: &Args, _: &[(Kind, usize)], _: Clock) -> Result<bool, String> {
        Err("the threaded series need Linux".into())
    }
}
