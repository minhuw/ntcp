// A closed-loop xylem-echo client on an AF_XDP port: one ntcp-native Network
// per local IPv4 address, each on its own RX/TX queue pair and pinned worker
// thread, the Networks sharing the port's ARP table. Each connection sends a
// 16-octet request ([request id: u64 LE][delay us: u64 LE = 0]), waits for
// the same 16 octets back and sends the next. It prints `METRIC name=value`
// lines and exits nonzero on any failure or if no request completed. Needs
// CAP_NET_ADMIN, CAP_BPF and CAP_NET_RAW (or root).
//
//   xdp_echo --dev IFNAME [--mode native|generic] --ip A.B.C.D [--ip ...]
//            [--queue N]... --prefix LEN [--gateway A.B.C.D]
//            [--neighbor A.B.C.D=MAC]... --server IP:PORT [--connections N]
//            [--duration SECS] [--cpu N]...
//
// Questions an embedding answers, and this example's answers:
//
// - Which queues? `--queue` once per `--ip` (default 0, 1, ...). The kernel
//   keeps using every queue for its own traffic; the program passes it on.
// - What does a queue receive? The program hands each queue's socket the
//   frames for the port's addresses that arrive on that queue. With more
//   than one RX queue, RSS spreads them over all queues, so each address is
//   steered to its queue and ARP to the first address's queue, whose
//   Network handles ARP for all of them through the shared table. With one
//   enabled RX queue (a default veth) every frame arrives there and no rule
//   is needed; rules the device does not support are then skipped.
// - Which clock? One process-wide monotonic origin (`now_ns`), in
//   nanoseconds: the shared ARP table requires every member to use one clock
//   and one unit, and the RTTs subtract instants taken on any thread.
// - How is the queue polled? Busy-polling: each worker drives its Network in
//   a loop on its own CPU, as `--cpu` pins it.

use ntcp_io_af_xdp::{HostedQueue, Port, PortConfig, QueueHandle, XdpMode};
use ntcp_native::{
    CallerTimebase, ConnId, Error as NetError, EthernetNextHop, Event, Link, Network,
    NetworkConfig, ReadOutcome, SharedNeighborLimits, SharedNeighbors, WorkBudget, WriteOptions,
};
use std::{
    collections::HashMap,
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    process::ExitCode,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

const NANOS: u64 = 1_000_000_000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
// After the measured window: in-flight responses, then FIN exchanges.
const DRAIN: Duration = Duration::from_secs(1);
const LINGER: Duration = Duration::from_secs(1);
const REQUEST_LEN: usize = 16;

static ORIGIN: OnceLock<Instant> = OnceLock::new();

// Nanoseconds since the process-wide origin, on every thread.
fn now_ns() -> u64 {
    ORIGIN.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

struct Args {
    dev: String,
    mode: XdpMode,
    ips: Vec<Ipv4Addr>,
    queues: Vec<u32>,
    prefix: u8,
    gateway: Option<Ipv4Addr>,
    neighbors: Vec<(Ipv4Addr, [u8; 6])>,
    server: SocketAddrV4,
    connections: usize,
    duration: Duration,
    cpus: Vec<usize>,
}

const USAGE: &str = "usage: xdp_echo --dev IFNAME [--mode native|generic] --ip A.B.C.D \
[--ip ...] [--queue N]... --prefix LEN [--gateway A.B.C.D] [--neighbor A.B.C.D=MAC]... \
--server IP:PORT [--connections N] [--duration SECS] [--cpu N]...";

fn parse_mac(text: &str) -> Result<[u8; 6], String> {
    let mut mac = [0; 6];
    let mut parts = text.split(':');
    for octet in &mut mac {
        let part = parts.next().ok_or_else(|| format!("bad MAC {text}"))?;
        *octet = u8::from_str_radix(part, 16).map_err(|_| format!("bad MAC {text}"))?;
    }
    if parts.next().is_some() {
        return Err(format!("bad MAC {text}"));
    }
    Ok(mac)
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        dev: String::new(),
        mode: XdpMode::Native,
        ips: Vec::new(),
        queues: Vec::new(),
        prefix: 0,
        gateway: None,
        neighbors: Vec::new(),
        server: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        connections: 1,
        duration: Duration::from_secs(10),
        cpus: Vec::new(),
    };
    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        let mut value = || iter.next().ok_or_else(|| format!("{flag} needs a value"));
        let bad = |what: &str| format!("bad {flag} {what}");
        match flag.as_str() {
            "--dev" => args.dev = value()?,
            "--mode" => {
                args.mode = match value()?.as_str() {
                    "native" => XdpMode::Native,
                    "generic" => XdpMode::Generic,
                    _ => return Err(bad("mode")),
                }
            }
            "--ip" => args.ips.push(value()?.parse().map_err(|_| bad("address"))?),
            "--queue" => args
                .queues
                .push(value()?.parse().map_err(|_| bad("queue"))?),
            "--prefix" => args.prefix = value()?.parse().map_err(|_| bad("length"))?,
            "--gateway" => args.gateway = Some(value()?.parse().map_err(|_| bad("address"))?),
            "--neighbor" => {
                let text = value()?;
                let (ip, mac) = text.split_once('=').ok_or_else(|| bad("IP=MAC"))?;
                let ip = ip.parse().map_err(|_| bad("address"))?;
                args.neighbors.push((ip, parse_mac(mac)?));
            }
            "--server" => args.server = value()?.parse().map_err(|_| bad("IP:PORT"))?,
            "--connections" => {
                args.connections = value()?.parse().map_err(|_| bad("count"))?;
            }
            "--duration" => {
                let seconds: f64 = value()?.parse().map_err(|_| bad("seconds"))?;
                args.duration = Duration::try_from_secs_f64(seconds).map_err(|_| bad("seconds"))?;
            }
            "--cpu" => args.cpus.push(value()?.parse().map_err(|_| bad("CPU"))?),
            "-h" | "--help" => return Err(USAGE.into()),
            _ => return Err(format!("unknown argument {flag}\n{USAGE}")),
        }
    }
    if args.dev.is_empty() || args.ips.is_empty() || args.prefix == 0 || args.server.port() == 0 {
        return Err(USAGE.into());
    }
    if args.queues.is_empty() {
        args.queues = (0..args.ips.len() as u32).collect();
    }
    if args.connections == 0
        || args.queues.len() != args.ips.len()
        || !args.cpus.is_empty() && args.cpus.len() != args.ips.len()
    {
        return Err("--connections must be positive; --queue and --cpu given once per --ip".into());
    }
    Ok(args)
}

fn single_cpu(cpu: usize) -> std::io::Result<libc::cpu_set_t> {
    if cpu >= libc::CPU_SETSIZE as usize {
        return Err(std::io::Error::other(format!("CPU {cpu} out of range")));
    }
    // SAFETY: an all-zero cpu_set_t is the empty set.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: cpu < CPU_SETSIZE.
    unsafe { libc::CPU_SET(cpu, &mut set) };
    Ok(set)
}

fn set_affinity(set: &libc::cpu_set_t) -> std::io::Result<()> {
    // SAFETY: reads size_of::<cpu_set_t>() bytes of `set`; 0 is this thread.
    if unsafe { libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), set) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[derive(Default)]
struct Report {
    requests: u64,
    window_ns: u64,
    rtt: Vec<u64>,
    arp_sent: u64,
    arp_received: u64,
    errors: Vec<String>,
}

struct Pending {
    request: [u8; REQUEST_LEN],
    written: usize,
    response: [u8; REQUEST_LEN],
    received: usize,
    started: u64,
}

struct Connection {
    id: ConnId,
    connected: bool,
    closed: bool,
    pending: Option<Pending>,
}

struct Worker {
    index: usize,
    ip: Ipv4Addr,
    handle: QueueHandle,
    cpu: Option<libc::cpu_set_t>,
    neighbors: SharedNeighbors,
}

fn main() -> ExitCode {
    now_ns();
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("xdp_echo: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<bool, Box<dyn std::error::Error>> {
    let args = parse_args()?;
    let mut config = PortConfig::new(args.dev.clone());
    config.mode = args.mode;
    let port = Port::attach(config)?;
    let mac = port.mac_address()?;
    let mac_text = mac.map(|o| format!("{o:02x}")).join(":");
    let enabled = port.enabled_queues();
    eprintln!(
        "PORT {} ifindex={} mode={:?} mac={mac_text} rx_queues={} enabled={enabled:?}",
        args.dev,
        port.ifindex(),
        port.mode(),
        port.queues()
    );
    let threads = args.ips.len();
    let neighbors = SharedNeighbors::new(
        mac,
        NANOS,
        SharedNeighborLimits {
            members: threads,
            entries: 64 + args.neighbors.len(),
            // Each member reserves max_connections + 1 output owners.
            held: threads * (args.connections + 1),
            replies: 16,
        },
    )?;
    let mut addresses = Vec::new();
    let mut rules = Vec::new();
    let single = enabled.is_ok_and(|n| n == 1);
    let mut steer = |what: &str, rule: std::io::Result<ntcp_io_af_xdp::Rule>| match rule {
        Ok(rule) => {
            eprintln!("RULE {what} location={}", rule.location());
            rules.push(rule);
            Ok(())
        }
        Err(error) if single && error.kind() == std::io::ErrorKind::Unsupported => {
            eprintln!("RULE {what} not installed ({error}); the only RX queue receives all");
            Ok(())
        }
        Err(error) => Err(format!("steer {what}: {error}")),
    };
    for (&ip, &queue) in args.ips.iter().zip(&args.queues) {
        addresses.push(port.add_ipv4(ip)?);
        steer(
            &format!("{ip} -> queue {queue}"),
            port.steer_ipv4(ip, queue),
        )?;
    }
    steer(
        &format!("ARP -> queue {}", args.queues[0]),
        port.steer_arp(args.queues[0]),
    )?;

    let args = Arc::new(args);
    let mut workers = Vec::new();
    for (index, (&ip, &queue)) in args.ips.iter().zip(&args.queues).enumerate() {
        let worker = Worker {
            index,
            ip,
            handle: port.take_queue(queue)?,
            cpu: args.cpus.get(index).map(|&c| single_cpu(c)).transpose()?,
            neighbors: neighbors.clone(),
        };
        let args = args.clone();
        workers.push(
            std::thread::Builder::new()
                .name(format!("ntcp-q{queue}"))
                .spawn(move || serve(worker, &args))?,
        );
    }
    let mut reports = Vec::new();
    for (index, worker) in workers.into_iter().enumerate() {
        reports.push(worker.join().unwrap_or_else(|_| Report {
            errors: vec![format!("worker {index} panicked")],
            ..Report::default()
        }));
    }
    let unsteered = port.unsteered()?;
    drop(rules);
    drop(addresses);
    Ok(summarize(&reports, &neighbors, unsteered))
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    // Nearest rank.
    let rank = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

fn summarize(reports: &[Report], neighbors: &SharedNeighbors, unsteered: u64) -> bool {
    let requests: u64 = reports.iter().map(|r| r.requests).sum();
    // Workers measure concurrently: the rate of each, summed.
    let rate: f64 = reports
        .iter()
        .filter(|r| r.window_ns != 0)
        .map(|r| r.requests as f64 * NANOS as f64 / r.window_ns as f64)
        .sum();
    let mut rtt: Vec<u64> = reports.iter().flat_map(|r| r.rtt.clone()).collect();
    rtt.sort_unstable();
    let errors: usize = reports.iter().map(|r| r.errors.len()).sum();
    for (index, report) in reports.iter().enumerate() {
        for error in &report.errors {
            eprintln!("ERROR worker {index}: {error}");
        }
    }
    println!("METRIC requests={requests}");
    println!("METRIC requests_per_second={rate:.1}");
    if !rtt.is_empty() {
        println!("METRIC sw_rtt_p50_ns={}", percentile(&rtt, 0.5));
        println!("METRIC sw_rtt_p99_ns={}", percentile(&rtt, 0.99));
    }
    let sum = |f: fn(&Report) -> u64| -> u64 { reports.iter().map(f).sum() };
    println!("METRIC arp_sent={}", sum(|r| r.arp_sent));
    println!("METRIC arp_received={}", sum(|r| r.arp_received));
    // The port's table counts failures once for all members.
    let arp = neighbors.counters();
    println!("METRIC arp_resolution_failures={}", arp.resolution_failures);
    println!("METRIC arp_requests_sent={}", arp.requests_sent);
    println!("METRIC arp_replies_sent={}", arp.replies_sent);
    println!("METRIC unsteered={unsteered}");
    println!("METRIC errors={errors}");
    errors == 0 && requests != 0
}

fn serve(worker: Worker, args: &Args) -> Report {
    let mut report = Report::default();
    if let Err(error) = serve_into(worker, args, &mut report) {
        report.errors.push(error);
    }
    report
}

fn serve_into(worker: Worker, args: &Args, report: &mut Report) -> Result<(), String> {
    if let Some(cpu) = &worker.cpu {
        set_affinity(cpu).map_err(|e| format!("sched_setaffinity: {e}"))?;
    }
    let queue = worker.handle.attach().map_err(|e| format!("attach: {e}"))?;
    let mut secret = [0; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut secret))
        .map_err(|e| format!("/dev/urandom: {e}"))?;
    let mut config = NetworkConfig::new(IpAddr::V4(worker.ip), 1500);
    config.tcp.max_connections = args.connections;
    config.tcp.connection.timebase = CallerTimebase {
        units_per_second: NANOS,
        ..CallerTimebase::default()
    };
    config.link = Link::Ethernet {
        local_mac: worker.neighbors.local_mac(),
        next_hop: EthernetNextHop::Arp {
            prefix_len: args.prefix,
            gateway: args.gateway,
        },
    };
    config.static_neighbors = args.neighbors.clone();
    let mut network =
        Network::with_shared_neighbors(config, queue, secret, now_ns(), &worker.neighbors)
            .map_err(|e| format!("network: {e}"))?;
    let outcome = exchange(&mut network, args, worker.index, report);
    // Counters also describe a failed run.
    let counters = network.counters();
    report.arp_sent = counters.arp_sent;
    report.arp_received = counters.arp_received;
    outcome
}

// Connect, run the closed loop for the window, drain, close and linger.
fn exchange(
    network: &mut Network<HostedQueue>,
    args: &Args,
    index: usize,
    report: &mut Report,
) -> Result<(), String> {
    let mut connections = Vec::with_capacity(args.connections);
    let mut slots = HashMap::new();
    for slot in 0..args.connections {
        let id = network
            .connect(SocketAddr::V4(args.server))
            .map_err(|e| format!("connect: {e}"))?;
        network
            .set_nodelay(id, true)
            .map_err(|e| format!("nodelay: {e}"))?;
        slots.insert(id, slot);
        connections.push(Connection {
            id,
            connected: false,
            closed: false,
            pending: None,
        });
    }

    let budget = WorkBudget::new(64, 64, 64, 64);
    let mut events = [Event::NetworkStopped; 64];
    let mut next_request = (index as u64) << 48;
    let started = now_ns();
    let mut window: Option<(u64, u64)> = None;
    let mut closing_since: Option<u64> = None;
    let mut last_done = 0;
    report.rtt.reserve(1 << 20);

    loop {
        let now = now_ns();
        network
            .drive(now, budget)
            .map_err(|e| format!("drive: {e}"))?;
        loop {
            let batch = network.drain_events(&mut events);
            for event in &events[..batch.written] {
                match *event {
                    Event::Connected(id) => {
                        if let Some(&slot) = slots.get(&id) {
                            connections[slot].connected = true;
                        }
                    }
                    Event::Closed { connection, reason } => {
                        if let Some(&slot) = slots.get(&connection) {
                            connections[slot].closed = true;
                            if closing_since.is_none() {
                                report.errors.push(format!(
                                    "connection {slot} closed by the network: {reason:?}"
                                ));
                            }
                        }
                    }
                    Event::NetworkStopped => {
                        return Err(format!("network stopped: {:?}", network.failure()));
                    }
                    _ => {}
                }
            }
            if !batch.more {
                break;
            }
        }
        if !report.errors.is_empty() {
            break;
        }

        match (window, closing_since) {
            (None, _) => {
                if connections.iter().all(|c| c.connected) {
                    window = Some((now, now + args.duration.as_nanos() as u64));
                } else if now - started > CONNECT_TIMEOUT.as_nanos() as u64 {
                    return Err("connections not established in time".into());
                }
            }
            (Some((_, end)), None) => {
                let idle = connections.iter().all(|c| c.pending.is_none());
                if now >= end + DRAIN.as_nanos() as u64 || now >= end && idle {
                    let stranded = connections.iter().filter(|c| c.pending.is_some()).count();
                    if stranded != 0 {
                        report
                            .errors
                            .push(format!("{stranded} responses missing after the drain"));
                    }
                    for connection in &connections {
                        network
                            .close(connection.id)
                            .map_err(|e| format!("close: {e}"))?;
                    }
                    closing_since = Some(now);
                }
            }
            (Some(_), Some(since)) => {
                if connections.iter().all(|c| c.closed) || now - since > LINGER.as_nanos() as u64 {
                    break;
                }
            }
        }
        let Some((_, end)) = window else {
            continue;
        };
        if closing_since.is_some() {
            continue;
        }

        for connection in &mut connections {
            if connection.pending.is_none() && now < end {
                let mut request = [0; REQUEST_LEN];
                request[..8].copy_from_slice(&next_request.to_le_bytes());
                next_request += 1;
                connection.pending = Some(Pending {
                    request,
                    written: 0,
                    response: [0; REQUEST_LEN],
                    received: 0,
                    started: now_ns(),
                });
            }
            let Some(pending) = &mut connection.pending else {
                continue;
            };
            if pending.written < REQUEST_LEN {
                match network.try_write(
                    connection.id,
                    &pending.request[pending.written..],
                    WriteOptions::default(),
                ) {
                    Ok(receipt) => pending.written += receipt.accepted,
                    Err(error) if error.is_would_block() => {}
                    Err(error) => return Err(format!("write: {error}")),
                }
            }
            match network.try_read(connection.id, &mut pending.response[pending.received..]) {
                Ok(ReadOutcome::Data { len, .. }) => pending.received += len,
                Ok(ReadOutcome::Eof) => return Err("server closed the connection".into()),
                Ok(ReadOutcome::EmptyBuffer) => {}
                Err(error) if error.is_would_block() => {}
                Err(NetError::ConnectionClosed(reason)) => {
                    return Err(format!("connection closed: {reason:?}"));
                }
                Err(error) => return Err(format!("read: {error}")),
            }
            if pending.received < REQUEST_LEN {
                continue;
            }
            let done = now_ns();
            let pending = connection.pending.take().unwrap();
            if pending.response != pending.request {
                return Err(format!(
                    "echo differs: sent {:02x?}, received {:02x?}",
                    pending.request, pending.response
                ));
            }
            report.requests += 1;
            last_done = done;
            report.rtt.push(done - pending.started);
        }
    }
    // Requests start until the window ends; the rate counts to the last
    // response, which may complete during the drain.
    if let Some((start, _)) = window {
        report.window_ns = last_done.saturating_sub(start);
    }
    Ok(())
}
