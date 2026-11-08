// A closed-loop xylem-echo client on a DPDK port: one ntcp-native Network
// per local IPv4 address, each on its own queue pair and pinned worker
// thread, the Networks sharing the port's ARP table. Each connection sends
// a 16-octet request ([request id: u64 LE][delay us: u64 LE = 0]), waits for
// the same 16 octets back and sends the next. It prints `METRIC name=value`
// lines and exits nonzero on any failure or if no request completed.
//
//   dpdk_echo --dev DEVARGS [--eal ARG]... --ip A.B.C.D [--ip ...] --prefix LEN
//             [--gateway A.B.C.D] [--neighbor A.B.C.D=MAC]... --server IP:PORT
//             [--connections N] [--duration SECS] [--isolate] [--rx-timestamps]
//             [--cpu N]... [--secret-from-urandom]
//
// Questions an embedding answers, and this example's answers:
//
// - How is the device named? EAL probes PCI devices at init (all bound ones,
//   or those allowed with `-a`), and PMD arguments such as mlx5's
//   `dv_flow_en=1` take effect only at that probe. `Port::start` then finds
//   the probed port by matching `PortConfig::device` as ethdev's iterator
//   does (rte_eth_iterator_init): the bus part (`0000:05:00.0`) selects the
//   device, and the other `key=value` arguments are ignored for matching, so
//   `0000:05:00.0` and `0000:05:00.0,dv_flow_en=1` find the same port and
//   neither probes it again. Only a device EAL has not probed is probed by
//   `Port::start` itself, with the arguments given there. This example
//   passes `--dev` both to EAL (`-a DEVARGS` for a PCI address, `--vdev
//   DEVARGS` otherwise) and as `PortConfig::device`: the PMD arguments are
//   applied once, at init, and EAL probes no other PCI device.
// - Which CPUs? rte_eal_init pins the calling thread to the main lcore, and
//   threads it spawns inherit that single CPU. Each worker therefore sets
//   its affinity before attaching its queue: to `--cpu` if given, otherwise
//   back to the process's affinity from before EAL. Unless `--eal` names
//   the lcores, EAL gets `--lcores=0@C` for the first CPU C of that set, so
//   EAL starts no worker lcores and leaves lcore ids for rte_thread_register.
// - What does a queue receive? Without `--isolate` the port's unmatched
//   traffic, ARP included, lands on queue 0 and `steer_ipv4` sends each
//   address to its queue. With `--isolate` (bifurcated mlx5) only what the
//   flows match reaches DPDK, and the flows match IPv4 only: ARP replies and
//   requests go to the kernel, so next hops need `--neighbor` entries, and
//   the peer needs a neighbor entry for these addresses (or the kernel must
//   answer ARP for them, e.g. by owning them on the same MAC).
// - Which clock? One process-wide monotonic origin (`now_ns`), in
//   nanoseconds: the shared ARP table requires every member to use one clock
//   and one unit, and the RTTs subtract instants taken on any thread.
// - Hardware RTT: the RX stamp of a response's last octet is in device
//   ticks; each worker fits its own ClockCalibration from (now, read_clock)
//   pairs taken every 100 ms, each the most tightly bracketed of three reads
//   (`bracketed_reading`), and converts the stamp to caller time. The
//   request's start is its Scheduled stamp: the caller time of the drive
//   that handed its octets to the queue. With `rte_eth_read_clock`
//   unsupported, or no stamps, no hardware RTT is reported.

use ntcp_io::ClockDescriptor;
use ntcp_io_dpdk::{
    ClockCalibration, ClockFit, Eal, HostedQueue, Port, PortConfig, QueueHandle, bracketed_reading,
};
use ntcp_native::{
    CallerTimebase, ConnId, Error as NetError, EthernetNextHop, Event, Link, Network,
    NetworkConfig, ReadOutcome, SharedNeighborLimits, SharedNeighbors, TimestampClock,
    TimestampEvent, TxTimestampOutcome, TxTimestampRequest, TxTimestampStage, WorkBudget,
    WriteOptions,
};
use std::{
    collections::HashMap,
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    process::ExitCode,
    sync::OnceLock,
    time::{Duration, Instant},
};

const NANOS: u64 = 1_000_000_000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
// After the measured window: in-flight responses, then FIN exchanges.
const DRAIN: Duration = Duration::from_secs(1);
const LINGER: Duration = Duration::from_secs(1);
const CALIBRATION_PERIOD: u64 = NANOS / 10;
const CALIBRATION_WINDOW: usize = 32;
// Device clock reads per paired reading; the most tightly bracketed is kept.
const CALIBRATION_READS: usize = 3;
const REQUEST_LEN: usize = 16;

static ORIGIN: OnceLock<Instant> = OnceLock::new();

// Nanoseconds since the process-wide origin, on every thread.
fn now_ns() -> u64 {
    ORIGIN.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

struct Args {
    dev: String,
    eal: Vec<String>,
    ips: Vec<Ipv4Addr>,
    prefix: u8,
    gateway: Option<Ipv4Addr>,
    neighbors: Vec<(Ipv4Addr, [u8; 6])>,
    server: SocketAddrV4,
    connections: usize,
    duration: Duration,
    isolate: bool,
    rx_timestamps: bool,
    cpus: Vec<usize>,
}

const USAGE: &str = "usage: dpdk_echo --dev DEVARGS [--eal ARG]... --ip A.B.C.D [--ip ...] \
--prefix LEN [--gateway A.B.C.D] [--neighbor A.B.C.D=MAC]... --server IP:PORT \
[--connections N] [--duration SECS] [--isolate] [--rx-timestamps] [--cpu N]... \
[--secret-from-urandom]";

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
        eal: Vec::new(),
        ips: Vec::new(),
        prefix: 0,
        gateway: None,
        neighbors: Vec::new(),
        server: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        connections: 1,
        duration: Duration::from_secs(10),
        isolate: false,
        rx_timestamps: false,
        cpus: Vec::new(),
    };
    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        let mut value = || iter.next().ok_or_else(|| format!("{flag} needs a value"));
        let bad = |what: &str| format!("bad {flag} {what}");
        match flag.as_str() {
            "--dev" => args.dev = value()?,
            "--eal" => args.eal.push(value()?),
            "--ip" => args.ips.push(value()?.parse().map_err(|_| bad("address"))?),
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
            "--isolate" => args.isolate = true,
            "--rx-timestamps" => args.rx_timestamps = true,
            "--cpu" => args.cpus.push(value()?.parse().map_err(|_| bad("CPU"))?),
            // The only source of TCP secrets this example has.
            "--secret-from-urandom" => {}
            "-h" | "--help" => return Err(USAGE.into()),
            _ => return Err(format!("unknown argument {flag}\n{USAGE}")),
        }
    }
    if args.dev.is_empty() || args.ips.is_empty() || args.prefix == 0 || args.server.port() == 0 {
        return Err(USAGE.into());
    }
    if args.connections == 0 || !args.cpus.is_empty() && args.cpus.len() != args.ips.len() {
        return Err("--connections must be positive and --cpu given once per --ip".into());
    }
    if args.ips.len() > usize::from(u16::MAX) {
        return Err("too many addresses".into());
    }
    Ok(args)
}

// `[DDDD:]BB:DD.F`, possibly followed by `,key=value` PMD arguments.
fn is_pci(devargs: &str) -> bool {
    let name = devargs.split(',').next().unwrap_or("");
    let Some((head, function)) = name.rsplit_once('.') else {
        return false;
    };
    let fields: Vec<_> = head.split(':').collect();
    matches!(fields.len(), 2 | 3)
        && fields
            .iter()
            .chain([&function])
            .all(|f| !f.is_empty() && f.chars().all(|c| c.is_ascii_hexdigit()))
}

fn affinity() -> std::io::Result<libc::cpu_set_t> {
    // SAFETY: an all-zero cpu_set_t is the empty set.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: writes at most size_of::<cpu_set_t>() bytes into `set`.
    if unsafe { libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &mut set) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(set)
}

fn set_affinity(set: &libc::cpu_set_t) -> std::io::Result<()> {
    // SAFETY: reads size_of::<cpu_set_t>() bytes of `set`; 0 is this thread.
    if unsafe { libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), set) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
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

fn first_cpu(set: &libc::cpu_set_t) -> Option<usize> {
    // SAFETY: every index is below CPU_SETSIZE.
    (0..libc::CPU_SETSIZE as usize).find(|&cpu| unsafe { libc::CPU_ISSET(cpu, set) })
}

#[derive(Default)]
struct Report {
    requests: u64,
    window_ns: u64,
    software_rtt: Vec<u64>,
    hardware_rtt: Vec<u64>,
    // Responses without a usable hardware stamp, Scheduled stamp or fit, and
    // conversions that landed before the request was scheduled.
    hardware_missing: u64,
    hardware_negative: u64,
    arp_sent: u64,
    arp_received: u64,
    clock: Option<String>,
    fit: Option<ClockFit>,
    calibration_rejected: u64,
    errors: Vec<String>,
}

struct Pending {
    request: [u8; REQUEST_LEN],
    written: usize,
    response: [u8; REQUEST_LEN],
    received: usize,
    started: u64,
    scheduled: Option<u64>,
    rx_stamp: Option<u64>,
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
            eprintln!("dpdk_echo: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<bool, Box<dyn std::error::Error>> {
    let args = parse_args()?;
    let original = affinity()?;
    let mut eal_args = vec![
        if is_pci(&args.dev) { "-a" } else { "--vdev" }.to_owned(),
        args.dev.clone(),
    ];
    let names_lcores = args.eal.iter().any(|a| {
        ["-l", "-c", "--lcores", "-L"]
            .iter()
            .any(|flag| a == flag || a.starts_with(&format!("{flag}=")))
            || a.starts_with("-l") && a.len() > 2
    });
    if !names_lcores {
        let cpu = first_cpu(&original).ok_or("empty CPU affinity")?;
        eal_args.push(format!("--lcores=0@{cpu}"));
    }
    eal_args.extend(args.eal.iter().cloned());
    eprintln!("EAL {}", eal_args.join(" "));
    let eal = Eal::init(eal_args)?;

    let mut config = PortConfig::new(args.dev.clone());
    config.queues = args.ips.len() as u16;
    config.isolate = args.isolate;
    config.rx_timestamps = args.rx_timestamps;
    let port = Port::start(eal, config)?;
    let mac = port.mac_address()?;
    let mac_text = mac.map(|o| format!("{o:02x}")).join(":");
    eprintln!(
        "PORT {} mac={mac_text} queues={} clock={:?}",
        port.port_id(),
        port.queues(),
        port.clock()
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
    let mut flows = Vec::new();
    for (queue, &ip) in args.ips.iter().enumerate() {
        match port.steer_ipv4(ip, queue as u16) {
            Ok(flow) => {
                eprintln!("FLOW {ip} -> queue {queue}");
                flows.push(flow);
            }
            // One queue without isolation already receives everything.
            Err(error) if !args.isolate && threads == 1 => {
                eprintln!("FLOW {ip} not installed ({error}); queue 0 receives all traffic");
            }
            Err(error) => return Err(format!("steer {ip} to queue {queue}: {error}").into()),
        }
    }

    let args = std::sync::Arc::new(args);
    let mut workers = Vec::new();
    for (index, &ip) in args.ips.iter().enumerate() {
        let worker = Worker {
            index,
            ip,
            handle: port.take_queue(index as u16)?,
            cpu: args.cpus.get(index).map(|&c| single_cpu(c)).transpose()?,
            neighbors: neighbors.clone(),
        };
        let args = args.clone();
        workers.push(
            std::thread::Builder::new()
                .name(format!("ntcp-q{index}"))
                .spawn(move || serve(worker, original, &args))?,
        );
    }
    let mut reports = Vec::new();
    for (index, worker) in workers.into_iter().enumerate() {
        reports.push(worker.join().unwrap_or_else(|_| Report {
            errors: vec![format!("worker {index} panicked")],
            ..Report::default()
        }));
    }
    drop(flows);
    Ok(summarize(&reports, &neighbors))
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    // Nearest rank.
    let rank = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

fn summarize(reports: &[Report], neighbors: &SharedNeighbors) -> bool {
    let requests: u64 = reports.iter().map(|r| r.requests).sum();
    // Workers measure concurrently: the rate of each, summed.
    let rate: f64 = reports
        .iter()
        .filter(|r| r.window_ns != 0)
        .map(|r| r.requests as f64 * NANOS as f64 / r.window_ns as f64)
        .sum();
    let mut software: Vec<u64> = reports
        .iter()
        .flat_map(|r| r.software_rtt.clone())
        .collect();
    let mut hardware: Vec<u64> = reports
        .iter()
        .flat_map(|r| r.hardware_rtt.clone())
        .collect();
    software.sort_unstable();
    hardware.sort_unstable();
    let errors: usize = reports.iter().map(|r| r.errors.len()).sum();
    for (index, report) in reports.iter().enumerate() {
        for error in &report.errors {
            eprintln!("ERROR worker {index}: {error}");
        }
        if let Some(clock) = &report.clock {
            eprintln!("NOTE worker {index}: {clock}");
        }
    }
    println!("METRIC requests={requests}");
    println!("METRIC requests_per_second={rate:.1}");
    if !software.is_empty() {
        println!("METRIC sw_rtt_p50_ns={}", percentile(&software, 0.5));
        println!("METRIC sw_rtt_p99_ns={}", percentile(&software, 0.99));
    }
    println!("METRIC hw_rtt_samples={}", hardware.len());
    if !hardware.is_empty() {
        println!("METRIC hw_rtt_p50_ns={}", percentile(&hardware, 0.5));
        println!("METRIC hw_rtt_p99_ns={}", percentile(&hardware, 0.99));
    }
    let sum = |f: fn(&Report) -> u64| -> u64 { reports.iter().map(f).sum() };
    println!("METRIC hw_rtt_missing={}", sum(|r| r.hardware_missing));
    println!("METRIC hw_rtt_negative={}", sum(|r| r.hardware_negative));
    println!("METRIC arp_sent={}", sum(|r| r.arp_sent));
    println!("METRIC arp_received={}", sum(|r| r.arp_received));
    // The port's table counts failures once for all members.
    let arp = neighbors.counters();
    println!("METRIC arp_resolution_failures={}", arp.resolution_failures);
    println!("METRIC arp_requests_sent={}", arp.requests_sent);
    println!("METRIC arp_replies_sent={}", arp.replies_sent);
    for (index, report) in reports.iter().enumerate() {
        println!(
            "METRIC t{index}_calibration_rejected={}",
            report.calibration_rejected
        );
        if let Some(fit) = report.fit {
            println!("METRIC t{index}_calibration_rate={:.9}", fit.rate());
            println!("METRIC t{index}_residual_rms_ns={:.1}", fit.residual_rms());
            println!("METRIC t{index}_max_residual_ns={:.1}", fit.max_residual());
            println!("METRIC t{index}_inliers={}", fit.inliers());
            println!("METRIC t{index}_outliers={}", fit.outliers());
        }
    }
    println!("METRIC errors={errors}");
    errors == 0 && requests != 0
}

fn serve(worker: Worker, original: libc::cpu_set_t, args: &Args) -> Report {
    let mut report = Report::default();
    if let Err(error) = serve_into(worker, original, args, &mut report) {
        report.errors.push(error);
    }
    report
}

fn serve_into(
    worker: Worker,
    original: libc::cpu_set_t,
    args: &Args,
    report: &mut Report,
) -> Result<(), String> {
    // Before attaching: rte_thread_register records the thread's CPU set.
    set_affinity(worker.cpu.as_ref().unwrap_or(&original))
        .map_err(|e| format!("sched_setaffinity: {e}"))?;
    let queue = worker.handle.attach().map_err(|e| format!("attach: {e}"))?;
    let clock = queue.clock();
    let mut calibration = ClockCalibration::new(CALIBRATION_WINDOW).unwrap();
    let calibrate = match queue.read_clock() {
        Ok(_) => true,
        Err(error) => {
            report.clock = Some(format!("no clock calibration and no hardware RTT: {error}"));
            false
        }
    };
    if calibrate && clock.is_none() {
        report.clock = Some("device clock readable, but RX timestamps are off".into());
    }

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
    // A response's stamps come with its last read; a few ranges per
    // connection cover segments read together.
    config.rx_timestamp_ranges = 4;
    // One Scheduled stamp per request, one request in flight per connection;
    // room for a partial write's second stamp and one drain behind.
    config.tx_timestamp_phases = 4;
    let mut network =
        Network::with_shared_neighbors(config, queue, secret, now_ns(), &worker.neighbors)
            .map_err(|e| format!("network: {e}"))?;

    let outcome = exchange(
        &mut network,
        args,
        worker.index,
        clock,
        calibrate.then_some(&mut calibration),
        report,
    );
    // Counters and fit also describe a failed run.
    let counters = network.counters();
    report.arp_sent = counters.arp_sent;
    report.arp_received = counters.arp_received;
    report.fit = calibration.fit().copied();
    outcome
}

// Connect, run the closed loop for the window, drain, close and linger.
fn exchange(
    network: &mut Network<HostedQueue>,
    args: &Args,
    index: usize,
    clock: Option<ClockDescriptor>,
    mut calibration: Option<&mut ClockCalibration>,
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
    let mut stamps = [TimestampEvent {
        connection: connections[0].id,
        observation: ntcp_native::TxTimestampEvent {
            cookie: 0,
            target: 0,
            stage: TxTimestampStage::Scheduled,
            source: ntcp_native::TxTimestampSource::Software,
            outcome: TxTimestampOutcome::Cancelled,
        },
    }; 64];
    let mut next_request = (index as u64) << 48;
    let mut next_calibration = 0;
    let started = now_ns();
    let mut window: Option<(u64, u64)> = None;
    let mut closing_since: Option<u64> = None;
    let mut rtt_capacity = false;
    let mut last_done = 0;

    loop {
        let now = now_ns();
        if let Some(calibration) = &mut calibration
            && now >= next_calibration
        {
            next_calibration = now + CALIBRATION_PERIOD;
            let queue = network.backend();
            match bracketed_reading(CALIBRATION_READS, now_ns, || queue.read_clock()) {
                Ok((caller, ticks)) => {
                    if calibration.push(caller, ticks).is_err() {
                        report.calibration_rejected += 1;
                    }
                }
                Err(error) => return Err(format!("read_clock: {error}")),
            }
        }
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
        loop {
            let batch = network.drain_timestamps(&mut stamps);
            for stamp in &stamps[..batch.written] {
                let observation = stamp.observation;
                let TxTimestampOutcome::Recorded { value, .. } = observation.outcome else {
                    continue;
                };
                if observation.stage != TxTimestampStage::Scheduled {
                    continue;
                }
                let Some(&slot) = slots.get(&stamp.connection) else {
                    continue;
                };
                if let Some(pending) = &mut connections[slot].pending
                    && u64::from_le_bytes(pending.request[..8].try_into().unwrap())
                        == observation.cookie
                {
                    // A partial write's later stamp covers its last octet.
                    pending.scheduled = Some(value);
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
                    scheduled: None,
                    rx_stamp: None,
                });
            }
            let Some(pending) = &mut connection.pending else {
                continue;
            };
            if pending.written < REQUEST_LEN {
                let options = WriteOptions {
                    timestamps: TxTimestampRequest {
                        cookie: u64::from_le_bytes(pending.request[..8].try_into().unwrap()),
                        scheduled: true,
                        ..TxTimestampRequest::default()
                    },
                };
                match network.try_write(connection.id, &pending.request[pending.written..], options)
                {
                    Ok(receipt) => pending.written += receipt.accepted,
                    Err(error) if error.is_would_block() => {}
                    Err(error) => return Err(format!("write: {error}")),
                }
            }
            match network.try_read(connection.id, &mut pending.response[pending.received..]) {
                Ok(ReadOutcome::Data {
                    len,
                    last_byte_timestamps,
                    ..
                }) => {
                    pending.received += len;
                    pending.rx_stamp = last_byte_timestamps
                        .and_then(|t| t.timestamps.hardware)
                        .filter(|stamp| {
                            matches!(stamp.clock, TimestampClock::DeviceTicks { .. })
                                && network.backend_clock(stamp.clock) == clock
                        })
                        .map(|stamp| stamp.value);
                }
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
            if !rtt_capacity {
                report.software_rtt.reserve(1 << 20);
                rtt_capacity = true;
            }
            report.requests += 1;
            last_done = done;
            report.software_rtt.push(done - pending.started);
            let converted = pending
                .rx_stamp
                .and_then(|ticks| calibration.as_ref()?.to_caller(ticks));
            match (converted, pending.scheduled) {
                (Some(rx), Some(scheduled)) if rx >= scheduled => {
                    report.hardware_rtt.push(rx - scheduled);
                }
                (Some(_), Some(_)) => report.hardware_negative += 1,
                _ => report.hardware_missing += 1,
            }
        }
    }
    // Requests start until the window ends; the rate counts to the last
    // response, which may complete during the drain.
    if let Some((start, _)) = window {
        report.window_ns = last_done.saturating_sub(start);
    }
    Ok(())
}
