// A closed-loop xylem-echo client on a DPDK port: one ntcp-native Network
// per local IPv4 address, each on its own queue pair and pinned worker
// thread, the Networks sharing the port's ARP table. With `--members N` the
// port instead serves one address with N Networks, one per queue pair and
// worker, that divide its flows (ntcp-native's SharedFlows) and each open
// their share of the connections. Each connection sends a request of
// `--request-size` octets (default 16): [request id: u64 LE][delay us: u64
// LE = 0], then pseudorandom octets drawn from the id and their offset. It
// waits for the same octets back, compares every one, and sends the next.
// A larger request needs a peer that echoes the byte stream unchanged, as
// ntcp-lab's does. It prints `METRIC name=value` lines and exits nonzero
// on any failure, a differing echo included, or if no request completed.
//
//   dpdk_echo --dev DEVARGS [--eal ARG]... --ip A.B.C.D [--ip ...] --prefix LEN
//             [--gateway A.B.C.D] [--neighbor A.B.C.D=MAC]... --server IP:PORT
//             [--connections N] [--duration SECS] [--request-size OCTETS]
//             [--isolate] [--rx-timestamps] [--cpu N]...
//             [--members N [--steering auto|rules|rss|none]] [--secret-from-urandom]
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
// - Shared address: which queue gets which frames? Member k drives queue k,
//   and a member takes in only the flows it owns; any other packet it copies
//   into the owner's inbox, so the steering mode decides how many packets
//   are handed off, never whether a connection works. `--steering rss`
//   spreads the port by RSS over all queues and installs no rule for the
//   address (a rule would take its traffic away from RSS). The members'
//   ownership mirrors the key and redirection table read back after start,
//   each table entry's queue naming its member, so a TCP segment arrives
//   at its owner; ICMP errors, which hash on the router's address, and
//   fragments, if the device does not hash them by addresses alone, may
//   land elsewhere and are handed off. `--steering none` keeps RSS off:
//   without `--isolate` every frame lands on queue 0, with it a rule steers
//   the address to queue 0, and member 0 hands each flow it does not own,
//   about (N-1)/N of them, to its owner. Ownership then hashes with ntcp's
//   default key over a round-robin table. Non-IP frames go where the port
//   puts unhashed traffic; the shared ARP table serves every member.
// - What does `--steering rules` add? Tier 1 of the design, ownership by
//   `FlowOwnership::TaggedPorts`: a member's active opens take only local
//   ports tagged with its number, `0xC000 | k` under the mask `0xC000 |
//   2^b - 1` (b bits number the members), and one TCP destination-port
//   rule per member (`SharedFlows::port_rule`, `Port::steer_tcp_port`)
//   steers what arrives for them to its queue, whatever the peer. The
//   other flows are owned and reach their queues as under rss when the
//   device's RSS is usable, else as under none. The tagged ports lie in
//   NetworkConfig's default ephemeral ports, 49152-65535, so every member
//   opens from its own.
// - Do the rules overlap? Without `--isolate` they do not: what they leave
//   follows RSS, or lands on queue 0, with no rule of its own. An isolated
//   port takes in only what rules match, so the address's other traffic
//   needs `steer_ipv4` to queue 0, which matches the tagged ports too, at
//   the port rules' rte_flow priority. rte_flow leaves the order of such
//   rules undefined; mlx5 matches the deepest layer first, so its port
//   rules win. The example combines the two only on mlx5
//   (`Port::driver_name` `mlx5_pci` or `mlx5_auxiliary`) and refuses rules
//   on any other isolated port: where the address rule won, every frame
//   would reach queue 0, which still works by handoff but is not the
//   steering it would report.
// - Why is ownership fixed at start? A connection's owner must not change
//   while it lives: active opens pick local ports whose flows they own, and
//   members route packets by the function without asking each other. It is
//   built once, from the RSS state read right after start and before any
//   member joins. Only then may the example rewrite the table: one that
//   names some member nowhere (the null PMD's is all queue 0) becomes
//   round-robin, since that member would own no flows and could open no
//   connection. A device that later moves its table only costs handoffs.
// - What does `--steering auto` choose? rules if every member's rule
//   validates and installs (isolated, only on mlx5). Otherwise rss if the
//   device takes RSS at start and the state read back is usable: Toeplitz
//   hashing, the IPv4 TCP hash type granted, a key of at least 16 octets,
//   and a power-of-two table naming every member's queue and no other. A
//   copy of the device's hash predicts its queues only for Toeplitz. A PMD
//   that does not report its function (mlx5, whose function is Toeplitz)
//   is assumed to use it, and `METRIC handed_off` near zero confirms the
//   guess; a wrong guess costs handoffs, never a connection. A device that
//   refuses RSS at start is started again without it. Otherwise none, as
//   always on an isolated port without rules (it spreads nothing by RSS);
//   a port that took RSS but whose state is unusable keeps spreading by
//   it, which costs handoffs but no connection. The choice, and why the
//   tiers above it were passed over, are printed, and the choice is
//   reported as `METRIC steering`. An explicit `--steering rules` or `rss`
//   fails instead of falling back.
// - TCP segmentation: the port asks for TSO (`PortConfig::tcp_segmentation`)
//   and gets it where the device offers it with TCP and IPv4 checksum
//   offloads; each queue then takes aggregates of many segments, cut by the
//   device, which also fills their checksums (`PORT ... tso=`, `METRIC
//   t<k>_tso`). Elsewhere every segment leaves on its own, as before. Only a
//   write of more than a segment forms an aggregate: requests of 16 octets
//   never do, `--request-size 65536` does. On mlx5 (`METRIC t<k>_tso_psh`)
//   the request's pushed short last segment joins its aggregate; elsewhere
//   it leaves on its own after it, so a request of 2000 octets (two
//   segments) forms an aggregate on mlx5 only. The echo checks each request's
//   octets end to end, so a wrongly cut or checksummed aggregate shows as a
//   differing echo, or as a segment the peer drops and ntcp retransmits.

use ntcp_io::{ClockDescriptor, PacketIo};
use ntcp_io_dpdk::{
    ClockCalibration, ClockFit, Eal, Flow, HostedQueue, Port, PortConfig, QueueHandle,
    RssAlgorithm, bracketed_reading,
};
use ntcp_native::{
    CallerTimebase, ConnId, DEFAULT_FLOW_KEY, Error as NetError, EthernetNextHop, Event,
    FlowOwnership, Link, Network, NetworkConfig, ReadOutcome, SharedFlowLimits, SharedFlows,
    SharedNeighborLimits, SharedNeighbors, TimestampClock, TimestampEvent, TxTimestampOutcome,
    TxTimestampRequest, TxTimestampStage, WorkBudget, WriteOptions,
};
use std::{
    collections::HashMap,
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    process::ExitCode,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

const NANOS: u64 = 1_000_000_000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
// After the measured window: in-flight responses, then FIN exchanges. A
// response whose request or reply segment was lost waits for a retransmission
// timeout (ntcp's is at least 1 s, doubled after a lost retransmission), so
// the drain outlasts one timeout and its backoff.
const DRAIN: Duration = Duration::from_secs(3);
const LINGER: Duration = Duration::from_secs(1);
const CALIBRATION_PERIOD: u64 = NANOS / 10;
const CALIBRATION_WINDOW: usize = 32;
// Device clock reads per paired reading; the most tightly bracketed is kept.
const CALIBRATION_READS: usize = 3;
// A request's header, and the whole of the default request.
const REQUEST_LEN: usize = 16;
const MAX_REQUEST: usize = 1 << 24;
// Tagged local ports of `--steering rules`: the IANA dynamic range
// 49152-65535, NetworkConfig's default ephemeral ports.
const TAG_PREFIX: u16 = 0xC000;
const TAG_MASK: u16 = 0xC000;
// Drivers that match a TCP port rule before an IPv4 rule for the same
// address at one rte_flow priority: mlx5 orders such rules by their deepest
// layer, on PCI functions and subfunctions alike.
const PORT_RULES_FIRST: [&str; 2] = ["mlx5_pci", "mlx5_auxiliary"];

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
    request_size: usize,
    isolate: bool,
    rx_timestamps: bool,
    cpus: Vec<usize>,
    // Shared-address mode: members on the one address.
    members: Option<usize>,
    steering: Steering,
}

// How frames of the shared address reach their members: tiers 1 (masked
// local-port rules), 2 (rss) and 3 (none) of the design. `auto` takes the
// first that works.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Steering {
    Auto,
    Rules,
    Rss,
    Off,
}

const USAGE: &str = "usage: dpdk_echo --dev DEVARGS [--eal ARG]... --ip A.B.C.D [--ip ...] \
--prefix LEN [--gateway A.B.C.D] [--neighbor A.B.C.D=MAC]... --server IP:PORT \
[--connections N] [--duration SECS] [--request-size OCTETS] [--isolate] [--rx-timestamps] \
[--cpu N]... [--members N [--steering auto|rules|rss|none]] [--secret-from-urandom]

Without --members, one Network per --ip, each on its own queue (and --cpu, if given).
--members N: N Networks share the single --ip, one per queue (and --cpu, if given),
and open --connections (at least N) between them. --steering (default auto) picks how
frames reach them, reported as METRIC steering: 1 none (ntcp's own key, software
handoff; RSS off, so queue 0 receives), 2 rss (the device's RSS key and table
mirrored), 3 rules (member k opens from local ports 0xC000 | k under the mask
0xC000 | 2^b - 1, b bits numbering the members, and one TCP port rule per member
steers them to its queue; other flows as rss when usable, else as none; with
--isolate only on mlx5, which orders the port rules before the address rule).
auto takes rules when every member's rule installs, else rss when usable, else none.
--request-size (default 16, at least 16): each request's octets, echoed and compared;
above one segment ntcp sends them as TSO aggregates where the port offers TSO
(METRIC tso_queues, segmented, segmentation_refused).";

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
        request_size: REQUEST_LEN,
        isolate: false,
        rx_timestamps: false,
        cpus: Vec::new(),
        members: None,
        steering: Steering::Auto,
    };
    let mut steering = false;
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
            "--request-size" => {
                args.request_size = value()?.parse().map_err(|_| bad("octets"))?;
                if !(REQUEST_LEN..=MAX_REQUEST).contains(&args.request_size) {
                    return Err(bad(&format!("octets ({REQUEST_LEN} to {MAX_REQUEST})")));
                }
            }
            "--isolate" => args.isolate = true,
            "--rx-timestamps" => args.rx_timestamps = true,
            "--cpu" => args.cpus.push(value()?.parse().map_err(|_| bad("CPU"))?),
            "--members" => args.members = Some(value()?.parse().map_err(|_| bad("count"))?),
            "--steering" => {
                args.steering = match value()?.as_str() {
                    "auto" => Steering::Auto,
                    "rules" => Steering::Rules,
                    "rss" => Steering::Rss,
                    "none" => Steering::Off,
                    _ => return Err(bad("mode (auto, rules, rss or none)")),
                };
                steering = true;
            }
            // The only source of TCP secrets this example has.
            "--secret-from-urandom" => {}
            "-h" | "--help" => return Err(USAGE.into()),
            _ => return Err(format!("unknown argument {flag}\n{USAGE}")),
        }
    }
    if args.dev.is_empty() || args.ips.is_empty() || args.prefix == 0 || args.server.port() == 0 {
        return Err(USAGE.into());
    }
    if let Some(members) = args.members {
        if args.ips.len() != 1 || members == 0 || args.connections < members {
            return Err("--members needs one --ip, and --connections at least --members".into());
        }
        if !args.cpus.is_empty() && args.cpus.len() != members {
            return Err("--cpu given once per member".into());
        }
        if members > usize::from(u16::MAX) {
            return Err("too many members".into());
        }
        return Ok(args);
    }
    if steering {
        return Err("--steering requires --members".into());
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
    // Octets of the requests whose echo matched, the request headers included.
    echoed: u64,
    window_ns: u64,
    software_rtt: Vec<u64>,
    hardware_rtt: Vec<u64>,
    // Responses without a usable hardware stamp, Scheduled stamp or fit, and
    // conversions that landed before the request was scheduled.
    hardware_missing: u64,
    hardware_negative: u64,
    arp_sent: u64,
    arp_received: u64,
    connections: usize,
    handed_off: u64,
    handoffs_received: u64,
    handoffs_dropped: u64,
    // The queue's largest TCP aggregate and whether its aggregates may carry
    // PSH and FIN (on the last segment: mlx5 only), None without TCP
    // segmentation.
    tso: Option<(usize, bool)>,
    // Network::counters at the end.
    counters: ntcp_native::Counters,
    clock: Option<String>,
    fit: Option<ClockFit>,
    calibration_rejected: u64,
    errors: Vec<String>,
}

struct Pending {
    id: u64,
    written: usize,
    received: usize,
    started: u64,
    scheduled: Option<u64>,
    rx_stamp: Option<u64>,
}

struct Connection {
    id: ConnId,
    connected: bool,
    closed: bool,
    // The pending request's octets, and what has come back of them.
    request: Vec<u8>,
    response: Vec<u8>,
    pending: Option<Pending>,
}

// Request `id`: its header, then octets that depend on the id and their
// offset (splitmix64 over consecutive states), so an octet echoed from
// another offset, request or connection differs.
fn fill_request(request: &mut [u8], id: u64) {
    let (header, payload) = request.split_at_mut(REQUEST_LEN);
    header[..8].copy_from_slice(&id.to_le_bytes());
    header[8..].fill(0);
    let mut state = id;
    for chunk in payload.chunks_mut(8) {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
    }
}

struct Worker {
    index: usize,
    ip: Ipv4Addr,
    handle: QueueHandle,
    cpu: Option<libc::cpu_set_t>,
    neighbors: SharedNeighbors,
    secret: [u8; 32],
    connections: usize,
    // Shared-address mode: the flows and this worker's member index.
    flows: Option<(SharedFlows, usize)>,
    finished: Finished,
}

// Workers that have finished their exchange. A worker's queue can carry
// frames for the others (ARP for every address lands on one queue, and with
// no steering every member's flows arrive on the first member's queue), and
// no other worker reads it, so each keeps driving until all have finished.
// A worker that fails or panics counts when its Worker drops.
struct Finished {
    count: Arc<AtomicUsize>,
    workers: usize,
    counted: bool,
}

impl Finished {
    fn mark(&mut self) {
        if !std::mem::replace(&mut self.counted, true) {
            self.count.fetch_add(1, Ordering::Release);
        }
    }
    fn all(&self) -> bool {
        self.count.load(Ordering::Acquire) == self.workers
    }
}

impl Drop for Finished {
    fn drop(&mut self) {
        self.mark();
    }
}

// Serve the queue for the other workers, discarding events, until every
// worker has finished.
fn serve_others(network: &mut Network<HostedQueue>, finished: &Finished) {
    let mut events = [Event::NetworkStopped; 64];
    while !finished.all() {
        if network
            .drive(now_ns(), WorkBudget::new(64, 64, 64, 64))
            .is_err()
        {
            return;
        }
        while network.drain_events(&mut events).more {}
    }
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

    let threads = args.members.unwrap_or(args.ips.len());
    let mut config = PortConfig::new(args.dev.clone());
    config.queues = threads as u16;
    config.isolate = args.isolate;
    config.rx_timestamps = args.rx_timestamps;
    // Where the device offers it; Port::tcp_segmentation tells.
    config.tcp_segmentation = true;
    // An isolated port spreads nothing by RSS; Port::start refuses both.
    // Under rules, RSS spreads the flows no rule takes.
    config.rss = args.members.is_some()
        && match args.steering {
            Steering::Rss => true,
            Steering::Auto | Steering::Rules => !args.isolate,
            Steering::Off => false,
        };
    let port = match Port::start(eal, config.clone()) {
        Err(error) if config.rss && args.steering != Steering::Rss => {
            eprintln!("STEERING rss refused at start ({error}); starting without");
            config.rss = false;
            Port::start(eal, config.clone())?
        }
        port => port?,
    };
    let mac = port.mac_address()?;
    let mac_text = mac.map(|o| format!("{o:02x}")).join(":");
    eprintln!(
        "PORT {} mac={mac_text} queues={} clock={:?} tso={}",
        port.port_id(),
        port.queues(),
        port.clock(),
        port.tcp_segmentation()
    );
    // Before any member joins: ownership is fixed for the port's life.
    let steered = match args.members {
        Some(members) => {
            let limits = SharedFlowLimits {
                members,
                // As many packets as an RX ring holds: under `none` queue 0
                // receives every member's frames and passes them on, so an
                // inbox stands in for the ring the device would have filled
                // for its member, and a longer backlog is dropped as an
                // overflowing ring drops it.
                inbox_packets: usize::from(config.rx_desc),
                // The port's largest IP packet.
                packet_bytes: usize::from(config.mtu),
                // The members only open connections, from ports whose flows
                // they own: none takes another's SYN.
                redirected_flows: 0,
            };
            Some(steer(&port, &args, limits)?)
        }
        None => None,
    };
    // Connections per worker: every address opens them all, members split them.
    let shares: Vec<usize> = match args.members {
        Some(members) => (0..members)
            .map(|k| args.connections / members + usize::from(k < args.connections % members))
            .collect(),
        None => vec![args.connections; threads],
    };
    let neighbors = SharedNeighbors::new(
        mac,
        NANOS,
        SharedNeighborLimits {
            members: threads,
            entries: 64 + args.neighbors.len(),
            // Each member reserves max_connections + 1 output owners.
            held: shares.iter().map(|share| share + 1).sum(),
            replies: 16,
        },
    )?;
    let mut rules = Vec::new();
    let mut shared = None;
    if let Some((flows, steering, installed)) = steered {
        rules = installed;
        shared = Some((flows, steering));
    } else {
        for (queue, &ip) in args.ips.iter().enumerate() {
            match port.steer_ipv4(ip, queue as u16) {
                Ok(flow) => {
                    eprintln!("FLOW {ip} -> queue {queue}");
                    rules.push(flow);
                }
                // One queue without isolation already receives everything.
                Err(error) if !args.isolate && threads == 1 => {
                    eprintln!("FLOW {ip} not installed ({error}); queue 0 receives all traffic");
                }
                Err(error) => return Err(format!("steer {ip} to queue {queue}: {error}").into()),
            }
        }
    }

    // Members share one secret, as one host has one: each member's ISNs and
    // SYN cookies must hold for flows another member hands it.
    let common = shared.as_ref().map(|_| random_secret()).transpose()?;
    let args = Arc::new(args);
    let finished = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();
    for (index, &connections) in shares.iter().enumerate() {
        let worker = Worker {
            index,
            ip: args.ips[if shared.is_some() { 0 } else { index }],
            handle: port.take_queue(index as u16)?,
            cpu: args.cpus.get(index).map(|&c| single_cpu(c)).transpose()?,
            neighbors: neighbors.clone(),
            secret: match common {
                Some(secret) => secret,
                None => random_secret()?,
            },
            connections,
            flows: shared.as_ref().map(|(flows, _)| (flows.clone(), index)),
            finished: Finished {
                count: finished.clone(),
                workers: shares.len(),
                counted: false,
            },
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
    drop(rules);
    let steering = shared.map(|(_, steering)| steering);
    Ok(summarize(&reports, &neighbors, steering))
}

fn random_secret() -> Result<[u8; 32], String> {
    let mut secret = [0; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut secret))
        .map_err(|e| format!("/dev/urandom: {e}"))?;
    Ok(secret)
}

// The shared address's flows, with their ownership fixed for the port's
// life, the steering they rely on (never Auto) and the rules it installed.
// Member k drives queue k.
fn steer(
    port: &Port,
    args: &Args,
    limits: SharedFlowLimits,
) -> Result<(SharedFlows, Steering, Vec<Flow>), String> {
    let members = limits.members;
    let ip = args.ips[0];
    // Every steering's hash: the device's, when a copy of it predicts the
    // queues, else ntcp's key over a round-robin table.
    let mirror = if args.steering == Steering::Off {
        Err("requested".to_owned())
    } else {
        spread(port, members).and_then(|rss| usable(rss, members))
    };
    let (key, table) = match &mirror {
        Ok(hash) => hash.clone(),
        Err(why) if args.steering == Steering::Rss => return Err(format!("--steering rss: {why}")),
        // Entries enough that members not a power of two in number
        // still own nearly equal shares.
        Err(_) => (
            DEFAULT_FLOW_KEY.to_vec(),
            (0..members.next_power_of_two().max(128))
                .map(|entry| entry % members)
                .collect(),
        ),
    };
    if matches!(args.steering, Steering::Rules | Steering::Auto) {
        let ownership = FlowOwnership::TaggedPorts {
            key: key.clone(),
            table: table.clone(),
            prefix: TAG_PREFIX,
            prefix_mask: TAG_MASK,
        };
        let tagged = SharedFlows::new(ownership, limits)
            .map_err(|e| format!("shared flows: {e}"))
            .and_then(|flows| Ok((tag_rules(port, &flows, ip, args.isolate)?, flows)));
        match tagged {
            Ok((rules, flows)) => {
                match &mirror {
                    Ok(_) => eprintln!(
                        "STEERING rules: tagged ports by rule, other flows by the device's key \
                         and table"
                    ),
                    Err(why) => eprintln!(
                        "STEERING rules: tagged ports by rule, other flows by ntcp's key and \
                         software handoff (rss: {why})"
                    ),
                }
                return Ok((flows, Steering::Rules, rules));
            }
            Err(why) if args.steering == Steering::Rules => {
                return Err(format!("--steering rules: {why}"));
            }
            Err(why) => eprintln!("STEERING rules refused: {why}"),
        }
    }
    let flows = SharedFlows::new(FlowOwnership::Hash { key, table }, limits)
        .map_err(|e| format!("shared flows: {e}"))?;
    let why = match mirror {
        Ok(_) => {
            eprintln!("STEERING rss: the device's key and table");
            return Ok((flows, Steering::Rss, Vec::new()));
        }
        Err(why) => why,
    };
    eprintln!("STEERING none ({why}): ntcp's key, software handoff");
    let mut rules = Vec::new();
    if args.isolate {
        rules.push(
            port.steer_ipv4(ip, 0)
                .map_err(|e| format!("steer {ip} to queue 0: {e}"))?,
        );
        eprintln!("FLOW {ip} -> queue 0");
    }
    Ok((flows, Steering::Off, rules))
}

// Member k's tagged ports to queue k (`SharedFlows::port_rule`) and, on an
// isolated port, which takes in only what rules match, the address's other
// traffic to queue 0. All or none: the rules installed before a refusal are
// destroyed with the error.
fn tag_rules(
    port: &Port,
    flows: &SharedFlows,
    ip: Ipv4Addr,
    isolate: bool,
) -> Result<Vec<Flow>, String> {
    if isolate {
        let driver = port.driver_name().map_err(|e| format!("driver: {e}"))?;
        if !PORT_RULES_FIRST.contains(&driver.as_str()) {
            return Err(format!(
                "isolated, {ip} needs an ipv4 rule beside the port rules, and {driver} \
                 may match it first"
            ));
        }
    }
    let members = flows.limits().members;
    let mut rules = Vec::with_capacity(members + 1);
    let mut lines = Vec::with_capacity(members + 1);
    for member in 0..members {
        let (value, mask) = flows.port_rule(member).ok_or("no tagged ports")?;
        let queue = member as u16;
        let flow = port
            .steer_tcp_port(ip, value, mask, queue)
            .map_err(|e| format!("member {member}'s rule {value:#06x}/{mask:#06x}: {e}"))?;
        rules.push(flow);
        lines.push(format!(
            "FLOW {ip} tcp dst port {value:#06x}/{mask:#06x} -> queue {queue}"
        ));
    }
    if isolate {
        let flow = port
            .steer_ipv4(ip, 0)
            .map_err(|e| format!("steer {ip} to queue 0: {e}"))?;
        rules.push(flow);
        lines.push(format!("FLOW {ip} -> queue 0, after the port rules"));
    }
    for line in lines {
        eprintln!("{line}");
    }
    Ok(rules)
}

// The port's RSS state, with a table that names every member: a member the
// table never names owns no flows, so it could open no connection. Such a
// table is rewritten round-robin, before any member joins.
fn spread(port: &Port, members: usize) -> Result<ntcp_io_dpdk::Rss, String> {
    let read = || match port.rss() {
        Ok(Some(rss)) => {
            let mut entries = vec![0; members];
            for &queue in &rss.reta {
                if let Some(count) = entries.get_mut(usize::from(queue)) {
                    *count += 1;
                }
            }
            eprintln!(
                "RSS key={} octets algorithm={:?} tcp={} ipv4={} fragments={} reta entries per \
                 queue {entries:?}",
                rss.key.len(),
                rss.algorithm,
                rss.ipv4_tcp,
                rss.ipv4,
                rss.ipv4_fragments
            );
            Ok(rss)
        }
        Ok(None) => Err("the port spreads nothing by rss".to_owned()),
        Err(error) => Err(format!("rss state unreadable: {error}")),
    };
    let rss = read()?;
    if names_every_member(&rss.reta, members) {
        return Ok(rss);
    }
    let table: Vec<u16> = (0..rss.reta.len()).map(|e| (e % members) as u16).collect();
    port.set_reta(&table)
        .map_err(|e| format!("the reta misses a member and cannot be rewritten: {e}"))?;
    eprintln!("RSS reta rewritten round-robin");
    read()
}

fn names_every_member(reta: &[u16], members: usize) -> bool {
    (0..members).all(|member| reta.iter().any(|&queue| usize::from(queue) == member))
}

// RSS the members can mirror, as the key and table of their ownership: TCP
// hashed by Toeplitz over addresses and ports with a key that covers them,
// and a table whose low hash bits index it and that names every member and
// nothing else.
fn usable(rss: ntcp_io_dpdk::Rss, members: usize) -> Result<(Vec<u8>, Vec<usize>), String> {
    match rss.algorithm {
        RssAlgorithm::Toeplitz => {}
        // mlx5 does not report its function, Toeplitz. Any PMD that does not
        // is assumed to hash so; the handoff counters show a wrong guess.
        RssAlgorithm::Default => {
            eprintln!("RSS algorithm unreported: assuming toeplitz, verified by handed_off");
        }
        other => return Err(format!("the device hashes with {other:?}, not toeplitz")),
    }
    if !rss.ipv4_tcp {
        return Err("the device does not hash ipv4 tcp ports".into());
    }
    if rss.key.len() < 16 {
        return Err(format!("the rss key has only {} octets", rss.key.len()));
    }
    if !rss.reta.len().is_power_of_two() {
        return Err(format!("the reta has {} entries", rss.reta.len()));
    }
    if rss.reta.iter().any(|&queue| usize::from(queue) >= members) {
        return Err("the reta names a queue no member drives".into());
    }
    if !names_every_member(&rss.reta, members) {
        return Err("the reta misses a member".into());
    }
    Ok((rss.key, rss.reta.into_iter().map(usize::from).collect()))
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    // Nearest rank.
    let rank = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

fn summarize(reports: &[Report], neighbors: &SharedNeighbors, steering: Option<Steering>) -> bool {
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
    if let Some(steering) = steering {
        for (index, report) in reports.iter().enumerate() {
            eprintln!(
                "MEMBER {index} connections={} handed_off={} handoffs_received={} \
                 handoffs_dropped={} tso={} segmented={} segmentation_refused={}",
                report.connections,
                report.handed_off,
                report.handoffs_received,
                report.handoffs_dropped,
                report.tso.is_some(),
                report.counters.segmented,
                report.counters.segmentation_refused
            );
        }
        println!("METRIC handed_off={}", sum(|r| r.handed_off));
        println!("METRIC handoffs_received={}", sum(|r| r.handoffs_received));
        println!("METRIC handoffs_dropped={}", sum(|r| r.handoffs_dropped));
        // As USAGE documents the codes.
        let code = match steering {
            Steering::Off => 1,
            Steering::Rss => 2,
            Steering::Rules => 3,
            Steering::Auto => unreachable!("auto resolves at start"),
        };
        println!("METRIC steering={code}");
    }
    println!("METRIC echoed_bytes={}", sum(|r| r.echoed));
    let tso = reports.iter().filter(|r| r.tso.is_some()).count();
    println!("METRIC tso_queues={tso}");
    println!("METRIC segmented={}", sum(|r| r.counters.segmented));
    println!(
        "METRIC segmentation_refused={}",
        sum(|r| r.counters.segmentation_refused)
    );
    println!("METRIC transmitted={}", sum(|r| r.counters.transmitted));
    println!("METRIC received={}", sum(|r| r.counters.received));
    for (index, report) in reports.iter().enumerate() {
        // Per worker (member k, or the k-th --ip): its queue's segmentation
        // and its Network's counters.
        let c = &report.counters;
        println!("METRIC t{index}_tso={}", u8::from(report.tso.is_some()));
        if let Some((len, psh)) = report.tso {
            println!("METRIC t{index}_tso_max_aggregate_len={len}");
            println!("METRIC t{index}_tso_psh={}", u8::from(psh));
        }
        println!("METRIC t{index}_connections={}", report.connections);
        println!("METRIC t{index}_requests={}", report.requests);
        println!("METRIC t{index}_echoed_bytes={}", report.echoed);
        println!("METRIC t{index}_segmented={}", c.segmented);
        println!(
            "METRIC t{index}_segmentation_refused={}",
            c.segmentation_refused
        );
        println!("METRIC t{index}_transmitted={}", c.transmitted);
        println!("METRIC t{index}_received={}", c.received);
        println!("METRIC t{index}_discarded={}", c.discarded);
        println!(
            "METRIC t{index}_backend_backpressure={}",
            c.backend_backpressure
        );
        println!("METRIC t{index}_arp_sent={}", c.arp_sent);
        println!("METRIC t{index}_arp_received={}", c.arp_received);
        println!("METRIC t{index}_handed_off={}", c.handed_off);
        println!("METRIC t{index}_handoffs_received={}", c.handoffs_received);
        println!("METRIC t{index}_handoffs_dropped={}", c.handoffs_dropped);
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
    mut worker: Worker,
    original: libc::cpu_set_t,
    args: &Args,
    report: &mut Report,
) -> Result<(), String> {
    // Before attaching: rte_thread_register records the thread's CPU set.
    set_affinity(worker.cpu.as_ref().unwrap_or(&original))
        .map_err(|e| format!("sched_setaffinity: {e}"))?;
    let queue = worker.handle.attach().map_err(|e| format!("attach: {e}"))?;
    let clock = queue.clock();
    // Read once, as the Network reads it when it is built.
    report.tso = queue
        .tcp_segmentation_capabilities()
        .map(|c| (c.max_aggregate_len, c.allow_psh));
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

    // The default ephemeral ports, 49152-65535, hold every member's tagged
    // ports under `--steering rules` (TAG_PREFIX and TAG_MASK).
    let mut config = NetworkConfig::new(IpAddr::V4(worker.ip), 1500);
    config.tcp.max_connections = worker.connections;
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
    let neighbors = &worker.neighbors;
    let mut network = match &worker.flows {
        Some((flows, member)) => Network::with_shared_flows(
            config,
            queue,
            worker.secret,
            now_ns(),
            Some(neighbors),
            flows,
            *member,
        ),
        None => Network::with_shared_neighbors(config, queue, worker.secret, now_ns(), neighbors),
    }
    .map_err(|e| format!("network: {e}"))?;
    report.connections = worker.connections;

    let outcome = exchange(
        &mut network,
        args,
        worker.index,
        worker.connections,
        clock,
        calibrate.then_some(&mut calibration),
        report,
    );
    worker.finished.mark();
    serve_others(&mut network, &worker.finished);
    // Counters and fit also describe a failed run.
    let counters = network.counters();
    report.arp_sent = counters.arp_sent;
    report.arp_received = counters.arp_received;
    report.handed_off = counters.handed_off;
    report.handoffs_received = counters.handoffs_received;
    report.handoffs_dropped = counters.handoffs_dropped;
    report.counters = counters;
    report.fit = calibration.fit().copied();
    outcome
}

// Connect, run the closed loop for the window, drain, close and linger.
fn exchange(
    network: &mut Network<HostedQueue>,
    args: &Args,
    index: usize,
    count: usize,
    clock: Option<ClockDescriptor>,
    mut calibration: Option<&mut ClockCalibration>,
    report: &mut Report,
) -> Result<(), String> {
    let mut connections = Vec::with_capacity(count);
    let mut slots = HashMap::new();
    for slot in 0..count {
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
            request: vec![0; args.request_size],
            response: vec![0; args.request_size],
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
                    && pending.id == observation.cookie
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
                fill_request(&mut connection.request, next_request);
                connection.pending = Some(Pending {
                    id: next_request,
                    written: 0,
                    received: 0,
                    started: now_ns(),
                    scheduled: None,
                    rx_stamp: None,
                });
                next_request += 1;
            }
            let Some(pending) = &mut connection.pending else {
                continue;
            };
            let size = connection.request.len();
            if pending.written < size {
                let options = WriteOptions {
                    timestamps: TxTimestampRequest {
                        cookie: pending.id,
                        scheduled: true,
                        ..TxTimestampRequest::default()
                    },
                };
                match network.try_write(
                    connection.id,
                    &connection.request[pending.written..],
                    options,
                ) {
                    Ok(receipt) => pending.written += receipt.accepted,
                    Err(error) if error.is_would_block() => {}
                    Err(error) => return Err(format!("write: {error}")),
                }
            }
            match network.try_read(connection.id, &mut connection.response[pending.received..]) {
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
            if pending.received < size {
                continue;
            }
            let done = now_ns();
            let pending = connection.pending.take().unwrap();
            if connection.response != connection.request {
                let at = (0..size)
                    .find(|&i| connection.response[i] != connection.request[i])
                    .unwrap();
                let shown = at..size.min(at + REQUEST_LEN);
                return Err(format!(
                    "echo of request {:#x} differs at octet {at} of {size}: sent {:02x?}, \
                     received {:02x?}",
                    pending.id,
                    &connection.request[shown.clone()],
                    &connection.response[shown]
                ));
            }
            report.echoed += size as u64;
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
