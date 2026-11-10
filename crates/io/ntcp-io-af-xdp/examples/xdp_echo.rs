// A closed-loop xylem-echo client on an AF_XDP port: one ntcp-native Network
// per local IPv4 address, each on its own RX/TX queue pair and pinned worker
// thread, the Networks sharing the port's ARP table. Each connection sends a
// 16-octet request ([request id: u64 LE][delay us: u64 LE = 0]), waits for
// the same 16 octets back and sends the next. It prints `METRIC name=value`
// lines and exits nonzero on any failure or if no request completed. Needs
// CAP_NET_ADMIN, CAP_BPF and CAP_NET_RAW (or root).
//
// With `--shared` the Networks instead share one address: one member of
// ntcp-native's shared flows per `--queue`, each opening its share of
// `--connections` with plain `connect()`, and `--steering` chooses how
// frames reach their owners.
//
//   xdp_echo --dev IFNAME [--mode native|generic] --ip A.B.C.D [--ip ...]
//            [--queue N]... --prefix LEN [--gateway A.B.C.D]
//            [--neighbor A.B.C.D=MAC]... --server IP:PORT [--connections N]
//            [--duration SECS] [--cpu N]...
//            [--shared [--steering auto|rules|rss|none]]
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
//
// With `--shared`:
//
// - Which queues? `--queue` once per member, every member serving the one
//   `--ip`, which is added to the port once.
// - Which member owns a flow? Fixed before the first member joins.
//   `--steering rules` (tier 1) uses `FlowOwnership::TaggedPorts` with the
//   tag 0xC000/0xC000: member k's active opens take the local ports p with
//   p & 0xC000 == 0xC000 and p & low == k, low being the next power of two
//   of the member count less one, and own their flows whatever the remote.
//   One rule per member (`SharedFlows::port_rule`, `Port::steer_tcp_port`:
//   tcp4 to the address, destination port p & (0xC000 | low) == 0xC000 | k,
//   to member k's queue) delivers their replies on its queue. Every other
//   flow, fragment, ARP and ICMP is hashed and delivered as rss below when
//   the device's RSS is usable, else as none, with that mode's rules. The
//   port rules take the first free rule locations and the address rule the
//   last, so drivers that rank rules by location apply the port rules
//   first; mlx5 ranks them by the fields they match, which also puts the
//   port rules first. A driver that applies the address rule first sends
//   the replies to the first member, which hands them on: correct, but
//   `METRIC handed_off` then counts nearly every reply. `--steering rss`
//   uses `FlowOwnership::Hash` mirroring the device's RSS (`Port::rss`):
//   its key, and its indirection table with each queue replaced by the
//   queue's member. No rule is installed: RSS spreads the address's frames
//   over the hosted queues, the program hands each to its arrival queue's
//   socket, and a flow's frames arrive at its owner. That needs Toeplitz
//   with no input transform (symmetric-xor or any other), a key covering
//   addresses and ports, a power-of-two table that names every member's
//   queue and only hosted queues (a frame on a queue without a socket is
//   dropped), and a tcp4 hash over exactly both addresses and both ports
//   (`Port::rss_tcp4_fields`; `ethtool -N IF rx-flow-hash tcp4 sdfn`,
//   mlx5's default). `--steering none` uses `FlowOwnership::Hash` with
//   ntcp's own key (`DEFAULT_FLOW_KEY`) and a round-robin table, and steers
//   the address and ARP to the first member's queue, which hands every
//   other member's frames on in software. Without rules, frames arrive
//   where the device puts them, which is safe only when every enabled RX
//   queue has a member. `--steering auto` takes rules if every member's
//   rule installs, else rss when the device's RSS is usable, else none, and
//   prints why. An explicit `--steering rules` or `rss` fails instead.
// - Where does ARP go? The program hands ARP for the address to the socket
//   of its arrival queue, never to the kernel. Under rss (and rules with rss
//   for the rest) that is whichever hosted queue the device picks, so every
//   member answers ARP through the shared table and resolves through it.
// - Which secret? One, read once and given to every member, as Linux has
//   one ISN secret for all CPUs.
// - How large is an inbox? A member's inbox is a second RX ring, so it holds
//   as many packets as the socket's RX ring (`PortConfig::ring_size`): under
//   none the first member receives every frame and may hand a full ring's
//   worth to one member before that member drains. Its packets are the
//   port's largest IP packet, the MTU.
// - How does a member learn of handoffs? Each drive drains its inbox first;
//   busy-polling needs no wake descriptor.
//
// Lab preparation for `--shared` (an mlx5 VF, for example):
//
// - Rules: the example installs its own (`ethtool -N` is not needed) and
//   deletes them on exit; it prints each as `RULE ... location=L`. A killed
//   run leaves them behind, where they only steer between the device's
//   queues: `ethtool -N IF delete L` removes one. `ethtool -n IF` lists
//   them while the example runs. Under rules, member k's shows `TCP over
//   IPv4`, the address as `Dest IP`, `Dest port: 49152+k` with `mask:` the
//   bits ethtool ignores (it prints masks inverted: 0x3ffc for three or four
//   members), and `Action: Direct to queue Q`. With none for the rest, an
//   `IPv4 user` rule for the address and an `Ether` rule for type 0x0806
//   follow at the end of the table. mlx5 applies rules without `ethtool -K
//   IF ntuple on`; other drivers may need it.
// - Queues: `ethtool -l IF` shows the enabled channels. Give every enabled
//   RX queue a `--queue` (or `ethtool -L IF combined N` first), so that
//   RSS has only hosted queues to choose from.
// - RSS: `ethtool -x IF` shows the key, table, hash function and input
//   transform; `ethtool -n IF rx-flow-hash tcp4` must list IP SA, IP DA and
//   L4 bytes 0 & 1 and 2 & 3 for rss to be usable.

use ntcp_io_af_xdp::{
    HostedQueue, Port, PortConfig, QueueHandle, Rss, RssFields, RssFunction, Rule, XdpMode,
};
use ntcp_native::{
    CallerTimebase, ConnId, DEFAULT_FLOW_KEY, Error as NetError, EthernetNextHop, Event,
    FlowOwnership, Link, Network, NetworkConfig, ReadOutcome, SharedFlowLimits, SharedFlows,
    SharedNeighborLimits, SharedNeighbors, WorkBudget, WriteOptions,
};
use std::{
    collections::HashMap,
    io::{self, Read},
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
const REQUEST_LEN: usize = 16;
// ntcp's Toeplitz hashes the received packet's IPv4 addresses and TCP ports,
// 12 octets, and needs 4 key octets beyond them.
const MIN_FLOW_KEY: usize = 16;
// Entries of the round-robin flow table: members that are not a power of two
// still own nearly equal shares.
const ROUND_ROBIN_ENTRIES: usize = 128;

// The tag of `FlowOwnership::TaggedPorts` under rules: the IANA dynamic
// ports 49152-65535, NetworkConfig's default ephemeral range, so every
// member's range holds its tagged ports.
const PORT_TAG: u16 = 0xC000;

// `METRIC steering=`: 0 one Network per address, then the design's tiers.
const STEERING_PER_ADDRESS: u8 = 0;
const STEERING_RULES: u8 = 1;
const STEERING_RSS: u8 = 2;
const STEERING_NONE: u8 = 3;

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
    // Some: one shared address, one member per queue.
    shared: Option<Steering>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Steering {
    Auto,
    Rules,
    Rss,
    // `--steering none`: no NIC help, software hands frames on.
    Software,
}

const USAGE: &str = "usage: xdp_echo --dev IFNAME [--mode native|generic] --ip A.B.C.D \
[--ip ...] [--queue N]... --prefix LEN [--gateway A.B.C.D] [--neighbor A.B.C.D=MAC]... \
--server IP:PORT [--connections N] [--duration SECS] [--cpu N]... \
[--shared [--steering auto|rules|rss|none]]

Without --shared: one Network per --ip, --queue and --cpu given once per --ip, \
--connections per Network.
With --shared: one --ip shared by one member per --queue (--cpu once per --queue), \
--connections in total, at least one per member. --steering (default auto): rules tags \
each member's local ports (0xC000/0xC000 plus member bits) and installs one tcp4 \
destination-port rule per member, other flows going as rss or none would send them; \
rss mirrors the device's readable RSS with no rules; none steers the address and ARP to \
the first member's queue and hands flows on in software; auto takes rules if every \
member's rule installs, else rss if usable, else none.

METRIC steering: 0 one Network per address, 1 rules, 2 rss, 3 none.";

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
        shared: None,
    };
    let mut shared = false;
    let mut steering = None;
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
            "--shared" => shared = true,
            "--steering" => {
                steering = Some(match value()?.as_str() {
                    "auto" => Steering::Auto,
                    "rules" => Steering::Rules,
                    "rss" => Steering::Rss,
                    "none" => Steering::Software,
                    _ => return Err(bad("mode")),
                })
            }
            "-h" | "--help" => return Err(USAGE.into()),
            _ => return Err(format!("unknown argument {flag}\n{USAGE}")),
        }
    }
    if args.dev.is_empty() || args.ips.is_empty() || args.prefix == 0 || args.server.port() == 0 {
        return Err(USAGE.into());
    }
    if steering.is_some() && !shared {
        return Err("--steering needs --shared".into());
    }
    if shared {
        args.shared = Some(steering.unwrap_or(Steering::Auto));
        let members = args.queues.len();
        let queues = &args.queues;
        let distinct = (0..members).all(|i| !queues[..i].contains(&queues[i]));
        if args.ips.len() != 1 || members == 0 || !distinct {
            return Err(
                "--shared serves one --ip on --queue given once per member, each queue once".into(),
            );
        }
        if args.connections < members || !args.cpus.is_empty() && args.cpus.len() != members {
            return Err(
                "--connections at least one per member; --cpu given once per --queue".into(),
            );
        }
        return Ok(args);
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
    handed_off: u64,
    handoffs_received: u64,
    handoffs_dropped: u64,
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
    secret: [u8; 32],
    connections: usize,
    // Some under --shared: the worker's Network is member `index`.
    flows: Option<SharedFlows>,
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
            eprintln!("xdp_echo: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<bool, Box<dyn std::error::Error>> {
    let args = parse_args()?;
    let mut config = PortConfig::new(args.dev.clone());
    config.mode = args.mode;
    let (ring_size, max_ip_packet) = (config.ring_size as usize, config.mtu as usize);
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
    let threads = args.queues.len();
    // Under --shared the members split --connections, the first ones taking
    // the remainder.
    let shares: Vec<usize> = (0..threads)
        .map(|i| match args.shared {
            Some(_) => args.connections / threads + usize::from(i < args.connections % threads),
            None => args.connections,
        })
        .collect();
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
    let mut addresses = Vec::new();
    let mut rules = Vec::new();
    let single = enabled.as_ref().is_ok_and(|&n| n == 1);
    // Every enabled RX queue has a worker: frames for ntcp's addresses reach
    // a socket wherever the device puts them.
    let all_hosted = enabled
        .as_ref()
        .is_ok_and(|&n| (0..n).all(|q| args.queues.contains(&q)));
    let mut steering = STEERING_PER_ADDRESS;
    let mut flows = None;
    match args.shared {
        None => {
            let rule_free = single.then_some("the only RX queue receives all");
            for (&ip, &queue) in args.ips.iter().zip(&args.queues) {
                addresses.push(port.add_ipv4(ip)?);
                let what = format!("{ip} -> queue {queue}");
                steer(&mut rules, &what, port.steer_ipv4(ip, queue), rule_free)?;
            }
            let what = format!("ARP -> queue {}", args.queues[0]);
            steer(&mut rules, &what, port.steer_arp(args.queues[0]), rule_free)?;
        }
        Some(choice) => {
            let ip = args.ips[0];
            addresses.push(port.add_ipv4(ip)?);
            let limits = SharedFlowLimits {
                members: threads,
                inbox_packets: ring_size,
                packet_bytes: max_ip_packet,
            };
            // Flows no port rule steers are hashed: with the device's RSS
            // when it places them at their owners, else with ntcp's own key.
            let rss = match choice {
                Steering::Software => None,
                _ => Some(mirror_rss(port.rss(), port.rss_tcp4_fields(), &args.queues)),
            };
            let (mirrored, unmirrored) = match rss {
                Some(Ok(mirrored)) => (Some(mirrored), None),
                Some(Err(why)) if choice == Steering::Rss => {
                    return Err(format!("--steering rss: {why}").into());
                }
                Some(Err(why)) => (None, Some(why)),
                None => (None, None),
            };
            let by_rss = mirrored.is_some();
            let rest = if by_rss { "rss" } else { "none" };
            let (key, table) = mirrored.unwrap_or_else(|| {
                let entries = ROUND_ROBIN_ENTRIES.max(threads.next_power_of_two());
                let table = (0..entries).map(|i| i % threads).collect();
                (DEFAULT_FLOW_KEY.to_vec(), table)
            });
            // Tier 1: each member's active opens take local ports tagged
            // with it, and one masked TCP destination-port rule per member
            // delivers their replies on its queue.
            let mut tagged = None;
            if matches!(choice, Steering::Auto | Steering::Rules) {
                let ownership = FlowOwnership::TaggedPorts {
                    key: key.clone(),
                    table: table.clone(),
                    prefix: PORT_TAG,
                    prefix_mask: PORT_TAG,
                };
                let group = SharedFlows::new(ownership, limits)?;
                match steer_ports(&port, ip, &group, &args.queues) {
                    Ok(installed) => {
                        rules.extend(installed);
                        tagged = Some(group);
                    }
                    Err(why) if choice == Steering::Rules => {
                        return Err(format!("--steering rules: {why}").into());
                    }
                    Err(why) => eprintln!("STEERING auto: no port rules, as {why}"),
                }
            }
            let label = match (&tagged, choice) {
                (Some(_), _) => {
                    let auto = if choice == Steering::Auto {
                        "auto: "
                    } else {
                        ""
                    };
                    eprintln!(
                        "STEERING {auto}rules: a tcp4 destination-port rule per member, \
                         local ports tagged {PORT_TAG:#06x}/{PORT_TAG:#06x}"
                    );
                    format!("other flows: {rest}")
                }
                (None, Steering::Auto) => format!("auto: {rest}"),
                (None, _) => rest.to_string(),
            };
            if by_rss {
                eprintln!(
                    "STEERING {label}: Toeplitz, {}-octet key, {}-entry table over hosted \
                     queues, no rules",
                    key.len(),
                    table.len()
                );
                if !all_hosted {
                    eprintln!(
                        "STEERING warning: an enabled RX queue has no member; frames \
                         the device puts there outside RSS are dropped (METRIC unsteered)"
                    );
                }
            } else {
                match &unmirrored {
                    Some(why) => eprintln!("STEERING {label}, as {why}"),
                    None => eprintln!("STEERING {label}"),
                }
                let rule_free = all_hosted
                    .then_some("every enabled RX queue has a member, which hands frames on");
                let refused = |error: String| {
                    format!(
                        "{error}; without the rule frames would arrive on enabled RX queues \
                         with no member: give every enabled queue a --queue, or use --steering rss"
                    )
                };
                let first = args.queues[0];
                let what = format!("{ip} -> queue {first}");
                steer(&mut rules, &what, port.steer_ipv4(ip, first), rule_free).map_err(refused)?;
                let what = format!("ARP -> queue {first}");
                steer(&mut rules, &what, port.steer_arp(first), rule_free).map_err(refused)?;
            }
            steering = match (&tagged, by_rss) {
                (Some(_), _) => STEERING_RULES,
                (None, true) => STEERING_RSS,
                (None, false) => STEERING_NONE,
            };
            flows = Some(match tagged {
                Some(group) => group,
                None => SharedFlows::new(FlowOwnership::Hash { key, table }, limits)?,
            });
        }
    }

    let mut secret = [0; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut secret))
        .map_err(|e| format!("/dev/urandom: {e}"))?;
    let args = Arc::new(args);
    let finished = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();
    for (index, &queue) in args.queues.iter().enumerate() {
        let worker = Worker {
            index,
            ip: args.ips[if flows.is_some() { 0 } else { index }],
            handle: port.take_queue(queue)?,
            cpu: args.cpus.get(index).map(|&c| single_cpu(c)).transpose()?,
            neighbors: neighbors.clone(),
            secret,
            connections: shares[index],
            flows: flows.clone(),
            finished: Finished {
                count: finished.clone(),
                workers: args.queues.len(),
                counted: false,
            },
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
    Ok(summarize(&reports, &neighbors, unsteered, steering, &args))
}

// Install a rule, or skip one the device does not support when `rule_free`
// says why frames reach a hosted queue without it.
fn steer(
    rules: &mut Vec<Rule>,
    what: &str,
    rule: io::Result<Rule>,
    rule_free: Option<&str>,
) -> Result<(), String> {
    match (rule, rule_free) {
        (Ok(rule), _) => {
            eprintln!("RULE {what} location={}", rule.location());
            rules.push(rule);
            Ok(())
        }
        (Err(error), Some(why)) if error.kind() == io::ErrorKind::Unsupported => {
            eprintln!("RULE {what} not installed ({error}); {why}");
            Ok(())
        }
        (Err(error), _) => Err(format!("steer {what}: {error}")),
    }
}

// One rule per member on the TCP destination ports tagged with it, to its
// queue: all of them, or why one was refused (and none is kept).
fn steer_ports(
    port: &Port,
    ip: Ipv4Addr,
    flows: &SharedFlows,
    queues: &[u32],
) -> Result<Vec<Rule>, String> {
    let mut rules = Vec::new();
    for (member, &queue) in queues.iter().enumerate() {
        let (value, mask) = flows
            .port_rule(member)
            .ok_or("tagged ports without a port rule")?;
        let what = format!("tcp4 {ip} dst-port {value:#06x}/{mask:#06x} -> queue {queue}");
        let rule = port.steer_tcp_port(ip, value, mask, queue);
        steer(&mut rules, &what, rule, None)?;
    }
    Ok(rules)
}

// The device's RSS as a flow key and a table of members (member i hosts
// `queues[i]`), or why it cannot place every flow's frames at its owner.
fn mirror_rss(
    rss: io::Result<Option<Rss>>,
    fields: io::Result<Option<RssFields>>,
    queues: &[u32],
) -> Result<(Vec<u8>, Vec<usize>), String> {
    let rss = match rss {
        Ok(Some(rss)) => rss,
        Ok(None) => return Err("the device reports no RSS".into()),
        Err(error) => return Err(format!("RSS is unreadable ({error})")),
    };
    if rss.function != RssFunction::Toeplitz {
        return Err(format!("the RSS hash is {:?}, not Toeplitz", rss.function));
    }
    if rss.input_transform != 0 {
        return Err(format!(
            "RSS transforms its input (RXH_XFRM bits {:#04x}; `ethtool -x` names them)",
            rss.input_transform
        ));
    }
    // ntcp's flow hash takes addresses and ports; with another input the
    // device puts flows on queues whose members do not own them.
    match fields {
        Ok(Some(fields)) if fields.addresses_and_ports() => {}
        Ok(Some(fields)) => {
            return Err(format!(
                "the tcp4 RSS hash takes fields {:#x}, not exactly both addresses and ports \
                 ({:#x}, `ethtool -N IF rx-flow-hash tcp4 sdfn`)",
                fields.0,
                RssFields::SOURCE_ADDRESS
                    | RssFields::DESTINATION_ADDRESS
                    | RssFields::SOURCE_PORT
                    | RssFields::DESTINATION_PORT
            ));
        }
        Ok(None) => return Err("the device reports no tcp4 RSS hash fields".into()),
        Err(error) => return Err(format!("the tcp4 RSS hash fields are unreadable ({error})")),
    }
    if rss.key.len() < MIN_FLOW_KEY {
        return Err(format!(
            "the RSS key has {} octets, fewer than {MIN_FLOW_KEY}",
            rss.key.len()
        ));
    }
    if !rss.table.len().is_power_of_two() {
        return Err(format!(
            "the RSS table has {} entries, not a power of two",
            rss.table.len()
        ));
    }
    let mut table = Vec::with_capacity(rss.table.len());
    for queue in &rss.table {
        let Some(member) = queues.iter().position(|q| q == queue) else {
            return Err(format!(
                "the RSS table names queue {queue}, which has no member"
            ));
        };
        table.push(member);
    }
    if let Some(queue) = queues.iter().find(|q| !rss.table.contains(q)) {
        return Err(format!(
            "the RSS table never names queue {queue}, whose member would own no flows"
        ));
    }
    Ok((rss.key, table))
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    // Nearest rank.
    let rank = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

fn summarize(
    reports: &[Report],
    neighbors: &SharedNeighbors,
    unsteered: u64,
    steering: u8,
    args: &Args,
) -> bool {
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
    if args.shared.is_some() {
        for (index, report) in reports.iter().enumerate() {
            eprintln!(
                "MEMBER {index} queue={} requests={} handed_off={} handoffs_received={} \
                 handoffs_dropped={}",
                args.queues[index],
                report.requests,
                report.handed_off,
                report.handoffs_received,
                report.handoffs_dropped
            );
        }
    }
    println!("METRIC handed_off={}", sum(|r| r.handed_off));
    println!("METRIC handoffs_received={}", sum(|r| r.handoffs_received));
    println!("METRIC handoffs_dropped={}", sum(|r| r.handoffs_dropped));
    println!("METRIC steering={steering}");
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

fn serve_into(mut worker: Worker, args: &Args, report: &mut Report) -> Result<(), String> {
    if let Some(cpu) = &worker.cpu {
        set_affinity(cpu).map_err(|e| format!("sched_setaffinity: {e}"))?;
    }
    let queue = worker.handle.attach().map_err(|e| format!("attach: {e}"))?;
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
    let (secret, neighbors) = (worker.secret, &worker.neighbors);
    let network = match &worker.flows {
        Some(flows) => Network::with_shared_flows(
            config,
            queue,
            secret,
            now_ns(),
            Some(neighbors),
            flows,
            worker.index,
        ),
        None => Network::with_shared_neighbors(config, queue, secret, now_ns(), neighbors),
    };
    let mut network = network.map_err(|e| format!("network: {e}"))?;
    let outcome = exchange(&mut network, args, worker.connections, worker.index, report);
    worker.finished.mark();
    serve_others(&mut network, &worker.finished);
    // Counters also describe a failed run.
    let counters = network.counters();
    report.arp_sent = counters.arp_sent;
    report.arp_received = counters.arp_received;
    report.handed_off = counters.handed_off;
    report.handoffs_received = counters.handoffs_received;
    report.handoffs_dropped = counters.handoffs_dropped;
    outcome
}

// Connect, run the closed loop for the window, drain, close and linger.
fn exchange(
    network: &mut Network<HostedQueue>,
    args: &Args,
    count: usize,
    index: usize,
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
