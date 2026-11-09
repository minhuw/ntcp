// Networks on the queues of one Ethernet port that divide the TCP flows of
// their IPv4 addresses (`SharedFlows`), driven with a peer host over an
// in-memory LAN. Every member has the port's MAC and its own transmit queue;
// a dispatcher that stands for the NIC places each frame for the port on a
// receive queue: all on one queue, RSS with the members' own key and table,
// RSS that disagrees with them, or a scatter of every frame. A router on the
// wire can fragment the peer's datagrams and answer packets too long for
// its next hop with ICMP. Whatever the steering, every connection must
// complete: steering only spares handoffs.
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::*;
use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

const SECOND: u64 = 1_000_000;
// The clock advances by TICK in a round that moves frames, and toward the
// next deadline, by at most IDLE, in one that does not.
const TICK: u64 = 100;
const IDLE: u64 = 10_000;
const BUDGET: WorkBudget = WorkBudget::new(32, 32, 32, 32);
const PORT_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const PEER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const ROUTER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xfe];
// The members' shared address under `FlowOwnership::Hash`.
const ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const PEER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 100);
const ROUTER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 254);
const LISTEN: u16 = 80;
const MSS: usize = 1460;
const MEMBER_CONNECTIONS: usize = 64;
const PEER_CONNECTIONS: usize = 80;
const TABLE: usize = 128;
const INBOX: usize = 256;
const SECRET: [u8; 32] = [7; 32];

fn member_ip(k: usize) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, 1 + k as u8)
}

type Frames = Arc<Mutex<VecDeque<Vec<u8>>>>;

// One queue of the port, or the peer's interface.
struct Port {
    incoming: Frames,
    outgoing: Frames,
}
impl PacketIo for Port {
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ethernet
    }
    fn max_packet_len(&self) -> Option<usize> {
        Some(1514)
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        let Some(frame) = self.incoming.lock().unwrap().pop_front() else {
            return Ok(None);
        };
        out[..frame.len()].copy_from_slice(&frame);
        Ok(Some(frame.len()))
    }
    fn transmit(&mut self, frame: &[u8]) -> io::Result<TxOutcome> {
        self.outgoing.lock().unwrap().push_back(frame.to_vec());
        Ok(TxOutcome::Submitted)
    }
}

struct Station {
    network: Network<Port>,
    incoming: Frames,
    outgoing: Frames,
}
impl Station {
    fn port(incoming: &Frames, outgoing: &Frames) -> Port {
        Port {
            incoming: incoming.clone(),
            outgoing: outgoing.clone(),
        }
    }
    fn build(make: impl FnOnce(Port) -> Result<Network<Port>>) -> Result<Self> {
        let (incoming, outgoing) = (Frames::default(), Frames::default());
        let network = make(Self::port(&incoming, &outgoing))?;
        Ok(Self {
            network,
            incoming,
            outgoing,
        })
    }
    fn peer() -> Self {
        let config = config(PEER, PEER_MAC, PEER_CONNECTIONS);
        Self::build(|port| Network::new(config, port, [9; 32], 0)).unwrap()
    }
    fn sent(&self) -> Vec<Vec<u8>> {
        self.outgoing.lock().unwrap().drain(..).collect()
    }
}

fn config(local: Ipv4Addr, mac: [u8; 6], connections: usize) -> NetworkConfig {
    let mut config = NetworkConfig::new(IpAddr::V4(local), 1500);
    config.tcp.max_connections = connections;
    config.tcp.max_listeners = 1;
    config.tcp.connection.send_capacity = 16384;
    config.tcp.connection.receive_capacity = 16384;
    config.link = Link::Ethernet {
        local_mac: mac,
        next_hop: EthernetNextHop::Arp {
            prefix_len: 24,
            gateway: None,
        },
    };
    config
}
fn neighbors(members: usize) -> SharedNeighbors {
    let limits = SharedNeighborLimits {
        members,
        entries: 8,
        held: members * (MEMBER_CONNECTIONS + 1),
        replies: 4,
    };
    SharedNeighbors::new(PORT_MAC, SECOND, limits).unwrap()
}
fn round_robin(members: usize, len: usize) -> Vec<usize> {
    (0..len).map(|i| i % members).collect()
}
fn limits(members: usize, inbox_packets: usize) -> SharedFlowLimits {
    SharedFlowLimits {
        members,
        inbox_packets,
        packet_bytes: 1500,
    }
}
fn hash_flows(members: usize, inbox_packets: usize) -> SharedFlows {
    let ownership = FlowOwnership::Hash {
        key: DEFAULT_FLOW_KEY.to_vec(),
        table: round_robin(members, TABLE),
    };
    SharedFlows::new(ownership, limits(members, inbox_packets)).unwrap()
}
// Member `k` of `flows`, on the port's shared neighbor table.
fn join(
    flows: &SharedFlows,
    neighbors: &SharedNeighbors,
    k: usize,
    config: NetworkConfig,
) -> Station {
    Station::build(|port| {
        Network::with_shared_flows(config, port, SECRET, 0, Some(neighbors), flows, k)
    })
    .unwrap_or_else(|e| panic!("member {k} joins the shared flows: {e:?}"))
}
// `members` members of new Hash flows on ADDRESS.
fn hash_members(
    members: usize,
    inbox_packets: usize,
    adjust: impl Fn(&mut NetworkConfig),
) -> (SharedFlows, Vec<Station>) {
    let flows = hash_flows(members, inbox_packets);
    let table = neighbors(members);
    let stations = (0..members)
        .map(|k| {
            let mut config = config(ADDRESS, PORT_MAC, MEMBER_CONNECTIONS);
            adjust(&mut config);
            join(&flows, &table, k, config)
        })
        .collect();
    (flows, stations)
}
fn v4(address: SocketAddr) -> SocketAddrV4 {
    match address {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => panic!("{address} is not IPv4"),
    }
}

// RSS's Toeplitz hash, written out here so that the dispatcher models the
// NIC independently of the crate: every set bit i of the input, counted
// from the most significant bit of its first octet, contributes the 32 key
// bits that start at bit i.
fn toeplitz(key: &[u8], input: &[u8]) -> u32 {
    let bit = |bytes: &[u8], i: usize| bytes[i / 8] >> (7 - i % 8) & 1;
    (0..input.len() * 8)
        .filter(|&i| bit(input, i) == 1)
        .map(|i| (0..32).fold(0u32, |w, j| w << 1 | u32::from(bit(key, i + j))))
        .fold(0, |hash, window| hash ^ window)
}

// Where the port puts a frame it receives.
#[derive(Clone, Debug)]
enum Dispatch {
    // A NIC with one receive queue.
    Queue0,
    // Receive-side scaling: the Toeplitz hash under `key` of source and
    // destination address and port of an unfragmented IPv4 TCP packet, or
    // of the addresses alone of any other IPv4 packet, selects a queue in
    // `reta` by its low bits. ARP and anything else go to queue 0.
    Rss { key: Vec<u8>, reta: Vec<usize> },
    // Every frame to a pseudo-random queue (xorshift), fragments of one
    // datagram included: the worst steering there is.
    Scatter(u64),
    // Every IPv4 frame to the queue of the member that serves its
    // destination (`addresses[k]` on queue k), as per-address flow rules
    // steer; ARP to queue 0.
    ByDestination(Vec<Ipv4Addr>),
    // Masked rules on the TCP destination port, (value, mask), ahead of
    // other steering, as a NIC matches its flow rules before RSS: an
    // unfragmented TCP packet whose destination port has the value of rule
    // k under its mask to queue k, any other frame where the second
    // steering puts it.
    Rules(Vec<(u16, u16)>, Box<Dispatch>),
}
impl Dispatch {
    // RSS as the members' flows hash.
    fn rss(members: usize) -> Self {
        Self::Rss {
            key: DEFAULT_FLOW_KEY.to_vec(),
            reta: round_robin(members, TABLE),
        }
    }
    fn queue(&mut self, frame: &[u8], queues: usize) -> usize {
        match self {
            Self::Queue0 => 0,
            Self::Rss { key, reta } => l3(frame).map_or(0, |ip| {
                let mut input = ip[12..20].to_vec();
                if let Some(ports) = ports(ip) {
                    input.extend(ports);
                }
                reta[toeplitz(key, &input) as usize & (reta.len() - 1)]
            }),
            Self::Scatter(state) => {
                *state ^= *state << 13;
                *state ^= *state >> 7;
                *state ^= *state << 17;
                (*state % queues as u64) as usize
            }
            Self::ByDestination(addresses) => l3(frame)
                .and_then(|ip| addresses.iter().position(|&a| a == destination(ip)))
                .unwrap_or(0),
            Self::Rules(rules, rss) => l3(frame)
                .and_then(port_pair)
                .and_then(|(_, port)| rules.iter().position(|&(v, mask)| port & mask == v))
                .unwrap_or_else(|| rss.queue(frame, queues)),
        }
    }
}

// The IPv4 packet of an Ethernet frame, without padding.
fn l3(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 34 || frame[12..14] != [0x08, 0x00] {
        return None;
    }
    let ip = &frame[14..];
    let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    ip.get(..total)
}
fn header_len(ip: &[u8]) -> usize {
    usize::from(ip[0] & 15) * 4
}
fn source(ip: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15])
}
fn destination(ip: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19])
}
fn is_fragment(ip: &[u8]) -> bool {
    u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0
}
// The source and destination port octets of an unfragmented TCP packet.
fn ports(ip: &[u8]) -> Option<&[u8]> {
    if ip[9] != 6 || is_fragment(ip) {
        return None;
    }
    ip.get(header_len(ip)..header_len(ip) + 4)
}
fn port_pair(ip: &[u8]) -> Option<(u16, u16)> {
    ports(ip).map(|p| {
        (
            u16::from_be_bytes([p[0], p[1]]),
            u16::from_be_bytes([p[2], p[3]]),
        )
    })
}
fn is_reset(ip: &[u8]) -> bool {
    ports(ip).is_some()
        && ip
            .get(header_len(ip) + 13)
            .is_some_and(|flags| flags & 4 != 0)
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], c.get(1).copied().unwrap_or(0)])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
fn ipv4_frame(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, data: &[u8]) -> Vec<u8> {
    let mut frame = PORT_MAC.to_vec();
    frame.extend(ROUTER_MAC);
    frame.extend([0x08, 0x00]);
    let mut header = [0; 20];
    header[0] = 0x45;
    header[2..4].copy_from_slice(&((20 + data.len()) as u16).to_be_bytes());
    header[8] = 64;
    header[9] = protocol;
    header[12..16].copy_from_slice(&source.octets());
    header[16..20].copy_from_slice(&destination.octets());
    let sum = checksum(&header);
    header[10..12].copy_from_slice(&sum.to_be_bytes());
    frame.extend(header);
    frame.extend(data);
    frame
}
// The router's ICMP destination unreachable, fragmentation needed and DF
// set (RFC 1191 section 4), about `invoking`: its header and first 8 data
// octets (RFC 792), the least a router quotes.
fn fragmentation_needed(invoking: &[u8], mtu: usize) -> Vec<u8> {
    let quote = &invoking[..(header_len(invoking) + 8).min(invoking.len())];
    let mut icmp = vec![3, 4, 0, 0, 0, 0];
    icmp.extend((mtu as u16).to_be_bytes());
    icmp.extend(quote);
    let sum = checksum(&icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    ipv4_frame(ROUTER, source(invoking), 1, &icmp)
}
// `frame`'s IPv4 datagram in fragments of at most `limit` octets, with
// Identification `id`; a datagram that fits, or a fragment, as it is.
fn fragment(frame: &[u8], limit: usize, id: u16) -> Vec<Vec<u8>> {
    let Some(ip) = l3(frame).filter(|ip| ip.len() > limit && !is_fragment(ip)) else {
        return vec![frame.to_vec()];
    };
    let header = header_len(ip);
    let data = &ip[header..];
    let room = (limit - header) & !7;
    data.chunks(room)
        .enumerate()
        .map(|(i, chunk)| {
            let offset = i * room;
            let more = offset + chunk.len() < data.len();
            let mut packet = ip[..header].to_vec();
            packet[2..4].copy_from_slice(&((header + chunk.len()) as u16).to_be_bytes());
            packet[4..6].copy_from_slice(&id.to_be_bytes());
            let flags = u16::from(more) << 13 | (offset / 8) as u16;
            packet[6..8].copy_from_slice(&flags.to_be_bytes());
            packet[10..12].fill(0);
            let sum = checksum(&packet);
            packet[10..12].copy_from_slice(&sum.to_be_bytes());
            let mut out = frame[..14].to_vec();
            out.extend(packet);
            out.extend(chunk);
            out
        })
        .collect()
}

// A router on the wire between the port and the peer.
#[derive(Default)]
struct Router {
    // Fragments the peer's IPv4 datagrams longer than this.
    fragment: Option<usize>,
    next_id: u16,
    // The MTU toward the peer: a longer packet from the port is dropped
    // and answered with fragmentation needed.
    mtu: Option<usize>,
    // Delivers that ICMP error to a queue of a member that does not own the
    // quoted flow, rather than where the dispatcher puts it.
    misdeliver_icmp: bool,
    // The drops: the time and the dropping packet's source port.
    drops: Vec<(u64, u16)>,
}

// The port's members, the peer and the wire between them, on one clock.
struct Lan {
    members: Vec<Option<Station>>,
    queues: Vec<Frames>,
    peer: Station,
    dispatch: Dispatch,
    router: Router,
    flows: Option<SharedFlows>,
    now: u64,
    // TCP resets each member sent to the peer, and the peer to the port.
    resets: Vec<usize>,
    peer_resets: usize,
}
impl Lan {
    fn new(members: Vec<Station>, dispatch: Dispatch, flows: Option<SharedFlows>) -> Self {
        Self {
            queues: members.iter().map(|m| m.incoming.clone()).collect(),
            resets: vec![0; members.len()],
            members: members.into_iter().map(Some).collect(),
            peer: Station::peer(),
            dispatch,
            router: Router::default(),
            flows,
            now: 0,
            peer_resets: 0,
        }
    }
    fn network(&mut self, k: usize) -> &mut Network<Port> {
        &mut self.members[k].as_mut().expect("a present member").network
    }
    // Each member drives and its frames cross to the peer, then the peer
    // drives and its frames reach the port's queues.
    fn step(&mut self) {
        let mut busy = false;
        let mut next = u64::MAX;
        for k in 0..self.members.len() {
            let Some(member) = &mut self.members[k] else {
                continue;
            };
            let report = member.network.drive(self.now, BUDGET).unwrap();
            busy |= report.more_work;
            next = next.min(report.next_deadline.unwrap_or(u64::MAX));
            let sent = member.sent();
            busy |= !sent.is_empty();
            for frame in sent {
                self.toward_peer(k, frame);
            }
        }
        let report = self.peer.network.drive(self.now, BUDGET).unwrap();
        busy |= report.more_work;
        next = next.min(report.next_deadline.unwrap_or(u64::MAX));
        let sent = self.peer.sent();
        busy |= !sent.is_empty();
        for frame in sent {
            self.toward_port(frame);
        }
        self.now = if busy {
            self.now + TICK
        } else {
            next.clamp(self.now + TICK, self.now + IDLE)
        };
    }
    fn toward_peer(&mut self, k: usize, frame: Vec<u8>) {
        if let Some(ip) = l3(&frame) {
            if is_reset(ip) {
                self.resets[k] += 1;
            }
            if let Some(mtu) = self.router.mtu
                && ip.len() > mtu
            {
                let (local, remote) = port_pair(ip).unwrap();
                self.router.drops.push((self.now, local));
                let error = fragmentation_needed(ip, mtu);
                let queue = match &self.flows {
                    Some(flows) if self.router.misdeliver_icmp => {
                        let owner = flows
                            .owner(
                                SocketAddrV4::new(source(ip), local),
                                SocketAddrV4::new(destination(ip), remote),
                            )
                            .unwrap();
                        (owner + 1) % self.queues.len()
                    }
                    _ => self.dispatch.queue(&error, self.queues.len()),
                };
                self.queues[queue].lock().unwrap().push_back(error);
                return;
            }
        }
        self.peer.incoming.lock().unwrap().push_back(frame);
    }
    fn toward_port(&mut self, frame: Vec<u8>) {
        if l3(&frame).is_some_and(is_reset) {
            self.peer_resets += 1;
        }
        let pieces = match self.router.fragment {
            Some(limit) => {
                self.router.next_id = self.router.next_id.wrapping_add(1);
                fragment(&frame, limit, self.router.next_id)
            }
            None => vec![frame],
        };
        for piece in pieces {
            let queue = self.dispatch.queue(&piece, self.queues.len());
            self.queues[queue].lock().unwrap().push_back(piece);
        }
    }
    // Steps until `apps`, run after every step, reports done, or until
    // `limit`; whether it finished.
    fn run(&mut self, limit: u64, mut apps: impl FnMut(&mut Self) -> bool) -> bool {
        while self.now < limit {
            self.step();
            if apps(self) {
                return true;
            }
        }
        false
    }
    // The handoff counters summed over the present members.
    fn handoffs(&self) -> (u64, u64, u64) {
        self.members
            .iter()
            .flatten()
            .fold((0, 0, 0), |(a, b, c), m| {
                let counters = m.network.counters();
                (
                    a + counters.handed_off,
                    b + counters.handoffs_received,
                    c + counters.handoffs_dropped,
                )
            })
    }
    fn assert_no_resets(&self) {
        assert_eq!(self.resets, vec![0; self.resets.len()], "members' resets");
        assert_eq!(self.peer_resets, 0, "the peer's resets");
    }
}

fn payload(id: usize, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(31) ^ id.wrapping_mul(131) ^ (i >> 8)) as u8)
        .collect()
}

// A listener that returns every octet each accepted connection sends.
struct Echo {
    listener: ListenerId,
    connections: Vec<(ConnId, VecDeque<u8>)>,
}
impl Echo {
    fn new(network: &mut Network<Port>) -> Self {
        Self {
            listener: network.listen(LISTEN, 64).unwrap(),
            connections: Vec::new(),
        }
    }
    fn serve(&mut self, network: &mut Network<Port>) {
        while let Ok(connection) = network.accept(self.listener) {
            self.connections.push((connection, VecDeque::new()));
        }
        let mut out = [0; 16384];
        for (connection, queued) in &mut self.connections {
            while let Ok(ReadOutcome::Data { len, .. }) = network.try_read(*connection, &mut out) {
                queued.extend(&out[..len]);
            }
            if !queued.is_empty()
                && let Ok(receipt) = network.try_write(
                    *connection,
                    queued.make_contiguous(),
                    WriteOptions::default(),
                )
            {
                queued.drain(..receipt.accepted);
            }
        }
    }
}

// A connection that writes `payload` and keeps what comes back.
struct Client {
    connection: ConnId,
    payload: Vec<u8>,
    sent: usize,
    received: Vec<u8>,
}
impl Client {
    fn new(connection: ConnId, payload: Vec<u8>) -> Self {
        Self {
            connection,
            payload,
            sent: 0,
            received: Vec::new(),
        }
    }
    fn pump(&mut self, network: &mut Network<Port>) {
        if self.sent < self.payload.len()
            && let Ok(receipt) = network.try_write(
                self.connection,
                &self.payload[self.sent..],
                WriteOptions::default(),
            )
        {
            self.sent += receipt.accepted;
        }
        let mut out = [0; 16384];
        while let Ok(ReadOutcome::Data { len, .. }) = network.try_read(self.connection, &mut out) {
            self.received.extend_from_slice(&out[..len]);
        }
    }
    fn done(&self) -> bool {
        self.received.len() >= self.payload.len()
    }
}
fn assert_echoed(clients: &[Client]) {
    for (i, client) in clients.iter().enumerate() {
        assert!(client.received == client.payload, "connection {i}");
    }
}

// The peer opens `connections` connections, from varied ports, to ADDRESS,
// where every member listens and echoes. Each completes intact, without a
// reset, on the member that owns its flow.
struct Passive {
    lan: Lan,
    servers: Vec<Echo>,
}
fn passive(lan: Lan, connections: usize, len: usize, limit: u64) -> Passive {
    let mut lan = lan;
    let members = lan.members.len();
    let mut servers: Vec<_> = (0..members).map(|k| Echo::new(lan.network(k))).collect();
    let mut clients: Vec<_> = (0..connections)
        .map(|i| {
            let to = SocketAddr::new(ADDRESS.into(), LISTEN);
            let connection = lan
                .peer
                .network
                .connect_from(to, Some(20_000 + 97 * i as u16))
                .unwrap();
            Client::new(connection, payload(i, len))
        })
        .collect();
    let done = lan.run(limit, |lan| {
        for (k, server) in servers.iter_mut().enumerate() {
            if let Some(member) = &mut lan.members[k] {
                server.serve(&mut member.network);
            }
        }
        for client in &mut clients {
            client.pump(&mut lan.peer.network);
        }
        clients.iter().all(Client::done)
    });
    let finished = clients.iter().filter(|c| c.done()).count();
    assert!(done, "{finished} of {connections} finished");
    assert_echoed(&clients);
    lan.assert_no_resets();
    let flows = lan.flows.clone().unwrap();
    let mut accepted = 0;
    for (k, server) in servers.iter().enumerate() {
        for &(connection, _) in &server.connections {
            let info = lan.network(k).connection_info(connection).unwrap();
            assert_eq!(info.state, State::Established);
            assert_eq!(
                flows.owner(v4(info.local), v4(info.peer)),
                Some(k),
                "{info:?}"
            );
            accepted += 1;
        }
    }
    assert_eq!(accepted, connections);
    Passive { lan, servers }
}
fn hash_lan(members: usize, dispatch: Dispatch, inbox_packets: usize) -> Lan {
    let (flows, stations) = hash_members(members, inbox_packets, |_| {});
    Lan::new(stations, dispatch, Some(flows))
}

// 1. Passive opens.

#[test]
fn passive_opens_on_a_single_queue_are_handed_to_their_owners() {
    for n in [2, 4] {
        let lan = hash_lan(n, Dispatch::Queue0, INBOX);
        let Passive { lan, servers } = passive(lan, 64, 4 * MSS, 5 * SECOND);
        for (k, server) in servers.iter().enumerate() {
            assert!(!server.connections.is_empty(), "member {k} of {n}");
        }
        let (handed_off, received, dropped) = lan.handoffs();
        assert!(handed_off > 0 && received > 0, "{n} members");
        assert!(received <= handed_off);
        assert_eq!(dropped, 0);
        // Only queue 0 receives from the wire, and a handed-off packet is
        // never handed on.
        for k in 1..n {
            assert_eq!(
                lan.members[k]
                    .as_ref()
                    .unwrap()
                    .network
                    .counters()
                    .handed_off,
                0
            );
        }
    }
}

#[test]
fn passive_opens_under_rss_with_the_flows_key_and_table_need_no_handoff() {
    for n in [2, 4] {
        let lan = hash_lan(n, Dispatch::rss(n), INBOX);
        // The NIC model and the members agree on every flow.
        let flows = lan.flows.clone().unwrap();
        let mut dispatch = Dispatch::rss(n);
        for i in 0..512u16 {
            let remote = SocketAddrV4::new(PEER, 1024 + i * 61);
            let local = SocketAddrV4::new(ADDRESS, if i % 2 == 0 { LISTEN } else { 49152 + i });
            let mut tcp = [0; 20];
            tcp[..2].copy_from_slice(&remote.port().to_be_bytes());
            tcp[2..4].copy_from_slice(&local.port().to_be_bytes());
            let frame = ipv4_frame(PEER, ADDRESS, 6, &tcp);
            assert_eq!(flows.owner(local, remote), Some(dispatch.queue(&frame, n)));
        }
        let Passive { lan, servers } = passive(lan, 64, 4 * MSS, 5 * SECOND);
        assert!(servers.iter().all(|s| !s.connections.is_empty()));
        assert_eq!(lan.handoffs(), (0, 0, 0), "{n} members");
    }
}

#[test]
fn passive_opens_survive_rss_that_disagrees_with_the_flows() {
    for n in [2, 4] {
        // Another key (the RSS verification suite's), then the right key
        // with a rotated table.
        let drifted = [
            Dispatch::Rss {
                key: MICROSOFT_KEY.to_vec(),
                reta: round_robin(n, TABLE),
            },
            Dispatch::Rss {
                key: DEFAULT_FLOW_KEY.to_vec(),
                reta: (0..TABLE).map(|i| (i + 1) % n).collect(),
            },
        ];
        for dispatch in drifted {
            let lan = hash_lan(n, dispatch.clone(), INBOX);
            let Passive { lan, .. } = passive(lan, 64, 4 * MSS, 5 * SECOND);
            let (handed_off, received, dropped) = lan.handoffs();
            assert!(handed_off > 0 && received > 0, "{n} members, {dispatch:?}");
            assert_eq!(dropped, 0);
        }
    }
}

#[test]
fn passive_opens_survive_every_frame_scattered_over_the_queues() {
    for n in [2, 4] {
        let lan = hash_lan(n, Dispatch::Scatter(0x9e37_79b9_7f4a_7c15), INBOX);
        let Passive { lan, servers } = passive(lan, 64, 4 * MSS, 5 * SECOND);
        assert!(servers.iter().all(|s| !s.connections.is_empty()));
        let (handed_off, _, dropped) = lan.handoffs();
        assert!(handed_off > 0, "{n} members");
        assert_eq!(dropped, 0);
    }
}

// 2. Active opens: every member connects to the peer's listener; the ports
// it chooses are of flows it owns.

fn active(lan: &mut Lan, per_member: usize, len: usize, limit: u64) {
    let members = lan.members.len();
    let mut server = Echo::new(&mut lan.peer.network);
    let to = SocketAddr::new(PEER.into(), LISTEN);
    let mut clients: Vec<Vec<Client>> = (0..members)
        .map(|k| {
            (0..per_member)
                .map(|i| {
                    let connection = lan.network(k).connect(to).unwrap();
                    Client::new(connection, payload(k * per_member + i, len))
                })
                .collect()
        })
        .collect();
    let done = lan.run(limit, |lan| {
        server.serve(&mut lan.peer.network);
        for (k, clients) in clients.iter_mut().enumerate() {
            for client in clients {
                client.pump(lan.network(k));
            }
        }
        clients.iter().flatten().all(Client::done)
    });
    assert!(done);
    let flows = lan.flows.clone();
    for (k, clients) in clients.iter().enumerate() {
        assert_echoed(clients);
        for client in clients {
            let info = lan.network(k).connection_info(client.connection).unwrap();
            assert_eq!(info.state, State::Established);
            if let Some(flows) = &flows {
                assert_eq!(
                    flows.owner(v4(info.local), v4(info.peer)),
                    Some(k),
                    "{info:?}"
                );
            }
        }
    }
    assert_eq!(server.connections.len(), members * per_member);
    lan.assert_no_resets();
}

#[test]
fn active_opens_choose_local_ports_whose_flows_their_member_owns() {
    for n in [2, 4] {
        for dispatch in [
            Dispatch::Queue0,
            Dispatch::rss(n),
            Dispatch::Scatter(0x2545_f491_4f6c_dd1d),
        ] {
            let mut lan = hash_lan(n, dispatch.clone(), INBOX);
            active(&mut lan, 8, 4 * MSS, 5 * SECOND);
            let (handed_off, _, dropped) = lan.handoffs();
            match dispatch {
                Dispatch::Rss { .. } => assert_eq!(handed_off, 0, "{n} members"),
                _ => assert!(handed_off > 0, "{n} members, {dispatch:?}"),
            }
            assert_eq!(dropped, 0);
        }
    }
}

// 3. An explicit local port is taken only if its flow is the member's own.

#[test]
fn connect_from_refuses_a_port_another_member_owns() {
    for n in [2, 4] {
        let mut lan = hash_lan(n, Dispatch::rss(n), INBOX);
        let flows = lan.flows.clone().unwrap();
        let remote = SocketAddrV4::new(PEER, LISTEN);
        let owner = |port| flows.owner(SocketAddrV4::new(ADDRESS, port), remote);
        let mut server = Echo::new(&mut lan.peer.network);
        let mut clients = Vec::new();
        for k in 0..n {
            let foreign = (40_000..).find(|&p| owner(p) != Some(k)).unwrap();
            assert!(
                lan.network(k)
                    .connect_from(remote.into(), Some(foreign))
                    .is_err(),
                "member {k}, port {foreign}"
            );
            // Nothing was opened: the member sends nothing.
            let now = lan.now;
            lan.network(k).drive(now, BUDGET).unwrap();
            assert!(lan.members[k].as_ref().unwrap().sent().is_empty());
            let own = (40_000..).find(|&p| owner(p) == Some(k)).unwrap();
            let connection = lan
                .network(k)
                .connect_from(remote.into(), Some(own))
                .unwrap();
            let info = lan.network(k).connection_info(connection).unwrap();
            assert_eq!(info.local, SocketAddr::new(ADDRESS.into(), own));
            clients.push(Client::new(connection, payload(k, 2 * MSS)));
        }
        let done = lan.run(5 * SECOND, |lan| {
            server.serve(&mut lan.peer.network);
            for (k, client) in clients.iter_mut().enumerate() {
                client.pump(lan.network(k));
            }
            clients.iter().all(Client::done)
        });
        assert!(done, "{n} members");
        assert_echoed(&clients);
        lan.assert_no_resets();
    }
}

// 4. ICMP errors: the router's next hop toward the peer takes 1200 octets,
// and its fragmentation-needed errors reach a member that does not own the
// quoted flow. The owner learns the smaller path MTU: once it has had the
// error for its flow it sends no packet the router drops, and its transfer
// completes. Had it not learned, every retransmission would be dropped
// again.

const ROUTER_MTU: usize = 1200;

fn with_pmtud(config: &mut NetworkConfig) {
    config.tcp.connection.pmtud = Some(ntcp::PmtudConfig::new(1500));
}
fn icmp_case(lan: &mut Lan) {
    lan.router.mtu = Some(ROUTER_MTU);
    active(lan, 1, 32 * 1024, 10 * SECOND);
    let drops = &lan.router.drops;
    assert!(!drops.is_empty());
    // A flow's first drop sent its error; every later drop must be of a
    // packet the owner sent before that error reached it.
    for &(at, port) in drops {
        let first = drops.iter().find(|d| d.1 == port).unwrap().0;
        assert!(
            at <= first + 2_000,
            "port {port}: drop at {at} after {first}"
        );
    }
}

#[test]
fn an_icmp_error_delivered_to_another_member_reaches_the_flows_owner() {
    for n in [2, 4] {
        let (flows, stations) = hash_members(n, INBOX, with_pmtud);
        let mut lan = Lan::new(stations, Dispatch::rss(n), Some(flows));
        lan.router.misdeliver_icmp = true;
        icmp_case(&mut lan);
        let errors = lan.router.drops.len() as u64;
        // Under RSS with the flows' key only the errors are misdelivered,
        // each once; every member had its own flow's errors handed to it.
        let (handed_off, received, dropped) = lan.handoffs();
        assert_eq!((handed_off, dropped), (errors, 0), "{n} members");
        assert_eq!(received, errors);
        for k in 0..n {
            let counters = lan.network(k).counters();
            assert!(counters.handoffs_received > 0, "member {k} of {n}");
        }
    }
}

// 5. Fragments: the router fragments the peer's datagrams into pieces of
// at most 576 octets, which reach the queues scattered (or, under RSS, by
// their addresses, at the member that reassembles them). The reassembler
// hands each complete datagram to its owner.

#[test]
fn fragments_spread_over_queues_are_reassembled_and_reach_the_flows_owner() {
    for n in [2, 4] {
        for dispatch in [Dispatch::Scatter(0xd1b5_4a32_d192_ed03), Dispatch::rss(n)] {
            // Room for two of the peer's drives of datagrams: the scatter
            // interleaves the fragments of one drive's datagrams, and some
            // wait in a queue while the next drive's arrive. A fragment
            // refused for room leaves the rest of its datagram holding a
            // slot until the reassembly timeout.
            let (flows, stations) = hash_members(n, INBOX, |config| {
                config.reassembly_datagrams = 2 * BUDGET.transmit;
            });
            let mut lan = Lan::new(stations, dispatch.clone(), Some(flows));
            lan.router.fragment = Some(576);
            let Passive { lan, .. } = passive(lan, 8, 8 * MSS, 5 * SECOND);
            let (handed_off, _, dropped) = lan.handoffs();
            assert!(handed_off > 0, "{n} members, {dispatch:?}");
            assert_eq!(dropped, 0);
        }
    }
}

// 6. A full inbox drops a handoff, as a full NIC queue drops a packet; TCP
// retransmits it.

#[test]
fn handoffs_to_a_full_inbox_are_dropped_and_tcp_recovers_them() {
    for n in [2, 4] {
        let lan = hash_lan(n, Dispatch::Queue0, 2);
        let Passive { lan, .. } = passive(lan, 8, 8 * MSS, 120 * SECOND);
        let (handed_off, _, dropped) = lan.handoffs();
        assert!(dropped > 0 && handed_off > 0, "{n} members");
    }
}

// 7 and 9. Members with an address each: the peer connects to every
// member's address and every member connects to the peer.

fn distinct(n: usize, dispatch: Dispatch, flows: Option<SharedFlows>) -> Lan {
    let table = neighbors(n);
    let members = (0..n)
        .map(|k| {
            let config = config(member_ip(k), PORT_MAC, MEMBER_CONNECTIONS);
            match &flows {
                Some(flows) => join(flows, &table, k, config),
                None => Station::build(|port| {
                    Network::with_shared_neighbors(config, port, SECRET, 0, &table)
                })
                .unwrap(),
            }
        })
        .collect();
    let mut lan = Lan::new(members, dispatch, flows);
    let mut servers: Vec<_> = (0..n).map(|k| Echo::new(lan.network(k))).collect();
    let mut peer_server = Echo::new(&mut lan.peer.network);
    let to_peer = SocketAddr::new(PEER.into(), LISTEN);
    // The peer's clients first, four per member, then two of each member.
    let mut clients: Vec<(Option<usize>, Client)> = Vec::new();
    for k in 0..n {
        for i in 0..4 {
            let to = SocketAddr::new(member_ip(k).into(), LISTEN);
            let connection = lan.peer.network.connect(to).unwrap();
            clients.push((None, Client::new(connection, payload(k * 4 + i, 3 * MSS))));
        }
    }
    for k in 0..n {
        for i in 0..2 {
            let connection = lan.network(k).connect(to_peer).unwrap();
            let data = payload(100 + k * 2 + i, 3 * MSS);
            clients.push((Some(k), Client::new(connection, data)));
        }
    }
    let done = lan.run(5 * SECOND, |lan| {
        for (k, server) in servers.iter_mut().enumerate() {
            server.serve(lan.network(k));
        }
        peer_server.serve(&mut lan.peer.network);
        for (member, client) in &mut clients {
            match member {
                Some(k) => client.pump(lan.network(*k)),
                None => client.pump(&mut lan.peer.network),
            }
        }
        clients.iter().all(|(_, c)| c.done())
    });
    assert!(done, "{n} members");
    for (member, client) in &clients {
        assert!(client.received == client.payload);
        if let Some(k) = *member {
            let info = lan.network(k).connection_info(client.connection).unwrap();
            assert_eq!(info.local.ip(), IpAddr::V4(member_ip(k)));
        }
    }
    for (k, server) in servers.iter().enumerate() {
        assert_eq!(server.connections.len(), 4, "member {k}");
        for &(connection, _) in &server.connections {
            let info = lan.network(k).connection_info(connection).unwrap();
            assert_eq!(info.local, SocketAddr::new(member_ip(k).into(), LISTEN));
        }
    }
    lan.assert_no_resets();
    lan
}
fn by_address(n: usize) -> SharedFlows {
    SharedFlows::new(FlowOwnership::ByAddress, limits(n, INBOX)).unwrap()
}
fn addresses(n: usize) -> Vec<Ipv4Addr> {
    (0..n).map(member_ip).collect()
}

#[test]
fn by_address_members_on_a_single_queue_hand_each_other_their_flows() {
    for n in [2, 4] {
        let lan = distinct(n, Dispatch::Queue0, Some(by_address(n)));
        let (handed_off, received, dropped) = lan.handoffs();
        assert!(handed_off > 0 && received > 0, "{n} members");
        assert_eq!(dropped, 0);
    }
}

// The per-address deployment of today, with flow rules steering each
// address to its member, keeps working with flows and needs no handoff.
#[test]
fn by_address_members_steered_by_destination_need_no_handoff() {
    for n in [2, 4] {
        let lan = distinct(
            n,
            Dispatch::ByDestination(addresses(n)),
            Some(by_address(n)),
        );
        assert_eq!(lan.handoffs(), (0, 0, 0), "{n} members");
    }
}

// 8. A member that leaves: data for its flows is handed off and dropped,
// and the other members' connections carry on.

#[test]
fn a_member_that_leaves_has_its_handoffs_dropped_and_spares_the_others() {
    for n in [2, 4] {
        let mut lan = hash_lan(n, Dispatch::Queue0, INBOX);
        let flows = lan.flows.clone().unwrap();
        let mut servers: Vec<_> = (0..n).map(|k| Echo::new(lan.network(k))).collect();
        let to = SocketAddr::new(ADDRESS.into(), LISTEN);
        let mut clients: Vec<(usize, Client)> = (0..16)
            .map(|i| {
                let port = 20_000 + 97 * i as u16;
                let connection = lan.peer.network.connect_from(to, Some(port)).unwrap();
                let owner = flows
                    .owner(
                        SocketAddrV4::new(ADDRESS, LISTEN),
                        SocketAddrV4::new(PEER, port),
                    )
                    .unwrap();
                (owner, Client::new(connection, payload(i, 64)))
            })
            .collect();
        let gone = n - 1;
        assert!(clients.iter().any(|&(owner, _)| owner == gone));
        let mut pump =
            |lan: &mut Lan, clients: &mut [(usize, Client)], counted: &dyn Fn(usize) -> bool| {
                for (k, server) in servers.iter_mut().enumerate() {
                    if let Some(member) = &mut lan.members[k] {
                        server.serve(&mut member.network);
                    }
                }
                for (_, client) in clients.iter_mut() {
                    client.pump(&mut lan.peer.network);
                }
                clients
                    .iter()
                    .filter(|(owner, _)| counted(*owner))
                    .all(|(_, c)| c.done())
            };
        assert!(lan.run(2 * SECOND, |lan| pump(lan, &mut clients, &|_| true)));
        lan.members[gone] = None;
        for (i, (_, client)) in clients.iter_mut().enumerate() {
            client.payload.extend(payload(100 + i, 3 * MSS));
        }
        let others = |owner: usize| owner != gone;
        assert!(lan.run(lan.now + 5 * SECOND, |lan| pump(lan, &mut clients, &others)));
        for (owner, client) in &clients {
            if *owner != gone {
                assert!(client.received == client.payload);
            } else {
                assert!(client.received.len() < client.payload.len());
            }
        }
        let (_, _, dropped) = lan.handoffs();
        assert!(dropped > 0, "{n} members");
        assert_eq!(lan.resets, vec![0; n]);
    }
}

// Members on their own threads, one shared clock: the port has one queue,
// member 0's, so every other member's packets cross threads through its
// inbox. A member that has its echo keeps driving until every member has
// its own: the port's queue has no other reader.
#[test]
fn members_on_separate_threads_take_handoffs_from_another_thread() {
    for n in [2, 4] {
        let flows = hash_flows(n, INBOX);
        let table = neighbors(n);
        let start = std::time::Instant::now();
        let clock = move || start.elapsed().as_micros() as u64;
        let mut peer = Station::peer();
        let listener = peer.network.listen(LISTEN, 16).unwrap();
        let incoming: Vec<Frames> = (0..n).map(|_| Frames::default()).collect();
        let len = 16 * 1024;
        let (ready, ready_rx) = mpsc::channel();
        let finished = Arc::new(AtomicUsize::new(0));
        let workers: Vec<_> = (0..n)
            .map(|k| {
                let (flows, table, ready) = (flows.clone(), table.clone(), ready.clone());
                let finished = finished.clone();
                let port = Station::port(&incoming[k], &peer.incoming);
                thread::spawn(move || -> Option<(Vec<u8>, Counters, Option<usize>)> {
                    let config = config(ADDRESS, PORT_MAC, MEMBER_CONNECTIONS);
                    let built = Network::with_shared_flows(
                        config,
                        port,
                        SECRET,
                        clock(),
                        Some(&table),
                        &flows,
                        k,
                    );
                    let mut network = match built {
                        Ok(network) => {
                            let _ = ready.send((k, Ok(())));
                            network
                        }
                        Err(e) => {
                            let _ = ready.send((k, Err(format!("{e:?}"))));
                            return None;
                        }
                    };
                    let data = payload(k, len);
                    let client = network
                        .connect(SocketAddr::new(PEER.into(), LISTEN))
                        .unwrap();
                    let (mut sent, mut echoed) = (0, Vec::new());
                    let mut out = [0; 4096];
                    let mut counted = false;
                    while finished.load(Ordering::Acquire) < n
                        && start.elapsed() < Duration::from_secs(30)
                    {
                        if !counted && echoed.len() == data.len() {
                            finished.fetch_add(1, Ordering::AcqRel);
                            counted = true;
                        }
                        network.drive(clock(), BUDGET).unwrap();
                        if sent < data.len()
                            && let Ok(receipt) =
                                network.try_write(client, &data[sent..], WriteOptions::default())
                        {
                            sent += receipt.accepted;
                        }
                        while let Ok(ReadOutcome::Data { len, .. }) =
                            network.try_read(client, &mut out)
                        {
                            echoed.extend_from_slice(&out[..len]);
                        }
                        thread::sleep(Duration::from_micros(100));
                    }
                    // While the member is still in the flows: once every
                    // member has left, no member serves the address.
                    let local = network.connection_info(client).unwrap().local;
                    let owner = flows.owner(v4(local), SocketAddrV4::new(PEER, LISTEN));
                    Some((echoed, network.counters(), owner))
                })
            })
            .collect();
        drop(ready);
        for _ in 0..n {
            let (k, joined) = ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            if let Err(e) = joined {
                panic!("member {k} joins the shared flows: {e}");
            }
        }
        let mut echoes: Vec<(ConnId, VecDeque<u8>)> = Vec::new();
        let mut out = [0; 4096];
        let mut dispatch = Dispatch::Queue0;
        while !workers.iter().all(|w| w.is_finished()) && start.elapsed() < Duration::from_secs(40)
        {
            peer.network.drive(clock(), BUDGET).unwrap();
            for frame in peer.sent() {
                let queue = dispatch.queue(&frame, n);
                incoming[queue].lock().unwrap().push_back(frame);
            }
            while let Ok(server) = peer.network.accept(listener) {
                echoes.push((server, VecDeque::new()));
            }
            for (server, queued) in &mut echoes {
                while let Ok(ReadOutcome::Data { len, .. }) =
                    peer.network.try_read(*server, &mut out)
                {
                    queued.extend(&out[..len]);
                }
                if !queued.is_empty()
                    && let Ok(receipt) = peer.network.try_write(
                        *server,
                        queued.make_contiguous(),
                        WriteOptions::default(),
                    )
                {
                    queued.drain(..receipt.accepted);
                }
            }
            thread::sleep(Duration::from_micros(100));
        }
        let mut handed_off = 0;
        for (k, worker) in workers.into_iter().enumerate() {
            let (echoed, counters, owner) = worker.join().unwrap().unwrap();
            assert!(echoed == payload(k, len), "member {k} of {n}");
            assert_eq!(owner, Some(k));
            if k > 0 {
                assert!(counters.handoffs_received > 0, "member {k} of {n}");
            }
            handed_off += counters.handed_off;
            assert_eq!(counters.handoffs_dropped, 0);
        }
        assert!(handed_off > 0);
        assert_eq!(echoes.len(), n);
    }
}

// Controls: the harness itself, and the ground the flows stand on.

// RSS's published verification suite ("Verifying the RSS Hash
// Calculation"): its key, and for each destination and source the hash of
// the addresses and of addresses and ports.
const MICROSOFT_KEY: [u8; 40] = [
    0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
    0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
    0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
];

#[test]
fn control_the_test_toeplitz_hash_matches_the_rss_verification_suite() {
    let vectors = [
        (
            "161.142.100.80:1766",
            "66.9.149.187:2794",
            0x323e_8fc2,
            0x51cc_c178,
        ),
        (
            "65.69.140.83:4739",
            "199.92.111.2:14230",
            0xd718_262a,
            0xc626_b0ea,
        ),
        (
            "12.22.207.184:38024",
            "24.19.198.95:12898",
            0xd2d0_a5de,
            0x5c2b_394a,
        ),
        (
            "209.142.163.6:2217",
            "38.27.205.30:48228",
            0x8298_9176,
            0xafc7_327f,
        ),
        (
            "202.188.127.2:1303",
            "153.39.163.191:44251",
            0x5d18_09c5,
            0x10e8_28a2,
        ),
    ];
    for (destination, source, addresses, with_ports) in vectors {
        let destination: SocketAddrV4 = destination.parse().unwrap();
        let source: SocketAddrV4 = source.parse().unwrap();
        let mut input = source.ip().octets().to_vec();
        input.extend(destination.ip().octets());
        assert_eq!(toeplitz(&MICROSOFT_KEY, &input), addresses);
        input.extend(source.port().to_be_bytes());
        input.extend(destination.port().to_be_bytes());
        assert_eq!(toeplitz(&MICROSOFT_KEY, &input), with_ports);
    }
}

#[test]
fn control_the_router_fragments_a_datagram_into_conforming_fragments() {
    let data: Vec<u8> = (0..1480).map(|i| i as u8).collect();
    let frame = ipv4_frame(PEER, ADDRESS, 6, &data);
    let pieces = fragment(&frame, 576, 7);
    assert_eq!(pieces.len(), 3);
    let mut joined: Vec<u8> = Vec::new();
    for (i, piece) in pieces.iter().enumerate() {
        let ip = l3(piece).unwrap();
        assert!(ip.len() <= 576);
        assert_eq!(checksum(&ip[..20]), 0);
        assert_eq!(ip[4..6], [0, 7]);
        let flags = u16::from_be_bytes([ip[6], ip[7]]);
        assert_eq!(flags & 0x2000 != 0, i < 2);
        assert_eq!(usize::from(flags & 0x1fff) * 8, joined.len());
        assert!(is_fragment(ip) && ports(ip).is_none());
        joined.extend(&ip[20..]);
    }
    assert_eq!(joined, data);
}

// The PMTU observable of the ICMP scenario, on a Network of its own.
#[test]
fn control_a_lone_network_learns_the_path_mtu_from_the_routers_error() {
    let mut config = config(ADDRESS, PORT_MAC, MEMBER_CONNECTIONS);
    with_pmtud(&mut config);
    let station = Station::build(|port| Network::new(config, port, SECRET, 0)).unwrap();
    let mut lan = Lan::new(vec![station], Dispatch::Queue0, None);
    icmp_case(&mut lan);
}

// 9. N members on one port with shared neighbors and an address each,
// steered by destination as flow rules would: the harness carries every
// connection without flows.
#[test]
fn control_members_with_their_own_addresses_and_ideal_steering_exchange_data() {
    for n in [2, 4] {
        distinct(n, Dispatch::ByDestination(addresses(n)), None);
    }
}

// 10. Two Networks with one address and no flows, on a single queue: the
// SYN/ACK of the second's connection reaches the first, which knows no such
// connection and resets it. This is what handoff exists to prevent.
#[test]
fn control_networks_sharing_an_address_without_flows_reset_each_others_segments() {
    let table = neighbors(2);
    let members = (0..2)
        .map(|_| {
            Station::build(|port| {
                let config = config(ADDRESS, PORT_MAC, MEMBER_CONNECTIONS);
                Network::with_shared_neighbors(config, port, SECRET, 0, &table)
            })
            .unwrap()
        })
        .collect();
    let mut lan = Lan::new(members, Dispatch::Queue0, None);
    let mut server = Echo::new(&mut lan.peer.network);
    let to = SocketAddr::new(PEER.into(), LISTEN);
    let connection = lan.network(1).connect(to).unwrap();
    let established = lan.run(3 * SECOND, |lan| {
        server.serve(&mut lan.peer.network);
        lan.network(1).connection_info(connection).unwrap().state == State::Established
    });
    assert!(!established);
    assert!(lan.resets[0] > 0, "{:?}", lan.resets);
    assert_eq!(lan.resets[1], 0);
    assert!(server.connections.is_empty());
}

// 11. Tagged ports (`FlowOwnership::TaggedPorts`): a member's active opens
// take its own tagged ports, and the port's rule for the member steers the
// replies to its queue; every other flow is hashed as RSS hashes it.

// The IANA dynamic range, the default ephemeral ports.
const TAG: u16 = 0xc000;

fn tagged_flows(members: usize) -> SharedFlows {
    let ownership = FlowOwnership::TaggedPorts {
        key: DEFAULT_FLOW_KEY.to_vec(),
        table: round_robin(members, TABLE),
        prefix: TAG,
        prefix_mask: TAG,
    };
    SharedFlows::new(ownership, limits(members, INBOX)).unwrap()
}
// `members` members of new TaggedPorts flows on ADDRESS.
fn tagged_members(
    members: usize,
    adjust: impl Fn(&mut NetworkConfig),
) -> (SharedFlows, Vec<Station>) {
    let flows = tagged_flows(members);
    let table = neighbors(members);
    let stations = (0..members)
        .map(|k| {
            let mut config = config(ADDRESS, PORT_MAC, MEMBER_CONNECTIONS);
            adjust(&mut config);
            join(&flows, &table, k, config)
        })
        .collect();
    (flows, stations)
}
// The port programmed for tagged flows: each member's port rule, ahead of
// RSS with the flows' key and table.
fn port_rules(flows: &SharedFlows) -> Dispatch {
    let members = flows.limits().members;
    let rules = (0..members).map(|k| flows.port_rule(k).unwrap()).collect();
    Dispatch::Rules(rules, Box::new(Dispatch::rss(members)))
}
fn tagged_lan(members: usize, dispatch: impl FnOnce(&SharedFlows) -> Dispatch) -> Lan {
    let (flows, stations) = tagged_members(members, |_| {});
    let dispatch = dispatch(&flows);
    Lan::new(stations, dispatch, Some(flows))
}
// A port of the tag's highest quarter tagged with member `k`.
fn tagged_port(k: usize) -> u16 {
    0xd000 | k as u16
}

#[test]
fn active_opens_from_tagged_ports_steered_by_port_rules_need_no_handoff() {
    for n in [2, 3, 4] {
        let mut lan = tagged_lan(n, port_rules);
        active(&mut lan, 8, 4 * MSS, 5 * SECOND);
        assert_eq!(lan.handoffs(), (0, 0, 0), "{n} members");
    }
}

#[test]
fn active_opens_from_tagged_ports_survive_a_port_without_rules() {
    for n in [2, 3, 4] {
        for dispatch in [Dispatch::Queue0, Dispatch::Scatter(0x2545_f491_4f6c_dd1d)] {
            let mut lan = tagged_lan(n, |_| dispatch.clone());
            active(&mut lan, 8, 4 * MSS, 5 * SECOND);
            let (handed_off, received, dropped) = lan.handoffs();
            assert!(handed_off > 0 && received > 0, "{n} members, {dispatch:?}");
            assert_eq!(dropped, 0);
        }
    }
}

#[test]
fn passive_opens_on_an_untagged_port_follow_rss_under_tagged_ports() {
    for n in [2, 3, 4] {
        let lan = tagged_lan(n, port_rules);
        let Passive { lan, servers } = passive(lan, 64, 4 * MSS, 5 * SECOND);
        assert!(servers.iter().all(|s| !s.connections.is_empty()), "{n}");
        assert_eq!(lan.handoffs(), (0, 0, 0), "{n} members");
    }
}

#[test]
fn an_icmp_error_about_a_tagged_port_delivered_elsewhere_reaches_its_member() {
    for n in [2, 3, 4] {
        let (flows, stations) = tagged_members(n, with_pmtud);
        let dispatch = port_rules(&flows);
        let mut lan = Lan::new(stations, dispatch, Some(flows.clone()));
        lan.router.misdeliver_icmp = true;
        icmp_case(&mut lan);
        // The rules steer every segment: only the errors are handed off,
        // each once, to the member tagged in the port they quote.
        let errors = lan.router.drops.len() as u64;
        assert_eq!(lan.handoffs(), (errors, errors, 0), "{n} members");
        for &(_, port) in &lan.router.drops {
            let rules = (0..n).filter_map(|k| flows.port_rule(k));
            let tagged = rules.filter(|&(value, mask)| port & mask == value);
            assert_eq!(tagged.count(), 1, "port {port}");
        }
        for k in 0..n {
            let counters = lan.network(k).counters();
            assert!(counters.handoffs_received > 0, "member {k} of {n}");
        }
    }
}

#[test]
fn connect_from_refuses_another_members_tagged_port() {
    for n in [2, 3, 4] {
        let mut lan = tagged_lan(n, port_rules);
        let flows = lan.flows.clone().unwrap();
        let remote = SocketAddrV4::new(PEER, LISTEN);
        let owner = |port| flows.owner(SocketAddrV4::new(ADDRESS, port), remote);
        let mut server = Echo::new(&mut lan.peer.network);
        let mut clients = Vec::new();
        for k in 0..n {
            // Another member's tagged port, then an untagged port whose
            // flow another member owns by its hash.
            let foreign = [
                tagged_port((k + 1) % n),
                (40_000..).find(|&p| owner(p) != Some(k)).unwrap(),
            ];
            for port in foreign {
                assert!(
                    matches!(
                        lan.network(k).connect_from(remote.into(), Some(port)),
                        Err(Error::InvalidConfig(_))
                    ),
                    "member {k}, port {port}"
                );
            }
            // Nothing was opened: the member sends nothing.
            let now = lan.now;
            lan.network(k).drive(now, BUDGET).unwrap();
            assert!(lan.members[k].as_ref().unwrap().sent().is_empty());
            // Its own tagged port, and an untagged port it owns by hash.
            let own = [
                tagged_port(k),
                (40_000..).find(|&p| owner(p) == Some(k)).unwrap(),
            ];
            for port in own {
                let connection = lan
                    .network(k)
                    .connect_from(remote.into(), Some(port))
                    .unwrap();
                let info = lan.network(k).connection_info(connection).unwrap();
                assert_eq!(info.local, SocketAddr::new(ADDRESS.into(), port));
                let data = payload(clients.len(), 2 * MSS);
                clients.push((k, Client::new(connection, data)));
            }
        }
        let done = lan.run(5 * SECOND, |lan| {
            server.serve(&mut lan.peer.network);
            for (k, client) in &mut clients {
                client.pump(lan.network(*k));
            }
            clients.iter().all(|(_, c)| c.done())
        });
        assert!(done, "{n} members");
        for (_, client) in &clients {
            assert!(client.received == client.payload);
        }
        assert_eq!(lan.handoffs(), (0, 0, 0), "{n} members");
        lan.assert_no_resets();
    }
}

// A tagged port's connections are its member's, so that member alone
// listens on it, and the port's rule steers them straight to its queue.
#[test]
fn a_tagged_port_is_listened_on_by_its_member_alone() {
    let n = 4;
    let mut lan = tagged_lan(n, port_rules);
    let mut servers = Vec::new();
    for k in 0..n {
        for other in (0..n).filter(|&m| m != k) {
            assert!(
                matches!(
                    lan.network(other).listen(tagged_port(k), 64),
                    Err(Error::InvalidConfig(_))
                ),
                "member {other} on member {k}'s port"
            );
        }
        let listener = lan.network(k).listen(tagged_port(k), 64).unwrap();
        servers.push(Echo {
            listener,
            connections: Vec::new(),
        });
    }
    let mut clients: Vec<_> = (0..4 * n)
        .map(|i| {
            let to = SocketAddr::new(ADDRESS.into(), tagged_port(i % n));
            let connection = lan.peer.network.connect(to).unwrap();
            Client::new(connection, payload(i, 3 * MSS))
        })
        .collect();
    let done = lan.run(5 * SECOND, |lan| {
        for (k, server) in servers.iter_mut().enumerate() {
            server.serve(lan.network(k));
        }
        for client in &mut clients {
            client.pump(&mut lan.peer.network);
        }
        clients.iter().all(Client::done)
    });
    assert!(done);
    assert_echoed(&clients);
    for (k, server) in servers.iter().enumerate() {
        assert_eq!(server.connections.len(), 4, "member {k}");
    }
    assert_eq!(lan.handoffs(), (0, 0, 0));
    lan.assert_no_resets();
}

// A member's ephemeral ports are its tagged ports in its range, without
// those it listens on, until they run out; a range that holds none of
// them is refused, and nothing joins.
#[test]
fn active_opens_take_their_members_tagged_ports_until_they_run_out() {
    let n = 4;
    // Sixteen ephemeral ports, four tagged with each member.
    let (flows, stations) = tagged_members(n, |c| c.ephemeral_ports = 0xc000..=0xc00f);
    let mut lan = Lan::new(stations, port_rules(&flows), Some(flows));
    let mut server = Echo::new(&mut lan.peer.network);
    let to = SocketAddr::new(PEER.into(), LISTEN);
    let mut clients = Vec::new();
    for k in 0..n {
        let tag = k as u16;
        lan.network(k).listen(TAG | tag, 4).unwrap();
        for port in [0xc004, 0xc008, 0xc00c] {
            let connection = lan.network(k).connect(to).unwrap();
            let local = lan.network(k).connection_info(connection).unwrap().local;
            assert_eq!(local, SocketAddr::new(ADDRESS.into(), port | tag));
            let data = payload(clients.len(), MSS);
            clients.push((k, Client::new(connection, data)));
        }
        assert!(
            matches!(lan.network(k).connect(to), Err(Error::Capacity)),
            "member {k}"
        );
    }
    let done = lan.run(5 * SECOND, |lan| {
        server.serve(&mut lan.peer.network);
        for (k, client) in &mut clients {
            client.pump(lan.network(*k));
        }
        clients.iter().all(|(_, c)| c.done())
    });
    assert!(done);
    assert_eq!(lan.handoffs(), (0, 0, 0));
    lan.assert_no_resets();

    let flows = tagged_flows(n);
    let table = neighbors(n);
    let member = |k: usize, ports: std::ops::RangeInclusive<u16>| {
        let mut config = config(ADDRESS, PORT_MAC, MEMBER_CONNECTIONS);
        config.ephemeral_ports = ports;
        Station::build(|port| {
            Network::with_shared_flows(config, port, SECRET, 0, Some(&table), &flows, k)
        })
    };
    // Member 3's tagged ports are none of 0xc000 to 0xc002, and no member's
    // are below the tag.
    for (k, ports) in [(3, 0xc000..=0xc002), (0, 1024..=0xbfff)] {
        assert!(
            matches!(member(k, ports.clone()), Err(Error::InvalidConfig(_))),
            "member {k}, {ports:?}"
        );
    }
    let joined = [member(2, 0xc000..=0xc002), member(3, 0xbfff..=0xc003)];
    assert!(joined.iter().all(Result::is_ok));
}
