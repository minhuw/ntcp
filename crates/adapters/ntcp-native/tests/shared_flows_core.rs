// Networks on the queues of one Ethernet port that share its flows, driven
// over an in-memory LAN on which the port cannot steer: every frame to the
// port reaches the first member's queue, which hands each packet of another
// member's flow to that member. A peer station with its own MAC and tables
// opens connections to them and accepts theirs.
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::*;
use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Mutex},
};

const SECOND: u64 = 1_000_000;
const STEP: u64 = 1_000;
const BUDGET: WorkBudget = WorkBudget::new(32, 32, 32, 32);
const PORT_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const PEER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const SHARED: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const PEER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 100);
const SERVICE: u16 = 80;
const PEER_SERVICE: u16 = 7000;
const CONNECTIONS: usize = 12;

type Queue = Arc<Mutex<VecDeque<Vec<u8>>>>;

struct Port {
    incoming: Queue,
    outgoing: Queue,
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
    incoming: Queue,
    outgoing: Queue,
}
impl Station {
    fn new(build: impl FnOnce(Port) -> Network<Port>) -> Self {
        let (incoming, outgoing) = (Queue::default(), Queue::default());
        let network = build(Port {
            incoming: incoming.clone(),
            outgoing: outgoing.clone(),
        });
        Self {
            network,
            incoming,
            outgoing,
        }
    }
    fn sent(&self) -> Vec<Vec<u8>> {
        self.outgoing.lock().unwrap().drain(..).collect()
    }
}

fn config(local: Ipv4Addr, mac: [u8; 6]) -> NetworkConfig {
    let mut config = NetworkConfig::new(IpAddr::V4(local), 1500);
    config.tcp.max_connections = 2 * CONNECTIONS;
    config.tcp.max_listeners = 1;
    config.tcp.connection.send_capacity = 4096;
    config.tcp.connection.receive_capacity = 4096;
    config.link = Link::Ethernet {
        local_mac: mac,
        next_hop: EthernetNextHop::Arp {
            prefix_len: 24,
            gateway: None,
        },
    };
    config
}
fn limits(members: usize) -> SharedFlowLimits {
    SharedFlowLimits {
        members,
        inbox_packets: 64,
        packet_bytes: 1500,
        redirected_flows: 64,
    }
}
fn neighbors(members: usize) -> SharedNeighbors {
    let limits = SharedNeighborLimits {
        members,
        entries: 8,
        held: members * (2 * CONNECTIONS + 1),
        replies: 4,
    };
    SharedNeighbors::new(PORT_MAC, SECOND, limits).unwrap()
}
fn members(
    addresses: &[Ipv4Addr],
    neighbors: &SharedNeighbors,
    flows: &SharedFlows,
) -> Vec<Station> {
    addresses
        .iter()
        .enumerate()
        .map(|(k, &address)| {
            Station::new(|port| {
                let config = config(address, PORT_MAC);
                Network::with_shared_flows(config, port, [7; 32], 0, Some(neighbors), flows, k)
                    .unwrap()
            })
        })
        .collect()
}
fn peer() -> Station {
    Station::new(|port| {
        let mut config = config(PEER, PEER_MAC);
        config.tcp.max_connections = 4 * CONNECTIONS;
        Network::new(config, port, [9; 32], 0).unwrap()
    })
}

// The TCP flags of an IPv4 frame.
fn tcp_flags(frame: &[u8]) -> Option<u8> {
    let ip = frame.get(14..34)?;
    if frame[12..14] != [8, 0] || ip[9] != 6 {
        return None;
    }
    frame.get(14 + usize::from(ip[0] & 15) * 4 + 13).copied()
}

struct Lan {
    members: Vec<Station>,
    peer: Station,
    now: u64,
    resets: usize,
}
impl Lan {
    // One drive of every station; everything to the port reaches the first
    // member's queue.
    fn step(&mut self) {
        self.now += STEP;
        for member in &mut self.members {
            member.network.drive(self.now, BUDGET).unwrap();
            for frame in member.sent() {
                self.resets += usize::from(tcp_flags(&frame).is_some_and(|f| f & 4 != 0));
                self.peer.incoming.lock().unwrap().push_back(frame);
            }
        }
        self.peer.network.drive(self.now, BUDGET).unwrap();
        for frame in self.peer.sent() {
            self.resets += usize::from(tcp_flags(&frame).is_some_and(|f| f & 4 != 0));
            self.members[0].incoming.lock().unwrap().push_back(frame);
        }
    }
}

fn payload(seed: usize) -> Vec<u8> {
    (0..3000).map(|i| (i * 7 + seed * 13) as u8).collect()
}

// One connection's two ends, each sending the other its payload.
struct Pair {
    // The member and its end, which it accepted (or opened); the peer's end.
    member: usize,
    passive: bool,
    near: ConnId,
    far: ConnId,
    near_data: (usize, Vec<u8>),
    far_data: (usize, Vec<u8>),
    seed: usize,
}

fn pump(network: &mut Network<Port>, id: ConnId, data: &[u8], progress: &mut (usize, Vec<u8>)) {
    if progress.0 < data.len()
        && let Ok(receipt) = network.try_write(id, &data[progress.0..], WriteOptions::default())
    {
        progress.0 += receipt.accepted;
    }
    let mut out = [0; 4096];
    while let Ok(ReadOutcome::Data { len, .. }) = network.try_read(id, &mut out) {
        progress.1.extend_from_slice(&out[..len]);
    }
}

// Every member listens on SERVICE and the peer on PEER_SERVICE; the peer
// opens CONNECTIONS connections to each of `targets`, and every member two
// to the peer. Each connection carries a payload each way.
fn exchange(lan: &mut Lan, targets: &[Ipv4Addr]) -> Vec<Pair> {
    let listeners: Vec<_> = lan
        .members
        .iter_mut()
        .map(|m| m.network.listen(SERVICE, CONNECTIONS).unwrap())
        .collect();
    let peer_listener = lan
        .peer
        .network
        .listen(PEER_SERVICE, 4 * CONNECTIONS)
        .unwrap();
    let mut pending: Vec<ConnId> = Vec::new();
    for &target in targets {
        for _ in 0..CONNECTIONS {
            let to = SocketAddr::new(target.into(), SERVICE);
            pending.push(lan.peer.network.connect(to).unwrap());
        }
    }
    let mut outbound: Vec<(usize, ConnId)> = Vec::new();
    for (k, member) in lan.members.iter_mut().enumerate() {
        for _ in 0..2 {
            let to = SocketAddr::new(PEER.into(), PEER_SERVICE);
            outbound.push((k, member.network.connect(to).unwrap()));
        }
    }
    let total = pending.len() + outbound.len();
    let mut pairs: Vec<Pair> = Vec::new();
    while lan.now < 20 * SECOND {
        lan.step();
        for (k, listener) in listeners.iter().enumerate() {
            while let Ok(near) = lan.members[k].network.accept(*listener) {
                let peer_end = lan.members[k].network.connection_info(near).unwrap().peer;
                let at = pending
                    .iter()
                    .position(|&c| lan.peer.network.connection_info(c).unwrap().local == peer_end)
                    .unwrap();
                pairs.push(Pair {
                    member: k,
                    passive: true,
                    near,
                    far: pending.swap_remove(at),
                    near_data: (0, Vec::new()),
                    far_data: (0, Vec::new()),
                    seed: pairs.len(),
                });
            }
        }
        while let Ok(far) = lan.peer.network.accept(peer_listener) {
            let member_end = lan.peer.network.connection_info(far).unwrap().peer;
            let at = outbound
                .iter()
                .position(|&(k, c)| {
                    lan.members[k].network.connection_info(c).unwrap().local == member_end
                })
                .unwrap();
            let (member, near) = outbound.swap_remove(at);
            pairs.push(Pair {
                member,
                passive: false,
                near,
                far,
                near_data: (0, Vec::new()),
                far_data: (0, Vec::new()),
                seed: pairs.len(),
            });
        }
        for pair in &mut pairs {
            let data = payload(pair.seed);
            let member = &mut lan.members[pair.member].network;
            pump(member, pair.near, &data, &mut pair.near_data);
            pump(&mut lan.peer.network, pair.far, &data, &mut pair.far_data);
        }
        if pairs.len() == total
            && pairs.iter().all(|p| {
                p.near_data.1.len() == payload(p.seed).len()
                    && p.far_data.1.len() == payload(p.seed).len()
            })
        {
            break;
        }
    }
    assert_eq!(pairs.len(), total, "connections established");
    for pair in &pairs {
        let data = payload(pair.seed);
        assert_eq!(pair.near_data.1, data, "member {}", pair.member);
        assert_eq!(pair.far_data.1, data, "peer of member {}", pair.member);
        let info = lan.members[pair.member]
            .network
            .connection_info(pair.near)
            .unwrap();
        assert_eq!(info.state, State::Established);
    }
    pairs
}

fn lan(members: Vec<Station>) -> Lan {
    Lan {
        members,
        peer: peer(),
        now: 0,
        resets: 0,
    }
}

// Three members of one address, a flow table of 16 entries.
#[cfg(unix)]
#[test]
fn members_of_one_address_take_every_flow_handed_from_one_unsteered_queue() {
    use std::io::Read;
    const MEMBERS: usize = 3;
    let table = (0..16).map(|i| i % MEMBERS).collect();
    let ownership = FlowOwnership::Hash {
        key: DEFAULT_FLOW_KEY.to_vec(),
        table,
    };
    let flows = SharedFlows::new(ownership, limits(MEMBERS)).unwrap();
    let neighbors = neighbors(MEMBERS);
    let mut lan = lan(members(&[SHARED; MEMBERS], &neighbors, &flows));
    // The second member blocks on one descriptor for both memberships.
    let (mut reader, writer) = io::pipe().unwrap();
    lan.members[1]
        .network
        .set_neighbor_wake_fd(std::os::fd::OwnedFd::from(writer))
        .unwrap();
    let pairs = exchange(&mut lan, &[SHARED]);
    // The peer's connections were divided among every member, each
    // accepted by the member owning its flow; the members' own opens chose
    // ports whose flows they own.
    for k in 0..MEMBERS {
        assert!(
            pairs.iter().any(|p| p.member == k && p.passive),
            "member {k} accepted none"
        );
    }
    for pair in &pairs {
        let info = lan.members[pair.member]
            .network
            .connection_info(pair.near)
            .unwrap();
        let (SocketAddr::V4(local), SocketAddr::V4(remote)) = (info.local, info.peer) else {
            unreachable!()
        };
        assert_eq!(flows.owner(local, remote), Some(pair.member));
    }
    assert_eq!(lan.resets, 0);
    let counters: Vec<_> = lan.members.iter().map(|m| m.network.counters()).collect();
    assert!(counters[0].handed_off > 0);
    assert_eq!(counters[0].handoffs_received, 0);
    for (k, c) in counters.iter().enumerate() {
        assert_eq!(c.handoffs_dropped, 0, "member {k}");
        if k != 0 {
            assert!(c.handoffs_received > 0, "member {k}");
            assert_eq!(c.handed_off, 0, "member {k}");
            // Its queue received nothing: everything came handed over.
            assert_eq!(c.received, 0, "member {k}");
        }
    }
    let handed: u64 = counters.iter().map(|c| c.handoffs_received).sum();
    assert_eq!(handed, counters[0].handed_off);
    // A local port whose flow to the peer another member owns is refused;
    // one whose flow it owns is not.
    let to = SocketAddr::new(PEER.into(), PEER_SERVICE);
    let remote = SocketAddrV4::new(PEER, PEER_SERVICE);
    let foreign = (1..)
        .find(|&p| flows.owner(SocketAddrV4::new(SHARED, p), remote) == Some(2))
        .unwrap();
    assert!(matches!(
        lan.members[1].network.connect_from(to, Some(foreign)),
        Err(Error::InvalidConfig(_))
    ));
    let own = (1..)
        .find(|&p| p != SERVICE && flows.owner(SocketAddrV4::new(SHARED, p), remote) == Some(1))
        .unwrap();
    lan.members[1].network.connect_from(to, Some(own)).unwrap();
    // Handoffs to the second member wrote its descriptor, one count at a
    // time; leaving closes it.
    lan.members.truncate(1);
    let mut written = Vec::new();
    reader.read_to_end(&mut written).unwrap();
    assert!(!written.is_empty() && written.len() % 8 == 0);
}

// Two members with their own addresses; everything still reaches the
// first member's queue.
#[test]
fn members_by_address_take_the_flows_of_their_address_from_one_queue() {
    let addresses = [SHARED, Ipv4Addr::new(10, 0, 0, 2)];
    let flows = SharedFlows::new(FlowOwnership::ByAddress, limits(2)).unwrap();
    let neighbors = neighbors(2);
    let mut lan = lan(members(&addresses, &neighbors, &flows));
    let pairs = exchange(&mut lan, &addresses);
    for pair in &pairs {
        let info = lan.members[pair.member]
            .network
            .connection_info(pair.near)
            .unwrap();
        assert_eq!(info.local.ip(), IpAddr::V4(addresses[pair.member]));
    }
    assert_eq!(
        pairs.iter().filter(|p| p.member == 1).count(),
        CONNECTIONS + 2
    );
    assert_eq!(lan.resets, 0);
    let (first, second) = (
        lan.members[0].network.counters(),
        lan.members[1].network.counters(),
    );
    assert!(first.handed_off > 0);
    assert_eq!(second.handoffs_received, first.handed_off);
    assert_eq!(first.handoffs_dropped + second.handoffs_dropped, 0);
}

// An active open takes no port another member listens on, and takes it
// once that listener is gone.
#[test]
fn active_opens_avoid_every_members_listening_ports() {
    let ownership = FlowOwnership::Hash {
        key: DEFAULT_FLOW_KEY.to_vec(),
        table: vec![0, 1],
    };
    let flows = SharedFlows::new(ownership, limits(2)).unwrap();
    let table = neighbors(2);
    let build = |k: usize, ports: std::ops::RangeInclusive<u16>| {
        Station::new(|port| {
            let mut config = config(SHARED, PORT_MAC);
            config.ephemeral_ports = ports;
            Network::with_shared_flows(config, port, [7; 32], 0, Some(&table), &flows, k).unwrap()
        })
    };
    let mut listening = build(1, 49152..=65535);
    // A range from a port whose flow to the peer the listening member owns
    // to the second one the opening member owns.
    let remote = SocketAddrV4::new(PEER, PEER_SERVICE);
    let owner = |p| flows.owner(SocketAddrV4::new(SHARED, p), remote);
    let start = (50000..).find(|&p| owner(p) == Some(1)).unwrap();
    let owned: Vec<u16> = (start..).filter(|&p| owner(p) == Some(0)).take(2).collect();
    let mut opening = build(0, start..=owned[1]);
    let listener = listening.network.listen(owned[0], 1).unwrap();
    let to = SocketAddr::V4(remote);
    let local = |s: &Station, c| s.network.connection_info(c).unwrap().local.port();
    let first = opening.network.connect(to).unwrap();
    assert_eq!(local(&opening, first), owned[1]);
    listening.network.close_listener(listener).unwrap();
    listening.network.drive(STEP, BUDGET).unwrap();
    let second = opening.network.connect(to).unwrap();
    assert_eq!(local(&opening, second), owned[0]);
    // The range's other ports are the listening member's flows.
    assert!(matches!(
        opening.network.connect(to),
        Err(Error::AddressNotAvailable)
    ));
    // A member number joins once.
    let port = Port {
        incoming: Queue::default(),
        outgoing: Queue::default(),
    };
    let config = config(SHARED, PORT_MAC);
    assert!(matches!(
        Network::with_shared_flows(config, port, [7; 32], 0, Some(&table), &flows, 1),
        Err(Error::InvalidConfig(_))
    ));
}

// A member's ephemeral ports are shared across destinations as a single
// Network's are, within its own flows: to each destination it takes
// exactly the ports of the range whose flow to it the member owns, but no
// port another member listens on, each once; so its opens to several
// destinations outnumber the range.
#[test]
fn a_members_ports_are_shared_across_destinations_within_its_flows() {
    let ownership = FlowOwnership::Hash {
        key: DEFAULT_FLOW_KEY.to_vec(),
        table: vec![0, 1],
    };
    let flows = SharedFlows::new(ownership, limits(2)).unwrap();
    // Room for every connection's output held on a resolution.
    let limits = SharedNeighborLimits {
        members: 2,
        entries: 8,
        held: 2 * 65,
        replies: 4,
    };
    let table = SharedNeighbors::new(PORT_MAC, SECOND, limits).unwrap();
    let range = 50000..=50015;
    let build = |k: usize, connections: usize| {
        let range = range.clone();
        Station::new(|port| {
            let mut config = config(SHARED, PORT_MAC);
            config.ephemeral_ports = range;
            config.tcp.max_connections = connections;
            config.tcp.max_buffer_bytes = config.buffer_budget(connections, &port).unwrap();
            Network::with_shared_flows(config, port, [7; 32], 0, Some(&table), &flows, k).unwrap()
        })
    };
    let mut listening = build(1, 4);
    let mut opening = build(0, 64);
    let listened = 50003;
    listening.network.listen(listened, 1).unwrap();
    let mut opened = 0;
    for d in 0..4 {
        let remote = SocketAddrV4::new(PEER, PEER_SERVICE + d);
        let owned: Vec<u16> = range
            .clone()
            .filter(|&p| p != listened)
            .filter(|&p| flows.owner(SocketAddrV4::new(SHARED, p), remote) == Some(0))
            .collect();
        let mut taken = Vec::new();
        loop {
            match opening.network.connect(SocketAddr::V4(remote)) {
                Ok(id) => taken.push(opening.network.connection_info(id).unwrap().local.port()),
                Err(Error::AddressNotAvailable) => break,
                Err(e) => panic!("{e:?}"),
            }
        }
        taken.sort_unstable();
        assert_eq!(taken, owned, "destination {d}");
        opened += taken.len();
    }
    assert!(opened > range.len(), "{opened}");
}

fn port() -> Port {
    Port {
        incoming: Queue::default(),
        outgoing: Queue::default(),
    }
}

// ARP for the port reaches the queue the NIC puts it on, so on an ARP link
// a member shares the port's neighbor table: without it, it is refused and
// joins nothing. A fixed next hop needs no table.
#[test]
fn members_on_an_arp_link_share_its_neighbor_table() {
    let ownership = FlowOwnership::Hash {
        key: DEFAULT_FLOW_KEY.to_vec(),
        table: vec![0, 1],
    };
    let flows = SharedFlows::new(ownership, limits(2)).unwrap();
    let local = SocketAddrV4::new(SHARED, SERVICE);
    let remote = SocketAddrV4::new(PEER, PEER_SERVICE);
    let config = || config(SHARED, PORT_MAC);
    let alone = Network::with_shared_flows(config(), port(), [7; 32], 0, None, &flows, 0);
    assert!(matches!(alone, Err(Error::InvalidConfig(_))));
    assert_eq!(flows.owner(local, remote), None);
    let table = neighbors(2);
    let shared = Network::with_shared_flows(config(), port(), [7; 32], 0, Some(&table), &flows, 0);
    assert!(shared.is_ok() && flows.owner(local, remote).is_some());
    let mut fixed = config();
    fixed.link = Link::Ethernet {
        local_mac: PORT_MAC,
        next_hop: EthernetNextHop::Fixed(PEER_MAC),
    };
    assert!(Network::with_shared_flows(fixed, port(), [7; 32], 0, None, &flows, 1).is_ok());
}

// A segment from the peer's `port` to SERVICE on the shared address, its
// TCP checksum left zero: members key it by its flow, and the owner's Host
// discards it.
fn segment(port: u16) -> Vec<u8> {
    let mut frame = [PORT_MAC, PEER_MAC].concat();
    frame.extend_from_slice(&[8, 0, 0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0]);
    frame.extend_from_slice(&PEER.octets());
    frame.extend_from_slice(&SHARED.octets());
    let mut sum: u32 = frame[14..34]
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], c[1]])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    frame[24..26].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    frame.extend_from_slice(&port.to_be_bytes());
    frame.extend_from_slice(&SERVICE.to_be_bytes());
    frame.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x10, 0x10, 0, 0, 0, 0, 0]);
    frame
}

// One drive of `station` with `receive` packets of budget: the packets it
// took from its queue and from its inbox.
fn receive(station: &mut Station, now: u64, receive: usize) -> (usize, usize) {
    let before = station.network.counters().handoffs_received;
    let report = station
        .network
        .drive(now, WorkBudget::new(receive, 8, 8, 8))
        .unwrap();
    let handed = station.network.counters().handoffs_received - before;
    (report.received, handed as usize)
}

// Other members can keep an inbox full however fast it drains, so it takes
// at most half of a drive's receive budget, rounded up, before the member's
// own queue, and after it what the queue leaves; the queue takes what the
// inbox leaves.
#[test]
fn the_inbox_and_the_queue_share_a_drives_receive_budget() {
    let ownership = FlowOwnership::Hash {
        key: DEFAULT_FLOW_KEY.to_vec(),
        table: vec![0, 1],
    };
    let flows = SharedFlows::new(ownership, limits(2)).unwrap();
    let neighbors = neighbors(2);
    let mut stations = members(&[SHARED; 2], &neighbors, &flows);
    let local = SocketAddrV4::new(SHARED, SERVICE);
    let port = (1024..)
        .find(|&p| flows.owner(local, SocketAddrV4::new(PEER, p)) == Some(1))
        .unwrap();
    let queue = |station: &Station, frames: usize| {
        let mut incoming = station.incoming.lock().unwrap();
        incoming.extend((0..frames).map(|_| segment(port)));
    };
    // 24 frames handed to the second member through the first, and 24 on
    // its own queue.
    queue(&stations[0], 24);
    receive(&mut stations[0], STEP, 64);
    assert_eq!(stations[0].network.counters().handed_off, 24);
    queue(&stations[1], 24);
    let second = &mut stations[1];
    assert_eq!(receive(second, STEP, 8), (4, 4));
    assert_eq!(receive(second, STEP, 7), (3, 4));
    // One frame left on the queue, 16 in the inbox.
    second.incoming.lock().unwrap().truncate(1);
    assert_eq!(receive(second, STEP, 8), (1, 7));
    assert_eq!(receive(second, STEP, 8), (0, 8));
    // One left in the inbox.
    queue(second, 20);
    assert_eq!(receive(second, STEP, 8), (7, 1));
    assert_eq!(second.network.counters().handoffs_dropped, 0);
}
