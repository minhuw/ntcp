// Fragmented input to a plain Network (`NetworkConfig::reassembly_datagrams`):
// a peer's stream through a router that fragments its datagrams, in order or
// rearranged with duplicate, overlapping and conflicting fragments, and
// crafted SYNs at the edge of the reassembled capacity. Last, the rule that
// members of hashed shared flows reassemble alike.
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::*;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    rc::Rc,
};

const SECOND: u64 = 1_000_000;
const TICK: u64 = 100;
const BUDGET: WorkBudget = WorkBudget::new(32, 32, 32, 32);
const LISTEN: u16 = 80;
// The router's MTU toward the Network under test.
const LIMIT: usize = 576;
const DATAGRAMS: usize = 4;

type Frames = Rc<RefCell<VecDeque<Vec<u8>>>>;

// An L3 link end, which may refuse to transmit.
struct Wire {
    incoming: Frames,
    outgoing: Frames,
    blocked: Rc<Cell<bool>>,
}
impl PacketIo for Wire {
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn max_packet_len(&self) -> Option<usize> {
        Some(65535)
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        let Some(packet) = self.incoming.borrow_mut().pop_front() else {
            return Ok(None);
        };
        out[..packet.len()].copy_from_slice(&packet);
        Ok(Some(packet.len()))
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        if self.blocked.get() {
            return Ok(TxOutcome::WouldBlock);
        }
        self.outgoing.borrow_mut().push_back(packet.to_vec());
        Ok(TxOutcome::Submitted)
    }
}

struct Station {
    network: Network<Wire>,
    incoming: Frames,
    outgoing: Frames,
    // The Identification of the next datagram `offer` fragments.
    next_id: u32,
}
impl Station {
    fn new(config: NetworkConfig) -> Self {
        let (incoming, outgoing) = (Frames::default(), Frames::default());
        let wire = Wire {
            incoming: incoming.clone(),
            outgoing: outgoing.clone(),
            blocked: Rc::default(),
        };
        let network = Network::new(config, wire, [5; 32], 0).unwrap();
        Self {
            network,
            incoming,
            outgoing,
            next_id: 0,
        }
    }
    fn sent(&self) -> Vec<Vec<u8>> {
        self.outgoing.borrow_mut().drain(..).collect()
    }
}

fn addresses(ipv6: bool) -> (IpAddr, IpAddr) {
    if ipv6 {
        (
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        )
    } else {
        ("10.9.0.1".parse().unwrap(), "10.9.0.2".parse().unwrap())
    }
}
fn config(address: IpAddr, mtu: u32, datagrams: usize) -> NetworkConfig {
    let mut config = NetworkConfig::new(address, mtu);
    config.tcp.max_connections = 4;
    config.tcp.max_listeners = 1;
    config.tcp.connection.send_capacity = 65536;
    config.tcp.connection.receive_capacity = 65536;
    config.reassembly_datagrams = datagrams;
    config
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
fn is_ipv6(ip: &[u8]) -> bool {
    ip[0] >> 4 == 6
}
// The unfragmentable part: the IPv4 header, or the IPv6 base header (the
// Networks send no extension headers).
fn header_len(ip: &[u8]) -> usize {
    if is_ipv6(ip) {
        40
    } else {
        usize::from(ip[0] & 15) * 4
    }
}
fn tcp(ip: &[u8]) -> Option<&[u8]> {
    let protocol = if is_ipv6(ip) { ip[6] } else { ip[9] };
    (protocol == 6).then(|| &ip[header_len(ip)..])
}
// The MSS option of a SYN segment.
fn mss(segment: &[u8]) -> Option<u16> {
    if segment[13] & 0x02 == 0 {
        return None;
    }
    let mut options = &segment[20..usize::from(segment[12] >> 4) * 4];
    while let [kind, rest @ ..] = options {
        match kind {
            0 => return None,
            1 => options = rest,
            2 => return Some(u16::from_be_bytes([rest[1], rest[2]])),
            _ => options = &options[usize::from(rest[0])..],
        }
    }
    None
}

// The fragment of datagram `ip` that carries its data octets `start..end`,
// with Identification `id`.
fn piece(ip: &[u8], id: u32, start: usize, end: usize) -> Vec<u8> {
    let header = header_len(ip);
    let data = &ip[header..];
    let more = end < data.len();
    let mut packet = ip[..header].to_vec();
    if is_ipv6(ip) {
        packet[4..6].copy_from_slice(&((8 + end - start) as u16).to_be_bytes());
        packet[6] = 44;
        packet.extend([ip[6], 0]);
        packet.extend((start as u16 | u16::from(more)).to_be_bytes());
        packet.extend(id.to_be_bytes());
    } else {
        packet[2..4].copy_from_slice(&((header + end - start) as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&(id as u16).to_be_bytes());
        let flags = u16::from(more) << 13 | (start / 8) as u16;
        packet[6..8].copy_from_slice(&flags.to_be_bytes());
        packet[10..12].fill(0);
        let sum = checksum(&packet);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
    }
    packet.extend(&data[start..end]);
    packet
}
// Data octets per fragment of at most `limit` octets.
fn room(ip: &[u8], limit: usize) -> usize {
    let fragment_header = if is_ipv6(ip) { 8 } else { 0 };
    (limit - header_len(ip) - fragment_header) & !7
}
// `ip` in fragments of at most `limit` octets, in order.
fn fragments(ip: &[u8], limit: usize, id: u32) -> Vec<Vec<u8>> {
    let data = ip.len() - header_len(ip);
    let room = room(ip, limit);
    (0..data)
        .step_by(room)
        .map(|start| piece(ip, id, start, (start + room).min(data)))
        .collect()
}

// A router between the peer and the Network under test: it passes the
// peer's datagrams up to LIMIT octets and gives `shape` each longer one,
// numbered from 0, to fragment.
type Shape = fn(usize, &[u8], u32) -> Vec<Vec<u8>>;
fn in_order(_: usize, ip: &[u8], id: u32) -> Vec<Vec<u8>> {
    fragments(ip, LIMIT, id)
}
// The final fragment first, then the final fragment again and one that
// straddles the first two fragments with their octets, then the rest from
// the end, so that fragment zero completes the datagram.
fn rearranged(_: usize, ip: &[u8], id: u32) -> Vec<Vec<u8>> {
    let mut pieces = fragments(ip, LIMIT, id);
    pieces.reverse();
    let (room, data) = (room(ip, LIMIT), ip.len() - header_len(ip));
    let from = (room / 2) & !7;
    let extra = [
        pieces[0].clone(),
        piece(ip, id, from, (from + room).min(data)),
    ];
    pieces.splice(1..1, extra);
    pieces
}
// As `rearranged`, but for the first datagram the straddling fragment's
// last octet, which the second fragment also carries, differs.
fn conflicting(index: usize, ip: &[u8], id: u32) -> Vec<Vec<u8>> {
    let mut pieces = rearranged(index, ip, id);
    if index == 0 {
        *pieces[2].last_mut().unwrap() ^= 0xff;
    }
    pieces
}

struct Lan {
    a: Station,
    b: Station,
    now: u64,
    shape: Shape,
    // Datagrams the router fragmented, and their fragments; when it first
    // fragmented one.
    fragmented: usize,
    pieces: usize,
    fragmented_at: Option<u64>,
    // The MSS the Network under test offered.
    offered: Option<u16>,
}
impl Lan {
    fn new(ipv6: bool, datagrams: usize, shape: Shape) -> Self {
        let (a, b) = addresses(ipv6);
        Self {
            a: Station::new(config(a, 1500, datagrams)),
            b: Station::new(config(b, 1500, 0)),
            now: 0,
            shape,
            fragmented: 0,
            pieces: 0,
            fragmented_at: None,
            offered: None,
        }
    }
    fn step(&mut self) {
        self.now += TICK;
        self.a.network.drive(self.now, BUDGET).unwrap();
        for ip in self.a.sent() {
            self.offered = self.offered.or(tcp(&ip).and_then(mss));
            self.b.incoming.borrow_mut().push_back(ip);
        }
        self.b.network.drive(self.now, BUDGET).unwrap();
        for ip in self.b.sent() {
            if ip.len() <= LIMIT {
                self.a.incoming.borrow_mut().push_back(ip);
                continue;
            }
            let index = self.fragmented;
            self.fragmented += 1;
            self.fragmented_at = self.fragmented_at.or(Some(self.now));
            let pieces = (self.shape)(index, &ip, 0x1000 + index as u32);
            self.pieces += pieces.len();
            self.a.incoming.borrow_mut().extend(pieces);
        }
    }
    // The peer connects to the Network under test and sends it `len`
    // octets; what the Network reads, by `limit`.
    fn transfer(&mut self, len: usize, limit: u64) -> Vec<u8> {
        let listener = self.a.network.listen(LISTEN, 4).unwrap();
        let (to, _) = addresses(self.a.network.config().local_address.is_ipv6());
        let client = self.b.network.connect(SocketAddr::new(to, LISTEN)).unwrap();
        let data = payload(len);
        let (mut sent, mut server, mut received) = (0, None, Vec::new());
        let mut out = [0; 16384];
        while self.now < limit && received.len() < len {
            self.step();
            if server.is_none() {
                server = self.a.network.accept(listener).ok();
            }
            if sent < len
                && let Ok(receipt) =
                    self.b
                        .network
                        .try_write(client, &data[sent..], WriteOptions::default())
            {
                sent += receipt.accepted;
            }
            if let Some(server) = server {
                while let Ok(ReadOutcome::Data { len, .. }) =
                    self.a.network.try_read(server, &mut out)
                {
                    received.extend_from_slice(&out[..len]);
                }
            }
        }
        received
    }
}
fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + i / 251) as u8).collect()
}

#[test]
fn by_default_a_network_reassembles_and_zero_discards_every_fragment() {
    let (a, _) = addresses(false);
    let default = NetworkConfig::new(a, 1500).reassembly_datagrams;
    assert_eq!(default, 64);
    let mut lan = Lan::new(false, default, in_order);
    let received = lan.transfer(16384, 2 * SECOND);
    assert!(received == payload(16384));
    let counters = lan.a.network.reassembly_counters();
    assert_eq!(counters.completed as usize, lan.fragmented);
    assert_eq!(counters.discarded, Default::default());
    // An explicit 0 opts out: every fragment is discarded and counted.
    let mut lan = Lan::new(false, 0, in_order);
    let received = lan.transfer(16384, 2 * SECOND);
    assert!(received.is_empty());
    // The handshake was not fragmented; every data segment was.
    assert!(lan.fragmented > 0);
    let counters = lan.a.network.reassembly_counters();
    assert_eq!(counters.completed + counters.held, 0);
    assert_eq!(counters.discarded.assemblies as usize, lan.pieces);
}

#[test]
fn reassembly_beyond_the_hosts_storage_is_refused() {
    let (a, _) = addresses(false);
    let wire = Wire {
        incoming: Frames::default(),
        outgoing: Frames::default(),
        blocked: Rc::default(),
    };
    let result = Network::new(config(a, 1500, usize::MAX), wire, [5; 32], 0);
    assert!(matches!(result, Err(Error::InvalidConfig(_))));
}

#[test]
fn enabled_reassembly_carries_a_fragmented_stream_in_both_families() {
    for ipv6 in [false, true] {
        let mut lan = Lan::new(ipv6, DATAGRAMS, in_order);
        let received = lan.transfer(65536, 2 * SECOND);
        assert!(received == payload(65536), "ipv6 {ipv6}");
        // The MSS offer still follows the 1500-octet MTU.
        assert_eq!(lan.offered, Some(if ipv6 { 1440 } else { 1460 }));
        let counters = lan.a.network.reassembly_counters();
        assert_eq!(counters.completed as usize, lan.fragmented, "ipv6 {ipv6}");
        assert_eq!(counters.duplicates, 0);
        assert_eq!(counters.discarded, Default::default());
        assert_eq!(lan.a.network.counters().discarded, 0);
    }
}

#[test]
fn reordered_duplicate_and_overlapping_fragments_complete_each_datagram_once() {
    let mut lan = Lan::new(false, DATAGRAMS, rearranged);
    let received = lan.transfer(65536, 2 * SECOND);
    assert!(received == payload(65536));
    let counters = lan.a.network.reassembly_counters();
    assert!(lan.fragmented > 0);
    assert_eq!(counters.completed as usize, lan.fragmented);
    assert_eq!(counters.duplicates as usize, lan.fragmented);
    assert_eq!(counters.discarded, Default::default());
}

// Octets that differ where fragments overlap discard the datagram; TCP
// sends the segment again. The fragment that arrives after the discard
// starts an assembly that never completes and expires at the IPv4
// timeout, 30 seconds after it arrived.
#[test]
fn a_conflicting_overlap_discards_its_datagram_and_tcp_recovers_it() {
    let mut lan = Lan::new(false, DATAGRAMS, conflicting);
    let received = lan.transfer(65536, 10 * SECOND);
    assert!(received == payload(65536));
    let counters = lan.a.network.reassembly_counters();
    assert_eq!(counters.discarded.conflict, 1);
    assert_eq!(counters.completed as usize, lan.fragmented - 1);
    assert_eq!(counters.expired, 0);
    // The stray fragment arrived after the router first fragmented and
    // before the transfer ended.
    let (first, end) = (lan.fragmented_at.unwrap(), lan.now);
    lan.now = first + 30 * SECOND - TICK;
    lan.step();
    assert_eq!(lan.a.network.reassembly_counters().expired, 0);
    lan.now = end + 30 * SECOND - TICK;
    lan.step();
    assert_eq!(lan.a.network.reassembly_counters().expired, 1);
}

// A TCP segment from `port` to LISTEN with `flags` and the sequence and
// acknowledgment numbers `numbers`, in a datagram of `len` octets; its
// payload octets count up from 0.
fn segment(
    (source, destination): (IpAddr, IpAddr),
    port: u16,
    numbers: (u32, u32),
    flags: u8,
    len: usize,
) -> Vec<u8> {
    let header = if source.is_ipv6() { 40 } else { 20 };
    let mut segment = vec![0; len - header];
    segment[0..2].copy_from_slice(&port.to_be_bytes());
    segment[2..4].copy_from_slice(&LISTEN.to_be_bytes());
    segment[4..8].copy_from_slice(&numbers.0.to_be_bytes());
    segment[8..12].copy_from_slice(&numbers.1.to_be_bytes());
    segment[12] = 5 << 4;
    segment[13] = flags;
    segment[14..16].copy_from_slice(&65535u16.to_be_bytes());
    for (i, octet) in segment[20..].iter_mut().enumerate() {
        *octet = i as u8;
    }
    let (mut ip, mut pseudo) = (Vec::new(), Vec::new());
    match (source, destination) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            ip.extend([0x45, 0]);
            ip.extend((len as u16).to_be_bytes());
            ip.extend([0, 0, 0, 0, 64, 6, 0, 0]);
            ip.extend(s.octets());
            ip.extend(d.octets());
            let sum = checksum(&ip);
            ip[10..12].copy_from_slice(&sum.to_be_bytes());
            pseudo.extend(s.octets());
            pseudo.extend(d.octets());
            pseudo.extend([0, 6]);
            pseudo.extend((segment.len() as u16).to_be_bytes());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            ip.extend([0x60, 0, 0, 0]);
            ip.extend((segment.len() as u16).to_be_bytes());
            ip.extend([6, 64]);
            ip.extend(s.octets());
            ip.extend(d.octets());
            pseudo.extend(s.octets());
            pseudo.extend(d.octets());
            pseudo.extend((segment.len() as u32).to_be_bytes());
            pseudo.extend([0, 0, 0, 6]);
        }
        _ => unreachable!(),
    }
    pseudo.extend(&segment);
    let sum = checksum(&pseudo);
    segment[16..18].copy_from_slice(&sum.to_be_bytes());
    ip.extend(segment);
    ip
}
const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
// A SYN from `port`, sequence number 0, in a datagram of `len` octets.
fn syn(source: IpAddr, destination: IpAddr, port: u16, len: usize) -> Vec<u8> {
    segment((source, destination), port, (0, 0), SYN, len)
}
// The sequence number of the Network's SYN-ACK to a SYN from `port`.
fn syn_ack(sent: &[Vec<u8>], port: u16) -> Option<u32> {
    sent.iter().filter_map(|ip| tcp(ip)).find_map(|segment| {
        (segment[2..4] == port.to_be_bytes() && segment[13] & (SYN | ACK) == SYN | ACK)
            .then(|| u32::from_be_bytes(segment[4..8].try_into().unwrap()))
    })
}
fn answered(sent: &[Vec<u8>], port: u16) -> bool {
    syn_ack(sent, port).is_some()
}
// The Network takes in each datagram, in fragments of at most `limit`
// octets, over drives from `now` on; what it sent.
fn offer(
    station: &mut Station,
    now: &mut u64,
    datagrams: &[Vec<u8>],
    limit: usize,
) -> Vec<Vec<u8>> {
    for ip in datagrams {
        let pieces = fragments(ip, limit, station.next_id);
        station.next_id += 1;
        station.incoming.borrow_mut().extend(pieces);
    }
    for _ in 0..10 {
        *now += TICK;
        station.network.drive(*now, BUDGET).unwrap();
    }
    station.sent()
}

#[test]
fn a_datagram_above_the_reassembly_capacity_is_discarded_and_counted() {
    let (a, b) = addresses(false);
    let mut station = Station::new(config(a, 1500, DATAGRAMS));
    station.network.listen(LISTEN, 4).unwrap();
    let datagrams = [syn(b, a, 40000, 1500), syn(b, a, 40001, 1501)];
    let sent = offer(&mut station, &mut 0, &datagrams, LIMIT);
    assert!(answered(&sent, 40000));
    assert!(!answered(&sent, 40001));
    let counters = station.network.reassembly_counters();
    assert_eq!(counters.completed, 1);
    // Only the final fragment of the longer one reaches beyond 1500
    // octets; the two before it wait for the timeout.
    assert_eq!(counters.discarded.capacity, 1);
    assert_eq!(counters.held, 2 + 2);
}

// RFC 8200 section 5: a 1500-octet packet reassembles on a link of the
// 1280-octet minimum MTU, so the Network's receive buffers hold more than
// its MTU.
#[test]
fn an_ipv6_network_on_a_minimum_mtu_link_reassembles_1500_octet_packets() {
    let (a, b) = addresses(true);
    for datagrams in [0, 1] {
        let mut station = Station::new(config(a, 1280, datagrams));
        station.network.listen(LISTEN, 4).unwrap();
        let sent = offer(&mut station, &mut 0, &[syn(b, a, 40000, 1500)], 1280);
        assert_eq!(answered(&sent, 40000), datagrams != 0);
        let counters = station.network.reassembly_counters();
        assert_eq!(counters.completed, u64::from(datagrams != 0));
    }
}

// A segment for a connection whose output waits for the backend is retained
// until the output leaves, a reassembled one longer than the MTU included:
// whether it is taken in does not depend on the backend's backpressure.
#[test]
fn a_reassembled_segment_longer_than_the_mtu_is_retained_under_backpressure() {
    let (a, b) = addresses(true);
    let mut station = Station::new(config(a, 1280, 1));
    let listener = station.network.listen(LISTEN, 4).unwrap();
    let mut now = 0;
    let sent = offer(&mut station, &mut now, &[syn(b, a, 40000, 60)], 1280);
    let isn = syn_ack(&sent, 40000).unwrap();
    let numbers = (1, isn.wrapping_add(1));
    let ack = segment((b, a), 40000, numbers, ACK, 60);
    offer(&mut station, &mut now, &[ack], 1280);
    let server = station.network.accept(listener).unwrap();
    station.network.backend().blocked.set(true);
    let reply = [7; 5];
    station
        .network
        .try_write(server, &reply, WriteOptions::default())
        .unwrap();
    offer(&mut station, &mut now, &[], 1280);
    assert!(matches!(
        station
            .network
            .try_write(server, &reply, WriteOptions::default()),
        Err(Error::WouldBlock(BlockReason::OutputReserved))
    ));
    let data = segment((b, a), 40000, numbers, ACK, 1500);
    offer(&mut station, &mut now, &[data], 1280);
    assert_eq!(station.network.counters().retained_input, 1);
    station.network.backend().blocked.set(false);
    offer(&mut station, &mut now, &[], 1280);
    assert_eq!(station.network.counters().retained_input, 0);
    let mut out = [0; 2048];
    let Ok(ReadOutcome::Data { len, .. }) = station.network.try_read(server, &mut out) else {
        panic!("no data from the retained segment");
    };
    assert_eq!(len, 1440);
    assert!(out[..len].iter().enumerate().all(|(i, &o)| o == i as u8));
}

// Under Hash a member reassembles for every member's flows; joining with a
// reassembly capacity other than the joined members' fails, and the group
// takes any once it is empty. By address each member reassembles its own.
#[test]
fn members_of_hashed_shared_flows_reassemble_alike() {
    let limits = SharedFlowLimits {
        members: 4,
        inbox_packets: 4,
        packet_bytes: 1500,
        redirected_flows: 4,
        ..SharedFlowLimits::default()
    };
    let address = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1));
    let join = |flows: &SharedFlows, member, config: NetworkConfig| {
        let wire = Wire {
            incoming: Frames::default(),
            outgoing: Frames::default(),
            blocked: Rc::default(),
        };
        Network::with_shared_flows(config, wire, [5; 32], 0, None, flows, member)
    };
    let refused = |result: Result<Network<Wire>>| matches!(result, Err(Error::InvalidConfig(_)));
    let hash = FlowOwnership::Hash {
        key: DEFAULT_FLOW_KEY.to_vec(),
        table: vec![0, 1, 2, 3],
    };
    let flows = SharedFlows::new(hash, limits).unwrap();
    let first = join(&flows, 0, config(address, 1500, DATAGRAMS)).unwrap();
    assert!(refused(join(&flows, 1, config(address, 1500, 0))));
    assert!(refused(join(&flows, 1, config(address, 1400, DATAGRAMS))));
    // The count of datagrams may differ, as may an MTU below the IPv4
    // minimum the capacity is raised to.
    let second = join(&flows, 1, config(address, 1500, 2 * DATAGRAMS)).unwrap();
    drop((first, second));
    let small = join(&flows, 2, config(address, 400, 1)).unwrap();
    assert!(join(&flows, 3, config(address, 500, DATAGRAMS)).is_ok());
    assert!(refused(join(&flows, 0, config(address, 1500, DATAGRAMS))));
    drop(small);
    let flows = SharedFlows::new(FlowOwnership::ByAddress, limits).unwrap();
    let other = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 2));
    let _a = join(&flows, 0, config(address, 1500, DATAGRAMS)).unwrap();
    assert!(join(&flows, 1, config(other, 1400, 0)).is_ok());
}
