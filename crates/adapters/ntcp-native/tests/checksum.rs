// Checksums of received and sent packets: the IPv4 header checksum is
// verified once per arriving packet, the TCP checksum once per segment, in
// software unless the receiving device verified it over exactly the bytes
// that reach TCP, and what each refuses is counted as Linux counts it (Ip
// InHdrErrors, Tcp InCsumErrors).
use ntcp_io::{PacketIo, PacketLayer, ReceivedPacket, RxChecksum, TxOutcome};
use ntcp_native::*;
use std::{
    cell::RefCell,
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    rc::Rc,
};

const TICK: u64 = 100;
const BUDGET: WorkBudget = WorkBudget::new(32, 32, 32, 32);
const LISTEN: u16 = 80;

// Packets with the device's verdict on their TCP checksum.
type Frames = Rc<RefCell<VecDeque<(Vec<u8>, RxChecksum)>>>;

// An L3 link end, whose device completes TCP checksums when `offload` is
// set (counting each such frame in `offloaded`).
struct Wire {
    incoming: Frames,
    outgoing: Frames,
    offload: bool,
    offloaded: Rc<RefCell<usize>>,
}
impl PacketIo for Wire {
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn max_packet_len(&self) -> Option<usize> {
        Some(65535)
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        Ok(self.receive_with_metadata(out)?.map(|p| p.len))
    }
    fn receive_with_metadata(&mut self, out: &mut [u8]) -> io::Result<Option<ReceivedPacket>> {
        let Some((packet, l4_checksum)) = self.incoming.borrow_mut().pop_front() else {
            return Ok(None);
        };
        out[..packet.len()].copy_from_slice(&packet);
        Ok(Some(ReceivedPacket {
            len: packet.len(),
            timestamps: Default::default(),
            tcp_segment_size: None,
            l4_checksum,
        }))
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        let sent = (packet.to_vec(), RxChecksum::Unknown);
        self.outgoing.borrow_mut().push_back(sent);
        Ok(TxOutcome::Submitted)
    }
    fn tcp_checksum_offload(&self) -> bool {
        self.offload
    }
    fn transmit_tcp_checksum_offload(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        assert!(self.offload);
        *self.offloaded.borrow_mut() += 1;
        let mut packet = packet.to_vec();
        complete_checksum(&mut packet);
        self.outgoing
            .borrow_mut()
            .push_back((packet, RxChecksum::Unknown));
        Ok(TxOutcome::Submitted)
    }
}

// What a device does for an IPv4 TCP packet whose checksum field holds the
// pseudo-header sum: the one's complement of the sum of the segment, that
// field included, written over it.
fn complete_checksum(packet: &mut [u8]) {
    assert_eq!((packet[0] >> 4, packet[9]), (4, 6));
    let header = usize::from(packet[0] & 15) * 4;
    let len = packet.len() - header;
    let mut pseudo = packet[12..20].to_vec();
    pseudo.extend([0, 6]);
    pseudo.extend((len as u16).to_be_bytes());
    let tcp = &mut packet[header..];
    assert_eq!(tcp[16..18], (!checksum(&pseudo)).to_be_bytes());
    let sum = checksum(tcp);
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
}

struct Station {
    network: Network<Wire>,
    incoming: Frames,
    outgoing: Frames,
}
fn config(address: IpAddr) -> NetworkConfig {
    let mut config = NetworkConfig::new(address, 1500);
    config.tcp.max_connections = 8;
    config.tcp.max_listeners = 1;
    config
}
impl Station {
    fn new(address: IpAddr) -> Self {
        Self::build(|wire| Network::new(config(address), wire, [5; 32], 0))
    }
    fn build(make: impl FnOnce(Wire) -> Result<Network<Wire>>) -> Self {
        Self::build_offload(false, make)
    }
    fn build_offload(offload: bool, make: impl FnOnce(Wire) -> Result<Network<Wire>>) -> Self {
        let (incoming, outgoing) = (Frames::default(), Frames::default());
        let wire = Wire {
            incoming: incoming.clone(),
            outgoing: outgoing.clone(),
            offload,
            offloaded: Rc::default(),
        };
        Self {
            network: make(wire).unwrap(),
            incoming,
            outgoing,
        }
    }
    fn sent(&self) -> Vec<Vec<u8>> {
        self.outgoing
            .borrow_mut()
            .drain(..)
            .map(|(p, _)| p)
            .collect()
    }
}

fn step(a: &mut Station, b: &mut Station, now: &mut u64) {
    *now += TICK;
    a.network.drive(*now, BUDGET).unwrap();
    let sent: Vec<_> = a.outgoing.borrow_mut().drain(..).collect();
    b.incoming.borrow_mut().extend(sent);
    b.network.drive(*now, BUDGET).unwrap();
    let sent: Vec<_> = b.outgoing.borrow_mut().drain(..).collect();
    a.incoming.borrow_mut().extend(sent);
}

// The peer (`b`) and the Network under test (`a`), connected; the test
// delivers the peer's packets itself.
struct Lan {
    a: Station,
    b: Station,
    now: u64,
    server: ConnId,
    client: ConnId,
}
impl Lan {
    fn new() -> Self {
        let mut a = Station::new("10.9.0.1".parse().unwrap());
        let mut b = Station::new("10.9.0.2".parse().unwrap());
        let listener = a.network.listen(LISTEN, 4).unwrap();
        let to = SocketAddr::new("10.9.0.1".parse().unwrap(), LISTEN);
        let client = b.network.connect(to).unwrap();
        let mut now = 0;
        for _ in 0..32 {
            step(&mut a, &mut b, &mut now);
        }
        let server = a.network.accept(listener).unwrap();
        // Each write leaves at once, whatever is unacknowledged.
        b.network.set_nodelay(client, true).unwrap();
        Self {
            a,
            b,
            now,
            server,
            client,
        }
    }
    // The next data packet the peer sends, carrying `data`, held back.
    fn peer_data(&mut self, data: &[u8]) -> Vec<u8> {
        self.b
            .network
            .try_write(self.client, data, WriteOptions::default())
            .unwrap();
        self.now += TICK;
        self.b.network.drive(self.now, BUDGET).unwrap();
        let mut sent = self.b.sent();
        assert_eq!(sent.len(), 1);
        sent.pop().unwrap()
    }
    // What the Network under test reads after `packet` arrives.
    fn deliver(&mut self, packet: &[u8]) -> Vec<u8> {
        self.deliver_as(packet, RxChecksum::Unknown)
    }
    // `deliver`, with the device's verdict `l4`.
    fn deliver_as(&mut self, packet: &[u8], l4: RxChecksum) -> Vec<u8> {
        self.deliver_all(&[packet.to_vec()], l4)
    }
    fn deliver_all(&mut self, packets: &[Vec<u8>], l4: RxChecksum) -> Vec<u8> {
        let queued = packets.iter().map(|p| (p.clone(), l4));
        self.a.incoming.borrow_mut().extend(queued);
        self.now += TICK;
        self.a.network.drive(self.now, BUDGET).unwrap();
        self.a.outgoing.borrow_mut().clear();
        let mut out = [0; 4096];
        match self.a.network.try_read(self.server, &mut out) {
            Ok(ReadOutcome::Data { len, .. }) => out[..len].to_vec(),
            _ => Vec::new(),
        }
    }
}

// A TCP checksum error discards the segment and counts it in Linux's Tcp
// InCsumErrors (and in discarded); an IPv4 header error, a bad header
// checksum included, in Ip InHdrErrors. The segment sent again arrives.
#[test]
fn checksum_and_header_errors_are_counted_as_linux_counts_them() {
    let mut lan = Lan::new();
    let before = lan.a.network.counters();
    assert_eq!(
        (before.tcp_checksum_errors, before.ip_header_errors),
        (0, 0)
    );
    let packet = lan.peer_data(b"request");
    let mut corrupt = packet.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(lan.deliver(&corrupt).is_empty());
    let mut header = packet.clone();
    header[8] ^= 1;
    assert!(lan.deliver(&header).is_empty());
    let counters = lan.a.network.counters();
    assert_eq!(
        (counters.tcp_checksum_errors, counters.ip_header_errors),
        (1, 1)
    );
    assert_eq!(counters.discarded, before.discarded + 2);
    assert_eq!(lan.deliver(&packet), b"request");
    let counters = lan.a.network.counters();
    assert_eq!(
        (counters.tcp_checksum_errors, counters.ip_header_errors),
        (1, 1)
    );
}

// The IPv4 packet `packet` with a TCP payload octet flipped: its TCP
// checksum fails, its header is intact.
fn corrupt_tcp(packet: &[u8]) -> Vec<u8> {
    let mut corrupt = packet.to_vec();
    *corrupt.last_mut().unwrap() ^= 1;
    corrupt
}

// The device's verdict on the TCP checksum: Good is trusted, as Linux trusts
// CHECKSUM_UNNECESSARY, so a frame the device verified is not verified again
// (shown with a corrupt one the test claims good). Bad and Unknown are
// verified in software: a corrupt frame is dropped and counted, a good one
// taken in, as Linux hands a packet the device found bad up as
// CHECKSUM_NONE. The IPv4 header checksum is verified whatever the verdict.
#[test]
fn only_a_good_device_verdict_spares_the_tcp_checksum() {
    let mut lan = Lan::new();
    let good = lan.peer_data(b"first");
    assert_eq!(
        lan.deliver_as(&corrupt_tcp(&good), RxChecksum::Good),
        b"firsu"
    );
    assert_eq!(lan.a.network.counters().tcp_checksum_errors, 0);
    for (l4, errors) in [(RxChecksum::Bad, 1), (RxChecksum::Unknown, 2)] {
        let packet = lan.peer_data(b"again");
        assert!(lan.deliver_as(&corrupt_tcp(&packet), l4).is_empty());
        assert_eq!(lan.a.network.counters().tcp_checksum_errors, errors);
        assert_eq!(lan.deliver_as(&packet, l4), b"again");
    }
    let packet = lan.peer_data(b"header");
    let mut header = packet.clone();
    header[8] ^= 1;
    assert!(lan.deliver_as(&header, RxChecksum::Good).is_empty());
    let counters = lan.a.network.counters();
    assert_eq!(
        (counters.tcp_checksum_errors, counters.ip_header_errors),
        (2, 1)
    );
    assert_eq!(lan.deliver_as(&packet, RxChecksum::Good), b"header");
}

// The fragments of IPv4 packet `packet` with `room` data octets each.
fn fragments(packet: &[u8], room: usize, id: u16) -> Vec<Vec<u8>> {
    let header = usize::from(packet[0] & 15) * 4;
    let data = &packet[header..];
    (0..data.len())
        .step_by(room)
        .map(|start| {
            let end = (start + room).min(data.len());
            let mut piece = packet[..header].to_vec();
            piece[2..4].copy_from_slice(&((header + end - start) as u16).to_be_bytes());
            piece[4..6].copy_from_slice(&id.to_be_bytes());
            let flags = u16::from(end < data.len()) << 13 | (start / 8) as u16;
            piece[6..8].copy_from_slice(&flags.to_be_bytes());
            piece[10..12].fill(0);
            let sum = checksum(&piece);
            piece[10..12].copy_from_slice(&sum.to_be_bytes());
            piece.extend(&data[start..end]);
            piece
        })
        .collect()
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

// A device's verdict is about the packet that arrived: a datagram
// reassembled from fragments it found good is verified in software.
#[test]
fn a_reassembled_segment_is_verified_in_software() {
    let mut lan = Lan::new();
    let packet = lan.peer_data(&[3; 600]);
    let pieces = fragments(&corrupt_tcp(&packet), 256, 7);
    assert_eq!(pieces.len(), 3);
    assert!(lan.deliver_all(&pieces, RxChecksum::Good).is_empty());
    assert_eq!(lan.a.network.counters().tcp_checksum_errors, 1);
    let pieces = fragments(&packet, 256, 8);
    assert_eq!(lan.deliver_all(&pieces, RxChecksum::Good), [3; 600]);
    assert_eq!(lan.a.network.reassembly_counters().completed, 2);
}

// A packet one member of shared flows receives for another member's flow
// reaches its owner without the receiving device's verdict, which stays
// with the queue that received it: the owner verifies it in software.
#[test]
fn a_handed_over_segment_is_verified_in_software() {
    const ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);
    let limits = SharedFlowLimits {
        members: 2,
        inbox_packets: 16,
        packet_bytes: 1500,
        redirected_flows: 4,
        ..SharedFlowLimits::default()
    };
    let ownership = FlowOwnership::Hash {
        key: DEFAULT_FLOW_KEY.to_vec(),
        table: (0..128).map(|i| i % 2).collect(),
    };
    let flows = SharedFlows::new(ownership, limits).unwrap();
    let mut members: Vec<_> = (0..2)
        .map(|k| {
            Station::build(|wire| {
                let config = config(IpAddr::V4(ADDRESS));
                Network::with_shared_flows(config, wire, [5; 32], 0, None, &flows, k)
            })
        })
        .collect();
    let listener = members[1].network.listen(LISTEN, 4).unwrap();
    members[0].network.listen(LISTEN, 4).unwrap();
    const PEER: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 2);
    let mut peer = Station::new(IpAddr::V4(PEER));
    let to = SocketAddr::new(IpAddr::V4(ADDRESS), LISTEN);
    let mut now = 0;
    // Every packet from the peer arrives at member 0's queue; a connection
    // whose flow member 1 owns has each of them handed over.
    let run = |members: &mut [Station], peer: &mut Station, now: &mut u64| {
        for _ in 0..32 {
            *now += TICK;
            for member in members.iter_mut() {
                member.network.drive(*now, BUDGET).unwrap();
                peer.incoming
                    .borrow_mut()
                    .extend(member.sent().into_iter().map(|p| (p, RxChecksum::Unknown)));
            }
            peer.network.drive(*now, BUDGET).unwrap();
            let sent = peer.sent().into_iter().map(|p| (p, RxChecksum::Good));
            members[0].incoming.borrow_mut().extend(sent);
        }
    };
    let local = SocketAddrV4::new(ADDRESS, LISTEN);
    let port = (40000..)
        .find(|&p| flows.owner(local, SocketAddrV4::new(PEER, p)) == Some(1))
        .unwrap();
    let client = peer.network.connect_from(to, Some(port)).unwrap();
    run(&mut members, &mut peer, &mut now);
    members[1].network.accept(listener).unwrap();
    peer.network
        .try_write(client, b"handed", WriteOptions::default())
        .unwrap();
    now += TICK;
    peer.network.drive(now, BUDGET).unwrap();
    let mut sent = peer.sent();
    assert_eq!(sent.len(), 1);
    let packet = sent.pop().unwrap();
    members[0]
        .incoming
        .borrow_mut()
        .push_back((corrupt_tcp(&packet), RxChecksum::Good));
    for member in &mut members {
        now += TICK;
        member.network.drive(now, BUDGET).unwrap();
        member.sent();
    }
    let (sender, owner) = (members[0].network.counters(), members[1].network.counters());
    assert_eq!(sender.handed_off, owner.handoffs_received);
    assert_eq!(owner.tcp_checksum_errors, 1);
    assert_eq!(sender.tcp_checksum_errors, 0);
}

// Every packet of a connection's life that the Network under test sends,
// the TCP checksums left to its device when `offload` is set; and how many
// left that way.
fn exchange(offload: bool) -> (Vec<Vec<u8>>, usize) {
    let address = "10.9.0.1".parse().unwrap();
    let mut a = Station::build_offload(offload, |wire| {
        Network::new(config(address), wire, [5; 32], 0)
    });
    let mut b = Station::new("10.9.0.2".parse().unwrap());
    assert_eq!(
        a.network.config().tcp.connection.tcp_checksum_offload,
        offload
    );
    let listener = b.network.listen(LISTEN, 4).unwrap();
    let client = a
        .network
        .connect(SocketAddr::new("10.9.0.2".parse().unwrap(), LISTEN))
        .unwrap();
    let (mut now, mut server, mut sent) = (0, None, Vec::new());
    let data = vec![7; 60_000];
    let mut written = 0;
    let mut out = [0; 4096];
    for round in 0..400 {
        now += TICK;
        if written < data.len()
            && let Ok(receipt) =
                a.network
                    .try_write(client, &data[written..], WriteOptions::default())
        {
            written += receipt.accepted;
        }
        if round == 300 {
            a.network.close(client).unwrap();
        }
        a.network.drive(now, BUDGET).unwrap();
        let frames = a.sent();
        sent.extend(frames.iter().cloned());
        b.incoming
            .borrow_mut()
            .extend(frames.into_iter().map(|p| (p, RxChecksum::Unknown)));
        b.network.drive(now, BUDGET).unwrap();
        let back = b.sent().into_iter().map(|p| (p, RxChecksum::Unknown));
        a.incoming.borrow_mut().extend(back);
        server = server.or_else(|| b.network.accept(listener).ok());
        if let Some(server) = server {
            while let Ok(ReadOutcome::Data { .. }) = b.network.try_read(server, &mut out) {}
        }
    }
    assert_eq!(written, data.len());
    assert_eq!(b.network.counters().tcp_checksum_errors, 0);
    let offloaded = *a.network.backend().offloaded.borrow();
    (sent, offloaded)
}

// A backend that completes TCP checksums is handed every segment with the
// pseudo-header sum in its checksum field (checked by the device model),
// and what leaves the device is exactly what a Network computing them in
// software sends; a backend without the capability gets software
// checksums through `transmit`.
#[test]
fn offloaded_tcp_checksums_leave_as_software_computes_them() {
    let (software, none) = exchange(false);
    let (offloaded, count) = exchange(true);
    assert_eq!(none, 0);
    assert_eq!(count, offloaded.len());
    assert!(software.len() > 40, "{}", software.len());
    assert!(software == offloaded);
}
