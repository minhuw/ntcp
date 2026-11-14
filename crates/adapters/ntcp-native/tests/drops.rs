// Discards by reason (`Counters::drops`, Linux's skb_drop_reason) for what
// the driver and the Host refuse, their sum `Counters::discarded`, and the
// opt-in per-discard feed (`Network::set_drop_feed`), as dropwatch reads
// drop_monitor's.
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::*;
use std::{
    cell::RefCell,
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr},
    rc::Rc,
};

const BUDGET: WorkBudget = WorkBudget::new(32, 32, 32, 32);
const LOCAL: [u8; 4] = [192, 0, 2, 2];
const REMOTE: [u8; 4] = [192, 0, 2, 1];
const MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];

// What a backend hands over next: a frame, or an error for one it could
// not deliver.
type Frames = Rc<RefCell<VecDeque<std::result::Result<Vec<u8>, io::ErrorKind>>>>;

struct Wire {
    layer: PacketLayer,
    incoming: Frames,
}
impl PacketIo for Wire {
    fn layer(&self) -> PacketLayer {
        self.layer
    }
    fn max_packet_len(&self) -> Option<usize> {
        Some(65535)
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        match self.incoming.borrow_mut().pop_front() {
            None => Ok(None),
            Some(Err(kind)) => Err(kind.into()),
            Some(Ok(frame)) => {
                out[..frame.len()].copy_from_slice(&frame);
                Ok(Some(frame.len()))
            }
        }
    }
    fn transmit(&mut self, _: &[u8]) -> io::Result<TxOutcome> {
        Ok(TxOutcome::Submitted)
    }
}

struct Station {
    network: Network<Wire>,
    incoming: Frames,
    now: u64,
}
impl Station {
    fn new(layer: PacketLayer) -> Self {
        let mut config = NetworkConfig::new(IpAddr::V4(Ipv4Addr::from(LOCAL)), 1500);
        config.tcp.max_connections = 4;
        config.tcp.max_listeners = 1;
        if layer == PacketLayer::Ethernet {
            config.link = Link::Ethernet {
                local_mac: MAC,
                next_hop: EthernetNextHop::Arp {
                    prefix_len: 24,
                    gateway: None,
                },
            };
        }
        let incoming = Frames::default();
        let wire = Wire {
            layer,
            incoming: incoming.clone(),
        };
        Self {
            network: Network::new(config, wire, [5; 32], 0).unwrap(),
            incoming,
            now: 0,
        }
    }
    // The reasons the Network recorded for `frames`, once per discard, after
    // checking that `discarded` and the drive's report count them all.
    fn take(
        &mut self,
        frames: Vec<std::result::Result<Vec<u8>, io::ErrorKind>>,
    ) -> Vec<DropReason> {
        let before = self.network.counters();
        self.incoming.borrow_mut().extend(frames);
        self.now += 100;
        let report = self.network.drive(self.now, BUDGET).unwrap();
        let after = self.network.counters();
        assert_eq!(after.discarded, after.drops.total());
        assert_eq!(report.discarded as u64, after.discarded - before.discarded);
        DropReason::ALL
            .iter()
            .flat_map(|&r| std::iter::repeat_n(r, (after.drops[r] - before.drops[r]) as usize))
            .collect()
    }
    fn ip(&mut self, packet: Vec<u8>) -> Vec<DropReason> {
        self.take(vec![Ok(packet)])
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// An IPv4 packet, its header checksum filled in. `fragment`: the flags and
// offset field.
fn ipv4_with(
    source: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    fragment: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0x45, 0, 0, 0, 0, 7, 0, 0, 64, protocol, 0, 0];
    packet[2..4].copy_from_slice(&(20 + payload.len() as u16).to_be_bytes());
    packet[6..8].copy_from_slice(&fragment.to_be_bytes());
    packet.extend(source);
    packet.extend(destination);
    let sum = checksum(&packet);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet.extend(payload);
    packet
}

fn ipv4(protocol: u8, payload: &[u8]) -> Vec<u8> {
    ipv4_with(REMOTE, LOCAL, protocol, 0x4000, payload)
}

// A TCP or UDP header and payload, its checksum filled in at `at`.
fn transport(protocol: u8, mut segment: Vec<u8>, at: usize) -> Vec<u8> {
    let mut pseudo = REMOTE.to_vec();
    pseudo.extend(LOCAL);
    pseudo.extend([0, protocol]);
    pseudo.extend((segment.len() as u16).to_be_bytes());
    pseudo.extend(&segment);
    let sum = checksum(&pseudo);
    segment[at..at + 2].copy_from_slice(&sum.to_be_bytes());
    segment
}

fn udp(destination: u16, payload: &[u8]) -> Vec<u8> {
    let mut segment = vec![0x9c, 0x40, 0, 0, 0, 0, 0, 0];
    segment[2..4].copy_from_slice(&destination.to_be_bytes());
    segment[4..6].copy_from_slice(&(8 + payload.len() as u16).to_be_bytes());
    segment.extend(payload);
    transport(17, segment, 6)
}

// A SYN from the remote end to `port`.
fn syn(port: u16) -> Vec<u8> {
    let mut segment = vec![
        0x9c, 0x40, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0x10, 0, 0, 0, 0, 0,
    ];
    segment[2..4].copy_from_slice(&port.to_be_bytes());
    transport(6, segment, 16)
}

// An ICMP message of `kind` (type, code) quoting a TCP segment this host
// could have sent to the remote end.
fn icmp(kind: (u8, u8)) -> Vec<u8> {
    let mut message = vec![kind.0, kind.1, 0, 0, 0, 0, 0, 0];
    let mut tcp = [0; 20];
    tcp[..8].copy_from_slice(&[0, 80, 0x9c, 0x40, 0, 0, 0, 1]);
    let quoted = ipv4_with(LOCAL, REMOTE, 6, 0x4000, &tcp);
    message.extend(&quoted[..28]);
    let sum = checksum(&message);
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    message
}

fn ethernet(destination: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = destination.to_vec();
    frame.extend([2, 0, 0, 0, 0, 1]);
    frame.extend(ethertype.to_be_bytes());
    frame.extend(payload);
    frame.resize(frame.len().max(60), 0);
    frame
}

#[test]
fn the_backend_and_the_ip_layer() {
    let mut s = Station::new(PacketLayer::Ip);
    assert_eq!(
        s.take(vec![Err(io::ErrorKind::InvalidData)]),
        [DropReason::DevHdr]
    );
    let mut bad = ipv4(17, &udp(9, b"x"));
    bad[10] ^= 0xff;
    assert_eq!(s.ip(bad), [DropReason::IpCsum]);
    assert_eq!(
        s.ip(ipv4(17, &[])[..12].to_vec()),
        [DropReason::PktTooSmall]
    );
    assert_eq!(s.network.counters().ip_header_errors, 2);
    let elsewhere = ipv4_with(REMOTE, [192, 0, 2, 99], 17, 0x4000, &udp(9, b"x"));
    assert_eq!(s.ip(elsewhere), [DropReason::IpInaddrerrors]);
    assert_eq!(s.ip(ipv4(99, b"payload")), [DropReason::IpNoproto]);
}

#[test]
fn udp_and_tcp_without_a_socket() {
    let mut s = Station::new(PacketLayer::Ip);
    assert_eq!(s.ip(ipv4(17, &udp(9, b"x"))), [DropReason::NoSocket]);
    let mut bad = udp(9, b"x");
    bad[8] ^= 1;
    assert_eq!(s.ip(ipv4(17, &bad)), [DropReason::UdpCsum]);
    assert_eq!(s.ip(ipv4(6, &syn(9))), [DropReason::NoSocket]);
    let mut bad = syn(9);
    bad[16] ^= 1;
    assert_eq!(s.ip(ipv4(6, &bad)), [DropReason::TcpCsum]);
    assert_eq!(s.network.counters().tcp_checksum_errors, 1);
}

#[test]
fn icmp_messages_acted_on_by_nothing() {
    let mut s = Station::new(PacketLayer::Ip);
    assert_eq!(s.ip(ipv4(1, &icmp((4, 0)))), [DropReason::IcmpSourceQuench]);
    assert_eq!(s.ip(ipv4(1, &icmp((3, 1)))), [DropReason::IcmpNoSocket]);
    let mut bad = icmp((3, 1));
    bad[2] ^= 1;
    assert_eq!(s.ip(ipv4(1, &bad)), [DropReason::IcmpCsum]);
    // A quote of a TCP segment without ports.
    let mut portless = icmp((3, 1));
    portless[28..32].fill(0);
    portless[2..4].fill(0);
    let sum = checksum(&portless);
    portless[2..4].copy_from_slice(&sum.to_be_bytes());
    assert_eq!(s.ip(ipv4(1, &portless)), [DropReason::IcmpInvalid]);
}

#[test]
fn fragments_duplicated_invalid_and_timed_out() {
    let mut s = Station::new(PacketLayer::Ip);
    let datagram = udp(9, &[3; 64]);
    // The first 16 octets, more to come.
    let first = ipv4_with(REMOTE, LOCAL, 17, 0x2000, &datagram[..16]);
    assert_eq!(s.ip(first.clone()), []);
    assert_eq!(s.ip(first), [DropReason::DupFrag]);
    // A non-final fragment whose data is not a multiple of eight octets.
    let ragged = ipv4_with(REMOTE, LOCAL, 17, 0x2000 | 4, &datagram[32..39]);
    assert_eq!(s.ip(ragged), [DropReason::FragInvalid]);
    // The held fragment goes with its assembly at the reassembly timeout.
    s.now += 61_000_000;
    assert_eq!(s.take(Vec::new()), [DropReason::FragReasmTimeout]);
}

#[test]
fn the_link_layer() {
    let mut s = Station::new(PacketLayer::Ethernet);
    let packet = ipv4(17, &udp(9, b"x"));
    assert_eq!(
        s.take(vec![Ok(ethernet([2, 0, 0, 0, 0, 9], 0x0800, &packet))]),
        [DropReason::OtherHost]
    );
    assert_eq!(
        s.take(vec![Ok(ethernet(MAC, 0x88b5, b"local experiment"))]),
        [DropReason::UnhandledProto]
    );
    // An ARP frame whose body is no ARP message.
    let mut arp = ethernet(MAC, 0x0806, &[0; 8]);
    arp.truncate(22);
    assert_eq!(s.take(vec![Ok(arp)]), [DropReason::ArpInvalid]);
    assert_eq!(
        s.take(vec![Ok(ethernet(MAC, 0x0800, &packet))]),
        [DropReason::NoSocket]
    );
}

#[test]
fn the_feed_is_off_by_default_bounded_and_drained_oldest_first() {
    let mut s = Station::new(PacketLayer::Ip);
    s.ip(ipv4(6, &syn(9)));
    let mut events = Vec::new();
    s.network.drain_drop_events(|e| events.push(e));
    assert!(events.is_empty());
    s.network.set_drop_feed(2).unwrap();
    // One discard each in the driver, the Host and the Endpoint, then two
    // more than the Endpoint's feed holds.
    s.take(vec![Err(io::ErrorKind::InvalidData)]);
    s.ip(ipv4(99, b"p"));
    let first = s.now;
    for _ in 0..4 {
        s.ip(ipv4(6, &syn(9)));
    }
    s.network.drain_drop_events(|e| events.push(e));
    let reasons: Vec<_> = events.iter().map(|e| e.reason).collect();
    assert_eq!(
        reasons,
        [
            DropReason::DevHdr,
            DropReason::IpNoproto,
            DropReason::NoSocket,
            DropReason::NoSocket,
        ]
    );
    assert!(events.windows(2).all(|w| w[0].at <= w[1].at));
    let event = events[2];
    assert_eq!(event.at, first + 100);
    assert_eq!(
        event.subject,
        DropSubject::Transport {
            protocol: 6,
            source: (Ipv4Addr::from(REMOTE), 40_000).into(),
            destination: (Ipv4Addr::from(LOCAL), 9).into(),
        }
    );
    assert_eq!(s.network.counters().drop_events_lost, 2);
    // Disabled again: counted, not reported.
    s.network.set_drop_feed(0).unwrap();
    s.ip(ipv4(6, &syn(9)));
    events.clear();
    s.network.drain_drop_events(|e| events.push(e));
    assert!(events.is_empty());
    assert_eq!(s.network.counters().drops[DropReason::NoSocket], 6);
}
