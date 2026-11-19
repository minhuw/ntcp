// The ICMP messages a Network originates (`NetworkConfig::icmp_output_messages`):
// Echo Replies, Port and Protocol Unreachables, sent by the drive that
// received their packets through the backend, within Linux's rate limits
// (`NetworkConfig::icmp_rate`), queued within a bound and charged to the
// buffer budget.
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::*;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    rc::Rc,
};

const SECOND: u64 = 1_000_000;
const BUDGET: WorkBudget = WorkBudget::new(32, 64, 32, 32);
const LOCAL: [u8; 4] = [192, 0, 2, 2];
const REMOTE: [u8; 4] = [192, 0, 2, 1];
const LOCAL6: &str = "2001:db8::2";
const REMOTE6: &str = "2001:db8::1";
const MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const REMOTE_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];

type Frames = Rc<RefCell<VecDeque<Vec<u8>>>>;

// A backend whose transmissions are recorded, or refused with WouldBlock
// while `blocked`.
struct Wire {
    layer: PacketLayer,
    incoming: Frames,
    outgoing: Frames,
    blocked: Rc<Cell<bool>>,
}
impl PacketIo for Wire {
    fn layer(&self) -> PacketLayer {
        self.layer
    }
    fn max_packet_len(&self) -> Option<usize> {
        Some(1514)
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        let Some(frame) = self.incoming.borrow_mut().pop_front() else {
            return Ok(None);
        };
        out[..frame.len()].copy_from_slice(&frame);
        Ok(Some(frame.len()))
    }
    fn transmit(&mut self, frame: &[u8]) -> io::Result<TxOutcome> {
        if self.blocked.get() {
            return Ok(TxOutcome::WouldBlock);
        }
        self.outgoing.borrow_mut().push_back(frame.to_vec());
        Ok(TxOutcome::Submitted)
    }
}

struct Station {
    network: Network<Wire>,
    incoming: Frames,
    outgoing: Frames,
    blocked: Rc<Cell<bool>>,
    now: u64,
}
impl Station {
    fn new(local: IpAddr, set: impl FnOnce(&mut NetworkConfig)) -> Self {
        Self::with_layer(PacketLayer::Ip, local, set)
    }
    fn with_layer(layer: PacketLayer, local: IpAddr, set: impl FnOnce(&mut NetworkConfig)) -> Self {
        let mut config = NetworkConfig::new(local, 1500);
        config.tcp.max_connections = 4;
        config.tcp.max_listeners = 1;
        set(&mut config);
        let (incoming, outgoing) = (Frames::default(), Frames::default());
        let blocked = Rc::new(Cell::new(false));
        let wire = Wire {
            layer,
            incoming: incoming.clone(),
            outgoing: outgoing.clone(),
            blocked: blocked.clone(),
        };
        Self {
            network: Network::new(config, wire, [5; 32], 0).unwrap(),
            incoming,
            outgoing,
            blocked,
            now: 0,
        }
    }
    // Deliver `frames` and drive once, 100 us later; what it sent.
    fn exchange(&mut self, frames: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        self.incoming.borrow_mut().extend(frames);
        self.drive()
    }
    fn drive(&mut self) -> Vec<Vec<u8>> {
        self.now += 100;
        self.network.drive(self.now, BUDGET).unwrap();
        self.outgoing.borrow_mut().drain(..).collect()
    }
    fn at(&mut self, now: u64) {
        assert!(now >= self.now);
        self.now = now - 100;
    }
}

fn sum(bytes: &[u8], mut sum: u32) -> u16 {
    for pair in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
fn checksum(bytes: &[u8]) -> u16 {
    sum(bytes, 0)
}
// The ICMPv6 or UDP-over-IPv6 checksum of `message` from `source` to
// `destination` (RFC 8200 section 8.1).
fn checksum6(source: Ipv6Addr, destination: Ipv6Addr, protocol: u8, message: &[u8]) -> u16 {
    let mut pseudo = source.octets().to_vec();
    pseudo.extend(destination.octets());
    pseudo.extend((message.len() as u32).to_be_bytes());
    pseudo.extend([0, 0, 0, protocol]);
    pseudo.extend(message);
    checksum(&pseudo)
}
fn v6(address: &str) -> Ipv6Addr {
    address.parse().unwrap()
}

fn ipv4_from(source: [u8; 4], protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x45, 0, 0, 0, 0, 7, 0x40, 0, 64, protocol, 0, 0];
    packet[2..4].copy_from_slice(&(20 + payload.len() as u16).to_be_bytes());
    packet.extend(source);
    packet.extend(LOCAL);
    let sum = checksum(&packet);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet.extend(payload);
    packet
}
fn ipv6(protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x60, 0, 0, 0, 0, 0, protocol, 64];
    packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend(v6(REMOTE6).octets());
    packet.extend(v6(LOCAL6).octets());
    packet.extend(payload);
    packet
}

// An Echo Request message (type 8, or 128 for ICMPv6).
fn echo(ipv6: bool, identifier: u16, sequence: u16, data: &[u8]) -> Vec<u8> {
    let mut message = vec![if ipv6 { 128 } else { 8 }, 0, 0, 0];
    message.extend(identifier.to_be_bytes());
    message.extend(sequence.to_be_bytes());
    message.extend(data);
    let sum = if ipv6 {
        checksum6(v6(REMOTE6), v6(LOCAL6), 58, &message)
    } else {
        checksum(&message)
    };
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    message
}

// A UDP datagram from port 40000 to `port` with its checksum.
fn udp_from(source: [u8; 4], port: u16, payload: &[u8]) -> Vec<u8> {
    let mut segment = vec![0x9c, 0x40, 0, 0, 0, 0, 0, 0];
    segment[2..4].copy_from_slice(&port.to_be_bytes());
    segment[4..6].copy_from_slice(&(8 + payload.len() as u16).to_be_bytes());
    segment.extend(payload);
    let mut pseudo = source.to_vec();
    pseudo.extend(LOCAL);
    pseudo.extend([0, 17]);
    pseudo.extend((segment.len() as u16).to_be_bytes());
    pseudo.extend(&segment);
    let sum = checksum(&pseudo);
    segment[6..8].copy_from_slice(&sum.to_be_bytes());
    ipv4_from(source, 17, &segment)
}
fn udp6(port: u16, payload: &[u8]) -> Vec<u8> {
    let mut segment = vec![0x9c, 0x40, 0, 0, 0, 0, 0, 0];
    segment[2..4].copy_from_slice(&port.to_be_bytes());
    segment[4..6].copy_from_slice(&(8 + payload.len() as u16).to_be_bytes());
    segment.extend(payload);
    let sum = checksum6(v6(REMOTE6), v6(LOCAL6), 17, &segment);
    segment[6..8].copy_from_slice(&sum.to_be_bytes());
    ipv6(17, &segment)
}

// The IPv4 packet `packet` checked as one from LOCAL to `destination` with
// TTL 64 carrying ICMP, its header checksum valid; its ICMP message, whose
// checksum is valid too.
fn icmp4_to(destination: [u8; 4], packet: &[u8]) -> Vec<u8> {
    assert_eq!(packet[0], 0x45);
    assert_eq!(
        usize::from(u16::from_be_bytes([packet[2], packet[3]])),
        packet.len()
    );
    assert_eq!((packet[8], packet[9]), (64, 1), "TTL 64, ICMP");
    assert_eq!(&packet[12..16], &LOCAL);
    assert_eq!(&packet[16..20], &destination);
    assert_eq!(checksum(&packet[..20]), 0);
    let message = packet[20..].to_vec();
    assert_eq!(checksum(&message), 0);
    message
}
fn icmp4(packet: &[u8]) -> Vec<u8> {
    icmp4_to(REMOTE, packet)
}
fn icmp6(packet: &[u8]) -> Vec<u8> {
    assert_eq!(packet[0] >> 4, 6);
    assert_eq!(
        usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40,
        packet.len()
    );
    assert_eq!((packet[6], packet[7]), (58, 64), "ICMPv6, Hop Limit 64");
    assert_eq!(&packet[8..24], &v6(LOCAL6).octets());
    assert_eq!(&packet[24..40], &v6(REMOTE6).octets());
    let message = packet[40..].to_vec();
    assert_eq!(checksum6(v6(LOCAL6), v6(REMOTE6), 58, &message), 0);
    message
}

// The reply the Echo Request `request` draws: the request with the reply
// type and its checksum recomputed.
fn reply_to(ipv6: bool, request: &[u8]) -> Vec<u8> {
    let mut reply = request.to_vec();
    reply[0] = if ipv6 { 129 } else { 0 };
    reply[2..4].fill(0);
    let sum = if ipv6 {
        checksum6(v6(LOCAL6), v6(REMOTE6), 58, &reply)
    } else {
        checksum(&reply)
    };
    reply[2..4].copy_from_slice(&sum.to_be_bytes());
    reply
}

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.2.6
//= type=test
//# Every host MUST implement an ICMP Echo server function that
//# receives Echo Requests and sends corresponding Echo Replies.
#[test]
fn an_echo_request_draws_exactly_one_reply() {
    let data: Vec<u8> = (0..100).collect();
    let mut s = Station::new(IpAddr::V4(LOCAL.into()), |_| {});
    let request = echo(false, 0x1234, 7, &data);
    let sent = s.exchange(vec![ipv4_from(REMOTE, 1, &request)]);
    assert_eq!(sent.len(), 1);
    assert_eq!(icmp4(&sent[0]), reply_to(false, &request));
    assert!(s.drive().is_empty());
    assert_eq!(s.network.icmp_counters().echo_replies, 1);
    assert_eq!(s.network.counters().transmitted, 1);
    assert_eq!(s.network.counters().discarded, 0);

    let mut s = Station::new(IpAddr::V6(v6(LOCAL6)), |_| {});
    let request = echo(true, 0x4321, 9, &data);
    let sent = s.exchange(vec![ipv6(58, &request)]);
    assert_eq!(sent.len(), 1);
    assert_eq!(icmp6(&sent[0]), reply_to(true, &request));
    assert!(s.drive().is_empty());
}

// On an Ethernet port the reply goes to the next hop's MAC: the fixed one,
// or the requester's, resolved by ARP while the reply waits.
#[test]
fn an_echo_reply_waits_for_its_next_hop() {
    let request = echo(false, 1, 1, b"ping");
    let ethernet = |destination: [u8; 6], ethertype: u16, payload: &[u8]| {
        let mut frame = destination.to_vec();
        frame.extend(REMOTE_MAC);
        frame.extend(ethertype.to_be_bytes());
        frame.extend(payload);
        frame.resize(frame.len().max(60), 0);
        frame
    };
    let mut s = Station::with_layer(PacketLayer::Ethernet, IpAddr::V4(LOCAL.into()), |c| {
        c.link = Link::Ethernet {
            local_mac: MAC,
            next_hop: EthernetNextHop::Arp {
                prefix_len: 24,
                gateway: None,
            },
        };
    });
    let sent = s.exchange(vec![ethernet(MAC, 0x0800, &ipv4_from(REMOTE, 1, &request))]);
    // Only the ARP request for the requester leaves.
    assert_eq!(sent.len(), 1);
    let (destination, _, arp) = ntcp_arp::parse_frame(&sent[0]).unwrap();
    assert_eq!(destination, [0xff; 6]);
    assert_eq!(arp.target_ip, Ipv4Addr::from(REMOTE));
    // The reply waits for the resolution, whose next request is the
    // network's next deadline.
    assert_eq!(s.network.next_deadline(), Some(s.now + SECOND));
    let answer = ntcp_arp::Arp {
        operation: ntcp_arp::Operation::Reply,
        sender_mac: REMOTE_MAC,
        sender_ip: REMOTE.into(),
        target_mac: MAC,
        target_ip: LOCAL.into(),
    };
    let mut frame = vec![0; 60];
    let len = ntcp_arp::encode_frame(&mut frame, REMOTE_MAC, MAC, &answer).unwrap();
    frame.truncate(len);
    let sent = s.exchange(vec![frame]);
    assert_eq!(sent.len(), 1);
    assert_eq!(&sent[0][..6], &REMOTE_MAC);
    assert_eq!(&sent[0][6..12], &MAC);
    assert_eq!(&sent[0][12..14], &[8, 0]);
    let packet = &sent[0][14..14 + 20 + request.len()];
    assert_eq!(icmp4(packet), reply_to(false, &request));
    assert!(s.drive().is_empty());

    let fixed = [2, 0, 0, 0, 0, 9];
    let mut s = Station::with_layer(PacketLayer::Ethernet, IpAddr::V6(v6(LOCAL6)), |c| {
        c.link = Link::Ethernet {
            local_mac: MAC,
            next_hop: EthernetNextHop::Fixed(fixed),
        };
    });
    let request = echo(true, 1, 1, b"ping");
    let sent = s.exchange(vec![ethernet(MAC, 0x86dd, &ipv6(58, &request))]);
    assert_eq!(sent.len(), 1);
    assert_eq!(&sent[0][..6], &fixed);
    assert_eq!(&sent[0][6..12], &MAC);
    assert_eq!(&sent[0][12..14], &[0x86, 0xdd]);
    assert_eq!(icmp6(&sent[0][14..]), reply_to(true, &request));
}

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.2.1
//= type=test
//# A host SHOULD generate Destination Unreachable messages with
//# code:
//#
//# 2    (Protocol Unreachable), when the designated transport
//#      protocol is not supported; or
//#
//# 3    (Port Unreachable), when the designated transport
//#      protocol (e.g., UDP) is unable to demultiplex the
//#      datagram but has no protocol mechanism to inform the
//#      sender.
#[test]
fn udp_and_unknown_protocols_draw_unreachables() {
    let mut s = Station::new(IpAddr::V4(LOCAL.into()), |_| {});
    let datagram = udp_from(REMOTE, 9, &[5; 32]);
    let sent = s.exchange(vec![datagram.clone()]);
    assert_eq!(sent.len(), 1);
    let message = icmp4(&sent[0]);
    assert_eq!(&message[..2], &[3, 3]);
    assert_eq!(&message[4..8], &[0; 4]);
    assert_eq!(&message[8..], &datagram[..]);
    // The quote keeps the whole error within 576 octets.
    let datagram = udp_from(REMOTE, 9, &[6; 1000]);
    let message = icmp4(&s.exchange(vec![datagram.clone()])[0]);
    assert_eq!(message.len(), 576 - 20);
    assert_eq!(&message[8..], &datagram[..576 - 28]);
    let packet = ipv4_from(REMOTE, 99, b"payload");
    let message = icmp4(&s.exchange(vec![packet.clone()])[0]);
    assert_eq!(&message[..2], &[3, 2]);
    assert_eq!(&message[8..], &packet[..]);
    assert_eq!(s.network.icmp_counters().errors, 3);
    // No error answers an ICMP error, a broadcast, or a datagram whose
    // checksum is wrong.
    let mut bad = udp_from(REMOTE, 9, b"x");
    bad[27] ^= 1;
    let mut to_broadcast = udp_from(REMOTE, 9, b"x");
    to_broadcast[16..20].copy_from_slice(&[255; 4]);
    assert!(
        s.exchange(vec![bad, ipv4_from(REMOTE, 1, &message), to_broadcast])
            .is_empty()
    );

    let mut s = Station::new(IpAddr::V6(v6(LOCAL6)), |_| {});
    let datagram = udp6(9, &[5; 32]);
    let message = icmp6(&s.exchange(vec![datagram.clone()])[0]);
    assert_eq!(&message[..2], &[1, 4]);
    assert_eq!(&message[4..8], &[0; 4]);
    assert_eq!(&message[8..], &datagram[..]);
}

// Linux's per-destination bucket (inet_peer_xrlim_allow): six errors at
// once, then one a second; Echo Replies are not limited.
#[test]
fn errors_to_one_destination_are_limited_and_replies_are_not() {
    let mut s = Station::new(IpAddr::V4(LOCAL.into()), |_| {});
    let burst = (0..20).map(|_| udp_from(REMOTE, 9, b"x")).collect();
    assert_eq!(s.exchange(burst).len(), 6);
    let counters = s.network.icmp_counters();
    assert_eq!((counters.errors, counters.rate_limited_host), (6, 14));
    assert_eq!(counters.rate_limited_global, 0);
    s.at(SECOND - 1);
    assert!(s.exchange(vec![udp_from(REMOTE, 9, b"x")]).is_empty());
    s.at(SECOND + 1000);
    let two = vec![udp_from(REMOTE, 9, b"x"), udp_from(REMOTE, 9, b"x")];
    assert_eq!(s.exchange(two).len(), 1);
    let requests = (0..32).map(|n| ipv4_from(REMOTE, 1, &echo(false, 1, n, b"p")));
    assert_eq!(s.exchange(requests.collect()).len(), 32);
    assert_eq!(s.network.icmp_counters().echo_replies, 32);
}

// Linux's bucket shared by every destination (icmp_global_allow): 50 deep,
// each message taking 0 to 2 tokens, refilled 20 ms after its last refill.
#[test]
fn errors_to_many_destinations_share_a_bucket() {
    let mut s = Station::new(IpAddr::V4(LOCAL.into()), |_| {});
    let mut sent = 0;
    for round in 0..8u8 {
        let datagrams = (0..25u8).map(|n| udp_from([10, 1, round, n], 9, b"x"));
        sent += s.exchange(datagrams.collect()).len();
    }
    assert!((25..=120).contains(&sent), "{sent}");
    let counters = s.network.icmp_counters();
    assert_eq!(counters.errors, sent as u64);
    assert_eq!(counters.rate_limited_global, 200 - sent as u64);
    assert_eq!(counters.rate_limited_host, 0);
    // 20 ms later the bucket gains 20 tokens.
    s.at(SECOND / 50 + 1000);
    let datagrams = (0..30u8).map(|n| udp_from([10, 2, 0, n], 9, b"x"));
    let refill = s.exchange(datagrams.collect()).len();
    assert!((10..=30).contains(&refill), "{refill}");
}

// Messages a drive leaves for want of transmit budget are more work, which
// the next drive sends: the network's next deadline does not tell them.
#[test]
fn messages_left_for_want_of_budget_are_more_work() {
    let mut s = Station::new(IpAddr::V4(LOCAL.into()), |_| {});
    let requests = (0..3).map(|n| ipv4_from(REMOTE, 1, &echo(false, 1, n, b"ping")));
    s.incoming.borrow_mut().extend(requests);
    s.now += 100;
    let report = s
        .network
        .drive(s.now, WorkBudget::new(32, 1, 32, 32))
        .unwrap();
    assert_eq!(report.transmitted, 1);
    assert!(report.more_work);
    assert_eq!(s.network.next_deadline(), None);
    assert_eq!(s.outgoing.borrow_mut().drain(..).count(), 1);
    assert_eq!(s.drive().len(), 2);
}

// A full queue drops what does not fit, counted, and the queued messages
// wait for TX room, charged to the buffer budget until they leave.
#[test]
fn a_full_queue_drops_and_backpressure_waits() {
    let mut s = Station::new(IpAddr::V4(LOCAL.into()), |c| c.icmp_output_messages = 2);
    let idle = s.network.counters().buffer_bytes;
    s.blocked.set(true);
    let requests = (0..5).map(|n| ipv4_from(REMOTE, 1, &echo(false, 1, n, &[n as u8; 200])));
    assert!(s.exchange(requests.collect()).is_empty());
    let counters = s.network.counters();
    assert_eq!(counters.drops[DropReason::IcmpOutputDropped], 3);
    assert!(counters.backend_backpressure >= 1);
    assert_eq!(s.network.icmp_counters().dropped, 3);
    // Two queued messages of 208 octets each.
    assert!(
        counters.buffer_bytes >= idle + 2 * 208,
        "{idle} {}",
        counters.buffer_bytes
    );
    s.blocked.set(false);
    let sent = s.drive();
    assert_eq!(sent.len(), 2);
    for (n, packet) in sent.iter().enumerate() {
        let message = icmp4(packet);
        assert_eq!(&message[6..8], &(n as u16).to_be_bytes());
    }
    assert_eq!(s.network.counters().buffer_bytes, idle);
}

// With output off the Network originates nothing, and its budget holds no
// queue.
#[test]
fn icmp_output_can_be_turned_off() {
    let off = |c: &mut NetworkConfig| c.icmp_output_messages = 0;
    let mut s = Station::new(IpAddr::V4(LOCAL.into()), off);
    let request = ipv4_from(REMOTE, 1, &echo(false, 1, 1, b"ping"));
    assert!(
        s.exchange(vec![request, udp_from(REMOTE, 9, b"x")])
            .is_empty()
    );
    let counters = s.network.counters();
    assert_eq!(counters.drops[DropReason::IcmpOutputDropped], 1);
    assert_eq!(counters.drops[DropReason::NoSocket], 1);
    let mut on = NetworkConfig::new(IpAddr::V4(LOCAL.into()), 1500);
    let wire = Wire {
        layer: PacketLayer::Ip,
        incoming: Frames::default(),
        outgoing: Frames::default(),
        blocked: Rc::default(),
    };
    let with = on.buffer_budget(0, &wire).unwrap();
    off(&mut on);
    assert!(on.buffer_budget(0, &wire).unwrap() < with);
}
