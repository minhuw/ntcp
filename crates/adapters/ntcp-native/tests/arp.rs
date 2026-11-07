// Native Ethernet ports that resolve IPv4 next hops by ARP, driven over an
// in-memory LAN whose frames the tests inspect, drop or inject.
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::*;
use std::{
    cell::RefCell,
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    rc::Rc,
};

const SECOND: u64 = 1_000_000;
const BUDGET: WorkBudget = WorkBudget::new(32, 32, 32, 32);
const MAC_A: [u8; 6] = [2, 0, 0, 0, 0, 1];
const MAC_B: [u8; 6] = [2, 0, 0, 0, 0, 2];
const STATION: [u8; 6] = [2, 0, 0, 0, 0, 0x77];
const IP_A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const IP_B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

// One port's attachment: frames to receive and frames it transmitted.
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
        let Some(frame) = self.incoming.borrow_mut().pop_front() else {
            return Ok(None);
        };
        out[..frame.len()].copy_from_slice(&frame);
        Ok(Some(frame.len()))
    }
    fn transmit(&mut self, frame: &[u8]) -> io::Result<TxOutcome> {
        self.outgoing.borrow_mut().push_back(frame.to_vec());
        Ok(TxOutcome::Submitted)
    }
}
struct Station {
    network: Network<Port>,
    incoming: Queue,
    outgoing: Queue,
}
impl Station {
    fn new(config: NetworkConfig) -> Self {
        let incoming = Queue::default();
        let outgoing = Queue::default();
        let port = Port {
            incoming: incoming.clone(),
            outgoing: outgoing.clone(),
        };
        let network = Network::new(config, port, [7; 32], 0).unwrap();
        Self {
            network,
            incoming,
            outgoing,
        }
    }
    fn drive(&mut self, now: u64) -> DriveReport {
        self.network.drive(now, BUDGET).unwrap()
    }
    fn sent(&self) -> Vec<Vec<u8>> {
        self.outgoing.borrow_mut().drain(..).collect()
    }
    fn deliver(&self, frames: &[Vec<u8>]) {
        self.incoming.borrow_mut().extend(frames.iter().cloned());
    }
}

fn config(local: Ipv4Addr, mac: [u8; 6], gateway: Option<Ipv4Addr>) -> NetworkConfig {
    let mut config = NetworkConfig::new(IpAddr::V4(local), 1500);
    config.tcp.max_connections = 4;
    config.tcp.max_listeners = 1;
    config.tcp.connection.send_capacity = 4096;
    config.tcp.connection.receive_capacity = 4096;
    config.link = Link::Ethernet {
        local_mac: mac,
        next_hop: EthernetNextHop::Arp {
            prefix_len: 24,
            gateway,
        },
    };
    config
}
fn ethertype(frame: &[u8]) -> u16 {
    u16::from_be_bytes([frame[12], frame[13]])
}
fn arp(frame: &[u8]) -> Option<([u8; 6], ntcp_arp::Arp)> {
    let (destination, _, arp) = ntcp_arp::parse_frame(frame).ok()?;
    Some((destination, arp))
}
fn arps(frames: &[Vec<u8>]) -> Vec<([u8; 6], ntcp_arp::Arp)> {
    frames.iter().filter_map(|f| arp(f)).collect()
}
fn ipv4(frames: &[Vec<u8>]) -> Vec<&Vec<u8>> {
    frames.iter().filter(|f| ethertype(f) == 0x0800).collect()
}
fn request(sender: ([u8; 6], Ipv4Addr), target: Ipv4Addr) -> ntcp_arp::Arp {
    ntcp_arp::Arp {
        operation: ntcp_arp::Operation::Request,
        sender_mac: sender.0,
        sender_ip: sender.1,
        target_mac: [0; 6],
        target_ip: target,
    }
}
fn frame(destination: [u8; 6], arp: &ntcp_arp::Arp) -> Vec<u8> {
    let mut out = vec![0; 60];
    let len = ntcp_arp::encode_frame(&mut out, arp.sender_mac, destination, arp).unwrap();
    out.truncate(len);
    out
}
// Run both stations over a LAN that carries every frame, from `now` for
// `steps` steps of `step`; frames each sent are returned.
fn run(
    a: &mut Station,
    b: &mut Station,
    now: &mut u64,
    steps: usize,
    step: u64,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let (mut from_a, mut from_b) = (Vec::new(), Vec::new());
    for _ in 0..steps {
        *now += step;
        a.drive(*now);
        let sent = a.sent();
        b.deliver(&sent);
        from_a.extend(sent);
        b.drive(*now);
        let sent = b.sent();
        a.deliver(&sent);
        from_b.extend(sent);
    }
    (from_a, from_b)
}
// Accept on `listener` within a bounded exchange.
fn established(a: &mut Station, b: &mut Station, now: &mut u64, listener: ListenerId) -> ConnId {
    for _ in 0..100 {
        run(a, b, now, 1, 1000);
        match b.network.accept(listener) {
            Ok(server) => return server,
            Err(error) if error.is_would_block() => {}
            Err(error) => panic!("accept: {error:?}"),
        }
    }
    panic!("no connection");
}
fn read_all(station: &mut Station, connection: ConnId) -> Vec<u8> {
    let mut data = Vec::new();
    let mut out = [0; 4096];
    while let Ok(ReadOutcome::Data { len, .. }) = station.network.try_read(connection, &mut out) {
        data.extend_from_slice(&out[..len]);
    }
    data
}

//= https://www.rfc-editor.org/rfc/rfc826#name-abstract
//= type=test
//# It then causes
//# this packet to be broadcast to all stations on the Ethernet cable
//# originally determined by the routing mechanism.
//= https://www.rfc-editor.org/rfc/rfc1122#section-2.3.2.2
//= type=test
//# The link layer SHOULD save (rather than discard) at least
//# one (the latest) packet of each set of packets destined to
//# the same unresolved IP address, and transmit the saved
//# packet when the address has been resolved.
#[test]
fn stations_resolve_each_other_and_exchange_data_both_ways() {
    let mut a = Station::new(config(IP_A, MAC_A, None));
    let mut b = Station::new(config(IP_B, MAC_B, None));
    let listener = b.network.listen(80, 2).unwrap();
    let client = a.network.connect(SocketAddr::new(IP_B.into(), 80)).unwrap();
    // The SYN waits for resolution: only the broadcast request leaves.
    let report = a.drive(10);
    let sent = a.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        arps(&sent),
        [(ntcp_ethernet::BROADCAST, request((MAC_A, IP_A), IP_B))]
    );
    assert_eq!(report.transmitted, 1);
    assert!(!report.more_work && !report.tx_blocked);
    assert_eq!(report.next_deadline, Some(10 + SECOND));
    // Waiting neither spins nor reports backpressure.
    for now in [20, 1000, 500_000] {
        let report = a.drive(now);
        assert_eq!(report.transmitted, 0);
        assert!(!report.more_work && !report.tx_blocked);
        assert_eq!(report.next_deadline, Some(10 + SECOND));
        assert!(a.sent().is_empty());
    }
    // B answers with its MAC, unicast; the reply releases the SYN to it.
    b.deliver(&sent);
    b.drive(500_000);
    let reply = b.sent();
    assert_eq!(
        arps(&reply),
        [(
            MAC_A,
            ntcp_arp::Arp {
                operation: ntcp_arp::Operation::Reply,
                sender_mac: MAC_B,
                sender_ip: IP_B,
                target_mac: MAC_A,
                target_ip: IP_A,
            }
        )]
    );
    a.deliver(&reply);
    let report = a.drive(500_010);
    let syn = a.sent();
    assert_eq!(ipv4(&syn).len(), 1);
    assert_eq!(syn[0][..6], MAC_B);
    assert_eq!(syn[0][6..12], MAC_A);
    assert_eq!(report.transmitted, 1);
    b.deliver(&syn);
    let mut now = 500_010;
    let server = established(&mut a, &mut b, &mut now, listener);
    // Both directions carry data; B learned A from its request and never
    // asks, and neither probes while TCP makes progress.
    let up: Vec<u8> = (0..3000).map(|i| i as u8).collect();
    let down: Vec<u8> = (0..2000).map(|i| (i * 7) as u8).collect();
    let (mut sent_up, mut sent_down) = (0, 0);
    let (mut got_up, mut got_down) = (Vec::new(), Vec::new());
    let (mut from_a, mut from_b) = (Vec::new(), Vec::new());
    for _ in 0..400 {
        if let Ok(receipt) = a
            .network
            .try_write(client, &up[sent_up..], WriteOptions::default())
        {
            sent_up += receipt.accepted;
        }
        if let Ok(receipt) =
            b.network
                .try_write(server, &down[sent_down..], WriteOptions::default())
        {
            sent_down += receipt.accepted;
        }
        let (fa, fb) = run(&mut a, &mut b, &mut now, 1, 50_000);
        from_a.extend(fa);
        from_b.extend(fb);
        got_up.extend(read_all(&mut b, server));
        got_down.extend(read_all(&mut a, client));
        if got_up.len() == up.len() && got_down.len() == down.len() {
            break;
        }
    }
    assert_eq!(got_up, up);
    assert_eq!(got_down, down);
    assert!(arps(&from_a).is_empty() && arps(&from_b).is_empty());
    for frame in ipv4(&from_a) {
        assert_eq!(frame[..6], MAC_B);
    }
    for frame in ipv4(&from_b) {
        assert_eq!(frame[..6], MAC_A);
    }
    let (ca, cb) = (a.network.counters(), b.network.counters());
    assert_eq!(
        (ca.arp_sent, ca.arp_received, ca.resolution_failures),
        (1, 1, 0)
    );
    assert_eq!(
        (cb.arp_sent, cb.arp_received, cb.resolution_failures),
        (1, 1, 0)
    );
}

#[test]
fn a_silent_peer_fails_resolution_and_the_syn_is_never_sent() {
    let mut a = Station::new(config(IP_A, MAC_A, None));
    let silent = Ipv4Addr::new(10, 0, 0, 9);
    let client = a
        .network
        .connect(SocketAddr::new(silent.into(), 80))
        .unwrap();
    let mut requests = Vec::new();
    let mut drives = 0;
    let mut now = 0;
    // Drive at every deadline the network reports, as an embedding would.
    while now < 3 * SECOND {
        let report = a.drive(now);
        drives += 1;
        assert!(!report.more_work && !report.tx_blocked);
        let sent = a.sent();
        assert!(ipv4(&sent).is_empty());
        requests.extend(arps(&sent).into_iter().map(|r| (now, r)));
        now = report.next_deadline.unwrap();
    }
    // Three broadcast requests one second apart, then failure a second
    // after the last.
    assert_eq!(
        requests,
        [0, SECOND, 2 * SECOND].map(|at| (
            at,
            (ntcp_ethernet::BROADCAST, request((MAC_A, IP_A), silent))
        ))
    );
    assert_eq!(now, 3 * SECOND);
    assert!(drives <= 4);
    let report = a.drive(now);
    assert!(a.sent().is_empty());
    assert_eq!(a.network.counters().resolution_failures, 1);
    // The SYN was withdrawn unsubmitted: TCP retries on its own clock, no
    // earlier than its RTO, resolving again.
    assert!(!report.more_work && !report.tx_blocked);
    let retry = report.next_deadline.unwrap();
    assert!(retry >= now + SECOND, "{retry}");
    assert_eq!(
        a.network.connection_info(client).unwrap().state,
        State::SynSent
    );
    a.drive(retry);
    let sent = a.sent();
    assert_eq!(
        arps(&sent),
        [(ntcp_ethernet::BROADCAST, request((MAC_A, IP_A), silent))]
    );
    assert!(ipv4(&sent).is_empty());
    // Over a minute the request rate stays bounded and no SYN leaves.
    let (mut frames, mut drives) = (0, 0);
    let mut now = retry;
    while now < 60 * SECOND {
        let report = a.drive(now);
        drives += 1;
        let sent = a.sent();
        assert!(ipv4(&sent).is_empty());
        frames += sent.len();
        now = report.next_deadline.unwrap().max(now + 1);
    }
    assert!(
        frames <= 60 && drives <= 120,
        "{frames} frames in {drives} drives"
    );
    // The application gives up; the held state goes with the connection.
    a.network.abort(client).unwrap();
    a.drive(now);
    a.drive(now + 4 * SECOND);
    assert!(ipv4(&a.sent()).is_empty());
}

#[test]
fn off_link_destinations_resolve_the_gateway() {
    let gateway = Ipv4Addr::new(10, 0, 0, 254);
    let gateway_mac = [2, 0, 0, 0, 0, 0xfe];
    let mut a = Station::new(config(IP_A, MAC_A, Some(gateway)));
    a.network
        .connect(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 7).into(), 80))
        .unwrap();
    a.drive(0);
    let sent = a.sent();
    assert_eq!(
        arps(&sent),
        [(ntcp_ethernet::BROADCAST, request((MAC_A, IP_A), gateway))]
    );
    let reply = ntcp_arp::Arp {
        operation: ntcp_arp::Operation::Reply,
        sender_mac: gateway_mac,
        sender_ip: gateway,
        target_mac: MAC_A,
        target_ip: IP_A,
    };
    a.deliver(&[frame(MAC_A, &reply)]);
    a.drive(100);
    let sent = a.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0][..6], gateway_mac);
    assert_eq!(ethertype(&sent[0]), 0x0800);
    // IPv4 destination 192.0.2.7.
    assert_eq!(sent[0][14 + 16..14 + 20], [192, 0, 2, 7]);
}

#[test]
fn static_neighbors_need_no_arp_and_bad_configurations_are_refused() {
    let mut ca = config(IP_A, MAC_A, None);
    ca.static_neighbors = vec![(IP_B, MAC_B)];
    let mut cb = config(IP_B, MAC_B, None);
    cb.static_neighbors = vec![(IP_A, MAC_A)];
    let mut a = Station::new(ca);
    let mut b = Station::new(cb);
    let listener = b.network.listen(80, 2).unwrap();
    let client = a.network.connect(SocketAddr::new(IP_B.into(), 80)).unwrap();
    let mut now = 0;
    let server = established(&mut a, &mut b, &mut now, listener);
    a.network
        .try_write(client, b"static", WriteOptions::default())
        .unwrap();
    let (from_a, from_b) = run(&mut a, &mut b, &mut now, 20, 10_000);
    assert_eq!(read_all(&mut b, server), b"static");
    assert!(arps(&from_a).is_empty() && arps(&from_b).is_empty());
    assert_eq!(
        a.network.counters().arp_sent + b.network.counters().arp_sent,
        0
    );

    let refused = |config: NetworkConfig| {
        let port = Port {
            incoming: Queue::default(),
            outgoing: Queue::default(),
        };
        matches!(
            Network::new(config, port, [7; 32], 0),
            Err(Error::InvalidConfig(_))
        )
    };
    let arp = |prefix_len, gateway| EthernetNextHop::Arp {
        prefix_len,
        gateway,
    };
    let with = |local: IpAddr, next_hop| {
        let mut config = config(IP_A, MAC_A, None);
        config.local_address = local;
        config.link = Link::Ethernet {
            local_mac: MAC_A,
            next_hop,
        };
        config
    };
    let a4 = IpAddr::V4(IP_A);
    assert!(refused(with("2001:db8::1".parse().unwrap(), arp(64, None))));
    for prefix_len in [0, 33] {
        assert!(refused(with(a4, arp(prefix_len, None))));
    }
    for gateway in [
        IP_A,
        Ipv4Addr::new(10, 0, 1, 1),
        Ipv4Addr::new(10, 0, 0, 255),
        Ipv4Addr::new(10, 0, 0, 0),
    ] {
        assert!(refused(with(a4, arp(24, Some(gateway)))), "{gateway}");
    }
    let mut no_entries = with(a4, arp(24, None));
    no_entries.neighbor_entries = 0;
    assert!(refused(no_entries));
    for (address, mac) in [
        (IP_A, MAC_B),
        (Ipv4Addr::new(10, 0, 9, 2), MAC_B),
        (IP_B, [0xff; 6]),
    ] {
        let mut config = with(a4, arp(24, None));
        config.static_neighbors = vec![(address, mac)];
        assert!(refused(config), "{address}");
    }
    let mut duplicate = with(a4, arp(24, None));
    duplicate.static_neighbors = vec![(IP_B, MAC_B), (IP_B, STATION)];
    assert!(refused(duplicate));
    let mut fixed = with(a4, EthernetNextHop::Fixed(MAC_B));
    fixed.static_neighbors = vec![(IP_B, MAC_B)];
    assert!(refused(fixed));
    // /31 has no network or broadcast address (RFC 3021).
    let mut point = with(a4, arp(31, Some(Ipv4Addr::new(10, 0, 0, 0))));
    point.local_address = IpAddr::V4(IP_A);
    assert!(!refused(point));
}

//= https://www.rfc-editor.org/rfc/rfc826#name-abstract
//= type=test
//# ?Is the opcode ares_op$REQUEST?  (NOW look at the opcode!!)
//# Yes:
//# Swap hardware and protocol fields, putting the local
//# hardware and protocol addresses in the sender fields.
//# Set the ar$op field to ares_op$REPLY
//# Send the packet to the (new) target hardware address on
//# the same hardware on which the request was received.
#[test]
fn only_requests_for_the_local_address_are_answered() {
    let mut a = Station::new(config(IP_A, MAC_A, None));
    let other = Ipv4Addr::new(10, 0, 0, 5);
    let from = (STATION, Ipv4Addr::new(10, 0, 0, 77));
    // For another address: learned nothing to answer.
    a.deliver(&[frame(ntcp_ethernet::BROADCAST, &request(from, other))]);
    a.drive(0);
    assert!(a.sent().is_empty());
    // For ours: a unicast reply with our MAC.
    a.deliver(&[frame(ntcp_ethernet::BROADCAST, &request(from, IP_A))]);
    a.drive(1);
    assert_eq!(
        arps(&a.sent()),
        [(
            STATION,
            ntcp_arp::Arp {
                operation: ntcp_arp::Operation::Reply,
                sender_mac: MAC_A,
                sender_ip: IP_A,
                target_mac: STATION,
                target_ip: from.1,
            }
        )]
    );
    assert_eq!(a.network.counters().arp_received, 2);
    // Addressed to another station: not ours to learn from or answer.
    let discarded = a.network.counters().discarded;
    a.deliver(&[frame([2, 0, 0, 0, 0, 0x55], &request(from, IP_A))]);
    a.drive(2);
    assert!(a.sent().is_empty());
    assert_eq!(a.network.counters().arp_received, 2);
    assert_eq!(a.network.counters().discarded, discarded + 1);
    // A broadcast IP frame is still dropped as before.
    let mut broadcast = vec![0; 60];
    broadcast[..6].copy_from_slice(&ntcp_ethernet::BROADCAST);
    broadcast[6..12].copy_from_slice(&STATION);
    broadcast[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    broadcast[14] = 0x45;
    a.deliver(&[broadcast]);
    a.drive(3);
    assert!(a.sent().is_empty());
    assert_eq!(a.network.counters().discarded, discarded + 2);
}

//= https://www.rfc-editor.org/rfc/rfc826#name-abstract
//= type=test
//# After a suitable time, the daemon considers removing an entry.
//# It first sends (with a small number of retransmissions if needed)
//# an address resolution packet with opcode REQUEST directly to the
//# Ethernet address in the table.  If a REPLY is not seen in a short
//# amount of time, the entry is deleted.  The request is sent
//# directly so as not to bother every station on the Ethernet.
#[test]
fn idle_entries_are_validated_by_probe_unless_tcp_confirms_them() {
    let mut a = Station::new(config(IP_A, MAC_A, None));
    let mut b = Station::new(config(IP_B, MAC_B, None));
    let listener = b.network.listen(80, 2).unwrap();
    let client = a.network.connect(SocketAddr::new(IP_B.into(), 80)).unwrap();
    let mut now = 0;
    let server = established(&mut a, &mut b, &mut now, listener);
    run(&mut a, &mut b, &mut now, 10, 100_000);
    // Idle beyond any ReachableTime (at most 1.5 times 30 s): nothing is
    // sent while the entries go STALE.
    let (from_a, from_b) = run(&mut a, &mut b, &mut now, 50, SECOND);
    assert!(from_a.is_empty() && from_b.is_empty());
    // Used again with forward progress: the acknowledgments confirm the
    // entry, so DELAY ends REACHABLE and no probe follows.
    a.network
        .try_write(client, b"progress", WriteOptions::default())
        .unwrap();
    let (from_a, _) = run(&mut a, &mut b, &mut now, 100, 100_000);
    assert_eq!(read_all(&mut b, server), b"progress");
    // (B, which only acknowledges, gets no confirmation and probes A,
    // which answers.)
    assert!(
        arps(&from_a)
            .iter()
            .all(|(_, arp)| arp.operation == ntcp_arp::Operation::Reply)
    );
    assert!(!ipv4(&from_a).is_empty());
    // Idle again, then used without progress (B's frames are lost): after
    // DELAY_FIRST_PROBE_TIME the entry is probed by unicast.
    run(&mut a, &mut b, &mut now, 50, SECOND);
    let start = now;
    a.network
        .try_write(client, b"lost", WriteOptions::default())
        .unwrap();
    let mut probes = Vec::new();
    for _ in 0..100 {
        now += 100_000;
        a.drive(now);
        let sent = a.sent();
        probes.extend(arps(&sent).into_iter().map(|p| (now, p)));
        b.deliver(&sent);
        b.drive(now);
        b.sent();
    }
    let (at, _) = probes[0];
    assert!(
        at >= start + 5 * SECOND && at <= start + 5 * SECOND + 200_000,
        "{at} {start}"
    );
    // Three unicast requests one second apart, unanswered; a second after
    // the last the entry is deleted.
    assert_eq!(probes.len(), 3);
    for (index, &(sent, (destination, probe))) in probes.iter().enumerate() {
        assert_eq!(destination, MAC_B);
        assert_eq!(probe, request((MAC_A, IP_A), IP_B));
        assert_eq!(sent, at + index as u64 * SECOND);
    }
    assert_eq!(a.network.counters().resolution_failures, 1);
}

// Frames given up while their next hop resolves leave their held records
// behind. Those records are drained once their resolution ends, even when
// no other frame is held, so they never fill the held table and refuse the
// resolution of a later next hop.
#[test]
fn held_records_of_aborted_connections_do_not_block_later_resolution() {
    let mut a = Station::new(config(IP_A, MAC_A, None));
    let mut b = Station::new(config(IP_B, MAC_B, None));
    let listener = b.network.listen(80, 4).unwrap();
    let silent = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 9).into(), 80);
    // Every connection slot holds its SYN, and all are given up; then one
    // more, given up before the drive after the one that held it. The held
    // table (one record per output owner) is then full of their records.
    let held: Vec<_> = (0..4).map(|_| a.network.connect(silent).unwrap()).collect();
    a.drive(0);
    for &id in &held {
        a.network.abort(id).unwrap();
    }
    // The aborted connections' slots come free over a few drives.
    let mut now = 1;
    let late = loop {
        a.drive(now);
        a.network.drain_events(&mut [Event::NetworkStopped; 16]);
        now += 1;
        match a.network.connect(silent) {
            Ok(id) => break id,
            Err(Error::Capacity) if now < 100 => {}
            Err(error) => panic!("connect: {error:?}"),
        }
    };
    a.drive(now);
    a.network.abort(late).unwrap();
    now += 1;
    a.drive(now);
    // The silent next hop fails; nothing else is held.
    while now < 5 * SECOND {
        a.drive(now);
        now += SECOND / 4;
    }
    assert!(a.network.counters().resolution_failures >= 1);
    a.sent();
    // A live station is resolved and reached.
    let client = a.network.connect(SocketAddr::new(IP_B.into(), 80)).unwrap();
    let server = established(&mut a, &mut b, &mut now, listener);
    a.network
        .try_write(client, b"after", WriteOptions::default())
        .unwrap();
    run(&mut a, &mut b, &mut now, 20, 1000);
    assert_eq!(read_all(&mut b, server), b"after");
}
