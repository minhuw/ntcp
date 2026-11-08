// Networks on the queues of one Ethernet port that share its IPv4 neighbor
// table, driven over an in-memory LAN: one port MAC for every member, IPv4
// frames to the port steered to the member owning their destination, ARP
// to whichever member the test chooses. The queues are Send, so members can
// run on their own threads.
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::*;
use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

const SECOND: u64 = 1_000_000;
const BUDGET: WorkBudget = WorkBudget::new(32, 32, 32, 32);
const PORT_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const PEER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const STATION: [u8; 6] = [2, 0, 0, 0, 0, 0x77];
const STATION_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 77);
const PEER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 100);
const SILENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
// Each member's output owners: max_connections + 1.
const OWNERS: usize = 5;

fn member_ip(k: usize) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, 1 + k as u8)
}

type Queue = Arc<Mutex<VecDeque<Vec<u8>>>>;

// An ARP transmission waits here, its member holding the shared table,
// until the test releases it (or ten seconds pass).
struct Gate {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
}
struct Port {
    incoming: Queue,
    outgoing: Queue,
    gate: Option<Gate>,
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
        if ethertype(frame) == 0x0806
            && let Some(gate) = &self.gate
        {
            gate.entered.send(()).unwrap();
            let _ = gate.release.recv_timeout(Duration::from_secs(10));
        }
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
    fn port(incoming: &Queue, outgoing: &Queue) -> Port {
        Port {
            incoming: incoming.clone(),
            outgoing: outgoing.clone(),
            gate: None,
        }
    }
    // Member `k` of `table`, at 10.0.0.(k + 1).
    fn member(table: &SharedNeighbors, k: usize) -> Self {
        let (incoming, outgoing) = (Queue::default(), Queue::default());
        let port = Self::port(&incoming, &outgoing);
        let network =
            Network::with_shared_neighbors(config(member_ip(k), PORT_MAC), port, [7; 32], 0, table)
                .unwrap();
        Self {
            network,
            incoming,
            outgoing,
        }
    }
    // A station with its own table.
    fn peer() -> Self {
        let (incoming, outgoing) = (Queue::default(), Queue::default());
        let mut config = config(PEER, PEER_MAC);
        config.tcp.max_connections = 8;
        let network = Network::new(config, Self::port(&incoming, &outgoing), [9; 32], 0).unwrap();
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
        self.outgoing.lock().unwrap().drain(..).collect()
    }
    fn deliver(&self, frames: &[Vec<u8>]) {
        self.incoming.lock().unwrap().extend(frames.iter().cloned());
    }
}

fn config(local: Ipv4Addr, mac: [u8; 6]) -> NetworkConfig {
    let mut config = NetworkConfig::new(IpAddr::V4(local), 1500);
    config.tcp.max_connections = OWNERS - 1;
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
fn table_with(members: usize, held: usize) -> SharedNeighbors {
    let limits = SharedNeighborLimits {
        members,
        entries: 8,
        held,
        replies: 4,
    };
    SharedNeighbors::new(PORT_MAC, SECOND, limits).unwrap()
}
fn table(members: usize) -> SharedNeighbors {
    table_with(members, members * OWNERS)
}
fn ethertype(frame: &[u8]) -> u16 {
    u16::from_be_bytes([frame[12], frame[13]])
}
fn arps(frames: &[Vec<u8>]) -> Vec<([u8; 6], ntcp_arp::Arp)> {
    frames
        .iter()
        .filter_map(|f| ntcp_arp::parse_frame(f).ok())
        .map(|(destination, _, arp)| (destination, arp))
        .collect()
}
fn ipv4(frames: &[Vec<u8>]) -> Vec<&Vec<u8>> {
    frames.iter().filter(|f| ethertype(f) == 0x0800).collect()
}
fn source_ip(frame: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(frame[26], frame[27], frame[28], frame[29])
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
fn reply(sender: ([u8; 6], Ipv4Addr), target: ([u8; 6], Ipv4Addr)) -> ntcp_arp::Arp {
    ntcp_arp::Arp {
        operation: ntcp_arp::Operation::Reply,
        sender_mac: sender.0,
        sender_ip: sender.1,
        target_mac: target.0,
        target_ip: target.1,
    }
}
fn frame(destination: [u8; 6], arp: &ntcp_arp::Arp) -> Vec<u8> {
    let mut out = vec![0; 60];
    let len = ntcp_arp::encode_frame(&mut out, arp.sender_mac, destination, arp).unwrap();
    out.truncate(len);
    out
}
// The port's side of the LAN: ARP to member `arp`, IPv4 to the member that
// owns its destination.
fn steer(frames: Vec<Vec<u8>>, members: &[Queue], arp: usize) {
    for frame in frames {
        let member = match ethertype(&frame) {
            0x0806 => arp,
            0x0800 => usize::from(frame[33]) - 1,
            _ => continue,
        };
        members[member].lock().unwrap().push_back(frame);
    }
}
fn queues(members: &[Station]) -> Vec<Queue> {
    members.iter().map(|m| m.incoming.clone()).collect()
}
// One step of `members` and the peer at `now`.
fn exchange(members: &mut [Station], peer: &mut Station, now: u64, arp: usize) {
    for member in members.iter_mut() {
        member.drive(now);
        peer.deliver(&member.sent());
    }
    peer.drive(now);
    steer(peer.sent(), &queues(members), arp);
}
fn read_all(network: &mut Network<Port>, connection: ConnId) -> Vec<u8> {
    let mut data = Vec::new();
    let mut out = [0; 4096];
    while let Ok(ReadOutcome::Data { len, .. }) = network.try_read(connection, &mut out) {
        data.extend_from_slice(&out[..len]);
    }
    data
}

// The members drive every 50 ms, far more often than RetransTimer; the next
// hop answers only after the third request.
#[test]
fn members_resolving_one_slow_next_hop_send_one_request_per_retrans_timer() {
    let shared = table(3);
    let mut members: Vec<_> = (0..3).map(|k| Station::member(&shared, k)).collect();
    for member in &mut members {
        member
            .network
            .connect(SocketAddr::new(PEER.into(), 80))
            .unwrap();
    }
    let mut requests = Vec::new();
    let mut now = 0;
    while now < 2 * SECOND + SECOND / 2 {
        for member in &mut members {
            member.drive(now);
            let sent = member.sent();
            assert!(ipv4(&sent).is_empty());
            requests.extend(arps(&sent).into_iter().map(|r| (now, r)));
        }
        now += 50_000;
    }
    // One broadcast request per second for all three, from the port's MAC
    // and its first member's address.
    assert_eq!(
        requests,
        [0, SECOND, 2 * SECOND].map(|at| (
            at,
            (
                ntcp_ethernet::BROADCAST,
                request((PORT_MAC, member_ip(0)), PEER)
            )
        ))
    );
    assert_eq!(shared.counters().requests_sent, 3);
    // The answer releases every member's SYN.
    members[0].deliver(&[frame(
        PORT_MAC,
        &reply((PEER_MAC, PEER), (PORT_MAC, member_ip(0))),
    )]);
    for (k, member) in members.iter_mut().enumerate() {
        member.drive(now);
        let sent = member.sent();
        let syns = ipv4(&sent);
        assert_eq!(syns.len(), 1, "member {k}");
        assert_eq!(syns[0][..6], PEER_MAC);
        assert_eq!(source_ip(syns[0]), member_ip(k));
        assert!(arps(&sent).is_empty());
    }
    assert_eq!(shared.counters().requests_sent, 3);
}

#[test]
fn a_reply_delivered_to_one_member_releases_held_syns_on_every_member() {
    let shared = table(3);
    let mut members: Vec<_> = (0..3).map(|k| Station::member(&shared, k)).collect();
    let mut peer = Station::peer();
    let listener = peer.network.listen(80, 4).unwrap();
    let clients: Vec<_> = members
        .iter_mut()
        .map(|m| m.network.connect(SocketAddr::new(PEER.into(), 80)).unwrap())
        .collect();
    let mut sent = Vec::new();
    for member in &mut members {
        member.drive(10);
        sent.extend(member.sent());
    }
    assert_eq!(
        arps(&sent),
        [(
            ntcp_ethernet::BROADCAST,
            request((PORT_MAC, member_ip(0)), PEER)
        )]
    );
    assert!(ipv4(&sent).is_empty());
    peer.deliver(&sent);
    peer.drive(20);
    let answer = peer.sent();
    assert_eq!(
        arps(&answer),
        [(PORT_MAC, reply((PEER_MAC, PEER), (PORT_MAC, member_ip(0))))]
    );
    // Only the third member receives the reply; it releases its own SYN at
    // once and the others' at their next drive.
    members[2].deliver(&answer);
    for k in [2, 0, 1] {
        members[k].drive(30);
        let sent = members[k].sent();
        let syns = ipv4(&sent);
        assert_eq!(syns.len(), 1, "member {k}");
        assert_eq!(syns[0][..6], PEER_MAC);
        assert_eq!(syns[0][6..12], PORT_MAC);
        assert_eq!(source_ip(syns[0]), member_ip(k));
        peer.deliver(&sent);
    }
    // The handshakes complete on every member. The peer resolves the
    // members it did not learn from the request; member 0 takes the port's
    // ARP and answers for all of them.
    let mut servers = Vec::new();
    let mut now = 30;
    while servers.len() < 3 && now < 2 * SECOND {
        now += 1000;
        exchange(&mut members, &mut peer, now, 0);
        while let Ok(server) = peer.network.accept(listener) {
            servers.push(server);
        }
    }
    assert_eq!(servers.len(), 3);
    for (k, member) in members.iter_mut().enumerate() {
        member
            .network
            .try_write(
                clients[k],
                format!("member {k}").as_bytes(),
                WriteOptions::default(),
            )
            .unwrap();
    }
    let mut got = vec![Vec::new(); 3];
    for _ in 0..50 {
        now += 1000;
        exchange(&mut members, &mut peer, now, 0);
        for &server in &servers {
            let client = peer.network.connection_info(server).unwrap().peer;
            let k = (0..3)
                .find(|&k| client.ip() == IpAddr::V4(member_ip(k)))
                .unwrap();
            got[k].extend(read_all(&mut peer.network, server));
        }
    }
    for (k, data) in got.iter().enumerate() {
        assert_eq!(data, format!("member {k}").as_bytes());
        assert_eq!(
            members[k]
                .network
                .connection_info(clients[k])
                .unwrap()
                .state,
            State::Established
        );
    }
    // The members asked once for all of them.
    assert_eq!(shared.counters().requests_sent, 1);
    assert_eq!(shared.counters().resolution_failures, 0);
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
fn any_member_answers_for_every_members_address_and_for_no_other() {
    let shared = table(3);
    let mut members: Vec<_> = (0..3).map(|k| Station::member(&shared, k)).collect();
    let from = (STATION, STATION_IP);
    for (receiver, owner) in [(0, 2), (1, 0), (2, 2)] {
        members[receiver].deliver(&[frame(
            ntcp_ethernet::BROADCAST,
            &request(from, member_ip(owner)),
        )]);
        for member in &mut members {
            member.drive(10 + receiver as u64);
        }
        // The member that received the request answers it, with the port's
        // MAC for the owner's address; the others send nothing.
        for (k, member) in members.iter().enumerate() {
            let sent = member.sent();
            if k == receiver {
                assert_eq!(
                    arps(&sent),
                    [(STATION, reply((PORT_MAC, member_ip(owner)), from))]
                );
            } else {
                assert!(sent.is_empty(), "member {k}");
            }
        }
    }
    // An address no member owns, on the port's own subnet, is not answered.
    members[1].deliver(&[frame(
        ntcp_ethernet::BROADCAST,
        &request(from, Ipv4Addr::new(10, 0, 0, 50)),
    )]);
    for member in &mut members {
        member.drive(20);
        assert!(member.sent().is_empty());
    }
    assert_eq!(shared.counters().replies_sent, 3);
}

// Every member runs on its own thread, where its Network is built, and
// drives itself on one shared clock; the peer, on the test's thread, echoes
// what each member sends.
#[test]
fn members_on_separate_threads_exchange_data_with_a_peer() {
    const MEMBERS: usize = 3;
    let shared = table(MEMBERS);
    let start = std::time::Instant::now();
    let clock = move || start.elapsed().as_micros() as u64;
    let mut peer = Station::peer();
    let listener = peer.network.listen(80, 4).unwrap();
    let incoming: Vec<Queue> = (0..MEMBERS).map(|_| Queue::default()).collect();
    let payload = |k: usize| -> Vec<u8> { (0..20_000).map(|i| (i * (k + 3)) as u8).collect() };
    let workers: Vec<_> = (0..MEMBERS)
        .map(|k| {
            let shared = shared.clone();
            let port = Station::port(&incoming[k], &peer.incoming);
            thread::spawn(move || -> Vec<u8> {
                let config = config(member_ip(k), PORT_MAC);
                let mut network =
                    Network::with_shared_neighbors(config, port, [k as u8; 32], clock(), &shared)
                        .unwrap();
                let data = payload(k);
                let client = network.connect(SocketAddr::new(PEER.into(), 80)).unwrap();
                let (mut sent, mut echoed) = (0, Vec::new());
                let mut out = [0; 4096];
                while echoed.len() < data.len() && start.elapsed() < Duration::from_secs(30) {
                    network.drive(clock(), BUDGET).unwrap();
                    if sent < data.len()
                        && let Ok(receipt) =
                            network.try_write(client, &data[sent..], WriteOptions::default())
                    {
                        sent += receipt.accepted;
                    }
                    if let Ok(ReadOutcome::Data { len, .. }) = network.try_read(client, &mut out) {
                        echoed.extend_from_slice(&out[..len]);
                    }
                    thread::sleep(Duration::from_micros(100));
                }
                echoed
            })
        })
        .collect();
    let mut echoes: Vec<(ConnId, VecDeque<u8>)> = Vec::new();
    let mut out = [0; 4096];
    while !workers.iter().all(|w| w.is_finished()) && start.elapsed() < Duration::from_secs(40) {
        peer.drive(clock());
        // The port's ARP reaches the second member's queue.
        steer(peer.sent(), &incoming, 1);
        while let Ok(server) = peer.network.accept(listener) {
            echoes.push((server, VecDeque::new()));
        }
        for (server, queued) in &mut echoes {
            if let Ok(ReadOutcome::Data { len, .. }) = peer.network.try_read(*server, &mut out) {
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
    for (k, worker) in workers.into_iter().enumerate() {
        assert_eq!(worker.join().unwrap(), payload(k), "member {k}");
    }
    assert_eq!(echoes.len(), MEMBERS);
    assert_eq!(shared.counters().resolution_failures, 0);
}

#[test]
fn a_silent_next_hop_fails_every_members_held_syn_without_busy_loops() {
    let shared = table(3);
    let mut members: Vec<_> = (0..3).map(|k| Station::member(&shared, k)).collect();
    let clients: Vec<_> = members
        .iter_mut()
        .map(|m| {
            m.network
                .connect(SocketAddr::new(SILENT.into(), 80))
                .unwrap()
        })
        .collect();
    // Each round drives every member at the earliest deadline they report,
    // as an embedding would.
    let mut requests = Vec::new();
    let mut now = 0;
    while now < 3 * SECOND {
        let mut next = u64::MAX;
        for member in &mut members {
            let report = member.drive(now);
            assert!(!report.more_work && !report.tx_blocked);
            let sent = member.sent();
            assert!(ipv4(&sent).is_empty());
            requests.extend(arps(&sent).into_iter().map(|r| (now, r)));
            next = next.min(report.next_deadline.unwrap());
        }
        now = next;
    }
    assert_eq!(
        requests,
        [0, SECOND, 2 * SECOND].map(|at| (
            at,
            (
                ntcp_ethernet::BROADCAST,
                request((PORT_MAC, member_ip(0)), SILENT)
            )
        ))
    );
    assert_eq!(now, 3 * SECOND);
    // A second after the last request the entry fails. Every member's SYN
    // is withdrawn unsent: TCP retries it on its own clock, no earlier than
    // its RTO, and no member is left with a wake to spin on.
    for (k, member) in members.iter_mut().enumerate() {
        let report = member.drive(now);
        assert!(member.sent().is_empty());
        assert!(!report.more_work && !report.tx_blocked, "member {k}");
        let retry = report.next_deadline.unwrap();
        assert!(retry >= now + SECOND, "member {k}: {retry}");
        assert_eq!(
            member.network.connection_info(clients[k]).unwrap().state,
            State::SynSent
        );
        assert_eq!(member.network.counters().resolution_failures, 1);
    }
    assert_eq!(shared.counters().resolution_failures, 1);
    // Over a minute the retried SYNs resolve again, together, at a bounded
    // request rate; none leaves, and the members' drives stay bounded.
    let (mut frames, mut drives) = (0, 0);
    while now < 60 * SECOND {
        let mut next = u64::MAX;
        for member in &mut members {
            let report = member.drive(now);
            drives += 1;
            let sent = member.sent();
            assert!(ipv4(&sent).is_empty());
            frames += sent.len();
            next = next.min(report.next_deadline.unwrap().max(now + 1));
        }
        now = next;
    }
    assert!(frames >= 3, "{frames}");
    assert!(
        frames <= 60 && drives <= 3 * 120,
        "{frames} frames in {drives} drives"
    );
}

#[test]
fn a_member_that_leaves_is_no_longer_answered_for_and_frees_its_held_records() {
    // Three members' worth of slots, two members' worth of held records.
    let shared = table_with(3, 2 * OWNERS);
    let mut a = Station::member(&shared, 0);
    let mut b = Station::member(&shared, 1);
    for _ in 0..OWNERS - 1 {
        a.network
            .connect(SocketAddr::new(SILENT.into(), 80))
            .unwrap();
    }
    a.drive(0);
    b.drive(0);
    assert_eq!(arps(&a.sent()).len(), 1);
    // The held records are all reserved by the two members.
    let port = Station::port(&Queue::default(), &Queue::default());
    assert!(matches!(
        Network::with_shared_neighbors(config(member_ip(2), PORT_MAC), port, [7; 32], 0, &shared),
        Err(Error::Capacity)
    ));
    drop(a);
    // Its address is answered no more; B's still is.
    let from = (STATION, STATION_IP);
    b.deliver(&[
        frame(ntcp_ethernet::BROADCAST, &request(from, member_ip(0))),
        frame(ntcp_ethernet::BROADCAST, &request(from, member_ip(1))),
    ]);
    b.drive(10);
    assert_eq!(
        arps(&b.sent()),
        [(STATION, reply((PORT_MAC, member_ip(1)), from))]
    );
    // A's reservation and its four held records went with it: a new member
    // joins, and it and B hold four SYNs each, which the peer's answer
    // releases together. Had A's records stayed, two of those eight would
    // find the held table full and wait for TCP's retry instead.
    let mut c = Station::member(&shared, 2);
    let mut peer = Station::peer();
    peer.network.listen(80, 8).unwrap();
    for _ in 0..OWNERS - 1 {
        for member in [&mut b, &mut c] {
            member
                .network
                .connect(SocketAddr::new(PEER.into(), 80))
                .unwrap();
        }
    }
    b.drive(20);
    c.drive(20);
    let sent: Vec<_> = b.sent().into_iter().chain(c.sent()).collect();
    assert!(ipv4(&sent).is_empty());
    let asked = arps(&sent);
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].1.target_ip, PEER);
    peer.deliver(&sent);
    peer.drive(30);
    b.deliver(&peer.sent());
    b.drive(40);
    c.drive(40);
    assert_eq!(ipv4(&b.sent()).len(), OWNERS - 1);
    assert_eq!(ipv4(&c.sent()).len(), OWNERS - 1);
}

// Member A, on its own thread, is held inside its backend's transmission
// of an ARP reply, which it sends holding the port's table. B's drive, with
// that reply due too, neither waits for the table nor sends the reply
// itself, and its data still leaves through the mapping it resolved.
#[test]
fn a_member_skips_housekeeping_while_another_holds_the_table() {
    let shared = table(2);
    let (entered, entered_rx) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let (drive, drive_rx) = mpsc::channel::<u64>();
    let (driven, driven_rx) = mpsc::channel();
    let (a_incoming, a_outgoing) = (Queue::default(), Queue::default());
    let worker = {
        let shared = shared.clone();
        let (incoming, outgoing) = (a_incoming.clone(), a_outgoing.clone());
        thread::spawn(move || {
            let port = Port {
                incoming,
                outgoing,
                gate: Some(Gate {
                    entered,
                    release: release_rx,
                }),
            };
            let mut a = Network::with_shared_neighbors(
                config(member_ip(0), PORT_MAC),
                port,
                [7; 32],
                0,
                &shared,
            )
            .unwrap();
            driven.send(()).unwrap();
            while let Ok(now) = drive_rx.recv() {
                a.drive(now, BUDGET).unwrap();
                driven.send(()).unwrap();
            }
        })
    };
    // A joins first: the port's requests come from its address.
    driven_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let mut b = [Station::member(&shared, 1)];
    let mut peer = Station::peer();
    let listener = peer.network.listen(80, 2).unwrap();
    let client = b[0]
        .network
        .connect(SocketAddr::new(PEER.into(), 80))
        .unwrap();
    // B resolves the peer (the port's ARP reaches B) and makes progress.
    let mut port = vec![a_incoming.clone()];
    port.extend(queues(&b));
    let mut now = 0;
    let server = loop {
        now += 1000;
        exchange_steered(&mut b, &mut peer, now, &port);
        if let Ok(server) = peer.network.accept(listener) {
            break server;
        }
        assert!(now < SECOND);
    };
    b[0].network.set_nodelay(client, true).unwrap();
    b[0].network
        .try_write(client, b"before", WriteOptions::default())
        .unwrap();
    for _ in 0..20 {
        now += 1000;
        exchange_steered(&mut b, &mut peer, now, &port);
    }
    assert_eq!(read_all(&mut peer.network, server), b"before");
    // A takes a request for B's address and is held sending the reply.
    let replies = shared.counters().replies_sent;
    let from = (STATION, STATION_IP);
    a_incoming.lock().unwrap().push_back(frame(
        ntcp_ethernet::BROADCAST,
        &request(from, member_ip(1)),
    ));
    now += 1000;
    drive.send(now).unwrap();
    entered_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("A sends the reply");
    b[0].network
        .try_write(client, b"while held", WriteOptions::default())
        .unwrap();
    let started = std::time::Instant::now();
    let report = b[0].drive(now);
    assert!(started.elapsed() < Duration::from_secs(5), "B waited for A");
    let sent = b[0].sent();
    assert!(arps(&sent).is_empty());
    let data = ipv4(&sent);
    assert_eq!(data.len(), 1);
    assert_eq!(data[0][..6], PEER_MAC);
    // The reply is still due: B's drive reports it.
    assert!(report.next_deadline.is_some_and(|at| at <= now));
    release.send(()).unwrap();
    driven_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let from_a: Vec<_> = a_outgoing.lock().unwrap().drain(..).collect();
    assert_eq!(
        arps(&from_a),
        [(STATION, reply((PORT_MAC, member_ip(1)), from))]
    );
    // Sent once: B finds nothing left to send.
    b[0].drive(now + 1);
    assert!(arps(&b[0].sent()).is_empty());
    peer.deliver(&sent);
    for _ in 0..20 {
        now += 1000;
        exchange_steered(&mut b, &mut peer, now, &port);
    }
    assert_eq!(read_all(&mut peer.network, server), b"while held");
    assert_eq!(shared.counters().replies_sent, replies + 1);
    drop(drive);
    worker.join().unwrap();
}

// As `exchange`, with the port's queues listed by member (ARP to the last).
fn exchange_steered(members: &mut [Station], peer: &mut Station, now: u64, queues: &[Queue]) {
    for member in members.iter_mut() {
        member.drive(now);
        peer.deliver(&member.sent());
    }
    peer.drive(now);
    steer(peer.sent(), queues, queues.len() - 1);
}

// A blocking embedding polls a descriptor the table writes when another
// member ends one of its resolutions.
#[cfg(unix)]
#[test]
fn a_member_woken_by_another_member_has_its_wake_descriptor_written() {
    use std::io::Read;
    let shared = table(2);
    let mut members: Vec<_> = (0..2).map(|k| Station::member(&shared, k)).collect();
    let (mut reader, writer) = io::pipe().unwrap();
    members[0]
        .network
        .set_neighbor_wake_fd(std::os::fd::OwnedFd::from(writer))
        .unwrap();
    members[0]
        .network
        .connect(SocketAddr::new(PEER.into(), 80))
        .unwrap();
    members[0].drive(0);
    members[1].drive(0);
    assert_eq!(arps(&members[0].sent()).len(), 1);
    members[1].deliver(&[frame(
        PORT_MAC,
        &reply((PEER_MAC, PEER), (PORT_MAC, member_ip(0))),
    )]);
    members[1].drive(10);
    let (read, read_rx) = mpsc::channel();
    thread::spawn(move || {
        let mut count = [0; 8];
        read.send(
            reader
                .read_exact(&mut count)
                .map(|_| u64::from_ne_bytes(count)),
        )
        .unwrap();
    });
    let count = read_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(count.unwrap(), 1);
    // The woken member's next drive releases its SYN.
    let report = members[0].drive(10);
    assert_eq!(ipv4(&members[0].sent()).len(), 1);
    assert!(report.transmitted >= 1);
    // A member without a shared table has no wake to signal.
    let mut peer = Station::peer();
    let (_, writer) = io::pipe().unwrap();
    assert!(matches!(
        peer.network
            .set_neighbor_wake_fd(std::os::fd::OwnedFd::from(writer)),
        Err(Error::Unsupported(_))
    ));
}
