// The local ports a Network's opens take. An ephemeral port is shared by
// active opens to distinct destinations, each 4-tuple once among the
// connections and TIME-WAIT records, as Linux's __inet_hash_connect shares
// it; a port a listener or an explicit open took is no ephemeral open's,
// and an explicit port is refused while anything uses it. Ports run out per
// destination; an open finds no slot in a full table until one is freed.
// Two Networks over an in-memory IP wire.
use ntcp::EndpointError;
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::*;
use std::{
    cell::RefCell,
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    ops::RangeInclusive,
    rc::Rc,
};

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

struct Wire {
    incoming: Queue,
    outgoing: Queue,
}
impl PacketIo for Wire {
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn max_packet_len(&self) -> Option<usize> {
        Some(1500)
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        let Some(packet) = self.incoming.borrow_mut().pop_front() else {
            return Ok(None);
        };
        out[..packet.len()].copy_from_slice(&packet);
        Ok(Some(packet.len()))
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        self.outgoing.borrow_mut().push_back(packet.to_vec());
        Ok(TxOutcome::Submitted)
    }
}

const BUDGET: WorkBudget = WorkBudget::new(32, 32, 32, 32);
const PORT: u16 = 9000;

fn address(side: u8) -> IpAddr {
    IpAddr::from([10, 75, 0, side])
}

fn network(
    side: u8,
    incoming: &Queue,
    outgoing: &Queue,
    ports: RangeInclusive<u16>,
    max_time_wait: Option<usize>,
) -> Network<Wire> {
    built(side, incoming, outgoing, [side; 32], |config| {
        if let Some(records) = max_time_wait {
            config.tcp.max_time_wait = records;
        }
        config.ephemeral_ports = ports;
    })
}

// A Network of `side` with `secret`, its configuration adjusted.
fn built(
    side: u8,
    incoming: &Queue,
    outgoing: &Queue,
    secret: [u8; 32],
    adjust: impl FnOnce(&mut NetworkConfig),
) -> Network<Wire> {
    let mut config = NetworkConfig::new(address(side), 1500);
    config.tcp.max_connections = 8;
    config.tcp.max_listeners = 2;
    config.tcp.connection.send_capacity = 2048;
    config.tcp.connection.receive_capacity = 8192;
    adjust(&mut config);
    let wire = Wire {
        incoming: incoming.clone(),
        outgoing: outgoing.clone(),
    };
    let connections = config.tcp.max_connections;
    config.tcp.max_buffer_bytes = config.buffer_budget(connections, &wire).unwrap();
    Network::new(config, wire, secret, 0).unwrap()
}

struct Pair {
    client: Network<Wire>,
    server: Network<Wire>,
    listener: ListenerId,
    now: u64,
}
impl Pair {
    fn new(client_ports: RangeInclusive<u16>, server_ports: RangeInclusive<u16>) -> Self {
        Self::with_server_records(client_ports, server_ports, None)
    }
    // A pair whose server keeps at most `max_time_wait` TIME-WAIT records.
    fn with_server_records(
        client_ports: RangeInclusive<u16>,
        server_ports: RangeInclusive<u16>,
        max_time_wait: Option<usize>,
    ) -> Self {
        let (a, b) = (Queue::default(), Queue::default());
        let client = network(1, &a, &b, client_ports, None);
        let mut server = network(2, &b, &a, server_ports, max_time_wait);
        let listener = server.listen(PORT, 8).unwrap();
        Self {
            client,
            server,
            listener,
            now: 0,
        }
    }
    fn step(&mut self) {
        self.now += 1000;
        self.client.drive(self.now, BUDGET).unwrap();
        self.server.drive(self.now, BUDGET).unwrap();
        drain(&mut self.client);
        drain(&mut self.server);
    }
    fn steps(&mut self, n: usize) {
        for _ in 0..n {
            self.step();
        }
    }
    fn accepted(&mut self) -> ConnId {
        self.accepted_from(self.listener)
    }
    fn accepted_from(&mut self, listener: ListenerId) -> ConnId {
        for _ in 0..100 {
            self.step();
            if let Ok(server) = self.server.accept(listener) {
                return server;
            }
        }
        panic!("handshake did not finish");
    }
    // Drives past TIME-WAIT until the client's `id` is reclaimed.
    fn reclaim(&mut self, id: ConnId) {
        self.now += self.client.config().tcp.connection.time_wait_us;
        for _ in 0..100 {
            self.step();
            if matches!(self.client.connection_info(id), Err(Error::InvalidHandle)) {
                return;
            }
        }
        panic!("the connection was not reclaimed");
    }
}

fn drain(network: &mut Network<Wire>) -> Vec<Event> {
    let mut result = Vec::new();
    let mut out = [Event::NetworkStopped; 8];
    loop {
        let report = network.drain_events(&mut out);
        result.extend_from_slice(&out[..report.written]);
        if !report.more {
            return result;
        }
    }
}

fn local_port(network: &Network<Wire>, id: ConnId) -> u16 {
    network.connection_info(id).unwrap().local.port()
}

fn in_use<T: std::fmt::Debug>(result: Result<T>) -> bool {
    matches!(result, Err(Error::Tcp(EndpointError::AddressInUse)))
}

// No ephemeral port is left to the destination (Linux's EADDRNOTAVAIL).
fn ports_exhausted<T: std::fmt::Debug>(result: Result<T>) -> bool {
    matches!(result, Err(Error::AddressNotAvailable))
}

// No connection or listener slot is free.
fn slots_exhausted<T: std::fmt::Debug>(result: Result<T>) -> bool {
    matches!(result, Err(Error::Capacity))
}

// A closed connection's tuple stays taken through TIME-WAIT, after its
// released slot was freed into the endpoint's TIME-WAIT record, and is free
// after: no open to its destination takes the port, an explicit one none,
// while an ephemeral open to another destination does. A TIME-WAIT record
// is never reused by an active open, as Linux's tcp_tw_reuse allows only
// over loopback by default.
#[test]
fn a_closed_connections_tuple_is_taken_until_its_time_wait_ends() {
    let mut pair = Pair::new(40000..=40000, 50000..=50000);
    let server_address = SocketAddr::new(address(2), PORT);
    let client = pair.client.connect(server_address).unwrap();
    assert_eq!(local_port(&pair.client, client), 40000);
    let server = pair.accepted();
    pair.client.close(client).unwrap();
    pair.steps(4);
    assert!(matches!(
        pair.server.try_read(server, &mut [0; 8]),
        Ok(ReadOutcome::Eof)
    ));
    pair.server.close(server).unwrap();
    for _ in 0..100 {
        pair.step();
        if pair.client.counters().time_wait_connections == 1 {
            break;
        }
    }
    pair.steps(4);
    // The application closed it and drained its events: the slot is free.
    assert_eq!(pair.client.counters().time_wait_connections, 1);
    assert!(matches!(
        pair.client.connection_info(client),
        Err(Error::InvalidHandle)
    ));
    assert!(in_use(
        pair.client.connect_from(server_address, Some(40000))
    ));
    assert!(ports_exhausted(pair.client.connect(server_address)));
    let other = SocketAddr::new(address(2), PORT + 1);
    let second = pair.server.listen(PORT + 1, 8).unwrap();
    let elsewhere = pair.client.connect(other).unwrap();
    assert_eq!(local_port(&pair.client, elsewhere), 40000);
    pair.accepted_from(second);
    pair.client.abort(elsewhere).unwrap();
    pair.steps(4);
    pair.reclaim(client);
    assert_eq!(pair.client.counters().time_wait_connections, 0);
    let next = pair.client.connect(server_address).unwrap();
    assert_eq!(local_port(&pair.client, next), 40000);
    pair.accepted();
}

// Ports run out per destination: one destination takes each port of the
// range once and then none, while another destination takes them all
// again; an aborted connection's port is its destination's again once its
// reset is sent, as Linux's tcp_close frees the port with the socket.
#[test]
fn an_ephemeral_range_runs_out_per_destination() {
    // Two ports to each of two destinations hold four of the eight slots.
    let mut pair = Pair::new(40000..=40001, 50000..=50000);
    let second = pair.server.listen(PORT + 1, 8).unwrap();
    let mut opened = Vec::new();
    for to in [PORT, PORT + 1] {
        let server_address = SocketAddr::new(address(2), to);
        let mut ports: Vec<u16> = (0..2)
            .map(|_| {
                let id = pair.client.connect(server_address).unwrap();
                opened.push(id);
                local_port(&pair.client, id)
            })
            .collect();
        // Slots remain; this destination's ports do not.
        assert!(ports_exhausted(pair.client.connect(server_address)));
        ports.sort_unstable();
        assert_eq!(ports, [40000, 40001]);
    }
    pair.steps(4);
    assert!(pair.server.accept(pair.listener).is_ok());
    assert!(pair.server.accept(second).is_ok());
    let first = SocketAddr::new(address(2), PORT);
    let freed = local_port(&pair.client, opened[1]);
    pair.client.abort(opened[1]).unwrap();
    pair.steps(4);
    assert!(matches!(
        pair.client.connection_info(opened[1]),
        Err(Error::InvalidHandle)
    ));
    let next = pair.client.connect(first).unwrap();
    assert_eq!(local_port(&pair.client, next), freed);
    assert!(ports_exhausted(pair.client.connect(first)));
    assert!(ports_exhausted(
        pair.client.connect(SocketAddr::new(address(2), PORT + 1))
    ));
}

// A destination whose ephemeral ports are all taken refuses an open with
// AddressNotAvailable while slots remain, as Linux's __inet_hash_connect
// returns EADDRNOTAVAIL; a full table refuses one with Capacity while the
// destination still has ports.
#[test]
fn port_exhaustion_and_a_full_table_are_told_apart() {
    let (a, b) = (Queue::default(), Queue::default());
    let mut client = built(1, &a, &b, [1; 32], |config| {
        config.ephemeral_ports = 40000..=40003;
        config.tcp.max_connections = 6;
    });
    let first = SocketAddr::new(address(2), PORT);
    let second = SocketAddr::new(address(2), PORT + 1);
    for _ in 0..4 {
        client.connect(first).unwrap();
    }
    // Two slots remain; the first destination's ports do not.
    assert!(ports_exhausted(client.connect(first)));
    for _ in 0..2 {
        client.connect(second).unwrap();
    }
    // The second destination has two ports left; no slot is.
    assert!(slots_exhausted(client.connect(second)));
    assert!(slots_exhausted(client.connect(first)));
}

// The bind conflict rules, as Linux's bind bucket keeps them. A port a
// listener or an explicit open took (bind(), fastreuse >= 0) is no
// ephemeral open's, for any peer, and is refused to explicit opens. A port
// an ephemeral open took is shared by ephemeral opens to other
// destinations and refused to explicit ones, a bind() without
// SO_REUSEADDR, which the native API has not. A closing listener holds its
// port until a drive frees its slot.
#[test]
fn listeners_and_explicit_opens_take_their_ports() {
    let mut pair = Pair::new(40000..=40000, PORT..=PORT + 2);
    let client_address = SocketAddr::new(address(1), 7000);
    let other_client = SocketAddr::new(address(1), 7001);
    let third_client = SocketAddr::new(address(1), 7002);
    assert!(in_use(pair.server.connect_from(client_address, Some(PORT))));
    assert!(matches!(
        pair.server.connect_from(client_address, Some(0)),
        Err(Error::InvalidConfig(_))
    ));
    let explicit = pair
        .server
        .connect_from(client_address, Some(PORT + 1))
        .unwrap();
    assert_eq!(local_port(&pair.server, explicit), PORT + 1);
    assert!(in_use(
        pair.server.connect_from(other_client, Some(PORT + 1))
    ));
    // Neither the listener's port nor the explicit one is ephemeral; the
    // third is, for each destination once.
    for peer in [client_address, other_client, third_client] {
        let ephemeral = pair.server.connect(peer).unwrap();
        assert_eq!(local_port(&pair.server, ephemeral), PORT + 2);
        assert!(ports_exhausted(pair.server.connect(peer)));
    }
    assert!(in_use(pair.server.connect_from(
        SocketAddr::new(address(1), 7003),
        Some(PORT + 2)
    )));
    pair.server.close_listener(pair.listener).unwrap();
    assert!(in_use(pair.server.connect_from(client_address, Some(PORT))));
    assert!(ports_exhausted(pair.server.connect(client_address)));
    pair.step();
    let reused = pair.server.connect(client_address).unwrap();
    assert_eq!(local_port(&pair.server, reused), PORT);
}

// The connections a listener accepted share its port, and keep it taken
// after the listener is gone.
#[test]
fn accepted_connections_keep_their_listeners_port() {
    let mut pair = Pair::new(40000..=40001, 50000..=50000);
    let server_address = SocketAddr::new(address(2), PORT);
    let client_address = SocketAddr::new(address(1), 7000);
    pair.client.connect(server_address).unwrap();
    let first = pair.accepted();
    pair.client.connect(server_address).unwrap();
    let second = pair.accepted();
    assert_eq!(local_port(&pair.server, first), PORT);
    assert_eq!(local_port(&pair.server, second), PORT);
    pair.server.close_listener(pair.listener).unwrap();
    pair.steps(2);
    assert!(matches!(
        pair.server.acceptable(pair.listener),
        Err(Error::InvalidHandle)
    ));
    assert!(in_use(pair.server.connect_from(client_address, Some(PORT))));
    pair.server.abort(first).unwrap();
    pair.steps(4);
    assert!(in_use(pair.server.connect_from(client_address, Some(PORT))));
}

// A full table of connections or listeners refuses opens until a slot is
// freed, an aborted connection's once its reset is sent and a closed
// listener's at the next drive, and then gives back that slot only, under a
// handle its old one cannot reach.
#[test]
fn a_full_table_takes_again_only_the_slots_freed() {
    let mut pair = Pair::new(40000..=40015, 50000..=50000);
    let server_address = SocketAddr::new(address(2), PORT);
    let opened: Vec<_> = (0..8)
        .map(|_| pair.client.connect(server_address).unwrap())
        .collect();
    // Ports remain; slots do not.
    assert!(slots_exhausted(pair.client.connect(server_address)));
    pair.steps(4);
    pair.client.abort(opened[3]).unwrap();
    pair.steps(4);
    let next = pair.client.connect(server_address).unwrap();
    assert!(!opened.contains(&next));
    assert!(matches!(
        pair.client.connection_info(opened[3]),
        Err(Error::InvalidHandle)
    ));
    assert!(slots_exhausted(pair.client.connect(server_address)));

    let second = pair.server.listen(PORT + 1, 8).unwrap();
    assert!(slots_exhausted(pair.server.listen(PORT + 2, 8)));
    pair.server.close_listener(second).unwrap();
    assert!(slots_exhausted(pair.server.listen(PORT + 2, 8)));
    pair.step();
    let third = pair.server.listen(PORT + 2, 8).unwrap();
    assert_ne!(third, second);
    assert!(matches!(
        pair.server.acceptable(second),
        Err(Error::InvalidHandle)
    ));
    assert!(pair.server.acceptable(third).is_ok());
    assert!(slots_exhausted(pair.server.listen(PORT + 3, 8)));
}

// A server that closes first frees each connection's slot once TIME-WAIT
// holds only its tuple: four times its eight slots of short connections
// complete within one TIME-WAIT period.
#[test]
fn server_closed_connections_beyond_the_slots_within_one_time_wait() {
    // Ports enough that the client takes no tuple in the server's
    // TIME-WAIT, which would reopen it.
    let mut pair = Pair::new(40000..=50000, 50000..=50000);
    let server_address = SocketAddr::new(address(2), PORT);
    for n in 1..=32 {
        let client = pair.client.connect(server_address).unwrap();
        let server = pair.accepted();
        pair.server.close(server).unwrap();
        for _ in 0..100 {
            pair.step();
            if matches!(
                pair.client.try_read(client, &mut [0; 8]),
                Ok(ReadOutcome::Eof)
            ) {
                break;
            }
        }
        pair.client.close(client).unwrap();
        for _ in 0..100 {
            pair.step();
            if pair.server.counters().time_wait_connections == n
                && matches!(
                    pair.server.connection_info(server),
                    Err(Error::InvalidHandle)
                )
            {
                break;
            }
        }
        assert_eq!(pair.server.counters().time_wait_connections, n);
    }
    assert!(pair.now < pair.server.config().tcp.connection.time_wait_us);
}

// Past max_time_wait records, a server-closed connection closes without
// TIME-WAIT, and Counters reports it as Linux's TCPTimeWaitOverflow.
#[test]
fn server_closed_connections_past_the_records_overflow() {
    let mut pair = Pair::with_server_records(40000..=40100, 50000..=50000, Some(2));
    let server_address = SocketAddr::new(address(2), PORT);
    for n in 1..=4usize {
        let client = pair.client.connect(server_address).unwrap();
        let server = pair.accepted();
        pair.server.close(server).unwrap();
        for _ in 0..100 {
            pair.step();
            if matches!(
                pair.client.try_read(client, &mut [0; 8]),
                Ok(ReadOutcome::Eof)
            ) {
                break;
            }
        }
        pair.client.close(client).unwrap();
        for _ in 0..100 {
            pair.step();
            if matches!(
                pair.server.connection_info(server),
                Err(Error::InvalidHandle)
            ) {
                break;
            }
        }
        let counters = pair.server.counters();
        assert_eq!(counters.time_wait_connections, n.min(2), "{n}");
        assert_eq!(
            counters.time_wait_overflows,
            n.saturating_sub(2) as u64,
            "{n}"
        );
    }
}

// Each destination starts at an offset of its own, RFC 6056 Algorithm 4's
// keyed hash of the addresses and the remote port, under a key the
// Network derives from its secret: 16 destinations take ports of the
// default range (Linux's ip_local_port_range) in no one sequence, the same
// for the same secret and others for another.
#[test]
fn each_destination_starts_at_its_own_secret_offset() {
    let firsts = |secret: u8| -> Vec<u16> {
        let (a, b) = (Queue::default(), Queue::default());
        let mut client = built(1, &a, &b, [secret; 32], |config| {
            config.tcp.max_connections = 16;
        });
        assert_eq!(client.config().ephemeral_ports, 32768..=60999);
        (0..16)
            .map(|k| {
                let id = client
                    .connect(SocketAddr::new(address(2), PORT + k))
                    .unwrap();
                local_port(&client, id)
            })
            .collect()
    };
    let ports = firsts(1);
    assert!(ports.iter().all(|port| (32768..=60999).contains(port)));
    assert!(ports.windows(2).any(|w| w[0] != w[1]));
    // Not one counter's run either, as a global next_ephemeral gives.
    assert!(!ports.windows(2).all(|w| w[1].wrapping_sub(w[0]) <= 16));
    assert_eq!(ports, firsts(1));
    let other = firsts(2);
    assert!(
        ports.iter().zip(&other).filter(|(a, b)| a == b).count() < 4,
        "{ports:?} {other:?}"
    );
}

// The proxy case: a client that opens and closes connections to 16
// destinations from the default range keeps connecting while 17024 of its
// connections are in TIME-WAIT, past the 16384 NetworkConfig::new's former
// range held when a port was exclusive whatever the peer. The records
// share ports across destinations: fewer ports than records.
#[test]
fn a_proxy_keeps_connecting_with_17k_connections_in_time_wait() {
    const DESTINATIONS: u16 = 16;
    const BATCH: usize = 64;
    const RECORDS: usize = 17_024;
    let (a, b) = (Queue::default(), Queue::default());
    let mut client = built(1, &a, &b, [1; 32], |config| {
        config.tcp.max_connections = 2 * BATCH;
        config.tcp.max_time_wait = 2 * RECORDS;
    });
    let mut server = built(2, &b, &a, [2; 32], |config| {
        config.tcp.max_connections = 2 * BATCH;
        config.tcp.max_listeners = usize::from(DESTINATIONS);
    });
    let listeners: Vec<ListenerId> = (0..DESTINATIONS)
        .map(|k| server.listen(PORT + k, BATCH).unwrap())
        .collect();
    let mut now = 0;
    let mut step = |client: &mut Network<Wire>, server: &mut Network<Wire>| {
        now += 200;
        client.drive(now, BUDGET).unwrap();
        server.drive(now, BUDGET).unwrap();
        drain(client);
        drain(server);
    };
    let mut ports = std::collections::HashSet::new();
    let mut opened = 0;
    while opened < RECORDS {
        let clients: Vec<ConnId> = (0..BATCH)
            .map(|i| {
                let k = (opened + i) as u16 % DESTINATIONS;
                let id = client
                    .connect(SocketAddr::new(address(2), PORT + k))
                    .unwrap_or_else(|e| panic!("connect {}: {e:?}", opened + i));
                ports.insert(local_port(&client, id));
                id
            })
            .collect();
        let mut servers = Vec::new();
        for _ in 0..200 {
            step(&mut client, &mut server);
            for &listener in &listeners {
                while let Ok(id) = server.accept(listener) {
                    servers.push(id);
                }
            }
            if servers.len() == BATCH {
                break;
            }
        }
        assert_eq!(servers.len(), BATCH);
        for &id in &clients {
            client.close(id).unwrap();
        }
        let mut closed = [false; BATCH];
        for _ in 0..200 {
            step(&mut client, &mut server);
            for (i, &id) in servers.iter().enumerate() {
                if !closed[i] && matches!(server.try_read(id, &mut [0; 8]), Ok(ReadOutcome::Eof)) {
                    server.close(id).unwrap();
                    closed[i] = true;
                }
            }
            if client.counters().time_wait_connections == opened + BATCH
                && clients
                    .iter()
                    .all(|&id| matches!(client.connection_info(id), Err(Error::InvalidHandle)))
            {
                break;
            }
        }
        opened += BATCH;
        assert_eq!(client.counters().time_wait_connections, opened);
    }
    // All within one TIME-WAIT, none reopened or expired.
    assert!(now < client.config().tcp.connection.time_wait_us);
    assert_eq!(client.counters().time_wait_overflows, 0);
    assert!(ports.len() < RECORDS, "{} ports", ports.len());
}

// The endpoint gives a reclaimed connection's slot to the next open; what
// the connection on it raises reaches that connection's handle, never the
// handle of the one the slot held before.
#[test]
fn a_reused_endpoint_slot_reports_to_its_own_connection() {
    let mut pair = Pair::new(40000..=40015, 50000..=50000);
    let server_address = SocketAddr::new(address(2), PORT);
    for _ in 0..4 {
        let earlier = pair.client.connect(server_address).unwrap();
        let _ = pair.accepted();
        pair.client.abort(earlier).unwrap();
        pair.steps(4);
        let client = pair.client.connect(server_address).unwrap();
        let server = pair.accepted();
        pair.server
            .try_write(server, b"slot", WriteOptions::default())
            .unwrap();
        let mut events = Vec::new();
        for _ in 0..8 {
            pair.now += 1000;
            pair.server.drive(pair.now, BUDGET).unwrap();
            pair.client.drive(pair.now, BUDGET).unwrap();
            events.extend(drain(&mut pair.client));
            drain(&mut pair.server);
        }
        assert!(events.contains(&Event::Readable(client)), "{events:?}");
        assert!(events.iter().all(|e| !matches!(
            e,
            Event::Readable(id) | Event::Connected(id) | Event::Writable(id)
                if *id == earlier
        )));
        let mut out = [0; 8];
        assert!(matches!(
            pair.client.try_read(client, &mut out),
            Ok(ReadOutcome::Data { len: 4, .. })
        ));
        assert_eq!(&out[..4], b"slot");
        pair.client.abort(client).unwrap();
        pair.server.abort(server).unwrap();
        pair.steps(4);
    }
}
