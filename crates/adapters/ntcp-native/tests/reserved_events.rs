// A connection whose output is reserved, its packet refused by a backend
// with no TX room, is used as any other (c151), as a Linux socket is while
// its device queue is full: every call takes effect at once and only its
// wire work waits for the reservation's end. Events are given as they are
// raised, each once. Debug builds check, after every drain that leaves
// nothing queued, that no connection has an event the ready queue misses.
// Two Networks over an in-memory IP wire whose transmit a test can refuse
// (WouldBlock).
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::*;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    rc::Rc,
};

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

struct Wire {
    incoming: Queue,
    outgoing: Queue,
    blocked: Rc<Cell<bool>>,
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
        if self.blocked.get() {
            return Ok(TxOutcome::WouldBlock);
        }
        self.outgoing.borrow_mut().push_back(packet.to_vec());
        Ok(TxOutcome::Submitted)
    }
}

const BUDGET: WorkBudget = WorkBudget::new(32, 32, 32, 32);
const PORT: u16 = 9000;
const FIN: u8 = 0x01;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;

fn address(side: u8) -> IpAddr {
    IpAddr::from([10, 78, 0, side])
}

fn network(side: u8, incoming: &Queue, outgoing: &Queue) -> Network<Wire> {
    let mut config = NetworkConfig::new(address(side), 1500);
    config.tcp.max_connections = 8;
    config.tcp.max_listeners = 2;
    let wire = Wire {
        incoming: incoming.clone(),
        outgoing: outgoing.clone(),
        blocked: Rc::default(),
    };
    Network::new(config, wire, [side; 32], 0).unwrap()
}

// One IPv4 TCP segment's flags, window field and payload length.
struct Segment {
    flags: u8,
    window: u16,
    payload: usize,
}
fn segment(packet: &[u8]) -> Segment {
    let ip = usize::from(packet[0] & 0x0f) * 4;
    let tcp = &packet[ip..];
    let header = usize::from(tcp[12] >> 4) * 4;
    Segment {
        flags: tcp[13],
        window: u16::from_be_bytes([tcp[14], tcp[15]]),
        payload: tcp.len() - header,
    }
}

struct Pair {
    client: Network<Wire>,
    server: Network<Wire>,
    listener: ListenerId,
    // What the server sent the client and the client has not received.
    to_client: Queue,
    // What the client sent the server and the server has not received.
    to_server: Queue,
    now: u64,
}
impl Pair {
    fn new() -> Self {
        let (a, b) = (Queue::default(), Queue::default());
        let client = network(1, &a, &b);
        let mut server = network(2, &b, &a);
        let listener = server.listen(PORT, 4).unwrap();
        Self {
            client,
            server,
            listener,
            to_client: a,
            to_server: b,
            now: 0,
        }
    }
    fn step(&mut self) {
        self.now += 1000;
        self.client.drive(self.now, BUDGET).unwrap();
        self.server.drive(self.now, BUDGET).unwrap();
    }
    // The client alone, its output collected: what it sent the server.
    fn client_output(&mut self) -> Vec<Segment> {
        self.now += 1000;
        self.client.drive(self.now, BUDGET).unwrap();
        self.to_server
            .borrow()
            .iter()
            .map(|packet| segment(packet))
            .collect()
    }
    // A connection from the client, accepted, with the events of the
    // handshake drained on both sides; Nagle on or off.
    fn connected_with(&mut self, nodelay: bool) -> (ConnId, ConnId) {
        let client = self
            .client
            .connect(SocketAddr::new(address(2), PORT))
            .unwrap();
        for _ in 0..100 {
            self.step();
            if let Ok(server) = self.server.accept(self.listener) {
                self.client.set_nodelay(client, nodelay).unwrap();
                self.server.set_nodelay(server, nodelay).unwrap();
                self.step();
                self.step();
                assert_eq!(count(&drain(&mut self.client), Event::Connected(client)), 1);
                drain(&mut self.server);
                return (client, server);
            }
        }
        panic!("handshake did not finish");
    }
    fn connected(&mut self) -> (ConnId, ConnId) {
        self.connected_with(true)
    }
    // The client's output reserved: `len` bytes written while the backend
    // has no TX room, held by the drive that tried to send them.
    fn reserve(&mut self, client: ConnId, len: usize) -> Rc<Cell<bool>> {
        let blocked = self.client.backend().blocked.clone();
        blocked.set(true);
        let receipt = self
            .client
            .try_write(client, &vec![3; len], WriteOptions::default())
            .unwrap();
        assert_eq!(receipt.accepted, len);
        self.now += 1000;
        self.client.drive(self.now, BUDGET).unwrap();
        assert!(self.to_server.borrow().is_empty());
        blocked
    }
    // What the server reads from `server` until `len` bytes or the end of
    // the stream.
    fn server_reads(&mut self, server: ConnId, len: usize) -> (usize, Option<ReadOutcome>) {
        let mut read = 0;
        let mut out = [0; 4096];
        for _ in 0..100 {
            self.step();
            loop {
                match self.server.try_read(server, &mut out) {
                    Ok(ReadOutcome::Data { len, .. }) => read += len,
                    Ok(other) => return (read, Some(other)),
                    Err(Error::WouldBlock(_)) => break,
                    Err(error) => panic!("{error:?}"),
                }
            }
            if read >= len {
                return (read, None);
            }
        }
        (read, None)
    }
}

// Every event, over as many drains as it takes.
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

fn count(events: &[Event], event: Event) -> usize {
    events.iter().filter(|&&e| e == event).count()
}

// The client's ACK of the SYN-ACK refused: the connection is ESTABLISHED,
// and Connected is given at once, once; a write and set_nodelay take
// effect, the write's data following the ACK once there is TX room.
#[test]
fn connected_is_given_while_the_ack_of_the_syn_ack_is_reserved() {
    let mut pair = Pair::new();
    let blocked = pair.client.backend().blocked.clone();
    let client = pair
        .client
        .connect(SocketAddr::new(address(2), PORT))
        .unwrap();
    pair.now += 1000;
    pair.client.drive(pair.now, BUDGET).unwrap();
    assert!(drain(&mut pair.client).is_empty());
    pair.server.drive(pair.now, BUDGET).unwrap();
    assert!(!pair.to_client.borrow().is_empty());
    blocked.set(true);
    pair.step();
    assert_eq!(drain(&mut pair.client), [Event::Connected(client)]);
    pair.client.set_nodelay(client, true).unwrap();
    let receipt = pair
        .client
        .try_write(client, b"x", WriteOptions::default())
        .unwrap();
    assert_eq!(receipt.accepted, 1);
    for _ in 0..3 {
        pair.step();
        assert!(drain(&mut pair.client).is_empty());
    }
    assert!(pair.to_server.borrow().is_empty());
    assert!(pair.server.accept(pair.listener).is_err());
    blocked.set(false);
    pair.step();
    assert!(drain(&mut pair.client).is_empty());
    let server = pair.server.accept(pair.listener).unwrap();
    assert_eq!(pair.server_reads(server, 1).0, 1);
    assert!(drain(&mut pair.client).is_empty());
}

// Data arrived whose ACK is refused: Readable is given at once, once, the
// data is read and readiness tells of it; only the ACK waits for TX room.
#[test]
fn readable_is_given_while_the_ack_of_the_data_is_reserved() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    let blocked = pair.client.backend().blocked.clone();
    blocked.set(true);
    pair.server
        .try_write(server, &[7; 600], WriteOptions::default())
        .unwrap();
    pair.server.drive(pair.now, BUDGET).unwrap();
    assert!(!pair.to_client.borrow().is_empty());
    pair.step();
    assert!(pair.client.readiness(client).unwrap().readable);
    assert_eq!(drain(&mut pair.client), [Event::Readable(client)]);
    assert!(matches!(
        pair.client.try_read(client, &mut [0; 1024]),
        Ok(ReadOutcome::Data { len: 600, .. })
    ));
    assert!(!pair.client.readiness(client).unwrap().readable);
    for _ in 0..3 {
        pair.step();
        assert!(drain(&mut pair.client).is_empty());
    }
    assert!(pair.to_server.borrow().is_empty());
    blocked.set(false);
    let sent = pair.client_output();
    assert!(!sent.is_empty() && sent.iter().all(|s| s.payload == 0));
    assert!(drain(&mut pair.client).is_empty());
    assert!(matches!(
        pair.client.try_read(client, &mut [0; 1024]),
        Err(Error::WouldBlock(BlockReason::Receive))
    ));
}

// A write is queued while the connection's output is reserved; only a full
// send buffer refuses one (SendBuffer). What was queued leaves in order
// once there is TX room, and Writable is given once there is room again.
#[test]
fn a_write_is_queued_while_the_output_is_reserved() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    let blocked = pair.reserve(client, 100);
    let mut queued = 100;
    loop {
        match pair
            .client
            .try_write(client, &[4; 65536], WriteOptions::default())
        {
            Ok(receipt) => queued += receipt.accepted,
            Err(error) => {
                assert!(
                    matches!(error, Error::WouldBlock(BlockReason::SendBuffer)),
                    "{error:?}"
                );
                break;
            }
        }
    }
    assert!(queued > 100);
    assert!(pair.to_server.borrow().is_empty());
    blocked.set(false);
    assert_eq!(pair.server_reads(server, queued).0, queued);
    assert_eq!(count(&drain(&mut pair.client), Event::Writable(client)), 1);
}

// try_write_vectored follows try_write (c151): a reservation does not
// refuse it, and its slices leave as one send once there is TX room, PUSH
// on the last byte only.
#[test]
fn a_vectored_write_is_queued_while_the_output_is_reserved() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    let blocked = pair.reserve(client, 100);
    let receipt = pair
        .client
        .try_write_vectored(
            client,
            &[
                std::io::IoSlice::new(&[6; 24]),
                std::io::IoSlice::new(&[7; 1000]),
            ],
        )
        .unwrap();
    assert_eq!(receipt.accepted, 1024);
    assert!(pair.to_server.borrow().is_empty());
    blocked.set(false);
    let sent = pair.client_output();
    let data: Vec<_> = sent.iter().filter(|s| s.payload != 0).collect();
    assert_eq!(data.len(), 2);
    assert_eq!((data[0].payload, data[1].payload), (100, 1024));
    assert_ne!(data[1].flags & PSH, 0);
    assert_eq!(pair.server_reads(server, 1124).0, 1124);
    assert!(drain(&mut pair.client).is_empty());
}

// set_nodelay under a reservation applies at once; the frames Nagle held
// leave as the reservation ends, with no ACK from the peer.
#[test]
fn nodelay_pushes_held_frames_as_the_reservation_ends() {
    for nodelay in [false, true] {
        let mut pair = Pair::new();
        let (client, _) = pair.connected_with(false);
        let blocked = pair.reserve(client, 100);
        // Held by Nagle behind the reserved short segment.
        pair.client
            .try_write(client, &[5; 100], WriteOptions::default())
            .unwrap();
        if nodelay {
            pair.client.set_nodelay(client, true).unwrap();
        }
        blocked.set(false);
        let sent = pair.client_output();
        let payload: Vec<usize> = sent.iter().map(|s| s.payload).filter(|&n| n != 0).collect();
        if nodelay {
            assert_eq!(payload, [100, 100]);
        } else {
            assert_eq!(payload, [100]);
        }
        assert!(drain(&mut pair.client).is_empty());
    }
}

// shutdown under a reservation queues the FIN at once: writes are refused
// from then on, and the FIN leaves after the reserved data. Still
// connecting, the shutdown ends the connection once its SYN is out.
#[test]
fn shutdown_queues_the_fin_while_the_output_is_reserved() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    let blocked = pair.reserve(client, 100);
    pair.client.shutdown_write(client).unwrap();
    let write = pair
        .client
        .try_write(client, b"late", WriteOptions::default());
    assert!(write.is_err() && !write.unwrap_err().is_would_block());
    blocked.set(false);
    let sent = pair.client_output();
    assert_eq!(sent[0].payload, 100);
    assert!(sent.iter().any(|s| s.flags & FIN != 0));
    assert_eq!(
        pair.server_reads(server, usize::MAX),
        (100, Some(ReadOutcome::Eof))
    );
    assert!(drain(&mut pair.client).is_empty());

    let mut pair = Pair::new();
    let blocked = pair.client.backend().blocked.clone();
    blocked.set(true);
    let client = pair
        .client
        .connect(SocketAddr::new(address(2), PORT))
        .unwrap();
    pair.now += 1000;
    pair.client.drive(pair.now, BUDGET).unwrap();
    pair.client.shutdown_write(client).unwrap();
    assert!(drain(&mut pair.client).is_empty());
    blocked.set(false);
    for _ in 0..3 {
        pair.step();
    }
    // As without a reservation, the end is readable (Eof).
    assert_eq!(
        drain(&mut pair.client),
        [
            Event::Closed {
                connection: client,
                reason: Some(CloseReason::Normal)
            },
            Event::Readable(client)
        ]
    );
    assert_eq!(
        pair.client.try_read(client, &mut [0; 16]).unwrap(),
        ReadOutcome::Eof
    );
}

// The buffer setters apply at once under a reservation; the larger receive
// window shows in the next segment built, the reserved one keeping the
// window it was built with.
#[test]
fn buffer_setters_apply_while_the_output_is_reserved() {
    let mut pair = Pair::new();
    let (client, _) = pair.connected();
    let blocked = pair.reserve(client, 100);
    let (send, receive) = pair.client.buffer_capacities(client).unwrap();
    pair.client.set_send_buffer(client, send * 2).unwrap();
    pair.client.set_receive_buffer(client, receive * 4).unwrap();
    assert_eq!(
        pair.client.buffer_capacities(client).unwrap(),
        (send * 2, receive * 4)
    );
    pair.client
        .try_write(client, &[6; 100], WriteOptions::default())
        .unwrap();
    blocked.set(false);
    let sent = pair.client_output();
    let data: Vec<&Segment> = sent.iter().filter(|s| s.payload != 0).collect();
    assert_eq!(data.len(), 2);
    assert!(data[1].window > data[0].window);
    assert!(drain(&mut pair.client).is_empty());
}

// close, abort and close_listener under a reservation return Ok and take
// effect once the reservation ends: a FIN, a reset, the port free again.
#[test]
fn close_abort_and_close_listener_wait_for_the_reservation() {
    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    let blocked = pair.reserve(client, 100);
    pair.client.close(client).unwrap();
    blocked.set(false);
    assert_eq!(
        pair.server_reads(server, usize::MAX),
        (100, Some(ReadOutcome::Eof))
    );

    let mut pair = Pair::new();
    let (client, server) = pair.connected();
    let blocked = pair.reserve(client, 100);
    pair.client.abort(client).unwrap();
    assert_eq!(
        pair.client
            .try_write(client, b"x", WriteOptions::default())
            .err()
            .map(|e| e.is_would_block()),
        Some(false)
    );
    blocked.set(false);
    let sent = pair.client_output();
    assert!(sent.iter().any(|s| s.flags & RST != 0));
    // The abort withdraws the reserved data, so the server first answers
    // the reset beyond what it received with a challenge ACK (RFC 5961),
    // which the client's closed tuple resets.
    let mut ended = None;
    for _ in 0..10 {
        pair.step();
        match pair.server.try_read(server, &mut [0; 1024]) {
            Err(Error::WouldBlock(_)) | Ok(ReadOutcome::Data { .. }) => {}
            other => {
                ended = Some(other);
                break;
            }
        }
    }
    let ended = ended.unwrap();
    assert!(
        matches!(
            ended,
            Err(Error::ConnectionClosed(Some(CloseReason::Reset)))
        ),
        "{ended:?}"
    );

    // A listener whose unaccepted child's SYN-ACK is reserved.
    let mut pair = Pair::new();
    let blocked = pair.server.backend().blocked.clone();
    blocked.set(true);
    pair.client
        .connect(SocketAddr::new(address(2), PORT))
        .unwrap();
    pair.step();
    assert!(pair.to_client.borrow().is_empty());
    pair.server.close_listener(pair.listener).unwrap();
    assert!(matches!(
        pair.server.accept(pair.listener),
        Err(Error::InvalidHandle)
    ));
    pair.step();
    blocked.set(false);
    for _ in 0..3 {
        pair.step();
    }
    pair.server.listen(PORT, 4).unwrap();
}

// A child whose output is reserved (its ACK of the client's first data) is
// acceptable at once, once, and accepted with its data readable.
#[test]
fn a_child_whose_output_is_reserved_is_accepted() {
    let mut pair = Pair::new();
    let client = pair
        .client
        .connect(SocketAddr::new(address(2), PORT))
        .unwrap();
    pair.client.set_nodelay(client, true).unwrap();
    pair.now += 1000;
    pair.client.drive(pair.now, BUDGET).unwrap();
    pair.server.drive(pair.now, BUDGET).unwrap();
    pair.now += 1000;
    pair.client.drive(pair.now, BUDGET).unwrap();
    assert_eq!(drain(&mut pair.client), [Event::Connected(client)]);
    pair.client
        .try_write(client, &[2; 100], WriteOptions::default())
        .unwrap();
    pair.client.drive(pair.now, BUDGET).unwrap();
    pair.server.backend().blocked.set(true);
    pair.server.drive(pair.now, BUDGET).unwrap();
    assert!(pair.to_client.borrow().is_empty());
    assert_eq!(drain(&mut pair.server), [Event::Acceptable(pair.listener)]);
    let server = pair.server.accept(pair.listener).unwrap();
    assert!(matches!(
        pair.server.try_read(server, &mut [0; 1024]),
        Ok(ReadOutcome::Data { len: 100, .. })
    ));
    pair.server.backend().blocked.set(false);
    let mut events = drain(&mut pair.server);
    for _ in 0..3 {
        pair.step();
        events.extend(drain(&mut pair.server));
    }
    assert_eq!(count(&events, Event::Acceptable(pair.listener)), 0);
    assert_eq!(count(&events, Event::Connected(server)), 1);
}
