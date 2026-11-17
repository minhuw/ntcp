// Received frames held by reference (PacketIo::rx_frame_budget): a Network
// on a FramePool backend (the in-memory stand-in for a DPDK queue) against
// the same Network on the copying wire it wraps. The wire and the streams
// are the same; the pool's frames are held until read, never past ¾ of the
// budget (copies beyond it), retained input keeps its frame, and every
// frame is back once the data is read.
mod frame_pool;

use frame_pool::{ELEMENT, FramePool};
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::*;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    rc::Rc,
};

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

const BUDGET: WorkBudget = WorkBudget::new(64, 64, 64, 64);
const PORT: u16 = 9000;
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 80, 0, 1);
const SERVER: Ipv4Addr = Ipv4Addr::new(10, 80, 0, 2);

struct Wire {
    incoming: Queue,
    outgoing: Queue,
    // Every frame this side sent, in order.
    sent: Rc<RefCell<Vec<Vec<u8>>>>,
    // No TX room while set.
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
        self.sent.borrow_mut().push(packet.to_vec());
        self.outgoing.borrow_mut().push_back(packet.to_vec());
        Ok(TxOutcome::Submitted)
    }
}

// The server's backend: the wire itself, or a pool over it.
enum Server {
    Copy(Wire),
    Pool(FramePool<Wire>),
}
macro_rules! both {
    ($s:expr, $io:ident => $e:expr) => {
        match $s {
            Server::Copy($io) => $e,
            Server::Pool($io) => $e,
        }
    };
}
impl PacketIo for Server {
    fn layer(&self) -> PacketLayer {
        both!(self, io => io.layer())
    }
    fn max_packet_len(&self) -> Option<usize> {
        both!(self, io => io.max_packet_len())
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        both!(self, io => io.receive(out))
    }
    fn receive_with_metadata(
        &mut self,
        out: &mut [u8],
    ) -> io::Result<Option<ntcp_io::ReceivedPacket>> {
        both!(self, io => io.receive_with_metadata(out))
    }
    fn receive_frame(&mut self, scratch: &mut [u8]) -> io::Result<Option<ntcp_io::ReceivedFrame>> {
        both!(self, io => io.receive_frame(scratch))
    }
    fn rx_frame_budget(&self) -> Option<usize> {
        both!(self, io => io.rx_frame_budget())
    }
    fn rx_frames_outstanding(&self) -> Option<usize> {
        both!(self, io => io.rx_frames_outstanding())
    }
    fn device_counters(&self) -> ntcp_io::DeviceCounters {
        both!(self, io => io.device_counters())
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        both!(self, io => io.transmit(packet))
    }
}

struct Net {
    server: Network<Server>,
    client: Network<Wire>,
    listener: ListenerId,
    server_sent: Rc<RefCell<Vec<Vec<u8>>>>,
    client_sent: Rc<RefCell<Vec<Vec<u8>>>>,
    blocked: Rc<Cell<bool>>,
    now: u64,
}
impl Net {
    // `pool`: the server receives into a pool of this many elements, of
    // which it may hold `budget`.
    fn new(pool: Option<(usize, usize)>) -> Self {
        let (a, b) = (Queue::default(), Queue::default());
        let config = |address: Ipv4Addr| {
            let mut config = NetworkConfig::new(IpAddr::V4(address), 1500);
            config.tcp.max_connections = 8;
            config.tcp.max_listeners = 1;
            config
        };
        let blocked = Rc::new(Cell::new(false));
        let (server_sent, client_sent) = (Rc::default(), Rc::default());
        let client = Wire {
            incoming: a.clone(),
            outgoing: b.clone(),
            sent: Rc::clone(&client_sent),
            blocked: Rc::default(),
        };
        let wire = Wire {
            incoming: b,
            outgoing: a,
            sent: Rc::clone(&server_sent),
            blocked: Rc::clone(&blocked),
        };
        let io = match pool {
            None => Server::Copy(wire),
            Some((elements, budget)) => Server::Pool(FramePool::new(wire, elements, budget)),
        };
        let mut server = Network::new(config(SERVER), io, [2; 32], 0).unwrap();
        let client = Network::new(config(CLIENT), client, [1; 32], 0).unwrap();
        let listener = server.listen(PORT, 8).unwrap();
        Self {
            server,
            client,
            listener,
            server_sent,
            client_sent,
            blocked,
            now: 0,
        }
    }
    fn step(&mut self) {
        self.now += 1000;
        self.client.drive(self.now, BUDGET).unwrap();
        self.server.drive(self.now, BUDGET).unwrap();
    }
    // A connection, accepted: (client, server) handles.
    fn connect(&mut self) -> (ConnId, ConnId) {
        let client = self
            .client
            .connect(SocketAddr::new(SERVER.into(), PORT))
            .unwrap();
        for _ in 0..100 {
            self.step();
            if let Ok(server) = self.server.accept(self.listener) {
                self.step();
                return (client, server);
            }
        }
        panic!("no connection");
    }
    // What the server can read now.
    fn read(&mut self, id: ConnId) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0; 65536];
        while let Ok(ReadOutcome::Data { len, .. }) = self.server.try_read(id, &mut buf) {
            out.extend_from_slice(&buf[..len]);
        }
        out
    }
    fn held(&self) -> usize {
        self.server.counters().rx_frames_held
    }
}
fn data(len: usize) -> Vec<u8> {
    (0..len).map(|n| (n * 7 % 251) as u8).collect()
}

// A request/response exchange and a bulk transfer, read as it arrives:
// the same frames both ways, the same streams, and, with the pool, every
// frame back once read and none copied.
#[test]
fn frames_by_reference_are_the_copying_wire() {
    let run = |pool| {
        let mut net = Net::new(pool);
        let (client, server) = net.connect();
        let mut received = Vec::new();
        for round in 0..20 {
            let request = data(18 + round * 5);
            net.client
                .try_write(client, &request, WriteOptions::default())
                .unwrap();
            net.step();
            let got = net.read(server);
            assert_eq!(got, request);
            received.extend(got);
            net.server
                .try_write(server, &data(71), WriteOptions::default())
                .unwrap();
            net.step();
        }
        let bulk = data(300_000);
        let mut written = 0;
        for _ in 0..2000 {
            if written < bulk.len()
                && let Ok(receipt) =
                    net.client
                        .try_write(client, &bulk[written..], WriteOptions::default())
            {
                written += receipt.accepted;
            }
            net.step();
            received.extend(net.read(server));
            if received.len() == 20 * 18 + 5 * 190 + bulk.len() {
                break;
            }
        }
        assert!(received.ends_with(&bulk));
        let counters = net.server.counters();
        if pool.is_some() {
            assert_eq!(counters.rx_frames_held, 0, "every frame back");
            assert_eq!(counters.rx_frames_copied, 0);
        }
        assert_eq!(counters.rx_missed, 0);
        let sent = (net.server_sent.take(), net.client_sent.take());
        (sent, received)
    };
    let copy = run(None);
    let pool = run(Some((4096, 4000)));
    assert_eq!(copy.1, pool.1, "streams");
    assert_eq!(copy.0.1, pool.0.1, "client frames");
    // The server's frames differ in their windows alone, and only in ACKs
    // the server sent with small segments unread (a frame's truesize is the
    // element, not the payload: Linux's on a page_pool NIC).
    let (copy, pool) = (&copy.0.0, &pool.0.0);
    assert_eq!(copy.len(), pool.len());
    let mut differ = Vec::new();
    for (n, (a, b)) in copy.iter().zip(pool).enumerate() {
        assert_eq!(a.len(), b.len(), "frame {n}");
        let mut x = a.clone();
        let mut y = b.clone();
        // Window and TCP checksum.
        for f in [&mut x, &mut y] {
            f[34..36].fill(0);
            f[36..38].fill(0);
        }
        assert_eq!(x, y, "frame {n} differs beyond its window");
        if a[34..36] != b[34..36] {
            differ.push((
                n,
                u16::from_be_bytes([a[34], a[35]]),
                u16::from_be_bytes([b[34], b[35]]),
            ));
        }
    }
    eprintln!(
        "windows differ in {} of {} server frames: {:?}",
        differ.len(),
        copy.len(),
        &differ[..differ.len().min(20)]
    );
}

// A reader that stops: frames are held up to ¾ of the budget, never past,
// and the arrivals beyond are copied; the pool never runs dry; once read,
// the data is whole and every frame back.
#[test]
fn a_stalled_reader_never_holds_past_three_quarters_of_the_budget() {
    let (elements, budget) = (64, 32);
    let mut net = Net::new(Some((elements, budget)));
    let (client, server) = net.connect();
    let bulk = data(1 << 20);
    let mut written = 0;
    let mut most = 0;
    for _ in 0..200 {
        if let Ok(receipt) = net
            .client
            .try_write(client, &bulk[written..], WriteOptions::default())
        {
            written += receipt.accepted;
        }
        net.step();
        most = most.max(net.held());
        assert!(net.held() <= budget * 3 / 4, "{}", net.held());
    }
    let stalled = net.server.counters();
    assert_eq!(most, budget * 3 / 4, "held up to ¾ F");
    assert!(stalled.rx_frames_copied > 0);
    assert_eq!(stalled.rx_missed, 0, "the pool never ran dry");
    let mut read = net.read(server);
    for _ in 0..2000 {
        if read.len() == bulk.len() {
            break;
        }
        if written < bulk.len()
            && let Ok(receipt) =
                net.client
                    .try_write(client, &bulk[written..], WriteOptions::default())
        {
            written += receipt.accepted;
        }
        net.step();
        read.extend(net.read(server));
    }
    assert_eq!(read, bulk);
    assert_eq!(net.held(), 0);
    // A held device frame is charged its element: the stalled queue held
    // ¾ F of them.
    assert!(ELEMENT * budget * 3 / 4 <= stalled.buffer_bytes);
}

// A segment for a connection whose output waits for TX room is retained
// with its frame, not a copy, and taken in once the room is back.
#[test]
fn retained_input_keeps_its_frame() {
    let mut net = Net::new(Some((64, 48)));
    let (client, server) = net.connect();
    // The server's reply waits for TX room: its output is reserved.
    net.blocked.set(true);
    net.server
        .try_write(server, b"reply", WriteOptions::default())
        .unwrap();
    net.step();
    net.client
        .try_write(client, b"request", WriteOptions::default())
        .unwrap();
    net.step();
    let counters = net.server.counters();
    assert_eq!(counters.retained_input, 1);
    assert_eq!((counters.rx_frames_held, counters.rx_frames_copied), (1, 0));
    net.blocked.set(false);
    net.step();
    net.step();
    assert_eq!(net.read(server), b"request");
    assert_eq!(net.server.counters().retained_input, 0);
    assert_eq!(net.held(), 0);
}

// The budget is the backend's unless the configuration lowers it, never
// above it, and a copying backend takes none.
#[test]
fn the_frame_budget_is_at_most_the_backends() {
    let wire = || Wire {
        incoming: Queue::default(),
        outgoing: Queue::default(),
        sent: Rc::default(),
        blocked: Rc::default(),
    };
    let mut config = NetworkConfig::new(IpAddr::V4(SERVER), 1500);
    config.rx_frame_budget = Some(16);
    assert!(Network::new(config.clone(), FramePool::new(wire(), 32, 16), [2; 32], 0).is_ok());
    assert!(matches!(
        Network::new(config.clone(), FramePool::new(wire(), 32, 15), [2; 32], 0),
        Err(Error::InvalidConfig(_))
    ));
    assert!(matches!(
        Network::new(config, wire(), [2; 32], 0),
        Err(Error::InvalidConfig(_))
    ));
}
