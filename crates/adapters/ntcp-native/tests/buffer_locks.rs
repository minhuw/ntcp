// Per-direction buffer sizes set through the Network, as SO_SNDBUF and
// SO_RCVBUF set them on a Linux socket: each sets one direction's size and
// locks it against autotuning (SOCK_SNDBUF_LOCK, SOCK_RCVBUF_LOCK), a
// listener's lock carries to the children it accepts, and a receive size
// locked before connect sets the SYN's window scale. Two Networks with
// NetworkConfig::new's defaults (64 KiB initial sizes, 32 MiB receive and
// 4 MiB send maxima) over an in-memory IP wire.
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::*;
use std::{
    cell::RefCell,
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    rc::Rc,
};

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;
// Every packet a side transmitted, in order.
type Sent = Rc<RefCell<Vec<Vec<u8>>>>;

struct Wire {
    incoming: Queue,
    outgoing: Queue,
    sent: Sent,
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
        self.sent.borrow_mut().push(packet.to_vec());
        self.outgoing.borrow_mut().push_back(packet.to_vec());
        Ok(TxOutcome::Submitted)
    }
}

// The TCP header of an IPv4 packet.
fn tcp(packet: &[u8]) -> &[u8] {
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    &packet[ihl..]
}

// The window scale option (kind 3) of a SYN.
fn window_scale(packet: &[u8]) -> Option<u8> {
    let header = tcp(packet);
    let mut options = &header[20..usize::from(header[12] >> 4) * 4];
    while let [kind, rest @ ..] = options {
        match kind {
            0 => return None,
            1 => options = rest,
            _ => {
                let len = usize::from(*rest.first()?).max(2).min(options.len());
                if *kind == 3 {
                    return options.get(2).copied();
                }
                options = &options[len..];
            }
        }
    }
    None
}

fn window_field(packet: &[u8]) -> usize {
    usize::from(u16::from_be_bytes([tcp(packet)[14], tcp(packet)[15]]))
}

// The SYNs (SYN or SYN-ACK) among `packets`.
fn syns(packets: &[Vec<u8>]) -> Vec<Vec<u8>> {
    packets
        .iter()
        .filter(|p| tcp(p)[13] & 0x02 != 0)
        .cloned()
        .collect()
}

// Linux's tcp_select_initial_window: rcv_wscale = ilog2(space) - 15,
// clamped to 0..=14, `space` the window it may offer (tcp_full_space,
// clamped by window_clamp).
fn linux_wscale(space: usize) -> u8 {
    (space.ilog2() as i32 - 15).clamp(0, 14) as u8
}

const BUDGET: WorkBudget = WorkBudget::new(32, 32, 32, 32);
const PORT: u16 = 9000;
const MS: u64 = 1000;

fn address(side: u8) -> IpAddr {
    IpAddr::from([10, 76, 0, side])
}

fn side_with(
    n: u8,
    incoming: &Queue,
    outgoing: &Queue,
    configure: impl FnOnce(&mut NetworkConfig, &Wire),
) -> (Network<Wire>, Sent) {
    let wire = Wire {
        incoming: incoming.clone(),
        outgoing: outgoing.clone(),
        sent: Rc::default(),
    };
    let sent = wire.sent.clone();
    let mut config = NetworkConfig::new(address(n), 1500);
    config.tcp.max_connections = 4;
    configure(&mut config, &wire);
    (Network::new(config, wire, [n; 32], 0).unwrap(), sent)
}

// A client and a server with NetworkConfig::new's defaults, the server
// listening.
struct Pair {
    client: Network<Wire>,
    client_sent: Sent,
    server: Network<Wire>,
    server_sent: Sent,
    listener: ListenerId,
    now: u64,
}
impl Pair {
    fn new() -> Self {
        Self::with(|_, _| ())
    }
    fn with(configure: impl Fn(&mut NetworkConfig, &Wire)) -> Self {
        let (a, b) = (Queue::default(), Queue::default());
        let (client, client_sent) = side_with(1, &a, &b, &configure);
        let (mut server, server_sent) = side_with(2, &b, &a, &configure);
        let listener = server.listen(PORT, 4).unwrap();
        Self {
            client,
            client_sent,
            server,
            server_sent,
            listener,
            now: 0,
        }
    }
    fn peer(&self) -> SocketAddr {
        SocketAddr::new(address(2), PORT)
    }
    fn step(&mut self) {
        self.now += MS;
        self.client.drive(self.now, BUDGET).unwrap();
        self.server.drive(self.now, BUDGET).unwrap();
    }
    // Drives until the server accepts the client's open.
    fn accept(&mut self) -> ConnId {
        let until = self.now + 100 * MS;
        loop {
            self.step();
            if let Ok(accepted) = self.server.accept(self.listener) {
                return accepted;
            }
            assert!(self.now < until, "handshake did not finish");
        }
    }
    // A bulk transfer from the client's `id` to the server's `accepted`
    // for 200 ms, the server reading all it can after each step: the
    // widest window the server advertised at its window scale `scale`, in
    // bytes.
    fn bulk(&mut self, id: ConnId, accepted: ConnId, scale: u8) -> usize {
        let data = [5; 1 << 14];
        let mut out = vec![0; 1 << 16];
        let (mut read, mut widest) = (0, 0);
        let mut seen = self.server_sent.borrow().len();
        let until = self.now + 200 * MS;
        while self.now < until {
            while let Ok(receipt) = self.client.try_write(id, &data, WriteOptions::default()) {
                if receipt.accepted == 0 {
                    break;
                }
            }
            self.step();
            while let Ok(ReadOutcome::Data { len, .. }) = self.server.try_read(accepted, &mut out) {
                read += len;
            }
            let sent = self.server_sent.borrow();
            widest = sent[seen..]
                .iter()
                .filter(|p| tcp(p)[13] & 0x02 == 0)
                .map(|p| window_field(p) << scale)
                .fold(widest, usize::max);
            seen = sent.len();
        }
        assert!(read > 1 << 20, "read {read} bytes");
        widest
    }
}

const INITIAL: usize = 65536;

// A receive size locked on an open connection keeps DRS
// (tcp_rcv_space_adjust) from growing it, as SOCK_RCVBUF_LOCK keeps
// tcp_rcvbuf_grow from raising sk_rcvbuf: the window the receiver
// advertises stays within it. The same transfer without the lock grows it.
#[test]
fn a_locked_receive_size_stops_drs_growth() {
    for locked in [false, true] {
        let mut pair = Pair::new();
        let id = pair.client.connect(pair.peer()).unwrap();
        let accepted = pair.accept();
        if locked {
            pair.server.set_receive_buffer(accepted, INITIAL).unwrap();
        }
        let widest = pair.bulk(id, accepted, 10);
        let (_, receive) = pair.server.buffer_capacities(accepted).unwrap();
        if locked {
            assert_eq!(receive, INITIAL);
            assert!(widest <= INITIAL, "advertised {widest} bytes");
        } else {
            assert!(receive > INITIAL, "receive size {receive}");
            assert!(widest > INITIAL, "advertised {widest} bytes");
        }
    }
}

// A send size locked on an open connection keeps it from expanding with
// the congestion window (tcp_sndbuf_expand), as SOCK_SNDBUF_LOCK does in
// tcp_should_expand_sndbuf. The same transfer without the lock expands it.
#[test]
fn a_locked_send_size_stops_send_expansion() {
    for locked in [false, true] {
        let mut pair = Pair::new();
        let id = pair.client.connect(pair.peer()).unwrap();
        let accepted = pair.accept();
        if locked {
            pair.client.set_send_buffer(id, INITIAL).unwrap();
        }
        pair.bulk(id, accepted, 10);
        let (send, receive) = pair.client.buffer_capacities(id).unwrap();
        if locked {
            assert_eq!(send, INITIAL);
        } else {
            assert!(send > INITIAL, "send size {send}");
        }
        // The client's receive direction, idle, stays where it began.
        assert_eq!(receive, INITIAL);
    }
}

// Sizes a listener locks are its children's, locked, as a Linux child
// inherits sk_sndbuf, sk_rcvbuf and sk_userlocks (inet_csk_clone_lock):
// the child's SYN-ACK offers the scale its receive size gives, and a bulk
// transfer grows neither direction.
#[test]
fn a_listener_lock_is_inherited_by_an_accepted_child() {
    const SEND: usize = 32768;
    const RECEIVE: usize = 131072;
    let mut pair = Pair::new();
    let listener = pair.listener;
    assert_eq!(
        pair.server.listener_buffer_capacities(listener).unwrap(),
        (INITIAL, INITIAL)
    );
    pair.server
        .set_listener_receive_buffer(listener, RECEIVE)
        .unwrap();
    pair.server
        .set_listener_send_buffer(listener, SEND)
        .unwrap();
    assert_eq!(
        pair.server.listener_buffer_capacities(listener).unwrap(),
        (SEND, RECEIVE)
    );
    let id = pair.client.connect(pair.peer()).unwrap();
    let accepted = pair.accept();
    assert_eq!(
        pair.server.buffer_capacities(accepted).unwrap(),
        (SEND, RECEIVE)
    );
    // 131072 > 65535·2: scale 2 (the default 32 MiB maximum gives 10).
    let syn_ack = syns(&pair.server_sent.borrow())[0].clone();
    assert_eq!(tcp(&syn_ack)[13], 0x12);
    assert_eq!(window_scale(&syn_ack), Some(2));
    assert_eq!(window_scale(&syn_ack), Some(linux_wscale(RECEIVE)));
    let widest = pair.bulk(id, accepted, 2);
    assert!(widest <= RECEIVE, "advertised {widest} bytes");
    // The child writes too: its send size stays locked, so no write burst
    // queues more than it.
    let data = [6; 1 << 14];
    let mut out = vec![0; 1 << 16];
    let (mut read, mut largest) = (0, 0);
    for _ in 0..200 {
        let mut burst = 0;
        while let Ok(receipt) = pair
            .server
            .try_write(accepted, &data, WriteOptions::default())
        {
            if receipt.accepted == 0 {
                break;
            }
            burst += receipt.accepted;
        }
        largest = usize::max(largest, burst);
        pair.step();
        while let Ok(ReadOutcome::Data { len, .. }) = pair.client.try_read(id, &mut out) {
            read += len;
        }
    }
    assert!(read > 1 << 20, "read {read} bytes");
    assert!(largest <= SEND, "a burst queued {largest} bytes");
    assert_eq!(
        pair.server.buffer_capacities(accepted).unwrap(),
        (SEND, RECEIVE)
    );
}

// A receive size locked before the SYN leaves sets the scale the SYN
// offers, as SO_RCVBUF before connect(2) clamps window_clamp in Linux's
// tcp_connect_init before tcp_select_initial_window picks rcv_wscale:
// ilog2(425984) - 15 = 18 - 15 = 3, where the default 32 MiB maximum
// gives 10. ntcp's size is the window: Linux offers tcp_full_space, half
// of a locked sk_rcvbuf at the default scaling ratio, so its sk_rcvbuf
// 425984 (SO_RCVBUF 212992) offers 212992, scale 2, and a 425984-byte
// window needs sk_rcvbuf 851968. Both paths lock it: the size given to
// connect_with, and set_receive_buffer between connect and the next drive.
// Once the SYN has left, the scale stays.
#[test]
fn a_receive_lock_before_the_syn_fixes_the_window_scale() {
    const RECEIVE: usize = 425_984;
    assert_eq!(linux_wscale(RECEIVE), 3);
    assert_eq!(linux_wscale(RECEIVE / 2), 2);
    assert_eq!(linux_wscale(32 << 20), 10);
    for path in ["default", "connect_with", "set_receive_buffer"] {
        let mut pair = Pair::new();
        let id = match path {
            "connect_with" => pair
                .client
                .connect_with(
                    pair.peer(),
                    ConnectOptions {
                        receive_buffer: Some(RECEIVE),
                        ..ConnectOptions::default()
                    },
                )
                .unwrap(),
            _ => pair.client.connect(pair.peer()).unwrap(),
        };
        if path == "set_receive_buffer" {
            pair.client.set_receive_buffer(id, RECEIVE).unwrap();
        }
        let accepted = pair.accept();
        let syn = syns(&pair.client_sent.borrow())[0].clone();
        assert_eq!(tcp(&syn)[13], 0x02);
        // The SYN's window field is not scaled: at most 65535.
        assert_eq!(window_field(&syn), 65535);
        if path == "default" {
            // The 32 MiB maximum: 2^25 > 65535·2^9, scale 10, as Linux's
            // ilog2(tcp_rmem[2]) - 15.
            assert_eq!(window_scale(&syn), Some(linux_wscale(32 << 20)));
            continue;
        }
        assert_eq!(window_scale(&syn), Some(linux_wscale(RECEIVE)));
        assert_eq!(pair.client.buffer_capacities(id).unwrap().1, RECEIVE);
        // After the SYN, a larger lock grows the window but not the scale:
        // the server reads the client's windows at scale 3, so data flows
        // back past 64 KiB.
        pair.client.set_receive_buffer(id, 4 << 20).unwrap();
        assert_eq!(pair.client.buffer_capacities(id).unwrap().1, 4 << 20);
        let data = [7; 1 << 14];
        let mut out = vec![0; 1 << 16];
        let mut read = 0;
        for _ in 0..100 {
            while let Ok(receipt) = pair
                .server
                .try_write(accepted, &data, WriteOptions::default())
            {
                if receipt.accepted == 0 {
                    break;
                }
            }
            pair.step();
            while let Ok(ReadOutcome::Data { len, .. }) = pair.client.try_read(id, &mut out) {
                read += len;
            }
        }
        assert!(read > 1 << 20, "read {read} bytes");
        assert_eq!(syns(&pair.client_sent.borrow()).len(), 1);
    }
}

// The getters report the live sizes: the configured initial ones, then
// what each setter set (one direction each), on connections and listeners;
// a size out of range is InvalidConfig and changes nothing; a closed
// connection or listener, or a stale handle, is InvalidHandle.
#[test]
fn getters_report_live_sizes() {
    let mut pair = Pair::new();
    let id = pair.client.connect(pair.peer()).unwrap();
    assert_eq!(
        pair.client.buffer_capacities(id).unwrap(),
        (INITIAL, INITIAL)
    );
    pair.client.set_send_buffer(id, 100_000).unwrap();
    assert_eq!(
        pair.client.buffer_capacities(id).unwrap(),
        (100_000, INITIAL)
    );
    pair.client.set_receive_buffer(id, 200_000).unwrap();
    assert_eq!(
        pair.client.buffer_capacities(id).unwrap(),
        (100_000, 200_000)
    );
    // A smaller receive size is the live size too; the ring stays.
    pair.client.set_receive_buffer(id, 50_000).unwrap();
    assert_eq!(
        pair.client.buffer_capacities(id).unwrap(),
        (100_000, 50_000)
    );
    pair.client.set_send_buffer(id, (1 << 30) - 1).unwrap();
    for bad in [0, 1 << 30] {
        assert!(matches!(
            pair.client.set_send_buffer(id, bad),
            Err(Error::InvalidConfig(_))
        ));
    }
    for bad in [0, (65535 << 14) + 1] {
        assert!(matches!(
            pair.client.set_receive_buffer(id, bad),
            Err(Error::InvalidConfig(_))
        ));
        assert!(matches!(
            pair.server.set_listener_receive_buffer(pair.listener, bad),
            Err(Error::InvalidConfig(_))
        ));
    }
    assert!(matches!(
        pair.server.set_listener_send_buffer(pair.listener, 0),
        Err(Error::InvalidConfig(_))
    ));
    assert!(matches!(
        pair.client.connect_with(
            pair.peer(),
            ConnectOptions {
                send_buffer: Some(0),
                ..ConnectOptions::default()
            }
        ),
        Err(Error::InvalidConfig(_))
    ));
    assert_eq!(
        pair.client.buffer_capacities(id).unwrap(),
        ((1 << 30) - 1, 50_000)
    );
    // Both open with the sizes they were given.
    let other = pair
        .client
        .connect_with(
            pair.peer(),
            ConnectOptions {
                local_port: Some(40000),
                send_buffer: Some(8192),
                receive_buffer: Some(16384),
            },
        )
        .unwrap();
    assert_eq!(
        pair.client.connection_info(other).unwrap().local.port(),
        40000
    );
    assert_eq!(pair.client.buffer_capacities(other).unwrap(), (8192, 16384));
    pair.client.close(other).unwrap();
    assert!(matches!(
        pair.client.buffer_capacities(other),
        Err(Error::InvalidHandle)
    ));
    assert!(matches!(
        pair.client.set_send_buffer(other, 4096),
        Err(Error::InvalidHandle)
    ));
    pair.server.close_listener(pair.listener).unwrap();
    assert!(matches!(
        pair.server.listener_buffer_capacities(pair.listener),
        Err(Error::InvalidHandle)
    ));
    assert!(matches!(
        pair.server.set_listener_receive_buffer(pair.listener, 4096),
        Err(Error::InvalidHandle)
    ));
}

// A size whose memory the budget cannot give is refused with NoMemory, as
// Linux's ENOMEM, and changes nothing: a receive size that would grow the
// ring past the cap, and an open whose locked receive ring does not fit
// (refused at admission, taking no slot or port).
#[test]
fn a_size_the_budget_refuses_is_no_memory() {
    let mut pair = Pair::with(|config, wire| {
        config.tcp.max_buffer_bytes = config.buffer_budget(4, wire).unwrap();
    });
    let id = pair.client.connect(pair.peer()).unwrap();
    pair.accept();
    let charged = pair.client.counters().buffer_bytes;
    assert!(matches!(
        pair.client.set_receive_buffer(id, 32 << 20),
        Err(Error::NoMemory)
    ));
    assert_eq!(
        pair.client.buffer_capacities(id).unwrap(),
        (INITIAL, INITIAL)
    );
    assert_eq!(pair.client.counters().buffer_bytes, charged);
    let refused = pair.client.counters().memory_refused_opens;
    assert!(matches!(
        pair.client.connect_with(
            pair.peer(),
            ConnectOptions {
                local_port: Some(40000),
                receive_buffer: Some(32 << 20),
                ..ConnectOptions::default()
            }
        ),
        Err(Error::NoMemory)
    ));
    assert_eq!(pair.client.counters().memory_refused_opens, refused + 1);
    assert_eq!(pair.client.counters().buffer_bytes, charged);
    // The port and the slot are still free.
    let other = pair.client.connect_from(pair.peer(), Some(40000)).unwrap();
    assert_eq!(
        pair.client.buffer_capacities(other).unwrap(),
        (INITIAL, INITIAL)
    );
}
