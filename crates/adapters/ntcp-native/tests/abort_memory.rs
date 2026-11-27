use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::*;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    rc::Rc,
};

// An IP wire whose transmit refuses every frame (WouldBlock) while
// `blocked` is set, as a full device TX queue does.
struct Wire {
    incoming: Rc<RefCell<VecDeque<Vec<u8>>>>,
    outgoing: Rc<RefCell<VecDeque<Vec<u8>>>>,
    blocked: Rc<Cell<bool>>,
}
impl PacketIo for Wire {
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
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

const CONNECTIONS: usize = 40;
const WRITE: usize = 64 * 1024;
const BUDGET: WorkBudget = WorkBudget::new(64, 64, 64, 64);

fn network(address: IpAddr, wire: Wire) -> Network<Wire> {
    let mut config = NetworkConfig::new(address, 1500);
    config.tcp.max_connections = CONNECTIONS;
    config.tcp.connection.timebase.units_per_second = 1_000_000_000;
    config.tcp.max_buffer_bytes = CONNECTIONS * 8 * WRITE;
    Network::new(config, wire, [7; 32], 0).unwrap()
}

// The TCP flags of an IPv4 packet carrying TCP.
fn tcp_flags(packet: &[u8]) -> u8 {
    assert_eq!(packet[9], 6);
    packet[usize::from(packet[0] & 0x0f) * 4 + 13]
}

const RST: u8 = 0x04;

// An abort frees the connection's send storage at once, as Linux's
// tcp_disconnect purges the write queue (tcp_write_queue_purge), even
// while the device refuses every frame and the reset it owes cannot
// leave: the charge falls at the abort, not when the reset is sent. The
// resets go out once the device takes frames again, and the slots are
// reclaimed after them.
#[test]
fn aborts_free_send_storage_while_tx_is_blocked_and_reset_later() {
    let (server_ip, client_ip): (IpAddr, IpAddr) =
        ("198.18.0.1".parse().unwrap(), "198.18.0.2".parse().unwrap());
    let to_server = Rc::new(RefCell::new(VecDeque::new()));
    let to_client = Rc::new(RefCell::new(VecDeque::new()));
    let blocked = Rc::new(Cell::new(false));
    let mut server = network(
        server_ip,
        Wire {
            incoming: to_server.clone(),
            outgoing: to_client.clone(),
            blocked: blocked.clone(),
        },
    );
    let mut client = network(
        client_ip,
        Wire {
            incoming: to_client.clone(),
            outgoing: to_server.clone(),
            blocked: Rc::new(Cell::new(false)),
        },
    );
    let listener = server.listen(7000, CONNECTIONS).unwrap();
    let now = Cell::new(0u64);
    let drive = |network: &mut Network<Wire>| {
        now.set(now.get() + 20_000);
        network.drive(now.get(), BUDGET).unwrap();
        let mut out = [Event::NetworkStopped; 8];
        while network.drain_events(&mut out).more {}
    };
    drive(&mut server);
    // What the server charges with no connection.
    let idle = server.counters().buffer_bytes;
    for _ in 0..CONNECTIONS {
        client.connect(SocketAddr::new(server_ip, 7000)).unwrap();
    }
    let mut accepted = Vec::new();
    while accepted.len() < CONNECTIONS {
        drive(&mut server);
        drive(&mut client);
        while let Ok(id) = server.accept(listener) {
            accepted.push(id);
        }
    }
    drive(&mut server);
    let opened = server.counters().buffer_bytes;
    // Each connection sends its initial window, which the client never
    // receives (unacknowledged), and queues the rest (unsent).
    let data = vec![7u8; WRITE];
    let mut queued = 0;
    for &id in &accepted {
        queued += server
            .try_write(id, &data, WriteOptions::default())
            .unwrap()
            .accepted;
    }
    drive(&mut server);
    assert!(!to_client.borrow().is_empty());
    to_client.borrow_mut().clear();
    // The device refuses everything from now on: what the server polls is
    // held for room, and no reset can leave.
    blocked.set(true);
    drive(&mut server);
    let held = server.counters().buffer_bytes;
    assert!(
        held - opened >= queued,
        "queued {queued} bytes, charge {opened} -> {held}"
    );
    for &id in &accepted {
        server.abort(id).unwrap();
    }
    for _ in 0..4 {
        drive(&mut server);
    }
    let aborted = server.counters().buffer_bytes;
    // Every queue went at its abort: less than any one connection queued
    // remains above the idle charge (the owner's shared transmit storage).
    assert!(
        aborted - idle < queued / CONNECTIONS,
        "charge {held} fell only to {aborted} at the aborts (idle {idle}, queued {queued})"
    );
    assert!(to_client.borrow().is_empty());
    blocked.set(false);
    for _ in 0..4 {
        drive(&mut server);
    }
    let resets = to_client
        .borrow()
        .iter()
        .filter(|packet| tcp_flags(packet) & RST != 0)
        .count();
    assert_eq!(resets, CONNECTIONS);
    // Every slot is reclaimed once its reset is out.
    assert_eq!(server.counters().buffer_bytes, idle);
}
