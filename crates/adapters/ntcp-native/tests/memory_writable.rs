use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::*;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    rc::Rc,
};

struct Wire {
    incoming: Rc<RefCell<VecDeque<Vec<u8>>>>,
    outgoing: Rc<RefCell<VecDeque<Vec<u8>>>>,
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
        self.outgoing.borrow_mut().push_back(packet.to_vec());
        Ok(TxOutcome::Submitted)
    }
}
fn wires() -> (Wire, Wire) {
    let a = Rc::new(RefCell::new(VecDeque::new()));
    let b = Rc::new(RefCell::new(VecDeque::new()));
    let wire = |incoming, outgoing| Wire { incoming, outgoing };
    (wire(a.clone(), b.clone()), wire(b, a))
}

const CONNECTIONS: usize = 4;
const BUDGET: WorkBudget = WorkBudget::new(64, 64, 64, 64);
// A drive that only transmits, as an embedding flushes a write.
const FLUSH: WorkBudget = WorkBudget::new(0, 64, 0, 0);

// NetworkConfig::new's defaults (a tuned send limit, Nagle on) in
// nanoseconds, whose buffer cap is the floor of `opens` connections and
// `headroom`, with memory pressure beginning at the cap: a send limit
// expanded with cwnd grows until the cap itself refuses its ring.
fn network(address: IpAddr, wire: Wire, opens: usize, headroom: usize) -> Network<Wire> {
    let mut config = NetworkConfig::new(address, 1500);
    config.tcp.max_connections = CONNECTIONS;
    config.tcp.connection.timebase.units_per_second = 1_000_000_000;
    let cap = config.buffer_budget(opens, &wire).unwrap() + headroom;
    config.tcp.max_buffer_bytes = cap;
    config.tcp.buffer_pressure_bytes = Some(cap);
    config.tcp.buffer_low_bytes = Some(cap - 1);
    Network::new(config, wire, [7; 32], 0).unwrap()
}

// A writer that fills its send buffer, with Nagle on, until the budget
// refuses to grow its ring for the send limit cwnd expanded, is writable
// again once the peer has read everything: as Linux's tcp_poll reports
// EPOLLOUT once sk_stream_is_writeable holds, which an ACK that empties
// sk_wmem_queued makes true. Each write is flushed before the next, so a
// write's short tail leaves with its full segments (Minshall's Nagle) and
// one ACK drains the whole queue, which frees the ring the refused growth
// wanted to double. (Stackbench's ntcp-mux test a_write_the_budget_
// refuses_is_partial_or_eagain_and_writable_again_once_the_peer_reads,
// c152.)
#[test]
fn a_writer_refused_memory_is_writable_again_once_the_peer_reads() {
    let (server_ip, client_ip): (IpAddr, IpAddr) =
        ("198.18.0.1".parse().unwrap(), "198.18.0.2".parse().unwrap());
    let (near, far) = wires();
    // Room for the server's send ring at the initial 64 KiB limit and its
    // ledgers, not for the ring of a limit expanded with cwnd.
    let mut server = network(server_ip, near, 1, 2 * 65536 + 16 * 1024);
    let mut client = network(client_ip, far, CONNECTIONS, CONNECTIONS * 70 * 65536);
    let listener = server.listen(7000, 4).unwrap();
    let dialer = client.connect(SocketAddr::new(server_ip, 7000)).unwrap();
    let now = Cell::new(0u64);
    let drive = |network: &mut Network<Wire>, budget| {
        now.set(now.get() + 20_000);
        network.drive(now.get(), budget).unwrap();
        let mut out = [Event::NetworkStopped; 8];
        while network.drain_events(&mut out).more {}
    };
    let accepted = loop {
        drive(&mut server, BUDGET);
        drive(&mut client, BUDGET);
        match server.accept(listener) {
            Ok(id) => break id,
            Err(error) => assert!(error.is_would_block(), "{error:?}"),
        }
    };
    let data: Vec<u8> = (0..1 << 20).map(|i: u32| (i * 7 % 251) as u8).collect();
    let (mut sent, mut received) = (0, Vec::with_capacity(data.len()));
    let mut buffer = vec![0u8; 65536];
    let mut refused = 0;
    while received.len() < data.len() {
        while sent < data.len() {
            let offered = &data[sent..data.len().min(sent + 65536)];
            let throttled = server.counters().memory_throttled_writes;
            let result = server.try_write(accepted, offered, WriteOptions::default());
            refused += usize::from(server.counters().memory_throttled_writes > throttled);
            match result {
                Ok(receipt) => {
                    sent += receipt.accepted;
                    drive(&mut server, FLUSH);
                }
                Err(error) => {
                    assert!(error.is_would_block(), "{error:?}");
                    break;
                }
            }
        }
        let before = received.len();
        while received.len() == before {
            drive(&mut server, BUDGET);
            drive(&mut client, BUDGET);
            while let Ok(ReadOutcome::Data { len, .. }) = client.try_read(dialer, &mut buffer) {
                received.extend_from_slice(&buffer[..len]);
            }
        }
        if sent < data.len() {
            let mut waits = 0;
            while {
                drive(&mut server, BUDGET);
                !server.readiness(accepted).unwrap().writable
            } {
                waits += 1;
                assert!(
                    waits < 10_000,
                    "never writable again: sent {sent}, received {}, {:?}",
                    received.len(),
                    server.counters()
                );
                drive(&mut client, BUDGET);
            }
        }
    }
    assert_eq!(received, data);
    assert!(refused > 0, "no write was refused for memory");
}
