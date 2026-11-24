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
    let cap = base(address).buffer_budget(opens, &wire).unwrap() + headroom;
    capped(address, wire, cap)
}

fn base(address: IpAddr) -> NetworkConfig {
    let mut config = NetworkConfig::new(address, 1500);
    config.tcp.max_connections = CONNECTIONS;
    config.tcp.connection.timebase.units_per_second = 1_000_000_000;
    config
}

// The same with a buffer cap of `cap` bytes.
fn capped(address: IpAddr, wire: Wire, cap: usize) -> Network<Wire> {
    let mut config = base(address);
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

// A connection is writable by Linux's rule while the budget refuses its
// send storage: tcp_poll reports EPOLLOUT by __sk_stream_is_writeable,
// which asks sk_wmem_queued and sk_sndbuf, not memory. Its write takes what
// fits and the next one is refused (WouldBlock, throttled writes), no
// Writable comes while memory stays short, and the return of another
// connection's storage, once the peer has read that connection's data,
// raises Writable; the next write then takes bytes.
#[test]
fn a_writable_connection_refused_memory_is_woken_by_a_return_and_writes() {
    let (server_ip, client_ip): (IpAddr, IpAddr) =
        ("198.18.0.1".parse().unwrap(), "198.18.0.2".parse().unwrap());
    let data: Vec<u8> = (0..1 << 16).map(|i: u32| (i * 7 % 251) as u8).collect();
    // The charge once `bulk` filled its send buffer, unacknowledged, with
    // room to spare; then a cap 64 KiB above it, which `bulk`'s growth
    // peaks fit and the waiter's full 64 KiB write does not.
    let run = |cap: Option<usize>| -> usize {
        let (near, far) = wires();
        let mut server = match cap {
            Some(cap) => capped(server_ip, near, cap),
            None => network(server_ip, near, CONNECTIONS, CONNECTIONS * 70 * 65536),
        };
        let mut client = network(client_ip, far, CONNECTIONS, CONNECTIONS * 70 * 65536);
        let listener = server.listen(7000, 4).unwrap();
        let now = Cell::new(0u64);
        let drive = |network: &mut Network<Wire>, budget| {
            now.set(now.get() + 20_000);
            network.drive(now.get(), budget).unwrap();
            let mut events = Vec::new();
            let mut out = [Event::NetworkStopped; 8];
            loop {
                let report = network.drain_events(&mut out);
                events.extend_from_slice(&out[..report.written]);
                if !report.more {
                    return events;
                }
            }
        };
        let dialers: Vec<_> = (0..2)
            .map(|_| client.connect(SocketAddr::new(server_ip, 7000)).unwrap())
            .collect();
        let mut accepted = Vec::new();
        while accepted.len() < 2 {
            drive(&mut server, BUDGET);
            drive(&mut client, BUDGET);
            match server.accept(listener) {
                Ok(id) => accepted.push(id),
                Err(error) => assert!(error.is_would_block(), "{error:?}"),
            }
        }
        let (bulk, waiter) = (accepted[0], accepted[1]);
        // A fixed send limit, as SO_SNDBUF sets: pressure does not moderate
        // it to what the waiter queued. 128 KiB keeps any partial write of
        // `data` (64 KiB) below half of SO_SNDBUF so Linux's rule stays writable.
        server.set_send_buffer(waiter, 131072).unwrap();
        // The client reads nothing yet: `bulk`'s data stays queued.
        let mut sent = 0;
        while let Ok(receipt) = server.try_write(bulk, &data[sent..], WriteOptions::default()) {
            sent += receipt.accepted;
            drive(&mut server, FLUSH);
        }
        assert!(sent > 0);
        assert_eq!(server.counters().memory_throttled_writes, 0);
        let charge = server.counters().buffer_bytes;
        if cap.is_none() {
            return charge;
        }
        drive(&mut server, BUDGET);
        let taken = server
            .try_write(waiter, &data, WriteOptions::default())
            .unwrap()
            .accepted;
        assert!(taken > 0 && taken < data.len(), "{taken}");
        assert_eq!(server.counters().memory_throttled_writes, 1);
        let error = server
            .try_write(waiter, &data[taken..], WriteOptions::default())
            .unwrap_err();
        assert!(error.is_would_block(), "{error:?}");
        assert_eq!(server.counters().memory_throttled_writes, 2);
        // Writable by Linux's rule, but no Writable while memory is short.
        assert!(server.readiness(waiter).unwrap().writable);
        assert!(!drive(&mut server, BUDGET).contains(&Event::Writable(waiter)));
        // The client reads; its ACKs drain `bulk`, whose freed storage
        // wakes the waiter.
        let mut buffer = vec![0u8; 65536];
        let (mut received, mut woken) = (0, false);
        for _ in 0..10_000 {
            woken |= drive(&mut server, BUDGET).contains(&Event::Writable(waiter));
            drive(&mut client, BUDGET);
            while let Ok(ReadOutcome::Data { len, .. }) = client.try_read(dialers[0], &mut buffer) {
                received += len;
            }
            if woken && received == sent {
                break;
            }
        }
        assert_eq!(received, sent);
        assert!(
            woken,
            "no Writable after the return: {:?}",
            server.counters()
        );
        let receipt = server
            .try_write(waiter, &data[taken..], WriteOptions::default())
            .unwrap();
        assert!(receipt.accepted > 0);
        charge
    };
    let charge = run(None);
    assert_eq!(run(Some(charge + 65536)), charge);
}

// A connection whose first write the cap refuses with nothing queued, the
// cap leaving some room but less than its first send ring, gets no
// Writable while no memory comes back, over many vm_wait retries: each
// would only bring the same WouldBlock, and an edge-triggered writer would
// spin on it (Stackbench c184, where the retries raised Writable every
// 74-337 ms). Once another connection's unread data is read, its return
// raises one Writable, and the write goes through.
#[test]
fn a_refused_writer_gets_no_writable_until_a_return_fits_its_growth() {
    let (server_ip, client_ip): (IpAddr, IpAddr) =
        ("198.18.0.1".parse().unwrap(), "198.18.0.2".parse().unwrap());
    let request: Vec<u8> = (0..32768).map(|i: u32| (i * 7 % 251) as u8).collect();
    // The server's charge once it holds `request` unread; then a cap 1000
    // bytes above it, less than a send ring.
    let run = |cap: Option<usize>| -> usize {
        let (near, far) = wires();
        let mut server = match cap {
            Some(cap) => capped(server_ip, near, cap),
            None => network(server_ip, near, CONNECTIONS, CONNECTIONS * 70 * 65536),
        };
        let mut client = network(client_ip, far, CONNECTIONS, CONNECTIONS * 70 * 65536);
        let listener = server.listen(7000, 4).unwrap();
        let now = Cell::new(0u64);
        let drive = |network: &mut Network<Wire>, step: u64| {
            now.set(now.get() + step);
            network.drive(now.get(), BUDGET).unwrap();
            let mut events = Vec::new();
            let mut out = [Event::NetworkStopped; 8];
            loop {
                let report = network.drain_events(&mut out);
                events.extend_from_slice(&out[..report.written]);
                if !report.more {
                    return events;
                }
            }
        };
        let dialers: Vec<_> = (0..2)
            .map(|_| client.connect(SocketAddr::new(server_ip, 7000)).unwrap())
            .collect();
        let mut accepted = Vec::new();
        while accepted.len() < 2 {
            drive(&mut server, 20_000);
            drive(&mut client, 20_000);
            match server.accept(listener) {
                Ok(id) => accepted.push(id),
                Err(error) => assert!(error.is_would_block(), "{error:?}"),
            }
        }
        let (holder, waiter) = (accepted[0], accepted[1]);
        let receipt = client
            .try_write(dialers[0], &request, WriteOptions::default())
            .unwrap();
        assert_eq!(receipt.accepted, request.len());
        for _ in 0..64 {
            drive(&mut client, 20_000);
            drive(&mut server, 20_000);
        }
        assert_eq!(server.counters().memory_throttled_writes, 0);
        let charge = server.counters().buffer_bytes;
        if cap.is_none() {
            return charge;
        }
        let error = server
            .try_write(waiter, &request, WriteOptions::default())
            .unwrap_err();
        assert!(error.is_would_block(), "{error:?}");
        assert_eq!(server.counters().memory_throttled_writes, 1);
        // Writable by Linux's rule, but no Writable over 10 s of retries.
        assert!(server.readiness(waiter).unwrap().writable);
        for _ in 0..1000 {
            let events = drive(&mut server, 10_000_000);
            assert!(
                !events.contains(&Event::Writable(waiter)),
                "{:?}",
                server.counters()
            );
            drive(&mut client, 0);
        }
        assert_eq!(server.counters().memory_throttled_writes, 1);
        assert_eq!(server.counters().buffer_bytes, charge);
        // The server reads `holder`'s data: its return wakes the waiter.
        let mut buffer = vec![0u8; 65536];
        let mut received = 0;
        while let Ok(ReadOutcome::Data { len, .. }) = server.try_read(holder, &mut buffer) {
            received += len;
        }
        assert_eq!(received, request.len());
        let mut woken = 0;
        for _ in 0..64 {
            let events = drive(&mut server, 20_000);
            woken += events
                .iter()
                .filter(|&&e| e == Event::Writable(waiter))
                .count();
            drive(&mut client, 20_000);
        }
        assert_eq!(woken, 1, "{:?}", server.counters());
        let receipt = server
            .try_write(waiter, &request[..1000], WriteOptions::default())
            .unwrap();
        assert_eq!(receipt.accepted, 1000);
        assert_eq!(server.counters().memory_throttled_writes, 1);
        charge
    };
    let charge = run(None);
    assert_eq!(run(Some(charge + 1000)), charge);
}
