// NetworkConfig::new's TCP defaults, as Linux's: SACK and timestamps offered
// on the SYN and no ECN asked for, a lost tail segment retransmitted near
// the 200 ms RTO floor rather than RFC 6298's 1 s, a 60 s TIME-WAIT, a
// listener that takes a fresh SYN for a tuple in TIME-WAIT, and receive
// buffers autotuned up to tcp_rmem[2]. Two Networks over an in-memory IP
// wire that can drop a chosen segment.
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
    sent: Rc<RefCell<Vec<Vec<u8>>>>,
    // Drop the next TCP segment this side sends that carries payload.
    drop_data: Rc<Cell<bool>>,
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
        if tcp_payload(packet) != 0 && self.drop_data.replace(false) {
            return Ok(TxOutcome::Submitted);
        }
        self.outgoing.borrow_mut().push_back(packet.to_vec());
        Ok(TxOutcome::Submitted)
    }
}

// The TCP header of an IPv4 packet.
fn tcp(packet: &[u8]) -> &[u8] {
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    &packet[ihl..]
}

fn tcp_payload(packet: &[u8]) -> usize {
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    let offset = usize::from(tcp(packet)[12] >> 4) * 4;
    total - ihl - offset
}

// Whether a SYN carries the option of `wanted` kind (4 SACK-permitted, 8
// timestamps).
fn has_option(packet: &[u8], wanted: u8) -> bool {
    option(packet, wanted).is_some()
}

// The body of the first option of `wanted` kind.
fn option(packet: &[u8], wanted: u8) -> Option<&[u8]> {
    let header = tcp(packet);
    let mut options = &header[20..usize::from(header[12] >> 4) * 4];
    while let [kind, rest @ ..] = options {
        match kind {
            0 => return None,
            1 => options = rest,
            _ => {
                let len = usize::from(*rest.first()?).max(2).min(options.len());
                if *kind == wanted {
                    return Some(&options[2..len]);
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

const BUDGET: WorkBudget = WorkBudget::new(32, 32, 32, 32);
const PORT: u16 = 9000;
const MS: u64 = 1000;

fn address(side: u8) -> IpAddr {
    IpAddr::from([10, 75, 0, side])
}

fn side(n: u8, incoming: &Queue, outgoing: &Queue) -> (Network<Wire>, Wire) {
    side_with(n, incoming, outgoing, |config, wire| {
        config.tcp.max_buffer_bytes = config.buffer_budget(4, wire).unwrap();
    })
}

fn side_with(
    n: u8,
    incoming: &Queue,
    outgoing: &Queue,
    configure: impl FnOnce(&mut NetworkConfig, &Wire),
) -> (Network<Wire>, Wire) {
    let make = || Wire {
        incoming: incoming.clone(),
        outgoing: outgoing.clone(),
        sent: Rc::default(),
        drop_data: Rc::default(),
    };
    let wire = make();
    let probe = Wire {
        sent: wire.sent.clone(),
        drop_data: wire.drop_data.clone(),
        ..make()
    };
    let mut config = NetworkConfig::new(address(n), 1500);
    config.tcp.max_connections = 4;
    configure(&mut config, &wire);
    (Network::new(config, wire, [n; 32], 0).unwrap(), probe)
}

fn step(now: &mut u64, client: &mut Network<Wire>, server: &mut Network<Wire>) -> u64 {
    *now += MS;
    client.drive(*now, BUDGET).unwrap();
    server.drive(*now, BUDGET).unwrap();
    *now
}

#[test]
fn defaults_follow_linux_and_stay_configurable() {
    let config = NetworkConfig::new(address(1), 1500);
    let c = &config.tcp.connection;
    assert!(c.sack && c.rack && c.tlp && c.adaptive_ack && c.timestamps);
    assert!(c.ecn && !c.ecn_initiate && c.prr && !c.prr_pacing);
    assert_eq!(c.initial_window, ntcp::InitialWindow::Iw10);
    assert_eq!(c.congestion_algorithm, ntcp::CongestionAlgorithm::Cubic);
    assert_eq!((c.rto_min_us, c.delayed_ack_us), (200_000, 200_000));
    assert_eq!(c.time_wait_us, 60_000_000);
    assert!(config.tcp.reuse_time_wait);
    // tcp_rmem = 4096 131072 33554432 in window bytes (Linux's 128 KiB of
    // memory starts about 64 KiB of window), and tcp_wmem[2] = 4 MiB.
    let buffers = config.tcp.buffers();
    let sizes = |min, initial, max| ntcp::BufferSizes { min, initial, max };
    assert_eq!(buffers.receive, sizes(4096, 65536, 32 << 20));
    assert_eq!(buffers.send, sizes(4096, 65536, 4 << 20));
    let memory = buffers.memory;
    assert_eq!(
        (memory.low, memory.pressure, memory.high),
        (128 << 20, (256 << 20) * 2 / 3, 256 << 20)
    );
    // The RFC baseline of the Endpoint is still a configuration away.
    let mut config = config;
    let baseline = ntcp::ConnectionConfig::default();
    config.tcp.connection.sack = baseline.sack;
    config.tcp.connection.rack = baseline.rack;
    config.tcp.connection.tlp = baseline.tlp;
    config.tcp.connection.rto_min_us = baseline.rto_min_us;
    config.tcp.connection.adaptive_ack = baseline.adaptive_ack;
    config.tcp.connection.timestamps = baseline.timestamps;
    config.tcp.connection.ecn_initiate = baseline.ecn_initiate;
    config.tcp.connection.initial_window = baseline.initial_window;
    config.tcp.connection.congestion_algorithm = baseline.congestion_algorithm;
    config.tcp.connection.prr = baseline.prr;
    config.tcp.connection.time_wait_us = baseline.time_wait_us;
    config.tcp.connection.receive_capacity_max = baseline.receive_capacity_max;
    config.tcp.connection.send_capacity_max = baseline.send_capacity_max;
    assert_eq!(config.tcp.buffers().receive, sizes(4096, 65536, 65536));
    assert_eq!(config.tcp.buffers().send, sizes(4096, 65536, 65536));
    config.tcp.reuse_time_wait = ntcp::EndpointConfig::default().reuse_time_wait;
    let wire = || Wire {
        incoming: Queue::default(),
        outgoing: Queue::default(),
        sent: Rc::default(),
        drop_data: Rc::default(),
    };
    assert!(Network::new(config.clone(), wire(), [1; 32], 0).is_ok());
    // Any positive TIME-WAIT is accepted; only zero, which would end before
    // the ACK of the peer's FIN left, is refused.
    for time_wait_us in [1, 1_000, u64::MAX] {
        config.tcp.connection.time_wait_us = time_wait_us;
        assert!(Network::new(config.clone(), wire(), [1; 32], 0).is_ok());
    }
    config.tcp.connection.time_wait_us = 0;
    assert!(Network::new(config, wire(), [1; 32], 0).is_err());
}

// The side that closes first waits 60 s, TCP_TIMEWAIT_LEN, before its
// connection leaves TIME-WAIT.
#[test]
fn time_wait_lasts_60_s() {
    let (a, b) = (Queue::default(), Queue::default());
    let (mut client, _) = side(1, &a, &b);
    let (mut server, _) = side(2, &b, &a);
    let listener = server.listen(PORT, 4).unwrap();
    let id = client.connect(SocketAddr::new(address(2), PORT)).unwrap();
    let mut now = 0;
    let accepted = loop {
        step(&mut now, &mut client, &mut server);
        if let Ok(accepted) = server.accept(listener) {
            break accepted;
        }
        assert!(now < 100 * MS, "handshake did not finish");
    };
    client.close(id).unwrap();
    loop {
        step(&mut now, &mut client, &mut server);
        if let Ok(ReadOutcome::Eof) = server.try_read(accepted, &mut [0; 8]) {
            break;
        }
        assert!(now < 1_000 * MS, "the FIN never arrived");
    }
    server.close(accepted).unwrap();
    // TIME-WAIT begins at the drive that first counts it.
    let began = loop {
        let at = step(&mut now, &mut client, &mut server);
        if client.counters().time_wait_connections == 1 {
            break at;
        }
        assert!(at < 1_000 * MS, "TIME-WAIT never began");
    };
    let end = began + 60_000 * MS;
    client.drive(end - 1, BUDGET).unwrap();
    assert_eq!(client.counters().time_wait_connections, 1);
    client.drive(end, BUDGET).unwrap();
    assert_eq!(client.counters().time_wait_connections, 0);
}

#[test]
fn the_syn_offers_sack_and_timestamps_without_ecn_and_a_lost_tail_returns_near_200_ms() {
    let (a, b) = (Queue::default(), Queue::default());
    let (mut client, client_wire) = side(1, &a, &b);
    let (mut server, _) = side(2, &b, &a);
    let listener = server.listen(PORT, 4).unwrap();
    let id = client.connect(SocketAddr::new(address(2), PORT)).unwrap();
    let mut now = 0;
    let accepted = loop {
        step(&mut now, &mut client, &mut server);
        if let Ok(accepted) = server.accept(listener) {
            break accepted;
        }
        assert!(now < 100 * MS, "handshake did not finish");
    };
    let syn = client_wire.sent.borrow()[0].clone();
    assert!(has_option(&syn, 4) && has_option(&syn, 8));
    // No ECE or CWR on the SYN: ECN is answered, never asked for.
    assert_eq!(tcp(&syn)[13] & 0xc0, 0);
    client.set_nodelay(id, true).unwrap();
    for _ in 0..20 {
        step(&mut now, &mut client, &mut server);
    }
    // The only segment in flight is lost: no later data, no duplicate ACK.
    client_wire.drop_data.set(true);
    let lost_at = now;
    let receipt = client
        .try_write(id, &[7; 100], WriteOptions::default())
        .unwrap();
    assert_eq!(receipt.accepted, 100);
    let mut out = [0; 256];
    let arrived = loop {
        let at = step(&mut now, &mut client, &mut server);
        if let Ok(ReadOutcome::Data { len, .. }) = server.try_read(accepted, &mut out) {
            assert_eq!(&out[..len], &[7; 100]);
            break at;
        }
        assert!(at - lost_at < 2_000 * MS, "the lost segment never returned");
    };
    let recovery = arrived - lost_at;
    // The RTO floor, not RFC 6298's 1 s, bounds the retransmission.
    assert!(
        (200 * MS..400 * MS).contains(&recovery),
        "recovered after {} ms",
        recovery / MS
    );
}

// The server closes first, so its side of the tuple is in TIME-WAIT. A
// replayed SYN of the old incarnation opens nothing and leaves it there,
// answered with the TIME-WAIT's ACK as a Linux timewait socket answers it
// (TCP_TW_ACK_OOW); the client's next SYN from the same port reopens the
// tuple at once, as a Linux listener takes it (tcp_timewait_state_process,
// TCP_TW_SYN), rather than after the 60 s.
#[test]
fn a_fresh_syn_reopens_a_tuple_in_time_wait_and_a_stale_one_does_not() {
    const CLIENT_PORT: u16 = 40000;
    let (a, b) = (Queue::default(), Queue::default());
    // Both sides use timestamps, so the server judges each SYN by its TSval
    // first (RFC 6191). The client's TSval offset is its tuple's, as Linux's
    // (secure_tcp_seq_and_ts_off), so its next incarnation's SYN carries a
    // TSval newer than any the TIME-WAIT saw, whatever its sequence number.
    let (mut client, client_wire) = side(1, &a, &b);
    let (mut server, server_wire) = side(2, &b, &a);
    let listener = server.listen(PORT, 4).unwrap();
    let peer = SocketAddr::new(address(2), PORT);
    let id = client.connect_from(peer, Some(CLIENT_PORT)).unwrap();
    let mut now = 0;
    let accepted = loop {
        step(&mut now, &mut client, &mut server);
        if let Ok(accepted) = server.accept(listener) {
            break accepted;
        }
        assert!(now < 100 * MS, "handshake did not finish");
    };
    let old_syn = client_wire.sent.borrow()[0].clone();
    assert_eq!(tcp(&old_syn)[13], 0x02);
    assert!(has_option(&old_syn, 8));
    server.close(accepted).unwrap();
    loop {
        step(&mut now, &mut client, &mut server);
        if let Ok(ReadOutcome::Eof) = client.try_read(id, &mut [0; 8]) {
            break;
        }
        assert!(now < 1_000 * MS, "the FIN never arrived");
    }
    client.close(id).unwrap();
    // Taking the closed connections' events releases them: the server's
    // TIME-WAIT is then a record, and the client's port is free.
    let mut events = [Event::NetworkStopped; 16];
    for _ in 0..20 {
        step(&mut now, &mut client, &mut server);
        client.drain_events(&mut events);
        server.drain_events(&mut events);
    }
    assert!(client.connection_info(id).is_err());
    assert!(server.connection_info(accepted).is_err());
    assert_eq!(server.counters().time_wait_connections, 1);
    assert_eq!(client.counters().time_wait_connections, 0);
    // The old incarnation's SYN: its sequence number is below the FIN the
    // TIME-WAIT acknowledged. Only the server takes it in, and its answer
    // stays off the wire: a client's RST to that ACK would end the
    // TIME-WAIT (Linux's tcp_rfc1337=0 does the same).
    let sent = server_wire.sent.borrow().len();
    b.borrow_mut().push_back(old_syn);
    for _ in 0..20 {
        now += MS;
        server.drive(now, BUDGET).unwrap();
    }
    a.borrow_mut().clear();
    let answers = server_wire.sent.borrow()[sent..].to_vec();
    assert_eq!(answers.len(), 1);
    assert_eq!(tcp(&answers[0])[13], 0x10);
    assert_eq!(tcp_payload(&answers[0]), 0);
    assert!(!server.acceptable(listener).unwrap());
    assert_eq!(server.counters().time_wait_connections, 1);
    let syns = client_wire.sent.borrow().len();
    let id = client.connect_from(peer, Some(CLIENT_PORT)).unwrap();
    let accepted = loop {
        step(&mut now, &mut client, &mut server);
        if let Ok(accepted) = server.accept(listener) {
            break accepted;
        }
        assert!(now < 2_000 * MS, "the tuple did not reopen");
    };
    // The first SYN reopened it, without a retransmission.
    let client_syns: Vec<_> = client_wire.sent.borrow()[syns..]
        .iter()
        .filter(|packet| tcp(packet)[13] & 0x02 != 0)
        .cloned()
        .collect();
    assert_eq!(client_syns.len(), 1);
    assert!(has_option(&client_syns[0], 8));
    // The new connection took the tuple and ended the TIME-WAIT.
    assert_eq!(server.counters().time_wait_connections, 0);
    let receipt = client
        .try_write(id, &[9; 10], WriteOptions::default())
        .unwrap();
    assert_eq!(receipt.accepted, 10);
    let mut out = [0; 16];
    loop {
        step(&mut now, &mut client, &mut server);
        if let Ok(ReadOutcome::Data { len, .. }) = server.try_read(accepted, &mut out) {
            assert_eq!(&out[..len], &[9; 10]);
            break;
        }
        assert!(now < 3_000 * MS, "no data on the new connection");
    }
}

// The server closes a connection whose request it never read, so it resets
// the connection (RFC 9293 3.6.1, Linux tcp_close's data_was_unread). As on
// Linux, the reset leaves nothing of the connection behind: the client's next
// SYN from the same port reaches the listener and is answered at once.
#[test]
fn a_syn_after_a_reset_on_close_reaches_the_listener() {
    const CLIENT_PORT: u16 = 40001;
    let (a, b) = (Queue::default(), Queue::default());
    let (mut client, client_wire) = side(1, &a, &b);
    let (mut server, server_wire) = side(2, &b, &a);
    let listener = server.listen(PORT, 4).unwrap();
    let peer = SocketAddr::new(address(2), PORT);
    let id = client.connect_from(peer, Some(CLIENT_PORT)).unwrap();
    let mut now = 0;
    let accepted = loop {
        step(&mut now, &mut client, &mut server);
        if let Ok(accepted) = server.accept(listener) {
            break accepted;
        }
        assert!(now < 100 * MS, "handshake did not finish");
    };
    let receipt = client
        .try_write(id, &[5; 13], WriteOptions::default())
        .unwrap();
    assert_eq!(receipt.accepted, 13);
    client.close(id).unwrap();
    for _ in 0..20 {
        step(&mut now, &mut client, &mut server);
    }
    let sent = server_wire.sent.borrow().len();
    server.close(accepted).unwrap();
    let mut events = [Event::NetworkStopped; 16];
    for _ in 0..20 {
        step(&mut now, &mut client, &mut server);
        client.drain_events(&mut events);
        server.drain_events(&mut events);
    }
    let resets = server_wire.sent.borrow()[sent..]
        .iter()
        .filter(|packet| tcp(packet)[13] & 0x04 != 0)
        .count();
    assert_eq!(resets, 1);
    assert!(client.connection_info(id).is_err());
    assert_eq!(server.counters().time_wait_connections, 0);
    let syns = client_wire.sent.borrow().len();
    let id = client.connect_from(peer, Some(CLIENT_PORT)).unwrap();
    let accepted = loop {
        step(&mut now, &mut client, &mut server);
        if let Ok(accepted) = server.accept(listener) {
            break accepted;
        }
        assert!(now < 5_000 * MS, "the listener never took the SYN");
    };
    let client_syns = client_wire.sent.borrow()[syns..]
        .iter()
        .filter(|packet| tcp(packet)[13] & 0x02 != 0)
        .count();
    assert_eq!(client_syns, 1);
    let receipt = client
        .try_write(id, &[6; 10], WriteOptions::default())
        .unwrap();
    assert_eq!(receipt.accepted, 10);
    let mut out = [0; 16];
    loop {
        step(&mut now, &mut client, &mut server);
        if let Ok(ReadOutcome::Data { len, .. }) = server.try_read(accepted, &mut out) {
            assert_eq!(&out[..len], &[6; 10]);
            break;
        }
        assert!(now < 6_000 * MS, "no data on the new connection");
    }
}

// The 32 MiB receive maximum sets the window scale both SYNs offer, 10 as
// Linux's tcp_select_initial_window derives it from tcp_rmem[2], while the
// SYN window is the 64 KiB initial size, at most 65535. A reader that keeps
// up with a bulk sender then grows its ring at read (DRS, Linux's
// tcp_rcv_space_adjust), and its ACKs advertise more than 64 KiB, while the
// sender's limit rises with its congestion window past the 64 KiB start
// (tcp_sndbuf_expand), so it holds more than 64 KiB written and unread.
// Both keep the default 256 MiB cap: `buffer_budget` leaves no room to
// write.
#[test]
fn the_buffers_start_at_64_kib_with_window_scale_10_and_grow() {
    let (a, b) = (Queue::default(), Queue::default());
    let (mut client, client_wire) = side_with(1, &a, &b, |_, _| ());
    let (mut server, server_wire) = side_with(2, &b, &a, |_, _| ());
    let listener = server.listen(PORT, 4).unwrap();
    let id = client.connect(SocketAddr::new(address(2), PORT)).unwrap();
    let mut now = 0;
    let accepted = loop {
        step(&mut now, &mut client, &mut server);
        if let Ok(accepted) = server.accept(listener) {
            break accepted;
        }
        assert!(now < 100 * MS, "handshake did not finish");
    };
    let syn = client_wire.sent.borrow()[0].clone();
    let syn_ack = server_wire.sent.borrow()[0].clone();
    assert_eq!(tcp(&syn_ack)[13], 0x12);
    for packet in [&syn, &syn_ack] {
        assert_eq!(option(packet, 3), Some(&[10][..]));
        assert_eq!(window_field(packet), 65535);
    }
    let opened = server.counters().buffer_bytes;
    let mut out = vec![0; 1 << 16];
    let (mut read, mut written, mut deepest) = (0, 0, 0);
    let data = [5; 1 << 14];
    let mut widest = 0;
    let mut seen = server_wire.sent.borrow().len();
    while now < 200 * MS {
        while let Ok(receipt) = client.try_write(id, &data, WriteOptions::default()) {
            if receipt.accepted == 0 {
                break;
            }
            written += receipt.accepted;
        }
        deepest = deepest.max(written - read);
        step(&mut now, &mut client, &mut server);
        while let Ok(ReadOutcome::Data { len, .. }) = server.try_read(accepted, &mut out) {
            read += len;
        }
        let sent = server_wire.sent.borrow();
        widest = sent[seen..]
            .iter()
            .map(|p| window_field(p) << 10)
            .fold(widest, usize::max);
        seen = sent.len();
    }
    assert!(read > 1 << 20, "read {read} bytes");
    assert!(
        widest > 65536,
        "the widest advertised window was {widest} bytes"
    );
    assert!(
        deepest > 65536,
        "at most {deepest} bytes written and unread"
    );
    // The grown ring is charged, 1.375 bytes per byte.
    assert!(server.counters().buffer_bytes > opened);
}
