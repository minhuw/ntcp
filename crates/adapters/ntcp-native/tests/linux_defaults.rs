// NetworkConfig::new's TCP defaults, as Linux's: SACK and timestamps offered
// on the SYN and no ECN asked for, and a lost tail segment retransmitted
// near the 200 ms RTO floor rather than RFC 6298's 1 s. Two Networks over an
// in-memory IP wire that can drop a chosen segment.
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
    let header = tcp(packet);
    let mut options = &header[20..usize::from(header[12] >> 4) * 4];
    while let [kind, rest @ ..] = options {
        match kind {
            0 => return false,
            1 => options = rest,
            kind if *kind == wanted => return true,
            _ => {
                let len = usize::from(rest[0]).max(2);
                options = &options[len.min(options.len())..];
            }
        }
    }
    false
}

const BUDGET: WorkBudget = WorkBudget::new(32, 32, 32, 32);
const PORT: u16 = 9000;
const MS: u64 = 1000;

fn address(side: u8) -> IpAddr {
    IpAddr::from([10, 75, 0, side])
}

fn side(n: u8, incoming: &Queue, outgoing: &Queue) -> (Network<Wire>, Wire) {
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
    config.tcp.max_buffer_bytes = config.buffer_budget(4).unwrap();
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
    let (incoming, outgoing) = (Queue::default(), Queue::default());
    let wire = Wire {
        incoming,
        outgoing,
        sent: Rc::default(),
        drop_data: Rc::default(),
    };
    assert!(Network::new(config, wire, [1; 32], 0).is_ok());
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
