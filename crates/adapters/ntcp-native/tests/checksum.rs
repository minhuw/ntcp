// Checksums of received and sent packets: the IPv4 header checksum is
// verified once per arriving packet, the TCP checksum once per segment, and
// what each refuses is counted as Linux counts it (Ip InHdrErrors, Tcp
// InCsumErrors).
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_native::*;
use std::{
    cell::RefCell,
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    rc::Rc,
};

const TICK: u64 = 100;
const BUDGET: WorkBudget = WorkBudget::new(32, 32, 32, 32);
const LISTEN: u16 = 80;

type Frames = Rc<RefCell<VecDeque<Vec<u8>>>>;

// An L3 link end.
struct Wire {
    incoming: Frames,
    outgoing: Frames,
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
        self.outgoing.borrow_mut().push_back(packet.to_vec());
        Ok(TxOutcome::Submitted)
    }
}

struct Station {
    network: Network<Wire>,
    incoming: Frames,
    outgoing: Frames,
}
impl Station {
    fn new(address: IpAddr) -> Self {
        let mut config = NetworkConfig::new(address, 1500);
        config.tcp.max_connections = 4;
        config.tcp.max_listeners = 1;
        let (incoming, outgoing) = (Frames::default(), Frames::default());
        let wire = Wire {
            incoming: incoming.clone(),
            outgoing: outgoing.clone(),
        };
        let network = Network::new(config, wire, [5; 32], 0).unwrap();
        Self {
            network,
            incoming,
            outgoing,
        }
    }
}

fn step(a: &mut Station, b: &mut Station, now: &mut u64) {
    *now += TICK;
    a.network.drive(*now, BUDGET).unwrap();
    let sent: Vec<_> = a.outgoing.borrow_mut().drain(..).collect();
    b.incoming.borrow_mut().extend(sent);
    b.network.drive(*now, BUDGET).unwrap();
    let sent: Vec<_> = b.outgoing.borrow_mut().drain(..).collect();
    a.incoming.borrow_mut().extend(sent);
}

// The peer (`b`) and the Network under test (`a`), connected; the test
// delivers the peer's packets itself.
struct Lan {
    a: Station,
    b: Station,
    now: u64,
    server: ConnId,
    client: ConnId,
}
impl Lan {
    fn new() -> Self {
        let mut a = Station::new("10.9.0.1".parse().unwrap());
        let mut b = Station::new("10.9.0.2".parse().unwrap());
        let listener = a.network.listen(LISTEN, 4).unwrap();
        let to = SocketAddr::new("10.9.0.1".parse().unwrap(), LISTEN);
        let client = b.network.connect(to).unwrap();
        let mut now = 0;
        for _ in 0..32 {
            step(&mut a, &mut b, &mut now);
        }
        let server = a.network.accept(listener).unwrap();
        Self {
            a,
            b,
            now,
            server,
            client,
        }
    }
    // The next data packet the peer sends, carrying `data`, held back.
    fn peer_data(&mut self, data: &[u8]) -> Vec<u8> {
        self.b
            .network
            .try_write(self.client, data, WriteOptions::default())
            .unwrap();
        self.now += TICK;
        self.b.network.drive(self.now, BUDGET).unwrap();
        let mut sent: Vec<_> = self.b.outgoing.borrow_mut().drain(..).collect();
        assert_eq!(sent.len(), 1);
        sent.pop().unwrap()
    }
    // What the Network under test reads after `packet` arrives.
    fn deliver(&mut self, packet: &[u8]) -> Vec<u8> {
        self.a.incoming.borrow_mut().push_back(packet.to_vec());
        self.now += TICK;
        self.a.network.drive(self.now, BUDGET).unwrap();
        self.a.outgoing.borrow_mut().clear();
        let mut out = [0; 4096];
        match self.a.network.try_read(self.server, &mut out) {
            Ok(ReadOutcome::Data { len, .. }) => out[..len].to_vec(),
            _ => Vec::new(),
        }
    }
}

// A TCP checksum error discards the segment and counts it in Linux's Tcp
// InCsumErrors (and in discarded); an IPv4 header error, a bad header
// checksum included, in Ip InHdrErrors. The segment sent again arrives.
#[test]
fn checksum_and_header_errors_are_counted_as_linux_counts_them() {
    let mut lan = Lan::new();
    let before = lan.a.network.counters();
    assert_eq!(
        (before.tcp_checksum_errors, before.ip_header_errors),
        (0, 0)
    );
    let packet = lan.peer_data(b"request");
    let mut corrupt = packet.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(lan.deliver(&corrupt).is_empty());
    let mut header = packet.clone();
    header[8] ^= 1;
    assert!(lan.deliver(&header).is_empty());
    let counters = lan.a.network.counters();
    assert_eq!(
        (counters.tcp_checksum_errors, counters.ip_header_errors),
        (1, 1)
    );
    assert_eq!(counters.discarded, before.discarded + 2);
    assert_eq!(lan.deliver(&packet), b"request");
    let counters = lan.a.network.counters();
    assert_eq!(
        (counters.tcp_checksum_errors, counters.ip_header_errors),
        (1, 1)
    );
}
