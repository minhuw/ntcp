// Network::transport_info: a connection's TCP state as the core reports it,
// read without changing anything. Two Networks over an in-memory IP wire.
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
const MS: u64 = 1000;

fn network(side: u8, incoming: &Queue, outgoing: &Queue) -> Network<Wire> {
    let mut config = NetworkConfig::new(IpAddr::from([10, 76, 0, side]), 1500);
    config.tcp.max_connections = 4;
    config.tcp.max_listeners = 1;
    let wire = Wire {
        incoming: incoming.clone(),
        outgoing: outgoing.clone(),
    };
    Network::new(config, wire, [side; 32], 0).unwrap()
}

fn drive(network: &mut Network<Wire>, now: u64) {
    network.drive(now, BUDGET).unwrap();
    let mut out = [Event::NetworkStopped; 8];
    while network.drain_events(&mut out).more {}
}

#[test]
fn transport_info_follows_a_write_through_flight_and_acknowledgment() {
    let (a, b) = (Queue::default(), Queue::default());
    let mut client = network(1, &a, &b);
    let mut server = network(2, &b, &a);
    let listener = server.listen(PORT, 4).unwrap();
    let id = client
        .connect(SocketAddr::new(IpAddr::from([10, 76, 0, 2]), PORT))
        .unwrap();
    let mut now = 0;
    let accepted = loop {
        now += MS;
        drive(&mut client, now);
        drive(&mut server, now);
        if let Ok(accepted) = server.accept(listener) {
            break accepted;
        }
        assert!(now < 100 * MS, "no connection");
    };
    drive(&mut client, now);

    let idle = client.transport_info(id).unwrap();
    assert_eq!(idle.state, State::Established);
    assert_eq!((idle.unacked, idle.notsent_bytes), (0, 0));
    // A Linux-default connection: timestamps, 1460 - 12 bytes per segment,
    // an initial window of ten segments (in bytes here).
    assert_eq!(idle.mss, 1448);
    assert_eq!(idle.cwnd, 10 * 1448);
    assert_eq!(
        server.transport_info(accepted).unwrap().state,
        State::Established
    );

    // Queued, not yet sent: reading does not send it or change anything.
    let written = client
        .try_write(id, &[5; 3000], WriteOptions::default())
        .unwrap();
    assert_eq!(written.accepted, 3000);
    let queued = client.transport_info(id).unwrap();
    assert_eq!((queued.unacked, queued.notsent_bytes), (0, 3000));
    assert_eq!(client.transport_info(id).unwrap(), queued);
    assert!(b.borrow().is_empty());

    // Sent, not yet acknowledged: three segments in flight. Nagle is on,
    // and Minshall's rule (Linux's) sends the short last one with the full
    // ones: no earlier short segment is unacknowledged.
    now += MS;
    drive(&mut client, now);
    let flight = client.transport_info(id).unwrap();
    assert_eq!((flight.unacked, flight.notsent_bytes), (3, 0));

    // Acknowledged: nothing in flight, and an RTT sample.
    now += MS;
    drive(&mut server, now);
    now += MS;
    drive(&mut client, now);
    let acked = client.transport_info(id).unwrap();
    assert_eq!((acked.unacked, acked.notsent_bytes), (0, 0));
    assert!(acked.rtt_us.is_some());
}

#[test]
fn transport_info_refuses_another_networks_handle() {
    let (a, b) = (Queue::default(), Queue::default());
    let mut client = network(1, &a, &b);
    let other = network(2, &b, &a);
    let id = client
        .connect(SocketAddr::new(IpAddr::from([10, 76, 0, 2]), PORT))
        .unwrap();
    assert!(client.transport_info(id).is_ok());
    assert!(matches!(
        other.transport_info(id),
        Err(Error::InvalidHandle)
    ));
}
