// ConnId::slot and ListenerId::slot are the indexes the Network keeps the
// handle's entry at, and a slot released is reused by a later handle with a
// greater generation.
use super::*;
use ntcp_io::{PacketLayer, TxOutcome};
use std::{
    cell::RefCell,
    collections::VecDeque,
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

fn network(side: u8, incoming: &Queue, outgoing: &Queue) -> Network<Wire> {
    let mut config = NetworkConfig::new(IpAddr::from([10, 76, 0, side]), 1500);
    config.tcp.max_connections = 4;
    config.tcp.max_listeners = 2;
    let wire = Wire {
        incoming: incoming.clone(),
        outgoing: outgoing.clone(),
    };
    Network::new(config, wire, [side; 32], 0).unwrap()
}

fn step(networks: [&mut Network<Wire>; 2], now: u64) {
    let mut out = [Event::NetworkStopped; 8];
    for network in networks {
        network.drive(now, BUDGET).unwrap();
        while network.drain_events(&mut out).more {}
    }
}

#[test]
fn handle_parts_are_the_slots_the_network_keeps() {
    let (a, b) = (Queue::default(), Queue::default());
    let mut client = network(1, &a, &b);
    let mut server = network(2, &b, &a);
    let listener = server.listen(9000, 4).unwrap();
    assert!(listener.slot() < 2);
    assert_eq!(listener.instance(), server.instance);
    assert_eq!(
        listener.generation(),
        server.listeners[listener.slot()].generation
    );
    assert!(server.listeners[listener.slot()].value.is_some());
    assert_eq!(
        server.listener_map.values().copied().collect::<Vec<_>>(),
        [listener.slot()]
    );
    let peer = SocketAddr::new(IpAddr::from([10, 76, 0, 2]), 9000);
    let ids: Vec<ConnId> = (0..3).map(|_| client.connect(peer).unwrap()).collect();
    for (k, &id) in ids.iter().enumerate() {
        assert!(id.slot() < 4);
        assert_eq!(id.instance(), client.instance);
        assert_ne!(id.instance(), server.instance);
        assert_eq!(client.conn_id(id.slot()), id);
        assert!(client.connections[id.slot()].value.is_some());
        assert!(ids[..k].iter().all(|other| other.slot() != id.slot()));
    }
    let mut now = 0;
    let mut accepted = Vec::new();
    while accepted.len() < 3 {
        now += 1000;
        assert!(now < 100_000, "handshakes did not finish");
        step([&mut client, &mut server], now);
        while let Ok(id) = server.accept(listener) {
            assert_eq!(server.conn_id(id.slot()), id);
            assert!(server.live_connections.contains(&id.slot()));
            accepted.push(id);
        }
    }
    // A released slot goes to the next handle, one generation on.
    let gone = ids[1];
    client.abort(gone).unwrap();
    while client.connections[gone.slot()].value.is_some() {
        now += 1000;
        assert!(now < 1_000_000, "the aborted connection was not released");
        step([&mut client, &mut server], now);
    }
    let again = client.connect(peer).unwrap();
    assert_eq!(again.slot(), gone.slot());
    assert_eq!(again.generation(), gone.generation() + 1);
    assert_ne!(again, gone);
    assert!(matches!(client.readiness(gone), Err(Error::InvalidHandle)));
}
