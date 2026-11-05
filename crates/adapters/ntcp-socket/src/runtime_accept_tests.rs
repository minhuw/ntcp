// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::super::tests::{new, pair, poll_packet, pump};
use super::*;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct AckBackend {
    blocked: bool,
    attempts: usize,
}
struct Backend(Arc<Mutex<AckBackend>>);
impl PacketIo for Backend {
    fn layer(&self) -> ntcp_io::PacketLayer {
        ntcp_io::PacketLayer::Ethernet
    }
    fn receive(&mut self, _: &mut [u8]) -> std::io::Result<Option<usize>> {
        Ok(None)
    }
    fn transmit(&mut self, bytes: &[u8]) -> std::io::Result<TxOutcome> {
        let frame = ntcp_ethernet::parse_ethernet(bytes).unwrap();
        let ip = ntcp_ip::parse(frame.payload, false).unwrap();
        let tcp = ntcp::wire::parse(ip.ip, ip.payload).unwrap();
        assert_eq!(tcp.header.flags, ntcp::wire::ACK);
        assert!(tcp.payload.is_empty());
        let mut state = self.0.lock().unwrap();
        state.attempts += 1;
        Ok(if state.blocked {
            TxOutcome::WouldBlock
        } else {
            TxOutcome::Submitted
        })
    }
}

// Establish before enabling egress: the held packet is a data ACK, not SYN-ACK.
fn held_child(siblings: usize, flags: i32) -> (Owner, u64, ConnectionId, Arc<Mutex<AckBackend>>) {
    let (mut a, mut b, _, _, listener) = pair();
    // Pair setup uses elapsed time; never move either endpoint backwards if
    // parallel test load makes that setup take more than one second.
    let now = a.now().max(b.now()).max(1_000_000);
    a.test_now = Some(now);
    b.test_now = Some(now);
    b.sockets.get_mut(&listener).unwrap().flags = flags;
    let mut clients = Vec::new();
    for _ in 0..=siblings {
        let client = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(client, Op::Connect("10.73.0.3:16379".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        pump(&mut a, &mut b);
        clients.push(client);
    }
    let cid = b.child_timeouts[0].0;
    assert_eq!(b.endpoint.state(cid), Ok(State::Established));
    assert_ne!(b.execute(listener, Op::Ready).unwrap().value & EPOLLIN, 0);
    let backend = Arc::new(Mutex::new(AckBackend {
        blocked: true,
        ..Default::default()
    }));
    b.ports[0].ethernet = Some(EthernetBackend {
        io: Box::new(Backend(backend.clone())),
        local: [2; 6],
        next_hop: Some([4; 6]),
        next_cookie: 1,
        pending: Vec::new(),
        cancelled: Vec::new(),
    });
    b.enable_egress(4, None).unwrap();
    a.execute(clients[0], Op::Write(vec![7; 10])).unwrap();
    let bytes = poll_packet(&mut a).unwrap();
    let ip = ntcp_ip::parse(&bytes, false).unwrap();
    b.input(b.now(), ip.ip, ip.traffic_class, ip.payload)
        .unwrap();
    b.test_now = Some(b.now() + 250_000);
    b.endpoint.on_timeout(b.now(), BUDGET).unwrap();
    b.service_egress().unwrap();
    assert!(b.endpoint.is_output_reserved(cid));
    assert_eq!(backend.lock().unwrap().attempts, 1);
    (b, listener, cid, backend)
}

fn accept_request(listener: u64) -> (Request, Receiver<Result<Reply>>) {
    let (reply, response) = mpsc::sync_channel(1);
    (
        Request {
            id: listener,
            op: Op::Wait(Box::new(Op::Accept(SOCK_NONBLOCK)), None),
            reply,
            deadline: None,
            send: None,
            closing: None,
        },
        response,
    )
}

#[test]
fn held_ack_nonblocking_accept_returns_eagain() {
    let (mut b, listener, cid, _) = held_child(0, SOCK_NONBLOCK);
    let (mut request, response) = accept_request(listener);
    assert!(b.service(&mut request));
    assert_eq!(response.recv().unwrap().unwrap_err(), EAGAIN);
    assert_eq!(b.execute(listener, Op::Ready).unwrap().value & EPOLLIN, 0);
    assert!(b.endpoint.is_output_reserved(cid));
    assert_eq!(engine(EndpointError::OutputReserved), EINVAL);
}

#[test]
fn held_ack_blocking_accept_waits_until_resolution() {
    let (mut b, listener, cid, backend) = held_child(0, 0);
    let (mut request, response) = accept_request(listener);
    for _ in 0..3 {
        assert!(!b.service(&mut request));
        assert!(response.try_recv().is_err());
    }
    assert_eq!(b.execute(listener, Op::Ready).unwrap().value & EPOLLIN, 0);
    backend.lock().unwrap().blocked = false;
    b.test_now = Some(b.now() + 1000);
    b.service_egress().unwrap();
    assert!(!b.endpoint.is_output_reserved(cid));
    b.events();
    assert_ne!(b.execute(listener, Op::Ready).unwrap().value & EPOLLIN, 0);
    assert!(b.service(&mut request));
    let accepted = response.recv().unwrap().unwrap().value as u64;
    assert!(matches!(b.sockets[&accepted].handle, Handle::Connection(id) if id == cid));
    assert_eq!(backend.lock().unwrap().attempts, 2);
}

#[test]
fn held_ack_accept_skips_to_unheld_sibling() {
    let (mut b, listener, held, _) = held_child(1, SOCK_NONBLOCK);
    let sibling = b.child_timeouts[1].0;
    assert!(!b.endpoint.is_output_reserved(sibling));
    let (mut request, response) = accept_request(listener);
    assert!(b.service(&mut request));
    let accepted = response.recv().unwrap().unwrap().value as u64;
    assert!(matches!(b.sockets[&accepted].handle, Handle::Connection(id) if id == sibling));
    assert!(b.endpoint.is_output_reserved(held));
    assert_eq!(b.execute(listener, Op::Accept(0)).unwrap_err(), EAGAIN);
}
