use super::*;

fn listen_at(owner: &mut Owner, port: u16) -> u64 {
    let fd = new(owner, SOCK_NONBLOCK);
    owner.execute(fd, Op::Bind(SocketAddr::new(owner.local, port))).unwrap();
    owner.execute(fd, Op::Listen(4)).unwrap();
    fd
}
fn present(owner: &mut Owner, port: u16) -> bool {
    owner.execute(0, Op::ListenerPresent(port)).unwrap().value != 0
}

#[test]
fn listener_query_checks_port_closing_state_and_generation() {
    let mut a = owner(1, Profile::Pipeline, 8);
    let fd = new(&mut a, SOCK_NONBLOCK);
    let address = "192.0.2.1:8080".parse().unwrap();
    a.execute(fd, Op::Bind(address)).unwrap();
    assert!(!present(&mut a, 8080));
    a.execute(fd, Op::Listen(4)).unwrap();
    let Handle::Listener(first) = a.sockets[&fd].handle else {panic!()};
    assert!(present(&mut a, 8080));
    assert!(!present(&mut a, 8081));
    assert_eq!(a.execute(0, Op::ListenerPresent(0)).unwrap_err(), EINVAL);
    // Deliberately stale runtime label: SO_ACCEPTCONN alone still says1.
    a.endpoint.close_listener(first).unwrap();
    assert_eq!(a.execute(fd, Op::Get(SOL_SOCKET, SO_ACCEPTCONN)).unwrap().value, 1);
    assert!(!present(&mut a, 8080));
    a.endpoint.poll_transmit(a.now(), &mut [0;2048], BUDGET).unwrap();
    let next = a.endpoint.listen(address, 4).unwrap();
    assert_ne!(first, next);
    assert!(!present(&mut a, 8080)); // New core generation cannot revive old label.
    a.sockets.get_mut(&fd).unwrap().handle = Handle::Listener(next);
    assert!(present(&mut a, 8080));
    a.execute(fd, Op::Close).unwrap();
    assert!(!present(&mut a, 8080));
}

#[test]
fn listener_query_does_not_treat_established_or_timewait_children_as_listeners() {
    let (mut a, mut b, clients, servers) = pair(Profile::Pipeline, 8);
    let listener = b.sockets.iter().find_map(|(&fd,s)| matches!(s.handle, Handle::Listener(_)).then_some(fd)).unwrap();
    assert!(present(&mut b, 8080));
    b.execute(listener, Op::Close).unwrap();
    assert!(!present(&mut b, 8080));
    let child = cid(&b, servers[0]);
    assert_eq!(b.endpoint.state(child).unwrap(), State::Established);
    b.execute(servers[0], Op::Shutdown(SHUT_WR)).unwrap();
    exchange(&mut a, &mut b);
    a.execute(clients[0], Op::Shutdown(SHUT_WR)).unwrap();
    exchange(&mut a, &mut b);
    assert_eq!(b.endpoint.state(child).unwrap(), State::TimeWait);
    assert_eq!(b.endpoint.state(cid(&b, servers[1])).unwrap(), State::Established);
    assert!(!present(&mut b, 8080));
}

#[test]
fn listener_query_preserves_pending_accept_and_connection_clock() {
    let (mut a, mut b, listener) = tfo_setup(false);
    let client = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(a.execute(client, Op::Connect("192.0.2.2:8080".parse().unwrap())).unwrap_err(), EINPROGRESS);
    exchange(&mut a, &mut b);
    let Handle::Listener(id) = b.sockets[&listener].handle else {panic!()};
    assert_eq!(b.endpoint.listener_queue_info(id).unwrap(), (1,4));
    let remote = a.sockets[&client].local.unwrap();
    let child = b.endpoint.connection_id(ntcp::Tuple {local:"192.0.2.2:8080".parse().unwrap(),remote}).unwrap();
    let before = format!("{:?}", b.endpoint.transport_info(child).unwrap());
    let budget = b.endpoint.buffer_bytes();
    let deadline = b.endpoint.next_deadline();
    let ready = b.endpoint.ready_connections().collect::<Vec<_>>();
    let queued = (b.packets.as_ref().unwrap().input.len(),b.packets.as_ref().unwrap().output.len());
    b.test_now = Some(b.now()+123_000);
    for _ in 0..4 {assert!(present(&mut b, 8080));}
    assert_eq!(format!("{:?}", b.endpoint.transport_info(child).unwrap()), before);
    assert_eq!(b.endpoint.listener_queue_info(id).unwrap(), (1,4));
    assert_eq!(b.endpoint.buffer_bytes(),budget);
    assert_eq!(b.endpoint.next_deadline(),deadline);
    assert_eq!(b.endpoint.ready_connections().collect::<Vec<_>>(),ready);
    assert_eq!((b.packets.as_ref().unwrap().input.len(),b.packets.as_ref().unwrap().output.len()),queued);
    let server=b.execute(listener, Op::Accept(SOCK_NONBLOCK)).unwrap().value as u64;
    assert_eq!(cid(&b,server),child);
}

#[test]
fn listener_query_preserves_held_output_and_progresses_under_backpressure() {
    let (mut a, _b, clients, _) = pair(Profile::PipelineGso, 1);
    listen_at(&mut a, 8081);
    let held = cid(&a,clients[0]);
    a.execute(clients[0],Op::Write(vec![7;4380])).unwrap();
    a.service_egress().unwrap();
    assert!(a.endpoint.is_output_reserved(held));
    let attempt = a.egress.as_ref().unwrap().attempt(held);
    let bytes = a
        .packets
        .as_ref()
        .unwrap()
        .output
        .front()
        .unwrap()
        .0
        .bytes
        .clone();
    let descriptor = a.endpoint.transmit_segmentation(attempt).unwrap();
    let deadline = a.endpoint.next_deadline();
    assert!(present(&mut a,8081));
    assert!(a.endpoint.is_output_reserved(held));
    assert_eq!(a.egress.as_ref().unwrap().attempt(held),attempt);
    assert_eq!(
        a.packets.as_ref().unwrap().output.front().unwrap().0.bytes,
        bytes
    );
    assert_eq!(a.endpoint.transmit_segmentation(attempt).unwrap(),descriptor);
    assert_eq!(a.endpoint.next_deadline(),deadline);
}
