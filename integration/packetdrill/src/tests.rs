// SPDX-License-Identifier: GPL-2.0-or-later
use super::*;

fn request(
    op: i32,
    fd: i32,
    a: i32,
    bytes: Vec<u8>,
    capacity: usize,
) -> (Request, Receiver<Result<Response>>) {
    let (reply, rx) = mpsc::sync_channel(1);
    (
        Request {
            op,
            fd,
            a,
            b: 0,
            bytes,
            capacity,
            deadline: None,
            started: false,
            reply,
        },
        rx,
    )
}
fn call(
    adapter: &Adapter,
    op: i32,
    fd: i32,
    a: i32,
    bytes: Vec<u8>,
    capacity: usize,
) -> Result<Response> {
    let (r, rx) = request(op, fd, a, bytes, capacity);
    adapter
        .tx
        .try_send(r)
        .unwrap_or_else(|_| panic!("test request channel unexpectedly full"));
    rx.recv_timeout(Duration::from_secs(3))
        .expect("owner did not respond")
}
fn local() -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, 1)
}
fn syn(sequence: u32, destination_port: u16) -> Vec<u8> {
    let ip = IpMetadata {
        source: Ipv4Addr::new(192, 0, 2, 2).into(),
        destination: local().into(),
    };
    let header = ntcp::wire::Header {
        source_port: 50000,
        destination_port,
        sequence,
        acknowledgment: 0,
        flags: ntcp::wire::SYN,
        window: 65535,
        urgent_pointer: 0,
    };
    let mut tcp = [0; 64];
    let n = ntcp::wire::encode(ip, header, &[], &[], &mut tcp).unwrap();
    frame(
        ntcp::Transmit {
            ip,
            len: n,
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
            ipv4_options: Default::default(),
        },
        &tcp[..n],
    )
    .unwrap()
}

#[test]
fn abi_table_null_counts_vectors_variadics_and_host_clock() {
    unsafe extern "C" {
        fn ntcp_abi_check(userdata: *mut c_void);
    }
    let mut adapter = Adapter::start(local()).unwrap();
    unsafe {
        ntcp_abi_check((&mut adapter as *mut Adapter).cast());
    }
}

#[test]
fn ipv4_validation_and_address_roundtrip() {
    let packet = syn(7, 8080);
    let (ip, tcp) = parse_frame(&packet).unwrap();
    assert_eq!(ntcp::wire::parse(ip, tcp).unwrap().header.sequence, 7);
    assert_eq!(parse_frame(&packet[..19]).unwrap_err(), EINVAL);
    for index in [2, 10, 24, 36] {
        let mut malformed = packet.clone();
        malformed[index] ^= 1;
        assert_eq!(parse_frame(&malformed).unwrap_err(), EINVAL);
    }
    let mut malformed = packet.clone();
    malformed[6] |= 0x20;
    assert_eq!(parse_frame(&malformed).unwrap_err(), ENOSYS);
    malformed = packet.clone();
    malformed[0] = 0x46;
    assert_eq!(parse_frame(&malformed).unwrap_err(), ENOSYS);
    malformed[0] = 0x60;
    assert_eq!(parse_frame(&malformed).unwrap_err(), ENOSYS);
    let address = SocketAddr::new(local().into(), 8080);
    assert_eq!(decode_addr(&encode_addr(address)).unwrap(), address);
    assert!(profile("").is_err());
    assert_eq!(profile("baseline,local=192.0.2.1").unwrap(), local());
    assert!(profile("baseline,local=192.0.2.1,sack").is_err());
}

#[test]
fn owner_constructs_endpoint_and_preserves_output_under_backpressure() {
    let adapter = Adapter::start(local()).unwrap();
    for i in 0..LIMIT + 4 {
        // Respect Endpoint's separate 128-control-replies/second rate limit.
        if i == LIMIT {
            thread::sleep(Duration::from_millis(1010));
        }
        call(&adapter, 14, 0, 0, syn(i as u32, 8080), 0).unwrap();
    }
    // A small caller buffer must not consume the queued packet.
    assert_eq!(call(&adapter, 15, 0, 0, vec![], 1).err(), Some(EMSGSIZE));
    for i in 0..LIMIT + 4 {
        let response = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap();
        let (ip, tcp) = parse_frame(&response.bytes).unwrap();
        let segment = ntcp::wire::parse(ip, tcp).unwrap();
        assert_eq!(segment.header.flags, ntcp::wire::RST | ntcp::wire::ACK);
        assert_eq!(segment.header.acknowledgment, i as u32 + 1);
        assert!(response.stamp > 1_700_000_000_000_000);
    }
}

#[test]
fn pending_accept_does_not_block_packets_and_stop_joins() {
    let adapter = Adapter::start(local()).unwrap();
    let fd = call(&adapter, 1, 0, SOCK_STREAM, vec![], 0).unwrap().value as i32;
    call(
        &adapter,
        2,
        fd,
        0,
        encode_addr(SocketAddr::new(local().into(), 8080)),
        0,
    )
    .unwrap();
    call(&adapter, 3, fd, 1, vec![], 0).unwrap();
    let (r, waiting) = request(4, fd, 0, vec![], 16);
    adapter.tx.send(r).unwrap();
    assert!(waiting.recv_timeout(Duration::from_millis(5)).is_err());
    call(&adapter, 14, 0, 0, syn(100, 8080), 0).unwrap();
    let response = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap();
    let (ip, tcp) = parse_frame(&response.bytes).unwrap();
    assert_eq!(
        ntcp::wire::parse(ip, tcp).unwrap().header.flags,
        ntcp::wire::SYN | ntcp::wire::ACK
    );
    let before = Instant::now();
    drop(adapter);
    assert!(before.elapsed() < Duration::from_secs(1));
    assert_eq!(
        waiting.recv_timeout(Duration::from_secs(1)).unwrap().err(),
        Some(ECANCELED)
    );
}

#[test]
fn descriptor_and_request_limits_fail_without_hanging() {
    let adapter = Adapter::start(local()).unwrap();
    for _ in 0..LIMIT {
        call(&adapter, 1, 0, SOCK_STREAM, vec![], 0).unwrap();
    }
    assert_eq!(
        call(&adapter, 1, 0, SOCK_STREAM, vec![], 0).err(),
        Some(EMFILE)
    );
    call(&adapter, 8, 10000, 0, vec![], 0).unwrap();
    assert!(call(&adapter, 1, 0, SOCK_STREAM, vec![], 0).is_ok());
    assert_eq!(call(&adapter, 6, -1, 0, vec![], 10).err(), Some(EBADF));
    let (tx, _rx) = mpsc::sync_channel(1);
    let adapter = Adapter {
        tx,
        stop: Default::default(),
        failed: AtomicBool::new(false),
        join: None,
    };
    adapter.tx.try_send(request(1, 0, 0, vec![], 0).0).unwrap();
    assert_eq!(
        adapter.call(request(1, 0, 0, vec![], 0).0).err(),
        Some(EAGAIN)
    );
}

#[test]
fn pending_limit_and_poll_timeout() {
    let mut owner = Owner::new(local()).unwrap();
    let fd = owner.alloc(Socket::new(0)).unwrap();
    let p = pollfd {
        fd,
        events: POLLIN,
        revents: 0,
    };
    let bytes = unsafe {
        slice::from_raw_parts((&p as *const pollfd).cast(), std::mem::size_of::<pollfd>()).to_vec()
    };
    let (mut r, _) = request(13, 0, 5, bytes.clone(), bytes.len());
    assert!(owner.execute(&mut r).unwrap().is_none());
    r.deadline = Some(Instant::now());
    assert_eq!(owner.execute(&mut r).unwrap().unwrap().value, 0);
    owner.sockets.get_mut(&fd).unwrap().readable = None;
    assert_eq!(owner.execute(&mut r).err(), Some(ENOSYS));
    let adapter = Adapter::start(local()).unwrap();
    let mut replies = Vec::new();
    for _ in 0..LIMIT {
        let (r, rx) = request(13, 0, -1, vec![], 0);
        adapter.tx.send(r).unwrap();
        replies.push(rx);
    }
    // FIFO ordering means all earlier requests have occupied their pending slots.
    assert_eq!(
        call(&adapter, 1, 0, SOCK_STREAM, vec![], 0).err(),
        Some(EAGAIN)
    );
    drop(adapter);
    for rx in replies {
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap().err(),
            Some(ECANCELED)
        );
    }
}

#[test]
fn reuseaddr_allows_rebinding_connected_socket_but_not_listener() {
    let mut owner = Owner::new(local()).unwrap();
    let address = SocketAddr::new(local().into(), 40000);
    let id = owner
        .endpoint
        .connect(
            0,
            address,
            SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080),
        )
        .unwrap();
    let mut first = Socket::new(0);
    first.handle = Handle::Connection(id);
    first.local = Some(address);
    first.reuse = true;
    owner.alloc(first).unwrap();
    let fd = owner.alloc(Socket::new(0)).unwrap();
    let (mut bind, _) = request(2, fd, 0, encode_addr(address), 0);
    assert_eq!(owner.execute(&mut bind).err(), Some(EADDRINUSE));
    owner.sockets.get_mut(&fd).unwrap().reuse = true;
    assert!(owner.execute(&mut bind).unwrap().is_some());
    let (mut listen, _) = request(3, fd, 1, vec![], 0);
    assert!(owner.execute(&mut listen).unwrap().is_some());
    let mut third = Socket::new(0);
    third.reuse = true;
    bind.fd = owner.alloc(third).unwrap();
    assert_eq!(owner.execute(&mut bind).err(), Some(EADDRINUSE));
}

#[test]
fn socket_sends_wait_for_handshake_without_core_buffering() {
    let mut owner = Owner::new(local()).unwrap();
    let fd = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
    let remote = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080);
    let (mut connect, _) = request(5, fd, 0, encode_addr(remote), 0);
    assert_eq!(owner.execute(&mut connect).err(), Some(EINPROGRESS));
    let id = owner.connection(fd).unwrap();
    let (mut send, _) = request(7, fd, 0, vec![1, 2, 3, 4], 0);
    assert_eq!(owner.execute(&mut send).err(), Some(EAGAIN));
    owner.sockets.get_mut(&fd).unwrap().nonblock = false;
    send.a = MSG_DONTWAIT;
    assert_eq!(owner.execute(&mut send).err(), Some(EAGAIN));
    send.a = 0;
    assert!(owner.execute(&mut send).unwrap().is_none());
    assert_eq!(owner.sockets[&fd].written, 0);
    assert_eq!(owner.endpoint.state(id).unwrap(), State::SynSent);

    let mut tcp = [0; 1500];
    let tx = owner
        .endpoint
        .poll_transmit(owner.now(), &mut tcp, BUDGET)
        .unwrap()
        .packet
        .unwrap();
    let syn = ntcp::wire::parse(tx.ip, &tcp[..tx.len]).unwrap().header;
    let ip = IpMetadata {
        source: tx.ip.destination,
        destination: tx.ip.source,
    };
    let header = ntcp::wire::Header {
        source_port: syn.destination_port,
        destination_port: syn.source_port,
        sequence: 100,
        acknowledgment: syn.sequence.wrapping_add(1),
        flags: ntcp::wire::SYN | ntcp::wire::ACK,
        window: 65535,
        urgent_pointer: 0,
    };
    let n = ntcp::wire::encode(ip, header, &[], &[], &mut tcp).unwrap();
    owner.endpoint.input(owner.now(), ip, &tcp[..n]).unwrap();
    assert_eq!(owner.execute(&mut send).unwrap().unwrap().value, 4);
    assert_eq!(owner.sockets[&fd].written, 4);
    // Failed/pending sends must not have queued extra data in the core.
    let tx = owner
        .endpoint
        .poll_transmit(owner.now(), &mut tcp, BUDGET)
        .unwrap()
        .packet
        .unwrap();
    assert_eq!(
        ntcp::wire::parse(tx.ip, &tcp[..tx.len]).unwrap().payload,
        &[1, 2, 3, 4]
    );
}
