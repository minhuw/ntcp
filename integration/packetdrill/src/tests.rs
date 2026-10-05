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
    syn_with_options(sequence, destination_port, &[])
}
fn syn_with_options(sequence: u32, destination_port: u16, options: &[u8]) -> Vec<u8> {
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
    let n = ntcp::wire::encode(ip, header, options, &[], &mut tcp).unwrap();
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
    let mut adapter = Adapter::start((local(), Profile::Baseline)).unwrap();
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
    assert_eq!(
        profile("baseline,local=192.0.2.1").unwrap(),
        (local(), Profile::Baseline)
    );
    assert!(profile("baseline,local=192.0.2.1,sack").is_err());
}

#[test]
fn owner_constructs_endpoint_and_preserves_output_under_backpressure() {
    let adapter = Adapter::start((local(), Profile::Baseline)).unwrap();
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
    let adapter = Adapter::start((local(), Profile::Baseline)).unwrap();
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
    let inode = identity(fd).unwrap();
    let before = Instant::now();
    drop(adapter);
    assert_ne!(identity(fd), Some(inode));
    assert!(before.elapsed() < Duration::from_secs(1));
    assert_eq!(
        waiting.recv_timeout(Duration::from_secs(1)).unwrap().err(),
        Some(ECANCELED)
    );
}

#[test]
fn descriptor_and_request_limits_fail_without_hanging() {
    let adapter = Adapter::start((local(), Profile::Baseline)).unwrap();
    let mut fds = Vec::new();
    for _ in 0..LIMIT {
        fds.push(call(&adapter, 1, 0, SOCK_STREAM, vec![], 0).unwrap().value as i32);
    }
    assert_eq!(
        call(&adapter, 1, 0, SOCK_STREAM, vec![], 0).err(),
        Some(EMFILE)
    );
    call(&adapter, 8, fds[0], 0, vec![], 0).unwrap();
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
    let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
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
    let adapter = Adapter::start((local(), Profile::Baseline)).unwrap();
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
    let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
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
    let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
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

#[test]
fn profiles_require_one_selection_and_one_ipv4_address() {
    assert_eq!(
        profile("local=192.0.2.1,upstream-window8").unwrap(),
        (local(), Profile::UpstreamWindow8)
    );
    for flags in [
        "",
        "baseline",
        "upstream-window8",
        "local=192.0.2.1",
        "baseline,baseline,local=192.0.2.1",
        "upstream-window8,upstream-window8,local=192.0.2.1",
        "baseline,upstream-window8,local=192.0.2.1",
        "upstream-window8,baseline,local=192.0.2.1",
        "baseline,local=192.0.2.1,local=192.0.2.1",
        "upstream-window8,local=192.0.2.1,local=192.0.2.2",
        "upstream-window8,local=::1",
        "baseline,local=invalid",
        "upstream-window8,local=192.0.2.1,sack",
        "upstream-window8,local=192.0.2.1,",
    ] {
        assert_eq!(profile(flags), Err(ENOSYS), "{flags}");
    }
}

#[test]
fn profiles_emit_real_synack_scale_through_owner_thread() {
    for (name, scale) in [("baseline", 0), ("upstream-window8", 8)] {
        let adapter = Adapter::start(profile(&format!("{name},local=192.0.2.1")).unwrap()).unwrap();
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
        // MSS and WS only, matching the upstream tests' lack of SACK/TS negotiation.
        let syn = syn_with_options(100, 8080, &[2, 4, 5, 180, 1, 3, 3, 7]);
        call(&adapter, 14, 0, 0, syn, 0).unwrap();
        let response = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap();
        let (ip, tcp) = parse_frame(&response.bytes).unwrap();
        let segment = ntcp::wire::parse(ip, tcp).unwrap();
        assert_eq!(segment.header.flags, ntcp::wire::SYN | ntcp::wire::ACK);
        assert_eq!(segment.header.window, 65535);
        assert_eq!(segment.options.window_scale, Some(scale));
        assert_eq!(segment.options.mss, Some(1460));
        assert_eq!(segment.options.timestamps, None);
        assert_eq!(segment.raw_options, &[2, 4, 5, 180, 1, 3, 3, scale]);
    }
}

#[test]
fn profiles_charge_actual_receive_capacity_and_enforce_aggregate_cap() {
    for (name, receive_capacity) in [("baseline", 65535), ("upstream-window8", 8 * 1024 * 1024)] {
        let mut owner = Owner::new(profile(&format!("{name},local=192.0.2.1")).unwrap()).unwrap();
        // Core accounts for receive data/presence/urgent maps, send storage and MSS scratch.
        let per_connection = 3 * receive_capacity + 2 * 65536 + 1460;
        let max_bytes = 32 * 1024 * 1024;
        let count = LIMIT.min(max_bytes / per_connection);
        for i in 0..count {
            owner
                .endpoint
                .connect(
                    0,
                    SocketAddr::new(local().into(), 40000 + i as u16),
                    SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080),
                )
                .unwrap();
            assert_eq!(owner.endpoint.buffer_bytes(), (i + 1) * per_connection);
            assert!(owner.endpoint.buffer_bytes() <= max_bytes);
        }
        assert_eq!(
            owner.endpoint.connect(
                0,
                SocketAddr::new(local().into(), 50000),
                SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080),
            ),
            Err(EndpointError::LimitReached)
        );
        assert_eq!(owner.endpoint.buffer_bytes(), count * per_connection);
    }
}

fn execute_value(owner: &mut Owner, op: i32, fd: i32, key: i32, value: i32) -> Result<i64> {
    let (mut r, _) = request(op, fd, key, vec![], 0);
    r.b = value;
    owner.execute(&mut r).map(|r| r.unwrap().value)
}

#[test]
fn user_timeout_preconnect_updates_reset_and_deadlines() {
    let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
    let fd = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
    assert_eq!(execute_value(&mut owner, 12, fd, 5, 0), Ok(0));
    assert_eq!(execute_value(&mut owner, 11, fd, 5, -1), Err(EINVAL));
    assert_eq!(execute_value(&mut owner, 12, fd, 5, 0), Ok(0));
    assert_eq!(user_timeout_us(0), Ok(None));
    execute_value(&mut owner, 11, fd, 5, i32::MAX).unwrap();
    assert_eq!(user_timeout_us(i32::MAX), Ok(Some(2_147_483_647_000)));
    execute_value(&mut owner, 11, fd, 5, 1234).unwrap();
    let (mut connect, _) = request(
        5,
        fd,
        0,
        encode_addr(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080)),
        0,
    );
    assert_eq!(owner.execute(&mut connect).err(), Some(EINPROGRESS));
    assert_eq!(execute_value(&mut owner, 12, fd, 5, 0), Ok(1234));
    let mut tcp = [0; 1500];
    let sent_at = owner.now();
    let tx = owner
        .endpoint
        .poll_transmit(sent_at, &mut tcp, BUDGET)
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
    let established_at = owner.now();
    owner.endpoint.input(established_at, ip, &tcp[..n]).unwrap();
    let id = owner.connection(fd).unwrap();
    owner.endpoint.write(id, b"data").unwrap();
    owner
        .endpoint
        .poll_transmit(owner.now(), &mut tcp, BUDGET)
        .unwrap();
    execute_value(&mut owner, 11, fd, 5, 1).unwrap();
    assert_eq!(owner.endpoint.next_deadline(), Some(established_at + 1000));
    execute_value(&mut owner, 11, fd, 5, 0).unwrap();
    assert_eq!(execute_value(&mut owner, 12, fd, 5, 0), Ok(0));
    assert!(owner.endpoint.next_deadline().unwrap() > established_at + 1000);
    assert_eq!(execute_value(&mut owner, 11, fd, 99, 1), Err(ENOSYS));
    assert_eq!(execute_value(&mut owner, 17, -1, 0, 0), Err(EBADF));
    assert_eq!(execute_value(&mut owner, 17, fd, 0, 0), Ok(0));
    execute_value(&mut owner, 11, fd, 5, 1).unwrap();
    owner
        .endpoint
        .on_timeout(established_at + 1000, BUDGET)
        .unwrap();
    owner.events();
    assert_eq!(
        execute_value(&mut owner, 12, fd, 3, 0),
        Ok(ETIMEDOUT as i64)
    );
}

#[test]
fn listener_timeout_inheritance_and_queued_payload_gap_urgent_fin() {
    let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
    let listener = owner.alloc(Socket::new(0)).unwrap();
    execute_value(&mut owner, 11, listener, 5, 1234).unwrap();
    let (mut bind, _) = request(
        2,
        listener,
        0,
        encode_addr(SocketAddr::new(local().into(), 8080)),
        0,
    );
    owner.execute(&mut bind).unwrap();
    execute_value(&mut owner, 3, listener, 1, 0).unwrap();
    assert_eq!(execute_value(&mut owner, 17, listener, 0, 0), Err(EINVAL));
    let (ip, tcp) = parse_frame(&syn(100, 8080))
        .map(|(ip, tcp)| (ip, tcp.to_vec()))
        .unwrap();
    owner.endpoint.input(0, ip, &tcp).unwrap();
    let mut out = [0; 1500];
    let tx = owner
        .endpoint
        .poll_transmit(0, &mut out, BUDGET)
        .unwrap()
        .packet
        .unwrap();
    let ack = ntcp::wire::parse(tx.ip, &out[..tx.len])
        .unwrap()
        .header
        .sequence
        .wrapping_add(1);
    let mut inject = |owner: &mut Owner, seq, flags, urgent, payload: &[u8]| {
        let header = ntcp::wire::Header {
            source_port: 50000,
            destination_port: 8080,
            sequence: seq,
            acknowledgment: ack,
            flags,
            window: 65535,
            urgent_pointer: urgent,
        };
        let n = ntcp::wire::encode(ip, header, &[], payload, &mut out).unwrap();
        owner.endpoint.input(0, ip, &out[..n]).unwrap();
    };
    inject(&mut owner, 101, ntcp::wire::ACK, 0, &[]);
    execute_value(&mut owner, 11, listener, 5, 3456).unwrap();
    let fd = execute_value(&mut owner, 4, listener, 0, 0).unwrap() as i32;
    let id = owner.connection(fd).unwrap();
    assert_eq!(execute_value(&mut owner, 12, fd, 5, 0), Ok(1234));
    execute_value(&mut owner, 11, listener, 5, 3456).unwrap();
    assert_eq!(execute_value(&mut owner, 12, fd, 5, 0), Ok(1234));
    owner.endpoint.write(id, b"x").unwrap();
    let mut outgoing = [0; 1500];
    owner
        .endpoint
        .poll_transmit(0, &mut outgoing, BUDGET)
        .unwrap();
    assert_eq!(owner.endpoint.application_timeout(id), Ok(Some(1_234_000)));
    assert!(owner.endpoint.next_deadline().unwrap() <= 1_234_000);
    assert_eq!(owner.endpoint.readable_bytes(id), Ok(0));
    inject(
        &mut owner,
        104,
        ntcp::wire::ACK | ntcp::wire::FIN | ntcp::wire::URG,
        3,
        b"def",
    );
    assert_eq!(execute_value(&mut owner, 17, fd, 0, 0), Ok(0));
    inject(&mut owner, 101, ntcp::wire::ACK, 0, b"abc");
    for _ in 0..2 {
        assert_eq!(execute_value(&mut owner, 17, fd, 0, 0), Ok(6));
    }
    assert_eq!(owner.endpoint.urgent_remaining(id), Ok(6));
    let (mut read, _) = request(6, fd, 0, vec![], 2);
    let response = owner.execute(&mut read).unwrap().unwrap();
    assert_eq!(response.bytes, b"ab");
    assert_eq!(execute_value(&mut owner, 17, fd, 0, 0), Ok(4));
    execute_value(&mut owner, 11, fd, 5, 4567).unwrap();
    assert_eq!(execute_value(&mut owner, 12, fd, 5, 0), Ok(4567));
    read.capacity = 8;
    assert_eq!(owner.execute(&mut read).unwrap().unwrap().bytes, b"cdef");
    assert_eq!(execute_value(&mut owner, 17, fd, 0, 0), Ok(0));
    assert_eq!(owner.execute(&mut read).unwrap().unwrap().value, 0);
    assert_eq!(execute_value(&mut owner, 17, fd, 0, 0), Ok(0));
}

fn identity(fd: i32) -> Option<(dev_t, ino_t)> {
    let mut info: stat = unsafe { std::mem::zeroed() };
    (unsafe { fstat(fd, &mut info) } == 0).then_some((info.st_dev, info.st_ino))
}

#[test]
fn token_explicit_close_host_close_and_foreign_replacement() {
    let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
    let fd = owner.alloc(Socket::new(0)).unwrap();
    let inode = identity(fd).unwrap();
    let retained = owner.sockets[&fd]
        .token
        .as_ref()
        .unwrap()
        .retained
        .as_raw_fd();
    assert_eq!(identity(retained), Some(inode));
    execute_value(&mut owner, 8, fd, 0, 0).unwrap();
    assert_ne!(identity(fd), Some(inode));
    assert_ne!(identity(retained), Some(inode));
    assert_eq!(execute_value(&mut owner, 8, fd, 0, 0), Err(EBADF));

    let token = Token::new().unwrap();
    let inode = identity(token.fd).unwrap();
    let retained = token.retained.as_raw_fd();
    unsafe {
        assert_eq!(libc::close(token.fd), 0);
    }
    assert_eq!(identity(retained), Some(inode));
    drop(token);
    assert_ne!(identity(retained), Some(inode));

    let fd = owner.alloc(Socket::new(0)).unwrap();
    let foreign = std::fs::File::open("/dev/null").unwrap();
    assert_eq!(
        execute_value(&mut owner, 8, foreign.as_raw_fd(), 0, 0),
        Err(EBADF)
    );
    // dup2 atomically models host close followed by reuse, avoiding a test race
    // with other tests' allocations in the freed-fd interval.
    unsafe {
        assert_eq!(dup2(foreign.as_raw_fd(), fd), fd);
    }
    let replacement = unsafe { OwnedFd::from_raw_fd(fd) };
    assert_eq!(execute_value(&mut owner, 8, -1, 0, 0), Err(EBADF));
    drop(owner);
    assert_eq!(
        identity(replacement.as_raw_fd()),
        identity(foreign.as_raw_fd())
    );
}

#[test]
fn token_partial_allocation_failure_closes_first_descriptor() {
    let mut allocated = None;
    let result = Token::with_duplicate(|fd| {
        allocated = Some((fd, identity(fd).unwrap()));
        unsafe {
            *__errno_location() = EMFILE;
        }
        -1
    });
    assert_eq!(result.err(), Some(EMFILE));
    let (fd, inode) = allocated.unwrap();
    assert_ne!(identity(fd), Some(inode));
}

#[test]
fn logical_ephemeral_ports_do_not_follow_reused_os_descriptors() {
    let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
    let remote = encode_addr(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080));
    for port in 40000..40004 {
        let fd = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
        let (mut connect, _) = request(5, fd, 0, remote.clone(), 0);
        assert_eq!(owner.execute(&mut connect).err(), Some(EINPROGRESS));
        assert_eq!(owner.sockets[&fd].local.unwrap().port(), port);
        execute_value(&mut owner, 8, fd, 0, 0).unwrap();
    }
    owner.next_port = 60000;
    let fd = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
    let (mut connect, _) = request(5, fd, 0, remote, 0);
    assert_eq!(owner.execute(&mut connect).err(), Some(EADDRNOTAVAIL));
}

#[test]
fn explicit_close_cancels_pending_accept_before_descriptor_reuse() {
    let adapter = Adapter::start((local(), Profile::Baseline)).unwrap();
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
    call(&adapter, 8, fd, 0, vec![], 0).unwrap();
    assert_eq!(
        waiting.recv_timeout(Duration::from_secs(1)).unwrap().err(),
        Some(EBADF)
    );
    call(&adapter, 1, 0, SOCK_STREAM, vec![], 0).unwrap();
}
