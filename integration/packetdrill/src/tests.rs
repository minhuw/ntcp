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
            connection: None,
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
    let userdata = (&mut adapter as *mut Adapter).cast();
    *INSTANCE.write().unwrap() = userdata as usize;
    unsafe {
        ntcp_abi_check(userdata);
    }
    *INSTANCE.write().unwrap() = 0;
    drop(adapter);
    let mut adapter = Adapter::start((local(), Profile::Baseline)).unwrap();
    let userdata = (&mut adapter as *mut Adapter).cast();
    *INSTANCE.write().unwrap() = userdata as usize;
    let fd = call(&adapter, 1, 0, SOCK_NONBLOCK, vec![], 0)
        .unwrap()
        .value as i32;
    assert_eq!(
        call(
            &adapter,
            5,
            fd,
            0,
            encode_addr(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080)),
            0
        )
        .err(),
        Some(EINPROGRESS)
    );
    let mut info = [0xa5u8; TCP_INFO_SIZE + 8];
    let mut n = info.len() as socklen_t;
    unsafe {
        assert_eq!(
            getsockopt(fd, IPPROTO_TCP, TCP_INFO, info.as_mut_ptr().cast(), &mut n),
            0
        );
    }
    assert_eq!(n as usize, TCP_INFO_SIZE);
    assert_eq!((info[0], info[1]), (2, 0));
    assert_eq!(&info[TCP_INFO_SIZE..], &[0xa5; 8]);
    let expected = call(&adapter, 18, fd, 1, vec![], TCP_INFO_SIZE)
        .unwrap()
        .bytes;
    assert_eq!(&info[..TCP_INFO_SIZE], expected);
    for (option, length) in [(TCP_CC_INFO, 0), (TCP_INFO, TCP_INFO_SIZE)] {
        for capacity in [0, 1, 7, TCP_INFO_SIZE + 8] {
            info.fill(0xa5);
            n = capacity as socklen_t;
            unsafe {
                assert_eq!(
                    getsockopt(fd, IPPROTO_TCP, option, info.as_mut_ptr().cast(), &mut n),
                    0
                );
            }
            assert_eq!(n as usize, capacity.min(length));
            assert!(info[n as usize..].iter().all(|b| *b == 0xa5));
        }
    }
    n = 36;
    unsafe {
        assert_eq!(
            getsockopt(fd, SOL_SOCKET, SO_MEMINFO, info.as_mut_ptr().cast(), &mut n),
            0
        );
    }
    assert_eq!(n, 36);
    assert_eq!(u32::from_ne_bytes(info[4..8].try_into().unwrap()), 65535);
    unsafe {
        assert_eq!(
            getsockopt(fd, IPPROTO_TCP, TCP_INFO, ptr::null_mut(), &mut n),
            -1
        );
        assert_eq!(*__errno_location(), EFAULT);
        assert_eq!(
            getsockopt(
                fd,
                IPPROTO_TCP,
                TCP_INFO,
                info.as_mut_ptr().cast(),
                ptr::null_mut()
            ),
            -1
        );
        assert_eq!(*__errno_location(), EFAULT);
    }
    n = TCP_INFO_SIZE as socklen_t;
    unsafe {
        assert_eq!(
            getsockopt(-1, IPPROTO_TCP, TCP_INFO, info.as_mut_ptr().cast(), &mut n),
            -1
        );
        assert_eq!(*__errno_location(), EBADF);
        // Keep fd reserved until dup2 atomically replaces our own descriptor.
        // Closing first lets parallel tests reuse it before the assertions or dup2.
        let host = libc::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        assert!(host >= 0);
        if host != fd {
            assert_eq!(dup2(host, fd), fd);
            libc::close(host);
        }
        assert_eq!(
            getsockopt(fd, IPPROTO_TCP, TCP_INFO, info.as_mut_ptr().cast(), &mut n),
            -1
        );
        assert_ne!(*__errno_location(), ENOTCONN);
        let mut domain = 0;
        n = 4;
        assert_eq!(
            getsockopt(
                fd,
                SOL_SOCKET,
                SO_DOMAIN,
                (&mut domain as *mut i32).cast(),
                &mut n
            ),
            0
        );
        assert_eq!(domain, AF_UNIX);
        assert_eq!(
            call(&adapter, 18, fd, 1, vec![], TCP_INFO_SIZE).err(),
            Some(EBADF)
        );
        libc::close(fd);
    }
    *INSTANCE.write().unwrap() = 0;
    drop(adapter);
    n = TCP_INFO_SIZE as socklen_t;
    unsafe {
        assert_eq!(
            getsockopt(-1, IPPROTO_TCP, TCP_INFO, info.as_mut_ptr().cast(), &mut n),
            -1
        );
        assert_eq!(*__errno_location(), EBADF);
        assert_eq!(
            ntcp_call(
                userdata,
                1,
                0,
                0,
                0,
                ptr::null(),
                0,
                ptr::null_mut(),
                0,
                ptr::null_mut()
            ),
            -1
        );
        assert_eq!(*__errno_location(), EIO);
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
fn owner_loop_emits_pure_handshake_ack_before_pending_send_data() {
    for selected in [Profile::Baseline, Profile::UpstreamWindow8] {
        let adapter = Adapter::start((local(), selected)).unwrap();
        let fd = call(&adapter, 1, 0, SOCK_NONBLOCK, vec![], 0)
            .unwrap()
            .value as i32;
        let remote = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080);
        assert_eq!(
            call(&adapter, 5, fd, 0, encode_addr(remote), 0).err(),
            Some(EINPROGRESS)
        );
        let syn = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap();
        let (outgoing_ip, tcp) = parse_frame(&syn.bytes).unwrap();
        let sent = ntcp::wire::parse(outgoing_ip, tcp).unwrap().header;
        let (mut blocking, _) = request(10, fd, F_SETFL, vec![], 0);
        blocking.b = 0;
        adapter.call(blocking).unwrap();
        let (send, sent_reply) = request(7, fd, 0, b"data".to_vec(), 0);
        adapter.tx.send(send).unwrap();
        // FIFO barrier proves SEND is pending before the SYNACK arrives.
        call(&adapter, 17, fd, 0, vec![], 0).unwrap();
        assert!(matches!(
            sent_reply.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        // Also queue a packet read: it must observe this iteration's pure ACK.
        let (read, packet_reply) = request(15, 0, 0, vec![], BYTES);
        adapter.tx.send(read).unwrap();
        call(&adapter, 17, fd, 0, vec![], 0).unwrap();
        assert!(matches!(
            packet_reply.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        let ip = IpMetadata {
            source: outgoing_ip.destination,
            destination: outgoing_ip.source,
        };
        let header = ntcp::wire::Header {
            source_port: sent.destination_port,
            destination_port: sent.source_port,
            sequence: 100,
            acknowledgment: sent.sequence.wrapping_add(1),
            flags: ntcp::wire::SYN | ntcp::wire::ACK,
            window: 65535,
            urgent_pointer: 0,
        };
        let mut tcp = [0; 64];
        let len = ntcp::wire::encode(ip, header, &[], &[], &mut tcp).unwrap();
        let bytes = frame(
            ntcp::Transmit {
                connection: None,
                ip,
                len,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: Default::default(),
            },
            &tcp[..len],
        )
        .unwrap();
        call(&adapter, 14, 0, 0, bytes, 0).unwrap();
        assert_eq!(
            sent_reply
                .recv_timeout(Duration::from_secs(3))
                .unwrap()
                .unwrap()
                .value,
            4
        );
        let ack = packet_reply
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .unwrap();
        let (ip, tcp) = parse_frame(&ack.bytes).unwrap();
        let ack = ntcp::wire::parse(ip, tcp).unwrap();
        assert_eq!(ack.header.flags, ntcp::wire::ACK);
        assert_eq!(ack.header.acknowledgment, 101);
        assert_eq!(ack.header.sequence, sent.sequence.wrapping_add(1));
        assert!(
            ack.payload.is_empty(),
            "{selected:?}: handshake ACK carried SEND data"
        );
        let data = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap();
        let (ip, tcp) = parse_frame(&data.bytes).unwrap();
        let data = ntcp::wire::parse(ip, tcp).unwrap();
        assert_eq!(data.header.sequence, ack.header.sequence);
        assert_eq!(data.header.acknowledgment, 101);
        assert_eq!(data.payload, b"data");
    }
}

#[test]
fn owner_loop_preserves_pending_send_read_fifo_on_refused_handshake() {
    let (mut send, _) = request(7, 0, 0, b"data".to_vec(), 0);
    let (mut read, _) = request(6, 0, 0, vec![], 4);
    // Rendezvous replies make out-of-order completion fail: an early READ
    // reply blocks the owner before it can answer the earlier SEND.
    let (send_reply, sent) = mpsc::sync_channel(0);
    let (read_reply, read_result) = mpsc::sync_channel(0);
    send.reply = send_reply;
    read.reply = read_reply;
    let (ready, barrier) = mpsc::sync_channel(1);
    let (requests, incoming) = mpsc::sync_channel(1);
    let join = thread::spawn(move || {
        let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
        let fd = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
        let remote = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080);
        let (mut connect, _) = request(5, fd, 0, encode_addr(remote), 0);
        assert_eq!(owner.execute_at_now(&mut connect).err(), Some(EINPROGRESS));
        let (tx, packet) = poll_frame(&mut owner).unwrap();
        let syn = packet_header(&packet);
        owner.sockets.get_mut(&fd).unwrap().nonblock = false;
        send.fd = fd;
        read.fd = fd;
        assert!(!owner.retry(&mut send));
        assert!(!owner.retry(&mut read));
        owner.pending.push_back(send);
        owner.pending.push_back(read);
        // Begin with real blocked requests in SEND/READ order.
        assert_eq!(
            owner.pending.iter().map(|r| r.op).collect::<Vec<_>>(),
            [7, 6]
        );
        let ip = IpMetadata {
            source: tx.ip.destination,
            destination: tx.ip.source,
        };
        let header = ntcp::wire::Header {
            source_port: syn.destination_port,
            destination_port: syn.source_port,
            sequence: 0,
            acknowledgment: syn.sequence.wrapping_add(1),
            flags: ntcp::wire::RST | ntcp::wire::ACK,
            window: 0,
            urgent_pointer: 0,
        };
        let mut tcp = [0; 64];
        let len = ntcp::wire::encode(ip, header, &[], &[], &mut tcp).unwrap();
        let rst = frame(
            ntcp::Transmit {
                connection: None,
                ip,
                len,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: Default::default(),
            },
            &tcp[..len],
        )
        .unwrap();
        ready.send((fd, rst)).unwrap();
        owner.run(incoming, &AtomicBool::new(false));
        assert!(owner.pending.is_empty());
        assert_eq!(owner.sockets[&fd].error, 0);
    });
    let (fd, rst) = barrier.recv_timeout(Duration::from_secs(3)).unwrap();
    // Each barrier is answered after a full error-free owner iteration with
    // both requests pending. Idle retries must not rotate SEND behind READ.
    for _ in 0..3 {
        let (r, reply) = request(17, fd, 0, vec![], 0);
        requests.try_send(r).unwrap();
        assert_eq!(
            reply
                .recv_timeout(Duration::from_secs(3))
                .unwrap()
                .unwrap()
                .value,
            0
        );
        assert!(matches!(sent.try_recv(), Err(mpsc::TryRecvError::Empty)));
        assert!(matches!(
            read_result.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }
    let (r, reply) = request(14, 0, 0, rst, 0);
    requests.try_send(r).unwrap();
    reply.recv_timeout(Duration::from_secs(3)).unwrap().unwrap();
    let send_result = sent.recv_timeout(Duration::from_secs(3));
    let received = read_result.recv_timeout(Duration::from_secs(3));
    // Drain both replies and disconnect before asserting; even a reordered
    // SEND must leave its rendezvous after the earlier receive times out.
    drop(sent);
    drop(read_result);
    drop(requests);
    join.join().unwrap();
    assert_eq!(send_result.unwrap().err(), Some(ECONNREFUSED));
    // Preserve the existing underlying closed-state READ error mapping.
    assert_eq!(received.unwrap().err(), Some(ENOTCONN));
}

#[test]
fn profiles_require_one_selection_and_one_ipv4_address() {
    assert_eq!(
        profile("local=192.0.2.1,upstream-window8").unwrap(),
        (local(), Profile::UpstreamWindow8)
    );
    assert_eq!(
        profile("sack,local=192.0.2.1").unwrap(),
        (local(), Profile::Sack)
    );
    assert_eq!(
        profile("upstream-sack,local=192.0.2.1").unwrap(),
        (local(), Profile::UpstreamSack)
    );
    for flags in [
        "",
        "upstream-sack",
        "upstream-sack,sack,local=192.0.2.1",
        "upstream-sack,upstream-sack,local=192.0.2.1",
        "sack",
        "sack,sack,local=192.0.2.1",
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
    for (name, scale) in [
        ("baseline", 0),
        ("upstream-window8", 8),
        ("upstream-sack", 8),
    ] {
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
fn window8_acks_third_2000_byte_packet_before_application_read() {
    for selected in [
        Profile::Baseline,
        Profile::Sack,
        Profile::UpstreamSack,
        Profile::UpstreamWindow8,
    ] {
        let mut owner = Owner::new((local(), selected)).unwrap();
        let listener = owner.alloc(Socket::new(0)).unwrap();
        let (mut bind, _) = request(
            2,
            listener,
            0,
            encode_addr(SocketAddr::new(local().into(), 8080)),
            0,
        );
        owner.execute_at_now(&mut bind).unwrap();
        execute_value(&mut owner, 3, listener, 1, 0).unwrap();
        let incoming_syn = syn_with_options(100, 8080, &[2, 4, 5, 180, 1, 3, 3, 7]);
        let ip = parse_frame(&incoming_syn).unwrap().0;
        let (mut incoming, _) = request(14, 0, 0, incoming_syn, 0);
        owner.execute_at_now(&mut incoming).unwrap();
        let (_, bytes) = poll_frame(&mut owner).unwrap();
        let ack = packet_header(&bytes).sequence.wrapping_add(1);
        let mut header = ntcp::wire::Header {
            source_port: 50000,
            destination_port: 8080,
            sequence: 101,
            acknowledgment: ack,
            flags: ntcp::wire::ACK,
            window: 65535,
            urgent_pointer: 0,
        };
        input_packet(&mut owner, ip, header, &[]);
        let fd = execute_value(&mut owner, 4, listener, 0, 0).unwrap() as i32;
        for i in 0..3 {
            header.sequence = 101 + i * 2000;
            let mut tcp = vec![0; 2020];
            let len = ntcp::wire::encode(ip, header, &[], &vec![0; 2000], &mut tcp).unwrap();
            let bytes = frame(
                ntcp::Transmit {
                    connection: None,
                    ip,
                    len,
                    hop_limit: 64,
                    dscp: 0,
                    ecn: 0,
                    ipv4_options: Default::default(),
                },
                &tcp[..len],
            )
            .unwrap();
            let (mut data, _) = request(14, 0, 0, bytes, 0);
            owner.execute_at_now(&mut data).unwrap();
            // Same owner iteration: process timers and poll real wire output,
            // without sleeping or advancing to the delayed-ACK deadline.
            owner.endpoint.on_timeout(owner.now(), BUDGET).unwrap();
            let output = poll_frame(&mut owner);
            if selected == Profile::UpstreamWindow8 {
                let (_, bytes) = output.expect("immediate ACK before read");
                let sent = packet_header(&bytes);
                assert_eq!(sent.flags, ntcp::wire::ACK);
                assert_eq!(sent.acknowledgment, 101 + (i + 1) * 2000);
            } else {
                assert!(output.is_none(), "{selected:?} retains delayed ACK");
            }
            if i < 2 {
                let (mut read, _) = request(6, fd, 0, vec![], 2000);
                assert_eq!(
                    owner.execute_at_now(&mut read).unwrap().unwrap().value,
                    2000
                );
                while poll_frame(&mut owner).is_some() {}
            }
        }
    }
}

#[test]
fn owner_loop_coalesces_queued_reads_with_immediate_ack_window_credit() {
    let adapter = Adapter::start((local(), Profile::UpstreamWindow8)).unwrap();
    let listener = call(&adapter, 1, 0, SOCK_STREAM, vec![], 0).unwrap().value as i32;
    call(
        &adapter,
        2,
        listener,
        0,
        encode_addr(SocketAddr::new(local().into(), 8080)),
        0,
    )
    .unwrap();
    call(&adapter, 3, listener, 1, vec![], 0).unwrap();
    let incoming_syn = syn_with_options(100, 8080, &[2, 4, 3, 232, 1, 3, 3, 7]);
    let ip = parse_frame(&incoming_syn).unwrap().0;
    call(&adapter, 14, 0, 0, incoming_syn, 0).unwrap();
    let synack = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap();
    let mut header = ntcp::wire::Header {
        source_port: 50000,
        destination_port: 8080,
        sequence: 101,
        acknowledgment: packet_header(&synack.bytes).sequence.wrapping_add(1),
        flags: ntcp::wire::ACK,
        window: 257,
        urgent_pointer: 0,
    };
    let send = |header, payload: &[u8]| {
        let mut tcp = vec![0; 20 + payload.len()];
        let len = ntcp::wire::encode(ip, header, &[], payload, &mut tcp).unwrap();
        let bytes = frame(
            ntcp::Transmit {
                connection: None,
                ip,
                len,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: Default::default(),
            },
            &tcp[..len],
        )
        .unwrap();
        call(&adapter, 14, 0, 0, bytes, 0).unwrap();
    };
    send(header, &[]);
    let fd = call(&adapter, 4, listener, 0, vec![], 0).unwrap().value as i32;
    for i in 0..3 {
        let read = if i < 2 {
            let (request, rx) = request(6, fd, 0, vec![], 2000);
            adapter
                .tx
                .try_send(request)
                .unwrap_or_else(|_| panic!("request channel full"));
            // FIFO barrier: the read has been attempted and queued before data.
            call(&adapter, 17, fd, 0, vec![], 0).unwrap();
            assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
            Some(rx)
        } else {
            None
        };
        header.sequence = 101 + i * 2000;
        header.flags = ntcp::wire::ACK | ntcp::wire::PSH;
        send(header, &vec![0; 2000]);
        if let Some(rx) = read {
            assert_eq!(
                rx.recv_timeout(Duration::from_secs(3))
                    .unwrap()
                    .unwrap()
                    .value,
                2000
            );
        }
        let output = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap();
        let sent = packet_header(&output.bytes);
        // An extra ACK from an earlier read would fail the cumulative ACK check.
        assert_eq!(sent.acknowledgment, 101 + (i + 1) * 2000);
        assert_eq!(sent.flags, ntcp::wire::ACK);
        assert_eq!(sent.window, if i < 2 { 32768 } else { 32760 });
        assert!(output.stamp > 0);
    }
    // No application read follows the third data: its ACK must already be out,
    // and no redundant ACK from the two queued reads may remain in the queue.
    let (request, rx) = request(15, 0, 0, vec![], BYTES);
    adapter
        .tx
        .try_send(request)
        .unwrap_or_else(|_| panic!("request channel full"));
    assert!(matches!(
        rx.recv_timeout(Duration::from_millis(20)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    drop(adapter);
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(3)).unwrap().err(),
        Some(ECANCELED)
    );
}

#[test]
fn sack_profile_negotiation_reaches_owner_thread() {
    for selected in [Profile::Baseline, Profile::Sack] {
        let adapter = Adapter::start((local(), selected)).unwrap();
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
        let syn = syn_with_options(100, 8080, &[2, 4, 5, 180, 1, 3, 3, 0, 1, 1, 4, 2]);
        call(&adapter, 14, 0, 0, syn, 0).unwrap();
        let response = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap();
        let (ip, tcp) = parse_frame(&response.bytes).unwrap();
        let segment = ntcp::wire::parse(ip, tcp).unwrap();
        assert_eq!(segment.options.sack_permitted, selected == Profile::Sack);
        assert_eq!(segment.options.timestamps, None);
        assert_eq!(segment.options.window_scale, Some(0));
    }
}

#[test]
fn upstream_sack_profile_negotiates_combined_options_and_peer_fallback() {
    for (sack, timestamps, options) in [
        (
            true,
            true,
            &[
                2, 4, 5, 180, 4, 2, 8, 10, 0, 0, 0, 100, 0, 0, 0, 0, 1, 3, 3, 7,
            ][..],
        ),
        (
            false,
            true,
            &[
                2, 4, 5, 180, 1, 1, 8, 10, 0, 0, 0, 100, 0, 0, 0, 0, 1, 3, 3, 7,
            ][..],
        ),
        (true, false, &[2, 4, 5, 180, 1, 1, 4, 2, 1, 3, 3, 7][..]),
        (false, false, &[2, 4, 5, 180, 1, 3, 3, 7][..]),
    ] {
        let adapter = Adapter::start((local(), Profile::UpstreamSack)).unwrap();
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
        call(&adapter, 14, 0, 0, syn_with_options(100, 8080, options), 0).unwrap();
        let response = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap();
        let (ip, tcp) = parse_frame(&response.bytes).unwrap();
        let segment = ntcp::wire::parse(ip, tcp).unwrap();
        assert_eq!(segment.options.sack_permitted, sack);
        assert_eq!(segment.options.window_scale, Some(8));
        assert_eq!(segment.options.mss, Some(1460));
        assert_eq!(segment.header.window, 65535);
        assert_eq!(
            segment.options.timestamps.map(|pair| pair.1),
            timestamps.then_some(100)
        );
        let mut expected = options.to_vec();
        *expected.last_mut().unwrap() = 8;
        if let Some((value, _)) = segment.options.timestamps {
            expected[8..12].copy_from_slice(&value.to_be_bytes());
            expected[12..16].copy_from_slice(&100u32.to_be_bytes());
        }
        assert_eq!(segment.raw_options, expected);
    }
}

#[test]
fn upstream_sack_rto_uses_linux_floor_while_baseline_keeps_core_floor() {
    for (profile, initial_rto, floor) in [
        (Profile::Baseline, 1_000_000, 1_000_000),
        (Profile::UpstreamSack, 300_000, 200_000),
    ] {
        let mut owner = Owner::new((local(), profile)).unwrap();
        let fd = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
        let (mut connect, _) = request(
            5,
            fd,
            0,
            encode_addr(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080)),
            0,
        );
        assert_eq!(owner.execute(&mut connect).err(), Some(EINPROGRESS));
        let id = owner.connection(fd).unwrap();
        let mut tcp = vec![0; BYTES];
        let mut now = owner.now();
        let tx = owner
            .endpoint
            .poll_transmit(now, &mut tcp, BUDGET)
            .unwrap()
            .packet
            .unwrap();
        let syn = ntcp::wire::parse(tx.ip, &tcp[..tx.len]).unwrap().header;
        let (ip, mut reply) = reverse_ack(tx, syn, syn.sequence.wrapping_add(1));
        reply.sequence = 100;
        reply.flags |= ntcp::wire::SYN;
        let len =
            ntcp::wire::encode(ip, reply, &[2, 4, 5, 180, 1, 1, 4, 2], &[], &mut tcp).unwrap();
        now += 100_000;
        owner.endpoint.input(now, ip, &tcp[..len]).unwrap();
        let info = owner.endpoint.transport_info(id).unwrap();
        assert_eq!(info.state, State::Established);
        assert_eq!(info.rtt_us, Some(100_000));
        assert_eq!(info.rto_us, initial_rto, "{profile:?}");
        // Drain the handshake ACK, then reduce RTTVAR with three 100 ms samples.
        owner.endpoint.poll_transmit(now, &mut tcp, BUDGET).unwrap();
        for _ in 0..3 {
            owner.endpoint.write(id, b"data").unwrap();
            let tx = owner
                .endpoint
                .poll_transmit(now, &mut tcp, BUDGET)
                .unwrap()
                .packet
                .unwrap();
            let sent = ntcp::wire::parse(tx.ip, &tcp[..tx.len]).unwrap();
            let (ip, reply) = reverse_ack(
                tx,
                sent.header,
                sent.header.sequence.wrapping_add(sent.payload.len() as u32),
            );
            let len = ntcp::wire::encode(ip, reply, &[], &[], &mut tcp).unwrap();
            now += 100_000;
            owner.endpoint.input(now, ip, &tcp[..len]).unwrap();
        }
        let info = owner.endpoint.transport_info(id).unwrap();
        assert_eq!(info.rtt_us, Some(100_000));
        assert_eq!(info.rto_us, floor, "{profile:?}");
    }
}

#[test]
fn profiles_charge_actual_receive_capacity_and_enforce_aggregate_cap() {
    for (name, receive_capacity) in [
        ("baseline", 65535),
        ("upstream-window8", 8 * 1024 * 1024),
        ("upstream-sack", 8 * 1024 * 1024),
    ] {
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
    let ip = parse_frame(&syn(100, 8080)).unwrap().0;
    let (mut incoming, _) = request(14, 0, 0, syn(100, 8080), 0);
    owner.execute(&mut incoming).unwrap();
    let mut out = [0; 1500];
    let tx = owner
        .endpoint
        .poll_transmit(owner.now(), &mut out, BUDGET)
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
        owner.endpoint.input(owner.now(), ip, &out[..n]).unwrap();
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
        .poll_transmit(owner.now(), &mut outgoing, BUDGET)
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

#[test]
fn only_upstream_sack_uses_iw10() {
    for (profile, expected) in [
        (Profile::Baseline, 4380),
        (Profile::UpstreamWindow8, 4380),
        (Profile::Sack, 4380),
        (Profile::UpstreamSack, 14600),
    ] {
        let mut owner = Owner::new((local(), profile)).unwrap();
        let fd = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
        let (mut connect, _) = request(
            5,
            fd,
            0,
            encode_addr(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080)),
            0,
        );
        assert_eq!(owner.execute(&mut connect).err(), Some(EINPROGRESS));
        let mut tcp = vec![0; BYTES];
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
        let n = ntcp::wire::encode(ip, header, &[2, 4, 5, 180], &[], &mut tcp).unwrap();
        owner.endpoint.input(owner.now(), ip, &tcp[..n]).unwrap();
        let id = owner.connection(fd).unwrap();
        owner.endpoint.write(id, &vec![0; 20000]).unwrap();
        let mut flight = 0;
        while let Some(tx) = owner
            .endpoint
            .poll_transmit(owner.now(), &mut tcp, BUDGET)
            .unwrap()
            .packet
        {
            flight += ntcp::wire::parse(tx.ip, &tcp[..tx.len])
                .unwrap()
                .payload
                .len();
        }
        assert_eq!(flight, expected, "{profile:?}");
    }
}

fn input_packet(owner: &mut Owner, ip: IpMetadata, header: ntcp::wire::Header, options: &[u8]) {
    let mut tcp = [0; 64];
    let len = ntcp::wire::encode(ip, header, options, &[], &mut tcp).unwrap();
    let packet = frame(
        ntcp::Transmit {
            connection: None,
            ip,
            len,
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
            ipv4_options: Default::default(),
        },
        &tcp[..len],
    )
    .unwrap();
    let (mut r, _) = request(14, 0, 0, packet, 0);
    owner.execute(&mut r).unwrap();
}
fn poll_frame(owner: &mut Owner) -> Option<(ntcp::Transmit, Vec<u8>)> {
    let mut tcp = vec![0; BYTES - 20];
    let tx = owner
        .endpoint
        .poll_transmit(owner.now(), &mut tcp, BUDGET)
        .unwrap()
        .packet?;
    Some((tx, owner.frame(tx, &tcp[..tx.len]).unwrap()))
}
fn packet_header(bytes: &[u8]) -> ntcp::wire::Header {
    let (ip, tcp) = parse_frame(bytes).unwrap();
    ntcp::wire::parse(ip, tcp).unwrap().header
}
fn check_ip(bytes: &[u8], tos: u8, df: bool) {
    assert_eq!(bytes[1], tos);
    assert_eq!(
        u16::from_be_bytes([bytes[6], bytes[7]]),
        if df { 0x4000 } else { 0 }
    );
    assert_eq!(ip_checksum(&bytes[..20]), 0);
    parse_frame(bytes).unwrap();
}
fn reverse_ack(
    tx: ntcp::Transmit,
    sent: ntcp::wire::Header,
    ack: u32,
) -> (IpMetadata, ntcp::wire::Header) {
    (
        IpMetadata {
            source: tx.ip.destination,
            destination: tx.ip.source,
        },
        ntcp::wire::Header {
            source_port: sent.destination_port,
            destination_port: sent.source_port,
            sequence: 101,
            acknowledgment: ack,
            flags: ntcp::wire::ACK,
            window: 65535,
            urgent_pointer: 0,
        },
    )
}
fn active_ip_connection(
    owner: &mut Owner,
    tos: i32,
    mode: i32,
) -> (i32, ConnectionId, ntcp::Transmit, ntcp::wire::Header) {
    let fd = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
    execute_value(owner, 11, fd, 6, tos).unwrap();
    execute_value(owner, 11, fd, 7, mode).unwrap();
    let (mut connect, _) = request(
        5,
        fd,
        0,
        encode_addr(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080)),
        0,
    );
    assert_eq!(owner.execute(&mut connect).err(), Some(EINPROGRESS));
    let id = owner.connection(fd).unwrap();
    let (tx, bytes) = poll_frame(owner).unwrap();
    check_ip(&bytes, tos as u8 & !3, mode != IP_PMTUDISC_DONT);
    let sent = packet_header(&bytes);
    let (ip, mut reply) = reverse_ack(tx, sent, sent.sequence.wrapping_add(1));
    reply.sequence = 100;
    reply.flags |= ntcp::wire::SYN;
    input_packet(owner, ip, reply, &[2, 4, 5, 180, 1, 1, 4, 2]);
    assert_eq!(owner.endpoint.state(id), Ok(State::Established));
    let (_, bytes) = poll_frame(owner).unwrap();
    check_ip(&bytes, tos as u8 & !3, mode != IP_PMTUDISC_DONT);
    (fd, id, tx, sent)
}

#[test]
fn ip_options_pending_connect_updates_and_engine_owned_ecn() {
    let mut owner = Owner::new((local(), Profile::Sack)).unwrap();
    let fd = owner.alloc(Socket::new(0)).unwrap();
    assert_eq!(execute_value(&mut owner, 12, fd, 6, 0), Ok(0));
    assert_eq!(
        execute_value(&mut owner, 12, fd, 7, 0),
        Ok(IP_PMTUDISC_WANT as i64)
    );
    execute_value(&mut owner, 11, fd, 6, 7).unwrap();
    execute_value(&mut owner, 11, fd, 7, IP_PMTUDISC_DONT).unwrap();
    let (mut connect, _) = request(
        5,
        fd,
        0,
        encode_addr(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080)),
        0,
    );
    assert!(owner.execute(&mut connect).unwrap().is_none());
    assert!(connect.started);
    let (tx, bytes) = poll_frame(&mut owner).unwrap();
    check_ip(&bytes, 4, false);
    let sent = packet_header(&bytes);
    for bad in [-1, 3, 4, 5, 6] {
        assert_eq!(
            execute_value(&mut owner, 11, fd, 7, bad),
            Err(if (3..=5).contains(&bad) {
                ENOSYS
            } else {
                EINVAL
            })
        );
        assert_eq!(
            execute_value(&mut owner, 12, fd, 7, 0),
            Ok(IP_PMTUDISC_DONT as i64)
        );
    }
    execute_value(&mut owner, 11, fd, 6, 255).unwrap();
    execute_value(&mut owner, 11, fd, 7, IP_PMTUDISC_DO).unwrap();
    let (ip, mut reply) = reverse_ack(tx, sent, sent.sequence.wrapping_add(1));
    reply.flags |= ntcp::wire::SYN;
    reply.sequence = 100;
    input_packet(&mut owner, ip, reply, &[2, 4, 5, 180]);
    assert!(owner.execute(&mut connect).unwrap().is_some());
    let (_, bytes) = poll_frame(&mut owner).unwrap();
    check_ip(&bytes, 252, true);
    // Framing must preserve an engine-produced ECN codepoint, not socket ECN bits.
    let mut tcp = [0; 64];
    let len = ntcp::wire::encode(tx.ip, sent, &[], &[], &mut tcp).unwrap();
    let engine_tx = ntcp::Transmit {
        len,
        dscp: 63,
        ecn: 2,
        ..tx
    };
    check_ip(&owner.frame(engine_tx, &tcp[..len]).unwrap(), 254, true);
    let id = owner.connection(fd).unwrap();
    for mode in [IP_PMTUDISC_WANT, IP_PMTUDISC_DONT, IP_PMTUDISC_DO] {
        execute_value(&mut owner, 11, fd, 7, mode).unwrap();
        execute_value(&mut owner, 11, fd, 6, 4).unwrap();
        let before = owner.endpoint.buffer_bytes();
        let (mut write, _) = request(7, fd, 0, b"data".to_vec(), 0);
        assert_eq!(owner.execute(&mut write).unwrap().unwrap().value, 4);
        let (_, bytes) = poll_frame(&mut owner).unwrap();
        check_ip(&bytes, 4, mode != IP_PMTUDISC_DONT);
        let header = packet_header(&bytes);
        let acknowledged = owner.endpoint.acknowledged(id).unwrap();
        let deadline = owner.endpoint.next_deadline();
        execute_value(&mut owner, 11, fd, 6, 0).unwrap();
        assert_eq!(owner.endpoint.buffer_bytes(), before);
        assert_eq!(owner.endpoint.next_deadline(), deadline);
        assert_eq!(owner.endpoint.acknowledged(id).unwrap(), acknowledged);
        let (ip, reply) = reverse_ack(tx, header, header.sequence.wrapping_add(4));
        input_packet(&mut owner, ip, reply, &[]);
        assert_eq!(owner.endpoint.acknowledged(id).unwrap(), acknowledged + 4);
    }
    // A failed core update must not partially change either socket or IP policy.
    let (ip, mut reset) = reverse_ack(tx, sent, sent.sequence.wrapping_add(13));
    reset.flags = ntcp::wire::RST;
    input_packet(&mut owner, ip, reset, &[]);
    assert_eq!(owner.endpoint.state(id), Ok(State::Closed));
    owner.endpoint.release(id).unwrap();
    let previous = owner.sockets[&fd].ip_options;
    assert_eq!(execute_value(&mut owner, 11, fd, 6, 40), Err(EBADF));
    assert_eq!(
        execute_value(&mut owner, 11, fd, 7, IP_PMTUDISC_DONT),
        Err(EBADF)
    );
    assert_eq!(owner.sockets[&fd].ip_options, previous);
    assert_eq!(
        owner
            .connection_ip
            .iter()
            .find(|p| p.id == id)
            .unwrap()
            .options,
        previous
    );
}

#[test]
fn ip_options_listener_snapshot_accept_detached_fin_and_fd_reuse() {
    let mut owner = Owner::new((local(), Profile::Sack)).unwrap();
    let listener = owner.alloc(Socket::new(0)).unwrap();
    execute_value(&mut owner, 11, listener, 6, 187).unwrap();
    execute_value(&mut owner, 11, listener, 7, IP_PMTUDISC_DONT).unwrap();
    let (mut bind, _) = request(
        2,
        listener,
        0,
        encode_addr(SocketAddr::new(local().into(), 8080)),
        0,
    );
    owner.execute(&mut bind).unwrap();
    execute_value(&mut owner, 3, listener, 1, 0).unwrap();
    let (mut incoming, _) = request(14, 0, 0, syn(100, 8080), 0);
    owner.execute(&mut incoming).unwrap();
    let tuple = ntcp::Tuple {
        local: SocketAddr::new(local().into(), 8080),
        remote: SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 50000),
    };
    let id = owner.endpoint.connection_id(tuple).unwrap();
    execute_value(&mut owner, 11, listener, 6, 4).unwrap();
    execute_value(&mut owner, 11, listener, 7, IP_PMTUDISC_DO).unwrap();
    // A duplicate SYN must not overwrite the original listener snapshot.
    owner.execute(&mut incoming).unwrap();
    assert_eq!(owner.connection_ip.len(), 1);
    let (tx, bytes) = poll_frame(&mut owner).unwrap();
    assert_eq!(tx.connection, Some(id));
    check_ip(&bytes, 184, false);
    let sent = packet_header(&bytes);
    let (ip, reply) = reverse_ack(tx, sent, sent.sequence.wrapping_add(1));
    input_packet(&mut owner, ip, reply, &[]);
    let fd = execute_value(&mut owner, 4, listener, 0, 0).unwrap() as i32;
    assert_eq!(execute_value(&mut owner, 12, fd, 6, 0), Ok(184));
    assert_eq!(
        execute_value(&mut owner, 12, fd, 7, 0),
        Ok(IP_PMTUDISC_DONT as i64)
    );
    assert_eq!(owner.connection(fd), Ok(id));
    // Pin the old exposed fd until dup2: no parallel test can allocate it.
    let old_token = owner.sockets.get_mut(&fd).unwrap().token.take().unwrap();
    execute_value(&mut owner, 8, fd, 0, 0).unwrap();
    let replacement = Token::new().unwrap();
    assert_eq!(unsafe { dup2(replacement.fd, fd) }, fd);
    let token = Token {
        fd,
        retained: replacement.retained.try_clone().unwrap(),
    };
    drop(old_token);
    drop(replacement);
    owner.alloc_token(Socket::new(0), token).unwrap();
    execute_value(&mut owner, 11, fd, 6, 4).unwrap();
    execute_value(&mut owner, 11, fd, 7, IP_PMTUDISC_DO).unwrap();
    let (fin_tx, bytes) = poll_frame(&mut owner).unwrap();
    assert_eq!(fin_tx.connection, Some(id));
    check_ip(&bytes, 184, false);
    let fin = packet_header(&bytes);
    assert_ne!(fin.flags & ntcp::wire::FIN, 0);
    let (ip, mut reply) = reverse_ack(fin_tx, fin, fin.sequence.wrapping_add(1));
    reply.flags |= ntcp::wire::FIN;
    input_packet(&mut owner, ip, reply, &[]);
    assert_eq!(owner.endpoint.state(id), Ok(State::TimeWait));
    let retained_bytes = owner.endpoint.buffer_bytes();
    owner.endpoint.release(id).unwrap();
    assert!(owner.endpoint.state(id).is_err());
    assert!(owner.endpoint.connection_exists(id));
    owner.gc_ip_options();
    assert_eq!(owner.connection_ip.len(), 1);
    let (_, bytes) = poll_frame(&mut owner).unwrap();
    check_ip(&bytes, 184, false);
    // Even after its last ACK, a released TIME-WAIT record still owns policy
    // and buffers. A repeated FIN must get the original policy, not the new fd's.
    owner.gc_ip_options();
    assert_eq!(owner.connection_ip.len(), 1);
    assert_eq!(owner.endpoint.buffer_bytes(), retained_bytes);
    input_packet(&mut owner, ip, reply, &[]);
    let (ack_tx, bytes) = poll_frame(&mut owner).unwrap();
    assert_eq!(ack_tx.connection, Some(id));
    check_ip(&bytes, 184, false);
    assert_eq!(owner.endpoint.buffer_bytes(), retained_bytes);
    let expiry = owner.endpoint.next_deadline().unwrap().max(owner.now());
    owner.endpoint.on_timeout(expiry, BUDGET).unwrap();
    owner.epoch = Instant::now() - Duration::from_micros(expiry);
    assert!(poll_frame(&mut owner).is_none());
    assert!(!owner.endpoint.connection_exists(id));
    owner.gc_ip_options();
    assert!(owner.connection_ip.is_empty());
    assert_eq!(owner.endpoint.buffer_bytes(), 0);
    assert_eq!(execute_value(&mut owner, 12, fd, 6, 0), Ok(4));
    assert_eq!(
        execute_value(&mut owner, 12, fd, 7, 0),
        Ok(IP_PMTUDISC_DO as i64)
    );
}

#[test]
fn ip_options_passive_expiry_gc_final_reset_and_unmatched_control() {
    let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
    let listener = owner.alloc(Socket::new(0)).unwrap();
    execute_value(&mut owner, 11, listener, 6, 40).unwrap();
    execute_value(&mut owner, 11, listener, 7, IP_PMTUDISC_DONT).unwrap();
    execute_value(&mut owner, 11, listener, 5, 1).unwrap();
    let (mut bind, _) = request(
        2,
        listener,
        0,
        encode_addr(SocketAddr::new(local().into(), 8080)),
        0,
    );
    owner.execute(&mut bind).unwrap();
    execute_value(&mut owner, 3, listener, 2, 0).unwrap();
    let (mut incoming, _) = request(14, 0, 0, syn(100, 8080), 0);
    owner.execute(&mut incoming).unwrap();
    let (tx, bytes) = poll_frame(&mut owner).unwrap();
    check_ip(&bytes, 40, false);
    let old = tx.connection.unwrap();
    let deadline = owner.now() + 2000;
    owner.endpoint.on_timeout(deadline, BUDGET).unwrap();
    // Avoid wall-clock regression in following application operations.
    owner.epoch = Instant::now() - Duration::from_micros(deadline);
    assert!(poll_frame(&mut owner).is_none());
    assert!(owner.endpoint.state(old).is_err());
    owner.gc_ip_options();
    assert!(owner.connection_ip.is_empty());
    execute_value(&mut owner, 11, listener, 5, 0).unwrap();
    execute_value(&mut owner, 11, listener, 6, 80).unwrap();
    owner.execute(&mut incoming).unwrap();
    let (tx, bytes) = poll_frame(&mut owner).unwrap();
    assert_ne!(tx.connection, Some(old));
    check_ip(&bytes, 80, false);
    let child = tx.connection.unwrap();
    let tuple = owner.endpoint.tuple(child).unwrap();
    owner.endpoint.abort(child).unwrap();
    assert!(owner.endpoint.state(child).is_err());
    assert!(owner.endpoint.connection_exists(child));
    execute_value(&mut owner, 11, listener, 6, 120).unwrap();
    execute_value(&mut owner, 11, listener, 7, IP_PMTUDISC_DO).unwrap();
    owner.execute(&mut incoming).unwrap();
    assert_eq!(owner.endpoint.connection_id(tuple), Some(child));
    let (tx, bytes) = poll_frame(&mut owner).unwrap();
    assert_eq!(tx.connection, Some(child));
    assert_ne!(packet_header(&bytes).flags & ntcp::wire::RST, 0);
    check_ip(&bytes, 80, false);
    // The terminal reset retains its original policy and tuple through 2MSL.
    owner.execute(&mut incoming).unwrap();
    assert!(poll_frame(&mut owner).is_none());
    assert_eq!(owner.endpoint.connection_id(tuple), Some(child));
    owner.gc_ip_options();
    assert_eq!(owner.connection_ip.len(), 1);
    let expiry = owner.endpoint.next_deadline().unwrap().max(owner.now());
    owner.endpoint.on_timeout(expiry, BUDGET).unwrap();
    owner.epoch = Instant::now() - Duration::from_micros(expiry);
    assert!(!owner.endpoint.connection_exists(child));
    owner.gc_ip_options();
    assert!(owner.connection_ip.is_empty());
    owner.execute(&mut incoming).unwrap();
    let replacement = owner.endpoint.connection_id(tuple).unwrap();
    assert_ne!(replacement, child);
    let (tx, bytes) = poll_frame(&mut owner).unwrap();
    assert_eq!(tx.connection, Some(replacement));
    assert_ne!(packet_header(&bytes).flags & ntcp::wire::SYN, 0);
    check_ip(&bytes, 120, true);
    let child = replacement;
    execute_value(&mut owner, 8, listener, 0, 0).unwrap();
    owner.endpoint.on_timeout(owner.now(), BUDGET).unwrap();
    // Closed children must retain policy until their last RST is framed.
    owner.gc_ip_options();
    let (tx, bytes) = poll_frame(&mut owner).unwrap();
    assert_eq!(tx.connection, Some(child));
    assert_ne!(packet_header(&bytes).flags & ntcp::wire::RST, 0);
    check_ip(&bytes, 120, true);
    assert!(owner.endpoint.connection_exists(child));
    owner.gc_ip_options();
    assert_eq!(owner.connection_ip.len(), 1);
    let expiry = owner.endpoint.next_deadline().unwrap().max(owner.now());
    owner.endpoint.on_timeout(expiry, BUDGET).unwrap();
    owner.epoch = Instant::now() - Duration::from_micros(expiry);
    assert!(!owner.endpoint.connection_exists(child));
    owner.gc_ip_options();
    assert!(owner.connection_ip.is_empty());
    let (mut unmatched, _) = request(14, 0, 0, syn(200, 9090), 0);
    owner.execute(&mut unmatched).unwrap();
    let (tx, bytes) = poll_frame(&mut owner).unwrap();
    assert_eq!(tx.connection, None);
    check_ip(&bytes, 0, true);
}

#[test]
fn ip_options_changes_preserve_sack_holes_and_data_ack() {
    let mut owner = Owner::new((local(), Profile::Sack)).unwrap();
    let (fd, id, handshake_tx, _) = active_ip_connection(&mut owner, 0, IP_PMTUDISC_DONT);
    let data: Vec<u8> = (0..4380).map(|i| (i % 251) as u8).collect();
    let (mut write, _) = request(7, fd, 0, data.clone(), 0);
    owner.execute(&mut write).unwrap();
    let (_, bytes) = poll_frame(&mut owner).unwrap();
    let first = packet_header(&bytes);
    let base = first.sequence;
    let (original_ip, original_tcp) = parse_frame(&bytes).unwrap();
    let mut original_bytes = ntcp::wire::parse(original_ip, original_tcp)
        .unwrap()
        .payload
        .len();
    while let Some((_, bytes)) = poll_frame(&mut owner) {
        let (ip, tcp) = parse_frame(&bytes).unwrap();
        original_bytes += ntcp::wire::parse(ip, tcp).unwrap().payload.len();
    }
    assert_eq!(original_bytes, data.len());
    let (ip, reply) = reverse_ack(handshake_tx, first, base);
    let mut sack = vec![1, 1, 5, 10];
    sack.extend_from_slice(&base.wrapping_add(1460).to_be_bytes());
    sack.extend_from_slice(&base.wrapping_add(1940).to_be_bytes());
    input_packet(&mut owner, ip, reply, &sack);
    let bytes_reserved = owner.endpoint.buffer_bytes();
    let deadline = owner.endpoint.next_deadline();
    execute_value(&mut owner, 11, fd, 6, 4).unwrap();
    execute_value(&mut owner, 11, fd, 6, 0).unwrap();
    assert_eq!(execute_value(&mut owner, 11, fd, 7, 3), Err(ENOSYS));
    assert_eq!(owner.endpoint.buffer_bytes(), bytes_reserved);
    assert_eq!(owner.endpoint.next_deadline(), deadline);
    assert_eq!(owner.endpoint.acknowledged(id), Ok(0));
    for edge in [2420, 2920] {
        sack[8..12].copy_from_slice(&base.wrapping_add(edge).to_be_bytes());
        input_packet(&mut owner, ip, reply, &sack);
    }
    let mut retransmitted = 0;
    while let Some((_, bytes)) = poll_frame(&mut owner) {
        check_ip(&bytes, 0, false);
        let (ip, tcp) = parse_frame(&bytes).unwrap();
        let segment = ntcp::wire::parse(ip, tcp).unwrap();
        if !segment.payload.is_empty() {
            let start = segment.header.sequence.wrapping_sub(base) as usize;
            let end = start + segment.payload.len();
            assert!(end <= 1460 || start >= 2920, "retransmitted SACKed bytes");
            assert_eq!(segment.payload, &data[start..end]);
            retransmitted += segment.payload.len();
        }
    }
    assert!(retransmitted >= 1460);
    let (_, final_ack) = reverse_ack(handshake_tx, first, base.wrapping_add(data.len() as u32));
    input_packet(&mut owner, ip, final_ack, &[]);
    assert_eq!(owner.endpoint.acknowledged(id), Ok(data.len() as u64));
}

#[test]
fn ip_metadata_limit_is_reserved_before_connect_and_reused_after_gc() {
    let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
    // Small real buffers let this test reach all 128 slots, not the profile's
    // separate aggregate byte cap. Production profile settings remain untouched.
    let mut config = EndpointConfig {
        max_connections: LIMIT,
        ..EndpointConfig::default()
    };
    config.connection.receive_capacity = 128;
    config.connection.send_capacity = 128;
    config.connection.mss = 128;
    owner.endpoint = Endpoint::new(config, [42; 32], 0, |_| true).unwrap();
    let remote = encode_addr(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080));
    let mut first = None;
    for _ in 0..LIMIT {
        let fd = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
        let (mut connect, _) = request(5, fd, 0, remote.clone(), 0);
        assert_eq!(owner.execute(&mut connect).err(), Some(EINPROGRESS));
        first.get_or_insert((fd, owner.connection(fd).unwrap()));
        assert!(owner.connection_ip.len() <= LIMIT);
    }
    let (fd, old) = first.unwrap();
    execute_value(&mut owner, 8, fd, 0, 0).unwrap();
    let replacement = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
    let port = owner.next_port;
    let (mut connect, _) = request(5, replacement, 0, remote, 0);
    assert_eq!(owner.execute(&mut connect).err(), Some(ENOBUFS));
    assert_eq!(owner.next_port, port);
    assert!(matches!(owner.sockets[&replacement].handle, Handle::Fresh));
    owner.endpoint.release(old).unwrap();
    while poll_frame(&mut owner).is_some() {}
    owner.gc_ip_options();
    assert_eq!(owner.connection_ip.len(), LIMIT - 1);
    assert_eq!(owner.execute(&mut connect).err(), Some(EINPROGRESS));
    assert_eq!(owner.connection_ip.len(), LIMIT);
}

#[test]
fn host_bridge_preloaded_process_and_lifecycle() {
    use std::process::Command;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let library = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join("libntcp_packetdrill.so");
    // cargo test alone need not refresh its companion cdylib.
    let mut build = Command::new("cargo");
    build
        .args(["build", "-p", "ntcp-packetdrill", "--manifest-path"])
        .arg(root.join("Cargo.toml"));
    if library
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .file_name()
        .unwrap()
        == "release"
    {
        build.arg("--release");
    }
    build.arg("--target-dir").arg(
        library
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap(),
    );
    assert!(build.status().unwrap().success());
    assert!(library.exists(), "missing cdylib: {}", library.display());
    let dir = std::env::temp_dir().join(format!("ntcp-bridge-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("check.c");
    std::fs::write(&source, r#"
#define _GNU_SOURCE
#include "packetdrill.h"
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/syscall.h>
#include <pthread.h>
static void *blocked(void *arg) {
    struct packetdrill_interface *p = arg;
    unsigned char packet[65535]; size_t n = sizeof(packet); long long t;
    assert(p->netdev_receive(p->userdata, packet, &n, &t) == -1);
    assert(errno == ECANCELED || errno == EIO);
    return NULL;
}
int main(void) {
    void (*init)(const char *, struct packetdrill_interface *) = dlsym(RTLD_DEFAULT, "packetdrill_interface_init");
    assert(init);
    struct packetdrill_interface p, other;
    init("local=192.0.2.1,upstream-sack", &p); assert(p.userdata);
    init("local=192.0.2.1,baseline", &other); assert(!other.userdata);
    int fd = p.socket(p.userdata, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP); assert(fd >= 0);
    struct sockaddr_in addr = {.sin_family=AF_INET, .sin_port=htons(8080), .sin_addr={htonl(0xc0000202)}};
    assert(p.connect(p.userdata, fd, (void *)&addr, sizeof(addr)) == -1 && errno == EINPROGRESS);
    unsigned char info[288], abi[280]; memset(info, 0xa5, sizeof(info)); socklen_t n = sizeof(info);
    assert(getsockopt(fd, IPPROTO_TCP, TCP_INFO, info, &n) == 0 && n == 280 && info[0] == 2);
    n = sizeof(abi); assert(p.getsockopt(p.userdata, fd, IPPROTO_TCP, TCP_INFO, abi, &n) == 0);
    assert(memcmp(info, abi, sizeof(abi)) == 0 && info[280] == 0xa5);
    n = sizeof(abi); assert(syscall(SYS_getsockopt, fd, IPPROTO_TCP, TCP_INFO, abi, &n) == -1);
    n = sizeof(abi); assert(getsockopt(fd, IPPROTO_TCP, TCP_CC_INFO, abi, &n) == 0 && n == 0);
    n = sizeof(abi); assert(getsockopt(fd, SOL_SOCKET, SO_MEMINFO, abi, &n) == 0 && n == 36);
    int domain; n = sizeof(domain); assert(getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &n) == 0 && domain == AF_UNIX);
    int host = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); assert(host >= 0);
    unsigned char kernel[104], forwarded[104]; socklen_t k = sizeof(kernel); n = sizeof(forwarded);
    assert(syscall(SYS_getsockopt, host, IPPROTO_TCP, TCP_INFO, kernel, &k) == 0);
    assert(getsockopt(host, IPPROTO_TCP, TCP_INFO, forwarded, &n) == 0 && k == n && !memcmp(kernel, forwarded, n)); close(host);
    // Drain SYN output; next netdev callback blocks until teardown cancels it.
    unsigned char packet[65535]; size_t size = sizeof(packet); long long t;
    assert(p.netdev_receive(p.userdata, packet, &size, &t) == 0);
    pthread_t thread; assert(!pthread_create(&thread, NULL, blocked, &p)); usleep(10000);
    p.free(p.userdata); assert(!pthread_join(thread, NULL));
    p.free(p.userdata); // Stale userdata never dereferenced.
    n = sizeof(info); assert(getsockopt(fd, IPPROTO_TCP, TCP_INFO, info, &n) == -1 && errno == EBADF);
    init("local=192.0.2.1,baseline", &p); assert(p.userdata); p.free(p.userdata);
    return 0;
}
"#).unwrap();
    let executable = dir.join("check");
    assert!(
        Command::new("cc")
            .args(["-Wall", "-Wextra", "-Werror", "-pthread"])
            .arg("-I")
            .arg(root)
            .arg(&source)
            .args(["-ldl", "-o"])
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );
    let mut child = Command::new(&executable)
        .env("LD_PRELOAD", library)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            panic!("preload helper deadlocked");
        }
        thread::sleep(Duration::from_millis(10));
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn transport_encoding_counts_recovery_and_invalid_ledger() {
    let mut owner = Owner::new((local(), Profile::UpstreamSack)).unwrap();
    let fd = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
    let (mut req, _) = request(
        5,
        fd,
        0,
        encode_addr(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080)),
        0,
    );
    assert_eq!(owner.execute(&mut req).err(), Some(EINPROGRESS));
    let mut info = owner
        .endpoint
        .transport_info(owner.connection(fd).unwrap())
        .unwrap();
    let data = transport_option(info, 1).unwrap();
    assert_eq!(data.len(), 280);
    assert_eq!(
        u32::from_ne_bytes(data[80..84].try_into().unwrap()),
        info.cwnd / info.mss
    );
    // Exercise each ABI category independently of packet sequence fixtures.
    info.unacked = 10;
    info.sacked = 3;
    info.lost = 2;
    info.retransmitted = 1;
    info.reordering = 7;
    let data = transport_option(info, 1).unwrap();
    for (offset, count) in [(24, 10), (28, 3), (32, 2), (36, 1), (88, 7)] {
        assert_eq!(
            u32::from_ne_bytes(data[offset..offset + 4].try_into().unwrap()),
            count
        );
    }
    assert_eq!(data[1], 1);
    info.recovery = true;
    assert_eq!(transport_option(info, 1).unwrap()[1], 3);
    info.loss = true;
    assert_eq!(transport_option(info, 1).unwrap()[1], 4);
    info.ledger_valid = false;
    assert_eq!(transport_option(info, 1).err(), Some(ENOSYS));
    assert!(transport_option(info, 2).unwrap().is_empty());
    assert_eq!(transport_option(info, 3).unwrap().len(), 36);
}
