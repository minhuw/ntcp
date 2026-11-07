use super::*;
#[path = "runtime_accounting_expectations_tests.rs"]
mod accounting_expectations_tests;
#[path = "runtime_clock_tests.rs"]
mod clock_tests;
#[path = "file_transfer_tests.rs"]
mod file_transfer_tests;
#[path = "large_write_tests.rs"]
mod large_write_tests;
#[path = "runtime_lowat_tests.rs"]
mod lowat_tests;
#[cfg(feature = "packet-test")]
#[path = "runtime_lowat_upstream_tests.rs"]
mod lowat_upstream;
#[path = "runtime_mss_mark_tests.rs"]
mod mss_mark_tests;
#[path = "runtime_pacing_tests.rs"]
pub(super) mod pacing_tests;
#[path = "runtime_route_tests.rs"]
mod route_policy;
#[path = "runtime_syncnt_tests.rs"]
mod syncnt_tests;
#[path = "runtime_time_wait_tests.rs"]
mod time_wait_tests;
#[cfg(feature = "packet-test")]
#[path = "runtime_timestamp_partial_tests.rs"]
mod timestamp_partial;
#[path = "timestamp_tests.rs"]
mod timestamp_tests;

#[test]
fn sender_metadata_failure_does_not_consume_external_producer() {
    let mut config = SocketConfig::new("test", Ipv4Addr::new(10, 73, 0, 2)).tcp;
    config.preallocate_connections = 0;
    config.connection.send_capacity = 128;
    config.connection.receive_capacity = 1;
    config.connection.mss = 64;
    let mut probe = Endpoint::new(config.clone(), [1; 32], 0, |_| true).unwrap();
    probe
        .connect(
            0,
            "10.73.0.2:40000".parse().unwrap(),
            "10.73.0.3:8080".parse().unwrap(),
        )
        .unwrap();
    config.max_buffer_bytes = probe.buffer_bytes();
    let mut a = owner_with_config(2, config);
    let mut b = owner(3);
    let listener = new(&mut b, SOCK_NONBLOCK);
    b.execute(listener, Op::Bind("10.73.0.3:8080".parse().unwrap()))
        .unwrap();
    b.execute(listener, Op::Listen(1)).unwrap();
    let id = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(id, Op::Connect("10.73.0.3:8080".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    pump(&mut a, &mut b);
    let Handle::Connection(cid) = a.sockets[&id].handle else {
        panic!()
    };
    let before = a.endpoint.send_progress(cid).unwrap();
    let mut consumed = false;
    let result = a.timestamp_write_from(id, cid, 128, 0, 0, |room| {
        consumed = true;
        Ok(vec![1; room])
    });
    assert_eq!(result, Err(ENOMEM));
    assert!(!consumed);
    assert_eq!(a.endpoint.send_progress(cid).unwrap(), before);
}

fn owner(last: u8) -> Owner {
    owner_with_config(
        last,
        SocketConfig::new("test", Ipv4Addr::new(10, 73, 0, last)).tcp,
    )
}
fn owner_with_config(last: u8, config: EndpointConfig) -> Owner {
    let local = Ipv4Addr::new(10, 73, 0, last);
    Owner::with_config(
        local,
        (Ipv4Addr::new(10, 73, 0, 1), 24),
        [last; 32],
        None,
        config,
    )
    .unwrap()
}
pub(super) fn new(o: &mut Owner, flags: i32) -> u64 {
    o.execute(0, Op::New(flags)).unwrap().value as u64
}
// Test transport: IP-encode one directly polled segment as egress encodes
// it. An IP_PMTUDISC_DONT Identification is leased only at submission
// (`Owner::lease_dont_identification`), which callers that model it apply.
pub(super) fn ip_packet(owner: &Owner, tx: ntcp::Transmit, tcp: &[u8]) -> Vec<u8> {
    let header = crate::ip::header_len(tx.ip.source);
    let mut packet = vec![0; header + tcp.len()];
    packet[header..].copy_from_slice(tcp);
    let n = crate::ip::encode(&mut packet, tx, &[], (owner.now() / 1000) as u32, tx.len).unwrap();
    packet.truncate(n);
    packet
}
// Test transport: one IP packet directly polled from a backend-less peer.
pub(super) fn poll_packet(owner: &mut Owner) -> Option<Vec<u8>> {
    let header = crate::ip::header_len(owner.local);
    let mut tcp = vec![0; owner.output_packet_len() - header];
    let pair = ClockPair::sample(owner).unwrap();
    let tx = owner
        .endpoint
        .poll_transmit(owner.now(), &mut tcp, BUDGET)
        .unwrap()
        .packet?;
    let packet = ip_packet(owner, tx, &tcp[..tx.len]);
    owner.timestamp_packet(tx.tx_timestamp, &packet);
    owner.drain_timestamps(pair);
    Some(packet)
}
pub(super) fn pump(a: &mut Owner, b: &mut Owner) {
    for _ in 0..32 {
        let mut progress = false;
        for reverse in [false, true] {
            let (from, to) = if reverse {
                (&mut *b, &mut *a)
            } else {
                (&mut *a, &mut *b)
            };
            for _ in 0..32 {
                let mut bytes = [0u8; 1480];
                let pair = ClockPair::sample(from).unwrap();
                let p = from
                    .endpoint
                    .poll_transmit(from.now(), &mut bytes, 32)
                    .unwrap();
                let Some(p) = p.packet else {
                    break;
                };
                let frame = ip_packet(from, p, &bytes[..p.len]);
                from.timestamp_packet(p.tx_timestamp, &frame);
                from.drain_timestamps(pair);
                from.software_transmitted(p.tx_timestamp, timestamps::realtime());
                to.input(to.now(), p.ip, p.dscp << 2 | p.ecn, &bytes[..p.len])
                    .unwrap();
                progress = true;
            }
            from.events();
            to.events();
        }
        if !progress {
            break;
        }
    }
}
pub(super) fn pair() -> (Owner, Owner, u64, u64, u64) {
    let mut a = owner(2);
    let mut b = owner(3);
    let listen = new(&mut b, SOCK_NONBLOCK);
    b.execute(listen, Op::Bind("10.73.0.3:16379".parse().unwrap()))
        .unwrap();
    b.execute(listen, Op::Listen(16)).unwrap();
    let client = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(client, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    assert_eq!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
    pump(&mut a, &mut b);
    assert_ne!(b.execute(listen, Op::Ready).unwrap().value & EPOLLIN, 0);
    let server = b.execute(listen, Op::Accept(SOCK_NONBLOCK)).unwrap().value as u64;
    (a, b, client, server, listen)
}
#[cfg(feature = "packet-test")]
#[test]
fn timestamp_default_control_rejects_non_packet_backend() {
    let mut owner = owner(2);
    assert!(owner.packets.is_none());
    for enabled in [false, true] {
        assert_eq!(
            owner.execute(0, Op::TimestampDefault(enabled)).err(),
            Some(EOPNOTSUPP)
        );
    }
    assert_eq!(
        owner.execute(0, Op::ClearFastOpenClientCache).err(),
        Some(EOPNOTSUPP)
    );
    assert_eq!(
        owner.execute(0, Op::ListenerPresent(8080)).err(),
        Some(EOPNOTSUPP)
    );
}

#[test]
fn client_tfo_permission_native_configuration_and_management() {
    let mut owner = owner(2);
    let mut config = SocketConfig::new("test", Ipv4Addr::new(10, 73, 0, 2));
    config.io.source_quiet = crate::SourceQuiet::Never;
    config.socket.fast_open_client_enabled = false;
    owner.apply_socket_config(&config).unwrap();
    let id = new(&mut owner, SOCK_NONBLOCK);
    assert_eq!(
        owner
            .execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
            .unwrap_err(),
        EOPNOTSUPP
    );
    owner
        .execute(0, Op::SetFastOpenClientEnabled(true))
        .unwrap();
    assert_eq!(
        owner
            .execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
            .unwrap()
            .value,
        0
    );
}

#[test]
fn client_tfo_permission_management_progresses_with_full_waiter_queue() {
    let (mut a, _b, client, _, _) = pair();
    a.execute(client, Op::Flags(F_SETFL, 0)).unwrap();
    let (reply, _) = mpsc::sync_channel(1);
    for _ in 0..a.socket_limit() {
        let mut request = Request {
            id: client,
            op: Op::Wait(Box::new(Op::Read(1)), None),
            reply: reply.clone(),
            deadline: None,
            send: None,
            closing: None,
        };
        assert!(!a.service(&mut request));
        a.pending.push_back(request);
    }
    let (reply, result) = mpsc::sync_channel(1);
    let mut control = Request {
        id: 0,
        op: Op::SetFastOpenClientEnabled(false),
        reply,
        deadline: None,
        send: None,
        closing: None,
    };
    assert_eq!(a.pending.len(), a.socket_limit());
    assert!(!a.admission_full(&control));
    assert!(a.service(&mut control));
    assert!(result.try_recv().unwrap().is_ok());
    assert!(!a.socket_policy.fast_open_client_enabled);
    assert_eq!(a.pending.len(), a.socket_limit());
}

#[test]
fn tcp_info_prefix_survives_ambiguous_data_fin_delivery() {
    use ntcp::wire::{self, ACK, FIN, SYN};
    let mut config = SocketConfig::new("test", Ipv4Addr::new(10, 73, 0, 2)).tcp;
    config.connection.sack = true;
    config.connection.tlp = false;
    config.connection.timestamps = false;
    let mut owner = owner_with_config(2, config);
    owner.test_now = Some(0);
    let id = new(&mut owner, SOCK_NONBLOCK);
    assert_eq!(
        owner
            .execute(id, Op::Connect("10.73.0.3:2000".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    let Handle::Connection(cid) = owner.sockets[&id].handle else {
        panic!()
    };
    let mut out = [0; 2048];
    let tx = owner
        .endpoint
        .poll_transmit(0, &mut out, 16)
        .unwrap()
        .packet
        .unwrap();
    let syn = wire::parse(tx.ip, &out[..tx.len]).unwrap().header;
    let base = syn.sequence.wrapping_add(1);
    let ip = ntcp::IpMetadata {
        source: tx.ip.destination,
        destination: tx.ip.source,
    };
    let mut ack = wire::Header {
        source_port: syn.destination_port,
        destination_port: syn.source_port,
        sequence: 100,
        acknowledgment: base,
        flags: SYN | ACK,
        window: 32000,
        urgent_pointer: 0,
    };
    let input = |owner: &mut Owner, now, header, options: &[u8]| {
        let mut bytes = [0; 64];
        let len = wire::encode(ip, header, options, &[], &mut bytes).unwrap();
        owner.endpoint.input(now, ip, &bytes[..len]).unwrap();
    };
    input(&mut owner, 10, ack, &[1, 1, 4, 2]);
    owner.endpoint.poll_transmit(20, &mut out, 16).unwrap();
    owner.test_now = Some(20);
    let full = owner.execute(id, Op::Transport(1)).unwrap().bytes;
    assert_eq!(full.len(), 280);
    for requested in [0, 1, 192, 193, 280, 512] {
        assert_eq!(
            owner
                .execute(id, Op::TransportPrefix(1, requested))
                .unwrap()
                .bytes,
            full[..requested.min(280)]
        );
    }
    // SACK data sent separately from FIN, then retransmit them together.
    // The core cannot attribute the combined retry to one delivery packet.
    owner.endpoint.write(cid, &[0; 100]).unwrap();
    let tx = owner
        .endpoint
        .poll_transmit(100, &mut out, 16)
        .unwrap()
        .packet
        .unwrap();
    assert_eq!(
        wire::parse(tx.ip, &out[..tx.len]).unwrap().payload.len(),
        100
    );
    owner.endpoint.shutdown(cid).unwrap();
    let tx = owner
        .endpoint
        .poll_transmit(100, &mut out, 16)
        .unwrap()
        .packet
        .unwrap();
    let fin = wire::parse(tx.ip, &out[..tx.len]).unwrap();
    assert!(fin.payload.is_empty());
    assert_ne!(fin.header.flags & FIN, 0);
    ack.sequence = 101;
    ack.flags = ACK;
    let mut sack = vec![5, 10];
    sack.extend_from_slice(&base.to_be_bytes());
    sack.extend_from_slice(&base.wrapping_add(100).to_be_bytes());
    sack.extend_from_slice(&[1, 1]);
    input(&mut owner, 200, ack, &sack);
    let deadline = owner.endpoint.next_deadline().unwrap();
    owner.endpoint.on_timeout(deadline, 16).unwrap();
    let tx = owner
        .endpoint
        .poll_transmit(deadline, &mut out, 16)
        .unwrap()
        .packet
        .unwrap();
    let retry = wire::parse(tx.ip, &out[..tx.len]).unwrap();
    assert_eq!(retry.payload.len(), 100);
    assert_ne!(retry.header.flags & FIN, 0);
    owner.test_now = Some(deadline);
    let info = owner.endpoint.transport_info(cid).unwrap();
    assert!(info.ledger_valid);
    assert!(info.delivered_segments_valid);
    let prefix = owner
        .execute(id, Op::TransportPrefix(1, 280))
        .unwrap()
        .bytes;
    assert_eq!(prefix.len(), 280);
    assert_eq!(prefix[0], 4); // FIN_WAIT1
    for requested in [0, 1, 7, 191] {
        assert_eq!(
            owner
                .execute(id, Op::TransportPrefix(1, requested))
                .unwrap()
                .bytes,
            prefix[..requested]
        );
    }
    for requested in [193, 280, 512] {
        assert_eq!(
            owner
                .execute(id, Op::TransportPrefix(1, requested))
                .unwrap()
                .bytes,
            prefix[..requested.min(280)]
        );
    }
    assert_eq!(owner.execute(id, Op::Transport(1)).unwrap().bytes, prefix);
    assert!(
        owner
            .execute(id, Op::Transport(2))
            .unwrap()
            .bytes
            .is_empty()
    );
}

#[test]
fn errorqueue_fault_preserves_entry_and_short_control_consumes() {
    let (mut owner, _peer, client, _, _) = pair();
    owner
        .execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    for capacity in 0..=56 {
        let before = owner
            .execute(client, Op::Ready)
            .unwrap()
            .readiness_generations[2];
        owner
            .execute(client, Op::WriteFlags(vec![1], MSG_ZEROCOPY))
            .unwrap();
        let ready = owner.execute(client, Op::Ready).unwrap();
        assert_ne!(ready.value & EPOLLERR, 0);
        assert_ne!(ready.readiness_generations[2], before);
        let mut header: msghdr = unsafe { std::mem::zeroed() };
        header.msg_control = std::ptr::dangling_mut::<c_void>();
        header.msg_controllen = 48;
        let address = (&mut header as *mut msghdr) as usize;
        assert_eq!(
            owner
                .execute(client, Op::ErrorQueueTo(address))
                .unwrap_err(),
            EFAULT
        );
        assert_eq!(owner.sockets[&client].completions.len(), 1);
        assert_ne!(
            owner.execute(client, Op::Ready).unwrap().value & EPOLLERR,
            0
        );
        let mut control = [0xa5u8; 64];
        header.msg_control = control.as_mut_ptr().cast();
        header.msg_controllen = capacity;
        owner.execute(client, Op::ErrorQueueTo(address)).unwrap();
        assert_eq!(
            header.msg_flags,
            MSG_ERRQUEUE | if capacity < 48 { MSG_CTRUNC } else { 0 }
        );
        assert_eq!(
            header.msg_controllen,
            if capacity < 16 { 0 } else { capacity.min(48) }
        );
        assert!(control[capacity..].iter().all(|b| *b == 0xa5));
        assert!(owner.sockets[&client].completions.is_empty());
        assert_eq!(
            owner.execute(client, Op::Ready).unwrap().value & EPOLLERR,
            0
        );
        assert_eq!(
            owner
                .execute(client, Op::ErrorQueueTo(address))
                .unwrap_err(),
            EAGAIN
        );
    }
}
#[test]
fn new_data_generations_and_post_read_inq_fin() {
    let (mut a, mut b, client, server, _) = pair();
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    b.execute(server, Op::Set(IPPROTO_TCP, TCP_INQ, 1)).unwrap();
    a.execute(client, Op::Write(b"abcdef".to_vec())).unwrap();
    pump(&mut a, &mut b);
    let first = b.execute(server, Op::Ready).unwrap();
    assert_ne!(first.value & EPOLLIN, 0);
    for _ in 0..32 {
        assert_eq!(
            b.execute(server, Op::Ready).unwrap().readiness_generations,
            first.readiness_generations
        );
    }
    assert_eq!(b.execute(server, Op::Inq(0)).unwrap().value, 6);
    assert_eq!(b.execute(server, Op::Inq(2)).unwrap().value, 4);
    assert_eq!(b.execute(server, Op::Peek(2)).unwrap().bytes, b"ab");
    assert_eq!(b.execute(server, Op::Inq(0)).unwrap().value, 6);
    b.execute(server, Op::Read(2)).unwrap();
    assert_eq!(
        b.execute(server, Op::Ready).unwrap().readiness_generations,
        first.readiness_generations
    );
    a.execute(client, Op::Write(b"ghi".to_vec())).unwrap();
    pump(&mut a, &mut b);
    let next = b.execute(server, Op::Ready).unwrap();
    assert_ne!(
        next.readiness_generations[0],
        first.readiness_generations[0]
    );
    assert_eq!(b.execute(server, Op::Inq(0)).unwrap().value, 7);
    a.execute(client, Op::Shutdown(SHUT_WR)).unwrap();
    pump(&mut a, &mut b);
    assert_eq!(b.execute(server, Op::Inq(0)).unwrap().value, 8);
    assert_eq!(b.execute(server, Op::Inq(7)).unwrap().value, 1);
    assert_eq!(b.execute(server, Op::Read(32)).unwrap().bytes, b"cdefghi");
    assert_eq!(b.execute(server, Op::Read(32)).unwrap().value, 0);
    assert_eq!(b.execute(server, Op::Inq(0)).unwrap().value, 1);
}
#[test]
fn inq_reset_error_consumption_never_fabricates_fin() {
    for via_so_error in [false, true] {
        let (mut a, mut b, client, server, _) = pair();
        b.execute(server, Op::Set(IPPROTO_TCP, TCP_INQ, 1)).unwrap();
        a.execute(client, Op::Write(b"ab".to_vec())).unwrap();
        pump(&mut a, &mut b);
        let Handle::Connection(cid) = a.sockets[&client].handle else {
            panic!()
        };
        a.endpoint.abort(cid).unwrap();
        pump(&mut a, &mut b);
        assert_eq!(b.execute(server, Op::Inq(0)).unwrap().value, 2);
        assert_eq!(b.execute(server, Op::Read(2)).unwrap().bytes, b"ab");
        assert_eq!(b.execute(server, Op::Inq(0)).unwrap().value, 0);
        if via_so_error {
            assert_eq!(
                b.execute(server, Op::Get(SOL_SOCKET, SO_ERROR))
                    .unwrap()
                    .value,
                ECONNRESET
            );
        } else {
            assert_eq!(b.execute(server, Op::Read(1)).unwrap_err(), ECONNRESET);
        }
        assert_eq!(b.execute(server, Op::Read(1)).unwrap().value, 0);
        assert_eq!(b.execute(server, Op::Inq(0)).unwrap().value, 0);
    }
    let (mut a, mut b, client, server, _) = pair();
    b.execute(server, Op::Set(IPPROTO_TCP, TCP_INQ, 1)).unwrap();
    a.execute(client, Op::Shutdown(SHUT_WR)).unwrap();
    pump(&mut a, &mut b);
    b.execute(server, Op::Shutdown(SHUT_WR)).unwrap();
    pump(&mut a, &mut b);
    let Handle::Connection(cid) = b.sockets[&server].handle else {
        panic!()
    };
    assert_eq!(b.endpoint.state(cid).unwrap(), State::Closed);
    assert_eq!(b.execute(server, Op::Read(1)).unwrap().value, 0);
    assert_eq!(
        b.execute(server, Op::Get(SOL_SOCKET, SO_ERROR))
            .unwrap()
            .value,
        0
    );
    assert_eq!(b.execute(server, Op::Inq(0)).unwrap().value, 1);
}
#[test]
fn lowwater_sets_notify_independent_writable_registrations() {
    let (mut a, _b, client, _, _) = pair();
    let mut first = a.execute(client, Op::Ready).unwrap().readiness_generations;
    let mut second = first;
    for value in [4000, 4000, -1, 0] {
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, value))
            .unwrap();
        let ready = a.execute(client, Op::Ready).unwrap();
        assert_ne!(ready.value & EPOLLOUT, 0);
        assert!(socket_options::edge_changed(
            EPOLLOUT as u32,
            Some(first),
            ready.readiness_generations
        ));
        first = ready.readiness_generations;
        assert!(!socket_options::edge_changed(
            EPOLLOUT as u32,
            Some(first),
            ready.readiness_generations
        ));
        // Consuming one registration must not consume another's edge.
        assert!(socket_options::edge_changed(
            EPOLLOUT as u32,
            Some(second),
            ready.readiness_generations
        ));
        second = ready.readiness_generations;
    }
}
#[test]
fn lowwater_bounds_batch_before_copy_and_preserves_hysteresis() {
    let (mut a, _b, client, _, _) = pair();
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_CORK, 1))
        .unwrap();
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, 4000))
        .unwrap();
    assert_eq!(
        a.execute(client, Op::WriteFlags(vec![1; 1999], MSG_MORE))
            .unwrap()
            .value,
        1999
    );
    assert_ne!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
    assert_eq!(
        a.execute(client, Op::WriteFlags(vec![2], MSG_MORE))
            .unwrap()
            .value,
        1
    );
    // Readiness retains the independent half-threshold rule.
    assert_eq!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        panic!()
    };
    let goal = send::batch_goal(&a.endpoint.transport_info(cid).unwrap());
    let tail = vec![3; goal];
    // Bytes outside the batch prefix must not be dereferenced.
    let sources = vec![(tail.as_ptr() as usize, tail.len()), (0, 1)];
    assert_eq!(
        a.execute(client, Op::Send(sources, MSG_MORE | MSG_EOR))
            .unwrap()
            .value as usize,
        goal - 2000
    );
    assert_eq!(a.execute(client, Op::Write(vec![4])).unwrap_err(), EAGAIN);
    assert_eq!(a.endpoint.transport_info(cid).unwrap().notsent_bytes, goal);
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, -1))
        .unwrap();
    assert_eq!(
        a.execute(client, Op::Write(vec![4; 20000])).unwrap().value,
        20000
    );
}

#[test]
fn lowwater_tracks_unsent_not_unacked_and_option_wakes() {
    let (mut a, _b, client, _, _) = pair();
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, 4000))
        .unwrap();
    assert_eq!(
        a.execute(client, Op::WriteFlags(vec![1; 4000], MSG_EOR))
            .unwrap()
            .value,
        4000
    );
    let blocked = a.execute(client, Op::Ready).unwrap();
    assert_eq!(blocked.value & EPOLLOUT, 0);
    assert_eq!(a.execute(client, Op::Write(vec![2])).unwrap_err(), EAGAIN);
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, -1))
        .unwrap();
    let ready = a.execute(client, Op::Ready).unwrap();
    assert_ne!(ready.value & EPOLLOUT, 0);
    assert_ne!(
        ready.readiness_generations[1],
        blocked.readiness_generations[1]
    );
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, 4000))
        .unwrap();
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        panic!()
    };
    let mut packet = [0; 65535];
    for _ in 0..8 {
        let _ = a.endpoint.poll_transmit(a.now(), &mut packet, 32).unwrap();
    }
    let info = a.endpoint.transport_info(cid).unwrap();
    assert_eq!(info.notsent_bytes, 0);
    assert_eq!(info.send_used, 4000); // No peer ACKs were delivered.
    a.events();
    assert_ne!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
}
#[test]
fn stream_options_inherit_at_child_admission() {
    let mut a = owner(2);
    let mut b = owner(3);
    let listener = new(&mut b, 0);
    b.execute(listener, Op::Bind("10.73.0.3:16379".parse().unwrap()))
        .unwrap();
    for (option, value) in [
        (TCP_INQ, 1),
        (TCP_CORK, 1),
        (TCP_NODELAY, 1),
        (TCP_NOTSENT_LOWAT, -1),
    ] {
        b.execute(listener, Op::Set(IPPROTO_TCP, option, value))
            .unwrap();
    }
    b.execute(listener, Op::Listen(16)).unwrap();
    let client = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(client, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    pump(&mut a, &mut b);
    for option in [TCP_INQ, TCP_CORK, TCP_NODELAY, TCP_NOTSENT_LOWAT] {
        b.execute(listener, Op::Set(IPPROTO_TCP, option, 0))
            .unwrap();
    }
    let child = b.execute(listener, Op::Accept(0)).unwrap().value as u64;
    for (option, value) in [
        (TCP_INQ, 1),
        (TCP_CORK, 1),
        (TCP_NODELAY, 1),
        (TCP_NOTSENT_LOWAT, -1),
    ] {
        assert_eq!(
            b.execute(child, Op::Get(IPPROTO_TCP, option))
                .unwrap()
                .value,
            value
        );
    }
}

#[test]
fn finish_connect_after_handshake_and_immediate_fin() {
    let (mut a, mut b, _, _, listen) = pair();
    let client = new(&mut a, 0);
    assert_eq!(
        a.execute(client, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    let (reply, completed) = mpsc::sync_channel(1);
    let mut request = Request {
        id: client,
        op: Op::Wait(Box::new(Op::FinishConnect), None),
        reply,
        deadline: None,
        send: None,
        closing: None,
    };
    assert!(!a.service(&mut request));
    pump(&mut a, &mut b);
    let server = b.execute(listen, Op::Accept(0)).unwrap().value as u64;
    b.execute(server, Op::Shutdown(SHUT_WR)).unwrap();
    pump(&mut a, &mut b);
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        panic!()
    };
    assert_eq!(a.endpoint.state(cid), Ok(State::CloseWait));
    assert_eq!(a.execute(client, Op::FinishConnect).unwrap().value, 0);
    // The libc blocking connect retry and owner pending-request service
    // share FinishConnect; neither may keep waiting after the peer's FIN.
    assert!(a.service(&mut request));
    assert_eq!(completed.try_recv().unwrap().unwrap().value, 0);
    assert_eq!(a.execute(client, Op::Read(8)).unwrap().value, 0);
}

#[test]
fn peek_dispatch_and_timeout_inheritance() {
    let (mut a, mut b, client, server, listen) = pair();
    assert_eq!(b.execute(server, Op::Peek(8)).unwrap_err(), EAGAIN);
    a.execute(client, Op::Write(b"abcdef".to_vec())).unwrap();
    pump(&mut a, &mut b);
    let Handle::Connection(cid) = b.sockets[&server].handle else {
        panic!()
    };
    let before = b.endpoint.transport_info(cid).unwrap();
    for _ in 0..2 {
        assert_eq!(b.execute(server, Op::Peek(3)).unwrap().bytes, b"abc");
        assert_eq!(
            b.endpoint.transport_info(cid).unwrap().receive_used,
            before.receive_used
        );
    }
    assert_eq!(b.execute(server, Op::Read(8)).unwrap().bytes, b"abcdef");
    b.execute(listen, Op::SetTimeout(false, 123456)).unwrap();
    b.execute(listen, Op::SetTimeout(true, u64::MAX)).unwrap();
    let next = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(next, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    pump(&mut a, &mut b);
    b.execute(listen, Op::SetTimeout(false, 654321)).unwrap();
    b.execute(listen, Op::SetTimeout(true, 987654)).unwrap();
    let child = b.execute(listen, Op::Accept(0)).unwrap().value as u64;
    assert!(b.child_timeouts.is_empty());
    assert_eq!(
        b.execute(child, Op::GetTimeout(false)).unwrap().timeout_us,
        123456
    );
    assert_eq!(
        b.execute(child, Op::GetTimeout(true)).unwrap().timeout_us,
        u64::MAX
    );
    assert_eq!(
        b.execute(child, Op::Flags(F_GETFL, 0)).unwrap().value & O_NONBLOCK,
        0
    );
}

#[test]
fn passive_timeouts_snapshot_at_syn_and_cleanup_on_listener_close() {
    let (mut a, mut b, _, _, listen) = pair();
    b.execute(listen, Op::SetTimeout(false, 123456)).unwrap();
    b.execute(listen, Op::SetTimeout(true, 234567)).unwrap();
    let next = new(&mut a, 0);
    assert_eq!(
        a.execute(next, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    let mut bytes = [0; 1480];
    let syn = a
        .endpoint
        .poll_transmit(a.now(), &mut bytes, BUDGET)
        .unwrap()
        .packet
        .unwrap();
    b.input(b.now(), syn.ip, syn.dscp << 2 | syn.ecn, &bytes[..syn.len])
        .unwrap();
    let cid = b.child_timeouts[0].0;
    assert_eq!(b.endpoint.state(cid).unwrap(), State::SynReceived);
    b.execute(listen, Op::SetTimeout(false, 345678)).unwrap();
    b.execute(listen, Op::SetTimeout(true, 456789)).unwrap();
    // A retransmitted SYN must not replace the initial snapshot.
    b.input(b.now(), syn.ip, syn.dscp << 2 | syn.ecn, &bytes[..syn.len])
        .unwrap();
    assert_eq!(b.child_timeouts.len(), 1);
    pump(&mut a, &mut b);
    let child = b.execute(listen, Op::Accept(0)).unwrap().value as u64;
    assert_eq!(
        b.execute(child, Op::GetTimeout(false)).unwrap().timeout_us,
        123456
    );
    assert_eq!(
        b.execute(child, Op::GetTimeout(true)).unwrap().timeout_us,
        234567
    );
    assert!(b.child_timeouts.is_empty());
    let next = new(&mut a, 0);
    assert_eq!(
        a.execute(next, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    pump(&mut a, &mut b);
    assert_eq!(b.child_timeouts.len(), 1);
    b.execute(listen, Op::Close).unwrap();
    assert!(b.child_timeouts.is_empty());
}

#[test]
fn dispatch_stream_readiness_eof_and_listener_drain() {
    let (mut a, mut b, client, server, listen) = pair();
    assert_ne!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
    assert_eq!(b.execute(listen, Op::Accept(0)).unwrap_err(), EAGAIN);
    assert_eq!(b.execute(listen, Op::Ready).unwrap().value & EPOLLIN, 0);
    assert_eq!(b.execute(server, Op::Read(4)).unwrap_err(), EAGAIN);
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    assert_eq!(
        a.execute(client, Op::Write(b"abcdef".to_vec()))
            .unwrap()
            .value,
        6
    );
    a.execute(client, Op::Shutdown(SHUT_WR)).unwrap();
    pump(&mut a, &mut b);
    assert_ne!(b.execute(server, Op::Ready).unwrap().value & EPOLLIN, 0);
    assert_eq!(b.execute(server, Op::Read(2)).unwrap().bytes, b"ab");
    assert_eq!(b.execute(server, Op::Read(32)).unwrap().bytes, b"cdef");
    assert_eq!(b.execute(server, Op::Read(32)).unwrap().value, 0);
    assert_ne!(b.execute(server, Op::Ready).unwrap().value & EPOLLIN, 0);
    assert_eq!(a.execute(client, Op::Write(vec![1])).unwrap_err(), EPIPE);
    b.execute(server, Op::Close).unwrap();
    a.execute(client, Op::Close).unwrap();
    assert_eq!(a.execute(client, Op::Ready).unwrap_err(), EBADF);
    pump(&mut a, &mut b);
    assert!(!a.endpoint.has_pending_output());
}
#[test]
fn refusal_completes_and_error_is_consumed_once() {
    let mut a = owner(2);
    let mut b = owner(3);
    let id = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(id, Op::Connect("10.73.0.3:12345".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    pump(&mut a, &mut b);
    let ready = a.execute(id, Op::Ready).unwrap().value;
    assert_ne!(ready & EPOLLOUT, 0);
    assert_ne!(ready & EPOLLERR, 0);
    assert_eq!(
        a.execute(id, Op::Get(SOL_SOCKET, SO_ERROR)).unwrap().value,
        ECONNREFUSED
    );
    assert_eq!(
        a.execute(id, Op::Get(SOL_SOCKET, SO_ERROR)).unwrap().value,
        0
    );
}
#[test]
fn bounds_flags_addresses_and_honest_options() {
    let mut a = owner(2);
    let id = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(id, Op::Bind("10.73.0.1:1234".parse().unwrap()))
            .unwrap_err(),
        EADDRNOTAVAIL
    );
    a.execute(id, Op::Bind("0.0.0.0:0".parse().unwrap()))
        .unwrap();
    assert_ne!(
        a.execute(id, Op::Name(false)).unwrap().addr.unwrap().port(),
        0
    );
    a.execute(id, Op::Flags(F_SETFL, 0)).unwrap();
    assert_eq!(
        a.execute(id, Op::Flags(F_GETFL, 0)).unwrap().value & O_NONBLOCK,
        0
    );
    assert_eq!(
        a.execute(id, Op::Set(SOL_SOCKET, SO_REUSEPORT, 1))
            .unwrap_err(),
        ENOPROTOOPT
    );
    assert_eq!(
        a.execute(id, Op::Set(IPPROTO_TCP, TCP_KEEPIDLE, 0))
            .unwrap_err(),
        EINVAL
    );
    a.execute(id, Op::Set(IPPROTO_TCP, TCP_KEEPIDLE, 60))
        .unwrap();
    a.execute(id, Op::Set(SOL_SOCKET, SO_KEEPALIVE, 1)).unwrap();
    assert_eq!(
        a.execute(id, Op::Get(IPPROTO_TCP, TCP_KEEPIDLE))
            .unwrap()
            .value,
        60
    );
    for _ in 1..LIMIT {
        new(&mut a, 0);
    }
    assert_eq!(a.execute(0, Op::New(0)).unwrap_err(), EMFILE);
}
#[test]
fn reset_drains_payload_then_reports_error_once_then_eof() {
    let (mut a, mut b, client, server, _) = pair();
    a.execute(client, Op::Write(b"abcdef".to_vec())).unwrap();
    pump(&mut a, &mut b);
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        panic!()
    };
    a.endpoint.abort(cid).unwrap();
    pump(&mut a, &mut b);
    assert_eq!(b.execute(server, Op::Available).unwrap().value, 6);
    assert_eq!(b.execute(server, Op::Read(2)).unwrap().bytes, b"ab");
    assert_eq!(b.execute(server, Op::Available).unwrap().value, 4);
    assert_eq!(b.execute(server, Op::Read(32)).unwrap().bytes, b"cdef");
    assert_eq!(b.execute(server, Op::Read(32)).unwrap_err(), ECONNRESET);
    for _ in 0..2 {
        assert_eq!(b.execute(server, Op::Read(32)).unwrap().value, 0);
        assert_ne!(b.execute(server, Op::Ready).unwrap().value & EPOLLIN, 0);
    }
}

#[test]
fn keepalive_rejection_is_transactional_in_all_socket_states() {
    let (mut a, mut b, client, server, listen) = pair();
    let fresh = new(&mut b, 0);
    for id in [fresh, listen, server] {
        b.execute(id, Op::Set(IPPROTO_TCP, TCP_KEEPCNT, 4)).unwrap();
        b.execute(id, Op::Set(SOL_SOCKET, SO_KEEPALIVE, 1)).unwrap();
        assert_eq!(
            b.execute(id, Op::Set(IPPROTO_TCP, TCP_KEEPCNT, 1))
                .unwrap_err(),
            EINVAL
        );
        assert_eq!(
            b.execute(id, Op::Get(IPPROTO_TCP, TCP_KEEPCNT))
                .unwrap()
                .value,
            4
        );
        assert_eq!(
            b.execute(id, Op::Get(SOL_SOCKET, SO_KEEPALIVE))
                .unwrap()
                .value,
            1
        );
    }
    let second = new(&mut a, 0);
    assert_eq!(
        a.execute(second, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    pump(&mut a, &mut b);
    let accepted = b.execute(listen, Op::Accept(0)).unwrap().value as u64;
    assert_eq!(
        b.execute(accepted, Op::Get(IPPROTO_TCP, TCP_KEEPCNT))
            .unwrap()
            .value,
        4
    );
    a.execute(client, Op::Close).unwrap();
}

#[test]
fn option_application_failure_releases_connect_and_accept_records() {
    let mut a = owner(2);
    let mut b = owner(3);
    let listen = new(&mut b, 0);
    b.execute(listen, Op::Bind("10.73.0.3:16379".parse().unwrap()))
        .unwrap();
    b.execute(listen, Op::Listen(16)).unwrap();
    let client = new(&mut a, 0);
    // Inject an invalid internal configuration to exercise otherwise
    // unreachable failure paths; public sets reject this before mutation.
    a.sockets.get_mut(&client).unwrap().keepalive = true;
    a.sockets.get_mut(&client).unwrap().probes = 1;
    assert_eq!(
        a.execute(client, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINVAL
    );
    assert!(matches!(a.sockets[&client].handle, Handle::Fresh));
    assert!(a.sockets[&client].local.is_none());
    pump(&mut a, &mut b);
    assert_eq!(a.endpoint.buffer_bytes(), 0);
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_KEEPCNT, 2))
        .unwrap();
    assert_eq!(
        a.execute(client, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    pump(&mut a, &mut b);
    b.sockets.get_mut(&listen).unwrap().keepalive = true;
    b.sockets.get_mut(&listen).unwrap().probes = 1;
    assert_eq!(b.execute(listen, Op::Accept(0)).unwrap_err(), EINVAL);
    assert_eq!(b.sockets.len(), 1);
    assert!(b.child_timeouts.is_empty());
    // The failed child owes a reset: release must retain it until output.
    assert_ne!(b.endpoint.buffer_bytes(), 0);
    pump(&mut a, &mut b);
    // Local resets retain the released record for the core's 2MSL
    // quarantine; expiry must reclaim it rather than leak a slot.
    assert_ne!(b.endpoint.buffer_bytes(), 0);
    b.advance_clock(ntcp::ConnectionConfig::default().time_wait_us + 1);
    b.endpoint.on_timeout(b.now(), BUDGET).unwrap();
    assert_eq!(b.endpoint.buffer_bytes(), 0);
    b.execute(listen, Op::Set(IPPROTO_TCP, TCP_KEEPCNT, 2))
        .unwrap();
    let second = new(&mut a, 0);
    assert_eq!(
        a.execute(second, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    pump(&mut a, &mut b);
    assert!(b.execute(listen, Op::Accept(0)).is_ok());
}

#[test]
fn close_delivery_waits_for_space_in_bounded_queue() {
    let (tx, rx) = mpsc::sync_channel(LIMIT);
    for _ in 0..LIMIT {
        let (reply, _) = mpsc::sync_channel(1);
        tx.send(Request {
            id: 1,
            op: Op::Ready,
            reply,
            deadline: None,
            send: None,
            closing: None,
        })
        .unwrap();
    }
    let runtime = Runtime {
        tx,
        wake: -1,
        family: AF_INET,
        io_limit: BYTES,
        stop: Default::default(),
        worker: Mutex::new(None),
    };
    let caller = std::thread::spawn(move || runtime.call(1, Op::Close));
    for _ in 0..LIMIT {
        assert!(matches!(rx.recv().unwrap().op, Op::Ready));
    }
    let request = rx.recv().unwrap();
    assert!(matches!(request.op, Op::Close));
    request.reply.send(Ok(Reply::default())).unwrap();
    assert!(caller.join().unwrap().is_ok());
}

#[test]
fn startup_failure_joins_before_closing_wake() {
    // The post-close fd-number assertion needs its own process: parallel
    // tests may legitimately allocate the just-closed number immediately.
    const CHILD: &str = "NTCP_TEST_STARTUP_CLOSE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "runtime::tests::startup_failure_joins_before_closing_wake",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let wake = unsafe { syscall(SYS_eventfd2, 0, EFD_NONBLOCK | EFD_CLOEXEC) as i32 };
    assert!(wake >= 0);
    let (tx, rx) = mpsc::sync_channel(0);
    let open_at_exit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = open_at_exit.clone();
    let worker = std::thread::spawn(move || {
        rx.recv().unwrap();
        observed.store(
            unsafe { syscall(SYS_fcntl, wake, F_GETFD) } >= 0,
            std::sync::atomic::Ordering::SeqCst,
        );
        signal(wake);
    });
    let closer = std::thread::spawn(move || close_failed_startup(worker, wake));
    tx.send(()).unwrap();
    closer.join().unwrap();
    assert!(open_at_exit.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(unsafe { syscall(SYS_fcntl, wake, F_GETFD) }, -1);
}

#[test]
fn socket_buffer_semantics_inherit_at_syn_and_resize_readiness() {
    for (name, minimum) in [(SO_SNDBUF, 4608), (SO_RCVBUF, 2304)] {
        for (request, expected) in [
            (0, minimum),
            (1, minimum),
            (65536, 131072),
            (-1, 2097152),
            (i32::MAX, 2097152),
        ] {
            assert_eq!(socket_buffer_value(name, request), expected);
        }
    }
    let mut config = SocketConfig::new("test", Ipv4Addr::new(10, 73, 0, 2)).tcp;
    // Budget for actual per-byte ledger storage: admit 2 MiB, but reject later growth.
    config.max_buffer_bytes = 160 * 1024 * 1024;
    let mut a = owner_with_config(2, config);
    let mut b = owner(3);
    let listener = new(&mut b, SOCK_NONBLOCK);
    b.execute(listener, Op::Set(SOL_SOCKET, SO_SNDBUF, 8192))
        .unwrap();
    b.execute(listener, Op::Set(SOL_SOCKET, SO_RCVBUF, 131072))
        .unwrap();
    b.execute(listener, Op::Bind("10.73.0.3:16379".parse().unwrap()))
        .unwrap();
    b.execute(listener, Op::Listen(4)).unwrap();
    let client = new(&mut a, SOCK_NONBLOCK);
    a.execute(client, Op::Set(SOL_SOCKET, SO_SNDBUF, 4096))
        .unwrap();
    a.execute(client, Op::Set(SOL_SOCKET, SO_RCVBUF, 262144))
        .unwrap();
    assert_eq!(
        a.execute(client, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    pump(&mut a, &mut b);
    b.execute(listener, Op::Set(SOL_SOCKET, SO_SNDBUF, 0))
        .unwrap();
    b.execute(listener, Op::Set(SOL_SOCKET, SO_RCVBUF, 0))
        .unwrap();
    let server = b
        .execute(listener, Op::Accept(SOCK_NONBLOCK))
        .unwrap()
        .value as u64;
    assert_eq!(
        b.execute(server, Op::Get(SOL_SOCKET, SO_SNDBUF))
            .unwrap()
            .value,
        16384
    );
    assert_eq!(
        b.execute(server, Op::Get(SOL_SOCKET, SO_RCVBUF))
            .unwrap()
            .value,
        262144
    );
    assert_eq!(
        a.execute(client, Op::Write(vec![42; 8192])).unwrap().value,
        8192
    );
    assert_eq!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
    a.execute(client, Op::Set(SOL_SOCKET, SO_SNDBUF, 0))
        .unwrap();
    assert_eq!(a.execute(client, Op::Write(vec![0])).unwrap_err(), EAGAIN);
    a.execute(client, Op::Set(SOL_SOCKET, SO_SNDBUF, 8192))
        .unwrap();
    assert_ne!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
    b.execute(server, Op::Set(SOL_SOCKET, SO_RCVBUF, 0))
        .unwrap();
    pump(&mut a, &mut b);
    assert_ne!(b.execute(server, Op::Ready).unwrap().value & EPOLLIN, 0);
    // The pre-shrink promised window accepts and retains all queued bytes.
    assert_eq!(
        b.execute(server, Op::Read(8192)).unwrap().bytes,
        vec![42; 8192]
    );
    assert_eq!(
        b.execute(server, Op::Get(SOL_SOCKET, SO_RCVBUF))
            .unwrap()
            .value,
        2304
    );
    a.endpoint
        .connect_with_buffer_capacities(
            a.now(),
            "10.73.0.2:25000".parse().unwrap(),
            "10.73.0.3:25000".parse().unwrap(),
            2 * BUFFER_REQUEST_CAP as usize,
            BYTES,
        )
        .unwrap();
    let old = a
        .execute(client, Op::Get(SOL_SOCKET, SO_SNDBUF))
        .unwrap()
        .value;
    assert_eq!(
        a.execute(client, Op::Set(SOL_SOCKET, SO_SNDBUF, i32::MAX))
            .unwrap_err(),
        ENOBUFS
    );
    assert_eq!(
        a.execute(client, Op::Get(SOL_SOCKET, SO_SNDBUF))
            .unwrap()
            .value,
        old
    );
}

#[test]
fn send_buffer_backpressure_and_short_write() {
    let (mut a, mut b, client, _server, _listen) = pair();
    let first = a
        .execute(client, Op::Write(vec![42; BYTES - 10]))
        .unwrap()
        .value;
    assert_eq!(first as usize, BYTES - 10);
    assert_eq!(
        a.execute(client, Op::Write(vec![42; 100])).unwrap().value,
        10
    );
    assert_eq!(
        a.execute(client, Op::Write(vec![42; 1])).unwrap_err(),
        EAGAIN
    );
    assert_eq!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
    pump(&mut a, &mut b);
}
