// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;
use crate::packet_profile::Profile;
use crate::packet_test::Options;
use crate::runtime::tests::new;

fn owner(last: u8, profile: Profile, capacity: usize) -> Owner {
    let mut owner = Owner::packet_with_options(
        (Ipv4Addr::new(192, 0, 2, last), profile),
        Options {
            queue_capacity: capacity,
            egress_capacity: 2,
        },
    )
    .unwrap();
    owner.test_now = Some(1000);
    assert!(owner.egress.is_some());
    assert!(owner.pending_packet.is_none());
    assert_eq!(
        owner.packets.as_ref().unwrap().layer(),
        ntcp_io::PacketLayer::Ip
    );
    assert!(
        owner
            .packets
            .as_ref()
            .unwrap()
            .tcp_segmentation_capabilities()
            .is_none()
    );
    owner
}
fn receive(owner: &mut Owner) {
    owner.receive_batch(&mut vec![0; 65535]).unwrap();
    owner.events();
}
fn exchange(a: &mut Owner, b: &mut Owner) {
    for _ in 0..16 {
        for reverse in [false, true] {
            let (from, to) = if reverse {
                (&mut *b, &mut *a)
            } else {
                (&mut *a, &mut *b)
            };
            receive(from);
            from.service_egress().unwrap();
            while let Ok(packet) = from.execute(0, Op::Capture(65535)) {
                to.execute(0, Op::Inject(packet.bytes)).unwrap();
                receive(to);
            }
        }
    }
}
fn pair(profile: Profile, capacity: usize) -> (Owner, Owner, [u64; 2], [u64; 2]) {
    let mut a = owner(1, profile, capacity);
    let mut b = owner(2, Profile::Pipeline, 128);
    let listener = new(&mut b, SOCK_NONBLOCK);
    b.execute(listener, Op::Bind("192.0.2.2:8080".parse().unwrap()))
        .unwrap();
    b.execute(listener, Op::Listen(2)).unwrap();
    let mut clients = [0; 2];
    let mut servers = [0; 2];
    for i in 0..2 {
        clients[i] = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(clients[i], Op::Connect("192.0.2.2:8080".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        exchange(&mut a, &mut b);
        servers[i] = b
            .execute(listener, Op::Accept(SOCK_NONBLOCK))
            .unwrap()
            .value as u64;
    }
    (a, b, clients, servers)
}
fn cid(owner: &Owner, fd: u64) -> ConnectionId {
    let Handle::Connection(id) = owner.sockets[&fd].handle else {
        panic!()
    };
    id
}
fn segment(bytes: &[u8]) -> ntcp::wire::Segment<'_> {
    let p = ntcp_ip::parse(bytes, false).unwrap();
    ntcp::wire::parse(p.ip, p.payload).unwrap()
}

#[test]
fn bounded_ip_backend_and_capture_acceptance_timestamp() {
    let mut a = owner(1, Profile::Pipeline, 1);
    let mut bytes = [0; 65535];
    let backend = a.packets.as_mut().unwrap();
    backend.inject(vec![1]).unwrap();
    assert_eq!(backend.inject(vec![2]), Err(EAGAIN));
    assert_eq!(
        backend.receive(&mut []).unwrap_err().raw_os_error(),
        Some(EMSGSIZE)
    );
    assert_eq!(backend.receive(&mut bytes).unwrap(), Some(1));
    assert_eq!(bytes[0], 1);
    let before = timestamps::realtime() / 1000;
    assert_eq!(backend.transmit(&[1, 2]).unwrap(), TxOutcome::Submitted);
    let after = timestamps::realtime() / 1000;
    assert_eq!(backend.transmit(&[3]).unwrap(), TxOutcome::WouldBlock);
    assert_eq!(a.execute(0, Op::Capture(1)).unwrap_err(), EMSGSIZE);
    std::thread::sleep(std::time::Duration::from_millis(2));
    let capture = a.execute(0, Op::Capture(2)).unwrap();
    assert_eq!(capture.bytes, [1, 2]);
    assert!((before..=after).contains(&(capture.stamp as u64)));
    assert!(capture.stamp < (timestamps::realtime() / 1000) as i64);
    assert_eq!(a.execute(0, Op::Capture(2)).unwrap_err(), EAGAIN);
}

#[test]
fn capacity_one_retains_ordered_rx_and_unrelated_commands_progress() {
    let (mut a, mut b, clients, servers) = pair(Profile::PipelineGso, 1);
    let held = cid(&a, clients[0]);
    a.execute(clients[0], Op::Write(vec![7; 4380])).unwrap();
    a.service_egress().unwrap();
    assert!(a.endpoint.is_output_reserved(held));
    let attempt = a.egress.as_ref().unwrap().attempt(held);
    let descriptor = a.endpoint.transmit_segmentation(attempt).unwrap();
    assert_eq!(descriptor.payload_len, 4380);
    assert_eq!(descriptor.segment_payload_len, 1460);
    assert_eq!(
        a.execute(clients[0], Op::Write(vec![1])).unwrap_err(),
        EAGAIN
    );
    // Held connection cannot stall independent socket commands or RX admission.
    a.execute(clients[1], Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    for data in [b"first".as_slice(), b"second".as_slice()] {
        b.execute(servers[0], Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
            .unwrap();
        b.execute(servers[0], Op::Write(data.to_vec())).unwrap();
        b.service_egress().unwrap();
        let bytes = b.execute(0, Op::Capture(65535)).unwrap().bytes;
        a.execute(0, Op::Inject(bytes)).unwrap();
        receive(&mut a);
    }
    assert_eq!(a.endpoint.readable_bytes(held).unwrap(), 0);
    assert_eq!(a.packets.as_ref().unwrap().input.len(), 0);
    for i in 0..3 {
        let capture = a.execute(0, Op::Capture(65535)).unwrap();
        assert_eq!(segment(&capture.bytes).payload, vec![7; 1460]);
        if i < 2 {
            assert!(a.endpoint.is_output_reserved(held));
            a.test_now = Some(a.now() + 1000);
            a.service_egress().unwrap();
        }
    }
    assert!(!a.endpoint.is_output_reserved(held));
    receive(&mut a);
    assert_eq!(
        a.execute(clients[0], Op::Read(64)).unwrap().bytes,
        b"firstsecond"
    );
}

#[test]
fn software_segments_match_scalar_and_share_a_bounded_service_turn() {
    let mut runs = Vec::new();
    for profile in [Profile::Pipeline, Profile::PipelineGso] {
        let (mut a, _, clients, _) = pair(profile, 128);
        for client in clients {
            a.execute(client, Op::Write(vec![8; 4380])).unwrap();
        }
        a.service_egress().unwrap();
        let packets: Vec<_> = a
            .packets
            .as_mut()
            .unwrap()
            .output
            .drain(..)
            .map(|r| r.bytes)
            .collect();
        assert_eq!(packets.len(), 6);
        assert!(packets.len() <= BUDGET);
        for packet in &packets {
            assert_eq!(packet.len(), 1500);
            assert_eq!(segment(packet).payload, vec![8; 1460]);
        }
        let ports: Vec<_> = packets
            .iter()
            .map(|p| segment(p).header.source_port)
            .collect();
        assert_ne!(ports[0], ports[1]);
        assert_eq!(
            ports,
            [ports[0], ports[1], ports[0], ports[1], ports[0], ports[1]]
        );
        assert_eq!(
            a.egress.as_ref().unwrap().selected_ranges,
            if profile == Profile::PipelineGso {
                6
            } else {
                10
            }
        );
        runs.push(packets);
    }
    assert_eq!(runs[0], runs[1]);
}

#[test]
fn deterministic_pacing_never_submits_before_core_deadline() {
    let (mut a, _, clients, _) = pair(Profile::PipelinePacedGso, 128);
    a.execute(clients[0], Op::Write(vec![9; 4380])).unwrap();
    a.service_egress().unwrap();
    let first = a.packets.as_ref().unwrap().output.len();
    assert!(first > 0 && first <= 2);
    let deadline = a.endpoint.next_deadline().unwrap();
    assert!(deadline > a.now());
    a.test_now = Some(deadline - 1);
    a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
    a.service_egress().unwrap();
    assert_eq!(a.packets.as_ref().unwrap().output.len(), first);
    a.test_now = Some(deadline);
    a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
    a.service_egress().unwrap();
    assert!(a.packets.as_ref().unwrap().output.len() > first);
}

#[test]
fn full_deferred_commands_do_not_hide_capture_or_inject() {
    let (initialized, initialization) = mpsc::sync_channel(1);
    let runtime = std::sync::Arc::new(
        Runtime::spawn(
            move || {
                let mut a = owner(1, Profile::Pipeline, 1);
                for port in [8080, 8081] {
                    let fd = new(&mut a, SOCK_NONBLOCK);
                    assert_eq!(
                        a.execute(
                            fd,
                            Op::Connect(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), port))
                        )
                        .unwrap_err(),
                        EINPROGRESS
                    );
                }
                a.service_egress().unwrap();
                let held = a
                    .sockets
                    .iter()
                    .find_map(|(&fd, socket)| match socket.handle {
                        Handle::Connection(cid) if a.endpoint.is_output_reserved(cid) => Some(fd),
                        _ => None,
                    })
                    .unwrap();
                let packet = a
                    .packets
                    .as_ref()
                    .unwrap()
                    .output
                    .front()
                    .unwrap()
                    .bytes
                    .clone();
                let mut replies = Vec::new();
                for _ in 0..a.socket_limit() {
                    let (reply, rx) = mpsc::sync_channel(1);
                    replies.push(rx);
                    a.pending.push_back(Request {
                        id: held,
                        op: Op::Set(IPPROTO_TCP, TCP_NODELAY, 1),
                        reply,
                        deadline: None,
                        send: None,
                        closing: None,
                    });
                }
                initialized.send((packet, replies)).unwrap();
                Ok(a)
            },
            true,
        )
        .unwrap(),
    );
    let (packet, _replies) = initialization.recv().unwrap();
    let worker = runtime.clone();
    let (done, completed) = mpsc::sync_channel(1);
    let join = std::thread::spawn(move || {
        assert_eq!(worker.call(0, Op::New(0)).unwrap_err(), EAGAIN);
        worker.call(0, Op::Inject(packet)).unwrap();
        let capture = worker.call(0, Op::Capture(65535)).unwrap();
        done.send(capture.bytes).unwrap();
    });
    let result = completed.recv_timeout(std::time::Duration::from_secs(2));
    runtime.stop();
    join.join().unwrap();
    assert!(!result.unwrap().is_empty());
}

#[test]
fn last_close_retries_full_admission_instead_of_leaking_removed_fd() {
    let (tx, requests) = mpsc::sync_channel::<Request>(1);
    let wake = unsafe { syscall(SYS_eventfd2, 0, EFD_NONBLOCK | EFD_CLOEXEC) as i32 };
    assert!(wake >= 0);
    let runtime = Runtime {
        tx,
        wake,
        family: AF_INET,
        io_limit: 65535,
        stop: Default::default(),
        worker: Mutex::new(None),
    };
    let worker = std::thread::spawn(move || {
        for result in [Err(EAGAIN), Ok(Reply::default())] {
            let request = requests.recv().unwrap();
            assert_eq!(request.id, 42);
            assert!(matches!(request.op, Op::Close));
            request.reply.send(result).unwrap();
        }
    });
    runtime.call(42, Op::Close).unwrap();
    worker.join().unwrap();
}

include!("runtime_fast_open_tests.rs");
