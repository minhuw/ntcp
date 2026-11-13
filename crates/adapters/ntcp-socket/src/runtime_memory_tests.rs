// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;
use crate::packet_profile::Profile;
use crate::packet_test::Options;
use crate::runtime::fast_open_tests::{tfo_capture, tfo_deliver, tfo_no_output};
use crate::runtime::pmtud_profile_tests::upstream_runtime_pmtud_profile_tests;
use crate::runtime::tests::{ip_packet, new};

pub(crate) fn owner(last: u8, profile: Profile, capacity: usize) -> Owner {
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
    assert!(!owner.egress.as_ref().unwrap().has_held());
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
pub(crate) fn receive(owner: &mut Owner) {
    owner.receive_batch(&mut vec![0; 65535]).unwrap();
    owner.events();
}
pub(crate) fn exchange(a: &mut Owner, b: &mut Owner) {
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
pub(crate) fn pair(profile: Profile, capacity: usize) -> (Owner, Owner, [u64; 2], [u64; 2]) {
    pair_with_owner(owner(1, profile, capacity))
}
fn pair_with_owner(mut a: Owner) -> (Owner, Owner, [u64; 2], [u64; 2]) {
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
pub(crate) fn cid(owner: &Owner, fd: u64) -> ConnectionId {
    let Handle::Connection(id) = owner.sockets[&fd].handle else {
        panic!()
    };
    id
}
pub(crate) fn segment(bytes: &[u8]) -> ntcp::wire::Segment<'_> {
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
            .map(|(r, _)| r.bytes)
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
        // GSO selects each connection's 4380 bytes once, as one range of three
        // software segments; scalar output selects every segment separately.
        // A one-packet backend holds that range after its first segment.
        let (mut held, _, held_clients, _) = pair(profile, 1);
        held.execute(held_clients[0], Op::Write(vec![8; 4380]))
            .unwrap();
        held.service_egress().unwrap();
        let attempt = held
            .egress
            .as_ref()
            .unwrap()
            .attempt(cid(&held, held_clients[0]));
        assert_eq!(held.packets.as_ref().unwrap().output.len(), 1);
        assert_eq!(
            held.endpoint
                .transmit_segmentation(attempt)
                .map(|range| (range.payload_len, range.segment_payload_len)),
            (profile == Profile::PipelineGso).then_some((4380, 1460))
        );
        runs.push(packets);
    }
    assert_eq!(runs[0], runs[1]);
}

#[test]
fn deterministic_pacing_never_submits_before_core_deadline() {
    let (mut a, mut b, clients, servers) = pair(Profile::PipelinePacedGso, 128);
    // Retire a real initial write before testing ordinary pacing deadlines.
    a.execute(clients[0], Op::Write(vec![8; 1460])).unwrap();
    exchange(&mut a, &mut b);
    let now = a.now() + 200000;
    a.test_now = Some(now);
    b.test_now = Some(now);
    a.endpoint.on_timeout(now, BUDGET).unwrap();
    b.endpoint.on_timeout(now, BUDGET).unwrap();
    exchange(&mut a, &mut b);
    assert_eq!(
        b.execute(servers[0], Op::Read(1460)).unwrap().bytes.len(),
        1460
    );
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
                    .0
                    .bytes
                    .clone();
                let mut replies = Vec::new();
                for _ in 0..a.request_limit() {
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

// PMTUD is opt-in independently of packet admission; keep profile defaults intact.
pub(crate) fn ptb_pair(capacity: usize) -> (Owner, Owner, [u64; 2], [u64; 2]) {
    let mut a = owner(1, Profile::PipelineGso, capacity);
    let mut config = crate::packet_profile::config(Profile::PipelineGso);
    config.connection.pmtud = Some(ntcp::PmtudConfig::new(1500));
    a.replace_packet_endpoint(config).unwrap();
    a.enable_egress(2, crate::packet_profile::gso(Profile::PipelineGso))
        .unwrap();
    pair_with_owner(a)
}
pub(crate) fn ptb_checksums(bytes: &mut [u8]) {
    bytes[10..12].fill(0);
    let sum = ntcp_ip::checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&sum.to_be_bytes());
    bytes[22..24].fill(0);
    let sum = ntcp_icmp::checksum(&bytes[20..]);
    bytes[22..24].copy_from_slice(&sum.to_be_bytes());
}
pub(crate) fn ptb_frame(packet: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 56];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&56u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 1;
    bytes[12..16].copy_from_slice(&[192, 0, 2, 254]); // Intermediate router.
    bytes[16..20].copy_from_slice(&packet[12..16]);
    bytes[20] = 3;
    bytes[21] = 4;
    bytes[26..28].copy_from_slice(&1200u16.to_be_bytes());
    bytes[28..].copy_from_slice(&packet[..28]);
    ptb_checksums(&mut bytes);
    bytes
}
pub(crate) fn path_mtu(a: &Owner, fd: u64) -> u32 {
    a.endpoint
        .path_mtu_info(cid(a, fd))
        .unwrap()
        .unwrap()
        .current_mtu
}

#[test]
fn packet_ptb_validation_precedes_bounded_queue_admission() {
    let (mut a, _, clients, _) = ptb_pair(1);
    a.execute(clients[0], Op::Write(vec![7; 1460])).unwrap();
    a.service_egress().unwrap();
    let packet = a.execute(0, Op::Capture(65535)).unwrap().bytes;
    let valid = ptb_frame(&packet);
    assert_eq!(
        ntcp_icmp::decode_icmp(&valid).unwrap().kind,
        ntcp_icmp::FeedbackKind::PacketTooBig
    );
    // Keep the TCP-only parser's contract for its other callers.
    assert_eq!(
        crate::packet_profile::parse_frame(&valid).unwrap_err(),
        ENOSYS
    );
    for (index, value, fix, errno) in [
        (10, valid[10] ^ 1, false, EINVAL), // Outer checksum.
        (22, valid[22] ^ 1, false, EINVAL), // ICMP checksum.
        (30, 0, true, EINVAL),              // Quoted total length, invalid header checksum.
        (48, 0, true, EINVAL),              // Zero quoted source port (both bytes below).
        (6, 0x20, true, ENOSYS),            // Outer fragment.
        (6, 0x80, true, ENOSYS),            // Reserved flag.
        (7, 1, true, ENOSYS),               // Fragment offset.
        (34, 0x20, true, EINVAL),           // Fragmented quote, even with valid checksum.
        (2, 1, true, EINVAL),               // Outer length exceeds supplied bytes.
        (0, 0x65, true, EINVAL),            // IPv4 bytes are not a valid IPv6 frame.
        (0, 0x46, true, ENOSYS),            // Outer options remain unsupported.
        (9, 17, true, ENOSYS),              // UDP is not admitted.
        (20, 8, true, ENOSYS),              // Echo is not admitted.
        (16, 203, true, EINVAL),            // Destination must match quoted sender.
    ] {
        let mut bad = valid.clone();
        bad[index] = value;
        if index == 48 {
            bad[49] = 0;
        }
        if index == 34 {
            bad[38..40].fill(0);
            let sum = ntcp_ip::checksum(&bad[28..48]);
            bad[38..40].copy_from_slice(&sum.to_be_bytes());
        }
        if fix {
            ptb_checksums(&mut bad);
        }
        assert_eq!(
            a.execute(0, Op::Inject(bad)).unwrap_err(),
            errno,
            "index {index}"
        );
        assert!(a.packets.as_ref().unwrap().input.is_empty());
    }
    let mut truncated = valid[..55].to_vec();
    truncated[2..4].copy_from_slice(&55u16.to_be_bytes());
    ptb_checksums(&mut truncated);
    assert_eq!(a.execute(0, Op::Inject(truncated)).unwrap_err(), EINVAL);
    a.execute(0, Op::Inject(valid.clone())).unwrap();
    assert_eq!(a.packets.as_ref().unwrap().input.len(), 1);
    assert_eq!(path_mtu(&a, clients[0]), 1500); // Admission is not delivery.
    assert_eq!(a.execute(0, Op::Inject(valid)).unwrap_err(), EAGAIN);
    receive(&mut a);
    assert_eq!(path_mtu(&a, clients[0]), 1200);
    assert_eq!(path_mtu(&a, clients[1]), 1500);
}

// PMTU feedback re-rounds the send space C of an unchanged SO_SNDBUF (B):
// a smaller C keeps the bytes already admitted above it, a larger one
// reopens writable readiness with a new edge; getsockopt keeps B.
#[test]
fn packet_ptb_rerounds_send_space_readiness_and_edges() {
    let (mut a, _, clients, _) = ptb_pair(1);
    let fd = clients[0];
    let id = cid(&a, fd);
    a.execute(fd, Op::Set(SOL_SOCKET, SO_SNDBUF, 2304)).unwrap();
    let sndbuf = |a: &mut Owner| a.execute(fd, Op::Get(SOL_SOCKET, SO_SNDBUF)).unwrap().value;
    let ready = |a: &mut Owner| a.execute(fd, Op::Ready).unwrap();
    assert_eq!(sndbuf(&mut a), 4608);
    assert_eq!(a.endpoint.transport_info(id).unwrap().mss, 1460);
    assert_eq!(
        a.execute(fd, Op::Write(vec![7; 10000])).unwrap().value,
        3 * 1460
    );
    // Send everything so that no reserved output defers the feedback.
    let mut packets = Vec::new();
    for _ in 0..3 {
        a.service_egress().unwrap();
        packets.push(a.execute(0, Op::Capture(65535)).unwrap().bytes);
        a.test_now = Some(a.now() + 1000);
    }
    assert!(!a.endpoint.is_output_reserved(id));
    let blocked = ready(&mut a);
    assert_eq!(blocked.value & EPOLLOUT, 0);
    let info = a.endpoint.transport_info(id).unwrap();
    assert!(info.send_used < info.send_capacity);
    let feedback = |a: &mut Owner, mtu: u16| {
        let mut report = ptb_frame(&packets[0]);
        report[26..28].copy_from_slice(&mtu.to_be_bytes());
        ptb_checksums(&mut report);
        a.execute(0, Op::Inject(report)).unwrap();
        receive(a);
        assert_eq!(path_mtu(a, fd), u32::from(mtu));
        a.endpoint.transport_info(id).unwrap()
    };
    // 1200: C = 3 * 1160 is below the 4380 admitted bytes, which stay.
    let info = feedback(&mut a, 1200);
    assert_eq!(
        (info.mss, info.send_space, info.send_used),
        (1160, 3480, 4380)
    );
    assert_eq!(ready(&mut a).value & EPOLLOUT, 0);
    assert_eq!(a.execute(fd, Op::Write(vec![7; 1])).unwrap_err(), EAGAIN);
    // 1140: C = 4 * 1100 exceeds them again and reopens 20 bytes.
    let info = feedback(&mut a, 1140);
    assert_eq!(
        (info.mss, info.send_space, info.send_used),
        (1100, 4400, 4380)
    );
    let reopened = ready(&mut a);
    assert_ne!(reopened.value & EPOLLOUT, 0);
    assert!(socket_options::edge_changed(
        EPOLLOUT as u32,
        Some(blocked.readiness_generations),
        reopened.readiness_generations,
    ));
    assert_eq!(a.execute(fd, Op::Write(vec![7; 10000])).unwrap().value, 20);
    assert_eq!(ready(&mut a).value & EPOLLOUT, 0);
    assert_eq!(sndbuf(&mut a), 4608);
}

#[test]
fn packet_ptb_retained_owner_does_not_block_other_flow() {
    let (mut a, mut b, clients, servers) = ptb_pair(1);
    let held = cid(&a, clients[0]);
    a.execute(clients[0], Op::Write(vec![7; 4380])).unwrap();
    a.service_egress().unwrap();
    assert!(a.endpoint.is_output_reserved(held));
    let packet = a.execute(0, Op::Capture(65535)).unwrap().bytes;
    a.execute(0, Op::Inject(ptb_frame(&packet))).unwrap();
    receive(&mut a);
    assert!(a.packets.as_ref().unwrap().input.is_empty());
    assert_eq!(path_mtu(&a, clients[0]), 1500);
    b.execute(servers[1], Op::Write(b"other flow".to_vec()))
        .unwrap();
    b.service_egress().unwrap();
    let packet = b.execute(0, Op::Capture(65535)).unwrap().bytes;
    a.execute(0, Op::Inject(packet)).unwrap();
    receive(&mut a);
    assert_eq!(
        a.execute(clients[1], Op::Read(64)).unwrap().bytes,
        b"other flow"
    );
    assert!(a.endpoint.is_output_reserved(held));
    assert_eq!(path_mtu(&a, clients[0]), 1500);
    // Drain the remaining software segments, releasing the exact held owner.
    for _ in 0..2 {
        a.test_now = Some(a.now() + 1000);
        a.service_egress().unwrap();
        let packet = a.execute(0, Op::Capture(65535)).unwrap().bytes;
        assert_eq!(segment(&packet).payload, vec![7; 1460]);
    }
    assert!(!a.endpoint.is_output_reserved(held));
    receive(&mut a);
    assert_eq!(path_mtu(&a, clients[0]), 1200);
    assert_eq!(path_mtu(&a, clients[1]), 1500);
}

#[test]
fn packet_ptb_queued_feedback_still_checks_target_tuple_and_sequence() {
    let (mut a, _, clients, _) = ptb_pair(1);
    a.execute(clients[0], Op::Write(vec![7; 1460])).unwrap();
    a.service_egress().unwrap();
    let packet = a.execute(0, Op::Capture(65535)).unwrap().bytes;
    let valid = ptb_frame(&packet);
    for index in [16, 44, 50, 52] {
        let mut wrong = valid.clone();
        wrong[index] ^= 0x40;
        if index == 16 {
            // Structurally consistent feedback, but not addressed to this owner.
            wrong[40] = wrong[16];
        }
        wrong[38..40].fill(0);
        let sum = ntcp_ip::checksum(&wrong[28..48]);
        wrong[38..40].copy_from_slice(&sum.to_be_bytes());
        ptb_checksums(&mut wrong);
        ntcp_icmp::decode_icmp(&wrong).unwrap();
        a.execute(0, Op::Inject(wrong)).unwrap();
        receive(&mut a);
        assert_eq!(path_mtu(&a, clients[0]), 1500, "index {index}");
        assert_eq!(path_mtu(&a, clients[1]), 1500);
    }
    a.execute(0, Op::Inject(valid)).unwrap();
    receive(&mut a);
    assert_eq!(path_mtu(&a, clients[0]), 1200);
    assert_eq!(path_mtu(&a, clients[1]), 1500);
}

#[test]
fn icmp_synrecv_baseline_soft_errors_preserve_handshake() {
    for mode in [
        "packet-admission",
        "production-input",
        "soft-core",
        "hard-core-control",
    ] {
        let mut a = owner(1, upstream_runtime_pmtud_profile_tests(""), 8);
        let listener = new(&mut a, SOCK_NONBLOCK);
        let local: SocketAddr = "192.0.2.1:8080".parse().unwrap();
        let remote: SocketAddr = "192.0.2.2:50000".parse().unwrap();
        a.execute(listener, Op::Bind(local)).unwrap();
        a.execute(listener, Op::Listen(1)).unwrap();
        let incoming = ntcp::IpMetadata {
            source: remote.ip(),
            destination: local.ip(),
        };
        let mut tcp = [0u8; 128];
        let size = ntcp::wire::encode(
            incoming,
            ntcp::wire::Header {
                source_port: remote.port(),
                destination_port: local.port(),
                sequence: 100,
                acknowledgment: 0,
                flags: ntcp::wire::SYN,
                window: 32792,
                urgent_pointer: 0,
            },
            &[
                2, 4, 5, 180, 4, 2, 1, 1, 254, 12, 0xf9, 0x89, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                0x12, 0x34,
            ],
            &[0x42; 10],
            &mut tcp,
        )
        .unwrap();
        let frame = ip_packet(
            &a,
            ntcp::Transmit {
                tx_timestamp: None,
                connection: None,
                ip: incoming,
                len: size,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: Default::default(),
                mark: 0,
            },
            &tcp[..size],
        );
        tfo_deliver(&mut a, frame);
        let synack = tfo_capture(&mut a);
        let sent = segment(&synack);
        assert_eq!(sent.header.flags, ntcp::wire::SYN | ntcp::wire::ACK);
        assert_eq!(sent.header.acknowledgment, 101); // SYN data not accepted.
        assert!(sent.payload.is_empty());
        assert!(sent.options.fast_open.is_none());
        let sequence = sent.header.sequence;
        let tuple = ntcp::Tuple { local, remote };
        let child = a.endpoint.connection_id(tuple).unwrap();
        assert_eq!(a.endpoint.state(child).unwrap(), State::SynReceived);
        let now = a.now();
        let mut wrong = tuple;
        wrong.remote.set_port(50001);
        assert!(
            !a.endpoint
                .network_error(now, wrong, sequence, ntcp::NetworkError::SoftUnreachable)
                .unwrap()
        );
        assert!(
            !a.endpoint
                .network_error(
                    now,
                    tuple,
                    sequence.wrapping_add(1),
                    ntcp::NetworkError::SoftUnreachable
                )
                .unwrap()
        );
        let mut feedback = ptb_frame(&synack);
        feedback[21] = 1; // ICMP type3/code1: host unreachable, a soft error.
        feedback[24..28].fill(0);
        ptb_checksums(&mut feedback);
        let decoded = ntcp_icmp::decode_icmp(&feedback).unwrap();
        assert_eq!(
            decoded.kind,
            ntcp_icmp::FeedbackKind::DestinationUnreachable
        );
        assert_eq!(decoded.code, 1);
        assert_eq!(decoded.quoted.sequence, sequence);
        let hard = mode == "hard-core-control";
        match mode {
            "packet-admission" => {
                a.execute(0, Op::Inject(feedback)).unwrap();
                a.receive_batch(&mut vec![0; 65535]).unwrap();
            }
            "production-input" => a.input_ip(&feedback, ntcp::RxPacketTimestamps::default()),
            "soft-core" | "hard-core-control" => {
                // HardUnreachable is an API control, not a proposed mapping
                // of host-unreachable code1. It proves the late-RST path.
                assert!(
                    a.endpoint
                        .network_error(
                            now,
                            tuple,
                            sequence,
                            if hard {
                                ntcp::NetworkError::HardUnreachable
                            } else {
                                ntcp::NetworkError::SoftUnreachable
                            }
                        )
                        .unwrap()
                );
            }
            _ => unreachable!(),
        }
        let mut reports = 0;
        while let Some(event) = a.endpoint.next_event() {
            if let ntcp::Event::PassiveError {
                tuple: reported,
                error,
                ..
            } = event
            {
                assert_eq!(reported, tuple);
                assert_eq!(
                    error,
                    if hard {
                        ntcp::NetworkError::HardUnreachable
                    } else {
                        ntcp::NetworkError::SoftUnreachable
                    }
                );
                reports += 1;
            }
        }
        assert_eq!(reports, 1); // Wire ingress and direct calls reach the same core report.
        if hard {
            assert!(a.endpoint.connection_id(tuple).is_none());
        } else {
            assert_eq!(a.endpoint.state(child).unwrap(), State::SynReceived);
        }
        tfo_no_output(&mut a);
        let size = ntcp::wire::encode(
            incoming,
            ntcp::wire::Header {
                source_port: remote.port(),
                destination_port: local.port(),
                sequence: 101,
                acknowledgment: sequence.wrapping_add(1),
                flags: ntcp::wire::ACK,
                window: 32792,
                urgent_pointer: 0,
            },
            &[],
            &[],
            &mut tcp,
        )
        .unwrap();
        let ack = ip_packet(
            &a,
            ntcp::Transmit {
                tx_timestamp: None,
                connection: None,
                ip: incoming,
                len: size,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: Default::default(),
                mark: 0,
            },
            &tcp[..size],
        );
        tfo_deliver(&mut a, ack);
        if hard {
            let reset = tfo_capture(&mut a);
            assert_eq!(segment(&reset).header.flags, ntcp::wire::RST);
            assert_eq!(segment(&reset).header.sequence, sequence.wrapping_add(1));
            assert_eq!(
                a.execute(listener, Op::Accept(SOCK_NONBLOCK)).unwrap_err(),
                EAGAIN
            );
        } else {
            assert_eq!(a.endpoint.state(child).unwrap(), State::Established);
            let accepted = a
                .execute(listener, Op::Accept(SOCK_NONBLOCK))
                .unwrap()
                .value as u64;
            assert_eq!(cid(&a, accepted), child);
            let readable = a.endpoint.readable_bytes(child).unwrap();
            a.service_egress().unwrap();
            let mut responses = Vec::new();
            while let Ok(packet) = a.execute(0, Op::Capture(65535)) {
                let header = segment(&packet.bytes).header;
                assert_eq!(header.flags & ntcp::wire::RST, 0);
                responses.push((header.flags, header.acknowledgment));
            }
            eprintln!(
                "ICMP_SYNRECV_CONTINUATION mode={mode} readable={readable} responses={responses:?}"
            );
            assert_eq!(a.execute(accepted, Op::Read(10)).unwrap().bytes, [0x42; 10]);
        }
        eprintln!(
            "ICMP_SYNRECV mode={mode} code=1 decoded=true before=SynReceived after_error={} after_late_ack={} wrong_tuple_rejected=true wrong_sequence_rejected=true",
            if hard { "Removed" } else { "SynReceived" },
            if hard { "RST" } else { "Established" }
        );
    }
}
