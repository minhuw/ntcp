// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;
use ntcp::wire::{self, ACK, PSH, SYN};

fn established(
    global: bool,
) -> (
    Owner,
    u64,
    ntcp::ConnectionId,
    ntcp::IpMetadata,
    wire::Header,
    u32,
) {
    established_with_window(global, 32792, 257)
}

fn established_with_window(
    global: bool,
    syn_window: u16,
    ack_window: u16,
) -> (
    Owner,
    u64,
    ntcp::ConnectionId,
    ntcp::IpMetadata,
    wire::Header,
    u32,
) {
    let settings = crate::packet_profile::profile("upstream,local=192.168.0.1").unwrap();
    let mut a = Owner::packet(settings).unwrap();
    a.test_now = Some(0);
    if global {
        a.socket_policy.notsent_lowat = 4000;
    }
    let listener = new(&mut a, SOCK_NONBLOCK);
    a.execute(listener, Op::Bind("192.168.0.1:8080".parse().unwrap()))
        .unwrap();
    a.execute(listener, Op::Listen(1)).unwrap();
    let ip = ntcp::IpMetadata {
        source: "192.0.2.1".parse().unwrap(),
        destination: "192.168.0.1".parse().unwrap(),
    };
    let mut incoming = wire::Header {
        source_port: 40000,
        destination_port: 8080,
        sequence: 0,
        acknowledgment: 0,
        flags: SYN,
        window: syn_window,
        urgent_pointer: 0,
    };
    let mut bytes = [0; 2048];
    let n = wire::encode(
        ip,
        incoming,
        &[2, 4, 3, 232, 4, 2, 1, 1, 1, 3, 3, 7],
        &[],
        &mut bytes,
    )
    .unwrap();
    a.input(0, ip, 0, &bytes[..n]).unwrap();
    a.events();
    let tx = a
        .endpoint
        .poll_transmit(0, &mut bytes, BUDGET)
        .unwrap()
        .packet
        .unwrap();
    let synack = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
    let iss = synack.header.sequence;
    incoming.sequence = 1;
    incoming.acknowledgment = iss.wrapping_add(1);
    incoming.flags = ACK;
    incoming.window = ack_window;
    let n = wire::encode(ip, incoming, &[], &[], &mut bytes).unwrap();
    a.test_now = Some(10000);
    a.input(10000, ip, 0, &bytes[..n]).unwrap();
    a.events();
    let child = a
        .execute(listener, Op::Accept(SOCK_NONBLOCK))
        .unwrap()
        .value as u64;
    if !global {
        a.execute(child, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, 4000))
            .unwrap();
    }
    assert_eq!(
        a.execute(child, Op::Get(IPPROTO_TCP, TCP_NOTSENT_LOWAT))
            .unwrap()
            .value,
        if global { 0 } else { 4000 }
    );
    let Handle::Connection(cid) = a.sockets[&child].handle else {
        unreachable!()
    };
    assert_eq!(a.endpoint.transport_info(cid).unwrap().cwnd, 10000);
    (a, child, cid, ip, incoming, iss)
}

fn drain(a: &mut Owner, now: u64, iss: u32) -> Vec<(u32, usize, bool)> {
    let mut result = Vec::new();
    let mut bytes = [0; 2048];
    for _ in 0..64 {
        let Some(tx) = a
            .endpoint
            .poll_transmit(now, &mut bytes, BUDGET)
            .unwrap()
            .packet
        else {
            a.events();
            return result;
        };
        let segment = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
        if !segment.payload.is_empty() {
            result.push((
                segment.header.sequence.wrapping_sub(iss),
                segment.payload.len(),
                segment.header.flags & PSH != 0,
            ));
        }
    }
    panic!("output did not quiesce");
}

fn save(name: &str, rows: &[String]) {
    if let Ok(directory) = std::env::var("NTCP_LOWAT_STUDY_DIR") {
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            format!("{directory}/{name}.json"),
            format!("[{}]\n", rows.join(",")),
        )
        .unwrap();
    }
}

fn nonblocking_request(id: u64, op: Op) -> (Request, Receiver<Result<Reply>>) {
    let (reply, rx) = mpsc::sync_channel(1);
    (
        Request {
            id,
            op,
            reply,
            deadline: None,
            send: None,
            closing: None,
        },
        rx,
    )
}

#[test]
fn upstream_lowat_batched_nonblocking_send_and_ack_timeline() {
    for global in [false, true] {
        let (mut a, child, cid, ip, mut incoming, iss) = established(global);
        let bytes = vec![0x55; 59000];
        let (mut request, rx) = nonblocking_request(
            child,
            Op::Send(vec![(bytes.as_ptr() as usize, bytes.len())], 0),
        );
        assert!(!a.service(&mut request));
        assert_eq!(request.send.as_ref().unwrap().accepted, 16000);
        let first = drain(&mut a, 10000, iss);
        assert_eq!(first.iter().map(|s| s.1).sum::<usize>(), 10000);
        assert!(first.last().unwrap().2);
        assert!(!a.service(&mut request));
        assert_eq!(request.send.as_ref().unwrap().accepted, 26000);
        assert!(drain(&mut a, 10000, iss).is_empty());
        assert!(a.service(&mut request));
        assert_eq!(rx.recv().unwrap().unwrap().value, 26000);
        assert_eq!(a.execute(child, Op::Ready).unwrap().value & EPOLLOUT, 0);
        assert_eq!(a.execute(child, Op::Write(vec![1])).unwrap_err(), EAGAIN);
        let mut last_end = 10001;
        for (stage, now, ack, unsent, cwnd) in [
            (1, 20000, 2000, 12000, 12000),
            (2, 30000, 4000, 8000, 14000),
            (3, 40000, 6000, 4000, 16000),
            (4, 50000, 8000, 0, 18000),
        ] {
            a.test_now = Some(now);
            incoming.acknowledgment = iss.wrapping_add(1 + ack);
            let mut bytes = [0; 2048];
            let n = wire::encode(ip, incoming, &[], &[], &mut bytes).unwrap();
            a.input(now, ip, 0, &bytes[..n]).unwrap();
            a.events();
            let packets = drain(&mut a, now, iss);
            assert_eq!(packets.iter().map(|p| p.1).sum::<usize>(), 4000);
            assert!(packets.last().unwrap().2);
            for &(seq, len, _) in &packets {
                assert_eq!(seq, last_end);
                last_end += len as u32;
            }
            let info = a.endpoint.transport_info(cid).unwrap();
            assert_eq!((info.notsent_bytes, info.cwnd), (unsent, cwnd));
            assert_eq!(
                a.execute(child, Op::Ready).unwrap().value & EPOLLOUT != 0,
                stage == 4
            );
        }
        assert_eq!(last_end, 26001);
    }
}

#[test]
fn lowat_partial_tail_option_changes_eor_and_bounded_producer() {
    let (mut a, child, cid, _, _, _) = established(false);
    assert_eq!(
        a.execute(child, Op::WriteFlags(vec![1; 1000], MSG_MORE))
            .unwrap()
            .value,
        1000
    );
    assert_eq!(
        a.execute(child, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, 1))
            .unwrap()
            .value,
        0
    );
    // A lower threshold does not discard the existing coalescible tail.
    assert_eq!(
        a.timestamp_write_from(child, cid, 20000, MSG_MORE, 0, |room| {
            assert_eq!(room, 15000);
            Ok(vec![2; room])
        })
        .unwrap(),
        15000
    );
    assert_eq!(
        a.timestamp_write_from::<Vec<u8>>(child, cid, 1, 0, 0, |_| panic!(
            "full batch consumed producer"
        ))
        .unwrap_err(),
        EAGAIN
    );
    a.execute(child, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, -1))
        .unwrap();
    assert_eq!(
        a.execute(child, Op::WriteFlags(vec![3; 100], MSG_EOR))
            .unwrap()
            .value,
        100
    );
    assert!(a.sockets[&child].send_batch.is_none());
    a.execute(child, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, 1))
        .unwrap();
    assert_eq!(a.execute(child, Op::Write(vec![4])).unwrap_err(), EAGAIN);
}

#[test]
fn lowat_nonblocking_fault_after_accepted_batch_finalizes_one_logical_completion() {
    let (mut a, child, cid, _, _, iss) = established(false);
    a.execute(child, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    timestamp_set(
        &mut a,
        child,
        ts::TX_SCHED
            | ts::TX_SOFTWARE
            | ts::SOFTWARE
            | ts::OPT_TSONLY
            | ts::OPT_ID
            | ts::OPT_ID_TCP,
    );
    let bytes = vec![7; 16000];
    let (mut request, rx) = nonblocking_request(
        child,
        Op::Send(
            vec![(bytes.as_ptr() as usize, bytes.len()), (0, 10000)],
            MSG_ZEROCOPY,
        ),
    );
    assert!(!a.service(&mut request));
    let packets = drain(&mut a, 10000, iss);
    assert_eq!(packets.iter().map(|p| p.1).sum::<usize>(), 10000);
    assert!(a.service(&mut request));
    assert_eq!(rx.recv().unwrap().unwrap().value, 16000);
    assert_eq!(a.endpoint.transport_info(cid).unwrap().send_used, 16000);
    assert_eq!(a.sockets[&child].zc_next, 1);
    assert_eq!(a.sockets[&child].zc_reserved, 0);
    assert_eq!(
        a.sockets[&child]
            .completions
            .iter()
            .filter_map(Completion::range)
            .collect::<Vec<_>>(),
        [(0, 0)]
    );
    assert_eq!(a.sockets[&child].timestamps.reserved(), 2);
}

#[test]
fn upstream_lowat_counterfactual_26k_ack_and_readiness_timeline() {
    let mut rows = Vec::new();
    for global in [false, true] {
        let (mut a, child, cid, ip, mut incoming, iss) = established(global);
        // Diagnostic only: bypass the lowat admission gate for this one prefix.
        // The socket's actual lowat/readiness policy remains4000 throughout.
        assert_eq!(a.endpoint.write(cid, &vec![0x55; 26000]).unwrap(), 26000);
        let mut last_end = 1;
        for (stage, now, ack, expected_sent, expected_unsent, expected_cwnd) in [
            (0, 10000, 0, 10000, 16000, 10000),
            (1, 20000, 2000, 4000, 12000, 12000),
            (2, 30000, 4000, 4000, 8000, 14000),
            (3, 40000, 6000, 4000, 4000, 16000),
            (4, 50000, 8000, 4000, 0, 18000),
        ] {
            a.test_now = Some(now);
            if ack != 0 {
                incoming.acknowledgment = iss.wrapping_add(1 + ack);
                let mut bytes = [0; 2048];
                let n = wire::encode(ip, incoming, &[], &[], &mut bytes).unwrap();
                a.input(now, ip, 0, &bytes[..n]).unwrap();
                a.events();
            }
            let packets = drain(&mut a, now, iss);
            assert_eq!(packets.iter().map(|p| p.1).sum::<usize>(), expected_sent);
            assert!(packets.last().unwrap().2);
            for &(seq, len, _) in &packets {
                assert_eq!(seq, last_end);
                last_end += len as u32;
            }
            let info = a.endpoint.transport_info(cid).unwrap();
            assert_eq!(info.notsent_bytes, expected_unsent);
            assert_eq!(info.cwnd, expected_cwnd);
            let ready = a.execute(child, Op::Ready).unwrap().value & EPOLLOUT != 0;
            assert_eq!(ready, stage == 4);
            rows.push(format!("{{\"global_default\":{global},\"counterfactual_admission\":26000,\"stage\":{stage},\"now_us\":{now},\"acknowledged_payload\":{ack},\"sent_this_stage\":{expected_sent},\"highest_data_end\":{last_end},\"notsent\":{expected_unsent},\"cwnd\":{expected_cwnd},\"pollout\":{ready},\"terminal_psh\":true}}"));
        }
        assert_eq!(last_end, 26001);
    }
    save("counterfactual-timeline", &rows);
}

#[test]
fn upstream_lowat_half_threshold_and_write_admission_are_distinct() {
    let mut rows = Vec::new();
    for global in [false, true] {
        for queued in [11999, 12000, 13999, 14000] {
            let (mut a, child, cid, _, _, iss) = established(global);
            assert_eq!(a.endpoint.write(cid, &vec![0x55; queued]).unwrap(), queued);
            let packets = drain(&mut a, 10000, iss);
            assert_eq!(packets.iter().map(|p| p.1).sum::<usize>(), 10000);
            let unsent = a.endpoint.transport_info(cid).unwrap().notsent_bytes;
            assert_eq!(unsent, queued - 10000);
            let ready = a.execute(child, Op::Ready).unwrap().value & EPOLLOUT != 0;
            assert_eq!(ready, unsent < 2000);
            let room = a.endpoint.send_admission_room(cid, Some(4000)).unwrap();
            assert_eq!(room, 4000usize.saturating_sub(unsent));
            rows.push(format!("{{\"global_default\":{global},\"counterfactual_queued\":{queued},\"notsent\":{unsent},\"pollout\":{ready},\"write_admission_room\":{room}}}"));
        }
    }
    save("thresholds", &rows);
}

#[test]
fn lowat_batch_goal_tracks_window_without_magic_admission_count() {
    let (mut a, child, cid, _, _, iss) = established_with_window(false, 16000, 125);
    assert_eq!(
        send::batch_goal(&a.endpoint.transport_info(cid).unwrap()),
        8000
    );
    let bytes = vec![7; 59000];
    let (mut request, rx) = nonblocking_request(
        child,
        Op::Send(vec![(bytes.as_ptr() as usize, bytes.len())], 0),
    );
    let mut sent = 0;
    for _ in 0..8 {
        if a.service(&mut request) {
            break;
        }
        sent += drain(&mut a, 10000, iss).iter().map(|p| p.1).sum::<usize>();
    }
    assert_eq!(rx.try_recv().unwrap().unwrap().value, 18000);
    assert_eq!(sent, 10000);
    assert_eq!(a.endpoint.transport_info(cid).unwrap().notsent_bytes, 8000);
}

#[test]
fn lowat_nonblocking_held_output_returns_prefix_then_finalizes_boundary() {
    let (mut a, child, cid, _, _, _) = established(false);
    let bytes = vec![7; 59000];
    let (mut request, rx) = nonblocking_request(
        child,
        Op::Send(vec![(bytes.as_ptr() as usize, bytes.len())], MSG_EOR),
    );
    assert!(!a.service(&mut request));
    let mut output = [0; 2048];
    let (poll, token) = a
        .endpoint
        .poll_reserved_transmit(10000, &mut output, BUDGET)
        .unwrap();
    assert!(poll.packet.is_some());
    let retained = output;
    let progress = a.endpoint.send_progress(cid).unwrap();
    assert!(a.service(&mut request));
    assert_eq!(rx.try_recv().unwrap().unwrap().value, 16000);
    assert_eq!(a.endpoint.send_progress(cid).unwrap(), progress);
    assert_eq!(output, retained);
    assert!(a.sockets[&child].send_finish.is_some());
    assert!(a.sockets[&child].send_batch.is_none());
    assert!(a.endpoint.accept_transmit(10000, token.unwrap()).unwrap());
    // A real software group retains the reservation through every accepted
    // physical segment. A SEND boundary may finalize only after its suffix.
    while a.endpoint.is_output_reserved(cid) {
        let (poll, token) = a.endpoint.poll_reserved_transmit(10000, &mut output, BUDGET).unwrap();
        assert!(poll.packet.is_some());
        assert!(a.endpoint.accept_transmit(10000, token.unwrap()).unwrap());
    }
    a.events();
    assert!(a.sockets[&child].send_finish.is_none());
}
