// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

fn local_repair_packet(
    a: &mut Owner,
    at: u64,
    ack: u32,
    syn: bool,
    blocks: &[(u32, u32)],
    payload: &[u8],
) -> Vec<u8> {
    local_repair_packet_seq(a, at, ack, syn, blocks, payload, 1)
}

fn local_repair_packet_seq(
    a: &mut Owner,
    at: u64,
    ack: u32,
    syn: bool,
    blocks: &[(u32, u32)],
    payload: &[u8],
    sequence: u32,
) -> Vec<u8> {
    a.test_now = Some(at);
    let metadata = ntcp::IpMetadata {
        source: "10.73.0.3".parse().unwrap(),
        destination: "10.73.0.2".parse().unwrap(),
    };
    let mut options = if syn {
        vec![2, 4, 3, 232, 4, 2, 1, 1, 1, 3, 3, 7]
    } else {
        vec![]
    };
    if !blocks.is_empty() {
        options.extend_from_slice(&[1, 1, 5, (2 + 8 * blocks.len()) as u8]);
        for (lo, hi) in blocks {
            options.extend_from_slice(&lo.to_be_bytes());
            options.extend_from_slice(&hi.to_be_bytes());
        }
    }
    let mut tcp = vec![0; 60 + payload.len()];
    let n = ntcp::wire::encode(
        metadata,
        ntcp::wire::Header {
            source_port: 2000,
            destination_port: 1000,
            sequence: if syn { 0 } else { sequence },
            acknowledgment: ack,
            flags: if syn {
                ntcp::wire::SYN
            } else {
                ntcp::wire::ACK
            },
            window: if syn { 32792 } else { 320 },
            urgent_pointer: 0,
        },
        &options,
        payload,
        &mut tcp,
    )
    .unwrap();
    let mut packet = vec![0; 20 + n];
    packet[20..].copy_from_slice(&tcp[..n]);
    ntcp_ip::encode(
        &mut packet,
        ntcp::Transmit {
            connection: None,
            tx_timestamp: None,
            ipv4_options: Default::default(),
            ecn: 0,
            ip: metadata,
            len: n,
            hop_limit: 64,
            dscp: 0,
        },
        0,
    )
    .unwrap();
    packet
}

#[test]
fn local_repair_certified_rejection_yields_to_ingress_and_retries_without_false_stats() {
    let local = Ipv4Addr::new(10, 73, 0, 2);
    let config =
        crate::packet_profile::config(crate::packet_profile::Profile::Upstream(Default::default()));
    let mut a = Owner::with_config(local, (local, 24), [2; 32], None, config).unwrap();
    a.test_now = Some(0);
    let state = attach(&mut a, 0);
    a.enable_egress(2, None).unwrap();
    let listener = new(&mut a, SOCK_NONBLOCK);
    a.execute(listener, Op::Bind("10.73.0.2:1000".parse().unwrap()))
        .unwrap();
    a.execute(listener, Op::Listen(1)).unwrap();
    let p = local_repair_packet(&mut a, 0, 0, true, &[], &[]);
    ingress(&mut a, &state, &p);
    a.service_egress().unwrap();
    let frame = state.lock().unwrap().sent.pop_front().unwrap();
    let eth = ntcp_ethernet::parse_ethernet(&frame).unwrap();
    let p = ntcp_ip::parse(eth.payload, false).unwrap();
    let base = ntcp::wire::parse(p.ip, p.payload)
        .unwrap()
        .header
        .sequence
        .wrapping_add(1);
    let p = local_repair_packet(&mut a, 20_000, base, false, &[], &[]);
    ingress(&mut a, &state, &p);
    let socket = a
        .execute(listener, Op::Accept(SOCK_NONBLOCK))
        .unwrap()
        .value as u64;
    let id = connection(&a, socket);
    a.execute(socket, Op::Write(vec![7; 10_000])).unwrap();
    a.service_egress().unwrap();
    assert_eq!(state.lock().unwrap().sent.len(), 10);
    state.lock().unwrap().sent.clear();
    for blocks in [
        &[(9000u32, 10000u32)][..],
        &[(3000u32, 4000u32), (9000, 10000)][..],
    ] {
        let blocks: Vec<_> = blocks
            .iter()
            .map(|(l, r)| (base.wrapping_add(*l), base.wrapping_add(*r)))
            .collect();
        let p = local_repair_packet(&mut a, 40_000, base, false, &blocks, &[]);
        ingress(&mut a, &state, &p);
    }
    let p = local_repair_packet(&mut a, 40_000, base.wrapping_add(10000), false, &[], &[]);
    ingress(&mut a, &state, &p);
    a.test_now = Some(65_000);
    a.execute(socket, Op::Write(vec![8; 2000])).unwrap();
    a.service_egress().unwrap();
    assert_eq!(state.lock().unwrap().sent.len(), 2);
    state.lock().unwrap().sent.clear();
    let p = local_repair_packet(
        &mut a,
        85_000,
        base.wrapping_add(10000),
        false,
        &[(base.wrapping_add(11000), base.wrapping_add(12000))],
        &[],
    );
    ingress(&mut a, &state, &p);
    a.test_now = Some(90_000);
    a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
    state.lock().unwrap().reject = true;
    let calls = state.lock().unwrap().output_calls;
    a.service_egress().unwrap();
    assert_eq!(state.lock().unwrap().output_calls, calls + 1);
    assert!(state.lock().unwrap().sent.is_empty());
    assert!(!a.endpoint.is_output_reserved(id));
    let info = a.execute(socket, Op::Transport(1)).unwrap().bytes;
    assert_eq!(u32::from_ne_bytes(info[36..40].try_into().unwrap()), 0);
    assert_eq!(a.endpoint.transport_info(id).unwrap().retransmitted, 0);
    assert!(a.output_wait() > std::time::Duration::ZERO);
    let p = local_repair_packet(
        &mut a,
        95_000,
        base.wrapping_add(10000),
        false,
        &[(base.wrapping_add(11000), base.wrapping_add(12000))],
        &[9; 1000],
    );
    ingress(&mut a, &state, &p);
    assert_eq!(
        a.execute(socket, Op::Read(1000)).unwrap().bytes,
        vec![9; 1000]
    );
    let calls = state.lock().unwrap().output_calls;
    a.service_egress().unwrap(); // This ACK-carrying retry is rejected too.
    assert_eq!(state.lock().unwrap().output_calls, calls + 1);
    assert!(!a.endpoint.is_output_reserved(id));
    assert_eq!(a.endpoint.transport_info(id).unwrap().retransmitted, 0);
    let p = local_repair_packet_seq(
        &mut a,
        95_500,
        base.wrapping_add(10000),
        false,
        &[(base.wrapping_add(11000), base.wrapping_add(12000))],
        &[6; 1000],
        1001,
    );
    ingress(&mut a, &state, &p);
    assert_eq!(
        a.execute(socket, Op::Read(1000)).unwrap().bytes,
        vec![6; 1000]
    );
    state.lock().unwrap().reject = false;
    a.test_now = Some(96_000);
    a.service_egress().unwrap();
    assert!(!state.lock().unwrap().sent.is_empty());
    assert_eq!(a.endpoint.transport_info(id).unwrap().retransmitted, 1);
    assert!(!a.endpoint.is_output_reserved(id));
    assert!(a.endpoint.transport_info(id).unwrap().recovery);
}

#[test]
fn resource_study_fresh_rejection_and_backpressure_keep_backend_deadline_policy() {
    let mut traces = Vec::new();
    for rejected in [false, true] {
        for io_timeout in [1_000_000, 4_000_000] {
            let (mut a, _, socket, _, state) = pmtud_pair(None);
            let cid = connection(&a, socket);
            a.test_now = Some(200_000);
            a.execute(socket, Op::Set(IPPROTO_TCP, TCP_USER_TIMEOUT, 3000))
                .unwrap();
            assert_eq!(
                a.endpoint.application_timeout(cid).unwrap(),
                Some(3_000_000)
            );
            a.enable_egress(2, None).unwrap();
            a.reservation_timeout_us = io_timeout;
            {
                let mut io = state.lock().unwrap();
                io.sent.clear();
                io.reject = rejected;
                io.block = !rejected;
            }
            assert_eq!(a.execute(socket, Op::Write(vec![7; 24])).unwrap().value, 24);
            a.service_egress().unwrap();
            assert!(a.endpoint.is_output_reserved(cid));
            assert!(state.lock().unwrap().sent.is_empty());
            let began = a.now();
            let mut closed = false;
            for elapsed in [
                0, 1000, 500_000, 999_999, 1_000_000, 2_999_999, 3_000_000, 3_250_000, 3_350_000,
                3_999_999, 4_000_000,
            ] {
                if closed {
                    break;
                }
                a.test_now = Some(began + elapsed);
                a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
                a.expire_egress(a.now()).unwrap();
                a.events();
                let info = a.endpoint.transport_info(cid).unwrap();
                let reserved = a.endpoint.is_output_reserved(cid);
                let write_held = a.command_held(socket, &Op::Write(vec![9; 24]));
                let error = a.sockets[&socket].error;
                let io = state.lock().unwrap();
                traces.push(format!("{{\"certified_rejection\":{rejected},\"backend_timeout_us\":{io_timeout},\"elapsed_us\":{elapsed},\"state\":\"{:?}\",\"reserved\":{reserved},\"write_held\":{write_held},\"socket_error\":{error},\"output_calls\":{},\"submitted_packets\":{}}}", info.state, io.output_calls, io.sent.len()));
                assert!(io.sent.is_empty());
                drop(io);
                if elapsed < io_timeout {
                    assert_eq!(info.state, ntcp::State::Established);
                    assert!(reserved && write_held);
                    assert_eq!(error, 0);
                    a.service_egress().unwrap();
                } else {
                    assert_eq!(info.state, ntcp::State::Closed);
                    assert!(!reserved && !write_held);
                    assert_eq!(error, ECONNABORTED);
                    closed = true;
                }
            }
            assert!(closed);
        }
    }
    if let Some(directory) = std::env::var_os("NTCP_RESOURCE_STUDY_OUT") {
        let path = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("trace.jsonl"), traces.join("\n") + "\n").unwrap();
    }
}
