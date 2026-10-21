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

fn local_repair_snapshot(a: &Owner, id: ntcp::ConnectionId, at: u64, event: &str) -> String {
    let i = a.endpoint.transport_info(id).unwrap();
    format!(
        "{{\"event\":\"{event}\",\"at_us\":{at},\"cwnd_bytes\":{},\"ssthresh_bytes\":{},\"unacked\":{},\"sacked\":{},\"lost\":{},\"retransmitted\":{},\"delivered\":{},\"reordering\":{},\"recovery\":{},\"reserved\":{}}}",
        i.cwnd,
        i.ssthresh,
        i.unacked,
        i.sacked,
        i.lost,
        i.retransmitted,
        i.delivered_segments,
        i.reordering,
        i.recovery,
        a.endpoint.is_output_reserved(id)
    )
}

#[test]
fn local_repair_certified_rejection_yields_to_ingress_and_retries_without_false_stats() {
    let mut trace = Vec::new();
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
    trace.push(local_repair_snapshot(
        &a,
        id,
        40_000,
        "prefix_cumulative_ack",
    ));
    assert_eq!(a.endpoint.transport_info(id).unwrap().cwnd, 18_000);
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
    trace.push(local_repair_snapshot(&a, id, 90_000, "rack_timer_entry"));
    let before_rejection = a.endpoint.transport_info(id).unwrap();
    assert_eq!(
        (before_rejection.cwnd, before_rejection.ssthresh),
        (1000, 2000)
    );
    state.lock().unwrap().reject = true;
    let calls = state.lock().unwrap().output_calls;
    a.service_egress().unwrap();
    assert_eq!(state.lock().unwrap().output_calls, calls + 1);
    assert!(state.lock().unwrap().sent.is_empty());
    assert!(!a.endpoint.is_output_reserved(id));
    let info = a.execute(socket, Op::Transport(1)).unwrap().bytes;
    assert_eq!(u32::from_ne_bytes(info[36..40].try_into().unwrap()), 0);
    assert_eq!(&info[148..152], &20_000u32.to_ne_bytes());
    assert_eq!(&info[220..224], &2u32.to_ne_bytes());
    assert_eq!(a.endpoint.transport_info(id).unwrap().retransmitted, 0);
    trace.push(local_repair_snapshot(
        &a,
        id,
        90_000,
        "repair_locally_rejected",
    ));
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
    trace.push(local_repair_snapshot(
        &a,
        id,
        95_000,
        "data_with_repeated_sack",
    ));
    let after_input = a.endpoint.transport_info(id).unwrap();
    assert_eq!(
        after_input.delivered_segments,
        before_rejection.delivered_segments
    );
    assert_eq!(after_input.cwnd, before_rejection.cwnd);
    let metrics = a.execute(socket, Op::Transport(1)).unwrap().bytes;
    assert_eq!(&metrics[148..152], &20_000u32.to_ne_bytes());
    assert_eq!(&metrics[220..224], &2u32.to_ne_bytes());
    assert_eq!(
        (after_input.unacked, after_input.sacked, after_input.lost),
        (2, 1, 1)
    );
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
    trace.push(local_repair_snapshot(
        &a,
        id,
        96_000,
        "repair_physically_accepted",
    ));
    if let Ok(directory) = std::env::var("NTCP_LOCAL_REPAIR_RECHECK_DIR") {
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            format!("{directory}/owner-trace.json"),
            format!("[\n{}\n]\n", trace.join(",\n")),
        )
        .unwrap();
    }
}

#[test]
fn fresh_resource_rejection_retries_without_holding_writes_or_network_backoff() {
    for io_timeout in [1_000_000, 4_000_000] {
        let (mut a, _, socket, _, state) = pmtud_pair(None);
        let cid = connection(&a, socket);
        a.test_now = Some(200_000);
        a.execute(socket, Op::Set(IPPROTO_TCP, TCP_USER_TIMEOUT, 3000))
            .unwrap();
        a.enable_egress(2, None).unwrap();
        a.reservation_timeout_us = io_timeout;
        state.lock().unwrap().reject = true;
        state.lock().unwrap().sent.clear();
        let initial_calls = state.lock().unwrap().output_calls;
        assert_eq!(a.execute(socket, Op::Write(vec![7; 24])).unwrap().value, 24);
        a.service_egress().unwrap();
        assert!(!a.endpoint.is_output_reserved(cid));
        assert!(!a.command_held(socket, &Op::Write(vec![9; 24])));
        let info = a.endpoint.transport_info(cid).unwrap();
        assert_eq!(info.unacked, 0);
        assert_eq!(info.notsent_bytes, 24);
        assert_eq!(info.resource_probes, 0);
        let mut observed = Vec::new();
        let mut appended = false;
        let mut closed = false;
        for _ in 0..32 {
            let at = a.endpoint.next_deadline().unwrap();
            a.test_now = Some(at);
            a.endpoint.on_timeout(at, BUDGET).unwrap();
            a.expire_egress(at).unwrap();
            a.events();
            if a.endpoint.state(cid).unwrap() == ntcp::State::Closed {
                closed = true;
                break;
            }
            let count = a.endpoint.transport_info(cid).unwrap().resource_probes;
            if observed.last().is_none_or(|&(_, prior)| prior != count) && count != 0 {
                observed.push((at, count));
            }
            a.service_egress().unwrap();
            assert_eq!(
                state.lock().unwrap().output_calls - initial_calls,
                count as usize + 1
            );
            assert!(!a.endpoint.is_output_reserved(cid));
            if count != 0 && !appended {
                assert_eq!(a.execute(socket, Op::Write(vec![9; 24])).unwrap().value, 24);
                appended = true;
            }
            assert!(state.lock().unwrap().sent.is_empty());
            let info = a.endpoint.transport_info(cid).unwrap();
            assert_eq!(info.unacked, 0);
            assert_eq!(info.rto_backoff, 0);
            assert_eq!(info.retransmitted, 0);
        }
        assert!(closed);
        assert_eq!(observed.len(), 6, "{observed:?}");
        for (index, &(at, count)) in observed.iter().enumerate() {
            assert_eq!(count, index as u32 + 1);
            assert_eq!(at, observed[0].0 + index as u64 * 500_000);
        }
        assert_eq!(a.now(), observed[0].0 + 3_000_000);
        assert_eq!(a.sockets[&socket].error, ETIMEDOUT);
        let info = a.endpoint.transport_info(cid).unwrap();
        assert_eq!(info.resource_probes, 6);
        assert_eq!(state.lock().unwrap().output_calls - initial_calls, 7);
        assert_eq!(info.rto_backoff, 0);
        assert!(state.lock().unwrap().sent.is_empty());
        assert_eq!(
            a.execute(socket, Op::Write(vec![9; 24])).err(),
            Some(ETIMEDOUT)
        );
    }
}

#[test]
fn held_backend_output_obeys_earliest_application_or_io_deadline() {
    for io_timeout in [1_000_000, 3_000_000, 4_000_000] {
        let (mut a, _, socket, _, state) = pmtud_pair(None);
        let cid = connection(&a, socket);
        a.test_now = Some(200_000);
        a.execute(socket, Op::Set(IPPROTO_TCP, TCP_USER_TIMEOUT, 3000))
            .unwrap();
        a.enable_egress(2, None).unwrap();
        a.reservation_timeout_us = io_timeout;
        state.lock().unwrap().block = true;
        state.lock().unwrap().sent.clear();
        a.execute(socket, Op::Write(vec![7; 24])).unwrap();
        a.service_egress().unwrap();
        assert!(a.endpoint.is_output_reserved(cid));
        let expiry = a.now() + io_timeout.min(3_000_000);
        a.test_now = Some(expiry - 1);
        a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
        a.expire_egress(a.now()).unwrap();
        assert_eq!(a.endpoint.state(cid).unwrap(), ntcp::State::Established);
        a.test_now = Some(expiry);
        a.expire_egress(expiry).unwrap();
        a.events();
        assert_eq!(a.endpoint.state(cid).unwrap(), ntcp::State::Closed);
        assert!(!a.endpoint.is_output_reserved(cid));
        assert_eq!(
            a.sockets[&socket].error,
            if io_timeout < 3_000_000 {
                ECONNABORTED
            } else {
                ETIMEDOUT
            }
        );
        assert_eq!(a.endpoint.transport_info(cid).unwrap().resource_probes, 0);
    }
}

#[test]
fn fresh_resource_retry_resumes_once_with_all_queued_data() {
    let (mut a, _, socket, _, state) = pmtud_pair(None);
    let cid = connection(&a, socket);
    a.test_now = Some(200_000);
    a.execute(socket, Op::Set(IPPROTO_TCP, TCP_USER_TIMEOUT, 3000))
        .unwrap();
    a.enable_egress(2, None).unwrap();
    state.lock().unwrap().reject = true;
    state.lock().unwrap().sent.clear();
    a.execute(socket, Op::Write(vec![7; 24])).unwrap();
    a.service_egress().unwrap();
    for _ in 0..8 {
        let at = a.endpoint.next_deadline().unwrap();
        a.test_now = Some(at);
        a.endpoint.on_timeout(at, BUDGET).unwrap();
        a.service_egress().unwrap();
        if a.endpoint.transport_info(cid).unwrap().resource_probes == 1 {
            break;
        }
    }
    assert_eq!(a.endpoint.transport_info(cid).unwrap().resource_probes, 1);
    a.execute(socket, Op::Write(vec![9; 24])).unwrap();
    state.lock().unwrap().reject = false;
    for _ in 0..8 {
        let at = a.endpoint.next_deadline().unwrap();
        a.test_now = Some(at);
        a.endpoint.on_timeout(at, BUDGET).unwrap();
        a.service_egress().unwrap();
        if !state.lock().unwrap().sent.is_empty() {
            break;
        }
    }
    let io = state.lock().unwrap();
    assert_eq!(io.sent.len(), 1);
    let eth = ntcp_ethernet::parse_ethernet(io.sent.front().unwrap()).unwrap();
    let ip = ntcp_ip::parse(eth.payload, false).unwrap();
    let segment = ntcp::wire::parse(ip.ip, ip.payload).unwrap();
    assert_eq!(segment.payload, [&[7u8; 24][..], &[9u8; 24][..]].concat());
    drop(io);
    let info = a.endpoint.transport_info(cid).unwrap();
    assert_eq!(info.resource_probes, 2);
    assert_eq!(info.rto_backoff, 0);
    assert_eq!(info.notsent_bytes, 0);
    assert_eq!(info.unacked, 1);
    assert!(!a.endpoint.is_output_reserved(cid));
}
