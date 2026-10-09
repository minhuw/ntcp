// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::super::tests::{new, pair, pump};
use super::*;
use crate::timestamping as ts;
use ntcp_io::{TimestampCapabilities, TxTimestampCompletion, TxTimestampRequest};
use std::{
    io,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct State {
    mtu: Option<u32>,
    mtu_error: Option<i32>,
    mtu_queries: usize,
    max_packet_len: Option<usize>,
    layer: Option<ntcp_io::PacketLayer>,
    incoming: VecDeque<io::Result<Vec<u8>>>,
    sent: VecDeque<Vec<u8>>,
    requests: Vec<TxTimestampRequest>,
    completions: VecDeque<TxTimestampCompletion>,
    cancelled: Vec<u64>,
    calls: usize,
    output_calls: usize,
    output_error: Option<io::ErrorKind>,
    receives: usize,
    capacity: usize,
    block: bool,
    error: Option<io::ErrorKind>,
    poll_error: Option<io::ErrorKind>,
    disabled: bool,
}
struct Fixture(Arc<Mutex<State>>);
impl PacketIo for Fixture {
    fn local_ip_mtu(&self) -> io::Result<Option<u32>> {
        let mut state = self.0.lock().unwrap();
        state.mtu_queries += 1;
        if let Some(errno) = state.mtu_error {
            return Err(io::Error::from_raw_os_error(errno));
        }
        Ok(state.mtu)
    }
    fn max_packet_len(&self) -> Option<usize> {
        self.0.lock().unwrap().max_packet_len
    }
    fn layer(&self) -> ntcp_io::PacketLayer {
        self.0
            .lock()
            .unwrap()
            .layer
            .unwrap_or(ntcp_io::PacketLayer::Ethernet)
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        let mut state = self.0.lock().unwrap();
        state.receives += 1;
        let Some(packet) = state.incoming.pop_front() else {
            return Ok(None);
        };
        let packet = packet?;
        out[..packet.len()].copy_from_slice(&packet);
        Ok(Some(packet.len()))
    }
    fn transmit(&mut self, bytes: &[u8]) -> io::Result<TxOutcome> {
        let mut state = self.0.lock().unwrap();
        state.output_calls += 1;
        if let Some(error) = state.output_error {
            return Err(error.into());
        }
        if state.block {
            return Ok(TxOutcome::WouldBlock);
        }
        state.sent.push_back(bytes.to_vec());
        Ok(TxOutcome::Submitted)
    }
    fn timestamp_capabilities(&self) -> TimestampCapabilities {
        let state = self.0.lock().unwrap();
        TimestampCapabilities {
            tx_software: !state.disabled,
            tx_hardware: !state.disabled,
            tx_completion_capacity: state.capacity,
            ..Default::default()
        }
    }
    fn transmit_with_timestamp(
        &mut self,
        bytes: &[u8],
        request: TxTimestampRequest,
    ) -> io::Result<TxOutcome> {
        let mut state = self.0.lock().unwrap();
        state.calls += 1;
        if let Some(error) = state.error {
            return Err(error.into());
        }
        if state.block {
            return Ok(TxOutcome::WouldBlock);
        }
        let reserved: usize = state
            .requests
            .iter()
            .map(|r| usize::from(r.software) + usize::from(r.hardware))
            .sum();
        assert!(
            reserved + usize::from(request.software) + usize::from(request.hardware)
                <= state.capacity
        );
        assert!(!state.requests.iter().any(|r| r.cookie == request.cookie));
        state.requests.push(request);
        state.sent.push_back(bytes.to_vec());
        Ok(TxOutcome::Submitted)
    }
    fn cancel_tx_timestamp(&mut self, cookie: u64) -> io::Result<bool> {
        let mut state = self.0.lock().unwrap();
        state.cancelled.push(cookie);
        let old = state.requests.len();
        state.requests.retain(|r| r.cookie != cookie);
        state.completions.retain(|c| c.cookie != cookie);
        Ok(old != state.requests.len())
    }
    fn poll_tx_timestamp(&mut self) -> io::Result<Option<TxTimestampCompletion>> {
        let mut state = self.0.lock().unwrap();
        if let Some(error) = state.poll_error {
            return Err(error.into());
        }
        let completion = state.completions.pop_front();
        if let Some(c) = completion {
            for r in &mut state.requests {
                if r.cookie == c.cookie {
                    match c.timestamp.source {
                        TimestampSource::Software => r.software = false,
                        TimestampSource::Hardware => r.hardware = false,
                    }
                }
            }
            state.requests.retain(|r| r.software || r.hardware);
        }
        Ok(completion)
    }
}
fn attach(owner: &mut Owner, capacity: usize) -> Arc<Mutex<State>> {
    let state = Arc::new(Mutex::new(State {
        capacity,
        ..Default::default()
    }));
    owner.ethernet = Some(EthernetBackend {
        io: Box::new(Fixture(state.clone())),
        local: [2; 6],
        next_hop: [4; 6],
        next_cookie: 1,
        pending: Vec::new(),
    });
    state
}
fn flags(owner: &mut Owner, id: u64, bits: u32) {
    owner
        .execute(
            id,
            Op::Set(
                SOL_SOCKET,
                ts::OLD,
                (bits | ts::SOFTWARE | ts::RAW_HARDWARE | ts::OPT_TSONLY | ts::OPT_TX_SWHW) as i32,
            ),
        )
        .unwrap();
}
fn stage_count(owner: &Owner, id: u64, stage: u32) -> usize {
    owner.sockets[&id].completions.iter().filter(|c| matches!(c,
        Completion::Timestamp { error, .. } if u32::from_ne_bytes(error[8..12].try_into().unwrap()) == stage)).count()
}
fn prepare(owner: &mut Owner) {
    assert!(owner.pending_packet.is_none());
    let mut bytes = [0; 1480];
    let packet = owner
        .endpoint
        .poll_transmit(owner.now(), &mut bytes, BUDGET)
        .unwrap()
        .packet
        .unwrap();
    let frame = owner.frame(packet, &bytes[..packet.len]).unwrap();
    owner.timestamp_packet(packet.tx_timestamp, &frame);
    owner.drain_timestamps(ClockPair::sample(owner));
    owner.pending_packet = Some(frame);
    owner.pending_token = packet.tx_timestamp;
}
fn submit(owner: &mut Owner) {
    assert_eq!(owner.transmit_ethernet().unwrap(), TxOutcome::Submitted);
    owner.pending_packet = None;
    owner.pending_token = None;
}
fn deliver(owner: &mut Owner, peer: &mut Owner, state: &Arc<Mutex<State>>) {
    while let Some(frame) = state.lock().unwrap().sent.pop_front() {
        let ethernet = ntcp_ip::parse_ethernet(&frame).unwrap();
        let ip = ntcp_ip::parse(ethernet.payload, false).unwrap();
        peer.input(peer.now(), ip.ip, ip.traffic_class, ip.payload)
            .unwrap();
    }
    // Force the peer's delayed ACK without sleeps or a NIC.
    peer.epoch -= std::time::Duration::from_millis(250);
    peer.endpoint.on_timeout(peer.now(), BUDGET).unwrap();
    pump(peer, owner);
}
fn completion(cookie: u64, source: TimestampSource) -> TxTimestampCompletion {
    TxTimestampCompletion {
        cookie,
        timestamp: PacketTimestamp {
            value: 123,
            source,
            point: if source == TimestampSource::Software {
                TimestampPoint::KernelTransmit
            } else {
                TimestampPoint::DeviceTransmit
            },
            clock: ntcp_io::ClockDescriptor {
                domain: ClockDomain::Realtime,
                unit: TimestampUnit::Nanoseconds,
            },
        },
    }
}

#[test]
fn unsupported_receive_is_packet_local_and_budgeted() {
    let (mut a, mut b, client, server, _) = pair();
    let state = attach(&mut b, 2);
    a.execute(client, Op::Write(b"healthy".to_vec())).unwrap();
    prepare(&mut a);
    let bytes = a.pending_packet.take().unwrap();
    let mut frame = vec![0; bytes.len() + 14];
    ntcp_ip::encode_ethernet(&mut frame, [2; 6], [4; 6], ntcp_ip::ETHERTYPE_IPV4, &bytes).unwrap();
    {
        let mut state = state.lock().unwrap();
        // Models the consumed VLAN-stripped receive rejection from AF_PACKET.
        for _ in 0..BUDGET {
            state
                .incoming
                .push_back(Err(io::ErrorKind::Unsupported.into()));
        }
        state
            .incoming
            .push_back(Err(io::ErrorKind::InvalidData.into()));
        state.incoming.push_back(Ok(frame));
    }
    b.receive_batch(&mut [0; 65535]).unwrap();
    assert_eq!(state.lock().unwrap().receives, BUDGET);
    assert_eq!(b.execute(server, Op::Read(99)).unwrap_err(), EAGAIN);
    b.receive_batch(&mut [0; 65535]).unwrap();
    assert_eq!(b.execute(server, Op::Read(99)).unwrap().bytes, b"healthy");
    state
        .lock()
        .unwrap()
        .incoming
        .push_back(Err(io::ErrorKind::BrokenPipe.into()));
    assert_eq!(
        b.receive_batch(&mut [0; 65535]).unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[test]
fn missing_hardware_evicts_oldest_sources_not_tcp_or_ack_or_queued_events() {
    let (mut a, mut b, first, first_peer, listen) = pair();
    let second = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(second, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    pump(&mut a, &mut b);
    let second_peer = b.execute(listen, Op::Accept(SOCK_NONBLOCK)).unwrap().value as u64;
    let plain = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(plain, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    pump(&mut a, &mut b);
    let plain_peer = b.execute(listen, Op::Accept(SOCK_NONBLOCK)).unwrap().value as u64;
    let state = attach(&mut a, 2);
    for id in [first, second] {
        flags(
            &mut a,
            id,
            ts::TX_SCHED | ts::TX_SOFTWARE | ts::TX_HARDWARE | ts::TX_ACK,
        );
        a.execute(id, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1)).unwrap();
    }
    a.execute(first, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    a.execute(first, Op::WriteFlags(b"first".to_vec(), MSG_ZEROCOPY))
        .unwrap();
    prepare(&mut a);
    submit(&mut a);
    // Both sources occupy capacity, including a callback queued but not consumed.
    state
        .lock()
        .unwrap()
        .completions
        .push_back(completion(1, TimestampSource::Software));
    deliver(&mut a, &mut b, &state);
    assert_eq!(stage_count(&a, first, 2), 1);
    a.poll_backend_timestamps().unwrap();
    assert_eq!(stage_count(&a, first, 0), 1);
    let saved = a.sockets[&first].completions.clone();
    assert!(matches!(saved.front(), Some(Completion::ZeroCopy(..))));
    a.execute(second, Op::Write(b"second".to_vec())).unwrap();
    prepare(&mut a);
    state.lock().unwrap().block = true;
    let packet = a.pending_packet.clone();
    for _ in 0..3 {
        assert_eq!(a.transmit_ethernet().unwrap(), TxOutcome::WouldBlock);
        assert_eq!(a.pending_packet, packet);
        assert_eq!(state.lock().unwrap().cancelled, [1]);
        assert!(a.ethernet.as_ref().unwrap().pending.is_empty());
    }
    state.lock().unwrap().block = false;
    submit(&mut a); // One missing HW + two new sources > capacity: evict first HW.
    assert_eq!(state.lock().unwrap().cancelled, [1]);
    assert_eq!(a.sockets[&first].completions, saved);
    assert_eq!(a.sockets[&first].timestamps.reserved(), 0);
    deliver(&mut a, &mut b, &state);
    assert_eq!(stage_count(&a, second, 2), 1);
    // Unconsumed SW callback + absent HW still count as two, not one packet.
    state
        .lock()
        .unwrap()
        .completions
        .push_back(completion(2, TimestampSource::Software));
    a.execute(first, Op::Write(b"third".to_vec())).unwrap();
    prepare(&mut a);
    submit(&mut a);
    assert_eq!(state.lock().unwrap().cancelled, [1, 2]);
    assert!(state.lock().unwrap().completions.is_empty());
    assert_eq!(a.sockets[&second].timestamps.reserved(), 0);
    deliver(&mut a, &mut b, &state);
    let old_events = a.sockets[&first].completions.clone();
    state
        .lock()
        .unwrap()
        .completions
        .push_back(completion(1, TimestampSource::Hardware));
    a.poll_backend_timestamps().unwrap(); // Stale callback cannot resurrect cancellation.
    assert_eq!(a.sockets[&first].completions, old_events);
    a.execute(plain, Op::Write(b"plain".to_vec())).unwrap();
    prepare(&mut a);
    submit(&mut a);
    deliver(&mut a, &mut b, &state);
    assert_eq!(
        b.execute(first_peer, Op::Read(99)).unwrap().bytes,
        b"firstthird"
    );
    assert_eq!(
        b.execute(second_peer, Op::Read(99)).unwrap().bytes,
        b"second"
    );
    assert_eq!(b.execute(plain_peer, Op::Read(99)).unwrap().bytes, b"plain");
    assert_eq!(a.ethernet.as_ref().unwrap().pending.len(), 1);
}

#[test]
fn real_backpressure_retries_unchanged_without_reservation_or_duplicate() {
    let (mut a, mut b, client, server, _) = pair();
    let state = attach(&mut a, 2);
    flags(
        &mut a,
        client,
        ts::TX_SOFTWARE | ts::TX_HARDWARE | ts::TX_ACK,
    );
    a.execute(client, Op::Write(b"once".to_vec())).unwrap();
    prepare(&mut a);
    let bytes = a.pending_packet.clone();
    let token = a.pending_token;
    state.lock().unwrap().block = true;
    for _ in 0..3 {
        assert_eq!(a.transmit_ethernet().unwrap(), TxOutcome::WouldBlock);
        assert_eq!(a.pending_packet, bytes);
        assert_eq!(a.pending_token, token);
        assert_eq!(a.sockets[&client].timestamps.reserved(), 3);
        assert!(a.ethernet.as_ref().unwrap().pending.is_empty());
        assert_eq!(a.ethernet.as_ref().unwrap().next_cookie, 1);
    }
    state.lock().unwrap().block = false;
    submit(&mut a);
    assert_eq!(state.lock().unwrap().sent.len(), 1);
    assert_eq!(state.lock().unwrap().requests.len(), 1);
    deliver(&mut a, &mut b, &state);
    assert_eq!(b.execute(server, Op::Read(99)).unwrap().bytes, b"once");
}

#[test]
fn impossible_or_unsupported_metadata_falls_back_but_fatal_io_does_not() {
    for (capacity, exhausted, error) in [
        (0, false, None),
        (1, false, None),
        (2, true, None),
        (2, false, Some(io::ErrorKind::Unsupported)),
        (2, false, Some(io::ErrorKind::BrokenPipe)),
    ] {
        let (mut a, mut b, client, server, _) = pair();
        let state = attach(&mut a, capacity);
        flags(
            &mut a,
            client,
            ts::TX_SOFTWARE | ts::TX_HARDWARE | ts::TX_ACK | ts::TX_SCHED,
        );
        a.execute(client, Op::Write(b"data".to_vec())).unwrap();
        prepare(&mut a);
        if exhausted {
            a.ethernet.as_mut().unwrap().next_cookie = u64::MAX;
        }
        state.lock().unwrap().error = error;
        if error == Some(io::ErrorKind::BrokenPipe) {
            assert_eq!(
                a.transmit_ethernet().unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            assert!(state.lock().unwrap().sent.is_empty());
            assert_eq!(a.sockets[&client].timestamps.reserved(), 3);
            continue;
        }
        // Fallback itself can backpressure; only observations are cancelled once.
        state.lock().unwrap().block = true;
        assert_eq!(a.transmit_ethernet().unwrap(), TxOutcome::WouldBlock);
        assert_eq!(a.sockets[&client].timestamps.reserved(), 1); // ACK survives.
        state.lock().unwrap().block = false;
        submit(&mut a);
        assert!(state.lock().unwrap().requests.is_empty());
        assert_eq!(state.lock().unwrap().sent.len(), 1);
        deliver(&mut a, &mut b, &state);
        assert_eq!(b.execute(server, Op::Read(99)).unwrap().bytes, b"data");
        assert_eq!(stage_count(&a, client, 0), 0);
        assert_eq!(stage_count(&a, client, 1), 1);
        assert_eq!(stage_count(&a, client, 2), 1);
        assert_eq!(a.sockets[&client].timestamps.reserved(), 0);
    }
}

#[test]
fn full_phase_capacity_across_connections_never_blocks_transport() {
    let (mut a, mut b, first, first_peer, listen) = pair();
    let second = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(second, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    pump(&mut a, &mut b);
    let second_peer = b.execute(listen, Op::Accept(SOCK_NONBLOCK)).unwrap().value as u64;
    let plain = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(plain, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    pump(&mut a, &mut b);
    let plain_peer = b.execute(listen, Op::Accept(SOCK_NONBLOCK)).unwrap().value as u64;
    let state = attach(&mut a, timestamps::PHASES);
    for id in [first, second] {
        flags(&mut a, id, ts::TX_HARDWARE);
    }
    for i in 0..timestamps::PHASES + 1 {
        let (id, peer) = if i % 2 == 0 {
            (first, first_peer)
        } else {
            (second, second_peer)
        };
        a.execute(id, Op::Write(vec![i as u8])).unwrap();
        prepare(&mut a);
        submit(&mut a);
        deliver(&mut a, &mut b, &state);
        assert_eq!(b.execute(peer, Op::Read(99)).unwrap().bytes, [i as u8]);
        let Handle::Connection(cid) = a.sockets[&id].handle else {
            unreachable!()
        };
        assert_eq!(a.endpoint.transport_info(cid).unwrap().unacked, 0);
        assert!(a.ethernet.as_ref().unwrap().pending.len() <= timestamps::PHASES);
    }
    assert_eq!(state.lock().unwrap().cancelled, [1]);
    assert_eq!(
        a.ethernet.as_ref().unwrap().pending.len(),
        timestamps::PHASES
    );
    a.execute(plain, Op::Write(b"plain".to_vec())).unwrap();
    prepare(&mut a);
    submit(&mut a);
    deliver(&mut a, &mut b, &state);
    assert_eq!(b.execute(plain_peer, Op::Read(99)).unwrap().bytes, b"plain");
    assert_eq!(
        a.sockets[&first].timestamps.reserved() + a.sockets[&second].timestamps.reserved(),
        timestamps::PHASES
    );
}

#[test]
fn capability_and_poll_failures_do_not_cancel_unrelated_phases() {
    let (mut a, mut b, client, server, _) = pair();
    let state = attach(&mut a, 2);
    flags(
        &mut a,
        client,
        ts::TX_SOFTWARE | ts::TX_HARDWARE | ts::TX_ACK | ts::TX_SCHED,
    );
    a.execute(client, Op::Write(b"first".to_vec())).unwrap();
    prepare(&mut a);
    submit(&mut a);
    state.lock().unwrap().poll_error = Some(io::ErrorKind::Unsupported);
    a.poll_backend_timestamps().unwrap();
    assert_eq!(state.lock().unwrap().cancelled, [1]);
    assert_eq!(a.sockets[&client].timestamps.reserved(), 1);
    assert_eq!(stage_count(&a, client, 1), 1);
    deliver(&mut a, &mut b, &state);
    assert_eq!(stage_count(&a, client, 2), 1);
    let saved = a.sockets[&client].completions.clone();
    state.lock().unwrap().disabled = true;
    a.execute(client, Op::Write(b"second".to_vec())).unwrap();
    prepare(&mut a);
    submit(&mut a);
    assert_eq!(state.lock().unwrap().calls, 1); // Disabled capabilities bypass metadata submission.
    deliver(&mut a, &mut b, &state);
    assert_eq!(
        b.execute(server, Op::Read(99)).unwrap().bytes,
        b"firstsecond"
    );
    assert!(
        a.sockets[&client]
            .completions
            .iter()
            .zip(saved)
            .all(|(a, b)| *a == b)
    );
    state.lock().unwrap().poll_error = Some(io::ErrorKind::BrokenPipe);
    assert_eq!(
        a.poll_backend_timestamps().unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[test]
fn output_error_finalizes_logical_send_parked_after_output_once() {
    let (mut a, _, client, _, _) = pair();
    let state = attach(&mut a, 2);
    flags(&mut a, client, ts::TX_SOFTWARE | ts::TX_SCHED | ts::TX_ACK);
    a.execute(client, Op::Set(SOL_SOCKET, SO_SNDBUF, 1000))
        .unwrap();
    a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    a.execute(client, Op::Flags(F_SETFL, 0)).unwrap();
    let bytes = vec![7; 150000];
    let (reply, result) = mpsc::sync_channel(1);
    let mut request = Request {
        id: client,
        op: Op::Wait(
            Box::new(Op::Send(
                vec![(bytes.as_ptr() as usize, bytes.len())],
                MSG_ZEROCOPY,
            )),
            None,
        ),
        reply,
        deadline: None,
        send: None,
    };
    assert!(!a.service(&mut request));
    assert_eq!(request.send.as_ref().unwrap().accepted, 4608);
    a.pending.push_back(request);
    state.lock().unwrap().output_error = Some(io::ErrorKind::BrokenPipe);
    let (_tx, rx) = mpsc::sync_channel(1);
    // run moves the pending send into after_output, then the real backend
    // submission fails on its first packet. No synthetic owner exit.
    a.run(rx, -1, &std::sync::atomic::AtomicBool::new(false));
    assert_eq!(state.lock().unwrap().output_calls, 1);
    assert_eq!(result.recv().unwrap().unwrap().value, 4608);
    assert!(matches!(
        result.try_recv(),
        Err(mpsc::TryRecvError::Disconnected)
    ));
    assert!(a.pending.is_empty());
    assert_eq!(a.sockets[&client].zc_reserved, 0);
    assert_eq!(a.sockets[&client].zc_next, 1);
    assert_eq!(
        a.sockets[&client]
            .completions
            .iter()
            .filter_map(Completion::range)
            .collect::<Vec<_>>(),
        [(0, 0)]
    );
    assert_eq!(stage_count(&a, client, 1), 0);
}

#[test]
fn pmtud_startup_uses_real_mtu_and_separate_adapter_capacity() {
    let state = Arc::new(Mutex::new(State {
        mtu: Some(9000),
        max_packet_len: Some(3514),
        ..Default::default()
    }));
    let io = Fixture(state.clone());
    let mut config = SocketConfig::new("test", Ipv4Addr::new(10, 73, 0, 2));
    config.tcp.connection.mss = 8960;
    config.tcp.connection.send_ip_payload_limit = 8980;
    assert!(config.validate().is_ok());
    let tcp = backend_config(config.tcp.clone(), &io).unwrap();
    assert_eq!(tcp.connection.pmtud.unwrap().first_hop_mtu, 9000);
    assert_eq!(tcp.connection.send_ip_payload_limit, 3480);
    assert_eq!(tcp.connection.mss, 8960);
    state.lock().unwrap().layer = Some(ntcp_io::PacketLayer::Ip);
    state.lock().unwrap().max_packet_len = Some(3500);
    assert_eq!(
        backend_config(config.tcp.clone(), &io)
            .unwrap()
            .connection
            .send_ip_payload_limit,
        3480
    );
    state.lock().unwrap().layer = None;
    state.lock().unwrap().max_packet_len = Some(3514);
    config.tcp.connection.send_ip_payload_limit = 1000;
    config.tcp.connection.mss = 500;
    let tcp = backend_config(config.tcp.clone(), &io).unwrap();
    assert_eq!(tcp.connection.send_ip_payload_limit, 1000);
    assert_eq!(tcp.connection.mss, 500);
    let owner = Owner::with_config(
        config.io.address,
        (config.io.address, 24),
        [2; 32],
        None,
        tcp,
    )
    .unwrap();
    assert_eq!(owner.output_packet_len(), 580); // MSS plus maximum TCP and IPv4 headers.
    state.lock().unwrap().mtu = None;
    assert_eq!(
        backend_config(config.tcp.clone(), &io).unwrap_err(),
        EOPNOTSUPP
    );
    state.lock().unwrap().mtu_error = Some(ENODEV);
    assert_eq!(backend_config(config.tcp.clone(), &io).unwrap_err(), ENODEV);
    state.lock().unwrap().mtu_error = None;
    state.lock().unwrap().mtu = Some(67);
    assert_eq!(backend_config(config.tcp.clone(), &io).unwrap_err(), EINVAL);
    state.lock().unwrap().mtu = Some(9000);
    for capacity in [0, 14, 81] {
        state.lock().unwrap().max_packet_len = Some(capacity);
        assert_eq!(backend_config(config.tcp.clone(), &io).unwrap_err(), EINVAL);
    }
}

fn pmtud_owner(last: u8, mtu: u32, capacity: Option<usize>) -> (Owner, Arc<Mutex<State>>) {
    let state = Arc::new(Mutex::new(State {
        mtu: Some(mtu),
        max_packet_len: capacity,
        ..Default::default()
    }));
    let io = Fixture(state.clone());
    let local = Ipv4Addr::new(10, 73, 0, last);
    let mut config = SocketConfig::new("test", local).tcp;
    config.connection.mss = 8960;
    config.connection.send_ip_payload_limit = 8980;
    let config = backend_config(config, &io).unwrap();
    let mut owner = Owner::with_config(local, (local, 24), [last; 32], None, config).unwrap();
    owner.ethernet = Some(EthernetBackend {
        io: Box::new(io),
        local: [2; 6],
        next_hop: [4; 6],
        next_cookie: 1,
        pending: Vec::new(),
    });
    (owner, state)
}

fn pmtud_pair(capacity: Option<usize>) -> (Owner, Owner, u64, u64, Arc<Mutex<State>>) {
    let (mut a, state) = pmtud_owner(2, 9000, capacity);
    let (mut b, _) = pmtud_owner(3, 9000, None);
    let listen = new(&mut b, SOCK_NONBLOCK);
    assert_eq!(
        b.execute(listen, Op::Get(IPPROTO_IP, IP_MTU)).unwrap_err(),
        ENOTCONN
    );
    b.execute(listen, Op::Bind("10.73.0.3:16379".parse().unwrap()))
        .unwrap();
    b.execute(listen, Op::Listen(16)).unwrap();
    assert_eq!(
        b.execute(listen, Op::Get(IPPROTO_IP, IP_MTU)).unwrap_err(),
        ENOTCONN
    );
    let client = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(client, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    pump(&mut a, &mut b);
    let server = b.execute(listen, Op::Accept(SOCK_NONBLOCK)).unwrap().value as u64;
    (a, b, client, server, state)
}

fn ptb(packet: &[u8], mtu: u16) -> Vec<u8> {
    let mut ip = vec![0; 56];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&56u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 1;
    ip[12..16].copy_from_slice(&[10, 73, 0, 1]); // Router, not TCP peer.
    ip[16..20].copy_from_slice(&packet[12..16]);
    ip[20] = 3;
    ip[21] = 4;
    ip[26..28].copy_from_slice(&mtu.to_be_bytes());
    ip[28..].copy_from_slice(&packet[..28]);
    fix_ptb_checksum(&mut ip);
    let checksum = ntcp_ip::checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    ip
}
fn fix_ptb_checksum(ip: &mut [u8]) {
    ip[22..24].fill(0);
    let checksum = ntcp_ip::checksum(&ip[20..]);
    ip[22..24].copy_from_slice(&checksum.to_be_bytes());
}
fn ingress(owner: &mut Owner, state: &Arc<Mutex<State>>, ip: &[u8]) {
    let mut frame = vec![0; (14 + ip.len()).max(60)];
    ntcp_ip::encode_ethernet(&mut frame, [4; 6], [2; 6], ntcp_ip::ETHERTYPE_IPV4, ip).unwrap();
    state.lock().unwrap().incoming.push_back(Ok(frame));
    owner.receive_batch(&mut vec![0; 65549]).unwrap();
}
fn mtu(owner: &mut Owner, socket: u64) -> i32 {
    owner
        .execute(socket, Op::Get(IPPROTO_IP, IP_MTU))
        .unwrap()
        .value
}

#[test]
fn pmtud_jumbo_allocation_capacity_and_validated_ingress() {
    for capacity in [None, Some(3514)] {
        let (mut a, mut b, client, server, state) = pmtud_pair(capacity);
        assert_eq!(mtu(&mut b, server), 9000); // Passive initialization too.
        let bound = capacity.map_or(9000, |n| n - 14);
        assert_eq!(mtu(&mut a, client), bound as i32);
        a.execute(client, Op::Write(vec![7; 16000])).unwrap();
        assert!(a.prepare_packet(None).unwrap());
        let packet = a.pending_packet.as_ref().unwrap().clone();
        assert!(packet.len() > 1500);
        assert!(packet.len() <= bound);
        submit(&mut a);
        let sent = state.lock().unwrap().sent.pop_front().unwrap();
        assert_eq!(sent.len(), packet.len() + 14);
        assert!(capacity.is_none_or(|cap| sent.len() <= cap));
        let valid = ptb(&packet, 1400);
        let mut bad = valid.clone();
        bad[22] ^= 1;
        ingress(&mut a, &state, &bad); // Invalid checksum.
        assert_eq!(mtu(&mut a, client), bound as i32);
        let mut bad = valid.clone();
        bad[48..50].copy_from_slice(&1u16.to_be_bytes()); // Wrong local port.
        fix_ptb_checksum(&mut bad);
        ingress(&mut a, &state, &bad);
        assert_eq!(mtu(&mut a, client), bound as i32);
        let mut bad = valid.clone();
        let seq = u32::from_be_bytes(packet[24..28].try_into().unwrap());
        bad[52..56].copy_from_slice(&seq.wrapping_sub(1).to_be_bytes());
        fix_ptb_checksum(&mut bad);
        ingress(&mut a, &state, &bad); // Not in the live send window.
        assert_eq!(mtu(&mut a, client), bound as i32);
        let mut bad = valid.clone();
        bad[19] = 99; // Valid checksums but addressed to another local IP.
        bad[10..12].fill(0);
        let checksum = ntcp_ip::checksum(&bad[..20]);
        bad[10..12].copy_from_slice(&checksum.to_be_bytes());
        ingress(&mut a, &state, &bad);
        assert_eq!(mtu(&mut a, client), bound as i32);
        let mut bad = valid.clone();
        bad[21] = 1; // Other unreachable errors are not MTU reports.
        fix_ptb_checksum(&mut bad);
        ingress(&mut a, &state, &bad);
        assert_eq!(mtu(&mut a, client), bound as i32);
        ingress(&mut a, &state, &valid);
        assert_eq!(mtu(&mut a, client), 1400);
        ingress(&mut a, &state, &ptb(&packet, 2000)); // No ICMP-driven increase.
        assert_eq!(mtu(&mut a, client), 1400);
        assert!(a.prepare_packet(None).unwrap());
        assert!(a.pending_packet.as_ref().unwrap().len() <= 1400);
        assert_eq!(state.lock().unwrap().mtu_queries, 1); // Never query in owner service.
    }
}

#[test]
fn pmtud_zero_mtu_and_ipv4_floor_are_dispatched_without_clamping() {
    for candidate in [0, 68] {
        let (mut a, _, client, _, state) = pmtud_pair(None);
        a.execute(client, Op::Write(vec![7; 16000])).unwrap();
        assert!(a.prepare_packet(None).unwrap());
        let packet = a.pending_packet.as_ref().unwrap().clone();
        submit(&mut a);
        ingress(&mut a, &state, &ptb(&packet, candidate));
        assert_eq!(mtu(&mut a, client), if candidate == 0 { 8166 } else { 68 });
    }
    let (mut a, _, client, _, _) = pair();
    assert_eq!(
        a.execute(client, Op::Get(IPPROTO_IP, IP_MTU)).unwrap_err(),
        EOPNOTSUPP
    );
}
