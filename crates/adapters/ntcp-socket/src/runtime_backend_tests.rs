// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::super::tests::pacing_tests::{paced_pair, pacing_tick};
use super::super::tests::{ip_packet, new, pair, poll_packet, pump};
use super::*;
#[path = "runtime_managed_tests.rs"]
mod managed;
use crate::timestamping as ts;
use ntcp_io::{TimestampCapabilities, TxTimestampCompletion, TxTimestampRequest};
use std::{
    io,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct State {
    mtu: Option<u32>,
    enforce_mtu: bool,
    mtu_error: Option<i32>,
    mtu_queries: usize,
    max_packet_len: Option<usize>,
    layer: Option<ntcp_io::PacketLayer>,
    incoming: VecDeque<io::Result<Vec<u8>>>,
    // Every frame handed to the backend, whatever its outcome.
    offered: Vec<Vec<u8>>,
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
    reject: bool,
    block_port: Option<u16>,
    block_after: Option<(u16, usize)>,
    rx_stamps: PacketTimestamps,
    rx_segment_size: Option<core::num::NonZeroU16>,
    interrupted: bool,
    cancel_error: Option<i32>,
    error: Option<io::ErrorKind>,
    poll_error: Option<io::ErrorKind>,
    disabled: bool,
    shared: bool,
    shared_offered: Vec<(usize, usize)>,
}
fn frame_port(bytes: &[u8]) -> Option<[u8; 2]> {
    let frame = ntcp_ethernet::parse_ethernet(bytes).ok()?;
    let packet = crate::ip::parse(frame.payload).ok()?;
    packet.payload.get(..2)?.try_into().ok()
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
    fn receive_with_metadata(&mut self, out: &mut [u8]) -> io::Result<Option<ReceivedPacket>> {
        let len = self.receive(out)?;
        let state = self.0.lock().unwrap();
        Ok(len.map(|len| ReceivedPacket {
            len,
            timestamps: state.rx_stamps,
            tcp_segment_size: state.rx_segment_size,
        }))
    }
    fn transmit(&mut self, bytes: &[u8]) -> io::Result<TxOutcome> {
        let mut state = self.0.lock().unwrap();
        state.output_calls += 1;
        state.offered.push(bytes.to_vec());
        if state.enforce_mtu && state.mtu.is_some_and(|mtu| bytes.len() > mtu as usize + 14) {
            return Err(io::Error::from_raw_os_error(EMSGSIZE));
        }
        if let Some(error) = state.output_error {
            return Err(error.into());
        }
        if state.reject {
            return Ok(TxOutcome::Rejected);
        }
        // Model native packet syscall EINTR: no packet or timestamp consumed.
        if state.interrupted
            || state.block
            || state.block_after.is_some_and(|(port, limit)| {
                state.sent.len() >= limit && frame_port(bytes) == Some(port.to_be_bytes())
            })
            || state
                .block_port
                .is_some_and(|port| frame_port(bytes) == Some(port.to_be_bytes()))
        {
            return Ok(TxOutcome::WouldBlock);
        }
        state.sent.push_back(bytes.to_vec());
        Ok(TxOutcome::Submitted)
    }
    fn zero_copy_capabilities(&self) -> Option<ntcp_io::ZeroCopyCapabilities> {
        self.0
            .lock()
            .unwrap()
            .shared
            .then_some(ntcp_io::ZeroCopyCapabilities {
                max_payload_segments: 8,
                max_packet_len: 2048,
            })
    }
    fn zero_copy_payload_supported(&self, payload: &ntcp_io::Payload) -> bool {
        payload.storage::<Vec<u8>>().is_some()
    }
    fn transmit_zero_copy(&mut self, packet: &ntcp_io::OwnedPacket) -> io::Result<TxOutcome> {
        let payload_len = packet.payload.iter().map(ntcp_io::Payload::len).sum();
        self.0
            .lock()
            .unwrap()
            .shared_offered
            .push((packet.header.len(), payload_len));
        let mut wire = packet.header.clone();
        for part in &packet.payload {
            wire.extend_from_slice(part.as_slice());
        }
        self.transmit(&wire)
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
        state.offered.push(bytes.to_vec());
        if state.enforce_mtu && state.mtu.is_some_and(|mtu| bytes.len() > mtu as usize + 14) {
            return Err(io::Error::from_raw_os_error(EMSGSIZE));
        }
        if let Some(error) = state.error {
            return Err(error.into());
        }
        if state.reject {
            return Ok(TxOutcome::Rejected);
        }
        // Model native packet syscall EINTR: no packet or timestamp consumed.
        if state.interrupted
            || state.block
            || state.block_after.is_some_and(|(port, limit)| {
                state.sent.len() >= limit && frame_port(bytes) == Some(port.to_be_bytes())
            })
            || state
                .block_port
                .is_some_and(|port| frame_port(bytes) == Some(port.to_be_bytes()))
        {
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
        if let Some(errno) = state.cancel_error {
            return Err(io::Error::from_raw_os_error(errno));
        }
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
    owner.ports[0].ethernet = Some(EthernetBackend {
        io: Box::new(Fixture(state.clone())),
        local: [2; 6],
        next_hop: Some([4; 6]),
        next_cookie: 1,
        pending: Vec::new(),
        cancelled: Vec::new(),
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
// One egress turn in which the backend accepts exactly one new frame.
fn submit_one(owner: &mut Owner, state: &Arc<Mutex<State>>) {
    let sent = state.lock().unwrap().sent.len();
    owner.service_egress().unwrap();
    assert_eq!(state.lock().unwrap().sent.len(), sent + 1);
}
// The frame last handed to the backend since the previous call.
fn take_offered(state: &Arc<Mutex<State>>) -> Option<Vec<u8>> {
    let mut state = state.lock().unwrap();
    let last = state.offered.pop();
    state.offered.clear();
    last
}
fn deliver(owner: &mut Owner, peer: &mut Owner, state: &Arc<Mutex<State>>) {
    while let Some(frame) = state.lock().unwrap().sent.pop_front() {
        let ethernet = ntcp_ethernet::parse_ethernet(&frame).unwrap();
        let ip = ntcp_ip::parse(ethernet.payload, false).unwrap();
        peer.input(peer.now(), ip.ip, ip.traffic_class, ip.payload)
            .unwrap();
    }
    // Force the peer's delayed ACK without sleeps or a NIC.
    peer.advance_clock(250_000);
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
    let bytes = poll_packet(&mut a).unwrap();
    let mut frame = vec![0; bytes.len() + 14];
    ntcp_ethernet::encode_ethernet(
        &mut frame,
        [2; 6],
        [4; 6],
        ntcp_ethernet::ETHERTYPE_IPV4,
        &bytes,
    )
    .unwrap();
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
    a.enable_egress(4, None).unwrap();
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
    submit_one(&mut a, &state);
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
    state.lock().unwrap().block = true;
    a.service_egress().unwrap();
    let packet = take_offered(&state);
    assert!(packet.is_some());
    for _ in 0..3 {
        // Each retry offers the same held frame once and the backend refuses it.
        advance(&mut a, 1000);
        a.service_egress().unwrap();
        assert_eq!(take_offered(&state), packet);
        assert!(state.lock().unwrap().sent.is_empty());
        assert_eq!(state.lock().unwrap().cancelled, [1]);
        assert!(a.ports[0].ethernet.as_ref().unwrap().pending.is_empty());
    }
    state.lock().unwrap().block = false;
    advance(&mut a, 1000);
    submit_one(&mut a, &state); // One missing HW + two new sources > capacity: evict first HW.
    assert_eq!(state.lock().unwrap().sent.front(), packet.as_ref());
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
    submit_one(&mut a, &state);
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
    submit_one(&mut a, &state);
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
    assert_eq!(a.ports[0].ethernet.as_ref().unwrap().pending.len(), 1);
}

#[test]
fn real_backpressure_retries_unchanged_without_reservation_or_duplicate() {
    let (mut a, mut b, client, server, _) = pair();
    let state = attach(&mut a, 2);
    a.enable_egress(4, None).unwrap();
    flags(
        &mut a,
        client,
        ts::TX_SOFTWARE | ts::TX_HARDWARE | ts::TX_ACK,
    );
    a.execute(client, Op::Write(b"once".to_vec())).unwrap();
    let cid = connection(&a, client);
    state.lock().unwrap().block = true;
    a.service_egress().unwrap();
    let bytes = take_offered(&state);
    assert!(bytes.is_some());
    // The held ticket, and so its timestamp token, is never reselected.
    let attempt = a.egress.as_ref().unwrap().attempt(cid);
    for _ in 0..3 {
        // Each retry offers the same held frame once and the backend refuses it.
        advance(&mut a, 1000);
        a.service_egress().unwrap();
        assert_eq!(take_offered(&state), bytes);
        assert_eq!(a.egress.as_ref().unwrap().attempt(cid), attempt);
        assert_eq!(a.sockets[&client].timestamps.reserved(), 3);
        assert!(a.ports[0].ethernet.as_ref().unwrap().pending.is_empty());
        assert_eq!(a.ports[0].ethernet.as_ref().unwrap().next_cookie, 1);
    }
    state.lock().unwrap().block = false;
    advance(&mut a, 1000);
    submit_one(&mut a, &state);
    assert_eq!(state.lock().unwrap().sent.len(), 1);
    assert_eq!(state.lock().unwrap().sent.front(), bytes.as_ref());
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
        a.enable_egress(4, None).unwrap();
        flags(
            &mut a,
            client,
            ts::TX_SOFTWARE | ts::TX_HARDWARE | ts::TX_ACK | ts::TX_SCHED,
        );
        a.execute(client, Op::Write(b"data".to_vec())).unwrap();
        if exhausted {
            a.ports[0].ethernet.as_mut().unwrap().next_cookie = u64::MAX;
        }
        state.lock().unwrap().error = error;
        if error == Some(io::ErrorKind::BrokenPipe) {
            // Fatal I/O is not a fallback: egress reports it without a retry.
            assert_eq!(a.service_egress(), Err(EIO));
            assert!(state.lock().unwrap().sent.is_empty());
            assert_eq!(a.sockets[&client].timestamps.reserved(), 3);
            continue;
        }
        // Fallback itself can backpressure; only observations are cancelled once.
        state.lock().unwrap().block = true;
        a.service_egress().unwrap();
        assert!(take_offered(&state).is_some());
        assert!(state.lock().unwrap().sent.is_empty());
        assert_eq!(a.sockets[&client].timestamps.reserved(), 1); // ACK survives.
        state.lock().unwrap().block = false;
        advance(&mut a, 1000);
        submit_one(&mut a, &state);
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
    a.enable_egress(4, None).unwrap();
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
        submit_one(&mut a, &state);
        deliver(&mut a, &mut b, &state);
        assert_eq!(b.execute(peer, Op::Read(99)).unwrap().bytes, [i as u8]);
        let Handle::Connection(cid) = a.sockets[&id].handle else {
            unreachable!()
        };
        assert_eq!(a.endpoint.transport_info(cid).unwrap().unacked, 0);
        assert!(a.ports[0].ethernet.as_ref().unwrap().pending.len() <= timestamps::PHASES);
    }
    assert_eq!(state.lock().unwrap().cancelled, [1]);
    assert_eq!(
        a.ports[0].ethernet.as_ref().unwrap().pending.len(),
        timestamps::PHASES
    );
    a.execute(plain, Op::Write(b"plain".to_vec())).unwrap();
    submit_one(&mut a, &state);
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
    a.enable_egress(4, None).unwrap();
    flags(
        &mut a,
        client,
        ts::TX_SOFTWARE | ts::TX_HARDWARE | ts::TX_ACK | ts::TX_SCHED,
    );
    a.execute(client, Op::Write(b"first".to_vec())).unwrap();
    submit_one(&mut a, &state);
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
    submit_one(&mut a, &state);
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
    a.enable_egress(4, None).unwrap();
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
        closing: None,
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
//= https://www.rfc-editor.org/rfc/rfc4821#section-3
//= type=test
//= reason=PacketIo reports IP MTU separately from layer-unit buffer capacity. Executable backend fixture distinguishes9000 IP MTU from3514 Ethernet/3500 IP capacity; no physical-link enforcement claim.
//# MTU: Maximum Transmission Unit, the size in bytes of the largest IP packet, including
//# the IP header and payload, that can be transmitted on a link or path. Note that this
//# could more properly be called the IP MTU, to be consistent with how other standards
//# organizations use the acronym MTU.

//= https://www.rfc-editor.org/rfc/rfc4821#section-3
//= type=test
//= reason=PacketIo reports IP MTU separately from layer-unit buffer capacity. Executable backend fixture distinguishes9000 IP MTU from3514 Ethernet/3500 IP capacity; no physical-link enforcement claim.
//# Link MTU: The Maximum Transmission Unit, i.e., maximum IP packet size in bytes, that can
//# be conveyed in one piece over a link. Be aware that this definition is different from
//# the definition used by other standards organizations.

//= https://www.rfc-editor.org/rfc/rfc4821#section-3
//= type=test
//= reason=PacketIo reports IP MTU separately from layer-unit buffer capacity. Executable backend fixture distinguishes9000 IP MTU from3514 Ethernet/3500 IP capacity; no physical-link enforcement claim.
//# For IETF documents, link MTU is uniformly defined as the IP MTU over the link. This
//# includes the IP header, but excludes link layer headers and other framing that is not
//# part of IP or the IP payload.

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

fn pmtud_owner(
    last: u8,
    mtu: u32,
    capacity: Option<usize>,
    pacing: Option<ntcp::PacingConfig>,
) -> (Owner, Arc<Mutex<State>>) {
    let state = Arc::new(Mutex::new(State {
        mtu: Some(mtu),
        max_packet_len: capacity,
        ..Default::default()
    }));
    let io = Fixture(state.clone());
    let local = Ipv4Addr::new(10, 73, 0, last);
    let mut config = SocketConfig::new("test", local).tcp;
    config.connection.pacing = pacing;
    config.connection.mss = 8960;
    config.connection.send_ip_payload_limit = 8980;
    let config = backend_config(config, &io).unwrap();
    let mut owner = Owner::with_config(local, (local, 24), [last; 32], None, config).unwrap();
    owner.test_now = Some(1000);
    owner.ports[0].ethernet = Some(EthernetBackend {
        io: Box::new(io),
        local: [2; 6],
        next_hop: Some([4; 6]),
        next_cookie: 1,
        pending: Vec::new(),
        cancelled: Vec::new(),
    });
    (owner, state)
}

// The host-less native parser hands every option except NOP/EOL to TCP
// without destination processing (managed input records them:
// runtime_managed_io_tests).
#[test]
fn native_hostless_ingress_hands_every_option_to_tcp_unprocessed() {
    fn add_options(mut packet: Vec<u8>, options: &[u8]) -> Vec<u8> {
        assert!(options.len().is_multiple_of(4));
        packet.splice(20..20, options.iter().copied());
        packet[0] = 0x45 + (options.len() / 4) as u8;
        let len = packet.len() as u16;
        packet[2..4].copy_from_slice(&len.to_be_bytes());
        packet[10..12].fill(0);
        let sum = ntcp_ip::checksum(&packet[..20 + options.len()]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
        packet
    }
    for known in [false, true] {
        let (mut a, a_io) = pmtud_owner(2, 1500, None, None);
        let (mut b, b_io) = pmtud_owner(3, 1500, None, None);
        let listener = new(&mut b, SOCK_NONBLOCK);
        b.execute(listener, Op::Bind("10.73.0.3:8080".parse().unwrap()))
            .unwrap();
        b.execute(listener, Op::Listen(1)).unwrap();
        let client = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(client, Op::Connect("10.73.0.3:8080".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        let raw = if known {
            // RR and TS (flag 1) with two free slots each, among copied and
            // non-copied opaque options. RR/TS used to be filtered out before
            // TCP; every option is now delivered.
            let mut raw = vec![30, 2, 158, 3, 0, 7, 11, 4, 0, 0, 0, 0, 0, 0, 0, 0];
            raw.extend_from_slice(&[68, 20, 5, 1]);
            raw.extend_from_slice(&[0; 16]);
            raw
        } else {
            vec![30, 2, 158, 3, 0, 1, 0, 255]
        };
        let received = ntcp::Ipv4Options::parse(&raw, false).unwrap();
        assert_eq!(received.as_bytes().len(), if known { 36 } else { 5 });
        assert!(b.host.is_none());
        let syn = poll_packet(&mut a).unwrap();
        assert_eq!(
            crate::ip::parse(&add_options(syn.clone(), &raw))
                .unwrap()
                .ipv4_options,
            received
        );
        let routed = add_options(syn.clone(), &[131, 7, 8, 10, 73, 0, 9, 0]);
        assert_eq!(
            crate::ip::parse(&routed).unwrap_err(),
            ntcp_ip_common::Error::Options
        );
        ingress(&mut b, &b_io, &routed);
        assert!(poll_packet(&mut b).is_none());
        ingress(&mut b, &b_io, &add_options(syn.clone(), &raw));
        let synack = poll_packet(&mut b).expect("ordinary native SYN accepted");
        assert_eq!(synack[0], 0x45);
        ingress(&mut a, &a_io, &synack);
        let ack = poll_packet(&mut a).unwrap();
        ingress(&mut b, &b_io, &add_options(ack, &raw));
        let server = b
            .execute(listener, Op::Accept(SOCK_NONBLOCK))
            .unwrap()
            .value as u64;
        let cid = connection(&b, server);
        assert_eq!(
            b.endpoint.received_ipv4_options(cid).unwrap(),
            Some(received)
        );
        a.execute(client, Op::Write(b"native opaque handoff".to_vec()))
            .unwrap();
        let data = poll_packet(&mut a).unwrap();
        ingress(&mut b, &b_io, &add_options(data, &raw));
        assert_eq!(
            b.endpoint.received_ipv4_options(cid).unwrap(),
            Some(received)
        );
        assert_eq!(
            b.execute(server, Op::Read(BYTES)).unwrap().bytes,
            b"native opaque handoff"
        );
        // Exercise the existing ICMP decoder over a real checksummed raw frame.
        // This proves acceptance, not a new ICMP host option service.
        let error = add_options(ptb(&syn, 1400), &raw);
        let parsed = ntcp_ip::parse(&error, false).unwrap();
        assert_eq!(parsed.ipv4_options, received);
        assert_eq!(
            ntcp_icmp::decode_icmp(&error).unwrap().kind,
            ntcp_icmp::FeedbackKind::PacketTooBig
        );
    }
}

fn pmtud_pair(capacity: Option<usize>) -> (Owner, Owner, u64, u64, Arc<Mutex<State>>) {
    pmtud_paced_pair(capacity, None)
}
fn pmtud_paced_pair(
    capacity: Option<usize>,
    pacing: Option<ntcp::PacingConfig>,
) -> (Owner, Owner, u64, u64, Arc<Mutex<State>>) {
    let (mut a, state) = pmtud_owner(2, 9000, capacity, pacing);
    let (mut b, _) = pmtud_owner(3, 9000, None, None);
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
    let checksum = ntcp_ip_common::checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    ip
}
fn fix_ptb_checksum(ip: &mut [u8]) {
    ip[22..24].fill(0);
    let checksum = ntcp_ip_common::checksum(&ip[20..]);
    ip[22..24].copy_from_slice(&checksum.to_be_bytes());
}
fn ingress(owner: &mut Owner, state: &Arc<Mutex<State>>, ip: &[u8]) {
    let mut frame = vec![0; (14 + ip.len()).max(60)];
    ntcp_ethernet::encode_ethernet(
        &mut frame,
        [4; 6],
        [2; 6],
        ntcp_ethernet::ETHERTYPE_IPV4,
        ip,
    )
    .unwrap();
    state.lock().unwrap().incoming.push_back(Ok(frame));
    owner.receive_batch(&mut vec![0; 65549]).unwrap();
}
// The IPv4 datagram carried by a fixture frame, without Ethernet padding.
fn datagram(frame: &[u8]) -> &[u8] {
    let len = u16::from_be_bytes([frame[16], frame[17]]);
    &frame[14..14 + usize::from(len)]
}
fn mtu(owner: &mut Owner, socket: u64) -> i32 {
    owner
        .execute(socket, Op::Get(IPPROTO_IP, IP_MTU))
        .unwrap()
        .value
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc1191#section-2
//= type=test
//= reason=Native IPv4 input validates codec output then dispatches quoted tuple/sequence to endpoint policy; tests reject wrong checksum/tuple/window and observe bounded output after valid PTB.
//# Upon receipt of such a message (henceforth called a "Datagram Too Big" message), the
//# source host reduces its assumed PMTU for the path.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.2
//= type=test
//= reason=Enabled core implements validated PTB, real-data ACK-confirmed probes, bounded search and R1 black-hole fallback. Native IPv4 TUN/AF_PACKET ingress and real MTU startup integrate it. This closes the implementation recommendation, not all external RFC clauses: RFC1191/8201/4821 inventories retain exact gaps; native IPv6 sockets remain unsupported.
//# Instead, implementation of Path MTU Discovery (PMTUD) and Packetization Layer Path MTU
//# Discovery (PLPMTUD) is strongly recommended in order for TCP to improve segmentation
//# decisions.
//= https://www.rfc-editor.org/rfc/rfc5927#section-4.3
//= type=test
//= reason=Informational rationale: outer source may be a router, not the peer. Runtime fixture sends PTB from10.73.0.1 for peer10.73.0.3; quoted tuple/live sequence and checksums still gate acceptance.
//# The source address of ICMP error messages does not need to be spoofed to perform the
//# attacks described in this document, as the ICMP error messages might legitimately come
//# from an intermediate system.
//= https://www.rfc-editor.org/rfc/rfc1191#section-2
//= type=test
//= reason=Enabled PMTUD initializes from the supplied first-hop MTU, capped by independent peer/allocation ceilings; native startup/jumbo tests establish those bounds. This does not assert a router implementation.
//# The basic idea is that a source host initially assumes that the PMTU of a path is
//# the (known) MTU of its first hop,

fn pmtud_jumbo_allocation_capacity_and_validated_ingress() {
    for capacity in [None, Some(3514)] {
        let (mut a, mut b, client, server, state) = pmtud_pair(capacity);
        a.enable_egress(1, None).unwrap();
        assert_eq!(mtu(&mut b, server), 9000); // Passive initialization too.
        let bound = capacity.map_or(9000, |n| n - 14);
        assert_eq!(mtu(&mut a, client), bound as i32);
        a.execute(client, Op::Write(vec![7; 16000])).unwrap();
        a.service_egress().unwrap();
        let sent = state.lock().unwrap().sent.pop_front().unwrap();
        let packet = datagram(&sent).to_vec();
        assert!(packet.len() > 1500);
        assert!(packet.len() <= bound);
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
        let checksum = ntcp_ip_common::checksum(&bad[..20]);
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
        state.lock().unwrap().sent.clear();
        a.service_egress().unwrap();
        let repaired = state.lock().unwrap().sent.clone();
        assert!(!repaired.is_empty());
        assert!(repaired.iter().all(|frame| datagram(frame).len() <= 1400));
        assert_eq!(state.lock().unwrap().mtu_queries, 1); // Never query in owner service.
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc1191#section-3
//= type=test
//= reason=IPv4 zero Next-Hop MTU selects the next lower plateau using exact sent length and legacy header correction. Connection, direct-state and native socket tests cover zero-MTU processing; the following section5 cross-reference is context, not a missing feature.
//# Hosts MUST be able to deal with Datagram Too Big messages that do not include the
//# next-hop MTU, since it is not feasible to upgrade all the routers in the Internet in
//# any finite time. A Datagram Too Big message from an unmodified router can be
//# recognized by the presence of a zero in the (newly-defined) Next-Hop MTU field.

fn pmtud_zero_mtu_and_ipv4_floor_are_dispatched_without_clamping() {
    for candidate in [0, 68] {
        let (mut a, _, client, _, state) = pmtud_pair(None);
        a.enable_egress(1, None).unwrap();
        a.execute(client, Op::Write(vec![7; 16000])).unwrap();
        a.service_egress().unwrap();
        let sent = state.lock().unwrap().sent.pop_front().unwrap();
        let packet = datagram(&sent).to_vec();
        ingress(&mut a, &state, &ptb(&packet, candidate));
        assert_eq!(mtu(&mut a, client), if candidate == 0 { 8166 } else { 68 });
    }
    let (mut a, _, client, _, _) = pair();
    assert_eq!(
        a.execute(client, Op::Get(IPPROTO_IP, IP_MTU)).unwrap_err(),
        EOPNOTSUPP
    );
}

// Production egress after the handshake, with a controllable MTU refresh worker.
fn egress_with_refresh(
    owner: &mut Owner,
    capacity: usize,
) -> (Receiver<()>, SyncSender<io::Result<Option<u32>>>) {
    owner.enable_egress(capacity, None).unwrap();
    let (refresh, request, result) = super::super::output::MtuRefresh::fixture();
    owner.ports[0].mtu_refresh = Some(refresh);
    (request, result)
}
fn connection(owner: &Owner, id: u64) -> ConnectionId {
    let Handle::Connection(cid) = owner.sockets[&id].handle else {
        panic!()
    };
    cid
}
fn advance(owner: &mut Owner, delta: u64) {
    owner.test_now = Some(owner.now() + delta);
}
fn refresh(owner: &mut Owner, result: &SyncSender<io::Result<Option<u32>>>, mtu: u32) {
    result.send(Ok(Some(mtu))).unwrap();
    owner.poll_mtu_refresh();
}
fn drain_scheduled(owner: &mut Owner, cid: ConnectionId) {
    for _ in 0..64 {
        owner.service_egress().unwrap();
        if !owner.endpoint.is_output_reserved(cid) {
            return;
        }
        owner.test_now = Some(
            owner
                .endpoint
                .next_deadline()
                .expect("repair pacing deadline"),
        );
    }
    panic!("reservation did not drain");
}

#[test]
fn reserved_mtu_drop_split_backpressure_late_accept_and_prefix() {
    for expire in [false, true] {
        let (mut a, mut b, client, server, state) = pmtud_pair(None);
        a.execute(client, Op::Write(vec![7; 8000])).unwrap();
        let (requests, results) = egress_with_refresh(&mut a, 1);
        let cid = connection(&a, client);
        state.lock().unwrap().interrupted = true;
        advance(&mut a, 100);
        a.service_egress().unwrap();
        // The first refused submission starts the I/O deadline.
        let deadline = a.now() + 1_000_000;
        let original = take_offered(&state).unwrap();
        let selected = ntcp_ip::parse(datagram(&original), false).unwrap();
        let selected = ntcp::wire::parse(selected.ip, selected.payload).unwrap();
        let selected_len = selected.payload.len();
        let start = selected.header.sequence;
        assert!(datagram(&original).len() > 1500);
        let token = a.egress.as_ref().unwrap().attempt(cid);
        for i in 0..3 {
            state.lock().unwrap().interrupted = i % 2 == 0;
            state.lock().unwrap().block = i % 2 != 0;
            advance(&mut a, 1000);
            a.service_egress().unwrap();
            assert_eq!(a.egress.as_ref().unwrap().attempt(cid), token);
            assert_eq!(take_offered(&state).as_ref(), Some(&original));
        }
        {
            let mut state = state.lock().unwrap();
            state.block = false;
            state.interrupted = false;
            state.enforce_mtu = true;
            state.mtu = Some(1400);
        }
        advance(&mut a, 1000);
        a.service_egress().unwrap();
        requests.try_recv().unwrap();
        assert_eq!(take_offered(&state).as_ref(), Some(&original));
        // The rejected bytes are dropped and nothing is reselected before a refresh.
        advance(&mut a, 1000);
        a.service_egress().unwrap();
        assert_eq!(take_offered(&state), None);
        refresh(&mut a, &results, 1400);
        assert_eq!(
            a.endpoint
                .path_mtu_info(cid)
                .unwrap()
                .unwrap()
                .first_hop_mtu,
            1400
        );
        assert_eq!(a.defaults.connection.send_ip_payload_limit, 8980); // Not a capacity resize.
        // Accept one repaired prefix, then refuse the next repaired segment.
        let port = a.endpoint.tuple(cid).unwrap().local.port();
        state.lock().unwrap().block_after = Some((port, 1));
        advance(&mut a, 10_000);
        a.service_egress().unwrap();
        assert_eq!(state.lock().unwrap().sent.len(), 1);
        assert!(a.endpoint.is_output_reserved(cid)); // Accepted prefix does not free the barrier.
        {
            let mut state = state.lock().unwrap();
            state.block_after = None;
            state.mtu = Some(600);
        }
        advance(&mut a, 1000);
        a.service_egress().unwrap();
        requests.try_recv().unwrap();
        refresh(&mut a, &results, 600);
        a.expire_egress(deadline - 1).unwrap();
        assert!(a.endpoint.is_output_reserved(cid));
        if expire {
            // Refusals, the accepted prefix and both repairs kept the first deadline.
            a.test_now = Some(deadline);
            a.expire_egress(deadline).unwrap();
            assert_eq!(a.endpoint.state(cid), Ok(ntcp::State::Closed));
            assert_eq!(state.lock().unwrap().sent.len(), 1);
            continue;
        }
        drain_scheduled(&mut a, cid);
        assert!(!a.egress.as_ref().unwrap().has_held());
        let mut seq = start;
        let mut count = 0;
        for (index, frame) in state.lock().unwrap().sent.iter().enumerate() {
            let ethernet = ntcp_ethernet::parse_ethernet(frame).unwrap();
            assert!(ethernet.payload.len() <= if index == 0 { 1400 } else { 600 });
            let ip = ntcp_ip::parse(ethernet.payload, false).unwrap();
            let tcp = ntcp::wire::parse(ip.ip, ip.payload).unwrap();
            assert_eq!(tcp.header.sequence, seq);
            assert!(tcp.payload.iter().all(|b| *b == 7));
            seq = seq.wrapping_add(tcp.payload.len() as u32);
            count += tcp.payload.len();
            b.input(b.now(), ip.ip, ip.traffic_class, ip.payload)
                .unwrap();
        }
        assert_eq!(count, selected_len);
        assert_eq!(
            b.execute(server, Op::Read(8000)).unwrap().bytes,
            vec![7; selected_len]
        );
        assert_eq!(a.endpoint.transport_info(cid).unwrap().send_used, 8000);
        assert!(a.endpoint.on_timeout(a.now(), 0).is_ok());
        assert!(requests.try_recv().is_err());
    }
}

#[test]
fn reserved_refresh_failure_nochange_stall_expires_only_owner_and_allows_progress() {
    for response in [Some(Err(ENODEV)), Some(Ok(9000)), Some(Ok(67)), None] {
        let (mut a, mut b, client, _, state) = pmtud_pair(None);
        let listener = new(&mut b, SOCK_NONBLOCK);
        b.execute(listener, Op::Bind("10.73.0.3:16380".parse().unwrap()))
            .unwrap();
        b.execute(listener, Op::Listen(4)).unwrap();
        let healthy = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(healthy, Op::Connect("10.73.0.3:16380".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        pump(&mut a, &mut b);
        b.execute(listener, Op::Accept(SOCK_NONBLOCK)).unwrap();
        a.execute(client, Op::Write(vec![5; 8000])).unwrap();
        let (requests, results) = egress_with_refresh(&mut a, 1);
        {
            let mut s = state.lock().unwrap();
            s.enforce_mtu = true;
            s.mtu = Some(1400);
        }
        a.service_egress().unwrap();
        requests.try_recv().unwrap();
        assert!(take_offered(&state).is_some());
        let deadline = a.now() + 1_000_000;
        if let Some(response) = response {
            results
                .send(response.map(Some).map_err(io::Error::from_raw_os_error))
                .unwrap();
        }
        for _ in 0..4 {
            a.poll_mtu_refresh();
            a.service_egress().unwrap();
            assert_eq!(take_offered(&state), None);
            assert_eq!(a.output_wait(), std::time::Duration::from_millis(1));
            assert!(requests.try_recv().is_err());
            advance(&mut a, 100);
        }
        a.expire_egress(deadline - 1).unwrap();
        assert!(a.endpoint.is_output_reserved(connection(&a, client)));
        a.test_now = Some(deadline);
        a.expire_egress(deadline).unwrap();
        assert_eq!(
            a.endpoint.state(connection(&a, client)).unwrap(),
            ntcp::State::Closed
        );
        assert_eq!(
            a.endpoint.state(connection(&a, healthy)).unwrap(),
            ntcp::State::Established
        );
        assert!(state.lock().unwrap().sent.is_empty()); // No fabricated reset.
        a.events();
        assert_eq!(a.sockets[&client].error, ECONNABORTED);
        a.execute(healthy, Op::Write(vec![9; 100])).unwrap();
        a.service_egress().unwrap();
        assert_eq!(state.lock().unwrap().sent.len(), 1);
        assert!(!a.egress.as_ref().unwrap().has_held());
        if response.is_none() {
            a.execute(healthy, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
                .unwrap();
            a.execute(healthy, Op::Write(vec![3; 8000])).unwrap();
            a.service_egress().unwrap();
            assert!(requests.try_recv().is_err()); // Still only the first stalled query.
            // The new obligation starts its own deadline.
            let cid = connection(&a, healthy);
            let deadline = a.now() + 1_000_000;
            a.expire_egress(deadline - 1).unwrap();
            assert!(a.endpoint.is_output_reserved(cid));
            a.expire_egress(deadline).unwrap();
            assert_eq!(a.endpoint.state(cid), Ok(ntcp::State::Closed));
        }
    }
}

#[test]
fn reserved_commands_producers_and_rx_are_deferred_before_admission() {
    let (mut a, mut b, client, server, state) = pmtud_pair(None);
    let fresh = new(&mut a, SOCK_NONBLOCK);
    a.execute(client, Op::Write(vec![1; 100])).unwrap();
    a.enable_egress(1, None).unwrap();
    state.lock().unwrap().block = true;
    a.service_egress().unwrap();
    let cid = connection(&a, client);
    assert!(a.endpoint.is_output_reserved(cid));
    let mut commands = Vec::new();
    for (id, op, held) in [
        (0, Op::New(SOCK_NONBLOCK), false),
        (client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1), true),
        (fresh, Op::Close, false),
    ] {
        let (reply, response) = mpsc::sync_channel(1);
        let mut request = Request {
            id,
            op,
            reply,
            deadline: None,
            send: None,
            closing: None,
        };
        // Only the held owner's commands wait; other sockets keep progressing.
        assert_eq!(a.service(&mut request), !held);
        if held {
            assert!(response.try_recv().is_err());
            commands.push((request, response));
        } else {
            assert!(response.recv().unwrap().is_ok());
        }
    }
    let mut pipe = [0; 2];
    assert_eq!(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), O_NONBLOCK | O_CLOEXEC) },
        0
    );
    assert_eq!(
        unsafe { libc::write(pipe[1], b"pipe".as_ptr().cast(), 4) },
        4
    );
    let mut staging = [0; 2];
    assert_eq!(
        unsafe { libc::pipe2(staging.as_mut_ptr(), O_NONBLOCK | O_CLOEXEC) },
        0
    );
    let _fds: Vec<_> = pipe
        .into_iter()
        .chain(staging)
        .map(crate::Retained)
        .collect();
    let (reply, response) = mpsc::sync_channel(1);
    let mut request = Request {
        id: client,
        op: Op::Transfer {
            source: pipe[0],
            staging,
            offset: None,
            count: 4,
            flags: 0,
        },
        reply,
        deadline: None,
        send: None,
        closing: None,
    };
    assert!(!a.service(&mut request));
    assert!(response.try_recv().is_err());
    let mut available = 0;
    assert_eq!(unsafe { libc::ioctl(pipe[0], FIONREAD, &mut available) }, 0);
    assert_eq!(available, 4);
    let file = unsafe { libc::memfd_create(c"reservation-producer".as_ptr(), libc::MFD_CLOEXEC) };
    assert!(file >= 0);
    let _file = crate::Retained(file);
    assert_eq!(unsafe { libc::write(file, b"file".as_ptr().cast(), 4) }, 4);
    let mut offset: libc::off_t = 0;
    let (reply, file_response) = mpsc::sync_channel(1);
    let mut file_request = Request {
        id: client,
        op: Op::Transfer {
            source: file,
            staging,
            offset: Some((&mut offset as *mut libc::off_t) as usize),
            count: 4,
            flags: 0,
        },
        reply,
        deadline: None,
        send: None,
        closing: None,
    };
    assert!(!a.service(&mut file_request));
    assert!(file_response.try_recv().is_err());
    assert_eq!(offset, 0);
    b.execute(server, Op::Write(vec![2; 20])).unwrap();
    let packet = poll_packet(&mut b).unwrap();
    ingress(&mut a, &state, &packet);
    // Egress retains the held owner's RX without processing it.
    assert!(a.egress.as_ref().unwrap().retained_rx(cid));
    assert_eq!(a.endpoint.readable_bytes(cid).unwrap(), 0);
    // Multi-owner core timers no longer use the legacy global barrier probe.
    assert_eq!(a.endpoint.on_timeout(a.now(), 0), Ok(false));
    state.lock().unwrap().block = false;
    advance(&mut a, 1000);
    a.service_egress().unwrap();
    assert_eq!(state.lock().unwrap().sent.len(), 1);
    a.receive_batch(&mut vec![0; 65549]).unwrap();
    assert!(!a.egress.as_ref().unwrap().retained_rx(cid));
    assert_eq!(a.execute(client, Op::Read(20)).unwrap().bytes, vec![2; 20]);
    // A producer request is now admitted, not rejected with OutputReserved/EINVAL.
    assert!(a.service(&mut request));
    assert_eq!(response.recv().unwrap().unwrap().value, 4);
    assert_eq!(unsafe { libc::ioctl(pipe[0], FIONREAD, &mut available) }, 0);
    assert_eq!(available, 0);
    assert!(a.service(&mut file_request));
    assert_eq!(file_response.recv().unwrap().unwrap().value, 4);
    assert_eq!(offset, 4);
    for (mut request, response) in commands {
        assert!(a.service(&mut request));
        assert!(response.recv().unwrap().is_ok());
    }
}

#[test]
fn reserved_pacing_alone_has_no_deadline_and_late_accept_debits_once() {
    let (mut a, mut b, client, _, state) = pmtud_paced_pair(
        None,
        Some(ntcp::PacingConfig {
            max_burst_segments: 1,
            max_bytes_per_second: Some(1_000_000),
            ..Default::default()
        }),
    );
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    a.execute(client, Op::Write(vec![1; 24000])).unwrap();
    a.enable_egress(1, None).unwrap();
    let cid = connection(&a, client);
    a.service_egress().unwrap();
    assert_eq!(state.lock().unwrap().sent.len(), 1);
    // A pacing wait holds no ticket, so it has no I/O deadline.
    assert!(!a.endpoint.is_output_reserved(cid));
    assert!(!a.egress.as_ref().unwrap().has_held());
    let deadline = a.endpoint.next_deadline().unwrap();
    assert!(deadline > a.now());
    a.test_now = Some(deadline);
    a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
    state.lock().unwrap().block = true;
    a.service_egress().unwrap();
    assert!(a.endpoint.is_output_reserved(cid));
    let first = a.now() + 1_000_000;
    advance(&mut a, 50_000);
    // The refused ticket is still held just before its I/O deadline.
    a.expire_egress(first - 1).unwrap();
    assert!(a.endpoint.is_output_reserved(cid));
    state.lock().unwrap().block = false;
    a.service_egress().unwrap();
    assert_eq!(state.lock().unwrap().sent.len(), 2);
    assert!(!a.egress.as_ref().unwrap().has_held());
    a.service_egress().unwrap();
    assert_eq!(state.lock().unwrap().sent.len(), 2); // No catch-up credit after late accept.
    // Free the two-packet initial congestion window, without selecting new output.
    for frame in state.lock().unwrap().sent.drain(..) {
        let frame = ntcp_ethernet::parse_ethernet(&frame).unwrap();
        let ip = ntcp_ip::parse(frame.payload, false).unwrap();
        b.input(b.now(), ip.ip, ip.traffic_class, ip.payload)
            .unwrap();
    }
    b.test_now = Some(b.now() + 250_000);
    b.endpoint.on_timeout(b.now(), BUDGET).unwrap();
    let mut bytes = [0; 2048];
    let ack = b
        .endpoint
        .poll_transmit(b.now(), &mut bytes, BUDGET)
        .unwrap()
        .packet
        .unwrap();
    a.input(a.now(), ack.ip, 0, &bytes[..ack.len]).unwrap();
    let deadline = a.endpoint.next_deadline().unwrap();
    assert!(deadline > a.now());
    a.test_now = Some(deadline);
    a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
    state.lock().unwrap().block = true;
    a.service_egress().unwrap();
    assert!(
        a.endpoint.is_output_reserved(cid),
        "now {} next {:?} info {:?}",
        a.now(),
        a.endpoint.next_deadline(),
        a.endpoint.transport_info(cid)
    );
    let second = a.now() + 1_000_000;
    // New obligation, new and later deadline: the first one has no effect on it.
    assert!(second > first);
    a.expire_egress(first).unwrap();
    assert!(a.endpoint.is_output_reserved(cid));
    a.expire_egress(second - 1).unwrap();
    assert!(a.endpoint.is_output_reserved(cid));
    a.expire_egress(second).unwrap();
    assert_eq!(a.endpoint.state(cid), Ok(ntcp::State::Closed));
}

#[test]
fn reserved_timestamp_rejection_preserves_scheduled_and_services_completions_while_blocked() {
    let (mut a, _, client, _, state) = pmtud_pair(None);
    state.lock().unwrap().capacity = 4;
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    flags(
        &mut a,
        client,
        ts::TX_SCHED | ts::TX_SOFTWARE | ts::TX_HARDWARE,
    );
    a.execute(client, Op::Write(vec![1; 100])).unwrap();
    a.enable_egress(1, None).unwrap();
    submit_one(&mut a, &state);
    assert_eq!(state.lock().unwrap().requests.len(), 1);
    assert_eq!(stage_count(&a, client, 1), 1);
    a.execute(client, Op::Write(vec![2; 8000])).unwrap();
    state.lock().unwrap().block = true;
    a.service_egress().unwrap();
    let deadline = a.now() + 1_000_000;
    state
        .lock()
        .unwrap()
        .completions
        .push_back(completion(1, TimestampSource::Software));
    a.poll_backend_timestamps().unwrap();
    assert_eq!(stage_count(&a, client, 0), 1);
    assert_eq!(stage_count(&a, client, 1), 2);
    {
        let mut s = state.lock().unwrap();
        s.enforce_mtu = true;
        s.mtu = Some(1400);
        s.block = false;
    }
    advance(&mut a, 1000);
    a.service_egress().unwrap();
    assert_eq!(stage_count(&a, client, 1), 2); // Scheduled is never rolled back.
    assert_eq!(a.sockets[&client].timestamps.reserved(), 1); // Only earlier HW remains.
    a.test_now = Some(deadline);
    a.expire_egress(a.now()).unwrap();
    assert_eq!(a.sockets[&client].timestamps.reserved(), 0);
    assert_eq!(stage_count(&a, client, 0), 1); // No fabricated transmit observation.
}

#[test]
fn reserved_stateless_rejection_is_best_effort_and_impossible_headers_abandon() {
    let (mut a, _, client, _, state) = pmtud_pair(None);
    a.enable_egress(1, None).unwrap();
    // A valid ACK to an unbound port generates an endpoint-owned stateless RST.
    let ip = ntcp::IpMetadata {
        source: "10.73.0.3".parse().unwrap(),
        destination: "10.73.0.2".parse().unwrap(),
    };
    let mut tcp = [0; 64];
    let len = ntcp::wire::encode(
        ip,
        ntcp::wire::Header {
            source_port: 6550,
            destination_port: 6551,
            sequence: 1,
            acknowledgment: 1,
            flags: ntcp::wire::ACK,
            window: 100,
            urgent_pointer: 0,
        },
        &[],
        &[],
        &mut tcp,
    )
    .unwrap();
    a.input(a.now(), ip, 0, &tcp[..len]).unwrap();
    state.lock().unwrap().enforce_mtu = true;
    state.lock().unwrap().mtu = Some(20); // Force synchronous rejection, even of a RST.
    a.service_egress().unwrap();
    assert!(take_offered(&state).is_some());
    // Stateless output is a best-effort discard: no held ticket or deadline.
    assert!(!a.egress.as_ref().unwrap().has_held());
    assert_eq!(
        a.endpoint.state(connection(&a, client)).unwrap(),
        ntcp::State::Established
    );

    // Native socket policy forbids source routes. Exercise the fail-closed
    // runtime branch with a core fixture that can retain impossible IP headers.
    let mut config = a.defaults.clone();
    config.ipv4_options_enabled = true;
    a.endpoint = Endpoint::new(config, [1; 32], 0, |_| true).unwrap();
    a.enable_egress(1, None).unwrap();
    let id = a
        .endpoint
        .connect_with_ipv4_options(
            a.now(),
            "10.73.0.2:1".parse().unwrap(),
            "10.73.0.3:2".parse().unwrap(),
            ntcp::OutgoingIpv4Options {
                source_route: Some(
                    ntcp::SourceRoute::new(&["10.73.0.4".parse().unwrap(); 9], false).unwrap(),
                ),
                ..Default::default()
            },
        )
        .unwrap();
    // The source-routed SYN is refused unsubmitted and waits for an MTU refresh.
    a.service_egress().unwrap();
    assert!(take_offered(&state).is_some());
    assert!(a.endpoint.is_output_reserved(id));
    a.endpoint.set_endpoint_first_hop_mtu(a.now(), 68).unwrap();
    a.egress.as_mut().unwrap().mtu_refreshed();
    a.service_egress().unwrap();
    assert!(!a.egress.as_ref().unwrap().has_held());
    assert_eq!(
        a.endpoint.close_reason(id).unwrap(),
        Some(CloseReason::Aborted)
    );
}

#[test]
fn reserved_late_direct_accept_and_prefix_expiry_keep_accepted_bytes() {
    let (mut a, mut b, client, server, state) = pmtud_pair(None);
    a.execute(client, Op::Write(vec![6; 8000])).unwrap();
    let (requests, results) = egress_with_refresh(&mut a, 1);
    a.reservation_timeout_us = 2_000_000;
    state.lock().unwrap().block = true;
    a.service_egress().unwrap();
    let cid = connection(&a, client);
    let before = a.endpoint.transport_info(cid).unwrap();
    advance(&mut a, before.rto_us + 1);
    a.expire_egress(a.now()).unwrap();
    state.lock().unwrap().block = false;
    a.service_egress().unwrap();
    assert_eq!(state.lock().unwrap().sent.len(), 1);
    assert!(!a.egress.as_ref().unwrap().has_held());
    a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
    assert_eq!(a.endpoint.transport_info(cid).unwrap().cwnd, before.cwnd);
    assert!(requests.try_recv().is_err());
    // ACK the first send and then retain a physically submitted repair prefix.
    deliver(&mut a, &mut b, &state);
    b.test_now = Some(b.now() + 250_000);
    b.endpoint.on_timeout(b.now(), BUDGET).unwrap();
    pump(&mut b, &mut a);
    assert_eq!(
        b.execute(server, Op::Read(8000)).unwrap().bytes,
        vec![6; 8000]
    );
    a.execute(client, Op::Write(vec![7; 8000])).unwrap();
    {
        let mut s = state.lock().unwrap();
        s.enforce_mtu = true;
        s.mtu = Some(1400);
    }
    a.service_egress().unwrap();
    let deadline = a.now() + 2_000_000;
    requests.try_recv().unwrap();
    refresh(&mut a, &results, 1400);
    // Accept one repaired prefix, then refuse the next repaired segment.
    let port = a.endpoint.tuple(cid).unwrap().local.port();
    state.lock().unwrap().block_after = Some((port, 1));
    a.service_egress().unwrap();
    assert!(a.endpoint.is_output_reserved(cid));
    let frame = state.lock().unwrap().sent.pop_front().unwrap();
    let frame = ntcp_ethernet::parse_ethernet(&frame).unwrap();
    let ip = ntcp_ip::parse(frame.payload, false).unwrap();
    let accepted = ntcp::wire::parse(ip.ip, ip.payload).unwrap().payload.len();
    b.input(b.now(), ip.ip, ip.traffic_class, ip.payload)
        .unwrap();
    assert_eq!(
        b.execute(server, Op::Read(8000)).unwrap().bytes,
        vec![7; accepted]
    );
    {
        let mut s = state.lock().unwrap();
        s.block_after = None;
        s.interrupted = true;
    }
    advance(&mut a, 1000);
    a.service_egress().unwrap();
    assert!(take_offered(&state).is_some());
    a.test_now = Some(deadline);
    a.expire_egress(a.now()).unwrap();
    assert_eq!(a.endpoint.state(cid).unwrap(), ntcp::State::Closed);
    assert!(state.lock().unwrap().sent.is_empty());
    assert_eq!(b.execute(server, Op::Read(8000)).unwrap_err(), EAGAIN);
    assert_eq!(
        b.endpoint.state(connection(&b, server)).unwrap(),
        ntcp::State::Established
    );
}

#[test]
fn reserved_repeated_interrupted_expires_only_owner_and_releases_commands() {
    for timestamped in [false, true] {
        let (mut a, mut b, client, _, state) = pmtud_pair(None);
        let listener = new(&mut b, SOCK_NONBLOCK);
        b.execute(listener, Op::Bind("10.73.0.3:16380".parse().unwrap()))
            .unwrap();
        b.execute(listener, Op::Listen(4)).unwrap();
        let healthy = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(healthy, Op::Connect("10.73.0.3:16380".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        pump(&mut a, &mut b);
        let peer = b
            .execute(listener, Op::Accept(SOCK_NONBLOCK))
            .unwrap()
            .value as u64;
        if timestamped {
            state.lock().unwrap().capacity = 2;
            flags(
                &mut a,
                client,
                ts::TX_SCHED | ts::TX_SOFTWARE | ts::TX_HARDWARE | ts::TX_ACK,
            );
        }
        a.execute(client, Op::Write(vec![5; 100])).unwrap();
        a.enable_egress(2, None).unwrap();
        let cid = connection(&a, client);
        state.lock().unwrap().interrupted = true;
        a.service_egress().unwrap();
        let deadline = a.now() + 1_000_000;
        let token = a.egress.as_ref().unwrap().attempt(cid);
        let packet = take_offered(&state);
        assert!(packet.is_some());
        let before = a.endpoint.transport_info(cid).unwrap();

        let file =
            unsafe { libc::memfd_create(c"interrupted-producer".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(file >= 0);
        let _file = crate::Retained(file);
        assert_eq!(unsafe { libc::write(file, b"file".as_ptr().cast(), 4) }, 4);
        let mut offset: libc::off_t = 0;
        let (reply, produced) = mpsc::sync_channel(1);
        let mut producer = Request {
            id: client,
            op: Op::Transfer {
                source: file,
                staging: [-1; 2],
                offset: Some((&mut offset as *mut libc::off_t) as usize),
                count: 4,
                flags: 0,
            },
            reply,
            deadline: None,
            send: None,
            closing: None,
        };
        let (reply, closed) = mpsc::sync_channel(1);
        let mut close = Request {
            id: client,
            op: Op::Close,
            reply,
            deadline: None,
            send: None,
            closing: None,
        };
        for _ in 0..4 {
            advance(&mut a, 200_000);
            assert!(!a.service(&mut producer));
            assert!(!a.service(&mut close));
            assert!(produced.try_recv().is_err());
            assert!(closed.try_recv().is_err());
            assert_eq!(offset, 0);
            a.service_egress().unwrap();
            assert_eq!(a.egress.as_ref().unwrap().attempt(cid), token);
            assert_eq!(take_offered(&state), packet);
            assert_eq!(
                a.endpoint.transport_info(cid).unwrap().unacked,
                before.unacked
            );
            assert!(state.lock().unwrap().sent.is_empty());
            assert!(state.lock().unwrap().requests.is_empty());
            assert_eq!(a.ports[0].ethernet.as_ref().unwrap().next_cookie, 1);
        }
        a.expire_egress(deadline - 1).unwrap();
        assert!(a.endpoint.is_output_reserved(cid));
        a.test_now = Some(deadline);
        a.expire_egress(a.now()).unwrap();
        assert!(!a.endpoint.is_output_reserved(cid));
        assert!(!a.egress.as_ref().unwrap().has_held());
        assert_eq!(a.endpoint.state(cid).unwrap(), ntcp::State::Closed);
        assert_eq!(
            a.endpoint.state(connection(&a, healthy)).unwrap(),
            ntcp::State::Established
        );
        assert!(state.lock().unwrap().sent.is_empty()); // Neither acceptance nor reset.
        assert_eq!(stage_count(&a, client, 0), 0);
        assert_eq!(stage_count(&a, client, 2), 0);
        assert_eq!(a.sockets[&client].timestamps.reserved(), 0);
        a.events();
        assert_eq!(a.sockets[&client].error, ECONNABORTED);
        assert!(a.service(&mut producer));
        assert!(produced.recv().unwrap().is_err());
        assert_eq!(offset, 0);
        // Last close waits for one egress turn over its now idle connection.
        assert!(!a.service(&mut close));
        a.service_egress().unwrap();
        assert!(a.service(&mut close));
        assert!(closed.recv().unwrap().is_ok());
        state.lock().unwrap().interrupted = false;
        a.execute(healthy, Op::Write(b"healthy".to_vec())).unwrap();
        submit_one(&mut a, &state);
        assert_eq!(state.lock().unwrap().sent.len(), 1);
        deliver(&mut a, &mut b, &state);
        assert_eq!(b.execute(peer, Op::Read(99)).unwrap().bytes, b"healthy");
    }
}

#[test]
fn reserved_unknown_interrupted_and_wrapped_cancellation_do_not_certify_rejection() {
    let (mut a, _, client, _, state) = pmtud_pair(None);
    a.execute(client, Op::Write(vec![1; 100])).unwrap();
    let (refreshes, _) = egress_with_refresh(&mut a, 1);
    state.lock().unwrap().output_error = Some(io::ErrorKind::Interrupted);
    assert_eq!(a.service_egress(), Err(EIO));
    // The ticket stays held: no deadline expires it and no MTU refresh is awaited.
    let cid = connection(&a, client);
    a.expire_egress(u64::MAX).unwrap();
    assert!(a.endpoint.is_output_reserved(cid));
    assert!(refreshes.try_recv().is_err());

    for errno in [EINTR, EMSGSIZE] {
        let (mut a, _, client, _, state) = pmtud_pair(None);
        state.lock().unwrap().capacity = 2;
        flags(&mut a, client, ts::TX_SOFTWARE | ts::TX_HARDWARE);
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
            .unwrap();
        a.execute(client, Op::Write(vec![1; 100])).unwrap();
        let (refreshes, _) = egress_with_refresh(&mut a, 1);
        submit_one(&mut a, &state);
        a.execute(client, Op::Write(vec![2; 100])).unwrap();
        state.lock().unwrap().cancel_error = Some(errno);
        assert_eq!(a.service_egress(), Err(EIO));
        let cid = connection(&a, client);
        a.expire_egress(u64::MAX).unwrap();
        assert!(a.endpoint.is_output_reserved(cid));
        assert!(refreshes.try_recv().is_err());
        assert_eq!(state.lock().unwrap().sent.len(), 1);
        assert_eq!(state.lock().unwrap().requests.len(), 1);
    }
}

#[test]
fn pacing_blocked_backend_retains_one_commit_and_resumes_at_core_deadline() {
    let (mut a, mut b, client, server, _) = paced_pair();
    let state = attach(&mut a, 0);
    a.enable_egress(1, None).unwrap();
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    a.execute(client, Op::Write(vec![9; 12000])).unwrap();
    let cid = connection(&a, client);
    state.lock().unwrap().block = true;
    a.service_egress().unwrap();
    let pending = take_offered(&state);
    let unsent = a.endpoint.transport_info(cid).unwrap().notsent_bytes;
    for _ in 0..2 {
        // The production egress path must not re-encode while blocked.
        advance(&mut a, 1000);
        a.service_egress().unwrap();
        assert_eq!(take_offered(&state), pending);
        assert_eq!(
            a.endpoint.transport_info(cid).unwrap().notsent_bytes,
            unsent
        );
    }
    assert_eq!(state.lock().unwrap().output_calls, 3);
    assert!(state.lock().unwrap().sent.is_empty());
    state.lock().unwrap().block = false;
    advance(&mut a, 1000);
    a.service_egress().unwrap();
    // The retained frame departs first and once; pacing may release its successor.
    let sent: Vec<_> = state.lock().unwrap().sent.drain(..).collect();
    assert_eq!(sent.first(), pending.as_ref());
    assert_eq!(
        sent.iter()
            .filter(|frame| Some(*frame) == pending.as_ref())
            .count(),
        1
    );
    for frame in &sent {
        let frame = ntcp_ethernet::parse_ethernet(frame).unwrap();
        let ip = ntcp_ip::parse(frame.payload, false).unwrap();
        b.input(b.now(), ip.ip, ip.traffic_class, ip.payload)
            .unwrap();
    }
    pump(&mut a, &mut b);
    let mut received = b.execute(server, Op::Read(BYTES)).unwrap().bytes;
    assert!(received.len() <= 2 * 1460);
    let calls = state.lock().unwrap().output_calls;
    a.service_egress().unwrap();
    assert_eq!(
        state.lock().unwrap().output_calls,
        calls,
        "must wait for pacing, not encode ahead"
    );
    for _ in 0..128 {
        if received.len() == 12000 {
            break;
        }
        pacing_tick(&mut a, &mut b);
        match b.execute(server, Op::Read(BYTES)) {
            Ok(reply) => received.extend(reply.bytes),
            Err(EAGAIN) => (),
            Err(error) => panic!("read: {error}"),
        }
    }
    assert_eq!(received, vec![9; 12000]);
}

// Two connections share one native-runtime owner and one copying backend.
fn scheduled_pair(capacity: usize) -> (Owner, Owner, [u64; 2], [u64; 2], Arc<Mutex<State>>) {
    scheduled_pair_gso(capacity, None)
}
fn scheduled_pair_gso(
    capacity: usize,
    gso: Option<ntcp::GsoLimits>,
) -> (Owner, Owner, [u64; 2], [u64; 2], Arc<Mutex<State>>) {
    let (mut a, mut b, first, server, state) = pmtud_pair(None);
    let listener = b
        .sockets
        .iter()
        .find(|(_, s)| matches!(s.handle, Handle::Listener(_)))
        .unwrap()
        .0
        .to_owned();
    let second = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(second, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    pump(&mut a, &mut b);
    let accepted = b
        .execute(listener, Op::Accept(SOCK_NONBLOCK))
        .unwrap()
        .value as u64;
    for id in [first, second] {
        a.execute(id, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1)).unwrap();
    }
    a.enable_egress(capacity, gso).unwrap();
    (a, b, [first, second], [server, accepted], state)
}
fn deliver_scheduled(a: &mut Owner, b: &mut Owner, state: &Arc<Mutex<State>>) {
    while let Some(frame) = state.lock().unwrap().sent.pop_front() {
        let frame = ntcp_ethernet::parse_ethernet(&frame).unwrap();
        b.input_ip(frame.payload, ntcp::RxPacketTimestamps::default());
    }
    for _ in 0..BUDGET {
        let Some(bytes) = poll_packet(b) else {
            break;
        };
        ingress(a, state, &bytes);
    }
    a.events();
    b.events();
}

#[test]
fn scheduled_unpaced_refills_within_one_service_even_at_capacity_one() {
    for capacity in [1, 32] {
        let (mut a, _, clients, _, state) = scheduled_pair(capacity);
        let cid = connection(&a, clients[0]);
        a.execute(clients[0], Op::Write(vec![7; 17000])).unwrap();
        // The unpaced jumbo-MSS initial window admits two segments without ACKs.
        a.service_egress().unwrap();
        let state = state.lock().unwrap();
        assert_eq!(state.sent.len(), 2, "capacity {capacity}");
        assert!(state.output_calls <= BUDGET);
        let progress = a.endpoint.send_progress(cid).unwrap();
        assert_eq!(
            progress
                .next_write_sequence
                .wrapping_sub(progress.unacknowledged_sequence),
            17000
        );
        assert!(a.output_wait() > std::time::Duration::ZERO);
    }
}

#[test]
fn scheduled_refill_after_accepting_a_held_retry() {
    let (mut a, _, clients, _, state) = scheduled_pair(1);
    a.execute(clients[0], Op::Write(vec![7; 17000])).unwrap();
    state.lock().unwrap().block = true;
    a.service_egress().unwrap();
    assert!(state.lock().unwrap().sent.is_empty());
    state.lock().unwrap().block = false;
    advance(&mut a, 1000);
    a.service_egress().unwrap();
    assert_eq!(state.lock().unwrap().sent.len(), 2);
    assert!(a.output_wait() > std::time::Duration::ZERO);
}

#[test]
fn scheduled_refill_budget_leaves_eligible_work_awake_but_not_blocked_work() {
    for capacity in [1, 32] {
        let (mut a, _, clients, _, state) = scheduled_pair(capacity);
        // Repair one already-selected jumbo obligation into > BUDGET frames.
        state.lock().unwrap().enforce_mtu = true;
        state.lock().unwrap().mtu = Some(200);
        a.execute(clients[0], Op::Write(vec![7; 8000])).unwrap();
        a.service_egress().unwrap();
        a.endpoint.set_endpoint_first_hop_mtu(a.now(), 200).unwrap();
        a.egress.as_mut().unwrap().mtu_refreshed();
        state.lock().unwrap().output_calls = 0;
        a.service_egress().unwrap();
        assert_eq!(state.lock().unwrap().sent.len(), BUDGET);
        assert_eq!(state.lock().unwrap().output_calls, BUDGET);
        assert_eq!(a.output_wait(), std::time::Duration::ZERO);
        state.lock().unwrap().block = true;
        a.service_egress().unwrap();
        assert_eq!(state.lock().unwrap().output_calls, BUDGET + 1);
        assert!(a.output_wait() > std::time::Duration::ZERO);
        a.service_egress().unwrap();
        assert_eq!(state.lock().unwrap().output_calls, BUDGET + 1);
    }
}

#[test]
fn scheduled_refill_rotates_healthy_owners_at_capacity_one() {
    let (mut a, _, clients, _, state) = scheduled_pair(1);
    for id in clients {
        a.execute(id, Op::Write(vec![7; 17000])).unwrap();
    }
    a.service_egress().unwrap();
    let state = state.lock().unwrap();
    assert_eq!(state.sent.len(), 4);
    let ports: Vec<_> = state.sent.iter().map(|bytes| &bytes[34..36]).collect();
    assert_ne!(ports[0], ports[1]);
    assert_eq!(ports[0], ports[2]);
    assert_eq!(ports[1], ports[3]);
}

#[test]
fn scheduled_refill_shares_service_with_healthy_owner_while_one_is_blocked() {
    let (mut a, _, clients, _, state) = scheduled_pair(2);
    let held = connection(&a, clients[0]);
    state.lock().unwrap().block_port = Some(a.endpoint.tuple(held).unwrap().local.port());
    for id in clients {
        a.execute(id, Op::Write(vec![7; 17000])).unwrap();
    }
    a.service_egress().unwrap();
    assert!(a.endpoint.is_output_reserved(held));
    assert_eq!(state.lock().unwrap().sent.len(), 2);
    assert_eq!(state.lock().unwrap().output_calls, 3);
    assert!(a.output_wait() > std::time::Duration::ZERO);
}

#[test]
fn scheduled_refill_does_not_spin_on_pacing_candidates() {
    let (mut a, _, client, _, state) = pmtud_paced_pair(
        None,
        Some(ntcp::PacingConfig {
            max_burst_segments: 1,
            max_bytes_per_second: Some(1_000_000),
            ..Default::default()
        }),
    );
    a.enable_egress(1, None).unwrap();
    a.execute(client, Op::Write(vec![7; 17000])).unwrap();
    a.service_egress().unwrap();
    assert_eq!(state.lock().unwrap().sent.len(), 1);
    assert!(a.output_wait() > std::time::Duration::ZERO);
    a.service_egress().unwrap();
    assert_eq!(state.lock().unwrap().output_calls, 1);
    assert!(a.output_wait() > std::time::Duration::ZERO);
}

#[test]
fn scheduled_blocked_owner_does_not_freeze_input_commands_timer_or_output() {
    let (mut a, mut b, clients, servers, state) = scheduled_pair(32);
    let held = connection(&a, clients[0]);
    let healthy = connection(&a, clients[1]);
    let port = a.endpoint.tuple(held).unwrap().local.port();
    state.lock().unwrap().block_port = Some(port);
    a.execute(clients[0], Op::Write(vec![1; 200])).unwrap();
    a.service_egress().unwrap();
    assert!(a.endpoint.is_output_reserved(held));
    assert_eq!(
        a.execute(clients[0], Op::Write(vec![2; 1])).unwrap_err(),
        EAGAIN
    );
    a.execute(clients[1], Op::Write(vec![3; 200])).unwrap();
    a.service_egress().unwrap();
    deliver_scheduled(&mut a, &mut b, &state);
    assert_eq!(
        b.execute(servers[1], Op::Read(200)).unwrap().bytes,
        vec![3; 200]
    );
    b.execute(servers[1], Op::Write(vec![4; 100])).unwrap();
    deliver_scheduled(&mut a, &mut b, &state);
    assert_eq!(
        a.execute(clients[1], Op::Read(100)).unwrap().bytes,
        vec![4; 100]
    );
    // Healthy delayed ACK/RTO timers remain serviceable with A's timer removed.
    advance(&mut a, 100_000);
    b.test_now = Some(a.now());
    a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
    b.endpoint.on_timeout(b.now(), BUDGET).unwrap();
    a.service_egress().unwrap();
    deliver_scheduled(&mut a, &mut b, &state);
    assert!(!a.endpoint.is_output_reserved(healthy));
    assert_eq!(
        a.endpoint
            .send_progress(healthy)
            .unwrap()
            .unacknowledged_sequence,
        a.endpoint
            .send_progress(healthy)
            .unwrap()
            .next_write_sequence
    );
    assert!(a.output_wait() > std::time::Duration::ZERO);
    let socket = new(&mut a, SOCK_NONBLOCK);
    a.execute(socket, Op::Bind("10.73.0.2:16400".parse().unwrap()))
        .unwrap();
    a.execute(socket, Op::Listen(2)).unwrap();
    a.execute(socket, Op::Close).unwrap();
    a.test_now = Some(1_001_000);
    a.expire_egress(a.now()).unwrap();
    assert!(!a.endpoint.is_output_reserved(held));
    assert_eq!(a.endpoint.state(held), Ok(ntcp::State::Closed));
    assert_eq!(a.endpoint.state(healthy), Ok(ntcp::State::Established));
    assert!(a.execute(clients[1], Op::Write(vec![5; 20])).is_ok());
}

#[test]
fn scheduled_rx_retains_observed_timestamp_and_full_queue_stops_reading() {
    let (mut a, mut b, clients, servers, state) = scheduled_pair(2);
    let held = connection(&a, clients[0]);
    a.endpoint.set_rx_timestamp_capacity(held, 8).unwrap();
    state.lock().unwrap().block_port = Some(a.endpoint.tuple(held).unwrap().local.port());
    state.lock().unwrap().rx_stamps.software = Some(PacketTimestamp {
        value: 123456789,
        source: TimestampSource::Software,
        point: TimestampPoint::UserReceive,
        clock: ntcp_io::ClockDescriptor {
            domain: ClockDomain::Realtime,
            unit: TimestampUnit::Nanoseconds,
        },
    });
    a.execute(clients[0], Op::Write(vec![1; 10])).unwrap();
    a.service_egress().unwrap();
    b.execute(servers[0], Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    b.execute(servers[0], Op::Write(vec![7; 10])).unwrap();
    let bytes = poll_packet(&mut b).unwrap();
    ingress(&mut a, &state, &bytes);
    // Duplicate also retained; no premature ACK/SACK processing on the held TCB.
    ingress(&mut a, &state, &bytes);
    assert_eq!(a.endpoint.readable_bytes(held).unwrap(), 0);
    ingress(&mut a, &state, &bytes);
    let receives = state.lock().unwrap().receives;
    assert_eq!(state.lock().unwrap().incoming.len(), 1);
    a.receive_batch(&mut vec![0; 65549]).unwrap();
    assert_eq!(state.lock().unwrap().receives, receives);
    // Clear only A; replay at current protocol time, not observation time.
    state.lock().unwrap().block_port = None;
    advance(&mut a, 50_000);
    a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
    a.service_egress().unwrap();
    a.receive_batch(&mut vec![0; 65549]).unwrap();
    assert!(state.lock().unwrap().incoming.is_empty());
    let stamp = a.endpoint.peek_rx_timestamps(held, 10).unwrap().unwrap();
    assert_eq!(stamp.timestamps.software.unwrap().value, 123456789);
    assert_eq!(
        a.execute(clients[0], Op::Read(10)).unwrap().bytes,
        vec![7; 10]
    );
}

#[test]
fn scheduled_capacity_one_backpressures_output_not_other_commands_and_expiry_is_per_owner() {
    let (mut a, mut b, clients, servers, state) = scheduled_pair(1);
    state.lock().unwrap().block_port = Some(
        a.endpoint
            .tuple(connection(&a, clients[0]))
            .unwrap()
            .local
            .port(),
    );
    a.execute(clients[0], Op::Write(vec![1; 10])).unwrap();
    a.service_egress().unwrap();
    a.execute(clients[1], Op::Write(vec![2; 10])).unwrap();
    a.service_egress().unwrap();
    assert!(state.lock().unwrap().sent.is_empty());
    a.test_now = Some(1_001_000);
    a.expire_egress(a.now()).unwrap();
    for _ in 0..4 {
        a.service_egress().unwrap();
    }
    deliver_scheduled(&mut a, &mut b, &state);
    assert_eq!(
        b.execute(servers[1], Op::Read(10)).unwrap().bytes,
        vec![2; 10]
    );
}

#[test]
fn scheduled_mtu_prefix_repair_keeps_deadline_and_other_owner_alive() {
    let (mut a, mut b, clients, servers, state) = scheduled_pair(4);
    let held = connection(&a, clients[0]);
    let (refresh, request, result) = super::super::output::MtuRefresh::fixture();
    a.ports[0].mtu_refresh = Some(refresh);
    state.lock().unwrap().enforce_mtu = true;
    state.lock().unwrap().mtu = Some(1400);
    a.execute(clients[0], Op::Write(vec![7; 8000])).unwrap();
    a.service_egress().unwrap();
    request.try_recv().unwrap();
    assert!(a.endpoint.is_output_reserved(held));
    a.execute(clients[1], Op::Write(vec![4; 20])).unwrap();
    a.service_egress().unwrap();
    deliver_scheduled(&mut a, &mut b, &state);
    assert_eq!(
        b.execute(servers[1], Op::Read(20)).unwrap().bytes,
        vec![4; 20]
    );
    result.send(Ok(Some(1400))).unwrap();
    a.poll_mtu_refresh();
    // Interleaved refill also attempts the suffix: block it after one prefix.
    {
        let mut state = state.lock().unwrap();
        state.block_after = Some((
            a.endpoint.tuple(held).unwrap().local.port(),
            state.sent.len() + 1,
        ));
    }
    a.service_egress().unwrap();
    assert!(a.endpoint.is_output_reserved(held)); // Prefix accepted, suffix retained.
    assert!(state.lock().unwrap().sent.iter().all(|p| p.len() <= 1414));
    state.lock().unwrap().block_port = Some(a.endpoint.tuple(held).unwrap().local.port());
    advance(&mut a, 500_000);
    a.service_egress().unwrap();
    a.test_now = Some(1_001_000);
    a.expire_egress(a.now()).unwrap();
    assert_eq!(a.endpoint.state(held), Ok(ntcp::State::Closed));
    assert_eq!(
        a.endpoint.state(connection(&a, clients[1])),
        Ok(ntcp::State::Established)
    );
}

#[test]
fn scheduled_guard_precedes_foreign_buffers_close_and_options() {
    let (mut a, _, clients, _, state) = scheduled_pair(2);
    let cid = connection(&a, clients[0]);
    state.lock().unwrap().block_port = Some(a.endpoint.tuple(cid).unwrap().local.port());
    a.execute(clients[0], Op::Write(vec![7; 50])).unwrap();
    a.service_egress().unwrap();
    for op in [
        Op::Send(vec![(usize::MAX, 4)], 0),
        Op::Set(IPPROTO_TCP, TCP_CORK, 1),
        Op::Close,
    ] {
        let (reply, response) = mpsc::sync_channel(1);
        let mut request = Request {
            id: clients[0],
            op,
            reply,
            deadline: None,
            send: None,
            closing: None,
        };
        assert!(!a.service(&mut request));
        assert!(request.send.is_none());
        assert!(response.try_recv().is_err());
    }
    assert!(!a.sockets[&clients[0]].cork);
    // Readiness scans must not wait for A before querying B.
    assert_eq!(a.execute(clients[0], Op::Ready).unwrap().value, 0);
    assert_ne!(
        a.execute(clients[1], Op::Ready).unwrap().value & EPOLLOUT,
        0
    );
    a.execute(clients[1], Op::Set(IPPROTO_TCP, TCP_CORK, 1))
        .unwrap();
    assert!(a.sockets[&clients[1]].cork);
}

#[test]
fn scheduled_unknown_error_is_fatal_without_rejection_or_retry() {
    let (mut a, _, clients, _, state) = scheduled_pair(2);
    let cid = connection(&a, clients[0]);
    a.execute(clients[0], Op::Write(vec![1; 100])).unwrap();
    state.lock().unwrap().output_error = Some(io::ErrorKind::Interrupted);
    assert_eq!(a.service_egress(), Err(EIO));
    assert!(a.endpoint.is_output_reserved(cid));
    assert_eq!(state.lock().unwrap().output_calls, 1);
    assert_eq!(a.endpoint.state(cid), Ok(ntcp::State::Established));
    assert!(state.lock().unwrap().sent.is_empty());
    assert!(state.lock().unwrap().cancelled.is_empty());
}

#[test]
fn scheduled_stateless_lane_is_bounded_and_expires_without_aborting_connections() {
    let (mut a, _, clients, _, state) = scheduled_pair(2);
    let ip = ntcp::IpMetadata {
        source: "10.73.0.3".parse().unwrap(),
        destination: "10.73.0.2".parse().unwrap(),
    };
    let mut tcp = [0; 64];
    let len = ntcp::wire::encode(
        ip,
        ntcp::wire::Header {
            source_port: 6550,
            destination_port: 6551,
            sequence: 1,
            acknowledgment: 1,
            flags: ntcp::wire::ACK,
            window: 100,
            urgent_pointer: 0,
        },
        &[],
        &[],
        &mut tcp,
    )
    .unwrap();
    state.lock().unwrap().block_port = Some(6551);
    a.input(a.now(), ip, 0, &tcp[..len]).unwrap();
    a.service_egress().unwrap();
    for _ in 0..8 {
        a.input(a.now(), ip, 0, &tcp[..len]).unwrap();
    }
    a.execute(clients[0], Op::Write(vec![8; 20])).unwrap();
    a.service_egress().unwrap();
    assert_eq!(state.lock().unwrap().sent.len(), 1);
    assert!(a.output_wait() > std::time::Duration::ZERO);
    a.test_now = Some(1_001_000);
    a.expire_egress(a.now()).unwrap();
    assert_eq!(
        a.endpoint.state(connection(&a, clients[0])),
        Ok(ntcp::State::Established)
    );
    state.lock().unwrap().block_port = None;
    a.service_egress().unwrap();
    assert!(state.lock().unwrap().sent.len() > 1);
}

#[test]
fn scheduled_out_of_order_replay_keeps_tcp_options_and_original_range_timestamps() {
    let (mut a, mut b, clients, servers, state) = scheduled_pair(4);
    let cid = connection(&a, clients[0]);
    a.endpoint.set_rx_timestamp_capacity(cid, 8).unwrap();
    state.lock().unwrap().block_port = Some(a.endpoint.tuple(cid).unwrap().local.port());
    a.execute(clients[0], Op::Write(vec![1; 10])).unwrap();
    a.service_egress().unwrap();
    b.execute(servers[0], Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    b.execute(servers[0], Op::Write(vec![9; 16000])).unwrap();
    let first = poll_packet(&mut b).unwrap();
    let second = poll_packet(&mut b).unwrap();
    for (packet, observed) in [(&second, 222), (&first, 333)] {
        state.lock().unwrap().rx_stamps.software = Some(PacketTimestamp {
            value: observed,
            source: TimestampSource::Software,
            point: TimestampPoint::UserReceive,
            clock: ntcp_io::ClockDescriptor {
                domain: ClockDomain::Realtime,
                unit: TimestampUnit::Nanoseconds,
            },
        });
        ingress(&mut a, &state, packet);
    }
    assert_eq!(a.endpoint.readable_bytes(cid).unwrap(), 0);
    state.lock().unwrap().block_port = None;
    advance(&mut a, 100_000);
    a.service_egress().unwrap();
    a.receive_batch(&mut vec![0; 65549]).unwrap();
    assert_eq!(
        a.endpoint
            .peek_rx_timestamps(cid, 16000)
            .unwrap()
            .unwrap()
            .timestamps
            .software
            .unwrap()
            .value,
        222
    );
    assert_eq!(
        a.execute(clients[0], Op::Read(16000)).unwrap().bytes,
        vec![9; 16000]
    );
}

#[test]
fn scheduled_timestamp_rejection_and_late_completion_are_owner_local() {
    let (mut a, _, clients, _, state) = scheduled_pair(4);
    state.lock().unwrap().capacity = 8;
    for id in clients {
        flags(&mut a, id, ts::TX_SCHED | ts::TX_SOFTWARE | ts::TX_HARDWARE);
    }
    a.execute(clients[0], Op::Write(vec![1; 100])).unwrap();
    a.service_egress().unwrap();
    let cookie = state.lock().unwrap().requests[0].cookie;
    a.execute(clients[0], Op::Write(vec![2; 8000])).unwrap();
    let port = a
        .endpoint
        .tuple(connection(&a, clients[0]))
        .unwrap()
        .local
        .port();
    state.lock().unwrap().block_port = Some(port);
    a.service_egress().unwrap();
    a.execute(clients[1], Op::Write(vec![3; 100])).unwrap();
    a.service_egress().unwrap();
    state
        .lock()
        .unwrap()
        .completions
        .push_back(completion(cookie, TimestampSource::Software));
    a.poll_backend_timestamps().unwrap();
    assert_eq!(stage_count(&a, clients[0], 0), 1);
    assert_eq!(stage_count(&a, clients[0], 1), 2);
    state.lock().unwrap().enforce_mtu = true;
    state.lock().unwrap().mtu = Some(1400);
    advance(&mut a, 1000);
    a.service_egress().unwrap();
    assert_eq!(a.sockets[&clients[0]].timestamps.reserved(), 1); // Earlier HW only.
    assert_eq!(a.sockets[&clients[1]].timestamps.reserved(), 2);
    a.test_now = Some(1_001_000);
    a.expire_egress(a.now()).unwrap();
    assert_eq!(a.sockets[&clients[0]].timestamps.reserved(), 0);
    assert_eq!(a.sockets[&clients[1]].timestamps.reserved(), 2);
    state
        .lock()
        .unwrap()
        .completions
        .push_back(completion(cookie, TimestampSource::Hardware));
    a.poll_backend_timestamps().unwrap();
    assert_eq!(stage_count(&a, clients[0], 0), 1); // Cancelled late HW not fabricated.
}

#[test]
fn scheduled_full_admission_rotates_stateless_with_continuously_ready_tcp() {
    let (mut a, _, clients, _, state) = scheduled_pair(1);
    for id in clients {
        a.execute(id, Op::Write(vec![1; 50000])).unwrap();
    }
    let ip = ntcp::IpMetadata {
        source: "10.73.0.3".parse().unwrap(),
        destination: "10.73.0.2".parse().unwrap(),
    };
    let mut tcp = [0; 64];
    let len = ntcp::wire::encode(
        ip,
        ntcp::wire::Header {
            source_port: 6550,
            destination_port: 6551,
            sequence: 1,
            acknowledgment: 1,
            flags: ntcp::wire::ACK,
            window: 100,
            urgent_pointer: 0,
        },
        &[],
        &[],
        &mut tcp,
    )
    .unwrap();
    a.input(a.now(), ip, 0, &tcp[..len]).unwrap();
    for _ in 0..3 {
        a.service_egress().unwrap();
    }
    assert!(
        state
            .lock()
            .unwrap()
            .sent
            .iter()
            .any(|bytes| bytes[34..36] == 6551u16.to_be_bytes())
    );
}

#[test]
fn scheduled_last_close_waits_for_its_fin_submission_not_other_owners() {
    let (mut a, mut b, clients, servers, state) = scheduled_pair(2);
    let cid = connection(&a, clients[0]);
    state.lock().unwrap().block_port = Some(a.endpoint.tuple(cid).unwrap().local.port());
    let (reply, response) = mpsc::sync_channel(1);
    let mut close = Request {
        id: clients[0],
        op: Op::Close,
        reply,
        deadline: None,
        send: None,
        closing: None,
    };
    assert!(!a.service(&mut close));
    assert!(!a.sockets.contains_key(&clients[0]));
    assert_eq!(close.closing, Some((cid, LingerWait::Off)));
    a.service_egress().unwrap();
    assert!(a.endpoint.is_output_reserved(cid));
    assert!(!a.service(&mut close));
    assert!(response.try_recv().is_err());
    a.execute(clients[1], Op::Write(vec![4; 20])).unwrap();
    a.service_egress().unwrap();
    deliver_scheduled(&mut a, &mut b, &state);
    assert_eq!(
        b.execute(servers[1], Op::Read(20)).unwrap().bytes,
        vec![4; 20]
    );
    state.lock().unwrap().block_port = None;
    advance(&mut a, 1000);
    a.service_egress().unwrap();
    // Acceptance refreshes readiness; the following bounded poll clears the
    // now-idle candidate without selecting a duplicate FIN.
    a.service_egress().unwrap();
    assert!(a.service(&mut close));
    assert_eq!(response.recv().unwrap().unwrap().value, 0);
    deliver_scheduled(&mut a, &mut b, &state);
    assert_eq!(b.execute(servers[0], Op::Read(1)).unwrap().value, 0);
}

// Flags and payload length of each TCP segment handed to the backend and
// not yet delivered.
fn sent_segments(state: &Arc<Mutex<State>>) -> Vec<(u8, usize)> {
    state
        .lock()
        .unwrap()
        .sent
        .iter()
        .map(|frame| {
            let ip = ntcp_ip::parse(datagram(frame), false).unwrap();
            let tcp = ntcp::wire::parse(ip.ip, ip.payload).unwrap();
            (tcp.header.flags, tcp.payload.len())
        })
        .collect()
}
fn close_request(id: u64) -> (Request, mpsc::Receiver<Result<Reply>>) {
    let (reply, response) = mpsc::sync_channel(1);
    let request = Request {
        id,
        op: Op::Close,
        reply,
        deadline: None,
        send: None,
        closing: None,
    };
    (request, response)
}
fn linger_bytes(value: [i32; 2]) -> Vec<u8> {
    value.iter().flat_map(|v| v.to_ne_bytes()).collect()
}

#[test]
fn zero_linger_close_resets_and_discards_unsent_data() {
    let (mut a, mut b, clients, servers, state) = scheduled_pair(2);
    let cid = connection(&a, clients[0]);
    a.execute(clients[0], Op::SetLinger(1, 0)).unwrap();
    a.execute(clients[0], Op::Write(vec![5; 20])).unwrap();
    let (mut close, response) = close_request(clients[0]);
    assert!(!a.service(&mut close));
    assert_eq!(close.closing, Some((cid, LingerWait::Off)));
    assert_eq!(a.endpoint.state(cid), Ok(ntcp::State::Closed));
    a.service_egress().unwrap();
    assert!(a.service(&mut close));
    assert_eq!(response.recv().unwrap().unwrap().value, 0);
    // The RST alone: the 20 queued bytes and the FIN are never sent.
    let segments = sent_segments(&state);
    assert_eq!(segments.len(), 1);
    assert_ne!(segments[0].0 & ntcp::wire::RST, 0);
    assert_eq!(segments[0].1, 0);
    deliver_scheduled(&mut a, &mut b, &state);
    assert_eq!(b.execute(servers[0], Op::Read(20)).unwrap_err(), ECONNRESET);
    assert_eq!(a.endpoint.time_wait_connections(), 0);
}

#[test]
fn zero_linger_after_shutdown_resets_but_time_wait_stays() {
    let (mut a, mut b, clients, servers, state) = scheduled_pair(2);
    let cids = clients.map(|id| connection(&a, id));
    for id in clients {
        a.execute(id, Op::SetLinger(1, 0)).unwrap();
        a.execute(id, Op::Shutdown(SHUT_WR)).unwrap();
    }
    b.execute(servers[1], Op::Shutdown(SHUT_WR)).unwrap();
    a.service_egress().unwrap();
    deliver_scheduled(&mut a, &mut b, &state);
    a.service_egress().unwrap();
    deliver_scheduled(&mut a, &mut b, &state);
    assert_eq!(a.endpoint.state(cids[0]), Ok(ntcp::State::FinWait2));
    assert_eq!(a.endpoint.state(cids[1]), Ok(ntcp::State::TimeWait));
    assert!(state.lock().unwrap().sent.is_empty());
    let mut responses = Vec::new();
    for id in clients {
        let (mut close, response) = close_request(id);
        assert!(!a.service(&mut close));
        a.service_egress().unwrap();
        assert!(a.service(&mut close));
        responses.push(response);
    }
    for response in responses {
        assert_eq!(response.recv().unwrap().unwrap().value, 0);
    }
    // Linux tcp_disconnect resets FIN-WAIT-2; a TIME-WAIT socket is already
    // CLOSE to tcp_close, so its TIME-WAIT is kept and it sends nothing.
    let segments = sent_segments(&state);
    assert_eq!(segments.len(), 1);
    assert_ne!(segments[0].0 & ntcp::wire::RST, 0);
    assert_eq!(a.endpoint.state(cids[0]), Ok(ntcp::State::Closed));
    assert_eq!(a.endpoint.state(cids[1]), Ok(ntcp::State::TimeWait));
}

#[test]
fn lingering_close_returns_once_its_fin_is_acknowledged_even_nonblocking() {
    let (mut a, mut b, clients, servers, state) = scheduled_pair(2);
    let cid = connection(&a, clients[0]);
    assert_ne!(a.sockets[&clients[0]].flags & SOCK_NONBLOCK, 0);
    a.execute(clients[0], Op::SetLinger(1, 30)).unwrap();
    a.execute(clients[0], Op::Write(vec![5; 20])).unwrap();
    let (mut close, response) = close_request(clients[0]);
    assert!(!a.service(&mut close));
    assert!(matches!(close.closing, Some((id, LingerWait::Until(_))) if id == cid));
    a.service_egress().unwrap();
    assert_eq!(a.endpoint.state(cid), Ok(ntcp::State::FinWait1));
    assert!(!a.service(&mut close));
    assert!(response.try_recv().is_err());
    deliver_scheduled(&mut a, &mut b, &state);
    assert_eq!(a.endpoint.state(cid), Ok(ntcp::State::FinWait2));
    assert!(a.service(&mut close));
    assert_eq!(response.recv().unwrap().unwrap().value, 0);
    assert_eq!(
        b.execute(servers[0], Op::Read(20)).unwrap().bytes,
        vec![5; 20]
    );
}

#[test]
fn lingering_close_returns_at_its_time_and_the_close_continues() {
    let (mut a, mut b, clients, servers, state) = scheduled_pair(2);
    let cids = clients.map(|id| connection(&a, id));
    a.execute(clients[0], Op::SetLinger(1, 30)).unwrap();
    // Clearing l_onoff turns lingering off whatever time remains.
    a.execute(clients[1], Op::SetLinger(1, 30)).unwrap();
    a.execute(clients[1], Op::SetLinger(0, 0)).unwrap();
    assert_eq!(
        a.execute(clients[1], Op::GetLinger).unwrap().bytes,
        linger_bytes([0, 30])
    );
    let mut closes = Vec::new();
    for id in clients {
        a.execute(id, Op::Write(vec![5; 20])).unwrap();
        let (mut close, response) = close_request(id);
        assert!(!a.service(&mut close));
        closes.push((close, response));
    }
    a.service_egress().unwrap();
    assert_eq!(closes[1].0.closing, Some((cids[1], LingerWait::Off)));
    assert!(a.service(&mut closes[1].0));
    assert_eq!(a.endpoint.state(cids[1]), Ok(ntcp::State::FinWait1));
    assert!(!a.service(&mut closes[0].0));
    // The linger time runs out before the peer acknowledges the FIN.
    closes[0].0.closing = Some((cids[0], LingerWait::Until(Instant::now())));
    assert!(a.service(&mut closes[0].0));
    for (_, response) in &closes {
        assert_eq!(response.recv().unwrap().unwrap().value, 0);
    }
    // Linux returns from close without aborting: no RST, the FIN stands.
    assert_eq!(a.endpoint.state(cids[0]), Ok(ntcp::State::FinWait1));
    assert!(
        sent_segments(&state)
            .iter()
            .all(|&(flags, _)| flags & ntcp::wire::RST == 0)
    );
    deliver_scheduled(&mut a, &mut b, &state);
    for (id, cid) in servers.into_iter().zip(cids) {
        assert_eq!(a.endpoint.state(cid), Ok(ntcp::State::FinWait2));
        assert_eq!(b.execute(id, Op::Read(20)).unwrap().bytes, vec![5; 20]);
        assert_eq!(b.execute(id, Op::Read(20)).unwrap().value, 0);
    }
}

#[test]
fn accepted_socket_inherits_the_listener_linger_it_was_created_with() {
    let (mut a, _) = pmtud_owner(2, 9000, None, None);
    let (mut b, _) = pmtud_owner(3, 9000, None, None);
    let listen = new(&mut b, SOCK_NONBLOCK);
    b.execute(listen, Op::Bind("10.73.0.3:16379".parse().unwrap()))
        .unwrap();
    b.execute(listen, Op::Listen(16)).unwrap();
    b.execute(listen, Op::SetLinger(1, 7)).unwrap();
    let client = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(client, Op::Connect("10.73.0.3:16379".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    pump(&mut a, &mut b);
    // Linux sk_clone_lock copies the listener once the handshake completes;
    // a later change to the listener is not the child's.
    b.execute(listen, Op::SetLinger(0, 9)).unwrap();
    let server = b.execute(listen, Op::Accept(SOCK_NONBLOCK)).unwrap().value as u64;
    for (id, expected) in [(server, [1, 7]), (listen, [0, 7])] {
        assert_eq!(
            b.execute(id, Op::GetLinger).unwrap().bytes,
            linger_bytes(expected)
        );
    }
    assert_eq!(
        a.execute(client, Op::GetLinger).unwrap().bytes,
        linger_bytes([0, 0])
    );
}

const SOFTWARE_GSO: ntcp::GsoLimits = ntcp::GsoLimits {
    max_bytes: 65536,
    max_segments: 4,
};

fn held_segmentation(a: &Owner, cid: ConnectionId) -> Option<ntcp::TransmitSegmentation> {
    a.endpoint
        .transmit_segmentation(a.egress.as_ref().unwrap().attempt(cid))
}

#[test]
fn software_gso_wire_matches_scalar_and_capacity_one_refills_second_owner() {
    let mut packets = Vec::new();
    for gso in [None, Some(SOFTWARE_GSO)] {
        let (mut a, _, clients, _, state) = scheduled_pair_gso(1, gso);
        let cid = connection(&a, clients[0]);
        a.execute(clients[0], Op::Write(vec![7; 26000])).unwrap();
        state.lock().unwrap().block = true;
        a.service_egress().unwrap();
        let descriptor = held_segmentation(&a, cid);
        assert_eq!(descriptor.is_some(), gso.is_some());
        if let Some(d) = descriptor {
            assert!(d.payload_len >= 2 * d.segment_payload_len);
        }
        a.execute(clients[1], Op::Write(vec![8; 26000])).unwrap();
        state.lock().unwrap().block = false;
        advance(&mut a, 1000);
        a.service_egress().unwrap();
        let sent = state.lock().unwrap().sent.clone();
        assert_eq!(sent.len(), 4);
        assert!(state.lock().unwrap().output_calls <= BUDGET + 1);
        // Range owners keep capacity one until the suffix finishes; the next
        // owner still receives service in this call, not on an ACK round trip.
        let mut bases = [None; 2];
        let ports = clients.map(|id| a.endpoint.tuple(connection(&a, id)).unwrap().local.port());
        let mut by_port: Vec<_> = sent
            .into_iter()
            .map(|mut packet| {
                // Independent native allocations also change tuple-derived ISNs.
                // Validate each real checksum before comparing the same logical
                // streams relative to their observed tuple/sequence origins.
                let ip = ntcp_ip::parse(&packet[14..], false).unwrap();
                let tcp = ntcp::wire::parse(ip.ip, ip.payload).unwrap();
                let index = ports
                    .iter()
                    .position(|&p| p == tcp.header.source_port)
                    .unwrap();
                let (seq, ack) =
                    *bases[index].get_or_insert((tcp.header.sequence, tcp.header.acknowledgment));
                let sequence = tcp.header.sequence.wrapping_sub(seq);
                let acknowledgment = tcp.header.acknowledgment.wrapping_sub(ack);
                packet[34..36].copy_from_slice(&(index as u16).to_be_bytes());
                packet[38..42].copy_from_slice(&sequence.to_be_bytes());
                packet[42..46].copy_from_slice(&acknowledgment.to_be_bytes());
                packet[50..52].fill(0);
                packet
            })
            .collect();
        by_port.sort_by_key(|packet| u16::from_be_bytes(packet[34..36].try_into().unwrap()));
        packets.push(by_port);
    }
    assert_eq!(packets[0], packets[1]);
}

#[test]
fn software_gso_midrange_block_replays_ingress_only_after_final_segment() {
    let (mut a, mut b, clients, servers, state) = scheduled_pair_gso(1, Some(SOFTWARE_GSO));
    let cid = connection(&a, clients[0]);
    a.execute(clients[0], Op::Write(vec![7; 26000])).unwrap();
    state.lock().unwrap().block_after = Some((a.endpoint.tuple(cid).unwrap().local.port(), 1));
    a.service_egress().unwrap();
    let descriptor = held_segmentation(&a, cid).unwrap();
    assert!(descriptor.payload_len >= 2 * descriptor.segment_payload_len);
    assert_eq!(state.lock().unwrap().sent.len(), 1);
    let attempt = a.egress.as_ref().unwrap().attempt(cid);
    b.execute(servers[0], Op::Write(vec![9; 10])).unwrap();
    ingress(&mut a, &state, &poll_packet(&mut b).unwrap());
    assert_eq!(a.endpoint.readable_bytes(cid).unwrap(), 0);
    advance(&mut a, 1000);
    a.service_egress().unwrap();
    assert_eq!(a.egress.as_ref().unwrap().attempt(cid), attempt);
    assert_eq!(state.lock().unwrap().sent.len(), 1);
    state.lock().unwrap().block_after = None;
    advance(&mut a, 1000);
    a.service_egress().unwrap();
    assert!(!a.endpoint.is_output_reserved(cid));
    assert_eq!(state.lock().unwrap().sent.len(), 2);
    a.receive_batch(&mut vec![0; 65549]).unwrap();
    assert_eq!(
        a.execute(clients[0], Op::Read(10)).unwrap().bytes,
        vec![9; 10]
    );
    assert!(!a.endpoint.accept_transmit(a.now(), attempt).unwrap());
}

#[test]
fn software_gso_midrange_mtu_shrink_preserves_suffix_and_original_deadline() {
    for expire in [false, true] {
        let (mut a, mut b, clients, servers, state) = scheduled_pair_gso(2, Some(SOFTWARE_GSO));
        let cid = connection(&a, clients[0]);
        let port = a.endpoint.tuple(cid).unwrap().local.port();
        a.execute(clients[0], Op::Write(vec![7; 26000])).unwrap();
        state.lock().unwrap().block = true;
        a.service_egress().unwrap();
        let descriptor = held_segmentation(&a, cid).unwrap();
        {
            let mut state = state.lock().unwrap();
            state.block = false;
            state.block_after = Some((port, 1));
        }
        advance(&mut a, 500_000);
        a.service_egress().unwrap();
        assert_eq!(state.lock().unwrap().sent.len(), 1);
        assert_eq!(held_segmentation(&a, cid), Some(descriptor));
        let rejected = a.egress.as_ref().unwrap().attempt(cid);
        {
            let mut state = state.lock().unwrap();
            state.enforce_mtu = true;
            state.mtu = Some(1400);
        }
        advance(&mut a, 1000);
        a.service_egress().unwrap(); // EMSGSIZE on the already-selected suffix.
        assert!(!a.endpoint.accept_transmit(a.now(), rejected).unwrap());
        a.endpoint
            .set_endpoint_first_hop_mtu(a.now(), 1400)
            .unwrap();
        a.egress.as_mut().unwrap().mtu_refreshed();
        state.lock().unwrap().block_after = Some((port, 2));
        a.service_egress().unwrap();
        assert_eq!(state.lock().unwrap().sent.len(), 2);
        assert_eq!(held_segmentation(&a, cid), Some(descriptor));
        let accepted: usize = state
            .lock()
            .unwrap()
            .sent
            .iter()
            .map(|frame| {
                let ip = ntcp_ip::parse(&frame[14..], false).unwrap();
                ntcp::wire::parse(ip.ip, ip.payload).unwrap().payload.len()
            })
            .sum();
        assert!(accepted > descriptor.segment_payload_len && accepted < descriptor.payload_len);
        // A different owner can still submit while this suffix is blocked.
        a.execute(clients[1], Op::Write(vec![8; 10])).unwrap();
        a.service_egress().unwrap();
        assert_eq!(state.lock().unwrap().sent.len(), 3);
        if expire {
            // First block was at 1000, not the later accept or MTU rejection.
            a.test_now = Some(1_001_000);
            a.expire_egress(a.now()).unwrap();
            assert_eq!(a.endpoint.state(cid), Ok(ntcp::State::Closed));
            assert_eq!(
                a.endpoint.state(connection(&a, clients[1])),
                Ok(ntcp::State::Established)
            );
            assert_eq!(state.lock().unwrap().sent.len(), 3);
        } else {
            state.lock().unwrap().block_after = None;
            advance(&mut a, 1000);
            a.service_egress().unwrap();
            assert!(!a.endpoint.is_output_reserved(cid));
            assert!(
                state
                    .lock()
                    .unwrap()
                    .sent
                    .iter()
                    .skip(1)
                    .all(|frame| frame.len() <= 1414)
            );
            deliver_scheduled(&mut a, &mut b, &state);
            assert_eq!(
                b.execute(servers[0], Op::Read(26000)).unwrap().bytes,
                vec![7; descriptor.payload_len]
            );
            assert_eq!(
                b.execute(servers[1], Op::Read(10)).unwrap().bytes,
                vec![8; 10]
            );
        }
    }
}

// Pacing keeps software GSO scalar. A TX timestamp request keeps only the
// segment holding its byte scalar: the range before it is one selection,
// and the backend gets one request, for that segment.
#[test]
fn software_gso_pacing_and_timestamp_requests_fall_back_to_scalar() {
    for timestamp in [false, true] {
        let pacing = (!timestamp).then_some(ntcp::PacingConfig::default());
        let (mut a, mut b, client, _, state) = pmtud_paced_pair(None, pacing);
        a.enable_egress(1, Some(SOFTWARE_GSO)).unwrap();
        if timestamp {
            state.lock().unwrap().capacity = 8;
            flags(
                &mut a,
                client,
                ts::TX_SCHED | ts::TX_SOFTWARE | ts::TX_HARDWARE,
            );
        }
        a.execute(client, Op::Write(vec![7; 26000])).unwrap();
        state.lock().unwrap().block = true;
        a.service_egress().unwrap();
        let cid = connection(&a, client);
        assert!(a.endpoint.is_output_reserved(cid));
        if timestamp {
            let held = held_segmentation(&a, cid).unwrap();
            let size = held.segment_payload_len;
            assert!(held.payload_len >= 2 * size);
            assert!(held.payload_len <= 25999 / size * size, "{held:?}");
        } else {
            assert_eq!(held_segmentation(&a, cid), None);
        }
        assert!(state.lock().unwrap().requests.is_empty());
        state.lock().unwrap().block = false;
        advance(&mut a, 1000);
        a.service_egress().unwrap();
        assert!(!state.lock().unwrap().sent.is_empty());
        if timestamp {
            deliver_scheduled(&mut a, &mut b, &state);
            a.service_egress().unwrap();
            assert_eq!(state.lock().unwrap().requests.len(), 1);
        }
    }
}

#[test]
#[ignore = "reproducible CPU sample, not a performance gate; run with --ignored --nocapture"]
fn software_gso_cpu_sample() {
    fn cpu_ns() -> u64 {
        let mut time: libc::timespec = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time) },
            0
        );
        time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
    }
    for gso in [None, Some(SOFTWARE_GSO)] {
        // Untimed probe: a blocked backend holds the first selection, whose
        // core segment group shows how many physical segments one selection
        // covers. Scalar output selects one segment at a time.
        let (mut a, _, clients, _, state) = scheduled_pair_gso(1, gso);
        a.execute(clients[0], Op::Write(vec![7; 26000])).unwrap();
        state.lock().unwrap().block = true;
        a.service_egress().unwrap();
        let per_selection = held_segmentation(&a, connection(&a, clients[0])).map_or(1, |group| {
            group.payload_len.div_ceil(group.segment_payload_len)
        });
        let mut ns = 0;
        let mut submissions = 0;
        // Setup/handshake/allocation excluded; fixed seed, clock and two full
        // physical segments per sample. Counts are backend calls, not an
        // assertion about core instruction counts.
        for _ in 0..100 {
            let (mut a, _, clients, _, state) = scheduled_pair_gso(1, gso);
            a.execute(clients[0], Op::Write(vec![7; 26000])).unwrap();
            let start = cpu_ns();
            a.service_egress().unwrap();
            ns += cpu_ns() - start;
            submissions += state.lock().unwrap().output_calls;
            assert_eq!(state.lock().unwrap().sent.len(), 2);
        }
        eprintln!(
            "gso={} samples=100 service_cpu_ns={ns} segments_per_selection={per_selection} backend_calls={submissions}",
            gso.is_some()
        );
    }
}

#[cfg(feature = "packet-test")]
#[path = "runtime_local_repair_tests.rs"]
mod local_repair;

#[test]
fn backend_first_hop_refresh_preserves_configured_path_policy() {
    let state = Arc::new(Mutex::new(State {
        mtu: Some(1500),
        ..Default::default()
    }));
    let io = Fixture(state.clone());
    let mut config = SocketConfig::new("test", Ipv4Addr::new(10, 73, 0, 2)).tcp;
    let mut policy = ntcp::PmtudConfig::new(9000);
    policy.route_mtu = Some(1400);
    policy.initial_mtu = Some(1300);
    policy.initial_search_low = Some(1280);
    policy.initial_search_high = Some(1400);
    policy.policy.search_aging = ntcp::SearchAging::Infinity;
    config.connection.pmtud = Some(policy);
    let actual = backend_config(config.clone(), &io).unwrap();
    policy.first_hop_mtu = 1500;
    assert_eq!(actual.connection.pmtud, Some(policy));
    state.lock().unwrap().mtu = Some(1280);
    assert!(backend_config(config, &io).is_err());
}

#[test]
fn retained_native_receive_preserves_original_segment_size_through_reservation() {
    let (mut a, b, clients, servers, state) = scheduled_pair(2);
    let cid = connection(&a, clients[0]);
    let peer = connection(&b, servers[0]);
    a.execute(clients[0], Op::Write(vec![1; 100])).unwrap();
    state.lock().unwrap().block = true;
    a.service_egress().unwrap();
    assert!(a.endpoint.is_output_reserved(cid));
    let before = a.endpoint.transport_info(cid).unwrap().received_mss;
    let tuple = a.endpoint.tuple(cid).unwrap();
    let ip = ntcp::IpMetadata {
        source: tuple.remote.ip(),
        destination: tuple.local.ip(),
    };
    let seq = b.endpoint.send_progress(peer).unwrap().next_write_sequence;
    let ack = a
        .endpoint
        .send_progress(cid)
        .unwrap()
        .unacknowledged_sequence;
    let options = if a
        .endpoint
        .transport_info(cid)
        .unwrap()
        .timestamps_negotiated
    {
        &[1, 1, 8, 10, 0, 0, 0, 2, 0, 0, 0, 0][..]
    } else {
        &[]
    };
    let mut tcp = vec![0; 10037 + 20 + options.len()];
    ntcp::wire::encode(
        ip,
        ntcp::wire::Header {
            source_port: tuple.remote.port(),
            destination_port: tuple.local.port(),
            sequence: seq,
            acknowledgment: ack,
            flags: ntcp::wire::ACK,
            window: 32000,
            urgent_pointer: 0,
        },
        options,
        &vec![0x51; 10037],
        &mut tcp,
    )
    .unwrap();
    let packet = ip_packet(
        &a,
        ntcp::Transmit {
            connection: None,
            tx_timestamp: None,
            ip,
            len: tcp.len(),
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
            ipv4_options: Default::default(),
            mark: 0,
        },
        &tcp,
    );
    state.lock().unwrap().rx_segment_size = core::num::NonZeroU16::new(1000);
    ingress(&mut a, &state, &packet);
    assert_eq!(a.endpoint.transport_info(cid).unwrap().received_mss, before);
    state.lock().unwrap().block = false;
    advance(&mut a, 1000);
    a.service_egress().unwrap();
    assert!(!a.endpoint.is_output_reserved(cid));
    a.receive_batch(&mut vec![0; 65549]).unwrap();
    assert_eq!(a.endpoint.transport_info(cid).unwrap().received_mss, 1000);
    let info = a
        .execute(clients[0], Op::TransportPrefix(1, 24))
        .unwrap()
        .bytes;
    assert_eq!(u32::from_ne_bytes(info[20..24].try_into().unwrap()), 1000);
    assert_eq!(
        a.execute(clients[0], Op::Read(10037)).unwrap().bytes,
        vec![0x51; 10037]
    );
}

// Device timestamps compare equal only within one opened clock: a later
// interface given the same index is another device.
#[test]
fn device_clock_identities_are_not_interface_indices_and_never_repeat() {
    let first = device_clock();
    let second = device_clock();
    assert_ne!(first, second);
    assert!(second > first);
}
