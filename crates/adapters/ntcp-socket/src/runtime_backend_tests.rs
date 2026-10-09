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
    enforce_mtu: bool,
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
    interrupted: bool,
    cancel_error: Option<i32>,
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
        if state.enforce_mtu && state.mtu.is_some_and(|mtu| bytes.len() > mtu as usize + 14) {
            return Err(io::Error::from_raw_os_error(EMSGSIZE));
        }
        if let Some(error) = state.output_error {
            return Err(error.into());
        }
        // Model native packet syscall EINTR: no packet or timestamp consumed.
        if state.interrupted || state.block {
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
        if state.enforce_mtu && state.mtu.is_some_and(|mtu| bytes.len() > mtu as usize + 14) {
            return Err(io::Error::from_raw_os_error(EMSGSIZE));
        }
        if let Some(error) = state.error {
            return Err(error.into());
        }
        // Model native packet syscall EINTR: no packet or timestamp consumed.
        if state.interrupted || state.block {
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

// The legacy fixtures above deliberately retain their direct poll/submit API.
// These tests opt into exactly the production reservation path after handshake.
fn reserve(owner: &mut Owner) -> (Receiver<()>, SyncSender<io::Result<Option<u32>>>) {
    owner.endpoint.enable_output_reservations().unwrap();
    owner.reservations = true;
    owner.test_now = Some(owner.now());
    let (refresh, request, result) = super::super::output::MtuRefresh::fixture();
    owner.mtu_refresh = Some(refresh);
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
fn drain_reservation(owner: &mut Owner) {
    for _ in 0..64 {
        if owner.reservation.is_none() {
            return;
        }
        if owner.prepare_packet(None).unwrap() {
            assert_eq!(owner.submit_reserved_packet(), Ok(TxOutcome::Submitted));
        } else {
            owner.test_now = Some(
                owner
                    .endpoint
                    .next_deadline()
                    .expect("repair pacing deadline"),
            );
        }
    }
    panic!("reservation did not drain");
}

#[test]
fn reserved_mtu_drop_split_backpressure_late_accept_and_prefix() {
    let (mut a, mut b, client, server, state) = pmtud_pair(None);
    a.execute(client, Op::Write(vec![7; 8000])).unwrap();
    let (requests, results) = reserve(&mut a);
    let cid = connection(&a, client);
    assert!(a.prepare_packet(None).unwrap());
    let original = a.pending_packet.clone().unwrap();
    let selected = ntcp_ip::parse(&original, false).unwrap();
    let selected = ntcp::wire::parse(selected.ip, selected.payload).unwrap();
    let selected_len = selected.payload.len();
    let start = selected.header.sequence;
    assert!(original.len() > 1500);
    assert_eq!(a.reservation_deadline, None);
    let token = a.reservation;
    state.lock().unwrap().interrupted = true;
    advance(&mut a, 100);
    assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::WouldBlock));
    let deadline = a.reservation_deadline.unwrap();
    assert_eq!(deadline, a.now() + 1_000_000);
    for i in 0..3 {
        state.lock().unwrap().interrupted = i % 2 == 0;
        state.lock().unwrap().block = i % 2 != 0;
        advance(&mut a, 100);
        assert!(a.prepare_packet(None).unwrap());
        assert_eq!(a.reservation, token);
        assert_eq!(a.pending_packet.as_ref(), Some(&original));
        assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::WouldBlock));
        assert_eq!(a.reservation_deadline, Some(deadline));
    }
    {
        let mut state = state.lock().unwrap();
        state.block = false;
        state.interrupted = false;
        state.enforce_mtu = true;
        state.mtu = Some(1400);
    }
    assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::WouldBlock));
    requests.try_recv().unwrap();
    assert!(a.pending_packet.is_none());
    assert!(!a.prepare_packet(None).unwrap());
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
    assert!(a.prepare_packet(None).unwrap());
    advance(&mut a, 10_000); // Physical departure later than selection.
    assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::Submitted));
    assert!(a.reservation.is_some()); // Accepted prefix does not free the barrier.
    assert_eq!(a.reservation_deadline, Some(deadline));
    assert!(a.prepare_packet(None).unwrap());
    state.lock().unwrap().interrupted = true;
    advance(&mut a, 100);
    assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::WouldBlock));
    assert_eq!(a.reservation_deadline, Some(deadline));
    state.lock().unwrap().interrupted = false;
    state.lock().unwrap().mtu = Some(600);
    assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::WouldBlock));
    requests.try_recv().unwrap();
    refresh(&mut a, &results, 600);
    assert_eq!(a.reservation_deadline, Some(deadline));
    drain_reservation(&mut a);
    assert_eq!(a.reservation_deadline, None);
    let mut seq = start;
    let mut count = 0;
    for (index, frame) in state.lock().unwrap().sent.iter().enumerate() {
        let ethernet = ntcp_ip::parse_ethernet(frame).unwrap();
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
        let (requests, results) = reserve(&mut a);
        assert!(a.prepare_packet(None).unwrap());
        {
            let mut s = state.lock().unwrap();
            s.enforce_mtu = true;
            s.mtu = Some(1400);
        }
        assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::WouldBlock));
        requests.try_recv().unwrap();
        let deadline = a.reservation_deadline.unwrap();
        assert_eq!(deadline, a.now() + 1_000_000);
        if let Some(response) = response {
            results
                .send(response.map(Some).map_err(io::Error::from_raw_os_error))
                .unwrap();
        }
        for _ in 0..4 {
            a.poll_mtu_refresh();
            assert!(!a.prepare_packet(None).unwrap());
            assert_eq!(a.reservation_deadline, Some(deadline));
            assert_eq!(a.output_wait(), std::time::Duration::from_millis(1));
            assert!(requests.try_recv().is_err());
            advance(&mut a, 100);
        }
        a.expire_reservation(deadline - 1).unwrap();
        assert!(a.reservation.is_some());
        a.test_now = Some(deadline);
        a.expire_reservation(deadline).unwrap();
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
        assert!(a.prepare_packet(None).unwrap());
        assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::Submitted));
        assert_eq!(state.lock().unwrap().sent.len(), 1);
        assert!(a.reservation.is_none());
        if response.is_none() {
            a.execute(healthy, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
                .unwrap();
            a.execute(healthy, Op::Write(vec![3; 8000])).unwrap();
            assert!(a.prepare_packet(None).unwrap());
            assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::WouldBlock));
            assert!(requests.try_recv().is_err()); // Still only the first stalled query.
            assert_eq!(a.reservation_deadline, Some(a.now() + 1_000_000));
        }
    }
}

#[test]
fn reserved_commands_producers_and_rx_are_deferred_before_admission() {
    let (mut a, mut b, client, server, state) = pmtud_pair(None);
    let fresh = new(&mut a, SOCK_NONBLOCK);
    a.execute(client, Op::Write(vec![1; 100])).unwrap();
    reserve(&mut a);
    assert!(a.prepare_packet(None).unwrap());
    let mut commands = Vec::new();
    for (id, op) in [
        (0, Op::New(SOCK_NONBLOCK)),
        (client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1)),
        (fresh, Op::Close),
    ] {
        let (reply, response) = mpsc::sync_channel(1);
        let mut request = Request {
            id,
            op,
            reply,
            deadline: None,
            send: None,
        };
        assert!(!a.service(&mut request));
        assert!(response.try_recv().is_err());
        commands.push((request, response));
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
    };
    assert!(!a.service(&mut file_request));
    assert!(file_response.try_recv().is_err());
    assert_eq!(offset, 0);
    b.execute(server, Op::Write(vec![2; 20])).unwrap();
    assert!(b.prepare_packet(None).unwrap());
    let packet = b.pending_packet.take().unwrap();
    ingress(&mut a, &state, &packet);
    assert_eq!(state.lock().unwrap().incoming.len(), 1);
    assert_eq!(state.lock().unwrap().receives, 0);
    assert_eq!(
        a.endpoint.on_timeout(a.now(), 0),
        Err(EndpointError::OutputReserved)
    );
    assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::Submitted));
    a.receive_batch(&mut vec![0; 65549]).unwrap();
    assert!(state.lock().unwrap().incoming.is_empty());
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
    reserve(&mut a);
    assert!(a.prepare_packet(None).unwrap());
    assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::Submitted));
    assert!(!a.prepare_packet(None).unwrap());
    assert!(a.reservation.is_none());
    assert_eq!(a.reservation_deadline, None);
    let deadline = a.endpoint.next_deadline().unwrap();
    assert!(deadline > a.now());
    a.test_now = Some(deadline);
    a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
    assert!(a.prepare_packet(None).unwrap());
    assert_eq!(a.reservation_deadline, None);
    state.lock().unwrap().block = true;
    assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::WouldBlock));
    let first = a.reservation_deadline.unwrap();
    advance(&mut a, 50_000);
    state.lock().unwrap().block = false;
    assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::Submitted));
    assert!(a.reservation_deadline.is_none());
    assert!(!a.prepare_packet(None).unwrap()); // No catch-up credit after late accept.
    // Free the two-packet initial congestion window, without selecting new output.
    for frame in state.lock().unwrap().sent.drain(..) {
        let frame = ntcp_ip::parse_ethernet(&frame).unwrap();
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
    assert!(
        a.prepare_packet(None).unwrap(),
        "now {} next {:?} info {:?}",
        a.now(),
        a.endpoint.next_deadline(),
        a.endpoint.transport_info(connection(&a, client))
    );
    state.lock().unwrap().block = true;
    assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::WouldBlock));
    assert!(a.reservation_deadline.unwrap() > first); // New obligation, new deadline.
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
    reserve(&mut a);
    assert!(a.prepare_packet(None).unwrap());
    assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::Submitted));
    assert_eq!(state.lock().unwrap().requests.len(), 1);
    assert_eq!(stage_count(&a, client, 1), 1);
    a.execute(client, Op::Write(vec![2; 8000])).unwrap();
    assert!(a.prepare_packet(None).unwrap());
    state.lock().unwrap().block = true;
    assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::WouldBlock));
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
    assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::WouldBlock));
    assert_eq!(stage_count(&a, client, 1), 2); // Scheduled is never rolled back.
    assert_eq!(a.sockets[&client].timestamps.reserved(), 1); // Only earlier HW remains.
    a.test_now = a.reservation_deadline;
    a.expire_reservation(a.now()).unwrap();
    assert_eq!(a.sockets[&client].timestamps.reserved(), 0);
    assert_eq!(stage_count(&a, client, 0), 1); // No fabricated transmit observation.
}

#[test]
fn reserved_stateless_rejection_is_best_effort_and_impossible_headers_abandon() {
    let (mut a, _, client, _, state) = pmtud_pair(None);
    reserve(&mut a);
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
    assert!(a.prepare_packet(None).unwrap());
    state.lock().unwrap().enforce_mtu = true;
    state.lock().unwrap().mtu = Some(20); // Force synchronous rejection, even of a RST.
    assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::WouldBlock));
    assert!(a.reservation.is_none());
    assert!(a.reservation_deadline.is_none());
    assert_eq!(
        a.endpoint.state(connection(&a, client)).unwrap(),
        ntcp::State::Established
    );

    // Native socket policy forbids source routes. Exercise the fail-closed
    // runtime branch with a core fixture that can retain impossible IP headers.
    let mut config = a.defaults.clone();
    config.ipv4_options_enabled = true;
    a.endpoint = Endpoint::new(config, [1; 32], 0, |_| true).unwrap();
    a.endpoint.enable_output_reservations().unwrap();
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
    let (_, attempt) = a
        .endpoint
        .poll_reserved_transmit(a.now(), &mut [0; 2048], BUDGET)
        .unwrap();
    a.reservation = attempt;
    a.endpoint.set_endpoint_first_hop_mtu(a.now(), 68).unwrap();
    a.endpoint.reject_unsubmitted(attempt.unwrap()).unwrap();
    assert!(!a.prepare_packet(None).unwrap());
    assert!(a.reservation.is_none());
    assert_eq!(
        a.endpoint.close_reason(id).unwrap(),
        Some(CloseReason::Aborted)
    );
}

#[test]
fn reserved_late_direct_accept_and_prefix_expiry_keep_accepted_bytes() {
    let (mut a, mut b, client, server, state) = pmtud_pair(None);
    a.execute(client, Op::Write(vec![6; 8000])).unwrap();
    let (requests, results) = reserve(&mut a);
    a.reservation_timeout_us = 2_000_000;
    assert!(a.prepare_packet(None).unwrap());
    state.lock().unwrap().block = true;
    assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::WouldBlock));
    let cid = connection(&a, client);
    let before = a.endpoint.transport_info(cid).unwrap();
    advance(&mut a, before.rto_us + 1);
    a.expire_reservation(a.now()).unwrap();
    state.lock().unwrap().block = false;
    assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::Submitted));
    assert!(a.reservation_deadline.is_none());
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
    assert!(a.prepare_packet(None).unwrap());
    {
        let mut s = state.lock().unwrap();
        s.enforce_mtu = true;
        s.mtu = Some(1400);
    }
    assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::WouldBlock));
    requests.try_recv().unwrap();
    refresh(&mut a, &results, 1400);
    assert!(a.prepare_packet(None).unwrap());
    assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::Submitted));
    assert!(a.reservation.is_some());
    let frame = state.lock().unwrap().sent.pop_front().unwrap();
    let frame = ntcp_ip::parse_ethernet(&frame).unwrap();
    let ip = ntcp_ip::parse(frame.payload, false).unwrap();
    let accepted = ntcp::wire::parse(ip.ip, ip.payload).unwrap().payload.len();
    b.input(b.now(), ip.ip, ip.traffic_class, ip.payload)
        .unwrap();
    assert_eq!(
        b.execute(server, Op::Read(8000)).unwrap().bytes,
        vec![7; accepted]
    );
    assert!(a.prepare_packet(None).unwrap());
    let deadline = a.reservation_deadline;
    state.lock().unwrap().interrupted = true;
    advance(&mut a, 100);
    assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::WouldBlock));
    assert_eq!(a.reservation_deadline, deadline);
    a.test_now = deadline;
    a.expire_reservation(a.now()).unwrap();
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
        reserve(&mut a);
        assert!(a.prepare_packet(None).unwrap());
        let cid = connection(&a, client);
        let token = a.reservation;
        let packet = a.pending_packet.clone();
        let before = a.endpoint.transport_info(cid).unwrap();
        state.lock().unwrap().interrupted = true;
        assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::WouldBlock));
        let deadline = a.reservation_deadline.unwrap();
        assert_eq!(deadline, a.now() + 1_000_000);

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
        };
        let (reply, closed) = mpsc::sync_channel(1);
        let mut close = Request {
            id: client,
            op: Op::Close,
            reply,
            deadline: None,
            send: None,
        };
        for _ in 0..4 {
            advance(&mut a, 200_000);
            assert!(!a.service(&mut producer));
            assert!(!a.service(&mut close));
            assert!(produced.try_recv().is_err());
            assert!(closed.try_recv().is_err());
            assert_eq!(offset, 0);
            assert!(a.prepare_packet(None).unwrap());
            assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::WouldBlock));
            assert_eq!(a.reservation_deadline, Some(deadline));
            assert_eq!(a.reservation, token);
            assert_eq!(a.pending_packet, packet);
            assert_eq!(
                a.endpoint.transport_info(cid).unwrap().unacked,
                before.unacked
            );
            assert!(state.lock().unwrap().sent.is_empty());
            assert!(state.lock().unwrap().requests.is_empty());
            assert_eq!(a.ethernet.as_ref().unwrap().next_cookie, 1);
        }
        a.expire_reservation(deadline - 1).unwrap();
        assert!(a.reservation.is_some());
        a.test_now = Some(deadline);
        a.expire_reservation(a.now()).unwrap();
        assert!(a.reservation.is_none());
        assert!(a.pending_packet.is_none());
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
        assert!(a.service(&mut close));
        assert!(closed.recv().unwrap().is_ok());
        state.lock().unwrap().interrupted = false;
        a.execute(healthy, Op::Write(b"healthy".to_vec())).unwrap();
        assert!(a.prepare_packet(None).unwrap());
        assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::Submitted));
        assert_eq!(state.lock().unwrap().sent.len(), 1);
        deliver(&mut a, &mut b, &state);
        assert_eq!(b.execute(peer, Op::Read(99)).unwrap().bytes, b"healthy");
    }
}

#[test]
fn reserved_unknown_interrupted_and_wrapped_cancellation_do_not_certify_rejection() {
    let (mut a, _, client, _, state) = pmtud_pair(None);
    a.execute(client, Op::Write(vec![1; 100])).unwrap();
    reserve(&mut a);
    assert!(a.prepare_packet(None).unwrap());
    state.lock().unwrap().output_error = Some(io::ErrorKind::Interrupted);
    assert_eq!(a.submit_reserved_packet(), Err(EIO));
    assert!(a.reservation_deadline.is_none());
    assert!(a.reservation.is_some());
    assert!(a.pending_packet.is_some());
    assert!(!a.waiting_mtu);

    for errno in [EINTR, EMSGSIZE] {
        let (mut a, _, client, _, state) = pmtud_pair(None);
        state.lock().unwrap().capacity = 2;
        flags(&mut a, client, ts::TX_SOFTWARE | ts::TX_HARDWARE);
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
            .unwrap();
        a.execute(client, Op::Write(vec![1; 100])).unwrap();
        reserve(&mut a);
        assert!(a.prepare_packet(None).unwrap());
        assert_eq!(a.submit_reserved_packet(), Ok(TxOutcome::Submitted));
        a.execute(client, Op::Write(vec![2; 100])).unwrap();
        assert!(a.prepare_packet(None).unwrap());
        state.lock().unwrap().cancel_error = Some(errno);
        assert_eq!(a.submit_reserved_packet(), Err(EIO));
        assert!(a.reservation_deadline.is_none());
        assert!(a.reservation.is_some());
        assert!(a.pending_packet.is_some());
        assert!(!a.waiting_mtu);
        assert_eq!(state.lock().unwrap().sent.len(), 1);
        assert_eq!(state.lock().unwrap().requests.len(), 1);
    }
}
